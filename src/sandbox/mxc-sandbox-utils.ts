/**
 * MXC BaseContainer backend for Windows, chosen by the caller with
 * `windows.backend: 'mxc'`.
 *
 * On hosts whose Windows build supports MXC's **BaseContainer** tier,
 * sandboxed commands start through the `@microsoft/mxc-sdk` Node API,
 * in this process: the OS applies filesystem and network policy in its
 * own elevated context, with no install step, no UAC, no ACL stamping,
 * and policy lifetime bound to the container. MXC's AppContainer tiers
 * are never used: srt-win's WFP fence is mandatory and fail-closed,
 * where MXC's AppContainer network enforcement is cooperative.
 *
 * The SDK starts the process itself, so this backend has no argv form:
 * callers use `SandboxManager.spawnSandboxed()`, and
 * `wrapWithSandboxArgv()` refuses.
 *
 * `network.tlsTerminate` is not supported here: Schannel clients in a
 * BaseContainer do not trust the MITM CA.
 *
 * ── Fail closed ──────────────────────────────────────────────────────
 *
 * Every spawn first runs the SDK's request-aware `probe()` on the exact
 * request it is about to start. The probe runs MXC's own tier detector,
 * the same code that picks the tier at spawn time. Anything other than
 * a clean `base-container` answer that supports every restriction in
 * the request (denied paths, the host proxy, clipboard and input
 * injection blocking) refuses the spawn. Nothing retries with a weaker
 * request and nothing falls back to srt-win.
 *
 * Residual risk: tier selection runs again inside `spawn()`. If the
 * machine changed between the two calls, MXC could pick an AppContainer
 * tier rather than fail. The calls are milliseconds apart.
 *
 * ── Policy mapping ───────────────────────────────────────────────────
 *
 * srt's cross-platform contract: writes are an ALLOW-list
 * (`filesystem.allowWrite`), reads are a DENY-list
 * (`filesystem.denyRead`, readable everywhere else). BaseContainer is
 * default-deny in both directions, so:
 *
 *   - reads:  `readonlyPaths: [<system drive root>, cwd, ...allowRead]`
 *     restores read-everywhere, then `deniedPaths: denyRead ∪
 *     credential-file denies` carves the deny-list out.
 *     Only the system drive is granted: other fixed drives are
 *     unreadable unless listed in allowRead.
 *   - writes: `readwritePaths: [...allowWrite, %TEMP%]`. %TEMP% is
 *     granted for parity with macOS/Linux (TMPDIR is always writable).
 *     cwd is NOT auto-granted, as on every other platform.
 *   - denyWrite: mapped into `deniedPaths` too, which over-denies
 *     (BaseContainer has no write-only deny, so reads on those paths
 *     are lost as well).
 *   - network: `egress.default: 'deny'`; with a proxy configured,
 *     `ingress.default: 'allow'` + `ingress.hostLoopback: 'allow'` and
 *     `runtimeConfig.networkProxy` naming the proxy port as the only
 *     way out (MXC 1.0's host proxy without a peer identity). srt's
 *     proxy does the domain filtering exactly as on macOS/Linux.
 *   - UI: on for every command (see {@link buildMxcRequest}), with
 *     clipboard and input injection blocked.
 */

import { createRequire } from 'node:module'
import * as path from 'node:path'
import type { Readable, Writable } from 'node:stream'
import { logForDebugging } from '../utils/debug.js'
import { generateProxyEnvVars, buildGitConfigEnv } from './sandbox-utils.js'
import {
  parseWindowsBinShell,
  WindowsSandboxError,
} from './windows-sandbox-utils.js'
import type { WindowsBinShell } from './windows-sandbox-utils.js'

const MXC_PKG = '@microsoft/mxc-sdk'
const MXC_V1 = `${MXC_PKG}/v1`

// ────────────────────────────────────────────────────────────────────────
// The SDK surface srt uses. `@microsoft/mxc-sdk` is an optional
// dependency that only installs on Node 24+, so srt cannot compile
// against its types; these mirror the subset of `@microsoft/mxc-sdk/v1`
// (`ContainerRequest`, `ProbeOutput`, `MxcProcess`) srt reads and
// writes. Keep them in step with the pinned SDK major.
// ────────────────────────────────────────────────────────────────────────

/** Mirrors the subset of the SDK's v1 `ContainerRequest` srt sends. */
export interface MxcRequest {
  /** One command line, handed to the OS verbatim. */
  command: string
  filesystem: {
    readwritePaths: string[]
    readonlyPaths: string[]
    deniedPaths: string[]
  }
  network: {
    egress: { default: 'deny' }
    ingress: { default: 'allow' | 'deny'; hostLoopback: 'allow' | 'deny' }
    runtimeConfig?: { networkProxy: string }
  }
  ui: {
    disable: boolean
    clipboard: 'none'
    allowInputInjection: false
  }
  /** Milliseconds; omitted = no timeout. */
  timeoutMs?: number
  workingDirectory: string
  environment: Record<string, string>
  /** Always false: the child gets exactly `environment`. */
  inheritDefaultEnvironment: false
}

/** Mirrors the SDK's `UiCapabilitySupport` fields srt checks. */
export interface MxcUiCapabilities {
  canBlockClipboardRead: boolean
  canBlockClipboardWrite: boolean
  canBlockInputInjection: boolean
}

/** Mirrors the SDK's `ProbeOutput` fields srt checks. */
export interface MxcProbeOutput {
  tier?: string
  needsDaclAugmentation?: boolean
  warnings: readonly string[]
  error?: string
  probes: {
    baseContainerSupportsDenyPaths: boolean
    baseContainerSupportsIngressHostLoopbackAllow: boolean
    baseContainerSupportsIdentitylessLoopbackProxy: boolean
    uiCapabilities: MxcUiCapabilities
  }
}

/** Mirrors the SDK's `MxcProcess` members srt uses. */
export interface MxcProcessHandle {
  readonly id: number
  readonly standardInput: Writable | null
  readonly standardOutput: Readable | null
  readonly standardError: Readable | null
  wait(): Promise<{ exitCode: number; timedOut: boolean }>
  kill(): void
  dispose(): void
}

/** The two SDK entry points srt calls. */
export interface MxcSdk {
  probe(request: MxcRequest): MxcProbeOutput
  spawn(request: MxcRequest): Promise<MxcProcessHandle>
}

// ────────────────────────────────────────────────────────────────────────
// Loading the SDK
// ────────────────────────────────────────────────────────────────────────

/** Whether `@microsoft/mxc-sdk` resolves from here, without loading it. */
export function isMxcSdkInstalled(): boolean {
  try {
    createRequire(import.meta.url).resolve(`${MXC_PKG}/package.json`)
    return true
  } catch {
    return false
  }
}

/** Why `windows.backend: 'mxc'` cannot load the SDK. */
export const MXC_SDK_MISSING = `${MXC_PKG} is not installed (it needs Node 24 or later)`

/**
 * Load `@microsoft/mxc-sdk/v1`.
 *
 * @throws {WindowsSandboxError} `backend_unsupported` when the package
 * is missing or does not export `probe` and `spawn`.
 */
export async function loadMxcSdk(): Promise<MxcSdk> {
  let mod: unknown
  try {
    // A variable specifier keeps bundlers and tsc from resolving an
    // optional dependency that is usually absent.
    const specifier: string = MXC_V1
    mod = await import(specifier)
  } catch (e) {
    throw new WindowsSandboxError(
      'backend_unsupported',
      `windows.backend is 'mxc' but ${MXC_SDK_MISSING}: ${(e as Error).message}`,
    )
  }
  const sdk = mod as Partial<MxcSdk> | null
  if (typeof sdk?.probe !== 'function' || typeof sdk.spawn !== 'function') {
    throw new WindowsSandboxError(
      'backend_unsupported',
      `windows.backend is 'mxc' but ${MXC_V1} does not export probe() and spawn()`,
    )
  }
  return { probe: sdk.probe, spawn: sdk.spawn }
}

// ────────────────────────────────────────────────────────────────────────
// Probe & spawn
// ────────────────────────────────────────────────────────────────────────

export type WindowsBackendSelection =
  | Readonly<{ backend: 'srt-win' }>
  | Readonly<{
      backend: 'mxc'
      /** Whether the host can enforce per-command denied paths. */
      denyPathsSupported: boolean
    }>

/**
 * Every reason the probe's answer cannot enforce `request` exactly.
 * Empty means the request is safe to spawn.
 */
export function mxcProbeRefusals(
  request: MxcRequest,
  probe: MxcProbeOutput,
): string[] {
  if (probe.error !== undefined) return [`the probe failed: ${probe.error}`]
  const reasons: string[] = []
  if (probe.tier !== 'base-container') {
    reasons.push(
      `this host offers MXC tier '${probe.tier ?? 'none'}'; BaseContainer is required`,
    )
  }
  if (probe.needsDaclAugmentation === true) {
    reasons.push('the tier needs host ACL changes (DACL augmentation)')
  }
  const facts = probe.probes
  if (
    request.filesystem.deniedPaths.length > 0 &&
    !facts.baseContainerSupportsDenyPaths
  ) {
    reasons.push('BaseContainer cannot enforce denied paths on this host')
  }
  if (request.network.runtimeConfig !== undefined) {
    if (!facts.baseContainerSupportsIdentitylessLoopbackProxy) {
      reasons.push('BaseContainer cannot confine egress to the host proxy')
    }
    if (!facts.baseContainerSupportsIngressHostLoopbackAllow) {
      reasons.push('BaseContainer cannot allow host loopback for the proxy')
    }
  }
  const ui = facts.uiCapabilities
  if (!ui.canBlockClipboardRead || !ui.canBlockClipboardWrite) {
    reasons.push('this host cannot block clipboard access')
  }
  if (!ui.canBlockInputInjection) {
    reasons.push('this host cannot block input injection')
  }
  return reasons
}

/**
 * Probe `request`, refusing anything {@link mxcProbeRefusals} reports.
 *
 * @throws {WindowsSandboxError} `backend_unsupported`.
 */
export function assertMxcCanEnforce(
  sdk: MxcSdk,
  request: MxcRequest,
): MxcProbeOutput {
  let probe: MxcProbeOutput
  try {
    probe = sdk.probe(request)
  } catch (e) {
    throw new WindowsSandboxError(
      'backend_unsupported',
      `windows.backend is 'mxc' but the probe failed: ${(e as Error).message}`,
    )
  }
  const reasons = mxcProbeRefusals(request, probe)
  if (reasons.length > 0) {
    throw new WindowsSandboxError(
      'backend_unsupported',
      `windows.backend is 'mxc' but ${reasons.join('; ')}`,
    )
  }
  for (const warning of probe.warnings) {
    logForDebugging(`[Sandbox Windows] mxc probe: ${warning}`)
  }
  return probe
}

/**
 * Check, once at `initialize()`, that this host can run the session's
 * policy on BaseContainer. `request` is the session policy compiled by
 * {@link buildMxcRequest}.
 *
 * @throws {WindowsSandboxError} `backend_unsupported`.
 */
export function verifyMxcBackend(
  sdk: MxcSdk,
  request: MxcRequest,
): Extract<WindowsBackendSelection, { backend: 'mxc' }> {
  const probe = assertMxcCanEnforce(sdk, request)
  return {
    backend: 'mxc',
    denyPathsSupported: probe.probes.baseContainerSupportsDenyPaths,
  }
}

/**
 * Start `request` after {@link assertMxcCanEnforce} accepts it. The
 * probe runs on every spawn, so a command whose per-command policy the
 * host cannot enforce never starts.
 */
export async function spawnMxcRequest(
  sdk: MxcSdk,
  request: MxcRequest,
): Promise<MxcProcessHandle> {
  assertMxcCanEnforce(sdk, request)
  logForDebugging(
    `[Sandbox Windows] mxc spawn: ${request.filesystem.readwritePaths.length} write, ` +
      `${request.filesystem.deniedPaths.length} denied paths`,
  )
  return sdk.spawn(request)
}

// ────────────────────────────────────────────────────────────────────────
// Command-line assembly
// ────────────────────────────────────────────────────────────────────────

/**
 * MSVCRT/CreateProcess argument quoting: no quotes for safe tokens;
 * otherwise wrap in `"…"`, doubling backslashes that precede a `"` or
 * the closing quote and escaping each `"` as `\"`.
 */
export function joinWindowsCommandLine(argv: readonly string[]): string {
  return argv.map(quoteWindowsArg).join(' ')
}

/**
 * Build the ONE command line MXC hands verbatim to the OS as
 * `lpCommandLine`. The string must therefore be exactly what the
 * CHILD parses:
 *
 *   - cmd.exe does NOT use MSVCRT escaping: the payload after `/c`
 *     gets ONE outer quote pair for `/s` to strip, contents verbatim
 *     (quotes and metachars untouched: they are the user's tool
 *     inside the sandbox). This mirrors srt-win's `build_cmdline`.
 *   - pwsh/powershell/bash are CRT programs that argv-parse their
 *     command line MSVCRT-style, so the payload is a regular quoted
 *     argv element.
 */
export function buildShellCommandLine(
  sh: WindowsBinShell,
  command: string,
): string {
  const base = path.win32.basename(sh.exe).toLowerCase()
  if (base === 'cmd' || base === 'cmd.exe') {
    return `${joinWindowsCommandLine([sh.exe, ...sh.args])} "${command}"`
  }
  return joinWindowsCommandLine([sh.exe, ...sh.args, command])
}

function quoteWindowsArg(arg: string): string {
  if (arg.length > 0 && !/[ \t\n\v"]/.test(arg)) return arg
  let out = '"'
  let backslashes = 0
  for (const ch of arg) {
    if (ch === '\\') {
      backslashes++
      continue
    }
    if (ch === '"') {
      // 2n+1: escape the backslashes AND the quote.
      out += '\\'.repeat(backslashes * 2 + 1) + '"'
    } else {
      out += '\\'.repeat(backslashes) + ch
    }
    backslashes = 0
  }
  // 2n before the closing quote so it isn't escaped.
  out += '\\'.repeat(backslashes * 2) + '"'
  return out
}

// ────────────────────────────────────────────────────────────────────────
// Policy → request
// ────────────────────────────────────────────────────────────────────────

/**
 * Inputs to {@link buildMxcRequest}: the same information the srt-win
 * wrap receives, in srt's own semantics. The mapping to MXC's
 * allow-list model happens inside.
 */
export interface MxcSandboxParams {
  command: string
  /** Proxy port: the ONE loopback listener the child may reach. */
  httpProxyPort?: number
  socksProxyPort?: number
  proxyAuthToken?: string
  /** `mode:'mask'` sentinels; the child inherits no other env. */
  setEnvVars?: Readonly<Record<string, string>>
  /** srt read deny-list (expanded, concrete paths). */
  denyRead?: readonly string[]
  /** srt write deny-list (expanded): over-denied to full deny. */
  denyWrite?: readonly string[]
  /** srt read allow-list, on top of the system-drive grant. */
  allowRead?: readonly string[]
  /** srt write allow-list (expanded). */
  allowWrite?: readonly string[]
  cwd?: string
  gitSafeDirectories?: readonly string[]
  binShell?: WindowsBinShell
  timeoutMs?: number
}

/** Compile srt semantics into an SDK v1 container request. */
export function buildMxcRequest(p: MxcSandboxParams): MxcRequest {
  const systemDrive = `${process.env.SystemDrive ?? 'C:'}\\`
  const workingDirectory = p.cwd ?? process.cwd()
  const temp = process.env.TEMP ?? process.env.TMP
  const sh = p.binShell ?? parseWindowsBinShell(undefined)
  const hasProxy = p.httpProxyPort !== undefined
  const proxyEnv = generateProxyEnvVars(
    p.httpProxyPort,
    p.socksProxyPort,
    undefined,
    p.proxyAuthToken,
  )

  return {
    command: buildShellCommandLine(sh, p.command),
    filesystem: {
      readonlyPaths: [systemDrive, workingDirectory, ...(p.allowRead ?? [])],
      readwritePaths: [
        ...(p.allowWrite ?? []),
        ...(temp !== undefined ? [temp] : []),
      ],
      deniedPaths: [...(p.denyRead ?? []), ...(p.denyWrite ?? [])],
    },
    network: {
      egress: { default: 'deny' },
      // MXC 1.0 resolves hostLoopback on its own (it does not inherit
      // ingress.default), and admits a host proxy without a peer
      // identity only with hostLoopback 'allow' plus ingress 'allow'.
      // Without a proxy both are denied explicitly.
      ...(hasProxy
        ? {
            ingress: { default: 'allow', hostLoopback: 'allow' },
            runtimeConfig: {
              networkProxy: `http://${
                p.proxyAuthToken ? `srt:${p.proxyAuthToken}@` : ''
              }127.0.0.1:${p.httpProxyPort}`,
            },
          }
        : { ingress: { default: 'deny', hostLoopback: 'deny' } }),
    },
    // UI stays on for every command. With it off, any program that loads
    // user32 or gdi32 (PowerShell, git, node, whoami, tasklist and most
    // other tools) fails at startup with 0xC0000142, and children
    // inherit the container's setting, so it can't be chosen per shell.
    // The cost: a sandboxed program can open a window on the desktop.
    // Clipboard and input injection stay blocked.
    ui: { disable: false, clipboard: 'none', allowInputInjection: false },
    ...(p.timeoutMs !== undefined && p.timeoutMs > 0
      ? { timeoutMs: p.timeoutMs }
      : {}),
    workingDirectory,
    environment: buildChildEnv(p, proxyEnv),
    inheritDefaultEnvironment: false,
  }
}

/**
 * Host variables copied into the child's environment. The child gets
 * exactly the environment srt builds (`inheritDefaultEnvironment` is
 * off): the user's profile environment can hold secrets, so it is
 * never layered underneath. This is the set ordinary Windows programs
 * expect to find; MXC refuses to start a child without LOCALAPPDATA.
 */
const CHILD_BASE_ENV_VARS = [
  'ALLUSERSPROFILE',
  'APPDATA',
  'CommonProgramFiles',
  'CommonProgramFiles(Arm)',
  'CommonProgramFiles(x86)',
  'CommonProgramW6432',
  'COMPUTERNAME',
  'ComSpec',
  'HOMEDRIVE',
  'HOMEPATH',
  'LOCALAPPDATA',
  'NUMBER_OF_PROCESSORS',
  'OS',
  'PATH',
  'PATHEXT',
  'PROCESSOR_ARCHITECTURE',
  'PROCESSOR_IDENTIFIER',
  'PROCESSOR_LEVEL',
  'PROCESSOR_REVISION',
  'ProgramData',
  'ProgramFiles',
  'ProgramFiles(Arm)',
  'ProgramFiles(x86)',
  'ProgramW6432',
  'PUBLIC',
  'SystemDrive',
  'SystemRoot',
  'TEMP',
  'TMP',
  'USERDOMAIN',
  'USERNAME',
  'USERPROFILE',
  'windir',
] as const

/**
 * The child's environment. Precedence matches srt-win: host base vars,
 * then mask sentinels, then the generated proxy set (so a caller
 * masking HTTPS_PROXY cannot break the sandbox's own plumbing), then
 * GIT_CONFIG_* last so its COUNT composition wins.
 */
function buildChildEnv(
  p: MxcSandboxParams,
  proxyEnv: readonly string[],
): Record<string, string> {
  // Same two deletions as srt-win, same reasons: TMPDIR is POSIX-only
  // and breaks msys2 tools; NO_PROXY would send localhost DIRECT into
  // the container's egress block (only the proxy port is reachable).
  const envList = proxyEnv.filter(
    e =>
      !e.startsWith('TMPDIR=') &&
      !e.startsWith('NO_PROXY=') &&
      !e.startsWith('no_proxy='),
  )
  const gitCfg = buildGitConfigEnv({
    safeDirs: [
      p.cwd ?? process.cwd(),
      ...(p.allowWrite ?? []),
      ...(p.gitSafeDirectories ?? []),
    ],
    schannelCa: false,
    baseEnv: p.setEnvVars,
  })
  const merged: Record<string, string> = {}
  for (const k of CHILD_BASE_ENV_VARS) {
    const v = process.env[k]
    if (v !== undefined) merged[k] = v
  }
  for (const [k, v] of Object.entries(p.setEnvVars ?? {})) {
    merged[k] = v
  }
  for (const e of envList) {
    const eq = e.indexOf('=')
    if (eq > 0) merged[e.slice(0, eq)] = e.slice(eq + 1)
  }
  for (const [k, v] of Object.entries(gitCfg)) {
    merged[k] = v
  }
  return merged
}
