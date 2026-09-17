/**
 * MXC BaseContainer backend for Windows — automatic, not user-chosen.
 *
 * srt selects its Windows enforcement backend at `initialize()`:
 *
 *   - Hosts whose Windows build supports MXC's **BaseContainer** tier
 *     (`Experimental_CreateProcessInSandbox` in processmodel.dll,
 *     25H2+ with the OS feature enabled) run sandboxed execs through
 *     Microsoft's `wxc-exec.exe` — the OS applies filesystem and
 *     network policy in its own elevated context: no install step, no
 *     UAC, no ACL stamping, policy lifetime bound to the container.
 *   - Every other host (23H2/24H2/25H2 today, where MXC would fall
 *     back to its AppContainer tiers) uses srt-win, unchanged. MXC's
 *     AppContainer tiers are deliberately never used: srt-win's WFP
 *     fence is mandatory and fail-closed, where MXC's AppContainer
 *     network enforcement is cooperative (WinHTTP-stack proxying,
 *     env-var steering) and proceeds unfenced when firewall-rule
 *     writes fail without admin.
 *
 * There is no user-facing backend choice. The only config surface is
 * `windows.mxc.path` (where to find `wxc-exec.exe`), parallel to
 * `windows.srtWin.path`.
 *
 * ── Selection (see {@link selectWindowsBackend}) ────────────────────
 *
 * `wxc-exec --probe --config-base64 <b64>` runs MXC's own fallback
 * detector against OUR actual policy and reports the tier it would
 * dispatch (`"base-container"` / `"appcontainer-dacl"` / …). Selecting
 * on that answer is skew-free: the same code that will pick the tier
 * at exec time picks it at selection time, with denies, WRITE_DAC,
 * and the deny-capability bit all accounted for. Anything other than
 * a clean `"base-container"` answer — SDK not installed, binary
 * missing, probe error, any other tier — selects srt-win. srt-win
 * enforces everything srt promises, so failing toward it is always
 * safe; MXC is an upgrade, never a requirement.
 *
 * Residual risk: tier selection re-runs inside `wxc-exec` at exec
 * time, and if the machine state changed since the probe (feature
 * disabled, deny-cap lost) MXC silently falls back to ITS AppContainer
 * tier rather than failing. Their §2.1 "never silently downgrade"
 * contract suggests a fail-loud flag may come; until then the probe
 * and exec are seconds apart in practice.
 *
 * ── Policy mapping (same config, same semantics) ────────────────────
 *
 * srt's cross-platform contract: writes are an ALLOW-list
 * (`filesystem.allowWrite`), reads are a DENY-list
 * (`filesystem.denyRead`, readable everywhere else). BaseContainer is
 * default-deny in both directions, so:
 *
 *   - reads:  `readonlyPaths: [<system drive root>, ...allowRead]`
 *     restores read-everywhere, then `deniedPaths: denyRead ∪
 *     credential-file denies` carves the deny-list out (requires the
 *     `SANDBOX_CAP_FS_DENY` bit — the probe accounts for it).
 *     MULTI-DRIVE CAVEAT: only the system drive is granted; secondary
 *     fixed drives are unreadable under this mapping until verified
 *     on hardware.
 *   - writes: `readwritePaths: [...allowWrite, %TEMP%]`. %TEMP% is
 *     granted for parity with macOS/Linux (TMPDIR is always writable)
 *     and with srt-win (the sandbox user's own profile temp).
 *     cwd is NOT auto-granted — same as every other platform.
 *   - denyWrite: mapped into `deniedPaths` too, which OVER-denies
 *     (BaseContainer has no write-only deny primitive, so reads on
 *     those paths are lost as well). Fail-closed direction; refine
 *     after hardware verification.
 *   - network: egress blocked, `proxy: {localhost: <mux port>}` as
 *     the sole escape; srt's proxy does the domain filtering exactly
 *     as on macOS/Linux. OPEN (manual test #1): MXC's GA model scopes
 *     the loopback exemption to a proxy CONTAINER's SID
 *     (`allowedPeers`) — whether the OS-applied policy lets the child
 *     reach our plain host-process listener is unverified.
 *
 * ── Spawn contract ──────────────────────────────────────────────────
 *
 * Same as srt-win: {@link wrapCommandWithSandboxMxc} returns
 * `{argv, env}` for the CALLER to spawn with `shell: false`. The argv
 * is `wxc-exec.exe --config-base64 <base64(ContainerConfig JSON)>` —
 * the SDK is used only as the policy→config compiler
 * (`buildSandboxPayload`) and the vehicle that ships the signed
 * runner. MXC takes ONE `process.commandLine` string that wxc-exec
 * re-parses MSVCRT-style, so {@link joinWindowsCommandLine} re-encodes
 * srt's discrete argv with the standard CreateProcess quoting
 * algorithm.
 */

import { createRequire } from 'node:module'
import * as path from 'node:path'
import { existsSync } from 'node:fs'
import { spawnSync } from 'node:child_process'
import { logForDebugging } from '../utils/debug.js'
import { generateProxyEnvVars, buildGitConfigEnv } from './sandbox-utils.js'
import {
  parseWindowsBinShell,
  envListToObject,
} from './windows-sandbox-utils.js'
import type { WindowsBinShell } from './windows-sandbox-utils.js'
import type { MxcConfig } from './sandbox-config.js'

// ────────────────────────────────────────────────────────────────────────
// Structural subset of @microsoft/mxc-sdk@0.7 that srt actually uses.
//
// The SDK is an optionalDependency (Windows-only, ~40 MB with
// the bundled runners) loaded via dynamic import, so its types cannot
// be `import type`d unconditionally on macOS/Linux dev machines. These
// interfaces mirror sdk/node/src/types.ts for policy version
// 0.7.0-alpha; keep them in step with the pinned SDK minor.
// ────────────────────────────────────────────────────────────────────────

/** MXC config schema version srt targets. See SDK Compatibility table. */
export const MXC_POLICY_VERSION = '0.7.0-alpha'

/** Mirrors @microsoft/mxc-sdk `SandboxPolicy` (fields srt sets). */
export interface MxcSandboxPolicy {
  version: string
  filesystem?: {
    readwritePaths?: string[]
    readonlyPaths?: string[]
    deniedPaths?: string[]
  }
  network?: {
    allowOutbound?: boolean
    allowLocalNetwork?: boolean
    proxy?: { localhost: number }
  }
  ui?: { allowWindows?: boolean }
  timeoutMs?: number
}

/**
 * Mirrors the slice of @microsoft/mxc-sdk `ContainerConfig` we touch.
 * `process` is required because `createConfigFromPolicy` always builds
 * it; the SDK's own type marks it optional only for hand-written
 * configs. The runtime object carries more fields (processContainer,
 * network, ui, …) that pass through JSON.stringify untyped.
 */
export interface MxcContainerConfig {
  version: string
  containment?: string
  process: { commandLine: string; cwd?: string; env?: string[] }
}

/** The SDK entry point srt calls. */
export interface MxcSdk {
  buildSandboxPayload(
    script: string,
    policy: MxcSandboxPolicy,
    workingDirectory?: string,
    containerName?: string,
    containment?: string,
  ): MxcContainerConfig
}

const MXC_PKG = '@microsoft/mxc-sdk'

let mxcSdkPromise: Promise<MxcSdk> | undefined

/**
 * Lazily load the optional `@microsoft/mxc-sdk`. Cached for the
 * process. Absence is NOT an error at the selection layer (it just
 * means srt-win); callers that reach this after selection picked mxc
 * get the raw import error.
 */
export function loadMxcSdk(): Promise<MxcSdk> {
  mxcSdkPromise ??= import(MXC_PKG).then(
    m => m as unknown as MxcSdk,
    (e: unknown) => {
      mxcSdkPromise = undefined
      throw e
    },
  )
  return mxcSdkPromise
}

// ────────────────────────────────────────────────────────────────────────
// Binary resolution
// ────────────────────────────────────────────────────────────────────────

/** Resolved `wxc-exec.exe` spawn descriptor (parallel to `SrtWinSpawn`). */
export type MxcSpawn = Readonly<{ exe: string }>

/**
 * SDK bin-directory arch tag. Mirrors the SDK's `getSdkArch()`
 * (`x64` | `arm64`), which keys the `bin/<arch>/` layout the package
 * publishes for both architectures.
 */
function mxcArch(): 'x64' | 'arm64' {
  return process.arch === 'arm64' ? 'arm64' : 'x64'
}

/**
 * Locate the packaged `wxc-exec.exe`, in the SDK's own precedence
 * order so behaviour matches its `findWxcExecutable()`:
 *   1. `MXC_BIN_DIR/<arch>/wxc-exec.exe` (env override)
 *   2. `<@microsoft/mxc-sdk root>/bin/<arch>/wxc-exec.exe`
 *
 * Returns undefined when neither resolves — for the selection layer,
 * "no runner" simply means srt-win. The package root is resolved via
 * its exported `./package.json` subpath (the only non-`.` entry in
 * the SDK's exports map), so this survives node_modules hoisting and
 * npm/bun layout differences.
 */
export function getWxcExecPath(): string | undefined {
  const candidates: string[] = []
  if (process.env.MXC_BIN_DIR) {
    candidates.push(
      path.join(process.env.MXC_BIN_DIR, mxcArch(), 'wxc-exec.exe'),
    )
  }
  try {
    const require = createRequire(import.meta.url)
    const pkgJson = require.resolve(`${MXC_PKG}/package.json`)
    candidates.push(
      path.join(path.dirname(pkgJson), 'bin', mxcArch(), 'wxc-exec.exe'),
    )
  } catch {
    // Package not installed — selection falls back to srt-win.
  }
  return candidates.find(p => existsSync(p))
}

/**
 * Resolve the MXC runner from config. Returns undefined (→ srt-win)
 * when nothing resolves; an explicitly configured `windows.mxc.path`
 * that does not exist is undefined too — selection logs the reason.
 */
export function resolveMxc(cfg?: MxcConfig): MxcSpawn | undefined {
  if (cfg?.path) {
    return existsSync(cfg.path) ? { exe: cfg.path } : undefined
  }
  const exe = getWxcExecPath()
  return exe ? { exe } : undefined
}

// ────────────────────────────────────────────────────────────────────────
// Probe & selection
// ────────────────────────────────────────────────────────────────────────

/** Parsed subset of `wxc-exec --probe` JSON output (probe.rs). */
export interface MxcProbeResult {
  /** Tier the detector would dispatch: 'base-container' | 'appcontainer-bfs' | 'appcontainer-dacl'. */
  tier?: string
  /** Detector error (tier absent when set). */
  error?: string
  /** Raw machine facts. */
  probes?: {
    baseContainerApiPresent?: boolean
    baseContainerSupportsDenyPaths?: boolean
  }
}

/**
 * Run `wxc-exec --probe [--config-base64 <b64>]` and parse its JSON.
 * Read-only and side-effect-free by MXC's contract (probe.rs: "does
 * not write logs, modify the filesystem, or spawn child processes").
 * Passing the session's real config makes the tier answer account for
 * denies + the deny-capability bit. Returns undefined on any spawn or
 * parse failure — the caller treats that as "not base-container".
 */
export function probeMxc(
  spawn: MxcSpawn,
  configBase64?: string,
): MxcProbeResult | undefined {
  const args = ['--probe']
  if (configBase64 !== undefined) args.push('--config-base64', configBase64)
  const r = spawnSync(spawn.exe, args, { encoding: 'utf8', timeout: 15_000 })
  if (r.error || r.status !== 0 || !r.stdout) return undefined
  try {
    return JSON.parse(r.stdout) as MxcProbeResult
  } catch {
    return undefined
  }
}

export type WindowsBackendSelection =
  | Readonly<{ backend: 'srt-win'; reason: string }>
  | Readonly<{
      backend: 'mxc'
      reason: string
      mxc: MxcSpawn
      /** `SANDBOX_CAP_FS_DENY` bit at selection — gates per-exec denies. */
      denyPathsSupported: boolean
    }>

/** The reason string for the (common) no-runner srt-win selection. */
export function mxcUnavailableReason(cfg: MxcConfig | undefined): string {
  return cfg?.path
    ? `windows.mxc.path does not exist: ${cfg.path}`
    : `${MXC_PKG} not installed (wxc-exec.exe not found)`
}

/**
 * Decide which Windows enforcement backend this session uses, given a
 * resolved runner and the session policy compiled to a ContainerConfig
 * (see {@link buildMxcContainerConfig} + {@link encodeMxcConfig} —
 * compiling it is the caller's job so the same expansion feeds both
 * the probe and wrap-time). Called once from
 * `SandboxManager.initialize()`; the answer is held for the session.
 * EVERY failure or ambiguity selects srt-win — the packaged,
 * always-correct fallback.
 */
export function selectWindowsBackend(
  spawn: MxcSpawn,
  probeConfigBase64: string,
): WindowsBackendSelection {
  const srtWin = (reason: string): WindowsBackendSelection => ({
    backend: 'srt-win',
    reason,
  })
  const probe = probeMxc(spawn, probeConfigBase64)
  if (!probe) return srtWin('wxc-exec --probe failed or emitted no JSON')
  if (probe.error) return srtWin(`probe error: ${probe.error}`)
  if (probe.tier !== 'base-container') {
    return srtWin(
      `host supports mxc tier '${probe.tier}' only; BaseContainer required`,
    )
  }
  return {
    backend: 'mxc',
    reason: 'host supports BaseContainer for this policy',
    mxc: spawn,
    denyPathsSupported: probe.probes?.baseContainerSupportsDenyPaths === true,
  }
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
 * Build the ONE `process.commandLine` string wxc-exec hands VERBATIM
 * to the OS as `lpCommandLine` (base_container_runner.rs passes it
 * with `applicationName = NULL` — no re-parse, no re-quote). The
 * string must therefore be exactly what the CHILD parses:
 *
 *   - cmd.exe does NOT use MSVCRT escaping: the payload after `/c`
 *     gets ONE outer quote pair for `/s` to strip, contents verbatim
 *     (quotes and metachars untouched — they are the user's tool
 *     inside the sandbox). This mirrors srt-win's `build_cmdline`
 *     (launch.rs), including the reverted `"` → `""` mistake noted
 *     there: MSVCRT-escaping the payload turns embedded quotes into
 *     literal backslashes under cmd's parser and inverts quote state
 *     around `&`/`|`.
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
// Policy → ContainerConfig
// ────────────────────────────────────────────────────────────────────────

/**
 * Inputs to {@link wrapCommandWithSandboxMxc} — the same information
 * the srt-win wrap receives, expressed in srt's own semantics. The
 * mapping to MXC's allow-list model happens inside.
 */
export interface MxcSandboxParams {
  command: string
  /** Mux front-end port — the ONE loopback proxy the child may reach. */
  httpProxyPort?: number
  socksProxyPort?: number
  proxyAuthToken?: string
  /** `mode:'mask'` sentinels; the MXC child gets NO inherited env. */
  setEnvVars?: Readonly<Record<string, string>>
  /** srt read deny-list (expanded, concrete paths). */
  denyRead?: readonly string[]
  /** srt write deny-list (expanded) — over-denied to full deny, see header. */
  denyWrite?: readonly string[]
  /** srt read allow-list — additive on top of the system-drive grant. */
  allowRead?: readonly string[]
  /** srt write allow-list (expanded). */
  allowWrite?: readonly string[]
  cwd?: string
  gitSafeDirectories?: readonly string[]
  /**
   * TLS-termination trust bundle. Env-var layer only
   * (NODE_EXTRA_CA_CERTS/CURL_CA_BUNDLE/…) — whether schannel clients
   * inside a BaseContainer see the invoking user's Root store is
   * manual test #4.
   */
  caCertPath?: string
  binShell?: WindowsBinShell
  /** Resolved runner from selection. */
  mxc: MxcSpawn
  timeoutMs?: number
}

/**
 * Compile srt semantics into an MXC ContainerConfig via the SDK.
 * Separated from the wrap so `initialize()` can compile the session
 * policy once for the `--probe` selection call. `proxyEnv` lets the
 * wrap share one `generateProxyEnvVars` result between the child env
 * and the broker spawn env; omitted (probe path) it is computed here.
 */
export async function buildMxcContainerConfig(
  p: MxcSandboxParams,
  proxyEnv?: readonly string[],
): Promise<MxcContainerConfig> {
  const sdk = await loadMxcSdk()

  const systemDrive = `${process.env.SystemDrive ?? 'C:'}\\`
  const readonlyPaths = [systemDrive, ...(p.allowRead ?? [])]
  const temp = process.env.TEMP ?? process.env.TMP
  const readwritePaths = [
    ...(p.allowWrite ?? []),
    ...(temp !== undefined ? [temp] : []),
  ]
  const deniedPaths = [...(p.denyRead ?? []), ...(p.denyWrite ?? [])]

  const policy: MxcSandboxPolicy = {
    version: MXC_POLICY_VERSION,
    filesystem: { readonlyPaths, readwritePaths, deniedPaths },
    network:
      p.httpProxyPort !== undefined
        ? { allowOutbound: false, proxy: { localhost: p.httpProxyPort } }
        : { allowOutbound: false },
    // Shells need UI: upstream documents that PowerShell (5.1 and 7)
    // fails at startup under `ui.allowWindows: false` because of
    // win32k calls. cmd.exe is fine either way.
    ui: { allowWindows: isPowerShell(p.binShell) },
    timeoutMs: p.timeoutMs,
  }

  const sh = p.binShell ?? parseWindowsBinShell(undefined)
  const commandLine = buildShellCommandLine(sh, p.command)

  // 'process' is the ABSTRACT intent — the only spelling the SDK's
  // config compiler accepts (it resolves per-platform itself; the
  // concrete 'processcontainer' name is understood by wxc-exec's
  // parser but throws in createConfigFromPolicy).
  const cfg = sdk.buildSandboxPayload(
    commandLine,
    policy,
    p.cwd ?? process.cwd(),
    undefined,
    'process',
  )
  cfg.process.env = buildChildEnv(
    p,
    proxyEnv ??
      generateProxyEnvVars(
        p.httpProxyPort,
        p.socksProxyPort,
        p.caCertPath?.replace(/\\/g, '/'),
        p.proxyAuthToken,
      ),
  )
  return cfg
}

/**
 * Base OS variables copied from the broker into the sealed child env.
 * `encode_env_block(request.env)` is the child's COMPLETE environment
 * (base_container_runner.rs — the OS default block is used only when
 * env is empty), so everything a Windows process needs to merely run
 * must be enumerated. srt-win never has this problem: its child gets
 * a fresh OS logon-profile block and only an overlay rides on top.
 * TEMP/TMP are the broker's values on purpose — the same path
 * `buildMxcContainerConfig` grants readwrite, so `%TEMP%` inside the
 * child both resolves and is writable.
 */
const CHILD_BASE_ENV_VARS = [
  'SystemRoot',
  'windir',
  'SystemDrive',
  'ComSpec',
  'PATH',
  'PATHEXT',
  'TEMP',
  'TMP',
  'USERPROFILE',
  'NUMBER_OF_PROCESSORS',
  'PROCESSOR_ARCHITECTURE',
] as const

/**
 * The child's sealed environment as KEY=VALUE strings. Precedence
 * matches srt-win: OS base vars, then mask sentinels, then the
 * generated proxy set (so a caller masking HTTPS_PROXY cannot break
 * the sandbox's own plumbing), then GIT_CONFIG_* last so its COUNT
 * composition wins. Merged through one object so precedence is
 * decided HERE, last-wins — wxc-exec's `encode_env_block` keeps
 * duplicate keys (split+sort, no dedupe), and which duplicate a
 * child's getenv would see is not a contract to lean on.
 */
function buildChildEnv(
  p: MxcSandboxParams,
  proxyEnv: readonly string[],
): string[] {
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
    schannelCa: p.caCertPath !== undefined,
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
  return Object.entries(merged).map(([k, v]) => `${k}=${v}`)
}

/** Serialize a ContainerConfig for `--config-base64`. */
export function encodeMxcConfig(cfg: MxcContainerConfig): string {
  return Buffer.from(JSON.stringify(cfg), 'utf-8').toString('base64')
}

// ────────────────────────────────────────────────────────────────────────
// Wrap
// ────────────────────────────────────────────────────────────────────────

/**
 * Produce the `{argv, env}` to spawn under MXC BaseContainer. Same
 * contract as `wrapCommandWithSandboxWindows`: caller spawns `argv`
 * with `shell:false`. Async because the SDK is a lazily-imported
 * optional dependency.
 */
export async function wrapCommandWithSandboxMxc(
  p: MxcSandboxParams,
): Promise<{ argv: string[]; env: NodeJS.ProcessEnv }> {
  const proxyEnv = generateProxyEnvVars(
    p.httpProxyPort,
    p.socksProxyPort,
    p.caCertPath?.replace(/\\/g, '/'),
    p.proxyAuthToken,
  )
  const cfg = await buildMxcContainerConfig(p, proxyEnv)
  const argv = [p.mxc.exe, '--config-base64', encodeMxcConfig(cfg)]

  // Same CreateProcessW 32 767-WCHAR ceiling as srt-win — here the
  // whole policy (every path list) is inside ONE base64 argv element,
  // so large path lists are the pressure point, not the user command.
  // Base64 inflates by 4/3.
  const cmdlineEstimate = argv.reduce((n, a) => n + a.length + 3, 0)
  if (cmdlineEstimate > 30_000) {
    throw new Error(
      `MXC config is ~${cmdlineEstimate} chars on argv ` +
        `(CreateProcessW limit is 32 767). The base64 policy carries ` +
        `every path in the filesystem lists — trim allowRead/allowWrite/` +
        `denyRead/denyWrite.`,
    )
  }

  // Broker (wxc-exec) spawn env: our process env + the proxy set,
  // same as srt-win. The CHILD's env is the sealed process.env list
  // inside the config, not this.
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    ...envListToObject(proxyEnv),
  }
  logForDebugging(
    `[Sandbox Windows] mxc wrap: ${argv[0]} (config ${cmdlineEstimate} chars)`,
  )
  return { argv, env }
}

function isPowerShell(sh?: WindowsBinShell): boolean {
  if (!sh) return false
  const base = path.win32.basename(sh.exe).toLowerCase()
  return (
    base === 'pwsh' ||
    base === 'pwsh.exe' ||
    base === 'powershell' ||
    base === 'powershell.exe'
  )
}
