import * as fs from 'node:fs'
import * as net from 'node:net'
import * as path from 'node:path'
import { spawn, spawnSync } from 'node:child_process'
import { once } from 'node:events'
import { fileURLToPath } from 'node:url'
import { logForDebugging } from '../utils/debug.js'
import {
  generateProxyEnvVars,
  encodeSandboxedCommand,
  buildGitConfigEnv,
  normalizePathForSandbox,
  containsGlobCharsWin,
  expandGlobPattern,
  isUncPath,
} from './sandbox-utils.js'
// Re-export so existing tests (glob-expand.test.ts) and any
// out-of-tree caller keep their import path. `buildGitConfigEnv` is
// hoisted to sandbox-utils (cross-platform) but re-exported here for
// the existing `src/index.ts` surface.
export {
  containsGlobCharsWin,
  stripExtendedPathPrefix,
  buildGitConfigEnv,
  isUncPath,
} from './sandbox-utils.js'
import { certThumbprint, generateCa, validateCaPair } from './mitm-ca.js'
import type { SandboxDependencyCheck } from './linux-sandbox-utils.js'
import type { SrtWinConfig } from './sandbox-config.js'

/**
 * Windows sandbox backend.
 *
 * Network isolation is enforced by `srt-win.exe` — a Rust helper that
 * provisions a dedicated `srt-sandbox` local user account, installs a
 * machine-wide WFP filter set keyed on that account's SID, and
 * provides an `exec` subcommand that spawns the target via a two-hop
 * launch (broker → `CreateProcessWithLogonW(runner)` → runner →
 * restricted-token child) under `srt-sandbox`. The sandboxed child
 * reaches the host only via the JS mux proxy, which the caller
 * passes in via `--env`.
 *
 * The separate-user account structurally closes the surrogate-spawn
 * class (schtasks, `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`, BITS,
 * RunAs="Interactive User" COM): the child's token carries a
 * different user SID, so it cannot reach real-user processes, tasks
 * register under `srt-sandbox`, and the user-SID WFP filter fences
 * `srt-sandbox` egress regardless of how the child was spawned.
 *
 * This module is a thin wrapper around the `srt-win` CLI; all status
 * comes from live enumeration. There is no marker file.
 *
 * Filesystem rules (`denyRead`/`denyWrite`/`allowRead`/`allowWrite`)
 * are enforced via additive explicit ACEs for `<sb-SID>` — see
 * {@link grantWindowsAcl} / {@link stampWindowsAcl}.
 */

// ────────────────────────────────────────────────────────────────────
// Errors
// ────────────────────────────────────────────────────────────────────

/**
 * Stable machine-readable code carried on every
 * {@link WindowsSandboxError}. Consumers branch on `.code` instead of
 * prose-matching `.message` (message text is diagnostic and may change
 * between releases).
 */
export type WindowsSandboxErrorCode =
  /** `windows.srtWin.path` unset, or the configured/packaged exe is missing. */
  | 'srt_win_not_found'
  /** `spawnSync(srt-win)` itself failed (ENOENT, EACCES). */
  | 'spawn_failed'
  /** `srt-win` was killed by the spawn timeout (generic; see `install_timeout`). */
  | 'srt_win_timeout'
  /** A JSON-emitting `srt-win` subcommand exited non-zero. */
  | 'srt_win_nonzero'
  /** `srt-win` stdout was not valid JSON. */
  | 'srt_win_bad_json'
  /** {@link parseWindowsBinShell} rejected the `binShell` value. */
  | 'bin_shell_invalid'
  /** {@link verifyWindowsWfpEgress} could not bind a probe listener. */
  | 'wfp_verify_bind_failed'
  /** `srt-win wfp verify` produced no parseable result (timeout/kill). */
  | 'wfp_verify_unparseable'
  /** `srt-win wfp verify` proved direct egress SUCCEEDED (fence absent). */
  | 'wfp_fence_inactive'
  /** `srt-win wfp verify` was neither `blocked` nor `connected`. */
  | 'wfp_verify_inconclusive'
  /** `srt-win user trust-ca` exited non-zero. */
  | 'trust_ca_failed'
  /** `tlsTerminate` requested but no CA is installed for the sandbox user. */
  | 'trust_ca_not_installed'
  /** Installed CA thumbprint ≠ session CA thumbprint. */
  | 'trust_ca_thumbprint_mismatch'
  /** `srt-win install` exit 12 — WFP filter install failed. */
  | 'install_wfp_failed'
  /** `srt-win install` exit 14 — sandbox-user provisioning failed. */
  | 'install_user_failed'
  /** `srt-win install` exit 13 — different config under this sublayer. */
  | 'install_config_conflict'
  /** `srt-win install` exit 17 — ambient write-deny stamping failed. */
  | 'install_ambient_failed'
  /** `srt-win install` was killed by the spawn timeout (UAC left open). */
  | 'install_timeout'
  /** `srt-win install` failed with an unmapped exit code. */
  | 'install_failed'
  /** `srt-win uninstall` exited non-zero (not UAC-cancel). */
  | 'uninstall_failed'
  /** `srt-win acl stamp` exited non-zero. */
  | 'acl_stamp_failed'
  /** `srt-win acl grant` exited non-zero. */
  | 'acl_grant_failed'
  /** `srt-win exec` argv would exceed CreateProcessW's 32 767-char limit. */
  | 'argv_too_long'
  /** Sandbox user account / credential not present — run install. */
  | 'not_provisioned'
  /**
   * Working directory is on a mapped network drive; the sandbox
   * cannot start (per-user drive mappings don't exist under the
   * sandbox logon). `srt-win exec` exit **16**; parsed from its
   * stderr JSON by {@link parseWindowsSandboxError}, which carries
   * the failing root on `.drive` ({@link MappedDriveCwdError}).
   */
  | 'mapped_drive_cwd'

/**
 * Error thrown by the Windows sandbox backend. Carries a stable
 * {@link WindowsSandboxErrorCode} on `.code` so callers can branch
 * without prose-matching `.message`. `instanceof WindowsSandboxError`
 * narrows `.code` to the union.
 *
 * `.subcommand` is set on errors thrown from the `srt-win` spawn
 * chokepoint (`spawn_failed`, `srt_win_timeout`, `srt_win_nonzero`,
 * `srt_win_bad_json`) to the first CLI arg (e.g. `'install'`,
 * `'wfp'`) so a consumer can distinguish install-spawn-failed from
 * probe-spawn-failed without prose-matching. Unset elsewhere.
 */
export class WindowsSandboxError extends Error {
  readonly code: WindowsSandboxErrorCode
  readonly subcommand?: string
  constructor(
    code: WindowsSandboxErrorCode,
    message: string,
    subcommand?: string,
  ) {
    super(message)
    this.name = 'WindowsSandboxError'
    this.code = code
    this.subcommand = subcommand
  }
}

// ────────────────────────────────────────────────────────────────────
// Types
// ────────────────────────────────────────────────────────────────────

export const DEFAULT_WINDOWS_PROXY_PORT_RANGE: readonly [number, number] = [
  60080, 60089,
]

/**
 * `cannot-read` is the graceful-degrade state when BFE enumeration
 * is access-denied (it is admin-gated). The non-elevated readiness
 * check is {@link verifyWindowsWfpEgress}, not this enum.
 */
export type WindowsWfpStatus = 'absent' | 'installed' | 'cannot-read'

export interface WindowsWfpStatusResult {
  state: WindowsWfpStatus
  /** Live filter count from BFE enum; `0` on `cannot-read`. */
  filters: number
  /** `[low, high]` for the loopback PERMIT, when known. */
  portRange?: [number, number]
  /** Sandbox-user SID read from the first user-keyed filter tag. */
  userSid?: string
  /**
   * Populated only on `cannot-read` (BFE enumeration is admin-gated;
   * a non-elevated caller can't read it). The non-elevated readiness
   * check is {@link verifyWindowsWfpEgress}, not this enum.
   */
  hint?: string
}

/**
 * Result of `srt-win wfp verify` on success (exit 0, `blocked`) —
 * see {@link verifyWindowsWfpEgress}. Any other outcome throws, so
 * the tri-state is unobservable on the return path.
 */
export interface WindowsWfpVerifyResult {
  target: string
  /** Runner's stderr (carries the `BLOCKED (…)` diagnostic line). */
  stderr: string
}

/**
 * State of the `srt-sandbox` local account that `srt-win install`
 * provisions. The sandboxed child runs **as** this account.
 */
export interface WindowsSandboxUserStatus {
  /** The `srt-sandbox` local account exists. */
  provisioned: boolean
  /** `S-1-5-21-…` of `srt-sandbox`, when provisioned. */
  sid?: string
  /** The `sandbox-runtime-users` local group exists. */
  groupExists: boolean
  /** `S-1-5-21-…` of `sandbox-runtime-users`, when it exists. */
  groupSid?: string
  inBuiltinUsers: boolean
  inSandboxGroup: boolean
  hiddenFromLogon: boolean
  /**
   * The credential blob (`HKLM\SOFTWARE\sandbox-runtime\Cred`) is
   * present, decryptable, and readable by THIS process. False when
   * not yet written, or when called from inside the sandbox (the
   * Cred key carries an explicit DENY for `sandbox-runtime-users` —
   * machine-scope DPAPI alone is not a confidentiality boundary).
   */
  credPresent: boolean
  /** Setup marker schema version, when the marker row exists. */
  markerVersion?: number
  /**
   * The calling (real) user's SID — the broker's identity, surfaced
   * for diagnostics. The DENY-ACE trustee is `srt-sandbox`'s SID
   * ({@link sid}), not this. Always present.
   */
  realUserSid: string
  /**
   * SHA-1 thumbprint of the install-time CA, when one was
   * installed via `srt-win user trust-ca`. Uppercase hex.
   */
  caCertThumb?: string
  /** PEM-encoded install-time CA certificate, when present. */
  caCertPem?: string
}

/**
 * Inner shell to run `command` under, inside the sandbox: the
 * executable to spawn and the flag argv placed between it and the
 * user's command string. `exe` MUST originate from trusted host
 * configuration (user settings / install detection), NEVER from
 * workspace or repository content — the inner shell runs INSIDE the
 * sandbox so an unexpected path is not a sandbox-escape vector, but
 * it would still be an arbitrary-exec footgun if sourced from
 * untrusted input.
 *
 * Construct via {@link parseWindowsBinShell} — it is the SOLE
 * normalizer and the only place validation lives.
 */
export type WindowsBinShell = {
  /** Shell executable to spawn (absolute path when caller-supplied). */
  exe: string
  /** Argv placed between `exe` and the user's command string. */
  args: readonly string[]
}

const PWSH_FLAGS = ['-NoProfile', '-Command'] as const

/**
 * Sole normalizer from the cross-platform `binShell?: string |
 * WindowsBinShell` surface ({@link SandboxManager.wrapWithSandboxArgv})
 * to a spawnable `{exe, args}` pair. All validation lives here —
 * {@link wrapCommandWithSandboxWindows} consumes the result verbatim.
 *
 * String form: bare token (`'cmd'|'pwsh'|'powershell'`) resolves to
 * the default install; absolute path to `bash.exe`/`sh.exe`/
 * `pwsh.exe`/`powershell.exe`/`cmd.exe` keeps the caller's path with
 * the matching flag shape. Object form: `exe` must be absolute; `args`
 * pass through unchanged. Throws on anything else — no silent
 * fallback to cmd.exe.
 *
 * Uses `path.win32` explicitly so the function (and its unit test)
 * is platform-independent.
 */
export function parseWindowsBinShell(
  raw?: string | WindowsBinShell,
): WindowsBinShell {
  const systemRoot = process.env.SystemRoot ?? 'C:\\Windows'
  const cmdDefault: WindowsBinShell = {
    exe: path.win32.join(systemRoot, 'System32', 'cmd.exe'),
    args: ['/d', '/s', '/c'],
  }
  if (raw === undefined || raw === null) return cmdDefault
  if (typeof raw === 'object') {
    if (!path.win32.isAbsolute(raw.exe)) {
      throw new WindowsSandboxError(
        'bin_shell_invalid',
        `binShell.exe must be an absolute path ` +
          `(got ${JSON.stringify(raw.exe)})`,
      )
    }
    if (!Array.isArray(raw.args)) {
      throw new WindowsSandboxError(
        'bin_shell_invalid',
        `binShell.args must be an array (got ${JSON.stringify(raw.args)})`,
      )
    }
    return raw
  }
  const rawBase = path.win32.basename(raw)
  const base = rawBase.toLowerCase()
  const isAbs = path.win32.isAbsolute(raw)
  // A relative path with a directory component (`bin\bash.exe`) is
  // neither a token nor a resolved install — never silently degrade.
  if (!isAbs && raw !== rawBase) {
    throw new WindowsSandboxError(
      'bin_shell_invalid',
      `binShell string must be a bare token or an absolute path ` +
        `(got ${JSON.stringify(raw)})`,
    )
  }
  switch (base) {
    case 'bash':
    case 'bash.exe':
    case 'sh':
    case 'sh.exe':
      // Bare 'bash' is ambiguous (WSL vs Git Bash) — require the
      // resolved install path.
      if (!isAbs) {
        throw new WindowsSandboxError(
          'bin_shell_invalid',
          `binShell bash path must be absolute ` +
            `(got ${JSON.stringify(raw)}); pass the resolved Git Bash ` +
            `install path`,
        )
      }
      return { exe: raw, args: ['-c'] }
    case 'pwsh':
    case 'pwsh.exe':
      return { exe: isAbs ? raw : 'pwsh.exe', args: PWSH_FLAGS }
    case 'powershell':
    case 'powershell.exe':
      return {
        exe: isAbs
          ? raw
          : path.win32.join(
              systemRoot,
              'System32',
              'WindowsPowerShell',
              'v1.0',
              'powershell.exe',
            ),
        args: PWSH_FLAGS,
      }
    case 'cmd':
    case 'cmd.exe':
      return isAbs ? { exe: raw, args: cmdDefault.args } : cmdDefault
    default:
      throw new WindowsSandboxError(
        'bin_shell_invalid',
        `unrecognised binShell ${JSON.stringify(raw)}: expected ` +
          `'cmd' | 'powershell' | 'pwsh' or an absolute path to ` +
          `bash.exe/sh.exe/pwsh.exe/powershell.exe`,
      )
  }
}

export interface WindowsSandboxParams {
  command: string
  /** Attribution key encoded for violation correlation; defaults to
   *  `command`. See MacOSSandboxParams.commandId. */
  commandId?: string
  /**
   * JS HTTP proxy port — fed to `generateProxyEnvVars` for the env
   * overlay. With the in-process proxy this is the mux front-end
   * port (same as `socksProxyPort`).
   */
  httpProxyPort?: number
  /**
   * JS SOCKS proxy port — fed to `generateProxyEnvVars` for the env
   * overlay. With the in-process proxy this is the mux front-end
   * port (same as `httpProxyPort`).
   */
  socksProxyPort?: number
  /** Per-session proxy auth token; embedded in proxy env URLs. */
  proxyAuthToken?: string
  /**
   * `mode: 'mask'` credential env vars — sentinel values the
   * sandboxed child should see in place of the real credentials.
   * Threaded through the `--env` overlay so the runner forwards
   * them into the child's fresh profile env (the broker's own
   * environment never reaches the child, so an `env -u`-style
   * scrub is structurally moot — there is no `unsetEnvVars`).
   * Applied BEFORE the proxy assignments so the sandbox's own
   * proxy plumbing survives even if a caller masks one of those
   * names — same precedence as macOS/Linux.
   */
  setEnvVars?: Readonly<Record<string, string>>
  /**
   * Per-exec read-deny paths, applied via an additive
   * `(D;OICI;FA;;;<sb-SID>)` ACE under the `srt-win exec`
   * process's own PID and released after the child exits. Same
   * disk-first chokepoint as the session-level
   * {@link stampWindowsAcl}; same fail-closed semantics (exec
   * fails if any path cannot be stamped).
   *
   * Normalized concrete paths — globs expanded by the caller via
   * {@link expandWindowsFsPaths}, the same as session-level.
   * `srt-win exec`'s `canonicalize_ace_targets` hard-fails on a
   * glob (it never expands), so a `*`/`?` reaching this field is
   * a caller bug.
   */
  denyRead?: readonly string[]
  /** Per-exec write-deny paths — see {@link denyRead}. */
  denyWrite?: readonly string[]
  /**
   * Working directory the child starts in. Fed to
   * {@link buildGitConfigEnv} as a `safe.directory` entry so git
   * inside the sandbox accepts the real-user-owned working tree.
   * Default: `process.cwd()`.
   *
   * `srt-win exec` has no `--cwd` flag — the child's working
   * directory is whatever the caller passes as the spawn `{cwd:}`
   * option (broker `current_dir()` → runner `lpCurrentDirectory` →
   * child inherits). This field must match that spawn option so
   * `safe.directory` covers where git actually runs.
   */
  cwd?: string
  /**
   * Session-level write-granted paths (the resolved
   * `filesystem.allowWrite` set). Each becomes a `safe.directory`
   * entry — see {@link buildGitConfigEnv}.
   */
  allowWrite?: readonly string[]
  /**
   * Explicit `safe.directory` entries (from
   * `SandboxRuntimeConfig.git.safeDirectories`). Unioned with
   * {@link cwd} and {@link allowWrite} into the `safe.directory` set
   * — see {@link buildGitConfigEnv}. Use for the repo top-level when
   * launching from a subdirectory: the top-level must NOT go in
   * `allowWrite`, but git's dubious-ownership check keys on it.
   */
  gitSafeDirectories?: readonly string[]
  /**
   * Path to the TLS-termination trust bundle (the MITM CA + system
   * roots) — fed to {@link generateProxyEnvVars} so the child's
   * `NODE_EXTRA_CA_CERTS` / `CURL_CA_BUNDLE` / `SSL_CERT_FILE` /
   * etc. point at it. Backslashes are normalised to forward slashes
   * before emission so the value survives msys2 env conversion AND
   * is accepted by native tools.
   *
   * The env-var layer covers OpenSSL-backed clients (msys2 curl,
   * openssl-backed git, node, python, cargo). Schannel/.NET clients
   * that read the Windows certificate store exclusively (System32
   * `curl.exe`, `Invoke-WebRequest`, Go-built tools) trust via the
   * separate `srt-win user trust-ca` / {@link windowsTrustCa}
   * install-time write into the sandbox user's `CurrentUser\Root`.
   *
   * The caller is responsible for the sandbox user having read
   * access to this path — `sandbox-manager.ts`'s `initialize()`
   * pushes it into the session's `acl grant` read-set alongside the
   * working-tree grants.
   */
  caCertPath?: string
  /**
   * Suppress srt-win's informational stderr (progress lines,
   * per-exec-deny summary, seclogon-job note). Actual errors still
   * print. Default `true` — the host surfaces sandbox diagnostics
   * via its own debug log, not the child's stderr stream.
   */
  quiet?: boolean
  /**
   * Resolved `srt-win` spawn descriptor — from
   * {@link resolveSrtWin}. Omitting it throws (there is no implicit
   * vendor fallback); direct callers must resolve a path first.
   */
  srtWin?: SrtWinSpawn
  /**
   * Inner shell. Defaults to `parseWindowsBinShell(undefined)`
   * (System32 cmd.exe). The child's post-`args` content is
   * **passthrough** — `&` chains, `"…"`/`'…'` quotes exactly as
   * written. The security boundary is at the OUTER spawn (this argv
   * is spawned with `shell:false`); the inner shell runs INSIDE the
   * sandbox so its metachars are the user's tool. Construct via
   * {@link parseWindowsBinShell}.
   */
  binShell?: WindowsBinShell
}

// ────────────────────────────────────────────────────────────────────
// Binary resolution
// ────────────────────────────────────────────────────────────────────

function repoRoot(): string {
  // src/sandbox/windows-sandbox-utils.ts → repo root (compiled: dist/sandbox/…)
  const here = path.dirname(fileURLToPath(import.meta.url))
  return path.resolve(here, '..', '..')
}

const nodeArchToDir: Record<string, string> = { x64: 'x64', arm64: 'arm64' }

/**
 * The srt-win binary packaged with this module
 * (`vendor/srt-win/<arch>/srt-win.exe`, arch from `process.arch`).
 * Pass explicitly as `windows.srtWin.path` if you want the vendored
 * exe — {@link resolveSrtWin} never falls back to it implicitly.
 *
 * WARNING: in a dev checkout this file may live inside your sandbox
 * write grant — a sandboxed process could overwrite it; prefer a
 * binary outside any grant (e.g. your own signed executable).
 */
export const VENDORED_SRT_WIN_EXE: string = path.join(
  repoRoot(),
  'vendor',
  'srt-win',
  nodeArchToDir[process.arch] ?? process.arch,
  'srt-win.exe',
)

/**
 * Locate a built `srt-win.exe` for development/CI. Checks, in order:
 *   1. `<root>/vendor/srt-win/{arch}/srt-win.exe` (prebuilt —
 *      {@link VENDORED_SRT_WIN_EXE}).
 *   2. `<root>/vendor/srt-win-src/target/release/srt-win.exe` (local
 *      `cargo build --release`).
 *
 * `<root>` is {@link repoRoot} — `__dirname/../..`, which resolves to the
 * repo root from `src/sandbox/` and `dist/sandbox/` alike, and to the
 * package root when installed under `node_modules`.
 *
 * This is an explicit helper — nothing calls it as an ambient
 * default. Production callers set `windows.srtWin.path` (their own
 * binary, or {@link VENDORED_SRT_WIN_EXE}); see {@link resolveSrtWin}.
 *
 * @throws if neither candidate exists.
 */
export function getSrtWinPath(): string {
  const root = repoRoot()
  const arch = nodeArchToDir[process.arch]
  const candidates: string[] = []
  if (arch) {
    candidates.push(path.join(root, 'vendor', 'srt-win', arch, 'srt-win.exe'))
  }
  candidates.push(
    path.join(
      root,
      'vendor',
      'srt-win-src',
      'target',
      'release',
      'srt-win.exe',
    ),
  )
  for (const c of candidates) {
    if (fs.existsSync(c)) return c
  }
  throw new WindowsSandboxError(
    'srt_win_not_found',
    `srt-win.exe not found. Set windows.srtWin.path or build with ` +
      `\`cargo build --release --manifest-path vendor/srt-win-src/Cargo.toml\`. ` +
      `Looked in: ${candidates.join(', ')}`,
  )
}

/**
 * `argv[1]` sentinel a multicall embedder's dispatcher matches
 * against to route into `srt_win::run_from_args`. Mirrors the Rust
 * `srt_win::SRT_WIN_DISPATCH_ARG1`; the two MUST stay in sync.
 * `run_from_args` strips it before clap, so the standalone binary
 * accepts it harmlessly.
 */
export const SRT_WIN_DISPATCH_ARG1 = '--srt-win'

/**
 * Resolved `srt-win` spawn descriptor — the executable to load plus
 * the leading arguments that carry the dispatch sentinel. Threaded
 * to every spawn site so {@link resolveSrtWin} runs once (at
 * `initialize()`) instead of re-`stat`ing on every helper call.
 */
export type SrtWinSpawn = Readonly<{
  exe: string
  prependArgs: readonly string[]
}>

/**
 * Resolve the `srt-win` spawn target from config. `cfg.path` is
 * required and used verbatim; {@link SRT_WIN_DISPATCH_ARG1} is
 * prepended so a multicall dispatcher routes on `argv[1]` (the
 * standalone binary strips it harmlessly).
 *
 * The path must be explicit because the packaged exe lives under
 * the package root, which in a dev checkout sits inside the
 * working-tree write grant (a planted `srt-win.exe` there would be
 * spawned as the broker). Callers that want the packaged binary
 * pass {@link VENDORED_SRT_WIN_EXE}.
 *
 * @throws if `cfg.path` is unset or names a missing file.
 */
export function resolveSrtWin(cfg?: SrtWinConfig): SrtWinSpawn {
  if (cfg?.path === undefined) {
    throw new WindowsSandboxError(
      'srt_win_not_found',
      `no srt-win path configured; set windows.srtWin.path (e.g. to the ` +
        `exported VENDORED_SRT_WIN_EXE constant for the packaged binary)`,
    )
  }
  if (!fs.existsSync(cfg.path)) {
    throw new WindowsSandboxError(
      'srt_win_not_found',
      `windows.srtWin.path is set to '${cfg.path}' but the file does ` +
        `not exist`,
    )
  }
  return { exe: cfg.path, prependArgs: [SRT_WIN_DISPATCH_ARG1] }
}

// ────────────────────────────────────────────────────────────────────
// Internal: spawn helpers
// ────────────────────────────────────────────────────────────────────

interface RunResult {
  status: number | null
  signal: NodeJS.Signals | null
  stdout: string
  stderr: string
}

interface RunOpts {
  timeoutMs?: number
  stdin?: string
  srtWin?: SrtWinSpawn
}

function runSrtWin(args: string[], opts: RunOpts = {}): RunResult {
  // Callers must thread `srtWin` (SandboxManager resolves once at
  // `initialize()`); the argless `resolveSrtWin()` throws, telling a
  // direct helper caller to pass an explicit path.
  const { exe, prependArgs } = opts.srtWin ?? resolveSrtWin()
  const r = spawnSync(exe, [...prependArgs, ...args], {
    encoding: 'utf8',
    windowsHide: true,
    timeout: opts.timeoutMs ?? 15_000,
    ...(opts.stdin !== undefined ? { input: opts.stdin } : {}),
  })
  if (r.error) {
    // ETIMEDOUT means the process ran and spawnSync killed it after
    // `timeout` — throw a distinct code so every caller surfaces
    // "timed out" instead of an opaque `exited null`. Callers with a
    // more specific mapping (e.g. `install_timeout`) catch by code.
    // Any other `r.error` (ENOENT, EACCES, EINVAL) means the process
    // never started.
    if ((r.error as NodeJS.ErrnoException).code === 'ETIMEDOUT') {
      throw new WindowsSandboxError(
        'srt_win_timeout',
        `srt-win ${args.join(' ')} timed out after ` +
          `${opts.timeoutMs ?? 15_000}ms` +
          (r.signal ? ` (killed by ${r.signal})` : ''),
        args[0],
      )
    }
    throw new WindowsSandboxError(
      'spawn_failed',
      `srt-win ${args[0]}: spawn failed: ${r.error.message}`,
      args[0],
    )
  }
  return {
    status: r.status,
    signal: r.signal,
    stdout: (r.stdout ?? '').trim(),
    stderr: (r.stderr ?? '').trim(),
  }
}

/**
 * Async twin of {@link runSrtWin}: same signature, same result shape,
 * but the event loop stays live. Prefer it for any call reachable
 * from a UI/render path — the sync variant `spawnSync`-blocks, which
 * on Windows can be seconds when Defender cold-scans `srt-win.exe`.
 */
function runSrtWinAsync(
  args: string[],
  opts: RunOpts = {},
): Promise<RunResult> {
  const { exe, prependArgs } = opts.srtWin ?? resolveSrtWin()
  const timeoutMs = opts.timeoutMs ?? 15_000
  return new Promise((resolve, reject) => {
    const child = spawn(exe, [...prependArgs, ...args], {
      windowsHide: true,
    })
    // Manual timer instead of spawn's `timeout` option so a timeout
    // is distinguishable from an external kill — parity with the
    // sync variant's ETIMEDOUT branch (same code, same message).
    let timedOut = false
    const timer =
      timeoutMs > 0
        ? setTimeout(() => {
            timedOut = true
            child.kill()
          }, timeoutMs)
        : undefined
    let stdout = ''
    let stderr = ''
    child.stdout?.setEncoding('utf8').on('data', d => (stdout += d))
    child.stderr?.setEncoding('utf8').on('data', d => (stderr += d))
    // Swallow EPIPE if the child dies before the stdin write drains.
    child.stdin?.on('error', () => {}).end(opts.stdin)
    child.once('error', e => {
      clearTimeout(timer)
      reject(
        new WindowsSandboxError(
          'spawn_failed',
          `srt-win ${args[0]}: spawn failed: ${e.message}`,
          args[0],
        ),
      )
    })
    child.once('close', (status, signal) => {
      clearTimeout(timer)
      if (timedOut) {
        reject(
          new WindowsSandboxError(
            'srt_win_timeout',
            `srt-win ${args.join(' ')} timed out after ${timeoutMs}ms` +
              (signal ? ` (killed by ${signal})` : ''),
            args[0],
          ),
        )
        return
      }
      resolve({ status, signal, stdout: stdout.trim(), stderr: stderr.trim() })
    })
  })
}

function parseSrtWinJson<T>(args: string[], r: RunResult): T {
  if (r.status !== 0) {
    throw new WindowsSandboxError(
      'srt_win_nonzero',
      `srt-win ${args.join(' ')} exited ${r.status}: ${r.stderr || r.stdout}`,
      args[0],
    )
  }
  try {
    return JSON.parse(r.stdout) as T
  } catch (e) {
    throw new WindowsSandboxError(
      'srt_win_bad_json',
      `srt-win ${args.join(' ')}: unparseable JSON output ` +
        `${JSON.stringify(r.stdout)}: ${(e as Error).message}`,
      args[0],
    )
  }
}

function runSrtWinJson<T>(args: string[], opts?: RunOpts): T {
  return parseSrtWinJson(args, runSrtWin(args, opts))
}

async function runSrtWinJsonAsync<T>(
  args: string[],
  opts?: RunOpts,
): Promise<T> {
  return parseSrtWinJson(args, await runSrtWinAsync(args, opts))
}

/**
 * As {@link runSrtWinJson} but parses stdout BEFORE checking the
 * exit code, so a non-zero exit with the per-path JSON intact
 * still surfaces every entry. For best-effort teardown helpers
 * (`acl restore`/`acl revoke`).
 */
function runSrtWinJsonAllowFail<T>(
  args: string[],
  opts: RunOpts,
): { ok: boolean; json: T; stderr: string } {
  const r = runSrtWin(args, opts)
  let json: T
  try {
    json = JSON.parse(r.stdout) as T
  } catch (e) {
    throw new WindowsSandboxError(
      'srt_win_bad_json',
      `srt-win ${args.join(' ')}: unparseable JSON output ` +
        `${JSON.stringify(r.stdout)}: ${(e as Error).message}`,
      args[0],
    )
  }
  return { ok: r.status === 0, json, stderr: r.stderr }
}

// ────────────────────────────────────────────────────────────────────
// Status / install API
// ────────────────────────────────────────────────────────────────────

/** Shape of `srt-win wfp status` (and `srt-win status .wfp`) stdout. */
type RawWfpStatus = {
  state: WindowsWfpStatus
  filters: number
  port_range?: [number, number]
  user_sid?: string
  hint?: string
}

function wfpStatusArgs(sublayerGuid?: string): string[] {
  const args = ['wfp', 'status']
  if (sublayerGuid) args.push('--sublayer-guid', sublayerGuid)
  return args
}

function mapWfpStatus(raw: RawWfpStatus): WindowsWfpStatusResult {
  return {
    state: raw.state,
    filters: raw.filters,
    ...(raw.port_range && { portRange: raw.port_range }),
    ...(raw.user_sid && { userSid: raw.user_sid }),
    ...(raw.hint && { hint: raw.hint }),
  }
}

/** Shape of `srt-win user status` (and `srt-win status .user`) stdout. */
type RawUserStatus = {
  user: {
    exists: boolean
    sid?: string
    group_exists: boolean
    group_sid?: string
    in_builtin_users: boolean
    in_sandbox_group: boolean
    hidden_from_logon: boolean
  }
  cred_present: boolean
  marker_version?: number | null
  real_user_sid: string
  ca_cert_thumb?: string | null
  ca_cert_pem?: string | null
}

function mapUserStatus(raw: RawUserStatus): WindowsSandboxUserStatus {
  return {
    provisioned: raw.user.exists,
    ...(raw.user.sid && { sid: raw.user.sid }),
    groupExists: raw.user.group_exists,
    ...(raw.user.group_sid && { groupSid: raw.user.group_sid }),
    inBuiltinUsers: raw.user.in_builtin_users,
    inSandboxGroup: raw.user.in_sandbox_group,
    hiddenFromLogon: raw.user.hidden_from_logon,
    credPresent: raw.cred_present,
    ...(typeof raw.marker_version === 'number' && {
      markerVersion: raw.marker_version,
    }),
    realUserSid: raw.real_user_sid,
    ...(raw.ca_cert_thumb && { caCertThumb: raw.ca_cert_thumb }),
    ...(raw.ca_cert_pem && { caCertPem: raw.ca_cert_pem }),
  }
}

/** Combined result of `srt-win status` — see {@link checkWindowsSandboxStatus}. */
export interface WindowsSandboxStatus {
  user: WindowsSandboxUserStatus
  wfp: WindowsWfpStatusResult
}

/**
 * Query sandbox-user provisioning state AND the WFP filter set in a
 * single `srt-win status` spawn — the same objects
 * {@link getWindowsSandboxUserStatus} and {@link getWindowsWfpStatus}
 * return, without paying two subprocess round-trips. Does not require
 * elevation (WFP degrades to `cannot-read` for a non-elevated caller;
 * see {@link WindowsWfpStatusResult.hint}).
 */
export function checkWindowsSandboxStatus(
  opts: { sublayerGuid?: string; srtWin?: SrtWinSpawn } = {},
): WindowsSandboxStatus {
  const args = ['status']
  if (opts.sublayerGuid) args.push('--sublayer-guid', opts.sublayerGuid)
  const raw = runSrtWinJson<{ user: RawUserStatus; wfp: RawWfpStatus }>(args, {
    srtWin: opts.srtWin,
  })
  return { user: mapUserStatus(raw.user), wfp: mapWfpStatus(raw.wfp) }
}

/** Async twin of {@link checkWindowsSandboxStatus}. */
export async function checkWindowsSandboxStatusAsync(
  opts: { sublayerGuid?: string; srtWin?: SrtWinSpawn } = {},
): Promise<WindowsSandboxStatus> {
  const args = ['status']
  if (opts.sublayerGuid) args.push('--sublayer-guid', opts.sublayerGuid)
  const raw = await runSrtWinJsonAsync<{
    user: RawUserStatus
    wfp: RawWfpStatus
  }>(args, { srtWin: opts.srtWin })
  return { user: mapUserStatus(raw.user), wfp: mapWfpStatus(raw.wfp) }
}

/**
 * Query the WFP filter set under the given sublayer via live BFE
 * enumeration. `installed` means at least one srt-win-tagged
 * `block-user` filter is present. Detection is **tag-based**
 * (providerData JSON); filters installed by other tooling without the
 * tag are not counted.
 *
 * BFE enumeration is admin-gated — a non-elevated caller gets
 * `state:"cannot-read"` with a `hint` (not an error). The
 * non-elevated readiness check is {@link verifyWindowsWfpEgress}.
 *
 * Prefer {@link getWindowsWfpStatusAsync}; this variant
 * `spawnSync`-blocks the event loop.
 */
export function getWindowsWfpStatus(
  opts: { sublayerGuid?: string; srtWin?: SrtWinSpawn } = {},
): WindowsWfpStatusResult {
  return mapWfpStatus(
    runSrtWinJson<RawWfpStatus>(wfpStatusArgs(opts.sublayerGuid), {
      srtWin: opts.srtWin,
    }),
  )
}

/** Async twin of {@link getWindowsWfpStatus}. */
export async function getWindowsWfpStatusAsync(
  opts: { sublayerGuid?: string; srtWin?: SrtWinSpawn } = {},
): Promise<WindowsWfpStatusResult> {
  return mapWfpStatus(
    await runSrtWinJsonAsync<RawWfpStatus>(wfpStatusArgs(opts.sublayerGuid), {
      srtWin: opts.srtWin,
    }),
  )
}

/**
 * Behavioral proof that the WFP egress fence is active for the
 * sandbox user. Binds a local listener on an ephemeral loopback port
 * outside the WFP loopback-permit range, then spawns `srt-win
 * runner` as the sandbox user (via `CreateProcessWithLogonW`) to
 * attempt a direct TCP connect to it. The WFP block-user filter
 * fires at `ALE_AUTH_CONNECT` — before any packet leaves — so an
 * active fence yields WSAEACCES immediately and a missing fence lets
 * the connect through (the kernel completes the handshake against
 * the listening socket's backlog; no event-loop tick required, so
 * the synchronous `runSrtWin` is safe). Does not require elevation
 * and does not depend on any external host.
 *
 * `initialize()` calls this once per session, so a stale install
 * (sandbox user provisioned but filters since removed) fails closed
 * at session start instead of running every exec with full egress.
 *
 * @param opts.target overrides the probe target (skips the local
 *   listener bind).
 * @param opts.proxyPortRange the WFP loopback-permit range the
 *   listener must avoid. Default
 *   {@link DEFAULT_WINDOWS_PROXY_PORT_RANGE}.
 * @throws on any outcome other than `blocked` (exit 0).
 */
export async function verifyWindowsWfpEgress(
  opts: {
    target?: string
    proxyPortRange?: readonly [number, number]
    srtWin?: SrtWinSpawn
  } = {},
): Promise<WindowsWfpVerifyResult> {
  let target = opts.target
  let server: net.Server | undefined
  if (!target) {
    // Bind ephemeral; retry if it lands inside the WFP
    // loopback-permit range (a port in-range would be PERMITted
    // even with the fence active → false `connected`).
    const [lo, hi] = opts.proxyPortRange ?? DEFAULT_WINDOWS_PROXY_PORT_RANGE
    for (let i = 0; i < 5; i++) {
      const s = net.createServer()
      s.listen(0, '127.0.0.1')
      await once(s, 'listening')
      const p = (s.address() as net.AddressInfo).port
      if (p < lo || p > hi) {
        server = s
        target = `127.0.0.1:${p}`
        break
      }
      s.close()
    }
    if (!target) {
      throw new WindowsSandboxError(
        'wfp_verify_bind_failed',
        `verifyWindowsWfpEgress: could not bind a loopback ` +
          `listener outside the WFP permit range [${lo},${hi}] in ` +
          `5 attempts`,
      )
    }
  }
  try {
    // 30s: first call after install may create the sandbox user's
    // profile (LOGON_WITH_PROFILE) via CreateProcessWithLogonW —
    // same budget as windowsTrustCa, plus the runner's own 2s
    // connect timeout.
    const r = runSrtWin(['wfp', 'verify', '--target', target], {
      timeoutMs: 30_000,
      srtWin: opts.srtWin,
    })
    logForDebugging(
      `[Sandbox Windows] wfp verify exit=${r.status}: ${r.stderr || r.stdout}`,
    )
    let raw: { egress_probe: string; target: string }
    try {
      raw = JSON.parse(r.stdout)
    } catch {
      // Timeout is thrown as `srt_win_timeout` by `runSrtWin` before
      // this parse; status=null here means an external signal.
      // Include signal + stderr so the CI log self-explains instead
      // of just `exited null with unparseable output ""`.
      throw new WindowsSandboxError(
        'wfp_verify_unparseable',
        `WFP egress fence could not be verified — \`srt-win wfp ` +
          `verify\` exited ${r.status}` +
          (r.signal ? ` (signal ${r.signal})` : '') +
          ` with unparseable output ${JSON.stringify(r.stdout)} ` +
          `(stderr: ${JSON.stringify(r.stderr)})`,
      )
    }
    if (r.status === 3) {
      throw new WindowsSandboxError(
        'wfp_fence_inactive',
        `WFP egress fence is not active — direct outbound from the ` +
          `sandbox user to ${raw.target} succeeded. Re-run ` +
          `\`srt-win install\` (one UAC prompt). (${r.stderr})`,
      )
    }
    if (r.status !== 0) {
      throw new WindowsSandboxError(
        'wfp_verify_inconclusive',
        `WFP egress fence could not be verified — probe to ` +
          `${raw.target} was '${raw.egress_probe}' (exit ` +
          `${r.status}). The fence may be absent. Re-run \`srt-win ` +
          `install\`. (${r.stderr})`,
      )
    }
    return { target: raw.target, stderr: r.stderr }
  } finally {
    server?.close()
  }
}

/**
 * Query the sandbox user account's provisioning state. Each field
 * is independently observed so a half-provisioned install (e.g.
 * user exists but credential file missing) is distinguishable.
 * Does not require elevation.
 *
 * Prefer {@link getWindowsSandboxUserStatusAsync}; this variant
 * `spawnSync`-blocks the event loop.
 */
export function getWindowsSandboxUserStatus(
  opts: { srtWin?: SrtWinSpawn } = {},
): WindowsSandboxUserStatus {
  return mapUserStatus(
    runSrtWinJson<RawUserStatus>(['user', 'status'], { srtWin: opts.srtWin }),
  )
}

/** Async twin of {@link getWindowsSandboxUserStatus}. */
export async function getWindowsSandboxUserStatusAsync(
  opts: { srtWin?: SrtWinSpawn } = {},
): Promise<WindowsSandboxUserStatus> {
  return mapUserStatus(
    await runSrtWinJsonAsync<RawUserStatus>(['user', 'status'], {
      srtWin: opts.srtWin,
    }),
  )
}

/**
 * Read back the persistent MITM CA the sandbox was installed with
 * (via `srt-win user trust-ca` / {@link windowsTrustCa}).
 * Returns `null` when no CA was installed. The PEM is what `srt-win
 * user status` reconstructs from the DER recorded in the registry.
 *
 * On Windows, `tlsTerminate` requires this CA to be present in the
 * sandbox user's `CurrentUser\Root` (schannel-level trust is an
 * install-time concern, not per-session); the host calls this from
 * `initialize()` to fail early with an actionable message when it
 * isn't.
 *
 * @param status pass an already-fetched
 *   {@link getWindowsSandboxUserStatus} result to avoid a second
 *   `srt-win user status` spawn.
 */
export function getWindowsSandboxCaCert(
  status?: WindowsSandboxUserStatus,
  opts: { srtWin?: SrtWinSpawn } = {},
): { pem: string; thumb: string } | null {
  const u = status ?? getWindowsSandboxUserStatus(opts)
  if (!u.caCertThumb || !u.caCertPem) return null
  return { pem: u.caCertPem, thumb: u.caCertThumb }
}

/**
 * Install (or replace) the MITM CA in the **sandbox user's**
 * `CurrentUser\Root` and record it in the registry (so
 * {@link getWindowsSandboxCaCert} surfaces its thumbprint + PEM).
 * Thin wrapper around `srt-win user trust-ca <path>`. Does NOT
 * require elevation. Persistent until {@link uninstallWindowsSandbox}
 * deletes the sandbox user's profile.
 *
 * The CA has a separate lifecycle from {@link installWindowsSandbox}
 * — install provisions the account/filters and never touches the CA;
 * call this AFTER install when `tlsTerminate` will be used.
 *
 * @throws when the sandbox user is not provisioned, the file is not a
 *   parseable X.509 certificate, or the registry write into the
 *   sandbox user's hive fails.
 */
export function windowsTrustCa(
  caCertPath: string,
  opts: { srtWin?: SrtWinSpawn } = {},
): void {
  // 60s: first call may create the sandbox user's profile
  // (LOGON_WITH_PROFILE) via the one-shot CreateProcessWithLogonW.
  const r = runSrtWin(['user', 'trust-ca', caCertPath], {
    timeoutMs: 60_000,
    srtWin: opts.srtWin,
  })
  checkTrustCaResult(caCertPath, r)
}

/** Async twin of {@link windowsTrustCa} — identical argv and errors. */
export async function windowsTrustCaAsync(
  caCertPath: string,
  opts: { srtWin?: SrtWinSpawn } = {},
): Promise<void> {
  const r = await runSrtWinAsync(['user', 'trust-ca', caCertPath], {
    timeoutMs: 60_000,
    srtWin: opts.srtWin,
  })
  checkTrustCaResult(caCertPath, r)
}

function checkTrustCaResult(caCertPath: string, r: RunResult): void {
  logForDebugging(
    `[Sandbox Windows] user trust-ca exit=${r.status}: ${r.stderr || r.stdout}`,
  )
  if (r.status !== 0) {
    throw new WindowsSandboxError(
      'trust_ca_failed',
      `srt-win user trust-ca '${caCertPath}' failed (exit ` +
        `${r.status}): ${r.stderr || r.stdout}`,
    )
  }
}

/**
 * The machine-wide state directory `%ProgramData%\sandbox-runtime`,
 * mirroring `srt-win`'s `state_db::machine_store_dir()` exactly.
 * Since the registry move it hosts only the managed CA key material
 * (`ca\`), which must stay on the filesystem because the broker's
 * unelevated generate-if-absent self-heal rewrites it; the
 * credential, marker, and CA record live in
 * `HKLM\SOFTWARE\sandbox-runtime`. Created and ACL'd by the
 * elevated `srt-win install`: Administrators own it, BUILTIN\Users
 * have modify, and the sandbox group carries an explicit
 * `(OI)(CI)` DENY.
 */
export function windowsStateDir(): string {
  const programData = process.env.ProgramData
  if (!programData) throw new Error('ProgramData is not set')
  return path.win32.join(programData, 'sandbox-runtime')
}

/** Result of {@link ensurePersistentWindowsCa}. */
export type WindowsPersistentCa = {
  /**
   * PEM certificate — pass to `createMitmCA({caCertPem, caKeyPem})` so
   * the caller doesn't re-read from disk.
   */
  certPem: string
  /** PEM private key — see {@link certPem}. */
  keyPem: string
  /**
   * `cert.pem` on disk (derived from `ca.json`; exists so
   * {@link windowsTrustCa} and diagnostic tooling have a path).
   */
  certPath: string
  /** `key.pem` on disk (derived from `ca.json`). */
  keyPath: string
  /** Uppercase-hex SHA-1 (matches `srt-win user status` `caCertThumb`). */
  thumbprint: string
  /**
   * `true` when this call generated a fresh CA (first run, `force`, or
   * the on-disk pair was invalid/expiring); `false` when the existing
   * on-disk pair was reused.
   */
  generated: boolean
  /**
   * `true` when this call wrote the CA into the sandbox user's
   * `CurrentUser\Root` (via {@link windowsTrustCa}) — always on
   * `generated`, and on reuse when the sandbox user's installed
   * thumbprint didn't already match. Callers holding a
   * {@link WindowsSandboxUserStatus} fetched before this call should
   * treat its `caCertThumb` as stale when `trusted` is true.
   */
  trusted: boolean
}

/**
 * Generate-if-absent a persistent MITM CA under
 * `{windowsStateDir()}\ca\` and ensure it is trusted in
 * the sandbox user's `CurrentUser\Root`. Idempotent and unelevated:
 * a second call with a valid on-disk pair returns it with
 * `generated: false`. On the machine store the `ca\` subdir is
 * user-writable by design (BUILTIN\Users modify, inherited from the
 * install-ACL'd store), so this self-heal keeps working without
 * admin rights for every user of the machine.
 *
 * **Storage.** The pair lives in a single `ca.json = {certPem,
 * keyPem}` written atomically (tmp+rename) and re-read after every
 * write, so it is always a matched pair and concurrent brokers
 * converge on whichever rename landed last. `cert.pem`/`key.pem` are
 * derived copies for diagnostic tooling; `ca.json` is the source of
 * truth.
 *
 * **Key custody is broker-side.** The MITM proxy runs as the real
 * user, so the sandbox user never needs to read the key. The `ca/`
 * subdirectory inherits the machine store's `(OI)(CI)` DACL, which
 * carries an explicit `sandbox-runtime-users` DENY (see
 * {@link windowsStateDir}), so `ca.json`/`key.pem` are unreadable
 * from inside the sandbox with no per-file ACL work here. The key
 * IS readable (and replaceable) by other REAL local users — an
 * accepted trade-off of the shared store: the sandbox account is
 * network-confined by SID-keyed WFP filters regardless of who
 * spawns it. The certificate reaches the sandboxed child via the
 * schannel registry write ({@link windowsTrustCa}) and the
 * trust-bundle env vars — never via these files.
 *
 * `SandboxManager.initialize()` calls this on Windows when
 * `tlsTerminate` is enabled without an explicit
 * `caCertPath`/`caKeyPath`, then feeds the returned PEMs to
 * `createMitmCA` — so an embedder gets a stable CA across restarts
 * without orchestrating generation, storage, or trust itself. Explicit
 * paths in config bypass this entirely.
 *
 * @param opts.force regenerate even if a valid pair is on disk.
 * @param opts.status pass an already-fetched
 *   {@link getWindowsSandboxUserStatus} result to skip the
 *   provisioning check and avoid re-spawning `srt-win user status`
 *   for the trust reconcile.
 * @param opts.dir override the CA directory (tests). Default
 *   `windowsStateDir()/ca`.
 * @param opts.regenerateWithinDays regenerate if `notAfter` is within
 *   this many days. Default 30.
 * @throws when the sandbox user is not provisioned (run
 *   {@link installWindowsSandbox} first), or the CA directory cannot
 *   be created.
 */
export async function ensurePersistentWindowsCa(
  opts: {
    force?: boolean
    status?: WindowsSandboxUserStatus
    dir?: string
    regenerateWithinDays?: number
    srtWin?: SrtWinSpawn
  } = {},
): Promise<WindowsPersistentCa> {
  // Provisioning gate. The `ca/` subdirectory's whole custody story
  // depends on inheriting the state-DB dir's stamped DACL — which
  // `srt-win install` creates. Never mkdir the state dir here.
  const status =
    opts.status ??
    (await getWindowsSandboxUserStatusAsync({ srtWin: opts.srtWin }))
  if (!status.provisioned || !status.credPresent) {
    throw new Error(
      `ensurePersistentWindowsCa: sandbox user is not provisioned ` +
        `(user=${status.provisioned}, cred=${status.credPresent}). ` +
        `Run \`npx sandbox-runtime windows-install\` first.`,
    )
  }
  const stateDir = opts.dir ? undefined : windowsStateDir()
  if (stateDir && !fs.existsSync(stateDir)) {
    throw new Error(
      `ensurePersistentWindowsCa: state directory ${stateDir} does not ` +
        `exist. Run \`npx sandbox-runtime windows-install\` first.`,
    )
  }
  const dir = opts.dir ?? path.win32.join(stateDir!, 'ca')
  const jsonPath = path.join(dir, 'ca.json')
  const certPath = path.join(dir, 'cert.pem')
  const keyPath = path.join(dir, 'key.pem')
  const horizonMs = (opts.regenerateWithinDays ?? 30) * 24 * 60 * 60 * 1000

  // tmp+rename atomic write. Node's `renameSync` on Windows is
  // libuv's `MoveFileExW(…, MOVEFILE_REPLACE_EXISTING)` — an atomic
  // same-volume replace — so `p` is either its previous content or
  // the full new content, never partial.
  const atomicWrite = (p: string, data: string): void => {
    const tmp = `${p}.tmp.${process.pid}`
    fs.writeFileSync(tmp, data)
    fs.renameSync(tmp, p)
  }

  // Shared return path: write the derived cert.pem/key.pem siblings
  // (tooling-only — trust-ca never reads them), reconcile trust, and
  // assemble the result. Trust is idempotent and ADDITIVE: `srt-win
  // user trust-ca` writes a per-thumbprint registry key (a rotation
  // adds the new cert, prior ones stay trusted); the state-DB
  // `ca_cert` column tracks the latest.
  const finish = async (
    certPem: string,
    keyPem: string,
    thumbprint: string,
    generated: boolean,
  ): Promise<WindowsPersistentCa> => {
    atomicWrite(certPath, certPem)
    atomicWrite(keyPath, keyPem)
    const trusted = generated || status.caCertThumb !== thumbprint
    if (trusted) {
      // Trust from a per-call unique temp, never a shared mutable
      // path — a concurrent broker's write to `cert.pem` could
      // otherwise swap the bytes between our write and `srt-win user
      // trust-ca`'s read, leaving the registry trusting a different
      // cert than this session's proxy signs with.
      const t = path.join(dir, `.trust.${process.pid}.${Date.now()}.pem`)
      fs.writeFileSync(t, certPem)
      try {
        await windowsTrustCaAsync(t, { srtWin: opts.srtWin })
      } finally {
        fs.rmSync(t, { force: true })
      }
    }
    logForDebugging(
      `[Sandbox Windows] persistent CA ` +
        `${generated ? 'generated' : 'reused'} (thumb=${thumbprint}` +
        `${trusted && !generated ? ', trust reconciled' : ''})`,
    )
    return {
      certPem,
      keyPem,
      certPath,
      keyPath,
      thumbprint,
      generated,
      trusted,
    }
  }

  // Read+validate helper. Any read/parse/validate failure returns
  // undefined (never throws) so a corrupt on-disk pair is not an
  // error the embedder has to handle.
  const readValid = ():
    | { certPem: string; keyPem: string; thumbprint: string; notAfter: Date }
    | undefined => {
    let stored: { certPem?: unknown; keyPem?: unknown }
    try {
      stored = JSON.parse(fs.readFileSync(jsonPath, 'utf8'))
    } catch (err) {
      logForDebugging(
        `[Sandbox Windows] persistent CA ca.json unreadable ` +
          `(${(err as Error).message})`,
        { level: 'warn' },
      )
      return undefined
    }
    if (typeof stored.certPem !== 'string' || typeof stored.keyPem !== 'string')
      return undefined
    const v = validateCaPair(stored.certPem, stored.keyPem)
    if (!v.ok) {
      logForDebugging(`[Sandbox Windows] persistent CA invalid (${v.reason})`, {
        level: 'warn',
      })
      return undefined
    }
    return {
      certPem: stored.certPem,
      keyPem: stored.keyPem,
      thumbprint: v.thumbprint,
      notAfter: v.notAfter,
    }
  }

  // Reuse when ca.json exists, validates, and isn't expiring inside
  // the horizon.
  if (!opts.force) {
    const on = readValid()
    if (on && on.notAfter.getTime() - Date.now() > horizonMs) {
      return await finish(on.certPem, on.keyPem, on.thumbprint, false)
    }
    if (on) {
      logForDebugging(
        `[Sandbox Windows] persistent CA expiring ` +
          `${on.notAfter.toISOString()}; regenerating`,
        { level: 'warn' },
      )
    }
  }

  // Generate. `ca/` (not the state dir) is mkdir'd here so it
  // inherits the parent's (OI)(CI) DACL. After the atomic write,
  // RE-READ ca.json and use that content: a concurrent broker's
  // rename may have won, and returning our own PEMs would diverge
  // from disk — the re-read makes every racer converge.
  fs.mkdirSync(dir, { recursive: true })
  // Best-effort sweep of stale `*.tmp.*` / `.trust.*` files from
  // crashed prior brokers.
  try {
    const cutoff = Date.now() - 5 * 60 * 1000
    for (const f of fs.readdirSync(dir)) {
      if (!f.includes('.tmp.') && !f.startsWith('.trust.')) continue
      const p = path.join(dir, f)
      if (fs.statSync(p).mtimeMs < cutoff) fs.rmSync(p, { force: true })
    }
  } catch {
    // sweep is best-effort; a leftover tmp is harmless.
  }
  const gen = generateCa({ cn: 'sandbox-runtime persistent CA' })
  atomicWrite(
    jsonPath,
    JSON.stringify({ certPem: gen.certPem, keyPem: gen.keyPem }),
  )
  const on = readValid()
  // `on` can only be undefined if a concurrent broker overwrote with
  // an invalid pair (which the tmp+rename path can't produce) — so
  // treat as our own write having landed.
  const { certPem, keyPem, thumbprint } = on ?? {
    certPem: gen.certPem,
    keyPem: gen.keyPem,
    thumbprint: certThumbprint(gen.certPem),
  }
  return await finish(certPem, keyPem, thumbprint, true)
}

export interface WindowsInstallOptions {
  /** WFP sublayer GUID. Omit for srt-win's compile-time default. */
  sublayerGuid?: string
  /**
   * Loopback PERMIT port range. Must match what
   * `SandboxRuntimeConfig.windows.proxyPortRange` will be set to.
   * Default {@link DEFAULT_WINDOWS_PROXY_PORT_RANGE}.
   */
  proxyPortRange?: readonly [number, number]
  /**
   * Name for the sandbox user account (created if absent, adopted
   * if it already exists as a local user). Default `srt-sandbox`.
   */
  sandboxUser?: string
  /**
   * Replace an existing install whose configuration differs
   * (different port range or sandbox-user name under the same
   * sublayer). Without this, install refuses with "already
   * installed with different config" rather than silently
   * overwriting.
   */
  force?: boolean
  /**
   * How long to wait for the self-elevating install subprocess.
   * Default 120 000 ms — the Windows UAC consent dialog auto-
   * dismisses after ~2 minutes, so anything shorter risks killing
   * the subprocess while a legitimate approval is still pending
   * (elevation is not retracted when the parent dies, so a late
   * approval after we've timed out would half-complete).
   */
  timeoutMs?: number
  /** Resolved `srt-win` spawn descriptor — from {@link resolveSrtWin}. */
  srtWin?: SrtWinSpawn
}

export interface WindowsInstallResult {
  /** Post-install WFP state. */
  wfp: WindowsWfpStatusResult
  /** Post-install sandbox-user state. */
  user: WindowsSandboxUserStatus
  /**
   * `true` if the user dismissed the UAC prompt. Not an error —
   * the install simply didn't happen. Re-run when the user is
   * ready to grant elevation.
   */
  cancelled?: true
}

/**
 * Effective spawn budget for the self-elevating install/uninstall —
 * see {@link WindowsInstallOptions.timeoutMs} for the 120 s rationale.
 */
function installTimeoutMs(opts: { timeoutMs?: number }): number {
  return opts.timeoutMs ?? 120_000
}

function installArgs(opts: WindowsInstallOptions): string[] {
  const args = ['install']
  if (opts.sublayerGuid) args.push('--sublayer-guid', opts.sublayerGuid)
  if (opts.proxyPortRange) {
    args.push(
      '--proxy-port-range',
      `${opts.proxyPortRange[0]}-${opts.proxyPortRange[1]}`,
    )
  }
  if (opts.sandboxUser) args.push('--sandbox-user', opts.sandboxUser)
  if (opts.force) args.push('--force')
  return args
}

/**
 * Re-throw a `srt_win_timeout` from the install spawn as the more
 * specific `install_timeout` (the UAC prompt is the usual cause).
 * Shared by the sync and async install variants.
 */
function remapInstallTimeout(e: unknown): never {
  if (e instanceof WindowsSandboxError && e.code === 'srt_win_timeout') {
    throw new WindowsSandboxError(
      'install_timeout',
      `srt-win install timed out — the UAC prompt may still be open. ` +
        `Re-run when ready to grant elevation. (${e.message})`,
    )
  }
  throw e
}

// srt-win install exit-code contract:
//   0  ok
//   10 user cancelled UAC elevation
//   12 WFP install failed
//   13 already installed with different config (use --force)
//   14 sandbox-user provisioning failed
//   17 ambient write-deny stamping failed
//   1  other error (stderr has detail)
// Throws on any failure code; the caller reads back state on 0/10.
function throwOnInstallFailure(r: RunResult): void {
  logForDebugging(
    `[Sandbox Windows] install exit=${r.status}: ${r.stderr || r.stdout}`,
  )
  if (r.status === 0 || r.status === 10) return
  const out = r.stderr || r.stdout
  switch (r.status) {
    case 12:
      throw new WindowsSandboxError(
        'install_wfp_failed',
        `srt-win install: WFP filter install failed: ${out}`,
      )
    case 14:
      throw new WindowsSandboxError(
        'install_user_failed',
        `srt-win install: sandbox user provisioning failed: ${out}`,
      )
    case 13:
      throw new WindowsSandboxError(
        'install_config_conflict',
        `srt-win install: filters already exist under this sublayer with ` +
          `a different port range or sandbox-user name. Pass ` +
          `{force: true} to replace, or pick a different sublayerGuid. ` +
          `Output: ${out}`,
      )
    case 17:
      throw new WindowsSandboxError(
        'install_ambient_failed',
        `srt-win install: ambient write-deny stamping failed (stock ` +
          `world-writable system dirs could not be deny-stamped for the ` +
          `sandbox user): ${out}`,
      )
    default:
      throw new WindowsSandboxError(
        'install_failed',
        `srt-win install failed (exit ${r.status}): ${out}`,
      )
  }
}

/**
 * One-shot install: provisions the `srt-sandbox` user account and
 * installs the user-SID-keyed WFP filter set — all in a single
 * self-elevating process (one UAC prompt). Idempotent; re-running
 * rotates the sandbox user's password.
 *
 * Network for the calling user is **not disrupted**: the filters key
 * on the `srt-sandbox` user's SID, so the broker, services, and
 * every other principal fall through to default-permit. No logout
 * is required.
 *
 * Returns the post-call WFP + sandbox-user state. If the user
 * cancels the UAC prompt this returns `{cancelled: true, …}` rather
 * than throwing — cancellation is a user choice, not an error.
 *
 * Prefer {@link installWindowsSandboxAsync}; this variant
 * `spawnSync`-blocks the event loop for the full UAC-prompt wait
 * (up to `timeoutMs`).
 *
 * @throws on user/WFP creation failure, or if filters already exist
 *   under `sublayerGuid` with a different port range and `force` is
 *   not set.
 */
export function installWindowsSandbox(
  opts: WindowsInstallOptions = {},
): WindowsInstallResult {
  const srtWin = opts.srtWin ?? resolveSrtWin()
  let r: RunResult
  try {
    r = runSrtWin(installArgs(opts), {
      timeoutMs: installTimeoutMs(opts),
      srtWin,
    })
  } catch (e) {
    remapInstallTimeout(e)
  }
  throwOnInstallFailure(r)
  const state = checkWindowsSandboxStatus({
    sublayerGuid: opts.sublayerGuid,
    srtWin,
  })
  return r.status === 10 ? { ...state, cancelled: true } : state
}

/**
 * Async twin of {@link installWindowsSandbox}. Same options, same
 * return type, same throw semantics. The UAC prompt is still modal,
 * but the event loop stays live — spinners keep painting and timers
 * keep firing.
 */
export async function installWindowsSandboxAsync(
  opts: WindowsInstallOptions = {},
): Promise<WindowsInstallResult> {
  const srtWin = opts.srtWin ?? resolveSrtWin()
  let r: RunResult
  try {
    r = await runSrtWinAsync(installArgs(opts), {
      timeoutMs: installTimeoutMs(opts),
      srtWin,
    })
  } catch (e) {
    remapInstallTimeout(e)
  }
  throwOnInstallFailure(r)
  const state = await checkWindowsSandboxStatusAsync({
    sublayerGuid: opts.sublayerGuid,
    srtWin,
  })
  return r.status === 10 ? { ...state, cancelled: true } : state
}

/**
 * Remove the WFP filter set under `sublayerGuid` and the
 * `srt-sandbox` account, its credential file, and the setup marker
 * (one UAC prompt). Idempotent.
 *
 * @returns `{cancelled: true}` if the user dismissed UAC.
 */
export function uninstallWindowsSandbox(
  opts: {
    sublayerGuid?: string
    keepUser?: boolean
    /**
     * How long to wait for the self-elevating uninstall subprocess.
     * Default 120 000 ms — see {@link WindowsInstallOptions.timeoutMs}.
     */
    timeoutMs?: number
    srtWin?: SrtWinSpawn
  } = {},
): {
  cancelled?: true
} {
  const args = ['uninstall']
  if (opts.sublayerGuid) args.push('--sublayer-guid', opts.sublayerGuid)
  if (opts.keepUser) args.push('--keep-user')
  const r = runSrtWin(args, {
    timeoutMs: installTimeoutMs(opts),
    srtWin: opts.srtWin,
  })
  logForDebugging(
    `[Sandbox Windows] uninstall exit=${r.status}: ${r.stderr || r.stdout}`,
  )
  if (r.status === 10) return { cancelled: true }
  if (r.status !== 0) {
    throw new WindowsSandboxError(
      'uninstall_failed',
      `srt-win uninstall failed (exit ${r.status}): ${r.stderr || r.stdout}`,
    )
  }
  return {}
}

/**
 * Resolve any Windows filesystem-config path list — `allowRead`/
 * `allowWrite` grants and `denyRead`/`denyWrite` stamps — to
 * concrete paths via the single platform-aware
 * {@link normalizePathForSandbox} chokepoint (Linux/macOS parity:
 * point-in-time expansion at session initialize, not per-exec).
 * Glob patterns are expanded; non-glob paths are normalized and
 * returned 1:1. Directory targets are accepted — the additive
 * sandbox-user ACE carries `(OI)(CI)` so it covers the subtree.
 *
 * Missing literal paths are dropped for `mode: 'grant'` (a grant on
 * nothing is meaningless) but PASSED THROUGH for `mode: 'deny'` —
 * `srt-win acl stamp` materializes a placeholder chain (mkdirs each
 * missing intermediate + creates an empty leaf) and stamps every
 * created component, so the deny lands on the exact target path
 * and the sandbox user cannot create/write/delete it. A trailing
 * `/` or `\` on the raw input means "the target is a directory":
 * the placeholder leaf is created as an empty directory instead of
 * an empty file, so a later `mkdirSync({recursive: true})` on the
 * real path succeeds. Glob results (existing-by-construction) drop
 * on a stat miss regardless of mode: a glob is inherently "match
 * existing".
 *
 * **UNC exception:** a `\\server\share\…` **literal** passes through
 * raw in BOTH modes (no existence probe — see {@link isUncPath});
 * `srt-win` soft-drops a missing UNC deny target rather than
 * materializing a placeholder chain on an SMB share. A UNC **glob**
 * still walks the share (user-trusted).
 */
export function expandWindowsFsPaths(
  patterns: readonly string[],
  opts?: { mode?: 'grant' | 'deny' },
): string[] {
  const out = new Set<string>()
  for (const raw of patterns) {
    const norm = normalizePathForSandbox(raw)
    const isGlob = containsGlobCharsWin(norm)
    // UNC literal: pass raw (no stat) — see {@link isUncPath}. A
    // UNC glob falls through to expandGlobPattern below.
    if (isUncPath(norm) && !isGlob) {
      out.add(norm)
      continue
    }
    const candidates = isGlob
      ? expandGlobPattern(norm, { caseInsensitive: true })
      : [norm]
    for (const c of candidates) {
      const st = fs.statSync(c, { throwIfNoEntry: false })
      if (!st) {
        // normalizePathForSandbox (path.resolve) strips the
        // trailing separator (the dir-leaf signal — see doc);
        // re-apply it from the raw input.
        if (opts?.mode === 'deny' && !isGlob) {
          out.add(/[\\/]$/.test(raw) && !/[\\/]$/.test(c) ? c + '\\' : c)
        }
        continue
      }
      out.add(c)
    }
  }
  return [...out]
}

/**
 * {@link WindowsSandboxError} narrowed to `mapped_drive_cwd`,
 * carrying the `DRIVE_REMOTE` root that made the launch fail
 * (`Z:\` for a mapped letter, `\\server\share\` for a raw UNC cwd).
 */
export interface MappedDriveCwdError extends WindowsSandboxError {
  readonly code: 'mapped_drive_cwd'
  readonly drive?: string
}

/**
 * Parse a structured `srt-win exec` error from its stderr. `exec`
 * emits typed launch failures as a single JSON line
 * `{"code":…,"message":…}` alongside a distinct exit code —
 * `mapped_drive_cwd` is exit **16**. Embedders that spawn the
 * `{argv, env}` from {@link wrapCommandWithSandboxWindows} call
 * this on non-zero exit to surface an actionable
 * {@link WindowsSandboxError} instead of a bare status.
 *
 * Returns `undefined` when no typed-error line is present (the
 * common case: exit status is the child's own). Gate on the
 * `srt-win` exit code before calling — the sandboxed child's own
 * stderr is pumped through unchanged, so a child that happened to
 * print a matching JSON line would parse here too.
 */
export function parseWindowsSandboxError(
  stderr: string,
): MappedDriveCwdError | undefined {
  for (const line of stderr.split(/\r?\n/)) {
    const t = line.trim()
    if (!t.startsWith('{') || !t.includes('"code"')) continue
    try {
      const j = JSON.parse(t) as {
        code?: string
        message?: string
        drive?: string
      }
      if (j.code === 'mapped_drive_cwd') {
        // The canonical class carries `code`/`subcommand`; `drive`
        // is this one code's extra payload, attached as a plain
        // property rather than forking the class.
        return Object.assign(
          new WindowsSandboxError(
            'mapped_drive_cwd',
            j.message ?? 'mapped/network-drive working directory',
            'exec',
          ),
          { drive: j.drive },
        ) as MappedDriveCwdError
      }
    } catch {
      // not our line
    }
  }
  return undefined
}

export interface WindowsAclStampOptions {
  /** Paths the sandboxed child must not read. */
  denyRead: readonly string[]
  /** Paths the sandboxed child must not write (read stays allowed). */
  denyWrite: readonly string[]
  /** SID of the dedicated sandbox user — {@link WindowsSandboxUserStatus.sid}. */
  sandboxUserSid: string
  /** Long-lived host PID the holds are tied to. Default: this process. */
  holderPid?: number
  /** Resolved `srt-win` spawn descriptor — from {@link resolveSrtWin}. */
  srtWin?: SrtWinSpawn
}

/**
 * Apply the file-deny ACE set for one host session: an additive
 * `(D;OICI;mask;;;<sb-SID>)` on the target plus a
 * `(D;OICI;FILE_DELETE_CHILD;;;<sb-SID>)` on the parent — no
 * PROTECTED rewrite, no SD snapshot. Idempotent and refcounted via
 * srt-win's `working_aces` table.
 *
 * Inputs are passed verbatim to `srt-win` (which canonicalizes and
 * rejects globs). Callers that accept globs should pre-expand via
 * {@link expandWindowsFsPaths}.
 *
 * @throws on exit ≠ 0 — including exit 2 (one or more inputs
 *   skipped). srt-win stamps the resolvable inputs before exiting
 *   2, so on throw the caller should call {@link restoreWindowsAcl}
 *   to release whatever WAS stamped.
 */
export function stampWindowsAcl(opts: WindowsAclStampOptions): void {
  const holder = opts.holderPid ?? process.pid
  const stdin = JSON.stringify({
    denyRead: opts.denyRead,
    denyWrite: opts.denyWrite,
  })
  const r = runSrtWin(
    [
      'acl',
      'stamp',
      '--holder-pid',
      `${holder}`,
      '--sandbox-user-sid',
      opts.sandboxUserSid,
    ],
    { timeoutMs: 60_000, stdin, srtWin: opts.srtWin },
  )
  logForDebugging(
    `[Sandbox Windows] acl stamp exit=${r.status}: ${r.stderr || r.stdout}`,
  )
  if (r.status !== 0) {
    throw new WindowsSandboxError(
      'acl_stamp_failed',
      `srt-win acl stamp exited ${r.status} ` +
        (r.status === 2 ? '(partial — some inputs skipped)' : '(failed)') +
        `: ${r.stderr || r.stdout}`,
    )
  }
}

/**
 * Per-path outcome from `srt-win acl restore --json` /
 * `revoke --json`. The status set is intentionally loose: the
 * pre-/post- same-user-removal `srt-win` builds emit different
 * vocabularies for `restore` (`restored`/`leftChanged`/… vs
 * `revoked`/`stillHeld`/…). Callers (`reset()`) only log these,
 * so the union is whatever the binary on PATH says.
 */
export interface WindowsAclAceOutcome {
  path: string
  status: string
}

/**
 * Release this holder's deny ACEs and remove the sandbox-user ACE
 * on any path whose refcount falls to zero. Best-effort (does not
 * throw on per-path anomalies); returns per-path outcomes for the
 * caller to surface. Returns `undefined` only when `srt-win`
 * itself failed (no JSON to parse).
 */
export function restoreWindowsAcl(opts: {
  sandboxUserSid: string
  holderPid?: number
  srtWin?: SrtWinSpawn
}): WindowsAclAceOutcome[] | undefined {
  const holder = opts.holderPid ?? process.pid
  // Don't let a teardown helper throw — the caller's reset() must
  // complete. runSrtWinJsonAllowFail parses stdout before checking
  // the exit code, so a non-zero exit with the per-path JSON intact
  // still surfaces every entry to reset()'s loop. Only spawn-fail
  // / unparseable output throws → log and return undefined.
  try {
    const r = runSrtWinJsonAllowFail<
      | WindowsAclAceOutcome[]
      | { paths?: WindowsAclAceOutcome[]; parents?: WindowsAclAceOutcome[] }
    >(
      [
        'acl',
        'restore',
        '--holder-pid',
        `${holder}`,
        '--sandbox-user-sid',
        opts.sandboxUserSid,
        '--json',
      ],
      { timeoutMs: 60_000, srtWin: opts.srtWin },
    )
    if (!r.ok) {
      logForDebugging(
        `[Sandbox Windows] acl restore exited non-zero (per-path ` +
          `outcomes preserved): ${r.stderr}`,
        { level: 'error' },
      )
    }
    // Pre- same-user-removal builds emit `{paths, parents}`; post-
    // emit a flat array. Flatten either so reset()'s logging loop
    // is shape-agnostic across the transition.
    return Array.isArray(r.json)
      ? r.json
      : [...(r.json.paths ?? []), ...(r.json.parents ?? [])]
  } catch (e) {
    logForDebugging(`[Sandbox Windows] acl restore: ${(e as Error).message}`, {
      level: 'error',
    })
    return undefined
  }
}

export interface WindowsAclGrantOptions {
  /** Paths to grant `MODIFY_NO_FDC` on (the working tree, `allowWrite`). */
  write: readonly string[]
  /** Paths to grant `FILE_GENERIC_READ|EXECUTE` on (`allowRead`). */
  read: readonly string[]
  /** SID of the dedicated sandbox user — {@link WindowsSandboxUserStatus.sid}. */
  sandboxUserSid: string
  /** Long-lived host PID the holds are tied to. Default: this process. */
  holderPid?: number
  /** Resolved `srt-win` spawn descriptor — from {@link resolveSrtWin}. */
  srtWin?: SrtWinSpawn
}

/**
 * Apply per-session additive `(OI)(CI)` ALLOW ACEs for the sandbox
 * user on each path. The sandbox user has no inherent rights on
 * real-user-owned files; this is what makes the working tree (and
 * explicit `allowRead`/`allowWrite` paths) reachable from the
 * child. Idempotent and refcounted via srt-win's `working_aces`
 * table.
 *
 * @throws on exit ≠ 0. On throw the caller should call
 *   {@link revokeWindowsAcl} to release whatever WAS granted.
 */
export function grantWindowsAcl(opts: WindowsAclGrantOptions): void {
  const holder = opts.holderPid ?? process.pid
  const stdin = JSON.stringify({ read: opts.read, write: opts.write })
  const r = runSrtWin(
    [
      'acl',
      'grant',
      '--holder-pid',
      `${holder}`,
      '--sandbox-user-sid',
      opts.sandboxUserSid,
    ],
    { timeoutMs: 60_000, stdin, srtWin: opts.srtWin },
  )
  logForDebugging(
    `[Sandbox Windows] acl grant exit=${r.status}: ${r.stderr || r.stdout}`,
  )
  if (r.status !== 0) {
    throw new WindowsSandboxError(
      'acl_grant_failed',
      `srt-win acl grant exited ${r.status}: ${r.stderr || r.stdout}`,
    )
  }
}

/**
 * Release this holder's grants and remove the sandbox-user ACE on
 * any path whose refcount falls to zero. Best-effort (does not
 * throw); logs anomalies.
 */
export function revokeWindowsAcl(opts: {
  sandboxUserSid: string
  holderPid?: number
  srtWin?: SrtWinSpawn
}): WindowsAclAceOutcome[] | undefined {
  const holder = opts.holderPid ?? process.pid
  try {
    const r = runSrtWinJsonAllowFail<WindowsAclAceOutcome[]>(
      [
        'acl',
        'revoke',
        '--holder-pid',
        `${holder}`,
        '--sandbox-user-sid',
        opts.sandboxUserSid,
        '--json',
      ],
      { timeoutMs: 60_000, srtWin: opts.srtWin },
    )
    if (!r.ok) {
      logForDebugging(
        `[Sandbox Windows] acl revoke exited non-zero: ${r.stderr}`,
        { level: 'error' },
      )
    }
    return r.json
  } catch (e) {
    logForDebugging(`[Sandbox Windows] acl revoke: ${(e as Error).message}`, {
      level: 'error',
    })
    return undefined
  }
}

// ────────────────────────────────────────────────────────────────────
// Wrap
// ────────────────────────────────────────────────────────────────────

/**
 * Build the spawn descriptor for running `command` inside the Windows
 * sandbox: an `argv` array plus the `env` to spawn it with.
 *
 * Caller MUST spawn the result with `{shell: false}` — that is the
 * security boundary that keeps untrusted bytes off the host's shell
 * (the inner `cmd.exe /c` runs INSIDE the sandbox; see
 * `vendor/srt-win-src/src/launch.rs` `build_cmdline` for the passthrough
 * rationale) — AND with the returned `env`.
 *
 * Proxy configuration is single-sourced by {@link generateProxyEnvVars}
 * (the same canonical builder used on macOS/Linux). `srt-win exec`
 * takes no `--http-proxy` / `--socks-proxy` flags and synthesizes no
 * proxy env. The two-hop runner starts with the SANDBOX user's
 * profile env (`USERPROFILE`/`TEMP` isolated) and overlays exactly
 * what we pass as `--env` — built here from the broker's `PATH` plus
 * the generated proxy set.
 */
export function wrapCommandWithSandboxWindows(p: WindowsSandboxParams): {
  argv: string[]
  env: NodeJS.ProcessEnv
} {
  const { exe, prependArgs } = p.srtWin ?? resolveSrtWin()
  // Generated proxy + CA-trust env. Single-sourced here so the
  // same object feeds (a) the spawn env merge below and (b) the
  // explicit `--env` overlay for the runner.
  //
  // The CA trust-bundle path is emitted with forward slashes:
  // msys2's POSIX-path conversion leaves `C:/…` alone and every
  // tool we set the var for (curl, git, node, python, …) accepts
  // forward slashes on Windows; backslashes would be mangled if
  // the value passes through a bash command line. Schannel-level
  // trust comes from the registry write `srt-win user trust-ca`
  // did at install time; the env-var layer here covers the
  // OpenSSL-backed tools.
  const generated = envListToObject(
    generateProxyEnvVars(
      p.httpProxyPort,
      p.socksProxyPort,
      p.caCertPath?.replace(/\\/g, '/'),
      p.proxyAuthToken,
      undefined,
      encodeSandboxedCommand(p.commandId ?? p.command),
    ),
  )
  // TMPDIR is a POSIX path meant for the macOS/Linux FS sandbox — it
  // serves no purpose on Windows and breaks msys2 tools (mktemp etc.).
  delete generated.TMPDIR
  // NO_PROXY=localhost,127.0.0.1,… is correct on POSIX where seatbelt/
  // bwrap allow direct loopback: a NO_PROXY match makes the client
  // connect directly and it works. On Windows the WFP fence blocks
  // ALL direct connects from the sandbox user — including loopback
  // outside the proxy-port PERMIT range — so NO_PROXY makes clients
  // bypass the proxy and hit the fence; every localhost/127.0.0.1
  // request fails. Consumers currently work around with
  // `curl --noproxy ""`. Drop NO_PROXY here so localhost goes through
  // the proxy (which connects on the child's behalf, from the broker's
  // SID, and is not fenced).
  delete generated.NO_PROXY
  delete generated.no_proxy

  // GIT_CONFIG_* set — safe.directory (dubious-ownership) + the
  // schannel CA knobs. Composed against setEnvVars so a caller
  // that already emits GIT_CONFIG_COUNT keeps its entries.
  const gitCfg = buildGitConfigEnv({
    safeDirs: [
      p.cwd ?? process.cwd(),
      ...(p.allowWrite ?? []),
      ...(p.gitSafeDirectories ?? []),
    ],
    schannelCa: p.caCertPath !== undefined,
    baseEnv: p.setEnvVars,
  })

  const argv: string[] = [exe, ...prependArgs, 'exec']
  if (p.quiet !== false) argv.push('--quiet')
  for (const d of p.denyRead ?? []) argv.push('--deny-read', d)
  for (const d of p.denyWrite ?? []) argv.push('--deny-write', d)
  // The two-hop runner starts with the SANDBOX user's profile env
  // (USERPROFILE/TEMP isolated) and overlays exactly what we pass as
  // `--env`. The broker does NOT enumerate its own env — the overlay
  // is built here from the broker's PATH, the mode:'mask' sentinel
  // set, the generated proxy set, and the GIT_CONFIG_* set.
  // Sentinels precede `generated` so a caller masking e.g.
  // `HTTPS_PROXY` cannot break the sandbox's own proxy plumbing —
  // same precedence as the macOS/Linux `env -u … VAR=…
  // sandbox-exec` order. `gitCfg` is last so its GIT_CONFIG_COUNT
  // (which composes against setEnvVars) wins.
  const overlay: NodeJS.ProcessEnv = {
    PATH: process.env.PATH,
    PATHEXT: process.env.PATHEXT,
    ...(p.setEnvVars ?? {}),
    ...generated,
    ...gitCfg,
  }
  for (const [k, v] of Object.entries(overlay)) {
    if (v !== undefined) argv.push('--env', `${k}=${v}`)
  }
  argv.push('--')

  // Inner shell: `{exe, args}` from parseWindowsBinShell — the SOLE
  // normalizer. `p.command` lands as a single argv element; srt-win's
  // `build_cmdline` MSVCRT-quotes it (or wraps in one outer "…" for
  // cmd /s) so the inner shell receives it intact. See launch.rs.
  const sh = p.binShell ?? parseWindowsBinShell(undefined)
  argv.push(sh.exe, ...sh.args, p.command)

  // CreateProcessW's lpCommandLine is capped at 32 767 WCHARs.
  // Node's `shell:false` spawn builds it by MSVCRT-quoting each
  // argv element and joining with spaces; ~30 000 leaves headroom
  // for the quote overhead the estimate doesn't model.
  const cmdlineEstimate = argv.reduce((n, a) => n + a.length + 3, 0)
  if (cmdlineEstimate > 30_000) {
    throw new WindowsSandboxError(
      'argv_too_long',
      `Windows sandbox argv is ~${cmdlineEstimate} chars ` +
        `(CreateProcessW limit is 32 767).`,
    )
  }

  // The two-hop runner starts with a FRESH `srt-sandbox` profile
  // env (`lpEnvironment = NULL` + `LOGON_WITH_PROFILE`), so the
  // broker process's environment never reaches the child. The
  // returned `env` is the spawn env for the broker (srt-win)
  // process only; the child sees the `--env` overlay built into
  // `argv` above (PATH/PATHEXT + mode:'mask' sentinels + proxy).
  const env: NodeJS.ProcessEnv = { ...process.env, ...generated }
  return { argv, env }
}

/**
 * Parse a list of `KEY=VALUE` strings (as produced by
 * {@link generateProxyEnvVars}) into an object. Splits on the FIRST
 * `=` only, so values containing `=` survive intact. Shared with the
 * MXC backend's broker-env assembly.
 */
export function envListToObject(list: readonly string[]): NodeJS.ProcessEnv {
  const out: NodeJS.ProcessEnv = {}
  for (const entry of list) {
    const eq = entry.indexOf('=')
    if (eq === -1) continue
    out[entry.slice(0, eq)] = entry.slice(eq + 1)
  }
  return out
}

// ────────────────────────────────────────────────────────────────────
// Dependency / readiness check
// ────────────────────────────────────────────────────────────────────

/**
 * Install instructions, surfaced verbatim in error messages.
 */
export function windowsInstallInstructions(
  sublayerGuid: string | undefined,
): string {
  const sl = sublayerGuid ? ` --sublayer-guid ${sublayerGuid}` : ''
  return (
    `Windows sandbox needs a one-time install (one UAC prompt):\n` +
    `  npx sandbox-runtime windows-install\n` +
    `  — or call installWindowsSandbox(), or run ` +
    `\`srt-win.exe install${sl}\` directly.\n` +
    `No logout is needed: the WFP filter keys on the dedicated ` +
    `\`srt-sandbox\` user's SID, so your network is unaffected.`
  )
}

function settle<T>(fn: () => T): PromiseSettledResult<T> {
  try {
    return { status: 'fulfilled', value: fn() }
  } catch (e) {
    return { status: 'rejected', reason: e }
  }
}

/**
 * Interpret the two probe results into a {@link SandboxDependencyCheck}.
 * Shared by the sync and async `checkWindowsDependencies*` variants so
 * both produce byte-identical `errors[]` for the same underlying state.
 *
 * `getWfp` is lazy: the sync caller's thunk spawns `wfp status` on
 * demand (preserving the short-circuit — no second spawn when
 * `user status` already failed); the async caller has already run
 * both probes concurrently and its thunk returns the settled result.
 */
function interpretDependencyProbes(
  sublayerGuid: string | undefined,
  user: PromiseSettledResult<WindowsSandboxUserStatus>,
  getWfp: () => PromiseSettledResult<WindowsWfpStatusResult>,
): SandboxDependencyCheck {
  const errors: string[] = []
  const warnings: string[] = []

  // 2. Sandbox user provisioned + credential readable.
  if (user.status === 'rejected') {
    errors.push(`srt-win user status failed: ${(user.reason as Error).message}`)
    return { errors, warnings }
  }
  const us = user.value
  if (!us.provisioned || !us.credPresent) {
    errors.push(
      `Sandbox user is not provisioned (user=${us.provisioned}, ` +
        `cred=${us.credPresent}). ` +
        windowsInstallInstructions(sublayerGuid),
    )
  }

  // 3. WFP filters installed under the sublayer. BFE enumeration is
  // admin-gated; `cannot-read` is informational only — the
  // BEHAVIORAL check (`verifyWindowsWfpEgress`) runs at
  // `initialize()` and is what actually fails closed.
  const wfp = getWfp()
  if (wfp.status === 'rejected') {
    errors.push(`srt-win wfp status failed: ${(wfp.reason as Error).message}`)
    return { errors, warnings }
  }
  const ws = wfp.value
  if (ws.state === 'cannot-read') {
    logForDebugging(
      `[Sandbox Windows] wfp status cannot-read (non-elevated): ${ws.hint}`,
    )
  } else if (ws.state !== 'installed') {
    // 'absent'. If the user is also not-provisioned, the user-state
    // error above already gave the right instruction; don't repeat.
    if (us.provisioned && us.credPresent) {
      errors.push(
        `WFP filters not installed under sublayer ` +
          `${sublayerGuid ?? '(default)'}. ` +
          windowsInstallInstructions(sublayerGuid),
      )
    }
  } else if (ws.portRange) {
    logForDebugging(
      `[Sandbox Windows] WFP installed: ${ws.filters} filters, ` +
        `proxy port range ${ws.portRange[0]}-${ws.portRange[1]}`,
    )
  }

  return { errors, warnings }
}

/**
 * Check the Windows backend is ready to sandbox. Errors block
 * `initialize()`; warnings are informational.
 *
 * Prefer {@link checkWindowsDependenciesAsync}; this variant
 * `spawnSync`-blocks the event loop on two `srt-win.exe` spawns
 * (Windows Defender cold-scan can add seconds).
 */
export function checkWindowsDependencies(
  opts: { sublayerGuid?: string; srtWin?: SrtWinSpawn } = {},
): SandboxDependencyCheck {
  // 1. Binary present. The argless `resolveSrtWin()` throws (no
  // implicit vendor fallback) — surfaced as a dependency error
  // telling the caller to thread an explicit path.
  let srtWin: SrtWinSpawn
  try {
    srtWin = opts.srtWin ?? resolveSrtWin()
  } catch (e) {
    return { errors: [(e as Error).message], warnings: [] }
  }
  logForDebugging(`[Sandbox Windows] using srt-win at ${srtWin.exe}`)
  return interpretDependencyProbes(
    opts.sublayerGuid,
    settle(() => getWindowsSandboxUserStatus({ srtWin })),
    // Lazy: spawned only if user-status succeeded (short-circuit).
    () =>
      settle(() =>
        getWindowsWfpStatus({ sublayerGuid: opts.sublayerGuid, srtWin }),
      ),
  )
}

/**
 * Async twin of {@link checkWindowsDependencies}. Same result for the
 * same underlying state; runs the two `srt-win` probes concurrently
 * and never blocks the event loop.
 */
export async function checkWindowsDependenciesAsync(
  opts: { sublayerGuid?: string; srtWin?: SrtWinSpawn } = {},
): Promise<SandboxDependencyCheck> {
  let srtWin: SrtWinSpawn
  try {
    srtWin = opts.srtWin ?? resolveSrtWin()
  } catch (e) {
    return { errors: [(e as Error).message], warnings: [] }
  }
  logForDebugging(`[Sandbox Windows] using srt-win at ${srtWin.exe}`)
  const [user, wfp] = await Promise.allSettled([
    getWindowsSandboxUserStatusAsync({ srtWin }),
    getWindowsWfpStatusAsync({ sublayerGuid: opts.sublayerGuid, srtWin }),
  ])
  return interpretDependencyProbes(opts.sublayerGuid, user, () => wfp)
}
