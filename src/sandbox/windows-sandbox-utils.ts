import * as fs from 'node:fs'
import * as os from 'node:os'
import * as net from 'node:net'
import * as path from 'node:path'
import { spawn, spawnSync } from 'node:child_process'
import { once } from 'node:events'
import { fileURLToPath } from 'node:url'
import { logForDebugging } from '../utils/debug.js'
import {
  generateProxyEnvVars,
  encodeSandboxedCommand,
  attributionKeyFor,
  buildGitConfigEnv,
  normalizePathForSandbox,
  containsGlobCharsWin,
  expandGlobPattern,
  isAtOrUnder,
  isUncPath,
  markedLiteralPath,
  normalizeCaseForComparison,
  stripExtendedPathPrefix,
} from './sandbox-utils.js'
// Kept on this module's surface for out-of-tree importers; the
// implementations live in sandbox-utils.ts.
export {
  containsGlobCharsWin,
  stripExtendedPathPrefix,
  buildGitConfigEnv,
  isUncPath,
} from './sandbox-utils.js'
import { certThumbprint, generateCa, validateCaPair } from './mitm-ca.js'
import { literalReadings } from './path-entries.js'
import type { SandboxDependencyCheck } from './linux-sandbox-utils.js'
import type { FilesystemPathEntry, SrtWinConfig } from './sandbox-config.js'

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
  /** `srt-win acl forget` could not remove every persistent grant. */
  | 'acl_forget_failed'
  /**
   * A profile read grant is recorded and cannot be relied on: its run
   * did not finish, it was made with an older exclusion list (a path
   * excluded since would stay readable) or for another profile
   * directory, or its record cannot be read or lacks the exclusion
   * list. Run {@link grantWindowsProfileRead} (or the install) again,
   * or remove it with {@link forgetWindowsProfileRead}. A grant that
   * is simply ABSENT is not an error: the session runs, and the
   * profile is not readable.
   */
  | 'profile_grant_outdated'
  /**
   * `srt-win profile grant` did not complete. From an install: the
   * account and the filters are installed, the grant is not.
   */
  | 'profile_grant_failed'
  /** `srt-win profile forget` could not remove the whole grant. */
  | 'profile_forget_failed'
  | 'kept_grants_in_use'
  | 'srt_win_outdated'
  | 'profile_grant_blocked_by_session'
  | 'profile_operation_in_progress'
  | 'session_ended'
  /**
   * A path the session would grant — `filesystem.allowRead`, or a
   * write root (`allowWrite`) — is, contains, or lies inside a path
   * the profile read grant excludes. Nothing is granted.
   */
  | 'profile_exclusion_read_grant'
  /** `srt-win exec` argv would exceed CreateProcessW's 32 767-char limit. */
  | 'argv_too_long'
  /** Sandbox user account / credential not present — run install. */
  | 'not_provisioned'
  /**
   * The sandbox is installed, by a release whose setup version is not
   * the one this `srt-win` requires — re-run the install. Nothing is
   * granted or run until then.
   */
  | 'reinstall_required'
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
   * The setup version this `srt-win` requires. It launches nothing,
   * and keeps no grant, while {@link markerVersion} differs — see
   * {@link windowsSetupVersionMismatch}. Absent from an `srt-win`
   * that does not report it.
   */
  setupVersion?: number
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
  /**
   * Set when write grants kept between sessions (the default; see
   * `windows.writeRestrictedToken`) exist (`present`, with their
   * roots) or cannot be ruled out (`unknown`). While it is set,
   * `srt-win` refuses to run a command under the ordinary token;
   * `initialize()` with the option set to `false` removes the grants
   * first.
   */
  persistentGrants?: {
    state: 'present' | 'unknown'
    roots: string[]
    reason?: string
  }
  /**
   * Set when a profile read grant is recorded (`present`) or cannot
   * be ruled out (`unknown`). Whether it is current is
   * {@link getWindowsProfileReadStatus}'s to say. While it is set,
   * `srt-win` refuses to run a command under the ordinary token, and
   * `initialize()` with `windows.writeRestrictedToken: false` removes
   * the grant first.
   */
  profileGrant?: {
    state: 'present' | 'unknown'
    reason?: string
  }
  /**
   * What `srt-win` says it does, by name (see
   * {@link WINDOWS_SRT_WIN_CAPABILITIES}); empty from one that does
   * not say.
   */
  capabilities: string[]
  /**
   * SID of the user who owns the interactive session this process
   * runs in, when `srt-win` can tell. It differs from
   * {@link realUserSid} for a process started with other credentials
   * on someone's desktop (`runas`, an elevated prompt opened with an
   * administrator's account), and is absent in a session nobody is
   * logged on to (a service, a scheduled task).
   */
  sessionUserSid?: string
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
  /**
   * Paths the session is granted (read or write) that lie beneath a
   * {@link denyRead} path — see {@link windowsGrantsBeneathDenies}.
   * `srt-win` writes a read deny on the recorded paths of the profile
   * read grant beneath it, and leaves out those at or beneath one of
   * these: the session's own allow there ranks above a deny set
   * further up.
   */
  denyReadExcept?: readonly string[]
  /**
   * Under either token: the process whose session this command
   * belongs to and which `srt-win` has recorded as one
   * ({@link grantWindowsAclPersistent} or {@link grantWindowsAcl} with
   * that `holderPid`). Leave it out for a command with no such
   * session: `srt-win exec` then records itself until the command has
   * exited — one more acquisition of its lock — so that the profile
   * read grant is not made or removed beside the command, and no
   * write root is removed from under it.
   */
  heldBy?: number
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
   * Run the child under the write-restricted token
   * (`SandboxRuntimeConfig.windows.writeRestrictedToken`): adds
   * `--write-restricted-token` to the `srt-win exec` argv and selects
   * git's OpenSSL backend in the injected git config (Schannel
   * refuses restricted tokens). Default `true`; unset and `true` are
   * the same. Only an explicit `false` gives the ordinary token: no
   * flag, no `--write-root`, no git backend entry.
   *
   * The caller must have verified the egress fence for this token
   * shape first — {@link verifyWindowsWfpEgress} with the same value.
   */
  writeRestrictedToken?: boolean
  /**
   * The session's write roots, as granted by
   * {@link grantWindowsAclPersistent}. Each is passed as
   * `--write-root`, which puts the root's capability SID in the
   * child token — without it the child cannot write the root.
   * Ignored when {@link writeRestrictedToken} is `false`.
   */
  writeRoots?: readonly string[]
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
  throwIfRefusedBesideOthers(args, r.status, r.stdout ?? '')
  return {
    status: r.status,
    signal: r.signal,
    stdout: (r.stdout ?? '').trim(),
    stderr: (r.stderr ?? '').trim(),
  }
}

/**
 * `srt-win`'s exit code when the one lock is held by a `profile
 * grant` or `profile forget`: those run for as long as a walk of the
 * profile takes, with nothing else beside them, and whatever needs
 * the lock meanwhile is told so after about three seconds instead of
 * waiting it out.
 */
export const SRT_WIN_EXIT_PROFILE_BUSY = 25
/**
 * `srt-win exec`'s exit code when the session a command was started
 * for (`heldBy`) ended while the command ran: the command and
 * everything it started were terminated. A sandboxed command does not
 * outlive its session. {@link parseWindowsSandboxError} gives the
 * typed error (`session_ended`) from what it printed.
 */
export const SRT_WIN_EXIT_SESSION_ENDED = 26
/** `srt-win`'s exit code for "nothing was removed: sandbox sessions or commands are running". */
export const SRT_WIN_EXIT_HELD_BY_OTHERS = 22
/** `srt-win profile grant`'s exit code for "nothing was changed: sandbox sessions or commands are running". */
export const SRT_WIN_EXIT_GRANT_BLOCKED = 24

/** One row of `srt-win`'s `{"held_by": […]}`, said as what it is. */
function describeWindowsHolder(h: {
  pid?: unknown
  kind?: unknown
  path?: unknown
}): string {
  const who = `process ${String(h.pid)}`
  const at = String(h.path)
  switch (h.kind) {
    case 'profile':
      return `${who} is a sandbox session or command`
    case 'kept_root':
      return `${who} runs on the kept write grant on ${at}`
    case 'grant':
      return `${who} holds a session grant on ${at}`
    case 'deny':
    case 'deny_fdc':
    case 'deny_delete':
    case 'deny_satisfied':
      return `${who} holds a session deny on ${at}`
    default:
      return `${who} holds ${String(h.kind)} on ${at}`
  }
}

function describeWindowsHolders(stdout: string): string {
  let held: { pid?: unknown; kind?: unknown; path?: unknown }[] = []
  try {
    const parsed = JSON.parse(stdout) as { held_by?: unknown }
    if (Array.isArray(parsed.held_by)) held = parsed.held_by as typeof held
  } catch {
    // The exit code says it; the list is for the message only.
  }
  const said = held.slice(0, 8).map(describeWindowsHolder)
  if (held.length > said.length) {
    said.push(`${held.length - said.length} more`)
  }
  return said.join('; ')
}

/**
 * The one mapping of the exit codes with which `srt-win` refuses to
 * act beside other sandbox activity, used by every way this module
 * runs it: a profile operation is running (25); sessions or commands
 * are running and nothing was removed (22) or the profile grant was
 * not changed (24).
 */
function throwIfRefusedBesideOthers(
  args: readonly string[],
  status: number | null,
  stdout: string,
): void {
  if (status === SRT_WIN_EXIT_PROFILE_BUSY) {
    throw new WindowsSandboxError(
      'profile_operation_in_progress',
      `The read grant on your user profile is being written or removed ` +
        `right now (srt-win profile grant / profile forget). Nothing in the ` +
        `sandbox can start until that is done; try again when it has ` +
        `finished.`,
      args[0],
    )
  }
  if (
    status !== SRT_WIN_EXIT_HELD_BY_OTHERS &&
    status !== SRT_WIN_EXIT_GRANT_BLOCKED
  ) {
    return
  }
  const what = describeWindowsHolders(stdout)
  const who = what ? ` (${what})` : ''
  if (status === SRT_WIN_EXIT_GRANT_BLOCKED) {
    throw new WindowsSandboxError(
      'profile_grant_blocked_by_session',
      `The read grant on your user profile was not changed: sandbox ` +
        `sessions or commands are running${who}, and the grant is written ` +
        `only while none is, so that no session sees it change. What was ` +
        `granted before is as it was. End them and run it again.`,
      args[0],
    )
  }
  throw new WindowsSandboxError(
    'kept_grants_in_use',
    `srt-win ${args.slice(0, 2).join(' ')} removed nothing: sandbox ` +
      `sessions or commands are running${who}, and what they run on is ` +
      `not taken from under them. End them and run it again.`,
    args[0],
  )
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
      try {
        throwIfRefusedBesideOthers(args, status, stdout)
      } catch (e) {
        reject(e as Error)
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
  setup_version?: number | null
  real_user_sid: string
  ca_cert_thumb?: string | null
  ca_cert_pem?: string | null
  /** Absent from an `srt-win` that keeps no grants between sessions. */
  persistent_grants?: {
    state: string
    roots?: string[]
    reason?: string
  } | null
  /** Absent from an `srt-win` without the profile read grant. */
  profile_grant?: { state: string; reason?: string } | null
  session_user_sid?: string | null
  /** Absent from an `srt-win` that does not name what it does. */
  capabilities?: unknown
}

/**
 * Behaviours of `srt-win` this library relies on and asks for by
 * name. `srt-win` lists what it does as `capabilities` in `user
 * status` and `profile status`. The two are not always the same
 * build — an embedder can ship `srt-win` inside its own runtime and
 * take this library from the package registry — so a behaviour that
 * lives in `srt-win` is verified, not assumed: a session that depends
 * on one that is not listed is refused (`srt_win_outdated`).
 */
export const WINDOWS_SRT_WIN_CAPABILITIES = {
  /**
   * A read deny handed to `srt-win` is also written on every recorded
   * path of the profile read grant beneath it that carries an allow
   * of its own. This library names a deny once and leaves that to
   * `srt-win`; with one that does not do it, a `denyRead` on the
   * profile directory would not reach a granted directory in it.
   */
  profileDenyExpansion: 'profile-deny-expansion',
  /**
   * Sessions are recorded as holders of the kept grants they run on,
   * and `acl forget` / `profile forget` take
   * `--unless-held-by-others`.
   */
  keptGrantHolders: 'kept-grant-holders',
  /**
   * `acl grant` itself refuses a path that reaches an exclusion
   * recorded with the profile read grant. This library makes the same
   * check from the status it reads, and `srt-win`'s is what still
   * holds when that status does not show a grant that is on disk.
   */
  profileSessionGrantCheck: 'profile-session-grant-check',
  /**
   * That expansion leaves out the recorded paths the session allows
   * more specifically: the grants of the same `acl grant` call, and
   * the ones a command names with `--deny-read-except`. Without it a
   * deny on the profile would take a session's own write root away.
   */
  readDenyExcept: 'read-deny-except',
  /**
   * A session under the write-restricted token is recorded as a
   * holder of the profile read grant from its start, and `exec` is
   * told which session holds for it (`--held-by`) or holds for itself.
   */
  execHolder: 'exec-holder',
} as const

/**
 * The capability this library needs for a session under the
 * write-restricted token and `capabilities` (as `srt-win` reported
 * them) does not list, if any.
 *
 * The capabilities are a property of the `srt-win` BUILD, not of what
 * is recorded: they are required whether or not a profile read grant
 * or a kept write grant exists at the moment. A grant can be made
 * after the session started, by this process or another, and a status
 * that does not mention one is not proof that none is on disk; what
 * the library hands `srt-win` — a read deny named once, a removal
 * guarded by the holder check — must be right in either case.
 */
export function missingWindowsSrtWinCapability(
  capabilities: readonly string[],
): string | undefined {
  return Object.values(WINDOWS_SRT_WIN_CAPABILITIES).find(
    c => !capabilities.includes(c),
  )
}

function capabilityList(v: unknown): string[] {
  return Array.isArray(v)
    ? v.filter((x): x is string => typeof x === 'string')
    : []
}

/** The typed error for an `srt-win` that lacks a behaviour by name. */
export function windowsSrtWinOutdatedError(
  capability: string,
  why: string,
): WindowsSandboxError {
  return new WindowsSandboxError(
    'srt_win_outdated',
    `The srt-win in use is older than this library: it does not report ` +
      `the capability '${capability}', which ${why}. Update srt-win (the ` +
      `one shipped with the program embedding this library, or the ` +
      `package's own) to a build that matches the library. Nothing was ` +
      `granted.`,
  )
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
    ...(typeof raw.setup_version === 'number' && {
      setupVersion: raw.setup_version,
    }),
    realUserSid: raw.real_user_sid,
    ...(raw.ca_cert_thumb && { caCertThumb: raw.ca_cert_thumb }),
    ...(raw.ca_cert_pem && { caCertPem: raw.ca_cert_pem }),
    // Anything but an explicit "none" counts: a state this code does
    // not know must not read as "no grants".
    ...(raw.persistent_grants &&
      raw.persistent_grants.state !== 'none' && {
        persistentGrants: {
          state:
            raw.persistent_grants.state === 'present' ? 'present' : 'unknown',
          roots: raw.persistent_grants.roots ?? [],
          ...(raw.persistent_grants.reason && {
            reason: raw.persistent_grants.reason,
          }),
        },
      }),
    ...(typeof raw.session_user_sid === 'string' &&
      raw.session_user_sid !== '' && {
        sessionUserSid: raw.session_user_sid,
      }),
    capabilities: capabilityList(raw.capabilities),
    // As above: only an explicit "none" is no grant.
    ...(raw.profile_grant &&
      raw.profile_grant.state !== 'none' && {
        profileGrant: {
          state: raw.profile_grant.state === 'present' ? 'present' : 'unknown',
          ...(raw.profile_grant.reason && {
            reason: raw.profile_grant.reason,
          }),
        },
      }),
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
 * @param opts.writeRoots the session's write roots, so the probe
 *   child's token carries the same capability SIDs a command of the
 *   session gets. Ignored when `writeRestrictedToken` is `false`.
 * @param opts.writeRestrictedToken default `true`: probe with the
 *   write-restricted child token (`srt-win wfp verify
 *   --write-restricted-token`: the connect is made by a lockdown
 *   child holding that token). `false` probes with the ordinary one.
 *   The WFP block filter matches by an access check of the connecting
 *   token, and a restricted token is checked differently — a session
 *   MUST verify with the token its commands will run under, because a
 *   filter that stopped matching would leave egress open, not closed.
 * @throws on any outcome other than `blocked` (exit 0).
 */
export async function verifyWindowsWfpEgress(
  opts: {
    target?: string
    proxyPortRange?: readonly [number, number]
    writeRestrictedToken?: boolean
    writeRoots?: readonly string[]
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
    // profile (LOGON_WITH_PROFILE) via CreateProcessWithLogonW, and
    // the runner allows itself 2s to connect (runner.rs).
    const verifyArgs = ['wfp', 'verify', '--target', target]
    if (windowsWriteRestrictedTokenEnabled(opts)) {
      verifyArgs.push('--write-restricted-token')
      for (const r of opts.writeRoots ?? []) verifyArgs.push('--write-root', r)
    }
    const r = runSrtWin(verifyArgs, {
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
   * Defaults to {@link INSTALL_TIMEOUT_MS}.
   */
  timeoutMs?: number
  /**
   * Leave the profile read grant unapplied. The install then only
   * provisions the account and the filters: sessions run as they do
   * without the grant, reading nothing in the profile beyond
   * `allowRead`, until {@link grantWindowsProfileRead} is run.
   */
  skipProfileGrant?: boolean
  /**
   * Paths inside the profile to keep unreadable in addition to the
   * built-in exclusions — {@link WindowsProfileGrantOptions.exclude}.
   */
  profileExclude?: readonly string[]
  /**
   * How long the profile read grant may take. Default 30 minutes; the
   * first grant touches every file under the granted directories.
   */
  profileGrantTimeoutMs?: number
  /**
   * Called with each progress line of the profile read grant (a count
   * of top-level items done). The synchronous install delivers the
   * lines only when the grant has finished.
   */
  onProfileGrantProgress?: (line: string) => void
  /**
   * Called once, right before the profile read grant is applied (not
   * when it is skipped), with {@link windowsProfileGrantNotice} for
   * the profile about to be granted: one line to show the user.
   */
  onProfileGrantStart?: (notice: string) => void
  /** Resolved `srt-win` spawn descriptor — from {@link resolveSrtWin}. */
  srtWin?: SrtWinSpawn
}

/**
 * What an install did about the profile read grant. It is applied by
 * this process, as the user this process runs as, to that user's own
 * profile — never by the elevated step, which may run as another
 * (administrator) account.
 */
export type WindowsInstallProfileGrant =
  | {
      applied: true
      /** SID of the user whose profile was granted. */
      userSid: string
      result: WindowsProfileGrantResult
    }
  | {
      applied: false
      /**
       * Why not. Sessions still run; they read nothing in the profile
       * until the grant is applied.
       */
      reason: string
    }

export interface WindowsInstallResult {
  /** Post-install WFP state. */
  wfp: WindowsWfpStatusResult
  /** Post-install sandbox-user state. */
  user: WindowsSandboxUserStatus
  /** The profile read grant; absent when the install was cancelled. */
  profileGrant?: WindowsInstallProfileGrant
  /**
   * `true` if the user dismissed the UAC prompt. Not an error —
   * the install simply didn't happen. Re-run when the user is
   * ready to grant elevation.
   */
  cancelled?: true
}

/**
 * Default spawn budget for the self-elevating install/uninstall. The Windows
 * UAC consent dialog auto-dismisses after ~2 minutes, so anything shorter
 * risks killing the subprocess while a legitimate approval is still pending
 * (elevation is not retracted when the parent dies, so a late approval after
 * we have timed out would half-complete).
 */
const INSTALL_TIMEOUT_MS = 120_000

/** Effective spawn budget for the self-elevating install/uninstall. */
function installTimeoutMs(opts: { timeoutMs?: number }): number {
  return opts.timeoutMs ?? INSTALL_TIMEOUT_MS
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
  if (r.status === 10) return { ...state, cancelled: true }
  const skip = installProfileGrantSkip(opts, state.user)
  if (skip) return { ...state, profileGrant: skip }
  opts.onProfileGrantStart?.(windowsProfileGrantNotice(os.homedir()))
  try {
    const result = grantWindowsProfileReadSync(
      installProfileGrantOptions(opts, srtWin),
    )
    return {
      ...state,
      profileGrant: { applied: true, userSid: state.user.realUserSid, result },
    }
  } catch (e) {
    throwInstallProfileGrantFailure(e)
  }
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
  if (r.status === 10) return { ...state, cancelled: true }
  const skip = installProfileGrantSkip(opts, state.user)
  if (skip) return { ...state, profileGrant: skip }
  opts.onProfileGrantStart?.(windowsProfileGrantNotice(os.homedir()))
  try {
    const result = await grantWindowsProfileRead(
      installProfileGrantOptions(opts, srtWin),
    )
    return {
      ...state,
      profileGrant: { applied: true, userSid: state.user.realUserSid, result },
    }
  } catch (e) {
    throwInstallProfileGrantFailure(e)
  }
}

/** LocalSystem, LocalService, NetworkService: accounts no one runs sessions as. */
const WINDOWS_SERVICE_ACCOUNT_SIDS: ReadonlySet<string> = new Set([
  'S-1-5-18',
  'S-1-5-19',
  'S-1-5-20',
])

/**
 * Why an install leaves the profile read grant unapplied, if it does;
 * `undefined` when it applies it.
 *
 * The grant is made by this process, for the profile of the user it
 * runs as. It is applied only when that user is the person using the
 * session the install runs in:
 *
 * - not when `skipProfileGrant` is set;
 * - not for a service account (a machine-wide deployment): there is
 *   no person's profile to grant;
 * - not when the process runs as another account than the owner of
 *   the interactive session it is in — an administrator's elevated
 *   prompt on someone's desktop, `runas` — which would grant that
 *   other account's profile;
 * - not when the session's owner cannot be told (a session nobody is
 *   logged on to; an `srt-win` that does not report it).
 *
 * The session's owner is the Terminal Services session's logged-on
 * user, as `srt-win user status` reports it. It names the wrong
 * person only where a session has no single one: it is unset under a
 * service or scheduled task, and a remote-desktop session shadowed by
 * a helper still belongs to its owner.
 *
 * In every skipped case the person concerned applies the grant by
 * running the install, or {@link grantWindowsProfileRead}, as
 * themselves; until then their sessions run without reading the
 * profile.
 */
export function windowsProfileGrantSkipReason(
  user: Pick<WindowsSandboxUserStatus, 'realUserSid' | 'sessionUserSid'>,
  opts: { skipProfileGrant?: boolean } = {},
): string | undefined {
  if (opts.skipProfileGrant) return 'skipProfileGrant was set'
  const how =
    `run the install, or grantWindowsProfileRead() (\`srt-win profile ` +
    `grant\`), as the user whose sessions are to read their profile`
  if (WINDOWS_SERVICE_ACCOUNT_SIDS.has(user.realUserSid)) {
    return (
      `the install ran as the service account ${user.realUserSid}, which ` +
      `runs no sessions; ${how}`
    )
  }
  if (user.sessionUserSid === undefined) {
    return (
      `the owner of the session this install ran in could not be ` +
      `determined, so it is not known whose profile ${user.realUserSid} ` +
      `is; ${how}`
    )
  }
  if (user.sessionUserSid.toUpperCase() !== user.realUserSid.toUpperCase()) {
    return (
      `the install ran as ${user.realUserSid} in a session that belongs ` +
      `to ${user.sessionUserSid}; granting would open the installing ` +
      `account's profile, not the session owner's; ${how}`
    )
  }
  return undefined
}

function installProfileGrantSkip(
  opts: WindowsInstallOptions,
  user: WindowsSandboxUserStatus,
): WindowsInstallProfileGrant | undefined {
  const reason = windowsProfileGrantSkipReason(user, opts)
  return reason === undefined ? undefined : { applied: false, reason }
}

/**
 * What the profile read grant is about to do, in one line, for the
 * person at the keyboard: the install's CLI prints it before applying
 * the grant, and {@link WindowsInstallOptions.onProfileGrantStart}
 * hands it to an embedder to show.
 */
export function windowsProfileGrantNotice(profileDir: string): string {
  return (
    `Making ${profileDir} readable to sandboxed commands on this machine, ` +
    `except the excluded credential stores (SSH and GPG keys, cloud and ` +
    `browser sign-ins, password managers, registry hives). Readable ` +
    `files include package-manager configuration that can hold feed ` +
    `tokens: .npmrc, pip.ini, NuGet.Config, Maven settings.xml, ` +
    `gradle.properties, .gitconfig. Skip with --skip-profile-grant ` +
    `(skipProfileGrant); undo with \`srt-win profile forget\` ` +
    `(forgetWindowsProfileRead()).`
  )
}

function installProfileGrantOptions(
  opts: WindowsInstallOptions,
  srtWin: SrtWinSpawn,
): WindowsProfileGrantOptions {
  return {
    exclude: opts.profileExclude,
    timeoutMs: opts.profileGrantTimeoutMs,
    onProgress: opts.onProfileGrantProgress,
    srtWin,
  }
}

/**
 * The account and the filters are installed and the profile read
 * grant is not: its own error, so the caller does not take the whole
 * install for failed. An interrupted grant is recorded as incomplete —
 * no session starts on it — and running the install or the grant
 * again finishes it; `forgetWindowsProfileRead()` takes it back.
 */
function throwInstallProfileGrantFailure(e: unknown): never {
  const cause = e as Error
  // Refused beside other sandbox activity: nothing was written, and
  // a grant made before is still the current one. Said as that, under
  // its own code.
  if (
    cause instanceof WindowsSandboxError &&
    (cause.code === 'profile_grant_blocked_by_session' ||
      cause.code === 'profile_operation_in_progress')
  ) {
    throw new WindowsSandboxError(
      cause.code,
      `The Windows sandbox is installed. ${cause.message}`,
      'profile',
    )
  }
  const timedOut =
    cause instanceof WindowsSandboxError && cause.code === 'srt_win_timeout'
  throw new WindowsSandboxError(
    'profile_grant_failed',
    `The Windows sandbox is installed, but the read grant on your user ` +
      `profile ${timedOut ? 'did not finish in time' : 'could not be applied'}` +
      `: ${cause.message}\nNo session starts until it is complete. Run the ` +
      `install again, or grantWindowsProfileRead(), to finish it; ` +
      `forgetWindowsProfileRead() removes what was written.`,
    'profile',
  )
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
     * Defaults to {@link INSTALL_TIMEOUT_MS}.
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
 *
 * `[` and `]` are characters of a name here, but the walk that expands a
 * glob reads them as a character class. So a glob beneath a directory with
 * brackets in its name is also expanded beneath that directory taken as the
 * name it is (see path-entries.ts). A UNC glob is not: finding the directory
 * would probe the share.
 *
 * An entry marked `{ path, literal: true }` is a literal whatever it holds.
 * One that holds `*` or `?` is skipped: no Win32 name has them, and
 * `srt-win` refuses the characters outright.
 */
export function expandWindowsFsPaths(
  patterns: readonly FilesystemPathEntry[],
  opts?: { mode?: 'grant' | 'deny' },
): string[] {
  const out = new Set<string>()
  for (const entry of patterns) {
    const marked = typeof entry !== 'string'
    const raw = marked ? markedLiteralPath(entry) : entry
    const norm = normalizePathForSandbox(
      raw,
      marked ? { literal: true } : undefined,
    )
    if (marked && containsGlobCharsWin(norm)) {
      logForDebugging(
        `[Sandbox Windows] Skipping a literal path that no file can have: ${norm}`,
        { level: 'warn' },
      )
      continue
    }
    const isGlob = !marked && containsGlobCharsWin(norm)
    // UNC literal: pass raw (no stat) — see {@link isUncPath}. A
    // UNC glob falls through to expandGlobPattern below.
    if (isUncPath(norm) && !isGlob) {
      out.add(norm)
      continue
    }
    const candidates = isGlob
      ? [
          ...expandGlobPattern(norm, { caseInsensitive: true }),
          ...literalReadings(raw, opts?.mode === 'deny' ? 'deny' : 'allow', {
            isPattern: containsGlobCharsWin,
          }).flatMap(reading =>
            reading.glob
              ? expandGlobPattern(reading.path, {
                  caseInsensitive: true,
                  anchor: reading.anchor,
                })
              : [],
          ),
        ]
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
 * A path that names a network share (`\\\\server\\share\\…`, `\\\\?\\UNC\\…`) or
 * anything in the device namespace other than a drive (`\\\\.\\pipe\\…`,
 * `\\\\?\\GLOBALROOT\\…`). Such a path is never opened, listed or
 * resolved by the checks here: for a share that would send the real
 * user's credentials to whatever server a session's configuration
 * names (see {@link isUncPath}).
 */
function isUnprobedWindowsPath(p: string): boolean {
  return isUncPath(p) || /^[\\/]{2}[?.][\\/](?![a-z]:)/i.test(p)
}

/** What the one look at a path on disk found. */
type ResolvedWindowsPath =
  /** The object it names, with links, 8.3 names and case resolved. */
  | { state: 'resolved'; path: string }
  /** Nothing is there (or a parent is not a directory). */
  | { state: 'absent' }
  /** Not looked at: see {@link isUnprobedWindowsPath}. */
  | { state: 'unprobed' }
  /** Looking failed for another reason: access denied, an I/O error. */
  | { state: 'error'; code: string }

/** "Does not exist" as opposed to "could not look". */
function isAbsentError(e: unknown): boolean {
  const code = (e as NodeJS.ErrnoException | undefined)?.code
  return code === 'ENOENT' || code === 'ENOTDIR'
}

/**
 * The single place a path of a session's configuration is resolved on
 * disk for comparison: the same final-path lookup `srt-win` makes.
 */
function resolveWindowsPath(p: string): ResolvedWindowsPath {
  if (isUnprobedWindowsPath(p)) return { state: 'unprobed' }
  try {
    // The final-path lookup itself, which also resolves 8.3 names and the
    // case on disk.
    // eslint-disable-next-line no-restricted-properties
    return { state: 'resolved', path: fs.realpathSync.native(p) }
  } catch (e) {
    return isAbsentError(e)
      ? { state: 'absent' }
      : {
          state: 'error',
          code: (e as NodeJS.ErrnoException | undefined)?.code ?? 'unknown',
        }
  }
}

/**
 * `p` for comparison with another path, as the object `srt-win` opens for it:
 * links, junctions, 8.3 names and the case on disk are resolved by the same
 * final-path lookup the helper makes. On top of that, lower case, `/`
 * separators and none at the end. A path that cannot be opened is compared as
 * spelled, and so is one that is never probed (see
 * {@link isUnprobedWindowsPath}).
 */
function windowsPathKey(p: string): string {
  return windowsPathKeyOf(p, resolveWindowsPath(p))
}

/** {@link windowsPathKey} from a look at the path already taken. */
function windowsPathKeyOf(p: string, resolved: ResolvedWindowsPath): string {
  return normalizeCaseForComparison(
    path.win32
      .normalize(
        stripExtendedPathPrefix(
          resolved.state === 'resolved' ? resolved.path : p,
        ),
      )
      .replace(/\\/g, '/')
      .replace(/\/+$/, ''),
  )
}

/** The one of `dirs` that a path is, or lies beneath. */
function coveringWindowsPath(
  dirs: readonly string[],
): (p: string) => string | undefined {
  const keys = dirs.map(windowsPathKey)
  return p => {
    if (keys.length === 0) return undefined
    const key = windowsPathKey(p)
    const covering = keys.findIndex(dir => isAtOrUnder(key, dir))
    return covering < 0 ? undefined : dirs[covering]
  }
}

/**
 * The ones of `grants` that lie strictly beneath one of `denies`: the
 * grants that rank above those denies, an allow set further down
 * being the one that counts. `srt-win` is told about them with a
 * per-command read deny, so that it does not carry the deny onto a
 * recorded path of the profile read grant that the session's own
 * allow covers.
 */
export function windowsGrantsBeneathDenies(
  grants: readonly string[],
  denies: readonly string[],
): string[] {
  if (grants.length === 0 || denies.length === 0) return []
  const denyKeys = denies.map(windowsPathKey)
  const keyed = grants.map(g => ({ path: g, key: windowsPathKey(g) }))
  // Per deny, the topmost grants strictly beneath THAT deny: `srt-win`
  // spares, for each deny, what lies at or beneath an allow that is
  // strictly beneath it. A grant beneath another grant adds nothing
  // for the same deny — but it may be the only one beneath a second,
  // deeper deny that the upper grant lies above, so the reduction is
  // made deny by deny and the results joined. (If the list is still
  // too long for a command line, the command is refused with
  // `argv_too_long`; neither an exception nor the deny is dropped.)
  const out = new Map<string, string>()
  for (const d of denyKeys) {
    const beneath = keyed.filter(g => g.key !== d && isAtOrUnder(g.key, d))
    for (const g of beneath) {
      const covered = beneath.some(
        other => other.key !== g.key && isAtOrUnder(g.key, other.key),
      )
      if (!covered && !out.has(g.key)) out.set(g.key, g.path)
    }
  }
  return [...out.values()]
}

/** What `srt-win` is handed: see {@link rankWindowsFsAccess}. */
export interface WindowsFsAccessSet {
  grantRead: string[]
  grantWrite: string[]
  denyRead: string[]
  denyWrite: string[]
}

/**
 * Ranks the lists against each other, as on the other platforms, and returns
 * the grants and stamps that say so. Takes concrete paths
 * ({@link expandWindowsFsPaths}).
 *
 * The ACEs set on an object come before the ones it inherits, so beneath a
 * DENY on a directory an ALLOW set further down is the one that counts. That
 * is the rank of `allowRead` over `denyRead`. The other two ranks are the
 * opposite one, so `srt-win` is handed no such ALLOW for them:
 *
 * - `denyWrite` over `allowWrite`: a write grant at or beneath a write deny
 *   is a read grant.
 * - `credentialDeny` (`credentials.files`) over `allowRead` and `allowWrite`:
 *   a grant at or beneath a credential deny is left out. The caller adds the
 *   grants for the library's own files to the result, so they are the only
 *   exceptions.
 *
 * `held` are grants that are on disk already: the session's, when one command
 * brings denies of its own. They cannot be taken back for one command, so
 * each gets the deny at its own path, where `srt-win` puts DENY first.
 */
export function rankWindowsFsAccess(lists: {
  allowRead: readonly string[]
  allowWrite: readonly string[]
  denyRead: readonly string[]
  denyWrite: readonly string[]
  credentialDeny: readonly string[]
  held?: Pick<WindowsFsAccessSet, 'grantRead' | 'grantWrite'>
}): WindowsFsAccessSet {
  const credentialDenyOver = coveringWindowsPath(lists.credentialDeny)
  const writeDenyOver = coveringWindowsPath(lists.denyWrite)
  const grantRead = new Set<string>()
  const grantWrite = new Set<string>()
  const rank = (list: 'allowRead' | 'allowWrite', p: string): void => {
    const credentialDeny = credentialDenyOver(p)
    const writeDeny = list === 'allowWrite' ? writeDenyOver(p) : undefined
    if (credentialDeny === undefined && writeDeny === undefined) {
      const grants = list === 'allowRead' ? grantRead : grantWrite
      grants.add(p)
      return
    }
    if (credentialDeny === undefined) grantRead.add(p)
    logForDebugging(
      `[Sandbox Windows] ${list} ${p} is at or beneath ` +
        (credentialDeny !== undefined
          ? `the credential file entry ${credentialDeny}: not granted`
          : `denyWrite ${writeDeny}: granted read only`),
      { level: 'warn' },
    )
  }
  for (const p of lists.allowRead) rank('allowRead', p)
  for (const p of lists.allowWrite) rank('allowWrite', p)
  const heldRead = lists.held?.grantRead ?? []
  const heldWrite = lists.held?.grantWrite ?? []
  return {
    grantRead: [...grantRead],
    grantWrite: [...grantWrite],
    denyRead: [
      ...new Set([
        ...lists.denyRead,
        ...lists.credentialDeny,
        ...[...heldRead, ...heldWrite].filter(
          p => credentialDenyOver(p) !== undefined,
        ),
      ]),
    ],
    denyWrite: [
      ...new Set([
        ...lists.denyWrite,
        ...heldWrite.filter(p => writeDenyOver(p) !== undefined),
      ]),
    ],
  }
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
):
  | MappedDriveCwdError
  | (WindowsSandboxError & { drive?: undefined })
  | undefined {
  for (const line of stderr.split(/\r?\n/)) {
    const t = line.trim()
    if (!t.startsWith('{') || !t.includes('"code"')) continue
    try {
      const j = JSON.parse(t) as {
        code?: string
        message?: string
        drive?: string
      }
      // Exit 25: the command needed the lock a profile grant or forget
      // is holding.
      if (j.code === 'profile_operation_in_progress') {
        return new WindowsSandboxError(
          'profile_operation_in_progress',
          j.message ?? 'a profile grant or forget is in progress',
          'exec',
        )
      }
      // Exit 26: the process named with `heldBy` ended while the
      // command ran, and the command was terminated with it.
      if (j.code === 'session_ended') {
        return new WindowsSandboxError(
          'session_ended',
          j.message ??
            'the session that started this command ended; the command was terminated',
          'exec',
        )
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
 * The `acl revoke` statuses after which a grant is known to be off
 * disk, or legitimately still there for another holder. A revoke is
 * complete only if every outcome carries one of these.
 *
 * This is an allow-list, so a status this code does not know fails
 * closed: the srt-win binary a host embeds can be newer or older than
 * this file, and a status added later ("unreadable", "failed") means
 * the grant may still be on disk. "missing" has a further condition —
 * see {@link windowsAclGrantReleased}.
 */
const WINDOWS_ACL_GRANT_RELEASED_STATUSES: ReadonlySet<string> = new Set([
  'revoked',
  'stillHeld',
  'downgraded',
  'relocated',
  'noRow',
  'missing',
])

/**
 * Whether one `acl revoke` outcome shows its grant released.
 *
 * "missing" counts only if the path really is gone: an srt-win that
 * predates the "unreadable" status reports a path it merely could not
 * open as "missing" and forgets it, with the ACE still on the object.
 * A path that no longer exists carries no ACE. The check does not
 * follow a link at the path, and any answer other than "no such
 * entry" (including an error from the check) counts as still there.
 */
function windowsAclGrantReleased(o: unknown): boolean {
  if (typeof o !== 'object' || o === null) return false
  const { path: p, status } = o as Partial<WindowsAclAceOutcome>
  if (typeof p !== 'string' || typeof status !== 'string') return false
  if (!WINDOWS_ACL_GRANT_RELEASED_STATUSES.has(status)) return false
  if (status !== 'missing') return true
  try {
    fs.lstatSync(p)
    return false
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === 'ENOENT'
  }
}

/**
 * Holders (by PID) for which a grant revoke in this process did not
 * complete, with the paths it reported as possibly still granted.
 * Never cleared: once a grant may have been left on disk, a later
 * revoke that finds nothing to do proves nothing (an older srt-win
 * has already forgotten the path), so that holder's deny ACEs stay
 * for the rest of the process.
 */
const windowsAclIncompleteRevokes = new Map<number, Set<string>>()

/**
 * The paths whose grants an incomplete revoke by `holderPid` (default:
 * this process) may have left on disk — `undefined` if every revoke
 * so far completed. The list can be empty: a revoke that timed out or
 * printed nothing names no paths.
 */
export function windowsAclIncompleteRevoke(
  holderPid: number = process.pid,
): string[] | undefined {
  const paths = windowsAclIncompleteRevokes.get(holderPid)
  return paths && [...paths]
}

/** @internal Test hook: forget every incomplete revoke. */
export function clearWindowsAclIncompleteRevokesForTesting(): void {
  windowsAclIncompleteRevokes.clear()
}

/**
 * Release this holder's deny ACEs and remove the sandbox-user ACE
 * on any path whose refcount falls to zero. Best-effort (does not
 * throw on per-path anomalies); returns per-path outcomes for the
 * caller to surface. Returns `undefined` when `srt-win` itself
 * failed (no JSON to parse) or when the restore was refused.
 *
 * Ordering rule: release the grants first, with
 * {@link revokeWindowsAclChecked}, and call this only if that
 * reported `complete`. The deny ACEs protect paths inside the granted
 * trees from the sandbox account, which every session shares; taking
 * them off while a grant may still be on disk exposes those paths to
 * another session's sandboxed process. As a backstop this function
 * refuses (logs, spawns nothing, returns `undefined`) while a revoke
 * for the same holder has been incomplete in this process.
 */
export function restoreWindowsAcl(opts: {
  sandboxUserSid: string
  holderPid?: number
  srtWin?: SrtWinSpawn
}): WindowsAclAceOutcome[] | undefined {
  const holder = opts.holderPid ?? process.pid
  if (windowsAclIncompleteRevokes.has(holder)) {
    logForDebugging(
      `[Sandbox Windows] acl restore refused: a grant revoke for ` +
        `holder ${holder} did not complete in this process, so its ` +
        `deny ACEs stay in place`,
      { level: 'error' },
    )
    return undefined
  }
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
  /**
   * `read` paths that may be granted although the profile read grant
   * excludes them (`srt-win acl grant --allow-profile-exclusion`).
   * `srt-win` refuses a path that reaches an exclusion by itself; this
   * is the explicit word it takes for a read path that is a protected
   * path or lies inside one. Nothing admits a write path.
   */
  allowProfileExclusions?: readonly string[]
  /** Resolved `srt-win` spawn descriptor — from {@link resolveSrtWin}. */
  srtWin?: SrtWinSpawn
}

function allowProfileExclusionArgs(opts: WindowsAclGrantOptions): string[] {
  return (opts.allowProfileExclusions ?? []).flatMap(p => [
    '--allow-profile-exclusion',
    p,
  ])
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
      ...allowProfileExclusionArgs(opts),
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
 * Session start under the write-restricted token (the default; see
 * `windows.writeRestrictedToken`): one `srt-win acl grant
 * --persistent` carrying the grants and the deny lists.
 *
 * Each `write` path becomes a persistent root. It gets ACEs for the
 * sandbox group and for a capability SID of its own — none for the
 * sandbox user — and they are KEPT when the session ends:
 * {@link revokeWindowsAclChecked} does not remove them,
 * {@link forgetWindowsPersistentGrants} does. A root that already
 * carries them costs one DACL read here instead of a walk of its
 * tree. Deny targets under a persistent root are stamped for the
 * sandbox group and kept with it; `read` grants and deny targets
 * elsewhere are per-session, as with {@link grantWindowsAcl} and
 * {@link stampWindowsAcl}, and are released the same way.
 *
 * Pass `write` to {@link wrapCommandWithSandboxWindows} as
 * `writeRoots`.
 *
 * Asynchronous: a root's first grant walks its whole tree, and the
 * event loop of the embedding program stays live meanwhile.
 *
 * @throws on exit ≠ 0, including exit 2 (an input was skipped).
 *   Nothing falls back to a per-session grant.
 */
export async function grantWindowsAclPersistent(
  opts: WindowsAclGrantOptions & {
    denyRead: readonly string[]
    denyWrite: readonly string[]
  },
): Promise<void> {
  const holder = opts.holderPid ?? process.pid
  const stdin = JSON.stringify({
    read: opts.read,
    write: opts.write,
    denyRead: opts.denyRead,
    denyWrite: opts.denyWrite,
  })
  const r = await runSrtWinAsync(
    [
      'acl',
      'grant',
      '--holder-pid',
      `${holder}`,
      '--sandbox-user-sid',
      opts.sandboxUserSid,
      '--persistent',
      ...allowProfileExclusionArgs(opts),
    ],
    // A root's first grant walks its whole tree.
    { timeoutMs: 600_000, stdin, srtWin: opts.srtWin },
  )
  logForDebugging(
    `[Sandbox Windows] acl grant --persistent exit=${r.status}: ` +
      `${r.stderr || r.stdout}`,
  )
  if (r.status !== 0) {
    throw new WindowsSandboxError(
      'acl_grant_failed',
      `srt-win acl grant --persistent exited ${r.status} ` +
        (r.status === 2 ? '(partial — some inputs skipped)' : '(failed)') +
        `: ${r.stderr || r.stdout}`,
    )
  }
}

/**
 * Remove every write grant kept between sessions (`srt-win acl forget
 * --all`): one walk per root.
 *
 * A session with `windows.writeRestrictedToken: false` must run this
 * before it grants anything, whenever
 * {@link WindowsSandboxUserStatus.persistentGrants} is set: a kept
 * grant lets the sandbox account write its tree under the ordinary
 * token.
 *
 * Asynchronous: it walks each root's tree.
 *
 * `unlessHeldByOthers` (the calling session's process id) makes it
 * remove nothing if another live session is running on a kept grant.
 *
 * @throws `kept_grants_in_use` in that case, naming the sessions;
 *   `acl_forget_failed` if any grant could not be removed.
 */
export async function forgetWindowsPersistentGrants(
  opts: { unlessHeldByOthers?: number; srtWin?: SrtWinSpawn } = {},
): Promise<void> {
  const r = await runSrtWinAsync(
    ['acl', 'forget', '--all', ...unlessHeldArgs(opts.unlessHeldByOthers)],
    { timeoutMs: 600_000, srtWin: opts.srtWin },
  )
  logForDebugging(
    `[Sandbox Windows] acl forget --all exit=${r.status}: ` +
      `${r.stderr || r.stdout}`,
  )
  if (r.status !== 0) {
    throw new WindowsSandboxError(
      'acl_forget_failed',
      `Write grants kept from earlier sessions could not be removed, ` +
        `so windows.writeRestrictedToken: false cannot take effect (srt-win ` +
        `acl forget --all exited ${r.status}): ${r.stderr || r.stdout}`,
    )
  }
}

function unlessHeldArgs(holderPid: number | undefined): string[] {
  return holderPid === undefined
    ? []
    : ['--unless-held-by-others', `${holderPid}`]
}

/**
 * Outcome of a revoke as the session teardown needs it.
 */
export interface WindowsAclRevokeResult {
  /**
   * True only when `srt-win acl revoke` exited 0, its output parsed,
   * and every per-path outcome shows the grant released (see
   * {@link WINDOWS_ACL_GRANT_RELEASED_STATUSES}). A timeout, a spawn
   * failure, unparseable output, a non-zero exit, or any other
   * status leaves it false.
   */
  complete: boolean
  outcomes: WindowsAclAceOutcome[] | undefined
  /**
   * Paths whose outcome does not show the grant released — the grant
   * may still be on disk there. Empty when `complete`, and also when
   * the revoke reported no outcomes at all.
   */
  pending: string[]
  /** srt-win's stderr, or the error that stopped the revoke. */
  detail?: string
}

/**
 * {@link revokeWindowsAcl} that also reports whether the revoke
 * completed. Gate {@link restoreWindowsAcl} on `complete`: taking
 * the DENY stamps off while an ALLOW grant may still be on disk
 * would open the deny targets to the (shared) sandbox account.
 *
 * An incomplete revoke is remembered for the holder for the rest of
 * the process — see {@link windowsAclIncompleteRevoke}.
 */
export function revokeWindowsAclChecked(opts: {
  sandboxUserSid: string
  holderPid?: number
  srtWin?: SrtWinSpawn
}): WindowsAclRevokeResult {
  const holder = opts.holderPid ?? process.pid
  let result: WindowsAclRevokeResult
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
    result = windowsAclRevokeResult(r.ok, r.json, r.stderr)
  } catch (e) {
    const detail = (e as Error).message
    logForDebugging(`[Sandbox Windows] acl revoke: ${detail}`, {
      level: 'error',
    })
    result = { complete: false, outcomes: undefined, pending: [], detail }
  }
  noteWindowsAclRevoke(holder, result)
  return result
}

/** Judge a revoke that ran to the end and printed JSON. */
function windowsAclRevokeResult(
  exitedZero: boolean,
  json: unknown,
  stderr: string,
): WindowsAclRevokeResult {
  const outcomes = Array.isArray(json)
    ? (json as WindowsAclAceOutcome[])
    : undefined
  const unreleased = (outcomes ?? []).filter(o => !windowsAclGrantReleased(o))
  return {
    complete: exitedZero && outcomes !== undefined && unreleased.length === 0,
    outcomes,
    pending: unreleased.map(o => String(o?.path)),
    detail: stderr.trim() || undefined,
  }
}

function noteWindowsAclRevoke(
  holder: number,
  result: WindowsAclRevokeResult,
): void {
  if (result.complete) return
  let paths = windowsAclIncompleteRevokes.get(holder)
  if (!paths) windowsAclIncompleteRevokes.set(holder, (paths = new Set()))
  for (const p of result.pending) paths.add(p)
}

/**
 * Release this holder's grants and remove the sandbox-user ACE on
 * any path whose refcount falls to zero. Best-effort (does not
 * throw); logs anomalies.
 *
 * Ordering rule: do not follow this with {@link restoreWindowsAcl}.
 * The returned list does not say whether the revoke completed (a
 * path can be listed with a status that means its grant is still on
 * disk, and `undefined` means it did not run). Use
 * {@link revokeWindowsAclChecked} and restore only when it reports
 * `complete`.
 */
export function revokeWindowsAcl(opts: {
  sandboxUserSid: string
  holderPid?: number
  srtWin?: SrtWinSpawn
}): WindowsAclAceOutcome[] | undefined {
  return revokeWindowsAclChecked(opts).outcomes
}

// ────────────────────────────────────────────────────────────────────
// Profile read grant
// ────────────────────────────────────────────────────────────────────

/**
 * What `srt-win profile status` reports. Only `current` is a grant a
 * session may rely on: complete, made with this `srt-win`'s exclusion
 * list, for the profile directory that is there now.
 */
export type WindowsProfileGrantState =
  | 'none'
  | 'current'
  | 'outdated'
  | 'incomplete'
  | 'unknown'

/** One path the grant wrote on, as `srt-win` recorded it. */
export interface WindowsProfileGrantPath {
  /** Canonical (`\\?\`-prefixed) path. */
  path: string
  /**
   * `container`: listable, children granted one by one. `granted`: a
   * directory readable with everything below it. `file`: a single
   * readable file. `denied`: an exclusion.
   */
  kind: 'container' | 'granted' | 'file' | 'denied'
}

export interface WindowsProfileGrantStatus {
  state: WindowsProfileGrantState
  /** Why the state is not `current`, when `srt-win` says. */
  reason?: string
  /** The profile directory the grant was made for. */
  profile?: string
  /**
   * What `srt-win` says it does, by name (see
   * {@link WINDOWS_SRT_WIN_CAPABILITIES}); empty from one that does
   * not say.
   */
  capabilities: string[]
  /**
   * What the last run of the grant left as it found it, as
   * {@link WindowsProfileGrantResult} reports it: objects in the
   * profile this user may not change. None of them makes the grant
   * unusable. `unprotected` is the list to show the user.
   */
  notGranted: WindowsProfileGrantItem[]
  selfClosed: WindowsProfileGrantItem[]
  unverifiable: WindowsProfileGrantItem[]
  unprotected: WindowsProfileGrantItem[]
  staleAllow: WindowsProfileGrantItem[]
  /** Exclusions added to the built-in list when the grant was made, relative to the profile. */
  extraExclusions: string[]
  /**
   * Every PROTECTED path the grant was made to keep unreadable —
   * credential, key and token stores: the built-in list of the
   * `srt-win` that made it and the added ones — as absolute paths,
   * existing or not. A component that is `*` stands for any one name,
   * one ending in `*` for any name with that prefix. Each is denied,
   * and a session may not grant a path that is one, lies inside one,
   * or lies above one.
   */
  exclusions: string[]
  /**
   * The UNGRANTED-ONLY directories, in the same form (the user's
   * temporary directory): not readable through the grant, and not
   * denied. A session may grant a directory of its own inside one; it
   * may not grant the directory itself or one above it.
   */
  ungrantedOnly: string[]
  counts: { containers: number; granted: number; files: number; denied: number }
  /**
   * Configuration-file variables for a sandboxed command — see
   * {@link windowsProfileReadEnv}. Empty unless `current`.
   */
  env: Record<string, string>
  /** Every recorded path; only when asked for. */
  paths?: WindowsProfileGrantPath[]
}

type RawProfileStatus = {
  record_version?: unknown
  capabilities?: unknown
  not_granted?: unknown
  self_closed?: unknown
  unverifiable?: unknown
  unprotected?: unknown
  stale_allow?: unknown
  state?: string
  reason?: string
  profile?: string | null
  extra_exclusions?: string[]
  exclusions?: unknown
  ungranted_only?: unknown
  containers?: number
  granted?: number
  files?: number
  denied?: number
  env?: Record<string, unknown>
  paths?: { path?: unknown; kind?: unknown }[]
}

const PROFILE_GRANT_STATES: ReadonlySet<string> = new Set([
  'none',
  'current',
  'outdated',
  'incomplete',
  'unknown',
])
const PROFILE_PATH_KINDS: ReadonlySet<string> = new Set([
  'container',
  'granted',
  'file',
  'denied',
])

/**
 * The variables {@link windowsProfileReadEnv} can return. Each names
 * one configuration FILE, but for `RUSTUP_HOME` and `CARGO_HOME`,
 * which name the directories a Rust toolchain is found through:
 * rustup's `cargo` and `rustc` look for a toolchain under the home
 * they see, and the sandbox account's has none. Nothing in the real
 * profile is writable to a sandboxed command, so cargo builds from
 * what is already cached there (`--offline`) and cannot add to it.
 * None of the others is a directory a tool also writes under
 * (`USERPROFILE`, `HOME`, `APPDATA`, `LOCALAPPDATA`, `TEMP`, `TMP`,
 * `GRADLE_USER_HOME`, …): those stay in the sandbox account's own
 * profile, and a name outside this list is dropped whatever `srt-win`
 * reports.
 */
export const WINDOWS_PROFILE_READ_ENV_VARS: readonly string[] = [
  'NPM_CONFIG_USERCONFIG',
  'GIT_CONFIG_GLOBAL',
  'PIP_CONFIG_FILE',
  'MAVEN_ARGS',
  'RUSTUP_HOME',
  'CARGO_HOME',
]

/**
 * The version of `srt-win profile status`'s record format this
 * library reads. Another version — older, newer, or none — is not
 * read on a best-effort basis: the lists in it decide what a session
 * may grant.
 */
const WINDOWS_PROFILE_RECORD_VERSION = 1

function stringList(v: unknown): string[] | undefined {
  return Array.isArray(v) && v.every(x => typeof x === 'string' && x !== '')
    ? (v as string[])
    : undefined
}

/**
 * Why a status that says `current` cannot be relied on, if so. The
 * exclusion lists are what the session-path check runs against, and
 * the built-in list is never empty: a status without them (an older
 * `srt-win`, a damaged record, a renamed field) must not read as
 * "nothing is excluded".
 */
function profileStatusProblem(raw: RawProfileStatus): string | undefined {
  if (raw.record_version !== WINDOWS_PROFILE_RECORD_VERSION) {
    return (
      `srt-win reports record format ${JSON.stringify(raw.record_version)}; ` +
      `this library reads format ${WINDOWS_PROFILE_RECORD_VERSION}`
    )
  }
  const exclusions = stringList(raw.exclusions)
  if (!exclusions || exclusions.length === 0) {
    return 'the recorded grant carries no list of excluded paths'
  }
  if (!stringList(raw.ungranted_only)) {
    return 'the recorded grant carries no list of ungranted directories'
  }
  return undefined
}

function mapProfileStatus(raw: RawProfileStatus): WindowsProfileGrantStatus {
  // A state this code does not know is not a usable grant.
  let state = (
    PROFILE_GRANT_STATES.has(raw.state ?? '') ? raw.state : 'unknown'
  ) as WindowsProfileGrantState
  let reason = raw.reason
  const problem = state === 'current' ? profileStatusProblem(raw) : undefined
  if (problem) {
    state = 'outdated'
    reason = problem
  }
  const env: Record<string, string> = {}
  if (state === 'current') {
    for (const name of WINDOWS_PROFILE_READ_ENV_VARS) {
      const v = raw.env?.[name]
      if (typeof v === 'string' && v !== '') env[name] = v
    }
  }
  return {
    state,
    ...(reason && { reason }),
    ...(raw.profile && { profile: raw.profile }),
    capabilities: capabilityList(raw.capabilities),
    notGranted: grantItems(raw.not_granted),
    selfClosed: grantItems(raw.self_closed),
    unverifiable: grantItems(raw.unverifiable),
    unprotected: grantItems(raw.unprotected),
    staleAllow: grantItems(raw.stale_allow),
    extraExclusions: raw.extra_exclusions ?? [],
    exclusions: stringList(raw.exclusions) ?? [],
    ungrantedOnly: stringList(raw.ungranted_only) ?? [],
    counts: {
      containers: raw.containers ?? 0,
      granted: raw.granted ?? 0,
      files: raw.files ?? 0,
      denied: raw.denied ?? 0,
    },
    env,
    ...(raw.paths && {
      paths: raw.paths.filter(
        (p): p is WindowsProfileGrantPath =>
          typeof p.path === 'string' &&
          typeof p.kind === 'string' &&
          PROFILE_PATH_KINDS.has(p.kind),
      ),
    }),
  }
}

/**
 * The recorded profile read grant (`srt-win profile status`): whether
 * one exists and is current, and with `paths` every path it wrote on.
 * Cheap: `srt-win` reads its record and opens the profile directory,
 * nothing below it.
 */
export function getWindowsProfileReadStatus(
  opts: { paths?: boolean; srtWin?: SrtWinSpawn } = {},
): WindowsProfileGrantStatus {
  const args = ['profile', 'status']
  if (opts.paths) args.push('--paths')
  const raw = runSrtWinJson<RawProfileStatus>(args, {
    timeoutMs: 30_000,
    srtWin: opts.srtWin,
  })
  // Asked while a grant or forget is running: the record is being
  // rewritten, and is not a run that was cut short.
  if (raw.state === 'in_progress') {
    throwIfRefusedBesideOthers(args, SRT_WIN_EXIT_PROFILE_BUSY, '')
  }
  return mapProfileStatus(raw)
}

export interface WindowsProfileGrantOptions {
  /**
   * Paths inside the profile to keep unreadable in addition to the
   * built-in list (absolute, or relative to the profile): for example
   * the embedding program's own configuration directory. They are
   * recorded with the grant and stay in force — for every session,
   * read and write — on later runs that do not name them. Nothing
   * removes a built-in exclusion.
   *
   * These are deliberate, lasting choices. A session's own
   * `filesystem.denyRead` and `credentials.files` do NOT belong here:
   * a session denies those itself, for as long as it runs, and a path
   * recorded here can no longer lie inside any session's
   * `allowWrite` root.
   */
  exclude?: readonly string[]
  /**
   * Make `exclude` the whole added list, dropping the entries earlier
   * runs recorded. Without it a run only ever adds.
   */
  replaceExclusions?: boolean
  /**
   * Kill `srt-win` after this long. Default 30 minutes: the first run
   * touches every file under the granted directories.
   */
  timeoutMs?: number
  /** Called with each progress line `srt-win` writes (a count of top-level items done). */
  onProgress?: (line: string) => void
  /** Resolved `srt-win` spawn descriptor — from {@link resolveSrtWin}. */
  srtWin?: SrtWinSpawn
}

/** One path `srt-win profile grant` skipped or could not write. */
export interface WindowsProfileGrantItem {
  path: string
  reason: string
  /**
   * On an `unverifiable` item: whether YOU can open the object for
   * reading — `true`, `false`, or `'unknown'` where that was not
   * tried. One you can read without being able to see its access list
   * is to be taken as readable to sandboxed commands as well.
   */
  callerReads?: boolean | 'unknown'
  /**
   * On an `unverifiable` item: why it could not be examined —
   * `acl_unreadable`, `account_unknown` (the sandbox account's
   * identity is not known), `not_local`, `probe_failed`.
   */
  cause?: string
  /**
   * Set where an entry THIS PRODUCT wrote is what makes the path
   * readable to sandboxed commands and could not be removed: whether
   * the path is on the exclusion list now (`true`: a protected store
   * open through that entry — such an item is among `unprotected`) or
   * has merely left the grant (`false`, among `staleAllow`).
   */
  protectedExclusion?: boolean
  /**
   * With `protectedExclusion`: `explicit` — the entry is on the
   * object, which you may not change; `inherited` — a copy handed down
   * from a directory above, which could not be taken off the object.
   * `reason` carries the `icacls` command that removes it.
   */
  entry?: 'explicit' | 'inherited'
}

export interface WindowsProfileGrantResult {
  profile: string
  containers: number
  granted: number
  files: number
  denied: number
  /** Excluded directories that did not exist and were created empty. */
  placeholders: number
  /** DACLs written by this run; 0 on a refresh that found nothing new. */
  writes: number
  unchanged: number
  /** Recorded paths that left the grant and had their entry removed. */
  removed: number
  /** Junctions, symbolic links, cloud placeholders: nothing is written on or through them. */
  skipped: WindowsProfileGrantItem[]
  /**
   * Paths that were to be granted and whose access list this user may
   * not change. They stay unreadable to sandboxed commands; where one
   * was to be a directory whose children are granted one by one,
   * nothing beneath it is granted either. The grant is whole without
   * them.
   */
  notGranted: WindowsProfileGrantItem[]
  /**
   * Excluded paths whose deny could not be written, and whose own
   * access list gives the sandbox account no read.
   */
  selfClosed: WindowsProfileGrantItem[]
  /**
   * Excluded paths whose deny could not be written and whose access
   * list this user may not even read (and so cannot use either).
   */
  unverifiable: WindowsProfileGrantItem[]
  /**
   * Excluded paths whose deny could not be written and whose own
   * access list lets the sandbox account read them — as it did before
   * the grant, which neither opened them nor can close them. Show
   * these to the user: only the owner of the object or an
   * administrator can close it.
   */
  unprotected: WindowsProfileGrantItem[]
  /**
   * Paths that have left the grant and still carry the allow of an
   * earlier run, which could not be removed: readable through the
   * grant's own entry. (One that is on the exclusion list now is
   * among `unprotected`, with `protectedExclusion` set.) Show these to
   * the user as well.
   */
  staleAllow: WindowsProfileGrantItem[]
  elapsedMs: number
}

const PROFILE_GRANT_TIMEOUT_MS = 30 * 60_000

/** A `[{path, reason}]` list as `srt-win` reports it; anything else is none. */
function grantItems(v: unknown): WindowsProfileGrantItem[] {
  return Array.isArray(v)
    ? v.flatMap(i => {
        const { path: p, reason } = (i ?? {}) as {
          path?: unknown
          reason?: unknown
        }
        if (typeof p !== 'string') return []
        const {
          caller_reads: reads,
          cause,
          protected_exclusion: protectedExclusion,
          entry,
        } = i as {
          caller_reads?: unknown
          cause?: unknown
          protected_exclusion?: unknown
          entry?: unknown
        }
        return [
          {
            path: p,
            reason: typeof reason === 'string' ? reason : '',
            ...((typeof reads === 'boolean' || reads === 'unknown') && {
              callerReads: reads,
            }),
            ...(typeof cause === 'string' && { cause }),
            ...(typeof protectedExclusion === 'boolean' && {
              protectedExclusion,
            }),
            ...((entry === 'explicit' || entry === 'inherited') && { entry }),
          },
        ]
      })
    : []
}

/**
 * Write the profile read grant, or bring it up to date
 * (`srt-win profile grant`). {@link installWindowsSandbox} runs it
 * after the elevated step; call it yourself to refresh — a new item
 * at the top of the profile (or in another directory whose children
 * are granted one by one) is not readable until then — or to add
 * exclusions. It runs as the user of this process, without elevation,
 * and grants that user's profile. `initialize()` never runs it.
 *
 * The first run can take minutes on a large profile; `onProgress`
 * receives a line per top-level item. Other sessions of the same user
 * cannot start while it runs.
 *
 * Objects in the profile that this user may not change do not fail
 * it: see `notGranted`, `selfClosed`, `unverifiable` and `unprotected`
 * in the result.
 *
 * It runs only on a quiet machine: while any sandbox session or
 * command of this user is running it writes nothing, and while it
 * runs none can start (they fail with `profile_operation_in_progress`
 * after about three seconds). A refresh therefore needs running
 * sessions closed.
 *
 * @throws `profile_grant_blocked_by_session` when a session or
 *   command is running (nothing is written; run it again when they
 *   have ended),
 *   `profile_grant_failed` on any other non-zero exit (the grant is
 *   then recorded as incomplete, or not at all), `srt_win_timeout`
 *   when `timeoutMs` passes.
 */
export async function grantWindowsProfileRead(
  opts: WindowsProfileGrantOptions = {},
): Promise<WindowsProfileGrantResult> {
  const { exe, prependArgs } = opts.srtWin ?? resolveSrtWin()
  const args = profileGrantArgs(opts)
  const timeoutMs = opts.timeoutMs ?? PROFILE_GRANT_TIMEOUT_MS
  const r = await new Promise<RunResult>((resolve, reject) => {
    const child = spawn(exe, [...prependArgs, ...args], { windowsHide: true })
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
    let pending = ''
    child.stdout?.setEncoding('utf8').on('data', d => (stdout += d))
    child.stderr?.setEncoding('utf8').on('data', (d: string) => {
      stderr += d
      pending += d
      const lines = pending.split(/\r?\n/)
      pending = lines.pop() ?? ''
      for (const line of lines) {
        if (line.trim() !== '') opts.onProgress?.(line)
      }
    })
    child.stdin?.on('error', () => {}).end()
    child.once('error', e => {
      clearTimeout(timer)
      reject(
        new WindowsSandboxError(
          'spawn_failed',
          `srt-win profile: spawn failed: ${e.message}`,
          'profile',
        ),
      )
    })
    child.once('close', (status, signal) => {
      clearTimeout(timer)
      if (pending.trim() !== '') opts.onProgress?.(pending)
      if (timedOut) {
        reject(
          new WindowsSandboxError(
            'srt_win_timeout',
            `srt-win profile grant timed out after ${timeoutMs}ms; the ` +
              `grant is recorded as incomplete — run it again, or remove ` +
              `it with forgetWindowsProfileRead()`,
            'profile',
          ),
        )
        return
      }
      try {
        throwIfRefusedBesideOthers(args, status, stdout)
      } catch (e) {
        reject(e as Error)
        return
      }
      resolve({ status, signal, stdout: stdout.trim(), stderr: stderr.trim() })
    })
  })
  return profileGrantResult(args, r)
}

function profileGrantArgs(opts: WindowsProfileGrantOptions): string[] {
  const args = ['profile', 'grant', '--json']
  for (const e of opts.exclude ?? []) args.push('--exclude', e)
  if (opts.replaceExclusions) args.push('--replace-excludes')
  return args
}

function profileGrantResult(
  args: string[],
  r: RunResult,
): WindowsProfileGrantResult {
  logForDebugging(
    `[Sandbox Windows] profile grant exit=${r.status}: ${r.stderr.slice(-2000)}`,
  )
  if (r.status !== 0) {
    throw new WindowsSandboxError(
      'profile_grant_failed',
      `srt-win profile grant exited ${r.status}: ` +
        `${r.stderr.slice(-2000) || r.stdout}`,
      'profile',
    )
  }
  // stdout carries one JSON object; `--json` puts nothing else there.
  const raw = parseSrtWinJson<{
    profile: string
    containers: number
    granted: number
    files: number
    denied: number
    placeholders: number
    writes: number
    unchanged: number
    removed: number
    skipped?: WindowsProfileGrantItem[]
    not_granted?: unknown
    self_closed?: unknown
    unverifiable?: unknown
    unprotected?: unknown
    stale_allow?: unknown
    failed?: WindowsProfileGrantItem[]
    elapsed_ms: number
  }>(args, r)
  return {
    profile: raw.profile,
    containers: raw.containers,
    granted: raw.granted,
    files: raw.files,
    denied: raw.denied,
    placeholders: raw.placeholders,
    writes: raw.writes,
    unchanged: raw.unchanged,
    removed: raw.removed,
    skipped: raw.skipped ?? [],
    notGranted: grantItems(raw.not_granted),
    selfClosed: grantItems(raw.self_closed),
    unverifiable: grantItems(raw.unverifiable),
    unprotected: grantItems(raw.unprotected),
    staleAllow: grantItems(raw.stale_allow),
    elapsedMs: raw.elapsed_ms,
  }
}

/**
 * {@link grantWindowsProfileRead} for the synchronous install: blocks
 * until `srt-win` exits, and hands `onProgress` its lines only then.
 */
function grantWindowsProfileReadSync(
  opts: WindowsProfileGrantOptions,
): WindowsProfileGrantResult {
  const args = profileGrantArgs(opts)
  const r = runSrtWin(args, {
    timeoutMs: opts.timeoutMs ?? PROFILE_GRANT_TIMEOUT_MS,
    srtWin: opts.srtWin,
  })
  for (const line of r.stderr.split(/\r?\n/)) {
    if (line.trim() !== '') opts.onProgress?.(line)
  }
  return profileGrantResult(args, r)
}

/**
 * Remove the profile read grant (`srt-win profile forget`): the
 * sandbox group's entry from every recorded path — each access list
 * is left as it was before the grant — and the empty directories the
 * grant created. `initialize()` runs this itself when it finds a
 * grant and `windows.writeRestrictedToken` is `false`; uninstall
 * removes the grant too.
 *
 * This is the synchronous form, for callers that are synchronous by
 * contract (a command-line tool, an exit path). It blocks for as long
 * as the removal takes, which on a large profile is minutes:
 * anything with an event loop to keep alive uses
 * {@link forgetWindowsProfileReadAsync}, as `initialize()` does.
 *
 * @throws `profile_forget_failed` if any path could not be completed;
 *   the grant then still counts as existing.
 */
export function forgetWindowsProfileRead(
  opts: { timeoutMs?: number; srtWin?: SrtWinSpawn } = {},
): void {
  const r = runSrtWin(['profile', 'forget', '--json'], {
    timeoutMs: opts.timeoutMs ?? PROFILE_GRANT_TIMEOUT_MS,
    srtWin: opts.srtWin,
  })
  profileForgetResult(r)
}

/**
 * {@link forgetWindowsProfileRead} without blocking the event loop.
 *
 * `unlessHeldByOthers` (the calling session's process id) makes it
 * remove nothing if another live session is running on a kept grant.
 *
 * @throws `kept_grants_in_use` in that case; `profile_forget_failed`
 *   if any path could not be completed.
 */
export async function forgetWindowsProfileReadAsync(
  opts: {
    timeoutMs?: number
    unlessHeldByOthers?: number
    srtWin?: SrtWinSpawn
  } = {},
): Promise<void> {
  const r = await runSrtWinAsync(
    ['profile', 'forget', '--json', ...unlessHeldArgs(opts.unlessHeldByOthers)],
    {
      timeoutMs: opts.timeoutMs ?? PROFILE_GRANT_TIMEOUT_MS,
      srtWin: opts.srtWin,
    },
  )
  profileForgetResult(r)
}

function profileForgetResult(r: RunResult): void {
  logForDebugging(
    `[Sandbox Windows] profile forget exit=${r.status}: ` +
      `${r.stderr || r.stdout}`,
  )
  if (r.status !== 0) {
    throw new WindowsSandboxError(
      'profile_forget_failed',
      `The profile read grant could not be removed (srt-win profile ` +
        `forget exited ${r.status}): ${r.stderr || r.stdout}`,
      'profile',
    )
  }
}

/** `p` for a comparison of profile paths: no `\\?\` prefix, `/`, lower case, no separator at the end. */
function profilePathKey(p: string): string {
  return stripExtendedPathPrefix(p)
    .replace(/\\/g, '/')
    .replace(/\/+$/, '')
    .toLowerCase()
}

/** How a path a session wants to grant stands to a profile exclusion. */
export interface WindowsProfileExclusionConflict {
  /** The path as the session configuration resolved it. */
  path: string
  /** The exclusion, as the grant recorded it. */
  exclusion: string
  /** Which list the exclusion is on. */
  kind: 'protected' | 'ungranted-only'
  /** What the session would have granted on the path. */
  access: 'read' | 'write'
  /**
   * `equal`: the path is the excluded one. `inside`: it lies beneath
   * an excluded directory (protected only). `above`: an excluded path
   * lies beneath it.
   */
  relation: 'equal' | 'inside' | 'above'
  /**
   * Set on an `above` conflict with a wildcard exclusion when the path
   * could not be examined for what the exclusion covers beneath it —
   * access denied, an I/O error, a path on a share — with the reason.
   * "Could not look" is treated as "something may match".
   */
  unexamined?: string
}

/** One component of a recorded exclusion against one of a path; both lower case. */
function exclusionComponentMatches(pattern: string, name: string): boolean {
  if (pattern === '*') return true
  if (pattern.endsWith('*')) return name.startsWith(pattern.slice(0, -1))
  return pattern === name
}

/**
 * Whether something that exists beneath the directory `dir` matches
 * `rest`, the components of an exclusion that `dir` lies above. No
 * link is followed out of `dir`, and the lookup goes exactly as deep
 * as the exclusion has components left.
 *
 * - `none`: every level that could lead to a match was listed, and
 *   nothing matches — including when `dir` is not a directory.
 * - `match`: something does.
 * - an object with `unexamined`: a level could not be listed for a
 *   reason other than not being there (access denied, an I/O error),
 *   or `dir` itself turned out to be a link. The caller treats that as
 *   a possible match: a path is admitted only when it was looked at
 *   and found empty of matches, never because looking failed.
 */
function exclusionMatchedBeneath(
  dir: string,
  rest: readonly string[],
  top = true,
): 'none' | 'match' | { unexamined: string } {
  if (rest.length === 0) return 'match'
  let entries: fs.Dirent[]
  try {
    const st = fs.lstatSync(dir)
    if (st.isSymbolicLink()) {
      // Beneath `dir`, a link is simply not followed. `dir` itself was
      // resolved a moment ago and should not be one.
      return top ? { unexamined: `'${dir}' is a link` } : 'none'
    }
    if (!st.isDirectory()) return 'none'
    entries = fs.readdirSync(dir, { withFileTypes: true })
  } catch (e) {
    if (isAbsentError(e)) return 'none'
    const code = (e as NodeJS.ErrnoException | undefined)?.code ?? 'error'
    return { unexamined: `'${dir}' could not be listed (${code})` }
  }
  let unexamined: { unexamined: string } | undefined
  for (const e of entries) {
    if (
      !exclusionComponentMatches(rest[0]!, normalizeCaseForComparison(e.name))
    ) {
      continue
    }
    const found = exclusionMatchedBeneath(
      path.join(dir, e.name),
      rest.slice(1),
      false,
    )
    if (found === 'match') return 'match'
    if (found !== 'none') unexamined ??= found
  }
  return unexamined ?? 'none'
}

/**
 * The paths among `paths` that a session must not grant read access
 * to while the profile read grant exists, with the exclusion each
 * collides with (`grant` is the recorded
 * {@link WindowsProfileGrantStatus}, or its two lists).
 *
 * A path is compared as the object it resolves to: links, junctions,
 * 8.3 names and case are resolved first, the way `srt-win` resolves a
 * path it is asked to grant.
 *
 * - Against a PROTECTED exclusion it collides when it is the excluded
 *   path, lies inside it, or lies above it. Above counts because a
 *   session grant inherits: an excluded store that is deleted and
 *   created again beneath it would be readable, which is what the
 *   grant's own layout never allows. An exclusion with a wildcard
 *   (`…\Local\*\EBWebView`) names no path until something matches
 *   it, and would otherwise make every directory under `Local`
 *   ungrantable: a path counts as above one only while something that
 *   exists beneath the path matches it. `srt-win` applies the same
 *   rule. The look is taken when a session starts — for every read
 *   and write path of its configuration, so also for a write root kept
 *   from an earlier session — and not continuously: a store that
 *   appears beneath a root later is found at the next start, which is
 *   then refused. It fails closed: a path that exists and cannot be
 *   listed (access denied, an I/O error) is refused like one with a
 *   match, and a path on a share or in the device namespace is never
 *   opened at all and refused if a wildcard exclusion could lie
 *   beneath it (it cannot, for a profile on a local drive). A path
 *   that does not exist has nothing beneath it and is admitted.
 *
 *   A store the sandboxed command itself creates beneath its own
 *   write root is that command's own data: nothing here tries to keep
 *   a command from reading what it wrote, and the next start's
 *   refusal is about the root, not about that command.
 * - Against an UNGRANTED-ONLY directory (the temporary directory) it
 *   collides when it is that directory or lies above it: the grant
 *   would cover everything in it. A path INSIDE one does not collide:
 *   that is where sessions, and this library, stage directories of
 *   their own.
 *
 * `opts.write` says the paths are write roots. A write root grants
 * read too, and its grant is kept between sessions, so the same rule
 * applies to it — without the override.
 *
 * `opts.override` (the embedder's
 * `dangerouslyAllowReadOfProfileExclusions`) takes a READ path out of
 * the result when one of its entries resolves to the same object and
 * the path is a protected path or lies inside one. It never takes out
 * a write root, a path above an exclusion, or an ungranted-only
 * directory itself.
 *
 * With no grant recorded both lists are empty and nothing collides:
 * nothing in the profile is readable by default then.
 */
export function windowsProfileExclusionConflicts(
  paths: readonly string[],
  grant: Pick<WindowsProfileGrantStatus, 'exclusions' | 'ungrantedOnly'>,
  opts: { override?: readonly string[]; write?: boolean } = {},
): WindowsProfileExclusionConflict[] {
  if (paths.length === 0) return []
  const access = opts.write ? 'write' : 'read'
  const rulesOf = (
    list: readonly string[],
    kind: WindowsProfileExclusionConflict['kind'],
  ) =>
    list.map(e => ({
      exclusion: e,
      kind,
      parts: normalizeCaseForComparison(profilePathKey(e)).split('/'),
    }))
  // An ungranted-only directory is looked for first as the path
  // itself, so that it is reported as what it is and not as "above"
  // something inside it; then the protected paths; then the
  // ungranted-only directories the path lies above.
  const ungranted = rulesOf(grant.ungrantedOnly, 'ungranted-only')
  const rules = [
    ...ungranted.map(r => ({ ...r, onlyEqual: true })),
    ...rulesOf(grant.exclusions, 'protected').map(r => ({
      ...r,
      onlyEqual: false,
    })),
    ...ungranted.map(r => ({ ...r, onlyEqual: false })),
  ]
  if (rules.length === 0) return []
  const admitted = new Set(
    opts.write ? [] : (opts.override ?? []).map(windowsPathKey),
  )
  const out: WindowsProfileExclusionConflict[] = []
  for (const p of paths) {
    // One guarded look at the path: the comparison key and the
    // lookups beneath it use the same result.
    const onDisk = resolveWindowsPath(p)
    const key = windowsPathKeyOf(p, onDisk)
    const parts = key.split('/')
    for (const r of rules) {
      const shared = Math.min(parts.length, r.parts.length)
      let related = true
      for (let i = 0; related && i < shared; i++) {
        related = exclusionComponentMatches(r.parts[i]!, parts[i]!)
      }
      if (!related) continue
      const relation =
        parts.length === r.parts.length
          ? 'equal'
          : parts.length > r.parts.length
            ? 'inside'
            : 'above'
      if (r.onlyEqual && relation !== 'equal') continue
      let unexamined: string | undefined
      if (relation === 'above' && r.exclusion.includes('*')) {
        if (onDisk.state === 'absent') continue
        if (onDisk.state === 'resolved') {
          const found = exclusionMatchedBeneath(
            onDisk.path,
            r.parts.slice(parts.length),
          )
          if (found === 'none') continue
          if (found !== 'match') unexamined = found.unexamined
        } else {
          // Never opened (a share, the device namespace) or not
          // openable: nothing was looked at, so nothing is admitted.
          unexamined =
            onDisk.state === 'unprobed'
              ? `'${p}' is not on a local drive and is not examined`
              : `'${p}' could not be resolved (${onDisk.code})`
        }
      }
      if (r.kind === 'ungranted-only') {
        if (relation === 'inside') continue
      } else if (relation !== 'above' && admitted.has(key)) {
        // An admitted path is still checked against the other
        // exclusions: it may lie above one of them.
        continue
      }
      out.push({
        path: p,
        exclusion: r.exclusion,
        kind: r.kind,
        access,
        relation,
        ...(unexamined === undefined ? {} : { unexamined }),
      })
      break
    }
  }
  return out
}

/**
 * Environment variables an embedder may set for a sandboxed command
 * so each tool reads the real user's configuration FILE in place:
 * `NPM_CONFIG_USERCONFIG`, `GIT_CONFIG_GLOBAL`, `PIP_CONFIG_FILE`,
 * `MAVEN_ARGS` — and finds the real user's Rust toolchain:
 * `RUSTUP_HOME`, `CARGO_HOME`, the directories the user's own
 * environment names or else `.rustup` and `.cargo` in the profile.
 * Each only if its file or directory exists and the grant covers it,
 * and never one `env` (what the embedder sets itself) already
 * holds. Empty unless the grant is current. The library sets none of
 * them by itself.
 *
 * The sandboxed process keeps its own `USERPROFILE`, `HOME`,
 * `APPDATA`, `LOCALAPPDATA`, `TEMP` and `TMP`: tools write caches
 * under those, and nothing here is writable.
 */
export function windowsProfileReadEnv(
  status: WindowsProfileGrantStatus,
  env: Readonly<Record<string, string | undefined>> = {},
): Record<string, string> {
  if (status.state !== 'current') return {}
  const supplied = new Set(
    Object.entries(env)
      .filter(([, v]) => v !== undefined)
      .map(([k]) => k.toUpperCase()),
  )
  const out: Record<string, string> = {}
  for (const name of WINDOWS_PROFILE_READ_ENV_VARS) {
    const v = status.env[name]
    if (v !== undefined && !supplied.has(name)) out[name] = v
  }
  return out
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
  const writeRestricted = windowsWriteRestrictedTokenEnabled(p)
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
      encodeSandboxedCommand(attributionKeyFor(p.command, p.commandId)),
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
    // Schannel cannot acquire credentials under the write-restricted
    // token, so git's default backend on Windows would fail every
    // HTTPS operation; its OpenSSL backend is unaffected and reads the
    // same GIT_SSL_CAINFO.
    opensslBackend: writeRestricted,
    baseEnv: p.setEnvVars,
  })

  const argv: string[] = [exe, ...prependArgs, 'exec']
  if (p.quiet !== false) argv.push('--quiet')
  if (p.heldBy !== undefined) argv.push('--held-by', `${p.heldBy}`)
  if (writeRestricted) {
    argv.push('--write-restricted-token')
    for (const r of p.writeRoots ?? []) argv.push('--write-root', r)
  }
  for (const d of p.denyRead ?? []) argv.push('--deny-read', d)
  for (const a of p.denyReadExcept ?? []) argv.push('--deny-read-except', a)
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
        `(CreateProcessW limit is 32 767). Besides the command itself it ` +
        `carries ${p.denyRead?.length ?? 0} per-command read denies, ` +
        `${p.denyReadExcept?.length ?? 0} session grants beneath them, ` +
        `${p.denyWrite?.length ?? 0} write denies and ` +
        `${p.writeRoots?.length ?? 0} write roots; the command was not ` +
        `run with fewer.`,
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
 * `=` only, so values containing `=` survive intact.
 */
function envListToObject(list: string[]): NodeJS.ProcessEnv {
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
 * `windows.writeRestrictedToken` as it applies: on unless it is
 * explicitly `false`. The one place the default is decided — every
 * reader of the option (and of the parameters derived from it) goes
 * through here, so unset and `true` cannot diverge.
 */
export function windowsWriteRestrictedTokenEnabled(
  w: { writeRestrictedToken?: boolean } | undefined,
): boolean {
  return w?.writeRestrictedToken !== false
}

/**
 * Why an existing install cannot be used by this `srt-win`, or
 * `undefined` when it can: the install's setup marker was written by
 * a release with a different setup version. `srt-win` then refuses to
 * launch the sandbox account and to keep a write grant, and the
 * repair is to re-run the install, which upgrades in place.
 *
 * Only meaningful for a provisioned install; an `srt-win` that does
 * not report its setup version is not judged here (it enforces the
 * same check itself at launch).
 */
export function windowsSetupVersionMismatch(
  us: WindowsSandboxUserStatus,
  sublayerGuid?: string,
): string | undefined {
  if (us.setupVersion === undefined || us.markerVersion === us.setupVersion) {
    return undefined
  }
  const sl = sublayerGuid ? ` --sublayer-guid ${sublayerGuid}` : ''
  return (
    `The Windows sandbox on this machine was set up by a different ` +
    `release (setup version ${us.markerVersion ?? 'unknown'}; this ` +
    `release needs ${us.setupVersion}). Re-run the install to upgrade ` +
    `it in place (one UAC prompt):\n` +
    `  npx sandbox-runtime windows-install\n` +
    `  — or call installWindowsSandbox(), or run ` +
    `\`srt-win.exe install${sl}\` directly.\n` +
    `Nothing is granted or run until then.`
  )
}

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
  } else {
    // Installed, by a release with another setup version: an upgrade,
    // not a missing sandbox, so its own wording.
    const stale = windowsSetupVersionMismatch(us, sublayerGuid)
    if (stale) errors.push(stale)
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
