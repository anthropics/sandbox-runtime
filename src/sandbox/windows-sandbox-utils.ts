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
  /**
   * The installed loopback mode is not the one this session asks for
   * with `network.allowLocalBinding` (`srt-win` exit 19).
   */
  | 'wfp_loopback_mismatch'
  /** `srt-win` predates `--allow-loopback`; `network.allowLocalBinding` needs a newer one. */
  | 'srt_win_too_old'
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
  /**
   * A profile read grant is recorded and cannot be relied on (unfinished,
   * older exclusion list, another profile, unreadable record). An ABSENT
   * grant is not an error.
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
   * The Secondary Logon service (`seclogon`) is disabled or absent; `srt-win`
   * launch subcommands exit **18** ({@link SeclogonDisabledError}).
   */
  | 'seclogon_disabled'

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
 * The one loopback port that stays blocked for the sandbox account with
 * `network.allowLocalBinding`, so the fence check has a connect that must
 * be refused. `srt-win` owns it (`LOOPBACK_PROBE_PORT` in `wfp.rs`).
 */
export const WINDOWS_LOOPBACK_PROBE_PORT = 1

/** What `network.allowLocalBinding` opens on Windows, in plain words. */
export const WINDOWS_ALLOW_LOOPBACK_EFFECT =
  `Loopback is open: sandboxed commands can connect to every TCP and ` +
  `UDP port on localhost (127.0.0.0/8 and ::1; port ` +
  `${WINDOWS_LOOPBACK_PROBE_PORT} alone stays blocked, so the sandbox ` +
  `can check its own fence). Every service listening ` +
  `on localhost is reachable from them, and any local forwarder (a DNS ` +
  `stub, a SOCKS or HTTP proxy, a VPN or security agent, a tunnel) ` +
  `reachable there gives them a way off the machine that the network ` +
  `restrictions do not cover.`

/**
 * `cannot-read` is the graceful-degrade state when BFE enumeration
 * is access-denied (it is admin-gated). The non-elevated readiness
 * check is {@link verifyWindowsWfpEgress}, not this enum.
 *
 * `loopback-mismatch` (elevated callers only): the filters' loopback
 * mode is not the one the install recorded; re-install.
 */
export type WindowsWfpStatus =
  | 'absent'
  | 'installed'
  | 'loopback-mismatch'
  | 'cannot-read'

export interface WindowsWfpStatusResult {
  state: WindowsWfpStatus
  /** Live filter count from BFE enum; `0` on `cannot-read`. */
  filters: number
  /** `[low, high]` for the loopback PERMIT, when known. */
  portRange?: [number, number]
  /**
   * Whether the installed filter set opens loopback — see
   * {@link WINDOWS_ALLOW_LOOPBACK_EFFECT}.
   */
  allowLoopback: boolean
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
 * Result of one connect attempt by `srt-win wfp verify`. `connected`
 * and `refused` both mean the connect got past the filters;
 * `unreachable` and `error` say nothing about the fence.
 */
export type WindowsWfpProbeOutcome =
  | 'blocked'
  | 'connected'
  | 'refused'
  | 'unreachable'
  | 'skipped'
  | 'error'

/**
 * A gap {@link verifyWindowsWfpEgress} observed that the filter set
 * does not close. `anonymous-egress` is expected on every machine with
 * an off-loopback address: no filter is keyed on the anonymous token.
 */
export type WindowsWfpResidual =
  | 'anonymous-egress'
  | 'anonymous-loopback'
  | 'deny-only-user-sid'
  | 'lowered-integrity-unprobed'

/**
 * Result of `srt-win wfp verify` on success (exit 0); anything else
 * throws. `plain` is `blocked`. A lowered-integrity attempt may be
 * `error` (not set up), and the rest anything: see `residuals`.
 */
export interface WindowsWfpVerifyResult {
  target: string
  /** Runner's stderr (carries one diagnostic line per attempt). */
  stderr: string
  /**
   * One per attempt. `anonymous`, `lowIntegrity` and `untrustedIntegrity`
   * go to an off-loopback target, the rest to the loopback one: the
   * listener, or with loopback open {@link WINDOWS_LOOPBACK_PROBE_PORT}.
   */
  probes: {
    plain: WindowsWfpProbeOutcome
    anonymous: WindowsWfpProbeOutcome
    anonymousLoopback: WindowsWfpProbeOutcome
    denyOnly: WindowsWfpProbeOutcome
    lowIntegrity: WindowsWfpProbeOutcome
    lowIntegrityLoopback: WindowsWfpProbeOutcome
    untrustedIntegrity: WindowsWfpProbeOutcome
    untrustedIntegrityLoopback: WindowsWfpProbeOutcome
    /** With loopback open: own token, to the loopback listener. */
    openLoopback?: WindowsWfpProbeOutcome
  }
  /** Gaps the probe found open: NOT a clean pass when non-empty. */
  residuals: WindowsWfpResidual[]
  /**
   * Warnings for residuals, skipped attempts and open loopback;
   * `initialize()` logs them.
   */
  warnings: string[]
}

/**
 * Readiness of the Secondary Logon service every launch goes through. `ok`
 * covers a stopped Manual service (the launch demand-starts it);
 * `cannot-read` is not proof of a problem.
 */
export type WindowsSeclogonState = 'ok' | 'disabled' | 'missing' | 'cannot-read'

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
   * The setup version this `srt-win` requires; it launches nothing
   * while {@link markerVersion} differs. Absent from an `srt-win` that
   * does not report it.
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
  /** Secondary Logon readiness. Absent when `srt-win` predates the field. */
  seclogon?: WindowsSeclogonState
  /**
   * Set when write grants kept between sessions exist (`present`) or
   * cannot be ruled out (`unknown`); `srt-win` then refuses to run a
   * command under the ordinary token.
   */
  persistentGrants?: {
    state: 'present' | 'unknown'
    roots: string[]
    reason?: string
  }
  /**
   * Set when a profile read grant is recorded (`present`) or cannot
   * be ruled out (`unknown`). Whether it is current is {@link
   * getWindowsProfileReadStatus}'s to say.
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
   * runs in, when `srt-win` can tell.
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
   * The session's `network.allowLocalBinding`. `srt-win exec` launches
   * nothing (exit 19) unless the install recorded the same mode. When
   * true, with a proxy, `no_proxy` names the loopback hosts.
   */
  allowLoopback?: boolean
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
   */
  denyReadExcept?: readonly string[]
  /**
   * The process whose session this command belongs to, as `srt-win`
   * recorded it. Without it `srt-win exec` records itself until the command
   * has exited (one more acquisition of its lock).
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
   * The session's write roots. Each is passed as `--write-root`, which
   * puts the root's capability SID in the child token; without it the
   * child cannot write the root.
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
 * `srt-win`'s exit code when its lock is held by a `profile grant` or
 * `profile forget`: the caller is told after about three seconds.
 */
export const SRT_WIN_EXIT_PROFILE_BUSY = 25
/**
 * `srt-win exec`'s exit code when the session a command was started
 * for (`heldBy`) ended while the command ran: the command and
 * everything it started were terminated.
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
 * The one mapping of `srt-win`'s refusals beside other sandbox activity:
 * 25 (a profile operation runs), 22 (nothing removed), 24 (grant unchanged).
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
  allow_loopback?: boolean
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
    allowLoopback: raw.allow_loopback === true,
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
  /** Absent from an `srt-win` that predates the field. */
  seclogon?: string
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
 * status` and `profile status`.
 */
export const WINDOWS_SRT_WIN_CAPABILITIES = {
  /**
   * A read deny handed to `srt-win` is also written on every recorded
   * path of the profile read grant beneath it that carries an allow
   * of its own.
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
   * recorded with the profile read grant.
   */
  profileSessionGrantCheck: 'profile-session-grant-check',
  /**
   * That expansion leaves out the recorded paths the session allows
   * more specifically: the grants of the same `acl grant` call, and
   * the ones a command names with `--deny-read-except`.
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
 * The first capability this library needs that `capabilities` (as
 * `srt-win` reported them) does not list.
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

const SECLOGON_STATES: readonly string[] = [
  'ok',
  'disabled',
  'missing',
  'cannot-read',
] satisfies WindowsSeclogonState[]

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
    ...(raw.seclogon !== undefined &&
      SECLOGON_STATES.includes(raw.seclogon) && {
        seclogon: raw.seclogon as WindowsSeclogonState,
      }),
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

/** User-facing text for a disabled/absent Secondary Logon service. */
function seclogonDisabledMessage(state: 'disabled' | 'missing'): string {
  return state === 'missing'
    ? `The Windows Secondary Logon service (seclogon) is not present ` +
        `on this machine; the sandbox cannot start without it.`
    : `The Windows Secondary Logon service (seclogon) is disabled; an ` +
        `administrator must set its startup type to Manual (\`sc.exe ` +
        `config seclogon start= demand\`). The sandbox cannot start ` +
        `without it.`
}

/** `srt-win` exit code for a `seclogon_disabled` launch failure. */
const SRT_WIN_EXIT_SECLOGON_DISABLED = 18

/**
 * The typed `seclogon_disabled` error for an `srt-win` launch result, if it
 * is one. Gated on the exit code first: the child's own stderr could match.
 */
function seclogonDisabledFrom(
  r: { status: number | null; stderr: string },
  subcommand: string,
): SeclogonDisabledError | undefined {
  if (r.status !== SRT_WIN_EXIT_SECLOGON_DISABLED) return undefined
  const e = parseSrtWinLaunchError(r.stderr, subcommand)
  return e?.code === 'seclogon_disabled'
    ? (e as SeclogonDisabledError)
    : undefined
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

type RawWfpVerify = {
  egress_probe: string
  target: string
  anonymous_probe?: string
  anonymous_target?: string | null
  anonymous_loopback_probe?: string
  deny_only_probe?: string
  low_integrity_probe?: string
  low_integrity_loopback_probe?: string
  untrusted_integrity_probe?: string
  untrusted_integrity_loopback_probe?: string
  egress_target?: string
  allow_loopback?: boolean
  open_loopback_probe?: string
  residuals?: string[]
  allow_loopback_mismatch?: boolean
  hint?: string
}

/**
 * The options of the install a session expects. A suggested install
 * command names only the ones that are not the defaults.
 */
export interface WindowsInstallContext {
  sublayerGuid?: string
  proxyPortRange?: readonly [number, number]
  sandboxUser?: string
  allowLoopback?: boolean
}

/**
 * Install flags for `ctx`. `force` only when the install replaces a
 * set that is in place with another configuration: it refuses that
 * without `--force` (exit 13), and needs none otherwise.
 */
function windowsInstallFlags(
  ctx: WindowsInstallContext,
  force: boolean,
): string {
  const [lo, hi] = ctx.proxyPortRange ?? DEFAULT_WINDOWS_PROXY_PORT_RANGE
  const [defLo, defHi] = DEFAULT_WINDOWS_PROXY_PORT_RANGE
  return (
    (ctx.sublayerGuid ? ` --sublayer-guid ${ctx.sublayerGuid}` : '') +
    (lo !== defLo || hi !== defHi ? ` --proxy-port-range ${lo}-${hi}` : '') +
    (ctx.sandboxUser && ctx.sandboxUser !== 'srt-sandbox'
      ? ` --sandbox-user ${ctx.sandboxUser}`
      : '') +
    (ctx.allowLoopback ? ` --allow-loopback` : '') +
    (force ? ` --force` : '')
  )
}

/** The install command, as error messages print it. */
export const WINDOWS_INSTALL_COMMAND =
  'npx @anthropic-ai/sandbox-runtime windows-install'

function windowsInstallCommand(
  ctx: WindowsInstallContext,
  force: boolean,
): string {
  return WINDOWS_INSTALL_COMMAND + windowsInstallFlags(ctx, force)
}

/**
 * Whether a failed `srt-win` run is an `srt-win` that predates
 * `--allow-loopback` rejecting the argument.
 */
function rejectsAllowLoopback(r: { stderr: string }): boolean {
  return /unexpected argument '--allow-loopback'/.test(r.stderr)
}

function srtWinTooOld(stderr: string): WindowsSandboxError {
  return new WindowsSandboxError(
    'srt_win_too_old',
    `srt-win is too old for network.allowLocalBinding: it does not know ` +
      `\`--allow-loopback\`. Update srt-win (and re-run the install with ` +
      `it), or unset network.allowLocalBinding. (${stderr.trim()})`,
  )
}

const WFP_RESIDUAL_TEXT: Record<WindowsWfpResidual, string> = {
  'anonymous-egress':
    'a connect to an off-loopback destination made while impersonating ' +
    'the anonymous token is not blocked (no filter is keyed on that ' +
    'token; a sandboxed process that puts it on a thread before ' +
    'creating a socket is not fenced)',
  'anonymous-loopback':
    'a connect to a loopback destination made while impersonating the ' +
    'anonymous token is not blocked (local listeners outside the proxy ' +
    'port range are reachable that way)',
  'deny-only-user-sid':
    'a connect made under a copy of the sandbox token whose user SID is ' +
    'deny-only is not blocked (the filters cannot match that token)',
  'lowered-integrity-unprobed':
    'a lowered-integrity copy of the sandbox token could not be set up on ' +
    'this machine, so no connect under it was observed',
}

function isWfpResidual(s: string): s is WindowsWfpResidual {
  return Object.prototype.hasOwnProperty.call(WFP_RESIDUAL_TEXT, s)
}

/**
 * Turn one `srt-win wfp verify` run into a result or a typed error
 * (pure). An attempt the fence must refuse that got through rejects
 * whatever the exit code says; a residual never throws.
 */
export function interpretWindowsWfpVerify(
  r: {
    status: number | null
    signal?: NodeJS.Signals | null
    stdout: string
    stderr: string
  },
  install: WindowsInstallContext = {},
): WindowsWfpVerifyResult {
  let raw: RawWfpVerify
  try {
    raw = JSON.parse(r.stdout) as RawWfpVerify
  } catch {
    if (rejectsAllowLoopback(r)) throw srtWinTooOld(r.stderr)
    // Timeout is thrown as `srt_win_timeout` by `runSrtWinAsync` before this
    // parse; status=null here means an external signal.
    throw new WindowsSandboxError(
      'wfp_verify_unparseable',
      `WFP egress fence could not be verified — \`srt-win wfp ` +
        `verify\` exited ${r.status}` +
        (r.signal ? ` (signal ${r.signal})` : '') +
        ` with unparseable output ${JSON.stringify(r.stdout)} ` +
        `(stderr: ${JSON.stringify(r.stderr)})`,
    )
  }
  const outcome = (v: string | undefined): WindowsWfpProbeOutcome =>
    (v ?? 'skipped') as WindowsWfpProbeOutcome
  const probes = {
    plain: outcome(raw.egress_probe),
    anonymous: outcome(raw.anonymous_probe),
    anonymousLoopback: outcome(raw.anonymous_loopback_probe),
    denyOnly: outcome(raw.deny_only_probe),
    lowIntegrity: outcome(raw.low_integrity_probe),
    lowIntegrityLoopback: outcome(raw.low_integrity_loopback_probe),
    untrustedIntegrity: outcome(raw.untrusted_integrity_probe),
    untrustedIntegrityLoopback: outcome(raw.untrusted_integrity_loopback_probe),
    ...(raw.allow_loopback && {
      openLoopback: outcome(raw.open_loopback_probe),
    }),
  }
  const offLoopback = raw.anonymous_target ?? 'no target'
  // Where the attempts the fence must refuse on loopback went: the
  // reserved port when loopback is open, else the listener.
  const blockedTarget = raw.egress_target ?? raw.target
  const summary =
    `plain=${probes.plain} (${blockedTarget}), ` +
    `anonymous=${probes.anonymous} (${offLoopback}), ` +
    `anonymous-loopback=${probes.anonymousLoopback}, ` +
    `deny-only=${probes.denyOnly}, ` +
    `low-integrity=${probes.lowIntegrity} (${offLoopback}), ` +
    `low-integrity-loopback=${probes.lowIntegrityLoopback}, ` +
    `untrusted-integrity=${probes.untrustedIntegrity} (${offLoopback}), ` +
    `untrusted-integrity-loopback=${probes.untrustedIntegrityLoopback}` +
    (raw.allow_loopback
      ? `, open-loopback=${probes.openLoopback} (${raw.target})`
      : '')
  // The reinstall that suits THIS session: its loopback mode, and the
  // install options it was configured with.
  const session: WindowsInstallContext = {
    ...install,
    allowLoopback: raw.allow_loopback ?? install.allowLoopback,
  }
  if (r.status === 19 || raw.allow_loopback_mismatch) {
    throw new WindowsSandboxError(
      'wfp_loopback_mismatch',
      `WFP egress fence does not match network.allowLocalBinding — ` +
        (raw.hint ?? 'the installed filter set has a different loopback mode') +
        `. Through this package: \`` +
        windowsInstallCommand(session, true) +
        `\`.`,
    )
  }
  // The attempts the fence must refuse. One getting through rejects
  // whatever the exit code says.
  const lowIl = 'the sandbox user under a low-integrity copy of its token'
  const untrustedIl =
    'the sandbox user under an untrusted-integrity copy of its token'
  const which = (
    [
      [probes.plain, 'the sandbox user', blockedTarget],
      [probes.lowIntegrity, lowIl, raw.anonymous_target],
      [probes.lowIntegrityLoopback, lowIl, blockedTarget],
      [probes.untrustedIntegrity, untrustedIl, raw.anonymous_target],
      [probes.untrustedIntegrityLoopback, untrustedIl, blockedTarget],
    ] as const
  )
    .filter(([o]) => o === 'connected' || o === 'refused')
    .map(([, who, tgt]) => `direct outbound from ${who} to ${tgt}`)
  // With loopback open nothing listens at the plain attempt's port: no
  // answer in time is no refusal by the filter either.
  if (raw.allow_loopback && probes.plain === 'unreachable') {
    which.push(
      `direct outbound from the sandbox user to ${blockedTarget} (no ` +
        `answer where the filter must refuse at once)`,
    )
  }
  if (r.status === 3 || which.length > 0) {
    throw new WindowsSandboxError(
      'wfp_fence_inactive',
      `WFP egress fence is not active — ` +
        `${which.join(' and ') || 'a direct outbound connect'} was not ` +
        `blocked [${summary}]. Re-run \`` +
        windowsInstallCommand(session, false) +
        `\` (one UAC prompt). (${r.stderr})`,
    )
  }
  if (r.status !== 0) {
    throw new WindowsSandboxError(
      'wfp_verify_inconclusive',
      `WFP egress fence could not be verified — probe to ` +
        `${blockedTarget} was '${raw.egress_probe}' (exit ` +
        `${r.status}) [${summary}]. The fence may be absent. Re-run ` +
        `\`srt-win install\`. (${r.stderr})`,
    )
  }
  // Exit 0 alone is not a pass: the plain attempt must say `blocked`.
  if (raw.egress_probe !== 'blocked') {
    throw new WindowsSandboxError(
      'wfp_verify_inconclusive',
      `WFP egress fence could not be verified — \`srt-win wfp verify\` ` +
        `exited 0 but reported the plain attempt as ` +
        `'${raw.egress_probe ?? 'missing'}' [${summary}]. (${r.stderr})`,
    )
  }
  const residuals = (raw.residuals ?? []).filter(isWfpResidual)
  const warnings = residuals.map(
    x => `WFP egress fence residual '${x}': ${WFP_RESIDUAL_TEXT[x]}`,
  )
  if (
    probes.lowIntegrity === 'skipped' ||
    probes.untrustedIntegrity === 'skipped'
  ) {
    warnings.push(
      `WFP egress fence: the off-loopback lowered-integrity attempts ` +
        `were skipped (no off-loopback address on this machine, or an ` +
        `srt-win that does not make them)`,
    )
  }
  // A pass says direct egress is blocked. With loopback open that is
  // not the whole story, so the result says the rest.
  if (raw.allow_loopback) warnings.push(WINDOWS_ALLOW_LOOPBACK_EFFECT)
  return { target: raw.target, stderr: r.stderr, probes, residuals, warnings }
}

/**
 * Behavioral proof that the WFP egress fence is active for the
 * sandbox user. Binds a local listener on an ephemeral loopback port
 * outside the WFP loopback-permit range, then spawns `srt-win
 * runner` as the sandbox user (via `CreateProcessWithLogonW`) to
 * attempt direct TCP connects, one per token shape a sandboxed
 * process can present. The WFP block-user filter
 * fires at `ALE_AUTH_CONNECT` — before any packet leaves — so an
 * active fence yields WSAEACCES immediately and a missing fence lets
 * the connect through (the kernel completes the handshake against
 * the listening socket's backlog). The event loop stays live while
 * `srt-win` runs. Does not require elevation and does not depend on
 * any external host.
 *
 * With `opts.allowLoopback` the connects that must be blocked go to
 * {@link WINDOWS_LOOPBACK_PROBE_PORT}, where nothing listens and only
 * the filter's refusal passes, and the listener is what `srt-win` must
 * be able to reach.
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
 * @param opts.allowLoopback the session's `network.allowLocalBinding`;
 *   `srt-win` compares it with the installed loopback mode.
 * @param opts.sublayerGuid, opts.sandboxUser the session's install
 *   options, named in the reinstall command an error suggests.
 * @param opts.anonymousEgress also make the off-loopback attempt under
 *   the anonymous token. It cannot change the result and can take
 *   seconds, so `initialize()` leaves it out; for diagnostics only.
 * @param opts.writeRoots the session's write roots: the probe runs
 *   under the write-restricted token a command of the session gets.
 * @throws on any outcome other than exit 0.
 */
export async function verifyWindowsWfpEgress(
  opts: {
    target?: string
    proxyPortRange?: readonly [number, number]
    allowLoopback?: boolean
    anonymousEgress?: boolean
    sublayerGuid?: string
    sandboxUser?: string
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
      // A connect that gets through is accepted while `srt-win` runs:
      // drop it, and keep its errors from being uncaught.
      const s = net.createServer(c => c.on('error', () => {}).destroy())
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
  const args = ['wfp', 'verify', '--target', target]
  if (opts.anonymousEgress) args.push('--anonymous-egress')
  if (opts.allowLoopback) args.push('--allow-loopback')
  // Under the token a command of the session gets.
  args.push('--write-restricted-token')
  for (const r of opts.writeRoots ?? []) args.push('--write-root', r)
  try {
    // 30s: first call after install may create the sandbox user's
    // profile (LOGON_WITH_PROFILE) via CreateProcessWithLogonW, and
    // the runner bounds each of its connects (probe.rs).
    const r = await runSrtWinAsync(args, {
      timeoutMs: 30_000,
      srtWin: opts.srtWin,
    })
    logForDebugging(
      `[Sandbox Windows] wfp verify exit=${r.status}: ${r.stderr || r.stdout}`,
    )
    // Exit 18 comes with empty stdout: report the typed failure before
    // the output is parsed.
    const seclogon = seclogonDisabledFrom(r, 'wfp')
    if (seclogon) throw seclogon
    const result = interpretWindowsWfpVerify(r, {
      sublayerGuid: opts.sublayerGuid,
      proxyPortRange: opts.proxyPortRange,
      sandboxUser: opts.sandboxUser,
      allowLoopback: opts.allowLoopback,
    })
    for (const w of result.warnings) {
      logForDebugging(`[Sandbox Windows] ${w}`, { level: 'warn' })
    }
    return result
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
  const seclogon = seclogonDisabledFrom(r, 'user')
  if (seclogon) throw seclogon
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
        `Run \`${WINDOWS_INSTALL_COMMAND}\` first.`,
    )
  }
  const stateDir = opts.dir ? undefined : windowsStateDir()
  if (stateDir && !fs.existsSync(stateDir)) {
    throw new Error(
      `ensurePersistentWindowsCa: state directory ${stateDir} does not ` +
        `exist. Run \`${WINDOWS_INSTALL_COMMAND}\` first.`,
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
   * Open loopback ({@link WINDOWS_ALLOW_LOOPBACK_EFFECT}); must match
   * `network.allowLocalBinding`. Take it only from a source the machine's
   * user or administrator controls, never from a project's own files.
   */
  allowLoopback?: boolean
  /**
   * Name for the sandbox user account (created if absent, adopted
   * if it already exists as a local user). Default `srt-sandbox`.
   */
  sandboxUser?: string
  /**
   * Replace an existing install whose configuration differs
   * (different port range, loopback mode or sandbox-user name under
   * the same sublayer). Without this, install refuses with "already
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
   * Leave the profile read grant unapplied.
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
 * What an install did about the profile read grant.
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
  if (opts.allowLoopback) args.push('--allow-loopback')
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
  if (rejectsAllowLoopback(r)) throw srtWinTooOld(r.stderr)
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
          `a different port range, loopback mode or sandbox-user ` +
          `name. Pass ` +
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
 * @throws on user/WFP creation failure, if filters already exist
 *   under `sublayerGuid` with a different port range or loopback mode
 *   and `force` is not set, or if `srt-win` predates `allowLoopback`.
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
 * Why an install leaves the profile read grant unapplied (`undefined`: it
 * applies it): asked to skip, a service account, or not running as the
 * owner of the interactive session, whose profile it would open instead.
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
 * What the profile read grant is about to do, in one line, for the person
 * at the keyboard.
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
 * The account and the filters are installed and the profile read grant
 * is not: its own error, so the caller does not take the whole install
 * for failed.
 */
function throwInstallProfileGrantFailure(e: unknown): never {
  const cause = e as Error
  // Refused beside other sandbox activity: nothing was written, and a
  // grant made before is still the current one.
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
     * How long to wait for the uninstall: the elevation prompt, and
     * then the removal of the grants kept for this user, which walks
     * the profile. Defaults to the install's and the grant's together.
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
    timeoutMs:
      opts.timeoutMs ??
      (opts.keepUser
        ? INSTALL_TIMEOUT_MS
        : INSTALL_TIMEOUT_MS + PROFILE_GRANT_TIMEOUT_MS),
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
 * A path that names a network share (`\\\\server\\share\\…`, `\\\\?\\UNC\\…`)
 * or anything in the device namespace other than a drive (`\\\\.\\pipe\\…`,
 * `\\\\?\\GLOBALROOT\\…`).
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
 * `p` for comparison with another path: links, junctions, 8.3 names and
 * the case on disk are resolved, as `srt-win` resolves a path it is given.
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
 * being the one that counts.
 */
export function windowsGrantsBeneathDenies(
  grants: readonly string[],
  denies: readonly string[],
): string[] {
  if (grants.length === 0 || denies.length === 0) return []
  const denyKeys = denies.map(windowsPathKey)
  const keyed = grants.map(g => ({ path: g, key: windowsPathKey(g) }))
  // Per deny, the topmost grants strictly beneath THAT deny.
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

/** {@link WindowsSandboxError} narrowed to `seclogon_disabled`. */
export interface SeclogonDisabledError extends WindowsSandboxError {
  readonly code: 'seclogon_disabled'
  readonly state: 'disabled' | 'missing'
}

/**
 * Parse a structured `srt-win exec` error from its stderr. `exec`
 * emits typed launch failures as a single JSON line
 * `{"code":…,"message":…}` alongside a distinct exit code —
 * `mapped_drive_cwd` is exit **16**, `seclogon_disabled` exit **18**,
 * `wfp_loopback_mismatch` exit **19**. Embedders that spawn the
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
  | SeclogonDisabledError
  | (WindowsSandboxError & { drive?: undefined })
  | undefined {
  return parseSrtWinLaunchError(stderr, 'exec')
}

/** {@link parseWindowsSandboxError} for any runner-launching subcommand. */
function parseSrtWinLaunchError(
  stderr: string,
  subcommand: string,
):
  | MappedDriveCwdError
  | SeclogonDisabledError
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
        state?: string
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
            subcommand,
          ),
          { drive: j.drive },
        ) as MappedDriveCwdError
      }
      // Exit 19: the installed loopback mode is not the one the
      // command was wrapped for; nothing was launched.
      if (j.code === 'wfp_loopback_mismatch') {
        return new WindowsSandboxError(
          'wfp_loopback_mismatch',
          j.message ?? "the installed loopback mode is not this session's",
          'exec',
        )
      }
      if (j.code === 'seclogon_disabled') {
        const state = j.state === 'missing' ? 'missing' : 'disabled'
        return Object.assign(
          new WindowsSandboxError(
            'seclogon_disabled',
            j.message ?? seclogonDisabledMessage(state),
            subcommand,
          ),
          { state },
        ) as SeclogonDisabledError
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
 * `acl revoke` statuses that show a grant released. An allow-list, so
 * a status this code does not know fails closed.
 */
const WINDOWS_ACL_GRANT_RELEASED_STATUSES: ReadonlySet<string> = new Set([
  'revoked',
  'stillHeld',
  'downgraded',
  'relocated',
  'noRow',
  'gone',
  'missing',
])

/**
 * Whether one `acl revoke` outcome shows its grant released. "missing"
 * comes only from an older srt-win, which also says it of a path it
 * could not open, so it counts only if the path is really gone.
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
 * Release this holder's deny ACEs. Best-effort; `undefined` when
 * `srt-win` failed. srt-win refuses (status `grantPending`) while the
 * holder still has a grant recorded: revoke first.
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
  /**
   * `read` paths that may be granted although the profile read grant
   * excludes them (`srt-win acl grant --allow-profile-exclusion`).
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
 * Session start under the write-restricted token: one `srt-win acl
 * grant --persistent`. Grants on the `write` roots are KEPT at session
 * end; `srt-win acl forget` removes them.
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

export interface WindowsAclRevokeResult {
  /**
   * True only when `srt-win acl revoke` exited 0, its output parsed,
   * and every per-path outcome shows the grant released.
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
 * completed; gate {@link restoreWindowsAcl} on `complete`.
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

/**
 * Release this holder's grants. Best-effort (does not throw). Do not
 * follow with {@link restoreWindowsAcl}: use
 * {@link revokeWindowsAclChecked}, which says whether it completed.
 */
export function revokeWindowsAcl(opts: {
  sandboxUserSid: string
  holderPid?: number
  srtWin?: SrtWinSpawn
}): WindowsAclAceOutcome[] | undefined {
  return revokeWindowsAclChecked(opts).outcomes
}

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
   * What the last run of the grant left as it found it, as {@link
   * WindowsProfileGrantResult} reports it: objects in the profile
   * this user may not change.
   */
  notGranted: WindowsProfileGrantItem[]
  selfClosed: WindowsProfileGrantItem[]
  unverifiable: WindowsProfileGrantItem[]
  unprotected: WindowsProfileGrantItem[]
  staleAllow: WindowsProfileGrantItem[]
  /**
   * Configuration files granted by name that were replaced since (a save
   * by write-and-rename): unreadable to sandboxed commands, and their
   * variables are not in `env`, until the grant runs again.
   */
  replacedFiles: string[]
  /** Exclusions added to the built-in list when the grant was made, relative to the profile. */
  extraExclusions: string[]
  /**
   * Every PROTECTED path the grant keeps unreadable, absolute, existing or
   * not; `*` stands for one name, a trailing `*` for a prefix. A session may
   * not grant a path that is one, lies inside one, or lies above one.
   */
  exclusions: string[]
  /**
   * The UNGRANTED-ONLY directories, in the same form (the user's
   * temporary directory): not readable through the grant, and not
   * denied.
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
  replaced_files?: unknown
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
 * The variables {@link windowsProfileReadEnv} can return; any other name
 * `srt-win` reports is dropped. `RUSTUP_HOME` and `CARGO_HOME` name
 * directories, which stay read-only to the sandboxed command.
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
 * The version of `srt-win profile status`'s record format this library
 * reads. Any other version is not read: its lists decide what may be granted.
 */
const WINDOWS_PROFILE_RECORD_VERSION = 1

function stringList(v: unknown): string[] | undefined {
  return Array.isArray(v) && v.every(x => typeof x === 'string' && x !== '')
    ? (v as string[])
    : undefined
}

/**
 * Why a status that says `current` cannot be relied on, if so.
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
    replacedFiles: stringList(raw.replaced_files) ?? [],
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
 * The recorded profile read grant (`srt-win profile status`): whether one
 * exists and is current, and with `paths` every path it wrote on. Throws
 * `profile_operation_in_progress` while a grant or forget is running.
 * Blocks the event loop: prefer {@link getWindowsProfileReadStatusAsync}.
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

/** Async twin of {@link getWindowsProfileReadStatus}: the event loop stays live. */
export async function getWindowsProfileReadStatusAsync(
  opts: { paths?: boolean; srtWin?: SrtWinSpawn } = {},
): Promise<WindowsProfileGrantStatus> {
  const args = ['profile', 'status']
  if (opts.paths) args.push('--paths')
  const raw = await runSrtWinJsonAsync<RawProfileStatus>(args, {
    timeoutMs: 30_000,
    srtWin: opts.srtWin,
  })
  if (raw.state === 'in_progress') {
    throwIfRefusedBesideOthers(args, SRT_WIN_EXIT_PROFILE_BUSY, '')
  }
  return mapProfileStatus(raw)
}

export interface WindowsProfileGrantOptions {
  /**
   * Paths inside the profile to keep unreadable in addition to the
   * built-in list (absolute, or relative to the profile): for example
   * the embedding program's own configuration directory.
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
   * On an `unverifiable` item: whether YOU can open the object for reading
   * (`'unknown'`: not tried). One you can read without seeing its access
   * list is to be taken as readable to sandboxed commands as well.
   */
  callerReads?: boolean | 'unknown'
  /**
   * On an `unverifiable` item: why it could not be examined —
   * `acl_unreadable`, `account_unknown` (the sandbox account's
   * identity is not known), `not_local`, `probe_failed`.
   */
  cause?: string
  /**
   * Set where an entry THIS PRODUCT wrote makes the path readable and could
   * not be removed: `true` if the path is on the exclusion list now (among
   * `unprotected`), `false` if it merely left the grant (`staleAllow`).
   */
  protectedExclusion?: boolean
  /**
   * With `protectedExclusion`: `explicit` — the entry is on the
   * object, which you may not change; `inherited` — a copy handed down
   * from a directory above, which could not be taken off the object.
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
   * Paths that were to be granted and whose access list this user may not
   * change. They stay unreadable to sandboxed commands.
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
   * the grant, which neither opened them nor can close them.
   */
  unprotected: WindowsProfileGrantItem[]
  /**
   * Paths that have left the grant and still carry the allow of an
   * earlier run, which could not be removed: readable through the
   * grant's own entry.
   */
  staleAllow: WindowsProfileGrantItem[]
  /**
   * Write roots kept from earlier sessions whose grant this run removed
   * because it reached an exclusion (the root is one, lies inside one,
   * or lies above one). A session that asks for such a root is refused.
   */
  forgottenRoots: WindowsProfileGrantItem[]
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
 * Write or refresh the profile read grant (`srt-win profile grant`), as
 * the user of this process, unelevated. Runs only while no sandbox session
 * or command is running (`profile_grant_blocked_by_session`).
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
    forgotten_roots?: unknown
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
    forgottenRoots: grantItems(raw.forgotten_roots),
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
 * Remove the profile read grant (`srt-win profile forget`). Synchronous:
 * blocks for as long as the removal takes; with an event loop use
 * {@link forgetWindowsProfileReadAsync}. Throws `profile_forget_failed`.
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

/** {@link forgetWindowsProfileRead} without blocking the event loop. */
export async function forgetWindowsProfileReadAsync(
  opts: {
    timeoutMs?: number
    srtWin?: SrtWinSpawn
  } = {},
): Promise<void> {
  const r = await runSrtWinAsync(['profile', 'forget', '--json'], {
    timeoutMs: opts.timeoutMs ?? PROFILE_GRANT_TIMEOUT_MS,
    srtWin: opts.srtWin,
  })
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
 * `rest`, the components of an exclusion that `dir` lies above.
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
 * The paths among `paths` a session must not grant while the profile read
 * grant exists, with the exclusion each collides with. Paths are resolved
 * first; fails closed on a path that exists and cannot be listed.
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
  // The ungranted-only directory itself is looked for first, so it is
  // reported as what it is and not as "above" something inside it.
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
 * Variables an embedder may set so a tool reads the real user's files in
 * place. Empty unless the grant is current; never one `env` already holds.
 * The library sets none of them itself.
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
 * `no_proxy` for a sandboxed child with `network.allowLocalBinding`:
 * the loopback hosts, so proxy-aware clients connect to local servers
 * directly. Otherwise `no_proxy` is not set at all.
 */
export const WINDOWS_LOOPBACK_NO_PROXY = 'localhost,127.0.0.1,::1'

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
  // With loopback open the fence permits direct loopback connects, so the
  // loopback hosts (only: private networks are still fenced) skip the proxy.
  if (p.allowLoopback && (p.httpProxyPort || p.socksProxyPort)) {
    generated.no_proxy = WINDOWS_LOOPBACK_NO_PROXY
  }

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
    // token; git's OpenSSL backend reads the same GIT_SSL_CAINFO.
    opensslBackend: true,
    baseEnv: p.setEnvVars,
  })

  const argv: string[] = [exe, ...prependArgs, 'exec']
  if (p.quiet !== false) argv.push('--quiet')
  if (p.heldBy !== undefined) argv.push('--held-by', `${p.heldBy}`)
  argv.push('--write-restricted-token')
  for (const r of p.writeRoots ?? []) argv.push('--write-root', r)
  if (p.allowLoopback) argv.push('--allow-loopback')
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
  // Merged ignoring case, as Windows reads names: a caller's
  // `Https_Proxy` is the same variable as ours. Node's built-in clients
  // read the proxy variables only with NODE_USE_ENV_PROXY set; it sits in
  // the first layer, so a caller's value, in any case, wins.
  const overlay = mergeWindowsEnv(
    {
      PATH: process.env.PATH,
      PATHEXT: process.env.PATHEXT,
      ...(p.httpProxyPort ? { NODE_USE_ENV_PROXY: '1' } : {}),
    },
    p.setEnvVars ?? {},
    generated,
    gitCfg,
  )
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
 * The one spelling each proxy variable has in a sandboxed command's
 * environment. Must match `PROXY_NAME_SPELLING` in launch.rs.
 */
const WINDOWS_PROXY_NAME_SPELLING: readonly string[] = [
  'http_proxy',
  'https_proxy',
  'ftp_proxy',
  'all_proxy',
  'no_proxy',
  'grpc_proxy',
  'RSYNC_PROXY',
]

/**
 * Merge environment layers ignoring case, as Windows reads names: a later
 * layer's entry replaces an earlier one, name and value; an `undefined`
 * value sets nothing. Two names that differ only by case in one block make
 * .NET's `Process.Start` throw.
 */
export function mergeWindowsEnv(
  ...layers: Readonly<Record<string, string | undefined>>[]
): Record<string, string | undefined> {
  const byName = new Map<string, [name: string, value: string | undefined]>()
  for (const layer of layers) {
    for (const [name, value] of Object.entries(layer)) {
      if (value === undefined) continue
      const folded = name.toUpperCase()
      const spelling =
        WINDOWS_PROXY_NAME_SPELLING.find(n => n.toUpperCase() === folded) ??
        name
      byName.set(folded, [spelling, value])
    }
  }
  return Object.fromEntries(byName.values())
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
 * Why an existing install cannot be used by this `srt-win` (its setup
 * marker is another release's; re-run the install), or `undefined`.
 * An `srt-win` that does not report its setup version is not judged.
 */
export function windowsSetupVersionMismatch(
  us: WindowsSandboxUserStatus,
  sublayerGuid?: string,
): string | undefined {
  if (us.setupVersion === undefined || us.markerVersion === us.setupVersion) {
    return undefined
  }
  if (us.markerVersion !== undefined && us.markerVersion > us.setupVersion) {
    const sl = sublayerGuid ? ` --sublayer-guid ${sublayerGuid}` : ''
    return (
      `The Windows sandbox on this machine was set up by a newer ` +
      `release (setup version ${us.markerVersion}; this release needs ` +
      `${us.setupVersion}). Use that release, or replace its install ` +
      `with this one: \`srt-win.exe install --force${sl}\`.\n` +
      `Nothing is granted or run until then.`
    )
  }
  return (
    `The Windows sandbox on this machine was set up by a different ` +
    `release (setup version ${us.markerVersion ?? 'unknown'}; this ` +
    `release needs ${us.setupVersion}). Re-run the install to upgrade ` +
    `it in place (one UAC prompt):\n` +
    windowsInstallCommandLines(windowsInstallFlags({ sublayerGuid }, false)) +
    `Nothing is granted or run until then.`
  )
}

/** The two ways to run the install, with `flags` (see `windowsInstallFlags`). */
function windowsInstallCommandLines(flags: string): string {
  return (
    `  ${WINDOWS_INSTALL_COMMAND}${flags}\n` +
    `  — or call installWindowsSandbox(), or run ` +
    `\`srt-win.exe install${flags}\` directly.\n`
  )
}

/**
 * Install instructions, surfaced verbatim in error messages.
 */
export function windowsInstallInstructions(
  install: string | WindowsInstallContext | undefined,
  force = false,
): string {
  const ctx = typeof install === 'string' ? { sublayerGuid: install } : install
  return (
    `Windows sandbox needs a one-time install (one UAC prompt):\n` +
    windowsInstallCommandLines(windowsInstallFlags(ctx ?? {}, force)) +
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
  install: WindowsInstallContext,
  user: PromiseSettledResult<WindowsSandboxUserStatus>,
  getWfp: () => PromiseSettledResult<WindowsWfpStatusResult>,
): SandboxDependencyCheck {
  const { sublayerGuid, allowLoopback } = install
  const errors: string[] = []
  const warnings: string[] = []
  const mode = (open: boolean): string => (open ? 'open' : 'closed')
  let reinstallRequired: string | undefined
  let loopbackMismatch: string | undefined
  const result = (): SandboxDependencyCheck => ({
    errors,
    warnings,
    ...(reinstallRequired && { reinstallRequired }),
    ...(loopbackMismatch && { loopbackMismatch }),
  })

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
        windowsInstallInstructions(install),
    )
  } else {
    // Installed, by a release with another setup version: an upgrade,
    // not a missing sandbox, so its own wording.
    reinstallRequired = windowsSetupVersionMismatch(us, sublayerGuid)
    if (reinstallRequired) errors.push(reinstallRequired)
  }

  // 2b. Secondary Logon service usable: every launch goes through it.
  // Field absent (older srt-win) → no opinion.
  if (us.seclogon === 'disabled' || us.seclogon === 'missing') {
    errors.push(seclogonDisabledMessage(us.seclogon))
  } else if (us.seclogon === 'cannot-read') {
    logForDebugging(
      `[Sandbox Windows] Secondary Logon (seclogon) state cannot-read; ` +
        `a launch will show whether it is usable`,
    )
  }

  // 3. WFP filters installed under the sublayer. BFE enumeration is
  // admin-gated; `cannot-read` is informational only — the
  // BEHAVIORAL check (`verifyWindowsWfpEgress`) runs at
  // `initialize()` and is what actually fails closed.
  const wfp = getWfp()
  if (wfp.status === 'rejected') {
    errors.push(`srt-win wfp status failed: ${(wfp.reason as Error).message}`)
    return result()
  }
  const ws = wfp.value
  if (ws.state === 'cannot-read') {
    logForDebugging(
      `[Sandbox Windows] wfp status cannot-read (non-elevated): ${ws.hint}`,
    )
  } else if (ws.state === 'loopback-mismatch') {
    // The filters in place are not the ones the install recorded.
    errors.push(
      `WFP filters under sublayer ${sublayerGuid ?? '(default)'} cannot ` +
        `be used: their loopback mode ` +
        `(${ws.allowLoopback ? 'open' : 'closed'}) is not the one the ` +
        `install recorded. Re-run the install for this configuration ` +
        `(one UAC prompt):\n  ` +
        windowsInstallCommand(install, true),
    )
  } else if (ws.state !== 'installed') {
    // 'absent'. If the user is also not-provisioned, the user-state
    // error above already gave the right instruction; don't repeat.
    if (us.provisioned && us.credPresent) {
      errors.push(
        `WFP filters not installed under sublayer ` +
          `${sublayerGuid ?? '(default)'}. ` +
          windowsInstallInstructions(install),
      )
    }
  } else if (ws.portRange) {
    logForDebugging(
      `[Sandbox Windows] WFP installed: ${ws.filters} filters, ` +
        `proxy port range ${ws.portRange[0]}-${ws.portRange[1]}, ` +
        `loopback ${mode(ws.allowLoopback)}`,
    )
  }

  // 4. The installed loopback mode is the configured one, in either
  // direction (`undefined`: the caller did not say what is configured).
  const fenced =
    us.provisioned &&
    us.credPresent &&
    (ws.state === 'installed' || ws.state === 'cannot-read')
  if (
    fenced &&
    allowLoopback !== undefined &&
    ws.allowLoopback !== allowLoopback
  ) {
    loopbackMismatch =
      `WFP filters under sublayer ${sublayerGuid ?? '(default)'} do not ` +
      `match network.allowLocalBinding (installed: loopback ` +
      `${mode(ws.allowLoopback)}; configured: ` +
      `${mode(allowLoopback)}). Re-run the install for this ` +
      `configuration (one UAC prompt):\n  ` +
      windowsInstallCommand(install, true)
    errors.push(loopbackMismatch)
  } else if (fenced && ws.allowLoopback) {
    // Not an error, and not to be read past: say what is open.
    warnings.push(WINDOWS_ALLOW_LOOPBACK_EFFECT)
  }

  return result()
}

/**
 * Check the Windows backend is ready to sandbox. Errors block
 * `initialize()`; warnings are informational.
 *
 * Prefer {@link checkWindowsDependenciesAsync}; this variant
 * `spawnSync`-blocks the event loop on two `srt-win.exe` spawns
 * (Windows Defender cold-scan can add seconds).
 *
 * @param opts.allowLoopback the configured `network.allowLocalBinding`:
 *   an install with the other loopback mode is an error. Omit it to
 *   skip the comparison.
 * @param opts.proxyPortRange, opts.sandboxUser the configured install
 *   options, named in the install command an error suggests.
 */
export function checkWindowsDependencies(
  opts: WindowsInstallContext & { srtWin?: SrtWinSpawn } = {},
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
    opts,
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
  opts: WindowsInstallContext & { srtWin?: SrtWinSpawn } = {},
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
  return interpretDependencyProbes(opts, user, () => wfp)
}
