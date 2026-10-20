import {
  hasNameReading,
  literalReadLists,
  literalWriteLists,
  reExposedBy,
  readRulesOf,
  samePathEntries,
  spelledOf,
  withOtherReadings,
  writeRootsOf,
  type PathListKind,
} from './path-entries.js'
import { createHttpProxyServer } from './http-proxy.js'
import { assertTlsTerminationSupported } from './emitted-connection.js'
import { createSocksProxyServer } from './socks-proxy.js'
import type { SocksProxyWrapper } from './socks-proxy.js'
import { createMuxProxyServer, type MuxProxyServer } from './mux-proxy.js'
import { listenInRange } from './listen-in-range.js'
import { SentinelRegistry } from './credential-sentinel.js'
import {
  MaskedFileStore,
  buildMaskedFileBinds,
} from './credential-mask-files.js'
import { buildMaskedEnvVars } from './credential-mask-env.js'
import {
  AwsPairRegistry,
  createSigv4Planner,
  registerAwsPairs,
  type PlanSigv4,
} from './credential-aws-pairs.js'
import {
  createMitmCA,
  CRL_PATH,
  disposeMitmCA,
  disposeMitmCASync,
  type MitmCA,
} from './mitm-ca.js'
import { logForDebugging } from '../utils/debug.js'
import { whichSync } from '../utils/which.js'
import type { RipgrepConfig } from '../utils/ripgrep.js'
import { getPlatform, getWslVersion } from '../utils/platform.js'
import * as fs from 'fs'
import { randomBytes } from 'node:crypto'
import type {
  CredentialsConfig,
  FilesystemPathEntry,
  SandboxRuntimeConfig,
  SeccompConfig,
} from './sandbox-config.js'
import type {
  SandboxAskCallback,
  CredentialRestrictionConfig,
  FsReadRestrictionConfig,
  FsWriteRestrictionConfig,
  NetworkRestrictionConfig,
} from './sandbox-schemas.js'
import {
  WorkingDirectoryChanged,
  wrapCommandWithSandboxLinux,
  initializeLinuxNetworkBridge,
  type LinuxNetworkBridgeContext,
  checkLinuxDependencies,
  type SandboxDependencyCheck,
  cleanupBwrapMountPoints,
  linuxGetCwdMandatoryDenyPaths,
} from './linux-sandbox-utils.js'
import { expandReadDenyGlobLinuxSteps } from './read-deny-glob.js'
import {
  wrapCommandWithSandboxMacOS,
  startMacOSSandboxLogMonitor,
} from './macos-sandbox-utils.js'
import {
  startLinuxSandboxViolationMonitor,
  type LinuxViolationMonitor,
} from './linux-violation-monitor.js'
import {
  checkWindowsDependencies,
  checkWindowsDependenciesAsync,
  wrapCommandWithSandboxWindows,
  parseWindowsBinShell,
  expandWindowsFsPaths,
  rankWindowsFsAccess,
  restoreWindowsAcl,
  grantWindowsAclPersistent,
  windowsSetupVersionMismatch,
  windowsSrtWinOutdatedError,
  missingWindowsSrtWinCapability,
  windowsGrantsBeneathDenies,
  type WindowsProfileGrantItem,
  type WindowsProfileGrantStatus,
  getWindowsProfileReadStatus,
  getWindowsProfileReadStatusAsync,
  windowsProfileExclusionConflicts,
  revokeWindowsAclChecked,
  type WindowsAclRevokeResult,
  getWindowsSandboxUserStatusAsync,
  ensurePersistentWindowsCa,
  verifyWindowsWfpEgress,
  resolveSrtWin,
  WindowsSandboxError,
  type SrtWinSpawn,
  type WindowsBinShell,
  type WindowsFsAccessSet,
  DEFAULT_WINDOWS_PROXY_PORT_RANGE,
} from './windows-sandbox-utils.js'
import {
  getDefaultWritePaths,
  containsGlobChars,
  globBaseDirIsRoot,
  globPatternBaseDir,
  normalizePathForSandbox,
  removeTrailingGlobSuffix,
  walkGlobPatternSteps,
  workingDirectory,
  type GlobWalkListings,
  type Steps,
  finish,
  finishInTurns,
  attributionKeyFor,
  decodeSandboxedCommand,
  encodeSandboxedCommand,
} from './sandbox-utils.js'
import { ownInstallWarning } from './own-files.js'
import {
  SandboxViolationStore,
  sanitizeDenialReason,
  sanitizeUnregisteredCommandKey,
  shouldIgnoreViolation,
} from './sandbox-violation-store.js'
import type { MutateForwardedHeaders } from './request-filter.js'
import type { GetBodySubstitutions } from './body-substitution.js'
import {
  canonicalizeHost,
  isValidHost,
  redactUrl,
  resolveParentProxy,
} from './parent-proxy.js'
import {
  ALLOWED_DOMAIN_ENTRY_MESSAGE,
  isValidAllowedDomainEntry,
  matchesDomainPattern,
  matchesDomainPatternWithPort,
  stripDomainPatternPort,
} from './domain-pattern.js'
import type { ChildProcess } from 'node:child_process'
import type { DirectLookup, ResolvedParentProxy } from './parent-proxy.js'
import {
  createResolvedAddressGuard,
  isResolvedAddressDenied,
  type ResolvedAddressGuard,
} from './resolved-address-guard.js'
import { EOL } from 'node:os'
import { dirname } from 'node:path'
import { getJavaProxyAgentJarPathAsync } from './java-proxy-agent.js'
import { getApplySeccompBinaryPathAsync } from './generate-seccomp-filter.js'

interface HostNetworkManagerContext {
  httpProxyPort: number
  socksProxyPort: number
  linuxBridge: LinuxNetworkBridgeContext | undefined
}

// ============================================================================
// Private Module State
// ============================================================================

let config: SandboxRuntimeConfig | undefined
/** How many times a configuration has been installed. A wrap tells by this
 *  as well as by the object: initialize() keeps the caller's own, which can
 *  be handed to it again. */
let configInstalls = 0
let httpProxyServer: ReturnType<typeof createHttpProxyServer> | undefined
let socksProxyServer: SocksProxyWrapper | undefined
let muxProxyServer: MuxProxyServer | undefined
let managerContext: HostNetworkManagerContext | undefined
let initializationPromise: Promise<HostNetworkManagerContext> | undefined
let cleanupRegistered = false
let ownInstallLogged = false
let logMonitorShutdown: (() => void) | undefined
let linuxMonitor: LinuxViolationMonitor | undefined
let parentProxy: ResolvedParentProxy | undefined
/** Read live through {@link directLookup}, so a config update applies to the next dial. */
let resolvedAddressGuard: ResolvedAddressGuard = createResolvedAddressGuard()
let mitmCA: MitmCA | undefined
/**
 * Resolved path of the JVM proxy agent jar (see java-proxy-agent.ts); set
 * while a proxy is advertised to the sandbox, undefined if the jar is not
 * shipped/found (JVMs then just aren't proxy-aware, as before).
 */
let javaAgentJarPath: string | undefined
// Per-session proxy auth token. Generated at proxy start, exported only into
// the sandbox child env, checked on every CONNECT/request — so a host process
// dialing 127.0.0.1:<proxyPort> can't reach the filter callback.
let proxyAuthToken: string | undefined
// Windows: the config's resolved access set that was actually applied
// at initialize(). `undefined` means no stamp/grant was applied
// (gates running `acl restore`/`acl revoke` at reset()).
let windowsFsStampedSet: WindowsFsAccessSet | undefined
// The sandbox user SID captured at initialize(). reset() uses this
// so a config change between init and reset can't strand ACEs
// under a different SID.
let windowsFsSbUserSid: string | undefined
// The RAW config inputs that produced `windowsFsStampedSet`.
// updateConfig() compares these (not the resolved set) so it never
// re-expands globs — see `sameWindowsStampSet`.
let windowsFsRawInputs: ReturnType<typeof rawWindowsFsInputs> | undefined
// `verifyWindowsWfpEgress()` is once per PROCESS (it spawns a
// CreateProcessWithLogonW runner; first call may create the sandbox
// user's profile). The WFP fence is install-scoped, not config- or
// session-scoped — reset() does NOT clear this, so updateConfig()'s
// reset+reinit and the test suite's per-test reset() don't re-verify.
// Remembered as the sandbox account the check passed for: a different
// account (a reinstall) is checked again.
let windowsWfpVerifiedFor: string | undefined
// And the loopback mode (`network.allowLocalBinding`) it was run with: a
// session configured with the other is checked, and refused, again.
let windowsWfpVerifiedLoopback: boolean | undefined
// The `srt-win` builds, by identity, that reported every capability the
// library relies on. Only a yes is remembered.
const windowsCapableSrtWin = new Set<string>()

/**
 * What tells one `srt-win` from another: the executable, the arguments
 * put in front of every call, and — so that a file replaced in place
 * is a different one — its size and modification time.
 */
function windowsSrtWinIdentity(srtWin: SrtWinSpawn): string {
  let stat = ''
  try {
    const st = fs.statSync(srtWin.exe)
    stat = `${st.size}:${st.mtimeMs}`
  } catch {
    // Not a path that can be looked at (resolved through PATH, say):
    // the name and arguments are the identity.
  }
  return JSON.stringify([srtWin.exe, srtWin.prependArgs, stat])
}

const WINDOWS_CAPABILITIES_WHY =
  `a session depends on (its read ` +
  `denies are written on the profile read grant's paths by srt-win, ` +
  `and kept grants are checked and removed there)`

/**
 * Make sure the `srt-win` this command runs through has reported every
 * capability the library relies on; asked once per identity.
 */
function assertWindowsSrtWinCapable(srtWin: SrtWinSpawn): void {
  const id = windowsSrtWinIdentity(srtWin)
  if (windowsCapableSrtWin.has(id)) return
  const missing = missingWindowsSrtWinCapability(
    getWindowsProfileReadStatus({ srtWin }).capabilities,
  )
  if (missing !== undefined) {
    throw windowsSrtWinOutdatedError(missing, WINDOWS_CAPABILITIES_WHY)
  }
  windowsCapableSrtWin.add(id)
}

// Windows: whether this session's commands read the user's profile
// through the profile read grant.
let windowsProfileRead: 'granted' | 'absent' | undefined
// Windows: what the session has to tell its user about the profile
// read grant it runs on (getWindowsProfileReadWarnings).
let windowsProfileReadWarnings: WindowsProfileReadWarning[] = []

/** Something about the profile read grant that the user should be shown. */
export interface WindowsProfileReadWarning {
  /** See {@link windowsProfileReadWarningsOf}. */
  code:
    | 'profile_exclusion_unprotected'
    | 'profile_exclusion_unverifiable'
    | 'profile_stale_allow'
    | 'profile_file_replaced'
  message: string
  paths: WindowsProfileGrantItem[]
}

/**
 * What a session on this grant has to tell its user, from what
 * `srt-win` found — each message says what was established about its
 * paths and nothing more.
 */
export function windowsProfileReadWarningsOf(
  grant: Pick<
    WindowsProfileGrantStatus,
    'unprotected' | 'unverifiable' | 'staleAllow'
  > &
    Partial<Pick<WindowsProfileGrantStatus, 'replacedFiles'>>,
): WindowsProfileReadWarning[] {
  const list = (items: readonly WindowsProfileGrantItem[]) =>
    items.map(i => i.path).join(', ')
  const out: WindowsProfileReadWarning[] = []
  // Open through an entry this product wrote and could not take
  // back: the strongest case, said first and as what it is.
  const byOurs = grant.unprotected.filter(i => i.entry !== undefined)
  const byList = grant.unprotected.filter(i => i.entry === undefined)
  const callerReads = grant.unverifiable.filter(i => i.callerReads === true)
  const rest = grant.unverifiable.filter(i => i.callerReads !== true)
  if (byOurs.length + byList.length + callerReads.length > 0) {
    const parts: string[] = []
    if (byOurs.length > 0) {
      parts.push(
        `${byOurs.length} READABLE THROUGH AN ENTRY THIS PRODUCT WROTE and ` +
          `could not remove — each path's reason gives the icacls command ` +
          `that removes it, to be run as the object's owner or from an ` +
          `elevated prompt, followed by the grant again (${list(byOurs)})`,
      )
    }
    if (byList.length > 0) {
      parts.push(
        `${byList.length} by their own access lists, which you may not ` +
          `change (${list(byList)})`,
      )
    }
    if (callerReads.length > 0) {
      parts.push(
        `${callerReads.length} whose access lists could not be read but ` +
          `which you can read all the same, so sandboxed commands may ` +
          `too (${list(callerReads)})`,
      )
    }
    out.push({
      code: 'profile_exclusion_unprotected',
      message:
        `Paths on the exclusion list of the profile read grant could not ` +
        `be denied and are, or may be, readable to sandboxed commands: ` +
        parts.join('; ') +
        `. Only their owner or an administrator can close them.`,
      paths: [...byOurs, ...byList, ...callerReads],
    })
  }
  if (rest.length > 0) {
    const unreadable = rest.filter(i => i.callerReads === false)
    const noAccount = rest.filter(i => i.cause === 'account_unknown')
    const other = rest.filter(
      i => i.callerReads !== false && i.cause !== 'account_unknown',
    )
    const parts: string[] = []
    if (unreadable.length > 0) {
      parts.push(
        `${unreadable.length} whose access lists could not be read; you ` +
          `cannot read their content either (${list(unreadable)})`,
      )
    }
    if (noAccount.length > 0) {
      parts.push(
        `${noAccount.length} that could not be examined because the ` +
          `sandbox account is not known (${list(noAccount)})`,
      )
    }
    if (other.length > 0) {
      parts.push(`${other.length} that were not examined (${list(other)})`)
    }
    out.push({
      code: 'profile_exclusion_unverifiable',
      message:
        `Paths on the exclusion list of the profile read grant could not ` +
        `be denied, and whether sandboxed commands can read them was not ` +
        `established: ` +
        parts.join('; ') +
        `.`,
      paths: rest,
    })
  }
  if (grant.staleAllow.length > 0) {
    out.push({
      code: 'profile_stale_allow',
      message:
        `${grant.staleAllow.length} path(s) that have left the profile ` +
        `read grant still carry an entry of it that could not be removed, ` +
        `and are readable to sandboxed commands through it: ` +
        `${list(grant.staleAllow)}. None is on the exclusion list. Each ` +
        `path's reason gives the icacls command that removes the entry.`,
      paths: grant.staleAllow,
    })
  }
  const replaced = grant.replacedFiles ?? []
  if (replaced.length > 0) {
    out.push({
      code: 'profile_file_replaced',
      message:
        `${replaced.length} configuration file(s) were replaced since the ` +
        `profile read grant was made and are not readable to sandboxed ` +
        `commands; the variables that point at them are not returned: ` +
        `${replaced.join(', ')}. Run grantWindowsProfileRead() ` +
        `(\`srt-win profile grant\`) again.`,
      paths: replaced.map(path => ({
        path,
        reason: 'replaced since the grant was made',
      })),
    })
  }
  return out
}
// Resolved once at initialize() (`resolveSrtWin` stats the disk).
// Captured so wrapWithSandboxArgv/reset() don't re-resolve per call
// and so reset()'s revoke/restore addresses the SAME binary the
// grants/stamps were applied with even if `config` mutated between.
let srtWinSpawn: SrtWinSpawn | undefined
const sandboxViolationStore = new SandboxViolationStore()
// Per-session sentinel↔real-value map for masked credentials. Lives only in
// process memory; never written to disk or logged. Cleared on reset().
const sentinelRegistry = new SentinelRegistry()
// Per-session linked AWS credential pairs for SigV4 re-signing, keyed by
// the fake access key id. Same lifecycle and secrecy posture as the
// sentinel registry.
const awsPairRegistry = new AwsPairRegistry()
// Temp dir holding the sentinel-content fake files for masked credential
// files. Created lazily on first masked file; removed on reset().
const maskedFileStore = new MaskedFileStore()

// ============================================================================
// Private Helper Functions (not exported)
// ============================================================================

function registerCleanup(): void {
  if (cleanupRegistered) {
    return
  }
  const cleanupHandler = () =>
    reset().catch(e => {
      logForDebugging(`Cleanup failed in registerCleanup ${e}`, {
        level: 'error',
      })
    })
  process.once('exit', () => {
    void cleanupHandler()
    // On 'exit' reset() gets as far as its first await, so what it takes out
    // of the temp directory later than that goes here. After it, because on
    // Windows it starts by revoking a grant on the trust-bundle directory.
    // Only paths this process made and still holds: never a listing of the
    // temp directory, never a path out of the configuration.
    if (mitmCA) disposeMitmCASync(mitmCA)
    muxProxyServer?.removeBackendSocketSync()
    maskedFileStore.dispose()
    // A bridge told to end removes its own socket, but not every time.
    const bridge = managerContext?.linuxBridge
    for (const path of [bridge?.httpSocketPath, bridge?.socksSocketPath]) {
      try {
        if (path) fs.rmSync(path, { force: true })
      } catch {
        // Best effort: an 'exit' handler must not throw.
      }
    }
  })
  process.once('SIGINT', cleanupHandler)
  process.once('SIGTERM', cleanupHandler)
  cleanupRegistered = true
}

// An older srt-win reports 'restored'/'alreadyOriginal' where a
// current one reports 'revoked'/'stillHeld'.
const WINDOWS_ACL_RELEASE_OK = new Set([
  'revoked',
  'stillHeld',
  'restored',
  'alreadyOriginal',
])

function logWindowsAclOutcomes(
  kind: string,
  outcomes: readonly { path: string; status: string }[] | undefined,
): void {
  for (const e of outcomes ?? []) {
    if (!WINDOWS_ACL_RELEASE_OK.has(e.status)) {
      logForDebugging(
        `[Sandbox Windows] ${kind}: '${e.path}' ${e.status} — ` +
          `ACE may be left in place; resolve and run ` +
          `\`srt-win acl recover\` to clear`,
        { level: 'warn' },
      )
    }
  }
}

/**
 * Whether the deny restore may run: only after a revoke that
 * completed — otherwise a grant may still be on disk, and the sandbox
 * account is shared. srt-win enforces the same rule from its records.
 */
function windowsAclRestoreAllowed(revoke: WindowsAclRevokeResult): boolean {
  logWindowsAclOutcomes('grant revoke', revoke.outcomes)
  if (revoke.complete) return true
  const paths = revoke.pending
  logForDebugging(
    `[Sandbox Windows] grant revoke did not complete` +
      ` — NOT running the deny restore; deny ACEs stay in place ` +
      `while a grant may still be on disk. Grants possibly left in ` +
      `place: ${paths.length > 0 ? paths.map(p => `'${p}'`).join(', ') : '(none reported)'}` +
      (revoke.detail ? `. srt-win: ${revoke.detail}` : '') +
      `. The next revoke retries them; after this process exits, ` +
      `\`srt-win acl recover\` does, and removes its deny ACEs once ` +
      `they are released (\`--force\` drops the record of a grant ` +
      `that can no longer be located).`,
    { level: 'error' },
  )
  return false
}

function releaseWindowsSessionAcls(
  sandboxUserSid: string,
  srtWin: SrtWinSpawn | undefined,
): void {
  const o = { sandboxUserSid, srtWin }
  if (windowsAclRestoreAllowed(revokeWindowsAclChecked(o))) {
    logWindowsAclOutcomes('deny restore', restoreWindowsAcl(o))
  }
}

/**
 * Attribution key to command text for every wrapped invocation, so each
 * producer can report (and ignoreViolations can match) the command an event
 * belongs to rather than the opaque key. Keys are held decoded because that
 * is the form the carriers deliver. Bounded FIFO: the violation store itself
 * only retains the last 100 events, so long-gone invocations need no entry.
 */
const MAX_COMMAND_TEXTS = 1024
const commandTextsByKey = new Map<string, string>()

/** Exported for testing. */
export function registerCommandText(
  command: string,
  options: WrapWithSandboxOptions | undefined,
): void {
  const key = decodeSandboxedCommand(
    encodeSandboxedCommand(attributionKeyFor(command, options?.commandId)),
  )
  const text = options?.commandText ?? command
  commandTextsByKey.delete(key)
  commandTextsByKey.set(key, text)
  while (commandTextsByKey.size > MAX_COMMAND_TEXTS) {
    const oldest = commandTextsByKey.keys().next().value
    if (oldest === undefined) break
    commandTextsByKey.delete(oldest)
  }
}

/**
 * The command text for a decoded attribution key. Keys arrive over carriers
 * the sandboxed process can write (the observe socket's event field, the
 * macOS log tag, the proxy username), so only a key this process registered
 * carries the embedder's own text; anything else is untrusted bytes.
 * Exported for testing.
 */
export function resolveCommandText(decodedKey: string): string {
  return (
    commandTextsByKey.get(decodedKey) ??
    sanitizeUnregisteredCommandKey(decodedKey)
  )
}

/**
 * The shortest commandId a per-command allow list may be registered under:
 * 16 random bytes (128 bits) as unpadded base64url. The floor only turns away
 * what is too short to hold 128 bits: it cannot tell a random id from a
 * predictable one of the same length.
 */
const MIN_NETWORK_LISTS_COMMAND_ID_LENGTH = 22

/**
 * Attribution key to the network allow list registered for one invocation
 * (registerCommandNetworkLists), keyed the way commandTextsByKey is because
 * the proxy username delivers both. The embedder removes an entry when its
 * command is gone. Not bounded the way commandTextsByKey is: dropping the
 * oldest entry would silently take a list away from a running command.
 */
const commandNetworkListsByKey = new Map<string, { allowedDomains: string[] }>()

function registerCommandNetworkLists(
  commandId: string,
  lists: { allowedDomains?: string[] },
): void {
  // The floor is measured on the key the map holds, not on the raw id, and
  // less U+FFFD: every unpaired surrogate becomes one, so it carries nothing.
  const key =
    typeof commandId === 'string'
      ? decodeSandboxedCommand(encodeSandboxedCommand(commandId))
      : ''
  // The id is not echoed in either message: it is what stands between a
  // sandboxed process and this list, and error text ends up in logs.
  if (key.replace(/\ufffd/g, '').length < MIN_NETWORK_LISTS_COMMAND_ID_LENGTH) {
    throw new Error(
      `registerCommandNetworkLists: commandId must be a string of at least ` +
        `${MIN_NETWORK_LISTS_COMMAND_ID_LENGTH} characters, unpaired ` +
        `surrogates not counted. The id is the ` +
        `only thing that binds a proxy connection to this allow list, and ` +
        `the sandboxed process chooses which id it presents, so it must be ` +
        `random (at least 128 bits, e.g. 16 random bytes as base64url) and ` +
        `never derived from the command text, a counter or the time.`,
    )
  }
  const allowedDomains = lists?.allowedDomains ?? []
  if (!Array.isArray(allowedDomains)) {
    throw new Error(
      'registerCommandNetworkLists: allowedDomains must be an array of strings.',
    )
  }
  for (const entry of allowedDomains) {
    if (typeof entry !== 'string' || !isValidAllowedDomainEntry(entry)) {
      throw new Error(
        `registerCommandNetworkLists: invalid allowedDomains entry ` +
          `${JSON.stringify(entry)}. ${ALLOWED_DOMAIN_ENTRY_MESSAGE}`,
      )
    }
  }
  commandNetworkListsByKey.set(
    key,
    // Copied, so the caller cannot change what was validated.
    { allowedDomains: [...allowedDomains] },
  )
  // An external HTTP proxy is handed no username, so no connection names an id.
  if (config?.network.httpProxyPort !== undefined) {
    logForDebugging(
      'registerCommandNetworkLists: network.httpProxyPort is set (an ' +
        'external proxy), so this list will never apply',
      { level: 'warn' },
    )
  }
}

function unregisterCommandNetworkLists(commandId: string): void {
  if (typeof commandId !== 'string') return
  commandNetworkListsByKey.delete(
    decodeSandboxedCommand(encodeSandboxedCommand(commandId)),
  )
}

/**
 * Record a proxy-side denial in the violation store so the model sees a
 * structured <sandbox_violations> block alongside the raw 403 / SOCKS
 * failure in stderr — parity with the macOS seatbelt log monitor and the
 * Linux seccomp observer. The proxy is the only component that knows the
 * destination host of a network deny, so neither of those can produce
 * this line. `encodedCommand` (from the proxy username) attributes it to
 * the invocation; without one the event is stored unattributed.
 */
function recordProxyViolation(
  line: string,
  encodedCommand: string | undefined,
): void {
  const command = encodedCommand
    ? resolveCommandText(decodeSandboxedCommand(encodedCommand))
    : undefined
  // Same suppression the seatbelt / seccomp monitors apply, so a
  // configured ignoreViolations pattern silences the event no matter
  // which producer saw it.
  if (shouldIgnoreViolation(line, command, config?.ignoreViolations)) {
    return
  }
  sandboxViolationStore.addViolation({
    line,
    encodedCommand,
    command,
    timestamp: new Date(),
  })
}

function recordOutboundDeny(
  host: string,
  port: number,
  reason: string,
  encodedCommand?: string,
): void {
  recordProxyViolation(
    `deny network-outbound ${host}:${port} (${reason})`,
    encodedCommand,
  )
}

/** Direct-dial `lookup` for the proxies: the current guard's, with a refusal recorded as a violation. */
const directLookup: DirectLookup =
  (port, encodedCommand) => (hostname, options, callback) =>
    resolvedAddressGuard.lookupFor(port)(
      hostname,
      options,
      (err, address, family) => {
        if (isResolvedAddressDenied(err)) {
          recordOutboundDeny(hostname, port, err.reason, encodedCommand)
        }
        callback(err, address, family)
      },
    )

/**
 * The request URL as it should appear in a model-visible violation line: as
 * spelled (parsed, a refused `/a/../b` would read `/b`), with a query string
 * or fragment reduced to a `?…` or `#…` marker. (The proxy rebuilds the
 * authority, so an embedded `name:pass@` is gone already.) Query strings
 * routinely carry credentials (api_key=, access_token=, signed URLs) that
 * the sandboxed client interpolated at runtime and that were never in the
 * model's context, so they must not enter the transcript via the
 * <sandbox_violations> block. The full URL still reaches the embedder's
 * filterRequest callback and its own debug logging.
 */
function redactUrlForViolation(url: string): string {
  const cut = url.search(/[?#]/)
  return cut === -1 ? url : `${url.slice(0, cut + 1)}…`
}

/** Whether an ask-callback answer is one of the two documented denials. */
function isDeclaredDenial(answer: unknown): boolean {
  return (
    answer === false ||
    (typeof answer === 'object' &&
      answer !== null &&
      (answer as { allow?: unknown }).allow === false)
  )
}

/**
 * The reason an ask-callback answer gives for denying, sanitized, or
 * undefined when it gives none that can be shown. Only
 * `{ allow: false, reason }` supplies one: a reason on any other object was
 * not written as the explanation of a denial.
 */
function denialReasonOf(answer: unknown): string | undefined {
  if (typeof answer !== 'object' || answer === null) return undefined
  const { allow, reason } = answer as { allow?: unknown; reason?: unknown }
  if (allow !== false || typeof reason !== 'string') return undefined
  return sanitizeDenialReason(reason) || undefined
}

/** Own keys only: an entry can be spelled `constructor`. */
function deniedDomainReason(entry: string): string {
  const reasons = config?.network.deniedDomainReasons ?? {}
  const own = Object.prototype.hasOwnProperty.call(reasons, entry)
  return (own ? reasons[entry] : undefined) ?? 'host is on the deny list'
}

async function filterNetworkRequest(
  port: number,
  host: string,
  sandboxAskCallback: SandboxAskCallback | undefined,
  encodedCommand?: string,
  explain?: (reason: string) => void,
): Promise<boolean> {
  const denied = (reason: string): false => {
    recordOutboundDeny(host, port, reason, encodedCommand)
    explain?.(reason)
    return false
  }

  if (!config) {
    logForDebugging('No config available, denying network request')
    return denied('sandbox policy unavailable')
  }

  // Reject hosts containing control characters before pattern matching.
  // `matchesDomainPattern` uses string suffix matching which is trivially
  // fooled by e.g. `evil.com\x00.allowed.com` — the null byte passes
  // `.endsWith()` but truncates at the libc DNS layer. The SOCKS path is the
  // main exposure (DOMAINNAME is unvalidated bytes); HTTP is protected by
  // llhttp/URL parsing, but we check here for defence in depth.
  if (!isValidHost(host)) {
    logForDebugging(`Denying malformed host: ${JSON.stringify(host)}:${port}`, {
      level: 'error',
    })
    return denied('malformed host')
  }

  // Canonicalize so string comparisons match what getaddrinfo() will dial.
  // Without this, inet_aton shorthand like `2852039166` (= 169.254.169.254)
  // or `127.1` slips past a denylist entry for the dotted-decimal form.
  const canonicalHost = canonicalizeHost(host) ?? host

  // Check denied domains first
  for (const deniedDomain of config.network.deniedDomains) {
    if (matchesDomainPatternWithPort(canonicalHost, port, deniedDomain)) {
      logForDebugging(`Denied by config rule: ${host}:${port}`)
      // The matched entry's own reason when the caller supplied one, so the
      // model reads why this destination is off-limits (and the sanctioned
      // alternative) instead of a generic deny; keyed by the exact entry.
      return denied(deniedDomainReason(deniedDomain))
    }
  }

  // Check allowed domains
  for (const allowedDomain of config.network.allowedDomains) {
    if (matchesDomainPatternWithPort(canonicalHost, port, allowedDomain)) {
      logForDebugging(`Allowed by config rule: ${host}:${port}`)
      return true
    }
  }

  // strictAllowlist makes the configured allowlist deterministic enforcement:
  // neither a per-command allow list nor the callback below can widen it.
  if (config.network.strictAllowlist) {
    logForDebugging(`No matching config rule, denying: ${host}:${port}`)
    return denied('host is not on the allow list')
  }

  // The allow list registered for the invocation the proxy username names.
  // Coming after both configured lists, it lifts the default deny for that
  // one command and never a configured deniedDomains entry. The username is
  // presented by the sandboxed client: see registerCommandNetworkLists.
  const perCommand = encodedCommand
    ? commandNetworkListsByKey.get(decodeSandboxedCommand(encodedCommand))
    : undefined
  for (const allowedDomain of perCommand?.allowedDomains ?? []) {
    if (matchesDomainPatternWithPort(canonicalHost, port, allowedDomain)) {
      logForDebugging(`Allowed by per-command rule: ${host}:${port}`)
      return true
    }
  }

  if (!sandboxAskCallback) {
    logForDebugging(`No matching rule, denying: ${host}:${port}`)
    return denied('host is not on the allow list')
  }

  logForDebugging(`No matching rule, asking user: ${host}:${port}`)
  try {
    // Held as unknown: a JavaScript caller is not bound by the declared type.
    const answer: unknown = await sandboxAskCallback({ host, port })
    // Only `true` allows: an object is how a callback denies with a reason,
    // and a truthiness test here would read every such denial as an allow.
    if (answer === true) {
      logForDebugging(`User allowed: ${host}:${port}`)
      return true
    }
    if (!isDeclaredDenial(answer)) {
      logForDebugging(
        `Ask callback answered neither a boolean nor { allow: false, reason }; treating it as a denial: ${host}:${port}`,
        { level: 'warn' },
      )
    }
    logForDebugging(`User denied: ${host}:${port}`)
    // The callback's own reason, when it gave one, says what to do instead.
    return denied(denialReasonOf(answer) ?? 'user denied')
  } catch (error) {
    logForDebugging(`Error in permission callback: ${error}`, {
      level: 'error',
    })
    return denied('permission prompt failed')
  }
}

/**
 * Build the header-mutation callback that substitutes sentinel→real for
 * masked credentials. Returns undefined when no `credentials` block is
 * configured — wiring the seam at all is unnecessary then.
 *
 * Per-host gating happens inside the registry: each sentinel carries its
 * own injectHosts list and substitutes independently, so credential A's
 * sentinel cannot be laundered through credential B's allowed host. The
 * returned closure does not log header values; the registry holds the only
 * copy of the real value.
 */
function buildCredentialInjector(): MutateForwardedHeaders | undefined {
  if (!config?.credentials) return undefined
  return (headers, destHost) => {
    sentinelRegistry.substituteInHeaders(
      headers,
      destHost,
      matchesDomainPattern,
    )
  }
}

/**
 * Body counterpart of {@link buildCredentialInjector}: per-destination
 * sentinel→real pairs for streaming substitution in request bodies, with
 * the same per-credential injectHosts gating applied inside the registry.
 */
function buildBodyCredentialInjector(): GetBodySubstitutions | undefined {
  if (!config?.credentials) return undefined
  return destHost =>
    sentinelRegistry.sentinelsForHost(destHost, matchesDomainPattern)
}

/**
 * Build the per-request SigV4 hook for the TLS-terminating proxy.
 * Returns undefined when no `credentials` block is configured. The hook
 * consults {@link awsPairRegistry} at request time, so pairs registered
 * later (wrapWithSandbox runs after the proxy starts) are picked up.
 */
function buildSigv4Planner(): PlanSigv4 | undefined {
  if (!config?.credentials) return undefined
  // Re-read the policies per request (not captured at proxy start) so an
  // updateConfig() that changes credentials.sigv4 takes effect without a
  // proxy restart, matching how the injector sees live registry state.
  return (method, requestTarget, headers, destHost) =>
    createSigv4Planner(
      awsPairRegistry,
      config?.credentials?.sigv4,
      matchesDomainPattern,
    )(method, requestTarget, headers, destHost)
}

/**
 * Get the MITM proxy socket path for a given host, if configured.
 * Returns the socket path if the host matches any MITM domain pattern,
 * otherwise returns undefined.
 *
 * Matches the canonicalized hostname, like the allow/deny filter
 * (filterNetworkRequest) and the tlsTerminate exclusion below. This site
 * fails OPEN on a miss — a host that matches no MITM pattern is dialed
 * directly — so it must accept exactly the set of spellings the allowlist
 * accepts: otherwise `api.example.com.` (trailing-dot FQDN, same name to
 * DNS) passes the allowlist as `api.example.com` but misses every MITM
 * pattern and skips the MITM proxy entirely. The proxies already hand this
 * hook the canonical spelling; canonicalizing again here is defence in
 * depth for any other caller.
 */
function getMitmSocketPath(host: string): string | undefined {
  if (!config?.network.mitmProxy) {
    return undefined
  }

  const { socketPath, domains } = config.network.mitmProxy
  const canonicalHost = canonicalizeHost(host) ?? host

  for (const pattern of domains) {
    if (matchesDomainPattern(canonicalHost, pattern)) {
      logForDebugging(`Host ${host} matches MITM pattern ${pattern}`)
      return socketPath
    }
  }

  return undefined
}

/**
 * Per-host TLS-termination opt-out from network.tlsTerminate.excludeDomains.
 * Only consulted by the HTTP proxy when tlsTerminate is enabled; exempted
 * hosts fall back to the opaque CONNECT tunnel (still allowlist-filtered),
 * so mTLS / cert-pinning clients can complete their own handshake.
 *
 * Matches the canonicalized hostname, like the allow/deny filter
 * (filterNetworkRequest) — otherwise a spelling the allowlist accepts after
 * canonicalization (`127.1`, a trailing-dot FQDN) would dodge the exclusion
 * and get terminated anyway.
 */
function shouldTerminateTLSForHost(host: string): boolean {
  const excludeDomains = config?.network.tlsTerminate?.excludeDomains
  if (!excludeDomains?.length) return true
  const canonicalHost = canonicalizeHost(host) ?? host
  for (const pattern of excludeDomains) {
    if (!matchesDomainPattern(canonicalHost, pattern)) continue
    logForDebugging(
      `Host ${host} matches tlsTerminate.excludeDomains pattern ${pattern}; skipping TLS termination`,
    )
    // Masked-credential substitution only happens on the terminated path,
    // so a credential whose injectHosts cover this host can never be
    // injected here — the upstream gets the placeholder. Config validation
    // rejects the fully-contradictory spellings; this flags the partial
    // ones (e.g. default injectHosts = allowedDomains) at the moment they
    // actually bite.
    const masked = sentinelRegistry.namesInjectableAt(
      canonicalHost,
      matchesDomainPattern,
    )
    if (masked.length > 0) {
      logForDebugging(
        `tlsTerminate.excludeDomains: masked credential(s) ${masked.join(', ')} ` +
          `are configured for injection at ${host}, but its connections are ` +
          `not terminated, so the upstream will receive the placeholder`,
        { level: 'error' },
      )
    }
    return false
  }
  return true
}

async function startMuxProxyServer(
  sandboxAskCallback: SandboxAskCallback | undefined,
  portRange: readonly [number, number] | undefined,
): Promise<number> {
  const injectCredentials = buildCredentialInjector()
  const injectBodyCredentials = buildBodyCredentialInjector()
  httpProxyServer = createHttpProxyServer({
    filter: (port, host, _socket, encodedCommand, explain) =>
      filterNetworkRequest(
        port,
        host,
        sandboxAskCallback,
        encodedCommand,
        explain,
      ),
    getMitmSocketPath,
    mitmCA,
    shouldTerminateTLS: shouldTerminateTLSForHost,
    filterRequest: config?.network.filterRequest,
    plaintextHeaderSet: config?.network.allowPlaintextHeaderSet,
    stripResponseHeaders: config?.network.stripResponseHeaders,
    refuseOpaqueTunnels: config?.network.refuseOpaqueTunnels,
    requireHostMatch: config?.network.requireHostMatch,
    ambiguousRequestTarget: config?.network.ambiguousRequestTarget,
    // Read at each CONNECT, so that updateConfig changes them.
    get maxTerminatedTunnels() {
      return config?.network.tlsTerminate?.maxTunnels
    },
    get tlsHandshakeTimeoutMs() {
      return config?.network.tlsTerminate?.handshakeTimeoutMs
    },
    onFilterRequestDenied: ({ method, url, reason, encodedCommand }) => {
      // A refused CONNECT comes with its authority (`host:port`), not a URL.
      const target = method === 'CONNECT' ? url : redactUrlForViolation(url)
      recordProxyViolation(
        `deny http-request ${method} ${target} (${reason})`,
        encodedCommand,
      )
    },
    // TLS-terminated path always gets the injector; the plain-HTTP path
    // only when explicitly opted in. Without the opt-in, a sentinel sent
    // over plain HTTP reaches the upstream unchanged (fails closed).
    mutateHeaders: injectCredentials,
    mutateHeadersPlaintext: config?.credentials?.allowPlaintextInject
      ? injectCredentials
      : undefined,
    getBodySubstitutions: injectBodyCredentials,
    getBodySubstitutionsPlaintext: config?.credentials?.allowPlaintextInject
      ? injectBodyCredentials
      : undefined,
    // SigV4 re-signing is TLS-terminated-path only, like credential
    // injection: the real signature must not travel over plaintext.
    planSigv4: buildSigv4Planner(),
    parentProxy,
    lookupFor: directLookup,
    proxyAuthToken,
  })

  socksProxyServer = createSocksProxyServer({
    filter: (port, host, encodedCommand) =>
      filterNetworkRequest(port, host, sandboxAskCallback, encodedCommand),
    parentProxy,
    lookupFor: directLookup,
    proxyAuthToken,
    // A SOCKS tunnel is opaque, so the option that keeps opaque CONNECT
    // tunnels off the HTTP side must close this side of the port too.
    refuseOpaqueTunnels: config?.network.refuseOpaqueTunnels,
    onTunnelRefused: (port, host, encodedCommand) => {
      recordProxyViolation(
        `deny socks-tunnel ${host}:${port} (refuseOpaqueTunnels)`,
        encodedCommand,
      )
    },
    probeUnauthenticated: async (port, host) => {
      // Explicit deny rules only: an unauthenticated peer must never reach
      // the ask callback, and a merely off-list host gets the generic
      // cannot-authenticate refusal rather than a policy claim.
      if (!config) return {}
      const canonical = canonicalizeHost(host) ?? host
      for (const entry of config.network.deniedDomains) {
        if (matchesDomainPatternWithPort(canonical, port, entry)) {
          const reason = deniedDomainReason(entry)
          recordOutboundDeny(host, port, reason)
          return { deniedReason: reason }
        }
      }
      return {}
    },
  })

  muxProxyServer = createMuxProxyServer({
    httpServer: httpProxyServer,
    handleSocksConnection: s => socksProxyServer!.handleConnection(s),
    httpBackendPortRange: portRange,
  })

  const mux = muxProxyServer
  // Backend first so the front-end never accepts a connection that would
  // dispatch to an unbound backend. On Windows the backend's port is
  // excluded when binding the front-end in the same WFP range.
  const backendPort = await mux.listenHttpBackend()
  await listenInRange(
    mux.server,
    p => mux.server.listen(p, '127.0.0.1'),
    portRange,
    backendPort !== undefined ? new Set([backendPort]) : new Set(),
  )
  const muxPort = mux.getPort()
  if (muxPort === undefined) {
    throw new Error('Failed to get mux proxy server port')
  }
  mux.unref()
  logForDebugging(`Mux proxy (HTTP+SOCKS) listening on localhost:${muxPort}`)
  return muxPort
}

// ============================================================================
// Public Module Functions (will be exported via namespace)
// ============================================================================

/**
 * Options of {@link initialize} that are the embedding program's to
 * set, not part of the configuration a user writes.
 */
export interface SandboxInitializeOptions {
  /**
   * Windows: profile exclusions this session may still be granted READ on.
   * Never applies to a write root or to a path above an exclusion.
   */
  dangerouslyAllowReadOfProfileExclusions?: readonly string[]
}

async function initialize(
  runtimeConfig: SandboxRuntimeConfig,
  sandboxAskCallback?: SandboxAskCallback,
  enableLogMonitor = false,
  options?: SandboxInitializeOptions,
): Promise<void> {
  try {
    await initializeSteps(
      runtimeConfig,
      sandboxAskCallback,
      enableLogMonitor,
      options,
    )
  } catch (error) {
    // Here, not at reset() or 'exit': a step can fail before the clean-up is
    // registered, and the next call makes a CA of its own.
    if (mitmCA) disposeMitmCASync(mitmCA)
    mitmCA = undefined
    throw error
  }
}

async function initializeSteps(
  runtimeConfig: SandboxRuntimeConfig,
  sandboxAskCallback: SandboxAskCallback | undefined,
  enableLogMonitor: boolean,
  options: SandboxInitializeOptions | undefined,
): Promise<void> {
  // Return if already initializing
  if (initializationPromise) {
    await initializationPromise
    return
  }

  // Store config for use by other functions
  config = runtimeConfig
  configInstalls++

  // Resolve parent/upstream proxy from config or HTTP_PROXY env before we
  // start our own listeners (which will later shadow those vars in the child).
  parentProxy = resolveParentProxy(runtimeConfig.network.parentProxy)
  if (parentProxy) {
    logForDebugging(
      `Parent proxy configured: http=${redactUrl(parentProxy.httpUrl)} ` +
        `https=${redactUrl(parentProxy.httpsUrl)}`,
    )
  }
  resolvedAddressGuard = createResolvedAddressGuard(runtimeConfig.network)

  // Load TLS-termination CA if configured. Throws on unreadable/non-PEM —
  // tlsTerminate is explicit opt-in, so a bad config is a hard error.
  if (runtimeConfig.network.tlsTerminate && runtimeConfig.network.mitmProxy) {
    throw new Error(
      'network.tlsTerminate and network.mitmProxy are mutually exclusive',
    )
  }
  // Before any CA, proxy or sandbox is set up: a runtime that cannot
  // terminate TLS in-process fails here, not on each tunnel.
  if (runtimeConfig.network.tlsTerminate) assertTlsTerminationSupported()
  // On Windows with tlsTerminate and no explicit caCertPath/caKeyPath,
  // defer CA creation until the Windows block below has resolved
  // srt-win and fetched user status — the persistent CA is
  // generated-if-absent under windowsStateDir()/ca and
  // trusted in the sandbox user's Root store, then loaded here.
  // Explicit paths (or non-Windows) go straight to createMitmCA.
  const tlsTerminate = runtimeConfig.network.tlsTerminate
  const useWindowsPersistentCa =
    getPlatform() === 'windows' &&
    tlsTerminate !== undefined &&
    !tlsTerminate.caCertPath &&
    !tlsTerminate.caKeyPath
  mitmCA =
    tlsTerminate && !useWindowsPersistentCa
      ? createMitmCA(tlsTerminate)
      : undefined

  // Check dependencies
  const deps = await checkDependenciesAsync()
  if (deps.errors.length > 0) {
    if (deps.reinstallRequired) {
      throw new WindowsSandboxError(
        'reinstall_required',
        deps.reinstallRequired,
      )
    }
    // The session asks for the other loopback mode than the installed
    // one: refused here, before anything is granted or launched.
    if (deps.loopbackMismatch) {
      throw new WindowsSandboxError(
        'wfp_loopback_mismatch',
        deps.loopbackMismatch,
      )
    }
    throw new Error(
      `Sandbox dependencies not available: ${deps.errors.join(', ')}`,
    )
  }

  // Start log monitor for macOS if enabled
  if (enableLogMonitor && getPlatform() === 'macos') {
    logMonitorShutdown = startMacOSSandboxLogMonitor(
      sandboxViolationStore.addViolation.bind(sandboxViolationStore),
      config.ignoreViolations,
      resolveCommandText,
    )
    logForDebugging('Started macOS sandbox log monitor')
  }
  if (enableLogMonitor && getPlatform() === 'linux') {
    // The monitor compares paths the kernel reported, so its lists are
    // expanded the way the wrapper expands them (getFsWriteConfig folds in
    // the default write paths and drops the patterns, so only names are left;
    // normalizePathForSandbox resolves `~`, relative spellings and symlinks),
    // plus the built-in write denies the wrapper always applies.
    // It does not reproduce the wrapper's existence and boundary-symlink
    // filters, nor the ripgrep scan for nested dangerous paths; and it still
    // reports writes bwrap permits through `--dev`, `--proc` and the tmpfs
    // over each read-denied directory. Started once, so both lists are fixed
    // at the cwd and configuration of this call, and at the disk as it is
    // now: an entry with glob characters that becomes the name of a path
    // later is applied by the next wrap and stays unknown here.
    const monitoredWrites = getFsWriteConfig()
    linuxMonitor = startLinuxSandboxViolationMonitor(
      sandboxViolationStore.addViolation.bind(sandboxViolationStore),
      {
        // apply-seccomp's observer reports every write-intent syscall
        // (allowed or not). Only paths bwrap would actually refuse — outside
        // allowWrite or inside a denyWrite carve-out — go to the store. With
        // the policy on, the default write paths are listed in full rather
        // than as getFsWriteConfig() narrowed them: a home directory it leaves
        // out because it is read-denied sits under that deny's writable
        // tmpfs, so a write there is permitted and is not a violation.
        allowWritePaths: [
          ...writeRootsOf(monitoredWrites),
          ...(config.filesystem.disabled ? [] : getDefaultWritePaths()),
        ].map(p => normalizePathForSandbox(p, { literal: true })),
        denyWritePaths: [
          ...monitoredWrites.denyWithinAllow.map(p =>
            normalizePathForSandbox(p, { literal: true }),
          ),
          ...(monitoredWrites.literalDenyWithinAllow ?? []).map(p =>
            normalizePathForSandbox(p, { literal: true }),
          ),
          // filesystem.disabled reaches the wrapper as `writeConfig ===
          // undefined`, which skips every bind and the built-in denies with
          // them, so the monitor must not judge by them either.
          ...(config.filesystem.disabled
            ? []
            : linuxGetCwdMandatoryDenyPaths(getAllowGitConfig())),
        ],
        ignoreViolations: config.ignoreViolations,
        resolveCommandText,
      },
    )
    // Don't block initialization on listen() — wrap-time checks
    // fs.existsSync(observeSocketPath) and degrades gracefully.
    void linuxMonitor.ready
    logForDebugging('Started Linux seccomp violation monitor')
  }

  // Register cleanup handlers first time
  registerCleanup()

  // Windows: validate provisioning + filesystem config BEFORE any
  // sandboxed child can be spawned. Doing this at initialize() (not
  // wrap-time) means the host gets a single actionable error before
  // any per-exec work happens, instead of exit-15 on every command.
  if (getPlatform() === 'windows') {
    // Resolve once (stats disk); captured module-level for wrap/reset.
    srtWinSpawn = resolveSrtWin(runtimeConfig.windows?.srtWin)
    const srtWin = srtWinSpawn
    const u = await getWindowsSandboxUserStatusAsync({ srtWin })
    if (!u.provisioned || !u.credPresent) {
      config = undefined
      throw new WindowsSandboxError(
        'not_provisioned',
        `Windows sandbox user is not provisioned (user=` +
          `${u.provisioned}, cred=${u.credPresent}). Run \`npx ` +
          `sandbox-runtime windows-install\` (one UAC prompt) to ` +
          `provision it.`,
      )
    }
    // srt-win refuses to launch on an install of another setup
    // version; checked before anything is granted.
    const staleSetup = windowsSetupVersionMismatch(
      u,
      runtimeConfig.windows?.sublayerGuid ??
        runtimeConfig.windows?.wfpSublayerGuid,
    )
    if (staleSetup) {
      config = undefined
      throw new WindowsSandboxError('reinstall_required', staleSetup)
    }
    // initialize() never writes or refreshes the profile read grant.
    windowsProfileReadWarnings = []
    let profileRead: 'granted' | 'absent' = 'absent'
    let profileExclusions: Parameters<
      typeof windowsProfileExclusionConflicts
    >[1] = { exclusions: [], ungrantedOnly: [] }
    try {
      // Required whether or not a profile grant is recorded.
      const missing = missingWindowsSrtWinCapability(u.capabilities)
      if (missing !== undefined) {
        throw windowsSrtWinOutdatedError(missing, WINDOWS_CAPABILITIES_WHY)
      }
      windowsCapableSrtWin.add(windowsSrtWinIdentity(srtWin))
      if (u.profileGrant) {
        const grant = await getWindowsProfileReadStatusAsync({ srtWin })
        if (grant.state !== 'none' && grant.state !== 'current') {
          throw new WindowsSandboxError(
            'profile_grant_outdated',
            `The recorded read grant on your user profile cannot be used ` +
              `(${grant.state}${grant.reason ? `: ${grant.reason}` : ''}). ` +
              `Call grantWindowsProfileRead() (\`srt-win profile grant\`, ` +
              `or \`npx sandbox-runtime windows-install\` again) as the ` +
              `user who starts sessions to bring it up to date, or ` +
              `forgetWindowsProfileRead() (\`srt-win profile forget\`) to ` +
              `run without reading the profile. initialize() does neither ` +
              `itself.`,
          )
        }
        if (grant.state === 'current') {
          profileExclusions = grant
          profileRead = 'granted'
          windowsProfileReadWarnings = windowsProfileReadWarningsOf(grant)
          for (const w of windowsProfileReadWarnings) {
            logForDebugging(`[Sandbox Windows] ${w.message}`, { level: 'warn' })
          }
        }
      }
      // Stored once known: `absent` is never reported for a granted session.
      windowsProfileRead = profileRead
      if (profileRead === 'absent') {
        logForDebugging(
          `[Sandbox Windows] no profile read grant: the user profile is ` +
            `not readable to sandboxed commands in this session`,
        )
      }
    } catch (e) {
      windowsProfileRead = undefined
      config = undefined
      throw e
    }
    // Behavioral proof the WFP egress fence is active for the
    // sandbox user — BFE enumeration (`wfp status`) is admin-gated,
    // so this is the non-elevated readiness check. Fails closed: a
    // stale install (user provisioned but filters since removed)
    // throws here instead of running every exec with full egress.
    // After the user-status check so the not-provisioned message is
    // the actionable one. Once per process — the fence is install-
    // scoped, not session-scoped.
    // The probe runs below, after the grant: the capability SIDs of
    // the write roots exist only once the roots are granted.
    // Persistent-CA branch (see the deferral comment above).
    // `ensurePersistentWindowsCa` reconciles the registry thumb
    // itself (so initialize() after uninstall→reinstall repairs
    // trust) and may make `u.caCertThumb` stale — hence the
    // explicit-path thumb check below skips this branch.
    if (useWindowsPersistentCa && tlsTerminate) {
      try {
        const p = await ensurePersistentWindowsCa({ status: u, srtWin })
        mitmCA = createMitmCA({
          caCertPem: p.certPem,
          caKeyPem: p.keyPem,
          caCertPath: p.certPath,
          caKeyPath: p.keyPath,
          extraCaCertPaths: tlsTerminate.extraCaCertPaths,
        })
      } catch (e) {
        config = undefined
        throw e
      }
    }
    // Filesystem grants/denies — additive sandbox-user ACEs.
    try {
      let maskedFiles: string[] = []
      try {
        maskedFiles = windowsMaskedFileDenies(
          getCredentialRestrictions(
            runtimeConfig.credentials,
            runtimeConfig.network.allowedDomains,
          ),
        )
      } catch {
        // onExtractNoMatch: "error" is thrown by every wrap, so nothing runs.
      }
      const acc = computeWindowsFsAccessSet(runtimeConfig, maskedFiles)
      // No path the session grants, in any form, may reach what the
      // profile read grant excludes.
      const ownRead = mitmCA ? [dirname(mitmCA.trustBundlePath)] : []
      const override = options?.dangerouslyAllowReadOfProfileExclusions ?? []
      const refused = [
        ...windowsProfileExclusionConflicts(acc.grantRead, profileExclusions, {
          override,
        }),
        ...windowsProfileExclusionConflicts(ownRead, profileExclusions),
        ...windowsProfileExclusionConflicts(acc.grantWrite, profileExclusions, {
          write: true,
        }),
      ]
      if (refused.length > 0) {
        const describe = (c: (typeof refused)[number]): string => {
          const list = c.access === 'write' ? 'allowWrite' : 'allowRead'
          const what =
            c.kind === 'ungranted-only'
              ? (c.relation === 'equal' ? `is` : `contains`) +
                ` ${c.exclusion}, which is not granted as a whole (grant ` +
                `a directory inside it instead)`
              : c.relation === 'equal'
                ? `is the excluded ${c.exclusion}`
                : c.relation === 'inside'
                  ? `lies inside the excluded ${c.exclusion}`
                  : c.unexamined !== undefined
                    ? `may contain the excluded ${c.exclusion}: ` +
                      `${c.unexamined}, and a path is granted only once ` +
                      `it has been looked at`
                    : `contains the excluded ${c.exclusion}`
          return (
            `${list} ${c.path} ${what}` +
            (c.access === 'write' && c.relation === 'above'
              ? `: a write grant on it is kept and inherited, so that ` +
                `path would be writable and readable if it is ever ` +
                `created again — choose a narrower working directory`
              : '')
          )
        }
        throw new WindowsSandboxError(
          'profile_exclusion_read_grant',
          `The session would grant a path that reaches one excluded from ` +
            `reads of your user profile: ` +
            refused.map(describe).join('; ') +
            `. Nothing was granted. Remove the entry, or name a path that ` +
            `neither is nor contains an excluded one.`,
        )
      }
      // A read deny is passed once: `srt-win` adds the recorded profile paths it
      // covers. The CA trust bundle's directory rides the session's read grants.
      const grantRead = mitmCA
        ? [...acc.grantRead, dirname(mitmCA.trustBundlePath)]
        : acc.grantRead
      // `u` was fetched once above for the provisioning gate; the
      // same status carries the SID — don't re-spawn `srt-win user
      // status` here.
      if (!u.sid) {
        throw new Error(
          'sandbox user SID missing from `srt-win user status` ' +
            '(provisioned but in an inconsistent state)',
        )
      }
      const sb = u.sid
      // Record module-level state BEFORE the first acl call so the
      // catch's best-effort revoke/restore can address whatever
      // partially landed.
      windowsFsSbUserSid = sb
      // One call, always made: it also records this process as a
      // session. Write roots are kept at reset(); a failure throws.
      await grantWindowsAclPersistent({
        sandboxUserSid: sb,
        read: grantRead,
        write: acc.grantWrite,
        denyRead: acc.denyRead,
        denyWrite: acc.denyWrite,
        allowProfileExclusions: override,
        srtWin,
      })
      // Gates running revoke/restore at reset(): every session is
      // recorded with srt-win, whatever it was given. Set before the
      // probe, so that a reset() during it releases what was granted.
      windowsFsStampedSet = acc
      logForDebugging(
        `[Sandbox Windows] fs applied: ` +
          `${acc.grantWrite.length} grantWrite, ` +
          `${grantRead.length} grantRead, ` +
          `${acc.denyRead.length} denyRead, ` +
          `${acc.denyWrite.length} denyWrite`,
      )
      // The egress probe, under the token this session's commands
      // get; anything but a refused connect throws, and so does an
      // install whose loopback mode is not this session's. Remembered
      // per account and loopback mode.
      const allowLoopback = runtimeConfig.network?.allowLocalBinding === true
      if (
        windowsWfpVerifiedFor !== sb ||
        windowsWfpVerifiedLoopback !== allowLoopback
      ) {
        await verifyWindowsWfpEgress({
          proxyPortRange: runtimeConfig.windows?.proxyPortRange,
          writeRoots: acc.grantWrite,
          allowLoopback,
          sublayerGuid:
            runtimeConfig.windows?.sublayerGuid ??
            runtimeConfig.windows?.wfpSublayerGuid,
          sandboxUser: runtimeConfig.windows?.sandboxUser,
          srtWin,
        })
        windowsWfpVerifiedFor = sb
        windowsWfpVerifiedLoopback = allowLoopback
      }
      windowsFsRawInputs = rawWindowsFsInputs(runtimeConfig)
    } catch (e) {
      // Best-effort release of whatever WAS applied before the
      // failure (exit-2 partial stamps/grants the resolvable
      // inputs; harmless if nothing was — no holds for this PID).
      if (windowsFsSbUserSid) {
        releaseWindowsSessionAcls(windowsFsSbUserSid, srtWin)
      }
      windowsFsSbUserSid = undefined
      windowsFsStampedSet = undefined
      windowsProfileRead = undefined
      config = undefined
      throw e
    }
  }

  // Initialize network infrastructure
  initializationPromise = (async () => {
    try {
      // On Windows the WFP loopback permit covers a fixed port
      // range, so the proxies must bind inside it. Other platforms
      // bake the actual ephemeral port into the sandbox profile, so
      // they keep using port 0.
      const portRange: readonly [number, number] | undefined =
        getPlatform() === 'windows'
          ? (config.windows?.proxyPortRange ?? DEFAULT_WINDOWS_PROXY_PORT_RANGE)
          : undefined

      // The auth token is only set when this process owns the proxy; an
      // external proxy (config.network.httpProxyPort) handles its own auth,
      // and embedding our token in its URL would be wrong.
      proxyAuthToken =
        config.network.httpProxyPort !== undefined
          ? undefined
          : randomBytes(16).toString('hex')

      // The mux front-end serves both protocols on one port. Each side's
      // reported port is the external override if configured, else the mux
      // port — so the public config.network.{http,socks}ProxyPort contract
      // is unchanged. The mux is skipped only when BOTH are external.
      const needLocalProxy =
        config.network.httpProxyPort === undefined ||
        config.network.socksProxyPort === undefined
      const muxPort = needLocalProxy
        ? await startMuxProxyServer(sandboxAskCallback, portRange)
        : undefined
      const httpProxyPort = config.network.httpProxyPort ?? muxPort!
      const socksProxyPort = config.network.socksProxyPort ?? muxPort!
      // JVMs read neither HTTPS_PROXY nor its credential; the agent bridges
      // both. Resolved once here, advertised via JAVA_TOOL_OPTIONS per command.
      // Async: the global-npm fallback spawns `npm root -g`.
      javaAgentJarPath =
        (await getJavaProxyAgentJarPathAsync(config.javaAgentJarPath)) ??
        undefined
      // Leaves are minted lazily per-CONNECT (after this point), so setting
      // the CDP URL now means every leaf carries it. See MitmCA.crlUrl.
      // Windows-only: on Linux the child runs under bwrap --unshare-net and
      // reaches the proxy via a socat bridge on a fixed netns port, so a
      // host-namespace mux port would be unreachable — worse than no CDP,
      // since a Schannel-analog client (Java, OpenSSL with CRL_CHECK) then
      // hard-fails "CRL fetch error" instead of soft-passing "no CDP". macOS
      // has no in-tree Schannel-analog client. Also gated on `muxPort`: an
      // external `network.httpProxyPort` doesn't answer /srt.crl.
      if (mitmCA && muxPort !== undefined && getPlatform() === 'windows') {
        mitmCA.crlUrl = `http://127.0.0.1:${muxPort}${CRL_PATH}`
      }
      if (config.network.httpProxyPort !== undefined) {
        logForDebugging(`Using external HTTP proxy on port ${httpProxyPort}`)
      }
      if (config.network.socksProxyPort !== undefined) {
        logForDebugging(`Using external SOCKS proxy on port ${socksProxyPort}`)
      }

      // Initialize platform-specific infrastructure
      let linuxBridge: LinuxNetworkBridgeContext | undefined
      if (getPlatform() === 'linux') {
        linuxBridge = await initializeLinuxNetworkBridge(
          httpProxyPort,
          socksProxyPort,
          config.socatPath,
        )
      }

      const context: HostNetworkManagerContext = {
        httpProxyPort,
        socksProxyPort,
        linuxBridge,
      }
      managerContext = context
      logForDebugging('Network infrastructure initialized')
      return context
    } catch (error) {
      // Clear state on error so initialization can be retried
      initializationPromise = undefined
      managerContext = undefined
      reset().catch(e => {
        logForDebugging(`Cleanup failed in initializationPromise ${e}`, {
          level: 'error',
        })
      })
      throw error
    }
  })()

  await initializationPromise
}

function isSupportedPlatform(): boolean {
  const platform = getPlatform()
  if (platform === 'linux') {
    // WSL1 doesn't support bubblewrap
    return getWslVersion() !== '1'
  }
  return platform === 'macos' || platform === 'windows'
}

function isSandboxingEnabled(): boolean {
  // Sandboxing is enabled if config has been set (via initialize())
  return config !== undefined
}

/**
 * Platform-independent part of the dependency check. Returns either
 * a finished result (POSIX, unsupported platform, or a Windows
 * srt-win resolution failure) or the inputs for the Windows probe —
 * the only platform where the sync and async variants differ.
 */
function checkDependenciesCommon(ripgrepConfig?: RipgrepConfig):
  | { done: SandboxDependencyCheck }
  | {
      windows: {
        sublayerGuid?: string
        proxyPortRange?: readonly [number, number]
        sandboxUser?: string
        srtWin: SrtWinSpawn
        allowLoopback?: boolean
      }
    } {
  if (!isSupportedPlatform()) {
    return { done: { errors: ['Unsupported platform'], warnings: [] } }
  }

  const errors: string[] = []
  const warnings: string[] = []

  const platform = getPlatform()
  if (platform === 'linux') {
    // ripgrep is Linux-only: it's used by linuxGetMandatoryDenyPaths() to
    // expand glob deny-patterns to concrete paths for bwrap. macOS seatbelt
    // profiles take regex patterns directly, so rg is never invoked there.
    const rgToCheck = ripgrepConfig ?? config?.ripgrep ?? { command: 'rg' }
    if (whichSync(rgToCheck.command) === null) {
      errors.push(`ripgrep (${rgToCheck.command}) not found`)
    }

    const linuxDeps = checkLinuxDependencies({
      seccompConfig: config?.seccomp,
      bwrapPath: config?.bwrapPath,
      socatPath: config?.socatPath,
    })
    errors.push(...linuxDeps.errors)
    warnings.push(...linuxDeps.warnings)
  } else if (platform === 'windows') {
    let srtWin: SrtWinSpawn
    try {
      srtWin = resolveSrtWin(config?.windows?.srtWin)
    } catch (e) {
      errors.push((e as Error).message)
      return { done: { errors, warnings } }
    }
    return {
      windows: {
        sublayerGuid:
          config?.windows?.sublayerGuid ?? config?.windows?.wfpSublayerGuid,
        proxyPortRange: config?.windows?.proxyPortRange,
        sandboxUser: config?.windows?.sandboxUser,
        srtWin,
        // With a config to go by, an install whose loopback mode is
        // not the configured one is an error.
        ...(config && {
          allowLoopback: config.network?.allowLocalBinding === true,
        }),
      },
    }
  }

  // The library itself writable from inside the sandbox: see own-files.ts.
  if (!config?.filesystem.disabled) {
    try {
      const ownInstall = ownInstallWarning(writeRootsOf(getFsWriteConfig()))
      if (ownInstall !== undefined) warnings.push(ownInstall)
    } catch {
      // It only advises: whoever enforces a config says what is wrong with it.
    }
  }

  return { done: { errors, warnings } }
}

/**
 * Check sandbox dependencies for the current platform
 * @param ripgrepConfig - Ripgrep command to check. If not provided, uses config from initialization or defaults to 'rg'
 * @returns { warnings, errors } - errors mean sandbox cannot run, warnings mean degraded functionality
 */
function checkDependencies(
  ripgrepConfig?: RipgrepConfig,
): SandboxDependencyCheck {
  const common = checkDependenciesCommon(ripgrepConfig)
  if ('done' in common) return common.done
  return checkWindowsDependencies(common.windows)
}

/**
 * Async variant of {@link checkDependencies} — same result for the
 * same underlying state. On Windows the srt-win probes run via
 * `spawn` (never blocking the event loop) and concurrently; on other
 * platforms the checks are native and this simply wraps the sync
 * result. Windows callers should prefer this variant.
 */
async function checkDependenciesAsync(
  ripgrepConfig?: RipgrepConfig,
): Promise<SandboxDependencyCheck> {
  // Linux: resolve apply-seccomp first so its global-npm fallback
  // (`npm root -g`) runs off the event loop; the sync check below then
  // hits the shared path cache.
  if (getPlatform() === 'linux' && !config?.seccomp?.argv0) {
    await getApplySeccompBinaryPathAsync(config?.seccomp?.applyPath)
  }
  const common = checkDependenciesCommon(ripgrepConfig)
  if ('done' in common) return common.done
  return checkWindowsDependenciesAsync(common.windows)
}

/**
 * Build the read-deny / env-unset / env-set maps implied by the
 * `credentials` config.
 *
 * Only explicitly declared sources are restricted: `mode: 'deny'` file
 * entries join the read-deny set, `mode: 'deny'` env vars are unset, and
 * `mode: 'mask'` env vars are set to a fake value (whole-value sentinel,
 * the real value with extract-captured spans swapped for sentinels, or a
 * JWT-shaped fake for `decode: 'jwt'` / `maskClaims` entries) registered
 * in {@link sentinelRegistry} — see {@link buildMaskedEnvVars}.
 */
function getCredentialRestrictions(
  credentials: CredentialsConfig | undefined,
  allowedDomains: readonly string[] | undefined,
): CredentialRestrictionConfig {
  if (!credentials) {
    return {
      denyReadPaths: [],
      unsetEnvVars: [],
      setEnvVars: {},
      maskedFileBinds: [],
      maskedFileStoreDir: undefined,
      degradeToDenyPaths: [],
    }
  }

  const denyReadPaths = getCredentialDenyReadPaths(credentials)

  // Default injectHosts (= allowedDomains) is host-scoped: drop any
  // `:port` suffixes, otherwise the sentinel would carry an entry no bare
  // destination host can ever match and the credential would never inject.
  const defaultInjectHosts = [
    ...new Set((allowedDomains ?? []).map(stripDomainPatternPort)),
  ]

  const unsetEnvVars: string[] = []
  for (const v of credentials.envVars ?? []) {
    if (v.mode === 'deny') unsetEnvVars.push(v.name)
  }

  // Masked env vars: read the real value from the host environment,
  // register sentinel(s), and set the variable to the fake value inside
  // the sandbox. degradeToUnsetNames carries variables whose extract
  // pattern matched nothing with onExtractNoMatch: "deny" — merged into
  // unsetEnvVars below so the value is withheld rather than exposed.
  const { setEnvVars, degradeToUnsetNames } = buildMaskedEnvVars(
    credentials.envVars ?? [],
    defaultInjectHosts,
    sentinelRegistry,
  )
  unsetEnvVars.push(...degradeToUnsetNames)

  // Link masked AWS credentials into pairs so the proxy can re-sign
  // SigV4 requests (the signature is derived from the secret; header
  // substitution alone cannot fix it).
  registerAwsPairs(
    credentials.envVars ?? [],
    credentials.awsPairs,
    defaultInjectHosts,
    setEnvVars,
    awsPairRegistry,
  )

  // Masked files: read the real bytes on the host, register a sentinel,
  // write it to a fake file in the manager-owned temp dir. Missing/unreadable
  // entries are skipped (same posture as an unset masked env var).
  // degradeToDenyPaths carries paths whose extract pattern matched
  // nothing with onExtractNoMatch: "deny" — merged into denyReadPaths
  // below so both the read-deny config and the platform builders see
  // them, and carried separately so they stay literal on the way there.
  const files = credentials.files ?? []
  const { binds: maskedFileBinds, degradeToDenyPaths } = buildMaskedFileBinds(
    files,
    defaultInjectHosts,
    sentinelRegistry,
    maskedFileStore,
  )

  return {
    denyReadPaths: [...new Set([...denyReadPaths, ...degradeToDenyPaths])],
    unsetEnvVars: [...new Set(unsetEnvVars)],
    setEnvVars,
    maskedFileBinds,
    maskedFileStoreDir: maskedFileStore.dirPath,
    degradeToDenyPaths,
  }
}

/**
 * Pure (side-effect-free) chokepoint for credential file-deny
 * paths — `credentials.files` entries with `mode: 'deny'`. Any
 * code that needs the credential→denyRead contribution routes
 * through here so a comparison predicate can read it without
 * touching {@link sentinelRegistry}.
 */
function getCredentialDenyReadPaths(
  credentials: CredentialsConfig | undefined,
): string[] {
  const files = credentials?.files ?? []
  return [...new Set(files.filter(f => f.mode === 'deny').map(f => f.path))]
}

/**
 * The default write paths under a filesystem policy's read rules, for
 * getFsWriteConfig() and wrapWithSandbox() alike. Fed the entries as
 * configured, through the pure {@link getCredentialDenyReadPaths}: no glob
 * expansion and no credential masking, because getFsWriteConfig() is a
 * getter callers reach from permission checks and render paths. A mask entry
 * that degrades to a deny is a file and cannot cover a directory, so
 * leaving those out changes nothing. An entry with glob characters that is
 * also the name of a path counts as that name too. The credential denies are
 * judged apart, with no `allowRead`: they have no exceptions.
 */
function defaultWritePathsUnder({
  denyRead,
  allowRead,
  credentials,
}: {
  denyRead: readonly FilesystemPathEntry[]
  allowRead: readonly FilesystemPathEntry[] | undefined
  credentials: CredentialsConfig | undefined
}): string[] {
  const underCredentialDenies = getDefaultWritePaths(
    readRulesOf([], undefined, getCredentialDenyReadPaths(credentials)),
  )
  return getDefaultWritePaths(readRulesOf(denyRead, allowRead, [])).filter(p =>
    underCredentialDenies.includes(p),
  )
}

/**
 * The explicit `filesystem.denyRead` and the credential-derived deny paths,
 * each through {@link resolveReadPathEntries}. The single source of "what
 * files does this config want read-denied" on macOS and Linux, so a new
 * credential kind that contributes deny paths reaches both. The credential
 * ones are also returned apart, for the precedence the backends give them.
 */
function* resolveReadDenies(
  denyRead: readonly FilesystemPathEntry[] = [],
  credentialRestrictions: CredentialRestrictionConfig,
  expandGlob: (pattern: string, anchor?: string) => Steps<string[]>,
): Steps<Pick<FsReadRestrictionConfig, 'denyOnly' | 'credentialDenyOnly'>> {
  const listed = yield* resolveReadPathEntries('deny', denyRead, expandGlob)
  const credentialDenyOnly = yield* resolveReadPathEntries(
    'deny',
    credentialRestrictions.denyReadPaths,
    expandGlob,
    credentialRestrictions.degradeToDenyPaths,
  )
  return {
    denyOnly: [...new Set([...listed, ...credentialDenyOnly])],
    ...(credentialDenyOnly.length > 0 && { credentialDenyOnly }),
  }
}

/**
 * Strip a trailing `/**` from each read-path entry and, on Linux, replace
 * any remaining glob with what `expandGlob` returns for it (bubblewrap takes
 * concrete paths only). Other platforms match globs natively.
 * On Linux the entry's other readings are added (see `withOtherReadings`);
 * elsewhere the backend decides them. Entries the caller marked literal are
 * not in the result: they travel in the `literal…` lists.
 *
 * `literalPaths` are the ones the library resolved itself (a masked
 * credential file that degraded to deny) — each names one file on disk, so
 * it is passed through whatever characters it contains. Expanded as a
 * pattern, a name holding `[` matches nothing and the deny is lost.
 *
 * Each path once, where it first came up: every `**` pattern over one base
 * returns the directories it could not list, and the Linux wrapper looks at
 * every entry it is given.
 */
function* resolveReadPathEntries(
  kind: PathListKind,
  paths: readonly FilesystemPathEntry[],
  expandGlob: (pattern: string, anchor?: string) => Steps<string[]>,
  literalPaths: readonly string[] = [],
): Steps<string[]> {
  const literal = new Set(literalPaths)
  const resolved = new Set<string>()
  for (const p of spelledOf(paths)) {
    const stripped = removeTrailingGlobSuffix(p)
    if (
      getPlatform() === 'linux' &&
      !literal.has(p) &&
      containsGlobChars(stripped)
    ) {
      for (const found of yield* withOtherReadings(
        p,
        stripped,
        kind,
        expandGlob,
      )) {
        resolved.add(found)
      }
    } else {
      resolved.add(stripped)
    }
  }
  return [...resolved]
}

/**
 * Strip a trailing `/**` and drop what is still a glob on Linux: bwrap needs
 * real paths. macOS subpath matching is recursive, so the strip is harmless
 * there and the filter never fires.
 * A glob that is also the name of a path that exists is kept, as that name.
 * Marked entries are not in the result, as in {@link resolveReadPathEntries}.
 */
function stripWriteGlobs(
  kind: PathListKind,
  paths: readonly FilesystemPathEntry[],
): string[] {
  return spelledOf(paths)
    .map(p => removeTrailingGlobSuffix(p))
    .filter(p => {
      if (
        getPlatform() === 'linux' &&
        containsGlobChars(p) &&
        !hasNameReading(p, kind)
      ) {
        logForDebugging(`[Sandbox] Skipping glob write pattern on Linux: ${p}`)
        return false
      }
      return true
    })
}

function* expandAllowReadGlob(
  pattern: string,
  anchor?: string,
): Steps<string[]> {
  const expanded = (yield* walkGlobPatternSteps(pattern, { anchor })).matches
  logForDebugging(
    `[Sandbox] Expanded allowRead glob pattern "${pattern}" to ${expanded.length} paths on Linux`,
  )
  return expanded
}

/**
 * The read policy of the initialized config, for inspection and display.
 * On Linux, denyRead globs are collapsed to covering directory mounts against
 * this config's allowRead and {@link getFsWriteConfig}'s write roots, so
 * `denyOnly` is only sound alongside that write config and must not be handed
 * to wrapCommandWithSandboxLinux with a different one. Marked entries are
 * in the `literal…` lists, as spelled: pass the object on whole.
 */
function getFsReadConfig(): FsReadRestrictionConfig {
  if (!config || config.filesystem.disabled) {
    return { denyOnly: [], allowWithinDeny: [] }
  }

  // Credential deny paths are unioned with the caller's denyRead — never
  // replacing it — so explicit filesystem restrictions always survive.
  const credentialRestrictions = getCredentialRestrictions(
    config.credentials,
    config.network.allowedDomains,
  )
  // allowRead (re-allow within denied regions) is resolved first: the
  // denyRead glob expansion collapses against it.
  const allowPaths = finish(
    resolveReadPathEntries(
      'allow',
      config.filesystem.allowRead ?? [],
      expandAllowReadGlob,
    ),
  )
  const reExposedPaths = reExposedBy(
    allowPaths,
    config.filesystem.allowRead,
    getFsWriteConfig(),
  )
  const unlistableDenyDirs = new Set<string>()
  const listings: GlobWalkListings = new Map()
  const denyPaths = finish(
    resolveReadDenies(
      config.filesystem.denyRead,
      credentialRestrictions,
      (pattern, anchor) =>
        expandReadDenyGlobLinuxSteps(
          pattern,
          reExposedPaths,
          unlistableDenyDirs,
          { anchor, listings },
        ),
    ),
  )

  return {
    ...denyPaths,
    allowWithinDeny: allowPaths,
    unlistableDenyDirs: [...unlistableDenyDirs],
    ...literalReadLists(
      config.filesystem.denyRead,
      config.filesystem.allowRead,
    ),
  }
}

function getFsWriteConfig(): FsWriteRestrictionConfig {
  if (!config) {
    return { allowOnly: getDefaultWritePaths(), denyWithinAllow: [] }
  }

  if (config.filesystem.disabled) {
    return { allowOnly: ['/'], denyWithinAllow: [] }
  }

  const allowPaths = stripWriteGlobs('allow', config.filesystem.allowWrite)
  const denyPaths = stripWriteGlobs('deny', config.filesystem.denyWrite)

  const allowOnly = [
    ...defaultWritePathsUnder({
      denyRead: config.filesystem.denyRead,
      allowRead: config.filesystem.allowRead,
      credentials: config.credentials,
    }),
    ...allowPaths,
  ]

  return {
    allowOnly,
    denyWithinAllow: denyPaths,
    ...literalWriteLists(
      config.filesystem.allowWrite,
      config.filesystem.denyWrite,
    ),
  }
}

/**
 * Build the Windows file-access set (deny stamps + sandbox-user
 * grants) from `runtimeConfig`. Globs are expanded to concrete
 * paths (point-in-time — a path appearing after this returns is NOT
 * covered). Directory targets are accepted (the `(OI)(CI)` ACEs
 * cover the subtree).
 *
 * The sandbox user has no inherent rights on real-user-owned files,
 * so `allowWrite` (the working-tree roots) becomes a per-session
 * `MODIFY_NO_FDC` ALLOW ACE for `<sb-SID>`, `allowRead` a
 * `READ|EXECUTE` ALLOW ACE, and `denyRead`/`denyWrite` become an
 * explicit DENY ACE for `<sb-SID>` on the target plus a
 * `(OI)(CI) FILE_DELETE_CHILD` DENY on its parent.
 * {@link rankWindowsFsAccess} ranks the lists against each other.
 *
 * `maskedFiles`: see {@link windowsMaskedFileDenies}.
 */
function computeWindowsFsAccessSet(
  c: SandboxRuntimeConfig,
  maskedFiles: readonly string[],
): WindowsFsAccessSet {
  const fs = c.filesystem
  // filesystem.disabled bypasses ALL filesystem rule generation —
  // same as the macOS/Linux wrapWithSandbox path (readConfig /
  // writeConfig left undefined). On Windows this means no grant, and
  // no stamp but a masked file's; credential FILE denies are dropped
  // along with the rest (credential ENV: mode:'deny' is structural
  // under the fresh srt-sandbox env; mode:'mask' sentinels are passed
  // via the --env overlay).
  if (fs?.disabled) {
    return {
      grantRead: [],
      grantWrite: [],
      denyRead: [...maskedFiles],
      denyWrite: [],
    }
  }
  const expand = expandWindowsFsPaths
  // `mode: 'deny'` — non-existent literals reach srt-win, which
  // creates a placeholder chain and stamps it (deny lands on the
  // exact target path). `mode: 'grant'` drops them (a grant on
  // nothing is meaningless).
  return rankWindowsFsAccess({
    allowRead: expand(fs?.allowRead ?? [], { mode: 'grant' }),
    allowWrite: expand(fs?.allowWrite ?? [], { mode: 'grant' }),
    denyRead: expand(fs?.denyRead ?? [], { mode: 'deny' }),
    denyWrite: expand(fs?.denyWrite ?? [], { mode: 'deny' }),
    credentialDeny: [
      ...expand(getCredentialDenyReadPaths(c.credentials), { mode: 'deny' }),
      ...maskedFiles,
    ],
  })
}

/**
 * The `mode: "mask"` files, as credential denies: an ACL cannot redirect a
 * read, so on Windows, as on macOS, a masked file is unreadable. Each is a
 * file the library opened, so none is expanded, and `filesystem.disabled`
 * leaves them in force, as it leaves the masks on the other platforms.
 */
function windowsMaskedFileDenies(
  credentialRestrictions: CredentialRestrictionConfig,
): string[] {
  return [
    ...credentialRestrictions.maskedFileBinds.map(b => b.realPath),
    ...credentialRestrictions.degradeToDenyPaths,
  ]
}

/**
 * Snapshot the raw config fields that feed
 * {@link computeWindowsFsAccessSet}. Used by updateConfig() to
 * short-circuit the resolved-set diff (which re-runs glob
 * expansion) when nothing relevant changed.
 */
function rawWindowsFsInputs(c: SandboxRuntimeConfig) {
  // Keyed exactly on what {@link computeWindowsFsAccessSet} reads of
  // the config. The masked files are not session-wide: each wrap
  // denies the ones the session has not stamped.
  // `network.allowedDomains` does NOT feed file-deny (only mask
  // injectHosts), so a network-only updateConfig hits the cache.
  return {
    disabled: c.filesystem.disabled ?? false,
    denyRead: [...c.filesystem.denyRead],
    denyWrite: [...c.filesystem.denyWrite],
    allowRead: [...(c.filesystem.allowRead ?? [])],
    allowWrite: [...c.filesystem.allowWrite],
    credFiles: getCredentialDenyReadPaths(c.credentials),
  }
}

function sameRawWindowsFsInputs(
  a: ReturnType<typeof rawWindowsFsInputs>,
  b: ReturnType<typeof rawWindowsFsInputs>,
): boolean {
  return (
    a.disabled === b.disabled &&
    samePathEntries(a.denyRead, b.denyRead) &&
    samePathEntries(a.denyWrite, b.denyWrite) &&
    samePathEntries(a.allowRead, b.allowRead) &&
    samePathEntries(a.allowWrite, b.allowWrite) &&
    samePathEntries(a.credFiles, b.credFiles)
  )
}

/**
 * True when `newConfig`'s file-deny inputs match what was
 * stamped at initialize(). Compares raw inputs only (cheap,
 * order-insensitive); never re-expands globs — updateConfig is
 * warn-only on Windows and the resolved set wouldn't be used.
 */
function sameWindowsStampSet(newConfig: SandboxRuntimeConfig): boolean {
  return (
    windowsFsRawInputs !== undefined &&
    sameRawWindowsFsInputs(windowsFsRawInputs, rawWindowsFsInputs(newConfig))
  )
}

/** Why a loopback mode other than the session's verified one is refused. */
function windowsLoopbackModeChanged(
  wanted: boolean,
  verified: boolean,
): string {
  const mode = (open: boolean) => (open ? 'open' : 'closed')
  return (
    `network.allowLocalBinding asks for loopback ${mode(wanted)}, but this ` +
    `session verified the network fence with loopback ${mode(verified)}. ` +
    `On Windows the loopback mode is fixed by the install and checked at ` +
    `initialize(): it cannot change for one command or through ` +
    `updateConfig(). Call reset() then initialize() with the new value; ` +
    `the installed mode must match it.`
  )
}

function getNetworkRestrictionConfig(): NetworkRestrictionConfig {
  if (!config) {
    return {}
  }

  // Preserve an explicitly-empty allowlist: consumers need to distinguish
  // "no network restriction configured" (absent) from "allowlist configured
  // with zero entries" (block-all / ask-only). Stripping the empty array
  // made a host app's restriction-status UI report an airgapped config as
  // unrestricted. deniedHosts keeps the strip — an empty denylist and an
  // absent one are semantically identical.
  const allowedHosts = config.network.allowedDomains
  const deniedHosts = config.network.deniedDomains

  return {
    allowedHosts,
    ...(deniedHosts.length > 0 && { deniedHosts }),
  }
}

function getAllowUnixSockets(): string[] | undefined {
  return config?.network?.allowUnixSockets
}

function getAllowAllUnixSockets(): boolean | undefined {
  return config?.network?.allowAllUnixSockets
}

function getAllowLocalBinding(): boolean | undefined {
  return config?.network?.allowLocalBinding
}

function getAllowMachLookup(): string[] | undefined {
  return config?.network?.allowMachLookup
}

function getIgnoreViolations(): Record<string, string[]> | undefined {
  return config?.ignoreViolations
}

function getEnableWeakerNestedSandbox(): boolean | undefined {
  return config?.enableWeakerNestedSandbox
}

function getEnableWeakerNetworkIsolation(): boolean | undefined {
  return config?.enableWeakerNetworkIsolation
}

function getAllowAppleEvents(): boolean | undefined {
  return config?.allowAppleEvents
}

function getRipgrepConfig(): RipgrepConfig {
  return config?.ripgrep ?? { command: 'rg' }
}

function getMandatoryDenySearchDepth(): number {
  return config?.mandatoryDenySearchDepth ?? 3
}

function getAllowGitConfig(): boolean {
  return config?.filesystem?.allowGitConfig ?? false
}

/**
 * Union of session-level and per-call `git.safeDirectories`. Marks
 * paths as `safe.directory` (dubious-ownership bypass) WITHOUT
 * touching the write grant — the repo top-level for a subdirectory
 * launch must NOT go in `filesystem.allowWrite`.
 */
function getGitSafeDirectories(
  customConfig?: Partial<SandboxRuntimeConfig>,
): string[] {
  return [
    ...(config?.git?.safeDirectories ?? []),
    ...(customConfig?.git?.safeDirectories ?? []),
  ]
}

function getSeccompConfig(): SeccompConfig | undefined {
  return config?.seccomp
}

function getProxyAuthToken(): string | undefined {
  return proxyAuthToken
}

function getProxyPort(): number | undefined {
  return managerContext?.httpProxyPort
}

function getSocksProxyPort(): number | undefined {
  return managerContext?.socksProxyPort
}

function getLinuxHttpSocketPath(): string | undefined {
  return managerContext?.linuxBridge?.httpSocketPath
}

function getLinuxSocksSocketPath(): string | undefined {
  return managerContext?.linuxBridge?.socksSocketPath
}

/**
 * Wait for network initialization to complete if already in progress
 * Returns true if initialized successfully, false otherwise
 */
async function waitForNetworkInitialization(): Promise<boolean> {
  if (!config) {
    return false
  }
  if (initializationPromise) {
    try {
      await initializationPromise
      return true
    } catch {
      return false
    }
  }
  return managerContext !== undefined
}

/**
 * Per-invocation options for {@link wrapWithSandbox} /
 * {@link wrapWithSandboxArgv} that aren't sandbox *policy* (that's
 * `customConfig`).
 */
export type WrapWithSandboxOptions = {
  /**
   * Opaque per-invocation correlation key. Violations observed while the
   * wrapped command runs (seatbelt log lines, seccomp events, proxy denies)
   * are stored under this key, so it must equal what you later pass to
   * `annotateStderrWithSandboxFailures` / `getViolationsForCommand`.
   * Defaults to `command`. Prefer a unique id (e.g. a tool-use id) over the
   * command text: keys are compared on their first 100 characters, so two
   * long commands sharing a prefix would otherwise cross-attribute, and a
   * rerun of the same text would inherit the earlier run's events.
   *
   * An id that a network allow list is registered under must also be
   * unguessable: see `registerCommandNetworkLists`.
   */
  commandId?: string
  /**
   * The command this invocation *represents*, when that differs from the
   * string being wrapped (e.g. you wrap an assembled
   * `source <snapshot> && eval '<cmd>'` but the user-facing command is
   * `<cmd>`). Used for `ignoreViolations` command-pattern matching and
   * reported as the violation's `command`. Defaults to `command`.
   */
  commandText?: string
}

/** A wrap that has started over this many times walks without giving the
 *  thread back. */
const RESTARTS_IN_TURNS = 2

/** In place of what a walk finds: the configuration was replaced under it. */
const REPLACED = Symbol('replaced')

/** Whether a wrap is walking, and the ones waiting to, first come first. */
let walking = false
const waitingToWalk: (() => void)[] = []

/**
 * Resolves once no other wrap is walking, with what says that this one's walk
 * has ended; only the first call of it counts. Walks that take turns on one
 * thread end no sooner for it, while each keeps all it has listed until it
 * ends and has its turn before the event loop gets one: the memory and the
 * thread held would both grow with the wraps in flight.
 * Rejects with `signal`'s reason as soon as that is aborted during the wait.
 * Nothing else takes a wrap out of the line, reset() included.
 */
async function waitToWalk(signal?: AbortSignal): Promise<() => void> {
  if (walking) {
    signal?.throwIfAborted()
    await new Promise<void>((resolve, reject) => {
      const go = (): void => {
        signal?.removeEventListener('abort', leave)
        resolve()
      }
      const leave = (): void => {
        waitingToWalk.splice(waitingToWalk.indexOf(go), 1)
        reject(signal?.reason)
      }
      waitingToWalk.push(go)
      signal?.addEventListener('abort', leave, { once: true })
    })
  }
  walking = true
  let ended = false
  return () => {
    if (ended) return
    ended = true
    // Handed on while `walking` stays set, so that no newcomer gets in first.
    const next = waitingToWalk.shift()
    if (next) next()
    else walking = false
  }
}

async function wrapWithSandbox(
  command: string,
  binShell?: string,
  customConfig?: Partial<SandboxRuntimeConfig>,
  abortSignal?: AbortSignal,
  options?: WrapWithSandboxOptions,
): Promise<string> {
  return wrapWithSandboxAgain(
    0,
    command,
    binShell,
    customConfig,
    abortSignal,
    options,
  )
}

/** {@link wrapWithSandbox}, having started over `restarts` times. */
async function wrapWithSandboxAgain(
  restarts: number,
  command: string,
  binShell?: string,
  customConfig?: Partial<SandboxRuntimeConfig>,
  abortSignal?: AbortSignal,
  options?: WrapWithSandboxOptions,
): Promise<string> {
  // INVARIANT: an attempt waits before it reads anything, so that it goes by
  // the configuration, the working directory and the disk it finds afterwards.
  const walkEnded = await waitToWalk(abortSignal)
  try {
    return await wrapWithSandboxOnce(
      walkEnded,
      restarts,
      command,
      binShell,
      customConfig,
      abortSignal,
      options,
    )
  } finally {
    walkEnded()
  }
}

/** One attempt of {@link wrapWithSandboxAgain}, which calls `walkEnded` once
 *  it walks no more. */
async function wrapWithSandboxOnce(
  walkEnded: () => void,
  restarts: number,
  command: string,
  binShell?: string,
  customConfig?: Partial<SandboxRuntimeConfig>,
  abortSignal?: AbortSignal,
  options?: WrapWithSandboxOptions,
): Promise<string> {
  const platform = getPlatform()
  const commandId = options?.commandId
  registerCommandText(command, options)
  const startedWith = config
  const startedAt = configInstalls
  const startedIn = workingDirectory()
  const movedOn = (): boolean =>
    config !== startedWith ||
    configInstalls !== startedAt ||
    workingDirectory() !== startedIn
  const startOver = (): Promise<string> => {
    // The next attempt waits like any other wrap, behind the ones there are.
    walkEnded()
    return wrapWithSandboxAgain(
      restarts + 1,
      command,
      binShell,
      customConfig,
      abortSignal,
      options,
    )
  }
  /** `steps`, left as soon as the host is seen to have moved on: what they
   *  would go on to find is for a wrap that starts over anyway. */
  function* whileCurrent<T>(steps: Steps<T>): Steps<T | typeof REPLACED> {
    for (;;) {
      if (movedOn()) return REPLACED
      const step = steps.next()
      if (step.done) return step.value
      yield
    }
  }
  const walked = <T>(
    steps: Steps<T>,
  ): T | typeof REPLACED | Promise<T | typeof REPLACED> => {
    if (restarts < RESTARTS_IN_TURNS) {
      return finishInTurns(whileCurrent(steps), abortSignal)
    }
    abortSignal?.throwIfAborted()
    return finish(steps)
  }

  // filesystem.disabled bypasses ALL filesystem rule generation. Both
  // platform wrappers treat readConfig/writeConfig === undefined as "no
  // filesystem restrictions" (seatbelt emits `(allow file-write*)`; bwrap
  // skips the `--ro-bind / /` root and all path binds).
  //
  // Precedence: when a caller passes a per-call filesystem override at all,
  // its `disabled` (defaulting to false) wins outright. A global
  // disabled=true must not silently discard a per-call tightening that
  // omits the new key.
  const fsDisabled =
    customConfig?.filesystem !== undefined
      ? (customConfig.filesystem.disabled ?? false)
      : (config?.filesystem.disabled ?? false)

  // Credential env handling is independent of filesystem policy: unsetEnvVars /
  // setEnvVars must be applied even when fsDisabled (the credential file
  // deny-reads are dropped, but env scrubbing still happens).
  const credentialRestrictions = getCredentialRestrictions(
    customConfig?.credentials ?? config?.credentials,
    customConfig?.network?.allowedDomains ?? config?.network?.allowedDomains,
  )

  // Get configs - use custom if provided, otherwise fall back to main config
  // If neither exists, defaults to empty arrays (most restrictive)
  // Always include default system write paths (like /dev/null, /tmp/claude)
  let writeConfig: FsWriteRestrictionConfig | undefined
  let readConfig: FsReadRestrictionConfig | undefined
  if (!fsDisabled) {
    const userAllowWrite = stripWriteGlobs(
      'allow',
      customConfig?.filesystem?.allowWrite ??
        config?.filesystem.allowWrite ??
        [],
    )
    writeConfig = {
      allowOnly: [
        ...defaultWritePathsUnder({
          denyRead:
            customConfig?.filesystem?.denyRead ??
            config?.filesystem.denyRead ??
            [],
          allowRead:
            customConfig?.filesystem?.allowRead ?? config?.filesystem.allowRead,
          credentials: customConfig?.credentials ?? config?.credentials,
        }),
        ...userAllowWrite,
      ],
      denyWithinAllow: stripWriteGlobs(
        'deny',
        customConfig?.filesystem?.denyWrite ??
          config?.filesystem.denyWrite ??
          [],
      ),
      ...literalWriteLists(
        customConfig?.filesystem?.allowWrite ?? config?.filesystem.allowWrite,
        customConfig?.filesystem?.denyWrite ?? config?.filesystem.denyWrite,
      ),
    }
    // For a caller that never reads checkDependencies(), the CLI among them.
    if (!ownInstallLogged) {
      ownInstallLogged = true
      try {
        const ownInstall = ownInstallWarning(writeRootsOf(writeConfig))
        if (ownInstall !== undefined) {
          logForDebugging(ownInstall, { level: 'warn' })
        }
      } catch {
        // It only advises, as in checkDependenciesCommon().
      }
    }

    // Credential deny paths are unioned with the caller's denyRead — never
    // replacing it — so explicit filesystem restrictions always survive.
    // allowRead is resolved first: on Linux a denyRead glob's expansion is
    // collapsed against the paths that re-expose contents under a denied
    // directory (allowRead + allowWrite), so both must be final here.
    const expandedAllowRead = await walked(
      resolveReadPathEntries(
        'allow',
        customConfig?.filesystem?.allowRead ??
          config?.filesystem.allowRead ??
          [],
        expandAllowReadGlob,
      ),
    )
    if (expandedAllowRead === REPLACED) return startOver()
    // The TLS-termination CA cert and the trust bundle the env vars point at
    // (NODE_EXTRA_CA_CERTS etc.) must be readable by the child, even if their
    // paths fall under a user-configured denyRead or credential entry.
    const ownAllowWithinDeny: string[] = []
    if (mitmCA) {
      ownAllowWithinDeny.push(mitmCA.certPath, mitmCA.trustBundlePath)
    }
    // Likewise the JVM proxy agent jar JAVA_TOOL_OPTIONS points at.
    if (javaAgentJarPath) {
      ownAllowWithinDeny.push(javaAgentJarPath)
    }
    expandedAllowRead.push(...ownAllowWithinDeny)
    const reExposedPaths = reExposedBy(
      expandedAllowRead,
      customConfig?.filesystem?.allowRead ?? config?.filesystem.allowRead,
      writeConfig,
    )
    const unlistableDenyDirs = new Set<string>()
    const listings: GlobWalkListings = new Map()
    const expandedDenyRead = await walked(
      resolveReadDenies(
        customConfig?.filesystem?.denyRead ?? config?.filesystem.denyRead,
        credentialRestrictions,
        (pattern, anchor) =>
          expandReadDenyGlobLinuxSteps(
            pattern,
            reExposedPaths,
            unlistableDenyDirs,
            { anchor, listings },
          ),
      ),
    )
    // Emptied by hand: a runtime may keep what this function has named for as
    // long as it is suspended, which is until the scan below has ended.
    listings.clear()
    if (expandedDenyRead === REPLACED) return startOver()
    readConfig = {
      ...expandedDenyRead,
      allowWithinDeny: expandedAllowRead,
      ...(ownAllowWithinDeny.length > 0 && { ownAllowWithinDeny }),
      unlistableDenyDirs: [...unlistableDenyDirs],
      ...literalReadLists(
        customConfig?.filesystem?.denyRead ?? config?.filesystem.denyRead,
        customConfig?.filesystem?.allowRead ?? config?.filesystem.allowRead,
      ),
    }
  }
  // Nothing below walks, and what it waits for is not this thread.
  walkEnded()

  // Check if network config is specified - this determines if we need network restrictions
  // Network restriction is needed when:
  // 1. customConfig has network.allowedDomains defined (even if empty array = block all)
  // 2. OR config has network.allowedDomains defined (even if empty array = block all)
  // An empty allowedDomains array means "no domains allowed" = block all network access
  const hasNetworkConfig =
    customConfig?.network?.allowedDomains !== undefined ||
    config?.network?.allowedDomains !== undefined

  // Network RESTRICTION is needed whenever network config is specified
  // This includes empty allowedDomains which means "block all network"
  const needsNetworkRestriction = hasNetworkConfig

  // Network PROXY is needed whenever network config is specified
  // Even with empty allowedDomains, we route through proxy so that:
  // 1. updateConfig() can enable network access for already-running processes
  // 2. The proxy blocks all requests when allowlist is empty
  const needsNetworkProxy = hasNetworkConfig

  // Wait for network initialization only if proxy is actually needed
  if (needsNetworkProxy) {
    await waitForNetworkInitialization()
  }

  // INVARIANT: one wrap, one configuration. updateConfig() can run in any of
  // the turns above, and what was read before it must not be put together
  // with what is read after it: the write list of one configuration with the
  // allowGitConfig of another is a policy nobody chose. So the wrap starts
  // over. Nothing from here to the platform's wrapper awaits.
  //
  // And one working directory, which a relative entry is resolved against
  // wherever it is read: a `.` bound back from where the host has gone to,
  // over denies walked from where it was, uncovers what they matched.
  //
  // INVARIANT: what a wrap hands out was read from the disk after its
  // configuration was installed. A host that writes a file and then installs
  // a rule that denies it finds it denied by every wrap that goes by that
  // rule. So a wrap that starts over keeps nothing of what it has listed or
  // walked, the same rules included. A configuration installed after this
  // check is the next wrap's.
  //
  // An embedder can replace the configuration many times during one walk.
  // After RESTARTS_IN_TURNS the wrap walks without a turn of the event loop,
  // so no timer or I/O callback replaces it meanwhile. That holds the thread
  // for one walk, as every wrap did before the walk took turns. It is not a
  // proof that the wrap ends: a promise continuation, or anything at all
  // while the network is still being initialized, can replace it between the
  // walk and this check, and the wrap then starts over once more.
  if (movedOn()) return startOver()

  // Check custom config to allow pseudo-terminal (can be applied dynamically)
  const allowPty = customConfig?.allowPty ?? config?.allowPty
  const allowNestedUserNamespaces =
    customConfig?.allowNestedUserNamespaces ?? config?.allowNestedUserNamespaces

  const gitSafeDirectories = getGitSafeDirectories(customConfig)

  switch (platform) {
    case 'macos':
      // macOS sandbox profile supports glob patterns directly, no ripgrep needed
      return wrapCommandWithSandboxMacOS({
        command,
        commandId,
        needsNetworkRestriction,
        // Only pass proxy ports if proxy is running (when there are domains to filter)
        httpProxyPort: needsNetworkProxy ? getProxyPort() : undefined,
        socksProxyPort: needsNetworkProxy ? getSocksProxyPort() : undefined,
        proxyAuthToken: needsNetworkProxy ? proxyAuthToken : undefined,
        caCertPath: mitmCA?.trustBundlePath,
        javaAgentJarPath: needsNetworkProxy ? javaAgentJarPath : undefined,
        readConfig,
        writeConfig,
        unsetEnvVars: credentialRestrictions.unsetEnvVars,
        setEnvVars: credentialRestrictions.setEnvVars,
        maskedFileBinds: credentialRestrictions.maskedFileBinds,
        degradeToDenyPaths: credentialRestrictions.degradeToDenyPaths,
        allowUnixSockets: getAllowUnixSockets(),
        allowAllUnixSockets: getAllowAllUnixSockets(),
        allowLocalBinding: getAllowLocalBinding(),
        allowMachLookup: getAllowMachLookup(),
        ignoreViolations: getIgnoreViolations(),
        allowPty,
        allowGitConfig: getAllowGitConfig(),
        gitSafeDirectories,
        enableWeakerNetworkIsolation: getEnableWeakerNetworkIsolation(),
        allowAppleEvents: getAllowAppleEvents(),
        binShell,
      })

    case 'linux':
      return wrapCommandWithSandboxLinux({
        command,
        commandId,
        needsNetworkRestriction,
        // Only pass socket paths if proxy is running (when there are domains to filter)
        httpSocketPath: needsNetworkProxy
          ? getLinuxHttpSocketPath()
          : undefined,
        socksSocketPath: needsNetworkProxy
          ? getLinuxSocksSocketPath()
          : undefined,
        httpProxyPort: needsNetworkProxy
          ? managerContext?.httpProxyPort
          : undefined,
        socksProxyPort: needsNetworkProxy
          ? managerContext?.socksProxyPort
          : undefined,
        proxyAuthToken: needsNetworkProxy ? proxyAuthToken : undefined,
        caCertPath: mitmCA?.trustBundlePath,
        javaAgentJarPath: needsNetworkProxy ? javaAgentJarPath : undefined,
        readConfig,
        writeConfig,
        unsetEnvVars: credentialRestrictions.unsetEnvVars,
        setEnvVars: credentialRestrictions.setEnvVars,
        maskedFileBinds: credentialRestrictions.maskedFileBinds,
        maskedFileStoreDir: credentialRestrictions.maskedFileStoreDir,
        enableWeakerNestedSandbox: getEnableWeakerNestedSandbox(),
        allowNestedUserNamespaces,
        allowAllUnixSockets: getAllowAllUnixSockets(),
        binShell,
        ripgrepConfig: getRipgrepConfig(),
        mandatoryDenySearchDepth: getMandatoryDenySearchDepth(),
        allowGitConfig: getAllowGitConfig(),
        gitSafeDirectories,
        seccompConfig: getSeccompConfig(),
        bwrapPath: config?.bwrapPath,
        socatPath: config?.socatPath,
        observeSocketPath: linuxMonitor?.observeSocketPath,
        abortSignal,
      }).catch((err: unknown) => {
        // It awaits once more, for its scan: see the invariant above.
        if (err instanceof WorkingDirectoryChanged) return startOver()
        throw err
      })

    case 'windows':
      // Windows wraps to an argv array, not a shell string. Forcing
      // callers through wrapWithSandboxArgv() means they spawn with
      // {shell:false}, which is the security boundary that keeps the
      // user's command bytes off the HOST shell.
      throw new Error(
        'wrapWithSandbox() returns a shell string and is not supported ' +
          'on Windows. Use SandboxManager.wrapWithSandboxArgv() and ' +
          'spawn the result with {shell: false}.',
      )

    default:
      // Unsupported platform - this should not happen since isSandboxingEnabled() checks platform support
      throw new Error(
        `Sandbox configuration is not supported on platform: ${platform}`,
      )
  }
}

/**
 * Wrap `command` for the sandbox and return a spawn descriptor:
 * `{ argv, env }`, suitable for
 * `spawn(argv[0], argv.slice(1), {shell: false, env})`.
 *
 * On Windows this is the ONLY supported wrap method (see
 * {@link wrapWithSandbox}); `env` is the broker process's spawn env
 * — the sandboxed child gets a fresh `srt-sandbox` profile env with
 * only the `--env` overlay baked into `argv` (see
 * {@link wrapCommandWithSandboxWindows}). On
 * macOS/Linux `argv` is `[binShell, '-c', <wrapWithSandbox result>]`
 * (proxy env is baked into that command) and `env` is the unchanged
 * `process.env`, so callers can spawn uniformly across platforms.
 *
 * @param cwd the working directory the caller will spawn the result
 *   with. On Windows the child's cwd is whatever the caller passes
 *   as the spawn `{cwd:}` option (there is no `--cwd` flag), and
 *   the `safe.directory` git-config injection derives from this — so
 *   pass the same value here as to `spawn({cwd})`. Defaults to
 *   `process.cwd()`. Currently unused on macOS/Linux.
 */
async function wrapWithSandboxArgv(
  command: string,
  binShell?: string | WindowsBinShell,
  customConfig?: Partial<SandboxRuntimeConfig>,
  abortSignal?: AbortSignal,
  cwd?: string,
  options?: WrapWithSandboxOptions,
): Promise<{ argv: string[]; env: NodeJS.ProcessEnv }> {
  const platform = getPlatform()

  if (platform === 'windows') {
    const hasNetworkConfig =
      customConfig?.network?.allowedDomains !== undefined ||
      config?.network?.allowedDomains !== undefined
    if (hasNetworkConfig) {
      await waitForNetworkInitialization()
    }
    const credentialRestrictions = getCredentialRestrictions(
      customConfig?.credentials ?? config?.credentials,
      customConfig?.network?.allowedDomains ?? config?.network?.allowedDomains,
    )
    // Per-exec FILE denies (customConfig only — the session-level
    // config's denies were already stamped at initialize()).
    // Paths go through `expandWindowsFsPaths` — the SAME
    // chokepoint the session-level set uses (point-in-time glob
    // expand, normalize, missing→drop) — so a per-exec entry
    // resolves identically to its session-level equivalent.
    // macOS/Linux per-exec already reuses session-level expansion;
    // Windows now matches.
    //
    // The dedup against `windowsFsStampedSet` is an OPTIMIZATION,
    // not a correctness gate: re-stamping a session-held path
    // under the exec's distinct holder is refcount-safe but wastes
    // a SetSecurityInfo round-trip.
    //
    // filesystem.disabled bypasses ALL filesystem rule generation
    // — including credential-derived file denies — same ordering
    // as session-level `computeWindowsFsAccessSet` (credential
    // ENV: mode:'deny' is structural under the fresh srt-sandbox
    // env; mode:'mask' sentinels are passed via the --env
    // overlay). The masked files stay denied, as of this wrap: the
    // session has stamped the ones it found at initialize().
    // Per-exec allowRead/allowWrite throw — `srt-win exec` only
    // exposes `--deny-*`; per-exec grants are not implemented.
    const fsCfg = customConfig?.filesystem
    const maskedFiles = windowsMaskedFileDenies(credentialRestrictions)
    let rawRead: readonly FilesystemPathEntry[] = []
    let rawWrite: readonly FilesystemPathEntry[] = []
    let rawCredential: readonly string[] = []
    if (!fsCfg?.disabled) {
      if (fsCfg?.allowRead?.length || fsCfg?.allowWrite?.length) {
        throw new Error(
          `Per-exec filesystem.allowRead/allowWrite is not supported ` +
            `on Windows — \`srt-win exec\` only exposes per-exec ` +
            `denies. Set them at the session level (initialize()).`,
        )
      }
      rawRead = fsCfg?.denyRead ?? []
      rawWrite = fsCfg?.denyWrite ?? []
      rawCredential = getCredentialDenyReadPaths(customConfig?.credentials)
    }
    let perExecDenyRead: string[] = []
    let perExecDenyWrite: string[] = []
    // Skip on the dominant path (no per-exec fs deny, no credential
    // file).
    if (
      rawRead.length > 0 ||
      rawWrite.length > 0 ||
      rawCredential.length > 0 ||
      maskedFiles.length > 0
    ) {
      const sessRead = new Set(windowsFsStampedSet?.denyRead ?? [])
      const sessWrite = new Set(windowsFsStampedSet?.denyWrite ?? [])
      const expand = expandWindowsFsPaths
      const ranked = rankWindowsFsAccess({
        allowRead: [],
        allowWrite: [],
        denyRead: expand(rawRead, { mode: 'deny' }),
        denyWrite: expand(rawWrite, { mode: 'deny' }),
        credentialDeny: [
          ...expand(rawCredential, { mode: 'deny' }),
          ...maskedFiles,
        ],
        held: windowsFsStampedSet,
      })
      const denyRead = ranked.denyRead
      perExecDenyRead = denyRead.filter(p => !sessRead.has(p))
      // srt-win expands the deny from the record as it is when the command
      // runs, so a grant made since initialize() is covered.
      perExecDenyWrite = ranked.denyWrite.filter(
        p => !sessRead.has(p) && !sessWrite.has(p),
      )
    }
    // Per-exec deny rides on argv (`acl stamp` reads stdin, but
    // exec's stdin belongs to the child). The CreateProcessW
    // length check lives in `wrapCommandWithSandboxWindows`
    // where the full argv (incl. shell + user command) is known.
    //
    // The `denyReadPaths` half of the SESSION-level credentials
    // is already unioned into the stamp set at initialize() time
    // via `computeWindowsFsAccessSet`.
    // Asked once per srt-win, so an older one is refused as outdated
    // instead of failing on a flag it does not know.
    assertWindowsSrtWinCapable(
      customConfig?.windows?.srtWin
        ? resolveSrtWin(customConfig.windows.srtWin)
        : (srtWinSpawn ?? resolveSrtWin(config?.windows?.srtWin)),
    )
    // The loopback mode is the one initialize() probed the fence with.
    // A command or an updateConfig() asking for the other is refused here.
    const wantsLoopback =
      (customConfig?.network?.allowLocalBinding ?? getAllowLocalBinding()) ===
      true
    if (
      windowsWfpVerifiedLoopback !== undefined &&
      wantsLoopback !== windowsWfpVerifiedLoopback
    ) {
      throw new WindowsSandboxError(
        'wfp_loopback_mismatch',
        windowsLoopbackModeChanged(wantsLoopback, windowsWfpVerifiedLoopback),
      )
    }
    registerCommandText(command, options)
    return wrapCommandWithSandboxWindows({
      command,
      commandId: options?.commandId,
      httpProxyPort: hasNetworkConfig ? getProxyPort() : undefined,
      socksProxyPort: hasNetworkConfig ? getSocksProxyPort() : undefined,
      proxyAuthToken: hasNetworkConfig ? proxyAuthToken : undefined,
      // `srt-win exec` launches nothing unless this is the loopback mode
      // the install recorded: a difference is refused, never ignored.
      allowLoopback: wantsLoopback,
      // mode:'deny' env vars are structurally absent (fresh
      // srt-sandbox profile env). mode:'mask' sentinels are
      // passed via the --env overlay so the sandboxed child sees
      // the sentinel value, same as macOS/Linux.
      setEnvVars: credentialRestrictions.setEnvVars,
      denyRead: perExecDenyRead,
      // The session's own grants beneath those denies keep their rank.
      denyReadExcept: windowsGrantsBeneathDenies(
        [
          ...(windowsFsStampedSet?.grantRead ?? []),
          ...(windowsFsStampedSet?.grantWrite ?? []),
        ],
        perExecDenyRead,
      ),
      denyWrite: perExecDenyWrite,
      // safe.directory: cwd + the resolved session-level write
      // grants + explicit git.safeDirectories — the working-tree
      // roots the sandbox user has MODIFY on plus any repo top-level
      // the caller marks as safe without granting write.
      cwd,
      allowWrite: windowsFsStampedSet?.grantWrite,
      gitSafeDirectories: getGitSafeDirectories(customConfig),
      caCertPath: mitmCA?.trustBundlePath,
      // srt-win verifies the holder and otherwise holds for the command
      // itself.
      heldBy: windowsFsSbUserSid !== undefined ? process.pid : undefined,
      // The roots initialize() granted persistently; their capability
      // SIDs are what let this command write them.
      writeRoots: windowsFsStampedSet?.grantWrite,
      binShell: parseWindowsBinShell(binShell),
      srtWin: customConfig?.windows?.srtWin
        ? resolveSrtWin(customConfig.windows.srtWin)
        : (srtWinSpawn ?? resolveSrtWin(config?.windows?.srtWin)),
    })
  }

  // macOS/Linux: delegate to the existing string wrapper, then put
  // the result behind `<shell> -c` so the caller's argv-spawn works.
  if (typeof binShell === 'object') {
    throw new Error(
      'binShell object form is Windows-only; pass a shell path string ' +
        'on macOS/Linux',
    )
  }
  const wrapped = await wrapWithSandbox(
    command,
    binShell,
    customConfig,
    abortSignal,
    options,
  )
  const shell = binShell ?? '/bin/bash'
  return { argv: [shell, '-c', wrapped], env: process.env }
}

/**
 * Get the current sandbox configuration
 * @returns The current configuration, or undefined if not initialized
 */
function getConfig(): SandboxRuntimeConfig | undefined {
  return config
}

/**
 * Update the sandbox configuration in place.
 *
 * **Network/allowlist changes are a live swap**: the running
 * mux proxy reads `config.network.allowedDomains` /
 * `deniedDomains` per-request (via `filterNetworkRequest`), so
 * reassigning `config` here takes effect on the next connection
 * with no proxy rebind and no port change — on every platform,
 * including Windows. This is what lets a host enable/deny domains
 * for already-running sandboxed children.
 *
 * Filesystem changes (denyRead/denyWrite) are NOT applied live:
 * macOS bakes them into the seatbelt profile at wrap time, and
 * Linux/Windows bake them into the bwrap argv / DENY-ACE set at
 * wrap time. Call reset() + initialize() to apply a new
 * filesystem config.
 *
 * @param newConfig - The new configuration to use
 */
function updateConfig(newConfig: SandboxRuntimeConfig): void {
  if (
    getPlatform() === 'windows' &&
    config &&
    !sameWindowsStampSet(newConfig)
  ) {
    logForDebugging(
      `[Sandbox Windows] updateConfig: the resolved file-access set ` +
        `(filesystem.* ∪ credentials.files) changed but the ACL ` +
        `stamp/grant is session-wide — call reset() then initialize() ` +
        `to apply. The previously-applied set stays in effect.`,
      { level: 'warn' },
    )
  }
  const nextLoopback = newConfig.network?.allowLocalBinding === true
  if (
    getPlatform() === 'windows' &&
    config &&
    windowsWfpVerifiedLoopback !== undefined &&
    nextLoopback !== windowsWfpVerifiedLoopback
  ) {
    logForDebugging(
      `[Sandbox Windows] updateConfig: ` +
        windowsLoopbackModeChanged(nextLoopback, windowsWfpVerifiedLoopback) +
        ` Commands are refused until then.`,
      { level: 'warn' },
    )
  }
  // Built before anything is swapped, so a malformed range leaves the
  // previous config fully in effect.
  const nextGuard = createResolvedAddressGuard(newConfig.network)
  // Deep clone the config to avoid mutations. structuredClone cannot clone
  // functions, so pull filterRequest out, clone the rest, and put it back —
  // a function reference is immutable in the sense that matters here.
  const { filterRequest, ...rest } = newConfig.network
  config = structuredClone({ ...newConfig, network: rest })
  config.network.filterRequest = filterRequest
  configInstalls++
  resolvedAddressGuard = nextGuard
  // Re-resolve parent proxy so hot-reload picks up changes. Note: the proxy
  // servers capture `parentProxy` by value at creation, so changes here take
  // effect only on re-initialize. This keeps the state consistent for the
  // next initialize() call.
  parentProxy = resolveParentProxy(newConfig.network.parentProxy)
  logForDebugging('Sandbox configuration updated')
}

/**
 * Lightweight cleanup to call after each sandboxed command completes.
 *
 * On Linux, bwrap creates empty files on the host filesystem as mount points
 * when protecting non-existent deny paths (e.g. ~/.bashrc, ~/.gitconfig).
 * These persist after bwrap exits. This function removes them.
 *
 * Safe to call on any platform — it's a no-op on macOS.
 * Also called automatically by reset() and on process exit as safety nets.
 */
function cleanupAfterCommand(): void {
  cleanupBwrapMountPoints()
}

/**
 * How long to wait for a bridge process to exit after SIGTERM before
 * escalating to SIGKILL.
 *
 * socat exits within ~10ms of SIGTERM; this is purely a safety margin.
 * Keep it well below bun's default 5s test/hook timeout: when a bridge's
 * `'exit'` event is missed entirely (a Linux-only Bun pidfd notification
 * bug, oven-sh/bun#30301), this timer is the only thing that lets `reset()`
 * make progress, and a 5000ms value here loses the race against the hook
 * timer by a couple of milliseconds — that race was the dominant CI flake.
 */
const BRIDGE_EXIT_TIMEOUT_MS = 1500

/**
 * SIGTERM a bridge process and resolve once it has exited.
 *
 * Returns immediately if the process has already exited (`.exitCode` /
 * `.signalCode` set) — registering `.once('exit')` after the event has
 * already been emitted produces a listener that never fires.
 *
 * Falls back to SIGKILL after {@link BRIDGE_EXIT_TIMEOUT_MS}.
 */
function killBridgeProcess(proc: ChildProcess, label: string): Promise<void> {
  // Already exited → 'exit' already emitted → a fresh once('exit') would
  // never fire. Don't wait on it.
  if (!proc.pid || proc.exitCode !== null || proc.signalCode !== null) {
    return Promise.resolve()
  }

  try {
    process.kill(proc.pid, 'SIGTERM')
    logForDebugging(`Sent SIGTERM to ${label} bridge process`)
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'ESRCH') {
      logForDebugging(`Error killing ${label} bridge: ${err}`, {
        level: 'error',
      })
    }
    // ESRCH = process already gone; nothing to wait for either way.
    return Promise.resolve()
  }

  return new Promise<void>(resolve => {
    let settled = false
    const done = () => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      resolve()
    }
    proc.once('exit', () => {
      logForDebugging(`${label} bridge process exited`)
      done()
    })
    const timer = setTimeout(() => {
      // Re-check liveness — the 'exit' may have raced us.
      if (proc.exitCode === null && proc.signalCode === null) {
        logForDebugging(`${label} bridge did not exit, forcing SIGKILL`, {
          level: 'warn',
        })
        try {
          if (proc.pid) process.kill(proc.pid, 'SIGKILL')
        } catch {
          // Process may have already exited
        }
      }
      done()
    }, BRIDGE_EXIT_TIMEOUT_MS)
    // The bridge process is being torn down; this timer must not be the
    // only thing keeping the event loop alive.
    timer.unref?.()
  })
}

/**
 * Forcibly close an http.Server, including any in-flight requests.
 *
 * Plain `server.close()` waits for every active request to finish.
 * The proxy may be mid-upstream-request when reset() runs (e.g. a test's
 * curl was killed by --max-time while the proxy was still dialing the
 * real example.com / api.github.com), and `dialDirect()` allows up to
 * 30s before giving up. Combined with a socat fork that hasn't yet seen
 * its unix-socket EOF, that leaves a fully-open inbound connection and
 * `server.close()` never calls back. `closeAllConnections()` (Node 18.2+,
 * also implemented in Bun) tears down those sockets so `close()` resolves
 * immediately.
 */
function forceCloseHttpServer(
  server: ReturnType<typeof createHttpProxyServer>,
): Promise<void> {
  return new Promise<void>(resolve => {
    // Must run *before* close(): in Bun, close() also detaches the
    // underlying handle, so a closeAllConnections() called afterwards
    // becomes a no-op and the close callback waits for the in-flight
    // request to drain — defeating the purpose. With closeAllConnections()
    // first, the connections are gone by the time close() runs and its
    // callback fires immediately (Bun reports "Server is not running.",
    // Node reports no error). Verified against both orderings.
    if (typeof server.closeAllConnections === 'function') {
      server.closeAllConnections()
    }
    server.close(error => {
      if (error && error.message !== 'Server is not running.') {
        logForDebugging(`Error closing HTTP proxy server: ${error.message}`, {
          level: 'error',
        })
      }
      resolve()
    })
  })
}

async function reset(): Promise<void> {
  // Windows: release this session's sandbox-user ACEs. Best-effort:
  // log anomalies rather than throw, so teardown always completes.
  // Persistent write roots and the denies under them are not released.
  if (windowsFsStampedSet && windowsFsSbUserSid) {
    const sb = windowsFsSbUserSid
    // Captured at initialize() — the SAME binary the grants/stamps
    // were applied with, immune to `config` mutation between.
    const srtWin = srtWinSpawn
    // The 'exit'/signal handler lands here too: this part of
    // reset() runs synchronously.
    releaseWindowsSessionAcls(sb, srtWin)
  }
  windowsFsStampedSet = undefined
  windowsFsSbUserSid = undefined
  windowsFsRawInputs = undefined
  srtWinSpawn = undefined
  windowsProfileRead = undefined
  windowsProfileReadWarnings = []
  windowsCapableSrtWin.clear()
  // windowsWfpVerifiedFor is NOT cleared — per-process, not per-session.

  // Clean up any leftover bwrap mount points. Force past the
  // active-sandbox counter — reset() means the session is over.
  cleanupBwrapMountPoints({ force: true })

  // Stop log monitor
  if (logMonitorShutdown) {
    logMonitorShutdown()
    logMonitorShutdown = undefined
  }
  if (linuxMonitor) {
    linuxMonitor.stop()
    linuxMonitor = undefined
  }

  if (managerContext?.linuxBridge) {
    const {
      httpSocketPath,
      socksSocketPath,
      httpBridgeProcess,
      socksBridgeProcess,
    } = managerContext.linuxBridge

    // Kill both bridges and wait for them to exit
    await Promise.all([
      killBridgeProcess(httpBridgeProcess, 'HTTP'),
      killBridgeProcess(socksBridgeProcess, 'SOCKS'),
    ])

    // Clean up sockets
    if (httpSocketPath) {
      try {
        fs.rmSync(httpSocketPath, { force: true })
        logForDebugging('Cleaned up HTTP socket')
      } catch (err) {
        logForDebugging(`HTTP socket cleanup error: ${err}`, {
          level: 'error',
        })
      }
    }

    if (socksSocketPath) {
      try {
        fs.rmSync(socksSocketPath, { force: true })
        logForDebugging('Cleaned up SOCKS socket')
      } catch (err) {
        logForDebugging(`SOCKS socket cleanup error: ${err}`, {
          level: 'error',
        })
      }
    }
  }

  // Close servers in parallel (only if they exist, i.e., were started by us)
  const closePromises: Promise<void>[] = []

  if (mitmCA) {
    closePromises.push(disposeMitmCA(mitmCA))
  }

  if (muxProxyServer) {
    closePromises.push(
      muxProxyServer.close().catch((error: Error) => {
        logForDebugging(`Error closing mux proxy server: ${error.message}`, {
          level: 'error',
        })
      }),
    )
  }

  if (httpProxyServer) {
    closePromises.push(forceCloseHttpServer(httpProxyServer))
  }

  if (socksProxyServer) {
    const socksClose = socksProxyServer.close().catch((error: Error) => {
      logForDebugging(`Error closing SOCKS proxy server: ${error.message}`, {
        level: 'error',
      })
    })
    closePromises.push(socksClose)
  }

  // Wait for all servers to close
  await Promise.all(closePromises)

  // Clear references
  muxProxyServer = undefined
  httpProxyServer = undefined
  proxyAuthToken = undefined
  socksProxyServer = undefined
  managerContext = undefined
  initializationPromise = undefined
  parentProxy = undefined
  resolvedAddressGuard = createResolvedAddressGuard()
  mitmCA = undefined
  javaAgentJarPath = undefined
  sentinelRegistry.clear()
  awsPairRegistry.clear()
  commandTextsByKey.clear()
  commandNetworkListsByKey.clear()
  maskedFileStore.dispose()
}

function getSandboxViolationStore() {
  return sandboxViolationStore
}

function annotateStderrWithSandboxFailures(
  command: string,
  stderr: string,
): string {
  if (!config) {
    return stderr
  }

  const violations = sandboxViolationStore.getViolationsForCommand(command)
  if (violations.length === 0) {
    return stderr
  }

  let annotated = stderr
  annotated += EOL + '<sandbox_violations>' + EOL
  for (const violation of violations) {
    annotated += violation.line + EOL
  }
  annotated += '</sandbox_violations>'

  return annotated
}

/**
 * Returns glob patterns from Edit/Read permission rules that are not
 * fully supported on Linux. Returns empty array on macOS or when
 * sandboxing is disabled.
 *
 * Patterns ending with /** are excluded since they work as subpaths.
 * So are entries marked literal. An entry that is also the name of a path
 * that exists is still returned: what is returned must not depend on what
 * is on the disk, which a sandboxed command can change.
 */
function getLinuxGlobPatternWarnings(): string[] {
  // Only warn on Linux/WSL (bubblewrap doesn't support globs)
  // macOS supports glob patterns via regex conversion
  if (getPlatform() !== 'linux' || !config || config.filesystem.disabled) {
    return []
  }

  const globPatterns: string[] = []

  // Write paths take no globs at all on Linux: bubblewrap binds concrete
  // paths, and nothing expands them.
  const allPaths = [
    ...config.filesystem.allowWrite,
    ...config.filesystem.denyWrite,
  ]

  for (const path of allPaths) {
    if (typeof path !== 'string') continue
    // Strip trailing /** since that's just a subpath (directory and everything under it)
    const pathWithoutTrailingStar = removeTrailingGlobSuffix(path)

    // Only warn if there are still glob characters after removing trailing /**
    if (containsGlobChars(pathWithoutTrailingStar)) {
      globPatterns.push(path)
    }
  }

  // Read paths are expanded, so a glob there is supported — unless the
  // pattern has no literal directory below the root for the walk to start
  // from (a wildcard in its first path component, `/**/*.pem`), which
  // expands to nothing and leaves the entry unenforced.
  for (const path of [
    ...new Set([
      ...config.filesystem.denyRead,
      // Joins the read denies, and is skipped like one of them.
      ...getCredentialDenyReadPaths(config.credentials),
    ]),
    ...(config.filesystem.allowRead ?? []),
  ]) {
    if (typeof path !== 'string') continue
    const baseDir = globPatternBaseDir(normalizePathForSandbox(path))
    if (
      containsGlobChars(removeTrailingGlobSuffix(path)) &&
      globBaseDirIsRoot(baseDir)
    ) {
      globPatterns.push(path)
    }
  }

  return globPatterns
}

// ============================================================================
// Public API Interface
// ============================================================================

/**
 * Interface for the sandbox manager API
 */
export interface ISandboxManager {
  initialize(
    runtimeConfig: SandboxRuntimeConfig,
    sandboxAskCallback?: SandboxAskCallback,
    enableLogMonitor?: boolean,
    options?: SandboxInitializeOptions,
  ): Promise<void>
  isSupportedPlatform(): boolean
  isSandboxingEnabled(): boolean
  checkDependencies(ripgrepConfig?: {
    command: string
    args?: string[]
  }): SandboxDependencyCheck
  checkDependenciesAsync(ripgrepConfig?: {
    command: string
    args?: string[]
  }): Promise<SandboxDependencyCheck>
  getFsReadConfig(): FsReadRestrictionConfig
  getFsWriteConfig(): FsWriteRestrictionConfig
  getNetworkRestrictionConfig(): NetworkRestrictionConfig
  getAllowUnixSockets(): string[] | undefined
  getAllowLocalBinding(): boolean | undefined
  getAllowMachLookup(): string[] | undefined
  getIgnoreViolations(): Record<string, string[]> | undefined
  getEnableWeakerNestedSandbox(): boolean | undefined
  getProxyPort(): number | undefined
  getProxyAuthToken(): string | undefined
  getSocksProxyPort(): number | undefined
  getLinuxHttpSocketPath(): string | undefined
  getLinuxSocksSocketPath(): string | undefined
  waitForNetworkInitialization(): Promise<boolean>
  wrapWithSandbox(
    command: string,
    binShell?: string,
    customConfig?: Partial<SandboxRuntimeConfig>,
    abortSignal?: AbortSignal,
    options?: WrapWithSandboxOptions,
  ): Promise<string>
  wrapWithSandboxArgv(
    command: string,
    binShell?: string | WindowsBinShell,
    customConfig?: Partial<SandboxRuntimeConfig>,
    abortSignal?: AbortSignal,
    cwd?: string,
    options?: WrapWithSandboxOptions,
  ): Promise<{ argv: string[]; env: NodeJS.ProcessEnv }>
  /**
   * Register the network allow list of one invocation, under the `commandId`
   * its wrap was given ({@link WrapWithSandboxOptions}). Entries are matched
   * and validated as `network.allowedDomains` entries are; an invalid one
   * throws. Registering an id again replaces its list.
   *
   * Order of evaluation for a connection: a configured `deniedDomains` match
   * denies; a configured `allowedDomains` match allows;
   * `network.strictAllowlist` denies; a match in the list registered for the
   * id the connection presents allows; then the ask callback decides if
   * there is one, and otherwise the connection is denied. So a per-command
   * entry never overrides a configured `deniedDomains` entry and is ignored
   * entirely under `strictAllowlist`. It also never enters `network.*`, so
   * the default `injectHosts` scope of a masked credential does not grow.
   *
   * The proxy reads the id from the proxy username, which the sandboxed
   * client presents, so the id is the ONLY thing binding a connection to an
   * allow list. It MUST be unguessable: at least 128 bits of randomness (16
   * random bytes as base64url, 22 characters; a shorter id throws), never a
   * counter, a timestamp or anything derived from the command. Presenting
   * another live invocation's id gets that invocation's allows: this is
   * attribution, not a boundary between concurrent commands of one session.
   *
   * Register just before spawning the wrapped command, and unregister when
   * the child exits or never started: a registration that outlives its
   * command widens the window in which its id is worth presenting.
   *
   * As with every attribution key, only the first 100 characters of an id
   * take part, and a list under an id whose encoded form does not fit in the
   * proxy username (possible only with non-ASCII ids) never applies. An
   * unpaired surrogate does not count towards the 22 characters.
   *
   * No list applies while `network.httpProxyPort` names an external proxy:
   * the wrap gives that proxy no username, so no connection carries an id.
   * Registering still succeeds, and every connection is decided as if no list
   * existed.
   */
  registerCommandNetworkLists(
    commandId: string,
    lists: { allowedDomains?: string[] },
  ): void
  /**
   * Remove the list registered for `commandId`. A no-op for an id that has
   * none. `reset()` removes them all.
   */
  unregisterCommandNetworkLists(commandId: string): void
  /**
   * True when the network filter understands an ask callback's
   * `{ allow: false, reason }` answer (see {@link SandboxAskCallback}). Read
   * it before returning that object: releases up to v0.0.77 allow on any
   * truthy answer, so there the object would be read as an allow. Where this
   * is absent, deny with a plain `false`.
   */
  readonly askCallbackDenyReason: true
  getSandboxViolationStore(): SandboxViolationStore
  annotateStderrWithSandboxFailures(command: string, stderr: string): string
  getLinuxGlobPatternWarnings(): string[]
  getConfig(): SandboxRuntimeConfig | undefined
  getMitmCA(): MitmCA | undefined
  /**
   * Windows: whether the commands of the current session read the
   * user's profile through the profile read grant.
   */
  getWindowsProfileRead(): 'granted' | 'absent' | undefined
  /**
   * Windows: warnings about the profile read grant for the current session:
   * excluded paths that are, or may be, readable to sandboxed commands, and
   * entries that could not be removed. None of them is a rejection.
   */
  getWindowsProfileReadWarnings(): WindowsProfileReadWarning[]
  getSentinelRegistry(): SentinelRegistry
  getAwsPairRegistry(): AwsPairRegistry
  getMaskedFileStore(): MaskedFileStore
  updateConfig(newConfig: SandboxRuntimeConfig): void
  cleanupAfterCommand(): void
  reset(): Promise<void>
}

// ============================================================================
// Export as Namespace with Interface
// ============================================================================

/**
 * Global sandbox manager that handles both network and filesystem restrictions
 * for this session. This runs outside of the sandbox, on the host machine.
 */
export const SandboxManager: ISandboxManager = {
  initialize,
  isSupportedPlatform,
  isSandboxingEnabled,
  checkDependencies,
  checkDependenciesAsync,
  getFsReadConfig,
  getFsWriteConfig,
  getNetworkRestrictionConfig,
  getAllowUnixSockets,
  getAllowLocalBinding,
  getAllowMachLookup,
  getIgnoreViolations,
  getEnableWeakerNestedSandbox,
  getProxyPort,
  getProxyAuthToken,
  getSocksProxyPort,
  getLinuxHttpSocketPath,
  getLinuxSocksSocketPath,
  waitForNetworkInitialization,
  wrapWithSandbox,
  wrapWithSandboxArgv,
  registerCommandNetworkLists,
  unregisterCommandNetworkLists,
  askCallbackDenyReason: true,
  cleanupAfterCommand,
  reset,
  getMitmCA: () => mitmCA,
  getWindowsProfileRead: () => windowsProfileRead,
  getWindowsProfileReadWarnings: () => [...windowsProfileReadWarnings],
  getSentinelRegistry: () => sentinelRegistry,
  getAwsPairRegistry: () => awsPairRegistry,
  getMaskedFileStore: () => maskedFileStore,
  getSandboxViolationStore,
  annotateStderrWithSandboxFailures,
  getLinuxGlobPatternWarnings,
  getConfig,
  updateConfig,
} as const
