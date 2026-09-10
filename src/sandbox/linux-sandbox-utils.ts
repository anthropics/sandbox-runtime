import { quote } from '../utils/shell-quote.js'
import { logForDebugging } from '../utils/debug.js'
import { whichSync } from '../utils/which.js'
import { randomBytes } from 'node:crypto'
import * as fs from 'fs'
import { spawn } from 'node:child_process'
import type { ChildProcess } from 'node:child_process'
import { tmpdir } from 'node:os'
import path, { join } from 'node:path'
import { ripGrep } from '../utils/ripgrep.js'
import { buildJavaToolOptions } from './java-proxy-agent.js'
import {
  generateProxyEnvVars,
  buildPosixGitSafeDirEnv,
  normalizePathForSandbox,
  normalizeCaseForComparison,
  isSymlinkOutsideBoundary,
  encodeSandboxedCommand,
  DANGEROUS_FILES,
  isAtOrUnder,
  isStrictlyUnder,
  getDangerousDirectories,
} from './sandbox-utils.js'
import type {
  FsReadRestrictionConfig,
  FsWriteRestrictionConfig,
} from './sandbox-schemas.js'
import { getApplySeccompBinaryPath } from './generate-seccomp-filter.js'
import type { SeccompConfig } from './sandbox-config.js'

export interface LinuxNetworkBridgeContext {
  httpSocketPath: string
  socksSocketPath: string
  httpBridgeProcess: ChildProcess
  socksBridgeProcess: ChildProcess
  httpProxyPort: number
  socksProxyPort: number
}

export interface LinuxSandboxParams {
  command: string
  /** Attribution key encoded for violation correlation; defaults to
   *  `command`. See MacOSSandboxParams.commandId. */
  commandId?: string
  needsNetworkRestriction: boolean
  httpSocketPath?: string
  socksSocketPath?: string
  httpProxyPort?: number
  socksProxyPort?: number
  /** Per-session proxy auth token; embedded in proxy env URLs. */
  proxyAuthToken?: string
  /** Path to the TLS-termination CA cert; injected as trust env vars. */
  caCertPath?: string
  /** Path to the JVM proxy agent jar; injected via JAVA_TOOL_OPTIONS. */
  javaAgentJarPath?: string
  readConfig?: FsReadRestrictionConfig
  writeConfig?: FsWriteRestrictionConfig
  /** Environment variable names to unset inside the sandbox (bwrap --unsetenv) */
  unsetEnvVars?: string[]
  /** Environment variables to set inside the sandbox (bwrap --setenv NAME VALUE) */
  setEnvVars?: Record<string, string>
  /**
   * Whole-file credential masks: bind fakePath (sentinel content) over
   * realPath read-only so the sandbox reads the sentinel.
   */
  maskedFileBinds?: Array<{ realPath: string; fakePath: string }>
  /**
   * Host directory holding the fake files. Ro-bound over itself so the
   * sandbox cannot write the bind sources even if allowWrite covers it.
   */
  maskedFileStoreDir?: string
  enableWeakerNestedSandbox?: boolean
  allowAllUnixSockets?: boolean
  binShell?: string
  ripgrepConfig?: { command: string; args?: string[] }
  /** Maximum directory depth to search for dangerous files (default: 3) */
  mandatoryDenySearchDepth?: number
  /** Allow writes to .git/config files (default: false) */
  allowGitConfig?: boolean
  /**
   * Directories to emit as `safe.directory` via `GIT_CONFIG_*` env
   * vars (see {@link buildPosixGitSafeDirEnv}). Under `--unshare-user`
   * the repo owner's uid is unmapped inside the sandbox, so git
   * refuses with "detected dubious ownership" without this.
   */
  gitSafeDirectories?: readonly string[]
  /** Custom seccomp binary paths */
  seccompConfig?: SeccompConfig
  /** Absolute path to the bwrap binary (default: resolve "bwrap" via PATH) */
  bwrapPath?: string
  /** Absolute path to the socat binary (default: resolve "socat" via PATH) */
  socatPath?: string
  /** Filesystem unix socket bound by the Linux violation monitor. When set,
   *  the socket is bind-mounted into the sandbox and apply-seccomp is told
   *  (via SRT_OBSERVE_SOCK) to install a USER_NOTIF observation filter and
   *  stream observed write-intent paths over that socket as newline JSON. */
  observeSocketPath?: string
  /** Abort signal to cancel the ripgrep scan */
  abortSignal?: AbortSignal
}

/** Default max depth for searching dangerous files */
const DEFAULT_MANDATORY_DENY_SEARCH_DEPTH = 3

/**
 * Find if any component of the path is a symlink within the allowed write paths.
 * Returns the symlink path if found, or null if no symlinks.
 *
 * This is used to detect and block symlink replacement attacks where an attacker
 * could delete a symlink and create a real directory with malicious content.
 */
function findSymlinkInPath(
  targetPath: string,
  allowedWritePaths: string[],
): string | null {
  const parts = targetPath.split(path.sep)
  let currentPath = ''

  for (const part of parts) {
    if (!part) continue // Skip empty parts (leading /)
    const nextPath = currentPath + path.sep + part

    try {
      const stats = fs.lstatSync(nextPath)
      if (stats.isSymbolicLink()) {
        // Check if this symlink is within an allowed write path
        const isWithinAllowedPath = allowedWritePaths.some(
          allowedPath =>
            nextPath.startsWith(allowedPath + '/') || nextPath === allowedPath,
        )
        if (isWithinAllowedPath) {
          return nextPath
        }
      }
    } catch {
      // Path doesn't exist - no symlink issue here
      break
    }
    currentPath = nextPath
  }

  return null
}

/** Bounded depth for chasing dangling symlink chains (kernel ELOOP limit). */
const MAX_SYMLINK_RESOLUTION_DEPTH = 40

/**
 * Canonicalize a deny path through symlinks before any mask or bind is
 * computed (resolve-before-mask). Deny paths regularly contain symlinked
 * ancestors — the common dotfiles setup symlinks .claude (or the parent of
 * .mcp.json) to a real directory — and masking the raw symlink with
 * `--ro-bind /dev/null <symlink>` makes bwrap abort at startup: "Is a
 * directory" for relative link targets, ENOENT for absolute ones.
 *
 * Resolution: realpath when the full path exists; otherwise canonicalize the
 * deepest existing ancestor and re-join the missing components. A dangling
 * symlink along the way is chain-walked (bounded) so the deny lands where a
 * write through the link would actually create the file. Returns null when
 * the path cannot be canonicalized (e.g. a symlink cycle); callers should
 * skip such paths rather than emit a mask bwrap will reject.
 *
 * Unlike normalizePathForSandbox, this intentionally applies no
 * isSymlinkOutsideBoundary check: that check exists so allow paths can't
 * silently widen write access through a symlink, but a deny path only ever
 * removes access, and the mask must land on the inode that writes through
 * the symlink actually reach.
 */
function resolveSymlinkedDenyPath(targetPath: string): string | null {
  let current = targetPath
  for (let i = 0; i < MAX_SYMLINK_RESOLUTION_DEPTH; i++) {
    try {
      return fs.realpathSync(current)
    } catch {
      // Some component is missing or dangling — canonicalize manually below.
    }

    // Find the deepest ancestor that fully resolves, collecting the missing
    // suffix components (leaf first, so unshift keeps them in path order).
    let ancestor = current
    const remainder: string[] = []
    let resolvedAncestor: string | null = null
    while (resolvedAncestor === null) {
      const parent = path.dirname(ancestor)
      if (parent === ancestor) {
        return null // reached the root without resolving anything
      }
      remainder.unshift(path.basename(ancestor))
      ancestor = parent
      try {
        resolvedAncestor = fs.realpathSync(ancestor)
      } catch {
        // Keep walking up.
      }
    }

    // The first missing component may be a dangling symlink (lstat succeeds,
    // realpath fails). Follow it and loop to re-canonicalize; otherwise the
    // remainder is genuinely non-existent and the re-joined path is final.
    const firstMissing = path.join(resolvedAncestor, remainder[0])
    let linkTarget: string | null = null
    try {
      linkTarget = fs.readlinkSync(firstMissing)
    } catch {
      // Not a symlink — nothing left to resolve.
    }
    if (linkTarget === null) {
      return path.join(resolvedAncestor, ...remainder)
    }
    current = path.join(
      path.resolve(path.dirname(firstMissing), linkTarget),
      ...remainder.slice(1),
    )
  }
  return null // symlink chain too long or cyclic
}

/**
 * Check if any existing component in the path is a file (not a directory).
 * If so, the target path can never be created because you can't mkdir under a file.
 *
 * This handles the git worktree case: .git is a file, so .git/hooks can never
 * exist and there's nothing to deny.
 */
function hasFileAncestor(targetPath: string): boolean {
  const parts = targetPath.split(path.sep)
  let currentPath = ''

  for (const part of parts) {
    if (!part) continue // Skip empty parts (leading /)
    const nextPath = currentPath + path.sep + part
    try {
      const stat = fs.statSync(nextPath)
      if (stat.isFile() || stat.isSymbolicLink()) {
        // This component exists as a file — nothing below it can be created
        return true
      }
    } catch {
      // Path doesn't exist — stop checking
      break
    }
    currentPath = nextPath
  }

  return false
}

/**
 * Find the first non-existent path component.
 * E.g., for "/existing/parent/nonexistent/child/file.txt" where /existing/parent exists,
 * returns "/existing/parent/nonexistent"
 *
 * This is used to block creation of non-existent deny paths by mounting /dev/null
 * at the first missing component, preventing mkdir from creating the parent directories.
 */
function findFirstNonExistentComponent(targetPath: string): string {
  const parts = targetPath.split(path.sep)
  let currentPath = ''

  for (const part of parts) {
    if (!part) continue // Skip empty parts (leading /)
    const nextPath = currentPath + path.sep + part
    if (!fs.existsSync(nextPath)) {
      return nextPath
    }
    currentPath = nextPath
  }

  return targetPath // Shouldn't reach here if called correctly
}

/**
 * Get mandatory deny paths using ripgrep (Linux only).
 * Uses a SINGLE ripgrep call with multiple glob patterns for efficiency.
 * With --max-depth limiting, this is fast enough to run on each command without memoization.
 */
async function linuxGetMandatoryDenyPaths(
  ripgrepConfig: { command: string; args?: string[] } = { command: 'rg' },
  maxDepth: number = DEFAULT_MANDATORY_DENY_SEARCH_DEPTH,
  allowGitConfig = false,
  abortSignal?: AbortSignal,
): Promise<string[]> {
  const cwd = process.cwd()
  // Use provided signal or create a fallback controller
  const fallbackController = new AbortController()
  const signal = abortSignal ?? fallbackController.signal
  const dangerousDirectories = getDangerousDirectories()

  // Note: Settings files are added at the callsite in sandbox-manager.ts
  const denyPaths = [
    // Dangerous files in CWD
    ...DANGEROUS_FILES.map(f => path.resolve(cwd, f)),
    // Dangerous directories in CWD
    ...dangerousDirectories.map(d => path.resolve(cwd, d)),
  ]

  // Git hooks and config are only denied when .git exists as a directory.
  // In git worktrees, .git is a file (e.g., "gitdir: /path/..."), so
  // .git/hooks can never exist — denying it would cause bwrap to fail.
  // When .git doesn't exist at all, mounting at .git would block its
  // creation and break git init.
  const dotGitPath = path.resolve(cwd, '.git')
  let dotGitIsDirectory = false
  try {
    dotGitIsDirectory = fs.statSync(dotGitPath).isDirectory()
  } catch {
    // .git doesn't exist
  }

  if (dotGitIsDirectory) {
    // Git hooks always blocked for security
    denyPaths.push(path.resolve(cwd, '.git/hooks'))

    // Git config conditionally blocked based on allowGitConfig setting
    if (!allowGitConfig) {
      denyPaths.push(path.resolve(cwd, '.git/config'))
    }
  }

  // Build iglob args for all patterns in one ripgrep call
  const iglobArgs: string[] = []
  for (const fileName of DANGEROUS_FILES) {
    iglobArgs.push('--iglob', fileName)
  }
  for (const dirName of dangerousDirectories) {
    iglobArgs.push('--iglob', `**/${dirName}/**`)
  }
  // Git hooks always blocked in nested repos
  iglobArgs.push('--iglob', '**/.git/hooks/**')

  // Git config conditionally blocked in nested repos
  if (!allowGitConfig) {
    iglobArgs.push('--iglob', '**/.git/config')
  }

  // Single ripgrep call to find all dangerous paths in subdirectories
  // Limit depth for performance - deeply nested dangerous files are rare
  // and the security benefit doesn't justify the traversal cost
  let matches: string[] = []
  try {
    matches = await ripGrep(
      [
        '--files',
        '--hidden',
        '--max-depth',
        String(maxDepth),
        ...iglobArgs,
        '-g',
        '!**/node_modules/**',
      ],
      cwd,
      signal,
      ripgrepConfig,
    )
  } catch (error) {
    logForDebugging(`[Sandbox] ripgrep scan failed: ${error}`)
  }

  // Process matches
  for (const match of matches) {
    const absolutePath = path.resolve(cwd, match)

    // File inside a dangerous directory -> add the directory path
    let foundDir = false
    for (const dirName of [...dangerousDirectories, '.git']) {
      const normalizedDirName = normalizeCaseForComparison(dirName)
      const segments = absolutePath.split(path.sep)
      const dirIndex = segments.findIndex(
        s => normalizeCaseForComparison(s) === normalizedDirName,
      )
      if (dirIndex !== -1) {
        // For .git, we want hooks/ or config, not the whole .git dir
        if (dirName === '.git') {
          const gitDir = segments.slice(0, dirIndex + 1).join(path.sep)
          if (match.includes('.git/hooks')) {
            denyPaths.push(path.join(gitDir, 'hooks'))
          } else if (match.includes('.git/config')) {
            denyPaths.push(path.join(gitDir, 'config'))
          }
        } else {
          denyPaths.push(segments.slice(0, dirIndex + 1).join(path.sep))
        }
        foundDir = true
        break
      }
    }

    // Dangerous file match
    if (!foundDir) {
      denyPaths.push(absolutePath)
    }
  }

  return [...new Set(denyPaths)]
}

// Track mount points created by bwrap for non-existent deny paths.
// When bwrap does --ro-bind /dev/null /nonexistent/path, it creates an empty
// file on the host as a mount point. These persist after bwrap exits and must
// be cleaned up explicitly.
const bwrapMountPoints: Set<string> = new Set()

const CAP_SETFCAP = 31

/** Whether this process holds `cap` in its effective set (Linux). */
function processHasEffectiveCapability(cap: number): boolean {
  try {
    const status = fs.readFileSync('/proc/self/status', 'utf8')
    const capEff = status.match(/^CapEff:\s*([0-9a-fA-F]+)\s*$/m)
    if (!capEff) return false
    return ((BigInt('0x' + capEff[1]) >> BigInt(cap)) & 1n) === 1n
  } catch {
    return false
  }
}

/**
 * Capability arguments: the command holds no capability in bwrap's user
 * namespace. For a non-root caller that is bwrap's default and the drop is a
 * no-op; bwrap run by uid 0 hands the command every capability the caller
 * holds unless told otherwise, and inside bwrap's user namespace
 * CAP_SYS_ADMIN is enough to unmount a read-deny tmpfs or a write-deny bind,
 * or remount / read-write: the whole filesystem policy. The one exception,
 * for a root caller while the seccomp helper is in use and the caller has
 * it, is CAP_SETFCAP: the helper's nested user namespace must map uid 0,
 * which the kernel (5.12+) permits only when the namespace's creator held
 * CAP_SETFCAP. The helper loses it on entering that namespace, so the
 * command itself runs with no capability in bwrap's namespace and full ones
 * only in a nested namespace whose copies of these mounts are locked. A
 * non-root caller may not add a capability.
 */
function capabilityArgs(usesSeccompHelper: boolean): string[] {
  const args = ['--cap-drop', 'ALL']
  if (
    usesSeccompHelper &&
    process.geteuid?.() === 0 &&
    processHasEffectiveCapability(CAP_SETFCAP)
  ) {
    args.push('--cap-add', 'CAP_SETFCAP')
  }
  return args
}

// Number of wrapped commands that have been generated but whose cleanup has
// not yet run. cleanupBwrapMountPoints() defers file deletion while this is
// positive, because deleting a mount point file on the host while another
// bwrap instance is still running detaches that instance's bind mount and
// the deny rule stops applying inside it.
let activeSandboxCount = 0

let exitHandlerRegistered = false

/**
 * Register cleanup handler for bwrap mount points
 */
function registerExitCleanupHandler(): void {
  if (exitHandlerRegistered) {
    return
  }

  process.on('exit', () => {
    cleanupBwrapMountPoints({ force: true })
  })

  exitHandlerRegistered = true
}

/**
 * Clean up mount point files created by bwrap for non-existent deny paths.
 *
 * When protecting non-existent deny paths, bwrap creates empty files on the
 * host filesystem as mount points for --ro-bind. These files persist after
 * bwrap exits. This function removes them.
 *
 * This should be called after each sandboxed command completes to prevent
 * ghost dotfiles (e.g. .bashrc, .gitconfig) from appearing in the working
 * directory. It is also called automatically on process exit as a safety net.
 *
 * Each call decrements the active-sandbox counter that was incremented by
 * wrapCommandWithSandboxLinux(). File deletion is deferred until the counter
 * reaches zero. Deleting a mount point file on the host while another bwrap
 * instance is still running detaches that instance's bind mount (the dentry
 * is unhashed, so path lookup no longer finds the mount) and the deny rule
 * stops applying inside that sandbox.
 *
 * Pass `{ force: true }` to delete unconditionally — used by the process-exit
 * handler and reset() where deferral is not meaningful.
 */
export function cleanupBwrapMountPoints(opts?: { force?: boolean }): void {
  if (!opts?.force) {
    if (activeSandboxCount > 0) {
      activeSandboxCount--
    }
    if (activeSandboxCount > 0) {
      logForDebugging(
        `[Sandbox Linux] Deferring mount point cleanup — ${activeSandboxCount} sandbox(es) still active`,
      )
      return
    }
  } else {
    activeSandboxCount = 0
  }

  for (const mountPoint of bwrapMountPoints) {
    try {
      // Only remove if it's still the empty file/directory bwrap created.
      // If something else has written real content, leave it alone.
      const stat = fs.statSync(mountPoint)
      if (stat.isFile() && stat.size === 0) {
        fs.unlinkSync(mountPoint)
        logForDebugging(
          `[Sandbox Linux] Cleaned up bwrap mount point (file): ${mountPoint}`,
        )
      } else if (stat.isDirectory()) {
        // Empty directory mount points are created for intermediate
        // components (Fix 2). Only remove if still empty.
        const entries = fs.readdirSync(mountPoint)
        if (entries.length === 0) {
          fs.rmdirSync(mountPoint)
          logForDebugging(
            `[Sandbox Linux] Cleaned up bwrap mount point (dir): ${mountPoint}`,
          )
        }
      }
    } catch {
      // Ignore cleanup errors — the file may have already been removed
    }
  }
  bwrapMountPoints.clear()
}

/**
 * Detailed status of Linux sandbox dependencies
 */
export type LinuxDependencyStatus = {
  hasBwrap: boolean
  hasSocat: boolean
  hasSeccompApply: boolean
}

/**
 * Result of checking sandbox dependencies
 */
export type SandboxDependencyCheck = {
  warnings: string[]
  errors: string[]
}

/**
 * Options for Linux dependency checks. Explicit binary paths, when set,
 * are checked directly instead of resolving via PATH.
 */
export type LinuxDependencyOptions = {
  seccompConfig?: SeccompConfig
  bwrapPath?: string
  socatPath?: string
}

function isExecutable(p: string): boolean {
  try {
    fs.accessSync(p, fs.constants.X_OK)
    return true
  } catch {
    return false
  }
}

/**
 * Get detailed status of Linux sandbox dependencies
 */
export function getLinuxDependencyStatus(
  opts?: LinuxDependencyOptions,
): LinuxDependencyStatus {
  const { seccompConfig, bwrapPath, socatPath } = opts ?? {}
  // argv0 mode: apply-seccomp is compiled into the caller's binary — skip
  // the on-disk lookup and trust that applyPath resolves inside bwrap.
  return {
    hasBwrap: bwrapPath ? isExecutable(bwrapPath) : whichSync('bwrap') !== null,
    hasSocat: socatPath ? isExecutable(socatPath) : whichSync('socat') !== null,
    hasSeccompApply: seccompConfig?.argv0
      ? true
      : getApplySeccompBinaryPath(seccompConfig?.applyPath) !== null,
  }
}

/**
 * Check sandbox dependencies and return structured result
 */
export function checkLinuxDependencies(
  opts?: LinuxDependencyOptions,
): SandboxDependencyCheck {
  const { seccompConfig, bwrapPath, socatPath } = opts ?? {}
  const errors: string[] = []
  const warnings: string[] = []

  // An explicit override is a directive, not a hint — if it doesn't exist,
  // surface that rather than silently falling back to PATH.
  if (bwrapPath) {
    if (!isExecutable(bwrapPath))
      errors.push(`bubblewrap (bwrap) not executable at ${bwrapPath}`)
  } else if (whichSync('bwrap') === null) {
    errors.push('bubblewrap (bwrap) not installed')
  }

  if (socatPath) {
    if (!isExecutable(socatPath))
      errors.push(`socat not executable at ${socatPath}`)
  } else if (whichSync('socat') === null) {
    errors.push('socat not installed')
  }

  if (
    !seccompConfig?.argv0 &&
    getApplySeccompBinaryPath(seccompConfig?.applyPath) === null
  ) {
    warnings.push('seccomp not available - unix socket access not restricted')
  }

  return { warnings, errors }
}

/**
 * Initialize the Linux network bridge for sandbox networking
 *
 * ARCHITECTURE NOTE:
 * Linux network sandboxing uses bwrap --unshare-net which creates a completely isolated
 * network namespace with NO network access. To enable network access, we:
 *
 * 1. Host side: Run socat bridges that listen on Unix sockets and forward to host proxy servers
 *    - HTTP bridge: Unix socket -> host HTTP proxy (for HTTP/HTTPS traffic)
 *    - SOCKS bridge: Unix socket -> host SOCKS5 proxy (for SSH/git traffic)
 *
 * 2. Sandbox side: Bind the Unix sockets into the isolated namespace and run socat listeners
 *    - HTTP listener on port 3128 -> HTTP Unix socket -> host HTTP proxy
 *    - SOCKS listener on port 1080 -> SOCKS Unix socket -> host SOCKS5 proxy
 *
 * 3. Configure environment:
 *    - HTTP_PROXY=http://localhost:3128 for HTTP/HTTPS tools
 *    - GIT_SSH_COMMAND with socat for SSH through SOCKS5
 *
 * LIMITATION: Unlike macOS sandbox which can enforce domain-based allowlists at the kernel level,
 * Linux's --unshare-net provides only all-or-nothing network isolation. Domain filtering happens
 * at the host proxy level, not the sandbox boundary. This means network restrictions on Linux
 * depend on the proxy's filtering capabilities.
 *
 * DEPENDENCIES: Requires bwrap (bubblewrap) and socat
 */
export async function initializeLinuxNetworkBridge(
  httpProxyPort: number,
  socksProxyPort: number,
  socatPath?: string,
): Promise<LinuxNetworkBridgeContext> {
  const socat = socatPath ?? 'socat'
  const socketId = randomBytes(8).toString('hex')
  const httpSocketPath = join(tmpdir(), `claude-http-${socketId}.sock`)
  // Only allocated when ports differ; in the mux case the SOCKS side
  // reuses httpSocketPath.
  const socksSocketPath = join(tmpdir(), `claude-socks-${socketId}.sock`)

  // Start HTTP bridge
  const httpSocatArgs = [
    `UNIX-LISTEN:${httpSocketPath},fork,reuseaddr`,
    `TCP:localhost:${httpProxyPort},keepalive,keepidle=10,keepintvl=5,keepcnt=3`,
  ]

  logForDebugging(`Starting HTTP bridge: ${socat} ${httpSocatArgs.join(' ')}`)

  const httpBridgeProcess = spawn(socat, httpSocatArgs, {
    stdio: 'ignore',
  })

  // Add error and exit handlers to monitor bridge health. These must be
  // registered before the !pid check: when spawn fails (e.g. socat is
  // missing or not executable), the ChildProcess emits an asynchronous
  // 'error' event, and throwing first would leave that event without a
  // listener — surfacing as an uncaughtException instead of the rejection
  // below.
  httpBridgeProcess.on('error', err => {
    logForDebugging(`HTTP bridge process error: ${err}`, { level: 'error' })
  })
  httpBridgeProcess.on('exit', (code, signal) => {
    logForDebugging(
      `HTTP bridge process exited with code ${code}, signal ${signal}`,
      { level: code === 0 ? 'info' : 'error' },
    )
  })

  if (!httpBridgeProcess.pid) {
    throw new Error('Failed to start HTTP bridge process')
  }

  // SOCKS bridge: when the host serves both protocols on one port (the mux),
  // a second socat to the same TCP target is redundant — reuse the HTTP
  // bridge's process and socket path. Downstream consumers
  // (LinuxNetworkBridgeContext, in-sandbox socat, cleanup) treat duplicate
  // refs idempotently. A separate bridge is only spawned when the ports
  // differ (external proxy override).
  let socksBridgeProcess: ChildProcess
  let socksSockPath: string
  if (socksProxyPort === httpProxyPort) {
    socksBridgeProcess = httpBridgeProcess
    socksSockPath = httpSocketPath
  } else {
    socksSockPath = socksSocketPath
    const socksSocatArgs = [
      `UNIX-LISTEN:${socksSocketPath},fork,reuseaddr`,
      `TCP:localhost:${socksProxyPort},keepalive,keepidle=10,keepintvl=5,keepcnt=3`,
    ]

    logForDebugging(
      `Starting SOCKS bridge: ${socat} ${socksSocatArgs.join(' ')}`,
    )

    socksBridgeProcess = spawn(socat, socksSocatArgs, {
      stdio: 'ignore',
    })

    // Add error and exit handlers to monitor bridge health — registered
    // before the !pid check for the same reason as the HTTP bridge above.
    socksBridgeProcess.on('error', err => {
      logForDebugging(`SOCKS bridge process error: ${err}`, { level: 'error' })
    })
    socksBridgeProcess.on('exit', (code, signal) => {
      logForDebugging(
        `SOCKS bridge process exited with code ${code}, signal ${signal}`,
        { level: code === 0 ? 'info' : 'error' },
      )
    })

    if (!socksBridgeProcess.pid) {
      // Clean up HTTP bridge
      if (httpBridgeProcess.pid) {
        try {
          process.kill(httpBridgeProcess.pid, 'SIGTERM')
        } catch {
          // Ignore errors
        }
      }
      throw new Error('Failed to start SOCKS bridge process')
    }
  }

  // Wait for both sockets to be ready
  const maxAttempts = 5
  for (let i = 0; i < maxAttempts; i++) {
    if (
      !httpBridgeProcess.pid ||
      httpBridgeProcess.killed ||
      !socksBridgeProcess.pid ||
      socksBridgeProcess.killed
    ) {
      throw new Error('Linux bridge process died unexpectedly')
    }

    try {
      // fs already imported
      if (fs.existsSync(httpSocketPath) && fs.existsSync(socksSockPath)) {
        logForDebugging(`Linux bridges ready after ${i + 1} attempts`)
        break
      }
    } catch (err) {
      logForDebugging(`Error checking sockets (attempt ${i + 1}): ${err}`, {
        level: 'error',
      })
    }

    if (i === maxAttempts - 1) {
      // Clean up both processes
      if (httpBridgeProcess.pid) {
        try {
          process.kill(httpBridgeProcess.pid, 'SIGTERM')
        } catch {
          // Ignore errors
        }
      }
      if (socksBridgeProcess.pid) {
        try {
          process.kill(socksBridgeProcess.pid, 'SIGTERM')
        } catch {
          // Ignore errors
        }
      }
      throw new Error(
        `Failed to create bridge sockets after ${maxAttempts} attempts`,
      )
    }

    await new Promise(resolve => setTimeout(resolve, i * 100))
  }

  return {
    httpSocketPath,
    socksSocketPath: socksSockPath,
    httpBridgeProcess,
    socksBridgeProcess,
    httpProxyPort,
    socksProxyPort,
  }
}

/**
 * Resolve how to invoke apply-seccomp: either a standalone binary path, or a
 * multicall-binary prefix that dispatches on the ARGV0 env var.
 *
 * Returns a shell-ready string ending in a trailing space — callers append
 * quote([shell, '-c', cmd]). Returns undefined when seccomp is
 * unavailable (no argv0, no binary found).
 *
 * When argv0 is set, applyPath is used verbatim (no existence check); the
 * caller is responsible for ensuring it resolves inside the bwrap namespace.
 */
function resolveApplySeccompPrefix(
  applyPath: string | undefined,
  argv0: string | undefined,
): string | undefined {
  if (argv0) {
    if (!applyPath) {
      throw new Error('seccompConfig.argv0 requires seccompConfig.applyPath')
    }
    return `ARGV0=${quote([argv0])} ${quote([applyPath])} `
  }
  const binary = getApplySeccompBinaryPath(applyPath)
  return binary ? `${quote([binary])} ` : undefined
}

/**
 * Build the command that runs inside the sandbox.
 * Sets up HTTP proxy on port 3128 and SOCKS proxy on port 1080
 */
function buildSandboxCommand(
  httpSocketPath: string,
  socksSocketPath: string,
  userCommand: string,
  applySeccompPrefix: string | undefined,
  shell?: string,
  socatPath?: string,
): string {
  // Default to bash for backward compatibility
  const shellPath = shell || 'bash'
  // Host filesystem is bind-mounted into the sandbox, so an explicit
  // socatPath resolves to the same binary inside bwrap.
  const socat = quote([socatPath ?? 'socat'])
  const socatCommands = [
    `${socat} TCP-LISTEN:3128,fork,reuseaddr UNIX-CONNECT:${httpSocketPath} >/dev/null 2>&1 &`,
    `${socat} TCP-LISTEN:1080,fork,reuseaddr UNIX-CONNECT:${socksSocketPath} >/dev/null 2>&1 &`,
    'trap "kill %1 %2 2>/dev/null; exit" EXIT',
  ]

  // apply-seccomp runs after socat so socat can still create Unix sockets.
  if (applySeccompPrefix) {
    const applySeccompCmd =
      applySeccompPrefix + quote([shellPath, '-c', userCommand])
    const innerScript = [...socatCommands, applySeccompCmd].join('\n')
    return `${shellPath} -c ${quote([innerScript])}`
  } else {
    const innerScript = [...socatCommands, `eval ${quote([userCommand])}`].join(
      '\n',
    )
    return `${shellPath} -c ${quote([innerScript])}`
  }
}

/**
 * bwrap cannot create a file bind mount point over a destination that is
 * itself a symlink — `--ro-bind /dev/null <symlink>` fails with "Can't create
 * file at <path>" and the whole command refuses to start. File read-deny
 * binds therefore target the symlink's resolved target instead: reads
 * through the symlink resolve to that target inside the mount namespace, so
 * the denied content stays covered. This matters for credential dotfiles
 * (~/.netrc, ~/.npmrc, …) that are commonly symlinks into a dotfile
 * manager's directory. Directory denies (`--tmpfs`) are left on the original
 * path: bwrap accepts those, and rewriting them would break allowRead
 * carve-outs expressed against the symlink path (e.g. /bin on usr-merged
 * systems).
 */
function resolveSymlinkDenyDest(normalizedPath: string): string {
  try {
    if (fs.lstatSync(normalizedPath).isSymbolicLink()) {
      return fs.realpathSync(normalizedPath)
    }
  } catch {
    // Dangling symlink or vanished path — keep the original.
  }
  return normalizedPath
}

/**
 * Mount a tmpfs over a read-denied directory, then restore the allowed write
 * paths and allowRead paths the tmpfs just wiped. Used by the denyRead loop
 * in generateFilesystemArgs and again when a late denyWrite ro-bind re-exposes
 * a read-denied directory and the tmpfs must be re-applied on top.
 */
function pushReadDenyDirMounts(
  args: string[],
  normalizedPath: string,
  allowedWritePaths: string[],
  readAllowPaths: string[],
): void {
  const denySep = normalizedPath === '/' ? '/' : normalizedPath + '/'
  args.push('--tmpfs', normalizedPath)

  // tmpfs wiped any earlier write binds under this path — restore them.
  for (const writePath of allowedWritePaths) {
    if (writePath.startsWith(denySep) || writePath === normalizedPath) {
      args.push('--bind', writePath, writePath)
      logForDebugging(
        `[Sandbox Linux] Re-bound write path wiped by denyRead tmpfs: ${writePath}`,
      )
    }
  }

  // Re-allow specific paths within the denied directory (allowRead overrides denyRead).
  // After mounting tmpfs over the denied dir, bind back the allowed subdirectories
  // so they are readable again.
  for (const allowPath of readAllowPaths) {
    if (allowPath.startsWith(denySep) || allowPath === normalizedPath) {
      if (!fs.existsSync(allowPath)) {
        logForDebugging(
          `[Sandbox Linux] Skipping non-existent read allow path: ${allowPath}`,
        )
        continue
      }
      // Skip only if a write path was re-bound just above AND covers
      // allowPath. A write path that's an ancestor of the deny dir isn't
      // re-bound (it wasn't wiped), so allowPath under it still needs
      // its own ro-bind here.
      if (
        allowedWritePaths.some(
          w =>
            (w.startsWith(denySep) || w === normalizedPath) &&
            (allowPath === w || allowPath.startsWith(w + '/')),
        )
      ) {
        continue
      }
      // Bind the allowed path back over the tmpfs so it's readable
      args.push('--ro-bind', allowPath, allowPath)
      logForDebugging(
        `[Sandbox Linux] Re-allowed read access within denied region: ${allowPath}`,
      )
    }
  }
}

/**
 * Generate filesystem bind mount arguments for bwrap
 */
async function generateFilesystemArgs(
  readConfig: FsReadRestrictionConfig | undefined,
  writeConfig: FsWriteRestrictionConfig | undefined,
  maskedFileBinds: Array<{ realPath: string; fakePath: string }> | undefined,
  maskedFileStoreDir: string | undefined,
  ripgrepConfig: { command: string; args?: string[] } = { command: 'rg' },
  mandatoryDenySearchDepth: number = DEFAULT_MANDATORY_DENY_SEARCH_DEPTH,
  allowGitConfig = false,
  abortSignal?: AbortSignal,
): Promise<string[]> {
  const args: string[] = []
  // fs already imported

  // Collect normalized allowed write paths. Populated in the writeConfig
  // block, read again in the denyRead loop to re-bind writes under tmpfs.
  const allowedWritePaths: string[] = []
  // denyWrite binds are buffered and emitted after denyRead processing so that
  // a denyRead tmpfs over an ancestor directory doesn't wipe them out.
  const denyWriteArgs: string[] = []
  // Directories that a deny entry re-binds read-only inside the sandbox
  // (--ro-bind <dir> <dir>), keyed by resolved dest, with every raw
  // (pre-resolution) spelling each was reached through. A non-existent deny
  // path whose deepest existing ancestor lies within one of these is already
  // uncreatable, and must not get a /dev/null stub: bwrap would have to
  // creat() the mount point inside that read-only mount and abort ("Can't
  // create file at <path>: Read-only file system"). An EXISTING deny path
  // strictly beneath one is likewise already unwritable and its own
  // --ro-bind <p> <p> is skipped as redundant. The spellings matter
  // because the emission filter and the denyRead re-application compare raw
  // spellings as well as the resolved dest, so the stub-skip guard tests a
  // covering directory in its canonical form AND every recorded spelling.
  const readOnlyDenyDirSpellings = new Map<string, Set<string>>()
  // dest → the pre-resolution deny path it came from. denyWrite dests are
  // canonicalized through symlinks but the denyRead tmpfs dirs and the write
  // binds they are later compared against are not, so a dest reached via a
  // symlink no longer matches them by string prefix. Both spellings name the
  // same inode once bwrap resolves them, so the comparisons below test both.
  const denyWriteRawDests = new Map<string, string>()

  // Determine initial root mount based on write restrictions
  if (writeConfig) {
    // Write restrictions: Start with read-only root, then allow writes to specific paths
    args.push('--ro-bind', '/', '/')

    // Allow writes to specific paths
    for (const pathPattern of writeConfig.allowOnly || []) {
      // Trailing slashes are stripped HERE, at the single point where allow
      // paths are bound and recorded, because every downstream comparison —
      // the deny loop's within-allowlist gate, findSymlinkInPath's mask
      // scoping, the emission filter's re-expose check, the denyRead
      // re-bind and its allowRead skip, and the stub-skip vetoes — matches
      // by `allowedPath + '/'` prefix, which a preserved trailing slash
      // ('<dir>//') silently defeats. bwrap binds 'dir' and 'dir/'
      // identically, so normalizing the recorded spelling fixes every
      // consumer at once instead of per-predicate. ('/' itself is kept.)
      const normalizedPath =
        normalizePathForSandbox(pathPattern).replace(/\/+$/, '') || '/'

      logForDebugging(
        `[Sandbox Linux] Processing write path: ${pathPattern} -> ${normalizedPath}`,
      )

      // Skip /dev/* paths since --dev /dev already handles them
      if (normalizedPath.startsWith('/dev/')) {
        logForDebugging(`[Sandbox Linux] Skipping /dev path: ${normalizedPath}`)
        continue
      }

      if (!fs.existsSync(normalizedPath)) {
        logForDebugging(
          `[Sandbox Linux] Skipping non-existent write path: ${normalizedPath}`,
        )
        continue
      }

      // Check if path is a symlink pointing outside expected boundaries
      // bwrap follows symlinks, so --bind on a symlink makes the target writable
      // This could unexpectedly expose paths the user didn't intend to allow
      try {
        const resolvedPath = fs.realpathSync(normalizedPath)
        // Trim trailing slashes before comparing: realpathSync never returns
        // a trailing slash, but normalizedPath may have one, which would cause
        // a false mismatch and incorrectly treat the path as a symlink.
        const normalizedForComparison = normalizedPath.replace(/\/+$/, '')
        if (
          resolvedPath !== normalizedForComparison &&
          isSymlinkOutsideBoundary(normalizedPath, resolvedPath)
        ) {
          logForDebugging(
            `[Sandbox Linux] Skipping symlink write path pointing outside expected location: ${pathPattern} -> ${resolvedPath}`,
          )
          continue
        }
      } catch {
        // realpathSync failed - path might not exist or be accessible, skip it
        logForDebugging(
          `[Sandbox Linux] Skipping write path that could not be resolved: ${normalizedPath}`,
        )
        continue
      }

      args.push('--bind', normalizedPath, normalizedPath)
      allowedWritePaths.push(normalizedPath)
    }

    // Inputs for the covering-directory vetoes, computed at most once and
    // only when a deny path (absent or existing) lies strictly beneath a
    // recorded read-only deny dir — commands with no such covering directory
    // skip the extra stat/realpath/readdir syscalls entirely. Lazy
    // evaluation also means the derivation runs from inside the deny loop,
    // AFTER the (unbounded) mandatory-deny ripgrep await below, keeping the
    // snapshot as close as possible to the denyRead loop that later acts on
    // the real filesystem.
    //
    // allowedWritePathsBothForms: allowWrite paths in their recorded and
    // realpath-canonical spellings. The canonical form is re-resolved HERE,
    // not reused from the allow loop's earlier resolution, deliberately: the
    // getter runs after the (unbounded) mandatory-deny scan, and a fresh
    // realpath sees an allow path whose symlink target changed during that
    // window — the fail-closed direction, since a link now pointing into a
    // covering deny dir must veto the skip. The guard's veto compares deny
    // dests (always canonical) against allow paths, so it keeps both
    // domains.
    //
    // prospectiveReadDenyTmpfsDirsBothForms: the tmpfs targets the denyRead
    // loop below will actually mount, derived the way that loop derives them
    // — expand a '/' entry into the root's children (minus proc/dev/sys), add
    // /etc/ssh/ssh_config.d when present, and keep only entries that exist as
    // directories (the loop skips absent entries and gives file entries a
    // read-only /dev/null mask instead of a tmpfs) — in raw and canonical
    // spellings. A read-denied tmpfs at or under a covering deny dir is the
    // TRIGGER for the post-denyWrite writable re-application, and a deny bind
    // whose dest sits under one can be dropped by the emission filter — both
    // facts feed the guard.
    let stubSkipVetoInputs:
      | {
          allowedWritePathsBothForms: string[]
          prospectiveReadDenyTmpfsDirsBothForms: string[]
        }
      | undefined
    const getStubSkipVetoInputs = (): NonNullable<
      typeof stubSkipVetoInputs
    > => {
      if (stubSkipVetoInputs !== undefined) {
        return stubSkipVetoInputs
      }
      const allowedWritePathsBothForms: string[] = []
      for (const writePath of allowedWritePaths) {
        allowedWritePathsBothForms.push(writePath)
        try {
          const canonical = fs.realpathSync(writePath)
          if (canonical !== writePath) {
            allowedWritePathsBothForms.push(canonical)
          }
        } catch {
          // vanished since the allow loop: the recorded form suffices
        }
      }
      const prospectiveReadDenyTmpfsDirsBothForms: string[] = []
      if (readConfig) {
        const effectiveReadDenyPaths: string[] = []
        const rootSkipForGuard = new Set(['proc', 'dev', 'sys'])
        for (const denyReadPattern of readConfig.denyOnly || []) {
          if (normalizePathForSandbox(denyReadPattern) === '/') {
            try {
              for (const child of fs.readdirSync('/')) {
                if (!rootSkipForGuard.has(child))
                  effectiveReadDenyPaths.push('/' + child)
              }
            } catch {
              // Unreadable root: contribute nothing. (The denyRead loop has
              // no catch and would abort the whole wrap, so an
              // under-predicted tmpfs set here can never reach a running
              // sandbox.)
            }
          } else {
            effectiveReadDenyPaths.push(denyReadPattern)
          }
        }
        if (fs.existsSync('/etc/ssh/ssh_config.d')) {
          effectiveReadDenyPaths.push('/etc/ssh/ssh_config.d')
        }
        for (const effectiveReadDenyPath of effectiveReadDenyPaths) {
          const denyReadPath = normalizePathForSandbox(effectiveReadDenyPath)
          let isDirectory = false
          try {
            isDirectory = fs.statSync(denyReadPath).isDirectory()
          } catch {
            continue // absent: the denyRead loop skips it — no tmpfs, no trigger
          }
          if (!isDirectory) {
            continue // a file gets a read-only /dev/null mask, never a tmpfs
          }
          prospectiveReadDenyTmpfsDirsBothForms.push(denyReadPath)
          try {
            const canonical = fs.realpathSync(denyReadPath)
            if (canonical !== denyReadPath) {
              prospectiveReadDenyTmpfsDirsBothForms.push(canonical)
            }
          } catch {
            // vanished between the stat and here: the raw form suffices
          }
        }
      }
      stubSkipVetoInputs = {
        allowedWritePathsBothForms,
        prospectiveReadDenyTmpfsDirsBothForms,
      }
      return stubSkipVetoInputs
    }
    // The ONE predicate deciding whether a deny dest lies inside the write
    // allowlist. The read-only pre-pass below and the loop's --ro-bind gate
    // MUST share it: the pre-pass is only sound if it records exactly the
    // directories the loop re-binds read-only (a recorded directory that is
    // never re-bound read-only would suppress stubs unsafely; a re-bound
    // directory missing from the record only costs an abort). No spelling
    // handling is needed here: allowedWritePaths entries are recorded with
    // trailing slashes stripped, and candidates are resolved deny dests.
    const isWithinAnyAllowedWritePath = (candidatePath: string): boolean =>
      allowedWritePaths.some(
        allowedPath =>
          candidatePath.startsWith(allowedPath + '/') ||
          candidatePath === allowedPath,
      )

    // Deny writes within allowed paths (user-specified + mandatory denies)
    const denyPaths = [
      ...(writeConfig.denyWithinAllow || []),
      ...(await linuxGetMandatoryDenyPaths(
        ripgrepConfig,
        mandatoryDenySearchDepth,
        allowGitConfig,
        abortSignal,
      )),
    ]

    // Duplicate deny entries must be collapsed: a duplicate
    // --ro-bind /dev/null <dest> hits a char device on the second pass and
    // bwrap's ensure_file() falls through to creat() on a read-only mount.
    const seenDenyWrite = new Set<string>()
    // PRE-PASS (order-independent): record the directories the loop below
    // re-binds read-only, BEFORE any stub decision, so the read-only
    // conclusion does not depend on where an enclosing directory appears in
    // the caller's denyWrite ordering. It applies the loop's own resolution,
    // the same symlink re-check, and the same isWithinAnyAllowedWritePath
    // gate as the --ro-bind emission, and it records every raw spelling each
    // directory is reached through. A recorded directory is EVIDENCE for
    // skipping a stub only if it also passes the guard's vetoes below (no
    // allowed write path strictly beneath it; incomparable with every
    // read-deny tmpfs in any spelling), which exclude every way its subtree
    // could be writable in the sandbox. Keep the two passes in lockstep: a
    // directory recorded here but never re-bound read-only AND not vetoed
    // would suppress stubs unsafely, while an emitted one missing from the
    // record only costs a spurious abort.
    for (const pathPattern of denyPaths) {
      const rawPath = normalizePathForSandbox(pathPattern)
      if (rawPath.startsWith('/dev/')) {
        continue
      }
      const resolvedPath = resolveSymlinkedDenyPath(rawPath)
      if (resolvedPath === null || resolvedPath.startsWith('/dev/')) {
        continue
      }
      // Same defense-in-depth re-check as the loop: there the --ro-bind is
      // replaced by a symlink mask, so such a directory must not be recorded
      // as re-bound here.
      if (findSymlinkInPath(resolvedPath, allowedWritePaths)) {
        continue
      }
      let isDirectory = false
      try {
        isDirectory = fs.statSync(resolvedPath).isDirectory()
      } catch {
        continue // absent (or vanished): not a read-only re-bound directory
      }
      if (!isDirectory) {
        continue
      }
      if (isWithinAnyAllowedWritePath(resolvedPath)) {
        // Keep every spelling this dest is reached through (the emission
        // filter tests the first-seen raw spelling, which this pass cannot
        // assume, and the re-application matches raw tmpfs spellings): the
        // guard below treats the directory as unsafe if a read-deny tmpfs
        // contains ANY of them.
        let spellings = readOnlyDenyDirSpellings.get(resolvedPath)
        if (spellings === undefined) {
          spellings = new Set()
          readOnlyDenyDirSpellings.set(resolvedPath, spellings)
        }
        spellings.add(rawPath)
      }
    }
    // Per-covering-dir veto verdict, computed once per recorded directory
    // (the inputs never change during the deny loop) instead of per absent
    // deny entry.
    // INVARIANT: a stub, or an existing deny path's own bind, is skipped
    // only under a recorded covering deny directory that has no allowed
    // write path strictly beneath it and is INCOMPARABLE with every
    // read-deny tmpfs directory (neither at-or-beneath it nor containing it
    // or any spelling it was reached through). Containment is root-aware
    // (isAtOrUnder): '/' is a recordable covering directory when allowOnly
    // and denyWithinAllow both name it, and '/' + '/' is a prefix of
    // nothing, so a string-prefix test would judge it safe for every path
    // and drop the binds the re-application passes below key off.
    // Rationale: the only writable emissions that land after the
    // buffered read-only binds are the denyRead re-applications
    // (pushReadDenyDirMounts), which mount a tmpfs and re-bind allowed write
    // paths beneath it WITHOUT re-emitting the binds it buries — so a
    // comparable tmpfs is both the re-opening vector (beneath or around the
    // dir) and the only way the dir's own --ro-bind gets dropped at emission
    // as hidden-by-a-tmpfs. (The emission filter's other drop condition,
    // maskedFiles, holds file dests only — /dev/null read-deny masks and
    // credential-mask fakes — while the pre-pass stat-verifies every
    // recorded dir as a directory, so it cannot drop a recorded dir short of
    // a dir→file race, which ends in bwrap refusing to start, not a silent
    // gap.) Only existing read-deny directories become a tmpfs: absent and
    // file-level read-denies count for nothing. If any condition could
    // apply, keep the stub — the pre-existing abort is preferable to a
    // silently creatable deny path. (An allow path bound before the
    // denyWrite binds is not a vector by itself: the later read-only re-bind
    // lands on top of it.)
    const coveringDirUnsafeVerdicts = new Map<string, boolean>()
    const coveringDirIsUnsafe = (denyDir: string): boolean => {
      const cached = coveringDirUnsafeVerdicts.get(denyDir)
      if (cached !== undefined) {
        return cached
      }
      const {
        allowedWritePathsBothForms,
        prospectiveReadDenyTmpfsDirsBothForms,
      } = getStubSkipVetoInputs()
      const unsafe =
        // (i) an allowed write path strictly beneath the dir: the
        //     re-application's effect would re-bind it writable.
        allowedWritePathsBothForms.some(writePath =>
          isStrictlyUnder(writePath, denyDir),
        ) ||
        // (ii) a read-deny tmpfs at or beneath the dir: the re-application's
        //     trigger.
        prospectiveReadDenyTmpfsDirsBothForms.some(tmpfsDir =>
          isAtOrUnder(tmpfsDir, denyDir),
        ) ||
        // (iii) a read-deny tmpfs CONTAINING the dir or any raw spelling it
        //     was reached through: the dir's own --ro-bind can be dropped as
        //     hidden-by-the-tmpfs at emission, and a tmpfs above it can
        //     re-bind an allowed path around it — either way the directory
        //     is not reliably read-only in the sandbox.
        prospectiveReadDenyTmpfsDirsBothForms.some(tmpfsDir =>
          [denyDir, ...(readOnlyDenyDirSpellings.get(denyDir) ?? [])].some(
            spelling => isAtOrUnder(spelling, tmpfsDir),
          ),
        )
      coveringDirUnsafeVerdicts.set(denyDir, unsafe)
      return unsafe
    }
    // Materialized once: the pre-pass above fully populates the map and the
    // deny loop never mutates it.
    const readOnlyDenyDirs = [...readOnlyDenyDirSpellings.keys()]
    // Is `candidate` already unwritable in the sandbox: strictly under a
    // recorded read-only deny directory that survives every
    // coveringDirIsUnsafe veto? Strictly, because a deny equal to a recorded
    // directory IS that covering bind and must be emitted (an absent path
    // never equals one). Stops at the first vetoed covering directory.
    const coveredBySafeReadOnlyDenyDir = (candidate: string): boolean => {
      let covered = false
      for (const denyDir of readOnlyDenyDirs) {
        if (!isStrictlyUnder(candidate, denyDir)) continue
        if (coveringDirIsUnsafe(denyDir)) {
          // A vetoed '/' neither covers a path nor disqualifies an inner
          // recorded directory: everything lies beneath it, so it would
          // veto every skip and stub each absent mandatory-deny path of a
          // write-denied cwd after that cwd's own bind — the startup abort.
          // Its descendants are decided by their own recorded directories,
          // as before, when the string-prefix filter matched '/' only for a
          // path directly beneath it and the vetoes never fired for it.
          if (denyDir === '/') continue
          return false
        }
        covered = true
      }
      return covered
    }
    for (const pathPattern of denyPaths) {
      const rawPath = normalizePathForSandbox(pathPattern)

      // Skip /dev/* paths since --dev /dev already handles them
      if (rawPath.startsWith('/dev/')) {
        continue
      }

      // Resolve-before-mask: normalizePathForSandbox keeps the raw symlink
      // path whenever resolution crosses isSymlinkOutsideBoundary (the
      // common dotfiles case), so canonicalize here. Every mask/bind below
      // must be computed against the resolved path — bwrap dest-resolves
      // symlinks, so a mask on the raw path either aborts startup (dir
      // symlink) or lands on the target inode anyway (file symlink). Writes
      // through the original symlinked path resolve to the same denied
      // target inside the mount namespace.
      const normalizedPath = resolveSymlinkedDenyPath(rawPath)
      if (normalizedPath === null) {
        // Unresolvable: a symlink cycle, or a chain past the ELOOP bound.
        // Fail closed. Dropping the deny here would sandbox the command with
        // the path unprotected, so instead mask the symlink component and let
        // bwrap refuse to start. When no component is a symlink inside an
        // allowed write path there is nothing to protect: the path is already
        // read-only from the initial --ro-bind / /.
        const unresolvableSymlink = findSymlinkInPath(
          rawPath,
          allowedWritePaths,
        )
        if (unresolvableSymlink && !seenDenyWrite.has(unresolvableSymlink)) {
          seenDenyWrite.add(unresolvableSymlink)
          denyWriteArgs.push('--ro-bind', '/dev/null', unresolvableSymlink)
          denyWriteRawDests.set(unresolvableSymlink, rawPath)
        }
        logForDebugging(
          `[Sandbox Linux] Deny path could not be resolved through symlinks, failing closed: ${rawPath}`,
        )
        continue
      }
      if (normalizedPath !== rawPath) {
        logForDebugging(
          `[Sandbox Linux] Resolved symlinked deny path: ${rawPath} -> ${normalizedPath}`,
        )
      }

      // Re-check after resolution: a deny path can only now land in /dev (e.g.
      // a symlink into it), where --dev /dev has already replaced the tree and
      // a bind would either miss or fight the new devtmpfs.
      if (normalizedPath.startsWith('/dev/')) {
        continue
      }

      // Dedup post-resolution: distinct spellings (tilde vs absolute, via
      // symlink vs direct) converge to the same real path here.
      if (seenDenyWrite.has(normalizedPath)) continue
      seenDenyWrite.add(normalizedPath)

      // Defense-in-depth: the resolved path should be symlink-free for its
      // existing prefix, but the tree may change between resolution and this
      // check. A hit still fails closed — bwrap refuses to start rather than
      // sandboxing with an unprotected deny path.
      const symlinkInPath = findSymlinkInPath(normalizedPath, allowedWritePaths)
      if (symlinkInPath) {
        if (!seenDenyWrite.has(symlinkInPath)) {
          seenDenyWrite.add(symlinkInPath)
          denyWriteArgs.push('--ro-bind', '/dev/null', symlinkInPath)
          denyWriteRawDests.set(symlinkInPath, rawPath)
        }
        logForDebugging(
          `[Sandbox Linux] Mounted /dev/null at symlink ${symlinkInPath} to prevent symlink replacement attack`,
        )
        continue
      }

      // Handle non-existent paths by mounting /dev/null to block creation.
      // Without this, a sandboxed process could mkdir+write a denied path that
      // doesn't exist yet, bypassing the deny rule entirely.
      //
      // bwrap creates empty files on the host as mount points for these binds.
      // We track them in bwrapMountPoints so cleanupBwrapMountPoints() can
      // remove them after the command exits.
      if (!fs.existsSync(normalizedPath)) {
        // Fix 1 (worktree): If any existing component in the deny path is a
        // file (not a directory), skip the deny entirely. You can't mkdir
        // under a file, so the deny path can never be created. This handles
        // git worktrees where .git is a file.
        if (hasFileAncestor(normalizedPath)) {
          logForDebugging(
            `[Sandbox Linux] Skipping deny path with file ancestor (cannot create paths under a file): ${normalizedPath}`,
          )
          continue
        }

        // Find the deepest existing ancestor directory
        let ancestorPath = path.dirname(normalizedPath)
        while (ancestorPath !== '/' && !fs.existsSync(ancestorPath)) {
          ancestorPath = path.dirname(ancestorPath)
        }

        // Only protect if the existing ancestor is within an allowed write path.
        // If not, the path is already read-only from --ro-bind / /.
        // Same predicate as the pre-pass and the --ro-bind gate (equality on
        // the absent normalizedPath itself is unreachable — allow entries
        // exist, the deny path does not).
        const ancestorIsWithinAllowedPath =
          isWithinAnyAllowedWritePath(ancestorPath) ||
          isWithinAnyAllowedWritePath(normalizedPath)

        // An ancestor inside a directory that an earlier deny re-bound
        // read-only (e.g. an explicit denyWrite on the project dir) is
        // already read-only in the sandbox: the deny path cannot be created
        // there, and stubbing it would make bwrap creat() a mount point
        // inside that read-only mount and abort. The order-independent
        // pre-pass above has already recorded every directory the loop
        // re-binds read-only, so a covering directory deny is visible here
        // regardless of where it appears in denyPaths. A recorded covering
        // directory is evidence for skipping only if it survives the
        // coveringDirIsUnsafe vetoes (see the INVARIANT at its definition).
        // (Tested on the absent path itself: a recorded directory that
        // covers it is at-or-above its deepest existing ancestor, since
        // recorded directories exist.)
        const ancestorIsWithinReadOnlyDeny =
          coveredBySafeReadOnlyDenyDir(normalizedPath)

        if (ancestorIsWithinAllowedPath && !ancestorIsWithinReadOnlyDeny) {
          const firstNonExistent = findFirstNonExistentComponent(normalizedPath)

          // Fix 2: If firstNonExistent is an intermediate component (not the
          // leaf deny path itself), mount a read-only empty directory instead
          // of /dev/null. This prevents the component from appearing as a file
          // which breaks tools that expect to traverse it as a directory.
          if (firstNonExistent !== normalizedPath) {
            const emptyDir = fs.mkdtempSync(
              path.join(tmpdir(), 'claude-empty-'),
            )
            denyWriteArgs.push('--ro-bind', emptyDir, firstNonExistent)
            denyWriteRawDests.set(firstNonExistent, rawPath)
            bwrapMountPoints.add(firstNonExistent)
            registerExitCleanupHandler()
            logForDebugging(
              `[Sandbox Linux] Mounted empty dir at ${firstNonExistent} to block creation of ${normalizedPath}`,
            )
          } else {
            denyWriteArgs.push('--ro-bind', '/dev/null', firstNonExistent)
            denyWriteRawDests.set(firstNonExistent, rawPath)
            bwrapMountPoints.add(firstNonExistent)
            registerExitCleanupHandler()
            logForDebugging(
              `[Sandbox Linux] Mounted /dev/null at ${firstNonExistent} to block creation of ${normalizedPath}`,
            )
          }
        } else if (ancestorIsWithinReadOnlyDeny) {
          logForDebugging(
            `[Sandbox Linux] Skipping non-existent deny path inside a read-only denied directory (already uncreatable): ${normalizedPath}`,
          )
        } else {
          logForDebugging(
            `[Sandbox Linux] Skipping non-existent deny path not within allowed paths: ${normalizedPath}`,
          )
        }
        continue
      }

      // Only add deny binding if this path is within an allowed write path
      // Otherwise it's already read-only from the initial --ro-bind / /
      const isWithinAllowedPath = isWithinAnyAllowedWritePath(normalizedPath)

      if (isWithinAllowedPath) {
        // Already unwritable under a read-only denied directory (the
        // existing-path twin of the stub skip above). Veto (iii) keeps the
        // covering bind through the emission filter; a symlinked spelling
        // keeps its own bind because the re-application passes below key
        // off emitted raw spellings.
        if (
          rawPath === normalizedPath &&
          coveredBySafeReadOnlyDenyDir(normalizedPath)
        ) {
          logForDebugging(
            `[Sandbox Linux] Skipping deny path already under read-only denied directory: ${normalizedPath}`,
          )
          continue
        }
        denyWriteArgs.push('--ro-bind', normalizedPath, normalizedPath)
        denyWriteRawDests.set(normalizedPath, rawPath)
      } else {
        logForDebugging(
          `[Sandbox Linux] Skipping deny path not within allowed paths: ${normalizedPath}`,
        )
      }
    }
  } else {
    // No write restrictions: Allow all writes
    args.push('--bind', '/', '/')
  }
  // denyWriteArgs is emitted after the denyRead loop below.

  // Handle read restrictions by mounting tmpfs over denied paths.
  // Non-glob spellings arrive slash-free from normalizePathForSandbox — the
  // comparisons below (hidden-by-tmpfs prefixes, the exact-match allowRead
  // skip, pushReadDenyDirMounts' re-bind checks) depend on that.
  const readDenyPaths: string[] = []
  const readAllowPaths = (readConfig?.allowWithinDeny || []).map(p =>
    normalizePathForSandbox(p),
  )
  // Files masked by --ro-bind <source> <dest> below. Map of dest → source
  // (/dev/null for read-deny, the sentinel fake for credential mask). Used
  // to filter denyWriteArgs so that --ro-bind <host> <host> doesn't undo
  // the mask, and to re-apply the correct source if a denyWrite ancestor
  // bind re-exposes the dest.
  const maskedFiles = new Map<string, string>()
  // Directories masked by --tmpfs below, in emission (shallow-first) order.
  // Used to filter denyWriteArgs the same way: a dir in both deny lists must
  // not get its host contents re-bound on top of its own tmpfs.
  const tmpfsDirs: string[] = []

  // --tmpfs / would wipe all prior mounts (ro-bind /, write binds, deny binds).
  // Expand a root deny into its direct children so the existing per-dir tmpfs
  // + re-bind logic applies. Skip /proc and /dev: they're remounted by the
  // caller after this function returns. Skip /sys: kernel interface, tmpfs
  // over it breaks tooling and the host /sys is already read-only via ro-bind.
  const rootSkip = new Set(['proc', 'dev', 'sys'])
  for (const p of readConfig?.denyOnly || []) {
    if (normalizePathForSandbox(p) === '/') {
      for (const child of fs.readdirSync('/')) {
        if (!rootSkip.has(child)) readDenyPaths.push('/' + child)
      }
    } else {
      readDenyPaths.push(p)
    }
  }

  // Always hide /etc/ssh/ssh_config.d to avoid permission issues with OrbStack
  // SSH is very strict about config file permissions and ownership, and they can
  // appear wrong inside the sandbox causing "Bad owner or permissions" errors
  //
  // Skipped when readConfig is undefined (filesystem.disabled): no read
  // policy means no implicit read denies either.
  if (readConfig && fs.existsSync('/etc/ssh/ssh_config.d')) {
    readDenyPaths.push('/etc/ssh/ssh_config.d')
  }

  // Normalize then sort shallow-first so tmpfs over ancestor dirs lands before
  // /dev/null masks on descendant files. Otherwise a file-deny listed before
  // a dir-deny in denyRead gets wiped when the ancestor tmpfs is applied.
  const normalizedDenyPaths = readDenyPaths
    .map(p => normalizePathForSandbox(p))
    .sort((a, b) => a.split('/').length - b.split('/').length)

  for (const normalizedPath of normalizedDenyPaths) {
    if (!fs.existsSync(normalizedPath)) {
      logForDebugging(
        `[Sandbox Linux] Skipping non-existent read deny path: ${normalizedPath}`,
      )
      continue
    }

    const readDenyStat = fs.statSync(normalizedPath)
    if (readDenyStat.isDirectory()) {
      tmpfsDirs.push(normalizedPath)
      pushReadDenyDirMounts(
        args,
        normalizedPath,
        allowedWritePaths,
        readAllowPaths,
      )
    } else {
      // For files, only an exact allowRead match overrides the deny. A
      // directory allowRead does not un-deny a file specifically listed in
      // denyRead — otherwise denyRead: ['.env'] + allowRead: ['.'] silently
      // drops the .env deny.
      if (readAllowPaths.includes(normalizedPath)) {
        logForDebugging(
          `[Sandbox Linux] Skipping read deny for re-allowed path: ${normalizedPath}`,
        )
        continue
      }
      // For files, bind /dev/null instead of tmpfs. bwrap rejects symlink
      // bind destinations, so the deny bind lands on the resolved target.
      const denyDest = resolveSymlinkDenyDest(normalizedPath)
      args.push('--ro-bind', '/dev/null', denyDest)
      maskedFiles.set(denyDest, '/dev/null')
      maskedFiles.set(normalizedPath, '/dev/null')
    }
  }

  // Whole-file credential masks: same bind shape as a file read-deny,
  // but the source is the sentinel-content fake instead of /dev/null.
  // realPath was already normalized (tilde-expanded, realpath'd) by the
  // caller; resolveSymlinkDenyDest covers the symlinked-credential case
  // for the same reason as above. The fake's parent dir is explicitly
  // ro-bound at the end of this function, so the bind source is never
  // writable from inside the sandbox. Adding the dest to maskedFiles
  // ensures a later denyWrite ro-bind over the same path doesn't undo
  // the mask.
  for (const { realPath, fakePath } of maskedFileBinds ?? []) {
    const dest = resolveSymlinkDenyDest(realPath)
    args.push('--ro-bind', fakePath, dest)
    maskedFiles.set(dest, fakePath)
    maskedFiles.set(realPath, fakePath)
  }

  // Emitting denyWrite last means these ro-binds layer on top of any write
  // paths the denyRead loop just re-bound. Before this ordering, tmpfs over
  // an ancestor of cwd would wipe the .git/hooks protection. But skip any
  // dest already masked by denyRead:
  //
  // - file masks: --ro-bind <host> <host> for denyWrite would undo
  //   --ro-bind /dev/null <host> from denyRead, which landed first.
  // - tmpfs dirs: a dest at or under a denyRead tmpfs is already hidden, and
  //   re-binding the host path on top of the tmpfs would expose the real
  //   (read-denied) contents read-only. Writes inside the tmpfs never reach
  //   the host, so the write-deny stays enforced without the bind. Exception:
  //   if an allowed write path at-or-under that tmpfs covers the dest, the
  //   denyRead loop re-bound it (the .git/hooks case) and the write-deny bind
  //   is still required on top.
  // tmpfsDirs and allowedWritePaths hold unresolved paths while dest has been
  // canonicalized, so each dest is tested under both spellings: they name the
  // same inode after bwrap resolves the mount destinations, and a hit on
  // either means the tmpfs really does cover this bind.
  const isHiddenByTmpfs = (dest: string): boolean =>
    tmpfsDirs.some(tmpfsDir => {
      const underTmpfs = dest === tmpfsDir || dest.startsWith(tmpfsDir + '/')
      if (!underTmpfs) return false
      const reExposedByWriteBind = allowedWritePaths.some(
        writePath =>
          (writePath === tmpfsDir || writePath.startsWith(tmpfsDir + '/')) &&
          (dest === writePath || dest.startsWith(writePath + '/')),
      )
      return !reExposedByWriteBind
    })

  const emittedDenyWriteDests: string[] = []
  for (let i = 0; i < denyWriteArgs.length; i += 3) {
    const dest = denyWriteArgs[i + 2]!
    const rawDest = denyWriteRawDests.get(dest) ?? dest
    if (maskedFiles.has(dest)) continue
    if (isHiddenByTmpfs(dest) || isHiddenByTmpfs(rawDest)) {
      logForDebugging(
        `[Sandbox Linux] Skipping denyWrite bind already hidden by denyRead tmpfs: ${dest}`,
      )
      continue
    }
    args.push(denyWriteArgs[i]!, denyWriteArgs[i + 1]!, dest)
    emittedDenyWriteDests.push(dest)
    // The tmpfs / mask re-application passes below ask "does this bind sit
    // above a read-denied path?". A bind at the resolved dest also re-exposes
    // anything under the symlinked spelling, so record both.
    if (rawDest !== dest) emittedDenyWriteDests.push(rawDest)
  }

  // The inverse stacking problem: a denyWrite ro-bind whose dest strictly
  // contains a read-denied dir re-exposes that dir's real contents (the bind
  // landed after the tmpfs). Re-apply the tmpfs on top, with the same write
  // and allowRead re-binds the denyRead loop emitted. A bind of '/' itself
  // (allowOnly and denyWithinAllow both naming it) contains every one of
  // them, so containment is root-aware.
  for (const tmpfsDir of tmpfsDirs) {
    if (emittedDenyWriteDests.some(dest => isStrictlyUnder(tmpfsDir, dest))) {
      logForDebugging(
        `[Sandbox Linux] Re-applying denyRead tmpfs re-exposed by denyWrite bind: ${tmpfsDir}`,
      )
      pushReadDenyDirMounts(args, tmpfsDir, allowedWritePaths, readAllowPaths)
    }
  }
  // Same problem for masked files: the mask landed before the denyWrite
  // ancestor bind, so the real file is back. Re-apply the mask with its
  // original source (/dev/null for read-deny, the fake for credential mask).
  for (const [maskedFile, source] of maskedFiles) {
    if (emittedDenyWriteDests.some(dest => isStrictlyUnder(maskedFile, dest))) {
      // maskedFiles holds both the symlink path and its resolved target so
      // the denyWrite skip-check above matches either. Re-emission must go
      // to the target only — bwrap rejects a symlink bind dest (see
      // resolveSymlinkDenyDest), and the target is masked independently:
      // either its original mask survived (target outside this denyWrite
      // ancestor) or its own iteration re-emits it here.
      if (resolveSymlinkDenyDest(maskedFile) !== maskedFile) continue
      logForDebugging(
        `[Sandbox Linux] Re-applying file mask re-exposed by denyWrite bind: ${maskedFile}`,
      )
      args.push('--ro-bind', source, maskedFile)
    }
  }

  // INVARIANT: the fake-file store directory must never be writable from
  // inside the sandbox. If it were, a sandboxed process could plant a
  // symlink at a fake path and a later host-side write() would follow it,
  // or replace a fake's content so the bind exposes attacker bytes. Emit
  // last so it overlays any earlier --bind that covers the store dir
  // (e.g. allowWrite: ['/tmp'] when the store is under os.tmpdir()).
  if (maskedFileStoreDir !== undefined) {
    args.push('--ro-bind', maskedFileStoreDir, maskedFileStoreDir)
  }

  return args
}

/**
 * Wrap a command with sandbox restrictions on Linux
 *
 * UNIX SOCKET BLOCKING (APPLY-SECCOMP):
 * This implementation uses a custom apply-seccomp binary to block Unix domain socket
 * creation for user commands while allowing network infrastructure:
 *
 * Stage 1: Outer bwrap - Network and filesystem isolation (NO seccomp)
 *   - Bubblewrap starts with isolated network namespace (--unshare-net)
 *   - Bubblewrap applies PID namespace isolation (--unshare-pid and --proc)
 *   - Filesystem restrictions are applied (read-only mounts, bind mounts, etc.)
 *   - Socat processes start and connect to Unix socket bridges (can use socket(AF_UNIX, ...))
 *
 * Stage 2: apply-seccomp - Nested PID namespace + seccomp filter
 *   - apply-seccomp creates a nested user+PID+mount namespace and remounts /proc
 *   - Inside, apply-seccomp becomes PID 1 (non-dumpable init/reaper)
 *   - Forks, sets PR_SET_NO_NEW_PRIVS, applies seccomp via prctl(PR_SET_SECCOMP)
 *   - Execs user command with seccomp active (cannot create new Unix sockets)
 *   - User command cannot see or ptrace bwrap/bash/socat (separate PID namespace)
 *
 * This solves the conflict between:
 * - Security: Blocking arbitrary Unix socket creation in user commands
 * - Functionality: Network sandboxing requires socat to call socket(AF_UNIX, ...) for bridge connections
 *
 * The seccomp-bpf filter blocks socket(AF_UNIX, ...) syscalls, preventing:
 * - Creating new Unix domain socket file descriptors
 *
 * Security limitations:
 * - Does NOT block operations (bind, connect, sendto, etc.) on inherited Unix socket FDs
 * - Does NOT prevent passing Unix socket FDs via SCM_RIGHTS
 * - For most sandboxing use cases, blocking socket creation is sufficient
 *
 * The filter allows:
 * - All TCP/UDP sockets (AF_INET, AF_INET6) for normal network operations
 * - All other syscalls
 *
 * PLATFORM NOTE:
 * The allowUnixSockets configuration is not path-based on Linux (unlike macOS)
 * because seccomp-bpf cannot inspect user-space memory to read socket paths.
 *
 * Requirements for seccomp filtering:
 * - Pre-built apply-seccomp binaries are included for x64 and ARM64
 * - Pre-generated BPF filters are included for x64 and ARM64
 * - Other architectures are not currently supported (no apply-seccomp binary available)
 * - To use sandboxing without Unix socket blocking on unsupported architectures,
 *   set allowAllUnixSockets: true in your configuration
 * Dependencies are checked by checkLinuxDependencies() before enabling the sandbox.
 */
export async function wrapCommandWithSandboxLinux(
  params: LinuxSandboxParams,
): Promise<string> {
  const {
    command,
    commandId,
    needsNetworkRestriction,
    httpSocketPath,
    socksSocketPath,
    httpProxyPort,
    socksProxyPort,
    proxyAuthToken,
    caCertPath,
    javaAgentJarPath,
    readConfig,
    writeConfig,
    unsetEnvVars,
    setEnvVars,
    maskedFileBinds,
    maskedFileStoreDir,
    enableWeakerNestedSandbox,
    allowAllUnixSockets,
    binShell,
    ripgrepConfig = { command: 'rg' },
    mandatoryDenySearchDepth = DEFAULT_MANDATORY_DENY_SEARCH_DEPTH,
    allowGitConfig = false,
    gitSafeDirectories,
    seccompConfig,
    bwrapPath,
    socatPath,
    observeSocketPath,
    abortSignal,
  } = params

  // Determine if we have restrictions to apply
  // Read: denyOnly pattern - empty array means no restrictions
  // Write: allowOnly pattern - undefined means no restrictions, any config means restrictions
  const hasReadRestrictions =
    (readConfig && readConfig.denyOnly.length > 0) ||
    (maskedFileBinds !== undefined && maskedFileBinds.length > 0)
  const hasWriteRestrictions = writeConfig !== undefined
  const hasEnvRestrictions =
    (unsetEnvVars !== undefined && unsetEnvVars.length > 0) ||
    (setEnvVars !== undefined && Object.keys(setEnvVars).length > 0)
  const hasGitConfig = (gitSafeDirectories?.length ?? 0) > 0

  // Check if we need any sandboxing
  if (
    !needsNetworkRestriction &&
    !hasReadRestrictions &&
    !hasWriteRestrictions &&
    !hasEnvRestrictions &&
    !hasGitConfig
  ) {
    return command
  }

  // Mark this sandbox invocation as active. cleanupBwrapMountPoints() will
  // defer file deletion until this (and every other concurrent) invocation
  // has been cleaned up. The matching decrement happens in
  // cleanupBwrapMountPoints(), which the caller must invoke after the
  // spawned command exits. If wrapping fails below, the catch block
  // decrements so the count does not leak.
  activeSandboxCount++

  const bwrapArgs: string[] = ['--new-session', '--die-with-parent']
  let applySeccompPrefix: string | undefined

  try {
    // ========== SECCOMP FILTER (Unix Socket Blocking) ==========
    // apply-seccomp wraps the workload and applies the baked-in BPF filter
    // that blocks socket(AF_UNIX, ...). Skipped when allowAllUnixSockets is true.
    if (!allowAllUnixSockets) {
      applySeccompPrefix = resolveApplySeccompPrefix(
        seccompConfig?.applyPath,
        seccompConfig?.argv0,
      )

      if (!applySeccompPrefix) {
        logForDebugging(
          '[Sandbox Linux] apply-seccomp binary not available - unix socket blocking disabled. ' +
            'Install @anthropic-ai/sandbox-runtime globally for full protection.',
          { level: 'warn' },
        )
      } else {
        logForDebugging(
          '[Sandbox Linux] Applying seccomp filter for Unix socket blocking',
        )
      }
    } else {
      logForDebugging(
        '[Sandbox Linux] Skipping seccomp filter - allowAllUnixSockets is enabled',
      )
    }

    // ========== VIOLATION OBSERVATION (best-effort) ==========
    // Only meaningful when apply-seccomp will run — it is the binary that
    // installs the USER_NOTIF filter and ships the listener fd.
    if (observeSocketPath && applySeccompPrefix) {
      if (fs.existsSync(observeSocketPath)) {
        bwrapArgs.push('--bind', observeSocketPath, observeSocketPath)
        bwrapArgs.push('--setenv', 'SRT_OBSERVE_SOCK', observeSocketPath)
        // Tag events with the encoded command so the violation store can
        // associate them with this invocation (parity with macOS log tag).
        bwrapArgs.push(
          '--setenv',
          'SRT_ENCODED_CMD',
          encodeSandboxedCommand(commandId ?? command),
        )
      } else {
        logForDebugging(
          '[Sandbox Linux] observe socket missing — supervisor not running; ' +
            'continuing without violation monitoring',
        )
      }
    }

    // ========== ENV RESTRICTIONS ==========
    // Drop denied credential env vars from the inherited environment. Emitted
    // before the proxy --setenv flags below: bwrap applies env operations in
    // argument order, so SRT's own proxy plumbing vars survive even if a
    // caller lists one of them as a denied credential.
    if (hasEnvRestrictions) {
      for (const name of unsetEnvVars ?? []) {
        bwrapArgs.push('--unsetenv', name)
      }
      // Masked credentials override the inherited real value with a
      // sentinel; bwrap --setenv replaces any inherited value of NAME.
      for (const [name, value] of Object.entries(setEnvVars ?? {})) {
        bwrapArgs.push('--setenv', name, value)
      }
    }

    // ========== GIT CONFIG (safe.directory) ==========
    // Under `--unshare-user` the repo owner's uid is unmapped so git
    // sees dubious ownership. `buildPosixGitSafeDirEnv` composes
    // against the child's actual starting env (process.env inherited,
    // unsetEnvVars dropped, setEnvVars overlaid) so an ambient
    // GIT_CONFIG_COUNT is continued, not clobbered.
    if (gitSafeDirectories && gitSafeDirectories.length > 0) {
      const gitCfg = buildPosixGitSafeDirEnv({
        safeDirs: gitSafeDirectories,
        unsetEnvVars,
        setEnvVars,
      })
      for (const [name, value] of Object.entries(gitCfg)) {
        bwrapArgs.push('--setenv', name, value)
      }
    }

    // ========== NETWORK RESTRICTIONS ==========
    if (needsNetworkRestriction) {
      // Always unshare network namespace to isolate network access
      // This removes all network interfaces, effectively blocking all network
      bwrapArgs.push('--unshare-net')

      // If proxy sockets are provided, bind them into the sandbox to allow
      // filtered network access through the proxy. If not provided, network
      // is completely blocked (empty allowedDomains = block all)
      if (httpSocketPath && socksSocketPath) {
        // Verify socket files still exist before trying to bind them
        if (!fs.existsSync(httpSocketPath)) {
          throw new Error(
            `Linux HTTP bridge socket does not exist: ${httpSocketPath}. ` +
              'The bridge process may have died. Try reinitializing the sandbox.',
          )
        }
        if (!fs.existsSync(socksSocketPath)) {
          throw new Error(
            `Linux SOCKS bridge socket does not exist: ${socksSocketPath}. ` +
              'The bridge process may have died. Try reinitializing the sandbox.',
          )
        }

        // Bind both sockets into the sandbox
        bwrapArgs.push('--bind', httpSocketPath, httpSocketPath)
        // When the mux serves both protocols, socksSocketPath is the same
        // file as httpSocketPath; bwrap rejects a duplicate --bind of the
        // same source→target.
        if (socksSocketPath !== httpSocketPath) {
          bwrapArgs.push('--bind', socksSocketPath, socksSocketPath)
        }

        // Add proxy environment variables
        // HTTP_PROXY points to the socat listener inside the sandbox (port 3128)
        // which forwards to the Unix socket that bridges to the host's proxy server
        const proxyEnv = generateProxyEnvVars(
          3128, // Internal HTTP listener port
          1080, // Internal SOCKS listener port
          caCertPath,
          proxyAuthToken,
          writeConfig === undefined,
          encodeSandboxedCommand(commandId ?? command),
        )
        bwrapArgs.push(
          ...proxyEnv.flatMap((env: string) => {
            const firstEq = env.indexOf('=')
            const key = env.slice(0, firstEq)
            const value = env.slice(firstEq + 1)
            return ['--setenv', key, value]
          }),
        )

        // JVMs ignore the proxy env vars above; the agent jar translates
        // them into system properties + an Authenticator at JVM start
        // (see java-proxy-agent.ts). Composed against the inherited value
        // so a caller's own JAVA_TOOL_OPTIONS survives.
        const javaToolOptions = buildJavaToolOptions({
          agentJarPath: javaAgentJarPath,
          unsetEnvVars,
          inherited: process.env.JAVA_TOOL_OPTIONS,
        })
        if (javaToolOptions !== undefined) {
          bwrapArgs.push('--setenv', 'JAVA_TOOL_OPTIONS', javaToolOptions)
        }

        // Add host proxy port environment variables for debugging/transparency
        // These show which host ports the Unix socket bridges connect to
        if (httpProxyPort !== undefined) {
          bwrapArgs.push(
            '--setenv',
            'CLAUDE_CODE_HOST_HTTP_PROXY_PORT',
            String(httpProxyPort),
          )
        }
        if (socksProxyPort !== undefined) {
          bwrapArgs.push(
            '--setenv',
            'CLAUDE_CODE_HOST_SOCKS_PROXY_PORT',
            String(socksProxyPort),
          )
        }
      }
      // If no sockets provided, network is completely blocked (--unshare-net without proxy)
    }

    // ========== FILESYSTEM RESTRICTIONS ==========
    const fsArgs = await generateFilesystemArgs(
      readConfig,
      writeConfig,
      maskedFileBinds,
      maskedFileStoreDir,
      ripgrepConfig,
      mandatoryDenySearchDepth,
      allowGitConfig,
      abortSignal,
    )
    bwrapArgs.push(...fsArgs)

    // Always bind /dev
    bwrapArgs.push('--dev', '/dev')

    // ========== PID NAMESPACE ISOLATION ==========
    // IMPORTANT: These must come AFTER filesystem binds for nested bwrap to work
    // By default, always unshare PID namespace and mount fresh /proc.
    // If we don't have --unshare-pid, it is possible to escape the sandbox.
    // If we don't have --proc, it is possible to read host /proc and leak information about code running
    // outside the sandbox. But, --proc is not available when running in unprivileged docker containers
    // so we support running without it if explicitly requested.
    bwrapArgs.push('--unshare-pid')
    // --unshare-user in both modes: bwrap only auto-creates a userns when
    // EUID != 0. A root parent in an unprivileged container (Docker's
    // default: EUID=0 without CAP_SYS_ADMIN) would otherwise try a direct
    // clone and EPERM; a root parent WITH capabilities would leave the
    // command holding them, CAP_SYS_ADMIN included, which unmounts any deny
    // in this namespace — hence capabilityArgs in both modes as well.
    // apply-seccomp creates its own nested userns to obtain CAP_SYS_ADMIN
    // for its PID+mount unshare (see below); for a root caller that needs
    // the one capability capabilityArgs keeps.
    bwrapArgs.push(
      '--unshare-user',
      ...capabilityArgs(applySeccompPrefix !== undefined),
    )
    if (!enableWeakerNestedSandbox) {
      // Mount fresh /proc if PID namespace is isolated (secure mode).
      bwrapArgs.push('--proc', '/proc')
    } else {
      // --bind /proc /proc: apply-seccomp's nested-userns path writes
      // /proc/self/setgroups and uid_map. Without --proc above, the
      // --ro-bind / / leaves /proc read-only and those writes EROFS; a
      // fresh proc mount is what an unprivileged container refuses.
      bwrapArgs.push('--bind', '/proc', '/proc')
    }

    // apply-seccomp obtains CAP_SYS_ADMIN for its nested PID+mount unshare
    // by creating a nested user namespace. This requires the host to permit
    // capability-bearing unprivileged user namespaces (the same requirement
    // bwrap itself has when not installed setuid). See README for the
    // Ubuntu 24.04 sysctl if AppArmor restricts this.

    // ========== COMMAND ==========
    // Use the user's shell (zsh, bash, etc.) to ensure aliases/snapshots work
    // Resolve the full path to the shell binary since bwrap doesn't use $PATH
    const shellName = binShell || 'bash'
    const shell = whichSync(shellName)
    if (!shell) {
      throw new Error(`Shell '${shellName}' not found in PATH`)
    }
    bwrapArgs.push('--', shell, '-c')

    // With network restrictions, route the command through buildSandboxCommand
    // so socat starts before seccomp is applied. Otherwise invoke apply-seccomp
    // directly if we have a binary.
    if (needsNetworkRestriction && httpSocketPath && socksSocketPath) {
      const sandboxCommand = buildSandboxCommand(
        httpSocketPath,
        socksSocketPath,
        command,
        applySeccompPrefix,
        shell,
        socatPath,
      )
      bwrapArgs.push(sandboxCommand)
    } else if (applySeccompPrefix) {
      const applySeccompCmd = applySeccompPrefix + quote([shell, '-c', command])
      bwrapArgs.push(applySeccompCmd)
    } else {
      bwrapArgs.push(command)
    }

    const wrappedCommand = quote([bwrapPath ?? 'bwrap', ...bwrapArgs])

    const restrictions = []
    if (needsNetworkRestriction) restrictions.push('network')
    if (hasReadRestrictions || hasWriteRestrictions)
      restrictions.push('filesystem')
    if (hasEnvRestrictions) restrictions.push('env')
    if (applySeccompPrefix) restrictions.push('seccomp(unix-block)')

    logForDebugging(
      `[Sandbox Linux] Wrapped command with bwrap (${restrictions.join(', ')} restrictions)`,
    )

    return wrappedCommand
  } catch (error) {
    // Undo the activeSandboxCount increment — the caller won't call
    // cleanupBwrapMountPoints() for a wrap that threw.
    if (activeSandboxCount > 0) {
      activeSandboxCount--
    }
    throw error
  }
}
