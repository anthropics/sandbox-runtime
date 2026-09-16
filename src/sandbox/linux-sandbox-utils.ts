import { quote } from '../utils/shell-quote.js'
import { logForDebugging } from '../utils/debug.js'
import { whichSync } from '../utils/which.js'
import { randomBytes } from 'node:crypto'
import * as fs from 'fs'
import { spawn } from 'node:child_process'
import type { ChildProcess } from 'node:child_process'
import { endianness, tmpdir } from 'node:os'
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
        const isWithinAllowedPath = allowedWritePaths.some(allowedPath =>
          isAtOrUnder(nextPath, allowedPath),
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

/**
 * Linux's per-argument cap, MAX_ARG_STRLEN: 32 pages, so 128 KiB on most
 * kernels and up to 2 MiB with 64 KiB pages. The page size is AT_PAGESZ in
 * /proc/self/auxv (pairs of native words); 4 KiB, the smallest, if unreadable.
 */
let linuxMaxArgStrlen: number | undefined
function maxArgStrlen(): number {
  if (linuxMaxArgStrlen === undefined) {
    const AT_PAGESZ = 6
    let pageSize = 4096
    try {
      const auxv = fs.readFileSync('/proc/self/auxv')
      const wordBytes = /64|s390x/.test(process.arch) ? 8 : 4
      // Buffer reads at most 6 bytes as a number; no value needed here is wider.
      const low = Math.min(wordBytes, 6)
      const word = (at: number): number =>
        endianness() === 'BE'
          ? auxv.readUIntBE(at + wordBytes - low, low)
          : auxv.readUIntLE(at, low)
      for (let at = 0; at + 2 * wordBytes <= auxv.length; at += 2 * wordBytes) {
        if (word(at) === AT_PAGESZ) {
          pageSize = word(at + wordBytes)
          break
        }
      }
    } catch {
      // No /proc: the smallest page size only moves a profile to the file
      // sooner than it had to.
    }
    linuxMaxArgStrlen = 32 * pageSize
  }
  return linuxMaxArgStrlen
}

/**
 * Room left below the cap when deciding whether the profile stays on the
 * command line: the embedder may put a prefix of its own (`exec`, `cd x &&`,
 * an assignment) in the same argument.
 */
const ARG_HEADROOM_BYTES = 4096

/** bwrap's cap on parsed words, the command line and `--args` file together. */
const BWRAP_MAX_ARGS = 9000

/**
 * The fd the `--args` file is opened on: a single digit, since dash rejects
 * multi-digit redirections, and high, since embedders hand the command low
 * fds of their own (an extra stdio pipe, a helper as `/proc/self/fd/3`).
 */
const BWRAP_ARGS_FD = 9

/**
 * Linux's O_TMPFILE, which neither Node nor Bun exposes in `fs.constants`:
 * the asm-generic __O_TMPFILE, the value on every architecture they build
 * for Linux, together with the O_DIRECTORY the flag is defined to carry — a
 * kernel or filesystem that does not know it therefore fails the open on the
 * directory rather than creating a named file.
 */
const O_TMPFILE = 0o20000000 | fs.constants.O_DIRECTORY

/**
 * The `--args` profiles this process holds open.
 *
 * A profile is an unnamed file (O_TMPFILE): written at wrap time, kept open
 * here, and opened again by the string bwrap runs through
 * `/proc/<pid>/fd/<n>`, which is a fresh read-only description of the same
 * inode at offset 0. Nothing is named at any point, so there is nothing for
 * anyone to substitute between the wrap and the execution — not a sandbox
 * that renames an ancestor of tmpdir, not a sandbox another process of the
 * same user launched with tmpdir writable. Every sandbox this library starts
 * has its own PID namespace and a fresh /proc, so none of them can reach
 * /proc/<this pid> either.
 *
 * Fds close when the sandboxes of a batch are cleaned up, and fd numbers are
 * reused: a string kept past its cleanup and run later opens whatever the
 * number means by then — nothing (the redirection fails and the command does
 * not run), something bwrap refuses, or another profile of this process,
 * never one from outside it.
 */
const bwrapArgsFds: Set<number> = new Set()

/** Where the string bwrap runs opens the profile held on `fd`. */
function bwrapArgsProfilePath(fd: number): string {
  return `/proc/${process.pid}/fd/${fd}`
}

/**
 * Writes `mountWords` NUL-separated to an unnamed file and returns the fd it
 * stays open on. Throws when no directory takes an O_TMPFILE file, or when
 * the profile cannot be opened again through /proc: there is no named-file
 * fallback, and before any of this an over-long profile failed with E2BIG
 * anyway. The check is this process's own open; a child's can still be
 * refused (a process made non-dumpable owns its /proc entries as root), and
 * the string then fails in the redirection and runs no command.
 */
function openBwrapArgsProfile(mountWords: string[]): number {
  const contents = mountWords.map(word => word + '\0').join('')
  const failures: string[] = []
  for (const dir of new Set([tmpdir(), '/dev/shm'])) {
    let fd: number
    try {
      fd = fs.openSync(dir, O_TMPFILE | fs.constants.O_RDWR, 0o600)
    } catch (error) {
      failures.push(`${dir}: ${errorText(error)}`)
      continue
    }
    try {
      fs.writeFileSync(fd, contents)
      // Read-only from here: this process is done writing it.
      fs.fchmodSync(fd, 0o400)
      // The string opens this path. Fail now, where the caller is told why,
      // rather than when the command runs.
      fs.closeSync(fs.openSync(bwrapArgsProfilePath(fd), fs.constants.O_RDONLY))
    } catch (error) {
      failures.push(`${dir}: ${errorText(error)}`)
      fs.closeSync(fd)
      continue
    }
    bwrapArgsFds.add(fd)
    return fd
  }
  throw new Error(
    `no unnamed file could be opened for it (${failures.join('; ')})`,
  )
}

function closeBwrapArgsProfile(fd: number): void {
  bwrapArgsFds.delete(fd)
  try {
    fs.closeSync(fd)
  } catch {
    // Already closed: nothing left to release.
  }
}

function errorText(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

/**
 * The shell string that runs bwrap with `bwrapArgs`, which the caller runs
 * as one argument of `sh -c`. When that would not fit the kernel's
 * per-argument cap, the words in `mounts` (a slice of `bwrapArgs`) go to an
 * unnamed file this process holds open (see `bwrapArgsFds`) and bwrap reads
 * them through `--args` at the same position; the string opens that file
 * again through /proc. Every other word, the per-command environment and the
 * command among them, stays on the line. The result stays a simple command,
 * so a prefix (`exec`, `timeout 30`) or a suffix (`&& next`) still composes.
 * Throws when the profile cannot run: too many words for bwrap, no unnamed
 * file to put the mounts in, or a line too long even without them.
 */
function renderBwrapInvocation(
  bwrapBinary: string,
  bwrapArgs: string[],
  mounts: { start: number; end: number },
): string {
  if (bwrapArgs.length > BWRAP_MAX_ARGS) {
    throw new Error(
      `Sandbox profile has ${bwrapArgs.length} bwrap arguments and bwrap accepts at most ${BWRAP_MAX_ARGS} (about ${BWRAP_MAX_ARGS / 3} mounts); reduce the number of paths the configuration expands to`,
    )
  }
  const inline = quote([bwrapBinary, ...bwrapArgs])
  const inlineBytes = Buffer.byteLength(inline, 'utf8')
  const limit = maxArgStrlen() - 1
  if (inlineBytes <= limit - ARG_HEADROOM_BYTES) {
    return inline
  }

  const tooLong = `Sandbox profile is too long for the command line (${inlineBytes} bytes; past ${limit - ARG_HEADROOM_BYTES} it goes through a file)`
  // `--args <fd>` are two more words.
  if (bwrapArgs.length + 2 > BWRAP_MAX_ARGS) {
    throw new Error(
      `${tooLong} and, passed through a file, would exceed the ${BWRAP_MAX_ARGS} arguments bwrap accepts`,
    )
  }
  const mountWords = bwrapArgs.slice(mounts.start, mounts.end)
  if (mountWords.some(word => word.includes('\0'))) {
    // bwrap splits the file on NUL: the word would become several options.
    throw new Error(
      `${tooLong} and contains a path with a NUL byte, which a file of bwrap arguments cannot carry`,
    )
  }
  let argsFd: number
  try {
    argsFd = openBwrapArgsProfile(mountWords)
  } catch (error) {
    throw new Error(
      `${tooLong} and cannot be passed through a file: ${errorText(error)}`,
    )
  }
  // /bin/sh opens the profile on the fd and execs bwrap, which reads it to
  // EOF and closes it before running the command.
  const viaArgsFile = quote([
    '/bin/sh',
    '-c',
    `exec ${BWRAP_ARGS_FD}<"$1" && shift && exec "$@"`,
    'srt-args',
    bwrapArgsProfilePath(argsFd),
    bwrapBinary,
    ...bwrapArgs.slice(0, mounts.start),
    '--args',
    String(BWRAP_ARGS_FD),
    ...bwrapArgs.slice(mounts.end),
  ])
  const viaArgsFileBytes = Buffer.byteLength(viaArgsFile, 'utf8')
  if (viaArgsFileBytes > limit) {
    closeBwrapArgsProfile(argsFd)
    throw new Error(
      `Sandboxed command is too long for one shell argument even with the mounts passed through a file (${viaArgsFileBytes} bytes; the limit here is ${limit})`,
    )
  }
  logForDebugging(
    `[Sandbox Linux] bwrap mounts moved to an unnamed file, read through ${bwrapArgsProfilePath(argsFd)} on bwrap's fd ${BWRAP_ARGS_FD}: the command line would be ${inlineBytes} bytes as one argument`,
  )
  return viaArgsFile
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
 *
 * Also closes the `--args` profiles the wraps of this batch opened.
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

  for (const argsFd of [...bwrapArgsFds]) {
    closeBwrapArgsProfile(argsFd)
  }
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
 * The three classes an fs errno from a path lookup falls into, enumerated
 * here once because each leads somewhere different: ABSENCE, where the name
 * resolves to no file and every consumer already treats the path as absent;
 * TRANSIENT, a busy, unlucky or re-exporting host rather than a fact about
 * the path, worth asking once more before the failure is taken for an
 * answer; and SETTLED, a file that is there and cannot be looked at, and
 * will not become readable while this wrap runs. Every code neither
 * predicate below names is settled, because nothing says it clears.
 */
function isAbsenceErrno(err: unknown): boolean {
  const code = (err as NodeJS.ErrnoException | undefined)?.code
  return (
    code === 'ENOENT' ||
    code === 'ENOTDIR' ||
    code === 'ELOOP' ||
    code === 'ENAMETOOLONG'
  )
}

function isTransientErrno(err: unknown): boolean {
  const code = (err as NodeJS.ErrnoException | undefined)?.code
  return (
    code === 'EIO' ||
    code === 'ESTALE' ||
    code === 'EMFILE' ||
    code === 'ENFILE' ||
    code === 'EAGAIN'
  )
}

/**
 * `attempt`, asked a second time when the first failure was transient and
 * rethrown otherwise. Two caveats come with the second ask: a same-tick retry
 * cannot clear descriptor exhaustion (EMFILE, ENFILE), so for those it is
 * best effort. And on a soft-mounted network filesystem that is down, a
 * transient-class errno arrives only after the mount's own timeout, so the
 * retry can double that stall — a hard mount never returns at all, so the
 * retry never runs there.
 */
function retryingTransient<T>(attempt: () => T): T {
  try {
    return attempt()
  } catch (err) {
    if (!isTransientErrno(err)) throw err
  }
  return attempt()
}

/** The top-level directories this wrap leaves to the kernel and to the
 * caller's own remounts. A cover must never take one — --proc and --dev
 * replace two of them after the pins are spliced in, and /sys is kernel
 * state — and the '/' read-deny expansion must not hide one either. */
const KERNEL_TOP_LEVEL_DIRS = ['/proc', '/dev', '/sys']

/**
 * A self-bind ("pin") for every directory between a seed (where a deny bind,
 * file mask or read-deny tmpfs lands) and the allowed write root covering it,
 * shallow-first, which makes each one a mountpoint the kernel refuses to
 * rename or remove. A directory that is not there is skipped: bwrap cannot
 * bind a missing source and there is nothing to rename. One that exists but
 * cannot be inspected is still pinned, and if bwrap cannot bind it either the
 * sandbox does not start, which is where the deny loop lands too.
 *
 * Pins are read-only and spliced in beneath every other mount, so that one
 * landing on top of an allowed write root cannot make it read-only; a write
 * root needs no pin of its own there, its allow bind already being a live
 * mountpoint.
 *
 * A '/' write root defeats that: its own recursive `--bind / /` is one of the
 * mounts above the pins and buries them, leaving those directories renamable.
 * Under one the pins therefore go AFTER the allow binds and take every
 * ancestor, the other allowed write roots included, stopping below the
 * top-level directory D on the chain; a writable `--bind D D` — the cover —
 * takes D itself and buries them again. Lookups enter the cover and never meet
 * a pin, so no filesystem boundary lands inside D, while the kernel's rename
 * and rmdir checks scan mounts by dentry and still find one. The only new
 * boundary is at D. /proc, /dev and /sys are never covered, and a seed under
 * one of them gets no pins.
 */
function ancestorPinArgs(
  seeds: Iterable<string>,
  writeRoots: {
    rootIsWriteRoot: boolean
    isWithinAllowedWrite: (dir: string) => boolean
    isAllowedWriteRoot: (dir: string) => boolean
  },
): string[] {
  const { rootIsWriteRoot } = writeRoots
  const pinDirs = new Set<string>()
  const coverDirs = new Set<string>()
  // Verdicts are seed-independent: a visited ancestor's chain is done.
  const visited = new Set<string>()
  for (const seed of seeds) {
    if (
      rootIsWriteRoot &&
      KERNEL_TOP_LEVEL_DIRS.some(dir => isAtOrUnder(seed, dir))
    ) {
      continue
    }
    for (
      let dir = path.dirname(seed);
      dir !== '/' && !visited.has(dir) && writeRoots.isWithinAllowedWrite(dir);
      dir = path.dirname(dir)
    ) {
      visited.add(dir)
      if (rootIsWriteRoot) {
        if (path.dirname(dir) === '/') {
          coverDirs.add(dir)
          continue
        }
      } else if (writeRoots.isAllowedWriteRoot(dir)) {
        continue
      }
      try {
        fs.statSync(dir)
      } catch (err) {
        if (isAbsenceErrno(err)) continue
      }
      pinDirs.add(dir)
    }
  }
  const covers = [...coverDirs]
  if (covers.length > 0) {
    logForDebugging(
      `[Sandbox Linux] Covering the pinned ancestors under: ${covers.join(', ')}`,
    )
  }
  return [
    ...[...pinDirs]
      .sort((a, b) => a.split('/').length - b.split('/').length)
      .flatMap(dir => ['--ro-bind', dir, dir]),
    ...covers.flatMap(dir => ['--bind', dir, dir]),
  ]
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

/** A restore the tmpfs pass emitted: the mount's source and its destination
 * in the sandbox. Both are needed later — the destination says where the
 * path is visible, the source says which inode was vetted for it. */
type RestoredMount = { source: string; dest: string }

/**
 * Mount a tmpfs over a read-denied directory, then restore the allowed write
 * paths and allowRead paths the tmpfs just wiped. Returns the mounts it
 * re-bound, writable and read-only, which is what a later pass re-emits when
 * a denyWrite bind re-exposes this directory.
 */
function pushReadDenyDirMounts(
  args: string[],
  unit: {
    /** The directory as bwrap is given it (mountPlacement's dest). */
    dir: string
    /** Where the tmpfs lands in the sandbox (mountPlacement's landing). */
    landing: string
    allowedWritePaths: readonly string[]
    readAllowPaths: readonly string[]
    /** Where a path resolves to, and whether that is a resolution at all:
     * an unresolved answer is the spelling itself, which must never become a
     * mount source (canonicalLocationOf in the caller). */
    resolve: (p: string) => { canonical: string; resolved: boolean }
    /** What the read section hides at or around a resolved target, other
     * than this tmpfs and the denies above it (readDenialAround bound to
     * this unit's landing in the caller). */
    readDenialAround: (target: string) => string | undefined
    /** Where a path's name lives (nameLocationOf in the caller). */
    nameLocation: (p: string) => string
  },
): { restoredWrites: RestoredMount[]; restoredReads: RestoredMount[] } {
  const { dir, landing, allowedWritePaths, readAllowPaths } = unit
  args.push('--tmpfs', dir)

  // How to bind allowed path `p` back, if it is a carve-out of this unit:
  // its name must live inside the denied directory, and so must what it
  // resolves to. Parent directories may be symlinks (/lib/x is a carve-out
  // of a tmpfs on /usr, where /lib is a link to /usr/lib). A path that is
  // itself a symlink INTO the directory is not a carve-out: it names the
  // link, which this tmpfs did not hide, and re-allows nothing the link
  // points at, or a link planted at an allowed path (docs -> ~/.ssh) would
  // cancel the deny of its target.
  //
  // The mount goes back at the NAME (the entry re-allows the name it is, and
  // an entry whose last component is a symlink is ENOENT inside the sandbox
  // if restored only at its target), from the RESOLVED source: that is the
  // path both containment checks were made against, and naming it leaves
  // bwrap nothing to re-resolve at mount time.
  const restorePlacementOf = (p: string): RestoredMount | undefined => {
    const dest = unit.nameLocation(p)
    if (!isAtOrUnder(dest, landing)) return undefined
    const { canonical: source, resolved } = unit.resolve(p)
    if (!resolved) {
      logForDebugging(
        `[Sandbox Linux] Not restoring ${p} over denyRead tmpfs ${dir}: nothing there resolves (absent, dangling or unreadable), so the only source available is the name itself`,
        { level: 'warn' },
      )
      return undefined
    }
    if (!isAtOrUnder(source, landing)) {
      logForDebugging(
        `[Sandbox Linux] Not restoring ${p} over denyRead tmpfs ${dir}: it resolves outside it, to ${source}`,
        { level: 'warn' },
      )
      return undefined
    }
    // Restoring at the name from a DIFFERENT path is a second mount of the
    // target's inode, which nothing landing on the target's own path covers,
    // so such a restore is dropped whenever the read section hides anything
    // at, inside or around that target: the deny wins, and the follow-up that
    // gives the carve-out back has to bind the target at the target.
    if (source !== dest) {
      const denied = unit.readDenialAround(source)
      if (denied !== undefined) {
        logForDebugging(
          `[Sandbox Linux] Not restoring ${p} over denyRead tmpfs ${dir}: it resolves to ${source}, and the read section denies or masks ${denied}`,
          { level: 'warn' },
        )
        return undefined
      }
    }
    return { source, dest }
  }

  // tmpfs wiped any earlier write binds under this path — restore them.
  const restoredWrites: RestoredMount[] = []
  for (const writePath of allowedWritePaths) {
    const placement = restorePlacementOf(writePath)
    if (placement === undefined) continue
    args.push('--bind', placement.source, placement.dest)
    restoredWrites.push(placement)
    logForDebugging(
      `[Sandbox Linux] Re-bound write path wiped by denyRead tmpfs: ${writePath}`,
    )
  }

  // Re-allow specific paths within the denied directory (allowRead overrides denyRead).
  // After mounting tmpfs over the denied dir, bind back the allowed subdirectories
  // so they are readable again.
  const restoredReads: RestoredMount[] = []
  for (const allowPath of readAllowPaths) {
    const placement = restorePlacementOf(allowPath)
    if (placement === undefined) continue
    // Skip only if a write path was re-bound just above AND covers
    // allowPath. A write path that's an ancestor of the deny dir isn't
    // re-bound (it wasn't wiped), so allowPath under it still needs
    // its own ro-bind here.
    if (restoredWrites.some(w => isAtOrUnder(placement.dest, w.dest))) continue
    // Bind the allowed path back over the tmpfs so it's readable
    args.push('--ro-bind', placement.source, placement.dest)
    restoredReads.push(placement)
    logForDebugging(
      `[Sandbox Linux] Re-allowed read access within denied region: ${allowPath}`,
    )
  }
  return { restoredWrites, restoredReads }
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
  // because the re-application passes record a deny bind's raw spelling
  // beside its resolved dest, so the stub-skip guard tests a covering
  // directory in its canonical form AND every recorded spelling.
  const readOnlyDenyDirSpellings = new Map<string, Set<string>>()
  // dest → the pre-resolution deny path it came from. denyWrite dests are
  // canonicalized through symlinks but the denyRead tmpfs dirs and the write
  // binds they are later compared against are not, so a dest reached via a
  // symlink no longer matches them by string prefix. Both spellings name the
  // same inode once bwrap resolves them, so the comparisons below test both.
  const denyWriteRawDests = new Map<string, string>()
  // Where a mount given `p` lands: `p` fully resolved, every symlink on the
  // way and not one hop. One resolution per path per wrap, so every predicate
  // below sees the same answer, and none before the mandatory-deny scan's
  // await: that scan can run arbitrarily long, and a realpath taken ahead of
  // it would miss a symlink retargeted meanwhile.
  const canonicalFormCache = new Map<string, string>()
  // Paths whose canonical location could not be LOOKED AT — a settled errno,
  // or a transient one that outlived the retry — so the recorded spelling
  // stands in for it. That is a guess, and the
  // stub-skip prediction below refuses to conclude anything from a guess made
  // about its own inputs. Plain absence is not a guess: nothing is there to
  // resolve, and every consumer already treats such a path as absent (a
  // dangling symlink under '/' is ordinary, and counting it would keep every
  // deny placeholder on the whole host).
  const canonicalFormGuesses = new Set<string>()
  // Paths canonicalForm answered with the spelling it was given because
  // nothing could be resolved. A mount SOURCE must never be one of them:
  // bwrap would resolve whatever sits at that name at mount time, after the
  // containment checks ran against the name itself.
  const canonicalFormUnresolved = new Set<string>()
  const canonicalForm = (p: string): string => {
    let canonical = canonicalFormCache.get(p)
    if (canonical === undefined) {
      try {
        canonical = retryingTransient(() => fs.realpathSync(p))
      } catch (err) {
        canonical = p // vanished or unresolvable: the recorded form stands
        canonicalFormUnresolved.add(p)
        if (!isAbsenceErrno(err)) canonicalFormGuesses.add(p)
      }
      canonicalFormCache.set(p, canonical)
    }
    return canonical
  }
  /** Where `p` resolves to, beside whether anything was resolved at all.
   * Answered together because the answer is the spelling itself when nothing
   * was, and a mount source must never be one of those. */
  const canonicalLocationOf = (
    p: string,
  ): { canonical: string; resolved: boolean } => ({
    canonical: canonicalForm(p),
    resolved: !canonicalFormUnresolved.has(p),
  })
  /** `p` as recorded, plus its canonical location when that differs. */
  const mountForms = (p: string): string[] => {
    const canonical = canonicalForm(p)
    return canonical === p ? [p] : [p, canonical]
  }
  // Where the name `p` lives: its parent directories resolved, its last
  // component as written. This, not what `p` resolves to, decides which read
  // deny an allowRead entry is an exception to: an entry that is a symlink
  // names the link, and re-allows nothing the link points at.
  const nameLocationOf = (p: string): string => {
    if (p === '/') return p
    const parent = canonicalForm(path.dirname(p))
    return `${parent === '/' ? '' : parent}/${path.basename(p)}`
  }
  // Whether a canonical path lies inside the write allowlist, and so
  // whether it is denied, stubbed and pinned at all: a path outside it is
  // left read-only by the initial --ro-bind / /. The deny pre-pass, the deny
  // loop's --ro-bind gate and the ancestor-pin walk MUST share it: the
  // pre-pass is only sound if it records exactly the directories the loop
  // re-binds read-only (a recorded directory that is never re-bound read-only
  // would suppress stubs unsafely; a re-bound directory missing from the
  // record only costs an abort). allowedWritePaths entries are canonical (the
  // allow loop drops a symlink-spelled one) and recorded with trailing
  // slashes stripped.
  //
  // Containment is root-aware (isAtOrUnder) because '/' is a legal allowOnly
  // entry that the allow loop binds writable: an `allowedPath + '/'` prefix
  // test spells it '//' and matches nothing, so every deny no other allow
  // entry covers would be judged outside the allowlist and silently lose its
  // bind over a writable root. The ancestor pins are the one consumer that
  // treats a '/' write root specially: see ancestorPinArgs.
  const isWithinAnyAllowedWritePath = (candidatePath: string): boolean =>
    allowedWritePaths.some(allowedPath =>
      isAtOrUnder(candidatePath, allowedPath),
    )
  const isAllowedWriteRoot = (candidatePath: string): boolean =>
    allowedWritePaths.includes(candidatePath)
  // Resolves symlinks, so computed on first use, which is after the
  // mandatory-deny scan.
  let readAllowPathsMemo: string[] | undefined
  const readAllowPaths = (): string[] =>
    (readAllowPathsMemo ??= (readConfig?.allowWithinDeny || []).map(p =>
      normalizePathForSandbox(p),
    ))
  // What the read section mounts for one denyRead entry: a tmpfs (directory)
  // or a /dev/null mask (anything else) on the entry itself; nothing when it
  // is not there; and, when it cannot be inspected, a tmpfs on the deepest
  // directory above it that can. That hides more than was asked, never less:
  // a same-uid command can make a parent unsearchable (chmod 000) and undo it
  // again from inside the next sandbox, so "unreadable now" is not "absent".
  // '/' is never the stand-in: a --tmpfs / would wipe every mount before it
  // and the pivot would promote it, booting the command on an empty tree.
  // This is the widest blast radius a transient failure has, hence the retry:
  // one unlucky EIO turns a file deny into a stand-in over its whole
  // directory, and every carve-out beneath that is then refused.
  const readDenyTargetOf = (
    entry: string,
  ): { path: string; isDirectory: boolean } | undefined => {
    for (let candidate = entry; ; candidate = path.dirname(candidate)) {
      if (candidate === '/' && candidate !== entry) return undefined
      try {
        const stats = retryingTransient(() => fs.statSync(candidate))
        return { path: candidate, isDirectory: stats.isDirectory() }
      } catch (err) {
        if (isAbsenceErrno(err) || candidate === '/') return undefined
      }
    }
  }
  // The directories and files the read section denies, as configured. A '/'
  // entry is expanded into the root's children, because --tmpfs / would wipe
  // every prior mount (ro-bind /, write binds, deny binds). /proc and /dev are
  // skipped (the caller remounts them after this function returns) and so is
  // /sys (kernel interface; the host's is already read-only via ro-bind). A
  // child an allowRead entry covers (its name is the child, or an ancestor
  // of where the child lands) is skipped too: the deny is synthetic and the
  // allow is the caller's, and a tmpfs at the child's canonical location
  // (/bin lands at /usr/bin) would only be restored over again. An entry
  // that is a symlink to the child covers nothing: its name lives elsewhere. /etc/ssh/ssh_config.d is
  // always hidden when there is a read policy: ssh is strict about config
  // file ownership and permissions, which can look wrong inside the sandbox
  // ("Bad owner or permissions" under OrbStack). Throws if '/' cannot be
  // listed, a transient failure having been retried once. Computed on first
  // use, like readAllowPaths.
  let readDenyEntriesMemo: string[] | undefined
  const readDenyEntries = (): string[] => {
    if (readDenyEntriesMemo !== undefined) return readDenyEntriesMemo
    if (!readConfig) return []
    const entries: string[] = []
    for (const p of readConfig.denyOnly || []) {
      if (normalizePathForSandbox(p) !== '/') {
        entries.push(p)
        continue
      }
      // The only call here that throws, and the list is memoised on success
      // alone, so the retry belongs to it rather than to one of its callers:
      // the stub-skip derivation catches a throw and gives up on the
      // prediction, and the denyRead loop below does not catch one at all.
      const children = retryingTransient(() => fs.readdirSync('/'))
      for (const child of children) {
        if (KERNEL_TOP_LEVEL_DIRS.includes(`/${child}`)) continue
        const childLocation = canonicalForm('/' + child)
        const covered = readAllowPaths().some(allowPath =>
          isAtOrUnder(childLocation, nameLocationOf(allowPath)),
        )
        if (covered) {
          logForDebugging(
            `[Sandbox Linux] Root deny expansion skips /${child}: covered by allowRead`,
          )
          continue
        }
        entries.push('/' + child)
      }
    }
    if (fs.existsSync('/etc/ssh/ssh_config.d')) {
      entries.push('/etc/ssh/ssh_config.d')
    }
    readDenyEntriesMemo = entries
    return entries
  }
  // Where the ancestor pins are spliced in once every mount is known:
  // beneath the allow binds, or after them under a '/' write root that would
  // otherwise bury them (see ancestorPinArgs).
  let ancestorPinInsertAt: number

  // Determine initial root mount based on write restrictions
  if (writeConfig) {
    // Write restrictions: Start with read-only root, then allow writes to specific paths
    args.push('--ro-bind', '/', '/')
    const beneathAllowBinds = args.length

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
    ancestorPinInsertAt = isAllowedWriteRoot('/')
      ? args.length
      : beneathAllowBinds

    // Inputs for the covering-directory vetoes, computed at most once and
    // only when a deny path (absent or existing) lies strictly beneath a
    // recorded read-only deny dir — commands with no such covering directory
    // skip the extra stat/realpath/readdir syscalls entirely. Lazy
    // evaluation also means the derivation runs from inside the deny loop,
    // AFTER the (unbounded) mandatory-deny ripgrep await below, keeping the
    // snapshot as close as possible to the denyRead loop that later acts on
    // the real filesystem.
    type StubSkipVetoInputs =
      | {
          /** The derivation held; the arrays below describe this wrap. */
          usable: true
          /**
           * allowWrite paths in their recorded and realpath-canonical
           * spellings (mountForms). The canonical form is not reused from
           * the allow loop's earlier resolution, deliberately: canonicalForm
           * resolves after the (unbounded) mandatory-deny scan, so it sees
           * an allow path whose symlink target changed during that window —
           * the fail-closed direction, since a link now pointing into a
           * covering deny dir must veto the skip. The guard's veto compares
           * deny dests (always canonical) against allow paths, so it keeps
           * both domains.
           */
          allowedWritePathsBothForms: string[]
          /**
           * The tmpfs targets the denyRead loop below will mount, from the
           * same readDenyEntries() it uses, keeping only entries that exist
           * as directories (the loop skips absent entries and gives file
           * entries a read-only /dev/null mask instead of a tmpfs), in raw
           * and canonical spellings. A read-denied tmpfs at or under a
           * covering deny dir is the TRIGGER for the post-denyWrite
           * re-application, and a deny bind whose dest sits under one can be
           * dropped by the emission filter — both facts feed the guard.
           */
          prospectiveReadDenyTmpfsDirsBothForms: string[]
        }
      | {
          /**
           * The derivation threw, or needed a canonical location it could not
           * look at. A failure must not read as "no read-deny tmpfs", so
           * every covering directory is vetoed instead.
           */
          usable: false
        }
    let stubSkipVetoInputs: StubSkipVetoInputs | undefined
    const getStubSkipVetoInputs = (): StubSkipVetoInputs => {
      if (stubSkipVetoInputs !== undefined) {
        return stubSkipVetoInputs
      }
      const unusable = (cause: string): StubSkipVetoInputs => {
        logForDebugging(
          `[Sandbox Linux] Read-deny prediction unusable (${cause}); keeping every deny placeholder, which refuses to start wherever a covering deny directory is read-only: bubblewrap cannot create a placeholder's mount point there`,
          { level: 'warn' },
        )
        return { usable: false }
      }
      // Single-shot: readDenyEntries() owns the retry for the one thing that
      // throws here, its listing of '/'. A guess would survive a retry
      // anyway, being a settled verdict about a path that cannot be looked at.
      try {
        const allowedWritePathsBothForms = allowedWritePaths.flatMap(mountForms)
        const prospectiveReadDenyTmpfsDirsBothForms = readDenyEntries().flatMap(
          entry => {
            const target = readDenyTargetOf(normalizePathForSandbox(entry))
            return target?.isDirectory ? mountForms(target.path) : []
          },
        )
        // Every canonicalForm call site runs inside this derivation or after
        // the deny loop that triggers it, so a guess recorded by now was made
        // about the derivation's own inputs. A future caller that resolves
        // earlier can only add guesses here, which vetoes more skips, never
        // fewer.
        stubSkipVetoInputs =
          canonicalFormGuesses.size > 0
            ? unusable(
                `no canonical location for ${[...canonicalFormGuesses].join(', ')}`,
              )
            : {
                usable: true,
                allowedWritePathsBothForms,
                prospectiveReadDenyTmpfsDirsBothForms,
              }
      } catch (err) {
        stubSkipVetoInputs = unusable(`deriving it threw: ${err}`)
      }
      return stubSkipVetoInputs
    }
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
    // directory recorded here is either re-bound read-only by the loop or
    // skipped because a recorded directory above it survived the vetoes and
    // is bound in its place, so every record still stands for a bind that
    // lands — unless a symlink appears in its path between the two passes,
    // where the loop masks that component and emits no bind for the
    // directory (the re-check below); an emitted one missing from the record
    // only costs a spurious abort.
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
        // Keep every spelling this dest is reached through (the
        // re-application passes record the first-seen raw spelling beside
        // the dest, which this pass cannot assume): the guard below treats
        // the directory as unsafe if a read-deny tmpfs contains ANY of them.
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
    // only under a recorded covering deny directory that was judged against
    // a prediction that could be derived, has no allowed write path strictly
    // beneath it and is INCOMPARABLE with every read-deny tmpfs directory
    // (neither at-or-beneath it nor containing it or any spelling it was
    // reached through). '/' is the exception: it contains every tmpfs and
    // every allowed write path, so coveredBySafeReadOnlyDenyDir judges a
    // vetoed '/' against the candidate instead — see the branch there.
    // Containment is root-aware
    // (isAtOrUnder): '/' is a recordable covering directory when allowOnly
    // and denyWithinAllow both name it, and '/' + '/' is a prefix of
    // nothing, so a string-prefix test would judge it safe for every path
    // and drop the binds the re-application passes below key off.
    // Rationale: nothing writable lands after the buffered read-only binds,
    // so no later mount re-opens what a covering bind closed — the tmpfs the
    // denyRead re-application puts back hides rather than exposes, and what
    // it restores comes back read-only. It fires only for a tmpfs that
    // landed inside an emitted dest (a tmpfs comparable with the covering
    // directory). (The ancestor pins and their covers are spliced in
    // before the buffered deny binds, so neither is ever a writable emission
    // on top of one; under a '/' write root a cover adds no access that
    // root's own --bind / / had not already given. A buried pin survives a
    // later mount that shadows it, but not one AT '/': that one the pivot
    // promotes, and protection there is the deny's own EROFS.) A comparable
    // tmpfs is thus both the re-opening vector (beneath or around the dir)
    // and the only way the dir's own --ro-bind gets dropped at emission as
    // hidden-by-a-tmpfs. The vetoes stay all the same, for the reasons given
    // at each of them below. (The emission filter's
    // other drop condition, fileMasks, holds file dests only — /dev/null
    // read-deny masks and credential-mask fakes — while the pre-pass stat-verifies every
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
      const vetoInputs = getStubSkipVetoInputs()
      const unsafe =
        // (0) the prediction of what the denyRead loop will mount is
        //     unusable, so no veto below can be trusted to fire. Veto
        //     everything rather than nothing: a prediction that failed is no
        //     evidence that this directory is reliably read-only.
        !vetoInputs.usable ||
        // (i) an allowed write path strictly beneath the dir: the skip is
        //     kept to directories with nothing writable configured inside
        //     them, whatever the mount order makes of it. It is also the
        //     only veto that fires for a recorded '/' when there is no read
        //     policy, which is what sends coveredBySafeReadOnlyDenyDir
        //     through the '/' branch below instead of covering on the root's
        //     own bind.
        vetoInputs.allowedWritePathsBothForms.some(writePath =>
          isStrictlyUnder(writePath, denyDir),
        ) ||
        // (ii) a read-deny tmpfs at or beneath the dir: the tmpfs, not the
        //     covering bind, decides that subtree. Kept conservatively; the
        //     re-application's own trigger is strict containment.
        vetoInputs.prospectiveReadDenyTmpfsDirsBothForms.some(tmpfsDir =>
          isAtOrUnder(tmpfsDir, denyDir),
        ) ||
        // (iii) a read-deny tmpfs CONTAINING the dir: its own --ro-bind is
        //     dropped as hidden-by-the-tmpfs at emission, and a tmpfs above
        //     it restores allowed paths around it — either way the dir's own
        //     bind is not the last word on that subtree. A tmpfs containing
        //     only a raw spelling it was reached through counts too; that
        //     over-predicts, which only keeps a stub.
        vetoInputs.prospectiveReadDenyTmpfsDirsBothForms.some(tmpfsDir =>
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
          if (denyDir === '/') {
            // A vetoed '/' does not disqualify an inner recorded directory:
            // everything lies beneath it, so it would veto every skip and
            // stub each absent mandatory-deny path of a write-denied cwd
            // after that cwd's own bind — the startup abort. Its descendants
            // are decided by their own recorded directories.
            //
            // It does still COVER a candidate outside every predicted
            // read-deny tmpfs. Its own --ro-bind / / holds the whole tree
            // read-only from where it is emitted, burying the allow loop's
            // binds, and the only writable surface after it is a re-applied
            // tmpfs itself: the re-application passes no allowed write
            // paths, so everything it restores comes back read-only. An
            // allowed write path beneath the root is therefore not a vector
            // here, and vetoing on one only brings the abort back for
            // `allowOnly: ['/', <dir>]`. An underivable prediction proves
            // nothing and keeps the stub. Without this branch, `allowOnly:
            // ['/']` with `denyWithinAllow: ['/']` stubs each absent cwd
            // dotfile on the read-only root it just mounted — the startup
            // abort — whenever anything vetoes '/': a read-deny tmpfs
            // beneath it (the library's own /etc/ssh/ssh_config.d entry,
            // added when that directory exists) or a second allow entry.
            const vetoInputs = getStubSkipVetoInputs()
            if (
              vetoInputs.usable &&
              !vetoInputs.prospectiveReadDenyTmpfsDirsBothForms.some(tmpfsDir =>
                isAtOrUnder(candidate, tmpfsDir),
              )
            ) {
              covered = true
            }
            continue
          }
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
        // A deny's read-only bind is emitted after every allow bind, so an
        // allowed write path beneath it comes back read-only instead of
        // stopping the sandbox from starting. Say so: the config asked for
        // both and only the deny takes effect.
        for (const buried of allowedWritePaths) {
          if (isStrictlyUnder(buried, normalizedPath)) {
            logForDebugging(
              `[Sandbox Linux] Write deny ${normalizedPath} covers allowed write path ${buried}; ${buried} will be read-only`,
              { level: 'warn' },
            )
          }
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
    // Recording '/' makes isWithinAnyAllowedWritePath and isAllowedWriteRoot
    // say so, which is the '/'-write-root shape ancestorPinArgs treats
    // specially. Nothing is ever restored for it: no read-deny tmpfs lands
    // at '/'.
    allowedWritePaths.push('/')
    ancestorPinInsertAt = args.length
  }
  // denyWriteArgs is emitted after the denyRead loop below.

  // Handle read restrictions by mounting tmpfs over denied paths.
  // Non-glob spellings arrive slash-free from normalizePathForSandbox — the
  // comparisons below (hidden-by-tmpfs prefixes, the exact-match allowRead
  // skip, pushReadDenyDirMounts' re-bind checks) depend on that.

  // The read-deny mounts emitted so far, in emission order: directories
  // masked by --tmpfs with what their restore loops re-bound, and files
  // masked by --ro-bind <source> <dest> (/dev/null for read-deny, the
  // sentinel fake for a credential mask). `landing` is where each mount sits
  // in the sandbox. Every later decision reads these records: the ancestor
  // pins, the deny-bind emission filter and the re-application passes.
  const readDenyTmpfsUnits: Array<{
    dir: string
    landing: string
    restoredWrites: RestoredMount[]
    restoredReads: RestoredMount[]
  }> = []
  const fileMasks: Array<{ dest: string; source: string; landing: string }> = []

  // Replay the tmpfs units in order (bwrap is last-mount-wins): is `location`
  // beneath a unit's tmpfs and not brought back by a restore since? A restore
  // counts only where it lands. One reached through a symlink puts the
  // target's inode at the NAME; the target's own path is still under the
  // tmpfs, and asking there must not answer "brought back".
  const isHiddenByTmpfs = (
    location: string,
    broughtBackBy: 'writes' | 'writes and reads',
  ): boolean => {
    const broughtBack = (restored: readonly RestoredMount[]): boolean =>
      restored.some(r => isAtOrUnder(location, r.dest))
    let hidden = false
    for (const unit of readDenyTmpfsUnits) {
      if (isAtOrUnder(location, unit.landing)) {
        hidden = true
      }
      if (
        broughtBack(unit.restoredWrites) ||
        (broughtBackBy === 'writes and reads' &&
          broughtBack(unit.restoredReads))
      ) {
        hidden = false
      }
    }
    return hidden
  }
  // Where a mount whose destination is spelled `spelled` lands, and how to
  // spell that destination for bwrap. bwrap resolves a destination in the
  // root built so far: a component the host has at a place an earlier tmpfs
  // hid is not there, so it is created literally on that tmpfs and a symlink
  // the host has under that name is never followed; with nothing hidden on
  // the route the landing is the host's canonical location. The destination
  // is the configured spelling unless it lands somewhere an earlier tmpfs
  // hid, because bwrap cannot mount onto a symlink that dangles in the new
  // root (/bin after a tmpfs on /usr dies with ENOENT) and can always create
  // a plain path on the tmpfs. The two are one decision — the spelling is
  // chosen against its own landing — so they are derived and passed together.
  const mountPlacement = (
    spelled: string,
  ): { dest: string; landing: string } => {
    let walked = ''
    for (const name of spelled.split('/').filter(Boolean)) {
      const step = `${walked}/${name}`
      walked = isHiddenByTmpfs(step, 'writes and reads')
        ? step
        : canonicalForm(step)
    }
    const landing = walked || '/'
    return {
      dest: isHiddenByTmpfs(landing, 'writes and reads') ? landing : spelled,
      landing,
    }
  }

  // Shallow-first by canonical depth, so a tmpfs over a directory lands
  // before the tmpfs or /dev/null mask on anything inside it however either
  // was spelled. That order is what lets a unit restore its write and
  // allowRead paths unconditionally: nothing emitted so far can lie inside
  // one. Sorted by spelling, a symlink-spelled entry could mount first inside
  // a directory listed after it, whose restores would then bury it.
  const canonicalDepth = (p: string): number =>
    canonicalForm(p).split('/').length
  const normalizedDenyPaths = readDenyEntries()
    .map(p => normalizePathForSandbox(p))
    .sort((a, b) => canonicalDepth(a) - canonicalDepth(b))

  // What each entry mounts, walked once here so that the loop below and the
  // list of denied locations beside it cannot disagree about where a deny
  // lands. `target` is undefined where nothing is mounted at all;
  // `liftedFile` marks a file deny an allowRead entry naming that very file
  // cancels — the entry mounts nothing in that case either.
  const readDenyPlan = normalizedDenyPaths.map(normalizedPath => {
    const target = readDenyTargetOf(normalizedPath)
    return {
      normalizedPath,
      target,
      liftedFile:
        target !== undefined &&
        !target.isDirectory &&
        readAllowPaths().some(
          allowPath => nameLocationOf(allowPath) === canonicalForm(target.path),
        ),
    }
  })
  // Every location the read section hides, at the canonical location its
  // mount lands on: one per entry that mounts something — a directory's
  // tmpfs, the stand-in tmpfs of an entry that could not be inspected, a
  // file's /dev/null mask — and one per masked credential file. An entry
  // that mounts nothing hides nothing, and must not cost a carve-out; a
  // stand-in hides where it lands, which is above the entry that asked for
  // it.
  const readDeniedLocations = [
    ...readDenyPlan.flatMap(({ target, liftedFile }) =>
      target === undefined || liftedFile ? [] : [canonicalForm(target.path)],
    ),
    ...(maskedFileBinds ?? []).map(mask => canonicalForm(mask.realPath)),
  ]
  // What the read section hides at, inside, or around `target`, ignoring the
  // tmpfs landing at `landing` and every deny above it — those are what a
  // carve-out restored into that tmpfs is the exception to. Everything else
  // that overlaps the target wins over the carve-out. Returns the offending
  // location, for the debug line.
  const readDenialAround = (
    target: string,
    landing: string,
  ): string | undefined =>
    readDeniedLocations.find(
      denied =>
        !isAtOrUnder(landing, denied) &&
        (isAtOrUnder(denied, target) || isAtOrUnder(target, denied)),
    )

  for (const { normalizedPath, target, liftedFile } of readDenyPlan) {
    if (target === undefined) {
      logForDebugging(
        `[Sandbox Linux] Read deny path resolves to nothing this wrap can mount (absent, or uninspectable all the way up to '/'): ${normalizedPath}`,
      )
      continue
    }

    if (target.isDirectory) {
      const { dest: dir, landing } = mountPlacement(target.path)
      // A stand-in for an entry that could not be inspected hides everything
      // beneath it: nothing under it can be vouched for.
      const isStandIn = target.path !== normalizedPath
      if (isStandIn) {
        logForDebugging(
          `[Sandbox Linux] Read deny path ${normalizedPath} cannot be inspected; hiding ${target.path} instead`,
          { level: 'warn' },
        )
      }
      const restored = pushReadDenyDirMounts(args, {
        dir,
        landing,
        allowedWritePaths: isStandIn ? [] : allowedWritePaths,
        readAllowPaths: isStandIn ? [] : readAllowPaths(),
        resolve: canonicalLocationOf,
        readDenialAround: restoreTarget =>
          readDenialAround(restoreTarget, landing),
        nameLocation: nameLocationOf,
      })
      readDenyTmpfsUnits.push({ dir, landing, ...restored })
    } else {
      // For files, only an exact allowRead match overrides the deny: an
      // entry that names this very file, through whatever symlinked
      // directories. One that is a symlink to it names the link and lifts
      // nothing, or a link planted at an allowRead path would cancel the deny
      // of the file it points at. A directory allowRead does not un-deny a
      // file specifically listed in denyRead — otherwise denyRead: ['.env']
      // + allowRead: ['.'] silently drops the .env deny.
      if (liftedFile) {
        logForDebugging(
          `[Sandbox Linux] Skipping read deny for re-allowed path: ${normalizedPath}`,
        )
        continue
      }
      // For files, bind /dev/null instead of tmpfs. bwrap rejects symlink
      // bind destinations, so the deny bind lands on the resolved target.
      const { dest, landing } = mountPlacement(
        resolveSymlinkDenyDest(normalizedPath),
      )
      args.push('--ro-bind', '/dev/null', dest)
      fileMasks.push({ dest, source: '/dev/null', landing })
    }
  }

  // Whole-file credential masks: same bind shape as a file read-deny,
  // but the source is the sentinel-content fake instead of /dev/null.
  // realPath was already normalized (tilde-expanded, realpath'd) by the
  // caller; resolveSymlinkDenyDest covers the symlinked-credential case
  // for the same reason as above. The fake's parent dir is explicitly
  // ro-bound at the end of this function, so the bind source is never
  // writable from inside the sandbox.
  for (const { realPath, fakePath } of maskedFileBinds ?? []) {
    const { dest, landing } = mountPlacement(resolveSymlinkDenyDest(realPath))
    args.push('--ro-bind', fakePath, dest)
    fileMasks.push({ dest, source: fakePath, landing })
  }

  // Ancestor pinning: the directories between a deny bind, file mask or
  // read-deny tmpfs and its covering allowed write root carry no mount, so
  // rename(2) on one moves the mount along with it and the path can be
  // recreated unprotected (mv .git aside; mkdir .git; write .git/hooks/x),
  // or, for a read-denied path, is simply not found by the next command's
  // wrap and left readable under its new name. ancestorPinArgs says what is
  // pinned and where. Seeds are landings because the walk takes dirname() of
  // each: a symlink spelling would pin the chain of the link, not of where
  // the mount sits. Deny binds, tmpfs units and masks are emitted later and
  // land on top of both pins and covers.
  const pinArgs = ancestorPinArgs(
    [
      ...denyWriteRawDests.keys(),
      ...fileMasks.map(mask => mask.landing),
      ...readDenyTmpfsUnits.map(unit => unit.landing),
    ],
    {
      rootIsWriteRoot: isAllowedWriteRoot('/'),
      isWithinAllowedWrite: isWithinAnyAllowedWritePath,
      isAllowedWriteRoot,
    },
  )
  args.splice(ancestorPinInsertAt, 0, ...pinArgs)

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
  // Both are decided by where the mask or tmpfs landed against the deny's
  // canonical dest, which is where its bind lands: a symlink-spelled read
  // deny that mounted on an earlier tmpfs never covered its host target.
  const emittedDenyWriteDests: string[] = []
  // Write paths already restored read-only by a dropped deny bind, so two
  // denies covering the same path emit one --ro-bind.
  const restoredReadOnlyWritePaths = new Set<string>()
  for (let i = 0; i < denyWriteArgs.length; i += 3) {
    const dest = denyWriteArgs[i + 2]!
    const rawDest = denyWriteRawDests.get(dest) ?? dest
    // A mask's landing, not its dest: the landing is where the mask's bind
    // actually sits, and this deny's dest is canonical, so the two are
    // comparable as written.
    if (fileMasks.some(mask => mask.landing === dest)) continue
    if (isHiddenByTmpfs(dest, 'writes')) {
      logForDebugging(
        `[Sandbox Linux] Skipping denyWrite bind already hidden by denyRead tmpfs: ${dest}`,
      )
      // The tmpfs hides this dest but not a write path one of the units
      // restored writable beneath it: that path is inside this write deny, so
      // restore it read-only, where the unit left it. Emitting the dest's own
      // bind instead would expose the read-denied directory around it.
      for (const unit of readDenyTmpfsUnits) {
        for (const writeMount of unit.restoredWrites) {
          const writePath = writeMount.dest
          if (
            !isAtOrUnder(writePath, dest) &&
            !isAtOrUnder(writePath, rawDest)
          ) {
            continue
          }
          // A masked file needs no restore: its mask already holds it
          // unreadable and unwritable. A read-only bind of the real file here
          // would land ABOVE that mask, and the re-application below would
          // then have to put the mask back over a bind this loop only just
          // emitted — so skipping saves both that bind and its emitted-dest
          // entry. A masked file strictly BENEATH a restored directory is the
          // other case and stays: recording that directory is what puts its
          // mask back on top. Both spellings the record holds are checked,
          // since the restore is keyed by where the path lands.
          if (
            fileMasks.some(
              mask => mask.dest === writePath || mask.landing === writePath,
            )
          ) {
            logForDebugging(
              `[Sandbox Linux] Leaving a masked file to its mask inside dropped denyWrite bind ${dest}: ${writePath}`,
            )
            continue
          }
          if (restoredReadOnlyWritePaths.has(writePath)) continue
          restoredReadOnlyWritePaths.add(writePath)
          args.push('--ro-bind', writeMount.source, writePath)
          // Like a deny bind, this one lands above whatever the read section
          // mounted inside the write path, so the re-application passes below
          // have to see it and put those mounts back.
          emittedDenyWriteDests.push(writePath)
          logForDebugging(
            `[Sandbox Linux] Restoring write path read-only inside dropped denyWrite bind ${dest}: ${writePath}`,
          )
        }
      }
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
  // landed after the tmpfs). Re-apply the tmpfs on top, with the allowRead
  // re-binds the denyRead loop emitted. A bind of '/' itself (allowOnly and
  // denyWithinAllow both naming it) contains every one of them, so
  // containment is root-aware. An allowed write path beneath such a tmpfs
  // lies inside the emitted deny dest too, so the deny wins: it comes back
  // read-only, visible as it was after the first pass but not writable.
  // Deeper units and masks under the same dest follow in the same order as
  // the first pass, so nothing restored here stays on top of one.
  for (const unit of readDenyTmpfsUnits) {
    const reExposingDest = emittedDenyWriteDests.find(dest =>
      isStrictlyUnder(unit.landing, dest),
    )
    if (reExposingDest !== undefined) {
      logForDebugging(
        `[Sandbox Linux] Re-applying denyRead tmpfs re-exposed by denyWrite bind: ${unit.dir}`,
      )
      // Name the paths that lose their write access here, and to which deny.
      if (unit.restoredWrites.length > 0) {
        logForDebugging(
          `[Sandbox Linux] Restoring write paths read-only inside denyWrite bind ${reExposingDest}: ${unit.restoredWrites.map(w => w.dest).join(', ')}`,
        )
      }
      // The recorded pairs go back as they are: each restore returns to where
      // the first pass put it, from the source it vetted then. Write paths
      // come back read-only, being inside the deny that re-exposed the tmpfs.
      args.push('--tmpfs', unit.dir)
      for (const restored of [...unit.restoredWrites, ...unit.restoredReads]) {
        args.push('--ro-bind', restored.source, restored.dest)
      }
    }
  }
  // Same problem for masked files: the mask landed before the denyWrite
  // ancestor bind, so the real file is back. Re-apply the mask with its
  // original source (/dev/null for read-deny, the fake for credential mask).
  for (const mask of fileMasks) {
    if (emittedDenyWriteDests.some(dest => isAtOrUnder(mask.landing, dest))) {
      logForDebugging(
        `[Sandbox Linux] Re-applying file mask re-exposed by denyWrite bind: ${mask.dest}`,
      )
      args.push('--ro-bind', mask.source, mask.dest)
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
    const mountsStart = bwrapArgs.length
    bwrapArgs.push(...fsArgs)
    const mounts = { start: mountsStart, end: bwrapArgs.length }

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

    const wrappedCommand = renderBwrapInvocation(
      bwrapPath ?? 'bwrap',
      bwrapArgs,
      mounts,
    )

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
