import { quote } from '../utils/shell-quote.js'
import { logForDebugging } from '../utils/debug.js'
import { whichSync } from '../utils/which.js'
import { randomBytes } from 'node:crypto'
import * as fs from 'fs'
import { spawn, spawnSync } from 'node:child_process'
import type { ChildProcess } from 'node:child_process'
import { endianness, tmpdir } from 'node:os'
import path, { join } from 'node:path'
import {
  ripGrep,
  RipgrepError,
  DEFAULT_RIPGREP_TIMEOUT_MS,
  type RipgrepConfig,
} from '../utils/ripgrep.js'
import { buildJavaToolOptions } from './java-proxy-agent.js'
import {
  generateProxyEnvVars,
  buildPosixGitSafeDirEnv,
  normalizePathForSandbox,
  normalizeCaseForComparison,
  isSymlinkOutsideBoundary,
  encodeSandboxedCommand,
  attributionKeyFor,
  DANGEROUS_FILES,
  isAbsenceErrno,
  isAtOrUnder,
  isStrictlyUnder,
  getDangerousDirectories,
  MAX_SYMLINK_RESOLUTION_DEPTH,
} from './sandbox-utils.js'
import {
  GitMetadataError,
  SubmoduleWalkBudgetError,
  gitDirDenies,
  gitDirTreeDenies,
  gitDirTreeDenyPaths,
  gitFileDenies,
  gitRedirectPlaceholder,
} from './mandatory-deny-paths.js'
import type { GitDirTreeDenies, GitChainHop } from './mandatory-deny-paths.js'
import type {
  CollapseLevel,
  RepositorySubmodules,
  SubmoduleDenyPlan,
} from './linux-deny-collapse.js'
import {
  NO_COLLAPSE,
  collapseFurther,
  collapsedDenyPaths,
  describeCollapse,
  repositorySubmodules,
} from './linux-deny-collapse.js'
import type {
  FsReadRestrictionConfig,
  FsWriteRestrictionConfig,
} from './sandbox-schemas.js'
import { MaskedFileStore } from './credential-mask-files.js'
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
  ripgrepConfig?: RipgrepConfig
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
      if (stat.isFile()) {
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
 * What `file` holds, when it is a regular file of no more than `limit`
 * bytes; undefined for anything else, which is everything this needs to tell
 * from the placeholders it compares against.
 */
function fileContentsWithin(file: string, limit: number): string | undefined {
  try {
    const stat = fs.lstatSync(file)
    if (!stat.isFile() || stat.size > limit) return undefined
    return fs.readFileSync(file, 'utf8')
  } catch {
    return undefined
  }
}

/** What the deny of a file git reads back binds, once `dest` is ready. */
type GitRedirectBind =
  /** Bind this over `dest`, the ordinary answer. */
  | { bind: string }
  /** Nothing can be put at `dest`: bind this git directory read-only. */
  | { denyGitDirWhole: string }

/**
 * Make `dest` ready for the read-only bind that denies it, where it is one
 * of the files git reads back (`GIT_REDIRECT_FILES` in
 * src/sandbox/mandatory-deny-paths.ts says which and why), and say what to
 * bind. Called at emission time, because it writes on the HOST: a bind the
 * emission drops must not have cost anything.
 *
 * Three arms. Absent: the mount point is written here rather than left to
 * bubblewrap, holding the placeholder — a mount point bubblewrap makes is
 * empty, and git refuses to run at all against a `commondir` it cannot read
 * — with bubblewrap's own read-only mode, so that a wrap killed before its
 * cleanup leaves a file the next wrap can recognise. There, empty and in
 * that shape: this wrapper's own to repair and remove. Anything else: the
 * caller's file, and only the bind lands on it.
 *
 * What is bound is the store's copy, never the mount point itself: a host
 * process rewriting the file between this call and the mount would otherwise
 * choose what the sandbox reads, and another process's cleanup could unlink
 * the source out from under a live bind.
 *
 * Throws {@link LinuxSandboxProfileError} when the placeholder cannot be
 * prepared at all: what is left is /dev/null, which costs the repository
 * every git command inside the sandbox and, through the mount point, outside
 * it as well, so the command is refused rather than run behind that.
 */
function gitRedirectMountPoint(
  dest: string,
  placeholder: string,
  storeFiles: Map<string, string>,
): GitRedirectBind {
  const takeOwnership = (): void => {
    bwrapMountPoints.set(dest, placeholder)
    registerExitCleanupHandler()
  }
  const bindFromStore = (): GitRedirectBind => ({
    bind: gitRedirectStoreFile(dest, placeholder, storeFiles),
  })

  let written = false
  try {
    // Exclusive: a file that appeared since the deny loop looked is never
    // truncated, it falls to the existing-file arms below. Read-only, the
    // mode bubblewrap's ensure_file() leaves, so that a process killed
    // before the cleanup leaves a file the next wrap can recognise as one of
    // these rather than as a file somebody meant to be there.
    fs.writeFileSync(dest, placeholder, { flag: 'wx', mode: 0o444 })
    written = true
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code
    if (code === 'EACCES' || code === 'EPERM' || code === 'EROFS') {
      // A git directory this process cannot write — a vendored checkout
      // owned by another user, a read-only mount, one the command itself
      // made unwritable. Refusing every command in the tree over that would
      // be a brick a sandboxed command can plant; a read-only bind of the
      // directory denies the file and every other way into it at once.
      const gitDir = path.dirname(dest)
      logForDebugging(
        `[Sandbox Linux] ${gitDir} takes no mount point for ${path.basename(dest)} (${errorText(err)}); denying the git directory whole instead, which needs nothing written to it`,
        { level: 'warn' },
      )
      return { denyGitDirWhole: gitDir }
    }
    if (code !== 'EEXIST') {
      throw placeholderUnavailable(
        dest,
        'its mount point could not be made',
        err,
      )
    }
  }
  if (written) {
    takeOwnership()
    logForDebugging(
      `[Sandbox Linux] Wrote the mount point ${dest} holding ${JSON.stringify(placeholder)}, so git reads no redirect there while the command runs`,
    )
    return bindFromStore()
  }

  const contents = fileContentsWithin(dest, Buffer.byteLength(placeholder))
  if (contents === '' && placeholder !== '') {
    if (!isStaleBwrapMountPoint(dest)) {
      // Empty and not the shape bubblewrap leaves: a host git caught between
      // creating the file and writing it owns this one. Cover it with the
      // placeholder for the length of the command and leave the file alone.
      logForDebugging(
        `[Sandbox Linux] Binding ${JSON.stringify(placeholder)} over the empty ${dest}: it is not the shape bubblewrap leaves, so it is not this wrapper's to rewrite`,
      )
      return bindFromStore()
    }
    try {
      // bubblewrap makes its mount points read-only (ensure_file(dest,
      // 0444)), and the process that owns one need not be root, so the mode
      // it was left with is no reason to leave the repository broken.
      try {
        fs.writeFileSync(dest, placeholder)
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code !== 'EACCES') throw err
        fs.chmodSync(dest, 0o644)
        fs.writeFileSync(dest, placeholder)
      }
    } catch (err) {
      throw placeholderUnavailable(
        dest,
        'the empty file left there could not be rewritten',
        err,
      )
    }
    takeOwnership()
    logForDebugging(
      `[Sandbox Linux] Rewrote ${dest}, left empty by a sandbox that did not clean up, to ${JSON.stringify(placeholder)}: git reads no bytes there as a fault, not as "no redirect"`,
    )
    return bindFromStore()
  }
  if (
    contents === placeholder &&
    (placeholder !== '' || isStaleBwrapMountPoint(dest))
  ) {
    // This wrapper's own, left by a process that could not clean up: nothing
    // else writes exactly these bytes there, and for an empty placeholder
    // nothing else leaves a file of that shape. Removed with the rest, and
    // bound from the store rather than from itself: another process wrapping
    // a command in the same repository can claim and remove this same file,
    // and a bind whose source is unlinked while the sandbox runs is a bind
    // that no longer denies anything.
    takeOwnership()
    logForDebugging(
      `[Sandbox Linux] ${dest} already holds the placeholder ${JSON.stringify(placeholder)} an earlier sandbox left; binding the store's copy over it and taking it away with this wrap's mount points`,
    )
    return bindFromStore()
  }
  logForDebugging(
    `[Sandbox Linux] Binding ${dest} from itself: what it holds is not the ${JSON.stringify(placeholder)} placeholder, so it is not this wrapper's to replace`,
  )
  return { bind: dest }
}

/**
 * The store's copy of `placeholder`, made once per wrap: the store unlinks
 * and rewrites the file on every call, which is what revalidates it, and one
 * wrap needs one such check however many destinations share the content.
 */
function gitRedirectStoreFile(
  dest: string,
  placeholder: string,
  storeFiles: Map<string, string>,
): string {
  const made = storeFiles.get(placeholder)
  if (made !== undefined) return made
  try {
    // Keyed by content, so one file serves every destination that needs it.
    const file = gitRedirectStore.write(placeholder, placeholder)
    storeFiles.set(placeholder, file)
    return file
  } catch (err) {
    throw placeholderUnavailable(
      dest,
      'no placeholder file could be written to the temporary directory',
      err,
    )
  }
}

/** Refuse the wrap, once, naming what could not be prepared and why. */
function placeholderUnavailable(
  dest: string,
  what: string,
  cause: unknown,
): LinuxSandboxProfileError {
  const message =
    `Cannot deny ${dest} without stopping git from working in that ` +
    `repository: ${what} (${errorText(cause)}). git refuses to run at all ` +
    `against a redirect file it cannot read, so the command was not run ` +
    `rather than sandboxed behind a deny that breaks it`
  logForDebugging(`[Sandbox Linux] ${message}`, { level: 'warn' })
  return new LinuxSandboxProfileError(
    'deny_placeholder_unavailable',
    message,
    cause,
  )
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

/** Where `parts` first occurs as consecutive segments of `segments`, or -1. */
function indexOfSegmentRun(segments: string[], parts: string[]): number {
  return segments.findIndex((_, i) =>
    parts.every((part, j) => segments[i + j] === part),
  )
}

/** The errno a walk of an unreadable directory ends on. */
const EACCES = 13
/** The errno a walk of something that has gone away ends on. */
const ENOENT = 2

/**
 * Every OS error code a failed ripgrep run mentioned, from the `(os error N)`
 * tokens rg appends to each diagnostic. NO PATH IS EVER TAKEN FROM THIS TEXT:
 * a directory's name is chosen by whoever created it and lands in stderr
 * unescaped, so any path read out of a line can be a name rather than the
 * file rg failed on. A name can only ADD tokens, and an unrecognised token
 * refuses the wrap, so the worst a chosen name does is refuse.
 */
function ripgrepFailureErrnos(stderr: string): Set<number> {
  const errnos = new Set<number>()
  for (const match of stderr.matchAll(/\(os error (\d+)\)/g)) {
    errnos.add(Number(match[1]))
  }
  return errnos
}

/** At most `limit` characters of `text`, with what was dropped noted. */
function truncated(text: string, limit = 400): string {
  const collapsed = text.trim()
  return collapsed.length <= limit
    ? collapsed
    : `${collapsed.slice(0, limit)}… (${collapsed.length - limit} more characters)`
}

/**
 * The directories under `cwd` this process cannot read — cannot list at all,
 * or holding an entry it cannot type — walked the way the scan walks:
 * `readdir` with the kernel's own entry types, symlinks not followed,
 * `node_modules` skipped as the scan's globs skip it, no deeper than the
 * scan reaches. This is what stands in for parsing paths out of rg's stderr:
 * the answer comes off the filesystem, so a directory NAME cannot add to it,
 * aim it elsewhere, or empty it. `collectGitDirs` also gathers the `.git`
 * directories the walk passes.
 *
 * Throws {@link LinuxSandboxProfileError} when `deadline` passes: the walk
 * spends what is left of the scan's own time budget and no more.
 */
function walkScanDirectories(
  cwd: string,
  maxDepth: number,
  deadline: number,
  collectGitDirs = false,
): { unreadableDirs: string[]; gitDirs: string[] } {
  const unreadableDirs: string[] = []
  const gitDirs: string[] = []

  const isDirectory = (
    entry: fs.Dirent,
    child: string,
  ): boolean | undefined => {
    if (entry.isDirectory()) return true
    if (
      entry.isFile() ||
      entry.isSymbolicLink() ||
      entry.isFIFO() ||
      entry.isSocket() ||
      entry.isBlockDevice() ||
      entry.isCharacterDevice()
    ) {
      return false
    }
    // The filesystem returned no type with the entry (DT_UNKNOWN), so ask.
    try {
      return fs.lstatSync(child).isDirectory()
    } catch (err) {
      // Gone since the listing: nothing there to walk or to deny.
      return isAbsenceErrno(err) ? false : undefined
    }
  }

  const walk = (dir: string, depth: number): void => {
    if (Date.now() > deadline) {
      throw denyScanFailed(
        cwd,
        'left too little of its time budget to walk what it could not report on',
        new Error(`the walk stopped at ${dir}`),
      )
    }
    let entries: fs.Dirent[]
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true })
    } catch (err) {
      // Absent means it went away mid-walk, which leaves nothing to deny.
      if (!isAbsenceErrno(err)) unreadableDirs.push(dir)
      return
    }
    for (const entry of entries) {
      // Excluded from the scan's globs, so rg never reports one either.
      if (entry.name === 'node_modules') continue
      const child = path.join(dir, entry.name)
      const directory = isDirectory(entry, child)
      if (directory === undefined) {
        unreadableDirs.push(dir)
        return
      }
      if (!directory) continue
      if (collectGitDirs && entry.name === '.git' && depth + 2 <= maxDepth) {
        // The depth the scan itself reaches a repository at: it recognises
        // one by a file directly inside .git, one level further down.
        gitDirs.push(child)
      }
      if (depth + 1 < maxDepth) walk(child, depth + 1)
    }
  }

  walk(cwd, 0)
  return { unreadableDirs, gitDirs }
}

/**
 * Refuse the wrap, naming what the scan did instead of delivering the deny
 * paths below `cwd`. Sandboxing on a listing that stops somewhere unknown is
 * how a nested repository keeps writable hooks, so the wrap is refused.
 */
function denyScanFailed(
  cwd: string,
  what: string,
  cause: unknown,
): LinuxSandboxProfileError {
  const message =
    `The ripgrep scan of ${cwd} ${what} (${errorText(cause)}), so what it ` +
    `would have denied below there is unknown: the command was not run ` +
    `rather than sandboxed behind a deny list that may leave a nested ` +
    `repository's hooks writable`
  logForDebugging(`[Sandbox Linux] ${message}`, { level: 'warn' })
  return new LinuxSandboxProfileError('deny_scan_failed', message, cause)
}

/**
 * The part of the mandatory deny set that follows from the cwd alone: the
 * dangerous files and directories resolved against it, and what its own
 * `.git` leads to — the repository's hooks, config and redirect files and
 * those of its submodule git directories, or, where `.git` is a pointer
 * file, the file itself and the git directories it names.
 * {@link linuxGetMandatoryDenyPaths} adds the nested matches its ripgrep scan
 * finds on top of these. Split out so a consumer that must not scan — the
 * violation monitor, which needs the same denies to judge a write bwrap
 * refuses — reads the same definition rather than a copy of it.
 */
export function linuxGetCwdMandatoryDenyPaths(
  allowGitConfig = false,
  allowWritePaths: readonly string[] = [],
): string[] {
  const plan = cwdMandatoryDenyPlan(allowGitConfig, undefined)
  return [
    ...collapsedDenyPaths(plan, NO_COLLAPSE),
    ...chainHopDenies(plan.chainHops, allowWritePaths).held,
  ]
}

/** {@link linuxGetCwdMandatoryDenyPaths} with the working directory's own
 *  submodules still separable, which is what a wrap whose profile does not
 *  fit degrades. */
function cwdMandatoryDenyPlan(
  allowGitConfig: boolean,
  deadline: number | undefined,
): SubmoduleDenyPlan {
  const cwd = process.cwd()
  const denyPaths = cwdDangerousDenyPaths(cwd)
  const repositories: RepositorySubmodules[] = []
  const chainHops: GitChainHop[] = []

  const dotGitPath = path.resolve(cwd, '.git')
  let dotGitStat: fs.Stats | undefined
  try {
    dotGitStat = fs.statSync(dotGitPath)
  } catch (err) {
    // Absent is the ordinary case, and nothing is denied then: a mount at
    // .git would block `git init`. Anything else means a .git is there and
    // could not be looked at, which is no reason to skip the enumeration —
    // deny it whole instead.
    if (!isAbsenceErrno(err)) {
      return { denyPaths: [...denyPaths, dotGitPath], repositories, chainHops }
    }
  }
  if (dotGitStat?.isDirectory()) {
    const denies = gitDirTreeDenies(dotGitPath, allowGitConfig, { deadline })
    denyPaths.push(...linuxGitDirTreeDenyPaths(denies))
    chainHops.push(...denies.chainHops)
    const repository = repositorySubmodules(denies)
    if (repository !== undefined) repositories.push(repository)
  } else if (dotGitStat?.isFile()) {
    // A pointer file (linked worktree, submodule checkout) has no hooks/
    // beneath it, and binding a path under a file makes bwrap fail.
    const pointer = gitFileDenies(dotGitPath, allowGitConfig)
    denyPaths.push(
      ...withoutChainHopLinks(pointer.denyPaths, pointer.chainHops),
      ...pointer.linkedEntryDirs,
    )
    chainHops.push(...pointer.chainHops)
  }

  return { denyPaths, repositories, chainHops }
}

/**
 * {@link gitDirTreeDenyPaths} plus the directories that have to be denied
 * WHOLE because they hold an entry that is a symlink, and minus the deny
 * paths that name a symlink itself. Both follow from the same thing: a bind
 * lands on what a deny path resolves to, so the link's own path keeps
 * nothing and the directory around it is the handle on it, while a Seatbelt
 * filter matches the path as a rename or an unlink names it and needs
 * neither (see `gitDirDenies` in src/sandbox/mandatory-deny-paths.ts).
 */
function linuxGitDirTreeDenyPaths(denies: GitDirTreeDenies): string[] {
  return [
    ...withoutChainHopLinks(gitDirTreeDenyPaths(denies), denies.chainHops),
    ...denies.linkedEntryDirs,
  ]
}

/**
 * `denyPaths` without the ones naming an intermediate hop of a chain. A bind
 * there lands on whatever the link leads to — for a symlinked directory
 * component a whole directory nothing asked to deny, and for a `.git/modules`
 * entry the git directory it reaches — while holding the link itself, which
 * is the point, is what the hop's HOLDER is denied whole for.
 */
function withoutChainHopLinks(
  denyPaths: string[],
  chainHops: readonly GitChainHop[],
): string[] {
  if (chainHops.length === 0) return denyPaths
  const links = new Set(chainHops.map(hop => hop.link))
  return denyPaths.filter(denyPath => !links.has(denyPath))
}

/**
 * Which of the symlinks a git directory is reached THROUGH — between an entry
 * and what it leads to, or in the path a `gitdir:` pointer's value walks —
 * this backend can hold, and which it cannot.
 *
 * A bind cannot be put on a link — the destination resolves — so the
 * directory holding one is the whole handle, exactly as the git directory is
 * the handle on the entry's own link. `held` is those directories, one
 * read-only bind each, charged to the mount budget like any other deny.
 *
 * Three kinds are not in it. A hop a whole-directory deny already covers
 * names no holder at all. A hop no allowed write path contains is read-only
 * from the initial `--ro-bind / /` already, and a bind of the directory
 * around it would buy nothing. A hop whose holder IS a write root or the
 * working directory, or sits above one, has nothing that can be bound over it
 * — the bind would take the whole tree read-only, and a repository laid out
 * that way (`.git/hooks -> ../hooks-link`, with `hooks-link` in the
 * repository root) is one the caller had before this library saw it, so
 * refusing every command in it is the wrong answer too. That last kind comes
 * back in `unheld`, for the warning that has to stand in for a bind.
 */
function chainHopDenies(
  chainHops: readonly GitChainHop[],
  allowWritePaths: readonly string[],
): { held: string[]; unheld: GitChainHop[] } {
  const held = new Set<string>()
  const unheld: GitChainHop[] = []
  const cwd = process.cwd()
  for (const hop of chainHops) {
    const holder = hop.holder
    if (holder === undefined) continue
    if (!allowWritePaths.some(allowed => isAtOrUnder(holder, allowed))) {
      continue
    }
    if (
      isAtOrUnder(cwd, holder) ||
      allowWritePaths.some(allowed => isAtOrUnder(allowed, holder))
    ) {
      unheld.push(hop)
      continue
    }
    held.add(holder)
  }
  return { held: [...held], unheld }
}

/**
 * `plan` with the directories holding a chain hop this backend can bind added
 * to its deny paths, and one warning per wrap for the hops it cannot bind —
 * the only channel a wrap has to say so. Ordinary trees have no hops at all
 * and pay nothing here.
 */
function withChainHopDenies(
  plan: SubmoduleDenyPlan,
  allowWritePaths: readonly string[],
): SubmoduleDenyPlan {
  if (plan.chainHops.length === 0) return plan
  const { held, unheld } = chainHopDenies(plan.chainHops, allowWritePaths)
  if (unheld.length > 0) {
    const told = unheld
      .map(hop =>
        hop.kind === 'pointer'
          ? `the git directory ${hop.source} names is reached through ${hop.link}`
          : `${hop.source} reaches what it denies through ${hop.link}`,
      )
      .join('; ')
    const holders = [...new Set(unheld.map(hop => hop.holder))].join(', ')
    logForDebugging(
      `[Sandbox Linux] ${told}. A read-only bind of the directory holding such a link is the only thing that holds it, and ${holders} is the working directory or a path this command may write, which binding read-only would take the whole tree with: a command in this sandbox can point the link somewhere else, and a git run on the host afterwards follows it there. Moving the link inside the git directory, spelling the pointer's path without it, or a denyWrite entry naming the directory holding it, closes that.`,
      { level: 'warn' },
    )
  }
  if (held.length === 0) return plan
  const denied = new Set(plan.denyPaths)
  return {
    ...plan,
    denyPaths: [...plan.denyPaths, ...held.filter(dir => !denied.has(dir))],
  }
}

/**
 * The deny paths `cwd` has whatever its `.git` turns out to be, and whatever
 * can be read of it. Settings files are added at the callsite in
 * src/sandbox/sandbox-manager.ts.
 */
function cwdDangerousDenyPaths(cwd: string): string[] {
  return [
    // Dangerous files in CWD
    ...DANGEROUS_FILES.map(f => path.resolve(cwd, f)),
    // Dangerous directories in CWD
    ...getDangerousDirectories().map(d => path.resolve(cwd, d)),
  ]
}

/**
 * {@link linuxGetCwdMandatoryDenyPaths} for the violation monitor, which is
 * started once for the session and must not fail over one repository: the
 * same paths, or - where the enumeration refuses - this directory's plain
 * deny paths, with a warning naming which refusal it was. What this decides
 * is which refused write the monitor reports, never what bubblewrap
 * enforces.
 *
 * Nothing is collapsed here. A wrap collapses only where its own profile does
 * not fit, which is measured per command, while this is computed once for the
 * session: a command that forces a collapse later leaves the monitor naming
 * the precise path under a submodule git directory the wrap has by then
 * denied whole. The write is refused either way; the path in the report is
 * the one inside it.
 */
export function linuxGetMonitorCwdDenyPaths(
  allowGitConfig: boolean,
  allowWritePaths: readonly string[] = [],
): string[] {
  try {
    return linuxGetCwdMandatoryDenyPaths(allowGitConfig, allowWritePaths)
  } catch (err) {
    const cwd = process.cwd()
    logForDebugging(
      `[Sandbox Linux] ${monitorFallbackReason(cwd, err)}; the violation monitor judges writes against ${cwd}'s plain deny paths instead.`,
      { level: 'warn' },
    )
    return [
      ...cwdDangerousDenyPaths(cwd),
      ...monitorDotGitDenyPaths(cwd, allowGitConfig, allowWritePaths),
    ]
  }
}

/** Why the monitor is falling back, in the terms of the thing that failed:
 *  the two refusals differ in what a wrapped command in this directory gets. */
function monitorFallbackReason(cwd: string, err: unknown): string {
  if (err instanceof SubmoduleWalkBudgetError) {
    return `The walk of this repository's submodule git directories ran out of the time it was given (${errorText(err)}), which a wrap retakes from the clock and may well finish`
  }
  return `Could not resolve ${path.resolve(cwd, '.git')} the way git does (${errorText(err)}). Every wrapped command in this directory is refused until that is fixed`
}

/**
 * What the monitor treats as denied under `cwd`'s own `.git`, without
 * following anything: the same three answers the wrap gives for the shape
 * `.git` turns out to be. Absent is none of them — the wrap denies nothing
 * there either, since a mount at `.git` would block `git init`.
 */
function monitorDotGitDenyPaths(
  cwd: string,
  allowGitConfig: boolean,
  allowWritePaths: readonly string[],
): string[] {
  const dotGitPath = path.resolve(cwd, '.git')
  let dotGitStat: fs.Stats | undefined
  try {
    dotGitStat = fs.statSync(dotGitPath)
  } catch (err) {
    // There and not inspectable: denied whole, as the wrap denies it.
    return isAbsenceErrno(err) ? [] : [dotGitPath]
  }
  // A pointer file is itself a deny, and what it leads to is exactly what
  // could not be followed; a git directory's own hooks and config need
  // nothing followed to name.
  if (dotGitStat.isFile()) return [dotGitPath]
  if (dotGitStat.isDirectory()) {
    const denies = gitDirDenies(dotGitPath, allowGitConfig)
    return [
      ...withoutChainHopLinks(denies.denyPaths, denies.chainHops),
      ...denies.linkedEntryDirs,
      ...chainHopDenies(denies.chainHops, allowWritePaths).held,
    ]
  }
  return []
}

/**
 * Get mandatory deny paths using ripgrep (Linux only).
 * Uses a SINGLE ripgrep call with multiple glob patterns for efficiency.
 *
 * Runs on each command without memoization. `--max-depth` keeps that to
 * milliseconds on ordinary trees, but `--no-ignore` means gitignored data
 * within the depth is walked too: measured at about +100 ms per command on a
 * tree with 150k ignored files three levels down. A scan that does not
 * deliver what is below the working directory aborts the wrap rather than
 * sandboxing with a deny list of unknown completeness: one that could not be
 * run at all, one that does not finish inside {@link ripGrep}'s timeout, and
 * one that failed for a reason no deny stands in for. The failures that are
 * not fatal are told apart by the `(os error N)` codes on stderr and never
 * by the paths printed beside them — see {@link ripgrepFailureErrnos}.
 */
async function linuxGetMandatoryDenyPaths(
  ripgrepConfig: RipgrepConfig = { command: 'rg' },
  maxDepth: number = DEFAULT_MANDATORY_DENY_SEARCH_DEPTH,
  allowGitConfig = false,
  abortSignal?: AbortSignal,
): Promise<SubmoduleDenyPlan> {
  const cwd = process.cwd()
  const timeoutMs = ripgrepConfig.timeoutMs ?? DEFAULT_RIPGREP_TIMEOUT_MS
  // What the scan gets, and what the walk of the working directory's own
  // submodules that runs before it gets. Every walk made AFTER the scan takes
  // a budget of its own of the same length: the scan has its own timeout, and
  // a slow but successful one would otherwise refuse a repository whose
  // submodules a walk given the time would have got through.
  const deadline = Date.now() + timeoutMs
  const walkDeadline = (): number => Date.now() + timeoutMs
  // Use provided signal or create a fallback controller
  const fallbackController = new AbortController()
  const signal = abortSignal ?? fallbackController.signal
  const dangerousDirectories = getDangerousDirectories()

  // The working directory's own repository is the first the collapse works
  // back through, so it is the last to lose its precise denies.
  const plan = asProfileRefusal(() =>
    cwdMandatoryDenyPlan(allowGitConfig, deadline),
  )
  const denyPaths = plan.denyPaths

  // Each nested repository the scan finds, once: the same walk the cwd's own
  // git directory already had above, which every file listed under it leads
  // back to. Collected rather than denied as they are met, because ripgrep
  // lists a tree in whatever order its threads finish it in and a collapse
  // works back through them in the order they were served: two wraps of one
  // tree would otherwise degrade different repositories.
  const seenGitDirs = new Set<string>([path.resolve(cwd, '.git')])
  const nestedGitDirs: string[] = []
  const denyGitDir = (gitDir: string): void => {
    if (seenGitDirs.has(gitDir)) return
    seenGitDirs.add(gitDir)
    nestedGitDirs.push(gitDir)
  }
  const walkScan = (collectGitDirs: boolean) =>
    walkScanDirectories(cwd, maxDepth, walkDeadline(), collectGitDirs)

  // Build iglob args for all patterns in one ripgrep call
  const iglobArgs: string[] = []
  for (const fileName of DANGEROUS_FILES) {
    iglobArgs.push('--iglob', fileName)
  }
  for (const dirName of dangerousDirectories) {
    iglobArgs.push('--iglob', `**/${dirName}/**`)
  }
  // A nested repository is recognised by ANY regular file directly inside its
  // .git directory, so its hooks/ and config are denied at the depth the
  // repository itself is found, not one level further down where the hook
  // files sit (with the default depth, a repository directly under cwd has
  // .git/config within reach but .git/hooks/* beyond it). Detection must not
  // depend on any one file the sandboxed command could move aside, nor on
  // allowGitConfig, which governs what is denied and not what is found.
  // A FILE named .git is a worktree/submodule pointer (gitFileDenyPaths).
  iglobArgs.push('--iglob', '**/.git/*', '--iglob', '**/.git')

  // Single ripgrep call to find all dangerous paths in subdirectories
  // Limit depth for performance - deeply nested dangerous files are rare
  // and the security benefit doesn't justify the traversal cost
  let matches: string[] = []
  try {
    matches = await ripGrep(
      [
        '--files',
        '--hidden',
        // .gitignore, .ignore and .rgignore are writable inside the sandbox:
        // honouring them would let one command hide a nested repository
        // from the next command's scan.
        '--no-ignore',
        '--max-depth',
        String(maxDepth),
        ...iglobArgs,
        // The directory itself as well as what is under it: excluding only
        // the contents leaves rg trying to open an unreadable node_modules,
        // which fails the whole run over a directory nothing here wants.
        '-g',
        '!**/node_modules',
        '-g',
        '!**/node_modules/**',
      ],
      cwd,
      signal,
      ripgrepConfig,
    )
  } catch (error) {
    if (!(error instanceof RipgrepError)) {
      // The run never got far enough to report anything of its own: the
      // binary could not be spawned or this process is out of descriptors —
      // the missing dependency the start-up check refuses on, met later — or
      // the caller aborted, which is its own answer and travels as itself.
      if ((error as { name?: unknown }).name === 'AbortError') throw error
      throw denyScanFailed(cwd, 'could not be run', error)
    }
    if (error.timedOut) {
      // The command that runs next is the one that could have made the tree
      // slow to walk, so a truncated listing is not something to sandbox on:
      // an unreached nested repository would be one with writable hooks.
      throw denyScanFailed(cwd, 'did not finish', error)
    }
    // rg lists the rest of the tree and exits non-zero when an entry gets in
    // its way, so the matches still count — but only where every code it
    // reported is one a deny stands in for. Anything else, and anything that
    // reported no code at all, leaves whatever the run did not reach unknown.
    const errnos = ripgrepFailureErrnos(error.stderr)
    const stoodInFor = [...errnos].every(
      errno => errno === ENOENT || errno === EACCES,
    )
    if (errnos.size === 0 || !stoodInFor) {
      throw denyScanFailed(
        cwd,
        `failed for a reason no deny stands in for: ${truncated(error.stderr) || '(nothing on stderr)'}`,
        error,
      )
    }
    matches = error.partialMatches
    if (errnos.has(EACCES)) {
      // A directory rg could not read holds an unknown tree, so it is denied
      // whole. WHICH directories is settled by walking the filesystem, not by
      // reading rg's stderr: a name in there is chosen by whoever made the
      // directory. A walk finding none means the run failed over something
      // this cannot see, so there is nothing to stand in for it.
      const { unreadableDirs } = walkScan(false)
      if (unreadableDirs.length === 0) {
        throw denyScanFailed(
          cwd,
          `reported a directory it could not read, and none is there now: ${truncated(error.stderr)}`,
          error,
        )
      }
      denyPaths.push(...unreadableDirs)
      logForDebugging(
        `[Sandbox] ripgrep scan of ${cwd} could not read ${unreadableDirs.length} of the directories under it, which are denied whole; the ${matches.length} paths it did list still count: ${error}`,
        { level: 'warn' },
      )
    } else {
      // Every code was ENOENT: entries that went away while rg walked. There
      // is nothing at those paths to deny, and mounting one would plant a
      // file on the host where the command deleted one.
      logForDebugging(
        `[Sandbox] ripgrep scan of ${cwd} lost entries while it walked, which leaves nothing to deny; the ${matches.length} paths it did list still count: ${error}`,
        { level: 'warn' },
      )
    }
  }

  const dirPatterns = dangerousDirectories.map(d =>
    normalizeCaseForComparison(d).split('/'),
  )
  for (const match of matches) {
    // rg prefixes each match with its target, cwd, and does not follow
    // symlinks, so every line is under it. Segments are compared relative to
    // cwd, so a dangerous name in cwd's own location never counts.
    const relative = path.relative(cwd, match).split(path.sep)
    const lowered = relative.map(normalizeCaseForComparison)

    const dirRun = dirPatterns
      .map(parts => ({ parts, at: indexOfSegmentRun(lowered, parts) }))
      .find(({ at }) => at !== -1)
    if (dirRun) {
      // The directory, not the file, so files created in it later are covered.
      const end = dirRun.at + dirRun.parts.length
      denyPaths.push(path.join(cwd, ...relative.slice(0, end)))
      continue
    }
    const gitAt = lowered.indexOf('.git')
    if (gitAt === -1) {
      denyPaths.push(match)
    } else if (gitAt < relative.length - 1) {
      denyGitDir(path.join(cwd, ...relative.slice(0, gitAt + 1)))
    } else if (relative.length > 1) {
      // cwd's own pointer file is handled above, before the scan.
      const pointer = asProfileRefusal(() =>
        gitFileDenies(match, allowGitConfig),
      )
      denyPaths.push(
        ...withoutChainHopLinks(pointer.denyPaths, pointer.chainHops),
        ...pointer.linkedEntryDirs,
      )
      plan.chainHops.push(...pointer.chainHops)
    }
  }

  if (allowGitConfig) {
    // The scan recognises a repository by a regular file directly inside its
    // .git. With the config deny in place one is always there and cannot be
    // removed from inside the sandbox; with config writes allowed a command
    // can empty the directory of regular files and hide the repository from
    // the next command's scan, so the directories are found here instead.
    for (const gitDir of walkScan(true).gitDirs) denyGitDir(gitDir)
  }

  for (const gitDir of nestedGitDirs.sort()) {
    const denies = asProfileRefusal(() =>
      gitDirTreeDenies(gitDir, allowGitConfig, { deadline: walkDeadline() }),
    )
    denyPaths.push(...linuxGitDirTreeDenyPaths(denies))
    plan.chainHops.push(...denies.chainHops)
    const repository = repositorySubmodules(denies)
    if (repository !== undefined) plan.repositories.push(repository)
  }

  // Deduplicated here rather than at emission: a checked-out submodule's
  // `.git` pointer names the same git directory the walk of `.git/modules`
  // reached, so the two produce the same deny paths, and a collapse of that
  // git directory has to leave no copy of them behind.
  return { ...plan, denyPaths: [...new Set(denyPaths)] }
}

/**
 * Run `produce`, turning the refusal a git metadata file can raise into the
 * wrap's own typed one. A `.git` pointer or a `commondir` whose target cannot
 * be worked out the way git works it out refuses the command, and a
 * sandboxed command can write one, so the refusal has to reach the caller as
 * something it can branch on — and name the file, since lifting it takes a
 * command run outside the sandbox.
 */
function asProfileRefusal<T>(produce: () => T): T {
  try {
    return produce()
  } catch (err) {
    if (err instanceof SubmoduleWalkBudgetError) {
      // The same answer a ripgrep scan that runs out of its time gets, for
      // the same reason: a listing that stops somewhere unknown is not
      // something to sandbox on. The walk shares that budget.
      logForDebugging(`[Sandbox Linux] ${err.message}`, { level: 'warn' })
      throw new LinuxSandboxProfileError('deny_scan_failed', err.message, err)
    }
    if (!(err instanceof GitMetadataError)) throw err
    logForDebugging(`[Sandbox Linux] ${err.message}`, { level: 'warn' })
    throw new LinuxSandboxProfileError(
      'deny_git_metadata_unreadable',
      err.message,
      err,
    )
  }
}

// Mount points on the host for deny paths that are not there, against the
// bytes each holds. When bwrap does --ro-bind /dev/null /nonexistent/path it
// creates an empty file on the host as a mount point, and it persists after
// bwrap exits; the git redirect denies write their own instead, holding the
// placeholder (see gitRedirectMountPoint). undefined is bwrap's, empty one.
// The cleanup takes a file away only while it still holds what is recorded
// here, so one something else has written to is left where it is.
const bwrapMountPoints = new Map<string, string | undefined>()

/** Temp-directory prefix of the store below, so it is nobody else's. */
const GIT_REDIRECT_STORE_PREFIX = 'srt-gitredirect-'

// The placeholders the git redirect denies bind over their mount points: one
// file per distinct content for the life of the process, rewritten on each
// use, and pinned read-only inside every sandbox that mounts one. It is the
// masked-file store's own class for the reason that store exists — a bind
// exposes the source file itself, so a command that can reach the source
// under a name it can write chooses what git reads at the denied path.
// Emptied by cleanupBwrapMountPoints({ force: true }), which reset() and the
// process-exit handler call.
const gitRedirectStore = new MaskedFileStore(GIT_REDIRECT_STORE_PREFIX)

// The source of the empty-directory mount points: at most one at a time, made
// on first use, reused while a sandbox is running, and removed with the mount
// points — never before, because a live bind's source must stay.
// generateFilesystemArgs pins it read-only inside every sandbox that uses it.
let emptyMountSourceDir: string | undefined

function ensureEmptyMountSourceDir(): string {
  if (emptyMountSourceDir !== undefined) {
    // Revalidated, not trusted: the path is under the system temp dir, which
    // sandboxed commands commonly can write, and bwrap resolves a bind source
    // on the HOST, so a directory swapped for a symlink between two wraps
    // would publish whatever it points at. Anything that is not our own
    // private empty directory is left where it is: it is not ours to delete.
    try {
      const stat = fs.lstatSync(emptyMountSourceDir)
      if (
        stat.isDirectory() &&
        stat.uid === process.getuid?.() &&
        (stat.mode & 0o077) === 0 &&
        fs.readdirSync(emptyMountSourceDir).length === 0
      ) {
        return emptyMountSourceDir
      }
    } catch {
      // Gone, or no longer inspectable: make a new one below.
    }
    logForDebugging(
      `[Sandbox Linux] Not reusing the empty-directory mount source, it is gone or no longer our own empty directory: ${emptyMountSourceDir}`,
    )
  }
  emptyMountSourceDir = fs.mkdtempSync(path.join(tmpdir(), 'claude-empty-'))
  // mkdtemp asks for 0700 but the umask applies, so under `umask 0200` the
  // directory lands on 0500. Set the mode here rather than let the check
  // above reject the directory this call has just made.
  fs.chmodSync(emptyMountSourceDir, 0o700)
  return emptyMountSourceDir
}

/**
 * Is `p` a mount point an earlier sandbox left behind? bwrap makes the mount
 * point for `--ro-bind /dev/null <absent path>` with ensure_file(dest, 0444):
 * an empty regular file with no write bits. The set above lives in memory, so
 * a process that dies without an 'exit' event (SIGKILL, OOM) leaves the file
 * on the host with nothing left that knows what it is. Files that only look
 * similar are written by their creators with write bits (a lockfile, an empty
 * file materialised on purpose: 0666 & ~umask) or have content or a second
 * link. An empty read-only DIRECTORY left the same way is not recognisable:
 * it looks like anyone's empty directory.
 */
function isStaleBwrapMountPoint(p: string): boolean {
  try {
    const stat = fs.lstatSync(p)
    return (
      stat.isFile() &&
      stat.size === 0 &&
      (stat.mode & 0o222) === 0 &&
      stat.nlink === 1
    )
  } catch {
    return false
  }
}

export const CAP_SETFCAP = 31

// This process's bounding set unioned with its inheritable set, read once —
// see processHasBoundingCapability for why those two. Only prctl(CAPBSET_DROP)
// and capset move them and this library calls neither, and without the memo
// the read is a synchronous open of /proc/self/status on the path of every
// wrapped command. Only a successful read is stored, so a transient failure
// does not latch "no capabilities" for the life of the process.
let boundingCapabilities: bigint | undefined
let capabilityReadFailureLogged = false

/**
 * Whether this process holds `cap` in its bounding or inheritable set (Linux).
 *
 * bwrap is reached by execve, and for a euid-0 caller the kernel recomputes
 * the new permitted set from the bounding and inheritable sets, discarding
 * what the caller itself had permitted. Those two sets are therefore what
 * decides which capabilities bwrap holds when it writes its uid map; CapPrm
 * and CapEff do not, and for any process itself reached by exec as root they
 * merely repeat the union.
 */
export function processHasBoundingCapability(cap: number): boolean {
  let bits = boundingCapabilities
  if (bits === undefined) {
    let failure = 'has no CapBnd or CapInh line'
    try {
      bits = boundingCapabilitiesFromStatus(
        fs.readFileSync('/proc/self/status', 'utf8'),
      )
      boundingCapabilities = bits
    } catch (e) {
      failure = `could not be read (${String(e)})`
    }
    if (bits === undefined) {
      if (!capabilityReadFailureLogged) {
        capabilityReadFailureLogged = true
        logForDebugging(
          `[Sandbox Linux] /proc/self/status ${failure} - assuming this process holds no capabilities`,
          { level: 'warn' },
        )
      }
      return false
    }
  }
  return ((bits >> BigInt(cap)) & 1n) === 1n
}

/**
 * The capability set an execve gives a euid-0 caller's child, parsed out of a
 * `/proc/<pid>/status`: CapBnd unioned with CapInh. `undefined` when either
 * line is absent. CapPrm and CapEff are deliberately not consulted — see
 * processHasBoundingCapability.
 */
export function boundingCapabilitiesFromStatus(
  status: string,
): bigint | undefined {
  const bounding = status.match(/^CapBnd:\s*([0-9a-fA-F]+)\s*$/m)
  const inheritable = status.match(/^CapInh:\s*([0-9a-fA-F]+)\s*$/m)
  return bounding && inheritable
    ? BigInt('0x' + bounding[1]) | BigInt('0x' + inheritable[1])
    : undefined
}

/**
 * The bwrap capability list. Always `--cap-drop ALL`, which for a non-root
 * caller is bwrap's default anyway. `--cap-add CAP_SETFCAP` for the whole
 * bwrap invocation — the outer shell and the two socat relays hold it too —
 * when the caller is uid 0, the seccomp helper is in use and the capability
 * survives into bwrap: the helper's nested user namespace maps uid 0, which
 * Linux 5.12 and the distribution kernels that backported it allow only from
 * a creator holding CAP_SETFCAP. Under the helper a uid-0 caller's command
 * therefore has a full set inside that nested namespace, which is
 * identity-mapped to the caller's uid 0, and the filesystem policy there
 * rests on the nested namespace's mount copies being locked. Without the
 * helper (`allowAllUnixSockets`, or no usable helper binary) the command runs
 * in bwrap's own namespaces and `--cap-drop ALL` is what stops it unmounting
 * a deny.
 *
 * Pure: `hasSetfcap` is decided by the caller, which is also where the
 * missing-capability case is reported once per process.
 */
export function capabilityArgs({
  euid,
  hasSetfcap,
  usesSeccompHelper,
}: {
  euid: number | undefined
  hasSetfcap: boolean
  usesSeccompHelper: boolean
}): string[] {
  const args = ['--cap-drop', 'ALL']
  if (euid !== 0) return args
  if (!hasSetfcap) return args
  if (usesSeccompHelper) args.push('--cap-add', 'CAP_SETFCAP')
  return args
}

// Latch for the predicted case: once per process, not once per command.
let setfcapMissingLogged = false

// A uid-0 caller whose bounding set lacks CAP_SETFCAP cannot sandbox
// anything: bwrap's own --unshare-user writes a uid map containing uid 0, and
// so does the seccomp helper's nested namespace, and a kernel that enforces
// the requirement refuses both unless the namespace's creator held the
// capability. allowAllUnixSockets does not avoid it — it only drops the
// helper, not bwrap's own user namespace. Worded for both the predicted case
// (the debug warning on the path of a wrapped command) and the confirmed one
// (checkLinuxDependencies, after bubblewrap has actually refused).
export const CAP_SETFCAP_MISSING_MESSAGE =
  "running as uid 0 without CAP_SETFCAP in this process's capability bounding set - on " +
  'kernels that enforce the CAP_SETFCAP requirement for mapping uid 0 into a user namespace ' +
  '(Linux 5.12 and distribution backports) every sandboxed command fails while writing a uid ' +
  'map ("Operation not permitted"). Grant CAP_SETFCAP to this process, or run as a non-root user'

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

/** Words bubblewrap takes for one mount: the option and its two paths. */
const BWRAP_WORDS_PER_MOUNT = 3

/**
 * Words the wrap adds AFTER the mounts, which the mounts must leave room for.
 * Fifteen today — `--dev /dev`, `--unshare-pid`, `--unshare-user` and at most
 * four capability words, `--bind /proc /proc`, `--` with the shell and `-c`,
 * and the one word the command itself is — plus the two `--args <fd>` takes
 * when the mounts move off the command line, and a little over. Everything
 * BEFORE the mounts is counted as it is, not estimated: the wrap has already
 * built it when it asks for them.
 */
const BWRAP_TRAILING_WORDS = 24

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

/** Why a bubblewrap profile could not be run. */
export type LinuxSandboxProfileErrorCode =
  /**
   * More arguments than bubblewrap parses, on the line or through a file.
   * The submodule denies of a repository are degraded until the profile fits
   * (see src/sandbox/linux-deny-collapse.ts), so what reaches this is a
   * profile that does not fit with every one of them collapsed: the allow
   * binds, the read denies and what they restore, the `denyWrite` entries
   * the caller passed and the ancestor pins under them.
   */
  | 'too_many_arguments'
  /** A mount path holds a NUL byte, which no carrier of arguments can hold. */
  | 'nul_in_path'
  /**
   * No unnamed file could be opened to carry the mounts: passing (this
   * process is out of descriptors) or lasting (no directory on this host
   * takes one). The error on `.cause` names each directory tried and what it
   * said.
   */
  | 'args_file_unavailable'
  /** The line does not fit one shell argument even with the mounts in a file. */
  | 'command_too_long'
  /**
   * A deny path git reads back — a git directory's `commondir` or
   * `config.worktree` — could not be given a stand-in git accepts: neither
   * the mount point on the host nor the placeholder in the temporary
   * directory could be written. Mounting /dev/null there instead would stop
   * git working in that repository altogether, so the command is refused.
   * Whatever the wrap did make is tracked and goes with the next cleanup.
   */
  | 'deny_placeholder_unavailable'
  /**
   * The ripgrep scan the mandatory denies below the working directory come
   * from did not deliver them: it could not be run, it was killed before it
   * finished, or it failed for a reason that names no path under the working
   * directory to deny in its place. Sandboxing on what it did list would
   * leave whatever it never reached — a nested repository's hooks — writable,
   * so the command is refused instead. The `.git/modules` walk spends the
   * same budget and running out of it is the same answer.
   */
  | 'deny_scan_failed'
  /**
   * A `.git` pointer file or a `commondir` under the working directory names
   * a git directory that cannot be worked out the way git works it out: its
   * bytes are not valid UTF-8, it is larger than git reads, or it is there
   * and could not be read. The hooks and config git runs through it are
   * therefore unknown, so the command is refused rather than sandboxed
   * without them. A sandboxed command can write such a file, and the
   * message names it: the refusal is lifted only from outside the sandbox.
   */
  | 'deny_git_metadata_unreadable'

/**
 * Thrown when a Linux bubblewrap profile cannot be run on this host: what the
 * configuration expands to is past a limit, or, for `command_too_long` and
 * `nul_in_path`, what the caller passed in is. The command was not run and no
 * profile file stays open, so do not run the per-command cleanup
 * (`cleanupAfterCommand()`, `cleanupBwrapMountPoints()`) for a wrap that
 * threw: it would release a second time, and a sandbox still running would
 * lose its mount points. Branch on `.code`, never on `.message`, which
 * carries the sizes of the moment. Other wrap-time failures (a shell that is
 * not on PATH, a bridge socket that is gone) are plain Errors.
 */
export class LinuxSandboxProfileError extends Error {
  readonly code: LinuxSandboxProfileErrorCode
  declare readonly cause?: unknown
  constructor(
    code: LinuxSandboxProfileErrorCode,
    message: string,
    cause?: unknown,
  ) {
    super(message)
    this.name = 'LinuxSandboxProfileError'
    this.code = code
    if (cause !== undefined) {
      // Non-enumerable, as a native `cause` is. Once the compile target is
      // ES2022 this is `super(message, { cause })`.
      Object.defineProperty(this, 'cause', {
        value: cause,
        writable: true,
        configurable: true,
        enumerable: false,
      })
    }
  }
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
 * Throws {@link LinuxSandboxProfileError} when the profile cannot run.
 */
function renderBwrapInvocation(
  bwrapBinary: string,
  bwrapArgs: string[],
  mounts: { start: number; end: number },
): string {
  if (bwrapArgs.length > BWRAP_MAX_ARGS) {
    throw new LinuxSandboxProfileError(
      'too_many_arguments',
      `Sandbox profile has ${bwrapArgs.length} bwrap arguments and bwrap accepts at most ${BWRAP_MAX_ARGS} (about ${BWRAP_MAX_ARGS / 3} mounts); reduce what the configuration expands to: each path takes about three arguments, each environment variable two`,
    )
  }
  const mountWords = bwrapArgs.slice(mounts.start, mounts.end)
  // A command line ends at a NUL and bwrap splits an args file on one, so the
  // word is cut short on the line and becomes several options in the file.
  if (mountWords.some(word => word.includes('\0'))) {
    throw new LinuxSandboxProfileError(
      'nul_in_path',
      'Sandbox profile contains a path with a NUL byte, which neither a command line nor a file of bwrap arguments can carry',
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
    throw new LinuxSandboxProfileError(
      'too_many_arguments',
      `${tooLong} and, passed through a file, would exceed the ${BWRAP_MAX_ARGS} arguments bwrap accepts`,
    )
  }
  let argsFd: number
  try {
    argsFd = openBwrapArgsProfile(mountWords)
  } catch (error) {
    throw new LinuxSandboxProfileError(
      'args_file_unavailable',
      `${tooLong} and cannot be passed through a file: ${errorText(error)}`,
      error,
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
    throw new LinuxSandboxProfileError(
      'command_too_long',
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
 * handler and reset() where deferral is not meaningful. That is also what
 * empties the store of git redirect placeholders, which is per process.
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

  for (const [mountPoint, written] of bwrapMountPoints) {
    try {
      // Still empty, or still holding exactly what this wrote there: a
      // mount point something else has taken over is not this one's to
      // remove.
      const stat = fs.statSync(mountPoint)
      const stillAsCreated =
        stat.size === 0 ||
        (written !== undefined &&
          stat.size === Buffer.byteLength(written) &&
          fs.readFileSync(mountPoint, 'utf8') === written)
      if (stat.isFile() && stillAsCreated) {
        fs.unlinkSync(mountPoint)
        logForDebugging(
          `[Sandbox Linux] Cleaned up bwrap mount point (file): ${mountPoint}`,
        )
      } else if (stat.isDirectory()) {
        // Empty directory mount points are created for a missing
        // intermediate component. Only remove if still empty.
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
  if (opts?.force) {
    // The placeholders outlive a batch of wraps the way the masked-file
    // store's fakes do: what ends them is the session (or the process), not
    // a command. A live bind's source has to stay until then.
    gitRedirectStore.dispose()
  }
  if (emptyMountSourceDir !== undefined) {
    try {
      // rmdirSync, not a recursive remove: it neither follows a symlink nor
      // descends, so a path that is no longer our empty directory is left
      // exactly as found.
      fs.rmdirSync(emptyMountSourceDir)
      logForDebugging(
        `[Sandbox Linux] Cleaned up the empty-directory mount source: ${emptyMountSourceDir}`,
      )
      emptyMountSourceDir = undefined
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code
      if (code === 'ENOTEMPTY') {
        logForDebugging(
          `[Sandbox Linux] Left the empty-directory mount source behind, something has written into it: ${emptyMountSourceDir}`,
        )
      }
      // Forget the path only when there is nothing left to remove. ENOTEMPTY,
      // EACCES and EBUSY (a forced cleanup while a live sandbox still pins the
      // source) leave it ours to try again; the revalidation on next use
      // decides whether it can be reused.
      if (code === 'ENOENT' || code === 'ENOTDIR') {
        emptyMountSourceDir = undefined
      }
    }
  }

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
  let usableBwrap: string | null = null
  if (bwrapPath) {
    if (isExecutable(bwrapPath)) usableBwrap = bwrapPath
    else errors.push(`bubblewrap (bwrap) not executable at ${bwrapPath}`)
  } else {
    usableBwrap = whichSync('bwrap')
    if (usableBwrap === null) errors.push('bubblewrap (bwrap) not installed')
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

  const uid0Error = uid0SandboxError({
    euid: process.geteuid?.(),
    hasSetfcap: processHasBoundingCapability(CAP_SETFCAP),
    bwrap: usableBwrap,
  })
  if (uid0Error !== null) errors.push(uid0Error)

  return { warnings, errors }
}

/**
 * Predict, then confirm. The prediction — uid 0 with no CAP_SETFCAP to hand
 * to bwrap — is exact about the capability but not about the kernel, so ask
 * bubblewrap itself before failing the caller's initialize(). An error, not a
 * warning: if it holds, every sandboxed command fails.
 *
 * `bwrap === null` skips the probe: a missing or unusable bubblewrap is
 * already its own dependency error, and a second one about capabilities would
 * only misdirect.
 */
export function uid0SandboxError({
  euid,
  hasSetfcap,
  bwrap,
}: {
  euid: number | undefined
  hasSetfcap: boolean
  bwrap: string | null
}): string | null {
  if (euid !== 0 || hasSetfcap || bwrap === null) return null
  const refusal = probeUid0UserNamespace(bwrap)
  if (refusal === null) return null
  return refusal === ''
    ? CAP_SETFCAP_MISSING_MESSAGE
    : `${CAP_SETFCAP_MISSING_MESSAGE} (bubblewrap: ${refusal})`
}

// One probe result per bwrap binary: whether a uid-0 map is refused is a
// property of the kernel and the binary, not of the moment. Keyed by path so
// a caller that passes an explicit bwrapPath is not answered for another one.
const uid0UserNamespaceProbes = new Map<string, string | null>()

/**
 * Run `bwrap --unshare-user --dev-bind / / true` once and report whether this
 * kernel actually refuses to map uid 0. `null` means it does not, so there is
 * nothing to report; otherwise bubblewrap's own first stderr line, or the
 * empty string when the probe could not be run at all and the prediction
 * stands unaided.
 */
function probeUid0UserNamespace(bwrap: string): string | null {
  const cached = uid0UserNamespaceProbes.get(bwrap)
  if (cached !== undefined) return cached

  const probe = spawnSync(
    bwrap,
    ['--unshare-user', '--dev-bind', '/', '/', 'true'],
    {
      timeout: 5000,
      stdio: ['ignore', 'ignore', 'pipe'],
      encoding: 'utf8',
    },
  )
  const refusal =
    probe.error === undefined && probe.status === 0
      ? null
      : ((probe.stderr ?? '')
          .split('\n')
          .map(line => line.trim())
          .find(line => line.length > 0)
          ?.slice(0, 200) ?? '')
  uid0UserNamespaceProbes.set(bwrap, refusal)
  return refusal
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

    if (fs.existsSync(httpSocketPath) && fs.existsSync(socksSockPath)) {
      logForDebugging(`Linux bridges ready after ${i + 1} attempts`)
      break
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
 * once because each leads somewhere different: ABSENCE, where the name
 * resolves to no file and every consumer already treats the path as absent
 * (isAbsenceErrno, in sandbox-utils.ts, where the glob walk classifies the
 * same failures); TRANSIENT, a busy, unlucky or re-exporting host rather
 * than a fact about the path, worth asking once more before the failure is
 * taken for an answer; and SETTLED, a file that is there and cannot be
 * looked at, and will not become readable while this wrap runs. Every code
 * neither predicate names is settled, because nothing says it clears.
 */
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
    /** Where the tmpfs lands, and the destination bwrap is handed for it:
     *  a read deny is mounted where its path resolves (readDenyMountOf's
     *  landing in the caller), never on a symlink. */
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
  const { landing, allowedWritePaths, readAllowPaths } = unit
  args.push('--tmpfs', landing)

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
        `[Sandbox Linux] Not restoring ${p} over denyRead tmpfs ${landing}: nothing there resolves (absent, dangling or unreadable), so the only source available is the name itself`,
        { level: 'warn' },
      )
      return undefined
    }
    if (!isAtOrUnder(source, landing)) {
      logForDebugging(
        `[Sandbox Linux] Not restoring ${p} over denyRead tmpfs ${landing}: it resolves outside it, to ${source}`,
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
          `[Sandbox Linux] Not restoring ${p} over denyRead tmpfs ${landing}: it resolves to ${source}, and the read section denies or masks ${denied}`,
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
 * Generate filesystem bind mount arguments for bwrap, inside `wordsAvailable`
 * of bubblewrap's cap on parsed words.
 *
 * The mandatory-deny scan runs once. What it found is then built into mounts,
 * counted, and — while the count is past what the caller has room for —
 * degraded a step at a time and built again, each pass measuring the profile
 * the previous one produced rather than predicting it: the ancestor pins a
 * deny needs are known only once the deny list is complete, so the mounts a
 * repository's submodules really cost cannot be worked out before this point
 * (see src/sandbox/linux-deny-collapse.ts for what a step gives up, and
 * `LinuxSandboxProfileErrorCode`'s `too_many_arguments` for what is left when
 * there is nothing to degrade).
 *
 * A pass that is built and then degraded may already have written mount
 * points on the host for the denies it dropped; they are recorded like any
 * others and go with the same cleanup.
 */
async function generateFilesystemArgs(
  readConfig: FsReadRestrictionConfig | undefined,
  writeConfig: FsWriteRestrictionConfig | undefined,
  maskedFileBinds: Array<{ realPath: string; fakePath: string }> | undefined,
  maskedFileStoreDir: string | undefined,
  ripgrepConfig: RipgrepConfig = { command: 'rg' },
  mandatoryDenySearchDepth: number = DEFAULT_MANDATORY_DENY_SEARCH_DEPTH,
  allowGitConfig = false,
  abortSignal?: AbortSignal,
  wordsAvailable: number = Number.POSITIVE_INFINITY,
): Promise<string[]> {
  const mandatoryDenyScan: MandatoryDenyScanLatch = { done: false }
  const plan =
    writeConfig === undefined
      ? undefined
      : withChainHopDenies(
          await linuxGetMandatoryDenyPaths(
            ripgrepConfig,
            mandatoryDenySearchDepth,
            allowGitConfig,
            abortSignal,
          ),
          (writeConfig.allowOnly ?? []).map(p => normalizePathForSandbox(p)),
        )
  // The scan has run, or there is no write config to run one for: either way
  // nothing below is waiting on it, and the passes may resolve paths.
  mandatoryDenyScan.done = true
  let level =
    plan === undefined
      ? NO_COLLAPSE
      : collapseFloor(plan, writeConfig?.allowOnly ?? [], wordsAvailable)
  for (;;) {
    const args = buildFilesystemArgs(
      readConfig,
      writeConfig,
      maskedFileBinds,
      maskedFileStoreDir,
      plan === undefined ? [] : collapsedDenyPaths(plan, level),
      mandatoryDenyScan,
    )
    if (plan === undefined) return args
    const degraded =
      args.length <= wordsAvailable
        ? undefined
        : collapseFurther(
            plan,
            level,
            Math.ceil((args.length - wordsAvailable) / BWRAP_WORDS_PER_MOUNT),
          )
    if (degraded !== undefined) {
      level = degraded
      continue
    }
    // Settled: either it fits, or there is nothing left to degrade and
    // renderBwrapInvocation refuses it with too_many_arguments. One warning
    // per wrap, naming what the profile it returns gave up.
    const told = describeCollapse(plan, level)
    if (told !== '') {
      logForDebugging(
        `[Sandbox Linux] The profile for this command did not fit what bubblewrap parses, so ${told}`,
        { level: 'warn' },
      )
    }
    return args
  }
}

/**
 * Where the passes above start: the level counting alone says the profile
 * cannot do without, since every deny path inside the write allowlist takes
 * a mount of its own and the ancestor pins beneath each are more on top.
 * Without it a repository with ten thousand submodules is built out in full
 * before anything is degraded, and a wrapped command can make such a tree:
 * what one costs every command after it is not free to leave at whatever it
 * comes to.
 *
 * It is not the answer, and the measurement above is: what it leaves out can
 * only mean more collapsing, and the one way it can ask for too much — a
 * deny path counted here that another deny turns out to cover — is a mount
 * the profile saves rather than one it needs.
 */
function collapseFloor(
  plan: SubmoduleDenyPlan,
  allowOnly: string[],
  wordsAvailable: number,
): CollapseLevel {
  const allowedWritePaths = allowOnly.map(p => normalizePathForSandbox(p))
  const mounts = Math.floor(wordsAvailable / BWRAP_WORDS_PER_MOUNT)
  let level = NO_COLLAPSE
  for (;;) {
    const denies = collapsedDenyPaths(plan, level).filter(denyPath =>
      allowedWritePaths.some(allowedPath => isAtOrUnder(denyPath, allowedPath)),
    ).length
    if (denies <= mounts) return level
    const degraded = collapseFurther(plan, level, denies - mounts)
    if (degraded === undefined) return level
    level = degraded
  }
}

/**
 * Set by {@link generateFilesystemArgs} once the mandatory-deny scan is behind
 * it, and read by every pass it then builds: no path may be resolved
 * (realpath) before that scan, which can run arbitrarily long and would leave
 * a resolution taken ahead of it blind to a symlink retargeted meanwhile. A
 * pass asked for before the latch is set refuses rather than resolving, so the
 * ordering cannot be lost to a later edit that measures a profile early.
 */
type MandatoryDenyScanLatch = { done: boolean }

/**
 * The mounts for one deny list: `mandatoryDenyPaths` are the mandatory denies
 * as {@link generateFilesystemArgs} has settled them, and the caller's own
 * `denyWithinAllow` entries are added to them here.
 */
function buildFilesystemArgs(
  readConfig: FsReadRestrictionConfig | undefined,
  writeConfig: FsWriteRestrictionConfig | undefined,
  maskedFileBinds: Array<{ realPath: string; fakePath: string }> | undefined,
  maskedFileStoreDir: string | undefined,
  mandatoryDenyPaths: string[],
  mandatoryDenyScan: MandatoryDenyScanLatch,
): string[] {
  const args: string[] = []

  // Collect normalized allowed write paths. Populated in the writeConfig
  // block, read again in the denyRead loop to re-bind writes under tmpfs.
  const allowedWritePaths: string[] = []
  /** One buffered denyWrite bind. */
  type DenyWriteBind = {
    /** What the bind reads from. A /dev/null placeholder at an absent path
     *  is upgraded in place to the empty directory when a deeper deny needs
     *  the destination to be traversable. */
    source: string
    /** Where the bind lands: the deny path resolved. */
    dest: string
    /** The pre-resolution deny path `dest` came from. A bind at the resolved
     *  dest also re-exposes whatever the symlinked spelling leads to, so the
     *  re-application passes below compare a read deny's landing against
     *  both spellings. Landings and allowed write paths are canonical, so
     *  the extra spelling can only match more of them, never fewer. */
    rawDest: string
    /** Set where `dest` is a file git reads back: the placeholder it needs,
     *  acted on at emission (gitRedirectMountPoint). */
    gitRedirect?: string
  }
  // denyWrite binds are buffered and emitted after denyRead processing so that
  // a denyRead tmpfs over an ancestor directory doesn't wipe them out. They
  // are kept as entries rather than words so that the emission below is the
  // one place that knows a deny bind is spelled --ro-bind <source> <dest>,
  // and so nothing has to index into a flat array to change one.
  const denyWriteBinds: DenyWriteBind[] = []
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
  // The shared empty directory this call's placeholders bind from, resolved at
  // most once per wrap: resolving again mid-wrap (the cached path having been
  // tampered with in between) would leave the binds already emitted pointing
  // at a directory this same call has just judged not ours.
  let emptySource: string | undefined
  // The store file each placeholder content was written to, for this wrap:
  // the store unlinks and rewrites on every call, which is what revalidates
  // it, and one wrap needs that once however many destinations share it.
  const gitRedirectStoreFiles = new Map<string, string>()
  // Git directories this wrap denies whole because no mount point could be
  // made inside them, so the second redirect file in one does not emit a
  // second bind of the same directory.
  const denyWholeGitDirs = new Set<string>()
  // The store directory a placeholder came from, pinned read-only with the
  // other mount sources at the end. Set only where one was actually used.
  let gitRedirectSourceDir: string | undefined
  // Where a mount given `p` lands: `p` fully resolved, every symlink on the
  // way and not one hop. One resolution per path per pass, so every predicate
  // below sees the same answer.
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
    if (!mandatoryDenyScan.done) {
      throw new Error(
        `[Sandbox Linux] ${p} was resolved before the mandatory-deny scan finished: what a realpath taken now says can be stale by the time the mounts are built`,
      )
    }
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
  // This is the widest blast radius a transient failure has, hence the retry:
  // one unlucky EIO turns a file deny into a stand-in over its whole
  // directory, and every carve-out beneath that is then refused.
  const readDenyTargetOf = (
    entry: string,
  ): { path: string; isDirectory: boolean; isStandIn: boolean } | undefined => {
    for (let candidate = entry; ; candidate = path.dirname(candidate)) {
      if (candidate === '/' && candidate !== entry) return undefined
      try {
        const stats = retryingTransient(() => fs.statSync(candidate))
        return {
          path: candidate,
          isDirectory: stats.isDirectory(),
          isStandIn: candidate !== entry,
        }
      } catch (err) {
        if (isAbsenceErrno(err) || candidate === '/') return undefined
      }
    }
  }
  // Where that mount lands, which is where the entry really is: one mount
  // then covers every spelling of that place; the real contents are hidden
  // wherever they are reachable, even when the route that named them is
  // itself inside an earlier tmpfs; and no mount is ever asked to land on a
  // symlink, which bubblewrap refuses outright from 0.12 on ("Can't mount on
  // symlink destination").
  //
  // '/' is never a landing. Only a symlink to the root resolves there (a '/'
  // entry itself is expanded into the root's children), and a --tmpfs /
  // would wipe every mount placed before it while the pivot promoted it,
  // booting the command on an empty tree. The directory holding the link
  // stands in for it, on the same rule as an entry that cannot be inspected,
  // and `undefined` means nothing at all is mounted for this entry.
  const readDenyMountOf = (
    entry: string,
  ):
    | {
        /** Where the mount goes. */
        landing: string
        /** As the entry resolved, before the landing rules below. */
        named: string
        isDirectory: boolean
        /** The landing is not where the entry names: nothing beneath it can
         *  be vouched for, so nothing is bound back over it. */
        isStandIn: boolean
      }
    | undefined => {
    const target = readDenyTargetOf(entry)
    if (target === undefined) return undefined
    const landing = canonicalForm(target.path)
    if (landing !== '/') {
      return {
        landing,
        named: target.path,
        isDirectory: target.isDirectory,
        isStandIn: target.isStandIn,
      }
    }
    const holder = canonicalForm(path.dirname(target.path))
    if (holder === '/') return undefined
    return {
      landing: holder,
      named: target.path,
      isDirectory: true,
      isStandIn: true,
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
  // Shallow-first by canonical depth, so a tmpfs over a directory lands
  // before the tmpfs or /dev/null mask on anything inside it however either
  // was spelled. That order is what lets a unit restore its write and
  // allowRead paths unconditionally: nothing emitted so far can lie inside
  // one. Sorted by spelling, a symlink-spelled entry could mount first inside
  // a directory listed after it, whose restores would then bury it.
  const canonicalDepth = (p: string): number =>
    canonicalForm(p).split('/').length
  type ReadDenyPlanEntry = {
    normalizedPath: string
    mount: ReturnType<typeof readDenyMountOf>
    liftedFile: boolean
  }
  // What every denyRead entry mounts and where: ONE walk, whose answers the
  // deny loop, the locations the carve-out gate below reads, and the
  // stub-skip prediction all take, so none of them can disagree about where
  // a deny lands. `mount` is undefined where nothing is mounted at all;
  // `liftedFile` marks a file deny an allowRead entry naming that very file
  // cancels — the entry mounts nothing in that case either. Lazy and
  // memoised like readDenyEntries().
  let readDenyPlanMemo: ReadDenyPlanEntry[] | undefined
  const readDenyPlan = (): ReadDenyPlanEntry[] =>
    (readDenyPlanMemo ??= readDenyEntries()
      .map(p => normalizePathForSandbox(p))
      .sort((a, b) => canonicalDepth(a) - canonicalDepth(b))
      .map(normalizedPath => {
        const mount = readDenyMountOf(normalizedPath)
        return {
          normalizedPath,
          mount,
          liftedFile:
            mount !== undefined &&
            !mount.isDirectory &&
            readAllowPaths().some(
              allowPath => nameLocationOf(allowPath) === mount.landing,
            ),
        }
      }))
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
      // normalizePathForSandbox already strips a trailing slash from every
      // spelling it does not take for a glob; this strip covers the ones it
      // exempts — a literal directory named with glob characters, spelled
      // '<dir>/[id]/'. Allow paths are recorded slash-free because every
      // downstream comparison — the deny loop's within-allowlist gate,
      // findSymlinkInPath's mask scoping, the emission filter's re-expose
      // check, the denyRead re-bind and its allowRead skip, and the stub-skip
      // vetoes — matches by `allowedPath + '/'` prefix, which '<dir>//'
      // silently defeats. bwrap binds 'dir' and 'dir/' identically, so
      // normalizing the recorded spelling fixes every consumer at once
      // instead of per-predicate. ('/' itself is kept; the empty spelling an
      // empty $HOME expands '~' to is NOT the root, and falls out at the
      // existence check below.)
      const normalized = normalizePathForSandbox(pathPattern)
      const normalizedPath =
        normalized === '' ? '' : normalized.replace(/\/+$/, '') || '/'

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
    // skip the extra stat/realpath/readdir syscalls entirely. Running from
    // inside the deny loop also keeps the snapshot as close as possible to
    // the denyRead loop that later acts on the real filesystem.
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
           * Where the denyRead loop below would mount a tmpfs, read off the
           * same readDenyPlan() walk that loop takes its own answers from,
           * keeping only the entries that are directories (the loop skips
           * the ones that mount nothing and gives a file entry a read-only
           * /dev/null mask instead), in raw and canonical spellings. It
           * over-predicts: the loop also
           * skips an entry whose landing an earlier tmpfs already hides.
           * That direction is the safe one, since every veto below turns a
           * predicted tmpfs into a KEPT placeholder. A read-denied tmpfs at
           * or under a covering deny dir is the TRIGGER for the
           * post-denyWrite re-application, and a deny bind whose dest sits
           * under one can be dropped by the emission filter — both facts
           * feed the guard.
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
        const prospectiveReadDenyTmpfsDirsBothForms = readDenyPlan().flatMap(
          ({ mount }) => {
            if (!mount?.isDirectory) return []
            // The tmpfs hides its landing, and the spelling the entry
            // resolved to when that differs. '/' is never a landing, and
            // must not enter the prediction as a spelling either (a link
            // to the root resolves there, and its holder is the landing):
            // every covering directory lies under '/', so predicting a
            // tmpfs there would veto every skip on the whole host.
            return [
              ...new Set([...mountForms(mount.named), mount.landing]),
            ].filter(form => form !== '/')
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
      ...mandatoryDenyPaths,
    ]

    // Duplicate deny entries must be collapsed: a duplicate
    // --ro-bind /dev/null <dest> hits a char device on the second pass and
    // bwrap's ensure_file() falls through to creat() on a read-only mount.
    const seenDenyWrite = new Set<string>()
    // Placeholder destination -> its buffered bind, so a later deny reaching
    // the same destination can upgrade a /dev/null placeholder to the
    // directory form in place (see the emission below). Only placeholders
    // are recorded: a deny of an existing path binds that path itself.
    const placeholderBinds = new Map<string, DenyWriteBind>()
    /** What a deny entry is, to both passes over denyPaths below. */
    type DenyPathClass =
      /** Nothing to deny: --dev /dev has already replaced that tree. */
      | { kind: 'skip' }
      /** A symlink cycle, or a chain past the ELOOP bound. */
      | { kind: 'unresolved'; raw: string }
      /** A symlink appeared in the resolved path's existing prefix, at
       *  `at`, inside an allowed write path. */
      | { kind: 'masked-symlink'; raw: string; resolved: string; at: string }
      | { kind: 'absent'; raw: string; resolved: string }
      | { kind: 'directory'; raw: string; resolved: string }
      | { kind: 'file'; raw: string; resolved: string }
    /**
     * The one filter chain both passes below apply. They walk the same
     * denyPaths and must reach the same verdict about each entry in the same
     * order: the pre-pass is sound only if it records exactly the directories
     * the loop re-binds read-only, and a directory recorded but never
     * re-bound suppresses stubs the sandbox still needs.
     *
     * Run once per entry per pass — twice in all, once before any stub
     * decision and once to emit — so each pass judges the filesystem as it
     * stands when it acts on it.
     */
    const classifyDenyPath = (pathPattern: string): DenyPathClass => {
      const raw = normalizePathForSandbox(pathPattern)
      if (raw.startsWith('/dev/')) return { kind: 'skip' }
      // Resolve-before-mask: normalizePathForSandbox keeps the raw symlink
      // path whenever resolution crosses isSymlinkOutsideBoundary (the
      // common dotfiles case), so canonicalize here. Every mask/bind below
      // must be computed against the resolved path — bwrap dest-resolves
      // symlinks, so a mask on the raw path either aborts startup (dir
      // symlink) or lands on the target inode anyway (file symlink). Writes
      // through the original symlinked path resolve to the same denied
      // target inside the mount namespace.
      const resolved = resolveSymlinkedDenyPath(raw)
      if (resolved === null) return { kind: 'unresolved', raw }
      // A deny path can only now land in /dev (e.g. a symlink into it),
      // where --dev /dev has already replaced the tree and a bind would
      // either miss or fight the new devtmpfs.
      if (resolved.startsWith('/dev/')) return { kind: 'skip' }
      // Defense-in-depth: the resolved path should be symlink-free for its
      // existing prefix, but the tree may change between resolution and this
      // check. A hit fails closed — the loop masks the component and bwrap
      // refuses to start rather than sandboxing with an unprotected deny
      // path, and the pre-pass records no read-only re-bind for it.
      const at = findSymlinkInPath(resolved, allowedWritePaths)
      if (at) return { kind: 'masked-symlink', raw, resolved, at }
      try {
        return fs.statSync(resolved).isDirectory()
          ? { kind: 'directory', raw, resolved }
          : { kind: 'file', raw, resolved }
      } catch {
        // Absent, vanished, or behind a parent this process cannot search:
        // all three are "not there" to the loop's own existence check too.
        return { kind: 'absent', raw, resolved }
      }
    }
    // PRE-PASS (order-independent): record the directories the loop below
    // re-binds read-only, BEFORE any stub decision, so the read-only
    // conclusion does not depend on where an enclosing directory appears in
    // the caller's denyWrite ordering. It takes the classification above and
    // adds the same isWithinAnyAllowedWritePath gate as the --ro-bind
    // emission, and it records every raw spelling each directory is reached
    // through. A recorded directory is EVIDENCE for skipping a stub only if
    // it also passes the guard's vetoes below (no read-deny tmpfs contains
    // it in any spelling; no allowed write path is both beneath it and under
    // such a tmpfs), which exclude every way its subtree could be writable
    // in the sandbox. A directory recorded here is either re-bound read-only
    // by the loop or skipped because a recorded directory above it survived
    // the vetoes and is bound in its place, so every record still stands for
    // a bind that lands — unless a symlink appears in its path between the
    // two classifications, where the loop masks that component and emits no
    // bind for the directory; an emitted one missing from the record only
    // costs a spurious abort.
    for (const pathPattern of denyPaths) {
      const classified = classifyDenyPath(pathPattern)
      switch (classified.kind) {
        case 'skip':
        case 'unresolved':
        case 'masked-symlink':
        case 'absent':
        case 'file':
          continue
        case 'directory':
          if (isWithinAnyAllowedWritePath(classified.resolved)) {
            // Keep every spelling this dest is reached through (the
            // re-application passes record the first-seen raw spelling beside
            // the dest, which this pass cannot assume): the guard below treats
            // the directory as unsafe if a read-deny tmpfs contains ANY of them.
            let spellings = readOnlyDenyDirSpellings.get(classified.resolved)
            if (spellings === undefined) {
              spellings = new Set()
              readOnlyDenyDirSpellings.set(classified.resolved, spellings)
            }
            spellings.add(classified.raw)
          }
          continue
      }
    }
    // Per-covering-dir veto verdict, computed once per recorded directory
    // (the inputs never change during the deny loop) instead of per absent
    // deny entry.
    // INVARIANT: a stub, or an existing deny path's own bind, is skipped
    // only under a recorded covering deny directory that was judged against
    // a prediction that could be derived, that no read-deny tmpfs contains
    // (it, or any spelling it was reached through), and beneath which no
    // allowed write path sits that a read-deny tmpfs also covers. '/' is the
    // exception: it contains every allowed write path, so
    // coveredBySafeReadOnlyDenyDir judges a vetoed '/' against the candidate
    // instead — see the branch there.
    // The skip rests on the emission order: nothing host-backed and writable
    // lands after the buffered read-only binds, so a covering bind is the
    // last word on its subtree unless a tmpfs above it drops that bind at
    // emission. Where a veto could apply, keep the stub: the pre-existing
    // abort is preferable to a silently creatable deny path.
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
        // (i) an allowed write path both strictly beneath the dir and at or
        //     under a prospective read-deny tmpfs. Re-applying that tmpfs
        //     after the dir's read-only bind is the one pass that mounts
        //     anything inside such a path at all, and it restores read-only,
        //     so this names no live re-opening route today and no
        //     configuration is known that needs it. It is the only veto that
        //     speaks about a writable path under the dir: should a pass after
        //     the deny binds ever restore one writable again, the skip fails
        //     closed here.
        vetoInputs.allowedWritePathsBothForms.some(
          writePath =>
            isStrictlyUnder(writePath, denyDir) &&
            vetoInputs.prospectiveReadDenyTmpfsDirsBothForms.some(tmpfsDir =>
              isAtOrUnder(writePath, tmpfsDir),
            ),
        ) ||
        // (ii) a read-deny tmpfs CONTAINING the dir: its own --ro-bind is
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
            // abort — whenever anything vetoes '/', which an unusable
            // prediction or an allowed write path under a read-deny tmpfs
            // does. The branch is strictly stricter than covering on the
            // root's own bind, and it is what decides those two cases.
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
      const classified = classifyDenyPath(pathPattern)
      if (classified.kind === 'skip') continue
      if (classified.kind === 'unresolved') {
        // Fail closed. Dropping the deny here would sandbox the command with
        // the path unprotected, so instead mask the symlink component and let
        // bwrap refuse to start. When no component is a symlink inside an
        // allowed write path there is nothing to protect: the path is already
        // read-only from the initial --ro-bind / /.
        const unresolvableSymlink = findSymlinkInPath(
          classified.raw,
          allowedWritePaths,
        )
        if (unresolvableSymlink && !seenDenyWrite.has(unresolvableSymlink)) {
          seenDenyWrite.add(unresolvableSymlink)
          denyWriteBinds.push({
            source: '/dev/null',
            dest: unresolvableSymlink,
            rawDest: classified.raw,
          })
        }
        logForDebugging(
          `[Sandbox Linux] Deny path could not be resolved through symlinks, failing closed: ${classified.raw}`,
        )
        continue
      }
      const rawPath = classified.raw
      const normalizedPath = classified.resolved
      if (normalizedPath !== rawPath) {
        logForDebugging(
          `[Sandbox Linux] Resolved symlinked deny path: ${rawPath} -> ${normalizedPath}`,
        )
      }

      // Dedup post-resolution: distinct spellings (tilde vs absolute, via
      // symlink vs direct) converge to the same real path here.
      if (seenDenyWrite.has(normalizedPath)) continue
      seenDenyWrite.add(normalizedPath)

      if (classified.kind === 'masked-symlink') {
        const symlinkInPath = classified.at
        if (!seenDenyWrite.has(symlinkInPath)) {
          seenDenyWrite.add(symlinkInPath)
          denyWriteBinds.push({
            source: '/dev/null',
            dest: symlinkInPath,
            rawDest: rawPath,
          })
        }
        logForDebugging(
          `[Sandbox Linux] Mounted /dev/null at symlink ${symlinkInPath} to prevent symlink replacement attack`,
        )
        continue
      }

      // A mount point an earlier sandbox left on the host (see
      // isStaleBwrapMountPoint) is an absent deny path in all but name. Bound
      // onto itself as an existing file it would never be tracked, so never
      // removed, and on the host its existence can be the whole meaning (a
      // lockfile's). Cover it with /dev/null like the absent leaf below and
      // track it, so cleanupBwrapMountPoints() takes it away. Same gate as
      // that branch. Under a read-only denied directory nothing needs
      // covering (the file is already unwritable there), but it is still
      // tracked: it is no more the caller's file for being there. Not for a
      // file git reads back, which gitRedirectMountPoint settles instead.
      if (
        (isWithinAnyAllowedWritePath(path.dirname(normalizedPath)) ||
          isWithinAnyAllowedWritePath(normalizedPath)) &&
        gitRedirectPlaceholder(normalizedPath) === undefined &&
        isStaleBwrapMountPoint(normalizedPath)
      ) {
        if (!coveredBySafeReadOnlyDenyDir(normalizedPath)) {
          denyWriteBinds.push({
            source: '/dev/null',
            dest: normalizedPath,
            rawDest: rawPath,
          })
        }
        bwrapMountPoints.set(normalizedPath, undefined)
        registerExitCleanupHandler()
        logForDebugging(
          `[Sandbox Linux] Re-covering a mount point an earlier sandbox left behind: ${normalizedPath}`,
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
      switch (classified.kind) {
        case 'absent': {
          // A git worktree's .git is a file, so .git/hooks under it can never
          // be created: nothing to deny, and a bind under a file would abort
          // bwrap. Same for any other existing component that is a file.
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
            const firstNonExistent =
              findFirstNonExistentComponent(normalizedPath)

            // A missing INTERMEDIATE component gets an empty read-only
            // directory, not /dev/null: tools traversing it need a directory,
            // and a file there breaks them.
            const isIntermediate = firstNonExistent !== normalizedPath
            // Decided from the resolved path, which every spelling of one file
            // shares, rather than from the deny entry: a caller's own
            // denyWrite naming the same file must not miss it. /dev/null
            // stands in the buffer until gitRedirectMountPoint replaces it.
            const gitRedirectStub = isIntermediate
              ? undefined
              : gitRedirectPlaceholder(normalizedPath)
            const source = isIntermediate
              ? (emptySource ??= ensureEmptyMountSourceDir())
              : '/dev/null'

            // One mount point per destination. Deny paths are deduplicated on
            // the deny path, but a placeholder lands on the first MISSING
            // component, so two denies sharing one arrive here with a single
            // destination — denyWrite '<cwd>/.claude' together with the
            // mandatory '<cwd>/.claude/commands', in a project with no
            // `.claude/`. Two binds there make bwrap refuse to start when they
            // disagree about the destination's kind ("Can't mkdir <dest>: Not a
            // directory"). The directory form wins the disagreement: an empty
            // read-only directory blocks creating the destination and everything
            // below it exactly as /dev/null does, and stays traversable for the
            // deeper deny that asked for a directory.
            const placeholder = placeholderBinds.get(firstNonExistent)
            if (placeholder !== undefined) {
              if (isIntermediate) {
                placeholder.source = source
                // The destination has to be a directory for the deeper deny,
                // so it is no longer a file git reads back.
                placeholder.gitRedirect = undefined
              }
              logForDebugging(
                `[Sandbox Linux] Reusing the mount point at ${firstNonExistent} to block creation of ${normalizedPath}`,
              )
              continue
            }
            // First writer wins for a destination several denies share (the
            // reuse branch above returns before reaching this), and the raw
            // spelling recorded with it is purely additive: it only gives the
            // tmpfs and mask comparisons below a second spelling to test, and
            // `dest` itself is always tested.
            const placeholderBind: DenyWriteBind = {
              source,
              dest: firstNonExistent,
              rawDest: rawPath,
              gitRedirect: gitRedirectStub,
            }
            denyWriteBinds.push(placeholderBind)
            placeholderBinds.set(firstNonExistent, placeholderBind)
            bwrapMountPoints.set(firstNonExistent, undefined)
            registerExitCleanupHandler()
            logForDebugging(
              `[Sandbox Linux] Mounted ${
                isIntermediate
                  ? 'empty dir'
                  : gitRedirectStub === undefined
                    ? '/dev/null'
                    : 'a git redirect placeholder'
              } at ${firstNonExistent} to block creation of ${normalizedPath}`,
            )
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
        case 'directory':
        case 'file': {
          // Only add deny binding if this path is within an allowed write path
          // Otherwise it's already read-only from the initial --ro-bind / /
          const isWithinAllowedPath =
            isWithinAnyAllowedWritePath(normalizedPath)

          if (isWithinAllowedPath) {
            // Already unwritable under a read-only denied directory (the
            // existing-path twin of the stub skip above). Veto (ii) keeps the
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
            // A file git reads back is not necessarily bound from itself: an
            // empty one left by a killed wrap is a redirect git refuses. Which
            // it is is settled at emission (gitRedirectMountPoint).
            const gitRedirectStub = gitRedirectPlaceholder(normalizedPath)
            denyWriteBinds.push({
              source: normalizedPath,
              dest: normalizedPath,
              rawDest: rawPath,
              gitRedirect: gitRedirectStub,
            })
          } else {
            logForDebugging(
              `[Sandbox Linux] Skipping deny path not within allowed paths: ${normalizedPath}`,
            )
          }
        }
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
  // The buffered deny binds are emitted after the denyRead loop below.

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
    landing: string
    restoredWrites: RestoredMount[]
    restoredReads: RestoredMount[]
  }> = []
  const fileMasks: Array<{ source: string; landing: string }> = []

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
  // Entries a glob expansion produced for a directory it could not list.
  // What the pattern matches beneath an allowed path in there was never
  // found, so binding that path back over the tmpfs would show every one of
  // those matches unmasked.
  const unlistableDenyDirs = new Set(readConfig?.unlistableDenyDirs ?? [])

  // Every location the read section hides, each one where its mount lands:
  // one per entry that mounts something — a directory's tmpfs, the stand-in
  // tmpfs of an entry that could not be inspected or that resolves to '/', a
  // file's /dev/null mask — and one per masked credential file. An entry that
  // mounts nothing hides nothing, and must not cost a carve-out; a stand-in
  // hides where it lands, which is above the entry that asked for it. A
  // landing the loop below then skips as already hidden stays in this list:
  // it refuses a carve-out the mounts alone would have allowed, which is the
  // safe direction and one comparison fewer.
  const readDeniedLocations = [
    ...readDenyPlan().flatMap(({ mount, liftedFile }) =>
      mount === undefined || liftedFile ? [] : [mount.landing],
    ),
    ...(maskedFileBinds ?? []).map(mask => canonicalForm(mask.realPath)),
  ]
  // What the read section hides at, inside, or around `target`, ignoring the
  // tmpfs landing at `landing` and every deny above it — those are what a
  // carve-out restored into that tmpfs is the exception to. Everything else
  // that overlaps the target wins over the carve-out. Both sides are resolved
  // locations: every read deny mounts where its entry resolves, and `target`
  // is what the carve-out resolves to, so no spelling has to be guessed at.
  // Returns the offending location, for the debug line.
  const readDenialAround = (
    target: string,
    landing: string,
  ): string | undefined =>
    readDeniedLocations.find(
      denied =>
        !isAtOrUnder(landing, denied) &&
        (isAtOrUnder(denied, target) || isAtOrUnder(target, denied)),
    )

  for (const { normalizedPath, mount, liftedFile } of readDenyPlan()) {
    if (mount === undefined) {
      logForDebugging(
        `[Sandbox Linux] Read deny path mounts nothing this wrap can place (absent, or uninspectable, or a link to '/' with nothing but '/' holding it): ${normalizedPath}`,
      )
      continue
    }
    const { landing, isDirectory, isStandIn } = mount
    // One mount per location. A tmpfs emitted so far already hides this
    // place, and nothing bound back over it shows the host there again, so a
    // mount here would be created inside that tmpfs and change nothing. This
    // also collapses two spellings of one directory, and the entries a
    // collapsed read-deny glob leaves beneath a directory it already denies.
    if (isHiddenByTmpfs(landing, 'writes and reads')) {
      logForDebugging(
        `[Sandbox Linux] Skipping read deny already hidden by a denyRead tmpfs: ${landing}`,
      )
      continue
    }

    if (isDirectory) {
      // A stand-in for an entry this wrap cannot vouch for hides everything
      // beneath it: nothing under it can be vouched for either. So does a
      // directory a glob expansion could not enumerate.
      if (isStandIn) {
        logForDebugging(
          `[Sandbox Linux] Read deny path ${normalizedPath} cannot be mounted where it names; hiding ${landing} instead`,
          { level: 'warn' },
        )
      }
      const unlistable =
        unlistableDenyDirs.has(normalizedPath) ||
        unlistableDenyDirs.has(landing)
      if (unlistable) {
        logForDebugging(
          `[Sandbox Linux] Read-denied directory could not be listed when the glob was expanded; restoring nothing beneath it: ${landing}`,
          { level: 'warn' },
        )
      }
      const restoresNothing = isStandIn || unlistable
      const restored = pushReadDenyDirMounts(args, {
        landing,
        allowedWritePaths: restoresNothing ? [] : allowedWritePaths,
        readAllowPaths: restoresNothing ? [] : readAllowPaths(),
        resolve: canonicalLocationOf,
        readDenialAround: restoreTarget =>
          readDenialAround(restoreTarget, landing),
        nameLocation: nameLocationOf,
      })
      readDenyTmpfsUnits.push({ landing, ...restored })
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
      // For files, bind /dev/null instead of tmpfs, where the path resolves
      // like every other read-deny mount.
      args.push('--ro-bind', '/dev/null', landing)
      fileMasks.push({ source: '/dev/null', landing })
    }
  }

  // Whole-file credential masks: same bind shape as a file read-deny,
  // at the same place — where the path really resolves, which is what
  // covers a credential dotfile that is a symlink into a dotfile manager's
  // directory (~/.netrc, ~/.npmrc). realPath was already normalized
  // (tilde-expanded, realpath'd) by the caller. The fake's parent dir is
  // explicitly ro-bound at the end of this function, so the bind source is
  // never writable from inside the sandbox.
  for (const { realPath, fakePath } of maskedFileBinds ?? []) {
    const landing = canonicalForm(realPath)
    args.push('--ro-bind', fakePath, landing)
    fileMasks.push({ source: fakePath, landing })
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
      ...denyWriteBinds.map(bind => bind.dest),
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
  // canonical dest, which is where its bind lands.
  const emittedDenyWriteDests: string[] = []
  // Write paths already restored read-only by a dropped deny bind, so two
  // denies covering the same path emit one --ro-bind.
  const restoredReadOnlyWritePaths = new Set<string>()
  for (const bind of denyWriteBinds) {
    const { dest, rawDest } = bind
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
          // mask back on top. Masks and restores are both keyed by where they
          // land, so one comparison answers for every spelling.
          if (fileMasks.some(mask => mask.landing === writePath)) {
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
    // This bind lands, so the file git reads at `dest` is settled now: the
    // mount point on the host is written here, not left to bwrap, and the
    // placeholder bound over it comes from the store.
    let source = bind.source
    if (bind.gitRedirect !== undefined) {
      const prepared = gitRedirectMountPoint(
        dest,
        bind.gitRedirect,
        gitRedirectStoreFiles,
      )
      if ('denyGitDirWhole' in prepared) {
        const gitDir = prepared.denyGitDirWhole
        // Read-only over the directory itself: it needs nothing written to
        // the host, and it denies every file inside at once — including the
        // other redirect file, whose own turn in this loop then has nothing
        // left to do.
        if (!denyWholeGitDirs.has(gitDir)) {
          denyWholeGitDirs.add(gitDir)
          args.push('--ro-bind', gitDir, gitDir)
          emittedDenyWriteDests.push(gitDir)
        }
        continue
      }
      source = prepared.bind
      if (source !== dest) gitRedirectSourceDir = path.dirname(source)
    }
    args.push('--ro-bind', source, dest)
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
        `[Sandbox Linux] Re-applying denyRead tmpfs re-exposed by denyWrite bind: ${unit.landing}`,
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
      // The tmpfs goes back at the unit's landing, which is the destination
      // the first pass gave bwrap for it.
      args.push('--tmpfs', unit.landing)
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
        `[Sandbox Linux] Re-applying file mask re-exposed by denyWrite bind: ${mask.landing}`,
      )
      args.push('--ro-bind', mask.source, mask.landing)
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

  // INVARIANT, for the same reason and with the same remedy: the store of git
  // redirect placeholders. A bind exposes the source file itself, so a
  // command able to write it chooses what git reads at the DENIED path. The
  // three mount sources here are siblings under the temp directory, each its
  // own mkdtemp, so no one of these binds can cover another whatever the
  // order; all three sit after every mount that could cover them.
  if (gitRedirectSourceDir !== undefined) {
    args.push('--ro-bind', gitRedirectSourceDir, gitRedirectSourceDir)
  }

  // INVARIANT, for the same reason: the empty directory the placeholders above
  // bind from must never be writable from inside the sandbox. It lives under
  // the system temp dir, so a caller's allowWrite or a host $TMPDIR under a
  // default write path makes it writable — and a placeholder binds it onto a
  // DENIED destination, so a write to the source lands at the deny. Emit last,
  // like the store, to overlay any earlier --bind that covers it. A same-uid
  // process on the host can still swap the source between wrap and run, which
  // is outside what this library defends against.
  if (emptySource !== undefined) {
    args.push('--ro-bind', emptySource, emptySource)
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
 * The two stages are described in README.md, "Unix Socket Restrictions
 * (Linux)".
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
 *
 * CALLER OBLIGATION: the euid and capability decisions behind the returned
 * string are made here, in the process that builds it, so the string must be
 * run by a process with the same euid and the same capability bounding and
 * inheritable sets.
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

  // One encoded key for both carriers below (SRT_ENCODED_CMD for the seccomp
  // observer, the proxy username for network denies), so a violation seen
  // through either resolves to the same registry entry. macOS derives its log
  // tag from a single key the same way.
  const attributionKey = encodeSandboxedCommand(
    attributionKeyFor(command, commandId),
  )

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
        bwrapArgs.push('--setenv', 'SRT_ENCODED_CMD', attributionKey)
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
          attributionKey,
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
      // What bubblewrap will parse, less the environment and network words
      // already built above and the few that come after the mounts.
      BWRAP_MAX_ARGS - bwrapArgs.length - BWRAP_TRAILING_WORDS,
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
    // clone and EPERM.
    const euid = process.geteuid?.()
    const hasSetfcap = processHasBoundingCapability(CAP_SETFCAP)
    if (euid === 0 && !hasSetfcap && !setfcapMissingLogged) {
      setfcapMissingLogged = true
      logForDebugging(`[Sandbox Linux] ${CAP_SETFCAP_MISSING_MESSAGE}`, {
        level: 'warn',
      })
    }
    bwrapArgs.push(
      '--unshare-user',
      ...capabilityArgs({
        euid,
        hasSetfcap,
        usesSeccompHelper: applySeccompPrefix !== undefined,
      }),
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
    // The caller does not clean up after a wrap that threw, and this one may
    // already have written mount points on the host — the files git reads
    // back are written before bubblewrap is ever reached. No sandbox of this
    // wrap is running, so the cleanup that undoes the activeSandboxCount
    // increment takes them away with it; it still defers to any other wrap
    // that is still up.
    cleanupBwrapMountPoints()
    throw error
  }
}
