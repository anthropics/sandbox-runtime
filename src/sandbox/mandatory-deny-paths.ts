import * as fs from 'fs'
import * as path from 'path'
import { logForDebugging } from '../utils/debug.js'

/** The path is absent, as opposed to unreadable or otherwise unverifiable. */
function isAbsenceError(err: unknown): boolean {
  const code = (err as NodeJS.ErrnoException | undefined)?.code
  return code === 'ENOENT' || code === 'ENOTDIR'
}

/**
 * How much of a `.git` pointer or a `commondir` is read. Both hold a single
 * path, and git refuses a gitfile larger than 1 MiB, so a file this size is
 * not one git would follow either.
 */
const MAX_GIT_METADATA_BYTES = 8192

/**
 * Depth bound for the `.git/modules` walk. A submodule's name is its path
 * (`vendor/lib`) and submodules nest, so the walk descends both name segments
 * and nested `modules` directories; this bounds a hostile or looping tree, not
 * a real one, and is deliberately unrelated to the ripgrep scan's depth.
 */
const MAX_SUBMODULE_WALK_DEPTH = 10

/**
 * Entries whose presence makes a directory a git directory. git needs HEAD
 * and objects; config and hooks are what this file protects, so a directory
 * holding either is treated as one even if HEAD has been moved aside.
 */
const GIT_DIR_MARKERS = new Set(['HEAD', 'config', 'hooks', 'objects'])

/** What {@link gitDirKind} concluded about a `gitdir:`/`commondir` target. */
type GitDirKind = 'git-dir' | 'absent' | 'other' | 'unreadable'

/** Directories found under a `.git/modules`, and what could not be read. */
export interface SubmoduleScan {
  /** The submodule git directories. */
  gitDirs: string[]
  /**
   * Directories the walk could not list. Their contents are unknown, so they
   * are denied whole rather than left writable with a git directory possibly
   * inside them.
   */
  unreadableDirs: string[]
}

/**
 * The paths inside a git directory through which a write becomes code the
 * host's git runs later: hooks/ always, `commondir` always (it redirects the
 * hooks and config git reads to another directory entirely), and config plus
 * `config.worktree` (core.fsmonitor, core.editor, core.hooksPath and the
 * like, the latter read when extensions.worktreeConfig is on) unless the
 * caller allows config writes.
 */
export function gitDirDenyPaths(
  gitDir: string,
  allowGitConfig: boolean,
): string[] {
  const denyPaths = [path.join(gitDir, 'hooks'), path.join(gitDir, 'commondir')]
  if (!allowGitConfig) {
    denyPaths.push(
      path.join(gitDir, 'config'),
      path.join(gitDir, 'config.worktree'),
    )
  }
  return denyPaths
}

/**
 * Deny paths for a `.git` file, the `gitdir:` pointer of a linked worktree or
 * submodule checkout: the file itself plus the hooks/ and config git reads
 * through it (the named git directory's, and for a linked worktree its
 * commondir's as well).
 */
export function gitFileDenyPaths(
  gitFile: string,
  allowGitConfig: boolean,
): string[] {
  const denyPaths = [gitFile]
  try {
    const pointer = readGitMetadataFile(gitFile)
    const target =
      pointer === undefined ? undefined : parseGitdirPointer(pointer)
    if (target === undefined) return denyPaths
    const gitDir = path.resolve(path.dirname(gitFile), target)
    denyPaths.push(...gitDirTargetDenyPaths(gitDir, allowGitConfig, gitFile))

    // A linked worktree's git directory holds the path of the main one, whose
    // hooks and config its commits run.
    const commonFile = path.join(gitDir, 'commondir')
    const common = readGitMetadataFile(commonFile)
    const commonDir =
      common === undefined
        ? undefined
        : path.resolve(gitDir, firstLine(common).trim())
    if (commonDir !== undefined && commonDir !== gitDir) {
      denyPaths.push(
        ...gitDirTargetDenyPaths(commonDir, allowGitConfig, commonFile),
      )
    }
  } catch (err) {
    // A dangling pointer names nothing git would read. A pointer this process
    // cannot read is one the host's git cannot read either, so the file
    // itself is the whole deny; an unreadable TARGET is denied whole by
    // gitDirTargetDenyPaths instead.
    if (!isAbsenceError(err)) {
      logForDebugging(
        `[Sandbox] Could not follow ${gitFile}, denying only the file itself: ${err}`,
        { level: 'warn' },
      )
    }
  }
  return denyPaths
}

/**
 * Git directories of the submodules under `modulesDir` (a repository's
 * .git/modules), nested submodules included. A submodule's name is its path,
 * so one can sit several levels down (modules/vendor/lib), hence the walk.
 */
export function submoduleGitDirs(modulesDir: string): SubmoduleScan {
  const scan: SubmoduleScan = { gitDirs: [], unreadableDirs: [] }
  collectSubmoduleGitDirs(modulesDir, 0, scan, new Set())
  return scan
}

function collectSubmoduleGitDirs(
  dir: string,
  depth: number,
  scan: SubmoduleScan,
  visited: Set<string>,
): void {
  const entries = listDirectory(dir, scan)
  if (entries === undefined) return
  for (const entry of entries) {
    const child = path.join(dir, entry.name)
    // git accepts a symlinked entry under .git/modules, and Dirent.isDirectory
    // is false for one, so the link is followed — and the realpath recorded,
    // since a link back up would otherwise loop until the depth bound.
    if (!isDirectory(entry, child, scan)) continue
    const visitKey = realPathOrSelf(child)
    if (visited.has(visitKey)) continue
    visited.add(visitKey)

    const childEntries = listDirectory(child, scan)
    if (childEntries === undefined) continue
    const isGitDir = childEntries.some(e => GIT_DIR_MARKERS.has(e.name))
    if (isGitDir) scan.gitDirs.push(child)

    if (depth + 1 >= MAX_SUBMODULE_WALK_DEPTH) {
      logForDebugging(
        `[Sandbox] Stopped the .git/modules walk below ${child} at depth ${MAX_SUBMODULE_WALK_DEPTH}; submodule git directories beneath it are not denied`,
        { level: 'warn' },
      )
      continue
    }
    collectSubmoduleGitDirs(
      isGitDir ? path.join(child, 'modules') : child,
      depth + 1,
      scan,
      visited,
    )
  }
}

/** Entries of `dir`, or undefined when it is absent or (recorded) unreadable. */
function listDirectory(
  dir: string,
  scan: SubmoduleScan,
): fs.Dirent[] | undefined {
  try {
    return fs.readdirSync(dir, { withFileTypes: true })
  } catch (err) {
    // Absent is the common case: no submodules, or none nested in this one.
    if (!isAbsenceError(err)) {
      const denied = deepestReachableAncestor(dir) ?? dir
      scan.unreadableDirs.push(denied)
      logForDebugging(
        `[Sandbox] Could not list ${dir}, denying ${denied} whole: ${err}`,
        { level: 'warn' },
      )
    }
    return undefined
  }
}

/** Whether `entry` is a directory, following a symlink to one. */
function isDirectory(
  entry: fs.Dirent,
  entryPath: string,
  scan: SubmoduleScan,
): boolean {
  if (entry.isDirectory()) return true
  if (!entry.isSymbolicLink()) return false
  try {
    return fs.statSync(entryPath).isDirectory()
  } catch (err) {
    if (!isAbsenceError(err)) {
      scan.unreadableDirs.push(deepestReachableAncestor(entryPath) ?? entryPath)
    }
    return false
  }
}

/**
 * Deny paths for a directory a `gitdir:` or `commondir` names. An existing
 * directory that is not a git directory is left alone: file content must not
 * be able to point the deny list at, say, a Rails `config/`. An absent one is
 * still denied, so the sandboxed command cannot create the target and fill it
 * with hooks before the host's git first uses it.
 */
function gitDirTargetDenyPaths(
  target: string,
  allowGitConfig: boolean,
  source: string,
): string[] {
  const kind = gitDirKind(target)
  switch (kind) {
    case 'git-dir':
    case 'absent':
      return gitDirDenyPaths(target, allowGitConfig)
    case 'unreadable': {
      const denied = deepestReachableAncestor(target) ?? target
      logForDebugging(
        `[Sandbox] Could not read ${target} named by ${source}, denying ${denied} whole`,
        { level: 'warn' },
      )
      return [denied]
    }
    case 'other':
      logForDebugging(
        `[Sandbox] ${source} names ${target}, which is not a git directory; denying only ${source}`,
        { level: 'warn' },
      )
      return []
  }
}

function gitDirKind(dir: string): GitDirKind {
  let entries: fs.Dirent[]
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true })
  } catch (err) {
    return isAbsenceError(err) ? 'absent' : 'unreadable'
  }
  return entries.some(e => e.name === 'HEAD' || e.name === 'objects')
    ? 'git-dir'
    : 'other'
}

/**
 * At most {@link MAX_GIT_METADATA_BYTES} of `file`, or undefined when it is
 * absent, is not a regular file, or is longer than that. The path is one a
 * sandboxed command may create: a FIFO there would block the host on every
 * later wrap (hence O_NONBLOCK and the type check), and an arbitrarily large
 * file would be buffered whole on every command.
 */
function readGitMetadataFile(file: string): string | undefined {
  // O_NONBLOCK is POSIX-only; this file's callers are the Linux and macOS
  // backends, and 0 leaves the flags as they were.
  const nonBlocking = fs.constants.O_NONBLOCK ?? 0
  let fd: number
  try {
    fd = fs.openSync(file, fs.constants.O_RDONLY | nonBlocking)
  } catch (err) {
    if (isAbsenceError(err)) return undefined
    throw err
  }
  try {
    // From the open file description, so it describes what was actually
    // opened rather than what the path named a moment ago.
    if (!fs.fstatSync(fd).isFile()) return undefined
    const buffer = Buffer.alloc(MAX_GIT_METADATA_BYTES)
    const read = fs.readSync(fd, buffer, 0, buffer.length, 0)
    if (read === buffer.length) {
      logForDebugging(
        `[Sandbox] ${file} is larger than ${MAX_GIT_METADATA_BYTES} bytes, which is not a path git would follow; ignoring it`,
        { level: 'warn' },
      )
      return undefined
    }
    return buffer.toString('utf8', 0, read)
  } finally {
    fs.closeSync(fd)
  }
}

/**
 * The `gitdir:` target of a pointer file. git requires the prefix at byte 0
 * and trims only newline bytes from the end, and a path never spans lines.
 */
function parseGitdirPointer(contents: string): string | undefined {
  const prefix = 'gitdir: '
  const line = firstLine(contents)
  if (!line.startsWith(prefix)) return undefined
  const target = line.slice(prefix.length)
  return target.length > 0 ? target : undefined
}

/** The first line, without the newline bytes git strips (`\n`, `\r`). */
function firstLine(contents: string): string {
  const end = contents.indexOf('\n')
  return (end === -1 ? contents : contents.slice(0, end)).replace(/\r+$/, '')
}

/**
 * The deepest ancestor of `target` (itself included) this process can still
 * stat. Denying that directory fails closed when the path below it cannot be
 * inspected: nothing under it is writable in the sandbox.
 */
function deepestReachableAncestor(target: string): string | undefined {
  for (let dir = target; ; dir = path.dirname(dir)) {
    try {
      if (fs.lstatSync(dir).isDirectory()) return dir
    } catch {
      // Unreachable at this level; try the parent.
    }
    if (path.dirname(dir) === dir) return undefined
  }
}

/** `target` with symlinks resolved, or itself when that fails. */
function realPathOrSelf(target: string): string {
  try {
    return fs.realpathSync(target)
  } catch {
    return target
  }
}
