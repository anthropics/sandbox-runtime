import * as fs from 'fs'
import * as path from 'path'
import { logForDebugging } from '../utils/debug.js'

/** The path is absent, as opposed to unreadable or otherwise unverifiable. */
function isAbsenceError(err: unknown): boolean {
  const code = (err as NodeJS.ErrnoException | undefined)?.code
  return code === 'ENOENT' || code === 'ENOTDIR'
}

/**
 * The path is longer than the filesystem allows, so no file can occupy it:
 * git's own stat of it fails, and a sandboxed command cannot create a git
 * directory there either.
 */
function isUnusablePathError(err: unknown): boolean {
  return (err as NodeJS.ErrnoException | undefined)?.code === 'ENAMETOOLONG'
}

/**
 * How much of a `.git` pointer or a `commondir` is read: what git's
 * `read_gitfile_gently` accepts for a pointer file, so one larger than this
 * is not a pointer git follows either. `commondir` has no bound in git, so
 * one this large is read by git and not by this, and fails closed.
 */
const MAX_GIT_METADATA_BYTES = 1024 * 1024

/**
 * Symlink hops allowed while resolving one path, the limit Linux itself
 * applies before it gives up with ELOOP.
 */
const MAX_SYMLINK_HOPS = 40

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
type GitDirKind = 'git-dir' | 'absent' | 'other' | 'unreadable' | 'unusable'

/** What {@link readGitMetadataFile} found at a `.git` file or a `commondir`. */
type GitMetadata =
  /** The whole file, within the size git accepts. */
  | { kind: 'contents'; bytes: Buffer }
  /** Absent, or not the regular file git requires: nothing git reads here. */
  | { kind: 'none' }
  /** Longer than {@link MAX_GIT_METADATA_BYTES}. */
  | { kind: 'too-large' }

/**
 * A git metadata file whose target cannot be worked out the way git works it
 * out. Thrown rather than logged, and not swallowed by
 * {@link gitFileDenyPaths}: sandboxing with a deny list that misses the hooks
 * and config git reads is worse than not sandboxing, which is the same call
 * the Linux backend makes for a scan that does not finish in time.
 */
export class GitMetadataError extends Error {}

/** Directories found under a `.git/modules`, and what could not be read. */
export interface SubmoduleScan {
  /** The submodule git directories. */
  gitDirs: string[]
  /**
   * Directories the walk could not see through: one it could not list, and
   * the one it stops at on reaching {@link MAX_SUBMODULE_WALK_DEPTH}. What
   * lies under them is unknown, so they are denied whole rather than left
   * writable with a git directory possibly inside them.
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
 *
 * A `..` in either path can land the kernel somewhere other than where the
 * path folds to on paper, so both directories are denied — see
 * {@link gitMetadataTargets}.
 *
 * Throws {@link GitMetadataError} when the pointer or the `commondir` names
 * something this cannot resolve the way git does; the wrap is then refused
 * rather than applied with a deny list that may not cover the directory git
 * uses.
 */
export function gitFileDenyPaths(
  gitFile: string,
  allowGitConfig: boolean,
): string[] {
  const denyPaths = [gitFile]
  try {
    const pointer = readGitMetadataFile(gitFile)
    if (pointer.kind === 'too-large') {
      // git refuses a .git file this large outright, so it leads nowhere.
      logForDebugging(
        `[Sandbox] ${gitFile} is larger than the ${MAX_GIT_METADATA_BYTES} bytes git accepts for a .git file, so git does not follow it either; denying only the file itself`,
        { level: 'warn' },
      )
      return denyPaths
    }
    const target =
      pointer.kind === 'contents'
        ? parseGitdirPointer(pointer.bytes, gitFile)
        : undefined
    if (target === undefined) return denyPaths
    const gitDirs = gitMetadataTargets(path.dirname(gitFile), target)
    for (const gitDir of gitDirs) {
      denyPaths.push(...gitDirTargetDenyPaths(gitDir, allowGitConfig, gitFile))
    }

    // A linked worktree's git directory holds the path of the main one, whose
    // hooks and config its commits run. git reads it out of the directory it
    // opened, so each candidate above has its own.
    for (const gitDir of gitDirs) {
      const commonFile = path.join(gitDir, 'commondir')
      const common = readGitMetadataFile(commonFile)
      if (common.kind === 'too-large') {
        // git reads commondir whole, with no size limit of its own, so a
        // file past this bound still names the directory whose hooks git
        // runs.
        throw new GitMetadataError(
          `[Sandbox] ${commonFile} is larger than ${MAX_GIT_METADATA_BYTES} bytes; refusing to sandbox without the git directory it names`,
        )
      }
      const commonTarget =
        common.kind === 'contents'
          ? gitMetadataPath(common.bytes, commonFile)
          : undefined
      if (commonTarget === undefined) continue
      for (const commonDir of gitMetadataTargets(gitDir, commonTarget)) {
        if (commonDir === gitDir) continue
        denyPaths.push(
          ...gitDirTargetDenyPaths(commonDir, allowGitConfig, commonFile),
        )
      }
    }
  } catch (err) {
    if (err instanceof GitMetadataError) throw err
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
      // Nothing below here is inspected, so the directory is denied whole,
      // like one the walk could not list: a submodule git directory nested
      // deeper would otherwise keep its hooks and config writable.
      scan.unreadableDirs.push(child)
      logForDebugging(
        `[Sandbox] Stopped the .git/modules walk below ${child} at depth ${MAX_SUBMODULE_WALK_DEPTH}, denying ${child} whole`,
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
    case 'unusable':
      logForDebugging(
        `[Sandbox] ${source} names ${target}, which is longer than the filesystem allows: no file can be there for git to read or for a command to create; denying only ${source}`,
        { level: 'warn' },
      )
      return []
    case 'other':
      logForDebugging(
        `[Sandbox] ${source} names ${target}, which is not a git directory; denying only ${source}`,
        { level: 'warn' },
      )
      return []
  }
}

/**
 * Whether `dir` is a git directory. Deliberately looser than git's
 * `is_git_directory` (a valid HEAD plus objects/ and refs/): every directory
 * git accepts has a HEAD entry, so this accepts those and some besides,
 * which only ever denies more.
 *
 * Narrower than {@link GIT_DIR_MARKERS}, which the `.git/modules` walk uses:
 * a directory here is named by file content a sandboxed command can write, so
 * accepting `config` or `hooks` would let that content aim a deny anywhere.
 */
function gitDirKind(dir: string): GitDirKind {
  let entries: fs.Dirent[]
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true })
  } catch (err) {
    if (isUnusablePathError(err)) return 'unusable'
    return isAbsenceError(err) ? 'absent' : 'unreadable'
  }
  return entries.some(e => e.name === 'HEAD' || e.name === 'objects')
    ? 'git-dir'
    : 'other'
}

/**
 * The contents of `file`, or what stopped this from reading it the way git
 * does. The path is one a sandboxed command may create: a FIFO there would
 * block the host on every later wrap (hence O_NONBLOCK and the type check).
 */
function readGitMetadataFile(file: string): GitMetadata {
  // O_NONBLOCK is POSIX-only; this file's callers are the Linux and macOS
  // backends, and 0 leaves the flags as they were.
  const nonBlocking = fs.constants.O_NONBLOCK ?? 0
  let fd: number
  try {
    fd = fs.openSync(file, fs.constants.O_RDONLY | nonBlocking)
  } catch (err) {
    if (isAbsenceError(err) || isUnusablePathError(err)) return { kind: 'none' }
    throw err
  }
  try {
    // From the open file description, so it describes what was actually
    // opened rather than what the path named a moment ago.
    const stat = fs.fstatSync(fd)
    if (!stat.isFile()) return { kind: 'none' }
    if (stat.size > MAX_GIT_METADATA_BYTES) return { kind: 'too-large' }
    // Sized from that stat rather than from the bound, and one byte past it
    // so a file that grew since is read on rather than taken for whole;
    // readSync can also stop short of the length it was given.
    let buffer = Buffer.alloc(stat.size + 1)
    let read = 0
    for (;;) {
      if (read === buffer.length) {
        if (buffer.length > MAX_GIT_METADATA_BYTES) return { kind: 'too-large' }
        const grown = Buffer.alloc(MAX_GIT_METADATA_BYTES + 1)
        buffer.copy(grown)
        buffer = grown
      }
      const chunk = fs.readSync(fd, buffer, read, buffer.length - read, read)
      if (chunk === 0) break
      read += chunk
    }
    return { kind: 'contents', bytes: buffer.subarray(0, read) }
  } finally {
    fs.closeSync(fd)
  }
}

/**
 * The `gitdir:` target of a pointer file, or undefined when git would not
 * follow the file at all. git requires the 8-byte prefix at offset 0 — no
 * leading whitespace, no other spelling — and everything after it is path.
 */
function parseGitdirPointer(
  contents: Buffer,
  file: string,
): string | undefined {
  const prefix = Buffer.from('gitdir: ')
  if (!contents.subarray(0, prefix.length).equals(prefix)) return undefined
  return gitMetadataPath(contents.subarray(prefix.length), file)
}

/**
 * The path a git metadata file names, by git's rules rather than a line
 * reader's: `\n` and `\r` are stripped from the END OF THE FILE (so a newline
 * inside the path is part of it), nothing is trimmed, and what is left is a C
 * string and ends at the first NUL. `read_gitfile_gently` and
 * `get_common_dir_noenv` in git's setup.c both read this way.
 *
 * This re-implements that parsing instead of asking git, because the library
 * has to work where git is not installed, a wrap would otherwise spawn a
 * process per pointer per command, and running git inside a checkout the
 * sandboxed command can write is the hazard these denies exist to contain;
 * test/sandbox/git-pointer-parity.test.ts is what keeps the two in step,
 * resolving a corpus of pointer shapes both ways and comparing.
 *
 * Throws {@link GitMetadataError} for a path whose bytes are not valid UTF-8:
 * a JavaScript string of them names a different file than git opens, so
 * there is no path here to deny.
 */
function gitMetadataPath(contents: Buffer, file: string): string | undefined {
  let end = contents.length
  while (
    end > 0 &&
    (contents[end - 1] === 0x0a || contents[end - 1] === 0x0d)
  ) {
    end--
  }
  const nul = contents.subarray(0, end).indexOf(0)
  const pathBytes = contents.subarray(0, nul === -1 ? end : nul)
  if (pathBytes.length === 0) return undefined

  const decoded = pathBytes.toString('utf8')
  if (!Buffer.from(decoded, 'utf8').equals(pathBytes)) {
    throw new GitMetadataError(
      `[Sandbox] ${file} names a path that is not valid UTF-8; refusing to sandbox with a deny list that would name a different directory than git opens`,
    )
  }
  return decoded
}

/**
 * The git directories a `gitdir:` or `commondir` value read in `base` leads
 * to: the path as it folds on paper, which is the spelling these denies have
 * always used, and — when a `..` in it could send the kernel elsewhere — the
 * directory the kernel actually reaches. git hands the two strings to stat
 * joined and unnormalised, so a symlink is followed before a later `..`
 * applies and `a/link/../b` need not be `a/b`. Both are denied when they
 * differ: git opens one of them, and denying the other costs one bind.
 */
function gitMetadataTargets(base: string, target: string): string[] {
  const lexical = path.resolve(base, target)
  if (!target.split('/').includes('..')) return [lexical]
  const root = path.parse(lexical).root
  const physical = physicalPath(physicalPath(root, base), target)
  // Both sides resolved the same way, so a base that merely spells itself
  // differently (a /var that is a symlink to /private/var) is no difference.
  return physical === physicalPath(root, lexical)
    ? [lexical]
    : [lexical, physical]
}

/**
 * Where the kernel lands walking `target` from `base`, symlinks followed as
 * it meets them. `path.resolve` folds `..` lexically, and `fs.realpathSync`
 * folds its argument the same way before resolving it, so neither answers
 * this; a walk also reaches a tail that does not exist yet, which realpath
 * cannot. A component that cannot be walked — missing, unreadable, or a loop
 * past the hop limit — ends it, since the kernel cannot traverse one either
 * and nothing beyond it can redirect the path; the rest is taken as written
 * and classified by {@link gitDirTargetDenyPaths} like any other target.
 */
function physicalPath(base: string, target: string): string {
  let current = path.isAbsolute(target) ? path.parse(target).root : base
  let pending = target.split('/')
  let hops = 0
  while (pending.length > 0) {
    const name = pending.shift()
    if (name === undefined || name === '' || name === '.') continue
    if (name === '..') {
      current = path.dirname(current)
      continue
    }
    const next = path.join(current, name)
    let link: string | undefined
    try {
      if (fs.lstatSync(next).isSymbolicLink()) link = fs.readlinkSync(next)
    } catch {
      return path.join(next, ...pending)
    }
    if (link === undefined) {
      current = next
      continue
    }
    // A loop is where the walk stops, and what it hands back: the rest of
    // the path folded past it would name a directory this cannot vouch for,
    // while the link itself reads as unreadable and is denied whole.
    hops += 1
    if (hops > MAX_SYMLINK_HOPS) return next
    // A link's own target is walked in its place, from the directory holding
    // it unless it is absolute.
    if (path.isAbsolute(link)) current = path.parse(link).root
    pending = [...link.split('/'), ...pending]
  }
  return current
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
