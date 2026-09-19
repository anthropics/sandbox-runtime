import * as fs from 'fs'
import * as path from 'path'
import { logForDebugging } from '../utils/debug.js'
import { DEFAULT_RIPGREP_TIMEOUT_MS } from '../utils/ripgrep.js'
import {
  isAbsenceErrno,
  MAX_SYMLINK_RESOLUTION_DEPTH,
} from './sandbox-utils.js'

/**
 * The path is absent, as opposed to unreadable or otherwise unverifiable.
 * Narrower than the shared {@link isAbsenceErrno} by two codes: ELOOP must
 * read as unreadable here, so a `gitdir:` target that is a symlink loop is
 * denied whole rather than passed over as nothing, and ENAMETOOLONG has its
 * own answer in {@link isUnusablePathError}.
 */
function isAbsenceError(err: unknown): boolean {
  const code = (err as NodeJS.ErrnoException | undefined)?.code
  if (code === 'ELOOP' || code === 'ENAMETOOLONG') return false
  return isAbsenceErrno(err)
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

/** Time the `.git/modules` walk gets when the caller sets no deadline. */
const DEFAULT_SUBMODULE_WALK_TIMEOUT_MS = DEFAULT_RIPGREP_TIMEOUT_MS

/**
 * How often the walk looks at the clock: once per this many entries, rather
 * than once per directory, because one directory can hold as many entries as
 * the whole rest of the walk.
 */
const WALK_DEADLINE_CHECK_INTERVAL = 128

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
 *
 * The message names the file, because a sandboxed command can write one and
 * the refusal is then lifted only by a command run outside the sandbox. On
 * Linux the wrap turns this into a `LinuxSandboxProfileError` carrying
 * `deny_git_metadata_unreadable`; on macOS it is the profile generator's own
 * refusal and reaches the caller as itself. Branch on `.code`, not on the
 * message.
 */
export class GitMetadataError extends Error {
  readonly code = 'git_metadata_unreadable' as const
  constructor(message: string) {
    super(message)
    this.name = 'GitMetadataError'
  }
}

/**
 * The `.git/modules` walk ran out of the time it was given, so the submodule
 * git directories it never reached would have been left with writable hooks.
 * The Linux wrap turns this into a `LinuxSandboxProfileError` carrying
 * `deny_scan_failed`; on macOS it reaches the caller as itself. Branch on
 * `.code`, not on the message.
 */
export class SubmoduleWalkBudgetError extends Error {
  readonly code = 'submodule_walk_budget_exhausted' as const
  constructor(message: string) {
    super(message)
    this.name = 'SubmoduleWalkBudgetError'
  }
}

/** Directories found under a `.git/modules`, and what could not be read. */
export interface SubmoduleScan {
  /** The submodule git directories, sorted. */
  gitDirs: string[]
  /**
   * Directories the walk could not see through: what lies under them is
   * unknown, so they are denied whole rather than left writable with a git
   * directory possibly inside. Two things produce one — a directory the walk
   * could not list, and an entry whose target exists and could not be
   * inspected — and the recorded path is the deepest ancestor this process can
   * reach towards it, which can be the `.git/modules` root itself. Sorted and
   * without duplicates, like `gitDirs`.
   *
   * A whole-directory deny is read-only for everything beneath it, a
   * submodule's `objects`, `refs` and `index` included, so git writes inside a
   * tree that trips one stop working.
   */
  unreadableDirs: string[]
}

/**
 * What a git directory's tree is denied by, in the pieces a backend with a
 * ceiling on how many mounts it can carry degrades it in (Linux:
 * src/sandbox/linux-deny-collapse.ts). Every piece is a precise deny: nothing
 * here is collapsed, on either backend.
 */
export interface GitDirTreeDenies {
  /** The git directory's own hooks, config and redirect files. */
  ownDenyPaths: string[]
  /** `<gitDir>/modules`, whether or not the walk found anything under it. */
  modulesDir: string
  /** One per submodule git directory under `modulesDir`, sorted by path. */
  submodules: Array<{ gitDir: string; denyPaths: string[] }>
  /** What the walk could not see through; see {@link SubmoduleScan}. */
  unreadableDirs: string[]
}

/**
 * The files inside a git directory that send git to a git directory or a
 * config other than the one it opened, and what must stand in for one where
 * it does not exist.
 *
 * Denying a path that is not there means mounting something at it, and git
 * reads whichever of these two it finds: it refuses to run at all against a
 * `commondir` it cannot read, which both an empty file and a bound /dev/null
 * are (git rejects a commondir it reads zero bytes from, and a bind mount
 * carries nodev, so the device is unreadable). Each placeholder is what git
 * concludes with the file absent: `.` makes git resolve the git directory it
 * opened as its own common directory, and an empty `config.worktree` reads as
 * no worktree config at all.
 *
 * That is not invisible. The file's mere existence sets git's
 * `different_commondir`, so `git rev-parse --git-common-dir` and `--git-path`
 * print the absolute real path where they printed a relative one, and a
 * script that compares `--git-dir` with `--git-common-dir` to decide "this is
 * a linked worktree" answers yes for an ordinary repository while the deny
 * stands. No content avoids that: the alternative is git refusing to run.
 *
 * An empty placeholder also says that an empty file at that path is a
 * legitimate one to leave alone; a non-empty placeholder says the opposite,
 * which is what lets the Linux backend repair an empty `commondir` (see
 * `gitRedirectMountPoint` in src/sandbox/linux-sandbox-utils.ts).
 */
const GIT_REDIRECT_FILES: ReadonlyArray<{
  name: string
  placeholder: string
  /** Denied even where the caller allows writes to the git config. */
  deniedWithConfigAllowed: boolean
}> = [
  // Moves the hooks and config git reads to another directory entirely.
  { name: 'commondir', placeholder: '.\n', deniedWithConfigAllowed: true },
  // Read instead of `config` wherever extensions.worktreeConfig is on.
  { name: 'config.worktree', placeholder: '', deniedWithConfigAllowed: false },
]

/**
 * The paths inside a git directory through which a write becomes code the
 * host's git runs later: hooks/ always, config (core.fsmonitor, core.editor,
 * core.hooksPath and the like) unless the caller allows config writes, and
 * the redirect files of {@link GIT_REDIRECT_FILES}, each under the same
 * condition as the file it redirects.
 */
export function gitDirDenyPaths(
  gitDir: string,
  allowGitConfig: boolean,
): string[] {
  const redirectFiles = (deniedWithConfigAllowed: boolean): string[] =>
    GIT_REDIRECT_FILES.filter(
      file => file.deniedWithConfigAllowed === deniedWithConfigAllowed,
    ).map(file => path.join(gitDir, file.name))

  const denyPaths = [path.join(gitDir, 'hooks'), ...redirectFiles(true)]
  if (!allowGitConfig) {
    denyPaths.push(path.join(gitDir, 'config'), ...redirectFiles(false))
  }
  return denyPaths
}

/**
 * What must stand in for `denyPath` where it does not exist, or undefined for
 * a path git does not read this way. Decided by the basename, so every
 * spelling of one path - a tilde, a relative form, a trailing slash, a
 * symlinked prefix - answers the same. See {@link GIT_REDIRECT_FILES}.
 */
export function gitRedirectPlaceholder(denyPath: string): string | undefined {
  const name = path.basename(denyPath)
  return GIT_REDIRECT_FILES.find(file => file.name === name)?.placeholder
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
    let target: string | undefined
    switch (pointer.kind) {
      case 'contents':
        target = parseGitdirPointer(pointer.bytes, gitFile)
        break
      case 'too-large':
        // git refuses a .git file this large outright, so it leads nowhere.
        logForDebugging(
          `[Sandbox] ${gitFile} is larger than the ${MAX_GIT_METADATA_BYTES} bytes git accepts for a .git file, so git does not follow it either; denying only the file itself`,
          { level: 'warn' },
        )
        return denyPaths
      case 'none':
        break
    }
    if (target === undefined) return denyPaths
    const gitDirs = gitMetadataTargets(path.dirname(gitFile), target).map(
      gitDir => ({ gitDir, kind: gitDirKind(gitDir) }),
    )
    for (const { gitDir, kind } of gitDirs) {
      denyPaths.push(
        ...gitDirTargetDenyPaths(gitDir, kind, allowGitConfig, gitFile),
      )
    }

    // A linked worktree's git directory holds the path of the main one, whose
    // hooks and config its commits run. git reads it out of the directory it
    // opened, so each candidate above has its own.
    for (const { gitDir, kind } of gitDirs) {
      // Only a git directory has a commondir git reads; a directory this
      // process could not list is already denied whole, and git, running as
      // the same user, cannot read through it either.
      if (kind !== 'git-dir') continue
      const commonFile = path.join(gitDir, 'commondir')
      let common: GitMetadata
      try {
        common = readGitMetadataFile(commonFile)
      } catch (err) {
        if (isAbsenceError(err)) continue
        // The file is there and could not be read, so the directory whose
        // hooks this worktree's commits run is unknown. Returning the denies
        // gathered so far would leave that repository's hooks writable.
        throw new GitMetadataError(
          `[Sandbox] ${commonFile} could not be read (${String(err)}); refusing to sandbox without the git directory it names`,
        )
      }
      let commonTarget: string | undefined
      switch (common.kind) {
        case 'contents':
          commonTarget = gitMetadataPath(common.bytes, commonFile)
          break
        case 'too-large':
          // git reads commondir whole, with no size limit of its own, so a
          // file past this bound still names the directory whose hooks git
          // runs.
          throw new GitMetadataError(
            `[Sandbox] ${commonFile} is larger than ${MAX_GIT_METADATA_BYTES} bytes; refusing to sandbox without the git directory it names`,
          )
        case 'none':
          break
      }
      if (commonTarget === undefined) continue
      for (const commonDir of gitMetadataTargets(gitDir, commonTarget)) {
        if (commonDir === gitDir) continue
        denyPaths.push(
          ...gitDirTargetDenyPaths(
            commonDir,
            gitDirKind(commonDir),
            allowGitConfig,
            commonFile,
          ),
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
 * Every git directory a deny must cover once `gitDir` is one: its own hooks/
 * and config, and the same for each submodule git directory under its
 * `modules` (what a commit inside that submodule runs), plus whatever the
 * walk could not see through. `deadline` bounds the walk (see
 * {@link submoduleGitDirs}).
 *
 * Kept apart rather than flattened so that a backend which cannot carry every
 * mount can degrade the submodule denies and leave the rest alone;
 * {@link gitDirTreeDenyPaths} is the flat form both backends emit when
 * nothing has to be degraded.
 */
export function gitDirTreeDenies(
  gitDir: string,
  allowGitConfig: boolean,
  options: { deadline?: number } = {},
): GitDirTreeDenies {
  const modulesDir = path.join(gitDir, 'modules')
  const modules = submoduleGitDirs(modulesDir, options.deadline)
  return {
    ownDenyPaths: gitDirDenyPaths(gitDir, allowGitConfig),
    modulesDir,
    submodules: modules.gitDirs.map(submodule => ({
      gitDir: submodule,
      denyPaths: gitDirDenyPaths(submodule, allowGitConfig),
    })),
    unreadableDirs: modules.unreadableDirs,
  }
}

/** {@link gitDirTreeDenies} as one list, which is what a backend with no
 *  ceiling to stay under emits. */
export function gitDirTreeDenyPaths(denies: GitDirTreeDenies): string[] {
  return [
    ...denies.ownDenyPaths,
    ...denies.unreadableDirs,
    ...denies.submodules.flatMap(submodule => submodule.denyPaths),
  ]
}

/**
 * Git directories of the submodules under `modulesDir` (a repository's
 * .git/modules), nested submodules included, sorted. A submodule's name is
 * its path, so one can sit several levels down (modules/vendor/lib), hence
 * the walk.
 *
 * Every directory is visited once, keyed by where it really is, so a symlink
 * pointing back into the tree ends the branch that reached it rather than
 * looping - but a bind mount gives the same directory a second real path, and
 * one pointed at its own ancestor has no end the visited set can see. `deadline`
 * is what bounds that, and running out of it throws
 * {@link SubmoduleWalkBudgetError} rather than handing back a listing that
 * stops somewhere unknown. Nothing bounds how DEEP a real tree may be: a
 * submodule nested a hundred levels down has its hooks denied like any other,
 * and the walk keeps its own stack so that such a tree cannot overflow this
 * one's.
 */
export function submoduleGitDirs(
  modulesDir: string,
  deadline: number = Date.now() + DEFAULT_SUBMODULE_WALK_TIMEOUT_MS,
): SubmoduleScan {
  const walk: SubmoduleWalk = { gitDirs: [], unreadableDirs: new Set() }
  // Where the walk still has to look, and where it has already been. A
  // directory listed to see whether it is a git directory carries its entries
  // with it, so that no directory is listed twice. The root counts as visited:
  // an entry linked straight back to it is then the same dead end as one
  // linked to any other directory already walked.
  const pending: Array<{ dir: string; entries?: fs.Dirent[] }> = [
    { dir: modulesDir },
  ]
  const visited = new Set<string>([realPathOrSelf(modulesDir)])
  let entriesSeen = 0
  for (let item = pending.pop(); item !== undefined; item = pending.pop()) {
    const entries = item.entries ?? listDirectory(item.dir, walk)
    if (entries === undefined) continue
    for (const entry of entries) {
      if (
        entriesSeen++ % WALK_DEADLINE_CHECK_INTERVAL === 0 &&
        Date.now() > deadline
      ) {
        throw new SubmoduleWalkBudgetError(
          `[Sandbox] The walk of ${modulesDir} ran out of the time it was given while listing ${item.dir}, with ${pending.length} directories still to look at; refusing to sandbox on the submodule git directories it did reach`,
        )
      }
      const child = path.join(item.dir, entry.name)
      // git accepts a symlinked entry under .git/modules, and
      // Dirent.isDirectory is false for one, so the link is followed — and
      // the real path recorded, since a link back up would otherwise loop.
      if (!isDirectory(entry, child, walk)) continue
      const visitKey = realPathOrSelf(child)
      if (visited.has(visitKey)) continue
      visited.add(visitKey)

      const childEntries = listDirectory(child, walk)
      if (childEntries === undefined) continue
      const isGitDir = childEntries.some(e => GIT_DIR_MARKERS.has(e.name))
      if (isGitDir) walk.gitDirs.push(child)
      // A git directory keeps its own submodules under `modules`; anything
      // else is a segment of a submodule name (`vendor` of `vendor/lib`).
      pending.push(
        isGitDir
          ? { dir: path.join(child, 'modules') }
          : { dir: child, entries: childEntries },
      )
    }
  }
  return {
    gitDirs: walk.gitDirs.sort(),
    unreadableDirs: [...walk.unreadableDirs].sort(),
  }
}

/** What the walk has found so far. The deny paths a directory it could not
 *  see through produces are a set: one unreadable entry and the next fold to
 *  the same ancestor, and a repeated path is a mount the profile never pays
 *  for but would otherwise be counted as one. */
interface SubmoduleWalk {
  gitDirs: string[]
  unreadableDirs: Set<string>
}

/** Entries of `dir`, or undefined when it is absent or (recorded) unreadable. */
function listDirectory(
  dir: string,
  walk: SubmoduleWalk,
): fs.Dirent[] | undefined {
  try {
    return fs.readdirSync(dir, { withFileTypes: true })
  } catch (err) {
    // Absent is the common case: no submodules, or none nested in this one.
    if (!isAbsenceError(err)) {
      const denied = deepestReachableAncestor(dir) ?? dir
      walk.unreadableDirs.add(denied)
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
  walk: SubmoduleWalk,
): boolean {
  if (entry.isDirectory()) return true
  if (!entry.isSymbolicLink()) return false
  try {
    return fs.statSync(entryPath).isDirectory()
  } catch (err) {
    if (isAbsenceError(err) || isUnusablePathError(err)) return false
    if ((err as NodeJS.ErrnoException).code === 'ELOOP') {
      // A link that resolves back to itself reaches no directory at all, so
      // there is nothing behind it to deny and nothing a command can put
      // there without replacing the link, which the next wrap's walk sees.
      // The link's own path cannot carry a read-only bind either: bubblewrap
      // resolves a mount destination, and resolving this one is what just
      // failed. Denying the directory that HOLDS it is the one answer that
      // would be worse than none - a single link a command can write would
      // take every submodule beside it read-only.
      logForDebugging(
        `[Sandbox] ${entryPath} is a symlink loop, which leads to nothing to deny: ${err}`,
        { level: 'warn' },
      )
      return false
    }
    // Something is there and could not be inspected. Fail closed on the
    // deepest directory that can be reached TOWARDS IT rather than on the
    // directory holding the link, which would again be every submodule
    // beside it.
    const denied =
      deepestReachableAncestor(linkTarget(entryPath) ?? entryPath) ?? entryPath
    walk.unreadableDirs.add(denied)
    logForDebugging(
      `[Sandbox] Could not follow ${entryPath}, denying ${denied} whole: ${err}`,
      { level: 'warn' },
    )
    return false
  }
}

/** Where `link` points, resolved against the directory holding it, or
 *  undefined when it cannot be read. */
function linkTarget(link: string): string | undefined {
  try {
    return path.resolve(path.dirname(link), fs.readlinkSync(link))
  } catch {
    return undefined
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
  kind: GitDirKind,
  allowGitConfig: boolean,
  source: string,
): string[] {
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
 * accepting `config` or `hooks` would let that content aim a deny at any
 * directory at all. The walk reaches only what lies under `.git/modules` —
 * except through a symlinked entry there, which a command able to write under
 * it can aim at one directory of its choosing.
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
    if (hops > MAX_SYMLINK_RESOLUTION_DEPTH) return next
    // A link's own target is walked in its place, from the directory holding
    // it unless it is absolute.
    if (path.isAbsolute(link)) current = path.parse(link).root
    pending = [...link.split('/'), ...pending]
  }
  return current
}

/**
 * The deepest ancestor of `target` (itself included) this process can still
 * stat as a directory. Denying that directory fails closed when the path
 * below it cannot be inspected: nothing under it is writable in the sandbox.
 *
 * Symlinks are followed, so a link to a directory that cannot be listed is
 * answered with the link's own path rather than with the directory holding
 * it — the Linux deny loop puts the bind on the real target (see
 * `resolveSymlinkedDenyPath`), and answering with the parent would let one
 * unreadable directory anyone can plant a link to take every entry beside it
 * read-only.
 */
function deepestReachableAncestor(target: string): string | undefined {
  for (let dir = target; ; dir = path.dirname(dir)) {
    try {
      if (fs.statSync(dir).isDirectory()) return dir
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
