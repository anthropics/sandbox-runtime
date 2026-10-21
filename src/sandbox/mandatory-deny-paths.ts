import * as fs from 'fs'
import * as path from 'path'
import { logForDebugging } from '../utils/debug.js'
import { linkTextOf, realPathOrSelf } from '../utils/real-path.js'
import { DEFAULT_RIPGREP_TIMEOUT_MS } from '../utils/ripgrep.js'
import {
  isAbsenceErrno,
  isAtOrUnder,
  MAX_SYMLINK_RESOLUTION_DEPTH,
} from './sandbox-utils.js'

/**
 * Absent, so a command could still create it. Narrower than the shared {@link
 * isAbsenceErrno}: a symlink loop is walked instead, for its links to be held,
 * and ENAMETOOLONG is {@link isUnusablePathError}.
 */
function isAbsenceError(err: unknown): boolean {
  const code = (err as NodeJS.ErrnoException | undefined)?.code
  if (code === 'ELOOP' || code === 'ENAMETOOLONG') return false
  return isAbsenceErrno(err)
}

/**
 * Longer than the filesystem allows: no file can be there, for git to read or
 * for a command to create.
 */
function isUnusablePathError(err: unknown): boolean {
  return (err as NodeJS.ErrnoException | undefined)?.code === 'ENAMETOOLONG'
}

/**
 * How much of a `.git` file or a `commondir` is read: what git accepts for a
 * `.git` file. git has no bound for a `commondir`, so a larger one fails
 * closed.
 */
const MAX_GIT_METADATA_BYTES = 1024 * 1024

/** What a walk gets where the caller sets no deadline. */
const DEFAULT_SUBMODULE_WALK_TIMEOUT_MS = DEFAULT_RIPGREP_TIMEOUT_MS

/**
 * A walk looks at the clock once per this many entries or path components: one
 * directory, or one value, can hold as many as all the rest.
 */
const WALK_DEADLINE_CHECK_INTERVAL = 128

/**
 * Whether a directory holding `entries` is taken for a git directory.
 * Deliberately looser than git's `is_git_directory` (a valid HEAD plus objects/
 * and refs/), which only ever denies more: any one of these will do. git needs
 * `HEAD` and `objects`, and neither is a deny path, so a command can rename both
 * aside. `config`, `hooks` and `commondir` are what this file protects: from the
 * first wrap that saw the directory on, one that is there cannot be moved.
 *
 * Each counts as the kind of entry git reads there, so that `vendor/config/lib`
 * does not make a git directory of `vendor`. An entry of no known type counts.
 */
function looksLikeGitDir(entries: fs.Dirent[]): boolean {
  return entries.some(entry =>
    ['hooks', 'objects'].includes(entry.name)
      ? !entry.isFile()
      : ['HEAD', 'config', 'commondir'].includes(entry.name) &&
        !entry.isDirectory(),
  )
}

/**
 * Directories git and its helpers keep in a git directory, which is where a
 * repository is large. The `.git/modules` walk goes on past a git directory
 * ({@link walkModules}) and stays out of these but for one listing.
 */
const GIT_OWN_DIRECTORIES = new Set([
  'objects',
  'refs',
  'logs',
  'hooks',
  'info',
  'worktrees',
  'lfs',
  'rr-cache',
])

/**
 * What tells a submodule's git directory that has one of those names
 * (`vendor/lfs`) from git's own directory of that name. `logs/HEAD` and
 * `lfs/objects` rule the other markers out.
 */
const GIT_PROTECTED_ENTRIES = new Set(['config', 'hooks'])

/** The entries of a git directory that are denied and are files. */
const GIT_ENTRY_FILES = new Set(['config', 'commondir', 'config.worktree'])

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
 * A git metadata file, or a link, whose target cannot be worked out the way git
 * works it out. The wrap is refused: a deny list that misses the hooks and
 * config git reads is worse than no sandbox. The message names the file, since
 * a sandboxed command can write one and only a command run outside lifts it. On
 * Linux it becomes a `LinuxSandboxProfileError` with
 * `deny_git_metadata_unreadable`; on macOS it reaches the caller as itself.
 */
export class GitMetadataError extends Error {
  readonly code = 'git_metadata_unreadable' as const
  constructor(message: string) {
    super(message)
    this.name = 'GitMetadataError'
  }
}

/**
 * A walk ran out of the time it was given, so what it never reached would have
 * been left writable. On Linux it becomes a `LinuxSandboxProfileError` with
 * `deny_scan_failed`; on macOS it reaches the caller as itself.
 */
export class SubmoduleWalkBudgetError extends Error {
  readonly code = 'submodule_walk_budget_exhausted' as const
  constructor(message: string) {
    super(message)
    this.name = 'SubmoduleWalkBudgetError'
  }
}

/** One symlink a chain walk went through, and the directory holding it. */
interface ChainHop {
  /** The link's own path, as the walk reached it. */
  link: string
  /** The directory the link sits in. */
  holder: string
}

/** Where a chain walk landed, and what it went through; see
 *  {@link resolveChain}. */
interface ResolvedChain {
  landing: string
  /**
   * In the order the walk met them, each once: the first is the path the caller
   * asked about.
   */
  hops: ChainHop[]
  /**
   * False where the walk gave up past the kernel's hop limit, on a loop or a
   * chain too long: `landing` is then only where it stopped.
   */
  resolved: boolean
}

/**
 * A symlink a git directory is reached THROUGH: a further hop of a symlinked
 * entry, a symlinked directory on the way, or a component of the path a
 * `gitdir:` or a `commondir` names. The denies at the two ends of the chain
 * cover neither it nor the directory it sits in, and a command that retargets
 * it moves where the chain leads, for the host's git to follow.
 */
export interface GitChainHop {
  /**
   * Where the chain starts: a git directory ENTRY that is a symlink, or the
   * VALUE of a `gitdir:` or a `commondir`. Held alike; the warning differs.
   */
  kind: 'entry' | 'pointer'
  /**
   * `unresolvable` is a loop, or a chain past the kernel's limit. Nothing is
   * behind it to deny, and each link is a name that makes it reach a directory
   * as soon as a command puts one there. A backend that cannot hold such a link
   * refuses the command; for a chain that resolves it warns.
   */
  chain: 'resolved' | 'unresolvable'
  /** The git directory entry, or the metadata file, whose chain goes
   *  through it. */
  source: string
  /**
   * The link's own path: a deny path for the backend that matches the name a
   * rename or an unlink uses (macOS). A bind there would land on what the link
   * leads to, so Linux drops it (`withoutChainHopLinks`).
   */
  link: string
  /**
   * The directory holding the link, which Linux denies WHOLE to hold it.
   * Undefined where a whole deny covers the link already.
   */
  holder: string | undefined
}

/** Directories found under a `.git/modules`, and what could not be read. */
export interface SubmoduleScan {
  /**
   * Sorted. One reached through a symlink is here as the path it was reached
   * by, and one whose target is not there yet as the path that target folds to.
   */
  gitDirs: string[]
  /**
   * Directories the walk could not see through, denied whole: one it could not
   * list, or the deepest one reachable towards a target it could not look at.
   * Everything under one is read-only, so git writes there stop working.
   * Sorted, no duplicates.
   */
  unreadableDirs: string[]
  /**
   * Directories holding an entry that is a SYMLINK, denied whole for the link's
   * sake by the backend whose denies resolve: the target's deny does not stop a
   * command from putting a git directory of its own in the link's place.
   * Sorted, no duplicates.
   */
  linkedEntryDirs: string[]
  /** The hops between such an entry and what it lands on. */
  chainHops: GitChainHop[]
}

/**
 * What a git directory's tree is denied by, in the pieces a backend with a
 * ceiling on its mounts degrades it in (src/sandbox/linux-deny-collapse.ts).
 * Nothing here is collapsed.
 */
export interface GitDirTreeDenies {
  /** The git directory's own hooks, config and redirect files. */
  ownDenyPaths: string[]
  /** `<gitDir>/modules`, whether or not the walk found anything under it. */
  modulesDir: string
  /** One per submodule git directory under `modulesDir`, sorted by path. */
  submodules: Array<{ gitDir: string } & GitDirDenies>
  /** `<gitDir>/worktrees`, whether or not anything is under it. */
  worktreesDir: string
  /** One per linked worktree's git directory under `worktreesDir`, sorted by
   *  path; see {@link keptWorktrees}. */
  worktrees: Array<{ gitDir: string } & GitDirDenies>
  /** What neither walk could see through; see {@link SubmoduleScan}. */
  unreadableDirs: string[]
  /** Directories holding a symlinked entry; see {@link SubmoduleScan}. */
  linkedEntryDirs: string[]
  /** Every hop met anywhere in this tree. */
  chainHops: GitChainHop[]
}

/**
 * The files in a git directory that send git to another git directory or
 * config, and what must stand in for one that does not exist.
 *
 * Denying an absent path means mounting something at it, and git reads these
 * two: it refuses to run at all against a `commondir` it cannot read, which
 * both an empty file and a bound /dev/null are. Each placeholder is what git
 * concludes with the file absent: `.` is the git directory itself, and an empty
 * `config.worktree` is no worktree config.
 *
 * That is not invisible. The file's existence sets git's `different_commondir`,
 * so `git rev-parse --git-common-dir` prints an absolute path, and a script
 * that compares it with `--git-dir` takes an ordinary repository for a linked
 * worktree while the deny stands.
 *
 * The Linux backend writes them: `writeGitRedirectMountPoint`.
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
 * The paths in a git directory through which a write becomes code the host's
 * git runs: hooks/, config (core.fsmonitor, core.hooksPath and the like) unless
 * the caller allows config writes, and {@link GIT_REDIRECT_FILES}, each under
 * the condition of what it redirects. Path arithmetic alone, so that macOS can
 * hand it a glob. {@link gitDirDenies} is for a directory that is there.
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
 * The same for a linked worktree's git directory, `<git dir>/worktrees/<id>`,
 * reached from the repository that keeps it: the redirect files, and `gitdir`,
 * which names the checkout that `git worktree remove` deletes. Not `hooks` and
 * `config`, which git does not read here while a `commondir` stands.
 */
function worktreeGitDirDenyPaths(
  worktreeGitDir: string,
  allowGitConfig: boolean,
): string[] {
  return [
    ...GIT_REDIRECT_FILES.filter(
      file => file.deniedWithConfigAllowed || !allowGitConfig,
    ).map(file => path.join(worktreeGitDir, file.name)),
    path.join(worktreeGitDir, 'gitdir'),
  ]
}

/** What a git directory is denied by once its entries have been looked at. */
export interface GitDirDenies {
  /** The deny paths, in the order the backends emit them. */
  denyPaths: string[]
  /**
   * The ones that lead OUT of the git directory, which a backend that degrades
   * it to one read-only bind keeps.
   */
  escapingDenyPaths: string[]
  /**
   * The git directory itself where an entry of it is a symlink, else empty. See
   * {@link SubmoduleScan.linkedEntryDirs}.
   */
  linkedEntryDirs: string[]
  /**
   * The hops between a symlinked entry and what it leads to and, from {@link
   * gitFileDenies}, those in the path a pointer's value walks. Each hop's own
   * path is in `denyPaths` too.
   */
  chainHops: GitChainHop[]
}

/**
 * {@link gitDirDenyPaths} for a git directory that is there, with what an entry
 * that is a SYMLINK adds.
 *
 * Such an entry is two things: the target, where a write through it lands, and
 * the link, which a command can unlink to leave its own `hooks/` in its place.
 * A Linux bind lands on what the path resolves to and covers the first; a
 * Seatbelt filter matches the name an unlink uses and covers the second. So
 * both are named, and the git directory goes into `linkedEntryDirs` for Linux
 * to deny whole: `git status` and `log` go on working there, `git add` and `git
 * commit` fail read-only until the link is gone. Further links on the way are
 * held as {@link GitChainHop} says.
 *
 * An ordinary git directory costs one lstat per entry. `deadline` bounds the
 * walk of a chain ({@link resolveChain}). `entryPaths` is what is looked at,
 * for {@link worktreeGitDirDenyPaths}.
 */
export function gitDirDenies(
  gitDir: string,
  allowGitConfig: boolean,
  deadline: number = Date.now() + DEFAULT_SUBMODULE_WALK_TIMEOUT_MS,
  entryPaths: string[] = gitDirDenyPaths(gitDir, allowGitConfig),
): GitDirDenies {
  const denyPaths: string[] = []
  const escapingDenyPaths: string[] = []
  const chainHops: GitChainHop[] = []
  let denyWhole = false
  // Resolved on the first symlinked entry and not before: an ordinary git
  // directory must not pay a realpath for a question it never asks.
  let realGitDir: string | undefined
  const insideGitDir = (candidate: string): boolean => {
    realGitDir ??= realPathOrSelf(gitDir)
    return isAtOrUnder(candidate, realGitDir)
  }
  // The first hop IS the entry: its own path is a deny path already, and the
  // directory holding it is this git directory, denied whole below. The rest
  // lie between the two ends, and neither end holds them.
  const holdChain = (
    entryPath: string,
    hops: ChainHop[],
    chain: GitChainHop['chain'],
  ): void => {
    for (const hop of hops.slice(1)) {
      denyPaths.push(hop.link)
      // No bind of the git directory covers it, so a degrade must not drop it.
      if (!insideGitDir(hop.link)) escapingDenyPaths.push(hop.link)
      chainHops.push({
        kind: 'entry',
        chain,
        source: entryPath,
        link: hop.link,
        holder: insideGitDir(hop.holder) ? undefined : hop.holder,
      })
    }
  }
  for (const entryPath of entryPaths) {
    const entry = gitDirEntry(entryPath, deadline)
    switch (entry.kind) {
      case 'plain':
        denyPaths.push(entryPath)
        break
      case 'link':
        denyWhole = true
        // Both spellings: the Linux bind resolves the entry's own path to the
        // same place, while on macOS a filter matches where the write lands
        // and the target is the only one of the two that names it.
        denyPaths.push(entryPath, entry.target)
        if (!insideGitDir(entry.target)) {
          escapingDenyPaths.push(entry.target)
        }
        holdChain(entryPath, entry.hops, 'resolved')
        break
      case 'unreachable':
        // A loop, or a name no file can occupy: nothing is behind it to deny.
        // The whole deny holds the entry, and each link the walk went through
        // is held like any other hop: a directory put in its place makes the
        // chain reach one.
        denyWhole = true
        holdChain(entryPath, entry.hops, 'unresolvable')
        break
      case 'unknown':
        // There and not classifiable. Fail closed both ways: the entry's own
        // deny, kept through a degrade in case it is a link, and the whole deny
        // one would need.
        denyWhole = true
        denyPaths.push(entryPath)
        escapingDenyPaths.push(entryPath)
        holdChain(entryPath, entry.hops, 'resolved')
        break
    }
  }
  // Neither is a deny path: each git directory under one has precise denies of
  // its own. But remove one that is a link, put a directory where it was, and
  // every git directory this repository keeps there is one nothing denied. So
  // it is held as a chain hop is: by its own name, and by this git directory
  // denied whole.
  for (const name of ['modules', 'worktrees']) {
    const keptPath = path.join(gitDir, name)
    const kept = gitDirEntry(keptPath, deadline)
    switch (kept.kind) {
      case 'plain':
        break
      case 'link':
      case 'unknown':
        denyWhole = true
        denyPaths.push(keptPath)
        chainHops.push({
          kind: 'entry',
          chain: 'resolved',
          source: keptPath,
          link: keptPath,
          holder: undefined,
        })
        holdChain(keptPath, kept.hops, 'resolved')
        break
      case 'unreachable':
        denyWhole = true
        holdChain(keptPath, kept.hops, 'unresolvable')
        break
    }
  }
  return {
    denyPaths,
    escapingDenyPaths,
    linkedEntryDirs: denyWhole ? [gitDir] : [],
    chainHops,
  }
}

/** What an entry of a git directory turns out to be. */
type GitDirEntry =
  /** Not a symlink, or nothing at all: the deny it has always had. */
  | { kind: 'plain' }
  /** A symlink, resolved or dangling, leading to `target` through `hops`. */
  | { kind: 'link'; target: string; hops: ChainHop[] }
  /** A symlink that reaches nothing: a loop, or a name no file can occupy.
   *  `hops` is what the walk went through before it gave up. */
  | { kind: 'unreachable'; hops: ChainHop[] }
  /** There, and what it is could not be worked out; `hops` is as much of the
   *  chain as the walk read before it stopped. */
  | { kind: 'unknown'; hops: ChainHop[] }

function gitDirEntry(entryPath: string, deadline: number): GitDirEntry {
  let stats: fs.Stats
  try {
    stats = fs.lstatSync(entryPath)
  } catch (err) {
    // The shared classification: a loop or a name too long ABOVE the entry
    // reaches no file here, and leaves nothing to protect.
    if (isAbsenceErrno(err)) return { kind: 'plain' }
    logForDebugging(
      `[Sandbox] Could not tell whether ${entryPath} is a symlink (${err}); denying the git directory holding it whole, and the entry as it stands`,
      { level: 'warn' },
    )
    return { kind: 'unknown', hops: [] }
  }
  if (!stats.isSymbolicLink()) return { kind: 'plain' }
  // From the directory holding the entry, itself resolved first: a symlink
  // ABOVE the git directory is where this repository lives, not a hop.
  const chain = resolveChain(
    physicalPath(path.parse(entryPath).root, path.dirname(entryPath), deadline),
    path.basename(entryPath),
    deadline,
  )
  try {
    fs.statSync(entryPath)
  } catch (err) {
    const code = (err as NodeJS.ErrnoException | undefined)?.code
    if (code === 'ELOOP' || isUnusablePathError(err)) {
      return { kind: 'unreachable', hops: chain.hops }
    }
    if (!isAbsenceErrno(err)) {
      logForDebugging(
        `[Sandbox] Could not follow ${entryPath} (${err}); denying the git directory holding it whole, the entry as it stands, and the hops of its chain that could be read`,
        { level: 'warn' },
      )
      return { kind: 'unknown', hops: chain.hops }
    }
    // Dangling, which is no reason to pass over it: nothing is there yet and
    // a command can put a hooks directory there for the host's git to find,
    // so the deny goes where the link lands and blocks creating it.
  }
  return { kind: 'link', target: chain.landing, hops: chain.hops }
}

/**
 * What must stand in for `denyPath` where it does not exist, or undefined for a
 * path git does not read this way. By the basename, so that every spelling of
 * one path answers the same. See {@link GIT_REDIRECT_FILES}.
 */
export function gitRedirectPlaceholder(denyPath: string): string | undefined {
  const name = path.basename(denyPath)
  return GIT_REDIRECT_FILES.find(file => file.name === name)?.placeholder
}

/**
 * What a `.git` file, the `gitdir:` pointer of a linked worktree or submodule
 * checkout, is denied by: the file, the entries of the git directory it names
 * and, for a linked worktree, of the one its `commondir` names, and every
 * symlink the walk of either path went through. A `..` can land the kernel
 * elsewhere than where the path folds to, so both directories are denied
 * ({@link gitMetadataTargets}).
 *
 * What such a git directory keeps under its `modules` and `worktrees` is not
 * enumerated here: `gitDirs` names each one reached, for the caller to hand to
 * {@link gitDirTreeDenies}.
 *
 * Throws {@link GitMetadataError} where the pointer or the `commondir` names
 * something this cannot resolve the way git does, and {@link
 * SubmoduleWalkBudgetError} past `deadline`.
 */
export function gitFileDenies(
  gitFile: string,
  allowGitConfig: boolean,
  deadline: number = Date.now() + DEFAULT_SUBMODULE_WALK_TIMEOUT_MS,
): GitDirDenies & { gitDirs: string[] } {
  const gathered: GatheredDenies = {
    denyPaths: [gitFile],
    linkedEntryDirs: [],
    chainHops: [],
    gitDirs: [],
  }
  const denies = { ...gathered, escapingDenyPaths: [] }
  // Before the file is read, whatever it holds: a tree full of `.git` files is
  // as many reads of up to a megabyte as a command cared to leave names for.
  if (Date.now() > deadline) {
    throw new SubmoduleWalkBudgetError(
      `[Sandbox] The time given for working out what the .git files lead to ran out before ${gitFile} was read; refusing to sandbox on the ones read before it`,
    )
  }
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
        return denies
      case 'none':
        break
    }
    if (target === undefined) {
      return denies
    }
    const targets = gitMetadataTargets(path.dirname(gitFile), target, deadline)
    holdValueChain(gitFile, targets, gathered)
    const gitDirs = targets.gitDirs.map(gitDir => ({
      gitDir,
      kind: gitDirKind(gitDir),
    }))
    for (const { gitDir, kind } of gitDirs) {
      gatherTargetDenies(
        gitDir,
        kind,
        allowGitConfig,
        gitFile,
        gathered,
        deadline,
      )
    }

    // A linked worktree's git directory holds the path of the main one, whose
    // hooks and config its commits run. git reads it out of the directory it
    // opened, so each candidate above has its own.
    for (const { gitDir, kind } of gitDirs) {
      if (kind === 'git-dir') {
        gatherCommonDirDenies(gitDir, allowGitConfig, gathered, deadline)
      } else if (kind === 'unreadable') {
        // THREAT: one `chmod` by a command, which leaves the repository that
        // keeps this worktree as writable as it was, with nothing read here to
        // name it. WHERE the directory is names it as well.
        const worktrees = path.dirname(physicalDenyPath(gitDir, deadline))
        if (path.basename(worktrees) !== 'worktrees') continue
        const keeper = path.dirname(worktrees)
        gatherTargetDenies(
          keeper,
          gitDirKind(keeper),
          allowGitConfig,
          gitFile,
          gathered,
          deadline,
        )
      }
    }
  } catch (err) {
    // A dangling pointer names nothing git would read. A pointer this process
    // may not read is one the host's git, the same user's, cannot read either.
    // For those the file itself is the whole deny; an unreadable TARGET is
    // denied whole by gitDirTargetDenies instead.
    const code = (err as NodeJS.ErrnoException | undefined)?.code
    if (code === 'EACCES' || code === 'EPERM' || code === 'ELOOP') {
      logForDebugging(
        `[Sandbox] Could not read ${gitFile}, denying only the file itself: ${err}`,
        { level: 'warn' },
      )
    } else if (
      err instanceof GitMetadataError ||
      err instanceof SubmoduleWalkBudgetError
    ) {
      throw err
    } else if (!isAbsenceError(err)) {
      // No descriptor left, a disk that fails: git may well read it later.
      throw new GitMetadataError(
        `[Sandbox] ${gitFile} could not be read (${String(err)}); refusing to sandbox without the git directory it names`,
      )
    }
  }
  return denies
}

/** What following a `gitdir:` pointer or a `commondir` adds to, one target
 *  and one hop at a time. */
type GatheredDenies = Pick<
  GitDirDenies,
  'denyPaths' | 'linkedEntryDirs' | 'chainHops'
> & {
  /** The targets that are git directories. */
  gitDirs: string[]
}

/** The denies of one directory a `gitdir:` or a `commondir` names, added to
 *  `gathered`; see {@link gitDirTargetDenies}. */
function gatherTargetDenies(
  target: string,
  kind: GitDirKind,
  allowGitConfig: boolean,
  source: string,
  gathered: GatheredDenies,
  deadline: number,
): void {
  const denies = gitDirTargetDenies(
    target,
    kind,
    allowGitConfig,
    source,
    deadline,
  )
  gathered.denyPaths.push(...denies.denyPaths)
  gathered.linkedEntryDirs.push(...denies.linkedEntryDirs)
  gathered.chainHops.push(...denies.chainHops)
  if (kind === 'git-dir') gathered.gitDirs.push(target)
}

/**
 * The links the walk of a `gitdir:` or `commondir` value went through, added to
 * `gathered`. A value that reaches nothing names no git directory, and those
 * links are all a command can move. One warning says so: a `.git` file is
 * something a command may create, and refusing or denying the checkout whole
 * for it would lock the session out of its own project.
 */
function holdValueChain(
  source: string,
  targets: GitMetadataTargets,
  gathered: GatheredDenies,
): void {
  for (const hop of targets.hops) {
    gathered.denyPaths.push(hop.link)
    gathered.chainHops.push({
      kind: 'pointer',
      chain: targets.resolved ? 'resolved' : 'unresolvable',
      source,
      link: hop.link,
      holder: hop.holder,
    })
  }
  if (targets.resolved) return
  logForDebugging(
    `[Sandbox] The path ${source} names cannot be walked to an end (a symlink loop, or more than the ${MAX_SYMLINK_RESOLUTION_DEPTH} hops the kernel follows), so git opens nothing through it either; denying ${source} and the ${targets.hops.length} link(s) the walk did go through, and nothing besides`,
    { level: 'warn' },
  )
}

/**
 * What the `commondir` of `gitDir` leads to, added to `gathered`: the links its
 * value walks, and the denies of each directory it names that is not in
 * `heldAlready`. Throws {@link GitMetadataError} for one that is there and
 * whose target cannot be worked out: the directory whose hooks git runs is then
 * unknown.
 */
function gatherCommonDirDenies(
  gitDir: string,
  allowGitConfig: boolean,
  gathered: GatheredDenies,
  deadline: number,
  heldAlready: readonly string[] = [gitDir],
): void {
  const commonFile = path.join(gitDir, 'commondir')
  let common: GitMetadata
  try {
    common = readGitMetadataFile(commonFile)
  } catch (err) {
    if (isAbsenceError(err)) return
    // The file is there and could not be read, so the directory whose hooks
    // this worktree's commits run is unknown. Returning the denies gathered
    // so far would leave that repository's hooks writable.
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
      // git reads commondir whole, with no size limit of its own, so a file
      // past this bound still names the directory whose hooks git runs.
      throw new GitMetadataError(
        `[Sandbox] ${commonFile} is larger than ${MAX_GIT_METADATA_BYTES} bytes; refusing to sandbox without the git directory it names`,
      )
    case 'none':
      break
  }
  if (commonTarget === undefined) return
  const commonTargets = gitMetadataTargets(gitDir, commonTarget, deadline)
  holdValueChain(commonFile, commonTargets, gathered)
  for (const commonDir of commonTargets.gitDirs) {
    if (heldAlready.includes(commonDir)) continue
    gatherTargetDenies(
      commonDir,
      gitDirKind(commonDir),
      allowGitConfig,
      commonFile,
      gathered,
      deadline,
    )
  }
}

/**
 * Every git directory a deny must cover once `gitDir` is one: its own entries,
 * those of each submodule git directory under its `modules`, what redirects git
 * in each linked worktree's under its `worktrees`, and whatever the walks could
 * not see through. A submodule keeps linked worktrees and a linked worktree
 * keeps submodules, so the two walks call each other ({@link keptSubmodules},
 * {@link keptWorktrees}).
 *
 * `deadline` bounds the walks and the chains they meet. `visited` is for a
 * caller that enumerates several git directories and puts what comes back
 * together, so that what one of them keeps of another, or links to, is not
 * walked once for each ({@link isCutShort}).
 *
 * Kept in pieces so that a backend that cannot carry every mount can degrade
 * some; {@link gitDirTreeDenyPaths} is the flat form.
 */
export function gitDirTreeDenies(
  gitDir: string,
  allowGitConfig: boolean,
  options: { deadline?: number; visited?: Map<string, boolean> } = {},
): GitDirTreeDenies {
  const walk: TreeWalk = {
    allowGitConfig,
    deadline:
      options.deadline ?? Date.now() + DEFAULT_SUBMODULE_WALK_TIMEOUT_MS,
    root: gitDir,
    realRoot: realPathOrSelf(gitDir),
    visited: options.visited ?? new Map(),
    unreadableDirs: new Set(),
    linkedEntryDirs: new Set(),
    chainHops: [],
  }
  const submodules = keptSubmodules(gitDir, walk)
  const own = gitDirDenies(gitDir, allowGitConfig, walk.deadline)
  const worktrees = keptWorktrees(gitDir, walk)
  const all = [own, ...submodules, ...worktrees]
  return {
    ownDenyPaths: own.denyPaths,
    modulesDir: path.join(gitDir, 'modules'),
    submodules,
    worktreesDir: path.join(gitDir, 'worktrees'),
    worktrees,
    unreadableDirs: [...walk.unreadableDirs].sort(),
    linkedEntryDirs: [
      ...[...walk.linkedEntryDirs].sort(),
      ...all.flatMap(denies => denies.linkedEntryDirs),
    ],
    chainHops: [...walk.chainHops, ...all.flatMap(denies => denies.chainHops)],
  }
}

/** {@link gitDirTreeDenies} as one list, which is what a backend with no
 *  ceiling to stay under emits. */
export function gitDirTreeDenyPaths(denies: GitDirTreeDenies): string[] {
  const denyPaths = [
    ...denies.ownDenyPaths,
    ...denies.unreadableDirs,
    ...denies.submodules.flatMap(submodule => submodule.denyPaths),
    ...denies.worktrees.flatMap(worktree => worktree.denyPaths),
  ]
  // A hop of a `.git/modules` entry has no other list to sit in, and a hop of a
  // git directory's own entry is among its deny paths already.
  const named = new Set(denyPaths)
  for (const hop of denies.chainHops) {
    if (named.has(hop.link)) continue
    named.add(hop.link)
    denyPaths.push(hop.link)
  }
  return denyPaths
}

/** A git directory another one keeps, and what it is denied by. */
type KeptGitDir = { gitDir: string } & GitDirDenies

/**
 * `own`, the denies of `gitDir`, with those of the git directories it `keeps`
 * in turn: all under it, so that a bind of it stands in for them where the
 * profile is degraded. Except one reached through a link, which is somewhere
 * else, and what leads out of any of them.
 */
function withWhatItKeeps(
  gitDir: string,
  own: GitDirDenies,
  keeps: KeptGitDir[],
): KeptGitDir {
  const all = [own, ...keeps]
  const real = keeps.length > 0 ? realPathOrSelf(gitDir) : gitDir
  return {
    gitDir,
    denyPaths: all.flatMap(denies => denies.denyPaths),
    escapingDenyPaths: [
      ...own.escapingDenyPaths,
      ...keeps.flatMap(kept =>
        isAtOrUnder(realPathOrSelf(kept.gitDir), real)
          ? kept.escapingDenyPaths
          : kept.denyPaths,
      ),
    ],
    linkedEntryDirs: all.flatMap(denies => denies.linkedEntryDirs),
    chainHops: all.flatMap(denies => denies.chainHops),
  }
}

/**
 * The submodule git directories under the `modules` of `gitDir`, sorted by
 * path ({@link walkModules}), each with the linked worktrees it keeps:
 * `git worktree add` inside a submodule puts the worktree's git directory under
 * the SUBMODULE's.
 */
function keptSubmodules(gitDir: string, walk: TreeWalk): KeptGitDir[] {
  return walkModules(path.join(gitDir, 'modules'), walk).map(submodule =>
    withWhatItKeeps(
      submodule,
      gitDirDenies(submodule, walk.allowGitConfig, walk.deadline),
      keptWorktrees(submodule, walk),
    ),
  )
}

/**
 * The git directories of the linked worktrees `gitDir` keeps, one per entry of
 * its `worktrees`, sorted, and what each is denied by ({@link
 * worktreeGitDirDenyPaths}). With the submodules it keeps: their git
 * directories are under the WORKTREE's `modules`, while their checkouts can lie
 * outside everything the command may write.
 *
 * Every directory there is one, whatever it holds: git makes nothing else under
 * `worktrees`, and one a command emptied or made is one the host's git opens
 * all the same. An entry that is a symlink is followed and held ({@link
 * walkEntry}).
 *
 * Each one's `commondir` is followed as from a `.git` file. No bind of the
 * worktree's git directory covers what it names, so that is marked as leading
 * out.
 */
function keptWorktrees(gitDir: string, walk: TreeWalk): KeptGitDir[] {
  const { allowGitConfig, deadline } = walk
  const worktreesDir = path.join(gitDir, 'worktrees')
  if (isCutShort('worktrees', worktreesDir, walk)) return []
  const kept: KeptGitDir[] = []
  const entries = listDirectory(worktreesDir, walk) ?? []
  for (const [at, entry] of entries.entries()) {
    if (at % WALK_DEADLINE_CHECK_INTERVAL === 0 && Date.now() > deadline) {
      throw new SubmoduleWalkBudgetError(
        `[Sandbox] The walk of ${worktreesDir} ran out of the time it was given with ${entries.length - at} of its ${entries.length} entries still to look at; refusing to sandbox on the linked worktrees it did reach`,
      )
    }
    if (isNoText(entry, worktreesDir, walk)) continue
    const child = path.join(worktreesDir, entry.name)
    const found = walkEntry(entry, child, walk)
    if (found.kind === 'skip') continue
    // Where a link leads to nothing is denied as a git directory that is not
    // there yet, as the `.git/modules` walk denies one.
    const worktree = found.kind === 'dangling' ? found.landing : child
    if (found.kind === 'directory') {
      if (isCutShort('worktree', worktree, walk)) continue
      // git opens what is in there by name, which takes leave to search it and
      // none to list it. Without that leave git, the same user's, reads no
      // `commondir` either: denied whole, and nothing to refuse the command
      // over.
      try {
        fs.accessSync(worktree, fs.constants.X_OK)
      } catch (err) {
        denyUnreadable(worktree, err, walk)
        continue
      }
    }
    const own = gitDirDenies(
      worktree,
      allowGitConfig,
      deadline,
      worktreeGitDirDenyPaths(worktree, allowGitConfig),
    )
    const common: GatheredDenies = {
      denyPaths: [],
      linkedEntryDirs: [],
      chainHops: [],
      gitDirs: [],
    }
    gatherCommonDirDenies(worktree, allowGitConfig, common, deadline, [
      worktree,
      gitDir,
    ])
    kept.push(
      withWhatItKeeps(
        worktree,
        {
          denyPaths: [...own.denyPaths, ...common.denyPaths],
          escapingDenyPaths: [...own.escapingDenyPaths, ...common.denyPaths],
          linkedEntryDirs: [...own.linkedEntryDirs, ...common.linkedEntryDirs],
          chainHops: [...own.chainHops, ...common.chainHops],
        },
        keptSubmodules(worktree, walk),
      ),
    )
  }
  return kept.sort((a, b) => (a.gitDir < b.gitDir ? -1 : 1))
}

/**
 * {@link walkModules} by itself, with what it could not see through.
 */
export function submoduleGitDirs(
  modulesDir: string,
  deadline: number = Date.now() + DEFAULT_SUBMODULE_WALK_TIMEOUT_MS,
): SubmoduleScan {
  const walk: TreeWalk = {
    allowGitConfig: false,
    deadline,
    root: modulesDir,
    realRoot: realPathOrSelf(modulesDir),
    visited: new Map(),
    unreadableDirs: new Set(),
    linkedEntryDirs: new Set(),
    chainHops: [],
  }
  return {
    gitDirs: walkModules(modulesDir, walk),
    unreadableDirs: [...walk.unreadableDirs].sort(),
    linkedEntryDirs: [...walk.linkedEntryDirs].sort(),
    chainHops: walk.chainHops,
  }
}

/**
 * Git directories of the submodules under `modulesDir` (a `.git/modules`),
 * nested ones included, sorted. A submodule's name is its path, so one can sit
 * several levels down (modules/vendor/lib).
 *
 * A directory recorded as a git directory is walked on all the same. A segment
 * of a name (`vendor`) is a directory a command can write, and a walk that
 * stopped at what {@link looksLikeGitDir} would let one `HEAD` left there take
 * the denies off every submodule beneath it. That goes for its `modules` too:
 * where a git directory keeps its own submodules, and maybe the submodule
 * `vendor/modules`. Only {@link GIT_OWN_DIRECTORIES} are left at one listing.
 * `modulesDir` itself is never taken for a git directory.
 *
 * Nothing bounds how deep a tree may be, and the walk keeps its own stack. A
 * bind mount gives a directory a second real path, which the visited set cannot
 * see, so the deadline is what bounds the walk.
 */
function walkModules(modulesDir: string, walk: TreeWalk): string[] {
  if (isCutShort('names', modulesDir, walk)) return []
  const gitDirs = new Set<string>()
  // Where the walk still has to look. A directory that was listed carries its
  // entries, and `gitDir` says it was recorded as a git directory, so that some
  // of them may be git's own.
  const pending: Array<{
    dir: string
    entries?: fs.Dirent[]
    gitDir?: boolean
  }> = [{ dir: modulesDir }]
  let entriesSeen = 0
  for (let item = pending.pop(); item !== undefined; item = pending.pop()) {
    const entries = item.entries ?? listDirectory(item.dir, walk)
    if (entries === undefined) continue
    for (const entry of entries) {
      if (
        entriesSeen++ % WALK_DEADLINE_CHECK_INTERVAL === 0 &&
        Date.now() > walk.deadline
      ) {
        throw new SubmoduleWalkBudgetError(
          `[Sandbox] The walk of ${modulesDir} ran out of the time it was given while listing ${item.dir}, with ${pending.length} directories still to look at; refusing to sandbox on the submodule git directories it did reach`,
        )
      }
      if (isNoText(entry, item.dir, walk)) continue
      const child = path.join(item.dir, entry.name)
      let childEntries: fs.Dirent[] | undefined
      if (item.gitDir === true) {
        // Read as this git directory's entry by what denies it (gitDirDenies).
        // Followed here as well, what it leads to would be taken for a
        // submodule.
        if (entry.isSymbolicLink() && GIT_ENTRY_FILES.has(entry.name)) continue
        // git's own by its name: walked on only where one listing shows what a
        // submodule's git directory of that name has and git's own never does.
        // Listed before it is followed: that would deny whole a git directory
        // whose `objects` or `rr-cache` is a link to a shared store.
        if (
          GIT_OWN_DIRECTORIES.has(entry.name) &&
          (entry.isDirectory() || entry.isSymbolicLink())
        ) {
          if (isCutShort('own', child, walk)) continue
          childEntries = listDirectory(child, walk)
          if (
            childEntries?.some(e => GIT_PROTECTED_ENTRIES.has(e.name)) !== true
          ) {
            continue
          }
        }
      }
      // git accepts a symlinked entry under .git/modules, and
      // Dirent.isDirectory is false for one, so the link is followed — and
      // the real path recorded, since a link back up would otherwise loop.
      const found = walkEntry(entry, child, walk)
      if (found.kind === 'skip') continue
      if (found.kind === 'dangling') {
        // Where a link leads to nothing is denied as a git directory that is
        // not there yet, so a command cannot fill one in for the host's git
        // to find. Nothing is walked: there is nothing there to walk.
        gitDirs.add(found.landing)
        continue
      }
      // In the `modules` of a git directory every entry is a submodule's name,
      // as in `modulesDir`, whatever a command left beside them.
      const holdsNames = item.gitDir === true && entry.name === 'modules'
      // Before it is listed: how many links lead to it and how much it holds
      // are both a command's to choose.
      if (isCutShort(holdsNames ? 'names' : 'entry', child, walk)) continue
      childEntries ??= listDirectory(child, walk)
      if (childEntries === undefined) continue
      // `hooks` and `objects` are names there too, so neither makes a git
      // directory of it.
      const isGitDir = looksLikeGitDir(
        holdsNames
          ? childEntries.filter(e => e.name !== 'hooks' && e.name !== 'objects')
          : childEntries,
      )
      if (isGitDir) gitDirs.add(child)
      // Anything else is a segment of a submodule name (`vendor` of
      // `vendor/lib`) - and a directory that looks like a git directory can
      // be one as well, so what else it holds is looked at either way.
      pending.push({
        dir: child,
        entries: childEntries,
        gitDir: isGitDir && !holdsNames,
      })
    }
  }
  return [...gitDirs].sort()
}

/**
 * What the walks of one enumeration go by, and what they find beside the git
 * directories.
 */
interface TreeWalk {
  allowGitConfig: boolean
  deadline: number
  /** The directory that is enumerated, and where it really is. */
  root: string
  realRoot: string
  /** See {@link isCutShort}. */
  visited: Map<string, boolean>
  /**
   * As in {@link SubmoduleScan}. Sets: one unreadable entry and the next fold to
   * the same ancestor, and a repeated path is a mount the profile never pays
   * for but would otherwise be counted as one.
   *
   * INVARIANT: each of `unreadableDirs` is where the directory really is. The
   * name of a link is what holds the link, and no deny of what it leads to
   * ({@link GitChainHop.link}).
   */
  unreadableDirs: Set<string>
  linkedEntryDirs: Set<string>
  chainHops: GitChainHop[]
}

/**
 * Whether a walk stops short of `dir`, which it would read `as` an `entry` of a
 * walked directory (a git directory or a segment of a name, by what it holds),
 * as git's `own`, as the `names` of submodules, as a `worktrees` or as one
 * linked `worktree`: a walk has read it so before, by where `dir` really is.
 * That is what ends a link that leads back up, and what keeps many links to one
 * directory, or many `.git` files into one repository, from costing as many
 * walks of it. Such a link is held by its own name all the same ({@link
 * walkEntry}).
 *
 * INVARIANT: for a directory that is where its name says, with no link on the
 * way from the root, only a walk that came to it so stands in. A command can
 * link any directory into a `modules` or a `worktrees`, to have it visited from
 * there first and as something else. What really lies under a git directory is
 * walked from it all the same.
 */
function isCutShort(
  as: 'entry' | 'own' | 'names' | 'worktrees' | 'worktree',
  dir: string,
  walk: TreeWalk,
): boolean {
  const real = realPathOrSelf(dir)
  const key = `${as}:${real}`
  const isWhereItsNameSays =
    real === path.join(walk.realRoot, path.relative(walk.root, dir))
  const cameSoBefore = walk.visited.get(key)
  if (cameSoBefore === true) return true
  if (cameSoBefore === false && !isWhereItsNameSays) return true
  walk.visited.set(key, isWhereItsNameSays)
  return false
}

/** What one entry of a walked directory is worth looking into. */
type WalkEntry =
  /** A directory to walk, reached directly or through a symlink. */
  | { kind: 'directory' }
  /** A symlink whose target is not there: nothing to walk, and `landing` is
   *  where a command putting a git directory there would put it. */
  | { kind: 'dangling'; landing: string }
  /** Nothing to walk and nothing to deny. */
  | { kind: 'skip' }

/**
 * Whether the name of `entry`, of `dir`, may be bytes that are no text. The
 * string made of those names nothing, so no deny can be aimed at it, and `dir`
 * is denied whole.
 */
function isNoText(entry: fs.Dirent, dir: string, walk: TreeWalk): boolean {
  if (!entry.name.includes('\uFFFD')) return false
  walk.unreadableDirs.add(realPathOrSelf(dir))
  logForDebugging(
    `[Sandbox] An entry of ${dir} has a name that is not valid UTF-8, denying ${dir} whole`,
    { level: 'warn' },
  )
  return true
}

/** Entries of `dir`, or undefined when it is absent or (recorded) unreadable. */
function listDirectory(dir: string, walk: TreeWalk): fs.Dirent[] | undefined {
  try {
    return fs.readdirSync(dir, { withFileTypes: true })
  } catch (err) {
    // Absent is the common case: no submodules, or none nested in this one.
    if (!isAbsenceError(err)) denyUnreadable(dir, err, walk)
    return undefined
  }
}

function denyUnreadable(dir: string, err: unknown, walk: TreeWalk): void {
  const denied = realPathOrSelf(deepestReachableAncestor(dir) ?? dir)
  walk.unreadableDirs.add(denied)
  logForDebugging(
    `[Sandbox] Could not look into ${dir}, denying ${denied} whole: ${err}`,
    { level: 'warn' },
  )
}

/**
 * What `entry` is worth doing with, following a symlink to a directory. A link
 * that leads anywhere puts the directory HOLDING it on the whole-directory
 * denies ({@link SubmoduleScan.linkedEntryDirs}), and it and the further links
 * on the way are held hop by hop ({@link GitChainHop}). A command can plant one
 * and leave every submodule beside it read-only for the commands after it.
 */
function walkEntry(
  entry: fs.Dirent,
  entryPath: string,
  walk: TreeWalk,
): WalkEntry {
  if (entry.isDirectory()) return { kind: 'directory' }
  if (!entry.isSymbolicLink()) return { kind: 'skip' }
  const { deadline } = walk
  const holder = path.dirname(entryPath)
  let chain: ResolvedChain
  try {
    chain = resolveChain(
      physicalPath(path.parse(entryPath).root, holder, deadline),
      entry.name,
      deadline,
    )
  } catch (err) {
    if (!(err instanceof GitMetadataError)) throw err
    // Where it leads cannot be named, so a directory there cannot be denied,
    // nor what cannot be looked at.
    let behind: fs.Stats | undefined
    try {
      behind = fs.statSync(entryPath, { throwIfNoEntry: false })
    } catch {
      throw err
    }
    if (behind?.isDirectory() === true) throw err
    if (behind !== undefined) return { kind: 'skip' }
    // Nothing is there. A command can make such a link here, so it costs what
    // any link here does and not every command after it.
    walk.unreadableDirs.add(realPathOrSelf(holder))
    logForDebugging(
      `[Sandbox] ${entryPath} leads through a symlink whose target is not valid UTF-8, to nothing; denying ${holder} whole`,
      { level: 'warn' },
    )
    return { kind: 'skip' }
  }
  // The first hop is the entry, whose holder joins `linkedEntryDirs` below. The
  // rest lie between it and what it lands on, and that deny reaches neither
  // them nor the directories they sit in.
  const holdChain = (chainState: GitChainHop['chain']): void => {
    for (const hop of chain.hops) {
      walk.chainHops.push({
        kind: 'entry',
        chain: chainState,
        source: entryPath,
        link: hop.link,
        holder: isAtOrUnder(hop.holder, holder) ? undefined : hop.holder,
      })
    }
  }
  try {
    if (!fs.statSync(entryPath).isDirectory()) return { kind: 'skip' }
    walk.linkedEntryDirs.add(holder)
    holdChain('resolved')
    return { kind: 'directory' }
  } catch (err) {
    if (isAbsenceError(err)) {
      // Dangling. Nothing is there to walk, and a command can create it: what
      // the link lands on is denied as a git directory that is not there yet.
      walk.linkedEntryDirs.add(holder)
      holdChain('resolved')
      return { kind: 'dangling', landing: chain.landing }
    }
    if (isUnusablePathError(err)) return { kind: 'skip' }
    if ((err as NodeJS.ErrnoException).code === 'ELOOP') {
      // Nothing is behind it to deny, and no bind can be put at it. Denying the
      // directory that HOLDS it would let one link take every submodule beside
      // it read-only. The links it goes through are left alone too: putting a
      // directory at one is no shorter a way to a planted git directory under
      // a writable `.git/modules` than creating one outright.
      logForDebugging(
        `[Sandbox] ${entryPath} is a symlink loop, which leads to nothing to deny: ${err}`,
        { level: 'warn' },
      )
      return { kind: 'skip' }
    }
    // Something is there and could not be looked at. Failed closed on the
    // deepest directory reachable TOWARDS it, not on the one holding the link,
    // which is denied for the link's own sake.
    const denied = deepestReachableAncestor(chain.landing) ?? entryPath
    walk.unreadableDirs.add(denied)
    walk.linkedEntryDirs.add(holder)
    holdChain('resolved')
    logForDebugging(
      `[Sandbox] Could not follow ${entryPath}, denying ${denied} whole: ${err}`,
      { level: 'warn' },
    )
    return { kind: 'skip' }
  }
}

/**
 * What a directory a `gitdir:` or a `commondir` names is denied by. One that is
 * no git directory is left alone. An absent one is denied, so that a command
 * cannot create it and fill it with hooks.
 */
function gitDirTargetDenies(
  target: string,
  kind: GitDirKind,
  allowGitConfig: boolean,
  source: string,
  deadline: number,
): GitDirDenies {
  const only = (denyPaths: string[]): GitDirDenies => ({
    denyPaths,
    escapingDenyPaths: [],
    linkedEntryDirs: [],
    chainHops: [],
  })
  switch (kind) {
    case 'git-dir':
    case 'absent':
      return gitDirDenies(target, allowGitConfig, deadline)
    case 'unreadable': {
      const denied = deepestReachableAncestor(target) ?? target
      logForDebugging(
        `[Sandbox] Could not read ${target} named by ${source}, denying ${denied} whole`,
        { level: 'warn' },
      )
      return only([denied])
    }
    case 'unusable':
      logForDebugging(
        `[Sandbox] ${source} names ${target}, which is longer than the filesystem allows: no file can be there for git to read or for a command to create; denying only ${source}`,
        { level: 'warn' },
      )
      return only([])
    case 'other':
      logForDebugging(
        `[Sandbox] ${source} names ${target}, which is not a git directory; denying only ${source}`,
        { level: 'warn' },
      )
      return only([])
  }
}

/**
 * Whether `dir`, which a `gitdir:` or a `commondir` names, is a git directory:
 * by what it holds ({@link looksLikeGitDir}), or by where it is. WHERE a
 * directory is cannot be arranged by what a file says, so one that sits where
 * only git puts a git directory is one whatever it holds just now: see
 * {@link isGitOwnedLocation}.
 */
function gitDirKind(dir: string): GitDirKind {
  let entries: fs.Dirent[]
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true })
    // git opens what is in there by name, which takes leave to search it.
    fs.accessSync(dir, fs.constants.X_OK)
  } catch (err) {
    if (isUnusablePathError(err)) return 'unusable'
    return isAbsenceError(err) ? 'absent' : 'unreadable'
  }
  return looksLikeGitDir(entries) || isGitOwnedLocation(dir)
    ? 'git-dir'
    : 'other'
}

/**
 * Whether `dir` sits where git keeps a git directory of its own making:
 * `.git/worktrees/<id>`, or anywhere under a `.git/modules`, a linked
 * worktree's own included. Asked of the path the kernel lands on: a command can
 * make `x/.git` a symlink to any directory, and a value written through it has
 * this shape.
 */
function isGitOwnedLocation(dir: string): boolean {
  const parts = physicalDenyPath(dir).split('/')
  return parts.some((name, at) => {
    if (name !== '.git') return false
    let below = parts.slice(at + 1)
    if (below[0] === 'worktrees' && below.length >= 2) {
      if (below.length === 2) return true
      below = below.slice(2)
    }
    return below[0] === 'modules' && below.length >= 2
  })
}

/**
 * The contents of `file`, or what stopped this from reading it the way git
 * does. A command may create the path: a FIFO there would block every later
 * wrap, hence O_NONBLOCK and the type check.
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
 * The path a git metadata file names, by git's rules (`read_gitfile_gently`,
 * `get_common_dir_noenv`): `\n` and `\r` are stripped from the END OF THE FILE,
 * nothing else is trimmed, and what is left is a C string that ends at the
 * first NUL.
 *
 * Re-implemented instead of asking git: the library has to work without git,
 * and running git in a checkout the command can write is the hazard these
 * denies contain. test/sandbox/git-pointer-parity.test.ts keeps the two in
 * step.
 *
 * Throws {@link GitMetadataError} for bytes that are not valid UTF-8: a string
 * of them names another file than git opens.
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
  // git joins the empty string to the directory it reads the path from.
  if (nul === 0) return '.'
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

/** Where a `gitdir:` or `commondir` value leads, and what it goes through;
 *  see {@link gitMetadataTargets}. */
interface GitMetadataTargets {
  /** Empty where the walk reached no end: see {@link resolveChain}. */
  gitDirs: string[]
  /** Every symlink the walk of the value went through, in the order it met
   *  them. A link ABOVE the file holding the value is not one of them: the
   *  base is resolved before the walk starts, so a checkout reached through a
   *  symlink is where the repository lives rather than a hop of this chain. */
  hops: ChainHop[]
  /** {@link ResolvedChain.resolved} for the walk of the value. */
  resolved: boolean
}

/**
 * The git directories a `gitdir:` or `commondir` value read in `base` leads to:
 * the path as it folds on paper and, where a `..` in it could send the kernel
 * elsewhere, the directory the kernel reaches. git hands the joined string to
 * stat, so a symlink is followed before a later `..` applies, and it opens the
 * kernel's landing. Both are denied where they differ.
 *
 * A value whose walk reaches no end names NO git directory: git opens nothing
 * through it, and the deepest directory a fail-closed deny could reach is
 * usually the checkout. The links it went through come back as hops all the
 * same.
 */
function gitMetadataTargets(
  base: string,
  target: string,
  deadline: number,
): GitMetadataTargets {
  const lexical = path.resolve(base, target)
  const root = path.parse(lexical).root
  const chain = resolveChain(
    // An absolute value starts at the root and never looks at the base, so
    // resolving the base then is a walk that buys nothing.
    path.isAbsolute(target) ? root : physicalPath(root, base, deadline),
    target,
    deadline,
  )
  const hops = chain.hops
  const resolved = chain.resolved
  if (!resolved) return { gitDirs: [], hops, resolved }
  if (!target.split('/').includes('..')) {
    return { gitDirs: [lexical], hops, resolved }
  }
  // Both sides resolved the same way, so a base that merely spells itself
  // differently (a /var that is a symlink to /private/var) is no difference.
  return chain.landing === physicalPath(root, lexical, deadline)
    ? { gitDirs: [lexical], hops, resolved }
    : { gitDirs: [lexical, chain.landing], hops, resolved }
}

/**
 * Where the kernel lands walking `target` from `base`, and every symlink it
 * went through. `path.resolve` and `fs.realpathSync` fold `..` on paper, and a
 * walk also reaches a tail that does not exist yet. A component that cannot be
 * walked ends it, and the rest is taken as written.
 *
 * The hop limit bounds how many links are followed and nothing bounds how long
 * each is, so `deadline` does: past it this throws {@link
 * SubmoduleWalkBudgetError}. A link whose target is no text throws {@link
 * GitMetadataError}, as a value that is none does.
 */
function resolveChain(
  base: string,
  target: string,
  deadline: number,
): ResolvedChain {
  let current = path.isAbsolute(target) ? path.parse(target).root : base
  // What is still to be walked, last component first: a value can hold half a
  // million, and an array taken from at the front is copied each time.
  const pending = target.split('/').reverse()
  const hops: ChainHop[] = []
  const named = new Set<string>()
  let followed = 0
  let componentsSeen = 0
  for (let name = pending.pop(); name !== undefined; name = pending.pop()) {
    // On the first component as well as every so many after it: a tree full
    // of short chains is as many walks as a command cared to leave, and none
    // of them is long enough to come round to a later look.
    if (
      componentsSeen++ % WALK_DEADLINE_CHECK_INTERVAL === 0 &&
      Date.now() > deadline
    ) {
      throw new SubmoduleWalkBudgetError(
        `[Sandbox] The walk of ${abridged(target)} from ${base} ran out of the time it was given at ${current}, ${followed} symlinks in and with ${pending.length} path components still to go; refusing to sandbox on a path that was not walked to where it leads`,
      )
    }
    if (name === '' || name === '.') continue
    if (name === '..') {
      current = path.dirname(current)
      continue
    }
    const next = path.join(current, name)
    let link: string | undefined
    try {
      if (fs.lstatSync(next).isSymbolicLink()) link = linkTextOf(next)
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'EILSEQ') {
        throw new GitMetadataError(
          `[Sandbox] ${next} is a symlink whose target is not valid UTF-8; refusing to sandbox with a deny list that would name another path than the one it leads to`,
        )
      }
      return {
        landing: path.join(next, pending.reverse().join('/')),
        hops,
        resolved: true,
      }
    }
    if (link === undefined) {
      current = next
      continue
    }
    // Under the name the kernel reached it by, which is the one an unlink or a
    // rename uses. A loop arrives at the same link over and over: one hop.
    if (!named.has(next)) {
      named.add(next)
      hops.push({ link: next, holder: current })
    }
    // Past the kernel's own limit the chain reaches nothing, for git as for
    // this. The links it went THROUGH come back for the caller to hold.
    if (++followed > MAX_SYMLINK_RESOLUTION_DEPTH) {
      return { landing: next, hops, resolved: false }
    }
    // A link's own target is walked in its place, from the directory holding
    // it unless it is absolute.
    if (path.isAbsolute(link)) current = path.parse(link).root
    for (const part of link.split('/').reverse()) pending.push(part)
  }
  return { landing: current, hops, resolved: true }
}

/** {@link resolveChain} for a caller that wants only where the walk landed. */
function physicalPath(base: string, target: string, deadline: number): string {
  return resolveChain(base, target, deadline).landing
}

/** `value` cut to what a message can carry: a pointer's value is as long as
 *  its file, and the rest of it says nothing the start does not. */
function abridged(value: string, limit = 200): string {
  return value.length <= limit
    ? value
    : `${value.slice(0, limit)}… (${value.length - limit} more characters)`
}

/**
 * Where the kernel lands walking `denyPath` from the root: the spelling for a
 * backend whose filters are matched against the path an operation RESOLVED to
 * (`gitDiskDenyEntries` on macOS). `fs.realpathSync` throws on a path that is
 * not there, and an absent `hooks` is what these denies are for.
 */
export function physicalDenyPath(
  denyPath: string,
  deadline: number = Date.now() + DEFAULT_SUBMODULE_WALK_TIMEOUT_MS,
): string {
  return physicalPath(path.parse(denyPath).root, denyPath, deadline)
}

/**
 * The deepest ancestor of `target`, itself included, that this process can stat
 * as a directory. Denying it fails closed where what lies below cannot be
 * inspected. Symlinks are followed, so a link to an unlistable directory is
 * answered with the link's own path, which the Linux deny loop binds at its
 * target, not with the directory holding it.
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
