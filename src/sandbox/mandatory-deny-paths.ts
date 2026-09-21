import * as fs from 'fs'
import * as path from 'path'
import { logForDebugging } from '../utils/debug.js'
import { DEFAULT_RIPGREP_TIMEOUT_MS } from '../utils/ripgrep.js'
import {
  isAbsenceErrno,
  isAtOrUnder,
  MAX_SYMLINK_RESOLUTION_DEPTH,
} from './sandbox-utils.js'

/**
 * The path is absent, as opposed to unreadable or otherwise unverifiable.
 * Narrower than the shared {@link isAbsenceErrno} by two codes: an absent
 * path is denied as one a command could still create, and a symlink loop is
 * not that — it is walked instead, so that the links the walk went through
 * before it gave up are held ({@link resolveChain}) — while ENAMETOOLONG has
 * its own answer in {@link isUnusablePathError}.
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

/** Time the `.git/modules` walk gets when the caller sets no deadline, and
 *  the walk of a symlink chain or a pointer's value likewise. */
const DEFAULT_SUBMODULE_WALK_TIMEOUT_MS = DEFAULT_RIPGREP_TIMEOUT_MS

/**
 * How often the walk looks at the clock: once per this many entries, rather
 * than once per directory, because one directory can hold as many entries as
 * the whole rest of the walk. {@link resolveChain} counts path components the
 * same way, for the same reason: one link's target, or one pointer's value,
 * can hold as many as every other path put together.
 */
const WALK_DEADLINE_CHECK_INTERVAL = 128

/**
 * Entries whose presence makes a directory a git directory. git needs HEAD
 * and objects; config and hooks are what this file protects, so a directory
 * holding either is treated as one even if HEAD has been moved aside.
 */
const GIT_DIR_MARKERS = new Set(['HEAD', 'config', 'hooks', 'objects'])

/**
 * Directories git itself keeps in a git directory: its objects, its refs and
 * their logs, its hooks and `info`, the administrative directories of linked
 * worktrees, and the stores git-lfs and rerere put beside them. The
 * `.git/modules` walk goes on past a git directory (see
 * {@link submoduleGitDirs}) and stays out of these: they are where a
 * repository is large, and git keeps no submodule's git directory in any of
 * them. `modules` is not one of them because it IS walked, as the place a git
 * directory keeps its own submodules.
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
 * What tells a submodule's git directory that only has one of those names
 * (`vendor/lfs`, `tools/hooks`) from git's own directory of that name: the
 * two entries this file protects. Every git directory git makes has a
 * `config`, and git puts neither name in a directory of its own, where
 * `logs/HEAD` and `lfs/objects` rule the other two markers out. A linked
 * worktree or a ref namespace that is itself NAMED one of the two is the
 * exception: what holds it is walked for it, which only ever denies more.
 */
const GIT_PROTECTED_ENTRIES = new Set(['config', 'hooks'])

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
 * git directories it never reached would have been left with writable hooks —
 * or the walk of a symlink chain or of the path a `.git` pointer names did,
 * which spends the same budget, so the git directory it never landed on would
 * have been. The Linux wrap turns this into a `LinuxSandboxProfileError`
 * carrying `deny_scan_failed`; on macOS it reaches the caller as itself.
 * Branch on `.code`, not on the message.
 */
export class SubmoduleWalkBudgetError extends Error {
  readonly code = 'submodule_walk_budget_exhausted' as const
  constructor(message: string) {
    super(message)
    this.name = 'SubmoduleWalkBudgetError'
  }
}

/**
 * One symlink a chain walk went through, and the directory holding it.
 *
 * A bind cannot be put on a link — mounting at its own path resolves it — so
 * the directory around it is the only handle the backend whose denies resolve
 * has on it, while the backend that matches the name an unlink or a rename
 * uses wants the link's own path. Both are here, so each backend can take
 * what it holds a link by.
 */
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
  /** In the order the walk met them and each named once: the first is the
   *  path the caller asked about, the rest are what lies between it and the
   *  landing. A loop meets the same link over and over; it is one hop. */
  hops: ChainHop[]
  /**
   * Whether the walk ran to the end of the path. False only where it gave up
   * past the kernel's own hop limit — a loop, or a chain longer than the
   * kernel follows — and `landing` is then just where it stopped, a path
   * nothing can be reached through while the chain stands.
   */
  resolved: boolean
}

/**
 * A symlink a git directory is reached THROUGH: a second hop of a symlinked
 * entry's own link, a symlinked directory component on the way, or a
 * component of the path a `gitdir:` pointer or a `commondir` names.
 *
 * Neither end of such a chain covers one. The entry's or the pointer file's
 * deny holds that end and the landing's deny holds the other, while a hop in
 * between sits in an ordinary directory of the work tree: a command that
 * retargets it, or renames it aside and puts its own directory there, moves
 * what the chain resolves to without touching either end, and the host's git
 * follows the chain afterwards.
 */
export interface GitChainHop {
  /**
   * Where the chain starts: a git directory ENTRY that is itself a symlink,
   * or the VALUE of a `gitdir:` pointer or a `commondir`, which git walks the
   * same way and a command redirects the same way. Held alike; the warning
   * that stands in where one cannot be held says which, because what closes
   * it differs.
   */
  kind: 'entry' | 'pointer'
  /**
   * Whether the chain this hop lies on reaches anything. `unresolvable` is a
   * loop, or a chain past the kernel's hop limit: nothing is behind it, both
   * ends of it are held by a deny that stands on nothing, and each link the
   * walk DID go through is a name that makes the chain reach a real directory
   * as soon as a command puts one in its place. A backend that cannot hold
   * such a link has nothing left to fall back on and refuses the command; one
   * whose chain resolves has the landing's own denies behind it and warns.
   */
  chain: 'resolved' | 'unresolvable'
  /** The git directory entry, or the metadata file, whose chain goes
   *  through it. */
  source: string
  /**
   * The link's own path, and a deny path of its own: that is what holds it
   * on the backend which matches the name a rename or an unlink uses. The
   * backend whose denies RESOLVE gets nothing from it — a bind at a link
   * lands on what the link leads to, which for a symlinked directory
   * component is a whole directory nothing asked to deny — and drops it: see
   * `linuxGitDirTreeDenyPaths` in src/sandbox/linux-sandbox-utils.ts.
   */
  link: string
  /**
   * The directory holding the link: what that backend has to deny WHOLE to
   * hold it, as it denies the entry's own git directory whole. Undefined
   * where such a deny already covers the link — a hop inside the git
   * directory, or inside the directory holding a `.git/modules` entry. Where
   * it is a write root or the working directory there is nothing to bind
   * over it; the Linux backend's own note says what happens then.
   */
  holder: string | undefined
}

/** Directories found under a `.git/modules`, and what could not be read. */
export interface SubmoduleScan {
  /**
   * The submodule git directories, sorted. An entry the walk followed through
   * a symlink is here as the path it was reached by; one whose target is not
   * there yet is here as the path that target folds to, which is what a deny
   * has to block a command from creating.
   */
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
  /**
   * Directories holding an entry the walk followed through a SYMLINK, denied
   * whole for the link's sake: the deny the target gets covers what a write
   * through the link reaches, and the link's own path takes no mount of its
   * own (putting one there means resolving it). A `.git/modules` is writable
   * inside the sandbox, so a command that leaves the link alone but puts its
   * own git directory in its place aims every pointer that named it at hooks
   * the deny never saw. Denying the directory that holds it is the only
   * handle on that, and it is a whole-directory deny like the above. Sorted
   * and without duplicates.
   */
  linkedEntryDirs: string[]
  /**
   * The hops BETWEEN an entry the walk followed through a symlink and what
   * it lands on. One inside the directory holding that entry names no holder
   * of its own: `linkedEntryDirs` denies that whole already. See
   * {@link GitChainHop}.
   */
  chainHops: GitChainHop[]
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
  submodules: Array<{ gitDir: string } & GitDirDenies>
  /** What the walk could not see through; see {@link SubmoduleScan}. */
  unreadableDirs: string[]
  /** Directories holding a symlinked entry; see {@link SubmoduleScan}. */
  linkedEntryDirs: string[]
  /** Every hop between a symlinked entry of this tree and what it leads to,
   *  the git directory's own entries, the walked `.git/modules` entries and
   *  the submodules' own alike. See {@link GitChainHop}. */
  chainHops: GitChainHop[]
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
 *
 * Path arithmetic alone, so that macOS can hand it a glob pattern in place of
 * a directory. {@link gitDirDenies} is what a caller holding a real directory
 * wants: the same paths, plus what an entry that is a symlink needs.
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
 * What a git directory is denied by once the entries it holds have been
 * looked at, and what of that a read-only bind of the git directory would not
 * cover.
 */
export interface GitDirDenies {
  /** The deny paths, in the order the backends emit them. */
  denyPaths: string[]
  /**
   * The ones that lead OUT of the git directory: what a symlinked entry
   * points at, and an entry this could not classify. A backend that degrades
   * a git directory to one read-only bind of it keeps these and drops the
   * rest, which that bind covers.
   */
  escapingDenyPaths: string[]
  /**
   * The git directory itself, where an entry of it is a symlink — empty for
   * an ordinary one. Only a backend whose denies RESOLVE has to carry it:
   * see {@link SubmoduleScan.linkedEntryDirs}, which is the same answer for
   * an entry of a `.git/modules`.
   */
  linkedEntryDirs: string[]
  /**
   * The hops between a symlinked entry of this git directory and what it
   * leads to — and, from {@link gitFileDenies}, the ones in the path a
   * pointer's value walks. Each hop's own path is in `denyPaths` already, and
   * in `escapingDenyPaths` where no bind of the git directory covers it; what
   * is here besides is the directory holding each, which is what the backend
   * whose denies resolve has to deny whole to hold the link. See
   * {@link GitChainHop}.
   */
  chainHops: GitChainHop[]
}

/**
 * {@link gitDirDenyPaths} for a git directory that is really there, with what
 * an entry which is itself a SYMLINK adds to it.
 *
 * A symlinked entry is two things, and one deny covers one of them: the
 * target, where a write through the link lands, and the link itself, which
 * sits inside a writable git directory where a command can unlink it and
 * leave its own `hooks/` in its place for the host's git to run. Which of the
 * two a deny path covers is the backend's: a Linux bind lands on what the
 * path resolves to (so the target is covered and the link's own path keeps
 * nothing), while a Seatbelt filter matches the path as an unlink or a rename
 * names it (so the link is covered and the target is not). Both are therefore
 * named — the entry and its target as deny paths, and the git directory in
 * `linkedEntryDirs` for the backend that needs the link held by the directory
 * around it. Denying a git directory whole leaves `git status`, `log` and
 * `diff` working in that repository, while `git add`, `git commit` and
 * anything else that writes the index or an object fail read-only until the
 * link is gone.
 *
 * A chain with more than one link in it is more than two things, and the hops
 * BETWEEN the entry and the landing are neither of them: the entry's deny
 * holds the entry, the landing's deny holds the landing, and a hop in an
 * ordinary directory of the work tree moves what the chain resolves to
 * without touching either end. Each hop's own path is therefore a deny path
 * as well, and `chainHops` carries the directory holding each for the backend
 * that needs one — see {@link GitChainHop}.
 *
 * `modules` is checked for being a link as well, though it is no deny path of
 * its own: see the comment at the end of this function.
 *
 * An ordinary git directory costs one lstat per entry and is denied by exactly
 * what it always was. `deadline` bounds the walk of the chain an entry that IS
 * a symlink leads into (see {@link resolveChain}); past it this throws
 * {@link SubmoduleWalkBudgetError}, as the `.git/modules` walk does.
 */
export function gitDirDenies(
  gitDir: string,
  allowGitConfig: boolean,
  deadline: number = Date.now() + DEFAULT_SUBMODULE_WALK_TIMEOUT_MS,
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
      // A deny path like any other, for the backend that holds a link by its
      // own name; the one that resolves its denies drops it again.
      denyPaths.push(hop.link)
      if (insideGitDir(hop.link)) {
        chainHops.push({
          kind: 'entry',
          chain,
          source: entryPath,
          link: hop.link,
          holder: undefined,
        })
        continue
      }
      // No bind of the git directory covers it, so a degrade must not drop it.
      escapingDenyPaths.push(hop.link)
      chainHops.push({
        kind: 'entry',
        chain,
        source: entryPath,
        link: hop.link,
        holder: insideGitDir(hop.holder) ? undefined : hop.holder,
      })
    }
  }
  for (const entryPath of gitDirDenyPaths(gitDir, allowGitConfig)) {
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
        // A loop, or a name no file can occupy: nothing is behind it to deny
        // and nothing a command can create through it WHILE IT REACHES
        // NOTHING. The entry's own link is held by the whole-directory deny,
        // and every link the walk went through before it gave up is held like
        // any other hop: each is a name a command can replace with a real
        // directory, which makes the chain reach one and the host's git read
        // what is put there.
        denyWhole = true
        holdChain(entryPath, entry.hops, 'unresolvable')
        break
      case 'unknown':
        // There and not classifiable. Fail closed both ways: the deny the
        // entry has anyway, kept through a degrade in case it is a link, and
        // the whole-directory deny one would need. The hops behind it that
        // COULD be read are held as a resolved chain's are; what lies past
        // the one that could not is what the whole deny stands in for.
        denyWhole = true
        denyPaths.push(entryPath)
        escapingDenyPaths.push(entryPath)
        holdChain(entryPath, entry.hops, 'resolved')
        break
    }
  }
  // `modules` is not one of the deny paths - denying it whole would take
  // every submodule git directory under it read-only, and each of those has
  // precise denies of its own - but it is an entry like the others in the one
  // respect that matters here: remove the link, put a directory of your own
  // where it was, and every submodule git directory this repository keeps is
  // one nothing denied. So it is held the way a chain hop is, and for the
  // same reason: its own name, which is what a rename or an unlink of a link
  // uses, and the directory holding it - this git directory - denied whole
  // for the backend whose denies resolve, where a bind at the link's own path
  // would land on the modules tree and take every submodule with it.
  const modulesPath = path.join(gitDir, 'modules')
  const modules = gitDirEntry(modulesPath, deadline)
  switch (modules.kind) {
    case 'plain':
      break
    case 'link':
    case 'unknown':
      denyWhole = true
      denyPaths.push(modulesPath)
      chainHops.push({
        kind: 'entry',
        chain: 'resolved',
        source: modulesPath,
        link: modulesPath,
        holder: undefined,
      })
      holdChain(modulesPath, modules.hops, 'resolved')
      break
    case 'unreachable':
      denyWhole = true
      holdChain(modulesPath, modules.hops, 'unresolvable')
      break
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
    // The shared classification rather than this file's narrower one: a
    // component above the entry that is a loop, or a name too long for the
    // filesystem, reaches no file here and leaves nothing to protect, while
    // the narrower one exists for a `gitdir:` target and answers a different
    // question. Anything else is a fact about the entry this cannot read.
    if (isAbsenceErrno(err)) return { kind: 'plain' }
    logForDebugging(
      `[Sandbox] Could not tell whether ${entryPath} is a symlink (${err}); denying the git directory holding it whole, and the entry as it stands`,
      { level: 'warn' },
    )
    return { kind: 'unknown', hops: [] }
  }
  if (!stats.isSymbolicLink()) return { kind: 'plain' }
  // Walked from the directory holding the entry, itself resolved first, so
  // that a symlink ABOVE the git directory - a /tmp, a home reached through a
  // link - counts as where this repository lives and not as a hop of this
  // chain. The landing is what walking the whole path from the root gives.
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
 * {@link gitMetadataTargets} — and every symlink the walk of the path went
 * through is denied as well, since a command that retargets one of those
 * moves the directory git opens without touching the file or the landing.
 *
 * Throws {@link GitMetadataError} when the pointer or the `commondir` names
 * something this cannot resolve the way git does; the wrap is then refused
 * rather than applied with a deny list that may not cover the directory git
 * uses. Throws {@link SubmoduleWalkBudgetError} where walking what they name
 * takes longer than the `.git/modules` walk is given by default.
 */
export function gitFileDenyPaths(
  gitFile: string,
  allowGitConfig: boolean,
): string[] {
  return gitFileDenies(gitFile, allowGitConfig).denyPaths
}

/**
 * {@link gitFileDenyPaths} with the whole-directory denies and the chain hops
 * kept apart, as {@link gitDirDenies} keeps them: a git directory a pointer
 * leads to is a git directory like any other, so an entry of it that is a
 * symlink needs the directory holding the link denied whole on the backend
 * whose denies resolve, and so does a link in the path the pointer's own
 * value walks. Nothing else is enumerated through a pointer — a target's own
 * `.git/modules` is not walked — so this is what it adds.
 *
 * `deadline` bounds the walk of the pointer's value and of the `commondir`'s,
 * each of which can run to the megabyte the file may hold, and of any chain
 * an entry of the git directories they lead to starts. Past it this throws
 * {@link SubmoduleWalkBudgetError}: a value not walked to its end names a git
 * directory this never found, so there is no list to hand back.
 */
export function gitFileDenies(
  gitFile: string,
  allowGitConfig: boolean,
  deadline: number = Date.now() + DEFAULT_SUBMODULE_WALK_TIMEOUT_MS,
): GitDirDenies {
  const denyPaths = [gitFile]
  const linkedEntryDirs: string[] = []
  const chainHops: GitChainHop[] = []
  const targetDenies = (
    target: string,
    kind: GitDirKind,
    source: string,
  ): void => {
    const denies = gitDirTargetDenies(
      target,
      kind,
      allowGitConfig,
      source,
      deadline,
    )
    denyPaths.push(...denies.denyPaths)
    linkedEntryDirs.push(...denies.linkedEntryDirs)
    chainHops.push(...denies.chainHops)
  }
  // A pointer's VALUE is a path git walks as the kernel does, so a symlink in
  // it is held as a symlinked entry is: the file naming it is denied and the
  // git directory it reaches is denied, while a command that retargets a link
  // between the two moves where git lands without touching either end.
  //
  // A value that reaches nothing names no git directory to deny, and the
  // links the walk did go through are the whole of what a command can move.
  // One warning says so, because a `.git` file is something a sandboxed
  // command may create: refusing every later command, or denying the
  // checkout whole for it, would make writing one a way to lock the session
  // out of its own project.
  const holdChain = (source: string, targets: GitMetadataTargets): void => {
    for (const hop of targets.hops) {
      denyPaths.push(hop.link)
      chainHops.push({
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
  // Looked at before the file is, whatever the file turns out to hold: a tree
  // full of `.git` files is as many reads of up to a megabyte as a command
  // cared to leave names for, and one that is no pointer starts no walk that
  // would look at the clock for it.
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
        return { denyPaths, escapingDenyPaths: [], linkedEntryDirs, chainHops }
      case 'none':
        break
    }
    if (target === undefined) {
      return { denyPaths, escapingDenyPaths: [], linkedEntryDirs, chainHops }
    }
    const targets = gitMetadataTargets(path.dirname(gitFile), target, deadline)
    holdChain(gitFile, targets)
    const gitDirs = targets.gitDirs.map(gitDir => ({
      gitDir,
      kind: gitDirKind(gitDir),
    }))
    for (const { gitDir, kind } of gitDirs) {
      targetDenies(gitDir, kind, gitFile)
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
      const commonTargets = gitMetadataTargets(gitDir, commonTarget, deadline)
      holdChain(commonFile, commonTargets)
      for (const commonDir of commonTargets.gitDirs) {
        if (commonDir === gitDir) continue
        targetDenies(commonDir, gitDirKind(commonDir), commonFile)
      }
    }
  } catch (err) {
    if (err instanceof GitMetadataError) throw err
    // Out of time is not a pointer that could not be followed: what it names
    // was not worked out, and the file alone is no deny for that.
    if (err instanceof SubmoduleWalkBudgetError) throw err
    // A dangling pointer names nothing git would read. A pointer this process
    // cannot read is one the host's git cannot read either, so the file
    // itself is the whole deny; an unreadable TARGET is denied whole by
    // gitDirTargetDenies instead.
    if (!isAbsenceError(err)) {
      logForDebugging(
        `[Sandbox] Could not follow ${gitFile}, denying only the file itself: ${err}`,
        { level: 'warn' },
      )
    }
  }
  return { denyPaths, escapingDenyPaths: [], linkedEntryDirs, chainHops }
}

/**
 * Every git directory a deny must cover once `gitDir` is one: its own hooks/
 * and config, and the same for each submodule git directory under its
 * `modules` (what a commit inside that submodule runs), plus whatever the
 * walk could not see through. `deadline` bounds the walk (see
 * {@link submoduleGitDirs}) and, out of the same budget, the chains the
 * entries of each git directory it found lead into (see {@link gitDirDenies}).
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
  const deadline =
    options.deadline ?? Date.now() + DEFAULT_SUBMODULE_WALK_TIMEOUT_MS
  const modules = submoduleGitDirs(modulesDir, deadline)
  const own = gitDirDenies(gitDir, allowGitConfig, deadline)
  const submodules = modules.gitDirs.map(submodule => ({
    gitDir: submodule,
    ...gitDirDenies(submodule, allowGitConfig, deadline),
  }))
  return {
    ownDenyPaths: own.denyPaths,
    modulesDir,
    submodules,
    unreadableDirs: modules.unreadableDirs,
    linkedEntryDirs: [
      ...own.linkedEntryDirs,
      ...modules.linkedEntryDirs,
      ...submodules.flatMap(submodule => submodule.linkedEntryDirs),
    ],
    chainHops: [
      ...own.chainHops,
      ...modules.chainHops,
      ...submodules.flatMap(submodule => submodule.chainHops),
    ],
  }
}

/** {@link gitDirTreeDenies} as one list, which is what a backend with no
 *  ceiling to stay under emits. */
export function gitDirTreeDenyPaths(denies: GitDirTreeDenies): string[] {
  const denyPaths = [
    ...denies.ownDenyPaths,
    ...denies.unreadableDirs,
    ...denies.submodules.flatMap(submodule => submodule.denyPaths),
  ]
  // A hop of an entry under `.git/modules` has no other list to sit in, while
  // a hop of a git directory's OWN entry is already in that directory's deny
  // paths: named once either way, since a duplicate literal buys a backend
  // nothing.
  const named = new Set(denyPaths)
  for (const hop of denies.chainHops) {
    if (named.has(hop.link)) continue
    named.add(hop.link)
    denyPaths.push(hop.link)
  }
  return denyPaths
}

/**
 * Git directories of the submodules under `modulesDir` (a repository's
 * .git/modules), nested submodules included, sorted. A submodule's name is
 * its path, so one can sit several levels down (modules/vendor/lib), hence
 * the walk.
 *
 * A directory recorded as a git directory is walked on all the same. What
 * makes it one is a name ({@link GIT_DIR_MARKERS}), and a segment of a
 * submodule's name (`vendor` of `vendor/lib`) is an ordinary directory a
 * sandboxed command can write: a walk that stopped at the first directory
 * which looks like a git directory would let one empty `HEAD` left in `vendor`
 * take the denies off every submodule beneath it for the commands that
 * follow. git refuses a submodule whose git directory would sit inside
 * another's, so in a tree git made there is nothing past a git directory to
 * find, and looking costs one listing of each directory in it. The ones where
 * a repository is large are not walked into beyond that listing: see
 * {@link GIT_OWN_DIRECTORIES}. `modulesDir` itself, and a git directory's own
 * `modules`, are never taken for a git directory whatever they hold.
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
  const walk: SubmoduleWalk = {
    gitDirs: [],
    unreadableDirs: new Set(),
    linkedEntryDirs: new Set(),
    chainHops: [],
  }
  // Where the walk still has to look, and where it has already been. A
  // directory listed to see whether it is a git directory carries its entries
  // with it, so that no directory is listed twice. The root counts as visited:
  // an entry linked straight back to it is then the same dead end as one
  // linked to any other directory already walked. `gitDir` says the directory
  // was recorded as a git directory, so that some of its entries may be git's
  // own.
  const pending: Array<{
    dir: string
    entries?: fs.Dirent[]
    gitDir?: boolean
  }> = [{ dir: modulesDir }]
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
      let childEntries: fs.Dirent[] | undefined
      if (item.gitDir === true) {
        // Queued when the git directory was recorded.
        if (entry.name === 'modules') continue
        // One of git's own directories by its name: walked on only where one
        // listing of it shows something this file protects, which is what a
        // submodule's git directory that has such a name shows and git's own
        // directory never does. Listed before the entry is followed: following
        // a symlink puts the directory holding it on the whole-directory
        // denies (see walkEntry), and a git directory whose `objects` or
        // `rr-cache` is a link to a shared store is an ordinary one.
        if (
          GIT_OWN_DIRECTORIES.has(entry.name) &&
          (entry.isDirectory() || entry.isSymbolicLink())
        ) {
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
      const found = walkEntry(entry, child, walk, deadline)
      if (found.kind === 'skip') continue
      if (found.kind === 'dangling') {
        // Where a link leads to nothing is denied as a git directory that is
        // not there yet, so a command cannot fill one in for the host's git
        // to find. Nothing is walked: there is nothing there to walk.
        if (!visited.has(found.landing)) {
          visited.add(found.landing)
          walk.gitDirs.push(found.landing)
        }
        continue
      }
      const visitKey = realPathOrSelf(child)
      if (visited.has(visitKey)) continue
      visited.add(visitKey)

      childEntries ??= listDirectory(child, walk)
      if (childEntries === undefined) continue
      const isGitDir = childEntries.some(e => GIT_DIR_MARKERS.has(e.name))
      if (isGitDir) {
        walk.gitDirs.push(child)
        // A git directory keeps its own submodules under `modules`.
        pending.push({ dir: path.join(child, 'modules') })
      }
      // Anything else is a segment of a submodule name (`vendor` of
      // `vendor/lib`) - and a directory that looks like a git directory can
      // be one as well, so what else it holds is looked at either way.
      pending.push({ dir: child, entries: childEntries, gitDir: isGitDir })
    }
  }
  return {
    gitDirs: walk.gitDirs.sort(),
    unreadableDirs: [...walk.unreadableDirs].sort(),
    linkedEntryDirs: [...walk.linkedEntryDirs].sort(),
    chainHops: walk.chainHops,
  }
}

/** What the walk has found so far. The deny paths a directory it could not
 *  see through produces are a set: one unreadable entry and the next fold to
 *  the same ancestor, and a repeated path is a mount the profile never pays
 *  for but would otherwise be counted as one. */
interface SubmoduleWalk {
  gitDirs: string[]
  unreadableDirs: Set<string>
  linkedEntryDirs: Set<string>
  chainHops: GitChainHop[]
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

/**
 * What `entry` is worth doing with, following a symlink to a directory.
 *
 * A link that leads anywhere at all also puts the directory HOLDING it on the
 * whole-directory denies: what a deny of the target covers is what a write
 * through the link reaches, while the link itself takes no mount of its own,
 * and a `.git/modules` is writable — see {@link SubmoduleScan.linkedEntryDirs}.
 * A command can plant such a link and leave every submodule beside it
 * read-only for the commands after it, which is the answer this makes to a
 * command that plants git directories too.
 *
 * A chain that goes through further links is held hop by hop as a git
 * directory's own entry is: see {@link GitChainHop}.
 */
function walkEntry(
  entry: fs.Dirent,
  entryPath: string,
  walk: SubmoduleWalk,
  deadline: number,
): WalkEntry {
  if (entry.isDirectory()) return { kind: 'directory' }
  if (!entry.isSymbolicLink()) return { kind: 'skip' }
  const holder = path.dirname(entryPath)
  const chain = resolveChain(
    physicalPath(path.parse(entryPath).root, holder, deadline),
    entry.name,
    deadline,
  )
  // The first hop is the entry, whose holder joins `linkedEntryDirs` below;
  // the rest lie between it and what it lands on, and that deny reaches
  // neither them nor the directories they sit in.
  const holdChain = (chainState: GitChainHop['chain']): void => {
    for (const hop of chain.hops.slice(1)) {
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
      // A link that resolves back to itself reaches no directory at all, so
      // there is nothing behind it to deny and nothing a command can put
      // there without replacing the link, which the next wrap's walk sees.
      // The link's own path cannot carry a read-only bind either: bubblewrap
      // resolves a mount destination, and resolving this one is what just
      // failed. Denying the directory that HOLDS it is the one answer that
      // would be worse than none - a single link a command can write would
      // take every submodule beside it read-only. The links the loop goes
      // THROUGH are left alone for a reason of their own: a `.git/modules` is
      // writable in the sandbox, so putting a directory at one of them to
      // make this entry reach it is no shorter a way to a planted submodule
      // git directory than creating one outright, which is the recorded limit
      // of scanning before a command rather than after it. A git directory's
      // own entries are the other case: there, the whole-directory deny holds
      // the entry and the hops are all that is left open.
      logForDebugging(
        `[Sandbox] ${entryPath} is a symlink loop, which leads to nothing to deny: ${err}`,
        { level: 'warn' },
      )
      return { kind: 'skip' }
    }
    // Something is there and could not be inspected. What is behind the link
    // is failed closed on the deepest directory that can be reached TOWARDS
    // IT, rather than on the directory holding the link, which would take
    // every submodule beside it over one entry; the link itself is a link
    // like any other, and its holder is denied for it.
    const denied =
      deepestReachableAncestor(linkTarget(entryPath) ?? entryPath) ?? entryPath
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
 * What a directory a `gitdir:` or `commondir` names is denied by. An existing
 * directory that is not a git directory is left alone: file content must not
 * be able to point the deny list at, say, a Rails `config/`. An absent one is
 * still denied, so the sandboxed command cannot create the target and fill it
 * with hooks before the host's git first uses it.
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
 * The git directories a `gitdir:` or `commondir` value read in `base` leads
 * to: the path as it folds on paper, which is the spelling these denies have
 * always used, and — when a `..` in it could send the kernel elsewhere — the
 * directory the kernel actually reaches. git hands the two strings to stat
 * joined and unnormalised, so a symlink is followed before a later `..`
 * applies and `a/link/../b` need not be `a/b`; run against real git, it opens
 * the kernel's landing and refuses when only the lexical one is a git
 * directory (test/sandbox/git-pointer-parity.test.ts pins that). Both are
 * denied when they differ: denying more than git follows costs one bind.
 *
 * A value whose walk reaches no end names NO git directory. git opens nothing
 * through it — it gives up on the same loop, and the lexical fold is not a
 * fallback it takes — while the deepest directory a fail-closed deny could
 * still reach towards it is usually the checkout itself, and denying that
 * whole would take the project read-only over a `.git` file a sandboxed
 * command is allowed to create. The links the walk did go through come back
 * as hops all the same: putting a directory in one of their places is what
 * makes such a chain reach anything at all.
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
 * Where the kernel lands walking `target` from `base`, symlinks followed as
 * it meets them, and every symlink it went through on the way.
 * `path.resolve` folds `..` lexically, and `fs.realpathSync` folds its
 * argument the same way before resolving it, so neither answers this; a walk
 * also reaches a tail that does not exist yet, which realpath cannot. A
 * component that cannot be walked — missing, unreadable, or a loop past the
 * hop limit — ends it, since the kernel cannot traverse one either and
 * nothing beyond it can redirect the path; the rest is taken as written and
 * classified by {@link gitDirTargetDenies} like any other target.
 *
 * The hops are what a caller protecting the landing still has to hold: each
 * one is a name a command able to write the directory around it can point
 * somewhere else, which moves the landing without touching either end.
 *
 * The hop limit bounds how many links are followed and nothing bounds how long
 * each is: a link's target runs to a filesystem's four thousand bytes and a
 * pointer's value to the megabyte its file may hold, every component of either
 * is an lstat, and a command can leave as many of them as it likes. `deadline`
 * is what bounds that, looked at as the components go by, and running out of
 * it throws {@link SubmoduleWalkBudgetError} as the `.git/modules` walk does:
 * a landing that was never reached is not one to work a deny out from.
 */
function resolveChain(
  base: string,
  target: string,
  deadline: number,
): ResolvedChain {
  let current = path.isAbsolute(target) ? path.parse(target).root : base
  let pending = target.split('/')
  const hops: ChainHop[] = []
  const named = new Set<string>()
  let followed = 0
  let componentsSeen = 0
  while (pending.length > 0) {
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
      return { landing: path.join(next, ...pending), hops, resolved: true }
    }
    if (link === undefined) {
      current = next
      continue
    }
    // `current` is where the walk really is, so the hop is recorded under
    // the name the kernel reached it by rather than the one it was spelled
    // from: that is the name an unlink or a rename of the link uses. A loop
    // arrives at the same link over and over and it is one name, so the hop
    // count is not what bounds the walk.
    if (!named.has(next)) {
      named.add(next)
      hops.push({ link: next, holder: current })
    }
    // Past the kernel's own limit the chain reaches nothing: git gives up on
    // it exactly as this does, so there is nothing behind it to protect and
    // the landing is only where the walk stopped. The links it went THROUGH
    // are a different matter and come back — each is a name a command able to
    // write the directory around it can point at a real directory, which
    // makes the chain reach one and every deny worked out for it wrong — so
    // the caller holds them and says so where it cannot.
    if (++followed > MAX_SYMLINK_RESOLUTION_DEPTH) {
      return { landing: next, hops, resolved: false }
    }
    // A link's own target is walked in its place, from the directory holding
    // it unless it is absolute.
    if (path.isAbsolute(link)) current = path.parse(link).root
    pending = [...link.split('/'), ...pending]
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
 * Where the kernel lands walking `denyPath` from the root: the spelling a
 * backend needs whose filters are matched against the path an operation
 * RESOLVED to rather than the one it was spelled from (macOS Seatbelt — see
 * `gitDiskDenyEntries` in src/sandbox/macos-sandbox-utils.ts). `denyPath`
 * itself where nothing on the way is a symlink, which is every path of an
 * ordinary repository.
 *
 * `fs.realpathSync` does not answer this: it throws on a path that is not
 * there, and an absent `hooks` or `config.worktree` is exactly what these
 * denies exist to stop a command from creating.
 *
 * Throws {@link SubmoduleWalkBudgetError} past `deadline`, which bounds the
 * walk as it bounds every other (see {@link resolveChain}).
 */
export function physicalDenyPath(
  denyPath: string,
  deadline: number = Date.now() + DEFAULT_SUBMODULE_WALK_TIMEOUT_MS,
): string {
  return physicalPath(path.parse(denyPath).root, denyPath, deadline)
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
