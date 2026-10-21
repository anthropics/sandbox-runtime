import { realPathOrSelf } from '../utils/real-path.js'
import type {
  GitDirDenies,
  GitDirTreeDenies,
  GitChainHop,
} from './mandatory-deny-paths.js'
import { isAtOrUnder } from './sandbox-utils.js'

/**
 * The git directories one repository keeps under its `.git/modules`, or its
 * `.git/worktrees`. Their deny paths are ones the plan's list carries, and
 * collapsing one drops them from wherever they came from: a checked-out
 * submodule's `.git` file names the same git directory as the walk does, in the
 * same strings.
 */
export interface RepositorySubmodules {
  modulesDir: string
  /** Sorted by path, which is the order a collapse works back through. */
  gitDirs: Array<{ gitDir: string } & GitDirDenies>
  /**
   * The whole-directory denies UNDER `modulesDir`: what the walk could not see
   * through, and the directories holding an entry that is a symlink. A bind of
   * `modulesDir` covers the ones really under it.
   */
  wholeDirDenies: string[]
  /**
   * Set where these are linked worktrees' git directories and `modulesDir` is a
   * `.git/worktrees`: degraded the same way, and named for what they are in the
   * wrap's warning.
   */
  linkedWorktrees?: true
}

/** What one wrap denies, and what of that can be degraded. */
export interface SubmoduleDenyPlan {
  /** Every deny path the wrap found, in the order it found them. */
  denyPaths: string[]
  /**
   * In the order they were served: the working directory's own repository
   * first, then the nested ones, sorted. See {@link degradableGitDirs}.
   */
  repositories: RepositorySubmodules[]
  /**
   * Every symlink a git directory is reached THROUGH. Which of the directories
   * holding one a wrap can bind depends on the write roots, so that is decided
   * there and nothing collapses them: `chainHopDenies` in
   * src/sandbox/linux-sandbox-utils.ts.
   */
  chainHops: GitChainHop[]
  /**
   * The entries of the git directory the working directory's own `.git` is or
   * names. Each is denied from the first wrap that saw the repository, so a
   * link found at one is the user's layout, where any other git directory may
   * be one an earlier command made.
   */
  ownEntries?: string[]
}

/**
 * How far the denies have been degraded, counted from the END of the order
 * above, so that two wraps of one tree degrade the same entries.
 */
export interface CollapseLevel {
  /** Submodule git directories denied whole, one read-only bind each. */
  wholeGitDirs: number
  /** `.git/modules` directories denied whole, taking what is under them. */
  wholeModulesDirs: number
}

/** Nothing degraded: every submodule keeps its precise denies. */
export const NO_COLLAPSE: CollapseLevel = {
  wholeGitDirs: 0,
  wholeModulesDirs: 0,
}

/**
 * What of one repository's denies can be degraded: its submodule git
 * directories, then its linked worktrees'. A collapse works back from the end,
 * so within a repository the worktrees' go first: a command in this working
 * directory has less use for another checkout's HEAD and index than for a
 * submodule's objects.
 *
 * Neither is here where nothing is under it. An absent `.git/modules` or
 * `.git/worktrees` is never denied: a mount point at one stops
 * `git submodule add`, or `git worktree add`, in that repository.
 */
export function degradableGitDirs(
  denies: GitDirTreeDenies,
): RepositorySubmodules[] {
  const wholeDirDenies = [...denies.unreadableDirs, ...denies.linkedEntryDirs]
  return [
    { modulesDir: denies.modulesDir, gitDirs: denies.submodules },
    {
      modulesDir: denies.worktreesDir,
      gitDirs: denies.worktrees,
      linkedWorktrees: true as const,
    },
  ]
    .map(kept => ({
      ...kept,
      // Under it only: a git directory denied whole for an entry of its OWN
      // holds `modules` rather than sitting under it.
      wholeDirDenies: wholeDirDenies.filter(denyPath =>
        isAtOrUnder(denyPath, kept.modulesDir),
      ),
    }))
    .filter(kept => kept.gitDirs.length > 0 || kept.wholeDirDenies.length > 0)
}

/**
 * The deny paths of `plan` at `level`. A degraded git directory's deny paths
 * are dropped from the list and one read-only bind of it is added; a
 * `.git/modules` denied whole takes everything under it the same way. Not
 * dropped: a `.git` file's own deny, and what the producer marked as leading
 * out of the git directory.
 */
export function collapsedDenyPaths(
  plan: SubmoduleDenyPlan,
  level: CollapseLevel,
): string[] {
  if (level.wholeGitDirs === 0 && level.wholeModulesDirs === 0) {
    return plan.denyPaths
  }
  const order = collapsibleGitDirs(plan)
  const wholeGitDirs = new Set(
    order.slice(order.length - level.wholeGitDirs).map(entry => entry.gitDir),
  )
  const wholeModulesDirs = new Set(
    plan.repositories
      .slice(plan.repositories.length - level.wholeModulesDirs)
      .map(repository => repository.modulesDir),
  )

  // Paths a bind above them now covers, and the binds. The binds go at the end,
  // which leaves the rest of the list as the wrap found it.
  const covered = new Set<string>()
  const wholeBinds: string[] = []
  for (const repository of plan.repositories) {
    const wholeModules = wholeModulesDirs.has(repository.modulesDir)
    // A bind of `modules` covers the paths that are really under it, and only
    // those: an entry the walk reached through a symlink can have its real
    // path anywhere, and it keeps the deny it already has.
    const coveredByModules = wholeModules
      ? underDirectory(repository.modulesDir)
      : () => false
    if (wholeModules) wholeBinds.push(repository.modulesDir)
    for (const submodule of repository.gitDirs) {
      const byModules = coveredByModules(submodule.gitDir)
      if (!byModules && !wholeGitDirs.has(submodule.gitDir)) continue
      const escaping = new Set(submodule.escapingDenyPaths)
      for (const denyPath of submodule.denyPaths) {
        if (!escaping.has(denyPath)) covered.add(denyPath)
      }
      if (!byModules) wholeBinds.push(submodule.gitDir)
    }
    for (const wholeDirDeny of repository.wholeDirDenies) {
      if (coveredByModules(wholeDirDeny)) covered.add(wholeDirDeny)
    }
  }
  // A git directory that is a deny path in its own right — one holding a
  // symlinked entry — is both dropped as covered and added back as the bind
  // that covers it, so the binds are added only where the list has lost them.
  const kept = plan.denyPaths.filter(denyPath => !covered.has(denyPath))
  const keptPaths = new Set(kept)
  return [...kept, ...wholeBinds.filter(bind => !keptPaths.has(bind))]
}

/**
 * `level` degraded far enough to give back `mountsOver` mounts, or undefined
 * where nothing is left to degrade, which is where the profile is refused with
 * `too_many_arguments`. What a step really gives back is the caller's to
 * measure. The arithmetic decides how many entries one step takes, so that a
 * repository with thousands of submodules is not rebuilt once for each. An entry
 * none of whose deny paths `takesAMount` (all outside the write allowlist) gives
 * nothing back, and the step goes on past it.
 */
export function collapseFurther(
  plan: SubmoduleDenyPlan,
  level: CollapseLevel,
  mountsOver: number,
  takesAMount: (denyPath: string) => boolean = () => true,
): CollapseLevel | undefined {
  const order = collapsibleGitDirs(plan)
  if (level.wholeGitDirs < order.length) {
    const taken = stepBack(
      order.length - level.wholeGitDirs,
      mountsOver,
      at => {
        const escaping = new Set(order[at]?.escapingDenyPaths)
        return (order[at]?.denyPaths ?? []).filter(
          denyPath => !escaping.has(denyPath) && takesAMount(denyPath),
        ).length
      },
    )
    return { ...level, wholeGitDirs: level.wholeGitDirs + taken }
  }
  if (level.wholeModulesDirs < plan.repositories.length) {
    const taken = stepBack(
      plan.repositories.length - level.wholeModulesDirs,
      mountsOver,
      // Each git directory under it is one bind by now, and the one bind of
      // `modules` replaces the lot.
      at =>
        Math.max(
          (plan.repositories[at]?.gitDirs ?? []).filter(kept =>
            takesAMount(kept.gitDir),
          ).length - 1,
          0,
        ),
    )
    return { ...level, wholeModulesDirs: level.wholeModulesDirs + taken }
  }
  return undefined
}

/**
 * The last level, which is where the caller goes once a step has given nothing
 * back.
 */
export function collapseEverything(plan: SubmoduleDenyPlan): CollapseLevel {
  return {
    wholeGitDirs: collapsibleGitDirs(plan).length,
    wholeModulesDirs: plan.repositories.length,
  }
}

/**
 * Where the caller's passes start: the level counting alone says a profile with
 * room for `mounts` cannot do without, since every deny path that `takesAMount`
 * (one inside the write allowlist) takes one of its own, and the ancestor pins
 * beneath each are more on top. Without it a repository with ten thousand
 * submodules is planned out in full before anything is degraded, which takes
 * minutes, and a wrapped command can make such a tree.
 *
 * It is not the answer, and the caller's measurement is: what it leaves out can
 * only mean more collapsing, and the one way it can ask for too much — a deny
 * path counted here that another deny turns out to cover — is a mount the
 * profile saves rather than one it needs.
 */
export function collapseFloor(
  plan: SubmoduleDenyPlan,
  mounts: number,
  takesAMount: (denyPath: string) => boolean,
): CollapseLevel {
  let level = NO_COLLAPSE
  let deniesBefore = Number.POSITIVE_INFINITY
  for (;;) {
    const denies = collapsedDenyPaths(plan, level).filter(takesAMount).length
    if (denies <= mounts) return level
    // A step that gave nothing back took entries that take no mount, and how
    // many more of those lie ahead is a command's to choose.
    if (denies >= deniesBefore) return collapseEverything(plan)
    deniesBefore = denies
    const degraded = collapseFurther(plan, level, denies - mounts, takesAMount)
    if (degraded === undefined) return level
    level = degraded
  }
}

/** How many entries before `from` it takes for `gives` to reach `mounts`, at
 *  least one: a step that degraded nothing would loop for ever. */
function stepBack(
  from: number,
  mounts: number,
  gives: (at: number) => number,
): number {
  let given = 0
  let taken = 0
  for (let at = from - 1; at >= 0 && given < mounts; at--) {
    given += gives(at)
    taken += 1
  }
  return Math.max(taken, 1)
}

/**
 * One line naming what `level` degraded, for the wrap's warning. Not what a
 * whole-directory deny of the plan's own covers already: a collapse of that
 * takes nothing away.
 */
export function describeCollapse(
  plan: SubmoduleDenyPlan,
  level: CollapseLevel,
): string {
  const order = collapsibleGitDirs(plan)
  const alreadyWhole = coveredByWholeDirDeny(plan)
  const parts: string[] = []
  // Submodules and linked worktrees are degraded by the same steps and lose
  // different things to them, so each is told in its own words.
  for (const linkedWorktrees of [false, true]) {
    const ofKind = (entry: { linkedWorktrees?: true }): boolean =>
      (entry.linkedWorktrees === true) === linkedWorktrees
    if (level.wholeGitDirs > 0) {
      const collapsed = order
        .slice(order.length - level.wholeGitDirs)
        .filter(entry => ofKind(entry) && !alreadyWhole(entry.gitDir))
      if (collapsed.length > 0) {
        const repositories = [
          ...new Set(collapsed.map(entry => entry.modulesDir)),
        ].join(', ')
        const total = order.filter(ofKind).length
        parts.push(
          linkedWorktrees
            ? `${collapsed.length} of the ${total} linked worktree git directories under ${repositories} are denied whole rather than by path, so git writes into those worktrees' own HEAD, index and logs fail read-only`
            : `${collapsed.length} of the ${total} submodule git directories under ${repositories} are denied whole rather than by path, so git writes inside those submodules fail read-only`,
        )
      }
    }
    if (level.wholeModulesDirs > 0) {
      const collapsed = plan.repositories
        .slice(plan.repositories.length - level.wholeModulesDirs)
        .filter(ofKind)
        .map(repository => repository.modulesDir)
        .filter(modulesDir => !alreadyWhole(modulesDir))
      if (collapsed.length > 0) {
        const taken = linkedWorktrees
          ? `every linked worktree's git directory under ${collapsed.length === 1 ? 'it' : 'them'}, and \`git worktree add\` with ${collapsed.length === 1 ? 'it' : 'them'}`
          : `every submodule under ${collapsed.length === 1 ? 'it' : 'them'}`
        parts.push(
          `${collapsed.join(', ')} ${collapsed.length === 1 ? 'is' : 'are'} denied whole, taking ${taken}`,
        )
      }
    }
  }
  return parts.join('; ')
}

/** Whether a path is read-only whole in this plan whatever it degrades: a
 *  directory the walk could not see through, or one holding an entry that is
 *  a symlink, covers everything really under it. */
function coveredByWholeDirDeny(
  plan: SubmoduleDenyPlan,
): (candidate: string) => boolean {
  const covers = plan.repositories
    .flatMap(repository => repository.wholeDirDenies)
    .map(realPathOrSelf)
  if (covers.length === 0) return () => false
  // Resolved once, not once for each of them: both are a command's to multiply.
  return candidate => {
    const real = realPathOrSelf(candidate)
    return covers.some(cover => isAtOrUnder(real, cover))
  }
}

/** Every submodule git directory the plan may degrade, in the order a
 *  collapse works back through: by repository as served, each repository's
 *  own sorted. */
function collapsibleGitDirs(
  plan: SubmoduleDenyPlan,
): Array<
  { modulesDir: string; linkedWorktrees?: true; gitDir: string } & GitDirDenies
> {
  return plan.repositories.flatMap(repository =>
    repository.gitDirs.map(submodule => ({
      modulesDir: repository.modulesDir,
      linkedWorktrees: repository.linkedWorktrees,
      ...submodule,
    })),
  )
}

/** Whether a path really lies under `dir`, both sides resolved: what a
 *  read-only bind of `dir` actually covers. */
function underDirectory(dir: string): (candidate: string) => boolean {
  const real = realPathOrSelf(dir)
  return candidate => isAtOrUnder(realPathOrSelf(candidate), real)
}
