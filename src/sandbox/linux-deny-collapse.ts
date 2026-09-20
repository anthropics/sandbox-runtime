import * as fs from 'fs'
import type {
  GitDirDenies,
  GitDirTreeDenies,
  GitEntryChainHop,
} from './mandatory-deny-paths.js'
import { isAtOrUnder } from './sandbox-utils.js'

/**
 * The submodule git directories of one repository, and the `.git/modules`
 * directory they live under. Built from {@link GitDirTreeDenies}; the deny
 * paths are the ones the plan's list already carries, so collapsing one of
 * these drops them from wherever they came from — a checked-out submodule's
 * `.git` pointer names the same git directory as the walk does, and the
 * pointer's copy of its denies is the same string.
 */
export interface RepositorySubmodules {
  modulesDir: string
  /** Sorted by path, which is the order a collapse works back through. */
  gitDirs: Array<{ gitDir: string } & GitDirDenies>
  /**
   * The whole-directory denies UNDER `modulesDir`: what the walk could not
   * see through, and the directories holding an entry it followed through a
   * symlink. A bind of `modules` covers the ones really under it. The git
   * directory's own whole-deny is not one of these: it holds `modules`
   * rather than sitting under it, and it is no reason to degrade anything.
   */
  wholeDirDenies: string[]
}

/** What one wrap denies, and what of that can be degraded. */
export interface SubmoduleDenyPlan {
  /** Every deny path the wrap found, in the order it found them. */
  denyPaths: string[]
  /**
   * One per repository whose `.git/modules` the wrap walked and found
   * something under, in the order they were served: the working directory's
   * own repository first, then the nested ones the scan found, sorted. A
   * repository with nothing under its `modules` is not here at all, so an
   * absent one is never denied and never costs anything.
   */
  repositories: RepositorySubmodules[]
  /**
   * Every symlink BETWEEN a git directory entry and what it leads to that the
   * wrap found, in the order it found them. What this backend takes from one
   * is the directory holding it, the only thing a bind can hold a link by;
   * the link's own path is a deny path for the backend that holds a link by
   * its name and is dropped here. Which holders a wrap can actually bind
   * depends on where the write roots are, so it is decided there rather than
   * here and nothing collapses them: see `chainHopDenies` and
   * `withoutChainHopLinks` in src/sandbox/linux-sandbox-utils.ts.
   */
  chainHops: GitEntryChainHop[]
}

/**
 * How far the submodule denies have been degraded, counted from the END of
 * the order above, so that the repositories served first keep their precise
 * denies longest and two wraps of one tree degrade the same entries.
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

/** The submodule denies of one repository, or undefined where it has none. */
export function repositorySubmodules(
  denies: GitDirTreeDenies,
): RepositorySubmodules | undefined {
  // Under `modules` only: a git directory denied whole because one of its OWN
  // entries is a symlink is not a submodule deny, and a repository with
  // nothing under `modules` must stay out of the plan altogether — an absent
  // `.git/modules` is never denied, since a mount point planted at one stops
  // `git submodule add` working in that repository.
  const wholeDirDenies = [
    ...denies.unreadableDirs,
    ...denies.linkedEntryDirs,
  ].filter(denyPath => isAtOrUnder(denyPath, denies.modulesDir))
  if (denies.submodules.length === 0 && wholeDirDenies.length === 0) {
    return undefined
  }
  return {
    modulesDir: denies.modulesDir,
    gitDirs: denies.submodules,
    wholeDirDenies,
  }
}

/**
 * The deny paths of `plan` at `level`. The wrap and the violation monitor
 * both go through this, so what the monitor judges a refused write against is
 * what the wrap enforced at the level it passes.
 *
 * A degraded submodule git directory's own deny paths are dropped from the
 * list wherever they sit and one read-only bind of the git directory is added
 * in their place; a `.git/modules` denied whole takes everything under it the
 * same way. Two kinds of deny paths are NOT dropped: a `.git` pointer file's
 * own, which names a file and has nothing to collapse into, and the ones the
 * producer marked as leading out of the git directory — what an entry that is
 * a symlink points at, which no bind of the directory holding the link
 * covers.
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

  // Paths a bind above them now covers, and the binds that cover them. The
  // binds go at the end: the deny loop's passes are order-independent, so
  // where a path sits in the list is nothing to preserve, while leaving the
  // rest of the list alone is what makes a level that degrades nothing
  // exactly the list the wrap found.
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
 * where there is nothing left to degrade — which is where the profile is
 * refused with `too_many_arguments`.
 *
 * How much each step gives back is what the caller measures; the arithmetic
 * here only decides how many entries one step takes, so that a repository
 * with thousands of submodules is not rebuilt once per submodule. A
 * submodule git directory gives back one mount per deny path the bind that
 * replaces them covers — a deny leading out of it is kept and gives back
 * nothing — plus the ancestor pin of the git directory itself, which that
 * bind is.
 */
export function collapseFurther(
  plan: SubmoduleDenyPlan,
  level: CollapseLevel,
  mountsOver: number,
): CollapseLevel | undefined {
  const order = collapsibleGitDirs(plan)
  if (level.wholeGitDirs < order.length) {
    const taken = stepBack(
      order.length - level.wholeGitDirs,
      mountsOver,
      at => {
        const submodule = order[at]
        if (submodule === undefined) return 0
        return submodule.denyPaths.length - submodule.escapingDenyPaths.length
      },
    )
    return { ...level, wholeGitDirs: level.wholeGitDirs + taken }
  }
  if (level.wholeModulesDirs < plan.repositories.length) {
    const taken = stepBack(
      plan.repositories.length - level.wholeModulesDirs,
      mountsOver,
      // Each submodule under it is one bind by now, and the one bind of
      // `modules` replaces the lot.
      at => (plan.repositories[at]?.gitDirs.length ?? 1) - 1,
    )
    return { ...level, wholeModulesDirs: level.wholeModulesDirs + taken }
  }
  return undefined
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
 * One line naming what `level` degraded, for the wrap's warning.
 *
 * What a whole-directory deny of the plan's own already covers is left out of
 * it: a submodule under a `.git/modules` denied whole for an entry that is a
 * symlink is read-only whole before anything is degraded, so its precise
 * denies were never what held it and a collapse of it takes nothing away.
 * Saying otherwise names a cost the profile did not pay here.
 */
export function describeCollapse(
  plan: SubmoduleDenyPlan,
  level: CollapseLevel,
): string {
  const order = collapsibleGitDirs(plan)
  const alreadyWhole = coveredByWholeDirDeny(plan)
  const parts: string[] = []
  if (level.wholeGitDirs > 0) {
    const collapsed = order
      .slice(order.length - level.wholeGitDirs)
      .filter(entry => !alreadyWhole(entry.gitDir))
    if (collapsed.length > 0) {
      const repositories = [
        ...new Set(collapsed.map(entry => entry.modulesDir)),
      ].join(', ')
      parts.push(
        `${collapsed.length} of the ${order.length} submodule git directories under ${repositories} are denied whole rather than by path, so git writes inside those submodules fail read-only`,
      )
    }
  }
  if (level.wholeModulesDirs > 0) {
    const collapsed = plan.repositories
      .slice(plan.repositories.length - level.wholeModulesDirs)
      .map(repository => repository.modulesDir)
      .filter(modulesDir => !alreadyWhole(modulesDir))
    if (collapsed.length > 0) {
      parts.push(
        `${collapsed.join(', ')} ${collapsed.length === 1 ? 'is' : 'are'} denied whole, taking every submodule under ${collapsed.length === 1 ? 'it' : 'them'}`,
      )
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
    .map(underDirectory)
  if (covers.length === 0) return () => false
  return candidate => covers.some(under => under(candidate))
}

/** Every submodule git directory the plan may degrade, in the order a
 *  collapse works back through: by repository as served, each repository's
 *  own sorted. */
function collapsibleGitDirs(
  plan: SubmoduleDenyPlan,
): Array<{ modulesDir: string; gitDir: string } & GitDirDenies> {
  return plan.repositories.flatMap(repository =>
    repository.gitDirs.map(submodule => ({
      modulesDir: repository.modulesDir,
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

/** `target` with symlinks resolved, or itself when that fails - which leaves
 *  a path that cannot be resolved outside the bind, and so denied as it was. */
function realPathOrSelf(target: string): string {
  try {
    return fs.realpathSync(target)
  } catch {
    return target
  }
}
