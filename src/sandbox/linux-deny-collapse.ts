import * as fs from 'fs'
import type { GitDirTreeDenies } from './mandatory-deny-paths.js'
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
  gitDirs: Array<{ gitDir: string; denyPaths: string[] }>
  /** Directories the walk could not see through: whole-directory denies. */
  unreadableDirs: string[]
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
  if (denies.submodules.length === 0 && denies.unreadableDirs.length === 0) {
    return undefined
  }
  return {
    modulesDir: denies.modulesDir,
    gitDirs: denies.submodules,
    unreadableDirs: denies.unreadableDirs,
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
 * same way. A `.git` pointer file's own deny is never one of them: it names a
 * file, and a file has nothing to collapse into.
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
      if (coveredByModules(submodule.gitDir)) {
        for (const denyPath of submodule.denyPaths) covered.add(denyPath)
        continue
      }
      if (!wholeGitDirs.has(submodule.gitDir)) continue
      for (const denyPath of submodule.denyPaths) covered.add(denyPath)
      wholeBinds.push(submodule.gitDir)
    }
    for (const unreadableDir of repository.unreadableDirs) {
      if (coveredByModules(unreadableDir)) covered.add(unreadableDir)
    }
  }
  return [
    ...plan.denyPaths.filter(denyPath => !covered.has(denyPath)),
    ...wholeBinds,
  ]
}

/**
 * `level` degraded far enough to give back `mountsOver` mounts, or undefined
 * where there is nothing left to degrade — which is where the profile is
 * refused with `too_many_arguments`.
 *
 * How much each step gives back is what the caller measures; the arithmetic
 * here only decides how many entries one step takes, so that a repository
 * with thousands of submodules is not rebuilt once per submodule. A
 * submodule git directory gives back one mount per deny path it loses, plus
 * the ancestor pin of the git directory itself, which the bind that replaces
 * them is.
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
      at => order[at]?.denyPaths.length ?? 0,
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

/** One line naming what `level` degraded, for the wrap's warning. */
export function describeCollapse(
  plan: SubmoduleDenyPlan,
  level: CollapseLevel,
): string {
  const order = collapsibleGitDirs(plan)
  const parts: string[] = []
  if (level.wholeGitDirs > 0) {
    const collapsed = order.slice(order.length - level.wholeGitDirs)
    const repositories = [
      ...new Set(collapsed.map(entry => entry.modulesDir)),
    ].join(', ')
    parts.push(
      `${level.wholeGitDirs} of the ${order.length} submodule git directories under ${repositories} are denied whole rather than by path, so git writes inside those submodules fail read-only`,
    )
  }
  if (level.wholeModulesDirs > 0) {
    const collapsed = plan.repositories
      .slice(plan.repositories.length - level.wholeModulesDirs)
      .map(repository => repository.modulesDir)
    parts.push(
      `${collapsed.join(', ')} ${collapsed.length === 1 ? 'is' : 'are'} denied whole, taking every submodule under ${collapsed.length === 1 ? 'it' : 'them'}`,
    )
  }
  return parts.join('; ')
}

/** Every submodule git directory the plan may degrade, in the order a
 *  collapse works back through: by repository as served, each repository's
 *  own sorted. */
function collapsibleGitDirs(plan: SubmoduleDenyPlan): Array<{
  modulesDir: string
  gitDir: string
  denyPaths: string[]
}> {
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
