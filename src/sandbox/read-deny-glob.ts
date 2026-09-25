import { logForDebugging } from '../utils/debug.js'
import {
  type GlobWalkBudget,
  isAtOrUnder,
  normalizePathForSandbox,
  pathSpellings,
  properAncestors,
  walkGlobPattern,
} from './sandbox-utils.js'

/**
 * A read-deny glob still needing more than this many mounts after collapsing
 * is logged at warn level (SRT_DEBUG) as a hint that the pattern is broad.
 * The expansion is never truncated, which would silently un-deny paths.
 */
const READ_DENY_GLOB_MOUNT_WARN_THRESHOLD = 256

/** The directory holding `p`, or '' for a root child. */
function parentOf(p: string): string {
  return p.slice(0, p.lastIndexOf('/'))
}

/**
 * Reduce the places a read-deny glob's matches really live to the ones whose
 * mount changes what the sandbox can read. A location is dropped only when a
 * kept proper ancestor's tmpfs already hides it and no re-exposer sits at the
 * ancestor or between the two.
 */
function collapseReadDenyLocations({
  locations,
  reExposedPaths,
}: {
  /** Absolute, symlink-free, trailing-slash-free paths. */
  locations: Iterable<string>
  /** allowRead/allowWrite paths the denyRead loop binds back over a tmpfs, as
   *  spelled and as resolved. */
  reExposedPaths: ReadonlySet<string>
}): Set<string> {
  // A proper ancestor is a proper string prefix, so lexicographic order
  // visits every ancestor before its descendants.
  const sorted = [...new Set(locations)].sort()
  const kept = new Set<string>()
  for (const location of sorted) {
    let reExposedBetween = reExposedPaths.has(location)
    let hidden = false
    for (const ancestor of properAncestors(location)) {
      // A re-exposer at the kept ancestor counts: the deny loop binds it back
      // over the tmpfs, so everything beneath needs its own mount.
      if (reExposedPaths.has(ancestor)) reExposedBetween = true
      if (kept.has(ancestor)) {
        hidden = true
        break
      }
    }
    if (!hidden || reExposedBetween) kept.add(location)
  }
  return kept
}

/**
 * Expand a read-deny glob into the paths bwrap should mount over, collapsed
 * against `reExposedPaths` (the caller's allowRead and allowWrite entries).
 * A pattern ending in `/**` also takes its directory form, so
 * `**\/build/**` yields one mount per `build/` directory. A directory the
 * walk could not list is denied whole. Sorted, so an ancestor precedes its
 * descendants.
 *
 * The pattern covers the tree under its literal directory, by every name
 * that leads around inside it: a match reached through a symlink that stays
 * in the tree is listed where it really lives. The tree is the pattern's
 * own, the directory written before its first wildcard, and not the project
 * it may lie in: `<project>/src/**\/.env` covers `<project>/src`, so
 * `src/shared -> ../shared` leads out of it. A symlinked directory that
 * leads out of the tree is not listed through. One that itself matches still
 * denies what it leads to, whole; where the pattern would carry on into that
 * directory, it is handed back through `unlistableDirs` like one that could
 * not be listed: what the pattern matches in there was not looked for. One
 * that does not match denies nothing, and a file that only a listing through
 * it would have found is not denied. That is not only a file out there: a
 * link out there can lead back into the tree, and a file in the tree that
 * the pattern matches by no name but the one through both links is not
 * found either.
 *
 * Throws {@link GlobWalkBudgetError} when `budget` runs out before the walk
 * is done. There is no shorter list to fall back on: a caller that cannot
 * have the whole expansion must not run the command.
 *
 * @param unlistableDirs - receives the returned locations that hide something
 * the walk did not enumerate, whether by being that directory or by
 * covering it: a directory it could not list, or one out of the tree that a
 * matched link denies and the pattern would carry on into. The Linux wrapper
 * binds nothing back beneath one: what the pattern matches under an allowed
 * path in there was never found, and would come back unmasked.
 * @param opts.budget - what this expansion and the others handed the same
 * object may spend between them.
 * @param opts.unfollowedLinks - receives each symlinked directory that was
 * not listed through because it leads out of the pattern's tree, with the
 * directory it leads to.
 */
export function expandReadDenyGlobLinux(
  globPattern: string,
  reExposedPaths: readonly string[],
  unlistableDirs?: Set<string>,
  opts: {
    budget?: GlobWalkBudget
    unfollowedLinks?: Map<string, string>
  } = {},
): string[] {
  const startedAt = performance.now()
  const walk = walkGlobPattern(globPattern, {
    withDirectoryForm: true,
    followSymlinkedDirectories: true,
    budget: opts.budget,
  })
  for (const [link, target] of walk.unfollowedLinks) {
    opts.unfollowedLinks?.set(link, target)
  }
  // Where a path the walk reported really lives: the denyRead loop mounts an
  // entry there, whatever spelling named it.
  const locationOf = (p: string): string => walk.realOf.get(p) ?? p
  // An unlisted directory hides whatever the pattern matches beneath it.
  const candidates = new Set([...walk.matches, ...walk.unlisted])
  if (walk.directoryMatches.length > 0) {
    // Everything beneath a directory-form match is itself a match (the
    // pattern ends in /**), so a directory with something to deny holds one.
    // An empty one gets no mount: it has nothing to deny, and as a tmpfs it
    // would swallow later writes. Compared where they live, since one
    // spelling of a directory is walked and the matches found through it are
    // reported at their real locations.
    const holdMatches = new Set(walk.matches.map(m => parentOf(locationOf(m))))
    for (const dir of walk.directoryMatches) {
      // A directory-form match that is a symlink counts in its own right:
      // one the walk did not list through (a link back up the tree or out
      // of it, or a further name for a directory already listed) has no
      // match beneath it, yet denies everything it reaches.
      if (holdMatches.has(locationOf(dir)) || walk.symlinks.has(dir)) {
        candidates.add(dir)
      }
    }
  }

  const locations = new Set<string>()
  /** Which spelling first put a location in the list, for the warning below. */
  const namedBy = new Map<string, string>()
  const addLocation = (location: string, candidate: string): void => {
    locations.add(location)
    if (!namedBy.has(location)) namedBy.set(location, candidate)
  }
  for (const candidate of candidates) {
    if (walk.symlinks.has(candidate) && !walk.realOf.has(candidate)) {
      if (!walk.uninspectableLinks.has(candidate)) {
        // A link that resolves to nothing denies nothing, and bwrap cannot
        // mount on the link itself.
        logForDebugging(
          `[Sandbox Linux] denyRead glob "${globPattern}": ${candidate} does not resolve, skipping`,
        )
        continue
      }
      // A link whose target is there but cannot be looked at: kept under its
      // own spelling, where the denyRead loop's stand-in rule hides the
      // nearest directory above it that can be inspected.
      logForDebugging(
        `[Sandbox Linux] denyRead glob "${globPattern}": ${candidate} leads somewhere that cannot be inspected; denying what holds it`,
        { level: 'warn' },
      )
      addLocation(candidate, candidate)
      continue
    }
    const location = locationOf(candidate)
    if (location !== '/') {
      addLocation(location, candidate)
      continue
    }
    // A link to the root. A tmpfs there would wipe every mount placed before
    // it and the pivot would promote it, booting the command on an empty
    // tree, and bwrap cannot mount on the link itself. The nearest directory
    // above the link stands in for it, as for an entry that cannot be
    // inspected — never the root itself.
    const standIn = locationOf(parentOf(candidate))
    if (standIn === '' || standIn === '/') {
      logForDebugging(
        `[Sandbox Linux] denyRead glob "${globPattern}": ${candidate} resolves to / and nothing but / holds it, skipping`,
        { level: 'warn' },
      )
      continue
    }
    logForDebugging(
      `[Sandbox Linux] denyRead glob "${globPattern}": ${candidate} resolves to /; denying ${standIn}, which holds it, instead`,
      { level: 'warn' },
    )
    addLocation(standIn, candidate)
  }

  const reExposed = new Set(
    reExposedPaths.flatMap(p => pathSpellings(normalizePathForSandbox(p))),
  )
  const mounts = collapseReadDenyLocations({
    locations,
    reExposedPaths: reExposed,
  })

  // Which mounts stand for something the walk did not enumerate: a directory
  // it could not list, or one a matched link leads to out of the tree, which
  // is denied whole and was not listed. The directory itself when it
  // survived the collapse, otherwise the kept ancestor that hides it. A link
  // out of the tree that is no match denies nothing: where it leads is not
  // a location, and nothing is reported for it, even where the mount of
  // another match happens to hide it.
  const unenumerated = [
    ...walk.unlisted.map(locationOf),
    ...[...walk.unfollowedLinks.values()].filter(target =>
      locations.has(target),
    ),
  ]
  for (const location of unenumerated) {
    if (mounts.has(location)) {
      unlistableDirs?.add(location)
      continue
    }
    for (const ancestor of properAncestors(location)) {
      if (mounts.has(ancestor)) {
        unlistableDirs?.add(ancestor)
        break
      }
    }
  }

  // One line for the whole expansion, with what it cost: a caller that times
  // its wraps takes the numbers from here.
  const [firstUnfollowed] = walk.unfollowedLinks
  logForDebugging(
    `[Sandbox Linux] Expanded denyRead glob "${globPattern}" in ${Math.round(performance.now() - startedAt)} ms: ` +
      `${walk.matches.length} matches -> ${mounts.size} mounts; ` +
      `directories listed: ${walk.directoriesListed}, entries looked at: ${walk.entriesExamined}, ` +
      `links out of the tree left unfollowed: ${walk.unfollowedLinks.size}` +
      (firstUnfollowed
        ? ` (first: ${firstUnfollowed[0]} -> ${firstUnfollowed[1]})`
        : ''),
  )
  for (const mount of mounts) {
    // A matched link decides what is hidden for the whole sandbox: a
    // `certs/*` entry pointing at a database directory mounts a tmpfs over
    // that directory, not over anything the pattern names.
    if (walk.baseLocation !== '' && !isAtOrUnder(mount, walk.baseLocation)) {
      logForDebugging(
        `[Sandbox Linux] denyRead glob "${globPattern}" hides ${mount}, outside ${walk.baseLocation}: reached through ${namedBy.get(mount) === mount ? 'a symlinked directory' : namedBy.get(mount)}`,
        { level: 'warn' },
      )
    }
  }
  if (mounts.size > READ_DENY_GLOB_MOUNT_WARN_THRESHOLD) {
    logForDebugging(
      `[Sandbox Linux] denyRead glob "${globPattern}" still needs ${mounts.size} mounts after collapsing ` +
        `(threshold ${READ_DENY_GLOB_MOUNT_WARN_THRESHOLD}); each is a separate bwrap mount at sandbox start. ` +
        `Prefer denying the enclosing directories.`,
      { level: 'warn' },
    )
  }
  return [...mounts].sort()
}
