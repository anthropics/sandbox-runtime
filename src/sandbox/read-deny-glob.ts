import { logForDebugging } from '../utils/debug.js'
import {
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
 * `**\/build/**` yields one mount per `build/` directory. A match reached
 * through a symlink is listed where it really lives, and a directory the walk
 * could not list is denied whole. Sorted, so an ancestor precedes its
 * descendants.
 *
 * @param unlistableDirs - receives the returned locations that hide something
 * the walk could not enumerate, whether by being that directory or by
 * covering it. The Linux wrapper binds nothing back beneath one: what the
 * pattern matches under an allowed path in there was never found, and would
 * come back unmasked.
 */
export function expandReadDenyGlobLinux(
  globPattern: string,
  reExposedPaths: readonly string[],
  unlistableDirs?: Set<string>,
): string[] {
  const walk = walkGlobPattern(globPattern, {
    withDirectoryForm: true,
    followSymlinkedDirectories: true,
  })
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
      // one the walk did not list through (a link back into its own
      // ancestry, or a second name for a directory already walked) has no
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

  // Which mounts stand for something the walk could not enumerate: the
  // unlistable directory itself when it survived the collapse, otherwise the
  // kept ancestor that hides it.
  for (const unlisted of walk.unlisted) {
    const location = locationOf(unlisted)
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

  logForDebugging(
    `[Sandbox Linux] Expanded denyRead glob "${globPattern}": ${walk.matches.length} matches -> ${mounts.size} mounts`,
  )
  for (const mount of mounts) {
    // A matched link decides what is hidden for the whole sandbox: a
    // `certs/*` entry pointing at a database directory mounts a tmpfs over
    // that directory, not over anything the pattern names.
    if (walk.baseLocation !== '' && !isAtOrUnder(mount, walk.baseLocation)) {
      logForDebugging(
        `[Sandbox Linux] denyRead glob "${globPattern}" hides ${mount}, outside ${walk.baseLocation}: reached through ${namedBy.get(mount)}`,
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
