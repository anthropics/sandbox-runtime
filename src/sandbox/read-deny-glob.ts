import { logForDebugging } from '../utils/debug.js'
import {
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

/**
 * Reduce the places a read-deny glob's matches really live to the ones whose
 * mount changes what the sandbox can read. A location is dropped only when a
 * kept proper ancestor's tmpfs already hides it and no re-exposer sits at the
 * ancestor or between the two. The denyRead loop mounts each entry where it
 * really lives, so this is decided there too: the spelled parent of a match
 * reached through a symlink need not contain it.
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
    // A re-exposer at the kept ancestor counts: the deny loop binds it back
    // over the tmpfs, so everything beneath needs its own mount.
    let reExposedBetween = reExposedPaths.has(location)
    let hidden = false
    for (const ancestor of properAncestors(location)) {
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
 */
export function expandReadDenyGlobLinux(
  globPattern: string,
  reExposedPaths: readonly string[],
): string[] {
  const walk = walkGlobPattern(globPattern, { withDirectoryForm: true })
  // An unlisted directory hides whatever the pattern matches beneath it.
  const candidates = new Set([...walk.matches, ...walk.unlisted])
  if (walk.directoryMatches.length > 0) {
    // Everything beneath a directory-form match is itself a match (the
    // pattern ends in /**), so a directory with something to deny is some
    // match's parent. An empty one gets no mount: it has nothing to deny,
    // and as a tmpfs it would swallow later writes.
    const parents = new Set(
      walk.matches.map(m => m.slice(0, m.lastIndexOf('/'))),
    )
    for (const dir of walk.directoryMatches) {
      // A directory-form match that is a symlink counts in its own right:
      // one the walk did not descend (a link back into its own ancestry)
      // has no match beneath it, yet denies everything it reaches.
      if (parents.has(dir) || walk.symlinks.has(dir)) candidates.add(dir)
    }
  }

  // Where each candidate really lives: the denyRead loop mounts an entry
  // there, whatever spelling named it.
  const locations = new Set<string>()
  for (const candidate of candidates) {
    const location = walk.realOf.get(candidate) ?? candidate
    if (walk.symlinks.has(candidate) && !walk.realOf.has(candidate)) {
      // A link that resolves to nothing denies nothing, and bwrap cannot
      // mount on the link itself.
      logForDebugging(
        `[Sandbox Linux] denyRead glob "${globPattern}": ${candidate} does not resolve, skipping`,
      )
      continue
    }
    if (location === '/') {
      // A tmpfs over the root would hide everything, and one on the link is
      // refused by bwrap: every later command would fail to start for as
      // long as the link exists.
      logForDebugging(
        `[Sandbox Linux] denyRead glob "${globPattern}": ${candidate} resolves to /, skipping`,
        { level: 'warn' },
      )
      continue
    }
    locations.add(location)
  }

  const reExposed = new Set(
    reExposedPaths.flatMap(p => pathSpellings(normalizePathForSandbox(p))),
  )
  const mounts = collapseReadDenyLocations({
    locations,
    reExposedPaths: reExposed,
  })

  logForDebugging(
    `[Sandbox Linux] Expanded denyRead glob "${globPattern}": ${walk.matches.length} matches -> ${mounts.size} mounts`,
  )
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
