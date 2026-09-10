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
 * Reduce a read-deny glob's matches to the mounts that change what the
 * sandbox can read; ancestors precede descendants in the result. A match is
 * dropped only when a kept proper ancestor's tmpfs already hides it and no
 * re-exposer sits at the ancestor or between the two.
 */
function collapseReadDenyMounts({
  matches,
  reExposedPaths,
}: {
  /** Absolute, normalized, trailing-slash-free paths; a match reached
   *  through a symlink appears in both its spellings. */
  matches: Iterable<string>
  /** allowRead/allowWrite paths the denyRead loop re-binds over a tmpfs, in
   *  every spelling that can name them. */
  reExposedPaths: ReadonlySet<string>
}): string[] {
  // A proper ancestor is a proper string prefix, so lexicographic order
  // visits every ancestor before its descendants.
  const sorted = [...new Set(matches)].sort()
  const kept = new Set<string>()
  for (const candidate of sorted) {
    // A re-exposer at the kept ancestor counts: the deny loop binds it back
    // over the tmpfs, so everything beneath needs its own mount.
    let reExposedBetween = reExposedPaths.has(candidate)
    let hidden = false
    for (const ancestor of properAncestors(candidate)) {
      if (reExposedPaths.has(ancestor)) reExposedBetween = true
      if (kept.has(ancestor)) {
        hidden = true
        break
      }
    }
    if (!hidden || reExposedBetween) kept.add(candidate)
  }
  return [...kept]
}

/**
 * Expand a read-deny glob into the paths bwrap should mount over, collapsed
 * against `reExposedPaths` (the caller's allowRead and allowWrite entries).
 * A pattern ending in `/**` also takes its directory form, so
 * `**\/build/**` yields one mount per `build/` directory. A match reached
 * through a symlink is listed in its resolved spelling as well.
 */
export function expandReadDenyGlobLinux(
  globPattern: string,
  reExposedPaths: readonly string[],
): string[] {
  const walk = walkGlobPattern(globPattern, { withDirectoryForm: true })
  const candidates = new Set(walk.matches)
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

  const reExposed = new Set(
    reExposedPaths.flatMap(p => pathSpellings(normalizePathForSandbox(p))),
  )
  // Resolved spellings: a realpath for a match under a link the walk
  // descended, a string swap for one under a symlinked base.
  const throughWalkLink = (p: string): boolean => {
    if (walk.symlinks.has(p)) return true
    for (const ancestor of properAncestors(p)) {
      if (walk.symlinks.has(ancestor)) return true
    }
    return false
  }
  const base = walk.base
  const swappedBase =
    base !== undefined && base.real !== base.dir ? base : undefined
  for (const match of [...candidates]) {
    if (throughWalkLink(match)) {
      const spellings = pathSpellings(match)
      if (spellings.length === 2) {
        candidates.add(spellings[1])
      } else if (walk.symlinks.has(match)) {
        // The spelling stays, and bwrap refuses to mount on the link.
        logForDebugging(
          `[Sandbox Linux] denyRead glob "${globPattern}": ${match} is dangling or resolves to /, not denied at its target`,
          { level: 'warn' },
        )
      }
    } else if (swappedBase !== undefined) {
      const beneathBase = match.slice(swappedBase.dir.length)
      candidates.add(
        swappedBase.real === '/' ? beneathBase : swappedBase.real + beneathBase,
      )
    }
  }

  const mounts = collapseReadDenyMounts({
    matches: candidates,
    reExposedPaths: reExposed,
  })

  logForDebugging(
    `[Sandbox Linux] Expanded denyRead glob "${globPattern}": ${walk.matches.length} matches -> ${mounts.length} mounts`,
  )
  if (mounts.length > READ_DENY_GLOB_MOUNT_WARN_THRESHOLD) {
    logForDebugging(
      `[Sandbox Linux] denyRead glob "${globPattern}" still needs ${mounts.length} mounts after collapsing ` +
        `(threshold ${READ_DENY_GLOB_MOUNT_WARN_THRESHOLD}); each is a separate bwrap mount at sandbox start. ` +
        `Prefer denying the enclosing directories.`,
      { level: 'warn' },
    )
  }
  return mounts
}
