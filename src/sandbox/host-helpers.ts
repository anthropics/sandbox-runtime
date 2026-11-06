import * as fs from 'node:fs'
import * as path from 'node:path'
import { getPlatform } from '../utils/platform.js'
import { wayTo } from '../utils/real-path.js'
import {
  isExecutableFile,
  isPathQualified,
  pathCandidates,
  whichSync,
} from '../utils/which.js'
import {
  containsGlobChars,
  getDefaultWritePaths,
  globBaseDirIsRoot,
  globPatternBaseDir,
  isAtOrUnder,
  normalizePathForSandbox,
  workingDirectory,
} from './sandbox-utils.js'

/** A file the search found and would not use, and why. */
export type SkippedHostHelper = {
  path: string
  reason: string
  /** The allowed write path that covers it, when that is the reason. */
  writePath?: string
}

export type HostHelperSearch = {
  /** The helper to run, by absolute path; null when none may be used. */
  path: string | null
  /** What was found before it, or instead of it, and passed over. */
  skipped: SkippedHostHelper[]
}

/** What {@link writablePlaces} makes of a policy's write paths. */
export type WritablePlaces = readonly string[]

/**
 * Where a sandboxed command may write, in the form a location is compared
 * against: each allowed write path (`writeRootsOf` a write config) as
 * `normalizePathForSandbox` spells it, symlinks resolved. On Linux each is a
 * name, as it is to the wrap; elsewhere one that reads as a pattern counts by
 * the directory it starts from. `denyWithinAllow` is not subtracted: passing
 * over more is the safe side.
 *
 * - `'anywhere'`, said outright, or a list that names `/`: nowhere, since no
 *   place is then better than another. A file's permissions are not judged.
 * - `undefined`, the policy not being known yet: the working directory and the
 *   default write paths, which nearly every policy allows.
 * - A link that leads out of its own place is left as spelled, and the wrap
 *   binds nothing for it. The command can make such a link wherever one entry
 *   lies inside another (`<project>/dist -> /`), so it must neither switch
 *   the comparison off nor widen it.
 */
export function writablePlaces(
  allowedWritePaths: readonly string[] | 'anywhere' | undefined,
): WritablePlaces {
  if (allowedWritePaths === 'anywhere') return []
  const places = new Set<string>()
  const literal = getPlatform() === 'linux'
  const cwd = workingDirectory()
  for (const allowed of allowedWritePaths ?? [
    ...(cwd === undefined ? [] : [cwd]),
    ...getDefaultWritePaths(),
  ]) {
    const normalized = normalizePathForSandbox(allowed, { literal })
    // `~` under an empty $HOME is the empty spelling, which names no place.
    if (!path.isAbsolute(normalized)) continue
    const place =
      !literal && containsGlobChars(normalized)
        ? globPatternBaseDir(normalized)
        : normalized
    if (globBaseDirIsRoot(place)) return []
    places.add(place)
  }
  return [...places]
}

/**
 * Why the absolute path `file` must not be run on the host, or `undefined`
 * when it may. Every place a lookup of it passes through counts, not only the
 * outcome: `file` as spelled (which covers the `PATH` entry it lies beneath),
 * each symbolic link followed, each directory a link's target goes up from
 * again, and the file it resolves to. One the command may write can lead
 * elsewhere by the time the helper is run.
 */
function refusalFor(
  file: string,
  writable: WritablePlaces,
): Omit<SkippedHostHelper, 'path'> | undefined {
  if (writable.length === 0) return undefined
  const places = [file]
  const note = (place: string): unknown => places.push(place)
  let followed = false
  try {
    const { real, notThere } = wayTo(file, { link: note, left: note })
    followed = notThere === undefined
    places.push(real)
  } catch {
    // Judged by as far as it could be followed.
  }
  for (const place of places) {
    const writePath = writable.find(w => isAtOrUnder(place, w))
    if (writePath !== undefined) {
      return {
        reason: `${place === file ? '' : `leads through ${place}, `}inside the allowed write path ${writePath}`,
        writePath,
      }
    }
  }
  return followed ? undefined : { reason: 'it could not be followed to a file' }
}

/** Whether `file` lies, and is reached, where the command cannot write. */
export function isOutside(file: string, writable: WritablePlaces): boolean {
  return refusalFor(file, writable) === undefined
}

/**
 * Find `name`, a program that runs with more authority than the wrapped
 * command: on the host (bubblewrap, the socat bridges, the ripgrep scan), or
 * inside the sandbox ahead of the seccomp filter (the relays, the shell that
 * starts the helper). A file the policy lets the command write is never
 * taken: it is whatever an earlier wrapped command left there.
 *
 * `PATH` is searched as it stands, even when a writable directory leads it
 * (`<project>/node_modules/.bin` under `npx`), and nothing is run to search
 * it. What is found in a writable place, or through a relative `PATH` entry,
 * is passed over and recorded. A name with a directory part is a directive,
 * and taken as given.
 *
 * `path` is `null` when no candidate may be used. The caller refuses to go
 * on; falling back to the bare name would hand the choice back to `PATH`.
 * POSIX only.
 */
export function findHostHelper(
  name: string,
  writable: WritablePlaces,
): HostHelperSearch {
  if (isPathQualified(name)) return { path: whichSync(name), skipped: [] }
  const skipped: SkippedHostHelper[] = []
  for (const { entry, file } of pathCandidates(name)) {
    if (!isExecutableFile(file)) continue
    const refusal = path.isAbsolute(entry)
      ? refusalFor(file, writable)
      : { reason: `the PATH entry '${entry}' is relative` }
    if (refusal === undefined) return { path: file, skipped }
    skipped.push({ path: file, ...refusal })
  }
  return { path: null, skipped }
}

/**
 * The PATH for a program the library starts on the host that does look-ups of
 * its own (`npm`, a script that finds `node` by name): this process's PATH
 * less every entry a host helper would not be taken from. An entry is judged
 * as a directory and by its copy of each of `programs`, the names the child
 * looks up: a link in a directory nobody can write may lead to a file
 * somebody can. Never empty: a shell reads an empty PATH as the current
 * directory, so with no entry left it is `/dev/null`, which holds nothing.
 * POSIX only.
 */
export function hostSearchPath(
  writable: WritablePlaces,
  programs: readonly string[],
): string {
  const acceptable = (entry: string): boolean =>
    path.isAbsolute(entry) &&
    isOutside(entry, writable) &&
    programs.every(program => {
      const file = `${entry}/${program}`
      // Whatever is there is judged, executable or not, a dangling link
      // included: the command could supply the rest later.
      try {
        fs.lstatSync(file)
      } catch {
        return true
      }
      return isOutside(file, writable)
    })
  return (
    (process.env.PATH ?? '').split(':').filter(acceptable).join(':') ||
    '/dev/null'
  )
}

/**
 * The refusal for a search that found nothing to use: which helper, what was
 * passed over and why, and that `option` lifts it. INVARIANT: it opens with
 * "<helper> was not found on PATH", and of a helper that is nowhere to be
 * found the dependency check says `nowhere`, its words as ever. It hands out
 * strings only, and embedders tell its errors apart by them.
 */
export function describeUnavailableHostHelper(
  helper: string,
  option: string,
  { skipped }: HostHelperSearch,
  nowhere = isPathQualified(helper)
    ? `${helper} is not an executable file`
    : `${helper} was not found on PATH`,
): string {
  if (skipped.length === 0) return nowhere
  return (
    `${helper} was not found on PATH outside the paths the sandboxed command may write. ` +
    `Passed over: ${skipped.map(s => `${s.path} (${s.reason})`).join('; ')}. ` +
    `Install it outside those paths, put the directory that holds it on PATH, or name it by its path with ${option}.`
  )
}

/**
 * The dependency-check warning for `file`, a helper the operator named
 * outright through `option`, when the command may write it by the same test as
 * the search; `undefined` otherwise, and for a bare name, which names no file.
 * The file is still used as given.
 */
export function writableNamedHelperWarning(
  option: string,
  file: string | undefined,
  writable: WritablePlaces,
): string | undefined {
  const refusal =
    file && isPathQualified(file) && refusalFor(path.resolve(file), writable)
  return refusal && refusal.writePath !== undefined
    ? `${option} ${file} ${refusal.reason.replace(/^inside/, 'is inside')}: the sandboxed command can replace that file`
    : undefined
}
