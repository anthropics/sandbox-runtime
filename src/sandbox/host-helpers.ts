import * as fs from 'node:fs'
import * as path from 'node:path'
import {
  isExecutableFile,
  isPathQualified,
  pathCandidates,
  whichSync,
} from '../utils/which.js'
import {
  isAtOrUnder,
  isSymlinkOutsideBoundary,
  normalizePathForSandbox,
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

/** Bounded depth for following symbolic links (the kernel's ELOOP limit). */
const MAX_LINKS_FOLLOWED = 40

/**
 * The allowed write paths in the forms a location is compared against: what
 * the Linux wrap binds writable for each, as `normalizePathForSandbox` spells
 * it and with every symlink resolved. An entry the wrap binds nothing for
 * counts for nothing: an absent one, and a link leading out of its own place
 * (`isSymlinkOutsideBoundary`). The command can make such a link wherever one
 * entry lies inside another (`<project>/dist -> /`), so where it leads must
 * neither switch the comparison off nor widen it.
 * `denyWithinAllow` is not subtracted: passing over more is the safe side.
 *
 * `undefined` when there is nothing to compare against: no list at all, or
 * one that names `/` itself and so leaves no place to prefer. A file's own
 * permissions are not judged here.
 */
function writableForms(
  allowedWritePaths: readonly string[] | undefined,
): string[] | undefined {
  if (allowedWritePaths === undefined) return undefined
  const forms = new Set<string>()
  for (const allowed of allowedWritePaths) {
    const normalized = normalizePathForSandbox(allowed)
    // The empty spelling (an empty $HOME) would cover every path as a prefix.
    if (!path.isAbsolute(normalized)) continue
    // Slash-free, as the wrap records it: a directory named with glob
    // characters ('<dir>/[id]/') comes back with the slash it was given.
    const spelled = normalized.replace(/\/+$/, '') || '/'
    if (spelled === '/') return undefined
    let resolved: string
    try {
      resolved = fs.realpathSync(spelled)
    } catch {
      continue
    }
    if (isSymlinkOutsideBoundary(spelled, resolved)) continue
    forms.add(spelled).add(resolved)
  }
  return [...forms]
}

const components = (p: string): string[] =>
  p.split('/').filter(c => c !== '' && c !== '.')

/**
 * The places a lookup of the absolute path `file` passes through: `file` as
 * spelled (which covers the `PATH` entry it lies beneath), each symbolic link
 * followed on the way, by where the link itself is, and last the file it
 * resolves to. `null` when the path cannot be followed to the end.
 *
 * Every link counts, not only the outcome: one the command may write can be
 * aimed elsewhere by the time the helper is run.
 */
function resolutionTrail(file: string): string[] | null {
  const trail = [file]
  // `resolved` never holds a link, so '..' steps back the way the kernel does.
  let resolved: string[] = []
  let pending = components(file)
  let followed = 0
  while (pending.length > 0) {
    const component = pending.shift()!
    if (component === '..') {
      resolved.pop()
      continue
    }
    const here = '/' + [...resolved, component].join('/')
    let target: string | undefined
    try {
      if (fs.lstatSync(here).isSymbolicLink()) target = fs.readlinkSync(here)
    } catch {
      return null
    }
    if (target === undefined) {
      resolved.push(component)
      continue
    }
    if (++followed > MAX_LINKS_FOLLOWED) return null
    trail.push(here)
    if (path.isAbsolute(target)) resolved = []
    pending = [...components(target), ...pending]
  }
  trail.push('/' + resolved.join('/'))
  return trail
}

/** The first place on `trail` inside one of the `writable` paths, and which. */
function firstWritablePlace(
  trail: readonly string[],
  writable: readonly string[],
): { index: number; place: string; covering: string } | undefined {
  for (const [index, place] of trail.entries()) {
    const covering = writable.find(w => isAtOrUnder(place, w))
    if (covering !== undefined) return { index, place, covering }
  }
  return undefined
}

/**
 * Why `file` must not be run on the host under these write paths, or `null`
 * when it may. Refused too when it cannot be followed to its end.
 */
function refusalFor(
  file: string,
  writable: readonly string[],
): Omit<SkippedHostHelper, 'path'> | null {
  const trail = resolutionTrail(file)
  if (trail === null) return { reason: 'it could not be followed to a file' }
  const found = firstWritablePlace(trail, writable)
  if (found === undefined) return null
  const inside = `inside the allowed write path ${found.covering}`
  const reason =
    found.index === 0
      ? inside
      : found.index === trail.length - 1
        ? `resolves to ${found.place}, ${inside}`
        : `reached through the link ${found.place}, ${inside}`
  return { reason, writePath: found.covering }
}

// One accepted result per name and PATH string. A hit is never returned on
// trust: it is judged again under the write paths of THIS call, which an
// updateConfig() or a per-call configuration may have widened.
const accepted = new Map<string, string>()

/**
 * Find `name`, a program this library itself runs on the host (bubblewrap, the
 * socat bridges, the ripgrep scan) with the caller's full authority. A file
 * the policy lets the wrapped command write is never executed: it is whatever
 * an earlier wrapped command left there. `PATH` is searched as it stands,
 * even when a writable directory leads it (`<project>/node_modules/.bin`
 * under `npx`); what is found in such a place is passed over and recorded.
 *
 * Nothing is run to find it: this is the search of `whichSync`, taking the
 * first candidate outside everything `allowedWritePaths` (a wrap's
 * `writeConfig.allowOnly`) covers. A relative `PATH` entry, the empty one
 * included, is never used. With nothing to compare against (see
 * `writableForms`) it is the plain search.
 *
 * `path` is `null` when no candidate may be used. The caller refuses to go
 * on; falling back to the bare name would hand the choice back to `PATH`.
 * POSIX paths only: every helper looked for belongs to the Linux backend.
 */
export function findHostHelper(
  name: string,
  allowedWritePaths: readonly string[] | undefined,
): HostHelperSearch {
  const writable = writableForms(allowedWritePaths)
  if (writable === undefined || isPathQualified(name)) {
    return { path: whichSync(name), skipped: [] }
  }

  const pathVar = process.env.PATH ?? ''
  const key = `${name}\0${pathVar}`
  const earlier = accepted.get(key)
  if (earlier !== undefined) {
    if (isExecutableFile(earlier) && refusalFor(earlier, writable) === null) {
      return { path: earlier, skipped: [] }
    }
    accepted.delete(key)
  }

  const skipped: SkippedHostHelper[] = []
  for (const { entry, file } of pathCandidates(name, pathVar)) {
    if (!isExecutableFile(file)) continue
    const refusal = path.isAbsolute(entry)
      ? refusalFor(file, writable)
      : {
          reason:
            entry === ''
              ? 'an empty PATH entry means the current directory'
              : `the PATH entry ${entry} is relative`,
        }
    if (refusal === null) {
      accepted.set(key, file)
      return { path: file, skipped }
    }
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
 * somebody can. `undefined` where nothing is filtered. Never empty: a shell
 * reads an empty PATH as the current directory, which the command may write,
 * so with no entry left the answer is `/dev/null`, which holds nothing.
 */
export function hostSearchPath(
  allowedWritePaths: readonly string[] | undefined,
  programs: readonly string[] = [],
): string | undefined {
  const writable = writableForms(allowedWritePaths)
  if (writable === undefined) return undefined
  const acceptable = (entry: string): boolean =>
    path.isAbsolute(entry) &&
    refusalFor(entry, writable) === null &&
    programs.every(program => {
      // Joined as the shell joins them: the walk resolves a `..` through the
      // file system, not by spelling.
      const file = `${entry}${entry.endsWith('/') ? '' : '/'}${program}`
      // Whatever is there is judged, executable or not, a dangling link
      // included: the command could supply the rest later.
      try {
        fs.lstatSync(file)
      } catch {
        return true
      }
      return refusalFor(file, writable) === null
    })
  return (
    (process.env.PATH ?? '')
      .split(path.delimiter)
      .filter(acceptable)
      .join(path.delimiter) || '/dev/null'
  )
}

/** The option that names `helper` outright, for the message below. */
function optionNaming(helper: string): string {
  if (helper === 'bwrap') return 'bwrapPath'
  if (helper === 'socat') return 'socatPath'
  return 'ripgrep.command'
}

/**
 * The refusal for a search that found nothing to use: which helper, what was
 * passed over and why, and what lifts it. INVARIANT: it opens with
 * "<helper> runs on the host and was not found on PATH". The dependency check
 * hands out strings only, and embedders tell its errors apart by that.
 */
export function describeUnavailableHostHelper(
  helper: string,
  search: HostHelperSearch,
): string {
  const passedOver =
    search.skipped.length > 0
      ? ` Passed over: ${search.skipped
          .map(s => `${s.path} (${s.reason})`)
          .join('; ')}.`
      : ''
  return (
    `${helper} runs on the host and was not found on PATH outside the paths the sandboxed command may write.${passedOver} ` +
    `Install it outside those paths, put the directory that holds it on PATH, or name it with ${optionNaming(helper)}.`
  )
}

/**
 * The dependency-check warning for `file`, a helper the operator named
 * outright through `option`, when it lies inside an allowed write path by the
 * same test as the search; `undefined` otherwise. The file is still used as
 * given: naming it is a directive. A path that cannot be followed is judged
 * by its spelling.
 */
export function writableNamedHelperWarning(
  option: string,
  file: string | undefined,
  allowedWritePaths: readonly string[] | undefined,
): string | undefined {
  const writable = writableForms(allowedWritePaths)
  if (!file || writable === undefined) return undefined
  const spelled = path.resolve(file)
  const found = firstWritablePlace(
    resolutionTrail(spelled) ?? [spelled],
    writable,
  )
  return found === undefined
    ? undefined
    : `${option} ${file} is inside the allowed write path ${found.covering}: the sandboxed command can replace that file`
}
