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
  normalizePathForSandbox,
  pathSpellings,
} from './sandbox-utils.js'

/** A file the search found and would not use, and why. */
export type SkippedHostHelper = { candidate: string; reason: string }

export type HostHelperSearch = {
  /** The helper to run, by absolute path; null when none may be used. */
  path: string | null
  /** What was found before it, or instead of it, and passed over. */
  skipped: SkippedHostHelper[]
}

/** Bounded depth for following symbolic links (the kernel's ELOOP limit). */
const MAX_LINKS_FOLLOWED = 40

/**
 * The forms of the allowed write paths a location is compared against: each
 * as `normalizePathForSandbox` gives it, which is how the wrap spells its
 * bind, and with every symlink resolved. `denyWithinAllow` is deliberately
 * not subtracted; passing over more is the safe direction.
 *
 * `undefined` means there is nothing to compare against. That is the answer
 * when the policy restricts no writes (no list at all), and also when the
 * list holds `/`: a policy that lets the command write everywhere leaves no
 * place this rule could prefer, and what then stands between the command and
 * a helper is the file's own permissions, which are not judged here.
 */
function writableForms(
  allowedWritePaths: readonly string[] | undefined,
): string[] | undefined {
  if (allowedWritePaths === undefined) return undefined
  const forms = new Set<string>()
  for (const allowed of allowedWritePaths) {
    for (const form of pathSpellings(normalizePathForSandbox(allowed))) {
      // The empty spelling (an empty $HOME expanding '~') is not a path, and
      // as a prefix it would cover every absolute one.
      if (path.isAbsolute(form)) forms.add(form)
    }
  }
  return forms.has('/') ? undefined : [...forms]
}

const components = (p: string): string[] =>
  p.split('/').filter(c => c !== '' && c !== '.')

/**
 * The places a lookup of the absolute path `file` passes through: `file` as
 * spelled, then each symbolic link followed on the way, by where the link
 * itself is, and last the file it all resolves to. The `PATH` entry is
 * covered by the first of them, which is spelled beneath it. `null` when the
 * path cannot be followed to the end.
 *
 * Every link counts, not only the outcome: a link the command may write can
 * be aimed elsewhere by the time the helper is run, wherever it led when it
 * was looked at. That catches a link in a safe directory that leads to a
 * writable file, and equally a `PATH` entry that is a link kept inside the
 * writable directory and leads to a safe one, whatever alias of that
 * directory `PATH` spells it through.
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
 * when it may. A file that cannot be followed to its end is refused: what
 * cannot be looked at cannot be shown to lie outside them.
 */
function refusalFor(file: string, writable: readonly string[]): string | null {
  const trail = resolutionTrail(file)
  if (trail === null) return 'it could not be followed to a file'
  const found = firstWritablePlace(trail, writable)
  if (found === undefined) return null
  const inside = `inside the allowed write path ${found.covering}`
  if (found.index === 0) return inside
  return found.index === trail.length - 1
    ? `resolves to ${found.place}, ${inside}`
    : `reached through the link ${found.place}, ${inside}`
}

// One accepted result per name and PATH string. Whether a result may be used
// is a matter of the policy and not of the moment, so a hit is never returned
// on trust: it is looked at again under the write paths of THIS call, and
// searched for afresh once it has come to lie inside one of them (an
// updateConfig() that widened allowWrite, a per-call configuration).
const accepted = new Map<string, string>()

/**
 * Find `name`, a program this library itself runs on the host: bubblewrap, the
 * socat bridges, the ripgrep scan. Those run with the caller's full
 * authority, outside any sandbox, so the rule is: never execute a file the
 * sandbox policy lets the wrapped command write, because such a file is
 * whatever an earlier wrapped command left there. It is a rule about the file
 * that gets chosen, not about `PATH` as such: a `PATH` that leads with a
 * directory the command may write (`<project>/node_modules/.bin` under `npx`
 * and `npm run`, with the project in `allowWrite`) is searched as it stands,
 * and what is found in such a place is passed over.
 *
 * Nothing is run to find it. This is the in-process search of `whichSync`,
 * taking the first candidate that lies outside everything
 * `allowedWritePaths` (a wrap's `writeConfig.allowOnly`) lets the wrapped
 * command write. A candidate inside is passed over, and recorded, and the
 * search goes on. A relative `PATH` entry, the empty one included, names
 * wherever the process happens to stand and is never used.
 *
 * With nothing to compare against (see `writableForms`) this is the plain
 * search, and nothing is passed over.
 *
 * `path` is `null` when no candidate may be used. The caller refuses to go
 * on; it never falls back to the bare name, which would hand the choice back
 * to `PATH`.
 *
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
    const reason = path.isAbsolute(entry)
      ? refusalFor(file, writable)
      : entry === ''
        ? 'an empty PATH entry means the current directory'
        : `the PATH entry ${entry} is relative`
    if (reason === null) {
      accepted.set(key, file)
      return { path: file, skipped }
    }
    skipped.push({ candidate: file, reason })
  }
  return { path: null, skipped }
}

/** The option that names `helper` outright, for the message below. */
function optionNaming(helper: string): string {
  if (helper === 'bwrap') return 'bwrapPath'
  if (helper === 'socat') return 'socatPath'
  return 'ripgrep.command'
}

/**
 * The refusal for a search that found nothing to use: which helper, that no
 * copy lies outside the write paths, what was passed over and why, and what
 * lifts it.
 */
export function describeUnavailableHostHelper(
  helper: string,
  search: HostHelperSearch,
): string {
  const passedOver =
    search.skipped.length > 0
      ? ` Passed over: ${search.skipped
          .map(s => `${s.candidate} (${s.reason})`)
          .join('; ')}.`
      : ''
  return (
    `${helper} runs on the host and was not found on PATH outside the paths the sandboxed command may write.${passedOver} ` +
    `Install it outside those paths, put the directory that holds it on PATH, or name it with ${optionNaming(helper)}.`
  )
}

/**
 * The dependency-check warning for `file`, a helper the operator named
 * outright through `option` (`bwrapPath`, `socatPath`, `seccomp.applyPath`, a
 * `ripgrep.command` with a directory part), when it lies inside an allowed
 * write path by the same test as the search; `undefined` when it lies
 * outside them all, or is not set. Such a file is still used as given, since
 * naming it is a directive, and the operator is told what the sandboxed
 * command can do to it. A path that cannot be followed is judged by its
 * spelling.
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
