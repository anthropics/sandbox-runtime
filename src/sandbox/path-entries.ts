/**
 * How an entry of `denyRead`, `allowRead`, `allowWrite` or `denyWrite` is
 * read: as the pattern its characters spell, as the path they name, or both.
 *
 * An entry with `*`, `?`, `[` or `]` is a pattern. A directory may hold those
 * in its own name (`[WIP] project`), so such an entry is ALSO read as what it
 * names wherever the part that holds the characters exists on disk. An entry
 * marked `{ path, literal: true }` is the name and nothing else.
 *
 * The decision is made by the functions here only, for each stage that
 * needs it (the manager and the wrapper's fold on Linux, the profile builder
 * on macOS, `expandWindowsFsPaths` on Windows). One wrap may ask about an
 * entry more than once, and the disk may change in between.
 */

import * as fs from 'node:fs'
import * as path from 'node:path'
import { getPlatform } from '../utils/platform.js'
import {
  collapseInteriorSpellings,
  containsGlobChars,
  containsGlobCharsForPlatform,
  expandTilde,
  expandWindowsEnvRefs,
  isAbsenceErrno,
  isUncPath,
  markedLiteralPath,
  normalizePathForSandbox,
  removeTrailingGlobSuffix,
  type Steps,
  stripExtendedPathPrefix,
  toForwardSlashes,
} from './sandbox-utils.js'
import type { FilesystemPathEntry } from './sandbox-config.js'
import type {
  FsReadRestrictionConfig,
  FsWriteRestrictionConfig,
} from './sandbox-schemas.js'

/**
 * Which way a list cuts. A deny takes every reading that may hold, since one
 * more can only deny more; an allow takes one only for a path that is there
 * exactly as spelled.
 */
export type PathListKind = 'allow' | 'deny'

/** One reading of an entry, shaped as the macOS builder's `PathEntry`. */
export type PathReading =
  /** The entry is the name of this path. */
  | { glob: false; path: string }
  /**
   * The entry is a pattern beneath `anchor`, a directory taken as the name it
   * is: `path` is `anchor` plus the tail, and only the tail is pattern.
   */
  | { glob: true; path: string; anchor: string }

/**
 * The spellings and the marked paths of a list, apart. Throws on an entry
 * that is neither; see {@link markedLiteralPath}.
 */
export function splitPathEntries(
  entries: readonly FilesystemPathEntry[] | undefined,
): { spelled: string[]; marked: string[] } {
  const spelled: string[] = []
  const marked: string[] = []
  for (const entry of entries ?? []) {
    if (typeof entry === 'string') spelled.push(entry)
    else marked.push(markedLiteralPath(entry))
  }
  return { spelled, marked }
}

/** The spellings among the entries of a list: what may be a pattern. */
export function spelledOf(
  entries: readonly FilesystemPathEntry[] | undefined,
): string[] {
  return splitPathEntries(entries).spelled
}

/**
 * Whether two lists hold the same entries, in any order. Entries are told
 * apart by value: a marked entry is a new object after every clone of the
 * config, and `/x` is not `{ path: '/x' }`.
 */
export function samePathEntries(
  a: readonly FilesystemPathEntry[],
  b: readonly FilesystemPathEntry[],
): boolean {
  const key = (entry: FilesystemPathEntry): string =>
    typeof entry === 'string' ? `s:${entry}` : `l:${markedLiteralPath(entry)}`
  if (a.length !== b.length) return false
  const counts = new Map<string, number>()
  for (const entry of a) {
    const k = key(entry)
    counts.set(k, (counts.get(k) ?? 0) + 1)
  }
  for (const entry of b) {
    const k = key(entry)
    const count = counts.get(k) ?? 0
    if (count === 0) return false
    counts.set(k, count - 1)
  }
  return true
}

/**
 * The spelling made absolute as {@link normalizePathForSandbox} does for a
 * pattern: no symlink resolved, a trailing separator kept. Undefined for a
 * Windows UNC path, which is never probed (see {@link isUncPath}).
 */
function spelledAbsolute(spelling: string): string | undefined {
  const onWindows = getPlatform() === 'windows'
  let spelled = spelling
  if (onWindows) {
    spelled = stripExtendedPathPrefix(expandWindowsEnvRefs(spelled))
    if (isUncPath(spelled)) return undefined
  }
  const expanded = expandTilde(spelled)
  const absolute =
    expanded === spelled && !path.isAbsolute(spelled)
      ? path.resolve(process.cwd(), spelled)
      : expanded
  return onWindows
    ? toForwardSlashes(absolute)
    : collapseInteriorSpellings(absolute)
}

/**
 * Whether something may be at `p`, for a deny. A symbolic link counts,
 * dangling or not, and so does a path that cannot be looked at: otherwise a
 * command running as the same user could switch the deny off by making a
 * parent unsearchable, and undo that inside the next sandbox.
 */
function mayBeThere(p: string): boolean {
  try {
    fs.lstatSync(p)
    return true
  } catch (err) {
    return !isAbsenceErrno(err)
  }
}

/**
 * Whether `p` is there and is not a symbolic link, for an allow. Whoever can
 * write the directory that holds `p` can plant a link of that name, and the
 * allow would open what it points at. What cannot be looked at is not there.
 */
function isThereUnlinked(p: string): boolean {
  try {
    return !fs.lstatSync(p).isSymbolicLink()
  } catch {
    return false
  }
}

/** Whether a pattern can be walked beneath `p`, under the rule of `kind`. */
function isDirectoryFor(kind: PathListKind, p: string): boolean {
  try {
    return kind === 'allow'
      ? fs.lstatSync(p).isDirectory()
      : fs.statSync(p).isDirectory()
  } catch (err) {
    return kind === 'deny' && !isAbsenceErrno(err)
  }
}

/**
 * The readings a caller's spelling has BESIDE the one its characters give
 * it. Empty for a spelling that is no pattern, and for a pattern none of
 * whose glob characters are part of a name on disk: that costs one `lstat`.
 *
 * A trailing `/**` is set aside first. Of the components that hold glob
 * characters, the leading ones that exist on disk as spelled are names:
 *
 * - When all of them exist, the entry is also the NAME it spells. What
 *   follows the last of them need not exist.
 * - When a pattern follows an existing one, the entry is also that pattern
 *   BENEATH the directory. There is one such reading per existing component,
 *   the longest first, so creating or removing a directory adds or removes a
 *   reading and never turns one into another.
 *
 * Whether a spelling is a pattern is decided on what the caller wrote
 * (`isPattern`); which components hold glob characters, by
 * {@link containsGlobChars} on every platform, since those are what the
 * pattern compiler and the walk take for syntax.
 *
 * A component exists for a deny as {@link mayBeThere} has it. For an allow
 * no component from the first with glob characters on may be a symbolic
 * link or beyond looking at: a name to its end, a pattern up to its first
 * pattern component, from where the walk of an allow goes through no link.
 */
export function literalReadings(
  spelling: string,
  kind: PathListKind,
  opts: { isPattern?: (spelling: string) => boolean } = {},
): PathReading[] {
  const isPattern = opts.isPattern ?? containsGlobCharsForPlatform
  let stripped = removeTrailingGlobSuffix(spelling)
  if (!isPattern(stripped)) {
    // Where `[` and `]` are no pattern syntax (Windows), `<dir>/**` is a
    // pattern by its `/**` alone, and the walk still reads the brackets as a
    // class: the `/**` stays on, as a pattern beneath the directory.
    if (stripped === spelling || !containsGlobChars(stripped)) return []
    stripped = spelling
  }
  const spelled = spelledAbsolute(stripped)
  if (spelled === undefined) return []

  const parts = spelled.split('/')
  const globAt = parts.flatMap((part, i) =>
    containsGlobChars(part) ? [i] : [],
  )
  const first = globAt[0]
  const last = globAt[globAt.length - 1]
  if (first === undefined || last === undefined) return []
  const prefix = (i: number): string => parts.slice(0, i + 1).join('/') || '/'

  const isThere = kind === 'deny' ? mayBeThere : isThereUnlinked
  let reach = first - 1
  while (reach < last && isThere(prefix(reach + 1))) reach++
  if (reach < first) return []

  const readings: PathReading[] = []
  if (
    reach === last &&
    (kind === 'deny' || restIsUnlinked(last, parts.length - 1, prefix))
  ) {
    readings.push({
      glob: false,
      path: normalizePathForSandbox(stripped, { literal: true }),
    })
  }

  // The tail keeps a trailing separator, which makes a pattern match nothing
  // (`/x/*/`): stripped, an allow spelled so would match every child. The
  // `/**` set aside above goes back on, for the walk's directory form.
  const setAside = stripped === spelling ? '' : '/**'
  for (let n = globAt.length - 2; n >= 0; n--) {
    const at = globAt[n]!
    if (at > reach) continue
    // As far as the directory's own name goes on: up to the next component
    // with glob characters, or to where the disk ends.
    const next = globAt[n + 1]!
    let end = Math.min(next - 1, reach)
    while (end >= at && !isDirectoryFor(kind, prefix(end))) end--
    if (end < at) continue
    // The walk resolves what the tail spells before its first pattern
    // component: a link there would have an allow list what it points at.
    if (kind === 'allow' && !restIsUnlinked(end, next - 1, prefix)) continue
    const anchor = normalizePathForSandbox(prefix(end), { literal: true })
    readings.push({
      glob: true,
      anchor,
      path: anchor + spelled.slice(prefix(end).length) + setAside,
    })
  }
  return readings
}

/**
 * Whether no component after `from`, up to `to`, is a symbolic link or
 * beyond looking at. What is not there yet is neither.
 */
function restIsUnlinked(
  from: number,
  to: number,
  prefix: (i: number) => string,
): boolean {
  for (let i = from + 1; i <= to; i++) {
    try {
      if (fs.lstatSync(prefix(i)).isSymbolicLink()) return false
    } catch (err) {
      return isAbsenceErrno(err)
    }
  }
  return true
}

/** Whether a spelling that reads as a pattern is also the name of a path. */
export function hasNameReading(spelling: string, kind: PathListKind): boolean {
  return literalReadings(spelling, kind).some(reading => !reading.glob)
}

/**
 * What a Linux read entry resolves to: what `expandGlob` returns for the
 * pattern, then what the entry's other readings add. `name` is the entry as
 * a name, in the caller's spelling.
 */
export function* withOtherReadings(
  spelling: string,
  name: string,
  kind: PathListKind,
  expandGlob: (pattern: string, anchor?: string) => Steps<string[]>,
): Steps<string[]> {
  const expansion = yield* expandGlob(spelling)
  const seen = new Set(expansion)
  const added: string[] = []
  for (const reading of literalReadings(spelling, kind)) {
    const found = reading.glob
      ? yield* expandGlob(reading.path, reading.anchor)
      : [name]
    for (const p of found) {
      if (seen.has(p)) continue
      seen.add(p)
      added.push(p)
    }
  }
  return [...expansion, ...added]
}

/**
 * The read rules `getDefaultWritePaths()` is given: the entries, the
 * credential denies, and the name each spelling also is, as a marked path.
 */
export function readRulesOf(
  denyRead: readonly FilesystemPathEntry[],
  allowRead: readonly FilesystemPathEntry[] | undefined,
  credentialDenies: readonly string[],
): {
  denyRead: FilesystemPathEntry[]
  allowRead: FilesystemPathEntry[] | undefined
} {
  const withNames = (
    entries: readonly FilesystemPathEntry[],
    kind: PathListKind,
  ): FilesystemPathEntry[] => [
    ...entries,
    ...spelledOf(entries).flatMap(spelling =>
      literalReadings(spelling, kind).flatMap(
        (reading): FilesystemPathEntry[] =>
          reading.glob ? [] : [{ path: reading.path, literal: true }],
      ),
    ),
  ]
  return {
    denyRead: withNames([...denyRead, ...credentialDenies], 'deny'),
    allowRead:
      allowRead === undefined ? undefined : withNames(allowRead, 'allow'),
  }
}

function nonEmptyLists<T extends Record<string, string[]>>(
  lists: T,
): Partial<T> {
  return Object.fromEntries(
    Object.entries(lists).filter(([, list]) => list.length > 0),
  ) as Partial<T>
}

/**
 * The `literal…` lists of a read config: the marked entries of the two read
 * lists. A key is present only when its list is not empty.
 */
export function literalReadLists(
  denyRead: readonly FilesystemPathEntry[] | undefined,
  allowRead: readonly FilesystemPathEntry[] | undefined,
): Pick<FsReadRestrictionConfig, 'literalDenyOnly' | 'literalAllowWithinDeny'> {
  return nonEmptyLists({
    literalDenyOnly: splitPathEntries(denyRead).marked,
    literalAllowWithinDeny: splitPathEntries(allowRead).marked,
  })
}

/** The `literal…` lists of a write config; see {@link literalReadLists}. */
export function literalWriteLists(
  allowWrite: readonly FilesystemPathEntry[] | undefined,
  denyWrite: readonly FilesystemPathEntry[] | undefined,
): Pick<
  FsWriteRestrictionConfig,
  'literalAllowOnly' | 'literalDenyWithinAllow'
> {
  return nonEmptyLists({
    literalAllowOnly: splitPathEntries(allowWrite).marked,
    literalDenyWithinAllow: splitPathEntries(denyWrite).marked,
  })
}

/**
 * Every path a write config allows, whichever list it came in on. Whoever
 * asks "may the command write here" asks this, not `allowOnly` alone: a
 * path the caller marked literal is in `literalAllowOnly` and nowhere else.
 */
export function writeRootsOf(
  config: Pick<FsWriteRestrictionConfig, 'allowOnly' | 'literalAllowOnly'>,
): string[] {
  return [...(config.allowOnly || []), ...(config.literalAllowOnly ?? [])]
}

/**
 * The paths bound back over a read deny: the read allows and the write
 * allows, the marked ones among them. A deny glob's matches are collapsed
 * against these, and one left out loses the matches beneath it their mask.
 */
export function reExposedBy(
  expandedAllowRead: readonly string[],
  allowRead: readonly FilesystemPathEntry[] | undefined,
  writeConfig: FsWriteRestrictionConfig,
): string[] {
  return [
    ...expandedAllowRead,
    ...splitPathEntries(allowRead).marked,
    ...writeRootsOf(writeConfig),
  ]
}

/**
 * A read config for a backend to which every path is a name (Linux): the
 * literal lists folded into the lists they are more entries of, and gone as
 * keys, so that whatever reads `denyOnly` has read them all.
 */
export function readNamesOf(
  config: FsReadRestrictionConfig | undefined,
): FsReadRestrictionConfig | undefined {
  if (!config) return config
  const { literalDenyOnly, literalAllowWithinDeny, ...rest } = config
  return {
    ...rest,
    denyOnly: [...(config.denyOnly || []), ...(literalDenyOnly ?? [])],
    ...(config.allowWithinDeny || literalAllowWithinDeny
      ? {
          allowWithinDeny: [
            ...(config.allowWithinDeny ?? []),
            ...(literalAllowWithinDeny ?? []),
          ],
        }
      : {}),
  }
}

/**
 * The same for a write config; see {@link readNamesOf}. A string of
 * `allowOnly` that holds glob characters is kept only when it is also the
 * name of a path (see {@link literalReadings}). Any other is a pattern and
 * no name: resolving a name folds a `..` by the text, so `/home/*\/../.ssh`
 * would make `/home/.ssh` writable where nothing is named `*`.
 */
export function writeNamesOf(
  config: FsWriteRestrictionConfig | undefined,
): FsWriteRestrictionConfig | undefined {
  if (!config) return config
  const { literalAllowOnly, literalDenyWithinAllow, ...rest } = config
  return {
    ...rest,
    allowOnly: writeRootsOf({
      allowOnly: (config.allowOnly || []).filter(
        p => !containsGlobChars(p) || hasNameReading(p, 'allow'),
      ),
      literalAllowOnly,
    }),
    denyWithinAllow: [
      ...(config.denyWithinAllow || []),
      ...(literalDenyWithinAllow ?? []),
    ],
  }
}
