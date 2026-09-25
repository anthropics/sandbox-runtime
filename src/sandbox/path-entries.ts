/**
 * How an entry of `denyRead`, `allowRead`, `allowWrite` or `denyWrite` is
 * read: as the pattern its characters spell, as the path they name, or both.
 *
 * An entry is a pattern when it holds `*`, `?`, `[` or `]`. A directory may
 * hold those characters in its own name (`[WIP] project`, `notes (draft?)`),
 * and a caller that lists paths inside one means the paths. So an entry with
 * those characters keeps the pattern reading it always had, and is ALSO read
 * as what it names wherever the part of it that holds the characters exists
 * on disk. A caller that wants the name and nothing else marks the entry
 * `{ path, literal: true }`.
 *
 * The decision is made here and nowhere else, once per entry per wrap, by
 * the first stage that needs it: the manager on Linux (bubblewrap takes no
 * patterns, so the manager is where they are expanded), the profile builder
 * on macOS, `expandWindowsFsPaths` on Windows. What comes out is carried with
 * the entry from then on; no later stage looks at its characters again.
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
  stripExtendedPathPrefix,
  toForwardSlashes,
} from './sandbox-utils.js'
import type { FilesystemPathEntry } from './sandbox-config.js'
import type {
  FsReadRestrictionConfig,
  FsWriteRestrictionConfig,
} from './sandbox-schemas.js'

export { markedLiteralPath }

/**
 * Which way a list cuts. A reading added to a deny can only deny more, so a
 * deny takes every reading that may hold. A reading added to an allow opens
 * something, so an allow takes one only for a path that is there exactly as
 * spelled.
 */
export type PathListKind = 'allow' | 'deny'

/**
 * One reading of an entry. The same shape as the macOS builder's `PathEntry`,
 * so a reading is one without conversion.
 */
export type PathReading =
  /** The entry is the name of this path. */
  | { glob: false; path: string }
  /**
   * The entry is a pattern beneath `anchor`, a directory taken as the name it
   * is. `path` is `anchor` followed by the tail, and only the tail is
   * pattern.
   */
  | { glob: true; path: string; anchor: string }

/**
 * The spellings and the marked paths of a list, apart. Throws on an entry
 * that is neither: `initialize()` does not run the schema, and reading
 * `{ path }` either way would be a guess about a deny.
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
 * A key that tells entries apart by value: a marked entry is a new object
 * after every clone of the config, and `/x` is not `{ path: '/x' }`.
 */
export function pathEntryKey(entry: FilesystemPathEntry): string {
  return typeof entry === 'string'
    ? `s:${entry}`
    : `l:${markedLiteralPath(entry)}`
}

/**
 * The spelling made absolute the way {@link normalizePathForSandbox} does it
 * for a pattern, with no symlink resolved and a trailing separator kept: the
 * path the caller wrote, which is what the disk is asked about. Undefined
 * for a Windows UNC path, which is never probed (see {@link isUncPath}).
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
 * dangling or not: the name is taken. So does a path that could not be
 * looked at, because unreadable now is not absent: a command running as the
 * same user can make a parent unsearchable and undo that from inside the
 * next sandbox, and a deny it could switch off that way would be no deny.
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
 * Whether `p` is there and is not a symbolic link, for an allow. A link with
 * the name an entry spells is not the path the caller meant: whoever can
 * write the directory that holds it can plant one, and the allow would then
 * open what the link points at. Anything that cannot be looked at is not
 * there.
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
 * it. Empty for a spelling that does not read as a pattern (it is a name
 * already) and for a pattern none of whose glob characters are part of a
 * name on disk, which is every ordinary pattern: that one costs a single
 * `lstat`.
 *
 * A trailing `/**` is set aside first. Of the path components that hold glob
 * characters, the leading ones that exist on disk as spelled are names:
 *
 * - When all of them exist, the entry is also the NAME it spells. What
 *   follows the last of them need not exist.
 * - When a pattern follows an existing one, the entry is also that pattern
 *   BENEATH the directory, which is taken as the name it is. There is one
 *   such reading for each of the existing components, the longest first, so
 *   creating or removing a directory adds or removes a reading and never
 *   turns one into another.
 *
 * Whether a spelling is a pattern at all is decided on what the caller
 * wrote (`isPattern`, the platform's own check by default), as it always
 * was. Which components hold glob characters is decided by
 * {@link containsGlobChars} on every platform, because those are the
 * characters the pattern compiler and the walk take for syntax.
 *
 * For a deny, a component exists when something has its name, a symbolic
 * link included, or when it cannot be looked at. For an allow it exists only
 * as itself: no component from the first with glob characters on may be a
 * symbolic link, and none may be beyond looking at. That goes for a name to
 * its end and for a pattern up to its first pattern component, from where
 * the walk of an allow goes through no link.
 */
export function literalReadings(
  spelling: string,
  kind: PathListKind,
  opts: { isPattern?: (spelling: string) => boolean } = {},
): PathReading[] {
  const isPattern = opts.isPattern ?? containsGlobCharsForPlatform
  const stripped = removeTrailingGlobSuffix(spelling)
  if (!isPattern(stripped)) return []
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
    (kind === 'deny' || restIsUnlinked(parts.length - 1, last, prefix))
  ) {
    readings.push({
      glob: false,
      path: normalizePathForSandbox(stripped, { literal: true }),
    })
  }

  // The tail keeps a trailing separator, which makes a pattern match nothing
  // (`/x/*/`): stripped, an allow spelled so would start matching every
  // child. The `/**` set aside above goes back on, for the walk's directory
  // form.
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
    // The walk starts at the anchor followed by what the tail spells before
    // its first pattern component, and resolves that: a link there would
    // have an allow list what the link points at.
    if (kind === 'allow' && !restIsUnlinked(next - 1, end, prefix)) continue
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
  to: number,
  from: number,
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
 * What a Linux read entry resolves to: what `expandGlob` finds for the
 * pattern, exactly as it returns it, then what the entry's other readings
 * add. `name` is the entry as a name, in the caller's spelling like every
 * other name in these lists.
 */
export function withOtherReadings(
  spelling: string,
  name: string,
  kind: PathListKind,
  expandGlob: (pattern: string, anchor?: string) => string[],
): string[] {
  const expansion = expandGlob(spelling)
  const seen = new Set(expansion)
  const added: string[] = []
  for (const reading of literalReadings(spelling, kind)) {
    const found = reading.glob
      ? expandGlob(reading.path, reading.anchor)
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
 * The read rules `getDefaultWritePaths()` is given for a policy: its
 * entries, the credential denies, and beside each spelling the name it also
 * is, handed over as a marked path.
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

/** `lists` without the keys whose list is empty. */
function nonEmptyLists<T extends Record<string, string[]>>(
  lists: T,
): Partial<T> {
  return Object.fromEntries(
    Object.entries(lists).filter(([, list]) => list.length > 0),
  ) as Partial<T>
}

/**
 * The `literal…` lists of a read config: the marked entries of the two read
 * lists. A key is present only when its list is not empty, so a config
 * without marked entries gives the object it always gave.
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
 * name of a path (see {@link literalReadings}), the condition on which the
 * manager keeps one. Any other is a pattern that a caller of the backend
 * handed it, and no name: resolving a name folds a `..` by the text, so
 * `/home/*\/../.ssh` would make `/home/.ssh` writable where nothing is named
 * `*`. A path the caller marked is resolved like any name.
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
