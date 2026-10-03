/**
 * The entries of `denyRead`, `allowRead`, `allowWrite` and `denyWrite` as
 * configured: a spelling, which is a pattern when it holds `*`, `?`, `[` or
 * `]`, or a path marked `{ path, literal: true }`, which is the name and
 * nothing else, whatever it holds.
 *
 * Marked paths travel beside the spellings, in the `literal…` lists of the
 * restriction configs, so that no backend reads their characters again.
 */

import * as fs from 'node:fs'
import {
  containsGlobChars,
  expandTilde,
  markedLiteralPath,
} from './sandbox-utils.js'
import type { FilesystemPathEntry } from './sandbox-config.js'
import type {
  FsReadRestrictionConfig,
  FsWriteRestrictionConfig,
} from './sandbox-schemas.js'

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
  const keys = new Set(a.map(key))
  return b.every(entry => keys.has(key(entry)))
}

/**
 * Whether something is at `spelling`, as the kernel resolves it. `realpath`
 * cannot be asked: it folds a `..` by the text first.
 */
function isThereAsSpelled(spelling: string): boolean {
  try {
    fs.lstatSync(expandTilde(spelling))
    return true
  } catch {
    return false
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
 * `allowOnly` that holds glob characters is kept only when something is
 * there under that very spelling. Any other is a pattern and no name:
 * resolving a name folds a `..` by the text, so `/home/*\/../.ssh` would
 * make `/home/.ssh` writable where nothing is named `*`.
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
        p => !containsGlobChars(p) || isThereAsSpelled(p),
      ),
      literalAllowOnly,
    }),
    denyWithinAllow: [
      ...(config.denyWithinAllow || []),
      ...(literalDenyWithinAllow ?? []),
    ],
  }
}
