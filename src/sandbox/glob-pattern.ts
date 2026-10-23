/**
 * The glob syntax of a filesystem entry. {@link parseGlob} alone reads it;
 * what else needs it goes by the tokens.
 */

import { logForDebugging } from '../utils/debug.js'

export enum GlobTokenKind {
  /** Characters that stand for themselves, none of them a separator. */
  Text = 'text',
  /** `/` */
  Separator = 'separator',
  /** `?`: one character of a name. */
  AnyChar = 'anyChar',
  /** `*`: any number of characters of a name. */
  Star = 'star',
  /** `**`: any number of characters, separators among them. */
  Globstar = 'globstar',
  /** `**` with the `/` after it: any number of directories. */
  GlobstarSlash = 'globstarSlash',
  /** `[abc]`, `[a-z]`: one character of a set. `[!abc]`: one outside it. */
  Set = 'set',
}

export type GlobToken =
  | { kind: GlobTokenKind.Text; text: string }
  | {
      kind: GlobTokenKind.Set
      /** What is written between the brackets, after a `!` or `^` that negates. */
      members: string
      /** `[!abc]`, `[^abc]`: a character that is no member, and no `/`. */
      negated: boolean
      /** `[+-9]` does: a `/` lies between the two. A negated set never does. */
      matchesSeparator: boolean
    }
  | { kind: GlobTokenKind.Separator | GlobTokenKind.AnyChar | WildcardKind }

/** The kinds that match any number of characters. */
type WildcardKind =
  | GlobTokenKind.Star
  | GlobTokenKind.Globstar
  | GlobTokenKind.GlobstarSlash

/**
 * The ranges that `members` spells, a single character as a range of one, in
 * UTF-16 code units as a regular expression without the `u` flag reads them.
 * A `-` is a member where it is the first or the last. Undefined where they
 * spell no set: there are none, or a range runs backwards (`[user-id]`: `r-i`).
 */
function setRanges(members: string): [from: number, to: number][] | undefined {
  if (members === '') return undefined
  const ranges: [number, number][] = []
  for (let i = 0; i < members.length; i++) {
    const isRange = members[i + 1] === '-' && i + 2 < members.length
    const from = members.charCodeAt(i)
    if (isRange) i += 2
    const to = members.charCodeAt(i)
    if (to < from) return undefined
    ranges.push([from, to])
  }
  return ranges
}

const SEPARATOR = '/'.charCodeAt(0)

/**
 * `pattern` as its tokens, in time that grows with its length. Every string
 * is a pattern, and no character escapes another:
 *
 * - A set runs from a `[` to the first `]` after it, be that the next
 *   character. A `!` or a `^` straight after the `[` negates it. All else
 *   between the two are members, a `*`, a `?`, a `/` or another `[` too.
 * - Brackets that spell no set (see {@link setRanges}) are text, as POSIX
 *   reads a `[` that opens none, and what is between them keeps its meaning:
 *   `[!]` and `[^]` have no members. So are a `[` that nothing closes and a
 *   `]` that nothing opens.
 * - Of a run of `*`, the last two go with a `/` that follows. Two or more of
 *   the rest are a `**`.
 */
export function parseGlob(pattern: string): GlobToken[] {
  const tokens: GlobToken[] = []
  let textStart = 0
  const endText = (at: number): void => {
    if (textStart < at) {
      const text = pattern.slice(textStart, at)
      tokens.push({ kind: GlobTokenKind.Text, text })
    }
  }
  /**
   * Adds a wildcard that stands right after the last token. Wildcards side by
   * side are kept to the fewest that match the same, two at most: a regular
   * expression tries every way to share a path out among them, which takes a
   * power of its length.
   */
  const addWildcard = (kind: WildcardKind): void => {
    const { Star, Globstar, GlobstarSlash } = GlobTokenKind
    const kindAt = (fromEnd: number): GlobTokenKind | undefined =>
      tokens[tokens.length - fromEnd]?.kind
    // A `**` matches whatever there is, with any of them after it. And
    // `**/**/` is `**/`.
    if (kindAt(1) === Globstar || kindAt(1) === kind) return
    // So it does with any before it. `*` `**/` `*` and `**/` `*` `**/` are
    // one too: whatever there is, is directories and then a name.
    const isGlobstar =
      kind === Globstar ||
      (kindAt(2) === kind &&
        (kindAt(1) === Star || kindAt(1) === GlobstarSlash))
    if (!isGlobstar) {
      tokens.push({ kind })
      return
    }
    while (kindAt(1) === Star || kindAt(1) === GlobstarSlash) tokens.pop()
    tokens.push({ kind: Globstar })
  }
  // Found to open no set once, for all of them: looking for a `]` from every
  // `[` anew takes the square of the length.
  let bracketsAreTextUntil = 0
  const noSets: string[] = []

  let i = 0
  while (i < pattern.length) {
    switch (pattern[i]) {
      case '/':
        endText(i)
        tokens.push({ kind: GlobTokenKind.Separator })
        textStart = ++i
        break
      case '?':
        endText(i)
        tokens.push({ kind: GlobTokenKind.AnyChar })
        textStart = ++i
        break
      case '*': {
        endText(i)
        const start = i
        while (pattern[i] === '*') i++
        const withSeparator = i - start >= 2 && pattern[i] === '/'
        const rest = i - start - (withSeparator ? 2 : 0)
        if (rest >= 2) addWildcard(GlobTokenKind.Globstar)
        if (rest === 1) addWildcard(GlobTokenKind.Star)
        if (withSeparator) addWildcard(GlobTokenKind.GlobstarSlash)
        textStart = withSeparator ? ++i : i
        break
      }
      case '[': {
        if (i < bracketsAreTextUntil) {
          i++
          break
        }
        const close = pattern.indexOf(']', i + 1)
        if (close === -1) {
          noSets.push(pattern.slice(i))
          bracketsAreTextUntil = pattern.length
          i++
          break
        }
        const negated = pattern[i + 1] === '!' || pattern[i + 1] === '^'
        const members = pattern.slice(i + (negated ? 2 : 1), close)
        const ranges = setRanges(members)
        if (ranges === undefined) {
          noSets.push(pattern.slice(i, close + 1))
          bracketsAreTextUntil = close + 1
          i++
          break
        }
        endText(i)
        tokens.push({
          kind: GlobTokenKind.Set,
          members,
          negated,
          matchesSeparator:
            !negated &&
            ranges.some(([from, to]) => from <= SEPARATOR && SEPARATOR <= to),
        })
        textStart = i = close + 1
        break
      }
      default:
        i++
    }
  }
  endText(i)
  if (noSets.length > 0) {
    logForDebugging(
      `[Sandbox] The brackets in ${noSets.join(', ')} spell no set of characters, so they are read as text: ${pattern}`,
      { level: 'warn' },
    )
  }
  return tokens
}

/** A regular expression that matches `text` and nothing else. */
export function escapeRegexLiteral(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

const DASH = '-'.charCodeAt(0)
const CARET = '^'.charCodeAt(0)

/**
 * The regular expression for a set, written the way JavaScript and the regex
 * engine of a macOS sandbox profile read alike. What that engine does with a
 * set, as measured on macOS 14, 15 and 26, and what is done about it:
 *
 * - A backslash is a member (`[^/\$]` leaves out `\` as well as `$`). So a
 *   member is written as it is, and a backslash doubled: one `\` to both.
 * - `[.`, `[:` and `[=` open a POSIX element, and the whole profile is refused
 *   where nothing closes it (`[[.]`). So the members go in ascending order,
 *   in which none of the three follows a `[`.
 * - A `-` is a member only where it is the first: a set that ends in one
 *   (`[a-]`) and a range that starts at one (`[--9]`) are refused. So one
 *   that stands for itself, or at either end of a range, goes first, and such
 *   a range is the `-` and the rest of it, from `.` or up to `,`.
 * - In a rule with the tail of {@link denyGlobRegex}, a negated set in which
 *   two neighbours are written apart (`[^/0-9]`, `[^/abc]`) is read as `[^/]`.
 *   So there they are written as one range (`[^/-9]`, `[^/a-c]`). That leaves
 *   a `-` beside a `,` or a `.`, which the line above keeps apart.
 *
 * In a set that is not negated a `^` goes last, where neither takes it to
 * negate. Beyond ASCII nothing is moved: sorted by code unit, the halves of
 * two characters outside the basic plane would part.
 */
function setToRegex(members: string, negated: boolean): string {
  const ranges = setRanges(members) ?? []
  if (negated) ranges.push([SEPARATOR, SEPARATOR])
  const isAscii = ([, to]: (typeof ranges)[number]): boolean => to < 0x80
  const merged: typeof ranges = []
  for (const [from, to] of ranges.filter(isAscii).sort(([a], [b]) => a - b)) {
    const last = merged[merged.length - 1]
    if (last !== undefined && from <= last[1] + (negated ? 1 : 0)) {
      last[1] = Math.max(last[1], to)
    } else {
      merged.push([from, to])
    }
  }
  const member = (code: number): string =>
    String.fromCharCode(code).replace('\\', '\\\\')
  let dash = ''
  let caret = ''
  let rest = ''
  for (let [from, to] of [...merged, ...ranges.filter(r => !isAscii(r))]) {
    if (from === DASH || to === DASH) {
      dash = '-'
      if (from === to) continue
      if (from === DASH) from++
      else to--
    }
    if (from === CARET && !negated) {
      caret = '^'
      if (from === to) continue
      from++
    }
    rest += from === to ? member(from) : `${member(from)}-${member(to)}`
  }
  const body = dash + rest + caret
  // Alone in its set, the `-` is as well written without one.
  return body === '-' ? body : `[${negated ? '^' : ''}${body}]`
}

/** The regular expression for what `token` matches. */
export function globTokenToRegex(token: GlobToken): string {
  switch (token.kind) {
    case GlobTokenKind.Text:
      return escapeRegexLiteral(token.text)
    case GlobTokenKind.Separator:
      return '/'
    case GlobTokenKind.AnyChar:
      return '[^/]'
    case GlobTokenKind.Star:
      return '[^/]*'
    case GlobTokenKind.Globstar:
      return '.*'
    case GlobTokenKind.GlobstarSlash:
      return '(.*/)?'
    case GlobTokenKind.Set:
      return setToRegex(token.members, token.negated)
  }
}

/**
 * Convert a glob pattern to a regular expression
 *
 * This implements gitignore-style pattern matching to match the behavior of the
 * `ignore` library used by the permission system.
 *
 * Supported patterns:
 * - * matches any characters except / (e.g., *.ts matches foo.ts but not foo/bar.ts)
 * - ** matches any characters including / (e.g., src/**\/*.ts matches all .ts files in src/)
 * - ? matches any single character except / (e.g., file?.txt matches file1.txt)
 * - [abc] matches any character in the set (e.g., file[0-9].txt matches file3.txt)
 * - [!abc] and [^abc] match any character outside the set, never a `/`
 *
 * Whatever a pattern spells, what is returned compiles, so that no entry keeps
 * a sandbox from starting (see {@link parseGlob}). Only its size can be more
 * than an engine takes.
 *
 * Shared between macOS sandbox profiles and Linux glob expansion.
 */
export function globToRegex(globPattern: string): string {
  return `^${parseGlob(globPattern).map(globTokenToRegex).join('')}$`
}

/**
 * Regex for a glob used in a DENY rule: {@link globToRegex} plus an optional
 * `/…` tail, so the deny covers everything beneath each match the way
 * `subpath` does for literals. Callers strip a trailing `/**` before the
 * pattern gets here (removeTrailingGlobSuffix), so `**\/secrets/**` arrives
 * as `**\/secrets` and, matched exactly, would deny only the directory
 * vnode while `secrets/key` stayed readable. This is what the Linux backend
 * already does (a deny masks the whole subtree). Only ever widens a deny.
 *
 * Takes a whole pattern, so every character in it is glob syntax: right for
 * the pattern reading of a spelling the caller wrote, which is what
 * `readRuleCovers` passes. A pattern anchored at a directory that is a
 * name on disk goes through the macOS `denyGlobEntryRegex`, which splices
 * that directory back in escaped and calls this for the tail.
 */
export function denyGlobRegex(normalizedGlob: string): string {
  // globToRegex() always returns '^…$'.
  return globToRegex(normalizedGlob).slice(0, -1) + '(/.*)?$'
}
