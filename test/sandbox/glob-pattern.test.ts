import { describe, expect, it } from 'bun:test'
import * as fc from 'fast-check'
import {
  globToRegex,
  GlobTokenKind as Kind,
  parseGlob,
  type GlobToken,
} from '../../src/sandbox/glob-pattern.js'

const text = (t: string): GlobToken => ({ kind: Kind.Text, text: t })
const set = (members: string, matchesSeparator = false): GlobToken => ({
  kind: Kind.Set,
  members,
  matchesSeparator,
})
const SEPARATOR: GlobToken = { kind: Kind.Separator }
const ANY_CHAR: GlobToken = { kind: Kind.AnyChar }
const STAR: GlobToken = { kind: Kind.Star }
const GLOBSTAR: GlobToken = { kind: Kind.Globstar }
const GLOBSTAR_SLASH: GlobToken = { kind: Kind.GlobstarSlash }

describe('parseGlob', () => {
  it.each<[string, GlobToken[]]>([
    ['', []],
    ['/a/b.ts', [SEPARATOR, text('a'), SEPARATOR, text('b.ts')]],
    ['*.t?', [STAR, text('.t'), ANY_CHAR]],
    ['a/**/b', [text('a'), SEPARATOR, GLOBSTAR_SLASH, text('b')]],
    ['a/**', [text('a'), SEPARATOR, GLOBSTAR]],
    ['a**b', [text('a'), GLOBSTAR, text('b')]],
    ['\\(', [text('\\(')]],
  ])('reads %p', (pattern, tokens) => {
    expect(parseGlob(pattern)).toEqual(tokens)
  })

  it.each<[string, GlobToken[]]>([
    ['*/', [STAR, SEPARATOR]],
    ['**/', [GLOBSTAR_SLASH]],
    ['***/', [STAR, GLOBSTAR_SLASH]],
    ['***', [GLOBSTAR]],
    ['****', [GLOBSTAR]],
  ])('gives the last two of the run %p to the separator', (run, tokens) => {
    expect(parseGlob(run)).toEqual(tokens)
  })

  it.each<[string, GlobToken[]]>([
    ['****/', [GLOBSTAR]],
    ['*****/', [GLOBSTAR]],
    ['**/**/', [GLOBSTAR_SLASH]],
    ['**/**', [GLOBSTAR]],
    ['***/**', [GLOBSTAR]],
    ['***/*', [GLOBSTAR]],
    ['**/***/', [GLOBSTAR]],
    ['***/***/***/', [GLOBSTAR]],
    ['a***/*b', [text('a'), GLOBSTAR, text('b')]],
  ])('keeps the wildcards of %p to the fewest', (pattern, tokens) => {
    expect(parseGlob(pattern)).toEqual(tokens)
  })

  it.each<[string, GlobToken[]]>([
    ['**/*', [GLOBSTAR_SLASH, STAR]],
    ['*a*', [STAR, text('a'), STAR]],
    ['*?*', [STAR, ANY_CHAR, STAR]],
    ['*/*', [STAR, SEPARATOR, STAR]],
    ['**/a**/', [GLOBSTAR_SLASH, text('a'), GLOBSTAR_SLASH]],
    ['**[a]**', [GLOBSTAR, set('a'), GLOBSTAR]],
  ])('keeps the wildcards of %p as they are', (pattern, tokens) => {
    expect(parseGlob(pattern)).toEqual(tokens)
  })

  it.each<[string, GlobToken[]]>([
    ['[abc]', [set('abc')]],
    ['x[a-z]y', [text('x'), set('a-z'), text('y')]],
    ['[-a]', [set('-a')]],
    ['[a-]', [set('a-')]],
    ['[a-a]', [set('a-a')]],
    ['[^a]', [set('^a')]],
    ['[!a]', [set('!a')]],
    ['[a[b]', [set('a[b')]],
    ['[a]]', [set('a'), text(']')]],
    ['[s/]', [set('s/', true)]],
    ['[+-9]', [set('+-9', true)]],
    ['[0-9]', [set('0-9')]],
    ['[*]', [set('*')]],
    ['[a?]', [set('a?')]],
    ['[*-a]', [set('*-a', true)]],
  ])('reads %p as a set', (pattern, tokens) => {
    expect(parseGlob(pattern)).toEqual(tokens)
  })

  it.each<[string, GlobToken[]]>([
    ['[z-a]', [text('[z-a]')]],
    ['[user-id]', [text('[user-id]')]],
    ['[]', [text('[]')]],
    ['[]a]', [text('[]a]')]],
    ['a]b', [text('a]b')]],
    ['a[b', [text('a[b')]],
    ['a[b[c', [text('a[b[c')]],
    ['[[z-a]', [text('[[z-a]')]],
    ['[z-a[b]', [text('[z-a[b]')]],
    ['[z-a][b]', [text('[z-a]'), set('b')]],
    // In code units: the halves of the two characters run backwards.
    ['[\u{1f600}-\u{1f601}]', [text('[\u{1f600}-\u{1f601}]')]],
  ])('reads the brackets of %p as text', (pattern, tokens) => {
    expect(parseGlob(pattern)).toEqual(tokens)
  })

  it.each<[string, GlobToken[]]>([
    ['[z-a*]', [text('[z-a'), STAR, text(']')]],
    ['[z-a/?]', [text('[z-a'), SEPARATOR, ANY_CHAR, text(']')]],
    ['a[b[c*', [text('a[b[c'), STAR]],
    ['[**/', [text('['), GLOBSTAR_SLASH]],
  ])('keeps what is between such brackets a pattern: %p', (pattern, tokens) => {
    expect(parseGlob(pattern)).toEqual(tokens)
  })

  it.each(['[', '[a', '[a]', '[z-a]', '[z-a[', '*', '?'])(
    'takes time that grows with the length: 1,000,000 characters of %p',
    unit => {
      const began = performance.now()
      parseGlob(unit.repeat(1_000_000 / unit.length))
      expect(performance.now() - began).toBeLessThan(2_000)
    },
  )
})

/** Whether `members` spell a set, and whether `char` is in it. */
function setOf(members: string): ((char: string) => boolean) | undefined {
  const ranges: [string, string][] = []
  for (let i = 0; i < members.length; i++) {
    const isRange = members[i + 1] === '-' && i + 2 < members.length
    ranges.push([members[i]!, members[isRange ? i + 2 : i]!])
    if (isRange) i += 2
  }
  if (ranges.length === 0 || ranges.some(([from, to]) => from > to)) {
    return undefined
  }
  return char => ranges.some(([from, to]) => from <= char && char <= to)
}

/**
 * The glob syntax matched directly, by backtracking: no tokens, and nothing
 * compiled. Shares nothing with {@link parseGlob} or {@link globToRegex}, so
 * the property below is two implementations checking each other.
 */
function referenceGlobMatch(pattern: string, pathText: string): boolean {
  const from = (
    p: number,
    s: number,
    bracketsAreTextUntil: number,
  ): boolean => {
    if (p === pattern.length) return s === pathText.length
    const rest = (p2: number, s2: number): boolean =>
      from(p2, s2, bracketsAreTextUntil)
    const head = pattern[p]!
    if (head === '*') {
      let stars = 0
      while (pattern[p + stars] === '*') stars++
      const directories = stars >= 2 && pattern[p + stars] === '/'
      const next = p + stars + (directories ? 1 : 0)
      if (directories) stars -= 2
      for (let end = s; end <= pathText.length; end++) {
        if (end > s && stars === 0) break
        if (end > s && stars === 1 && pathText[end - 1] === '/') break
        if (rest(next, end)) return true
        if (!directories) continue
        for (let i = end; i < pathText.length; i++) {
          if (pathText[i] === '/' && rest(next, i + 1)) return true
        }
      }
      return false
    }
    if (s === pathText.length) return false
    if (head === '?') return pathText[s] !== '/' && rest(p + 1, s + 1)
    if (head === '[' && p >= bracketsAreTextUntil) {
      const close = pattern.indexOf(']', p + 1)
      const has = close === -1 ? undefined : setOf(pattern.slice(p + 1, close))
      if (has !== undefined) return has(pathText[s]!) && rest(close + 1, s + 1)
      bracketsAreTextUntil = close === -1 ? pattern.length : close + 1
    }
    return pathText[s] === head && from(p + 1, s + 1, bracketsAreTextUntil)
  }
  return from(0, 0, 0)
}

describe('globToRegex', () => {
  it.each(['*', '?'])('takes a %p in a set for the character', wildcard => {
    const regex = new RegExp(globToRegex(`/tmp/a[${wildcard}]c`))
    expect(regex.test(`/tmp/a${wildcard}c`)).toBe(true)
    expect(regex.test('/tmp/abc')).toBe(false)
    expect(regex.test('/tmp/ac')).toBe(false)
    expect(regex.test(`/tmp/a[${wildcard}]c`)).toBe(false)
  })

  it('takes brackets with nothing in them for text', () => {
    const regex = new RegExp(globToRegex('/tmp/list[].ts'))
    expect(regex.test('/tmp/list[].ts')).toBe(true)
    expect(regex.test('/tmp/list.ts')).toBe(false)
  })

  it('takes every [ that nothing closes for text, before a wildcard too', () => {
    const regex = new RegExp(globToRegex('/tmp/a[b[c*'))
    expect(regex.test('/tmp/a[b[c and more')).toBe(true)
    expect(regex.test('/tmp/a[b[c/more')).toBe(false)
    expect(regex.test('/tmp/a[bc')).toBe(false)
  })

  it.each(['*', '**/', '***/', '**/*'])(
    'answers at once for 1,000 characters of %p',
    unit => {
      const regex = new RegExp(
        globToRegex(`/x/${unit.repeat(1_000 / unit.length)}y`),
      )
      const began = performance.now()
      expect(regex.test(`/x/${'a/'.repeat(40)}z`)).toBe(false)
      expect(regex.test(`/x/${'a/'.repeat(40)}y`)).toBe(true)
      expect(performance.now() - began).toBeLessThan(1_000)
    },
  )

  it('agrees with a reference matcher over generated patterns and paths', () => {
    const piece = fc.constantFrom(
      ...'[[]]--**??//az09+.^!\\',
      '**/',
      '[a-z]',
      '[z-a]',
      '[+-9]',
      '[*]',
      '[]',
    )
    const pattern = fc.array(piece, { maxLength: 8 }).map(p => p.join(''))
    // A path like the pattern, so that a match is not rare, or any at all.
    const char = fc.constantFrom(...'[]-*?/az09+.^!\\')
    const pathFor = (p: string): fc.Arbitrary<string> =>
      fc.oneof(
        fc.array(char, { maxLength: 6 }).map(chars => chars.join('')),
        fc
          .tuple(...[...p].map(c => fc.oneof(fc.constant(c), char)))
          .map(chars => chars.join('')),
      )
    let matches = 0
    fc.assert(
      fc.property(
        pattern.chain(p => fc.tuple(fc.constant(p), pathFor(p))),
        ([p, f]) => {
          const expected = referenceGlobMatch(p, f)
          if (expected) matches++
          expect(new RegExp(globToRegex(p)).test(f)).toBe(expected)
        },
      ),
      { seed: 20261015, numRuns: 20_000 },
    )
    expect(matches).toBeGreaterThan(1_000)
  })
})
