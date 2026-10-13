import { afterAll, beforeAll, describe, expect, it } from 'bun:test'
import * as fc from 'fast-check'
import {
  mkdirSync,
  mkdtempSync,
  readdirSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import {
  globToRegex,
  walkGlobPattern,
} from '../../src/sandbox/sandbox-utils.js'
import { isWindows } from '../helpers/platform.js'

/**
 * The walk reads a pattern one path component at a time; globToRegex reads
 * the same pattern as one regular expression over a whole path, and nothing
 * else in the tree holds the two together.
 *
 * Over trees with no symlinks, where every path below the base is reached by
 * exactly one name, the two must agree exactly: what the walk returns is what
 * the regular expression matches beneath the pattern's base. A pattern the
 * walk cannot split is in the sample too.
 *
 * Seeded, so a failure is reproducible, and bounded, so the suite stays fast.
 * Not run on Windows, where a path is spelled with the other separator.
 */

/** Names that put the interesting readings next to each other: a bracket set
 *  that can match a separator (`[+-9]` spans `/`), a `**` written against
 *  text, a name that is a prefix of another, and brackets that spell no set
 *  (`b-a` runs backwards). */
const NAME = fc.constantFrom(
  'a',
  'b',
  'ab',
  'cert',
  'certs',
  'x.pem',
  'y.pem',
  'a9',
  's',
  '[b-a]',
)

const SEGMENT = fc.constantFrom(
  'a',
  'b',
  'ab',
  '*',
  '**',
  '?',
  'a*',
  '*b',
  'c*t',
  '[ab]',
  '[s/]',
  '[+-9]',
  '[a*]',
  '**.pem',
  '[b-a]',
)

const LAST_SEGMENT = fc.constantFrom(
  '*',
  '**',
  '*.pem',
  'x.pem',
  '?.pem',
  '[xy].pem',
  '[+-9].pem',
)

const PATTERN_TAIL = fc
  .tuple(fc.array(SEGMENT, { maxLength: 3 }), LAST_SEGMENT)
  .map(([segments, last]) => [...segments, last].join('/'))

/** A tree as the relative paths of its files. */
const TREE = fc.array(fc.array(NAME, { minLength: 1, maxLength: 4 }), {
  minLength: 8,
  maxLength: 24,
})

function materialize(root: string, entries: string[][]): void {
  for (const entry of entries) {
    const file = join(root, ...entry)
    try {
      mkdirSync(dirname(file), { recursive: true })
      writeFileSync(file, '')
    } catch {
      // A name already used the other way round (a file where this one wants
      // a directory): the tree keeps whichever came first.
    }
  }
}

/** Every path below `dir`, directories included, as the walk would spell them. */
function pathsUnder(dir: string): string[] {
  const found: string[] = []
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, entry.name)
    found.push(p)
    if (entry.isDirectory()) found.push(...pathsUnder(p))
  }
  return found
}

describe.if(!isWindows)('property: walkGlobPattern against globToRegex', () => {
  let scratch: string
  const trees: { root: string; paths: string[] }[] = []

  beforeAll(() => {
    scratch = realpathSync(mkdtempSync(join(tmpdir(), 'glob-walk-prop-')))
    const samples = fc.sample(TREE, { numRuns: 4, seed: 20260918 })
    for (const [index, entries] of samples.entries()) {
      const root = join(scratch, `t${index}`)
      mkdirSync(root)
      materialize(root, entries)
      trees.push({ root, paths: pathsUnder(root) })
    }
  })

  afterAll(() => {
    rmSync(scratch, { recursive: true, force: true })
  })

  it('returns exactly the paths beneath the base that the regex matches', () => {
    /** Runs where the pattern had something to find, so that agreeing on
     *  nothing at all cannot carry the property. */
    let withMatches = 0
    fc.assert(
      fc.property(fc.nat(trees.length - 1), PATTERN_TAIL, (index, tail) => {
        const { root, paths } = trees[index]!
        const pattern = join(root, tail)
        // 's': the flag the walk compiles its own regular expressions with.
        const regex = new RegExp(globToRegex(pattern), 's')
        const expected = paths.filter(p => regex.test(p)).sort()
        if (expected.length > 0) withMatches++
        // `unlisted` is not compared: a base can be one of the generated
        // files, and a directory the walk really could not list would show
        // up as a path missing from `matches`.
        const walked = walkGlobPattern(pattern, {
          followSymlinkedDirectories: true,
        })
        expect(walked.matches.sort()).toEqual(expected)
      }),
      { seed: 20260918, numRuns: 500 },
    )
    expect(withMatches).toBeGreaterThan(100)
  })
})
