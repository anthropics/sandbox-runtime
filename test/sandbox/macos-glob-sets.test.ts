import { describe, it, expect, afterAll, beforeAll } from 'bun:test'
import { spawnSync } from 'node:child_process'
import {
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { denyGlobRegex, globToRegex } from '../../src/sandbox/glob-pattern.js'
import { isMacOS } from '../helpers/platform.js'

/**
 * globToRegex writes one string for two regex engines, JavaScript's and a
 * macOS sandbox profile's. What a pattern means is glob-pattern.test.ts's;
 * here it is that both engines read what is written for a set alike.
 */

/** The characters the two disagree about, and a neighbour of each. */
const TRICKY = [...'-,.0:=[\\^ab']
/** Every set of one or two of them, and what only a range shows. */
const SETS = [
  ...TRICKY,
  ...TRICKY.flatMap(a => TRICKY.map(b => a + b)),
  ...['--0', '+--', '+-9', 'a-c.', '0-9', 'x^-z', '[:alpha:', '$', 'cab'],
  ...['\\-a', '-+.', ',.-'],
].flatMap(body => [`[${body}]`, `[!${body}]`])

describe('a bracket set, as it is written', () => {
  it.each([
    // Neighbours as one range, the `/` of a negated set among them.
    ['[!0-9]', '[^/-9]'],
    ['[!.]', '[^.-/]'],
    ['[!cab]', '[^/a-c]'],
    ['[!$]', '[^$/]'],
    // In ascending order, so that no `[` opens a POSIX element.
    ['[[.]', '[.[]'],
    ['[[:alpha:]', '[:[ahlp]'],
    // A `-` first, and a range that starts or ends at one without it.
    ['[a-]', '[-a]'],
    ['[!-a]', '[^-/a]'],
    ['[--0]', '[-.-0]'],
    ['[+--]', '[-+-,]'],
    // A `^` last, a backslash doubled, and a `-` alone without a set.
    ['[a^]', '[a^]'],
    ['[x^-z]', '[_-z^]'],
    ['[!\\]', '[^/\\\\]'],
    ['[-]', '-'],
    // Beyond ASCII as written, after the rest.
    ['[😀😁a]', '[a😀😁]'],
    ['[!😀😁]', '[^/😀😁]'],
  ])('%s is %s', (set, regex) => {
    expect(globToRegex(`/d/${set}`)).toBe(`^/d/${regex}$`)
  })

  it('holds nothing the profile engine was seen to refuse or misread', () => {
    const one = String.raw`(?:\\\\|[^\\\]-])`
    const wellFormed = new RegExp(`^\\^?-?(?:${one}(?:-${one})?)+$`)
    const bad: string[] = []
    let bodies = ['']
    for (let length = 1; length <= 4; length++) {
      bodies = bodies.flatMap(body => TRICKY.map(char => body + char))
      for (const glob of bodies.flatMap(b => [`[${b}]`, `[!${b}]`])) {
        const regex = globToRegex(glob).slice(1, -1)
        // Text, or a `-` that needs no set.
        if (!regex.startsWith('[')) continue
        const set = regex.slice(1, -1)
        // Apart from the `-`, which has to stand first, no two neighbours of
        // a negated set are written apart.
        const rest = [...set.replace(/^\^-?/, '').replace(/\\\\/g, '\\')]
        const codes = (beside: -1 | 1): number[] =>
          rest
            .filter((char, i) => char !== '-' && rest[i + beside] !== '-')
            .map(char => char.charCodeAt(0))
        const ends = codes(1)
        if (
          !wellFormed.test(set) ||
          /\[[.:=]/.test(set) ||
          set.startsWith('^') !== /^\[[!^]/.test(glob) ||
          (set.startsWith('^') &&
            codes(-1)
              .slice(1)
              .some((start, i) => start <= ends[i]! + 1))
        ) {
          bad.push(`${glob} is written ${regex}`)
        }
      }
    }
    expect(bad.slice(0, 10)).toEqual([])
  })
})

describe.if(isMacOS)('a bracket set, as a sandbox profile reads it', () => {
  const NAMES = [...new Set([...TRICKY, ...'+1]c!$z'])].map(char => `x${char}`)
  const RULES = ['deny', 'allow', 'carved']
  let dir: string

  beforeAll(() => {
    dir = realpathSync(mkdtempSync(join(tmpdir(), 'glob-sets-')))
    for (const rule of RULES) {
      mkdirSync(join(dir, rule))
      for (const name of NAMES) writeFileSync(join(dir, rule, name), '')
    }
  })

  afterAll(() => rmSync(dir, { recursive: true, force: true }))

  // The three places a pattern's regex goes: a deny, with its tail, an allow,
  // and what is carved out of a deny.
  it('as JavaScript does, in a deny, in an allow and in a carve-out', () => {
    const differing: string[] = []
    for (const set of SETS) {
      const regex = (rule: string, compile = globToRegex): string =>
        JSON.stringify(compile(join(dir, rule, `x${set}`)))
      const { stdout } = spawnSync(
        '/usr/bin/sandbox-exec',
        [
          '-p',
          `(version 1)(allow default)
           (deny file-read* (regex ${regex('deny', denyGlobRegex)}))
           (deny file-read* (subpath ${JSON.stringify(join(dir, 'allow'))}))
           (allow file-read* (regex ${regex('allow')}))
           (deny file-read* (require-all
             (subpath ${JSON.stringify(join(dir, 'carved'))})
             (require-not (regex ${regex('carved')}))))`,
          '/bin/sh',
          '-c',
          // By name: a directory denied whole lists nothing.
          'for f; do /bin/cat "$f" 2>/dev/null && echo "$f"; done',
          'sh',
          ...RULES.flatMap(rule => NAMES.map(name => `${rule}/${name}`)),
        ],
        { cwd: dir, encoding: 'utf8', timeout: 10000 },
      )
      // A profile that does not load reads nothing.
      const readable = stdout.split('\n')
      const matches = new RegExp(globToRegex(`x${set}`))
      // A `-` cannot be written into a range with its neighbours, and with
      // one of them a negated set is read as `[^/]` in a deny: wider.
      const widened = /^\^x\[\^-.*(,|\.-)/.test(matches.source)
      const wrong = RULES.flatMap(rule =>
        NAMES.filter(
          name =>
            readable.includes(`${rule}/${name}`) !==
            (rule === 'deny'
              ? !widened && !matches.test(name)
              : matches.test(name)),
        ).map(name => `${rule}/${name}`),
      )
      if (wrong.length > 0) {
        differing.push(`${set}, ${matches.source}: ${wrong.join(' ')}`)
      }
    }
    expect(differing).toEqual([])
  }, 120_000)
})
