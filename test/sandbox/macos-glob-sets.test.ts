import { describe, it, expect, afterAll, beforeAll } from 'bun:test'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, realpathSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { globToRegex } from '../../src/sandbox/sandbox-utils.js'
import { isMacOS, isWindows } from '../helpers/platform.js'

/**
 * globToRegex writes one string for two regex engines, JavaScript's and a
 * macOS sandbox profile's. Each case is a bracket set, the one-character
 * names it holds and some it does not: a deny of `x<set>` must refuse `x<c>`
 * for the first and leave the second readable, to both.
 *
 * A negated case leaves `x.` and `x0` out of its names: the README says how
 * the profile's engine reads a negated set with a member next to `/`.
 */
const CASES: [set: string, regex: string, holds: string, lacks: string][] = [
  ['[!$]', '[^/$]', 'a\\', '$'],
  ['[!a-c.]', '[^/a-c.]', 'd\\', 'ac'],
  ['[!\\]', '[^/\\\\]', 'a$', '\\'],
  ['[--0]', '[-.-0]', '-.0', '+1'],
  ['[+--]', '[-+-,]', '-+,', '.a'],
  ['[-]', '-', '-', 'a'],
  ['[a-]', '[-a]', '-a', 'b'],
]

describe.if(!isWindows)('bracket sets, as both regex engines read them', () => {
  let dir: string

  beforeAll(() => {
    dir = realpathSync(mkdtempSync(join(tmpdir(), 'glob-sets-')))
    for (const char of new Set(CASES.flatMap(c => [...c[2], ...c[3]]))) {
      writeFileSync(join(dir, `x${char}`), 'DATA')
    }
  })

  afterAll(() => {
    rmSync(dir, { recursive: true, force: true })
  })

  it('JavaScript', () => {
    for (const [set, regex, holds, lacks] of CASES) {
      const compiled = globToRegex(`/d/x${set}`)
      expect(compiled).toBe(`^/d/x${regex}$`)
      for (const char of holds + lacks) {
        expect([set, char, new RegExp(compiled).test(`/d/x${char}`)]).toEqual([
          set,
          char,
          holds.includes(char),
        ])
      }
    }
  })

  it.if(isMacOS)('sandbox-exec', () => {
    for (const [set, , holds, lacks] of CASES) {
      const deny = JSON.stringify(globToRegex(join(dir, `x${set}`)))
      const result = spawnSync(
        '/usr/bin/sandbox-exec',
        [
          '-p',
          `(version 1)(allow default)(deny file-read* (regex ${deny}))`,
          '/bin/sh',
          '-c',
          'for f in "$@"; do /bin/cat "$f" >/dev/null 2>&1 && printf "%s\\n" "$f"; done',
          'sh',
          ...[...holds, ...lacks].map(char => join(dir, `x${char}`)),
        ],
        { encoding: 'utf8', timeout: 10000 },
      )
      // A profile that does not load reads nothing: every case lacks a name.
      expect([set, result.stdout.split('\n').filter(Boolean)]).toEqual([
        set,
        [...lacks].map(char => join(dir, `x${char}`)),
      ])
    }
  })
})
