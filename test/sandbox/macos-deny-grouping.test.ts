import { describe, it, expect, beforeAll, afterAll } from 'bun:test'
import { spawnSync } from 'node:child_process'
import {
  existsSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { wrapCommandWithSandboxMacOS } from '../../src/sandbox/macos-sandbox-utils.js'
import { quote } from '../../src/utils/shell-quote.js'
import { isMacOS } from '../helpers/platform.js'

/**
 * Many literal deny paths of the shape `<dir>/<name>/<leaf>` — git's
 * per-worktree registry is the common case — are folded into anchored
 * alternation regexes instead of one `subpath` filter per path. These tests
 * pin that the folded profile is small, compiles quickly, and enforces
 * exactly what the per-path filters did: each leaf is denied, its siblings
 * stay writable, the `<dir>/<name>` directory cannot be renamed away, and a
 * new `<dir>/<other>` can still be created.
 */
describe.if(isMacOS)('macOS literal deny grouping', () => {
  const TEST_BASE_DIR = join(
    realpathSync(tmpdir()),
    'seatbelt-group-test-' + Date.now(),
  )
  const ALLOWED_DIR = join(TEST_BASE_DIR, 'allowed')
  const GIT_DIR = join(ALLOWED_DIR, 'repo', '.git')
  const REGISTRY = join(GIT_DIR, 'worktrees')
  const LEAVES = ['commondir', 'config.worktree', 'config.worktree.lock']
  const NAMES = 1500
  const name = (i: number) => `feature-branch-${i}`

  const denyWithinAllow: string[] = []
  // Every regex metacharacter that can reach a grouped name (glob
  // characters `*?[]` divert a path away from grouping) plus the two
  // characters the SBPL string literal itself escapes, and a non-ASCII
  // name: each must match byte-for-byte once rendered into a regex. Listed
  // first so they share a chunk with the probed plain name below and a
  // mis-parsed alternative would show up as a chunk-mate matching wrongly.
  const ODD_NAME = 'odd.name+(1){2}^$|\\"q'
  const UNICODE_NAME = 'funci\u00f3n-\u540d\u524d'
  for (const n of [ODD_NAME, UNICODE_NAME]) {
    for (const leaf of LEAVES) {
      denyWithinAllow.push(join(REGISTRY, n, leaf))
    }
  }
  for (let i = 0; i < NAMES; i++) {
    for (const leaf of LEAVES) {
      denyWithinAllow.push(join(REGISTRY, name(i), leaf))
    }
  }
  // A different leaf set forms its own group; a lone path stays literal.
  for (let i = 0; i < 5; i++) {
    denyWithinAllow.push(join(REGISTRY, `partial-${i}`, 'commondir'))
  }
  const LONE = join(ALLOWED_DIR, 'other', 'single', 'file')
  denyWithinAllow.push(LONE)
  // Under a deep directory a valid (<= 255 byte) name can still push the
  // group's regex past sandbox-exec's string cap; such names fall back to
  // literal filters, budgeted in bytes — the unit the cap is in — so a
  // non-ASCII name that is short in characters is not mis-grouped.
  const DEEP_REGISTRY = join(
    ALLOWED_DIR,
    'd'.repeat(200),
    'd'.repeat(200),
    'd'.repeat(200),
    'reg',
  )
  const LONG_NAMES = [
    'a'.repeat(240),
    'b'.repeat(240),
    'c'.repeat(240),
    '\u00e9'.repeat(120),
  ]
  for (const n of LONG_NAMES) {
    for (const leaf of LEAVES) {
      denyWithinAllow.push(join(DEEP_REGISTRY, n, leaf))
    }
  }

  function wrap(command: string): string {
    return wrapCommandWithSandboxMacOS({
      command,
      needsNetworkRestriction: false,
      readConfig: undefined,
      writeConfig: { allowOnly: [ALLOWED_DIR], denyWithinAllow },
    })
  }

  beforeAll(() => {
    for (const n of [name(7), ODD_NAME, UNICODE_NAME, 'partial-2']) {
      mkdirSync(join(REGISTRY, n), { recursive: true })
      writeFileSync(join(REGISTRY, n, 'commondir'), '../..\n')
    }
    mkdirSync(join(ALLOWED_DIR, 'other', 'single'), { recursive: true })
  })

  afterAll(() => {
    if (existsSync(TEST_BASE_DIR)) {
      rmSync(TEST_BASE_DIR, { recursive: true, force: true })
    }
  })

  it('renders each group as chunked regexes under the SBPL string cap', () => {
    const wrapped = wrap('true')
    const regexes =
      wrapped.match(/\(regex "(?:[^"\\]|\\.)*worktrees(?:[^"\\]|\\.)*"\)/g) ??
      []
    expect(regexes.length).toBeGreaterThan(2)
    for (const filter of regexes) {
      expect(Buffer.byteLength(filter)).toBeLessThan(1025)
    }
    // No per-path subpath filter survives for a grouped path.
    for (const n of [name(7), ODD_NAME, UNICODE_NAME]) {
      expect(wrapped).not.toContain(`(subpath "${join(REGISTRY, n)}`)
    }
    // The metacharacter and non-ASCII names sit in the same alternation as
    // the probed plain name, escaped (regex) then escaped again (SBPL
    // string literal).
    const firstDeny = regexes.find(r => r.includes(`|${name(7)}|`))
    expect(firstDeny).toBeDefined()
    expect(firstDeny).toContain(
      String.raw`(odd\\.name\\+\\(1\\)\\{2\\}\\^\\$\\|\\\\\"q|` +
        UNICODE_NAME +
        '|',
    )
    // The lone path is still a plain subpath filter.
    expect(wrapped).toContain(`(subpath "${LONE}")`)
    // A name too long for its group's regex is emitted literally rather
    // than in a regex sandbox-exec would refuse.
    for (const n of LONG_NAMES) {
      expect(wrapped).toContain(
        `(subpath "${join(DEEP_REGISTRY, n, 'commondir')}")`,
      )
    }
    for (const filter of wrapped.match(/\(regex "(?:[^"\\]|\\.)*"\)/g) ?? []) {
      expect(Buffer.byteLength(filter)).toBeLessThan(1025)
    }
    // Bytes: well under what one subpath filter per path would cost.
    expect(Buffer.byteLength(wrapped)).toBeLessThan(200 * 1024)
  })

  it('compiles quickly', () => {
    const start = performance.now()
    const result = spawnSync('/bin/bash', ['-c', wrap('true')], {
      encoding: 'utf8',
      timeout: 30000,
    })
    expect(result.status).toBe(0)
    expect(performance.now() - start).toBeLessThan(5000)
  })

  it('enforces the per-path semantics', () => {
    const entry = join(REGISTRY, name(7))
    const odd = join(REGISTRY, ODD_NAME)
    const uni = join(REGISTRY, UNICODE_NAME)
    const partial = join(REGISTRY, 'partial-2')
    const fresh = join(REGISTRY, 'brand-new')
    const q = (p: string) => quote([p])
    const script = [
      `echo x > ${q(`${entry}/commondir`)} && echo WROTE-LEAF`,
      `echo x > ${q(`${entry}/config.worktree`)} && echo WROTE-LEAF-2`,
      `echo x > ${q(`${entry}/other`)} && echo WROTE-SIBLING`,
      `mv ${q(entry)} ${q(`${REGISTRY}/moved`)} && echo MOVED-ENTRY`,
      `mkdir ${q(fresh)} && echo x > ${q(`${fresh}/commondir`)} && echo CREATED-NEW`,
      `echo x > ${q(`${odd}/commondir`)} && echo WROTE-ODD`,
      `echo x > ${q(`${odd}/other`)} && echo WROTE-ODD-SIBLING`,
      `mv ${q(odd)} ${q(`${REGISTRY}/moved-odd`)} && echo MOVED-ODD`,
      `echo x > ${q(`${uni}/commondir`)} && echo WROTE-UNICODE`,
      `echo x > ${q(`${uni}/other`)} && echo WROTE-UNICODE-SIBLING`,
      `mv ${q(uni)} ${q(`${REGISTRY}/moved-uni`)} && echo MOVED-UNICODE`,
      `echo x > ${q(`${partial}/commondir`)} && echo WROTE-PARTIAL`,
      `echo x > ${q(`${partial}/config.worktree`)} && echo WROTE-PARTIAL-OTHER-LEAF`,
      `echo x > ${q(LONE)} && echo WROTE-LONE`,
    ].join('; ')
    const result = spawnSync('/bin/bash', ['-c', wrap(script)], {
      encoding: 'utf8',
      timeout: 30000,
    })
    expect(result.error).toBeUndefined()
    const out = result.stdout
    expect(out).not.toContain('WROTE-LEAF')
    expect(out).toContain('WROTE-SIBLING')
    expect(out).not.toContain('MOVED-ENTRY')
    expect(out).toContain('CREATED-NEW')
    expect(out).not.toContain('WROTE-ODD\n')
    expect(out).toContain('WROTE-ODD-SIBLING')
    expect(out).not.toContain('MOVED-ODD')
    expect(out).not.toContain('WROTE-UNICODE\n')
    expect(out).toContain('WROTE-UNICODE-SIBLING')
    expect(out).not.toContain('MOVED-UNICODE')
    expect(out).not.toContain('WROTE-PARTIAL\n')
    expect(out).toContain('WROTE-PARTIAL-OTHER-LEAF')
    expect(out).not.toContain('WROTE-LONE')
    for (const dir of [entry, odd, uni]) {
      expect(readFileSync(join(dir, 'commondir'), 'utf8')).toBe('../..\n')
      expect(existsSync(dir)).toBe(true)
    }
    expect(existsSync(join(fresh, 'commondir'))).toBe(true)
  })
})
