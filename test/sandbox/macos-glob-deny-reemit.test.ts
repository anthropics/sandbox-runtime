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
import { isMacOS, isWindows } from '../helpers/platform.js'

/**
 * Profile-text tests for how the macOS read section orders denies against
 * allowWithinDeny (Seatbelt is last-match-wins). These only inspect the
 * generated SBPL, so they run on every POSIX host; the read-side enforcement
 * tests that execute the profiles under sandbox-exec live in
 * allow-read.test.ts (the write-side ones are at the bottom of this file).
 *
 * Layout under test (see generateReadRules):
 *   (allow file-read*)
 *   (deny  file-read* <denyOnly>)
 *   (allow file-read* <allowWithinDeny>)
 *   (deny  file-read* <nested literal denies, every glob deny minus the
 *                      allows it covers>)
 *   (allow file-read* (literal "/"))          only when a deny covers "/"
 *   ...
 *   (deny file-write-unlink <read-denied paths inside write roots>)   last
 *
 * The invariant every test here leans on: after the allowWithinDeny block,
 * the read section only adds denies. Nothing readable-today becomes
 * readable, so each assertion is about a deny landing late enough.
 */

const HEADERS = {
  allowRead: '(allow file-read*\n',
  denyRead: '(deny file-read*\n',
  denyUnlink: '(deny file-write-unlink\n',
  metadata: '(allow file-read-metadata',
  rootReallow: '(allow file-read* (literal "/"))',
} as const

function readSection(profile: string): string {
  const start = profile.indexOf('; File read\n')
  const end = profile.indexOf('; File write')
  expect(start).toBeGreaterThanOrEqual(0)
  expect(end).toBeGreaterThan(start)
  return profile.slice(start, end)
}

/** Body of the trailing unlink rule, or '' when none was emitted. */
function trailingUnlinkRule(profile: string): string {
  const marker = profile.indexOf('; File read: keep read-denied paths')
  if (marker < 0) return ''
  const rule = profile.slice(marker)
  expect(rule).toContain(HEADERS.denyUnlink)
  return rule
}

/** Position of the allowWithinDeny allow rule inside the read section. */
function allowBlockIndex(read: string): number {
  const idx = read.indexOf(HEADERS.allowRead)
  expect(idx).toBeGreaterThanOrEqual(0)
  return idx
}

/**
 * The slice of the read section between the allowWithinDeny allow rule and
 * the directory-metadata allow: the late deny rule plus (optionally) the
 * root re-allow. Everything that must beat the allows has to be in here —
 * later rules (move-blocking) mention the same filters for other
 * operations, so `lastIndexOf` over the whole section would mislead.
 */
function lateBlock(read: string): string {
  const allowAt = allowBlockIndex(read)
  const metadataAt = read.indexOf(HEADERS.metadata)
  expect(metadataAt).toBeGreaterThan(allowAt)
  const afterAllow = read.slice(allowAt + HEADERS.allowRead.length, metadataAt)
  return afterAllow
}

function wrap(
  readConfig: { denyOnly: string[]; allowWithinDeny?: string[] },
  allowWrite?: string[],
): string {
  return wrapCommandWithSandboxMacOS({
    command: 'true',
    needsNetworkRestriction: false,
    readConfig,
    writeConfig: allowWrite
      ? { allowOnly: allowWrite, denyWithinAllow: [] }
      : undefined,
  })
}

// Every glob deny is rendered with the subtree tail so `x/**` (stripped
// upstream to `x`) still covers x's contents.
const ENV_GLOB = '^/work/proj/(.*/)?\\\\.env(/.*)?$'
const SECRETS_GLOB = '^/work/proj/(.*/)?secrets(/.*)?$'
const KEY_GLOB = '^/(.*/)?[^/]*\\\\.key(/.*)?$'

describe.if(!isWindows)('macOS read profile: glob denies vs allowRead', () => {
  it('re-emits a leaf glob deny after the allow block, uncarved', () => {
    const read = readSection(
      wrap({
        denyOnly: ['/work/proj/**/.env'],
        allowWithinDeny: ['/work/proj'],
      }),
    )
    const filter = `(regex "${ENV_GLOB}")`
    // Base deny layer, then re-emitted after the allow (and before the
    // directory-metadata allow — lateBlock() is bounded by both).
    expect(read.indexOf(filter)).toBeLessThan(allowBlockIndex(read))
    const late = lateBlock(read)
    expect(late).toContain(HEADERS.denyRead)
    expect(late).toContain(filter)
    // Nothing about the allow dir is subtracted from it: `.env` beats the
    // directory allow it lands inside.
    expect(read).not.toContain('require-not')
  })

  it('renders glob denies with a subtree tail in every deny layer', () => {
    const profile = wrap(
      {
        denyOnly: ['/work/proj/**/secrets', '/**/*.key'],
        allowWithinDeny: ['/work/proj'],
      },
      ['/work/proj'],
    )
    // Base deny + re-emit + read move-blocking + trailing unlink = 4.
    expect(profile.split(`(regex "${SECRETS_GLOB}")`).length - 1).toBe(4)
    expect(profile.split(`(regex "${KEY_GLOB}")`).length - 1).toBe(4)
    // Allows keep the exact-match regex.
    const allowGlob = readSection(
      wrap({ denyOnly: ['/work'], allowWithinDeny: ['/work/proj*'] }),
    )
    expect(allowGlob).toContain('(regex "^/work/proj[^/]*$")')
    expect(allowGlob).not.toContain('^/work/proj[^/]*(/.*)?$')
  })

  it('carves the allows a region-shaped glob covers out of its re-emit', () => {
    const read = readSection(
      wrap({
        denyOnly: ['/Users/me/**/*'],
        allowWithinDeny: ['/Users/me/proj', '/Users/me/other*'],
      }),
    )
    expect(lateBlock(read)).toContain(
      '(require-all (regex "^/Users/me/(.*/)?[^/]*(/.*)?$")' +
        ' (require-not (subpath "/Users/me/proj"))' +
        ' (require-not (regex "^/Users/me/other[^/]*$")))',
    )
  })

  it('carves a specific file allow out of a glob deny that covers it', () => {
    // Shape sandbox-manager produces under tlsTerminate: the trust bundle
    // is pushed into allowWithinDeny; a user `/**/*.crt` deny covers it.
    const bundle = '/private/tmp/srt-ca-abc/trust-bundle.crt'
    const read = readSection(
      wrap({
        denyOnly: ['/**/*.crt', '/work/proj/**/.env'],
        allowWithinDeny: ['/work/proj', bundle],
      }),
    )
    const late = lateBlock(read)
    const crtReemit =
      '(require-all (regex "^/(.*/)?[^/]*\\\\.crt(/.*)?$")' +
      ` (require-not (subpath "${bundle}")))`
    expect(late).toContain(crtReemit)
    // The `.env` glob does not cover the bundle, so it stays uncarved.
    expect(late).toContain(`  (regex "${ENV_GLOB}")\n`)
    // Deny-only: no allow of any kind follows the re-emitted denies.
    expect(late).not.toContain(HEADERS.rootReallow)
    expect(read.slice(read.indexOf(crtReemit))).not.toContain(HEADERS.allowRead)
  })

  it('still re-emits a literal deny nested under a literal allow', () => {
    const read = readSection(
      wrap({
        denyOnly: ['/work/proj/secrets'],
        allowWithinDeny: ['/work/proj'],
      }),
    )
    const filter = '(subpath "/work/proj/secrets")'
    expect(read.indexOf(filter)).toBeLessThan(allowBlockIndex(read))
    expect(lateBlock(read)).toContain(filter)
  })

  it('still re-emits a literal deny nested under a literal allow of "/"', () => {
    // '/' is a legal allowWithinDeny entry and re-opens every denied path,
    // so the nested deny only survives if it lands after the allow block.
    // Containment against it has to be root-aware: a `dir + '/'` prefix
    // spells '//' and matches nothing.
    const read = readSection(
      wrap({ denyOnly: ['/work/proj/secrets'], allowWithinDeny: ['/'] }),
    )
    const filter = '(subpath "/work/proj/secrets")'
    expect(read.indexOf(filter)).toBeLessThan(allowBlockIndex(read))
    expect(lateBlock(read)).toContain(filter)
  })

  it('does not re-emit a literal deny that no allow is nested in', () => {
    const read = readSection(
      wrap({
        denyOnly: ['/work/other'],
        allowWithinDeny: ['/work/proj'],
      }),
    )
    // Only the base (deny file-read*) rule; no late one is emitted.
    expect(read.split(HEADERS.denyRead).length - 1).toBe(1)
  })

  it('emits no late deny rule at all when there is nothing to re-emit', () => {
    const read = readSection(wrap({ denyOnly: ['/work/other'] }))
    expect(read.split(HEADERS.denyRead).length - 1).toBe(1)
    expect(read).not.toContain(HEADERS.rootReallow)
  })
})

describe.if(!isWindows)('macOS read profile: root re-allow placement', () => {
  it('lands after the re-emitted denies when denyOnly has "/"', () => {
    const read = readSection(
      wrap({
        denyOnly: ['/', '/work/proj/**/.env'],
        allowWithinDeny: ['/work/proj', '/usr', '/bin'],
      }),
    )
    const late = lateBlock(read)
    const rootAt = late.indexOf(HEADERS.rootReallow)
    expect(rootAt).toBeGreaterThan(late.indexOf(`(regex "${ENV_GLOB}")`))
    // And nothing but the root re-allow follows the late denies.
    expect(late.slice(rootAt + HEADERS.rootReallow.length).trim()).toBe('')
  })

  it('is also emitted when a glob deny matches "/" itself', () => {
    const read = readSection(
      wrap({ denyOnly: ['/*'], allowWithinDeny: ['/usr', '/bin'] }),
    )
    const rootAt = read.indexOf(HEADERS.rootReallow)
    expect(rootAt).toBeGreaterThan(0)
    // The `/*` re-emit (carved for the allows it covers) precedes it.
    const reemit =
      '(require-all (regex "^/[^/]*(/.*)?$")' +
      ' (require-not (subpath "/usr")) (require-not (subpath "/bin")))'
    expect(read.indexOf(reemit)).toBeGreaterThan(0)
    expect(read.indexOf(reemit)).toBeLessThan(rootAt)
  })

  it('is not emitted for globs that cannot match "/"', () => {
    const read = readSection(
      wrap({ denyOnly: ['/**/*.key'], allowWithinDeny: ['/work'] }),
    )
    expect(read).not.toContain(HEADERS.rootReallow)
  })
})

describe.if(!isWindows)('macOS profile: trailing unlink re-deny', () => {
  it('is omitted when there are no write roots', () => {
    const profile = wrap({
      denyOnly: ['/work/proj/**/.env', '/work/proj/secrets'],
      allowWithinDeny: ['/work/proj'],
    })
    expect(trailingUnlinkRule(profile)).toBe('')
  })

  it('lands after the write section, after the unlink/create re-allow', () => {
    const profile = wrap(
      { denyOnly: ['/work/proj/**/.env'], allowWithinDeny: ['/work/proj'] },
      ['/work/proj'],
    )
    const rule = trailingUnlinkRule(profile)
    expect(rule).toContain(`(regex "${ENV_GLOB}")`)
    const ruleAt = profile.indexOf(rule)
    expect(ruleAt).toBeGreaterThan(profile.indexOf('; File write'))
    expect(ruleAt).toBeGreaterThan(
      profile.indexOf('(allow file-write-unlink file-write-create\n'),
    )
    expect(ruleAt).toBeGreaterThan(profile.indexOf('(allow file-write*\n'))
    // Unlink only: creating a new file at a read-denied name stays allowed.
    expect(rule).not.toContain('file-write-create')
    // A glob rooted at the write root itself protects no ancestor dirs, so
    // rm of unrelated files inside the root keeps working.
    expect(rule).not.toContain('(literal ')
  })

  it('covers a literal deny below a write root, even with no allowRead', () => {
    const profile = wrap({ denyOnly: ['/work/proj/secrets'] }, ['/work/proj'])
    const rule = trailingUnlinkRule(profile)
    expect(rule).toContain('(subpath "/work/proj/secrets")')
  })

  it('skips literal denies at or above a write root', () => {
    // `/work` contains the root; `/work/proj` is the root; `/elsewhere` is
    // unrelated. Move-blocking in the read section still covers all three.
    const profile = wrap({ denyOnly: ['/work', '/work/proj', '/elsewhere'] }, [
      '/work/proj',
    ])
    expect(trailingUnlinkRule(profile)).toBe('')
  })

  it('protects ancestor dirs strictly between the entry and the write root', () => {
    const profile = wrap(
      { denyOnly: ['/work/proj/a/b/secret', '/work/proj/conf/*.pem'] },
      ['/work/proj'],
    )
    const rule = trailingUnlinkRule(profile)
    expect(rule).toContain('(literal "/work/proj/a/b")')
    expect(rule).toContain('(literal "/work/proj/a")')
    expect(rule).toContain('(literal "/work/proj/conf")')
    expect(rule).not.toContain('(literal "/work/proj")')
    expect(rule).not.toContain('(literal "/work")')
  })

  it('carves nested allows and nested write roots out of a literal entry', () => {
    const profile = wrap(
      {
        denyOnly: ['/work/proj/secrets'],
        allowWithinDeny: ['/work/proj/secrets/pub'],
      },
      ['/work/proj', '/work/proj/secrets/scratch'],
    )
    const rule = trailingUnlinkRule(profile)
    expect(rule).toContain(
      '(require-all (subpath "/work/proj/secrets")' +
        ' (require-not (subpath "/work/proj/secrets/pub"))' +
        ' (require-not (subpath "/work/proj/secrets/scratch")))',
    )
  })

  it('carves the allows and write roots a region glob covers (#171 shape)', () => {
    const profile = wrap(
      { denyOnly: ['/Users/me/**/*'], allowWithinDeny: ['/Users/me/proj'] },
      ['/Users/me/proj', '/Users/me/.cache', '/private/tmp/claude'],
    )
    const rule = trailingUnlinkRule(profile)
    // proj is both an allow and a write root — carved once. .cache is only
    // a write root but the glob covers it, so rm there keeps working. The
    // /private/tmp root is outside the glob and needs no carve.
    expect(rule).toContain(
      '(require-all (regex "^/Users/me/(.*/)?[^/]*(/.*)?$")' +
        ' (require-not (subpath "/Users/me/proj"))' +
        ' (require-not (subpath "/Users/me/.cache")))',
    )
    expect(rule).not.toContain('/private/tmp/claude')
  })

  it('skips globs whose region is disjoint from every write root', () => {
    const profile = wrap({ denyOnly: ['/Users/me/.aws/*'] }, ['/work/proj'])
    expect(trailingUnlinkRule(profile)).toBe('')
  })

  it('includes root-anchored globs without protecting any ancestors', () => {
    const profile = wrap({ denyOnly: ['/**/*.key'] }, ['/work/proj'])
    const rule = trailingUnlinkRule(profile)
    expect(rule).toContain(`(regex "${KEY_GLOB}")`)
    expect(rule).not.toContain('(literal ')
  })

  it('is conservative (emitted) when a write root is itself a glob', () => {
    const profile = wrap({ denyOnly: ['/Users/me/.aws/*'] }, ['/scratch/*'])
    const rule = trailingUnlinkRule(profile)
    expect(rule).toContain('(regex "^/Users/me/\\\\.aws/[^/]*(/.*)?$")')
    // The glob root's exact-match filter is what the read section re-allowed,
    // so it is what gets carved when the deny covers it — here it doesn't.
    expect(rule).not.toContain('require-not')
  })
})

describe.if(!isWindows)(
  'macOS write profile: glob denies get the subtree tail',
  () => {
    it('renders a stripped denyWrite glob so it covers the directory contents', () => {
      // sandbox-manager strips a trailing /** before the pattern gets here, so
      // denyWrite: ["<proj>/**/secrets/**"] arrives as "<proj>/**/secrets".
      const profile = wrapCommandWithSandboxMacOS({
        command: 'true',
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig: {
          allowOnly: ['/work/proj'],
          denyWithinAllow: ['/work/proj/**/secrets'],
        },
      })
      const writeSection = profile.slice(profile.indexOf('; File write'))
      expect(writeSection).toContain(
        `(deny file-write*\n  (regex "^/work/proj/(.*/)?secrets(/.*)?$")`,
      )
      // allowWrite globs are unchanged (exact match, as before).
      const allowGlob = wrapCommandWithSandboxMacOS({
        command: 'true',
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig: { allowOnly: ['/work/out-*'], denyWithinAllow: [] },
      })
      expect(allowGlob).toContain('(regex "^/work/out-[^/]*$")')
      expect(allowGlob).not.toContain('^/work/out-[^/]*(/.*)?$')
    })
  },
)

describe.if(isMacOS)('macOS write enforcement for glob denies', () => {
  const BASE = join(realpathSync(tmpdir()), 'glob-deny-write-' + Date.now())
  const PROJECT = join(BASE, 'project')
  const ORIGINAL = 'ORIGINAL'
  let originalCwd = ''

  beforeAll(() => {
    originalCwd = process.cwd()
    mkdirSync(join(PROJECT, 'secrets'), { recursive: true })
    writeFileSync(join(PROJECT, 'secrets', 'existing'), ORIGINAL)
    mkdirSync(join(PROJECT, 'vendor', 'dep', '.git', 'hooks'), {
      recursive: true,
    })
    writeFileSync(
      join(PROJECT, 'vendor', 'dep', '.git', 'hooks', 'pre-commit'),
      ORIGINAL,
    )
    writeFileSync(join(PROJECT, 'plain.txt'), ORIGINAL)
  })

  afterAll(() => {
    process.chdir(originalCwd)
    rmSync(BASE, { recursive: true, force: true })
  })

  function runWrite(
    command: string,
    denyWithinAllow: string[] = [],
  ): { error?: Error } {
    const wrapped = wrapCommandWithSandboxMacOS({
      command,
      needsNetworkRestriction: false,
      readConfig: undefined,
      writeConfig: { allowOnly: [PROJECT], denyWithinAllow },
    })
    return spawnSync(wrapped, { shell: true, encoding: 'utf8', timeout: 10000 })
  }

  it('a stripped **/secrets denyWrite blocks writes inside the directory', () => {
    const existing = join(PROJECT, 'secrets', 'existing')
    const fresh = join(PROJECT, 'secrets', 'fresh')
    const r = runWrite(
      `echo X > ${existing}; echo X > ${fresh}; echo X > ${join(PROJECT, 'plain.txt')}`,
      [join(PROJECT, '**', 'secrets')],
    )
    expect(r.error).toBeUndefined()
    expect(readFileSync(existing, 'utf8')).toBe(ORIGINAL)
    expect(existsSync(fresh)).toBe(false)
    // The sibling outside the deny is still writable.
    expect(readFileSync(join(PROJECT, 'plain.txt'), 'utf8')).toBe('X\n')
  })

  it("mandatory **/.git/hooks/** still blocks a nested repo's hooks (regression guard)", () => {
    // The mandatory patterns are anchored at process.cwd(); this pattern
    // already carried its own /** tail before the subtree change, so this
    // guards that the change keeps it working rather than fixing it.
    process.chdir(PROJECT)
    const hook = join(PROJECT, 'vendor', 'dep', '.git', 'hooks', 'pre-commit')
    const newHook = join(
      PROJECT,
      'vendor',
      'dep',
      '.git',
      'hooks',
      'post-checkout',
    )
    const r = runWrite(`echo X > ${hook}; echo X > ${newHook}`)
    expect(r.error).toBeUndefined()
    expect(readFileSync(hook, 'utf8')).toBe(ORIGINAL)
    expect(existsSync(newHook)).toBe(false)
  })
})
