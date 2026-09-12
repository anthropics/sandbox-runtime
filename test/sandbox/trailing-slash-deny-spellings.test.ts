import { describe, it, expect, beforeEach, afterEach } from 'bun:test'
import {
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import {
  wrapCommandWithSandboxLinux,
  cleanupBwrapMountPoints,
} from '../../src/sandbox/linux-sandbox-utils.js'
import { wrapCommandWithSandboxMacOS } from '../../src/sandbox/macos-sandbox-utils.js'
import { normalizePathForSandbox } from '../../src/sandbox/sandbox-utils.js'
import { isLinux, isWindows } from '../helpers/platform.js'

/**
 * Trailing-slash spellings.
 *
 * The sandbox builders compare path spellings by exact match and
 * `path + '/'` prefixes, which a preserved trailing slash silently defeats
 * ('<dir>//' matches nothing). normalizePathForSandbox therefore strips
 * trailing slashes from non-glob spellings at the shared chokepoint, so
 * every consumer on the Linux and macOS paths sees one canonical form.
 * Confirmed pre-fix failure modes covered below:
 *
 * - Linux denyRead '<dir>/': records a tmpfs the hidden-by-tmpfs emission
 *   filter can never match, so a denyWrite bind beneath it is emitted AFTER
 *   the tmpfs and re-mounts the read-denied host contents readable.
 * - Linux allowWithinDeny + allowOnly sharing a slashed spelling: the
 *   re-allow skip in the tmpfs re-bind pass depends on both sides using the
 *   same spelling, or an extra ro-bind stacks over the writable re-bind and
 *   the allowed write dir becomes read-only (EROFS).
 * - macOS allowWithinDeny '<dir>/': the nested-deny re-emit never matches,
 *   so last-match-wins re-allows an explicitly denied nested path.
 *
 * Glob spellings are deliberately untouched (a slash after a glob segment
 * is semantic), as is Windows (a trailing separator there is the directory
 * marker for absent deny targets). The glob a trailing slash compiles to
 * matches nothing: harmless as an allow, which is why an allow still takes
 * it, and rejected at config validation as a deny.
 */
describe('normalizePathForSandbox trailing slashes', () => {
  // Pure string work on the POSIX spellings below, so it runs on Linux and
  // macOS alike. Gated off Windows only because the strip is deliberately
  // skipped there (see the header).
  it.if(!isWindows)('strips non-glob spellings, keeps globs and root', () => {
    expect(normalizePathForSandbox('/data/secrets/')).toBe('/data/secrets')
    expect(normalizePathForSandbox('/data/secrets//')).toBe('/data/secrets')
    expect(normalizePathForSandbox('/')).toBe('/')
    // Glob spellings keep their trailing slash — it changes glob semantics.
    expect(normalizePathForSandbox('/data/*/')).toBe('/data/*/')
    expect(normalizePathForSandbox('/data/**/')).toBe('/data/**/')
    // Empty input means the cwd, like any other relative spelling — it is
    // not rewritten into the filesystem root. The equivalence alone would
    // also hold for a normaliser that answered '/' to everything, so anchor
    // it — unless the cwd really is the root.
    expect(normalizePathForSandbox('')).toBe(
      normalizePathForSandbox(process.cwd()),
    )
    if (process.cwd() !== '/') {
      expect(normalizePathForSandbox('')).not.toBe('/')
    }
  })
})

describe.if(isLinux)('Linux: trailing-slash spellings', () => {
  // realpathSync so exact-string assertions hold even when tmpdir itself
  // contains symlinks.
  let BASE: string
  let AREA: string
  let SECRETS: string
  let SUB: string

  beforeEach(() => {
    BASE = realpathSync(mkdtempSync(join(tmpdir(), 'slash-deny-')))
    AREA = join(BASE, 'area')
    SECRETS = join(AREA, 'secrets')
    SUB = join(SECRETS, 'sub')
    mkdirSync(SUB, { recursive: true })
    writeFileSync(join(SUB, 'token'), 'x\n')
  })

  afterEach(() => {
    cleanupBwrapMountPoints({ force: true })
    rmSync(BASE, { recursive: true, force: true })
  })

  it.each([
    ['plain', ''],
    ['trailing-slash', '/'],
  ])(
    'drops a denyWrite bind hidden by a read-deny tmpfs (%s spelling)',
    async (_label, suffix) => {
      const denyRead = `${SECRETS}${suffix}`

      const command = await wrapCommandWithSandboxLinux({
        command: 'true',
        needsNetworkRestriction: false,
        readConfig: { denyOnly: [denyRead] },
        writeConfig: { allowOnly: [AREA], denyWithinAllow: [SUB] },
      })

      // The tmpfs mounts at the slash-free spelling either way (the trailing
      // space pins the full argument; the slashed spelling must not appear).
      expect(command).toContain(`--tmpfs ${SECRETS} `)
      expect(command).not.toContain(`--tmpfs ${SECRETS}/ `)
      // The denyWrite bind under the read-denied dir is dropped as
      // hidden-by-the-tmpfs: emitting it after the tmpfs would re-mount the
      // read-denied host contents readable inside the sandbox.
      expect(command).not.toContain(`--ro-bind ${SUB} ${SUB}`)
    },
  )

  it('does not stack a ro-bind over an allowed write dir named by a slashed carve-out (EROFS shape)', async () => {
    // The same directory appears (naturally, by copy-paste) as a
    // trailing-slash spelling in both allowWithinDeny and allowOnly. The
    // re-allow skip in the tmpfs re-bind pass compares the two lists; with
    // inconsistent spellings it misses and emits --ro-bind <data> <data> on
    // top of the writable re-bind, turning the allowed write dir read-only.
    const data = join(SECRETS, 'data')
    mkdirSync(data)
    writeFileSync(join(data, 'out.txt'), 'x\n')

    const command = await wrapCommandWithSandboxLinux({
      command: 'true',
      needsNetworkRestriction: false,
      readConfig: { denyOnly: [SECRETS], allowWithinDeny: [`${data}/`] },
      writeConfig: { allowOnly: [AREA, `${data}/`], denyWithinAllow: [] },
    })

    const writableRebind = command.lastIndexOf(`--bind ${data} ${data}`)
    expect(writableRebind).toBeGreaterThanOrEqual(0)
    // The ro-bind must be absent, or land before the writable re-bind — last
    // mount wins. `lastIndexOf` returns -1 when absent, which reads as
    // "before" given the precondition above.
    const roStack = command.lastIndexOf(`--ro-bind ${data} ${data}`)
    expect(roStack).toBeLessThan(writableRebind)
  })
})

// Profile GENERATION is pure string building, so these assertions run under
// Linux too even though the profile only executes under macOS sandbox-exec.
// Windows is excluded: the chokepoint keeps the trailing separator there, so
// the carve-out would not reach the profile in its slash-free spelling.
describe.if(!isWindows)(
  'macOS profile: trailing-slash allowWithinDeny spelling',
  () => {
    it.each([
      ['plain', ''],
      ['trailing-slash', '/'],
    ])(
      're-emits a nested literal deny after the carve-out allow (%s spelling)',
      (_label, suffix) => {
        const profile = wrapCommandWithSandboxMacOS({
          command: 'true',
          needsNetworkRestriction: false,
          readConfig: {
            denyOnly: ['/work/priv', '/work/priv/pub/secret'],
            allowWithinDeny: [`/work/priv/pub${suffix}`],
          },
          writeConfig: undefined,
        })

        // The carve-out allow rule uses the slash-free subpath spelling.
        const allowRule = `(allow file-read*\n  (subpath "/work/priv/pub")`
        const allowIdx = profile.indexOf(allowRule)
        expect(allowIdx).toBeGreaterThanOrEqual(0)
        // Last-match-wins: the more-specific nested deny must land AFTER the
        // allow rule, or the carve-out silently re-allows it.
        const lastDenyIdx = profile.lastIndexOf(
          `(deny file-read*\n  (subpath "/work/priv/pub/secret")`,
        )
        expect(lastDenyIdx).toBeGreaterThan(allowIdx)
      },
    )

    it('keeps glob carve-out spellings untouched (no dead-to-live regex flip)', () => {
      // A glob carve-out ending in '/' compiles to whatever regex its author
      // wrote; the chokepoint must not rewrite it into a broader one.
      const profile = wrapCommandWithSandboxMacOS({
        command: 'true',
        needsNetworkRestriction: false,
        readConfig: {
          denyOnly: ['/work/priv'],
          allowWithinDeny: ['/work/priv/pub/*/'],
        },
        writeConfig: undefined,
      })
      expect(profile).toContain('/work/priv/pub/[^/]*/$')
    })
  },
)
