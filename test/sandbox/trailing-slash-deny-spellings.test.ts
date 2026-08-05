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
import { isLinux } from '../helpers/platform.js'

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
 * - Linux allowOnly '<dir>/': every within-allowlist comparison misses, so
 *   denyWithinAllow (and mandatory) deny binds are silently dropped while
 *   the tree is bind-mounted writable.
 * - Linux allowWithinDeny + allowOnly sharing a slashed spelling: the
 *   re-allow skip in the tmpfs re-bind pass depends on both sides using the
 *   same spelling, or an extra ro-bind stacks over the writable re-bind and
 *   the allowed write dir becomes read-only (EROFS).
 * - macOS allowWithinDeny '<dir>/': the nested-deny re-emit never matches,
 *   so last-match-wins re-allows an explicitly denied nested path.
 *
 * Glob spellings are deliberately untouched (a slash after a glob segment
 * is semantic), as is Windows (a trailing separator there is the directory
 * marker for absent deny targets).
 */
describe('normalizePathForSandbox trailing slashes', () => {
  it.if(isLinux)('strips non-glob spellings, keeps globs and root', () => {
    expect(normalizePathForSandbox('/data/secrets/')).toBe('/data/secrets')
    expect(normalizePathForSandbox('/data/secrets//')).toBe('/data/secrets')
    expect(normalizePathForSandbox('/')).toBe('/')
    // Glob spellings keep their trailing slash — it changes glob semantics.
    expect(normalizePathForSandbox('/data/*/')).toBe('/data/*/')
    expect(normalizePathForSandbox('/data/**/')).toBe('/data/**/')
    // Empty input is not rewritten into the filesystem root.
    expect(normalizePathForSandbox('')).not.toBe('/')
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

  it.each([['plain'], ['trailing-slash']])(
    'drops a denyWrite bind hidden by a read-deny tmpfs (%s spelling)',
    async spelling => {
      const denyRead = spelling === 'trailing-slash' ? `${SECRETS}/` : SECRETS

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

  it('enforces denyWithinAllow under a trailing-slash allowOnly spelling', async () => {
    // A slashed allowOnly used to make every within-allowlist comparison
    // miss, silently dropping the deny re-binds while the tree stayed
    // bind-mounted writable.
    const secret = join(AREA, 'secret.txt')
    writeFileSync(secret, 'x\n')

    const command = await wrapCommandWithSandboxLinux({
      command: 'true',
      needsNetworkRestriction: false,
      readConfig: { denyOnly: [] },
      writeConfig: { allowOnly: [`${AREA}/`], denyWithinAllow: [secret] },
    })

    expect(command).toContain(`--bind ${AREA} ${AREA}`)
    expect(command).toContain(`--ro-bind ${secret} ${secret}`)
  })

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
    const roStack = command.lastIndexOf(`--ro-bind ${data} ${data}`)
    expect(roStack).toBeLessThan(writableRebind)
  })
})

// Profile GENERATION is pure string building, so these assertions run on
// every platform even though the profile only executes under macOS
// sandbox-exec.
describe('macOS profile: trailing-slash allowWithinDeny spelling', () => {
  it.each([['plain'], ['trailing-slash']])(
    're-emits a nested literal deny after the carve-out allow (%s spelling)',
    spelling => {
      const carveOut =
        spelling === 'trailing-slash' ? '/work/priv/pub/' : '/work/priv/pub'

      const profile = wrapCommandWithSandboxMacOS({
        command: 'true',
        needsNetworkRestriction: false,
        readConfig: {
          denyOnly: ['/work/priv', '/work/priv/pub/secret'],
          allowWithinDeny: [carveOut],
        },
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
    })
    expect(profile).toContain('/work/priv/pub/[^/]*/$')
  })
})
