import { describe, it, expect, beforeEach, afterEach } from 'bun:test'
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { spawnSync } from 'node:child_process'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import {
  wrapCommandWithSandboxLinux,
  cleanupBwrapMountPoints,
} from '../../src/sandbox/linux-sandbox-utils.js'
import { isLinux } from '../helpers/platform.js'

/**
 * A deny path strictly beneath a directory that denyWithinAllow re-binds
 * read-only gets no --ro-bind of its own, under the same evidence and vetoes
 * as the absent-path stub skip (readonly-deny-dir-stubs.test.ts); a deny
 * equal to an allowOnly root, or with no covering directory, is still bound.
 */
describe.if(isLinux)('Deny binds under a read-only denied directory', () => {
  let BASE: string
  let AREA: string // allowed write area
  let PROJ: string // project dir inside AREA
  let FILE: string // existing file under PROJ/sub

  const savedCwd = process.cwd()

  // Runtime arm, as in readonly-deny-dir-stubs.test.ts: only where bwrap can
  // run the namespace/proc surface the wrapped commands use.
  const BWRAP_CAN_NAMESPACE =
    spawnSync(
      'bwrap',
      [
        '--unshare-pid',
        '--unshare-user',
        '--cap-drop',
        'ALL',
        '--ro-bind',
        '/',
        '/',
        '--proc',
        '/proc',
        'true',
      ],
      { timeout: 5000 },
    ).status === 0

  beforeEach(() => {
    BASE = realpathSync(mkdtempSync(join(tmpdir(), 'ro-deny-bind-')))
    AREA = join(BASE, 'area')
    PROJ = join(AREA, 'proj')
    FILE = join(PROJ, 'sub', 'settings.json')
    mkdirSync(join(PROJ, 'sub'), { recursive: true })
    writeFileSync(FILE, '{}\n')
    // Keep cwd outside the allowlist so the mandatory-deny scan adds no
    // binds of its own to reason about.
    process.chdir(BASE)
  })

  afterEach(() => {
    process.chdir(savedCwd)
    cleanupBwrapMountPoints({ force: true })
    rmSync(BASE, { recursive: true, force: true })
  })

  // Same parameter order as readonly-deny-dir-stubs.test.ts, whose fixture
  // and covering-directory predicate this suite shares.
  async function wrap(
    denyPaths: string[],
    readDenyPaths: string[] = [],
    allowPaths: string[] = [AREA],
    command = 'echo hello',
  ): Promise<string> {
    return wrapCommandWithSandboxLinux({
      command,
      needsNetworkRestriction: false,
      readConfig: { denyOnly: readDenyPaths },
      writeConfig: { allowOnly: allowPaths, denyWithinAllow: denyPaths },
    })
  }

  const countOccurrences = (haystack: string, needle: string): number =>
    haystack.split(needle).length - 1

  /**
   * Occurrences of one whole `<flag> <source> <dest>` argv triple. Counting
   * triples, not substrings, is what keeps a `/` assertion honest: the base
   * `--ro-bind / /` root mount spells the deny-side bind of '/' exactly, so
   * `lastIndexOf('--ro-bind / /')` finds the root mount and passes even when
   * the deny-side bind was never emitted.
   */
  const countBinds = (
    command: string,
    flag: string,
    source: string,
    dest: string,
  ): number => {
    const argv = command.split(/\s+/)
    let found = 0
    for (let i = 0; i + 2 < argv.length; i++) {
      if (argv[i] === flag && argv[i + 1] === source && argv[i + 2] === dest) {
        found++
      }
    }
    return found
  }

  /**
   * The write really hit a read-only mount, rather than the command failing
   * for some other reason that also exits non-zero: bwrap refusing to start,
   * or the spawn timing out.
   */
  const expectDeniedByReadOnlyMount = (result: {
    error?: Error
    stderr: string
  }): void => {
    expect(result.error).toBeUndefined()
    expect(result.stderr).not.toContain('bwrap:')
    expect(result.stderr).toMatch(/Read-only file system|Permission denied/)
  }

  it('binds the denied allow-root once and skips the existing file beneath it', async () => {
    // allowOnly=[proj], denyWithinAllow=[proj, proj/sub/file]: the directory
    // deny equals the allow root and must still be emitted; the file is a
    // strict descendant of that read-only bind and needs nothing.
    const command = await wrap([PROJ, FILE], [], [PROJ])

    expect(countOccurrences(command, `--ro-bind ${PROJ} ${PROJ}`)).toBe(1)
    expect(command).not.toContain(`--ro-bind ${FILE} ${FILE}`)

    // Where the host can run bwrap, prove the covering bind alone still
    // holds: the file reads, and a write through it fails and changes
    // nothing on the host.
    if (BWRAP_CAN_NAMESPACE) {
      const run = (wrapped: string) =>
        spawnSync(wrapped, {
          shell: true,
          encoding: 'utf8',
          timeout: 15000,
          cwd: BASE,
        })
      const read = run(await wrap([PROJ, FILE], [], [PROJ], `cat ${FILE}`))
      expect(read.status).toBe(0)
      expect(read.stdout).toContain('{}')

      const write = run(
        await wrap([PROJ, FILE], [], [PROJ], `sh -c 'echo x >> ${FILE}'`),
      )
      // The specific failure, not merely a non-zero exit: a bwrap startup
      // abort or a spawn timeout would satisfy that just as well.
      expectDeniedByReadOnlyMount(write)
      expect(readFileSync(FILE, 'utf8')).toBe('{}\n')
    }
  })

  it('is independent of the order the denies are listed in', async () => {
    const command = await wrap([FILE, PROJ], [], [PROJ])

    expect(countOccurrences(command, `--ro-bind ${PROJ} ${PROJ}`)).toBe(1)
    expect(command).not.toContain(`--ro-bind ${FILE} ${FILE}`)
  })

  it('still binds the file when its directory is not itself denied', async () => {
    const command = await wrap([FILE], [], [PROJ])

    expect(command).toContain(`--bind ${PROJ} ${PROJ}`)
    expect(command).toContain(`--ro-bind ${FILE} ${FILE}`)
  })

  it('collapses a chain of nested directory denies to the outermost bind', async () => {
    const sub = join(PROJ, 'sub')
    const command = await wrap([PROJ, sub, FILE])

    expect(countOccurrences(command, `--ro-bind ${PROJ} ${PROJ}`)).toBe(1)
    expect(command).not.toContain(`--ro-bind ${sub} ${sub}`)
    expect(command).not.toContain(`--ro-bind ${FILE} ${FILE}`)
  })

  it('keeps the descendant bind when an allowed write path sits strictly beneath the covering dir (veto)', async () => {
    // Same veto as the stub skip: with an allowWrite under PROJ the denyRead
    // re-application machinery could re-open part of the subtree, so the
    // covering bind is not trusted and the explicit deny keeps its own.
    const nestedAllow = join(PROJ, 'w')
    mkdirSync(nestedAllow)

    const command = await wrap([PROJ, FILE], [], [AREA, nestedAllow])

    expect(command).toContain(`--ro-bind ${PROJ} ${PROJ}`)
    expect(command).toContain(`--ro-bind ${FILE} ${FILE}`)
  })

  it('keeps the descendant bind when a denyRead tmpfs sits under the covering dir (veto)', async () => {
    const readDenied = join(PROJ, 'secrets')
    mkdirSync(readDenied)

    const command = await wrap([PROJ, FILE], [readDenied])

    expect(command).toContain(`--ro-bind ${PROJ} ${PROJ}`)
    expect(command).toContain(`--ro-bind ${FILE} ${FILE}`)
  })

  it('does not trust a recorded "/" as a covering directory', async () => {
    // allowOnly and denyWithinAllow both naming '/' records it as a
    // read-only deny directory that every path lies beneath. A string-prefix
    // veto ('/' + '/') could never fire, so PROJ's own bind would be dropped
    // as covered; the recursive --ro-bind / / emitted later then shadows the
    // FILE mask with no bind left to key its re-application off, and the
    // read-denied file is readable. Root-aware containment vetoes '/' (AREA
    // is an allowed write path beneath it), keeps PROJ's bind, and re-applies
    // the mask after the root bind.
    const command = await wrap(['/', PROJ], [FILE], ['/', AREA])

    expect(command).toContain(`--ro-bind ${PROJ} ${PROJ}`)
    // Two: the base root mount, then the deny bind of '/' whose position the
    // mask has to beat.
    expect(countBinds(command, '--ro-bind', '/', '/')).toBe(2)
    const rootBind = command.lastIndexOf('--ro-bind / /')
    const mask = command.lastIndexOf(`--ro-bind /dev/null ${FILE}`)
    expect(mask).toBeGreaterThan(rootBind)
  })

  it('skips the stubs under a write-denied cwd even when a recorded "/" is vetoed', async () => {
    // '/' recorded and vetoed (AREA is writable beneath it). A veto that
    // disqualified every skip would stub each absent mandatory-deny dotfile
    // of the write-denied cwd after the cwd's own bind — the startup abort
    // readonly-deny-dir-stubs.test.ts documents. The cwd's recorded bind
    // decides instead.
    process.chdir(PROJ)
    const command = await wrap(['/', PROJ], [], ['/', AREA])

    expect(command).toContain(`--ro-bind ${PROJ} ${PROJ}`)
    expect(command).not.toContain(`/dev/null ${PROJ}/`)
    expect(command).not.toMatch(/--ro-bind \S*claude-empty-\S+ \S*\/proj\//)
  })

  it('re-applies a read-deny mask and tmpfs shadowed by a bind of "/" alone', async () => {
    // '/' is the only emitted deny bind, and it is recursive: it re-exposes
    // every read-denied path underneath, so the mask and the tmpfs must be
    // re-applied on top of it or the file and the directory stay readable.
    const secrets = join(PROJ, 'secrets')
    mkdirSync(secrets)
    const command = await wrap(['/'], [FILE, secrets], ['/'])

    // Two: the base root mount, then the deny bind under test.
    expect(countBinds(command, '--ro-bind', '/', '/')).toBe(2)
    const rootBind = command.lastIndexOf('--ro-bind / /')
    expect(command.lastIndexOf(`--ro-bind /dev/null ${FILE}`)).toBeGreaterThan(
      rootBind,
    )
    expect(command.lastIndexOf(`--tmpfs ${secrets}`)).toBeGreaterThan(rootBind)
  })

  it('does not treat a string-prefix sibling as covered', async () => {
    // AREA/proj2/x.txt shares a prefix with AREA/proj without lying beneath
    // it: a plain startsWith would drop its bind and leave it writable.
    const proj2 = join(AREA, 'proj2')
    mkdirSync(proj2)
    const sibling = join(proj2, 'x.txt')
    writeFileSync(sibling, '')

    const command = await wrap([PROJ, sibling])

    expect(command).toContain(`--ro-bind ${PROJ} ${PROJ}`)
    expect(command).toContain(`--ro-bind ${sibling} ${sibling}`)
  })

  it('vetoes "/" for an allowed write path beneath it even with no read policy', async () => {
    // Veto (i) alone must be root-aware: with readConfig undefined there is
    // no read-deny tmpfs for veto (ii) to catch '/' with.
    const command = await wrapCommandWithSandboxLinux({
      command: 'echo hello',
      needsNetworkRestriction: false,
      readConfig: undefined,
      writeConfig: { allowOnly: ['/', AREA], denyWithinAllow: ['/', PROJ] },
    })

    expect(command).toContain(`--ro-bind ${PROJ} ${PROJ}`)
  })

  it('does not re-apply a tmpfs over the bind that denies the same directory', async () => {
    // X in allowOnly, denyWithinAllow and denyRead: the read-only bind of X
    // is not "an ancestor that re-exposes X", so no --tmpfs X --bind X X may
    // follow it and make X writable again.
    const X = join(AREA, 'both')
    mkdirSync(X)
    const command = await wrap([X], [X], [AREA, X])

    const lastRoBind = command.lastIndexOf(`--ro-bind ${X} ${X}`)
    expect(lastRoBind).toBeGreaterThan(-1)
    expect(command.indexOf(`--bind ${X} ${X}`, lastRoBind)).toBe(-1)
  })

  it('keeps the bind for a deny reached through a symlinked spelling', async () => {
    // The re-application passes key off emitted raw spellings; a dest that
    // was reached via a symlink keeps its bind so that breadcrumb survives.
    const realSub = join(PROJ, 'sub')
    const linkSub = join(PROJ, 'link')
    symlinkSync(realSub, linkSub)
    const viaLink = join(linkSub, 'settings.json')

    const command = await wrap([PROJ, viaLink])

    expect(command).toContain(`--ro-bind ${PROJ} ${PROJ}`)
    expect(command).toContain(`--ro-bind ${FILE} ${FILE}`)
  })

  /**
   * '/' is a legal allowOnly entry — normalization keeps it — and the allow
   * loop binds it writable. Every deny then depends on the one predicate
   * deciding whether its dest lies inside the write allowlist; a string
   * prefix spells that '//' for a root allow and matches nothing, which
   * drops every deny no other allow entry happens to cover.
   *
   * Mandatory denies are resolved against the cwd, and a '/' allowlist
   * contains the cwd whatever it is, so unlike the suite above these cases
   * reason about them too.
   */
  describe('with "/" in the write allowlist', () => {
    it('binds a denyWrite file and directory no other allow entry covers', async () => {
      const denied = join(BASE, 'denied')
      mkdirSync(denied)

      const command = await wrap([FILE, denied], [], ['/'])

      expect(countBinds(command, '--bind', '/', '/')).toBe(1)
      expect(countBinds(command, '--ro-bind', FILE, FILE)).toBe(1)
      expect(countBinds(command, '--ro-bind', denied, denied)).toBe(1)
    })

    it('binds the mandatory denies that exist and stubs the ones that do not', async () => {
      const bashrc = join(BASE, '.bashrc')
      const hooks = join(BASE, '.git', 'hooks')
      const mcp = join(BASE, '.mcp.json')
      writeFileSync(bashrc, '')
      mkdirSync(hooks, { recursive: true })

      const command = await wrap([], [], ['/'])

      expect(countBinds(command, '--ro-bind', bashrc, bashrc)).toBe(1)
      expect(countBinds(command, '--ro-bind', hooks, hooks)).toBe(1)
      // Absent: blocked from being created rather than bound read-only.
      expect(countBinds(command, '--ro-bind', '/dev/null', mcp)).toBe(1)
    })

    it('masks a symlinked ancestor of a deny path', async () => {
      // A self-referential link: resolveSymlinkedDenyPath gives up and the
      // fail-closed branch masks the symlink component, so it cannot be
      // deleted and recreated as a real directory.
      const loop = join(AREA, 'loop')
      symlinkSync('loop', loop)

      const command = await wrap([join(loop, 'settings.json')], [], ['/'])

      expect(countBinds(command, '--ro-bind', '/dev/null', loop)).toBe(1)
    })

    it('denies the write at runtime and leaves the rest of the tree writable', async () => {
      if (!BWRAP_CAN_NAMESPACE) return
      const control = join(AREA, 'control.txt')
      writeFileSync(control, '')
      const run = (wrapped: string) =>
        spawnSync(wrapped, {
          shell: true,
          encoding: 'utf8',
          timeout: 15000,
          cwd: BASE,
        })

      const denied = run(
        await wrap([FILE], [], ['/'], `sh -c 'echo x >> ${FILE}'`),
      )
      expectDeniedByReadOnlyMount(denied)
      expect(readFileSync(FILE, 'utf8')).toBe('{}\n')

      const allowed = run(
        await wrap([FILE], [], ['/'], `sh -c 'echo ok >> ${control}'`),
      )
      expect(allowed.error).toBeUndefined()
      expect(allowed.stderr).not.toContain('bwrap:')
      expect(allowed.status).toBe(0)
      expect(readFileSync(control, 'utf8')).toBe('ok\n')
    })
  })
})
