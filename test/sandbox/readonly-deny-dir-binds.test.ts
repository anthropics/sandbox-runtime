import { describe, it, expect, beforeEach, afterEach } from 'bun:test'
import {
  existsSync,
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
      expect(write.status).not.toBe(0)
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
    const rootBind = command.lastIndexOf('--ro-bind / /')
    const mask = command.lastIndexOf(`--ro-bind /dev/null ${FILE}`)
    expect(rootBind).toBeGreaterThan(-1)
    expect(mask).toBeGreaterThan(rootBind)
  })

  it('skips the stubs under a write-denied cwd even when a recorded "/" is vetoed', async () => {
    // '/' recorded and vetoed (AREA is writable beneath it). A veto that
    // disqualified every skip would stub each absent mandatory-deny dotfile
    // of the write-denied cwd after the cwd's own bind — the startup abort
    // readonly-deny-dir-stubs.test.ts documents. The cwd's recorded bind
    // decides instead, as on main.
    process.chdir(PROJ)
    const command = await wrap(['/', PROJ], [], ['/', AREA])

    expect(command).toContain(`--ro-bind ${PROJ} ${PROJ}`)
    expect(command).not.toContain(`/dev/null ${PROJ}/`)
    expect(command).not.toMatch(/--ro-bind \S*claude-empty-\S+ \S*\/proj\//)
  })

  it('re-applies a read-deny mask and tmpfs shadowed by a bind of "/" alone', async () => {
    // '/' is the only emitted deny bind. main compared the bind by string
    // prefix ('/' + '/') and re-applied nothing after --ro-bind / /, so the
    // recursive root bind left the file and the directory readable.
    const secrets = join(PROJ, 'secrets')
    mkdirSync(secrets)
    const command = await wrap(['/'], [FILE, secrets], ['/'])

    const rootBind = command.lastIndexOf('--ro-bind / /')
    expect(rootBind).toBeGreaterThan(-1)
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

  // A write-deny bind under a read-deny tmpfs is kept at emission BECAUSE an
  // allowed write path restored it. Re-applying that tmpfs over a write-deny
  // bind of an ancestor buries the deny bind again, so the re-application
  // must restore what it covers read-only: everything under it is inside
  // that write deny.
  describe('a re-applied read-deny tmpfs restores read-only', () => {
    let RO: string // read-denied dir inside PROJ
    let W: string // allowed write path inside RO
    let SECRET: string // write-denied file inside W

    beforeEach(() => {
      RO = join(PROJ, 'ro')
      W = join(RO, 'w')
      mkdirSync(W, { recursive: true })
      SECRET = join(W, 'secret.txt')
      writeFileSync(SECRET, 'HOST\n')
    })

    it('restores the allow path read-only after the re-applied tmpfs', async () => {
      const command = await wrap([PROJ, SECRET], [RO], [AREA, W])

      const lastTmpfs = command.lastIndexOf(`--tmpfs ${RO} `)
      expect(lastTmpfs).toBeGreaterThan(-1)
      expect(command.lastIndexOf(`--ro-bind ${W} ${W}`)).toBeGreaterThan(
        lastTmpfs,
      )
      expect(command.indexOf(`--bind ${W} ${W}`, lastTmpfs)).toBe(-1)
    })

    it('leaves the allow path writable when no write deny re-exposes the tmpfs', async () => {
      // Control: without a deny on PROJ nothing re-applies the tmpfs, so the
      // first pass's writable re-bind of W is the last word and only SECRET
      // keeps its own deny bind.
      const command = await wrap([SECRET], [RO], [AREA, W])

      const lastTmpfs = command.lastIndexOf(`--tmpfs ${RO} `)
      expect(command.indexOf(`--bind ${W} ${W}`, lastTmpfs)).toBeGreaterThan(-1)
      expect(command).toContain(`--ro-bind ${SECRET} ${SECRET}`)
    })

    // `echo BOOTED` guards every runtime case below: a bwrap start-up abort
    // would otherwise read as "the write was blocked".
    it.skipIf(!BWRAP_CAN_NAMESPACE)(
      'blocks writes under the allow path while its contents stay readable',
      async () => {
        const sibling = join(W, 'notes.txt')
        writeFileSync(sibling, 'notes\n')

        const result = spawnSync(
          await wrap(
            [PROJ, SECRET],
            [RO],
            [AREA, W],
            `sh -c 'echo BOOTED; echo x >> ${SECRET}; echo y >> ${sibling}; cat ${sibling}'`,
          ),
          { shell: true, encoding: 'utf8', timeout: 15000, cwd: BASE },
        )

        expect(result.stdout).toContain('BOOTED')
        expect(result.stdout).toContain('notes')
        expect(readFileSync(SECRET, 'utf8')).toBe('HOST\n')
        expect(readFileSync(sibling, 'utf8')).toBe('notes\n')
      },
    )

    it.skipIf(!BWRAP_CAN_NAMESPACE)(
      'still writes under the allow path when no write deny re-exposes the tmpfs',
      async () => {
        const sibling = join(W, 'notes.txt')
        writeFileSync(sibling, 'notes\n')

        const result = spawnSync(
          await wrap(
            [SECRET],
            [RO],
            [AREA, W],
            `sh -c 'echo BOOTED; echo x >> ${SECRET}; echo y >> ${sibling}'`,
          ),
          { shell: true, encoding: 'utf8', timeout: 15000, cwd: BASE },
        )

        expect(result.stdout).toContain('BOOTED')
        expect(readFileSync(SECRET, 'utf8')).toBe('HOST\n')
        expect(readFileSync(sibling, 'utf8')).toBe('notes\ny\n')
      },
    )

    it.skipIf(!BWRAP_CAN_NAMESPACE)(
      'keeps the git hooks and config denies of a repo under the read-denied dir',
      async () => {
        // The shape the emission filter's own .git/hooks exception describes:
        // a repo under a read-denied directory, writable, inside a
        // write-denied project.
        const hooks = join(W, '.git', 'hooks')
        const config = join(W, '.git', 'config')
        mkdirSync(hooks, { recursive: true })
        writeFileSync(config, '[core]\n')

        const result = spawnSync(
          await wrap(
            [PROJ, hooks, config],
            [RO],
            [AREA, W],
            `sh -c 'echo BOOTED; echo hook > ${join(hooks, 'pre-commit')}; echo x >> ${config}'`,
          ),
          { shell: true, encoding: 'utf8', timeout: 15000, cwd: BASE },
        )

        expect(result.stdout).toContain('BOOTED')
        expect(existsSync(join(hooks, 'pre-commit'))).toBe(false)
        expect(readFileSync(config, 'utf8')).toBe('[core]\n')
      },
    )

    // Absent deny paths are listed FIRST in the two cases below, so their
    // placeholder mount points are created while the allow path is still
    // writable and bwrap starts instead of aborting. A placeholder the
    // re-application buries is covered by the read-only restore above it.
    it.skipIf(!BWRAP_CAN_NAMESPACE)(
      'keeps an absent deny path uncreatable through its /dev/null stub',
      async () => {
        // bwrap leaves the mount point behind as a mode-444 file on the host,
        // so the write has to be preceded by a chmod: on a writable restore
        // its owner may widen the mode and write through it.
        const absent = join(W, '.secret')

        const result = spawnSync(
          await wrap(
            [absent, PROJ],
            [RO],
            [AREA, W],
            `sh -c 'echo BOOTED; chmod u+w ${absent}; echo pwned > ${absent}'`,
          ),
          { shell: true, encoding: 'utf8', timeout: 15000, cwd: BASE },
        )

        expect(result.stdout).toContain('BOOTED')
        expect(readFileSync(absent, 'utf8')).toBe('')
      },
    )

    it.skipIf(!BWRAP_CAN_NAMESPACE)(
      'keeps an absent deny path uncreatable through its empty-dir placeholder',
      async () => {
        const placeholder = join(W, '.cfg')
        const absent = join(placeholder, 'deep', 'x')

        const result = spawnSync(
          await wrap(
            [absent, PROJ],
            [RO],
            [AREA, W],
            `sh -c 'echo BOOTED; mkdir -p ${join(placeholder, 'deep')} && echo pwned > ${absent}'`,
          ),
          { shell: true, encoding: 'utf8', timeout: 15000, cwd: BASE },
        )

        expect(result.stdout).toContain('BOOTED')
        expect(existsSync(absent)).toBe(false)
      },
    )
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
})
