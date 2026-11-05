import { describe, it, expect, beforeEach, afterEach } from 'bun:test'
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
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
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import { isAtOrUnder } from '../../src/sandbox/sandbox-utils.js'
import { isLinux } from '../helpers/platform.js'
import { countMounts, lastMountAt, mountsOf } from '../helpers/bwrap-argv.js'
import { bwrapCanNamespace } from '../helpers/bwrap-namespace.js'
import { withCapturedWarnings } from '../helpers/captured-warnings.js'

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

  const BWRAP_CAN_NAMESPACE = bwrapCanNamespace()

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

  const RUN_TIMEOUT_MS = 15000

  const run = (wrapped: string) =>
    spawnSync(wrapped, {
      shell: true,
      encoding: 'utf8',
      timeout: RUN_TIMEOUT_MS,
      cwd: BASE,
    })

  // Runs `payload` in the wrapped sandbox behind an `echo BOOTED`, so a bwrap
  // start-up abort cannot read as "the payload was blocked".
  async function runSandboxed(
    denyPaths: string[],
    readDenyPaths: string[],
    allowPaths: string[],
    payload: string,
  ) {
    const result = run(
      await wrap(
        denyPaths,
        readDenyPaths,
        allowPaths,
        `sh -c 'echo BOOTED; ${payload}'`,
      ),
    )
    expect(result.stdout).toContain('BOOTED')
    return result
  }

  /**
   * The write really hit a read-only mount, rather than the command failing
   * for some other reason that also exits non-zero: bwrap refusing to start,
   * or the spawn timing out.
   */
  const expectDeniedByReadOnlyMount = (result: {
    error?: Error
    status: number | null
    stderr: string
  }): void => {
    expect(result.error).toBeUndefined()
    expect(result.status).not.toBe(0)
    expect(result.stderr).not.toContain('bwrap:')
    expect(result.stderr).toMatch(/Read-only file system|Permission denied/)
  }

  it('binds the denied allow-root once and skips the existing file beneath it', async () => {
    // allowOnly=[proj], denyWithinAllow=[proj, proj/sub/file]: the directory
    // deny equals the allow root and must still be emitted; the file is a
    // strict descendant of that read-only bind and needs nothing.
    const command = await wrap([PROJ, FILE], [], [PROJ])

    expect(countMounts(command, '--ro-bind', PROJ, PROJ)).toBe(1)
    expect(command).not.toContain(`--ro-bind ${FILE} ${FILE}`)
  })

  it.skipIf(!BWRAP_CAN_NAMESPACE)(
    'holds the file beneath the covering bind readable and unwritable',
    async () => {
      // The covering bind is all that protects FILE: it must still read, and
      // a write through it must fail and change nothing on the host.
      const read = await runSandboxed([PROJ, FILE], [], [PROJ], `cat ${FILE}`)
      expect(read.status).toBe(0)
      expect(read.stdout).toContain('{}')

      const write = await runSandboxed(
        [PROJ, FILE],
        [],
        [PROJ],
        `echo x >> ${FILE}`,
      )
      // The specific failure, not merely a non-zero exit: a bwrap startup
      // abort or a spawn timeout would satisfy that just as well.
      expectDeniedByReadOnlyMount(write)
      expect(readFileSync(FILE, 'utf8')).toBe('{}\n')
    },
  )

  it('is independent of the order the denies are listed in', async () => {
    const command = await wrap([FILE, PROJ], [], [PROJ])

    expect(countMounts(command, '--ro-bind', PROJ, PROJ)).toBe(1)
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

    expect(countMounts(command, '--ro-bind', PROJ, PROJ)).toBe(1)
    expect(command).not.toContain(`--ro-bind ${sub} ${sub}`)
    expect(command).not.toContain(`--ro-bind ${FILE} ${FILE}`)
  })

  it('keeps the descendant bind when an allowed write path under a read-deny tmpfs sits beneath the covering dir (veto)', async () => {
    // Same veto as the stub skip: an allowWrite beneath PROJ that a denyRead
    // tmpfs also covers is the one shape where anything is mounted inside
    // PROJ after its read-only bind, so the covering bind is not trusted and
    // the explicit deny keeps its own.
    const readDenied = join(PROJ, 'ro')
    const nestedAllow = join(readDenied, 'w')
    mkdirSync(nestedAllow, { recursive: true })

    const command = await wrap([PROJ, FILE], [readDenied], [AREA, nestedAllow])

    expect(command).toContain(`--ro-bind ${PROJ} ${PROJ}`)
    expect(command).toContain(`--ro-bind ${FILE} ${FILE}`)
  })

  it('skips the descendant bind when the allowed write path beneath the covering dir is buried', async () => {
    // The veto needs a read-deny tmpfs over the nested allow. With none, the
    // allow's --bind is emitted before the covering read-only bind and stays
    // buried by it, so FILE is already unwritable and needs no bind of its
    // own — and stubbing its absent siblings would abort bwrap.
    const nestedAllow = join(PROJ, 'w')
    mkdirSync(nestedAllow)

    const command = await wrap([PROJ, FILE], [], [AREA, nestedAllow])

    expect(command).toContain(`--ro-bind ${PROJ} ${PROJ}`)
    expect(command).not.toContain(`--ro-bind ${FILE} ${FILE}`)
  })

  it('skips the descendant bind when only a denyRead tmpfs sits under the covering dir', async () => {
    // The tmpfs is re-applied after PROJ's bind, and what it restores comes
    // back read-only: all it adds under PROJ is a tmpfs whose contents never
    // reach the host, so FILE stays under the read-only bind.
    const readDenied = join(PROJ, 'secrets')
    mkdirSync(readDenied)

    const command = await wrap([PROJ, FILE], [readDenied])

    const projBind = command.lastIndexOf(`--ro-bind ${PROJ} ${PROJ}`)
    expect(projBind).toBeGreaterThan(-1)
    expect(command).not.toContain(`--ro-bind ${FILE} ${FILE}`)
    expect(command.lastIndexOf(`--tmpfs ${readDenied}`)).toBeGreaterThan(
      projBind,
    )
  })

  it.skipIf(!BWRAP_CAN_NAMESPACE)(
    'keeps the file unwritable when only a denyRead tmpfs sits under the covering dir',
    async () => {
      // The runtime half of the skip above: with the descendant bind gone,
      // the covering bind alone must still refuse the write.
      const readDenied = join(PROJ, 'secrets')
      mkdirSync(readDenied)

      const write = await runSandboxed(
        [PROJ, FILE],
        [readDenied],
        [AREA],
        `echo x >> ${FILE}`,
      )

      expectDeniedByReadOnlyMount(write)
      expect(readFileSync(FILE, 'utf8')).toBe('{}\n')
    },
  )

  it("covers a descendant deny with the root's own bind, and still re-applies the mask", async () => {
    // allowOnly and denyWithinAllow both naming '/' records it as a
    // read-only deny directory that every path lies beneath. Its own
    // --ro-bind / / lands after both allow binds and holds PROJ read-only,
    // so PROJ's bind is dropped as covered — and that root bind is what the
    // FILE mask's re-application keys off, so the read-denied file is masked
    // again on top of it. Containment has to be root-aware for any of that:
    // a string-prefix comparison ('/' + '/') matched nothing, dropped the
    // root's own deny, and left the file readable.
    const command = await wrap(['/', PROJ], [FILE], ['/', AREA])

    // Two whole triples: the base root mount, then the deny's own bind. Both
    // the dropped bind and the mask are measured against the SECOND —
    // against the base mount alone the assertions hold even when the deny
    // bind is missing, and that bind is what re-exposes the file.
    expect(countMounts(command, '--ro-bind', '/', '/')).toBe(2)
    const rootBind = command.lastIndexOf('--ro-bind / /')
    // PROJ's own deny bind is dropped; its ancestor pin, emitted before the
    // root's bind, is a different mount with the same spelling.
    expect(command.indexOf(`--ro-bind ${PROJ} ${PROJ}`, rootBind)).toBe(-1)
    expect(command.lastIndexOf(`--ro-bind /dev/null ${FILE}`)).toBeGreaterThan(
      rootBind,
    )
  })

  it.skipIf(!BWRAP_CAN_NAMESPACE)(
    "keeps the file masked and the directory unwritable under the root's own bind",
    async () => {
      const newFile = join(PROJ, 'new.txt')
      const result = run(
        await wrap(
          ['/', PROJ],
          [FILE],
          ['/', AREA],
          `(echo x > ${newFile}) 2>/dev/null && echo WROTE || echo REFUSED; echo "read:[$(cat ${FILE})]"`,
        ),
      )
      expect(result.stderr ?? '').not.toContain('bwrap:')
      expect(result.stdout).toContain('REFUSED')
      expect(result.stdout).toContain('read:[]')
      expect(existsSync(newFile)).toBe(false)
    },
  )

  it('warns that a write deny covers an allowed write path beneath it', async () => {
    // The deny's read-only bind is emitted after every allow bind, so this
    // shape starts with AREA read-only instead of aborting. Name both paths.
    const { warnings } = await withCapturedWarnings(() =>
      wrap(['/'], [], ['/', AREA]),
    )

    expect(warnings.join('\n')).toContain(
      `Write deny / covers allowed write path ${AREA}`,
    )
  })

  it('skips the stubs under a write-denied cwd when a recorded "/" is vetoed', async () => {
    // '/' recorded and vetoed: the allowed write path inside the read-denied
    // directory is both strictly beneath '/' and under that tmpfs. A veto
    // that disqualified every skip would stub each absent mandatory-deny
    // dotfile of the write-denied cwd after the cwd's own bind — the startup
    // abort readonly-deny-dir-stubs.test.ts documents.
    const readDenied = join(AREA, 'ro')
    const nestedAllow = join(readDenied, 'w')
    mkdirSync(nestedAllow, { recursive: true })
    process.chdir(PROJ)
    const command = await wrap(
      ['/', PROJ],
      [readDenied],
      ['/', AREA, nestedAllow],
    )

    // Two whole triples: the base root mount, then the deny's read-only bind
    // that holds PROJ and everything else uncreatable.
    expect(countMounts(command, '--ro-bind', '/', '/')).toBe(2)
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
    expect(countMounts(command, '--ro-bind', '/', '/')).toBe(2)
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

  it('emits the root deny that covers a descendant, with no read policy', async () => {
    // Containment must be root-aware even with readConfig undefined: a
    // string-prefix test ('/' + '/') judges '/' outside its own allowlist
    // and drops the bind that makes the whole tree read-only, leaving PROJ
    // writable with its own bind dropped as covered by it.
    const command = await wrapCommandWithSandboxLinux({
      command: 'echo hello',
      needsNetworkRestriction: false,
      readConfig: undefined,
      writeConfig: { allowOnly: ['/', AREA], denyWithinAllow: ['/', PROJ] },
    })

    expect(countMounts(command, '--ro-bind', '/', '/')).toBe(2)
    expect(command).not.toContain(`--ro-bind ${PROJ} ${PROJ}`)
    // The root's own read-only bind is what holds them: it lands after every
    // allow bind, burying them.
    expect(command.lastIndexOf('--ro-bind / /')).toBeGreaterThan(
      command.indexOf(`--bind ${AREA} ${AREA}`),
    )
  })

  it.skipIf(!BWRAP_CAN_NAMESPACE)(
    'holds the whole tree read-only when the per-path denies under "/" are dropped',
    async () => {
      // The runtime half of the drop above, which was argv-only: with PROJ's
      // own bind gone, the root deny's read-only bind is all that stands
      // between the command and the allowed write area, and the denied file
      // must still read (it is read-only, not masked).
      const result = run(
        await wrapCommandWithSandboxLinux({
          command: `sh -c 'echo BOOTED; touch ${join(AREA, 'x')} 2>/dev/null || echo AREA-READONLY; cat ${FILE}'`,
          needsNetworkRestriction: false,
          readConfig: undefined,
          writeConfig: {
            allowOnly: ['/', AREA],
            denyWithinAllow: ['/', PROJ],
          },
        }),
      )

      expect(result.stderr ?? '').not.toContain('bwrap:')
      expect(result.stdout).toContain('BOOTED')
      expect(result.stdout).toContain('AREA-READONLY')
      expect(result.stdout).toContain('{}')
      expect(existsSync(join(AREA, 'x'))).toBe(false)
    },
  )

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
    let nestedAllow: string // allowed write path inside RO
    let SECRET: string // write-denied file inside nestedAllow
    let UNREADABLE: string // read-denied file inside RO, outside nestedAllow

    beforeEach(() => {
      RO = join(PROJ, 'ro')
      nestedAllow = join(RO, 'w')
      mkdirSync(nestedAllow, { recursive: true })
      SECRET = join(nestedAllow, 'secret.txt')
      writeFileSync(SECRET, 'HOST\n')
      UNREADABLE = join(RO, 'other.txt')
      writeFileSync(UNREADABLE, 'HIDDEN\n')
    })

    it('restores the allow path read-only after the re-applied tmpfs', async () => {
      const command = await wrap([PROJ, SECRET], [RO], [AREA, nestedAllow])

      const lastTmpfs = command.lastIndexOf(`--tmpfs ${RO} `)
      expect(lastTmpfs).toBeGreaterThan(-1)
      expect(
        command.lastIndexOf(`--ro-bind ${nestedAllow} ${nestedAllow}`),
      ).toBeGreaterThan(lastTmpfs)
      expect(
        command.indexOf(`--bind ${nestedAllow} ${nestedAllow}`, lastTmpfs),
      ).toBe(-1)
    })

    it('leaves the allow path writable when no write deny re-exposes the tmpfs', async () => {
      // Control: without a deny on PROJ nothing re-applies the tmpfs, so the
      // first pass's writable re-bind of nestedAllow is the last word and
      // only SECRET keeps its own deny bind.
      const command = await wrap([SECRET], [RO], [AREA, nestedAllow])

      const lastTmpfs = command.lastIndexOf(`--tmpfs ${RO} `)
      expect(lastTmpfs).toBeGreaterThan(-1)
      expect(
        command.indexOf(`--bind ${nestedAllow} ${nestedAllow}`, lastTmpfs),
      ).toBeGreaterThan(-1)
      expect(command).toContain(`--ro-bind ${SECRET} ${SECRET}`)
    })

    it.skipIf(!BWRAP_CAN_NAMESPACE)(
      'blocks writes under the allow path while its contents stay readable',
      async () => {
        const sibling = join(nestedAllow, 'notes.txt')
        writeFileSync(sibling, 'notes\n')

        const result = await runSandboxed(
          [PROJ, SECRET],
          [RO],
          [AREA, nestedAllow],
          `echo x >> ${SECRET}; echo y >> ${sibling}; cat ${sibling}; cat ${UNREADABLE}`,
        )

        expect(result.stdout).toContain('notes')
        // The re-applied tmpfs still hides the read-denied directory around
        // the restored allow path.
        expect(result.stdout).not.toContain('HIDDEN')
        expect(readFileSync(SECRET, 'utf8')).toBe('HOST\n')
        expect(readFileSync(sibling, 'utf8')).toBe('notes\n')
      },
    )

    it.skipIf(!BWRAP_CAN_NAMESPACE)(
      'keeps an allowRead carve-out readable and unwritable across the re-application',
      async () => {
        const carveOut = join(RO, 'pub')
        const carveOutFile = join(carveOut, 'note.txt')
        mkdirSync(carveOut)
        writeFileSync(carveOutFile, 'PUBLIC\n')

        const command = await wrapCommandWithSandboxLinux({
          command: `sh -c 'echo BOOTED; cat ${carveOutFile}; echo x >> ${carveOutFile}'`,
          needsNetworkRestriction: false,
          readConfig: { denyOnly: [RO], allowWithinDeny: [carveOut] },
          writeConfig: {
            allowOnly: [AREA, nestedAllow],
            denyWithinAllow: [PROJ],
          },
        })

        // The carve-out is restored by the re-application, not just by the
        // first pass the deny bind of PROJ buries.
        const lastTmpfs = command.lastIndexOf(`--tmpfs ${RO} `)
        expect(lastTmpfs).toBeGreaterThan(-1)
        expect(
          command.lastIndexOf(`--ro-bind ${carveOut} ${carveOut}`),
        ).toBeGreaterThan(lastTmpfs)

        const result = run(command)

        expect(result.stdout).toContain('BOOTED')
        expect(result.stdout).toContain('PUBLIC')
        expect(readFileSync(carveOutFile, 'utf8')).toBe('PUBLIC\n')
      },
    )

    it.skipIf(!BWRAP_CAN_NAMESPACE)(
      'still writes under the allow path when no write deny re-exposes the tmpfs',
      async () => {
        const sibling = join(nestedAllow, 'notes.txt')
        writeFileSync(sibling, 'notes\n')

        await runSandboxed(
          [SECRET],
          [RO],
          [AREA, nestedAllow],
          `echo x >> ${SECRET}; echo y >> ${sibling}`,
        )

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
        const hooks = join(nestedAllow, '.git', 'hooks')
        const config = join(nestedAllow, '.git', 'config')
        mkdirSync(hooks, { recursive: true })
        writeFileSync(config, '[core]\n')

        await runSandboxed(
          [PROJ, hooks, config],
          [RO],
          [AREA, nestedAllow],
          `echo hook > ${join(hooks, 'pre-commit')}; echo x >> ${config}`,
        )

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
        const absent = join(nestedAllow, '.secret')

        await runSandboxed(
          [absent, PROJ],
          [RO],
          [AREA, nestedAllow],
          `chmod u+w ${absent}; echo pwned > ${absent}`,
        )

        expect(readFileSync(absent, 'utf8')).toBe('')
      },
    )

    it.skipIf(!BWRAP_CAN_NAMESPACE)(
      'keeps an absent deny path uncreatable through its empty-dir placeholder',
      async () => {
        const placeholder = join(nestedAllow, '.cfg')
        const absent = join(placeholder, 'deep', 'x')

        await runSandboxed(
          [absent, PROJ],
          [RO],
          [AREA, nestedAllow],
          `mkdir -p ${join(placeholder, 'deep')} && echo pwned > ${absent}`,
        )

        expect(existsSync(absent)).toBe(false)
      },
    )
  })

  // A write-deny bind whose dest is hidden by a read-deny tmpfs is dropped:
  // binding it would expose the read-denied contents. The allowed write paths
  // beneath the dest are a different matter — the read-deny loop re-bound
  // them writable and they are inside that write deny, so they come back
  // read-only.
  describe('a write deny dropped as hidden by a read-deny tmpfs', () => {
    let RO: string // read-denied dir inside PROJ
    let DENIED: string // write-denied dir inside RO
    let INNER: string // allowed write path inside DENIED
    let INNER_FILE: string
    let UNREADABLE: string // read-denied file inside DENIED, outside INNER

    beforeEach(() => {
      RO = join(PROJ, 'ro')
      DENIED = join(RO, 'x')
      INNER = join(DENIED, 'inner')
      mkdirSync(INNER, { recursive: true })
      INNER_FILE = join(INNER, 'f')
      writeFileSync(INNER_FILE, 'HOST\n')
      UNREADABLE = join(DENIED, 'other.txt')
      writeFileSync(UNREADABLE, 'SECRET\n')
    })

    it('restores the allow path beneath the dropped dest read-only', async () => {
      const command = await wrap([DENIED], [RO], [AREA, INNER])

      expect(command).not.toContain(`--ro-bind ${DENIED} ${DENIED}`)
      const lastTmpfs = command.lastIndexOf(`--tmpfs ${RO} `)
      expect(lastTmpfs).toBeGreaterThan(-1)
      expect(
        command.lastIndexOf(`--ro-bind ${INNER} ${INNER}`),
      ).toBeGreaterThan(command.lastIndexOf(`--bind ${INNER} ${INNER}`))
    })

    it('binds the dest itself when no read deny hides it', async () => {
      const command = await wrap([DENIED], [], [AREA, INNER])

      expect(
        command.lastIndexOf(`--ro-bind ${DENIED} ${DENIED}`),
      ).toBeGreaterThan(command.lastIndexOf(`--bind ${INNER} ${INNER}`))
      expect(command).not.toContain(`--ro-bind ${INNER} ${INNER}`)
    })

    it.skipIf(!BWRAP_CAN_NAMESPACE)(
      'blocks the write beneath the dropped dest without lifting the read deny',
      async () => {
        const result = await runSandboxed(
          [DENIED],
          [RO],
          [AREA, INNER],
          `cat ${INNER_FILE}; echo pwned >> ${INNER_FILE}; cat ${UNREADABLE}`,
        )

        expect(result.stdout).toContain('HOST')
        expect(result.stdout).not.toContain('SECRET')
        expect(readFileSync(INNER_FILE, 'utf8')).toBe('HOST\n')
      },
    )

    it.skipIf(!BWRAP_CAN_NAMESPACE)(
      'keeps a read deny mounted inside the restored allow path',
      async () => {
        // The read-only restore lands above the mounts the denyRead loop made
        // under the allow path, so those are re-applied on top of it.
        const nestedReadDeny = join(INNER, 'sub')
        mkdirSync(nestedReadDeny)
        writeFileSync(join(nestedReadDeny, 'token.txt'), 'NESTED\n')

        const result = await runSandboxed(
          [DENIED],
          [RO, nestedReadDeny],
          [AREA, INNER],
          `cat ${join(nestedReadDeny, 'token.txt')}`,
        )

        expect(result.stdout).not.toContain('NESTED')
      },
    )
  })

  // An allowed write path that IS a masked file is the one restore to skip:
  // its mask already holds it unreadable and unwritable, and a read-only bind
  // of the real file would land above that mask; skipping keeps the mask the
  // last mount on the file instead of relying on the re-application pass. A
  // masked file BENEATH a restored directory is the opposite case and is
  // re-applied.
  describe('a write path that is itself a masked file', () => {
    const SECRET = 'REAL-PRIVATE-KEY'
    const SENTINEL = 'SENTINEL-NOT-A-KEY'

    let SECRETS: string // read-denied and write-denied dir inside PROJ
    let PEM: string // masked file inside SECRETS, and an allowed write path
    let SUB: string // allowed write DIRECTORY inside SECRETS
    let NESTED: string // masked file strictly beneath SUB
    let PLAIN: string // unmasked file beside NESTED
    let STORE: string // fake-file store for the credential mask
    let FAKE: string

    beforeEach(() => {
      SECRETS = join(PROJ, 'secrets')
      mkdirSync(SECRETS, { recursive: true })
      PEM = join(SECRETS, 'dev.pem')
      writeFileSync(PEM, SECRET + '\n')
      SUB = join(SECRETS, 'sub')
      mkdirSync(SUB)
      NESTED = join(SUB, 'nested.pem')
      writeFileSync(NESTED, SECRET + '\n')
      PLAIN = join(SUB, 'plain.txt')
      writeFileSync(PLAIN, 'PLAIN\n')
      STORE = join(BASE, 'store')
      mkdirSync(STORE, { recursive: true })
      FAKE = join(STORE, 'dev.pem.fake')
      writeFileSync(FAKE, SENTINEL + '\n')
    })

    // The write deny on SECRETS has to stay hidden by its own tmpfs, with PEM
    // an allowed write path at-or-under it.
    const readDenyMask = () => wrap([SECRETS], [SECRETS, PEM], [AREA, PEM])

    // Same shape with a credential mask in place of the /dev/null read deny.
    const credentialMask = (command = 'echo hello') =>
      wrapCommandWithSandboxLinux({
        command,
        needsNetworkRestriction: false,
        readConfig: { denyOnly: [SECRETS] },
        writeConfig: { allowOnly: [AREA, PEM], denyWithinAllow: [SECRETS] },
        maskedFileBinds: [{ realPath: PEM, fakePath: FAKE }],
        maskedFileStoreDir: STORE,
      })

    it('leaves the /dev/null mask as the last mount on the write path', async () => {
      const command = await readDenyMask()

      expect(countMounts(command, '--ro-bind', PEM, PEM)).toBe(0)
      expect(lastMountAt(command, PEM)).toBe(`--ro-bind /dev/null ${PEM}`)
    })

    it.skipIf(!BWRAP_CAN_NAMESPACE)(
      'keeps the read-denied write path unreadable and unwritable',
      async () => {
        const read = await runSandboxed(
          [SECRETS],
          [SECRETS, PEM],
          [AREA, PEM],
          `cat ${PEM}`,
        )
        // The whole of stdout, not merely "no secret in it": a read that fails
        // for any other reason satisfies that just as well. No exit-code
        // assertion — binds are mounted nodev, so opening the /dev/null mask
        // may be refused outright.
        expect(read.stdout.trim()).toBe('BOOTED')

        const write = await runSandboxed(
          [SECRETS],
          [SECRETS, PEM],
          [AREA, PEM],
          `echo pwned >> ${PEM}`,
        )
        expectDeniedByReadOnlyMount(write)
        expect(readFileSync(PEM, 'utf8')).toBe(SECRET + '\n')
      },
    )

    it('leaves the credential mask as the last mount on the write path', async () => {
      const command = await credentialMask()

      expect(countMounts(command, '--ro-bind', PEM, PEM)).toBe(0)
      expect(lastMountAt(command, PEM)).toBe(`--ro-bind ${FAKE} ${PEM}`)
    })

    it.skipIf(!BWRAP_CAN_NAMESPACE)(
      'serves the fake for a masked credential write path and refuses the write',
      async () => {
        const read = run(
          await credentialMask(`sh -c 'echo BOOTED; cat ${PEM}'`),
        )
        expect(read.stdout).toContain('BOOTED')
        expect(read.stdout).toContain(SENTINEL)
        expect(read.stdout).not.toContain(SECRET)

        const write = run(
          await credentialMask(`sh -c 'echo BOOTED; echo pwned >> ${PEM}'`),
        )
        expect(write.stdout).toContain('BOOTED')
        expectDeniedByReadOnlyMount(write)
        expect(readFileSync(PEM, 'utf8')).toBe(SECRET + '\n')
      },
    )

    it('re-masks a file strictly beneath a restored write directory', async () => {
      const command = await wrap([SECRETS], [SECRETS, NESTED], [AREA, SUB])

      expect(countMounts(command, '--ro-bind', SUB, SUB)).toBe(1)
      // Twice: the denyRead loop's mask, then the re-application on top of the
      // directory's restore. Position, not lastMountAt: both masks are the
      // same triple at the same destination, so only order distinguishes a
      // re-applied mask from one the restore buried.
      expect(countMounts(command, '--ro-bind', '/dev/null', NESTED)).toBe(2)
      expect(
        command.lastIndexOf(`--ro-bind /dev/null ${NESTED}`),
      ).toBeGreaterThan(command.lastIndexOf(`--ro-bind ${SUB} ${SUB}`))
    })

    it.skipIf(!BWRAP_CAN_NAMESPACE)(
      'keeps the rest of the restored directory readable',
      async () => {
        const result = await runSandboxed(
          [SECRETS],
          [SECRETS, NESTED],
          [AREA, SUB],
          `cat ${PLAIN}; cat ${NESTED}`,
        )

        expect(result.stdout.trim()).toBe('BOOTED\nPLAIN')
      },
    )
  })

  // A symlinked ANCESTOR component makes the spelling a mask is listed under
  // differ from the canonical spelling deny-write dests and allowWrite entries
  // carry. The mask itself goes where the spelling resolves, so every
  // consumer below compares one location; each case hands the decision to a
  // different one.
  describe('a mask listed through a symlinked ancestor', () => {
    const SECRET = 'REAL-PRIVATE-KEY'
    const SENTINEL = 'SENTINEL-NOT-A-KEY'

    let DOT: string // the real directory PROJ/.claude points into
    let REAL: string // the masked file, canonically
    let VIA_LINK: string // the same file, spelled through PROJ/.claude
    let STORE: string
    let FAKE: string

    beforeEach(() => {
      DOT = join(AREA, 'dotfiles', 'claude')
      mkdirSync(DOT, { recursive: true })
      REAL = join(DOT, 'secrets.json')
      writeFileSync(REAL, SECRET + '\n')
      // Relative target: an absolute one resolves outside the not-yet-pivoted
      // root and bwrap aborts on the mask's own bind, before any of this.
      symlinkSync(join('..', 'dotfiles', 'claude'), join(PROJ, '.claude'))
      VIA_LINK = join(PROJ, '.claude', 'secrets.json')
      STORE = join(BASE, 'store')
      mkdirSync(STORE)
      FAKE = join(STORE, 'secrets.json.fake')
      writeFileSync(FAKE, SENTINEL + '\n')
    })

    /**
     * The policy that hands the decision to each consumer the cases above
     * cover, for the live arms to walk: the restore inside a deny bind
     * dropped as hidden by its own tmpfs, the flush's own skip where the deny
     * dest IS the masked file, and the mask re-application where a bind of
     * the canonical ancestor directory lands after the mask. The read-deny
     * arm adds VIA_LINK to readDenied; the credential arm masks that spelling
     * with the fake instead.
     */
    const POLICIES = () => [
      { denyWrite: [DOT], readDenied: [DOT], allow: [AREA, REAL] },
      { denyWrite: [REAL], readDenied: [], allow: [AREA] },
      { denyWrite: [DOT], readDenied: [], allow: [AREA] },
    ]

    const credentialWrap = (
      denyWrite: string[],
      readDenied: string[],
      allow: string[],
      command = 'echo hello',
    ) =>
      wrapCommandWithSandboxLinux({
        command,
        needsNetworkRestriction: false,
        readConfig: { denyOnly: readDenied },
        writeConfig: { allowOnly: allow, denyWithinAllow: denyWrite },
        maskedFileBinds: [{ realPath: VIA_LINK, fakePath: FAKE }],
        maskedFileStoreDir: STORE,
      })

    it('keeps the mask when a dropped deny bind restores the file canonically', async () => {
      const command = await wrap([DOT], [DOT, VIA_LINK], [AREA, REAL])

      expect(countMounts(command, '--ro-bind', REAL, REAL)).toBe(0)
      expect(lastMountAt(command, REAL)).toBe(`--ro-bind /dev/null ${REAL}`)
      expect(lastMountAt(command, VIA_LINK)).toBeUndefined()
    })

    it('keeps the mask when the deny dest resolves to the masked file', async () => {
      const command = await wrap([REAL], [VIA_LINK], [AREA])

      expect(countMounts(command, '--ro-bind', REAL, REAL)).toBe(0)
      expect(lastMountAt(command, REAL)).toBe(`--ro-bind /dev/null ${REAL}`)
    })

    it('re-applies the mask a bind of the canonical ancestor directory buried', async () => {
      const command = await wrap([DOT], [VIA_LINK], [AREA])

      // Twice: the ancestor pin spliced in beneath the allow binds, then the
      // write deny's own bind. Both are self-binds of the same directory and
      // spell the same triple.
      expect(countMounts(command, '--ro-bind', DOT, DOT)).toBe(2)
      // Twice: the denyRead loop's mask, then the re-application above the
      // directory bind. Only order tells the two apart.
      expect(countMounts(command, '--ro-bind', '/dev/null', REAL)).toBe(2)
      expect(
        command.lastIndexOf(`--ro-bind /dev/null ${REAL}`),
      ).toBeGreaterThan(command.lastIndexOf(`--ro-bind ${DOT} ${DOT}`))
    })

    it('reconciles the same three spellings for a credential mask', async () => {
      const restored = await credentialWrap([DOT], [DOT], [AREA, REAL])
      expect(countMounts(restored, '--ro-bind', REAL, REAL)).toBe(0)
      expect(lastMountAt(restored, REAL)).toBe(`--ro-bind ${FAKE} ${REAL}`)

      const skipped = await credentialWrap([REAL], [], [AREA])
      expect(countMounts(skipped, '--ro-bind', REAL, REAL)).toBe(0)
      expect(lastMountAt(skipped, REAL)).toBe(`--ro-bind ${FAKE} ${REAL}`)

      const buried = await credentialWrap([DOT], [], [AREA])
      expect(countMounts(buried, '--ro-bind', FAKE, REAL)).toBe(2)
      expect(buried.lastIndexOf(`--ro-bind ${FAKE} ${REAL}`)).toBeGreaterThan(
        buried.lastIndexOf(`--ro-bind ${DOT} ${DOT}`),
      )
    })

    it.skipIf(!BWRAP_CAN_NAMESPACE)(
      'serves the read-denied file through neither spelling and refuses the write',
      async () => {
        for (const { denyWrite, readDenied, allow } of POLICIES()) {
          const read = await runSandboxed(
            denyWrite,
            [...readDenied, VIA_LINK],
            allow,
            `cat ${REAL}; cat ${VIA_LINK}`,
          )
          expect(read.stdout.trim()).toBe('BOOTED')

          const write = await runSandboxed(
            denyWrite,
            [...readDenied, VIA_LINK],
            allow,
            `echo pwned >> ${REAL}`,
          )
          expectDeniedByReadOnlyMount(write)
          expect(readFileSync(REAL, 'utf8')).toBe(SECRET + '\n')
        }
      },
    )

    it.skipIf(!BWRAP_CAN_NAMESPACE)(
      'serves the fake through both spellings and refuses the write',
      async () => {
        for (const { denyWrite, readDenied, allow } of POLICIES()) {
          const read = run(
            await credentialWrap(
              denyWrite,
              readDenied,
              allow,
              `sh -c 'echo BOOTED; cat ${REAL}; cat ${VIA_LINK}'`,
            ),
          )
          expect(read.stdout.trim()).toBe(
            ['BOOTED', SENTINEL, SENTINEL].join('\n'),
          )

          const write = run(
            await credentialWrap(
              denyWrite,
              readDenied,
              allow,
              `sh -c 'echo BOOTED; echo pwned >> ${REAL}'`,
            ),
          )
          expect(write.stdout).toContain('BOOTED')
          expectDeniedByReadOnlyMount(write)
          expect(readFileSync(REAL, 'utf8')).toBe(SECRET + '\n')
        }
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

  // denyWithinAllow wins over allowOnly however the two are nested. A deny's
  // read-only bind lands after every allow bind and is recursive, so it holds
  // the allowed write paths beneath it too.
  describe('a write deny and an allowed write path, by where each lies', () => {
    let SUB: string // PROJ/sub, the allowed write path most rows name

    beforeEach(() => {
      SUB = join(PROJ, 'sub')
      mkdirSync(join(AREA, 'other'))
      mkdirSync(join(AREA, 'proj2'))
      symlinkSync(AREA, join(BASE, 'to-area'))
      symlinkSync(PROJ, join(BASE, 'to-proj'))
      symlinkSync(SUB, join(BASE, 'to-sub'))
    })

    const under = (names: string[]) => names.map(name => join(BASE, name))

    /** The mount that decides `p` in the sandbox: the last at or above it. */
    const decidingMount = (command: string, p: string) =>
      mountsOf(command)
        .filter(mount => isAtOrUnder(p, mount.split(' ').at(-1) ?? ''))
        .at(-1)

    // Where the deny lies, denyWithinAllow, allowOnly, and the directories
    // that end up read-only and writable; every path is relative to BASE.
    const [A, P, S, O] = ['area', 'area/proj', 'area/proj/sub', 'area/other']
    const PLACEMENTS: [string, string[], string[], string[], string[]][] = [
      ['inside it', [P], [A], [S], [O]],
      ['equal to it', [P], [P], [S], []],
      ['above it', [P], [S], [S], []],
      ['two levels above it', [A], [S], [S], []],
      ['between two of them', [P], [A, S], [S], [O]],
      ['above one and beside another', [P], [O, S], [S], [O]],
      ['above two of them', [A], [O, S], [O, S], []],
      ['beside it', [O], [S], [], [S]],
      ['beside it, its name a prefix', [P], [P + '2'], [], [P + '2']],
      ['above it, through a symlink', ['to-proj'], [S], [S], []],
      ['above it, through a symlinked parent', ['to-area/proj'], [S], [S], []],
      ['above what it is a symlink to', [P], ['to-sub'], [S], []],
    ]

    it.each(PLACEMENTS)(
      'plans the mounts for a deny %s',
      async (_where, deny, allow, readOnly, writable) => {
        const command = await wrap(under(deny), [], under(allow))

        for (const dir of under(readOnly)) {
          expect(decidingMount(command, dir)).toStartWith('--ro-bind ')
        }
        for (const dir of under(writable)) {
          expect(decidingMount(command, dir)).toStartWith('--bind ')
        }
      },
    )

    it.skipIf(!BWRAP_CAN_NAMESPACE).each(PLACEMENTS)(
      'refuses and takes the writes for a deny %s',
      async (_where, deny, allow, readOnly, writable) => {
        const files = under([...readOnly, ...writable]).map(d => join(d, 'new'))

        await runSandboxed(
          under(deny),
          [],
          under(allow),
          files.map(file => `echo x > ${file}`).join('; '),
        )

        expect(files.filter(file => existsSync(file))).toEqual(
          under(writable).map(d => join(d, 'new')),
        )
      },
    )

    it('mounts nothing for a deny that meets no allowed write path', async () => {
      const command = await wrap([join(AREA, 'other'), PROJ], [], [PROJ + '2'])

      expect(mountsOf(command).filter(mount => mount.includes(AREA))).toEqual([
        `--bind ${PROJ}2 ${PROJ}2`,
      ])
    })

    it('names the deny and the allowed write path beneath it', async () => {
      const { warnings } = await withCapturedWarnings(() =>
        wrap([PROJ], [], [SUB]),
      )

      expect(warnings.join('\n')).toContain(
        `Write deny ${PROJ} covers allowed write path ${SUB}`,
      )
    })

    it('binds "/" again over the allowed write paths when "/" is denied', async () => {
      const command = await wrap(['/'], [], [SUB])

      // Two: the base root mount, then the deny's.
      expect(countMounts(command, '--ro-bind', '/', '/')).toBe(2)
      expect(decidingMount(command, SUB)).toBe('--ro-bind / /')
    })

    it.skipIf(!BWRAP_CAN_NAMESPACE)(
      'starts with "/" denied, and nothing is writable',
      async () => {
        await runSandboxed(['/'], [], [SUB], `echo x > ${join(SUB, 'new')}`)

        expect(existsSync(join(SUB, 'new'))).toBe(false)
      },
    )

    // An absent deny path beneath the covered write path is uncreatable, and
    // bubblewrap could not make a mount point for it on a read-only mount.
    describe('with absent deny paths in the allowed write path', () => {
      const orders = (): string[][] => {
        const denies = [PROJ, join(SUB, '.secret'), join(SUB, 'a', 'b')]
        return [denies, [...denies].reverse()]
      }

      it('gives them no mount point, in either order', async () => {
        for (const denies of orders()) {
          expect(
            mountsOf(await wrap(denies, [], [SUB])).filter(mount =>
              mount.includes(BASE),
            ),
          ).toEqual([`--bind ${SUB} ${SUB}`, `--ro-bind ${PROJ} ${PROJ}`])
        }
      })

      it.skipIf(!BWRAP_CAN_NAMESPACE)(
        'starts and keeps them uncreatable, in either order',
        async () => {
          for (const denies of orders()) {
            await runSandboxed(
              denies,
              [],
              [SUB],
              `echo x > ${join(SUB, '.secret')}; mkdir -p ${join(SUB, 'a', 'b')}`,
            )

            expect(existsSync(join(SUB, '.secret'))).toBe(false)
            expect(existsSync(join(SUB, 'a'))).toBe(false)
          }
        },
      )

      it.skipIf(!BWRAP_CAN_NAMESPACE)(
        'starts in an allowed working directory beneath the deny',
        async () => {
          // The mandatory denies of the working directory are such paths.
          process.chdir(SUB)

          const command = await wrap([PROJ], [], [SUB], 'echo BOOTED')

          expect(command).not.toContain(`/dev/null ${SUB}/`)
          expect(run(command).stdout).toContain('BOOTED')
        },
      )
    })

    // A placeholder is bubblewrap's mount point for an absent deny path, made
    // on the host. A path that only covered write paths hold gets none, read
    // denies or not: nothing can create it, and nothing is left on the host.
    describe('with the working directory in the allowed write path', () => {
      let ABSENT: string // a configured deny path, absent like the dotfiles

      beforeEach(() => {
        ABSENT = join(SUB, '.secret')
        process.chdir(SUB)
      })

      const placeholdersIn = (command: string, dir: string) =>
        mountsOf(command)
          .filter(m => /^--ro-bind (\/dev\/null|\S*claude-empty-\S+) /.test(m))
          .map(mount => mount.split(' ').at(-1) ?? '')
          .filter(dest => isAtOrUnder(dest, dir))

      const wrapHere = (
        denyWithinAllow: string[],
        denyOnly: string[],
        allowOnly: string[],
        command = 'echo hello',
      ) =>
        wrapCommandWithSandboxLinux({
          command,
          needsNetworkRestriction: false,
          readConfig: { denyOnly, allowWithinDeny: [SUB] },
          writeConfig: { allowOnly, denyWithinAllow },
        })

      const attempt = () =>
        `sh -c 'echo BOOTED; cat ${FILE}; for f in new .secret .bashrc; do echo x > ${SUB}/$f; done'`

      // The read deny, relative to BASE, and how the write path is spelled.
      const READ_DENIES: [string, string[], string][] = [
        ['no read deny', [], S],
        ['a read deny at the write deny', [A], S],
        ['a read deny at the write deny, the write path "."', [A], '.'],
        ['a read deny above the write deny', ['.'], S],
        ['a read deny between the two', [P], S],
      ]

      it.each(READ_DENIES)(
        'plans no placeholder with %s',
        async (_name, readDenied, root) => {
          const command = await wrapHere(
            [AREA, ABSENT],
            under(readDenied),
            root === '.' ? ['.'] : under([root]),
          )

          expect(placeholdersIn(command, BASE)).toEqual([])
          expect(decidingMount(command, ABSENT)).toStartWith('--ro-bind ')
        },
      )

      it.skipIf(!BWRAP_CAN_NAMESPACE).each(READ_DENIES)(
        'runs read-only and leaves the host as it is with %s',
        async (_name, readDenied, root) => {
          const result = run(
            await wrapHere(
              [AREA, ABSENT],
              under(readDenied),
              root === '.' ? ['.'] : under([root]),
              attempt(),
            ),
          )

          expect(result.stderr).not.toContain('bwrap:')
          expect(result.stdout).toBe('BOOTED\n{}\n')
          expect(readdirSync(SUB)).toEqual(['settings.json'])
        },
      )

      it('plans them with a read deny and no write deny above', async () => {
        const planned = placeholdersIn(
          await wrapHere([ABSENT], [AREA], [SUB]),
          BASE,
        )

        expect(planned).toContain(ABSENT)
        expect(planned).toContain(join(SUB, '.bashrc'))
      })

      it.skipIf(!BWRAP_CAN_NAMESPACE)(
        'writes beside them with a read deny and no write deny above, and the clean-up removes them',
        async () => {
          const result = run(await wrapHere([ABSENT], [AREA], [SUB], attempt()))

          expect(result.stdout).toBe('BOOTED\n{}\n')
          expect(readFileSync(ABSENT, 'utf8')).toBe('')
          cleanupBwrapMountPoints()
          expect(readdirSync(SUB).sort()).toEqual(['new', 'settings.json'])
        },
      )
    })

    // The other side of that rule: a path that any write path with no deny
    // directory above it holds can be created, and keeps its placeholder.
    describe.each([
      ['no read deny', []],
      ['a read deny above them all', [A]],
    ])(
      'with an absent deny path, by what holds it, and %s',
      (_, readDenied) => {
        beforeEach(() => {
          mkdirSync(join(SUB, 'deeper'))
          mkdirSync(join(AREA, 'proj2', 'in'))
        })

        // denyWithinAllow's directories, allowOnly, the directory of the absent
        // deny path, and whether that directory ends up writable.
        const D = S + '/deeper'
        const HOLDERS: [string, string[], string[], string, boolean][] = [
          ['a covered write path', [P], [S], S, false],
          ['two covered write paths', [P], [S, D], D, false],
          ['one covered twice', [A, P], [S], S, false],
          [
            'one covered, a prefix beside it',
            [P + '2'],
            [P, P + '2/in'],
            P + '2/in',
            false,
          ],
          ['one beside the deny', [P], [S, O], O, true],
          [
            'one beside it, its name a prefix',
            [P],
            [S, P + '2'],
            P + '2',
            true,
          ],
          ['one above the deny, beside it', [S], [P], P, true],
        ]

        it.each(HOLDERS)(
          'plans for one that %s holds',
          async (_name, deny, allow, dir, writable) => {
            const absent = join(BASE, dir, '.secret')
            const command = await wrap(
              [...under(deny), absent],
              under(readDenied),
              under(allow),
            )

            expect(countMounts(command, '--ro-bind', '/dev/null', absent)).toBe(
              writable ? 1 : 0,
            )
            expect(decidingMount(command, absent)).toStartWith('--ro-bind ')
          },
        )

        it.skipIf(!BWRAP_CAN_NAMESPACE).each(HOLDERS)(
          'keeps one that %s holds uncreatable',
          async (_name, deny, allow, dir, writable) => {
            const absent = join(BASE, dir, '.secret')

            await runSandboxed(
              [...under(deny), absent],
              under(readDenied),
              under(allow),
              `echo x > ${absent}; echo x > ${join(BASE, dir, 'new')}`,
            )
            cleanupBwrapMountPoints()

            expect(existsSync(absent)).toBe(false)
            expect(existsSync(join(BASE, dir, 'new'))).toBe(writable)
          },
        )
      },
    )

    // Each wrap plans from its own configuration and the host as it finds it.
    describe('with the deny above there for one command and not the next', () => {
      it.skipIf(!BWRAP_CAN_NAMESPACE).each([
        ['first', [true, false]],
        ['second', [false, true]],
      ])('plans each command on its own, there %s', async (_name, commands) => {
        const absent = join(SUB, '.secret')
        for (const covered of commands) {
          rmSync(join(SUB, 'new'), { force: true })

          const command = await SandboxManager.wrapWithSandbox(
            `echo BOOTED; echo x > ${absent}; echo x > ${join(SUB, 'new')}`,
            undefined,
            {
              filesystem: {
                denyRead: [],
                allowWrite: [SUB],
                denyWrite: covered ? [PROJ, absent] : [absent],
              },
            },
          )
          expect(countMounts(command, '--ro-bind', '/dev/null', absent)).toBe(
            covered ? 0 : 1,
          )
          expect(run(command).stdout).toContain('BOOTED')

          // A mount point stays on the host until the clean-up, empty.
          expect(readdirSync(SUB).sort()).toEqual(
            covered ? ['settings.json'] : ['.secret', 'new', 'settings.json'],
          )
          if (!covered) expect(readFileSync(absent, 'utf8')).toBe('')
          SandboxManager.cleanupAfterCommand()
          expect(existsSync(absent)).toBe(false)
        }
      })
    })

    // The mandatory denies follow the same rule as the configured ones.
    describe('with the working directory outside every allowed write path', () => {
      it.each([
        '.git/hooks',
        '.vscode',
        '.idea',
        '.claude/commands',
        '.claude/agents',
      ])('holds an allowed write path beneath %s read-only', async name => {
        const inner = join(BASE, name, 'inner')
        mkdirSync(inner, { recursive: true })

        const command = await wrap([], [], [inner])

        expect(decidingMount(command, inner)).toBe(
          `--ro-bind ${join(BASE, name)} ${join(BASE, name)}`,
        )
      })

      it('leaves an allowed write path beside them writable', async () => {
        const objects = join(BASE, '.git', 'objects')
        mkdirSync(objects, { recursive: true })
        mkdirSync(join(BASE, '.git', 'hooks'))

        const command = await wrap([], [], [objects])

        expect(decidingMount(command, objects)).toBe(
          `--bind ${objects} ${objects}`,
        )
      })

      it.skipIf(!BWRAP_CAN_NAMESPACE)(
        'refuses a write beneath .git/hooks and takes one beside it',
        async () => {
          const inner = join(BASE, '.git', 'hooks', 'inner')
          const objects = join(BASE, '.git', 'objects')
          mkdirSync(inner, { recursive: true })
          mkdirSync(objects)

          await runSandboxed(
            [],
            [],
            [inner, objects],
            `echo x > ${join(inner, 'new')}; echo x > ${join(objects, 'new')}`,
          )

          expect(existsSync(join(inner, 'new'))).toBe(false)
          expect(existsSync(join(objects, 'new'))).toBe(true)
        },
      )
    })

    // The deny's bind shows the host's directory again, everything the read
    // section hid beneath it included, so all of that goes back on top of it:
    // each tmpfs with what it restores, then the file masks.
    describe('with read denies beneath the deny', () => {
      const HIDDEN = 'HIDDEN'
      let SECRET: string // read-denied directory beside SUB
      let PUB: string // allowRead directory inside SECRET
      let VAULT: string // credential-denied directory beside SUB
      let TOKEN: string // read-denied file beside SUB
      let CRED: string // credential-denied file beside SUB
      let NETRC: string // masked credential file beside SUB
      let PRIVATE: string // read-denied directory inside SUB
      let ENV: string // read-denied file inside SUB
      let STORE: string
      let FAKE: string

      beforeEach(() => {
        SECRET = join(PROJ, 'secret')
        PUB = join(SECRET, 'pub')
        VAULT = join(PROJ, 'vault')
        PRIVATE = join(SUB, 'private')
        STORE = join(BASE, 'store')
        for (const dir of [PUB, VAULT, PRIVATE, STORE]) {
          mkdirSync(dir, { recursive: true })
        }
        TOKEN = join(PROJ, 'token')
        CRED = join(PROJ, 'cred')
        NETRC = join(PROJ, 'netrc')
        ENV = join(SUB, '.env')
        for (const file of [
          TOKEN,
          CRED,
          NETRC,
          ENV,
          join(SECRET, 'key'),
          join(VAULT, 'key'),
          join(PRIVATE, 'key'),
        ]) {
          writeFileSync(file, HIDDEN + '\n')
        }
        writeFileSync(join(PUB, 'note'), 'PUBLIC\n')
        FAKE = join(STORE, 'netrc.fake')
        writeFileSync(FAKE, 'SENTINEL\n')
      })

      const wrapAll = (denyWithinAllow: string[], command = 'echo hello') =>
        wrapCommandWithSandboxLinux({
          command,
          needsNetworkRestriction: false,
          readConfig: {
            denyOnly: [SECRET, VAULT, TOKEN, CRED, PRIVATE, ENV],
            credentialDenyOnly: [VAULT, CRED],
            allowWithinDeny: [PUB],
          },
          writeConfig: { allowOnly: [SUB], denyWithinAllow },
          maskedFileBinds: [{ realPath: NETRC, fakePath: FAKE }],
          maskedFileStoreDir: STORE,
        })

      const readSection = () => [
        `--tmpfs ${SECRET}`,
        `--ro-bind ${PUB} ${PUB}`,
        `--tmpfs ${VAULT}`,
        `--tmpfs ${PRIVATE}`,
        `--ro-bind /dev/null ${TOKEN}`,
        `--ro-bind /dev/null ${CRED}`,
        `--ro-bind /dev/null ${ENV}`,
        `--ro-bind ${FAKE} ${NETRC}`,
      ]

      it('puts every one of them back after the bind, the masks last', async () => {
        const mounts = mountsOf(await wrapAll([PROJ]))

        expect(
          mounts.slice(mounts.indexOf(`--ro-bind ${PROJ} ${PROJ}`)),
        ).toEqual([
          `--ro-bind ${PROJ} ${PROJ}`,
          ...readSection(),
          `--ro-bind ${STORE} ${STORE}`,
          '--dev /dev',
          '--proc /proc',
        ])
      })

      it('mounts each of them once with no write deny above', async () => {
        const mounts = mountsOf(await wrapAll([]))

        expect(mounts.filter(m => m.includes(PROJ)).sort()).toEqual(
          [`--bind ${SUB} ${SUB}`, ...readSection()].sort(),
        )
      })

      it.skipIf(!BWRAP_CAN_NAMESPACE).each([
        ['a write deny above', true],
        ['no write deny', false],
      ])('shows none of them with %s', async (_name, denied) => {
        const reads = [
          TOKEN,
          CRED,
          ENV,
          join(SECRET, 'key'),
          join(VAULT, 'key'),
          join(PRIVATE, 'key'),
        ]
        const result = run(
          await wrapAll(
            denied ? [PROJ] : [],
            `sh -c 'echo BOOTED; cat ${reads.join(' ')} ${NETRC} ${join(PUB, 'note')} ${FILE}; echo x > ${join(SUB, 'new')}; echo x >> ${join(PUB, 'note')}; echo x >> ${ENV}'`,
          ),
        )

        expect(result.stderr).not.toContain('bwrap:')
        expect(result.stdout).toBe('BOOTED\nSENTINEL\nPUBLIC\n{}\n')
        expect(existsSync(join(SUB, 'new'))).toBe(!denied)
        expect(readFileSync(join(PUB, 'note'), 'utf8')).toBe('PUBLIC\n')
        expect(readFileSync(ENV, 'utf8')).toBe(HIDDEN + '\n')
      })

      // A read deny at or above the write deny hides it, and binding it would
      // show it: the allowed write path alone comes back, read-only.
      it.each([
        ['at', () => PROJ],
        ['above', () => AREA],
      ])(
        'does not bind a deny with a read deny %s it',
        async (_where, hidden) => {
          const command = await wrap([PROJ], [hidden(), ENV], [SUB])

          expect(countMounts(command, '--ro-bind', PROJ, PROJ)).toBe(0)
          expect(decidingMount(command, join(SUB, 'new'))).toBe(
            `--ro-bind ${SUB} ${SUB}`,
          )
          expect(decidingMount(command, TOKEN)).toBe(`--tmpfs ${hidden()}`)
          expect(decidingMount(command, ENV)).toBe(`--ro-bind /dev/null ${ENV}`)
        },
      )

      it.skipIf(!BWRAP_CAN_NAMESPACE).each([
        ['at', () => PROJ],
        ['above', () => AREA],
      ])(
        'refuses the write and shows nothing with a read deny %s the deny',
        async (_where, hidden) => {
          const result = await runSandboxed(
            [PROJ],
            [hidden(), ENV],
            [SUB],
            `cat ${TOKEN} ${ENV} ${FILE}; echo x > ${join(SUB, 'new')}`,
          )

          expect(result.stdout).toBe('BOOTED\n{}\n')
          expect(existsSync(join(SUB, 'new'))).toBe(false)
        },
      )
    })
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

      expect(countMounts(command, '--bind', '/', '/')).toBe(1)
      expect(countMounts(command, '--ro-bind', FILE, FILE)).toBe(1)
      expect(countMounts(command, '--ro-bind', denied, denied)).toBe(1)
    })

    it('binds the mandatory denies that exist and stubs the ones that do not', async () => {
      const bashrc = join(BASE, '.bashrc')
      const hooks = join(BASE, '.git', 'hooks')
      const mcp = join(BASE, '.mcp.json')
      writeFileSync(bashrc, '')
      mkdirSync(hooks, { recursive: true })

      const command = await wrap([], [], ['/'])

      expect(countMounts(command, '--ro-bind', bashrc, bashrc)).toBe(1)
      expect(countMounts(command, '--ro-bind', hooks, hooks)).toBe(1)
      // Absent: blocked from being created rather than bound read-only.
      expect(countMounts(command, '--ro-bind', '/dev/null', mcp)).toBe(1)
    })

    it('skips every per-path deny when "/" is denied whole, and keeps skipping them when "/" is vetoed', async () => {
      // allowOnly ['/'] and denyWithinAllow ['/'] and nothing else: '/' is
      // recorded as a covering deny directory, and nothing vetoes it — no
      // allowed write path lies strictly beneath it, and there is no
      // read-deny tmpfs at all. Every other deny, bind and stub alike, is
      // then skipped as already covered, and the deny-side --ro-bind / /
      // after the allow's writable --bind / / is the whole protection.
      // readConfig is undefined rather than { denyOnly: [] } so the implicit
      // /etc/ssh/ssh_config.d deny cannot make the verdict host-dependent.
      const bashrc = join(BASE, '.bashrc')
      const hooks = join(BASE, '.git', 'hooks')
      const mcp = join(BASE, '.mcp.json')
      writeFileSync(bashrc, '')
      mkdirSync(hooks, { recursive: true })
      const wrapRoot = (
        allowOnly: string[],
        readConfig: { denyOnly: string[] } | undefined,
      ) =>
        wrapCommandWithSandboxLinux({
          command: 'echo hello',
          needsNetworkRestriction: false,
          readConfig,
          writeConfig: { allowOnly, denyWithinAllow: ['/'] },
        })

      const rootDeniedWhole = await wrapRoot(['/'], undefined)

      expect(countMounts(rootDeniedWhole, '--bind', '/', '/')).toBe(1)
      // Two: the base root mount, then the deny bind of '/'.
      expect(countMounts(rootDeniedWhole, '--ro-bind', '/', '/')).toBe(2)
      expect(rootDeniedWhole.lastIndexOf('--ro-bind / /')).toBeGreaterThan(
        rootDeniedWhole.indexOf('--bind / /'),
      )
      expect(countMounts(rootDeniedWhole, '--ro-bind', bashrc, bashrc)).toBe(0)
      expect(countMounts(rootDeniedWhole, '--ro-bind', hooks, hooks)).toBe(0)
      expect(countMounts(rootDeniedWhole, '--ro-bind', '/dev/null', mcp)).toBe(
        0,
      )
      expect(rootDeniedWhole).not.toContain('claude-empty-')

      // A second allow entry vetoes '/' — it lies strictly beneath it — and
      // so does a single read-deny directory, the re-application's trigger.
      // Neither brings the per-path denies back: the root's own read-only
      // bind still covers every candidate that lies outside the read-deny
      // tmpfs set. What does bring a deny back is a candidate that bind
      // cannot reach — one inside a predicted tmpfs, or a prediction that
      // could not be derived — which readonly-deny-dir-stubs.test.ts covers.
      const secondAllow = await wrapRoot(['/', AREA], undefined)
      expect(countMounts(secondAllow, '--ro-bind', bashrc, bashrc)).toBe(0)
      expect(countMounts(secondAllow, '--ro-bind', '/dev/null', mcp)).toBe(0)

      const readDenied = join(BASE, 'ro')
      mkdirSync(readDenied)
      const oneReadDeny = await wrapRoot(['/'], { denyOnly: [readDenied] })
      expect(countMounts(oneReadDeny, '--ro-bind', bashrc, bashrc)).toBe(0)
      expect(countMounts(oneReadDeny, '--ro-bind', '/dev/null', mcp)).toBe(0)
    })

    it.skipIf(!BWRAP_CAN_NAMESPACE)(
      'boots with "/" denied whole, and the lone deny bind holds the write off',
      async () => {
        // The argv arm above pins a single `--ro-bind / /` after the allow's
        // `--bind / /` as the entire protection. Prove bubblewrap agrees:
        // it starts (nothing beneath the read-only root needs creating,
        // because every per-path deny was skipped), the tree it re-binds is
        // readable, and a write through it fails and changes nothing.
        const wrapRootDeniedWhole = (command: string) =>
          wrapCommandWithSandboxLinux({
            command,
            needsNetworkRestriction: false,
            readConfig: undefined,
            writeConfig: { allowOnly: ['/'], denyWithinAllow: ['/'] },
          })

        const write = run(
          await wrapRootDeniedWhole(`echo BOOTED; sh -c 'echo x >> ${FILE}'`),
        )
        expect(write.stdout).toContain('BOOTED')
        expectDeniedByReadOnlyMount(write)
        expect(readFileSync(FILE, 'utf8')).toBe('{}\n')

        const read = run(await wrapRootDeniedWhole(`echo BOOTED; cat ${FILE}`))
        expect(read.error).toBeUndefined()
        expect(read.stderr).not.toContain('bwrap:')
        expect(read.status).toBe(0)
        expect(read.stdout).toContain('BOOTED')
        expect(read.stdout).toContain('{}')
      },
    )

    it('masks a symlinked ancestor of a deny path', async () => {
      // A self-referential link: resolveSymlinkedDenyPath gives up and the
      // fail-closed branch masks the symlink component, so it cannot be
      // deleted and recreated as a real directory.
      const loop = join(AREA, 'loop')
      symlinkSync('loop', loop)

      const command = await wrap([join(loop, 'settings.json')], [], ['/'])

      expect(countMounts(command, '--ro-bind', '/dev/null', loop)).toBe(1)
    })

    it.skipIf(!BWRAP_CAN_NAMESPACE)(
      'denies the write at runtime and leaves the rest of the tree writable',
      async () => {
        const control = join(AREA, 'control.txt')
        writeFileSync(control, '')

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
      },
    )
  })
})
