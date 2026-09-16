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
import { countMounts, lastMountAt } from '../helpers/bwrap-argv.js'
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

  it('keeps the descendant bind when an allowed write path sits strictly beneath the covering dir (veto)', async () => {
    // Same veto as the stub skip: an allowWrite under PROJ is bound writable
    // before the covering bind, so that bind is not the only mount claiming
    // the subtree and the explicit deny keeps its own.
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
    // '/' recorded and vetoed (AREA is writable beneath it). A veto that
    // disqualified every skip would stub each absent mandatory-deny dotfile
    // of the write-denied cwd after the cwd's own bind — the startup abort
    // readonly-deny-dir-stubs.test.ts documents.
    process.chdir(PROJ)
    const command = await wrap(['/', PROJ], [], ['/', AREA])

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
  // carry. Each case below hands the decision to a different consumer.
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
      expect(lastMountAt(command, VIA_LINK)).toBe(
        `--ro-bind /dev/null ${VIA_LINK}`,
      )
    })

    it('keeps the mask when the deny dest resolves to the masked file', async () => {
      const command = await wrap([REAL], [VIA_LINK], [AREA])

      expect(countMounts(command, '--ro-bind', REAL, REAL)).toBe(0)
      expect(lastMountAt(command, VIA_LINK)).toBe(
        `--ro-bind /dev/null ${VIA_LINK}`,
      )
    })

    it('re-applies the mask a bind of the canonical ancestor directory buried', async () => {
      const command = await wrap([DOT], [VIA_LINK], [AREA])

      // Twice: the ancestor pin spliced in beneath the allow binds, then the
      // write deny's own bind. Both are self-binds of the same directory and
      // spell the same triple.
      expect(countMounts(command, '--ro-bind', DOT, DOT)).toBe(2)
      // Twice: the denyRead loop's mask, then the re-application above the
      // directory bind. Only order tells the two apart.
      expect(countMounts(command, '--ro-bind', '/dev/null', VIA_LINK)).toBe(2)
      expect(
        command.lastIndexOf(`--ro-bind /dev/null ${VIA_LINK}`),
      ).toBeGreaterThan(command.lastIndexOf(`--ro-bind ${DOT} ${DOT}`))
    })

    it('reconciles the same three spellings for a credential mask', async () => {
      const restored = await credentialWrap([DOT], [DOT], [AREA, REAL])
      expect(countMounts(restored, '--ro-bind', REAL, REAL)).toBe(0)
      expect(lastMountAt(restored, VIA_LINK)).toBe(
        `--ro-bind ${FAKE} ${VIA_LINK}`,
      )

      const skipped = await credentialWrap([REAL], [], [AREA])
      expect(countMounts(skipped, '--ro-bind', REAL, REAL)).toBe(0)
      expect(lastMountAt(skipped, VIA_LINK)).toBe(
        `--ro-bind ${FAKE} ${VIA_LINK}`,
      )

      const buried = await credentialWrap([DOT], [], [AREA])
      expect(countMounts(buried, '--ro-bind', FAKE, VIA_LINK)).toBe(2)
      expect(
        buried.lastIndexOf(`--ro-bind ${FAKE} ${VIA_LINK}`),
      ).toBeGreaterThan(buried.lastIndexOf(`--ro-bind ${DOT} ${DOT}`))
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
