import { describe, it, expect, beforeEach, afterEach, spyOn } from 'bun:test'
import * as fs from 'fs'
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
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
import { bwrapCanNamespace } from '../helpers/bwrap-namespace.js'
import { lastIndexOfMount } from '../helpers/bwrap-argv.js'
import { withCapturedWarnings } from '../helpers/captured-warnings.js'

/**
 * Regression tests for creation-blocking stubs under a read-only denied
 * directory.
 *
 * When denyWithinAllow covers a directory itself (e.g. the working
 * directory of a deliberately write-protected checkout), that directory is
 * re-bound read-only (--ro-bind <dir> <dir>). Every ABSENT deny path
 * beneath it — such as the mandatory dotfile denies (.gitconfig, .bashrc,
 * …) when cwd has none — used to still get a creation-blocking stub
 * (--ro-bind /dev/null <path> or a read-only empty dir). bwrap applies
 * mounts in order and must creat()/mkdir the stub's mount point inside the
 * read-only mount, so EVERY sandboxed command aborted at startup with
 * "bwrap: Can't create file at <path>: Read-only file system".
 *
 * The fix skips the stub when the absent path's deepest existing ancestor
 * sits inside a directory the deny loop re-binds read-only — the path is
 * already uncreatable there — and keeps the stub (fail closed, preferring
 * the pre-existing abort to a silently creatable deny path) whenever the
 * covering bind is not the last word on that subtree: an allowed write
 * path strictly beneath the covering directory, or a read-deny tmpfs
 * comparable with it (at/beneath it, or containing it or any spelling it
 * was reached through). Those vetoes are kept conservatively: the denyRead
 * re-applications restore what they cover read-only.
 */
describe.if(isLinux)('Deny stubs under a read-only denied directory', () => {
  // realpathSync so exact-string assertions hold even when tmpdir itself
  // contains symlinks.
  let BASE: string
  let AREA: string // allowed write area
  let PROJ: string // write-denied project dir inside AREA

  const savedCwd = process.cwd()

  const BWRAP_CAN_NAMESPACE = bwrapCanNamespace()

  beforeEach(() => {
    BASE = realpathSync(mkdtempSync(join(tmpdir(), 'ro-deny-stub-')))
    AREA = join(BASE, 'area')
    PROJ = join(AREA, 'proj')
    mkdirSync(PROJ, { recursive: true })
    writeFileSync(join(PROJ, 'README.md'), '# test\n')
  })

  afterEach(() => {
    process.chdir(savedCwd)
    cleanupBwrapMountPoints({ force: true })
    rmSync(BASE, { recursive: true, force: true })
  })

  const runIn = (wrapped: string) =>
    spawnSync(wrapped, {
      shell: true,
      encoding: 'utf8',
      timeout: 15000,
      cwd: PROJ,
    })

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
      writeConfig: {
        allowOnly: allowPaths,
        denyWithinAllow: denyPaths,
      },
    })
  }

  it('skips stubs for absent mandatory-deny dotfiles inside a write-denied cwd', async () => {
    // The real-world shape: cwd is write-denied, so the mandatory dotfile
    // denies at cwd (.gitconfig, .bashrc, …) are all absent stub candidates.
    process.chdir(PROJ)

    const command = await wrap([PROJ])

    // The deny reached bwrap: cwd is re-bound read-only.
    const cwdReadOnlyBind = `--ro-bind ${PROJ} ${PROJ}`
    expect(command).toContain(cwdReadOnlyBind)
    // The named symptom: no /dev/null stub at <cwd>/.gitconfig.
    expect(command).not.toContain(
      `--ro-bind /dev/null ${join(PROJ, '.gitconfig')}`,
    )
    // The invariant: no stub destination anywhere under the read-only
    // re-bound cwd — /dev/null file stubs and read-only empty-directory
    // stubs both require bwrap to create the mount point inside the
    // read-only mount. Re-binds of EXISTING paths onto themselves create
    // nothing and are fine. The slice starts at the argv words after that
    // bind, never at a character offset a longer path could match inside.
    const afterReadOnlyRebind = command
      .split(/\s+/)
      .slice(lastIndexOfMount(command, '--ro-bind', PROJ, PROJ) + 3)
      .join(' ')
    expect(afterReadOnlyRebind).not.toContain(`/dev/null ${PROJ}/`)
    expect(afterReadOnlyRebind).not.toMatch(
      /--ro-bind \S*claude-empty-\S+ \S*\/proj\//,
    )
  })

  it.skipIf(!BWRAP_CAN_NAMESPACE)(
    'boots in a write-denied cwd and still refuses to create the dotfile',
    async () => {
      // The pre-fix symptom was a startup abort with no command executed.
      process.chdir(PROJ)
      const booted = runIn(await wrap([PROJ]))
      expect(booted.stderr ?? '').not.toMatch(/Read-only file system/i)
      expect(booted.status).toBe(0)
      expect(booted.stdout).toContain('hello')

      const denied = runIn(
        await wrap([PROJ], [], [AREA], `touch ${join(PROJ, '.gitconfig')}`),
      )
      expect(denied.status).not.toBe(0)
      expect(existsSync(join(PROJ, '.gitconfig'))).toBe(false)
    },
  )

  it('still stubs an absent mandatory-deny dotfile when the cwd remains writable (no over-broad skip)', async () => {
    // Control: without the covering denyWrite, cwd stays writable, so the
    // stub is still required to block creating the dotfile.
    process.chdir(PROJ)

    const command = await wrap([])

    expect(command).toContain(`--bind ${AREA} ${AREA}`)
    expect(command).toContain(`--ro-bind /dev/null ${join(PROJ, '.gitconfig')}`)
  })

  it('keeps the stub (fails closed) when an allowed write path beneath the denied dir is restored by denyRead', async () => {
    // The one shape where "the ancestor is under a read-only deny" is not
    // the last word on its own: a denyRead directory inside the
    // write-denied dir plus an allowWrite path beneath it. The re-applied
    // "--tmpfs <dir>" lands after the deny binds it buries and restores the
    // allow path read-only; the stub is kept conservatively all the same.
    const readDenied = join(PROJ, 'ro')
    const nestedAllow = join(readDenied, 'w')
    mkdirSync(nestedAllow, { recursive: true })
    writeFileSync(join(nestedAllow, 'keep.txt'), 'x\n')
    const absentDeny = join(nestedAllow, '.secret')

    const command = await wrap(
      [PROJ, absentDeny],
      [readDenied],
      [AREA, nestedAllow],
    )

    expect(command).toContain(`--ro-bind ${PROJ} ${PROJ}`)
    expect(command).toContain(`--ro-bind /dev/null ${absentDeny}`)
  })

  it('keeps the stub when ANY covering deny dir has an allowed write path restored beneath it', async () => {
    // The read-only conclusion must hold across EVERY deny dir covering the
    // ancestor, not just one. Here the absent deny's ancestor d is covered
    // by both PROJ (which has the allowWrite t/w strictly beneath it,
    // restored by the denyRead re-application of t) and d itself (with
    // nothing beneath it). A per-dir check would skip on d, resting the
    // decision on a covering bind the t/w re-bind sits beneath.
    const readDenied = join(PROJ, 't')
    const nestedAllow = join(readDenied, 'w')
    const innerDenied = join(nestedAllow, 'd')
    mkdirSync(innerDenied, { recursive: true })
    writeFileSync(join(innerDenied, 'keep.txt'), 'x\n')
    const absentDeny = join(innerDenied, '.secret')

    const command = await wrap(
      [PROJ, innerDenied, absentDeny],
      [readDenied],
      [AREA, nestedAllow],
    )

    expect(command).toContain(`--ro-bind ${PROJ} ${PROJ}`)
    expect(command).toContain(`--ro-bind /dev/null ${absentDeny}`)
  })

  it('keeps the stub regardless of where the vetoed covering dir appears in the deny ordering', async () => {
    // Same shape, but the vetoed covering dir PROJ is listed AFTER the
    // absent entry. A decision that only consults deny dirs seen so far
    // would miss PROJ's veto and skip unsafely; the pre-pass collects
    // deny dirs order-independently, so the stub is kept.
    const readDenied = join(PROJ, 't')
    const nestedAllow = join(readDenied, 'w')
    const innerDenied = join(nestedAllow, 'd')
    mkdirSync(innerDenied, { recursive: true })
    writeFileSync(join(innerDenied, 'keep.txt'), 'x\n')
    const absentDeny = join(innerDenied, '.secret')

    const command = await wrap(
      [innerDenied, absentDeny, PROJ],
      [readDenied],
      [AREA, nestedAllow],
    )

    expect(command).toContain(`--ro-bind /dev/null ${absentDeny}`)
  })

  it('skips the stub when the covering deny dir is listed AFTER the absent entry and nothing vetoes it', async () => {
    // Order-independence in the safe direction: the skip must also work
    // when the covering directory comes later in denyWithinAllow.
    const absentDeny = join(PROJ, '.notyet')

    const command = await wrap([absentDeny, PROJ])

    expect(command).toContain(`--ro-bind ${PROJ} ${PROJ}`)
    expect(command).not.toContain(`--ro-bind /dev/null ${absentDeny}`)
  })

  it('keeps the stub when a denyRead directory sits under the covering deny dir (trigger without nested allow)', async () => {
    // A read-denied directory strictly inside the write-denied dir is the
    // TRIGGER for the post-deny re-application, so the covering bind is not
    // taken as the last word and the stub is kept even with no nested
    // allowWrite — a config a later allowWrite addition would otherwise
    // silently weaken.
    process.chdir(PROJ)
    const readDenied = join(PROJ, 'secrets')
    mkdirSync(readDenied)
    writeFileSync(join(readDenied, 'token.txt'), 'x\n')

    const command = await wrap([PROJ], [readDenied])

    expect(command).toContain(`--ro-bind ${PROJ} ${PROJ}`)
    expect(command).toContain(`--ro-bind /dev/null ${join(PROJ, '.gitconfig')}`)
  })

  it('skips the stub when only a file-level denyRead sits under the covering dir (no tmpfs, no re-open)', async () => {
    // Only an existing DIRECTORY in denyRead becomes a tmpfs and can
    // trigger the re-application; a read-denied FILE gets a read-only
    // /dev/null mask and re-opens nothing. It must not veto the skip —
    // otherwise the startup abort this fix removes comes straight back for
    // the common "deny reading .env in the checkout" configuration.
    process.chdir(PROJ)
    const deniedFile = join(PROJ, '.env')
    writeFileSync(deniedFile, 'SECRET=1\n')

    const command = await wrap([PROJ], [deniedFile])

    expect(command).toContain(`--ro-bind ${PROJ} ${PROJ}`)
    expect(command).not.toContain(
      `--ro-bind /dev/null ${join(PROJ, '.gitconfig')}`,
    )
  })

  it('skips the stub when an absent denyRead entry sits under the covering dir', async () => {
    // A non-existent denyRead entry is skipped outright by the denyRead
    // loop: no tmpfs, no re-application, nothing to re-open — so it must
    // not veto the skip either.
    process.chdir(PROJ)

    const command = await wrap([PROJ], [join(PROJ, 'no-such-path')])

    expect(command).toContain(`--ro-bind ${PROJ} ${PROJ}`)
    expect(command).not.toContain(
      `--ro-bind /dev/null ${join(PROJ, '.gitconfig')}`,
    )
  })

  it('keeps the stub when the covering dir is reached through a spelling a denyRead tmpfs hides', async () => {
    // The covering directory is reached through a symlink whose SPELLING
    // lies under a denyRead tmpfs (secrets/proj-link -> the project dir)
    // while its canonical dest is the writable project dir. The emission
    // filter drops the read-only re-bind as already-hidden-by-the-tmpfs, so
    // the directory is NOT read-only inside the sandbox; trusting the
    // recorded dir would skip the stub and leave the explicitly denied path
    // host-creatable. The guard mirrors that drop and keeps the stub.
    const secretsDir = join(BASE, 'secrets')
    mkdirSync(secretsDir)
    const projLink = join(secretsDir, 'proj-link')
    symlinkSync(PROJ, projLink)
    const absentDeny = join(PROJ, '.env')

    const command = await wrap([projLink, absentDeny], [secretsDir])

    expect(command).toContain(`--ro-bind /dev/null ${absentDeny}`)
  })

  it('skips stubs when the read-denied dirs are unrelated siblings of the write-denied dir', async () => {
    // A representative profile: a caller write-protects the checkout it
    // analyzes (cwd, inside the write allowlist), writes only to a separate
    // output dir, and read-denies credential directories elsewhere. Those
    // tmpfs dirs are INCOMPARABLE with the checkout — neither inside it nor
    // containing it — so the read-only re-bind is reliable, the absent
    // dotfile denies beneath it are not stubbed, and the sandbox starts
    // instead of aborting.
    const homeDir = join(BASE, 'home')
    mkdirSync(join(homeDir, '.ssh'), { recursive: true })
    writeFileSync(join(homeDir, '.ssh', 'id_test.pub'), 'ssh-test AAAA\n')
    const runDir = join(BASE, 'run')
    mkdirSync(runDir)
    process.chdir(PROJ)

    const command = await wrap([PROJ], [join(homeDir, '.ssh')], [AREA, runDir])

    expect(command).toContain(`--ro-bind ${PROJ} ${PROJ}`)
    expect(command).not.toContain(
      `--ro-bind /dev/null ${join(PROJ, '.gitconfig')}`,
    )
  })

  it.skipIf(!BWRAP_CAN_NAMESPACE)(
    'starts with the read-denied siblings mounted beside the write-denied cwd',
    async () => {
      const homeDir = join(BASE, 'home')
      mkdirSync(join(homeDir, '.ssh'), { recursive: true })
      writeFileSync(join(homeDir, '.ssh', 'id_test.pub'), 'ssh-test AAAA\n')
      const runDir = join(BASE, 'run')
      mkdirSync(runDir)
      process.chdir(PROJ)

      const started = runIn(
        await wrap([PROJ], [join(homeDir, '.ssh')], [AREA, runDir]),
      )
      expect(started.stderr ?? '').not.toMatch(/Read-only file system/i)
      expect(started.status).toBe(0)
    },
  )

  it('enforces denyWithinAllow under a trailing-slash allowOnly spelling', async () => {
    // A trailing-slash allowOnly entry survives normalizePathForSandbox and
    // used to defeat every `allowedPath + '/'` prefix comparison
    // ('<dir>//'), silently dropping denyWithinAllow re-binds while the
    // tree stayed bind-mounted writable. Allow paths are now recorded with
    // the slash stripped, so the deny is enforced and the bind spelling is
    // canonical.
    const secrets = join(PROJ, 'secrets')
    mkdirSync(secrets)
    writeFileSync(join(secrets, 'token.txt'), 'x\n')

    const command = await wrap([secrets], [], [`${AREA}/`])

    expect(command).toContain(`--bind ${AREA} ${AREA}`)
    expect(command).toContain(`--ro-bind ${secrets} ${secrets}`)
  })

  it('skips stubs under a trailing-slash allow spelled at the denied dir (no startup abort)', async () => {
    // The allow and the covering deny name the same directory in different
    // spellings (allowOnly '<proj>/', denyWithinAllow '<proj>'). With raw
    // spellings, veto (i) would misread '<proj>/' as strictly beneath
    // '<proj>' (prefix match against '<proj>' + '/') and keep the stubs —
    // resurrecting the startup abort. With the recorded spelling stripped,
    // the allow is AT the covering dir, no veto fires, and the stubs are
    // skipped.
    process.chdir(PROJ)

    const command = await wrap([PROJ], [], [`${PROJ}/`])

    expect(command).toContain(`--ro-bind ${PROJ} ${PROJ}`)
    expect(command).not.toContain(
      `--ro-bind /dev/null ${join(PROJ, '.gitconfig')}`,
    )
  })

  it.skipIf(!BWRAP_CAN_NAMESPACE)(
    'starts under a trailing-slash allow spelled at the denied dir',
    async () => {
      process.chdir(PROJ)

      const started = runIn(await wrap([PROJ], [], [`${PROJ}/`]))
      expect(started.stderr ?? '').not.toMatch(/Read-only file system/i)
      expect(started.status).toBe(0)
    },
  )

  it('re-applies a denyWithinAllow bind under a trailing-slash allow re-bound over a denyRead tmpfs', async () => {
    // The emission filter drops deny binds hidden by a denyRead tmpfs
    // UNLESS an allowed write path the tmpfs restored covers them. That
    // exception tests containment root-aware, which a trailing-slash allow
    // spelling used to defeat: the writable re-bind was emitted but the
    // deny bind beneath it was dropped — leaving the explicitly denied file
    // writable. With the recorded spelling stripped, the bind survives.
    const nestedAllow = join(PROJ, 'w')
    mkdirSync(nestedAllow, { recursive: true })
    const secret = join(nestedAllow, 'secret.txt')
    writeFileSync(secret, 'x\n')

    const command = await wrap([secret], [PROJ], [`${nestedAllow}/`])

    expect(command).toContain(`--tmpfs ${PROJ}`)
    expect(command).toContain(`--bind ${nestedAllow} ${nestedAllow}`)
    expect(command).toContain(`--ro-bind ${secret} ${secret}`)
  })

  it.skipIf(!BWRAP_CAN_NAMESPACE)(
    'starts, and still denies, under a write root of "/"',
    async () => {
      // A '/' write root contains everything, so the denies inside it apply
      // where a `root + '/'` prefix test matched nothing and dropped them
      // all. Both shapes have to start: with the root allowed only, the
      // absent cwd dotfiles are stubbed on a writable tree; with the root
      // denied as well, its second read-only bind covers them and they are
      // not stubbed, because a stub's mount point cannot be created there.
      process.chdir(PROJ)
      const dotfile = join(PROJ, '.gitconfig')

      const probe = `echo hello; (echo x > ${dotfile}) 2>/dev/null && echo WROTE || echo REFUSED`

      // Allowed only: the tree is writable, so the absent dotfile needs its
      // own stub. bwrap makes that stub's mount point on the host, so the
      // path existing afterwards says nothing; the refused write does.
      const writable = await wrapCommandWithSandboxLinux({
        command: probe,
        needsNetworkRestriction: false,
        writeConfig: { allowOnly: ['/'], denyWithinAllow: [] },
      })
      expect(writable).toContain(`--ro-bind /dev/null ${dotfile}`)
      const ran = spawnSync(writable, {
        shell: true,
        encoding: 'utf8',
        timeout: 15000,
        cwd: PROJ,
      })
      expect(ran.stderr ?? '').not.toContain('bwrap:')
      expect(ran.stdout).toContain('hello')
      expect(ran.stdout).toContain('REFUSED')
      cleanupBwrapMountPoints({ force: true })
      expect(existsSync(dotfile)).toBe(false)

      // Allowed and denied: the deny's second, read-only bind of '/' covers
      // the dotfile, so no stub is emitted — one there would be a mount
      // point bwrap has to create on that read-only root, and the sandbox
      // would not start.
      const denied = await wrapCommandWithSandboxLinux({
        command: probe,
        needsNetworkRestriction: false,
        writeConfig: { allowOnly: ['/'], denyWithinAllow: ['/'] },
      })
      expect(denied).not.toContain(`--ro-bind /dev/null ${dotfile}`)
      const ranDenied = spawnSync(denied, {
        shell: true,
        encoding: 'utf8',
        timeout: 15000,
        cwd: PROJ,
      })
      expect(ranDenied.stderr ?? '').not.toContain('bwrap:')
      expect(ranDenied.stdout).toContain('hello')
      expect(ranDenied.stdout).toContain('REFUSED')
      expect(existsSync(dotfile)).toBe(false)

      // Allowed and denied WITH a read policy: any read-deny tmpfs lies
      // under '/' and vetoes it, so the root's covering bind is judged
      // against the candidate instead. The dotfile is outside that tmpfs,
      // so it is still covered and still needs no stub.
      const readDenied = join(BASE, 'ro')
      mkdirSync(readDenied)
      writeFileSync(join(readDenied, 'token.txt'), 'x\n')
      const withRead = await wrapCommandWithSandboxLinux({
        command: probe,
        needsNetworkRestriction: false,
        readConfig: { denyOnly: [readDenied] },
        writeConfig: { allowOnly: ['/'], denyWithinAllow: ['/'] },
      })
      const ranWithRead = spawnSync(withRead, {
        shell: true,
        encoding: 'utf8',
        timeout: 15000,
        cwd: PROJ,
      })
      expect(ranWithRead.stderr ?? '').not.toContain('bwrap:')
      expect(ranWithRead.stdout).toContain('hello')
      expect(ranWithRead.stdout).toContain('REFUSED')
      expect(existsSync(dotfile)).toBe(false)
    },
  )

  it('stubs nothing under a "/" write root denied whole with a read policy', async () => {
    // The argv half of the bubblewrap case above: any read-deny tmpfs lies
    // under '/' and vetoes it, so the root's covering bind is judged against
    // the candidate instead. The dotfile is outside that tmpfs, so it is
    // still covered and still needs no stub.
    process.chdir(PROJ)
    const readDenied = join(BASE, 'ro')
    mkdirSync(readDenied)
    writeFileSync(join(readDenied, 'token.txt'), 'x\n')

    const command = await wrapCommandWithSandboxLinux({
      command: 'echo hello',
      needsNetworkRestriction: false,
      readConfig: { denyOnly: [readDenied] },
      writeConfig: { allowOnly: ['/'], denyWithinAllow: ['/'] },
    })

    expect(command).not.toContain(
      `--ro-bind /dev/null ${join(PROJ, '.gitconfig')}`,
    )
    // Two whole triples: the base root mount, then the deny's read-only bind
    // that covers the dotfile.
    expect(command.match(/--ro-bind \/ \/(?= )/g)).toHaveLength(2)
    expect(command).toContain(`--tmpfs ${readDenied} `)
  })

  it('skips stubs under a "/" write root denied whole beside a second allow entry', async () => {
    // The deny of '/' is emitted as a read-only bind after BOTH allow binds,
    // burying them, so a second allowOnly entry cannot make the candidate
    // creatable and must not veto the skip: doing so stubs the absent cwd
    // dotfile on the read-only root and the sandbox never starts.
    process.chdir(PROJ)

    const command = await wrapCommandWithSandboxLinux({
      command: 'echo hello',
      needsNetworkRestriction: false,
      writeConfig: { allowOnly: ['/', AREA], denyWithinAllow: ['/'] },
    })

    expect(command).toContain(`--bind ${AREA} ${AREA}`)
    expect(command.match(/--ro-bind \/ \/(?= )/g)).toHaveLength(2)
    expect(command).not.toContain(
      `--ro-bind /dev/null ${join(PROJ, '.gitconfig')}`,
    )
  })

  it.skipIf(!BWRAP_CAN_NAMESPACE)(
    'starts under a "/" write root denied whole beside a second allow entry, and denies both',
    async () => {
      // The root deny buries the allow binds, so nothing under it is
      // writable — not the absent cwd dotfile, and not the second allow
      // entry either.
      process.chdir(PROJ)
      const dotfile = join(PROJ, '.gitconfig')
      const inArea = join(AREA, 'probe.txt')

      const command = await wrapCommandWithSandboxLinux({
        command: `echo BOOTED; (echo x > ${dotfile}) 2>/dev/null && echo WROTE || echo REFUSED; (echo x > ${inArea}) 2>/dev/null && echo WROTE-AREA || echo REFUSED-AREA`,
        needsNetworkRestriction: false,
        writeConfig: { allowOnly: ['/', AREA], denyWithinAllow: ['/'] },
      })
      const run = spawnSync(command, {
        shell: true,
        encoding: 'utf8',
        timeout: 15000,
        cwd: PROJ,
      })

      expect(run.stderr ?? '').not.toContain('bwrap:')
      expect(run.stdout).toContain('BOOTED')
      expect(run.stdout).toContain('REFUSED')
      expect(run.stdout).toContain('REFUSED-AREA')
      expect(existsSync(dotfile)).toBe(false)
      expect(existsSync(inArea)).toBe(false)
    },
  )

  /**
   * A `denyOnly: ['/']` wrap, with the warnings it logged. allowRead keeps
   * the root child the temp tree lives under out of the '/' deny expansion,
   * so with a usable prediction no tmpfs lands anywhere near PROJ, nothing
   * vetoes it and the stubs are skipped.
   */
  async function wrapDenyingRoot(
    writeConfig: { allowOnly: string[]; denyWithinAllow: string[] } = {
      allowOnly: [AREA],
      denyWithinAllow: [PROJ],
    },
  ): Promise<{ command: string; warnings: string[] }> {
    process.chdir(PROJ)
    const tmpRoot = `/${BASE.split('/')[1]}`
    const { result: command, warnings } = await withCapturedWarnings(() =>
      wrapCommandWithSandboxLinux({
        command: 'echo hello',
        needsNetworkRestriction: false,
        readConfig: { denyOnly: ['/'], allowWithinDeny: [tmpRoot] },
        writeConfig,
      }),
    )
    return { command, warnings }
  }

  /**
   * The same wrap with the first `failures` listings of '/' throwing EMFILE,
   * reporting how many of them actually fired.
   */
  async function wrapWithFailingRootListings(
    failures: number,
    writeConfig?: { allowOnly: string[]; denyWithinAllow: string[] },
  ): Promise<{ command: string; warnings: string[]; failed: number }> {
    const realReaddirSync = fs.readdirSync
    let failed = 0
    const spy = spyOn(fs, 'readdirSync').mockImplementation(((
      p: fs.PathLike,
      ...rest: unknown[]
    ) => {
      if (String(p) === '/' && failed < failures) {
        failed++
        throw Object.assign(new Error('EMFILE: too many open files'), {
          code: 'EMFILE',
        })
      }
      return (realReaddirSync as (...a: unknown[]) => unknown)(p, ...rest)
    }) as typeof fs.readdirSync)
    try {
      return { ...(await wrapDenyingRoot(writeConfig)), failed }
    } finally {
      spy.mockRestore()
    }
  }

  it('keeps every stub only when the root listing fails twice', async () => {
    // The tmpfs dirs the vetoes are judged against are predicted from the
    // same readDenyEntries() the denyRead loop uses, and listing the root can
    // fail transiently (EMFILE/ENFILE). Reading that failure as "no read-deny
    // tmpfs" would skip stubs on evidence that never existed; treating one
    // failure as final keeps every placeholder, which is itself a start-up
    // refusal under a read-only covering deny. So the listing itself asks
    // once more, and only a second failure is taken for an answer.
    const stub = `--ro-bind /dev/null ${join(PROJ, '.gitconfig')}`

    const transient = await wrapWithFailingRootListings(1)
    expect(transient.failed).toBe(1)
    expect(transient.command).toContain(`--ro-bind ${PROJ} ${PROJ}`)
    expect(transient.command).not.toContain(stub)
    expect(transient.warnings.join('\n')).not.toContain(
      'Read-deny prediction unusable',
    )

    const persistent = await wrapWithFailingRootListings(2)
    expect(persistent.failed).toBe(2)
    expect(persistent.command).toContain(`--ro-bind ${PROJ} ${PROJ}`)
    expect(persistent.command).toContain(stub)
    // The throw is the reason, not some unresolvable child of '/' this
    // host happens to have: that would pass the test for free.
    expect(persistent.warnings.join('\n')).toContain(
      'Read-deny prediction unusable',
    )
    expect(persistent.warnings.join('\n')).toContain('deriving it threw')
  })

  it('keeps a per-path deny inside a read-deny tmpfs under a "/" write root denied whole', async () => {
    // The root's own read-only bind covers every candidate OUTSIDE the
    // predicted read-deny tmpfs set. One inside it is not covered by that
    // bind — the tmpfs lands on top of it, and an allowed write path
    // restored through the tmpfs is writable again — so such a deny keeps
    // its own bind and its own placeholder. This is the branch the
    // "keeps skipping them when '/' is vetoed" assertions in
    // readonly-deny-dir-binds.test.ts point at.
    const readDenied = join(BASE, 'ro')
    const writable = join(readDenied, 'w')
    mkdirSync(writable, { recursive: true })
    const existing = join(writable, 'settings.json')
    writeFileSync(existing, '{}\n')
    const absent = join(writable, '.mcp.json')
    process.chdir(PROJ)

    const command = await wrapCommandWithSandboxLinux({
      command: 'echo hello',
      needsNetworkRestriction: false,
      readConfig: { denyOnly: [readDenied] },
      writeConfig: {
        allowOnly: ['/', writable],
        denyWithinAllow: ['/', existing, absent],
      },
    })

    expect(command).toContain(`--tmpfs ${readDenied} `)
    expect(command).toContain(`--ro-bind ${existing} ${existing}`)
    expect(command).toContain(`--ro-bind /dev/null ${absent}`)
    // The control: a candidate outside that tmpfs is covered by the root's
    // own bind and needs neither.
    expect(command).not.toContain(
      `--ro-bind /dev/null ${join(PROJ, '.gitconfig')}`,
    )
  })

  it('keeps every placeholder under a "/" write root denied whole when the prediction is unusable', async () => {
    // The other half of that branch: with no usable prediction the root's
    // covering bind proves nothing, so even a candidate outside every
    // read-deny tmpfs keeps its placeholder — fail closed, at the cost the
    // unusable-prediction warning names.
    const rootDeniedWhole = { allowOnly: ['/'], denyWithinAllow: ['/'] }
    const stub = `--ro-bind /dev/null ${join(PROJ, '.gitconfig')}`

    const usable = await wrapWithFailingRootListings(0, rootDeniedWhole)
    expect(usable.command).not.toContain(stub)

    const unusable = await wrapWithFailingRootListings(2, rootDeniedWhole)
    expect(unusable.warnings.join('\n')).toContain(
      'Read-deny prediction unusable',
    )
    expect(unusable.command).toContain(stub)
  })

  /** What one wrap costs a root child whose location will not resolve:
   * twice normalizing the entry (the deny loop's list and the stub
   * prediction's, neither of which caches) and once for its canonical
   * location, which does cache. A retried failure adds exactly one, which is
   * what the counts below are asserted against. */
  const SETTLED_PROBE_LOOKUPS = 3

  /**
   * The same wrap with one extra, non-existent child listed under the root
   * whose canonical location fails to resolve for `code` on its first
   * `failures` lookups. The shape of a dangling symlink under '/' (Ubuntu
   * ships /initrd.img.old), without needing to create one.
   */
  async function wrapWithUnresolvableRootChild(
    code: string,
    failures = Number.POSITIVE_INFINITY,
  ): Promise<{ command: string; warnings: string[]; probeLookups: number }> {
    const probe = '/srt-unresolvable-probe'
    const realReaddirSync = fs.readdirSync
    const realRealpathSync = fs.realpathSync
    let probeLookups = 0
    const spies = [
      spyOn(fs, 'readdirSync').mockImplementation(((
        p: fs.PathLike,
        ...rest: unknown[]
      ) => {
        const real = (realReaddirSync as (...a: unknown[]) => unknown)(
          p,
          ...rest,
        )
        return String(p) === '/' && Array.isArray(real)
          ? [...real, probe.slice(1)]
          : real
      }) as typeof fs.readdirSync),
      spyOn(fs, 'realpathSync').mockImplementation(((
        p: fs.PathLike,
        ...rest: unknown[]
      ) => {
        if (String(p) === probe) {
          probeLookups++
          if (probeLookups <= failures) {
            throw Object.assign(new Error(`${code}: cannot resolve`), { code })
          }
          return probe
        }
        return (realRealpathSync as (...a: unknown[]) => unknown)(p, ...rest)
      }) as typeof fs.realpathSync),
    ]
    try {
      return { ...(await wrapDenyingRoot()), probeLookups }
    } finally {
      for (const spy of spies) spy.mockRestore()
    }
  }

  it('skips the stubs when a root child is merely absent', async () => {
    // A dangling symlink under '/' is ordinary. Counting its unresolvable
    // canonical location as a guess made the prediction unusable, which
    // vetoes every covering directory and stubs the absent cwd dotfiles on
    // the read-only cwd — every command on such a host aborts at startup.
    const { command, warnings, probeLookups } =
      await wrapWithUnresolvableRootChild('ENOENT')

    // No retry: absence is settled, and asking again would only cost a
    // syscall on a host whose root holds a dangling link.
    expect(probeLookups).toBe(SETTLED_PROBE_LOOKUPS)
    expect(warnings.join('\n')).not.toContain('Read-deny prediction unusable')
    expect(command).toContain(`--ro-bind ${PROJ} ${PROJ}`)
    expect(command).not.toContain(
      `--ro-bind /dev/null ${join(PROJ, '.gitconfig')}`,
    )
  })

  it('resolves a root child again when the first failure is transient', async () => {
    // EIO is about the host, not the path: settling on the fallback after
    // one such failure would record a guess, make the prediction unusable
    // and stub the absent cwd dotfiles on a read-only cwd. EACCES, below,
    // is the settled case that must not be retried into a pass.
    const { command, warnings, probeLookups } =
      await wrapWithUnresolvableRootChild('EIO', 1)

    // Exactly one more lookup than a settled failure costs: the retry fired
    // once, and its answer was cached rather than asked for again.
    expect(probeLookups).toBe(SETTLED_PROBE_LOOKUPS + 1)
    expect(warnings.join('\n')).not.toContain('Read-deny prediction unusable')
    expect(command).not.toContain(
      `--ro-bind /dev/null ${join(PROJ, '.gitconfig')}`,
    )
  })

  it('keeps the stubs when a root child cannot be looked at', async () => {
    // The other direction: a location that exists but cannot be resolved is
    // a guess about the prediction's own inputs, so the prediction is
    // unusable and every stub is kept.
    const { command, warnings, probeLookups } =
      await wrapWithUnresolvableRootChild('EACCES')

    // No retry here either: EACCES is settled, and retrying it would turn
    // the same wrap into two lookups of a path that cannot be looked at.
    expect(probeLookups).toBe(SETTLED_PROBE_LOOKUPS)
    expect(warnings.join('\n')).toContain('Read-deny prediction unusable')
    expect(warnings.join('\n')).toContain('/srt-unresolvable-probe')
    expect(command).toContain(`--ro-bind /dev/null ${join(PROJ, '.gitconfig')}`)
  })
})
