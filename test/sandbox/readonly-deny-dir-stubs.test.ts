import { describe, it, expect, beforeEach, afterEach } from 'bun:test'
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
 * denyRead re-application machinery could make that subtree writable
 * again: an allowed write path strictly beneath the covering directory, or
 * a read-deny tmpfs comparable with it (at/beneath it, or containing it or
 * any spelling it was reached through).
 */
describe.if(isLinux)('Deny stubs under a read-only denied directory', () => {
  // realpathSync so exact-string assertions hold even when tmpdir itself
  // contains symlinks.
  let BASE: string
  let AREA: string // allowed write area
  let PROJ: string // write-denied project dir inside AREA

  const savedCwd = process.cwd()

  // Runtime arm: only where bwrap can actually run the same namespace/proc
  // surface the wrapped commands use (--unshare-pid/--unshare-user/--proc —
  // a bare --ro-bind probe passes on hosts where mounting a fresh /proc in
  // the new PID namespace still EPERMs, turning the arm into a false red).
  // No --unshare-net: wrap() passes needsNetworkRestriction: false, so the
  // commands under test never create a netns and the probe must not require
  // one (a netns-restricted host would otherwise silently skip the arm).
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

  it('skips stubs for absent mandatory-deny dotfiles inside a write-denied cwd, and bwrap still boots', async () => {
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
    // nothing and are fine.
    const afterReadOnlyRebind = command.slice(
      command.lastIndexOf(cwdReadOnlyBind) + cwdReadOnlyBind.length,
    )
    expect(afterReadOnlyRebind).not.toContain(`/dev/null ${PROJ}/`)
    expect(afterReadOnlyRebind).not.toMatch(
      /--ro-bind \S*claude-empty-\S+ \S*\/proj\//,
    )

    // Where the host can run bwrap, prove the sandbox actually boots — the
    // pre-fix symptom was a startup abort with no command executed — and
    // that the deny still holds (the absent dotfile stays uncreatable).
    if (BWRAP_CAN_NAMESPACE) {
      const run = spawnSync(command, {
        shell: true,
        encoding: 'utf8',
        timeout: 15000,
        cwd: PROJ,
      })
      expect(run.stderr ?? '').not.toMatch(/Read-only file system/i)
      expect(run.status).toBe(0)
      expect(run.stdout).toContain('hello')

      const denied = spawnSync(
        await wrap([PROJ], [], [AREA], `touch ${join(PROJ, '.gitconfig')}`),
        { shell: true, encoding: 'utf8', timeout: 15000, cwd: PROJ },
      )
      expect(denied.status).not.toBe(0)
      expect(existsSync(join(PROJ, '.gitconfig'))).toBe(false)
    }
  })

  it('still stubs an absent mandatory-deny dotfile when the cwd remains writable (no over-broad skip)', async () => {
    // Control: without the covering denyWrite, cwd stays writable, so the
    // stub is still required to block creating the dotfile.
    process.chdir(PROJ)

    const command = await wrap([])

    expect(command).toContain(`--bind ${AREA} ${AREA}`)
    expect(command).toContain(`--ro-bind /dev/null ${join(PROJ, '.gitconfig')}`)
  })

  it('keeps the stub (fails closed) when an allowed write path beneath the denied dir is re-opened by denyRead', async () => {
    // The one shape where "the ancestor is under a read-only deny" is not
    // reliable: a denyRead directory inside the write-denied dir plus an
    // allowWrite path beneath it. The denyRead re-application emits
    // "--tmpfs <dir>" and a WRITABLE "--bind <allow> <allow>" after the
    // read-only re-bind, without re-emitting the deny binds it buries, so
    // the absent deny path below would otherwise become creatable.
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

  it('keeps the stub when ANY covering deny dir has an allowed write path re-opened beneath it', async () => {
    // The read-only conclusion must hold across EVERY deny dir covering the
    // ancestor, not just one. Here the absent deny's ancestor d is covered
    // by both PROJ (which has the allowWrite t/w strictly beneath it,
    // re-opened by the denyRead re-application of t) and d itself (with no
    // re-opener beneath it). A per-dir check would skip on d and leave the
    // path creatable through the t/w re-bind.
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
    // would miss PROJ's re-opener and skip unsafely; the pre-pass collects
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
    // TRIGGER for the post-deny writable re-application, so the subtree is
    // treated as re-openable and the stub is kept even with no nested
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

    if (BWRAP_CAN_NAMESPACE) {
      const run = spawnSync(command, {
        shell: true,
        encoding: 'utf8',
        timeout: 15000,
        cwd: PROJ,
      })
      expect(run.stderr ?? '').not.toMatch(/Read-only file system/i)
      expect(run.status).toBe(0)
    }
  })

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

    if (BWRAP_CAN_NAMESPACE) {
      const run = spawnSync(command, {
        shell: true,
        encoding: 'utf8',
        timeout: 15000,
        cwd: PROJ,
      })
      expect(run.stderr ?? '').not.toMatch(/Read-only file system/i)
      expect(run.status).toBe(0)
    }
  })

  it('re-applies a denyWithinAllow bind under a trailing-slash allow re-bound over a denyRead tmpfs', async () => {
    // The emission filter drops deny binds hidden by a denyRead tmpfs
    // UNLESS a write re-bind re-exposes them (reExposedByWriteBind). That
    // exception also compares `writePath + '/'` prefixes, so a
    // trailing-slash allow spelling used to defeat it: the writable
    // re-bind was emitted but the deny bind beneath it was dropped —
    // leaving the explicitly denied file writable. With the recorded
    // spelling stripped, the deny bind survives the filter.
    const nestedAllow = join(PROJ, 'w')
    mkdirSync(nestedAllow, { recursive: true })
    const secret = join(nestedAllow, 'secret.txt')
    writeFileSync(secret, 'x\n')

    const command = await wrap([secret], [PROJ], [`${nestedAllow}/`])

    expect(command).toContain(`--tmpfs ${PROJ}`)
    expect(command).toContain(`--bind ${nestedAllow} ${nestedAllow}`)
    expect(command).toContain(`--ro-bind ${secret} ${secret}`)
  })
})
