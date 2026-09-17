import { describe, it, expect, beforeEach, afterEach, spyOn } from 'bun:test'
import { spawnSync } from 'node:child_process'
import * as fs from 'fs'
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
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import {
  wrapCommandWithSandboxLinux,
  cleanupBwrapMountPoints,
} from '../../src/sandbox/linux-sandbox-utils.js'
import { getApplySeccompBinaryPath } from '../../src/sandbox/generate-seccomp-filter.js'
import { isLinux } from '../helpers/platform.js'
import { bwrapCanNamespace } from '../helpers/bwrap-namespace.js'
import {
  countMounts,
  indexOfMount,
  lastIndexOfMount,
  lastMountAt,
} from '../helpers/bwrap-argv.js'

// Every scenario has an argument-level arm that runs everywhere on Linux and,
// where one is useful, a "(live bwrap)" companion that executes the wrapped
// command. The companions are skipped, visibly, where unprivileged user
// namespaces are unavailable.
describe.if(isLinux)('Linux sandbox — denyWrite ancestor pinning', () => {
  let BASE: string
  let PROJECT: string
  const savedCwd = process.cwd()

  const BWRAP_CAN_NAMESPACE = bwrapCanNamespace()

  // Built in CI; absent elsewhere, where the arm that needs it must skip
  // visibly rather than quietly run without the seccomp stage.
  const APPLY_SECCOMP = getApplySeccompBinaryPath()

  // glibc before 2.28 and some other libcs have no renameat2 wrapper.
  const CAN_CALL_RENAMEAT2 =
    Bun.which('python3') !== null &&
    spawnSync('python3', ['-c', 'import ctypes; ctypes.CDLL(None).renameat2'], {
      timeout: 5000,
    }).status === 0

  type Tree = { [name: string]: string | Tree }

  function mkTree(root: string, tree: Tree): void {
    for (const [name, value] of Object.entries(tree)) {
      const entryPath = join(root, name)
      if (typeof value === 'string') {
        writeFileSync(entryPath, value)
      } else {
        mkdirSync(entryPath, { recursive: true })
        mkTree(entryPath, value)
      }
    }
  }

  beforeEach(() => {
    BASE = realpathSync(mkdtempSync(join(tmpdir(), 'ancestor-pin-')))
    PROJECT = join(BASE, 'project')
    mkdirSync(PROJECT)
    writeFileSync(join(PROJECT, 'README.md'), '# test\n')
  })

  afterEach(() => {
    process.chdir(savedCwd)
    cleanupBwrapMountPoints({ force: true })
    rmSync(BASE, { recursive: true, force: true })
  })

  async function wrap(
    filesystem: {
      allowWrite?: string[]
      denyWrite?: string[]
      denyRead?: string[]
      allowRead?: string[]
    } = {},
    command = 'echo ok',
  ): Promise<string> {
    // Mandatory denies (.git/config, .git/hooks, dotfiles) are relative to
    // process.cwd(); the project is the sandbox's cwd like a real session.
    process.chdir(PROJECT)
    return wrapCommandWithSandboxLinux({
      command,
      needsNetworkRestriction: false,
      allowAllUnixSockets: true,
      readConfig: {
        denyOnly: filesystem.denyRead ?? [],
        allowWithinDeny: filesystem.allowRead ?? [],
      },
      writeConfig: {
        allowOnly: [PROJECT, ...(filesystem.allowWrite ?? [])],
        denyWithinAllow: filesystem.denyWrite ?? [],
      },
    })
  }

  function run(command: string) {
    return spawnSync(command, {
      shell: true,
      encoding: 'utf8',
      timeout: 15000,
      cwd: PROJECT,
      // The EBUSY assertions match strerror text.
      env: { ...process.env, LC_ALL: 'C' },
    })
  }

  // A command that reports one errno per labelled raw syscall and ends with
  // PROBE_DONE, so a sandbox that never starts cannot pass as "no failures".
  const PROBE_DONE = 'PROBE_DONE'
  const asJsString = (s: string): string => JSON.stringify(s)
  function nodeProbe(ops: Array<[string, string]>): string {
    const script = [
      "const fs = require('fs')",
      "const op = (n, f) => { try { f(); console.log(n + '=OK') } catch (e) { console.log(n + '=' + e.code) } }",
      ...ops.map(
        ([label, body]) => `op(${asJsString(label)}, () => { ${body} })`,
      ),
      `console.log(${asJsString(PROBE_DONE)})`,
    ].join('; ')
    const probeFile = join(BASE, 'probe.cjs')
    writeFileSync(probeFile, script)
    return `${process.execPath} ${probeFile}`
  }

  it('pins the directories between a mandatory deny leaf and the allowWrite root', async () => {
    mkTree(PROJECT, { '.git': { hooks: {}, config: '[core]\n' } })
    const gitDir = join(PROJECT, '.git')

    const command = await wrap()

    expect(command).toContain('--ro-bind / /')
    const configDeny = `${gitDir}/config`
    expect(countMounts(command, '--ro-bind', configDeny, configDeny)).toBe(1)
    // .git sits strictly between the leaf denies and the allowWrite root.
    const gitPin = indexOfMount(command, '--ro-bind', gitDir, gitDir)
    expect(gitPin).toBeGreaterThan(-1)
    expect(gitPin).toBeLessThan(
      indexOfMount(command, '--bind', PROJECT, PROJECT),
    )
    expect(gitPin).toBeLessThan(
      indexOfMount(command, '--ro-bind', configDeny, configDeny),
    )
    const outside = dirname(PROJECT)
    expect(command).not.toContain(`--ro-bind ${outside} ${outside}`)
    // The allowWrite root is bound exactly once (its allow bind); a pin there
    // would add nothing.
    expect(countMounts(command, '--bind', PROJECT, PROJECT)).toBe(1)
    expect(countMounts(command, '--ro-bind', PROJECT, PROJECT)).toBe(0)
  })

  it('pins ancestors of absent-path stub dests', async () => {
    // .git exists but neither config nor hooks does: every deny dest on this
    // chain is a stub, so the .git pin can only come from stub dests.
    mkTree(PROJECT, { '.git': {} })
    const gitDir = join(PROJECT, '.git')

    const command = await wrap()

    expect(command).toContain(`--ro-bind /dev/null ${gitDir}/hooks`)
    expect(command).toContain(`--ro-bind /dev/null ${gitDir}/config`)
    expect(command).toContain(`--ro-bind ${gitDir} ${gitDir}`)
  })

  it('pins every intermediate directory above a nested repo found by the depth scan', async () => {
    mkTree(PROJECT, { nested: { '.git': { hooks: {}, config: '[core]\n' } } })
    const nestedDir = join(PROJECT, 'nested')
    const nestedGit = join(nestedDir, '.git')

    const command = await wrap()

    expect(command).toContain(
      `--ro-bind ${nestedGit}/config ${nestedGit}/config`,
    )
    expect(command).toContain(`--ro-bind ${nestedGit} ${nestedGit}`)
    expect(command).toContain(`--ro-bind ${nestedDir} ${nestedDir}`)
  })

  // x and y are pinned beneath everything; the tmpfs on y lands on top of
  // both, the denyRead section's restore of the nested allowWrite z runs
  // before the buffered deny binds, and the config deny lands on top of it.
  function nestedWriteRootsUnderTmpfs() {
    mkTree(PROJECT, {
      x: { y: { z: { '.git': { hooks: {}, config: '[core]\n' } } } },
    })
    const yDir = join(PROJECT, 'x', 'y')
    const zDir = join(yDir, 'z')
    return {
      xDir: join(PROJECT, 'x'),
      yDir,
      zDir,
      configPath: join(zDir, '.git', 'config'),
      filesystem: {
        allowWrite: [zDir],
        denyRead: [yDir],
        denyWrite: [join(zDir, '.git', 'config')],
      },
    }
  }

  it('keeps leaf denies enforced when a denyRead tmpfs sits between nested allowWrite roots', async () => {
    const { xDir, yDir, zDir, configPath, filesystem } =
      nestedWriteRootsUnderTmpfs()

    const command = await wrap(filesystem)

    expect(
      lastIndexOfMount(command, '--ro-bind', configPath, configPath),
    ).toBeGreaterThan(lastIndexOfMount(command, '--bind', zDir, zDir))
    expect(countMounts(command, '--bind', zDir, zDir)).toBeGreaterThan(0)
    const xPin = indexOfMount(command, '--ro-bind', xDir, xDir)
    expect(xPin).toBeGreaterThan(-1)
    expect(xPin).toBeLessThan(indexOfMount(command, '--tmpfs', yDir))
  })

  it.if(BWRAP_CAN_NAMESPACE)(
    'keeps leaf denies enforced when a denyRead tmpfs sits between nested allowWrite roots (live bwrap)',
    async () => {
      const { zDir, configPath, filesystem } = nestedWriteRootsUnderTmpfs()

      const result = run(
        await wrap(filesystem, `echo evil >> ${configPath} && echo PLANTED`),
      )
      expect(result.stdout ?? '').not.toContain('PLANTED')
      expect(result.status).not.toBe(0)
      expect(readFileSync(configPath, 'utf8')).toBe('[core]\n')

      const writable = await wrap(
        filesystem,
        `echo n > ${zDir}/newfile.txt && echo Z_WRITE_OK`,
      )
      expect(run(writable).stdout).toContain('Z_WRITE_OK')
      expect(existsSync(join(zDir, 'newfile.txt'))).toBe(true)
    },
  )

  function tmpfsInsidePinnedAncestor() {
    mkTree(PROJECT, {
      x: {
        y: {
          z: {
            app: {
              data: { 'secret.txt': 'TOPSECRET\n' },
              repo: { '.git': { hooks: {}, config: '[core]\n' } },
            },
          },
        },
      },
    })
    const yDir = join(PROJECT, 'x', 'y')
    const zDir = join(yDir, 'z')
    const appDir = join(zDir, 'app')
    const dataDir = join(appDir, 'data')
    const configPath = join(appDir, 'repo', '.git', 'config')
    return {
      xDir: join(PROJECT, 'x'),
      yDir,
      appDir,
      dataDir,
      secretPath: join(dataDir, 'secret.txt'),
      configPath,
      filesystem: {
        allowWrite: [zDir],
        denyRead: [yDir, dataDir],
        denyWrite: [configPath],
      },
    }
  }

  it('pins an ancestor that contains a read-deny tmpfs; the tmpfs still lands on top', async () => {
    const { xDir, yDir, appDir, dataDir, filesystem } =
      tmpfsInsidePinnedAncestor()

    const command = await wrap(filesystem)

    const dataTmpfs = indexOfMount(command, '--tmpfs', dataDir)
    const yTmpfs = indexOfMount(command, '--tmpfs', yDir)
    const appPin = indexOfMount(command, '--ro-bind', appDir, appDir)
    const xPin = indexOfMount(command, '--ro-bind', xDir, xDir)
    expect(dataTmpfs).toBeGreaterThan(-1)
    expect(yTmpfs).toBeGreaterThan(-1)
    expect(appPin).toBeLessThan(dataTmpfs)
    expect(xPin).toBeLessThan(yTmpfs)
    expect(appPin).toBeGreaterThan(-1)
    expect(xPin).toBeGreaterThan(-1)
    expect(command).toContain(
      `--ro-bind ${join(appDir, 'repo')} ${join(appDir, 'repo')}`,
    )
  })

  it.if(BWRAP_CAN_NAMESPACE)(
    'pins an ancestor that contains a read-deny tmpfs; the tmpfs still lands on top (live bwrap)',
    async () => {
      const { secretPath, configPath, filesystem } = tmpfsInsidePinnedAncestor()

      const result = run(
        await wrap(
          filesystem,
          `cat ${secretPath} 2>&1; echo evil >> ${secretPath} 2>&1; echo evil >> ${configPath} 2>&1; echo DONE`,
        ),
      )

      expect(result.stdout).toContain('DONE')
      expect(result.stdout).not.toContain('TOPSECRET')
      expect(readFileSync(secretPath, 'utf8')).toBe('TOPSECRET\n')
      expect(readFileSync(configPath, 'utf8')).toBe('[core]\n')
    },
  )

  // The tmpfs mounts at data/secrets via the symlink spelling; data is
  // pinned beneath it, so data cannot be renamed aside and the secret
  // stays hidden.
  function symlinkSpelledTmpfs() {
    mkTree(PROJECT, { data: { secrets: { 'secret.txt': 'TOPSECRET\n' } } })
    const dataDir = join(PROJECT, 'data')
    const secretsLink = join(PROJECT, 'secrets')
    symlinkSync(join('data', 'secrets'), secretsLink)
    return {
      dataDir,
      secretsLink,
      secretsCanonical: join(dataDir, 'secrets'),
      secretCanonical: join(dataDir, 'secrets', 'secret.txt'),
      filesystem: { denyRead: [secretsLink] },
    }
  }

  it('pins an ancestor that contains a symlink-spelled read-deny tmpfs location; the tmpfs still lands on top', async () => {
    const { dataDir, secretsLink, secretsCanonical, filesystem } =
      symlinkSpelledTmpfs()

    const command = await wrap(filesystem)

    // The tmpfs goes where the link leads, never on the link itself.
    expect(countMounts(command, '--tmpfs', secretsLink)).toBe(0)
    const tmpfsOp = indexOfMount(command, '--tmpfs', secretsCanonical)
    const dataPin = indexOfMount(command, '--ro-bind', dataDir, dataDir)
    expect(tmpfsOp).toBeGreaterThan(-1)
    expect(dataPin).toBeGreaterThan(-1)
    expect(dataPin).toBeLessThan(tmpfsOp)
  })

  it.if(BWRAP_CAN_NAMESPACE)(
    'pins an ancestor that contains a symlink-spelled read-deny tmpfs location; the tmpfs still lands on top (live bwrap)',
    async () => {
      const { dataDir, secretsLink, secretCanonical, filesystem } =
        symlinkSpelledTmpfs()

      const result = run(
        await wrap(
          filesystem,
          `cat ${secretCanonical} 2>&1; cat ${secretsLink}/secret.txt 2>&1; echo evil >> ${secretCanonical} 2>&1; mv ${dataDir} ${dataDir}-moved 2>&1; echo DONE`,
        ),
      )

      expect(result.stdout ?? '').toContain('DONE')
      expect(result.stderr ?? '').not.toContain('bwrap:')
      expect(result.stdout ?? '').not.toContain('TOPSECRET')
      expect(result.stdout ?? '').toMatch(/busy/i)
      expect(existsSync(`${dataDir}-moved`)).toBe(false)
      expect(readFileSync(secretCanonical, 'utf8')).toBe('TOPSECRET\n')
    },
  )

  function carveOutInsideSymlinkSpelledDenyRead() {
    mkTree(PROJECT, {
      data: {
        d: { w: { secret: 'DENYTEST\n' }, 'elsewhere.txt': 'ALSOSECRET\n' },
      },
    })
    const dDir = join(PROJECT, 'data', 'd')
    const wDir = join(dDir, 'w')
    const secretPath = join(wDir, 'secret')
    const linkD = join(PROJECT, 'link-d')
    symlinkSync(join('data', 'd'), linkD)
    return {
      dDir,
      wDir,
      secretPath,
      linkD,
      filesystem: {
        allowWrite: [wDir],
        denyRead: [linkD],
        denyWrite: [secretPath],
      },
    }
  }

  it('restores a canonical allowWrite carve-out inside a symlink-spelled denyRead', async () => {
    const { dDir, wDir, linkD, filesystem } =
      carveOutInsideSymlinkSpelledDenyRead()

    const command = await wrap(filesystem)

    // The carve-out's writable re-bind must follow the tmpfs, which lands
    // where the link leads.
    expect(countMounts(command, '--tmpfs', linkD)).toBe(0)
    const tmpfsOp = lastIndexOfMount(command, '--tmpfs', dDir)
    expect(tmpfsOp).toBeGreaterThan(-1)
    expect(lastIndexOfMount(command, '--bind', wDir, wDir)).toBeGreaterThan(
      tmpfsOp,
    )
  })

  it.if(BWRAP_CAN_NAMESPACE)(
    'restores a canonical allowWrite carve-out inside a symlink-spelled denyRead (live bwrap)',
    async () => {
      const { dDir, wDir, secretPath, filesystem } =
        carveOutInsideSymlinkSpelledDenyRead()

      const result = run(
        await wrap(
          filesystem,
          `echo n > ${wDir}/newfile.txt 2>&1; echo evil >> ${secretPath} 2>&1; cat ${dDir}/elsewhere.txt 2>&1; echo DONE`,
        ),
      )

      expect(result.stdout ?? '').toContain('DONE')
      expect(existsSync(join(wDir, 'newfile.txt'))).toBe(true)
      expect(readFileSync(secretPath, 'utf8')).toBe('DENYTEST\n')
      expect(result.stdout ?? '').not.toContain('ALSOSECRET')
    },
  )

  // The dotfile-manager shape: .netrc and docs inside a read-denied home are
  // links into a sibling directory inside it. Restoring them only where they
  // resolve leaves the names themselves missing in the sandbox; naming the
  // link as the bind SOURCE would hand bwrap the link to re-resolve at mount
  // time, after the containment check ran.
  function symlinkedAllowReadCarveOuts() {
    mkTree(BASE, {
      home: {
        store: { netrc: 'SECRETTOKEN\n', pages: { 'readme.md': 'PAGETEXT\n' } },
        'other.txt': 'HIDDEN\n',
      },
    })
    const homeDir = join(BASE, 'home')
    const netrcName = join(homeDir, '.netrc')
    const docsName = join(homeDir, 'docs')
    symlinkSync(join('store', 'netrc'), netrcName)
    symlinkSync(join('store', 'pages'), docsName)
    return {
      homeDir,
      netrcName,
      netrcTarget: join(homeDir, 'store', 'netrc'),
      docsName,
      docsTarget: join(homeDir, 'store', 'pages'),
      filesystem: {
        denyRead: [homeDir],
        allowRead: [netrcName, docsName],
      },
    }
  }

  it('restores an allowRead carve-out that is a symlink at the name it is, from its vetted target', async () => {
    const {
      homeDir,
      netrcName,
      netrcTarget,
      docsName,
      docsTarget,
      filesystem,
    } = symlinkedAllowReadCarveOuts()

    const command = await wrap(filesystem)

    expect(indexOfMount(command, '--tmpfs', homeDir)).toBeGreaterThan(-1)
    // The name is the destination; the vetted target is the source.
    expect(countMounts(command, '--ro-bind', netrcTarget, netrcName)).toBe(1)
    expect(countMounts(command, '--ro-bind', docsTarget, docsName)).toBe(1)
    expect(command).not.toContain(`--ro-bind ${netrcName} `)
    expect(command).not.toContain(`--ro-bind ${docsName} `)
  })

  it.if(BWRAP_CAN_NAMESPACE)(
    'restores an allowRead carve-out that is a symlink at the name it is, from its vetted target (live bwrap)',
    async () => {
      const { homeDir, netrcName, docsName, filesystem } =
        symlinkedAllowReadCarveOuts()

      const result = run(
        await wrap(
          filesystem,
          `cat ${netrcName} 2>&1; cat ${join(docsName, 'readme.md')} 2>&1; cat ${join(homeDir, 'other.txt')} 2>&1; echo DONE`,
        ),
      )

      expect(result.stdout).toContain('DONE')
      expect(result.stdout).toContain('SECRETTOKEN')
      expect(result.stdout).toContain('PAGETEXT')
      expect(result.stdout).not.toContain('HIDDEN')
    },
  )

  // Restoring such a carve-out puts the TARGET's inode at the NAME: a second
  // mount of it, which a deny or a credential mask landing on the target's
  // own path does not cover. So the read section wins over the carve-out
  // whenever it hides anything at, inside or around the target, and the
  // carve-out is not restored at all. Each flavour below has a control whose
  // carve-out is an ordinary directory, where the deeper deny lands inside
  // the restore and the rest of the carve-out stays readable.
  function carveOutsOverDeniedTargets() {
    mkTree(BASE, {
      home: {
        store: {
          netrc: 'SECRETTOKEN\n',
          pages: { 'readme.md': 'PAGETEXT\n', sec: { x: 'SECRETPAGE\n' } },
        },
        plain: { 'readme.md': 'PAGETEXT\n', sec: { x: 'SECRETPAGE\n' } },
      },
    })
    const homeDir = join(BASE, 'home')
    const storeDir = join(homeDir, 'store')
    const netrcName = join(homeDir, '.netrc')
    const docsName = join(homeDir, 'docs')
    const hopName = join(homeDir, '.hop')
    const danglingName = join(homeDir, '.gone')
    symlinkSync(join('store', 'netrc'), netrcName)
    symlinkSync(join('store', 'pages'), docsName)
    // Two hops, through a directory link: the source has to be the full
    // realpath, not one hop of it.
    symlinkSync('store', join(homeDir, 'alias'))
    symlinkSync(join('alias', 'netrc'), hopName)
    symlinkSync(join('store', 'gone'), danglingName)
    return {
      homeDir,
      netrcName,
      netrcTarget: join(storeDir, 'netrc'),
      docsName,
      docsTarget: join(storeDir, 'pages'),
      deniedPage: join(storeDir, 'pages', 'sec'),
      storeDir,
      hopName,
      danglingName,
      plainDir: join(homeDir, 'plain'),
      plainDenied: join(homeDir, 'plain', 'sec'),
    }
  }

  it('drops a symlinked allowRead carve-out whose target is read-denied', async () => {
    const { homeDir, netrcName, netrcTarget, plainDir, plainDenied } =
      carveOutsOverDeniedTargets()

    const command = await wrap({
      denyRead: [homeDir, netrcTarget],
      allowRead: [netrcName],
    })

    // Nothing lands at the name, whatever it would have been bound from:
    // asserting the absence of one spelling would pass for a restore spelled
    // `--ro-bind <name> <name>`, which bwrap resolves to the same inode.
    expect(lastMountAt(command, netrcName)).toBeUndefined()
    // The target's own mask is not emitted: it would land inside the tmpfs
    // the home directory's deny already put over it, and one mount per
    // location is all this wrap makes. The entry still says the target is
    // denied, which is what costs the carve-out its restore above.
    expect(countMounts(command, '--ro-bind', '/dev/null', netrcTarget)).toBe(0)

    // The control: an ordinary directory carve-out keeps its restore, and
    // the deeper deny lands inside it.
    const control = await wrap({
      denyRead: [homeDir, plainDenied],
      allowRead: [plainDir],
    })
    const restore = indexOfMount(control, '--ro-bind', plainDir, plainDir)
    expect(restore).toBeGreaterThan(-1)
    expect(indexOfMount(control, '--tmpfs', plainDenied)).toBeGreaterThan(
      restore,
    )
  })

  it('drops a symlinked directory carve-out whose target holds a read deny', async () => {
    const { homeDir, docsName, deniedPage } = carveOutsOverDeniedTargets()

    const command = await wrap({
      denyRead: [homeDir, deniedPage],
      allowRead: [docsName],
    })

    expect(lastMountAt(command, docsName)).toBeUndefined()
  })

  it('drops a symlinked carve-out whose target a deeper tmpfs hides', async () => {
    const { homeDir, netrcName, storeDir } = carveOutsOverDeniedTargets()

    // The deny is neither at nor under the target: it is around it, and the
    // name would sit outside it serving what it hides.
    const command = await wrap({
      denyRead: [homeDir, storeDir],
      allowRead: [netrcName],
    })

    expect(lastMountAt(command, netrcName)).toBeUndefined()
    // No tmpfs of its own: the store lies under the home directory's, which
    // hides it already. It is a denial around the target all the same.
    expect(countMounts(command, '--tmpfs', storeDir)).toBe(0)
  })

  it('drops a symlinked carve-out reached through more than one link', async () => {
    const { homeDir, hopName, netrcTarget } = carveOutsOverDeniedTargets()

    const command = await wrap({
      denyRead: [homeDir, netrcTarget],
      allowRead: [hopName],
    })

    expect(lastMountAt(command, hopName)).toBeUndefined()
  })

  it('restores nothing for a carve-out whose link dangles', async () => {
    const { homeDir, danglingName } = carveOutsOverDeniedTargets()

    const command = await wrap({
      denyRead: [homeDir],
      allowRead: [danglingName],
    })

    expect(countMounts(command, '--ro-bind', danglingName, danglingName)).toBe(
      0,
    )
    expect(command).not.toContain(`${danglingName} `)
  })

  it('drops a symlinked carve-out whose target is a masked credential', async () => {
    const { homeDir, netrcName, netrcTarget } = carveOutsOverDeniedTargets()
    const storeDir = join(BASE, 'fakes')
    mkdirSync(storeDir)
    const fakePath = join(storeDir, 'netrc')
    writeFileSync(fakePath, 'SENTINEL\n')

    const command = await wrapCommandWithSandboxLinux({
      command: 'echo ok',
      needsNetworkRestriction: false,
      allowAllUnixSockets: true,
      readConfig: { denyOnly: [homeDir], allowWithinDeny: [netrcName] },
      maskedFileBinds: [{ realPath: netrcTarget, fakePath }],
      maskedFileStoreDir: storeDir,
    })

    expect(lastMountAt(command, netrcName)).toBeUndefined()
    expect(
      indexOfMount(command, '--ro-bind', fakePath, netrcTarget),
    ).toBeGreaterThan(-1)
  })

  it.if(BWRAP_CAN_NAMESPACE)(
    'serves none of the denied bytes through a symlinked carve-out (live bwrap)',
    async () => {
      const {
        homeDir,
        netrcName,
        netrcTarget,
        docsName,
        deniedPage,
        storeDir,
        plainDir,
        plainDenied,
      } = carveOutsOverDeniedTargets()

      const denied = run(
        await wrap(
          { denyRead: [homeDir, netrcTarget], allowRead: [netrcName] },
          `cat ${netrcName} 2>&1; echo DONE`,
        ),
      )
      expect(denied.stdout).toContain('DONE')
      expect(denied.stdout).not.toContain('SECRETTOKEN')

      const directory = run(
        await wrap(
          { denyRead: [homeDir, deniedPage], allowRead: [docsName] },
          `cat ${join(docsName, 'sec', 'x')} 2>&1; echo DONE`,
        ),
      )
      expect(directory.stdout).toContain('DONE')
      expect(directory.stdout).not.toContain('SECRETPAGE')

      const around = run(
        await wrap(
          { denyRead: [homeDir, storeDir], allowRead: [netrcName] },
          `cat ${netrcName} 2>&1; echo DONE`,
        ),
      )
      expect(around.stdout).toContain('DONE')
      expect(around.stdout).not.toContain('SECRETTOKEN')

      // The control still reads everything the deeper deny does not cover.
      const control = run(
        await wrap(
          { denyRead: [homeDir, plainDenied], allowRead: [plainDir] },
          `cat ${join(plainDir, 'sec', 'x')} 2>&1; cat ${join(plainDir, 'readme.md')} 2>&1; echo DONE`,
        ),
      )
      expect(control.stdout).toContain('DONE')
      expect(control.stdout).not.toContain('SECRETPAGE')
      expect(control.stdout).toContain('PAGETEXT')
    },
  )

  it.if(BWRAP_CAN_NAMESPACE)(
    'never serves the real credential through a symlinked carve-out (live bwrap)',
    async () => {
      const { homeDir, netrcName, netrcTarget } = carveOutsOverDeniedTargets()
      const storeDir = join(BASE, 'fakes')
      mkdirSync(storeDir)
      const fakePath = join(storeDir, 'netrc')
      writeFileSync(fakePath, 'SENTINEL\n')

      const result = run(
        await wrapCommandWithSandboxLinux({
          command: `sh -c 'cat ${netrcName} 2>&1; echo DONE'`,
          needsNetworkRestriction: false,
          allowAllUnixSockets: true,
          readConfig: { denyOnly: [homeDir], allowWithinDeny: [netrcName] },
          maskedFileBinds: [{ realPath: netrcTarget, fakePath }],
          maskedFileStoreDir: storeDir,
        }),
      )

      expect(result.stdout).toContain('DONE')
      expect(result.stdout).not.toContain('SECRETTOKEN')
    },
  )

  // The other side of that rule: only a deny that MOUNTS something overlaps
  // the target. An entry naming a path that is not there mounts nothing (the
  // manager hands every configured credential file to the read denies,
  // present or not), and neither does a file deny an allowRead entry lifts —
  // so neither may cost the carve-out its restore.
  it('restores a symlinked carve-out around a read deny that is not there', async () => {
    const { homeDir, docsName, docsTarget } = symlinkedAllowReadCarveOuts()

    const command = await wrap({
      denyRead: [homeDir, join(docsTarget, 'secret.txt')],
      allowRead: [docsName],
    })

    expect(countMounts(command, '--ro-bind', docsTarget, docsName)).toBe(1)
  })

  it('restores a symlinked carve-out around a file deny an allowRead entry lifts', async () => {
    const { homeDir, docsName, docsTarget } = symlinkedAllowReadCarveOuts()
    const readme = join(docsTarget, 'readme.md')

    const command = await wrap({
      denyRead: [homeDir, readme],
      allowRead: [docsName, readme],
    })

    expect(countMounts(command, '--ro-bind', '/dev/null', readme)).toBe(0)
    expect(countMounts(command, '--ro-bind', readme, readme)).toBe(1)
    expect(countMounts(command, '--ro-bind', docsTarget, docsName)).toBe(1)
  })

  it.if(BWRAP_CAN_NAMESPACE)(
    'serves a symlinked carve-out no read deny lands inside (live bwrap)',
    async () => {
      const { homeDir, docsName, docsTarget } = symlinkedAllowReadCarveOuts()
      const readme = join(docsTarget, 'readme.md')
      const read = `cat ${join(docsName, 'readme.md')} 2>&1; cat ${join(homeDir, 'other.txt')} 2>&1; echo DONE`

      const absent = run(
        await wrap(
          {
            denyRead: [homeDir, join(docsTarget, 'secret.txt')],
            allowRead: [docsName],
          },
          read,
        ),
      )
      expect(absent.stdout).toContain('DONE')
      expect(absent.stdout).toContain('PAGETEXT')
      expect(absent.stdout).not.toContain('HIDDEN')

      const lifted = run(
        await wrap(
          { denyRead: [homeDir, readme], allowRead: [docsName, readme] },
          read,
        ),
      )
      expect(lifted.stdout).toContain('DONE')
      expect(lifted.stdout).toContain('PAGETEXT')
      expect(lifted.stdout).not.toContain('HIDDEN')
    },
  )

  // An entry that cannot be inspected is not mounted where it was written:
  // the tmpfs lands on the deepest directory above it that can be. That
  // stand-in is what hides the target here, and the carve-out's name sits
  // outside it, where the stand-in never reaches.
  function carveOutUnderStandIn() {
    mkTree(BASE, {
      home: {
        u: { app: { data: { 'readme.md': 'PAGETEXT\n' }, cfg: 'CFGTEXT\n' } },
      },
    })
    const homeDir = join(BASE, 'home')
    const appDir = join(homeDir, 'u', 'app')
    const docsName = join(homeDir, 'docs')
    symlinkSync(join('u', 'app', 'data'), docsName)
    return { homeDir, appDir, docsName, uninspectable: join(appDir, 'cfg') }
  }

  /** The wrap `uninspectable` answers EACCES throughout, as a parent made
   * unsearchable would. The spy is gone before the command runs, so a live
   * arm executes the plan against the real tree. */
  async function wrapWithUninspectable(
    uninspectable: string,
    filesystem: Parameters<typeof wrap>[0],
    command?: string,
  ): Promise<string> {
    const realStat = fs.statSync
    const spy = spyOn(fs, 'statSync').mockImplementation(((
      p: fs.PathLike,
      ...rest: unknown[]
    ) => {
      if (String(p) === uninspectable) {
        throw Object.assign(new Error('EACCES: permission denied'), {
          code: 'EACCES',
        })
      }
      return (realStat as (...a: unknown[]) => unknown)(p, ...rest)
    }) as typeof fs.statSync)
    try {
      return await wrap(filesystem, command)
    } finally {
      spy.mockRestore()
    }
  }

  it('drops a symlinked carve-out whose target a stand-in tmpfs hides', async () => {
    const { homeDir, appDir, docsName, uninspectable } = carveOutUnderStandIn()

    const command = await wrapWithUninspectable(uninspectable, {
      denyRead: [homeDir, uninspectable],
      allowRead: [docsName],
    })

    // The stand-in names the app directory, which the home directory's tmpfs
    // hides already, so it is not mounted a second time; the carve-out is
    // refused against where the stand-in would have landed.
    expect(countMounts(command, '--tmpfs', appDir)).toBe(0)
    expect(lastMountAt(command, docsName)).toBeUndefined()
  })

  it.if(BWRAP_CAN_NAMESPACE)(
    'serves nothing through a symlinked carve-out a stand-in hides (live bwrap)',
    async () => {
      const { homeDir, docsName, uninspectable } = carveOutUnderStandIn()

      const result = run(
        await wrapWithUninspectable(
          uninspectable,
          { denyRead: [homeDir, uninspectable], allowRead: [docsName] },
          `cat ${join(docsName, 'readme.md')} 2>&1; echo DONE`,
        ),
      )

      expect(result.stdout).toContain('DONE')
      expect(result.stdout).not.toContain('PAGETEXT')
    },
  )

  function pinsInsideWriteDeniedDirectory() {
    mkTree(PROJECT, {
      x: {
        y: {
          z: {
            app: {
              repo: { '.git': { hooks: {}, config: '[core]\n' } },
              'owned.txt': 'KEEP\n',
            },
          },
        },
      },
    })
    const yDir = join(PROJECT, 'x', 'y')
    const zDir = join(yDir, 'z')
    const appDir = join(zDir, 'app')
    const repoDir = join(appDir, 'repo')
    return {
      zDir,
      appDir,
      repoDir,
      filesystem: {
        allowWrite: [zDir],
        denyRead: [yDir],
        denyWrite: [appDir, join(repoDir, '.git', 'config')],
      },
    }
  }

  it('pins inside a write-denied directory; the directory deny bind still lands on top', async () => {
    const { zDir, appDir, repoDir, filesystem } =
      pinsInsideWriteDeniedDirectory()

    const command = await wrap(filesystem)

    const gitDir = join(repoDir, '.git')
    const repoPin = indexOfMount(command, '--ro-bind', repoDir, repoDir)
    const gitPin = indexOfMount(command, '--ro-bind', gitDir, gitDir)
    const projectBind = indexOfMount(command, '--bind', PROJECT, PROJECT)
    expect(repoPin).toBeGreaterThan(-1)
    expect(gitPin).toBeGreaterThan(-1)
    // app is both pinned (first occurrence) and denied (last occurrence);
    // the deny bind lands after z's writable restore and after every pin.
    expect(countMounts(command, '--ro-bind', appDir, appDir)).toBe(2)
    const firstAppRo = indexOfMount(command, '--ro-bind', appDir, appDir)
    const lastAppRo = lastIndexOfMount(command, '--ro-bind', appDir, appDir)
    expect(firstAppRo).toBeLessThan(projectBind)
    expect(lastAppRo).toBeGreaterThan(
      lastIndexOfMount(command, '--bind', zDir, zDir),
    )
    expect(lastAppRo).toBeGreaterThan(gitPin)
    expect(repoPin).toBeLessThan(projectBind)
  })

  it.if(BWRAP_CAN_NAMESPACE)(
    'pins inside a write-denied directory; the directory deny bind still lands on top (live bwrap)',
    async () => {
      const { appDir, repoDir, filesystem } = pinsInsideWriteDeniedDirectory()

      const result = run(
        await wrap(
          filesystem,
          `echo evil > ${repoDir}/.git/planted 2>&1; echo evil >> ${appDir}/owned.txt 2>&1; echo DONE`,
        ),
      )

      expect(result.stdout).toContain('DONE')
      expect(existsSync(join(repoDir, '.git', 'planted'))).toBe(false)
      expect(readFileSync(join(appDir, 'owned.txt'), 'utf8')).toBe('KEEP\n')
    },
  )

  // repo is denyRead-hidden and the carve-out sub inside it is restored
  // writable; x, between sub and the deeper leaf, is pinned. That restore
  // buries the pin, and a buried mount still answers the kernel's rename
  // check, so x cannot be moved aside.
  //
  // A denyWrite on repo itself would make this a different shape: its own
  // bind is dropped as tmpfs-hidden and sub, inside that write deny, comes
  // back read-only instead of writable (readonly-deny-dir-binds.test.ts).
  function pinnedCorridorBelowCarveOut() {
    mkTree(PROJECT, {
      repo: { sub: { x: { secret: 'DENYTEST\n' } }, 'hidden.txt': 'X\n' },
    })
    const repoDir = join(PROJECT, 'repo')
    const subDir = join(repoDir, 'sub')
    const xDir = join(subDir, 'x')
    const secretPath = join(xDir, 'secret')
    return {
      subDir,
      xDir,
      secretPath,
      filesystem: {
        allowWrite: [subDir],
        denyRead: [repoDir],
        denyWrite: [secretPath],
      },
    }
  }

  it('pins the corridor below an allowWrite carve-out nested inside a read-denied directory', async () => {
    const { xDir, filesystem } = pinnedCorridorBelowCarveOut()

    const command = await wrap(filesystem)

    expect(countMounts(command, '--ro-bind', xDir, xDir)).toBe(1)
  })

  it.if(BWRAP_CAN_NAMESPACE)(
    'pins the corridor below an allowWrite carve-out nested inside a read-denied directory (live bwrap)',
    async () => {
      const { subDir, secretPath, filesystem } = pinnedCorridorBelowCarveOut()

      const result = run(
        await wrap(
          filesystem,
          `cd ${subDir} && mv x x2 && mkdir -p x && echo evil > ${secretPath}; echo ${PROBE_DONE}`,
        ),
      )

      // The sentinel and a clean stderr first: a bwrap that never started
      // also exits non-zero and says nothing about the payload.
      expect(result.stdout ?? '').toContain(PROBE_DONE)
      expect(result.stderr ?? '').not.toContain('bwrap:')
      expect(result.stderr ?? '').toMatch(/busy/i)
      expect(existsSync(join(subDir, 'x2'))).toBe(false)
      expect(readFileSync(secretPath, 'utf8')).toBe('DENYTEST\n')
    },
  )

  // denyWrite dir > denyRead > allowWrite carve-out > denyWrite leaf, each
  // containing the next: the tmpfs re-application must not restore a write
  // path with an emitted deny bind under it.
  function denyLeafUnderNestedCarveOut() {
    mkTree(PROJECT, { d: { t: { w: { secret: 'PROTECT\n' } }, 'o.txt': 'X' } })
    const dDir = join(PROJECT, 'd')
    const tDir = join(dDir, 't')
    const wDir = join(tDir, 'w')
    const secretPath = join(wDir, 'secret')
    return {
      wDir,
      secretPath,
      filesystem: {
        allowWrite: [wDir],
        denyRead: [tDir],
        denyWrite: [dDir, secretPath],
      },
    }
  }

  it('keeps a deny leaf protected when its carve-out sits inside a denyRead inside a denied directory', async () => {
    const { wDir, secretPath, filesystem } = denyLeafUnderNestedCarveOut()

    const command = await wrap(filesystem)

    const secretRo = lastIndexOfMount(
      command,
      '--ro-bind',
      secretPath,
      secretPath,
    )
    expect(secretRo).toBeGreaterThan(-1)
    expect(lastIndexOfMount(command, '--bind', wDir, wDir)).toBeLessThan(
      secretRo,
    )
  })

  it.if(BWRAP_CAN_NAMESPACE)(
    'keeps a deny leaf protected when its carve-out sits inside a denyRead inside a denied directory (live bwrap)',
    async () => {
      const { secretPath, filesystem } = denyLeafUnderNestedCarveOut()

      const result = run(
        await wrap(filesystem, `echo evil >> ${secretPath} 2>&1; echo DONE`),
      )

      expect(result.stdout).toContain('DONE')
      expect(readFileSync(secretPath, 'utf8')).toBe('PROTECT\n')
    },
  )

  function denyReadFileMask() {
    mkTree(PROJECT, { config: { 'secrets.json': '{"k":"REAL"}\n' } })
    const configDir = join(PROJECT, 'config')
    const secretPath = join(configDir, 'secrets.json')
    return { configDir, secretPath, filesystem: { denyRead: [secretPath] } }
  }

  it('pins ancestors of denyRead file masks', async () => {
    const { configDir, secretPath, filesystem } = denyReadFileMask()

    const command = await wrap(filesystem)

    expect(countMounts(command, '--ro-bind', '/dev/null', secretPath)).toBe(1)
    expect(countMounts(command, '--ro-bind', configDir, configDir)).toBe(1)
  })

  it.if(BWRAP_CAN_NAMESPACE)(
    'pins ancestors of denyRead file masks (live bwrap)',
    async () => {
      const { secretPath, filesystem } = denyReadFileMask()

      const result = run(
        await wrap(
          filesystem,
          `cd ${PROJECT} && mv config config-moved && mkdir config && echo attacker > ${secretPath}; echo ${PROBE_DONE}`,
        ),
      )

      expect(result.stdout ?? '').toContain(PROBE_DONE)
      expect(result.stderr ?? '').not.toContain('bwrap:')
      expect(result.stderr).toMatch(/busy/i)
      expect(existsSync(join(PROJECT, 'config-moved'))).toBe(false)
      expect(readFileSync(secretPath, 'utf8')).toBe('{"k":"REAL"}\n')
    },
  )

  function readDeniedDirectory() {
    mkTree(PROJECT, { other: { secrets: { 'key.pem': 'REALKEY\n' } } })
    const otherDir = join(PROJECT, 'other')
    const secretsDir = join(otherDir, 'secrets')
    return { otherDir, secretsDir, filesystem: { denyRead: [secretsDir] } }
  }

  it('pins ancestors of a read-denied directory, so it cannot be renamed out from under its tmpfs', async () => {
    const { otherDir, secretsDir, filesystem } = readDeniedDirectory()

    const command = await wrap(filesystem)

    expect(indexOfMount(command, '--tmpfs', secretsDir)).toBeGreaterThan(-1)
    expect(countMounts(command, '--ro-bind', otherDir, otherDir)).toBe(1)
  })

  it.if(BWRAP_CAN_NAMESPACE)(
    'pins ancestors of a read-denied directory, so it cannot be renamed out from under its tmpfs (live bwrap)',
    async () => {
      const { secretsDir, filesystem } = readDeniedDirectory()

      const result = run(
        await wrap(
          filesystem,
          `cd ${PROJECT} && mv other o2; cat o2/secrets/key.pem 2>&1; echo DONE`,
        ),
      )

      expect(result.stdout).toContain('DONE')
      expect(result.stderr).toMatch(/busy/i)
      expect(result.stdout).not.toContain('REALKEY')
      expect(existsSync(join(PROJECT, 'o2'))).toBe(false)
      // The next command still finds the directory where its deny names it.
      const next = await wrap(
        filesystem,
        `cat ${secretsDir}/key.pem 2>&1; echo DONE`,
      )
      expect(run(next).stdout).not.toContain('REALKEY')
    },
  )

  it.if(BWRAP_CAN_NAMESPACE)(
    'starts, and honours the carve-out, when a symlink and the directory holding its target are both read-denied',
    async () => {
      // The merged-/usr shape under a root deny: bin -> usr/bin, lib -> usr/lib,
      // with the loader directory carved out through the lib link.
      mkTree(PROJECT, {
        usr: {
          bin: { tool: 'TOOL\n' },
          lib: { x86: { so: 'LIB\n' }, other: 'OTHER\n' },
          share: { doc: 'DOC\n' },
        },
      })
      symlinkSync(join('usr', 'bin'), join(PROJECT, 'bin'))
      symlinkSync(join('usr', 'lib'), join(PROJECT, 'lib'))
      const command = await wrap(
        {
          denyRead: [
            join(PROJECT, 'usr'),
            join(PROJECT, 'bin'),
            join(PROJECT, 'lib'),
          ],
          allowRead: [join(PROJECT, 'lib', 'x86')],
        },
        `cat ${PROJECT}/lib/x86/so; cat ${PROJECT}/lib/other 2>&1; cat ${PROJECT}/bin/tool 2>&1; cat ${PROJECT}/usr/share/doc 2>&1; echo DONE`,
      )
      const result = run(command)
      expect(result.stdout).toContain('DONE')
      expect(result.stdout).toContain('LIB')
      expect(result.stdout).not.toContain('OTHER')
      expect(result.stdout).not.toContain('TOOL')
      expect(result.stdout).not.toContain('DOC')
    },
  )

  it.if(BWRAP_CAN_NAMESPACE)(
    'does not let a symlink planted at an allowRead path re-open a read-denied directory',
    async () => {
      const sshDir = join(BASE, 'home', '.ssh')
      mkTree(BASE, { home: { '.ssh': { id_rsa: 'PRIVATEKEY\n' } } })
      const docs = join(PROJECT, 'docs')
      const filesystem = { denyRead: [sshDir], allowRead: [docs] }

      // The first command plants the link where a docs directory is allowed.
      mkdirSync(docs)
      const plant = await wrap(
        filesystem,
        `rm -rf ${docs} && ln -s ${sshDir} ${docs} && echo PLANTED`,
      )
      expect(run(plant).stdout).toContain('PLANTED')

      const next = await wrap(
        filesystem,
        `cat ${docs}/id_rsa 2>&1; cat ${sshDir}/id_rsa 2>&1; echo DONE`,
      )
      expect(next).not.toContain(`--ro-bind ${sshDir} ${sshDir}`)
      const result = run(next)
      expect(result.stdout).toContain('DONE')
      expect(result.stdout).not.toContain('PRIVATEKEY')
    },
  )

  it('pins ancestors of credential masks beneath the mask, which is emitted once', async () => {
    mkTree(PROJECT, {
      creds: { 'token.txt': 'REAL\n' },
      fakes: { 'token.txt': 'FAKE\n' },
    })
    const credsDir = join(PROJECT, 'creds')
    const realPath = join(credsDir, 'token.txt')
    const fakePath = join(PROJECT, 'fakes', 'token.txt')
    process.chdir(PROJECT)

    const command = await wrapCommandWithSandboxLinux({
      command: 'true',
      needsNetworkRestriction: false,
      allowAllUnixSockets: true,
      writeConfig: { allowOnly: [PROJECT], denyWithinAllow: [] },
      maskedFileBinds: [{ realPath, fakePath }],
    })

    const credsPin = indexOfMount(command, '--ro-bind', credsDir, credsDir)
    expect(credsPin).toBeGreaterThan(-1)
    expect(
      indexOfMount(command, '--ro-bind', fakePath, realPath),
    ).toBeGreaterThan(credsPin)
    expect(countMounts(command, '--ro-bind', fakePath, realPath)).toBe(1)
  })

  // A mask-only config passes no write config at all, so the root is bound
  // writable — the same shape as a '/' write root, and the pins go after that
  // bind under one writable cover. Without them the directory above the mask
  // is renamed aside and the real file read under its new name.
  function maskOnlyConfig() {
    mkTree(PROJECT, {
      creds: { 'token.txt': 'REALTOKEN\n' },
      fakes: { 'token.txt': 'FAKE\n' },
    })
    const credsDir = join(PROJECT, 'creds')
    const realPath = join(credsDir, 'token.txt')
    const fakePath = join(PROJECT, 'fakes', 'token.txt')
    process.chdir(PROJECT)
    return {
      credsDir,
      realPath,
      top: `/${BASE.split('/')[1]}`,
      wrap: (command: string): Promise<string> =>
        wrapCommandWithSandboxLinux({
          command,
          needsNetworkRestriction: false,
          allowAllUnixSockets: true,
          maskedFileBinds: [{ realPath, fakePath }],
        }),
    }
  }

  it('pins and covers a credential mask when there are no write restrictions', async () => {
    const { credsDir, realPath, top, wrap: maskOnlyWrap } = maskOnlyConfig()
    const fakePath = join(PROJECT, 'fakes', 'token.txt')

    const command = await maskOnlyWrap('echo ok')

    expect(command).toContain('--bind / /')
    const credsPin = indexOfMount(command, '--ro-bind', credsDir, credsDir)
    const projectPin = indexOfMount(command, '--ro-bind', PROJECT, PROJECT)
    const cover = indexOfMount(command, '--bind', top, top)
    const mask = indexOfMount(command, '--ro-bind', fakePath, realPath)
    expect(credsPin).toBeGreaterThan(-1)
    expect(projectPin).toBeGreaterThan(-1)
    expect(cover).toBeGreaterThan(-1)
    expect(mask).toBeGreaterThan(-1)
    // A read-only cover would make the whole top-level directory read-only.
    expect(countMounts(command, '--ro-bind', top, top)).toBe(0)
    expect(credsPin).toBeLessThan(cover)
    expect(cover).toBeLessThan(mask)
  })

  it.if(BWRAP_CAN_NAMESPACE)(
    'pins and covers a credential mask when there are no write restrictions (live bwrap)',
    async () => {
      const { realPath, wrap: maskOnlyWrap } = maskOnlyConfig()

      const result = run(
        await maskOnlyWrap(
          `cd ${PROJECT} && mv creds creds-moved 2>&1; cat ${realPath} 2>&1; echo DONE`,
        ),
      )

      expect(result.stdout).toContain('DONE')
      expect(result.stderr ?? '').not.toContain('bwrap:')
      expect(result.stdout).toMatch(/busy/i)
      expect(result.stdout).not.toContain('REALTOKEN')
      expect(existsSync(join(PROJECT, 'creds-moved'))).toBe(false)
      expect(readFileSync(realPath, 'utf8')).toBe('REALTOKEN\n')
    },
  )

  function maskInsideRestoredWritePath() {
    mkTree(PROJECT, { d: { w: { secret: 'MASKME\n', 'other.txt': 'ok\n' } } })
    const wDir = join(PROJECT, 'd', 'w')
    const sLink = join(PROJECT, 's-link')
    const dLink = join(PROJECT, 'link')
    symlinkSync(join('d', 'w', 'secret'), sLink)
    symlinkSync('d', dLink)
    return {
      wDir,
      dLink,
      dDir: join(PROJECT, 'd'),
      secretCanonical: join(wDir, 'secret'),
      filesystem: { denyRead: [sLink, dLink], allowWrite: [wDir] },
    }
  }

  it('restores a write path around a symlink-spelled mask inside it; the mask lands on top', async () => {
    const { wDir, dLink, dDir, secretCanonical, filesystem } =
      maskInsideRestoredWritePath()

    const command = await wrap(filesystem)

    // s-link is spelled shallower than link but lands deeper, so it mounts
    // after link's tmpfs and after w's restore. Both land where they lead.
    expect(countMounts(command, '--tmpfs', dLink)).toBe(0)
    const tmpfsOp = lastIndexOfMount(command, '--tmpfs', dDir)
    const wBind = lastIndexOfMount(command, '--bind', wDir, wDir)
    const mask = lastIndexOfMount(
      command,
      '--ro-bind',
      '/dev/null',
      secretCanonical,
    )
    expect(tmpfsOp).toBeGreaterThan(-1)
    expect(wBind).toBeGreaterThan(tmpfsOp)
    expect(mask).toBeGreaterThan(wBind)
  })

  it.if(BWRAP_CAN_NAMESPACE)(
    'restores a write path around a symlink-spelled mask inside it; the mask lands on top (live bwrap)',
    async () => {
      const { wDir, secretCanonical, filesystem } =
        maskInsideRestoredWritePath()

      const result = run(
        await wrap(
          filesystem,
          `cat ${secretCanonical} 2>&1; echo evil >> ${secretCanonical} 2>&1; cat ${wDir}/other.txt; echo DONE`,
        ),
      )

      expect(result.stdout).toContain('DONE')
      expect(result.stdout).toContain('ok')
      expect(result.stdout).not.toContain('MASKME')
      expect(readFileSync(secretCanonical, 'utf8')).toBe('MASKME\n')
    },
  )

  function carveOutInsideEmittedDenyDir() {
    mkTree(PROJECT, {
      D: { t: { w: { 'file.txt': 'KEEP\n' }, 'hidden.txt': 'HIDDEN\n' } },
    })
    const DDir = join(PROJECT, 'D')
    const tDir = join(DDir, 't')
    const wDir = join(tDir, 'w')
    return {
      DDir,
      tDir,
      wDir,
      filesystem: {
        allowWrite: [wDir],
        denyWrite: [DDir],
        denyRead: [tDir],
      },
    }
  }

  it('brings a carve-out inside an emitted denied directory back read-only across re-application', async () => {
    const { DDir, tDir, wDir, filesystem } = carveOutInsideEmittedDenyDir()

    const command = await wrap(filesystem)

    // D's bind re-exposes t, so t's tmpfs is re-applied on top of it. The
    // write path inside is under the deny too: visible again, not writable.
    const DRo = lastIndexOfMount(command, '--ro-bind', DDir, DDir)
    const wBind = lastIndexOfMount(command, '--bind', wDir, wDir)
    const wRo = lastIndexOfMount(command, '--ro-bind', wDir, wDir)
    const tTmpfs = lastIndexOfMount(command, '--tmpfs', tDir)
    expect(DRo).toBeGreaterThan(-1)
    expect(wBind).toBeLessThan(DRo)
    expect(tTmpfs).toBeGreaterThan(DRo)
    expect(wRo).toBeGreaterThan(tTmpfs)
  })

  it.if(BWRAP_CAN_NAMESPACE)(
    'brings a carve-out inside an emitted denied directory back read-only across re-application (live bwrap)',
    async () => {
      const { tDir, wDir, filesystem } = carveOutInsideEmittedDenyDir()

      const result = run(
        await wrap(
          filesystem,
          `echo evil > ${wDir}/planted.txt 2>&1; cat ${wDir}/file.txt; cat ${tDir}/hidden.txt 2>&1; echo DONE`,
        ),
      )

      expect(result.stdout).toContain('DONE')
      expect(result.stdout).toContain('KEEP')
      expect(result.stdout).not.toContain('HIDDEN')
      expect(existsSync(join(wDir, 'planted.txt'))).toBe(false)
    },
  )

  function maskOverAllowWriteOfTheSameFile() {
    mkTree(PROJECT, { d: { w: { secret: 'MASKME\n' } } })
    const secretCanonical = join(PROJECT, 'd', 'w', 'secret')
    const sLink = join(PROJECT, 's-link')
    const dLink = join(PROJECT, 'link')
    symlinkSync(join('d', 'w', 'secret'), sLink)
    symlinkSync('d', dLink)
    return {
      secretCanonical,
      dLink,
      dDir: join(PROJECT, 'd'),
      filesystem: {
        denyRead: [sLink, dLink],
        allowWrite: [secretCanonical],
      },
    }
  }

  it('masks a read-denied file on top of an allowWrite entry naming the same file', async () => {
    const { secretCanonical, dLink, dDir, filesystem } =
      maskOverAllowWriteOfTheSameFile()

    const command = await wrap(filesystem)

    expect(countMounts(command, '--tmpfs', dLink)).toBe(0)
    const tmpfsOp = lastIndexOfMount(command, '--tmpfs', dDir)
    const fileBind = lastIndexOfMount(
      command,
      '--bind',
      secretCanonical,
      secretCanonical,
    )
    const mask = lastIndexOfMount(
      command,
      '--ro-bind',
      '/dev/null',
      secretCanonical,
    )
    expect(tmpfsOp).toBeGreaterThan(-1)
    expect(mask).toBeGreaterThan(fileBind)
    expect(mask).toBeGreaterThan(tmpfsOp)
  })

  it.if(BWRAP_CAN_NAMESPACE)(
    'masks a read-denied file on top of an allowWrite entry naming the same file (live bwrap)',
    async () => {
      const { secretCanonical, filesystem } = maskOverAllowWriteOfTheSameFile()

      const result = run(
        await wrap(
          filesystem,
          `cat ${secretCanonical} 2>&1; echo evil >> ${secretCanonical} 2>&1; echo DONE`,
        ),
      )

      expect(result.stdout).toContain('DONE')
      expect(result.stdout).not.toContain('MASKME')
      expect(readFileSync(secretCanonical, 'utf8')).toBe('MASKME\n')
    },
  )

  it.if(BWRAP_CAN_NAMESPACE)(
    'blocks renaming .git aside inside the sandbox, and the host tree is untouched',
    async () => {
      mkTree(PROJECT, { '.git': { hooks: {}, config: '[core]\n' } })

      const command = await wrap(
        {},
        `cd ${PROJECT} && mv .git .git-moved && mkdir .git && echo planted > .git/config`,
      )
      const result = run(command)

      expect(result.status).not.toBe(0)
      expect(result.stderr ?? '').toMatch(/busy/i)
      expect(existsSync(join(PROJECT, '.git-moved'))).toBe(false)
      expect(readFileSync(join(PROJECT, '.git', 'config'), 'utf8')).toBe(
        '[core]\n',
      )
    },
  )

  it('pins above the allow binds under one writable cover with a "/" write root', async () => {
    mkTree(PROJECT, { '.git': { hooks: {}, config: '[core]\n' } })
    const gitDir = join(PROJECT, '.git')
    const top = `/${BASE.split('/')[1]}`

    const command = await wrap({ allowWrite: ['/'] })

    // Pins beneath the root's own recursive bind would be buried by it, so
    // they go after the allow binds; the cover over them is what keeps them
    // off the lookup path, which lets the pins themselves stay read-only.
    const rootBind = indexOfMount(command, '--bind', '/', '/')
    const gitPin = indexOfMount(command, '--ro-bind', gitDir, gitDir)
    // Another write root is an ancestor like any other here: its own allow
    // bind is buried by the root's and no longer makes it a mountpoint.
    const projectPin = indexOfMount(command, '--ro-bind', PROJECT, PROJECT)
    const cover = indexOfMount(command, '--bind', top, top)
    expect(rootBind).toBeGreaterThan(-1)
    expect(projectPin).toBeGreaterThan(rootBind)
    expect(gitPin).toBeGreaterThan(projectPin)
    expect(cover).toBeGreaterThan(gitPin)
    // A read-only cover would make the whole top-level directory read-only.
    expect(countMounts(command, '--ro-bind', top, top)).toBe(0)
    // The deny bind still lands on top of both.
    const hooksDir = join(gitDir, 'hooks')
    expect(
      indexOfMount(command, '--ro-bind', hooksDir, hooksDir),
    ).toBeGreaterThan(cover)
  })

  it('covers the top-level directory of a protected path sitting directly in it', async () => {
    // The WORKDIR /app shape: a protected path one level below '/' has no
    // ancestor to pin, and the cover is the only thing that keeps its
    // top-level directory a mountpoint. /usr holds no other protected path,
    // so the cover can only come from this deny.
    const absent = '/usr/srt-ancestor-pin-probe'
    const command = await wrap({ allowWrite: ['/'], denyWrite: [absent] })

    expect(command).toContain(`--ro-bind /dev/null ${absent}`)
    expect(command).toContain('--bind /usr /usr')
    expect(command).not.toContain('--ro-bind /usr /usr')
  })

  it('covers and pins nothing under /proc or /sys with a "/" write root', async () => {
    // --proc and --dev replace two of those trees after the pins are spliced
    // in, and /sys is kernel state the root bind already holds read-only, so
    // a cover or a pin there would only fight the mount that follows it. A
    // sibling top-level directory still gets its cover from its own deny.
    const probe = 'srt-ancestor-pin-probe'
    const command = await wrap({
      allowWrite: ['/'],
      denyWrite: [`/proc/${probe}`, `/sys/${probe}`, `/usr/${probe}`],
    })

    expect(command).toContain(`--ro-bind /dev/null /proc/${probe}`)
    expect(command).toContain(`--ro-bind /dev/null /sys/${probe}`)
    expect(command).toContain('--bind /usr /usr')
    expect(command).not.toContain('--bind /proc /proc')
    expect(command).not.toContain('--bind /sys /sys')
    expect(command).not.toContain('--ro-bind /sys /sys')
  })

  it('adds no cover for a top-level directory that is an ordinary write root', async () => {
    // The chain has to reach a top-level directory for the assertion to mean
    // anything, so the write root IS one: the walk visits it, finds it is an
    // allowed write root and stops. Without a '/' write root it keeps only
    // its own allow bind — never a second, writable cover over the pins.
    mkTree(PROJECT, { '.git': { hooks: {}, config: '[core]\n' } })
    const top = `/${BASE.split('/')[1]}`

    const command = await wrap({ allowWrite: [top] })

    const gitDir = join(PROJECT, '.git')
    expect(countMounts(command, '--ro-bind', gitDir, gitDir)).toBe(1)
    expect(countMounts(command, '--ro-bind', BASE, BASE)).toBe(1)
    expect(countMounts(command, '--bind', top, top)).toBe(1)
  })

  it.if(BWRAP_CAN_NAMESPACE)(
    'renames and hard-links across every pinned ancestor under a "/" write root',
    async () => {
      // mv copies when rename(2) fails with EXDEV, so only raw syscalls say
      // whether the pins put a filesystem boundary on the lookup path.
      mkTree(PROJECT, {
        '.git': { hooks: {}, config: '[core]\n', 'b.txt': 'b\n' },
        sub: { 'c.txt': 'c\n' },
        'a.txt': 'a\n',
      })
      const gitDir = join(PROJECT, '.git')
      writeFileSync(join(BASE, 'outside.txt'), 'o\n')

      const result = run(
        await wrap(
          { allowWrite: ['/'] },
          nodeProbe([
            [
              'within',
              `fs.renameSync(${asJsString(join(PROJECT, 'a.txt'))}, ${asJsString(join(PROJECT, 'sub', 'a2.txt'))})`,
            ],
            [
              'intoGit',
              `fs.renameSync(${asJsString(join(PROJECT, 'sub', 'c.txt'))}, ${asJsString(join(gitDir, 'c2.txt'))})`,
            ],
            [
              'outOfGit',
              `fs.renameSync(${asJsString(join(gitDir, 'b.txt'))}, ${asJsString(join(PROJECT, 'b2.txt'))})`,
            ],
            [
              'intoProject',
              `fs.renameSync(${asJsString(join(BASE, 'outside.txt'))}, ${asJsString(join(PROJECT, 'o2.txt'))})`,
            ],
            [
              'linkIntoGit',
              `fs.linkSync(${asJsString(join(PROJECT, 'sub', 'a2.txt'))}, ${asJsString(join(gitDir, 'hard.txt'))})`,
            ],
            [
              'writeInGit',
              `fs.writeFileSync(${asJsString(join(gitDir, 'new.txt'))}, 'x')`,
            ],
          ]),
        ),
      )

      expect(result.stdout).toContain(PROBE_DONE)
      for (const label of [
        'within',
        'intoGit',
        'outOfGit',
        'intoProject',
        'linkIntoGit',
        'writeInGit',
      ]) {
        expect(result.stdout).toContain(`${label}=OK`)
      }
      expect(existsSync(join(gitDir, 'hard.txt'))).toBe(true)
      expect(existsSync(join(PROJECT, 'o2.txt'))).toBe(true)
    },
  )

  it.if(BWRAP_CAN_NAMESPACE)(
    'refuses to move, exchange or remove any pinned ancestor under a "/" write root',
    async () => {
      mkTree(PROJECT, { '.git': { hooks: {}, config: '[core]\n' }, exch: {} })
      const gitDir = join(PROJECT, '.git')

      const result = run(
        await wrap(
          { allowWrite: ['/'] },
          nodeProbe([
            [
              'moveGit',
              `fs.renameSync(${asJsString(gitDir)}, ${asJsString(join(PROJECT, '.git-aside'))})`,
            ],
            [
              'moveProject',
              `fs.renameSync(${asJsString(PROJECT)}, ${asJsString(join(BASE, 'project2'))})`,
            ],
            [
              'moveBase',
              `fs.renameSync(${asJsString(BASE)}, ${asJsString(`${BASE}2`)})`,
            ],
            ['rmdirGit', `fs.rmdirSync(${asJsString(gitDir)})`],
            [
              'rmdirHooks',
              `fs.rmdirSync(${asJsString(join(gitDir, 'hooks'))})`,
            ],
          ]),
        ),
      )

      expect(result.stdout).toContain(PROBE_DONE)
      for (const label of [
        'moveGit',
        'moveProject',
        'moveBase',
        'rmdirGit',
        'rmdirHooks',
      ]) {
        expect(result.stdout).toContain(`${label}=EBUSY`)
      }
      expect(readFileSync(join(gitDir, 'config'), 'utf8')).toBe('[core]\n')
      expect(existsSync(`${BASE}2`)).toBe(false)
    },
  )

  it.if(BWRAP_CAN_NAMESPACE && CAN_CALL_RENAMEAT2)(
    'blocks an exchange-rename of a pinned directory under a "/" write root',
    async () => {
      mkTree(PROJECT, { '.git': { hooks: {}, config: '[core]\n' }, exch: {} })

      const result = run(
        await wrap(
          { allowWrite: ['/'] },
          `cd ${PROJECT} && python3 -c "import ctypes, sys; libc = ctypes.CDLL(None, use_errno=True); r = libc.renameat2(-100, b'.git', -100, b'exch', 2); print('exchange=' + ('OK' if r == 0 else str(ctypes.get_errno())))"; echo ${PROBE_DONE}`,
        ),
      )

      expect(result.stdout).toContain(PROBE_DONE)
      // 16 is EBUSY.
      expect(result.stdout).toContain('exchange=16')
      expect(existsSync(join(PROJECT, '.git', 'config'))).toBe(true)
    },
  )

  it.if(BWRAP_CAN_NAMESPACE && Bun.which('git') !== null)(
    'lets git commit in a pinned repository under a "/" write root',
    async () => {
      mkTree(PROJECT, { 'index.js': 'console.log(1)\n' })
      expect(
        spawnSync('git', [
          '-c',
          'init.defaultBranch=main',
          'init',
          '-q',
          PROJECT,
        ]).status,
      ).toBe(0)

      const result = run(
        await wrap(
          { allowWrite: ['/'] },
          `cd ${PROJECT} && git add index.js && git -c user.name=t -c user.email=t@t -c commit.gpgsign=false -c core.hooksPath=/dev/null commit -q -m init && echo ${PROBE_DONE}`,
        ),
      )

      expect(result.stdout).toContain(PROBE_DONE)
      expect(existsSync(join(PROJECT, '.git', 'refs', 'heads', 'main'))).toBe(
        true,
      )
    },
  )

  it.if(BWRAP_CAN_NAMESPACE)(
    'blocks renaming .git aside under a "/" write root too',
    async () => {
      mkTree(PROJECT, { '.git': { hooks: {}, config: '[core]\n' } })

      const command = await wrap(
        { allowWrite: ['/'] },
        `cd ${PROJECT} && echo work > newfile.txt && (mv .git .git-moved && mkdir .git && echo planted > .git/config) 2>&1; echo DONE`,
      )
      const result = run(command)

      expect(result.stdout).toContain('DONE')
      expect(result.stderr ?? '').not.toContain('bwrap:')
      expect(result.stdout).toMatch(/busy/i)
      expect(existsSync(join(PROJECT, 'newfile.txt'))).toBe(true)
      expect(existsSync(join(PROJECT, '.git-moved'))).toBe(false)
      expect(readFileSync(join(PROJECT, '.git', 'config'), 'utf8')).toBe(
        '[core]\n',
      )
    },
  )

  it.if(BWRAP_CAN_NAMESPACE)(
    'blocks rmdir of the pinned directory',
    async () => {
      mkTree(PROJECT, { '.git': { hooks: {}, config: '[core]\n' } })

      const result = run(
        await wrap({}, `cd ${PROJECT} && rmdir .git; echo ${PROBE_DONE}`),
      )

      expect(result.stdout ?? '').toContain(PROBE_DONE)
      expect(result.stderr ?? '').not.toContain('bwrap:')
      expect(result.stderr).toMatch(/busy/i)
      expect(existsSync(join(PROJECT, '.git'))).toBe(true)
    },
  )

  it.if(BWRAP_CAN_NAMESPACE && APPLY_SECCOMP !== null)(
    'blocks renaming the pinned directory with the seccomp helper in the stack',
    async () => {
      // Every other live arm here sets allowAllUnixSockets, which drops the
      // apply-seccomp stage. That stage makes its own user, PID and mount
      // namespaces and remounts /proc inside them, so the pins have to
      // survive it — otherwise they protect nothing in the configuration
      // the library actually ships.
      mkTree(PROJECT, { '.git': { hooks: {}, config: '[core]\n' } })
      process.chdir(PROJECT)

      const result = run(
        await wrapCommandWithSandboxLinux({
          command: `cd ${PROJECT} && mv .git .git-moved 2>&1; echo ${PROBE_DONE}`,
          needsNetworkRestriction: false,
          writeConfig: { allowOnly: [PROJECT], denyWithinAllow: [] },
        }),
      )

      expect(result.stdout ?? '').toContain(PROBE_DONE)
      expect(result.stderr ?? '').not.toContain('bwrap:')
      expect(result.stdout ?? '').toMatch(/busy/i)
      expect(existsSync(join(PROJECT, '.git-moved'))).toBe(false)
      expect(readFileSync(join(PROJECT, '.git', 'config'), 'utf8')).toBe(
        '[core]\n',
      )
    },
  )

  it.if(BWRAP_CAN_NAMESPACE && CAN_CALL_RENAMEAT2)(
    'blocks an exchange-rename of the pinned directory',
    async () => {
      mkTree(PROJECT, { '.git': { hooks: {}, config: '[core]\n' }, exch: {} })

      // renameat2(RENAME_EXCHANGE) must fail EBUSY (errno 16): the probe
      // exits 0 only in that case.
      const command = await wrap(
        {},
        `cd ${PROJECT} && python3 -c "import ctypes, os, sys; libc = ctypes.CDLL(None, use_errno=True); r = libc.renameat2(-100, b'.git', -100, b'exch', 2); sys.exit(0 if r != 0 and ctypes.get_errno() == 16 else 1)"`,
      )

      expect(run(command).status).toBe(0)
      expect(existsSync(join(PROJECT, '.git', 'config'))).toBe(true)
    },
  )

  it.if(BWRAP_CAN_NAMESPACE)(
    'leaves normal work inside the pinned directory and the project intact',
    async () => {
      mkTree(PROJECT, {
        '.git': { hooks: {}, config: '[core]\n' },
        sub: { 'file.txt': 'data\n' },
      })

      const command = await wrap(
        {},
        `cd ${PROJECT} && echo idx > .git/index && mkdir .git/objects && echo n > newfile.txt && mv sub sub-renamed && echo ALL_OK`,
      )
      const result = run(command)

      expect(result.stdout).toContain('ALL_OK')
      expect(result.status).toBe(0)
      expect(existsSync(join(PROJECT, '.git', 'index'))).toBe(true)
      expect(existsSync(join(PROJECT, 'sub-renamed'))).toBe(true)

      const straddle = await wrap(
        {},
        `cd ${PROJECT} && ${process.execPath} -e "require('fs').renameSync('README.md', '.git/README.md')" && echo STRADDLE_OK`,
      )
      expect(run(straddle).stdout).toContain('STRADDLE_OK')
      expect(existsSync(join(PROJECT, '.git', 'README.md'))).toBe(true)
      expect(existsSync(join(PROJECT, 'README.md'))).toBe(false)
    },
  )

  it('does not pin above a nested repo deeper than the mandatory-deny scan depth', async () => {
    // a/b/c/.git/config sits at depth 5 (ripgrep's --max-depth counts the
    // file itself); the default scan depth of 3 never finds it, so there is
    // no deny bind there and nothing to pin. Raising the depth finds it and
    // pins the whole chain.
    mkTree(PROJECT, {
      a: { b: { c: { '.git': { hooks: {}, config: '[core]\n' } } } },
    })
    const cDir = join(PROJECT, 'a', 'b', 'c')
    const gitDir = join(cDir, '.git')

    const shallow = await wrap()
    expect(shallow).not.toContain(`--ro-bind ${gitDir}/config`)
    expect(shallow).not.toContain(`--ro-bind ${gitDir} ${gitDir}`)
    expect(shallow).not.toContain(`--ro-bind ${cDir} ${cDir}`)

    process.chdir(PROJECT)
    const deep = await wrapCommandWithSandboxLinux({
      command: 'true',
      needsNetworkRestriction: false,
      allowAllUnixSockets: true,
      mandatoryDenySearchDepth: 5,
      writeConfig: { allowOnly: [PROJECT], denyWithinAllow: [] },
    })
    expect(deep).toContain(`--ro-bind ${gitDir}/config ${gitDir}/config`)
    for (const dir of [
      join(PROJECT, 'a'),
      join(PROJECT, 'a', 'b'),
      cDir,
      gitDir,
    ]) {
      expect(deep).toContain(`--ro-bind ${dir} ${dir}`)
    }
  })

  it.if(BWRAP_CAN_NAMESPACE && Bun.which('git') !== null)(
    'lets git and cross-directory renames work in a nested repo whose ancestors are pinned',
    async () => {
      // app is a nested repo at depth 1: app/.git/config and hooks are
      // mandatory denies found by the depth scan, so app and app/.git are
      // pinned.
      mkTree(PROJECT, {
        app: {
          'index.js': 'console.log(1)\n',
          'notes.txt': 'n\n',
          node_modules: {
            '.staging': { 'left-pad-abc': { 'index.js': 'x' } },
          },
        },
      })
      const appDir = join(PROJECT, 'app')
      const gitInit = spawnSync(
        'git',
        ['-c', 'init.defaultBranch=main', 'init', '-q', appDir],
        { encoding: 'utf8' },
      )
      expect(gitInit.status).toBe(0)

      const command = await wrap({})
      expect(command).toContain(`--ro-bind ${appDir} ${appDir}`)
      expect(command).toContain(
        `--ro-bind ${join(appDir, '.git')} ${join(appDir, '.git')}`,
      )

      // The npm-style staging rename (node_modules/.staging/x to
      // node_modules/x) inside the pinned directory works.
      const staged = join(appDir, 'node_modules', '.staging', 'left-pad-abc')
      const final = join(appDir, 'node_modules', 'left-pad')
      const npmLike = await wrap(
        {},
        `${process.execPath} -e "require('fs').renameSync('${staged}', '${final}')" && echo RENAME_OK`,
      )
      const npmResult = run(npmLike)
      expect(npmResult.stdout).toContain('RENAME_OK')
      expect(existsSync(join(final, 'index.js'))).toBe(true)

      // A plain rename(2) that straddles the pinned directory (app to
      // PROJECT and back) sees no mount boundary: it succeeds without a
      // copy fallback in either direction.
      const straddle = await wrap(
        {},
        `cd ${appDir} && ${process.execPath} -e "try { require('fs').renameSync('notes.txt', '../notes.txt'); console.log('NO_ERROR') } catch (e) { console.log('CODE=' + e.code) }" && mv ../notes.txt ./notes-back.txt && echo MV_OK`,
      )
      const straddleResult = run(straddle)
      expect(straddleResult.stdout).toContain('NO_ERROR')
      expect(straddleResult.stdout).toContain('MV_OK')
      expect(existsSync(join(appDir, 'notes-back.txt'))).toBe(true)
      expect(existsSync(join(PROJECT, 'notes.txt'))).toBe(false)
      expect(existsSync(join(appDir, 'notes.txt'))).toBe(false)

      // git's ordinary object/index/ref writes, including its atomic
      // rename-into-place of lockfiles within .git, work.
      const gitWork = await wrap(
        {},
        `cd ${appDir} && git add index.js && git -c user.name=t -c user.email=t@t -c commit.gpgsign=false -c core.hooksPath=/dev/null commit -q -m init && git log --oneline | wc -l && echo GIT_OK`,
      )
      const gitResult = run(gitWork)
      expect(gitResult.status).toBe(0)
      expect(gitResult.stdout).toContain('GIT_OK')
      expect(existsSync(join(appDir, '.git', 'refs', 'heads', 'main'))).toBe(
        true,
      )
    },
  )

  // top is read-denied and contains the nested repo's .git/config deny;
  // top/.git sits between them and is pinned, top itself is pinned too, and
  // the tmpfs on top is emitted after both so it still hides them.
  function readDeniedDirAboveNestedRepo() {
    mkTree(PROJECT, { top: { '.git': { hooks: {}, config: '[core]\n' } } })
    const topDir = join(PROJECT, 'top')
    return {
      topDir,
      gitDir: join(topDir, '.git'),
      filesystem: { denyRead: [topDir] },
    }
  }

  it('pins the ancestor between a read-denied directory and a nested repo deny below it; the tmpfs lands after the pin', async () => {
    const { topDir, gitDir, filesystem } = readDeniedDirAboveNestedRepo()

    const command = await wrap(filesystem)

    const topPin = indexOfMount(command, '--ro-bind', topDir, topDir)
    const gitPin = indexOfMount(command, '--ro-bind', gitDir, gitDir)
    const tmpfsOp = indexOfMount(command, '--tmpfs', topDir)
    expect(topPin).toBeGreaterThan(-1)
    expect(gitPin).toBeGreaterThan(-1)
    expect(topPin).toBeLessThan(tmpfsOp)
    expect(gitPin).toBeLessThan(tmpfsOp)
    expect(gitPin).toBeLessThan(
      indexOfMount(command, '--bind', PROJECT, PROJECT),
    )
  })

  it.if(BWRAP_CAN_NAMESPACE)(
    'pins the ancestor between a read-denied directory and a nested repo deny below it; the tmpfs lands after the pin (live bwrap)',
    async () => {
      const { gitDir, filesystem } = readDeniedDirAboveNestedRepo()

      const result = run(
        await wrap(filesystem, `cat ${gitDir}/config 2>&1; echo DONE`),
      )

      expect(result.stdout ?? '').not.toContain('[core]')
      expect(result.stdout ?? '').toContain('DONE')
    },
  )
})
