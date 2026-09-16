import { describe, it, expect, beforeEach, afterEach } from 'bun:test'
import { spawnSync } from 'node:child_process'
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
  countBinds,
  indexOfTriple,
  lastIndexOfTriple,
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
    expect(countBinds(command, '--ro-bind', configDeny, configDeny)).toBe(1)
    // .git sits strictly between the leaf denies and the allowWrite root.
    const gitPin = indexOfTriple(command, '--ro-bind', gitDir, gitDir)
    expect(gitPin).toBeGreaterThan(-1)
    expect(gitPin).toBeLessThan(
      indexOfTriple(command, '--bind', PROJECT, PROJECT),
    )
    expect(gitPin).toBeLessThan(
      indexOfTriple(command, '--ro-bind', configDeny, configDeny),
    )
    const outside = dirname(PROJECT)
    expect(command).not.toContain(`--ro-bind ${outside} ${outside}`)
    // The allowWrite root is bound exactly once (its allow bind); a pin there
    // would add nothing.
    expect(countBinds(command, '--bind', PROJECT, PROJECT)).toBe(1)
    expect(countBinds(command, '--ro-bind', PROJECT, PROJECT)).toBe(0)
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
      lastIndexOfTriple(command, '--ro-bind', configPath, configPath),
    ).toBeGreaterThan(lastIndexOfTriple(command, '--bind', zDir, zDir))
    expect(countBinds(command, '--bind', zDir, zDir)).toBeGreaterThan(0)
    const xPin = `--ro-bind ${xDir} ${xDir}`
    expect(command).toContain(xPin)
    expect(command.indexOf(xPin)).toBeLessThan(
      command.indexOf(`--tmpfs ${yDir}`),
    )
  })

  it.skipIf(!BWRAP_CAN_NAMESPACE)(
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

    const dataTmpfs = `--tmpfs ${dataDir}`
    // Space-terminated: yDir is a string prefix of dataDir.
    const yTmpfs = `--tmpfs ${yDir} `
    const appPin = `--ro-bind ${appDir} ${appDir}`
    const xPin = `--ro-bind ${xDir} ${xDir}`
    expect(command).toContain(dataTmpfs)
    expect(command).toContain(yTmpfs)
    expect(command).toContain(appPin)
    expect(command).toContain(xPin)
    expect(command.indexOf(appPin)).toBeLessThan(command.indexOf(dataTmpfs))
    expect(command.indexOf(xPin)).toBeLessThan(command.indexOf(yTmpfs))
    expect(command).toContain(
      `--ro-bind ${join(appDir, 'repo')} ${join(appDir, 'repo')}`,
    )
  })

  it.skipIf(!BWRAP_CAN_NAMESPACE)(
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
      secretCanonical: join(dataDir, 'secrets', 'secret.txt'),
      filesystem: { denyRead: [secretsLink] },
    }
  }

  it('pins an ancestor that contains a symlink-spelled read-deny tmpfs location; the tmpfs still lands on top', async () => {
    const { dataDir, secretsLink, filesystem } = symlinkSpelledTmpfs()

    const command = await wrap(filesystem)

    const tmpfsOp = `--tmpfs ${secretsLink}`
    const dataPin = `--ro-bind ${dataDir} ${dataDir}`
    expect(command).toContain(tmpfsOp)
    expect(command).toContain(dataPin)
    expect(command.indexOf(dataPin)).toBeLessThan(command.indexOf(tmpfsOp))
  })

  it.skipIf(!BWRAP_CAN_NAMESPACE)(
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
    const { wDir, linkD, filesystem } = carveOutInsideSymlinkSpelledDenyRead()

    const command = await wrap(filesystem)

    // The carve-out's writable re-bind must follow the tmpfs.
    const tmpfsOp = `--tmpfs ${linkD}`
    const wBind = `--bind ${wDir} ${wDir}`
    expect(command).toContain(tmpfsOp)
    expect(command.lastIndexOf(wBind)).toBeGreaterThan(
      command.lastIndexOf(tmpfsOp),
    )
  })

  it.skipIf(!BWRAP_CAN_NAMESPACE)(
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

    expect(command).toContain(`--tmpfs ${homeDir} `)
    // The name is the destination; the vetted target is the source.
    expect(countBinds(command, '--ro-bind', netrcTarget, netrcName)).toBe(1)
    expect(countBinds(command, '--ro-bind', docsTarget, docsName)).toBe(1)
    expect(command).not.toContain(`--ro-bind ${netrcName} `)
    expect(command).not.toContain(`--ro-bind ${docsName} `)
  })

  it.skipIf(!BWRAP_CAN_NAMESPACE)(
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
    const repoPin = indexOfTriple(command, '--ro-bind', repoDir, repoDir)
    const gitPin = indexOfTriple(command, '--ro-bind', gitDir, gitDir)
    const projectBind = indexOfTriple(command, '--bind', PROJECT, PROJECT)
    expect(repoPin).toBeGreaterThan(-1)
    expect(gitPin).toBeGreaterThan(-1)
    // app is both pinned (first occurrence) and denied (last occurrence);
    // the deny bind lands after z's writable restore and after every pin.
    expect(countBinds(command, '--ro-bind', appDir, appDir)).toBe(2)
    const firstAppRo = indexOfTriple(command, '--ro-bind', appDir, appDir)
    const lastAppRo = lastIndexOfTriple(command, '--ro-bind', appDir, appDir)
    expect(firstAppRo).toBeLessThan(projectBind)
    expect(lastAppRo).toBeGreaterThan(
      lastIndexOfTriple(command, '--bind', zDir, zDir),
    )
    expect(lastAppRo).toBeGreaterThan(gitPin)
    expect(repoPin).toBeLessThan(projectBind)
  })

  it.skipIf(!BWRAP_CAN_NAMESPACE)(
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

    expect(countBinds(command, '--ro-bind', xDir, xDir)).toBe(1)
  })

  it.skipIf(!BWRAP_CAN_NAMESPACE)(
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

    const secretRo = lastIndexOfTriple(
      command,
      '--ro-bind',
      secretPath,
      secretPath,
    )
    expect(secretRo).toBeGreaterThan(-1)
    expect(lastIndexOfTriple(command, '--bind', wDir, wDir)).toBeLessThan(
      secretRo,
    )
  })

  it.skipIf(!BWRAP_CAN_NAMESPACE)(
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

    expect(countBinds(command, '--ro-bind', '/dev/null', secretPath)).toBe(1)
    expect(countBinds(command, '--ro-bind', configDir, configDir)).toBe(1)
  })

  it.skipIf(!BWRAP_CAN_NAMESPACE)(
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

    expect(command).toContain(`--tmpfs ${secretsDir} `)
    expect(countBinds(command, '--ro-bind', otherDir, otherDir)).toBe(1)
  })

  it.skipIf(!BWRAP_CAN_NAMESPACE)(
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

    const credsPin = `--ro-bind ${credsDir} ${credsDir}`
    expect(command).toContain(credsPin)
    const maskBind = `--ro-bind ${fakePath} ${realPath}`
    expect(command.indexOf(maskBind)).toBeGreaterThan(command.indexOf(credsPin))
    expect(command.lastIndexOf(maskBind)).toBe(command.indexOf(maskBind))
  })

  // A mask-only config passes no write config at all, so the root is bound
  // writable — the same shape as a '/' write root, and the pins go after that
  // bind under one writable cover. Without them the directory above the mask
  // is renamed aside and the real file read under its new name.
  function maskOnlyWrap(command: string): Promise<string> {
    return wrapCommandWithSandboxLinux({
      command,
      needsNetworkRestriction: false,
      allowAllUnixSockets: true,
      maskedFileBinds: [
        {
          realPath: join(PROJECT, 'creds', 'token.txt'),
          fakePath: join(PROJECT, 'fakes', 'token.txt'),
        },
      ],
    })
  }

  it('pins and covers a credential mask when there are no write restrictions', async () => {
    mkTree(PROJECT, {
      creds: { 'token.txt': 'REALTOKEN\n' },
      fakes: { 'token.txt': 'FAKE\n' },
    })
    const credsDir = join(PROJECT, 'creds')
    const realPath = join(credsDir, 'token.txt')
    const fakePath = join(PROJECT, 'fakes', 'token.txt')
    const top = `/${BASE.split('/')[1]}`
    process.chdir(PROJECT)

    const command = await maskOnlyWrap('echo ok')

    expect(command).toContain('--bind / /')
    const credsPin = indexOfTriple(command, '--ro-bind', credsDir, credsDir)
    const cover = indexOfTriple(command, '--bind', top, top)
    const mask = indexOfTriple(command, '--ro-bind', fakePath, realPath)
    for (const index of [
      credsPin,
      indexOfTriple(command, '--ro-bind', PROJECT, PROJECT),
      cover,
      mask,
    ]) {
      expect(index).toBeGreaterThan(-1)
    }
    // A read-only cover would make the whole top-level directory read-only.
    expect(countBinds(command, '--ro-bind', top, top)).toBe(0)
    expect(credsPin).toBeLessThan(cover)
    expect(cover).toBeLessThan(mask)
  })

  it.skipIf(!BWRAP_CAN_NAMESPACE)(
    'pins and covers a credential mask when there are no write restrictions (live bwrap)',
    async () => {
      mkTree(PROJECT, {
        creds: { 'token.txt': 'REALTOKEN\n' },
        fakes: { 'token.txt': 'FAKE\n' },
      })
      const realPath = join(PROJECT, 'creds', 'token.txt')
      process.chdir(PROJECT)

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
      secretCanonical: join(wDir, 'secret'),
      filesystem: { denyRead: [sLink, dLink], allowWrite: [wDir] },
    }
  }

  it('restores a write path around a symlink-spelled mask inside it; the mask lands on top', async () => {
    const { wDir, dLink, secretCanonical, filesystem } =
      maskInsideRestoredWritePath()

    const command = await wrap(filesystem)

    // s-link is spelled shallower than link but lands deeper, so it mounts
    // after link's tmpfs and after w's restore.
    const tmpfsOp = `--tmpfs ${dLink} `
    const wBind = `--bind ${wDir} ${wDir}`
    const mask = `--ro-bind /dev/null ${secretCanonical}`
    expect(command).toContain(tmpfsOp)
    expect(command.lastIndexOf(wBind)).toBeGreaterThan(
      command.lastIndexOf(tmpfsOp),
    )
    expect(command.lastIndexOf(mask)).toBeGreaterThan(
      command.lastIndexOf(wBind),
    )
  })

  it.skipIf(!BWRAP_CAN_NAMESPACE)(
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
    const DRo = `--ro-bind ${DDir} ${DDir}`
    const wBind = `--bind ${wDir} ${wDir}`
    const wRo = `--ro-bind ${wDir} ${wDir}`
    const tTmpfs = `--tmpfs ${tDir} `
    expect(command).toContain(DRo)
    expect(command.lastIndexOf(wBind)).toBeLessThan(command.lastIndexOf(DRo))
    expect(command.lastIndexOf(tTmpfs)).toBeGreaterThan(
      command.lastIndexOf(DRo),
    )
    expect(command.lastIndexOf(wRo)).toBeGreaterThan(
      command.lastIndexOf(tTmpfs),
    )
  })

  it.skipIf(!BWRAP_CAN_NAMESPACE)(
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
      filesystem: {
        denyRead: [sLink, dLink],
        allowWrite: [secretCanonical],
      },
    }
  }

  it('masks a read-denied file on top of an allowWrite entry naming the same file', async () => {
    const { secretCanonical, dLink, filesystem } =
      maskOverAllowWriteOfTheSameFile()

    const command = await wrap(filesystem)

    const tmpfsOp = `--tmpfs ${dLink} `
    const fileBind = `--bind ${secretCanonical} ${secretCanonical}`
    const mask = `--ro-bind /dev/null ${secretCanonical}`
    expect(command).toContain(tmpfsOp)
    expect(command.lastIndexOf(mask)).toBeGreaterThan(
      command.lastIndexOf(fileBind),
    )
    expect(command.lastIndexOf(mask)).toBeGreaterThan(
      command.lastIndexOf(tmpfsOp),
    )
  })

  it.skipIf(!BWRAP_CAN_NAMESPACE)(
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
    const rootBind = command.indexOf('--bind / /')
    const gitPin = command.indexOf(`--ro-bind ${gitDir} ${gitDir}`)
    // Another write root is an ancestor like any other here: its own allow
    // bind is buried by the root's and no longer makes it a mountpoint.
    const projectPin = command.indexOf(`--ro-bind ${PROJECT} ${PROJECT}`)
    const cover = command.indexOf(`--bind ${top} ${top}`)
    for (const idx of [rootBind, gitPin, projectPin, cover]) {
      expect(idx).toBeGreaterThan(-1)
    }
    expect(projectPin).toBeGreaterThan(rootBind)
    expect(gitPin).toBeGreaterThan(projectPin)
    expect(cover).toBeGreaterThan(gitPin)
    // A read-only cover would make the whole top-level directory read-only.
    expect(command).not.toContain(`--ro-bind ${top} ${top}`)
    // The deny bind still lands on top of both.
    expect(
      command.indexOf(
        `--ro-bind ${join(gitDir, 'hooks')} ${join(gitDir, 'hooks')}`,
      ),
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
    expect(countBinds(command, '--ro-bind', gitDir, gitDir)).toBe(1)
    expect(countBinds(command, '--ro-bind', BASE, BASE)).toBe(1)
    expect(countBinds(command, '--bind', top, top)).toBe(1)
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

    const topPin = `--ro-bind ${topDir} ${topDir}`
    const gitPin = `--ro-bind ${gitDir} ${gitDir}`
    const tmpfsOp = `--tmpfs ${topDir}`
    expect(command).toContain(topPin)
    expect(command).toContain(gitPin)
    expect(command).toContain(tmpfsOp)
    expect(command.indexOf(topPin)).toBeLessThan(command.indexOf(tmpfsOp))
    expect(command.indexOf(gitPin)).toBeLessThan(command.indexOf(tmpfsOp))
    expect(command.indexOf(gitPin)).toBeLessThan(
      command.indexOf(`--bind ${PROJECT} ${PROJECT}`),
    )
  })

  it.skipIf(!BWRAP_CAN_NAMESPACE)(
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
