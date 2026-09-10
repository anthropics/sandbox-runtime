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
import { isLinux } from '../helpers/platform.js'

// The blocks that execute bwrap need unprivileged user namespaces; the
// argument-level assertions run everywhere on Linux.
describe.if(isLinux)('Linux sandbox — denyWrite ancestor pinning', () => {
  let BASE: string
  let PROJECT: string
  const savedCwd = process.cwd()

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

  type Tree = { [name: string]: string | Tree }

  function mkTree(root: string, tree: Tree): void {
    for (const [name, value] of Object.entries(tree)) {
      const p = join(root, name)
      if (typeof value === 'string') {
        writeFileSync(p, value)
      } else {
        mkdirSync(p, { recursive: true })
        mkTree(p, value)
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
      readConfig: { denyOnly: filesystem.denyRead ?? [] },
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

  it('pins the directories between a mandatory deny leaf and the allowWrite root', async () => {
    mkTree(PROJECT, { '.git': { hooks: {}, config: '[core]\n' } })
    const gitDir = join(PROJECT, '.git')

    const command = await wrap()

    expect(command).toContain('--ro-bind / /')
    const configBind = `--ro-bind ${gitDir}/config ${gitDir}/config`
    expect(command).toContain(configBind)
    // .git sits strictly between the leaf denies and the allowWrite root.
    const gitPin = `--ro-bind ${gitDir} ${gitDir}`
    expect(command).toContain(gitPin)
    const rootBind = `--bind ${PROJECT} ${PROJECT}`
    expect(command.indexOf(gitPin)).toBeLessThan(command.indexOf(rootBind))
    expect(command.indexOf(gitPin)).toBeLessThan(command.indexOf(configBind))
    const outside = dirname(PROJECT)
    expect(command).not.toContain(`--ro-bind ${outside} ${outside}`)
    // The allowWrite root is bound exactly once (its allow bind); a pin there
    // would add nothing.
    expect(command.split(rootBind).length - 1).toBe(1)
    expect(command).not.toContain(`--ro-bind ${PROJECT} ${PROJECT}`)
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

  it('keeps leaf denies enforced when a denyRead tmpfs sits between nested allowWrite roots', async () => {
    // x and y are pinned beneath everything; the tmpfs on y lands on top of
    // both, the denyRead section's restore of the nested allowWrite z runs
    // before the buffered deny binds, and the config deny lands on top of it.
    mkTree(PROJECT, {
      x: { y: { z: { '.git': { hooks: {}, config: '[core]\n' } } } },
    })
    const yDir = join(PROJECT, 'x', 'y')
    const zDir = join(yDir, 'z')
    const configPath = join(zDir, '.git', 'config')
    const filesystem = {
      allowWrite: [zDir],
      denyRead: [yDir],
      denyWrite: [configPath],
    }

    const command = await wrap(
      filesystem,
      `echo evil >> ${configPath} && echo PLANTED`,
    )

    const configBind = `--ro-bind ${configPath} ${configPath}`
    const zBind = `--bind ${zDir} ${zDir}`
    const xPin = `--ro-bind ${join(PROJECT, 'x')} ${join(PROJECT, 'x')}`
    expect(command).toContain(configBind)
    expect(command).toContain(zBind)
    expect(command.lastIndexOf(configBind)).toBeGreaterThan(
      command.lastIndexOf(zBind),
    )
    expect(command).toContain(xPin)
    expect(command.indexOf(xPin)).toBeLessThan(
      command.indexOf(`--tmpfs ${yDir}`),
    )

    if (BWRAP_CAN_NAMESPACE) {
      const result = run(command)
      expect(result.stdout ?? '').not.toContain('PLANTED')
      expect(result.status).not.toBe(0)
      expect(readFileSync(configPath, 'utf8')).toBe('[core]\n')

      const writable = await wrap(
        filesystem,
        `echo n > ${zDir}/newfile.txt && echo Z_WRITE_OK`,
      )
      expect(run(writable).stdout).toContain('Z_WRITE_OK')
      expect(existsSync(join(zDir, 'newfile.txt'))).toBe(true)
    }
  })

  it('pins an ancestor that contains a read-deny tmpfs; the tmpfs still lands on top', async () => {
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
    const secretPath = join(dataDir, 'secret.txt')
    const configPath = join(appDir, 'repo', '.git', 'config')

    const command = await wrap(
      {
        allowWrite: [zDir],
        denyRead: [yDir, dataDir],
        denyWrite: [configPath],
      },
      `cat ${secretPath} 2>&1; echo evil >> ${secretPath} 2>&1; echo evil >> ${configPath} 2>&1; echo DONE`,
    )

    const dataTmpfs = `--tmpfs ${dataDir}`
    // Space-terminated: yDir is a string prefix of dataDir.
    const yTmpfs = `--tmpfs ${yDir} `
    const appPin = `--ro-bind ${appDir} ${appDir}`
    const xPin = `--ro-bind ${join(PROJECT, 'x')} ${join(PROJECT, 'x')}`
    expect(command).toContain(dataTmpfs)
    expect(command).toContain(yTmpfs)
    expect(command).toContain(appPin)
    expect(command).toContain(xPin)
    expect(command.indexOf(appPin)).toBeLessThan(command.indexOf(dataTmpfs))
    expect(command.indexOf(xPin)).toBeLessThan(command.indexOf(yTmpfs))
    expect(command).toContain(
      `--ro-bind ${join(appDir, 'repo')} ${join(appDir, 'repo')}`,
    )

    if (BWRAP_CAN_NAMESPACE) {
      const result = run(command)
      expect(result.stdout).toContain('DONE')
      expect(result.stdout).not.toContain('TOPSECRET')
      expect(readFileSync(secretPath, 'utf8')).toBe('TOPSECRET\n')
      expect(readFileSync(configPath, 'utf8')).toBe('[core]\n')
    }
  })

  it('pins an ancestor that contains a symlink-spelled read-deny tmpfs location; the tmpfs still lands on top', async () => {
    // The tmpfs mounts at data/secrets via the symlink spelling; data is
    // pinned beneath it, so data cannot be renamed aside and the secret
    // stays hidden.
    mkTree(PROJECT, {
      data: {
        secrets: { 'secret.txt': 'TOPSECRET\n' },
        '.git': { hooks: {}, config: '[core]\n' },
      },
    })
    const dataDir = join(PROJECT, 'data')
    const secretsLink = join(PROJECT, 'secrets')
    symlinkSync(join('data', 'secrets'), secretsLink)
    const secretCanonical = join(dataDir, 'secrets', 'secret.txt')

    const command = await wrap(
      { denyRead: [secretsLink] },
      `cat ${secretCanonical} 2>&1; cat ${secretsLink}/secret.txt 2>&1; echo evil >> ${secretCanonical} 2>&1; mv ${dataDir} ${dataDir}-moved 2>&1; echo DONE`,
    )

    const tmpfsOp = `--tmpfs ${secretsLink}`
    const dataPin = `--ro-bind ${dataDir} ${dataDir}`
    expect(command).toContain(tmpfsOp)
    expect(command).toContain(dataPin)
    expect(command.indexOf(dataPin)).toBeLessThan(command.indexOf(tmpfsOp))
    expect(command).toContain(
      `--ro-bind ${join(dataDir, '.git')} ${join(dataDir, '.git')}`,
    )

    if (BWRAP_CAN_NAMESPACE) {
      const result = run(command)
      expect(result.stdout ?? '').not.toContain('TOPSECRET')
      expect(result.stdout ?? '').toMatch(/busy/i)
      expect(existsSync(`${dataDir}-moved`)).toBe(false)
      expect(readFileSync(secretCanonical, 'utf8')).toBe('TOPSECRET\n')
    }
  })

  it('restores a canonical allowWrite carve-out inside a symlink-spelled denyRead', async () => {
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

    const command = await wrap(
      { allowWrite: [wDir], denyRead: [linkD], denyWrite: [secretPath] },
      `echo n > ${wDir}/newfile.txt 2>&1; echo evil >> ${secretPath} 2>&1; cat ${dDir}/elsewhere.txt 2>&1; echo DONE`,
    )

    // The carve-out's writable re-bind must follow the tmpfs.
    const tmpfsOp = `--tmpfs ${linkD}`
    const wBind = `--bind ${wDir} ${wDir}`
    expect(command).toContain(tmpfsOp)
    expect(command.lastIndexOf(wBind)).toBeGreaterThan(
      command.lastIndexOf(tmpfsOp),
    )

    if (BWRAP_CAN_NAMESPACE) {
      const result = run(command)
      expect(existsSync(join(wDir, 'newfile.txt'))).toBe(true)
      expect(readFileSync(secretPath, 'utf8')).toBe('DENYTEST\n')
      expect(result.stdout ?? '').not.toContain('ALSOSECRET')
    }
  })

  it('pins inside a write-denied directory; the directory deny bind still lands on top', async () => {
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
    const configPath = join(repoDir, '.git', 'config')

    const command = await wrap(
      { allowWrite: [zDir], denyRead: [yDir], denyWrite: [appDir, configPath] },
      `echo evil > ${repoDir}/.git/planted 2>&1; echo evil >> ${appDir}/owned.txt 2>&1; echo DONE`,
    )

    const repoPin = `--ro-bind ${repoDir} ${repoDir}`
    const gitPin = `--ro-bind ${repoDir}/.git ${repoDir}/.git`
    const appRo = `--ro-bind ${appDir} ${appDir}`
    expect(command).toContain(repoPin)
    expect(command).toContain(gitPin)
    // app is both pinned (first occurrence) and denied (last occurrence);
    // the deny bind lands after z's writable restore and after every pin.
    expect(command.lastIndexOf(appRo)).toBeGreaterThan(
      command.lastIndexOf(`--bind ${zDir} ${zDir}`),
    )
    expect(command.lastIndexOf(appRo)).toBeGreaterThan(command.indexOf(gitPin))
    expect(command.indexOf(repoPin)).toBeLessThan(
      command.indexOf(`--bind ${PROJECT} ${PROJECT}`),
    )

    if (BWRAP_CAN_NAMESPACE) {
      expect(run(command).stdout).toContain('DONE')
      expect(existsSync(join(repoDir, '.git', 'planted'))).toBe(false)
      expect(readFileSync(join(appDir, 'owned.txt'), 'utf8')).toBe('KEEP\n')
    }
  })

  it('pins the corridor below an allowWrite carve-out nested inside a denied directory', async () => {
    // repo is denyRead-hidden (its own read-only bind is dropped as
    // tmpfs-hidden) and the carve-out sub inside it is restored writable;
    // x, between sub and the deeper leaf, is pinned and cannot be moved.
    mkTree(PROJECT, {
      repo: { sub: { x: { secret: 'DENYTEST\n' } }, 'hidden.txt': 'X\n' },
    })
    const repoDir = join(PROJECT, 'repo')
    const subDir = join(repoDir, 'sub')
    const xDir = join(subDir, 'x')
    const secretPath = join(xDir, 'secret')

    const command = await wrap(
      {
        allowWrite: [subDir],
        denyRead: [repoDir],
        denyWrite: [repoDir, secretPath],
      },
      `cd ${subDir} && mv x x2 && mkdir -p x && echo evil > ${secretPath}`,
    )

    expect(command).toContain(`--ro-bind ${xDir} ${xDir}`)

    if (BWRAP_CAN_NAMESPACE) {
      const result = run(command)
      expect(result.status).not.toBe(0)
      expect(result.stderr ?? '').toMatch(/busy/i)
      expect(existsSync(join(subDir, 'x2'))).toBe(false)
      expect(readFileSync(secretPath, 'utf8')).toBe('DENYTEST\n')
    }
  })

  it('keeps a deny leaf protected when its carve-out sits inside a denyRead inside a denied directory', async () => {
    // denyWrite dir > denyRead > allowWrite carve-out > denyWrite leaf, each
    // containing the next: the
    // tmpfs re-application must not restore a write path with an emitted
    // deny bind under it.
    mkTree(PROJECT, { d: { t: { w: { secret: 'PROTECT\n' } }, 'o.txt': 'X' } })
    const dDir = join(PROJECT, 'd')
    const tDir = join(dDir, 't')
    const wDir = join(tDir, 'w')
    const secretPath = join(wDir, 'secret')

    const command = await wrap(
      { allowWrite: [wDir], denyRead: [tDir], denyWrite: [dDir, secretPath] },
      `echo evil >> ${secretPath} 2>&1; echo DONE`,
    )

    const secretRo = `--ro-bind ${secretPath} ${secretPath}`
    const wBind = `--bind ${wDir} ${wDir}`
    expect(command).toContain(secretRo)
    expect(command.lastIndexOf(wBind)).toBeLessThan(
      command.lastIndexOf(secretRo),
    )

    if (BWRAP_CAN_NAMESPACE) {
      expect(run(command).stdout).toContain('DONE')
      expect(readFileSync(secretPath, 'utf8')).toBe('PROTECT\n')
    }
  })

  it('pins ancestors of denyRead file masks', async () => {
    mkTree(PROJECT, { config: { 'secrets.json': '{"k":"REAL"}\n' } })
    const configDir = join(PROJECT, 'config')
    const secretPath = join(configDir, 'secrets.json')

    const command = await wrap(
      { denyRead: [secretPath] },
      `cd ${PROJECT} && mv config config-moved && mkdir config && echo attacker > ${secretPath}`,
    )

    expect(command).toContain(`--ro-bind /dev/null ${secretPath}`)
    expect(command).toContain(`--ro-bind ${configDir} ${configDir}`)

    if (BWRAP_CAN_NAMESPACE) {
      const result = run(command)
      expect(result.status).not.toBe(0)
      expect(result.stderr).toMatch(/busy/i)
      expect(existsSync(join(PROJECT, 'config-moved'))).toBe(false)
      expect(readFileSync(secretPath, 'utf8')).toBe('{"k":"REAL"}\n')
    }
  })

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

  it('never restores a write path that canonically contains another read-deny location', async () => {
    mkTree(PROJECT, { d: { w: { secret: 'MASKME\n', 'other.txt': 'ok\n' } } })
    const wDir = join(PROJECT, 'd', 'w')
    const secretCanonical = join(wDir, 'secret')
    const sLink = join(PROJECT, 's-link')
    const dLink = join(PROJECT, 'link')
    symlinkSync(join('d', 'w', 'secret'), sLink)
    symlinkSync('d', dLink)

    const command = await wrap(
      { denyRead: [sLink, dLink], allowWrite: [wDir] },
      `cat ${secretCanonical} 2>&1; echo evil >> ${secretCanonical} 2>&1; echo DONE`,
    )

    const tmpfsOp = `--tmpfs ${dLink}`
    const wBind = `--bind ${wDir} ${wDir}`
    expect(command).toContain(tmpfsOp)
    expect(command.lastIndexOf(wBind)).toBeLessThan(
      command.lastIndexOf(tmpfsOp),
    )

    if (BWRAP_CAN_NAMESPACE) {
      const result = run(command)
      expect(result.stdout).toContain('DONE')
      expect(result.stdout).not.toContain('MASKME')
      expect(readFileSync(secretCanonical, 'utf8')).toBe('MASKME\n')
    }
  })

  it('keeps a carve-out inside an emitted denied directory read-only across re-application', async () => {
    mkTree(PROJECT, { D: { t: { w: { 'file.txt': 'KEEP\n' } } } })
    const DDir = join(PROJECT, 'D')
    const tDir = join(DDir, 't')
    const wDir = join(tDir, 'w')

    const command = await wrap(
      { allowWrite: [wDir], denyWrite: [DDir], denyRead: [tDir] },
      `echo evil > ${wDir}/planted.txt 2>&1; echo DONE`,
    )

    const DRo = `--ro-bind ${DDir} ${DDir}`
    const wBind = `--bind ${wDir} ${wDir}`
    expect(command).toContain(DRo)
    expect(command.lastIndexOf(wBind)).toBeLessThan(command.lastIndexOf(DRo))

    if (BWRAP_CAN_NAMESPACE) {
      expect(run(command).stdout).toContain('DONE')
      expect(existsSync(join(wDir, 'planted.txt'))).toBe(false)
    }
  })

  it('never restores an allow entry sitting exactly at a masked location', async () => {
    mkTree(PROJECT, { d: { w: { secret: 'MASKME\n' } } })
    const secretCanonical = join(PROJECT, 'd', 'w', 'secret')
    const sLink = join(PROJECT, 's-link')
    const dLink = join(PROJECT, 'link')
    symlinkSync(join('d', 'w', 'secret'), sLink)
    symlinkSync('d', dLink)

    const command = await wrap(
      { denyRead: [sLink, dLink], allowWrite: [secretCanonical] },
      `cat ${secretCanonical} 2>&1; echo evil >> ${secretCanonical} 2>&1; echo DONE`,
    )

    const tmpfsOp = `--tmpfs ${dLink}`
    const fileBind = `--bind ${secretCanonical} ${secretCanonical}`
    expect(command).toContain(tmpfsOp)
    expect(command.lastIndexOf(fileBind)).toBeLessThan(
      command.lastIndexOf(tmpfsOp),
    )

    if (BWRAP_CAN_NAMESPACE) {
      const result = run(command)
      expect(result.stdout).toContain('DONE')
      expect(result.stdout).not.toContain('MASKME')
      expect(readFileSync(secretCanonical, 'utf8')).toBe('MASKME\n')
    }
  })

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

  it.if(BWRAP_CAN_NAMESPACE)(
    'blocks rmdir of the pinned directory',
    async () => {
      mkTree(PROJECT, { '.git': { hooks: {}, config: '[core]\n' } })

      const result = run(await wrap({}, `cd ${PROJECT} && rmdir .git`))

      expect(result.status).not.toBe(0)
      expect(result.stderr).toMatch(/busy/i)
      expect(existsSync(join(PROJECT, '.git'))).toBe(true)
    },
  )

  it.if(BWRAP_CAN_NAMESPACE && Bun.which('python3') !== null)(
    'blocks an exchange-rename of the pinned directory',
    async () => {
      mkTree(PROJECT, { '.git': { hooks: {}, config: '[core]\n' }, exch: {} })

      // renameat2(RENAME_EXCHANGE) must fail EBUSY (errno 16): the probe
      // exits 0 only in that case.
      const command = await wrap(
        {},
        `cd ${PROJECT} && python3 -c "import ctypes, os, sys; libc = ctypes.CDLL('libc.so.6', use_errno=True); r = libc.renameat2(-100, b'.git', -100, b'exch', 2); sys.exit(0 if r != 0 and ctypes.get_errno() == 16 else 1)"`,
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
        `cd ${appDir} && git add index.js && git -c user.name=t -c user.email=t@t -c commit.gpgsign=false commit -q -m init && git log --oneline | wc -l && echo GIT_OK`,
      )
      const gitResult = run(gitWork)
      expect(gitResult.status).toBe(0)
      expect(gitResult.stdout).toContain('GIT_OK')
      expect(existsSync(join(appDir, '.git', 'refs', 'heads', 'main'))).toBe(
        true,
      )
    },
  )

  it('pins the ancestor between a read-denied directory and a nested repo deny below it; the tmpfs lands after the pin', async () => {
    // top is read-denied and contains the nested repo's .git/config deny;
    // top/.git sits between them and is pinned, top itself is pinned too,
    // and the tmpfs on top is emitted after both so it still hides them.
    mkTree(PROJECT, { top: { '.git': { hooks: {}, config: '[core]\n' } } })
    const topDir = join(PROJECT, 'top')
    const gitDir = join(topDir, '.git')

    const command = await wrap(
      { denyRead: [topDir] },
      `cat ${gitDir}/config 2>&1; echo DONE`,
    )

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

    if (BWRAP_CAN_NAMESPACE) {
      const result = run(command)
      expect(result.stdout ?? '').not.toContain('[core]')
      expect(result.stdout ?? '').toContain('DONE')
    }
  })
})
