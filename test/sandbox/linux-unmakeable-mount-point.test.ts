import { describe, it, expect, beforeEach, afterEach, spyOn } from 'bun:test'
import * as fs from 'fs'
import { spawnSync } from 'node:child_process'
import { basename, dirname, join } from 'node:path'
import { tmpdir } from 'node:os'
import {
  wrapCommandWithSandboxLinux,
  cleanupBwrapMountPoints,
} from '../../src/sandbox/linux-sandbox-utils.js'
import { isLinux } from '../helpers/platform.js'
import { countMounts, mountsOf } from '../helpers/bwrap-argv.js'
import { bwrapCanNamespace } from '../helpers/bwrap-namespace.js'

const REPO_ROOT = join(import.meta.dir, '../..')
const V9FS_MAGIC = 0x01021997

// The originals, for the stand-ins below to fall through to.
const real = {
  accessSync: fs.accessSync,
  chmodSync: fs.chmodSync,
  closeSync: fs.closeSync,
  fstatSync: fs.fstatSync,
  mkdirSync: fs.mkdirSync,
  openSync: fs.openSync,
  readlinkSync: fs.readlinkSync,
  statfsSync: fs.statfsSync,
}
type Stubbed = keyof typeof real

const errno = (code: string): Error =>
  Object.assign(new Error(`${code}: injected`), { code })

/** Whether `spelling` is `target` as the wrap names it: by a descriptor on
 * its directory, or on itself. */
function names(spelling: unknown, target: string): boolean {
  const viaFd = (p: string, dir: string): boolean =>
    /^\/proc\/self\/fd\/\d+$/.test(p) && real.readlinkSync(p) === dir
  return (
    typeof spelling === 'string' &&
    (viaFd(spelling, target) ||
      (basename(spelling) === basename(target) &&
        viaFd(dirname(spelling), dirname(target))))
  )
}

/**
 * An absent deny path is blocked by a placeholder, whose mount point
 * bubblewrap makes on the host, as this user, before the command runs. Where
 * neither it nor the command can create the path there is none to make, and
 * the sandbox starts without.
 */
describe.if(isLinux)('A placeholder where no mount point can be made', () => {
  let BASE: string
  let ROOT: string // the allowed write path
  let DIR: string // a directory in it, holding the absent deny paths
  const savedCwd = process.cwd()
  const spies: Array<{ mockRestore(): void }> = []

  const CAN_RUN = bwrapCanNamespace()
  // Directories of another's that this user cannot write: not root's view.
  const UNPRIVILEGED = ['/usr', '/etc'].every(dir => {
    try {
      fs.accessSync(dir, fs.constants.W_OK)
      return false
    } catch {
      return fs.statSync(dir).uid !== process.geteuid?.()
    }
  })

  beforeEach(() => {
    BASE = fs.realpathSync(fs.mkdtempSync(join(tmpdir(), 'no-mount-point-')))
    ROOT = join(BASE, 'root')
    DIR = join(ROOT, 'dir')
    fs.mkdirSync(DIR, { recursive: true })
    // Outside the allowed write path, so that the mandatory denies add no
    // placeholders of their own.
    process.chdir(BASE)
  })

  afterEach(() => {
    for (const spy of spies.splice(0)) spy.mockRestore()
    standIns.clear()
    process.chdir(savedCwd)
    cleanupBwrapMountPoints({ force: true })
    fs.rmSync(BASE, { recursive: true, force: true })
  })

  /** Stands in for fs[name] until the test ends. A stand-in gets the
   * arguments, and answers `undefined` to leave the call to the next one, the
   * original being the last. */
  type StandIn = (...args: unknown[]) => { value: unknown } | undefined
  const standIns = new Map<Stubbed, StandIn[]>()
  function stub(name: Stubbed, standIn: StandIn): void {
    const sofar = standIns.get(name)
    if (sofar !== undefined) {
      sofar.push(standIn)
      return
    }
    const all = [standIn]
    standIns.set(name, all)
    const original = real[name] as (...args: unknown[]) => unknown
    spies.push(
      spyOn(fs, name).mockImplementation(((...args: unknown[]) => {
        for (const each of all) {
          const stood = each(...args)
          if (stood !== undefined) return stood.value
        }
        return original(...args)
      }) as never),
    )
  }
  /** fs[name] fails with `code` when asked of `target`. */
  const refuse = (name: Stubbed, target: string, code = 'EACCES'): void =>
    stub(name, spelling => {
      if (names(spelling, target)) throw errno(code)
      return undefined
    })
  /** `directory` belongs to somebody else. */
  const ownedByAnother = (directory: string): void => {
    const { ino } = fs.statSync(directory)
    stub('fstatSync', fd => {
      const stats = real.fstatSync(fd as number)
      if (stats.ino !== ino) return undefined
      return { value: Object.assign(stats, { uid: stats.uid + 1 }) }
    })
  }
  /** Everything is on a Windows drive under WSL 2. */
  const onWindowsDrive = (): void =>
    stub('statfsSync', p => ({
      value: { ...real.statfsSync(p as string), type: V9FS_MAGIC },
    }))

  const wrap = (
    denyWithinAllow: string[],
    command = 'true',
    allowOnly = [ROOT],
  ): Promise<string> =>
    wrapCommandWithSandboxLinux({
      command,
      needsNetworkRestriction: false,
      writeConfig: { allowOnly, denyWithinAllow },
    })

  const run = (command: string) =>
    spawnSync(command, { shell: true, encoding: 'utf8', timeout: 15000 })

  /** The mounts that land at `dest`. */
  const mountsAt = (command: string, dest: string): string[] =>
    mountsOf(command).filter(mount => mount.endsWith(` ${dest}`))
  const emptyDirectoryAt = (dest: string) =>
    expect.stringMatching(
      new RegExp(`^--ro-bind \\S*claude-empty-\\S+ ${dest}$`),
    )

  describe('by what the parent directory answers', () => {
    // What access() says of the parent, whose it is, and whether the
    // placeholder is planned.
    const ANSWERS: [string, string | undefined, boolean, boolean][] = [
      ['writable', undefined, true, true],
      ['writable, and of another', undefined, false, true],
      ['unwritable by its mode, and of this user', 'EACCES', true, true],
      ['unwritable by its mode, and of another', 'EACCES', false, false],
      ['on a read-only file system, and of this user', 'EROFS', true, false],
      ['on a read-only file system, and of another', 'EROFS', false, false],
      ['immutable, and of this user', 'EPERM', true, false],
      ['failing to answer, and of another', 'EIO', false, true],
    ]

    it.each(ANSWERS)(
      'plans for a parent that is %s',
      async (_name, code, own, planned) => {
        if (code !== undefined) refuse('accessSync', DIR, code)
        if (!own) ownedByAnother(DIR)
        const leaf = join(DIR, 'policy.json')
        const nested = join(DIR, 'absent', 'policy.json')

        const command = await wrap([leaf, nested])

        expect(mountsAt(command, leaf)).toEqual(
          planned ? [`--ro-bind /dev/null ${leaf}`] : [],
        )
        expect(mountsAt(command, join(DIR, 'absent'))).toEqual(
          planned ? [emptyDirectoryAt(join(DIR, 'absent'))] : [],
        )
        // The parent is pinned either way, beneath the allow bind.
        expect(mountsOf(command).indexOf(`--ro-bind ${DIR} ${DIR}`)).toBe(1)
        // And the question is asked without a trace.
        expect(fs.readdirSync(DIR)).toEqual([])
      },
    )

    it.skipIf(!CAN_RUN)(
      'keeps a parent that takes no mount point from being moved aside',
      async () => {
        refuse('accessSync', DIR)
        ownedByAnother(DIR)
        const aside = join(ROOT, 'aside')

        // In truth DIR is this user's, in a directory it may write: only the
        // pin stands in the way.
        const result = run(
          await wrap(
            [join(DIR, 'policy.json')],
            `echo BOOTED; mv ${DIR} ${aside}; rmdir ${DIR}; echo x > ${join(ROOT, 'new')}`,
          ),
        )

        expect(result.stdout).toBe('BOOTED\n')
        expect(result.stderr).toMatch(/mv: .*busy/)
        expect(result.stderr).toMatch(/rmdir: .*busy/)
        expect(fs.readdirSync(ROOT).sort()).toEqual(['dir', 'new'])
      },
    )

    it('takes nothing that turns up at the path for its own', async () => {
      refuse('accessSync', DIR)
      ownedByAnother(DIR)
      const denied = join(DIR, 'policy.json')

      await wrap([denied])
      fs.writeFileSync(denied, '')
      cleanupBwrapMountPoints()

      expect(fs.existsSync(denied)).toBe(true)
    })

    it('asks for write and search together', async () => {
      const asked: unknown[] = []
      stub('accessSync', (spelling, mode) => {
        if (names(spelling, DIR)) asked.push(mode)
        return undefined
      })

      await wrap([join(DIR, 'policy.json')])

      expect(asked).toEqual([fs.constants.W_OK | fs.constants.X_OK])
    })
  })

  describe('on any doubt', () => {
    beforeEach(() => {
      // Every answer below would leave the placeholder out.
      refuse('accessSync', DIR)
      ownedByAnother(DIR)
    })

    const planned = async (): Promise<void> => {
      const denied = join(DIR, 'policy.json')
      expect(mountsAt(await wrap([denied]), denied)).toEqual([
        `--ro-bind /dev/null ${denied}`,
      ])
    }

    it('leaves it out when there is none', async () => {
      const denied = join(DIR, 'policy.json')
      expect(mountsAt(await wrap([denied]), denied)).toEqual([])
    })

    it('plans it when the parent cannot be opened', async () => {
      stub('openSync', p => {
        if (p === DIR) throw errno('EMFILE')
        return undefined
      })
      await planned()
    })

    it('plans it when /proc does not say where the descriptor leads', async () => {
      stub('readlinkSync', p => {
        if (names(p, DIR)) throw errno('ENOENT')
        return undefined
      })
      await planned()
    })

    it('plans it when the file system cannot be told', async () => {
      refuse('statfsSync', DIR, 'ENOSYS')
      await planned()
    })

    it('closes the descriptor whatever the answer', async () => {
      const open: unknown[] = []
      stub('openSync', (p, flags) => {
        if (p !== DIR) return undefined
        open.push(real.openSync(DIR, flags as number))
        return { value: open.at(-1) }
      })
      stub('closeSync', fd => {
        if (open.includes(fd)) open.splice(open.indexOf(fd), 1)
        return undefined
      })

      await wrap([join(DIR, 'policy.json')])
      refuse('statfsSync', DIR, 'ENOSYS')
      await wrap([join(DIR, 'other.json')])

      expect(open).toEqual([])
    })
  })

  // A command that is still running may write ROOT, and can put something
  // else at a path in it at any moment. /usr stands for a directory that
  // answers "no mount point": it is another's, and this user cannot write it.
  describe.if(UNPRIVILEGED)('with the parent swapped under the wrap', () => {
    const swapOnce = (
      name: Stubbed,
      when: (p: unknown) => boolean,
      swap: () => void,
    ) => {
      let done = false
      stub(name, p => {
        if (!done && when(p)) {
          done = true
          swap()
        }
        return undefined
      })
    }

    it('plans the placeholder when the parent is a symlink as it is opened', async () => {
      swapOnce(
        'openSync',
        p => p === DIR,
        () => {
          fs.rmdirSync(DIR)
          fs.symlinkSync('/usr', DIR)
        },
      )
      const denied = join(DIR, 'policy.json')

      expect(mountsAt(await wrap([denied]), denied)).toHaveLength(1)
    })

    it('plans it when a directory above the parent is a symlink as it is opened', async () => {
      const parent = join(DIR, 'share')
      fs.mkdirSync(parent)
      swapOnce(
        'openSync',
        p => p === parent,
        () => {
          fs.renameSync(DIR, join(ROOT, 'aside'))
          fs.symlinkSync('/usr', DIR)
        },
      )
      const denied = join(parent, 'policy.json')

      expect(mountsAt(await wrap([denied]), denied)).toHaveLength(1)
    })

    it('plans it when the parent is swapped once it is open', async () => {
      swapOnce(
        'fstatSync',
        () => true,
        () => {
          fs.renameSync(DIR, join(ROOT, 'aside'))
          fs.symlinkSync('/usr', DIR)
        },
      )
      const denied = join(DIR, 'policy.json')

      expect(mountsAt(await wrap([denied]), denied)).toHaveLength(1)
    })
  })

  // So that it is the directory that was opened that answers, whatever the
  // path names by then.
  it.each([
    ['off a Windows drive', false],
    ['on a Windows drive', true],
  ])(
    'asks everything of one descriptor on the parent, %s',
    async (_, drive) => {
      const opened: unknown[][] = []
      const asked: string[] = []
      const note = (p: unknown): void => {
        // From the open to the close.
        if (opened.length === 1) asked.push(String(p).replace(/\d+/, 'N'))
      }
      stub('openSync', (p, flags) => {
        if (p === DIR) opened.push([p, flags])
        else note(p)
        // Refused, like mkdir below, so that the questions go on to the last.
        if (names(p, join(DIR, 'policy.json'))) throw errno('EACCES')
        return undefined
      })
      for (const name of [
        'readlinkSync',
        'accessSync',
        'statfsSync',
        'mkdirSync',
        'chmodSync',
      ] as const) {
        stub(name, p => {
          note(p)
          if (name === 'mkdirSync') throw errno('EACCES')
          return undefined
        })
      }
      if (drive) onWindowsDrive()
      stub('closeSync', () => {
        opened.push([])
        return undefined
      })

      await wrap([join(DIR, 'policy.json')])

      expect(opened[0]).toEqual([
        DIR,
        0o10000000 | fs.constants.O_NOFOLLOW | fs.constants.O_DIRECTORY,
      ])
      const parent = '/proc/self/fd/N'
      expect(asked).toEqual([
        ...[parent, parent, parent],
        ...(drive
          ? [`${parent}/policy.json`, `${parent}/policy.json`, parent]
          : []),
      ])
    },
  )

  describe('on a Windows drive under WSL 2', () => {
    beforeEach(onWindowsDrive)

    const listing = () => fs.readdirSync(DIR).sort()

    it('makes the mount point itself, and the clean-up removes it', async () => {
      const leaf = join(DIR, 'policy.json')
      const nested = join(DIR, 'absent', 'policy.json')

      const command = await wrap([leaf, nested])

      expect(mountsAt(command, leaf)).toEqual([`--ro-bind /dev/null ${leaf}`])
      expect(mountsAt(command, join(DIR, 'absent'))).toEqual([
        emptyDirectoryAt(join(DIR, 'absent')),
      ])
      expect(listing()).toEqual(['absent', 'policy.json'])
      expect(fs.statSync(leaf).size).toBe(0)
      expect(fs.statSync(leaf).mode & 0o777).toBe(0o444)
      expect(fs.readdirSync(join(DIR, 'absent'))).toEqual([])
      cleanupBwrapMountPoints()
      expect(listing()).toEqual([])
    })

    it('covers a file with a directory in a folder that takes subfolders and no files', async () => {
      const denied = join(DIR, 'policy.json')
      refuse('openSync', denied)

      const command = await wrap([denied])

      expect(mountsAt(command, denied)).toEqual([emptyDirectoryAt(denied)])
      expect(fs.statSync(denied).isDirectory()).toBe(true)
      cleanupBwrapMountPoints()
      expect(listing()).toEqual([])
    })

    it.each([
      ['a file', 'policy.json', 'policy.json'],
      ['a directory', 'absent/policy.json', 'absent'],
    ])(
      'leaves %s out in a folder that takes nothing and is beyond this user',
      async (_kind, denied, dest) => {
        refuse('openSync', join(DIR, dest))
        refuse('mkdirSync', join(DIR, dest), 'EPERM')
        refuse('chmodSync', DIR)

        const command = await wrap([join(DIR, denied)])

        expect(mountsAt(command, join(DIR, dest))).toEqual([])
        expect(countMounts(command, '--ro-bind', DIR, DIR)).toBe(1)
        expect(listing()).toEqual([])
      },
    )

    it('plans the kind asked for when the name is refused in a folder this user governs', async () => {
      const denied = join(DIR, 'policy.json')
      fs.chmodSync(DIR, 0o2750)
      refuse('openSync', denied)
      refuse('mkdirSync', denied)
      const modes: unknown[] = []
      stub('chmodSync', (p, mode) => {
        if (names(p, DIR)) modes.push(mode)
        return undefined
      })

      const command = await wrap([denied])

      expect(mountsAt(command, denied)).toEqual([
        `--ro-bind /dev/null ${denied}`,
      ])
      // The mode it has, so that nothing changes.
      expect(modes).toEqual([0o2750])
    })

    it.each([
      ['plans it', 'governs', true],
      ['leaves it out', 'does not govern', false],
    ])(
      '%s, and tries nothing, where access() refuses a folder this user %s',
      async (_verdict, _governs, planned) => {
        const denied = join(DIR, 'policy.json')
        refuse('accessSync', DIR)
        if (!planned) refuse('chmodSync', DIR, 'EROFS')

        const command = await wrap([denied])

        expect(mountsAt(command, denied)).toHaveLength(planned ? 1 : 0)
        expect(listing()).toEqual([])
      },
    )

    it('tries no file where a directory is wanted', async () => {
      const tried: unknown[] = []
      stub('openSync', p => {
        if (names(p, join(DIR, 'absent'))) tried.push(p)
        return undefined
      })
      refuse('mkdirSync', join(DIR, 'absent'))
      refuse('chmodSync', DIR)

      await wrap([join(DIR, 'absent', 'policy.json')])

      expect(tried).toEqual([])
      expect(listing()).toEqual([])
    })

    it('plans it, and takes nothing for its own, when the path is there by the time it is tried', async () => {
      const denied = join(DIR, 'policy.json')
      stub('openSync', p => {
        if (names(p, denied)) fs.writeFileSync(denied, 'theirs')
        return undefined
      })

      const command = await wrap([denied])

      expect(mountsAt(command, denied)).toHaveLength(1)
      cleanupBwrapMountPoints()
      expect(fs.readFileSync(denied, 'utf8')).toBe('theirs')
    })

    // What one deny path's mount point puts on the host, the next is not
    // misled by: the plan is the same in either order, and as off the drive.
    describe.each([
      ['a missing folder', ['absent/policy.json', 'absent/policy.d/x']],
      ['a path and one beneath it', ['absent', 'absent/commands']],
    ])('with deny paths that share %s', (_name, denied) => {
      it.each([
        ['as listed', (list: string[]) => list],
        ['reversed', (list: string[]) => [...list].reverse()],
      ])('plans one directory, %s', async (_order, ordered) => {
        const command = await wrap(ordered(denied.map(d => join(DIR, d))))

        expect(mountsOf(command).filter(m => m.includes(`${DIR}/`))).toEqual([
          emptyDirectoryAt(join(DIR, 'absent')),
        ])
        expect(listing()).toEqual(['absent'])
        expect(fs.readdirSync(join(DIR, 'absent'))).toEqual([])
      })
    })

    it('removes what it made when the wrap then fails', async () => {
      const wrapped = wrapCommandWithSandboxLinux({
        command: 'true',
        needsNetworkRestriction: false,
        writeConfig: {
          allowOnly: [ROOT],
          denyWithinAllow: [join(DIR, 'policy.json')],
        },
        binShell: 'no-such-shell',
      })

      expect(wrapped).rejects.toThrow('no-such-shell')
      await wrapped.catch(() => {})
      expect(listing()).toEqual([])
    })

    it.skipIf(!CAN_RUN)(
      'runs on the mount points it made, and the paths cannot be created',
      async () => {
        const leaf = join(DIR, 'policy.json')
        const nested = join(DIR, 'absent', 'policy.json')

        const result = run(
          await wrap(
            [leaf, nested],
            `echo BOOTED; echo x > ${leaf}; echo x > ${nested}; echo x > ${join(DIR, 'new')}`,
          ),
        )

        expect(result.stdout).toBe('BOOTED\n')
        expect(result.stderr).not.toContain('bwrap:')
        cleanupBwrapMountPoints()
        expect(listing()).toEqual(['new'])
      },
    )
  })

  it('asks nothing of the host for a path that needs no placeholder', async () => {
    const opened: unknown[] = []
    stub('openSync', p => {
      opened.push(p)
      return undefined
    })
    fs.writeFileSync(join(ROOT, 'file'), '')

    await wrap(
      [
        ROOT, // covers DIR, the one allowed write path
        join(DIR, 'covered.json'),
        join(BASE, 'outside.json'),
      ],
      'true',
      [DIR],
    )

    expect(opened).toEqual([])
  })

  it('asks once for deny paths that share a missing directory', async () => {
    const opened: unknown[] = []
    stub('openSync', p => {
      opened.push(p)
      return undefined
    })

    await wrap([join(DIR, 'absent', 'a'), join(DIR, 'absent', 'b', 'c')])

    expect(opened).toEqual([DIR])
  })

  describe.if(UNPRIVILEGED)('in directories of another user', () => {
    const PROBE = 'srt-no-mount-point-probe'
    const denied = [`/usr/${PROBE}/policy.json`, `/etc/${PROBE}`, `/${PROBE}`]
    const dests = [`/usr/${PROBE}`, `/etc/${PROBE}`, `/${PROBE}`]

    it('plans no placeholder, and keeps their top-level directories mount points', async () => {
      const command = await wrap(denied, 'true', ['/'])

      for (const dest of dests) expect(mountsAt(command, dest)).toEqual([])
      expect(countMounts(command, '--bind', '/usr', '/usr')).toBe(1)
      expect(countMounts(command, '--bind', '/etc', '/etc')).toBe(1)
    })

    it.skipIf(!CAN_RUN).each([
      ['"/"', ['/']],
      ['the directories themselves', ['/usr', '/etc']],
    ])(
      'starts with %s allowed, and the paths cannot be created',
      async (_name, allowOnly) => {
        const result = run(
          await wrap(
            denied,
            `echo BOOTED; mkdir ${dests[0]}; echo x > ${dests[1]}; echo x > ${dests[2]}; mv /usr/share /usr/aside; echo x > ${join(DIR, 'new')}`,
            [...allowOnly, ROOT],
          ),
        )

        expect(result.stderr).not.toContain('bwrap:')
        expect(result.stdout).toBe('BOOTED\n')
        expect(dests.filter(dest => fs.existsSync(dest))).toEqual([])
        expect(fs.readdirSync(DIR)).toEqual(['new'])
      },
    )
  })

  describe('in a directory of this user that its mode closes', () => {
    beforeEach(() => fs.chmodSync(DIR, 0o555))
    afterEach(() => fs.chmodSync(DIR, 0o755))

    it.skipIf(process.geteuid?.() === 0)('plans the placeholder', async () => {
      const denied = join(DIR, 'policy.json')

      expect(mountsAt(await wrap([denied]), denied)).toEqual([
        `--ro-bind /dev/null ${denied}`,
      ])
    })

    it.skipIf(!CAN_RUN)(
      'holds the path against a command that opens the directory',
      async () => {
        const denied = join(DIR, 'policy.json')

        const result = run(
          await wrap(
            [denied],
            `echo BOOTED; chmod 755 ${DIR}; echo x > ${denied}; echo x > ${join(DIR, 'new')}`,
          ),
        )

        expect(result.stdout).toBe('BOOTED\n')
        expect(fs.readFileSync(denied, 'utf8')).toBe('')
        expect(fs.existsSync(join(DIR, 'new'))).toBe(true)
      },
    )
  })

  // A read-only file system that this user owns everything on: a sandbox
  // around the wrap and its own, with DIR bound read-only.
  it.skipIf(!CAN_RUN)(
    'starts with an absent deny path on a read-only file system',
    () => {
      const denied = join(DIR, 'policy.json')
      const script = `
        const { wrapCommandWithSandboxLinux } = await import('./src/sandbox/linux-sandbox-utils.ts')
        const { spawnSync } = await import('node:child_process')
        const command = await wrapCommandWithSandboxLinux({
          command: 'echo BOOTED; echo x > ${denied}; echo x > ${join(ROOT, 'new')}',
          needsNetworkRestriction: false,
          writeConfig: { allowOnly: ['${ROOT}'], denyWithinAllow: ['${denied}'] },
        })
        const { stdout, stderr } = spawnSync(command, { shell: true, encoding: 'utf8' })
        console.log(JSON.stringify({ command, stdout, stderr }))`
      const outer = spawnSync(
        'bwrap',
        [
          ...['--unshare-user', '--bind', '/', '/', '--ro-bind', DIR, DIR],
          ...['--dev', '/dev', '--proc', '/proc', '--chdir', REPO_ROOT],
          ...[process.execPath, '-e', script],
        ],
        { encoding: 'utf8', timeout: 60_000 },
      )
      const { command, stdout, stderr } = JSON.parse(
        outer.stdout.trim().split('\n').at(-1) ?? '{}',
      ) as { command: string; stdout: string; stderr: string }

      expect(stderr).not.toContain('bwrap:')
      expect(stdout).toBe('BOOTED\n')
      expect(mountsAt(command, denied)).toEqual([])
      expect(fs.readdirSync(DIR)).toEqual([])
      expect(fs.readdirSync(ROOT).sort()).toEqual(['dir', 'new'])
    },
  )
})
