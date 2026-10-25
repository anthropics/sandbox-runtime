import { describe, it, expect, beforeEach, afterEach, spyOn } from 'bun:test'
import { type ChildProcess, spawn, spawnSync } from 'node:child_process'
import * as fs from 'node:fs'
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  readlinkSync,
  realpathSync,
  rmSync,
  utimesSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { basename, extname, join } from 'node:path'
import {
  collectMountPoints,
  liveMountPoints,
  passesToEnd,
  passesUnderWay,
  publishMountPointManifest,
} from '../../src/sandbox/bwrap-mount-manifests.js'
import {
  cleanupBwrapMountPoints,
  LinuxSandboxProfileError,
  wrapCommandWithSandboxLinux,
} from '../../src/sandbox/linux-sandbox-utils.js'
import { manifestOf } from '../helpers/bwrap-argv.js'
import { bwrapCanNamespace } from '../helpers/bwrap-namespace.js'
import {
  aDeadProcess,
  leftover,
  type Process,
  processAt,
  recordOf,
  run,
  sleep,
  started,
  until,
  wrapIn,
  writeManifest,
  writeScript,
} from '../helpers/mount-point-fixtures.js'
import { isLinux } from '../helpers/platform.js'
import { usePrivateManifestDirectory } from '../helpers/private-manifest-directory.js'

/**
 * A clean-up decides on a reading of the manifests and removes afterwards, and
 * can be held up between the two for any length of time. So it puts itself on
 * record before it reads, and a wrap that has published its manifest hands no
 * command out while a clean-up is on record: whichever of the two came second
 * has seen the other.
 */
describe.if(isLinux)('A clean-up of mount points, on record', () => {
  const runtime = usePrivateManifestDirectory()
  const BWRAP_CAN_NAMESPACE = bwrapCanNamespace()
  const MODULE = JSON.stringify(
    join(import.meta.dir, '../helpers/isolated/manifests.ts'),
  )
  const OWN_NAMESPACE = isLinux ? readlinkSync('/proc/self/ns/pid') : ''
  const OWN_BOOT = isLinux
    ? readFileSync('/proc/sys/kernel/random/boot_id', 'utf8').trim()
    : ''
  /** Echoed first by every command that runs for real. */
  const BOOTED = 'BOOTED'

  let BASE: string
  let DIR: string // where the manifests and the passes go
  let AREA: string // the allowed write area
  let LOCK: string // the denyWrite path, absent to begin with
  let others: ChildProcess[] // ended after each test

  beforeEach(() => {
    BASE = realpathSync(mkdtempSync(join(tmpdir(), 'mount-point-passes-')))
    AREA = join(BASE, 'area')
    mkdirSync(AREA)
    LOCK = join(AREA, 'config.lock')
    DIR = runtime.manifestDir()
    mkdirSync(DIR, { recursive: true, mode: 0o700 })
    chmodSync(DIR, 0o700)
    others = []
  })

  afterEach(() => {
    for (const other of others) {
      if (other.pid !== undefined) {
        try {
          process.kill(other.pid, 'SIGCONT')
          process.kill(other.pid, 'SIGKILL')
        } catch {
          // Gone already.
        }
      }
    }
    for (const name of readdirSync(DIR)) rmSync(join(DIR, name))
    cleanupBwrapMountPoints({ force: true })
    rmSync(BASE, { recursive: true, force: true })
  })

  /** Another process of this user, which runs until the test is over. */
  function anotherProcess(): Process {
    const other = spawn('sleep', ['600'], { stdio: 'ignore' })
    others.push(other)
    return processAt(other.pid!)
  }

  /** What a killed process leaves in DIR, or one that `writer` wrote. */
  const manifestOfADeadProcess = (paths: string[], writer?: Process): string =>
    writeManifest(DIR, paths, { boot: OWN_BOOT, ...writer })

  /** Puts a pass of `who` on record, as the library names one. */
  function passOf(
    who: Process,
    where: { ns?: string; boot?: string } = {},
  ): string {
    const ns = where.ns ?? /\d+/.exec(OWN_NAMESPACE)![0]
    const boot = (where.boot ?? OWN_BOOT).replace(/-/g, '')
    const file = join(
      DIR,
      `${who.pid}-${who.start}-${ns}-${boot}-0123456789abcdef.pass`,
    )
    writeFileSync(file, '', { mode: 0o600 })
    return file
  }

  function aged(file: string, ms: number): string {
    const then = new Date(Date.now() - ms)
    utimesSync(file, then, then)
    return file
  }

  const passes = (): string[] =>
    readdirSync(DIR).filter(name => name.endsWith('.pass'))

  const wrap = (command = 'true', deny = [LOCK]): Promise<string> =>
    wrapIn(AREA, command, deny)

  const script = (name: string, lines: string[]): string =>
    writeScript(BASE, name, lines)

  // ---- the pass ------------------------------------------------------------

  it('says what is finished and goes on record before the reading it decides on, stays there while it removes, and is off it afterwards', () => {
    leftover(LOCK)
    manifestOfADeadProcess([LOCK])
    const open = fs.openSync
    const rename = fs.renameSync
    const unlink = fs.unlinkSync
    const seen: string[] = []
    const spies = [
      spyOn(fs, 'openSync').mockImplementation(((
        file: unknown,
        ...rest: unknown[]
      ) => {
        if (typeof file === 'string' && /\.(pass|finished)$/.test(file)) {
          seen.push(file.endsWith('.pass') ? 'on record' : 'reads the claim')
        }
        return (open as (...args: unknown[]) => number)(file, ...rest)
      }) as never),
      spyOn(fs, 'renameSync').mockImplementation(((
        from: string,
        to: string,
      ) => {
        seen.push(`renames to ${extname(to)}`)
        rename(from, to)
      }) as never),
      spyOn(fs, 'unlinkSync').mockImplementation(((file: string) => {
        if (file === LOCK)
          seen.push(`removes, with ${passes().length} on record`)
        unlink(file)
      }) as never),
    ]
    try {
      expect(collectMountPoints('all')).toEqual([LOCK])
    } finally {
      spies.forEach(spy => spy.mockRestore())
    }
    expect(seen).toEqual([
      'renames to .claimed',
      'renames to .finished',
      'on record',
      'reads the claim',
      'removes, with 1 on record',
    ])
    expect(readdirSync(DIR)).toEqual([])
  })

  it('is named for its process, so that a listing is all it takes to ask after it', () => {
    leftover(LOCK)
    manifestOfADeadProcess([LOCK])
    const unlink = fs.unlinkSync
    let name: string | undefined
    const spy = spyOn(fs, 'unlinkSync').mockImplementation(((file: string) => {
      if (file === LOCK) [name] = passes()
      unlink(file)
    }) as never)
    try {
      collectMountPoints('all')
    } finally {
      spy.mockRestore()
    }
    const { pid, start } = processAt(process.pid)
    expect(name).toStartWith(
      `${pid}-${start}-${/\d+/.exec(OWN_NAMESPACE)![0]}-${OWN_BOOT.replace(/-/g, '')}-`,
    )
  })

  it('puts nothing on record where there is nothing to remove', () => {
    manifestOfADeadProcess([LOCK], anotherProcess())
    const open = spyOn(fs, 'openSync')
    try {
      expect(collectMountPoints('all')).toEqual([])
      expect(
        open.mock.calls.filter(([file]) => String(file).endsWith('.pass')),
      ).toEqual([])
    } finally {
      open.mockRestore()
    }
  })

  it("removes nothing on a manifest's word where it cannot be put on record, and the next pass does", () => {
    leftover(LOCK)
    const manifest = manifestOfADeadProcess([LOCK])
    const open = fs.openSync
    const spy = spyOn(fs, 'openSync').mockImplementation(((
      file: unknown,
      ...rest: unknown[]
    ) => {
      if (String(file).endsWith('.pass')) {
        throw Object.assign(new Error('ENOSPC'), { code: 'ENOSPC' })
      }
      return (open as (...args: unknown[]) => number)(file, ...rest)
    }) as never)
    try {
      expect(collectMountPoints('all')).toEqual([])
    } finally {
      spy.mockRestore()
    }
    expect(existsSync(LOCK)).toBe(true)
    // What it has found finished stays so, and named, for the next.
    expect(readdirSync(DIR)).toEqual([
      basename(manifest).replace(/json$/, 'finished'),
    ])
    expect(collectMountPoints('all')).toEqual([LOCK])
  })

  it('still removes what this process could record nowhere, on a disk that takes neither a manifest nor a record', () => {
    // No other process knows it for a mount point, or waits for a pass over it.
    const full = (file: unknown): void => {
      if (/\.(pass|tmp)$/.test(String(file))) {
        throw Object.assign(new Error('ENOSPC'), { code: 'ENOSPC' })
      }
    }
    const open = fs.openSync
    const write = fs.writeFileSync
    const spies = [
      spyOn(fs, 'openSync').mockImplementation(((
        file: unknown,
        ...rest: unknown[]
      ) => {
        full(file)
        return (open as (...args: unknown[]) => number)(file, ...rest)
      }) as never),
      spyOn(fs, 'writeFileSync').mockImplementation(((
        file: unknown,
        ...rest: unknown[]
      ) => {
        full(file)
        ;(write as (...args: unknown[]) => void)(file, ...rest)
      }) as never),
    ]
    try {
      expect(publishMountPointManifest([LOCK], [])).toBeUndefined()
      leftover(LOCK)
      expect(collectMountPoints('all')).toEqual([LOCK])
    } finally {
      spies.forEach(spy => spy.mockRestore())
    }
  })

  it('goes on no record over manifests it cannot read, where it may remove nothing', () => {
    leftover(LOCK)
    manifestOfADeadProcess([LOCK])
    writeFileSync(join(DIR, '1-0123456789abcdef.json'), '{"version":"?"}')
    const open = spyOn(fs, 'openSync')
    try {
      expect(collectMountPoints('all')).toEqual([])
      expect(
        open.mock.calls.filter(([file]) => String(file).endsWith('.pass')),
      ).toEqual([])
    } finally {
      open.mockRestore()
    }
  })

  it('is off the record when the pass throws', () => {
    leftover(LOCK)
    manifestOfADeadProcess([LOCK])
    const now = performance.now.bind(performance)
    const spy = spyOn(performance, 'now').mockImplementation(() => {
      if (passes().length > 0) throw new TypeError('a bug')
      return now()
    })
    try {
      expect(() => collectMountPoints('all')).toThrow('a bug')
    } finally {
      spy.mockRestore()
    }
    expect(passes()).toEqual([])
  })

  /** Has that clock go on by `ms` whenever `heldUpFor` is called. */
  function aClockThatIsHeldUp(clock: typeof performance | typeof Date): {
    heldUpFor(ms: number): void
    mockRestore(): void
  } {
    const now = clock.now.bind(clock)
    let lost = 0
    const spy = spyOn(clock, 'now').mockImplementation(() => now() + lost)
    return {
      heldUpFor: ms => {
        lost += ms
      },
      mockRestore: () => spy.mockRestore(),
    }
  }
  // The wall clock alone goes on while the host is suspended, and others go by
  // it; it alone can be set back.
  const CLOCKS = [
    ['the monotonic clock', (): typeof performance => performance],
    ['the wall clock', (): typeof Date => Date],
  ] as const

  it.each(CLOCKS)(
    'leaves the rest to the next pass once it has been on record for two seconds, by %s',
    (_, which) => {
      const second = join(AREA, 'second.lock')
      leftover(LOCK)
      leftover(second)
      manifestOfADeadProcess([LOCK, second])
      const unlink = fs.unlinkSync
      const clock = aClockThatIsHeldUp(which())
      const spy = spyOn(fs, 'unlinkSync').mockImplementation(((
        file: string,
      ) => {
        unlink(file)
        if (file === second) clock.heldUpFor(2_001)
      }) as never)
      try {
        // Children first, which among siblings is the later name first.
        expect(collectMountPoints('all')).toEqual([second])
      } finally {
        spy.mockRestore()
        clock.mockRestore()
      }
      expect(existsSync(LOCK)).toBe(true)
      expect(passes()).toEqual([])
      expect(collectMountPoints('all')).toEqual([LOCK])
    },
  )

  it.each(CLOCKS)(
    'counts the time it takes to go on record, and to list the directories before a removal, by %s',
    (_, which) => {
      for (const heldUpIn of ['openSync', 'readdirSync'] as const) {
        leftover(LOCK)
        manifestOfADeadProcess([LOCK])
        const clock = aClockThatIsHeldUp(which())
        const real = fs[heldUpIn] as (...args: unknown[]) => unknown
        let listings = 0
        const spy = spyOn(fs, heldUpIn).mockImplementation(((
          file: unknown,
          ...rest: unknown[]
        ) => {
          const result = real(file, ...rest)
          if (
            heldUpIn === 'openSync'
              ? String(file).endsWith('.pass')
              : // The reading it decides on, then the one before the removal.
                file === DIR &&
                (result as string[]).some(name => name.endsWith('.pass')) &&
                ++listings === 2
          ) {
            clock.heldUpFor(2_001)
          }
          return result
        }) as never)
        try {
          expect(collectMountPoints('all')).toEqual([])
        } finally {
          spy.mockRestore()
          clock.mockRestore()
        }
        if (heldUpIn === 'readdirSync') expect(listings).toBe(2)
        expect(collectMountPoints('all')).toEqual([LOCK])
      }
    },
  )

  // ---- which passes are under way --------------------------------------------

  it('is under way while its process runs, however old its record', () => {
    const pass = aged(passOf(anotherProcess()), 24 * 60 * 60 * 1000)
    expect(passesUnderWay()).toEqual([pass])
  })

  it('is under way while its process is stopped', async () => {
    const other = anotherProcess()
    process.kill(other.pid, 'SIGSTOP')
    await until('the process to be stopped', () =>
      / T /.test(readFileSync(`/proc/${other.pid}/stat`, 'utf8')),
    )
    const pass = passOf(other)
    expect(passesUnderWay()).toEqual([pass])
  })

  it.each([
    ['its process is gone', (): string => passOf(aDeadProcess())],
    [
      'its pid is a later process',
      (): string => {
        const { pid, start } = anotherProcess()
        return passOf({ pid, start: String(Number(start) - 1) })
      },
    ],
    [
      'it is of an earlier boot',
      (): string =>
        passOf(anotherProcess(), {
          boot: '00000000-0000-0000-0000-000000000000',
        }),
    ],
  ])('is over when %s, and the next pass drops its record', (_what, plant) => {
    const pass = plant()
    expect(passesUnderWay()).toEqual([])
    collectMountPoints('all')
    expect(existsSync(pass)).toBe(false)
  })

  it.each([
    [
      "another PID namespace's",
      (): string => passOf(anotherProcess(), { ns: '1' }),
    ],
    [
      'of a process that could read neither its namespace nor the boot',
      (): string => passOf(anotherProcess(), { ns: '', boot: '' }),
    ],
    [
      'at a name that is none of ours',
      (): string => {
        const file = join(DIR, 'whatever.pass')
        writeFileSync(file, '')
        return file
      },
    ],
  ])(
    'goes by the age of its record where it cannot be asked after: %s',
    (_what, plant) => {
      const pass = plant()
      expect(passesUnderWay()).toEqual([pass])
      aged(pass, 59_000)
      expect(passesUnderWay()).toEqual([pass])
      collectMountPoints('all')
      expect(existsSync(pass)).toBe(true)
      aged(pass, 61_000)
      expect(passesUnderWay()).toEqual([])
      // Its record is not this process's to drop: its own may be stopped half
      // way, and those who can ask after it still wait for it.
      collectMountPoints('all')
      expect(existsSync(pass)).toBe(true)
      aged(pass, 8 * 24 * 60 * 60 * 1000)
      collectMountPoints('all')
      expect(existsSync(pass)).toBe(false)
    },
  )

  it('is over, to the copy of the library that made it, once that has gone on to something else', () => {
    // What a record that could not be dropped would otherwise do: hold up every
    // wrap of the user for as long as this process runs.
    leftover(LOCK)
    manifestOfADeadProcess([LOCK])
    const unlink = fs.unlinkSync
    const spy = spyOn(fs, 'unlinkSync').mockImplementation(((file: string) => {
      if (file.endsWith('.pass')) {
        throw Object.assign(new Error('EIO'), { code: 'EIO' })
      }
      unlink(file)
    }) as never)
    try {
      expect(collectMountPoints('all')).toEqual([LOCK])
    } finally {
      spy.mockRestore()
    }
    expect(passes()).toHaveLength(1)
    expect(passesUnderWay()).toEqual([])
    collectMountPoints('all')
    expect(passes()).toEqual([])
  })

  it('is under way to another copy of the library in the same process', () => {
    // A worker thread has the pid of the thread that started it.
    const pass = passOf(processAt(process.pid))
    expect(passesUnderWay()).toEqual([pass])
  })

  it('does not put a reading of the manifests in doubt', () => {
    passOf(anotherProcess())
    leftover(LOCK)
    manifestOfADeadProcess([LOCK], anotherProcess())
    expect([...(liveMountPoints() ?? [])]).toEqual([LOCK])
  })

  // ---- the wait --------------------------------------------------------------

  it('is waited for until its record goes', async () => {
    const pass = passOf(anotherProcess())
    let ended: string | undefined | null = null
    const waiting = passesToEnd([pass]).then(heldUp => (ended = heldUp))
    await sleep(150)
    expect(ended).toBeNull()
    rmSync(pass)
    await waiting
    expect(ended).toBeUndefined()
  })

  it('is waited for until its process goes', async () => {
    const other = anotherProcess()
    const waiting = passesToEnd([passOf(other)])
    await sleep(50)
    process.kill(other.pid, 'SIGKILL')
    expect(await waiting).toBeUndefined()
  })

  it('is named to the caller when it outlasts the wait', async () => {
    const pass = passOf(anotherProcess())
    const began = performance.now()
    expect(await passesToEnd([pass], undefined, 200)).toBe(pass)
    expect(performance.now() - began).toBeGreaterThanOrEqual(200)
  })

  it('is not waited for once the caller has given up', async () => {
    const gaveUp = new AbortController()
    const waiting = passesToEnd([passOf(anotherProcess())], gaveUp.signal)
    gaveUp.abort(new Error('gave up'))
    expect(
      await waiting.then(
        () => undefined,
        (error: unknown) => error,
      ),
    ).toEqual(new Error('gave up'))
  })

  it('is not waited for when it went on record after the wrap had listed them: it has read the manifest', async () => {
    const first = passOf(anotherProcess())
    const waiting = passesToEnd([first])
    const later = passOf(anotherProcess())
    await sleep(20)
    rmSync(first)
    expect(await waiting).toBeUndefined()
    expect(passesUnderWay()).toEqual([later])
  })

  it('is waited for by whichever name its directory is listed', async () => {
    // Two of the places may be one directory, and which of the names that goes
    // by may differ from one listing to the next.
    const listedAs = join(
      BASE,
      'the-other-name',
      basename(passOf(anotherProcess())),
    )
    expect(await passesToEnd([listedAs], undefined, 200)).toBe(listedAs)
  })

  // ---- the wrap ----------------------------------------------------------------

  it('holds back the command of a wrap that names a mount point, until it is over', async () => {
    const pass = passOf(anotherProcess())
    let handedOut = false
    const wrapping = wrap().then(command => {
      handedOut = true
      return command
    })
    await until('the wrap to publish', () =>
      readdirSync(DIR).some(name => name.endsWith('.json')),
    )
    await sleep(150)
    expect(handedOut).toBe(false)
    rmSync(pass)
    expect(manifestOf(await wrapping)).toBeDefined()
  })

  it('holds back no wrap that relies on nothing a clean-up could remove', async () => {
    passOf(anotherProcess())
    writeFileSync(LOCK, 'held by somebody')
    expect(manifestOf(await wrap())).toBeUndefined()
  })

  it('has the wrap look at the host after it, not before', async () => {
    // The mount point of a finished sandbox, which the wrap plans to cover
    // again, in a directory that is one too, which the wrap plans to make its
    // own in. The pass that is under way takes both.
    const directory = join(AREA, '.claude')
    const inside = join(directory, 'commands')
    mkdirSync(directory)
    manifestOfADeadProcess([directory])
    const pass = passOf(anotherProcess())
    const wrapping = wrap('true', [inside])
    await until('the wrap to publish', () =>
      readdirSync(DIR).some(
        name =>
          name.endsWith('.json') &&
          readFileSync(join(DIR, name), 'utf8').includes(inside),
      ),
    )
    rmSync(directory, { recursive: true })
    rmSync(pass)
    // Planned again: what is missing now is the directory.
    const manifest = manifestOf(await wrapping)
    const { paths } = JSON.parse(readFileSync(manifest!, 'utf8')) as {
      paths: string[]
    }
    expect(paths).toEqual([directory])
  })

  it('refuses the wrap when it is held up for longer than a wrap waits, and names its record', async () => {
    const pass = passOf(anotherProcess())
    const refused = await wrap().then(
      () => undefined,
      (error: unknown) => error,
    )
    expect(refused).toBeInstanceOf(LinuxSandboxProfileError)
    expect((refused as LinuxSandboxProfileError).code).toBe(
      'mount_points_changed',
    )
    expect((refused as LinuxSandboxProfileError).cause).toBe(pass)
    expect((refused as LinuxSandboxProfileError).message).toContain(pass)
    // The wrap has let go of what it named.
    expect(readdirSync(DIR)).toEqual([basename(pass)])
  }, 15000)

  it('lets the caller give the wrap up while it waits', async () => {
    passOf(anotherProcess())
    const gaveUp = new AbortController()
    const wrapping = wrapCommandWithSandboxLinux({
      command: 'true',
      needsNetworkRestriction: false,
      readConfig: { denyOnly: [] },
      writeConfig: { allowOnly: [AREA], denyWithinAllow: [LOCK] },
      abortSignal: gaveUp.signal,
    })
    await until('the wrap to publish', () =>
      readdirSync(DIR).some(name => name.endsWith('.json')),
    )
    gaveUp.abort(new Error('gave up'))
    expect(
      await wrapping.then(
        () => undefined,
        (error: unknown) => error,
      ),
    ).toEqual(new Error('gave up'))
  })

  it('plans again when a forced clean-up has let go of its manifest while it waited', async () => {
    const pass = passOf(anotherProcess())
    const published = (): string[] =>
      readdirSync(DIR).filter(name => name.endsWith('.json'))
    const wrapping = wrap()
    await until('the wrap to publish', () => published().length > 0)
    const [first] = published()
    cleanupBwrapMountPoints({ force: true })
    rmSync(pass)
    const manifest = manifestOf(await wrapping)
    expect(basename(manifest!)).not.toBe(first)
    expect(existsSync(manifest!)).toBe(true)
  })

  it('says nothing of the other commands of its process when it comes to nothing', async () => {
    // One that has run, whose caller has not cleaned up after it and may run it
    // again.
    const kept = await wrap()
    started(manifestOf(kept)!, aDeadProcess())
    const gaveUp = new AbortController()
    gaveUp.abort(new Error('gave up'))
    expect(
      await wrapCommandWithSandboxLinux({
        command: 'true',
        needsNetworkRestriction: false,
        readConfig: { denyOnly: [] },
        writeConfig: { allowOnly: [AREA], denyWithinAllow: [LOCK] },
        abortSignal: gaveUp.signal,
      }).then(
        () => undefined,
        (error: unknown) => error,
      ),
    ).toBeInstanceOf(Error)
    expect(existsSync(manifestOf(kept)!)).toBe(true)
    cleanupBwrapMountPoints()
    expect(existsSync(manifestOf(kept)!)).toBe(false)
  })

  // A clean-up in a process of its own, stopped between its last look at the
  // manifests and the removal, for as long as the test likes.
  it.if(BWRAP_CAN_NAMESPACE)(
    'cannot take a mount point from under a sandbox that starts while it is stopped before the removal',
    async () => {
      leftover(LOCK)
      manifestOfADeadProcess([LOCK])
      const about = join(BASE, 'about-to-remove')
      const cleaner = spawn(
        process.execPath,
        [
          script('stopped-cleaner.ts', [
            `import { spyOn } from 'bun:test'`,
            `import * as fs from 'node:fs'`,
            `const m = await import(${MODULE})`,
            `const unlink = fs.unlinkSync`,
            `spyOn(fs, 'unlinkSync').mockImplementation((file) => {`,
            `  if (file === ${JSON.stringify(LOCK)}) {`,
            `    fs.writeFileSync(${JSON.stringify(about)}, '')`,
            `    process.kill(process.pid, 'SIGSTOP')`,
            `  }`,
            `  unlink(file)`,
            `})`,
            `m.collectMountPoints('all')`,
          ]),
        ],
        { stdio: 'ignore' },
      )
      others.push(cleaner)
      const cleaned = new Promise(resolve => cleaner.on('exit', resolve))
      await until('the clean-up to reach the removal', () => existsSync(about))
      await until('the clean-up to be stopped', () =>
        / T /.test(readFileSync(`/proc/${cleaner.pid}/stat`, 'utf8')),
      )

      // What the sandbox tries once it is up: the removal first, which only a
      // bind still in place refuses.
      const up = join(AREA, 'up')
      const go = join(AREA, 'go')
      let command: string | undefined
      const wrapping = wrap(
        `echo ${BOOTED}; echo up > ${up}; while [ ! -e ${go} ]; do sleep 0.02; done; rm -f ${LOCK}; echo pwned > ${LOCK}; echo rc=$?`,
      ).then(wrapped => (command = wrapped))
      await sleep(1000)
      // No command, so no sandbox, for as long as the removal is pending.
      expect(command).toBeUndefined()
      expect(existsSync(LOCK)).toBe(true)

      process.kill(cleaner.pid!, 'SIGCONT')
      await cleaned
      await wrapping

      const sandbox = spawn(command!, { shell: true })
      others.push(sandbox)
      let said = ''
      sandbox.stdout.on('data', chunk => (said += String(chunk)))
      sandbox.stderr.on('data', chunk => (said += String(chunk)))
      const exited = new Promise(resolve => sandbox.on('exit', resolve))
      await until('the sandbox to be up', () => existsSync(up))
      writeFileSync(go, '')
      await exited
      expect(said).toContain(BOOTED)
      expect(said).toMatch(/rc=[1-9]/)
      expect(readFileSync(LOCK, 'utf8')).toBe('')

      cleanupBwrapMountPoints()
      expect(existsSync(LOCK)).toBe(false)
      expect(readdirSync(DIR)).toEqual([])
    },
    60000,
  )

  // ---- a command line run again ------------------------------------------------

  /** A process that wrapped nothing, cleaning up. */
  function anotherProcessCleansUp(): void {
    const cleaned = spawnSync(
      process.execPath,
      [
        script('cleaner.ts', [
          `const m = await import(${MODULE})`,
          `m.collectMountPoints('all')`,
        ]),
      ],
      { encoding: 'utf8', timeout: 30000 },
    )
    expect(cleaned.status).toBe(0)
  }

  it.if(BWRAP_CAN_NAMESPACE)(
    'leaves a command line good for another run, with other processes cleaning up in between, until its own process lets go of it',
    async () => {
      const command = await wrap(
        `echo ${BOOTED}; rm -f ${LOCK}; echo pwned > ${LOCK}; echo rc=$?`,
      )
      for (let time = 0; time < 3; time++) {
        const { said } = run(command)
        expect(said).toContain(BOOTED)
        expect(said).toMatch(/rc=[1-9]/)
        anotherProcessCleansUp()
        expect(existsSync(manifestOf(command)!)).toBe(true)
        expect(readFileSync(LOCK, 'utf8')).toBe('')
      }

      cleanupBwrapMountPoints()
      expect(existsSync(LOCK)).toBe(false)
      const refused = run(command)
      expect(refused.status).not.toBe(0)
      expect(refused.said).not.toContain(BOOTED)
      expect(refused.said).toContain("Can't find source path")
      // It made nothing, and the line it put on record goes with the next pass.
      expect(existsSync(LOCK)).toBe(false)
      collectMountPoints('none')
      expect(readdirSync(DIR)).toEqual([])
    },
    60000,
  )

  it.each(['first', 'last'] as const)(
    'asks after every run of a command line that has been run thousands of times: the %s may be the one that lasts',
    which => {
      leftover(LOCK)
      const gone = Array<Process>(3000).fill(aDeadProcess())
      const manifest = manifestOfADeadProcess([LOCK])
      started(
        manifest,
        ...(which === 'first'
          ? [anotherProcess(), ...gone]
          : [...gone, anotherProcess()]),
      )
      expect(collectMountPoints('all')).toEqual([])
      started(manifest, ...gone)
      expect(collectMountPoints('all')).toEqual([LOCK])
    },
  )

  it('takes a record too long to be read to vouch, like any that cannot be read', () => {
    leftover(LOCK)
    const manifest = manifestOfADeadProcess([LOCK])
    started(manifest, aDeadProcess())
    const record = recordOf(manifest)
    const line = fs.readFileSync(record, 'utf8')
    fs.writeFileSync(
      record,
      line.repeat(Math.ceil((4 * 1024 * 1024 + 1) / line.length)),
    )
    expect(collectMountPoints('all')).toEqual([])
    expect(existsSync(LOCK)).toBe(true)
  })

  /** The manifest this process publishes for a wrap that names `paths`. */
  function publish(paths: string[], commandKey?: string): string {
    const manifest = publishMountPointManifest(paths, [], commandKey)
    if (manifest === undefined || manifest === 'too-large') {
      throw new Error(`not published: ${manifest}`)
    }
    return manifest.file
  }

  it('lets go of the commands that have run and ended at every clean-up the caller makes, and of no other', () => {
    const [ended, running, notStarted] = ['ended', 'running', 'waiting'].map(
      name => join(AREA, name),
    ) as [string, string, string]
    for (const mountPoint of [ended, running, notStarted]) leftover(mountPoint)
    started(publish([ended]), aDeadProcess())
    started(publish([running]), anotherProcess())
    publish([notStarted])

    // A wrap of this process that came to nothing says nothing of the others.
    expect(collectMountPoints('none')).toEqual([])
    expect(collectMountPoints('ended')).toEqual([ended])
    expect(collectMountPoints('ended')).toEqual([])
    expect(collectMountPoints('all')).toEqual([notStarted])
    expect(existsSync(running)).toBe(true)
  })

  it('lets go of them along with the command the caller names', () => {
    const [ended, named, other] = ['ended', 'named', 'other'].map(name =>
      join(AREA, name),
    ) as [string, string, string]
    for (const mountPoint of [ended, named, other]) leftover(mountPoint)
    started(publish([ended], 'a'), aDeadProcess())
    publish([named], 'b')
    publish([other], 'c')
    expect(collectMountPoints({ commandKey: 'b' }).sort()).toEqual(
      [ended, named].sort(),
    )
    expect(existsSync(other)).toBe(true)
  })

  // ---- a process that has exited and is not waited for -------------------------

  /** Whether the shell started as `pid` has become the `sleep` it execs. */
  const isSleep = (pid: number): boolean =>
    readFileSync(`/proc/${pid}/comm`, 'utf8') === 'sleep\n'

  it('takes a process that has exited for gone, though nothing has asked after it yet', async () => {
    // The shell starts a child and becomes a program that never waits for one.
    // The child ends only then: a shell may wait for one that ends before.
    const go = join(BASE, 'go')
    const parent = spawn(
      'sh',
      [
        '-c',
        `(while [ ! -e ${go} ]; do sleep 0.02; done) & echo $!; exec sleep 600`,
      ],
      { stdio: ['ignore', 'pipe', 'ignore'] },
    )
    others.push(parent)
    let said = ''
    parent.stdout.on('data', chunk => (said += String(chunk)))
    await until('the pid of the child', () => said.includes('\n'))
    const pid = Number(said)
    await until('the shell to be gone', () => isSleep(parent.pid!))
    writeFileSync(go, '')
    await until('the child to have exited', () =>
      / Z /.test(readFileSync(`/proc/${pid}/stat`, 'utf8')),
    )
    const exited = processAt(pid)

    leftover(LOCK)
    started(manifestOfADeadProcess([LOCK]), exited)
    const pass = passOf(exited)
    expect(passesUnderWay()).toEqual([])
    expect([...(liveMountPoints() ?? [])]).toEqual([])
    expect(collectMountPoints('all')).toEqual([LOCK])
    expect(existsSync(pass)).toBe(false)
    // Still there to be asked after: it is what it says that counts.
    expect(existsSync(`/proc/${pid}`)).toBe(true)
  })

  it.if(BWRAP_CAN_NAMESPACE)(
    'cleans up after a sandbox that was killed and is never waited for',
    async () => {
      // As under a process 1 that reaps nothing: the sandbox is the child of a
      // program that never waits for it.
      const up = join(AREA, 'up')
      const command = await wrap(`echo up > ${up}; sleep 600`)
      const parent = spawn('sh', ['-c', `${command} & exec sleep 600`], {
        stdio: 'ignore',
      })
      others.push(parent)
      await until('the sandbox to be up', () => existsSync(up))
      const record = readFileSync(recordOf(manifestOf(command)!), 'utf8')
      const bwrap = Number(/^\d+/.exec(record)![0])
      cleanupBwrapMountPoints()
      expect(existsSync(LOCK)).toBe(true)

      await until('the shell to be gone', () => isSleep(parent.pid!))
      process.kill(bwrap, 'SIGKILL')
      await until('bubblewrap to have exited', () =>
        / Z /.test(readFileSync(`/proc/${bwrap}/stat`, 'utf8')),
      )
      collectMountPoints('none')
      expect(existsSync(LOCK)).toBe(false)
      expect(readdirSync(DIR)).toEqual([])
    },
    60000,
  )
})
