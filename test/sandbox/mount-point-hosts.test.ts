import { describe, it, expect, beforeEach, afterEach, spyOn } from 'bun:test'
import { type ChildProcess, spawn, spawnSync } from 'node:child_process'
import * as fs from 'node:fs'
import {
  chmodSync,
  existsSync,
  lstatSync,
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
import { basename, dirname, join } from 'node:path'
import {
  collectMountPoints,
  forgetMountPointManifestDirectory,
  liveMountPoints,
  lookAfreshAt,
  mountPointManifestDirectories,
  namedMountPoints,
  otherHostsReach,
  passesToEnd,
  passesUnderWay,
  publishMountPointManifest,
  setMountPointManifestPlacesForTesting,
} from '../../src/sandbox/bwrap-mount-manifests.js'
import {
  cleanupBwrapMountPoints,
  wrapCommandWithSandboxLinux,
} from '../../src/sandbox/linux-sandbox-utils.js'
import { manifestOf } from '../helpers/bwrap-argv.js'
import { bwrapCanNamespace } from '../helpers/bwrap-namespace.js'
import {
  leftover,
  sleep,
  until,
  writeScript,
} from '../helpers/mount-point-fixtures.js'
import { isLinux } from '../helpers/platform.js'
import { makePlaces } from '../helpers/private-manifest-directory.js'

const NFS = 0x6969
const EXT4 = 0xef53
const MINUTE_MS = 60 * 1000

/**
 * A mount point on a file system that several hosts mount is there for all of
 * them, and none can ask after another's processes or read a directory of
 * another's. So a wrap that names one keeps its manifest in the user's home,
 * where that is on such a file system, and there a manifest of another host is
 * live by its age, which its writer keeps low.
 */
describe.if(isLinux)('Mount points that other hosts reach', () => {
  const BWRAP_CAN_NAMESPACE = bwrapCanNamespace()
  const NOT_ROOT = process.getuid?.() !== 0
  const HOST = JSON.stringify(
    join(import.meta.dir, '../helpers/isolated/host.ts'),
  )
  const OWN_NAMESPACE = isLinux ? readlinkSync('/proc/self/ns/pid') : ''
  const OWN_BOOT = isLinux
    ? readFileSync('/proc/sys/kernel/random/boot_id', 'utf8').trim()
    : ''
  const ANOTHER_BOOT = '11111111-2222-3333-4444-555555555555'
  /** Echoed first by every command that runs for real. */
  const BOOTED = 'BOOTED'

  let BASE: string
  let HERE: string // what stands in for `/` on this host
  let PLACES: string[] // this host's own places
  let NETWORK: string // what every host mounts
  let HOME: string // the user's home, on it
  let SHARED: string // where the manifests go that other hosts read
  let PROJECT: string // a project on it
  let LOCK: string // a denyWrite path in that, absent to begin with
  let LOCAL: string // a directory only this host has
  let statfs: { mockRestore(): void }
  let others: ChildProcess[]

  beforeEach(() => {
    BASE = realpathSync(mkdtempSync(join(tmpdir(), 'mount-point-hosts-')))
    HERE = join(BASE, 'here')
    NETWORK = join(BASE, 'network')
    HOME = join(NETWORK, 'home')
    SHARED = join(HOME, '.srt-mount-points')
    PROJECT = join(NETWORK, 'project')
    LOCK = join(PROJECT, 'config.lock')
    LOCAL = join(BASE, 'local')
    for (const dir of [HERE, HOME, PROJECT, LOCAL]) {
      mkdirSync(dir, { recursive: true })
    }
    PLACES = makePlaces(HERE, HOME)
    statfs = networkIs(NFS)
    setMountPointManifestPlacesForTesting(HERE)
    cleanupBwrapMountPoints({ force: true })
    others = []
  })

  afterEach(() => {
    for (const other of others) {
      for (const signal of ['SIGCONT', 'SIGKILL'] as const) {
        try {
          if (other.pid !== undefined) process.kill(other.pid, signal)
        } catch {
          // Gone already.
        }
      }
    }
    cleanupBwrapMountPoints({ force: true })
    statfs.mockRestore()
    setMountPointManifestPlacesForTesting('/nonexistent')
    rmSync(BASE, { recursive: true, force: true })
  })

  /** Has what is under NETWORK be on a file system of that kind. */
  function networkIs(type: number): { mockRestore(): void } {
    return spyOn(fs, 'statfsSync').mockImplementation(((p: unknown) => {
      if (!existsSync(String(p))) {
        throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' })
      }
      // A plan asks through a descriptor it holds.
      const at = String(p).startsWith('/proc/self/fd/')
        ? readlinkSync(String(p))
        : String(p)
      return { type: `${at}/`.startsWith(`${NETWORK}/`) ? type : EXT4 }
    }) as never)
  }

  function aged(file: string, ms: number): string {
    const then = new Date(Date.now() - ms)
    utimesSync(file, then, then)
    return file
  }

  /**
   * As `aged`, of a file this process may have looked at. A manifest's time is
   * only ever set forward, and the library counts on that.
   */
  function setBack(file: string, ms: number): string {
    forgetMountPointManifestDirectory()
    return aged(file, ms)
  }

  /** A manifest another host wrote into the shared directory, just now. */
  function manifestOfAnotherHost(
    paths: string[],
    sources: string[] = [],
  ): string {
    mkdirSync(SHARED, { recursive: true, mode: 0o700 })
    chmodSync(SHARED, 0o700)
    // A pid that is this process's here, and there somebody else's.
    const file = join(
      SHARED,
      `${process.pid}-${Math.random().toString(16).slice(2)}.json`,
    )
    writeFileSync(
      file,
      JSON.stringify({
        version: 1,
        pid: process.pid,
        start: '1',
        ns: OWN_NAMESPACE,
        boot: ANOTHER_BOOT,
        keptYoung: true,
        created: Date.now(),
        paths,
        sources,
      }),
      { mode: 0o600 },
    )
    return file
  }

  /** Publishes for a wrap that names those. Returns the manifests written. */
  function publish(paths: string[], sources: string[] = []): string[] {
    const manifests = publishMountPointManifest(paths, sources)
    if (manifests === 'too-large') throw new Error(manifests)
    return manifests.map(({ file }) => file)
  }

  function named(): string[] | undefined {
    const reading = namedMountPoints()
    return 'inDoubt' in reading ? undefined : [...reading.paths].sort()
  }

  const live = (): string[] => [...(liveMountPoints() ?? ['in doubt'])]

  // ---- where a manifest goes ---------------------------------------------------

  /** What the manifest at `file` names. */
  function namedIn(file: string): { paths: string[]; sources: string[] } {
    const { paths, sources } = JSON.parse(readFileSync(file, 'utf8')) as {
      paths: string[]
      sources: string[]
    }
    return { paths, sources }
  }

  it("keeps a manifest of a wrap that names one in the home directory, beside the one in this host's own first place", () => {
    expect(publish([LOCK]).map(dirname)).toEqual([SHARED, PLACES[0]!])
    expect(lstatSync(SHARED).mode & 0o777).toBe(0o700)
  })

  it("names only what other hosts reach there, and all of it in this host's own first place", () => {
    // Whoever reads a manifest can then remove all it names: what a job left on
    // its own host's disk is not forgotten when another host sweeps the home.
    // And a process of this host that does not see the home (a service kept
    // out of it, a container with another) reads what it always did.
    const [a, b] = [join(LOCAL, 'a'), join(LOCAL, 'b')]
    const source = join(LOCAL, 'empty')
    const [theirsToo, here] = publish([a, LOCK, b], [source])
    expect(dirname(theirsToo!)).toBe(SHARED)
    expect(namedIn(theirsToo!)).toEqual({ paths: [LOCK], sources: [] })
    expect(dirname(here!)).toBe(PLACES[0]!)
    expect(namedIn(here!)).toEqual({ paths: [a, LOCK, b], sources: [source] })
  })

  it("keeps the manifest of a wrap that names none in this host's own first place", () => {
    expect(publish([join(LOCAL, 'config.lock')]).map(dirname)).toEqual([
      PLACES[0]!,
    ])
    expect(existsSync(SHARED)).toBe(false)
  })

  it.if(NOT_ROOT)(
    'has that one alone where the home takes no directory',
    () => {
      chmodSync(HOME, 0o500)
      try {
        const local = join(LOCAL, 'config.lock')
        const [here, ...more] = publish([LOCK, local])
        expect(more).toEqual([])
        expect(dirname(here!)).toBe(PLACES[0]!)
        expect(namedIn(here!).paths).toEqual([LOCK, local])
      } finally {
        chmodSync(HOME, 0o700)
      }
    },
  )

  it('does so too where the directory in the home takes no manifest, as in a home over its quota', () => {
    // A network file system takes the bytes and says so only as they are
    // flushed. Published all the same, an empty file would put every reading on
    // every host in doubt, and then be dropped with nothing naming the path.
    const spy = spyOn(fs, 'fsyncSync').mockImplementation((() => {
      throw Object.assign(new Error('EDQUOT'), { code: 'EDQUOT' })
    }) as never)
    try {
      const [here, ...more] = publish([LOCK])
      expect(more).toEqual([])
      expect(dirname(here!)).toBe(PLACES[0]!)
      expect(namedIn(here!).paths).toEqual([LOCK])
      expect(readdirSync(SHARED)).toEqual([])
    } finally {
      spy.mockRestore()
    }
  })

  it('writes neither of the two when both together are more than one manifest holds', () => {
    const many = Array.from({ length: 12000 }, (_, i) =>
      join(i % 2 ? LOCAL : PROJECT, `${'x'.repeat(80)}${i}`),
    )
    expect(publishMountPointManifest(many, [])).toBe('too-large')
    expect(existsSync(SHARED) ? readdirSync(SHARED) : []).toEqual([])
    expect(existsSync(PLACES[0]!) ? readdirSync(PLACES[0]!) : []).toEqual([])
  })

  it('reads and writes nothing in a home that only this host reaches, and makes nothing there that no command could', () => {
    statfs.mockRestore()
    statfs = networkIs(EXT4)
    forgetMountPointManifestDirectory()
    expect(mountPointManifestDirectories(true)).not.toContain(SHARED)
    expect(publish([LOCK]).map(dirname)).toEqual([PLACES[0]!])
    expect(existsSync(SHARED)).toBe(false)
    // One that is there all the same is nobody's word.
    manifestOfAnotherHost([LOCK])
    leftover(LOCK)
    collectMountPoints('all')
    expect(named()).toEqual([])
  })

  const wrapThatMayWrite = (...allowOnly: string[]): Promise<string> =>
    wrapCommandWithSandboxLinux({
      command: `echo ${BOOTED}; echo x > ${join(SHARED, 'forged.json')}; echo forged=$?`,
      needsNetworkRestriction: false,
      readConfig: { denyOnly: [] },
      writeConfig: { allowOnly, denyWithinAllow: [] },
    })

  it('keeps the directory out of reach there all the same: to the clients of a server, the disk it exports is a network home', async () => {
    statfs.mockRestore()
    statfs = networkIs(EXT4)
    forgetMountPointManifestDirectory()
    // Not there, and not the command's to make.
    expect(await wrapThatMayWrite(LOCAL)).not.toContain(`-try ${SHARED} `)
    expect(existsSync(SHARED)).toBe(false)
    // The command's to make, so it is made first.
    const command = await wrapThatMayWrite(NETWORK)
    expect(lstatSync(SHARED).mode & 0o777).toBe(0o700)
    expect(command).toContain(`--ro-bind-try ${SHARED} ${SHARED}`)
    expect(command).toContain(`--ro-bind ${HOME} ${HOME}`)
    // There, so it is bound, like any other place.
    expect(await wrapThatMayWrite(LOCAL)).toContain(
      `--ro-bind-try ${SHARED} ${SHARED}`,
    )
    // And is nobody's word here for that.
    manifestOfAnotherHost([LOCK])
    expect(named()).toEqual([])
    expect(publish([LOCK]).map(dirname)).toEqual([PLACES[0]!])
  })

  it('asks whether the command could make it of where the home really is, however the user database spells it', async () => {
    statfs.mockRestore()
    statfs = networkIs(EXT4)
    const spelled = join(BASE, 'home-of-user')
    fs.symlinkSync(HOME, spelled)
    makePlaces(HERE, spelled)
    forgetMountPointManifestDirectory()
    const command = await wrapThatMayWrite(HOME)
    expect(lstatSync(SHARED).isDirectory()).toBe(true)
    expect(command).toContain(`--ro-bind-try ${SHARED} ${SHARED}`)
  })

  it.if(BWRAP_CAN_NAMESPACE)(
    'lets no command of such a host write what the others would believe',
    async () => {
      statfs.mockRestore()
      statfs = networkIs(EXT4)
      forgetMountPointManifestDirectory()
      const { said } = run(await wrapThatMayWrite(HOME))
      expect(said).toContain(BOOTED)
      expect(said).toMatch(/forged=[1-9]/)
      expect(readdirSync(SHARED)).toEqual([])
    },
  )

  it.each([NFS, EXT4])(
    'hands out no command while the directory there cannot be looked at: it may be there, and would go unbound (%d)',
    async type => {
      mountPointManifestDirectories()
      statfs.mockRestore()
      statfs = networkIs(type)
      forgetMountPointManifestDirectory()
      const lstat = fs.lstatSync
      const spy = spyOn(fs, 'lstatSync').mockImplementation(((
        file: unknown,
        ...rest: unknown[]
      ) => {
        if (file === SHARED) {
          throw Object.assign(new Error('EIO'), { code: 'EIO' })
        }
        return (lstat as (...args: unknown[]) => unknown)(file, ...rest)
      }) as never)
      try {
        expect(() => mountPointManifestDirectories()).toThrow('EIO')
        const refused = await wrapThatMayWrite(LOCAL).then(
          () => undefined,
          (error: unknown) => error,
        )
        expect((refused as { code?: string }).code).toBe(
          'mount_points_unreadable',
        )
      } finally {
        spy.mockRestore()
      }
    },
  )

  it("hands out none while one of this host's own places cannot be looked at either", async () => {
    mountPointManifestDirectories()
    const lstat = fs.lstatSync
    const spy = spyOn(fs, 'lstatSync').mockImplementation(((
      file: unknown,
      ...rest: unknown[]
    ) => {
      if (file === PLACES[2]) {
        throw Object.assign(new Error('EIO'), { code: 'EIO' })
      }
      return (lstat as (...args: unknown[]) => unknown)(file, ...rest)
    }) as never)
    try {
      expect(() => mountPointManifestDirectories()).toThrow('EIO')
      const refused = await wrapThatMayWrite(LOCAL).then(
        () => undefined,
        (error: unknown) => error,
      )
      expect((refused as { code?: string }).code).toBe(
        'mount_points_unreadable',
      )
    } finally {
      spy.mockRestore()
    }
  })

  /** Has the file system the home is on not say what kind it is. */
  function homeSays(code: string): void {
    statfs.mockRestore()
    statfs = spyOn(fs, 'statfsSync').mockImplementation(((p: unknown) => {
      if (p === HOME) throw Object.assign(new Error(code), { code })
      return { type: EXT4 }
    }) as never)
    forgetMountPointManifestDirectory()
  }

  it.each(['ENOENT', 'EACCES'])(
    'takes a home that is not there, or not to be entered, for no network home, and asks again (%s)',
    code => {
      // No wrap could make a directory in it, so one that a sandboxed command
      // made there later, home and all, would be believed.
      homeSays(code)
      manifestOfAnotherHost([LOCK])
      expect(named()).toEqual([])
      statfs.mockRestore()
      statfs = networkIs(NFS)
      expect(mountPointManifestDirectories()).toContain(SHARED)
      expect(named()).toEqual([LOCK])
    },
  )

  it('hands out no command, and removes nothing, while it cannot tell whether the home is one', async () => {
    // The directory may be there, with what other hosts rely on in it, and the
    // command would find it unbound.
    leftover(LOCK)
    aged(manifestOfAnotherHost([LOCK]), 11 * MINUTE_MS)
    homeSays('EIO')
    expect(named()).toBeUndefined()
    expect(liveMountPoints()).toBeUndefined()
    expect(collectMountPoints('all')).toEqual([])
    const refused = await wrapCommandWithSandboxLinux({
      command: 'true',
      needsNetworkRestriction: false,
      readConfig: { denyOnly: [] },
      writeConfig: { allowOnly: [LOCAL], denyWithinAllow: [] },
    }).then(
      () => undefined,
      (error: unknown) => error,
    )
    expect((refused as { code?: string }).code).toBe('mount_points_unreadable')
    statfs.mockRestore()
    statfs = networkIs(NFS)
    expect(collectMountPoints('all')).toEqual([LOCK])
  })

  it('asks nothing of the home for a wrap that restricts no write', async () => {
    homeSays('EIO')
    expect(
      await wrapCommandWithSandboxLinux({
        command: 'true',
        needsNetworkRestriction: false,
        readConfig: { denyOnly: [LOCAL] },
      }),
    ).toContain(`--tmpfs ${LOCAL}`)
  })

  it('remembers that there is a network home, and never that there is none', () => {
    // What shows until the share is mounted over it is on this host's own disk.
    statfs.mockRestore()
    statfs = networkIs(EXT4)
    forgetMountPointManifestDirectory()
    expect(mountPointManifestDirectories()).not.toContain(SHARED)
    statfs.mockRestore()
    statfs = networkIs(NFS)
    expect(mountPointManifestDirectories()).toContain(SHARED)
    // And a share does not turn into a disk of this host's.
    statfs.mockRestore()
    statfs = networkIs(EXT4)
    expect(mountPointManifestDirectories()).toContain(SHARED)
  })

  it('asks a second time before it gives up on a home that gives an error of the moment', () => {
    let failures = 0
    statfs.mockRestore()
    statfs = spyOn(fs, 'statfsSync').mockImplementation(((p: unknown) => {
      if (p === HOME && failures++ === 0) {
        throw Object.assign(new Error('ESTALE'), { code: 'ESTALE' })
      }
      return { type: `${String(p)}/`.startsWith(`${NETWORK}/`) ? NFS : EXT4 }
    }) as never)
    forgetMountPointManifestDirectory()
    expect(mountPointManifestDirectories()).toContain(SHARED)
    expect(failures).toBeGreaterThan(1)
  })

  it('asks the user database again after a minute when it knew no such user: that is all an outage has it say', () => {
    const passwd = join(HERE, 'etc/passwd')
    const known = readFileSync(passwd, 'utf8')
    writeFileSync(passwd, '')
    forgetMountPointManifestDirectory()
    expect(mountPointManifestDirectories()).not.toContain(SHARED)
    writeFileSync(passwd, known)
    expect(mountPointManifestDirectories()).not.toContain(SHARED)
    const now = performance.now.bind(performance)
    const later = spyOn(performance, 'now').mockImplementation(
      () => now() + MINUTE_MS + 1000,
    )
    try {
      expect(mountPointManifestDirectories()).toContain(SHARED)
    } finally {
      later.mockRestore()
    }
  })

  it('does not take a user database that cannot be read for one that knows no such user', () => {
    const read = fs.readFileSync
    const spy = spyOn(fs, 'readFileSync').mockImplementation(((
      file: unknown,
      ...rest: unknown[]
    ) => {
      if (file === join(HERE, 'etc/passwd')) {
        throw Object.assign(new Error('EMFILE'), { code: 'EMFILE' })
      }
      return (read as (...args: unknown[]) => unknown)(file, ...rest)
    }) as never)
    try {
      forgetMountPointManifestDirectory()
      expect(() => mountPointManifestDirectories()).toThrow('EMFILE')
      expect(named()).toBeUndefined()
      expect(collectMountPoints('all')).toEqual([])
    } finally {
      spy.mockRestore()
    }
  })

  /** Puts a `getent` where the library looks for it, and forgets the user. */
  function getentIs(script: string): void {
    mkdirSync(join(HERE, 'usr/bin'), { recursive: true })
    writeFileSync(join(HERE, 'usr/bin/getent'), `#!/bin/sh\n${script}\n`, {
      mode: 0o755,
    })
    writeFileSync(join(HERE, 'etc/passwd'), '')
    forgetMountPointManifestDirectory()
  }

  it('asks getent for a user that /etc/passwd does not have', () => {
    const uid = process.getuid?.() ?? 0
    getentIs(
      `[ "$*" = "passwd ${uid}" ] && echo "user:x:${uid}:${uid}::${HOME}:/bin/sh"`,
    )
    expect(mountPointManifestDirectories()).toContain(SHARED)
  })

  it('takes its word that there is no such user', () => {
    getentIs('exit 2')
    expect(mountPointManifestDirectories()).not.toContain(SHARED)
  })

  it('does not ask it again at once when it gave no answer: each asking holds up the thread', () => {
    const asked = join(BASE, 'asked')
    getentIs(`echo x >> ${asked}; exit 1`)
    const times = (): number => readFileSync(asked, 'utf8').length / 2
    expect(() => mountPointManifestDirectories()).toThrow('gave no answer')
    expect(() => mountPointManifestDirectories()).toThrow('gave no answer')
    expect(named()).toBeUndefined()
    expect(times()).toBe(1)
    const now = performance.now.bind(performance)
    const later = spyOn(performance, 'now').mockImplementation(
      () => now() + 11_000,
    )
    try {
      expect(() => mountPointManifestDirectories()).toThrow('gave no answer')
      expect(times()).toBe(2)
    } finally {
      later.mockRestore()
    }
  })

  it('goes by the home the user database gives, whatever the environment says', () => {
    const saved = process.env['HOME']
    process.env['HOME'] = join(NETWORK, 'elsewhere')
    mkdirSync(process.env['HOME'])
    try {
      forgetMountPointManifestDirectory()
      expect(publish([LOCK]).map(dirname)).toContain(SHARED)
    } finally {
      if (saved === undefined) delete process.env['HOME']
      else process.env['HOME'] = saved
    }
  })

  it('keeps none there for a user the database does not know', () => {
    writeFileSync(
      join(HERE, 'etc/passwd'),
      'root:x:4294967294:0::/root:/bin/sh\n',
    )
    forgetMountPointManifestDirectory()
    expect(publish([LOCK]).map(dirname)).toEqual([PLACES[0]!])
  })

  it.if(NOT_ROOT)(
    "is no place for what other hosts do not reach, and stands in for none of this host's",
    () => {
      // A read-only image: none of the three can be written, the home can.
      const runtime = join(BASE, 'runtime')
      mkdirSync(runtime, { mode: 0o700 })
      const saved = process.env['XDG_RUNTIME_DIR']
      process.env['XDG_RUNTIME_DIR'] = runtime
      for (const place of PLACES) {
        rmSync(place, { recursive: true, force: true })
        chmodSync(dirname(place), 0o500)
      }
      try {
        forgetMountPointManifestDirectory()
        mountPointManifestDirectories()
        const local = join(LOCAL, 'config.lock')
        expect(publish([local]).map(dirname)).toEqual([
          join(runtime, 'srt-mount-points'),
        ])
        // And what the environment names is still believed.
        expect(named()).toEqual([local])
      } finally {
        for (const [i, place] of PLACES.entries()) {
          chmodSync(dirname(place), i === 1 ? 0o700 : 0o1777)
        }
        collectMountPoints('all')
        if (saved === undefined) delete process.env['XDG_RUNTIME_DIR']
        else process.env['XDG_RUNTIME_DIR'] = saved
      }
    },
  )

  it('has every wrap that restricts writes make the directory, bind it read-only and pin what lies above it', async () => {
    expect(mountPointManifestDirectories()).toContain(SHARED)
    const command = await wrapCommandWithSandboxLinux({
      command: 'true',
      needsNetworkRestriction: false,
      readConfig: { denyOnly: [] },
      writeConfig: { allowOnly: [NETWORK], denyWithinAllow: [] },
    })
    expect(command).toContain(`--ro-bind-try ${SHARED} ${SHARED}`)
    expect(command).toContain(`--ro-bind ${HOME} ${HOME}`)
  })

  it('leaves the directory hidden where a read deny covers the home', async () => {
    const command = await wrapCommandWithSandboxLinux({
      command: 'true',
      needsNetworkRestriction: false,
      readConfig: { denyOnly: [HOME] },
      writeConfig: { allowOnly: [PROJECT], denyWithinAllow: [LOCK] },
    })
    expect(manifestsOf(command).map(dirname)).toContain(SHARED)
    expect(command).toContain(`--tmpfs ${HOME}`)
    expect(command).not.toContain(` ${SHARED} ${SHARED}`)
  })

  /** The manifests of a wrapped command, by the records its shell is given. */
  const manifestsOf = (command: string): string[] =>
    [...command.matchAll(/ (\S+)\.started(?= )/g)].map(([, id]) => `${id}.json`)

  const wrapBoth = (command: string): Promise<string> =>
    wrapCommandWithSandboxLinux({
      command,
      needsNetworkRestriction: false,
      readConfig: { denyOnly: [] },
      writeConfig: {
        allowOnly: [PROJECT, LOCAL],
        denyWithinAllow: [LOCK, join(LOCAL, 'config.lock')],
      },
    })

  const run = (command: string): { status: number | null; said: string } => {
    const r = spawnSync(command, { shell: true, encoding: 'utf8' })
    return { status: r.status, said: `${r.stdout}${r.stderr}` }
  }

  it('has a command that names both kinds bind both manifests before anything else, and put itself on both records', async () => {
    const command = await wrapBoth('true')
    const [theirsToo, here, ...more] = manifestsOf(command)
    expect(more).toEqual([])
    expect([theirsToo, here].map(file => dirname(file!))).toEqual([
      SHARED,
      PLACES[0]!,
    ])
    expect(command).toContain(
      ` --ro-bind / / --ro-bind ${theirsToo} ${theirsToo} --ro-bind ${here} ${here} `,
    )
    for (const dir of [SHARED, PLACES[0]!]) {
      expect(command).toContain(` --ro-bind ${dir} ${dir}`)
    }
  })

  it.if(BWRAP_CAN_NAMESPACE)(
    'runs it with both denied, leaves a line on each record, and removes both mount points afterwards',
    async () => {
      const local = join(LOCAL, 'config.lock')
      const command = await wrapBoth(
        `echo ${BOOTED}; echo x > ${LOCK}; echo a=$?; echo x > ${local}; echo b=$?`,
      )
      const { said } = run(command)
      expect(said).toContain(BOOTED)
      expect(said).toMatch(/a=[1-9]/)
      expect(said).toMatch(/b=[1-9]/)
      for (const manifest of manifestsOf(command)) {
        expect(
          readFileSync(manifest.replace(/json$/, 'started'), 'utf8'),
        ).toMatch(/^\d+ \(.*\n$/)
      }
      expect([LOCK, local].map(p => existsSync(p))).toEqual([true, true])
      cleanupBwrapMountPoints()
      expect([LOCK, local].map(p => existsSync(p))).toEqual([false, false])
      expect(readdirSync(SHARED)).toEqual([])
      expect(readdirSync(PLACES[0]!)).toEqual([])
    },
  )

  it.if(BWRAP_CAN_NAMESPACE).each([0, 1])(
    'refuses it its start once either manifest is claimed (%d)',
    async which => {
      const command = await wrapBoth(`echo ${BOOTED}`)
      const manifest = manifestsOf(command)[which]!
      fs.renameSync(manifest, manifest.replace(/json$/, 'claimed'))
      const { status, said } = run(command)
      expect(status).not.toBe(0)
      expect(said).not.toContain(BOOTED)
      expect(existsSync(LOCK)).toBe(false)
      expect(existsSync(join(LOCAL, 'config.lock'))).toBe(false)
    },
  )

  // ---- what another host's manifest says ---------------------------------------

  it("takes an empty file that another host's manifest names for a mount point, covers it and names it", async () => {
    leftover(LOCK)
    manifestOfAnotherHost([LOCK])
    expect(named()).toEqual([LOCK])
    const command = await wrapCommandWithSandboxLinux({
      command: 'true',
      needsNetworkRestriction: false,
      readConfig: { denyOnly: [] },
      writeConfig: { allowOnly: [PROJECT], denyWithinAllow: [LOCK] },
    })
    expect(command).toContain(`--ro-bind /dev/null ${LOCK}`)
    const own = manifestOf(command)!
    expect(dirname(own)).toBe(SHARED)
    expect(readFileSync(own, 'utf8')).toContain(LOCK)
  })

  it('keeps what it names, though the pid in it is nobody here, or somebody else', () => {
    leftover(LOCK)
    const theirs = manifestOfAnotherHost([LOCK])
    expect(live()).toEqual([LOCK])
    expect(collectMountPoints('all')).toEqual([])
    expect(existsSync(LOCK)).toBe(true)
    expect(existsSync(theirs)).toBe(true)
  })

  it('takes it for left behind once neither it nor its record has been touched for ten minutes', () => {
    leftover(LOCK)
    const theirs = manifestOfAnotherHost([LOCK])
    const record = theirs.replace(/\.json$/, '.started')
    writeFileSync(record, `${process.pid} (bwrap) S\n`, { mode: 0o600 })

    setBack(theirs, 9 * MINUTE_MS)
    setBack(record, 60 * MINUTE_MS)
    expect(collectMountPoints('all')).toEqual([])
    setBack(theirs, 60 * MINUTE_MS)
    setBack(record, 9 * MINUTE_MS)
    expect(collectMountPoints('all')).toEqual([])

    setBack(record, 11 * MINUTE_MS)
    expect(live()).toEqual([])
    expect(collectMountPoints('all')).toEqual([LOCK])
    expect(readdirSync(SHARED)).toEqual([])
  })
  it('goes by it only for what both hosts reach: the same name on this host is another file', () => {
    const mine = join(LOCAL, 'config.lock')
    const source = join(LOCAL, 'claude-empty-abc')
    leftover(mine)
    leftover(LOCK)
    mkdirSync(source, { mode: 0o700 })
    manifestOfAnotherHost([mine, LOCK], [source])
    expect(named()).toEqual([LOCK])
    expect(live()).toEqual([LOCK])
  })

  for (const [what, elsewhere] of [
    ['is another file on this host', (): string => join(LOCAL, 'config.lock')],
    [
      'lies in a directory this host does not have',
      (): string => join(BASE, 'scratch/project/config.lock'),
    ],
  ] as const) {
    it(`leaves one that has grown old to a host that reaches all it names, when some of it ${what}`, () => {
      // Collected from here, the rest would have nothing left to name it.
      leftover(LOCK)
      const theirs = manifestOfAnotherHost([elsewhere(), LOCK])
      aged(theirs, 11 * MINUTE_MS)
      const open = spyOn(fs, 'openSync')
      try {
        expect(collectMountPoints('all')).toEqual([])
        // Nor is it worth a record, which wraps on every host would wait for.
        expect(
          open.mock.calls.filter(([file]) =>
            /\.pass(\.tmp)?$/.test(String(file)),
          ),
        ).toEqual([])
      } finally {
        open.mockRestore()
      }
      expect(existsSync(LOCK)).toBe(true)
      expect(readdirSync(SHARED)).toEqual([basename(theirs)])
      expect(live()).toEqual([])

      // Nothing is kept for it: it is old.
      publish([LOCK])
      expect(collectMountPoints('all')).toEqual([LOCK])
      expect(readdirSync(SHARED)).toEqual([basename(theirs)])

      // No such host has come for seven days.
      leftover(LOCK)
      setBack(theirs, 7 * 24 * 60 * MINUTE_MS + 1000)
      expect(collectMountPoints('all')).toEqual([LOCK])
      expect(readdirSync(SHARED)).toEqual([])
    })
  }

  it.each([
    ['names nothing', (): string[] => [], 11 * MINUTE_MS],
    [
      'names nothing that counts here, once no host has come for it',
      (): string[] => [join(LOCAL, 'config.lock')],
      7 * 24 * 60 * MINUTE_MS + 1000,
    ],
  ] as const)(
    'is rid of one there that %s, and does not claim it and give it back for ever',
    (_, paths, age) => {
      aged(manifestOfAnotherHost(paths()), age)
      expect(collectMountPoints('all')).toEqual([])
      expect(readdirSync(SHARED)).toEqual([])
    },
  )

  it('counts what it names by what this host mounts now, not when it first read it', () => {
    // Read while the share the project is on was not mounted yet.
    statfs.mockRestore()
    statfs = spyOn(fs, 'statfsSync').mockImplementation(((p: unknown) => ({
      type: `${String(p)}/`.startsWith(`${HOME}/`) ? NFS : EXT4,
    })) as never)
    forgetMountPointManifestDirectory()
    leftover(LOCK)
    manifestOfAnotherHost([LOCK])
    expect(named()).toEqual([])
    statfs.mockRestore()
    statfs = networkIs(NFS)
    expect(named()).toEqual([LOCK])
    expect(live()).toEqual([LOCK])
  })

  it('leaves one in any other directory that both hosts read to its own host as well, and goes by all it names till then', () => {
    // A /var/tmp that diskless nodes share. The manifest there names all its
    // wrap relies on, what is on its own host's disk included.
    statfs.mockRestore()
    statfs = spyOn(fs, 'statfsSync').mockImplementation(((p: unknown) => ({
      type: [NETWORK, PLACES[0]!].some(far =>
        `${String(p)}/`.startsWith(`${far}/`),
      )
        ? NFS
        : EXT4,
    })) as never)
    forgetMountPointManifestDirectory()
    mountPointManifestDirectories()
    const mine = join(LOCAL, 'config.lock')
    leftover(mine)
    leftover(LOCK)
    const written = manifestOfAnotherHost([mine, LOCK])
    const theirs = join(PLACES[0]!, basename(written))
    fs.renameSync(written, theirs)
    expect(named()).toEqual([mine, LOCK].sort())
    aged(theirs, 11 * MINUTE_MS)
    expect(collectMountPoints('all')).toEqual([])
    expect(readdirSync(PLACES[0]!)).toEqual([basename(theirs)])
    setBack(theirs, 7 * 24 * 60 * MINUTE_MS + 1000)
    expect(collectMountPoints('all').sort()).toEqual([mine, LOCK].sort())
    expect(readdirSync(PLACES[0]!)).toEqual([])
  })

  it('knows a manifest there for its own where it cannot read which boot this is', () => {
    // By its age, which this process itself keeps low, it would stay for as long
    // as the process runs.
    const read = fs.readFileSync
    const spy = spyOn(fs, 'readFileSync').mockImplementation(((
      file: unknown,
      ...rest: unknown[]
    ) => {
      if (file === '/proc/sys/kernel/random/boot_id') {
        throw Object.assign(new Error('EACCES'), { code: 'EACCES' })
      }
      return (read as (...args: unknown[]) => unknown)(file, ...rest)
    }) as never)
    try {
      forgetMountPointManifestDirectory()
      leftover(LOCK)
      expect(publish([LOCK]).map(dirname)).toContain(SHARED)
      expect(live()).toEqual([LOCK])
      expect(collectMountPoints('all')).toEqual([LOCK])
      expect(readdirSync(SHARED)).toEqual([])
    } finally {
      spy.mockRestore()
      forgetMountPointManifestDirectory()
    }
  })

  it('takes what lies in a directory that has gone from a share for reached all the same', () => {
    // A mount point nested in another, which went first: nothing is left of it
    // to remove, and nothing for another host to come for.
    aged(
      manifestOfAnotherHost([join(PROJECT, 'deep/er/config.lock')]),
      11 * MINUTE_MS,
    )
    expect(collectMountPoints('all')).toEqual([])
    expect(readdirSync(SHARED)).toEqual([])
  })

  it('goes by the age of one of this boot and another PID namespace as well: a container beside this one', () => {
    leftover(LOCK)
    const theirs = manifestOfAnotherHost([LOCK])
    writeFileSync(
      theirs,
      readFileSync(theirs, 'utf8')
        .replace(ANOTHER_BOOT, OWN_BOOT)
        .replace(OWN_NAMESPACE, 'pid:[1]'),
    )
    setBack(theirs, 9 * MINUTE_MS)
    expect(collectMountPoints('all')).toEqual([])
    setBack(theirs, 11 * MINUTE_MS)
    expect(collectMountPoints('all')).toEqual([LOCK])
  })

  it('goes by seven days for one whose writer does not say that it keeps it young', () => {
    // To that writer the directory may be on a file system of its own.
    leftover(LOCK)
    const theirs = manifestOfAnotherHost([LOCK])
    writeFileSync(
      theirs,
      readFileSync(theirs, 'utf8').replace('"keptYoung":true,', ''),
    )
    aged(theirs, 6 * 24 * 60 * MINUTE_MS)
    expect(collectMountPoints('all')).toEqual([])
    setBack(theirs, 7 * 24 * 60 * MINUTE_MS + 1000)
    expect(collectMountPoints('all')).toEqual([LOCK])
  })

  it('goes by ten minutes for one that says so wherever it finds it: to this reader the directory may be on a disk of its own', () => {
    const mine = join(LOCAL, 'config.lock')
    leftover(mine)
    mkdirSync(PLACES[0]!, { recursive: true, mode: 0o700 })
    const theirs = join(PLACES[0]!, basename(manifestOfAnotherHost([mine])))
    fs.renameSync(join(SHARED, basename(theirs)), theirs)
    writeFileSync(
      theirs,
      readFileSync(theirs, 'utf8')
        .replace(ANOTHER_BOOT, OWN_BOOT)
        .replace(OWN_NAMESPACE, 'pid:[1]'),
    )
    aged(theirs, 9 * MINUTE_MS)
    expect(collectMountPoints('all')).toEqual([])
    aged(theirs, 11 * MINUTE_MS)
    expect(collectMountPoints('all')).toEqual([mine])
  })

  it('says in a manifest that other kernels read that it keeps it young, and in no other', () => {
    const [theirsToo, here] = publish([LOCK, join(LOCAL, 'config.lock')])
    expect(JSON.parse(readFileSync(theirsToo!, 'utf8'))).toMatchObject({
      keptYoung: true,
    })
    expect(JSON.parse(readFileSync(here!, 'utf8'))).not.toHaveProperty(
      'keptYoung',
    )
  })

  it('goes by it so too when it arrives while a pass is under way', () => {
    // Kept for another host's file of the same name, this host's own leftover
    // would be dropped from its manifest and stay for good.
    const mine = join(LOCAL, 'config.lock')
    leftover(mine)
    mkdirSync(SHARED, { recursive: true, mode: 0o700 })
    mkdirSync(PLACES[0]!, { recursive: true, mode: 0o700 })
    const left = join(PLACES[0]!, '4194000-0123456789abcdef.json')
    writeFileSync(
      left,
      JSON.stringify({
        version: 1,
        pid: 4194000,
        start: '1',
        ns: OWN_NAMESPACE,
        boot: OWN_BOOT,
        created: 1,
        paths: [mine],
        sources: [],
      }),
      { mode: 0o600 },
    )
    const open = fs.openSync
    let arrived = false
    // The reading a pass decides on has listed every directory by the time it
    // opens what it has found finished.
    const spy = spyOn(fs, 'openSync').mockImplementation(((
      file: unknown,
      ...rest: unknown[]
    ) => {
      if (String(file).endsWith('.finished') && !arrived) {
        arrived = true
        manifestOfAnotherHost([mine])
      }
      return (open as (...args: unknown[]) => number)(file, ...rest)
    }) as never)
    try {
      expect(collectMountPoints('all')).toEqual([mine])
    } finally {
      spy.mockRestore()
    }
    expect(arrived).toBe(true)
  })

  it('asks after a process as ever when the manifest there is of this boot', () => {
    leftover(LOCK)
    const theirs = manifestOfAnotherHost([LOCK])
    writeFileSync(
      theirs,
      readFileSync(theirs, 'utf8')
        .replace(ANOTHER_BOOT, OWN_BOOT)
        .replace(/"created":\d+/, '"created":1'),
    )
    // Its writer has this process's pid and another start time: gone.
    expect(collectMountPoints('all')).toEqual([LOCK])
  })

  it('keeps nothing for one that its own host has found finished, and leaves that one to its host', () => {
    const other = join(PROJECT, 'other.lock')
    leftover(LOCK)
    leftover(other)
    const theirs = manifestOfAnotherHost([LOCK, other])
    const finished = theirs.replace(/json$/, 'finished')
    fs.renameSync(theirs, finished)
    publish([LOCK])
    expect(named()).toEqual([LOCK, other].sort())
    expect(live()).toEqual([LOCK])
    expect(collectMountPoints('all')).toEqual([LOCK])
    // That host is at it.
    expect(existsSync(other)).toBe(true)
    expect(readdirSync(SHARED)).toEqual([basename(finished)])
    setBack(finished, 11 * MINUTE_MS)
    expect(collectMountPoints('all')).toEqual([other])
    expect(readdirSync(SHARED)).toEqual([])
  })

  it('keeps what one names that its own host has only claimed: a sandbox may have got past the claim', () => {
    leftover(LOCK)
    const theirs = manifestOfAnotherHost([LOCK])
    const claim = theirs.replace(/json$/, 'claimed')
    fs.renameSync(theirs, claim)
    publish([LOCK])
    expect(collectMountPoints('all')).toEqual([])
    expect(existsSync(LOCK)).toBe(true)
    expect(readdirSync(SHARED)).toEqual([basename(claim)])
  })

  // ---- round trips -----------------------------------------------------------------

  /** Which files under SHARED are opened while `what` runs. */
  function opened(what: () => void): string[] {
    const open = spyOn(fs, 'openSync')
    try {
      what()
      return open.mock.calls
        .map(([file]) => String(file))
        .filter(file => file === SHARED || dirname(file) === SHARED)
    } finally {
      open.mockRestore()
    }
  }

  it('reads a manifest there once, and follows it by its name from then on', () => {
    leftover(LOCK)
    const theirs = manifestOfAnotherHost([LOCK])
    expect(opened(() => expect(named()).toEqual([LOCK]))).toEqual([theirs])
    expect(opened(() => expect(named()).toEqual([LOCK]))).toEqual([])
    expect(opened(() => expect(live()).toEqual([LOCK]))).toEqual([])
    const finished = theirs.replace(/json$/, 'finished')
    fs.renameSync(theirs, finished)
    expect(opened(() => expect(live()).toEqual([]))).toEqual([])
    expect(opened(() => expect(named()).toEqual([LOCK]))).toEqual([])
    // Forgotten with its name: what comes to that name later is read.
    rmSync(finished)
    expect(named()).toEqual([])
    writeFileSync(theirs, 'not a manifest', { mode: 0o600 })
    expect(named()).toBeUndefined()
  })

  it('asks once what file system a directory that other hosts reach is on, and every time of one of its own', () => {
    const asked = (): string[] =>
      (statfs as unknown as { mock: { calls: unknown[][] } }).mock.calls.map(
        ([dir]) => String(dir),
      )
    mountPointManifestDirectories()
    forgetMountPointManifestDirectory()
    ;(statfs as unknown as { mockClear(): void }).mockClear()
    publish([LOCK, join(LOCAL, 'config.lock')])
    named()
    named()
    expect(asked().filter(dir => dir === PROJECT)).toHaveLength(1)
    expect(asked().filter(dir => dir === SHARED)).toHaveLength(1)
    expect(asked().filter(dir => dir === PLACES[0]).length).toBeGreaterThan(1)
  })

  it('asks again after a minute: a share can be unmounted, and what is named there is then not for this host to collect', () => {
    leftover(LOCK)
    const theirs = aged(manifestOfAnotherHost([LOCK]), 11 * MINUTE_MS)
    expect(named()).toEqual([LOCK])
    // What shows in its place is this host's own disk.
    statfs.mockRestore()
    statfs = spyOn(fs, 'statfsSync').mockImplementation(((p: unknown) => ({
      type: `${String(p)}/`.startsWith(`${HOME}/`) ? NFS : EXT4,
    })) as never)
    const now = performance.now.bind(performance)
    const later = spyOn(performance, 'now').mockImplementation(
      () => now() + MINUTE_MS + 1000,
    )
    try {
      expect(named()).toEqual([])
      expect(collectMountPoints('all')).toEqual([])
    } finally {
      later.mockRestore()
    }
    expect(existsSync(LOCK)).toBe(true)
    expect(readdirSync(SHARED)).toEqual([basename(theirs)])
  })

  it('asks once in a reading what file system a directory of its own is on, however many paths in it are named', () => {
    manifestOfAnotherHost(
      Array.from({ length: 20 }, (_, i) => join(LOCAL, `config${i}.lock`)),
    )
    named()
    const asked = statfs as unknown as {
      mockClear(): void
      mock: { calls: unknown[][] }
    }
    asked.mockClear()
    expect(named()).toEqual([])
    expect(asked.mock.calls.filter(([dir]) => dir === LOCAL).length).toBe(1)
  })

  it('reads again when one that it remembers is listed at two of its names: it was renamed meanwhile', () => {
    // Taken at both, the name it has left would keep what it names and the one
    // it has come to would be dropped for that, with nothing removed.
    leftover(LOCK)
    const [mine] = publish([LOCK])
    expect(named()).toEqual([LOCK])
    const readdir = fs.readdirSync
    let listings = 0
    const spy = spyOn(fs, 'readdirSync').mockImplementation(((
      dir: unknown,
      options: unknown,
    ) => {
      const names = (readdir as (d: unknown, o: unknown) => string[])(
        dir,
        options,
      )
      return dir === SHARED && listings++ === 0
        ? [...names, basename(mine!).replace(/json$/, 'finished')]
        : names
    }) as never)
    try {
      expect(named()).toEqual([LOCK])
      expect(listings).toBeGreaterThan(1)
    } finally {
      spy.mockRestore()
    }
  })

  it('looks at a manifest of another host again only when it could have grown old', () => {
    // Every pass judges every manifest of every host, and a look is a round
    // trip. Its time is only ever set forward.
    leftover(LOCK)
    const theirs = aged(manifestOfAnotherHost([LOCK]), 2 * MINUTE_MS)
    const looks = (what: () => void): number => {
      const lstat = spyOn(fs, 'lstatSync')
      try {
        what()
        return lstat.mock.calls.filter(([file]) => file === theirs).length
      } finally {
        lstat.mockRestore()
      }
    }
    expect(looks(() => expect(live()).toEqual([LOCK]))).toBe(1)
    expect(looks(() => expect(live()).toEqual([LOCK]))).toBe(0)
    expect(looks(() => collectMountPoints('all'))).toBe(0)
    const now = performance.now.bind(performance)
    const date = Date.now.bind(Date)
    const later = [
      spyOn(performance, 'now').mockImplementation(
        () => now() + 8 * MINUTE_MS + 1000,
      ),
      spyOn(Date, 'now').mockImplementation(
        () => date() + 8 * MINUTE_MS + 1000,
      ),
    ]
    try {
      expect(looks(() => expect(live()).toEqual([]))).toBe(1)
    } finally {
      later.forEach(spy => spy.mockRestore())
    }
  })

  it('reads one that is at two of its names for good at both in the end, and is rid of it', () => {
    // A copy, a restored snapshot. In doubt for ever, it would refuse every wrap
    // on every host.
    leftover(LOCK)
    const theirs = aged(manifestOfAnotherHost([LOCK]), 11 * MINUTE_MS)
    const claim = theirs.replace(/json$/, 'claimed')
    fs.copyFileSync(theirs, claim)
    aged(claim, 11 * MINUTE_MS)
    expect(named()).toEqual([LOCK])
    expect(collectMountPoints('all')).toEqual([LOCK])
    expect(readdirSync(SHARED)).toEqual([])
  })

  it("reads one in this host's own places every time", () => {
    const [mine] = publish([join(LOCAL, 'config.lock')])
    const open = spyOn(fs, 'openSync')
    try {
      named()
      named()
      expect(open.mock.calls.filter(([file]) => file === mine).length).toBe(2)
    } finally {
      open.mockRestore()
    }
  })

  it.each(['openSync', 'fstatSync', 'readFileSync'] as const)(
    'takes a manifest that another host removes while it is read for gone, not for unreadable (%s)',
    call => {
      leftover(LOCK)
      const theirs = manifestOfAnotherHost([LOCK])
      const open = fs.openSync as (...args: unknown[]) => number
      const real = fs[call] as (...args: unknown[]) => unknown
      let fd: number | undefined
      // What a network file system says of a file the server no longer has.
      const stale = (): never => {
        rmSync(theirs)
        throw Object.assign(new Error('ESTALE'), { code: 'ESTALE' })
      }
      const spies: { mockRestore(): void }[] = [
        spyOn(fs, 'openSync').mockImplementation(((
          file: unknown,
          ...rest: unknown[]
        ) => {
          if (file !== theirs) return open(file, ...rest)
          return call === 'openSync' ? stale() : (fd = open(file, ...rest))
        }) as never),
      ]
      if (call !== 'openSync') {
        spies.push(
          spyOn(fs, call).mockImplementation(((
            what: unknown,
            ...rest: unknown[]
          ) => (what === fd ? stale() : real(what, ...rest))) as never),
        )
      }
      try {
        expect(named()).toEqual([])
      } finally {
        spies.forEach(spy => spy.mockRestore())
      }
    },
  )

  it('takes a record that cannot be read for that reason to vouch, like any that cannot be read', () => {
    // For a manifest "gone" only starts the reading over. For a record it would
    // lift the deny from under a running sandbox.
    leftover(LOCK)
    const [mine] = publish([LOCK])
    const record = mine!.replace(/json$/, 'started')
    writeFileSync(record, readFileSync('/proc/self/stat', 'utf8'), {
      mode: 0o600,
    })
    const open = fs.openSync
    const spy = spyOn(fs, 'openSync').mockImplementation(((
      file: unknown,
      ...rest: unknown[]
    ) => {
      if (file === record) {
        throw Object.assign(new Error('ESTALE'), { code: 'ESTALE' })
      }
      return (open as (...args: unknown[]) => number)(file, ...rest)
    }) as never)
    try {
      expect(collectMountPoints('all')).toEqual([])
    } finally {
      spy.mockRestore()
    }
    expect(existsSync(LOCK)).toBe(true)
    expect(existsSync(mine!)).toBe(true)
    rmSync(record)
    expect(collectMountPoints('all')).toEqual([LOCK])
  })

  it('judges afresh when a manifest it remembers has gone from its name by the time it looks at it', () => {
    // A third host is collecting what a dead one left. It has kept LOCK for this
    // host's manifest, which was live then, and drops the one it claimed. Kept
    // for that one in turn, LOCK would be left to nobody.
    leftover(LOCK)
    const left = manifestOfAnotherHost([LOCK])
    const theirs = left.replace(/json$/, 'claimed')
    fs.renameSync(left, theirs)
    aged(theirs, 11 * MINUTE_MS)
    expect(named()).toEqual([LOCK])
    publish([LOCK])
    const lstat = fs.lstatSync
    const spy = spyOn(fs, 'lstatSync').mockImplementation(((
      file: unknown,
      ...rest: unknown[]
    ) => {
      // On record by then: the look of the reading it decides on.
      if (
        file === theirs &&
        readdirSync(SHARED).some(name => name.endsWith('.pass'))
      ) {
        rmSync(theirs, { force: true })
      }
      return (lstat as (...args: unknown[]) => unknown)(file, ...rest)
    }) as never)
    try {
      expect(collectMountPoints('all')).toEqual([LOCK])
    } finally {
      spy.mockRestore()
    }
    expect(readdirSync(SHARED)).toEqual([])
  })

  it.each([
    ['in the home', (): string => SHARED],
    ["in this host's own place, of another PID namespace", () => PLACES[0]!],
  ] as const)(
    'reads again, when asked what is live, if one %s has gone from its name by the time it looks at it',
    (_, dir) => {
      // Its host has claimed it, and will give it back: a sandbox is on its
      // record. In doubt, whoever asked would have to take every path for live.
      leftover(LOCK)
      const written = manifestOfAnotherHost([LOCK])
      const theirs = join(dir(), basename(written))
      mkdirSync(dir(), { recursive: true, mode: 0o700 })
      writeFileSync(
        theirs,
        readFileSync(written, 'utf8')
          .replace(ANOTHER_BOOT, OWN_BOOT)
          .replace(OWN_NAMESPACE, 'pid:[1]'),
        { mode: 0o600 },
      )
      if (theirs !== written) rmSync(written)
      let read = false
      let moved = false
      const open = fs.openSync
      const lstat = fs.lstatSync
      const spies = [
        spyOn(fs, 'openSync').mockImplementation(((
          file: unknown,
          ...rest: unknown[]
        ) => {
          read ||= file === theirs
          return (open as (...args: unknown[]) => number)(file, ...rest)
        }) as never),
        spyOn(fs, 'lstatSync').mockImplementation(((
          file: unknown,
          ...rest: unknown[]
        ) => {
          if (file === theirs && read && !moved) {
            moved = true
            fs.renameSync(theirs, theirs.replace(/json$/, 'claimed'))
          }
          return (lstat as (...args: unknown[]) => unknown)(file, ...rest)
        }) as never),
      ]
      try {
        expect(live()).toEqual([LOCK])
      } finally {
        spies.forEach(spy => spy.mockRestore())
      }
      expect(moved).toBe(true)
    },
  )

  it('asks no more of the directory there, once it is as it should be, than whether it is', () => {
    mountPointManifestDirectories()
    const mkdir = spyOn(fs, 'mkdirSync')
    try {
      expect(opened(() => mountPointManifestDirectories())).toEqual([])
      expect(mkdir.mock.calls.map(([dir]) => dir)).not.toContain(SHARED)
    } finally {
      mkdir.mockRestore()
    }
    // One that is not is still put right.
    chmodSync(SHARED, 0o755)
    mountPointManifestDirectories()
    expect(lstatSync(SHARED).mode & 0o777).toBe(0o700)
  })

  // ---- kept young ----------------------------------------------------------------

  /** Captures the timer the library sets, to run it by hand. */
  function timers(): {
    ticks: (() => void)[]
    unrefs: number
    cleared: number
    restore(): void
  } {
    const state = { ticks: [] as (() => void)[], unrefs: 0, cleared: 0 }
    const spies = [
      spyOn(globalThis, 'setInterval').mockImplementation(((
        tick: () => void,
      ) => {
        state.ticks.push(tick)
        return { unref: () => state.unrefs++ }
      }) as never),
      spyOn(globalThis, 'clearInterval').mockImplementation((() => {
        state.cleared++
      }) as never),
    ]
    return Object.assign(state, {
      restore: () => spies.forEach(spy => spy.mockRestore()),
    })
  }

  it("has its time set by this host's clock before it is published, whatever the server's says", () => {
    const close = fs.closeSync
    const rename = fs.renameSync
    let ageWhenPublished: number | undefined
    const spies = [
      spyOn(fs, 'closeSync').mockImplementation(((fd: number) => {
        close(fd)
        // A server an hour behind.
        for (const name of readdirSync(SHARED)) {
          if (name.endsWith('.tmp')) aged(join(SHARED, name), 60 * MINUTE_MS)
        }
      }) as never),
      spyOn(fs, 'renameSync').mockImplementation(((
        from: string,
        to: string,
      ) => {
        if (dirname(to) === SHARED) {
          ageWhenPublished = Date.now() - lstatSync(from).mtimeMs
        }
        rename(from, to)
      }) as never),
    ]
    try {
      publish([LOCK])
    } finally {
      spies.forEach(spy => spy.mockRestore())
    }
    expect(ageWhenPublished).toBeLessThan(MINUTE_MS)
  })

  const isYoung = (file: string): boolean =>
    Date.now() - lstatSync(file).mtimeMs < MINUTE_MS

  it('has its time set again every minute for as long as its process knows of it, on a timer that keeps no process alive', async () => {
    const timer = timers()
    try {
      const [manifest] = publish([LOCK])
      expect(timer.ticks).toHaveLength(1)
      expect(timer.unrefs).toBe(1)
      publish([join(PROJECT, 'second.lock')])
      expect(timer.ticks).toHaveLength(1)

      aged(manifest!, 5 * MINUTE_MS)
      timer.ticks[0]!()
      await until('its time to be set', () => isYoung(manifest!))
      expect(timer.cleared).toBe(0)

      collectMountPoints('all')
      expect(readdirSync(SHARED)).toEqual([])
      timer.ticks[0]!()
      expect(timer.cleared).toBe(1)
    } finally {
      timer.restore()
    }
  })

  it('does not wait for the server on that timer: nobody has asked for anything when it runs', () => {
    const timer = timers()
    const waits = spyOn(fs, 'utimesSync')
    try {
      publish([LOCK])
      waits.mockClear()
      timer.ticks[0]!()
      expect(waits).not.toHaveBeenCalled()
    } finally {
      waits.mockRestore()
      timer.restore()
    }
  })

  it('goes on after a tick that failed: the next may do', async () => {
    const timer = timers()
    const utimes = fs.utimes
    const spy = spyOn(fs, 'utimes').mockImplementation(((
      ...args: unknown[]
    ) => {
      ;(args.at(-1) as (e: Error) => void)(
        Object.assign(new Error('EIO'), { code: 'EIO' }),
      )
    }) as never)
    try {
      const [manifest] = publish([LOCK])
      aged(manifest!, 5 * MINUTE_MS)
      timer.ticks[0]!()
      expect(timer.cleared).toBe(0)
      spy.mockImplementation(utimes as never)
      timer.ticks[0]!()
      await until('its time to be set', () => isYoung(manifest!))
    } finally {
      spy.mockRestore()
      timer.restore()
    }
  })

  it('has one request under way at a time, and starts no tick while the last is at it', () => {
    // A server that does not answer then ties up one thread of the pool these
    // requests run on, and not all of them.
    const timer = timers()
    const pending: (() => void)[] = []
    const spy = spyOn(fs, 'utimes').mockImplementation(((
      ...args: unknown[]
    ) => {
      pending.push(() => (args.at(-1) as (e: null) => void)(null))
    }) as never)
    try {
      publish([LOCK])
      publish([join(PROJECT, 'second.lock')])
      timer.ticks[0]!()
      expect(pending).toHaveLength(1)
      timer.ticks[0]!()
      expect(pending).toHaveLength(1)
      pending.shift()!()
      expect(pending).toHaveLength(1)
      pending.shift()!()
      expect(pending).toHaveLength(0)
      timer.ticks[0]!()
      expect(pending).toHaveLength(1)
    } finally {
      spy.mockRestore()
      timer.restore()
    }
  })

  it('keeps it young at the name of a claim too: a pass that finds a sandbox gives it back', async () => {
    const timer = timers()
    try {
      const [manifest] = publish([LOCK])
      const claim = manifest!.replace(/json$/, 'claimed')
      fs.renameSync(manifest!, claim)
      aged(claim, 5 * MINUTE_MS)
      timer.ticks[0]!()
      await until('its time to be set', () => isYoung(claim))
      expect(timer.cleared).toBe(0)
    } finally {
      timer.restore()
    }
  })

  it('sets no timer for a manifest that only this host reads', () => {
    const timer = timers()
    try {
      publish([join(LOCAL, 'config.lock')])
      expect(timer.ticks).toEqual([])
    } finally {
      timer.restore()
    }
  })

  // ---- clean-ups on record ---------------------------------------------------------

  /** Puts a pass of another host on record. */
  function passOfAnotherHost(): string {
    mkdirSync(SHARED, { recursive: true, mode: 0o700 })
    const file = join(
      SHARED,
      `${process.pid}-1-${/\d+/.exec(OWN_NAMESPACE)![0]}-${ANOTHER_BOOT.replace(/-/g, '')}-0123456789abcdef.pass`,
    )
    writeFileSync(file, '', { mode: 0o600 })
    return file
  }

  it("goes by the age of another host's, whose process cannot be asked after", () => {
    const pass = passOfAnotherHost()
    expect(passesUnderWay()).toEqual([pass])
    aged(pass, 40_000)
    expect(passesUnderWay()).toEqual([pass])
    aged(pass, 80_000)
    expect(passesUnderWay()).toEqual([])
    // And leaves its record to its own host.
    collectMountPoints('all')
    expect(existsSync(pass)).toBe(true)
  })

  it('is of no concern to a wrap that names nothing other hosts reach', async () => {
    const pass = passOfAnotherHost()
    expect(passesUnderWay(false)).toEqual([])
    const wrap = (deny: string, allow: string): Promise<string> =>
      wrapCommandWithSandboxLinux({
        command: 'true',
        needsNetworkRestriction: false,
        readConfig: { denyOnly: [] },
        writeConfig: { allowOnly: [allow], denyWithinAllow: [deny] },
      })
    // Held up by it, it would be refused.
    await wrap(join(LOCAL, 'config.lock'), LOCAL)
    // As one that does is.
    const refused = await wrap(LOCK, PROJECT).then(
      () => undefined,
      (error: unknown) => error,
    )
    expect((refused as { code?: string }).code).toBe('mount_points_changed')
    expect((refused as { cause?: unknown }).cause).toBe(pass)
  }, 15000)

  it("puts its own on record in the home directory as well, with its time set by this host's clock", () => {
    leftover(LOCK)
    aged(manifestOfAnotherHost([LOCK]), 11 * MINUTE_MS)
    const unlink = fs.unlinkSync
    const utimes = spyOn(fs, 'utimesSync')
    let onRecord: string[] = []
    const spy = spyOn(fs, 'unlinkSync').mockImplementation(((file: string) => {
      if (file === LOCK) {
        onRecord = [SHARED, ...PLACES].flatMap(dir =>
          existsSync(dir)
            ? readdirSync(dir)
                .filter(name => name.endsWith('.pass'))
                .map(() => dir)
            : [],
        )
      }
      unlink(file)
    }) as never)
    try {
      expect(collectMountPoints('all')).toEqual([LOCK])
      expect(onRecord).toContain(SHARED)
      expect(
        utimes.mock.calls
          .map(([file]) => String(file))
          .filter(file => file.endsWith('.pass.tmp'))
          .map(dirname),
      ).toEqual([SHARED])
    } finally {
      spy.mockRestore()
      utimes.mockRestore()
    }
  })

  it("has it come to its name there with its time set already, whatever the server's clock says", () => {
    // Listed with the time of a server two minutes behind, it would be taken
    // for overdue by a wrap on another host, which would not wait for it.
    leftover(LOCK)
    aged(manifestOfAnotherHost([LOCK]), 11 * MINUTE_MS)
    const close = fs.closeSync
    let stamped = false
    let agesAtItsName: number[] = []
    const look = (): void => {
      agesAtItsName = [
        ...agesAtItsName,
        ...readdirSync(SHARED)
          .filter(name => name.endsWith('.pass'))
          .map(name => Date.now() - lstatSync(join(SHARED, name)).mtimeMs),
      ]
    }
    const rename = fs.renameSync
    const spies = [
      spyOn(fs, 'closeSync').mockImplementation(((fd: number) => {
        close(fd)
        for (const name of readdirSync(SHARED)) {
          if (/\.pass(\.tmp)?$/.test(name) && !stamped) {
            stamped = true
            aged(join(SHARED, name), 2 * MINUTE_MS)
          }
        }
        look()
      }) as never),
      spyOn(fs, 'renameSync').mockImplementation(((
        from: string,
        to: string,
      ) => {
        rename(from, to)
        look()
      }) as never),
    ]
    try {
      expect(collectMountPoints('all')).toEqual([LOCK])
    } finally {
      spies.forEach(spy => spy.mockRestore())
    }
    expect(agesAtItsName.length).toBeGreaterThan(0)
    expect(Math.max(...agesAtItsName)).toBeLessThan(MINUTE_MS)
  })

  /** Has the clock go on by `ms` whenever `held` is called. */
  function aClockThatIsHeldUp(): {
    heldUpFor(ms: number): void
    mockRestore(): void
  } {
    const now = performance.now.bind(performance)
    let lost = 0
    const spy = spyOn(performance, 'now').mockImplementation(() => now() + lost)
    return {
      heldUpFor: ms => {
        lost += ms
      },
      mockRestore: () => spy.mockRestore(),
    }
  }

  it('counts what the server takes to put its record at its name as time it has had: others go by the age of that', () => {
    leftover(LOCK)
    aged(manifestOfAnotherHost([LOCK]), 11 * MINUTE_MS)
    const clock = aClockThatIsHeldUp()
    const rename = fs.renameSync
    const spy = spyOn(fs, 'renameSync').mockImplementation(((
      from: string,
      to: string,
    ) => {
      rename(from, to)
      if (to.endsWith('.pass') && dirname(to) === SHARED) clock.heldUpFor(3000)
    }) as never)
    try {
      expect(collectMountPoints('all')).toEqual([])
    } finally {
      spy.mockRestore()
      clock.mockRestore()
    }
    expect(existsSync(LOCK)).toBe(true)
    expect(collectMountPoints('all')).toEqual([LOCK])
  })

  it('looks at the clock after its last listing, not before: that waits for the server too', () => {
    leftover(LOCK)
    aged(manifestOfAnotherHost([LOCK]), 11 * MINUTE_MS)
    const clock = aClockThatIsHeldUp()
    const readdir = fs.readdirSync
    let onRecord = 0
    const spy = spyOn(fs, 'readdirSync').mockImplementation(((
      dir: unknown,
      ...rest: unknown[]
    ) => {
      const names = (readdir as (...args: unknown[]) => string[])(dir, ...rest)
      // The reading it decides on, and then the one before the removal.
      if (
        dir === SHARED &&
        names.some(name => name.endsWith('.pass')) &&
        ++onRecord === 2
      ) {
        clock.heldUpFor(3000)
      }
      return names
    }) as never)
    try {
      expect(collectMountPoints('all')).toEqual([])
    } finally {
      spy.mockRestore()
      clock.mockRestore()
    }
    expect(onRecord).toBe(2)
    expect(existsSync(LOCK)).toBe(true)
  })

  it('takes its fresh look directory by directory as it goes, and removes what it has the time for', () => {
    // All of them first, a slow server would have every pass use up its time on
    // that and none remove anything.
    const second = join(NETWORK, 'second')
    mkdirSync(second)
    const locks = [LOCK, join(second, 'config.lock')]
    locks.forEach(leftover)
    aged(manifestOfAnotherHost(locks), 11 * MINUTE_MS)
    const clock = aClockThatIsHeldUp()
    const open = fs.openSync
    const spy = spyOn(fs, 'openSync').mockImplementation(((
      file: unknown,
      ...rest: unknown[]
    ) => {
      if (file === PROJECT || file === second) clock.heldUpFor(1500)
      return (open as (...args: unknown[]) => number)(file, ...rest)
    }) as never)
    try {
      expect(collectMountPoints('all').length).toBe(1)
    } finally {
      spy.mockRestore()
      clock.mockRestore()
    }
    expect(collectMountPoints('all').length).toBe(1)
    expect(locks.map(lock => existsSync(lock))).toEqual([false, false])
    expect(readdirSync(SHARED)).toEqual([])
  })

  it('has a wrap that waits for one of another host look a few times a second, not twenty', async () => {
    const pass = passOfAnotherHost()
    const readdir = spyOn(fs, 'readdirSync')
    try {
      expect(await passesToEnd([pass], undefined, 1000)).toBe(pass)
      expect(
        readdir.mock.calls.filter(([dir]) => dir === SHARED).length,
      ).toBeLessThan(16)
    } finally {
      readdir.mockRestore()
    }
  })

  it("lists this host's own places before every removal all the same, and the home by a time of its own", () => {
    // A pass that no wrap can see has nothing else to keep what is published
    // after its reading.
    const locks = ['a', 'b', 'c'].map(name => join(PROJECT, `${name}.lock`))
    locks.forEach(leftover)
    aged(manifestOfAnotherHost(locks), 11 * MINUTE_MS)
    mountPointManifestDirectories(true)
    const unlink = fs.unlinkSync
    const readdir = spyOn(fs, 'readdirSync')
    // No time passes, so that none of this depends on how fast it runs.
    const at = performance.now()
    const clock = spyOn(performance, 'now').mockImplementation(() => at)
    const listedBefore: Record<string, number>[] = []
    const spy = spyOn(fs, 'unlinkSync').mockImplementation(((file: string) => {
      if (locks.includes(file)) {
        const of = (dir: string): number =>
          readdir.mock.calls.filter(([listed]) => listed === dir).length
        listedBefore.push({ own: of(PLACES[0]!), home: of(SHARED) })
      }
      unlink(file)
    }) as never)
    try {
      expect(collectMountPoints('all').sort()).toEqual(locks)
    } finally {
      spy.mockRestore()
      readdir.mockRestore()
      clock.mockRestore()
    }
    const [first, , last] = listedBefore
    expect(last!['own']! - first!['own']!).toBe(2)
    expect(last!['home']! - first!['home']!).toBe(0)
  })

  it('sets the directory in the home right before it reads, as a wrap does: opened up, it would be passed over', () => {
    // `chmod -R g+rX ~`. What another host relies on would go unread.
    leftover(LOCK)
    manifestOfAnotherHost([LOCK])
    publish([LOCK])
    chmodSync(SHARED, 0o755)
    expect(collectMountPoints('all')).toEqual([])
    expect(existsSync(LOCK)).toBe(true)
    expect(lstatSync(SHARED).mode & 0o777).toBe(0o700)
  })

  it("still removes what is this host's alone where the home takes no record, and nothing that other hosts reach", () => {
    // A home over its quota. Placeholders would else pile up in every project
    // on every host that shares it.
    const mine = join(LOCAL, 'config.lock')
    leftover(mine)
    leftover(LOCK)
    publish([mine, LOCK])
    const open = fs.openSync
    const spy = spyOn(fs, 'openSync').mockImplementation(((
      file: unknown,
      ...rest: unknown[]
    ) => {
      if (
        /\.pass(\.tmp)?$/.test(String(file)) &&
        dirname(String(file)) === SHARED
      ) {
        throw Object.assign(new Error('EDQUOT'), { code: 'EDQUOT' })
      }
      return (open as (...args: unknown[]) => number)(file, ...rest)
    }) as never)
    try {
      expect(collectMountPoints('all')).toEqual([mine])
    } finally {
      spy.mockRestore()
    }
    expect(existsSync(LOCK)).toBe(true)
    expect(named()).toEqual([LOCK])
    expect(readdirSync(PLACES[0]!)).toEqual([])
    expect(collectMountPoints('all')).toEqual([LOCK])
  })

  it("removes nothing that other hosts reach off the record in the home, though a manifest of this host's own names it", () => {
    // Recorded there because the home took no manifest either.
    leftover(LOCK)
    const full = (file: unknown): void => {
      if (dirname(String(file)) === SHARED) {
        throw Object.assign(new Error('EDQUOT'), { code: 'EDQUOT' })
      }
    }
    const open = fs.openSync
    const write = fs.writeFileSync
    const spies = [
      spyOn(fs, 'openSync').mockImplementation(((
        file: unknown,
        flags: unknown,
        ...rest: unknown[]
      ) => {
        if (flags === 'wx') full(file)
        return (open as (...args: unknown[]) => number)(file, flags, ...rest)
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
      expect(publish([LOCK]).map(dirname)).toEqual([PLACES[0]!])
      expect(collectMountPoints('all')).toEqual([])
      expect(existsSync(LOCK)).toBe(true)
      expect(named()).toEqual([LOCK])
    } finally {
      spies.forEach(spy => spy.mockRestore())
    }
    expect(collectMountPoints('all')).toEqual([LOCK])
  })

  it('goes on no record in the home for what no other host reaches', () => {
    // Every wrap on every host that names what they do reach would wait for it.
    const mine = join(LOCAL, 'config.lock')
    leftover(mine)
    mountPointManifestDirectories()
    publish([mine])
    expect(
      opened(() => expect(collectMountPoints('all')).toEqual([mine])),
    ).toEqual([])
  })

  it('goes by the manifests it reads where the home cannot be written from here at all', () => {
    // Mounted read-only on this host, or bound so by an outer sandbox. No pass
    // of this host is ever on record there: waiting for that, nothing on a
    // share would ever be removed.
    const other = join(PROJECT, 'other.lock')
    leftover(LOCK)
    leftover(other)
    manifestOfAnotherHost([other])
    const access = fs.accessSync
    const spy = spyOn(fs, 'accessSync').mockImplementation(((
      file: unknown,
      ...rest: unknown[]
    ) => {
      if (file === SHARED) {
        throw Object.assign(new Error('EROFS'), { code: 'EROFS' })
      }
      ;(access as (...args: unknown[]) => void)(file, ...rest)
    }) as never)
    try {
      expect(publish([LOCK, other]).map(dirname)).toEqual([PLACES[0]!])
      expect(collectMountPoints('all')).toEqual([LOCK])
      expect(existsSync(other)).toBe(true)
      expect(readdirSync(PLACES[0]!)).toEqual([])
    } finally {
      spy.mockRestore()
    }
  })

  it("takes another host's that is stamped far ahead for overdue as well: its clock is wrong", () => {
    const pass = passOfAnotherHost()
    const ahead = new Date(Date.now() + 8 * 60 * MINUTE_MS)
    utimesSync(pass, ahead, ahead)
    expect(passesUnderWay()).toEqual([])
  })

  // ---- what this host remembers of a directory ---------------------------------------

  it('opens the directories that hold what other hosts reach, each once, and no other', () => {
    const open = spyOn(fs, 'openSync')
    try {
      lookAfreshAt([
        LOCK,
        join(PROJECT, 'second.lock'),
        join(HOME, '.bashrc'),
        join(LOCAL, 'config.lock'),
        join(NETWORK, 'not-there', 'x'),
      ])
      expect(open.mock.calls.map(([dir]) => dir)).toEqual([
        PROJECT,
        HOME,
        join(NETWORK, 'not-there'),
      ])
      for (const [, flags] of open.mock.calls) {
        expect(Number(flags) & fs.constants.O_DIRECTORY).not.toBe(0)
      }
    } finally {
      open.mockRestore()
    }
  })

  it('opens none, and asks nothing, on a host with no network home', () => {
    statfs.mockRestore()
    statfs = networkIs(EXT4)
    forgetMountPointManifestDirectory()
    mountPointManifestDirectories()
    ;(statfs as unknown as { mockClear(): void }).mockClear()
    const open = spyOn(fs, 'openSync')
    try {
      lookAfreshAt([LOCK, join(HOME, '.bashrc')])
      expect(open).not.toHaveBeenCalled()
      expect(statfs).not.toHaveBeenCalled()
    } finally {
      open.mockRestore()
    }
  })

  it('has a wrap do so once its manifest is published, before it looks at the host again', async () => {
    const open = fs.openSync
    const seen: string[] = []
    const spy = spyOn(fs, 'openSync').mockImplementation(((
      file: unknown,
      ...rest: unknown[]
    ) => {
      if (file === PROJECT && Number(rest[0]) & fs.constants.O_DIRECTORY) {
        seen.push(
          readdirSync(SHARED).some(name => name.endsWith('.json'))
            ? 'published'
            : 'not published',
        )
      }
      return (open as (...args: unknown[]) => number)(file, ...rest)
    }) as never)
    try {
      await wrapCommandWithSandboxLinux({
        command: 'true',
        needsNetworkRestriction: false,
        readConfig: { denyOnly: [] },
        writeConfig: { allowOnly: [PROJECT], denyWithinAllow: [LOCK] },
      })
    } finally {
      spy.mockRestore()
    }
    expect(seen.at(-1)).toBe('published')
  })

  it("plans again when what it took for the caller's own turns out to be a mount point another host has removed", async () => {
    // That host removed it and then dropped its manifest. This one still
    // remembers the file, reads that nothing names it, and would bind it onto
    // itself: a mount on what the server no longer has, gone when the client
    // finds out. It finds out when the directory is opened, which stands in
    // for that here.
    leftover(LOCK)
    const open = fs.openSync
    const spy = spyOn(fs, 'openSync').mockImplementation(((
      file: unknown,
      ...rest: unknown[]
    ) => {
      if (file === PROJECT) rmSync(LOCK, { force: true })
      return (open as (...args: unknown[]) => number)(file, ...rest)
    }) as never)
    let command: string
    try {
      command = await wrapCommandWithSandboxLinux({
        command: 'true',
        needsNetworkRestriction: false,
        readConfig: { denyOnly: [] },
        writeConfig: { allowOnly: [PROJECT], denyWithinAllow: [LOCK] },
      })
    } finally {
      spy.mockRestore()
    }
    expect(command).toContain(`--ro-bind /dev/null ${LOCK}`)
    expect(command).not.toContain(`--ro-bind ${LOCK} ${LOCK}`)
    expect(namedIn(manifestOf(command)!).paths).toEqual([LOCK])
  })

  /** Not the plan's own open of a directory, by O_PATH, which asks no server. */
  const isToRead = (flags: unknown): boolean =>
    (Number(flags) & 0o10000000) === 0

  it('plans again when what it found absent turns out to be a file the user has put there from another host', async () => {
    // Named as this wrap's own, it would go with the next clean-up. This host
    // finds out when the directory is opened, which stands in for that here.
    let there = false
    const open = fs.openSync
    const spy = spyOn(fs, 'openSync').mockImplementation(((
      file: unknown,
      ...rest: unknown[]
    ) => {
      if (file === PROJECT && isToRead(rest[0]) && !there) {
        there = true
        writeFileSync(LOCK, '')
      }
      return (open as (...args: unknown[]) => number)(file, ...rest)
    }) as never)
    let command: string
    try {
      command = await wrapCommandWithSandboxLinux({
        command: 'true',
        needsNetworkRestriction: false,
        readConfig: { denyOnly: [] },
        writeConfig: { allowOnly: [PROJECT], denyWithinAllow: [LOCK] },
      })
    } finally {
      spy.mockRestore()
    }
    expect(command).toContain(`--ro-bind ${LOCK} ${LOCK}`)
    expect(manifestsOf(command)).toEqual([])
    cleanupBwrapMountPoints({ force: true })
    expect(existsSync(LOCK)).toBe(true)
  })

  it('does not when a manifest names what has come to be there: another sandbox has made it', async () => {
    let there = false
    const open = fs.openSync
    const spy = spyOn(fs, 'openSync').mockImplementation(((
      file: unknown,
      ...rest: unknown[]
    ) => {
      if (file === PROJECT && isToRead(rest[0]) && !there) {
        there = true
        manifestOfAnotherHost([LOCK])
        leftover(LOCK)
      }
      return (open as (...args: unknown[]) => number)(file, ...rest)
    }) as never)
    let command: string
    try {
      command = await wrapCommandWithSandboxLinux({
        command: 'true',
        needsNetworkRestriction: false,
        readConfig: { denyOnly: [] },
        writeConfig: { allowOnly: [PROJECT], denyWithinAllow: [LOCK] },
      })
    } finally {
      spy.mockRestore()
    }
    expect(command).toContain(`--ro-bind /dev/null ${LOCK}`)
    expect(namedIn(manifestOf(command)!).paths).toEqual([LOCK])
  })

  it("does not take what its own plan has made, on a 9p drive, for a file of the user's", async () => {
    // There the plan makes the mount point itself, so it is there at that look.
    statfs.mockRestore()
    statfs = networkIs(0x01021997)
    forgetMountPointManifestDirectory()
    const deep = join(PROJECT, 'a/b/c')
    const own = join(PROJECT, 'own.empty')
    writeFileSync(own, '')
    // The caller's empty file has the manifests read before anything is made.
    const command = await wrapCommandWithSandboxLinux({
      command: 'true',
      needsNetworkRestriction: false,
      readConfig: { denyOnly: [] },
      writeConfig: {
        allowOnly: [PROJECT],
        denyWithinAllow: [own, LOCK, deep],
      },
    })
    expect(command).toContain(`--ro-bind /dev/null ${LOCK}`)
    expect(namedIn(manifestOf(command)!).paths.sort()).toEqual(
      [LOCK, join(PROJECT, 'a')].sort(),
    )
    cleanupBwrapMountPoints()
    expect(readdirSync(PROJECT)).toEqual(['own.empty'])
  })

  it('has a clean-up do so before it removes anything: what this host remembers of a path may be a mount point that has gone', () => {
    // Another host has removed it, and the user has put a file of theirs there.
    leftover(LOCK)
    aged(manifestOfAnotherHost([LOCK]), 11 * MINUTE_MS)
    const remembered = lstatSync(LOCK)
    rmSync(LOCK)
    writeFileSync(LOCK, 'theirs')
    let asked = false
    const open = fs.openSync
    const lstat = fs.lstatSync
    const spies = [
      spyOn(fs, 'openSync').mockImplementation(((
        file: unknown,
        ...rest: unknown[]
      ) => {
        asked ||= file === PROJECT
        return (open as (...args: unknown[]) => number)(file, ...rest)
      }) as never),
      spyOn(fs, 'lstatSync').mockImplementation(((
        file: unknown,
        ...rest: unknown[]
      ) =>
        file === LOCK && !asked
          ? remembered
          : (lstat as (...args: unknown[]) => unknown)(
              file,
              ...rest,
            )) as never),
    ]
    try {
      expect(collectMountPoints('all')).toEqual([])
    } finally {
      spies.forEach(spy => spy.mockRestore())
    }
    expect(readFileSync(LOCK, 'utf8')).toBe('theirs')
    expect(readdirSync(SHARED)).toEqual([])
  })

  it('asks after the file itself as well: another host may have written into it, which leaves the directory as it was', () => {
    // Old bubblewrap makes it 0644. What this host remembers of it is empty.
    leftover(LOCK)
    aged(manifestOfAnotherHost([LOCK]), 11 * MINUTE_MS)
    const remembered = lstatSync(LOCK)
    chmodSync(LOCK, 0o644)
    writeFileSync(LOCK, 'theirs')
    let asked = false
    const open = fs.openSync
    const lstat = fs.lstatSync
    const spies = [
      spyOn(fs, 'openSync').mockImplementation(((
        file: unknown,
        ...rest: unknown[]
      ) => {
        asked ||= file === LOCK
        return (open as (...args: unknown[]) => number)(file, ...rest)
      }) as never),
      spyOn(fs, 'lstatSync').mockImplementation(((
        file: unknown,
        ...rest: unknown[]
      ) =>
        file === LOCK && !asked
          ? remembered
          : (lstat as (...args: unknown[]) => unknown)(
              file,
              ...rest,
            )) as never),
    ]
    try {
      expect(collectMountPoints('all')).toEqual([])
    } finally {
      spies.forEach(spy => spy.mockRestore())
    }
    expect(readFileSync(LOCK, 'utf8')).toBe('theirs')
  })

  it('counts the directory that mount points bind from among what other hosts reach', () => {
    expect(otherHostsReach([join(LOCAL, 'x')])).toBe(false)
    expect(otherHostsReach([join(LOCAL, 'x'), join(NETWORK, 'tmp/e')])).toBe(
      true,
    )
  })

  // ---- two hosts, for real but for the network ------------------------------------------

  /** The environment of a process on the host called `name`. */
  function onHost(name: string): Record<string, string> {
    const root = join(BASE, name)
    if (!existsSync(root)) {
      mkdirSync(root)
      makePlaces(root, HOME)
    }
    return {
      ...(process.env as Record<string, string>),
      SRT_TEST_HOST: root,
      SRT_TEST_BOOT: `${name.padEnd(8, '0')}-0000-0000-0000-000000000000`,
      SRT_TEST_NETWORK: NETWORK,
    }
  }

  const script = (name: string, lines: string[]): string =>
    writeScript(BASE, name, lines)

  /** Wraps `command` with LOCK denied, runs it, and then does `after`. */
  const wrapAndRun = (command: string, out: string, after: string[]) => [
    `import { spawn } from 'node:child_process'`,
    `import { writeFileSync } from 'node:fs'`,
    `const m = await import(${HOST})`,
    `const wrapped = await m.wrapCommandWithSandboxLinux({`,
    `  command: ${JSON.stringify(command)},`,
    `  needsNetworkRestriction: false,`,
    `  readConfig: { denyOnly: [] },`,
    `  writeConfig: { allowOnly: [${JSON.stringify(PROJECT)}], denyWithinAllow: [${JSON.stringify(LOCK)}] },`,
    `})`,
    `const child = spawn(wrapped, { shell: true })`,
    `let said = ''`,
    `child.stdout.on('data', d => (said += d))`,
    `child.stderr.on('data', d => (said += d))`,
    `await new Promise(resolve => child.on('exit', resolve))`,
    `writeFileSync(${JSON.stringify(out)}, said)`,
    ...after,
  ]

  function runOn(host: string, file: string): number | null {
    return spawnSync(process.execPath, [file], {
      env: onHost(host),
      encoding: 'utf8',
      timeout: 60000,
    }).status
  }

  /** Starts `file` on `host`, in a process group of its own. */
  function startOn(host: string, file: string): ChildProcess {
    const child = spawn(process.execPath, [file], {
      env: onHost(host),
      stdio: 'ignore',
      detached: true,
    })
    others.push(child)
    return child
  }

  const exitOf = (child: ChildProcess): Promise<unknown> =>
    new Promise(resolve => child.on('exit', resolve))

  /** A command that says it is up, waits to be told, and tries the denied write. */
  const triesWhenTold = (up: string, go: string): string =>
    `echo ${BOOTED}; touch ${up}; while [ ! -e ${go} ]; do sleep 0.05; done; rm -f ${LOCK}; echo pwned > ${LOCK}; echo rc=$?`

  it.if(BWRAP_CAN_NAMESPACE)(
    'keep a mount point for the sandbox on one while the other wraps, runs and cleans up over the same path',
    async () => {
      const up = join(PROJECT, 'up')
      const go = join(PROJECT, 'go')
      const out = join(BASE, 'first.out')
      const first = startOn(
        'aaaa',
        script(
          'first.ts',
          wrapAndRun(triesWhenTold(up, go), out, [
            'm.cleanupBwrapMountPoints()',
          ]),
        ),
      )
      const ended = exitOf(first)
      await until('the first sandbox to be up', () => existsSync(up))
      expect(existsSync(LOCK)).toBe(true)

      // The whole life of a command on the other host, over the same path.
      const second = join(BASE, 'second.out')
      expect(
        runOn(
          'bbbb',
          script(
            'second.ts',
            wrapAndRun(
              `echo ${BOOTED}; rm -f ${LOCK}; echo pwned > ${LOCK}; echo rc=$?`,
              second,
              [
                'm.cleanupBwrapMountPoints()',
                'm.cleanupBwrapMountPoints({ force: true })',
              ],
            ),
          ),
        ),
      ).toBe(0)
      expect(readFileSync(second, 'utf8')).toContain(BOOTED)
      expect(readFileSync(second, 'utf8')).toMatch(/rc=[1-9]/)
      expect(lstatSync(LOCK).size).toBe(0)

      writeFileSync(go, '')
      await ended
      expect(readFileSync(out, 'utf8')).toContain(BOOTED)
      expect(readFileSync(out, 'utf8')).toMatch(/rc=[1-9]/)
      expect(existsSync(LOCK)).toBe(false)
      expect(readdirSync(SHARED)).toEqual([])
    },
    90000,
  )

  it.if(BWRAP_CAN_NAMESPACE)(
    'keep a mount point for the sandbox on one when the other, whose sandbox made it, has finished and cleaned up',
    async () => {
      const at = (name: string): string => join(PROJECT, name)
      const outs = [join(BASE, 'maker.out'), join(BASE, 'later.out')]
      const maker = startOn(
        'aaaa',
        script(
          'maker.ts',
          wrapAndRun(triesWhenTold(at('up-1'), at('go-1')), outs[0]!, [
            'm.cleanupBwrapMountPoints({ force: true })',
          ]),
        ),
      )
      const makerEnded = exitOf(maker)
      await until('the sandbox that makes it to be up', () =>
        existsSync(at('up-1')),
      )
      const later = startOn(
        'bbbb',
        script(
          'later.ts',
          wrapAndRun(triesWhenTold(at('up-2'), at('go-2')), outs[1]!, [
            'm.cleanupBwrapMountPoints({ force: true })',
          ]),
        ),
      )
      const laterEnded = exitOf(later)
      await until('the later sandbox to be up', () => existsSync(at('up-2')))

      writeFileSync(at('go-1'), '')
      await makerEnded
      expect(readFileSync(outs[0]!, 'utf8')).toMatch(/rc=[1-9]/)
      expect(lstatSync(LOCK).size).toBe(0)

      writeFileSync(at('go-2'), '')
      await laterEnded
      expect(readFileSync(outs[1]!, 'utf8')).toContain(BOOTED)
      expect(readFileSync(outs[1]!, 'utf8')).toMatch(/rc=[1-9]/)
      expect(existsSync(LOCK)).toBe(false)
      expect(readdirSync(SHARED)).toEqual([])
    },
    90000,
  )

  /** A job on the host `aaaa`, killed with its sandbox while that is up. */
  async function aKilledJob(): Promise<void> {
    const up = join(PROJECT, 'up')
    const job = startOn(
      'aaaa',
      script(
        'job.ts',
        wrapAndRun(
          triesWhenTold(up, join(PROJECT, 'never')),
          join(BASE, 'job.out'),
          [],
        ),
      ),
    )
    const ended = exitOf(job)
    await until('the job to be up', () => existsSync(up))
    // The process, its shell and bubblewrap, which takes the sandbox with it.
    process.kill(-job.pid!, 'SIGKILL')
    await ended
    expect(existsSync(LOCK)).toBe(true)
    expect(readdirSync(SHARED)).not.toEqual([])
  }

  const sweep = (): string =>
    script('sweep.ts', [
      `const m = await import(${HOST})`,
      `m.collectMountPoints('all')`,
    ])

  it.if(BWRAP_CAN_NAMESPACE)(
    'have what a job killed on one of them left swept from the other, once it has not been heard of for ten minutes',
    async () => {
      await aKilledJob()
      expect(runOn('bbbb', sweep())).toBe(0)
      expect(existsSync(LOCK)).toBe(true)

      const left = readdirSync(SHARED)
      for (const name of left) aged(join(SHARED, name), 11 * MINUTE_MS)
      expect(runOn('bbbb', sweep())).toBe(0)
      expect(existsSync(LOCK)).toBe(false)
      expect(readdirSync(SHARED)).toEqual([])
    },
    90000,
  )

  it.if(BWRAP_CAN_NAMESPACE)(
    'have it swept at once by the next clean-up on the host it ran on',
    async () => {
      await aKilledJob()
      // bubblewrap may take a moment to go.
      await until('the clean-up to find the sandbox gone', () => {
        expect(runOn('aaaa', sweep())).toBe(0)
        return !existsSync(LOCK)
      })
      expect(readdirSync(SHARED)).toEqual([])
    },
    90000,
  )

  it.if(BWRAP_CAN_NAMESPACE)(
    'start no sandbox on one while a clean-up on the other is stopped before its removal',
    async () => {
      leftover(LOCK)
      aged(manifestOfAnotherHost([LOCK]), 11 * MINUTE_MS)
      const about = join(BASE, 'about-to-remove')
      const cleaner = spawn(
        process.execPath,
        [
          script('stopped-cleaner.ts', [
            `import { spyOn } from 'bun:test'`,
            `import * as fs from 'node:fs'`,
            `const m = await import(${HOST})`,
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
        { env: onHost('aaaa'), stdio: 'ignore' },
      )
      others.push(cleaner)
      const cleaned = new Promise(resolve => cleaner.on('exit', resolve))
      await until('the clean-up to reach the removal', () => existsSync(about))

      const out = join(BASE, 'second.out')
      const second = spawn(
        process.execPath,
        [
          script(
            'second.ts',
            wrapAndRun(
              `echo ${BOOTED}; rm -f ${LOCK}; echo pwned > ${LOCK}; echo rc=$?`,
              out,
              ['m.cleanupBwrapMountPoints()'],
            ),
          ),
        ],
        { env: onHost('bbbb'), stdio: 'ignore' },
      )
      others.push(second)
      const ended = new Promise(resolve => second.on('exit', resolve))
      await sleep(1500)
      expect(existsSync(out)).toBe(false)

      process.kill(cleaner.pid!, 'SIGCONT')
      await cleaned
      await ended
      expect(readFileSync(out, 'utf8')).toContain(BOOTED)
      expect(readFileSync(out, 'utf8')).toMatch(/rc=[1-9]/)
      expect(existsSync(LOCK)).toBe(false)
    },
    90000,
  )

  it('leave a mount point to neither when both finish with it at once, each of which would keep it for the other', async () => {
    // Each meets the other once it has made its claims, and again once it has
    // read and is about to remove or drop.
    leftover(LOCK)
    const side = (me: string, other: string): string => {
      const at = (who: string, where: string): string =>
        JSON.stringify(join(BASE, `${who}.${where}`))
      const meet = (where: string): string =>
        `fs.writeFileSync(${at(me, where)}, ''); while (!fs.existsSync(${at(other, where)})) Bun.sleepSync(1)`
      return script(`${me}.ts`, [
        `import { spyOn } from 'bun:test'`,
        `import * as fs from 'node:fs'`,
        `const m = await import(${HOST})`,
        `m.publishMountPointManifest([${JSON.stringify(LOCK)}], [])`,
        meet('published'),
        `const open = fs.openSync`,
        `const unlink = fs.unlinkSync`,
        `let met = 0`,
        `spyOn(fs, 'openSync').mockImplementation((p, ...rest) => {`,
        `  if (met === 0 && String(p).endsWith('.pass')) { met = 1; ${meet('claimed')} }`,
        `  return open(p, ...rest)`,
        `})`,
        `spyOn(fs, 'unlinkSync').mockImplementation(p => {`,
        `  if (met === 1) { met = 2; ${meet('read')} }`,
        `  return unlink(p)`,
        `})`,
        `m.collectMountPoints('all')`,
      ])
    }
    const ended = [
      ['aaaa', 'bbbb'],
      ['bbbb', 'aaaa'],
    ].map(([me, other]) => {
      const host = spawn(process.execPath, [side(me!, other!)], {
        env: onHost(me!),
        stdio: 'inherit',
      })
      others.push(host)
      return new Promise(resolve => host.on('exit', resolve))
    })
    expect(await Promise.all(ended)).toEqual([0, 0])
    expect(existsSync(LOCK)).toBe(false)
    expect(readdirSync(SHARED)).toEqual([])
  }, 30000)
})
