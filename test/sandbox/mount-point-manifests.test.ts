import { describe, it, expect, beforeEach, afterEach, spyOn } from 'bun:test'
import { spawn, spawnSync } from 'node:child_process'
import * as fs from 'node:fs'
import {
  chmodSync,
  existsSync,
  linkSync,
  lstatSync,
  lutimesSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  readlinkSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  utimesSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { basename, dirname, join } from 'node:path'
import {
  collectMountPoints,
  discardMountPointManifests,
  forgetMountPointManifestDirectory,
  keepTrackOfMountPoint,
  keepTrackOfMountSource,
  liveMountPoints,
  mountPointManifestDirectories,
  namedMountPoints,
  type NamedMountPoints,
  publishMountPointManifest,
  removePrivateManifestDirectory,
  setMountPointManifestPlacesForTesting,
} from '../../src/sandbox/bwrap-mount-manifests.js'
import {
  cleanupBwrapMountPoints,
  wrapCommandWithSandboxLinux,
} from '../../src/sandbox/linux-sandbox-utils.js'
import { mountsOf } from '../helpers/bwrap-argv.js'
import { bwrapCanNamespace } from '../helpers/bwrap-namespace.js'
import {
  aDeadProcess,
  deadPid,
  leftover,
  namedBy,
  recordOf,
  refusal,
  started,
  startOf,
  statLine,
  thisProcess,
  writeManifest,
} from '../helpers/mount-point-fixtures.js'
import { isLinux } from '../helpers/platform.js'
import {
  makePlaces,
  usePrivateManifestDirectory,
} from '../helpers/private-manifest-directory.js'

/**
 * The manifests and the pass that collects on their word, below the level of a
 * sandbox: which process a pass asks after, what it claims and looks at again
 * before it removes anything, and that what it cannot tell it leaves.
 */
describe.if(isLinux)('The mount point manifests', () => {
  const runtime = usePrivateManifestDirectory()
  const MODULE = JSON.stringify(
    join(import.meta.dir, '../helpers/isolated/manifests.ts'),
  )
  const LIBRARY = JSON.stringify(
    join(import.meta.dir, '../helpers/isolated/library.ts'),
  )
  const BWRAP_CAN_NAMESPACE = bwrapCanNamespace()
  const NOT_ROOT = process.getuid?.() !== 0
  const OWN_NAMESPACE = isLinux ? readlinkSync('/proc/self/ns/pid') : ''

  let BASE: string
  let DIR: string // where the manifests go
  let X: string // a mount point an earlier sandbox left
  let TMP: string // the temp dir of every child process

  beforeEach(() => {
    BASE = realpathSync(mkdtempSync(join(tmpdir(), 'mount-point-manifests-')))
    TMP = join(BASE, 'tmp')
    mkdirSync(TMP)
    DIR = runtime.manifestDir()
    mkdirSync(DIR, { recursive: true, mode: 0o700 })
    chmodSync(DIR, 0o700)
    X = join(BASE, 'config.lock')
  })

  afterEach(() => {
    for (const name of readdirSync(DIR)) {
      const file = join(DIR, name)
      try {
        chmodSync(file, 0o700)
      } catch {
        // A dangling link.
      }
      rmSync(file, { recursive: true, force: true })
    }
    collectMountPoints('all')
    rmSync(BASE, { recursive: true, force: true })
  })

  /** What a killed process leaves in DIR. `fields` overrides what it says. */
  const manifestOfADeadProcess = (
    paths: string[],
    fields: Record<string, unknown> = {},
  ): string => writeManifest(DIR, paths, fields)

  /** The manifest this process publishes for a wrap that names `paths`. */
  function publish(paths: string[], sources: string[] = []): string {
    const [manifest] = publishMountPointManifest(paths, sources)
    if (manifest === undefined || typeof manifest === 'string') {
      throw new Error(`not published: ${manifest}`)
    }
    return manifest.file
  }

  /** A reading that is not in doubt. */
  function reads(
    reading: ReturnType<typeof namedMountPoints>,
  ): NamedMountPoints {
    if ('inDoubt' in reading) throw new Error(reading.inDoubt)
    return reading
  }

  /** What a wrap is told the manifests name, sorted; `undefined` in doubt. */
  function named(): string[] | undefined {
    const reading = namedMountPoints()
    return 'inDoubt' in reading ? undefined : [...reading.paths].sort()
  }

  /** The claims in the manifest directory, by name. */
  function claims(): string[] {
    return readdirSync(DIR).filter(name => /\.(claimed|finished)$/.test(name))
  }

  /** The name a pass gives `manifest` when it claims it. */
  function claimOf(manifest: string): string {
    return basename(manifest).replace(/\.json$/, '.claimed')
  }

  /** And the one it gives that claim once it has found no process behind it. */
  function finishedOf(manifest: string): string {
    return basename(manifest).replace(/\.json$/, '.finished')
  }

  /**
   * Runs `source` with the module as `m` in a process of its own, which is
   * killed if it does not end by itself: what these cases guard against blocks
   * the thread. `first` runs before the module is loaded, and an `env` entry
   * that is undefined is removed from the child's environment.
   */
  function inAChild(
    source: string,
    options: {
      launcher?: string[]
      env?: Record<string, string | undefined>
      first?: string
    } = {},
  ): { status: number | null; stdout: string } {
    const script = join(BASE, `child-${Math.random().toString(16).slice(2)}.ts`)
    writeFileSync(
      script,
      `${options.first ?? ''}\nconst m = await import(${MODULE})\n${source}\n`,
    )
    const argv = [...(options.launcher ?? []), process.execPath, script]
    // A temp dir of its own: it is where the manifests go when the runtime
    // directory will not do, and the real one is every other process's.
    const env: Record<string, string | undefined> = {
      ...process.env,
      TMPDIR: TMP,
      ...options.env,
    }
    for (const [name, value] of Object.entries(env)) {
      if (value === undefined) delete env[name]
    }
    const run = spawnSync(argv[0]!, argv.slice(1), {
      env: env as Record<string, string>,
      encoding: 'utf8',
      // A read that blocks is killed, and has no status.
      timeout: 6000,
      killSignal: 'SIGKILL',
    })
    return { status: run.status, stdout: run.stdout }
  }

  const COLLECT = `m.collectMountPoints('all')`
  const PUBLISH = `console.log(JSON.stringify(m.publishMountPointManifest(['/nonexistent/x'], [])[0] ?? null))`

  it.if(BWRAP_CAN_NAMESPACE && NOT_ROOT)(
    'collects nothing on the word of a directory that is read-only from here',
    () => {
      // What a process inside a sandbox sees of the directory. It keeps its own
      // manifests elsewhere and does not judge what is in this one.
      leftover(X)
      const manifest = manifestOfADeadProcess([X])
      const collected = inAChild(COLLECT, {
        launcher: [
          'bwrap',
          '--dev-bind',
          '/',
          '/',
          '--ro-bind',
          DIR,
          DIR,
          '--',
        ],
      })
      expect(collected.status).toBe(0)
      expect(existsSync(X)).toBe(true)
      expect(existsSync(manifest)).toBe(true)
    },
    15000,
  )

  // ---- what a pass removes -----------------------------------------------

  /**
   * Runs `during` once, in the middle of the next pass: when it has claimed
   * the first finished manifest, before it reads that manifest's record again
   * and before it removes anything.
   */
  function duringTheNextPass(during: () => void): { restore(): void } {
    const rename = fs.renameSync
    let done = false
    const spy = spyOn(fs, 'renameSync').mockImplementation(((
      from: string,
      to: string,
    ) => {
      rename(from, to)
      if (to.endsWith('.claimed') && !done) {
        done = true
        during()
      }
    }) as never)
    return { restore: () => spy.mockRestore() }
  }

  it('removes what a finished manifest names once nothing else names it', () => {
    leftover(X)
    started(manifestOfADeadProcess([X]), aDeadProcess())
    expect(collectMountPoints('all')).toEqual([X])
    expect(existsSync(X)).toBe(false)
    // The manifest, its record and the claim on it went with it.
    expect(readdirSync(DIR)).toEqual([])
  })

  it('keeps a mount point named by a manifest that is published while the pass is under way', () => {
    // Nothing keeps a wrap from publishing while a pass is under way, naming a
    // path the pass is about to remove, with a sandbox starting under it.
    leftover(X)
    manifestOfADeadProcess([X])
    let published: { status: number | null; stdout: string } | undefined
    const pass = duringTheNextPass(() => {
      published = inAChild(
        `console.log(JSON.stringify(m.publishMountPointManifest([${JSON.stringify(X)}], [])[0] ?? null))`,
      )
    })
    let removed: string[]
    try {
      removed = collectMountPoints('all')
    } finally {
      pass.restore()
    }
    expect(published?.status).toBe(0)
    const arrived = (JSON.parse(published!.stdout) as { file: string }).file
    expect(readFileSync(arrived, 'utf8')).toContain(X)
    expect(removed).toEqual([])
    expect(existsSync(X)).toBe(true)
  }, 15000)

  it('removes what a pass spared on the word of a manifest whose wrap then comes to nothing', () => {
    // The pass drops the finished manifest, so the newcomer alone names the
    // path from then on: merely unlinked, it would leave the path for good.
    const Y = join(BASE, 'second.lock')
    leftover(X)
    leftover(Y)
    manifestOfADeadProcess([X, Y])
    let newcomer: string | undefined
    const pass = duringTheNextPass(() => (newcomer = publish([X, Y])))
    try {
      expect(collectMountPoints('none')).toEqual([])
    } finally {
      pass.restore()
    }
    expect(readdirSync(DIR)).toEqual([basename(newcomer!)])

    const live = started(manifestOfADeadProcess([Y]), thisProcess())
    discardMountPointManifests([newcomer!])
    expect(existsSync(X)).toBe(false)
    // What another manifest names as well is that one's to keep.
    expect(existsSync(Y)).toBe(true)
    expect(readdirSync(DIR).sort()).toEqual(
      [live, recordOf(live)].map(file => basename(file)).sort(),
    )
  })

  it.if(NOT_ROOT).each([
    ["another process's", (p: string): string => manifestOfADeadProcess([p])],
    ['its own', (p: string): string => publish([p])],
  ] as const)(
    'keeps the manifest of a mount point it could not remove, for a pass that can: %s',
    (_, manifestNaming) => {
      // Seen read-only from here, as from inside a sandbox that may not write
      // the directory it is in. The manifest is all that says the file is a
      // mount point, so it must stay while the file does.
      const readOnly = join(BASE, 'read-only-from-here')
      mkdirSync(readOnly)
      const inside = join(readOnly, 'config.lock')
      leftover(inside)
      const manifest = manifestNaming(inside)
      chmodSync(readOnly, 0o555)
      try {
        expect(collectMountPoints('all')).toEqual([])
        expect(existsSync(inside)).toBe(true)
        // Under its claim, which any later pass takes up.
        expect(claims()).toEqual([finishedOf(manifest)])
        expect(named()).toEqual([inside])
      } finally {
        chmodSync(readOnly, 0o755)
      }
      // Whatever the next pass is told to release.
      expect(collectMountPoints('none')).toEqual([inside])
      expect(readdirSync(DIR)).toEqual([])
    },
  )

  // ---- a manifest goes last, this process's own like anybody's ----
  //
  // A manifest is all that names its mount points. It stays until a pass has
  // removed what it names: after a pass that turned back, or a removal that was
  // refused, a later pass still has it to go by.

  it('keeps the manifest of a wrap of its own when the pass turns back half way, for the next', () => {
    leftover(X)
    const manifest = publish([X])
    // Another version of this library publishes, in a layout this one cannot
    // read, after the pass has claimed: the pass stops short of removing
    // anything.
    const stranger = join(DIR, '4242-0123456789abcdef.json')
    const pass = duringTheNextPass(() =>
      writeFileSync(stranger, '{"version":2}'),
    )
    try {
      expect(collectMountPoints('all')).toEqual([])
    } finally {
      pass.restore()
    }
    expect(existsSync(X)).toBe(true)
    expect(claims()).toEqual([finishedOf(manifest)])

    rmSync(stranger)
    expect(collectMountPoints('none')).toEqual([X])
    expect(readdirSync(DIR)).toEqual([])
  })

  it('lists the directory again before every removal of an ordinary pass', () => {
    // A sandbox about to start on a path shows as a manifest that was not there
    // when the pass began, at any point of the pass, with no time having to go
    // by: each removal is judged on a listing made just before it.
    const Y = join(BASE, 'second.lock')
    leftover(X)
    leftover(Y)
    manifestOfADeadProcess([X, Y])
    const unlink = fs.unlinkSync
    let arrived: string | undefined
    const spy = spyOn(fs, 'unlinkSync').mockImplementation(((file: string) => {
      unlink(file)
      if (file === Y && arrived === undefined) {
        // Published the moment the first mount point has gone.
        arrived = manifestOfADeadProcess([X], {
          pid: process.pid,
          created: Date.now(),
        })
      }
    }) as never)
    let removed: string[]
    try {
      removed = collectMountPoints('all')
    } finally {
      spy.mockRestore()
    }
    expect(arrived).toBeDefined()
    expect(removed).toEqual([Y])
    expect(existsSync(X)).toBe(true)
  })

  it('lists by the clock, not before every removal, in a pass of many mount points', () => {
    // A directory of thousands is not listed thousands of times.
    const many = Array.from({ length: 200 }, (_, i) => join(BASE, `m${i}.lock`))
    many.forEach(leftover)
    manifestOfADeadProcess(many)
    const readdir = fs.readdirSync
    let listings = 0
    const spy = spyOn(fs, 'readdirSync').mockImplementation(((
      ...args: Parameters<typeof fs.readdirSync>
    ) => {
      if (args[0] === DIR) listings++
      return readdir(...args)
    }) as never)
    let removed: string[]
    try {
      removed = collectMountPoints('all')
    } finally {
      spy.mockRestore()
    }
    expect(removed.sort()).toEqual([...many].sort())
    expect(listings).toBeGreaterThan(2)
    expect(listings).toBeLessThan(many.length)
  })

  it('takes a manifest of a later version by the fields it knows', () => {
    // Taken for unreadable, it would put everything in doubt, and every wrap of
    // an older process would be refused while a newer one is at work beside it.
    const Y = join(BASE, 'second.lock')
    leftover(X)
    leftover(Y)
    const later = { version: 2, added: { by: 'a later version' } }
    manifestOfADeadProcess([X], { ...later, ...thisProcess() })
    const finished = manifestOfADeadProcess([Y], later)

    expect(liveMountPoints()).toEqual(new Set([X]))
    expect(collectMountPoints('none')).toEqual([Y])
    expect(existsSync(X)).toBe(true)
    expect(existsSync(finished)).toBe(false)
  })

  it('is live for half a second from when it was written, though its writer is gone, and no longer', () => {
    // A command whose wrapping process was killed a moment ago is not refused
    // its start for that.
    leftover(X)
    const now = Date.now()
    const manifest = manifestOfADeadProcess([X], { created: now - 499 })
    const clock = spyOn(Date, 'now').mockReturnValue(now)
    try {
      expect(collectMountPoints('all')).toEqual([])
      expect(existsSync(manifest)).toBe(true)
      clock.mockReturnValue(now + 1)
      expect(collectMountPoints('all')).toEqual([X])
    } finally {
      clock.mockRestore()
    }
  })

  it('says when it was written, and by which process as /proc numbers it', () => {
    // Where the process has a PID namespace of its own under an outer /proc,
    // its own number for itself is nobody's there, or somebody else's.
    const stat = readFileSync('/proc/self/stat', 'utf8')
    const outer = deadPid()
    const read = fs.readFileSync
    const spy = spyOn(fs, 'readFileSync').mockImplementation(((
      file: unknown,
      options: unknown,
    ) =>
      file === '/proc/self/stat'
        ? stat.replace(/^\d+/, String(outer))
        : (read as (f: unknown, o: unknown) => unknown)(
            file,
            options,
          )) as never)
    const before = Date.now()
    let manifest: string
    try {
      manifest = publish([X])
    } finally {
      spy.mockRestore()
    }
    const written = JSON.parse(readFileSync(manifest, 'utf8')) as {
      created: number
    }
    expect(written).toMatchObject({
      pid: outer,
      start: startOf(stat),
      boot: readFileSync('/proc/sys/kernel/random/boot_id', 'utf8').trim(),
    })
    expect(written.created).toBeGreaterThanOrEqual(before)
    expect(written.created).toBeLessThanOrEqual(Date.now())
  })

  // ---- a sandbox vouches for itself ----
  //
  // The command line a wrap hands out records the process it starts bubblewrap
  // in. With a record, that process alone says whether the manifest is live.

  it('is live while a process on its record runs, whoever wrote it and whatever the caller has said', () => {
    const Y = join(BASE, 'second.lock')
    leftover(X)
    leftover(Y)
    const theirs = started(manifestOfADeadProcess([X]), thisProcess())
    const own = started(publish([Y]), thisProcess())

    expect(collectMountPoints('all')).toEqual([])
    expect(collectMountPoints('all')).toEqual([])
    for (const kept of [X, Y, theirs, own, recordOf(theirs), recordOf(own)]) {
      expect(existsSync(kept)).toBe(true)
    }
    expect(live()).toEqual([X, Y].sort())
  })

  it('is live while the process that wrote it runs, though no process on its record does: its command line may be run again', () => {
    leftover(X)
    const manifest = started(
      manifestOfADeadProcess([X], thisProcess()),
      aDeadProcess(),
    )
    expect(live()).toEqual([X])
    expect(collectMountPoints('none')).toEqual([])
    expect(existsSync(manifest)).toBe(true)
    expect(existsSync(recordOf(manifest))).toBe(true)
  })

  it('is finished once neither a process on its record nor the one that wrote it runs, however young', () => {
    leftover(X)
    const manifest = started(
      manifestOfADeadProcess([X], { created: Date.now() }),
      aDeadProcess(),
    )
    expect(live()).toEqual([])
    expect(collectMountPoints('none')).toEqual([X])
    expect(existsSync(manifest)).toBe(false)
    expect(existsSync(recordOf(manifest))).toBe(false)
  })

  it('tells a process from a later one with its pid by when it started', () => {
    leftover(X)
    const later = String(Number(thisProcess().start) + 1)
    started(manifestOfADeadProcess([X]), { pid: process.pid, start: later })
    expect(collectMountPoints('all')).toEqual([X])
  })

  it('is live while any of the runs on its record lasts', () => {
    // The same command line run again, before the first run is over or after.
    leftover(X)
    const gone = aDeadProcess()
    started(manifestOfADeadProcess([X]), gone, thisProcess(), gone)
    expect(collectMountPoints('all')).toEqual([])
    expect(existsSync(X)).toBe(true)
  })

  it('removes a record left without its manifest once no process on it runs', () => {
    // What a command line run after its manifest was collected leaves: it
    // records itself, and bubblewrap then finds no manifest to bind.
    const left = join(DIR, '4242-0123456789abcdef.started')
    writeFileSync(left, statLine(aDeadProcess()))
    collectMountPoints('all')
    expect(existsSync(left)).toBe(false)
  })

  // ---- nothing is removed but under a claim ----
  //
  // bubblewrap binds the manifest before it makes a mount point. A pass renames
  // a finished manifest before it removes what that names, so a command that
  // starts from then on fails having made nothing, and reads the directory
  // after that, for a command that started just before.

  /** Runs `at` just before the pass removes `mountPoint`. */
  function atTheRemovalOf(
    mountPoint: string,
    at: () => void,
  ): { restore(): void } {
    const unlink = fs.unlinkSync
    const spy = spyOn(fs, 'unlinkSync').mockImplementation(((file: string) => {
      if (file === mountPoint) at()
      unlink(file)
    }) as never)
    return { restore: () => spy.mockRestore() }
  }

  it('claims a finished manifest before it removes what that names', () => {
    leftover(X)
    const manifest = manifestOfADeadProcess([X])
    const seen: unknown[] = []
    const removal = atTheRemovalOf(X, () =>
      seen.push({ manifest: existsSync(manifest), claims: claims() }),
    )
    try {
      expect(collectMountPoints('all')).toEqual([X])
    } finally {
      removal.restore()
    }
    expect(seen).toEqual([{ manifest: false, claims: [finishedOf(manifest)] }])
    expect(readdirSync(DIR)).toEqual([])
  })

  it('gives its claim back, and removes nothing, when a process has started under the manifest by then', () => {
    // The command was started between the pass reading the manifest as finished
    // and its claim: bubblewrap has bound the manifest and goes on to its mount
    // points.
    leftover(X)
    const manifest = manifestOfADeadProcess([X])
    const pass = duringTheNextPass(() => started(manifest, thisProcess()))
    try {
      expect(collectMountPoints('all')).toEqual([])
    } finally {
      pass.restore()
    }
    expect(existsSync(X)).toBe(true)
    expect(existsSync(manifest)).toBe(true)
    expect(claims()).toEqual([])
  })

  /** Claims `manifest`, as a pass does. */
  function claimed(manifest: string): string {
    const claim = join(DIR, claimOf(manifest))
    fs.renameSync(manifest, claim)
    return claim
  }

  // ---- a path is kept while any manifest that names it may have a sandbox ----

  it('keeps a path that a live manifest names too, whichever manifest the pass is collecting', () => {
    // The same project wrapped twice: both wraps name the mount point.
    const Y = join(BASE, 'second.lock')
    leftover(X)
    leftover(Y)
    const finished = manifestOfADeadProcess([X, Y])
    const live = started(manifestOfADeadProcess([X]), thisProcess())
    expect(collectMountPoints('all')).toEqual([Y])
    expect(existsSync(X)).toBe(true)
    expect(existsSync(finished)).toBe(false)
    expect(existsSync(live)).toBe(true)

    // It goes once that sandbox has ended too.
    started(live, aDeadProcess())
    expect(collectMountPoints('all')).toEqual([X])
  })

  it('keeps a path that another manifest names when a command starts under that one during the pass', () => {
    // Both read as finished, and both are claimed. The reading that follows the
    // claims finds a process on the record of one: it keeps the path for both.
    leftover(X)
    const one = manifestOfADeadProcess([X])
    const other = manifestOfADeadProcess([X])
    const pass = duringTheNextPass(() => started(other, thisProcess()))
    try {
      expect(collectMountPoints('all')).toEqual([])
    } finally {
      pass.restore()
    }
    expect(existsSync(X)).toBe(true)
    expect(existsSync(other)).toBe(true)
    expect(existsSync(one)).toBe(false)
    expect(claims()).toEqual([])
  })

  it('keeps what a manifest at its own name names, finished or not', () => {
    // A command can start under it at any moment: only a claim refuses one.
    const Y = join(BASE, 'second.lock')
    leftover(X)
    leftover(Y)
    const refused = manifestOfADeadProcess([X])
    manifestOfADeadProcess([X, Y])
    const rename = fs.renameSync
    const spy = spyOn(fs, 'renameSync').mockImplementation(((
      from: string,
      to: string,
    ) => {
      if (from === refused) {
        throw Object.assign(new Error(`EACCES: ${from}`), { code: 'EACCES' })
      }
      rename(from, to)
    }) as never)
    try {
      expect(collectMountPoints('all')).toEqual([Y])
    } finally {
      spy.mockRestore()
    }
    expect(existsSync(X)).toBe(true)
    expect(existsSync(refused)).toBe(true)
  })

  // ---- any number of passes at once ----
  //
  // A pass takes no lock and waits for nobody. A claim is anybody's to act on:
  // with no process on its record nothing can start under it again.

  it('collects on a claim that another pass made, or that a killed one left', () => {
    const Y = join(BASE, 'second.lock')
    leftover(X)
    leftover(Y)
    // Though its writer runs: whoever claimed it knew its command to be over.
    const claim = claimed(manifestOfADeadProcess([X], thisProcess()))
    manifestOfADeadProcess([X, Y])
    expect(named()).toEqual([X, Y].sort())
    expect(live()).toEqual([])
    expect(collectMountPoints('all').sort()).toEqual([X, Y].sort())
    expect(existsSync(claim)).toBe(false)
    expect(readdirSync(DIR)).toEqual([])
  })

  it('keeps what a claimed manifest names while a process on its record runs, and leaves the claim to the pass that made it', () => {
    leftover(X)
    const claim = claimed(started(manifestOfADeadProcess([X]), thisProcess()))
    expect(live()).toEqual([X])
    expect(collectMountPoints('all')).toEqual([])
    expect(existsSync(X)).toBe(true)
    expect(claims()).toEqual([basename(claim)])
  })

  it('leaves a manifest and its record that are back at its own name while it removes what they name', () => {
    // No pass gives back what it has found finished. Should the manifest be at
    // its own name again all the same, a sandbox can start under it.
    const Y = join(BASE, 'second.lock')
    leftover(X)
    leftover(Y)
    const manifest = manifestOfADeadProcess([X, Y])
    const removal = atTheRemovalOf(Y, () => {
      fs.renameSync(join(DIR, finishedOf(manifest)), manifest)
      started(manifest, thisProcess())
    })
    try {
      // X stays: the manifest is at its own name by the time X's turn comes.
      expect(collectMountPoints('all')).toEqual([Y])
    } finally {
      removal.restore()
    }
    expect(existsSync(X)).toBe(true)
    expect(readdirSync(DIR).sort()).toEqual(
      [basename(manifest), basename(recordOf(manifest))].sort(),
    )
  })

  it('finds a manifest that is claimed, or given back, between being listed and being opened', () => {
    // Taken for gone, it would name nothing: a wrap would take its mount point
    // for the caller's own file, and a pass would remove what it names.
    leftover(X)
    const manifest = started(manifestOfADeadProcess([X]), thisProcess())
    const open = fs.openSync
    let claim: string | undefined
    const spy = spyOn(fs, 'openSync').mockImplementation(((
      file: string,
      ...rest: unknown[]
    ) => {
      if (file === manifest && claim === undefined) {
        claim = claimed(manifest)
      } else if (file === claim && !existsSync(manifest)) {
        fs.renameSync(claim, manifest)
      }
      return (open as (...args: unknown[]) => number)(file, ...rest)
    }) as never)
    try {
      expect(named()).toEqual([X])
      expect(claim).toBeDefined()
      expect(live()).toEqual([X])
      expect(collectMountPoints('all')).toEqual([])
    } finally {
      spy.mockRestore()
    }
    expect(existsSync(X)).toBe(true)
  })

  it('removes nothing while a listed manifest keeps being gone when it is opened', () => {
    const Y = join(BASE, 'second.lock')
    leftover(X)
    leftover(Y)
    manifestOfADeadProcess([Y])
    const elusive = started(manifestOfADeadProcess([X]), thisProcess())
    const open = fs.openSync
    const spy = spyOn(fs, 'openSync').mockImplementation(((
      file: string,
      ...rest: unknown[]
    ) => {
      if (file === elusive) {
        throw Object.assign(new Error(`ENOENT: ${file}`), { code: 'ENOENT' })
      }
      return (open as (...args: unknown[]) => number)(file, ...rest)
    }) as never)
    try {
      // What it names cannot be listed.
      expect(live()).toBeUndefined()
      expect(named()).toBeUndefined()
      expect(collectMountPoints('all')).toEqual([])
    } finally {
      spy.mockRestore()
    }
    expect(existsSync(Y)).toBe(true)
  })

  // ---- what cannot be told is live ----
  //
  // Only a process that is gone says its sandbox has ended. A sandboxed command
  // can use up what this user may open or map, so a read that fails in a pass
  // must never end in a removal.

  /** Has reading `target` fail with `code`: opening it, or reading what was opened. */
  function failing(
    target: string,
    code: string,
    at: 'open' | 'read' = 'open',
  ): { restore(): void } {
    const fail = (): never => {
      throw Object.assign(new Error(`${code}: ${target}`), { code })
    }
    const inode = existsSync(target) ? statSync(target).ino : undefined
    const open = fs.openSync
    const read = fs.readFileSync
    const fstat = fs.fstatSync
    const spies = [
      spyOn(fs, 'openSync').mockImplementation(((
        file: unknown,
        ...rest: unknown[]
      ) =>
        at === 'open' && file === target
          ? fail()
          : (open as (...args: unknown[]) => number)(file, ...rest)) as never),
      spyOn(fs, 'readFileSync').mockImplementation(((
        file: unknown,
        options: unknown,
      ) =>
        file === target ||
        (at === 'read' && typeof file === 'number' && fstat(file).ino === inode)
          ? fail()
          : (read as (f: unknown, o: unknown) => unknown)(
              file,
              options,
            )) as never),
    ]
    return { restore: () => spies.forEach(spy => spy.mockRestore()) }
  }

  /** What a pass removes, and the set a caller is given, with that in place. */
  function withThat(injected: { restore(): void }): {
    removed: string[]
    held: string[] | undefined
  } {
    try {
      return { held: live(), removed: collectMountPoints('all') }
    } finally {
      injected.restore()
    }
  }

  const NOTHING_REMOVED = { removed: [], held: [expect.any(String)] }

  // One that lasts and one that passes: the code takes every errno but "not
  // there" alike.
  for (const code of ['EACCES', 'EMFILE']) {
    it(`removes nothing when it cannot ask after the process on a record: ${code}`, () => {
      leftover(X)
      const gone = aDeadProcess()
      started(manifestOfADeadProcess([X]), gone)
      expect(withThat(failing(`/proc/${gone.pid}/stat`, code))).toEqual(
        NOTHING_REMOVED,
      )
      expect(existsSync(X)).toBe(true)
    })

    it(`removes nothing when it cannot ask after the writer of a manifest with no record: ${code}`, () => {
      leftover(X)
      const gone = aDeadProcess()
      manifestOfADeadProcess([X], gone)
      expect(withThat(failing(`/proc/${gone.pid}/stat`, code))).toEqual(
        NOTHING_REMOVED,
      )
      expect(existsSync(X)).toBe(true)
    })

    for (const at of ['open', 'read'] as const) {
      it(`removes nothing at all when a manifest cannot be read: ${code} at the ${at}`, () => {
        const Y = join(BASE, 'second.lock')
        leftover(X)
        leftover(Y)
        manifestOfADeadProcess([Y])
        const manifest = manifestOfADeadProcess([X])
        // However old it is, and with no process on its record: this is no
        // file to drop for being unreadable.
        const hoursAgo = new Date(Date.now() - 2 * 3600 * 1000)
        utimesSync(manifest, hoursAgo, hoursAgo)
        // What it names cannot be listed, so nobody can say what is held.
        expect(withThat(failing(manifest, code, at))).toEqual({
          removed: [],
          held: undefined,
        })
        expect(existsSync(X)).toBe(true)
        expect(existsSync(manifest)).toBe(true)
      })

      it(`keeps what a manifest names when its record cannot be read: ${code} at the ${at}`, () => {
        leftover(X)
        const manifest = started(manifestOfADeadProcess([X]), aDeadProcess())
        expect(withThat(failing(recordOf(manifest), code, at))).toEqual(
          NOTHING_REMOVED,
        )
        expect(existsSync(X)).toBe(true)
      })
    }
  }

  it('removes nothing when what it reads of the process on a record is cut short', () => {
    leftover(X)
    started(manifestOfADeadProcess([X]), thisProcess())
    const read = fs.readFileSync
    const spy = spyOn(fs, 'readFileSync').mockImplementation(((
      file: unknown,
      options: unknown,
    ) => {
      const whole = (read as (f: unknown, o: unknown) => unknown)(file, options)
      return file === `/proc/${process.pid}/stat`
        ? String(whole).split(' ').slice(0, 12).join(' ')
        : whole
    }) as never)
    expect(withThat({ restore: () => spy.mockRestore() })).toEqual(
      NOTHING_REMOVED,
    )
  })

  const gone = (): string => statLine(aDeadProcess())
  const notARecord: [string, (record: string) => void][] = [
    ['cut short of the start time', r => write(r, `${gone().slice(0, 30)}\n`)],
    ['not the line of a process', r => write(r, 'ended\n')],
    [
      'a line of a process and then something else',
      r => write(r, `${gone()}?\n`),
    ],
    [
      'a link to the record of a process that is gone',
      r => {
        write(join(BASE, 'elsewhere.started'), gone())
        symlinkSync(join(BASE, 'elsewhere.started'), r)
      },
    ],
    ['a directory', r => mkdirSync(r)],
    [
      'a FIFO nobody writes to',
      r => expect(spawnSync('mkfifo', [r]).status).toBe(0),
    ],
  ]
  function write(file: string, text = ''): void {
    writeFileSync(file, text, { mode: 0o600 })
  }
  if (NOT_ROOT) {
    notARecord.push([
      'one its owner may not read',
      r => writeFileSync(r, gone(), { mode: 0 }),
    ])
  }
  for (const [what, plant] of notARecord) {
    it(`keeps what a manifest names while its record is ${what}`, () => {
      leftover(X)
      const manifest = manifestOfADeadProcess([X])
      plant(recordOf(manifest))
      // In a process of its own: opening a FIFO to read waits for a writer, on
      // the one thread there is.
      const looked = inAChild(
        `console.log(JSON.stringify({ held: [...m.liveMountPoints()], removed: m.collectMountPoints('all') }))`,
      )
      expect(looked.status).toBe(0)
      expect(JSON.parse(looked.stdout)).toEqual({ held: [X], removed: [] })
      expect(existsSync(manifest)).toBe(true)
    }, 15000)
  }

  // ---- a record with no whole line on it is no record ----
  //
  // The command line execs bubblewrap only once its whole line is written. What
  // a shell that was killed before that leaves must not vouch for ever, and
  // nothing may become removable by its age alone.

  const MONTH_MS = 30 * 24 * 3600 * 1000
  const unwritten: [string, () => string][] = [
    ['empty, as its shell makes it', () => ''],
    ['cut short of its end of line', () => gone().slice(0, -1)],
  ]
  for (const [what, text] of unwritten) {
    it(`collects a manifest whose writer is gone and whose record is ${what}`, () => {
      leftover(X)
      write(recordOf(manifestOfADeadProcess([X])), text())
      expect(live()).toEqual([])
      expect(collectMountPoints('none')).toEqual([X])
      expect(readdirSync(DIR)).toEqual([])
    })
  }

  for (const [what, text] of [
    ['not there yet', undefined],
    ...unwritten,
  ] as const) {
    it(`keeps, however old, the manifest of a running process that has not released it, its record ${what}`, () => {
      // A wrap held up between publishing and its command putting itself on
      // record, for longer than every threshold there is.
      leftover(X)
      const own = publish([X])
      const theirs = manifestOfADeadProcess([X], thisProcess())
      const longAgo = new Date(Date.now() - MONTH_MS)
      for (const manifest of [own, theirs]) {
        const body = JSON.parse(readFileSync(manifest, 'utf8')) as object
        write(manifest, JSON.stringify({ ...body, created: longAgo.getTime() }))
        if (text !== undefined) write(recordOf(manifest), text())
        for (const file of [manifest, recordOf(manifest)]) {
          if (existsSync(file)) utimesSync(file, longAgo, longAgo)
        }
      }
      expect(collectMountPoints('none')).toEqual([])
      expect(live()).toEqual([X])
      expect(claims()).toEqual([])

      // Its own goes when the caller says the command is over; the other
      // process's is not this one's to release.
      expect(collectMountPoints('all')).toEqual([])
      expect(existsSync(own)).toBe(false)
      expect(existsSync(theirs)).toBe(true)
      expect(existsSync(X)).toBe(true)
    })
  }

  it('goes by the whole lines of a record whose last line is cut short', () => {
    // The same command line run again, its shell not yet done writing.
    leftover(X)
    const manifest = manifestOfADeadProcess([X])
    write(recordOf(manifest), statLine(thisProcess()) + gone().slice(0, -1))
    expect(collectMountPoints('none')).toEqual([])
    write(recordOf(manifest), gone() + gone().slice(0, -1))
    expect(collectMountPoints('none')).toEqual([X])
  })

  it('is not held up by a record with no whole line and no manifest, and drops it past the grace', () => {
    // Nothing names a path, so it protects none.
    leftover(X)
    started(manifestOfADeadProcess([X]), aDeadProcess())
    const [young, old, older] = ['4242', '4243', '4244'].map(pid =>
      join(DIR, `${pid}-0123456789abcdef.started`),
    ) as [string, string, string]
    write(young)
    write(old)
    write(older, gone().slice(0, -1))
    // Its shell may be about to write to it: not by the clock of a slow run.
    const soon = new Date(Date.now() + 60_000)
    utimesSync(young, soon, soon)
    const aSecondAgo = new Date(Date.now() - 1000)
    utimesSync(old, aSecondAgo, aSecondAgo)
    utimesSync(older, new Date(Date.now() - MONTH_MS), aSecondAgo)

    expect(live()).toEqual([])
    expect(named()).toEqual([X])
    expect(collectMountPoints('all')).toEqual([X])
    expect(readdirSync(DIR)).toEqual([basename(young)])
  })

  for (const [what, plant] of notARecord) {
    it(`is not held up by a record with no manifest that is ${what}`, () => {
      // It refuses every wrap of the user for as long as it counts.
      leftover(X)
      manifestOfADeadProcess([X])
      const orphan = join(DIR, '4242-0123456789abcdef.started')
      plant(orphan)
      const looked = inAChild(
        `console.log(JSON.stringify({ named: [...m.namedMountPoints().paths], held: [...m.liveMountPoints()], removed: m.collectMountPoints('all') }))`,
      )
      expect(looked.status).toBe(0)
      expect(JSON.parse(looked.stdout)).toEqual({
        named: [X],
        held: [],
        removed: [X],
      })
      // Dropped, where it can be.
      expect(readdirSync(DIR)).toEqual(
        what === 'a directory' ? [basename(orphan)] : [],
      )
    }, 15000)
  }

  it('removes nothing, however old it is, while a record with no manifest cannot be read for want of a descriptor', () => {
    // That says nothing of the record: its manifest may be passing from one
    // name to the other with a sandbox on it.
    leftover(X)
    manifestOfADeadProcess([X])
    const orphan = join(DIR, '4242-0123456789abcdef.started')
    write(orphan, gone())
    const longAgo = new Date(Date.now() - MONTH_MS)
    utimesSync(orphan, longAgo, longAgo)
    expect(withThat(failing(orphan, 'EMFILE'))).toEqual({
      removed: [],
      held: undefined,
    })
    expect(existsSync(orphan)).toBe(true)
  })

  /** Hides `name` from the next listing of the manifest directory. */
  function missedByTheNextListing(name: string): { restore(): void } {
    const readdir = fs.readdirSync
    let hidden = false
    const spy = spyOn(fs, 'readdirSync').mockImplementation(((
      dir: unknown,
      options: unknown,
    ) => {
      const names = (readdir as (d: unknown, o: unknown) => string[])(
        dir,
        options,
      )
      if (dir !== DIR || hidden) return names
      hidden = true
      return names.filter(listed => listed !== name)
    }) as never)
    return { restore: () => spy.mockRestore() }
  }

  for (const [what, text] of [
    ...unwritten,
    ['that of a process that runs', () => statLine(thisProcess())],
  ] as const) {
    it(`finds by name a manifest the listing missed, its record ${what}, and leaves that record`, () => {
      // Published, or renamed, while the directory was being listed: the record
      // shows and the manifest does not. Taken for a record without a manifest
      // it would be dropped, from under the shell about to write to it.
      leftover(X)
      const manifest = manifestOfADeadProcess([X], thisProcess())
      write(recordOf(manifest), text())
      const longAgo = new Date(Date.now() - MONTH_MS)
      utimesSync(recordOf(manifest), longAgo, longAgo)
      for (const look of [named, live, () => collectMountPoints('none')]) {
        const listing = missedByTheNextListing(basename(manifest))
        try {
          expect(look()).toEqual(look === named || look === live ? [X] : [])
        } finally {
          listing.restore()
        }
      }
      expect(existsSync(recordOf(manifest))).toBe(true)
      expect(existsSync(X)).toBe(true)
    })
  }

  it("keeps what a manifest names while its record is somebody else's", () => {
    leftover(X)
    const manifest = started(manifestOfADeadProcess([X]), aDeadProcess())
    const theirs = asSomebodyElses(recordOf(manifest))
    expect(withThat(theirs)).toEqual(NOTHING_REMOVED)
    expect(existsSync(X)).toBe(true)
  })

  it('removes nothing while a process that runs is on a record whose manifest is not to be found', () => {
    // A claim is a rename, and a rename can hide a name from a listing that is
    // under way: the manifest may be there all the same.
    leftover(X)
    manifestOfADeadProcess([X])
    const record = join(DIR, '4242-0123456789abcdef.started')
    writeFileSync(record, statLine(thisProcess()))
    // However old it is.
    const hoursAgo = new Date(Date.now() - 2 * 3600 * 1000)
    utimesSync(record, hoursAgo, hoursAgo)
    expect(collectMountPoints('all')).toEqual([])
    expect(existsSync(X)).toBe(true)
    expect(existsSync(record)).toBe(true)
  })

  /** Has this process fail to write its next manifest, as on a full disk. */
  function unrecorded(paths: string[], sources: string[] = []): void {
    const write = fs.writeFileSync
    const spy = spyOn(fs, 'writeFileSync').mockImplementation(((
      file: unknown,
      ...rest: unknown[]
    ) => {
      if (String(file).endsWith('.json.tmp')) {
        throw Object.assign(new Error('ENOSPC'), { code: 'ENOSPC' })
      }
      return (write as (...args: unknown[]) => void)(file, ...rest)
    }) as never)
    try {
      expect(publishMountPointManifest(paths, sources)).toEqual([])
    } finally {
      spy.mockRestore()
    }
  }

  it('removes nothing when the manifests cannot be listed', () => {
    // Not even what this process could not record and would remove on its own
    // word: a manifest that cannot be listed may name it too.
    leftover(X)
    unrecorded([X])
    const listing = failingCall('readdirSync', DIR, 'EMFILE')
    try {
      expect(collectMountPoints('all')).toEqual([])
    } finally {
      listing.restore()
    }
    expect(existsSync(X)).toBe(true)
    expect(collectMountPoints('all')).toEqual([X])
  })

  it('takes every manifest for live when it cannot tell which PID namespace it is in', () => {
    // With no /proc every process asked after reads as gone. However old: that
    // is a condition of this process, which the age of a file does not end.
    leftover(X)
    const manifest = manifestOfADeadProcess([X])
    aged(started(manifest, aDeadProcess()), 30 * 24 * 60)
    aged(recordOf(manifest), 30 * 24 * 60)
    forgetMountPointManifestDirectory()
    const spy = spyOn(fs, 'readlinkSync').mockImplementation((() => {
      throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' })
    }) as never)
    try {
      expect(live()).toEqual([X])
      expect(collectMountPoints('all')).toEqual([])
    } finally {
      spy.mockRestore()
      forgetMountPointManifestDirectory()
    }
    expect(collectMountPoints('all')).toEqual([X])
  })

  for (const [what, then] of [
    [
      'the directory cannot be listed again',
      () => failingCall('readdirSync', DIR, 'EMFILE'),
    ],
    [
      'a manifest that has arrived cannot be read',
      () => planted('1-garbage.json', '{}'),
    ],
  ] as const) {
    it(`stops removing, and keeps its claim, once ${what}`, () => {
      const Y = join(BASE, 'second.lock')
      leftover(X)
      leftover(Y)
      const manifest = manifestOfADeadProcess([X, Y])
      let injected: { restore(): void } | undefined
      const unlink = fs.unlinkSync
      const spy = spyOn(fs, 'unlinkSync').mockImplementation(((
        file: string,
      ) => {
        unlink(file)
        // The moment the first mount point has gone.
        injected ??= then()
      }) as never)
      try {
        expect(collectMountPoints('all')).toEqual([Y])
      } finally {
        spy.mockRestore()
        injected?.restore()
      }
      expect(existsSync(X)).toBe(true)
      expect(claims()).toEqual([finishedOf(manifest)])
      expect(collectMountPoints('all')).toEqual([X])
    })
  }

  // ---- a manifest is only a claim about a path ---------------------------

  // bubblewrap makes a file mount point 0444 from 0.5.0, and 0666 less the
  // umask before.
  for (const mode of [0o444, 0o644, 0o666, 0o600]) {
    it(`takes an empty file of mode 0${mode.toString(8)} that a manifest names for a mount point`, () => {
      writeFileSync(X, '')
      chmodSync(X, mode)
      const manifest = started(manifestOfADeadProcess([X]), thisProcess())
      expect(live()).toEqual([X])
      expect(collectMountPoints('all')).toEqual([])

      started(manifest, aDeadProcess())
      expect(live()).toEqual([])
      expect(collectMountPoints('all')).toEqual([X])
      expect(existsSync(X)).toBe(false)
      expect(readdirSync(DIR)).toEqual([])
    })
  }

  // ---- a directory mount point, and what lies in it ----

  /** `.claude`, as one sandbox made it, and what others nested in it. */
  function nested(): { Q: string; inside: string[] } {
    const Q = join(BASE, '.claude')
    const inside = [join(Q, 'agents'), join(Q, 'commands')]
    mkdirSync(Q)
    inside.forEach(leftover)
    return { Q, inside }
  }

  for (const order of ['as listed', 'the other way round']) {
    it(`removes what lies in a directory before the directory, the manifests read ${order}`, () => {
      const { Q, inside } = nested()
      manifestOfADeadProcess([Q, ...inside])
      manifestOfADeadProcess([Q])
      manifestOfADeadProcess(inside)
      const readdir = fs.readdirSync
      const spy = spyOn(fs, 'readdirSync').mockImplementation(((
        dir: unknown,
        options: unknown,
      ) => {
        const names = (readdir as (d: unknown, o: unknown) => string[])(
          dir,
          options,
        )
        return order === 'as listed' ? names : names.reverse()
      }) as never)
      try {
        expect(collectMountPoints('all')).toEqual(
          [...inside].reverse().concat(Q),
        )
      } finally {
        spy.mockRestore()
      }
      expect(existsSync(Q)).toBe(false)
      expect(readdirSync(DIR)).toEqual([])
    })
  }

  it('keeps its claim on a directory for as long as what lies in it is named by a manifest that is kept', () => {
    // Dropped, nothing would name the directory once it is empty.
    const { Q, inside } = nested()
    const outer = manifestOfADeadProcess([Q])
    const inner = started(manifestOfADeadProcess(inside), thisProcess())
    expect(collectMountPoints('all')).toEqual([])
    expect(claims()).toEqual([finishedOf(outer)])

    started(inner, aDeadProcess())
    expect(collectMountPoints('all')).toEqual([...inside].reverse().concat(Q))
    expect(readdirSync(DIR)).toEqual([])
  })

  it.if(NOT_ROOT)(
    'keeps its claim on a directory when what lies in it could not be removed',
    () => {
      const { Q, inside } = nested()
      const outer = manifestOfADeadProcess([Q])
      manifestOfADeadProcess(inside)
      chmodSync(Q, 0o555)
      try {
        expect(collectMountPoints('all')).toEqual([])
        expect(claims()).toContain(finishedOf(outer))
      } finally {
        chmodSync(Q, 0o755)
      }
      expect(collectMountPoints('all')).toEqual([...inside].reverse().concat(Q))
      expect(readdirSync(DIR)).toEqual([])
    },
  )

  it('keeps the directory a live manifest binds its mount points from', () => {
    const source = join(BASE, 'source')
    mkdirSync(source, { mode: 0o700 })
    manifestOfADeadProcess([], { sources: [source] })
    const live = started(
      manifestOfADeadProcess([], { sources: [source] }),
      thisProcess(),
    )
    expect(collectMountPoints('all')).toEqual([])
    started(live, aDeadProcess())
    expect(collectMountPoints('all')).toEqual([source])
  })

  it('leaves what a finished manifest names when it no longer looks like a mount point', () => {
    const written = join(BASE, 'written-to')
    writeFileSync(written, 'mine')
    chmodSync(written, 0o444)
    const linked = join(BASE, 'linked')
    leftover(linked)
    linkSync(linked, join(BASE, 'linked-again'))
    const pointer = join(BASE, 'pointer')
    leftover(join(BASE, 'pointed-at'))
    symlinkSync(join(BASE, 'pointed-at'), pointer)
    const inUse = join(BASE, 'directory-in-use')
    mkdirSync(inUse)
    writeFileSync(join(inUse, 'file'), '')
    const manifest = manifestOfADeadProcess([written, linked, pointer, inUse])
    expect(collectMountPoints('all')).toEqual([])
    for (const kept of [written, linked, pointer, inUse]) {
      expect(existsSync(kept)).toBe(true)
    }
    expect(existsSync(join(BASE, 'pointed-at'))).toBe(true)
    // None of them is a mount point any more, so the manifest has nothing
    // left to say.
    expect(existsSync(manifest)).toBe(false)
  })

  it("leaves a file, and an empty directory, that is somebody else's", () => {
    const directory = join(BASE, 'empty-directory')
    leftover(X)
    mkdirSync(directory)
    manifestOfADeadProcess([X, directory])
    // As another user's would look: nothing here can make one.
    const lstat = fs.lstatSync
    const spy = spyOn(fs, 'lstatSync').mockImplementation(((
      file: unknown,
      options: unknown,
    ) => {
      const stat = (lstat as (f: unknown, o: unknown) => fs.Stats)(
        file,
        options,
      )
      if (file === X || file === directory) {
        const theirs = Object.create(Object.getPrototypeOf(stat)) as fs.Stats
        return Object.assign(theirs, stat, { uid: stat.uid + 1 })
      }
      return stat
    }) as never)
    try {
      expect(collectMountPoints('all')).toEqual([])
    } finally {
      spy.mockRestore()
    }
    expect(existsSync(X)).toBe(true)
    expect(existsSync(directory)).toBe(true)
  })

  it('takes away what a killed process left half written, once it is old', () => {
    const old = [join(DIR, '4242-0123456789abcdef.json.tmp')]
    const young = join(DIR, '4243-0123456789abcdef.json.tmp')
    for (const file of [...old, young]) writeFileSync(file, '{}')
    const hoursAgo = new Date(Date.now() - 2 * 3600 * 1000)
    for (const file of old) utimesSync(file, hoursAgo, hoursAgo)
    collectMountPoints('all')
    for (const file of old) expect(existsSync(file)).toBe(false)
    // This one may be on its way into place.
    expect(existsSync(young)).toBe(true)
  })

  // ---- liveness is relative to a PID namespace ----
  //
  // /proc/PID is local to a PID namespace. From another namespace a running
  // sandbox's manifest looks like one a dead process left.

  it.each([
    ['written in another PID namespace', 'kept', { ns: 'pid:[1]' }],
    [
      'written in another PID namespace a long time ago',
      'kept',
      { ns: 'pid:[1]', created: Date.now() - 7 * 24 * 3600 * 1000 },
    ],
    ['that does not say where it was written', 'kept', { ns: undefined }],
    [
      'that does not say where it was written, from hours ago',
      'kept',
      { ns: undefined, created: Date.now() - 2 * 3600 * 1000 },
    ],
    ['written in this PID namespace', 'collected', {}],
  ] as const)(
    'a manifest %s, with no writer and no process on record to be seen, is %s',
    (_what, outcome, fields) => {
      leftover(X)
      const manifest = manifestOfADeadProcess([X], fields)
      collectMountPoints('all')
      expect(existsSync(X)).toBe(outcome === 'kept')
      expect(existsSync(manifest)).toBe(outcome === 'kept')
    },
  )

  it('is live for seven days when written in another PID namespace, or in none it records, and finished then', () => {
    // Nothing else ends one whose namespace is gone. Counted from the later of
    // the manifest and its record, which is when a sandbox last started.
    const DAYS = 24 * 60
    for (const ns of ['pid:[1]', undefined]) {
      leftover(X)
      const manifest = started(
        manifestOfADeadProcess([X], { ns }),
        aDeadProcess(),
      )
      for (const [written, recorded] of [
        [7 * DAYS - 1, 7 * DAYS + 1],
        [7 * DAYS + 1, 7 * DAYS - 1],
      ] as const) {
        aged(manifest, written)
        aged(recordOf(manifest), recorded)
        expect(live()).toEqual([X])
        expect(collectMountPoints('all')).toEqual([])
      }
      aged(recordOf(manifest), 7 * DAYS + 1)
      expect(live()).toEqual([])
      expect(collectMountPoints('all')).toEqual([X])
      expect(readdirSync(DIR)).toEqual([])

      // With no record, from the manifest alone.
      leftover(X)
      aged(manifestOfADeadProcess([X], { ns }), 7 * DAYS + 1)
      expect(collectMountPoints('all')).toEqual([X])
    }
  })

  // ---- what a pass that can judge says for those that cannot ----

  /** Has `manifest` finished by its name, as a pass that could judge it does. */
  function finished(manifest: string): string {
    const file = join(DIR, finishedOf(manifest))
    fs.renameSync(manifest, file)
    return file
  }

  it('keeps nothing for a manifest of another PID namespace that is finished by its name, and leaves that one to its own', () => {
    const Y = join(BASE, 'second.lock')
    leftover(X)
    leftover(Y)
    const theirs = finished(manifestOfADeadProcess([X, Y], { ns: 'pid:[1]' }))
    manifestOfADeadProcess([X])
    // A wrap still takes both for mount points, which they are.
    expect(named()).toEqual([X, Y].sort())
    expect(live()).toEqual([])
    expect(collectMountPoints('all')).toEqual([X])
    // What it names alone may be another file in that namespace's mounts.
    expect(existsSync(Y)).toBe(true)
    expect(readdirSync(DIR)).toEqual([basename(theirs)])
  })

  it('goes on no record for a manifest of another PID namespace that is finished by its name', () => {
    leftover(X)
    finished(manifestOfADeadProcess([X], { ns: 'pid:[1]' }))
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

  it('removes what such a manifest names alone once it is seven days old', () => {
    leftover(X)
    const theirs = finished(manifestOfADeadProcess([X], { ns: 'pid:[1]' }))
    aged(theirs, 7 * 24 * 60 - 1)
    expect(collectMountPoints('all')).toEqual([])
    aged(theirs, 7 * 24 * 60 + 1)
    expect(collectMountPoints('all')).toEqual([X])
    expect(readdirSync(DIR)).toEqual([])
  })

  it('does not say of a claim it cannot judge that it is finished', () => {
    leftover(X)
    const claim = claimed(manifestOfADeadProcess([X], { ns: 'pid:[1]' }))
    manifestOfADeadProcess([X])
    expect(collectMountPoints('all')).toEqual([])
    expect(existsSync(X)).toBe(true)
    expect(readdirSync(DIR)).toEqual([basename(claim)])
  })

  it('says so of a claim another pass left, and collects it', () => {
    leftover(X)
    const manifest = manifestOfADeadProcess([X])
    claimed(manifest)
    const seen: string[][] = []
    const removal = atTheRemovalOf(X, () => seen.push(claims()))
    try {
      expect(collectMountPoints('all')).toEqual([X])
    } finally {
      removal.restore()
    }
    expect(seen).toEqual([[finishedOf(manifest)]])
    expect(readdirSync(DIR)).toEqual([])
  })

  it("takes the record beside a manifest that is finished by its name for that one's", () => {
    leftover(X)
    const manifest = started(
      manifestOfADeadProcess([X], { ns: 'pid:[1]' }),
      aDeadProcess(),
    )
    const theirs = finished(manifest)
    aged(recordOf(manifest))
    expect(collectMountPoints('all')).toEqual([])
    expect(readdirSync(DIR).sort()).toEqual(
      [basename(theirs), basename(recordOf(manifest))].sort(),
    )
  })

  it('does not say so of a manifest it only takes for finished by its age: whoever can ask goes on asking', () => {
    leftover(X)
    const theirs = aged(
      manifestOfADeadProcess([X], { ns: 'pid:[1]' }),
      7 * 24 * 60 + 1,
    )
    const seen: string[][] = []
    const removal = atTheRemovalOf(X, () => seen.push(claims()))
    try {
      expect(collectMountPoints('all')).toEqual([X])
    } finally {
      removal.restore()
    }
    expect(seen).toEqual([[claimOf(theirs)]])
    expect(readdirSync(DIR)).toEqual([])
  })

  it('goes by what it finds, not by the name, where it can ask: a process on the record keeps what the manifest names', () => {
    leftover(X)
    const theirs = finished(started(manifestOfADeadProcess([X]), thisProcess()))
    manifestOfADeadProcess([X])
    expect(live()).toEqual([X])
    expect(collectMountPoints('all')).toEqual([])
    expect(existsSync(X)).toBe(true)
    expect(claims()).toEqual([basename(theirs)])
  })

  it('leaves a claim that could not be given the name to the next pass, with all it names', () => {
    // Dropped at the claim's name, with X kept for a manifest of another
    // namespace, a pass over that one would still take it for live.
    leftover(X)
    const manifest = manifestOfADeadProcess([X])
    const rename = fs.renameSync
    const spy = spyOn(fs, 'renameSync').mockImplementation(((
      from: string,
      to: string,
    ) => {
      if (to.endsWith('.finished')) {
        throw Object.assign(new Error('EIO'), { code: 'EIO' })
      }
      rename(from, to)
    }) as never)
    try {
      expect(collectMountPoints('all')).toEqual([])
    } finally {
      spy.mockRestore()
    }
    expect(existsSync(X)).toBe(true)
    expect(named()).toEqual([X])
    expect(collectMountPoints('all')).toEqual([X])
    expect(readdirSync(DIR)).toEqual([])
    expect(existsSync(manifest)).toBe(false)
  })

  it('finds by name one that the listing missed, and leaves its record', () => {
    // Renamed while the directory was being listed. Taken for a record without
    // a manifest it would be dropped, and a wrap would take X for the caller's.
    leftover(X)
    const manifest = started(
      manifestOfADeadProcess([X], { ns: 'pid:[1]' }),
      aDeadProcess(),
    )
    const theirs = finished(manifest)
    for (const look of [named, () => collectMountPoints('none')]) {
      const listing = missedByTheNextListing(basename(theirs))
      try {
        expect(look()).toEqual(look === named ? [X] : [])
      } finally {
        listing.restore()
      }
    }
    expect(existsSync(recordOf(manifest))).toBe(true)
  })

  it('leaves a path to neither of two clean-ups that cannot judge each other, each of which would keep it for the other', async () => {
    // Two processes that take themselves to be in PID namespaces of their own,
    // each with a manifest that names X. Each meets the other once it has made
    // its claims, and again once it has read and is about to remove or drop.
    leftover(X)
    const side = (me: string, other: string, ns: string): string => {
      const file = join(BASE, `${me}.ts`)
      const at = (who: string, where: string): string =>
        JSON.stringify(join(BASE, `${who}.${where}`))
      const meet = (where: string): string =>
        `fs.writeFileSync(${at(me, where)}, ''); while (!fs.existsSync(${at(other, where)})) Bun.sleepSync(1)`
      writeFileSync(
        file,
        [
          `import { spyOn } from 'bun:test'`,
          `import * as fs from 'node:fs'`,
          `const readlink = fs.readlinkSync`,
          `spyOn(fs, 'readlinkSync').mockImplementation((p, ...rest) =>`,
          `  p === '/proc/self/ns/pid' ? ${JSON.stringify(ns)} : readlink(p, ...rest))`,
          `const m = await import(${MODULE})`,
          `m.publishMountPointManifest([${JSON.stringify(X)}], [])`,
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
        ].join('\n'),
      )
      return file
    }
    const ended = [
      side('one', 'other', 'pid:[1]'),
      side('other', 'one', 'pid:[2]'),
    ].map(
      file =>
        new Promise<number | null>(resolve =>
          spawn(process.execPath, [file], {
            env: { ...process.env, TMPDIR: TMP },
            stdio: 'inherit',
            timeout: 10000,
            killSignal: 'SIGKILL',
          }).on('exit', resolve),
        ),
    )
    expect(await Promise.all(ended)).toEqual([0, 0])
    expect(existsSync(X)).toBe(false)
    expect(readdirSync(DIR)).toEqual([])
  }, 15000)

  /** Has every directory be on a file system of that kind, or not say. */
  function onAFileSystemOf(type: number | bigint | Error): {
    restore(): void
  } {
    const spy = spyOn(fs, 'statfsSync').mockImplementation((() => {
      if (type instanceof Error) throw type
      return { type }
    }) as never)
    // With what the library remembers of the answers.
    return {
      restore: () => {
        spy.mockRestore()
        forgetMountPointManifestDirectory()
      },
    }
  }

  it('is finished when written in another boot, whatever runs on its record and whichever PID namespace wrote it', () => {
    // The directory outlives a reboot, and no process does. On each kind of
    // file system that only this kernel reaches: tmpfs, ext4, xfs, btrfs,
    // overlayfs, zfs, f2fs. The kind may come as a bigint.
    for (const type of [
      ...[0x01021994, 0xef53, 0x58465342, 0x9123683e],
      ...[0x794c7630, 0x2fc12fc1, 0xf2f52010, BigInt(0xef53)],
    ]) {
      const kind = onAFileSystemOf(type)
      try {
        for (const ns of [OWN_NAMESPACE, 'pid:[1]', undefined]) {
          leftover(X)
          started(
            manifestOfADeadProcess([X], { ns, boot: 'another' }),
            thisProcess(),
          )
          expect(live()).toEqual([])
          expect(collectMountPoints('all')).toEqual([X])
          expect(readdirSync(DIR)).toEqual([])
        }
      } finally {
        kind.restore()
      }
    }
  })

  it('is not finished for its boot where another kernel may reach the directory, or that cannot be asked', () => {
    // There another boot id may be that of a host that is up, with the sandbox
    // running on it. NFS, 9p, FUSE and virtiofs, and a kind nobody has heard of.
    leftover(X)
    for (const type of [
      ...[0x6969, 0x01021997, 0x65735546, 0x12345678],
      Object.assign(new Error('ENOSYS'), { code: 'ENOSYS' }),
    ]) {
      const manifest = started(
        manifestOfADeadProcess([X], { boot: 'another' }),
        thisProcess(),
      )
      const kind = onAFileSystemOf(type)
      try {
        expect(live()).toEqual([X])
        expect(collectMountPoints('all')).toEqual([])
        expect(existsSync(X)).toBe(true)
      } finally {
        kind.restore()
      }
      rmSync(manifest)
      rmSync(recordOf(manifest))
    }
  })

  // Two hosts each in their initial PID namespace name that alike, so where
  // another kernel may reach the directory only an equal boot id says that a
  // manifest is this kernel's, and a pid on its record one to ask after here.
  const BOOT_ID = '/proc/sys/kernel/random/boot_id'
  const OWN_BOOT = isLinux ? readFileSync(BOOT_ID, 'utf8').trim() : ''

  for (const [what, fields, ownIsUnreadable] of [
    ['is of another boot', { boot: 'another' }, false],
    ['records no boot', {}, false],
    [
      'is of a boot this process cannot hold against its own',
      { boot: OWN_BOOT },
      true,
    ],
  ] as const) {
    it(`is live for seven days on a file system another kernel may reach when it ${what}, though of this PID namespace by name and with nobody on its record here`, () => {
      const left = (): string => {
        leftover(X)
        return started(manifestOfADeadProcess([X], fields), aDeadProcess())
      }
      const bothAged = (manifest: string, minutes: number): void => {
        aged(manifest, minutes)
        aged(recordOf(manifest), minutes)
        // A time is only ever set forward, and the library counts on that.
        forgetMountPointManifestDirectory()
      }
      forgetMountPointManifestDirectory()
      const spies = [onAFileSystemOf(0x6969)]
      if (ownIsUnreadable) {
        spies.push(failingCall('readFileSync', BOOT_ID, 'EACCES'))
      }
      try {
        const manifest = left()
        expect(live()).toEqual([X])
        expect(collectMountPoints('all')).toEqual([])
        bothAged(manifest, 6 * 24 * 60)
        expect(collectMountPoints('all')).toEqual([])
        bothAged(manifest, 7 * 24 * 60 + 1)
        expect(collectMountPoints('all')).toEqual([X])

        // Where only this kernel reaches: at once, as ever.
        spies.shift()!.restore()
        spies.push(onAFileSystemOf(0xef53))
        left()
        expect(collectMountPoints('all')).toEqual([X])
      } finally {
        spies.forEach(spy => spy.restore())
        forgetMountPointManifestDirectory()
      }
    })
  }

  it('is judged as ever on a file system another kernel may reach when it is of this boot: the same kernel', () => {
    for (const type of [0x6969, 0xef53]) {
      leftover(X)
      const manifest = started(
        manifestOfADeadProcess([X], { boot: OWN_BOOT }),
        thisProcess(),
      )
      const kind = onAFileSystemOf(type)
      try {
        expect(live()).toEqual([X])
        expect(collectMountPoints('all')).toEqual([])
        started(manifest, aDeadProcess())
        expect(collectMountPoints('all')).toEqual([X])
      } finally {
        kind.restore()
      }
    }
  })

  it('asks which kind of file system a directory is on once for a reading, however many manifests are in it', () => {
    for (let i = 0; i < 3; i++) {
      manifestOfADeadProcess([X], { boot: 'another' })
    }
    const statfs = spyOn(fs, 'statfsSync')
    try {
      expect(live()).toEqual([])
      expect(statfs.mock.calls.filter(([dir]) => dir === DIR)).toHaveLength(1)
    } finally {
      statfs.mockRestore()
    }
  })

  it('concludes nothing from the boot where it cannot tell its own', () => {
    leftover(X)
    started(manifestOfADeadProcess([X], { boot: 'another' }), thisProcess())
    forgetMountPointManifestDirectory()
    const failing = failingCall(
      'readFileSync',
      '/proc/sys/kernel/random/boot_id',
      'EACCES',
    )
    try {
      expect(live()).toEqual([X])
      expect(collectMountPoints('all')).toEqual([])
      expect(readFileSync(publish([X]), 'utf8')).not.toContain('"boot"')
    } finally {
      failing.restore()
    }
  })

  // ---- where the manifests are kept --------------------------------------

  it.if(BWRAP_CAN_NAMESPACE)(
    'are never kept under /dev, which the sandbox mounts afresh over them',
    () => {
      // The wrap mounts a new /dev after every bind: a manifest directory under
      // /dev could be neither bound nor kept out of the command's reach. Looked
      // at with a /dev/shm of the child's own, not the one every process has.
      const SHM = '/dev/shm'
      const launcher = ['bwrap', '--dev-bind', '/', '/', '--tmpfs', SHM, '--']
      const publishAndList = `const { readdirSync } = await import('node:fs')\nconsole.log(JSON.stringify({ manifest: m.publishMountPointManifest(['/nonexistent/x'], [])[0] ?? null, made: readdirSync(${JSON.stringify(SHM)}) }))`
      const fellBack = inAChild(publishAndList, {
        launcher,
        env: { XDG_RUNTIME_DIR: SHM },
      })
      expect(fellBack.status).toBe(0)
      const recorded = JSON.parse(fellBack.stdout) as {
        manifest: { file: string }
        made: string[]
      }
      expect(recorded.manifest.file.startsWith(`${TMP}/`)).toBe(true)
      expect(recorded.made).toEqual([])

      // With nowhere else to go it records nothing, rather than somewhere
      // bubblewrap cannot reach.
      const nowhere = inAChild(publishAndList, {
        launcher,
        env: { XDG_RUNTIME_DIR: undefined, TMPDIR: SHM },
      })
      expect(nowhere.status).toBe(0)
      expect(JSON.parse(nowhere.stdout)).toEqual({ manifest: null, made: [] })
    },
    15000,
  )

  it("are not kept behind a link planted at the directory's name, whose target is left as it was", () => {
    // The name is predictable and sits where sandboxed commands commonly write.
    // A link there is refused, not followed.
    const target = join(BASE, 'somebody-elses')
    mkdirSync(target)
    chmodSync(target, 0o755)
    symlinkSync(target, join(TMP, `srt-mount-points-${process.getuid!()}`))
    const published = inAChild(PUBLISH, { env: { XDG_RUNTIME_DIR: undefined } })
    expect(published.status).toBe(0)
    expect(statSync(target).mode & 0o777).toBe(0o755)
    expect(readdirSync(target)).toEqual([])
    // Recorded all the same, in a directory of this process's own.
    const manifest = JSON.parse(published.stdout) as { file: string }
    expect(dirname(manifest.file)).toMatch(
      new RegExp(`^${TMP}/srt-mount-points-[A-Za-z0-9]{6}$`),
    )
  })

  it.if(BWRAP_CAN_NAMESPACE && NOT_ROOT)(
    'go to a directory this process can write when the usual one is read-only from here',
    () => {
      // A process inside a sandbox sees the directory bound read-only. It is
      // ours in every other respect, and must not be settled on.
      const elsewhere = TMP
      const published = inAChild(PUBLISH, {
        launcher: [
          'bwrap',
          '--dev-bind',
          '/',
          '/',
          '--ro-bind',
          DIR,
          DIR,
          '--',
        ],
      })
      expect(published.status).toBe(0)
      const manifest = JSON.parse(published.stdout) as { file: string } | null
      expect(manifest).not.toBe(null)
      expect(dirname(manifest!.file)).not.toBe(DIR)
      expect(manifest!.file.startsWith(`${elsewhere}/`)).toBe(true)
    },
    15000,
  )

  // ---- which directory is believed ----
  //
  // A pass removes what it finds named in the directory, so the directory has
  // to be the user's alone, and is looked at again at every use.

  /** Has `file` look like another user's: nothing here can make one. */
  function asSomebodyElses(file: string): { restore(): void } {
    const inode = lstatSync(file).ino
    const spies = (['lstatSync', 'fstatSync'] as const).map(name => {
      const real = fs[name] as (f: unknown, o: unknown) => fs.Stats
      return spyOn(fs, name).mockImplementation(((
        target: unknown,
        options: unknown,
      ) => {
        const stat = real(target, options)
        if (stat.ino !== inode) return stat
        const theirs = Object.create(
          Object.getPrototypeOf(stat) as object,
        ) as fs.Stats
        return Object.assign(theirs, stat, { uid: stat.uid + 1 })
      }) as never)
    })
    return { restore: () => spies.forEach(spy => spy.mockRestore()) }
  }

  /** Where this process, having settled on nothing yet, records X. */
  function recordedIn(): string {
    forgetMountPointManifestDirectory()
    return dirname(publish([X]))
  }

  it("are not kept in a directory that is somebody else's", () => {
    const theirs = asSomebodyElses(DIR)
    try {
      expect(recordedIn()).toBe(
        join(tmpdir(), `srt-mount-points-${process.getuid!()}`),
      )
    } finally {
      theirs.restore()
      forgetMountPointManifestDirectory()
    }
    expect(readdirSync(DIR)).toEqual([])
  })

  it("are kept in a directory that others could read or write only once it has been made the user's alone", () => {
    chmodSync(DIR, 0o755)
    expect(recordedIn()).toBe(DIR)
    expect(statSync(DIR).mode & 0o777).toBe(0o700)
  })

  it("are not kept in a directory that cannot be made the user's alone", () => {
    chmodSync(DIR, 0o750)
    const spy = spyOn(fs, 'fchmodSync').mockImplementation((() => {
      throw Object.assign(new Error('EPERM'), { code: 'EPERM' })
    }) as never)
    try {
      expect(recordedIn()).not.toBe(DIR)
    } finally {
      spy.mockRestore()
      forgetMountPointManifestDirectory()
    }
    expect(readdirSync(DIR)).toEqual([])
  })

  it('are kept in a directory that is looked at again at every use', () => {
    expect(recordedIn()).toBe(DIR)
    rmSync(DIR, { recursive: true })

    // Opened up since: made the user's alone again before it is used.
    mkdirSync(DIR, { mode: 0o777 })
    chmodSync(DIR, 0o777)
    expect(dirname(publish([X]))).toBe(DIR)
    expect(statSync(DIR).mode & 0o777).toBe(0o700)
    rmSync(DIR, { recursive: true })

    // Swapped for a link since: not followed, and what it leads to left alone.
    const target = join(BASE, 'somebody-elses')
    mkdirSync(target, { mode: 0o700 })
    symlinkSync(target, DIR)
    try {
      expect(dirname(publish([X]))).not.toBe(DIR)
      expect(readdirSync(target)).toEqual([])
    } finally {
      rmSync(DIR)
      mkdirSync(DIR, { mode: 0o700 })
      forgetMountPointManifestDirectory()
    }
  })

  // ---- several directories ----
  //
  // Where the manifests go follows from the user id first, so that processes
  // with different environments read each other's, and a process believes
  // more directories than the one it writes in.

  describe('in several directories', () => {
    let PLACES: string[] // under /var/tmp, /run/user/UID and /tmp, none made
    let NAMED: string[] // what the environment names
    let Y: string

    beforeEach(() => {
      PLACES = makePlaces(join(BASE, 'root'))
      NAMED = [DIR, join(tmpdir(), `srt-mount-points-${process.getuid!()}`)]
      Y = join(BASE, 'second.lock')
      setMountPointManifestPlacesForTesting(join(BASE, 'root'))
    })

    afterEach(() => {
      setMountPointManifestPlacesForTesting('/nonexistent')
      rmSync(NAMED[1]!, { recursive: true, force: true })
    })

    /** What `make` makes, in `place`, which is made, instead of in DIR. */
    function at<T>(place: string, make: () => T): T {
      mkdirSync(place, { recursive: true, mode: 0o700 })
      chmodSync(place, 0o700)
      DIR = place
      try {
        return make()
      } finally {
        DIR = runtime.manifestDir()
      }
    }

    /** Has something else be at each of those names. */
    function taken(places: string[]): void {
      for (const place of places) {
        rmSync(place, { recursive: true, force: true })
        writeFileSync(place, '')
      }
    }

    it("are written in the first that can be made the user's alone: /var/tmp, /run/user/UID, /tmp, then as the environment says", () => {
      const order = [...PLACES, ...NAMED]
      try {
        for (const place of order) {
          expect(recordedIn()).toBe(place)
          expect(lstatSync(place).mode & 0o777).toBe(0o700)
          collectMountPoints('all')
          taken([place])
        }
        expect(order).not.toContain(recordedIn())
      } finally {
        collectMountPoints('all')
        order.forEach(place => rmSync(place))
        mkdirSync(DIR, { mode: 0o700 })
      }
    })

    it.each([
      ['/var/tmp', 0, 2],
      ['/tmp', 2, 0],
    ] as const)(
      'are one directory where %s is a link to the other, read once and collected in like any',
      (_, link, target) => {
        // A pass cannot go on record twice under one name, and off the record it
        // removes nothing.
        rmSync(dirname(PLACES[link]!), { recursive: true })
        symlinkSync(dirname(PLACES[target]!), dirname(PLACES[link]!))
        forgetMountPointManifestDirectory()
        leftover(X)
        leftover(Y)
        at(PLACES[target]!, () => manifestOfADeadProcess([X]))
        expect(dirname(publish([Y]))).toBe(PLACES[0]!)
        expect(named()).toEqual([X, Y].sort())
        expect(live()).toEqual([Y])
        expect(collectMountPoints('all').sort()).toEqual([X, Y].sort())
        expect(readdirSync(PLACES[target]!)).toEqual([])
        // Both names are kept out of a command's reach all the same.
        expect(mountPointManifestDirectories()).toEqual(
          expect.arrayContaining([PLACES[0]!, PLACES[2]!]),
        )
      },
    )

    it.each([
      ['names a mount point', ['absent.lock']],
      ['names none', []],
    ])(
      'are bound once where two of the names lead to one place, by a wrap that %s',
      async (_, denied) => {
        rmSync(dirname(PLACES[0]!), { recursive: true })
        symlinkSync(dirname(PLACES[2]!), dirname(PLACES[0]!))
        forgetMountPointManifestDirectory()
        const command = await wrapCommandWithSandboxLinux({
          command: 'true',
          needsNetworkRestriction: false,
          writeConfig: {
            allowOnly: [BASE],
            denyWithinAllow: denied.map(name => join(BASE, name)),
          },
        })
        cleanupBwrapMountPoints({ force: true })
        expect(
          mountsOf(command).filter(mount => mount.endsWith(` ${PLACES[2]!}`)),
        ).toHaveLength(1)
      },
    )

    it('goes by the name it can be written at where the other is read-only, as a read-only bind of it is', () => {
      rmSync(dirname(PLACES[0]!), { recursive: true })
      symlinkSync(dirname(PLACES[2]!), dirname(PLACES[0]!))
      // This process writes elsewhere, and knows neither name for its own.
      expect(dirname(publish([Y]))).toBe(PLACES[0]!)
      collectMountPoints('all')
      forgetMountPointManifestDirectory()
      leftover(X)
      at(PLACES[2]!, () => manifestOfADeadProcess([X]))
      const access = fs.accessSync
      const spy = spyOn(fs, 'accessSync').mockImplementation(((
        file: unknown,
        mode: unknown,
      ) => {
        if (file === PLACES[0]) {
          throw Object.assign(new Error('EROFS'), { code: 'EROFS' })
        }
        ;(access as (f: unknown, m: unknown) => void)(file, mode)
      }) as never)
      try {
        expect(collectMountPoints('all')).toEqual([X])
      } finally {
        spy.mockRestore()
      }
      expect(readdirSync(PLACES[2]!)).toEqual([])
    })

    it('goes by the name it writes under where that is the later of the two', () => {
      // Settled on /tmp while /var/tmp could not be written.
      taken([PLACES[0]!, dirname(PLACES[1]!)])
      leftover(Y)
      expect(dirname(publish([Y]))).toBe(PLACES[2]!)
      rmSync(dirname(PLACES[0]!), { recursive: true })
      symlinkSync(dirname(PLACES[2]!), dirname(PLACES[0]!))
      expect(collectMountPoints('all')).toEqual([Y])
      expect(readdirSync(PLACES[2]!)).toEqual([])
    })

    it('are believed, collected in and bound, but not written, under a /run/user/UID that is open to others', () => {
      // Where that is a write root a sandboxed command can open it up, and
      // must not have other processes read less by that.
      leftover(X)
      const relied = at(PLACES[1]!, () =>
        started(manifestOfADeadProcess([X]), thisProcess()),
      )
      at(PLACES[2]!, () => manifestOfADeadProcess([X]))
      taken([PLACES[0]!])
      chmodSync(dirname(PLACES[1]!), 0o777)
      expect(dirname(publish([Y]))).toBe(PLACES[2]!)
      expect(named()).toEqual([X, Y].sort())
      expect(live()).toEqual([X])
      expect(collectMountPoints('all')).toEqual([])
      expect(existsSync(X)).toBe(true)
      started(relied, aDeadProcess())
      expect(collectMountPoints('all')).toEqual([X])
      expect(readdirSync(PLACES[1]!)).toEqual([])

      // Made, too, so that the command cannot.
      rmSync(PLACES[1]!, { recursive: true })
      expect(mountPointManifestDirectories()).toContain(PLACES[1])
      expect(lstatSync(PLACES[1]!).mode & 0o40777).toBe(0o40700)

      // It is none to write in: with no other of the three, what the
      // environment names is believed.
      taken([PLACES[2]!])
      forgetMountPointManifestDirectory()
      at(NAMED[1]!, () => manifestOfADeadProcess([Y]))
      expect(named()).toEqual([Y])
    })

    for (const [what, spoil] of [
      [
        'a link',
        (dir: string) => {
          fs.renameSync(dir, `${dir}-moved`)
          symlinkSync(`${dir}-moved`, dir)
        },
      ],
      ["somebody else's", (dir: string) => asSomebodyElses(dir)],
    ] as const) {
      it(`are neither written nor believed under a /run/user/UID that is ${what}`, () => {
        leftover(X)
        at(PLACES[1]!, () => manifestOfADeadProcess([X]))
        taken([PLACES[0]!])
        const spoiled = spoil(dirname(PLACES[1]!))
        try {
          expect(dirname(publish([Y]))).toBe(PLACES[2]!)
          expect(mountPointManifestDirectories()).not.toContain(PLACES[1])
          expect(named()).toEqual([Y])
          expect(collectMountPoints('all')).toEqual([])
        } finally {
          spoiled?.restore()
        }
      })
    }

    for (const [what, squat] of [
      [
        'a link',
        (place: string) => {
          fs.renameSync(place, `${place}-moved`)
          symlinkSync(`${place}-moved`, place)
        },
      ],
      ["somebody else's", (place: string) => asSomebodyElses(place)],
    ] as const) {
      for (const [system, i, next] of [
        ['/var/tmp', 0, 1],
        ['/tmp', 2, 0],
      ] as const) {
        it(`are neither written, believed nor bound at the name in ${system} when that is ${what}`, () => {
          // The name is predictable, in a directory anyone may write.
          leftover(X)
          at(PLACES[i]!, () => manifestOfADeadProcess([X]))
          const squatted = squat(PLACES[i]!)
          try {
            expect(dirname(publish([Y]))).toBe(PLACES[next]!)
            expect(mountPointManifestDirectories()).not.toContain(PLACES[i])
            expect(named()).toEqual([Y])
            expect(collectMountPoints('all')).toEqual([])
          } finally {
            squatted?.restore()
          }
        })
      }
    }

    it('are made, every one, for a wrap to bind, and none by a mere look', () => {
      rmSync(DIR, { recursive: true })
      expect(named()).toEqual([])
      expect(live()).toEqual([])
      expect([...PLACES, ...NAMED].filter(existsSync)).toEqual([])
      expect(mountPointManifestDirectories()).toEqual([...PLACES, ...NAMED])
      for (const place of [...PLACES, ...NAMED]) {
        expect(lstatSync(place).mode & 0o40777).toBe(0o40700)
      }
    })

    it('are made before a wrap reads any, which believes nothing the environment names that no clean-up would', async () => {
      // Forged, or left by a process that could write nowhere else: it names a
      // directory of the user's own. And what is no manifest.
      const own = join(BASE, 'own')
      mkdirSync(own)
      at(NAMED[1]!, () => manifestOfADeadProcess([own]))
      writeFileSync(join(NAMED[0]!, '4242-00.json'), '{}')
      const command = await wrapCommandWithSandboxLinux({
        command: 'true',
        needsNetworkRestriction: false,
        writeConfig: {
          allowOnly: [BASE],
          denyWithinAllow: [join(own, 'absent.lock')],
        },
      })
      expect(namedBy(command)).toEqual([join(own, 'absent.lock')])
      cleanupBwrapMountPoints({ force: true })
      expect(existsSync(own)).toBe(true)
    })

    it('are believed in each of the three, whichever this process writes in', () => {
      for (const place of PLACES) {
        leftover(X)
        const relied = at(place, () =>
          started(manifestOfADeadProcess([X]), thisProcess()),
        )
        PLACES.forEach(each => at(each, () => manifestOfADeadProcess([X])))
        expect(named()).toEqual([X])
        expect(live()).toEqual([X])
        expect(collectMountPoints('all')).toEqual([])
        expect(existsSync(X)).toBe(true)
        started(relied, aDeadProcess())
        expect(collectMountPoints('all')).toEqual([X])
        expect(PLACES.flatMap(each => readdirSync(each))).toEqual([])
      }
    })

    it('are believed where the environment says only by a process that can write in none of the three, or has settled there', () => {
      // Only processes with that environment keep those out of a sandbox's
      // reach.
      leftover(X)
      const planted = NAMED.map(place =>
        at(place, () => manifestOfADeadProcess([X])),
      )
      const junk = join(NAMED[1]!, '4242-00.json')
      writeFileSync(junk, '{}')
      // A clean-up makes the first of the three before it looks.
      expect(collectMountPoints('all')).toEqual([])
      expect(named()).toEqual([])
      expect(live()).toEqual([])
      expect(planted.filter(existsSync)).toEqual(planted)

      // Both of them, with none of the three to write in.
      taken(PLACES)
      forgetMountPointManifestDirectory()
      expect(named()).toBeUndefined()
      rmSync(junk)
      rmSync(planted[0]!)
      expect(named()).toEqual([X])
      expect(dirname(publish([Y]))).toBe(NAMED[0]!)

      // Only the one it writes in, once one of the three will do again.
      PLACES.forEach(place => rmSync(place))
      mkdirSync(PLACES[2]!, { mode: 0o700 })
      expect(named()).toEqual([Y])
    })

    it('puts everything in doubt by what cannot be read in any of them', () => {
      for (const place of PLACES) {
        leftover(X)
        PLACES.forEach(each => at(each, () => manifestOfADeadProcess([X])))
        const junk = join(place, '4242-00.json')
        writeFileSync(junk, '{}')
        expect(named()).toBeUndefined()
        expect(live()).toBeUndefined()
        expect(collectMountPoints('all')).toEqual([])
        expect(PLACES.flatMap(each => at(each, claims))).toEqual([])
        rmSync(junk)
        expect(collectMountPoints('all')).toEqual([X])
      }
    })

    it("goes by the file system a manifest's own directory is on for what its boot says", () => {
      leftover(X)
      leftover(Y)
      for (const [place, mountPoint] of [
        [PLACES[0]!, X],
        [PLACES[2]!, Y],
      ] as const) {
        at(place, () =>
          started(
            manifestOfADeadProcess([mountPoint], { boot: 'another' }),
            thisProcess(),
          ),
        )
      }
      const spy = spyOn(fs, 'statfsSync').mockImplementation(((
        dir: string,
      ) => ({
        type: dir === PLACES[2] ? 0x6969 : 0xef53,
      })) as never)
      try {
        expect(live()).toEqual([Y])
        expect(collectMountPoints('all')).toEqual([X])
      } finally {
        spy.mockRestore()
      }
    })

    it('removes nothing when one of them cannot be looked at', () => {
      // Not even what this process could not record and would remove on its
      // own word.
      leftover(X)
      leftover(Y)
      at(PLACES[0]!, () => manifestOfADeadProcess([X]))
      unrecorded([Y])
      mkdirSync(PLACES[2]!, { mode: 0o700 })
      const look = failingCall('lstatSync', PLACES[2]!, 'EIO')
      try {
        expect(named()).toBeUndefined()
        expect(live()).toBeUndefined()
        expect(collectMountPoints('all')).toEqual([])
      } finally {
        look.restore()
      }
      expect(collectMountPoints('all').sort()).toEqual([X, Y].sort())
    })

    it('are not left unbound when one of them cannot be looked at: no command is handed out', async () => {
      // One that this process binds and does not believe, so that no reading
      // of its own is in doubt: a process that can write none of the first
      // three believes it, with the command in it.
      mountPointManifestDirectories()
      const look = failingCall('lstatSync', NAMED[1]!, 'EIO')
      try {
        expect(named()).toEqual([])
        expect(() => mountPointManifestDirectories()).toThrow('EIO')
        expect(
          await refusal(
            wrapCommandWithSandboxLinux({
              command: 'true',
              needsNetworkRestriction: false,
              writeConfig: { allowOnly: [BASE], denyWithinAllow: [] },
            }),
          ),
        ).toBe('mount_points_unreadable')
      } finally {
        look.restore()
      }
      expect(mountPointManifestDirectories()).toContain(NAMED[1]!)
    })

    it.each([
      ['/run/user/UID, which one of them is in', () => dirname(PLACES[1]!)],
      [
        'the one only this process knows',
        () => {
          taken([...PLACES, ...NAMED])
          return recordedIn()
        },
      ],
    ])('cannot be told while %s cannot be looked at', (_, which) => {
      try {
        const look = failingCall('lstatSync', which(), 'EIO')
        try {
          expect(() => mountPointManifestDirectories()).toThrow('EIO')
        } finally {
          look.restore()
        }
      } finally {
        collectMountPoints('all')
        removePrivateManifestDirectory()
        rmSync(DIR, { recursive: true, force: true })
        mkdirSync(DIR, { mode: 0o700 })
      }
    })

    it('reads every directory again once it has claimed, not only where it claimed', () => {
      // Published in another directory since the first reading, and claimed
      // there by another pass that its sandbox got past.
      leftover(X)
      at(PLACES[0]!, () => manifestOfADeadProcess([X]))
      mkdirSync(PLACES[2]!, { mode: 0o700 })
      let claim: string | undefined
      const pass = duringTheNextPass(() => {
        claim = at(PLACES[2]!, () =>
          claimed(started(manifestOfADeadProcess([X]), thisProcess())),
        )
      })
      try {
        expect(collectMountPoints('all')).toEqual([])
      } finally {
        pass.restore()
      }
      expect(existsSync(X)).toBe(true)
      expect(existsSync(claim!)).toBe(true)
    })

    it('lists every directory again before every removal, one made since the pass began too', () => {
      leftover(X)
      leftover(Y)
      at(PLACES[0]!, () => manifestOfADeadProcess([X, Y]))
      const removal = atTheRemovalOf(Y, () =>
        at(PLACES[2]!, () =>
          manifestOfADeadProcess([X], {
            pid: process.pid,
            created: Date.now(),
          }),
        ),
      )
      try {
        expect(collectMountPoints('all')).toEqual([Y])
      } finally {
        removal.restore()
      }
      expect(existsSync(X)).toBe(true)
    })

    it('lists the first of them last before a removal, where most is published', () => {
      leftover(X)
      leftover(Y)
      at(PLACES[0]!, () => manifestOfADeadProcess([X, Y]))
      mkdirSync(PLACES[2]!, { mode: 0o700 })
      const readdir = fs.readdirSync
      let listings = 0
      const spy = spyOn(fs, 'readdirSync').mockImplementation(((
        ...args: Parameters<typeof fs.readdirSync>
      ) => {
        // Two readings, then the listing before the first removal.
        if (args[0] === PLACES[2] && ++listings === 3) {
          at(PLACES[0]!, () =>
            manifestOfADeadProcess([X, Y], { pid: process.pid }),
          )
        }
        return readdir(...args)
      }) as never)
      try {
        expect(collectMountPoints('all')).toEqual([])
      } finally {
        spy.mockRestore()
      }
    })

    it('answers a wrap with an earlier reading only while none of them lists anything new', () => {
      at(PLACES[0]!, () => manifestOfADeadProcess([X]))
      const first = reads(namedMountPoints())
      expect(namedMountPoints(first)).toBe(first)
      at(PLACES[2]!, () => manifestOfADeadProcess([Y]))
      expect([...reads(namedMountPoints(first)).paths].sort()).toEqual(
        [X, Y].sort(),
      )
    })

    it.if(BWRAP_CAN_NAMESPACE && NOT_ROOT)(
      'keeps all that is named in a directory that is read-only from here, and writes in the next',
      () => {
        // As /var/tmp is in a read-only container, and every place is to a
        // process inside another sandbox: nothing can be claimed there.
        const Z = join(BASE, 'third.lock')
        ;[X, Y, Z].forEach(leftover)
        const [manifest, claim] = at(PLACES[0]!, () => [
          manifestOfADeadProcess([X]),
          claimed(manifestOfADeadProcess([Y])),
        ])
        at(PLACES[2]!, () => manifestOfADeadProcess([X, Y, Z]))
        const looked = inAChild(
          [
            `m.setMountPointManifestPlacesForTesting(${JSON.stringify(join(BASE, 'root'))})`,
            `const named = [...m.namedMountPoints().paths].sort()`,
            `const removed = m.collectMountPoints('all')`,
            `console.log(JSON.stringify({ named, removed, file: m.publishMountPointManifest(['/nonexistent/x'], [])[0].file }))`,
          ].join('\n'),
          {
            launcher: [
              ...['bwrap', '--dev-bind', '/', '/'],
              ...['--ro-bind', PLACES[0]!, PLACES[0]!, '--'],
            ],
          },
        )
        expect(looked.status).toBe(0)
        expect(JSON.parse(looked.stdout)).toEqual({
          named: [X, Y, Z].sort(),
          removed: [Z],
          file: expect.stringContaining(`${PLACES[1]}/`),
        })
        expect([X, Y, manifest!, claim!].filter(existsSync)).toHaveLength(4)
      },
      15000,
    )
  })

  // ---- with nowhere to record ----
  //
  // No other process can know of these mount points, so the process that made
  // them removes them itself, once none of its wraps is outstanding.

  it.if(NOT_ROOT)(
    'keeps in memory what it could record nowhere, and removes it at its own clean-up',
    () => {
      const directory = join(BASE, 'empty-directory')
      const source = join(BASE, 'source')
      const readOnly = join(BASE, 'read-only-tmp')
      leftover(X)
      mkdirSync(directory)
      mkdirSync(source, { mode: 0o700 })
      mkdirSync(readOnly, { mode: 0o500 })
      const nowhere = inAChild(
        [
          `const at = ${JSON.stringify({ X, directory, source })}`,
          `const { existsSync } = await import('node:fs')`,
          `const there = () => [at.X, at.directory, at.source].map(p => existsSync(p))`,
          `const published = m.publishMountPointManifest([at.X, at.directory], [at.source])[0] ?? null`,
          `const named = [...m.namedMountPoints().paths].sort()`,
          `const held = [...m.liveMountPoints()].sort()`,
          `const some = { removed: m.collectMountPoints('none'), there: there() }`,
          `const all = { removed: m.collectMountPoints('all').sort(), there: there() }`,
          `console.log(JSON.stringify({ published, named, held, some, all, again: m.collectMountPoints('all') }))`,
        ].join('\n'),
        // No runtime directory, and nothing can be made under the temp dir.
        { env: { XDG_RUNTIME_DIR: undefined, TMPDIR: readOnly } },
      )
      expect(nowhere.status).toBe(0)
      expect(JSON.parse(nowhere.stdout)).toEqual({
        published: null,
        named: [X, directory].sort(),
        held: [X, directory].sort(),
        some: { removed: [], there: [true, true, true] },
        all: {
          removed: [X, directory, source].sort(),
          there: [false, false, false],
        },
        again: [],
      })
    },
    15000,
  )

  it('keeps what it could not record while a manifest of another process names it, where there is a directory to go by', () => {
    // The manifest could not be written, as with the temp dir full, which a
    // sandboxed command can bring about.
    const Y = join(BASE, 'second.lock')
    leftover(X)
    leftover(Y)
    started(manifestOfADeadProcess([X]), thisProcess())
    unrecorded([X, Y])
    expect(named()).toEqual([X, Y].sort())
    expect(collectMountPoints('none')).toEqual([])
    expect(collectMountPoints('all')).toEqual([Y])
    expect(existsSync(X)).toBe(true)
  })

  it.each([
    ['had no part in making', undefined],
    ['had made itself', 'the first'],
    ['had no part in making, and the other made,', 'the second'],
  ])(
    'keeps what one wrap %s and could not record, while another wrap that names it too is cleaned up after',
    (_, madeBy) => {
      // The sandbox of the first may be running over it, and only this process
      // knows: the manifest of the second is not all that names it.
      const source = join(BASE, 'empty')
      const planOf = (wrap: string): void => {
        if (wrap !== madeBy) return
        keepTrackOfMountPoint(X)
        keepTrackOfMountSource(source)
      }
      leftover(X)
      mkdirSync(source, { mode: 0o700 })
      planOf('the first')
      unrecorded([X], [source])
      planOf('the second')
      publishMountPointManifest([X], [source], 'the second')
      expect(collectMountPoints({ commandKey: 'the second' })).toEqual([])
      expect([X, source].filter(existsSync)).toEqual([X, source])
      expect(named()).toEqual([X])
      expect(collectMountPoints('all').sort()).toEqual([X, source].sort())
    },
  )

  it('publishes no manifest that it would not read', () => {
    const paths = (count: number): string[] =>
      Array.from({ length: count }, (_, i) =>
        join(BASE, 'x'.repeat(80), String(i).padStart(6, '0')),
      )
    // Each with its quotes and a comma, in a mebibyte less the other fields.
    const fit = Math.floor((1024 * 1024 - 400) / (paths(1)[0]!.length + 3))
    expect(publishMountPointManifest(paths(fit + 10), [])).toBe('too-large')
    // Nothing is written, or kept in memory: no command comes of that wrap.
    expect(readdirSync(DIR)).toEqual([])
    expect(named()).toEqual([])
    // What it does publish, it reads.
    expect(statSync(publish(paths(fit))).size).toBeGreaterThan(1_000_000)
    expect(named()?.length).toBe(fit)
    leftover(X)
    manifestOfADeadProcess([X])
    expect(collectMountPoints('none')).toEqual([X])
  })

  // ---- what is read as a manifest ----
  //
  // Only a regular file of the user's, of a size a manifest can have, is read:
  // a link is not followed and a FIFO is not opened. What is there instead
  // names paths nobody can list, so while it may have a sandbox under it
  // nothing at all is removed.

  /**
   * `minutes` old, two hours unless said: past the hour for which what is no
   * manifest counts as live.
   */
  function aged(file: string, minutes = 120): string {
    const then = new Date(Date.now() - minutes * 60 * 1000)
    lutimesSync(file, then, then)
    return file
  }

  /** What a manifest of a dead process naming `paths` holds. */
  function finishedManifestText(paths: string[]): string {
    const file = manifestOfADeadProcess(paths)
    const text = readFileSync(file, 'utf8')
    rmSync(file)
    return text
  }

  // The last says what can be a manifest of no version, as a crash leaves one
  // that was not on disk yet: it counts for the grace, not for the hour.
  const notAManifest: [
    string,
    (name: string, paths: string[]) => void,
    'of no version'?,
  ][] = [
    [
      'a link to a manifest kept somewhere else',
      (name, paths) => {
        const elsewhere = join(BASE, 'elsewhere.json')
        writeFileSync(elsewhere, finishedManifestText(paths), { mode: 0o600 })
        symlinkSync(elsewhere, name)
      },
    ],
    [
      'a manifest of more than a mebibyte',
      (name, paths) =>
        writeFileSync(
          name,
          finishedManifestText(paths) + ' '.repeat(1024 * 1024),
          { mode: 0o600 },
        ),
    ],
    [
      'a manifest cut short',
      (name, paths) =>
        writeFileSync(name, finishedManifestText(paths).slice(0, -1)),
      'of no version',
    ],
    [
      'a manifest of a later version without a field this one goes by',
      (name, paths) =>
        writeFileSync(
          name,
          finishedManifestText(paths)
            .replace('"version":1', '"version":2')
            .replace('"sources":[]', '"origins":[]'),
        ),
    ],
    ['an empty file', name => writeFileSync(name, ''), 'of no version'],
    ['a directory', name => mkdirSync(name)],
    [
      'a FIFO nobody writes to',
      name => expect(spawnSync('mkfifo', [name]).status).toBe(0),
    ],
  ]
  if (NOT_ROOT) {
    notAManifest.push([
      'a manifest its owner may not read',
      (name, paths) =>
        writeFileSync(name, finishedManifestText(paths), { mode: 0 }),
    ])
  }
  for (const [what, plant, ofNoVersion] of notAManifest) {
    it(`removes nothing beside ${what} until it is ${ofNoVersion ? 'half a second' : 'an hour'} old, and passes over it then`, () => {
      const Y = join(BASE, 'second.lock')
      leftover(X)
      leftover(Y)
      const junk = join(DIR, '4242-0123456789abcdef.json')
      plant(junk, [X])
      manifestOfADeadProcess([Y])
      // In a process of its own: opening a FIFO to read waits for a writer, on
      // the one thread there is.
      const look = (): unknown => {
        const looked = inAChild(
          [
            `const list = set => (set === undefined ? 'cannot tell' : [...set])`,
            `console.log(JSON.stringify({ named: list(m.namedMountPoints()?.paths), held: list(m.liveMountPoints()), removed: m.collectMountPoints('all') }))`,
          ].join('\n'),
        )
        expect(looked.status).toBe(0)
        return JSON.parse(looked.stdout)
      }
      // It names nothing that can be read, and may name anything.
      const inDoubt = { named: 'cannot tell', held: 'cannot tell', removed: [] }
      // Not yet as old as the child takes to look, nor just short of the hour.
      aged(junk, ofNoVersion ? -1 : 59)
      expect(look()).toEqual(inDoubt)

      // Nor while a process is on its record, however old it is.
      aged(junk)
      writeFileSync(recordOf(junk), statLine(thisProcess()))
      expect(look()).toEqual(inDoubt)

      // A record that names no process to ask after puts nothing off.
      aged(junk, ofNoVersion ? 1 : 61)
      writeFileSync(recordOf(junk), 'ended\n')
      expect(look()).toEqual({ named: [Y], held: [], removed: [Y] })
      expect(existsSync(X)).toBe(true)
      // Dropped, where it is a file that can be.
      expect(existsSync(junk)).toBe(what === 'a directory')
    }, 30000)
  }

  it.each(['version', 'pid', 'start', 'created', 'paths', 'sources'])(
    'does not take for a manifest what holds no `%s`',
    field => {
      // A later version is read by the fields this one knows, so each of them
      // has to be there: read without one, it would name nothing or be live
      // for nobody.
      const Y = join(BASE, 'second.lock')
      leftover(X)
      leftover(Y)
      manifestOfADeadProcess([X], { [field]: undefined })
      manifestOfADeadProcess([Y])

      expect(named()).toBeUndefined()
      expect(liveMountPoints()).toBeUndefined()
      expect(collectMountPoints('all')).toEqual([])
      expect(existsSync(X)).toBe(true)
      expect(existsSync(Y)).toBe(true)
    },
  )

  it("removes nothing beside a manifest that is somebody else's until it is an hour old, and passes over it then", () => {
    const Y = join(BASE, 'second.lock')
    leftover(X)
    leftover(Y)
    const junk = manifestOfADeadProcess([X])
    manifestOfADeadProcess([Y])
    const theirs = asSomebodyElses(junk)
    try {
      expect(named()).toBeUndefined()
      expect(collectMountPoints('all')).toEqual([])
      // An hour, not less and not much more.
      aged(junk, 59)
      expect(named()).toBeUndefined()
      expect(collectMountPoints('all')).toEqual([])
      aged(junk, 61)
      expect(collectMountPoints('all')).toEqual([Y])
    } finally {
      theirs.restore()
    }
    expect(existsSync(X)).toBe(true)
  })

  // ---- which mount points a running sandbox relies on ----
  //
  // A caller that removes paths itself after a command can ask first which to
  // leave out. What it is told to leave out is never more than an empty
  // placeholder.

  /** The set, as a sorted list; `undefined` where it cannot tell. */
  function live(): string[] | undefined {
    const set = liveMountPoints()
    return set && [...set].sort()
  }

  it('holds a mount point while a live manifest names it, file or directory, and no other path', () => {
    const directory = join(BASE, 'empty-directory')
    const other = join(BASE, 'other.lock')
    leftover(X)
    mkdirSync(directory)
    leftover(other)
    // Of this process, and not released: live.
    const manifest = publish([X, directory, join(BASE, 'never-there')])

    expect(live()).toEqual([X, directory].sort())
    // Asking takes nothing away.
    expect(existsSync(X)).toBe(true)
    expect(existsSync(manifest)).toBe(true)

    expect(collectMountPoints('all').sort()).toEqual([X, directory].sort())
    expect(live()).toEqual([])
  })

  it('no longer holds a path once something has been written to it, though a live manifest still names it', () => {
    leftover(X)
    publishMountPointManifest([X], [])
    expect(live()).toEqual([X])

    chmodSync(X, 0o644)
    writeFileSync(X, 'x')
    chmodSync(X, 0o444)
    expect(live()).toEqual([])
  })

  it('holds nothing a live manifest names that does not look like a mount point any more', () => {
    const linked = join(BASE, 'linked')
    leftover(linked)
    linkSync(linked, join(BASE, 'linked-again'))
    const pointer = join(BASE, 'pointer')
    leftover(join(BASE, 'pointed-at'))
    symlinkSync(join(BASE, 'pointed-at'), pointer)
    const inUse = join(BASE, 'directory-in-use')
    mkdirSync(inUse)
    writeFileSync(join(inUse, 'file'), '')
    const theirs = join(BASE, 'somebody-elses')
    leftover(theirs)
    const theirDirectory = join(BASE, 'somebody-elses-directory')
    mkdirSync(theirDirectory)
    leftover(X)
    publish([linked, pointer, inUse, theirs, theirDirectory, X])
    // As another user's would look: nothing here can make one.
    const lstat = fs.lstatSync
    const spy = spyOn(fs, 'lstatSync').mockImplementation(((
      file: unknown,
      options: unknown,
    ) => {
      const stat = (lstat as (f: unknown, o: unknown) => fs.Stats)(
        file,
        options,
      )
      if (file === theirs || file === theirDirectory) {
        const other = Object.create(
          Object.getPrototypeOf(stat) as object,
        ) as fs.Stats
        return Object.assign(other, stat, { uid: stat.uid + 1 })
      }
      return stat
    }) as never)
    try {
      expect(live()).toEqual([X])
    } finally {
      spy.mockRestore()
    }
  })

  it('holds what a finished manifest names only while a process on its record runs', () => {
    leftover(X)
    const manifest = manifestOfADeadProcess([X])
    expect(live()).toEqual([])
    started(manifest, aDeadProcess())
    expect(live()).toEqual([])
    started(manifest, thisProcess())
    expect(live()).toEqual([X])
  })

  /** Has `call` on `target` fail with `code`. */
  function failingCall(
    call: 'readdirSync' | 'lstatSync' | 'readFileSync',
    target: string,
    code: string,
  ): { restore(): void } {
    const real = fs[call] as (f: unknown, o: unknown) => unknown
    const spy = spyOn(fs, call).mockImplementation(((
      file: unknown,
      options: unknown,
    ) => {
      if (file === target) {
        throw Object.assign(new Error(`${code}: ${target}`), { code })
      }
      return real(file, options)
    }) as never)
    return { restore: () => spy.mockRestore() }
  }

  const planted = (name: string, text: string): { restore(): void } => {
    writeFileSync(join(DIR, name), text)
    return { restore: () => rmSync(join(DIR, name)) }
  }
  const cannotTell: [string, (manifest: string) => { restore(): void }][] = [
    [
      'the directory cannot be looked at',
      () => failingCall('lstatSync', DIR, 'EIO'),
    ],
    [
      'the directory cannot be listed',
      () => failingCall('readdirSync', DIR, 'EMFILE'),
    ],
    ['a manifest cannot be opened', manifest => failing(manifest, 'EMFILE')],
    ['a manifest cannot be read', manifest => failing(manifest, 'EIO', 'read')],
    ['something is no manifest', () => planted('1-garbage.json', '{}')],
    [
      'a process runs on a record without a manifest',
      () => planted('1-0123456789abcdef.started', statLine(thisProcess())),
    ],
  ]
  for (const [what, inject] of cannotTell) {
    it(`says that it cannot tell, to a caller and to a wrap, when ${what}`, () => {
      // An empty set would read as "nothing is live", and the caller would
      // remove a mount point from under a sandbox that is running.
      leftover(X)
      const manifest = started(manifestOfADeadProcess([X]), thisProcess())
      expect(live()).toEqual([X])
      const earlier = reads(namedMountPoints())
      const injected = inject(manifest)
      const doubt = { inDoubt: expect.stringContaining(DIR) }
      try {
        expect(liveMountPoints()).toBeUndefined()
        expect(namedMountPoints()).toEqual(doubt)
        // A manifest already read is not read again, so that is no doubt.
        if (!what.startsWith('a manifest')) {
          expect(namedMountPoints(earlier)).toEqual(doubt)
        }
      } finally {
        injected.restore()
      }
      expect(live()).toEqual([X])
    })
  }

  it('holds a path a live manifest names that cannot be looked at', () => {
    leftover(X)
    started(manifestOfADeadProcess([X]), thisProcess())
    const look = failingCall('lstatSync', X, 'EACCES')
    try {
      expect(live()).toEqual([X])
    } finally {
      look.restore()
    }
  })

  it('answers a wrap with an earlier reading while the directory lists nothing new, and reads again when it does', () => {
    const [Y, Z] = [join(BASE, 'second.lock'), join(BASE, 'third.lock')]
    manifestOfADeadProcess([X])
    const first = reads(namedMountPoints())
    const open = spyOn(fs, 'openSync')
    try {
      expect(namedMountPoints(first)).toBe(first)
      expect(open).not.toHaveBeenCalled()
    } finally {
      open.mockRestore()
    }
    // The caller knows what it has published itself.
    const own = publish([Y])
    expect(namedMountPoints(first, [own])).toBe(first)
    expect([...reads(namedMountPoints(first)).paths].sort()).toEqual(
      [X, Y].sort(),
    )
    manifestOfADeadProcess([Z])
    expect([...reads(namedMountPoints(first, [own])).paths].sort()).toEqual(
      [X, Y, Z].sort(),
    )
  })

  it('names what a plan has made on the host itself from that moment, until a manifest names it', () => {
    const first = reads(namedMountPoints())
    const source = join(BASE, 'empty')
    keepTrackOfMountPoint(X)
    keepTrackOfMountSource(source)
    leftover(X)
    mkdirSync(source, { mode: 0o700 })
    expect([...reads(namedMountPoints(first)).paths]).toEqual([X])

    // From then on it is the manifest's, and goes with that.
    publishMountPointManifest([X], [source], 'the command')
    expect(collectMountPoints({ commandKey: 'the command' }).sort()).toEqual(
      [X, source].sort(),
    )
    // What the user puts there afterwards is the user's.
    writeFileSync(X, '')
    expect(named()).toEqual([])
    expect(collectMountPoints('all')).toEqual([])
    expect(existsSync(X)).toBe(true)
  })

  it('is one listing of the directory, and changes nothing in it', () => {
    leftover(X)
    publishMountPointManifest([X], [])
    started(manifestOfADeadProcess([join(BASE, 'other.lock')]), aDeadProcess())
    // What a pass would take away: a record whose manifest and process are gone.
    writeFileSync(
      join(DIR, '4242-0123456789abcdef.started'),
      statLine(aDeadProcess()),
    )
    const before = readdirSync(DIR).sort()

    const readdir = spyOn(fs, 'readdirSync')
    const rename = spyOn(fs, 'renameSync')
    let listed: string[] | undefined
    let listings: number
    try {
      listed = live()
      listings = readdir.mock.calls.filter(([dir]) => dir === DIR).length
      expect(rename).not.toHaveBeenCalled()
    } finally {
      readdir.mockRestore()
      rename.mockRestore()
    }
    expect(listed).toEqual([X])
    expect(listings).toBe(1)
    expect(readdirSync(DIR).sort()).toEqual(before)
  })

  it('makes no manifest directory where there is none, and holds nothing then', () => {
    const run = join(BASE, 'run')
    mkdirSync(run, { mode: 0o700 })
    const looked = inAChild(
      `console.log(JSON.stringify([...m.liveMountPoints()]))`,
      { env: { XDG_RUNTIME_DIR: run } },
    )
    expect(looked.status).toBe(0)
    expect(JSON.parse(looked.stdout)).toEqual([])
    expect(readdirSync(run)).toEqual([])
    expect(readdirSync(TMP)).toEqual([])
  })

  it('reads the directory a process without a runtime directory keeps, where that is the one there is', () => {
    const theirs = join(TMP, `srt-mount-points-${process.getuid!()}`)
    mkdirSync(theirs, { mode: 0o700 })
    chmodSync(theirs, 0o700)
    leftover(X)
    writeManifest(theirs, [X], thisProcess())
    const run = join(BASE, 'run')
    mkdirSync(run, { mode: 0o700 })
    const looked = inAChild(
      `console.log(JSON.stringify([...m.liveMountPoints()]))`,
      { env: { XDG_RUNTIME_DIR: run } },
    )
    expect(looked.status).toBe(0)
    expect(JSON.parse(looked.stdout)).toEqual([X])
    expect(readdirSync(run)).toEqual([])
  })

  // ---- all of it is bubblewrap's, which is Linux's -----------------------

  it('does nothing at all where the platform is not Linux', () => {
    // Every clean-up after a command, on every platform, comes through here.
    // Off Linux it must make nothing. One manifest to collect, one to hold by.
    const Y = join(BASE, 'second.lock')
    leftover(X)
    leftover(Y)
    manifestOfADeadProcess([X])
    writeManifest(DIR, [Y], thisProcess())
    const before = readdirSync(DIR).sort()
    const elsewhere = inAChild(
      [
        `const u = await import(${LIBRARY})`,
        `const published = m.publishMountPointManifest([${JSON.stringify(X)}], [])[0] ?? null`,
        `const live = [...m.liveMountPoints()]`,
        `const directories = m.mountPointManifestDirectories()`,
        `const collected = m.collectMountPoints('all')`,
        `u.cleanupBwrapMountPoints()`,
        `u.cleanupBwrapMountPoints({ force: true })`,
        `console.log(JSON.stringify({ published, live, directories, collected }))`,
      ].join('\n'),
      {
        first: `Object.defineProperty(process, 'platform', { value: 'darwin' })`,
      },
    )
    expect(elsewhere.status).toBe(0)
    expect(JSON.parse(elsewhere.stdout)).toEqual({
      published: null,
      live: [],
      directories: [],
      collected: [],
    })
    expect(existsSync(X)).toBe(true)
    expect(readdirSync(DIR).sort()).toEqual(before)
    expect(readdirSync(TMP)).toEqual([])
  })
})
