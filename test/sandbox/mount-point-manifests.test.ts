import { describe, it, expect, beforeEach, afterEach, spyOn } from 'bun:test'
import { spawnSync } from 'node:child_process'
import * as fs from 'node:fs'
import {
  accessSync,
  chmodSync,
  constants,
  existsSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  readlinkSync,
  realpathSync,
  rmSync,
  statSync,
  statfsSync,
  symlinkSync,
  utimesSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import {
  collectMountPoints,
  publishMountPointManifest,
} from '../../src/sandbox/bwrap-mount-manifests.js'
import { bwrapCanNamespace } from '../helpers/bwrap-namespace.js'
import { isLinux } from '../helpers/platform.js'
import { usePrivateManifestDirectory } from '../helpers/private-manifest-directory.js'

/**
 * The manifests and the pass that collects on their word, below the level of a
 * sandbox: what a pass believes, what it looks at again before it removes
 * anything, and that nothing about the directory's lock can hold a process up
 * or be relied on.
 */
describe.if(isLinux)('The mount point manifests', () => {
  const runtime = usePrivateManifestDirectory()
  const MODULE = JSON.stringify(
    join(import.meta.dir, '../../src/sandbox/bwrap-mount-manifests.ts'),
  )
  const LIBRARY = JSON.stringify(
    join(import.meta.dir, '../../src/sandbox/linux-sandbox-utils.ts'),
  )
  const BWRAP_CAN_NAMESPACE = bwrapCanNamespace()
  const NOT_ROOT = process.getuid?.() !== 0
  const OWN_NAMESPACE = isLinux ? readlinkSync('/proc/self/ns/pid') : ''

  let BASE: string
  let DIR: string // where the manifests go
  let LOCK: string // the directory's lock
  let X: string // a mount point an earlier sandbox left
  let TMP: string // the temp dir of every child process

  beforeEach(() => {
    BASE = realpathSync(mkdtempSync(join(tmpdir(), 'mount-point-manifests-')))
    TMP = join(BASE, 'tmp')
    mkdirSync(TMP)
    DIR = runtime.manifestDir()
    mkdirSync(DIR, { recursive: true, mode: 0o700 })
    chmodSync(DIR, 0o700)
    LOCK = join(DIR, 'directory.lock')
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
    collectMountPoints()
    rmSync(BASE, { recursive: true, force: true })
  })

  /** What bubblewrap leaves on the host for `--ro-bind /dev/null <absent>`. */
  function leftover(p: string): void {
    writeFileSync(p, '')
    chmodSync(p, 0o444)
  }

  /** A pid nothing in this PID namespace has. */
  function deadPid(): number {
    for (let pid = 4194000; pid > 1; pid--) {
      if (!existsSync(`/proc/${pid}`)) return pid
    }
    throw new Error('no free pid')
  }

  /**
   * The manifest of a wrap whose process is gone and which is long past its
   * grace: what a killed process leaves. `fields` overrides what it says.
   */
  function manifestOfADeadProcess(
    paths: string[],
    fields: Record<string, unknown> = {},
  ): string {
    const pid = deadPid()
    const file = join(DIR, `${pid}-${Math.random().toString(16).slice(2)}.json`)
    const body: Record<string, unknown> = {
      version: 1,
      pid,
      start: '1',
      ns: OWN_NAMESPACE,
      created: Date.now() - 60_000,
      paths,
      sources: [],
      ...fields,
    }
    for (const [key, value] of Object.entries(body)) {
      if (value === undefined) delete body[key]
    }
    writeFileSync(file, JSON.stringify(body), { mode: 0o600 })
    return file
  }

  /**
   * Runs `source` with the module as `m` in a process of its own, which is
   * killed if it has not ended by itself: what these cases guard against blocks
   * the thread it happens on, so a test in this process could not time it out.
   * `first` runs before the module is loaded, and an `env` entry that is
   * undefined is one the child does not have.
   */
  function inAChild(
    source: string,
    options: {
      launcher?: string[]
      env?: Record<string, string | undefined>
      first?: string
    } = {},
  ): { status: number | null; ms: number; stdout: string } {
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
    const began = Date.now()
    const run = spawnSync(argv[0]!, argv.slice(1), {
      env: env as Record<string, string>,
      encoding: 'utf8',
      timeout: 6000,
      killSignal: 'SIGKILL',
    })
    return { status: run.status, ms: Date.now() - began, stdout: run.stdout }
  }

  const COLLECT = `m.collectMountPoints()`
  const PUBLISH = `console.log(JSON.stringify(m.publishMountPointManifest(['/nonexistent/x'], []) ?? null))`

  // ---- the directory's lock never holds a process up ---------------------
  //
  // Whatever is at the lock's name, a collect and a publish both come back:
  // by the deadline when it is somebody's lock, and at once when it is nothing
  // this process could ever take. Each used to go round for ever, on the one
  // thread, in the wrap, in the clean-up after a command and in the exit
  // handler. "At once" is held to well under the two seconds somebody's lock
  // is waited for: the wait is made four times over by one command.
  const AT_ONCE_MS = 1500

  const notALock: [string, () => void, boolean][] = [
    ['a directory', () => mkdirSync(LOCK), true],
    [
      'a FIFO nobody writes to',
      () => expect(spawnSync('mkfifo', [LOCK]).status).toBe(0),
      true,
    ],
    [
      'a link to nothing',
      () => symlinkSync(join(BASE, 'nothing-here'), LOCK),
      true,
    ],
    [
      'a file that cannot be read',
      () => {
        writeFileSync(LOCK, `${deadPid()} 1 ${OWN_NAMESPACE}\n`)
        chmodSync(LOCK, 0o000)
      },
      NOT_ROOT,
    ],
  ]
  for (const [what, plant, applies] of notALock) {
    it.if(applies)(
      `comes back from a collect when its lock is ${what}`,
      () => {
        plant()
        const collected = inAChild(COLLECT)
        expect(collected.status).toBe(0)
        expect(collected.ms).toBeLessThan(AT_ONCE_MS)
      },
      15000,
    )

    it.if(applies)(
      `records a wrap's mount points all the same when its lock is ${what}`,
      () => {
        plant()
        const published = inAChild(PUBLISH)
        expect(published.status).toBe(0)
        expect(published.ms).toBeLessThan(AT_ONCE_MS)
        // A wrap is not refused, nor left unrecorded, for want of the lock.
        const manifest = JSON.parse(published.stdout) as { file: string }
        expect(readFileSync(manifest.file, 'utf8')).toContain('/nonexistent/x')
      },
      15000,
    )
  }

  it.if(BWRAP_CAN_NAMESPACE && NOT_ROOT)(
    'comes back from a collect at once where the directory is read-only from here, and collects nothing on its word',
    () => {
      // What a process inside a sandbox sees of the directory: bound
      // read-only, with a lock in it that it could never remove. It keeps its
      // own manifests elsewhere, and what is in this one is not for it to
      // judge: it could remove the mount point and not the manifest.
      const lock = `${deadPid()} 1 ${OWN_NAMESPACE}\n`
      writeFileSync(LOCK, lock)
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
      expect(collected.ms).toBeLessThan(AT_ONCE_MS)
      expect(readFileSync(LOCK, 'utf8')).toBe(lock)
      expect(existsSync(X)).toBe(true)
      expect(existsSync(manifest)).toBe(true)
    },
    15000,
  )

  it('waits for a lock somebody holds, and no longer than the wait', () => {
    // This process, which is running, in this namespace.
    const start = readFileSync('/proc/self/stat', 'utf8')
      .split(') ')
      .pop()!
      .split(' ')[19]
    writeFileSync(LOCK, `${process.pid} ${start} ${OWN_NAMESPACE}\n`)
    leftover(X)
    manifestOfADeadProcess([X])

    const collected = inAChild(COLLECT)
    expect(collected.status).toBe(0)
    expect(collected.ms).toBeGreaterThan(1500)
    expect(collected.ms).toBeLessThan(5500)
    // The pass was left to the holder: nothing was removed, its lock stands.
    expect(existsSync(X)).toBe(true)
    expect(readFileSync(LOCK, 'utf8')).toContain(`${process.pid} `)
  }, 15000)

  it('believes a lock that names nobody until it is old, and breaks it then', () => {
    // An empty lock file is what a lock made in two steps looked like for a
    // moment, and a waiter that read it then took it for nobody's and removed
    // it at once: two processes inside. The lock is made whole now, and one
    // that says nothing is believed like any other whose holder cannot be
    // asked after.
    writeFileSync(LOCK, '')
    leftover(X)
    manifestOfADeadProcess([X])

    const young = inAChild(COLLECT)
    expect(young.status).toBe(0)
    expect(young.ms).toBeGreaterThan(1500)
    expect(existsSync(LOCK)).toBe(true)
    expect(existsSync(X)).toBe(true)

    const longAgo = new Date(Date.now() - 61_000)
    utimesSync(LOCK, longAgo, longAgo)
    const old = inAChild(COLLECT)
    expect(old.status).toBe(0)
    expect(old.ms).toBeLessThan(4000)
    expect(existsSync(LOCK)).toBe(false)
    expect(existsSync(X)).toBe(false)
  }, 20000)

  it('breaks at once the lock of a holder in this namespace that is gone, and not one from another namespace', () => {
    leftover(X)
    manifestOfADeadProcess([X])

    // Its pid is no process here, which says nothing about a holder whose pid
    // was given in another namespace.
    writeFileSync(LOCK, `${deadPid()} 1 pid:[1]\n`)
    const elsewhere = inAChild(COLLECT)
    expect(elsewhere.status).toBe(0)
    expect(elsewhere.ms).toBeGreaterThan(1500)
    expect(existsSync(X)).toBe(true)

    writeFileSync(LOCK, `${deadPid()} 1 ${OWN_NAMESPACE}\n`)
    const here = inAChild(COLLECT)
    expect(here.status).toBe(0)
    // The pass ran, which it does not after waiting in vain.
    expect(existsSync(X)).toBe(false)
    expect(existsSync(LOCK)).toBe(false)
  }, 20000)

  // ---- nothing rests on the lock -----------------------------------------

  /**
   * Runs `during` once, in the middle of the next pass: after it has listed
   * the manifests and decided what is finished, before it removes anything.
   */
  function duringTheNextPass(during: () => void): { restore(): void } {
    const readFile = fs.readFileSync
    let done = false
    const spy = spyOn(fs, 'readFileSync').mockImplementation(((
      file: unknown,
      options: unknown,
    ) => {
      if (file === '/proc/locks' && !done) {
        done = true
        during()
      }
      return (readFile as (f: unknown, o: unknown) => unknown)(file, options)
    }) as never)
    return { restore: () => spy.mockRestore() }
  }

  it('removes what a finished manifest names once nothing else names it', () => {
    leftover(X)
    const manifest = manifestOfADeadProcess([X])
    expect(collectMountPoints()).toEqual([X])
    expect(existsSync(X)).toBe(false)
    expect(existsSync(manifest)).toBe(false)
  })

  it('keeps a mount point named by a manifest that is published while the pass is under way', () => {
    // The lock does not exclude: its holder can be held up past the age at
    // which it is broken, breaking one is not atomic, and a publish that
    // cannot have it goes ahead without. So a manifest can appear between a
    // pass listing the directory and its removals, naming a path the pass is
    // about to remove, with a sandbox starting under it.
    leftover(X)
    manifestOfADeadProcess([X])
    let published: { status: number | null; stdout: string } | undefined
    const pass = duringTheNextPass(() => {
      rmSync(LOCK, { force: true }) // what a waiter breaking the lock does
      published = inAChild(
        `console.log(JSON.stringify(m.publishMountPointManifest([${JSON.stringify(X)}], []) ?? null))`,
      )
    })
    let removed: string[]
    try {
      removed = collectMountPoints()
    } finally {
      pass.restore()
    }
    expect(published?.status).toBe(0)
    const arrived = (JSON.parse(published!.stdout) as { file: string }).file
    expect(readFileSync(arrived, 'utf8')).toContain(X)
    expect(removed).toEqual([])
    expect(existsSync(X)).toBe(true)
  }, 15000)

  it('gives up only a lock that is still its own', () => {
    // Held up for longer than a lock is believed, a pass finds on its way out
    // that the lock at that name is somebody else's by now. Removing it by
    // name let a third process in beside the second.
    const theirs = `${process.ppid} 1 pid:[1]\n`
    let mine = ''
    const pass = duringTheNextPass(() => {
      mine = readFileSync(LOCK, 'utf8')
      rmSync(LOCK)
      writeFileSync(LOCK, theirs)
    })
    try {
      collectMountPoints()
    } finally {
      pass.restore()
    }
    // Whole while it was held: who, since when, and where that can be asked.
    expect(mine).toMatch(
      new RegExp(
        `^${process.pid} \\d+ ${OWN_NAMESPACE.replace(/[[\]]/g, '\\$&')}\n$`,
      ),
    )
    expect(readFileSync(LOCK, 'utf8')).toBe(theirs)
  })

  it('makes its lock whole: it is never there with nothing in it', () => {
    // Linked into place from a file already written, so that nobody who finds
    // it can find it empty.
    const linked: string[] = []
    const link = fs.linkSync
    const spy = spyOn(fs, 'linkSync').mockImplementation(((
      from: string,
      to: string,
    ) => {
      if (to === LOCK) linked.push(readFileSync(from, 'utf8'))
      return link(from, to)
    }) as never)
    try {
      collectMountPoints()
    } finally {
      spy.mockRestore()
    }
    expect(linked.length).toBe(1)
    expect(linked[0]).toMatch(/^\d+ \d+ \S+\n$/)
    // And nothing of the making is left behind.
    expect(readdirSync(DIR)).toEqual([])
  })

  it('looks at /proc/locks a bounded number of times, not once for every mount point', () => {
    // The list is the host's, and reading all of it for each removal made a
    // pass over many mount points take seconds, under a lock whose waiters
    // give up after two.
    const many = 500
    const paths: string[] = []
    for (let i = 0; i < many; i++) {
      const p = join(BASE, `.placeholder-${i}`)
      leftover(p)
      paths.push(p)
    }
    expect(publishMountPointManifest(paths, [])).toBeDefined()
    const spy = spyOn(fs, 'readFileSync')
    let removed: string[]
    let looks: number
    let tookMs: number
    try {
      const began = Date.now()
      removed = collectMountPoints()
      tookMs = Date.now() - began
      looks = spy.mock.calls.filter(([file]) => file === '/proc/locks').length
    } finally {
      spy.mockRestore()
    }
    expect(removed.length).toBe(many)
    // One to begin with, one before the first removal, one for every 64
    // removals after that, and one more for every two milliseconds the pass
    // took, since a look goes out of date with time as well. No fewer than
    // that either: one look is not good for ever.
    expect(looks).toBeGreaterThanOrEqual(1 + Math.ceil(many / 64))
    expect(looks).toBeLessThanOrEqual(
      3 + Math.ceil(many / 64) + Math.ceil(tookMs / 2),
    )
    expect(looks).toBeLessThan(many)
  })

  it.if(NOT_ROOT)(
    'keeps the manifest of a mount point it could not remove, for a pass that can',
    () => {
      // Seen read-only from here, as from inside a sandbox that may not write
      // the directory it is in. The manifest is all that says the file is a
      // mount point and whose; with it gone the file stayed for good.
      const readOnly = join(BASE, 'read-only-from-here')
      mkdirSync(readOnly)
      const inside = join(readOnly, 'config.lock')
      leftover(inside)
      const manifest = manifestOfADeadProcess([inside])
      chmodSync(readOnly, 0o555)
      try {
        expect(collectMountPoints()).toEqual([])
        expect(existsSync(inside)).toBe(true)
        expect(existsSync(manifest)).toBe(true)
      } finally {
        chmodSync(readOnly, 0o755)
      }
      expect(collectMountPoints()).toEqual([inside])
      expect(existsSync(manifest)).toBe(false)
    },
  )

  // ---- a manifest goes last, this process's own like anybody's -----------
  //
  // A manifest is all that names its mount points. One this process wrote
  // used to be unlinked as soon as the caller said its command was over,
  // before the pass knew whether it would get as far as the removals or
  // whether they would work; after a pass that turned back, or a removal that
  // was refused, nothing on disk named the mount points and no later pass
  // removed them.

  it.if(NOT_ROOT)(
    'keeps the manifest of a wrap of its own whose mount point it could not remove, for a pass that can',
    () => {
      const readOnly = join(BASE, 'read-only-from-here')
      mkdirSync(readOnly)
      const inside = join(readOnly, 'config.lock')
      leftover(inside)
      const manifest = publishMountPointManifest([inside], [])!.file
      chmodSync(readOnly, 0o555)
      try {
        expect(collectMountPoints('all')).toEqual([])
        expect(existsSync(inside)).toBe(true)
        expect(existsSync(manifest)).toBe(true)
      } finally {
        chmodSync(readOnly, 0o755)
      }
      // Whatever the next pass is told to release: that this wrap is over has
      // been said already.
      expect(collectMountPoints('none')).toEqual([inside])
      expect(existsSync(manifest)).toBe(false)
    },
  )

  it('keeps the manifest of a wrap of its own when the pass turns back half way, for the next', () => {
    leftover(X)
    const manifest = publishMountPointManifest([X], [])!.file
    // Another version of this library publishes, in a layout this one cannot
    // read, after the pass has listed the directory: what that names cannot be
    // kept path by path, so the pass stops short of removing anything.
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
    expect(existsSync(manifest)).toBe(true)

    rmSync(stranger)
    expect(collectMountPoints('none')).toEqual([X])
    expect(existsSync(manifest)).toBe(false)
  })

  it('turns back, keeping everything, at an unreadable manifest that may have a sandbox starting under it', () => {
    leftover(X)
    const theirs = manifestOfADeadProcess([X])
    const own = publishMountPointManifest([join(BASE, 'other')], [])!.file
    const stranger = join(DIR, '1-garbage.json')
    writeFileSync(stranger, '{ not json')
    expect(collectMountPoints('all')).toEqual([])
    expect(existsSync(X)).toBe(true)
    expect(existsSync(theirs)).toBe(true)
    expect(existsSync(own)).toBe(true)
    // Once it is old enough that nothing can be starting under it, and no
    // lock is on it, it stands in the way of nothing.
    const halfAMinuteAgo = new Date(Date.now() - 30_000)
    utimesSync(stranger, halfAMinuteAgo, halfAMinuteAgo)
    expect(collectMountPoints('none')).toEqual([X])
    expect(existsSync(own)).toBe(false)
    expect(existsSync(stranger)).toBe(true)
  })

  it('removes nothing when /proc/locks cannot be read', () => {
    leftover(X)
    const manifest = manifestOfADeadProcess([X])
    const readFile = fs.readFileSync
    const spy = spyOn(fs, 'readFileSync').mockImplementation(((
      file: unknown,
      options: unknown,
    ) => {
      if (file === '/proc/locks') {
        throw Object.assign(new Error('EACCES: /proc/locks'), {
          code: 'EACCES',
        })
      }
      return (readFile as (f: unknown, o: unknown) => unknown)(file, options)
    }) as never)
    try {
      expect(collectMountPoints()).toEqual([])
    } finally {
      spy.mockRestore()
    }
    expect(existsSync(X)).toBe(true)
    expect(existsSync(manifest)).toBe(true)
  })

  it('keeps what a finished manifest names when its lock shows on the look before the removals', () => {
    // The bubblewrap a wrap has handed to its caller takes its lock whenever
    // the caller starts it, which no lock of this library's can put off: the
    // kernel is asked again before anything goes.
    leftover(X)
    const manifest = manifestOfADeadProcess([X])
    const line = `1: POSIX  ADVISORY  READ 4242 ${deviceOf(manifest)}:${statSync(manifest).ino} 0 EOF\n`
    const readFile = fs.readFileSync
    let reads = 0
    const spy = spyOn(fs, 'readFileSync').mockImplementation(((
      file: unknown,
      options: unknown,
    ) => {
      if (file === '/proc/locks') {
        reads++
        return reads === 1 ? '' : line
      }
      return (readFile as (f: unknown, o: unknown) => unknown)(file, options)
    }) as never)
    try {
      expect(collectMountPoints()).toEqual([])
    } finally {
      spy.mockRestore()
    }
    expect(reads).toBeGreaterThan(1)
    expect(existsSync(X)).toBe(true)
    expect(existsSync(manifest)).toBe(true)
  })

  it('lists the directory again between removals, not only before the first', () => {
    // A sandbox about to start on a path shows as a manifest that was not
    // there when the pass began, and it can appear at any point of a pass over
    // many mount points. One listing is good for a quarter of a millisecond,
    // far less than a sandbox needs to get to its binds.
    const Y = join(BASE, 'second.lock')
    leftover(X)
    leftover(Y)
    manifestOfADeadProcess([X, Y])
    const unlink = fs.unlinkSync
    let arrived: string | undefined
    const spy = spyOn(fs, 'unlinkSync').mockImplementation(((file: string) => {
      unlink(file)
      if (file === X && arrived === undefined) {
        // Published the moment the first mount point has gone, with the pass
        // held up for a millisecond before it goes on to the next: less than
        // the two for which it trusts what it read from /proc/locks.
        arrived = manifestOfADeadProcess([Y], {
          pid: process.pid,
          created: Date.now(),
        })
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 1)
      }
    }) as never)
    let removed: string[]
    try {
      removed = collectMountPoints()
    } finally {
      spy.mockRestore()
    }
    expect(arrived).toBeDefined()
    expect(removed).toEqual([X])
    expect(existsSync(Y)).toBe(true)
  })

  it('is live for half a second from when it was written, though its writer is gone', () => {
    // bubblewrap takes the lock in the sandbox's init process, a moment after
    // a wrapping process killed just then could still have vouched for it.
    leftover(X)
    const manifest = manifestOfADeadProcess([X], { created: Date.now() })
    expect(collectMountPoints()).toEqual([])
    expect(existsSync(X)).toBe(true)
    expect(existsSync(manifest)).toBe(true)
  })

  // ---- a manifest is only a claim about a path ---------------------------

  it('leaves what a finished manifest names when it no longer looks like a mount point', () => {
    const written = join(BASE, 'written-to')
    writeFileSync(written, 'mine')
    chmodSync(written, 0o444)
    const writable = join(BASE, 'writable')
    writeFileSync(writable, '')
    chmodSync(writable, 0o644)
    const linked = join(BASE, 'linked')
    leftover(linked)
    linkSync(linked, join(BASE, 'linked-again'))
    const pointer = join(BASE, 'pointer')
    leftover(join(BASE, 'pointed-at'))
    symlinkSync(join(BASE, 'pointed-at'), pointer)
    const inUse = join(BASE, 'directory-in-use')
    mkdirSync(inUse)
    writeFileSync(join(inUse, 'file'), '')
    const manifest = manifestOfADeadProcess([
      written,
      writable,
      linked,
      pointer,
      inUse,
    ])
    expect(collectMountPoints()).toEqual([])
    for (const kept of [written, writable, linked, pointer, inUse]) {
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
      expect(collectMountPoints()).toEqual([])
    } finally {
      spy.mockRestore()
    }
    expect(existsSync(X)).toBe(true)
    expect(existsSync(directory)).toBe(true)
  })

  it('takes away what a killed process left half written, once it is old', () => {
    const old = [
      join(DIR, 'directory.lock.4242.0123456789abcdef.tmp'),
      join(DIR, '4242-0123456789abcdef.json.tmp'),
    ]
    const young = join(DIR, '4243-0123456789abcdef.json.tmp')
    for (const file of [...old, young]) writeFileSync(file, '{}')
    const hoursAgo = new Date(Date.now() - 2 * 3600 * 1000)
    for (const file of old) utimesSync(file, hoursAgo, hoursAgo)
    collectMountPoints()
    for (const file of old) expect(existsSync(file)).toBe(false)
    // This one may be on its way into place.
    expect(existsSync(young)).toBe(true)
  })

  // ---- liveness is relative to a PID namespace ---------------------------
  //
  // /proc/locks lists a lock only when its holder has a pid in the namespace
  // of the /proc being read, and /proc/PID is local to it. From another
  // namespace a running sandbox's manifest looks exactly like one a dead
  // process left.

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
      'collected',
      { ns: undefined, created: Date.now() - 2 * 3600 * 1000 },
    ],
    ['written in this PID namespace', 'collected', {}],
  ] as const)(
    'a manifest %s, with no writer and no lock to be seen, is %s',
    (_what, outcome, fields) => {
      leftover(X)
      const manifest = manifestOfADeadProcess([X], fields)
      collectMountPoints()
      expect(existsSync(X)).toBe(outcome === 'kept')
      expect(existsSync(manifest)).toBe(outcome === 'kept')
    },
  )

  // ---- an inode number is not a file -------------------------------------

  /** Has the next passes read `text` for /proc/locks. */
  function withProcLocks(text: string): { restore(): void } {
    const readFile = fs.readFileSync
    const spy = spyOn(fs, 'readFileSync').mockImplementation(((
      file: unknown,
      options: unknown,
    ) =>
      file === '/proc/locks'
        ? text
        : (readFile as (f: unknown, o: unknown) => unknown)(
            file,
            options,
          )) as never)
    return { restore: () => spy.mockRestore() }
  }

  /** `major:minor` of the filesystem `p` is on, as /proc/locks prints it. */
  function deviceOf(p: string): string {
    const dev = statSync(p, { bigint: true }).dev
    const major = ((dev >> 8n) & 0xfffn) | ((dev >> 32n) & ~0xfffn)
    const minor = (dev & 0xffn) | ((dev >> 12n) & ~0xffn)
    const hex = (n: bigint): string => n.toString(16).padStart(2, '0')
    return `${hex(major)}:${hex(minor)}`
  }

  // tmpfs, ext2/3/4 and xfs report for a file the device /proc/locks prints.
  const DEVICES_COMPARE =
    isLinux &&
    [0x01021994, 0xef53, 0x58465342].includes(
      Number(statfsSync(realpathSync(tmpdir())).type),
    )

  it.if(DEVICES_COMPARE)(
    'is not kept live by a lock on a file with the same inode number on another filesystem',
    () => {
      // Inode numbers are per filesystem, and on a young tmpfs they are small.
      // A manifest whose number some unrelated locked file shared read as
      // live for as long as that lock was held: never released, and every
      // path it named a mount point to every later wrap.
      leftover(X)
      const manifest = publishMountPointManifest([X], [])!.file
      const inode = statSync(manifest).ino
      const elsewhere = withProcLocks(
        `1: POSIX  ADVISORY  WRITE 4242 fe:77:${inode} 0 EOF\n`,
      )
      try {
        expect(collectMountPoints()).toEqual([X])
      } finally {
        elsewhere.restore()
      }
      expect(existsSync(manifest)).toBe(false)
    },
  )

  it('is kept live by a lock on the manifest itself', () => {
    leftover(X)
    const manifest = publishMountPointManifest([X], [])!.file
    const inode = statSync(manifest).ino
    const onIt = withProcLocks(
      `1: POSIX  ADVISORY  READ 4242 ${deviceOf(manifest)}:${inode} 0 EOF\n`,
    )
    try {
      expect(collectMountPoints()).toEqual([])
    } finally {
      onIt.restore()
    }
    expect(existsSync(manifest)).toBe(true)
    expect(existsSync(X)).toBe(true)
    // And goes with the lock.
    expect(collectMountPoints()).toEqual([X])
  })

  // ---- where the manifests are kept --------------------------------------

  const SHM = '/dev/shm'
  const SHM_WRITABLE = (() => {
    try {
      accessSync(SHM, constants.W_OK | constants.X_OK)
      return true
    } catch {
      return false
    }
  })()

  it.if(SHM_WRITABLE)(
    'are never kept under /dev, which the sandbox mounts afresh over them',
    () => {
      // bubblewrap opens the manifest after its mounts, and the wrap mounts a
      // new /dev after every bind: a manifest under /dev is not there to be
      // opened, and every command with a mount point refused to start.
      const shm = mkdtempSync(join(SHM, 'mount-point-manifests-'))
      chmodSync(shm, 0o700)
      try {
        const elsewhere = TMP
        const fellBack = inAChild(PUBLISH, {
          env: { XDG_RUNTIME_DIR: shm, TMPDIR: elsewhere },
        })
        expect(fellBack.status).toBe(0)
        const manifest = JSON.parse(fellBack.stdout) as { file: string }
        expect(manifest.file.startsWith(`${elsewhere}/`)).toBe(true)
        expect(readdirSync(shm)).toEqual([])

        // With nowhere else to go it records nothing, rather than somewhere
        // bubblewrap cannot reach.
        const env: Record<string, string> = { ...process.env, TMPDIR: shm }
        delete env.XDG_RUNTIME_DIR
        const script = join(BASE, 'nowhere.ts')
        writeFileSync(script, `const m = await import(${MODULE})\n${PUBLISH}\n`)
        const nowhere = spawnSync(process.execPath, [script], {
          env,
          encoding: 'utf8',
          timeout: 6000,
        })
        expect(nowhere.status).toBe(0)
        expect(JSON.parse(nowhere.stdout)).toBe(null)
        expect(readdirSync(shm)).toEqual([])
      } finally {
        rmSync(shm, { recursive: true, force: true })
      }
    },
    15000,
  )

  it("are not kept behind a link planted at the directory's name, whose target is left as it was", () => {
    // The name is predictable and sits where sandboxed commands commonly
    // write. A link there is refused, not followed: its target is somebody's
    // directory, and would have had its mode changed.
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
      // ours in every other respect, and used to be settled on, after which
      // every wrap of that process failed to record its mount points.
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

  // ---- all of it is bubblewrap's, which is Linux's -----------------------

  it('does nothing at all where the platform is not Linux', () => {
    // Every clean-up after a command, on every platform, comes through here.
    // Off Linux it made the directory and its lock each time, and on a
    // platform with no uids a fresh temporary directory each time.
    leftover(X)
    manifestOfADeadProcess([X])
    const before = readdirSync(DIR).sort()
    const elsewhere = inAChild(
      [
        `const u = await import(${LIBRARY})`,
        `const published = m.publishMountPointManifest([${JSON.stringify(X)}], []) ?? null`,
        `const live = [...m.liveMountPoints()]`,
        `const directories = m.mountPointManifestDirectories()`,
        `const collected = m.collectMountPoints()`,
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
