import { describe, it, expect, beforeEach, afterEach, spyOn } from 'bun:test'
import * as fs from 'fs'
import { spawn, spawnSync } from 'node:child_process'
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  wrapCommandWithSandboxLinux,
  cleanupBwrapMountPoints,
} from '../../src/sandbox/linux-sandbox-utils.js'
import {
  indexOfMount,
  lastIndexOfMount,
  lastMountAt,
} from '../helpers/bwrap-argv.js'
import { bwrapCanNamespace } from '../helpers/bwrap-namespace.js'
import { isLinux } from '../helpers/platform.js'

/**
 * The mount point for a file git reads back (`commondir`, `config.worktree`)
 * is prepared on the host, in a git directory a command already running may
 * be writing: one that made the directory after its own wrap has nothing of
 * it mounted. So whatever the wrapper does to a name it found taken, it does
 * to the file it looked at and to nothing the name was given to since.
 */
describe.if(isLinux)('The mount point of a file git reads back', () => {
  const VICTIM = 'a file outside every write root\n'
  /** Echoed by a command that runs for real, so nothing concludes anything
   *  from a sandbox that never started. */
  const BOOTED = 'BOOTED'
  const WROTE_GIT_DIR = 'WROTE_GIT_DIR'
  const LIVE = bwrapCanNamespace()
  let dir: string
  const savedCwd = process.cwd()

  beforeEach(() => {
    dir = realpathSync(mkdtempSync(join(tmpdir(), 'git-redirect-race-')))
  })

  afterEach(() => {
    process.chdir(savedCwd)
    cleanupBwrapMountPoints({ force: true })
    rmSync(dir, { recursive: true, force: true })
  })

  /** A checkout whose `.git` git would accept, wrapped with it as the cwd. */
  function makeCheckout(name: string): string {
    const checkout = join(dir, name)
    mkdirSync(join(checkout, '.git', 'hooks'), { recursive: true })
    writeFileSync(join(checkout, '.git', 'HEAD'), 'ref: refs/heads/main')
    writeFileSync(join(checkout, '.git', 'config'), '[core]\n')
    return checkout
  }

  function wrapIn(checkout: string, command = 'true'): Promise<string> {
    process.chdir(checkout)
    return wrapCommandWithSandboxLinux({
      command,
      needsNetworkRestriction: false,
      allowAllUnixSockets: true,
      readConfig: undefined,
      writeConfig: { allowOnly: [checkout], denyWithinAllow: [] },
    })
  }

  /** A file with exactly this mode, whatever the umask. */
  function writeWithMode(file: string, contents: string, mode: number): void {
    writeFileSync(file, contents)
    chmodSync(file, mode)
  }

  /** The shape bubblewrap's own ensure_file() leaves behind. */
  function leaveStaleMountPoint(file: string): void {
    writeWithMode(file, '', 0o444)
  }

  /**
   * The source bwrap is given for the mount at `dest`. Throws where nothing
   * is mounted there, so no assertion about it passes on a wrap that emitted
   * no such mount.
   */
  function mountSource(command: string, dest: string): string {
    const mount = lastMountAt(command, dest)
    if (mount === undefined) throw new Error(`nothing is mounted at ${dest}`)
    const [, source, mounted] = mount.split(' ')
    if (source === undefined || mounted !== dest) {
      throw new Error(`the mount at ${dest} has no source: ${mount}`)
    }
    return source
  }

  /**
   * Runs `wrap` and hands the name `dest` to `swap` right after the wrapper
   * has touched that name for the `nth` time, counting from the exclusive
   * create that found it taken: each later look at the path, and each stat of
   * a descriptor opened on it, is one more. That is every point at which a
   * command writing the directory could have given the name to something
   * else between a check and what is done on the strength of it.
   */
  async function wrapSwappingAfterTouch<T>(
    dest: string,
    nth: number,
    swap: () => void,
    wrap: () => Promise<T>,
  ): Promise<{ result: T; swapped: boolean }> {
    type Fn = (...args: unknown[]) => unknown
    const spies: { mockRestore(): void }[] = []
    const descriptors = new Set<number>()
    let armed = false
    let touches = 0
    let swapped = false
    const touched = (): void => {
      if (!armed || ++touches !== nth) return
      swapped = true
      swap()
    }
    const intercept = (
      name: keyof typeof fs,
      around: (real: Fn, args: unknown[]) => unknown,
    ): void => {
      const real = fs[name] as Fn
      spies.push(
        spyOn(fs, name).mockImplementation(((...args: unknown[]) =>
          around(real, args)) as never),
      )
    }
    const byPath = (real: Fn, args: unknown[]): unknown => {
      try {
        return real(...args)
      } finally {
        if (String(args[0]) === dest) touched()
      }
    }

    for (const name of [
      'lstatSync',
      'statSync',
      'readFileSync',
      'chmodSync',
    ] as const) {
      intercept(name, byPath)
    }
    intercept('writeFileSync', (real, args) => {
      const exclusive =
        String(args[0]) === dest &&
        (args[2] as { flag?: string } | undefined)?.flag === 'wx'
      if (exclusive) armed = true
      return byPath(real, args)
    })
    intercept('openSync', (real, args) => {
      try {
        const fd = real(...args) as number
        if (String(args[0]) === dest) descriptors.add(fd)
        return fd
      } finally {
        if (String(args[0]) === dest) touched()
      }
    })
    intercept('fstatSync', (real, args) => {
      try {
        return real(...args)
      } finally {
        if (descriptors.has(args[0] as number)) touched()
      }
    })
    intercept('closeSync', (real, args) => {
      descriptors.delete(args[0] as number)
      return real(...args)
    })

    try {
      return { result: await wrap(), swapped }
    } finally {
      for (const spy of spies) spy.mockRestore()
    }
  }

  /** Gives the name `dest` to `replacement`, the way rename(2) does. */
  function renameOver(replacement: string, dest: string): void {
    fs.renameSync(replacement, dest)
  }

  /**
   * Every point at which the name can change hands, one wrap each, until the
   * wrapper is done with the name before the swap comes due: the stale mount
   * point's name goes to a link to a file outside every write root, made by
   * `link`. Returns what each wrap emitted, so the caller asserts on more
   * than survival.
   */
  async function atEveryTouch(
    victimMode: number,
    link: (victim: string, name: string) => void,
    check: (nth: number, victim: string) => void,
  ): Promise<string[]> {
    const outcomes: string[] = []
    for (let nth = 1; ; nth++) {
      const checkout = makeCheckout(`repo-${nth}`)
      const gitDir = join(checkout, '.git')
      const commondir = join(gitDir, 'commondir')
      leaveStaleMountPoint(commondir)
      const victim = join(dir, `victim-${nth}`)
      writeWithMode(victim, VICTIM, victimMode)

      const { result: command, swapped } = await wrapSwappingAfterTouch(
        commondir,
        nth,
        () => {
          const linked = join(dir, `link-${nth}`)
          link(victim, linked)
          renameOver(linked, commondir)
        },
        () =>
          wrapIn(
            checkout,
            `echo ${BOOTED}; touch .git/probe && echo ${WROTE_GIT_DIR}`,
          ),
      )
      if (!swapped) return outcomes
      check(nth, victim)

      // Either the file is denied where it stands or the git directory is
      // denied whole: no wrap comes out with the redirect file left open. A
      // pin of the git directory lies beneath the bind that makes the
      // checkout writable in every wrap, so it is a bind of it above that
      // one that is the deny.
      const madeWritable = indexOfMount(command, '--bind', checkout, checkout)
      expect(madeWritable).toBeGreaterThan(-1)
      if (
        lastIndexOfMount(command, '--ro-bind', gitDir, gitDir) > madeWritable
      ) {
        expect(lastMountAt(command, commondir)).toBeUndefined()
        outcomes.push('git directory denied whole')
        if (LIVE) {
          // The sandbox starts with the link still standing there, and
          // nothing in the git directory can be written, the link included.
          const run = spawnSync(command, {
            shell: true,
            encoding: 'utf8',
            timeout: 30000,
            cwd: checkout,
          })
          const output = `${run.stdout}${run.stderr}`
          expect({ nth, output }).toEqual({
            nth,
            output: expect.stringContaining(BOOTED),
          })
          expect(output).not.toContain(WROTE_GIT_DIR)
          expect(readFileSync(commondir, 'utf8')).toBe(VICTIM)
          check(nth, victim)
        }
      } else {
        mountSource(command, commondir)
        outcomes.push('file denied')
      }

      // Forced, as the exit handler runs it: what the wrap took for its own
      // goes, and the victim is no more its own for being linked to.
      cleanupBwrapMountPoints({ force: true })
      check(nth, victim)
    }
  }

  it('never writes through a link the name of a stale mount point was swapped for', async () => {
    const outcomes = await atEveryTouch(
      0o644,
      fs.symlinkSync,
      (nth, victim) => {
        expect({ nth, contents: readFileSync(victim, 'utf8') }).toEqual({
          nth,
          contents: VICTIM,
        })
      },
    )

    // The swap landed at least once, and at least once between the wrapper
    // finding the stale file and rewriting it, which is where it gives up on
    // the file and denies the directory instead.
    expect(outcomes.length).toBeGreaterThan(1)
    expect(outcomes).toContain('git directory denied whole')
  })

  it('never makes writable what such a link leads to', async () => {
    // Read-only, so that a write through the link is refused and what is left
    // to go wrong is the chmod that was there to make bubblewrap's own
    // read-only mount point writable.
    const outcomes = await atEveryTouch(
      0o444,
      fs.symlinkSync,
      (nth, victim) => {
        expect({
          nth,
          mode: (statSync(victim).mode & 0o777).toString(8),
          contents: readFileSync(victim, 'utf8'),
        }).toEqual({ nth, mode: '444', contents: VICTIM })
      },
    )

    expect(outcomes.length).toBeGreaterThan(1)
  })

  it('never writes to another file the name was made a hard link to', async () => {
    // No link to refuse this time: the name opens, as a regular file, and
    // only what the descriptors say tells it from the file that was checked.
    const outcomes = await atEveryTouch(0o644, fs.linkSync, (nth, victim) => {
      expect({ nth, contents: readFileSync(victim, 'utf8') }).toEqual({
        nth,
        contents: VICTIM,
      })
    })

    expect(outcomes.length).toBeGreaterThan(1)
    expect(outcomes).toContain('git directory denied whole')
  })

  /**
   * Runs `wrap` and says whether it waited on the FIFO that is, or is about
   * to be, at `name`. Opening a FIFO to read waits for somebody to open it to
   * write, and nobody will; so that a wrapper that does wait fails its test
   * rather than hanging the run, a helper opens both ends after a while. A
   * wrap that is back well before then waited on nothing.
   */
  async function waitsOnFifoAt<T>(
    name: string,
    wrap: () => Promise<T>,
  ): Promise<{ result: T; waited: boolean }> {
    const RESCUE_AFTER_MS = 3000
    const rescuer = spawn(
      'sh',
      [
        '-c',
        `sleep ${RESCUE_AFTER_MS / 1000}; exec 3<>"$1"; sleep 1`,
        'sh',
        name,
      ],
      { stdio: 'ignore' },
    )
    const started = Date.now()
    try {
      const result = await wrap()
      return { result, waited: Date.now() - started >= RESCUE_AFTER_MS / 2 }
    } finally {
      rescuer.kill('SIGKILL')
    }
  }

  it('does not wait on a FIFO the name was swapped for', async () => {
    for (let nth = 1; ; nth++) {
      const checkout = makeCheckout(`repo-${nth}`)
      const commondir = join(checkout, '.git', 'commondir')
      leaveStaleMountPoint(commondir)
      const fifo = join(dir, `fifo-${nth}`)
      expect(spawnSync('mkfifo', [fifo]).status).toBe(0)

      const {
        result: { swapped },
        waited,
      } = await waitsOnFifoAt(commondir, () =>
        wrapSwappingAfterTouch(
          commondir,
          nth,
          () => renameOver(fifo, commondir),
          () => wrapIn(checkout),
        ),
      )
      if (!swapped) break

      expect({ nth, waited }).toEqual({ nth, waited: false })
      expect(lstatSync(commondir).isFIFO()).toBe(true)
      cleanupBwrapMountPoints({ force: true })
      expect(lstatSync(commondir).isFIFO()).toBe(true)
    }
  }, 60000)

  it('binds a FIFO that was there all along from itself, without waiting on it', async () => {
    const checkout = makeCheckout('repo')
    const commondir = join(checkout, '.git', 'commondir')
    expect(spawnSync('mkfifo', [commondir]).status).toBe(0)

    const { result: command, waited } = await waitsOnFifoAt(commondir, () =>
      wrapIn(checkout),
    )

    expect(waited).toBe(false)
    expect(mountSource(command, commondir)).toBe(commondir)
  }, 60000)

  it('does not remove a name that stopped being its mount point', async () => {
    // The check looks through a link and the unlink does not, so a mount
    // point swapped for a link to an empty file would pass for still empty
    // and lose the link.
    const checkout = makeCheckout('repo')
    const commondir = join(checkout, '.git', 'commondir')
    const configWorktree = join(checkout, '.git', 'config.worktree')
    const emptyFile = join(dir, 'empty')
    const placeholderFile = join(dir, 'placeholder')
    writeFileSync(emptyFile, '')
    writeFileSync(placeholderFile, '.\n')

    await wrapIn(checkout)
    expect(readFileSync(commondir, 'utf8')).toBe('.\n')
    expect(readFileSync(configWorktree, 'utf8')).toBe('')
    rmSync(commondir)
    symlinkSync(placeholderFile, commondir)
    rmSync(configWorktree)
    symlinkSync(emptyFile, configWorktree)

    cleanupBwrapMountPoints({ force: true })

    expect(lstatSync(commondir).isSymbolicLink()).toBe(true)
    expect(lstatSync(configWorktree).isSymbolicLink()).toBe(true)
    expect(existsSync(placeholderFile)).toBe(true)
    expect(existsSync(emptyFile)).toBe(true)
  })

  /**
   * The ordinary arms, as one table: what each file of the git directory
   * holds before the wrap, what is bound over it, what the host finds there
   * while the command runs, and whether the cleanup takes it away.
   */
  describe('what is bound, by what was there', () => {
    const ownerCannotWrite = process.getuid?.() !== 0
    type Before = { contents: string; mode: number } | undefined
    type Expected = {
      /** 'itself', or the bytes of the placeholder file bound instead. */
      boundFrom: 'itself' | { placeholder: string }
      during: { contents: string; mode: number }
      removedByCleanup: boolean
    }
    const cases: {
      name: string
      file: 'commondir' | 'config.worktree'
      before: Before
      expected: Expected
    }[] = [
      {
        name: 'an absent commondir',
        file: 'commondir',
        before: undefined,
        expected: {
          boundFrom: { placeholder: '.\n' },
          during: { contents: '.\n', mode: 0o444 },
          removedByCleanup: true,
        },
      },
      {
        name: 'an absent config.worktree',
        file: 'config.worktree',
        before: undefined,
        expected: {
          boundFrom: { placeholder: '' },
          during: { contents: '', mode: 0o444 },
          removedByCleanup: true,
        },
      },
      {
        name: 'a commondir placeholder a killed wrap left',
        file: 'commondir',
        before: { contents: '.\n', mode: 0o444 },
        expected: {
          boundFrom: { placeholder: '.\n' },
          during: { contents: '.\n', mode: 0o444 },
          removedByCleanup: true,
        },
      },
      {
        name: 'a config.worktree placeholder a killed wrap left',
        file: 'config.worktree',
        before: { contents: '', mode: 0o444 },
        expected: {
          boundFrom: { placeholder: '' },
          during: { contents: '', mode: 0o444 },
          removedByCleanup: true,
        },
      },
      {
        name: 'a commondir naming a directory',
        file: 'commondir',
        before: { contents: '../..\n', mode: 0o644 },
        expected: {
          boundFrom: 'itself',
          during: { contents: '../..\n', mode: 0o644 },
          removedByCleanup: false,
        },
      },
      {
        name: 'a commondir as long as the placeholder, holding something else',
        file: 'commondir',
        before: { contents: '..', mode: 0o444 },
        expected: {
          boundFrom: 'itself',
          during: { contents: '..', mode: 0o444 },
          removedByCleanup: false,
        },
      },
      {
        name: 'a config.worktree with settings in it',
        file: 'config.worktree',
        before: { contents: '[core]\n', mode: 0o644 },
        expected: {
          boundFrom: 'itself',
          during: { contents: '[core]\n', mode: 0o644 },
          removedByCleanup: false,
        },
      },
      {
        name: 'an empty read-only commondir, the shape bubblewrap leaves',
        file: 'commondir',
        before: { contents: '', mode: 0o444 },
        expected: {
          boundFrom: { placeholder: '.\n' },
          // Rewritten in place; made writable for that only where the owner
          // of a read-only file cannot write it as it is.
          during: { contents: '.\n', mode: ownerCannotWrite ? 0o644 : 0o444 },
          removedByCleanup: true,
        },
      },
      {
        name: 'an empty writable commondir, a host git mid-write',
        file: 'commondir',
        before: { contents: '', mode: 0o644 },
        expected: {
          boundFrom: { placeholder: '.\n' },
          during: { contents: '', mode: 0o644 },
          removedByCleanup: false,
        },
      },
      {
        name: 'an empty writable config.worktree',
        file: 'config.worktree',
        before: { contents: '', mode: 0o644 },
        expected: {
          boundFrom: 'itself',
          during: { contents: '', mode: 0o644 },
          removedByCleanup: false,
        },
      },
    ]

    for (const { name, file, before, expected } of cases) {
      it(name, async () => {
        const checkout = makeCheckout('repo')
        const dest = join(checkout, '.git', file)
        if (before !== undefined) {
          writeWithMode(dest, before.contents, before.mode)
        }

        const command = await wrapIn(checkout)

        const mount = lastMountAt(command, dest)
        const source = mountSource(command, dest)
        expect(mount).toBe(`--ro-bind ${source} ${dest}`)
        expect(
          source === dest
            ? 'itself'
            : { placeholder: readFileSync(source, 'utf8') },
        ).toEqual(expected.boundFrom)
        expect(source).not.toBe('/dev/null')
        expect({
          contents: readFileSync(dest, 'utf8'),
          mode: statSync(dest).mode & 0o777,
        }).toEqual(expected.during)

        cleanupBwrapMountPoints({ force: true })
        expect(existsSync(dest)).toBe(!expected.removedByCleanup)
        if (!expected.removedByCleanup) {
          expect(readFileSync(dest, 'utf8')).toBe(expected.during.contents)
        }
      })
    }
  })
})
