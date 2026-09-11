import { describe, it, expect, beforeEach, afterEach } from 'bun:test'
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readlinkSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { spawnSync } from 'node:child_process'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  wrapCommandWithSandboxLinux,
  cleanupBwrapMountPoints,
} from '../../src/sandbox/linux-sandbox-utils.js'
import { isLinux } from '../helpers/platform.js'
import { bwrapCanNamespace } from '../helpers/bwrap.js'

/**
 * A bwrap profile too large for one shell argument (32 pages) has its mounts
 * handed to bwrap through `--args`, from an unnamed file this process holds
 * open and the string reopens through /proc; a profile that fits stays on the
 * command line.
 */
describe.if(isLinux)('bwrap --args for over-long profiles', () => {
  const MAX_ARG_STRLEN =
    32 * Number(spawnSync('getconf', ['PAGESIZE'], { encoding: 'utf8' }).stdout)
  // The largest rendering kept on the command line: the kernel's limit less
  // the NUL, less the 4 KiB left for a prefix of the caller's own.
  const INLINE_MAX = MAX_ARG_STRLEN - 1 - 4096
  // The one rendered shape: the profile's path, then the options left before
  // and the words left after `--args 9`.
  const VIA_ARGS_FILE =
    /^\/bin\/sh -c 'exec 9<"\$1" && shift && exec "\$@"' srt-args (\S+) bwrap (.*?) ?--args 9 (.*)$/s
  const MODULE = join(
    import.meta.dir,
    '../../src/sandbox/linux-sandbox-utils.ts',
  )

  let BASE: string
  const savedCwd = process.cwd()
  const BWRAP_CAN_NAMESPACE = bwrapCanNamespace()

  beforeEach(() => {
    // Other suites wrap without cleaning up, and the active count is shared.
    cleanupBwrapMountPoints({ force: true })
    BASE = realpathSync(mkdtempSync(join(tmpdir(), 'bwrap-args-')))
    // cwd outside the write allowlist keeps the mandatory-deny scan from
    // adding mounts of its own.
    process.chdir(BASE)
  })

  afterEach(() => {
    process.chdir(savedCwd)
    cleanupBwrapMountPoints({ force: true })
    rmSync(BASE, { recursive: true, force: true })
  })

  // `count` files with names near the 255-byte limit, each its own /dev/null
  // mask, as the concrete list the wrapper takes (glob expansion happens a
  // layer up, in SandboxManager).
  function maskedFiles(count: number): string[] {
    const dir = join(BASE, 'many')
    mkdirSync(dir, { recursive: true })
    const files: string[] = []
    for (let i = 0; i < count; i++) {
      const file = join(dir, `${'a'.repeat(240)}-${i}.log`)
      // Content, so the e2e case can tell the host file was left alone.
      writeFileSync(file, 'secret\n')
      files.push(file)
    }
    return files
  }

  // Each mask renders as about 300 bytes: comfortably past the cap.
  const overLongProfile = (): string[] =>
    maskedFiles(Math.ceil(MAX_ARG_STRLEN / 300) + 50)

  async function wrap(
    files: string[],
    opts: {
      command?: string
      allowOnly?: string[]
      denyWithinAllow?: string[]
      setEnvVars?: Record<string, string>
      unsetEnvVars?: string[]
      mandatoryDenySearchDepth?: number
    } = {},
  ): Promise<string> {
    return wrapCommandWithSandboxLinux({
      command: opts.command ?? 'echo hello',
      needsNetworkRestriction: false,
      readConfig: { denyOnly: files },
      writeConfig: {
        allowOnly: opts.allowOnly ?? [],
        denyWithinAllow: opts.denyWithinAllow ?? [],
      },
      setEnvVars: opts.setEnvVars,
      unsetEnvVars: opts.unsetEnvVars,
      mandatoryDenySearchDepth: opts.mandatoryDenySearchDepth,
    })
  }

  function rejection(wrapping: Promise<string>): Promise<string> {
    return wrapping.then(
      () => 'resolved',
      (error: unknown) => String(error),
    )
  }

  function argsPathOf(wrapped: string): string {
    const rendered = wrapped.match(VIA_ARGS_FILE)
    expect(rendered).not.toBeNull()
    return rendered![1]!
  }

  // A fresh process for what depends on the module's per-process state (the
  // open profiles, the fd baseline) or on TMPDIR at first use. `body` runs
  // after the prelude and prints one JSON value; `launcher` runs the runtime
  // itself under something (bwrap, to take away the directories an unnamed
  // file can go in).
  function isolated(
    body: string,
    env: Record<string, string> = {},
    launcher: string[] = [],
  ): unknown {
    const files = overLongProfile()
    const script = `
      import { wrapCommandWithSandboxLinux, cleanupBwrapMountPoints } from ${JSON.stringify(MODULE)}
      import * as fs from 'node:fs'
      const overLong = ${JSON.stringify(files)}
      const small = overLong.slice(0, 1)
      const wrap = (denyOnly, command = 'echo hello') => wrapCommandWithSandboxLinux({
        command,
        needsNetworkRestriction: false,
        readConfig: { denyOnly },
        writeConfig: { allowOnly: [], denyWithinAllow: [] },
      })
      const outcome = wrapping => wrapping.then(() => 'resolved', error => String(error))
      const argsPathOf = wrapped => wrapped.match(/' srt-args (\\S+) /)?.[1]
      ${body}
    `
    // A file, not `-e`: the script names every fixture path, and would not
    // fit one argument itself.
    const scriptFile = join(BASE, 'isolated.ts')
    writeFileSync(scriptFile, script)
    // A tmpdir of its own, so what a scenario leaves there goes with BASE.
    mkdirSync(join(BASE, 'tmp'), { recursive: true })
    const argv = [...launcher, process.execPath, 'run', scriptFile]
    const run = spawnSync(argv[0]!, argv.slice(1), {
      cwd: BASE,
      encoding: 'utf8',
      env: { ...process.env, TMPDIR: join(BASE, 'tmp'), ...env },
      timeout: 60000,
    })
    expect(run.stderr).toBe('')
    return JSON.parse(run.stdout)
  }

  it('keeps a profile that fits on the command line, and names no file for it', async () => {
    const files = maskedFiles(20)
    const wrapped = await wrap(files)
    expect(wrapped).not.toContain('--args')
    expect(wrapped).not.toContain('srt-args')
    expect(wrapped).toContain(`--ro-bind /dev/null ${files[0]}`)
  })

  it('moves the mounts, and only the mounts, to an unnamed file the string reopens through /proc', async () => {
    const files = overLongProfile()
    const wrapped = await wrap(files, {
      setEnvVars: { SRT_TEST_VAR: "value with spaces and 'quotes'" },
    })

    expect(Buffer.byteLength(wrapped)).toBeLessThan(MAX_ARG_STRLEN)
    const [, argsPath, before, after] = wrapped.match(VIA_ARGS_FILE)!
    // This process's own fd: the profile has no name anywhere, so nothing
    // can be put in its place between here and the execution.
    expect(argsPath).toMatch(new RegExp(`^/proc/${process.pid}/fd/\\d+$`))
    expect(readlinkSync(argsPath!)).toMatch(/\(deleted\)$/)

    const words = readFileSync(argsPath!, 'utf8').split('\0')
    expect(words[words.length - 1]).toBe('')
    const mounts = words.slice(0, -1)
    expect(mounts.filter(w => w === '/dev/null').length).toBe(files.length)
    expect(mounts).toContain(files[0])
    // Only mounts go to the file: nothing about the command or its
    // environment is in it.
    expect(
      mounts.filter(
        w => w.startsWith('--') && !/^--(ro-bind|bind|tmpfs)$/.test(w),
      ),
    ).toEqual([])
    expect(before).toContain(
      `--setenv SRT_TEST_VAR 'value with spaces and '"'"'quotes'"'"''`,
    )
    expect(before).toContain('--new-session')
    expect(before).not.toContain('--ro-bind /dev/null')
    // What followed the mounts still follows them.
    expect(after).toMatch(/--unshare-pid .* -- \S+ -c /s)
  })

  it('switches to the file exactly where one argument would come within 4 KiB of the cap', async () => {
    // The command is the last word on the line; a trailing two-byte
    // character keeps the shell quoter's output constant while every
    // added 'a' adds one byte, so the padding sets the rendered size byte
    // for byte, and a regression to string length (UTF-16 units) would
    // miscount it by one.
    const files = maskedFiles(20)
    const base = await wrap(files, { command: 'é' })
    expect(base).not.toContain('--args')
    const renderedAt = (bytes: number) =>
      wrap(files, {
        command: 'a'.repeat(bytes - Buffer.byteLength(base)) + 'é',
      })

    const fits = await renderedAt(INLINE_MAX)
    expect(Buffer.byteLength(fits)).toBe(INLINE_MAX)
    expect(fits).not.toContain('--args')

    expect(await renderedAt(INLINE_MAX + 1)).toMatch(VIA_ARGS_FILE)
  })

  it('refuses a command that is too long for one argument by itself', async () => {
    expect(
      await rejection(
        wrap(maskedFiles(20), { command: 'a'.repeat(MAX_ARG_STRLEN) }),
      ),
    ).toMatch(/too long for one shell argument even with the mounts/)
  })

  it('refuses a profile past the 9000 arguments bwrap accepts', async () => {
    const names = Array.from({ length: 4500 }, (_, i) => `V${i}`)
    expect(
      await rejection(wrap(maskedFiles(1), { unsetEnvVars: names })),
    ).toMatch(/bwrap accepts at most 9000/)
  })

  it('refuses a mount path with a NUL byte, which bwrap would split into several options', async () => {
    expect(
      await rejection(
        wrap(overLongProfile(), {
          allowOnly: [BASE],
          denyWithinAllow: [join(BASE, 'x\0--cap-add\0ALL')],
        }),
      ),
    ).toMatch(/NUL byte/)
  })

  it('holds one fd per pending profile and gives them all back at cleanup, a refused wrap included', () => {
    const seen = isolated(`
      const openFds = () => fs.readdirSync('/proc/self/fd').length
      // The runtime opens event-loop fds of its own on the first wrap.
      await wrap(small)
      const baseline = openFds()
      await wrap(overLong)
      await wrap(overLong)
      const held = openFds() - baseline
      // A rendering that cannot be run releases its profile too.
      const refused = await outcome(wrap(overLong, 'a'.repeat(${MAX_ARG_STRLEN})))
      const afterRefusal = openFds() - baseline
      cleanupBwrapMountPoints({ force: true })
      console.log(JSON.stringify({ held, refused, afterRefusal, afterCleanup: openFds() - baseline }))
    `)
    expect(seen).toEqual({
      held: 2,
      refused: expect.stringMatching(/too long for one shell argument/),
      afterRefusal: 2,
      afterCleanup: 0,
    })
  })

  it('refuses at wrap time, with the reason, when no directory takes an unnamed file', () => {
    // Both candidates read-only: tmpdir and /dev/shm. A profile that fits
    // needs neither and is unaffected.
    const roTmp = join(BASE, 'ro-tmp')
    mkdirSync(roTmp)
    const seen = isolated(
      `
      const fits = await wrap(small)
      console.log(JSON.stringify({
        fits: fits.includes('--ro-bind /dev/null') && !fits.includes('srt-args'),
        refused: await outcome(wrap(overLong)),
      }))
    `,
      { TMPDIR: roTmp },
      [
        'bwrap',
        '--dev-bind',
        '/',
        '/',
        '--ro-bind',
        '/etc',
        '/dev/shm',
        '--ro-bind',
        '/etc',
        roTmp,
      ],
    )
    expect(seen).toEqual({
      fits: true,
      refused: expect.stringMatching(
        /cannot be passed through a file: no unnamed file could be opened for it \(.*read-only/s,
      ),
    })
  })

  it('fails in the redirection, and does not run the command, when the string is run after its cleanup', async () => {
    const marker = join(BASE, 'ran')
    const wrapped = await wrap(overLongProfile(), {
      command: `touch ${marker}`,
    })
    cleanupBwrapMountPoints({ force: true })
    // No pipes for the run: a parent-side fd would take the number the
    // profile just gave up.
    const run = spawnSync(wrapped, {
      shell: true,
      stdio: 'ignore',
      timeout: 60000,
    })
    expect(run.status).not.toBe(0)
    expect(existsSync(marker)).toBe(false)
  })

  it.if(BWRAP_CAN_NAMESPACE)(
    'e2e: a pending profile survives a tmpdir whose parent is replaced, because no path leads to it',
    () => {
      const parent = join(BASE, 'scratch')
      mkdirSync(join(parent, 'tmp'), { recursive: true })
      const marker = join(BASE, 'written-by-the-sandbox')
      const seen = isolated(
        `
        const { spawnSync } = await import('node:child_process')
        const wrapped = await wrap(overLong, 'touch ${marker} 2>/dev/null && echo WROTE || echo DENIED')
        const argsPath = argsPathOf(wrapped)
        // The runtime leaves a cache of its own there; nothing of ours.
        const namedUnderTmpdir = fs.readdirSync(process.env.TMPDIR, { recursive: true })
          .filter(entry => /srt|args|bwrap/.test(entry))
        // What a sandbox with the parent writable, or another process of
        // this user sandboxing with tmpdir writable, can arrange: the
        // directory goes aside, and a profile that binds / read-write takes
        // the place of every path the string could still open.
        fs.renameSync(${JSON.stringify(parent)}, ${JSON.stringify(parent + '.aside')})
        let planted = null
        if (!argsPath.startsWith('/proc/')) {
          fs.mkdirSync(argsPath.slice(0, argsPath.lastIndexOf('/')), { recursive: true })
          fs.writeFileSync(argsPath, '--bind\\0/\\0/\\0')
          planted = argsPath
        }
        const run = spawnSync(wrapped, { shell: true, encoding: 'utf8', timeout: 60000 })
        console.log(JSON.stringify({
          argsPath,
          namedUnderTmpdir,
          planted,
          status: run.status,
          stdout: run.stdout.trim(),
          marker: fs.existsSync(${JSON.stringify(marker)}),
        }))
      `,
        { TMPDIR: join(parent, 'tmp') },
      )
      expect(seen).toEqual({
        argsPath: expect.stringMatching(/^\/proc\/\d+\/fd\/\d+$/),
        namedUnderTmpdir: [],
        planted: null,
        status: 0,
        // The command ran under the profile that was wrapped, not one
        // planted after it.
        stdout: 'DENIED',
        marker: false,
      })
    },
    60_000,
  )

  it.if(BWRAP_CAN_NAMESPACE)(
    'e2e: bwrap applies the mounts from the file, the string composes with a prefix and a suffix, and the command reaches neither fd 9 nor the profile',
    async () => {
      const files = overLongProfile()
      // tmpdir writable inside the sandbox: with nothing named there, that
      // is no longer a way to the pending profile. The runner's tmpdir is
      // scanned shallowly, since every mount costs bwrap time.
      const wrapped = await wrap(files, {
        allowOnly: [tmpdir()],
        mandatoryDenySearchDepth: 1,
        command: [
          // The mask is a bind of /dev/null: a character device in place
          // of the file (opening a device node inside the user namespace
          // is not portable across hosts, so its type is the oracle).
          `[ -c ${files[0]} ] && echo MASKED || echo UNMASKED`,
          '[ -e /proc/self/fd/9 ] && echo FD9_OPEN || echo FD9_CLOSED',
          // A fresh /proc in its own PID namespace: the wrapping process,
          // and so the fd its profiles are on, is not there at all.
          `[ -e /proc/${process.pid} ] && echo RUNTIME_PROC_VISIBLE || echo RUNTIME_PROC_HIDDEN`,
        ].join('; '),
      })
      expect(argsPathOf(wrapped)).toMatch(
        new RegExp(`^/proc/${process.pid}/fd/\\d+$`),
      )
      const run = spawnSync(`timeout 60 ${wrapped} && echo AFTER`, {
        shell: true,
        encoding: 'utf8',
        timeout: 60000,
        cwd: BASE,
      })
      expect(run.status).toBe(0)
      expect(run.stdout.trim().split('\n')).toEqual([
        'MASKED',
        'FD9_CLOSED',
        'RUNTIME_PROC_HIDDEN',
        'AFTER',
      ])
      expect(readFileSync(files[0]!, 'utf8')).toBe('secret\n')
    },
    60_000,
  )
})
