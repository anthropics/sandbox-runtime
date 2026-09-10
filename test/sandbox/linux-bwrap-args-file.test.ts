import { describe, it, expect, beforeEach, afterEach } from 'bun:test'
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { spawnSync } from 'node:child_process'
import { tmpdir } from 'node:os'
import { basename, dirname, join } from 'node:path'
import {
  wrapCommandWithSandboxLinux,
  cleanupBwrapMountPoints,
} from '../../src/sandbox/linux-sandbox-utils.js'
import { isLinux } from '../helpers/platform.js'
import { bwrapCanNamespace } from '../helpers/bwrap.js'

/**
 * A bwrap profile too large for one shell argument (32 pages) has its mounts
 * handed to bwrap through `--args` from a file in a per-process directory
 * that every profile ro-binds over itself; a profile that fits stays on the
 * command line.
 */
describe.if(isLinux)('bwrap --args for over-long profiles', () => {
  const MAX_ARG_STRLEN =
    32 * Number(spawnSync('getconf', ['PAGESIZE'], { encoding: 'utf8' }).stdout)
  // The largest rendering kept on the command line: the kernel's limit less
  // the NUL, less the 4 KiB left for a prefix of the caller's own.
  const INLINE_MAX = MAX_ARG_STRLEN - 1 - 4096
  // The one rendered shape: file, then the options left before and the words
  // left after `--args 9`.
  const VIA_ARGS_FILE =
    /^\/bin\/sh -c 'exec 9<"\$1" && (?:\/\S+ -f -- "\$1" && )?shift && exec "\$@"' srt-args (\S+) bwrap (.*?) ?--args 9 (.*)$/s
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

  // The per-process --args directory, from the trailing ro-bind every
  // profile that fits the command line carries (an over-long profile
  // carries it inside the file).
  function argsDirOf(wrapped: string): string {
    const bind = wrapped.match(/--ro-bind (\S*\.srt-bwrap-args-\S+) \1(?: |$)/)
    expect(bind).not.toBeNull()
    return bind![1]!
  }

  function argsFileOf(wrapped: string): string {
    const rendered = wrapped.match(VIA_ARGS_FILE)
    expect(rendered).not.toBeNull()
    return rendered![1]!
  }

  // A fresh process for what depends on the module's per-process state (the
  // directory is created once and never again) or on TMPDIR at first use.
  // `body` runs after the prelude and prints one JSON value.
  function isolated(body: string, env: Record<string, string> = {}): unknown {
    const files = overLongProfile()
    const script = `
      import { wrapCommandWithSandboxLinux, cleanupBwrapMountPoints } from ${JSON.stringify(MODULE)}
      import * as fs from 'node:fs'
      const overLong = ${JSON.stringify(files)}
      const small = overLong.slice(0, 1)
      const wrap = denyOnly => wrapCommandWithSandboxLinux({
        command: 'echo hello',
        needsNetworkRestriction: false,
        readConfig: { denyOnly },
        writeConfig: { allowOnly: [], denyWithinAllow: [] },
      })
      const outcome = wrapping => wrapping.then(() => 'resolved', error => String(error))
      const argsDirOf = wrapped => wrapped.match(/--ro-bind (\\S*\\.srt-bwrap-args-\\S+) \\1(?: |$)/)?.[1]
      ${body}
    `
    // A file, not `-e`: the script names every fixture path, and would not
    // fit one argument itself.
    const scriptFile = join(BASE, 'isolated.ts')
    writeFileSync(scriptFile, script)
    // A tmpdir of its own, so what a scenario leaves there goes with BASE.
    mkdirSync(join(BASE, 'tmp'), { recursive: true })
    const run = spawnSync(process.execPath, ['run', scriptFile], {
      cwd: BASE,
      encoding: 'utf8',
      env: { ...process.env, TMPDIR: join(BASE, 'tmp'), ...env },
      timeout: 60000,
    })
    expect(run.stderr).toBe('')
    return JSON.parse(run.stdout)
  }

  it('keeps a profile that fits on the command line and still ro-binds the --args directory last', async () => {
    const files = maskedFiles(20)
    const wrapped = await wrap(files)
    expect(wrapped).not.toContain('--args')
    expect(wrapped).toContain(`--ro-bind /dev/null ${files[0]}`)
    // In every profile, not only the ones that use it: a sandbox launched
    // with a small profile may still be running when a later over-long one
    // is written there.
    const argsDir = argsDirOf(wrapped)
    expect(existsSync(argsDir)).toBe(true)
    expect(wrapped.lastIndexOf(`--ro-bind ${argsDir} ${argsDir}`)).toBe(
      wrapped.lastIndexOf('--ro-bind'),
    )
    // Dot-prefixed, so a sandboxed `rm -rf "$TMPDIR"/*` does not trip on the
    // mount point.
    expect(basename(argsDir).startsWith('.')).toBe(true)
  })

  it('moves the mounts, and only the mounts, to a NUL-separated file and stays a simple command', async () => {
    const files = overLongProfile()
    const wrapped = await wrap(files, {
      setEnvVars: { SRT_TEST_VAR: "value with spaces and 'quotes'" },
    })

    expect(Buffer.byteLength(wrapped)).toBeLessThan(MAX_ARG_STRLEN)
    const [, argsFile, before, after] = wrapped.match(VIA_ARGS_FILE)!
    const argsDir = dirname(argsFile!)
    expect(basename(argsDir)).toMatch(/^\.srt-bwrap-args-/)

    const words = readFileSync(argsFile!, 'utf8').split('\0')
    expect(words[words.length - 1]).toBe('')
    const mounts = words.slice(0, -1)
    expect(mounts.filter(w => w === '/dev/null').length).toBe(files.length)
    expect(mounts).toContain(files[0])
    expect(mounts.slice(-3)).toEqual(['--ro-bind', argsDir, argsDir])
    // The file is readable in every sandbox of the process: nothing about
    // the command or its environment goes there.
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

  it('removes a file that was never spawned at cleanup and keeps the directory for the process', async () => {
    const argsFile = argsFileOf(await wrap(overLongProfile()))
    expect(existsSync(argsFile)).toBe(true)
    cleanupBwrapMountPoints()
    expect(existsSync(argsFile)).toBe(false)
    // A sandbox launched earlier may still have the directory bound.
    cleanupBwrapMountPoints({ force: true })
    expect(existsSync(dirname(argsFile))).toBe(true)
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

  it('refuses a command that is too long for one argument by itself, and writes no file for it', async () => {
    const argsDir = argsDirOf(await wrap(maskedFiles(1)))
    expect(
      await rejection(
        wrap(maskedFiles(20), { command: 'a'.repeat(MAX_ARG_STRLEN) }),
      ),
    ).toMatch(/too long for one shell argument even with the mounts/)
    expect(readdirSync(argsDir)).toEqual([])
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

  it('refuses over-long profiles for the rest of the process once the directory has been replaced', () => {
    const seen = isolated(`
      const made = argsDirOf(await wrap(small))
      // Same path, another inode: what a sandbox with the parent writable,
      // or a tmp cleaner followed by anyone, can arrange.
      fs.renameSync(made, made + '.aside')
      fs.mkdirSync(made, { mode: 0o700 })
      const refused = await outcome(wrap(overLong))
      const afterRefusal = await wrap(small)
      cleanupBwrapMountPoints()
      cleanupBwrapMountPoints({ force: true })
      console.log(JSON.stringify({
        refused,
        planted: fs.readdirSync(made),
        stillBinds: argsDirOf(afterRefusal) !== undefined,
        refusedAfterReset: await outcome(wrap(overLong)),
      }))
    `)
    expect(seen).toEqual({
      refused: expect.stringMatching(
        /cannot be passed through a file until this process restarts: \S+ was removed or replaced/,
      ),
      planted: [],
      stillBinds: false,
      refusedAfterReset: expect.stringMatching(/was removed or replaced/),
    })
  })

  it('says so, rather than ENOENT, when the directory vanishes while a profile is being generated', () => {
    const seen = isolated(`
      const made = argsDirOf(await wrap(small))
      const wrapping = outcome(wrap(overLong))
      fs.rmSync(made, { recursive: true })
      console.log(JSON.stringify(await wrapping))
    `)
    expect(seen).toMatch(/until this process restarts: \S+ was removed/)
  })

  it('wraps a profile that fits when tmpdir is unusable, and refuses only the over-long one', () => {
    // A file where the directory should be: not creatable by root either.
    writeFileSync(join(BASE, 'not-a-directory'), '')
    const seen = isolated(
      `
      const fits = await wrap(small)
      console.log(JSON.stringify({
        fits: fits.includes('--ro-bind /dev/null') && !fits.includes('srt-bwrap-args'),
        refused: await outcome(wrap(overLong)),
      }))
    `,
      { TMPDIR: join(BASE, 'not-a-directory') },
    )
    expect(seen).toEqual({
      fits: true,
      refused: expect.stringMatching(/it could not be created under \S+/),
    })
  })

  it.if(BWRAP_CAN_NAMESPACE)(
    'e2e: binds the directory by its resolved path, which bwrap before 0.12 needs when tmpdir is behind an absolute symlink',
    () => {
      mkdirSync(join(BASE, 'real-tmp'))
      symlinkSync(join(BASE, 'real-tmp'), join(BASE, 'link-tmp'))
      const seen = isolated(
        `
        const { spawnSync } = await import('node:child_process')
        const wrapped = await wrap(small)
        const run = spawnSync(wrapped, { shell: true, encoding: 'utf8' })
        console.log(JSON.stringify({ argsDir: argsDirOf(wrapped), status: run.status, stdout: run.stdout }))
      `,
        { TMPDIR: join(BASE, 'link-tmp') },
      ) as { argsDir: string; status: number; stdout: string }
      expect(dirname(seen.argsDir)).toBe(join(BASE, 'real-tmp'))
      expect(seen).toMatchObject({ status: 0, stdout: 'hello\n' })
    },
    60_000,
  )

  it.if(BWRAP_CAN_NAMESPACE)(
    'e2e: bwrap applies the mounts from the file, the string composes with a prefix and a suffix, and the command sees neither the fd nor a writable --args directory',
    async () => {
      const argsDir = argsDirOf(await wrap(maskedFiles(1)))
      const probe = join(argsDir, 'srt-args-probe')
      const files = overLongProfile()
      // tmpdir writable inside the sandbox: the case the trailing ro-bind
      // exists for. The runner's tmpdir is scanned shallowly, since every
      // mount costs bwrap time.
      const wrapped = await wrap(files, {
        allowOnly: [tmpdir()],
        mandatoryDenySearchDepth: 1,
        command: [
          // The mask is a bind of /dev/null: a character device in place
          // of the file (opening a device node inside the user namespace
          // is not portable across hosts, so its type is the oracle).
          `[ -c ${files[0]} ] && echo MASKED || echo UNMASKED`,
          '[ -e /proc/self/fd/9 ] && echo FD9_OPEN || echo FD9_CLOSED',
          `touch ${probe} 2>/dev/null && echo ARGS_WRITABLE || echo ARGS_READONLY`,
        ].join('; '),
      })
      const argsFile = argsFileOf(wrapped)
      expect(dirname(argsFile)).toBe(argsDir)
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
        'ARGS_READONLY',
        'AFTER',
      ])
      expect(readFileSync(files[0]!, 'utf8')).toBe('secret\n')
      expect(existsSync(probe)).toBe(false)
      // Unlinked by the spawn itself.
      expect(existsSync(argsFile)).toBe(false)
    },
    60_000,
  )
})
