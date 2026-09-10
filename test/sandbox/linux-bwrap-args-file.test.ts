import { describe, it, expect, beforeEach, afterEach } from 'bun:test'
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { spawnSync } from 'node:child_process'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import {
  wrapCommandWithSandboxLinux,
  cleanupBwrapMountPoints,
} from '../../src/sandbox/linux-sandbox-utils.js'
import { isLinux } from '../helpers/platform.js'

/**
 * A bwrap profile too large for one shell argument (128 KiB on a 4 KiB-page
 * kernel) is handed to bwrap through `--args` from a file in a per-process
 * directory that every profile ro-binds over itself; a profile that fits
 * stays on the command line.
 */
describe.if(isLinux)('bwrap --args for over-long profiles', () => {
  const MAX_ARG_STRLEN = 128 * 1024
  const VIA_ARGS_FILE = /^\{ command rm -f -- (\S+); exec bwrap --args 9 -- /

  let BASE: string
  const savedCwd = process.cwd()

  // Only where bwrap can create the user and pid namespaces and mount /proc.
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

  beforeEach(() => {
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

  // `count` files, each its own /dev/null mask, as the concrete list the
  // wrapper takes (glob expansion happens a layer up, in SandboxManager).
  function flatFiles(
    count: number,
    stem = 'a-reasonably-long-file-name-to-fill-the-profile-',
  ): string[] {
    const dir = join(BASE, 'many')
    mkdirSync(dir, { recursive: true })
    const files: string[] = []
    for (let i = 0; i < count; i++) {
      const file = join(dir, `${stem}${i}.log`)
      // Content, so the e2e case can tell the host file was left alone.
      writeFileSync(file, 'secret\n')
      files.push(file)
    }
    return files
  }

  // 2000 masks of ~80 bytes each: well past 128 KiB as one argument.
  const overLongProfile = (): string[] => flatFiles(2000)

  async function wrap(
    files: string[],
    opts: {
      command?: string
      allowOnly?: string[]
      setEnvVars?: Record<string, string>
      mandatoryDenySearchDepth?: number
    } = {},
  ): Promise<string> {
    return wrapCommandWithSandboxLinux({
      command: opts.command ?? 'echo hello',
      needsNetworkRestriction: false,
      readConfig: { denyOnly: files },
      writeConfig: { allowOnly: opts.allowOnly ?? [], denyWithinAllow: [] },
      setEnvVars: opts.setEnvVars,
      mandatoryDenySearchDepth: opts.mandatoryDenySearchDepth,
    })
  }

  // The per-process --args directory, from the trailing ro-bind every
  // profile that fits the command line carries (an over-long profile
  // carries it inside the file).
  function argsDirOf(wrapped: string): string {
    const bind = wrapped.match(/--ro-bind (\S*srt-bwrap-args-\S+) \1(?: |$)/)
    expect(bind).not.toBeNull()
    return bind![1]!
  }

  function argsFileOf(wrapped: string): string {
    const redirect = wrapped.match(/ 9<(\S+)$/)
    expect(redirect).not.toBeNull()
    return redirect![1]!
  }

  it('keeps a profile that fits on the command line and still ro-binds the --args directory last', async () => {
    const files = flatFiles(20)
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
  })

  it('moves every option, and only the options, to a NUL-separated file the string opens on fd 9 and unlinks', async () => {
    const files = overLongProfile()
    const wrapped = await wrap(files, {
      setEnvVars: { SRT_TEST_VAR: "value with spaces and 'quotes'" },
    })

    expect(Buffer.byteLength(wrapped)).toBeLessThan(MAX_ARG_STRLEN)
    // `--args 9` is followed at once by the trailer: no option is left on
    // the line.
    expect(wrapped).toMatch(
      /^\{ command rm -f -- \S+; exec bwrap --args 9 -- \S+ -c .+; \} 9<\S+$/s,
    )
    const argsFile = argsFileOf(wrapped)
    expect(wrapped.match(VIA_ARGS_FILE)![1]).toBe(argsFile)
    const argsDir = dirname(argsFile)
    expect(argsDir).toMatch(/srt-bwrap-args-/)

    const words = readFileSync(argsFile, 'utf8').split('\0')
    expect(words[words.length - 1]).toBe('')
    const options = words.slice(0, -1)
    expect(options).not.toContain('--')
    expect(options).not.toContain('-c')
    expect(
      options.filter(w => w === '--ro-bind').length,
    ).toBeGreaterThanOrEqual(files.length)
    expect(options).toContain(files[0])
    const lastBind = options.lastIndexOf('--ro-bind')
    expect(options.slice(lastBind, lastBind + 3)).toEqual([
      '--ro-bind',
      argsDir,
      argsDir,
    ])
    // A value bwrap must receive verbatim: one word, unquoted.
    const setenv = options.indexOf('--setenv')
    expect(options.slice(setenv, setenv + 3)).toEqual([
      '--setenv',
      'SRT_TEST_VAR',
      "value with spaces and 'quotes'",
    ])
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

  it('switches to --args exactly where one argument would exceed 128 KiB', async () => {
    // The command is the last word on the line; a trailing two-byte
    // character keeps the shell quoter's output constant while every
    // added 'a' adds one byte, so the padding sets the rendered size byte
    // for byte, and a regression to string length (UTF-16 units) would
    // miscount it by one.
    const files = flatFiles(20)
    const base = await wrap(files, { command: 'é' })
    expect(base).not.toContain('--args')
    const renderedAt = (bytes: number) =>
      wrap(files, {
        command: 'a'.repeat(bytes - Buffer.byteLength(base)) + 'é',
      })

    const fits = await renderedAt(MAX_ARG_STRLEN - 1)
    expect(Buffer.byteLength(fits)).toBe(MAX_ARG_STRLEN - 1)
    expect(fits).not.toContain('--args')

    expect(await renderedAt(MAX_ARG_STRLEN)).toMatch(VIA_ARGS_FILE)
  })

  it('leaves a command that alone exceeds 128 KiB to the kernel, whose cap grows with the page size', async () => {
    const wrapped = await wrap(flatFiles(20), {
      command: 'a'.repeat(MAX_ARG_STRLEN),
    })
    expect(wrapped).toMatch(VIA_ARGS_FILE)
    expect(Buffer.byteLength(wrapped)).toBeGreaterThan(MAX_ARG_STRLEN)
  })

  it('refuses an over-long profile after the directory was replaced under a sandbox that may still be running', async () => {
    const removed = argsDirOf(await wrap(flatFiles(1)))
    rmSync(removed, { recursive: true, force: true })

    const refusal = await wrap(overLongProfile()).then(
      () => undefined,
      (err: unknown) => err,
    )
    expect(String(refusal)).toMatch(
      /removed while an earlier sandboxed command/,
    )
    // A profile that fits only binds the directory, so it still wraps.
    const replacement = argsDirOf(await wrap(flatFiles(1)))
    expect(replacement).not.toBe(removed)
    expect(existsSync(replacement)).toBe(true)

    // Once no sandbox is active, no sandbox predates the new directory.
    cleanupBwrapMountPoints({ force: true })
    const wrapped = await wrap(overLongProfile())
    expect(dirname(argsFileOf(wrapped))).toBe(replacement)
  })

  it.if(BWRAP_CAN_NAMESPACE)(
    'e2e: bwrap applies the profile from the file, and the command sees neither the fd nor a writable --args directory',
    async () => {
      const argsDir = argsDirOf(await wrap(flatFiles(1)))
      const probe = join(argsDir, 'srt-args-probe')
      // tmpdir writable inside the sandbox: the case the trailing ro-bind
      // exists for. Fewer, longer-named masks than the shape test: every
      // mount costs bwrap time, and the runner's tmpdir is scanned shallowly
      // for the same reason.
      const files = flatFiles(700, `${'a'.repeat(150)}-`)
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
      const run = spawnSync(wrapped, {
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
      ])
      expect(readFileSync(files[0]!, 'utf8')).toBe('secret\n')
      expect(existsSync(probe)).toBe(false)
      // Unlinked by the spawn itself.
      expect(existsSync(argsFile)).toBe(false)
    },
    60_000,
  )
})
