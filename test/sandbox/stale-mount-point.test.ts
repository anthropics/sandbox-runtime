import { describe, it, expect, beforeEach, afterEach } from 'bun:test'
import {
  chmodSync,
  existsSync,
  linkSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  realpathSync,
  rmSync,
  rmdirSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { spawnSync } from 'node:child_process'
import { basename, join } from 'node:path'
import { tmpdir } from 'node:os'
import {
  wrapCommandWithSandboxLinux,
  cleanupBwrapMountPoints,
} from '../../src/sandbox/linux-sandbox-utils.js'
import { isLinux } from '../helpers/platform.js'

// Same probe as readonly-deny-dir-stubs.test.ts: the runtime arms need the
// namespace and /proc surface the wrapped commands use.
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

function run(
  command: string,
  cwd?: string,
): { status: number | null; stdout: string } {
  const r = spawnSync(command, {
    shell: true,
    encoding: 'utf8',
    timeout: 15000,
    cwd,
  })
  return { status: r.status, stdout: `${r.stdout}${r.stderr}` }
}

function escapeForRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

/**
 * A denyWrite path that does not exist gets `--ro-bind /dev/null <path>`, and
 * bwrap creates the mount point for it on the host: an empty file, mode 0444.
 * The wrapping process removes it after the command, from a set it keeps in
 * memory. A process killed before that (SIGKILL, OOM) leaves the file behind,
 * and it used to stay for good: every later wrap saw an existing file, bound
 * it onto itself and never removed it. For a path whose existence is its
 * meaning that is a lasting fault on the host: a leftover `.git/config.lock`
 * makes every `git config` write outside the sandbox fail with "could not
 * lock config file".
 */
describe.if(isLinux)('A mount point an earlier sandbox left behind', () => {
  let BASE: string
  let AREA: string // allowed write area
  let GIT_DIR: string
  let LOCK: string // the denyWrite path
  let OUTSIDE: string // not under any allowed write path

  beforeEach(() => {
    BASE = realpathSync(mkdtempSync(join(tmpdir(), 'stale-mount-point-')))
    AREA = join(BASE, 'area')
    GIT_DIR = join(AREA, 'repo', '.git')
    LOCK = join(GIT_DIR, 'config.lock')
    OUTSIDE = join(BASE, 'outside')
    mkdirSync(GIT_DIR, { recursive: true })
    mkdirSync(OUTSIDE, { recursive: true })
    writeFileSync(join(GIT_DIR, 'config'), '[core]\n')
  })

  afterEach(() => {
    cleanupBwrapMountPoints({ force: true })
    // A control's 0444 file would survive rmSync's unlink only on a
    // read-only directory; these directories are writable.
    rmSync(BASE, { recursive: true, force: true })
  })

  async function wrap(denyPaths: string[], command = 'true'): Promise<string> {
    return wrapCommandWithSandboxLinux({
      command,
      needsNetworkRestriction: false,
      readConfig: { denyOnly: [] },
      writeConfig: { allowOnly: [AREA], denyWithinAllow: denyPaths },
    })
  }

  /** What bwrap's ensure_file(dest, 0444) leaves on the host. */
  function plantLeftover(p: string): void {
    writeFileSync(p, '')
    chmodSync(p, 0o444)
  }

  it('is covered with /dev/null like an absent path, and removed after the command', async () => {
    plantLeftover(LOCK)

    const command = await wrap([LOCK])

    expect(command).toContain(`--ro-bind /dev/null ${LOCK}`)
    expect(command).not.toContain(`--ro-bind ${LOCK} ${LOCK}`)

    cleanupBwrapMountPoints()
    expect(existsSync(LOCK)).toBe(false)
  })

  it('waits for every outstanding sandbox before it is removed', async () => {
    plantLeftover(LOCK)

    await wrap([LOCK])
    await wrap([LOCK])

    cleanupBwrapMountPoints()
    // Unlinking it now would detach the second sandbox's bind.
    expect(existsSync(LOCK)).toBe(true)
    cleanupBwrapMountPoints()
    expect(existsSync(LOCK)).toBe(false)
  })

  // Everything below only LOOKS like a leftover in one respect. Each is
  // somebody's file: bound onto itself as an existing deny path, and still
  // there afterwards.
  it.each([
    [
      'an empty file with write bits (a lockfile, a file made empty on purpose)',
      (p: string) => {
        writeFileSync(p, '')
        chmodSync(p, 0o644)
      },
    ],
    [
      'a read-only file with content',
      (p: string) => {
        writeFileSync(p, 'x')
        chmodSync(p, 0o444)
      },
    ],
    [
      'an empty read-only file with a second link',
      (p: string) => {
        plantLeftover(p)
        linkSync(p, `${p}.other-name`)
      },
    ],
  ])('leaves %s alone', async (_what, plant) => {
    plant(LOCK)

    const command = await wrap([LOCK])

    expect(command).toContain(`--ro-bind ${LOCK} ${LOCK}`)
    expect(command).not.toContain(`/dev/null ${LOCK}`)
    cleanupBwrapMountPoints()
    expect(existsSync(LOCK)).toBe(true)
  })

  it('leaves an empty read-only file alone where no sandbox could have made it: outside every allowed write path', async () => {
    const outsideFile = join(OUTSIDE, 'config.lock')
    plantLeftover(outsideFile)

    const command = await wrap([outsideFile])

    // Already read-only from --ro-bind / /: no bind of either kind.
    expect(command).not.toContain(` ${outsideFile}`)
    cleanupBwrapMountPoints()
    expect(existsSync(outsideFile)).toBe(true)
  })

  it.if(BWRAP_CAN_NAMESPACE)(
    'still denies the write while covered, and the path stays denied once it is absent again',
    async () => {
      plantLeftover(LOCK)

      const overLeftover = run(
        await wrap([LOCK], `echo x > ${LOCK}; echo rc=$?`),
      )
      expect(overLeftover.stdout).toMatch(/rc=[1-9]/)
      expect(lstatSync(LOCK).size).toBe(0)
      cleanupBwrapMountPoints()
      expect(existsSync(LOCK)).toBe(false)

      // Now the ordinary absent case: nothing can create it, nothing stays.
      const command = await wrap([LOCK], `echo x > ${LOCK}; echo rc=$?`)
      expect(command).toContain(`--ro-bind /dev/null ${LOCK}`)
      expect(run(command).stdout).toMatch(/rc=[1-9]/)
      cleanupBwrapMountPoints()
      expect(existsSync(LOCK)).toBe(false)
      // The neighbour it protects is still what it was.
      expect(lstatSync(join(GIT_DIR, 'config')).size).toBe(7)
    },
  )

  // The leak itself, not a hand-made stand-in: a process wraps a command
  // against the absent path, runs it, and is killed before it can clean up.
  it.if(BWRAP_CAN_NAMESPACE)(
    'is what a killed process leaves, and the next process to wrap takes it away',
    async () => {
      const script = join(BASE, 'killed-wrapper.ts')
      writeFileSync(
        script,
        [
          `import { spawnSync } from 'node:child_process'`,
          `import { wrapCommandWithSandboxLinux } from ${JSON.stringify(
            join(import.meta.dir, '../../src/sandbox/linux-sandbox-utils.ts'),
          )}`,
          `const command = await wrapCommandWithSandboxLinux({`,
          `  command: 'true',`,
          `  needsNetworkRestriction: false,`,
          `  readConfig: { denyOnly: [] },`,
          `  writeConfig: { allowOnly: [${JSON.stringify(AREA)}], denyWithinAllow: [${JSON.stringify(LOCK)}] },`,
          `})`,
          `const r = spawnSync(command, { shell: true, timeout: 15000 })`,
          `if (r.status !== 0) process.exit(3)`,
          `process.kill(process.pid, 'SIGKILL')`,
        ].join('\n'),
      )
      const killed = spawnSync(process.execPath, [script], {
        encoding: 'utf8',
        timeout: 30000,
      })
      expect(killed.signal).toBe('SIGKILL')

      // What is left on the host, with no process that remembers it.
      const left = lstatSync(LOCK)
      expect(left.isFile()).toBe(true)
      expect(left.size).toBe(0)
      expect(left.mode & 0o222).toBe(0)

      const command = await wrap([LOCK], `echo x > ${LOCK}; echo rc=$?`)
      expect(command).toContain(`--ro-bind /dev/null ${LOCK}`)
      expect(run(command).stdout).toMatch(/rc=[1-9]/)
      cleanupBwrapMountPoints()
      expect(existsSync(LOCK)).toBe(false)
    },
  )
})

/**
 * A denyWrite path whose first MISSING component is an intermediate directory
 * is blocked by binding a read-only empty directory over that component. Both
 * ends of that bind are host state this library owns: the destination bwrap
 * creates, and the source it is bound from.
 */
describe.if(isLinux)(
  'Mount points for deny paths that do not exist yet',
  () => {
    let BASE: string
    let AREA: string // allowed write area
    let PROJ: string // a project with no .claude/, so two mandatory denies
    //                  (.claude/commands, .claude/agents) are absent under it
    let DOT_CLAUDE: string // the destination both of them land on

    const savedCwd = process.cwd()
    const savedTmpdir = process.env.TMPDIR
    const SENTINEL = 'srt-524-written-through-the-source'

    beforeEach(() => {
      // Drop any source a previous test file left cached in the module.
      cleanupBwrapMountPoints({ force: true })
      BASE = realpathSync(mkdtempSync(join(tmpdir(), 'deny-placeholder-')))
      AREA = join(BASE, 'area')
      PROJ = join(AREA, 'proj')
      DOT_CLAUDE = join(PROJ, '.claude')
      mkdirSync(PROJ, { recursive: true })
      process.chdir(PROJ)
      // The sources are minted under os.tmpdir(), which is read from the
      // environment per call. Point it at BASE, so counting the sources this
      // file makes cannot see another test file's, a sandboxed session running
      // on the machine, or an earlier failed run's.
      process.env.TMPDIR = BASE
    })

    afterEach(() => {
      process.chdir(savedCwd)
      cleanupBwrapMountPoints({ force: true })
      if (savedTmpdir === undefined) delete process.env.TMPDIR
      else process.env.TMPDIR = savedTmpdir
      // Takes away whatever a test planted under BASE, impostors included.
      rmSync(BASE, { recursive: true, force: true })
    })

    async function wrap(
      denyPaths: string[] = [],
      command = 'echo hello',
    ): Promise<string> {
      return wrapCommandWithSandboxLinux({
        command,
        needsNetworkRestriction: false,
        readConfig: { denyOnly: [] },
        writeConfig: { allowOnly: [AREA], denyWithinAllow: denyPaths },
      })
    }

    /**
     * Like wrap(), but with the temp dir the sources are minted under writable
     * too: the shape a host $TMPDIR inside a default write path produces
     * (/tmp/claude is one, and it is the value this library stamps on
     * sandboxed children).
     */
    async function wrapWithWritableTempDir(
      command = 'echo hello',
    ): Promise<string> {
      return wrapCommandWithSandboxLinux({
        command,
        needsNetworkRestriction: false,
        readConfig: { denyOnly: [] },
        writeConfig: { allowOnly: [AREA, BASE], denyWithinAllow: [] },
      })
    }

    /**
     * The empty-directory sources a wrapped command binds onto `dest`. Read
     * out of the whole shell-quoted string, anchored on the destination: a
     * split on whitespace would cut a source path containing a space in two.
     */
    function emptySourcesFor(command: string, dest: string): string[] {
      const bind = '--ro-bind '
      const sources: string[] = []
      for (const at of command.matchAll(
        new RegExp(`(?<=\\s)${escapeForRegExp(dest)}(?=\\s|$)`, 'g'),
      )) {
        const from = command.lastIndexOf(bind, at.index)
        const source = command.slice(from + bind.length, at.index - 1)
        if (from !== -1 && source.includes('/claude-empty-')) {
          sources.push(source)
        }
      }
      return sources
    }

    /** How many times `token` stands on its own in a wrapped command. */
    function tokenCount(command: string, token: string): number {
      return [
        ...command.matchAll(
          new RegExp(`(?<![^\\s])${escapeForRegExp(token)}(?=\\s|$)`, 'g'),
        ),
      ].length
    }

    function emptySourceDirs(): string[] {
      return readdirSync(tmpdir()).filter(n => n.startsWith('claude-empty-'))
    }

    it('binds one source for every empty-directory mount point, and takes it away with them', async () => {
      // A source per bind left two directories behind under the temp dir on
      // every command: only the destination was ever tracked.
      const sources: string[] = []
      for (let i = 0; i < 3; i++) {
        const command = await wrap()
        const bound = emptySourcesFor(command, DOT_CLAUDE)
        // .claude/commands and .claude/agents share the missing component
        // <cwd>/.claude: one destination, one bind, one source.
        expect(bound).toHaveLength(1)
        sources.push(bound[0]!)
      }
      expect(new Set(sources).size).toBe(1)
      expect(emptySourceDirs()).toEqual([basename(sources[0]!)])

      cleanupBwrapMountPoints({ force: true })
      expect(emptySourceDirs()).toEqual([])

      // A wrap after the cleanup makes a new one rather than binding a path
      // that is no longer there.
      const bound = emptySourcesFor(await wrap(), DOT_CLAUDE)
      expect(bound).toHaveLength(1)
      expect(bound[0]).not.toBe(sources[0])
      expect(existsSync(bound[0]!)).toBe(true)
    })

    it('emits one placeholder per destination, as a directory when the kinds collide', async () => {
      // denyWrite names the missing <cwd>/.claude itself, which asks for a
      // /dev/null placeholder, while the mandatory <cwd>/.claude/commands asks
      // for a directory at the same destination.
      const command = await wrap([DOT_CLAUDE])

      expect(tokenCount(command, DOT_CLAUDE)).toBe(1)
      expect(command).not.toContain(`--ro-bind /dev/null ${DOT_CLAUDE}`)
      expect(emptySourcesFor(command, DOT_CLAUDE)).toHaveLength(1)
    })

    it.skipIf(!BWRAP_CAN_NAMESPACE)(
      'starts the sandbox when a deny and a mandatory deny share one missing component',
      async () => {
        // Two binds at one destination made bwrap refuse to start with
        // "Can't mkdir <dest>: Not a directory".
        const started = run(await wrap([DOT_CLAUDE]), PROJ)
        expect(started.stdout).not.toMatch(/Not a directory/)
        expect(started.status).toBe(0)
        expect(started.stdout).toContain('hello')

        // That run left the mount point on the host. Without taking it away
        // the next wrap sees an existing path and emits no placeholder at all,
        // so the deny below would not be the one this test is about.
        cleanupBwrapMountPoints({ force: true })
        expect(existsSync(DOT_CLAUDE)).toBe(false)

        const denyCommand = await wrap(
          [DOT_CLAUDE],
          `mkdir -p ${join(DOT_CLAUDE, 'commands')}`,
        )
        expect(emptySourcesFor(denyCommand, DOT_CLAUDE)).toHaveLength(1)

        // The deny still holds, and nothing is left on the host.
        expect(run(denyCommand, PROJ).status).not.toBe(0)
        cleanupBwrapMountPoints({ force: true })
        expect(existsSync(DOT_CLAUDE)).toBe(false)
      },
    )

    it('reuses the source while it is still our own empty directory', async () => {
      const first = emptySourcesFor(await wrap(), DOT_CLAUDE)[0]
      expect(first).toBeDefined()
      expect(emptySourcesFor(await wrap(), DOT_CLAUDE)[0]).toBe(first!)
    })

    // The source sits under the system temp dir, which sandboxed commands
    // commonly can write, and bwrap resolves a bind source on the host —
    // reusing a path that has become something else would publish it at the
    // placeholder's destination.
    it.each([
      [
        'it has been swapped for a symlink',
        (p: string) => {
          const decoy = join(BASE, 'decoy')
          mkdirSync(decoy, { recursive: true })
          writeFileSync(join(decoy, 'secret.txt'), 'x\n')
          rmdirSync(p)
          symlinkSync(decoy, p)
        },
      ],
      [
        'something has been written into it',
        (p: string) => writeFileSync(join(p, 'planted'), ''),
      ],
      ['its mode has been widened', (p: string) => chmodSync(p, 0o755)],
    ])('makes a fresh source when %s', async (_what, tamper) => {
      const first = emptySourcesFor(await wrap(), DOT_CLAUDE)[0]!
      tamper(first)

      const command = await wrap()
      const second = emptySourcesFor(command, DOT_CLAUDE)[0]!
      expect(second).not.toBe(first)
      expect(command).not.toContain(first)
      expect(lstatSync(second).isSymbolicLink()).toBe(false)
      expect(readdirSync(second)).toEqual([])

      // What was there is left exactly as found: it is not ours any more.
      cleanupBwrapMountPoints({ force: true })
      expect(existsSync(first)).toBe(true)
    })

    it('keeps one source under a umask that clears the owner write bit', async () => {
      // mkdtemp asks for 0700 and the umask applies, so under `umask 0200` the
      // directory it makes is 0500. A revalidation that insists on exactly
      // 0700 rejects the directory the same call has just made, and every
      // placeholder mints another one that nothing will remove.
      const script = join(BASE, 'umask-wrapper.ts')
      writeFileSync(
        script,
        [
          `import { wrapCommandWithSandboxLinux } from ${JSON.stringify(
            join(import.meta.dir, '../../src/sandbox/linux-sandbox-utils.ts'),
          )}`,
          `process.umask(0o200)`,
          `for (let i = 0; i < 2; i++) {`,
          `  console.log(`,
          `    await wrapCommandWithSandboxLinux({`,
          `      command: 'true',`,
          `      needsNetworkRestriction: false,`,
          `      readConfig: { denyOnly: [] },`,
          `      writeConfig: { allowOnly: [${JSON.stringify(AREA)}], denyWithinAllow: [] },`,
          `    }),`,
          `  )`,
          `}`,
        ].join('\n'),
      )
      const wrapped = spawnSync(process.execPath, [script], {
        encoding: 'utf8',
        timeout: 30000,
        cwd: PROJ,
        env: { ...process.env, TMPDIR: BASE },
      })
      expect(wrapped.status).toBe(0)

      const [first, second] = wrapped.stdout
        .split('\n')
        .filter(line => line.includes('--ro-bind'))
        .map(line => emptySourcesFor(line, DOT_CLAUDE)[0])
      expect(first).toBeDefined()
      expect(second).toBe(first!)
    })

    it('pins the source read-only, after every other mount', async () => {
      const command = await wrap()
      const source = emptySourcesFor(command, DOT_CLAUDE)[0]!

      // Last, like the masked-file store's own pin, so nothing emitted after
      // it can put a writable mount back over the source.
      const pin = `--ro-bind ${source} ${source}`
      expect(command).toContain(pin)
      const after = command.slice(command.lastIndexOf(pin) + pin.length)
      expect(after).not.toMatch(/--ro-bind |--bind |--dev-bind |--tmpfs /)
    })

    it.skipIf(!BWRAP_CAN_NAMESPACE)(
      'refuses a write into the source from inside the sandbox, so nothing reaches the denied destination',
      async () => {
        // With the temp dir writable, the source and the DENIED destination
        // are the same directory: a write to the source would appear at the
        // deny, in this sandbox and in every concurrent one sharing it.
        const source = emptySourcesFor(
          await wrapWithWritableTempDir(),
          DOT_CLAUDE,
        )[0]!
        const planted = join(source, 'commands')
        const command = await wrapWithWritableTempDir(
          `mkdir -p ${planted} 2>&1; echo "mkdir rc=$?"; ` +
            `echo ${SENTINEL} > ${join(planted, 'x.md')} 2>&1; ` +
            `cat ${join(DOT_CLAUDE, 'commands', 'x.md')} 2>&1`,
        )
        expect(emptySourcesFor(command, DOT_CLAUDE)).toEqual([source])

        const attempt = run(command, PROJ)
        expect(attempt.stdout).toMatch(/mkdir rc=[1-9]/)
        expect(attempt.stdout).not.toContain(SENTINEL)
        expect(readdirSync(source)).toEqual([])
      },
    )
  },
)
