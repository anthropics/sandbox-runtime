import { describe, it, expect, beforeEach, afterEach } from 'bun:test'
import {
  chmodSync,
  existsSync,
  linkSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { spawnSync } from 'node:child_process'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import {
  wrapCommandWithSandboxLinux,
  cleanupBwrapMountPoints,
} from '../../src/sandbox/linux-sandbox-utils.js'
import { isLinux } from '../helpers/platform.js'

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

  function run(command: string): { status: number | null; stdout: string } {
    const r = spawnSync(command, {
      shell: true,
      encoding: 'utf8',
      timeout: 15000,
    })
    return { status: r.status, stdout: `${r.stdout}${r.stderr}` }
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
