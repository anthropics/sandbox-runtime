import { describe, it, expect, beforeEach, afterEach } from 'bun:test'
import { spawnSync } from 'node:child_process'
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  statSync,
} from 'node:fs'
import { basename, dirname, join } from 'node:path'
import { tmpdir } from 'node:os'
import {
  wrapCommandWithSandboxLinux,
  cleanupBwrapMountPoints,
} from '../../src/sandbox/linux-sandbox-utils.js'
import { isLinux } from '../helpers/platform.js'
import { countMounts, lastMountAt } from '../helpers/bwrap-argv.js'
import { bwrapCanNamespace } from '../helpers/bwrap-namespace.js'

/**
 * A write deny on a file that does not exist is covered by an empty read-only
 * file, not by /dev/null. bubblewrap gives every --ro-bind the nodev flag, and
 * opening a device node on a nodev mount fails with EACCES: a login shell
 * sourcing an absent ~/.bash_profile printed "Permission denied" and skipped
 * ~/.profile. The cover reads as empty, and still refuses the write.
 */
describe.if(isLinux)('An absent write-denied file reads as empty', () => {
  const BWRAP_CAN_NAMESPACE = bwrapCanNamespace()
  const savedCwd = process.cwd()
  let base: string
  let area: string
  let absent: string

  beforeEach(() => {
    cleanupBwrapMountPoints({ force: true })
    base = realpathSync(mkdtempSync(join(tmpdir(), 'absent-reads-empty-')))
    area = join(base, 'area')
    mkdirSync(area)
    absent = join(area, 'denied.conf')
    process.chdir(area)
  })

  afterEach(() => {
    process.chdir(savedCwd)
    cleanupBwrapMountPoints({ force: true })
    rmSync(base, { recursive: true, force: true })
  })

  const wrap = (command = 'true'): Promise<string> =>
    wrapCommandWithSandboxLinux({
      command,
      needsNetworkRestriction: false,
      readConfig: { denyOnly: [] },
      writeConfig: { allowOnly: [area], denyWithinAllow: [absent] },
    })

  const run = (command: string) =>
    spawnSync(command, {
      shell: true,
      encoding: 'utf8',
      timeout: 15000,
      cwd: area,
      env: { ...process.env, LC_ALL: 'C' },
    })

  /** The source of the last mount at `dest`, which must be a file placeholder. */
  function placeholderSourceAt(command: string, dest: string): string {
    const mount = lastMountAt(command, dest)
    expect(mount).toBeDefined()
    const [flag, source] = mount!.split(' ')
    expect(flag).toBe('--ro-bind')
    expect(source).not.toBe('/dev/null')
    return source!
  }

  it('binds an empty read-only file of our own over the path, and pins its directory', async () => {
    const command = await wrap()

    const source = placeholderSourceAt(command, absent)
    const stat = statSync(source)
    expect(stat.isFile()).toBe(true)
    expect(stat.size).toBe(0)
    expect(stat.mode & 0o777).toBe(0o400)
    expect(stat.uid).toBe(process.getuid!())
    expect(basename(dirname(source))).toStartWith('claude-empty-')
    // The directory that holds it is read-only inside the sandbox, so the
    // file can neither be written, replaced nor have its mode changed there.
    expect(
      countMounts(command, '--ro-bind', dirname(source), dirname(source)),
    ).toBe(1)
  })

  it('covers an absent mandatory deny the same way', async () => {
    const bashProfile = join(area, '.bash_profile')

    const command = await wrap()

    const source = placeholderSourceAt(command, bashProfile)
    expect(statSync(source).isFile()).toBe(true)
    expect(countMounts(command, '--ro-bind', '/dev/null', bashProfile)).toBe(0)
  })

  it('binds one file for every wrap, and takes it away with the mount points', async () => {
    const first = placeholderSourceAt(await wrap(), absent)
    const second = placeholderSourceAt(await wrap(), absent)
    expect(second).toBe(first)

    cleanupBwrapMountPoints({ force: true })
    expect(existsSync(first)).toBe(false)
    expect(existsSync(dirname(first))).toBe(false)

    // A wrap after the cleanup makes a new one rather than binding a path
    // that is no longer there.
    const third = placeholderSourceAt(await wrap(), absent)
    expect(third).not.toBe(first)
    expect(existsSync(third)).toBe(true)
  })

  it.skipIf(!BWRAP_CAN_NAMESPACE)(
    'reads as empty inside the sandbox, and still refuses the write',
    async () => {
      const result = run(
        await wrap(
          `sh -c 'cat ${absent}; echo "read=$?"; echo x > ${absent}; echo "write=$?"'`,
        ),
      )

      expect(result.stderr).not.toContain('bwrap:')
      expect(result.stderr).not.toContain('Permission denied')
      expect(result.stderr).toContain('Read-only file system')
      // A failed redirection exits 1 under bash and 2 under dash.
      expect(result.stdout).toMatch(/^read=0\nwrite=[12]\n$/)
    },
  )

  it.skipIf(!BWRAP_CAN_NAMESPACE)(
    'lets a login shell start without "Permission denied" on an absent ~/.bash_profile',
    async () => {
      // The reported symptom: HOME is the cwd, so ~/.bash_profile is an
      // absent mandatory deny, which bash reads first as a login shell.
      const result = run(await wrap(`HOME=${area} bash -l -c 'echo BOOTED'`))

      expect(result.stderr).not.toContain('bwrap:')
      expect(result.stderr).not.toContain('Permission denied')
      expect(result.stdout).toContain('BOOTED')
      expect(result.status).toBe(0)
    },
  )
})
