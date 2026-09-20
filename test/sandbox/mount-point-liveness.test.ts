import { describe, it, expect, beforeEach, afterEach } from 'bun:test'
import { spawn, spawnSync } from 'node:child_process'
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import {
  cleanupBwrapMountPoints,
  wrapCommandWithSandboxLinux,
} from '../../src/sandbox/linux-sandbox-utils.js'
import { bwrapCanNamespace } from '../helpers/bwrap-namespace.js'
import { isLinux } from '../helpers/platform.js'

/**
 * A denyWrite path that does not exist is blocked by binding /dev/null over
 * it, and bwrap makes the mount point for that bind on the host. Unlinking one
 * while a sandbox is still bound over it detaches the mount inside that
 * sandbox: the denied path can be created there, and what is written lands on
 * the host. Whether a sandbox is still running is therefore not something a
 * process may decide for itself — a second srt process, a caller that crashes,
 * one that cleans up early, twice or never, each had a different answer, and a
 * count kept in one process's memory could not see any of them.
 *
 * Every wrap now names the mount points it relies on in a manifest and has
 * bwrap hold a lock on it for the sandbox's lifetime, so the kernel answers
 * instead.
 */
describe.if(isLinux)('A mount point a running sandbox relies on', () => {
  const BWRAP_CAN_NAMESPACE = bwrapCanNamespace()
  const LIBRARY = JSON.stringify(
    join(import.meta.dir, '../../src/sandbox/linux-sandbox-utils.ts'),
  )
  let BASE: string
  let AREA: string // the allowed write area
  let LOCK: string // the denyWrite path, absent to begin with
  let SIGNAL: string // written from inside the sandbox once it is up
  let GO: string // written by the test to let the sandbox carry on
  let OUT: string // where a child process leaves what its sandbox printed

  beforeEach(() => {
    BASE = realpathSync(mkdtempSync(join(tmpdir(), 'mount-point-liveness-')))
    AREA = join(BASE, 'area')
    mkdirSync(join(AREA, 'repo', '.git'), { recursive: true })
    LOCK = join(AREA, 'repo', '.git', 'config.lock')
    SIGNAL = join(AREA, 'up')
    GO = join(AREA, 'go')
    OUT = join(BASE, 'out.txt')
  })

  afterEach(() => {
    cleanupBwrapMountPoints({ force: true })
    rmSync(BASE, { recursive: true, force: true })
  })

  async function wrap(command: string, denyPaths = [LOCK]): Promise<string> {
    return wrapCommandWithSandboxLinux({
      command,
      needsNetworkRestriction: false,
      readConfig: { denyOnly: [] },
      writeConfig: { allowOnly: [AREA], denyWithinAllow: denyPaths },
    })
  }

  /** Waits for the sandbox to report it is up, then tries the denied write. */
  function heldCommand(): string {
    return `echo up > ${SIGNAL}; while [ ! -e ${GO} ]; do sleep 0.05; done; echo pwned > ${LOCK}; echo rc=$?`
  }

  /** A child process that wraps `command`, runs it and writes what it said. */
  function wrapperScript(
    command: string,
    out: string,
    after: string[] = [],
  ): string {
    return [
      `import { spawnSync } from 'node:child_process'`,
      `import { writeFileSync } from 'node:fs'`,
      `import { wrapCommandWithSandboxLinux, cleanupBwrapMountPoints } from ${LIBRARY}`,
      `const out = ${JSON.stringify(out)}`,
      `const wrapped = await wrapCommandWithSandboxLinux({`,
      `  command: ${JSON.stringify(command)},`,
      `  needsNetworkRestriction: false,`,
      `  readConfig: { denyOnly: [] },`,
      `  writeConfig: { allowOnly: [${JSON.stringify(AREA)}], denyWithinAllow: [${JSON.stringify(LOCK)}] },`,
      `})`,
      `const r = spawnSync(wrapped, { shell: true, encoding: 'utf8', timeout: 60000 })`,
      `writeFileSync(out, String(r.stdout ?? '') + String(r.stderr ?? ''))`,
      ...after,
    ].join('\n')
  }

  function writeScript(name: string, source: string): string {
    const file = join(BASE, name)
    writeFileSync(file, source)
    return file
  }

  async function waitFor(file: string, timeoutMs = 30000): Promise<void> {
    const deadline = Date.now() + timeoutMs
    while (!existsSync(file)) {
      if (Date.now() > deadline) {
        throw new Error(`timed out waiting for ${file}`)
      }
      await new Promise(resolve => setTimeout(resolve, 25))
    }
  }

  function sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms))
  }

  /** What is at `file`, or '' where nothing is: a mount point holds nothing. */
  function contentAt(file: string): string {
    return existsSync(file) ? readFileSync(file, 'utf8') : ''
  }

  /** Where the wrap pointed bubblewrap's --lock-file. */
  function manifestOf(command: string): string {
    const file = /--lock-file (\S+)/.exec(command)?.[1]
    expect(file).toBeDefined()
    return file!
  }

  it.if(BWRAP_CAN_NAMESPACE)(
    'survives another process cleaning up in the same directory, and the deny holds',
    async () => {
      const holder = spawn(
        process.execPath,
        [writeScript('holder.ts', wrapperScript(heldCommand(), OUT))],
        { stdio: 'ignore' },
      )
      const holderExited = new Promise(resolve => holder.on('exit', resolve))
      try {
        await waitFor(SIGNAL)
        // The mount point bwrap made for the sandbox that is running.
        expect(lstatSync(LOCK).size).toBe(0)

        // A second process wraps the same deny path, runs a command and cleans
        // up. On the counter this took the running sandbox's mount point away.
        const second = spawnSync(
          process.execPath,
          [
            writeScript(
              'second.ts',
              wrapperScript('true', join(BASE, 'second-out.txt'), [
                'cleanupBwrapMountPoints()',
              ]),
            ),
          ],
          { encoding: 'utf8', timeout: 60000 },
        )
        expect(second.status).toBe(0)
        expect(existsSync(LOCK)).toBe(true)
      } finally {
        writeFileSync(GO, '')
      }

      await waitFor(OUT)
      expect(readFileSync(OUT, 'utf8')).toMatch(/rc=[1-9]/)
      expect(contentAt(LOCK)).toBe('')

      // Once nothing is running under it, it goes: on the holder's own cleanup
      // as it exits, or on this one.
      await holderExited
      await sleep(600)
      cleanupBwrapMountPoints()
      expect(existsSync(LOCK)).toBe(false)
    },
    90000,
  )

  it.if(BWRAP_CAN_NAMESPACE)(
    'survives a cleanup, twice over, while its own process still has the sandbox running',
    async () => {
      const command = await wrap(heldCommand())
      const child = spawn(command, { shell: true })
      let said = ''
      child.stdout.on('data', chunk => (said += String(chunk)))
      child.stderr.on('data', chunk => (said += String(chunk)))
      const exited = new Promise(resolve => child.on('exit', resolve))
      try {
        await waitFor(SIGNAL)
        cleanupBwrapMountPoints()
        cleanupBwrapMountPoints()
        cleanupBwrapMountPoints({ force: true })
        expect(existsSync(LOCK)).toBe(true)
      } finally {
        writeFileSync(GO, '')
      }

      await exited
      expect(said).toMatch(/rc=[1-9]/)
      expect(contentAt(LOCK)).toBe('')

      // And goes on the next cleanup, now that nothing is running under it.
      cleanupBwrapMountPoints()
      expect(existsSync(LOCK)).toBe(false)
    },
    90000,
  )

  it.if(BWRAP_CAN_NAMESPACE)(
    'is collected, manifest and all, when the process that made it never cleans up',
    async () => {
      const killed = spawnSync(
        process.execPath,
        [
          writeScript(
            'killed.ts',
            wrapperScript('true', OUT, [
              `process.kill(process.pid, 'SIGKILL')`,
            ]),
          ),
        ],
        { encoding: 'utf8', timeout: 60000 },
      )
      expect(killed.signal).toBe('SIGKILL')
      expect(contentAt(LOCK)).toBe('')

      const directory = dirname(manifestOf(await wrap('true')))
      await sleep(600)
      cleanupBwrapMountPoints()

      expect(existsSync(LOCK)).toBe(false)
      const naming = readdirSync(directory).filter(
        name =>
          name.endsWith('.json') &&
          readFileSync(join(directory, name), 'utf8').includes(LOCK),
      )
      expect(naming).toEqual([])
    },
    90000,
  )

  it.if(BWRAP_CAN_NAMESPACE)(
    'cannot be disowned from inside the sandbox: the manifests are read-only there',
    async () => {
      // This caller allows writes to the manifest directory itself, so only
      // the read-only bind the wrap emits last keeps the command out of it.
      const directory = dirname(manifestOf(await wrap('true')))
      const before = readdirSync(directory).filter(n => n.endsWith('.json'))
      expect(before.length).toBeGreaterThan(0)

      const attack = [
        `rm -f ${directory}/*.json; echo rm=$?`,
        `echo mine > ${directory}/planted.json; echo plant=$?`,
        `echo mine > ${directory}/${before[0]}; echo rewrite=$?`,
      ].join('; ')
      const result = spawnSync(
        await wrapCommandWithSandboxLinux({
          command: attack,
          needsNetworkRestriction: false,
          readConfig: { denyOnly: [] },
          writeConfig: {
            allowOnly: [AREA, directory],
            denyWithinAllow: [LOCK],
          },
        }),
        { shell: true, encoding: 'utf8', timeout: 60000 },
      )
      const said = `${result.stdout}${result.stderr}`
      expect(said).toMatch(/rm=[1-9]/)
      expect(said).toMatch(/plant=[1-9]/)
      expect(said).toMatch(/rewrite=[1-9]/)
      expect(existsSync(join(directory, 'planted.json'))).toBe(false)
      for (const name of before) {
        expect(existsSync(join(directory, name))).toBe(true)
        expect(readFileSync(join(directory, name), 'utf8')).toContain('"paths"')
      }
    },
    90000,
  )

  it.if(BWRAP_CAN_NAMESPACE)(
    'holds its deny while another process collects without pause',
    async () => {
      const loop = spawn(
        process.execPath,
        [
          writeScript(
            'collect-loop.ts',
            [
              `import { cleanupBwrapMountPoints } from ${LIBRARY}`,
              `const until = Date.now() + 20000`,
              `while (Date.now() < until) cleanupBwrapMountPoints()`,
            ].join('\n'),
          ),
        ],
        { stdio: 'ignore' },
      )
      try {
        for (let i = 0; i < 12; i++) {
          const result = spawnSync(
            await wrap(`echo pwned > ${LOCK}; echo rc=$?`),
            { shell: true, encoding: 'utf8', timeout: 60000 },
          )
          const said = `${result.stdout}${result.stderr}`
          expect(said).toMatch(/rc=[1-9]/)
          // Nothing was written at the deny path, on this pass or an earlier
          // one whose mount point this pass may have re-covered.
          expect(contentAt(LOCK)).toBe('')
          cleanupBwrapMountPoints()
        }
      } finally {
        loop.kill()
      }
    },
    120000,
  )

  it.if(BWRAP_CAN_NAMESPACE)(
    'refuses to start a command wrapped before a cleanup that has since taken its mount point away',
    async () => {
      const command = await wrap(`echo pwned > ${LOCK}; echo rc=$?`)
      cleanupBwrapMountPoints()
      expect(existsSync(LOCK)).toBe(false)

      const result = spawnSync(command, {
        shell: true,
        encoding: 'utf8',
        timeout: 60000,
      })
      // bubblewrap sets the mounts up before it opens the lock file, so the
      // mount point is back on the host; the command it was made for never
      // runs.
      expect(result.status).not.toBe(0)
      expect(`${result.stdout}${result.stderr}`).toContain(
        'Unable to open lock file',
      )
      expect(lstatSync(LOCK).size).toBe(0)
    },
    90000,
  )

  it('lets go of the mount points of a wrap that produced no command', async () => {
    // Left where a process killed before its cleanup would leave it, so that
    // both processes below name it.
    writeFileSync(LOCK, '')
    chmodSync(LOCK, 0o444)

    const wrapper = spawn(
      process.execPath,
      [
        writeScript(
          'throwing.ts',
          [
            `import { writeFileSync } from 'node:fs'`,
            `import { wrapCommandWithSandboxLinux } from ${LIBRARY}`,
            `try {`,
            `  await wrapCommandWithSandboxLinux({`,
            `    command: 'true',`,
            `    binShell: 'srt-no-such-shell',`,
            `    needsNetworkRestriction: false,`,
            `    readConfig: { denyOnly: [] },`,
            `    writeConfig: { allowOnly: [${JSON.stringify(AREA)}], denyWithinAllow: [${JSON.stringify(LOCK)}] },`,
            `  })`,
            `} catch {`,
            `  writeFileSync(${JSON.stringify(OUT)}, 'threw')`,
            `}`,
            // Stays alive: a manifest of a process that is still running
            // counts as live, so only letting go of it lets the mount point be
            // collected here.
            `await new Promise(resolve => setTimeout(resolve, 30000))`,
          ].join('\n'),
        ),
      ],
      { stdio: 'ignore' },
    )
    try {
      await waitFor(OUT)
      expect(readFileSync(OUT, 'utf8')).toBe('threw')
      // This process names the same mount point and asks for the cleanup. Had
      // the wrap that threw held on to its manifest, the process behind it
      // being alive would have kept the mount point here.
      await wrap('true')
      cleanupBwrapMountPoints()
      expect(existsSync(LOCK)).toBe(false)
    } finally {
      wrapper.kill()
    }
  }, 90000)
})
