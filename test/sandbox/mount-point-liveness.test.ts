import { describe, it, expect, beforeEach, afterEach, spyOn } from 'bun:test'
import { type ChildProcess, spawn, spawnSync } from 'node:child_process'
import * as fs from 'node:fs'
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
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import { bwrapCanNamespace } from '../helpers/bwrap-namespace.js'
import { isLinux } from '../helpers/platform.js'
import { usePrivateManifestDirectory } from '../helpers/private-manifest-directory.js'

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
  // These tests list the manifests, attack them from inside a sandbox and
  // assert on what is left: in a directory of their own.
  usePrivateManifestDirectory()
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
        // `force` is what the exit handler and reset() pass: everything this
        // process made may go. A sandbox that is running under a manifest is
        // not this process's to end, so that manifest and what it names stay,
        // for a later cleanup here or in any other process.
        cleanupBwrapMountPoints({ force: true })
        expect(lstatSync(LOCK).size).toBe(0)
        expect(existsSync(manifestOf(command))).toBe(true)
      } finally {
        writeFileSync(GO, '')
      }

      await exited
      expect(said).toMatch(/rc=[1-9]/)
      expect(contentAt(LOCK)).toBe('')

      // And goes on the next cleanup, now that nothing is running under it.
      cleanupBwrapMountPoints()
      expect(existsSync(LOCK)).toBe(false)
      expect(existsSync(manifestOf(command))).toBe(false)
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
      // Its sandbox ran, and left what bubblewrap made for it: without this
      // everything below holds of a path nothing was ever made at.
      expect(readFileSync(OUT, 'utf8')).not.toContain('bwrap:')
      expect(lstatSync(LOCK).size).toBe(0)

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
    'are read-only in a sandbox that names no manifest of its own',
    async () => {
      // A wrap with no absent deny path has no mount points and no manifest,
      // and the manifests in the directory are then other sandboxes'. The
      // collect that runs on the host believes them, so a command able to
      // write one could have any empty file removed, and one able to delete
      // one could make a running sandbox's mount points look unused.
      const directory = dirname(manifestOf(await wrap('true')))
      const before = readdirSync(directory).filter(n => n.endsWith('.json'))
      expect(before.length).toBeGreaterThan(0)

      const attack = [
        `rm -f ${directory}/*.json; echo rm=$?`,
        `echo mine > ${directory}/planted.json; echo plant=$?`,
        `echo mine > ${directory}/${before[0]}; echo rewrite=$?`,
      ].join('; ')
      const command = await wrapCommandWithSandboxLinux({
        command: attack,
        needsNetworkRestriction: false,
        readConfig: { denyOnly: [] },
        writeConfig: { allowOnly: [AREA, directory], denyWithinAllow: [] },
      })
      // The point of the case: this wrap relies on no mount point.
      expect(command).not.toContain('--lock-file')

      const result = spawnSync(command, {
        shell: true,
        encoding: 'utf8',
        timeout: 60000,
      })
      const said = `${result.stdout}${result.stderr}`
      expect(said).toMatch(/rm=[1-9]/)
      expect(said).toMatch(/plant=[1-9]/)
      expect(said).toMatch(/rewrite=[1-9]/)
      expect(existsSync(join(directory, 'planted.json'))).toBe(false)
      for (const name of before) {
        expect(readFileSync(join(directory, name), 'utf8')).toContain('"paths"')
      }
    },
    90000,
  )

  it.if(BWRAP_CAN_NAMESPACE)(
    'are read-only, too, where a process that was started without a runtime directory keeps them',
    async () => {
      // A process started with $XDG_RUNTIME_DIR keeps its manifests under it,
      // and one started without (from cron, over a plain ssh) under the temp
      // dir. A sandbox of the first kind that may write the temp dir could
      // delete and forge the manifests of the second, which a collect on the
      // host then believed. So every wrap binds both names read-only, and
      // makes the one that is not there so that the command cannot make it
      // first.
      const RUN = join(BASE, 'run')
      const TMP = join(BASE, 'tmp')
      mkdirSync(RUN, { mode: 0o700 })
      chmodSync(RUN, 0o700)
      mkdirSync(TMP)
      const theirs = join(TMP, `srt-mount-points-${process.getuid!()}`)
      const attacker = (script: string, attack: string): string =>
        writeScript(
          script,
          [
            `import { spawnSync } from 'node:child_process'`,
            `import { wrapCommandWithSandboxLinux } from ${LIBRARY}`,
            `const wrapped = await wrapCommandWithSandboxLinux({`,
            `  command: ${JSON.stringify(attack)},`,
            `  needsNetworkRestriction: false,`,
            `  readConfig: { denyOnly: [] },`,
            `  writeConfig: { allowOnly: [${JSON.stringify(TMP)}, ${JSON.stringify(AREA)}], denyWithinAllow: [] },`,
            `})`,
            `const r = spawnSync(wrapped, { shell: true, encoding: 'utf8', timeout: 60000 })`,
            `console.log(String(r.stdout ?? '') + String(r.stderr ?? ''))`,
          ].join('\n'),
        )
      const withARuntimeDirectory = (script: string) =>
        spawnSync(process.execPath, [script], {
          env: { ...process.env, XDG_RUNTIME_DIR: RUN, TMPDIR: TMP },
          encoding: 'utf8',
          timeout: 60000,
        })

      // Nobody has made the other directory yet: the command may not either.
      const early = withARuntimeDirectory(
        attacker(
          'early.ts',
          `mkdir -m 700 ${theirs} 2>/dev/null; echo forged > ${theirs}/planted.json; echo plant=$?`,
        ),
      )
      expect(early.stdout).toMatch(/plant=[1-9]/)
      expect(lstatSync(theirs).isDirectory()).toBe(true)
      expect(readdirSync(theirs)).toEqual([])

      // What a process without a runtime directory has recorded there.
      const manifest = join(theirs, '4242-0123456789abcdef.json')
      writeFileSync(manifest, '{"version":1,"paths":[]}', { mode: 0o600 })
      const late = withARuntimeDirectory(
        attacker(
          'late.ts',
          `rm -f ${theirs}/*.json; echo rm=$?; echo forged > ${theirs}/planted.json; echo plant=$?`,
        ),
      )
      expect(late.stdout).toMatch(/rm=[1-9]/)
      expect(late.stdout).toMatch(/plant=[1-9]/)
      expect(readdirSync(theirs)).toEqual(['4242-0123456789abcdef.json'])
      expect(readFileSync(manifest, 'utf8')).toContain('"paths"')
    },
    90000,
  )

  it.if(BWRAP_CAN_NAMESPACE)(
    'refuses to start a command wrapped before a cleanup that has since let go of its manifest',
    async () => {
      const command = await wrap(`echo pwned > ${LOCK}; echo rc=$?`)
      const manifest = manifestOf(command)
      expect(existsSync(manifest)).toBe(true)
      // The one clean-up this process owes, made before the command is run:
      // nothing is outstanding any more, so what the wrap prepared is let go.
      cleanupBwrapMountPoints()
      expect(existsSync(manifest)).toBe(false)

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

  // ---- two commands of one process in flight -----------------------------
  //
  // The caller cleans up once per command, when that command is over, and a
  // call cannot tell which command it is for. So while a wrap is outstanding
  // nothing this process made may go: the command that has not started yet
  // still needs its manifest (bubblewrap opens it to take the lock) and its
  // mount point.

  it.if(BWRAP_CAN_NAMESPACE)(
    'a command wrapped and not yet started survives the clean-up after the one that finished first',
    async () => {
      const first = await wrap('echo first-ran')
      const second = await wrap(
        `echo second-ran; echo pwned > ${LOCK}; echo rc=$?`,
      )
      const run = (command: string) =>
        spawnSync(command, { shell: true, encoding: 'utf8', timeout: 60000 })

      expect(run(first).stdout).toContain('first-ran')
      cleanupBwrapMountPoints() // after the first; the second is not started
      // The call could have been for either, so what the first left stays.
      expect(existsSync(LOCK)).toBe(true)
      expect(existsSync(manifestOf(second))).toBe(true)

      const result = run(second)
      const said = `${result.stdout}${result.stderr}`
      expect(said).not.toContain('Unable to open lock file')
      expect(said).not.toContain('bwrap:')
      expect(result.status).toBe(0)
      expect(result.stdout).toContain('second-ran')
      expect(result.stdout).toMatch(/rc=[1-9]/) // and its deny held
      expect(contentAt(LOCK)).toBe('')

      cleanupBwrapMountPoints() // after the second: nothing outstanding now
      expect(existsSync(LOCK)).toBe(false)
    },
    90000,
  )

  it.if(BWRAP_CAN_NAMESPACE)(
    'a sandbox that takes its lock while another command is being cleaned up after keeps its manifest and its deny',
    async () => {
      // The interleaving that chance produces when one command ends a few
      // milliseconds after another was spawned, made certain: the collect
      // looks at /proc/locks, where the second command's manifest is not yet
      // locked, and before it goes on that command's sandbox comes up and
      // takes the lock.
      const first = await wrap('true')
      const second = await wrap(heldCommand())
      const manifest = manifestOf(second)
      expect(spawnSync(first, { shell: true, timeout: 60000 }).status).toBe(0)

      const readFile = fs.readFileSync
      let started = false
      const spy = spyOn(fs, 'readFileSync').mockImplementation(((
        file: unknown,
        options: unknown,
      ) => {
        const value = (readFile as (f: unknown, o: unknown) => unknown)(
          file,
          options,
        )
        if (file === '/proc/locks' && !started) {
          started = true
          // `{ ...; true; }` keeps a shell as bubblewrap's parent.
          spawnSync('sh', ['-c', `{ ${second}; true; } > ${OUT} 2>&1 &`], {
            stdio: 'ignore',
          })
          const deadline = Date.now() + 20000
          while (!existsSync(SIGNAL)) {
            if (Date.now() > deadline) throw new Error('sandbox never came up')
            Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 5)
          }
        }
        return value
      }) as never)
      try {
        cleanupBwrapMountPoints() // after the first
      } finally {
        spy.mockRestore()
      }
      expect(started).toBe(true)
      // The second is running, and what it relies on is still on record.
      expect(existsSync(manifest)).toBe(true)

      // A later command in the same repository names the same mount point.
      const third = await wrap('true')
      expect(spawnSync(third, { shell: true, timeout: 60000 }).status).toBe(0)
      cleanupBwrapMountPoints() // after the third
      expect(existsSync(LOCK)).toBe(true)

      writeFileSync(GO, '')
      const deadline = Date.now() + 20000
      while (!/rc=\d/.test(contentAt(OUT))) {
        if (Date.now() > deadline) throw new Error('the second never finished')
        await sleep(25)
      }
      expect(contentAt(OUT)).toMatch(/rc=[1-9]/)
      expect(contentAt(LOCK)).toBe('')
    },
    90000,
  )

  it.if(BWRAP_CAN_NAMESPACE)(
    'with the id its wrap was given, a finished command lets go of its mount point while another is outstanding',
    async () => {
      const lockOfFirst = join(AREA, 'repo', '.git', 'first.lock')
      const wrapAs = (commandId: string, command: string, deny: string) =>
        wrapCommandWithSandboxLinux({
          command,
          commandId,
          needsNetworkRestriction: false,
          readConfig: { denyOnly: [] },
          writeConfig: { allowOnly: [AREA], denyWithinAllow: [deny] },
        })
      const run = (command: string) =>
        spawnSync(command, { shell: true, encoding: 'utf8', timeout: 60000 })

      const first = await wrapAs('first-0123456789abcdef', 'true', lockOfFirst)
      const second = await wrapAs(
        'second-0123456789abcdef',
        `echo pwned > ${LOCK}; echo rc=$?`,
        LOCK,
      )
      expect(run(first).status).toBe(0)
      expect(existsSync(lockOfFirst)).toBe(true) // bubblewrap leaves it

      // One call per command, as always. This one says which command it is
      // for, so that command's mount point goes although the second is still
      // outstanding, and the second's manifest is untouched.
      cleanupBwrapMountPoints({ commandId: 'first-0123456789abcdef' })
      expect(existsSync(lockOfFirst)).toBe(false)
      expect(existsSync(manifestOf(second))).toBe(true)

      const result = run(second)
      expect(`${result.stdout}${result.stderr}`).not.toContain('bwrap:')
      expect(result.stdout).toMatch(/rc=[1-9]/)
      cleanupBwrapMountPoints({ commandId: 'second-0123456789abcdef' })
      expect(existsSync(LOCK)).toBe(false)
    },
    90000,
  )

  it.if(BWRAP_CAN_NAMESPACE)(
    'a wrap that produced no command is not waited for by the clean-up after the next',
    async () => {
      // It gave its count back when it threw: the caller has no command to
      // clean up after, and one clean-up after the command that did run is
      // all that is owed.
      const refused = wrapCommandWithSandboxLinux({
        command: 'true',
        binShell: 'srt-no-such-shell',
        needsNetworkRestriction: false,
        readConfig: { denyOnly: [] },
        writeConfig: { allowOnly: [AREA], denyWithinAllow: [LOCK] },
      })
      expect(refused).rejects.toThrow()
      await refused.catch(() => undefined)

      const command = await wrap('true')
      expect(spawnSync(command, { shell: true, timeout: 60000 }).status).toBe(0)
      expect(existsSync(LOCK)).toBe(true) // bubblewrap leaves it
      cleanupBwrapMountPoints()
      expect(existsSync(LOCK)).toBe(false)
    },
    90000,
  )

  it("takes a path a live manifest names for the caller's own file once something has been written to it", async () => {
    // Live: written by this process, which has not let go of it. The path
    // was a mount point when that manifest was written; a file with content
    // is nothing bubblewrap made, and /dev/null over it would hide it from
    // the command it belongs to.
    const first = await wrap('true')
    expect(first).toContain(`--ro-bind /dev/null ${LOCK}`)
    writeFileSync(LOCK, 'somebody wrote this\n')
    const second = await wrap('true')
    expect(second).not.toContain(`--ro-bind /dev/null ${LOCK}`)
    expect(second).toContain(`--ro-bind ${LOCK} ${LOCK}`)
    // Nor does the second wrap name it: it is not its to remove.
    expect(second).not.toContain('--lock-file')
  })

  it('takes for a mount point one that another sandbox makes while the wrap is looking at the path', async () => {
    // Absent when the wrap asked what shape it has, there when it asked
    // whether anything is: another sandbox started on the same path in
    // between. Bound onto itself as the caller's own file it was named by
    // this wrap nowhere, and went from under its sandbox at the other's
    // clean-up.
    const exists = fs.existsSync
    let made = false
    const spy = spyOn(fs, 'existsSync').mockImplementation(((file: unknown) => {
      if (file === LOCK && !made) {
        made = true
        expect(exists(LOCK)).toBe(false)
        writeFileSync(LOCK, '')
        chmodSync(LOCK, 0o444)
      }
      return exists(file as string)
    }) as never)
    let command: string
    try {
      command = await wrap('true')
    } finally {
      spy.mockRestore()
    }
    expect(made).toBe(true)
    expect(command).toContain(`--ro-bind /dev/null ${LOCK}`)
    expect(command).not.toContain(`--ro-bind ${LOCK} ${LOCK}`)
    expect(readFileSync(manifestOf(command), 'utf8')).toContain(LOCK)
  })

  it.if(BWRAP_CAN_NAMESPACE)(
    'goes at once through the public clean-up, given the id its wrap was given',
    async () => {
      const lockOfFirst = join(AREA, 'repo', '.git', 'first.lock')
      const config = (deny: string) => ({
        filesystem: { denyRead: [], allowWrite: [AREA], denyWrite: [deny] },
      })
      await SandboxManager.initialize({
        network: { allowedDomains: [], deniedDomains: [] },
        ...config(lockOfFirst),
      })
      try {
        const first = await SandboxManager.wrapWithSandbox(
          'true',
          undefined,
          undefined,
          undefined,
          { commandId: 'first-0123456789abcdef' },
        )
        const second = await SandboxManager.wrapWithSandbox(
          'true',
          undefined,
          config(LOCK),
          undefined,
          { commandId: 'second-0123456789abcdef' },
        )
        expect(spawnSync(first, { shell: true, timeout: 60000 }).status).toBe(0)
        expect(existsSync(lockOfFirst)).toBe(true)

        SandboxManager.cleanupAfterCommand({
          commandId: 'first-0123456789abcdef',
        })
        expect(existsSync(lockOfFirst)).toBe(false)
        expect(existsSync(manifestOf(first))).toBe(false)
        // The other command has not started, and still can.
        expect(existsSync(manifestOf(second))).toBe(true)
        expect(spawnSync(second, { shell: true, timeout: 60000 }).status).toBe(
          0,
        )
      } finally {
        await SandboxManager.reset()
      }
    },
    90000,
  )

  it.if(BWRAP_CAN_NAMESPACE)(
    "is recorded in a directory of the process's own only when there is one to record, and that directory goes with the process",
    async () => {
      // Neither shared name will do: no runtime directory, and the name under
      // the temp dir is somebody's file.
      const TMP = join(BASE, 'tmp')
      mkdirSync(TMP)
      const squatted = join(TMP, `srt-mount-points-${process.getuid!()}`)
      writeFileSync(squatted, '')
      const env: Record<string, string | undefined> = {
        ...process.env,
        TMPDIR: TMP,
      }
      delete env.XDG_RUNTIME_DIR
      const inThatPlace = (script: string, deny: string[]) =>
        spawnSync(
          process.execPath,
          [
            writeScript(
              script,
              [
                `import { spawnSync } from 'node:child_process'`,
                `import { readdirSync } from 'node:fs'`,
                `import { wrapCommandWithSandboxLinux } from ${LIBRARY}`,
                `const wrapped = await wrapCommandWithSandboxLinux({`,
                `  command: 'true',`,
                `  needsNetworkRestriction: false,`,
                `  readConfig: { denyOnly: [] },`,
                `  writeConfig: { allowOnly: [${JSON.stringify(AREA)}], denyWithinAllow: ${JSON.stringify(deny)} },`,
                `})`,
                `const r = spawnSync(wrapped, { shell: true, encoding: 'utf8', timeout: 60000 })`,
                `console.log(JSON.stringify({ wrapped, status: r.status, said: String(r.stdout ?? '') + String(r.stderr ?? ''), made: readdirSync(${JSON.stringify(TMP)}) }))`,
              ].join('\n'),
            ),
          ],
          {
            env: env as Record<string, string>,
            encoding: 'utf8',
            timeout: 60000,
          },
        )
      const manifestDirectories = (names: string[]): string[] =>
        names.filter(name => /^srt-mount-points-[A-Za-z0-9]{6}$/.test(name))

      // With no mount point there is nothing to record and nothing to keep
      // out of the command's reach, and no directory is made for it.
      const nothingToRecord = JSON.parse(
        inThatPlace('nothing-to-record.ts', []).stdout,
      ) as { wrapped: string; status: number; made: string[] }
      expect(nothingToRecord.status).toBe(0)
      expect(nothingToRecord.wrapped).not.toContain('--lock-file')
      expect(manifestDirectories(nothingToRecord.made)).toEqual([])
      expect(manifestDirectories(readdirSync(TMP))).toEqual([])

      // With one, it is made, used, and gone again when the process ends.
      const recorded = JSON.parse(
        inThatPlace('recorded.ts', [LOCK]).stdout,
      ) as { wrapped: string; status: number; said: string; made: string[] }
      expect(recorded.said).not.toContain('bwrap:')
      expect(recorded.status).toBe(0)
      expect(manifestDirectories(recorded.made).length).toBe(1)
      expect(dirname(manifestOf(recorded.wrapped))).toBe(
        join(TMP, manifestDirectories(recorded.made)[0]!),
      )
      expect(manifestDirectories(readdirSync(TMP))).toEqual([])
      expect(existsSync(LOCK)).toBe(false)
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

/**
 * The one case where nothing but the kernel's lock keeps a mount point: the
 * process that wrapped the command is GONE, and the sandbox it started is
 * STILL RUNNING. The manifest's writer no longer vouches for it, the grace
 * period has run out, and no count in anyone's memory knows about it; only
 * bubblewrap's --lock-file, seen through /proc/locks, says the sandbox is
 * there. Every test above has the wrapping process alive, which alone keeps
 * the manifest live.
 *
 * The wrap always asks for --die-with-parent, so a sandbox outlives the
 * process that wrapped it only when something else is bubblewrap's parent:
 * here a shell in a session of its own, as when a wrapped command is handed to
 * a job runner, a terminal multiplexer or `nohup sh -c`, or when the wrapping
 * process is killed and the `sh -c` it spawned the command through is not.
 */
describe.if(isLinux)(
  'A mount point whose sandbox outlives the process that wrapped it',
  () => {
    usePrivateManifestDirectory()
    const BWRAP_CAN_NAMESPACE = bwrapCanNamespace()
    const LIBRARY = JSON.stringify(
      join(import.meta.dir, '../../src/sandbox/linux-sandbox-utils.ts'),
    )
    // Comfortably past the grace a new manifest is given (500 ms): after this
    // only the writer being alive, or the lock, can make the manifest live.
    const PAST_GRACE_MS = 1200

    let BASE: string
    let AREA: string // the allowed write area
    let LOCK: string // the denyWrite path, absent to begin with
    let SIGNAL: string // written from inside the sandbox once it is up
    let GO: string // written by the test to let the sandbox try its write
    let RESULT: string // what the denied write returned, from inside
    let INFO: string // what the writer says about itself before it goes
    let launcher: number | undefined // the shell bubblewrap is a child of
    let writer: ChildProcess | undefined

    beforeEach(() => {
      BASE = realpathSync(mkdtempSync(join(tmpdir(), 'mount-point-orphan-')))
      AREA = join(BASE, 'area')
      mkdirSync(join(AREA, 'repo', '.git'), { recursive: true })
      LOCK = join(AREA, 'repo', '.git', 'config.lock')
      SIGNAL = join(AREA, 'up')
      GO = join(AREA, 'go')
      RESULT = join(AREA, 'result')
      INFO = join(BASE, 'info.json')
      launcher = undefined
      writer = undefined
    })

    afterEach(async () => {
      writer?.kill('SIGKILL')
      if (launcher !== undefined) {
        await killTree(launcher)
      }
      cleanupBwrapMountPoints({ force: true })
      rmSync(BASE, { recursive: true, force: true })
    })

    function sleep(ms: number): Promise<void> {
      return new Promise(resolve => setTimeout(resolve, ms))
    }

    async function waitFor(
      what: string,
      done: () => boolean,
      timeoutMs = 30000,
    ): Promise<void> {
      const deadline = Date.now() + timeoutMs
      while (!done()) {
        if (Date.now() > deadline) {
          throw new Error(`timed out waiting for ${what}`)
        }
        await sleep(25)
      }
    }

    /** "pid state ppid" of every process this one can see. */
    function processes(): { pid: number; state: string; ppid: number }[] {
      const found: { pid: number; state: string; ppid: number }[] = []
      for (const name of readdirSync('/proc')) {
        if (!/^\d+$/.test(name)) continue
        try {
          const stat = readFileSync(`/proc/${name}/stat`, 'utf8')
          const [state, ppid] = stat
            .slice(stat.lastIndexOf(')') + 1)
            .trim()
            .split(' ')
          found.push({
            pid: Number(name),
            state: state ?? '?',
            ppid: Number(ppid),
          })
        } catch {
          // Went away while we were looking.
        }
      }
      return found
    }

    /** `root` and everything under it that is still running (not a zombie). */
    function runningTree(root: number): number[] {
      const all = processes()
      const tree = [root]
      for (let i = 0; i < tree.length; i++) {
        for (const p of all) {
          if (p.ppid === tree[i] && !tree.includes(p.pid)) tree.push(p.pid)
        }
      }
      return tree.filter(pid =>
        all.some(p => p.pid === pid && p.state !== 'Z' && p.state !== 'X'),
      )
    }

    async function killTree(root: number): Promise<void> {
      const tree = runningTree(root)
      for (const pid of tree) {
        try {
          process.kill(pid, 'SIGKILL')
        } catch {
          // Gone already.
        }
      }
      await waitFor(
        `the sandbox under ${root} to be gone`,
        () =>
          !processes().some(
            p => tree.includes(p.pid) && p.state !== 'Z' && p.state !== 'X',
          ),
      )
    }

    /**
     * Says it is up, waits to be told, tries the denied write, reports what
     * that returned, and then STAYS: the sandbox is still running when it is
     * killed further down.
     */
    function heldCommand(): string {
      return `echo up > ${SIGNAL}; while [ ! -e ${GO} ]; do sleep 0.05; done; echo pwned > ${LOCK}; echo rc=$? > ${RESULT}; sleep 600`
    }

    /**
     * A process that wraps the held command, starts it under a shell in a
     * session of its own, says who is who, waits for the sandbox to be up and
     * then goes: `leave` is how.
     */
    function writerScript(leave: string): string {
      return [
        `import { spawn } from 'node:child_process'`,
        `import { existsSync, writeFileSync } from 'node:fs'`,
        `import { wrapCommandWithSandboxLinux } from ${LIBRARY}`,
        `const wrapped = await wrapCommandWithSandboxLinux({`,
        `  command: ${JSON.stringify(heldCommand())},`,
        `  needsNetworkRestriction: false,`,
        `  readConfig: { denyOnly: [] },`,
        `  writeConfig: { allowOnly: [${JSON.stringify(AREA)}], denyWithinAllow: [${JSON.stringify(LOCK)}] },`,
        `})`,
        // "; exit" so that no shell execs bubblewrap in its own place: the
        // shell has to stay, as the parent --die-with-parent watches.
        `const child = spawn('/bin/sh', ['-c', wrapped + '\\nexit $?'], { detached: true, stdio: 'ignore' })`,
        `child.unref()`,
        `writeFileSync(${JSON.stringify(INFO)}, JSON.stringify({ writer: process.pid, launcher: child.pid, wrapped }))`,
        // Not for ever: a sandbox that never comes up fails the test at once.
        `const deadline = Date.now() + 30000`,
        `while (!existsSync(${JSON.stringify(SIGNAL)})) {`,
        `  if (Date.now() > deadline) process.exit(3)`,
        `  await new Promise(r => setTimeout(r, 25))`,
        `}`,
        leave,
      ].join('\n')
    }

    /** A process that only collects: it has wrapped nothing. */
    function collectorScript(): string {
      return [
        `import { cleanupBwrapMountPoints } from ${LIBRARY}`,
        `cleanupBwrapMountPoints()`,
        `cleanupBwrapMountPoints({ force: true })`,
      ].join('\n')
    }

    /** A process that denies the same path, runs a command and cleans up. */
    function secondWrapperScript(): string {
      return [
        `import { spawnSync } from 'node:child_process'`,
        `import { wrapCommandWithSandboxLinux, cleanupBwrapMountPoints } from ${LIBRARY}`,
        `const wrapped = await wrapCommandWithSandboxLinux({`,
        `  command: 'true',`,
        `  needsNetworkRestriction: false,`,
        `  readConfig: { denyOnly: [] },`,
        `  writeConfig: { allowOnly: [${JSON.stringify(AREA)}], denyWithinAllow: [${JSON.stringify(LOCK)}] },`,
        `})`,
        `const r = spawnSync(wrapped, { shell: true, encoding: 'utf8', timeout: 60000 })`,
        `cleanupBwrapMountPoints()`,
        `process.exit(r.status ?? 1)`,
      ].join('\n')
    }

    function runScript(name: string, source: string): number | null {
      const file = join(BASE, name)
      writeFileSync(file, source)
      return spawnSync(process.execPath, [file], {
        encoding: 'utf8',
        timeout: 60000,
      }).status
    }

    /** The manifests in `dir` that name the deny path. */
    function manifestsNamingLock(dir: string): string[] {
      return readdirSync(dir).filter(
        name =>
          name.endsWith('.json') &&
          readFileSync(join(dir, name), 'utf8').includes(LOCK),
      )
    }

    type Writer = { writer: number; launcher: number; wrapped: string }

    /**
     * Has a process wrap the held command, start it and go, and checks the
     * premise: that process is gone, and its sandbox is up and running.
     */
    async function sandboxWhoseWriterHasGone(
      leave: string,
      signal: NodeJS.Signals | null,
    ): Promise<Writer> {
      const writerFile = join(BASE, 'writer.ts')
      writeFileSync(writerFile, writerScript(leave))
      writer = spawn(process.execPath, [writerFile], { stdio: 'ignore' })
      const left = await new Promise<{
        code: number | null
        signal: NodeJS.Signals | null
      }>(resolve =>
        writer!.on('exit', (code, signal) => resolve({ code, signal })),
      )
      expect(left).toEqual({ code: signal === null ? 0 : null, signal })

      const info = JSON.parse(readFileSync(INFO, 'utf8')) as Writer
      launcher = info.launcher
      expect(existsSync(`/proc/${info.writer}`)).toBe(false)
      expect(existsSync(SIGNAL)).toBe(true)
      expect(runningTree(info.launcher).length).toBeGreaterThan(1)
      return info
    }

    /** Lets the sandbox try its write, and says what came of it. */
    async function theDeniedWrite(): Promise<{
      deniedWrite: string
      onTheHost: string
    }> {
      writeFileSync(GO, '')
      await waitFor(
        'the sandbox to say what its write returned',
        () => existsSync(RESULT) && readFileSync(RESULT, 'utf8').includes('\n'),
      )
      return {
        deniedWrite: readFileSync(RESULT, 'utf8').trim(),
        onTheHost: existsSync(LOCK)
          ? readFileSync(LOCK, 'utf8')
          : '(no mount point)',
      }
    }

    const ways: [string, string, NodeJS.Signals | null][] = [
      [
        'is killed before it can clean up',
        `process.kill(process.pid, 'SIGKILL')`,
        'SIGKILL',
      ],
      // Its exit handler runs the cleanup, with `force`, under its own
      // sandbox: everything the process made may go, and a sandbox that is
      // still running under a manifest is not the process's to end.
      ['exits, running its exit-time cleanup', `process.exit(0)`, null],
    ]

    for (const [how, leave, signal] of ways) {
      it.if(BWRAP_CAN_NAMESPACE)(
        `stays, and the deny holds, while other processes collect after its writer ${how}; goes once the sandbox is gone`,
        async () => {
          const info = await sandboxWhoseWriterHasGone(leave, signal)
          const manifest = /--lock-file (\S+)/.exec(info.wrapped)?.[1]
          expect(manifest).toBeDefined()
          // Still naming the deny path, and the process that is gone.
          const written = JSON.parse(readFileSync(manifest!, 'utf8')) as {
            pid: number
            paths: string[]
          }
          expect(written.pid).toBe(info.writer)
          expect(written.paths).toContain(LOCK)

          // Whether the mount point bwrap made is on the host, and the
          // manifest that names it where the wrap put it, after each thing
          // that might have taken them. Looked at together further down, so
          // that a failure says all of what happened and not only the first
          // of it.
          const BOTH = 'the mount point and its manifest'
          const stayed: Record<string, string> = {}
          const look = (when: string): void => {
            const mountPoint = existsSync(LOCK) && lstatSync(LOCK).size === 0
            const named = existsSync(manifest!)
            stayed[when] =
              mountPoint && named
                ? BOTH
                : mountPoint
                  ? 'the mount point, not its manifest'
                  : named
                    ? 'the manifest, not the mount point'
                    : 'neither'
          }
          look('after its writer went')

          // Past the grace a new manifest is given, so that neither it nor
          // the writer is what keeps the manifest live below.
          await sleep(PAST_GRACE_MS)

          expect(runScript('collector.ts', collectorScript())).toBe(0)
          look('after a process that wrapped nothing collected')
          expect(runScript('second.ts', secondWrapperScript())).toBe(0)
          look('after a process that denies the same path ran and cleaned up')
          cleanupBwrapMountPoints()
          cleanupBwrapMountPoints({ force: true })
          look('after this process collected, twice')

          // The sandbox is still there. Let it try the denied write: it must
          // fail inside, and nothing may land on the host. (A mount point
          // that was removed and made again by the second wrap is on the host
          // again, but is no longer what this sandbox is bound over, so only
          // the write tells.)
          expect(runningTree(info.launcher).length).toBeGreaterThan(1)
          expect({ stayed, ...(await theDeniedWrite()) }).toEqual({
            stayed: {
              'after its writer went': BOTH,
              'after a process that wrapped nothing collected': BOTH,
              'after a process that denies the same path ran and cleaned up':
                BOTH,
              'after this process collected, twice': BOTH,
            },
            deniedWrite: expect.stringMatching(/^rc=[1-9]/),
            onTheHost: '',
          })

          // Still running after its write, and a collect still leaves it.
          expect(runningTree(info.launcher).length).toBeGreaterThan(1)
          expect(runScript('collector.ts', collectorScript())).toBe(0)
          expect(existsSync(LOCK)).toBe(true)

          // Kill the sandbox. However it ends the kernel drops the lock, and
          // the next collect, by anyone, takes the mount point and the
          // manifest away.
          await killTree(info.launcher)
          launcher = undefined
          expect(runScript('collector.ts', collectorScript())).toBe(0)
          expect(existsSync(LOCK)).toBe(false)
          expect(manifestsNamingLock(join(manifest!, '..'))).toEqual([])
        },
        120000,
      )
    }

    it.if(BWRAP_CAN_NAMESPACE)(
      'holds its deny while another process collects without pause, with the process that wrapped it gone',
      async () => {
        // A collector that never has a candidate proves nothing, and with the
        // wrapping process alive it never has one: the writer vouches for the
        // manifest whatever the kernel says. Here the writer is gone and the
        // grace is over before the write is tried, so for most of each round
        // the lock is all that stands between the collector and the mount
        // point, and the collector is asking the whole time.
        const loopFile = join(BASE, 'collect-loop.ts')
        writeFileSync(
          loopFile,
          [
            `import { cleanupBwrapMountPoints } from ${LIBRARY}`,
            `const until = Date.now() + 90000`,
            `while (Date.now() < until) cleanupBwrapMountPoints()`,
          ].join('\n'),
        )
        const loop = spawn(process.execPath, [loopFile], { stdio: 'ignore' })
        try {
          for (let round = 0; round < 3; round++) {
            const info = await sandboxWhoseWriterHasGone(
              `process.kill(process.pid, 'SIGKILL')`,
              'SIGKILL',
            )
            await sleep(PAST_GRACE_MS)
            expect(loop.exitCode).toBe(null) // still collecting
            expect(lstatSync(LOCK).size).toBe(0)
            expect(await theDeniedWrite()).toEqual({
              deniedWrite: expect.stringMatching(/^rc=[1-9]/),
              onTheHost: '',
            })
            await killTree(info.launcher)
            launcher = undefined
            // With the sandbox gone the same collector takes it away.
            await waitFor(
              'the collector to take the mount point away',
              () => !existsSync(LOCK),
            )
            for (const file of [SIGNAL, GO, RESULT, INFO]) {
              rmSync(file, { force: true })
            }
          }
        } finally {
          loop.kill('SIGKILL')
        }
      },
      120000,
    )
  },
)

/**
 * The mount point for a deny whose first missing component is not the leaf is
 * an empty DIRECTORY, bound from an empty read-only one. On the host it looks
 * like anyone's empty directory, so only a manifest says what it is.
 */
describe.if(isLinux)(
  'A directory mount point a running sandbox relies on',
  () => {
    usePrivateManifestDirectory()
    const BWRAP_CAN_NAMESPACE = bwrapCanNamespace()
    const LIBRARY = JSON.stringify(
      join(import.meta.dir, '../../src/sandbox/linux-sandbox-utils.ts'),
    )
    let BASE: string
    let AREA: string
    let DIRECTORY: string // the first missing component of LEAF
    let LEAF: string

    beforeEach(() => {
      BASE = realpathSync(mkdtempSync(join(tmpdir(), 'mount-point-directory-')))
      AREA = join(BASE, 'area')
      mkdirSync(join(AREA, 'proj'), { recursive: true })
      DIRECTORY = join(AREA, 'proj', '.claude')
      LEAF = join(DIRECTORY, 'commands')
    })

    afterEach(() => {
      cleanupBwrapMountPoints({ force: true })
      rmSync(BASE, { recursive: true, force: true })
    })

    const wrap = (command: string, deny: string[]): Promise<string> =>
      wrapCommandWithSandboxLinux({
        command,
        needsNetworkRestriction: false,
        readConfig: { denyOnly: [] },
        writeConfig: { allowOnly: [AREA], denyWithinAllow: deny },
      })

    const run = (
      command: string,
    ): { status: number | null; said: string; stdout: string } => {
      const r = spawnSync(command, {
        shell: true,
        encoding: 'utf8',
        timeout: 60000,
      })
      return {
        status: r.status,
        said: `${r.stdout}${r.stderr}`,
        stdout: r.stdout,
      }
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

    /**
     * Another process: denies LEAF, holds its sandbox until `go` is there,
     * and cleans up after it.
     */
    function holder(up: string, go: string): ChildProcess {
      const file = join(BASE, 'holder.ts')
      writeFileSync(
        file,
        [
          `import { spawnSync } from 'node:child_process'`,
          `import { wrapCommandWithSandboxLinux, cleanupBwrapMountPoints } from ${LIBRARY}`,
          `const wrapped = await wrapCommandWithSandboxLinux({`,
          `  command: ${JSON.stringify(`echo up > ${up}; while [ ! -e ${go} ]; do sleep 0.05; done`)},`,
          `  needsNetworkRestriction: false,`,
          `  readConfig: { denyOnly: [] },`,
          `  writeConfig: { allowOnly: [${JSON.stringify(AREA)}], denyWithinAllow: [${JSON.stringify(LEAF)}] },`,
          `})`,
          `spawnSync(wrapped, { shell: true, encoding: 'utf8', timeout: 60000 })`,
          `cleanupBwrapMountPoints()`,
        ].join('\n'),
      )
      return spawn(process.execPath, [file], { stdio: 'ignore' })
    }

    it.if(BWRAP_CAN_NAMESPACE)(
      'can be denied by a second wrap whose deny path is exactly that directory',
      async () => {
        // A live manifest names it, which used to get it /dev/null bound over
        // it like a file mount point: bubblewrap cannot put a character device
        // over a directory, and the command did not start.
        const up = join(AREA, 'up-holder')
        const go = join(AREA, 'go-holder')
        const held = holder(up, go)
        const heldExited = new Promise(resolve => held.on('exit', resolve))
        try {
          await waitFor(up)
          expect(lstatSync(DIRECTORY).isDirectory()).toBe(true)
          const command = await wrap(`touch ${DIRECTORY}/x; echo rc=$?`, [
            DIRECTORY,
          ])
          expect(command).not.toContain(`--ro-bind /dev/null ${DIRECTORY}`)
          expect(command).toContain(`--ro-bind ${DIRECTORY} ${DIRECTORY}`)
          const second = run(command)
          expect(second.said).not.toContain('bwrap:')
          expect(second.status).toBe(0)
          expect(second.stdout).toMatch(/rc=[1-9]/)
        } finally {
          writeFileSync(go, '')
          await heldExited
        }
      },
      90000,
    )

    it.if(BWRAP_CAN_NAMESPACE)(
      'can be denied again by the same list, with the earlier wrap of this process not yet cleaned up after',
      async () => {
        // No second process and nothing running: a manifest is live for as
        // long as the process that wrote it has not let go of it. A deny list
        // that names a missing directory and something beneath it makes the
        // directory the mount point, and the same list again then finds it
        // named by a live manifest. It is what the mandatory denies under
        // `<cwd>/.claude` make of a `denyWrite` on `<cwd>/.claude` itself.
        const first = run(await wrap('echo first-ran', [DIRECTORY, LEAF]))
        expect(first.stdout).toContain('first-ran')
        expect(lstatSync(DIRECTORY).isDirectory()).toBe(true)

        const command = await wrap(
          `echo second-ran; touch ${DIRECTORY}/x; echo rc=$?`,
          [DIRECTORY, LEAF],
        )
        expect(command).not.toContain(`--ro-bind /dev/null ${DIRECTORY}`)
        const second = run(command)
        expect(second.said).not.toContain('bwrap:')
        expect(second.stdout).toContain('second-ran')
        expect(second.stdout).toMatch(/rc=[1-9]/)

        cleanupBwrapMountPoints()
        cleanupBwrapMountPoints()
        expect(existsSync(DIRECTORY)).toBe(false)
      },
      90000,
    )

    it.if(BWRAP_CAN_NAMESPACE)(
      'stays while that second sandbox runs, after the sandbox that made it has ended and been cleaned up after',
      async () => {
        // Bound onto itself and not named, it went with the sandbox that made
        // it: the bind came off inside the second sandbox, the denied
        // directory could be made again there, and what was written under it
        // landed on the host.
        const upHolder = join(AREA, 'up-holder')
        const goHolder = join(AREA, 'go-holder')
        const upSecond = join(AREA, 'up-second')
        const goSecond = join(AREA, 'go-second')
        const held = holder(upHolder, goHolder)
        const heldExited = new Promise(resolve => held.on('exit', resolve))
        let said = ''
        try {
          await waitFor(upHolder)
          const second = spawn(
            await wrap(
              `echo up > ${upSecond}; while [ ! -e ${goSecond} ]; do sleep 0.05; done; mkdir -p ${LEAF}; echo pwned > ${LEAF}/x.md; echo rc=$?`,
              [DIRECTORY],
            ),
            { shell: true },
          )
          second.stdout.on('data', chunk => (said += String(chunk)))
          second.stderr.on('data', chunk => (said += String(chunk)))
          const secondExited = new Promise(resolve =>
            second.on('exit', resolve),
          )
          await waitFor(upSecond)

          writeFileSync(goHolder, '')
          await heldExited // and its own clean-up has run
          await new Promise(resolve => setTimeout(resolve, 700))
          cleanupBwrapMountPoints()
          expect(existsSync(DIRECTORY)).toBe(true)

          writeFileSync(goSecond, '')
          await secondExited
          expect(said).toMatch(/rc=[1-9]/)
          expect(existsSync(join(LEAF, 'x.md'))).toBe(false)

          // And goes once nothing runs under it.
          cleanupBwrapMountPoints()
          expect(existsSync(DIRECTORY)).toBe(false)
        } finally {
          writeFileSync(goHolder, '')
          writeFileSync(goSecond, '')
          await heldExited
        }
      },
      90000,
    )
  },
)

/**
 * Both of a manifest's witnesses are relative to a PID namespace: /proc/PID
 * is, and /proc/locks leaves out every lock whose holder has no pid in the
 * namespace of the /proc being read. A process that cleans up from another PID
 * namespace while sharing the manifest directory - a container beside the
 * host, one srt inside another's sandbox - sees a running sandbox's manifest
 * exactly as it would see one a dead process left.
 */
describe.if(isLinux)(
  'A mount point a running sandbox relies on, seen from another PID namespace',
  () => {
    usePrivateManifestDirectory()
    // A second PID namespace with a /proc of its own, uid unchanged, no root.
    const IN_NEW_PID_NAMESPACE = [
      'unshare',
      '--user',
      '--map-current-user',
      '--pid',
      '--fork',
      '--mount-proc',
    ]
    const CAN =
      bwrapCanNamespace() &&
      spawnSync(IN_NEW_PID_NAMESPACE[0]!, [
        ...IN_NEW_PID_NAMESPACE.slice(1),
        'true',
      ]).status === 0
    const LIBRARY = JSON.stringify(
      join(import.meta.dir, '../../src/sandbox/linux-sandbox-utils.ts'),
    )
    let BASE: string
    let AREA: string
    let LOCK: string
    let SIGNAL: string
    let GO: string
    let OUT: string
    let WRAPPED: string

    beforeEach(() => {
      BASE = realpathSync(mkdtempSync(join(tmpdir(), 'mount-point-pidns-')))
      AREA = join(BASE, 'area')
      mkdirSync(join(AREA, 'repo', '.git'), { recursive: true })
      LOCK = join(AREA, 'repo', '.git', 'config.lock')
      SIGNAL = join(AREA, 'up')
      GO = join(AREA, 'go')
      OUT = join(BASE, 'out.txt')
      WRAPPED = join(BASE, 'wrapped.txt')
    })

    afterEach(() => {
      cleanupBwrapMountPoints({ force: true })
      rmSync(BASE, { recursive: true, force: true })
    })

    function writeScript(name: string, lines: string[]): string {
      const file = join(BASE, name)
      writeFileSync(file, lines.join('\n'))
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

    it.if(CAN)(
      'survives a cleanup run where neither its writer nor its lock can be seen',
      async () => {
        const command = `echo up > ${SIGNAL}; while [ ! -e ${GO} ]; do sleep 0.05; done; echo pwned > ${LOCK}; echo rc=$?`
        const holder = spawn(
          process.execPath,
          [
            writeScript('holder.ts', [
              `import { spawnSync } from 'node:child_process'`,
              `import { writeFileSync } from 'node:fs'`,
              `import { wrapCommandWithSandboxLinux } from ${LIBRARY}`,
              `const wrapped = await wrapCommandWithSandboxLinux({`,
              `  command: ${JSON.stringify(command)},`,
              `  needsNetworkRestriction: false,`,
              `  readConfig: { denyOnly: [] },`,
              `  writeConfig: { allowOnly: [${JSON.stringify(AREA)}], denyWithinAllow: [${JSON.stringify(LOCK)}] },`,
              `})`,
              `writeFileSync(${JSON.stringify(WRAPPED)}, wrapped)`,
              `const r = spawnSync(wrapped, { shell: true, encoding: 'utf8', timeout: 60000 })`,
              `writeFileSync(${JSON.stringify(OUT)}, String(r.stdout ?? '') + String(r.stderr ?? ''))`,
            ]),
          ],
          // Outside every allowed write path, so no mount points for cwd.
          { stdio: 'ignore', cwd: import.meta.dir },
        )
        const holderExited = new Promise(resolve => holder.on('exit', resolve))
        let manifest: string
        try {
          await waitFor(SIGNAL)
          manifest = /--lock-file (\S+)/.exec(
            readFileSync(WRAPPED, 'utf8'),
          )![1]!
          expect(existsSync(manifest)).toBe(true)
          expect(lstatSync(LOCK).size).toBe(0)
          // Past the grace: only the writer's pid and the kernel's lock vouch
          // for the manifest now, and neither can be seen from over there.
          await new Promise(resolve => setTimeout(resolve, 800))

          const collector = spawnSync(
            IN_NEW_PID_NAMESPACE[0]!,
            [
              ...IN_NEW_PID_NAMESPACE.slice(1),
              process.execPath,
              writeScript('collector.ts', [
                `import { existsSync, readFileSync, statSync } from 'node:fs'`,
                `import { cleanupBwrapMountPoints } from ${LIBRARY}`,
                // The premise, so that a pass means something: from here the
                // kernel's list really does leave the sandbox's lock out, and
                // the writer's pid is nobody's.
                `const inode = statSync(${JSON.stringify(manifest)}).ino`,
                `if (readFileSync('/proc/locks', 'utf8').includes(':' + inode + ' ')) process.exit(7)`,
                `if (existsSync('/proc/${holder.pid}')) process.exit(8)`,
                `cleanupBwrapMountPoints()`,
              ]),
            ],
            { encoding: 'utf8', timeout: 60000, cwd: import.meta.dir },
          )
          expect(collector.status).toBe(0)

          // The sandbox is still running: both must still be there.
          expect(existsSync(LOCK)).toBe(true)
          expect(existsSync(manifest)).toBe(true)
        } finally {
          writeFileSync(GO, '')
        }

        await holderExited
        expect(readFileSync(OUT, 'utf8')).toMatch(/rc=[1-9]/)
        expect(existsSync(LOCK) ? readFileSync(LOCK, 'utf8') : '').toBe('')

        // And it still goes once nothing runs under it, from the namespace
        // that can tell: the holder's exit handler, or this cleanup.
        await new Promise(resolve => setTimeout(resolve, 600))
        cleanupBwrapMountPoints()
        expect(existsSync(LOCK)).toBe(false)
        expect(existsSync(manifest)).toBe(false)
      },
      90000,
    )
  },
)
