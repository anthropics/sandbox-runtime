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
  readlinkSync,
  realpathSync,
  rmSync,
  symlinkSync,
  utimesSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { basename, dirname, join } from 'node:path'
import { liveMountPoints } from '../../src/index.js'
import {
  cleanupBwrapMountPoints,
  LinuxSandboxProfileError,
  wrapCommandWithSandboxLinux,
} from '../../src/sandbox/linux-sandbox-utils.js'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import { whichSync } from '../../src/utils/which.js'
import {
  countMounts,
  indexOfMount,
  manifestOf as recordedBy,
  RECORD_STEP,
  STEP_SHELL,
} from '../helpers/bwrap-argv.js'
import { bwrapCanNamespace } from '../helpers/bwrap-namespace.js'
import { isLinux } from '../helpers/platform.js'
import { usePrivateManifestDirectory } from '../helpers/private-manifest-directory.js'

/** bubblewrap as a wrap names it: by the path it was found at. */
const BWRAP = whichSync('bwrap') ?? 'bwrap'

/**
 * A denyWrite path that does not exist is blocked by binding over a mount point
 * bwrap makes on the host. Unlinking one while a sandbox is bound over it
 * detaches the mount inside that sandbox, and the denied path can then be
 * created on the host. So every wrap names its mount points in a manifest, and
 * the command it hands out puts the process it starts bubblewrap in on that
 * manifest's record: a mount point goes only when no process on the record of
 * a manifest that names it is running.
 */
describe.if(isLinux)('A mount point a running sandbox relies on', () => {
  // These tests list the manifests, attack them from inside a sandbox and
  // assert on what is left: in a directory of their own.
  const runtime = usePrivateManifestDirectory()
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

  /** The set a caller is given of the live mount points, as a list. */
  function live(): string[] | undefined {
    const set = liveMountPoints()
    return set && [...set]
  }

  /** The manifest the wrap recorded its mount points in. */
  function manifestOf(command: string): string {
    const file = recordedBy(command)
    expect(file).toBeDefined()
    return file!
  }

  /**
   * The manifest of a wrap that named `paths`, written a minute ago by
   * `writer`: by default a process that is gone, which makes it a finished one.
   */
  function manifestNaming(paths: string[], writer?: number): string {
    const dir = runtime.manifestDir()
    mkdirSync(dir, { recursive: true, mode: 0o700 })
    chmodSync(dir, 0o700)
    let pid = 4194000
    let start = '1'
    if (writer === undefined) {
      while (existsSync(`/proc/${pid}`)) pid--
    } else {
      const stat = readFileSync(`/proc/${writer}/stat`, 'utf8')
      pid = writer
      start = stat
        .slice(stat.lastIndexOf(')') + 1)
        .trim()
        .split(' ')[19]!
    }
    const file = join(dir, `${pid}-0123456789abcdef.json`)
    writeFileSync(
      file,
      JSON.stringify({
        version: 1,
        pid,
        start,
        ns: readlinkSync('/proc/self/ns/pid'),
        created: Date.now() - 60_000,
        paths,
        sources: [],
      }),
      { mode: 0o600 },
    )
    return file
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
        // The mount point bwrap made for the sandbox that is running, on
        // record where this test and the process below look.
        expect(lstatSync(LOCK).size).toBe(0)
        expect(readdirSync(runtime.manifestDir())).toHaveLength(2)

        // A second process wraps the same deny path, runs a command and cleans
        // up.
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
          { env: { ...process.env }, encoding: 'utf8', timeout: 60000 },
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
        // `force` is what the exit handler and reset() pass. A sandbox running
        // under a manifest is not this process's to end, so that manifest and
        // what it names stay.
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
    'is in the set another process is given of the live mount points, for as long as the sandbox runs',
    async () => {
      // For a caller that removes paths itself after a command: what it is
      // about to remove may be what another process's sandbox is bound over.
      expect(live()).toEqual([])
      const holder = spawn(
        process.execPath,
        [writeScript('holder.ts', wrapperScript(heldCommand(), OUT))],
        { stdio: 'ignore' },
      )
      const holderExited = new Promise(resolve => holder.on('exit', resolve))
      try {
        await waitFor(SIGNAL)
        expect(live()).toEqual([LOCK])
      } finally {
        writeFileSync(GO, '')
      }
      await holderExited
      expect(live()).toEqual([])
    },
    90000,
  )

  it('is given in that set as the wrap recorded it: where the directories above it really are', async () => {
    // A caller that holds its own paths against the set has to spell them the
    // same way.
    const through = join(AREA, 'through')
    symlinkSync(join(AREA, 'repo', '.git'), through)
    const command = await wrap('true', [join(through, 'config.lock')])
    expect(readFileSync(manifestOf(command), 'utf8')).toContain(LOCK)
    // What bubblewrap makes for it, once the command runs.
    writeFileSync(LOCK, '')
    chmodSync(LOCK, 0o444)

    expect(live()).toEqual([LOCK])
  })

  it.if(BWRAP_CAN_NAMESPACE)(
    'stays while a second sandbox that denies it runs, after the one it was made for has ended and been cleaned up after',
    async () => {
      // The second wrap finds the file there. A manifest names it, so the wrap
      // covers and names it too, and its own manifest keeps it once the first
      // is gone.
      const upSecond = join(AREA, 'up-second')
      const goSecond = join(AREA, 'go-second')
      const holder = spawn(
        process.execPath,
        [
          writeScript(
            'holder.ts',
            wrapperScript(heldCommand(), OUT, ['cleanupBwrapMountPoints()']),
          ),
        ],
        { stdio: 'ignore' },
      )
      const holderExited = new Promise(resolve => holder.on('exit', resolve))
      let said = ''
      try {
        await waitFor(SIGNAL)
        const command = await wrap(
          `echo up > ${upSecond}; while [ ! -e ${goSecond} ]; do sleep 0.05; done; echo pwned > ${LOCK}; echo rc=$?`,
        )
        expect(command).toContain(`--ro-bind /dev/null ${LOCK}`)
        expect(readFileSync(manifestOf(command), 'utf8')).toContain(LOCK)
        const second = spawn(command, { shell: true })
        second.stdout.on('data', chunk => (said += String(chunk)))
        second.stderr.on('data', chunk => (said += String(chunk)))
        const secondExited = new Promise(resolve => second.on('exit', resolve))
        await waitFor(upSecond)

        writeFileSync(GO, '')
        await holderExited // and its own clean-up has run
        cleanupBwrapMountPoints()
        expect(lstatSync(LOCK).size).toBe(0)

        writeFileSync(goSecond, '')
        await secondExited
        expect(said).toMatch(/rc=[1-9]/)
        expect(contentAt(LOCK)).toBe('')

        // And goes once nothing runs under it.
        cleanupBwrapMountPoints()
        expect(existsSync(LOCK)).toBe(false)
      } finally {
        writeFileSync(GO, '')
        writeFileSync(goSecond, '')
        await holderExited
      }
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
        { env: { ...process.env }, encoding: 'utf8', timeout: 60000 },
      )
      expect(killed.signal).toBe('SIGKILL')
      // Its sandbox ran, and left what bubblewrap made for it: without this
      // everything below holds of a path nothing was ever made at.
      expect(readFileSync(OUT, 'utf8')).not.toContain('bwrap:')
      expect(lstatSync(LOCK).size).toBe(0)

      const directory = dirname(manifestOf(await wrap('true')))
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
      // A wrap with no absent deny path has no manifest, and the manifests in
      // the directory are then other sandboxes'. A collect on the host believes
      // them, so the command must be able neither to write nor to delete one.
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
      expect(recordedBy(command)).toBeUndefined()

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
      // one started without under the temp dir. Every wrap binds both names
      // read-only and makes the one that is missing, so a sandbox of the first
      // kind cannot forge the manifests of the second.
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
    'refuses to start a command wrapped before a cleanup that has since let go of its manifest, and makes nothing for it',
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
      // The manifest is the first thing bubblewrap binds, so it has made no
      // mount point by then: nothing is on the host that no manifest names.
      expect(result.status).not.toBe(0)
      expect(`${result.stdout}${result.stderr}`).toContain(
        `Can't find source path ${manifest}`,
      )
      expect(existsSync(LOCK)).toBe(false)
      // What the command line recorded of itself goes at the next clean-up.
      expect(readdirSync(dirname(manifest))).toEqual([
        basename(manifest).replace(/json$/, 'started'),
      ])
      cleanupBwrapMountPoints()
      expect(readdirSync(dirname(manifest))).toEqual([])
    },
    90000,
  )

  it('hands out a command that puts itself on record and then binds its manifest, before any other mount', async () => {
    const command = await wrap('true')
    const manifest = manifestOf(command)
    const record = manifest.replace(/json$/, 'started')
    // One shell, which bubblewrap takes the place of: the pid on record is
    // bubblewrap's own, and the sandbox dies with it.
    expect(command).toStartWith(
      `${STEP_SHELL} '${RECORD_STEP} && exec "$@"' srt ${record} ${BWRAP} --new-session --die-with-parent `,
    )
    expect(command).toContain(
      ` --ro-bind / / --ro-bind ${manifest} ${manifest} --`,
    )
    // A wrap that names no mount point has nothing to vouch for.
    expect(await wrap('true', [])).toStartWith(
      `${BWRAP} --new-session --die-with-parent `,
    )
  })

  /** Field 22 of a /proc/PID/stat line: when that process started. */
  function startOf(stat: string): string | undefined {
    return stat
      .slice(stat.lastIndexOf(')') + 1)
      .trim()
      .split(' ')[19]
  }

  it.if(BWRAP_CAN_NAMESPACE)(
    'puts bubblewrap itself on record, each time it is run',
    async () => {
      const command = await wrap(heldCommand())
      const child = spawn(command, { shell: true, stdio: 'ignore' })
      const exited = new Promise(resolve => child.on('exit', resolve))
      let pid: string
      try {
        await waitFor(SIGNAL)
        const lines = onRecord(command)
        expect(lines).toHaveLength(1)
        pid = lines[0]!.split(' ')[0]!
        // The shell that wrote the line has become bubblewrap.
        const now = readFileSync(`/proc/${pid}/stat`, 'utf8')
        expect(lines[0]).toMatch(/^\d+ \((ba)?sh\) /)
        expect(now).toStartWith(`${pid} (bwrap) `)
        expect(startOf(now)).toBe(startOf(lines[0]!)!)
      } finally {
        writeFileSync(GO, '')
      }
      await exited
      expect(existsSync(`/proc/${pid}`)).toBe(false)

      expect(spawnSync(command, { shell: true, timeout: 60000 }).status).toBe(0)
      expect(onRecord(command)).toHaveLength(2)
    },
    90000,
  )

  it.if(BWRAP_CAN_NAMESPACE)(
    'puts itself on record by the number /proc has for it, where the shell has another for itself',
    async () => {
      // A PID namespace of its own under the outer /proc, as in a nested
      // sandbox. Only the steps the command takes before bubblewrap are run.
      const command = await wrap('true')
      const steps = /^.*? srt \S+\.started /.exec(command)![0]
      const nested = spawn(
        'bwrap',
        [
          ...['--dev-bind', '/', '/', '--unshare-pid', '--die-with-parent'],
          ...['--', '/bin/sh', '-c', `${steps} sleep 60`],
        ],
        { stdio: 'ignore' },
      )
      try {
        const deadline = Date.now() + 20000
        while (!existsSync(manifestOf(command).replace(/json$/, 'started'))) {
          if (Date.now() > deadline) throw new Error('nothing was recorded')
          await sleep(25)
        }
        while (onRecord(command).length === 0 && Date.now() < deadline) {
          await sleep(25)
        }
        const [line] = onRecord(command)
        const pid = line!.split(' ')[0]
        while (
          !contentAt(`/proc/${pid}/stat`).includes('(sleep)') &&
          Date.now() < deadline
        ) {
          await sleep(25)
        }
        const now = readFileSync(`/proc/${pid}/stat`, 'utf8')
        expect(now).toStartWith(`${pid} (sleep) `)
        expect(startOf(now)).toBe(startOf(line!)!)
      } finally {
        nested.kill('SIGKILL')
      }
    },
    90000,
  )

  it.if(BWRAP_CAN_NAMESPACE)(
    'makes nothing on the host when its manifest is claimed after bubblewrap has looked its sources up',
    async () => {
      // bubblewrap looks up every bind source before it mounts anything, so a
      // claim made before that refuses the start wherever the manifest is
      // bound. Here bubblewrap is held up after that look, with only the root
      // bound (`--file` copies from a FIFO nobody has closed), and the claim
      // lands then: the manifest has to be the next thing it binds.
      const command = await wrap('echo ran')
      const manifest = manifestOf(command)
      const fifo = join(BASE, 'fifo')
      const gate = join(AREA, 'gate')
      expect(spawnSync('mkfifo', [fifo]).status).toBe(0)
      const hold = fs.openSync(fifo, fs.constants.O_RDWR)
      const root = ' --ro-bind / / '
      expect(command.split(root)).toHaveLength(2)
      const child = spawn(
        `${command.replace(root, `${root}--bind ${AREA} ${AREA} --file 8 ${gate} `)} 8<${fifo}`,
        { shell: true },
      )
      let said = ''
      child.stdout.on('data', chunk => (said += String(chunk)))
      child.stderr.on('data', chunk => (said += String(chunk)))
      const exited = new Promise(resolve => child.on('exit', resolve))
      try {
        await waitFor(gate)
        fs.renameSync(manifest, manifest.replace(/json$/, 'claimed'))
      } finally {
        fs.closeSync(hold)
      }
      expect(await exited).not.toBe(0)
      expect(said).toContain(`bwrap: Can't`)
      expect(said).toContain(manifest)
      expect(said).not.toContain('ran')
      expect(existsSync(LOCK)).toBe(false)
    },
    90000,
  )

  // ---- the shell the command takes its own steps in, on the host ----

  const BASH = ['/bin/bash', '/usr/bin/bash'].find(shell => existsSync(shell))

  it.if(BASH !== undefined)(
    'takes its steps in bash, where that is at one of its usual places, and has it import nothing',
    async () => {
      expect(await wrap('true')).toStartWith(`${BASH} -p -c '`)
    },
  )

  for (const [sh, begins] of [
    ['/nix/store/bash-5.2/bin/bash', `/bin/sh -p -c '`],
    ['/usr/bin/dash', `/bin/sh -c '`],
  ] as const) {
    it(`takes them in /bin/sh where bash is at neither, which is ${sh}: ${begins}`, async () => {
      const access = fs.accessSync
      const realpath = fs.realpathSync
      const spies = [
        spyOn(fs, 'accessSync').mockImplementation(((
          file: unknown,
          mode: unknown,
        ) => {
          if (file === '/bin/bash' || file === '/usr/bin/bash') {
            throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' })
          }
          return (access as (...args: unknown[]) => void)(file, mode)
        }) as never),
        spyOn(fs, 'realpathSync').mockImplementation(((
          file: unknown,
          ...rest: unknown[]
        ) =>
          file === '/bin/sh'
            ? sh
            : (realpath as (...args: unknown[]) => string)(
                file,
                ...rest,
              )) as never),
      ]
      try {
        // The shell is found once, so in a copy of the library of its own.
        const fresh = (await import(
          `${JSON.parse(LIBRARY)}?${basename(sh)}`
        )) as {
          wrapCommandWithSandboxLinux: typeof wrapCommandWithSandboxLinux
        }
        expect(
          await fresh.wrapCommandWithSandboxLinux({
            command: 'true',
            binShell: 'sh',
            needsNetworkRestriction: false,
            readConfig: { denyOnly: [] },
            writeConfig: { allowOnly: [AREA], denyWithinAllow: [LOCK] },
          }),
        ).toStartWith(begins)
      } finally {
        spies.forEach(spy => spy.mockRestore())
      }
    })
  }

  it.if(BWRAP_CAN_NAMESPACE && BASH !== undefined)(
    'hands the command every entry of the environment, whatever its name',
    async () => {
      // dash rebuilds the environment from its variables, and drops these.
      const run = spawnSync(BASH!, ['-c', await wrap('env')], {
        env: { ...process.env, 'a.b': 'dotted', 'FOO-BAR': 'dashed' },
        encoding: 'utf8',
        timeout: 60000,
      })
      expect(run.status).toBe(0)
      expect(run.stdout.split('\n')).toEqual(
        expect.arrayContaining(['a.b=dotted', 'FOO-BAR=dashed']),
      )
    },
    90000,
  )

  it.if(BWRAP_CAN_NAMESPACE && BASH !== undefined)(
    'runs nothing on the host that the environment plants for a shell',
    async () => {
      // Each leaves a file where only the host can: the sandbox may not write
      // outside AREA.
      const functionRan = join(BASE, 'function-ran')
      const fileRead = join(BASE, 'file-read')
      const planted = join(BASE, 'bash-env.sh')
      writeFileSync(planted, `touch ${fileRead} 2>/dev/null\n`)
      const command = await wrap('echo started')
      for (const [shell, entry, value] of [
        // Through bash, which hands an exported function on; dash drops it.
        [
          BASH!,
          'BASH_FUNC_shift%%',
          `() { touch ${functionRan} 2>/dev/null; builtin shift; }`,
        ],
        // Through sh, which does not read that file for itself.
        ['/bin/sh', 'BASH_ENV', planted],
      ] as const) {
        const run = spawnSync(shell, ['-c', command], {
          env: { ...process.env, [entry]: value },
          encoding: 'utf8',
          timeout: 60000,
        })
        expect(`${run.stdout}${run.stderr}`).toBe('started\n')
        expect(run.status).toBe(0)
      }
      expect(existsSync(functionRan)).toBe(false)
      expect(existsSync(fileRead)).toBe(false)
    },
    90000,
  )

  // ---- two commands of one process in flight ----
  //
  // A call to clean up cannot tell which command it is for, so while a wrap is
  // outstanding nothing this process made may go: the command that has not
  // started still needs its manifest and its mount point.

  it.if(BWRAP_CAN_NAMESPACE)(
    'a command wrapped and not yet started survives the clean-up after the one that finished first',
    async () => {
      const first = await wrap('echo first-ran')
      // Removed first: the file's mode alone refuses a plain write.
      const second = await wrap(
        `echo second-ran; rm -f ${LOCK}; echo pwned > ${LOCK}; echo rc=$?`,
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

  /**
   * Runs `before` just before, and `after` just after, the next clean-up claims
   * `manifest`.
   */
  function atTheClaimOn(
    manifest: string,
    at: { before?: () => void; after?: () => void },
  ): { restore(): void } {
    const rename = fs.renameSync
    const spy = spyOn(fs, 'renameSync').mockImplementation(((
      from: string,
      to: string,
    ) => {
      const meant = from === manifest && to.endsWith('.claimed')
      if (meant) at.before?.()
      rename(from, to)
      if (meant) at.after?.()
    }) as never)
    return { restore: () => spy.mockRestore() }
  }

  /** The lines on the started record of `command`. */
  function onRecord(command: string): string[] {
    return readFileSync(manifestOf(command).replace(/json$/, 'started'), 'utf8')
      .split('\n')
      .filter(line => line !== '')
  }

  /** Waits until no process on the record of `command` is left. */
  async function ended(command: string): Promise<void> {
    const pids = onRecord(command).map(line => line.split(' ')[0])
    const deadline = Date.now() + 20000
    while (pids.some(pid => existsSync(`/proc/${pid}`))) {
      if (Date.now() > deadline) throw new Error('the sandbox never ended')
      await sleep(25)
    }
  }

  /**
   * Waits to be told, then tries the denied write the hard way: a mount point
   * that was removed and made again is an empty file without a write bit, which
   * refuses a plain write by its mode alone, so the file is removed first. Only
   * a bind still in place refuses that.
   */
  function heldCommandThatRemovesFirst(): string {
    return `echo up > ${SIGNAL}; while [ ! -e ${GO} ]; do sleep 0.05; done; rm -f ${LOCK}; echo pwned > ${LOCK}; echo rc=$?`
  }

  it.if(BWRAP_CAN_NAMESPACE)(
    'a sandbox that starts while a clean-up is about to claim its manifest keeps its manifest and its deny',
    async () => {
      // The interleaving made certain: the clean-up has read the manifest as
      // finished, the command's sandbox then starts and binds over its mount
      // point, and only then does the clean-up claim the manifest.
      const command = await wrap(heldCommandThatRemovesFirst())
      const manifest = manifestOf(command)
      let inode: number | undefined
      const pass = atTheClaimOn(manifest, {
        before: () => {
          // `{ ...; true; }` keeps a shell as bubblewrap's parent.
          spawnSync('sh', ['-c', `{ ${command}; true; } > ${OUT} 2>&1 &`], {
            stdio: 'ignore',
          })
          const deadline = Date.now() + 20000
          while (!existsSync(SIGNAL)) {
            if (Date.now() > deadline) throw new Error('sandbox never came up')
            Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 5)
          }
          inode = lstatSync(LOCK).ino
        },
      })
      try {
        // The one clean-up this wrap is owed, made too early: the command is
        // taken for over, and nothing but a process on its record can speak
        // for its manifest.
        cleanupBwrapMountPoints()
      } finally {
        pass.restore()
      }
      expect(inode).toBeDefined()
      // The claim was given back, and what the sandbox is bound over is what
      // it was bound over.
      expect(readdirSync(dirname(manifest)).sort()).toEqual([
        basename(manifest),
        basename(manifest).replace(/json$/, 'started'),
      ])
      expect(lstatSync(LOCK).ino).toBe(inode!)

      // A later command in the same repository names the same mount point.
      const third = await wrap('true')
      expect(spawnSync(third, { shell: true, timeout: 60000 }).status).toBe(0)
      cleanupBwrapMountPoints() // after the third
      expect(lstatSync(LOCK).ino).toBe(inode!)

      writeFileSync(GO, '')
      const deadline = Date.now() + 20000
      while (!/rc=\d/.test(contentAt(OUT))) {
        if (Date.now() > deadline) throw new Error('the command never finished')
        await sleep(25)
      }
      expect(contentAt(OUT)).toMatch(/rc=[1-9]/)
      expect(contentAt(LOCK)).toBe('')
      expect(lstatSync(LOCK).ino).toBe(inode!)

      // Not left running for the next test to find on record.
      await ended(command)
      cleanupBwrapMountPoints()
      expect(readdirSync(dirname(manifest))).toEqual([])
    },
    90000,
  )

  it.if(BWRAP_CAN_NAMESPACE)(
    'a command started once a clean-up has claimed its manifest is refused, and nothing is removed or made under it',
    async () => {
      const command = await wrap(`echo pwned > ${LOCK}; echo rc=$?`)
      let refused: { status: number | null; said: string } | undefined
      const pass = atTheClaimOn(manifestOf(command), {
        after: () => {
          const run = spawnSync(command, {
            shell: true,
            encoding: 'utf8',
            timeout: 60000,
          })
          refused = { status: run.status, said: `${run.stdout}${run.stderr}` }
        },
      })
      try {
        cleanupBwrapMountPoints() // too early, and the command starts under it
      } finally {
        pass.restore()
      }
      expect(refused).toBeDefined()
      expect(refused?.status).not.toBe(0)
      expect(refused?.said).toContain("Can't find source path")
      expect(refused?.said).not.toContain('rc=')
      expect(existsSync(LOCK)).toBe(false)
      expect(readdirSync(dirname(manifestOf(command)))).toEqual([])
    },
    90000,
  )

  // ---- which command a clean-up is for ----
  //
  // A command that ran is judged by its record alone: any clean-up collects it
  // once it has ended. Of one that never started, only the caller can say that
  // it is over, so these commands never start. What each holds on to is a mount
  // point a killed process left, which the wrap covers and names.

  function leftByAKilledProcess(mountPoint: string): void {
    writeFileSync(mountPoint, '')
    chmodSync(mountPoint, 0o444)
    manifestNaming([mountPoint])
  }

  it('with the id its wrap was given, a command that never started lets go of its mount point at once, while others are outstanding', async () => {
    const lockOfFirst = join(AREA, 'repo', '.git', 'first.lock')
    leftByAKilledProcess(lockOfFirst)
    const wrapAs = (commandId: string, deny: string) =>
      wrapCommandWithSandboxLinux({
        command: 'true',
        commandId,
        needsNetworkRestriction: false,
        readConfig: { denyOnly: [] },
        writeConfig: { allowOnly: [AREA], denyWithinAllow: [deny] },
      })
    const first = await wrapAs('first-0123456789abcdef', lockOfFirst)
    const others = [
      await wrapAs('second-0123456789abcdef', LOCK),
      await wrapAs('third-0123456789abcdef', LOCK),
    ]

    // The control: a call that does not say which command it is for releases
    // nothing this process made.
    cleanupBwrapMountPoints()
    expect(existsSync(lockOfFirst)).toBe(true)
    expect(existsSync(manifestOf(first))).toBe(true)

    cleanupBwrapMountPoints({ commandId: 'first-0123456789abcdef' })
    expect(existsSync(lockOfFirst)).toBe(false)
    expect(existsSync(manifestOf(first))).toBe(false)
    for (const other of others) {
      expect(existsSync(manifestOf(other))).toBe(true)
    }
  })

  it.if(BWRAP_CAN_NAMESPACE)(
    'lets go of it the same way through the public clean-up, and the others can still start',
    async () => {
      const lockOfFirst = join(AREA, 'repo', '.git', 'first.lock')
      leftByAKilledProcess(lockOfFirst)
      const config = (deny: string) => ({
        filesystem: { denyRead: [], allowWrite: [AREA], denyWrite: [deny] },
      })
      await SandboxManager.initialize({
        network: { allowedDomains: [], deniedDomains: [] },
        ...config(lockOfFirst),
      })
      try {
        const wrapAs = (commandId: string, deny: string) =>
          SandboxManager.wrapWithSandbox(
            'true',
            undefined,
            config(deny),
            undefined,
            { commandId },
          )
        const first = await wrapAs('first-0123456789abcdef', lockOfFirst)
        const second = await wrapAs('second-0123456789abcdef', LOCK)
        await wrapAs('third-0123456789abcdef', LOCK)

        SandboxManager.cleanupAfterCommand()
        expect(existsSync(lockOfFirst)).toBe(true)

        SandboxManager.cleanupAfterCommand({
          commandId: 'first-0123456789abcdef',
        })
        expect(existsSync(lockOfFirst)).toBe(false)
        expect(existsSync(manifestOf(first))).toBe(false)
        expect(spawnSync(second, { shell: true, timeout: 60000 }).status).toBe(
          0,
        )
      } finally {
        await SandboxManager.reset()
      }
    },
    90000,
  )

  it('a wrap that produced no command is not waited for by the clean-up after the next', async () => {
    // It gave its count back when it threw, so one clean-up is all that is owed.
    const thrown: unknown = await wrapCommandWithSandboxLinux({
      command: 'true',
      binShell: 'srt-no-such-shell',
      needsNetworkRestriction: false,
      readConfig: { denyOnly: [] },
      writeConfig: { allowOnly: [AREA], denyWithinAllow: [LOCK] },
    }).catch((error: unknown) => error)
    expect(String(thrown)).toContain('srt-no-such-shell')

    leftByAKilledProcess(LOCK)
    const command = await wrap('true')
    cleanupBwrapMountPoints()
    expect(existsSync(LOCK)).toBe(false)
    expect(existsSync(manifestOf(command))).toBe(false)
  })

  it('a clean-up too many, with nothing outstanding, is not held against the next wrap', async () => {
    cleanupBwrapMountPoints()
    cleanupBwrapMountPoints()

    leftByAKilledProcess(LOCK)
    const command = await wrap('true')
    cleanupBwrapMountPoints()
    expect(existsSync(LOCK)).toBe(false)
    expect(existsSync(manifestOf(command))).toBe(false)
  })

  // ---- what a wrap cannot tell, it does not guess ----

  /** What the wrap was refused with. */
  async function refusal(wrapping: Promise<string>): Promise<unknown> {
    const thrown: unknown = await wrapping.then(
      () => 'the wrap resolved',
      (error: unknown) => error,
    )
    expect(thrown).toBeInstanceOf(LinuxSandboxProfileError)
    return (thrown as LinuxSandboxProfileError).code
  }

  it("refuses to wrap when it cannot read another sandbox's manifest", async () => {
    // Taken for the caller's own, the file would be bound onto itself and named
    // nowhere, and would go from under this sandbox with the one that made it.
    writeFileSync(LOCK, '')
    chmodSync(LOCK, 0o444)
    const theirs = manifestNaming([LOCK], process.pid)
    // However old it is: what this process is short of says nothing of the file.
    const hoursAgo = new Date(Date.now() - 2 * 3600 * 1000)
    utimesSync(theirs, hoursAgo, hoursAgo)
    const open = fs.openSync
    const spy = spyOn(fs, 'openSync').mockImplementation(((
      file: unknown,
      ...rest: unknown[]
    ) => {
      if (file === theirs) {
        throw Object.assign(new Error('EMFILE'), { code: 'EMFILE' })
      }
      return (open as (...args: unknown[]) => number)(file, ...rest)
    }) as never)
    try {
      const wrapping = wrap('true')
      expect(await refusal(wrapping)).toBe('mount_points_unreadable')
      // It refuses every wrap while it lasts, so it says which file and why.
      const said = (await wrapping.catch((e: unknown) => e)) as Error
      for (const where of [said.message, said.cause]) {
        expect(where).toContain(theirs)
        expect(where).toContain('EMFILE')
      }
      cleanupBwrapMountPoints({ force: true })
      expect(existsSync(LOCK)).toBe(true)
    } finally {
      spy.mockRestore()
    }
    expect(readdirSync(dirname(theirs))).toEqual([basename(theirs)])
    expect(await wrap('true')).toContain(`--ro-bind /dev/null ${LOCK}`)
  })

  it('plans again, and does not call the manifests unreadable, when they keep moving while it reads them', async () => {
    // Other processes are busy, in whatever project: listed, and gone when
    // opened, is what a manifest claimed, given back or collected looks like.
    writeFileSync(LOCK, '')
    const theirs = manifestNaming([LOCK], process.pid)
    const open = fs.openSync
    let [opens, elusiveFor] = [0, Infinity]
    const spy = spyOn(fs, 'openSync').mockImplementation(((
      file: unknown,
      ...rest: unknown[]
    ) => {
      if (file === theirs && opens++ < elusiveFor) {
        throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' })
      }
      return (open as (...args: unknown[]) => number)(file, ...rest)
    }) as never)
    try {
      expect(await refusal(wrap('true'))).toBe('mount_points_changed')
      expect(readdirSync(dirname(theirs))).toEqual([basename(theirs)])
      const inOnePlan = opens / 3
      // Which planning again does not mend where something else is amiss too.
      const junk = join(dirname(theirs), '4242-00.json')
      writeFileSync(junk, 'no manifest')
      expect(await refusal(wrap('true'))).toBe('mount_points_unreadable')
      rmSync(junk)
      ;[opens, elusiveFor] = [0, inOnePlan]
      expect(await wrap('true')).toContain(`--ro-bind /dev/null ${LOCK}`)
    } finally {
      spy.mockRestore()
    }
  })

  it('is not asked of a wrap that restricts no write, which has no mount point', async () => {
    mkdirSync(runtime.manifestDir(), { recursive: true, mode: 0o700 })
    writeFileSync(join(runtime.manifestDir(), '4242-00.json'), 'no manifest')
    expect(await refusal(wrap('true'))).toBe('mount_points_unreadable')
    expect(
      await wrapCommandWithSandboxLinux({
        command: 'true',
        needsNetworkRestriction: false,
        readConfig: { denyOnly: [AREA] },
        writeConfig: undefined,
      }),
    ).toContain(`--tmpfs ${AREA}`)
  })

  it('refuses to wrap what needs a manifest larger than can be read, and publishes none', async () => {
    const many = Array.from({ length: 4000 }, (_, i) =>
      join(AREA, `${'x'.repeat(240)}-${i}`),
    )
    expect(await refusal(wrap('true', many))).toBe('too_many_mount_points')
    expect(readdirSync(runtime.manifestDir())).toEqual([])
  }, 30000)

  it("takes a path a live manifest names for the caller's own file once something has been written to it", async () => {
    // Live: written by this process, which has not let go of it. A file with
    // content is nothing bubblewrap made, and /dev/null over it would hide it
    // from the command it belongs to.
    const first = await wrap('true')
    expect(first).toContain(`--ro-bind /dev/null ${LOCK}`)
    writeFileSync(LOCK, 'somebody wrote this\n')
    const second = await wrap('true')
    expect(second).not.toContain(`--ro-bind /dev/null ${LOCK}`)
    expect(second).toContain(`--ro-bind ${LOCK} ${LOCK}`)
    // Nor does the second wrap name it: it is not its to remove.
    expect(recordedBy(second)).toBeUndefined()
  })

  it('takes for a mount point one that another sandbox makes while the wrap is looking at the path', async () => {
    // Absent when the wrap asked for its shape, there when it asked whether
    // anything is: another sandbox started on the same path in between.
    const exists = fs.existsSync
    let made = false
    const spy = spyOn(fs, 'existsSync').mockImplementation(((file: unknown) => {
      if (file === LOCK && !made) {
        made = true
        expect(exists(LOCK)).toBe(false)
        manifestNaming([LOCK], process.pid)
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

  it("is named by a wrap that took it for the caller's own file, another sandbox having made it again meanwhile", async () => {
    // No manifest named it when the wrap read them: the one that had was
    // collected. Not named, it would go with the sandbox that made it again.
    writeFileSync(LOCK, '')
    const exists = fs.existsSync
    let theirs: string | undefined
    const spy = spyOn(fs, 'existsSync').mockImplementation(((file: unknown) => {
      if (file === LOCK) theirs ??= manifestNaming([LOCK], process.pid)
      return exists(file as string)
    }) as never)
    let command: string
    try {
      command = await wrap('true')
    } finally {
      spy.mockRestore()
    }
    expect(theirs).toBeDefined()
    expect(command).toContain(`--ro-bind ${LOCK} ${LOCK}`)
    expect(readFileSync(manifestOf(command), 'utf8')).toContain(LOCK)
  })

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
      expect(recordedBy(nothingToRecord.wrapped)).toBeUndefined()
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

  it.if(BWRAP_CAN_NAMESPACE && process.getuid?.() !== 0)(
    'is removed by the process that made it, at its clean-up or as it ends, where it could be recorded nowhere',
    async () => {
      // No runtime directory, and nothing can be made under the temp dir: no
      // other process can know of the mount point.
      const TMP = join(BASE, 'read-only-tmp')
      mkdirSync(TMP, { mode: 0o500 })
      const env: Record<string, string | undefined> = {
        ...process.env,
        TMPDIR: TMP,
      }
      delete env.XDG_RUNTIME_DIR
      const inThatPlace = (script: string, after: string) =>
        spawnSync(
          process.execPath,
          [
            writeScript(
              script,
              [
                `import { spawnSync } from 'node:child_process'`,
                `import { existsSync } from 'node:fs'`,
                `import { wrapCommandWithSandboxLinux, cleanupBwrapMountPoints } from ${LIBRARY}`,
                `const wrapped = await wrapCommandWithSandboxLinux({`,
                `  command: ${JSON.stringify(`echo pwned > ${LOCK}; echo rc=$?`)},`,
                `  needsNetworkRestriction: false,`,
                `  readConfig: { denyOnly: [] },`,
                `  writeConfig: { allowOnly: [${JSON.stringify(AREA)}], denyWithinAllow: [${JSON.stringify(LOCK)}] },`,
                `})`,
                `const r = spawnSync(wrapped, { shell: true, encoding: 'utf8', timeout: 60000 })`,
                `const made = existsSync(${JSON.stringify(LOCK)})`,
                after,
                `console.log(JSON.stringify({ wrapped, said: String(r.stdout ?? '') + String(r.stderr ?? ''), made, left: existsSync(${JSON.stringify(LOCK)}) }))`,
              ].join('\n'),
            ),
          ],
          {
            env: env as Record<string, string>,
            encoding: 'utf8',
            timeout: 60000,
            // Outside every allowed write path, so no mount points for cwd.
            cwd: import.meta.dir,
          },
        )
      for (const [script, after, left] of [
        ['cleans-up.ts', 'cleanupBwrapMountPoints()', false],
        ['only-ends.ts', '', true],
      ] as const) {
        const ran = JSON.parse(inThatPlace(script, after).stdout) as {
          wrapped: string
          said: string
          made: boolean
          left: boolean
        }
        expect(recordedBy(ran.wrapped)).toBeUndefined()
        expect(ran.wrapped).toStartWith(`${BWRAP} `)
        expect(ran.said).toMatch(/rc=[1-9]/)
        expect(ran).toMatchObject({ made: true, left })
        expect(existsSync(LOCK)).toBe(false)
      }
    },
    90000,
  )

  it('lets go of the mount points of a wrap that produced no command', async () => {
    // Left where a process killed before its cleanup would leave it, with the
    // manifest it would leave, so that both processes below name it.
    writeFileSync(LOCK, '')
    chmodSync(LOCK, 0o444)
    manifestNaming([LOCK])

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
            // Stays alive: a manifest of a running process counts as live, so
            // only letting go of it lets the mount point be collected here.
            `await new Promise(resolve => setTimeout(resolve, 30000))`,
          ].join('\n'),
        ),
      ],
      { stdio: 'ignore' },
    )
    try {
      await waitFor(OUT)
      expect(readFileSync(OUT, 'utf8')).toBe('threw')
      // This process names the same mount point and asks for the cleanup. A
      // wrap that threw must not have held on to its manifest.
      await wrap('true')
      cleanupBwrapMountPoints()
      expect(wrapper.exitCode).toBe(null)
      expect(existsSync(LOCK)).toBe(false)
    } finally {
      wrapper.kill()
    }
  }, 90000)
})

/**
 * The process that wrapped the command is gone and the sandbox it started is
 * still running: nothing but the process on the manifest's record keeps the
 * mount point.
 *
 * The wrap always asks for --die-with-parent, so a sandbox outlives its wrapper
 * only when something else is bubblewrap's parent: here a shell in a session of
 * its own, as under a job runner, a terminal multiplexer or `nohup sh -c`.
 */
describe.if(isLinux)(
  'A mount point whose sandbox outlives the process that wrapped it',
  () => {
    usePrivateManifestDirectory()
    const BWRAP_CAN_NAMESPACE = bwrapCanNamespace()
    const LIBRARY = JSON.stringify(
      join(import.meta.dir, '../../src/sandbox/linux-sandbox-utils.ts'),
    )
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
     * Says it is up, waits to be told, tries the denied write, reports the
     * result, and then stays: the sandbox is still running when it is killed.
     */
    function heldCommand(): string {
      return `echo up > ${SIGNAL}; while [ ! -e ${GO} ]; do sleep 0.05; done; rm -f ${LOCK}; echo pwned > ${LOCK}; echo rc=$? > ${RESULT}; sleep 600`
    }

    /**
     * A process that wraps the held command, starts it under a shell in a
     * session of its own, waits for the sandbox to be up and then goes: `leave`
     * is how.
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
        env: { ...process.env },
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
     * premise: that process is gone, its sandbox is running, and its manifest
     * is past the grace.
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
      // Past its grace, or the grace is what keeps the manifest live and not
      // the process on its record.
      const manifest = recordedBy(info.wrapped)
      expect(manifest).toBeDefined()
      const { created } = JSON.parse(readFileSync(manifest!, 'utf8')) as {
        created: number
      }
      await waitFor(
        'the manifest to be past its grace',
        () => Date.now() - created > 750,
      )
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
      // Its exit handler runs the cleanup with `force`: a sandbox still running
      // under a manifest is not the process's to end.
      ['exits, running its exit-time cleanup', `process.exit(0)`, null],
    ]

    for (const [how, leave, signal] of ways) {
      it.if(BWRAP_CAN_NAMESPACE)(
        `stays, and the deny holds, while other processes collect after its writer ${how}; goes once the sandbox is gone`,
        async () => {
          const info = await sandboxWhoseWriterHasGone(leave, signal)
          const manifest = recordedBy(info.wrapped)
          expect(manifest).toBeDefined()
          // Still naming the deny path, and the process that is gone.
          const written = JSON.parse(readFileSync(manifest!, 'utf8')) as {
            pid: number
            paths: string[]
          }
          expect(written.pid).toBe(info.writer)
          expect(written.paths).toContain(LOCK)

          // Whether the mount point and the manifest that names it are still
          // there after each thing that might have taken them. Checked together
          // further down, so a failure says all of what happened.
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

          expect(runScript('collector.ts', collectorScript())).toBe(0)
          look('after a process that wrapped nothing collected')
          expect(runScript('second.ts', secondWrapperScript())).toBe(0)
          look('after a process that denies the same path ran and cleaned up')
          cleanupBwrapMountPoints()
          cleanupBwrapMountPoints({ force: true })
          look('after this process collected, twice')

          // The sandbox is still there. Its denied write must fail inside, and
          // nothing may land on the host. (A mount point removed and made again
          // by the second wrap is on the host but is no longer what this
          // sandbox is bound over: the command removes the file before it
          // writes, which only a bind still in place refuses.)
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

          // Kill the sandbox. The next collect by anyone removes the mount
          // point and the manifest.
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
        // A collector that never has a candidate proves nothing. Here the
        // writer is gone and the grace is over before the write is tried, so
        // the process on record is all that stands between the collector and
        // the mount point.
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
 * an empty directory. On the host it looks like anyone's, so only a manifest
 * says what it is.
 */
describe.if(isLinux)(
  'A directory mount point a running sandbox relies on',
  () => {
    const runtime = usePrivateManifestDirectory()
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
        // A live manifest names it. /dev/null cannot be bound over a directory:
        // bubblewrap would refuse to start.
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
        // No second process: a manifest is live while the process that wrote it
        // has not let go of it. A deny list naming a missing directory and
        // something beneath it makes the directory the mount point, and the
        // same list again finds it named by a live manifest.
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
        // Bound onto itself and not named, it would go with the sandbox that
        // made it, and the denied directory could be made again inside the
        // second sandbox.
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

    // ---- left by a process that was killed ----
    //
    // Its manifest is finished, not live. The next clean-up in any process
    // removes the directory on that manifest's word, so a wrap that denies the
    // directory in the meantime has to name it for itself.

    /** What a process killed a minute ago left in the manifest directory. */
    function manifestOfAKilledProcess(paths: string[]): string {
      const dir = runtime.manifestDir()
      mkdirSync(dir, { recursive: true, mode: 0o700 })
      chmodSync(dir, 0o700)
      let pid = 4194000
      while (existsSync(`/proc/${pid}`)) pid--
      const file = join(dir, `${pid}-0123456789abcdef.json`)
      writeFileSync(
        file,
        JSON.stringify({
          version: 1,
          pid,
          start: '1',
          ns: readlinkSync('/proc/self/ns/pid'),
          created: Date.now() - 60_000,
          paths,
          sources: [],
        }),
        { mode: 0o600 },
      )
      return file
    }

    /** The mount points the wrap named in its manifest, none without one. */
    function namedBy(command: string): string[] {
      const file = recordedBy(command)
      return file === undefined
        ? []
        : (JSON.parse(readFileSync(file, 'utf8')) as { paths: string[] }).paths
    }

    it('is named by a wrap that denies it, and stays until that wrap is cleaned up after', async () => {
      mkdirSync(DIRECTORY)
      const left = manifestOfAKilledProcess([DIRECTORY])

      // The directory itself, beside something beneath it, which needs no mount
      // point of its own under a read-only directory.
      const command = await wrap('true', [DIRECTORY, LEAF])
      expect(command).toContain(`--ro-bind ${DIRECTORY} ${DIRECTORY}`)
      expect(command).not.toContain(LEAF)
      expect(namedBy(command)).toEqual([DIRECTORY])

      // A second command of this process and the clean-up after it: the first
      // is still outstanding, so nothing of this process's is released, and
      // what the killed process left is collected.
      await wrap('true', [])
      cleanupBwrapMountPoints()
      expect(existsSync(left)).toBe(false)
      expect(existsSync(DIRECTORY)).toBe(true)

      // And it goes like any other mount point, once nothing relies on it.
      cleanupBwrapMountPoints()
      expect(existsSync(DIRECTORY)).toBe(false)
    })

    // ---- relied on, not denied: what a second wrap nests under it ----
    //
    // The second wrap finds the directory there, so its own mount point is made
    // inside it and its pin is on it. It has to name the directory too, or that
    // goes with the sandbox it was made for.

    it('is named by a wrap whose own mount point is made in it, and kept for that wrap', async () => {
      mkdirSync(DIRECTORY)
      const left = manifestOfAKilledProcess([DIRECTORY])

      const command = await wrap('true', [LEAF])
      expect(command).toContain(`--ro-bind /dev/null ${LEAF}`)
      expect(countMounts(command, '--ro-bind', DIRECTORY, DIRECTORY)).toBe(1)
      expect(namedBy(command).sort()).toEqual([DIRECTORY, LEAF].sort())

      // What the killed process left is collected; the directory stays.
      await wrap('true', [])
      cleanupBwrapMountPoints()
      expect(existsSync(left)).toBe(false)
      expect(existsSync(DIRECTORY)).toBe(true)

      cleanupBwrapMountPoints()
      expect(existsSync(DIRECTORY)).toBe(false)
    })

    it.if(BWRAP_CAN_NAMESPACE)(
      'is still there for a second command of this process, wrapped before and started after the clean-up for the first',
      async () => {
        const first = await wrap('echo first', [LEAF])
        expect(run(first).stdout).toBe('first\n')
        expect(lstatSync(DIRECTORY).isDirectory()).toBe(true)
        const second = await wrap('echo second', [LEAF])
        expect(namedBy(second)).toContain(DIRECTORY)

        cleanupBwrapMountPoints() // for the first, which has ended
        expect(existsSync(DIRECTORY)).toBe(true)
        expect(run(second)).toMatchObject({ status: 0, said: 'second\n' })

        cleanupBwrapMountPoints()
        expect(readdirSync(join(AREA, 'proj'))).toEqual([])
        expect(readdirSync(runtime.manifestDir())).toEqual([])
      },
      90000,
    )

    it.if(BWRAP_CAN_NAMESPACE)(
      'keeps its pin in a sandbox that is starting when the sandbox it was made for is cleaned up after',
      async () => {
        // bubblewrap is held up after its pins and before it makes the mount
        // point inside the directory: `--file` copies from a FIFO nobody has
        // closed. Removed then, the directory would be made again, unpinned.
        expect(run(await wrap('true', [LEAF])).status).toBe(0)
        const inode = lstatSync(DIRECTORY).ino
        const mountsAt = (p: string): string =>
          `$(grep -c ' ${p} ' /proc/self/mountinfo)`
        const second = await wrap(
          `echo "${mountsAt(DIRECTORY)} ${mountsAt(LEAF)}"`,
          [LEAF],
        )
        const placeholder = `--ro-bind /dev/null ${LEAF}`
        expect(second.split(placeholder)).toHaveLength(2)
        const fifo = join(BASE, 'fifo')
        const gate = join(AREA, 'gate')
        expect(spawnSync('mkfifo', [fifo]).status).toBe(0)
        const hold = fs.openSync(fifo, fs.constants.O_RDWR)
        const child = spawn(
          `${second.replace(placeholder, `--file 8 ${gate} ${placeholder}`)} 8<${fifo}`,
          { shell: true },
        )
        let said = ''
        child.stdout.on('data', chunk => (said += String(chunk)))
        child.stderr.on('data', chunk => (said += String(chunk)))
        const exited = new Promise(resolve => child.on('exit', resolve))
        try {
          await waitFor(gate)
          cleanupBwrapMountPoints() // for the first, which has ended
          expect(lstatSync(DIRECTORY).ino).toBe(inode)
        } finally {
          fs.closeSync(hold)
        }
        expect(await exited).toBe(0)
        // One mount at the directory, its pin, and one at what is denied in it.
        expect(said).toBe('1 1\n')
        expect(lstatSync(DIRECTORY).ino).toBe(inode)

        cleanupBwrapMountPoints()
        expect(readdirSync(join(AREA, 'proj'))).toEqual([])
      },
      90000,
    )

    it.if(BWRAP_CAN_NAMESPACE)(
      'covers all that is denied in it, though another sandbox makes it while the wrap goes from one deny to the next',
      async () => {
        // Absent for the first deny and there for the second, it would be
        // planned as an empty read-only directory and, inside that, a mount
        // point bubblewrap cannot make.
        const OTHER = join(DIRECTORY, 'agents')
        const first = await wrap('true', [LEAF, OTHER])
        const lstat = fs.lstatSync
        let ran = false
        const spy = spyOn(fs, 'lstatSync').mockImplementation(((
          file: unknown,
          ...rest: unknown[]
        ) => {
          // The first deny is judged: the wrap looks at what it will bind from.
          if (String(file).includes('claude-empty-') && !ran) {
            ran = true
            expect(run(first).status).toBe(0)
            expect(existsSync(DIRECTORY)).toBe(true)
          }
          return (lstat as (...args: unknown[]) => unknown)(file, ...rest)
        }) as never)
        let second: string
        try {
          second = await wrap(`touch ${LEAF} ${OTHER}; echo rc=$?`, [
            LEAF,
            OTHER,
          ])
        } finally {
          spy.mockRestore()
        }
        expect(ran).toBe(true)
        expect(namedBy(second)).toEqual([DIRECTORY])
        expect(run(second)).toMatchObject({ status: 0, stdout: 'rc=1\n' })

        cleanupBwrapMountPoints()
        cleanupBwrapMountPoints()
        expect(readdirSync(join(AREA, 'proj'))).toEqual([])
      },
      90000,
    )

    /** Runs `then` each time the wrap is about to publish a manifest. */
    function atEachPublish(then: () => void): { restore(): void } {
      const write = fs.writeFileSync
      const spy = spyOn(fs, 'writeFileSync').mockImplementation(((
        file: unknown,
        ...rest: unknown[]
      ) => {
        if (String(file).endsWith('.json.tmp')) then()
        return (write as (...args: unknown[]) => void)(file, ...rest)
      }) as never)
      return { restore: () => spy.mockRestore() }
    }

    /**
     * Runs `then` when the wrap has decided where its mount points go and has
     * yet to pin what lies above them: as it makes sure of the manifest
     * directories.
     */
    function beforeThePins(then: () => void): { restore(): void } {
      const mkdir = fs.mkdirSync
      const spy = spyOn(fs, 'mkdirSync').mockImplementation(((
        dir: unknown,
        ...rest: unknown[]
      ) => {
        if (dir === runtime.manifestDir()) then()
        return (mkdir as (...args: unknown[]) => unknown)(dir, ...rest)
      }) as never)
      return { restore: () => spy.mockRestore() }
    }

    for (const [when, early] of [
      ['by the time its manifest is published', false],
      ['between its decision to nest in it and the pin', true],
    ] as const) {
      it(`plans again when the directory has gone ${when}`, async () => {
        // Until it has published nothing of this wrap's names it, and a clean-up
        // in another process takes it away with the sandbox it was made for.
        // That pass spares the file, which the new manifest names by then, and
        // drops the manifest it was collecting.
        const spared = join(AREA, 'proj', '.bashrc')
        writeFileSync(spared, '')
        mkdirSync(DIRECTORY)
        const left = manifestOfAKilledProcess([spared, DIRECTORY])
        const goes = (now: boolean): void => {
          if (now && existsSync(left)) {
            fs.rmdirSync(DIRECTORY)
            rmSync(left)
          }
        }
        let published = 0
        const publishing = atEachPublish(() =>
          goes(published++ === 0 && !early),
        )
        const pinning = beforeThePins(() => goes(early))
        let command: string
        try {
          command = await wrap('true', [spared, LEAF])
        } finally {
          pinning.restore()
          publishing.restore()
        }
        // The plan that was handed out found it absent, and covers it itself.
        expect(published).toBe(2)
        expect(command).not.toContain(`--ro-bind /dev/null ${LEAF}`)
        expect(command).toMatch(
          new RegExp(`--ro-bind \\S+/claude-empty-\\S+ ${DIRECTORY} `),
        )
        // Nothing is left of the plan it gave up, nor of what only that named:
        // found there, the file would be the caller's own from now on.
        expect(command).toContain(`--ro-bind /dev/null ${spared}`)
        expect(namedBy(command).sort()).toEqual([spared, DIRECTORY].sort())
        expect(readdirSync(join(AREA, 'proj'))).toEqual([])
        expect(readdirSync(runtime.manifestDir())).toEqual([
          basename(recordedBy(command)!),
        ])
      })
    }

    for (const [what, meanwhile, names] of [
      [
        'a directory it mounts a tmpfs on has gone',
        () => fs.rmdirSync(join(AREA, 'hidden')),
        () => [LEAF],
      ],
      [
        // Of a sandbox that has ended: the directory goes with the plan.
        'a manifest has come that names the directory it nests in',
        () => manifestOfAKilledProcess([DIRECTORY]),
        () => [DIRECTORY],
      ],
    ] as const) {
      it(`plans again when ${what} by the time its manifest is published`, async () => {
        mkdirSync(DIRECTORY)
        mkdirSync(join(AREA, 'hidden'))
        let published = 0
        const publishing = atEachPublish(() => {
          if (published++ === 0) meanwhile()
        })
        let command: string
        try {
          command = await wrapCommandWithSandboxLinux({
            command: 'true',
            needsNetworkRestriction: false,
            readConfig: { denyOnly: [join(AREA, 'hidden')] },
            writeConfig: { allowOnly: [AREA], denyWithinAllow: [LEAF] },
          })
        } finally {
          publishing.restore()
        }
        expect(published).toBe(2)
        expect(namedBy(command)).toEqual(names())
      })
    }

    it('takes what it cannot look at again for there', async () => {
      // bubblewrap does not start on what it cannot bind.
      let published = 0
      const publishing = atEachPublish(() => published++)
      const stat = fs.statSync
      const spy = spyOn(fs, 'statSync').mockImplementation(((
        file: unknown,
        ...rest: unknown[]
      ) => {
        if (file === AREA && published > 0) {
          throw Object.assign(new Error('EACCES'), { code: 'EACCES' })
        }
        return (stat as (...args: unknown[]) => unknown)(file, ...rest)
      }) as never)
      try {
        await wrap('true', [LEAF])
      } finally {
        spy.mockRestore()
        publishing.restore()
      }
      expect(published).toBe(1)
    })

    it('plans again when its manifest went to a directory settled on since the pins', async () => {
      // Nothing is pinned above that one. Both shared names are taken as the
      // wrap reads the manifests, so it publishes in a directory of its own.
      const shared = [
        runtime.manifestDir(),
        join(tmpdir(), `srt-mount-points-${process.getuid!()}`),
      ]
      const readdir = fs.readdirSync
      const spy = spyOn(fs, 'readdirSync').mockImplementation(((
        dir: unknown,
        ...rest: unknown[]
      ) => {
        const names = (readdir as (...args: unknown[]) => unknown)(dir, ...rest)
        if (dir === shared[0]) {
          for (const name of shared) {
            fs.rmdirSync(name)
            writeFileSync(name, '')
          }
        }
        return names
      }) as never)
      let published = 0
      const publishing = atEachPublish(() => published++)
      try {
        const command = await wrap('true', [LEAF])
        expect(published).toBe(2)
        const own = dirname(recordedBy(command)!)
        expect(shared).not.toContain(own)
        expect(countMounts(command, '--ro-bind', own, own)).toBe(1)
        expect(readdirSync(own)).toEqual([basename(recordedBy(command)!)])
      } finally {
        publishing.restore()
        spy.mockRestore()
        shared.forEach(name => rmSync(name))
      }
    })

    it('is let go of when a process exits whose wrap made no mount point of its own', () => {
      mkdirSync(DIRECTORY)
      manifestOfAKilledProcess([DIRECTORY])
      const file = join(BASE, 'exits.ts')
      writeFileSync(
        file,
        [
          `import { wrapCommandWithSandboxLinux } from ${LIBRARY}`,
          `await wrapCommandWithSandboxLinux({`,
          `  command: 'true',`,
          `  needsNetworkRestriction: false,`,
          `  readConfig: { denyOnly: [] },`,
          `  writeConfig: { allowOnly: [${JSON.stringify(AREA)}], denyWithinAllow: [${JSON.stringify(DIRECTORY)}] },`,
          `})`,
        ].join('\n'),
      )
      const exited = spawnSync(process.execPath, [file], {
        env: { ...process.env },
        timeout: 60000,
        cwd: import.meta.dir,
      })
      expect(exited.status).toBe(0)
      expect(readdirSync(runtime.manifestDir())).toEqual([])
      expect(existsSync(DIRECTORY)).toBe(false)
    }, 90000)

    const emptySources = (): string[] =>
      readdirSync(tmpdir())
        .filter(name => name.startsWith('claude-empty-'))
        .map(name => join(tmpdir(), name))

    it('leaves nothing behind when it throws, having published or not', async () => {
      const thrown: unknown = await wrapCommandWithSandboxLinux({
        command: 'true',
        binShell: 'srt-no-such-shell',
        needsNetworkRestriction: false,
        readConfig: { denyOnly: [] },
        writeConfig: { allowOnly: [AREA], denyWithinAllow: [LEAF] },
      }).catch((error: unknown) => error)
      expect(String(thrown)).toContain('srt-no-such-shell')
      expect(readdirSync(runtime.manifestDir())).toEqual([])
      expect(emptySources()).toEqual([])

      // Before it publishes: what it made goes once a clean-up can tell.
      const junk = join(runtime.manifestDir(), '4242-00.json')
      writeFileSync(junk, 'no manifest')
      expect(await wrap('true', [LEAF]).catch((e: Error) => e.name)).toBe(
        'LinuxSandboxProfileError',
      )
      expect(emptySources()).toHaveLength(1)
      rmSync(junk)
      cleanupBwrapMountPoints()
      expect(emptySources()).toEqual([])
    })

    it('gives up, with a code of its own and nothing left behind, when that happens to every plan', async () => {
      let published = 0
      const publishing = atEachPublish(() => {
        published++
        // What the mount point is bound from, as a clean-up elsewhere takes it.
        emptySources().forEach(source => fs.rmdirSync(source))
      })
      let refused: unknown
      try {
        refused = await wrap('true', [LEAF]).catch((error: unknown) => error)
      } finally {
        publishing.restore()
      }
      expect(refused).toBeInstanceOf(LinuxSandboxProfileError)
      expect((refused as LinuxSandboxProfileError).code).toBe(
        'mount_points_changed',
      )
      expect(published).toBe(3)
      expect(readdirSync(runtime.manifestDir())).toEqual([])

      // And it is not counted: one clean-up is all the next wrap is owed.
      const command = await wrap('true', [LEAF])
      cleanupBwrapMountPoints()
      expect(existsSync(recordedBy(command)!)).toBe(false)
    })

    it('is named by a wrap that denies it though another sandbox made it after that wrap last read the manifests', async () => {
      // An empty file at an earlier deny path has the manifests read. The
      // directory is made, by a sandbox that published first, as the wrap comes
      // to look at it.
      const earlier = join(AREA, 'proj', 'earlier.lock')
      writeFileSync(earlier, '')
      const exists = fs.existsSync
      let made = false
      const spy = spyOn(fs, 'existsSync').mockImplementation(((
        file: unknown,
      ) => {
        if (file === DIRECTORY && !made) {
          made = true
          manifestOfAKilledProcess([DIRECTORY])
          mkdirSync(DIRECTORY)
        }
        return exists(file as string)
      }) as never)
      let command: string
      try {
        command = await wrap('true', [earlier, DIRECTORY])
      } finally {
        spy.mockRestore()
      }
      expect(made).toBe(true)
      expect(command).toContain(`--ro-bind ${DIRECTORY} ${DIRECTORY}`)
      expect(namedBy(command)).toEqual([DIRECTORY])
    })

    it('is never removed once something has been put into it', async () => {
      mkdirSync(DIRECTORY)
      const left = manifestOfAKilledProcess([DIRECTORY])
      const command = await wrap('true', [DIRECTORY])
      expect(namedBy(command)).toEqual([DIRECTORY])

      writeFileSync(join(DIRECTORY, 'settings.json'), '{}')
      cleanupBwrapMountPoints()
      cleanupBwrapMountPoints()

      expect(readFileSync(join(DIRECTORY, 'settings.json'), 'utf8')).toBe('{}')
      // Nothing names it any more: it is the user's directory from here on.
      expect(existsSync(left)).toBe(false)
      expect(existsSync(recordedBy(command)!)).toBe(false)
      expect(namedBy(await wrap('true', [DIRECTORY]))).toEqual([])
    })

    it('is left alone, by the wrap and by the clean-up, where no manifest names it', async () => {
      // An empty directory looks like anyone's: this one is the user's.
      mkdirSync(DIRECTORY)
      manifestOfAKilledProcess([join(AREA, 'proj', '.vscode')])

      const command = await wrap('true', [DIRECTORY, LEAF])
      expect(command).toContain(`--ro-bind ${DIRECTORY} ${DIRECTORY}`)
      expect(namedBy(command)).toEqual([])

      cleanupBwrapMountPoints()
      expect(existsSync(DIRECTORY)).toBe(true)
    })

    it.if(BWRAP_CAN_NAMESPACE)(
      'stays while a sandbox that denies it runs, with the process that made it killed and another cleaning up',
      async () => {
        // Bound onto itself and not named, it would go at the next clean-up in
        // any process, from under the running sandbox.
        const script = (name: string, lines: string[]): string => {
          const file = join(BASE, name)
          writeFileSync(file, lines.join('\n'))
          return file
        }
        const killed = spawnSync(
          process.execPath,
          [
            script('killed.ts', [
              `import { spawnSync } from 'node:child_process'`,
              `import { wrapCommandWithSandboxLinux } from ${LIBRARY}`,
              `const wrapped = await wrapCommandWithSandboxLinux({`,
              `  command: 'true',`,
              `  needsNetworkRestriction: false,`,
              `  readConfig: { denyOnly: [] },`,
              `  writeConfig: { allowOnly: [${JSON.stringify(AREA)}], denyWithinAllow: [${JSON.stringify(LEAF)}] },`,
              `})`,
              `spawnSync(wrapped, { shell: true, encoding: 'utf8', timeout: 60000 })`,
              `process.kill(process.pid, 'SIGKILL')`,
            ]),
          ],
          {
            env: { ...process.env },
            encoding: 'utf8',
            timeout: 60000,
            cwd: import.meta.dir,
          },
        )
        expect(killed.signal).toBe('SIGKILL')
        // Its sandbox ran, and left what bubblewrap made for it.
        expect(lstatSync(DIRECTORY).isDirectory()).toBe(true)
        expect(readdirSync(DIRECTORY)).toEqual([])
        expect(
          readdirSync(runtime.manifestDir()).filter(name =>
            name.endsWith('.json'),
          ),
        ).toHaveLength(1)
        const up = join(AREA, 'up-second')
        const go = join(AREA, 'go-second')
        let said = ''
        const second = spawn(
          await wrap(
            `echo up > ${up}; while [ ! -e ${go} ]; do sleep 0.05; done; mkdir -p ${LEAF}; echo pwned > ${LEAF}/x.md; echo rc=$?`,
            [DIRECTORY],
          ),
          { shell: true },
        )
        second.stdout.on('data', chunk => (said += String(chunk)))
        second.stderr.on('data', chunk => (said += String(chunk)))
        const secondExited = new Promise(resolve => second.on('exit', resolve))
        try {
          await waitFor(up)
          const collector = spawnSync(
            process.execPath,
            [
              script('collector.ts', [
                `import { cleanupBwrapMountPoints } from ${LIBRARY}`,
                `cleanupBwrapMountPoints()`,
              ]),
            ],
            {
              env: { ...process.env },
              encoding: 'utf8',
              timeout: 60000,
              cwd: import.meta.dir,
            },
          )
          expect(collector.status).toBe(0)
          expect(existsSync(DIRECTORY)).toBe(true)
        } finally {
          writeFileSync(go, '')
          await secondExited
        }
        expect(said).toMatch(/rc=[1-9]/)
        expect(existsSync(join(LEAF, 'x.md'))).toBe(false)

        // And goes once nothing runs under it.
        cleanupBwrapMountPoints()
        expect(existsSync(DIRECTORY)).toBe(false)
      },
      90000,
    )
  },
)

/**
 * The manifest directories, the fake-file store and the empty placeholder
 * source are bound read-only in a sandbox, and what is found at their names is
 * believed on the host. The bind keeps a command out of the directory, not the
 * name leading to it: where the temp dir lies strictly inside a write root the
 * directories between the two are pinned.
 */
describe.if(isLinux)(
  'The directories above the ones this library keeps on the host',
  () => {
    usePrivateManifestDirectory()
    const BWRAP_CAN_NAMESPACE = bwrapCanNamespace()
    const LIBRARY = JSON.stringify(
      join(import.meta.dir, '../../src/sandbox/linux-sandbox-utils.ts'),
    )
    const UID = isLinux ? process.getuid!() : 0
    let BASE: string
    let HOME: string // the allowed write root
    let TMP: string // the temp dir, strictly inside it
    let GUARD: string // a denyWrite path, absent to begin with

    beforeEach(() => {
      BASE = realpathSync(mkdtempSync(join(tmpdir(), 'mount-point-pins-')))
      HOME = join(BASE, 'home')
      TMP = join(HOME, 'tmp')
      mkdirSync(TMP, { recursive: true })
      GUARD = join(HOME, 'guard.lock')
    })

    afterEach(() => {
      cleanupBwrapMountPoints({ force: true })
      rmSync(BASE, { recursive: true, force: true })
    })

    /**
     * Runs `lines` in a process of its own whose temp dir is TMP. An `env`
     * entry that is undefined is removed from its environment.
     */
    function inAChild(
      name: string,
      lines: string[],
      env: Record<string, string | undefined> = {},
    ): { status: number | null; stdout: string } {
      const file = join(BASE, name)
      writeFileSync(file, lines.join('\n'))
      const merged: Record<string, string | undefined> = {
        ...process.env,
        TMPDIR: TMP,
        ...env,
      }
      for (const [key, value] of Object.entries(merged)) {
        if (value === undefined) delete merged[key]
      }
      const r = spawnSync(process.execPath, [file], {
        env: merged as Record<string, string>,
        encoding: 'utf8',
        timeout: 60000,
        // Outside every allowed write path, so no mount points for cwd.
        cwd: import.meta.dir,
      })
      return { status: r.status, stdout: r.stdout }
    }

    /** What a process with that environment wraps `true` as. */
    function wrapped(
      options: Record<string, unknown>,
      env: Record<string, string | undefined> = {},
    ): string {
      const child = inAChild(
        'wrap.ts',
        [
          `import { wrapCommandWithSandboxLinux } from ${LIBRARY}`,
          `console.log(await wrapCommandWithSandboxLinux({`,
          `  command: 'true',`,
          `  needsNetworkRestriction: false,`,
          `  readConfig: { denyOnly: [] },`,
          `  ...${JSON.stringify(options)},`,
          `}))`,
        ],
        env,
      )
      expect(child.status).toBe(0)
      return child.stdout
    }

    /** Whether `dir` is pinned, beneath the allow bind of the write root. */
    function expectPinned(command: string, dir: string): void {
      const pin = indexOfMount(command, '--ro-bind', dir, dir)
      expect(pin).toBeGreaterThan(-1)
      expect(pin).toBeLessThan(indexOfMount(command, '--bind', HOME, HOME))
    }

    /** Puts the shared name under TMP out of use: a link is refused there. */
    function takeTheSharedName(): void {
      mkdirSync(join(BASE, 'somebody-elses'))
      symlinkSync(
        join(BASE, 'somebody-elses'),
        join(TMP, `srt-mount-points-${UID}`),
      )
    }

    it('are pinned above the manifest directory a process with no runtime directory keeps', () => {
      const command = wrapped(
        { writeConfig: { allowOnly: [HOME], denyWithinAllow: [] } },
        { XDG_RUNTIME_DIR: undefined },
      )
      expect(command).toContain(`--ro-bind-try ${TMP}/srt-mount-points-${UID}`)
      expectPinned(command, TMP)
      // The write root is a mount point already, and nothing above it is the
      // command's to rename.
      expect(countMounts(command, '--ro-bind', HOME, HOME)).toBe(0)
      expect(countMounts(command, '--ro-bind', BASE, BASE)).toBe(0)
    }, 30000)

    it('are pinned above the manifest directory under the runtime directory', () => {
      const RUN = join(HOME, 'run', 'user')
      mkdirSync(RUN, { recursive: true, mode: 0o700 })
      chmodSync(RUN, 0o700)
      const command = wrapped(
        { writeConfig: { allowOnly: [HOME], denyWithinAllow: [GUARD] } },
        { XDG_RUNTIME_DIR: RUN },
      )
      expect(dirname(recordedBy(command)!)).toBe(`${RUN}/srt-mount-points`)
      expectPinned(command, RUN)
      expectPinned(command, join(HOME, 'run'))
    }, 30000)

    it('are pinned above the directory of its own a process settles on as it records', () => {
      // Neither shared name will do, so the wrap makes a directory only this
      // process knows, and makes it as it publishes: after the pins.
      takeTheSharedName()
      const command = wrapped(
        { writeConfig: { allowOnly: [HOME], denyWithinAllow: [GUARD] } },
        { XDG_RUNTIME_DIR: undefined },
      )
      expect(dirname(recordedBy(command)!)).toMatch(
        new RegExp(`^${TMP}/srt-mount-points-[A-Za-z0-9]{6}$`),
      )
      expectPinned(command, TMP)
    }, 30000)

    it('are pinned above the empty directory the placeholders bind from', () => {
      // The manifests are out of the way, under a runtime directory outside
      // the write root: the temp dir is pinned for the source alone.
      takeTheSharedName()
      const command = wrapped({
        writeConfig: {
          allowOnly: [HOME],
          denyWithinAllow: [join(HOME, 'absent', 'leaf')],
        },
      })
      expect(command).toMatch(
        new RegExp(`--ro-bind ${TMP}/claude-empty-\\S+ ${HOME}/absent `),
      )
      expectPinned(command, TMP)
    }, 30000)

    it('are pinned above the store of fake files, under a wrap that restricts no write', () => {
      const store = join(TMP, 'srt-credmask-store')
      mkdirSync(store, { mode: 0o700 })
      writeFileSync(join(store, '0.fake'), 'sentinel')
      const secret = join(BASE, 'secret')
      writeFileSync(secret, 'real')
      const command = wrapped({
        maskedFileBinds: [
          { realPath: secret, fakePath: join(store, '0.fake') },
        ],
        maskedFileStoreDir: store,
      })
      expect(countMounts(command, '--ro-bind', store, store)).toBe(1)
      // Everything is writable, so every directory above the store is
      // pinned, on top of the root's own bind.
      for (const dir of [TMP, HOME]) {
        const pin = indexOfMount(command, '--ro-bind', dir, dir)
        expect(pin).toBeGreaterThan(indexOfMount(command, '--bind', '/', '/'))
        expect(pin).toBeLessThan(
          indexOfMount(command, '--ro-bind', store, store),
        )
      }
    }, 30000)

    it('are pinned where the temp dir really is, when its name leads there through a link', () => {
      // A pin is a mount, and a mount lands where its path resolves; on the
      // name it would be a mount on a link, which bubblewrap refuses.
      const real = join(HOME, 'real-tmp')
      const through = join(HOME, 'tmp-link')
      mkdirSync(real)
      symlinkSync('real-tmp', through)
      const command = wrapped(
        { writeConfig: { allowOnly: [HOME], denyWithinAllow: [] } },
        { XDG_RUNTIME_DIR: undefined, TMPDIR: through },
      )
      expectPinned(command, real)
      expect(countMounts(command, '--ro-bind', through, through)).toBe(0)
    }, 30000)

    it('are not pinned where the temp dir is itself the write root, or outside every one', () => {
      const inside = wrapped(
        { writeConfig: { allowOnly: [TMP], denyWithinAllow: [] } },
        { XDG_RUNTIME_DIR: undefined },
      )
      expect(countMounts(inside, '--bind', TMP, TMP)).toBe(1)
      expect(countMounts(inside, '--ro-bind', TMP, TMP)).toBe(0)

      const AREA = join(BASE, 'area')
      mkdirSync(AREA)
      const outside = wrapped(
        { writeConfig: { allowOnly: [AREA], denyWithinAllow: [] } },
        { XDG_RUNTIME_DIR: undefined },
      )
      expect(countMounts(outside, '--ro-bind', TMP, TMP)).toBe(0)
      expect(countMounts(outside, '--ro-bind', HOME, HOME)).toBe(0)
    }, 30000)

    it.if(BWRAP_CAN_NAMESPACE)(
      'cannot be moved aside from inside a sandbox, to make the manifest directory again with a manifest of its own',
      async () => {
        // What the command is after: a clean-up on the host that reads the
        // directory at the name, finds no live manifest claiming GUARD, and
        // removes it from under the sandbox that relies on it.
        const theirs = join(TMP, `srt-mount-points-${UID}`)
        const up = join(HOME, 'up')
        const go = join(HOME, 'go')
        const out = join(BASE, 'out.txt')
        const forged = JSON.stringify({
          version: 1,
          pid: 4194000,
          start: '0',
          created: 0,
          paths: [GUARD],
          sources: [],
        })
        const command = [
          `mv ${TMP} ${TMP}.aside; echo mv=$?`,
          `mkdir -p -m 700 ${theirs}`,
          `echo '${forged}' > ${theirs}/forged.json; echo plant=$?`,
          `echo up > ${up}; while [ ! -e ${go} ]; do sleep 0.05; done`,
          `echo pwned > ${GUARD}; echo rc=$?`,
        ].join('; ')
        const env: Record<string, string> = { ...process.env, TMPDIR: TMP }
        delete env.XDG_RUNTIME_DIR
        const script = join(BASE, 'holder.ts')
        writeFileSync(
          script,
          [
            `import { spawnSync } from 'node:child_process'`,
            `import { writeFileSync } from 'node:fs'`,
            `import { wrapCommandWithSandboxLinux } from ${LIBRARY}`,
            `const wrapped = await wrapCommandWithSandboxLinux({`,
            `  command: ${JSON.stringify(command)},`,
            `  needsNetworkRestriction: false,`,
            `  readConfig: { denyOnly: [] },`,
            `  writeConfig: { allowOnly: [${JSON.stringify(HOME)}], denyWithinAllow: [${JSON.stringify(GUARD)}] },`,
            `})`,
            `const r = spawnSync(wrapped, { shell: true, encoding: 'utf8', timeout: 60000 })`,
            `writeFileSync(${JSON.stringify(out)}, String(r.stdout ?? '') + String(r.stderr ?? ''))`,
          ].join('\n'),
        )
        const holder = spawn(process.execPath, [script], {
          env,
          stdio: 'ignore',
          cwd: import.meta.dir,
        })
        const holderExited = new Promise(resolve => holder.on('exit', resolve))
        try {
          const deadline = Date.now() + 30000
          while (!existsSync(up)) {
            if (Date.now() > deadline) throw new Error('the sandbox never ran')
            await new Promise(resolve => setTimeout(resolve, 25))
          }
          expect(lstatSync(GUARD).size).toBe(0)

          const collector = inAChild(
            'collector.ts',
            [
              `import { cleanupBwrapMountPoints } from ${LIBRARY}`,
              `cleanupBwrapMountPoints()`,
            ],
            { XDG_RUNTIME_DIR: undefined },
          )
          expect(collector.status).toBe(0)
          expect(existsSync(GUARD)).toBe(true)
        } finally {
          writeFileSync(go, '')
          await holderExited
        }

        const said = readFileSync(out, 'utf8')
        expect(said).toMatch(/mv=[1-9]/)
        expect(said).toMatch(/plant=[1-9]/)
        expect(said).toMatch(/rc=[1-9]/)
        expect(existsSync(`${TMP}.aside`)).toBe(false)
        expect(existsSync(join(theirs, 'forged.json'))).toBe(false)
        expect(existsSync(GUARD) ? readFileSync(GUARD, 'utf8') : '').toBe('')
      },
      90000,
    )
  },
)

/**
 * A bind is made where its destination really is: bubblewrap makes the
 * destination by name inside the new root, and a link with an absolute target
 * on the way leads out of that root. So with a temp dir reached through such a
 * link, every manifest directory is bound at its real path.
 */
describe.if(isLinux)(
  'The manifest directory under a temp dir whose name is a link',
  () => {
    usePrivateManifestDirectory()
    const BWRAP_CAN_NAMESPACE = bwrapCanNamespace()
    const LIBRARY = JSON.stringify(
      join(import.meta.dir, '../../src/sandbox/linux-sandbox-utils.ts'),
    )
    const UID = isLinux ? process.getuid!() : 0
    let BASE: string
    let HOME: string // the allowed write root
    let GUARD: string // a denyWrite path, absent to begin with

    beforeEach(() => {
      BASE = realpathSync(mkdtempSync(join(tmpdir(), 'mount-point-linked-')))
      HOME = join(BASE, 'home')
      mkdirSync(HOME)
      GUARD = join(HOME, 'guard.lock')
    })

    afterEach(() => {
      cleanupBwrapMountPoints({ force: true })
      rmSync(BASE, { recursive: true, force: true })
    })

    /**
     * What a process whose temp dir is `through`, with no runtime directory,
     * wraps `command` as with that deny list, and what the command said when
     * run.
     */
    function wrappedAndRun(
      through: string,
      command: string,
      deny: string[],
      store?: string,
    ): { wrapped: string; status: number | null; said: string } {
      const file = join(BASE, 'wrap-and-run.ts')
      writeFileSync(
        file,
        [
          `import { spawnSync } from 'node:child_process'`,
          `import { wrapCommandWithSandboxLinux } from ${LIBRARY}`,
          `const wrapped = await wrapCommandWithSandboxLinux({`,
          `  command: ${JSON.stringify(command)},`,
          `  needsNetworkRestriction: false,`,
          `  readConfig: { denyOnly: [] },`,
          `  writeConfig: { allowOnly: [${JSON.stringify(HOME)}], denyWithinAllow: ${JSON.stringify(deny)} },`,
          ...(store === undefined
            ? []
            : [`  maskedFileStoreDir: ${JSON.stringify(store)},`]),
          `})`,
          `const r = ${BWRAP_CAN_NAMESPACE ? `spawnSync(wrapped, { shell: true, encoding: 'utf8', timeout: 60000 })` : `{ status: null, stdout: '', stderr: '' }`}`,
          `console.log(JSON.stringify({ wrapped, status: r.status, said: String(r.stdout ?? '') + String(r.stderr ?? '') }))`,
        ].join('\n'),
      )
      const env: Record<string, string> = { ...process.env, TMPDIR: through }
      delete env.XDG_RUNTIME_DIR
      const child = spawnSync(process.execPath, [file], {
        env,
        encoding: 'utf8',
        timeout: 90000,
        // Outside every allowed write path, so no mount points for cwd.
        cwd: import.meta.dir,
      })
      expect(child.status).toBe(0)
      return JSON.parse(child.stdout) as {
        wrapped: string
        status: number | null
        said: string
      }
    }

    const variants = (['inside', 'outside'] as const).flatMap(where =>
      (['absolute', 'relative'] as const).map(target => ({ where, target })),
    )
    for (const { where, target } of variants) {
      /** The temp dir, and the name that leads to it. */
      const linked = (): { real: string; through: string } => {
        const parent = where === 'inside' ? HOME : BASE
        const real = join(parent, 'real-tmp')
        const through = join(parent, 'tmp')
        mkdirSync(real)
        symlinkSync(target === 'absolute' ? real : 'real-tmp', through)
        return { real, through }
      }

      it(`is bound where it really is, with the link ${where} the write root and its target ${target}`, () => {
        const { real, through } = linked()
        const kept = join(real, `srt-mount-points-${UID}`)
        const named = join(through, `srt-mount-points-${UID}`)

        const recording = wrappedAndRun(through, 'true', [GUARD]).wrapped
        expect(countMounts(recording, '--ro-bind', kept, kept)).toBe(1)
        expect(dirname(recordedBy(recording)!)).toBe(kept)
        expect(recording).not.toContain(named)

        // A wrap with nothing to record keeps the command out of it as well.
        const other = wrappedAndRun(through, 'true', []).wrapped
        expect(other).toContain(`--ro-bind-try ${kept} ${kept}`)
        expect(other).not.toContain(named)
      }, 30000)

      it(`binds the empty directory and the store of fake files where they really are, with the link ${where} the write root and its target ${target}`, () => {
        const { real, through } = linked()
        const store = join(through, 'fake-files')
        mkdirSync(store)

        // A deny beneath a directory that is not there makes that directory
        // the mount point, bound from the empty directory under the temp dir.
        const wrapped = wrappedAndRun(
          through,
          'true',
          [join(HOME, 'absent', 'inner.lock')],
          store,
        ).wrapped
        const empty = /--ro-bind (\S+\/claude-empty-\S+) \1(?= |$)/.exec(
          wrapped,
        )
        expect(empty?.[1]).toStartWith(`${real}/`)
        expect(countMounts(wrapped, '--ro-bind', empty![1]!, empty![1]!)).toBe(
          1,
        )
        const kept = join(real, 'fake-files')
        expect(countMounts(wrapped, '--ro-bind', kept, kept)).toBe(1)
        // Neither is a destination under the name that leads there.
        expect(wrapped).not.toMatch(
          new RegExp(`--ro-bind \\S+ ${through}/(claude-empty-|fake-files)`),
        )
      }, 30000)

      it.if(BWRAP_CAN_NAMESPACE)(
        `does not keep a sandbox from starting, with the link ${where} the write root and its target ${target}`,
        () => {
          const { real, through } = linked()
          const kept = join(real, `srt-mount-points-${UID}`)
          const attempts = [
            `echo started`,
            `echo pwned > ${GUARD}; echo rc=$?`,
            `touch ${kept}/planted.json; echo real=$?`,
            `touch ${through}/srt-mount-points-${UID}/planted.json; echo through=$?`,
          ].join('; ')

          const recording = wrappedAndRun(through, attempts, [GUARD])
          expect(recording.said).not.toContain('bwrap:')
          expect(recording.status).toBe(0)
          expect(recording.said).toContain('started')
          // Its deny holds, and the manifest directory is out of its reach by
          // either name.
          expect(recording.said).toMatch(/rc=[1-9]/)
          expect(recording.said).toMatch(/real=[1-9]/)
          expect(recording.said).toMatch(/through=[1-9]/)
          expect(existsSync(GUARD) ? readFileSync(GUARD, 'utf8') : '').toBe('')
          expect(existsSync(join(kept, 'planted.json'))).toBe(false)

          // And one with no mount point of its own, which binds the directory
          // all the same.
          const other = wrappedAndRun(through, attempts, [])
          expect(other.said).not.toContain('bwrap:')
          expect(other.status).toBe(0)
          expect(other.said).toContain('started')
          expect(other.said).toMatch(/real=[1-9]/)
          expect(other.said).toMatch(/through=[1-9]/)
          expect(existsSync(join(kept, 'planted.json'))).toBe(false)
        },
        90000,
      )

      it.if(BWRAP_CAN_NAMESPACE)(
        `does not keep a sandbox that needs a directory mount point or a store of fake files from starting, with the link ${where} the write root and its target ${target}`,
        () => {
          const { real, through } = linked()
          const store = join(through, 'fake-files')
          mkdirSync(store)
          const inner = join(HOME, 'absent', 'inner.lock')
          const attempts = [
            `echo started`,
            `mkdir -p ${dirname(inner)} 2>/dev/null; echo pwned > ${inner}; echo rc=$?`,
            `touch ${join(real, 'fake-files')}/planted; echo store=$?`,
            `touch ${store}/planted; echo through=$?`,
          ].join('; ')

          const ran = wrappedAndRun(through, attempts, [inner], store)
          expect(ran.said).not.toContain('bwrap:')
          expect(ran.status).toBe(0)
          expect(ran.said).toContain('started')
          expect(ran.said).toMatch(/rc=[1-9]/)
          expect(ran.said).toMatch(/store=[1-9]/)
          expect(ran.said).toMatch(/through=[1-9]/)
          expect(existsSync(inner)).toBe(false)
          expect(existsSync(join(real, 'fake-files', 'planted'))).toBe(false)
        },
        90000,
      )
    }
  },
)

/**
 * A manifest's witnesses are processes, and /proc/PID is relative to a PID
 * namespace. A process cleaning up from another PID namespace that shares the
 * manifest directory sees a running sandbox's manifest as it would see a dead
 * process's.
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
      'survives a cleanup run where neither its writer nor the process on its record can be seen',
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
          manifest = recordedBy(readFileSync(WRAPPED, 'utf8'))!
          expect(existsSync(manifest)).toBe(true)
          expect(lstatSync(LOCK).size).toBe(0)

          const collector = spawnSync(
            IN_NEW_PID_NAMESPACE[0]!,
            [
              ...IN_NEW_PID_NAMESPACE.slice(1),
              process.execPath,
              writeScript('collector.ts', [
                `import { existsSync, readFileSync } from 'node:fs'`,
                `import { cleanupBwrapMountPoints } from ${LIBRARY}`,
                // The premise: from here the pid on record and the writer's
                // are nobody's.
                `const record = readFileSync(${JSON.stringify(manifest.replace(/json$/, 'started'))}, 'utf8')`,
                `if (existsSync('/proc/' + record.split(' ')[0])) process.exit(7)`,
                `if (existsSync('/proc/${holder.pid}')) process.exit(8)`,
                `cleanupBwrapMountPoints()`,
              ]),
            ],
            {
              env: { ...process.env },
              encoding: 'utf8',
              timeout: 60000,
              cwd: import.meta.dir,
            },
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
        cleanupBwrapMountPoints()
        expect(existsSync(LOCK)).toBe(false)
        expect(existsSync(manifest)).toBe(false)
      },
      90000,
    )
  },
)
