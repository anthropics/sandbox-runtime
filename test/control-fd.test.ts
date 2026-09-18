import { describe, it, expect, afterEach, beforeEach } from 'vitest'
import {
  spawn,
  spawnSync,
  execFileSync,
  type ChildProcess,
} from 'child_process'
import * as fs from 'fs'
import * as os from 'os'
import * as path from 'path'
import { type Writable } from 'stream'
import { isLinux, isWindows } from './helpers/platform.js'

// Get the path to the built CLI
const CLI_PATH = path.join(process.cwd(), 'dist', 'cli.js')

// srt is expected to exit on its own shortly after the wrapped command
// (which runs for well under a second) finishes; a hang is a failure, not
// something to wait out. The cap is generous against CI load (the slowest
// job takes about a second per test) but stays under bun's 5 s default
// per-test timeout so the failure names the hang rather than the runner.
const EXIT_TIMEOUT_MS = 4500

// Extra time for the stdio pipes to close after srt's own exit. It starts
// only once 'exit' has fired, and EXIT_TIMEOUT_MS + this stays under bun's
// 5 s per-test default so a stalled drain still names itself.
const DRAIN_TIMEOUT_MS = 400

type Spawned = {
  child: ChildProcess
  exited: Promise<number | null>
  stdout: string[]
  stderr: string[]
}

// Resolves on 'close', not 'exit': 'exit' fires while the stdio pipes may
// still hold the command's last chunk, which every stdout assertion here
// would then race. The code comes from 'exit', the only event that carries
// it.
function waitForExit(child: ChildProcess): Promise<number | null> {
  return new Promise((resolve, reject) => {
    let code: number | null = null
    let drainTimer: ReturnType<typeof setTimeout> | undefined
    const exitTimer = setTimeout(
      () =>
        reject(
          new Error(
            `srt did not exit within ${EXIT_TIMEOUT_MS}ms of the wrapped command`,
          ),
        ),
      EXIT_TIMEOUT_MS,
    )
    child.on('exit', c => {
      code = c
      // srt is gone; only the pipes are still open, which is a different
      // failure (something else holding them) and gets its own deadline.
      clearTimeout(exitTimer)
      drainTimer = setTimeout(
        () =>
          reject(
            new Error(
              `srt exited but its stdio did not close within ${DRAIN_TIMEOUT_MS}ms`,
            ),
          ),
        DRAIN_TIMEOUT_MS,
      )
    })
    child.on('close', () => {
      clearTimeout(exitTimer)
      clearTimeout(drainTimer)
      resolve(code)
    })
    child.on('error', err => {
      clearTimeout(exitTimer)
      clearTimeout(drainTimer)
      reject(err)
    })
  })
}

// srt's own runtime is node (the bin shebang); under `bun test` the same
// dist is exercised through bun as well, whose net.Socket({ fd }) reads
// nothing and whose fs stream does not hold exit — the reason the CLI
// gates on the runtime.
const RUNTIMES: Array<{ name: string; bin: string }> = [
  { name: 'node', bin: 'node' },
  ...(process.versions.bun ? [{ name: 'bun', bin: process.execPath }] : []),
]

// One config update, with a domain the debug log will echo back.
const CONFIG_UPDATE = JSON.stringify({
  network: { allowedDomains: ['updated-domain.com'], deniedDomains: [] },
  filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
})

// The same, as a sandboxed command would try to inject it.
const INJECTED_UPDATE = JSON.stringify({
  network: {
    allowedDomains: ['injected-by-the-sandbox.com'],
    deniedDomains: [],
  },
  filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
})

// mkfifo and /bin/bash; the Windows CI legs run neither this suite nor
// anything it shells out to.
describe.skipIf(isWindows)('--control-fd', () => {
  let tmpDir: string
  // Every process this file starts, so a test that fails with one still
  // running does not leave it behind.
  let spawned: ChildProcess[] = []
  // fds this side keeps open for the child (a FIFO writer, a file); closed
  // after each test.
  let heldFds: number[] = []

  // Spawn srt and start watching for its exit before anything else happens,
  // so an srt that dies early is reported by its real exit, not as a hang.
  function spawnSrt(
    args: string[],
    stdio: Array<'inherit' | 'pipe' | 'ignore' | number>,
    env?: NodeJS.ProcessEnv,
    runtime = 'node',
  ): Spawned {
    const child = spawn(runtime, [CLI_PATH, ...args], { stdio, env })
    spawned.push(child)
    const exited = waitForExit(child)
    // Attached later; a rejection before then must not surface as unhandled.
    exited.catch(() => {})
    const stdout: string[] = []
    const stderr: string[] = []
    child.stdout?.on('data', (data: Buffer) => {
      stdout.push(data.toString())
    })
    child.stderr?.on('data', (data: Buffer) => {
      stderr.push(data.toString())
    })
    return { child, exited, stdout, stderr }
  }

  // Resolves once srt has printed `needle` on stderr, so a test can act on
  // srt's own progress instead of waiting a guessed interval.
  function waitForStderr(spawnedSrt: Spawned, needle: string): Promise<void> {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(
        () =>
          reject(
            new Error(
              `srt did not print ${JSON.stringify(needle)} within ${EXIT_TIMEOUT_MS}ms`,
            ),
          ),
        EXIT_TIMEOUT_MS,
      )
      // spawnSrt's own collector is attached first, so the buffer this
      // reads is already up to date when this runs.
      const check = (): void => {
        if (spawnedSrt.stderr.join('').includes(needle)) {
          clearTimeout(timer)
          resolve()
        }
      }
      spawnedSrt.child.stderr?.on('data', check)
      check()
    })
  }

  // For a run that needs nothing written to the control fd while it is in
  // progress: spawnSync keeps the runner's asynchronous child bookkeeping
  // out of it, which matters because this file spawns srt a dozen times
  // over, and it makes a hang a bounded failure rather than a wait.
  function runSrt(
    args: string[],
    stdio: Array<'inherit' | 'pipe' | 'ignore' | number>,
    env: NodeJS.ProcessEnv = process.env,
  ): { status: number | null; stdout: string; stderr: string } {
    const result = spawnSync('node', [CLI_PATH, ...args], {
      stdio,
      env,
      encoding: 'utf8',
      timeout: EXIT_TIMEOUT_MS,
      // srt traps SIGTERM and only forwards it, so the default timeout
      // signal would leave a hung srt alive and spawnSync waiting forever.
      killSignal: 'SIGKILL',
    })
    if (result.error) {
      throw new Error(
        `srt did not exit within ${EXIT_TIMEOUT_MS}ms of the wrapped command: ${result.error.message}`,
      )
    }
    return {
      status: result.status,
      stdout: result.stdout,
      stderr: result.stderr,
    }
  }

  function writeScript(body: string): string {
    const testScript = path.join(tmpDir, 'test.sh')
    fs.writeFileSync(testScript, `#!/bin/bash\n${body}\n`, { mode: 0o755 })
    return testScript
  }

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'control-fd-test-'))
    spawned = []
    heldFds = []
  })

  afterEach(async () => {
    // A no-op once srt has exited on its own, which every test waits for;
    // it only bites when a test already failed with srt still running.
    for (const child of spawned) {
      if (child.exitCode === null && child.signalCode === null) {
        child.kill('SIGKILL')
      }
    }
    spawned = []
    for (const fd of heldFds) {
      try {
        fs.closeSync(fd)
      } catch {
        // One fd already closed by the test must not skip the rest.
      }
    }
    heldFds = []
    fs.rmSync(tmpDir, { recursive: true, force: true })
    // Bun's node:child_process shim implements extra stdio 'pipe' entries
    // (fd 3 here) via a unix socket torn down asynchronously after the
    // child exits, and a spawn that races that teardown throws `Failed to
    // connect` (connect ENOENT), so yield briefly before the next test's
    // spawn either way.
    await new Promise(r => setTimeout(r, 50))
  })

  for (const runtime of RUNTIMES) {
    it(`should update config when receiving valid JSON on control fd (${runtime.name})`, async () => {
      // Verify through the debug output that the update was applied.
      const testScript = writeScript('sleep 0.3\necho "DONE"')

      // Spawn srt with --control-fd 3, passing fd 3 as a pipe
      const { child, exited, stderr } = spawnSrt(
        ['--debug', '--control-fd', '3', '--', testScript],
        ['inherit', 'pipe', 'pipe', 'pipe'],
        { ...process.env, SRT_DEBUG: 'true' },
        runtime.bin,
      )

      // No wait for srt to initialize: a line written now waits in the
      // pipe buffer until srt attaches its reader.
      const controlFd = child.stdio[3] as Writable
      controlFd.write(CONFIG_UPDATE + '\n')

      // srt must exit by itself once the wrapped command finishes, with the
      // control fd still open on our side.
      expect(await exited).toBe(0)

      // Applied, not rejected: the rejection path names the fd too, so the
      // domain alone would not tell the two apart.
      const allStderr = stderr.join('')
      expect(allStderr).toContain('Config updated from control fd')
      expect(allStderr).toContain('updated-domain.com')
      expect(allStderr).not.toContain('Invalid config on control fd')
    })
  }

  it('should apply an update written after the reader is listening', async () => {
    // Every other case here writes before srt starts, so the line is
    // waiting in the descriptor's buffer when the reader attaches. This one
    // writes once srt has said it is listening, which is the live-update
    // path the flag exists for.
    const testScript = writeScript('sleep 0.3\necho "LIVE_DONE"')

    const spawnedSrt = spawnSrt(
      ['--debug', '--control-fd', '3', '--', testScript],
      ['inherit', 'pipe', 'pipe', 'pipe'],
      { ...process.env, SRT_DEBUG: 'true' },
    )

    await waitForStderr(spawnedSrt, 'Listening for config updates on fd 3')
    const controlFd = spawnedSrt.child.stdio[3] as Writable
    controlFd.write(CONFIG_UPDATE + '\n')

    expect(await spawnedSrt.exited).toBe(0)
    expect(spawnedSrt.stdout.join('')).toContain('LIVE_DONE')
    const allStderr = spawnedSrt.stderr.join('')
    expect(allStderr).toContain('Config updated from control fd')
    expect(allStderr).toContain('updated-domain.com')
  })

  it('should ignore invalid JSON on control fd and continue running', async () => {
    const testScript = writeScript('sleep 0.3\necho "COMPLETED"')

    const { child, exited, stdout } = spawnSrt(
      ['--debug', '--control-fd', '3', '--', testScript],
      ['inherit', 'pipe', 'pipe', 'pipe'],
      { ...process.env, SRT_DEBUG: 'true' },
    )

    const controlFd = child.stdio[3] as Writable
    controlFd.write('{ invalid json }\n')

    expect(await exited).toBe(0)

    // Process should still complete successfully
    expect(stdout.join('')).toContain('COMPLETED')
  })

  it('should report a rejected update on stderr without SRT_DEBUG', async () => {
    // The caller has to learn its update was dropped even when srt is not
    // running with --debug, and the line itself must not be echoed back.
    const testScript = writeScript('sleep 0.3\necho "COMPLETED"')
    const env = { ...process.env }
    delete env.SRT_DEBUG

    const { child, exited, stdout, stderr } = spawnSrt(
      ['--control-fd', '3', '--', testScript],
      ['inherit', 'pipe', 'pipe', 'pipe'],
      env,
    )

    const controlFd = child.stdio[3] as Writable
    controlFd.write('{ "network": "not-an-object" }\n')

    expect(await exited).toBe(0)
    expect(stdout.join('')).toContain('COMPLETED')
    const allStderr = stderr.join('')
    expect(allStderr).toContain('Invalid config on control fd 3')
    expect(allStderr).not.toContain('not-an-object')
  })

  it('should ignore empty lines on control fd', async () => {
    const testScript = writeScript('sleep 0.3\necho "DONE"')

    const { child, exited, stdout, stderr } = spawnSrt(
      ['--control-fd', '3', '--', testScript],
      ['inherit', 'pipe', 'pipe', 'pipe'],
    )

    const controlFd = child.stdio[3] as Writable
    controlFd.write('\n')
    controlFd.write('   \n')
    controlFd.write('\t\n')

    expect(await exited).toBe(0)

    // Process should still complete successfully
    expect(stdout.join('')).toContain('DONE')
    expect(stderr.join('')).not.toContain('Invalid config on control fd')
  })

  it('should exit with a FIFO control fd the parent keeps open', async () => {
    // stdio 'pipe' hands srt a unix socket; a named pipe is what pipe(2),
    // mkfifo and Python's pass_fds embedders hand it, and the fd kind the
    // hang was reported against. The write end stays open for the whole
    // test, so srt only exits if the fd does not keep it alive.
    const fifo = path.join(tmpDir, 'control.fifo')
    execFileSync('mkfifo', [fifo])
    // O_RDWR: opens without a reader and never delivers EOF to srt.
    const writer = fs.openSync(fifo, fs.constants.O_RDWR)
    heldFds.push(writer)
    const readEnd = fs.openSync(fifo, fs.constants.O_RDONLY)
    heldFds.push(readEnd)

    fs.writeSync(writer, CONFIG_UPDATE + '\n')

    const testScript = writeScript('sleep 0.3\necho "FIFO_DONE"')
    const { status, stdout, stderr } = runSrt(
      ['--debug', '--control-fd', '3', '--', testScript],
      ['inherit', 'pipe', 'pipe', readEnd],
      { ...process.env, SRT_DEBUG: 'true' },
    )

    expect(status).toBe(0)
    expect(stdout).toContain('FIFO_DONE')
    expect(stderr).toContain('Config updated from control fd')
  })

  it('should read a regular file on the control fd', () => {
    // Not a pipe or socket: the fs stream path, which both the fd-kind gate
    // and its fallback lead to, so this pins the branch rather than the
    // choice between them. The update is read to EOF and applied before the
    // command finishes.
    const configFile = path.join(tmpDir, 'control.json')
    fs.writeFileSync(configFile, CONFIG_UPDATE + '\n')
    const fileFd = fs.openSync(configFile, fs.constants.O_RDONLY)
    heldFds.push(fileFd)

    const testScript = writeScript('sleep 0.3\necho "FILE_DONE"')
    const { status, stdout, stderr } = runSrt(
      ['--debug', '--control-fd', '3', '--', testScript],
      ['inherit', 'pipe', 'pipe', fileFd],
      { ...process.env, SRT_DEBUG: 'true' },
    )

    expect(status).toBe(0)
    expect(stdout).toContain('FILE_DONE')
    expect(stderr).toContain('Config updated from control fd')
  })

  it('should work without --control-fd (backward compat)', () => {
    const testScript = writeScript('echo "NO_CONTROL_FD"')

    const { status, stdout } = runSrt(
      ['--', testScript],
      ['inherit', 'pipe', 'pipe'],
    )

    expect(status).toBe(0)
    expect(stdout).toContain('NO_CONTROL_FD')
  })

  it('should allow stdin to pass through to child process', async () => {
    // Create a script that reads from stdin
    const testScript = writeScript('read line\necho "GOT: $line"')

    // Spawn with stdin as pipe (not inherit) so we can write to it
    const { child, exited, stdout } = spawnSrt(
      ['--control-fd', '3', '--', testScript],
      ['pipe', 'pipe', 'pipe', 'pipe'],
    )

    // Write to stdin (fd 0)
    const stdin = child.stdin as Writable
    stdin.write('hello from stdin\n')

    expect(await exited).toBe(0)
    expect(stdout.join('')).toContain('GOT: hello from stdin')
  })

  // A descriptor number that cannot carry a control channel is refused
  // before the sandbox is built, so no command ever runs against a channel
  // that is not there.
  for (const bad of ['abc', '2', '-1']) {
    it(`should refuse --control-fd ${bad} before running anything`, () => {
      const testScript = writeScript('echo "SHOULD_NOT_RUN"')

      const { status, stdout, stderr } = runSrt(
        ['--control-fd', bad, '--', testScript],
        ['inherit', 'pipe', 'pipe'],
      )

      expect(status).toBe(1)
      expect(stdout).not.toContain('SHOULD_NOT_RUN')
      // The flag name alone is in commander's own usage banner; this is the
      // text the parser rejects the value with.
      expect(stderr).toContain('must be an integer file descriptor >= 3')
    })
  }

  // A settings file that lets the wrapped command write to tmpDir, so a
  // marker it fails to leave is evidence that it never ran rather than
  // evidence that the sandbox denied the write.
  function writeWritableSettings(): string {
    const settings = path.join(tmpDir, 'settings.json')
    fs.writeFileSync(
      settings,
      JSON.stringify({
        network: { allowedDomains: [], deniedDomains: [] },
        filesystem: {
          denyRead: [],
          allowRead: [],
          allowWrite: [tmpDir],
          denyWrite: [],
        },
      }),
    )
    return settings
  }

  it('should refuse a control fd it cannot read from', () => {
    // A descriptor open for writing only: fstat succeeds on it, so nothing
    // short of asking the kernel whether a read is permitted tells it from
    // a live channel. Running the command would give the caller a sandbox
    // whose updates — including the ones that tighten it — go nowhere.
    const marker = path.join(tmpDir, 'ran')
    const settings = writeWritableSettings()
    const sink = fs.openSync(path.join(tmpDir, 'sink'), 'w')
    heldFds.push(sink)
    const testScript = writeScript(`touch ${marker}\necho "SHOULD_NOT_RUN"`)

    const { status, stdout, stderr } = runSrt(
      ['--settings', settings, '--control-fd', '3', '--', testScript],
      ['inherit', 'pipe', 'pipe', sink],
    )

    expect(status).toBe(1)
    expect(stderr).toContain('--control-fd 3 is not usable')
    expect(stdout).not.toContain('SHOULD_NOT_RUN')
    expect(fs.existsSync(marker)).toBe(false)
  })

  it('should refuse to run when the control fd cannot be opened', () => {
    // 200 is well past anything node opens for itself, so it is closed in
    // srt and fstat fails on it. Running the command anyway would give the
    // caller a sandbox whose updates — including the ones that tighten it —
    // go nowhere.
    const marker = path.join(tmpDir, 'ran')
    const settings = writeWritableSettings()
    const testScript = writeScript(`touch ${marker}\necho "SHOULD_NOT_RUN"`)

    const { status, stdout, stderr } = runSrt(
      ['--settings', settings, '--control-fd', '200', '--', testScript],
      ['inherit', 'pipe', 'pipe'],
    )

    expect(status).toBe(1)
    expect(stderr).toContain('--control-fd 200 is not usable')
    expect(stdout).not.toContain('SHOULD_NOT_RUN')
    expect(fs.existsSync(marker)).toBe(false)
  })

  it.skipIf(!isLinux)(
    'should keep the control fd out of the sandboxed command',
    () => {
      // The descriptor survives into the sandbox at fd 20, and one O_RDWR
      // open of the FIFO is both the caller's end and srt's control fd, so
      // a command that reaches it can write a config srt would then apply.
      const fifo = path.join(tmpDir, 'control.fifo')
      execFileSync('mkfifo', [fifo])
      // The caller's own end, holding the fifo open and carrying the
      // caller's update, which waits there until srt attaches.
      const caller = fs.openSync(fifo, fs.constants.O_RDWR)
      heldFds.push(caller)
      fs.writeSync(caller, CONFIG_UPDATE + '\n')

      // `>&20` writes through the descriptor the command inherited.
      // `>/dev/fd/20` would not: that re-opens the symlink's target, which
      // succeeds whether the slot holds the fifo or /dev/null.
      const testScript = writeScript(
        'ls -l /proc/self/fd\n' +
          `printf '%s\\n' '${INJECTED_UPDATE}' >&20 || echo "WRITE_REFUSED"\n` +
          'sleep 0.3\necho "SANDBOX_DONE"',
      )

      // Through a shell's `exec 20<>`, not this runner's stdio array: a
      // descriptor that arrived across an exec carries no close-on-exec
      // flag, which is what makes fd 20 reach the sandboxed command, and
      // it is how an embedder hands srt a control channel in the first
      // place. Descriptors the runner places in a stdio slot come with the
      // flag already set, so they could not show this either way.
      const result = spawnSync(
        'bash',
        [
          '-c',
          `exec 20<>${fifo}; exec node ${CLI_PATH} --debug --control-fd 20 -- ${testScript}`,
        ],
        {
          stdio: ['inherit', 'pipe', 'pipe'],
          env: { ...process.env, SRT_DEBUG: 'true' },
          encoding: 'utf8',
          timeout: EXIT_TIMEOUT_MS,
          // As in runSrt: srt forwards SIGTERM rather than dying of it.
          killSignal: 'SIGKILL',
        },
      )
      const { status, stdout, stderr } = result

      expect(status).toBe(0)
      expect(stdout).toContain('SANDBOX_DONE')
      // The slot holds srt's read-only /dev/null, so the write fails...
      expect(stdout).toContain('WRITE_REFUSED')
      // ...and that is what is in the slot, not merely something that is
      // not the fifo: an assertion on the fifo's absence alone would also
      // pass on an `ls` that printed nothing at all.
      expect(stdout).toMatch(/\b20 -> \/dev\/null/)
      // Nothing written there is ever applied...
      expect(stderr).not.toContain('injected-by-the-sandbox.com')
      // ...while the caller's line still is.
      expect(stderr).toContain('updated-domain.com')
    },
  )
})
