import { describe, it, expect, afterEach, beforeEach } from 'vitest'
import { spawn, execFileSync, type ChildProcess } from 'child_process'
import * as fs from 'fs'
import * as os from 'os'
import * as path from 'path'
import { type Writable } from 'stream'

// Get the path to the built CLI
const CLI_PATH = path.join(process.cwd(), 'dist', 'cli.js')

// srt is expected to exit on its own shortly after the wrapped command
// (which runs for well under a second) finishes; a hang is a failure, not
// something to wait out. The cap is generous against CI load (the slowest
// job takes about a second per test) but stays under bun's 5 s default
// per-test timeout so the failure names the hang rather than the runner.
const EXIT_TIMEOUT_MS = 4500

function waitForExit(child: ChildProcess): Promise<number | null> {
  return new Promise((resolve, reject) => {
    if (child.exitCode !== null || child.signalCode !== null) {
      resolve(child.exitCode)
      return
    }
    const timer = setTimeout(
      () =>
        reject(
          new Error(
            `srt did not exit within ${EXIT_TIMEOUT_MS}ms of the wrapped command`,
          ),
        ),
      EXIT_TIMEOUT_MS,
    )
    child.on('exit', code => {
      clearTimeout(timer)
      resolve(code)
    })
    child.on('error', err => {
      clearTimeout(timer)
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

describe('--control-fd', () => {
  let tmpDir: string
  let child: ChildProcess | null = null
  // Subscribed right after spawn so an srt that dies during the settle
  // sleep below is reported by its real exit, not as a hang.
  let exited: Promise<number | null> | null = null
  // fds this side keeps open for the child (a FIFO writer, a file); closed
  // after each test.
  let heldFds: number[] = []

  // Spawn srt and start watching for its exit before anything else happens.
  function spawnSrt(
    args: string[],
    stdio: Array<'inherit' | 'pipe' | number>,
    env?: NodeJS.ProcessEnv,
    runtime = 'node',
  ): { stdout: string[]; stderr: string[] } {
    child = spawn(runtime, [CLI_PATH, ...args], { stdio, env })
    exited = waitForExit(child)
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
    return { stdout, stderr }
  }

  function writeScript(body: string): string {
    const testScript = path.join(tmpDir, 'test.sh')
    fs.writeFileSync(testScript, `#!/bin/bash\n${body}\n`, { mode: 0o755 })
    return testScript
  }

  // Let srt initialize before the control channel is used.
  const settle = () => new Promise(r => setTimeout(r, 100))

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'control-fd-test-'))
  })

  afterEach(async () => {
    // A no-op once srt has exited on its own, which every test waits for;
    // it only bites when a test already failed with srt still running.
    if (child && child.exitCode === null && child.signalCode === null) {
      child.kill('SIGKILL')
    }
    for (const fd of heldFds) fs.closeSync(fd)
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
      const { stderr } = spawnSrt(
        ['--debug', '--control-fd', '3', '--', testScript],
        ['inherit', 'pipe', 'pipe', 'pipe'],
        { ...process.env, SRT_DEBUG: 'true' },
        runtime.bin,
      )

      await settle()

      const controlFd = child!.stdio[3] as Writable
      controlFd.write(CONFIG_UPDATE + '\n')

      // srt must exit by itself once the wrapped command finishes, with the
      // control fd still open on our side.
      expect(await exited).toBe(0)

      // Applied, not rejected: the rejection path logs the raw line too, so
      // the domain alone would not tell the two apart.
      const allStderr = stderr.join('')
      expect(allStderr).toContain('Config updated from control fd')
      expect(allStderr).toContain('updated-domain.com')
      expect(allStderr).not.toContain('Invalid config on control fd')
    })
  }

  it('should ignore invalid JSON on control fd and continue running', async () => {
    const testScript = writeScript('sleep 0.3\necho "COMPLETED"')

    const { stdout } = spawnSrt(
      ['--debug', '--control-fd', '3', '--', testScript],
      ['inherit', 'pipe', 'pipe', 'pipe'],
      { ...process.env, SRT_DEBUG: 'true' },
    )

    await settle()

    const controlFd = child!.stdio[3] as Writable
    controlFd.write('{ invalid json }\n')

    expect(await exited).toBe(0)

    // Process should still complete successfully
    expect(stdout.join('')).toContain('COMPLETED')
  })

  it('should ignore empty lines on control fd', async () => {
    const testScript = writeScript('sleep 0.3\necho "DONE"')

    const { stdout } = spawnSrt(
      ['--control-fd', '3', '--', testScript],
      ['inherit', 'pipe', 'pipe', 'pipe'],
    )

    await settle()

    const controlFd = child!.stdio[3] as Writable
    controlFd.write('\n')
    controlFd.write('   \n')
    controlFd.write('\t\n')

    expect(await exited).toBe(0)

    // Process should still complete successfully
    expect(stdout.join('')).toContain('DONE')
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

    const testScript = writeScript('sleep 0.3\necho "FIFO_DONE"')
    const { stdout, stderr } = spawnSrt(
      ['--debug', '--control-fd', '3', '--', testScript],
      ['inherit', 'pipe', 'pipe', readEnd],
      { ...process.env, SRT_DEBUG: 'true' },
    )
    fs.closeSync(readEnd)

    await settle()
    fs.writeSync(writer, CONFIG_UPDATE + '\n')

    expect(await exited).toBe(0)
    expect(stdout.join('')).toContain('FIFO_DONE')
    expect(stderr.join('')).toContain('Config updated from control fd')
  })

  it('should read a regular file on the control fd', async () => {
    // Not a pipe or socket: the fs stream path. The update is read to EOF
    // and applied before the command finishes.
    const configFile = path.join(tmpDir, 'control.json')
    fs.writeFileSync(configFile, CONFIG_UPDATE + '\n')
    const fileFd = fs.openSync(configFile, fs.constants.O_RDONLY)

    const testScript = writeScript('sleep 0.3\necho "FILE_DONE"')
    const { stdout, stderr } = spawnSrt(
      ['--debug', '--control-fd', '3', '--', testScript],
      ['inherit', 'pipe', 'pipe', fileFd],
      { ...process.env, SRT_DEBUG: 'true' },
    )
    fs.closeSync(fileFd)

    expect(await exited).toBe(0)
    expect(stdout.join('')).toContain('FILE_DONE')
    expect(stderr.join('')).toContain('Config updated from control fd')
  })

  it('should work without --control-fd (backward compat)', async () => {
    const testScript = writeScript('echo "NO_CONTROL_FD"')

    // Spawn without --control-fd
    const { stdout } = spawnSrt(['--', testScript], ['inherit', 'pipe', 'pipe'])

    expect(await exited).toBe(0)
    expect(stdout.join('')).toContain('NO_CONTROL_FD')
  })

  it('should allow stdin to pass through to child process', async () => {
    // Create a script that reads from stdin
    const testScript = writeScript('read line\necho "GOT: $line"')

    // Spawn with stdin as pipe (not inherit) so we can write to it
    const { stdout } = spawnSrt(
      ['--control-fd', '3', '--', testScript],
      ['pipe', 'pipe', 'pipe', 'pipe'],
    )

    // Write to stdin (fd 0)
    const stdin = child!.stdin as Writable
    stdin.write('hello from stdin\n')

    expect(await exited).toBe(0)
    expect(stdout.join('')).toContain('GOT: hello from stdin')
  })
})
