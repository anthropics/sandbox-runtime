import { describe, it, expect, afterEach, beforeEach } from 'vitest'
import { spawn, spawnSync, type ChildProcess } from 'child_process'
import * as fs from 'fs'
import * as os from 'os'
import * as path from 'path'

const CLI_PATH = path.join(process.cwd(), 'dist', 'cli.js')

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

describe('--pass-fd', () => {
  let tmpDir: string
  let child: ChildProcess | null = null
  let exited: Promise<number | null> | null = null
  let heldFds: number[] = []

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pass-fd-test-'))
  })

  afterEach(async () => {
    if (child && child.exitCode === null && child.signalCode === null) {
      child.kill('SIGKILL')
    }
    for (const fd of heldFds) fs.closeSync(fd)
    heldFds = []
    fs.rmSync(tmpDir, { recursive: true, force: true })
    await new Promise(r => setTimeout(r, 50))
  })

  it('should pass a file descriptor to the sandboxed command at the same number', async () => {
    const testFile = path.join(tmpDir, 'test-data.txt')
    const testContent = 'hello from passed fd'
    fs.writeFileSync(testFile, testContent + '\n')

    const fileFd = fs.openSync(testFile, 'r')
    heldFds.push(fileFd)

    child = spawn('node', [CLI_PATH, '--pass-fd', '3', '-c', 'cat <&3'], {
      stdio: ['inherit', 'pipe', 'pipe', fileFd],
      env: { ...process.env, HOME: '/tmp/pass-fd-test-nonexistent' },
    })
    exited = waitForExit(child)
    exited.catch(() => {})

    let stdout = ''
    child.stdout?.setEncoding('utf8').on('data', (d: string) => (stdout += d))

    expect(await exited).toBe(0)
    expect(stdout.trim()).toBe(testContent)
  })

  it('should pass multiple file descriptors at their correct numbers', async () => {
    const file1 = path.join(tmpDir, 'file1.txt')
    const file2 = path.join(tmpDir, 'file2.txt')
    fs.writeFileSync(file1, 'content1\n')
    fs.writeFileSync(file2, 'content2\n')

    const fd1 = fs.openSync(file1, 'r')
    const fd2 = fs.openSync(file2, 'r')
    heldFds.push(fd1, fd2)

    child = spawn(
      'node',
      [CLI_PATH, '--pass-fd', '3', '--pass-fd', '5', '-c', 'cat <&3; cat <&5'],
      {
        stdio: ['inherit', 'pipe', 'pipe', fd1, 'ignore', fd2],
        env: { ...process.env, HOME: '/tmp/pass-fd-test-nonexistent' },
      },
    )
    exited = waitForExit(child)
    exited.catch(() => {})

    let stdout = ''
    child.stdout?.setEncoding('utf8').on('data', (d: string) => (stdout += d))

    expect(await exited).toBe(0)
    expect(stdout).toContain('content1')
    expect(stdout).toContain('content2')
  })

  it('should reject fd numbers out of range (0)', () => {
    const result = spawnSync(
      'node',
      [CLI_PATH, '--pass-fd', '0', '-c', 'echo test'],
      {
        encoding: 'utf-8',
        env: { ...process.env, HOME: '/tmp/pass-fd-test-nonexistent' },
      },
    )
    expect(result.status).toBe(1)
    expect(result.stderr).toContain('between 3 and 8')
  })

  it('should reject fd numbers out of range (9)', () => {
    const result = spawnSync(
      'node',
      [CLI_PATH, '--pass-fd', '9', '-c', 'echo test'],
      {
        encoding: 'utf-8',
        env: { ...process.env, HOME: '/tmp/pass-fd-test-nonexistent' },
      },
    )
    expect(result.status).toBe(1)
    expect(result.stderr).toContain('between 3 and 8')
  })

  it('should work without --pass-fd (backward compat)', async () => {
    child = spawn('node', [CLI_PATH, '-c', 'echo NO_PASS_FD'], {
      stdio: ['inherit', 'pipe', 'pipe'],
      env: { ...process.env, HOME: '/tmp/pass-fd-test-nonexistent' },
    })
    exited = waitForExit(child)
    exited.catch(() => {})

    let stdout = ''
    child.stdout?.setEncoding('utf8').on('data', (d: string) => (stdout += d))

    expect(await exited).toBe(0)
    expect(stdout.trim()).toBe('NO_PASS_FD')
  })
})
