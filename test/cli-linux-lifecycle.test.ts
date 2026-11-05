import { describe, expect, test } from 'bun:test'
import { spawn } from 'node:child_process'
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { quote } from '../src/utils/shell-quote.js'
import { bwrapCanNamespace } from './helpers/bwrap-namespace.js'
import { isLinux } from './helpers/platform.js'

async function waitFor(
  check: () => boolean,
  timeout: number,
): Promise<boolean> {
  const deadline = Date.now() + timeout
  while (!check()) {
    if (Date.now() >= deadline) return false
    await new Promise(resolve => setTimeout(resolve, 20))
  }
  return true
}

function isWorkload(pid: number, script: string): boolean {
  try {
    return (
      readFileSync(`/proc/${pid}/cmdline`, 'utf8').split('\0')[1] === script
    )
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code
    if (code === 'ENOENT' || code === 'ESRCH') return false
    throw error
  }
}

describe.skipIf(!isLinux || !bwrapCanNamespace())(
  'Linux CLI signals after the workload has started',
  () => {
    for (const signal of ['SIGINT', 'SIGTERM', 'SIGKILL'] as const) {
      test(`stops the workload when only the CLI receives ${signal}`, async () => {
        const root = mkdtempSync(join(tmpdir(), 'srt-cli-lifecycle-'))
        const settings = join(root, 'settings.json')
        const script = join(root, 'workload.py')
        const marker = join(root, 'started')
        writeFileSync(
          settings,
          JSON.stringify({
            filesystem: { denyRead: [], allowWrite: [root], denyWrite: [] },
            network: {
              allowedDomains: [],
              deniedDomains: [],
              // Exercise bwrap's parent lifetime without requiring the helper.
              allowAllUnixSockets: true,
            },
            enableWeakerNestedSandbox: true,
          }),
        )
        writeFileSync(
          script,
          'import sys, time\nwith open(sys.argv[1], "w") as f: f.write("started")\ntime.sleep(30)\n',
        )
        const child = spawn(
          'bun',
          [
            'run',
            join(process.cwd(), 'src', 'cli.ts'),
            '-s',
            settings,
            '-c',
            quote(['python3', script, marker]),
          ],
          { detached: true, stdio: ['ignore', 'pipe', 'pipe'] },
        )
        let exited = false
        let stderr = ''
        let workload: number | undefined
        let cleanupError: unknown
        child.stdout.resume()
        child.stderr.on('data', (chunk: Buffer) => (stderr += String(chunk)))
        const finished = new Promise<void>((resolve, reject) => {
          child.once('exit', () => {
            exited = true
            resolve()
          })
          child.once('error', reject)
        })
        try {
          const started = await waitFor(
            () =>
              existsSync(marker) && readFileSync(marker, 'utf8') === 'started',
            15_000,
          )
          if (!started) throw new Error(`Workload never started: ${stderr}`)
          const workloads = readdirSync('/proc')
            .filter(name => /^\d+$/.test(name))
            .map(Number)
            .filter(pid => isWorkload(pid, script))
          expect(workloads).toHaveLength(1)
          workload = workloads[0]
          expect(child.kill(signal)).toBe(true)
          const stopped = await waitFor(
            () => exited && !isWorkload(workload!, script),
            2_000,
          )
          expect(stopped).toBe(true)
        } finally {
          // A failing main-version run must not leave its sandbox behind.
          if (
            !exited ||
            (workload !== undefined && isWorkload(workload, script))
          ) {
            try {
              process.kill(-child.pid!, 'SIGKILL')
            } catch (error) {
              if ((error as NodeJS.ErrnoException).code !== 'ESRCH') {
                cleanupError = error
              }
            }
          }
          await finished
          rmSync(root, { recursive: true, force: true })
        }
        expect(cleanupError).toBeUndefined()
      }, 30_000)
    }
  },
)
