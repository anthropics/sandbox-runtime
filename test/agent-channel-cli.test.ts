import { describe, it, expect, beforeAll, afterAll } from 'bun:test'
import { spawn } from 'node:child_process'
import * as fs from 'node:fs'
import * as os from 'node:os'
import * as path from 'node:path'
import { isLinux, isMacOS } from './helpers/platform.js'

/**
 * End-to-end tests for `srt --agent-channel`, driving the reference agent
 * (examples/agent-demo.sh) inside a real sandbox:
 *
 *   - the wrapped command sees the channel fd named by
 *     SANDBOX_AGENT_CHANNEL_FD
 *   - a host no rule covers is asked over the channel, and the agent's
 *     allow/deny decides the request
 *   - an agent deny is NOT echoed back to it as a `blocked` message
 *   - a config-denied host is never asked, but produces a `blocked` message
 */

const CLI_PATH = path.join(process.cwd(), 'dist', 'cli.js')
const AGENT_DEMO = path.join(process.cwd(), 'examples', 'agent-demo.sh')

const TEST_TIMEOUT = 30000

interface RunResult {
  stdout: string
  stderr: string
  combined: string
  exitCode: number | null
}

function runSrt(
  args: string[],
  env: Record<string, string> = {},
): Promise<RunResult> {
  return new Promise((resolve, reject) => {
    const child = spawn('node', [CLI_PATH, ...args], {
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, ...env },
    })
    let stdout = ''
    let stderr = ''
    let combined = ''
    child.stdout.on('data', (data: Buffer) => {
      stdout += data.toString()
      combined += data.toString()
    })
    child.stderr.on('data', (data: Buffer) => {
      stderr += data.toString()
      combined += data.toString()
    })
    const timer = setTimeout(() => {
      child.kill('SIGKILL')
    }, TEST_TIMEOUT - 2000)
    child.on('exit', code => {
      clearTimeout(timer)
      resolve({ stdout, stderr, combined, exitCode: code })
    })
    child.on('error', err => {
      clearTimeout(timer)
      reject(err)
    })
  })
}

describe.if(isMacOS || isLinux)('srt --agent-channel', () => {
  let tmpDir: string
  let settingsPath: string

  beforeAll(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-channel-test-'))
    settingsPath = path.join(tmpDir, 'settings.json')
    fs.writeFileSync(
      settingsPath,
      JSON.stringify({
        network: {
          allowedDomains: [],
          deniedDomains: ['blocked.example'],
        },
        filesystem: {
          denyRead: [],
          allowRead: [],
          allowWrite: [tmpDir],
          denyWrite: [],
        },
      }),
    )
  })

  afterAll(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true })
  })

  it(
    'exposes the channel to the wrapped command on SANDBOX_AGENT_CHANNEL_FD',
    async () => {
      const result = await runSrt([
        '-s',
        settingsPath,
        '--agent-channel',
        '--',
        'sh',
        '-c',
        'echo "FD=$SANDBOX_AGENT_CHANNEL_FD"',
      ])
      expect(result.stdout).toContain('FD=3')
      expect(result.exitCode).toBe(0)
    },
    TEST_TIMEOUT,
  )

  it(
    'denies an uncovered host when the agent answers deny, without echoing it back as blocked',
    async () => {
      const result = await runSrt(
        [
          '-s',
          settingsPath,
          '--agent-channel',
          '--',
          AGENT_DEMO,
          'bash',
          '-c',
          'sleep 0.3; curl -s --max-time 10 http://ask-me.example >/dev/null; echo "curl-exit=$?"; sleep 1',
        ],
        { SRT_AGENT_DEMO_BEHAVIOR: 'deny' },
      )
      // The permission_request round-tripped and the agent denied it.
      expect(result.stderr).toContain('Connecting to ask-me.example:80 → deny')
      // The deny was the agent's own decision, so no `blocked` message
      // reports it back.
      const blockedLines = result.stderr
        .split('\n')
        .filter(line => line.includes('sandbox blocked an action'))
      expect(blockedLines.filter(l => l.includes('ask-me.example'))).toEqual([])
    },
    TEST_TIMEOUT,
  )

  it(
    'allows an uncovered host when the agent answers allow',
    async () => {
      const result = await runSrt(
        [
          '-s',
          settingsPath,
          '--agent-channel',
          '--',
          AGENT_DEMO,
          'bash',
          '-c',
          'sleep 0.3; curl -s --max-time 10 http://ask-me.example >/dev/null; sleep 1',
        ],
        { SRT_AGENT_DEMO_BEHAVIOR: 'allow' },
      )
      // The request round-tripped and the agent's allow reached the proxy.
      // (The host doesn't resolve, so the connection itself goes nowhere —
      // what's under test is the permission flow.)
      expect(result.stderr).toContain('Connecting to ask-me.example:80 → allow')
    },
    TEST_TIMEOUT,
  )

  it(
    'reports a config-denied host to the agent as blocked without asking',
    async () => {
      const result = await runSrt(
        [
          '-s',
          settingsPath,
          '--agent-channel',
          '--',
          AGENT_DEMO,
          'bash',
          '-c',
          'sleep 0.3; curl -s --max-time 10 http://blocked.example >/dev/null; sleep 2',
        ],
        { SRT_AGENT_DEMO_BEHAVIOR: 'allow' },
      )
      // The sandbox's own policy decided, so the agent was never asked...
      expect(result.stderr).not.toContain('blocked.example:80 → ')
      // ...but it was told about the block.
      const blockedLines = result.stderr
        .split('\n')
        .filter(line => line.includes('sandbox blocked an action'))
      expect(
        blockedLines.filter(line => line.includes('blocked.example')),
      ).not.toEqual([])
    },
    TEST_TIMEOUT,
  )
})
