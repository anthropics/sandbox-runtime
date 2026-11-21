import { describe, expect, it } from 'bun:test'
import { spawnSync } from 'node:child_process'
import * as fs from 'node:fs'
import * as os from 'node:os'
import * as path from 'node:path'
import { PassThrough } from 'node:stream'
import type { SandboxRuntimeConfig } from '../src/sandbox/sandbox-config.js'
import {
  applyDeciderHelloToConfig,
  assertDeciderCompatibleConfig,
  buildSandboxedStdio,
  connectCliDecider,
  DEFAULT_DECIDER_TIMEOUT_MS,
  parseDeciderTimeoutMs,
  parseInheritedFd,
  resolveCliDeciderSpec,
} from '../src/utils/cli-decider.js'
import { fakeDecider } from './helpers/fake-decider.js'
import { isWindows } from './helpers/platform.js'

const CLI_PATH = path.join(process.cwd(), 'dist', 'cli.js')

const RUNTIMES: Array<{ name: string; bin: string }> = [
  { name: 'node', bin: 'node' },
  ...(process.versions.bun ? [{ name: 'bun', bin: process.execPath }] : []),
]

function baseConfig(
  overrides?: Partial<SandboxRuntimeConfig['network']>,
): SandboxRuntimeConfig {
  return {
    network: {
      allowedDomains: [],
      deniedDomains: [],
      ...overrides,
    },
    filesystem: {
      denyRead: [],
      allowRead: [],
      allowWrite: [],
      denyWrite: [],
    },
  }
}

describe('CLI external decider helpers', () => {
  it('parses inherited fds >= 3 and decider timeout values', () => {
    expect(parseInheritedFd('3')).toBe(3)
    expect(parseInheritedFd('19')).toBe(19)
    for (const bad of ['0', '1', '2', '-1', 'abc', '0x10', '3e0', ' 4 ']) {
      expect(() => parseInheritedFd(bad)).toThrow(
        'must be an integer file descriptor >= 3',
      )
    }

    expect(parseDeciderTimeoutMs('1')).toBe(1)
    expect(parseDeciderTimeoutMs('5000')).toBe(5000)
    expect(parseDeciderTimeoutMs('600000')).toBe(600_000)
    for (const bad of ['0', '-5', '600001', 'abc', '1e3', '5.5']) {
      expect(() => parseDeciderTimeoutMs(bad)).toThrow(
        'must be an integer between 1 and 600000',
      )
    }
  })

  it('resolves valid decider flag combinations and rejects conflicts', () => {
    expect(resolveCliDeciderSpec({}, 'linux')).toBeUndefined()

    expect(resolveCliDeciderSpec({ deciderFd: 5 }, 'linux')).toEqual({
      inFd: 5,
      outFd: 5,
      fds: [5],
      timeoutMs: DEFAULT_DECIDER_TIMEOUT_MS,
    })

    expect(
      resolveCliDeciderSpec(
        { deciderIn: 5, deciderOut: 6, deciderTimeoutMs: 2500, controlFd: 3 },
        'darwin',
      ),
    ).toEqual({
      inFd: 5,
      outFd: 6,
      fds: [5, 6],
      timeoutMs: 2500,
    })

    expect(() =>
      resolveCliDeciderSpec({ deciderTimeoutMs: 1000 }, 'linux'),
    ).toThrow('--decider-timeout-ms requires')

    expect(() =>
      resolveCliDeciderSpec({ deciderFd: 4, deciderIn: 5 }, 'linux'),
    ).toThrow('--decider-fd cannot be combined')

    expect(() => resolveCliDeciderSpec({ deciderIn: 5 }, 'linux')).toThrow(
      '--decider-in and --decider-out must be provided together',
    )

    expect(() => resolveCliDeciderSpec({ deciderOut: 6 }, 'linux')).toThrow(
      '--decider-in and --decider-out must be provided together',
    )

    expect(() =>
      resolveCliDeciderSpec({ deciderIn: 5, deciderOut: 5 }, 'linux'),
    ).toThrow('--decider-in and --decider-out must be distinct')

    expect(() =>
      resolveCliDeciderSpec({ controlFd: 5, deciderFd: 5 }, 'linux'),
    ).toThrow('--control-fd cannot share a file descriptor')

    expect(() =>
      resolveCliDeciderSpec(
        { controlFd: 6, deciderIn: 5, deciderOut: 6 },
        'linux',
      ),
    ).toThrow('--control-fd cannot share a file descriptor')

    expect(() => resolveCliDeciderSpec({ deciderFd: 5 }, 'win32')).toThrow(
      'not supported on Windows',
    )
  })

  it('displaces every inherited control and decider fd slot with /dev/null', () => {
    expect(buildSandboxedStdio([], () => 99)).toEqual([
      'inherit',
      'inherit',
      'inherit',
    ])

    let nextNull = 100
    const stdio = buildSandboxedStdio([8, 3, 5, 5], () => nextNull++)
    expect(stdio).toEqual([
      'inherit',
      'inherit',
      'inherit',
      100, // fd 3
      'ignore', // fd 4
      101, // fd 5
      'ignore', // fd 6
      'ignore', // fd 7
      102, // fd 8
    ])
  })

  it('merges hello egress lists monotonically and rejects conflicting settings', () => {
    const dummyFilter = async () => ({ action: 'allow' as const })
    const merged = applyDeciderHelloToConfig(
      baseConfig({ deniedDomains: ['blocked.local', 'dup.local'] }),
      {
        t: 'hello',
        proto: 1,
        allowedDomains: ['api.example.com'],
        deniedDomains: ['dup.local', 'evil.example.com'],
      },
      dummyFilter,
    )

    expect(merged.network.allowedDomains).toEqual(['api.example.com'])
    expect(merged.network.deniedDomains).toEqual([
      'blocked.local',
      'dup.local',
      'evil.example.com',
    ])
    expect(merged.network.filterRequest).toBe(dummyFilter)

    expect(() =>
      assertDeciderCompatibleConfig(
        baseConfig({ allowedDomains: ['settings.example.com'] }),
      ),
    ).toThrow('network.allowedDomains in settings must be empty')

    expect(() =>
      assertDeciderCompatibleConfig(baseConfig({ httpProxyPort: 8080 })),
    ).toThrow('network.httpProxyPort cannot be combined')
  })

  it('completes v1 hello handshake, forwards allow/deny verdicts, and handles post-hello death', async () => {
    const deadReasons: string[] = []
    const fake = fakeDecider(
      ['api.example.com'],
      frame => {
        if (frame.path === '/ok') {
          return {
            action: 'allow',
            setHeaders: { 'x-decider': ['checked'] },
            removeHeaders: ['x-untrusted'],
          }
        }
        if (frame.path === '/crash') {
          return 'garbage'
        }
        return { action: 'deny', status: 451, reason: 'blocked by policy' }
      },
      ['denied.example.com'],
    )

    const { decider, hello } = await connectCliDecider({
      streams: fake.streams,
      timeoutMs: 2000,
      onDead: why => deadReasons.push(why),
    })

    const cfg = applyDeciderHelloToConfig(
      baseConfig({ deniedDomains: ['settings-deny.example.com'] }),
      hello,
      decider.filterRequest,
    )
    expect(cfg.network.allowedDomains).toEqual(['api.example.com'])
    expect(cfg.network.deniedDomains).toEqual([
      'settings-deny.example.com',
      'denied.example.com',
    ])

    const allowRes = await decider.filterRequest(
      new Request('https://api.example.com/ok', {
        method: 'GET',
        headers: { 'x-untrusted': 'drop-me' },
      }),
      {
        scheme: 'https',
        sni: 'api.example.com',
        target: { host: 'api.example.com', port: 443 },
        requestTarget: '/ok',
      },
    )
    expect(allowRes).toEqual({
      action: 'allow',
      setHeaders: [['x-decider', 'checked']],
      removeHeaders: ['x-untrusted'],
    })

    const denyRes = await decider.filterRequest(
      new Request('https://api.example.com/secret', { method: 'POST' }),
      {
        scheme: 'https',
        sni: 'api.example.com',
        target: { host: 'api.example.com', port: 443 },
        requestTarget: '/secret',
      },
    )
    expect(denyRes).toEqual({
      action: 'deny',
      status: 451,
      reason: 'blocked by policy',
      mark: 'decider',
    })

    // Trigger a protocol violation after hello: fails closed and notifies onDead.
    const crashRes = await decider.filterRequest(
      new Request('https://api.example.com/crash', { method: 'GET' }),
      {
        scheme: 'https',
        sni: 'api.example.com',
        target: { host: 'api.example.com', port: 443 },
        requestTarget: '/crash',
      },
    )
    expect(crashRes.action).toBe('deny')
    if (crashRes.action === 'deny') {
      expect(crashRes.status).toBe(503)
    }
    expect(deadReasons.length).toBe(1)

    decider.close()
  })

  it('rejects startup cleanly without firing onDead if decider closes before hello', async () => {
    const input = new PassThrough()
    const output = new PassThrough()
    const deadReasons: string[] = []

    const pending = connectCliDecider({
      streams: { input, output },
      timeoutMs: 2000,
      onDead: why => deadReasons.push(why),
    })

    input.end()

    const err = await pending.then(
      () => null,
      (e: Error) => e,
    )
    expect(err).toBeInstanceOf(Error)
    expect(err?.message).toContain('decider unavailable')
    expect(deadReasons).toHaveLength(0)
  })

  it('does not invoke onDead when closed cleanly by caller after hello', async () => {
    const deadReasons: string[] = []
    const fake = fakeDecider(['api.example.com'], () => ({ action: 'allow' }))
    const { decider } = await connectCliDecider({
      streams: fake.streams,
      timeoutMs: 2000,
      onDead: why => deadReasons.push(why),
    })

    decider.close()
    expect(deadReasons).toHaveLength(0)
  })
})

describe('CLI --decider-* flag handling', () => {
  for (const runtime of RUNTIMES) {
    it(`rejects invalid decider flag combinations before running anything (${runtime.name})`, () => {
      const run = (args: string[]) =>
        spawnSync(runtime.bin, [CLI_PATH, ...args], {
          stdio: ['ignore', 'pipe', 'pipe'],
          encoding: 'utf8',
          timeout: 4500,
        })

      const badFd = run(['--decider-fd', '2', '--', 'echo', 'NO'])
      expect(badFd.status).toBe(1)
      expect(badFd.stdout).not.toContain('NO')
      expect(badFd.stderr).toContain('must be an integer file descriptor >= 3')

      const badTimeout = run([
        '--decider-fd',
        '5',
        '--decider-timeout-ms',
        '0',
        '--',
        'echo',
        'NO',
      ])
      expect(badTimeout.status).toBe(1)
      expect(badTimeout.stderr).toContain('must be an integer between 1')

      const mixed = run([
        '--decider-fd',
        '4',
        '--decider-in',
        '5',
        '--decider-out',
        '6',
        '--',
        'echo',
        'NO',
      ])
      expect(mixed.status).toBe(1)
      expect(mixed.stderr).toContain('--decider-fd cannot be combined')

      const halfPair = run(['--decider-in', '5', '--', 'echo', 'NO'])
      expect(halfPair.status).toBe(1)
      expect(halfPair.stderr).toContain(
        '--decider-in and --decider-out must be provided together',
      )

      const collision = run([
        '--control-fd',
        '5',
        '--decider-fd',
        '5',
        '--',
        'echo',
        'NO',
      ])
      expect(collision.status).toBe(1)
      expect(collision.stderr).toContain(
        '--control-fd cannot share a file descriptor',
      )

      if (isWindows) {
        const winRefusal = run(['--decider-fd', '5', '--', 'echo', 'NO'])
        expect(winRefusal.status).toBe(1)
        expect(winRefusal.stdout).not.toContain('NO')
        expect(winRefusal.stderr).toContain('not supported on Windows')
      }
    })
  }

  it.skipIf(isWindows)(
    'refuses conflicting settings allowedDomains and unusable decider fds on POSIX',
    () => {
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cli-decider-test-'))
      try {
        const settings = path.join(tmpDir, 'settings.json')
        fs.writeFileSync(
          settings,
          JSON.stringify({
            network: {
              allowedDomains: ['example.com'],
              deniedDomains: [],
            },
            filesystem: {
              denyRead: [],
              allowRead: [],
              allowWrite: [],
              denyWrite: [],
            },
          }),
        )

        const conflict = spawnSync(
          'node',
          [
            CLI_PATH,
            '--settings',
            settings,
            '--decider-fd',
            '200',
            '--',
            'echo',
            'NO',
          ],
          {
            stdio: ['ignore', 'pipe', 'pipe'],
            encoding: 'utf8',
            timeout: 4500,
          },
        )
        expect(conflict.status).toBe(1)
        expect(conflict.stdout).not.toContain('NO')
        expect(conflict.stderr).toContain(
          'network.allowedDomains in settings must be empty',
        )

        const closedFd = spawnSync(
          'node',
          [CLI_PATH, '--decider-fd', '200', '--', 'echo', 'NO'],
          {
            stdio: ['ignore', 'pipe', 'pipe'],
            encoding: 'utf8',
            timeout: 4500,
          },
        )
        expect(closedFd.status).toBe(1)
        expect(closedFd.stdout).not.toContain('NO')
        expect(closedFd.stderr).toContain(
          'external decider descriptor is not usable',
        )
      } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true })
      }
    },
  )
})
