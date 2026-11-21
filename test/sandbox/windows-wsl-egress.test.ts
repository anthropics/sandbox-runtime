import { describe, expect, it } from 'bun:test'
import { spawnSync } from 'node:child_process'
import * as path from 'node:path'
import {
  interpretWindowsWfpVerify,
  WINDOWS_BLOCK_WSL_NAT_EFFECT,
} from '../../src/sandbox/windows-sandbox-utils.js'

const CLI_PATH = path.join(process.cwd(), 'dist', 'cli.js')

function baseVerifyPayload(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({
    egress_probe: 'blocked',
    anonymous_probe: 'skipped',
    anonymous_loopback_probe: 'blocked',
    deny_only_probe: 'blocked',
    low_integrity_probe: 'blocked',
    low_integrity_loopback_probe: 'blocked',
    untrusted_integrity_probe: 'blocked',
    untrusted_integrity_loopback_probe: 'blocked',
    open_loopback_probe: 'skipped',
    target: '127.0.0.1:49999',
    egress_target: '127.0.0.1:49999',
    anonymous_target: '192.0.2.10:49999',
    allow_loopback: false,
    residuals: [],
    ...overrides,
  })
}

describe('Windows WFP WSL reachability residual & --block-wsl-nat surface', () => {
  it('surfaces wsl_probe and wsl-reachable residual warning without failing the fence check', () => {
    const result = interpretWindowsWfpVerify({
      status: 0,
      stdout: baseVerifyPayload({
        wsl_probe: 'connected',
        residuals: ['wsl-reachable'],
      }),
      stderr: '',
    })

    expect(result.probes.plain).toBe('blocked')
    expect(result.probes.wsl).toBe('connected')
    expect(result.residuals).toEqual(['wsl-reachable'])
    expect(result.warnings).toHaveLength(1)
    expect(result.warnings[0]).toContain("residual 'wsl-reachable'")
    expect(result.warnings[0]).toContain('--block-wsl-nat')
  })

  it('produces no warning when wsl_probe is blocked or skipped', () => {
    for (const wslProbe of ['blocked', 'skipped', 'unreachable'] as const) {
      const result = interpretWindowsWfpVerify({
        status: 0,
        stdout: baseVerifyPayload({
          wsl_probe: wslProbe,
          residuals: [],
        }),
        stderr: '',
      })
      expect(result.probes.wsl).toBe(wslProbe)
      expect(result.residuals).toEqual([])
      expect(result.warnings).toEqual([])
    }
  })

  it('stays backward-compatible with older srt-win verify output omitting wsl_probe', () => {
    const result = interpretWindowsWfpVerify({
      status: 0,
      stdout: baseVerifyPayload(),
      stderr: '',
    })
    expect('wsl' in result.probes).toBe(false)
    expect(result.residuals).toEqual([])
    expect(result.warnings).toEqual([])
  })

  it('includes --block-wsl-nat in suggested reinstall command when configured in install context', () => {
    let caught: Error | undefined
    try {
      interpretWindowsWfpVerify(
        {
          status: 3,
          stdout: baseVerifyPayload({
            egress_probe: 'connected',
            wsl_probe: 'connected',
          }),
          stderr: 'fence inactive',
        },
        { blockWslNat: true },
      )
    } catch (err) {
      caught = err as Error
    }
    expect(caught).toBeInstanceOf(Error)
    expect(caught?.message).toContain('--block-wsl-nat')
    expect(caught?.message).toContain('wsl=connected')
  })

  it('exposes --block-wsl-nat on srt windows-install --help and plain effect notice', () => {
    expect(WINDOWS_BLOCK_WSL_NAT_EFFECT).toContain('IPFORWARD')
    expect(WINDOWS_BLOCK_WSL_NAT_EFFECT).toContain('--block-wsl-nat')

    const help = spawnSync('node', [CLI_PATH, 'windows-install', '--help'], {
      stdio: ['ignore', 'pipe', 'pipe'],
      encoding: 'utf8',
      timeout: 4500,
    })
    expect(help.status).toBe(0)
    expect(help.stdout).toContain('--block-wsl-nat')
  })
})
