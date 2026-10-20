import { describe, expect, it } from 'bun:test'
import {
  MXC_POLICY_VERSION,
  buildMxcContainerConfig,
  encodeMxcConfig,
} from '../../src/sandbox/mxc-sandbox-utils.js'

/**
 * Pins the exact MXC 1.0.0 one-shot request srt hands
 * `wxc-exec --config-base64`. Runs on every platform: the compiler is
 * pure (no SDK import, no Windows API), so the wire shape is checked
 * everywhere even though only a Windows host can execute it.
 */

const mxc = { exe: 'C:\\mxc\\wxc-exec.exe' } as const

/** Network fields every registered 1.x contract rejects. */
const RETIRED_NETWORK_FIELDS = [
  'allowOutbound',
  'defaultPolicy',
  'enforcementMode',
  'allowLocalNetwork',
  'allowedHosts',
  'blockedHosts',
  'proxy',
  'removeRulesOnExit',
]

describe('MXC 1.0.0 one-shot request', () => {
  it('targets the 1.0.0 contract with the process intent', () => {
    const cfg = buildMxcContainerConfig({ command: 'exit 0', mxc })
    expect(MXC_POLICY_VERSION).toBe('1.0.0')
    expect(cfg.version).toBe('1.0.0')
    expect(cfg.containment).toBe('process')
    expect(cfg.containerId).toMatch(/^[0-9a-f]{32}$/)
    expect(cfg.lifecycle).toEqual({
      destroyOnExit: true,
      preservePolicy: false,
    })
    expect(cfg.process.commandLine).toContain('exit 0')
    expect(cfg.process.timeout).toBe(0)
    // Sealed child env: an explicit list, never the broker's block.
    expect(Array.isArray(cfg.process.env)).toBe(true)
  })

  it('denies egress, ingress and host loopback explicitly without a proxy', () => {
    const cfg = buildMxcContainerConfig({ command: 'exit 0', mxc })
    expect(cfg.network).toEqual({
      egress: { default: 'deny' },
      ingress: { default: 'deny', hostLoopback: 'deny' },
    })
    expect(cfg.runtimeConfig).toBeUndefined()
  })

  it('requests the identity-less host-proxy posture with a proxy', () => {
    const cfg = buildMxcContainerConfig({
      command: 'exit 0',
      httpProxyPort: 48123,
      proxyAuthToken: 'tok',
      mxc,
    })
    // 1.0: hostLoopback no longer inherits ingress.default, and a host
    // proxy with no allowedProxyPeer needs both axes set to allow.
    expect(cfg.network).toEqual({
      egress: { default: 'deny' },
      ingress: { default: 'allow', hostLoopback: 'allow' },
    })
    expect(cfg.runtimeConfig).toEqual({
      networkProxy: 'http://srt:tok@127.0.0.1:48123',
    })
    expect(cfg.process.env).toContain(
      'HTTPS_PROXY=http://srt:tok@localhost:48123',
    )
  })

  it('emits no retired 0.x fields on the wire', () => {
    const cfg = buildMxcContainerConfig({
      command: 'exit 0',
      httpProxyPort: 1,
      mxc,
    })
    const wire = JSON.parse(
      Buffer.from(encodeMxcConfig(cfg), 'base64').toString('utf8'),
    ) as Record<string, unknown>
    for (const field of RETIRED_NETWORK_FIELDS) {
      expect(wire.network).not.toHaveProperty(field)
    }
    expect(wire).not.toHaveProperty('appContainer')
    expect(wire).not.toHaveProperty('processContainer')
  })

  it('maps the shell UI need onto ui.disable', () => {
    const cmd = buildMxcContainerConfig({ command: 'exit 0', mxc })
    expect(cmd.ui).toEqual({
      disable: true,
      clipboard: 'none',
      injection: false,
    })
    const pwsh = buildMxcContainerConfig({
      command: 'exit 0',
      mxc,
      binShell: { exe: 'C:\\pwsh\\pwsh.exe', args: ['-c'] },
    })
    expect(pwsh.ui?.disable).toBe(false)
  })
})
