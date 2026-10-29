import { describe, expect, it } from 'bun:test'
import {
  buildMxcRequest,
  mxcProbeRefusals,
  spawnMxcRequest,
  verifyMxcBackend,
  type MxcProbeOutput,
  type MxcProcessHandle,
  type MxcRequest,
  type MxcSdk,
} from '../../src/sandbox/mxc-sandbox-utils.js'

/**
 * The request srt hands the MXC SDK, and the probe gate in front of
 * every spawn. Runs on every platform: request building is pure and
 * the SDK is a fake here, so only a Windows host runs the real thing.
 */

/** A probe answer that supports everything srt asks for. */
function fullSupport(): MxcProbeOutput {
  return {
    tier: 'base-container',
    needsDaclAugmentation: false,
    warnings: [],
    probes: {
      baseContainerSupportsDenyPaths: true,
      baseContainerSupportsIngressHostLoopbackAllow: true,
      baseContainerSupportsIdentitylessLoopbackProxy: true,
      uiCapabilities: {
        canBlockClipboardRead: true,
        canBlockClipboardWrite: true,
        canBlockInputInjection: true,
      },
    },
  }
}

/** A request with a proxy and a denied path, so every check applies. */
function strictRequest(): MxcRequest {
  return buildMxcRequest({
    command: 'exit 0',
    httpProxyPort: 48123,
    proxyAuthToken: 'tok',
    denyRead: ['C:\\secret'],
  })
}

function fakeSdk(probe: () => MxcProbeOutput): {
  sdk: MxcSdk
  spawned: MxcRequest[]
} {
  const spawned: MxcRequest[] = []
  const sdk: MxcSdk = {
    probe: () => probe(),
    spawn: request => {
      spawned.push(request)
      return Promise.resolve({ id: 1 } as unknown as MxcProcessHandle)
    },
  }
  return { sdk, spawned }
}

describe('MXC SDK request', () => {
  it('seals the environment and sets no backend containment', () => {
    const req = buildMxcRequest({ command: 'exit 0' })
    expect(req.command).toContain('exit 0')
    expect(req.inheritDefaultEnvironment).toBe(false)
    expect(req).not.toHaveProperty('containment')
    expect(req).not.toHaveProperty('timeoutMs')
    expect(typeof req.environment).toBe('object')
  })

  it('denies egress, ingress and host loopback explicitly without a proxy', () => {
    const req = buildMxcRequest({ command: 'exit 0' })
    expect(req.network).toEqual({
      egress: { default: 'deny' },
      ingress: { default: 'deny', hostLoopback: 'deny' },
    })
  })

  it('routes egress through the host proxy when there is one', () => {
    const req = buildMxcRequest({
      command: 'exit 0',
      httpProxyPort: 48123,
      proxyAuthToken: 'tok',
    })
    expect(req.network).toEqual({
      egress: { default: 'deny' },
      ingress: { default: 'allow', hostLoopback: 'allow' },
      runtimeConfig: { networkProxy: 'http://srt:tok@127.0.0.1:48123' },
    })
    expect(req.environment.HTTPS_PROXY).toBe('http://srt:tok@localhost:48123')
    expect(req.environment).not.toHaveProperty('NO_PROXY')
  })

  it('keeps UI on for every shell, with clipboard and injection blocked', () => {
    for (const binShell of [
      undefined,
      { exe: 'C:\\Windows\\System32\\cmd.exe', args: ['/c'] },
      { exe: 'C:\\pwsh\\pwsh.exe', args: ['-c'] },
    ]) {
      expect(buildMxcRequest({ command: 'exit 0', binShell }).ui).toEqual({
        disable: false,
        clipboard: 'none',
        allowInputInjection: false,
      })
    }
  })

  it('maps reads, writes and denies onto the allow-list model', () => {
    const req = buildMxcRequest({
      command: 'exit 0',
      cwd: 'C:\\work',
      allowRead: ['D:\\data'],
      allowWrite: ['C:\\work\\out'],
      denyRead: ['C:\\work\\secret'],
      denyWrite: ['C:\\work\\out\\keep'],
      timeoutMs: 5000,
    })
    expect(req.workingDirectory).toBe('C:\\work')
    expect(req.filesystem.readonlyPaths).toContain('C:\\work')
    expect(req.filesystem.readonlyPaths).toContain('D:\\data')
    expect(req.filesystem.readwritePaths).toContain('C:\\work\\out')
    expect(req.filesystem.readwritePaths).not.toContain('C:\\work')
    expect(req.filesystem.deniedPaths).toEqual([
      'C:\\work\\secret',
      'C:\\work\\out\\keep',
    ])
    expect(req.timeoutMs).toBe(5000)
  })

  it('does not pass the host environment through', () => {
    process.env.SRT_MXC_HOST_ONLY = 'host-secret'
    try {
      const req = buildMxcRequest({
        command: 'exit 0',
        setEnvVars: { MASKED: 'sentinel' },
      })
      expect(req.environment).not.toHaveProperty('SRT_MXC_HOST_ONLY')
      expect(req.environment.MASKED).toBe('sentinel')
    } finally {
      delete process.env.SRT_MXC_HOST_ONLY
    }
  })
})

describe('MXC probe gate (fail closed)', () => {
  it('accepts a request the probe fully supports', async () => {
    const { sdk, spawned } = fakeSdk(fullSupport)
    expect(mxcProbeRefusals(strictRequest(), fullSupport())).toEqual([])
    await spawnMxcRequest(sdk, strictRequest())
    expect(spawned).toHaveLength(1)
  })

  const unsupported: Array<[string, (p: MxcProbeOutput) => void, RegExp]> = [
    ['an AppContainer tier', p => (p.tier = 'appcontainer-dacl'), /tier/],
    ['no tier', p => delete p.tier, /tier 'none'/],
    ['DACL augmentation', p => (p.needsDaclAugmentation = true), /DACL/],
    [
      'no denied-path support',
      p => (p.probes.baseContainerSupportsDenyPaths = false),
      /denied paths/,
    ],
    [
      'no host-proxy confinement',
      p => (p.probes.baseContainerSupportsIdentitylessLoopbackProxy = false),
      /host proxy/,
    ],
    [
      'no host loopback',
      p => (p.probes.baseContainerSupportsIngressHostLoopbackAllow = false),
      /host loopback/,
    ],
    [
      'no clipboard blocking',
      p => (p.probes.uiCapabilities.canBlockClipboardRead = false),
      /clipboard/,
    ],
    [
      'no input-injection blocking',
      p => (p.probes.uiCapabilities.canBlockInputInjection = false),
      /input injection/,
    ],
    ['a detector error', p => (p.error = 'detector broke'), /detector broke/],
  ]
  for (const [what, degrade, message] of unsupported) {
    it(`refuses to spawn when the probe reports ${what}`, async () => {
      const { sdk, spawned } = fakeSdk(() => {
        const p = fullSupport()
        degrade(p)
        return p
      })
      // eslint-disable-next-line @typescript-eslint/await-thenable
      await expect(spawnMxcRequest(sdk, strictRequest())).rejects.toMatchObject(
        {
          code: 'backend_unsupported',
          message: expect.stringMatching(message),
        },
      )
      expect(spawned).toHaveLength(0)
    })
  }

  it('refuses to spawn when the probe throws', async () => {
    const { sdk, spawned } = fakeSdk(() => {
      throw new Error('mxc_ffi missing')
    })
    // eslint-disable-next-line @typescript-eslint/await-thenable
    await expect(spawnMxcRequest(sdk, strictRequest())).rejects.toMatchObject({
      code: 'backend_unsupported',
      message: expect.stringContaining('mxc_ffi missing'),
    })
    expect(spawned).toHaveLength(0)
  })

  it('only checks denied-path and proxy support when the request uses them', () => {
    const p = fullSupport()
    p.probes.baseContainerSupportsDenyPaths = false
    p.probes.baseContainerSupportsIdentitylessLoopbackProxy = false
    p.probes.baseContainerSupportsIngressHostLoopbackAllow = false
    expect(mxcProbeRefusals(buildMxcRequest({ command: 'x' }), p)).toEqual([])
  })

  it('verifyMxcBackend reports the deny capability and refuses like spawn', () => {
    const p = fullSupport()
    p.probes.baseContainerSupportsDenyPaths = false
    const req = buildMxcRequest({ command: 'x' })
    expect(verifyMxcBackend(fakeSdk(() => p).sdk, req)).toEqual({
      backend: 'mxc',
      denyPathsSupported: false,
    })
    p.tier = 'appcontainer-bfs'
    expect(() => verifyMxcBackend(fakeSdk(() => p).sdk, req)).toThrow(
      /BaseContainer is required/,
    )
  })
})
