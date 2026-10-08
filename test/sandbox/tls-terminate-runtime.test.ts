import { afterEach, describe, expect, test } from 'bun:test'
import { connect, type Socket } from 'node:net'
import { overrideEmittedConnectionProbe } from '../../src/sandbox/emitted-connection.js'
import { createHttpProxyServer } from '../../src/sandbox/http-proxy.js'
import { createMitmCA, generateCa } from '../../src/sandbox/mitm-ca.js'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import type { SandboxRuntimeConfig } from '../../src/sandbox/sandbox-config.js'
import { SERVES_EMITTED_CONNECTIONS } from '../helpers/emitted-connections.js'

// TLS termination runs in this process and needs an http.Server that
// serves a connection handed to it (Node, Bun 1.4 and later). Where the
// runtime has none, asking for termination fails at start-up, at both
// entry points, rather than on every tunnel.

const STARTUP_ERROR =
  /^tlsTerminate needs Node, or Bun 1\.4 or later \(this is (Bun|Node) \S+\)$/

const cleanup: Array<() => void | Promise<void>> = []
afterEach(async () => {
  while (cleanup.length) await cleanup.pop()!()
})

/** Answer the runtime probe with `serves` until the test ends. */
function pretendRuntimeServes(serves: boolean): void {
  overrideEmittedConnectionProbe(() => serves)
  cleanup.push(() => overrideEmittedConnectionProbe(undefined))
}

function testCA() {
  const ca = generateCa()
  return createMitmCA({ caCertPem: ca.certPem, caKeyPem: ca.keyPem })
}

const baseConfig = (
  network: Partial<SandboxRuntimeConfig['network']> = {},
): SandboxRuntimeConfig => ({
  network: { allowedDomains: ['a.test'], deniedDomains: [], ...network },
  filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
})

describe('a runtime that cannot terminate TLS in-process fails at start-up', () => {
  test('incompatible TLS modes leave the previous config unchanged', async () => {
    const previousConfig = SandboxManager.getConfig()
    const previouslyEnabled = SandboxManager.isSandboxingEnabled()
    cleanup.push(() => SandboxManager.reset())
    // eslint-disable-next-line @typescript-eslint/await-thenable
    await expect(
      SandboxManager.initialize(
        baseConfig({
          tlsTerminate: {},
          mitmProxy: { socketPath: 'unused', domains: ['a.test'] },
        }),
      ),
    ).rejects.toThrow('mutually exclusive')
    expect(SandboxManager.isSandboxingEnabled()).toBe(previouslyEnabled)
    expect(SandboxManager.getConfig()).toEqual(previousConfig)
    expect(SandboxManager.getProxyPort()).toBeUndefined()
  })

  test('createHttpProxyServer with a CA throws naming the requirement and the runtime; without one it starts', () => {
    pretendRuntimeServes(false)
    expect(() =>
      createHttpProxyServer({ filter: () => true, mitmCA: testCA() }),
    ).toThrow(STARTUP_ERROR)
    const plain = createHttpProxyServer({ filter: () => true })
    expect(plain.listening).toBe(false)
  })

  test('SandboxManager.initialize with tlsTerminate rejects with that error before starting anything', async () => {
    const previousConfig = SandboxManager.getConfig()
    const previouslyEnabled = SandboxManager.isSandboxingEnabled()
    pretendRuntimeServes(false)
    cleanup.push(() => SandboxManager.reset())
    // bun-types declares .rejects matchers as returning void, but bun returns
    // a Promise at runtime: the await is load-bearing for the assertion.
    // eslint-disable-next-line @typescript-eslint/await-thenable
    await expect(
      SandboxManager.initialize(baseConfig({ tlsTerminate: {} })),
    ).rejects.toThrow(STARTUP_ERROR)
    expect(SandboxManager.getProxyPort()).toBeUndefined()
    expect(SandboxManager.getMitmCA()).toBeUndefined()
    expect(SandboxManager.isSandboxingEnabled()).toBe(previouslyEnabled)
    expect(SandboxManager.getConfig()).toEqual(previousConfig)
  })

  test('SandboxManager.initialize without tlsTerminate is not affected', async () => {
    pretendRuntimeServes(false)
    cleanup.push(() => SandboxManager.reset())
    await SandboxManager.initialize(baseConfig())
    expect(SandboxManager.getProxyPort()).toBeNumber()
  }, 15_000)

  const runtime =
    typeof Bun !== 'undefined' ? `Bun ${Bun.version}` : process.version
  test(
    SERVES_EMITTED_CONNECTIONS
      ? `this runtime (${runtime}) serves handed-in connections: a terminating proxy starts`
      : `this runtime (${runtime}) cannot: a terminating proxy fails to start, naming it`,
    () => {
      const start = () =>
        createHttpProxyServer({ filter: () => true, mitmCA: testCA() })
      if (SERVES_EMITTED_CONNECTIONS) {
        expect(start).not.toThrow()
      } else {
        expect(start).toThrow(`(this is ${runtime})`)
      }
    },
  )
})

/** A CONNECT to a.test:443 through the manager's proxy: the reply head and the socket. */
function connectThroughManager(): Promise<{ head: string; sock: Socket }> {
  const port = SandboxManager.getProxyPort()!
  const auth = Buffer.from(`srt:${SandboxManager.getProxyAuthToken()!}`)
  return new Promise(resolve => {
    const sock = connect(port, '127.0.0.1', () =>
      sock.write(
        'CONNECT a.test:443 HTTP/1.1\r\nHost: a.test:443\r\n' +
          `Proxy-Authorization: Basic ${auth.toString('base64')}\r\n\r\n`,
      ),
    )
    sock.on('error', () => {})
    cleanup.push(() => void sock.destroy())
    let head = ''
    sock.on('data', (d: Buffer) => {
      head += d.toString('latin1')
      if (head.includes('\r\n\r\n')) resolve({ head, sock })
    })
  })
}

describe.skipIf(!SERVES_EMITTED_CONNECTIONS)(
  "the manager's proxy takes its tunnel cap and handshake deadline from tlsTerminate",
  () => {
    test('maxTunnels: 1 answers a second tunnel 503; handshakeTimeoutMs closes a silent one and frees its slot', async () => {
      cleanup.push(() => SandboxManager.reset())
      await SandboxManager.initialize(
        baseConfig({
          tlsTerminate: { maxTunnels: 1, handshakeTimeoutMs: 500 },
        }),
      )
      const first = await connectThroughManager()
      expect(first.head).toStartWith('HTTP/1.1 200')
      const openedAt = Date.now()
      const firstClosed = new Promise<number>(r =>
        first.sock.once('close', () => r(Date.now())),
      )
      const second = await connectThroughManager()
      expect(second.head).toStartWith('HTTP/1.1 503')
      expect(second.head).toContain('X-Proxy-Error: too-many-tunnels')
      // The silent first tunnel is closed at the deadline, well before the
      // default 10 s.
      const closedAt = await firstClosed
      expect(closedAt - openedAt).toBeGreaterThanOrEqual(400)
      expect(closedAt - openedAt).toBeLessThan(5_000)
      await new Promise(r => setTimeout(r, 50))
      const third = await connectThroughManager()
      expect(third.head).toStartWith('HTTP/1.1 200')
    }, 20_000)
  },
)
