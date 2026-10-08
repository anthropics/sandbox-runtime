import { afterEach, describe, expect, test } from 'bun:test'
import { createServer as createHttpsServer } from 'node:https'
import { connect, type AddressInfo, type Socket } from 'node:net'
import { Duplex } from 'node:stream'
import { connect as tlsConnect, type SecureVersion } from 'node:tls'
import { createHttpProxyServer } from '../../src/sandbox/http-proxy.js'
import { createMitmCA, generateCa } from '../../src/sandbox/mitm-ca.js'
import { mintLeafCert } from '../../src/sandbox/mitm-leaf.js'
import { SERVES_EMITTED_CONNECTIONS } from '../helpers/emitted-connections.js'

// Long enough that a handshake on a busy machine fits well inside it.
const HANDSHAKE_MS = 1500
const TEST_MS = 30_000
const VERSIONS: SecureVersion[] = ['TLSv1.2', 'TLSv1.3']

const cleanup: Array<() => Promise<void> | void> = []
afterEach(async () => {
  while (cleanup.length) await cleanup.pop()!()
})

type Tunnel = { raw: Socket; openedAt: number; closed: Promise<number> }

/**
 * A proxy that terminates TLS on one tunnel at a time, with a short
 * handshake deadline, in front of an HTTPS upstream on loopback.
 */
async function serve() {
  const ca = generateCa()
  const mitmCA = createMitmCA({ caCertPem: ca.certPem, caKeyPem: ca.keyPem })
  const leaf = mintLeafCert(mitmCA, '127.0.0.1')
  const leafOnly = leaf.certPem.match(
    /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\r?\n?/,
  )![0]
  const up = createHttpsServer({ cert: leafOnly, key: leaf.keyPem }, (_, res) =>
    res.end('ok'),
  )
  await new Promise<void>(r => up.listen(0, '127.0.0.1', r))
  const proxy = createHttpProxyServer({
    filter: () => true,
    mitmCA,
    shouldTerminateTLS: () => true,
    tlsTerminateUpstreamCA: ca.certPem,
    tlsHandshakeTimeoutMs: HANDSHAKE_MS,
    maxTerminatedTunnels: 1,
  })
  await new Promise<void>(r => proxy.listen(0, '127.0.0.1', r))
  for (const server of [up, proxy]) {
    cleanup.push(
      () =>
        new Promise<void>(r => {
          server.close(() => r())
          server.closeAllConnections()
        }),
    )
  }
  const target = `127.0.0.1:${(up.address() as AddressInfo).port}`
  const port = (proxy.address() as AddressInfo).port

  /** The status line of the answer to a CONNECT, and the tunnel if it is 200. */
  const connectTo = (): Promise<{ status: string; tunnel: Tunnel }> =>
    new Promise((resolve, reject) => {
      const raw = connect(port, '127.0.0.1', () =>
        raw.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`),
      )
      raw.on('error', reject)
      const closed = new Promise<number>(r =>
        raw.once('close', () => r(Date.now())),
      )
      let head = ''
      const onData = (x: Buffer): void => {
        head += x.toString('latin1')
        if (!head.includes('\r\n\r\n')) return
        raw.off('data', onData)
        raw.off('error', reject)
        raw.on('error', () => {})
        const status = head.slice(0, head.indexOf('\r\n'))
        resolve({ status, tunnel: { raw, openedAt: Date.now(), closed } })
      }
      raw.on('data', onData)
    })
  const open = async (): Promise<Tunnel> => {
    const { status, tunnel } = await connectTo()
    expect(status).toContain(' 200 ')
    return tunnel
  }
  const tlsOptions = (version: SecureVersion) => ({
    ca: ca.certPem,
    checkServerIdentity: () => undefined,
    ALPNProtocols: ['http/1.1'],
    minVersion: version,
    maxVersion: version,
  })
  return { target, connectTo, open, tlsOptions }
}

/**
 * A real TLS client whose writes to the tunnel are gated: `partialHello`
 * lets only the first 20 bytes of its ClientHello through; `noFinished`
 * lets the whole ClientHello through and drops everything the client sends
 * once the server has spoken (so its Finished never arrives).
 */
function stalledClient(
  { raw }: Tunnel,
  stall: 'partialHello' | 'noFinished',
  options: ReturnType<Awaited<ReturnType<typeof serve>>['tlsOptions']>,
): { serverSpoke: () => boolean; dropped: () => number } {
  let sent = 0
  let dropped = 0
  let serverSpoke = false
  const gate = new Duplex({
    read() {},
    write(chunk: Buffer, _encoding, callback) {
      const allowed =
        stall === 'partialHello'
          ? Math.max(0, 20 - sent)
          : serverSpoke
            ? 0
            : chunk.length
      if (allowed > 0) raw.write(chunk.subarray(0, allowed))
      sent += Math.min(allowed, chunk.length)
      dropped += chunk.length - Math.min(allowed, chunk.length)
      callback()
    },
  })
  raw.on('data', (x: Buffer) => {
    serverSpoke = true
    gate.push(x)
  })
  raw.once('close', () => gate.destroy())
  tlsConnect({ socket: gate, ...options }).on('error', () => {})
  return { serverSpoke: () => serverSpoke, dropped: () => dropped }
}

/** The stalled tunnel holds the only slot until the deadline destroys it. */
async function expectDestroyedAtDeadline(
  proxy: Awaited<ReturnType<typeof serve>>,
  tunnel: Tunnel,
): Promise<void> {
  expect((await proxy.connectTo()).status).toContain(' 503 ')
  const closedAt = await tunnel.closed
  // Timers do not fire early; allow for the proxy arming its timer just
  // before the test saw the 200.
  expect(closedAt - tunnel.openedAt).toBeGreaterThanOrEqual(HANDSHAKE_MS - 100)
  // The slot is free again: a new tunnel is accepted and can be used.
  const next = await proxy.open()
  next.raw.destroy()
}

describe.skipIf(!SERVES_EMITTED_CONNECTIONS)('TLS handshake deadline', () => {
  for (const version of VERSIONS) {
    test(
      `${version}: a client quiet after the handshake keeps its tunnel`,
      async () => {
        const proxy = await serve()
        const tunnel = await proxy.open()
        let closed = false
        void tunnel.closed.then(() => (closed = true))
        const client = tlsConnect({
          socket: tunnel.raw,
          ...proxy.tlsOptions(version),
        })
        client.on('error', () => {})
        await new Promise<void>(r => client.once('secureConnect', r))
        expect(client.getProtocol()).toBe(version)
        await new Promise<void>(r => setTimeout(r, HANDSHAKE_MS * 3))
        expect(closed).toBe(false)
        const answer = new Promise<string>(resolve => {
          let text = ''
          client.on('data', (x: Buffer) => {
            text += x.toString('latin1')
            if (text.includes('\r\n\r\n')) resolve(text)
          })
          client.once('close', () => resolve(text))
        })
        client.write(`GET / HTTP/1.1\r\nHost: ${proxy.target}\r\n\r\n`)
        expect(await answer).toStartWith('HTTP/1.1 200 ')
        client.destroy()
      },
      TEST_MS,
    )

    test(
      `${version}: a client that never sends its Finished is cut off, and its slot freed`,
      async () => {
        const proxy = await serve()
        const tunnel = await proxy.open()
        const client = stalledClient(
          tunnel,
          'noFinished',
          proxy.tlsOptions(version),
        )
        await expectDestroyedAtDeadline(proxy, tunnel)
        // The client did get the server's flight, and its reply was held back.
        expect(client.serverSpoke()).toBe(true)
        expect(client.dropped()).toBeGreaterThan(0)
      },
      TEST_MS,
    )
  }

  test(
    'a client that sends part of a ClientHello is cut off, and its slot freed',
    async () => {
      const proxy = await serve()
      const tunnel = await proxy.open()
      const client = stalledClient(
        tunnel,
        'partialHello',
        proxy.tlsOptions('TLSv1.3'),
      )
      await expectDestroyedAtDeadline(proxy, tunnel)
      expect(client.serverSpoke()).toBe(false)
    },
    TEST_MS,
  )
})
