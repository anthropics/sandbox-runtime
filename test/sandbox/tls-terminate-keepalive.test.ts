import { describe, test, expect, beforeAll, afterAll } from 'bun:test'
import { createServer as createHttpsServer } from 'node:https'
import { connect, type AddressInfo, type Server, type Socket } from 'node:net'
import type { LookupFunction } from 'node:net'
import { connect as tlsConnect, type TLSSocket } from 'node:tls'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { createHttpProxyServer } from '../../src/sandbox/http-proxy.js'
import { createMitmCA } from '../../src/sandbox/mitm-ca.js'
import { mintLeafCert } from '../../src/sandbox/mitm-leaf.js'

// Committed test-only CA — see test/fixtures/tls-terminate/README.md.
const FIXTURE_DIR = join(import.meta.dir, '..', 'fixtures', 'tls-terminate')
const CA_CERT = join(FIXTURE_DIR, 'ca.crt')
const CA_KEY = join(FIXTURE_DIR, 'ca.key')
const CA_PEM = readFileSync(CA_CERT, 'utf8')

const UPSTREAM_NAME = 'keepalive.localhost'

type Reply = { status: number; body: string }

/**
 * CONNECT through the proxy and complete the TLS handshake against the
 * terminating leaf. The returned socket is one client connection.
 */
function openTunnel(
  proxyPort: number,
  host: string,
  port: number,
): Promise<TLSSocket> {
  return new Promise((resolve, reject) => {
    const raw = connect(proxyPort, '127.0.0.1', () => {
      raw.write(
        `CONNECT ${host}:${port} HTTP/1.1\r\nHost: ${host}:${port}\r\n\r\n`,
      )
    })
    raw.once('error', reject)
    raw.once('data', () => {
      const tls = tlsConnect(
        { socket: raw, ca: CA_PEM, servername: host },
        () => resolve(tls),
      )
      tls.once('error', reject)
    })
  })
}

/**
 * One GET on an open client connection. Resolves with the parsed reply, or
 * 'closed' if the connection ended before a full reply arrived.
 */
function get(tls: TLSSocket, path: string): Promise<Reply | 'closed'> {
  return new Promise(resolve => {
    let buf = ''
    const finish = (r: Reply | 'closed') => {
      tls.removeListener('data', onData)
      tls.removeListener('close', onClose)
      tls.removeListener('error', onClose)
      resolve(r)
    }
    const onClose = () => finish('closed')
    const onData = (chunk: Buffer) => {
      buf += chunk.toString('latin1')
      const sep = buf.indexOf('\r\n\r\n')
      if (sep < 0) return
      const head = buf.slice(0, sep)
      const status = Number(/^HTTP\/1\.1 (\d+)/.exec(head)?.[1] ?? 0)
      const length = Number(/^content-length: (\d+)/im.exec(head)?.[1] ?? 0)
      const body = buf.slice(sep + 4)
      if (body.length >= length) finish({ status, body: body.slice(0, length) })
    }
    tls.on('data', onData)
    tls.once('close', onClose)
    tls.once('error', onClose)
    tls.write(`GET ${path} HTTP/1.1\r\nHost: ${UPSTREAM_NAME}\r\n\r\n`)
  })
}

describe('tls-terminate-proxy: upstream keep-alive', () => {
  const ca = createMitmCA({ caCertPath: CA_CERT, caKeyPath: CA_KEY })

  let upstream: Server
  let upstreamPort: number
  let proxy: Server
  let proxyPort: number
  /**
   * Upstream connections that carried a request, by the id the reply body
   * reports. (The vetting probe also connects, but never sends a request.)
   */
  const upstreamSockets = new Map<number, Socket>()
  let lookups = 0

  const lookup = ((_hostname, options, callback) => {
    lookups++
    const all = typeof options === 'object' && options.all
    if (all) callback(null, [{ address: '127.0.0.1', family: 4 }])
    else callback(null, '127.0.0.1', 4)
  }) as LookupFunction

  beforeAll(async () => {
    const upCert = mintLeafCert(ca, UPSTREAM_NAME)
    const upLeafOnly = upCert.certPem.match(
      /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\r?\n?/,
    )![0]
    const ids = new Map<Socket, number>()
    upstream = createHttpsServer(
      { cert: upLeafOnly, key: upCert.keyPem },
      (req, res) => {
        if (!ids.has(req.socket)) {
          ids.set(req.socket, ids.size + 1)
          upstreamSockets.set(ids.size, req.socket)
        }
        if (req.url === '/drop') {
          req.socket.destroy()
          return
        }
        res.end(String(ids.get(req.socket)))
      },
    )
    await new Promise<void>(r => upstream.listen(0, '127.0.0.1', r))
    upstreamPort = (upstream.address() as AddressInfo).port

    proxy = createHttpProxyServer({
      filter: () => true,
      mitmCA: ca,
      tlsTerminateUpstreamCA: CA_PEM,
      lookupFor: () => lookup,
    })
    await new Promise<void>(r => proxy.listen(0, '127.0.0.1', () => r()))
    proxyPort = (proxy.address() as AddressInfo).port
  })

  afterAll(async () => {
    for (const s of upstreamSockets.values()) s.destroy()
    await new Promise<void>(r => proxy.close(() => r()))
    await new Promise<void>(r => upstream.close(() => r()))
  })

  test('requests on one client connection share one upstream connection, vetted once', async () => {
    const tls = await openTunnel(proxyPort, UPSTREAM_NAME, upstreamPort)
    const first = await get(tls, '/a')
    const lookupsAfterFirst = lookups
    const second = await get(tls, '/b')
    const third = await get(tls, '/c')
    tls.destroy()

    expect(first).toMatchObject({ status: 200 })
    expect(second).toEqual(first)
    expect(third).toEqual(first)
    expect(lookupsAfterFirst).toBeGreaterThan(0)
    expect(lookups).toBe(lookupsAfterFirst)
  })

  test('an upstream that closed the idle connection is redialed', async () => {
    const tls = await openTunnel(proxyPort, UPSTREAM_NAME, upstreamPort)
    const first = (await get(tls, '/a')) as Reply
    expect(first.status).toBe(200)

    upstreamSockets.get(Number(first.body))!.destroy()
    await new Promise(r => setTimeout(r, 200))

    const second = (await get(tls, '/b')) as Reply
    tls.destroy()
    expect(second.status).toBe(200)
    expect(second.body).not.toBe(first.body)
  })

  test('a reused upstream connection dropped mid-request closes the client connection, not 502', async () => {
    const tls = await openTunnel(proxyPort, UPSTREAM_NAME, upstreamPort)
    expect(await get(tls, '/a')).toMatchObject({ status: 200 })
    const dropped = await get(tls, '/drop')
    tls.destroy()
    expect(dropped).toBe('closed')
  })
})
