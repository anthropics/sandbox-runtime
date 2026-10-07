import { describe, test, expect, beforeAll, afterAll } from 'bun:test'
import {
  createServer as createHttpServer,
  type IncomingMessage,
  type ServerResponse,
} from 'node:http'
import { createServer, connect, type AddressInfo, type Server } from 'node:net'
import type { LookupFunction, Socket } from 'node:net'
import {
  createServer as createTlsServer,
  connect as tlsConnect,
} from 'node:tls'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { createHttpProxyServer } from '../../src/sandbox/http-proxy.js'
import { createMitmCA } from '../../src/sandbox/mitm-ca.js'
import { mintLeafCert } from '../../src/sandbox/mitm-leaf.js'
import { relayResponseHead } from '../../src/sandbox/parent-proxy.js'

const FIXTURE_DIR = join(import.meta.dir, '..', 'fixtures', 'tls-terminate')
const CA_CERT = join(FIXTURE_DIR, 'ca.crt')
const CA_KEY = join(FIXTURE_DIR, 'ca.key')
const CA_PEM = readFileSync(CA_CERT, 'utf8')

const TLS_UPSTREAM_NAME = 'badstatus.test'

/**
 * Fake upstream speaking raw bytes, so it can send response heads a real
 * HTTP server would refuse to produce. The reply depends on the request path.
 */
function answer(socket: Socket): void {
  let buf = ''
  socket.on('error', () => {})
  socket.on('data', chunk => {
    buf += chunk.toString('latin1')
    if (!buf.includes('\r\n\r\n')) return
    const path = /^GET (\S+)/.exec(buf)?.[1] ?? ''
    buf = ''
    if (path === '/status-099') {
      socket.write('HTTP/1.1 099 x\r\nX-Up: 1\r\nContent-Length: 4\r\n\r\nleak')
    } else if (path === '/status-000') {
      socket.write('HTTP/1.1 000 x\r\nX-Up: 1\r\nContent-Length: 4\r\n\r\nleak')
    } else {
      socket.write('HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok')
    }
  })
}

/** Send one request head, read the reply until the connection closes. */
function exchange(
  socket: Socket,
  head: string,
): Promise<{ status: number; raw: string }> {
  return new Promise(resolve => {
    let raw = ''
    socket.on('data', chunk => (raw += chunk.toString('latin1')))
    socket.on('error', () => {})
    socket.on('close', () =>
      resolve({ status: Number(/^HTTP\/1\.1 (\d+)/.exec(raw)?.[1] ?? 0), raw }),
    )
    socket.write(head)
  })
}

// On Bun the HTTP client rejects these status lines itself, so these cases
// pin the end-to-end 502 outcome without reaching writeHead. The
// relayResponseHead cases below exercise the writeHead failure directly.
describe('invalid upstream status line', () => {
  const ca = createMitmCA({ caCertPath: CA_CERT, caKeyPath: CA_KEY })
  const lookup = ((_hostname, options, callback) => {
    if (typeof options === 'object' && options.all)
      callback(null, [{ address: '127.0.0.1', family: 4 }])
    else callback(null, '127.0.0.1', 4)
  }) as LookupFunction
  let plainUpstream: Server
  let tlsUpstream: Server
  let proxy: Server
  let plainPort: number
  let tlsPort: number
  let proxyPort: number

  const listen = async (server: Server): Promise<number> => {
    await new Promise<void>(r => server.listen(0, '127.0.0.1', () => r()))
    return (server.address() as AddressInfo).port
  }

  beforeAll(async () => {
    plainUpstream = createServer(answer)
    plainPort = await listen(plainUpstream)
    const leaf = mintLeafCert(ca, TLS_UPSTREAM_NAME)
    const leafOnly = leaf.certPem.match(
      /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\r?\n?/,
    )![0]
    tlsUpstream = createTlsServer(
      { cert: leafOnly, key: leaf.keyPem, ALPNProtocols: ['http/1.1'] },
      answer,
    )
    tlsUpstream.on('tlsClientError', () => {})
    tlsPort = await listen(tlsUpstream)
    proxy = createHttpProxyServer({
      filter: () => true,
      mitmCA: ca,
      tlsTerminateUpstreamCA: CA_PEM,
      lookupFor: () => lookup,
    })
    proxyPort = await listen(proxy)
  })

  afterAll(async () => {
    await new Promise<void>(r => proxy.close(() => r()))
    await new Promise<void>(r => plainUpstream.close(() => r()))
    await new Promise<void>(r => tlsUpstream.close(() => r()))
  })

  function plainGet(path: string): Promise<{ status: number; raw: string }> {
    const authority = `127.0.0.1:${plainPort}`
    const socket = connect(proxyPort, '127.0.0.1')
    return exchange(
      socket,
      `GET http://${authority}${path} HTTP/1.1\r\nHost: ${authority}\r\nConnection: close\r\n\r\n`,
    )
  }

  function tlsGet(path: string): Promise<{ status: number; raw: string }> {
    const authority = `${TLS_UPSTREAM_NAME}:${tlsPort}`
    return new Promise((resolve, reject) => {
      const raw = connect(proxyPort, '127.0.0.1', () => {
        raw.write(`CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\n\r\n`)
      })
      raw.once('error', reject)
      raw.once('data', () => {
        const tls = tlsConnect(
          { socket: raw, ca: CA_PEM, servername: TLS_UPSTREAM_NAME },
          () =>
            resolve(
              exchange(
                tls,
                `GET ${path} HTTP/1.1\r\nHost: ${authority}\r\nConnection: close\r\n\r\n`,
              ),
            ),
        )
        tls.once('error', reject)
      })
    })
  }

  for (const [name, get] of [
    ['plain HTTP', plainGet],
    ['TLS-terminated', tlsGet],
  ] as const) {
    for (const path of ['/status-099', '/status-000']) {
      test(`${name}: ${path} becomes 502 and the proxy keeps serving`, async () => {
        const bad = await get(path)
        expect(bad.status).toBe(502)
        // Nothing from the upstream head or body is relayed.
        expect(bad.raw.toLowerCase()).not.toContain('x-up')
        expect(bad.raw).not.toContain('leak')

        const good = await get('/ok')
        expect(good.status).toBe(200)
        expect(good.raw.endsWith('ok')).toBe(true)
      })
    }
  }
})

describe('relayResponseHead', () => {
  let server: Server
  let port: number
  let handler: (res: ServerResponse) => void = res => res.end()

  beforeAll(async () => {
    server = createHttpServer((_req, res) => handler(res))
    await new Promise<void>(r => server.listen(0, '127.0.0.1', () => r()))
    port = (server.address() as AddressInfo).port
  })

  afterAll(async () => {
    await new Promise<void>(r => server.close(() => r()))
  })

  /**
   * Answer one request by relaying a stub upstream head, and report what the
   * client received and what relayResponseHead did. With `afterPartialHead`,
   * the server first sends its own 200 head and 5 of 10 body bytes, and
   * relays only once the client has them.
   */
  async function relay(
    upstream: { statusCode: number; headers: Record<string, string> },
    { afterPartialHead = false } = {},
  ) {
    let destroyed = false
    let returned: boolean | undefined
    let threw: unknown
    // relayResponseHead uses only statusCode, headers and destroy().
    const upstreamRes = {
      ...upstream,
      destroy: () => {
        destroyed = true
      },
    } as unknown as IncomingMessage
    const run = (res: ServerResponse): void => {
      try {
        returned = relayResponseHead(res, upstreamRes)
      } catch (err) {
        // Recorded, so a throw fails the assertions instead of escaping the
        // request handler.
        threw = err
        res.destroy()
        return
      }
      if (returned) res.end('body')
    }
    let pending: ServerResponse | undefined
    handler = res => {
      if (!afterPartialHead) return run(res)
      pending = res
      res.writeHead(200, { 'Content-Length': '10' })
      res.write('first')
    }
    const socket = connect(port, '127.0.0.1')
    let seen = ''
    socket.on('data', chunk => {
      seen += chunk.toString('latin1')
      if (pending && seen.endsWith('first')) {
        run(pending)
        pending = undefined
      }
    })
    const { status, raw } = await exchange(
      socket,
      `GET / HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nConnection: close\r\n\r\n`,
    )
    return { status, raw, returned, threw, destroyed }
  }

  for (const statusCode of [99, 1000]) {
    test(`status ${statusCode} becomes 502 and the upstream is destroyed`, async () => {
      const r = await relay({ statusCode, headers: { 'x-up': '1' } })
      expect(r.threw).toBeUndefined()
      expect(r.returned).toBe(false)
      expect(r.destroyed).toBe(true)
      expect(r.status).toBe(502)
      expect(r.raw).toContain('Bad Gateway')
      expect(r.raw.toLowerCase()).not.toContain('x-up')
    })
  }

  // x-up comes first, so a header accepted before the rejected one must not
  // reach the client with the 502.
  for (const [name, headers] of [
    [
      'a control character in a header value',
      { 'x-up': '1', 'x-bad': 'a\x01b' },
    ],
    ['an invalid header name', { 'x-up': '1', 'x(bad)': '1' }],
  ] as const) {
    test(`${name} becomes 502 and the upstream is destroyed`, async () => {
      const r = await relay({ statusCode: 200, headers })
      expect(r.threw).toBeUndefined()
      expect(r.returned).toBe(false)
      expect(r.destroyed).toBe(true)
      expect(r.status).toBe(502)
      expect(r.raw).toContain('Bad Gateway')
      expect(r.raw.toLowerCase()).not.toContain('x-up')
    })
  }

  test('once a head was sent, the response is cut off instead', async () => {
    const r = await relay(
      { statusCode: 99, headers: { 'x-up': '1' } },
      { afterPartialHead: true },
    )
    expect(r.threw).toBeUndefined()
    expect(r.returned).toBe(false)
    expect(r.destroyed).toBe(true)
    // The client has the 200 head and 5 of 10 body bytes when the connection
    // closes: no 502, and no complete response.
    expect(r.status).toBe(200)
    expect(r.raw.endsWith('\r\n\r\nfirst')).toBe(true)
    expect(r.raw).not.toContain('Bad Gateway')
  })

  test('a valid head is relayed', async () => {
    const r = await relay({ statusCode: 203, headers: { 'x-up': '1' } })
    expect(r.threw).toBeUndefined()
    expect(r.returned).toBe(true)
    expect(r.destroyed).toBe(false)
    expect(r.status).toBe(203)
    expect(r.raw.toLowerCase()).toContain('\r\nx-up: 1\r\n')
    expect(r.raw).toContain('body')
  })
})
