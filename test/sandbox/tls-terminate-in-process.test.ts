import { afterEach, describe, expect, spyOn, test } from 'bun:test'
import {
  createServer,
  Server as HttpServer,
  type IncomingMessage,
  type ServerResponse,
} from 'node:http'
import {
  createServer as createHttpsServer,
  Server as HttpsServer,
} from 'node:https'
import {
  connect,
  createServer as createNetServer,
  Server as NetServer,
  type AddressInfo,
  type Socket,
} from 'node:net'
import { connect as tlsConnect, type TLSSocket } from 'node:tls'
import { createHttpProxyServer } from '../../src/sandbox/http-proxy.js'
import { createMitmCA, generateCa } from '../../src/sandbox/mitm-ca.js'
import { mintLeafCert } from '../../src/sandbox/mitm-leaf.js'
import {
  SERVES_EMITTED_CONNECTIONS,
  testWithTls,
} from '../helpers/emitted-connections.js'

// TLS termination in this process: a CONNECT tunnel's TLS runs on its own
// socket and the decrypted connection goes to an HTTP server that never
// listens, within the proxy's bounds on tunnels and the leaf caches.

const cleanup: Array<() => Promise<void> | void> = []
afterEach(async () => {
  while (cleanup.length) await cleanup.pop()!()
})

type Seen = {
  url: string
  rawHeaders: string[]
  rawTrailers: string[]
  body: string
}

/** An HTTP or HTTPS upstream that records each request's raw header lines, raw trailers and body. */
async function recordingUpstream(tlsOpts?: { cert: string; key: string }) {
  const seen: Seen[] = []
  const handler = (req: IncomingMessage, res: ServerResponse) => {
    let body = ''
    req.on('data', c => (body += c))
    req.on('end', () => {
      seen.push({
        url: req.url ?? '',
        rawHeaders: [...req.rawHeaders],
        rawTrailers: [...req.rawTrailers],
        body,
      })
      res.end('ok')
    })
  }
  const server = tlsOpts
    ? createHttpsServer(tlsOpts, handler)
    : createServer(handler)
  await new Promise<void>(r => server.listen(0, '127.0.0.1', r))
  cleanup.push(() => new Promise<void>(r => server.close(() => r())))
  return { seen, port: (server.address() as AddressInfo).port }
}

/**
 * A proxy that terminates every tunnel, in front of an HTTPS upstream on
 * loopback, whose filterRequest allows every request and records its URL.
 */
async function tlsSetup(extra: { requireHostMatch?: boolean } = {}) {
  const ca = generateCa()
  const leaf = mintLeafCert(
    createMitmCA({ caCertPem: ca.certPem, caKeyPem: ca.keyPem }),
    '127.0.0.1',
  )
  const leafOnly = leaf.certPem.match(
    /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\r?\n?/,
  )![0]
  const up = await recordingUpstream({ cert: leafOnly, key: leaf.keyPem })
  const asked: string[] = []
  const proxy = createHttpProxyServer({
    filter: () => true,
    mitmCA: createMitmCA({ caCertPem: ca.certPem, caKeyPem: ca.keyPem }),
    tlsTerminateUpstreamCA: ca.certPem,
    requireHostMatch: extra.requireHostMatch,
    filterRequest: async request => {
      asked.push(request.url)
      return { action: 'allow' }
    },
  })
  await new Promise<void>(r => proxy.listen(0, '127.0.0.1', r))
  cleanup.push(
    () =>
      new Promise<void>(r => {
        proxy.close(() => r())
        proxy.closeAllConnections()
      }),
  )
  const port = (proxy.address() as AddressInfo).port
  const target = `127.0.0.1:${up.port}`
  /** One GET in a tunnel, with Host (default: the target); the raw response. */
  const send = (requestTarget: string, host = target): Promise<string> =>
    new Promise(resolve => {
      const c = connect(port, '127.0.0.1', () =>
        c.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`),
      )
      let head = ''
      const onData = (x: Buffer): void => {
        head += x.toString('latin1')
        if (!head.includes('\r\n\r\n')) return
        c.off('data', onData)
        const t = tlsConnect({
          socket: c,
          ca: ca.certPem,
          checkServerIdentity: () => undefined,
          ALPNProtocols: ['http/1.1'],
        })
        let out = ''
        t.on('secureConnect', () =>
          t.write(
            `GET ${requestTarget} HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\n\r\n`,
          ),
        )
        t.on('data', y => (out += y))
        t.on('close', () => resolve(out))
        t.on('error', () => resolve(out))
      }
      c.on('data', onData)
      c.on('error', () => resolve(''))
    })
  return { up, asked, send, target, port, ca: ca.certPem }
}

const statusOf = (raw: string): number => Number(raw.split(' ')[1] ?? 0)

describe('TLS termination opens nothing another process could reach', () => {
  test.skipIf(!SERVES_EMITTED_CONNECTIONS)(
    'a tunnel is terminated with no listener: no listen() from CONNECT to the end of the response',
    async () => {
      const s = await tlsSetup()
      const listened: unknown[] = []
      // Every server class a listener could come from (they need not share
      // a prototype chain).
      const protos = new Set<{ listen: (...args: unknown[]) => unknown }>([
        NetServer.prototype as never,
        HttpServer.prototype as never,
        HttpsServer.prototype as never,
      ])
      for (const proto of protos) {
        const listen = proto.listen
        const spy = spyOn(proto, 'listen').mockImplementation(function (
          this: unknown,
          ...args: unknown[]
        ) {
          listened.push(args[0])
          return listen.apply(this, args)
        })
        cleanup.push(() => spy.mockRestore())
      }
      const raw = await s.send('/ok')
      expect(raw).toStartWith('HTTP/1.1 200')
      expect(s.up.seen.map(g => g.url)).toEqual(['/ok'])
      expect(listened).toEqual([])
    },
  )
})

describe('the terminated tunnels are capped', () => {
  // Every case runs a TLS-terminating proxy: skipped where none can run.
  const test = testWithTls
  test('past maxTerminatedTunnels, a CONNECT is answered 503 and marked too-many-tunnels', async () => {
    const ca = generateCa()
    const mitmCA = createMitmCA({ caCertPem: ca.certPem, caKeyPem: ca.keyPem })
    const proxy = createHttpProxyServer({
      filter: () => true,
      mitmCA,
      maxTerminatedTunnels: 2,
    })
    await new Promise<void>(r => proxy.listen(0, '127.0.0.1', r))
    cleanup.push(() => new Promise<void>(r => proxy.close(() => r())))
    const port = (proxy.address() as AddressInfo).port
    const open = (): Promise<{
      head: string
      sock: Socket
    }> =>
      new Promise(resolve => {
        const c = connect(port, '127.0.0.1', () =>
          c.write('CONNECT a.test:443 HTTP/1.1\r\nHost: a.test:443\r\n\r\n'),
        )
        c.on('error', () => {})
        let head = ''
        c.on('data', d => {
          head += d.toString('latin1')
          if (head.includes('\r\n\r\n')) resolve({ head, sock: c })
        })
      })
    const first = await open()
    const second = await open()
    cleanup.push(() => {
      first.sock.destroy()
      second.sock.destroy()
    })
    expect(first.head).toStartWith('HTTP/1.1 200')
    expect(second.head).toStartWith('HTTP/1.1 200')
    const third = await open()
    third.sock.destroy()
    expect(third.head).toStartWith('HTTP/1.1 503')
    expect(third.head).toContain('X-Proxy-Error: too-many-tunnels')
    // A slot frees when a tunnel closes.
    first.sock.destroy()
    await new Promise(r => setTimeout(r, 100))
    const fourth = await open()
    fourth.sock.destroy()
    expect(fourth.head).toStartWith('HTTP/1.1 200')
  })
})

describe('the leaf caches keep the most recently used host names', () => {
  test('past the limit the least recently used name goes', () => {
    const ca = generateCa()
    const mitmCA = createMitmCA({ caCertPem: ca.certPem, caKeyPem: ca.keyPem })
    mitmCA.cacheLimit = 2
    mintLeafCert(mitmCA, 'a.test')
    mintLeafCert(mitmCA, 'b.test')
    mintLeafCert(mitmCA, 'a.test') // a is now the most recent
    mintLeafCert(mitmCA, 'c.test')
    expect([...mitmCA.leafCerts.keys()]).toEqual(['a.test', 'c.test'])
  })
})

/**
 * A 128 MiB TLS-terminated response to a client that reads nothing for 2 s
 * and then reads it all: how much the upstream managed to write during the
 * stall (the rest waits on backpressure), and what the client got.
 */
async function stalledClientResponse(): Promise<{
  upstreamWroteDuringStall: number
  read: number
  size: number
}> {
  const size = 128 << 20
  const ca = generateCa()
  const mitmCA = createMitmCA({ caCertPem: ca.certPem, caKeyPem: ca.keyPem })
  const leaf = mintLeafCert(mitmCA, '127.0.0.1')
  const leafOnly = leaf.certPem.match(
    /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\r?\n?/,
  )![0]
  let written = 0
  const up = createHttpsServer(
    { cert: leafOnly, key: leaf.keyPem },
    (_req, res) => {
      res.writeHead(200, { 'content-length': size })
      const chunk = Buffer.alloc(64 << 10, 0x61)
      const pump = (): void => {
        while (written < size) {
          written += chunk.length
          if (!res.write(chunk)) {
            res.once('drain', pump)
            return
          }
        }
        res.end()
      }
      pump()
    },
  )
  await new Promise<void>(r => up.listen(0, '127.0.0.1', r))
  cleanup.push(() => new Promise<void>(r => up.close(() => r())))
  const target = `127.0.0.1:${(up.address() as AddressInfo).port}`
  const p = createHttpProxyServer({
    filter: () => true,
    mitmCA,
    tlsTerminateUpstreamCA: ca.certPem,
  })
  await new Promise<void>(r => p.listen(0, '127.0.0.1', r))
  cleanup.push(() => new Promise<void>(r => p.close(() => r())))
  const port = (p.address() as AddressInfo).port
  let duringStall = 0
  const read = await new Promise<number>(resolve => {
    const c = connect(port, '127.0.0.1', () =>
      c.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`),
    )
    c.once('data', () => {
      const t = tlsConnect({
        socket: c,
        ca: ca.certPem,
        checkServerIdentity: () => undefined,
      })
      t.on('secureConnect', () => {
        t.write(
          `GET /big HTTP/1.1\r\nHost: ${target}\r\nConnection: close\r\n\r\n`,
        )
        t.pause()
        setTimeout(() => {
          duringStall = written
          t.resume()
        }, 2000)
      })
      let n = 0
      t.on('data', d => (n += d.length))
      t.on('close', () => resolve(n))
      t.on('error', () => resolve(n))
    })
    c.on('error', () => resolve(0))
  })
  return { upstreamWroteDuringStall: duringStall, read, size }
}

describe('a TLS-terminated response waits for a stalled client', () => {
  test.skipIf(!SERVES_EMITTED_CONNECTIONS)(
    "full mode (the runtime's own listener): the upstream is held back, and the client then gets every byte",
    async () => {
      const r = await stalledClientResponse()
      expect(r.read).toBeGreaterThan(r.size)
      expect(r.read - r.size).toBeLessThan(1024)
      // Kernel buffers and the queue caps: far below the body.
      expect(r.upstreamWroteDuringStall).toBeLessThan(48 << 20)
    },
    60_000,
  )
})

describe('a client that resets its tunnel only ends that tunnel', () => {
  test.skipIf(!SERVES_EMITTED_CONNECTIONS)(
    'a reset mid-handshake and a reset mid-request; the next tunnel is served',
    async () => {
      const s = await tlsSetup()
      for (const at of ['handshake', 'request'] as const) {
        await new Promise<void>(resolve => {
          const c = connect(s.port, '127.0.0.1', () =>
            c.write(
              `CONNECT ${s.target} HTTP/1.1\r\nHost: ${s.target}\r\n\r\n`,
            ),
          )
          c.on('error', () => {})
          c.once('data', () => {
            const t = tlsConnect({
              socket: c,
              ca: s.ca,
              checkServerIdentity: () => undefined,
            })
            t.on('error', () => {})
            if (at === 'handshake') {
              setImmediate(() => {
                c.resetAndDestroy()
                resolve()
              })
              return
            }
            t.on('secureConnect', () => {
              t.write(`GET /half HTTP/1.1\r\nHost: ${s.target}\r\n`)
              setTimeout(() => {
                c.resetAndDestroy()
                resolve()
              }, 50)
            })
          })
        })
      }
      await new Promise(r => setTimeout(r, 200))
      expect(await s.send('/ok')).toStartWith('HTTP/1.1 200')
    },
  )
})

/** One GET in a tunnel with this SNI: the raw response and the certificate's CN. */
function sendWithSni(
  s: { port: number; target: string; ca: string },
  servername: string,
): Promise<{ raw: string; cn: string | undefined }> {
  return new Promise(resolve => {
    let cn: string | undefined
    const c = connect(s.port, '127.0.0.1', () =>
      c.write(`CONNECT ${s.target} HTTP/1.1\r\nHost: ${s.target}\r\n\r\n`),
    )
    c.on('error', () => resolve({ raw: '', cn }))
    c.once('data', () => {
      const t = tlsConnect({
        socket: c,
        ca: s.ca,
        servername,
        checkServerIdentity: (_host, cert) => {
          cn = String(cert.subject.CN)
          return undefined
        },
      })
      let out = ''
      t.on('secureConnect', () =>
        t.write(
          `GET /sni HTTP/1.1\r\nHost: ${s.target}\r\nConnection: close\r\n\r\n`,
        ),
      )
      t.on('data', d => (out += d))
      t.on('close', () => resolve({ raw: out, cn }))
      t.on('error', () => resolve({ raw: out, cn }))
    })
  })
}

describe('the server name a tunnel is asked for', () => {
  test.skipIf(!SERVES_EMITTED_CONNECTIONS)(
    'one that cannot be read is a mismatch: 421, nothing asked or dialled',
    async () => {
      const s = await tlsSetup({ requireHostMatch: true })
      const r = await sendWithSni(s, 'x_front.example')
      expect(statusOf(r.raw)).toBe(421)
      expect(s.asked).toHaveLength(0)
      expect(s.up.seen).toHaveLength(0)
    },
  )

  test.skipIf(!SERVES_EMITTED_CONNECTIONS)(
    "with requireHostMatch the certificate is the target's whatever name is asked for",
    async () => {
      const s = await tlsSetup({ requireHostMatch: true })
      const r = await sendWithSni(s, 'other.example.test')
      expect(r.cn).toBe('127.0.0.1')
      expect(statusOf(r.raw)).toBe(421)
      expect(s.up.seen).toHaveLength(0)
    },
  )

  test('every leaf of a CA shares one key: a new name costs a signature', () => {
    const ca = generateCa()
    const mitmCA = createMitmCA({ caCertPem: ca.certPem, caKeyPem: ca.keyPem })
    const a = mintLeafCert(mitmCA, 'a.example')
    const b = mintLeafCert(mitmCA, 'b.example')
    expect(b.keyPem).toBe(a.keyPem)
    expect(b.certPem).not.toBe(a.certPem)
  })
})

/** A CONNECT to `target` on the proxy at `port`; resolves with its reply head and socket. */
function openConnect(
  port: number,
  target: string,
): Promise<{ head: string; sock: Socket }> {
  return new Promise(resolve => {
    const c = connect(port, '127.0.0.1', () =>
      c.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`),
    )
    c.on('error', () => {})
    let head = ''
    c.on('data', d => {
      head += d.toString('latin1')
      if (head.includes('\r\n\r\n')) resolve({ head, sock: c })
    })
  })
}

describe('a tunnel to be terminated holds its slot only while it gets somewhere', () => {
  // Every case runs a TLS-terminating proxy: skipped where none can run.
  const test = testWithTls
  async function capped(extra: Record<string, unknown> = {}) {
    const ca = generateCa()
    const mitmCA = createMitmCA({ caCertPem: ca.certPem, caKeyPem: ca.keyPem })
    const proxy = createHttpProxyServer({
      filter: () => true,
      mitmCA,
      tlsTerminateUpstreamCA: ca.certPem,
      maxTerminatedTunnels: 1,
      tlsHandshakeTimeoutMs: 300,
      ...extra,
    })
    await new Promise<void>(r => proxy.listen(0, '127.0.0.1', r))
    cleanup.push(() => new Promise<void>(r => proxy.close(() => r())))
    return { port: (proxy.address() as AddressInfo).port, ca, mitmCA }
  }

  test('a CONNECT that sends nothing is closed at the deadline, and its slot freed', async () => {
    const p = await capped()
    const silent = await openConnect(p.port, 'a.test:443')
    expect(silent.head).toStartWith('HTTP/1.1 200')
    const closed = await new Promise<boolean>(resolve => {
      silent.sock.once('close', () => resolve(true))
      setTimeout(() => resolve(false), 2000)
    })
    expect(closed).toBe(true)
    const next = await openConnect(p.port, 'a.test:443')
    next.sock.destroy()
    expect(next.head).toStartWith('HTTP/1.1 200')
  })

  testWithTls(
    'a tunnel that got going outlives the deadline: a request, an idle spell past it, another request',
    async () => {
      const p = await capped()
      const leaf = mintLeafCert(p.mitmCA, '127.0.0.1')
      const up = await recordingUpstream({
        cert: leaf.certPem.match(
          /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\r?\n?/,
        )![0],
        key: leaf.keyPem,
      })
      const target = `127.0.0.1:${up.port}`
      const t = await new Promise<TLSSocket>(resolve => {
        void openConnect(p.port, target).then(({ sock }) => {
          const tls = tlsConnect(
            {
              socket: sock,
              ca: p.ca.certPem,
              checkServerIdentity: () => undefined,
            },
            () => resolve(tls),
          )
          tls.on('error', () => {})
        })
      })
      cleanup.push(() => {
        t.destroy()
      })
      let out = ''
      t.on('data', d => (out += d))
      const request = async (path: string): Promise<void> => {
        const before = (out.match(/HTTP\/1\.1 /g) ?? []).length
        t.write(`GET ${path} HTTP/1.1\r\nHost: ${target}\r\n\r\n`)
        for (let i = 0; i < 100; i++) {
          if ((out.match(/HTTP\/1\.1 200/g) ?? []).length > before) return
          await new Promise(r => setTimeout(r, 20))
        }
      }
      await request('/first')
      await new Promise(r => setTimeout(r, 700))
      expect(t.destroyed).toBe(false)
      await request('/second')
      expect(up.seen.map(g => g.url)).toEqual(['/first', '/second'])
    },
  )

  test('a tunnel that turns out not to be TLS frees its slot', async () => {
    const echo = createNetServer(sock => sock.pipe(sock))
    await new Promise<void>(r => echo.listen(0, '127.0.0.1', r))
    cleanup.push(() => new Promise<void>(r => echo.close(() => r())))
    const target = `127.0.0.1:${(echo.address() as AddressInfo).port}`
    const p = await capped()
    const plain = await openConnect(p.port, target)
    cleanup.push(() => {
      plain.sock.destroy()
    })
    plain.sock.write('SSH-2.0-test\r\n')
    await new Promise(r => setTimeout(r, 100))
    const next = await openConnect(p.port, target)
    next.sock.destroy()
    expect(next.head).toStartWith('HTTP/1.1 200')
  })

  test('a tunnel whose TLS setup throws is closed, and the proxy keeps serving', async () => {
    const p = await capped({ tlsHandshakeTimeoutMs: 5000 })
    // Minting a leaf now fails.
    p.mitmCA.keyPem = 'not a key'
    const broken = await openConnect(p.port, 'never-minted.test:443')
    const closed = new Promise<void>(r => broken.sock.once('close', () => r()))
    const t = tlsConnect({
      socket: broken.sock,
      servername: 'never-minted.test',
      rejectUnauthorized: false,
    })
    t.on('error', () => {})
    await closed
    const next = await openConnect(p.port, 'a.test:443')
    next.sock.destroy()
    expect(next.head).toStartWith('HTTP/1.1 200')
  })
})
