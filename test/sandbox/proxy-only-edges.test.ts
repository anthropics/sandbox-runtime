import { afterEach, describe, expect, test } from 'bun:test'
import { createServer, type Server } from 'node:http'
import { createServer as createHttpsServer } from 'node:https'
import { connect, type AddressInfo, type Socket } from 'node:net'
import { connect as tlsConnect, type TLSSocket } from 'node:tls'
import { createMitmCA, generateCa } from '../../src/sandbox/mitm-ca.js'
import { mintLeafCert } from '../../src/sandbox/mitm-leaf.js'
import { startProxyOnly } from '../../src/sandbox/proxy-only.js'
import {
  SERVES_EMITTED_CONNECTIONS,
  testWithTls,
} from '../helpers/emitted-connections.js'
import { fakeDecider, type Frame } from '../helpers/fake-decider.js'

const cleanup: Array<() => Promise<void> | void> = []
afterEach(async () => {
  while (cleanup.length) await cleanup.pop()!()
})

type Path = 'tls' | 'plain'

/** A tunnel is terminated only where the runtime can do it in-process. */
const cannotServe = (path: Path): boolean =>
  path === 'tls' && !SERVES_EMITTED_CONNECTIONS

/**
 * A proxy-only proxy in front of an upstream on loopback (HTTPS with a leaf
 * of the proxy's CA, or plain HTTP), and a way to open a connection to it
 * that is ready for a request: a TLS-terminated tunnel, or the bare socket.
 */
async function serve({
  path,
  handler,
  decide,
  deniedDomains = [],
}: {
  path: Path
  handler: Parameters<typeof createServer>[1]
  decide: Parameters<typeof fakeDecider>[1]
  deniedDomains?: string[]
}) {
  const ca = generateCa()
  let up: Server
  if (path === 'tls') {
    const leaf = mintLeafCert(
      createMitmCA({ caCertPem: ca.certPem, caKeyPem: ca.keyPem }),
      '127.0.0.1',
    )
    const leafOnly = leaf.certPem.match(
      /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\r?\n?/,
    )![0]
    up = createHttpsServer({ cert: leafOnly, key: leaf.keyPem }, handler)
  } else {
    up = createServer(handler)
  }
  await new Promise<void>(r => up.listen(0, '127.0.0.1', r))
  cleanup.push(
    () =>
      new Promise<void>(r => {
        up.close(() => r())
        up.closeAllConnections()
      }),
  )
  const target = `127.0.0.1:${(up.address() as AddressInfo).port}`
  const d = fakeDecider([target, 'denied.test:443'], decide, deniedDomains)
  const proxy = startProxyOnly({
    listen: { host: '127.0.0.1', port: 0 },
    decider: d.streams,
    // Only a tunnel needs the CA, and a proxy given one starts only where
    // the runtime can terminate TLS in-process.
    ...(path === 'tls'
      ? { caPem: ca.keyPem + ca.certPem, upstreamCA: ca.certPem }
      : {}),
    deciderTimeoutMs: 1000,
  })
  cleanup.push(() => proxy.close())
  await proxy.ready
  const port = (proxy.listener.address() as AddressInfo).port
  /** For the plain path the request-target is absolute. */
  const requestTarget = (p: string): string =>
    path === 'tls' ? p : `http://${target}${p}`
  const open = (): Promise<Socket | TLSSocket> =>
    new Promise((resolve, reject) => {
      const c = connect(port, '127.0.0.1', () => {
        if (path === 'plain') {
          resolve(c)
          return
        }
        c.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`)
      })
      c.on('error', reject)
      if (path === 'plain') return
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
        t.on('error', reject)
        t.once('secureConnect', () => resolve(t))
      }
      c.on('data', onData)
    })
  return { d, port, target, open, requestTarget }
}

/** Everything a connection sends until it closes. */
function readAll(s: Socket | TLSSocket): Promise<string> {
  return new Promise(resolve => {
    let out = ''
    s.on('data', (x: Buffer) => (out += x.toString('latin1')))
    s.on('close', () => resolve(out))
    s.on('error', () => resolve(out))
  })
}

describe('a deny while the body is still arriving', () => {
  // The decider answers in the same turn it is asked, and the client keeps
  // uploading after the answer. In a TLS-terminated tunnel the rest of the
  // body must be drained, not fed into the stream the decider would have
  // read the body from (Bun throws on that, uncaught, which ends the proxy).
  // The plain case passes without that drain, so it is not a regression
  // test for it: it checks only what the client and the next request see.
  for (const path of ['tls', 'plain'] as const) {
    test.skipIf(cannotServe(path))(
      `${path}: the client gets the whole deny, and the proxy keeps serving`,
      async () => {
        let upstreamHit = false
        const s = await serve({
          path,
          handler: (_req, res) => {
            upstreamHit = true
            res.end('ok')
          },
          decide: f =>
            String(f.path) === '/x'
              ? { action: 'deny', status: 403, reason: 'denied for the test' }
              : { action: 'allow' },
        })
        const sock = await s.open()
        const reply = readAll(sock)
        sock.write(
          `POST ${s.requestTarget('/x')} HTTP/1.1\r\nHost: ${s.target}\r\nContent-Length: 200000\r\n\r\n` +
            'a'.repeat(1000),
        )
        for (let i = 1; i <= 20; i++) {
          setTimeout(() => {
            if (!sock.destroyed) sock.write('b'.repeat(9950))
          }, i * 10)
        }
        const raw = await reply
        expect(raw).toStartWith('HTTP/1.1 403')
        expect(raw).toContain('denied for the test')
        expect(upstreamHit).toBe(false)
        // The same proxy still answers.
        const again = await s.open()
        const next = readAll(again)
        again.write(
          `GET ${s.requestTarget('/y')} HTTP/1.1\r\nHost: ${s.target}\r\nConnection: close\r\n\r\n`,
        )
        expect(await next).toStartWith('HTTP/1.1 200')
      },
    )
  }
})

describe('a streamed response reaches the client as the upstream sends it', () => {
  // Server-sent events, as a streaming API sends them: nothing may be held
  // back until more arrives or the response ends.
  for (const path of ['tls', 'plain'] as const) {
    test.skipIf(cannotServe(path))(
      `${path}: each event arrives before the next is sent`,
      async () => {
        const EVENTS = 5
        // No clock decides this: the upstream sends an event only once the
        // client has the one before it, and gives up on a client that does not
        // get it. A proxy that held an event back would end the stream short.
        const GIVE_UP_MS = 5000
        const arrived: Array<() => void> = []
        const arrivals = Array.from(
          { length: EVENTS },
          () => new Promise<void>(resolve => arrived.push(resolve)),
        )
        let sent = 0
        const sentOnArrival: number[] = []
        const s = await serve({
          path,
          handler: async (_req, res) => {
            res.writeHead(200, { 'content-type': 'text/event-stream' })
            for (let n = 0; n < EVENTS; n++) {
              res.write(`data: ${n}\n\n`)
              sent++
              let timer: ReturnType<typeof setTimeout> | undefined
              const got = await Promise.race([
                arrivals[n]!.then(() => true),
                new Promise<boolean>(resolve => {
                  timer = setTimeout(() => resolve(false), GIVE_UP_MS)
                }),
              ])
              clearTimeout(timer)
              if (!got) break
            }
            res.end()
          },
          decide: () => ({ action: 'allow' }),
        })
        const sock = await s.open()
        let seen = ''
        sock.on('data', (x: Buffer) => {
          seen += x.toString('latin1')
          while (seen.includes(`data: ${sentOnArrival.length}\n\n`)) {
            sentOnArrival.push(sent)
            arrived[sentOnArrival.length - 1]!()
          }
        })
        const done = readAll(sock)
        sock.write(
          `GET ${s.requestTarget('/events')} HTTP/1.1\r\nHost: ${s.target}\r\nConnection: close\r\n\r\n`,
        )
        await done
        // Event n arrived when n + 1 events had been sent, the next one not yet.
        expect(sentOnArrival).toEqual(
          Array.from({ length: EVENTS }, (_v, n) => n + 1),
        )
      },
      15_000,
    )
  }
})

describe("the decider's denied entries", () => {
  testWithTls(
    'a CONNECT to a denied entry is refused 403, unasked, even when an allowed entry covers it',
    async () => {
      const s = await serve({
        path: 'tls',
        handler: (_req, res) => res.end('ok'),
        decide: () => ({ action: 'allow' }),
        deniedDomains: ['denied.test:443'],
      })
      const c = connect(s.port, '127.0.0.1')
      const reply = readAll(c)
      c.write(
        'CONNECT denied.test:443 HTTP/1.1\r\nHost: denied.test:443\r\n\r\n',
      )
      const raw = await reply
      expect(raw).toStartWith('HTTP/1.1 403')
      expect(raw.toLowerCase()).toContain('x-deny-reason: host_not_allowed')
      expect(s.d.seen.filter((f: Frame) => f.t === 'req')).toHaveLength(0)
    },
  )
})

describe('an allow that sets a header to several values', () => {
  test.skipIf(cannotServe('tls'))(
    'tls: every value reaches the upstream, in order',
    async () => {
      let seen: string[] = []
      const s = await serve({
        path: 'tls',
        handler: (req, res) => {
          seen = req.rawHeaders.filter(
            (_v, i, all) =>
              i % 2 === 1 && all[i - 1]!.toLowerCase() === 'x-beta',
          )
          res.end('ok')
        },
        decide: () => ({
          action: 'allow',
          setHeaders: { 'x-beta': ['one', 'two'] },
        }),
      })
      const sock = await s.open()
      const reply = readAll(sock)
      sock.write(
        `GET /x HTTP/1.1\r\nHost: ${s.target}\r\nX-Beta: guest\r\nConnection: close\r\n\r\n`,
      )
      expect(await reply).toStartWith('HTTP/1.1 200')
      expect(seen).toEqual(['one', 'two'])
    },
  )
})

describe('TRACE inside a terminated tunnel', () => {
  test.skipIf(cannotServe('tls'))(
    'is refused 405 before the decider or the upstream sees it, and a new tunnel still works',
    async () => {
      const reached: string[] = []
      const s = await serve({
        path: 'tls',
        handler: (req, res) => {
          reached.push(req.method ?? '')
          res.end('ok')
        },
        decide: f => ({ t: 'verdict', id: f.id, action: 'allow' }),
      })
      const requests = (): unknown[] =>
        s.d.seen.filter(f => f.t === 'req').map(f => f.method)

      const first = await s.open()
      const before = requests()
      first.write(`TRACE /x HTTP/1.1\r\nHost: ${s.target}\r\n\r\n`)
      // The proxy ends the connection once its own refusal has flushed, as
      // it does after its other refusals; readAll resolves only because it
      // does, so a further request needs a new tunnel.
      const refused = await readAll(first)
      expect(refused).toMatch(/^HTTP\/1\.1 405 /)
      expect(refused).toContain('method_refused')
      expect(requests()).toEqual(before)
      expect(reached).toEqual([])

      const second = await s.open()
      second.write(
        `GET /x HTTP/1.1\r\nHost: ${s.target}\r\nConnection: close\r\n\r\n`,
      )
      expect(await readAll(second)).toMatch(/^HTTP\/1\.1 200 /)
      expect(requests()).toEqual([...before, 'GET'])
      expect(reached).toEqual(['GET'])
    },
  )
})
