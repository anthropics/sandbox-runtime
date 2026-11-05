import { afterEach, describe, expect, test } from 'bun:test'
import type { ServerResponse } from 'node:http'
import {
  connect,
  createServer,
  type AddressInfo,
  type Server,
  type Socket,
} from 'node:net'
import {
  connect as tlsConnect,
  createServer as createTlsServer,
  type TLSSocket,
} from 'node:tls'
import { createHttpProxyServer } from '../../src/sandbox/http-proxy.js'
import { createMitmCA, generateCa } from '../../src/sandbox/mitm-ca.js'
import { mintLeafCert } from '../../src/sandbox/mitm-leaf.js'
import { startProxyOnly } from '../../src/sandbox/proxy-only.js'
import { respondDenied } from '../../src/sandbox/request-filter.js'
import { SERVES_EMITTED_CONNECTIONS } from '../helpers/emitted-connections.js'
import { fakeDecider } from '../helpers/fake-decider.js'

const cleanup: Array<() => Promise<void> | void> = []
afterEach(async () => {
  while (cleanup.length) await cleanup.pop()!()
})

const latin1 = (s: string): Buffer => Buffer.from(s, 'latin1')

/** Every byte past ASCII, and the headers a client acts on, in both of the encodings seen in the wild. */
const SENT: Array<[string, Buffer]> = [
  ['x-high', Buffer.from(Array.from({ length: 128 }, (_, i) => 0x80 + i))],
  ['location', Buffer.from('/café')],
  ['content-disposition', latin1('attachment; filename="caf\xe9.txt"')],
  ['set-cookie', latin1('a=\xe9')],
  ['set-cookie', Buffer.from('b=é')],
]

const REASON = 'refused: café ☃'

/** An upstream that answers in raw bytes: no HTTP server writes these. */
function answer(socket: Socket): void {
  let seen = ''
  socket.on('error', () => {})
  socket.on('data', chunk => {
    seen += chunk.toString('latin1')
    for (let end; (end = seen.indexOf('\r\n\r\n')) >= 0; ) {
      seen = seen.slice(end + 4)
      socket.write(
        Buffer.concat([
          latin1('HTTP/1.1 200 OK\r\n'),
          ...SENT.flatMap(([name, value]) => [
            latin1(`${name}: `),
            value,
            latin1('\r\n'),
          ]),
          latin1('Content-Length: 2\r\n\r\nok'),
        ]),
      )
    }
  })
}

/** Which proxy, and whether the request goes in a TLS-terminated tunnel. */
const PATHS = [
  'full mode, plain HTTP',
  'full mode, TLS',
  'srt-proxy, plain HTTP',
  'srt-proxy, TLS',
] as const

/** Ask for `paths` one after the other on one connection through the proxy; everything the client receives. */
async function fetchRaw(
  path: (typeof PATHS)[number],
  paths: string[],
): Promise<Buffer> {
  const tls = path.endsWith('TLS')
  const authority = generateCa()
  const ca = (): ReturnType<typeof createMitmCA> =>
    createMitmCA({ caCertPem: authority.certPem, caKeyPem: authority.keyPem })
  let up: Server
  if (tls) {
    const leaf = mintLeafCert(ca(), '127.0.0.1')
    const leafOnly = leaf.certPem.match(
      /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\r?\n?/,
    )![0]
    up = createTlsServer({ cert: leafOnly, key: leaf.keyPem }, answer)
  } else {
    up = createServer(answer)
  }
  await new Promise<void>(r => up.listen(0, '127.0.0.1', r))
  cleanup.push(() => void up.close())
  const target = `127.0.0.1:${(up.address() as AddressInfo).port}`

  let port: number
  if (path.startsWith('full mode')) {
    const proxy = createHttpProxyServer({
      filter: () => true,
      mitmCA: SERVES_EMITTED_CONNECTIONS ? ca() : undefined,
      tlsTerminateUpstreamCA: authority.certPem,
      filterRequest: async request =>
        request.url.endsWith('/refuse')
          ? { action: 'deny', reason: REASON }
          : { action: 'allow' },
    })
    await new Promise<void>(r => proxy.listen(0, '127.0.0.1', r))
    cleanup.push(() => {
      proxy.close()
      proxy.closeAllConnections()
    })
    port = (proxy.address() as AddressInfo).port
  } else {
    const d = fakeDecider([target], f =>
      f.path === '/refuse'
        ? { action: 'deny', status: 403, reason: REASON }
        : { action: 'allow' },
    )
    const proxy = startProxyOnly({
      listen: { host: '127.0.0.1', port: 0 },
      decider: d.streams,
      deciderTimeoutMs: 2000,
      ...(SERVES_EMITTED_CONNECTIONS
        ? {
            caPem: authority.keyPem + authority.certPem,
            upstreamCA: authority.certPem,
          }
        : {}),
    })
    cleanup.push(() => proxy.close())
    await proxy.ready
    port = (proxy.listener.address() as AddressInfo).port
  }

  let sock: Socket | TLSSocket = await new Promise<Socket>(
    (resolve, reject) => {
      const c = connect(port, '127.0.0.1', () => resolve(c))
      c.on('error', reject)
    },
  )
  if (tls) {
    const raw = sock
    raw.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`)
    await new Promise<void>(resolve => raw.once('data', () => resolve()))
    sock = await new Promise<TLSSocket>((resolve, reject) => {
      const t = tlsConnect({
        socket: raw,
        ca: authority.certPem,
        checkServerIdentity: () => undefined,
      })
      t.on('error', reject)
      t.once('secureConnect', () => resolve(t))
    })
  }
  sock.on('error', () => {})
  let got = Buffer.alloc(0)
  let onData = (): void => {}
  sock.on('data', (chunk: Buffer) => {
    got = Buffer.concat([got, chunk])
    onData()
  })
  const closed = new Promise<void>(r => sock.once('close', () => r()))
  for (const [i, p] of paths.entries()) {
    const last = i === paths.length - 1
    sock.write(
      `GET ${tls ? p : `http://${target}${p}`} HTTP/1.1\r\nHost: ${target}\r\n` +
        `${last ? 'Connection: close\r\n' : ''}\r\n`,
    )
    // The next request goes once this one's answer is in.
    await (last
      ? closed
      : new Promise<void>(resolve => {
          onData = () => {
            if (got.subarray(-2).toString() === 'ok') resolve()
          }
        }))
  }
  return got
}

describe.each([...PATHS])('bytes past ASCII through the proxy (%s)', path => {
  const run = test.skipIf(path.endsWith('TLS') && !SERVES_EMITTED_CONNECTIONS)

  run(
    'a response header value reaches the client as the upstream sent it',
    async () => {
      // Twice on one connection: every head on it, not only the first.
      const lines = (await fetchRaw(path, ['/one', '/two']))
        .toString('latin1')
        .split('\r\n')
      const once = SENT.map(
        ([name, value]) => `${name}: ${value.toString('latin1')}`,
      )
      expect(
        lines.filter(l => SENT.some(([name]) => l.startsWith(`${name}:`))),
      ).toEqual([...once, ...once])
    },
  )

  run("a refusal's reason is UTF-8, after a relayed response too", async () => {
    const raw = await fetchRaw(path, ['/one', '/refuse'])
    const refusal = raw.subarray(raw.indexOf('HTTP/1.1 403'))
    const body = Buffer.from(`${REASON}\n`)
    expect(
      refusal.subarray(refusal.indexOf('\r\n\r\n') + 4).toString('latin1'),
    ).toBe(
      `${body.length.toString(16)}\r\n${body.toString('latin1')}\r\n0\r\n\r\n`,
    )
  })
})

test("a refusal's reason is handed to the response as bytes", () => {
  let body: unknown
  respondDenied(
    {
      writeHead: () => {},
      end: (chunk: unknown) => {
        body = chunk
      },
    } as unknown as ServerResponse,
    REASON,
  )
  expect(body).toEqual(Buffer.from(`${REASON}\n`))
})
