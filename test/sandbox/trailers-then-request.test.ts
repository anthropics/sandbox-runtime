import { afterEach, describe, expect, test } from 'bun:test'
import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from 'node:http'
import { createServer as createHttpsServer } from 'node:https'
import { connect, type AddressInfo, type Socket } from 'node:net'
import { connect as tlsConnect, type TLSSocket } from 'node:tls'
import { createHttpProxyServer } from '../../src/sandbox/http-proxy.js'
import { createMitmCA, generateCa } from '../../src/sandbox/mitm-ca.js'
import { mintLeafCert } from '../../src/sandbox/mitm-leaf.js'
import { startProxyOnly } from '../../src/sandbox/proxy-only.js'
import { SERVES_EMITTED_CONNECTIONS } from '../helpers/emitted-connections.js'
import { fakeDecider } from '../helpers/fake-decider.js'

const cleanup: Array<() => Promise<void> | void> = []
afterEach(async () => {
  while (cleanup.length) await cleanup.pop()!()
})

/**
 * Where the requests go through the proxy: srt-proxy on plain HTTP or in a
 * TLS-terminated tunnel, or the full sandbox mode's proxy in a
 * TLS-terminated tunnel. Each terminated tunnel's connection is handed to
 * an HTTP server, which is where a runtime's parser reports trailers.
 */
type Path = 'srt-proxy, plain HTTP' | 'srt-proxy, TLS' | 'full mode, TLS'

/** The proxy under test, and what it asked about each request. */
async function startProxy(
  path: Path,
  target: string,
  authority: ReturnType<typeof generateCa>,
): Promise<{ port: number; asked: () => string[] }> {
  if (path === 'full mode, TLS') {
    const asked: string[] = []
    const proxy = createHttpProxyServer({
      filter: () => true,
      mitmCA: createMitmCA({
        caCertPem: authority.certPem,
        caKeyPem: authority.keyPem,
      }),
      tlsTerminateUpstreamCA: authority.certPem,
      filterRequest: async request => {
        asked.push(
          `${request.method} ${new URL(request.url).pathname} x-late=${String(request.headers.get('x-late') ?? undefined)}`,
        )
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
    return {
      port: (proxy.address() as AddressInfo).port,
      asked: () => asked,
    }
  }
  const d = fakeDecider([target], () => ({ action: 'allow' }))
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
  return {
    port: (proxy.listener.address() as AddressInfo).port,
    asked: () =>
      d.seen.map(
        f =>
          `${String(f.method)} ${String(f.path)} x-late=${String((f.headers as Record<string, unknown> | undefined)?.['x-late'])}`,
      ),
  }
}

/**
 * A request's trailers are its own. A runtime's parser reports them the
 * way it reports a batch of header lines, with the request's target again;
 * held over, they would be read as the start of the next request's head on
 * the connection, whose target would then begin with the previous one and
 * whose headers would begin with the previous request's trailers.
 */
describe.each([
  'srt-proxy, plain HTTP',
  'srt-proxy, TLS',
  'full mode, TLS',
] as const)('a request after a chunked request with trailers (%s)', path => {
  const tls = path !== 'srt-proxy, plain HTTP'
  test.skipIf(tls && !SERVES_EMITTED_CONNECTIONS)(
    'has its own target and headers, for the request filter and for the upstream',
    async () => {
      const authority = generateCa()
      const got: string[] = []
      const handler = (req: IncomingMessage, res: ServerResponse): void => {
        req.resume()
        req.on('end', () => {
          got.push(
            `${req.method} ${req.url} x-late=${String(req.headers['x-late'])}`,
          )
          res.end('upstream ok')
        })
      }
      let up: Server
      if (tls) {
        const leaf = mintLeafCert(
          createMitmCA({
            caCertPem: authority.certPem,
            caKeyPem: authority.keyPem,
          }),
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
      const proxy = await startProxy(path, target, authority)
      let sock: Socket | TLSSocket = await new Promise<Socket>(
        (resolve, reject) => {
          const c = connect(proxy.port, '127.0.0.1', () => resolve(c))
          c.on('error', reject)
        },
      )
      sock.on('error', () => {})
      if (tls) {
        const raw = sock
        raw.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`)
        await new Promise<void>(resolve => raw.once('data', () => resolve()))
        sock = await new Promise<TLSSocket>((resolve, reject) => {
          const t = tlsConnect({
            socket: raw,
            ca: authority.certPem,
            checkServerIdentity: () => undefined,
            ALPNProtocols: ['http/1.1'],
          })
          t.on('error', reject)
          t.once('secureConnect', () => resolve(t))
        })
        sock.on('error', () => {})
      }
      const head = (method: string, p: string, more: string[]): string =>
        [
          `${method} ${tls ? p : `http://${target}${p}`} HTTP/1.1`,
          `Host: ${target}`,
          ...more,
          '',
          '',
        ].join('\r\n')
      const first =
        head('POST', '/first', [
          'Transfer-Encoding: chunked',
          'Trailer: X-Late',
        ]) + '3\r\nabc\r\n2\r\nde\r\n0\r\nX-Late: from-the-trailer\r\n\r\n'
      const second = head('GET', '/second', ['Connection: close'])
      const closed = new Promise<void>(r => sock.once('close', () => r()))
      sock.resume()
      // The second request goes once the first has been read, not in the
      // same write: this is about what a finished request leaves behind on
      // its connection, not about pipelining.
      sock.write(first)
      await new Promise(r => setTimeout(r, 150))
      sock.write(second)
      await closed
      const asked = proxy.asked()
      expect(asked).toEqual([
        'POST /first x-late=undefined',
        'GET /second x-late=undefined',
      ])
      expect(got).toEqual(asked)
    },
  )
})
