import { describe, test, expect, beforeAll, afterAll } from 'bun:test'
import { spawn, type ChildProcess } from 'node:child_process'
import { createServer as createHttpsServer } from 'node:https'
import { connect, type AddressInfo, type Server } from 'node:net'
import type { LookupFunction } from 'node:net'
import {
  connect as tlsConnect,
  type ConnectionOptions,
  type TLSSocket,
} from 'node:tls'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { createHttpProxyServer } from '../../src/sandbox/http-proxy.js'
import { createMitmCA } from '../../src/sandbox/mitm-ca.js'
import { mintLeafCert } from '../../src/sandbox/mitm-leaf.js'
import type { FilterRequestCallback } from '../../src/sandbox/request-filter.js'

// Committed test-only CA — see test/fixtures/tls-terminate/README.md.
const FIXTURE_DIR = join(import.meta.dir, '..', 'fixtures', 'tls-terminate')
const CA_CERT = join(FIXTURE_DIR, 'ca.crt')
const CA_KEY = join(FIXTURE_DIR, 'ca.key')
const CA_PEM = readFileSync(CA_CERT, 'utf8')

const UPSTREAM_NAME = 'pipelining.localhost'
/**
 * How long filterRequest holds a /slow or /denied request: long enough for
 * the request pipelined behind it to be parsed, allowed and dialed first.
 */
const SLOW_MS = 150
/** A response well past the 16 KiB a held-back response buffers. */
const BIG = 256 * 1024

type Reply = { status: number; body: string }

const lookup = ((_hostname, options, callback) => {
  const all = typeof options === 'object' && options.all
  if (all) callback(null, [{ address: '127.0.0.1', family: 4 }])
  else callback(null, '127.0.0.1', 4)
}) as LookupFunction

const sleep = (ms: number) => new Promise(r => setTimeout(r, ms))

function get(path: string): string {
  return `GET ${path} HTTP/1.1\r\nHost: ${UPSTREAM_NAME}\r\n\r\n`
}

function put(path: string, body: string): string {
  return (
    `PUT ${path} HTTP/1.1\r\nHost: ${UPSTREAM_NAME}\r\n` +
    `Content-Length: ${body.length}\r\n\r\n${body}`
  )
}

/**
 * CONNECT through the proxy and complete the TLS handshake against the
 * terminating leaf. The returned socket is one client connection.
 */
function openTunnel(proxyPort: number, port: number): Promise<TLSSocket> {
  return new Promise((resolve, reject) => {
    const raw = connect(proxyPort, '127.0.0.1', () => {
      raw.write(
        `CONNECT ${UPSTREAM_NAME}:${port} HTTP/1.1\r\nHost: ${UPSTREAM_NAME}:${port}\r\n\r\n`,
      )
    })
    raw.once('error', reject)
    raw.once('data', () => {
      const tls: TLSSocket = tlsConnect(
        {
          socket: raw,
          ca: CA_PEM,
          servername: UPSTREAM_NAME,
        } satisfies ConnectionOptions,
        () => resolve(tls),
      )
      tls.once('error', reject)
    })
  })
}

/** One complete response off the front of `buf`, or null if it is not all there. */
function parseReply(buf: Buffer): { reply: Reply; rest: Buffer } | null {
  const sep = buf.indexOf('\r\n\r\n')
  if (sep < 0) return null
  const head = buf.subarray(0, sep).toString('latin1')
  const status = Number(/^HTTP\/1\.1 (\d+)/.exec(head)?.[1] ?? 0)
  let rest = buf.subarray(sep + 4)
  const length = /^content-length: *(\d+)/im.exec(head)
  if (length) {
    const n = Number(length[1])
    if (rest.length < n) return null
    const body = rest.subarray(0, n).toString('latin1')
    return { reply: { status, body }, rest: rest.subarray(n) }
  }
  // Chunked, without trailers.
  const chunks: Buffer[] = []
  for (;;) {
    const eol = rest.indexOf('\r\n')
    if (eol < 0) return null
    const size = parseInt(rest.subarray(0, eol).toString('latin1'), 16)
    if (rest.length < eol + 2 + size + 2) return null
    if (size === 0) {
      const body = Buffer.concat(chunks).toString('latin1')
      return { reply: { status, body }, rest: rest.subarray(eol + 4) }
    }
    chunks.push(rest.subarray(eol + 2, eol + 2 + size))
    rest = rest.subarray(eol + 2 + size + 2)
  }
}

/**
 * Write `requests` in one go (so they are pipelined) and read up to `count`
 * replies. Resolves with fewer if the connection closes or the replies stall
 * for `timeoutMs`.
 */
function exchange(
  tls: TLSSocket,
  requests: string,
  count: number,
  timeoutMs = 3000,
): Promise<Reply[]> {
  return new Promise(resolve => {
    const replies: Reply[] = []
    let buf: Buffer = Buffer.alloc(0)
    const finish = () => {
      clearTimeout(timer)
      tls.removeListener('data', onData)
      tls.removeListener('close', finish)
      resolve(replies)
    }
    const timer = setTimeout(finish, timeoutMs)
    const onData = (chunk: Buffer) => {
      buf = Buffer.concat([buf, chunk])
      for (let r = parseReply(buf); r; r = parseReply(buf)) {
        replies.push(r.reply)
        buf = r.rest
        if (replies.length === count) return finish()
      }
    }
    tls.on('data', onData)
    tls.once('close', finish)
    tls.write(requests)
  })
}

describe('tls-terminate-proxy: pipelined requests', () => {
  const ca = createMitmCA({ caCertPath: CA_CERT, caKeyPath: CA_KEY })

  let upstream: Server
  let upstreamPort: number
  let proxy: Server
  let proxyPort: number
  /** `METHOD /path` of every request the upstream received, in arrival order. */
  const seen: string[] = []
  const seenUnder = (prefix: string) =>
    seen.filter(r => r.split(' ')[1].startsWith(prefix))
  /** Requests the upstream received with the stand-in SigV4 signature. */
  const resigned: string[] = []

  // /held waits in filterRequest until the test releases it.
  let heldSignal: AbortSignal | undefined
  let heldEntered: () => void = () => {}
  let held = Promise.resolve()

  const filterRequest: FilterRequestCallback = async request => {
    const path = new URL(request.url).pathname
    if (path.endsWith('/held')) {
      heldSignal = request.signal
      heldEntered()
      await held
    }
    if (path.endsWith('/slow') || path.endsWith('/denied')) await sleep(SLOW_MS)
    if (path.endsWith('/denied')) return { action: 'deny', reason: 'test' }
    return { action: 'allow' }
  }

  beforeAll(async () => {
    const upCert = mintLeafCert(ca, UPSTREAM_NAME)
    const upLeafOnly = upCert.certPem.match(
      /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\r?\n?/,
    )![0]
    upstream = createHttpsServer(
      { cert: upLeafOnly, key: upCert.keyPem },
      (req, res) => {
        const line = `${req.method} ${req.url}`
        seen.push(line)
        if (req.headers['x-test-resigned']) resigned.push(line)
        if (req.url?.endsWith('/drop')) {
          req.socket.destroy()
          return
        }
        req.resume()
        req.on('end', () =>
          res.end(req.url?.endsWith('/big') ? 'a'.repeat(BIG) : line),
        )
      },
    )
    await new Promise<void>(r => upstream.listen(0, '127.0.0.1', r))
    upstreamPort = (upstream.address() as AddressInfo).port

    proxy = createHttpProxyServer({
      filter: () => true,
      mitmCA: ca,
      tlsTerminateUpstreamCA: CA_PEM,
      lookupFor: () => lookup,
      filterRequest,
    })
    await new Promise<void>(r => proxy.listen(0, '127.0.0.1', () => r()))
    proxyPort = (proxy.address() as AddressInfo).port
  })

  afterAll(async () => {
    await new Promise<void>(r => proxy.close(() => r()))
    await new Promise<void>(r => upstream.close(() => r()))
  })

  test('a request does not go upstream ahead of an earlier one still being filtered', async () => {
    const tls = await openTunnel(proxyPort, upstreamPort)
    const replies = await exchange(
      tls,
      put('/order/slow', 'x') + get('/order/after'),
      2,
    )
    tls.destroy()

    expect(replies).toEqual([
      { status: 200, body: 'PUT /order/slow' },
      { status: 200, body: 'GET /order/after' },
    ])
    expect(seenUnder('/order/')).toEqual([
      'PUT /order/slow',
      'GET /order/after',
    ])
  })

  test('a denied request lets the one behind it go upstream', async () => {
    const tls = await openTunnel(proxyPort, upstreamPort)
    const replies = await exchange(
      tls,
      put('/deny/denied', 'x') + get('/deny/after'),
      2,
    )
    tls.destroy()

    expect(replies.map(r => r.status)).toEqual([403, 200])
    expect(seenUnder('/deny/')).toEqual(['GET /deny/after'])
  })

  test('requests behind one whose client went away mid-filter are dropped, and the proxy keeps serving', async () => {
    const entered = new Promise<void>(r => (heldEntered = r))
    let release: () => void = () => {}
    held = new Promise<void>(r => (release = r))
    const tls = await openTunnel(proxyPort, upstreamPort)
    tls.write(put('/abort/held', 'x') + get('/abort/after'))
    await entered
    // Let the second request reach its turn, then go away, and let the
    // first request's decision come back only once the proxy has seen it.
    await sleep(50)
    tls.destroy()
    while (!heldSignal?.aborted) await sleep(10)
    release()
    await sleep(100)
    expect(seenUnder('/abort/')).toEqual([])

    const next = await openTunnel(proxyPort, upstreamPort)
    const replies = await exchange(next, get('/abort/next'), 1)
    next.destroy()
    expect(replies).toEqual([{ status: 200, body: 'GET /abort/next' }])
  })

  test('a stale upstream socket under the first request closes the client connection, not a hang', async () => {
    const tls = await openTunnel(proxyPort, upstreamPort)
    expect(await exchange(tls, get('/stale/a'), 1)).toEqual([
      { status: 200, body: 'GET /stale/a' },
    ])
    let closed = false
    tls.once('close', () => (closed = true))
    // The upstream drops the reused connection when the first request
    // lands, with the second queued behind it.
    const replies = await exchange(
      tls,
      get('/stale/drop') + get('/stale/after'),
      2,
    )
    tls.destroy()
    expect(replies).toEqual([])
    expect(closed).toBe(true)
  })

  // srt's CLI runs on Node, and two of the failures only show there. Node's
  // http server emits a pipelined request before the body of the one ahead of
  // it has ended, so a request behind a SigV4-buffered one overtakes it; and
  // it holds a pipelined response back until the one ahead has finished, so
  // an overtaking request with a large response stalls both. These drive the
  // built proxy (CI builds before it tests) in a node child.
  describe('under Node', () => {
    let child: ChildProcess
    let nodeProxyPort: number

    beforeAll(async () => {
      const script = `
        import { readFileSync } from 'node:fs'
        const [dist, caCert, caKey, slowMs] = process.argv.slice(1)
        const { createHttpProxyServer } = await import(dist + '/sandbox/http-proxy.js')
        const { createMitmCA } = await import(dist + '/sandbox/mitm-ca.js')
        const lookup = (_h, o, cb) =>
          o && o.all ? cb(null, [{ address: '127.0.0.1', family: 4 }]) : cb(null, '127.0.0.1', 4)
        const proxy = createHttpProxyServer({
          filter: () => true,
          mitmCA: createMitmCA({ caCertPath: caCert, caKeyPath: caKey }),
          tlsTerminateUpstreamCA: readFileSync(caCert, 'utf8'),
          lookupFor: () => lookup,
          filterRequest: async r => {
            if (new URL(r.url).pathname.endsWith('/slow'))
              await new Promise(s => setTimeout(s, Number(slowMs)))
            return { action: 'allow' }
          },
          // Re-sign /signed requests over a buffered body, as for a client
          // that signed a literal payload hash; apply() stands in for the
          // signer.
          planSigv4: (_method, target) =>
            target.endsWith('/signed')
              ? {
                  action: 'resign',
                  payloadHash: undefined,
                  apply: headers => { headers['x-test-resigned'] = '1' },
                }
              : undefined,
        })
        proxy.listen(0, '127.0.0.1', () => console.log(proxy.address().port))
      `
      const dist = pathToFileURL(join(import.meta.dir, '..', '..', 'dist'))
      child = spawn(
        'node',
        [
          '--input-type=module',
          '-e',
          script,
          dist.href,
          CA_CERT,
          CA_KEY,
          `${SLOW_MS}`,
        ],
        { stdio: ['ignore', 'pipe', 'inherit'] },
      )
      nodeProxyPort = await new Promise<number>((resolve, reject) => {
        child.stdout!.once('data', d => resolve(Number(String(d).trim())))
        child.once('exit', code => reject(new Error(`node exited ${code}`)))
      })
    })

    afterAll(() => {
      child.kill('SIGKILL')
    })

    test('a request does not go upstream ahead of an earlier one buffered for SigV4 re-signing', async () => {
      const tls = await openTunnel(nodeProxyPort, upstreamPort)
      const replies = await exchange(
        tls,
        put('/sigv4/signed', 'body') + get('/sigv4/after'),
        2,
      )
      tls.destroy()

      expect(replies.map(r => r.status)).toEqual([200, 200])
      expect(seenUnder('/sigv4/')).toEqual([
        'PUT /sigv4/signed',
        'GET /sigv4/after',
      ])
      expect(resigned).toContain('PUT /sigv4/signed')
    })

    test('a large response to a request behind a slow one does not stall', async () => {
      const tls = await openTunnel(nodeProxyPort, upstreamPort)
      const replies = await exchange(
        tls,
        get('/stall/slow') + get('/stall/big'),
        2,
      )
      tls.destroy()

      expect(replies.map(r => [r.status, r.body.length])).toEqual([
        [200, 'GET /stall/slow'.length],
        [200, BIG],
      ])
    })
  })
})
