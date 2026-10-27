import { afterEach, describe, expect, spyOn, test } from 'bun:test'
import {
  createServer,
  type IncomingHttpHeaders,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from 'node:http'
import {
  connect,
  createServer as createNetServer,
  Server as NetServer,
  type AddressInfo,
  type Socket,
} from 'node:net'
import { PassThrough } from 'node:stream'
import { connect as tlsConnect } from 'node:tls'
import {
  createServer as createHttpServer,
  Server as HttpServer,
} from 'node:http'
import {
  createHttpProxyServer,
  markHandedInConnection,
} from '../../src/sandbox/http-proxy.js'
import { createMitmCA, generateCa } from '../../src/sandbox/mitm-ca.js'
import { mintLeafCert } from '../../src/sandbox/mitm-leaf.js'
import {
  createServer as createHttpsServer,
  Server as HttpsServer,
} from 'node:https'
import { foldHeaderName } from '../../src/sandbox/request-filter.js'
import { stripHopByHop } from '../../src/sandbox/parent-proxy.js'
import { requestTargetAsSpelled } from '../../src/sandbox/request-filter.js'
import { MAX_QUEUED_BYTES } from '../../src/sandbox/decider-client.js'
import {
  REQUEST_HEAD_LIMIT,
  startProxyOnly,
  type ProxyOnly,
} from '../../src/sandbox/proxy-only.js'
import {
  SERVES_EMITTED_CONNECTIONS,
  testWithTls,
} from '../helpers/emitted-connections.js'
import { fakeDecider, frameOf } from '../helpers/fake-decider.js'

type Upstream = {
  server: Server
  port: number
  got: Array<{ url: string; headers: IncomingHttpHeaders; body: string }>
}

async function upstream(): Promise<Upstream> {
  const got: Upstream['got'] = []
  const server = createServer((req, res) => {
    let body = ''
    req.on('data', c => (body += c))
    req.on('end', () => {
      got.push({ url: req.url ?? '', headers: req.headers, body })
      res.writeHead(200, {
        'set-cookie': 'sid=upstream',
        set_cookie2: 'x',
        'x-kept': 'yes',
      })
      res.end('upstream ok')
    })
  })
  await new Promise<void>(r => server.listen(0, '127.0.0.1', r))
  return { server, port: (server.address() as AddressInfo).port, got }
}

/**
 * One absolute-form request to the proxy over a raw socket. (Bun's
 * node:http client dials the URL in `path` itself rather than the proxy,
 * so it can't be used to talk to a forward proxy.)
 */
function viaProxy(
  proxyPort: number,
  target: string,
  opts: {
    method?: string
    headers?: Record<string, string>
    body?: string
    host?: string | null
  } = {},
): Promise<{ status: number; headers: IncomingHttpHeaders; body: string }> {
  return new Promise((resolve, reject) => {
    const u = new URL(target)
    const body = opts.body ?? ''
    const lines = [
      `${opts.method ?? 'GET'} ${target} HTTP/1.1`,
      'Connection: close',
    ]
    if (opts.host !== null) lines.push(`Host: ${opts.host ?? u.host}`)
    for (const [k, v] of Object.entries(opts.headers ?? {}))
      lines.push(`${k}: ${v}`)
    if (body) lines.push(`Content-Length: ${Buffer.byteLength(body)}`)
    const c = connect(proxyPort, '127.0.0.1', () =>
      c.write(lines.join('\r\n') + '\r\n\r\n' + body),
    )
    let raw = ''
    c.on('data', d => (raw += d))
    c.on('error', reject)
    c.on('close', () => {
      const [head = '', ...rest] = raw.split('\r\n\r\n')
      const [statusLine = '', ...hl] = head.split('\r\n')
      const headers: IncomingHttpHeaders = {}
      for (const l of hl) {
        const i = l.indexOf(':')
        headers[l.slice(0, i).toLowerCase()] = l.slice(i + 1).trim()
      }
      let text = rest.join('\r\n\r\n')
      if (/chunked/i.test(String(headers['transfer-encoding'] ?? ''))) {
        let out = ''
        while (text.length) {
          const nl = text.indexOf('\r\n')
          const n = parseInt(text.slice(0, nl), 16)
          if (!n) break
          out += text.slice(nl + 2, nl + 2 + n)
          text = text.slice(nl + 2 + n + 2)
        }
        text = out
      }
      resolve({
        status: Number(statusLine.split(' ')[1] ?? 0),
        headers,
        body: text,
      })
    })
  })
}

const cleanup: Array<() => Promise<void> | void> = []
afterEach(async () => {
  while (cleanup.length) await cleanup.pop()!()
})

async function setup(
  decide: Parameters<typeof fakeDecider>[1],
  extra: {
    timeoutMs?: number
    plaintextHeaderSet?: boolean
    caPem?: string
  } = {},
) {
  const up = await upstream()
  cleanup.push(() => new Promise<void>(r => up.server.close(() => r())))
  const d = fakeDecider([`127.0.0.1:${up.port}`], decide)
  const closed: string[] = []
  const lifeline = new PassThrough()
  const proxy: ProxyOnly = startProxyOnly({
    listen: { host: '127.0.0.1', port: 0 },
    decider: d.streams,
    lifeline,
    deciderTimeoutMs: extra.timeoutMs ?? 2000,
    stripResponseHeaders: ['set-cookie', 'set-cookie2'],
    // The credential cases go over plain HTTP with sets explicitly allowed,
    // so they run on every runtime; the TLS-terminated cases are separate.
    plaintextHeaderSet: extra.plaintextHeaderSet ?? true,
    caPem: extra.caPem,
    onClosed: why => closed.push(why),
  })
  cleanup.push(() => proxy.close())
  await proxy.ready
  const port = (proxy.listener.address() as AddressInfo).port
  return {
    up,
    d,
    proxy,
    port,
    closed,
    lifeline,
    base: `http://127.0.0.1:${up.port}`,
  }
}

const allowWithCredential = {
  action: 'allow',
  cred: 'session-token',
  credential: 'host-secret',
  removeHeaders: ['x-api-key', 'cookie'],
}

describe('proxy-only mode with an external decider', () => {
  test('allow: the decider sets the credential and strips the client auth in every spelling', async () => {
    const s = await setup(() => allowWithCredential)
    const r = await viaProxy(s.port, `${s.base}/ok`, {
      headers: {
        Authorization: 'Bearer guest',
        X_Api_Key: 'guest',
        'x.api.key': 'guest',
        cookie: 'a=b',
      },
    })
    expect(r.status).toBe(200)
    expect(r.body).toBe('upstream ok')
    expect(s.up.got).toHaveLength(1)
    const h = s.up.got[0]!.headers
    expect(h.authorization).toBe('Bearer host-secret')
    expect(
      Object.keys(h).filter(k => k.replace(/[_.]/g, '-') === 'x-api-key'),
    ).toEqual([])
    expect(h.cookie).toBeUndefined()
    // Response: upstream cookies never reach the client, in either spelling.
    expect(r.headers['set-cookie']).toBeUndefined()
    expect(r.headers['set_cookie2']).toBeUndefined()
    expect(r.headers['x-kept']).toBe('yes')
    // The decider saw the client's request line and headers.
    expect(s.d.seen[0]).toMatchObject({
      t: 'req',
      id: 1,
      method: 'GET',
      host: '127.0.0.1',
      port: s.up.port,
      path: '/ok',
    })
  })

  test('plain HTTP: an allow that sets headers is refused and nothing is dialled', async () => {
    const s = await setup(() => allowWithCredential, {
      plaintextHeaderSet: false,
    })
    const r = await viaProxy(s.port, `${s.base}/ok`, {
      headers: { authorization: 'Bearer guest' },
    })
    expect(r.status).toBe(403)
    expect(r.headers['x-deny-reason']).toBe('plaintext_header_set')
    expect(r.body).toContain('plain-HTTP')
    expect(s.d.seen).toHaveLength(1)
    expect(s.up.got).toHaveLength(0)
    const open = await new Promise<number>(resolve =>
      s.up.server.getConnections((_, n) => resolve(n)),
    )
    expect(open).toBe(0)
  })

  test('plain HTTP: the same request allowed without sets is forwarded', async () => {
    const s = await setup(() => ({ action: 'allow' }), {
      plaintextHeaderSet: false,
    })
    const r = await viaProxy(s.port, `${s.base}/ok`, {
      headers: { authorization: 'Bearer guest' },
    })
    expect(r.status).toBe(200)
    expect(s.up.got).toHaveLength(1)
    expect(s.up.got[0]!.headers.authorization).toBe('Bearer guest')
  })

  test('plain HTTP: with plaintext header sets on, the set header reaches the upstream', async () => {
    const s = await setup(() => allowWithCredential, {
      plaintextHeaderSet: true,
    })
    const r = await viaProxy(s.port, `${s.base}/ok`, {
      headers: { authorization: 'Bearer guest' },
    })
    expect(r.status).toBe(200)
    expect(s.up.got).toHaveLength(1)
    expect(s.up.got[0]!.headers.authorization).toBe('Bearer host-secret')
  })

  test('deny: status and reason reach the client and nothing is dialled', async () => {
    const s = await setup(() => ({
      action: 'deny',
      status: 451,
      reason: 'path refused',
    }))
    const r = await viaProxy(s.port, `${s.base}/deny`, {
      headers: { authorization: 'Bearer guest' },
    })
    expect(r.status).toBe(451)
    expect(r.body).toContain('path refused')
    expect(s.up.got).toHaveLength(0)
  })

  test('need_body: the decider reads the JSON body before deciding', async () => {
    const s = await setup(f => {
      if (f.t === 'req') return { action: 'need_body', max: 1024 }
      const body = Buffer.from(String(f.data), 'base64').toString()
      return JSON.parse(body).tool === 'forbidden'
        ? { action: 'deny', status: 403, reason: 'body refused' }
        : allowWithCredential
    })
    const bad = await viaProxy(s.port, `${s.base}/v1/x`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{"tool":"forbidden"}',
    })
    expect(bad.status).toBe(403)
    expect(s.up.got).toHaveLength(0)
    const good = await viaProxy(s.port, `${s.base}/v1/x`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{"tool":"ok"}',
    })
    expect(good.status).toBe(200)
    expect(s.up.got[0]!.body).toBe('{"tool":"ok"}')
    expect(s.up.got[0]!.headers.authorization).toBe('Bearer host-secret')
  })

  test('a second need_body is a protocol violation: denied, and the link dies', async () => {
    const s = await setup(() => ({ action: 'need_body', max: 1024 }))
    const r = await viaProxy(s.port, `${s.base}/x`, {
      method: 'POST',
      body: '{}',
    })
    expect(r.status).toBe(503)
    expect(s.up.got).toHaveLength(0)
    await s.proxy.close()
    expect(s.closed[0]).toBe('decider: a second need_body')
  })

  test('need_body: a body past max is sent cut at max, flagged cut', async () => {
    const s = await setup(f =>
      f.t === 'req' ? { action: 'need_body', max: 4 } : allowWithCredential,
    )
    const r = await viaProxy(s.port, `${s.base}/v1/x`, {
      method: 'POST',
      body: 'abcdefgh',
    })
    expect(r.status).toBe(200)
    const body = s.d.seen.find(f => f.t === 'body')!
    expect(Buffer.from(String(body.data), 'base64').toString()).toBe('abcd')
    expect(body.cut).toBe(true)
    // The upstream still gets the whole body.
    expect(s.up.got[0]!.body).toBe('abcdefgh')
  })

  test('the req frame: structured target, Host header apart, query without "?", headers as lower-case lists', async () => {
    const s = await setup(() => ({ action: 'deny', status: 403 }))
    await viaProxy(s.port, `${s.base}/a/b?x=1&y=2`, {
      headers: { 'X-Two': 'one', 'x-two': 'two', Accept: 'text/plain' },
    })
    const f = s.d.seen[0]!
    expect(f).toMatchObject({
      t: 'req',
      id: 1,
      method: 'GET',
      host: '127.0.0.1',
      port: s.up.port,
      hostHeader: `127.0.0.1:${s.up.port}`,
      path: '/a/b',
      query: 'x=1&y=2',
    })
    // The frame carries no field beyond the documented ones: a decider may
    // reject a frame with a key it does not know.
    expect(f).not.toHaveProperty('scheme')
    const h = f.headers as Record<string, string[]>
    expect(h['x-two']).toEqual(['one', 'two'])
    expect(h['accept']).toEqual(['text/plain'])
    expect('host' in h).toBe(false)
    expect('url' in f || 'sni' in f).toBe(false)
  })

  test('a header the decider could not be sent is refused here without asking', async () => {
    const s = await setup(() => allowWithCredential)
    const r = await viaProxy(s.port, `${s.base}/ok`, {
      headers: { 'X-Big': 'a'.repeat(70 * 1024) },
    })
    // 431 from the proxy, or the runtime's parser refusing first (400, or a closed connection)
    expect([0, 400, 431]).toContain(r.status)
    expect(s.d.seen).toHaveLength(0)
    expect(s.up.got).toHaveLength(0)
  })

  test('decider timeout denies 503; a late verdict is dropped, not fatal', async () => {
    let first = true
    const s = await setup(
      () => {
        if (first) {
          first = false
          return 'hang'
        }
        return allowWithCredential
      },
      { timeoutMs: 300 },
    )
    const r = await viaProxy(s.port, `${s.base}/hang`)
    expect(r.status).toBe(503)
    expect(s.up.got).toHaveLength(0)
    // The allow for the request that timed out arrives now. Frames are read
    // in order, so the next request's answer shows it was read and dropped.
    s.d.streams.input.write(
      frameOf(
        JSON.stringify({ t: 'verdict', id: s.d.seen[0]!.id, action: 'allow' }),
      ),
    )
    const r2 = await viaProxy(s.port, `${s.base}/ok`)
    expect(r2.status).toBe(200)
    expect(s.up.got.map(g => g.url)).toEqual(['/ok'])
    expect(s.closed).toEqual([])
  })

  test('a malformed verdict frame denies and shuts the proxy down', async () => {
    const s = await setup(() => 'garbage')
    const r = await viaProxy(s.port, `${s.base}/garbage`)
    expect(r.status).toBe(503)
    expect(s.up.got).toHaveLength(0)
    await s.proxy.close()
    expect(s.closed[0]).toContain('decider')
  })

  test('an unknown action or an extra field denies', async () => {
    const s = await setup(() => ({
      action: 'allow',
      removeHeaders: ['x-api-key'],
      extra: true,
    }))
    const r = await viaProxy(s.port, `${s.base}/ok`)
    expect(r.status).toBe(503)
    expect(s.up.got).toHaveLength(0)
  })

  test('decider crash (stream end) denies in-flight requests and stops the proxy', async () => {
    const s = await setup(() => 'end')
    const r = await viaProxy(s.port, `${s.base}/crash`)
    expect(r.status).toBe(503)
    expect(s.up.got).toHaveLength(0)
    await s.proxy.close()
    expect(s.closed).toEqual(['decider: decider closed the stream'])
  })

  test('hosts outside the decider allowlist are refused before the decider is asked', async () => {
    const s = await setup(() => allowWithCredential)
    const r = await viaProxy(s.port, 'http://127.0.0.2:9/x')
    expect(r.status).toBe(403)
    expect(s.d.seen).toHaveLength(0)
  })

  test('with no CA, a CONNECT to an allowed host is refused (no opaque tunnel past the decider)', async () => {
    const s = await setup(() => allowWithCredential)
    const reply = await new Promise<string>(resolve => {
      const c = connect(s.port, '127.0.0.1', () => {
        c.write(
          `CONNECT 127.0.0.1:${s.up.port} HTTP/1.1\r\nHost: 127.0.0.1:${s.up.port}\r\n\r\n`,
        )
      })
      let out = ''
      c.on('data', d => (out += d))
      c.on('close', () => resolve(out))
      c.on('error', () => resolve(out))
    })
    expect(reply).toStartWith('HTTP/1.1 403')
    expect(s.d.seen).toHaveLength(0)
  })

  test('lifeline end shuts the proxy down', async () => {
    const s = await setup(() => allowWithCredential)
    s.lifeline.end()
    await new Promise(r => setTimeout(r, 50))
    await s.proxy.close()
    expect(s.closed).toEqual(['lifeline closed'])
    expect(s.proxy.listener.listening).toBe(false)
  })

  test('a handed fd the runtime cannot listen on fails the start (never a silent listener)', async () => {
    const d = fakeDecider([], () => allowWithCredential)
    const closed: string[] = []
    const p = startProxyOnly({
      listen: { fd: 987 },
      decider: d.streams,
      onClosed: why => closed.push(why),
    })
    // eslint-disable-next-line @typescript-eslint/await-thenable -- bun:test types .rejects.toThrow() as void; the await is required at runtime
    await expect(p.ready).rejects.toThrow()
    await p.close()
    expect(closed[0]).toStartWith('start failed')
  })

  test('a listen that fails ends the start (the proxy never runs without its listener)', async () => {
    const up = await upstream()
    cleanup.push(() => new Promise<void>(r => up.server.close(() => r())))
    const d = fakeDecider([], () => allowWithCredential)
    const closed: string[] = []
    const p = startProxyOnly({
      listen: { host: '127.0.0.1', port: up.port },
      decider: d.streams,
      onClosed: why => closed.push(why),
    })
    // eslint-disable-next-line @typescript-eslint/await-thenable -- bun:test types .rejects.toThrow() as void; the await is required at runtime
    await expect(p.ready).rejects.toThrow()
    await p.close()
    expect(closed[0]).toStartWith('start failed')
  })
  test('a Host header that does not name the request target is refused 421 before the decider is asked', async () => {
    const s = await setup(() => allowWithCredential)
    const r = await viaProxy(s.port, `${s.base}/ok`, {
      host: 'other.example.test',
    })
    expect(r.status).toBe(421)
    expect(s.d.seen).toHaveLength(0)
    expect(s.up.got).toHaveLength(0)
    const wrongPort = await viaProxy(s.port, `${s.base}/ok`, {
      host: '127.0.0.1:1',
    })
    expect(wrongPort.status).toBe(421)
    // HTTP/1.1 without Host: 400, from the runtime's HTTP parser or from
    // the proxy (Bun's parser for an emitted connection passes it on); a
    // closed connection under Bun 1.3. Either way nothing is decided or
    // dialled.
    const missing = await viaProxy(s.port, `${s.base}/ok`, { host: null })
    expect([0, 400]).toContain(missing.status)
    expect(s.up.got).toHaveLength(0)
    expect(s.d.seen).toHaveLength(0)
  })

  testWithTls(
    'the hello frame is byte for byte the pinned one, whatever descriptors are given',
    async () => {
      const { generateCa } = await import('../../src/sandbox/mitm-ca.js')
      const { readFileSync } = await import('node:fs')
      const want = readFileSync(
        new URL('../fixtures/srt-proxy-hello.json', import.meta.url),
        'utf8',
      )
      const ca = generateCa()
      const toProxy = new PassThrough()
      const fromProxy = new PassThrough()
      const first = new Promise<Buffer>(resolve =>
        fromProxy.once('data', (c: Buffer) => resolve(c)),
      )
      // As `srt-proxy --listen-fd 4 --lifeline-fd 3 --decider-fd 5 --ca-fd 6`:
      // a listen fd, a lifeline, the decider's streams and the CA PEM.
      const p = startProxyOnly({
        listen: { fd: 987654 },
        lifeline: new PassThrough(),
        decider: { input: toProxy, output: fromProxy },
        caPem: ca.keyPem + ca.certPem,
      })
      const frame = await first
      expect(frame.readUInt32BE(0)).toBe(frame.length - 4)
      expect(frame.subarray(4).toString('utf8')).toBe(want)
      await p.close()
      // With nothing but the decider, the same bytes.
      const bare = fakeDecider([], () => ({ action: 'deny', status: 403 }))
      const seenHello = new Promise<Buffer>(resolve =>
        bare.streams.output.once('data', (c: Buffer) => resolve(c)),
      )
      const q = startProxyOnly({
        listen: { host: '127.0.0.1', port: 0 },
        decider: bare.streams,
      })
      expect((await seenHello).subarray(4).toString('utf8')).toBe(want)
      await q.close()
    },
  )

  test('a path past 8 KiB is answered 400 without asking, and the link stays up', async () => {
    const s = await setup(() => allowWithCredential)
    const r = await viaProxy(s.port, `${s.base}/${'a'.repeat(8 * 1024)}`)
    expect(r.status).toBe(400)
    expect(s.d.seen).toHaveLength(0)
    const ok = await viaProxy(s.port, `${s.base}/ok`)
    expect(ok.status).toBe(200)
    expect(s.closed).toEqual([])
  })
})

/**
 * Whether this runtime's HTTP server takes a larger maxHeaderSize and
 * answers a head past it through clientError; probed on a loopback server.
 * (Bun 1.3 keeps its own limit.)
 */
async function probeMaxHeaderSize(): Promise<boolean> {
  const server = createHttpServer({ maxHeaderSize: 64 << 10 }, (_req, res) =>
    res.end('ok'),
  )
  await new Promise<void>(r => server.listen(0, '127.0.0.1', r))
  const port = (server.address() as AddressInfo).port
  const reply = await new Promise<string>(resolve => {
    const c = connect(port, '127.0.0.1', () =>
      c.write(
        `GET / HTTP/1.1\r\nHost: x\r\nX-Big: ${'a'.repeat(20 << 10)}\r\nConnection: close\r\n\r\n`,
      ),
    )
    let out = ''
    c.on('data', d => (out += d))
    c.on('error', () => resolve(out))
    c.on('close', () => resolve(out))
  })
  await new Promise<void>(r => server.close(() => r()))
  return reply.startsWith('HTTP/1.1 200')
}
const TAKES_MAX_HEADER_SIZE = await probeMaxHeaderSize()

/** One request inside a TLS-terminated tunnel to the proxy; the status. */
function viaTunnel(
  proxyPort: number,
  target: string,
  raw: (host: string) => string,
  ca: string,
): Promise<string> {
  return new Promise(resolve => {
    const c = connect(proxyPort, '127.0.0.1', () =>
      c.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`),
    )
    let head = ''
    const onData = (d: Buffer): void => {
      head += d.toString('latin1')
      if (!head.includes('\r\n\r\n')) return
      c.off('data', onData)
      if (!head.startsWith('HTTP/1.1 200')) return resolve(head)
      const t = tlsConnect({
        socket: c,
        ca,
        servername:
          target.split(':')[0] === '127.0.0.1'
            ? undefined
            : target.split(':')[0],
        checkServerIdentity: () => undefined,
        ALPNProtocols: ['http/1.1'],
      })
      let out = ''
      t.on('secureConnect', () => t.write(raw(target)))
      t.on('data', x => (out += x))
      t.on('error', () => resolve(out))
      t.on('close', () => resolve(out))
    }
    c.on('data', onData)
    c.on('error', () => resolve(''))
  })
}

describe("requests past the decider's limits are answered 400 by the proxy, not by the parser", () => {
  const big = (host: string): string =>
    `GET /ok HTTP/1.1\r\nHost: ${host}\r\nX-Big: ${'a'.repeat(65 << 10)}\r\nConnection: close\r\n\r\n`
  const longQuery = (host: string): string =>
    `GET /ok?q=${'a'.repeat(1100 << 10)} HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\n\r\n`
  const pastTheHead = (host: string): string =>
    `GET /ok HTTP/1.1\r\nHost: ${host}\r\nX-Big: ${'a'.repeat(REQUEST_HEAD_LIMIT + 1)}\r\nConnection: close\r\n\r\n`

  test.skipIf(!TAKES_MAX_HEADER_SIZE)(
    'plain HTTP: a 65 KiB header, a 1.1 MiB query, and a head past the parser limit',
    async () => {
      const s = await setup(() => ({ action: 'allow' }))
      const target = `127.0.0.1:${s.up.port}`
      for (const raw of [big, longQuery, pastTheHead]) {
        const reply = await new Promise<string>(resolve => {
          const c = connect(s.port, '127.0.0.1', () =>
            c.write(raw(target).replace('GET /ok', `GET http://${target}/ok`)),
          )
          let out = ''
          c.on('data', d => (out += d))
          c.on('error', () => resolve(out))
          c.on('close', () => resolve(out))
        })
        expect(Number(reply.split(' ')[1])).toBe(400)
        // Past the head limit the runtime's parser refuses it, and the proxy
        // still says it did.
        expect(reply.toLowerCase()).toContain(
          '\r\nx-deny-reason: bad_request\r\n',
        )
      }
      expect(s.d.seen).toHaveLength(0)
      expect(s.up.got).toHaveLength(0)
      expect((await viaProxy(s.port, `${s.base}/ok`)).status).toBe(200)
    },
    20_000,
  )

  test.skipIf(!TAKES_MAX_HEADER_SIZE)(
    'TLS-terminated: the same three',
    async () => {
      const ca = generateCa()
      const s = await setup(() => ({ action: 'allow' }), {
        caPem: ca.keyPem + ca.certPem,
      })
      const target = `127.0.0.1:${s.up.port}`
      for (const raw of [big, longQuery, pastTheHead]) {
        const reply = await viaTunnel(s.port, target, raw, ca.certPem)
        expect(Number(reply.split(' ')[1])).toBe(400)
        expect(reply.toLowerCase()).toContain(
          '\r\nx-deny-reason: bad_request\r\n',
        )
      }
      expect(s.d.seen).toHaveLength(0)
      expect(s.up.got).toHaveLength(0)
      expect(s.closed).toEqual([])
    },
    20_000,
  )
})

describe('a CONNECT the allowlist refuses', () => {
  test('proxy-only mode marks it X-Deny-Reason: host_not_allowed', async () => {
    const s = await setup(() => ({ action: 'allow' }))
    const reply = await new Promise<string>(resolve => {
      const c = connect(s.port, '127.0.0.1', () =>
        c.write(
          'CONNECT denied.invalid:443 HTTP/1.1\r\nHost: denied.invalid:443\r\n\r\n',
        ),
      )
      let out = ''
      c.on('data', d => (out += d))
      c.on('close', () => resolve(out))
      c.on('error', () => resolve(out))
    })
    expect(reply).toStartWith('HTTP/1.1 403')
    expect(reply.toLowerCase()).toContain(
      '\r\nx-deny-reason: host_not_allowed\r\n',
    )
    expect(reply.toLowerCase()).not.toContain('x-proxy-error')
    expect(s.d.seen).toHaveLength(0)
    // An absolute-form request to such a host gets the same mark.
    const plain = await viaProxy(s.port, 'http://denied.invalid/x')
    expect(plain.status).toBe(403)
    expect(plain.headers['x-deny-reason']).toBe('host_not_allowed')
  })

  test('the ordinary proxy keeps X-Proxy-Error: blocked-by-allowlist', async () => {
    const proxy = createHttpProxyServer({ filter: () => false })
    await new Promise<void>(r => proxy.listen(0, '127.0.0.1', () => r()))
    cleanup.push(() => new Promise<void>(r => proxy.close(() => r())))
    const port = (proxy.address() as AddressInfo).port
    const reply = await new Promise<string>(resolve => {
      const c = connect(port, '127.0.0.1', () =>
        c.write(
          'CONNECT denied.invalid:443 HTTP/1.1\r\nHost: denied.invalid:443\r\n\r\n',
        ),
      )
      let out = ''
      c.on('data', d => (out += d))
      c.on('close', () => resolve(out))
      c.on('error', () => resolve(out))
    })
    expect(reply).toStartWith('HTTP/1.1 403')
    expect(reply).toContain('X-Proxy-Error: blocked-by-allowlist')
    expect(reply.toLowerCase()).not.toContain('x-deny-reason')
  })
})

/**
 * Whether this runtime's HTTP server answers a request carrying an
 * `Upgrade` field without an upgrade handler; probed on a loopback server.
 * Bun 1.3 leaves it unanswered, and also stalls on the hop-by-hop request
 * below, so those tests need a runtime that passes this probe.
 */
async function probeServesUpgradeField(): Promise<boolean> {
  const server = createServer((req, res) => {
    req.resume()
    req.on('end', () => res.end('ok'))
  })
  await new Promise<void>(r => server.listen(0, '127.0.0.1', r))
  const port = (server.address() as AddressInfo).port
  const reply = await new Promise<string>(resolve => {
    const c = connect(port, '127.0.0.1', () =>
      c.write(
        'GET / HTTP/1.1\r\nHost: x\r\nUpgrade: h2c\r\nConnection: close\r\n\r\n',
      ),
    )
    let out = ''
    const t = setTimeout(() => {
      c.destroy()
      resolve(out)
    }, 1000)
    c.on('data', d => (out += d))
    c.on('close', () => {
      clearTimeout(t)
      resolve(out)
    })
    c.on('error', () => resolve(out))
  })
  server.closeAllConnections?.()
  await new Promise<void>(r => server.close(() => r()))
  return reply.startsWith('HTTP/1.1 200')
}
const SERVES_UPGRADE_FIELD = await probeServesUpgradeField()

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

describe('hop-by-hop headers and request trailers never reach the upstream', () => {
  // Every RFC 9110 7.6.1 hop-by-hop field, a field the Connection header
  // names, separator-folded spellings of two of them, and a chunked body
  // with a trailer.
  const hopRequest = (target: string, path: string, host: string): string =>
    [
      `POST ${target} HTTP/1.1`,
      `Host: ${host}`,
      'Connection: keep-alive, X-Conn-Named',
      'X-Conn-Named: named-in-connection',
      'Keep-Alive: timeout=5',
      'Proxy-Connection: keep-alive',
      'TE: trailers',
      'Trailer: X-Trail',
      'Upgrade: h2c',
      'Proxy-Authorization: Basic Z3Vlc3Q6Z3Vlc3Q=',
      'Proxy-Authenticate: Basic',
      'Proxy_Authorization: Basic Z3Vlc3Q6Z3Vlc3Q=',
      'Keep.Alive: timeout=5',
      'X-Kept: yes',
      'Transfer-Encoding: chunked',
      '',
      '5',
      'hello',
      '0',
      'X-Trail: trailer-value',
      '',
      '',
    ]
      .join('\r\n')
      .replace(`POST ${target}`, `POST ${path}`)

  const HOP = new Set(
    [
      'connection',
      'keep-alive',
      'proxy-connection',
      'te',
      'trailer',
      'transfer-encoding',
      'upgrade',
      'proxy-authorization',
      'proxy-authenticate',
      'x-conn-named',
    ].map(foldHeaderName),
  )
  const expectClean = (s: Seen | undefined): void => {
    expect(s).toBeDefined()
    const names = s!.rawHeaders
      .filter((_, i) => i % 2 === 0)
      .map(n => n.toLowerCase())
    // The proxy's own framing and connection handling may appear; nothing
    // the client sent among these names may.
    const values = s!.rawHeaders.filter((_, i) => i % 2 === 1)
    for (const v of [
      'named-in-connection',
      'timeout=5',
      'trailers',
      'X-Trail',
      'h2c',
      'Basic Z3Vlc3Q6Z3Vlc3Q=',
      'Basic',
    ]) {
      expect(values).not.toContain(v)
    }
    for (const n of names) {
      if (
        n === 'connection' ||
        n === 'transfer-encoding' ||
        n === 'content-length'
      )
        continue
      expect(HOP.has(foldHeaderName(n))).toBe(false)
    }
    expect(names).toContain('x-kept')
    expect(s!.rawTrailers).toEqual([])
    expect(s!.body).toBe('hello')
  }

  test.skipIf(!SERVES_UPGRADE_FIELD)('plain HTTP', async () => {
    const up = await recordingUpstream()
    const d = fakeDecider([`127.0.0.1:${up.port}`], () => ({ action: 'allow' }))
    const proxy = startProxyOnly({
      listen: { host: '127.0.0.1', port: 0 },
      decider: d.streams,
    })
    cleanup.push(() => proxy.close())
    await proxy.ready
    const port = (proxy.listener.address() as AddressInfo).port
    const target = `127.0.0.1:${up.port}`
    const status = await new Promise<string>(resolve => {
      const c = connect(port, '127.0.0.1', () =>
        c.write(
          hopRequest(`http://${target}/hop`, `http://${target}/hop`, target),
        ),
      )
      let out = ''
      c.on('data', x => {
        out += x
        if (out.includes('ok')) c.end()
      })
      c.on('close', () => resolve(out.split('\r\n')[0]!))
      c.on('error', () => resolve(out.split('\r\n')[0]!))
    })
    expect(status).toBe('HTTP/1.1 200 OK')
    expectClean(up.seen[0])
  })

  test.skipIf(!SERVES_UPGRADE_FIELD)(
    'TLS-terminated',
    async () => {
      const ca = generateCa()
      const leaf = mintLeafCert(
        createMitmCA({ caCertPem: ca.certPem, caKeyPem: ca.keyPem }),
        '127.0.0.1',
      )
      const leafOnly = leaf.certPem.match(
        /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\r?\n?/,
      )![0]
      const up = await recordingUpstream({ cert: leafOnly, key: leaf.keyPem })
      const d = fakeDecider([`127.0.0.1:${up.port}`], () => ({
        action: 'allow',
      }))
      const proxy = startProxyOnly({
        listen: { host: '127.0.0.1', port: 0 },
        decider: d.streams,
        caPem: ca.keyPem + ca.certPem,
        upstreamCA: ca.certPem,
      })
      cleanup.push(() => proxy.close())
      await proxy.ready
      const port = (proxy.listener.address() as AddressInfo).port
      const target = `127.0.0.1:${up.port}`
      const status = await new Promise<string>(resolve => {
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
            t.write(hopRequest('/hop', '/hop', target)),
          )
          t.on('data', y => {
            out += y
            if (out.includes('ok')) t.end()
          })
          t.on('close', () => resolve(out.split('\r\n')[0]!))
          t.on('error', () => resolve(out.split('\r\n')[0]!))
        }
        c.on('data', onData)
      })
      expect(status).toBe('HTTP/1.1 200 OK')
      expectClean(up.seen[0])
    },
    15_000,
  )
})

describe('stripHopByHop', () => {
  const h = {
    connection: 'close, X_Named',
    'x-named': '1',
    'keep-alive': '1',
    proxy_authorization: 'b',
    'keep.alive': '1',
    'x-kept': 'yes',
  }
  test('by default only the exact spellings (the ordinary proxy is unchanged)', () => {
    expect(stripHopByHop(h)).toEqual({
      'x-named': '1',
      proxy_authorization: 'b',
      'keep.alive': '1',
      'x-kept': 'yes',
    })
  })
  test('folded: every spelling of - _ and ., for the fields and for the names Connection lists', () => {
    expect(stripHopByHop(h, { folded: true })).toEqual({ 'x-kept': 'yes' })
  })
})

/** A CA, a TLS upstream that records requests, and a proxy-only proxy in front of it. */
async function tlsSetup(decide: Parameters<typeof fakeDecider>[1]) {
  const ca = generateCa()
  const leaf = mintLeafCert(
    createMitmCA({ caCertPem: ca.certPem, caKeyPem: ca.keyPem }),
    '127.0.0.1',
  )
  const leafOnly = leaf.certPem.match(
    /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\r?\n?/,
  )![0]
  const up = await recordingUpstream({ cert: leafOnly, key: leaf.keyPem })
  const d = fakeDecider([`127.0.0.1:${up.port}`], decide)
  const proxy = startProxyOnly({
    listen: { host: '127.0.0.1', port: 0 },
    decider: d.streams,
    caPem: ca.keyPem + ca.certPem,
    upstreamCA: ca.certPem,
    deciderTimeoutMs: 1000,
  })
  cleanup.push(() => proxy.close())
  await proxy.ready
  const port = (proxy.listener.address() as AddressInfo).port
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
  return { up, d, send, target, port, ca: ca.certPem }
}

const statusOf = (raw: string): number => Number(raw.split(' ')[1] ?? 0)
const denyReasonOf = (raw: string): string | undefined =>
  /\r\nx-deny-reason: ([^\r]*)\r\n/i.exec(raw)?.[1]

describe('requestTargetAsSpelled', () => {
  test.each([
    ['/v1/messages', '/v1/messages'],
    ['/v1/%2E/messages', '/v1/%2E/messages'],
    ['/v1/.%2e/messages', '/v1/.%2e/messages'],
    ['/v1/%2e%2e/messages', '/v1/%2e%2e/messages'],
    ['/v1//./messages', '/v1//./messages'],
    ['/v1/models?q=%2e', '/v1/models?q=%2e'],
    ['/a\\b', '/a\\b'],
  ])('origin form %p goes as spelled', (raw, want) => {
    expect(requestTargetAsSpelled(raw)).toBe(want)
  })
  test.each([
    'https://other.example/v1/messages',
    'other.example:443',
    '*',
    '//v1/messages',
    '/\\v1/messages',
    '/v1/messages#frag',
    '/v1/mes sages',
    '/v1/\u0001',
    '',
  ])('%p is refused', raw => {
    expect(requestTargetAsSpelled(raw)).toBeUndefined()
  })
  test('absolute: the path and query of an http(s) URI, as spelled', () => {
    const abs = (raw: string): string | undefined =>
      requestTargetAsSpelled(raw, { absolute: true })
    expect(abs('http://h.test/v1/%2E/x?y=1')).toBe('/v1/%2E/x?y=1')
    expect(abs('http://h.test')).toBe('/')
    expect(abs('http://h.test?x')).toBe('/?x')
    expect(abs('ftp://h.test/x')).toBeUndefined()
    expect(abs('http://h.test//x')).toBeUndefined()
  })
})

/**
 * Whether this runtime's HTTP client sends a request path exactly as given
 * (Node and Bun 1.4 do; Bun 1.3 resolves dot segments itself), probed
 * against a loopback server.
 */
async function probeClientSendsPathAsGiven(): Promise<boolean> {
  let got = ''
  const server = createServer((req, res) => {
    got = req.url ?? ''
    res.end()
  })
  await new Promise<void>(r => server.listen(0, '127.0.0.1', r))
  const { request } = await import('node:http')
  await new Promise<void>(resolve => {
    const r = request(
      {
        host: '127.0.0.1',
        port: (server.address() as AddressInfo).port,
        path: '/a/%2e%2e/b',
      },
      res => {
        res.resume()
        res.on('end', () => resolve())
      },
    )
    r.on('error', () => resolve())
    r.end()
  })
  await new Promise<void>(r => server.close(() => r()))
  return got === '/a/%2e%2e/b'
}
const CLIENT_SENDS_PATH_AS_GIVEN = await probeClientSendsPathAsGiven()

describe('proxy-only mode: the request-target reaches the decider and the upstream as spelled', () => {
  const spellings = [
    '/v1/%2E/messages',
    '/v1/.%2e/messages',
    '/v1/%2e%2e/messages',
    '/v1//./messages',
  ]

  test.skipIf(!CLIENT_SENDS_PATH_AS_GIVEN)(
    'TLS-terminated: the decider sees each spelling, and an allowed one goes upstream unchanged',
    async () => {
      const s = await tlsSetup(() => ({ action: 'allow' }))
      for (const p of spellings) {
        expect(statusOf(await s.send(p))).toBe(200)
        expect(s.d.seen.at(-1)).toMatchObject({ t: 'req', path: p })
        expect(s.up.seen.at(-1)!.url).toBe(p)
      }
    },
    20_000,
  )

  test.skipIf(!SERVES_EMITTED_CONNECTIONS)(
    'TLS-terminated: a decider that matches paths exactly refuses them, and nothing is dialled',
    async () => {
      const s = await tlsSetup(f =>
        f.path === '/v1/messages'
          ? { action: 'allow' }
          : { action: 'deny', status: 403, reason: 'not a route' },
      )
      for (const p of spellings) {
        const raw = await s.send(p)
        expect(statusOf(raw)).toBe(403)
        expect(denyReasonOf(raw)).toBe('decider')
      }
      expect(s.up.seen).toHaveLength(0)
      expect(statusOf(await s.send('/v1/messages'))).toBe(200)
    },
    20_000,
  )

  testWithTls(
    'TLS-terminated: //, /\\ and absolute form are answered 400 without asking',
    async () => {
      const s = await tlsSetup(() => ({ action: 'allow' }))
      for (const p of [
        '//v1/messages',
        '/\\v1/messages',
        `https://${s.target}/v1/messages`,
      ]) {
        const raw = await s.send(p)
        // A runtime's parser may refuse one of these itself (no answer).
        if (raw !== '') {
          expect(statusOf(raw)).toBe(400)
          expect(denyReasonOf(raw)).toBe('bad_request')
        }
      }
      expect(s.d.seen).toHaveLength(0)
      expect(s.up.seen).toHaveLength(0)
    },
    20_000,
  )

  test.skipIf(!CLIENT_SENDS_PATH_AS_GIVEN)(
    "plain HTTP: the absolute URI's path goes to the decider and upstream as spelled",
    async () => {
      const up = await recordingUpstream()
      const d = fakeDecider([`127.0.0.1:${up.port}`], () => ({
        action: 'allow',
      }))
      const proxy = startProxyOnly({
        listen: { host: '127.0.0.1', port: 0 },
        decider: d.streams,
      })
      cleanup.push(() => proxy.close())
      await proxy.ready
      const port = (proxy.listener.address() as AddressInfo).port
      for (const p of spellings) {
        const r = await viaProxy(port, `http://127.0.0.1:${up.port}${p}`)
        expect(r.status).toBe(200)
        expect(d.seen.at(-1)).toMatchObject({ t: 'req', path: p })
        expect(up.seen.at(-1)!.url).toBe(p)
      }
    },
  )
})

describe('proxy-only mode marks every refusal of its own with X-Deny-Reason', () => {
  test.skipIf(!SERVES_EMITTED_CONNECTIONS)(
    'a decider deny: X-Deny-Reason: decider, and no X-Proxy-Error',
    async () => {
      const s = await tlsSetup(() => ({
        action: 'deny',
        status: 451,
        reason: 'no',
      }))
      const raw = await s.send('/v1/messages')
      expect(statusOf(raw)).toBe(451)
      expect(denyReasonOf(raw)).toBe('decider')
      expect(raw.toLowerCase()).not.toContain('x-proxy-error')
    },
    20_000,
  )

  test.skipIf(!SERVES_EMITTED_CONNECTIONS)(
    "the proxy's own: misdirected (421), bad_request (400 past the limits), decider_unavailable (503)",
    async () => {
      let hang = false
      const s = await tlsSetup(() => (hang ? 'hang' : { action: 'allow' }))
      const misdirected = await s.send('/v1/messages', 'other.example.test')
      expect(statusOf(misdirected)).toBe(421)
      expect(denyReasonOf(misdirected)).toBe('misdirected')
      const past = await s.send('/' + 'a'.repeat(9 << 10))
      expect(statusOf(past)).toBe(400)
      expect(denyReasonOf(past)).toBe('bad_request')
      hang = true
      const late = await s.send('/v1/messages')
      expect(statusOf(late)).toBe(503)
      expect(denyReasonOf(late)).toBe('decider_unavailable')
      for (const raw of [misdirected, past, late]) {
        expect(raw.toLowerCase()).not.toContain('x-proxy-error')
      }
    },
    20_000,
  )

  test('the plain path: 421 misdirected', async () => {
    const s = await setup(() => ({ action: 'allow' }))
    const r = await viaProxy(s.port, `${s.base}/ok`, {
      host: 'other.example.test',
    })
    expect(r.status).toBe(421)
    expect(r.headers['x-deny-reason']).toBe('misdirected')
    expect(r.headers['x-proxy-error']).toBeUndefined()
  })
})

describe('proxy-only mode takes destination hosts in plain ASCII only', () => {
  /** A CONNECT to target; the raw reply (the 200 or the refusal). */
  const connectTo = (port: number, target: string): Promise<string> =>
    new Promise(resolve => {
      const c = connect(port, '127.0.0.1', () =>
        c.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`),
      )
      let out = ''
      c.on('data', d => {
        out += d.toString('latin1')
        if (out.includes('\r\n\r\n')) c.end()
      })
      c.on('close', () => resolve(out))
      c.on('error', () => resolve(out))
    })

  test.each([
    ['fullwidth', 'ａllowed.test:443'],
    ['percent-encoded dot', 'allowed%2etest:443'],
    ['double dot', 'allowed.test..:443'],
    ['leading dot', '.allowed.test:443'],
    ['empty label', 'allowed..test:443'],
    ['non-ASCII letter', 'allowéd.test:443'],
  ])(
    'CONNECT with a %s is answered 400 bad_request, unasked',
    async (_label, target) => {
      const s = await setup(() => ({ action: 'allow' }))
      const reply = await connectTo(s.port, target)
      expect(reply).toStartWith('HTTP/1.1 400')
      expect(reply.toLowerCase()).toContain(
        '\r\nx-deny-reason: bad_request\r\n',
      )
      expect(s.d.seen).toHaveLength(0)
    },
  )

  testWithTls(
    'a single trailing dot and ASCII case are still canonicalized, and allowed',
    async () => {
      const ca = generateCa()
      const d = fakeDecider(['allowed.test:443'], () => ({
        action: 'deny',
        status: 403,
      }))
      const proxy = startProxyOnly({
        listen: { host: '127.0.0.1', port: 0 },
        decider: d.streams,
        caPem: ca.keyPem + ca.certPem,
      })
      cleanup.push(() => proxy.close())
      await proxy.ready
      const port = (proxy.listener.address() as AddressInfo).port
      for (const target of [
        'allowed.test:443',
        'allowed.test.:443',
        'ALLOWED.Test:443',
      ]) {
        expect(await connectTo(port, target)).toStartWith('HTTP/1.1 200')
      }
      expect(await connectTo(port, 'other.test:443')).toStartWith(
        'HTTP/1.1 403',
      )
    },
  )

  test('plain HTTP: the same rule for an absolute URI', async () => {
    const s = await setup(() => ({ action: 'allow' }))
    for (const url of [
      `http://ａllowed.test/x`,
      `http://allowed%2etest/x`,
      `http://allowed.test../x`,
    ]) {
      const r = await viaProxy(s.port, url, { host: 'allowed.test' })
      // A runtime's parser may refuse the raw bytes itself (no answer).
      if (r.status !== 0) {
        expect(r.status).toBe(400)
        expect(r.headers['x-deny-reason']).toBe('bad_request')
      }
    }
    expect(s.d.seen).toHaveLength(0)
  })
})

describe('a request the decider answers late', () => {
  // The body gate must not start a body flowing before it is read: a
  // bodyless request would end before it is forwarded, and hang.
  test('a GET and a POST are forwarded whole after a 300 ms verdict', async () => {
    const s = await setup(
      () => new Promise(r => setTimeout(() => r({ action: 'allow' }), 300)),
    )
    const get = await viaProxy(s.port, `${s.base}/late`)
    expect(get.status).toBe(200)
    const post = await viaProxy(s.port, `${s.base}/late`, {
      method: 'POST',
      body: 'x'.repeat(100_000),
    })
    expect(post.status).toBe(200)
    expect(s.up.got.map(g => g.body.length)).toEqual([0, 100_000])
  })
})

describe('a request with many header lines reaches the decider whole', () => {
  // The HTTP parser hands such a head over in batches of 31 lines; Bun's
  // server for an emitted connection used to keep only the last batch.
  test('70 header lines: the target, Host and every line are asked about, and forwarded', async () => {
    const s = await setup(() => ({ action: 'allow' }))
    const headers = Object.fromEntries(
      Array.from({ length: 70 }, (_, i) => [`X-Line-${i}`, `v${i}`]),
    )
    const r = await viaProxy(s.port, `${s.base}/many?q=1`, { headers })
    expect(r.status).toBe(200)
    const f = s.d.seen[0]!
    expect(f).toMatchObject({
      hostHeader: `127.0.0.1:${s.up.port}`,
      path: '/many',
      query: 'q=1',
    })
    const h = f.headers as Record<string, string[]>
    for (let i = 0; i < 70; i++) expect(h[`x-line-${i}`]).toEqual([`v${i}`])
    expect(s.up.got[0]!.headers['x-line-0']).toBe('v0')
  })
})

describe("proxy-only mode keeps to the decider's header limit exactly", () => {
  const pads = (n: number): Record<string, string> =>
    Object.fromEntries(Array.from({ length: n }, (_, i) => [`X-Pad-${i}`, 'v']))

  test('190 header values (Host apart) are asked about; 191 are answered 400 bad_request, unasked', async () => {
    const s = await setup(() => ({ action: 'allow' }))
    // viaProxy adds Connection: close, the 190th value.
    const at = await viaProxy(s.port, `${s.base}/ok`, { headers: pads(189) })
    expect(at.status).toBe(200)
    expect(s.d.seen).toHaveLength(1)
    const past = await viaProxy(s.port, `${s.base}/ok`, { headers: pads(190) })
    expect(past.status).toBe(400)
    expect(past.headers['x-deny-reason']).toBe('bad_request')
    expect(s.d.seen).toHaveLength(1)
    expect(s.up.got).toHaveLength(1)
    // The link is up: the next request is asked as usual.
    expect((await viaProxy(s.port, `${s.base}/ok`)).status).toBe(200)
    expect(s.closed).toEqual([])
  })
})

describe('an upload to a slow upstream is not buffered whole (maxBufferedRequestBody)', () => {
  test.skipIf(!SERVES_EMITTED_CONNECTIONS)(
    'a connection handed in with emit("connection"): the proxy reads a few MiB ahead, not the whole body',
    async () => {
      const SIZE = 64 << 20
      // The upstream reads 1 MiB, then nothing for 1.5 s, then the rest.
      const up = createServer((req, res) => {
        let n = 0
        let stalled = false
        req.on('data', c => {
          n += c.length
          if (!stalled && n >= 1 << 20) {
            stalled = true
            req.pause()
            setTimeout(() => req.resume(), 1500)
          }
        })
        req.on('end', () => res.end(`got ${n}`))
      })
      await new Promise<void>(r => up.listen(0, '127.0.0.1', r))
      cleanup.push(() => new Promise<void>(r => up.close(() => r())))
      const upPort = (up.address() as AddressInfo).port
      const proxy = createHttpProxyServer({
        filter: () => true,
        maxBufferedRequestBody: 4 << 20,
      })
      // As proxy-only mode serves a handed fd: a net.Server passes each
      // connection to the HTTP server.
      let accepted: Socket | undefined
      const front = createNetServer(sock => {
        accepted = sock
        markHandedInConnection(sock)
        proxy.emit('connection', sock)
      })
      await new Promise<void>(r => front.listen(0, '127.0.0.1', r))
      cleanup.push(() => new Promise<void>(r => front.close(() => r())))
      const port = (front.address() as AddressInfo).port
      let readDuringStall = 0
      const reply = await new Promise<string>(resolve => {
        const c = connect(port, '127.0.0.1', () => {
          c.write(
            `POST http://127.0.0.1:${upPort}/up HTTP/1.1\r\nHost: 127.0.0.1:${upPort}\r\nContent-Length: ${SIZE}\r\nConnection: close\r\n\r\n`,
          )
          const chunk = Buffer.alloc(64 << 10)
          let sent = 0
          const pump = (): void => {
            while (sent < SIZE) {
              sent += chunk.length
              if (!c.write(chunk)) {
                c.once('drain', pump)
                return
              }
            }
          }
          pump()
          setTimeout(() => {
            readDuringStall = accepted?.bytesRead ?? 0
          }, 1200)
        })
        let out = ''
        c.on('data', d => (out += d))
        c.on('close', () => resolve(out))
        c.on('error', () => resolve(out))
      })
      expect(reply).toContain(`got ${SIZE}`)
      // The cap, the kernel's and the streams' own buffers: well under the body.
      expect(readDuringStall).toBeLessThan(24 << 20)
    },
    30_000,
  )
})

describe('an upload in a TLS-terminated tunnel to a slow upstream is not buffered whole', () => {
  // Bun's native HTTP listener keeps reading a CONNECT socket that is
  // paused, so on a loopback listen too the proxy must accept through a
  // net.Server.
  // need_body: the decider is shown the first KiB; the rest streams with
  // the same backpressure.
  // The last column: the sizes of the body frames the decider must be sent.
  const deciders: Array<[string, Parameters<typeof fakeDecider>[1], number[]]> =
    [
      ['allow', () => ({ action: 'allow' }), []],
      [
        'need_body',
        f =>
          f.t === 'req'
            ? { action: 'need_body', max: 1024 }
            : { action: 'allow' },
        [1024],
      ],
    ]
  test.skipIf(!SERVES_EMITTED_CONNECTIONS).each(deciders)(
    'a loopback listen, %s: the client stalls with the upstream, then the whole body arrives',
    async (_name, decide, shown) => {
      const SIZE = 192 << 20
      const ca = generateCa()
      const leaf = mintLeafCert(
        createMitmCA({ caCertPem: ca.certPem, caKeyPem: ca.keyPem }),
        '127.0.0.1',
      )
      const leafOnly = leaf.certPem.match(
        /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\r?\n?/,
      )![0]
      // Reads 1 MiB, then nothing for 3 s, then the rest.
      const up = createHttpsServer(
        { cert: leafOnly, key: leaf.keyPem },
        (req, res) => {
          let n = 0
          let stalled = false
          req.on('data', c => {
            n += c.length
            if (!stalled && n >= 1 << 20) {
              stalled = true
              req.pause()
              setTimeout(() => req.resume(), 3000)
            }
          })
          req.on('end', () => res.end(`got ${n}`))
        },
      )
      await new Promise<void>(r => up.listen(0, '127.0.0.1', r))
      cleanup.push(() => new Promise<void>(r => up.close(() => r())))
      const target = `127.0.0.1:${(up.address() as AddressInfo).port}`
      const d = fakeDecider([target], decide)
      const proxy = startProxyOnly({
        listen: { host: '127.0.0.1', port: 0 },
        decider: d.streams,
        caPem: ca.keyPem + ca.certPem,
        upstreamCA: ca.certPem,
        deciderTimeoutMs: 1000,
      })
      cleanup.push(() => proxy.close())
      await proxy.ready
      const port = (proxy.listener.address() as AddressInfo).port
      let sentDuringStall = 0
      const reply = await new Promise<string>(resolve => {
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
          let sent = 0
          t.on('secureConnect', () => {
            t.write(
              `POST /up HTTP/1.1\r\nHost: ${target}\r\nContent-Length: ${SIZE}\r\nConnection: close\r\n\r\n`,
            )
            const chunk = Buffer.alloc(64 << 10)
            const pump = (): void => {
              while (sent < SIZE) {
                sent += chunk.length
                if (!t.write(chunk)) {
                  t.once('drain', pump)
                  return
                }
              }
            }
            pump()
            setTimeout(() => (sentDuringStall = sent), 2500)
          })
          let out = ''
          t.on('data', y => (out += y))
          t.on('close', () => resolve(out))
          t.on('error', () => resolve(out))
        }
        c.on('data', onData)
        c.on('error', () => resolve(''))
      })
      expect(reply).toContain(`got ${SIZE}`)
      const bodies = d.seen.filter(f => f.t === 'body')
      expect(
        bodies.map(f => Buffer.from(String(f.data), 'base64').length),
      ).toEqual(shown)
      // More body followed what the decider was shown.
      expect(bodies.every(f => f.cut === true)).toBe(true)
      // What the kernel's socket buffers on three loopback hops (up to some
      // 30 MiB here) and the streams hold: well under the body.
      expect(sentDuringStall).toBeLessThan(64 << 20)
    },
    30_000,
  )
})

describe('TLS termination opens nothing another process could reach', () => {
  test.skipIf(!SERVES_EMITTED_CONNECTIONS)(
    'a tunnel is terminated with no listener: no listen() from CONNECT to the end of the response',
    async () => {
      const s = await tlsSetup(() => ({ action: 'allow' }))
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
  testWithTls(
    'past maxTerminatedTunnels, a CONNECT is answered 503 and marked too_many_tunnels',
    async () => {
      const ca = generateCa()
      const mitmCA = createMitmCA({
        caCertPem: ca.certPem,
        caKeyPem: ca.keyPem,
      })
      const proxy = createHttpProxyServer({
        filter: () => true,
        mitmCA,
        maxTerminatedTunnels: 2,
        denyHeader: 'X-Deny-Reason',
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
      expect(third.head).toContain('X-Deny-Reason: too_many_tunnels')
      // A slot frees when a tunnel closes.
      first.sock.destroy()
      await new Promise(r => setTimeout(r, 100))
      const fourth = await open()
      fourth.sock.destroy()
      expect(fourth.head).toStartWith('HTTP/1.1 200')
    },
  )
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
  const d = fakeDecider([target], () => ({ action: 'allow' }))
  const p = startProxyOnly({
    listen: { host: '127.0.0.1', port: 0 },
    decider: d.streams,
    caPem: ca.keyPem + ca.certPem,
    upstreamCA: ca.certPem,
    deciderTimeoutMs: 1000,
  })
  cleanup.push(() => p.close())
  await p.ready
  const port = (p.listener.address() as AddressInfo).port
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
    'proxy-only mode: the upstream is held back, and the client then gets every byte',
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
      const s = await tlsSetup(() => ({ action: 'allow' }))
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
      const s = await tlsSetup(() => ({ action: 'allow' }))
      const r = await sendWithSni(s, 'x_front.example')
      expect(statusOf(r.raw)).toBe(421)
      expect(denyReasonOf(r.raw)).toBe('misdirected')
      expect(s.d.seen).toHaveLength(0)
      expect(s.up.seen).toHaveLength(0)
    },
  )

  test.skipIf(!SERVES_EMITTED_CONNECTIONS)(
    "with requireHostMatch the certificate is the target's whatever name is asked for",
    async () => {
      const s = await tlsSetup(() => ({ action: 'allow' }))
      const r = await sendWithSni(s, 'other.example.test')
      expect(r.cn).toBe('127.0.0.1')
      expect(statusOf(r.raw)).toBe(421)
      expect(s.up.seen).toHaveLength(0)
    },
  )
})

describe("a proxy's connections share one budget for what they hold", () => {
  test.skipIf(!SERVES_EMITTED_CONNECTIONS)(
    'two uploads to stalled upstreams together hold about the budget, then both arrive whole',
    async () => {
      const SIZE = 128 << 20
      const up = createServer((req, res) => {
        let n = 0
        let stalled = false
        req.on('data', c => {
          n += c.length
          if (!stalled && n >= 1 << 20) {
            stalled = true
            req.pause()
            setTimeout(() => req.resume(), 3000)
          }
        })
        req.on('end', () => res.end(`got ${n}`))
      })
      await new Promise<void>(r => up.listen(0, '127.0.0.1', r))
      cleanup.push(() => new Promise<void>(r => up.close(() => r())))
      const upPort = (up.address() as AddressInfo).port
      // Each upload alone may hold far more than both together.
      const proxy = createHttpProxyServer({
        filter: () => true,
        maxBufferedRequestBody: 512 << 20,
        maxBufferedBytes: 8 << 20,
      })
      const front = createNetServer(sock => {
        markHandedInConnection(sock)
        proxy.emit('connection', sock)
      })
      await new Promise<void>(r => front.listen(0, '127.0.0.1', r))
      cleanup.push(() => new Promise<void>(r => front.close(() => r())))
      const port = (front.address() as AddressInfo).port
      const upload = (): { sentAt: () => number; reply: Promise<string> } => {
        let sent = 0
        const reply = new Promise<string>(resolve => {
          const c = connect(port, '127.0.0.1', () => {
            c.write(
              `POST http://127.0.0.1:${upPort}/up HTTP/1.1\r\nHost: 127.0.0.1:${upPort}\r\nContent-Length: ${SIZE}\r\nConnection: close\r\n\r\n`,
            )
            const chunk = Buffer.alloc(64 << 10)
            const pump = (): void => {
              while (sent < SIZE) {
                sent += chunk.length
                if (!c.write(chunk)) {
                  c.once('drain', pump)
                  return
                }
              }
            }
            pump()
          })
          let out = ''
          c.on('data', d => (out += d))
          c.on('close', () => resolve(out))
          c.on('error', () => resolve(out))
        })
        return { sentAt: () => sent, reply }
      }
      const a = upload()
      const b = upload()
      await new Promise(r => setTimeout(r, 2500))
      const heldDuringStall = a.sentAt() + b.sentAt()
      expect(await a.reply).toContain(`got ${SIZE}`)
      expect(await b.reply).toContain(`got ${SIZE}`)
      // The budget, the kernel's buffers on four loopback hops and the
      // streams': no more than the decider's queue may hold before it counts
      // as stalled, and far below the 256 MiB the two would hold without it.
      expect(heldDuringStall).toBeLessThan(MAX_QUEUED_BYTES)
    },
    60_000,
  )
})
