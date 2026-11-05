import { afterEach, describe, expect, test } from 'bun:test'
import { createServer } from 'node:http'
import { connect, type AddressInfo, type Socket } from 'node:net'
import { PassThrough } from 'node:stream'
import { startProxyOnly } from '../../src/sandbox/proxy-only.js'
import { fakeDecider, type Frame } from '../helpers/fake-decider.js'

const cleanup: Array<() => unknown> = []
afterEach(async () => {
  for (const f of cleanup.splice(0).reverse()) await f()
})

async function setup(decide: Parameters<typeof fakeDecider>[1]) {
  const requests: Array<{ method: string; body: string }> = []
  const server = createServer((req, res) => {
    let body = ''
    req.on('data', (c: Buffer) => (body += c.toString('utf8')))
    req.on('end', () => {
      requests.push({ method: req.method ?? '', body })
      res.end('ok')
    })
  })
  await new Promise<void>(r => server.listen(0, '127.0.0.1', r))
  cleanup.push(() => new Promise<void>(r => server.close(() => r())))
  const upPort = (server.address() as AddressInfo).port
  const d = fakeDecider([`127.0.0.1:${upPort}`], decide)
  const proxy = startProxyOnly({
    listen: { host: '127.0.0.1', port: 0 },
    decider: d.streams,
    lifeline: new PassThrough(),
    deciderTimeoutMs: 2000,
    stripResponseHeaders: [],
    onClosed: () => {},
  })
  cleanup.push(() => proxy.close())
  await proxy.ready
  const port = (proxy.listener.address() as AddressInfo).port
  const open = async (): Promise<Socket> => {
    const sock = connect(port, '127.0.0.1')
    cleanup.push(() => sock.destroy())
    await new Promise<void>(r => sock.once('connect', () => r()))
    return sock
  }
  const head = (method: string) =>
    `${method} http://127.0.0.1:${upPort}/x HTTP/1.1\r\nHost: 127.0.0.1:${upPort}\r\n`
  const frames = (t: string) => d.seen.filter(f => f.t === t)
  return { requests, open, head, frames }
}

/** Writes one request and resolves with the whole response to it. */
function exchange(sock: Socket, raw: string): Promise<string> {
  return new Promise<string>((resolve, reject) => {
    let buf = ''
    const onData = (c: Buffer) => {
      buf += c.toString('latin1')
      const end = buf.indexOf('\r\n\r\n')
      if (end < 0) return
      const length = Number(/^content-length:\s*(\d+)/im.exec(buf)?.[1] ?? 0)
      if (buf.length - (end + 4) < length) return
      sock.off('data', onData)
      resolve(buf)
    }
    sock.on('data', onData)
    sock.once('close', () => reject(new Error(`closed after: ${buf}`)))
    sock.write(raw)
  })
}

const allow = (f: Frame): Frame => ({ t: 'verdict', id: f.id, action: 'allow' })

describe('methods the proxy refuses itself', () => {
  // The runtime's HTTP parser may reject TRACK as an unknown method (400)
  // before the proxy's own rule (405) is reached; both are refusals.
  for (const [method, status] of [
    ['TRACE', /^HTTP\/1\.1 405 /],
    ['TRACK', /^HTTP\/1\.1 (405|400) /],
  ] as const)
    test(`${method} over plain HTTP is refused before the decider or the upstream sees it`, async () => {
      const s = await setup(allow)
      const refused = await exchange(await s.open(), `${s.head(method)}\r\n`)
      expect(refused).toMatch(status)
      if (method === 'TRACE') expect(refused).toContain('method_refused')
      expect(s.frames('req')).toHaveLength(0)
      expect(s.requests).toHaveLength(0)
      // The refusal closes its connection; the proxy keeps serving.
      const next = await exchange(await s.open(), `${s.head('GET')}\r\n`)
      expect(next).toStartWith('HTTP/1.1 200 ')
      expect(s.frames('req')).toHaveLength(1)
      expect(s.requests).toEqual([{ method: 'GET', body: '' }])
    })
})

describe('a body on a method that normally has none', () => {
  // Asks for the body of every request, then allows whatever it is shown.
  const askThenAllow = (f: Frame) =>
    f.t === 'req'
      ? { t: 'verdict', id: f.id, action: 'need_body', max: 1024 }
      : f.t === 'body'
        ? allow(f)
        : 'hang'
  const shown = (s: { frames: (t: string) => Frame[] }) =>
    s
      .frames('body')
      .map(f => Buffer.from(String(f.data), 'base64').toString('utf8'))

  for (const method of ['GET', 'HEAD', 'OPTIONS'])
    for (const [framing, tail] of [
      ['Content-Length', 'Content-Length: 5\r\n\r\nhello'],
      ['chunked', 'Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n'],
    ] as const)
      test(`${method} with a ${framing} body is refused when the decider asks to see the body`, async () => {
        const s = await setup(askThenAllow)
        const refused = await exchange(
          await s.open(),
          `${s.head(method)}${tail}`,
        )
        expect(refused).toStartWith('HTTP/1.1 403 ')
        expect(refused).toContain('bodyless_method_body')
        // Nothing went upstream, and the decider was never shown a body
        // that was not the request's.
        expect(s.requests).toHaveLength(0)
        expect(s.frames('req')).toHaveLength(1)
        expect(s.frames('body')).toHaveLength(0)
      })

  for (const [name, tail] of [
    ['no body', '\r\n'],
    ['Content-Length: 0', 'Content-Length: 0\r\n\r\n'],
    ['an empty chunked body', 'Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n'],
  ] as const)
    test(`GET with ${name} still shows the decider an empty complete body and its allow is honoured`, async () => {
      const s = await setup(askThenAllow)
      const ok = await exchange(await s.open(), `${s.head('GET')}${tail}`)
      expect(ok).toStartWith('HTTP/1.1 200 ')
      expect(shown(s)).toEqual([''])
      expect(s.frames('body')[0]?.cut).toBeUndefined()
      expect(s.requests).toEqual([{ method: 'GET', body: '' }])
    })

  test('GET with a body is forwarded as before when the decider allows without asking for it', async () => {
    const s = await setup(allow)
    const ok = await exchange(
      await s.open(),
      `${s.head('GET')}Content-Length: 5\r\n\r\nhello`,
    )
    expect(ok).toStartWith('HTTP/1.1 200 ')
    expect(s.frames('body')).toHaveLength(0)
    expect(s.requests).toEqual([{ method: 'GET', body: 'hello' }])
  })

  test('GET with a body is denied as before when the decider denies without asking for it', async () => {
    const s = await setup(f => ({
      t: 'verdict',
      id: f.id,
      action: 'deny',
      status: 403,
    }))
    const denied = await exchange(
      await s.open(),
      `${s.head('GET')}Content-Length: 5\r\n\r\nhello`,
    )
    expect(denied).toStartWith('HTTP/1.1 403 ')
    expect(denied).not.toContain('bodyless_method_body')
    expect(s.requests).toHaveLength(0)
  })

  test('POST is unchanged: the decider is shown the body and its allow forwards it', async () => {
    const s = await setup(askThenAllow)
    const ok = await exchange(
      await s.open(),
      `${s.head('POST')}Content-Length: 5\r\n\r\nhello`,
    )
    expect(ok).toStartWith('HTTP/1.1 200 ')
    expect(shown(s)).toEqual(['hello'])
    expect(s.requests).toEqual([{ method: 'POST', body: 'hello' }])
  })
})
