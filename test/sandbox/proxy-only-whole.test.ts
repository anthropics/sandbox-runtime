import { afterEach, describe, expect, spyOn, test } from 'bun:test'
import { createServer, type Server } from 'node:http'
import { connect, createServer as createNetServer } from 'node:net'
import type { AddressInfo } from 'node:net'
import { PassThrough } from 'node:stream'
import * as deciderClient from '../../src/sandbox/decider-client.js'
import { startProxyOnly } from '../../src/sandbox/proxy-only.js'

type Frame = Record<string, unknown>

const cleanup: Array<() => Promise<unknown> | void> = []
afterEach(async () => {
  while (cleanup.length) await cleanup.pop()!()
})

/** A decider on a pair of streams that does nothing on its own. */
function manualDecider() {
  const toProxy = new PassThrough()
  const fromProxy = new PassThrough()
  const seen: Frame[] = []
  let onFrame: (f: Frame) => void = () => {}
  let buf = Buffer.alloc(0)
  const read = (c: Buffer) => {
    buf = Buffer.concat([buf, c])
    while (buf.length >= 4 && buf.length >= 4 + buf.readUInt32BE(0)) {
      const n = buf.readUInt32BE(0)
      const f = JSON.parse(buf.subarray(4, 4 + n).toString()) as Frame
      buf = buf.subarray(4 + n)
      seen.push(f)
      onFrame(f)
    }
  }
  fromProxy.on('data', read)
  return {
    streams: { input: toProxy, output: fromProxy },
    seen,
    send(m: Frame) {
      const b = Buffer.from(JSON.stringify(m))
      const n = Buffer.alloc(4)
      n.writeUInt32BE(b.length)
      toProxy.write(Buffer.concat([n, b]))
    },
    end() {
      toProxy.end()
    },
    onFrame(fn: (f: Frame) => void) {
      onFrame = fn
    },
    /** Keep the stream open and never take another byte from it. */
    stopReading() {
      fromProxy.off('data', read)
      fromProxy.pause()
    },
  }
}

async function upstream() {
  const got: Array<{ url: string; body: string }> = []
  let connections = 0
  const server: Server = createServer((req, res) => {
    let body = ''
    req.on('data', (c: Buffer) => (body += c.toString()))
    req.on('end', () => {
      got.push({ url: req.url ?? '', body })
      res.end('upstream ok')
    })
  })
  server.on('connection', () => connections++)
  await new Promise<void>(r => server.listen(0, '127.0.0.1', r))
  cleanup.push(() => new Promise<void>(r => server.close(() => r())))
  const port = (server.address() as AddressInfo).port
  return { port, got, connections: () => connections }
}

/** A loopback port nothing listens on (taken, then given back). */
async function freePort(): Promise<number> {
  const s = createNetServer()
  await new Promise<void>(r => s.listen(0, '127.0.0.1', r))
  const port = (s.address() as AddressInfo).port
  await new Promise<void>(r => s.close(() => r()))
  return port
}

/** One absolute-form request over a raw socket; the whole response text. */
function request(
  proxyPort: number,
  target: string,
  opts: { body?: string; headers?: Record<string, string> } = {},
): Promise<string> {
  return new Promise(resolve => {
    const sock = connect(proxyPort, '127.0.0.1')
    let out = ''
    sock.on('data', (c: Buffer) => (out += c.toString()))
    sock.on('close', () => resolve(out))
    // A connection the stopping proxy drops unanswered reads as a reset.
    sock.on('error', () => resolve(out || 'reset'))
    const body = opts.body ?? ''
    const headers = {
      host: new URL(target).host,
      connection: 'close',
      ...(opts.body === undefined
        ? {}
        : { 'content-length': String(Buffer.byteLength(body)) }),
      ...opts.headers,
    }
    sock.write(
      `${opts.body === undefined ? 'GET' : 'POST'} ${target} HTTP/1.1\r\n` +
        Object.entries(headers)
          .map(([k, v]) => `${k}: ${v}\r\n`)
          .join('') +
        '\r\n' +
        body,
    )
  })
}

function refused(port: number): Promise<string> {
  return new Promise(resolve => {
    const sock = connect(port, '127.0.0.1')
    sock.on('connect', () => {
      sock.destroy()
      resolve('connected')
    })
    sock.on('error', (e: NodeJS.ErrnoException) => resolve(e.code ?? 'error'))
  })
}

function start(
  d: ReturnType<typeof manualDecider>,
  listenPort: number,
  deciderTimeoutMs = 5000,
) {
  const closed: string[] = []
  let stopped!: (why: string) => void
  const whenStopped = new Promise<string>(r => (stopped = r))
  const proxy = startProxyOnly({
    listen: { host: '127.0.0.1', port: listenPort },
    decider: d.streams,
    deciderTimeoutMs,
    onClosed: why => {
      closed.push(why)
      stopped(why)
    },
  })
  cleanup.push(() => proxy.close())
  return { proxy, closed, whenStopped }
}

/** Limits reach the decider client only as createDecider options. */
function withDeciderLimits(
  limits: Pick<
    deciderClient.DeciderOptions,
    'maxBodyBytesHeld' | 'maxQueuedBytes'
  >,
) {
  const real = deciderClient.createDecider
  const spy = spyOn(deciderClient, 'createDecider').mockImplementation(o =>
    real({ ...o, ...limits }),
  )
  cleanup.push(() => spy.mockRestore())
}

describe('the whole proxy: start-up order and decider limits', () => {
  test('nothing listens until the decider has said hello; then requests are served', async () => {
    const up = await upstream()
    const port = await freePort()
    const d = manualDecider()
    const firstFrame = new Promise<Frame>(r => d.onFrame(r))
    const { proxy } = start(d, port)

    expect(await firstFrame).toEqual({ t: 'hello', proto: 1 })
    expect(await refused(port)).toBe('ECONNREFUSED')
    expect(proxy.listener.listening).toBe(false)
    expect(up.connections()).toBe(0)
    expect(d.seen).toHaveLength(1)

    d.onFrame(f => d.send({ t: 'verdict', id: f.id, action: 'allow' }))
    d.send({
      t: 'hello',
      proto: 1,
      allowedDomains: [`127.0.0.1:${up.port}`],
      deniedDomains: [],
    })
    await proxy.ready
    const res = await request(port, `http://127.0.0.1:${up.port}/after`)
    expect(res).toStartWith('HTTP/1.1 200')
    expect(up.got.map(g => g.url)).toEqual(['/after'])
    expect(d.seen.map(f => f.t)).toEqual(['hello', 'req'])
  })

  test('a hello of another protocol version, or a decider that leaves without one, fails the start and never listens', async () => {
    for (const badHello of [true, false]) {
      const port = await freePort()
      const d = manualDecider()
      const firstFrame = new Promise<Frame>(r => d.onFrame(r))
      const { proxy, whenStopped } = start(d, port)
      await firstFrame
      // There is no deadline for the hello itself: until it comes, or the
      // decider's stream ends, the proxy waits without listening.
      expect(proxy.listener.listening).toBe(false)
      if (badHello) {
        d.send({ t: 'hello', proto: 2, allowedDomains: [], deniedDomains: [] })
      } else {
        d.end()
      }
      const err = await proxy.ready.then(
        () => undefined,
        (e: Error) => e,
      )
      expect(err?.message).toMatch(
        badHello
          ? /^decider unavailable: bad hello$/
          : /^decider unavailable: /,
      )
      expect(await whenStopped).toMatch(
        badHello ? /^decider: bad hello$/ : /^decider: /,
      )
      expect(proxy.listener.listening).toBe(false)
      expect(await refused(port)).toBe('ECONNREFUSED')
      expect(d.seen.map(f => f.t)).toEqual(['hello'])
    }
  })

  test('body inspection past the held-body budget is refused 503 and dials nothing; the budget is released', async () => {
    const max = 2048
    withDeciderLimits({ maxBodyBytesHeld: 2 * max })
    const up = await upstream()
    const d = manualDecider()
    let release!: () => void
    const gate = new Promise<void>(r => (release = r))
    let asked = 0
    let allAsked!: () => void
    const threeAsked = new Promise<void>(r => (allAsked = r))
    d.onFrame(f => {
      if (f.t === 'hello') {
        d.send({
          t: 'hello',
          proto: 1,
          allowedDomains: [`127.0.0.1:${up.port}`],
          deniedDomains: [],
        })
      } else if (f.t === 'req') {
        d.send({ t: 'verdict', id: f.id, action: 'need_body', max })
        if (++asked === 3) allAsked()
      } else {
        void gate.then(() =>
          d.send({ t: 'verdict', id: f.id, action: 'allow' }),
        )
      }
    })
    const { proxy } = start(d, 0)
    await proxy.ready
    const port = (proxy.listener.address() as AddressInfo).port
    const post = (n: number) =>
      request(port, `http://127.0.0.1:${up.port}/p${n}`, {
        body: `${n}`.repeat(1500),
      })

    const pending = [post(1), post(2), post(3)]
    await threeAsked
    // The one over the budget is answered while the other two are held.
    const over = await Promise.race(pending)
    expect(over).toStartWith('HTTP/1.1 503')
    expect(over).toContain('decider_unavailable')
    expect(up.connections()).toBe(0)

    release()
    const all = await Promise.all(pending)
    expect(all.filter(r => r.startsWith('HTTP/1.1 200'))).toHaveLength(2)
    expect(all.filter(r => r.startsWith('HTTP/1.1 503'))).toHaveLength(1)
    expect(up.got).toHaveLength(2)
    expect(up.connections()).toBe(2)
    for (const g of up.got) expect(g.body).toBe(g.url[2]!.repeat(1500))

    expect(await post(4)).toStartWith('HTTP/1.1 200')
    expect(up.got.at(-1)).toEqual({ url: '/p4', body: '4'.repeat(1500) })
  })

  test('a decider that stops reading stops the proxy; requests in flight are refused and none is dialled', async () => {
    withDeciderLimits({ maxQueuedBytes: 64 * 1024 })
    const up = await upstream()
    const d = manualDecider()
    d.onFrame(() => {
      d.stopReading()
      d.send({
        t: 'hello',
        proto: 1,
        allowedDomains: [`127.0.0.1:${up.port}`],
        deniedDomains: [],
      })
    })
    const { proxy, whenStopped } = start(d, 0)
    await proxy.ready
    const port = (proxy.listener.address() as AddressInfo).port

    const pending = Array.from({ length: 24 }, (_, i) =>
      request(port, `http://127.0.0.1:${up.port}/q${i}`, {
        headers: { 'x-fill': 'f'.repeat(8000) },
      }),
    )
    expect(await whenStopped).toMatch(
      /^decider: not reading: \d+ bytes queued$/,
    )
    const all = await Promise.all(pending)
    // Those the decider client had taken are answered 503; a connection the
    // stopping proxy had not got to is dropped. Nothing gets a 2xx.
    const answered = all.filter(r => r !== 'reset')
    expect(answered.length).toBeGreaterThan(0)
    for (const r of answered) {
      expect(r).toStartWith('HTTP/1.1 503')
      expect(r).toContain('decider_unavailable')
    }
    expect(up.connections()).toBe(0)
    expect(up.got).toHaveLength(0)
  })
})
