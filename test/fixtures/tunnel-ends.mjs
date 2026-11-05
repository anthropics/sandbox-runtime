/**
 * The scenarios of tls-terminate-tunnel-ends.test.ts, run as a child under
 * Node and under Bun against dist/. Each scenario has a proxy with one
 * tunnel slot and an upstream of its own, and says how its tunnel ended.
 * argv[2] is `accepted` (the proxy listens) or `handed` (it is given each
 * connection with emit('connection')); argv[3], if given, names the one
 * scenario to run. Prints one JSON object. (`exit with a tunnel open` prints
 * nothing: it opens a tunnel and has nothing more to do.)
 */
import { readFileSync } from 'node:fs'
import { IncomingMessage } from 'node:http'
import { connect, createServer } from 'node:net'
import { Duplex } from 'node:stream'
import { fileURLToPath } from 'node:url'
import {
  connect as tlsConnect,
  createServer as createTlsServer,
} from 'node:tls'

const dist = f => new URL(`../../dist/sandbox/${f}.js`, import.meta.url).href
const { createHttpProxyServer } = await import(dist('http-proxy'))
const { createByteBudget } = await import(dist('emitted-connection'))
const { createMitmCA } = await import(dist('mitm-ca'))
const { mintLeafCert } = await import(dist('mitm-leaf'))

// Whether a server drains a request that was being read when its response
// ends differs by runtime and version. Here none does.
IncomingMessage.prototype._dump = function () {}

const HANDED = process.argv[2] === 'handed'
const MiB = 1 << 20
/** More than a proxy that stops reading, and the kernel, take in. */
const UPLOAD = 24 * MiB
/** A tunnel still open this long after it should have closed counts as open. */
const GIVE_UP_MS = 3_000
/** A timeout that plays no part in a scenario. */
const NEVER = 600_000
const NO_TIMEOUTS = {
  firstRequestMs: NEVER,
  keepAliveMs: NEVER,
  keepAliveMarginMs: 0,
  stalledMs: NEVER,
}
const sleep = ms => new Promise(r => setTimeout(r, ms))

const pem = f => fileURLToPath(new URL(`tls-terminate/${f}`, import.meta.url))
const caPem = readFileSync(pem('ca.crt'), 'utf8')
const mitmCA = createMitmCA({
  caCertPath: pem('ca.crt'),
  caKeyPath: pem('ca.key'),
})
const leaf = mintLeafCert(mitmCA, '127.0.0.1')
const listen = server =>
  new Promise(r =>
    server.listen(0, '127.0.0.1', () => r(server.address().port)),
  )
/** Nothing listens there. */
const CLOSED = '127.0.0.1:1'

/**
 * A TLS upstream. It reads a request's head; a GET is answered by `onGet`
 * (default: 200 at once), and a POST is left to `onPost`, paused, with how
 * much of its body came with the head.
 */
async function startUpstream({ onPost, onGet } = {}) {
  const open = new Set()
  const answer = (s, status, body = 'ok') =>
    s.write(
      `HTTP/1.1 ${status} X\r\nContent-Length: ${body.length}\r\n\r\n${body}`,
    )
  const server = createTlsServer(
    { cert: leaf.certPem, key: leaf.keyPem },
    s => {
      open.add(s)
      s.on('error', () => {})
      s.once('close', () => open.delete(s))
      let seen = Buffer.alloc(0)
      const onHead = d => {
        seen = Buffer.concat([seen, d])
        const end = seen.indexOf('\r\n\r\n')
        if (end < 0) return
        const rest = seen.length - end - 4
        const isPost = seen.toString('latin1', 0, 4) === 'POST'
        seen = Buffer.alloc(0)
        if (!isPost) return void (onGet ?? answer)(s, 200)
        s.off('data', onHead)
        s.pause()
        onPost(s, answer, rest)
      }
      s.on('data', onHead)
    },
  )
  return {
    target: `127.0.0.1:${await listen(server)}`,
    /** The connections the proxy still holds (a paused one must read to see its end). */
    async stillOpen() {
      for (const s of open) s.resume()
      await sleep(100)
      return open.size
    },
  }
}

/** An `onGet` that answers with `size` bytes (a multiple of 64 KiB), as fast as they are taken. */
const longAnswer = size => s => {
  s.write(`HTTP/1.1 200 X\r\nContent-Length: ${size}\r\n\r\n`)
  const chunk = Buffer.alloc(64 << 10, 7)
  let sent = 0
  const pump = () => {
    while (sent < size) {
      sent += chunk.length
      if (!s.write(chunk)) return void s.once('drain', pump)
    }
  }
  pump()
}

/**
 * A tunnel through a proxy with one slot in front of `target`, its handshake
 * done. `halfOpen`: the client's socket does not end because the proxy's did.
 */
async function openTunnel({
  target,
  timeouts,
  trustUpstream = true,
  halfOpen = false,
  ...options
}) {
  const budget = createByteBudget(256 * MiB)
  const proxy = createHttpProxyServer({
    filter: () => true,
    filterRequest: () => ({ action: 'allow' }),
    mitmCA,
    tlsTerminateUpstreamCA: trustUpstream ? caPem : undefined,
    maxTerminatedTunnels: 1,
    tunnelTimeouts: timeouts,
    byteBudget: budget,
    ...options,
  })
  const front = HANDED
    ? createServer(s => {
        s.on('error', () => {})
        proxy.emit('connection', s)
      })
    : proxy
  const port = await listen(front)
  /** The status of the answer to a CONNECT, and its socket. */
  const connectTo = (allowHalfOpen = false) =>
    new Promise(resolve => {
      const raw = connect({ port, host: '127.0.0.1', allowHalfOpen }, () =>
        raw.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`),
      )
      raw.on('error', () => {})
      raw.once('data', d =>
        resolve({ status: Number(String(d).split(' ')[1]), raw }),
      )
    })

  const { raw } = await connectTo(halfOpen)
  // The TLS client runs on a stream over the socket, so that what the proxy
  // sends can be counted.
  let got = 0
  let mute = false
  const wire = new Duplex({
    read() {},
    write: (chunk, _encoding, callback) =>
      mute ? callback() : raw.write(chunk, callback),
    final(callback) {
      if (!mute) raw.end()
      callback()
    },
  })
  raw.on('data', d => {
    got += d.length
    wire.push(d)
  })
  raw.once('end', () => wire.push(null))
  const closed = new Promise(r => raw.once('close', () => r(Date.now())))
  const t = tlsConnect({
    socket: wire,
    ca: caPem,
    checkServerIdentity: () => undefined,
  })
  t.on('error', () => {})
  await new Promise(r => t.once('secureConnect', r))
  let text = ''
  // The bytes of a long answer's body are counted, not kept, once its head
  // is in.
  let long = false
  let body
  let lastByteAt = Date.now()
  t.on('data', d => {
    lastByteAt = Date.now()
    if (body !== undefined) return void (body += d.length)
    text += d.toString('latin1')
    const head = text.indexOf('\r\n\r\n')
    if (!long || head < 0) return
    body = text.length - head - 4
    text = ''
  })

  /** The next whole answer (status 0: none came). */
  const answer = async () => {
    for (const until = Date.now() + 2 * GIVE_UP_MS; ; await sleep(5)) {
      const m = /^(HTTP\/1\.1 (\d+)[^]*?\r\n\r\n)/.exec(text)
      const length = Number(/content-length: (\d+)/i.exec(m?.[1])?.[1] ?? 0)
      if (m && text.length >= m[1].length + length) {
        text = text.slice(m[1].length + length)
        return { status: Number(m[2]), head: m[1] }
      }
      if (raw.destroyed || Date.now() > until) return { status: 0, head: '' }
    }
  }
  return {
    answer,
    write: bytes => void t.write(bytes),
    get() {
      t.write(`GET / HTTP/1.1\r\nHost: ${target}\r\n\r\n`)
      return answer()
    },
    /**
     * Send a POST of `size`. Resolves true once it has all gone out, false
     * once nothing of it has for 200 ms.
     */
    async post(size, { host = target, path = '/' } = {}) {
      t.write(
        `POST ${path} HTTP/1.1\r\nHost: ${host}\r\nContent-Length: ${size}\r\n\r\n`,
      )
      const chunk = Buffer.alloc(64 << 10, 7)
      let sent = 0
      let out = false
      const pump = () => {
        while (sent < size && !t.destroyed) {
          sent += chunk.length
          const last = sent >= size ? () => (out = true) : undefined
          if (!t.write(chunk, last)) return void t.once('drain', pump)
        }
      }
      pump()
      for (let seen = -1; !out && seen !== raw.bytesWritten; await sleep(200)) {
        seen = raw.bytesWritten
      }
      return out
    },
    /** Ask for a long answer; `headers` go with the request. */
    askForLong(headers = '') {
      long = true
      t.write(`GET / HTTP/1.1\r\nHost: ${target}\r\n${headers}\r\n`)
    },
    /** Take nothing more from the socket, or take it up again. */
    stopReading: () => void raw.pause(),
    readOn: () => void raw.resume(),
    /** How much of the first `size` bytes of a long answer never came. */
    async missingOf(size) {
      const missing = () => Math.max(0, size - (body ?? 0))
      const until = Date.now() + 20_000
      while (missing() > 0 && !raw.destroyed && Date.now() < until) {
        await sleep(5)
      }
      return missing()
    },
    leave: () => void t.end(),
    /** From now on the client sends nothing, not even its end. */
    fallSilent: () => void (mute = true),
    /** When the tunnel's slot is free again, from the proxy's last byte. */
    async slotFree() {
      for (const until = Date.now() + GIVE_UP_MS; Date.now() < until; ) {
        const next = await connectTo()
        next.raw.destroy()
        if (next.status === 200) return Date.now() - lastByteAt
        await sleep(25)
      }
      return 'held'
    },
    /** Let neither the proxy's listener nor the client's socket hold the process. */
    unref() {
      front.unref()
      raw.unref()
    },
    /**
     * How the tunnel ends: when, from the proxy's last byte or from `since`;
     * whether the proxy said so first (a close_notify); whether its slot
     * and the bytes counted for it are free again.
     */
    async end(since = lastByteAt) {
      const before = got
      const closedAt = await Promise.race([closed, sleep(GIVE_UP_MS)])
      raw.destroy()
      await sleep(50)
      const next = await connectTo()
      next.raw.destroy()
      return {
        closedAfterMs: closedAt === undefined ? 'open' : closedAt - since,
        closeNotify: got > before,
        nextConnect: next.status,
        heldBytes: budget.used,
      }
    },
  }
}

/** An upload answered before it is all in; `then` is what its client does next. */
async function answeredEarly(then, { host, path, ...options } = {}) {
  const up = await startUpstream({
    onPost: (s, answer) => setTimeout(() => answer(s, 413, 'early'), 200),
  })
  const c = await openTunnel({
    target: up.target,
    timeouts: NO_TIMEOUTS,
    ...options,
  })
  const sent = c.post(UPLOAD, { host, path })
  const { status } = await c.answer()
  const more = await then(c, await sent)
  return { status, ...more, ...(await c.end()), upstream: await up.stillOpen() }
}
const leaves = c => c.leave()

/** Timed to a few hundred ms: run together, with nothing heavy beside them. */
const light = {
  async 'idle after a response'() {
    const up = await startUpstream()
    const c = await openTunnel({
      target: up.target,
      timeouts: { ...NO_TIMEOUTS, keepAliveMs: 1_000, keepAliveMarginMs: 500 },
    })
    const { status, head } = await c.get()
    const advertised = /keep-alive: ([^\r]*)/i.exec(head)?.[1]
    return {
      status,
      advertised,
      ...(await c.end()),
      upstream: await up.stillOpen(),
    }
  },

  async 'asked again when the advertised time is up'() {
    const up = await startUpstream()
    const c = await openTunnel({
      target: up.target,
      timeouts: { ...NO_TIMEOUTS, keepAliveMs: 1_000, keepAliveMarginMs: 700 },
    })
    await c.get()
    await sleep(1_100)
    return { status: (await c.get()).status }
  },

  // Node's server has a keep-alive timeout of its own, 1 s past the time
  // advertised.
  async 'a margin longer than the runtime has'() {
    const up = await startUpstream()
    const c = await openTunnel({
      target: up.target,
      timeouts: { ...NO_TIMEOUTS, keepAliveMs: 200, keepAliveMarginMs: 1_800 },
    })
    await c.get()
    return c.end()
  },

  async 'idle, and the client answers no end'() {
    const up = await startUpstream()
    const c = await openTunnel({
      target: up.target,
      timeouts: { ...NO_TIMEOUTS, keepAliveMs: 500 },
      halfOpen: true,
    })
    await c.get()
    c.fallSilent()
    return { slotFreeAfterMs: await c.slotFree() }
  },

  async 'the default Keep-Alive'() {
    const up = await startUpstream()
    const c = await openTunnel({ target: up.target })
    const { head } = await c.get()
    c.leave()
    return { advertised: /keep-alive: ([^\r]*)/i.exec(head)?.[1] }
  },

  async 'each response starts the idle time anew'() {
    const up = await startUpstream()
    const c = await openTunnel({
      target: up.target,
      timeouts: { ...NO_TIMEOUTS, keepAliveMs: 800 },
    })
    const statuses = []
    for (let i = 0; i < 3; i++) {
      if (i) await sleep(500)
      statuses.push((await c.get()).status)
    }
    return { statuses, ...(await c.end()) }
  },

  async 'no request after the handshake'() {
    const c = await openTunnel({
      target: CLOSED,
      timeouts: { ...NO_TIMEOUTS, firstRequestMs: 800 },
    })
    return c.end(Date.now())
  },

  async 'half a head'() {
    const c = await openTunnel({
      target: CLOSED,
      timeouts: { ...NO_TIMEOUTS, firstRequestMs: 800 },
    })
    c.write('GET / HTTP/1.1\r\nX-Half')
    return c.end(Date.now())
  },

  async 'half a head after a response'() {
    const up = await startUpstream()
    const c = await openTunnel({
      target: up.target,
      timeouts: { ...NO_TIMEOUTS, keepAliveMs: 800 },
    })
    const { status } = await c.get()
    c.write('GET / HTTP/1.1\r\nX-Half')
    return { status, ...(await c.end()) }
  },

  async 'half a body'() {
    const up = await startUpstream({ onPost: s => s.resume() })
    const c = await openTunnel({
      target: up.target,
      timeouts: { ...NO_TIMEOUTS, stalledMs: 500 },
    })
    c.write(
      `POST / HTTP/1.1\r\nHost: ${up.target}\r\nContent-Length: 10\r\n\r\nhalf`,
    )
    return { ...(await c.end(Date.now())), upstream: await up.stillOpen() }
  },

  async 'a body that trickles in'() {
    const up = await startUpstream({
      onPost(s, answer, rest) {
        let taken = rest
        s.on('data', d => (taken += d.length) >= 8 && answer(s, 200))
        s.resume()
      },
    })
    const c = await openTunnel({
      target: up.target,
      timeouts: { ...NO_TIMEOUTS, stalledMs: 700 },
    })
    c.write(
      `POST / HTTP/1.1\r\nHost: ${up.target}\r\nContent-Length: 8\r\n\r\n`,
    )
    for (let i = 0; i < 8; i++) {
      await sleep(250)
      c.write('.')
    }
    return { status: (await c.answer()).status }
  },

  async 'an answer that takes longer than every timeout'() {
    const up = await startUpstream({
      onGet: s =>
        setTimeout(
          () => s.write('HTTP/1.1 200 X\r\nContent-Length: 0\r\n\r\n'),
          1_200,
        ),
    })
    const c = await openTunnel({
      target: up.target,
      timeouts: { firstRequestMs: 300, keepAliveMs: 300, stalledMs: 300 },
    })
    return { status: (await c.get()).status }
  },
}

/** Much to carry: run one at a time. */
const heavy = {
  // What the kernel takes for a client that reads nothing differs, and only
  // an answer up to a megabyte longer than that is all out, and yet queued.
  async 'readers that take nothing for a while, then everything'() {
    const cases = []
    for (let size = MiB; size <= 6 * MiB; size += MiB / 2) {
      cases.push([size, ''], [size, 'Connection: close\r\n'])
    }
    const ends = await Promise.all(
      cases.map(async ([size, headers]) => {
        const up = await startUpstream({ onGet: longAnswer(size) })
        const c = await openTunnel({
          target: up.target,
          timeouts: { ...NO_TIMEOUTS, keepAliveMs: 200 },
        })
        c.stopReading()
        c.askForLong(headers)
        await sleep(1_000)
        c.readOn()
        return [await c.missingOf(size), (await c.end()).closedAfterMs]
      }),
    )
    // All of it came, and then the tunnel was closed as any idle one is.
    return { missing: ends.filter(([n, closed]) => n > 0 || closed === 'open') }
  },

  'answered early, the client leaves': () => answeredEarly(leaves),
  'upstream port closed, the client leaves': () =>
    answeredEarly(leaves, { target: CLOSED }),
  'upstream certificate untrusted, the client leaves': () =>
    answeredEarly(leaves, { trustUpstream: false }),
  'refused for its Host, the client leaves': () =>
    answeredEarly(leaves, { requireHostMatch: true, host: 'other.test' }),
  'refused for its target, the client leaves': () =>
    answeredEarly(leaves, { path: '*' }),
  'answered early, the client stays': () =>
    answeredEarly(() => {}, { timeouts: { ...NO_TIMEOUTS, keepAliveMs: 600 } }),
  'answered early, the client sends on and asks again': () =>
    answeredEarly(async (c, allSent) => {
      const second = allSent && (await c.get()).status
      c.leave()
      return { second }
    }),

  async 'a reader that takes an answer in bursts'() {
    const up = await startUpstream({ onGet: longAnswer(UPLOAD) })
    const c = await openTunnel({
      target: up.target,
      timeouts: { ...NO_TIMEOUTS, keepAliveMs: 200, stalledMs: 1_000 },
    })
    c.askForLong()
    // 6 MiB, then nothing for 400 ms, and so on: longer in all than
    // stalledMs, never that long at a time.
    for (let next = 6 * MiB; next < UPLOAD; next += 6 * MiB) {
      await c.missingOf(next)
      c.stopReading()
      await sleep(400)
      c.readOn()
    }
    return { missing: await c.missingOf(UPLOAD) }
  },

  async 'a client that never reads its answer'() {
    const up = await startUpstream({ onGet: longAnswer(UPLOAD) })
    const c = await openTunnel({
      target: up.target,
      timeouts: { ...NO_TIMEOUTS, stalledMs: 500 },
    })
    c.stopReading()
    c.askForLong()
    return {
      slotFreeAfterMs: await c.slotFree(),
      upstream: await up.stillOpen(),
    }
  },

  async 'an upload the upstream stops taking'() {
    const up = await startUpstream({ onPost() {} })
    const c = await openTunnel({
      target: up.target,
      timeouts: { ...NO_TIMEOUTS, stalledMs: 500 },
    })
    const since = Date.now()
    await c.post(2 * UPLOAD)
    return { ...(await c.end(since)), upstream: await up.stillOpen() }
  },

  async 'an upload the upstream takes in bursts'() {
    const size = 2 * UPLOAD
    const up = await startUpstream({
      // 6 MiB (more than the proxy holds back, so that it reads on), then
      // nothing for 300 ms, and so on: far longer in all than stalledMs,
      // never that long at a time.
      onPost(s, answer, rest) {
        let taken = rest
        let burst = 0
        s.on('data', d => {
          taken += d.length
          burst += d.length
          if (taken >= size) return void answer(s, 200)
          if (burst < 6 * MiB) return
          burst = 0
          s.pause()
          setTimeout(() => s.resume(), 300)
        })
        s.resume()
      },
    })
    const c = await openTunnel({
      target: up.target,
      timeouts: { ...NO_TIMEOUTS, stalledMs: 700 },
    })
    void c.post(size)
    return { status: (await c.answer()).status }
  },
}

if (process.argv[3] === 'exit with a tunnel open') {
  const c = await openTunnel({
    target: CLOSED,
    timeouts: NO_TIMEOUTS,
  })
  c.unref()
} else {
  const only = ([name]) =>
    process.argv[3] === undefined || name === process.argv[3]
  const results = Object.fromEntries(
    await Promise.all(
      Object.entries(light)
        .filter(only)
        .map(async ([name, run]) => [name, await run()]),
    ),
  )
  for (const [name, run] of Object.entries(heavy).filter(only)) {
    results[name] = await run()
  }
  process.stdout.write(JSON.stringify(results), () => process.exit(0))
}
