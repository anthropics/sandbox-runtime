import { afterEach, expect, test } from 'bun:test'
import { createHash } from 'node:crypto'
import {
  connect,
  createServer as createNetServer,
  type AddressInfo,
  type Socket,
} from 'node:net'
import {
  connect as tlsConnect,
  createServer as createTlsServer,
  type TLSSocket,
} from 'node:tls'
import { createByteBudget } from '../../src/sandbox/emitted-connection.js'
import { createHttpProxyServer } from '../../src/sandbox/http-proxy.js'
import { createMitmCA, generateCa } from '../../src/sandbox/mitm-ca.js'
import { mintLeafCert } from '../../src/sandbox/mitm-leaf.js'
import { SERVES_EMITTED_CONNECTIONS } from '../helpers/emitted-connections.js'

// An upload through a TLS-terminated tunnel to an upstream that stops
// reading: the proxy holds a bounded part of it, and the rest waits in the
// client. The proxy is handed its connections with emit('connection'), the
// path on which Bun's server is held back by the proxy (the upload gate);
// on a connection Bun's own listener accepted, the runtime reads on.

const cleanup: Array<() => void | Promise<void>> = []
afterEach(async () => {
  while (cleanup.length) await cleanup.pop()!()
})

const SIZE = 96 << 20

/**
 * A TLS upstream that reads a request's head and then nothing until
 * `release()`; then it reads the body (Content-Length: SIZE) and answers
 * with how many bytes it got and their SHA-256.
 */
async function stallingUpstream(cert: string, key: string) {
  let release!: () => void
  const released = new Promise<void>(r => (release = r))
  const server = createTlsServer({ cert, key }, s => {
    s.on('error', () => {})
    cleanup.push(() => void s.destroy())
    let head = Buffer.alloc(0)
    const onHead = (d: Buffer): void => {
      head = Buffer.concat([head, d])
      const end = head.indexOf('\r\n\r\n')
      if (end < 0) return
      s.off('data', onHead)
      s.pause()
      const hash = createHash('sha256')
      let got = 0
      const take = (b: Buffer): void => {
        got += b.length
        hash.update(b)
        if (got < SIZE) return
        const answer = `${got} ${hash.digest('hex')}`
        s.end(
          `HTTP/1.1 200 OK\r\nContent-Length: ${answer.length}\r\nConnection: close\r\n\r\n${answer}`,
        )
      }
      void released.then(() => {
        take(head.subarray(end + 4))
        s.on('data', take)
        s.resume()
      })
    }
    s.on('data', onHead)
  })
  await new Promise<void>(r => server.listen(0, '127.0.0.1', r))
  cleanup.push(() => new Promise<void>(r => server.close(() => r())))
  return { port: (server.address() as AddressInfo).port, release }
}

test.skipIf(!SERVES_EMITTED_CONNECTIONS)(
  'an upload to a stalled upstream is held back in the client, then arrives whole',
  async () => {
    const ca = generateCa()
    const mitmCA = createMitmCA({ caCertPem: ca.certPem, caKeyPem: ca.keyPem })
    const leaf = mintLeafCert(mitmCA, '127.0.0.1')
    const up = await stallingUpstream(
      leaf.certPem.match(
        /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\r?\n?/,
      )![0],
      leaf.keyPem,
    )
    const target = `127.0.0.1:${up.port}`

    const budget = createByteBudget(256 << 20)
    const proxy = createHttpProxyServer({
      filter: () => true,
      mitmCA,
      tlsTerminateUpstreamCA: ca.certPem,
      byteBudget: budget,
    })
    // The proxy is handed each connection, as a host that accepts them
    // itself does; its own listen() is never called.
    let handed: Socket | undefined
    const front = createNetServer(s => {
      handed = s
      s.on('error', () => {})
      cleanup.push(() => void s.destroy())
      proxy.emit('connection', s)
    })
    await new Promise<void>(r => front.listen(0, '127.0.0.1', r))
    cleanup.push(() => new Promise<void>(r => front.close(() => r())))

    const raw = connect((front.address() as AddressInfo).port, '127.0.0.1')
    raw.on('error', () => {})
    cleanup.push(() => void raw.destroy())
    raw.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`)
    const connectReply = await new Promise<string>(r =>
      raw.once('data', (d: Buffer) => r(d.toString('latin1'))),
    )
    expect(connectReply).toStartWith('HTTP/1.1 200')
    const t: TLSSocket = tlsConnect({
      socket: raw,
      ca: ca.certPem,
      checkServerIdentity: () => undefined,
    })
    t.on('error', () => {})
    await new Promise<void>(r => t.once('secureConnect', () => r()))
    // The answer: a head and a body of the upstream's count and digest.
    let response = ''
    const answered = new Promise<void>(resolve => {
      t.on('data', (d: Buffer) => {
        response += d.toString('latin1')
        if (/\r\n\r\n\d+ [0-9a-f]{64}$/.test(response)) resolve()
      })
      t.once('close', () => resolve())
    })

    t.write(
      `POST /upload HTTP/1.1\r\nHost: ${target}\r\nContent-Length: ${SIZE}\r\n\r\n`,
    )
    const chunk = Buffer.alloc(64 << 10)
    for (let i = 0; i < chunk.length; i++) chunk[i] = (i * 7 + (i >> 9)) & 0xff
    const whole = createHash('sha256')
    for (let n = 0; n < SIZE; n += chunk.length) whole.update(chunk)
    let sent = 0
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

    // Wait until the proxy stops taking the upload in (or has all of it).
    let read = -1
    for (let stable = 0, i = 0; stable < 4 && i < 50; i++) {
      await new Promise(r => setTimeout(r, 250))
      const now = handed?.bytesRead ?? 0
      stable = now === read ? stable + 1 : 0
      read = now
    }
    // The gate's 4 MiB, stream and kernel buffers: far below the upload.
    expect(read).toBeLessThan(32 << 20)

    up.release()
    await answered
    expect(response).toStartWith('HTTP/1.1 200')
    expect(response.slice(response.indexOf('\r\n\r\n') + 4)).toBe(
      `${SIZE} ${whole.digest('hex')}`,
    )
    expect(budget.used).toBe(0)
  },
  60_000,
)
