import { afterEach, expect } from 'bun:test'
// Every case here runs a proxy configured to terminate TLS, so each is
// skipped where this runtime cannot terminate it in-process.
import { testWithTls as test } from '../helpers/emitted-connections.js'
import { createHash } from 'node:crypto'
import { request } from 'node:http'
import { createServer as createHttpsServer } from 'node:https'
import { connect, type AddressInfo, type Socket } from 'node:net'
import { connect as tlsConnect } from 'node:tls'
import { createByteBudget } from '../../src/sandbox/emitted-connection.js'
import { createHttpProxyServer } from '../../src/sandbox/http-proxy.js'
import { createMitmCA, generateCa } from '../../src/sandbox/mitm-ca.js'
import { mintLeafCert } from '../../src/sandbox/mitm-leaf.js'

const cleanup: Array<() => void | Promise<void>> = []
afterEach(async () => {
  for (const fn of cleanup.splice(0).reverse()) await fn()
})

test('two large responses to slow readers through terminated tunnels share a small budget, arrive whole, and leave it empty', async () => {
  const SIZE = 48 << 20
  const chunk = Buffer.alloc(64 << 10)
  for (let i = 0; i < chunk.length; i++) chunk[i] = (i * 31 + (i >> 8)) & 0xff
  const whole = createHash('sha256')
  for (let sent = 0; sent < SIZE; sent += chunk.length) whole.update(chunk)
  const wholeDigest = whole.digest('hex')

  const ca = generateCa()
  const leaf = mintLeafCert(
    createMitmCA({ caCertPem: ca.certPem, caKeyPem: ca.keyPem }),
    '127.0.0.1',
  )
  const leafOnly = leaf.certPem.match(
    /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\r?\n?/,
  )![0]
  // Each large response reports the first time the path to its client is
  // full, so the clients start reading only once the proxy holds all it will.
  const backedUp: Array<() => void> = []
  const up = createHttpsServer(
    { cert: leafOnly, key: leaf.keyPem },
    (req, res) => {
      if (req.url !== '/large') {
        res.end('small')
        return
      }
      res.writeHead(200, { 'Content-Length': SIZE })
      res.on('error', () => {})
      let sent = 0
      const pump = (): void => {
        while (sent < SIZE) {
          sent += chunk.length
          if (!res.write(chunk)) {
            backedUp.shift()?.()
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

  const budget = createByteBudget(30_000)
  const proxy = createHttpProxyServer({
    filter: () => true,
    mitmCA: createMitmCA({ caCertPem: ca.certPem, caKeyPem: ca.keyPem }),
    tlsTerminateUpstreamCA: ca.certPem,
    byteBudget: budget,
  })
  await new Promise<void>(r => proxy.listen(0, '127.0.0.1', r))
  cleanup.push(() => new Promise<void>(r => proxy.close(() => r())))
  const port = (proxy.address() as AddressInfo).port

  const tunnel = (): Promise<Socket> =>
    new Promise((resolve, reject) => {
      const c = connect(port, '127.0.0.1', () =>
        c.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`),
      )
      cleanup.push(() => void c.destroy())
      c.on('error', reject)
      let head = ''
      const onData = (d: Buffer): void => {
        head += d.toString('latin1')
        if (!head.includes('\r\n\r\n')) return
        c.off('data', onData)
        if (!head.startsWith('HTTP/1.1 200')) return reject(new Error(head))
        const t = tlsConnect({
          socket: c,
          ca: ca.certPem,
          checkServerIdentity: () => undefined,
          ALPNProtocols: ['http/1.1'],
        })
        t.on('error', reject)
        t.on('secureConnect', () => resolve(t))
      }
      c.on('data', onData)
    })
  // `startReading` holds the body unread until it resolves; after that the
  // reader takes one chunk per turn of the event loop.
  const get = async (
    path: string,
    startReading: Promise<unknown>,
  ): Promise<{ bytes: number; digest: string }> => {
    const socket = await tunnel()
    return new Promise((resolve, reject) => {
      const req = request(
        {
          createConnection: () => socket,
          path,
          headers: { Host: target, Connection: 'close' },
        },
        res => {
          const hash = createHash('sha256')
          let bytes = 0
          res.on('error', reject)
          res.on('end', () => resolve({ bytes, digest: hash.digest('hex') }))
          void startReading.then(() =>
            res.on('data', (d: Buffer) => {
              bytes += d.length
              hash.update(d)
              res.pause()
              setImmediate(() => res.resume())
            }),
          )
        },
      )
      req.on('error', reject)
      req.end()
    })
  }

  const bothBackedUp = Promise.all([
    new Promise<void>(r => backedUp.push(r)),
    new Promise<void>(r => backedUp.push(r)),
  ])
  const [a, b] = await Promise.all([
    get('/large', bothBackedUp),
    get('/large', bothBackedUp),
  ])
  expect(a).toEqual({ bytes: SIZE, digest: wholeDigest })
  expect(b).toEqual({ bytes: SIZE, digest: wholeDigest })
  expect(budget.waiters.size).toBe(0)
  expect(budget.used).toBe(0)

  const after = await get('/small', Promise.resolve())
  expect(after.bytes).toBe(5)
  expect(budget.used).toBe(0)
}, 30_000)
