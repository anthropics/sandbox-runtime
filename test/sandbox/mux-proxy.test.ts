import { afterEach, beforeEach, describe, expect, it } from 'bun:test'
import { existsSync } from 'node:fs'
import { createServer as createHttpServer, type Server } from 'node:http'
import { connect, type Socket } from 'node:net'
import {
  createMuxProxyServer,
  type MuxProxyServer,
} from '../../src/sandbox/mux-proxy.js'

/**
 * Exercises the first-byte sniffer in isolation: a stub http.Server
 * stands in for the real HTTP proxy and a recording callback stands in
 * for the SOCKS handler. Runs on all platforms — on Windows the HTTP
 * backend listens on an ephemeral TCP port (range [0,0]); elsewhere it
 * listens on a unix socket.
 */
describe('mux-proxy first-byte dispatch', () => {
  let mux: MuxProxyServer
  let httpStub: Server
  let port: number
  let socksHits: Buffer[]

  beforeEach(async () => {
    socksHits = []
    httpStub = createHttpServer((req, res) => {
      res.writeHead(200, { connection: 'close' })
      res.end(`http-request:${req.method}:${req.url}\n`)
    })
    httpStub.on('connect', (req, sock) => {
      sock.end(
        `HTTP/1.1 200 Connection Established\r\n\r\nhttp-connect:${req.url}\n`,
      )
    })
    mux = createMuxProxyServer({
      httpServer: httpStub,
      handleSocksConnection: sock => {
        // Drain everything the client sends so we can assert the unshifted
        // first byte is intact, then close.
        sock.on('data', chunk => socksHits.push(chunk))
        sock.end(Buffer.from([0x05, 0x00])) // SOCKS5 "no auth" reply
      },
      firstByteTimeoutMs: 500,
    })
    await mux.listenHttpBackend()
    await new Promise<void>((resolve, reject) => {
      mux.server.once('error', reject)
      mux.server.listen(0, '127.0.0.1', () => resolve())
    })
    port = mux.getPort()!
  })

  afterEach(async () => {
    await mux.close()
  })

  function send(bytes: Buffer): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      const chunks: Buffer[] = []
      const c: Socket = connect(port, '127.0.0.1', () => c.write(bytes))
      c.on('data', d => chunks.push(d))
      c.on('close', () => resolve(Buffer.concat(chunks)))
      c.on('error', reject)
    })
  }

  it('routes 0x05 (SOCKS5 greeting) to the SOCKS handler with byte 0 intact', async () => {
    const greeting = Buffer.from([0x05, 0x01, 0x00])
    const reply = await send(greeting)
    expect(reply).toEqual(Buffer.from([0x05, 0x00]))
    // The handler must see the FULL greeting including the peeked 0x05.
    expect(Buffer.concat(socksHits)).toEqual(greeting)
  })

  it('routes 0x04 (SOCKS4) to the SOCKS handler', async () => {
    const req = Buffer.from([
      0x04, 0x01, 0x00, 0x50, 0x7f, 0x00, 0x00, 0x01, 0x00,
    ])
    await send(req)
    expect(Buffer.concat(socksHits)[0]).toBe(0x04)
  })

  it('routes an absolute-URI GET to the HTTP backend', async () => {
    const reply = await send(
      Buffer.from(
        'GET http://x/ HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n',
      ),
    )
    const text = reply.toString()
    expect(text).toContain('HTTP/1.1 200')
    expect(text).toContain('http-request:GET:http://x/')
    expect(socksHits.length).toBe(0)
  })

  it('routes CONNECT to the HTTP backend connect handler', async () => {
    const reply = await send(
      Buffer.from('CONNECT x:443 HTTP/1.1\r\nHost: x:443\r\n\r\n'),
    )
    const text = reply.toString()
    expect(text).toContain('200 Connection Established')
    expect(text).toContain('http-connect:x:443')
  })

  it('routes a TLS ClientHello first byte (0x16) to HTTP, not SOCKS', async () => {
    // Not a valid HTTP request — the backend will 400 it — but the point
    // is it must NOT be treated as SOCKS.
    await send(Buffer.from([0x16, 0x03, 0x01, 0x00, 0x05])).catch(() => {})
    expect(socksHits.length).toBe(0)
  })

  it('destroys a connect-then-stall client after firstByteTimeoutMs', async () => {
    const start = Date.now()
    await new Promise<void>(resolve => {
      const c = connect(port, '127.0.0.1')
      // Send nothing; wait for the server to drop us.
      c.on('close', () => resolve())
      c.on('error', () => {}) // ECONNRESET is fine
    })
    const elapsed = Date.now() - start
    expect(elapsed).toBeGreaterThanOrEqual(450)
    expect(elapsed).toBeLessThan(2000)
    expect(socksHits.length).toBe(0)
  })

  it('handles connect-then-immediate-close without dispatching', async () => {
    await new Promise<void>(resolve => {
      const c = connect(port, '127.0.0.1', () => c.end())
      c.on('close', () => resolve())
      c.on('error', () => {})
    })
    expect(socksHits.length).toBe(0)
  })

  it('removeBackendSocketSync removes the backend socket file, and close() still works', () => {
    const address = httpStub.address() // a path, or on Windows a port
    if (typeof address === 'string') expect(existsSync(address)).toBe(true)
    mux.removeBackendSocketSync()
    if (typeof address === 'string') expect(existsSync(address)).toBe(false)
  })
})
