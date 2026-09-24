import { connect, createServer, type Server, type Socket } from 'node:net'
import { once } from 'node:events'
import { afterEach, beforeEach, describe, expect, it } from 'bun:test'
import { createHttpProxyServer } from '../../src/sandbox/http-proxy.js'
import { createMitmCA, disposeMitmCA } from '../../src/sandbox/mitm-ca.js'
import { looksLikeClientHello } from '../../src/sandbox/tls-terminate-proxy.js'

/**
 * Regression: with tlsTerminate on, every CONNECT was handed to the
 * TLS terminator regardless of port/protocol. The sandbox routes
 * `git push` over SSH through this proxy via
 *   GIT_SSH_COMMAND=ssh -o ProxyCommand='socat - PROXY:localhost:%h:%p,...'
 * which is `CONNECT github.com:22` — not TLS. The terminator replied with a
 * fatal protocol_version alert and closed, breaking SSH.
 *
 * Fix: sniff the client's first post-CONNECT bytes; only terminate when they
 * look like a TLS ClientHello, otherwise opaque-tunnel (base-sandbox
 * behaviour, hostname allowlist still enforced upstream of this branch).
 */

describe('looksLikeClientHello', () => {
  it('matches a TLS Handshake record header', () => {
    // type=0x16, version=0x0301 (TLS1.0 record layer; ClientHello uses this
    // for all TLS versions), then arbitrary length/body bytes.
    expect(
      looksLikeClientHello(Buffer.from([0x16, 0x03, 0x01, 0x00, 0x2a])),
    ).toBe(true)
    expect(looksLikeClientHello(Buffer.from([0x16, 0x03, 0x03, 0xff]))).toBe(
      true,
    )
    expect(looksLikeClientHello(Buffer.from([0x16, 0x03, 0x00]))).toBe(true)
  })
  it('rejects an SSH banner', () => {
    expect(looksLikeClientHello(Buffer.from('SSH-2.0-OpenSSH_9.7\r\n'))).toBe(
      false,
    )
  })
  it('rejects plain HTTP', () => {
    expect(looksLikeClientHello(Buffer.from('GET / HTTP/1.1\r\n'))).toBe(false)
  })
  it('rejects a TLS Alert record (not Handshake)', () => {
    expect(
      looksLikeClientHello(Buffer.from([0x15, 0x03, 0x01, 0x00, 0x02])),
    ).toBe(false)
  })
  it('rejects short buffers', () => {
    expect(looksLikeClientHello(Buffer.from([0x16, 0x03]))).toBe(false)
    expect(looksLikeClientHello(Buffer.alloc(0))).toBe(false)
  })
})

describe('CONNECT carrying non-TLS bytes with mitmCA configured', () => {
  let upstream: Server
  let upstreamPort: number
  let received: Buffer[]

  beforeEach(async () => {
    received = []
    upstream = createServer(sock => {
      sock.on('data', d => received.push(d))
      sock.write('SSH-2.0-FakeUpstream\r\n')
    })
    upstream.listen(0, '127.0.0.1')
    await once(upstream, 'listening')
    upstreamPort = (upstream.address() as { port: number }).port
  })

  afterEach(() => upstream.close())

  async function tunnel(mitmCA: unknown): Promise<{
    buf: string
    upstreamSaw: string
  }> {
    const proxy = createHttpProxyServer({
      filter: () => true,
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      mitmCA: mitmCA as any,
    })
    proxy.listen(0, '127.0.0.1')
    await once(proxy, 'listening')
    const proxyPort = (proxy.address() as { port: number }).port

    const sock: Socket = connect({ host: '127.0.0.1', port: proxyPort })
    await once(sock, 'connect')
    sock.write(
      `CONNECT localhost:${upstreamPort} HTTP/1.1\r\nHost: localhost:${upstreamPort}\r\n\r\n`,
    )

    let buf = ''
    let sent = false
    sock.on('data', d => {
      buf += d.toString()
      if (!sent && buf.includes('Connection Established')) {
        sent = true
        sock.write('SSH-2.0-OpenSSH_9.7\r\n')
      }
    })
    await Promise.race([
      new Promise<void>(r => {
        const i = setInterval(() => {
          if (buf.includes('FakeUpstream') && received.length) {
            clearInterval(i)
            r()
          }
        }, 10)
      }),
      once(sock, 'close'),
      new Promise(r => setTimeout(r, 2000)),
    ])
    sock.destroy()
    proxy.close()
    return { buf, upstreamSaw: Buffer.concat(received).toString() }
  }

  it('without mitmCA: opaque tunnel relays SSH bytes (baseline)', async () => {
    const r = await tunnel(undefined)
    expect(r.buf).toContain('SSH-2.0-FakeUpstream')
    expect(r.upstreamSaw).toContain('SSH-2.0-OpenSSH')
  })

  it('with mitmCA: non-TLS bytes are sniffed and opaque-tunnelled', async () => {
    const ca = createMitmCA({})
    try {
      const r = await tunnel(ca)
      // Before the fix: buf was "200...\r\n\r\n\x15\x03\x01\x00\x02\x02\x46"
      // (TLS protocol_version alert) and upstreamSaw was "".
      expect(r.buf).toContain('SSH-2.0-FakeUpstream')
      expect(r.upstreamSaw).toContain('SSH-2.0-OpenSSH')
    } finally {
      await disposeMitmCA(ca)
    }
  })

  it('with mitmCA: hostname filter still runs before the sniff', async () => {
    let filterCalled = false
    const ca = createMitmCA({})
    try {
      const proxy = createHttpProxyServer({
        filter: (_port, host) => {
          filterCalled = host === 'localhost'
          return false
        },
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        mitmCA: ca as any,
      })
      proxy.listen(0, '127.0.0.1')
      await once(proxy, 'listening')
      const proxyPort = (proxy.address() as { port: number }).port
      const sock = connect({ host: '127.0.0.1', port: proxyPort })
      await once(sock, 'connect')
      sock.write(
        `CONNECT localhost:${upstreamPort} HTTP/1.1\r\nHost: localhost:${upstreamPort}\r\n\r\n`,
      )
      let buf = ''
      sock.on('data', d => (buf += d.toString()))
      await once(sock, 'close')
      proxy.close()
      expect(filterCalled).toBe(true)
      expect(buf).toContain('403 Forbidden')
    } finally {
      await disposeMitmCA(ca)
    }
  })
})
