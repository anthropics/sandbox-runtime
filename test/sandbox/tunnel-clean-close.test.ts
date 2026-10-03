import { connect, createServer, type Server } from 'node:net'
import { afterEach, beforeEach, describe, expect, it } from 'bun:test'
import { createHttpProxyServer } from '../../src/sandbox/http-proxy.js'
import {
  createMuxProxyServer,
  type MuxProxyServer,
} from '../../src/sandbox/mux-proxy.js'

describe('Tunnel clean close response flushing (#606)', () => {
  let upstream: Server
  let upstreamPort: number
  let payload: Buffer

  beforeEach(async () => {
    // 500KB payload to ensure buffering occurs
    payload = Buffer.alloc(500 * 1024, 'x')
    upstream = createServer(sock => {
      sock.write(payload)
      sock.end() // Upstream sends data and closes cleanly (Connection: close)
    })
    await new Promise<void>(resolve => upstream.listen(0, '127.0.0.1', resolve))
    upstreamPort = (upstream.address() as { port: number }).port
  })

  afterEach(async () => {
    await new Promise<void>(resolve => upstream.close(() => resolve()))
  })

  it('flushes queued bytes when upstream closes cleanly in HTTP CONNECT proxy', async () => {
    const proxy = createHttpProxyServer({
      filter: () => true,
    })
    await new Promise<void>(resolve =>
      proxy.listen(0, '127.0.0.1', () => resolve()),
    )
    const proxyPort = (proxy.address() as { port: number }).port

    try {
      const client = connect(proxyPort, '127.0.0.1')
      await new Promise<void>(resolve => client.once('connect', resolve))

      client.write(
        `CONNECT 127.0.0.1:${upstreamPort} HTTP/1.1\r\nHost: 127.0.0.1:${upstreamPort}\r\n\r\n`,
      )

      const chunks: Buffer[] = []
      let headersRead = false

      await new Promise<void>((resolve, reject) => {
        client.on('data', data => {
          if (!headersRead) {
            const str = data.toString()
            const idx = str.indexOf('\r\n\r\n')
            if (idx !== -1) {
              headersRead = true
              const body = data.subarray(idx + 4)
              if (body.length > 0) chunks.push(body)
            }
          } else {
            chunks.push(data)
          }
        })
        client.on('close', resolve)
        client.on('error', reject)
      })

      const received = Buffer.concat(chunks)
      expect(received.length).toBe(payload.length)
      expect(received).toEqual(payload)
    } finally {
      await new Promise<void>(resolve => proxy.close(() => resolve()))
    }
  })

  it('flushes queued bytes when upstream closes cleanly in Mux proxy', async () => {
    const httpStub = createHttpProxyServer({
      filter: () => true,
    })
    const mux: MuxProxyServer = createMuxProxyServer({
      httpServer: httpStub,
      handleSocksConnection: () => {},
    })
    await mux.listenHttpBackend()
    await new Promise<void>(resolve =>
      mux.server.listen(0, '127.0.0.1', () => resolve()),
    )
    const muxPort = mux.getPort()!

    try {
      const client = connect(muxPort, '127.0.0.1')
      await new Promise<void>(resolve => client.once('connect', resolve))

      client.write(
        `CONNECT 127.0.0.1:${upstreamPort} HTTP/1.1\r\nHost: 127.0.0.1:${upstreamPort}\r\n\r\n`,
      )

      const chunks: Buffer[] = []
      let headersRead = false

      await new Promise<void>((resolve, reject) => {
        client.on('data', data => {
          if (!headersRead) {
            const str = data.toString()
            const idx = str.indexOf('\r\n\r\n')
            if (idx !== -1) {
              headersRead = true
              const body = data.subarray(idx + 4)
              if (body.length > 0) chunks.push(body)
            }
          } else {
            chunks.push(data)
          }
        })
        client.on('close', resolve)
        client.on('error', reject)
      })

      const received = Buffer.concat(chunks)
      expect(received.length).toBe(payload.length)
      expect(received).toEqual(payload)
    } finally {
      await mux.close()
    }
  })
})
