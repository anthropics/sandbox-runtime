import { afterEach, describe, expect, it } from 'bun:test'
import { createServer, type Server } from 'node:http'
import { connect, type AddressInfo, type Socket } from 'node:net'
import { createHttpProxyServer } from '../../src/sandbox/http-proxy.js'

const HOST = '127.0.0.1'

describe('HTTP proxy CONNECT tunnel drain on origin close', () => {
  const servers: Server[] = []
  const sockets: Socket[] = []

  afterEach(async () => {
    for (const socket of sockets) {
      socket.destroy()
    }
    sockets.length = 0
    await Promise.all(
      servers.map(
        server =>
          new Promise<void>(resolve => {
            server.close(() => resolve())
            server.closeAllConnections?.()
          }),
      ),
    )
    servers.length = 0
  })

  it('delivers the entire response body when origin closes immediately after sending', async () => {
    const payloadSize = 64 * 1024
    const payload = Buffer.alloc(payloadSize, 'x')

    const origin = createServer((req, res) => {
      res.writeHead(200, {
        'Content-Type': 'application/octet-stream',
        'Content-Length': String(payloadSize),
        Connection: 'close',
      })
      res.end(payload)
      // Ensure origin socket is closed right after sending
      req.socket.end()
    })
    servers.push(origin)
    await new Promise<void>(resolve => origin.listen(0, HOST, resolve))
    const originPort = (origin.address() as AddressInfo).port

    const proxy = createHttpProxyServer({
      filter: async () => ({ allow: true }),
    })
    servers.push(proxy)
    await new Promise<void>(resolve => proxy.listen(0, HOST, resolve))
    const proxyPort = (proxy.address() as AddressInfo).port

    const client = connect(proxyPort, HOST)
    sockets.push(client)

    const receivedChunks: Buffer[] = []
    let tunnelEstablished = false

    await new Promise<void>((resolve, reject) => {
      client.on('error', reject)

      client.on('connect', () => {
        client.write(
          `CONNECT 127.0.0.1:${originPort} HTTP/1.1\r\nHost: 127.0.0.1:${originPort}\r\n\r\n`,
        )
      })

      let buffer = ''
      client.on('data', chunk => {
        if (!tunnelEstablished) {
          buffer += chunk.toString('latin1')
          if (buffer.includes('\r\n\r\n')) {
            tunnelEstablished = true
            expect(buffer).toContain('200 Connection Established')
            // Send request to origin through tunnel
            client.write(
              `GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n`,
            )
            // Pause client briefly to simulate slower client reading while origin finishes
            client.pause()
            setTimeout(() => {
              client.resume()
            }, 30)
          }
          return
        }

        receivedChunks.push(chunk)
      })

      client.on('close', () => {
        resolve()
      })
    })

    const fullResponse = Buffer.concat(receivedChunks).toString('latin1')
    expect(fullResponse).toContain('HTTP/1.1 200 OK')
    const headerEnd = fullResponse.indexOf('\r\n\r\n')
    expect(headerEnd).toBeGreaterThan(0)
    const bodyReceived = Buffer.byteLength(
      fullResponse.slice(headerEnd + 4),
      'latin1',
    )
    expect(bodyReceived).toBe(payloadSize)
  })
})
