import { connect, createServer, type Server, type Socket } from 'node:net'
import { once } from 'node:events'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { unlinkSync } from 'node:fs'
import { describe, expect, it } from 'bun:test'
import { createHttpProxyServer } from '../../src/sandbox/http-proxy.js'
import {
  createSocksProxyServer,
  type SocksProxyWrapper,
} from '../../src/sandbox/socks-proxy.js'

/**
 * Regression: the CONNECT and SOCKS relays destroyed the client socket the
 * moment the upstream socket closed:
 *
 *   upstream.pipe(socket)
 *   upstream.on('close', () => socket.destroy())
 *
 * A server that closes right after writing its response (HTTP/1.1
 * `Connection: close`) races its FIN against the relay: the upstream socket
 * fully closes as soon as the FIN is read, and destroy() discards response
 * bytes still queued in the client socket's write buffer. The client sees a
 * clean EOF mid-body — silent truncation, no error anywhere. Clients that
 * send `Connection: close` on every request (e.g. Python's urllib) lost the
 * tail of any response too big for the socket buffers.
 *
 * The tests tunnel a close-after-write stream through each proxy to a client
 * that drains slower than the relay fills (like a TLS stack decrypting
 * records), so relayed bytes are reliably queued when the upstream's FIN
 * arrives — exactly when destroy() loses them. The client leg runs over a
 * Unix domain socket: its kernel buffers are small and fixed, which keeps
 * the queue in userspace where destroy() discards it (over loopback TCP the
 * kernel absorbs a few hundred KB and hides the bug most of the time).
 */

const PAYLOAD_SIZE = 1024 * 1024
// Several transfers per proxy: each is an independent chance to hit the
// race, so requiring all of them intact makes the regression signal robust
// on runtimes/kernels where an individual transfer occasionally survives.
const TRANSFERS = 6
// Drain pace: 16 KiB every 2ms (~8 MB/s) — slower than the relay fills, so
// the write queue stays non-empty through the upstream's close.
const READ_CHUNK = 16 * 1024
const READ_INTERVAL_MS = 2

async function listenTcp(server: Server): Promise<number> {
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  return (server.address() as { port: number }).port
}

async function listenUnix(server: Server, name: string): Promise<string> {
  const path = join(tmpdir(), name)
  try {
    unlinkSync(path)
  } catch {
    // stale socket from a previous run may not exist
  }
  server.listen(path)
  await once(server, 'listening')
  return path
}

/** Origin that writes the payload and immediately closes, like an HTTP/1.1
 * server honoring `Connection: close`. */
function createCloseAfterWriteOrigin(): Server {
  return createServer(sock => {
    sock.on('error', () => {})
    sock.end(Buffer.alloc(PAYLOAD_SIZE, 0x78))
  })
}

/**
 * Count tunneled bytes arriving on `sock` after `handshake` resolves,
 * draining at a fixed byte rate until the socket closes.
 */
function drainPaced(
  sock: Socket,
  handshake: (chunk: Buffer) => Buffer | null,
): Promise<number> {
  return new Promise(resolve => {
    let inTunnel = false
    let total = 0
    const timer = setInterval(() => {
      const chunk = sock.read(
        inTunnel ? READ_CHUNK : undefined,
      ) as Buffer | null
      if (chunk === null) return
      if (!inTunnel) {
        const rest = handshake(chunk)
        if (rest === null) return
        inTunnel = true
        total += rest.length
      } else {
        total += chunk.length
      }
    }, READ_INTERVAL_MS)
    sock.on('error', () => {})
    sock.on('close', () => {
      // Bytes delivered before the close but not yet drained still count.
      let chunk: Buffer | null
      while ((chunk = sock.read()) !== null) total += chunk.length
      clearInterval(timer)
      resolve(total)
    })
  })
}

describe('tunnel relays flush when the upstream closes after writing', () => {
  it('HTTP CONNECT: client receives the full stream', async () => {
    const origin = createCloseAfterWriteOrigin()
    const originPort = await listenTcp(origin)
    const proxy = createHttpProxyServer({ filter: () => true })
    const proxyPath = await listenUnix(proxy, `tcf-h-${process.pid}.sock`)

    const results: number[] = []
    for (let i = 0; i < TRANSFERS; i++) {
      const sock = connect({ path: proxyPath })
      await once(sock, 'connect')
      sock.pause()
      sock.write(
        `CONNECT 127.0.0.1:${originPort} HTTP/1.1\r\n` +
          `Host: 127.0.0.1:${originPort}\r\n\r\n`,
      )
      let header = Buffer.alloc(0)
      results.push(
        await drainPaced(sock, chunk => {
          header = Buffer.concat([header, chunk])
          const end = header.indexOf('\r\n\r\n')
          if (end === -1) return null
          expect(header.subarray(0, end).toString()).toStartWith('HTTP/1.1 200')
          return header.subarray(end + 4)
        }),
      )
    }

    proxy.close()
    origin.close()
    expect(results).toEqual(Array(TRANSFERS).fill(PAYLOAD_SIZE))
  }, 30000)

  it('SOCKS5: client receives the full stream', async () => {
    const origin = createCloseAfterWriteOrigin()
    const originPort = await listenTcp(origin)
    const wrapper: SocksProxyWrapper = createSocksProxyServer({
      filter: () => true,
    })
    const front = createServer(s => wrapper.handleConnection(s))
    const frontPath = await listenUnix(front, `tcf-s-${process.pid}.sock`)

    const results: number[] = []
    for (let i = 0; i < TRANSFERS; i++) {
      const sock = connect({ path: frontPath })
      await once(sock, 'connect')
      sock.pause()
      // Greeting: version 5, one auth method, NO AUTH.
      sock.write(Buffer.from([0x05, 0x01, 0x00]))
      // Handshake replies: 2-byte greeting reply, then a 10-byte CONNECT
      // reply (ATYP=IPv4); anything after that is tunneled payload.
      let buf = Buffer.alloc(0)
      let stage: 'greeting' | 'connect' = 'greeting'
      results.push(
        await drainPaced(sock, chunk => {
          buf = Buffer.concat([buf, chunk])
          if (stage === 'greeting') {
            if (buf.length < 2) return null
            expect([...buf.subarray(0, 2)]).toEqual([0x05, 0x00])
            buf = buf.subarray(2)
            stage = 'connect'
            sock.write(
              Buffer.from([
                0x05,
                0x01,
                0x00,
                0x01,
                127,
                0,
                0,
                1,
                originPort >> 8,
                originPort & 0xff,
              ]),
            )
          }
          if (buf.length < 10) return null
          expect(buf[1]).toBe(0x00) // REP = succeeded
          return buf.subarray(10)
        }),
      )
    }

    await wrapper.close()
    front.close()
    origin.close()
    expect(results).toEqual(Array(TRANSFERS).fill(PAYLOAD_SIZE))
  }, 30000)
})
