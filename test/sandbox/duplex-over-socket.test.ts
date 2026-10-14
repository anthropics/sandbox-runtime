import { afterEach, describe, expect, test } from 'bun:test'
import { connect, createServer, type AddressInfo, type Socket } from 'node:net'
import { join } from 'node:path'
import type { Duplex } from 'node:stream'
import { connect as tlsConnect } from 'node:tls'
import { createMitmCA } from '../../src/sandbox/mitm-ca.js'
import { mintLeafCert } from '../../src/sandbox/mitm-leaf.js'
import {
  duplexOverSocket,
  serverTlsOn,
} from '../../src/sandbox/tls-terminate-proxy.js'

// More than the kernel takes for a client that is not reading.
const SIZE = 32 << 20

const FIXTURES = join(import.meta.dir, '..', 'fixtures', 'tls-terminate')
const LEAF = (): { cert: string; key: string } => {
  const leaf = mintLeafCert(
    createMitmCA({
      caCertPath: join(FIXTURES, 'ca.crt'),
      caKeyPath: join(FIXTURES, 'ca.key'),
    }),
    'localhost',
  )
  return { cert: leaf.certPem, key: leaf.keyPem }
}

const cleanup: Array<() => void> = []
afterEach(() => {
  while (cleanup.length) cleanup.pop()!()
})

/**
 * What a client reads, and whether it saw the end, from a server that hands
 * `serve` the stream over its socket. The client reads nothing for a while,
 * so `serve` is done long before its bytes are taken, and then slowly, so the
 * kernel still holds some whenever the stream finishes. `unread` bytes it
 * sends first, which nobody reads.
 */
async function lateClientOf(
  serve: (d: Duplex, socket: Socket) => void,
  unread = 0,
  overTls = false,
): Promise<{ read: number; ended: boolean }> {
  // As an http server's sockets are, a CONNECT's among them.
  const server = createServer({ allowHalfOpen: true }, socket => {
    socket.on('error', () => {})
    if (!overTls) {
      const { duplex } = duplexOverSocket(socket, Buffer.alloc(0), () => {})
      return serve(duplex, socket)
    }
    const { tls } = serverTlsOn(socket, Buffer.alloc(0), LEAF(), () => {})
    tls.on('error', () => {})
    tls.once('secure', () => serve(tls, socket))
  })
  cleanup.push(() => server.close())
  await new Promise<void>(r => server.listen(0, '127.0.0.1', r))
  return new Promise(resolve => {
    const to = {
      port: (server.address() as AddressInfo).port,
      host: '127.0.0.1',
      allowHalfOpen: true,
    }
    const c = overTls
      ? tlsConnect({ ...to, rejectUnauthorized: false })
      : connect(to)
    let read = 0
    let ended = false
    c.pause()
    if (unread) c.write(Buffer.alloc(unread, 0x62))
    setTimeout(() => c.resume(), 300)
    c.on('data', d => {
      read += d.length
      c.pause()
      setTimeout(() => c.resume(), 5)
    })
    c.on('end', () => {
      ended = true
      c.end()
    })
    c.on('error', () => {})
    c.on('close', () => resolve({ read, ended }))
  })
}

/** All at once, as Bun's TLS socket writes to the stream under it. */
function writeAll(d: Duplex): void {
  const chunk = Buffer.alloc(64 << 10, 0x61)
  for (let sent = 0; sent < SIZE; sent += chunk.length) d.write(chunk)
}

describe('serverTlsOn', () => {
  // What a runtime's http server does, depending on the runtime, once it has
  // answered an HTTP/1.0 request.
  test('ended, then destroySoon(): the client gets every byte, then the end', async () => {
    const got = await lateClientOf(
      tls => {
        writeAll(tls)
        tls.end()
        ;(tls as Socket).destroySoon()
      },
      0,
      true,
    )
    expect(got).toEqual({ read: SIZE, ended: true })
  }, 60_000)
})

describe('duplexOverSocket', () => {
  test('ended, and destroyed with bytes still queued: the client gets them all, then the end', async () => {
    let queued = 0
    const got = await lateClientOf(d => {
      writeAll(d)
      d.end()
      queued = d.writableLength
      d.destroy()
    })
    expect(queued).toBeGreaterThan(0)
    expect(got).toEqual({ read: SIZE, ended: true })
  }, 60_000)

  test('destroyed once it has finished: the close goes on, and bytes of the client that nobody read cost it nothing', async () => {
    const got = await lateClientOf(d => {
      writeAll(d)
      d.end()
      d.once('finish', () => d.destroy())
    }, 4 << 20)
    expect(got).toEqual({ read: SIZE, ended: true })
  }, 60_000)

  test.each([
    ['with an error', (d: Duplex) => (d.end(), d.destroy(new Error('x')))],
    ['without having been ended', (d: Duplex) => d.destroy()],
  ])(
    'destroyed %s: cut at once',
    async (_how, cut) => {
      let destroyed: boolean | undefined
      const got = await lateClientOf((d, socket) => {
        writeAll(d)
        cut(d)
        destroyed = socket.destroyed
      })
      expect(destroyed).toBe(true)
      expect(got.read).toBeLessThan(SIZE)
    },
    60_000,
  )
})
