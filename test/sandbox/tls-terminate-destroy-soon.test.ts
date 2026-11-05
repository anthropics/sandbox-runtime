import { afterEach, describe, expect, test } from 'bun:test'
import { readFileSync } from 'node:fs'
import { createServer, type AddressInfo } from 'node:net'
import { join } from 'node:path'
import { connect, type TLSSocket } from 'node:tls'
import { createMitmCA } from '../../src/sandbox/mitm-ca.js'
import { mintLeafCert } from '../../src/sandbox/mitm-leaf.js'
import { serverTlsOn } from '../../src/sandbox/tls-terminate-proxy.js'

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
 * What a TLS client reads, and whether it saw the end, from a server that
 * writes SIZE bytes to its TLS socket, all at once, and hands it to `then`.
 * The client reads nothing for a while, so `then` is done long before the
 * bytes are taken, and then slowly.
 */
async function lateClientOf(
  then: (tls: TLSSocket) => void,
): Promise<{ read: number; ended: boolean }> {
  // As an http server's sockets are, a CONNECT's among them.
  const server = createServer({ allowHalfOpen: true }, socket => {
    socket.on('error', () => {})
    const { tls } = serverTlsOn(socket, Buffer.alloc(0), LEAF(), () => {})
    tls.on('error', () => {})
    tls.once('secure', () => {
      const chunk = Buffer.alloc(64 << 10, 0x61)
      for (let sent = 0; sent < SIZE; sent += chunk.length) tls.write(chunk)
      then(tls)
    })
  })
  cleanup.push(() => server.close())
  await new Promise<void>(r => server.listen(0, '127.0.0.1', r))
  return new Promise(resolve => {
    const to = {
      port: (server.address() as AddressInfo).port,
      host: '127.0.0.1',
      allowHalfOpen: true,
      servername: 'localhost',
      ca: readFileSync(join(FIXTURES, 'ca.crt')),
    }
    const c = connect(to)
    let read = 0
    let ended = false
    c.pause()
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

describe('serverTlsOn', () => {
  // What a runtime's http server does, depending on the runtime, once it has
  // answered an HTTP/1.0 request.
  test.each([
    ['end(), then destroySoon()', (t: TLSSocket) => (t.end(), t.destroySoon())],
    ['destroySoon()', (t: TLSSocket) => t.destroySoon()],
  ])(
    '%s: the client gets every byte, then the end',
    async (_how, close) => {
      expect(await lateClientOf(close)).toEqual({ read: SIZE, ended: true })
    },
    60_000,
  )

  // As the back-stops do, a while after an end that a client does not answer.
  test.each([
    [
      'end(), and destroy() once it has finished',
      (t: TLSSocket) => t.end(() => setImmediate(() => t.destroy())),
    ],
    ['destroy()', (t: TLSSocket) => t.destroy()],
  ])(
    '%s: cut at once',
    async (_how, cut) => {
      // Long before the client reads its first byte.
      expect((await lateClientOf(cut)).read).toBeLessThan(SIZE)
    },
    60_000,
  )
})
