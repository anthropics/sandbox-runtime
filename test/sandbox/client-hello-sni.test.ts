import { afterEach, describe, expect, test } from 'bun:test'
import { createServer, type AddressInfo } from 'node:net'
import { connect as tlsConnect } from 'node:tls'
import { serverNameFromClientHello } from '../../src/sandbox/tls-terminate-proxy.js'

const u16 = (n: number): Buffer => Buffer.from([n >> 8, n & 0xff])
const u24 = (n: number): Buffer =>
  Buffer.from([n >> 16, (n >> 8) & 0xff, n & 0xff])

/** A server_name extension (type 0) with the given raw list entries. */
function sniExtension(entries: Array<{ type: number; name: Buffer }>): Buffer {
  const list = Buffer.concat(
    entries.map(e =>
      Buffer.concat([Buffer.from([e.type]), u16(e.name.length), e.name]),
    ),
  )
  const body = Buffer.concat([u16(list.length), list])
  return Buffer.concat([u16(0), u16(body.length), body])
}

const otherExtension = (type: number, len: number): Buffer =>
  Buffer.concat([u16(type), u16(len), Buffer.alloc(len, 0x41)])

/**
 * A TLS record carrying a ClientHello with these extensions (none when
 * undefined). `recordCut` keeps only that many bytes of the handshake in
 * the record, as when the ClientHello continues in a second record.
 */
function clientHello(
  extensions: Buffer[] | undefined,
  recordCut?: number,
): Buffer {
  const body = Buffer.concat([
    u16(0x0303),
    Buffer.alloc(32, 7), // random
    Buffer.from([0]), // session_id
    u16(2),
    u16(0x1301), // cipher_suites
    Buffer.from([1, 0]), // compression_methods
    ...(extensions === undefined
      ? []
      : [u16(Buffer.concat(extensions).length), ...extensions]),
  ])
  const handshake = Buffer.concat([Buffer.from([1]), u24(body.length), body])
  const inRecord =
    recordCut === undefined ? handshake : handshake.subarray(0, recordCut)
  return Buffer.concat([
    Buffer.from([0x16, 3, 1]),
    u16(inRecord.length),
    inRecord,
  ])
}

const name = (s: string): Buffer => Buffer.from(s, 'latin1')

describe('serverNameFromClientHello', () => {
  test('a plain name, lower-cased, among other extensions', () => {
    expect(
      serverNameFromClientHello(
        clientHello([
          otherExtension(10, 4),
          sniExtension([{ type: 0, name: name('API.Example.com') }]),
          otherExtension(16, 11),
        ]),
      ),
    ).toEqual({ kind: 'name', name: 'api.example.com' })
  })

  test('no server_name extension, or no extensions at all: absent', () => {
    expect(
      serverNameFromClientHello(clientHello([otherExtension(10, 4)])),
    ).toEqual({
      kind: 'absent',
    })
    expect(serverNameFromClientHello(clientHello(undefined))).toEqual({
      kind: 'absent',
    })
  })

  test.each([
    ['an underscore', 'x_front.example'],
    ['a trailing dot', 'api.example.com.'],
    ['an empty label', 'api..example.com'],
    ['non-ASCII', 'bücher.example'],
    ['a zero-length name', ''],
    ['a name past 253 bytes', `${'a.'.repeat(127)}ab`],
    ['a label past 63 bytes', `${'a'.repeat(64)}.example`],
    ['a space', 'api example.com'],
  ])('%s: unreadable', (_what, n) => {
    expect(
      serverNameFromClientHello(
        clientHello([sniExtension([{ type: 0, name: name(n) }])]),
      ),
    ).toEqual({ kind: 'unreadable' })
  })

  test('two names, a first name of another type, or two server_name extensions: unreadable', () => {
    const a = { type: 0, name: name('a.example') }
    const b = { type: 0, name: name('b.example') }
    for (const extensions of [
      [sniExtension([a, b])],
      [sniExtension([{ type: 1, name: name('a.example') }])],
      [sniExtension([a]), sniExtension([b])],
    ]) {
      expect(serverNameFromClientHello(clientHello(extensions))).toEqual({
        kind: 'unreadable',
      })
    }
  })

  test('a ClientHello split across records: the name if it is in the first, else unreadable', () => {
    const extensions = [
      sniExtension([{ type: 0, name: name('a.example') }]),
      otherExtension(21, 400),
    ]
    const whole = clientHello(extensions).length - 5
    // Cut inside the padding after the name: the name is read.
    expect(
      serverNameFromClientHello(clientHello(extensions, whole - 100)),
    ).toEqual({
      kind: 'name',
      name: 'a.example',
    })
    // The name after the cut: it may be there, so unreadable, not absent.
    const late = [
      otherExtension(21, 400),
      sniExtension([{ type: 0, name: name('a.example') }]),
    ]
    expect(
      serverNameFromClientHello(
        clientHello(late, clientHello(late).length - 5 - 20),
      ),
    ).toEqual({ kind: 'unreadable' })
    // Cut before the extensions start.
    expect(serverNameFromClientHello(clientHello(extensions, 30))).toEqual({
      kind: 'unreadable',
    })
  })

  test('a truncated record, garbage, or not a ClientHello: unreadable', () => {
    const hello = clientHello([
      sniExtension([{ type: 0, name: name('a.example') }]),
    ])
    expect(serverNameFromClientHello(hello.subarray(0, 20))).toEqual({
      kind: 'unreadable',
    })
    expect(
      serverNameFromClientHello(Buffer.from('GET / HTTP/1.1\r\n\r\n')),
    ).toEqual({
      kind: 'unreadable',
    })
    const serverHello = Buffer.from(hello)
    serverHello[5] = 2
    expect(serverNameFromClientHello(serverHello)).toEqual({
      kind: 'unreadable',
    })
  })
})

describe("a real ClientHello from this runtime's TLS client", () => {
  const servers: Array<() => void> = []
  afterEach(() => {
    while (servers.length) servers.pop()!()
  })

  test('its server name is read', async () => {
    const first = await new Promise<Buffer>(resolve => {
      const server = createServer(sock => {
        sock.once('data', d => {
          resolve(d)
          sock.destroy()
        })
      })
      servers.push(() => server.close())
      server.listen(0, '127.0.0.1', () => {
        const t = tlsConnect({
          port: (server.address() as AddressInfo).port,
          host: '127.0.0.1',
          servername: 'api.example.com',
        })
        t.on('error', () => {})
      })
    })
    expect(serverNameFromClientHello(first)).toEqual({
      kind: 'name',
      name: 'api.example.com',
    })
  })
})
