import { test, expect, beforeAll, afterAll } from 'bun:test'
// Every case here runs a proxy configured to terminate TLS, so each is
// skipped where this runtime cannot terminate it in-process.
import { describeWithTls as describe } from '../helpers/emitted-connections.js'
import { connect, createServer, type AddressInfo, type Server } from 'node:net'
import type { LookupFunction, Socket } from 'node:net'
import {
  connect as tlsConnect,
  createServer as createTlsServer,
} from 'node:tls'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { createHttpProxyServer } from '../../src/sandbox/http-proxy.js'
import { createMitmCA } from '../../src/sandbox/mitm-ca.js'
import { mintLeafCert } from '../../src/sandbox/mitm-leaf.js'

const FIXTURE_DIR = join(import.meta.dir, '..', 'fixtures', 'tls-terminate')
const CA_CERT = join(FIXTURE_DIR, 'ca.crt')
const CA_KEY = join(FIXTURE_DIR, 'ca.key')
const CA_PEM = readFileSync(CA_CERT, 'utf8')

const UPSTREAM_NAME = 'upstream.test'

/** Request target as the client writes it, and as it must reach upstream. */
type Case = [sent: string, forwarded: string]

// TLS-terminated, no filterRequest: origin-form targets go out untouched.
const TLS_UNCHANGED: Case[] = [
  ['/a/../b', '/a/../b'],
  ['/a/./b/%2e%2e/c', '/a/./b/%2e%2e/c'],
  ['/a/%2E%2E/b', '/a/%2E%2E/b'],
  ['//k/x', '//k/x'],
  ['/a?', '/a?'],
  ['/a\\b', '/a\\b'],
  ['/a;p=1/b;q?x=1', '/a;p=1/b;q?x=1'],
  ['/a#frag', '/a#frag'],
]

// Plain HTTP, no filterRequest: the path and query of the parsed absolute
// URI, with a leading `//` kept.
const PLAIN_UNCHANGED: Case[] = [
  ['/a/../b', '/b'],
  ['/a/%2e%2e/b', '/b'],
  ['//k/x', '//k/x'],
  ['/a?', '/a'],
  ['/a\\b', '/a/b'],
  ['/a;p=1/b;q?x=1', '/a;p=1/b;q?x=1'],
]

const lookup = ((_hostname, options, callback) => {
  const all = typeof options === 'object' && options.all
  if (all) callback(null, [{ address: '127.0.0.1', family: 4 }])
  else callback(null, '127.0.0.1', 4)
}) as LookupFunction

/** Records the request target of every request head, off the wire. */
function recordTargets(seen: string[]): (socket: Socket) => void {
  return socket => {
    let buf = ''
    socket.on('error', () => {})
    socket.on('data', chunk => {
      buf += chunk.toString('latin1')
      for (let end; (end = buf.indexOf('\r\n\r\n')) >= 0; ) {
        seen.push(buf.slice(0, buf.indexOf('\r\n')).split(' ')[1]!)
        buf = buf.slice(end + 4)
        socket.write('HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n')
      }
    })
  }
}

/** Writes one request head and resolves with the reply's status code. */
function exchange(socket: Socket, head: string): Promise<number> {
  return new Promise((resolve, reject) => {
    let buf = ''
    socket.on('data', chunk => {
      buf += chunk.toString('latin1')
      if (!buf.includes('\r\n\r\n')) return
      socket.destroy()
      resolve(Number(/^HTTP\/1\.1 (\d+)/.exec(buf)?.[1] ?? 0))
    })
    socket.once('error', reject)
    socket.once('close', () => reject(new Error('closed before a reply')))
    socket.write(head)
  })
}

describe('request target forwarding', () => {
  const ca = createMitmCA({ caCertPath: CA_CERT, caKeyPath: CA_KEY })
  const tlsSeen: string[] = []
  const plainSeen: string[] = []
  const hookSeen: (string | undefined)[] = []
  const servers: Server[] = []
  let tlsPort: number
  let plainPort: number
  let noHookPort: number
  let hookPort: number

  async function listen(server: Server): Promise<number> {
    servers.push(server)
    await new Promise<void>(r => server.listen(0, '127.0.0.1', () => r()))
    return (server.address() as AddressInfo).port
  }

  beforeAll(async () => {
    const leaf = mintLeafCert(ca, UPSTREAM_NAME)
    const cert = leaf.certPem.match(
      /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\r?\n?/,
    )![0]
    tlsPort = await listen(
      createTlsServer({ cert, key: leaf.keyPem }, recordTargets(tlsSeen)),
    )
    plainPort = await listen(createServer(recordTargets(plainSeen)))
    const base = {
      filter: () => true,
      mitmCA: ca,
      tlsTerminateUpstreamCA: CA_PEM,
      lookupFor: () => lookup,
    }
    noHookPort = await listen(createHttpProxyServer(base))
    hookPort = await listen(
      createHttpProxyServer({
        ...base,
        filterRequest: async (_request, info) => {
          hookSeen.push(info?.requestTarget)
          return { action: 'allow' }
        },
      }),
    )
  })

  afterAll(async () => {
    for (const s of servers) {
      await new Promise<void>(r => s.close(() => r()))
    }
  })

  /** One GET over a fresh TLS-terminated tunnel; the target upstream saw. */
  async function viaTls(proxyPort: number, target: string): Promise<string> {
    const authority = `${UPSTREAM_NAME}:${tlsPort}`
    const raw = await new Promise<Socket>((resolve, reject) => {
      const socket = connect(proxyPort, '127.0.0.1', () => {
        socket.write(
          `CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\n\r\n`,
        )
      })
      socket.once('error', reject)
      socket.once('data', () => resolve(socket))
    })
    const tls = await new Promise<Socket>((resolve, reject) => {
      const t = tlsConnect(
        { socket: raw, ca: CA_PEM, servername: UPSTREAM_NAME },
        () => resolve(t),
      )
      t.once('error', reject)
    })
    const before = tlsSeen.length
    const head = `GET ${target} HTTP/1.1\r\nHost: ${authority}\r\n\r\n`
    expect(await exchange(tls, head)).toBe(200)
    expect(tlsSeen.length).toBe(before + 1)
    return tlsSeen[before]!
  }

  /** One absolute-form GET through the proxy; the target upstream saw. */
  async function viaPlain(proxyPort: number, target: string): Promise<string> {
    const authority = `127.0.0.1:${plainPort}`
    const before = plainSeen.length
    const head = `GET http://${authority}${target} HTTP/1.1\r\nHost: ${authority}\r\n\r\n`
    const socket = await new Promise<Socket>((resolve, reject) => {
      const s = connect(proxyPort, '127.0.0.1', () => resolve(s))
      s.once('error', reject)
    })
    expect(await exchange(socket, head)).toBe(200)
    expect(plainSeen.length).toBe(before + 1)
    return plainSeen[before]!
  }

  describe('no hook: target forwarded unchanged', () => {
    test.each(TLS_UNCHANGED)('TLS-terminated %s', async (sent, forwarded) => {
      expect(await viaTls(noHookPort, sent)).toBe(forwarded)
    })

    test.each(PLAIN_UNCHANGED)('plain HTTP %s', async (sent, forwarded) => {
      expect(await viaPlain(noHookPort, sent)).toBe(forwarded)
    })
  })

  describe('with a hook: the target it judges is the target forwarded', () => {
    test.each(TLS_UNCHANGED)('TLS-terminated %s', async sent => {
      const forwarded = await viaTls(hookPort, sent)
      expect(hookSeen.at(-1)).toBe(forwarded)
    })

    test.each(PLAIN_UNCHANGED)('plain HTTP %s', async sent => {
      const forwarded = await viaPlain(hookPort, sent)
      expect(hookSeen.at(-1)).toBe(forwarded)
    })

    test('dot segments and a leading // are resolved before the hook', async () => {
      expect(await viaTls(hookPort, '//a/../b')).toBe('/b')
      expect(hookSeen.at(-1)).toBe('/b')
      expect(await viaPlain(hookPort, '//k/x')).toBe('/k/x')
      expect(hookSeen.at(-1)).toBe('/k/x')
    })
  })
})
