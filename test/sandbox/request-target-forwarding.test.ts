import { test, expect, beforeAll, afterAll, spyOn } from 'bun:test'
// Every case here runs a proxy configured to terminate TLS, so each is
// skipped where this runtime cannot terminate it in-process.
import { describeWithTls as describe } from '../helpers/emitted-connections.js'
import { connect, createServer, type AddressInfo, type Server } from 'node:net'
import type { LookupFunction, Socket } from 'node:net'
import {
  connect as tlsConnect,
  createServer as createTlsServer,
} from 'node:tls'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { PassThrough } from 'node:stream'
import {
  createHttpProxyServer,
  type HttpProxyServerOptions,
} from '../../src/sandbox/http-proxy.js'
import { createMitmCA } from '../../src/sandbox/mitm-ca.js'
import { mintLeafCert } from '../../src/sandbox/mitm-leaf.js'
import {
  readRequestTarget,
  refuseUnparsedRequest,
  type RequestInfo,
} from '../../src/sandbox/request-filter.js'
import { SentinelRegistry } from '../../src/sandbox/credential-sentinel.js'
import {
  AwsPairRegistry,
  createSigv4Planner,
} from '../../src/sandbox/credential-aws-pairs.js'
import { signSigv4, UNSIGNED_PAYLOAD } from '../../src/sandbox/aws-sigv4.js'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import { spawnAsync } from '../helpers/spawn.js'

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

// With filterRequest. Ambiguous: as spelled, and normalized.
const AMBIGUOUS: Case[] = [
  ['/a/../b', '/b'],
  ['/a/./b', '/a/b'],
  ['/a/..', '/'],
  ['/a/.', '/a/'],
  ['/a/%2e%2e/b', '/b'],
  ['/a/.%2E/b', '/b'],
  ['/a/%2e/b', '/a/b'],
  ['/a;/../b', '/b'],
  ['/a//../b', '/a/b'],
  ['//k/x', '/k/x'],
  ['///k?q=1', '/k?q=1'],
  ['/a\\b', '/a/b'],
  ['/\\k', '/k'],
  // Two kinds at once.
  ['//k/../b', '/b'],
  ['//k\\b', '/k/b'],
  ['/\\/k', '/k'],
  ['/a\\..\\b', '/b'],
  ['/a\\%2e%2e\\b', '/b'],
  ['/a\\b/../c', '/a/c'],
  // One kind, beside the escape of another.
  ['/a%5cb/../c', '/c'],
  ['//k%5cb', '/k%5cb'],
  ['/a%23/../b', '/b'],
  ['/a%23b\\c', '/a%23b/c'],
  ['//k%23', '/k%23'],
]

// A fragment is cut off before anything is read: as sent, and what is left.
const FRAGMENT: Case[] = [
  ['/p#f', '/p'],
  ['/p#', '/p'],
  ['/p#f?q', '/p'],
  ['/p?q#f', '/p?q'],
  ['/p?#f', '/p?'],
  ['/#f', '/'],
  ['/p#f#g', '/p'],
  ['/p%23a#f', '/p%23a'],
  // What would be ambiguous in the path is not, in the fragment.
  ['/p#/../x', '/p'],
  ['/p#\\x', '/p'],
]

// What is left is ambiguous as it would be without one: and normalized.
const FRAGMENT_AMBIGUOUS = [
  ['/a/../b#x', '/a/../b', '/b'],
  ['/a/%2e%2e/b#x', '/a/%2e%2e/b', '/b'],
  ['//k#x', '//k', '/k'],
  ['/a\\b#x', '/a\\b', '/a/b'],
  ['/a\\b/../c?q#x', '/a\\b/../c?q', '/a/c?q'],
] as const

// Not ambiguous: normalizing leaves them alone, or only escapes a character
// or drops an empty query.
const UNAMBIGUOUS = [
  '/',
  '/a/b/?x=1',
  '/a//b',
  '/a/b//',
  '/a%2Fb',
  '/a%2f..%2fb',
  '/a/..%2fb',
  '/a/%252e%252e/b',
  '/a/...',
  '/a/..b',
  '/a/.hidden',
  '/a/..;/b',
  '/a;p=1/b;q?x=1',
  '/a?x=../y&z=//&w=\\',
  '/%61%7e',
  '/a%zz',
  // The escape of `\\` or `#` is data.
  '/a%5cb',
  '/a%5c..%5cb',
  '/a/..%5cb',
  '/a%23b',
  '/a/..%23',
  '/a/%2e%2e%23',
  '/a?x=%23',
  '/a?',
  '/a??',
  '/a{b}|c^d"e<f>g`h',
  `/a?q='x'&r="y"`,
]

const lookup = ((_hostname, options, callback) => {
  const all = typeof options === 'object' && options.all
  if (all) callback(null, [{ address: '127.0.0.1', family: 4 }])
  else callback(null, '127.0.0.1', 4)
}) as LookupFunction

/** Records the request target of every request head, off the wire. */
function recordTargets(
  seen: string[],
  heads: string[] = [],
): (socket: Socket) => void {
  return socket => {
    let buf = ''
    socket.on('error', () => {})
    socket.on('data', chunk => {
      buf += chunk.toString('latin1')
      for (let end; (end = buf.indexOf('\r\n\r\n')) >= 0; ) {
        seen.push(buf.slice(0, buf.indexOf('\r\n')).split(' ')[1]!)
        heads.push(buf.slice(0, end))
        buf = buf.slice(end + 4)
        socket.write('HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n')
      }
    })
  }
}

type Reply = { status: number; text: string }

/** Writes one request head and resolves with the reply, read to its end. */
function exchange(socket: Socket, head: string): Promise<Reply> {
  return new Promise((resolve, reject) => {
    let buf = ''
    socket.on('data', chunk => {
      buf += chunk.toString('latin1')
      if (!buf.includes('\r\n\r\n')) return
      if (
        /^transfer-encoding: chunked/im.test(buf) &&
        !/\r\n0\r\n\r\n$/.test(buf)
      )
        return
      socket.destroy()
      resolve({
        status: Number(/^HTTP\/1\.1 (\d+)/.exec(buf)?.[1] ?? 0),
        text: buf,
      })
    })
    socket.once('error', reject)
    socket.once('close', () => reject(new Error('closed before a reply')))
    socket.write(Buffer.from(head, 'latin1'))
  })
}

describe('request target forwarding', () => {
  const ca = createMitmCA({ caCertPath: CA_CERT, caKeyPath: CA_KEY })
  const tlsSeen: string[] = []
  const tlsHeads: string[] = []
  const plainSeen: string[] = []
  const hookSeen: { url: string; info?: RequestInfo }[] = []
  const denied: { method: string; url: string; reason: string }[] = []
  const servers: Server[] = []
  let tlsPort: number
  let plainPort: number
  let noHookPort: number
  /** A proxy with an allow-all hook, by its ambiguousRequestTarget. */
  const hookPort = { default: 0, refuse: 0, asSpelled: 0, normalize: 0 }
  let base: HttpProxyServerOptions

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
      createTlsServer(
        { cert, key: leaf.keyPem },
        recordTargets(tlsSeen, tlsHeads),
      ),
    )
    plainPort = await listen(createServer(recordTargets(plainSeen)))
    base = {
      filter: () => true,
      mitmCA: ca,
      tlsTerminateUpstreamCA: CA_PEM,
      lookupFor: () => lookup,
    }
    noHookPort = await listen(createHttpProxyServer(base))
    for (const mode of [
      'default',
      'refuse',
      'asSpelled',
      'normalize',
    ] as const) {
      hookPort[mode] = await listen(
        createHttpProxyServer({
          ...base,
          ambiguousRequestTarget: mode === 'default' ? undefined : mode,
          filterRequest: async (request, info) => {
            hookSeen.push({ url: request.url, info })
            return { action: 'allow' }
          },
        }),
      )
    }
  })

  afterAll(async () => {
    for (const s of servers) {
      await new Promise<void>(r => s.close(() => r()))
    }
  })

  type Sent = Reply & { forwarded: string | undefined }

  /** A fresh TLS-terminated tunnel to the upstream. */
  async function tunnel(proxyPort: number): Promise<Socket> {
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
    return new Promise<Socket>((resolve, reject) => {
      const t = tlsConnect(
        { socket: raw, ca: CA_PEM, servername: UPSTREAM_NAME },
        () => resolve(t),
      )
      t.once('error', reject)
    })
  }

  /** One request over a fresh tunnel, and the target upstream saw. */
  async function sendTls(
    proxyPort: number,
    target: string,
    headers: string[] = [],
  ): Promise<Sent> {
    const authority = `${UPSTREAM_NAME}:${tlsPort}`
    const tls = await tunnel(proxyPort)
    const before = tlsSeen.length
    const lines = [`GET ${target} HTTP/1.1`, `Host: ${authority}`, ...headers]
    const reply = await exchange(tls, lines.join('\r\n') + '\r\n\r\n')
    expect(tlsSeen.length - before).toBe(reply.status === 200 ? 1 : 0)
    return { ...reply, forwarded: tlsSeen[before] }
  }

  /** One absolute-form GET through the proxy, and the target upstream saw. */
  async function sendPlain(
    proxyPort: number,
    target: string,
    scheme = 'http://',
  ): Promise<Sent> {
    const authority = `127.0.0.1:${plainPort}`
    const before = plainSeen.length
    const head = `GET ${scheme}${authority}${target} HTTP/1.1\r\nHost: ${authority}\r\n\r\n`
    const socket = await new Promise<Socket>((resolve, reject) => {
      const s = connect(proxyPort, '127.0.0.1', () => resolve(s))
      s.once('error', reject)
    })
    const reply = await exchange(socket, head)
    expect(plainSeen.length - before).toBe(reply.status === 200 ? 1 : 0)
    return { ...reply, forwarded: plainSeen[before] }
  }

  const LEGS = [
    ['TLS-terminated', sendTls],
    ['plain HTTP', sendPlain],
  ] as const

  describe('no hook: target forwarded unchanged', () => {
    test.each(TLS_UNCHANGED)('TLS-terminated %s', async (sent, forwarded) => {
      expect((await sendTls(noHookPort, sent)).forwarded).toBe(forwarded)
    })

    test.each(PLAIN_UNCHANGED)('plain HTTP %s', async (sent, forwarded) => {
      expect((await sendPlain(noHookPort, sent)).forwarded).toBe(forwarded)
    })
  })

  describe.each(LEGS)('with a hook, %s', (_leg, send) => {
    // The upstream may act on either form, and the hook has not said that it
    // judged both: neither is sent.
    describe.each(['default', 'refuse'] as const)('%s', mode => {
      test.each(AMBIGUOUS)('%s is refused, loudly', async sent => {
        const asked = hookSeen.length
        const reply = await send(hookPort[mode], sent)
        expect(reply.status).toBe(400)
        expect(reply.text).toMatch(
          /^x-proxy-error: ambiguous-request-target\r$/im,
        )
        expect(reply.text).toContain(
          `(network.ambiguousRequestTarget in the sandbox's configuration is "refuse")`,
        )
        expect(reply.forwarded).toBeUndefined()
        expect(hookSeen.length).toBe(asked)
      })
    })

    test.each(AMBIGUOUS)(
      'asSpelled: %s goes out as spelled, and the hook gets both forms',
      async (sent, normalized) => {
        expect((await send(hookPort.asSpelled, sent)).forwarded).toBe(sent)
        expect(hookSeen.at(-1)!.info?.requestTarget).toBe(sent)
        expect(hookSeen.at(-1)!.info?.normalizedRequestTarget).toBe(normalized)
      },
    )

    test.each(AMBIGUOUS)(
      'normalize: %s goes out as %s, and the hook gets both forms',
      async (sent, normalized) => {
        const reply = await send(hookPort.normalize, sent)
        expect(reply.forwarded).toBe(normalized)
        expect(hookSeen.at(-1)!.info?.requestTarget).toBe(sent)
        expect(hookSeen.at(-1)!.info?.normalizedRequestTarget).toBe(normalized)
        expect(hookSeen.at(-1)!.url.endsWith(normalized)).toBe(true)
      },
    )

    test.each(UNAMBIGUOUS)('%s goes out byte for byte', async sent => {
      for (const mode of ['default', 'asSpelled'] as const) {
        expect((await send(hookPort[mode], sent)).forwarded).toBe(sent)
        expect(hookSeen.at(-1)!.info?.requestTarget).toBe(sent)
      }
      const { forwarded } = await send(hookPort.normalize, sent)
      expect(forwarded).toBe(hookSeen.at(-1)!.info?.normalizedRequestTarget)
    })

    // What a rule on request.url alone judges is the parsed URL. By default
    // nothing goes out whose spelling says anything else.
    test('a prefix rule on request.url is not got around in either direction', async () => {
      const port = await listen(
        createHttpProxyServer({
          ...base,
          filterRequest: async request => ({
            action: new URL(request.url).pathname.startsWith('/allowed/')
              ? 'allow'
              : 'deny',
          }),
        }),
      )
      expect((await send(port, '/allowed/x')).forwarded).toBe('/allowed/x')
      for (const target of [
        '/allowed/../secret',
        '/allowed/%2e%2e/secret',
        '/allowed\\..\\secret',
        '//secret',
        '/secret',
        // Under /secret/ to an upstream that takes the path literally.
        '/secret/../allowed/x',
        '/secret/%2E%2E/allowed/x',
        '/secret\\..\\allowed/x',
      ]) {
        const reply = await send(port, target)
        expect([400, 403]).toContain(reply.status)
        expect(reply.forwarded).toBeUndefined()
      }
    })

    test('asSpelled: a hook can refuse an ambiguous target itself, where and how it likes', async () => {
      const port = await listen(
        createHttpProxyServer({
          ...base,
          ambiguousRequestTarget: 'asSpelled',
          filterRequest: async (_request, info) =>
            info!.requestTargetIsAmbiguous === false
              ? { action: 'allow' }
              : { action: 'deny', status: 422 },
        }),
      )
      expect((await send(port, `/a{b}?q='x'`)).status).toBe(200)
      expect((await send(port, '/a/../b')).status).toBe(422)
    })

    test('a value that is none of the three refuses', async () => {
      const port = await listen(
        createHttpProxyServer({
          ...base,
          ambiguousRequestTarget: 'spelled' as 'asSpelled',
          filterRequest: async () => ({ action: 'allow' }),
        }),
      )
      expect((await send(port, '/a/../b')).status).toBe(400)
    })

    test('requestTargetAsSpelled: what it refuses is malformed, and reported', async () => {
      const port = await listen(
        createHttpProxyServer({
          ...base,
          requestTargetAsSpelled: true,
          filterRequest: async () => ({ action: 'allow' }),
          onFilterRequestDenied: d => denied.push(d),
        }),
      )
      denied.length = 0
      expect((await send(port, '/a/../b')).forwarded).toBe('/a/../b')
      expect((await send(port, '//k')).status).toBe(400)
      expect(denied.map(d => d.reason)).toEqual(['malformed request-target'])
    })

    // Some clients leave it in the absolute form they send a proxy. An
    // upstream may end the path at it or take it into the path, so no mode
    // sends it, and the hook judges what is sent.
    test.each(FRAGMENT)('%s goes out as %s', async (sent, left) => {
      for (const mode of ['default', 'asSpelled', 'normalize'] as const) {
        const { forwarded } = await send(hookPort[mode], sent)
        const { url, info } = hookSeen.at(-1)!
        expect(forwarded).toBe(
          mode === 'normalize' ? info?.normalizedRequestTarget : left,
        )
        expect(info?.requestTarget).toBe(left)
        expect(info?.requestTargetIsAmbiguous).toBe(false)
        expect(url).not.toContain('#')
      }
    })

    test.each(FRAGMENT_AMBIGUOUS)(
      '%s is judged as %s',
      async (sent, left, normalized) => {
        const refused = await send(hookPort.default, sent)
        expect(refused.text).toMatch(
          /^x-proxy-error: ambiguous-request-target\r$/im,
        )
        expect((await send(hookPort.asSpelled, sent)).forwarded).toBe(left)
        expect(hookSeen.at(-1)!.info).toMatchObject({
          requestTarget: left,
          normalizedRequestTarget: normalized,
          requestTargetIsAmbiguous: true,
        })
        expect((await send(hookPort.normalize, sent)).forwarded).toBe(
          normalized,
        )
      },
    )

    test.each([
      ['/a/../b?q=1', '/a/../b?q=1', 'ambiguous request-target'],
      ['/a/../b?q=1#x', '/a/../b?q=1', 'ambiguous request-target'],
    ])(
      'the refusal of %s is reported like a denial of the hook, and logged',
      async (sent, shown, reason) => {
        const port = await listen(
          createHttpProxyServer({
            ...base,
            filterRequest: async () => ({ action: 'allow' }),
            onFilterRequestDenied: d => denied.push(d),
            denyHeader: 'X-Deny-Reason',
          }),
        )
        denied.length = 0
        const warn = spyOn(console, 'warn').mockImplementation(() => {})
        const error = spyOn(console, 'error').mockImplementation(() => {})
        process.env.SRT_DEBUG = '1'
        try {
          const reply = await send(port, sent)
          expect(reply.status).toBe(400)
          expect(reply.text).toMatch(/^x-deny-reason: bad_request\r$/im)
          expect(warn.mock.calls.flat().join('\n')).toContain(reason)
        } finally {
          delete process.env.SRT_DEBUG
          warn.mockRestore()
          error.mockRestore()
        }
        expect(denied).toHaveLength(1)
        expect(denied[0]!.method).toBe('GET')
        expect(denied[0]!.url.replace(/^https?:\/\/[^/]+/, '')).toBe(shown)
        expect(denied[0]!.reason).toStartWith(reason)
      },
    )
  })

  test.each([
    ['TLS-terminated', 'https://upstream.test:'],
    ['plain HTTP', 'http://127.0.0.1:'],
  ])(
    'with a hook, %s: a target of no known shape is reported too',
    async (leg, origin) => {
      const port = await listen(
        createHttpProxyServer({
          ...base,
          filterRequest: async () => ({ action: 'allow' }),
          onFilterRequestDenied: d => denied.push(d),
        }),
      )
      denied.length = 0
      const reply =
        leg === 'plain HTTP'
          ? await sendPlain(port, '/x', 'http:///')
          : await sendTls(port, `http:///${UPSTREAM_NAME}/x`)
      expect(reply.status).toBe(400)
      expect(reply.text).toMatch(
        /^x-proxy-error: blocked-by-sandbox-runtime\r$/im,
      )
      expect(denied).toHaveLength(1)
      expect(denied[0]!.url.replace(/\d+$/, '')).toBe(origin)
      expect(denied[0]!.reason).toBe('malformed request-target')
    },
  )

  test.each(['default', 'asSpelled', 'normalize'] as const)(
    'with a hook, %s: OPTIONS * is judged under its own host, and sent as it is',
    async mode => {
      const authority = `${UPSTREAM_NAME}:${tlsPort}`
      const [asked, arrived] = [hookSeen.length, tlsSeen.length]
      const reply = await exchange(
        await tunnel(hookPort[mode]),
        `OPTIONS * HTTP/1.1\r\nHost: ${authority}\r\n\r\n`,
      )
      expect(reply.status).toBe(200)
      expect(tlsSeen.slice(arrived)).toEqual(['*'])
      const [seen] = hookSeen.slice(asked)
      expect(seen!.url).toBe(`https://${authority}/`)
      expect(seen!.info!.requestTarget).toBe('*')
    },
  )

  test.each(['default', 'asSpelled', 'normalize'] as const)(
    'with a hook, %s: a fragment right after the authority leaves the root',
    async mode => {
      for (const rest of ['#x', '#x/y', '#', '#@other.test/x']) {
        const reply = await sendPlain(hookPort[mode], rest)
        expect([rest, reply.status, reply.forwarded]).toEqual([rest, 200, '/'])
      }
    },
  )

  // No request handler sees these: the runtime's HTTP parser gives up on
  // them. Left to itself the tunnel would close without a word.
  describe('a request the parser refuses, in a tunnel', () => {
    const host = (): string => `Host: ${UPSTREAM_NAME}:${tlsPort}\r\n`
    const ADVICE =
      'malformed request-target: percent-encode its bytes outside printable ASCII'

    /** Writes the chunks on a fresh tunnel; all it answers, once it closes. */
    async function untilClosed(
      proxyPort: number,
      ...chunks: string[]
    ): Promise<string> {
      const tls = await tunnel(proxyPort)
      const closed = new Promise<void>(r => tls.once('close', () => r()))
      let reply = ''
      tls.on('error', () => {})
      tls.on('data', chunk => (reply += chunk.toString('latin1')))
      for (const chunk of chunks) {
        tls.write(Buffer.from(chunk, 'latin1'))
        await new Promise(r => setTimeout(r, 50))
      }
      await closed
      return reply
    }

    const reporting = (
      extra: Partial<HttpProxyServerOptions> = {},
    ): Promise<number> => {
      denied.length = 0
      return listen(
        createHttpProxyServer({
          ...base,
          filterRequest: async (request, info) => {
            hookSeen.push({ url: request.url, info })
            return { action: 'allow' }
          },
          onFilterRequestDenied: d => denied.push(d),
          ...extra,
        }),
      )
    }

    test.each([
      ['/caf\xc3\xa9', '/caf%C3%A9'],
      ['/x?q=caf\xc3\xa9&k=v#f', '/x?q=caf%C3%A9&k=v#f'],
      ['/caf\xe9', '/caf%E9'],
      ['/a\tb\x00c\x7f', '/a%09b%00c%7F'],
    ])(
      '%p is answered 400 with what to do, and reported as %s',
      async (sent, shown) => {
        const port = await reporting()
        const [asked, arrived] = [hookSeen.length, tlsSeen.length]
        const reply = await untilClosed(
          port,
          `POST ${sent} HTTP/1.1\r\n${host()}\r\n`,
        )
        expect(reply).toBe(
          'HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\n' +
            'X-Proxy-Error: blocked-by-sandbox-runtime\r\n' +
            `Content-Length: ${ADVICE.length + 1}\r\nConnection: close\r\n\r\n` +
            `${ADVICE}\n`,
        )
        expect(denied).toEqual([
          {
            method: 'POST',
            url: `https://${UPSTREAM_NAME}:${tlsPort}${shown}`,
            reason: ADVICE,
          },
        ])
        expect([hookSeen.length, tlsSeen.length]).toEqual([asked, arrived])
      },
    )

    test.each([
      ['a space in the target', `GET /a b HTTP/1.1\r\n`, ''],
      ['a header name with a space', 'GET /a HTTP/1.1\r\n', 'Bad Name: x\r\n'],
      ['a control byte in a header', 'GET /a HTTP/1.1\r\n', 'X: a\x01b\r\n'],
      ['a method it does not know', 'FROB /a HTTP/1.1\r\n', ''],
      [
        'two lengths',
        'POST /a HTTP/1.1\r\n',
        'Content-Length: 1\r\n'.repeat(2),
      ],
      [
        'a head too long',
        'GET /a HTTP/1.1\r\n',
        `X: ${'y'.repeat(200000)}\r\n`,
      ],
    ])('%s: 400, and only the tunnel is named', async (_what, line, header) => {
      const port = await reporting()
      const reply = await untilClosed(port, `${line}${host()}${header}\r\n`)
      expect(reply).toStartWith('HTTP/1.1 400 Bad Request\r\n')
      expect(reply).toMatch(
        /\r\n\r\nmalformed request \(Parse Error: [ -~]+\)\n$/,
      )
      expect(reply.match(/HTTP\/1\.1 /g)).toHaveLength(1)
      expect(denied).toHaveLength(1)
      expect(denied[0]).toMatchObject({
        method: '-',
        url: `https://${UPSTREAM_NAME}:${tlsPort}`,
      })
      expect(denied[0]!.reason).toStartWith('malformed request (Parse Error: ')
    })

    test('it is answered whoever listens, and without a hook, and the tunnel ends at once', async () => {
      for (const port of [hookPort.default, noHookPort]) {
        const began = Date.now()
        expect(
          await untilClosed(port, `GET /\xc3\xa9 HTTP/1.1\r\n${host()}\r\n`),
        ).toEndWith(`${ADVICE}\n`)
        expect(Date.now() - began).toBeLessThan(700)
      }
    })

    test('a proxy that marks its refusals marks this one', async () => {
      const port = await reporting({ denyHeader: 'X-Deny-Reason' })
      const reply = await untilClosed(
        port,
        `GET /\xc3\xa9 HTTP/1.1\r\n${host()}\r\n`,
      )
      expect(reply).toContain('\r\nX-Deny-Reason: bad_request\r\n')
      expect(reply).not.toMatch(/x-proxy-error/i)
    })

    test('it leaves a warn-level debug line', async () => {
      const warn = spyOn(console, 'warn').mockImplementation(() => {})
      const error = spyOn(console, 'error').mockImplementation(() => {})
      process.env.SRT_DEBUG = '1'
      try {
        await untilClosed(
          hookPort.default,
          `GET /\xc3\xa9 HTTP/1.1\r\n${host()}\r\n`,
        )
        expect(warn.mock.calls.flat().join('\n')).toContain(ADVICE)
      } finally {
        delete process.env.SRT_DEBUG
        warn.mockRestore()
        error.mockRestore()
      }
    })

    test('after an answered request it is answered in its turn', async () => {
      const port = await reporting()
      const reply = await untilClosed(
        port,
        `GET /ok HTTP/1.1\r\n${host()}\r\n`,
        `GET /\xc3\xa9 HTTP/1.1\r\n${host()}\r\n`,
      )
      expect(reply.match(/HTTP\/1\.1 \d+/g)).toEqual([
        'HTTP/1.1 200',
        'HTTP/1.1 400',
      ])
      expect(denied.map(d => d.url)).toEqual([
        `https://${UPSTREAM_NAME}:${tlsPort}/%C3%A9`,
      ])
    })

    // The 400 would be read as the answer to the request before it.
    test('behind a request still being answered, nothing is written', async () => {
      const port = await reporting()
      const reply = await untilClosed(
        port,
        `GET /ok HTTP/1.1\r\n${host()}\r\nGET /\xc3\xa9 HTTP/1.1\r\n${host()}\r\n`,
      )
      expect(reply).not.toContain(' 400 ')
      // The line the parser stopped in, not the packet's first.
      expect(denied.map(d => d.url)).toEqual([
        `https://${UPSTREAM_NAME}:${tlsPort}/%C3%A9`,
      ])
    })

    test('a client that goes away in the middle of a head is no refusal', async () => {
      const port = await reporting()
      const error = spyOn(console, 'error').mockImplementation(() => {})
      process.env.SRT_DEBUG = '1'
      try {
        const tls = await tunnel(port)
        tls.on('error', () => {})
        tls.write(`GET /a HTTP/1.1\r\n${host()}X: `)
        await new Promise(r => setTimeout(r, 50))
        tls.destroy()
        await new Promise(r => setTimeout(r, 100))
        // The server was told, so this is the path that reports nothing.
        expect(error.mock.calls.flat().join('\n')).toContain(
          '[tls-terminate] client connection error',
        )
      } finally {
        delete process.env.SRT_DEBUG
        error.mockRestore()
      }
      expect(denied).toEqual([])
    })

    test('one answer and one report, whatever follows', async () => {
      const port = await reporting()
      const bad = `GET /\xc3\xa9 HTTP/1.1\r\n${host()}\r\n`
      const reply = await untilClosed(port, bad + bad, bad, bad)
      expect(reply.match(/HTTP\/1\.1 /g)).toHaveLength(1)
      expect(denied).toHaveLength(1)
    })
  })

  test('a refused upload does not keep its tunnel', async () => {
    const tls = await tunnel(hookPort.default)
    const closed = new Promise<void>(r => tls.once('close', () => r()))
    let reply = ''
    tls.on('error', () => {})
    tls.on('data', chunk => (reply += chunk.toString('latin1')))
    // A body announced and never sent: nothing else ends this connection.
    tls.write(
      `PUT /a/../b HTTP/1.1\r\nHost: ${UPSTREAM_NAME}:${tlsPort}\r\n` +
        'Content-Length: 1000000\r\n\r\nstart',
    )
    await closed
    expect(reply).toStartWith('HTTP/1.1 400 ')
  }, 3000)

  describe('with a hook: an absolute-form target', () => {
    test('in a tunnel, its path and query are read like an origin-form target', async () => {
      const abs = `https://${UPSTREAM_NAME}:${tlsPort}`
      expect((await sendTls(hookPort.default, `${abs}/a//b?x`)).forwarded).toBe(
        '/a//b?x',
      )
      expect((await sendTls(hookPort.default, abs)).forwarded).toBe('/')
      expect((await sendTls(hookPort.default, `${abs}?x`)).forwarded).toBe(
        '/?x',
      )
      expect((await sendTls(hookPort.default, `${abs}/a/../b`)).status).toBe(
        400,
      )
      expect(
        (await sendTls(hookPort.asSpelled, `${abs}//a/../b`)).forwarded,
      ).toBe('//a/../b')
      expect(hookSeen.at(-1)!.info?.normalizedRequestTarget).toBe('/b')
    })
  })

  // The service takes the path literally: `a/../b.txt` is a key, and the
  // signature covers the path as it arrives.
  describe('a request signed over its path', () => {
    const REAL = {
      accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
      secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    }
    const SIGNED: Case[] = [
      ['//lead.txt', '/lead.txt'],
      ['/a/../b.txt', '/b.txt'],
      ['/a/..', '/'],
      ['/bucket/../up.txt', '/up.txt'],
    ]
    const amz = {
      'x-amz-content-sha256': UNSIGNED_PAYLOAD,
      'x-amz-date': '20260101T000000Z',
    }
    const authorizationFor = (target: string, creds: typeof REAL): string =>
      signSigv4({
        method: 'GET',
        requestTarget: target,
        headers: amz,
        hostHeader: `${UPSTREAM_NAME}:${tlsPort}`,
        signedHeaders: ['host', ...Object.keys(amz)],
        payloadHash: UNSIGNED_PAYLOAD,
        amzDate: amz['x-amz-date'],
        scope: { date: '20260101', region: 'us-east-1', service: 's3' },
        ...creds,
      }).authorization
    const sendSigned = (port: number, target: string, creds: typeof REAL) =>
      sendTls(port, target, [
        ...Object.entries(amz).map(([k, v]) => `${k}: ${v}`),
        `Authorization: ${authorizationFor(target, creds)}`,
      ])
    const receivedAuthorization = (): string | undefined =>
      /^authorization: (.*)$/im.exec(tlsHeads.at(-1)!)?.[1]

    describe('by the client', () => {
      test.each(SIGNED)('asSpelled: %s still verifies', async sent => {
        const reply = await sendSigned(hookPort.asSpelled, sent, REAL)
        expect(reply.forwarded).toBe(sent)
        expect(receivedAuthorization()).toBe(authorizationFor(sent, REAL))
      })

      test.each(SIGNED)('default: %s is refused', async sent => {
        expect((await sendSigned(hookPort.default, sent, REAL)).status).toBe(
          400,
        )
      })

      test.each(SIGNED)(
        'normalize: %s arrives as %s, which it is not signed for',
        async (sent, normalized) => {
          const reply = await sendSigned(hookPort.normalize, sent, REAL)
          expect(reply.forwarded).toBe(normalized)
          expect(receivedAuthorization()).not.toBe(
            authorizationFor(normalized, REAL),
          )
        },
      )
    })

    describe('again by the proxy, for a masked credential', () => {
      const sentinels = new SentinelRegistry()
      const pairs = new AwsPairRegistry()
      const eq = (h: string, p: string): boolean => h === p
      const FAKE = {
        accessKeyId: sentinels.register('AKID', REAL.accessKeyId, [
          UPSTREAM_NAME,
        ]),
        secretAccessKey: sentinels.register('SECRET', REAL.secretAccessKey, [
          UPSTREAM_NAME,
        ]),
      }
      pairs.register({
        accessKeyIdSentinel: FAKE.accessKeyId,
        realAccessKeyId: REAL.accessKeyId,
        realSecretAccessKey: REAL.secretAccessKey,
        injectHosts: [UPSTREAM_NAME],
      })
      const resigning = (
        ambiguousRequestTarget: HttpProxyServerOptions['ambiguousRequestTarget'],
      ): Promise<number> =>
        listen(
          createHttpProxyServer({
            ...base,
            ambiguousRequestTarget,
            filterRequest: async () => ({ action: 'allow' }),
            mutateHeaders: (headers, host) =>
              sentinels.substituteInHeaders(headers, host, eq),
            planSigv4: createSigv4Planner(pairs, undefined, eq),
          }),
        )

      test.each(SIGNED)(
        'asSpelled: %s is signed for the path the client named',
        async sent => {
          const reply = await sendSigned(
            await resigning('asSpelled'),
            sent,
            FAKE,
          )
          expect(reply.forwarded).toBe(sent)
          expect(receivedAuthorization()).toBe(authorizationFor(sent, REAL))
        },
      )

      test.each(SIGNED)('default: %s is never signed', async sent => {
        const reply = await sendSigned(await resigning(undefined), sent, FAKE)
        expect(reply.status).toBe(400)
      })

      test.each(SIGNED)(
        'normalize: %s is signed for %s, the bytes forwarded',
        async (sent, normalized) => {
          const reply = await sendSigned(
            await resigning('normalize'),
            sent,
            FAKE,
          )
          expect(reply.forwarded).toBe(normalized)
          expect(receivedAuthorization()).toBe(
            authorizationFor(normalized, REAL),
          )
        },
      )

      test.each([undefined, 'asSpelled', 'normalize'] as const)(
        '%p: a fragment is in neither the path sent nor the path signed',
        async mode => {
          const reply = await sendSigned(
            await resigning(mode),
            '/k.txt#f',
            FAKE,
          )
          expect(reply.forwarded).toBe('/k.txt')
          expect(receivedAuthorization()).toBe(authorizationFor('/k.txt', REAL))
        },
      )
    })
  })

  // Bun's listener lets a byte outside ASCII through, decoded. (Node's
  // parser, and Bun's for a tunnel's connection, refuse the request.)
  describe.each(['default', 'asSpelled', 'normalize'] as const)(
    'with a hook, %s: a byte outside ASCII, plain HTTP',
    mode => {
      test.each([
        ['/caf\xc3\xa9?q=caf\xc3\xa9', '/caf%C3%A9?q=caf%C3%A9'],
        ['/\xe2\x82\xac/\xf0\x9f\x98\x80', '/%E2%82%AC/%F0%9F%98%80'],
        ['/\xc3\xa9%c3%a9', '/%C3%A9%c3%a9'],
      ])('UTF-8 goes out percent-encoded: %p', async (sent, encoded) => {
        expect((await sendPlain(hookPort[mode], sent)).forwarded).toBe(encoded)
        expect(hookSeen.at(-1)!.info).toMatchObject({
          requestTarget: encoded,
          normalizedRequestTarget: encoded,
          requestTargetIsAmbiguous: false,
        })
      })

      // U+FFFD stands where they were: percent-encoding that would name
      // another resource.
      test.each(['/caf\xe9', '/a?q=\xe9', '/a\xc3', '/a\xc0\xafb'])(
        'bytes that are not UTF-8 are refused: %p',
        async sent => {
          const asked = hookSeen.length
          const reply = await sendPlain(hookPort[mode], sent)
          expect(reply.status).toBe(400)
          expect(reply.text).toContain('bytes that are not UTF-8')
          expect(hookSeen.length).toBe(asked)
        },
      )
    },
  )

  test('with a hook: a dot segment beside a byte outside ASCII is still ambiguous', async () => {
    const reply = await sendPlain(hookPort.default, '/\xc3\xa9/../b')
    expect(reply.text).toMatch(/^x-proxy-error: ambiguous-request-target\r$/im)
  })
})

describe('readRequestTarget', () => {
  test.each(AMBIGUOUS)('%s is ambiguous', (raw, normalized) => {
    const forms = { spelled: raw, normalized, ambiguous: true }
    for (const r of [raw, `http://h.test:8080${raw}`]) {
      const refused = readRequestTarget(r, 'GET')
      expect(refused).toMatchObject(forms)
      expect(refused.forwarded).toBeUndefined()
      expect(refused.refusal).toStartWith('ambiguous request-target')
      expect(readRequestTarget(r, 'GET', 'refuse')).toEqual(refused)
      expect(readRequestTarget(r, 'GET', 'asSpelled')).toEqual({
        ...forms,
        forwarded: raw,
        refusal: undefined,
      })
      expect(readRequestTarget(r, 'GET', 'normalize')).toEqual({
        ...forms,
        forwarded: normalized,
        refusal: undefined,
      })
    }
  })

  test.each(UNAMBIGUOUS)('%s is not', raw => {
    expect(readRequestTarget(raw, 'GET')).toMatchObject({
      spelled: raw,
      ambiguous: false,
      forwarded: raw,
      refusal: undefined,
    })
  })

  test.each([
    ['*', '*'],
    ['http://h.test', '/'],
    ['HTTPS://u:p@h.test?x', '/?x'],
    ['http://[::1]:80/a?', '/a?'],
    ['/caf\u00e9?q=\u20ac', '/caf%C3%A9?q=%E2%82%AC'],
    ['http://caf\u00e9.test/\u{1f600}', '/%F0%9F%98%80'],
  ])('%s is spelled %s', (raw, spelled) => {
    expect(readRequestTarget(raw, 'OPTIONS')).toMatchObject({
      spelled,
      ambiguous: false,
      forwarded: spelled,
    })
  })

  // Only an escape the parser ADDS is the same resource: `%2F` is not `/`.
  test('an escape is not its character', () => {
    expect(readRequestTarget('/a%7Bb', 'GET').normalized).toBe('/a%7Bb')
    expect(readRequestTarget('/a%5Cb', 'GET').ambiguous).toBe(false)
    expect(readRequestTarget('/a%5C../b', 'GET').spelled).toBe('/a%5C../b')
  })

  test('a character that only looks like a dot or a slash is data', () => {
    expect(readRequestTarget('/a/\uff0e\uff0e/b\uff0fc', 'GET')).toMatchObject({
      spelled: '/a/%EF%BC%8E%EF%BC%8E/b%EF%BC%8Fc',
      ambiguous: false,
    })
  })

  const MODES = [undefined, 'refuse', 'asSpelled', 'normalize'] as const

  test.each(FRAGMENT)('%s is read as %s', (raw, left) => {
    for (const mode of MODES) {
      for (const origin of ['', 'http://h.test']) {
        expect(readRequestTarget(origin + raw, 'GET', mode)).toEqual(
          readRequestTarget(left, 'GET', mode),
        )
      }
    }
    expect(readRequestTarget(raw, 'GET').forwarded).toBe(left)
  })

  test.each(FRAGMENT_AMBIGUOUS)('%s is read as %s', (raw, left) => {
    for (const mode of MODES) {
      expect(readRequestTarget(raw, 'GET', mode)).toEqual(
        readRequestTarget(left, 'GET', mode),
      )
    }
    expect(readRequestTarget(raw, 'GET').ambiguous).toBe(true)
  })

  test('what the fragment holds is not read', () => {
    for (const fragment of ['\ufffd', '\ud800', '\u00e9', ' ', '\n#']) {
      expect(readRequestTarget(`/p?q#${fragment}`, 'GET')).toEqual(
        readRequestTarget('/p?q', 'GET'),
      )
    }
  })

  test.each([
    ['/caf\ufffd', '/caf%EF%BF%BD'],
    ['/a?q=\ufffd', '/a?q=%EF%BF%BD'],
    ['/\ud800', '/%EF%BF%BD'],
    ['/\udc00x', '/%EF%BF%BDx'],
    ['/\ufffd#x', '/%EF%BF%BD'],
  ])('%p is refused for what the runtime replaced', (raw, spelled) => {
    for (const mode of MODES) {
      expect(readRequestTarget(raw, 'GET', mode)).toEqual({
        spelled,
        refusal:
          'malformed request-target: it holds bytes that are not UTF-8, or U+FFFD',
      })
    }
  })

  test.each([
    '*',
    '*x',
    'h.test/x',
    'http://[::1/x',
    'ftp://h.test/x',
    // The URL parser reads another authority, or another path, than the
    // spelling has.
    'http:///h.test/x',
    'http:/h.test/x',
    'http://h.test\\x',
    'http://h.test\\@other.test/x',
    '#x',
    '*#x',
    '/a b',
    '/a\tb',
    '/a\x7f',
  ])('%p has no spelling to forward', raw => {
    for (const mode of MODES) {
      expect(readRequestTarget(raw, 'GET', mode)).toEqual({
        refusal: 'malformed request-target',
      })
    }
  })

  // What a client that leaves the fragment in sends for a URL with no path. The
  // URL parser ends the authority at the `#` too.
  test.each([
    'http://h.test#x',
    'http://h.test#x/y',
    'http://h.test#',
    'http://h.test#@other.test/x',
  ])('%p is the root of its authority', raw => {
    expect(new URL(raw).host).toBe('h.test')
    for (const mode of MODES) {
      expect(readRequestTarget(raw, 'GET', mode)).toEqual({
        spelled: '/',
        normalized: '/',
        ambiguous: false,
        forwarded: '/',
        refusal: undefined,
      })
    }
  })
})

describe('refuseUnparsedRequest', () => {
  const parseError = (
    packet: string | undefined,
    at: number | undefined,
    code = 'HPE_INVALID_URL',
  ): Error =>
    Object.assign(new Error('Parse Error: x'), {
      code,
      bytesParsed: at,
      rawPacket:
        packet === undefined ? undefined : Buffer.from(packet, 'latin1'),
    })
  /** What is reported of a packet the parser stopped in at `at`. */
  const named = (packet: string | undefined, at?: number, code?: string) => {
    const refused = refuseUnparsedRequest(
      parseError(packet, at, code),
      new PassThrough(),
      false,
    )!
    return `${refused.method} ${refused.target}`
  }

  test('the line the parser stopped in, with nothing raw', () => {
    expect(named('GET /\xe9 HTTP/1.1\r\nHost: h\r\n\r\n', 5)).toBe('GET /%E9')
    expect(named('M-SEARCH /\xe9 HTTP/1.0\n', 10)).toBe('M-SEARCH /%E9')
    expect(
      named('GET /ok HTTP/1.1\r\n\r\nPUT /\x01<>\x80 HTTP/1.1\r\n', 25),
    ).toBe('PUT /%01<>%80')
  })

  test('at most 200 bytes of it', () => {
    expect(named(`GET /${'\xe9'.repeat(300)} HTTP/1.1\r\n`, 5)).toBe(
      `GET /${'%E9'.repeat(199)}`,
    )
  })

  test.each([
    ['no packet', undefined, 5],
    ['no offset', 'GET /\xe9 HTTP/1.1\r\n', undefined],
    ['a line that began in another packet', '\xe9 HTTP/1.1\r\nHost: h\r\n', 0],
    ['a line that ends in another packet', 'GET /\xe9', 5],
    ['a line whose end is in another packet', 'GET /\xe9 HTTP/1.1', 5],
    ['a method the runtime does not know', 'FROB /\xe9 HTTP/1.1\r\n', 6],
    ['absolute form', 'GET http://o.test/\xe9 HTTP/1.1\r\n', 18],
    ['a space in the target', 'GET /\xe9 b HTTP/1.1\r\n', 5],
    ['another version', 'GET /\xe9 HTTP/2.0\r\n', 5],
    ['a request line further on', '\xe9\nGET /x HTTP/1.1\r\n', 0],
    ['a request line after the byte', '\nGET /\xe9 HTTP/1.1\r\n', 0],
    ['two lines that end like one', 'GET /\xe9\r\nX HTTP/1.1\r\n', 5],
    ['an offset that is no number', 'GET /\xe9 HTTP/1.1\r\n', '5' as never],
    ['a request line further back', 'GET /x HTTP/1.1\r\nX: \xe9\r\n', 20],
  ])('%s: nothing of the packet', (_what, packet, at) => {
    expect(named(packet, at)).toBe('- ')
  })

  test('only where it stopped in the target', () => {
    const packet = 'GET /x HTTP/1.1\r\nBad Name: y\r\n'
    expect(named(packet, 5, 'HPE_INVALID_HEADER_TOKEN')).toBe('- ')
  })

  test("an error that is not the parser's ends the socket, unanswered", () => {
    for (const code of [
      'ECONNRESET',
      'EPIPE',
      'HPE_INVALID_EOF_STATE',
      undefined,
      7,
    ]) {
      for (const ended of [false, true]) {
        const socket = new PassThrough()
        if (ended) socket.end()
        expect(
          refuseUnparsedRequest(
            Object.assign(new Error('x'), { code }),
            socket,
            true,
          ),
        ).toBeUndefined()
        expect(socket.destroyed).toBe(true)
        expect(socket.readableLength).toBe(0)
      }
    }
  })

  test('what fails the parser after a refusal is the same refusal', () => {
    const socket = new PassThrough({ highWaterMark: 1 })
    expect(
      refuseUnparsedRequest(parseError('x', 0), socket, true),
    ).toBeDefined()
    const answer = socket.readableLength
    const warn = spyOn(console, 'warn').mockImplementation(() => {})
    process.env.SRT_DEBUG = '1'
    try {
      for (const mayAnswer of [true, false]) {
        expect(
          refuseUnparsedRequest(parseError('x', 0), socket, mayAnswer),
        ).toBeUndefined()
      }
      expect(warn).not.toHaveBeenCalled()
    } finally {
      delete process.env.SRT_DEBUG
      warn.mockRestore()
    }
    // The answer is still on its way out.
    expect(socket.destroyed).toBe(false)
    expect(socket.readableLength).toBe(answer)
  })

  test('the socket is ended at once, and goes a second later', async () => {
    const socket = new PassThrough({ autoDestroy: false })
    socket.resume()
    refuseUnparsedRequest(parseError('x', 0), socket, true)
    expect(socket.writableEnded).toBe(true)
    await new Promise(r => setTimeout(r, 500))
    expect(socket.destroyed).toBe(false)
    await new Promise(r => setTimeout(r, 700))
    expect(socket.destroyed).toBe(true)
  })

  test('no write on a socket that takes none, or where it may not answer', () => {
    const errored = new PassThrough()
    errored.on('error', () => {})
    errored.destroy(new Error('x'))
    for (const [socket, mayAnswer] of [
      [errored, true],
      [new PassThrough(), false],
    ] as const) {
      const write = spyOn(socket, 'write')
      const end = spyOn(socket, 'end')
      expect(
        refuseUnparsedRequest(parseError('x', 0), socket, mayAnswer),
      ).toBeDefined()
      expect(write).not.toHaveBeenCalled()
      expect(end).not.toHaveBeenCalled()
      expect(socket.destroyed).toBe(true)
    }
  })

  test("a reset while the answer flushes is nobody's exception", () => {
    const socket = new PassThrough()
    refuseUnparsedRequest(parseError('x', 0), socket, true)
    expect(() => socket.emit('error', new Error('reset'))).not.toThrow()
  })

  test('a socket whose flush never ends is destroyed all the same', async () => {
    const stuck = new PassThrough({ highWaterMark: 1 })
    stuck.cork()
    refuseUnparsedRequest(parseError('x', 0), stuck, true)
    expect(stuck.destroyed).toBe(false)
    await new Promise(r => setTimeout(r, 1100))
    expect(stuck.destroyed).toBe(true)
  })
})

describe('network.ambiguousRequestTarget', () => {
  const seen: string[] = []
  const upstream = createServer(recordTargets(seen))
  let port: number

  beforeAll(async () => {
    await new Promise<void>(r => upstream.listen(0, '127.0.0.1', () => r()))
    port = (upstream.address() as AddressInfo).port
  })

  afterAll(async () => {
    await SandboxManager.reset()
    await new Promise<void>(r => upstream.close(() => r()))
  })

  test.each([
    [undefined, 400, undefined],
    ['refuse', 400, undefined],
    ['asSpelled', 200, '/a/../b?k=SECRET'],
    ['normalize', 200, '/b?k=SECRET'],
  ] as const)('%p: %d', async (ambiguousRequestTarget, status, forwarded) => {
    await SandboxManager.reset()
    await SandboxManager.initialize({
      network: {
        allowedDomains: ['127.0.0.1'],
        deniedDomains: [],
        filterRequest: async () => ({ action: 'allow' }),
        ambiguousRequestTarget,
      },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    })
    const auth = Buffer.from(`srt:${SandboxManager.getProxyAuthToken()}`)
    const socket = await new Promise<Socket>((resolve, reject) => {
      const s = connect(SandboxManager.getProxyPort()!, '127.0.0.1', () =>
        resolve(s),
      )
      s.once('error', reject)
    })
    const store = SandboxManager.getSandboxViolationStore()
    store.clear()
    seen.length = 0
    const reply = await exchange(
      socket,
      `GET http://u:SECRET@127.0.0.1:${port}/a/../b?k=SECRET#SECRET HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\n` +
        `Proxy-Authorization: Basic ${auth.toString('base64')}\r\n\r\n`,
    )
    expect(reply.status).toBe(status)
    expect(seen).toEqual(forwarded === undefined ? [] : [forwarded])
    // The line names what was refused, not what it would resolve to.
    expect(store.getViolations().map(v => v.line.replace(/ \(.*/, ''))).toEqual(
      status === 400
        ? [`deny http-request GET http://127.0.0.1:${port}/a/../b?…`]
        : [],
    )
    expect(JSON.stringify(store.getViolations())).not.toContain('SECRET')
  })

  test.each([
    ['/caf\xe9', '/caf%EF%BF%BD', 'bytes that are not UTF-8, or U+FFFD'],
    ['/caf\xe9#t=SECRET', '/caf%EF%BF%BD', 'bytes that are not UTF-8'],
  ])('%p is recorded as %s', async (sent, shown, reason) => {
    await SandboxManager.reset()
    await SandboxManager.initialize({
      network: {
        allowedDomains: ['127.0.0.1'],
        deniedDomains: [],
        filterRequest: async () => ({ action: 'allow' }),
        ambiguousRequestTarget: 'asSpelled',
      },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    })
    const auth = Buffer.from(`srt:${SandboxManager.getProxyAuthToken()}`)
    const socket = await new Promise<Socket>((resolve, reject) => {
      const s = connect(SandboxManager.getProxyPort()!, '127.0.0.1', () =>
        resolve(s),
      )
      s.once('error', reject)
    })
    const store = SandboxManager.getSandboxViolationStore()
    store.clear()
    const reply = await exchange(
      socket,
      `GET http://127.0.0.1:${port}${sent} HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\n` +
        `Proxy-Authorization: Basic ${auth.toString('base64')}\r\n\r\n`,
    )
    expect(reply.status).toBe(400)
    const lines = store.getViolations().map(v => v.line)
    expect(lines).toHaveLength(1)
    expect(lines[0]).toStartWith(
      `deny http-request GET http://127.0.0.1:${port}${shown} (malformed request-target: `,
    )
    expect(lines[0]).toContain(reason)
    expect(lines[0]).not.toContain('SECRET')
  })

  test.each([
    ['/caf\xc3\xa9?k=SECRET#SECRET', '/caf%C3%A9?…'],
    ['/caf\xc3\xa9#t=SECRET', '/caf%C3%A9#…'],
  ])(
    'in a tunnel, %p that the parser refuses is recorded as %s',
    async (sent, shown) => {
      await SandboxManager.reset()
      await SandboxManager.initialize({
        network: {
          allowedDomains: ['127.0.0.1'],
          deniedDomains: [],
          tlsTerminate: { caCertPath: CA_CERT, caKeyPath: CA_KEY },
        },
        filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
      })
      const auth = Buffer.from(`srt:${SandboxManager.getProxyAuthToken()}`)
      const raw = await new Promise<Socket>((resolve, reject) => {
        const s = connect(SandboxManager.getProxyPort()!, '127.0.0.1', () =>
          s.write(
            `CONNECT 127.0.0.1:${port} HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\n` +
              `Proxy-Authorization: Basic ${auth.toString('base64')}\r\n\r\n`,
          ),
        )
        s.once('error', reject)
        s.once('data', () => resolve(s))
      })
      const tls = await new Promise<Socket>((resolve, reject) => {
        const t = tlsConnect(
          { socket: raw, ca: CA_PEM, checkServerIdentity: () => undefined },
          () => resolve(t),
        )
        t.once('error', reject)
      })
      const store = SandboxManager.getSandboxViolationStore()
      store.clear()
      const reply = await exchange(
        tls,
        `GET ${sent} HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\n\r\n`,
      )
      expect(reply.status).toBe(400)
      expect(store.getViolations().map(v => v.line)).toEqual([
        `deny http-request GET https://127.0.0.1:${port}${shown} ` +
          '(malformed request-target: percent-encode its bytes outside printable ASCII)',
      ])
    },
  )

  // By a client in a process of its own, busy with its upload: one that shares
  // this event loop reads the answer the moment it is there. And through the
  // manager's proxy, mux and all.
  test.skipIf(Bun.which('curl') === null)(
    'in a tunnel, one with a body on its way still gets its answer',
    async () => {
      await SandboxManager.reset()
      await SandboxManager.initialize({
        network: {
          allowedDomains: ['127.0.0.1'],
          deniedDomains: [],
          tlsTerminate: { caCertPath: CA_CERT, caKeyPath: CA_KEY },
        },
        filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
      })
      const store = SandboxManager.getSandboxViolationStore()
      store.clear()
      const dir = mkdtempSync(join(tmpdir(), 'refused-upload-'))
      try {
        writeFileSync(join(dir, 'body'), Buffer.alloc(256 << 10))
        for (let n = 0; n < 8; n++) {
          const curl = await spawnAsync(
            'curl',
            [
              ...['-sk', '-m', '10', '--noproxy', ''],
              '-x',
              `http://srt:${SandboxManager.getProxyAuthToken()}@127.0.0.1:${SandboxManager.getProxyPort()}`,
              ...['--data-binary', `@${join(dir, 'body')}`],
              // As given: what curl makes of such a byte in a URL differs by
              // version.
              ...['--request-target', '/caf\u00e9'],
              `https://127.0.0.1:${port}/`,
            ],
            { encoding: 'utf8', timeout: 15_000 },
          )
          expect([curl.status, curl.stdout]).toEqual([
            0,
            'malformed request-target: percent-encode its bytes outside printable ASCII\n',
          ])
        }
        expect(store.getViolations()).toHaveLength(8)
      } finally {
        rmSync(dir, { recursive: true, force: true })
      }
    },
    60_000,
  )
})
