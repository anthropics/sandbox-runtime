import { afterAll, beforeAll, describe, expect, test } from 'bun:test'
import {
  SERVES_EMITTED_CONNECTIONS,
  testWithTls,
} from '../helpers/emitted-connections.js'
import {
  createServer as createHttpServer,
  type IncomingHttpHeaders,
  type IncomingMessage,
  type ServerResponse,
} from 'node:http'
import { createServer as createHttpsServer } from 'node:https'
import { connect, type AddressInfo, type Server } from 'node:net'
import { connect as tlsConnect } from 'node:tls'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import {
  createHttpProxyServer,
  type HttpProxyServerOptions,
} from '../../src/sandbox/http-proxy.js'
import { createMitmCA } from '../../src/sandbox/mitm-ca.js'
import { createMuxProxyServer } from '../../src/sandbox/mux-proxy.js'
import { createSocksProxyServer } from '../../src/sandbox/socks-proxy.js'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'

import { NetworkConfigSchema } from '../../src/sandbox/sandbox-config.js'
import { mintLeafCert } from '../../src/sandbox/mitm-leaf.js'
import {
  applyHeaderEdits,
  normalizeRequestTarget,
  hostMismatch,
  type FilterRequestCallback,
  type RequestDecision,
  type RequestInfo,
} from '../../src/sandbox/request-filter.js'

const FIXTURE_DIR = join(import.meta.dir, '..', 'fixtures', 'tls-terminate')
const CA_CERT = join(FIXTURE_DIR, 'ca.crt')
const CA_KEY = join(FIXTURE_DIR, 'ca.key')
const CA_PEM = readFileSync(CA_CERT, 'utf8')

type Seen = { url: string; headers: IncomingHttpHeaders; body: string }
type Reply = { status: number; headers: Record<string, string>; body: string }

const seen: Seen[] = []
let httpsUpstream: Server
let httpUpstream: Server
let httpsPort: number
let httpPort: number

function upstreamHandler(req: IncomingMessage, res: ServerResponse): void {
  let body = ''
  req.on('data', c => (body += c))
  req.on('end', () => {
    seen.push({ url: req.url ?? '', headers: req.headers, body })
    res.writeHead(200, { 'set-cookie': 'sid=up', 'x-kept': 'yes' })
    res.end('upstream ok')
  })
}

beforeAll(async () => {
  const ca = createMitmCA({ caCertPath: CA_CERT, caKeyPath: CA_KEY })
  const leaf = mintLeafCert(ca, '127.0.0.1')
  const leafOnly = leaf.certPem.match(
    /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\r?\n?/,
  )![0]
  httpsUpstream = createHttpsServer(
    { cert: leafOnly, key: leaf.keyPem },
    upstreamHandler,
  )
  httpUpstream = createHttpServer(upstreamHandler)
  await new Promise<void>(r => httpsUpstream.listen(0, '127.0.0.1', r))
  await new Promise<void>(r => httpUpstream.listen(0, '127.0.0.1', r))
  httpsPort = (httpsUpstream.address() as AddressInfo).port
  httpPort = (httpUpstream.address() as AddressInfo).port
})

afterAll(async () => {
  await new Promise<void>(r => httpsUpstream.close(() => r()))
  await new Promise<void>(r => httpUpstream.close(() => r()))
})

async function withProxy(
  filterRequest: FilterRequestCallback | undefined,
  extra: Partial<HttpProxyServerOptions>,
  fn: (port: number) => Promise<void>,
): Promise<void> {
  const proxy = createHttpProxyServer({
    filter: () => true,
    mitmCA: createMitmCA({ caCertPath: CA_CERT, caKeyPath: CA_KEY }),
    filterRequest,
    tlsTerminateUpstreamCA: CA_PEM,
    ...extra,
  })
  await new Promise<void>(r => proxy.listen(0, '127.0.0.1', () => r()))
  try {
    await fn((proxy.address() as AddressInfo).port)
  } finally {
    await new Promise<void>(r => proxy.close(() => r()))
  }
}

function parse(raw: string): Reply {
  const [head = '', ...rest] = raw.split('\r\n\r\n')
  const [statusLine = '', ...lines] = head.split('\r\n')
  const headers: Record<string, string> = {}
  for (const l of lines) {
    const i = l.indexOf(':')
    if (i > 0) headers[l.slice(0, i).toLowerCase()] = l.slice(i + 1).trim()
  }
  let body = rest.join('\r\n\r\n')
  if (/chunked/i.test(headers['transfer-encoding'] ?? '')) {
    let out = ''
    while (body.length) {
      const nl = body.indexOf('\r\n')
      const n = parseInt(body.slice(0, nl), 16)
      if (!n) break
      out += body.slice(nl + 2, nl + 2 + n)
      body = body.slice(nl + 2 + n + 2)
    }
    body = out
  }
  return { status: Number(statusLine.split(' ')[1] ?? 0), headers, body }
}

/** Raw request lines: method, target, then header lines (Host included by the caller). */
function requestText(
  method: string,
  target: string,
  headers: string[],
  body = '',
): string {
  const lines = [
    `${method} ${target} HTTP/1.1`,
    ...headers,
    'Connection: close',
  ]
  if (body) lines.push(`Content-Length: ${Buffer.byteLength(body)}`)
  return lines.join('\r\n') + '\r\n\r\n' + body
}

/** One absolute-form request to the proxy over plain HTTP. */
function viaPlain(
  proxyPort: number,
  path: string,
  headers: string[] = [],
  host?: string,
): Promise<Reply> {
  return new Promise((resolve, reject) => {
    const authority = `127.0.0.1:${httpPort}`
    const c = connect(proxyPort, '127.0.0.1', () =>
      c.write(
        requestText('GET', `http://${authority}${path}`, [
          `Host: ${host ?? authority}`,
          ...headers,
        ]),
      ),
    )
    let raw = ''
    c.on('data', d => (raw += d))
    c.on('error', reject)
    c.on('close', () => resolve(parse(raw)))
  })
}

/** CONNECT through the proxy, TLS to the terminating proxy, one request inside. */
function viaTls(
  proxyPort: number,
  path: string,
  opts: {
    headers?: string[]
    host?: string | null
    servername?: string
    method?: string
    body?: string
  } = {},
): Promise<Reply> {
  return new Promise((resolve, reject) => {
    const target = `127.0.0.1:${httpsPort}`
    const c = connect(proxyPort, '127.0.0.1', () => {
      c.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`)
    })
    c.on('error', reject)
    let head = ''
    const onData = (d: Buffer): void => {
      head += d.toString('latin1')
      if (!head.includes('\r\n\r\n')) return
      c.off('data', onData)
      if (!head.startsWith('HTTP/1.1 200')) return resolve(parse(head))
      const t = tlsConnect({
        socket: c,
        ca: CA_PEM,
        servername: opts.servername,
        checkServerIdentity: () => undefined,
        ALPNProtocols: ['http/1.1'],
      })
      let raw = ''
      t.on('secureConnect', () => {
        const hostLine =
          opts.host === null ? [] : [`Host: ${opts.host ?? target}`]
        t.write(
          requestText(
            opts.method ?? 'GET',
            path,
            [...hostLine, ...(opts.headers ?? [])],
            opts.body,
          ),
        )
      })
      t.on('data', (d: Buffer) => (raw += d))
      t.on('error', reject)
      t.on('close', () => resolve(parse(raw)))
    }
    c.on('data', onData)
  })
}

const lastSeen = (): Seen => seen[seen.length - 1]!

/**
 * Whether this runtime tells an https server which server name the client
 * sent (through SNICallback or the socket), probed on a loopback server.
 */
async function probeServerNameSupport(): Promise<boolean> {
  const ca = createMitmCA({ caCertPath: CA_CERT, caKeyPath: CA_KEY })
  const leaf = mintLeafCert(ca, 'localhost')
  let fromCallback: string | undefined
  let fromSocket: unknown
  const server = createHttpsServer(
    {
      cert: leaf.certPem,
      key: leaf.keyPem,
      SNICallback: (name, cb) => {
        fromCallback = name
        cb(null, undefined)
      },
    },
    (req, res) => {
      fromSocket = (req.socket as { servername?: unknown }).servername
      res.end()
    },
  )
  await new Promise<void>(r => server.listen(0, '127.0.0.1', r))
  const port = (server.address() as AddressInfo).port
  await new Promise<void>(resolve => {
    const t = tlsConnect(
      { port, host: '127.0.0.1', servername: 'localhost', ca: CA_PEM },
      () => t.write('GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n'),
    )
    t.on('data', () => {})
    t.on('error', () => resolve())
    t.on('close', () => resolve())
  })
  await new Promise<void>(r => server.close(() => r()))
  return fromCallback === 'localhost' || fromSocket === 'localhost'
}
const EXPOSES_SERVER_NAME = await probeServerNameSupport()
const testIfServerName = test.skipIf(
  !EXPOSES_SERVER_NAME || !SERVES_EMITTED_CONNECTIONS,
)

describe('applyHeaderEdits', () => {
  test('removals fold case and the separators - _ and .', () => {
    const h: IncomingHttpHeaders = {
      'x-api-key': 'a',
      x_api_key: 'b',
      'x.api.key': 'c',
      'X-Other': 'd',
    }
    applyHeaderEdits(h, { removeHeaders: ['X-Api-Key'] })
    expect(h).toEqual({ 'X-Other': 'd' })
  })
  test('sets replace every spelling, keep repeated values in order, and never touch framing', () => {
    const h: IncomingHttpHeaders = {
      authorization: 'client',
      host: 'h',
      'content-length': '3',
    }
    applyHeaderEdits(h, {
      setHeaders: [
        ['Authorization', 'Bearer x'],
        ['x-multi', '1'],
        ['x-multi', '2'],
        ['host', 'evil'],
        ['content-length', '999'],
        ['x-crlf', 'a\r\nInjected: 1'],
      ],
    })
    expect(h).toEqual({
      authorization: 'Bearer x',
      host: 'h',
      'content-length': '3',
      'x-multi': ['1', '2'],
    })
  })
})

describe('applyHeaderEdits: framing and grouping', () => {
  test('framing headers are never removed', () => {
    const h: IncomingHttpHeaders = {
      host: 'h',
      'content-length': '3',
      'x-a': '1',
    }
    applyHeaderEdits(h, { removeHeaders: ['Host', 'content_length', 'x-a'] })
    expect(h).toEqual({ host: 'h', 'content-length': '3' })
  })
  test('sets are grouped by folded name and emitted under the first spelling', () => {
    const h: IncomingHttpHeaders = {}
    applyHeaderEdits(h, {
      setHeaders: [
        ['x-foo', 'a'],
        ['x_foo', 'b'],
        ['X.Foo', 'c'],
      ],
    })
    expect(h).toEqual({ 'x-foo': ['a', 'b', 'c'] })
  })
})

describe('an allow decision rewrites the forwarded request', () => {
  // Every case runs a TLS-terminating proxy: skipped where none can run.
  const test = testWithTls
  const rewrite: FilterRequestCallback = async () => ({
    action: 'allow',
    removeHeaders: ['x-api-key'],
    setHeaders: [
      ['authorization', 'Bearer from-policy'],
      ['x-added', 'yes'],
    ],
  })

  test('TLS-terminated: removals and sets reach the upstream', async () => {
    await withProxy(rewrite, {}, async port => {
      const r = await viaTls(port, '/tls', {
        headers: [
          'Authorization: Bearer client',
          'X_Api_Key: k',
          'x.api.key: k',
        ],
      })
      expect(r.status).toBe(200)
      const h = lastSeen().headers
      expect(h.authorization).toBe('Bearer from-policy')
      expect(h['x-added']).toBe('yes')
      expect(
        Object.keys(h).filter(k => k.replace(/[_.]/g, '-') === 'x-api-key'),
      ).toEqual([])
    })
  }, 15_000)

  test('plain HTTP: an allow with sets is refused unless plaintextHeaderSet', async () => {
    await withProxy(rewrite, {}, async port => {
      const before = seen.length
      const r = await viaPlain(port, '/plain', [
        'Authorization: Bearer client',
        'X-Api-Key: k',
      ])
      // The sets cannot be applied in cleartext, so nothing is forwarded.
      expect(r.status).toBe(403)
      expect(seen.length).toBe(before)
    })
    await withProxy(rewrite, { plaintextHeaderSet: true }, async port => {
      await viaPlain(port, '/plain', ['Authorization: Bearer client'])
      expect(lastSeen().headers.authorization).toBe('Bearer from-policy')
      expect(lastSeen().headers['x-added']).toBe('yes')
    })
  })

  test('an allow with no edits forwards the request unchanged', async () => {
    await withProxy(
      async () => ({ action: 'allow' }),
      {},
      async port => {
        await viaPlain(port, '/unchanged', ['X-Api-Key: k'])
        expect(lastSeen().headers['x-api-key']).toBe('k')
      },
    )
  })
})

describe('a set strips every spelling of its name the client sent', () => {
  // Every case runs a TLS-terminating proxy: skipped where none can run.
  const test = testWithTls
  const setFoo: FilterRequestCallback = async () => ({
    action: 'allow',
    setHeaders: [['x-foo', 'real']],
  })
  const forged = ['x_foo: forged', 'x.foo: forged', 'X-Foo: forged']
  const fooKeys = (h: IncomingHttpHeaders): string[] =>
    Object.keys(h).filter(k => k.replace(/[_.]/g, '-') === 'x-foo')

  test('TLS-terminated: the upstream receives only the decision value', async () => {
    await withProxy(setFoo, {}, async port => {
      const r = await viaTls(port, '/foo', { headers: forged })
      expect(r.status).toBe(200)
      const h = lastSeen().headers
      expect(fooKeys(h)).toEqual(['x-foo'])
      expect(h['x-foo']).toBe('real')
    })
  }, 15_000)

  test('plain HTTP with plaintextHeaderSet: the upstream receives only the decision value', async () => {
    await withProxy(setFoo, { plaintextHeaderSet: true }, async port => {
      await viaPlain(port, '/foo', forged)
      const h = lastSeen().headers
      expect(fooKeys(h)).toEqual(['x-foo'])
      expect(h['x-foo']).toBe('real')
    })
  })

  test('plain HTTP with sets off: the request is refused, so no client spelling is forwarded', async () => {
    await withProxy(setFoo, {}, async port => {
      const before = seen.length
      const r = await viaPlain(port, '/foo', forged)
      expect(r.status).toBe(403)
      expect(seen.length).toBe(before)
    })
  })
})

describe('edits and the credential hooks, in the same order on both paths', () => {
  // Every case runs a TLS-terminating proxy: skipped where none can run.
  const test = testWithTls
  // A stand-in for the masked-credential substitution: swaps a sentinel
  // for the real value in any header, as the manager's hook does.
  const substitute = (h: IncomingHttpHeaders): void => {
    for (const [k, v] of Object.entries(h)) {
      if (typeof v === 'string') h[k] = v.replace('SENTINEL', 'real-secret')
    }
  }
  const setSentinel: FilterRequestCallback = async () => ({
    action: 'allow',
    setHeaders: [['authorization', 'Bearer SENTINEL']],
  })

  test('TLS-terminated: a value the decision sets is substituted by the credential hook', async () => {
    await withProxy(setSentinel, { mutateHeaders: substitute }, async port => {
      await viaTls(port, '/cred')
      expect(lastSeen().headers.authorization).toBe('Bearer real-secret')
    })
  }, 15_000)

  test('plain HTTP (sets and plaintext substitution on): the same', async () => {
    await withProxy(
      setSentinel,
      { plaintextHeaderSet: true, mutateHeadersPlaintext: substitute },
      async port => {
        await viaPlain(port, '/cred')
        expect(lastSeen().headers.authorization).toBe('Bearer real-secret')
      },
    )
  })

  test('removing a header the credential hook would fill leaves the hook free to fill it', async () => {
    await withProxy(
      async () => ({ action: 'allow', removeHeaders: ['authorization'] }),
      {
        mutateHeaders: h => {
          h.authorization = 'Bearer injected-after-edits'
        },
      },
      async port => {
        await viaTls(port, '/cred', {
          headers: ['Authorization: Bearer client'],
        })
        expect(lastSeen().headers.authorization).toBe(
          'Bearer injected-after-edits',
        )
      },
    )
  }, 15_000)

  test('a multi-value set reaches the upstream as repeated values', async () => {
    await withProxy(
      async () => ({
        action: 'allow',
        setHeaders: [
          ['x-multi', 'one'],
          ['x_multi', 'two'],
        ],
      }),
      {},
      async port => {
        await viaTls(port, '/multi')
        expect(lastSeen().headers['x-multi']).toBe('one, two')
      },
    )
  }, 15_000)
})

describe('a deny decision chooses its status', () => {
  // Every case runs a TLS-terminating proxy: skipped where none can run.
  const test = testWithTls
  test('the status and reason reach the client, and nothing is dialled', async () => {
    const before = seen.length
    await withProxy(
      async () => ({ action: 'deny', status: 451, reason: 'not here' }),
      {},
      async port => {
        const tls = await viaTls(port, '/denied')
        expect(tls.status).toBe(451)
        expect(tls.body).toContain('not here')
        expect(tls.headers['x-proxy-error']).toBe('blocked-by-sandbox-runtime')
        const plain = await viaPlain(port, '/denied')
        expect(plain.status).toBe(451)
      },
    )
    expect(seen.length).toBe(before)
  }, 15_000)

  test('a status outside 400-599, or none, answers 403', async () => {
    for (const status of [200, 302, 600, 450.5, undefined]) {
      await withProxy(
        async () => ({ action: 'deny', status }),
        {},
        async port => {
          expect((await viaPlain(port, '/denied')).status).toBe(403)
        },
      )
    }
  })
})

describe('TRACE is refused before filterRequest is asked', () => {
  // Every case runs a TLS-terminating proxy: skipped where none can run.
  const test = testWithTls
  // Its response echoes the request, so a header the decision sets would
  // come back to the client. (TRACK is refused too, but Node's and Bun's
  // HTTP parsers answer it 400 before the proxy sees it.)
  const tracePlain = (port: number): Promise<Reply> =>
    new Promise((resolve, reject) => {
      const authority = `127.0.0.1:${httpPort}`
      const c = connect(port, '127.0.0.1', () =>
        c.write(
          requestText('TRACE', `http://${authority}/echo`, [
            `Host: ${authority}`,
          ]),
        ),
      )
      let raw = ''
      c.on('data', d => (raw += d))
      c.on('error', reject)
      c.on('close', () => resolve(parse(raw)))
    })

  test('405 on plain HTTP and inside a terminated tunnel, and nothing is dialled', async () => {
    let asked = 0
    const before = seen.length
    await withProxy(
      async () => {
        asked++
        return { action: 'allow', setHeaders: [['authorization', 'secret']] }
      },
      { plaintextHeaderSet: true },
      async port => {
        const tls = await viaTls(port, '/echo', { method: 'TRACE' })
        expect(tls.status).toBe(405)
        expect(tls.body).toContain('the TRACE method is not forwarded')
        expect(tls.headers['x-proxy-error']).toBe('blocked-by-sandbox-runtime')
        const plain = await tracePlain(port)
        expect(plain.status).toBe(405)
        expect(plain.body).toContain('the TRACE method is not forwarded')
      },
    )
    expect(asked).toBe(0)
    expect(seen.length).toBe(before)
  }, 15_000)

  test('without filterRequest, TRACE is forwarded as before', async () => {
    const before = seen.length
    await withProxy(undefined, {}, async port => {
      const tls = await viaTls(port, '/echo', { method: 'TRACE' })
      expect(tls.status).toBe(200)
      expect((await tracePlain(port)).status).toBe(200)
    })
    expect(seen.length).toBe(before + 2)
  }, 15_000)
})

describe('a malformed decision denies', () => {
  // Every case runs a TLS-terminating proxy: skipped where none can run.
  const test = testWithTls
  const malformed: Array<[string, unknown]> = [
    ['null', null],
    ['an unknown action', { action: 'maybe' }],
    ['setHeaders that is not an array', { action: 'allow', setHeaders: 'ab' }],
    ['a set entry with no value', { action: 'allow', setHeaders: [['x-foo']] }],
    [
      'a set name that is not a string',
      { action: 'allow', setHeaders: [[7, 'v']] },
    ],
    [
      'a set name that is not a token',
      { action: 'allow', setHeaders: [['x foo', 'v']] },
    ],
    ['an empty set name', { action: 'allow', setHeaders: [['', 'v']] }],
    [
      'a set value with a control character',
      { action: 'allow', setHeaders: [['x-foo', 'a\x01b']] },
    ],
    [
      'a set value with a character above U+00FF',
      { action: 'allow', setHeaders: [['x-foo', 'a\u2014b']] },
    ],
    [
      'a set value with CR LF',
      { action: 'allow', setHeaders: [['x-foo', 'a\r\nInjected: 1']] },
    ],
    [
      'removeHeaders that is not an array',
      { action: 'allow', removeHeaders: 'x-foo' },
    ],
    [
      'a removal that is not a string',
      { action: 'allow', removeHeaders: [null] },
    ],
    ['a status that is not a number', { action: 'deny', status: '451' }],
  ]
  for (const [label, decision] of malformed) {
    test(`${label}: 403 on both paths and nothing is dialled`, async () => {
      const before = seen.length
      const filter: FilterRequestCallback = async () =>
        decision as RequestDecision
      await withProxy(filter, { plaintextHeaderSet: true }, async port => {
        const tls = await viaTls(port, '/malformed')
        expect(tls.status).toBe(403)
        expect(tls.body).toContain('malformed filterRequest decision')
        const plain = await viaPlain(port, '/malformed')
        expect(plain.status).toBe(403)
        expect(plain.body).toContain('malformed filterRequest decision')
      })
      expect(seen.length).toBe(before)
    }, 15_000)
  }

  test('a tab inside a set value is allowed', async () => {
    await withProxy(
      async () => ({ action: 'allow', setHeaders: [['x-tab', 'a\tb']] }),
      {},
      async port => {
        expect((await viaTls(port, '/tab')).status).toBe(200)
        expect(lastSeen().headers['x-tab']).toBe('a\tb')
      },
    )
  }, 15_000)

  test('TLS-terminated: a failure after the allow answers 502 instead of hanging', async () => {
    await withProxy(
      async () => ({ action: 'allow' }),
      {
        mutateHeaders: () => {
          throw new Error('hook failed')
        },
      },
      async port => {
        const reply = await viaTls(port, '/hook-throws')
        expect(reply.status).toBe(502)
      },
    )
  }, 15_000)
})

describe('the callback gets the request details it cannot recover from the Request', () => {
  // Every case runs a TLS-terminating proxy: skipped where none can run.
  const test = testWithTls
  test('TLS-terminated: server name, CONNECT target, request-target and raw headers', async () => {
    let got: RequestInfo | undefined
    await withProxy(
      async (_req, info) => {
        got = info
        return { action: 'deny', status: 403 }
      },
      {},
      async port => {
        await viaTls(port, '/a/b?x=1', {
          servername: 'localhost',
          headers: ['X_Spelled: 1'],
        })
      },
    )
    // Some runtimes expose no server name to an https server at all.
    expect(got?.sni).toBe(EXPOSES_SERVER_NAME ? 'localhost' : undefined)
    expect(got?.target).toEqual({ host: '127.0.0.1', port: httpsPort })
    expect(got?.requestTarget).toBe('/a/b?x=1')
    // Some runtimes lower-case rawHeaders names; the spelling of the
    // separators is what matters.
    expect(got?.rawHeaders?.map(h => h.toLowerCase())).toEqual(
      expect.arrayContaining(['x_spelled', '1']),
    )
  }, 15_000)

  test('plain HTTP: target and the origin form of the absolute request-target', async () => {
    let got: RequestInfo | undefined
    await withProxy(
      async (_req, info) => {
        got = info
        return { action: 'deny', status: 403 }
      },
      {},
      async port => {
        await viaPlain(port, '/c?y=2', ['X_Spelled: 2'])
      },
    )
    expect(got?.sni).toBeUndefined()
    expect(got?.target).toEqual({ host: '127.0.0.1', port: httpPort })
    expect(got?.requestTarget).toBe('/c?y=2')
    expect(got?.rawHeaders?.map(h => h.toLowerCase())).toEqual(
      expect.arrayContaining(['x_spelled', '2']),
    )
  })
})

describe('normalizeRequestTarget', () => {
  test.each([
    ['/a/b?x=1', '/a/b?x=1'],
    ['/public/%2e%2e/admin', '/admin'],
    ['//admin', '/admin'],
    ['///admin?q=1', '/admin?q=1'],
    ['//public/../admin', '/admin'],
    ['https://other.test//x/../y?z', '/y?z'],
    ['http://h.test', '/'],
  ])('%p becomes %p', (raw, want) => {
    expect(normalizeRequestTarget(raw, 'GET')).toBe(want)
    // Normalizing twice changes nothing.
    expect(normalizeRequestTarget(want, 'GET')).toBe(want)
  })
  test.each([
    ['@other.test/x', 'GET'],
    ['other.test/x', 'GET'],
    ['ftp://other.test/x', 'GET'],
    ['*', 'GET'],
    ['', 'GET'],
  ])('%p (%s) is refused', (raw, method) => {
    expect(normalizeRequestTarget(raw, method)).toBeUndefined()
  })
  test('* is accepted for OPTIONS', () => {
    expect(normalizeRequestTarget('*', 'OPTIONS')).toBe('*')
  })
})

describe('the request-target the callback sees is the one forwarded', () => {
  // Every case runs a TLS-terminating proxy: skipped where none can run.
  const test = testWithTls
  // Each spelling would pass a naive "/public/" prefix rule, or dodge a
  // "/admin" deny rule, if the callback saw it raw while the proxy (or the
  // runtime's HTTP client) forwarded a normalized form.
  const spellings = [
    '/public/%2e%2e/admin',
    '/public/%2E%2E/admin',
    '/public/../admin',
    '/public/./../admin?q=1',
    '/public/..%2fadmin',
    '/public/%2fadmin',
    '//admin',
    '///admin?q=1',
    '//public/../admin',
  ]
  const recordTarget =
    (sink: { got?: string }): FilterRequestCallback =>
    async (_req, info) => {
      sink.got = info?.requestTarget
      return { action: 'allow' }
    }
  for (const [label, send] of [
    ['plain HTTP', (port: number, path: string) => viaPlain(port, path)],
    ['TLS-terminated', (port: number, path: string) => viaTls(port, path)],
  ] as const) {
    for (const spelling of spellings) {
      test(`${label}: ${spelling}`, async () => {
        const sink: { got?: string } = {}
        const before = seen.length
        await withProxy(recordTarget(sink), {}, async port => {
          expect((await send(port, spelling)).status).toBe(200)
        })
        expect(seen.length).toBe(before + 1)
        expect(sink.got).toBe(lastSeen().url)
      }, 15_000)
    }
    test(`${label}: dot segments and leading slashes are normalized before the callback sees them`, async () => {
      const sink: { got?: string } = {}
      await withProxy(recordTarget(sink), {}, async port => {
        await send(port, '/public/%2e%2e/admin')
        expect(sink.got).toBe('/admin')
        expect(lastSeen().url).toBe('/admin')
        await send(port, '//admin')
        expect(sink.got).toBe('/admin')
        expect(lastSeen().url).toBe('/admin')
      })
    }, 15_000)
  }
})

describe('a request-target of any other shape is refused with 400', () => {
  // Every case runs a TLS-terminating proxy: skipped where none can run.
  const test = testWithTls
  test('TLS-terminated: @host, a bare name, a non-http scheme and * without OPTIONS', async () => {
    let asked = 0
    const before = seen.length
    await withProxy(
      async () => {
        asked++
        return { action: 'allow' }
      },
      {},
      async port => {
        for (const [method, target] of [
          ['GET', '@other.test/x'],
          ['GET', 'other.test/x'],
          ['GET', 'ftp://127.0.0.1/x'],
          ['GET', '*'],
        ]) {
          const reply = await viaTls(port, target!, { method })
          // A runtime's HTTP parser may refuse some of these itself and
          // close the connection without a response (status 0).
          expect([0, 400]).toContain(reply.status)
        }
      },
    )
    expect(asked).toBe(0)
    expect(seen.length).toBe(before)
  }, 15_000)

  test('plain HTTP: a non-http absolute URI', async () => {
    let asked = 0
    await withProxy(
      async () => {
        asked++
        return { action: 'allow' }
      },
      {},
      async port => {
        const reply = await new Promise<Reply>((resolve, reject) => {
          const authority = `127.0.0.1:${httpPort}`
          const c = connect(port, '127.0.0.1', () =>
            c.write(
              requestText('GET', `ftp://${authority}/x`, [
                `Host: ${authority}`,
              ]),
            ),
          )
          let raw = ''
          c.on('data', d => (raw += d))
          c.on('error', reject)
          c.on('close', () => resolve(parse(raw)))
        })
        // Some runtimes' parsers refuse it themselves (status 0).
        expect([0, 400]).toContain(reply.status)
      },
    )
    expect(asked).toBe(0)
  })
})

describe('an allow decision can observe the upstream response', () => {
  // Every case runs a TLS-terminating proxy: skipped where none can run.
  const test = testWithTls
  test('onResponse sees the status and headers before the client does, on both paths', async () => {
    const got: Array<{ status: number; headers: IncomingHttpHeaders }> = []
    await withProxy(
      async () => ({
        action: 'allow',
        onResponse: (status, headers) => {
          got.push({ status, headers })
        },
      }),
      {},
      async port => {
        expect((await viaTls(port, '/observed')).status).toBe(200)
        expect((await viaPlain(port, '/observed')).status).toBe(200)
      },
    )
    expect(got.map(g => g.status)).toEqual([200, 200])
    for (const g of got) {
      expect(g.headers['x-kept']).toBe('yes')
      expect(g.headers['set-cookie']).toEqual(['sid=up'])
      expect(g.headers.connection).toBeUndefined()
    }
  }, 15_000)

  test('an onResponse that throws does not disturb the response', async () => {
    await withProxy(
      async () => ({
        action: 'allow',
        onResponse: () => {
          throw new Error('observer failed')
        },
      }),
      {},
      async port => {
        const r = await viaPlain(port, '/observed')
        expect(r.status).toBe(200)
        expect(r.body).toBe('upstream ok')
        const t = await viaTls(port, '/observed')
        expect(t.status).toBe(200)
        expect(t.body).toBe('upstream ok')
      },
    )
  }, 15_000)

  test('an async onResponse that rejects is contained, on both paths', async () => {
    const unhandled: unknown[] = []
    const onUnhandled = (reason: unknown): void => {
      unhandled.push(reason)
    }
    process.on('unhandledRejection', onUnhandled)
    try {
      let calls = 0
      await withProxy(
        async () => ({
          action: 'allow',
          onResponse: async () => {
            calls++
            throw new Error('async observer failed')
          },
        }),
        {},
        async port => {
          expect((await viaTls(port, '/observed')).status).toBe(200)
          expect((await viaPlain(port, '/observed')).status).toBe(200)
        },
      )
      await new Promise(r => setTimeout(r, 50))
      expect(calls).toBe(2)
      expect(unhandled).toEqual([])
    } finally {
      process.off('unhandledRejection', onUnhandled)
    }
  }, 15_000)

  test('onResponse gets a copy: changing it does not change what the client receives', async () => {
    await withProxy(
      async () => ({
        action: 'allow',
        onResponse: (_status, headers) => {
          ;(headers['set-cookie'] as string[]).push('injected=1')
          headers['x-kept'] = 'changed'
        },
      }),
      {},
      async port => {
        for (const reply of [
          await viaTls(port, '/observed'),
          await viaPlain(port, '/observed'),
        ]) {
          expect(reply.headers['set-cookie']).toBe('sid=up')
          expect(reply.headers['x-kept']).toBe('yes')
        }
      },
    )
  }, 15_000)

  test('an onResponse that is not a function denies', async () => {
    await withProxy(
      async () =>
        ({ action: 'allow', onResponse: 'nope' }) as unknown as RequestDecision,
      {},
      async port => {
        expect((await viaTls(port, '/observed')).status).toBe(403)
        expect((await viaPlain(port, '/observed')).status).toBe(403)
      },
    )
  }, 15_000)
})

describe('stripResponseHeaders', () => {
  // Every case runs a TLS-terminating proxy: skipped where none can run.
  const test = testWithTls
  test('keeps the listed response headers from the client on both paths', async () => {
    let observed: IncomingHttpHeaders | undefined
    await withProxy(
      async () => ({ action: 'allow', onResponse: (_s, h) => (observed = h) }),
      { stripResponseHeaders: ['Set-Cookie'] },
      async port => {
        for (const r of [
          await viaTls(port, '/strip'),
          await viaPlain(port, '/strip'),
        ]) {
          expect(r.status).toBe(200)
          expect(r.headers['set-cookie']).toBeUndefined()
          expect(r.headers['x-kept']).toBe('yes')
        }
      },
    )
    // onResponse sees the upstream's headers before stripping.
    expect(observed?.['set-cookie']).toEqual(['sid=up'])
  }, 15_000)
})

/** CONNECT to the plain upstream, then speak plain HTTP inside the tunnel. */
function plainInsideConnect(proxyPort: number): Promise<string> {
  return new Promise(resolve => {
    const target = `127.0.0.1:${httpPort}`
    const c = connect(proxyPort, '127.0.0.1', () =>
      c.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`),
    )
    let raw = ''
    let sent = false
    c.on('data', d => {
      raw += d
      if (!sent && raw.startsWith('HTTP/1.1 200') && raw.includes('\r\n\r\n')) {
        sent = true
        c.write(requestText('GET', '/tunnelled', [`Host: ${target}`]))
      }
    })
    c.on('error', () => resolve(raw))
    c.on('close', () => resolve(raw))
  })
}

describe('refuseOpaqueTunnels', () => {
  // Every case runs a TLS-terminating proxy: skipped where none can run.
  const test = testWithTls
  const allowAll: FilterRequestCallback = async () => ({ action: 'allow' })

  test('by default a non-TLS CONNECT is tunnelled past filterRequest', async () => {
    let asked = 0
    const before = seen.length
    await withProxy(
      async () => {
        asked++
        return { action: 'allow' }
      },
      {},
      async port => {
        const raw = await plainInsideConnect(port)
        expect(raw).toContain('upstream ok')
      },
    )
    expect(asked).toBe(0)
    expect(seen.length).toBe(before + 1)
  })

  test('with it, a non-TLS CONNECT is closed and nothing reaches the upstream', async () => {
    const before = seen.length
    await withProxy(allowAll, { refuseOpaqueTunnels: true }, async port => {
      const raw = await plainInsideConnect(port)
      expect(raw).not.toContain('upstream ok')
    })
    expect(seen.length).toBe(before)
  })

  test('with it and no mitmCA, a CONNECT is refused with 403', async () => {
    const proxy = createHttpProxyServer({
      filter: () => true,
      refuseOpaqueTunnels: true,
    })
    await new Promise<void>(r => proxy.listen(0, '127.0.0.1', () => r()))
    const port = (proxy.address() as AddressInfo).port
    const raw = await plainInsideConnect(port)
    await new Promise<void>(r => proxy.close(() => r()))
    expect(raw).toStartWith('HTTP/1.1 403')
  })

  test('with it, a CONNECT to a host shouldTerminateTLS exempts is refused with 403', async () => {
    const refused: string[] = []
    await withProxy(
      allowAll,
      {
        refuseOpaqueTunnels: true,
        shouldTerminateTLS: () => false,
        onFilterRequestDenied: ({ method, url }) =>
          refused.push(`${method} ${url}`),
      },
      async port => {
        expect(await plainInsideConnect(port)).toStartWith('HTTP/1.1 403')
      },
    )
    expect(refused).toEqual([`CONNECT 127.0.0.1:${httpPort}`])
  })
})

describe('refuseOpaqueTunnels on the shared HTTP and SOCKS port', () => {
  // Every case runs a TLS-terminating proxy: skipped where none can run.
  const test = testWithTls
  const allowAll: FilterRequestCallback = async () => ({ action: 'allow' })

  /** The manager's front end: one port, sniffed into HTTP or SOCKS. */
  async function withMux(
    refuse: boolean,
    fn: (port: number, refusals: string[]) => Promise<void>,
  ): Promise<void> {
    const refusals: string[] = []
    const httpServer = createHttpProxyServer({
      filter: () => true,
      mitmCA: createMitmCA({ caCertPath: CA_CERT, caKeyPath: CA_KEY }),
      filterRequest: allowAll,
      tlsTerminateUpstreamCA: CA_PEM,
      refuseOpaqueTunnels: refuse,
      onFilterRequestDenied: ({ method, url }) =>
        refusals.push(`http ${method} ${url}`),
    })
    const socks = createSocksProxyServer({
      filter: () => true,
      refuseOpaqueTunnels: refuse,
      onTunnelRefused: (port, host) => refusals.push(`socks ${host}:${port}`),
    })
    const mux = createMuxProxyServer({
      httpServer,
      handleSocksConnection: s => socks.handleConnection(s),
    })
    await mux.listenHttpBackend()
    await new Promise<void>(r => mux.server.listen(0, '127.0.0.1', () => r()))
    try {
      await fn(mux.getPort()!, refusals)
    } finally {
      await socks.close()
      await mux.close()
    }
  }

  /** Everything the proxy sends back, until it closes or 3 s pass. */
  function exchange(
    port: number,
    onConnect: (c: ReturnType<typeof connect>) => void,
    onData?: (c: ReturnType<typeof connect>, all: Buffer) => void,
  ): Promise<Buffer> {
    return new Promise(resolve => {
      const chunks: Buffer[] = []
      const c = connect(port, '127.0.0.1', () => onConnect(c))
      const done = (): void => {
        c.destroy()
        resolve(Buffer.concat(chunks))
      }
      c.on('data', d => {
        chunks.push(d)
        onData?.(c, Buffer.concat(chunks))
      })
      c.on('error', done)
      c.on('close', done)
      setTimeout(done, 3_000).unref()
    })
  }

  /** SOCKS5, no auth, CONNECT 127.0.0.1:httpPort, then a GET if granted. */
  function socksConnect(port: number): Promise<Buffer> {
    let step = 0
    return exchange(
      port,
      c => c.write(Buffer.from([0x05, 0x01, 0x00])),
      (c, all) => {
        if (step === 0 && all.length >= 2) {
          step = 1
          const p = Buffer.alloc(2)
          p.writeUInt16BE(httpPort)
          c.write(
            Buffer.concat([
              Buffer.from([0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1]),
              p,
            ]),
          )
        } else if (step === 1 && all.length >= 12 && all[3] === 0x00) {
          step = 2
          const target = `127.0.0.1:${httpPort}`
          c.write(requestText('GET', '/via-socks', [`Host: ${target}`]))
        }
      },
    )
  }

  test('without it, SOCKS tunnels to an allowed host past filterRequest', async () => {
    const before = seen.length
    await withMux(false, async port => {
      const reply = await socksConnect(port)
      expect(reply[3]).toBe(0x00)
      expect(reply.toString('latin1')).toContain('upstream ok')
    })
    expect(seen.length).toBe(before + 1)
  })

  test('with it, SOCKS CONNECT to an allowed host is refused at the handshake', async () => {
    const before = seen.length
    await withMux(true, async (port, refusals) => {
      const reply = await socksConnect(port)
      // Method select [5, 0], then the CONNECT reply: VER 5, REP 1.
      expect([...reply.subarray(0, 4)]).toEqual([0x05, 0x00, 0x05, 0x01])
      expect(reply.length).toBe(12)
      expect(refusals).toEqual([`socks 127.0.0.1:${httpPort}`])
    })
    expect(seen.length).toBe(before)
  })

  test('with it, an HTTP CONNECT carrying no TLS is still refused', async () => {
    const before = seen.length
    await withMux(true, async (port, refusals) => {
      const raw = await plainInsideConnect(port)
      expect(raw).not.toContain('upstream ok')
      expect(refusals).toEqual([`http CONNECT 127.0.0.1:${httpPort}`])
    })
    expect(seen.length).toBe(before)
  })

  test('with it, a connection that starts as SOCKS and then speaks HTTP gets nowhere', async () => {
    const before = seen.length
    await withMux(true, async port => {
      const target = `127.0.0.1:${httpPort}`
      const reply = await exchange(port, c =>
        c.write(
          Buffer.concat([
            Buffer.from([0x05]),
            Buffer.from(
              `CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n` +
                requestText('GET', '/steered', [`Host: ${target}`]),
            ),
          ]),
        ),
      )
      expect(reply.toString('latin1')).not.toContain('HTTP/1.1 200')
      expect(reply.toString('latin1')).not.toContain('upstream ok')
    })
    expect(seen.length).toBe(before)
  })

  test('with it, a CONNECT tunnel that then speaks SOCKS gets nowhere', async () => {
    const before = seen.length
    await withMux(true, async port => {
      const target = `127.0.0.1:${httpPort}`
      let sent = false
      const reply = await exchange(
        port,
        c => c.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`),
        (c, all) => {
          if (!sent && all.includes('\r\n\r\n')) {
            sent = true
            c.write(Buffer.from([0x05, 0x01, 0x00]))
          }
        },
      )
      expect(reply.toString('latin1')).toStartWith('HTTP/1.1 200')
      expect(reply.toString('latin1')).not.toContain('\x05\x00')
    })
    expect(seen.length).toBe(before)
  })
})

describe('hostMismatch: the Host and server-name shapes that name the target', () => {
  const t = { hostname: 'api.example.test', port: 443, defaultPort: 443 }
  test.each([
    [['api.example.test'], undefined],
    [['API.Example.Test'], undefined],
    [['api.example.test:443'], undefined],
    [[], undefined],
    [['api.example.test'], 'API.example.test'],
  ] as const)('accepts Host %p with server name %p', (host, sni) => {
    expect(hostMismatch([...host], sni, t)).toBeUndefined()
  })
  test('no port names the target only on the default port', () => {
    const on8443 = { hostname: 'h.example.test', port: 8443, defaultPort: 443 }
    expect(hostMismatch(['h.example.test'], undefined, on8443)).toMatch(
      /Host header/,
    )
    expect(
      hostMismatch(['h.example.test:8443'], undefined, on8443),
    ).toBeUndefined()
  })
  test('an absolute-form authority must name the target too', () => {
    expect(
      hostMismatch(['api.example.test'], undefined, t, 'api.example.test'),
    ).toBeUndefined()
    expect(
      hostMismatch(['api.example.test'], undefined, t, 'api.example.test:443'),
    ).toBeUndefined()
    expect(
      hostMismatch(['api.example.test'], undefined, t, 'other.example.test'),
    ).toMatch(/request-target authority/)
    expect(hostMismatch(['api.example.test'], undefined, t, '')).toMatch(
      /request-target authority/,
    )
  })
  test.each([
    [['other.example.test'], undefined, /Host header/],
    [['api.example.test:8443'], undefined, /Host header/],
    [['api.example.test.'], undefined, /Host header/],
    [['api.example.test:'], undefined, /Host header/],
    [['[api.example.test]'], undefined, /Host header/],
    [[''], undefined, /Host header/],
    [['api.example.test:0443'], undefined, /Host header/],
    [['a:b:c'], undefined, /Host header/],
    [['api.example.test', 'api.example.test'], undefined, /more than one/],
    [['api.example.test'], 'other.example.test', /server name/],
    [['api.example.test'], 'api.example.test.', /server name/],
  ] as const)('refuses Host %p with server name %p', (host, sni, why) => {
    expect(hostMismatch([...host], sni, t)).toMatch(why)
  })
  test('brackets only around an IPv6 address', () => {
    const v6 = { hostname: '::1', port: 8080, defaultPort: 8080 }
    expect(hostMismatch(['[::1]:8080'], undefined, v6)).toBeUndefined()
    expect(hostMismatch(['[::1]'], undefined, v6)).toBeUndefined()
    expect(hostMismatch(['[::1]:80'], undefined, v6)).toMatch(/Host header/)
    expect(hostMismatch(['::1'], undefined, v6)).toMatch(/Host header/)
  })
})

describe('requireHostMatch', () => {
  // Every case runs a TLS-terminating proxy: skipped where none can run.
  const test = testWithTls
  let asked = 0
  const counting: FilterRequestCallback = async () => {
    asked++
    return { action: 'allow' }
  }

  test('TLS-terminated: a Host of another host is answered 421 before filterRequest is asked', async () => {
    asked = 0
    const before = seen.length
    await withProxy(counting, { requireHostMatch: true }, async port => {
      expect(
        (await viaTls(port, '/m', { host: 'other.example.test' })).status,
      ).toBe(421)
      expect(
        (await viaTls(port, '/m', { host: `127.0.0.1:${httpsPort + 1}` }))
          .status,
      ).toBe(421)
      expect((await viaTls(port, '/m')).status).toBe(200)
    })
    expect(asked).toBe(1)
    expect(seen.length).toBe(before + 1)
  }, 15_000)

  testIfServerName(
    'TLS-terminated: a server name of another host is answered 421',
    async () => {
      asked = 0
      await withProxy(counting, { requireHostMatch: true }, async port => {
        const r = await viaTls(port, '/m', { servername: 'evil.example.test' })
        expect(r.status).toBe(421)
      })
      expect(asked).toBe(0)
    },
    15_000,
  )

  test('TLS-terminated: an absolute-form request-target naming another host is answered 421', async () => {
    asked = 0
    await withProxy(counting, { requireHostMatch: true }, async port => {
      const target = `127.0.0.1:${httpsPort}`
      expect(
        (await viaTls(port, 'https://other.example.test/m', { host: target }))
          .status,
      ).toBe(421)
      expect(
        (await viaTls(port, `https://${target}/m`, { host: target })).status,
      ).toBe(200)
    })
    expect(asked).toBe(1)
  }, 15_000)

  test('421 refusals are reported like filterRequest denials', async () => {
    const denied: string[] = []
    await withProxy(
      counting,
      {
        requireHostMatch: true,
        onFilterRequestDenied: ({ reason }) => denied.push(reason),
      },
      async port => {
        await viaTls(port, '/m', { host: 'other.example.test' })
        await viaPlain(port, '/m', [], 'other.example.test')
      },
    )
    expect(denied).toEqual([
      'Host header does not match the request target',
      'Host header does not match the request target',
    ])
  }, 15_000)

  test('plain HTTP: an IPv6 target matches only its bracketed Host', async () => {
    const denyAll: FilterRequestCallback = async () => ({ action: 'deny' })
    await withProxy(denyAll, { requireHostMatch: true }, async port => {
      const send = (host: string): Promise<Reply> =>
        new Promise((resolve, reject) => {
          const c = connect(port, '127.0.0.1', () =>
            c.write(requestText('GET', 'http://[::1]:1/m', [`Host: ${host}`])),
          )
          let raw = ''
          c.on('data', d => (raw += d))
          c.on('error', reject)
          c.on('close', () => resolve(parse(raw)))
        })
      expect((await send('::1')).status).toBe(421)
      expect((await send('[::1]')).status).toBe(421)
      // Names the target, so it reaches filterRequest, which denies.
      expect((await send('[::1]:1')).status).toBe(403)
    })
  }, 15_000)

  test('plain HTTP: a Host of another host is answered 421; without the option it is asked', async () => {
    asked = 0
    await withProxy(counting, { requireHostMatch: true }, async port => {
      expect(
        (await viaPlain(port, '/m', [], 'other.example.test')).status,
      ).toBe(421)
    })
    expect(asked).toBe(0)
    await withProxy(counting, {}, async port => {
      expect(
        (await viaPlain(port, '/m', [], 'other.example.test')).status,
      ).toBe(200)
    })
    expect(asked).toBe(1)
  })
})

describe('network config', () => {
  test('accepts the rewriting options and rejects bad values', () => {
    const base = { allowedDomains: [], deniedDomains: [] }
    const ok = NetworkConfigSchema.safeParse({
      ...base,
      allowPlaintextHeaderSet: false,
      stripResponseHeaders: ['set-cookie'],
      refuseOpaqueTunnels: true,
      requireHostMatch: true,
    })
    expect(ok.success).toBe(true)
    expect(
      NetworkConfigSchema.safeParse({ ...base, stripResponseHeaders: [''] })
        .success,
    ).toBe(false)
    expect(
      NetworkConfigSchema.safeParse({ ...base, requireHostMatch: 'yes' })
        .success,
    ).toBe(false)
  })
})

describe('the manager applies refuseOpaqueTunnels to the SOCKS side of its port', () => {
  afterAll(async () => {
    await SandboxManager.reset()
  })

  test('an authenticated SOCKS CONNECT to an allowed host is refused at the handshake', async () => {
    await SandboxManager.initialize({
      network: {
        allowedDomains: ['allowed.test'],
        deniedDomains: [],
        refuseOpaqueTunnels: true,
      },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    })
    const port = SandboxManager.getProxyPort()!
    const token = Buffer.from(SandboxManager.getProxyAuthToken()!)
    const host = Buffer.from('allowed.test')
    const reply = await new Promise<Buffer>(resolve => {
      const chunks: Buffer[] = []
      const c = connect(port, '127.0.0.1', () => {
        c.write(Buffer.from([0x05, 0x01, 0x02]))
        c.write(
          Buffer.concat([
            Buffer.from([0x01, 3]),
            Buffer.from('srt'),
            Buffer.from([token.length]),
            token,
          ]),
        )
        c.write(
          Buffer.concat([
            Buffer.from([0x05, 0x01, 0x00, 0x03, host.length]),
            host,
            Buffer.from([0x01, 0xbb]),
          ]),
        )
      })
      const done = (): void => {
        c.destroy()
        resolve(Buffer.concat(chunks))
      }
      c.on('data', d => chunks.push(d))
      c.on('error', done)
      c.on('close', done)
      setTimeout(done, 4_000).unref()
    })
    // Method select [5, 2], auth status [1, 0], CONNECT reply VER 5 REP 1.
    expect([...reply.subarray(0, 6)]).toEqual([5, 2, 1, 0, 5, 1])
  }, 15_000)
})
