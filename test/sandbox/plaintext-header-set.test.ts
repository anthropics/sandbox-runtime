import { afterAll, beforeAll, describe, expect, test } from 'bun:test'
import {
  createServer,
  request,
  type IncomingHttpHeaders,
  type Server,
} from 'node:http'
import type { AddressInfo } from 'node:net'
import {
  createHttpProxyServer,
  type HttpProxyServerOptions,
} from '../../src/sandbox/http-proxy.js'
import type {
  RequestDecision,
  RequestInfo,
} from '../../src/sandbox/request-filter.js'

// Header sets on the plain-HTTP path: an allow decision whose setHeaders
// cannot be applied (cleartext, opt-in off) must be refused, never forwarded
// without them.

const received: IncomingHttpHeaders[] = []
let upstream: Server
let upstreamPort: number

beforeAll(async () => {
  upstream = createServer((req, res) => {
    received.push(req.headers)
    res.end('ok')
  })
  await new Promise<void>(r => upstream.listen(0, '127.0.0.1', () => r()))
  upstreamPort = (upstream.address() as AddressInfo).port
})

afterAll(async () => {
  await new Promise<void>(r => upstream.close(() => r()))
})

type Reply = { status: number; body: string }

/** One absolute-form GET through a proxy built with the given decision. */
async function getThroughProxy(
  decision: RequestDecision,
  extra: Partial<HttpProxyServerOptions> = {},
  onInfo?: (info: RequestInfo | undefined) => void,
): Promise<Reply> {
  const proxy = createHttpProxyServer({
    filter: () => true,
    filterRequest: async (_req, info) => {
      onInfo?.(info)
      return decision
    },
    ...extra,
  })
  await new Promise<void>(r => proxy.listen(0, '127.0.0.1', () => r()))
  const proxyPort = (proxy.address() as AddressInfo).port
  try {
    return await new Promise<Reply>((resolve, reject) => {
      const req = request(
        {
          host: '127.0.0.1',
          port: proxyPort,
          path: `http://127.0.0.1:${upstreamPort}/resource`,
          headers: {
            host: `127.0.0.1:${upstreamPort}`,
            authorization: 'Bearer from-client',
            'x-api-key': 'client-key',
            connection: 'close',
          },
        },
        res => {
          let body = ''
          res.setEncoding('utf8')
          res.on('data', chunk => (body += chunk))
          res.on('end', () => resolve({ status: res.statusCode ?? 0, body }))
        },
      )
      req.on('error', reject)
      req.end()
    })
  } finally {
    await new Promise<void>(r => proxy.close(() => r()))
  }
}

const allowWithSet: RequestDecision = {
  action: 'allow',
  setHeaders: [['authorization', 'Bearer from-policy']],
}

describe('plain HTTP: allow decisions that set headers', () => {
  test('opt-in off: the request is refused and nothing reaches the upstream', async () => {
    const before = received.length
    const denied: string[] = []
    const reply = await getThroughProxy(allowWithSet, {
      onFilterRequestDenied: ({ reason }) => denied.push(reason),
    })
    expect(reply.status).toBe(403)
    expect(reply.body).toContain('plain-HTTP')
    expect(received.length).toBe(before)
    expect(denied).toHaveLength(1)
    expect(denied[0]).toContain('sets headers')
  })

  test('opt-in on: the upstream receives the set header', async () => {
    const before = received.length
    const reply = await getThroughProxy(allowWithSet, {
      plaintextHeaderSet: true,
    })
    expect(reply.status).toBe(200)
    expect(received.length).toBe(before + 1)
    expect(received.at(-1)?.authorization).toBe('Bearer from-policy')
  })

  test('opt-in off: an allow with no sets is forwarded, removals applied', async () => {
    const before = received.length
    const reply = await getThroughProxy({
      action: 'allow',
      removeHeaders: ['x-api-key'],
    })
    expect(reply.status).toBe(200)
    expect(received.length).toBe(before + 1)
    expect(received.at(-1)?.authorization).toBe('Bearer from-client')
    expect(received.at(-1)?.['x-api-key']).toBeUndefined()
  })

  test('opt-in off: an empty setHeaders list is forwarded', async () => {
    const before = received.length
    const reply = await getThroughProxy({ action: 'allow', setHeaders: [] })
    expect(reply.status).toBe(200)
    expect(received.length).toBe(before + 1)
  })

  test("the callback is told the request arrived as 'http'", async () => {
    const schemes: Array<string | undefined> = []
    await getThroughProxy({ action: 'allow' }, {}, info =>
      schemes.push(info?.scheme),
    )
    expect(schemes).toEqual(['http'])
  })
})
