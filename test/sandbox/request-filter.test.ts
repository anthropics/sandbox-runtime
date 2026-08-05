import { describe, test, expect, beforeAll, afterAll } from 'bun:test'
import { createServer as createHttpsServer } from 'node:https'
import type { Server, AddressInfo } from 'node:net'
import { spawn } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { createHttpProxyServer } from '../../src/sandbox/http-proxy.js'
import { createMitmCA } from '../../src/sandbox/mitm-ca.js'
import { mintLeafCert } from '../../src/sandbox/mitm-leaf.js'
import type {
  FilterRequestCallback,
  RequestDecision,
} from '../../src/sandbox/request-filter.js'

const FIXTURE_DIR = join(import.meta.dir, '..', 'fixtures', 'tls-terminate')
const CA_CERT = join(FIXTURE_DIR, 'ca.crt')
const CA_KEY = join(FIXTURE_DIR, 'ca.key')
const CA_PEM = readFileSync(CA_CERT, 'utf8')

describe('network.filterRequest', () => {
  // Every test here drives real TLS (CA mint, MITM re-encrypt) through a
  // spawned curl whose functional watchdog is --max-time 10. The per-test
  // budget must exceed that watchdog: with bun's 5s default, a slow shard
  // gets an opaque 5001ms kill instead of a pass or a diagnosable curl
  // failure. 15s keeps curl as the real timeout.
  const TEST_TIMEOUT = 15_000

  let upstream: Server
  let upstreamPort: number

  beforeAll(async () => {
    const ca0 = createMitmCA({ caCertPath: CA_CERT, caKeyPath: CA_KEY })
    const upCert = mintLeafCert(ca0, '127.0.0.1')
    const upLeafOnly = upCert.certPem.match(
      /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\r?\n?/,
    )![0]
    upstream = createHttpsServer(
      { cert: upLeafOnly, key: upCert.keyPem },
      (req, res) => {
        let body = ''
        req.on('data', c => (body += c))
        req.on('end', () => {
          res.writeHead(200, { 'x-upstream': 'ok' })
          res.end(
            JSON.stringify({ path: req.url, method: req.method, echoed: body }),
          )
        })
      },
    )
    await new Promise<void>(r => upstream.listen(0, '127.0.0.1', r))
    upstreamPort = (upstream.address() as AddressInfo).port
  })

  afterAll(async () => {
    await new Promise<void>(r => upstream.close(() => r()))
  })

  async function withProxy(
    filterRequest: FilterRequestCallback,
    fn: (proxyPort: number) => Promise<void>,
  ): Promise<void> {
    const ca = createMitmCA({ caCertPath: CA_CERT, caKeyPath: CA_KEY })
    const proxy = createHttpProxyServer({
      filter: () => true,
      mitmCA: ca,
      filterRequest,
      tlsTerminateUpstreamCA: CA_PEM,
    })
    await new Promise<void>(r => proxy.listen(0, '127.0.0.1', () => r()))
    try {
      await fn((proxy.address() as AddressInfo).port)
    } finally {
      await new Promise<void>(r => proxy.close(() => r()))
    }
  }

  test(
    'callback receives method, URL, headers; allow forwards upstream',
    async () => {
      let seen: Request | undefined
      await withProxy(
        async req => {
          seen = req
          return { action: 'allow' }
        },
        async port => {
          const r = await curl(
            port,
            `https://127.0.0.1:${upstreamPort}/hello?a=1`,
            {
              headers: ['X-Custom: yep'],
            },
          )
          expect(r.status).toBe(200)
          expect(r.headers['x-upstream']).toBe('ok')
        },
      )
      expect(seen).toBeDefined()
      expect(seen!.method).toBe('GET')
      const u = new URL(seen!.url)
      expect(u.hostname).toBe('127.0.0.1')
      expect(u.port).toBe(String(upstreamPort))
      expect(u.pathname).toBe('/hello')
      expect(u.search).toBe('?a=1')
      expect(seen!.headers.get('x-custom')).toBe('yep')
      expect(seen!.body).toBeNull()
      expect(seen!.signal).toBeInstanceOf(AbortSignal)
    },
    TEST_TIMEOUT,
  )

  // Regression: previously, the URL passed to filterRequest was built
  // from `req.headers.host ?? target.hostname`. The Host header is
  // attacker-controlled (the sandboxed client picks any value once TLS
  // is terminated), so a sandboxed process could CONNECT to allowlisted
  // host A and send a decrypted request with `Host: B` (some other
  // allowlisted host). filterRequest would see "the request is going
  // to B" while the request is actually delivered to A. A consumer
  // using filterRequest for per-host method gating (e.g. "POST allowed
  // only to inference endpoints") was bypassable: spoof
  // `Host: api.inference.example` on a CONNECT to a non-inference
  // host, get the POST allowed, and have it delivered to the original
  // CONNECT target.
  //
  // Fix: derive the URL from the verified CONNECT target only.
  test(
    'URL passed to filterRequest is the CONNECT target, NOT a spoofed Host header',
    async () => {
      let seen: Request | undefined
      let upstreamSawRequest = false
      upstream.on('request', () => {
        upstreamSawRequest = true
      })
      await withProxy(
        async req => {
          seen = req
          // Deny anything that isn't 127.0.0.1 — i.e. emulate a per-host
          // policy. If the URL came from the spoofed Host header, this
          // would erroneously allow the request through.
          const host = new URL(req.url).hostname
          if (host !== '127.0.0.1') {
            return { action: 'deny', reason: `unexpected host ${host}` }
          }
          return { action: 'deny', reason: 'denied for the test' }
        },
        async port => {
          const r = await curl(port, `https://127.0.0.1:${upstreamPort}/x`, {
            method: 'POST',
            body: 'exfil',
            headers: ['Host: spoofed.example.com'],
          })
          // We expect the deny to fire, but with the CORRECT host
          // (127.0.0.1), not 'spoofed.example.com'.
          expect(r.status).toBe(403)
          expect(r.body).toContain('denied for the test')
        },
      )
      expect(seen).toBeDefined()
      const u = new URL(seen!.url)
      expect(u.hostname).toBe('127.0.0.1')
      expect(u.port).toBe(String(upstreamPort))
      // Upstream must NOT have seen the request — even though the Host
      // header named an allowlisted-looking host.
      expect(upstreamSawRequest).toBe(false)
    },
    TEST_TIMEOUT,
  )

  test(
    'deny returns 403 with reason; upstream not reached',
    async () => {
      let upstreamHit = false
      const decision: RequestDecision = {
        action: 'deny',
        reason: 'nope: not on the list',
      }
      await withProxy(
        async () => decision,
        async port => {
          const r = await curl(port, `https://127.0.0.1:${upstreamPort}/denied`)
          expect(r.status).toBe(403)
          expect(r.body.trim()).toBe('nope: not on the list')
          expect(r.headers['x-proxy-error']).toBe('blocked-by-sandbox-runtime')
          upstreamHit = r.headers['x-upstream'] === 'ok'
        },
      )
      expect(upstreamHit).toBe(false)
    },
    TEST_TIMEOUT,
  )

  test(
    'throw → deny (fail closed)',
    async () => {
      await withProxy(
        () => {
          throw new Error('boom')
        },
        async port => {
          const r = await curl(port, `https://127.0.0.1:${upstreamPort}/`)
          expect(r.status).toBe(403)
          expect(r.body).toContain('sandbox policy check failed: boom')
        },
      )
    },
    TEST_TIMEOUT,
  )

  test(
    'decision can depend on request path (awaited)',
    async () => {
      await withProxy(
        async req => {
          await new Promise(r => setTimeout(r, 5))
          return new URL(req.url).pathname === '/ok'
            ? { action: 'allow' }
            : { action: 'deny', reason: 'path not allowed' }
        },
        async port => {
          const a = await curl(port, `https://127.0.0.1:${upstreamPort}/ok`)
          expect(a.status).toBe(200)
          const b = await curl(port, `https://127.0.0.1:${upstreamPort}/nope`)
          expect(b.status).toBe(403)
          expect(b.body).toContain('path not allowed')
        },
      )
    },
    TEST_TIMEOUT,
  )

  test(
    'callback can read the body; upstream still receives it',
    async () => {
      let seenBody = ''
      await withProxy(
        async req => {
          seenBody = await req.text()
          return seenBody.includes('forbidden')
            ? { action: 'deny', reason: 'body matched forbidden' }
            : { action: 'allow' }
        },
        async port => {
          const a = await curl(port, `https://127.0.0.1:${upstreamPort}/up`, {
            method: 'POST',
            body: 'hello-from-client',
          })
          expect(a.status).toBe(200)
          expect(seenBody).toBe('hello-from-client')
          // Upstream got the same bytes the callback read.
          expect(JSON.parse(a.body).echoed).toBe('hello-from-client')

          const b = await curl(port, `https://127.0.0.1:${upstreamPort}/up`, {
            method: 'POST',
            body: 'this is forbidden content',
          })
          expect(b.status).toBe(403)
          expect(b.body.trim()).toBe('body matched forbidden')
        },
      )
    },
    TEST_TIMEOUT,
  )

  test(
    'callback that ignores body does not buffer it (upstream still gets it)',
    async () => {
      await withProxy(
        async () => ({ action: 'allow' }),
        async port => {
          const r = await curl(port, `https://127.0.0.1:${upstreamPort}/up`, {
            method: 'POST',
            body: 'passthrough',
          })
          expect(r.status).toBe(200)
          expect(JSON.parse(r.body).echoed).toBe('passthrough')
        },
      )
    },
    TEST_TIMEOUT,
  )

  test(
    'also gates plain HTTP through the proxy',
    async () => {
      let seen: Request | undefined
      const httpUp = (await import('node:http')).createServer((_req, res) => {
        res.writeHead(200, { 'x-upstream': 'ok' })
        res.end('plain')
      })
      await new Promise<void>(r => httpUp.listen(0, '127.0.0.1', () => r()))
      const httpUpPort = (httpUp.address() as AddressInfo).port
      try {
        await withProxy(
          async req => {
            seen = req
            return new URL(req.url).pathname === '/ok'
              ? { action: 'allow' }
              : { action: 'deny', reason: 'nope' }
          },
          async port => {
            const a = await curl(port, `http://127.0.0.1:${httpUpPort}/ok`)
            expect(a.status).toBe(200)
            expect(new URL(seen!.url).protocol).toBe('http:')
            const b = await curl(port, `http://127.0.0.1:${httpUpPort}/bad`)
            expect(b.status).toBe(403)
            expect(b.body.trim()).toBe('nope')
          },
        )
      } finally {
        await new Promise<void>(r => httpUp.close(() => r()))
      }
    },
    TEST_TIMEOUT,
  )

  test(
    'no filterRequest → all requests forward (back-compat)',
    async () => {
      const ca = createMitmCA({ caCertPath: CA_CERT, caKeyPath: CA_KEY })
      const proxy = createHttpProxyServer({
        filter: () => true,
        mitmCA: ca,
        tlsTerminateUpstreamCA: CA_PEM,
      })
      await new Promise<void>(r => proxy.listen(0, '127.0.0.1', () => r()))
      try {
        const r = await curl(
          (proxy.address() as AddressInfo).port,
          `https://127.0.0.1:${upstreamPort}/compat`,
        )
        expect(r.status).toBe(200)
      } finally {
        await new Promise<void>(r => proxy.close(() => r()))
      }
    },
    TEST_TIMEOUT,
  )
})

type CurlResult = {
  exit: number
  status: number
  headers: Record<string, string>
  body: string
}

async function curl(
  proxyPort: number,
  url: string,
  opts: { headers?: string[]; method?: string; body?: string } = {},
): Promise<CurlResult> {
  const args = [
    '-sS',
    '--proxy',
    `http://127.0.0.1:${proxyPort}`,
    '--cacert',
    CA_CERT,
    '--max-time',
    '10',
    '-D',
    '-',
  ]
  for (const h of opts.headers ?? []) args.push('-H', h)
  if (opts.method) args.push('-X', opts.method)
  if (opts.body !== undefined) args.push('--data-binary', opts.body)
  args.push(url)

  const child = spawn('curl', args)
  let out = ''
  child.stdout.setEncoding('utf8').on('data', c => (out += c))
  child.stderr.setEncoding('utf8').on('data', () => {})
  await Promise.all([
    new Promise<void>(r => child.stdout.once('end', r)),
    new Promise<void>(r => child.stderr.once('end', r)),
  ])
  const exit = await new Promise<number>(r =>
    child.on('close', code => r(code ?? 1)),
  )

  const sep = out.lastIndexOf('\r\n\r\n')
  const headerPart = sep >= 0 ? out.slice(0, sep) : ''
  const body = sep >= 0 ? out.slice(sep + 4) : out
  const blocks = headerPart.split(/\r\n\r\n/)
  const lastHdr = blocks[blocks.length - 1] ?? ''
  const lines = lastHdr.split('\r\n')
  const m = /HTTP\/[\d.]+ (\d+)/.exec(lines.shift() ?? '')
  const status = m ? Number(m[1]) : 0
  const headers: Record<string, string> = {}
  for (const line of lines) {
    const i = line.indexOf(':')
    if (i > 0)
      headers[line.slice(0, i).toLowerCase()] = line.slice(i + 1).trim()
  }
  return { exit, status, headers, body }
}
