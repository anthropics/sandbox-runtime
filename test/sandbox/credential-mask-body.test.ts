import { describe, test, expect, beforeAll, afterAll } from 'bun:test'
import { testWithTls } from '../helpers/emitted-connections.js'
import { createServer as createHttpsServer } from 'node:https'
import {
  createServer as createHttpServer,
  request as httpRequest,
  type IncomingHttpHeaders,
} from 'node:http'
import type { Server, AddressInfo } from 'node:net'
import { spawn } from 'node:child_process'
import { gzipSync } from 'node:zlib'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { SentinelRegistry } from '../../src/sandbox/credential-sentinel.js'
import { createHttpProxyServer } from '../../src/sandbox/http-proxy.js'
import { createMitmCA } from '../../src/sandbox/mitm-ca.js'
import { mintLeafCert } from '../../src/sandbox/mitm-leaf.js'

/**
 * End-to-end tests for masked-credential substitution in request BODIES:
 * a sandboxed client sends the sentinel (fake) in a JSON / form / multipart
 * body, and the upstream must receive the real secret with valid framing.
 * Driven with curl like tls-terminate-proxy.test.ts, so a real
 * CONNECT-through-proxy client exercises the terminated path.
 */

// Committed test-only CA — see test/fixtures/tls-terminate/README.md.
const FIXTURE_DIR = join(import.meta.dir, '..', 'fixtures', 'tls-terminate')
const CA_CERT = join(FIXTURE_DIR, 'ca.crt')
const CA_KEY = join(FIXTURE_DIR, 'ca.key')
const CA_PEM = readFileSync(CA_CERT, 'utf8')

// Longer than the 47-byte base sentinel, so register() length-matches it.
const REAL_LONG = 'ghp_realsecret_0123456789abcdef_0123456789abcdef_0123456789'
// Shorter than the base sentinel — register() keeps 47 bytes, NOT matched.
const REAL_SHORT = 'ghp_short'

/** Host matcher for tests: exact equality. */
const eq = (h: string, p: string) => h === p

type SeenRequest = {
  method: string
  url: string
  headers: IncomingHttpHeaders
  body: Buffer
}

/**
 * On the chunked-fallback path the proxy deletes the client's (now stale)
 * Content-Length and lets the runtime re-frame the upstream leg. Node
 * streams it chunked; Bun sometimes buffers a small body and sends a fresh
 * correct Content-Length instead. Both are valid framing — what must never
 * appear is the stale length, `clientSentLength`.
 */
function expectReframed(got: SeenRequest, clientSentLength: number): void {
  const cl = got.headers['content-length']
  if (got.headers['transfer-encoding'] === 'chunked') {
    expect(cl).toBeUndefined()
  } else {
    expect(cl).toBe(String(got.body.length))
  }
  expect(cl).not.toBe(String(clientSentLength))
}

describe('credential-mask-body: end-to-end through the TLS-terminating proxy', () => {
  // Every case runs a TLS-terminating proxy: skipped where none can run.
  const test = testWithTls
  const ca = createMitmCA({ caCertPath: CA_CERT, caKeyPath: CA_KEY })

  let upstream: Server
  let upstreamPort: number
  const seen: SeenRequest[] = []
  const lastSeen = () => seen[seen.length - 1]!

  /** Proxy wired to `reg` exactly as sandbox-manager wires the registry. */
  async function startProxy(
    reg: SentinelRegistry,
  ): Promise<{ server: Server; port: number }> {
    const server = createHttpProxyServer({
      filter: () => true,
      mitmCA: ca,
      tlsTerminateUpstreamCA: CA_PEM,
      mutateHeaders: (h, d) => reg.substituteInHeaders(h, d, eq),
      getBodySubstitutions: d => reg.sentinelsForHost(d, eq),
    })
    await new Promise<void>(r => server.listen(0, '127.0.0.1', () => r()))
    return { server, port: (server.address() as AddressInfo).port }
  }

  const stop = (s: Server) => new Promise<void>(r => s.close(() => r()))

  beforeAll(async () => {
    const upCert = mintLeafCert(ca, '127.0.0.1')
    const upLeafOnly = upCert.certPem.match(
      /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\r?\n?/,
    )![0]
    upstream = createHttpsServer(
      { cert: upLeafOnly, key: upCert.keyPem },
      (req, res) => {
        const chunks: Buffer[] = []
        req.on('data', (c: Buffer) => chunks.push(c))
        req.on('end', () => {
          seen.push({
            method: req.method!,
            url: req.url!,
            headers: req.headers,
            body: Buffer.concat(chunks),
          })
          res.writeHead(200, { 'x-upstream': 'ok' })
          res.end('ok')
        })
      },
    )
    await new Promise<void>(r => upstream.listen(0, '127.0.0.1', r))
    upstreamPort = (upstream.address() as AddressInfo).port
  })

  afterAll(async () => {
    await stop(upstream)
  })

  const url = (path: string) => `https://127.0.0.1:${upstreamPort}${path}`

  test('JSON body, length-matched: real secret arrives, Content-Length verbatim', async () => {
    const reg = new SentinelRegistry()
    const sentinel = reg.register('GH_TOKEN', REAL_LONG, ['127.0.0.1'])
    expect(sentinel.length).toBe(REAL_LONG.length) // length-matched
    const { server, port } = await startProxy(reg)
    try {
      const payload = `{"token":"${sentinel}","note":"hi"}`
      const r = await curlViaProxy(port, url('/json'), {
        method: 'POST',
        body: payload,
        headers: ['Content-Type: application/json'],
      })
      expect(r.exit).toBe(0)
      expect(r.status).toBe(200)
      const got = lastSeen()
      expect(got.body.toString()).toBe(`{"token":"${REAL_LONG}","note":"hi"}`)
      // Same byte length → the client's Content-Length was forwarded
      // verbatim and still frames the substituted body correctly.
      expect(got.headers['content-length']).toBe(String(payload.length))
      expect(got.headers['transfer-encoding']).toBeUndefined()
    } finally {
      await stop(server)
    }
  })

  test('JSON body, non-length-matched sentinel: chunked fallback, real secret arrives', async () => {
    const reg = new SentinelRegistry()
    const sentinel = reg.register('GH_TOKEN', REAL_SHORT, ['127.0.0.1'])
    expect(sentinel.length).not.toBe(REAL_SHORT.length)
    const { server, port } = await startProxy(reg)
    try {
      const payload = `{"token":"${sentinel}"}`
      const r = await curlViaProxy(port, url('/json-chunked'), {
        method: 'POST',
        body: payload,
        headers: ['Content-Type: application/json'],
      })
      expect(r.exit).toBe(0)
      expect(r.status).toBe(200)
      const got = lastSeen()
      expect(got.body.toString()).toBe(`{"token":"${REAL_SHORT}"}`)
      // Substitution changed the body length: the client's Content-Length
      // was dropped and the upstream leg re-framed.
      expectReframed(got, payload.length)
    } finally {
      await stop(server)
    }
  })

  test('caller-minted sentinel (registerWithSentinel) also takes the chunked fallback', async () => {
    const reg = new SentinelRegistry()
    // Shaped fake, e.g. a JWT-form sentinel — never padded by the registry.
    const fake = 'eyJhbGciOiJub25lIn0.fake-a1b2c3d4-5678-4abc-8def-000011112222'
    reg.registerWithSentinel('JWT', fake, REAL_LONG, ['127.0.0.1'])
    const { server, port } = await startProxy(reg)
    try {
      const payload = `token=${fake}`
      const r = await curlViaProxy(port, url('/jwt'), {
        method: 'POST',
        body: payload,
        headers: ['Content-Type: application/x-www-form-urlencoded'],
      })
      expect(r.exit).toBe(0)
      expect(r.status).toBe(200)
      const got = lastSeen()
      expect(got.body.toString()).toBe(`token=${REAL_LONG}`)
      expectReframed(got, payload.length)
    } finally {
      await stop(server)
    }
  })

  test('form-urlencoded body, length-matched path', async () => {
    const reg = new SentinelRegistry()
    const sentinel = reg.register('GH_TOKEN', REAL_LONG, ['127.0.0.1'])
    const { server, port } = await startProxy(reg)
    try {
      const payload = `a=1&token=${sentinel}&b=2`
      const r = await curlViaProxy(port, url('/form'), {
        method: 'POST',
        body: payload,
        headers: ['Content-Type: application/x-www-form-urlencoded'],
      })
      expect(r.exit).toBe(0)
      expect(r.status).toBe(200)
      const got = lastSeen()
      expect(got.body.toString()).toBe(`a=1&token=${REAL_LONG}&b=2`)
      expect(got.headers['content-length']).toBe(String(payload.length))
    } finally {
      await stop(server)
    }
  })

  test('multipart body: sentinel inside a part is substituted, framing intact', async () => {
    const reg = new SentinelRegistry()
    const sentinel = reg.register('GH_TOKEN', REAL_LONG, ['127.0.0.1'])
    const { server, port } = await startProxy(reg)
    try {
      const r = await curlViaProxy(port, url('/multipart'), {
        formFields: [
          ['token', sentinel],
          ['name', 'unrelated'],
        ],
      })
      expect(r.exit).toBe(0)
      expect(r.status).toBe(200)
      const got = lastSeen()
      const body = got.body.toString()
      expect(body).toContain(REAL_LONG)
      expect(body).not.toContain(sentinel)
      expect(body).toContain('name="name"')
      // Length-matched substitution → curl's multipart Content-Length still
      // frames the body exactly.
      expect(got.headers['content-length']).toBe(String(got.body.length))
      const boundary = /boundary=(\S+)/.exec(
        String(got.headers['content-type']),
      )![1]!
      expect(body).toContain(`--${boundary}--`)
    } finally {
      await stop(server)
    }
  })

  test('gzip request body passes through byte-identical (fail-safe skip)', async () => {
    const reg = new SentinelRegistry()
    const sentinel = reg.register('GH_TOKEN', REAL_LONG, ['127.0.0.1'])
    const { server, port } = await startProxy(reg)
    const tmp = mkdtempSync(join(tmpdir(), 'srt-body-gz-'))
    try {
      const gz = gzipSync(Buffer.from(`{"token":"${sentinel}"}`))
      const gzPath = join(tmp, 'body.gz')
      writeFileSync(gzPath, gz)
      const r = await curlViaProxy(port, url('/gz'), {
        method: 'POST',
        dataFile: gzPath,
        headers: ['Content-Type: application/json', 'Content-Encoding: gzip'],
      })
      expect(r.exit).toBe(0)
      expect(r.status).toBe(200)
      const got = lastSeen()
      expect(got.body.equals(gz)).toBe(true)
      expect(got.headers['content-length']).toBe(String(gz.length))
    } finally {
      await stop(server)
      rmSync(tmp, { recursive: true, force: true })
    }
  })

  test('host without injectable credentials: byte-identical passthrough', async () => {
    const reg = new SentinelRegistry()
    // Injectable only at some OTHER host — not at the CONNECT target.
    const sentinel = reg.register('GH_TOKEN', REAL_LONG, ['other.example.com'])
    const { server, port } = await startProxy(reg)
    try {
      const payload = `{"token":"${sentinel}"}`
      const r = await curlViaProxy(port, url('/other-host'), {
        method: 'POST',
        body: payload,
        headers: ['Content-Type: application/json'],
      })
      expect(r.exit).toBe(0)
      expect(r.status).toBe(200)
      const got = lastSeen()
      // The fake stays a useless fake; nothing about the request changed.
      expect(got.body.toString()).toBe(payload)
      expect(got.headers['content-length']).toBe(String(payload.length))
      expect(got.headers['transfer-encoding']).toBeUndefined()
    } finally {
      await stop(server)
    }
  })

  test('regression: header substitution still works alongside body substitution', async () => {
    const reg = new SentinelRegistry()
    const sentinel = reg.register('GH_TOKEN', REAL_LONG, ['127.0.0.1'])
    const { server, port } = await startProxy(reg)
    try {
      const r = await curlViaProxy(port, url('/both'), {
        method: 'POST',
        body: `{"token":"${sentinel}"}`,
        headers: [
          'Content-Type: application/json',
          `Authorization: Bearer ${sentinel}`,
        ],
      })
      expect(r.exit).toBe(0)
      expect(r.status).toBe(200)
      const got = lastSeen()
      expect(got.headers.authorization).toBe(`Bearer ${REAL_LONG}`)
      expect(got.body.toString()).toBe(`{"token":"${REAL_LONG}"}`)
    } finally {
      await stop(server)
    }
  })

  test('regression: bodyless GET is unaffected', async () => {
    const reg = new SentinelRegistry()
    reg.register('GH_TOKEN', REAL_LONG, ['127.0.0.1'])
    const { server, port } = await startProxy(reg)
    try {
      const r = await curlViaProxy(port, url('/plain-get'))
      expect(r.exit).toBe(0)
      expect(r.status).toBe(200)
      const got = lastSeen()
      expect(got.method).toBe('GET')
      expect(got.body.length).toBe(0)
    } finally {
      await stop(server)
    }
  })
})

describe('credential-mask-body: plaintext proxy path (opt-in)', () => {
  test('getBodySubstitutionsPlaintext substitutes in a plain-HTTP POST body', async () => {
    const seen: SeenRequest[] = []
    const upstream = createHttpServer((req, res) => {
      const chunks: Buffer[] = []
      req.on('data', (c: Buffer) => chunks.push(c))
      req.on('end', () => {
        seen.push({
          method: req.method!,
          url: req.url!,
          headers: req.headers,
          body: Buffer.concat(chunks),
        })
        res.writeHead(200)
        res.end('ok')
      })
    })
    await new Promise<void>(r => upstream.listen(0, '127.0.0.1', r))
    const upstreamPort = (upstream.address() as AddressInfo).port

    const reg = new SentinelRegistry()
    const sentinel = reg.register('GH_TOKEN', REAL_LONG, ['127.0.0.1'])
    const proxy = createHttpProxyServer({
      filter: () => true,
      mutateHeadersPlaintext: (h, d) => reg.substituteInHeaders(h, d, eq),
      getBodySubstitutionsPlaintext: d => reg.sentinelsForHost(d, eq),
    })
    await new Promise<void>(r => proxy.listen(0, '127.0.0.1', () => r()))
    const proxyPort = (proxy.address() as AddressInfo).port

    try {
      const payload = `{"token":"${sentinel}"}`
      const status = await new Promise<number>((resolve, reject) => {
        const req = httpRequest(
          {
            host: '127.0.0.1',
            port: proxyPort,
            method: 'POST',
            // Absolute-form request-target: this is how proxy clients speak
            // plain HTTP to a forward proxy.
            path: `http://127.0.0.1:${upstreamPort}/plain`,
            headers: {
              'content-type': 'application/json',
              'content-length': payload.length,
            },
          },
          res => {
            res.resume()
            res.on('end', () => resolve(res.statusCode ?? 0))
          },
        )
        req.on('error', reject)
        req.end(payload)
      })
      expect(status).toBe(200)
      const got = seen[seen.length - 1]!
      expect(got.body.toString()).toBe(`{"token":"${REAL_LONG}"}`)
      expect(got.headers['content-length']).toBe(String(payload.length))
    } finally {
      await new Promise<void>(r => proxy.close(() => r()))
      await new Promise<void>(r => upstream.close(() => r()))
    }
  })
})

type CurlResult = {
  exit: number
  status: number
  headers: Record<string, string>
  body: string
  stderr: string
}

async function curlViaProxy(
  proxyPort: number,
  url: string,
  opts: {
    method?: string
    body?: string
    /** Raw request headers, `Name: value` form. */
    headers?: string[]
    /** Multipart form fields (`curl -F name=value`). */
    formFields?: Array<[string, string]>
    /** File whose bytes become the request body (`--data-binary @file`). */
    dataFile?: string
  } = {},
): Promise<CurlResult> {
  const args = [
    '-sS',
    '-v',
    '--proxy',
    `http://127.0.0.1:${proxyPort}`,
    // An empty list overrides NO_PROXY, which would send curl around
    // the proxy under test for 127.0.0.1.
    '--noproxy',
    '',
    '--cacert',
    CA_CERT,
    '--max-time',
    '10',
    '-D',
    '-',
  ]
  if (opts.method) args.push('-X', opts.method)
  for (const h of opts.headers ?? []) args.push('-H', h)
  if (opts.body !== undefined) args.push('--data-binary', opts.body)
  if (opts.dataFile !== undefined)
    args.push('--data-binary', `@${opts.dataFile}`)
  for (const [name, value] of opts.formFields ?? []) {
    args.push('-F', `${name}=${value}`)
  }
  args.push(url)

  const child = spawn('curl', args)
  let out = ''
  let stderr = ''
  child.stdout.setEncoding('utf8').on('data', c => (out += c))
  child.stderr.setEncoding('utf8').on('data', c => (stderr += c))
  await Promise.all([
    new Promise<void>(r => child.stdout.once('end', r)),
    new Promise<void>(r => child.stderr.once('end', r)),
  ])
  const exit = await new Promise<number>(resolve =>
    child.on('close', code => resolve(code ?? 1)),
  )

  const sep = out.lastIndexOf('\r\n\r\n')
  const headerPart = sep >= 0 ? out.slice(0, sep) : ''
  const body = sep >= 0 ? out.slice(sep + 4) : out
  const blocks = headerPart.split(/\r\n\r\n/)
  const lastHdr = blocks[blocks.length - 1] ?? ''
  const lines = lastHdr.split('\r\n')
  const statusLine = lines.shift() ?? ''
  const m = /HTTP\/[\d.]+ (\d+)/.exec(statusLine)
  const status = m ? Number(m[1]) : 0
  const headers: Record<string, string> = {}
  for (const line of lines) {
    const i = line.indexOf(':')
    if (i > 0)
      headers[line.slice(0, i).toLowerCase()] = line.slice(i + 1).trim()
  }
  return { exit, status, headers, body, stderr }
}
