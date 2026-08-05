/**
 * End-to-end SigV4 re-signing through the TLS-terminating proxy.
 *
 * The client (curl --aws-sigv4, a real independent SigV4 implementation)
 * holds only the FAKE credentials, exactly like a sandboxed AWS SDK. The
 * proxy terminates TLS, detects the fake access key id in the credential
 * scope, and re-signs with the real pair. The local TLS upstream plays
 * the AWS service: it recomputes the signature from the REAL secret over
 * the request it received and asserts an exact match.
 *
 * The signer itself is pinned by the official test vectors in
 * aws-sigv4.test.ts; these tests pin the proxy plumbing around it.
 */

import { describe, test, expect, beforeAll, afterAll } from 'bun:test'
import { createServer as createHttpsServer } from 'node:https'
import type { IncomingHttpHeaders, IncomingMessage } from 'node:http'
import type { Server, AddressInfo } from 'node:net'
import { spawn } from 'node:child_process'
import { connect as netConnect } from 'node:net'
import { connect as tlsConnect } from 'node:tls'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { SentinelRegistry } from '../../src/sandbox/credential-sentinel.js'
import {
  AwsPairRegistry,
  createSigv4Planner,
} from '../../src/sandbox/credential-aws-pairs.js'
import {
  parseSigv4Authorization,
  sha256Hex,
  signSigv4,
  singleHeader,
  UNSIGNED_PAYLOAD,
} from '../../src/sandbox/aws-sigv4.js'
import { createHttpProxyServer } from '../../src/sandbox/http-proxy.js'
import { MAX_SIGV4_RESIGN_BODY_BYTES } from '../../src/sandbox/tls-terminate-proxy.js'
import { createMitmCA, disposeMitmCA } from '../../src/sandbox/mitm-ca.js'
import { mintLeafCert } from '../../src/sandbox/mitm-leaf.js'
import type { Sigv4Config } from '../../src/sandbox/sandbox-config.js'

const FIXTURE_DIR = join(import.meta.dir, '..', 'fixtures', 'tls-terminate')
const CA_CERT = join(FIXTURE_DIR, 'ca.crt')
const CA_KEY = join(FIXTURE_DIR, 'ca.key')
const CA_PEM = readFileSync(CA_CERT, 'utf8')

const REAL_AKID = 'AKIAIOSFODNN7EXAMPLE'
const REAL_SECRET = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
const REAL_TOKEN = 'FQoGZXIvYXdzEXAMPLEsessiontoken=='
const REGION = 'us-east-1'
const SERVICE = 's3'
const DEST = '127.0.0.1'

/** Host matcher for tests: exact equality. */
const eq = (h: string, p: string) => h === p

interface Captured {
  method: string
  url: string
  headers: IncomingHttpHeaders
  body: Buffer
}

/**
 * "AWS-side" verification: recompute the signature from the REAL secret
 * over the request exactly as the upstream received it, and compare.
 */
function verifyUpstreamSignature(
  captured: Captured,
  opts: { secret?: string; akid?: string } = {},
): void {
  const auth = parseSigv4Authorization(
    singleHeader(captured.headers.authorization)!,
  )
  expect(auth).not.toBeNull()
  expect(auth!.accessKeyId).toBe(opts.akid ?? REAL_AKID)
  const contentSha = singleHeader(captured.headers['x-amz-content-sha256'])
  const payloadHash =
    contentSha === UNSIGNED_PAYLOAD
      ? UNSIGNED_PAYLOAD
      : sha256Hex(captured.body)
  const expected = signSigv4({
    method: captured.method,
    requestTarget: captured.url,
    headers: captured.headers,
    hostHeader: singleHeader(captured.headers.host)!,
    signedHeaders: auth!.signedHeaders,
    payloadHash,
    amzDate: singleHeader(captured.headers['x-amz-date'])!,
    scope: { date: auth!.date, region: auth!.region, service: auth!.service },
    accessKeyId: auth!.accessKeyId,
    secretAccessKey: opts.secret ?? REAL_SECRET,
  })
  expect(auth!.signature).toBe(expected.signature)
}

type CurlResult = { exit: number; status: number; body: string }

async function curlViaProxy(
  proxyPort: number,
  url: string,
  opts: {
    headers?: string[]
    method?: string
    data?: string
    /** Path to a file sent as the request body (--data-binary @file). */
    dataFile?: string
    awsSigv4?: { akid: string; secret: string }
  } = {},
): Promise<CurlResult> {
  const args = [
    '-sS',
    '--proxy',
    `http://127.0.0.1:${proxyPort}`,
    '--max-time',
    '10',
    '-D',
    '-',
    '--cacert',
    CA_CERT,
  ]
  if (opts.method) args.push('-X', opts.method)
  if (opts.data !== undefined) args.push('--data-binary', opts.data)
  if (opts.dataFile !== undefined)
    args.push('--data-binary', `@${opts.dataFile}`)
  if (opts.awsSigv4) {
    args.push(
      '--aws-sigv4',
      `aws:amz:${REGION}:${SERVICE}`,
      '--user',
      `${opts.awsSigv4.akid}:${opts.awsSigv4.secret}`,
    )
  }
  for (const h of opts.headers ?? []) args.push('-H', h)
  args.push(url)

  const child = spawn('curl', args)
  let out = ''
  let err = ''
  child.stdout.setEncoding('utf8').on('data', c => (out += c))
  child.stderr.setEncoding('utf8').on('data', c => (err += c))
  await Promise.all([
    new Promise<void>(r => child.stdout.once('end', r)),
    new Promise<void>(r => child.stderr.once('end', r)),
  ])
  const exit = await new Promise<number>(r =>
    child.on('close', code => r(code ?? 1)),
  )
  const sep = out.lastIndexOf('\r\n\r\n')
  const headerPart = sep >= 0 ? out.slice(0, sep) : out
  const body = sep >= 0 ? out.slice(sep + 4) : ''
  const blocks = headerPart.split(/\r\n\r\n/)
  const m = /HTTP\/[\d.]+ (\d+)/.exec(blocks[blocks.length - 1] ?? '')
  return { exit, status: m ? Number(m[1]) : 0, body: body || err }
}

/** One TLS upstream + one terminating proxy with the given SigV4 config. */
function makeStack(opts: {
  sigv4?: Sigv4Config
  sessionToken?: boolean
  maxSigv4ResignBodyBytes?: number
  /** Also wire request-BODY sentinel substitution (body-substitution.ts). */
  bodySubstitution?: boolean
}) {
  const ca = createMitmCA({ caCertPath: CA_CERT, caKeyPath: CA_KEY })
  const sentinels = new SentinelRegistry()
  const pairs = new AwsPairRegistry()
  const fakeAkid = sentinels.register('AWS_ACCESS_KEY_ID', REAL_AKID, [DEST])
  const fakeSecret = sentinels.register('AWS_SECRET_ACCESS_KEY', REAL_SECRET, [
    DEST,
  ])
  let fakeToken: string | undefined
  if (opts.sessionToken) {
    fakeToken = sentinels.register('AWS_SESSION_TOKEN', REAL_TOKEN, [DEST])
  }
  pairs.register({
    accessKeyIdSentinel: fakeAkid,
    realAccessKeyId: REAL_AKID,
    realSecretAccessKey: REAL_SECRET,
    ...(opts.sessionToken ? { realSessionToken: REAL_TOKEN } : {}),
    injectHosts: [DEST],
  })

  const state: {
    ca: ReturnType<typeof createMitmCA>
    sentinels: SentinelRegistry
    fakeAkid: string
    fakeSecret: string
    fakeToken: string | undefined
    upstream?: Server
    upstreamPort?: number
    proxy?: Server
    proxyPort?: number
    captured?: Captured
  } = { ca, sentinels, fakeAkid, fakeSecret, fakeToken }

  const start = async () => {
    const upCert = mintLeafCert(ca, DEST)
    const upLeafOnly = upCert.certPem.match(
      /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\r?\n?/,
    )![0]
    const upstream = createHttpsServer(
      { cert: upLeafOnly, key: upCert.keyPem },
      (req: IncomingMessage, res) => {
        const chunks: Buffer[] = []
        req.on('data', (c: Buffer) => chunks.push(c))
        req.on('end', () => {
          state.captured = {
            method: req.method!,
            url: req.url!,
            headers: req.headers,
            body: Buffer.concat(chunks),
          }
          res.writeHead(200, { 'content-type': 'text/plain' })
          res.end('ok')
        })
      },
    )
    await new Promise<void>(r => upstream.listen(0, DEST, r))
    state.upstream = upstream
    state.upstreamPort = (upstream.address() as AddressInfo).port

    const proxy = createHttpProxyServer({
      filter: () => true,
      mitmCA: ca,
      tlsTerminateUpstreamCA: CA_PEM,
      mutateHeaders: (headers, destHost) =>
        sentinels.substituteInHeaders(headers, destHost, eq),
      ...(opts.bodySubstitution
        ? {
            getBodySubstitutions: (destHost: string) =>
              sentinels.sentinelsForHost(destHost, eq),
          }
        : {}),
      planSigv4: createSigv4Planner(pairs, opts.sigv4, eq),
      ...(opts.maxSigv4ResignBodyBytes !== undefined
        ? { maxSigv4ResignBodyBytes: opts.maxSigv4ResignBodyBytes }
        : {}),
    })
    await new Promise<void>(r => proxy.listen(0, '127.0.0.1', () => r()))
    state.proxy = proxy
    state.proxyPort = (proxy.address() as AddressInfo).port
  }

  const stop = async () => {
    if (state.proxy) {
      await new Promise<void>(r => state.proxy!.close(() => r()))
    }
    if (state.upstream) {
      await new Promise<void>(r => state.upstream!.close(() => r()))
    }
    await disposeMitmCA(ca)
  }

  return { state, start, stop }
}

describe('SigV4 re-signing through the TLS-terminating proxy', () => {
  const stack = makeStack({ sessionToken: true })
  const { state } = stack

  beforeAll(stack.start)
  afterAll(stack.stop)

  test('curl --aws-sigv4 with fake creds: upstream sees a valid real-credential signature', async () => {
    state.captured = undefined
    const r = await curlViaProxy(
      state.proxyPort!,
      `https://${DEST}:${state.upstreamPort}/bucket/key?list-type=2&prefix=a%20b`,
      { awsSigv4: { akid: state.fakeAkid, secret: state.fakeSecret } },
    )
    expect(r.exit).toBe(0)
    expect(r.status).toBe(200)
    const captured = state.captured!
    expect(captured).toBeDefined()

    // The scope carries the REAL access key id...
    const auth = singleHeader(captured.headers.authorization)!
    expect(auth).toContain(`Credential=${REAL_AKID}/`)
    expect(auth).toContain(`/${REGION}/${SERVICE}/aws4_request`)
    // ...and the signature verifies against the REAL secret over the
    // request as received (the upstream's own recomputation).
    verifyUpstreamSignature(captured)
    // Nothing fake leaked upstream.
    expect(JSON.stringify(captured.headers)).not.toContain(state.fakeAkid)
    expect(JSON.stringify(captured.headers)).not.toContain(state.fakeSecret)
  }, 20000)

  test('POST with a body: hash recomputed over the forwarded bytes, body intact', async () => {
    state.captured = undefined
    const body = 'Param1=value1&Param2=value2'
    const r = await curlViaProxy(
      state.proxyPort!,
      `https://${DEST}:${state.upstreamPort}/`,
      {
        awsSigv4: { akid: state.fakeAkid, secret: state.fakeSecret },
        data: body,
        headers: ['Content-Type: application/x-www-form-urlencoded'],
      },
    )
    expect(r.exit).toBe(0)
    expect(r.status).toBe(200)
    const captured = state.captured!
    expect(captured.body.toString()).toBe(body)
    // curl signs the body hash without emitting x-amz-content-sha256, so
    // the proxy had to buffer the body and recompute the hash itself —
    // the recomputed signature only verifies if it covers sha256(body).
    verifyUpstreamSignature(captured)
  }, 20000)

  test('DELETE with a chunked literal-hash body: proxy re-frames with content-length', async () => {
    // The unsound case needs a client that sends its body chunked WITHOUT
    // signing Transfer-Encoding (curl signs every header it sends, so this
    // is hand-rolled with the repo's own signing primitives). Without the
    // unconditional content-length restore, Node's end(Buffer) emits NO
    // framing for bodyless-default methods — the upstream parses an empty
    // DELETE and the raw-appended body poisons the connection (verified:
    // 400 + empty body on Node). Bun auto-computes a content-length, so
    // under bun this pins the e2e scenario rather than the regression.
    state.captured = undefined
    const body = 'delete-with-chunked-body'
    const payloadHash = sha256Hex(Buffer.from(body))
    const amzDate = new Date()
      .toISOString()
      .replace(/[-:]/g, '')
      .replace(/\..*/, 'Z')
    const scope = {
      date: amzDate.slice(0, 8),
      region: REGION,
      service: SERVICE,
    }
    const hostHeader = `${DEST}:${state.upstreamPort}`
    const signed = signSigv4({
      method: 'DELETE',
      requestTarget: '/bucket/key',
      headers: {
        'x-amz-content-sha256': payloadHash,
        'x-amz-date': amzDate,
      },
      hostHeader,
      signedHeaders: ['host', 'x-amz-content-sha256', 'x-amz-date'],
      payloadHash,
      amzDate,
      scope,
      accessKeyId: state.fakeAkid,
      secretAccessKey: state.fakeSecret,
    })
    const status = await new Promise<string>(resolve => {
      let resp = ''
      const raw = netConnect(state.proxyPort!, '127.0.0.1', () => {
        raw.write(
          `CONNECT ${DEST}:${state.upstreamPort} HTTP/1.1\r\nHost: ${DEST}:${state.upstreamPort}\r\n\r\n`,
        )
      })
      raw.on('error', () => {})
      raw.once('data', () => {
        const tls = tlsConnect(
          // SNI cannot carry an IP literal; the CA is pinned, so skip the
          // hostname identity check instead.
          {
            socket: raw,
            ca: CA_PEM,
            checkServerIdentity: () => undefined,
          },
          () => {
            tls.write(
              `DELETE /bucket/key HTTP/1.1\r\n` +
                `Host: ${hostHeader}\r\n` +
                `Authorization: ${signed.authorization}\r\n` +
                `x-amz-date: ${amzDate}\r\n` +
                `x-amz-content-sha256: ${payloadHash}\r\n` +
                'Transfer-Encoding: chunked\r\n' +
                '\r\n' +
                `${body.length.toString(16)}\r\n${body}\r\n0\r\n\r\n`,
            )
          },
        )
        tls.on('data', d => {
          resp += d.toString()
          if (resp.includes('\r\n\r\n')) {
            tls.destroy()
            resolve(resp.split('\r\n')[0] ?? '')
          }
        })
        tls.on('error', () => resolve(resp.split('\r\n')[0] ?? ''))
      })
      setTimeout(() => resolve(resp.split('\r\n')[0] ?? ''), 8000)
    })
    expect(status).toContain('200')
    const captured = state.captured!
    expect(captured).toBeDefined()
    expect(captured.method).toBe('DELETE')
    expect(captured.body.toString()).toBe(body)
    expect(singleHeader(captured.headers['content-length'])).toBe(
      String(body.length),
    )
    verifyUpstreamSignature(captured)
  }, 20000)

  test('the real session token is injected and covered by the signature', async () => {
    state.captured = undefined
    const r = await curlViaProxy(
      state.proxyPort!,
      `https://${DEST}:${state.upstreamPort}/`,
      { awsSigv4: { akid: state.fakeAkid, secret: state.fakeSecret } },
    )
    expect(r.exit).toBe(0)
    expect(r.status).toBe(200)
    const captured = state.captured!
    expect(singleHeader(captured.headers['x-amz-security-token'])).toBe(
      REAL_TOKEN,
    )
    const auth = parseSigv4Authorization(
      singleHeader(captured.headers.authorization)!,
    )!
    expect(auth.signedHeaders).toContain('x-amz-security-token')
    verifyUpstreamSignature(captured)
  }, 20000)

  test('UNSIGNED-PAYLOAD: re-signed without hashing the body', async () => {
    // Hand-signed client request (curl --aws-sigv4 always hashes), using
    // the vector-pinned signer with the FAKE credentials — the same
    // bytes a real SDK configured for UNSIGNED-PAYLOAD would produce.
    state.captured = undefined
    const amzDate = '20260715T000000Z'
    const hostHeader = `${DEST}:${state.upstreamPort}`
    const headers: IncomingHttpHeaders = {
      'x-amz-date': amzDate,
      'x-amz-content-sha256': UNSIGNED_PAYLOAD,
    }
    const { authorization } = signSigv4({
      method: 'PUT',
      requestTarget: '/bucket/key',
      headers,
      hostHeader,
      signedHeaders: ['host', 'x-amz-date', 'x-amz-content-sha256'],
      payloadHash: UNSIGNED_PAYLOAD,
      amzDate,
      scope: { date: '20260715', region: REGION, service: SERVICE },
      accessKeyId: state.fakeAkid,
      secretAccessKey: state.fakeSecret,
    })
    const r = await curlViaProxy(
      state.proxyPort!,
      `https://${DEST}:${state.upstreamPort}/bucket/key`,
      {
        method: 'PUT',
        data: 'streamed-bytes',
        headers: [
          `Authorization: ${authorization}`,
          `X-Amz-Date: ${amzDate}`,
          `X-Amz-Content-Sha256: ${UNSIGNED_PAYLOAD}`,
        ],
      },
    )
    expect(r.exit).toBe(0)
    expect(r.status).toBe(200)
    const captured = state.captured!
    expect(captured.body.toString()).toBe('streamed-bytes')
    // Marker preserved; signature covers the marker, not a body hash.
    expect(singleHeader(captured.headers['x-amz-content-sha256'])).toBe(
      UNSIGNED_PAYLOAD,
    )
    verifyUpstreamSignature(captured)
  }, 20000)

  test('an AWS-shaped request with unmasked credentials is untouched', async () => {
    state.captured = undefined
    const otherAkid = 'AKIDUNRELATEDEXAMPLE'
    const otherSecret = 'unrelated-real-secret-the-proxy-never-saw'
    const amzDate = '20260715T000000Z'
    const { authorization } = signSigv4({
      method: 'GET',
      requestTarget: '/',
      headers: { 'x-amz-date': amzDate },
      hostHeader: `${DEST}:${state.upstreamPort}`,
      signedHeaders: ['host', 'x-amz-date'],
      payloadHash: sha256Hex(''),
      amzDate,
      scope: { date: '20260715', region: REGION, service: SERVICE },
      accessKeyId: otherAkid,
      secretAccessKey: otherSecret,
    })
    const r = await curlViaProxy(
      state.proxyPort!,
      `https://${DEST}:${state.upstreamPort}/`,
      {
        headers: [`Authorization: ${authorization}`, `X-Amz-Date: ${amzDate}`],
      },
    )
    expect(r.exit).toBe(0)
    expect(r.status).toBe(200)
    // Byte-identical Authorization upstream: never rewritten, never denied.
    expect(singleHeader(state.captured!.headers.authorization)).toBe(
      authorization,
    )
    verifyUpstreamSignature(state.captured!, {
      akid: otherAkid,
      secret: otherSecret,
    })
  }, 20000)

  test('a signed hop-by-hop header fails closed instead of crashing the proxy', async () => {
    // The client lists a header in SignedHeaders that it also declares
    // hop-by-hop via Connection, so the proxy strips it before signing.
    // The plan must see the post-strip header set and deny — not throw
    // inside the signer after claiming the request.
    state.captured = undefined
    const amzDate = '20260715T000000Z'
    const r = await curlViaProxy(
      state.proxyPort!,
      `https://${DEST}:${state.upstreamPort}/`,
      {
        headers: [
          `Authorization: AWS4-HMAC-SHA256 Credential=${state.fakeAkid}/20260715/${REGION}/${SERVICE}/aws4_request, ` +
            'SignedHeaders=host;x-amz-date;x-custom, Signature=ff00',
          `X-Amz-Date: ${amzDate}`,
          'Connection: x-custom',
          'X-Custom: value',
        ],
      },
    )
    expect(r.status).toBe(403)
    expect(r.body).toContain('x-custom')
    expect(state.captured).toBeUndefined()
    // The proxy survived: a follow-up request still works.
    const r2 = await curlViaProxy(
      state.proxyPort!,
      `https://${DEST}:${state.upstreamPort}/`,
      { awsSigv4: { akid: state.fakeAkid, secret: state.fakeSecret } },
    )
    expect(r2.status).toBe(200)
  }, 20000)

  test('a non-AWS request with a masked sentinel still gets plain substitution', async () => {
    state.captured = undefined
    const r = await curlViaProxy(
      state.proxyPort!,
      `https://${DEST}:${state.upstreamPort}/`,
      { headers: [`X-Api-Key: ${state.fakeAkid}`] },
    )
    expect(r.exit).toBe(0)
    expect(r.status).toBe(200)
    expect(singleHeader(state.captured!.headers['x-api-key'])).toBe(REAL_AKID)
  }, 20000)
})

describe('literal-hash body buffering cap', () => {
  // The production 64 MiB cap (MAX_SIGV4_RESIGN_BODY_BYTES) is injected
  // smaller here so the over-cap denial doesn't need a 64 MiB fixture
  // upload per test; the mechanism under test is identical.
  const CAP = 256 * 1024
  const stack = makeStack({ maxSigv4ResignBodyBytes: CAP })
  const { state } = stack
  let bodyDir: string
  let underCapFile: string
  let overCapFile: string

  beforeAll(async () => {
    await stack.start()
    bodyDir = mkdtempSync(join(tmpdir(), 'srt-sigv4-body-'))
    underCapFile = join(bodyDir, 'under')
    overCapFile = join(bodyDir, 'over')
    writeFileSync(underCapFile, Buffer.alloc(CAP, 'a'))
    writeFileSync(overCapFile, Buffer.alloc(CAP + 1, 'a'))
  })
  afterAll(async () => {
    rmSync(bodyDir, { recursive: true, force: true })
    await stack.stop()
  })

  test('the default cap is the exported 64 MiB constant', () => {
    expect(MAX_SIGV4_RESIGN_BODY_BYTES).toBe(64 * 1024 * 1024)
  })

  test('a body at the cap is buffered and re-signed', async () => {
    state.captured = undefined
    const r = await curlViaProxy(
      state.proxyPort!,
      `https://${DEST}:${state.upstreamPort}/bucket/key`,
      {
        method: 'PUT',
        dataFile: underCapFile,
        awsSigv4: { akid: state.fakeAkid, secret: state.fakeSecret },
        // curl sends Expect: 100-continue for large bodies; disable so
        // the flow matches the small-body tests.
        headers: ['Expect:'],
      },
    )
    expect(r.exit).toBe(0)
    expect(r.status).toBe(200)
    const captured = state.captured!
    expect(captured.body.length).toBe(CAP)
    verifyUpstreamSignature(captured)
  }, 30000)

  test('a body over the cap fails closed with a 403, nothing upstream', async () => {
    state.captured = undefined
    const r = await curlViaProxy(
      state.proxyPort!,
      `https://${DEST}:${state.upstreamPort}/bucket/key`,
      {
        method: 'PUT',
        dataFile: overCapFile,
        awsSigv4: { akid: state.fakeAkid, secret: state.fakeSecret },
        headers: ['Expect:'],
      },
    )
    expect(r.status).toBe(403)
    expect(r.body).toContain(`${CAP}-byte`)
    expect(r.body).toContain('UNSIGNED-PAYLOAD')
    expect(state.captured).toBeUndefined()
    // The proxy survived: a follow-up request still works.
    const r2 = await curlViaProxy(
      state.proxyPort!,
      `https://${DEST}:${state.upstreamPort}/`,
      { awsSigv4: { akid: state.fakeAkid, secret: state.fakeSecret } },
    )
    expect(r2.status).toBe(200)
  }, 30000)
})

describe('multi-megabyte upload through the terminating relay', () => {
  // Regression test for the client→inner relay in terminateAndForward:
  // under Bun, pipe()'s pause/resume flow control corrupted the TLS byte
  // stream once a large upload queued writes (client saw bad_record_mac /
  // a mid-upload reset). 16 MiB trips the old code near-deterministically;
  // the relay must deliver every byte intact. See relayPullMode.
  const SIZE = 16 * 1024 * 1024
  const stack = makeStack({ maxSigv4ResignBodyBytes: SIZE })
  const { state } = stack
  let bodyDir: string
  let bigFile: string

  beforeAll(async () => {
    await stack.start()
    bodyDir = mkdtempSync(join(tmpdir(), 'srt-sigv4-big-'))
    bigFile = join(bodyDir, 'big')
    writeFileSync(bigFile, Buffer.alloc(SIZE, 'a'))
  })
  afterAll(async () => {
    rmSync(bodyDir, { recursive: true, force: true })
    await stack.stop()
  })

  test('a 16 MiB literal-hash PUT uploads intact and re-signs', async () => {
    state.captured = undefined
    const r = await curlViaProxy(
      state.proxyPort!,
      `https://${DEST}:${state.upstreamPort}/bucket/big`,
      {
        method: 'PUT',
        dataFile: bigFile,
        awsSigv4: { akid: state.fakeAkid, secret: state.fakeSecret },
        headers: ['Expect:'],
      },
    )
    expect(r.exit).toBe(0)
    expect(r.status).toBe(200)
    const captured = state.captured!
    expect(captured.body.length).toBe(SIZE)
    // Byte-intact, not just length-intact: the historical failure mode was
    // corruption inside the stream, which TLS turns into a hard error, but
    // assert content anyway so a silent-corruption regression cannot pass.
    expect(captured.body.every(b => b === 0x61)).toBe(true)
    verifyUpstreamSignature(captured)
  }, 30000)
})

describe('policies for non-re-signable SigV4 shapes', () => {
  function streamingHeaders(fakeAkid: string): string[] {
    return [
      `Authorization: AWS4-HMAC-SHA256 Credential=${fakeAkid}/20260715/${REGION}/${SERVICE}/aws4_request, ` +
        'SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=ff00',
      'X-Amz-Date: 20260715T000000Z',
      'X-Amz-Content-Sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD',
      'Content-Encoding: aws-chunked',
    ]
  }
  function sigv4aHeaders(fakeAkid: string): string[] {
    return [
      `Authorization: AWS4-ECDSA-P256-SHA256 Credential=${fakeAkid}/20260715/${SERVICE}/aws4_request, ` +
        'SignedHeaders=host;x-amz-date;x-amz-region-set, Signature=ff00',
      'X-Amz-Date: 20260715T000000Z',
      'X-Amz-Region-Set: *',
    ]
  }
  function presignedTarget(fakeAkid: string): string {
    return (
      '/key?X-Amz-Algorithm=AWS4-HMAC-SHA256' +
      `&X-Amz-Credential=${encodeURIComponent(`${fakeAkid}/20260715/${REGION}/${SERVICE}/aws4_request`)}` +
      '&X-Amz-Date=20260715T000000Z&X-Amz-Expires=3600' +
      '&X-Amz-SignedHeaders=host&X-Amz-Signature=ff00'
    )
  }

  describe('default: deny with a clear error naming the case', () => {
    const stack = makeStack({})
    const { state } = stack
    beforeAll(stack.start)
    afterAll(stack.stop)

    test('streaming', async () => {
      state.captured = undefined
      const r = await curlViaProxy(
        state.proxyPort!,
        `https://${DEST}:${state.upstreamPort}/bucket/key`,
        {
          method: 'PUT',
          data: 'chunked',
          headers: streamingHeaders(state.fakeAkid),
        },
      )
      expect(r.status).toBe(403)
      expect(r.body).toContain('streaming')
      expect(r.body).toContain('credentials.sigv4.streaming')
      expect(state.captured).toBeUndefined()
    }, 20000)

    test('presigned', async () => {
      state.captured = undefined
      const r = await curlViaProxy(
        state.proxyPort!,
        `https://${DEST}:${state.upstreamPort}${presignedTarget(state.fakeAkid)}`,
      )
      expect(r.status).toBe(403)
      expect(r.body).toContain('presigned')
      expect(r.body).toContain('credentials.sigv4.presigned')
      expect(state.captured).toBeUndefined()
    }, 20000)

    test('sigv4a', async () => {
      state.captured = undefined
      const r = await curlViaProxy(
        state.proxyPort!,
        `https://${DEST}:${state.upstreamPort}/`,
        { headers: sigv4aHeaders(state.fakeAkid) },
      )
      expect(r.status).toBe(403)
      expect(r.body).toContain('sigv4a')
      expect(r.body).toContain('credentials.sigv4.sigv4a')
      expect(state.captured).toBeUndefined()
    }, 20000)

    test('a presigned URL with an unmasked key id is not denied', async () => {
      state.captured = undefined
      const r = await curlViaProxy(
        state.proxyPort!,
        `https://${DEST}:${state.upstreamPort}${presignedTarget('AKIDUNRELATEDEXAMPLE')}`,
      )
      expect(r.status).toBe(200)
      expect(state.captured).toBeDefined()
    }, 20000)

    test('a junk Authorization header does not bypass the presigned policy', async () => {
      state.captured = undefined
      const r = await curlViaProxy(
        state.proxyPort!,
        `https://${DEST}:${state.upstreamPort}${presignedTarget(state.fakeAkid)}`,
        { headers: ['Authorization: Basic dXNlcjpwYXNz'] },
      )
      expect(r.status).toBe(403)
      expect(r.body).toContain('presigned')
      expect(state.captured).toBeUndefined()
    }, 20000)

    test('junk Authorization + unmasked presigned query stays untouched', async () => {
      state.captured = undefined
      const junkAuth = 'Basic dXNlcjpwYXNz'
      const r = await curlViaProxy(
        state.proxyPort!,
        `https://${DEST}:${state.upstreamPort}${presignedTarget('AKIDUNRELATEDEXAMPLE')}`,
        { headers: [`Authorization: ${junkAuth}`] },
      )
      expect(r.status).toBe(200)
      expect(singleHeader(state.captured!.headers.authorization)).toBe(junkAuth)
      expect(state.captured!.url).toContain('X-Amz-Signature=ff00')
    }, 20000)
  })

  describe('passthrough when configured', () => {
    const stack = makeStack({
      sigv4: {
        streaming: 'passthrough',
        presigned: 'passthrough',
        sigv4a: 'passthrough',
      },
    })
    const { state } = stack
    beforeAll(stack.start)
    afterAll(stack.stop)

    test('each shape is forwarded un-resigned', async () => {
      // streaming
      state.captured = undefined
      let r = await curlViaProxy(
        state.proxyPort!,
        `https://${DEST}:${state.upstreamPort}/bucket/key`,
        {
          method: 'PUT',
          data: 'chunked',
          headers: streamingHeaders(state.fakeAkid),
        },
      )
      expect(r.status).toBe(200)
      let auth = singleHeader(state.captured!.headers.authorization)!
      // Not re-signed: the client's fake-secret signature survives (and
      // will fail at a real upstream). Ordinary sentinel substitution
      // still ran on the header text.
      expect(auth).toContain('Signature=ff00')
      expect(auth).toContain(`Credential=${REAL_AKID}/`)

      // presigned
      state.captured = undefined
      r = await curlViaProxy(
        state.proxyPort!,
        `https://${DEST}:${state.upstreamPort}${presignedTarget(state.fakeAkid)}`,
      )
      expect(r.status).toBe(200)
      expect(state.captured!.url).toContain('X-Amz-Signature=ff00')

      // sigv4a
      state.captured = undefined
      r = await curlViaProxy(
        state.proxyPort!,
        `https://${DEST}:${state.upstreamPort}/`,
        { headers: sigv4aHeaders(state.fakeAkid) },
      )
      expect(r.status).toBe(200)
      auth = singleHeader(state.captured!.headers.authorization)!
      expect(auth).toStartWith('AWS4-ECDSA-P256-SHA256')
      expect(auth).toContain('Signature=ff00')
    }, 30000)
  })
})

describe('body substitution composes with SigV4 re-signing', () => {
  // Ordering contract under test: when a literal-hash SigV4 request
  // carries body-injectable sentinels, the proxy buffers the SUBSTITUTED
  // stream (body → bodyTransform → collectBody), hashes that, and signs —
  // the signature must cover the bytes actually sent upstream, never the
  // sentinel-bearing bytes the client wrote.
  const stack = makeStack({ bodySubstitution: true })
  const { state } = stack
  beforeAll(stack.start)
  afterAll(stack.stop)

  test('literal-hash POST: recomputed hash covers the substituted body (length-matched)', async () => {
    // Real value ≥ 47 bytes → the sentinel is padded to the same length,
    // so substitution cannot change the body length.
    const real = 'real-api-token-' + 'x'.repeat(45)
    const fake = state.sentinels.register('API_TOKEN_LONG', real, [DEST])
    expect(fake.length).toBe(real.length)

    state.captured = undefined
    const body = JSON.stringify({ token: fake, note: 'sentinel in body' })
    const r = await curlViaProxy(
      state.proxyPort!,
      `https://${DEST}:${state.upstreamPort}/compose/long`,
      {
        awsSigv4: { akid: state.fakeAkid, secret: state.fakeSecret },
        data: body,
        headers: ['Content-Type: application/json'],
      },
    )
    expect(r.exit).toBe(0)
    expect(r.status).toBe(200)
    const captured = state.captured!
    // Body substitution ran: upstream got the REAL token, never the fake.
    expect(captured.body.toString()).toContain(real)
    expect(captured.body.toString()).not.toContain(fake)
    // Length-matched → framing untouched.
    expect(singleHeader(captured.headers['content-length'])).toBe(
      String(Buffer.byteLength(body)),
    )
    // The crux: verifyUpstreamSignature recomputes the hash over the
    // body AS RECEIVED (post-substitution); the proxy's signature only
    // verifies if it hashed the substituted bytes too.
    verifyUpstreamSignature(captured)
  }, 20000)

  test('literal-hash POST: short secret re-frames; signature and Content-Length track the substituted body', async () => {
    // Real value < 47 bytes → the sentinel is longer than the real value,
    // substitution shrinks the body, and the buffered length becomes the
    // outgoing Content-Length.
    const real = 'short-real-token'
    const fake = state.sentinels.register('API_TOKEN_SHORT', real, [DEST])
    expect(fake.length).toBeGreaterThan(real.length)

    state.captured = undefined
    const body = JSON.stringify({ token: fake })
    const r = await curlViaProxy(
      state.proxyPort!,
      `https://${DEST}:${state.upstreamPort}/compose/short`,
      {
        awsSigv4: { akid: state.fakeAkid, secret: state.fakeSecret },
        data: body,
        headers: ['Content-Type: application/json'],
      },
    )
    expect(r.exit).toBe(0)
    expect(r.status).toBe(200)
    const captured = state.captured!
    expect(captured.body.toString()).toContain(real)
    expect(captured.body.toString()).not.toContain(fake)
    // Re-framed to the substituted (shorter) length, not the client's.
    expect(captured.body.length).toBeLessThan(Buffer.byteLength(body))
    expect(singleHeader(captured.headers['content-length'])).toBe(
      String(captured.body.length),
    )
    verifyUpstreamSignature(captured)
  }, 20000)
})
