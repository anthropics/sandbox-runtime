import { describe, test, expect } from 'bun:test'
import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import type { IncomingHttpHeaders } from 'node:http'
import {
  buildCanonicalRequest,
  buildStringToSign,
  canonicalQueryString,
  canonicalUri,
  detectSigv4,
  parseSigv4Authorization,
  sha256Hex,
  signSigv4,
  UNSIGNED_PAYLOAD,
} from '../../src/sandbox/aws-sigv4.js'

// Official aws-sig-v4-test-suite constants (see the suite's docs): every
// vector signs with these credentials, region, and service.
const SUITE_AKID = 'AKIDEXAMPLE'
const SUITE_SECRET = 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY'
const SUITE_REGION = 'us-east-1'
const SUITE_SERVICE = 'service'
const SUITE_DATE = '20150830'
// get-vanilla-with-session-token: the .req carries no token header; the
// signer is expected to add x-amz-security-token with this value and
// include it in the signed set — the same injection path the proxy takes
// when a masked pair carries a session token the client never saw.
const SUITE_SESSION_TOKEN =
  '6e86291e8372ff2a2260956d9b8aae1d763fbf315fa00fa31553b73ebf194267'

const SUITE_DIR = join(import.meta.dir, '..', 'fixtures', 'aws-sigv4-suite')

interface Vector {
  name: string
  method: string
  requestTarget: string
  headers: IncomingHttpHeaders
  body: string
  creq: string
  sts: string
  authz: string
}

/** Parse a test-suite `.req` file (raw HTTP/1.1 request text). */
function parseReq(raw: string): {
  method: string
  requestTarget: string
  headers: IncomingHttpHeaders
  body: string
} {
  const headerEnd = raw.indexOf('\n\n')
  const head = headerEnd === -1 ? raw : raw.slice(0, headerEnd)
  const body = headerEnd === -1 ? '' : raw.slice(headerEnd + 2)
  const lines = head.split('\n')
  const requestLine = lines[0]!
  const firstSpace = requestLine.indexOf(' ')
  const method = requestLine.slice(0, firstSpace)
  // The target may itself contain spaces (get-space); the version suffix
  // is always the trailing ' HTTP/1.1'.
  const requestTarget = requestLine
    .slice(firstSpace + 1)
    .replace(/ HTTP\/1\.1$/, '')
  const headers: IncomingHttpHeaders = {}
  for (const line of lines.slice(1)) {
    if (line === '') continue
    const colon = line.indexOf(':')
    const name = line.slice(0, colon).toLowerCase()
    const value = line.slice(colon + 1)
    const existing = headers[name]
    if (existing === undefined) {
      headers[name] = value
    } else if (Array.isArray(existing)) {
      existing.push(value)
    } else {
      headers[name] = [existing, value]
    }
  }
  return { method, requestTarget, headers, body }
}

function loadVectors(dir: string, out: Vector[] = []): Vector[] {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue
    const name = entry.name
    const sub = join(dir, name)
    const reqPath = join(sub, `${name}.req`)
    if (existsSync(reqPath)) {
      const read = (ext: string) =>
        readFileSync(join(sub, `${name}.${ext}`), 'utf8').replace(/\n$/, '')
      out.push({
        name,
        ...parseReq(readFileSync(reqPath, 'utf8')),
        creq: read('creq'),
        sts: read('sts'),
        authz: read('authz'),
      })
    } else {
      loadVectors(sub, out)
    }
  }
  return out
}

describe('SigV4 signer against the official aws-sig-v4-test-suite', () => {
  const vectors = loadVectors(SUITE_DIR)
  // The fixture set covers GET with query params, path normalization,
  // UTF-8/unreserved encoding, header trimming/duplicates, POST with a
  // literal body hash, and session tokens. Guard against a silently
  // missing fixture directory.
  expect(vectors.length).toBeGreaterThanOrEqual(20)

  for (const v of vectors) {
    test(v.name, () => {
      const headers = { ...v.headers }
      const signedHeaders = Object.keys(headers)
      if (v.name === 'get-vanilla-with-session-token') {
        headers['x-amz-security-token'] = SUITE_SESSION_TOKEN
        signedHeaders.push('x-amz-security-token')
      }
      const input = {
        method: v.method,
        requestTarget: v.requestTarget,
        headers,
        hostHeader: String(headers.host),
        signedHeaders,
        payloadHash: sha256Hex(v.body),
        amzDate: String(headers['x-amz-date']),
        scope: {
          date: SUITE_DATE,
          region: SUITE_REGION,
          service: SUITE_SERVICE,
        },
      }
      const result = signSigv4({
        ...input,
        accessKeyId: SUITE_AKID,
        secretAccessKey: SUITE_SECRET,
      })
      expect(result.canonicalRequest).toBe(v.creq)
      expect(result.stringToSign).toBe(v.sts)
      expect(result.authorization).toBe(v.authz)
    })
  }
})

describe('canonicalUri', () => {
  test('s3 uses the raw path verbatim — no normalization or re-encoding', () => {
    expect(canonicalUri('/bucket//key/./with%20space', 's3')).toBe(
      '/bucket//key/./with%20space',
    )
    expect(canonicalUri('', 's3')).toBe('/')
  })

  test('non-s3 normalizes dot segments and re-encodes the wire path', () => {
    // An already-encoded wire path gets encoded once more ("double
    // encoding" relative to the original key), matching the AWS SDK
    // signer applied to the escaped path.
    expect(canonicalUri('/a%20b/c', 'execute-api')).toBe('/a%2520b/c')
    expect(canonicalUri('/example/..', 'service')).toBe('/')
    expect(canonicalUri('//example//', 'service')).toBe('/example/')
  })
})

describe('canonicalQueryString', () => {
  test('sorts by key then value and strictly RFC3986-encodes', () => {
    expect(canonicalQueryString('b=2&a=2&a=1')).toBe('a=1&a=2&b=2')
    expect(canonicalQueryString('k=a+b')).toBe('k=a%2Bb')
    expect(canonicalQueryString('key')).toBe('key=')
  })
})

describe('UNSIGNED-PAYLOAD signing', () => {
  test('the marker is signed verbatim as the payload hash', () => {
    const input = {
      method: 'PUT',
      requestTarget: '/bucket/key',
      headers: {
        'x-amz-date': '20150830T123600Z',
        'x-amz-content-sha256': UNSIGNED_PAYLOAD,
      } as IncomingHttpHeaders,
      hostHeader: 's3.amazonaws.com',
      signedHeaders: ['host', 'x-amz-date', 'x-amz-content-sha256'],
      payloadHash: UNSIGNED_PAYLOAD,
      amzDate: '20150830T123600Z',
      scope: { date: SUITE_DATE, region: SUITE_REGION, service: 's3' },
    }
    const creq = buildCanonicalRequest(input)
    expect(creq.endsWith(`\n${UNSIGNED_PAYLOAD}`)).toBe(true)
    const sts = buildStringToSign(creq, input.amzDate, input.scope)
    const { authorization, signature } = signSigv4({
      ...input,
      accessKeyId: SUITE_AKID,
      secretAccessKey: SUITE_SECRET,
    })
    expect(sts).toContain(sha256Hex(creq))
    expect(authorization).toContain(`Signature=${signature}`)
    // Deterministic: same input, same signature.
    expect(
      signSigv4({
        ...input,
        accessKeyId: SUITE_AKID,
        secretAccessKey: SUITE_SECRET,
      }).signature,
    ).toBe(signature)
  })
})

describe('buildCanonicalRequest failure modes', () => {
  test('throws when a signed header is missing', () => {
    expect(() =>
      buildCanonicalRequest({
        method: 'GET',
        requestTarget: '/',
        headers: {},
        hostHeader: 'example.amazonaws.com',
        signedHeaders: ['host', 'x-amz-date'],
        payloadHash: sha256Hex(''),
        amzDate: '20150830T123600Z',
        scope: { date: SUITE_DATE, region: SUITE_REGION, service: 'service' },
      }),
    ).toThrow('x-amz-date')
  })
})

describe('parseSigv4Authorization', () => {
  const AUTH =
    'AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, ' +
    'SignedHeaders=host;x-amz-date, Signature=abc123def456'

  test('parses credential scope, signed headers, and signature', () => {
    const parsed = parseSigv4Authorization(AUTH)
    expect(parsed).toEqual({
      accessKeyId: 'AKIDEXAMPLE',
      date: '20150830',
      region: 'us-east-1',
      service: 'service',
      signedHeaders: ['host', 'x-amz-date'],
      signature: 'abc123def456',
    })
  })

  test('rejects malformed values', () => {
    expect(parseSigv4Authorization('Bearer token')).toBeNull()
    expect(
      parseSigv4Authorization(
        'AWS4-HMAC-SHA256 Credential=AKID/20150830/us-east-1/aws4_request, ' +
          'SignedHeaders=host, Signature=ff',
      ),
    ).toBeNull()
    expect(
      parseSigv4Authorization('AWS4-HMAC-SHA256 SignedHeaders=host'),
    ).toBeNull()
  })
})

describe('detectSigv4 classification', () => {
  const AKID = 'fake_value_e5b0c442-98fc-1c14-9afb-f4c8996fb924'
  const HEADER_AUTH =
    `AWS4-HMAC-SHA256 Credential=${AKID}/20150830/us-east-1/s3/aws4_request, ` +
    'SignedHeaders=host;x-amz-date, Signature=ff00'

  test('header-sigv4: AWS4-HMAC-SHA256 Authorization', () => {
    expect(detectSigv4({ authorization: HEADER_AUTH }, '/')).toEqual({
      kind: 'header-sigv4',
      accessKeyId: AKID,
    })
  })

  test('header-sigv4 with a literal x-amz-content-sha256 stays header-sigv4', () => {
    expect(
      detectSigv4(
        { authorization: HEADER_AUTH, 'x-amz-content-sha256': sha256Hex('') },
        '/',
      ),
    ).toEqual({ kind: 'header-sigv4', accessKeyId: AKID })
  })

  test('streaming: STREAMING-AWS4-HMAC-SHA256-PAYLOAD content hash', () => {
    for (const marker of [
      'STREAMING-AWS4-HMAC-SHA256-PAYLOAD',
      'STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER',
      'STREAMING-UNSIGNED-PAYLOAD-TRAILER',
    ]) {
      expect(
        detectSigv4(
          {
            authorization: HEADER_AUTH,
            'x-amz-content-sha256': marker,
            'content-encoding': 'aws-chunked',
          },
          '/key',
        ),
      ).toEqual({ kind: 'streaming', accessKeyId: AKID })
    }
  })

  test('presigned: no Authorization, signature in the query', () => {
    const target =
      '/key?X-Amz-Algorithm=AWS4-HMAC-SHA256' +
      `&X-Amz-Credential=${encodeURIComponent(`${AKID}/20150830/us-east-1/s3/aws4_request`)}` +
      '&X-Amz-Date=20150830T123600Z&X-Amz-Expires=3600' +
      '&X-Amz-SignedHeaders=host&X-Amz-Signature=ff00'
    expect(detectSigv4({}, target)).toEqual({
      kind: 'presigned',
      accessKeyId: AKID,
    })
  })

  test('sigv4a: AWS4-ECDSA-P256-SHA256 Authorization', () => {
    const auth =
      `AWS4-ECDSA-P256-SHA256 Credential=${AKID}/20150830/s3/aws4_request, ` +
      'SignedHeaders=host;x-amz-date;x-amz-region-set, Signature=ff00'
    expect(
      detectSigv4({ authorization: auth, 'x-amz-region-set': '*' }, '/key'),
    ).toEqual({ kind: 'sigv4a', accessKeyId: AKID })
  })

  test('non-AWS requests are not detected', () => {
    expect(detectSigv4({ authorization: 'Bearer abc' }, '/')).toBeNull()
    expect(detectSigv4({}, '/?a=1')).toBeNull()
    expect(detectSigv4({}, '/')).toBeNull()
    // Query mentions X-Amz-Signature but not the SigV4 algorithm.
    expect(detectSigv4({}, '/?X-Amz-Signature=ff00')).toBeNull()
  })

  test('a non-AWS Authorization header does not hide a presigned query', () => {
    const target =
      '/key?X-Amz-Algorithm=AWS4-HMAC-SHA256' +
      `&X-Amz-Credential=${encodeURIComponent(`${AKID}/20150830/us-east-1/s3/aws4_request`)}` +
      '&X-Amz-Date=20150830T123600Z&X-Amz-Expires=3600' +
      '&X-Amz-SignedHeaders=host&X-Amz-Signature=ff00'
    // Junk Authorization values must not exempt the query from
    // classification, or the presigned policy could be bypassed by
    // adding one alongside the presigned sentinel params.
    for (const authorization of [
      'Basic dXNlcjpwYXNz',
      'Bearer abc',
      // Starts with the SigV4 algorithm but carries no Credential scope.
      'AWS4-HMAC-SHA256 garbage',
      // SigV4A shape without a parsable Credential.
      'AWS4-ECDSA-P256-SHA256 garbage',
    ]) {
      expect(detectSigv4({ authorization }, target)).toEqual({
        kind: 'presigned',
        accessKeyId: AKID,
      })
    }
  })

  test('a classifiable header signature wins over a presigned query', () => {
    const queryAkid = 'AKIDQUERYEXAMPLE'
    const target =
      '/key?X-Amz-Algorithm=AWS4-HMAC-SHA256' +
      `&X-Amz-Credential=${encodeURIComponent(`${queryAkid}/20150830/us-east-1/s3/aws4_request`)}` +
      '&X-Amz-Signature=ff00'
    expect(detectSigv4({ authorization: HEADER_AUTH }, target)).toEqual({
      kind: 'header-sigv4',
      accessKeyId: AKID,
    })
  })
})
