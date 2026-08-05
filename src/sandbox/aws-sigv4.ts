/**
 * AWS Signature Version 4 protocol code for the TLS-terminating proxy.
 *
 * A masked AWS credential hands the sandboxed process a fake access key id
 * and secret, so any SigV4 signature the client computes is an HMAC over
 * the fake secret — header substitution can swap the access key id in the
 * credential scope, but it cannot fix the signature. The proxy therefore
 * re-signs: strip the client's Authorization, keep its credential scope /
 * signed-header set / x-amz-date, and recompute the signature with the
 * real secret over the request as it actually goes upstream. Prior art:
 * awslabs/aws-sigv4-proxy.
 *
 * This module is pure protocol code — request classification,
 * Authorization parsing, canonical-request construction, and signing —
 * validated against the official aws-sig-v4-test-suite vectors
 * (test/fixtures/aws-sigv4-suite). The credential-pair registry and the
 * proxy-side planner live in credential-aws-pairs.ts.
 */

import { createHash, createHmac } from 'node:crypto'
import type { IncomingHttpHeaders } from 'node:http'

export const SIGV4_ALGORITHM = 'AWS4-HMAC-SHA256'
export const SIGV4A_ALGORITHM = 'AWS4-ECDSA-P256-SHA256'
export const UNSIGNED_PAYLOAD = 'UNSIGNED-PAYLOAD'

/**
 * How a request references AWS SigV4 authentication:
 *
 * - `header-sigv4`: Authorization is `AWS4-HMAC-SHA256 ...` — the case the
 *   proxy can re-sign.
 * - `streaming`: `x-amz-content-sha256` declares an aws-chunked payload
 *   (`STREAMING-*`) whose chunk signatures chain off the seed signature —
 *   re-signing would require rewriting the body's per-chunk signatures.
 * - `presigned`: the signature lives in the query (`X-Amz-Algorithm` /
 *   `X-Amz-Signature`) — re-signing would rewrite the URL itself. Applies
 *   whenever the Authorization header does not itself classify: a non-AWS
 *   Authorization value (e.g. `Basic ...`) must not exempt the query, or
 *   adding a junk header would bypass the presigned policy.
 * - `sigv4a`: Authorization is `AWS4-ECDSA-P256-SHA256 ...` — asymmetric
 *   signing keyed off the secret via ECDSA; there is no shared-key HMAC to
 *   recompute without the client's derived private key.
 */
export type Sigv4Kind = 'header-sigv4' | 'streaming' | 'presigned' | 'sigv4a'

export interface Sigv4Detection {
  kind: Sigv4Kind
  /**
   * Access key id the signature references — from the Authorization
   * `Credential=<akid>/...` scope, or `X-Amz-Credential` in the query for
   * presigned URLs. Callers exact-match this against registered masked
   * pairs to decide whether the request is theirs to handle.
   */
  accessKeyId: string
}

/**
 * Classify a request's SigV4 shape from headers and the request-target
 * only (no body inspection). Returns null when the request carries no
 * recognizable SigV4 signature.
 */
export function detectSigv4(
  headers: IncomingHttpHeaders,
  requestTarget: string,
): Sigv4Detection | null {
  const auth = singleHeader(headers.authorization)
  if (auth !== undefined && auth.startsWith(SIGV4A_ALGORITHM)) {
    const akid = credentialAccessKeyId(auth)
    if (akid !== undefined) return { kind: 'sigv4a', accessKeyId: akid }
  } else if (auth !== undefined && auth.startsWith(SIGV4_ALGORITHM)) {
    const akid = credentialAccessKeyId(auth)
    if (akid !== undefined) {
      const contentSha = singleHeader(headers['x-amz-content-sha256'])
      // Covers STREAMING-AWS4-HMAC-SHA256-PAYLOAD, its -TRAILER variant,
      // and STREAMING-UNSIGNED-PAYLOAD-TRAILER: all declare an aws-chunked
      // body the plain re-sign path cannot reproduce.
      const kind = contentSha?.startsWith('STREAMING-')
        ? 'streaming'
        : 'header-sigv4'
      return { kind, accessKeyId: akid }
    }
  }

  // Presigned URL: the signature is in the query string. Checked whenever
  // the Authorization header did not classify above — an unrecognized or
  // malformed Authorization value alongside presigned sentinel params must
  // not turn the request invisible to the presigned policy.
  const q = requestTarget.indexOf('?')
  if (q === -1) return null
  const params = new URLSearchParams(requestTarget.slice(q + 1))
  if (params.get('X-Amz-Algorithm') !== SIGV4_ALGORITHM) return null
  if (!params.has('X-Amz-Signature')) return null
  const credential = params.get('X-Amz-Credential')
  if (!credential) return null
  const akid = credential.split('/')[0]
  return akid ? { kind: 'presigned', accessKeyId: akid } : null
}

/** `Credential=<akid>/...` access key id from an Authorization value. */
function credentialAccessKeyId(auth: string): string | undefined {
  const m = /Credential=([^/,\s]+)\//.exec(auth)
  return m?.[1]
}

export interface ParsedSigv4Authorization {
  accessKeyId: string
  /** Credential-scope date (yyyymmdd). */
  date: string
  region: string
  service: string
  /** Lowercase signed header names, in the order the client listed them. */
  signedHeaders: string[]
  signature: string
}

/**
 * Parse an `AWS4-HMAC-SHA256 Credential=..., SignedHeaders=...,
 * Signature=...` Authorization value. Returns null when any component is
 * missing or the credential scope is not the 5-part
 * `<akid>/<date>/<region>/<service>/aws4_request` form.
 */
export function parseSigv4Authorization(
  auth: string,
): ParsedSigv4Authorization | null {
  if (!auth.startsWith(SIGV4_ALGORITHM)) return null
  const cred = /Credential=([^,\s]+)/.exec(auth)?.[1]
  const signedHeaders = /SignedHeaders=([^,\s]+)/.exec(auth)?.[1]
  const signature = /Signature=([0-9a-fA-F]+)/.exec(auth)?.[1]
  if (!cred || !signedHeaders || !signature) return null
  const parts = cred.split('/')
  if (parts.length !== 5 || parts[4] !== 'aws4_request') return null
  const [accessKeyId, date, region, service] = parts
  if (!accessKeyId || !date || !region || !service) return null
  return {
    accessKeyId,
    date,
    region,
    service,
    signedHeaders: signedHeaders.split(';').map(h => h.toLowerCase()),
    signature,
  }
}

/**
 * Strict RFC 3986 percent-encoding: everything except unreserved
 * characters (A-Za-z0-9 - _ . ~) is encoded. encodeURIComponent leaves
 * `!'()*` raw; SigV4 requires them encoded.
 */
export function uriEncode(s: string): string {
  return encodeURIComponent(s).replace(
    /[!'()*]/g,
    c => '%' + c.charCodeAt(0).toString(16).toUpperCase(),
  )
}

/**
 * Canonical URI per SigV4: for S3 the raw request path is used verbatim
 * (no dot-segment normalization, no re-encoding — S3 object keys are
 * byte-significant and the service verifies against the wire path); for
 * every other service, dot segments are resolved and the path is
 * percent-encoded once more on top of its wire encoding ('/' preserved).
 * Matches the AWS SDK signer (smithy SignatureV4.getCanonicalPath) and
 * awslabs/aws-sigv4-proxy, which disables path escaping for s3 only.
 */
export function canonicalUri(rawPath: string, service: string): string {
  if (rawPath === '') return '/'
  if (service === 's3') return rawPath
  const segments: string[] = []
  for (const seg of rawPath.split('/')) {
    if (seg === '' || seg === '.') continue
    if (seg === '..') segments.pop()
    else segments.push(seg)
  }
  const trailing = segments.length > 0 && rawPath.endsWith('/') ? '/' : ''
  const normalized = `/${segments.join('/')}${trailing}`
  return uriEncode(normalized).replace(/%2F/gi, '/')
}

/**
 * Canonical query string per SigV4: each key and value is decoded then
 * strictly re-encoded, pairs are sorted by encoded key then encoded
 * value, and joined with '&'. A literal '+' is treated as a plus (RFC
 * 3986), not a space.
 */
export function canonicalQueryString(rawQuery: string): string {
  if (rawQuery === '') return ''
  const pairs: Array<[string, string]> = []
  for (const part of rawQuery.split('&')) {
    if (part === '') continue
    const eq = part.indexOf('=')
    const rawKey = eq === -1 ? part : part.slice(0, eq)
    const rawValue = eq === -1 ? '' : part.slice(eq + 1)
    pairs.push([uriEncode(safeDecode(rawKey)), uriEncode(safeDecode(rawValue))])
  }
  pairs.sort(([ak, av], [bk, bv]) =>
    ak < bk ? -1 : ak > bk ? 1 : av < bv ? -1 : av > bv ? 1 : 0,
  )
  return pairs.map(([k, v]) => `${k}=${v}`).join('&')
}

function safeDecode(s: string): string {
  try {
    return decodeURIComponent(s)
  } catch {
    return s
  }
}

/** SigV4 "trimall": strip leading/trailing whitespace, collapse runs. */
function trimall(value: string): string {
  return value.trim().replace(/[ \t]+/g, ' ')
}

export interface Sigv4SignInput {
  method: string
  /**
   * Origin-form request-target exactly as forwarded upstream
   * (`/path?query`). The canonical URI/query are derived from it.
   */
  requestTarget: string
  /**
   * Headers as they will be sent upstream. `host` is not looked up here
   * (the proxy deletes it and lets the runtime re-derive it) — its value
   * comes from `hostHeader`.
   */
  headers: IncomingHttpHeaders
  /** Host header value the upstream connection will carry. */
  hostHeader: string
  /**
   * Lowercase header names to sign. Sorted internally; every name other
   * than `host` must be present in `headers`.
   */
  signedHeaders: readonly string[]
  /** Hex SHA-256 of the payload, or the UNSIGNED-PAYLOAD marker. */
  payloadHash: string
  /** ISO 8601 basic timestamp (e.g. 20150830T123600Z). */
  amzDate: string
  scope: { date: string; region: string; service: string }
}

/**
 * Build the SigV4 canonical request. Throws if a signed header (other
 * than `host`) is absent from `headers` — the caller must have validated
 * presence, since signing an empty value the upstream never sees would
 * produce a signature the service rejects confusingly.
 */
export function buildCanonicalRequest(input: Sigv4SignInput): string {
  const q = input.requestTarget.indexOf('?')
  const rawPath =
    q === -1 ? input.requestTarget : input.requestTarget.slice(0, q)
  const rawQuery = q === -1 ? '' : input.requestTarget.slice(q + 1)

  const names = [...input.signedHeaders].map(h => h.toLowerCase()).sort()
  const headerLines: string[] = []
  for (const name of names) {
    const value = name === 'host' ? input.hostHeader : input.headers[name]
    if (value === undefined) {
      throw new Error(`signed header "${name}" is missing from the request`)
    }
    const canonical = Array.isArray(value)
      ? value.map(trimall).join(',')
      : trimall(String(value))
    headerLines.push(`${name}:${canonical}`)
  }

  return [
    input.method.toUpperCase(),
    canonicalUri(rawPath, input.scope.service),
    canonicalQueryString(rawQuery),
    headerLines.join('\n') + '\n',
    names.join(';'),
    input.payloadHash,
  ].join('\n')
}

/** String-to-sign over a canonical request. */
export function buildStringToSign(
  canonicalRequest: string,
  amzDate: string,
  scope: { date: string; region: string; service: string },
): string {
  return [
    SIGV4_ALGORITHM,
    amzDate,
    `${scope.date}/${scope.region}/${scope.service}/aws4_request`,
    sha256Hex(canonicalRequest),
  ].join('\n')
}

/** kSigning = HMAC-chain(AWS4+secret, date, region, service, terminator). */
export function deriveSigningKey(
  secretAccessKey: string,
  scope: { date: string; region: string; service: string },
): Buffer {
  const kDate = hmac(`AWS4${secretAccessKey}`, scope.date)
  const kRegion = hmac(kDate, scope.region)
  const kService = hmac(kRegion, scope.service)
  return hmac(kService, 'aws4_request')
}

export interface Sigv4SignResult {
  /** Full Authorization header value. */
  authorization: string
  signature: string
  canonicalRequest: string
  stringToSign: string
}

/**
 * Sign a request with SigV4. The caller supplies the credential scope and
 * timestamp taken from the client's (fake-signed) request so the re-signed
 * request stays byte-compatible with what the client believes it sent.
 */
export function signSigv4(
  input: Sigv4SignInput & { accessKeyId: string; secretAccessKey: string },
): Sigv4SignResult {
  const canonicalRequest = buildCanonicalRequest(input)
  const stringToSign = buildStringToSign(
    canonicalRequest,
    input.amzDate,
    input.scope,
  )
  const signature = createHmac(
    'sha256',
    deriveSigningKey(input.secretAccessKey, input.scope),
  )
    .update(stringToSign, 'utf8')
    .digest('hex')
  const names = [...input.signedHeaders].map(h => h.toLowerCase()).sort()
  const scopeStr = `${input.scope.date}/${input.scope.region}/${input.scope.service}/aws4_request`
  return {
    authorization:
      `${SIGV4_ALGORITHM} Credential=${input.accessKeyId}/${scopeStr}, ` +
      `SignedHeaders=${names.join(';')}, Signature=${signature}`,
    signature,
    canonicalRequest,
    stringToSign,
  }
}

export function sha256Hex(data: string | Buffer): string {
  return createHash('sha256').update(data).digest('hex')
}

function hmac(key: string | Buffer, data: string): Buffer {
  return createHmac('sha256', key).update(data, 'utf8').digest()
}

/** First value of a possibly-repeated header, or undefined. */
export function singleHeader(
  v: string | string[] | undefined,
): string | undefined {
  return Array.isArray(v) ? v[0] : v
}
