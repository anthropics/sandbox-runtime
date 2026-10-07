/**
 * Streaming sentinel→real substitution for forwarded HTTP request bodies.
 *
 * The proxy substitutes masked-credential sentinels in request headers
 * (SentinelRegistry.substituteInHeaders); a credential a tool places in a
 * request body (JSON payload, form post) would otherwise reach the API as
 * the useless fake. Sentinels are exact-match strings over `[a-z0-9_-]`, so
 * they survive JSON, form-urlencoded, multipart, and XML verbatim — a raw
 * byte scan needs no format parsing. Bodies are never buffered whole:
 * memory is bounded by one chunk plus a hold-back of `maxSentinelLength - 1`
 * bytes carried across chunk boundaries.
 *
 * Fail-safe direction: substitution is fake→real, so a missed sentinel
 * (compressed body, base64-wrapped, split by an encoder) means the FAKE
 * value reaches the API and auth fails — never a leaked secret.
 */

import type { IncomingHttpHeaders, IncomingMessage } from 'node:http'
import { Transform, type Readable } from 'node:stream'
import { logForDebugging } from '../utils/debug.js'
import { BODYLESS_METHODS } from './request-filter.js'

/** One sentinel→real replacement, as raw bytes. */
export interface SentinelBufferPair {
  sentinel: Buffer
  realValue: Buffer
}

/**
 * Per-destination substitution set for masked-credential body rewriting.
 * Consulted once per request with the canonical destination host (the
 * CONNECT target, never the spoofable Host header). Empty/undefined means
 * no credential is injectable at the host — the caller must keep the
 * existing bare pipe, byte-identical.
 */
export type GetBodySubstitutions = (
  destHost: string,
) => SentinelBufferPair[] | undefined

/** True when substitution cannot change the body length. */
export function allLengthMatched(
  pairs: readonly SentinelBufferPair[],
): boolean {
  return pairs.every(p => p.sentinel.length === p.realValue.length)
}

/**
 * Build the substitution Transform for one forwarded request, or undefined
 * when the body must keep the existing bare pipe, byte-identical: bodyless
 * method, no credential injectable at `destHost`, or a Content-Encoding the
 * byte scan cannot see through.
 *
 * When substitution *can* change the body length, callers must buffer the
 * substituted body and set an exact Content-Length. Do not drop
 * Content-Length here: most requests to a host with a short credential
 * never contain a sentinel, and deleting the header reframes every upload
 * as chunked (GitHub release assets return 400 Bad Content-Length).
 */
export type BodySubstitutionPlan = {
  transform: Transform
  mayChangeLength: boolean
}

export function prepareBodySubstitution(
  getBodySubstitutions: GetBodySubstitutions | undefined,
  req: IncomingMessage,
  fwdHeaders: IncomingHttpHeaders,
  destHost: string,
): BodySubstitutionPlan | undefined {
  if (getBodySubstitutions === undefined) return undefined
  // A bodyless-method request can still carry a declared body (GET-with-body
  // APIs are legal HTTP and forwarded today) — skip only when there is
  // provably nothing to scan.
  const declaresBody =
    req.headers['content-length'] !== undefined ||
    req.headers['transfer-encoding'] !== undefined
  if (BODYLESS_METHODS.has(req.method ?? 'GET') && !declaresBody) {
    return undefined
  }
  const pairs = getBodySubstitutions(destHost)
  if (!pairs?.length) return undefined
  if (req.headers['content-encoding'] !== undefined) {
    // Fail-safe direction: an encoded body cannot be scanned for sentinel
    // bytes, so it passes through unchanged — a sentinel in it reaches the
    // upstream as the useless fake and auth fails, but the real secret
    // cannot leak. Warn so the resulting 401 is diagnosable.
    logForDebugging(
      `[body-substitution] ${destHost}: request body has Content-Encoding ` +
        `"${String(req.headers['content-encoding'])}"; masked-credential ` +
        `substitution skipped — a sentinel in this body reaches the ` +
        `upstream as the fake value`,
      { level: 'warn' },
    )
    return undefined
  }
  return {
    transform: createBodySubstitutionTransform(pairs),
    mayChangeLength: !allLengthMatched(pairs),
  }
}

/**
 * Transform that replaces every occurrence of each pair's sentinel bytes
 * with its real-value bytes.
 *
 * Boundary-safe: the last `maxSentinelLength - 1` bytes of each chunk are
 * held back and prepended to the next chunk, so a sentinel split across any
 * chunk boundary is still seen whole; the hold-back is flushed on stream
 * end. Replacement is left-to-right, resuming after each replacement — the
 * substituted real value is never rescanned. Backpressure propagates
 * through normal Transform semantics.
 */
export function createBodySubstitutionTransform(
  pairs: readonly SentinelBufferPair[],
): Transform {
  const maxLen = Math.max(...pairs.map(p => p.sentinel.length))
  let carry: Buffer | undefined
  return new Transform({
    transform(chunk: Buffer | string, encoding, callback) {
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, encoding)
      const work = carry?.length ? Buffer.concat([carry, buf]) : buf
      const { out, tail } = substitute(work, pairs, maxLen)
      carry = tail
      callback(null, out)
    },
    flush(callback) {
      // The hold-back cannot contain a complete sentinel — the scan loop
      // only stops when no full match remains — so it flushes verbatim.
      callback(null, carry?.length ? carry : undefined)
    },
  })
}

function substitute(
  work: Buffer,
  pairs: readonly SentinelBufferPair[],
  maxLen: number,
): { out: Buffer; tail: Buffer } {
  const parts: Buffer[] = []
  let pos = 0
  for (;;) {
    // Earliest match across all pairs (typically 1–3 sentinels per host).
    // Matching is earliest-position-then-registration-order, not
    // longest-match — sound because no sentinel is a substring of another
    // (registerWithSentinel's caller contract).
    let matchIdx = -1
    let matchPair: SentinelBufferPair | undefined
    for (const p of pairs) {
      const i = work.indexOf(p.sentinel, pos)
      if (i !== -1 && (matchIdx === -1 || i < matchIdx)) {
        matchIdx = i
        matchPair = p
      }
    }
    if (matchPair === undefined) break
    parts.push(work.subarray(pos, matchIdx), matchPair.realValue)
    pos = matchIdx + matchPair.sentinel.length
  }
  // Hold back the longest suffix that could still be a proper prefix of a
  // sentinel completed by the next chunk. A partial match of a sentinel of
  // length L occupies at most L-1 trailing bytes, so maxLen-1 always covers
  // it. Copied (not a subarray view) so the carry never aliases a buffer
  // the stream may reuse.
  const tailStart = Math.max(pos, work.length - (maxLen - 1))
  parts.push(work.subarray(pos, tailStart))
  return {
    out: Buffer.concat(parts),
    tail: Buffer.from(work.subarray(tailStart)),
  }
}

/** Cap for buffering a length-changing substituted body before setting Content-Length. */
export const MAX_BODY_SUBSTITUTION_BUFFER_BYTES = 64 * 1024 * 1024

export class BodySubstitutionTooLargeError extends Error {}

export function collectLimitedBody(
  body: Readable,
  maxBytes: number,
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []
    let total = 0
    const onData = (c: Buffer) => {
      total += c.length
      if (total > maxBytes) {
        chunks.length = 0
        body.removeListener('data', onData)
        reject(
          new BodySubstitutionTooLargeError(
            `request body exceeds ${maxBytes} bytes`,
          ),
        )
        return
      }
      chunks.push(c)
    }
    body.on('data', onData)
    body.once('end', () => resolve(Buffer.concat(chunks)))
    body.once('error', reject)
  })
}
