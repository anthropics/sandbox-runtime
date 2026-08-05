/**
 * Request-level filter hook for the forward proxy.
 *
 * Library consumers supply a `filterRequest` callback via
 * `network.filterRequest`. It receives the parsed HTTP request (web-standard
 * `Request`) and returns a decision. Applies to plain HTTP through the proxy
 * and, when `tlsTerminate` is configured, to terminated HTTPS. The proxy
 * enforces the decision; the library does not bless any matching DSL.
 */

import type {
  IncomingHttpHeaders,
  IncomingMessage,
  ServerResponse,
} from 'node:http'
import { PassThrough, Readable } from 'node:stream'
import { logForDebugging } from '../utils/debug.js'

export type RequestDecision = {
  action: 'allow' | 'deny'
  /**
   * Human-readable reason. For denials this is surfaced to the sandboxed
   * client in the response body so the agent can tell a policy block from a
   * network failure.
   */
  reason?: string
}

/**
 * Called once per HTTP request that the proxy parses.
 *
 * - `request` is a web-standard `Request`: method, URL, headers, and a lazy
 *   `request.body` stream (one branch of a tee — reading it does not consume
 *   the bytes that get forwarded upstream). `request.signal` aborts when the
 *   client disconnects.
 * - **Throwing or rejecting denies the request.** This is the failure
 *   contract for a security boundary: a buggy policy fails closed.
 */
export type FilterRequestCallback = (
  request: Request,
) => Promise<RequestDecision>

/**
 * Mutate the headers that will be sent upstream, in place.
 *
 * Runs after the allow/deny decision and hop-by-hop stripping, immediately
 * before the upstream request is built. `destHost` is the canonical
 * destination host (the CONNECT target on the TLS-terminated path, or the
 * absolute-URI host on the plain-HTTP path) — never the client-supplied
 * Host header, which is spoofable.
 */
export type MutateForwardedHeaders = (
  headers: IncomingHttpHeaders,
  destHost: string,
) => void

export const BODYLESS_METHODS = new Set(['GET', 'HEAD', 'OPTIONS'])

/**
 * User-facing reason when a filterRequest denial doesn't supply one. This
 * text reaches the sandboxed client (403 body) and the model
 * (<sandbox_violations>), so it names the policy, not the internal hook.
 */
export const DEFAULT_DENY_REASON = 'denied by sandbox policy'

/**
 * Destroy a denied client's request only after the 403 has flushed —
 * destroying the shared socket in the same tick can RST the response
 * away (observed on Node; the unread request body makes close send RST).
 */
function destroyAfterResponse(req: IncomingMessage, res: ServerResponse): void {
  if (res.writableFinished || res.destroyed) {
    req.destroy()
    return
  }
  res.once('finish', () => req.destroy())
  res.once('close', () => req.destroy())
}

/**
 * Build a `Request`, run the callback, and if denied write the 403 response
 * and return `null`. On allow, returns the body stream the caller must pipe
 * upstream — this is the original `IncomingMessage` when no tee was needed
 * (GET/HEAD/OPTIONS), or the upstream-side branch of the tee otherwise.
 * Callers must pipe the returned stream (not `req`) to the outbound request.
 *
 * For methods that carry a body, `req` is converted to a web stream and
 * `tee()`'d: one branch goes to the callback's `Request.body`, the other is
 * returned for the caller to forward. If the callback never reads its
 * branch, we cancel it after the decision so the tee does not buffer the
 * entire upload.
 */
export async function decideAndRespond(
  filterRequest: FilterRequestCallback,
  req: IncomingMessage,
  res: ServerResponse,
  url: string,
  signal: AbortSignal,
  onDeny?: (method: string, url: string, reason: string) => void,
): Promise<Readable | null> {
  const method = req.method ?? 'GET'
  let forCallback: ReadableStream<Uint8Array> | undefined
  let forUpstream: Readable = req
  // Gate on a declared body, not just the method: a GET/HEAD/OPTIONS with
  // Content-Length or Transfer-Encoding is legal HTTP and its body must go
  // through the tee like any other — skipping it here would hide the body
  // from filterRequest AND (with transfer-encoding stripped as hop-by-hop)
  // let its decoded bytes be written raw after a complete-framed bodyless
  // request upstream: a request-smuggling primitive.
  // Truthiness, not presence: an empty Content-Length/Transfer-Encoding
  // value declares nothing and must not trigger teeing or re-framing.
  const declaresBody = Boolean(
    req.headers['content-length'] || req.headers['transfer-encoding'],
  )
  const bodylessMethod = BODYLESS_METHODS.has(method)
  if (!bodylessMethod || declaresBody) {
    // Never hand toWeb a stream that can error: when its source errors,
    // the toWeb/tee/fromWeb bridge leaks the error as internal promise
    // rejections (and, under Bun, uncaught exceptions) that no userland
    // listener can catch. A client abort mid-body becomes a clean EOF on
    // the shim instead, and the abort is propagated by destroying the
    // upstream branch directly — a truncated body must never be forwarded
    // framed as complete (chunked framing would otherwise emit a valid
    // terminator; on the SigV4 path a truncated buffer would be signed).
    // The shim's own error listener covers the tee cancelling it while
    // the client is still piping.
    const shim = new PassThrough()
    shim.on('error', () => {})
    req.pipe(shim)
    const web = Readable.toWeb(shim) as ReadableStream<Uint8Array>
    const [a, b] = web.tee()
    forCallback = a
    forUpstream = Readable.fromWeb(b)
    const upstreamBranch = forUpstream
    // The caller only wires its own 'error' handler after this function
    // resolves; a client abort during the filterRequest await must not
    // land on a listener-less stream.
    upstreamBranch.on('error', () => {})
    req.on('error', err => {
      shim.end()
      upstreamBranch.destroy(err)
    })
  }

  let webReq: Request
  try {
    // Fetch-spec Requests reject a body on GET/HEAD (Node throws; Bun is
    // lenient) — a GET with a declared body is still teed above so the
    // upstream leg stays framed, but the callback sees a bodyless Request.
    const callbackBody =
      forCallback && !bodylessMethod
        ? { body: forCallback, duplex: 'half' as const }
        : {}
    webReq = new Request(url, {
      method,
      headers: incomingHeaders(req),
      signal,
      ...callbackBody,
    })
  } catch (err) {
    // Malformed URL/headers from the client — deny rather than crash.
    const reason = `malformed request: ${(err as Error).message}`
    onDeny?.(method, url, reason)
    deny(res, { action: 'deny', reason })
    forCallback?.cancel().catch(() => {})
    forUpstream.destroy()
    // The shim breaks the old fromWeb→tee→toWeb cancel cascade that used
    // to destroy req; without this a denied client keeps uploading into a
    // stalled pipe and holds the connection open.
    if (forUpstream !== req) destroyAfterResponse(req, res)
    return null
  }

  let decision: RequestDecision
  try {
    decision = await filterRequest(webReq)
  } catch (err) {
    decision = {
      action: 'deny',
      reason: `sandbox policy check failed: ${(err as Error).message}`,
    }
  }

  // If the callback didn't read its branch, cancel it so tee() stops
  // buffering bytes nobody will consume. If it did, the tee already buffered
  // whatever was read; the upstream branch sees the same bytes.
  if (forCallback && !webReq.bodyUsed) {
    // cancel() rejects with the stream's stored error if it already
    // failed; that rejection must not escape.
    forCallback.cancel().catch(() => {})
  }

  if (decision.action === 'allow') {
    logForDebugging(`[request-filter] allow ${method} ${url}`)
    return forUpstream
  }

  onDeny?.(method, url, decision.reason ?? DEFAULT_DENY_REASON)
  deny(res, decision)
  forUpstream.destroy()
  if (forUpstream !== req) destroyAfterResponse(req, res)
  return null
}

function deny(res: ServerResponse, decision: RequestDecision): void {
  respondDenied(res, decision.reason ?? DEFAULT_DENY_REASON)
}

/**
 * Write the proxy's standard policy-denial response: 403 with the reason
 * in the body, so the sandboxed client can tell a policy block from a
 * network failure. Shared by filterRequest denials and other in-proxy
 * policy decisions (e.g. SigV4 shapes that cannot be re-signed).
 */
export function respondDenied(res: ServerResponse, reason: string): void {
  logForDebugging(`[request-filter] deny: ${reason}`)
  if (res.headersSent) {
    res.destroy()
    return
  }
  res.writeHead(403, {
    'Content-Type': 'text/plain',
    'X-Proxy-Error': 'blocked-by-sandbox-runtime',
  })
  res.end(reason + '\n')
}

function incomingHeaders(req: IncomingMessage): Headers {
  const h = new Headers()
  for (const [k, v] of Object.entries(req.headers)) {
    if (v === undefined) continue
    if (Array.isArray(v)) {
      for (const vv of v) h.append(k, vv)
    } else {
      h.append(k, v)
    }
  }
  return h
}
