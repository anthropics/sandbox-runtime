/**
 * Request-level filter hook for the forward proxy.
 *
 * Library consumers supply a `filterRequest` callback via
 * `network.filterRequest`. It receives the parsed HTTP request (web-standard
 * `Request`) and returns a decision. Applies to plain HTTP through the proxy
 * and, when `tlsTerminate` is configured, to terminated HTTPS. The proxy
 * enforces the decision; the library does not bless any matching DSL.
 */

import { endRequestAfterResponse } from './emitted-connection.js'
import type {
  IncomingHttpHeaders,
  IncomingMessage,
  ServerResponse,
} from 'node:http'
import { isIP } from 'node:net'
import { PassThrough, Readable } from 'node:stream'
import { logForDebugging } from '../utils/debug.js'
import { isResolvedAddressDenied } from './resolved-address-guard.js'

export type RequestDecision = {
  action: 'allow' | 'deny'
  /**
   * Human-readable reason. For denials this is surfaced to the sandboxed
   * client in the response body so the agent can tell a policy block from a
   * network failure.
   */
  reason?: string
  /**
   * Deny only: the response status, 400 to 599. Anything else, or none,
   * answers 403.
   */
  status?: number
  /**
   * Deny only: a short reason code for the refusal (an HTTP token, e.g.
   * `decider`). A proxy created with `denyHeader` sends it as that
   * header's value; `denied` when none is given. Otherwise it is unused.
   */
  mark?: string
  /**
   * Allow only: headers to remove from the forwarded request. Names match
   * case-insensitively and with `-`, `_` and `.` treated as one character,
   * so `x-api-key` also removes `X_Api_Key` and `x.api.key`. Framing headers
   * (see setHeaders) are never removed.
   */
  removeHeaders?: string[]
  /**
   * Allow only: headers to set on the forwarded request, after
   * `removeHeaders`. A name given more than once gets every value, in
   * order; each name first removes every spelling of itself the client
   * sent. Framing headers (`host`, `content-length`, `transfer-encoding`,
   * `connection`, `upgrade`, `te`, `trailer`, `keep-alive`,
   * `proxy-connection`) are never set. A value holding a control character
   * other than tab, or a character above U+00FF, makes the whole decision
   * malformed and the request is denied. On the plain-HTTP path (`scheme`
   * is `'http'`) sets apply only when the proxy was created with
   * `plaintextHeaderSet`; without it an allow that carries any `setHeaders`
   * entry is refused with 403 rather than forwarded without them.
   */
  setHeaders?: Array<[string, string]>
  /**
   * Allow only: called once with the upstream response's status and
   * headers (hop-by-hop headers removed), just before the response is
   * written to the client. It gets a copy of the headers, so it observes
   * and cannot change the response. It may be async: a throw, or a
   * rejection of the promise it returns, is logged and ignored, and the
   * response is not held for it.
   */
  onResponse?: (status: number, headers: IncomingHttpHeaders) => void
}

/**
 * Called once per HTTP request that the proxy parses.
 *
 * - `request` is a web-standard `Request`: method, URL, headers, and a lazy
 *   `request.body` stream (one branch of a tee — reading it does not consume
 *   the bytes that get forwarded upstream). `request.signal` aborts when the
 *   client disconnects.
 * - **Throwing or rejecting denies the request.** This is the failure
 *   contract for a security boundary: a buggy policy fails closed. So does
 *   a decision that is not well-formed: an unknown action, a header name
 *   that is not an HTTP token, or a header value holding a control
 *   character other than tab or a character above U+00FF.
 */
export type FilterRequestCallback = (
  request: Request,
  info?: RequestInfo,
) => Promise<RequestDecision>

/** What the proxy knows about a request beyond the Request itself. */
export type RequestInfo = {
  /**
   * How the proxy received the request: `'https'` on the TLS-terminated
   * path, `'http'` when it arrived in cleartext (an absolute `https://` URI
   * sent in cleartext included).
   */
  scheme?: 'http' | 'https'
  /** The TLS server name the client sent, on the TLS-terminated path. */
  sni?: string
  /**
   * Set only for GET, HEAD and OPTIONS requests that declare a body, whose
   * Request is built without one: resolves true once the request is known
   * to carry body bytes (a non-zero Content-Length, or the first decoded
   * byte of a chunked body) and false when the body ends empty. A callback
   * that needs to have seen the whole request must refuse when it is true.
   */
  unshownBody?: () => Promise<boolean>
  /**
   * Where the request goes: the CONNECT target on the TLS-terminated
   * path, or the absolute URI's host and port on the plain path, in the
   * canonical spelling the allowlist evaluated.
   */
  target?: { host: string; port: number }
  /**
   * The request-target in origin form (path and query), exactly as it is
   * forwarded upstream; path rules should key on this. It is normalized
   * once on both paths (see normalizeRequestTarget) and that exact value
   * is forwarded. (With no filterRequest configured there is no hook to
   * judge the target: plain HTTP forwards the URL-parsed path and query,
   * and the TLS-terminated path forwards the client's bytes unchanged.)
   */
  requestTarget?: string
  /**
   * A copy of the client's header lines as received: name, value, name,
   * value, ... Some runtimes lower-case the names.
   */
  rawHeaders?: string[]
}

/**
 * Mutate the headers that will be sent upstream, in place.
 *
 * Runs after the allow/deny decision and hop-by-hop stripping, immediately
 * before the upstream request is built. `destHost` is the canonical
 * destination host (the CONNECT target on the TLS-terminated path, or the
 * absolute-URI host on the plain-HTTP path, after canonicalizeHost — the
 * spelling the allowlist evaluated) — never the client-supplied Host
 * header, which is spoofable.
 */
export type MutateForwardedHeaders = (
  headers: IncomingHttpHeaders,
  destHost: string,
) => void

export const BODYLESS_METHODS = new Set(['GET', 'HEAD', 'OPTIONS'])

/** Methods whose response echoes the request; never forwarded. */
const ECHO_METHODS = new Set(['TRACE', 'TRACK'])

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
  if (res.destroyed) {
    req.destroy()
    return
  }
  if (res.writableFinished) {
    endRequestAfterResponse(req)
    return
  }
  res.once('finish', () => endRequestAfterResponse(req))
  res.once('close', () => {
    if (!res.writableFinished) req.destroy()
  })
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
  info?: RequestInfo,
  denyHeader?: string,
  canSetHeaders = true,
): Promise<{ body: Readable; decision: RequestDecision } | null> {
  const method = req.method ?? 'GET'
  let forCallback: ReadableStream<Uint8Array> | undefined
  let forUpstream: Readable = req
  let shim: PassThrough | undefined
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
    const teeSource = new PassThrough()
    shim = teeSource
    teeSource.on('error', () => {})
    req.pipe(teeSource)
    const web = Readable.toWeb(teeSource) as ReadableStream<Uint8Array>
    const [a, b] = web.tee()
    forCallback = a
    forUpstream = Readable.fromWeb(b)
    const upstreamBranch = forUpstream
    // The caller only wires its own 'error' handler after this function
    // resolves; a client abort during the filterRequest await must not
    // land on a listener-less stream.
    upstreamBranch.on('error', () => {})
    req.on('error', err => {
      teeSource.end()
      upstreamBranch.destroy(err)
    })
  }

  // TRACE (and TRACK, which some servers treat the same) asks the server
  // to echo the request back: forwarded with a credential the decision
  // attached, the echo would hand that credential to the client. Refused
  // here, before the callback is asked and before anything is dialled.
  // Node's and Bun's HTTP parsers reject TRACK as an unknown method (their
  // own 400) before this runs; it is listed for a parser that would not.
  if (ECHO_METHODS.has(method.toUpperCase())) {
    const reason = `the ${method} method is not forwarded`
    onDeny?.(method, url, reason)
    deny(
      res,
      { action: 'deny', status: 405, reason, mark: 'method_refused' },
      denyHeader,
    )
    forCallback?.cancel().catch(() => {})
    endDeniedBody(req, res, forUpstream, shim)
    return null
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
    deny(res, { action: 'deny', reason, mark: 'bad_request' }, denyHeader)
    forCallback?.cancel().catch(() => {})
    endDeniedBody(req, res, forUpstream, shim)
    return null
  }

  let decision: RequestDecision
  try {
    decision = await filterRequest(
      webReq,
      forCallback && bodylessMethod
        ? { ...info, unshownBody: unshownBodyProbe(req, forCallback) }
        : info,
    )
  } catch (err) {
    decision = {
      action: 'deny',
      reason: `sandbox policy check failed: ${(err as Error).message}`,
    }
  }
  const malformed = malformedDecisionReason(decision)
  if (malformed !== undefined) {
    decision = {
      action: 'deny',
      reason: `malformed filterRequest decision: ${malformed}`,
    }
  }
  // A caller that cannot apply header sets (cleartext, without the opt-in)
  // refuses the request: forwarding it without a header the decision relied
  // on would fail open, and the callback has no way to learn of the drop.
  if (
    !canSetHeaders &&
    decision.action === 'allow' &&
    (decision.setHeaders?.length ?? 0) > 0
  ) {
    decision = {
      action: 'deny',
      reason: PLAINTEXT_HEADER_SET_REASON,
      mark: 'plaintext_header_set',
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
    return { body: forUpstream, decision }
  }

  onDeny?.(method, url, decision.reason ?? DEFAULT_DENY_REASON)
  deny(res, decision, denyHeader)
  endDeniedBody(req, res, forUpstream, shim)
  return null
}

/**
 * After a deny, stop the request: destroy a teed body's upstream branch at
 * once, and the request itself once the answer is out. The shim breaks the
 * old fromWeb→tee→toWeb cancel cascade that used to destroy req; without
 * this a denied client keeps uploading into a stalled pipe and holds the
 * connection open. Destroying req before the answer is flushed loses the
 * answer under Node (for a request without a body, req is what destroys
 * the socket).
 *
 * A teed body's bytes stop going to the shim at once and are dropped from
 * then on: the tee is cancelled, and a byte the shim passed on to its
 * closed web stream would throw (Bun: "Controller is already closed").
 */
function endDeniedBody(
  req: IncomingMessage,
  res: ServerResponse,
  forUpstream: Readable,
  shim: PassThrough | undefined,
): void {
  if (shim !== undefined) {
    req.unpipe(shim)
    shim.pause()
    req.resume()
  }
  if (forUpstream !== req) forUpstream.destroy()
  destroyAfterResponse(req, res)
}

/**
 * Whether a request whose body the callback's Request leaves out carries
 * any body bytes. A non-zero Content-Length answers at once; otherwise the
 * callback's branch of the tee is read, which holds decoded body bytes, so
 * empty reads are skipped and only the end of the body means "none".
 */
function unshownBodyProbe(
  req: IncomingMessage,
  branch: ReadableStream<Uint8Array>,
): () => Promise<boolean> {
  let answer: Promise<boolean> | undefined
  const probe = async (): Promise<boolean> => {
    if (
      !req.headers['transfer-encoding'] &&
      Number(req.headers['content-length']) > 0
    ) {
      return true
    }
    const reader = branch.getReader()
    try {
      for (;;) {
        const { done, value } = await reader.read()
        if (done) return false
        if (value.byteLength > 0) return true
      }
    } finally {
      reader.cancel().catch(() => {})
    }
  }
  return () => (answer ??= probe())
}

const PLAINTEXT_HEADER_SET_REASON =
  'the allow decision sets headers, and headers are not set on plain-HTTP ' +
  'requests unless plaintext header sets are enabled; nothing was forwarded'

// RFC 9110 token; the same set Node's own header-name check accepts.
const HEADER_NAME = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/

/**
 * Why a decision cannot be applied as given, or undefined when it can. The
 * callback's return is only typed, not checked, and a decision that would
 * throw half-way through forwarding must deny instead.
 */
function malformedDecisionReason(decision: unknown): string | undefined {
  if (typeof decision !== 'object' || decision === null) return 'not an object'
  const d = decision as Record<string, unknown>
  if (d.action !== 'allow' && d.action !== 'deny') return 'unknown action'
  if (d.reason !== undefined && typeof d.reason !== 'string') {
    return 'reason is not a string'
  }
  if (d.status !== undefined && typeof d.status !== 'number') {
    return 'status is not a number'
  }
  if (
    d.mark !== undefined &&
    (typeof d.mark !== 'string' || !HEADER_NAME.test(d.mark))
  ) {
    return 'mark is not a reason code'
  }
  if (d.action === 'deny') return undefined
  if (d.onResponse !== undefined && typeof d.onResponse !== 'function') {
    return 'onResponse is not a function'
  }
  const removals = d.removeHeaders
  if (removals !== undefined) {
    if (!Array.isArray(removals)) return 'removeHeaders is not an array'
    for (const name of removals) {
      if (typeof name !== 'string' || !HEADER_NAME.test(name)) {
        return 'removeHeaders holds an invalid header name'
      }
    }
  }
  const sets = d.setHeaders
  if (sets !== undefined) {
    if (!Array.isArray(sets)) return 'setHeaders is not an array'
    for (const entry of sets) {
      if (!Array.isArray(entry) || entry.length !== 2) {
        return 'setHeaders holds an entry that is not a [name, value] pair'
      }
      const [name, value] = entry
      if (typeof name !== 'string' || !HEADER_NAME.test(name)) {
        return 'setHeaders holds an invalid header name'
      }
      if (typeof value !== 'string' || !isValidHeaderValue(value)) {
        return 'setHeaders holds an invalid header value'
      }
    }
  }
  return undefined
}

/**
 * A field value may carry HTAB but no other control character, and no
 * character above U+00FF (Node's HTTP client throws on those).
 */
function isValidHeaderValue(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i)
    if ((code < 0x20 && code !== 0x09) || code === 0x7f || code > 0xff) {
      return false
    }
  }
  return true
}

function deny(
  res: ServerResponse,
  decision: RequestDecision,
  denyHeader: string | undefined,
): void {
  const s = decision.status
  const status =
    s !== undefined && Number.isInteger(s) && s >= 400 && s <= 599 ? s : 403
  respondDenied(
    res,
    decision.reason ?? DEFAULT_DENY_REASON,
    denyHeader !== undefined
      ? { name: denyHeader, value: decision.mark ?? 'denied' }
      : undefined,
    status,
  )
}

/**
 * A request-target in origin form (path and query), normalized once: the
 * URL parser resolves dot segments and reads `%2e` as `.`, and a run of
 * leading slashes becomes one. Normalizing the result again changes
 * nothing, so an HTTP client that re-normalizes on the way out sends the
 * same bytes. Accepts origin form, an absolute http(s) URI (whose
 * authority is dropped; the caller names the host) and `*` for OPTIONS;
 * returns undefined for any other shape, which the caller refuses.
 */
export function normalizeRequestTarget(
  raw: string,
  method: string | undefined,
): string | undefined {
  if (raw === '*') return method === 'OPTIONS' ? raw : undefined
  let url: URL
  try {
    // The fixed prefix keeps an origin-form target in the path: a leading
    // `//` is never read as an authority.
    url = new URL(raw.startsWith('/') ? `http://origin.invalid${raw}` : raw)
  } catch {
    return undefined
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return undefined
  return `${url.pathname.replace(/^\/{2,}/, '/')}${url.search}`
}

/**
 * A request-target as the client spelled it, for a proxy that forwards it
 * unchanged and lets its policy match it exactly: dot segments and
 * percent-escapes, encoded or not, are kept, so an unusual spelling of an
 * admitted path is simply not that path. Origin form only (`/` first, and
 * not `//` or `/\`), with no `#`, space, control byte or DEL; with
 * `absolute`, the path and query of an absolute http(s) URI, as spelled.
 * Any other shape (authority form, asterisk form, or absolute form where
 * origin form is required) is undefined, which the caller answers 400.
 */
export function requestTargetAsSpelled(
  raw: string,
  { absolute = false }: { absolute?: boolean } = {},
): string | undefined {
  let target = raw
  if (absolute) {
    const m = /^https?:\/\/[^/?#]*/i.exec(raw)
    if (!m) return undefined
    target = raw.slice(m[0].length)
    if (target === '' || target.startsWith('?')) target = '/' + target
  }
  if (!target.startsWith('/') || target.startsWith('//')) return undefined
  if (target.startsWith('/\\')) return undefined
  for (let i = 0; i < target.length; i++) {
    const c = target.charCodeAt(i)
    if (c <= 0x20 || c === 0x7f || c === 0x23) return undefined
  }
  return target
}

/**
 * A header name folded for comparison: lower case, with `_` and `.` read
 * as `-`. Upstreams differ in which separators they treat as equivalent,
 * so a removal must cover every spelling.
 */
export function foldHeaderName(name: string): string {
  return name.toLowerCase().replace(/[_.]/g, '-')
}

const UNSETTABLE_HEADERS = new Set([
  'host',
  'connection',
  'keep-alive',
  'proxy-connection',
  'transfer-encoding',
  'te',
  'trailer',
  'upgrade',
  'content-length',
])

/** Remove every header whose folded name is one of `names`, in place. */
export function removeHeadersFolded(
  headers: IncomingHttpHeaders,
  names: Iterable<string>,
): void {
  const drop = new Set<string>()
  for (const n of names) drop.add(foldHeaderName(n))
  if (drop.size === 0) return
  for (const k of Object.keys(headers)) {
    if (drop.has(foldHeaderName(k))) delete headers[k]
  }
}

/**
 * Apply an allow decision's header edits to the headers about to be sent
 * upstream, in place: first remove every header whose folded name (see
 * foldHeaderName) is a removal or a name the decision sets, then add the
 * set values. Sets are grouped by folded name (`x-foo` and `x_foo` are one
 * header, emitted under the first spelling), and framing headers are
 * neither removed nor set.
 */
export function applyHeaderEdits(
  headers: IncomingHttpHeaders,
  decision: Pick<RequestDecision, 'removeHeaders' | 'setHeaders'>,
): void {
  // Grouped by folded name, emitted under the first spelling given.
  const sets = new Map<string, { name: string; values: string[] }>()
  for (const [name, value] of decision.setHeaders ?? []) {
    const folded = foldHeaderName(name)
    if (UNSETTABLE_HEADERS.has(folded)) continue
    const entry = sets.get(folded) ?? { name: name.toLowerCase(), values: [] }
    if (!/[\r\n\0]/.test(value)) entry.values.push(value)
    sets.set(folded, entry)
  }
  const removals = (decision.removeHeaders ?? []).filter(
    n => !UNSETTABLE_HEADERS.has(foldHeaderName(n)),
  )
  removeHeadersFolded(headers, [...removals, ...sets.keys()])
  for (const { name, values } of sets.values()) {
    if (values.length > 0) {
      headers[name] = values.length === 1 ? values[0] : values
    }
  }
}

/** Call an allow decision's onResponse, containing its failures. */
export function notifyResponse(
  decision: RequestDecision | undefined,
  status: number,
  headers: IncomingHttpHeaders,
): void {
  if (!decision?.onResponse) return
  const copy: IncomingHttpHeaders = {}
  for (const [name, value] of Object.entries(headers)) {
    copy[name] = Array.isArray(value) ? [...value] : value
  }
  try {
    const returned: unknown = decision.onResponse(status, copy)
    if (isThenable(returned)) returned.then(undefined, logResponseFailure)
  } catch (err) {
    logResponseFailure(err)
  }
}

function isThenable(value: unknown): value is PromiseLike<unknown> {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as { then?: unknown }).then === 'function'
  )
}

function logResponseFailure(err: unknown): void {
  logForDebugging(
    `[request-filter] onResponse failed: ${(err as Error)?.message ?? String(err)}`,
    { level: 'error' },
  )
}

/**
 * The Host header of a request as a list of its values, from the raw
 * header lines (a runtime keeps only the first of repeated Host headers in
 * `headers`).
 */
export function hostHeaderValues(rawHeaders: string[]): string[] {
  const out: string[] = []
  for (let i = 0; i + 1 < rawHeaders.length; i += 2) {
    if (rawHeaders[i]!.toLowerCase() === 'host') out.push(rawHeaders[i + 1]!)
  }
  return out
}

/**
 * Why a request's Host header, TLS server name or absolute-form authority
 * does not name the host and port it is being sent to, or undefined when
 * they agree.
 *
 * A server name must be the target's host, in any case. A Host header (or
 * the authority of an absolute-form request-target) names the target when
 * it is the target's host in any case, with the target's port after one
 * colon, or with no port when the target's port is the scheme's default,
 * and with brackets only around an IPv6 address; any other shape (an empty
 * value, a trailing colon or dot, brackets around a name) names no host.
 * More than one Host header is a mismatch; none is not (HTTP/1.1 parsers
 * already require one).
 */
export function hostMismatch(
  hostHeaders: string[],
  serverName: string | undefined,
  target: { hostname: string; port: number; defaultPort: number },
  requestTargetAuthority?: string,
): string | undefined {
  const want = target.hostname.toLowerCase()
  if (serverName !== undefined && serverName.toLowerCase() !== want) {
    return 'TLS server name does not match the request target'
  }
  if (
    requestTargetAuthority !== undefined &&
    !namesTarget(requestTargetAuthority, want, target)
  ) {
    return 'request-target authority does not match the request target'
  }
  if (hostHeaders.length === 0) return undefined
  if (hostHeaders.length > 1) return 'more than one Host header'
  if (!namesTarget(hostHeaders[0]!, want, target)) {
    return 'Host header does not match the request target'
  }
  return undefined
}

function namesTarget(
  authority: string,
  want: string,
  target: { port: number; defaultPort: number },
): boolean {
  const parsed = hostAndPort(authority)
  if (parsed === undefined || parsed.host.toLowerCase() !== want) return false
  return parsed.port === ''
    ? target.port === target.defaultPort
    : parsed.port === String(target.port)
}

/** A Host header's host and port ("" when none), or undefined for any other shape. */
function hostAndPort(h: string): { host: string; port: string } | undefined {
  let host = h
  let rest = ''
  if (h.startsWith('[')) {
    const end = h.indexOf(']')
    if (end < 0) return undefined
    host = h.slice(1, end)
    rest = h.slice(end + 1)
    if (isIP(host) !== 6) return undefined
  } else {
    const i = h.indexOf(':')
    if (i >= 0) {
      host = h.slice(0, i)
      rest = h.slice(i)
    }
    if (/[[\]]/.test(host)) return undefined
  }
  if (rest === '') return { host, port: '' }
  const port = rest.slice(1)
  if (rest[0] !== ':' || port === '' || /[[\]:]/.test(port)) return undefined
  return { host, port }
}

const DEFAULT_DENY_TAG = 'blocked-by-sandbox-runtime'

/**
 * The proxy's standard policy-denial response as raw bytes, for paths that
 * answer on a bare socket (CONNECT): 403 with an `X-Proxy-Error` tag and
 * the reason as the body.
 */
/**
 * The header that marks a denial: `X-Proxy-Error: <tag>` for a tag, or a
 * caller's own header and value.
 */
export type DenyMark = string | { name: string; value: string }

function denyMarkHeader(mark: DenyMark): [string, string] {
  return typeof mark === 'string'
    ? ['X-Proxy-Error', mark]
    : [mark.name, mark.value]
}

export function rawDenied(
  reason: string,
  tag: DenyMark = DEFAULT_DENY_TAG,
): string {
  const [name, value] = denyMarkHeader(tag)
  return (
    'HTTP/1.1 403 Forbidden\r\n' +
    'Content-Type: text/plain\r\n' +
    `${name}: ${value}\r\n` +
    '\r\n' +
    reason
  )
}

/**
 * Write the proxy's standard policy-denial response: 403 with the reason
 * in the body, so the sandboxed client can tell a policy block from a
 * network failure. Shared by filterRequest denials and other in-proxy
 * policy decisions (e.g. SigV4 shapes that cannot be re-signed).
 */
export function respondDenied(
  res: ServerResponse,
  reason: string,
  tag: DenyMark = DEFAULT_DENY_TAG,
  status = 403,
): void {
  logForDebugging(`[proxy] deny: ${reason}`)
  if (res.headersSent || res.destroyed) {
    res.destroy()
    return
  }
  const [name, value] = denyMarkHeader(tag)
  res.writeHead(status, {
    'Content-Type': 'text/plain',
    [name]: value,
  })
  res.end(reason + '\n')
}

/**
 * Answer a failed upstream leg: a resolved-address refusal is a policy
 * denial (403 with the reason); anything else is a 502, or a bare destroy
 * once headers are out.
 */
export function respondUpstreamError(
  res: ServerResponse,
  err: Error,
  denyHeader?: string,
): void {
  if (isResolvedAddressDenied(err)) {
    respondDenied(
      res,
      err.message,
      denyHeader !== undefined
        ? { name: denyHeader, value: 'address_not_allowed' }
        : undefined,
    )
  } else if (!res.headersSent) {
    res.writeHead(502, { 'Content-Type': 'text/plain' })
    res.end('Bad Gateway')
  } else {
    res.destroy()
  }
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
