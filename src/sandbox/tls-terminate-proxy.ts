/**
 * In-process TLS termination for HTTPS traffic through the forward proxy.
 *
 * When a MitmCA is configured, the forward proxy hands CONNECT requests here
 * instead of opening an opaque byte tunnel. We terminate the client's TLS
 * with a per-host leaf cert (see mitm-leaf.ts), parse the decrypted stream
 * as HTTP/1.1, and re-issue each request upstream over a real TLS
 * connection. The optional `filterRequest` callback runs on each parsed
 * request before it is forwarded.
 */

import {
  createServer as createHttpsServer,
  request as httpsRequest,
} from 'node:https'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { connect, isIP } from 'node:net'
import { unlink } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { Duplex, Readable } from 'node:stream'
import { logForDebugging } from '../utils/debug.js'
import type { MitmCA } from './mitm-ca.js'
import {
  decideAndRespond,
  respondDenied,
  type FilterRequestCallback,
  type MutateForwardedHeaders,
} from './request-filter.js'
import {
  prepareBodySubstitution,
  type GetBodySubstitutions,
} from './body-substitution.js'
import { mintLeafCert, secureContextFor } from './mitm-leaf.js'
import { stripHopByHop } from './parent-proxy.js'
import { sha256Hex } from './aws-sigv4.js'
import type { PlanSigv4 } from './credential-aws-pairs.js'

/**
 * Upper bound on the request body the proxy will buffer to recompute a
 * literal SigV4 body hash. The signature must cover the exact bytes sent
 * upstream, so buffering is unavoidable for that shape — but without a
 * cap a sandboxed client could pin arbitrary host memory with one large
 * signed upload (awslabs/aws-sigv4-proxy buffers with no limit; we fail
 * closed instead). Bodies over the cap are denied with a 403; clients
 * with larger payloads should sign UNSIGNED-PAYLOAD, which streams.
 */
export const MAX_SIGV4_RESIGN_BODY_BYTES = 64 * 1024 * 1024

/** Rejection cause when a body exceeds {@link MAX_SIGV4_RESIGN_BODY_BYTES}. */
class BodyTooLargeError extends Error {}

/**
 * True if `buf` starts with a TLS Handshake record header.
 *
 * Three bytes: content type 0x16 (Handshake) + legacy_record_version
 * 0x03,0x00–0x03. RFC 8446 §5.1 froze the record-layer version (TLS 1.3+
 * negotiate via the supported_versions extension, the wire header stays
 * ≤0x0303), so this holds for current and future TLS. Same predicate as
 * mitmproxy `starts_like_tls_record`; nginx `ssl_preread` routes on byte 0
 * alone and HAProxy `req.ssl_hello_type` reads 9 bytes to also extract the
 * handshake type — 3 is the established middle ground for "is this TLS".
 *
 * Routing heuristic, not a security check: a non-TLS stream that happens to
 * start 16 03 0x is handed to the TLS server, which then rejects it properly.
 */
export function looksLikeClientHello(buf: Buffer): boolean {
  return (
    buf.length >= 3 && buf[0] === 0x16 && buf[1] === 0x03 && buf[2]! <= 0x03
  )
}

/**
 * Wait for the client's first post-CONNECT bytes and report whether they look
 * like a TLS ClientHello. The caller must already have written the
 * `200 Connection Established` line — clients don't send until they see it.
 *
 * Any bytes consumed here are returned in `.head` so the caller can forward
 * them to whichever downstream (terminate or opaque tunnel) it picks. The
 * socket is left paused so further bytes buffer until the downstream
 * `pipe()` resumes it.
 */
export function peekForClientHello(
  socket: Duplex,
  head: Buffer,
): Promise<{ isTLS: boolean; head: Buffer }> {
  if (head.length >= 3) {
    return Promise.resolve({ isTLS: looksLikeClientHello(head), head })
  }
  return new Promise(resolve => {
    let buf = head
    const done = () => {
      socket.removeListener('data', onData)
      socket.removeListener('close', done)
      resolve({ isTLS: looksLikeClientHello(buf), head: buf })
    }
    const onData = (chunk: Buffer) => {
      // Pause synchronously so anything after this chunk buffers for the
      // downstream pipe() rather than being dropped in flowing mode.
      socket.pause()
      buf = buf.length ? Buffer.concat([buf, chunk]) : chunk
      if (buf.length >= 3) return done()
      socket.resume()
    }
    socket.on('data', onData)
    socket.once('close', done)
  })
}

/**
 * Relay `src` into `dst` with paused-mode reads (`'readable'` + `read()`)
 * instead of `src.pipe(dst)`.
 *
 * `pipe()` throttles a flowing source with `pause()`/`resume()`, and under
 * Bun a socket delivered by an http server's `'connect'` event corrupts its
 * byte stream across those pause/resume cycles once writes queue (reliably
 * reproducible with multi-megabyte uploads; the TLS server behind the relay
 * then fails record MAC verification and the client sees `bad_record_mac` /
 * a mid-upload reset). Pull-mode reads never call `pause()` and provide the
 * same flow control: `read()` is only called while `dst` has buffer space,
 * so the kernel backpressures the peer identically. Do not replace this
 * with `pipe()` — under Node both are equivalent, but under Bun only this
 * form is safe for CONNECT-upgraded sockets.
 */
function relayPullMode(src: Duplex, dst: Duplex): void {
  const pump = (): void => {
    let chunk: Buffer | string | null
    while ((chunk = src.read() as Buffer | string | null) !== null) {
      if (!dst.write(chunk)) {
        dst.once('drain', pump)
        return
      }
    }
    src.once('readable', pump)
  }
  pump()
  src.once('end', () => dst.end())
}

export type TerminateTarget = {
  hostname: string
  port: number
  /**
   * Additional trusted CA(s) for the proxy's outbound TLS leg. Unset → system
   * roots + NODE_EXTRA_CA_CERTS. Primarily a test seam (NODE_EXTRA_CA_CERTS
   * is read at process start, so tests can't set it from inside the suite).
   */
  upstreamCA?: string | Buffer | Array<string | Buffer>
  /**
   * Called when filterRequest denies a parsed request, with the verified
   * method/URL and the decision reason. Carried on the target so the
   * per-connection request handler (which closes over `target`) can reach
   * it without an extra parameter on every layer.
   */
  onFilterRequestDeny?: (method: string, url: string, reason: string) => void
}

/**
 * Terminate the client's TLS on `socket`, parse the decrypted HTTP/1.1
 * stream, and forward each request to `target` over a fresh upstream TLS
 * connection.
 *
 * Preconditions: the caller has already validated `target` against the
 * domain allowlist; this function does not re-check it.
 *
 * Implementation: we stand up a short-lived https.Server on a unix socket
 * and pipe the client socket through it. The Node-idiomatic alternative —
 * feeding the raw socket to a non-listening server via
 * `emit('connection', socket)` — is not implemented by Bun's https.Server,
 * and SRT runs under both runtimes. A per-connection server lets the
 * request handler close over `target` (which carries the originally-
 * requested host:port) without socket-keyed lookups.
 */
export function terminateAndForward(
  ca: MitmCA,
  filterRequest: FilterRequestCallback | undefined,
  mutateHeaders: MutateForwardedHeaders | undefined,
  getBodySubstitutions: GetBodySubstitutions | undefined,
  socket: Duplex,
  head: Buffer,
  target: TerminateTarget,
  planSigv4?: PlanSigv4,
  maxSigv4BodyBytes: number = MAX_SIGV4_RESIGN_BODY_BYTES,
): void {
  // ALPN advertises HTTP/1.1 only — terminating HTTP/2 would require a frame
  // parser; clients negotiate down. The base secureContext covers clients
  // that don't send SNI; SNICallback covers everyone else.
  const baseLeaf = mintLeafCert(ca, target.hostname)
  const inner = createHttpsServer({
    ALPNProtocols: ['http/1.1'],
    cert: baseLeaf.certPem,
    key: baseLeaf.keyPem,
    SNICallback: (servername, cb) => {
      try {
        cb(null, secureContextFor(ca, servername || target.hostname))
      } catch (err) {
        cb(err as Error)
      }
    },
  })

  inner.on('request', (req, res) => {
    // A client abort mid-request destroys req/res with an error; with no
    // listener it escapes as an uncaughtException (the runtime emits it
    // from node:_http_server).
    req.on('error', err => {
      logForDebugging(`[tls-terminate] client request error: ${err.message}`, {
        level: 'error',
      })
    })
    res.on('error', err => {
      logForDebugging(`[tls-terminate] client response error: ${err.message}`, {
        level: 'error',
      })
    })
    forwardUpstreamGuarded(
      filterRequest,
      mutateHeaders,
      getBodySubstitutions,
      req,
      res,
      target,
      planSigv4,
      maxSigv4BodyBytes,
    )
  })
  inner.on('clientError', (err, sock) => {
    // Post-handshake parse errors / resets on the loopback leg would
    // otherwise escalate to an uncaughtException, same class as the
    // request-stream errors handled above.
    logForDebugging(
      `[tls-terminate] client connection error for ${target.hostname}: ${err.message}`,
      { level: 'error' },
    )
    sock.destroy()
  })
  inner.on('tlsClientError', (err, sock) => {
    logForDebugging(
      `[tls-terminate] client TLS error for ${target.hostname}: ${err.message}`,
      { level: 'error' },
    )
    sock.destroy()
  })
  inner.on('upgrade', (_req, sock) => {
    // WebSocket / non-HTTP over TLS — out of scope for now.
    logForDebugging('[tls-terminate] upgrade request refused', {
      level: 'warn',
    })
    sock.destroy()
  })

  const sockPath = innerSocketPath()
  const cleanup = () => {
    inner.close()
    unlink(sockPath, () => {})
  }
  inner.on('error', err => {
    logForDebugging(
      `[tls-terminate] inner server listen failed: ${err.message}`,
      { level: 'error' },
    )
    socket.destroy()
    cleanup()
  })
  inner.listen(sockPath, () => {
    const loop = connect({ path: sockPath })
    loop.on('error', err => {
      logForDebugging(`[tls-terminate] inner loopback failed: ${err.message}`, {
        level: 'error',
      })
      socket.destroy()
      cleanup()
    })
    loop.once('connect', () => {
      // The caller wrote `200 Connection Established` before sniffing for the
      // ClientHello; `head` holds whatever the sniff consumed.
      if (head.length) loop.write(head)
      relayPullMode(socket, loop)
      loop.pipe(socket)
    })
    socket.on('error', () => loop.destroy())
    socket.once('close', () => {
      loop.destroy()
      cleanup()
    })
    loop.once('close', () => socket.destroy())
  })
  inner.unref()
}

/**
 * Destroy a denied client's request only after the 403 has flushed —
 * destroying the shared socket in the same tick can RST the response away.
 */
function destroyAfterDenial(req: IncomingMessage, res: ServerResponse): void {
  if (res.writableFinished || res.destroyed) {
    req.destroy()
    return
  }
  res.once('finish', () => req.destroy())
  res.once('close', () => req.destroy())
}

function forwardUpstreamGuarded(
  ...args: Parameters<typeof forwardUpstream>
): void {
  // Fire-and-forget from the request handler: a rejection (e.g. a
  // synchronous throw writing a denial to a client that already reset)
  // must not become an unhandledRejection.
  forwardUpstream(...args).catch(err => {
    logForDebugging(
      `[tls-terminate] forwardUpstream failed: ${(err as Error).message}`,
      { level: 'error' },
    )
  })
}

async function forwardUpstream(
  filterRequest: FilterRequestCallback | undefined,
  mutateHeaders: MutateForwardedHeaders | undefined,
  getBodySubstitutions: GetBodySubstitutions | undefined,
  req: IncomingMessage,
  res: ServerResponse,
  target: TerminateTarget,
  planSigv4?: PlanSigv4,
  maxSigv4BodyBytes: number = MAX_SIGV4_RESIGN_BODY_BYTES,
): Promise<void> {
  // req.url is the request-target verbatim. Inside a CONNECT tunnel almost
  // every client sends origin-form (`/path?q`), but RFC 7230 §5.3.2 also
  // permits absolute-form (`https://host/path`) and servers MUST accept it.
  // Normalize to origin-form so concatenating onto `https://${host}` below
  // yields a well-formed URL, and discard any client-supplied authority so
  // the CONNECT-verified target stays authoritative (same rationale as the
  // Host-header note below).
  const path = originFormPath(req.url)
  let body: Readable = req
  if (filterRequest) {
    const ac = new AbortController()
    res.once('close', () => ac.abort())
    // Build the URL passed to filterRequest from the CONNECT target,
    // NOT from `req.headers.host`. The Host header is supplied by the
    // sandboxed client and can be spoofed: a sandboxed process can
    // CONNECT to allowlisted host A and then send a decrypted request
    // with `Host: B` (where B is some other allowlisted host). If we
    // built the filterRequest URL from req.headers.host the callback
    // would see "host=B" while the request is actually delivered to A.
    // A consumer using filterRequest for per-host method gating (e.g.
    // "POST allowed only to inference endpoints") would be bypassed —
    // the agent could spoof Host: api.example.com on a CONNECT to a
    // different allowlisted host, get the POST allowed, and have it
    // delivered to the CONNECT target instead.
    //
    // Always derive the URL from the verified CONNECT target so
    // filterRequest sees the actual upstream destination.
    const host =
      target.port === 443
        ? target.hostname
        : `${target.hostname}:${target.port}`
    const out = await decideAndRespond(
      filterRequest,
      req,
      res,
      `https://${host}${path}`,
      ac.signal,
      target.onFilterRequestDeny,
    )
    if (out === null) return
    body = out
    // The client may have aborted during the filterRequest await — the tee
    // branch is already destroyed and res 'close' already fired, so the
    // teardown listeners attached below would never run. Don't dial an
    // upstream for a dead client. A COMPLETED request is also
    // destroyed=true (normal stream lifecycle after 'end'); only a
    // destroy without a clean end is an abort.
    if (
      (req.destroyed && !req.readableEnded) ||
      res.destroyed ||
      req.socket.destroyed ||
      body.destroyed
    ) {
      body.destroy()
      return
    }
  }

  // Bun's https.request verifies the upstream cert against headers.host
  // verbatim (including ":port"), which never matches a SAN. Drop the host
  // header and let the runtime derive it from {host, port} — same wire value,
  // correct verification under both Node and Bun.
  const fwdHeaders = stripHopByHop(req.headers)
  delete fwdHeaders.host
  // SigV4 planning runs on the PRE-substitution headers (the trigger is
  // the fake access key id in the credential scope, which the header
  // substitution below replaces) but on the POST-strip view: the plan's
  // signed-header presence check must see exactly the set that will be
  // signed and forwarded, or a signed hop-by-hop header would pass the
  // check and then blow up inside the signer.
  const sigv4Plan = planSigv4?.(
    req.method ?? 'GET',
    path,
    fwdHeaders,
    target.hostname,
  )
  // Header mutation runs after the allow decision and before httpsRequest.
  // The upstream TLS handshake (rejectUnauthorized defaults to true)
  // completes before any HTTP bytes are written, so mutated headers never
  // reach an unverified server.
  mutateHeaders?.(fwdHeaders, target.hostname)
  // Masked-credential substitution in the request body, mirroring the
  // header substitution above. undefined → the bare pipe below, exactly as
  // before. May delete content-length from fwdHeaders (chunked fallback).
  const bodyTransform = prepareBodySubstitution(
    getBodySubstitutions,
    req,
    fwdHeaders,
    target.hostname,
  )

  // SigV4 re-signing runs after substitution so the new signature covers
  // the headers as they actually go upstream (real access key id, real
  // session token). Same denial surface as filterRequest.
  let bufferedBody: Buffer | undefined
  if (sigv4Plan?.action === 'deny') {
    respondDenied(res, sigv4Plan.reason)
    body.destroy()
    if (body !== req) destroyAfterDenial(req, res)
    return
  }
  if (sigv4Plan?.action === 'resign') {
    let payloadHash = sigv4Plan.payloadHash
    if (payloadHash === undefined) {
      // The client signed a literal body hash: buffer the body and
      // recompute so the signature covers the bytes actually sent. Body
      // substitution runs FIRST — the buffered bytes (and therefore the
      // hash and signature) must be the substituted body, not the
      // sentinel-bearing one the client wrote.
      const bodySource = bodyTransform ? body.pipe(bodyTransform) : body
      if (bodyTransform) {
        body.on('error', err => bodyTransform.destroy(err))
      }
      try {
        bufferedBody = await collectBody(bodySource, maxSigv4BodyBytes)
      } catch (err) {
        if (err instanceof BodyTooLargeError) {
          respondDenied(
            res,
            `AWS SigV4 request uses a masked credential and signs a ` +
              `literal body hash, so the proxy must buffer the body to ` +
              `re-sign it, but the body exceeds the ` +
              `${maxSigv4BodyBytes}-byte buffering limit; denied. Sign ` +
              `the payload as UNSIGNED-PAYLOAD to stream it without ` +
              `buffering, or use an unmasked credential to have the ` +
              `request forwarded untouched.`,
          )
          // Drain (discarding) whatever the client is still sending so it
          // can read the 403 instead of seeing a reset mid-upload.
          bodySource.resume()
          return
        }
        logForDebugging(
          `[tls-terminate] failed to buffer body for SigV4 re-sign: ${(err as Error).message}`,
          { level: 'error' },
        )
        res.destroy()
        return
      }
      payloadHash = sha256Hex(bufferedBody)
      // The body is fully buffered so its exact length is known — set the
      // header unconditionally. end(Buffer) only auto-computes a
      // content-length for methods that default to chunked encoding; on
      // bodyless-default methods it would raw-append the buffer unframed.
      fwdHeaders['content-length'] = String(bufferedBody.length)
    }
    // Mirror the Host value the runtime derives from {host, port} below.
    const bracketedHost =
      isIP(target.hostname) === 6 ? `[${target.hostname}]` : target.hostname
    const hostHeader =
      target.port === 443 ? bracketedHost : `${bracketedHost}:${target.port}`
    try {
      sigv4Plan.apply(fwdHeaders, hostHeader, payloadHash)
    } catch (err) {
      // Fail closed on any signer error — a request the proxy claimed to
      // handle must not go upstream half-rewritten, and a client-crafted
      // header set must not become an unhandled rejection.
      respondDenied(
        res,
        `AWS SigV4 re-signing failed: ${(err as Error).message}`,
      )
      body.destroy()
      if (body !== req) destroyAfterDenial(req, res)
      return
    }
  }

  // When the client declared a body but the forwarded headers carry no
  // framing (chunked TE stripped as hop-by-hop, or a body transform
  // deleted content-length), the upstream leg must re-frame explicitly:
  // for bodyless-method requests the runtime would otherwise write the
  // piped body bytes raw after complete-framed headers — a
  // request-smuggling primitive. The SigV4 buffered path is exempt:
  // end(bufferedBody) computes its own content-length.
  const clientDeclaredBody = Boolean(
    req.headers['content-length'] || req.headers['transfer-encoding'],
  )
  if (
    clientDeclaredBody &&
    bufferedBody === undefined &&
    fwdHeaders['content-length'] === undefined &&
    fwdHeaders['transfer-encoding'] === undefined
  ) {
    fwdHeaders['transfer-encoding'] = 'chunked'
  }

  // TODO(terminating-tls): honour parentProxy for the upstream leg.
  const upstream = httpsRequest(
    {
      host: target.hostname,
      port: target.port,
      path,
      method: req.method,
      headers: fwdHeaders,
      // We're a TLS-terminating proxy, not a trust boundary for the upstream
      // server's identity — let the runtime do normal verification against
      // system roots (and NODE_EXTRA_CA_CERTS). servername must match the
      // host the client intended; SNI cannot carry an IP literal, and Bun's
      // https.request treats `servername: undefined` differently from
      // omitting the key, so spread conditionally.
      ...(isIP(target.hostname) ? {} : { servername: target.hostname }),
      ...(target.upstreamCA ? { ca: target.upstreamCA } : {}),
      // No global agent: a proxy's outbound leg shouldn't share a connection
      // pool keyed on the proxy process. Also works around a Bun quirk where
      // the first request's `ca:` value is cached on the global agent and
      // subsequent calls with a different `ca:` are silently ignored.
      agent: false,
    },
    upRes => {
      // The response stream errors independently of the ClientRequest;
      // pipe() does not handle source errors.
      upRes.on('error', err => {
        logForDebugging(
          `[tls-terminate] upstream response error: ${err.message}`,
          { level: 'error' },
        )
        res.destroy()
      })
      res.writeHead(upRes.statusCode ?? 502, stripHopByHop(upRes.headers))
      upRes.pipe(res)
    },
  )

  upstream.on('error', err => {
    logForDebugging(
      `[tls-terminate] upstream ${target.hostname}:${target.port} failed: ${err.message}`,
      { level: 'error' },
    )
    if (!res.headersSent) {
      res.writeHead(502, { 'Content-Type': 'text/plain' })
      res.end('Bad Gateway')
    } else {
      res.destroy()
    }
  })

  res.on('close', () => upstream.destroy())
  if (bufferedBody !== undefined) {
    // SigV4 literal-hash path: the buffered body already went through
    // bodyTransform above (when one applied), so send it verbatim.
    upstream.end(bufferedBody)
  } else if (bodyTransform) {
    // Errors on either side of the extra pipe stage tear the chain down —
    // a stalled half-open upstream would otherwise wait for the client.
    bodyTransform.on('error', err => upstream.destroy(err))
    body.on('error', err => bodyTransform.destroy(err))
    res.on('close', () => bodyTransform.destroy())
    body.pipe(bodyTransform).pipe(upstream)
  } else {
    // pipe() does not handle source errors. `body` may be a tee branch
    // from decideAndRespond (not `req` itself), so a client abort surfaces
    // here as an 'error' that would otherwise escape as an
    // uncaughtException.
    body.on('error', err => upstream.destroy(err))
    body.pipe(upstream)
  }
}

/**
 * Read a request body fully into memory (for SigV4 body-hash re-signing).
 * Rejects with {@link BodyTooLargeError} once more than `maxBytes` have
 * arrived, discarding everything buffered so far — the caller denies the
 * request, so holding the partial body would defeat the cap.
 */
function collectBody(body: Readable, maxBytes: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []
    let total = 0
    const onData = (c: Buffer) => {
      total += c.length
      if (total > maxBytes) {
        chunks.length = 0
        body.removeListener('data', onData)
        reject(new BodyTooLargeError(`request body exceeds ${maxBytes} bytes`))
        return
      }
      chunks.push(c)
    }
    body.on('data', onData)
    body.once('end', () => resolve(Buffer.concat(chunks)))
    body.once('error', reject)
  })
}

function originFormPath(reqUrl: string | undefined): string {
  const raw = reqUrl ?? '/'
  if (raw.startsWith('/')) return raw
  try {
    const u = new URL(raw)
    return `${u.pathname}${u.search}` || '/'
  } catch {
    // asterisk-form (`OPTIONS *`) or anything else non-absolute — pass through.
    return raw
  }
}

let sockSeq = 0
function innerSocketPath(): string {
  // Keep it short — macOS sun_path is 104 bytes.
  return join(
    tmpdir(),
    `srt-tt-${process.pid}-${(sockSeq++).toString(36)}.sock`,
  )
}
