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

import { Agent as HttpsAgent, request as httpsRequest } from 'node:https'
import { createServer as createHttpServer } from 'node:http'
import type { ClientRequest, IncomingMessage, ServerResponse } from 'node:http'
import type { LookupFunction, Socket } from 'node:net'
import { checkServerIdentity, TLSSocket } from 'node:tls'
import type { TLSSocketOptions } from 'node:tls'
import { Duplex } from 'node:stream'
import type { Readable, Writable } from 'node:stream'
import { logForDebugging } from '../utils/debug.js'
import {
  adjustByteBudget,
  endRequestAfterResponse,
  gateSocketOnBufferedBody,
  keepFlushedHeaderBatches,
  type ByteBudget,
  markEndsGracefully,
  runsOnBun,
} from './emitted-connection.js'
import type { MitmCA } from './mitm-ca.js'
import {
  decideAndRespond,
  normalizeRequestTarget,
  requestTargetAsSpelled,
  type DenyMark,
  applyHeaderEdits,
  notifyResponse,
  removeHeadersFolded,
  hostHeaderValues,
  hostMismatch,
  type RequestDecision,
  respondDenied,
  respondUpstreamError,
  type FilterRequestCallback,
  type MutateForwardedHeaders,
} from './request-filter.js'
import {
  prepareBodySubstitution,
  type GetBodySubstitutions,
} from './body-substitution.js'
import { secureContextFor } from './mitm-leaf.js'
import {
  directRequestOptions,
  type DirectRequestOptions,
  formatAuthority,
  relayResponseHead,
  stripHopByHop,
} from './parent-proxy.js'
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
 * A duplex over a CONNECT socket that yields `head` first, for a TLS socket
 * to run on in this process.
 *
 * Reads are pull-mode (`'readable'` + `read()`), never `pause()`/`resume()`:
 * under Bun a socket delivered by an http server's `'connect'` event
 * corrupts its byte stream across those cycles once writes queue (the TLS
 * layer then fails record MAC verification). A write completes once the
 * socket has taken it, so the TLS socket above sees the client's
 * backpressure. Ending the duplex closes the socket with closeAfterFlush.
 *
 * Bun's TLS socket keeps reading the duplex under it while it is itself
 * paused, so once `consumer` (the TLS socket) is set, nothing more is read
 * from the client while that is paused: its uploads wait in the kernel.
 */
function duplexOverSocket(
  socket: Duplex,
  head: Buffer,
  onClosed: (how: string) => void,
): { duplex: Duplex; setConsumer: (consumer: Readable) => void } {
  let waiting = false
  let consumer: Readable | undefined
  let waitingForConsumer = false
  const onConsumerResume = (): void => {
    waitingForConsumer = false
    pull()
  }
  const pull = (): void => {
    if (consumer?.isPaused()) {
      if (!waitingForConsumer) {
        waitingForConsumer = true
        consumer.once('resume', onConsumerResume)
      }
      return
    }
    let chunk: Buffer | string | null
    while ((chunk = socket.read() as Buffer | string | null) !== null) {
      if (!d.push(chunk)) return
    }
    if (!waiting) {
      waiting = true
      socket.once('readable', onReadable)
    }
  }
  const onReadable = (): void => {
    waiting = false
    pull()
  }
  const d: Duplex = new Duplex({
    read() {
      pull()
    },
    write(chunk: Buffer, _encoding, cb) {
      if (socket.write(chunk)) cb()
      else socket.once('drain', () => cb())
    },
    final(cb) {
      socket.off('readable', onReadable)
      closeAfterFlush(socket, onClosed)
      cb()
    },
    destroy(err, cb) {
      socket.destroy()
      cb(err)
    },
  })
  if (head.length) d.push(head)
  socket.once('end', () => d.push(null))
  // The socket's own errors are handled where the tunnel starts; here they
  // only end the stream (an 'error' on it would have no listener).
  socket.once('close', () => d.destroy())
  d.on('error', () => {})
  return {
    duplex: d,
    setConsumer: c => {
      consumer = c
    },
  }
}

/**
 * Start the server side of TLS on a tunnel's own socket, in this process:
 * no listener, so no other process can reach the tunnel's plaintext side.
 * Under Node the TLS socket runs on the socket itself. Under Bun it runs on
 * a duplex over it: Bun's TLS socket on a net.Socket leaves every byte it
 * reads in that socket's own buffer too, which grows by the whole upload.
 * `outbound` is the stream whose write queue holds what is on its way to
 * the client.
 */
function serverTlsOn(
  socket: Duplex,
  head: Buffer,
  options: TLSSocketOptions,
  onClosed: (how: string) => void,
): { tls: TLSSocket; outbound: Writable } {
  if (!runsOnBun()) {
    if (head.length) socket.unshift(head)
    const tls = new TLSSocket(socket as Socket, { ...options, isServer: true })
    return { tls, outbound: tls }
  }
  const { duplex, setConsumer } = duplexOverSocket(socket, head, onClosed)
  const tls = new TLSSocket(duplex as unknown as Socket, {
    ...options,
    isServer: true,
  })
  setConsumer(tls)
  return { tls, outbound: duplex }
}

/** What a tunnel's TLS socket writes goes out through this stream. */
const outboundOf = new WeakMap<object, Writable>()

/** The proxy's shared byte budget, per tunnel TLS socket. */
const budgetOf = new WeakMap<object, ByteBudget>()

/**
 * Past this many bytes queued for a client, a response waits for the
 * queue to drain. Bun's server for an emitted connection lets a response
 * write on (its 'drain' comes at once) while the socket underneath queues
 * without bound, so the relay watches the socket's own queue.
 */
const MAX_QUEUED_FOR_CLIENT = 1 << 20

/**
 * On a TLS-terminated request, Bun's server keeps reading a request whose
 * stream is paused: past this many buffered body bytes, the TLS socket is
 * paused instead (gateSocketOnBufferedBody).
 */
const MAX_BUFFERED_REQUEST_BODY = 4 << 20

export type TerminateTarget = {
  /**
   * Canonical (see canonicalizeHost) CONNECT target: what the allowlist
   * evaluated. Used verbatim for the minted leaf, the filterRequest URL,
   * the credential hooks' destHost, and the upstream host/SNI, so all of
   * them agree with the policy decision regardless of how the client
   * spelled the name.
   */
  hostname: string
  port: number
  /**
   * Additional trusted CA(s) for the proxy's outbound TLS leg. Unset → system
   * roots + NODE_EXTRA_CA_CERTS. Primarily a test seam (NODE_EXTRA_CA_CERTS
   * is read at process start, so tests can't set it from inside the suite).
   */
  upstreamCA?: string | Buffer | Array<string | Buffer>
  /** Upstream-leg name resolution, already bound for this target (see HttpProxyServerOptions.lookupFor). */
  lookup?: LookupFunction
  /**
   * Called when filterRequest denies a parsed request, with the verified
   * method/URL and the decision reason. Carried on the target so the
   * per-connection request handler (which closes over `target`) can reach
   * it without an extra parameter on every layer.
   */
  onFilterRequestDeny?: (method: string, url: string, reason: string) => void
  /** Response headers removed before the response reaches the client. */
  stripResponseHeaders?: string[]
  /** Answer 421 when the Host header or TLS server name is not the target. */
  requireHostMatch?: boolean
  /** The largest request head parsed in the tunnel; past it, 400 (see HttpProxyServerOptions.maxHeaderSize). */
  maxHeaderSize?: number
  /** Drop hop-by-hop headers in any separator spelling (see HttpProxyServerOptions.foldHopByHop). */
  foldHopByHop?: boolean
  /** The header that marks the proxy's own refusals (see HttpProxyServerOptions.denyHeader). */
  denyHeader?: string
  /** Forward the request-target as spelled (see HttpProxyServerOptions.requestTargetAsSpelled). */
  requestTargetAsSpelled?: boolean
  /** The TLS server name the client sent (set by terminateAndForward). */
  clientServerName?: string
  /** The ClientHello carries a server name that could not be read (see serverNameFromClientHello). */
  clientServerNameUnreadable?: boolean
  /** Called once the tunnel's TLS handshake is done. */
  onEstablished?: () => void
  /** Given a way to ask, at any later time, whether the tunnel's TLS handshake is done. */
  onHandshakeProbe?: (isDone: () => boolean) => void
  /** Shared across a proxy's tunnels: bytes they may hold for slow parties (see ByteBudget). */
  byteBudget?: ByteBudget
}

/**
 * Terminate the client's TLS on `socket`, parse the decrypted HTTP/1.1
 * stream, and forward each request to `target` over an upstream TLS
 * connection kept alive for the life of the client's connection (see
 * {@link createUpstreamLeg}).
 *
 * Preconditions: the caller has already validated `target` against the
 * domain allowlist; this function does not re-check it.
 *
 * Implementation: the TLS runs in this process on the tunnel's own socket
 * (serverTlsOn), and the decrypted connection is handed with
 * `emit('connection')` to an http.Server that never listens, so nothing
 * another process can connect to exists. A server per tunnel lets the
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
  // The tunnel's one connection is its client's, so the server name in its
  // ClientHello is the tunnel's (read below, before the handshake).
  let serverName: ServerName = { kind: 'absent' }
  // Never listens: the TLS socket below is handed to it.
  const inner = createHttpServer(
    target.maxHeaderSize !== undefined
      ? { maxHeaderSize: target.maxHeaderSize }
      : {},
  )

  // Needs an http.Server that serves a connection handed to it (Node, Bun
  // 1.4 and later: such a server has a 'connection' listener of its own).
  // Without one the tunnel is refused, never left hanging.
  if (inner.listenerCount('connection') === 0) {
    logForDebugging(
      '[tls-terminate] this runtime cannot terminate TLS in-process; tunnel refused',
      { level: 'error' },
    )
    socket.destroy()
    return
  }

  const leg = createUpstreamLeg(target)

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
    if (runsOnBun()) {
      gateSocketOnBufferedBody(
        req,
        MAX_BUFFERED_REQUEST_BODY,
        target.byteBudget,
      )
    }
    forwardUpstreamGuarded(
      filterRequest,
      mutateHeaders,
      getBodySubstitutions,
      req,
      res,
      {
        ...target,
        clientServerName:
          serverName.kind === 'name' ? serverName.name : undefined,
        clientServerNameUnreadable: serverName.kind === 'unreadable',
      },
      leg,
      planSigv4,
      maxSigv4BodyBytes,
    )
  })
  inner.on('clientError', (err, sock) => {
    // Parse errors and resets on the tunnel would otherwise escalate to an
    // uncaughtException, same class as the request-stream errors handled
    // above.
    logForDebugging(
      `[tls-terminate] client connection error for ${target.hostname}: ${err.message}`,
      { level: 'error' },
    )
    if (
      target.maxHeaderSize !== undefined &&
      (err as NodeJS.ErrnoException).code === 'HPE_HEADER_OVERFLOW' &&
      sock.writable
    ) {
      // A head past the caller's own limit is a request past its limits:
      // 400, flushed before the socket goes.
      sock.on('error', () => {})
      const mark =
        target.denyHeader !== undefined
          ? `${target.denyHeader}: bad_request\r\n`
          : ''
      sock.end(
        `HTTP/1.1 400 Bad Request\r\n${mark}Content-Length: 0\r\nConnection: close\r\n\r\n`,
        () => sock.destroy(),
      )
      setTimeout(() => sock.destroy(), 1000).unref?.()
      return
    }
    sock.destroy()
  })
  inner.on('upgrade', (_req, sock) => {
    // WebSocket / non-HTTP over TLS — out of scope for now.
    logForDebugging('[tls-terminate] upgrade request refused', {
      level: 'warn',
    })
    sock.destroy()
  })

  // A client that resets at any point (while its ClientHello is still being
  // read, too) only ends its own tunnel.
  socket.on('error', err => {
    logForDebugging(
      `[tls-terminate] client connection error for ${target.hostname}: ${err.message}`,
    )
    socket.destroy()
  })
  socket.once('close', () => leg.agent.destroy())
  // The certificate is chosen from the ClientHello's server name before the
  // handshake, the same way under every runtime and on every socket (Bun's
  // TLS socket over a stream calls no SNICallback).
  void readFirstRecord(socket, head)
    .then(hello => {
      if (socket.destroyed) return
      serverName = serverNameFromClientHello(hello)
      startTls(hello)
    })
    .catch((err: unknown) => {
      logForDebugging(
        `[tls-terminate] tunnel setup failed for ${target.hostname}: ${(err as Error).message}`,
        { level: 'error' },
      )
      socket.destroy()
    })

  const startTls = (hello: Buffer): void => {
    let closedBy: string | undefined
    // Where the Host and server name must name the target, the certificate
    // is the target's whatever the client asks for: a mismatched name gets
    // 421 anyway, and the names a client can have minted stay the targets.
    const leafFor =
      !target.requireHostMatch && serverName.kind === 'name'
        ? serverName.name
        : target.hostname
    const { tls, outbound } = serverTlsOn(
      socket,
      hello,
      {
        ALPNProtocols: ['http/1.1'],
        secureContext: secureContextFor(ca, leafFor),
      },
      how => {
        closedBy = how
      },
    )
    outboundOf.set(tls, outbound)
    if (target.byteBudget) budgetOf.set(tls, target.byteBudget)
    markEndsGracefully(tls)
    // The handshake is done at 'secure', or by the first decrypted byte
    // (Bun's TLS socket on a stream does not always say 'secure').
    let established = false
    const onEstablished = (): void => {
      if (established) return
      established = true
      target.onEstablished?.()
    }
    tls.once('data', onEstablished)
    // Neither event comes for a client that finishes the handshake and then
    // stays quiet where 'secure' is not said, so a deadline asks instead.
    target.onHandshakeProbe?.(() => established || isTlsHandshakeDone(tls))
    tls.once('secure', () => {
      onEstablished()
      // Where the runtime reports the name its TLS layer took, it must be
      // the one read from the ClientHello.
      const negotiated = (tls as { servername?: unknown }).servername
      const read = serverName.kind === 'name' ? serverName.name : undefined
      // (An unreadable name is already a mismatch where names are pinned.)
      if (
        serverName.kind !== 'unreadable' &&
        typeof negotiated === 'string' &&
        negotiated !== '' &&
        negotiated.toLowerCase() !== read
      ) {
        logForDebugging(
          `[tls-terminate] server name ${negotiated} is not the one read from the ClientHello (${read ?? 'none'}); tunnel closed`,
          { level: 'error' },
        )
        socket.destroy()
      }
    })
    tls.on('error', err => {
      logForDebugging(
        `[tls-terminate] client TLS error for ${target.hostname}: ${err.message}`,
        { level: 'error' },
      )
      socket.destroy()
    })
    if (outbound === tls) {
      // The server ends the connection once it is done with it; a client
      // that never closes its side is let go a while after the flush.
      tls.once('finish', () => {
        const grace = setTimeout(() => tls.destroy(), 5_000)
        grace.unref?.()
        tls.once('close', () => clearTimeout(grace))
      })
    }
    socket.once('close', () => {
      if (!tls.destroyed) tls.destroy()
      // A tick later, so closeAfterFlush has said how it closed the socket.
      setImmediate(() =>
        logForDebugging(
          `[tls-terminate] tunnel closed for ${target.hostname}:${target.port}: ` +
            `TLS on ${outbound === tls ? 'the socket' : 'a stream over the socket'}; ` +
            `to the client ${(socket as { bytesWritten?: number }).bytesWritten ?? '?'} B, ` +
            `${outbound.writableLength} B still queued; closed by ${closedBy ?? 'the connection ending'}`,
        ),
      )
    })
    inner.emit('connection', tls)
    keepFlushedHeaderBatches(tls)
  }
}

/**
 * Read on until `head` holds the whole first TLS record (the ClientHello,
 * at most 16 KiB of it), the client stops sending, or 5 s pass. Pull-mode
 * reads: nothing more is taken than is there.
 */
function readFirstRecord(socket: Duplex, head: Buffer): Promise<Buffer> {
  const want = (b: Buffer): number =>
    b.length >= 5 ? 5 + Math.min(b.readUInt16BE(3), 16 << 10) : 5
  if (head.length >= want(head)) return Promise.resolve(head)
  return new Promise(resolve => {
    let buf = head
    const done = (): void => {
      clearTimeout(timer)
      socket.off('readable', pull)
      socket.off('close', done)
      resolve(buf)
    }
    const pull = (): void => {
      let chunk: Buffer | null
      while ((chunk = socket.read() as Buffer | null) !== null) {
        buf = Buffer.concat([buf, chunk])
        if (buf.length >= want(buf)) {
          done()
          return
        }
      }
    }
    const timer = setTimeout(done, 5_000)
    socket.on('readable', pull)
    socket.once('close', done)
    pull()
  })
}

/** The server name a ClientHello carries: none, a plain DNS name, or one that cannot be read. */
export type ServerName =
  | { kind: 'absent' }
  | { kind: 'name'; name: string }
  | { kind: 'unreadable' }

/**
 * The server name a TLS ClientHello record carries (the server_name
 * extension's host_name), lower-cased.
 *
 * `unreadable` whenever a name may be there but cannot be taken as a plain
 * DNS name: the extension is malformed, lists more than one name, or names
 * something other than a host; the name is empty, too long, not ASCII
 * letters, digits, - and . in non-empty labels, or ends in a dot; or the
 * record ends (a ClientHello split across records) before the extensions
 * have all been read. `absent` only when every extension was read and none
 * is server_name.
 */
export function serverNameFromClientHello(record: Buffer): ServerName {
  const unreadable: ServerName = { kind: 'unreadable' }
  if (record.length < 9 || record[0] !== 0x16 || record[5] !== 0x01) {
    return unreadable
  }
  const end = Math.min(record.length, 5 + record.readUInt16BE(3))
  // Handshake header (4), client_version (2), random (32).
  let i = 5 + 4 + 2 + 32
  const skip = (lengthBytes: 1 | 2): boolean => {
    if (i + lengthBytes > end) return false
    const n = lengthBytes === 1 ? record[i]! : record.readUInt16BE(i)
    i += lengthBytes + n
    return i <= end
  }
  // session_id, cipher_suites, compression_methods.
  if (!skip(1) || !skip(2) || !skip(1)) return unreadable
  // A ClientHello with no extensions at all carries no name.
  if (i === end && end === 5 + record.readUInt16BE(3)) return { kind: 'absent' }
  if (i + 2 > end) return unreadable
  const declaredEnd = i + 2 + record.readUInt16BE(i)
  const extensionsEnd = Math.min(end, declaredEnd)
  i += 2
  let found: ServerName | undefined
  while (i + 4 <= extensionsEnd) {
    const type = record.readUInt16BE(i)
    const length = record.readUInt16BE(i + 2)
    i += 4
    if (i + length > extensionsEnd) {
      // Past the end of a record that is complete: malformed. Past where
      // the record was cut: the rest is in the next record.
      if (extensionsEnd === declaredEnd) return unreadable
      break
    }
    if (type === 0) {
      if (found !== undefined) return unreadable
      found = hostNameEntry(record.subarray(i, i + length))
    }
    i += length
  }
  if (found !== undefined) return found
  // Every extension read and none a server_name, or the list was cut short.
  return i === declaredEnd ? { kind: 'absent' } : unreadable
}

/** The one host_name entry of a server_name extension's body. */
function hostNameEntry(body: Buffer): ServerName {
  if (body.length < 5 || body.readUInt16BE(0) !== body.length - 2) {
    return { kind: 'unreadable' }
  }
  const nameType = body[2]!
  const nameLength = body.readUInt16BE(3)
  if (nameType !== 0 || 5 + nameLength !== body.length) {
    return { kind: 'unreadable' }
  }
  const name = body.toString('latin1', 5).toLowerCase()
  const plain =
    name.length <= 253 &&
    name
      .split('.')
      .every(label => /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(label))
  return plain ? { kind: 'name', name } : { kind: 'unreadable' }
}

/**
 * Close a socket once what is written to it has gone out and the client
 * has seen it: end it, and once the writes are flushed, destroy it when
 * the client ends its side, or after a grace period. Until then what the
 * client sends is read and dropped, since unread input when the socket
 * closes turns the close into a reset, and a reset discards what the
 * client has not read yet. A backstop covers a client that stops reading.
 */
export function closeAfterFlush(
  socket: Duplex,
  done: (how: string) => void,
): void {
  if (socket.destroyed) {
    done('the client, earlier')
    return
  }
  let finished = socket.writableFinished
  let clientEnded = socket.readableEnded
  let settled = false
  const close = (how: string): void => {
    if (settled) return
    settled = true
    clearTimeout(backstop)
    clearTimeout(grace)
    if (!socket.destroyed) socket.destroy()
    done(how)
  }
  const backstop = setTimeout(() => close('the 30 s backstop'), 30_000)
  backstop.unref?.()
  let grace: ReturnType<typeof setTimeout> | undefined
  const onFinish = (): void => {
    finished = true
    if (clientEnded) {
      close('the client ending after the flush')
      return
    }
    grace = setTimeout(() => close('the 5 s grace after the flush'), 5_000)
    grace.unref?.()
  }
  socket.once('end', () => {
    clientEnded = true
    if (finished) close('the client ending after the flush')
  })
  socket.once('close', () => close('the client closing'))
  socket.on('data', () => {})
  socket.resume()
  if (finished) onFinish()
  else socket.once('finish', onFinish)
  socket.end()
}

/**
 * The upstream leg of one client connection: a keep-alive agent capped at one
 * socket, and the vetted upstream address.
 *
 * One agent per client connection rather than a shared pool, so requests from
 * different client connections never share an upstream socket, and the
 * upstream connection lives exactly as long as the client's. One socket keeps
 * the client's request order on the wire: a pipelined request queues in the
 * agent until the previous response has finished.
 *
 * `ca` and `checkServerIdentity` are agent options, not request options — a
 * per-request `checkServerIdentity` makes Node open a new socket for every
 * request. The target is fixed for the connection, so nothing is lost.
 *
 * The address is vetted once (see directRequestOptions) and then reused: a
 * second probe could pick a different record of a multi-address name, which
 * is a different agent key and so a new socket. A redial after the upstream
 * closes an idle socket goes to the same vetted literal. Any upstream failure
 * forgets the address, so the next request vets again.
 */
type UpstreamLeg = {
  agent: HttpsAgent
  address(): Promise<DirectRequestOptions>
  forgetAddress(): void
}

function createUpstreamLeg(target: TerminateTarget): UpstreamLeg {
  const agent = new HttpsAgent({
    keepAlive: true,
    maxSockets: 1,
    // We're a TLS-terminating proxy, not a trust boundary for the upstream
    // server's identity — the runtime verifies it normally (system roots and
    // NODE_EXTRA_CA_CERTS). Pin the identity to the tunnel's target so the
    // check does not depend on how a runtime derives it from the Host header
    // (some verify against `Host` verbatim, so a non-default port would
    // never match a SAN); `servername` still carries the name for SNI.
    checkServerIdentity: (_host, cert) =>
      checkServerIdentity(target.hostname, cert),
    ...(target.upstreamCA ? { ca: target.upstreamCA } : {}),
  })
  let vetted: Promise<DirectRequestOptions> | undefined
  return {
    agent,
    address() {
      if (!vetted) {
        const probe = directRequestOptions(
          target.hostname,
          target.port,
          target.lookup,
          true,
        )
        vetted = probe
        probe.catch(() => {
          if (vetted === probe) vetted = undefined
        })
      }
      return vetted
    },
    forgetAddress() {
      vetted = undefined
    },
  }
}

/**
 * True for the failure a reused keep-alive socket produces when the upstream
 * closed it while the request was on its way.
 */
function isStaleSocketError(err: Error): boolean {
  const code = (err as NodeJS.ErrnoException).code
  return code === 'ECONNRESET' || code === 'EPIPE'
}

/**
 * Destroy a denied client's request only after the 403 has flushed —
 * destroying the shared socket in the same tick can RST the response away.
 */
function destroyAfterDenial(req: IncomingMessage, res: ServerResponse): void {
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
 * After a deny: stop a forwarded body that is not the request itself (a
 * tee branch, a transform) at once, and the request once the answer is
 * out. A request without a body is its own body, and destroying it before
 * the answer is out would drop the answer.
 */
function endDeniedRequest(
  req: IncomingMessage,
  res: ServerResponse,
  body: Readable,
): void {
  if (body !== req) body.destroy()
  destroyAfterDenial(req, res)
}

function forwardUpstreamGuarded(
  ...args: Parameters<typeof forwardUpstream>
): void {
  // Fire-and-forget from the request handler: a rejection (e.g. a
  // synchronous throw writing a denial to a client that already reset)
  // must not become an unhandledRejection, and the client still gets an
  // answer (502, or a reset once headers are out) instead of waiting for
  // a server timeout.
  const [, , , req, res, target] = args
  forwardUpstream(...args).catch(err => {
    logForDebugging(
      `[tls-terminate] forwardUpstream failed: ${(err as Error).message}`,
      { level: 'error' },
    )
    respondUpstreamError(res, err as Error, target.denyHeader)
    destroyAfterDenial(req, res)
  })
}

async function forwardUpstream(
  filterRequest: FilterRequestCallback | undefined,
  mutateHeaders: MutateForwardedHeaders | undefined,
  getBodySubstitutions: GetBodySubstitutions | undefined,
  req: IncomingMessage,
  res: ServerResponse,
  target: TerminateTarget,
  leg: UpstreamLeg,
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
  // With filterRequest, the request target is normalized before the hook
  // sees it and that normalized target is what is forwarded: some runtimes'
  // HTTP clients normalize it again on the way out, and the hook must judge
  // exactly what is sent. A target of any other shape could make the judged
  // URL name another host, so it is refused. Without filterRequest nothing
  // judges the path, so the target is forwarded unchanged (and a masked AWS
  // credential is re-signed over those same bytes). requestTargetAsSpelled
  // comes first: it forwards the target as the client spelled it.
  const markFor = (code: string): DenyMark | undefined =>
    target.denyHeader !== undefined
      ? { name: target.denyHeader, value: code }
      : undefined
  const path = target.requestTargetAsSpelled
    ? requestTargetAsSpelled(req.url ?? '/')
    : filterRequest
      ? normalizeRequestTarget(req.url ?? '/', req.method)
      : originFormPath(req.url)
  if (path === undefined) {
    respondDenied(res, 'malformed request-target', markFor('bad_request'), 400)
    return
  }
  // RFC 9112 3.2: an HTTP/1.1 request without Host is answered 400. Not
  // every runtime's parser does it (Bun's for a handed-in connection
  // passes it on).
  if (
    req.httpVersion === '1.1' &&
    hostHeaderValues(req.rawHeaders).length === 0
  ) {
    respondDenied(
      res,
      'HTTP/1.1 request without a Host header',
      markFor('bad_request'),
      400,
    )
    return
  }
  // The tunnel target as it goes on the wire: filterRequest URL, Host, SigV4.
  const authority = formatAuthority(target.hostname, target.port, 443)
  let body: Readable = req
  let decision: RequestDecision | undefined
  const sni = target.clientServerName ?? serverNameOf(req)
  if (target.requireHostMatch && target.clientServerNameUnreadable) {
    const why = 'TLS server name could not be read'
    target.onFilterRequestDeny?.(
      req.method ?? 'GET',
      `https://${authority}${path}`,
      why,
    )
    respondDenied(res, why, markFor('misdirected'), 421)
    return
  }
  if (target.requireHostMatch) {
    const why = hostMismatch(
      hostHeaderValues(req.rawHeaders),
      sni,
      { hostname: target.hostname, port: target.port, defaultPort: 443 },
      absoluteFormAuthority(req.url),
    )
    if (why !== undefined) {
      target.onFilterRequestDeny?.(
        req.method ?? 'GET',
        `https://${authority}${path}`,
        why,
      )
      respondDenied(res, why, markFor('misdirected'), 421)
      return
    }
  }
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
    const out = await decideAndRespond(
      filterRequest,
      req,
      res,
      `https://${authority}${path}`,
      ac.signal,
      target.onFilterRequestDeny,
      {
        sni,
        target: { host: target.hostname, port: target.port },
        requestTarget: path,
        rawHeaders: [...req.rawHeaders],
        scheme: 'https',
      },
      target.denyHeader,
    )
    if (out === null) return
    body = out.body
    decision = out.decision
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

  // The upstream is dialed by vetted address (below), so Host and SNI are
  // what carry the name: rebuild Host from the tunnel's target — the name the
  // allowlist saw — rather than forwarding the client's spelling.
  const fwdHeaders = stripHopByHop(req.headers, {
    folded: target.foldHopByHop,
  })
  fwdHeaders.host = authority
  // The decision's edits go before the credential hooks below, so a value
  // a decision sets can itself carry a masked credential's sentinel.
  if (decision) applyHeaderEdits(fwdHeaders, decision)
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
    endDeniedRequest(req, res, body)
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
    try {
      sigv4Plan.apply(fwdHeaders, authority, payloadHash)
    } catch (err) {
      // Fail closed on any signer error — a request the proxy claimed to
      // handle must not go upstream half-rewritten, and a client-crafted
      // header set must not become an unhandled rejection.
      respondDenied(
        res,
        `AWS SigV4 re-signing failed: ${(err as Error).message}`,
      )
      endDeniedRequest(req, res, body)
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

  const failUpstream = (err: Error, sent?: ClientRequest) => {
    logForDebugging(
      `[tls-terminate] upstream ${target.hostname}:${target.port} failed: ${err.message}`,
      { level: 'error' },
    )
    leg.forgetAddress()
    if (sent?.reusedSocket && !res.headersSent && isStaleSocketError(err)) {
      // The upstream closed the kept-alive socket as this request went out.
      // Close the client's connection rather than answer 502: that is what
      // the client would see on a direct keep-alive connection, and what its
      // own retry policy is written for. Destroy the socket, not `res`: with
      // no headers sent yet, Bun's res.destroy() answers `200 OK` with an
      // empty body before closing, which would hand the client a fabricated
      // success.
      req.socket.destroy()
      return
    }
    respondUpstreamError(res, err, target.denyHeader)
  }
  // Vet and pick the upstream address first (see createUpstreamLeg); the
  // name stays in Host and SNI.
  let direct: DirectRequestOptions
  try {
    direct = await leg.address()
  } catch (err) {
    failUpstream(err as Error)
    return
  }
  if (res.destroyed || req.socket.destroyed) {
    // Client went away during the dial.
    body.destroy()
    return
  }

  // TODO(terminating-tls): honour parentProxy for the upstream leg.
  const upstream = httpsRequest(
    {
      ...direct,
      agent: leg.agent,
      path,
      method: req.method,
      headers: fwdHeaders,
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
      const outHeaders = stripHopByHop(upRes.headers)
      notifyResponse(decision, upRes.statusCode ?? 502, outHeaders)
      if (target.stripResponseHeaders) {
        removeHeadersFolded(outHeaders, target.stripResponseHeaders)
      }
      if (relayResponseHead(res, upRes, outHeaders)) relayResponse(upRes, res)
    },
  )

  upstream.on('error', err => failUpstream(err, upstream))

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

/** The authority of an absolute-form request-target, as spelled; undefined for origin form. */
function absoluteFormAuthority(reqUrl: string | undefined): string | undefined {
  const m = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/([^/?#]*)/.exec(reqUrl ?? '')
  return m ? m[1] : undefined
}

/** The TLS server name on the request's socket, where the runtime exposes it. */
function serverNameOf(req: IncomingMessage): string | undefined {
  const name = (req.socket as { servername?: unknown }).servername
  return typeof name === 'string' && name !== '' ? name : undefined
}

/**
 * Pipe an upstream response into `res`, waiting whenever the client's side
 * is full: `res` itself (its write() returning false), or the stream the
 * tunnel's TLS socket writes out through holding more than
 * MAX_QUEUED_FOR_CLIENT, or anything while the proxy's shared byte budget
 * is spent.
 */
function relayResponse(src: Readable, res: ServerResponse): void {
  const outbound = outboundOf.get(res.socket as object)
  const budget = budgetOf.get(res.socket as object)
  let counted = 0
  let released = false
  const recount = (): void => {
    const queued = released ? 0 : (outbound?.writableLength ?? 0)
    const delta = queued - counted
    counted = queued
    if (budget && delta !== 0) adjustByteBudget(budget, delta)
  }
  const full = (): boolean => {
    if (outbound === undefined) return false
    recount()
    return (
      outbound.writableLength > MAX_QUEUED_FOR_CLIENT ||
      (budget !== undefined &&
        budget.used > budget.limit &&
        outbound.writableLength > 0)
    )
  }
  const resumeWhenRoom = (): void => {
    if (released || res.destroyed) return
    if (full()) {
      waitForRoom()
      return
    }
    src.resume()
  }
  // 'drain' only follows a write() that returned false, so a queue below
  // the stream's high-water mark empties without one. An empty write's
  // callback runs once everything queued ahead of it has gone out, at any
  // queue size; a failed stream calls it too, and then `res` closes.
  let awaitingFlush = false
  const waitForRoom = (): void => {
    budget?.waiters.add(resumeWhenRoom)
    if (awaitingFlush || outbound === undefined) return
    awaitingFlush = true
    outbound.write(EMPTY_CHUNK, () => {
      awaitingFlush = false
      resumeWhenRoom()
    })
  }
  const release = (): void => {
    released = true
    budget?.waiters.delete(resumeWhenRoom)
    recount()
  }
  src.on('data', (chunk: Buffer) => {
    const ok = res.write(chunk)
    if (full()) {
      src.pause()
      waitForRoom()
    } else if (!ok) {
      src.pause()
      res.once('drain', resumeWhenRoom)
    }
  })
  src.once('end', () => res.end())
  res.once('close', release)
  res.once('finish', release)
}

/**
 * The request-target as forwarded when no filterRequest is configured:
 * origin form verbatim, an absolute URI reduced to its path and query, and
 * anything else (`OPTIONS *`) passed through.
 */
function originFormPath(reqUrl: string | undefined): string {
  const raw = reqUrl ?? '/'
  if (raw.startsWith('/')) return raw
  try {
    const u = new URL(raw)
    return `${u.pathname}${u.search}` || '/'
  } catch {
    return raw
  }
}

const EMPTY_CHUNK = Buffer.alloc(0)

/**
 * Whether the client has finished the TLS handshake: its Finished message
 * has been received and verified. Unlike the negotiated protocol or cipher,
 * which a runtime may report as soon as the ClientHello is read, neither
 * sign is there for a client that reads the server's flight and never
 * answers it.
 *
 * getPeerFinished() is the public way to ask, and is enough on Node. Bun's
 * TLS library reports no peer Finished for TLS 1.3, so there the socket's
 * own (private) record that the handshake is done is read as well; were
 * that field to go away, a quiet TLS 1.3 client on Bun would again be held
 * to the deadline until its first byte.
 */
function isTlsHandshakeDone(tls: {
  getPeerFinished?: () => Buffer | undefined
  _secureEstablished?: unknown
}): boolean {
  return Boolean(tls.getPeerFinished?.()) || tls._secureEstablished === true
}
