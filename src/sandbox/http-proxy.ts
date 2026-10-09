import type { Socket } from 'node:net'
import type { Duplex, Readable } from 'node:stream'
import type { Server } from 'node:http'
import { Agent, createServer } from 'node:http'
import { request as httpRequest } from 'node:http'
import { request as httpsRequest } from 'node:https'
import { connect, isIP } from 'node:net'
import { URL } from 'node:url'
import { logForDebugging } from '../utils/debug.js'
import { encodedCommandFromProxyUser } from './sandbox-utils.js'
import {
  assertTlsTerminationSupported,
  type ByteBudget,
  createByteBudget,
  gateSocketOnBufferedBody,
} from './emitted-connection.js'
import { CRL_PATH, type MitmCA } from './mitm-ca.js'
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
  rawDenied,
  respondDenied,
  respondUpstreamError,
  type FilterRequestCallback,
  type MutateForwardedHeaders,
} from './request-filter.js'

const ALLOWLIST_DENY = [
  'Connection blocked by network allowlist',
  'blocked-by-allowlist',
] as const
import {
  peekForClientHello,
  terminateAndForward,
} from './tls-terminate-proxy.js'
import {
  prepareBodySubstitution,
  type GetBodySubstitutions,
} from './body-substitution.js'
import type { PlanSigv4 } from './credential-aws-pairs.js'
import type { ResolvedParentProxy } from './parent-proxy.js'
import { isResolvedAddressDenied } from './resolved-address-guard.js'
import {
  canonicalizeHost,
  connectViaParentProxy,
  directRequestOptions,
  type DirectRequestOptions,
  dialDirect,
  formatAuthority,
  type DirectLookup,
  openConnectTunnel,
  proxyAuthHeader,
  relayResponseHead,
  selectParentProxyUrl,
  shouldBypassParentProxy,
  stripBrackets,
  stripHopByHop,
} from './parent-proxy.js'

export interface HttpProxyServerOptions {
  /**
   * Host-allowlist decision. `encodedCommand` is the per-command suffix
   * parsed from the Proxy-Authorization username (`srt.<encodedCommand>`),
   * so the manager can attribute a denial to the invocation that made it.
   *
   * Receives the host exactly as the client spelled it (so denials and
   * permission prompts show what the process asked for); the manager's
   * filter canonicalizes internally. Every other hook below, and the
   * upstream leg itself, get the {@link canonicalizeHost} spelling of an
   * allowed host — see the note at the CONNECT handler's routing step.
   *
   * `explain`, called before a refusal, gives the reason: the status phrase
   * a refused CONNECT is answered with.
   */
  filter(
    port: number,
    host: string,
    socket: Socket | Duplex,
    encodedCommand?: string,
    explain?: (reason: string) => void,
  ): Promise<boolean> | boolean

  /**
   * Optional function to get the MITM proxy socket path for a given host.
   * If returns a socket path, the request will be routed through that MITM proxy.
   * If returns undefined, the request will be handled directly.
   *
   * Called with the canonical host; the CONNECT authority / absolute URI
   * forwarded to the MITM socket carries the same canonical spelling, so
   * the proxy behind the socket never has to re-derive it.
   */
  getMitmSocketPath?(host: string): string | undefined

  /**
   * If present, CONNECT requests are TLS-terminated in-process and the
   * decrypted HTTP forwarded upstream over real TLS, instead of opening an
   * opaque byte tunnel. Mutually exclusive with getMitmSocketPath at the
   * config layer (sandbox-manager rejects both being set). Needs Node, or
   * Bun 1.4 or later: on an older runtime createHttpProxyServer throws
   * (see assertTlsTerminationSupported).
   */
  mitmCA?: MitmCA

  /**
   * Per-host opt-out of TLS termination; consulted only when `mitmCA` is
   * set. Return false to leave that CONNECT as an opaque byte tunnel
   * (still hostname-allowlisted via `filter`, but not content-inspected —
   * the same posture as the non-tlsTerminate path), so the sandboxed
   * client performs its own TLS handshake end-to-end with the upstream.
   *
   * Use for upstreams the proxy must not re-originate: mTLS services
   * (only the in-sandbox client holds the client certificate) and
   * certificate-pinning clients that reject the MITM CA. Note that
   * `filterRequest` and `mutateHeaders` never see the HTTPS traffic to
   * these hosts; plain-HTTP proxy requests to them are unaffected (those
   * are readable without termination and keep the normal request pipeline).
   *
   * Absent, or returning true, means today's behaviour: terminate.
   */
  shouldTerminateTLS?(hostname: string, port: number): boolean

  /**
   * Per-request filter; runs on plain-HTTP proxy requests and on terminated
   * HTTPS requests. See request-filter.ts.
   *
   * With `filterRequest`, the request target is normalised before the hook
   * sees it and that normalised target is what is forwarded. Without it,
   * the target is forwarded as it was before the hook existed: on plain
   * HTTP that is the URL-parsed path and query (so `/a/../b` still goes
   * out as `/b`), and on the TLS-terminated path it is the client's bytes
   * unchanged.
   */
  filterRequest?: FilterRequestCallback

  /**
   * Called when `filterRequest` denies a request, with the verified
   * method/URL, the decision reason, and the encodedCommand parsed from
   * the Proxy-Authorization username. Lets the manager record the deny in
   * the SandboxViolationStore alongside the host-allowlist denials.
   */
  onFilterRequestDenied?: (info: {
    method: string
    url: string
    reason: string
    encodedCommand?: string
  }) => void

  /**
   * Mutate forwarded headers on the TLS-terminated path, after the allow
   * decision and before the upstream request is built. The upstream leg is
   * always cert-verified (rejectUnauthorized defaults to true), so the TLS
   * handshake fails before any mutated header bytes reach an unverified
   * server. See {@link MutateForwardedHeaders}.
   */
  mutateHeaders?: MutateForwardedHeaders

  /**
   * Mutate forwarded headers on the plain-HTTP path. Separate from
   * `mutateHeaders` so callers can wire the TLS path only — credential
   * injection over plaintext is opt-in.
   */
  mutateHeadersPlaintext?: MutateForwardedHeaders

  /**
   * Per-destination sentinel→real byte pairs for masked-credential
   * substitution in request BODIES on the TLS-terminated path — the body
   * counterpart of `mutateHeaders`. Consulted once per body-carrying
   * request; an empty/undefined result keeps the existing bare body pipe,
   * byte-identical. See body-substitution.ts for gating and framing rules.
   */
  getBodySubstitutions?: GetBodySubstitutions

  /**
   * Body substitution on the plain-HTTP path. Separate from
   * `getBodySubstitutions` for the same reason `mutateHeadersPlaintext` is
   * separate: credential injection over plaintext is opt-in.
   */
  getBodySubstitutionsPlaintext?: GetBodySubstitutions

  /**
   * Per-request AWS SigV4 hook on the TLS-terminated path. Runs in
   * forwardUpstream around `mutateHeaders`: requests whose signature
   * references a masked credential pair are re-signed with the real
   * credentials (or denied per policy for shapes that cannot be
   * re-signed); everything else is untouched. See credential-aws-pairs.ts.
   */
  planSigv4?: PlanSigv4

  /**
   * Override for the SigV4 literal-hash body buffering cap
   * (MAX_SIGV4_RESIGN_BODY_BYTES). Primarily a test seam — exercising the
   * over-cap denial with the production 64 MiB value would need a 64 MiB
   * fixture upload per test.
   */
  maxSigv4ResignBodyBytes?: number

  /**
   * Additional trusted CA(s) for the terminating proxy's outbound TLS leg.
   * Unset → system roots + NODE_EXTRA_CA_CERTS. Primarily a test seam.
   */
  tlsTerminateUpstreamCA?: string | Buffer | Array<string | Buffer>

  /**
   * Optional upstream HTTP proxy. When present, direct-connect traffic (i.e.
   * not routed via mitmProxy) is tunnelled through this parent instead of
   * connecting directly. NO_PROXY-matched hosts still connect directly.
   */
  parentProxy?: ResolvedParentProxy

  /**
   * Name resolution for DIRECT dials (opaque CONNECT tunnel, plain-HTTP
   * forward, TLS-terminated upstream leg), bound per destination port and
   * requesting command. The manager returns the resolved-address guard's
   * lookup, which refuses (and records) an allow-listed hostname that
   * resolves into denied address space; the proxy answers that with a 403.
   * Not consulted for the mitmProxy or parentProxy routes — that hop
   * resolves the name.
   */
  lookupFor?: DirectLookup

  /**
   * Per-session bearer token. When set, every CONNECT and absolute-URI
   * request must carry `Proxy-Authorization: Basic
   * base64("srt[.<encodedCommand>]:<token>")` or it gets a 407. Without
   * this, any host process can dial 127.0.0.1 and reach the filter
   * callback. The optional `<encodedCommand>` suffix is parsed and passed to
   * `filter()` / `onFilterRequestDenied` so denials can be attributed to a
   * specific command.
   */
  proxyAuthToken?: string

  /**
   * Whether a filterRequest allow may SET headers on a plain-HTTP request.
   * Off by default: a header set there (a credential, say) would travel in
   * cleartext. While off, an allow that carries `setHeaders` is refused with
   * 403 and nothing is forwarded; an allow without sets is unaffected, and
   * removals always apply.
   */
  plaintextHeaderSet?: boolean

  /**
   * Response headers removed before a response is written to the client,
   * on both paths, matched as removeHeaders matches (case and `-` `_` `.`
   * folded). E.g. ['set-cookie', 'set-cookie2'] keeps upstream cookies
   * from the client.
   */
  stripResponseHeaders?: string[]

  /**
   * When true, a CONNECT is served only by in-process TLS termination: a
   * CONNECT whose first bytes are not a TLS ClientHello is closed, and one
   * that would not be terminated at all (no mitmCA, or shouldTerminateTLS
   * says no) is refused with 403, instead of either being tunnelled
   * opaquely past filterRequest. Each refusal is reported through
   * onFilterRequestDenied with method CONNECT. Use it when every request
   * must be seen by filterRequest; the SOCKS side of the same port needs
   * SocksProxyServerOptions.refuseOpaqueTunnels too. CONNECT-carried SSH
   * (e.g. a GIT_SSH_COMMAND through this proxy) stops working.
   */
  refuseOpaqueTunnels?: boolean

  /**
   * When true, a request whose Host header (or, on the TLS-terminated path,
   * whose TLS server name or absolute-form authority) does not name the
   * host and port it is being sent to is answered 421 Misdirected Request
   * before filterRequest is asked, and reported through
   * onFilterRequestDenied. See hostMismatch for the accepted shapes.
   */
  requireHostMatch?: boolean

  /**
   * The largest request head (request line and headers) the proxy parses,
   * on the plain path and inside a TLS-terminated tunnel, in place of the
   * runtime's default (16 KiB in Node). A head past it is answered 400.
   * Set it above any limit filterRequest enforces, so that limit is the
   * one that answers.
   */
  maxHeaderSize?: number

  /**
   * When set, every refusal the proxy answers itself is marked
   * `<denyHeader>: <code>` in place of `X-Proxy-Error: <tag>`. The codes:
   * `host_not_allowed` (the host allowlist), `misdirected` (a 421 from
   * requireHostMatch), `bad_request` (a request-target or request the
   * proxy cannot forward), `opaque_tunnel` (refuseOpaqueTunnels),
   * `address_not_allowed` (a resolved-address refusal), and, for a
   * filterRequest deny, the decision's `mark` (`denied` when it has none).
   */
  denyHeader?: string

  /**
   * Forward the request-target exactly as the client spelled it and show
   * filterRequest that same spelling (see requestTargetAsSpelled), instead
   * of normalizing it; a target in any other shape is answered 400, as is
   * absolute form inside a TLS-terminated tunnel.
   */
  requestTargetAsSpelled?: boolean

  /**
   * Refuse, with 400 and before the allowlist is consulted, a request
   * whose destination host is not spelled in plain ASCII: letters, digits,
   * `-` and `.` in non-empty labels (one trailing dot allowed), or an IP
   * literal (IPv6 in brackets). The URL parser would otherwise map
   * fullwidth, percent-encoded and other Unicode spellings onto an ASCII
   * name. Case and a single trailing dot are still canonicalized.
   */
  requireAsciiHost?: boolean

  /**
   * Drop the client's hop-by-hop headers (and those its Connection header
   * names) in any spelling of `-`, `_` and `.` too, not only in the exact
   * spelling, before forwarding, on both paths.
   */
  foldHopByHop?: boolean

  /**
   * On the plain path, for a connection handed to the server with
   * emit('connection') and marked with markHandedInConnection, pause the
   * client's socket whenever more than this many bytes of its request body
   * are buffered in the proxy, until the body's reader pulls again.
   * Bun's HTTP server keeps reading such a connection while its request is
   * paused, and would otherwise take a large upload into memory while the
   * upstream reads slowly. Connections the server accepted itself are left
   * alone.
   */
  maxBufferedRequestBody?: number

  /**
   * At most this many CONNECT tunnels are TLS-terminated at once (default
   * 256); a CONNECT past it is answered 503 with `X-Proxy-Error:
   * too-many-tunnels`. Each holds a TLS session and an HTTP parser in this
   * process. A slot is taken when a CONNECT to a host that would be
   * terminated is accepted, before its first bytes are seen, and held until
   * the tunnel closes (an idle keep-alive tunnel holds one too), or until
   * the tunnel turns out not to carry TLS. So at the cap, a CONNECT that
   * would have been tunnelled opaquely as non-TLS is refused too.
   * SandboxManager sets it from network.tlsTerminate.maxTunnels.
   */
  maxTerminatedTunnels?: number

  /**
   * A tunnel to be TLS-terminated must finish its TLS handshake this long
   * after its CONNECT (default 10 s), or it is closed and its slot freed.
   * A tunnel that finished its handshake is not timed out afterwards.
   * SandboxManager sets it from network.tlsTerminate.handshakeTimeoutMs.
   */
  tlsHandshakeTimeoutMs?: number

  /**
   * Bytes all of this proxy's connections together may hold for slow
   * parties: request bodies waiting for an upstream, and responses waiting
   * for a client. Past it, each holds no more than it must (default
   * 256 MiB).
   *
   * Where it applies to request bodies: inside TLS-terminated tunnels under
   * Bun, on connections the proxy is handed with emit('connection'); and on
   * the plain path, for such a connection, when maxBufferedRequestBody is
   * set. Under Node the runtime's own server applies backpressure to an upload,
   * so nothing needs counting. A tunnel on a connection Bun's own listener
   * accepted (the proxy's listen(), which is how SandboxManager runs it) is
   * read on by the runtime while paused, so an upload to a stalled upstream
   * is buffered without bound there whatever this says; that is a
   * limitation of the runtime.
   */
  maxBufferedBytes?: number
  /** @internal A budget to use in place of a new one, so a test can read its counter. */
  byteBudget?: ByteBudget
}

const handedIn = new WeakSet<object>()

/**
 * Mark a socket about to be handed to a proxy server with
 * emit('connection'), so maxBufferedRequestBody applies to it.
 */
export function markHandedInConnection(socket: object): void {
  handedIn.add(socket)
}

export function createHttpProxyServer(options: HttpProxyServerOptions): Server {
  // Before anything is set up: a runtime that cannot terminate TLS
  // in-process fails here, not on each tunnel.
  if (options.mitmCA) assertTlsTerminationSupported()
  const server = createServer(
    options.maxHeaderSize !== undefined
      ? { maxHeaderSize: options.maxHeaderSize }
      : {},
  )
  let terminatedTunnels = 0
  const byteBudget =
    options.byteBudget ??
    createByteBudget(options.maxBufferedBytes ?? 256 << 20)
  /** The mark for a refusal: the deny header's code, or the legacy tag. */
  const markFor = (code: string, tag?: string): DenyMark | undefined =>
    options.denyHeader !== undefined
      ? { name: options.denyHeader, value: code }
      : tag
  const allowlistDeny = [
    ALLOWLIST_DENY[0],
    markFor('host_not_allowed', ALLOWLIST_DENY[1]),
  ] as const

  // A client that is killed mid-exchange (sandboxed process tree teardown)
  // resets its connection; without a listener that surfaces as an
  // ECONNRESET uncaughtException from node:_http_server and can take down
  // the host process. Parse errors get the RFC-required 400; resets and
  // already-unwritable sockets are just dropped.
  server.on('clientError', (err, socket) => {
    logForDebugging(`Client connection error: ${err.message}`, {
      level: 'error',
    })
    // The peer may reset while the 400 flushes; without a listener that
    // write failure is itself an uncaughtException.
    socket.on('error', () => {})
    if (
      (err as NodeJS.ErrnoException).code !== 'ECONNRESET' &&
      socket.writable
    ) {
      // Destroy only after the flush: destroying immediately races the
      // write and can reset the connection before the 400 reaches the
      // client, while end() alone can leave a half-open socket from a
      // client that never closes its side. Under Bun the flush callback
      // may never fire on a parse-errored socket (the 400 is dropped;
      // verified empirically), so back-stop with a timer or the socket
      // leaks.
      // A head past a caller's own maxHeaderSize is a request past its
      // limits: 400, as any other request past them.
      const status =
        (err as NodeJS.ErrnoException).code === 'HPE_HEADER_OVERFLOW' &&
        options.maxHeaderSize === undefined
          ? '431 Request Header Fields Too Large'
          : '400 Bad Request'
      // In a proxy that marks its refusals, this one says it came from the
      // proxy too.
      const mark =
        options.denyHeader !== undefined
          ? `${options.denyHeader}: bad_request\r\n`
          : ''
      socket.end(`HTTP/1.1 ${status}\r\n${mark}\r\n`, () => socket.destroy())
      const backstop = setTimeout(() => socket.destroy(), 1000)
      backstop.unref?.()
      return
    }
    socket.destroy()
  })

  type AuthResult = { ok: true; encodedCommand?: string } | { ok: false }
  const checkAuth = (got: string | undefined): AuthResult => {
    if (!options.proxyAuthToken) return { ok: true }
    const m = /^basic\s+([a-z0-9+/=]+)\s*$/i.exec(got ?? '')
    if (!m) return { ok: false }
    const decoded = Buffer.from(m[1]!, 'base64').toString('utf8')
    const sep = decoded.indexOf(':')
    if (sep <= 0 || decoded.slice(sep + 1) !== options.proxyAuthToken) {
      return { ok: false }
    }
    return {
      ok: true,
      encodedCommand: encodedCommandFromProxyUser(decoded.slice(0, sep)),
    }
  }

  // Handle CONNECT requests for HTTPS traffic
  server.on('connect', async (req, socket, head) => {
    // Attach error handler immediately to prevent unhandled errors
    socket.on('error', err => {
      logForDebugging(`Client socket error: ${err.message}`, { level: 'error' })
      // A failed write (e.g. EPIPE to a dead peer) must also release
      // the descriptor: logging alone leaves the fd open for the life
      // of the process, and an open dead-peer fd is what the runtime's
      // EPIPE retry loop spun on (idle-CPU busy-loop incident).
      // destroy() is idempotent, so overlap with the close handlers
      // below is harmless.
      socket.destroy()
    })

    // Track client liveness so we can abort the upstream dial if they bail.
    let clientGone = false
    socket.once('close', () => {
      clientGone = true
    })

    // EOF during the decision window is treated as abandonment — a
    // half-closed client cannot run any bidirectional protocol over the
    // tunnel it is waiting for — so close our side immediately, the
    // same close every healthy cycle performs at teardown. Without
    // this, an EOF'd socket survives an arbitrarily long filter await
    // half-open (the host decision may be a model-classifier call or
    // an interactive permission prompt), and the verdict write lands on
    // a dead descriptor. The armed window runs from here through the
    // filter await, the ClientHello peek (MITM path), and the upstream
    // dial; it is disarmed only at tunnel handoff, where established
    // tunnels forward FIN through pipe() and keep half-open semantics —
    // a FIN during the dial tears the connection down rather than
    // half-opening it, which is the cleaner teardown for a client that
    // is gone.
    //
    // Deliberate tradeoff: a hypothetical pipelined send-and-FIN
    // CONNECT client (payload + FIN up front, then read the response
    // across the half-open socket) is also destroyed here. Accepting
    // that means nothing is written once EOF has been observed
    // (checked again at write time via readableEnded). EOF
    // notification is best-effort on a paused socket, so the layered
    // backstop matters: a write that still hits a dead peer errors,
    // and the error handler above destroys the socket, releasing the
    // descriptor. On runtimes whose EPIPE handling spins on dead-peer
    // writes (the incident's Bun builds, pre oven-sh/bun#37076) this
    // narrows the exposure from every abandoned decision to only those
    // whose EOF was never notified.
    const onDecisionWindowEof = () => {
      clientGone = true
      socket.destroy()
    }
    // 'end' only fires once the stream is being read: on a paused socket
    // (which a CONNECT socket is, between the header parse and the tunnel
    // handoff) a client FIN can sit unobserved for the whole decision.
    // On the opaque path, capture decision-window data to put the socket
    // into flowing mode — making EOF notification reliable across
    // runtimes — and fold anything captured back into `head` at disarm
    // so early tunnel bytes (a client that pipelines its first payload
    // behind the CONNECT) are never lost.
    //
    // Deliberately NOT armed on the mitmCA path: the ClientHello peek
    // and the terminating relay manage this socket's flow themselves
    // (pull-mode reads chosen specifically because pause()/resume()
    // cycles corrupt CONNECT-upgraded sockets under Bun — see
    // relayPaused), and injecting a flowing-mode phase ahead of them
    // breaks the terminating path outright. There, EOF detection during
    // the decision stays best-effort ('close' fires on full close — the
    // incident case — and the peek's own reads surface 'end' once it
    // runs); the write-time guards and the error-handler backstop cover
    // the remainder.
    //
    // Capture is bounded: the paused socket used to give free TCP
    // backpressure, and an untrusted client streaming at line rate for
    // the length of an interactive permission prompt must not balloon
    // host memory. A legitimate pipelined first flight (an SSH banner)
    // is tiny; blowing the cap is abandonment-grade abuse and closes
    // the connection.
    const MAX_DECISION_CAPTURE_BYTES = 64 * 1024
    let decisionCaptureBytes = 0
    let capturing = false
    const decisionData: Buffer[] = []
    const onDecisionData = (chunk: Buffer) => {
      if (!capturing) return
      decisionCaptureBytes += chunk.length
      if (decisionCaptureBytes > MAX_DECISION_CAPTURE_BYTES) {
        logForDebugging(
          'CONNECT client exceeded pre-establishment capture cap; destroying',
          { level: 'error' },
        )
        onDecisionWindowEof()
        return
      }
      decisionData.push(chunk)
    }
    if (!options.mitmCA) {
      capturing = true
      socket.on('data', onDecisionData)
    }
    // EOF may already have been processed before this handler arms (a
    // client that sent CONNECT and FIN together), and an already-emitted
    // 'end' never re-fires — check the flag first.
    if (socket.readableEnded) {
      onDecisionWindowEof()
    } else {
      socket.once('end', onDecisionWindowEof)
    }
    // Stop capturing, folding captured bytes into `head`. The listener
    // deliberately STAYS attached as a discarding sink: 'data' events
    // broadcast to every listener, so the real consumer (pipe()) still
    // receives everything, while removing the last listener from a
    // flowing stream would silently DROP bytes arriving before the
    // consumer attaches (e.g. during the awaited upstream dial). No
    // pause() — pause/resume cycles corrupt CONNECT-upgraded sockets
    // under Bun (see relayPaused).
    const disarmDecisionCapture = () => {
      capturing = false
      if (decisionData.length) {
        head = Buffer.concat([head, ...decisionData])
        decisionData.length = 0
      }
    }
    const disarmDecisionWindowEof = () => {
      socket.removeListener('end', onDecisionWindowEof)
      disarmDecisionCapture()
    }
    // Decision-phase status writes go through this guard: a verdict for
    // a dead client is dropped, never written. The filter's work is not
    // wasted — host-side allow/deny caches serve the client's retry.
    const endWithStatus = (payload: string) => {
      if (
        clientGone ||
        socket.destroyed ||
        socket.readableEnded ||
        !socket.writable
      ) {
        logForDebugging(
          'CONNECT client gone before status write; dropping verdict and destroying socket',
        )
        socket.destroy()
        return
      }
      // Disarm before writing: a FIN processed while this verdict is
      // still queued (backpressured or slow client) would otherwise
      // fire the armed 'end' handler and destroy() the unflushed write.
      disarmDecisionWindowEof()
      socket.end(payload)
    }
    // A client that sent CONNECT and FIN together (or closed before the
    // handler ran) was destroyed at arm time: return before spending a
    // decision — possibly an interactive permission prompt or a
    // classifier call — on a connection that no longer exists.
    if (clientGone || socket.destroyed) {
      return
    }

    // Whether the MITM sniff path already wrote the 200 — hoisted so the
    // catch below can see it: once the 200 is out, any HTTP status line
    // would land inside what the client treats as tunnel payload.
    let wrote200 = false
    try {
      const auth = checkAuth(req.headers['proxy-authorization'])
      if (!auth.ok) {
        endWithStatus(
          'HTTP/1.1 407 Proxy Authentication Required\r\n' +
            'Proxy-Authenticate: Basic realm="srt"\r\n\r\n',
        )
        return
      }
      const target = parseConnectTarget(req.url!)
      if (
        !target ||
        (options.requireAsciiHost && !isAsciiAuthority(req.url!, false))
      ) {
        logForDebugging(`Invalid CONNECT request: ${req.url}`, {
          level: 'error',
        })
        const mark =
          options.denyHeader !== undefined
            ? `${options.denyHeader}: bad_request\r\n`
            : ''
        endWithStatus(`HTTP/1.1 400 Bad Request\r\n${mark}\r\n`)
        return
      }
      const { hostname: requestedHost, port } = target

      let reason: string | undefined
      const allowed = await options.filter(
        port,
        requestedHost,
        socket,
        auth.encodedCommand,
        given => {
          reason = given
        },
      )
      if (!allowed) {
        logForDebugging(`Connection blocked to ${requestedHost}:${port}`, {
          level: 'error',
        })
        endWithStatus(rawDenied(...allowlistDeny, reason))
        return
      }
      // The client may have died during the filter await (EOF destroy
      // above, or full close): there is nothing left to establish.
      if (clientGone || socket.destroyed) {
        socket.destroy()
        return
      }

      // From here on, use the spelling the allowlist actually evaluated.
      // The filter canonicalizes before matching (so `Api.Example.com.`,
      // `127.1`, `0x7f.0.0.1` are allowed iff their canonical forms are),
      // and every decision below — TLS-termination exemption, MITM
      // routing, parent-proxy bypass, credential injection, the leaf cert
      // and upstream SNI, the authority we put on the wire — must key off
      // that same spelling. Routing off the raw one let a trailing-dot
      // FQDN pass the allowlist as `api.example.com`, miss every MITM
      // pattern, and dial out directly. Same fallback as the filter for
      // the (already-validated, so practically unreachable) case where
      // canonicalization fails, so the two layers can never disagree.
      const hostname = canonicalizeHost(requestedHost) ?? requestedHost
      const lookup = options.lookupFor?.(port, auth.encodedCommand)

      // Decide upstream route:
      //   in-process TLS termination
      //   > external MITM unix socket
      //   > parent HTTP proxy
      //   > direct
      // (tlsTerminate and mitmProxy are mutually exclusive at the config
      // layer, so the first two never both apply.)
      if (
        options.mitmCA &&
        (options.shouldTerminateTLS?.(hostname, port) ?? true)
      ) {
        // We can only terminate TLS. CONNECT also carries non-TLS streams —
        // notably SSH on Linux, where the sandbox's own GIT_SSH_COMMAND
        // routes `ssh` through this proxy via `socat - PROXY:`. Send 200 so
        // the client transmits its first bytes, sniff for a ClientHello, and
        // only terminate if it is one. Non-TLS falls through to the opaque
        // tunnel below — i.e. base-sandbox behaviour, hostname-allowlisted
        // but not content-inspected (same as the SOCKS path).
        if (terminatedTunnels >= (options.maxTerminatedTunnels ?? 256)) {
          const mark = markFor('too_many_tunnels', 'too-many-tunnels')!
          const [name, value] =
            typeof mark === 'string'
              ? ['X-Proxy-Error', mark]
              : [mark.name, mark.value]
          socket.end(
            `HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\n${name}: ${value}\r\nConnection: close\r\n\r\ntoo many TLS-terminated tunnels at once`,
          )
          return
        }
        // A slot is held from here to the tunnel's close, or until it turns
        // out not to be TLS; its handshake must be done by the deadline.
        terminatedTunnels++
        let slotHeld = true
        const freeSlot = (): void => {
          if (!slotHeld) return
          slotHeld = false
          terminatedTunnels--
        }
        let handshakeDone = (): boolean => false
        const deadline = setTimeout(() => {
          // The deadline is for the handshake only: a client that finished
          // it and has sent nothing since keeps its tunnel.
          if (handshakeDone()) return
          logForDebugging(
            `[proxy] TLS handshake not done in time for ${hostname}:${port}; tunnel closed`,
          )
          socket.destroy()
        }, options.tlsHandshakeTimeoutMs ?? 10_000)
        deadline.unref?.()
        socket.once('close', () => {
          clearTimeout(deadline)
          freeSlot()
        })
        socket.write('HTTP/1.1 200 Connection Established\r\n\r\n')
        wrote200 = true
        const peeked = await peekForClientHello(socket, head)
        if (!peeked.isTLS) {
          clearTimeout(deadline)
          freeSlot()
        }
        if (clientGone || socket.destroyed) {
          socket.destroy()
          return
        }
        if (peeked.isTLS) {
          disarmDecisionWindowEof()
          terminateAndForward(
            options.mitmCA,
            options.filterRequest,
            options.mutateHeaders,
            options.getBodySubstitutions,
            socket,
            peeked.head,
            {
              hostname,
              port,
              upstreamCA: options.tlsTerminateUpstreamCA,
              lookup,
              stripResponseHeaders: options.stripResponseHeaders,
              requireHostMatch: options.requireHostMatch,
              maxHeaderSize: options.maxHeaderSize,
              foldHopByHop: options.foldHopByHop,
              denyHeader: options.denyHeader,
              requestTargetAsSpelled: options.requestTargetAsSpelled,
              byteBudget,
              onEstablished: () => clearTimeout(deadline),
              onHandshakeProbe: isDone => {
                handshakeDone = isDone
              },
              onFilterRequestDeny: options.onFilterRequestDenied
                ? (method, url, reason) =>
                    options.onFilterRequestDenied!({
                      method,
                      url,
                      reason,
                      encodedCommand: auth.encodedCommand,
                    })
                : undefined,
            },
            options.planSigv4,
            options.maxSigv4ResignBodyBytes,
          )
          return
        }
        if (options.refuseOpaqueTunnels) {
          logForDebugging(
            `[tls-terminate] non-TLS bytes on CONNECT ${hostname}:${port}; refused (refuseOpaqueTunnels)`,
          )
          options.onFilterRequestDenied?.({
            method: 'CONNECT',
            url: formatAuthority(hostname, port, 0),
            reason: 'tunnel carries no TLS and cannot be inspected',
            encodedCommand: auth.encodedCommand,
          })
          socket.destroy()
          return
        }
        logForDebugging(
          `[tls-terminate] non-TLS bytes on CONNECT ${hostname}:${port}; opaque-tunnelling`,
        )
        head = peeked.head
      } else if (options.refuseOpaqueTunnels) {
        const reason = 'this proxy does not tunnel CONNECTs it cannot inspect'
        options.onFilterRequestDenied?.({
          method: 'CONNECT',
          url: formatAuthority(hostname, port, 0),
          reason,
          encodedCommand: auth.encodedCommand,
        })
        endWithStatus(rawDenied(reason, markFor('opaque_tunnel')))
        return
      } else if (options.mitmCA) {
        // Per-host termination opt-out: the policy exempts this host (mTLS
        // upstream, cert-pinning client), so skip the MITM entirely and
        // take the opaque tunnel below, exactly as if mitmCA were unset.
        logForDebugging(
          `[tls-terminate] policy exempts ${hostname}:${port}; opaque-tunnelling`,
        )
      }

      const mitmSocketPath = options.getMitmSocketPath?.(hostname)
      const parentUrl =
        !mitmSocketPath &&
        options.parentProxy &&
        !shouldBypassParentProxy(options.parentProxy, hostname)
          ? selectParentProxyUrl(options.parentProxy, { isHttps: true })
          : undefined

      let upstream: Socket
      try {
        if (mitmSocketPath) {
          logForDebugging(
            `Routing CONNECT ${hostname}:${port} through MITM proxy at ${mitmSocketPath}`,
          )
          upstream = await openConnectTunnel({
            dial: () => connect({ path: mitmSocketPath }),
            readyEvent: 'connect',
            destHost: hostname,
            destPort: port,
          })
        } else if (parentUrl) {
          upstream = await connectViaParentProxy(parentUrl, hostname, port)
        } else {
          upstream = await dialDirect(hostname, port, lookup)
        }
      } catch (err) {
        logForDebugging(`CONNECT tunnel failed: ${(err as Error).message}`, {
          level: 'error',
        })
        // If we already sent 200 (mitmCA sniff path), an HTTP status line now
        // would land inside the tunnel as payload. Just close.
        if (wrote200) socket.destroy()
        else if (isResolvedAddressDenied(err)) {
          endWithStatus(
            rawDenied(err.message, markFor('address_not_allowed'), err.reason),
          )
        } else endWithStatus('HTTP/1.1 502 Bad Gateway\r\n\r\n')
        return
      }

      if (clientGone || socket.destroyed) {
        upstream.on('error', () => {}) // swallow post-resolve errors
        upstream.destroy()
        socket.destroy()
        return
      }

      if (!wrote200) {
        socket.write('HTTP/1.1 200 Connection Established\r\n\r\n')
      }
      disarmDecisionWindowEof()
      // An established tunnel relays each TCP direction independently: a
      // client that half-closes (FIN after its request bytes) must still
      // receive the upstream's reply. Without this, runtimes that default
      // http-server sockets to allowHalfOpen=false auto-close the client
      // side on FIN and the reply is lost.
      socket.allowHalfOpen = true
      // Forward any bytes the client sent in the same packet as the CONNECT
      // (Node delivers these as the `head` buffer, not via the socket stream),
      // plus anything the ClientHello sniff consumed when mitmCA is on.
      if (head.length) upstream.write(head)
      upstream.pipe(socket)
      socket.pipe(upstream)

      upstream.on('error', err => {
        logForDebugging(`CONNECT tunnel failed: ${err.message}`, {
          level: 'error',
        })
        socket.destroy()
      })
      socket.on('close', () => upstream.destroy())
      upstream.on('close', () => socket.destroy())
    } catch (err) {
      logForDebugging(`Error handling CONNECT: ${err}`, { level: 'error' })
      // Same rule as the 502 path: once the MITM sniff's 200 is out, a
      // status line would corrupt the tunnel byte stream — just close.
      if (wrote200) socket.destroy()
      else endWithStatus('HTTP/1.1 500 Internal Server Error\r\n\r\n')
    }
  })

  // Handle regular HTTP requests
  server.on('request', async (req, res) => {
    // A client abort mid-request destroys req/res with an error; with no
    // listener it escapes as an uncaughtException (the runtime emits it
    // from node:_http_server). `pipe()` does not forward error events, so
    // the body pipelines below never see it either.
    req.on('error', err => {
      logForDebugging(`Client request error: ${err.message}`, {
        level: 'error',
      })
    })
    res.on('error', err => {
      logForDebugging(`Client response error: ${err.message}`, {
        level: 'error',
      })
      // A failed response write (EPIPE to a dead peer) must release
      // the descriptor — same rationale as the CONNECT handler's
      // socket error handler. The res 'close' teardown listeners then
      // handle the upstream leg.
      res.socket?.destroy()
    })
    try {
      // Serve the empty CRL for Schannel's revocation check on MITM-minted
      // leaves (see MitmCA.crlDer). CryptoAPI fetches the leaf's
      // cRLDistributionPoints URL over plain HTTP with no
      // Proxy-Authorization, so this must precede both the auth check and
      // the `new URL(req.url)` parse below (which requires absolute-form).
      // Match on pathname so both origin-form (`GET /srt.crl`, what
      // CryptoAPI sends) and absolute-form (`GET http://…/srt.crl`, what a
      // proxy-aware fetcher would send) resolve; the base is ignored for
      // the absolute case.
      if (
        options.mitmCA &&
        req.method === 'GET' &&
        new URL(req.url ?? '', 'http://x').pathname === CRL_PATH
      ) {
        res.writeHead(200, {
          'Content-Type': 'application/pkix-crl',
          'Content-Length': options.mitmCA.crlDer.length,
        })
        res.end(options.mitmCA.crlDer)
        return
      }
      const auth = checkAuth(req.headers['proxy-authorization'])
      if (!auth.ok) {
        res.writeHead(407, { 'Proxy-Authenticate': 'Basic realm="srt"' })
        res.end()
        return
      }
      if (options.requireAsciiHost && !isAsciiAuthority(req.url!, true)) {
        respondDenied(
          res,
          'destination host is not plain ASCII',
          markFor('bad_request'),
          400,
        )
        return
      }
      const url = new URL(req.url!)
      const isHttps = url.protocol === 'https:'
      const defaultPort = isHttps ? 443 : 80
      const requestedHost = stripBrackets(url.hostname)
      const port = url.port ? parseInt(url.port, 10) : defaultPort

      const allowed = await options.filter(
        port,
        requestedHost,
        req.socket,
        auth.encodedCommand,
      )
      if (!allowed) {
        logForDebugging(`HTTP request blocked to ${requestedHost}:${port}`, {
          level: 'error',
        })
        // The client may have aborted during the filter await; a
        // deny for a dead client is dropped, not written. Plain
        // half-close (EOF after a complete request) is legal HTTP
        // and still gets its verdict — only a destroyed socket is
        // dead here.
        if (req.socket.destroyed || res.destroyed) {
          res.destroy()
          return
        }
        respondDenied(res, ...allowlistDeny)
        return
      }

      // Client may have disconnected while we awaited the filter; bail now
      // rather than dialing an upstream nobody will read from.
      if (req.socket.destroyed) return

      // Same rule as the CONNECT handler: everything after the allow
      // decision keys off the canonical spelling. The URL parser has
      // already lowercased and IPv4-normalized `url.hostname`; what it
      // leaves behind is the trailing dot, which is exactly the spelling
      // that used to reach getMitmSocketPath / the upstream unchanged.
      const hostname = canonicalizeHost(requestedHost) ?? requestedHost
      // The authority we forward (request-target and Host header) is rebuilt
      // from the canonical host so the MITM / parent proxy sees the host we
      // allowlist-checked, not the client's spelling of it.
      const authority = formatAuthority(hostname, port, defaultPort)

      const fwdHeaders = {
        ...stripHopByHop(req.headers, { folded: options.foldHopByHop }),
        host: authority,
      }

      // Decide upstream route: MITM unix socket > parent HTTP proxy > direct.
      const mitmSocketPath = options.getMitmSocketPath?.(hostname)
      const parentUrl =
        !mitmSocketPath &&
        options.parentProxy &&
        !shouldBypassParentProxy(options.parentProxy, hostname)
          ? selectParentProxyUrl(options.parentProxy, {
              isHttps,
            })
          : undefined

      // Reconstruct the absolute URI from parsed components rather than
      // forwarding the client's raw req.url. This ensures the upstream proxy
      // sees exactly the host we allowlist-checked, closing URL-parser
      // differential bypasses.
      // With filterRequest, the request target is normalized before the
      // hook sees it and that normalized target is what is forwarded;
      // without it, the parsed path and query are forwarded unchanged.
      // requestTargetAsSpelled comes first: it forwards the target as the
      // client spelled it, hook or no hook.
      const requestTarget = options.requestTargetAsSpelled
        ? requestTargetAsSpelled(req.url!, { absolute: true })
        : options.filterRequest
          ? normalizeRequestTarget(req.url!, req.method)
          : `${url.pathname}${url.search}`
      if (requestTarget === undefined) {
        respondDenied(
          res,
          'malformed request-target',
          markFor('bad_request'),
          400,
        )
        return
      }
      const absUrl = `${url.protocol}//${authority}${requestTarget}`

      // Per-request filter applies to plain HTTP too — otherwise a sandboxed
      // client could bypass it by using http:// where the upstream serves it.
      if (
        options.maxBufferedRequestBody !== undefined &&
        handedIn.has(req.socket)
      ) {
        gateSocketOnBufferedBody(
          req,
          options.maxBufferedRequestBody,
          byteBudget,
        )
      }
      let body: Readable = req
      let decision: RequestDecision | undefined
      if (options.requireHostMatch) {
        const hostHeaders = hostHeaderValues(req.rawHeaders)
        // RFC 9112 3.2: an HTTP/1.1 request without Host is answered 400.
        // Not every runtime's parser does it (Bun's for an emitted
        // connection passes it on).
        if (hostHeaders.length === 0 && req.httpVersion === '1.1') {
          respondDenied(
            res,
            'HTTP/1.1 request without a Host header',
            markFor('bad_request'),
            400,
          )
          return
        }
        const why = hostMismatch(hostHeaders, undefined, {
          hostname,
          port,
          defaultPort,
        })
        if (why !== undefined) {
          options.onFilterRequestDenied?.({
            method: req.method ?? 'GET',
            url: absUrl,
            reason: why,
            encodedCommand: auth.encodedCommand,
          })
          respondDenied(res, why, markFor('misdirected'), 421)
          return
        }
      }
      if (options.filterRequest) {
        const ac = new AbortController()
        res.once('close', () => ac.abort())
        const out = await decideAndRespond(
          options.filterRequest,
          req,
          res,
          absUrl,
          ac.signal,
          options.onFilterRequestDenied
            ? (method, url, reason) =>
                options.onFilterRequestDenied!({
                  method,
                  url,
                  reason,
                  encodedCommand: auth.encodedCommand,
                })
            : undefined,
          {
            target: { host: hostname, port },
            requestTarget,
            rawHeaders: [...req.rawHeaders],
            scheme: 'http',
          },
          options.denyHeader,
          options.plaintextHeaderSet === true,
        )
        if (out === null) return
        body = out.body
        decision = out.decision
        applyHeaderEdits(fwdHeaders, out.decision)
        // The client may have aborted during the filterRequest await —
        // the tee branch is already destroyed and res 'close' has already
        // fired, so the teardown listeners attached below would never
        // run. Don't dial an upstream for a dead client. A COMPLETED
        // request is also destroyed=true (normal stream lifecycle after
        // 'end'); only a destroy without a clean end is an abort.
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

      // Credential substitution runs after the decision's header edits, as
      // on the TLS-terminated path, so a set value can carry a sentinel.
      options.mutateHeadersPlaintext?.(fwdHeaders, hostname)
      // Body-substitution counterpart of mutateHeadersPlaintext (opt-in via
      // the same config gate). May delete content-length from fwdHeaders.
      const bodyTransform = prepareBodySubstitution(
        options.getBodySubstitutionsPlaintext,
        req,
        fwdHeaders,
        hostname,
      )

      // When the client declared a body but the forwarded headers carry no
      // framing (chunked TE stripped as hop-by-hop, or a body transform
      // deleted content-length), the upstream leg must re-frame
      // explicitly: for bodyless-method requests the runtime would
      // otherwise write the piped body bytes raw after complete-framed
      // headers — a request-smuggling primitive.
      const clientDeclaredBody = Boolean(
        req.headers['content-length'] || req.headers['transfer-encoding'],
      )
      if (
        clientDeclaredBody &&
        fwdHeaders['content-length'] === undefined &&
        fwdHeaders['transfer-encoding'] === undefined
      ) {
        fwdHeaders['transfer-encoding'] = 'chunked'
      }

      const failUpstream = (err: Error) => {
        logForDebugging(`Proxy request failed: ${err.message}`, {
          level: 'error',
        })
        respondUpstreamError(res, err, options.denyHeader)
      }
      let proxyReq
      if (mitmSocketPath) {
        logForDebugging(
          `Routing HTTP ${req.method} ${hostname}:${port} through MITM proxy at ${mitmSocketPath}`,
        )
        const mitmAgent = new Agent({
          // @ts-expect-error - socketPath is valid but not in types
          socketPath: mitmSocketPath,
        })
        proxyReq = httpRequest(
          {
            agent: mitmAgent,
            path: absUrl,
            method: req.method,
            headers: fwdHeaders,
          },
          proxyRes => {
            // The response stream errors independently of proxyReq (e.g.
            // upstream reset mid-body after headers); pipe() does not
            // handle source errors.
            proxyRes.on('error', err => {
              logForDebugging(`Upstream response error: ${err.message}`, {
                level: 'error',
              })
              res.destroy()
            })
            const outHeaders = stripHopByHop(proxyRes.headers)
            notifyResponse(decision, proxyRes.statusCode!, outHeaders)
            if (options.stripResponseHeaders) {
              removeHeadersFolded(outHeaders, options.stripResponseHeaders)
            }
            if (relayResponseHead(res, proxyRes, outHeaders)) proxyRes.pipe(res)
          },
        )
      } else if (parentUrl) {
        const parentHost = stripBrackets(parentUrl.hostname)
        const parentPort =
          Number(parentUrl.port) || (parentUrl.protocol === 'https:' ? 443 : 80)
        const auth = proxyAuthHeader(parentUrl)
        const requestFn =
          parentUrl.protocol === 'https:' ? httpsRequest : httpRequest
        proxyReq = requestFn(
          {
            hostname: parentHost,
            port: parentPort,
            path: absUrl,
            method: req.method,
            headers: auth
              ? { ...fwdHeaders, 'proxy-authorization': auth }
              : fwdHeaders,
          },
          proxyRes => {
            // The response stream errors independently of proxyReq (e.g.
            // upstream reset mid-body after headers); pipe() does not
            // handle source errors.
            proxyRes.on('error', err => {
              logForDebugging(`Upstream response error: ${err.message}`, {
                level: 'error',
              })
              res.destroy()
            })
            const outHeaders = stripHopByHop(proxyRes.headers)
            notifyResponse(decision, proxyRes.statusCode!, outHeaders)
            if (options.stripResponseHeaders) {
              removeHeadersFolded(outHeaders, options.stripResponseHeaders)
            }
            if (relayResponseHead(res, proxyRes, outHeaders)) proxyRes.pipe(res)
          },
        )
      } else {
        // Vet and pick the upstream address before any request object exists
        // (see directRequestOptions); the name stays in Host and, for TLS, SNI.
        let direct: DirectRequestOptions
        try {
          direct = await directRequestOptions(
            hostname,
            port,
            options.lookupFor?.(port, auth.encodedCommand),
            isHttps,
          )
        } catch (err) {
          failUpstream(err as Error)
          return
        }
        if (res.destroyed || req.socket.destroyed) {
          // Client went away during the dial.
          body.destroy()
          return
        }
        proxyReq = (isHttps ? httpsRequest : httpRequest)(
          {
            ...direct,
            path: requestTarget,
            method: req.method,
            headers: fwdHeaders,
          },
          proxyRes => {
            // The response stream errors independently of proxyReq (e.g.
            // upstream reset mid-body after headers); pipe() does not
            // handle source errors.
            proxyRes.on('error', err => {
              logForDebugging(`Upstream response error: ${err.message}`, {
                level: 'error',
              })
              res.destroy()
            })
            const outHeaders = stripHopByHop(proxyRes.headers)
            notifyResponse(decision, proxyRes.statusCode!, outHeaders)
            if (options.stripResponseHeaders) {
              removeHeadersFolded(outHeaders, options.stripResponseHeaders)
            }
            if (relayResponseHead(res, proxyRes, outHeaders)) proxyRes.pipe(res)
          },
        )
      }

      proxyReq.on('error', failUpstream)

      // Tear down the upstream request if the client goes away mid-flight.
      res.on('close', () => proxyReq.destroy())

      if (bodyTransform) {
        // Errors on either side of the extra pipe stage tear the chain
        // down — a stalled half-open upstream would otherwise wait for the
        // client.
        bodyTransform.on('error', err => proxyReq.destroy(err))
        body.on('error', err => bodyTransform.destroy(err))
        res.on('close', () => bodyTransform.destroy())
        body.pipe(bodyTransform).pipe(proxyReq)
      } else {
        // pipe() does not handle source errors. `body` may be a tee branch
        // from decideAndRespond (not `req` itself), so a client abort
        // surfaces here as an 'error' that would otherwise escape as an
        // uncaughtException.
        body.on('error', err => proxyReq.destroy(err))
        body.pipe(proxyReq)
      }
    } catch (err) {
      logForDebugging(`Error handling HTTP request: ${err}`, { level: 'error' })
      if (!res.headersSent) {
        res.writeHead(500, { 'Content-Type': 'text/plain' })
        res.end('Internal Server Error')
      } else {
        res.destroy()
      }
    }
  })

  return server
}

/**
 * Parse a CONNECT request-target into host + port. Handles both plain
 * `host:port` and bracketed IPv6 `[::1]:port`.
 */
function parseConnectTarget(
  target: string,
): { hostname: string; port: number } | undefined {
  const m =
    /^\[([^\]]+)\]:(\d+)$/.exec(target) ?? /^([^:]+):(\d+)$/.exec(target)
  if (!m) return undefined
  const port = Number(m[2])
  if (!Number.isInteger(port) || port < 1 || port > 65535) return undefined
  return { hostname: m[1]!, port }
}

/**
 * Whether the destination host of a CONNECT authority (`host:port`) or of
 * an absolute http(s) URI (`absolute`) is spelled in plain ASCII: an IP
 * literal (IPv6 in brackets), or letters, digits and `-` in non-empty
 * dot-separated labels, with one trailing dot at most.
 */
function isAsciiAuthority(raw: string, absolute: boolean): boolean {
  const m = absolute
    ? /^https?:\/\/(\[[^\]]*\]|[^/?#:@[\]]*)(?::\d+)?(?:[/?]|$)/i.exec(raw)
    : /^(\[[^\]]*\]|[^:[\]]*):\d+$/.exec(raw)
  if (!m) return false
  const host = m[1]!
  if (host.startsWith('[')) return isIP(host.slice(1, -1)) === 6
  if (isIP(host) === 4) return true
  return /^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.?$/.test(host)
}
