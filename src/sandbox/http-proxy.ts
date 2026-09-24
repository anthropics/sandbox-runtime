import type { Socket } from 'node:net'
import type { Duplex, Readable } from 'node:stream'
import type { Server } from 'node:http'
import { Agent, createServer } from 'node:http'
import { request as httpRequest } from 'node:http'
import { request as httpsRequest } from 'node:https'
import { connect } from 'node:net'
import { URL } from 'node:url'
import { logForDebugging } from '../utils/debug.js'
import { encodedCommandFromProxyUser } from './sandbox-utils.js'
import { CRL_PATH, type MitmCA } from './mitm-ca.js'
import {
  decideAndRespond,
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
   */
  filter(
    port: number,
    host: string,
    socket: Socket | Duplex,
    encodedCommand?: string,
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
   * config layer (sandbox-manager rejects both being set).
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
}

export function createHttpProxyServer(options: HttpProxyServerOptions): Server {
  const server = createServer()

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
      const status =
        (err as NodeJS.ErrnoException).code === 'HPE_HEADER_OVERFLOW'
          ? '431 Request Header Fields Too Large'
          : '400 Bad Request'
      socket.end(`HTTP/1.1 ${status}\r\n\r\n`, () => socket.destroy())
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
      if (!target) {
        logForDebugging(`Invalid CONNECT request: ${req.url}`, {
          level: 'error',
        })
        endWithStatus('HTTP/1.1 400 Bad Request\r\n\r\n')
        return
      }
      const { hostname: requestedHost, port } = target

      const allowed = await options.filter(
        port,
        requestedHost,
        socket,
        auth.encodedCommand,
      )
      if (!allowed) {
        logForDebugging(`Connection blocked to ${requestedHost}:${port}`, {
          level: 'error',
        })
        endWithStatus(rawDenied(...ALLOWLIST_DENY))
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
        socket.write('HTTP/1.1 200 Connection Established\r\n\r\n')
        wrote200 = true
        const peeked = await peekForClientHello(socket, head)
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
        logForDebugging(
          `[tls-terminate] non-TLS bytes on CONNECT ${hostname}:${port}; opaque-tunnelling`,
        )
        head = peeked.head
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
          endWithStatus(rawDenied(err.message))
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
        respondDenied(res, ...ALLOWLIST_DENY)
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

      const fwdHeaders = { ...stripHopByHop(req.headers), host: authority }
      options.mutateHeadersPlaintext?.(fwdHeaders, hostname)
      // Body-substitution counterpart of mutateHeadersPlaintext (opt-in via
      // the same config gate). May delete content-length from fwdHeaders.
      const bodyTransform = prepareBodySubstitution(
        options.getBodySubstitutionsPlaintext,
        req,
        fwdHeaders,
        hostname,
      )

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
      const absUrl = `${url.protocol}//${authority}${url.pathname}${url.search}`

      // Per-request filter applies to plain HTTP too — otherwise a sandboxed
      // client could bypass it by using http:// where the upstream serves it.
      let body: Readable = req
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
        )
        if (out === null) return
        body = out
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
        respondUpstreamError(res, err)
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
            res.writeHead(proxyRes.statusCode!, stripHopByHop(proxyRes.headers))
            proxyRes.pipe(res)
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
            res.writeHead(proxyRes.statusCode!, stripHopByHop(proxyRes.headers))
            proxyRes.pipe(res)
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
            path: url.pathname + url.search,
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
            res.writeHead(proxyRes.statusCode!, stripHopByHop(proxyRes.headers))
            proxyRes.pipe(res)
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
