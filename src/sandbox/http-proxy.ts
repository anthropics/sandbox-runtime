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
  type FilterRequestCallback,
  type MutateForwardedHeaders,
} from './request-filter.js'
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
import {
  connectViaParentProxy,
  dialDirect,
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
    })

    // Track client liveness so we can abort the upstream dial if they bail.
    let clientGone = false
    socket.once('close', () => {
      clientGone = true
    })

    try {
      const auth = checkAuth(req.headers['proxy-authorization'])
      if (!auth.ok) {
        socket.end(
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
        socket.end('HTTP/1.1 400 Bad Request\r\n\r\n')
        return
      }
      const { hostname, port } = target

      const allowed = await options.filter(
        port,
        hostname,
        socket,
        auth.encodedCommand,
      )
      if (!allowed) {
        logForDebugging(`Connection blocked to ${hostname}:${port}`, {
          level: 'error',
        })
        socket.end(
          'HTTP/1.1 403 Forbidden\r\n' +
            'Content-Type: text/plain\r\n' +
            'X-Proxy-Error: blocked-by-allowlist\r\n' +
            '\r\n' +
            'Connection blocked by network allowlist',
        )
        return
      }

      // Decide upstream route:
      //   in-process TLS termination
      //   > external MITM unix socket
      //   > parent HTTP proxy
      //   > direct
      // (tlsTerminate and mitmProxy are mutually exclusive at the config
      // layer, so the first two never both apply.)
      let wrote200 = false
      if (
        options.mitmCA &&
        (options.shouldTerminateTLS?.(hostname, port) ?? true)
      ) {
        if (clientGone) return
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
        if (clientGone) return
        if (peeked.isTLS) {
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
          upstream = await dialDirect(hostname, port)
        }
      } catch (err) {
        logForDebugging(`CONNECT tunnel failed: ${(err as Error).message}`, {
          level: 'error',
        })
        // If we already sent 200 (mitmCA sniff path), an HTTP status line now
        // would land inside the tunnel as payload. Just close.
        if (wrote200) socket.destroy()
        else socket.end('HTTP/1.1 502 Bad Gateway\r\n\r\n')
        return
      }

      if (clientGone) {
        upstream.on('error', () => {}) // swallow post-resolve errors
        upstream.destroy()
        return
      }

      if (!wrote200) {
        socket.write('HTTP/1.1 200 Connection Established\r\n\r\n')
      }
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
      socket.end('HTTP/1.1 500 Internal Server Error\r\n\r\n')
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
      const hostname = stripBrackets(url.hostname)
      const port = url.port
        ? parseInt(url.port, 10)
        : url.protocol === 'https:'
          ? 443
          : 80

      const allowed = await options.filter(
        port,
        hostname,
        req.socket,
        auth.encodedCommand,
      )
      if (!allowed) {
        logForDebugging(`HTTP request blocked to ${hostname}:${port}`, {
          level: 'error',
        })
        res.writeHead(403, {
          'Content-Type': 'text/plain',
          'X-Proxy-Error': 'blocked-by-allowlist',
        })
        res.end('Connection blocked by network allowlist')
        return
      }

      // Client may have disconnected while we awaited the filter; bail now
      // rather than dialing an upstream nobody will read from.
      if (req.socket.destroyed) return

      const fwdHeaders = { ...stripHopByHop(req.headers), host: url.host }
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
              isHttps: url.protocol === 'https:',
            })
          : undefined

      // Reconstruct the absolute URI from parsed components rather than
      // forwarding the client's raw req.url. This ensures the upstream proxy
      // sees exactly the host we allowlist-checked, closing URL-parser
      // differential bypasses.
      const absUrl = `${url.protocol}//${url.host}${url.pathname}${url.search}`

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
        const requestFn = url.protocol === 'https:' ? httpsRequest : httpRequest
        proxyReq = requestFn(
          {
            hostname,
            port,
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

      proxyReq.on('error', err => {
        logForDebugging(`Proxy request failed: ${err.message}`, {
          level: 'error',
        })
        if (!res.headersSent) {
          res.writeHead(502, { 'Content-Type': 'text/plain' })
          res.end('Bad Gateway')
        } else {
          res.destroy()
        }
      })

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
