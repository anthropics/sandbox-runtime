/**
 * Proxy-only mode: SRT's HTTP proxy with no sandboxed child, for a host
 * that runs the workload elsewhere (a VM, a container) and points it at
 * this proxy.
 *
 * - Serves a listening socket the host hands in as an inherited fd (the
 *   host binds it and owns its path), or a loopback port for tests. A
 *   net.Server accepts on it and passes each connection to the HTTP proxy
 *   server, so the runtime only needs net-level listen-on-fd support.
 * - Every request is decided by an external decider (decider-client.ts).
 *   There is no other policy source: the host allowlist comes from the
 *   decider's hello, and no request is forwarded without an allow verdict.
 * - Only TLS-terminated or plain-HTTP requests are served: CONNECTs that
 *   cannot be terminated are refused, so nothing bypasses the decider.
 * - A lifeline stream (the read end of a pipe the host holds) ending
 *   shuts the proxy down, as does the decider's stream ending.
 */

import { readFileSync } from 'node:fs'
import {
  createServer as createNetServer,
  Socket as NetSocket,
  type Server as NetServer,
} from 'node:net'
import type { Server } from 'node:http'
import type { Socket } from 'node:net'
import { Readable, Writable } from 'node:stream'
import { logForDebugging } from '../utils/debug.js'
import {
  createDecider,
  type CredentialPlacement,
  type Decider,
} from './decider-client.js'
import { matchesDomainPatternWithPort } from './domain-pattern.js'
import { keepFlushedHeaderBatches } from './emitted-connection.js'
import { createHttpProxyServer, markHandedInConnection } from './http-proxy.js'
import { createMitmCA, disposeMitmCA, type MitmCA } from './mitm-ca.js'
import { canonicalizeHost, type DirectLookup } from './parent-proxy.js'
import { createResolvedAddressGuard } from './resolved-address-guard.js'

/** The largest request head proxy-only mode parses (see maxHeaderSize). */
export const REQUEST_HEAD_LIMIT = 2 << 20

/** Private and shared address space a proxy-only upstream dial never reaches by name. */
export const DEFAULT_DENIED_RESOLVED_ADDRESSES = [
  '10.0.0.0/8',
  '172.16.0.0/12',
  '192.168.0.0/16',
  '100.64.0.0/10',
  'fc00::/7',
]

/**
 * Where an allow's credential goes when its placement isn't configured:
 * `Authorization: Bearer <value>`, except that a credential of class
 * "github" sent to github.com's git transport goes as HTTP Basic with the
 * user "x-access-token", as that transport expects.
 */
export const DEFAULT_CREDENTIAL_PLACEMENTS: CredentialPlacement[] = [
  {
    class: 'github',
    host: 'github.com',
    scheme: 'basic',
    user: 'x-access-token',
  },
]

/**
 * Where the proxy accepts connections: an inherited listening socket
 * (`fd`), or a loopback address it binds itself (tests and development).
 */
export type ProxyListen = { fd: number } | { host: string; port: number }

export type ProxyOnlyOptions = {
  listen: ProxyListen
  /** The decider's streams: required, the proxy forwards nothing without one. */
  decider: { input: Readable; output: Writable }
  deciderTimeoutMs?: number
  /** CA (PEM private key and certificate) for TLS termination. Without it, every CONNECT is refused. */
  caPem?: string
  /** Stream whose end (or error) shuts the proxy down. */
  lifeline?: Readable
  stripResponseHeaders?: string[]
  deniedResolvedAddresses?: string[]
  /** Let allow verdicts set headers on plain-HTTP requests (cleartext). Default off. */
  plaintextHeaderSet?: boolean
  /** Where credential classes' values go (first match wins; default Bearer). */
  credentialPlacements?: CredentialPlacement[]
  /** Upstream CA override for the terminated leg. Test seam. */
  upstreamCA?: string
  /** Called once when the proxy has shut down; `why` names the cause. */
  onClosed?: (why: string) => void
}

export type ProxyOnly = {
  /** The HTTP proxy server. It never listens itself; `listener` feeds it. */
  server: Server
  /** The net.Server accepting on the handed fd (or loopback address). */
  listener: NetServer
  decider: Decider
  /** Resolves once the decider's hello is in and the listener is serving. */
  ready: Promise<void>
  close(why?: string): Promise<void>
}

export function isBunRuntime(): boolean {
  return typeof (globalThis as { Bun?: unknown }).Bun !== 'undefined'
}

export function startProxyOnly(opts: ProxyOnlyOptions): ProxyOnly {
  let allowed: readonly string[] = []
  let denied: readonly string[] = []
  let guard = createResolvedAddressGuard({
    deniedResolvedAddresses:
      opts.deniedResolvedAddresses ?? DEFAULT_DENIED_RESOLVED_ADDRESSES,
  })

  let closing: Promise<void> | undefined
  const decider = createDecider({
    input: opts.decider.input,
    output: opts.decider.output,
    timeoutMs: opts.deciderTimeoutMs,
    credentialPlacements:
      opts.credentialPlacements ?? DEFAULT_CREDENTIAL_PLACEMENTS,
    onDead: why => void close(`decider: ${why}`),
  })

  let mitmCA: MitmCA | undefined
  if (opts.caPem !== undefined) {
    const key =
      /-----BEGIN (?:RSA )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA )?PRIVATE KEY-----/.exec(
        opts.caPem,
      )
    const cert =
      /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/.exec(
        opts.caPem,
      )
    if (!key || !cert)
      throw new Error(
        'proxy-only: the CA PEM needs a private key and a certificate',
      )
    mitmCA = createMitmCA({
      caCertPem: cert[0] + '\n',
      caKeyPem: key[0] + '\n',
    })
  }

  const hostAllowed = (port: number, host: string): boolean => {
    const h = canonicalizeHost(host)
    if (h === undefined) return false
    if (denied.some(p => matchesDomainPatternWithPort(h, port, p))) return false
    return allowed.some(p => matchesDomainPatternWithPort(h, port, p))
  }
  const lookupFor: DirectLookup = port => guard.lookupFor(port)

  const server = createHttpProxyServer({
    filter: (port, host) => hostAllowed(port, host),
    mitmCA,
    shouldTerminateTLS: () => mitmCA !== undefined,
    refuseOpaqueTunnels: true,
    requireHostMatch: true,
    // Above the decider's 1 MiB frame, so a request past the decider's
    // limits is refused by those limits (400) rather than by the runtime's
    // header parser; a head past this is answered 400 as well.
    maxHeaderSize: REQUEST_HEAD_LIMIT,
    // Every refusal the proxy answers itself says why in X-Deny-Reason
    // (host_not_allowed, misdirected, bad_request, ...; `decider` for the
    // decider's own deny), and the request-target goes to the decider and
    // upstream exactly as the client spelled it, for the decider to match.
    denyHeader: 'X-Deny-Reason',
    requestTargetAsSpelled: true,
    // Hosts are plain ASCII; only case and one trailing dot are
    // canonicalized before the allowlist and the decider see them.
    requireAsciiHost: true,
    // A slow upstream holds at most this much of an upload in the proxy.
    // Only Bun needs it; Node's server pauses the socket itself, and a
    // 'data' listener on its socket would move its parsing to JS midway.
    maxBufferedRequestBody: isBunRuntime() ? 4 << 20 : undefined,
    // The request goes upstream without the client's hop-by-hop headers
    // (RFC 9110 7.6.1, in any separator spelling) or its trailers, which
    // the forwarding never copies.
    foldHopByHop: true,
    plaintextHeaderSet: opts.plaintextHeaderSet ?? false,
    filterRequest: decider.filterRequest,
    stripResponseHeaders: opts.stripResponseHeaders,
    lookupFor,
    tlsTerminateUpstreamCA: opts.upstreamCA,
  })
  const takesEmittedConnections = server.listenerCount('connection') > 0
  const sockets = new Set<Socket>()
  server.on('connection', (s: Socket) => {
    sockets.add(s)
    s.once('close', () => sockets.delete(s))
  })
  // Connections are accepted by a net.Server that passes each one to the
  // HTTP server. For a handed fd, http.Server.listen({ fd }) is not reliable
  // across runtimes (Bun reports success and never accepts), while
  // net.Server.listen({ fd }) either works or errors, and an error fails
  // the start. For both forms, a connection Bun's native HTTP listener
  // accepted keeps being read while paused once it is a CONNECT tunnel, so
  // a slow upstream would make the proxy buffer an upload whole; a
  // net.Socket pauses. Needs a runtime whose http.Server takes emitted
  // connections (Node, Bun >= 1.4: it has a 'connection' listener of its
  // own, counted before ours below); without one, only a loopback address
  // can be served, by the HTTP server directly.
  const listener: NetServer =
    'fd' in opts.listen || takesEmittedConnections
      ? createNetServer(sock => {
          if (closing) {
            sock.destroy()
            return
          }
          markHandedInConnection(sock)
          server.emit('connection', sock)
          keepFlushedHeaderBatches(sock)
        })
      : server

  const ready = (async () => {
    const hello = await decider.hello
    allowed = hello.allowedDomains
    denied = hello.deniedDomains
    guard = createResolvedAddressGuard({
      allowedDomains: allowed,
      deniedDomains: denied,
      deniedResolvedAddresses:
        opts.deniedResolvedAddresses ?? DEFAULT_DENIED_RESOLVED_ADDRESSES,
    })
    await new Promise<void>((resolve, reject) => {
      listener.once('error', reject)
      const done = () => {
        listener.off('error', reject)
        resolve()
      }
      if ('fd' in opts.listen) listener.listen({ fd: opts.listen.fd }, done)
      else listener.listen(opts.listen.port, opts.listen.host, done)
    })
  })()
  ready.catch(err => void close(`start failed: ${(err as Error).message}`))

  opts.lifeline?.on('data', () => {})
  opts.lifeline?.on('end', () => void close('lifeline closed'))
  opts.lifeline?.on('error', () => void close('lifeline error'))

  function close(why = 'closed'): Promise<void> {
    if (closing) return closing
    logForDebugging(`[proxy-only] shutting down: ${why}`)
    closing = (async () => {
      await Promise.resolve()
      decider.close()
      // Stop accepting; give in-flight requests (including the denials a
      // dead decider just produced) a grace period to flush, then destroy.
      if (listener.listening) listener.close()
      server.closeIdleConnections?.()
      await new Promise<void>(resolve => {
        const check = setInterval(() => {
          if (sockets.size === 0) done()
        }, 25)
        const t = setTimeout(() => {
          for (const s of sockets) s.destroy()
          done()
        }, 1000)
        function done(): void {
          clearInterval(check)
          clearTimeout(t)
          resolve()
        }
      })
      if (mitmCA) await disposeMitmCA(mitmCA)
      opts.onClosed?.(why)
    })()
    return closing
  }

  return { server, listener, decider, ready, close }
}

/** Read a whole PEM from an inherited fd (a pipe the host closes after writing). */
export function readPemFromFd(fd: number): string {
  return readFileSync(fd, 'utf8')
}

/**
 * Streams over an inherited fd (a pipe or a socket).
 *
 * Node: a net.Socket on the fd, which libuv drives non-blockingly. An
 * fs stream would park a threadpool thread in read(), and process.exit()
 * then waits for that read to return, so the proxy could not exit while
 * the peer keeps the fd open.
 * Bun: the runtime's own file streams, which poll the fd as Node's sockets
 * do. Bun's net.Socket({fd}) does not read or write an inherited fd, and an
 * fs stream parks a thread-pool thread in each blocking read(): with the
 * decider and the lifeline both waiting, a machine with one or two CPUs has
 * no thread left to write the next frame to the decider, and every request
 * times out. The writer is opened on first write, so an fd used only for
 * input (the lifeline) gets none.
 */
export function openFdStreams(fd: number): {
  input: Readable
  output: Writable
} {
  if (isBunRuntime()) {
    const file = globalThis.Bun.file(fd)
    let sink: ReturnType<typeof file.writer> | undefined
    return {
      input: Readable.fromWeb(file.stream()),
      output: new Writable({
        write(chunk: Buffer, _encoding, callback) {
          try {
            sink ??= file.writer()
            // write() may give a promise, whose failure has to reach the
            // callback too. On a broken pipe flush() throws rather than rejects.
            Promise.resolve(sink.write(chunk))
              .then(() => sink?.flush())
              .then(() => callback(), callback)
          } catch (err) {
            callback(err as Error)
          }
        },
        final(callback) {
          Promise.resolve(sink?.end()).then(() => callback(), callback)
        },
      }),
    }
  }
  const sock = new NetSocket({ fd, readable: true, writable: true })
  return { input: sock, output: sock }
}
