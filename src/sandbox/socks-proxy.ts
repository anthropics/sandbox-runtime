import type { Socket } from 'net'
import { createServer } from '@pondwader/socks5-server'
import { logForDebugging } from '../utils/debug.js'
import type { ResolvedParentProxy } from './parent-proxy.js'
import {
  connectViaParentProxy,
  dialDirect,
  isValidHost,
  selectParentProxyUrl,
  shouldBypassParentProxy,
} from './parent-proxy.js'
import {
  encodedCommandFromProxyUser,
  PROXY_AUTH_USER,
} from './sandbox-utils.js'

export interface SocksProxyServerOptions {
  /**
   * Host-allowlist decision. `encodedCommand` is the per-command suffix
   * parsed from the SOCKS5 username (`srt.<encodedCommand>`), so the
   * manager can attribute a denial to the invocation that made it.
   */
  filter(
    port: number,
    host: string,
    encodedCommand?: string,
  ): Promise<boolean> | boolean

  /**
   * Optional upstream HTTP proxy. When present, SOCKS CONNECT requests are
   * tunnelled through the parent's HTTP CONNECT instead of dialing directly.
   * NO_PROXY-matched hosts still connect directly.
   */
  parentProxy?: ResolvedParentProxy

  /**
   * Per-session token (same value as the HTTP proxy's). When set, the
   * server requires SOCKS5 username/password auth and only accepts
   * usernames of the form `srt` or `srt.<encodedCommand>` with this token
   * as the password. The `<encodedCommand>` suffix is passed to `filter()`
   * so denials can be attributed to a specific command.
   */
  proxyAuthToken?: string
}

export interface SocksProxyWrapper {
  /**
   * Hand an already-accepted socket to the SOCKS state machine. Used by the
   * mux front-end after first-byte sniffing. The socket must carry the full
   * SOCKS greeting starting at byte 0 (i.e. any peeked bytes already
   * `unshift()`ed back). Replicates the library's own accept path
   * (`setNoDelay()` + `_handleConnection`) and tracks the socket so
   * `close()` can force-destroy it.
   */
  handleConnection(socket: Socket): void
  /** Force-destroy all injected connections. */
  close(): Promise<void>
}

export function createSocksProxyServer(
  options: SocksProxyServerOptions,
): SocksProxyWrapper {
  const socksServer = createServer()

  if (options.proxyAuthToken) {
    socksServer.setAuthHandler((conn, accept, deny) => {
      if (
        (conn.username === PROXY_AUTH_USER ||
          conn.username.startsWith(`${PROXY_AUTH_USER}.`)) &&
        conn.password === options.proxyAuthToken
      ) {
        accept()
      } else {
        logForDebugging('SOCKS auth rejected', { level: 'error' })
        deny()
      }
    })
  }

  socksServer.setRulesetValidator(async conn => {
    try {
      const hostname = conn.destAddress
      const port = conn.destPort

      // SOCKS5 DOMAINNAME is a raw length-prefixed byte string with zero
      // validation from the protocol or the library. Reject control chars
      // (null bytes, CRLF) here so they never reach the allowlist matcher,
      // where string suffix matching would be trivially fooled.
      if (!isValidHost(hostname)) {
        logForDebugging(
          `Rejecting malformed SOCKS host: ${JSON.stringify(hostname)}`,
          { level: 'error' },
        )
        return false
      }

      logForDebugging(`Connection request to ${hostname}:${port}`)

      const allowed = await options.filter(
        port,
        hostname,
        encodedCommandFromProxyUser(conn.username),
      )

      if (!allowed) {
        logForDebugging(`Connection blocked to ${hostname}:${port}`, {
          level: 'error',
        })
        return false
      }

      logForDebugging(`Connection allowed to ${hostname}:${port}`)
      return true
    } catch (error) {
      logForDebugging(`Error validating connection: ${error}`, {
        level: 'error',
      })
      return false
    }
  })

  // Override the default connection handler so we can route through a parent
  // HTTP proxy when one is configured. The default handler does a straight
  // net.connect() which fails when direct egress is blocked.
  socksServer.setConnectionHandler((conn, sendStatus) => {
    const host = conn.destAddress
    const port = conn.destPort

    // Track client liveness so we can abort the upstream dial if they bail.
    let clientGone = false
    let upstreamRef: Socket | undefined
    conn.socket.once('close', () => {
      clientGone = true
      upstreamRef?.destroy()
    })
    conn.socket.on('error', () => upstreamRef?.destroy())

    // SOCKS is an opaque TCP tunnel — semantically identical to HTTP
    // CONNECT — so always prefer HTTPS_PROXY if set, regardless of dest port.
    const parentUrl =
      options.parentProxy && !shouldBypassParentProxy(options.parentProxy, host)
        ? selectParentProxyUrl(options.parentProxy, { isHttps: true })
        : undefined

    const open = parentUrl
      ? connectViaParentProxy(parentUrl, host, port)
      : dialDirect(host, port)

    open
      .then(upstream => {
        upstreamRef = upstream
        upstream.on('error', () => conn.socket.destroy())
        if (clientGone) {
          upstream.destroy()
          return
        }
        sendStatus('REQUEST_GRANTED')
        upstream.pipe(conn.socket)
        conn.socket.pipe(upstream)
        upstream.on('close', () => conn.socket.destroy())
      })
      .catch(err => {
        logForDebugging(
          `SOCKS connect to ${host}:${port} failed: ${(err as Error).message}`,
          { level: 'error' },
        )
        if (!clientGone) {
          try {
            sendStatus('HOST_UNREACHABLE')
          } catch {
            // socket may have closed between the check and the write
          }
        }
      })
  })

  // Track every injected client socket so close() can tear them down
  // immediately. A SOCKS connection mid-`dialDirect()` (30s timeout) or
  // mid-relay would otherwise hold reset() open past bun's test timeout.
  // The library's internal net.Server is never .listen()ed — the mux owns
  // accept — so there's no listener to close; we only destroy sockets.
  const openSockets = new Set<Socket>()

  return {
    handleConnection(socket: Socket): void {
      socket.setNoDelay()
      openSockets.add(socket)
      socket.once('close', () => openSockets.delete(socket))
      socksServer._handleConnection(socket)
    },
    async close(): Promise<void> {
      for (const socket of openSockets) socket.destroy()
      openSockets.clear()
    },
  }
}
