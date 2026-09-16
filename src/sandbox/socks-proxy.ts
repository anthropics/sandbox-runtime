import type { Socket } from 'net'
import { createServer } from '@pondwader/socks5-server'
import { logForDebugging } from '../utils/debug.js'
import type { DirectLookup, ResolvedParentProxy } from './parent-proxy.js'
import { isResolvedAddressDenied } from './resolved-address-guard.js'
import {
  canonicalizeHost,
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

  /** Direct-dial name resolution (see HttpProxyServerOptions.lookupFor); a refusal is answered "not allowed by ruleset". */
  lookupFor?: DirectLookup

  /**
   * Per-session token (same value as the HTTP proxy's). When set, the
   * server requires SOCKS5 username/password auth and only accepts
   * usernames of the form `srt` or `srt.<encodedCommand>` with this token
   * as the password. The `<encodedCommand>` suffix is passed to `filter()`
   * so denials can be attributed to a specific command.
   */
  proxyAuthToken?: string

  /**
   * Consulted for a client that cannot authenticate (it offered no
   * username/password method — e.g. BSD `nc -X 5`, the stock macOS ssh
   * ProxyCommand). Such a connection is NEVER tunnelled; this decides what
   * the refusal says. Return `deniedReason` when the destination matches an
   * explicit deny rule (the caller may also record the violation);
   * return `{}` for everything else. Must not prompt the user — the peer
   * is unauthenticated.
   *
   * Reason copy guidance: OpenSSH truncates the printed disconnect
   * description (~400 chars) and octal-escapes non-ASCII, so keep reasons
   * for SSH-ported deny entries short, imperative-first, and ASCII.
   */
  probeUnauthenticated?(
    port: number,
    host: string,
  ): Promise<{ deniedReason?: string }>
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
    // The ruleset validator above allowed this destination on its
    // canonical spelling; dial (and make the parent-proxy decision on)
    // that same spelling, as the HTTP proxy does, rather than the client's.
    const host = canonicalizeHost(conn.destAddress) ?? conn.destAddress
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
      : dialDirect(
          host,
          port,
          options.lookupFor?.(port, encodedCommandFromProxyUser(conn.username)),
        )

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
            sendStatus(
              isResolvedAddressDenied(err)
                ? 'CONNECTION_NOT_ALLOWED'
                : 'HOST_UNREACHABLE',
            )
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
      if (!options.proxyAuthToken) {
        socksServer._handleConnection(socket)
        return
      }
      // Auth is required. Peek the greeting (VER NMETHODS METHODS...): a
      // client that does not offer method 0x02 (username/password) can never
      // authenticate — the library would reply 0xFF and the client dies with
      // an opaque "authentication method negotiation failed". Route it to
      // the refusal probe instead so the failure carries the policy reason
      // (for SSH, in-band — see refuseUnauthenticated). Clients that DO
      // offer 0x02 get the greeting unshifted back and the normal
      // authenticated path.
      readSocksGreeting(socket, canAuthenticate => {
        if (canAuthenticate) {
          socksServer._handleConnection(socket)
          return
        }
        refuseUnauthenticated(socket, options).catch(() => socket.destroy())
      })
    },
    async close(): Promise<void> {
      for (const socket of openSockets) socket.destroy()
      openSockets.clear()
    },
  }
}

const SOCKS_METHOD_NO_AUTH = 0x00
const SOCKS_METHOD_USERPASS = 0x02

/**
 * Peek the SOCKS5 greeting off the socket and report whether the client
 * offered username/password auth. Before the callback runs, the socket is
 * paused and every buffered byte is pushed back in a single `unshift` for
 * the authenticated path (the library re-reads the greeting itself), or
 * just the post-greeting surplus for the probe path (which consumed the
 * greeting by answering it). A single unshift on a paused socket is the
 * only ordering the stream API guarantees — two unshifts on a flowing
 * socket can drop or reorder pipelined bytes. Destroys the socket on
 * malformed input.
 */
function readSocksGreeting(
  socket: Socket,
  done: (canAuthenticate: boolean) => void,
): void {
  let buf = Buffer.alloc(0)
  const onData = (chunk: Buffer): void => {
    buf = Buffer.concat([buf, chunk])
    if (buf.length < 2) return
    if (buf[0] !== 0x05) {
      socket.off('data', onData)
      socket.destroy()
      return
    }
    const nMethods = buf[1]!
    if (buf.length < 2 + nMethods) return
    socket.off('data', onData)
    socket.pause()
    const methods = buf.subarray(2, 2 + nMethods)
    const canAuthenticate = methods.includes(SOCKS_METHOD_USERPASS)
    const pushBack = canAuthenticate ? buf : buf.subarray(2 + nMethods)
    if (pushBack.length > 0) socket.unshift(pushBack)
    done(canAuthenticate)
  }
  socket.on('data', onData)
  socket.once('error', () => socket.off('data', onData))
}

/**
 * Terminal handler for a SOCKS5 client that cannot authenticate. Completes
 * just enough of the protocol to learn the CONNECT destination, then
 * refuses — there is deliberately no code path here that dials upstream, so
 * an unauthenticated peer can never use the proxy as a relay.
 *
 * For an SSH destination (port 22) the refusal is delivered in-band: a
 * minimal SSH server identification plus a plaintext pre-key-exchange
 * SSH_MSG_DISCONNECT whose description is the policy reason. OpenSSH prints
 * that description verbatim ("Received disconnect from ...: <reason>"), so
 * a git-over-ssh user (or agent) sees WHY instead of an opaque
 * "authentication method negotiation failed". Non-SSH ports get the plain
 * SOCKS "connection not allowed" reply.
 */
async function refuseUnauthenticated(
  socket: Socket,
  options: SocksProxyServerOptions,
): Promise<void> {
  // Select the no-auth method so the client proceeds to its CONNECT request.
  socket.write(Buffer.from([0x05, SOCKS_METHOD_NO_AUTH]))
  const request = await readSocksConnect(socket)
  if (request === undefined) {
    socket.destroy()
    return
  }
  const { host, port } = request
  if (!isValidHost(host)) {
    socket.end(socksReply(0x02))
    return
  }
  const probe = options.probeUnauthenticated
    ? await options.probeUnauthenticated(port, host)
    : {}
  logForDebugging(
    `SOCKS unauthenticated client refused for ${host}:${port}` +
      (probe.deniedReason !== undefined ? ' (denied by policy)' : ''),
  )
  if (port !== 22) {
    socket.end(socksReply(0x02))
    return
  }
  // The built-in fallback states only what the proxy itself knows. An
  // embedder that wants environment-specific guidance (e.g. "use an
  // https:// remote") should express it as a deny rule with a reason —
  // a `*:22` deniedDomains entry covers every SSH destination.
  const reason =
    probe.deniedReason ??
    'This proxy requires authentication, and this client did not offer an ' +
      'authentication method, so the connection was refused.'
  // SOCKS success (bind address 0.0.0.0:0), then speak SSH.
  socket.write(socksReply(0x00))
  socket.write(Buffer.from('SSH-2.0-policy_refusal\r\n'))
  socket.end(sshDisconnectPacket(reason))
}

/** SOCKS5 reply with the given status and a zero bind address. */
function socksReply(status: number): Buffer {
  return Buffer.from([0x05, status, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
}

/** Parse the SOCKS5 CONNECT request (after method selection). */
function readSocksConnect(
  socket: Socket,
): Promise<{ host: string; port: number } | undefined> {
  return new Promise(resolve => {
    let buf = Buffer.alloc(0)
    const finish = (value: { host: string; port: number } | undefined) => {
      socket.off('data', onData)
      clearTimeout(timer)
      resolve(value)
    }
    // An unauthenticated peer gets a short leash: if the CONNECT request
    // doesn't arrive promptly, drop the connection.
    const timer = setTimeout(() => finish(undefined), 5000)
    const onData = (chunk: Buffer): void => {
      buf = Buffer.concat([buf, chunk])
      if (buf.length < 4) return
      if (buf[0] !== 0x05 || buf[1] !== 0x01 /* CONNECT */) {
        finish(undefined)
        return
      }
      const atyp = buf[3]!
      if (atyp === 0x01) {
        if (buf.length < 10) return
        const host = Array.from(buf.subarray(4, 8)).join('.')
        finish({ host, port: buf.readUInt16BE(8) })
      } else if (atyp === 0x03) {
        if (buf.length < 5) return
        const len = buf[4]!
        if (buf.length < 5 + len + 2) return
        finish({
          host: buf.subarray(5, 5 + len).toString('utf8'),
          port: buf.readUInt16BE(5 + len),
        })
      } else if (atyp === 0x04) {
        if (buf.length < 22) return
        const parts: string[] = []
        for (let i = 0; i < 16; i += 2) {
          parts.push(buf.readUInt16BE(4 + i).toString(16))
        }
        finish({ host: parts.join(':'), port: buf.readUInt16BE(20) })
      } else {
        finish(undefined)
      }
    }
    socket.on('data', onData)
    // readSocksGreeting explicitly pause()d the socket; an explicit pause is
    // NOT lifted by attaching a 'data' listener, so resume by hand.
    socket.resume()
    socket.once('error', () => finish(undefined))
    socket.once('close', () => finish(undefined))
  })
}

/**
 * A plaintext SSH_MSG_DISCONNECT, legal before key exchange (RFC 4253:
 * SSH_MSG_DISCONNECT may be sent at any time; pre-NEWKEYS packets carry no
 * MAC and no encryption). reason code 1 = HOST_NOT_ALLOWED_TO_CONNECT.
 * The description is what OpenSSH prints; collapse control characters so a
 * configured reason can't fabricate extra log lines, and cap the length.
 */
function sshDisconnectPacket(description: string): Buffer {
  const text = description
    // eslint-disable-next-line no-control-regex -- stripping control chars is the point
    .replace(/[\x00-\x1f\x7f-\x9f]+/g, ' ')
    .slice(0, 1000)
  const desc = Buffer.from(text, 'utf8')
  const lang = Buffer.alloc(0)
  const payload = Buffer.concat([
    Buffer.from([0x01]), // SSH_MSG_DISCONNECT
    uint32(1), // SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT
    uint32(desc.length),
    desc,
    uint32(lang.length),
    lang,
  ])
  // packet_length = padding_length byte + payload + padding;
  // (4 + packet_length) must be a multiple of 8, padding >= 4.
  let padding = 8 - ((4 + 1 + payload.length) % 8)
  if (padding < 4) padding += 8
  const packet = Buffer.concat([
    uint32(1 + payload.length + padding),
    Buffer.from([padding]),
    payload,
    Buffer.alloc(padding),
  ])
  return packet
}

function uint32(n: number): Buffer {
  const b = Buffer.alloc(4)
  b.writeUInt32BE(n, 0)
  return b
}
