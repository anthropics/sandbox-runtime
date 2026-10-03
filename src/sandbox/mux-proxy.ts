import { createServer, connect, type Server, type Socket } from 'node:net'
import type { Server as HttpServer } from 'node:http'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { unlink } from 'node:fs/promises'
import { logForDebugging } from '../utils/debug.js'
import { getPlatform } from '../utils/platform.js'
import { listenInRange, loopbackListenOptions } from './listen-in-range.js'

/**
 * First-byte values that select the SOCKS handler. SOCKS5's greeting is
 * `VER NMETHODS METHODS...` with VER=0x05; SOCKS4's CONNECT is
 * `VN CD DSTPORT...` with VN=0x04. Everything else on this port is HTTP:
 * request methods start with an ASCII uppercase letter (>= 0x41 'A'),
 * h2-prior-knowledge starts `PRI ` (0x50), and a stray TLS ClientHello
 * starts 0x16 — none of which collide with 0x04/0x05. A one-byte peek is
 * therefore an unambiguous discriminator.
 */
const SOCKS_FIRST_BYTES = new Set([0x04, 0x05])

export interface MuxProxyOptions {
  /**
   * The HTTP CONNECT/absolute-URI proxy. Must NOT already be listening;
   * the mux owns its listen lifecycle (on a private unix socket on
   * macOS/Linux, or a localhost TCP port on Windows).
   */
  httpServer: HttpServer
  /**
   * Per-connection SOCKS entry point. The mux calls this with a socket
   * whose peeked first byte has been `unshift()`ed back, so the handler
   * sees the full SOCKS greeting starting at byte 0.
   */
  handleSocksConnection: (socket: Socket) => void
  /**
   * How long to wait for the client's first byte before destroying the
   * connection. Guards against connect-then-stall clients holding a slot.
   */
  firstByteTimeoutMs?: number
  /**
   * Windows only: range the HTTP backend's TCP port must fall inside, so
   * the WFP loopback permit covers the mux→backend hop. Ignored on other
   * platforms (unix socket needs no port).
   */
  httpBackendPortRange?: readonly [number, number]
}

export interface MuxProxyServer {
  /** The front-end TCP listener. Call `.listen()` on this. */
  server: Server
  /** Bound front-end port, once listening. */
  getPort(): number | undefined
  /**
   * Start the HTTP backend listener (unix socket on macOS/Linux, localhost
   * TCP on Windows). Must be awaited before the front-end `.listen()`s so
   * an early HTTP connection never dispatches to an unbound backend.
   * Returns the backend's TCP port on Windows (so the caller can exclude
   * it when binding the front-end in the same range), or undefined on
   * unix-socket platforms.
   */
  listenHttpBackend(): Promise<number | undefined>
  /** Tear down front-end, backend, and all open client sockets. */
  close(): Promise<void>
  /** unref() both listeners so they don't keep the event loop alive. */
  unref(): void
}

const DEFAULT_FIRST_BYTE_TIMEOUT_MS = 10_000

let backendSeq = 0
function unixSocketPath(): string {
  // Keep it short — macOS sun_path is 104 bytes.
  return join(
    tmpdir(),
    `srt-mux-${process.pid}-${(backendSeq++).toString(36)}.sock`,
  )
}

/**
 * Single-port proxy front-end that dispatches each connection to either the
 * SOCKS handler or the HTTP proxy based on the first byte the client sends.
 *
 * The HTTP leg cannot use `httpServer.emit('connection', socket)` because
 * Bun's `http.Server` does not implement that injection path (Node does).
 * Instead the HTTP backend listens on a private endpoint — a unix socket on
 * macOS/Linux, a localhost TCP port on Windows — and the mux pipes the
 * client socket to it. SOCKS connections are handed directly to the
 * library's per-connection entry, no extra hop.
 */
export function createMuxProxyServer(opts: MuxProxyOptions): MuxProxyServer {
  const firstByteTimeoutMs =
    opts.firstByteTimeoutMs ?? DEFAULT_FIRST_BYTE_TIMEOUT_MS
  const isWindows = getPlatform() === 'windows'

  // Where the HTTP backend listens. Exactly one of these is set after
  // listenHttpBackend() resolves.
  let backendSocketPath: string | undefined
  let backendTcpPort: number | undefined

  // Track every accepted client socket so close() can tear them down
  // immediately rather than waiting for in-flight tunnels to drain.
  const openSockets = new Set<Socket>()

  function dispatchHttp(client: Socket): void {
    if (backendSocketPath === undefined && backendTcpPort === undefined) {
      // listenHttpBackend() must resolve before the front-end listens; this
      // guard is defense-in-depth in case a future caller reorders them.
      logForDebugging('mux: HTTP dispatch before backend bound; dropping', {
        level: 'error',
      })
      client.destroy()
      return
    }
    const upstream = backendSocketPath
      ? connect(backendSocketPath)
      : connect(backendTcpPort!, '127.0.0.1')
    upstream.on('error', err => {
      // Surface a 502 with the errno code so callers (and CI logs) can tell
      // *why* the backend was unreachable instead of an opaque empty-reply.
      // Full error (including path) goes to debug logging only — the client
      // is our own sandboxed child, but there's no need to echo host paths.
      const code = (err as NodeJS.ErrnoException).code ?? 'ERR'
      logForDebugging(
        `mux: HTTP backend dial failed: ${(err as Error).message}`,
        { level: 'error' },
      )
      if (!client.destroyed) {
        client.end(
          `HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n` +
            `mux backend dial failed (${code})\n`,
        )
      }
    })
    client.on('error', () => upstream.destroy())
    client.once('close', () => upstream.destroy())
    upstream.once('close', () => client.destroy())
    client.pipe(upstream)
    upstream.pipe(client)
  }

  const server = createServer(client => {
    openSockets.add(client)
    client.once('close', () => openSockets.delete(client))
    client.on('error', err =>
      logForDebugging(`mux: client socket error: ${err.message}`),
    )

    const timer = setTimeout(() => {
      logForDebugging('mux: first-byte timeout; destroying connection')
      client.destroy()
    }, firstByteTimeoutMs)
    // Don't let a pending sniff keep the process alive.
    if (typeof timer.unref === 'function') timer.unref()

    client.once('readable', () => {
      clearTimeout(timer)
      const peek = client.read(1) as Buffer | null
      if (!peek || peek.length === 0) {
        // EOF before any byte — client connected and closed.
        client.destroy()
        return
      }
      client.unshift(peek)
      if (SOCKS_FIRST_BYTES.has(peek[0]!)) {
        opts.handleSocksConnection(client)
      } else {
        dispatchHttp(client)
      }
    })
  })

  return {
    server,
    getPort(): number | undefined {
      const addr = server.address()
      return addr && typeof addr === 'object' ? addr.port : undefined
    },
    async listenHttpBackend(): Promise<number | undefined> {
      if (!isWindows) {
        const path = unixSocketPath()
        // A prior process with the same PID may have crashed without
        // unlinking; clear any stale file so listen() doesn't EADDRINUSE.
        await unlink(path).catch(() => {})
        await new Promise<void>((resolve, reject) => {
          opts.httpServer.once('error', reject)
          opts.httpServer.listen(path, () => {
            opts.httpServer.removeListener('error', reject)
            resolve()
          })
        })
        backendSocketPath = path
        logForDebugging(`mux: HTTP backend listening on ${path}`)
        return undefined
      }
      // Windows: AF_UNIX support under Bun is unverified, so the backend
      // listens on a localhost TCP port inside the WFP-permitted range.
      // The mux→backend hop originates from the parent process (not the
      // sandboxed child), so WFP doesn't strictly require it; staying in
      // range just keeps the port surface predictable.
      // Exclusive for the same reason as the front-end: under `cluster` a
      // shared handle would let one worker's backend serve another's traffic,
      // which the pid-scoped unix socket path already prevents elsewhere.
      await listenInRange(
        opts.httpServer,
        p => opts.httpServer.listen(loopbackListenOptions(p)),
        opts.httpBackendPortRange,
        new Set(),
      )
      const addr = opts.httpServer.address()
      backendTcpPort = addr && typeof addr === 'object' ? addr.port : undefined
      logForDebugging(
        `mux: HTTP backend listening on 127.0.0.1:${backendTcpPort}`,
      )
      return backendTcpPort
    },
    async close(): Promise<void> {
      for (const s of openSockets) s.destroy()
      openSockets.clear()
      await new Promise<void>(resolve => server.close(() => resolve()))
      // The mux owns httpServer's listen lifecycle, so it owns close too.
      // sandbox-manager.reset() additionally calls forceCloseHttpServer()
      // for closeAllConnections() semantics; double-close is a no-op.
      await new Promise<void>(resolve => opts.httpServer.close(() => resolve()))
      if (backendSocketPath) {
        await unlink(backendSocketPath).catch(() => {})
        backendSocketPath = undefined
      }
      backendTcpPort = undefined
    },
    unref(): void {
      server.unref()
      opts.httpServer.unref()
    },
  }
}
