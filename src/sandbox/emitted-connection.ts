/**
 * Workarounds for a runtime whose http.Server, serving a connection handed
 * to it with emit('connection') (Bun's), falls short of Node's server.
 */
import { createServer, type IncomingMessage } from 'node:http'
import type { Socket } from 'node:net'

/** Whether this is Bun, whose http.Server these workarounds are for. */
export function runsOnBun(): boolean {
  return typeof (globalThis as { Bun?: unknown }).Bun !== 'undefined'
}

let probeOverride: (() => boolean) | undefined

/**
 * Whether this runtime's http.Server serves a connection handed to it with
 * emit('connection'): Node's and Bun's from 1.4 do, and such a server has
 * a 'connection' listener of its own. TLS termination in this process
 * hands each tunnel's decrypted connection to one.
 */
export function servesEmittedConnections(): boolean {
  return probeOverride?.() ?? createServer().listenerCount('connection') > 0
}

/**
 * @internal Test seam: answer servesEmittedConnections with `probe` in
 * place of the runtime's own answer (undefined restores it). Not exported
 * from the package.
 */
export function overrideEmittedConnectionProbe(
  probe: (() => boolean) | undefined,
): void {
  probeOverride = probe
}

/** The runtime, as the start-up error names it. */
function runtimeName(): string {
  const bun = (globalThis as { Bun?: { version?: unknown } }).Bun
  if (bun !== undefined) return `Bun ${String(bun.version)}`
  return `Node ${process.version}`
}

/**
 * Throw where TLS termination is asked for and this runtime cannot do it
 * in-process (Bun before 1.4, see servesEmittedConnections). Called before
 * anything is started: without it, every tunnel to be terminated would be
 * answered 200 and then closed.
 */
export function assertTlsTerminationSupported(): void {
  if (servesEmittedConnections()) return
  throw new Error(
    `tlsTerminate needs Node, or Bun 1.4 or later (this is ${runtimeName()})`,
  )
}

/**
 * The HTTP parser hands a request's head over in batches when it has many
 * header lines (every 31 in Node's and Bun's), calling onHeaders for each
 * and then onHeadersComplete with no headers and no URL of its own. Bun's
 * server for an emitted connection installs no onHeaders, so all but the
 * last batch, the request target among them, would be lost. Where the
 * parser on the socket has no onHeaders, collect the batches as Node's
 * server does and hand them to onHeadersComplete.
 *
 * The parser reports a chunked request's trailers through onHeaders too
 * (with the request's own target again), after the body and before
 * onMessageComplete. Those are not a batch of the next request's head:
 * what is held when a message completes is dropped, as Node's server
 * clears its own, so a request's trailers and target never become part of
 * the request that follows it on the connection. Where the parser has no
 * onMessageComplete to tell the two apart, nothing is installed.
 */
export function keepFlushedHeaderBatches(sock: Socket): void {
  const parser: unknown = (sock as { parser?: unknown }).parser
  if (typeof parser !== 'object' || parser === null) return
  const slots = parser as Record<number, unknown>
  const statics = parser.constructor as {
    kOnHeaders?: unknown
    kOnHeadersComplete?: unknown
    kOnMessageComplete?: unknown
  }
  if (
    typeof statics.kOnHeaders !== 'number' ||
    typeof statics.kOnHeadersComplete !== 'number' ||
    typeof statics.kOnMessageComplete !== 'number'
  ) {
    return
  }
  const onHeaders = statics.kOnHeaders
  const onHeadersComplete = statics.kOnHeadersComplete
  const onMessageComplete = statics.kOnMessageComplete
  const complete = slots[onHeadersComplete]
  const messageComplete = slots[onMessageComplete]
  if (
    typeof slots[onHeaders] === 'function' ||
    typeof complete !== 'function' ||
    typeof messageComplete !== 'function'
  )
    return
  let headers: string[] = []
  let url = ''
  slots[onHeaders] = (batch: string[], part: string) => {
    headers = headers.concat(batch)
    url += part
  }
  slots[onHeadersComplete] = function (
    this: unknown,
    ...args: unknown[]
  ): unknown {
    if (headers.length > 0 || url !== '') {
      args[2] = Array.isArray(args[2]) ? headers.concat(args[2]) : headers
      args[4] = url + (typeof args[4] === 'string' ? args[4] : '')
      headers = []
      url = ''
    }
    return (complete as (...a: unknown[]) => unknown).apply(this, args)
  }
  slots[onMessageComplete] = function (
    this: unknown,
    ...args: unknown[]
  ): unknown {
    // Whatever came through onHeaders since the head was the message's
    // trailers.
    headers = []
    url = ''
    return (messageComplete as (...a: unknown[]) => unknown).apply(this, args)
  }
}

/**
 * Bytes a proxy's connections together may hold for slow parties (request
 * bodies waiting for an upstream, responses waiting for a client). Each
 * connection adds what it holds to `used`; past `limit`, every one of
 * them holds no more than it must.
 */
export type ByteBudget = {
  limit: number
  used: number
  /** Holders paused on the budget; each is called once when `used` drops. */
  waiters: Set<() => void>
}

export function createByteBudget(limit: number): ByteBudget {
  return { limit, used: 0, waiters: new Set() }
}

/**
 * Add `delta` to what `budget`'s holders hold. A drop wakes every waiter:
 * each re-counts for itself and waits again if there is still no room.
 */
export function adjustByteBudget(budget: ByteBudget, delta: number): void {
  budget.used += delta
  if (delta >= 0 || budget.waiters.size === 0) return
  const woken = [...budget.waiters]
  budget.waiters.clear()
  for (const wake of woken) wake()
}

/**
 * Pause req's socket whenever more than `cap` bytes of req's body sit in
 * req's buffer, or any do while `budget` is spent. Pausing the
 * IncomingMessage is not enough where the runtime keeps pushing into it
 * from a flowing socket; pausing the socket is. The server resumes the
 * socket itself when the body's reader pulls (IncomingMessage._read). Only
 * the socket is listened to: a 'data' listener on req would start the body
 * flowing before anyone reads it.
 */
export function gateSocketOnBufferedBody(
  req: IncomingMessage,
  cap: number,
  budget?: ByteBudget,
): void {
  const socket = req.socket
  let counted = 0
  const check = (): void => {
    const held = req.readableLength
    if (budget) adjustByteBudget(budget, held - counted)
    counted = held
    if (
      held > cap ||
      (budget !== undefined && budget.used > budget.limit && held > 0)
    ) {
      socket.pause()
    }
  }
  const release = (): void => {
    socket.off('data', check)
    if (budget) adjustByteBudget(budget, -counted)
    counted = 0
  }
  socket.on('data', check)
  req.once('end', release)
  req.once('close', release)
}

const endsGracefully = new WeakSet<object>()

/**
 * Mark a TLS-terminated tunnel's socket: once a response on it is done, the
 * request is ended by ending the socket (close_notify, then a FIN once the
 * queue is flushed), not by destroying it, which would drop what the TLS
 * layer has not yet written out.
 */
export function markEndsGracefully(socket: object): void {
  endsGracefully.add(socket)
}

/**
 * Stop a request whose response is out: end its socket where it is marked
 * (then destroy it after a second, for a client that keeps sending), else
 * destroy the request.
 */
export function endRequestAfterResponse(req: IncomingMessage): void {
  const socket = req.socket
  if (!endsGracefully.has(socket) || socket.destroyed) {
    req.destroy()
    return
  }
  socket.end()
  const backstop = setTimeout(() => req.destroy(), 1_000)
  backstop.unref?.()
  socket.once('close', () => clearTimeout(backstop))
}
