/**
 * Teardown for denied requests.
 *
 * A denial is enforced as soon as it is decided, but the client may still be
 * uploading the request body. Destroying the request once the 403 has
 * flushed closes a socket whose receive side still holds unread body bytes,
 * and the kernel answers that close with RST — so the client loses a 403 it
 * never read: curl reports a transport failure (broken pipe / TLS alert),
 * and a client that retries transport failures retries a refusal it must
 * not retry. Reading the remainder first lets the 403 flush and the close
 * be a clean FIN.
 *
 * Bounded so a denied upload cannot pin the connection:
 *
 * - `maxBytes` caps how much is read (a body larger than the cap still
 *   denies, at the cost of the clean 403);
 * - `idleMs` destroys once the client stops sending — the common case for a
 *   denial decided mid-body, so a stalled client releases the socket in
 *   seconds rather than waiting out `deadlineMs`;
 * - `deadlineMs` destroys a client that keeps dripping slowly forever.
 */

import type { IncomingMessage, ServerResponse } from 'node:http'

/** Stop draining after this many bytes and destroy. */
const DRAIN_MAX_BYTES = 32 * 1024 * 1024
/** Destroy once the client has sent nothing for this long. */
const DRAIN_IDLE_MS = 2_000
/** Destroy a client that never stops sending after this long. */
const DRAIN_DEADLINE_MS = 10_000

/**
 * Destroy `req` once its denial response has flushed and its remaining body
 * has been read (bounded). Callers only use this when the request stream was
 * teed — i.e. `req` itself is no longer the forwarder the caller destroys.
 *
 * The bounds are parameters so tests can exercise them without feeding
 * 32 MiB or waiting the timers out.
 */
export function drainThenDestroy(
  req: IncomingMessage,
  res: ServerResponse,
  maxBytes: number = DRAIN_MAX_BYTES,
  idleMs: number = DRAIN_IDLE_MS,
  deadlineMs: number = DRAIN_DEADLINE_MS,
): void {
  let started = false
  const destroy = () => {
    const socket = req.socket
    if (!req.destroyed) req.destroy()
    // Bun's IncomingMessage.destroy() detaches the message without tearing
    // the connection down; destroy the socket explicitly so the denied
    // client actually loses the connection.
    if (socket && !socket.destroyed) socket.destroy()
  }
  const drain = () => {
    if (started) return
    started = true
    // The parser saw the whole message: nothing is unread in the socket.
    if (req.destroyed || req.complete) {
      destroy()
      return
    }
    let drained = 0
    let finished = false
    let idle: NodeJS.Timeout | undefined
    const finish = () => {
      if (finished) return
      finished = true
      if (idle !== undefined) clearTimeout(idle)
      clearTimeout(deadline)
      destroy()
    }
    const deadline = setTimeout(finish, deadlineMs)
    deadline.unref?.()
    const touchIdle = () => {
      if (idle !== undefined) clearTimeout(idle)
      idle = setTimeout(finish, idleMs)
      idle.unref?.()
    }
    touchIdle()
    req.on('data', (chunk: Buffer) => {
      drained += chunk.length
      if (drained > maxBytes) {
        finish()
        return
      }
      touchIdle()
    })
    req.once('end', finish)
    req.once('error', finish)
    req.once('close', finish)
    // Detach any tee/forwarder pipe so `resume` reads the client's bytes
    // directly; left piped, the abandoned forwarder's backpressure pauses
    // the socket and the body never drains.
    req.unpipe()
    req.resume()
  }
  if (res.writableFinished || res.destroyed) {
    drain()
    return
  }
  res.once('finish', drain)
  res.once('close', drain)
}
