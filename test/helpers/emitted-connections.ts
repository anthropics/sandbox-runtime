import { describe, test } from 'bun:test'
import { servesEmittedConnections } from '../../src/sandbox/emitted-connection.js'

/**
 * Whether this runtime's http.Server serves a connection handed to it with
 * emit('connection'): Node and Bun >= 1.4 do, and such a server has a
 * 'connection' listener of its own. TLS termination in this process and a
 * handed listening socket both need it; without it a proxy given a CA
 * refuses to start, and the descriptor forms of srt-proxy cannot serve.
 */
export const SERVES_EMITTED_CONNECTIONS = servesEmittedConnections()

/**
 * `describe` and `test` for cases that run a proxy configured to terminate
 * TLS: skipped where this runtime cannot (Bun before 1.4), where such a
 * proxy refuses to start. The reason is logged once below.
 */
export const describeWithTls = describe.skipIf(!SERVES_EMITTED_CONNECTIONS)
export const testWithTls = test.skipIf(!SERVES_EMITTED_CONNECTIONS)

if (!SERVES_EMITTED_CONNECTIONS) {
  console.warn(
    `TLS termination tests are skipped: tlsTerminate needs Node, or Bun 1.4 or later, and this is Bun ${String((globalThis as { Bun?: { version?: unknown } }).Bun?.version)}`,
  )
}
