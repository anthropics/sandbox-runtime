import { describe, it, expect } from 'bun:test'
import * as net from 'node:net'
import { execSync } from 'node:child_process'
import { isLinux } from '../helpers/platform.js'
import { initializeLinuxPortForwardBridges } from '../../src/sandbox/linux-sandbox-utils.js'

/**
 * Regression test for the vacuous-readiness bug: previously,
 * initializeLinuxPortForwardBridges' readiness loop only checked
 * fs.existsSync(socketPath), a placeholder file created unconditionally
 * *before* socat even starts. This meant that if socat failed to bind the
 * requested TCP port (e.g. EADDRINUSE because something else already holds
 * it) and exited quickly, the placeholder file's existence still reported
 * "ready", silently swallowing a dead-on-arrival bridge.
 *
 * This test occupies a real port with a plain net.createServer() first (no
 * mocks), then asserts initializeLinuxPortForwardBridges rejects instead of
 * falsely reporting success — proving readiness is now tied to an actual
 * TCP connect probe against the bridged port.
 */

/** Pick a random ephemeral port, then verify it's actually free before use. */
async function pickFreePort(): Promise<number> {
  for (let attempt = 0; attempt < 10; attempt++) {
    const candidate = 20000 + Math.floor(Math.random() * 20000)
    const free = await new Promise<boolean>(resolve => {
      const server = net.createServer()
      server.once('error', () => resolve(false))
      server.listen(candidate, '127.0.0.1', () => {
        server.close(() => resolve(true))
      })
    })
    if (free) return candidate
  }
  throw new Error('Could not find a free ephemeral port after 10 attempts')
}

function occupyPort(port: number): Promise<net.Server> {
  return new Promise((resolve, reject) => {
    const server = net.createServer()
    server.once('error', reject)
    server.listen(port, '127.0.0.1', () => resolve(server))
  })
}

function closeServer(server: net.Server): Promise<void> {
  return new Promise(resolve => server.close(() => resolve()))
}

const d = isLinux ? describe : describe.skip

d('initializeLinuxPortForwardBridges bind conflict', () => {
  it('rejects instead of falsely reporting readiness when the port is already occupied', async () => {
    const port = await pickFreePort()
    const occupyingServer = await occupyPort(port)

    try {
      // eslint-disable-next-line @typescript-eslint/await-thenable
      await expect(initializeLinuxPortForwardBridges([port])).rejects.toThrow()
    } finally {
      await closeServer(occupyingServer)

      // Confirm no leaked socat process remains bound to this port.
      let psOutput = ''
      try {
        psOutput = execSync('ps aux | grep socat | grep -v grep', {
          encoding: 'utf8',
        })
      } catch {
        // grep exits non-zero when there are no matches at all — that's the
        // expected clean state.
        psOutput = ''
      }
      expect(psOutput.includes(`TCP-LISTEN:${port},`)).toBe(false)
    }
  }, 15000)
})
