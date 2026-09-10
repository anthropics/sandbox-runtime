import { describe, it, expect } from 'bun:test'
import * as net from 'node:net'
import { spawn } from 'node:child_process'
import { unlinkSync } from 'node:fs'
import { isLinux } from '../helpers/platform.js'
import {
  initializeLinuxPortForwardBridges,
  wrapCommandWithSandboxLinux,
} from '../../src/sandbox/linux-sandbox-utils.js'

/**
 * Real, no-mock E2E coverage for the reverse loopback port-forward feature:
 * a sandboxed process that binds a TCP server on 127.0.0.1:<port> inside an
 * `--unshare-net` namespace can be reached from the (unsandboxed) host when
 * `exposeLoopbackPorts` is configured, and remains unreachable (isolation
 * intact) when it isn't. Uses real bwrap and socat binaries.
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

/** Poll until a TCP connect to 127.0.0.1:<port> succeeds or the deadline passes. */
async function connectWithRetry(
  port: number,
  deadlineMs: number,
): Promise<string> {
  const start = Date.now()
  let lastError: unknown
  while (Date.now() - start < deadlineMs) {
    try {
      const data = await new Promise<string>((resolve, reject) => {
        const socket = net.connect({ host: '127.0.0.1', port }, () => {})
        let received = ''
        socket.setTimeout(500)
        socket.on('data', d => (received += d.toString()))
        socket.on('close', () => resolve(received))
        socket.on('timeout', () => {
          socket.destroy()
          resolve(received)
        })
        socket.on('error', reject)
      })
      // The host-side bridge accepts the TCP connection immediately, but
      // its UNIX-CONNECT to the sandbox side can fail (empty response,
      // connection closed) until the in-sandbox socat listener has
      // finished its `unlink-early` bind — retry until real data arrives.
      if (data.length > 0) return data
    } catch (err) {
      lastError = err
    }
    await new Promise(r => setTimeout(r, 100))
  }
  throw lastError ?? new Error(`Timed out connecting to port ${port}`)
}

/** Attempt a single connect, expecting it to fail or time out quickly. */
async function expectConnectionRefusedOrTimeout(
  port: number,
  timeoutMs: number,
): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const socket = net.connect({ host: '127.0.0.1', port })
    const timer = setTimeout(() => {
      socket.destroy()
      resolve() // timed out without connecting: isolation intact
    }, timeoutMs)
    socket.on('connect', () => {
      clearTimeout(timer)
      socket.destroy()
      reject(new Error(`Unexpectedly connected to port ${port}`))
    })
    socket.on('error', () => {
      clearTimeout(timer)
      resolve() // connection refused: isolation intact
    })
  })
}

const d = isLinux ? describe : describe.skip

d('Linux loopback port-forward (real bwrap + socat)', () => {
  it('allows the host to reach a TCP server bound inside the network-isolated sandbox when exposeLoopbackPorts is configured', async () => {
    const port = await pickFreePort()
    const bridge = (
      await initializeLinuxPortForwardBridges([port], undefined)
    )[0]!

    let sandboxChild: ReturnType<typeof spawn> | undefined
    try {
      const command = await wrapCommandWithSandboxLinux({
        command: `socat TCP-LISTEN:${port},fork,reuseaddr,bind=127.0.0.1 SYSTEM:'echo ok'`,
        needsNetworkRestriction: true,
        exposeLoopbackPorts: [{ port, socketPath: bridge.socketPath }],
      })

      sandboxChild = spawn(command, {
        shell: true,
        stdio: 'ignore',
        detached: true,
      })

      const response = await connectWithRetry(port, 5000)
      expect(response.trim()).toBe('ok')
    } finally {
      if (sandboxChild?.pid) {
        try {
          process.kill(-sandboxChild.pid, 'SIGKILL')
        } catch {
          // Ignore errors (process may already be gone)
        }
      }
      if (bridge.bridgeProcess.pid) {
        try {
          process.kill(bridge.bridgeProcess.pid, 'SIGKILL')
        } catch {
          // Ignore errors
        }
      }
      try {
        unlinkSync(bridge.socketPath)
      } catch {
        // Ignore errors (may already be removed)
      }
    }
  }, 15000)

  it('keeps network isolation intact (host cannot reach the sandboxed port) when exposeLoopbackPorts is not configured', async () => {
    const port = await pickFreePort()

    let sandboxChild: ReturnType<typeof spawn> | undefined
    try {
      const command = await wrapCommandWithSandboxLinux({
        command: `socat TCP-LISTEN:${port},fork,reuseaddr,bind=127.0.0.1 SYSTEM:'echo ok'`,
        needsNetworkRestriction: true,
      })

      sandboxChild = spawn(command, {
        shell: true,
        stdio: 'ignore',
        detached: true,
      })

      // Give the sandboxed socat listener a moment to actually start
      // (inside its own isolated namespace) before probing from the host.
      await new Promise(r => setTimeout(r, 500))

      await expectConnectionRefusedOrTimeout(port, 2000)
    } finally {
      if (sandboxChild?.pid) {
        try {
          process.kill(-sandboxChild.pid, 'SIGKILL')
        } catch {
          // Ignore errors (process may already be gone)
        }
      }
    }
  }, 10000)
})
