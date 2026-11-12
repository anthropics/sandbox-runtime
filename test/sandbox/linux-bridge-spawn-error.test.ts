import { describe, test, expect, beforeEach, afterEach } from 'bun:test'
import * as net from 'node:net'
import * as fs from 'node:fs'
import * as os from 'node:os'
import * as path from 'node:path'
import {
  initializeLinuxNetworkBridge,
  getLinuxBridgeSocketDir,
  LINUX_MAX_UNIX_SOCKET_PATH_LEN,
} from '../../src/sandbox/linux-sandbox-utils.js'

// When spawn() cannot start socat (e.g. the binary is missing or not
// executable), the ChildProcess gets no pid and emits an asynchronous
// 'error' event. initializeLinuxNetworkBridge must have an 'error'
// listener attached before it throws on the missing pid — otherwise the
// queued event fires with no listener and escalates to an
// uncaughtException, crashing the host process even though the caller
// handled the rejection.
describe('initializeLinuxNetworkBridge spawn failure', () => {
  const uncaught: Error[] = []
  const onUncaught = (err: Error): void => {
    uncaught.push(err)
  }

  beforeEach(() => {
    uncaught.length = 0
    process.on('uncaughtException', onUncaught)
  })

  afterEach(() => {
    process.off('uncaughtException', onUncaught)
  })

  test('rejects without an unhandled error event when socat cannot be spawned', async () => {
    // bun-types declares .rejects matchers as returning void, but bun returns
    // a Promise at runtime — the await is load-bearing for the assertion.
    // eslint-disable-next-line @typescript-eslint/await-thenable
    await expect(
      initializeLinuxNetworkBridge(0, 0, '/nonexistent-for-test/socat'),
    ).rejects.toThrow('Failed to start HTTP bridge process')

    // Give the queued 'error' event a tick to fire so we can assert it was
    // absorbed by the bridge's own listener.
    await new Promise(r => setTimeout(r, 50))

    expect(uncaught).toEqual([])
  })

  test('reports child stderr in rejection when bridge process exits unexpectedly', async () => {
    const scriptPath = path.join(os.tmpdir(), `fake-socat-${Date.now()}.sh`)
    fs.writeFileSync(
      scriptPath,
      '#!/bin/sh\necho "socat: unix socket address exceeds limit" >&2\nexit 1\n',
      { mode: 0o755 },
    )

    try {
      // eslint-disable-next-line @typescript-eslint/await-thenable
      await expect(
        initializeLinuxNetworkBridge(12345, 12345, scriptPath),
      ).rejects.toThrow('socat: unix socket address exceeds limit')
    } finally {
      try {
        fs.unlinkSync(scriptPath)
      } catch {
        // Ignore cleanup error
      }
    }
  })
})

describe('Linux bridge socket path length handling', () => {
  const originalTmpdir = process.env.TMPDIR

  afterEach(() => {
    if (originalTmpdir !== undefined) {
      process.env.TMPDIR = originalTmpdir
    } else {
      delete process.env.TMPDIR
    }
  })

  test('LINUX_MAX_UNIX_SOCKET_PATH_LEN is 108', () => {
    expect(LINUX_MAX_UNIX_SOCKET_PATH_LEN).toBe(108)
  })

  test('getLinuxBridgeSocketDir returns default tmpdir when under limit', () => {
    process.env.TMPDIR = '/tmp/short-dir'
    const dir = getLinuxBridgeSocketDir('claude-socks-0123456789abcdef.sock')
    expect(dir).toBe('/tmp/short-dir')
  })

  test('getLinuxBridgeSocketDir falls back to /tmp when tmpdir produces a path >= 108 chars', () => {
    process.env.TMPDIR = '/tmp/' + 'x'.repeat(80)
    const dir = getLinuxBridgeSocketDir('claude-socks-0123456789abcdef.sock')
    expect(dir).toBe('/tmp')
    expect(
      path.join(dir, 'claude-socks-0123456789abcdef.sock').length,
    ).toBeLessThan(108)
  })

  test('initializeLinuxNetworkBridge succeeds with fallback to /tmp when TMPDIR is overlong', async () => {
    const longTmp = '/tmp/deep/' + 'y'.repeat(75)
    fs.mkdirSync(longTmp, { recursive: true })
    process.env.TMPDIR = longTmp

    const server = net.createServer()
    await new Promise<void>((resolve, reject) => {
      server.listen(0, '127.0.0.1', () => resolve())
      server.on('error', reject)
    })

    const address = server.address() as net.AddressInfo
    try {
      const bridge = await initializeLinuxNetworkBridge(
        address.port,
        address.port,
      )
      expect(bridge.httpSocketPath.length).toBeLessThan(
        LINUX_MAX_UNIX_SOCKET_PATH_LEN,
      )
      expect(bridge.httpSocketPath.startsWith('/tmp/claude-http-')).toBe(true)
      expect(fs.existsSync(bridge.httpSocketPath)).toBe(true)

      // Clean up bridge processes
      bridge.httpBridgeProcess.kill('SIGTERM')
      if (
        bridge.socksBridgeProcess &&
        bridge.socksBridgeProcess !== bridge.httpBridgeProcess
      ) {
        bridge.socksBridgeProcess.kill('SIGTERM')
      }
      try {
        fs.rmSync(bridge.httpSocketPath, { force: true })
      } catch {
        // Ignore
      }
    } finally {
      server.close()
      try {
        fs.rmSync('/tmp/deep', { recursive: true, force: true })
      } catch {
        // Ignore
      }
    }
  })
})
