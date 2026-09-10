import { describe, test, expect, beforeEach, afterEach } from 'bun:test'
import { initializeLinuxPortForwardBridges } from '../../src/sandbox/linux-sandbox-utils.js'

// Mirrors linux-bridge-spawn-error.test.ts: when spawn() cannot start socat
// (e.g. the binary is missing or not executable), the ChildProcess gets no
// pid and emits an asynchronous 'error' event. initializeLinuxPortForwardBridges
// must have an 'error' listener attached before it throws on the missing pid —
// otherwise the queued event fires with no listener and escalates to an
// uncaughtException, crashing the host process even though the caller
// handled the rejection.
describe('initializeLinuxPortForwardBridges spawn failure', () => {
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

  test('rejects without an unhandled error event for a single port when socat cannot be spawned', async () => {
    // eslint-disable-next-line @typescript-eslint/await-thenable
    await expect(
      initializeLinuxPortForwardBridges([0], '/nonexistent-for-test/socat'),
    ).rejects.toThrow('Failed to start port-forward bridge process')

    // Give the queued 'error' event a tick to fire so we can assert it was
    // absorbed by the bridge's own listener.
    await new Promise(r => setTimeout(r, 50))

    expect(uncaught).toEqual([])
  })

  test('rejects cleanly for multiple ports with no leaked bridge processes when the first spawn fails', async () => {
    // The bogus socat path fails deterministically on the very first port,
    // exercising the same partial-cleanup path that would run if a later
    // port in a multi-port list failed after earlier bridges started: the
    // cleanupAll() helper in initializeLinuxPortForwardBridges must
    // terminate every bridge process spawned so far and not leave any
    // running processes behind.
    // eslint-disable-next-line @typescript-eslint/await-thenable
    await expect(
      initializeLinuxPortForwardBridges(
        [0, 1, 2],
        '/nonexistent-for-test/socat',
      ),
    ).rejects.toThrow('Failed to start port-forward bridge process')

    await new Promise(r => setTimeout(r, 50))

    expect(uncaught).toEqual([])
  })
})
