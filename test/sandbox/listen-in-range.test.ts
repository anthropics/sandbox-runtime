import { describe, expect, it } from 'bun:test'
import { EventEmitter } from 'node:events'
import { listenInRange } from '../../src/sandbox/listen-in-range.js'

// A server whose listen() fails with `failCode` on every port in `failing`.
function fakeServer(failing: ReadonlySet<number>, failCode: string) {
  const server = new EventEmitter()
  const tried: number[] = []
  const doListen = (port: number): void => {
    tried.push(port)
    queueMicrotask(() => {
      if (failing.has(port)) {
        const err = Object.assign(
          new Error(`listen ${failCode} 127.0.0.1:${port}`),
          {
            code: failCode,
          },
        ) as NodeJS.ErrnoException
        server.emit('error', err)
      } else {
        server.emit('listening')
      }
    })
  }
  return { server, doListen, tried }
}

describe('listenInRange', () => {
  // Windows reports a port another process holds as EACCES, not EADDRINUSE (#773).
  it('moves to the next port in range when a port fails with EACCES', async () => {
    const { server, doListen, tried } = fakeServer(new Set([60080]), 'EACCES')
    await listenInRange(server, doListen, [60080, 60089], new Set())
    expect(tried).toEqual([60080, 60081])
  })

  it('still moves to the next port on EADDRINUSE', async () => {
    const { server, doListen, tried } = fakeServer(
      new Set([60080, 60081]),
      'EADDRINUSE',
    )
    await listenInRange(server, doListen, [60080, 60089], new Set())
    expect(tried).toEqual([60080, 60081, 60082])
  })

  it('rejects with the last error when every port in range fails with EACCES', async () => {
    const { server, doListen, tried } = fakeServer(
      new Set([60080, 60081, 60082]),
      'EACCES',
    )
    // eslint-disable-next-line @typescript-eslint/await-thenable -- bun:test types .rejects as void; the await is required at runtime
    await expect(
      listenInRange(server, doListen, [60080, 60082], new Set()),
    ).rejects.toMatchObject({ code: 'EACCES' })
    expect(tried).toEqual([60080, 60081, 60082])
  })

  it('does not retry EACCES without a range', async () => {
    const { server, doListen, tried } = fakeServer(new Set([0]), 'EACCES')
    // eslint-disable-next-line @typescript-eslint/await-thenable -- bun:test types .rejects as void; the await is required at runtime
    await expect(
      listenInRange(server, doListen, undefined, new Set()),
    ).rejects.toMatchObject({ code: 'EACCES' })
    expect(tried).toEqual([0])
  })

  it('does not retry an unrelated error', async () => {
    const { server, doListen, tried } = fakeServer(
      new Set([60080]),
      'EADDRNOTAVAIL',
    )
    // eslint-disable-next-line @typescript-eslint/await-thenable -- bun:test types .rejects as void; the await is required at runtime
    await expect(
      listenInRange(server, doListen, [60080, 60089], new Set()),
    ).rejects.toMatchObject({ code: 'EADDRNOTAVAIL' })
    expect(tried).toEqual([60080])
  })

  it('leaves no stale listeners after retries', async () => {
    const { server, doListen } = fakeServer(new Set([60080, 60081]), 'EACCES')
    await listenInRange(server, doListen, [60080, 60089], new Set())
    expect(server.listenerCount('error')).toBe(0)
    expect(server.listenerCount('listening')).toBe(0)
  })
})
