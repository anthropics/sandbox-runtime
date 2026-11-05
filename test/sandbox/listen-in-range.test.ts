import { describe, expect, test } from 'bun:test'
import { EventEmitter } from 'node:events'
import { listenInRange } from '../../src/sandbox/listen-in-range.js'

describe('listenInRange', () => {
  for (const code of ['EADDRINUSE', 'EACCES']) {
    test(`tries the next permitted port after ${code}`, async () => {
      const server = new EventEmitter()
      const ports: number[] = []

      await listenInRange(
        server,
        port => {
          ports.push(port)
          queueMicrotask(() => {
            if (port === 60080) {
              server.emit('error', Object.assign(new Error(code), { code }))
            } else {
              server.emit('listening')
            }
          })
        },
        [60080, 60083],
        new Set([60081]),
      )

      expect(ports).toEqual([60080, 60082])
      expect(server.listenerCount('error')).toBe(0)
      expect(server.listenerCount('listening')).toBe(0)
    })
  }

  test('rejects with the last EACCES when the range is exhausted', async () => {
    const server = new EventEmitter()
    const ports: number[] = []
    const error = Object.assign(new Error('permission denied'), {
      code: 'EACCES',
    })

    const result = listenInRange(
      server,
      port => {
        ports.push(port)
        queueMicrotask(() => server.emit('error', error))
      },
      [60080, 60082],
      new Set(),
    )

    expect(await result.catch((err: unknown) => err)).toBe(error)
    expect(ports).toEqual([60080, 60081, 60082])
    expect(server.listenerCount('listening')).toBe(0)
  })

  for (const code of ['EADDRINUSE', 'EACCES']) {
    test(`does not retry ${code} without a range`, async () => {
      const server = new EventEmitter()
      const ports: number[] = []
      const error = Object.assign(new Error(code), { code })

      const result = listenInRange(
        server,
        port => {
          ports.push(port)
          queueMicrotask(() => server.emit('error', error))
        },
        undefined,
        new Set(),
      )

      expect(await result.catch((err: unknown) => err)).toBe(error)
      expect(ports).toEqual([0])
    })
  }

  test('does not retry unrelated errors within a range', async () => {
    const server = new EventEmitter()
    const ports: number[] = []
    const error = Object.assign(new Error('address unavailable'), {
      code: 'EADDRNOTAVAIL',
    })

    const result = listenInRange(
      server,
      port => {
        ports.push(port)
        queueMicrotask(() => server.emit('error', error))
      },
      [60080, 60089],
      new Set(),
    )

    expect(await result.catch((err: unknown) => err)).toBe(error)
    expect(ports).toEqual([60080])
  })
})
