import { afterEach, describe, expect, test } from 'bun:test'
import { connect, createServer, type AddressInfo, type Socket } from 'node:net'
import { closeAfterFlush } from '../../src/sandbox/tls-terminate-proxy.js'

const cleanup: Array<() => void> = []
afterEach(() => {
  while (cleanup.length) cleanup.pop()!()
})

describe('closeAfterFlush', () => {
  test('a slow client that sends bytes nobody reads still gets every byte, then a FIN', async () => {
    const size = 32 << 20
    let closedBy: (how: string) => void = () => {}
    const how = new Promise<string>(r => (closedBy = r))
    const server = createServer((s: Socket) => {
      s.on('error', () => {})
      // Nothing reads what the client sends, as a relay whose far end has
      // closed does not.
      s.pause()
      const chunk = Buffer.alloc(64 << 10, 0x61)
      let sent = 0
      const pump = (): void => {
        while (sent < size) {
          sent += chunk.length
          if (!s.write(chunk)) {
            s.once('drain', pump)
            return
          }
        }
        closeAfterFlush(s, closedBy)
      }
      pump()
    })
    cleanup.push(() => server.close())
    await new Promise<void>(r => server.listen(0, '127.0.0.1', r))
    const read = await new Promise<number>(resolve => {
      const c = connect((server.address() as AddressInfo).port, '127.0.0.1')
      let n = 0
      let poked = false
      c.on('data', d => {
        n += d.length
        // Once the server is done writing, bytes it will never read, more
        // than the runtime reads ahead into a paused socket.
        if (!poked && n > size / 2) {
          poked = true
          c.write(Buffer.alloc(4 << 20, 0x62))
        }
        c.pause()
        setTimeout(() => c.resume(), 1)
      })
      c.on('error', () => {})
      c.on('close', () => resolve(n))
    })
    expect(read).toBe(size)
    expect(await how).toBe('the client ending after the flush')
  }, 60_000)
})
