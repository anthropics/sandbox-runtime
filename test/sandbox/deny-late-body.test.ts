import { afterEach, expect, test } from 'bun:test'
// Every case here runs a proxy configured to terminate TLS, so each is
// skipped where this runtime cannot terminate it in-process.
import { describeWithTls as describe } from '../helpers/emitted-connections.js'
import { connect, type AddressInfo } from 'node:net'
import { connect as tlsConnect } from 'node:tls'
import { createHttpProxyServer } from '../../src/sandbox/http-proxy.js'
import { createMitmCA, generateCa } from '../../src/sandbox/mitm-ca.js'

const cleanup: Array<() => void> = []
afterEach(() => {
  while (cleanup.length) cleanup.pop()!()
})

describe('a body that keeps arriving after a deny', () => {
  // The deny cancels the stream filterRequest's Request reads the body
  // from; the rest of the upload must not be fed into it.
  test('the client gets the whole 403, and the proxy no error', async () => {
    const ca = generateCa()
    const proxy = createHttpProxyServer({
      filter: () => true,
      mitmCA: createMitmCA({ caCertPem: ca.certPem, caKeyPem: ca.keyPem }),
      filterRequest: async () => ({
        action: 'deny',
        reason: 'denied for the test',
      }),
    })
    await new Promise<void>(r => proxy.listen(0, '127.0.0.1', r))
    cleanup.push(() => proxy.close())
    const port = (proxy.address() as AddressInfo).port
    const raw = await new Promise<string>(resolve => {
      const c = connect(port, '127.0.0.1', () =>
        c.write('CONNECT 127.0.0.1:9 HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n'),
      )
      c.on('error', () => resolve(''))
      c.once('data', () => {
        const t = tlsConnect({
          socket: c,
          ca: ca.certPem,
          checkServerIdentity: () => undefined,
        })
        let out = ''
        t.on('secureConnect', () => {
          t.write(
            'POST /x HTTP/1.1\r\nHost: 127.0.0.1:9\r\nContent-Length: 200000\r\n\r\n' +
              'a'.repeat(1000),
          )
          // The rest of the body, after the deny is out.
          for (let i = 1; i <= 20; i++) {
            setTimeout(() => {
              if (!t.destroyed) t.write('b'.repeat(9950))
            }, i * 10)
          }
        })
        t.on('data', (d: Buffer) => (out += d))
        t.on('close', () => resolve(out))
        t.on('error', () => resolve(out))
      })
    })
    expect(raw).toStartWith('HTTP/1.1 403')
    expect(raw).toContain('denied for the test')
  })
})
