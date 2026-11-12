import { afterEach, describe, expect, test } from 'bun:test'
import { connect, createServer, type AddressInfo, type Socket } from 'node:net'
import { connect as tlsConnect } from 'node:tls'
import { createHttpProxyServer } from '../../src/sandbox/http-proxy.js'
import { createMitmCA, generateCa } from '../../src/sandbox/mitm-ca.js'
import { MAX_BODY_SUBSTITUTION_BUFFER_BYTES } from '../../src/sandbox/body-substitution.js'
import { SERVES_EMITTED_CONNECTIONS } from '../helpers/emitted-connections.js'

const cleanup: Array<() => void> = []
afterEach(() => {
  while (cleanup.length) cleanup.pop()!()
})

const pairs = () => [
  { sentinel: Buffer.from('fake_value_test'), realValue: Buffer.from('x') },
]

describe('substitution overflow terminates an unfinished upload', () => {
  for (const tls of [false, true]) {
    for (const filtered of [false, true]) {
      test.skipIf(tls && !SERVES_EMITTED_CONNECTIONS)(
        `${tls ? 'TLS' : 'HTTP'}, ${filtered ? 'teed' : 'direct'} body`,
        async () => {
          let upstreamConnections = 0
          const upstream = createServer(socket => {
            upstreamConnections++
            socket.destroy()
          })
          cleanup.push(() => upstream.close())
          await new Promise<void>(resolve =>
            upstream.listen(0, '127.0.0.1', resolve),
          )
          const target = `127.0.0.1:${(upstream.address() as AddressInfo).port}`
          const ca = tls ? generateCa() : undefined
          const proxy = createHttpProxyServer({
            filter: () => true,
            ...(ca
              ? {
                  mitmCA: createMitmCA({
                    caCertPem: ca.certPem,
                    caKeyPem: ca.keyPem,
                  }),
                }
              : {}),
            filterRequest: filtered
              ? async () => ({ action: 'allow' as const })
              : undefined,
            getBodySubstitutions: pairs,
            getBodySubstitutionsPlaintext: pairs,
            maxSigv4ResignBodyBytes: 128,
          })
          cleanup.push(() => proxy.close())
          await new Promise<void>(resolve =>
            proxy.listen(0, '127.0.0.1', resolve),
          )
          const port = (proxy.address() as AddressInfo).port
          const result = await new Promise<{
            response: string
            closed: boolean
          }>((resolve, reject) => {
            const raw = connect(port, '127.0.0.1')
            cleanup.push(() => raw.destroy())
            let client: Socket = raw
            let response = ''
            const timer = setTimeout(() => {
              client.destroy()
              reject(
                new Error(
                  `upload did not close after denial: ${response.slice(0, 200)}`,
                ),
              )
            }, 10_000)
            const start = (socket: Socket) => {
              client = socket
              cleanup.push(() => socket.destroy())
              socket.on('data', data => (response += data.toString()))
              socket.on('error', () => {})
              socket.on('close', () => {
                clearTimeout(timer)
                resolve({ response, closed: true })
              })
              socket.write(
                `POST ${tls ? '/upload' : `http://${target}/upload`} HTTP/1.1\r\nHost: ${target}\r\nContent-Length: 1073741824\r\n\r\n`,
              )
              // Send past the cap, but deliberately never finish the declared upload.
              const chunk = Buffer.alloc(64 * 1024, 0x61)
              const toSend = tls
                ? 1024
                : MAX_BODY_SUBSTITUTION_BUFFER_BYTES + chunk.length * 2
              let sent = 0
              const pump = () => {
                while (!socket.destroyed && sent < toSend) {
                  sent += chunk.length
                  if (!socket.write(chunk)) {
                    socket.once('drain', pump)
                    return
                  }
                }
              }
              pump()
            }
            raw.on('error', () => {})
            raw.on('connect', () => {
              if (!tls) {
                start(raw)
                return
              }
              raw.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`)
              raw.once('data', () => {
                const secure = tlsConnect({
                  socket: raw,
                  ca: ca!.certPem,
                  checkServerIdentity: () => undefined,
                })
                secure.once('secureConnect', () => start(secure))
                secure.on('error', reject)
              })
            })
          })
          expect(result.closed).toBe(true)
          expect(result.response).toStartWith('HTTP/1.1 403')
          expect(result.response).toContain('byte buffering limit; denied.')
          expect(upstreamConnections).toBe(0)
        },
        20_000,
      )
    }
  }
})
