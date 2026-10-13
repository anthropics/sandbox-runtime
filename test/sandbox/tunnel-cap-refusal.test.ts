import { afterEach, expect } from 'bun:test'
import { connect, type AddressInfo, type Socket } from 'node:net'
import { createHttpProxyServer } from '../../src/sandbox/http-proxy.js'
import { createMitmCA, generateCa } from '../../src/sandbox/mitm-ca.js'
import { withCapturedWarnings } from '../helpers/captured-warnings.js'
import { testWithTls as test } from '../helpers/emitted-connections.js'

// Of the 503 at the tunnel cap a client shows the status at most. That the
// limit is the sandbox's own is logged and passed on as a refusal is, once
// per command and burst of refusals.

const TOKEN = 'sekrit'
const cleanup: Array<() => void | Promise<void>> = []
afterEach(async () => {
  while (cleanup.length) await cleanup.pop()!()
})

type Denial = {
  method: string
  url: string
  reason: string
  encodedCommand?: string
}

async function proxyWithSlots(maxTerminatedTunnels: number) {
  const ca = generateCa()
  const denials: Denial[] = []
  const proxy = createHttpProxyServer({
    filter: () => true,
    mitmCA: createMitmCA({ caCertPem: ca.certPem, caKeyPem: ca.keyPem }),
    maxTerminatedTunnels,
    proxyAuthToken: TOKEN,
    onFilterRequestDenied: info => denials.push(info),
  })
  await new Promise<void>(r => proxy.listen(0, '127.0.0.1', r))
  cleanup.push(() => new Promise<void>(r => proxy.close(() => r())))
  const port = (proxy.address() as AddressInfo).port

  /** CONNECT as `command` (none: the bare user name); the status and the socket. */
  const open = (command?: string): Promise<{ status: number; sock: Socket }> =>
    new Promise(resolve => {
      const user = command === undefined ? 'srt' : `srt.${command}`
      const basic = Buffer.from(`${user}:${TOKEN}`).toString('base64')
      const sock = connect(port, '127.0.0.1', () =>
        sock.write(
          'CONNECT a.test:443 HTTP/1.1\r\nHost: a.test:443\r\n' +
            `Proxy-Authorization: Basic ${basic}\r\n\r\n`,
        ),
      )
      sock.on('error', () => {})
      cleanup.push(() => void sock.destroy())
      sock.once('data', (d: Buffer) =>
        resolve({ status: Number(d.toString('latin1').split(' ')[1]), sock }),
      )
    })
  const held: Socket[] = []
  return {
    denials,
    /** Take slots until none is free. */
    async fill() {
      while (held.length < maxTerminatedTunnels) {
        const { status, sock } = await open('holder')
        expect(status).toBe(200)
        held.push(sock)
      }
    },
    async free(slots: number) {
      for (const sock of held.splice(0, slots)) sock.destroy()
      await new Promise(r => setTimeout(r, 100))
    },
    /** A CONNECT at the cap; who has been told of the cap so far. */
    async refused(command?: string) {
      expect((await open(command)).status).toBe(503)
      return denials.map(d => d.encodedCommand)
    },
  }
}

test('the first refusal of each command is logged and passed on, naming the limit and its option', async () => {
  const p = await proxyWithSlots(2)
  await p.fill()
  const { warnings } = await withCapturedWarnings(async () => {
    expect(await p.refused('A')).toEqual(['A'])
    expect(await p.refused('A')).toEqual(['A'])
    expect(await p.refused('B')).toEqual(['A', 'B'])
    expect(await p.refused()).toEqual(['A', 'B', undefined])
    expect(await p.refused('B')).toEqual(['A', 'B', undefined])
  })
  const reason =
    "the sandbox's limit of 2 TLS-terminated tunnels at once is reached; " +
    "the limit is network.tlsTerminate.maxTunnels in the sandbox's configuration"
  expect(p.denials[0]).toEqual({
    method: 'CONNECT',
    url: 'a.test:443',
    reason,
    encodedCommand: 'A',
  })
  expect(warnings).toEqual(
    Array<string>(3).fill(
      `[SandboxDebug] [proxy] CONNECT a.test:443 refused: ${reason}`,
    ),
  )
})

test('a burst ends once half the slots are free again, not before', async () => {
  const p = await proxyWithSlots(4)
  await p.fill()
  expect(await p.refused('A')).toEqual(['A'])
  await p.free(1)
  await p.fill()
  expect(await p.refused('A')).toEqual(['A'])
  await p.free(2)
  await p.fill()
  expect(await p.refused('A')).toEqual(['A', 'A'])
})

test('the names kept are bounded: past a hundred they are forgotten', async () => {
  const p = await proxyWithSlots(1)
  await p.fill()
  for (let i = 0; i < 100; i++) await p.refused(`c${i}`)
  expect(await p.refused('c0')).toHaveLength(100)
  expect(await p.refused('one-more')).toHaveLength(101)
  expect(await p.refused('c0')).toHaveLength(102)
})
