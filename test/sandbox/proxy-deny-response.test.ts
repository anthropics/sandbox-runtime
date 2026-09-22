import { connect, type Socket } from 'node:net'
import { once } from 'node:events'
import { afterEach, beforeEach, describe, expect, it } from 'bun:test'
import type { Server } from 'node:http'
import {
  createHttpProxyServer,
  type HttpProxyServerOptions,
} from '../../src/sandbox/http-proxy.js'
import { SandboxManager } from '../../src/index.js'

const TOKEN = 'sekrit'

function basicAuth(token: string): string {
  const b64 = Buffer.from(`srt:${token}`).toString('base64')
  return `Proxy-Authorization: Basic ${b64}\r\n`
}

/**
 * Everything the proxy wrote back, read to close. The deny response's body
 * is the part the sandboxed client prints, so the status line alone is not
 * enough to assert on here.
 */
async function readToClose(sock: Socket): Promise<string> {
  const chunks: Buffer[] = []
  sock.on('data', d => chunks.push(d))
  await once(sock, 'close')
  return Buffer.concat(chunks).toString('utf8')
}

async function sendConnect(
  proxyPort: number,
  target: string,
  token = TOKEN,
): Promise<string> {
  const sock = connect(proxyPort, '127.0.0.1')
  await once(sock, 'connect')
  sock.write(
    `CONNECT ${target} HTTP/1.1\r\n` +
      `Host: ${target}\r\n` +
      basicAuth(token) +
      '\r\n',
  )
  return readToClose(sock)
}

async function sendGet(
  proxyPort: number,
  url: string,
  token = TOKEN,
): Promise<string> {
  const sock = connect(proxyPort, '127.0.0.1')
  await once(sock, 'connect')
  sock.write(
    `GET ${url} HTTP/1.1\r\n` +
      `Host: ${new URL(url).host}\r\n` +
      basicAuth(token) +
      'Connection: close\r\n\r\n',
  )
  return readToClose(sock)
}

describe('host-allowlist deny response carries the filter reason', () => {
  let proxy: Server | undefined

  afterEach(() => {
    proxy?.close()
    proxy = undefined
  })

  async function startProxy(
    filter: HttpProxyServerOptions['filter'],
  ): Promise<number> {
    proxy = createHttpProxyServer({ filter, proxyAuthToken: TOKEN })
    proxy.listen(0, '127.0.0.1')
    await once(proxy, 'listening')
    return (proxy.address() as { port: number }).port
  }

  const REASON =
    'blocked by sandbox policy; do not retry with another DNS server, proxy or VPN'

  it('CONNECT: the reason is the 403 body, under the allowlist tag', async () => {
    const port = await startProxy(() => ({ allow: false, reason: REASON }))
    const resp = await sendConnect(port, 'blocked.test:443')

    expect(resp).toContain('HTTP/1.1 403 Forbidden')
    expect(resp).toContain('X-Proxy-Error: blocked-by-allowlist')
    expect(resp.endsWith(REASON)).toBe(true)
  })

  it('plain HTTP: the reason is the 403 body, under the allowlist tag', async () => {
    const port = await startProxy(() => ({ allow: false, reason: REASON }))
    const resp = await sendGet(port, 'http://blocked.test/x')

    expect(resp).toContain('HTTP/1.1 403 Forbidden')
    expect(resp).toContain('X-Proxy-Error: blocked-by-allowlist')
    expect(resp.endsWith(`${REASON}\n`)).toBe(true)
  })

  it('a bare false still gets the generic allowlist text', async () => {
    const port = await startProxy(() => false)

    const connectResp = await sendConnect(port, 'blocked.test:443')
    expect(connectResp).toContain('HTTP/1.1 403 Forbidden')
    expect(connectResp).toContain('Connection blocked by network allowlist')

    const getResp = await sendGet(port, 'http://blocked.test/x')
    expect(getResp).toContain('HTTP/1.1 403 Forbidden')
    expect(getResp).toContain('Connection blocked by network allowlist')
  })

  it('an object verdict is a deny, and an empty reason falls back', async () => {
    // Only `true` allows: a `{ allow: false }` object is truthy, so a
    // truthiness test on the verdict would tunnel the connection instead.
    const port = await startProxy(() => ({ allow: false, reason: '' }))

    const resp = await sendConnect(port, 'blocked.test:443')
    expect(resp).toContain('HTTP/1.1 403 Forbidden')
    expect(resp).toContain('Connection blocked by network allowlist')
  })
})

describe('the sandboxed client reads which policy denied it', () => {
  beforeEach(async () => {
    await SandboxManager.reset()
  })
  afterEach(async () => {
    await SandboxManager.reset()
  })

  it("delivers a deniedDomains entry's reason in-band, not just in the violation line", async () => {
    const reason = 'SSH pushes to GitHub are blocked; use an https:// remote'
    await SandboxManager.initialize({
      network: {
        allowedDomains: ['example.com'],
        deniedDomains: ['github.com'],
        deniedDomainReasons: { 'github.com': reason },
      },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    })
    const port = SandboxManager.getProxyPort()!
    const resp = await sendConnect(
      port,
      'github.com:443',
      SandboxManager.getProxyAuthToken()!,
    )

    expect(resp).toContain('HTTP/1.1 403 Forbidden')
    expect(resp).toContain(reason)
  })

  it('names the allow list when nothing matched the host', async () => {
    await SandboxManager.initialize({
      network: { allowedDomains: ['example.com'], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    })
    const port = SandboxManager.getProxyPort()!
    const resp = await sendConnect(
      port,
      'off.test:443',
      SandboxManager.getProxyAuthToken()!,
    )

    expect(resp).toContain('HTTP/1.1 403 Forbidden')
    expect(resp).toContain('host is not on the allow list')
  })

  it('uses network.allowlistDenyReason for an off-allowlist host, in both channels', async () => {
    const reason =
      'blocked by sandbox policy; do not retry with --no-proxy, another DNS server or a VPN'
    await SandboxManager.initialize({
      network: {
        allowedDomains: ['example.com'],
        deniedDomains: [],
        allowlistDenyReason: reason,
      },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    })
    const port = SandboxManager.getProxyPort()!
    const store = SandboxManager.getSandboxViolationStore()
    store.clear()

    const resp = await sendConnect(
      port,
      'off.test:443',
      SandboxManager.getProxyAuthToken()!,
    )

    expect(resp).toContain('HTTP/1.1 403 Forbidden')
    expect(resp).toContain(reason)
    expect(store.getViolations().map(v => v.line)).toContain(
      `deny network-outbound off.test:443 (${reason})`,
    )
  })
})
