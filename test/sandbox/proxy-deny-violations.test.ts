import { connect } from 'node:net'
import { once } from 'node:events'
import { afterEach, describe, expect, it } from 'bun:test'
import type { Server } from 'node:http'
import { createHttpProxyServer } from '../../src/sandbox/http-proxy.js'
import {
  encodeSandboxedCommand,
  encodedCommandFromProxyUser,
  generateProxyEnvVars,
  proxyUsernameFor,
} from '../../src/sandbox/sandbox-utils.js'

describe('proxyUsernameFor / encodedCommandFromProxyUser', () => {
  it('bare "srt" when there is no encodedCommand', () => {
    expect(proxyUsernameFor(undefined)).toBe('srt')
    expect(proxyUsernameFor('')).toBe('srt')
  })

  it('appends the encodedCommand as a suffix', () => {
    expect(proxyUsernameFor('Zm9v')).toBe('srt.Zm9v')
  })

  it('falls back to bare "srt" when the username would exceed the RFC 1929 255-byte limit', () => {
    // 100 CJK code units → 300 UTF-8 bytes → 400 base64 chars.
    const enc = encodeSandboxedCommand('漢'.repeat(100))
    expect(Buffer.byteLength(`srt.${enc}`)).toBeGreaterThan(255)
    expect(proxyUsernameFor(enc)).toBe('srt')
  })

  it('returns undefined for bare "srt" and unrecognized usernames', () => {
    expect(encodedCommandFromProxyUser('srt')).toBeUndefined()
    expect(encodedCommandFromProxyUser('srt.')).toBeUndefined()
    expect(encodedCommandFromProxyUser('alice')).toBeUndefined()
    expect(encodedCommandFromProxyUser('')).toBeUndefined()
    expect(encodedCommandFromProxyUser(undefined)).toBeUndefined()
  })

  it('round-trips encodeSandboxedCommand for commands containing +/= b64 chars', () => {
    const cmd = 'curl https://example.com/?q=a+b'
    const enc = encodeSandboxedCommand(cmd)
    expect(enc).toMatch(/[+/=]/)
    expect(encodedCommandFromProxyUser(proxyUsernameFor(enc))).toBe(enc)
  })
})

describe('generateProxyEnvVars encodedCommand', () => {
  const TOKEN = 'tok123'

  it('embeds the percent-encoded encodedCommand in HTTP/SOCKS proxy URLs', () => {
    const enc = encodeSandboxedCommand('curl https://example.com/')
    const env = generateProxyEnvVars(3128, 1080, undefined, TOKEN, false, enc)

    const expectedUser = `srt.${encodeURIComponent(enc)}`
    expect(env).toContain(
      `HTTP_PROXY=http://${expectedUser}:${TOKEN}@localhost:3128`,
    )
    expect(env).toContain(
      `FTP_PROXY=socks5h://${expectedUser}:${TOKEN}@localhost:1080`,
    )
  })

  it('round-trips through URL userinfo parsing', () => {
    // This is the critical encoding gotcha: clients URL-decode the userinfo
    // before building the Basic header / RFC 1929 frame, so the proxy must
    // see the raw base64 — including +/= — and recover the same encodedCommand
    // that getViolationsForCommand() will key on.
    const cmd = 'curl https://example.com/?q=a+b'
    const enc = encodeSandboxedCommand(cmd)
    const env = generateProxyEnvVars(3128, 1080, undefined, TOKEN, false, enc)

    const httpProxy = env
      .find(e => e.startsWith('HTTP_PROXY='))!
      .slice('HTTP_PROXY='.length)
    const url = new URL(httpProxy)
    // URL.username is still pct-encoded; clients decode before sending Basic.
    const decodedUser = decodeURIComponent(url.username)
    expect(encodedCommandFromProxyUser(decodedUser)).toBe(enc)
  })

  it('still uses bare "srt" when no encodedCommand is supplied', () => {
    const env = generateProxyEnvVars(3128, 1080, undefined, TOKEN)
    expect(env).toContain(`HTTP_PROXY=http://srt:${TOKEN}@localhost:3128`)
  })
})

describe('HTTP proxy threads encodedCommand from Basic auth to filter()', () => {
  let proxy: Server | undefined

  afterEach(() => {
    proxy?.close()
    proxy = undefined
  })

  async function sendConnect(
    proxyPort: number,
    user: string,
    token: string,
    target: string,
  ): Promise<string> {
    const sock = connect(proxyPort, '127.0.0.1')
    await once(sock, 'connect')
    const basic = Buffer.from(`${user}:${token}`).toString('base64')
    sock.write(
      `CONNECT ${target} HTTP/1.1\r\n` +
        `Host: ${target}\r\n` +
        `Proxy-Authorization: Basic ${basic}\r\n\r\n`,
    )
    const chunks: Buffer[] = []
    sock.on('data', d => chunks.push(d))
    await once(sock, 'close')
    return Buffer.concat(chunks).toString('utf8')
  }

  it('passes the encodedCommand suffix to filter() and 403s on deny', async () => {
    const TOKEN = 'sekrit'
    const seen: Array<string | undefined> = []
    proxy = createHttpProxyServer({
      filter: (_port, _host, _socket, encodedCommand) => {
        seen.push(encodedCommand)
        return false
      },
      proxyAuthToken: TOKEN,
    })
    proxy.listen(0, '127.0.0.1')
    await once(proxy, 'listening')
    const port = (proxy.address() as { port: number }).port

    const enc = encodeSandboxedCommand('curl https://blocked.test/')
    const resp = await sendConnect(
      port,
      `srt.${enc}`,
      TOKEN,
      'blocked.test:443',
    )

    expect(resp).toContain('HTTP/1.1 403')
    expect(seen).toEqual([enc])
  })

  it('still authenticates and passes undefined for bare "srt"', async () => {
    const TOKEN = 'sekrit'
    const seen: Array<string | undefined> = []
    proxy = createHttpProxyServer({
      filter: (_port, _host, _socket, encodedCommand) => {
        seen.push(encodedCommand)
        return false
      },
      proxyAuthToken: TOKEN,
    })
    proxy.listen(0, '127.0.0.1')
    await once(proxy, 'listening')
    const port = (proxy.address() as { port: number }).port

    const resp = await sendConnect(port, 'srt', TOKEN, 'blocked.test:443')

    expect(resp).toContain('HTTP/1.1 403')
    expect(seen).toEqual([undefined])
  })

  it('407s on wrong token regardless of username', async () => {
    const seen: unknown[] = []
    proxy = createHttpProxyServer({
      filter: (_port, _host, _socket, ec) => {
        seen.push(ec)
        return true
      },
      proxyAuthToken: 'right',
    })
    proxy.listen(0, '127.0.0.1')
    await once(proxy, 'listening')
    const port = (proxy.address() as { port: number }).port

    const resp = await sendConnect(port, 'srt.Zm9v', 'wrong', 'x.test:443')

    expect(resp).toContain('HTTP/1.1 407')
    expect(seen).toEqual([])
  })

  it('threads encodedCommand to onFilterRequestDenied on plain-HTTP filterRequest deny', async () => {
    const TOKEN = 'sekrit'
    type Denied = {
      method: string
      url: string
      reason: string
      encodedCommand?: string
    }
    const denied: Denied[] = []
    proxy = createHttpProxyServer({
      filter: () => true,
      filterRequest: async () => ({ action: 'deny', reason: 'policy says no' }),
      onFilterRequestDenied: info => denied.push(info),
      proxyAuthToken: TOKEN,
    })
    proxy.listen(0, '127.0.0.1')
    await once(proxy, 'listening')
    const port = (proxy.address() as { port: number }).port

    const enc = encodeSandboxedCommand('curl http://blocked.test/x')
    const sock = connect(port, '127.0.0.1')
    await once(sock, 'connect')
    const basic = Buffer.from(`srt.${enc}:${TOKEN}`).toString('base64')
    sock.write(
      `GET http://blocked.test/x HTTP/1.1\r\n` +
        `Host: blocked.test\r\n` +
        `Proxy-Authorization: Basic ${basic}\r\n` +
        `Connection: close\r\n\r\n`,
    )
    const chunks: Buffer[] = []
    sock.on('data', d => chunks.push(d))
    await once(sock, 'close')
    const resp = Buffer.concat(chunks).toString('utf8')

    expect(resp).toContain('HTTP/1.1 403')
    expect(denied).toEqual([
      {
        method: 'GET',
        url: 'http://blocked.test/x',
        reason: 'policy says no',
        encodedCommand: enc,
      },
    ])
  })

  it('uses the default policy reason when filterRequest denies without one', async () => {
    const TOKEN = 'sekrit'
    const reasons: string[] = []
    proxy = createHttpProxyServer({
      filter: () => true,
      filterRequest: async () => ({ action: 'deny' }),
      onFilterRequestDenied: info => reasons.push(info.reason),
      proxyAuthToken: TOKEN,
    })
    proxy.listen(0, '127.0.0.1')
    await once(proxy, 'listening')
    const port = (proxy.address() as { port: number }).port

    const sock = connect(port, '127.0.0.1')
    await once(sock, 'connect')
    const basic = Buffer.from(`srt:${TOKEN}`).toString('base64')
    sock.write(
      `GET http://blocked.test/y HTTP/1.1\r\n` +
        `Host: blocked.test\r\n` +
        `Proxy-Authorization: Basic ${basic}\r\n` +
        `Connection: close\r\n\r\n`,
    )
    await once(sock, 'close')

    expect(reasons).toEqual(['denied by sandbox policy'])
  })
})
