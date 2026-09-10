import { describe, test, expect, beforeEach, afterEach } from 'bun:test'
import { connect } from 'node:net'
import {
  canonicalizeHost,
  isValidHost,
  openConnectTunnel,
  redactUrl,
  resolveParentProxy,
  selectParentProxyUrl,
  shouldBypassParentProxy,
  stripBrackets,
  stripHopByHop,
} from '../../src/sandbox/parent-proxy.js'

describe('parent-proxy: resolveParentProxy', () => {
  const saved: Record<string, string | undefined> = {}
  const vars = [
    'HTTP_PROXY',
    'http_proxy',
    'HTTPS_PROXY',
    'https_proxy',
    'NO_PROXY',
    'no_proxy',
  ]

  beforeEach(() => {
    for (const v of vars) {
      saved[v] = process.env[v]
      delete process.env[v]
    }
  })
  afterEach(() => {
    for (const v of vars) {
      if (saved[v] === undefined) delete process.env[v]
      else process.env[v] = saved[v]
    }
  })

  test('returns undefined when nothing is set', () => {
    expect(resolveParentProxy(undefined)).toBeUndefined()
  })

  test('explicit config takes precedence over env', () => {
    process.env.HTTP_PROXY = 'http://env-proxy:8080'
    const r = resolveParentProxy({ http: 'http://cfg-proxy:3128' })
    expect(r?.httpUrl?.href).toBe('http://cfg-proxy:3128/')
  })

  test('falls back to HTTP_PROXY env', () => {
    process.env.HTTP_PROXY = 'http://env-proxy:8080'
    const r = resolveParentProxy(undefined)
    expect(r?.httpUrl?.hostname).toBe('env-proxy')
    // HTTPS falls back to HTTP when HTTPS_PROXY unset
    expect(r?.httpsUrl?.hostname).toBe('env-proxy')
  })

  test('lowercase env vars are honoured', () => {
    process.env.http_proxy = 'http://lower:8080'
    const r = resolveParentProxy(undefined)
    expect(r?.httpUrl?.hostname).toBe('lower')
  })

  test('HTTPS_PROXY distinct from HTTP_PROXY', () => {
    process.env.HTTP_PROXY = 'http://plain:8080'
    process.env.HTTPS_PROXY = 'http://secure:8443'
    const r = resolveParentProxy(undefined)
    expect(r?.httpUrl?.hostname).toBe('plain')
    expect(r?.httpsUrl?.hostname).toBe('secure')
  })
})

describe('parent-proxy: NO_PROXY matching', () => {
  const mk = (noProxy: string) =>
    resolveParentProxy({ http: 'http://p:1', noProxy })!

  test('exact hostname match', () => {
    const r = mk('example.com')
    expect(shouldBypassParentProxy(r, 'example.com')).toBe(true)
    expect(shouldBypassParentProxy(r, 'other.com')).toBe(false)
  })

  test('bare hostname also matches subdomains (golang semantics)', () => {
    const r = mk('example.com')
    expect(shouldBypassParentProxy(r, 'api.example.com')).toBe(true)
  })

  test('leading-dot suffix match', () => {
    const r = mk('.example.com')
    expect(shouldBypassParentProxy(r, 'api.example.com')).toBe(true)
    expect(shouldBypassParentProxy(r, 'example.com')).toBe(true)
    expect(shouldBypassParentProxy(r, 'notexample.com')).toBe(false)
  })

  test('wildcard *. prefix is normalised to leading-dot', () => {
    const r = mk('*.local')
    expect(shouldBypassParentProxy(r, 'foo.local')).toBe(true)
  })

  test('wildcard * matches everything', () => {
    const r = mk('*')
    expect(shouldBypassParentProxy(r, 'anything.com')).toBe(true)
  })

  test('CIDR v4 match', () => {
    const r = mk('10.0.0.0/8,192.168.0.0/16')
    expect(shouldBypassParentProxy(r, '10.1.2.3')).toBe(true)
    expect(shouldBypassParentProxy(r, '192.168.99.1')).toBe(true)
    expect(shouldBypassParentProxy(r, '172.16.0.1')).toBe(false)
    expect(shouldBypassParentProxy(r, '11.0.0.1')).toBe(false)
  })

  test('CIDR v4 /32 exact', () => {
    const r = mk('1.2.3.4/32')
    expect(shouldBypassParentProxy(r, '1.2.3.4')).toBe(true)
    expect(shouldBypassParentProxy(r, '1.2.3.5')).toBe(false)
  })

  test('CIDR v6 match', () => {
    const r = mk('fe80::/10')
    expect(shouldBypassParentProxy(r, 'fe80::1')).toBe(true)
    expect(shouldBypassParentProxy(r, '2001:db8::1')).toBe(false)
  })

  test('link-local CIDR', () => {
    const r = mk('169.254.0.0/16')
    expect(shouldBypassParentProxy(r, '169.254.169.254')).toBe(true)
  })

  test('localhost always bypasses regardless of NO_PROXY', () => {
    const r = mk('')
    expect(shouldBypassParentProxy(r, 'localhost')).toBe(true)
    expect(shouldBypassParentProxy(r, '127.0.0.1')).toBe(true)
    expect(shouldBypassParentProxy(r, '::1')).toBe(true)
  })

  test('full 127/8 and v4-mapped loopback bypass', () => {
    const r = mk('')
    expect(shouldBypassParentProxy(r, '127.0.0.2')).toBe(true)
    expect(shouldBypassParentProxy(r, '127.255.255.254')).toBe(true)
    expect(shouldBypassParentProxy(r, '::ffff:127.0.0.1')).toBe(true)
  })

  test('bracketed IPv6 host is handled', () => {
    const r = mk('')
    expect(shouldBypassParentProxy(r, '[::1]')).toBe(true)
  })

  test('case-insensitive hostname matching', () => {
    const r = mk('Example.COM')
    expect(shouldBypassParentProxy(r, 'EXAMPLE.com')).toBe(true)
  })

  test('port suffix in NO_PROXY entry is stripped', () => {
    const r = mk('example.com:8080')
    expect(shouldBypassParentProxy(r, 'example.com')).toBe(true)
  })

  test('IPv6 literal in NO_PROXY is not mangled by port-stripping', () => {
    const r = mk('fe80::1')
    expect(shouldBypassParentProxy(r, 'fe80::1')).toBe(true)
  })

  test('a zoned IPv6 entry is its unzoned range and never throws', () => {
    const r = mk('fe80::1%eth0,fe80::%eth1/10,10.0.0.0/8')
    expect(shouldBypassParentProxy(r, 'fe80::1')).toBe(true)
    expect(shouldBypassParentProxy(r, 'fe80::2')).toBe(true)
    expect(shouldBypassParentProxy(r, '10.1.1.1')).toBe(true)
    expect(shouldBypassParentProxy(r, '8.8.8.8')).toBe(false)
  })

  test('an IPv4-mapped entry matches exactly its IPv4 address, not every IPv4 host', () => {
    const r = mk('::ffff:10.0.0.1,::ffff:192.168.0.0/112')
    expect(shouldBypassParentProxy(r, '10.0.0.1')).toBe(true)
    expect(shouldBypassParentProxy(r, '192.168.4.4')).toBe(true)
    expect(shouldBypassParentProxy(r, '10.0.0.2')).toBe(false)
    expect(shouldBypassParentProxy(r, '8.8.8.8')).toBe(false)
  })

  test('empty CIDR suffix does not become match-all', () => {
    const r = mk('10.0.0.0/')
    // Malformed — should be ignored, not treated as /0
    expect(shouldBypassParentProxy(r, '8.8.8.8')).toBe(false)
  })

  test('malformed CIDR is ignored', () => {
    const r = mk('10.0.0.0/999,not-an-ip/24')
    expect(shouldBypassParentProxy(r, '10.0.0.1')).toBe(false)
  })

  test('comma-separated list with whitespace', () => {
    const r = mk(' foo.com , bar.com ,  10.0.0.0/8 ')
    expect(shouldBypassParentProxy(r, 'foo.com')).toBe(true)
    expect(shouldBypassParentProxy(r, 'bar.com')).toBe(true)
    expect(shouldBypassParentProxy(r, '10.1.1.1')).toBe(true)
    expect(shouldBypassParentProxy(r, 'baz.com')).toBe(false)
  })
})

describe('parent-proxy: selectParentProxyUrl', () => {
  test('picks https proxy for https, http for http', () => {
    const r = resolveParentProxy({
      http: 'http://plain:1',
      https: 'http://secure:2',
    })!
    expect(selectParentProxyUrl(r, { isHttps: true })?.hostname).toBe('secure')
    expect(selectParentProxyUrl(r, { isHttps: false })?.hostname).toBe('plain')
  })

  test('falls back when only one is set', () => {
    const r = resolveParentProxy({ http: 'http://only:1' })!
    expect(selectParentProxyUrl(r, { isHttps: true })?.hostname).toBe('only')
  })
})

describe('parent-proxy: openConnectTunnel validation', () => {
  const rejectMsg = (p: Promise<unknown>) =>
    p.then(
      () => 'resolved',
      (e: Error) => e.message,
    )

  test('rejects CRLF in destHost', async () => {
    const msg = await rejectMsg(
      openConnectTunnel({
        dial: () => connect(1, '127.0.0.1'),
        readyEvent: 'connect',
        destHost: 'evil\r\nX-Injected: yes',
        destPort: 443,
      }),
    )
    expect(msg).toMatch(/Invalid destination host/)
  })

  test('rejects request-smuggling payload in destHost', async () => {
    const msg = await rejectMsg(
      openConnectTunnel({
        dial: () => connect(1, '127.0.0.1'),
        readyEvent: 'connect',
        destHost: 'a\r\n\r\nCONNECT internal:8080 HTTP/1.1\r\nX: .allowed.com',
        destPort: 443,
      }),
    )
    expect(msg).toMatch(/Invalid destination host/)
  })

  test('rejects invalid port', async () => {
    const msg = await rejectMsg(
      openConnectTunnel({
        dial: () => connect(1, '127.0.0.1'),
        readyEvent: 'connect',
        destHost: 'example.com',
        destPort: 99999,
      }),
    )
    expect(msg).toMatch(/Invalid destination port/)
  })

  test('accepts plain hostname (fails on dial, not validation)', async () => {
    const msg = await rejectMsg(
      openConnectTunnel({
        dial: () => connect(1, '127.0.0.1'),
        readyEvent: 'connect',
        destHost: 'registry.npmjs.org',
        destPort: 443,
        timeoutMs: 500,
      }),
    )
    expect(msg).not.toMatch(/Invalid destination/)
  })

  test('accepts IPv6 literal (fails on dial, not validation)', async () => {
    const msg = await rejectMsg(
      openConnectTunnel({
        dial: () => connect(1, '127.0.0.1'),
        readyEvent: 'connect',
        destHost: 'fe80::1',
        destPort: 443,
        timeoutMs: 500,
      }),
    )
    expect(msg).not.toMatch(/Invalid destination/)
  })
})

describe('parent-proxy: utilities', () => {
  test('stripBrackets removes IPv6 brackets', () => {
    expect(stripBrackets('[::1]')).toBe('::1')
    expect(stripBrackets('[fe80::1]')).toBe('fe80::1')
    expect(stripBrackets('example.com')).toBe('example.com')
    expect(stripBrackets('127.0.0.1')).toBe('127.0.0.1')
  })

  test('redactUrl hides userinfo', () => {
    expect(redactUrl(new URL('http://user:secret@proxy:3128'))).toBe(
      'http://***:***@proxy:3128/',
    )
    expect(redactUrl(new URL('http://proxy:3128'))).toBe('http://proxy:3128/')
    expect(redactUrl(undefined)).toBe('-')
  })

  test('stripHopByHop removes proxy and connection headers', () => {
    const out = stripHopByHop({
      host: 'example.com',
      'proxy-authorization': 'Basic secret',
      'proxy-connection': 'keep-alive',
      connection: 'close',
      'transfer-encoding': 'chunked',
      'x-custom': 'keep-me',
    })
    expect(out).toEqual({ host: 'example.com', 'x-custom': 'keep-me' })
  })

  test('stripHopByHop strips headers named in Connection', () => {
    const out = stripHopByHop({
      host: 'example.com',
      connection: 'x-foo, x-bar',
      'x-foo': 'drop',
      'x-bar': 'drop',
      'x-keep': 'keep',
    })
    expect(out).toEqual({ host: 'example.com', 'x-keep': 'keep' })
  })

  test('stripHopByHop preserves content-length (end-to-end header)', () => {
    const out = stripHopByHop({
      'content-length': '42',
      'transfer-encoding': 'chunked',
      'x-keep': 'keep',
    })
    expect(out).toEqual({ 'content-length': '42', 'x-keep': 'keep' })
  })

  test('isValidHost rejects null bytes (DNS-truncation bypass)', () => {
    expect(isValidHost('evil.com\x00.allowed.com')).toBe(false)
  })

  test('isValidHost rejects CRLF', () => {
    expect(isValidHost('a\r\nInjected: x')).toBe(false)
    expect(isValidHost('a\nInjected: x')).toBe(false)
  })

  test('isValidHost rejects IPv6 zone-ID allowlist bypass', () => {
    // This payload passes net.isIP() === 6, passes .endsWith('.github.com'),
    // and connects to 127.0.0.1 when the OS discards the bogus scope.
    expect(isValidHost('::ffff:127.0.0.1%x.github.com')).toBe(false)
    expect(isValidHost('fe80::1%eth0')).toBe(false)
    expect(isValidHost('[fe80::1%eth0]')).toBe(false)
  })

  test('isValidHost accepts underscore (real-world DNS records)', () => {
    expect(isValidHost('_dmarc.example.com')).toBe(true)
    expect(isValidHost('_acme-challenge.example.com')).toBe(true)
  })

  test('isValidHost accepts DNS names and IPs', () => {
    expect(isValidHost('registry.npmjs.org')).toBe(true)
    expect(isValidHost('sub-domain.example.co.uk')).toBe(true)
    expect(isValidHost('192.168.1.1')).toBe(true)
    expect(isValidHost('::1')).toBe(true)
    expect(isValidHost('[::1]')).toBe(true)
    expect(isValidHost('fe80::1')).toBe(true)
  })

  test('isValidHost rejects empty and overlong', () => {
    expect(isValidHost('')).toBe(false)
    expect(isValidHost('a'.repeat(256))).toBe(false)
  })
})

describe('parent-proxy: resolveParentProxy URL normalisation', () => {
  test('accepts schemeless host:port like curl', () => {
    const r = resolveParentProxy({ http: 'proxy.corp:3128' })
    expect(r?.httpUrl?.hostname).toBe('proxy.corp')
    expect(r?.httpUrl?.port).toBe('3128')
  })

  test('rejects non-http(s) schemes', () => {
    const r = resolveParentProxy({ http: 'socks5://proxy:1080' })
    expect(r?.httpUrl).toBeUndefined()
  })
})

describe('parent-proxy: selectParentProxyUrl curl semantics', () => {
  test('plain HTTP returns undefined when only HTTPS_PROXY set', () => {
    const r = resolveParentProxy({ https: 'http://secure:1' })!
    expect(selectParentProxyUrl(r, { isHttps: false })).toBeUndefined()
    expect(selectParentProxyUrl(r, { isHttps: true })?.hostname).toBe('secure')
  })
})

describe('parent-proxy: canonicalizeHost', () => {
  test('normalizes inet_aton shorthand (denylist evasion guard)', () => {
    expect(canonicalizeHost('127.1')).toBe('127.0.0.1')
    expect(canonicalizeHost('2130706433')).toBe('127.0.0.1')
    expect(canonicalizeHost('0x7f.0.0.1')).toBe('127.0.0.1')
    // AWS metadata as decimal
    expect(canonicalizeHost('2852039166')).toBe('169.254.169.254')
  })

  test('normalizes IPv6 forms', () => {
    expect(canonicalizeHost('0:0:0:0:0:0:0:1')).toBe('::1')
    expect(canonicalizeHost('[::1]')).toBe('::1')
  })

  test('spells an IPv4-mapped IPv6 literal as the IPv4 address it connects to', () => {
    expect(canonicalizeHost('::ffff:127.0.0.1')).toBe('127.0.0.1')
    expect(canonicalizeHost('[::FFFF:A9FE:A9FE]')).toBe('169.254.169.254')
    expect(canonicalizeHost('0:0:0:0:0:ffff:7f00:1')).toBe('127.0.0.1')
    // Other IPv4-embedding forms are different destinations; left as IPv6.
    expect(canonicalizeHost('::ffff:0:7f00:1')).toBe('::ffff:0:7f00:1')
    expect(canonicalizeHost('64:ff9b::7f00:1')).toBe('64:ff9b::7f00:1')
  })

  test('strips trailing dot and lowercases', () => {
    expect(canonicalizeHost('Example.COM.')).toBe('example.com')
  })

  test('passes through ordinary hostnames', () => {
    expect(canonicalizeHost('registry.npmjs.org')).toBe('registry.npmjs.org')
  })

  test('returns undefined for garbage', () => {
    expect(canonicalizeHost('not a host')).toBeUndefined()
  })
})
