/**
 * Parent/upstream HTTP proxy support.
 *
 * When SRT runs in an environment that requires an HTTP proxy for outbound
 * internet access (e.g. inside a VM on a host behind a corporate proxy),
 * SRT's own proxies must chain through that upstream rather than connecting
 * directly.
 *
 * This module provides:
 *   - config resolution (explicit config -> HTTP_PROXY/HTTPS_PROXY/NO_PROXY env)
 *   - NO_PROXY matching (hostname suffix + CIDR via net.BlockList). Follows
 *     golang.org/x/net/http/httpproxy semantics for suffix matching. Note:
 *     port-specific NO_PROXY entries (e.g. `host:8080`) are matched by host
 *     only; the port is ignored.
 *   - a generic CONNECT-tunnel helper that works over Unix socket, TCP, or TLS
 */

import type { LookupFunction, Socket } from 'node:net'
import type { IncomingHttpHeaders } from 'node:http'
import { BlockList, connect as netConnect, isIP } from 'node:net'
import { connect as tlsConnect } from 'node:tls'
import { URL } from 'node:url'
import { logForDebugging } from '../utils/debug.js'
import type { ParentProxyConfig } from './sandbox-config.js'
import {
  addRange,
  addressInSet,
  isLoopbackAddress,
  mappedIPv4,
} from './address.js'

export interface ResolvedParentProxy {
  httpUrl?: URL
  httpsUrl?: URL
  noProxy: NoProxyRules
}

interface NoProxyRules {
  all: boolean
  suffixes: string[]
  cidr: BlockList
}

const CONNECT_TIMEOUT_MS = 30_000

/**
 * Hop-by-hop headers per RFC 7230 §6.1, plus proxy-specific headers that
 * MUST NOT be forwarded to the upstream. `transfer-encoding` is included
 * because we re-frame bodies via Node's client; Content-Length is preserved
 * end-to-end (Node's llhttp already rejects the TE+CL smuggling vector).
 */
const HOP_BY_HOP = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'proxy-connection',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
])

/**
 * Resolve the parent proxy config, falling back to the SRT process's own
 * environment. Note: SRT later overwrites HTTP_PROXY etc. in the *sandboxed
 * child's* environment to point at itself — but process.env here reflects the
 * environment SRT itself was launched with, which is what we want.
 */
export function resolveParentProxy(
  cfg?: ParentProxyConfig,
): ResolvedParentProxy | undefined {
  const http =
    cfg?.http ?? process.env.HTTP_PROXY ?? process.env.http_proxy ?? undefined
  const https =
    cfg?.https ??
    process.env.HTTPS_PROXY ??
    process.env.https_proxy ??
    // Fall back to HTTP_PROXY for HTTPS if HTTPS_PROXY is unset — this is
    // the de-facto behaviour of curl and most tooling.
    http
  const noProxyRaw =
    cfg?.noProxy ?? process.env.NO_PROXY ?? process.env.no_proxy ?? ''

  if (!http && !https) return undefined

  const parse = (u: string | undefined): URL | undefined => {
    if (!u) return undefined
    // Accept schemeless `host:port` like curl does, but reject any scheme
    // other than http/https.
    const hasScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(u)
    const withScheme = hasScheme ? u : `http://${u}`
    try {
      const parsed = new URL(withScheme)
      if (
        (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') ||
        !parsed.hostname
      ) {
        throw new Error('unsupported scheme or empty host')
      }
      return parsed
    } catch {
      logForDebugging(
        `Invalid parent proxy URL, ignoring: ${redactUserinfo(u)}`,
        { level: 'error' },
      )
      return undefined
    }
  }

  const httpUrl = parse(http)
  const httpsUrl = parse(https)
  // If both parsed to undefined, behave as if no parent proxy was configured
  // rather than returning a husk object that makes callers do bypass checks
  // for nothing.
  if (!httpUrl && !httpsUrl) return undefined

  return { httpUrl, httpsUrl, noProxy: parseNoProxy(noProxyRaw) }
}

function parseNoProxy(raw: string): NoProxyRules {
  const rules: NoProxyRules = {
    all: false,
    suffixes: [],
    cidr: new BlockList(),
  }

  for (let entry of raw.split(',')) {
    entry = entry.trim()
    if (!entry) continue
    if (entry === '*') {
      rules.all = true
      continue
    }

    // CIDR? A malformed one is ignored (do NOT treat as suffix; `/` isn't
    // a valid hostname char).
    if (entry.includes('/')) {
      addRange(rules.cidr, entry)
      continue
    }

    // Hostname suffix. Normalise: lowercase, strip brackets (handling the
    // `[v6]:port` form), strip leading `*.`, strip a trailing `:port` (unless
    // the entry is an IP literal — IPv6 addresses contain colons).
    let v = entry.toLowerCase()
    const bracketed = /^\[([^\]]+)\](?::\d+)?$/.exec(v)
    if (bracketed) v = bracketed[1]!
    if (v.startsWith('*.')) v = v.slice(1)
    if (!isIP(v)) {
      const colon = v.lastIndexOf(':')
      if (colon !== -1 && /^\d+$/.test(v.slice(colon + 1))) {
        v = v.slice(0, colon)
      }
    } else if (addRange(rules.cidr, v)) {
      // Bare IP literal — an exact-match /32 or /128 rule, so lookups go
      // through BlockList rather than string suffix matching.
      continue
    }
    rules.suffixes.push(v)
  }

  return rules
}

/**
 * Returns true if the given host should bypass the parent proxy and connect
 * directly. Always bypasses loopback.
 *
 * NB: the port is not consulted. NO_PROXY entries of the form `host:port` are
 * matched by host only (the port suffix is stripped during parsing).
 */
export function shouldBypassParentProxy(
  resolved: ResolvedParentProxy,
  host: string,
): boolean {
  const h = stripBrackets(host.toLowerCase().replace(/\.$/, ''))

  // Always bypass loopback — chaining localhost through an upstream proxy is
  // never what you want. Covers the whole 127/8 block and IPv4-mapped forms.
  if (h === 'localhost' || isLoopbackAddress(h)) return true

  if (resolved.noProxy.all) return true
  if (addressInSet(resolved.noProxy.cidr, h)) return true

  for (const v of resolved.noProxy.suffixes) {
    if (v.startsWith('.')) {
      // .example.com matches foo.example.com and example.com
      if (h === v.slice(1) || h.endsWith(v)) return true
    } else {
      // example.com matches example.com and foo.example.com (golang semantics)
      if (h === v || h.endsWith('.' + v)) return true
    }
  }
  return false
}

/**
 * Pick which parent proxy URL to use for a given destination.
 */
export function selectParentProxyUrl(
  resolved: ResolvedParentProxy,
  opts: { isHttps: boolean },
): URL | undefined {
  if (opts.isHttps) return resolved.httpsUrl ?? resolved.httpUrl
  // For plain HTTP we only fall back to HTTPS_PROXY if it was explicitly set
  // — matches curl's behaviour where HTTP requests go direct if only
  // HTTPS_PROXY is configured.
  return resolved.httpUrl
}

// ---------------------------------------------------------------------------
// CONNECT tunnelling
// ---------------------------------------------------------------------------

export interface ConnectTunnelOptions {
  /** Establish the transport to the proxy. */
  dial(): Socket
  /** Fired when the transport is ready to write (e.g. 'connect'/'secureConnect'). */
  readyEvent: 'connect' | 'secureConnect'
  destHost: string
  destPort: number
  authHeader?: string
  timeoutMs?: number
}

/**
 * Generic CONNECT-tunnel: dial a proxy transport (unix/tcp/tls), send
 * `CONNECT host:port`, wait for a 2xx, and resolve with the tunnelled socket.
 * Validates destHost to prevent CRLF injection from untrusted callers.
 */
export function openConnectTunnel(opts: ConnectTunnelOptions): Promise<Socket> {
  const { destHost, destPort } = opts

  // CRLF-injection guard: destHost may originate from an untrusted SOCKS5
  // DOMAINNAME field. Reject anything that isn't a plain hostname or IP.
  const bare = stripBrackets(destHost)
  if (!isValidHost(bare)) {
    return Promise.reject(
      new Error(
        `Invalid destination host for CONNECT: ${JSON.stringify(destHost)}`,
      ),
    )
  }
  if (!Number.isInteger(destPort) || destPort < 1 || destPort > 65535) {
    return Promise.reject(new Error(`Invalid destination port: ${destPort}`))
  }

  const authority =
    isIP(bare) === 6 ? `[${bare}]:${destPort}` : `${bare}:${destPort}`

  return new Promise((resolve, reject) => {
    const sock = opts.dial()
    let settled = false

    const fail = (err: Error) => {
      if (settled) return
      settled = true
      sock.destroy()
      reject(err)
    }
    const onClose = () =>
      fail(new Error('Proxy closed during CONNECT handshake'))

    sock.setTimeout(opts.timeoutMs ?? CONNECT_TIMEOUT_MS, () =>
      fail(new Error('CONNECT handshake timed out')),
    )
    sock.once('error', fail)
    sock.once('close', onClose)

    sock.once(opts.readyEvent, () => {
      sock.write(
        `CONNECT ${authority} HTTP/1.1\r\n` +
          `Host: ${authority}\r\n` +
          (opts.authHeader
            ? `Proxy-Authorization: ${opts.authHeader}\r\n`
            : '') +
          '\r\n',
      )

      let buf = ''
      const onData = (chunk: Buffer) => {
        buf += chunk.toString('latin1')
        const end = buf.indexOf('\r\n\r\n')
        if (end === -1) {
          // Cap header size to avoid unbounded buffering on a misbehaving proxy.
          if (buf.length > 16 * 1024)
            fail(new Error('CONNECT response header too large'))
          return
        }
        // Pause before detaching the data listener so the stream stops
        // flowing — otherwise the unshift below (or any bytes arriving
        // between now and the caller's pipe()) would be dropped.
        sock.pause()
        sock.removeListener('data', onData)

        const statusLine = buf.slice(0, buf.indexOf('\r\n'))
        if (!/^HTTP\/1\.[01] 2\d\d(?:\s|$)/.test(statusLine)) {
          return fail(new Error(`Proxy refused CONNECT: ${statusLine.trim()}`))
        }

        // Re-emit any bytes that arrived after the header terminator.
        const rest = buf.slice(end + 4)
        if (rest.length) sock.unshift(Buffer.from(rest, 'latin1'))

        settled = true
        sock.setTimeout(0)
        sock.removeListener('error', fail)
        sock.removeListener('close', onClose)
        resolve(sock)
      }
      sock.on('data', onData)
    })
  })
}

/**
 * Open a CONNECT tunnel through a parent HTTP(S) proxy specified by URL.
 * Thin wrapper around openConnectTunnel that dials TCP or TLS based on the
 * proxy URL scheme.
 */
export function connectViaParentProxy(
  proxyUrl: URL,
  destHost: string,
  destPort: number,
): Promise<Socket> {
  const proxyHost = stripBrackets(proxyUrl.hostname)
  const proxyPort =
    Number(proxyUrl.port) || (proxyUrl.protocol === 'https:' ? 443 : 80)
  const useTls = proxyUrl.protocol === 'https:'

  return openConnectTunnel({
    destHost,
    destPort,
    authHeader: proxyAuthHeader(proxyUrl),
    readyEvent: useTls ? 'secureConnect' : 'connect',
    dial: () =>
      useTls
        ? tlsConnect({
            host: proxyHost,
            port: proxyPort,
            // SNI must be a hostname, never an IP literal (RFC 6066 §3).
            ...(isIP(proxyHost) ? {} : { servername: proxyHost }),
          })
        : netConnect(proxyPort, proxyHost),
  })
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

export function proxyAuthHeader(proxyUrl: URL): string | undefined {
  if (!proxyUrl.username && !proxyUrl.password) return undefined
  try {
    const creds = `${decodeURIComponent(proxyUrl.username)}:${decodeURIComponent(proxyUrl.password)}`
    return `Basic ${Buffer.from(creds).toString('base64')}`
  } catch {
    // Malformed percent-encoding in userinfo — fall back to raw values
    // rather than throwing synchronously into the caller.
    const creds = `${proxyUrl.username}:${proxyUrl.password}`
    return `Basic ${Buffer.from(creds).toString('base64')}`
  }
}

/**
 * Strip hop-by-hop and proxy-specific headers before forwarding upstream.
 * Also strips any headers named in the incoming `Connection` header, per
 * RFC 7230 §6.1.
 */
export function stripHopByHop(h: IncomingHttpHeaders): IncomingHttpHeaders {
  const extra = new Set<string>()
  const connHeader = h.connection
  if (connHeader) {
    for (const tok of String(connHeader).split(',')) {
      extra.add(tok.trim().toLowerCase())
    }
  }
  const out: IncomingHttpHeaders = {}
  for (const [k, v] of Object.entries(h)) {
    const lk = k.toLowerCase()
    if (!HOP_BY_HOP.has(lk) && !extra.has(lk)) out[k] = v
  }
  return out
}

/** Remove surrounding square brackets from an IPv6 literal. */
export function stripBrackets(host: string): string {
  return host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host
}

/** Redact userinfo from a URL for safe logging. */
export function redactUrl(u: URL | undefined): string {
  if (!u) return '-'
  if (!u.username && !u.password) return u.href
  const c = new URL(u.href)
  c.username = '***'
  c.password = '***'
  return c.href
}

function redactUserinfo(raw: string): string {
  // Best-effort redaction for unparseable URLs.
  return raw.replace(/\/\/[^@/]*@/, '//***:***@')
}

/**
 * Hostname validation: accepts DNS names and IP literals (without zone IDs).
 * Primary purpose is to block control characters (CRLF injection, null-byte
 * DNS truncation) and zone-identifier allowlist bypasses from reaching the
 * wire or the allowlist matcher.
 *
 * IPv6 zone IDs (`fe80::1%eth0`) are rejected because `isIP` accepts a very
 * permissive zone charset including dots — `::ffff:1.2.3.4%x.allowed.com`
 * would pass `isIP`, pass a `.endsWith('.allowed.com')` wildcard check, and
 * then connect to 1.2.3.4 when the OS discards the bogus scope.
 */
export function isValidHost(h: string): boolean {
  if (!h || h.length > 255) return false
  const bare = stripBrackets(h)
  // Reject zone identifiers outright (see doc comment).
  if (bare.includes('%')) return false
  if (isIP(bare)) return true
  // DNS label charset. Underscore is permitted for compatibility with real-
  // world DNS records (_dmarc, _acme-challenge, etc.).
  return /^[A-Za-z0-9._-]+$/.test(bare)
}

/**
 * Canonicalize a host string via the WHATWG URL parser so that string
 * comparisons in the allowlist agree with what `net.connect()`/`getaddrinfo()`
 * will actually dial. This normalizes:
 *   - inet_aton shorthand (`127.1` → `127.0.0.1`, `2130706433` → `127.0.0.1`)
 *   - hex/octal octets (`0x7f.0.0.1` → `127.0.0.1`)
 *   - IPv6 compression (`0:0:0:0:0:0:0:1` → `::1`)
 *   - trailing dots, case, brackets
 *
 * Returns undefined if the input is not a valid URL host.
 */
export function canonicalizeHost(h: string): string | undefined {
  try {
    const bare = stripBrackets(h)
    // WHATWG URL rejects zone IDs and most garbage; it normalizes inet_aton
    // forms and IPv6 compression. It does NOT strip trailing dots or IPv6
    // brackets from the output, so we do that ourselves.
    const bracketed = isIP(bare) === 6 ? `[${bare}]` : bare
    const out = stripBrackets(new URL(`http://${bracketed}/`).hostname)
    // An IPv4-mapped literal connects to that IPv4 address, so it is spelled
    // as one: allow/deny entries and requests then compare equal.
    return isIP(out) === 6 ? (mappedIPv4(out) ?? out) : out.replace(/\.$/, '')
  } catch {
    return undefined
  }
}

/** Per-dial name resolution the proxies are handed: the guard's `lookup` for `port`, refusals recorded. */
export type DirectLookup = (
  port: number,
  encodedCommand?: string,
) => LookupFunction

/** `host[:port]` as it belongs in a Host header / URL authority: IPv6 bracketed, the default port elided. */
export function formatAuthority(
  host: string,
  port: number,
  defaultPort: number,
): string {
  const bracketed = isIP(host) === 6 ? `[${host}]` : host
  return port === defaultPort ? bracketed : `${bracketed}:${port}`
}

export interface DirectRequestOptions {
  host: string
  port: number
  servername?: string
  agent: false
}

/**
 * Connection options for an `http(s).request` to `host:port` over the direct
 * route. The name is dialed exactly as a tunnel would be ({@link dialDirect}:
 * the guard's `lookup`, the connect timeout, the runtime's address-family
 * fallback), the address that answered is kept and that connection released;
 * the request then goes to the literal, with the name in SNI (callers keep it
 * in Host). So the vetted address is the one requested and `lookup` never
 * reaches the HTTP client: Bun's node:http client up to 1.3.x resolves through
 * a custom `lookup` but then drops or repeats a streamed request body, and
 * ignores `createConnection` (oven-sh/bun#7471), so the vetted socket cannot
 * simply be adopted. Bun 1.4 rewrote that client (oven-sh/bun#31587); once it
 * is the floor, hand the request the dialed socket and drop the second connect.
 * No agent: the global pool is shared with the embedding process (and Bun
 * caches the first request's `ca` on it), and the vetting dial runs per request
 * anyway. Without a `lookup`, or for an IP literal, the host is used as given.
 */
export async function directRequestOptions(
  host: string,
  port: number,
  lookup: LookupFunction | undefined,
  tls: boolean,
): Promise<DirectRequestOptions> {
  let address = host
  if (lookup && !isIP(host)) {
    const probe = await dialDirect(host, port, lookup)
    address = probe.remoteAddress ?? ''
    probe.destroy()
    if (!address) throw new Error(`connect ${host}:${port}: no peer address`)
  }
  // SNI cannot carry an IP literal, and Bun treats `servername: undefined`
  // differently from an absent key.
  return {
    host: address,
    port,
    ...(tls && !isIP(host) ? { servername: host } : {}),
    agent: false,
  }
}

/**
 * Dial `host:port` directly with a bounded timeout. Shared by the HTTP and
 * SOCKS direct-connect paths so they get the same timeout behaviour as the
 * CONNECT-tunnelled paths. `lookup` is the resolved-address guard's (see
 * resolved-address-guard.ts); the runtime dials what it returns. It is a
 * required argument so no direct dial omits it by accident — pass
 * `undefined` explicitly to use the runtime's resolver unguarded.
 */
export function dialDirect(
  host: string,
  port: number,
  lookup: LookupFunction | undefined,
  timeoutMs = CONNECT_TIMEOUT_MS,
): Promise<Socket> {
  return new Promise((resolve, reject) => {
    const s = netConnect({ port, host, lookup })
    let settled = false
    const done = (err?: Error) => {
      if (settled) return
      settled = true
      s.setTimeout(0)
      if (err) {
        s.destroy()
        reject(err)
      } else {
        resolve(s)
      }
    }
    s.setTimeout(timeoutMs, () => done(new Error('connect timed out')))
    s.once('connect', () => done())
    s.once('error', done)
    s.once('close', () => done(new Error('socket closed before connect')))
  })
}
