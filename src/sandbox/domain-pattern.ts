/**
 * Domain-pattern matching shared between runtime host filtering
 * (sandbox-manager) and config-time validation (sandbox-config).
 * Lives in its own module so the schema can import it without pulling
 * in sandbox-manager (which imports the schema — circular).
 */

import { isIP } from 'node:net'
import { canonicalizeHost, stripBrackets } from './parent-proxy.js'

/** Drop an IPv6 zone id from an IP-literal entry; matching ignores zones. */
function dropZone(host: string): string {
  const pct = host.indexOf('%')
  return pct === -1 ? host : host.slice(0, pct)
}

/**
 * Split an optional `:port` suffix off a domain pattern.
 *
 * `api.github.com:443` → `{ hostPattern: 'api.github.com', port: 443 }`
 * `api.github.com`     → `{ hostPattern: 'api.github.com', port: undefined }`
 * `[::1]:443`          → `{ hostPattern: '::1', port: 443 }`
 * `[2001:db8::1]`      → `{ hostPattern: '2001:db8::1', port: undefined }`
 *
 * Only a strictly-numeric suffix in 1–65535 (no leading zeros) counts as a
 * port, so a smuggled host suffix like `evil.com:443.allowed.com` is left
 * whole (and then fails host validation on the remaining `:`).
 *
 * IPv6 literals must be bracketed (RFC 3986 / RFC 5952 §6: `[addr]` or
 * `[addr]:port`); the returned hostPattern is the bare, canonically
 * compressed address so it compares equal to what {@link canonicalizeHost}
 * yields for a destination. An *unbracketed* string with two or more colons
 * is ambiguous (`::1:443` is itself a valid address) — it is returned whole
 * with no port, never split, so a trailing hextet can't be mistaken for a
 * port and silently narrow the entry. The config schema rejects that form;
 * this fallback only matters for embedders passing config programmatically.
 */
export function splitDomainPatternPort(pattern: string): {
  hostPattern: string
  port: number | undefined
} {
  if (pattern.startsWith('[')) {
    const close = pattern.indexOf(']')
    if (close === -1) return { hostPattern: pattern, port: undefined }
    const inner = dropZone(pattern.slice(1, close))
    const host = canonicalizeHost(inner) ?? inner
    const rest = pattern.slice(close + 1)
    if (rest === '') return { hostPattern: host, port: undefined }
    const port = parsePortSuffix(rest.startsWith(':') ? rest.slice(1) : '')
    // `[::1]junk` / `[::1]:0` — leave whole so validation rejects it.
    return port === undefined
      ? { hostPattern: pattern, port: undefined }
      : { hostPattern: host, port }
  }
  const idx = pattern.lastIndexOf(':')
  if (idx === -1) return { hostPattern: pattern, port: undefined }
  if (pattern.indexOf(':') !== idx) {
    // ≥2 colons, no brackets: an IPv6 literal (or garbage). Never split.
    const host = dropZone(pattern)
    return {
      hostPattern: canonicalizeHost(host) ?? host,
      port: undefined,
    }
  }
  const port = parsePortSuffix(pattern.slice(idx + 1))
  if (port === undefined) return { hostPattern: pattern, port: undefined }
  return { hostPattern: pattern.slice(0, idx), port }
}

function parsePortSuffix(suffix: string): number | undefined {
  if (!/^[1-9][0-9]{0,4}$/.test(suffix)) return undefined
  const port = Number(suffix)
  return port > 65535 ? undefined : port
}

/**
 * The IP-literal entries of an allow/deny list as `{ range, port? }` rules
 * for the resolved-address check: an address the list names explicitly is
 * judged the same way when a hostname resolves to it.
 */
export function ipLiteralRules(
  entries: readonly string[],
): Array<{ range: string; port?: number }> {
  return entries.flatMap(entry => {
    const { hostPattern, port } = splitDomainPatternPort(entry)
    return isIP(hostPattern) ? [{ range: hostPattern, port }] : []
  })
}

/** Drop a `:port` suffix, if any (see {@link splitDomainPatternPort}). */
export function stripDomainPatternPort(pattern: string): string {
  return splitDomainPatternPort(pattern).hostPattern
}

/**
 * Match a hostname against a domain pattern.
 *
 * Patterns:
 *   - `*` matches everything (deny-all; the schema only accepts this in
 *     deniedDomains).
 *   - `*.example.com` matches any strict subdomain of example.com.
 *   - anything else matches exactly (case-insensitive).
 *
 * Wildcard suffix matching is refused for IP literals so an IPv6 zone-ID
 * payload like `::ffff:1.2.3.4%x.allowed.com` cannot pass `.endsWith()`
 * while the OS connects to the bare IP. isValidHost already rejects `%`,
 * but we refuse here too for defence in depth.
 */
export function matchesDomainPattern(
  hostname: string,
  pattern: string,
): boolean {
  const h = hostname.toLowerCase()
  if (pattern === '*') return true
  if (pattern.startsWith('*.')) {
    if (isIP(stripBrackets(h))) return false
    const baseDomain = pattern.substring(2).toLowerCase()
    return h.endsWith('.' + baseDomain)
  }
  return h === pattern.toLowerCase()
}

/**
 * {@link matchesDomainPattern} with an optional `:port` suffix on the
 * pattern (`example.com:443`, `*.example.com:8443`, `*:22`). A pattern
 * without a port matches every port; a pattern with one matches only when
 * the destination port is equal.
 */
export function matchesDomainPatternWithPort(
  hostname: string,
  port: number,
  pattern: string,
): boolean {
  const { hostPattern, port: patternPort } = splitDomainPatternPort(pattern)
  if (patternPort !== undefined && patternPort !== port) return false
  return matchesDomainPattern(hostname, hostPattern)
}

/**
 * Decide whether a per-credential `injectHosts` entry is reachable via
 * `network.allowedDomains` — i.e. every concrete host that could match
 * `injectHost` is allowed by at least one entry in `allowedDomains`.
 *
 * For an exact `injectHost` (`api.github.com`) this is just
 * `matchesDomainPattern` against each allowed pattern.
 *
 * For a wildcard `injectHost` (`*.X`), an exact allowedDomain can never
 * cover it (it admits only one host), so coverage requires an allowed
 * wildcard `*.Y` whose base is `X` or an ancestor of `X` — e.g.
 * `*.api.github.com` is covered by `*.github.com`.
 *
 * `:port` suffixes on allowedDomains entries are ignored: injection is
 * host-scoped, and a port-scoped allow still makes the host reachable.
 */
export function isInjectHostCoveredByAllowedDomains(
  injectHost: string,
  allowedDomains: readonly string[],
): boolean {
  const allowedHosts = allowedDomains.map(stripDomainPatternPort)
  if (!injectHost.startsWith('*.')) {
    return allowedHosts.some(p => matchesDomainPattern(injectHost, p))
  }
  const injectBase = injectHost.slice(2).toLowerCase()
  return allowedHosts.some(p => {
    if (!p.startsWith('*.')) return false
    const allowedBase = p.slice(2).toLowerCase()
    return injectBase === allowedBase || injectBase.endsWith('.' + allowedBase)
  })
}
