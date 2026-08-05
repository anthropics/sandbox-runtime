/**
 * Domain-pattern matching shared between runtime host filtering
 * (sandbox-manager) and config-time validation (sandbox-config).
 * Lives in its own module so the schema can import it without pulling
 * in sandbox-manager (which imports the schema — circular).
 */

import { isIP } from 'node:net'
import { stripBrackets } from './parent-proxy.js'

/**
 * Split an optional `:port` suffix off a domain pattern.
 *
 * `api.github.com:443` → `{ hostPattern: 'api.github.com', port: 443 }`
 * `api.github.com`     → `{ hostPattern: 'api.github.com', port: undefined }`
 *
 * Only a strictly-numeric suffix in 1–65535 (no leading zeros) counts as a
 * port, so a smuggled host suffix like `evil.com:443.allowed.com` is left
 * whole (and then fails host validation on the remaining `:`). IPv6 literals
 * are never in these lists (the schema rejects `:` outside the port suffix),
 * so last-colon splitting is unambiguous.
 */
export function splitDomainPatternPort(pattern: string): {
  hostPattern: string
  port: number | undefined
} {
  const idx = pattern.lastIndexOf(':')
  if (idx === -1) return { hostPattern: pattern, port: undefined }
  const suffix = pattern.slice(idx + 1)
  if (!/^[1-9][0-9]{0,4}$/.test(suffix)) {
    return { hostPattern: pattern, port: undefined }
  }
  const port = Number(suffix)
  if (port > 65535) return { hostPattern: pattern, port: undefined }
  return { hostPattern: pattern.slice(0, idx), port }
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
