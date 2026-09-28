/**
 * Per-session sentinel registry for credential masking.
 *
 * A masked credential's real value is replaced inside the sandbox with a
 * sentinel of the form `fake_value_<uuid4>`. The sandboxed process sees only
 * the sentinel; the host-side proxy substitutes sentinel→real on egress to
 * allowlisted destinations. The map lives only in process memory — it is
 * never written to disk and never logged.
 */

import { randomBytes, randomUUID } from 'node:crypto'
import type { IncomingHttpHeaders } from 'node:http'
import type { SentinelBufferPair } from './body-substitution.js'

export const SENTINEL_PREFIX = 'fake_value_'

// Padding alphabet: the same character class as the base sentinel, so a
// padded sentinel still survives shells, JSON, URLs, and multipart unquoted.
const SENTINEL_ALPHABET = 'abcdefghijklmnopqrstuvwxyz0123456789_-'

/**
 * Mint `fake_value_<uuid4>`, padded with random alphabet chars up to the
 * real value's byte length when the real value is longer. A length-matched
 * sentinel keeps Content-Length invariant under body substitution, so the
 * proxy forwards the header verbatim; a shorter real value keeps the
 * 47-byte base sentinel (entropy is never reduced below the uuid4) and the
 * proxy falls back to chunked framing instead. The padding carries no
 * entropy contract — the uuid4 does — so modulo bias is irrelevant.
 */
function mintSentinel(realValue: string): string {
  const base = SENTINEL_PREFIX + randomUUID()
  const pad = Buffer.byteLength(realValue) - base.length
  if (pad <= 0) return base
  let out = base
  for (const b of randomBytes(pad)) {
    out += SENTINEL_ALPHABET[b % SENTINEL_ALPHABET.length]
  }
  return out
}

/** Predicate matching a destination host against one injectHosts pattern. */
export type HostMatcher = (host: string, pattern: string) => boolean

interface SentinelEntry {
  readonly name: string
  readonly sentinel: string
  realValue: string
  injectHosts: readonly string[]
}

/**
 * Sentinel↔real-value map for one sandbox session, keyed by credential name.
 *
 * Each credential carries its own `injectHosts` list, and substitution is
 * gated per sentinel: a sentinel is swapped to its real value only when the
 * destination matches THAT credential's hosts. This prevents laundering
 * credential A through credential B's allowlisted host by sending A's
 * sentinel there — the proxy leaves A's sentinel intact on B's host.
 *
 * Keying on name (not value) means two env vars holding the same secret get
 * distinct sentinels, so each can have an independent host list.
 */
export class SentinelRegistry {
  private readonly byName = new Map<string, SentinelEntry>()
  private readonly bySentinel = new Map<string, SentinelEntry>()
  // True while every registered sentinel starts with SENTINEL_PREFIX, which
  // keeps the substring fast path in substituteInString() valid. A
  // caller-minted sentinel (e.g. a JWT-shaped fake) clears it.
  private allSentinelsPrefixed = true

  /**
   * Return the sentinel for the credential named `name`, minting a fresh one
   * on first use. The sentinel is `fake_value_<uuid4>`: long enough that an
   * accidental collision with legitimate header content is negligible, and
   * free of shell/URL metacharacters so it survives `--setenv` and
   * `env NAME=value` unquoted.
   *
   * Idempotent on `name`: a repeat call returns the same sentinel and updates
   * `realValue`/`injectHosts` in place so `updateConfig()` can change either
   * without invalidating sentinels the sandboxed process has already read.
   * (A re-register whose new value has a different byte length leaves the
   * sentinel un-length-matched; body substitution then re-frames as chunked
   * rather than trusting a stale Content-Length.)
   */
  register(
    name: string,
    realValue: string,
    injectHosts: readonly string[],
  ): string {
    return this.registerWithSentinel(
      name,
      mintSentinel(realValue),
      realValue,
      injectHosts,
    )
  }

  /**
   * Like {@link register}, but with a caller-minted sentinel instead of the
   * default `fake_value_<uuid4>` — used when the fake must keep the real
   * value's shape (e.g. a structurally valid JWT for `decode: "jwt"`), so
   * client-side parsers inside the sandbox don't choke on it.
   *
   * Same idempotency contract as {@link register}: if `name` is already
   * registered, the EXISTING sentinel is returned (and `sentinel` discarded)
   * so a re-register never invalidates a fake the sandboxed process has
   * already read. The caller must mint sentinels with enough entropy that
   * collisions with real content are negligible (embed a uuid4). A sentinel
   * that nests with one already registered is refused (see the check below).
   *
   * Caller-minted sentinels are used verbatim — never length-padded: a
   * shaped fake (e.g. a JWT) must keep its structure. They are therefore
   * generally not length-matched, and body substitution at hosts where they
   * inject falls back to chunked framing.
   */
  registerWithSentinel(
    name: string,
    sentinel: string,
    realValue: string,
    injectHosts: readonly string[],
  ): string {
    const existing = this.byName.get(name)
    if (existing !== undefined) {
      existing.realValue = realValue
      existing.injectHosts = injectHosts
      return existing.sentinel
    }
    // No registered sentinel may be a substring of another. The
    // body-substitution scan matches earliest-position-then-registration-
    // order, not longest-match, so a nested pair replaces the wrong span, and
    // which one wins depends on where the streaming transform's chunk
    // boundaries fall. Minted sentinels each carry their own uuid4 and cannot
    // nest; a caller-minted one (a shaped fake) can, and is refused here
    // rather than at the first body that carries it. Registration is once per
    // credential at wrap time, so the scan costs nothing that matters.
    for (const registered of this.bySentinel.values()) {
      if (
        registered.sentinel.includes(sentinel) ||
        sentinel.includes(registered.sentinel)
      ) {
        throw new Error(
          `Credential "${name}" was given a sentinel that nests with the one ` +
            `already registered for "${registered.name}": body substitution ` +
            `would replace the wrong span. Mint sentinels that embed a uuid4.`,
        )
      }
    }
    if (!sentinel.startsWith(SENTINEL_PREFIX)) {
      this.allSentinelsPrefixed = false
    }
    const entry: SentinelEntry = { name, sentinel, realValue, injectHosts }
    this.byName.set(name, entry)
    this.bySentinel.set(sentinel, entry)
    return sentinel
  }

  /** Real value for `sentinel`, or undefined if not registered. */
  lookupReal(sentinel: string): string | undefined {
    return this.bySentinel.get(sentinel)?.realValue
  }

  /**
   * Names of the registered credentials whose `injectHosts` cover
   * `destHost`. Diagnostic helper: the proxy uses it to warn when a host is
   * exempted from TLS termination (so substitution can never run there) but
   * a masked credential is configured for injection at it.
   */
  namesInjectableAt(destHost: string, matches: HostMatcher): string[] {
    const names: string[] = []
    for (const e of this.byName.values()) {
      if (e.injectHosts.some(p => matches(destHost, p))) names.push(e.name)
    }
    return names
  }

  /**
   * Sentinel→real byte pairs for every credential whose `injectHosts`
   * cover `destHost` — the substitution set the body transform scans for.
   * Same per-credential gating as {@link substituteInHeaders}. Buffers are
   * built per call so a re-registered credential's updated real value is
   * always current.
   */
  sentinelsForHost(
    destHost: string,
    matches: HostMatcher,
  ): SentinelBufferPair[] {
    const pairs: SentinelBufferPair[] = []
    for (const e of this.bySentinel.values()) {
      if (!e.injectHosts.some(p => matches(destHost, p))) continue
      pairs.push({
        sentinel: Buffer.from(e.sentinel),
        realValue: Buffer.from(e.realValue),
      })
    }
    return pairs
  }

  /** Iterate registered `[sentinel, realValue]` pairs. */
  *entries(): IterableIterator<[string, string]> {
    for (const e of this.bySentinel.values()) yield [e.sentinel, e.realValue]
  }

  /** Number of registered sentinels. */
  get size(): number {
    return this.bySentinel.size
  }

  /** Drop every mapping. Called on session teardown. */
  clear(): void {
    this.byName.clear()
    this.bySentinel.clear()
    this.allSentinelsPrefixed = true
  }

  /**
   * Replace registered sentinels found in `headers` with their real values,
   * in place. Each sentinel substitutes only when `destHost` matches one of
   * THAT credential's `injectHosts` patterns (via `matches`); a sentinel
   * whose host list does not cover `destHost` is left as the useless fake.
   *
   * Scans all header values rather than a fixed set — a sentinel showing up
   * anywhere is the substitution trigger, regardless of header name
   * (Authorization, X-Api-Key, Private-Token, ...).
   *
   * The caller remains responsible for transport gating (TLS-terminated path
   * unless `allowPlaintextInject`).
   */
  substituteInHeaders(
    headers: IncomingHttpHeaders,
    destHost: string,
    matches: HostMatcher,
  ): void {
    if (this.bySentinel.size === 0) return
    for (const [name, value] of Object.entries(headers)) {
      if (value === undefined) continue
      if (Array.isArray(value)) {
        for (let i = 0; i < value.length; i++) {
          value[i] = this.substituteInString(value[i]!, destHost, matches)
        }
      } else {
        headers[name] = this.substituteInString(value, destHost, matches)
      }
    }
  }

  private substituteInString(
    s: string,
    destHost: string,
    matches: HostMatcher,
  ): string {
    // Fast path: while every sentinel carries the fixed prefix, a header
    // value that doesn't contain it cannot contain any sentinel. Disabled
    // once a caller-minted sentinel (arbitrary shape) is registered.
    if (this.allSentinelsPrefixed && !s.includes(SENTINEL_PREFIX)) return s
    let out = s
    for (const e of this.bySentinel.values()) {
      if (!out.includes(e.sentinel)) continue
      if (!e.injectHosts.some(p => matches(destHost, p))) continue
      out = out.split(e.sentinel).join(e.realValue)
    }
    return out
  }
}
