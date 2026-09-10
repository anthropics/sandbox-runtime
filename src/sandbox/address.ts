/**
 * IP-literal / CIDR helpers over `net.BlockList`, shared by the
 * resolved-address guard, the parent-proxy NO_PROXY matcher and config
 * validation.
 */

import { BlockList, isIP } from 'node:net'

/** Loopback in both families (BlockList matches IPv4-mapped forms against the IPv4 rule). */
export const LOOPBACK_RANGES: readonly string[] = ['127.0.0.0/8', '::1']

type AddressFamily = 'ipv4' | 'ipv6'

/** BlockList family of an address string, or undefined if it is not an IP. */
function ipFamily(address: string): AddressFamily | undefined {
  const fam = isIP(address)
  return fam === 4 ? 'ipv4' : fam === 6 ? 'ipv6' : undefined
}

type AddressRange = {
  address: string
  prefix: number
  family: AddressFamily
}

/**
 * Parse an IP literal or CIDR range (`10.0.0.0/8`, `fc00::/7`, `::1`) into
 * the one form rules are stored in: an IPv4-mapped IPv6 entry becomes the
 * IPv4 rule it stands for (`::ffff:10.0.0.0/104` → `10.0.0.0/8`) and a zone
 * id is dropped, since matching treats both spellings alike and some
 * runtimes mis-evaluate or refuse the IPv6 ones. Undefined for anything
 * else; IPv6 is unbracketed.
 */
export function parseAddressRange(entry: string): AddressRange | undefined {
  const slash = entry.indexOf('/')
  const address = stripZone(slash === -1 ? entry : entry.slice(0, slash))
  const family = ipFamily(address)
  if (!family) return undefined
  const max = family === 'ipv6' ? 128 : 32
  let prefix = max
  if (slash !== -1) {
    const raw = entry.slice(slash + 1)
    if (!/^\d{1,3}$/.test(raw) || Number(raw) > max) return undefined
    prefix = Number(raw)
  }
  const mapped = family === 'ipv6' ? mappedIPv4(address) : undefined
  if (mapped !== undefined) {
    return prefix < 96
      ? undefined
      : { address: mapped, prefix: prefix - 96, family: 'ipv4' }
  }
  return { address, prefix, family }
}

/** Add an IP literal or CIDR range to `list`; false (list untouched) if malformed or refused by the runtime. */
export function addRange(list: BlockList, entry: string): boolean {
  const range = parseAddressRange(entry)
  if (!range) return false
  try {
    list.addSubnet(range.address, range.prefix, range.family)
  } catch {
    return false
  }
  return true
}

/**
 * Build a BlockList from IP/CIDR entries. Throws on a malformed entry — the
 * config schema validates first, so a throw here means a caller bypassed it.
 */
function buildAddressSet(entries: readonly string[]): BlockList {
  const list = new BlockList()
  for (const entry of entries) {
    if (!addRange(list, entry)) {
      throw new Error(
        `Invalid IP address or CIDR range: ${JSON.stringify(entry)}`,
      )
    }
  }
  return list
}

/**
 * BlockList membership for an address string of either family. IPv4 rules
 * also match the IPv4-mapped IPv6 spelling (BlockList does that itself);
 * an IPv6 zone id (`fe80::1%en0`) is dropped first because a zoned address
 * is a non-match on some runtimes.
 */
export function addressInSet(list: BlockList, address: string): boolean {
  const addr = stripZone(address)
  const family = ipFamily(addr)
  return family !== undefined && list.check(addr, family)
}

/** Drop an IPv6 zone id (`fe80::1%en0` → `fe80::1`). */
function stripZone(address: string): string {
  const pct = address.indexOf('%')
  return pct === -1 ? address : address.slice(0, pct)
}

/** The eight 16-bit groups of an IPv6 literal (zone dropped), or undefined. */
function ipv6Groups(address: string): number[] | undefined {
  let host: string
  try {
    host = new URL(`http://[${stripZone(address)}]/`).hostname.slice(1, -1)
  } catch {
    return undefined
  }
  const [head = '', tail] = host.split('::')
  const lead = head ? head.split(':') : []
  const rest = tail ? tail.split(':') : []
  const fill = tail === undefined ? 0 : 8 - lead.length - rest.length
  if (fill < 0 || lead.length + fill + rest.length !== 8) return undefined
  return [...lead, ...Array<string>(fill).fill('0'), ...rest].map(g =>
    parseInt(g, 16),
  )
}

const dottedQuad = (hi: number, lo: number): string =>
  `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`

/** The IPv4 address of an IPv4-mapped IPv6 literal (`::ffff:a.b.c.d`), or undefined. */
export function mappedIPv4(address: string): string | undefined {
  // Cheap reject before the URL parse: a mapped form always spells `ffff`.
  if (!/ffff/i.test(address)) return undefined
  const g = ipv6Groups(address)
  return g && g.slice(0, 5).every(x => x === 0) && g[5] === 0xffff
    ? dottedQuad(g[6]!, g[7]!)
    : undefined
}

/**
 * The IPv4 address an IPv6 address carries in one of the forms a network
 * delivers to that IPv4 destination: IPv4-mapped and IPv4-compatible
 * (`::ffff:0:0/96`, `::/96`), IPv4-translated (`::ffff:0:0:0/96`), the NAT64
 * well-known prefix (`64:ff9b::/96`) and 6to4 (`2002::/16`). Undefined for
 * anything else — including the local-use NAT64 prefix `64:ff9b:1::/48` and
 * network-specific prefixes, whose layout (RFC 6052 §2.2 allows /32…/96)
 * cannot be told from the address, so the embedded IPv4 could be anywhere;
 * an embedder on such a network lists the prefix's translations of the
 * ranges it denies.
 */
export function embeddedIPv4(address: string): string | undefined {
  if (isIP(address) !== 6) return undefined
  const g = ipv6Groups(address)
  if (!g) return undefined
  const zero = (from: number, to: number) =>
    g.slice(from, to).every(x => x === 0)
  if (g[0] === 0x2002) return dottedQuad(g[1]!, g[2]!)
  const low = dottedQuad(g[6]!, g[7]!)
  if (g[0] === 0x64 && g[1] === 0xff9b && zero(2, 6)) return low // NAT64 /96
  if (zero(0, 5) && (g[5] === 0 || g[5] === 0xffff)) return low
  if (zero(0, 4) && g[4] === 0xffff && g[5] === 0) return low
  return undefined
}

const LOOPBACK = buildAddressSet(LOOPBACK_RANGES)

/** True for an IPv4/IPv6 loopback literal (including v4-mapped forms). */
export function isLoopbackAddress(address: string): boolean {
  return addressInSet(LOOPBACK, address)
}

/** `localhost` and names under `.localhost` (RFC 6761 §6.3). */
export function isLoopbackName(hostname: string): boolean {
  const h = hostname.toLowerCase().replace(/\.$/, '')
  return h === 'localhost' || h.endsWith('.localhost')
}
