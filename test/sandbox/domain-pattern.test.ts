import { describe, test, expect } from 'bun:test'
import {
  ipLiteralRules,
  isAddressRangeEntry,
  isInjectHostCoveredByAllowedDomains,
  matchesDomainPattern,
  matchesDomainPatternWithPort,
  splitDomainPatternPort,
} from '../../src/sandbox/domain-pattern.js'

describe('matchesDomainPattern', () => {
  test('exact match is case-insensitive', () => {
    expect(matchesDomainPattern('API.Example.com', 'api.example.com')).toBe(
      true,
    )
  })

  test('wildcard matches strict subdomains only', () => {
    expect(matchesDomainPattern('a.example.com', '*.example.com')).toBe(true)
    expect(matchesDomainPattern('a.b.example.com', '*.example.com')).toBe(true)
    expect(matchesDomainPattern('example.com', '*.example.com')).toBe(false)
    expect(matchesDomainPattern('notexample.com', '*.example.com')).toBe(false)
  })
})

// Generic "is this pattern fully covered by that pattern list" predicate.
// Used for injectHosts ⊆ allowedDomains and, since tlsTerminate
// excludeDomains, for "could this injectHost ever be injected".
describe('isInjectHostCoveredByAllowedDomains', () => {
  test('exact host covered by an exact entry or a wildcard', () => {
    expect(
      isInjectHostCoveredByAllowedDomains('api.example.com', [
        'api.example.com',
      ]),
    ).toBe(true)
    expect(
      isInjectHostCoveredByAllowedDomains('api.example.com', ['*.example.com']),
    ).toBe(true)
    expect(
      isInjectHostCoveredByAllowedDomains('api.example.com', ['example.com']),
    ).toBe(false)
  })

  test('a wildcard is never covered by exact entries', () => {
    expect(
      isInjectHostCoveredByAllowedDomains('*.example.com', [
        'api.example.com',
        'b.example.com',
      ]),
    ).toBe(false)
  })

  test('a wildcard is covered by an equal or ancestor wildcard only', () => {
    expect(
      isInjectHostCoveredByAllowedDomains('*.api.example.com', [
        '*.example.com',
      ]),
    ).toBe(true)
    expect(
      isInjectHostCoveredByAllowedDomains('*.example.com', [
        '*.api.example.com',
      ]),
    ).toBe(false)
  })

  test('ignores :port suffixes on allowedDomains entries', () => {
    expect(
      isInjectHostCoveredByAllowedDomains('api.example.com', [
        'api.example.com:443',
      ]),
    ).toBe(true)
    expect(
      isInjectHostCoveredByAllowedDomains('*.api.example.com', [
        '*.example.com:8443',
      ]),
    ).toBe(true)
  })
})

describe('splitDomainPatternPort', () => {
  test('splits a numeric port suffix', () => {
    expect(splitDomainPatternPort('example.com:443')).toEqual({
      hostPattern: 'example.com',
      port: 443,
    })
    expect(splitDomainPatternPort('*.example.com:8080')).toEqual({
      hostPattern: '*.example.com',
      port: 8080,
    })
    expect(splitDomainPatternPort('*:22')).toEqual({
      hostPattern: '*',
      port: 22,
    })
  })

  test('no suffix, or a non-port suffix, is left whole', () => {
    expect(splitDomainPatternPort('example.com')).toEqual({
      hostPattern: 'example.com',
      port: undefined,
    })
    for (const s of [
      'example.com:0',
      'example.com:65536',
      'example.com:99999999',
      'example.com:0443',
      'example.com:abc',
      'example.com:443.allowed.com',
      'example.com:',
    ]) {
      expect(splitDomainPatternPort(s)).toEqual({
        hostPattern: s,
        port: undefined,
      })
    }
  })
})

describe('splitDomainPatternPort — IPv6 literals', () => {
  test('bracketed literal, with and without port; host is bare + canonical', () => {
    expect(splitDomainPatternPort('[::1]')).toEqual({
      hostPattern: '::1',
      port: undefined,
    })
    expect(splitDomainPatternPort('[::1]:443')).toEqual({
      hostPattern: '::1',
      port: 443,
    })
    // Canonical compression so it compares equal to canonicalizeHost(dest).
    expect(splitDomainPatternPort('[2001:0db8:0000::0001]:8443')).toEqual({
      hostPattern: '2001:db8::1',
      port: 8443,
    })
    expect(splitDomainPatternPort('[fd00:ec2::254]')).toEqual({
      hostPattern: 'fd00:ec2::254',
      port: undefined,
    })
    // A zone id is meaningless for matching (a request can never carry one)
    // and is dropped, so the entry matches the address on any interface.
    expect(splitDomainPatternPort('[fe80::1%en0]:22')).toEqual({
      hostPattern: 'fe80::1',
      port: 22,
    })
    expect(splitDomainPatternPort('fe80::1%en0')).toEqual({
      hostPattern: 'fe80::1',
      port: undefined,
    })
  })

  test('unbracketed multi-colon is never split (no hextet mistaken for a port)', () => {
    // The pre-fix behaviour parsed this as host "fd00:ec2:" + port 254.
    expect(splitDomainPatternPort('fd00:ec2::254')).toEqual({
      hostPattern: 'fd00:ec2::254',
      port: undefined,
    })
    expect(splitDomainPatternPort('::1')).toEqual({
      hostPattern: '::1',
      port: undefined,
    })
    // Not an address at all: left whole for validation to reject.
    expect(splitDomainPatternPort('example.com:80:443')).toEqual({
      hostPattern: 'example.com:80:443',
      port: undefined,
    })
  })

  test('malformed bracket forms are left whole', () => {
    for (const s of ['[::1', '[::1]junk', '[::1]:', '[::1]:0', '[::1]:65536']) {
      expect(splitDomainPatternPort(s)).toEqual({
        hostPattern: s,
        port: undefined,
      })
    }
  })
})

describe('matchesDomainPatternWithPort — IPv6 literals', () => {
  // filterNetworkRequest matches against canonicalizeHost(dest): bare,
  // lowercase, compressed. These are the strings the matcher really sees.
  test('bracketed deny entry matches the canonical destination', () => {
    expect(matchesDomainPatternWithPort('::1', 443, '[::1]:443')).toBe(true)
    expect(matchesDomainPatternWithPort('::1', 80, '[::1]:443')).toBe(false)
    expect(matchesDomainPatternWithPort('::1', 80, '[::1]')).toBe(true)
    expect(
      matchesDomainPatternWithPort('fd00:ec2::254', 80, '[fd00:ec2::254]'),
    ).toBe(true)
    expect(
      matchesDomainPatternWithPort(
        '2001:db8::1',
        8443,
        '[2001:DB8:0:0::1]:8443',
      ),
    ).toBe(true)
  })

  test('unbracketed entry still matches its own canonical form on every port (fails closed for deny lists)', () => {
    expect(
      matchesDomainPatternWithPort('fd00:ec2::254', 254, 'fd00:ec2::254'),
    ).toBe(true)
    expect(
      matchesDomainPatternWithPort('fd00:ec2::254', 80, 'fd00:ec2::254'),
    ).toBe(true)
  })
})

describe('matchesDomainPatternWithPort', () => {
  test('entry without port matches any port', () => {
    expect(matchesDomainPatternWithPort('example.com', 22, 'example.com')).toBe(
      true,
    )
    expect(
      matchesDomainPatternWithPort('a.example.com', 65535, '*.example.com'),
    ).toBe(true)
  })

  test('entry with port matches only that port', () => {
    expect(
      matchesDomainPatternWithPort('example.com', 443, 'example.com:443'),
    ).toBe(true)
    expect(
      matchesDomainPatternWithPort('example.com', 80, 'example.com:443'),
    ).toBe(false)
    expect(
      matchesDomainPatternWithPort('a.example.com', 8443, '*.example.com:8443'),
    ).toBe(true)
    expect(
      matchesDomainPatternWithPort('a.example.com', 443, '*.example.com:8443'),
    ).toBe(false)
  })

  test('bare "*" with port (deniedDomains)', () => {
    expect(matchesDomainPatternWithPort('anything.test', 22, '*:22')).toBe(true)
    expect(matchesDomainPatternWithPort('anything.test', 23, '*:22')).toBe(
      false,
    )
  })
})

describe('IP literal and CIDR entries', () => {
  test('CIDR entries match IP-literal destinations by range', () => {
    expect(matchesDomainPattern('10.22.86.5', '10.22.86.0/24')).toBe(true)
    expect(matchesDomainPattern('10.22.86.255', '10.22.86.0/24')).toBe(true)
    expect(matchesDomainPattern('10.22.87.1', '10.22.86.0/24')).toBe(false)
    expect(matchesDomainPattern('10.22.86.5', '10.0.0.0/8')).toBe(true)
    expect(matchesDomainPattern('11.0.0.1', '10.0.0.0/8')).toBe(false)
  })

  test('IPv6 CIDR entries (unbracketed) match IPv6 literals', () => {
    expect(matchesDomainPattern('2001:db8::1', '2001:db8::/32')).toBe(true)
    expect(matchesDomainPattern('2001:db8:ffff::99', '2001:db8::/32')).toBe(
      true,
    )
    expect(matchesDomainPattern('2001:db9::1', '2001:db8::/32')).toBe(false)
    expect(matchesDomainPattern('2001:db8::1', 'fc00::/7')).toBe(false)
    expect(matchesDomainPattern('fc00::1', 'fc00::/7')).toBe(true)
  })

  test('numeric IP spellings canonicalize into the range', () => {
    // 169236173 == 10.22.86.205 (10*2^24 + 22*2^16 + 86*2^8 + 205). A
    // pure decimal / dotted-integer destination is an IP spelling, not a
    // name — it is judged by the address it spells.
    expect(matchesDomainPattern('169236173', '10.22.86.0/24')).toBe(true)
    expect(matchesDomainPattern('127.1', '127.0.0.0/8')).toBe(true)
  })

  test('names never match range entries, even with an address inside them', () => {
    // Anything that is not an IP spelling (strict or pure numeric) is a
    // name: it never matches a range, and is judged by where it
    // resolves, via the resolved-address check.
    expect(matchesDomainPattern('169236173x', '10.22.86.0/24')).toBe(false)
    expect(matchesDomainPattern('x169236173', '10.22.86.0/24')).toBe(false)
    expect(
      matchesDomainPattern('10.22.86.5.example.com', '10.22.86.0/24'),
    ).toBe(false)
  })

  test('CIDR entries never match names, and names never match CIDRs', () => {
    expect(matchesDomainPattern('evil.com', '10.0.0.0/8')).toBe(false)
    expect(matchesDomainPattern('10.22.86.5', 'evil.com')).toBe(false)
    expect(matchesDomainPattern('a.example.com', '*.example.com/24')).toBe(
      false,
    )
  })

  test('port scoping composes with CIDR', () => {
    expect(
      matchesDomainPatternWithPort('10.22.86.5', 8080, '10.22.86.0/24:8080'),
    ).toBe(true)
    expect(
      matchesDomainPatternWithPort('10.22.86.5', 443, '10.22.86.0/24:8080'),
    ).toBe(false)
    // no port suffix: every port
    expect(
      matchesDomainPatternWithPort('10.22.86.5', 443, '10.22.86.0/24'),
    ).toBe(true)
  })

  test('port-scoped IPv6 ranges are written bracketed', () => {
    // Like a bracketed IPv6 literal ([2001:db8::1]:443), an IPv6 range
    // takes its port suffix bracketed: unbracketed, "2001:db8::/32:8080"
    // is indistinguishable from an address spelling and is refused.
    expect(splitDomainPatternPort('[2001:db8::/32]:8080')).toEqual({
      hostPattern: '2001:db8::/32',
      port: 8080,
    })
    expect(isAddressRangeEntry('[2001:db8::/32]:8080')).toBe(true)
    expect(isAddressRangeEntry('2001:db8::/32:8080')).toBe(false)
    expect(
      matchesDomainPatternWithPort('2001:db8::5', 8080, '[2001:db8::/32]:8080'),
    ).toBe(true)
    expect(
      matchesDomainPatternWithPort('2001:db8::5', 443, '[2001:db8::/32]:8080'),
    ).toBe(false)
    expect(
      matchesDomainPatternWithPort(
        '[2001:db8::5]',
        8080,
        '[2001:db8::/32]:8080',
      ),
    ).toBe(true)
    expect(
      matchesDomainPatternWithPort('2001:db9::5', 8080, '[2001:db8::/32]:8080'),
    ).toBe(false)
  })

  test('unparsable "/ entries" match nothing', () => {
    expect(matchesDomainPattern('10.0.0.1', '10.0.0.0/33')).toBe(false)
    expect(matchesDomainPattern('evil.com', 'evil.com/24')).toBe(false)
  })

  test('ipLiteralRules carries IP literals and CIDRs, drops domains', () => {
    const rules = ipLiteralRules([
      '10.22.86.0/24',
      '10.22.86.5',
      'example.com',
      '*.example.com',
      '2001:db8::/32',
      '[2001:db8::1]',
      'localhost',
      '10.22.86.0/24:8080',
      '[2001:db8::/32]:8080',
    ])
    expect(rules).toEqual([
      { range: '10.22.86.0/24', port: undefined },
      { range: '10.22.86.5', port: undefined },
      { range: '2001:db8::/32', port: undefined },
      { range: '2001:db8::1', port: undefined },
      { range: '10.22.86.0/24', port: 8080 },
      { range: '2001:db8::/32', port: 8080 },
    ])
  })
})
