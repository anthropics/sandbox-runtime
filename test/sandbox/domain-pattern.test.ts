import { describe, test, expect } from 'bun:test'
import {
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
