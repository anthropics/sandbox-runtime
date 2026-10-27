import { describe, test, expect, spyOn } from 'bun:test'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { X509Certificate } from 'node:crypto'
import { createSecureContext } from 'node:tls'
import forge from 'node-forge'
import { createMitmCA, disposeMitmCA } from '../../src/sandbox/mitm-ca.js'
import { mintLeafCert, secureContextFor } from '../../src/sandbox/mitm-leaf.js'
import { whichSync } from '../../src/utils/which.js'

// Committed test-only CA — see test/fixtures/tls-terminate/README.md.
const FIXTURE_DIR = join(import.meta.dir, '..', 'fixtures', 'tls-terminate')
const CA_CERT = join(FIXTURE_DIR, 'ca.crt')
const CA_KEY = join(FIXTURE_DIR, 'ca.key')

describe('mitm-leaf: mintLeafCert', () => {
  // One CA per describe — createMitmCA is pure, leaf cache is per-CA.
  const ca = createMitmCA({ caCertPath: CA_CERT, caKeyPath: CA_KEY })

  test('mints a leaf with CN, DNS SAN, and serverAuth EKU', () => {
    const leaf = mintLeafCert(ca, 'example.com')
    // certPem is leaf+CA chain — split off the first PEM block.
    const leafOnly = firstPemBlock(leaf.certPem)
    const x = new X509Certificate(leafOnly)
    expect(x.subject).toContain('CN=example.com')
    expect(x.subjectAltName).toContain('DNS:example.com')
    expect(x.keyUsage).toContain('1.3.6.1.5.5.7.3.1') // serverAuth OID
    expect(x.ca).toBe(false)
    // Issuer matches the fixture CA's subject.
    expect(x.issuer).toContain('CN=srt-test-ca DO NOT TRUST')
  })

  test('carries SKI and an AKI matching the CA SKI', async () => {
    // Python ≥3.13 enables ssl.VERIFY_X509_STRICT by default, which rejects
    // non-self-signed certs that lack authorityKeyIdentifier (RFC 5280
    // §4.2.1.1). Minted leaves must carry both, and the AKI keyid must equal
    // the CA's SKI byte-for-byte — not the hex-string form node-forge stores
    // internally. The `openssl verify -x509_strict` test below is the
    // end-to-end check; this asserts the extensions directly so a regression
    // is obvious even where openssl is unavailable.
    const { pki } = forge
    const ephemeral = createMitmCA({})
    for (const c of [ca, ephemeral]) {
      const leaf = pki.certificateFromPem(
        firstPemBlock(mintLeafCert(c, 'ski.example').certPem),
      )
      expect(leaf.getExtension('subjectKeyIdentifier')).toBeTruthy()
      const aki = leaf.getExtension('authorityKeyIdentifier') as {
        value: string
      }
      expect(aki).toBeTruthy()
      // AKI's DER value is SEQUENCE { [0] keyid }. Hex-encode the whole thing
      // and check the CA's SKI hex appears as a suffix — proves we wrote raw
      // SKI bytes, not their ASCII-hex encoding.
      const caSki = c.cert.generateSubjectKeyIdentifier().toHex()
      expect(forge.util.bytesToHex(aki.value)).toMatch(new RegExp(`${caSki}$`))
    }
    await disposeMitmCA(ephemeral)
  })

  test('carries a cRLDistributionPoints URI when ca.crlUrl is set (Schannel revocation)', async () => {
    // Schannel checks revocation on the LEAF and hard-fails when there's no
    // CDP; the URL points at the empty CRL the proxy serves. Without crlUrl
    // (e.g. minted before the proxy port is bound) the extension is absent —
    // fine for OpenSSL-backed clients, which don't check by default. `ca` is
    // the file-level fixture CA (crlUrl unset).
    const { pki } = forge
    expect(
      pki
        .certificateFromPem(
          firstPemBlock(mintLeafCert(ca, 'cdp.example').certPem),
        )
        .getExtension('cRLDistributionPoints'),
    ).toBeFalsy()

    const withUrl = createMitmCA({ caCertPath: CA_CERT, caKeyPath: CA_KEY })
    withUrl.crlUrl = 'http://127.0.0.1:60080/srt.crl'
    try {
      const leaf = pki.certificateFromPem(
        firstPemBlock(mintLeafCert(withUrl, 'cdp.example').certPem),
      )
      const cdp = leaf.getExtension('cRLDistributionPoints') as {
        value: string
      }
      expect(cdp).toBeTruthy()
      // node-forge stores the DER value as a binary string; the URI is a
      // GeneralName IA5String inside it.
      expect(cdp.value).toContain('http://127.0.0.1:60080/srt.crl')
    } finally {
      await disposeMitmCA(withUrl)
    }
  })

  test('uses an IP SAN for IP-literal hostnames', () => {
    const leaf = mintLeafCert(ca, '127.0.0.1')
    const x = new X509Certificate(firstPemBlock(leaf.certPem))
    expect(x.subjectAltName).toContain('IP Address:127.0.0.1')
  })

  test('Node tls accepts the cert+key as a SecureContext', () => {
    const leaf = mintLeafCert(ca, 'example.com')
    expect(() =>
      createSecureContext({ cert: leaf.certPem, key: leaf.keyPem }),
    ).not.toThrow()
  })

  // Whatever the random source gives. All zeros is the far end of a serial
  // that begins with zero bytes, about one in 65,000.
  for (const [what, byte] of [
    ['zeros', '\x00'],
    ['ones', '\xff'],
  ] as const) {
    test(`a serial drawn as all ${what} gives a certificate that parses`, () => {
      // The leaves' key pair is made first, from the real source.
      mintLeafCert(ca, 'first.serial.example.com')
      const drawn = spyOn(forge.random, 'getBytesSync').mockImplementation(n =>
        byte.repeat(n),
      )
      let leaf
      try {
        leaf = mintLeafCert(ca, `${what}.serial.example.com`)
        expect(drawn).toHaveBeenCalled()
      } finally {
        drawn.mockRestore()
      }
      expect(() =>
        createSecureContext({ cert: leaf.certPem, key: leaf.keyPem }),
      ).not.toThrow()
      const serial = new X509Certificate(leaf.certPem).serialNumber
      expect(serial).toHaveLength(32)
      expect(serial).toMatch(/^[4-7]/)
    })
  }

  test('caches per (CA instance, hostname)', () => {
    const a = secureContextFor(ca, 'cached.example')
    expect(secureContextFor(ca, 'cached.example')).toBe(a)
    expect(secureContextFor(ca, 'other.example')).not.toBe(a)
    // A different CA instance gets its own cache.
    const ca2 = createMitmCA({ caCertPath: CA_CERT, caKeyPath: CA_KEY })
    expect(secureContextFor(ca2, 'cached.example')).not.toBe(a)
  })

  test('mintLeafCert caches per (CA instance, hostname)', () => {
    const a = mintLeafCert(ca, 'mint-cache.example')
    expect(mintLeafCert(ca, 'mint-cache.example')).toBe(a)
    const ca2 = createMitmCA({ caCertPath: CA_CERT, caKeyPath: CA_KEY })
    expect(mintLeafCert(ca2, 'mint-cache.example')).not.toBe(a)
  })

  test('leaf validity span is ≤99 days', () => {
    const leaf = mintLeafCert(ca, 'validity.example')
    const x = new X509Certificate(firstPemBlock(leaf.certPem))
    const days =
      (Date.parse(x.validTo) - Date.parse(x.validFrom)) / (1000 * 60 * 60 * 24)
    // Span must be exactly 99 days: notAfter must be clamped relative to
    // notBefore, not now — otherwise the 1-day backdate of notBefore pushes
    // the span to 100, eating into our margin under the public CA/B cap.
    expect(days).toBeGreaterThan(98)
    expect(days).toBeLessThanOrEqual(99)
  })

  test('leaf notAfter never exceeds a short-lived CA notAfter', () => {
    // CA expires in 10 days. Leaf must clamp to the CA, not to
    // notBefore+99d (which would mint a leaf valid long after its issuer).
    const shortCA = makeShortLivedCA(10)
    try {
      const leaf = mintLeafCert(shortCA, 'short.example')
      const x = new X509Certificate(firstPemBlock(leaf.certPem))
      const leafEnd = Date.parse(x.validTo)
      const caEnd = shortCA.cert.validity.notAfter.getTime()
      expect(leafEnd).toBeLessThanOrEqual(caEnd)
      // Sanity: the leaf actually picked up the CA cap (within a few seconds)
      // rather than the 825-day cap.
      expect(caEnd - leafEnd).toBeLessThan(5_000)
    } finally {
      rmSync(shortCA.certPath.replace(/\/[^/]+$/, ''), {
        recursive: true,
        force: true,
      })
    }
  })

  // Chain verification via openssl — the strongest correctness signal.
  // Skipped only if openssl is unavailable.
  const verifyTest = whichSync('openssl') !== null ? test : test.skip
  verifyTest(
    'leaf verifies against the CA via `openssl verify` (fixture and ephemeral)',
    async () => {
      // Regression: with an ephemeral (forge-generated) CA, node-forge stores
      // the SKI as a hex string, which the leaf's authorityKeyIdentifier was
      // copying verbatim → AKI ≠ SKI → chain verification failed.
      const ephemeral = createMitmCA({})
      const dir = mkdtempSync(join(tmpdir(), 'srt-mitm-leaf-'))
      try {
        for (const c of [ca, ephemeral]) {
          const leaf = mintLeafCert(c, 'verify.example')
          const leafPath = join(dir, 'leaf.crt')
          writeFileSync(leafPath, firstPemBlock(leaf.certPem))
          // -x509_strict mirrors Python 3.13's ssl.VERIFY_X509_STRICT default
          // and rejects leaves missing AKI/SKI.
          const out = execFileSync(
            'openssl',
            ['verify', '-x509_strict', '-CAfile', c.certPath, leafPath],
            { encoding: 'utf8' },
          )
          expect(out.trim()).toMatch(/: OK$/)
        }
      } finally {
        rmSync(dir, { recursive: true, force: true })
        await disposeMitmCA(ephemeral)
      }
    },
  )
})

/**
 * Build an on-disk RSA CA whose notAfter is `days` from now, then load it via
 * createMitmCA. Used to exercise the CA-end branch of clampValidity.
 */
function makeShortLivedCA(days: number) {
  const { pki, md } = forge
  const keys = pki.rsa.generateKeyPair(1024) // small key — test speed
  const cert = pki.createCertificate()
  cert.publicKey = keys.publicKey
  cert.serialNumber = '01'
  const now = new Date()
  cert.validity.notBefore = new Date(now.getTime() - 24 * 60 * 60 * 1000)
  cert.validity.notAfter = new Date(now.getTime() + days * 24 * 60 * 60 * 1000)
  const subject = [{ name: 'commonName', value: 'short-lived test CA' }]
  cert.setSubject(subject)
  cert.setIssuer(subject)
  cert.setExtensions([
    { name: 'basicConstraints', cA: true, critical: true },
    {
      name: 'keyUsage',
      critical: true,
      keyCertSign: true,
      cRLSign: true,
      digitalSignature: true,
    },
    { name: 'subjectKeyIdentifier' },
  ])
  cert.sign(keys.privateKey, md.sha256.create())

  const dir = mkdtempSync(join(tmpdir(), 'srt-short-ca-'))
  const certPath = join(dir, 'ca.crt')
  const keyPath = join(dir, 'ca.key')
  writeFileSync(certPath, pki.certificateToPem(cert))
  writeFileSync(keyPath, pki.privateKeyToPem(keys.privateKey))
  return createMitmCA({ caCertPath: certPath, caKeyPath: keyPath })
}

function firstPemBlock(pem: string): string {
  const m = pem.match(
    /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\r?\n?/,
  )
  if (!m) throw new Error('no PEM CERTIFICATE block found')
  return m[0]
}
