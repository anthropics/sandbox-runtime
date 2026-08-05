import { describe, test, expect, beforeAll, afterAll } from 'bun:test'
import { spawnSync } from 'node:child_process'
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import forge from 'node-forge'
import {
  certThumbprint,
  createMitmCA,
  disposeMitmCA,
  generateCa,
  signCertificateNative,
  validateCaPair,
} from '../../src/sandbox/mitm-ca.js'
import { mintLeafCert } from '../../src/sandbox/mitm-leaf.js'
import { whichSync } from '../../src/utils/which.js'

// Committed test-only CA — see test/fixtures/tls-terminate/README.md.
const FIXTURE_DIR = join(import.meta.dir, '..', 'fixtures', 'tls-terminate')
const certPath = join(FIXTURE_DIR, 'ca.crt')
const keyPath = join(FIXTURE_DIR, 'ca.key')
const certPem = readFileSync(certPath, 'utf8')
const keyPem = readFileSync(keyPath, 'utf8')

describe('mitm-ca: createMitmCA', () => {
  const scratch = mkdtempSync(join(tmpdir(), 'srt-mitm-ca-'))
  const junkPath = join(scratch, 'junk.txt')
  writeFileSync(junkPath, 'not pem\n')

  afterAll(() => {
    rmSync(scratch, { recursive: true, force: true })
  })

  test('returns parsed cert+key from a real CA', () => {
    const ca = createMitmCA({ caCertPath: certPath, caKeyPath: keyPath })
    expect(ca.certPath).toBe(certPath)
    expect(ca.keyPath).toBe(keyPath)
    expect(ca.certPem).toBe(certPem)
    expect(ca.keyPem).toBe(keyPem)
    expect(ca.certPem).toContain('-----BEGIN CERTIFICATE-----')
    // openssl req -nodes emits PKCS8 ("PRIVATE KEY"); the loader's regex also
    // accepts PKCS1 "RSA PRIVATE KEY" / "EC PRIVATE KEY".
    expect(ca.keyPem).toMatch(/-----BEGIN (RSA |EC )?PRIVATE KEY-----/)
    expect(ca.cert.subject.getField('CN').value).toContain('srt-test-ca')
    expect(ca.key.n).toBeDefined() // RSA modulus present
  })

  test('is a pure factory: each call returns a new instance', () => {
    const a = createMitmCA({ caCertPath: certPath, caKeyPath: keyPath })
    const b = createMitmCA({ caCertPath: certPath, caKeyPath: keyPath })
    expect(b).not.toBe(a)
    expect(b.certPem).toBe(a.certPem)
  })

  test('throws with field+path+code when cert path is missing', () => {
    const missing = join(scratch, 'nope.crt')
    expect(() =>
      createMitmCA({ caCertPath: missing, caKeyPath: keyPath }),
    ).toThrow(/tlsTerminate\.caCertPath: cannot read .*nope\.crt \(ENOENT\)/)
  })

  test('throws with field+path+code when key path is missing', () => {
    const missing = join(scratch, 'nope.key')
    expect(() =>
      createMitmCA({ caCertPath: certPath, caKeyPath: missing }),
    ).toThrow(/tlsTerminate\.caKeyPath: cannot read .*nope\.key \(ENOENT\)/)
  })

  test('throws when cert file is not PEM', () => {
    expect(() =>
      createMitmCA({ caCertPath: junkPath, caKeyPath: keyPath }),
    ).toThrow(/tlsTerminate\.caCertPath: .* is not a PEM CERTIFICATE/)
  })

  test('throws when key file is not PEM', () => {
    expect(() =>
      createMitmCA({ caCertPath: certPath, caKeyPath: junkPath }),
    ).toThrow(/tlsTerminate\.caKeyPath: .* is not a PEM PRIVATE KEY/)
  })

  test('throws when cert and key are swapped', () => {
    expect(() =>
      createMitmCA({ caCertPath: keyPath, caKeyPath: certPath }),
    ).toThrow(/is not a PEM CERTIFICATE/)
  })
})

describe('mitm-ca: ephemeral generation', () => {
  test('createMitmCA({}) generates a CA, writes PEMs to a temp dir', async () => {
    const ca = createMitmCA({})
    try {
      expect(ca.ephemeral).toBe(true)
      expect(ca.certPath).toContain('srt-ca-')
      expect(readFileSync(ca.certPath, 'utf8')).toBe(ca.certPem)
      expect(readFileSync(ca.keyPath, 'utf8')).toBe(ca.keyPem)
      expect(ca.certPem).toContain('-----BEGIN CERTIFICATE-----')
      expect(ca.cert.subject.getField('CN').value).toBe(
        'sandbox-runtime ephemeral CA',
      )
      expect(ca.key.n).toBeDefined()
      // Can mint a leaf against it.
      const leaf = mintLeafCert(ca, 'example.com')
      expect(leaf.certPem).toContain('-----BEGIN CERTIFICATE-----')
    } finally {
      await disposeMitmCA(ca)
    }
  })

  test('disposeMitmCA removes the temp dir for ephemeral, no-ops for user CA', async () => {
    const eph = createMitmCA({})
    const dir = dirname(eph.certPath)
    expect(existsSync(dir)).toBe(true)
    await disposeMitmCA(eph)
    expect(existsSync(dir)).toBe(false)

    const user = createMitmCA({ caCertPath: certPath, caKeyPath: keyPath })
    expect(user.ephemeral).toBe(false)
    await disposeMitmCA(user) // must not delete the fixture
    expect(existsSync(certPath)).toBe(true)
  })

  test('writes a trust bundle: MITM CA first, then the host root store', async () => {
    // The child's trust env vars (SSL_CERT_FILE etc.) REPLACE the tool's
    // root store, so the bundle must contain the system roots too or hosts
    // exempted from termination (tlsTerminate.excludeDomains) could never
    // be verified by the in-sandbox client.
    const ca = createMitmCA({})
    try {
      const bundle = readFileSync(ca.trustBundlePath, 'utf8')
      expect(bundle.startsWith(ca.certPem.trim())).toBe(true)
      const certCount = bundle.match(/-----BEGIN CERTIFICATE-----/g)!.length
      expect(certCount).toBeGreaterThan(1)
    } finally {
      await disposeMitmCA(ca)
    }
  })

  test('disposeMitmCA removes the trust-bundle dir of a user-supplied CA', async () => {
    const user = createMitmCA({ caCertPath: certPath, caKeyPath: keyPath })
    const bundleDir = dirname(user.trustBundlePath)
    expect(bundleDir).not.toBe(dirname(certPath))
    expect(existsSync(user.trustBundlePath)).toBe(true)
    await disposeMitmCA(user)
    expect(existsSync(bundleDir)).toBe(false)
    expect(existsSync(certPath)).toBe(true) // fixture untouched
  })

  test('signCertificateNative is byte-identical to node-forge cert.sign()', async () => {
    // RSASSA-PKCS1-v1_5 is deterministic, so signing the same TBSCertificate
    // with the same key via native crypto and via node-forge's pure-JS RSA
    // must produce the same signature bytes — and therefore the same PEM.
    // This is the equivalence guarantee that lets generateEphemeralCA(),
    // generateEmptyCrl(), and mintLeafCert() use native crypto for the RSA
    // private-key operation without changing what ends up on the wire.
    const ca = createMitmCA({})
    try {
      const { pki, md } = forge
      // Rebuild an unsigned copy of the ephemeral CA's own cert (same
      // subject/issuer/serial/validity/extensions/public key), then sign that
      // one copy with node-forge. `ca.cert` was signed via the native path.
      const ref = pki.createCertificate()
      ref.publicKey = ca.cert.publicKey
      ref.serialNumber = ca.cert.serialNumber
      ref.validity.notBefore = ca.cert.validity.notBefore
      ref.validity.notAfter = ca.cert.validity.notAfter
      ref.setSubject(ca.cert.subject.attributes)
      ref.setIssuer(ca.cert.issuer.attributes)
      ref.setExtensions(ca.cert.extensions)
      ref.sign(ca.key, md.sha256.create())

      expect(Buffer.from(ca.cert.signature, 'binary')).toEqual(
        Buffer.from(ref.signature, 'binary'),
      )
      expect(ca.certPem).toBe(pki.certificateToPem(ref))
      // Re-signing the reference cert via the native path is also identical.
      signCertificateNative(ref, ca.keyPem)
      expect(ca.certPem).toBe(pki.certificateToPem(ref))
      // And node-forge's own verifier accepts the native-signed cert.
      expect(ref.verify(ca.cert)).toBe(true)
    } finally {
      await disposeMitmCA(ca)
    }
  })

  test('throws when only one of caCertPath/caKeyPath is provided', () => {
    expect(() => createMitmCA({ caCertPath: certPath })).toThrow(
      /must be provided together/,
    )
    expect(() => createMitmCA({ caKeyPath: keyPath })).toThrow(
      /must be provided together/,
    )
  })
})

describe('mitm-ca: generateCa + validateCaPair', () => {
  // One shared pair — RSA-2048 keygen dominates the cost.
  const g = generateCa({ cn: 'srt-test-generateCa', validityDays: 7 })

  test('generateCa: cn + validityDays are honoured; pair validates', () => {
    const cert = forge.pki.certificateFromPem(g.certPem)
    expect(cert.subject.getField('CN').value).toBe('srt-test-generateCa')
    // notAfter within [6, 8] days from now (allow for slow CI + DST).
    const days =
      (cert.validity.notAfter.getTime() - Date.now()) / (24 * 60 * 60 * 1000)
    expect(days).toBeGreaterThan(5)
    expect(days).toBeLessThan(9)
    const v = validateCaPair(g.certPem, g.keyPem)
    expect(v.ok).toBe(true)
    if (v.ok) {
      expect(v.notAfter.getTime()).toBe(cert.validity.notAfter.getTime())
      // 40 uppercase-hex chars, no separators — matches srt-win's
      // `CertDer::thumb()` and PowerShell's `Cert:\…\Thumbprint`.
      expect(v.thumbprint).toMatch(/^[0-9A-F]{40}$/)
      expect(v.thumbprint).toBe(certThumbprint(g.certPem))
    }
  })

  test('generateCa: defaults match the ephemeral CA (cn + 825d)', () => {
    // The defaults are also what the ephemeral in-process CA uses, so
    // this row pins that generateEphemeralCA's refactor to call
    // generateCa() didn't change its output shape.
    const d = generateCa()
    const cert = forge.pki.certificateFromPem(d.certPem)
    expect(cert.subject.getField('CN').value).toBe(
      'sandbox-runtime ephemeral CA',
    )
    const days =
      (cert.validity.notAfter.getTime() - Date.now()) / (24 * 60 * 60 * 1000)
    expect(Math.round(days)).toBe(825)
  })

  test('validateCaPair: mismatched key → ok:false', () => {
    // Fixture cert with the freshly-generated key: moduli differ.
    const v = validateCaPair(certPem, g.keyPem)
    expect(v.ok).toBe(false)
    if (!v.ok) expect(v.reason).toMatch(/does not match/)
  })

  test('validateCaPair: unparseable input → ok:false, not throw', () => {
    expect(validateCaPair('not pem', g.keyPem).ok).toBe(false)
    expect(validateCaPair(g.certPem, 'not pem').ok).toBe(false)
  })

  test('validateCaPair: fixture cert+key → ok:true', () => {
    // The committed fixture is a real matching pair.
    const v = validateCaPair(certPem, keyPem)
    expect(v.ok).toBe(true)
  })

  test('validateCaPair: notBefore in the future → ok:false (clock-skew guard)', () => {
    // Re-sign the generated CA with notBefore pushed into the future,
    // as a system-clock-ahead-then-NTP-corrected machine would
    // produce. Without this check the persistent-CA layer would keep
    // reusing a cert schannel/OpenSSL both reject as not-yet-valid.
    const c = forge.pki.certificateFromPem(g.certPem)
    c.validity.notBefore = new Date(Date.now() + 24 * 60 * 60 * 1000)
    signCertificateNative(c, g.keyPem)
    const v = validateCaPair(forge.pki.certificateToPem(c), g.keyPem)
    expect(v.ok).toBe(false)
    if (!v.ok) expect(v.reason).toMatch(/notBefore .* is in the future/)
  })
})

describe('mitm-ca: generateEmptyCrl', () => {
  // The CRL is what the proxy serves at /srt.crl so Schannel's revocation
  // check on MITM-minted leaves resolves to "not revoked" instead of
  // hard-failing CRYPT_E_NO_REVOCATION_CHECK. One ephemeral CA for the
  // whole describe — RSA-2048 keygen is the slow part.
  let ca: ReturnType<typeof createMitmCA>
  beforeAll(() => {
    ca = createMitmCA({})
  })
  afterAll(async () => {
    await disposeMitmCA(ca)
  })

  test('createMitmCA populates crlDer on both load paths', async () => {
    const user = createMitmCA({ caCertPath: certPath, caKeyPath: keyPath })
    try {
      for (const c of [ca, user]) {
        expect(c.crlDer).toBeInstanceOf(Buffer)
        expect(c.crlDer.length).toBeGreaterThan(0)
      }
    } finally {
      await disposeMitmCA(user)
    }
  })

  test('parses as a v2 CRL: issuer==CA subject, no revoked certs, AKI matches CA SKI', () => {
    // node-forge has no CRL parser either, so validate the DER structurally
    // via asn1.fromDer. The `openssl crl` test below is the interop check.
    const { asn1, pki, util } = forge
    const crl = asn1.fromDer(ca.crlDer.toString('binary'))
    // CertificateList ::= SEQUENCE { tbsCertList, signatureAlgorithm, signature }
    const [tbs, , sig] = crl.value as forge.asn1.Asn1[]
    expect(sig.type).toBe(asn1.Type.BITSTRING)
    // TBSCertList ::= SEQUENCE { version, signature, issuer, thisUpdate,
    //   nextUpdate, [revokedCertificates absent], crlExtensions }
    const tbsFields = tbs.value as forge.asn1.Asn1[]
    expect(tbsFields).toHaveLength(6) // absent revokedCertificates
    // issuer Name matches the CA subject byte-for-byte.
    const issuerDer = asn1.toDer(tbsFields[2]).getBytes()
    const caSubjectDer = asn1
      .toDer(pki.distinguishedNameToAsn1(ca.cert.subject))
      .getBytes()
    expect(issuerDer).toBe(caSubjectDer)
    // crlExtensions carries AKI whose keyid = the CA's SKI (raw bytes,
    // not the hex-string node-forge stores — same trap as mitm-leaf).
    const caSki = ca.cert.generateSubjectKeyIdentifier().toHex()
    const extsDer = util.bytesToHex(asn1.toDer(tbsFields[5]).getBytes())
    expect(extsDer).toContain(caSki)
  })

  // Signature verification via openssl — the strongest correctness signal.
  const opensslTest = whichSync('openssl') !== null ? test : test.skip
  opensslTest(
    'openssl crl parses it and verifies the signature against the CA',
    () => {
      // Pipe DER on stdin (no `-in` → stdin) — the CRL is served from
      // memory, not disk.
      const text = spawnSync(
        'openssl',
        ['crl', '-inform', 'DER', '-noout', '-text'],
        { input: ca.crlDer, encoding: 'utf8' },
      )
      expect(text.status).toBe(0)
      expect(text.stdout).toMatch(/Issuer:.*sandbox-runtime ephemeral CA/)
      expect(text.stdout).toContain('No Revoked Certificates')
      expect(text.stdout).toMatch(/CRL Number:\s*\n?\s*1/)
      // -CAfile makes openssl verify the CRL signature against the CA.
      // "verify OK" goes to stderr; a bad signature exits non-zero.
      const verify = spawnSync(
        'openssl',
        ['crl', '-inform', 'DER', '-noout', '-CAfile', ca.certPath],
        { input: ca.crlDer, encoding: 'utf8' },
      )
      expect(verify.status).toBe(0)
      expect(verify.stderr).toMatch(/verify OK/)
    },
  )
})

describe('mitm-ca: extraCaCertPaths', () => {
  // A site-local root (e.g. an internal mTLS CA) that excluded/passthrough
  // hosts present. Reuse the committed fixture CA as a structurally real PEM.
  const scratch = mkdtempSync(join(tmpdir(), 'srt-extra-ca-'))
  const extraRootPath = join(scratch, 'extra-root.pem')
  writeFileSync(extraRootPath, certPem)
  const notACert = join(scratch, 'not-a-cert.pem')
  writeFileSync(
    notACert,
    '-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n',
  )
  // Combined cert+key PEM — a common layout for "the CA file". Only the
  // CERTIFICATE block may reach the (world-readable) trust bundle.
  const combined = join(scratch, 'combined.pem')
  writeFileSync(combined, certPem + keyPem)

  afterAll(() => {
    rmSync(scratch, { recursive: true, force: true })
  })

  test('appends the PEM to the trust bundle (ephemeral CA path)', async () => {
    const ca = createMitmCA({ extraCaCertPaths: [extraRootPath] })
    try {
      const bundle = readFileSync(ca.trustBundlePath, 'utf8')
      // MITM CA still first; the extra root rides along at the end.
      expect(bundle.startsWith(ca.certPem.trim())).toBe(true)
      expect(bundle).toContain(certPem.trim())
    } finally {
      await disposeMitmCA(ca)
    }
  })

  test('appends the PEM on the user-supplied CA path too (loadCA)', async () => {
    const ca = createMitmCA({
      caCertPath: certPath,
      caKeyPath: keyPath,
      extraCaCertPaths: [extraRootPath],
    })
    try {
      const bundle = readFileSync(ca.trustBundlePath, 'utf8')
      // The fixture CA is both the MITM CA and the "extra" root here, so it
      // must appear twice: once as the bundle head, once appended.
      const occurrences = bundle.split(certPem.trim()).length - 1
      expect(occurrences).toBe(2)
    } finally {
      await disposeMitmCA(ca)
    }
  })

  test('skips missing paths without throwing', async () => {
    const ca = createMitmCA({
      extraCaCertPaths: [join(scratch, 'nope.pem'), extraRootPath],
    })
    try {
      const bundle = readFileSync(ca.trustBundlePath, 'utf8')
      // The missing path is skipped; later entries are still appended.
      expect(bundle).toContain(certPem.trim())
    } finally {
      await disposeMitmCA(ca)
    }
  })

  test('skips files with no PEM CERTIFICATE block', async () => {
    const ca = createMitmCA({ extraCaCertPaths: [notACert] })
    try {
      expect(readFileSync(ca.trustBundlePath, 'utf8')).not.toContain(
        'PRIVATE KEY',
      )
    } finally {
      await disposeMitmCA(ca)
    }
  })

  test('copies only the CERTIFICATE blocks of a combined cert+key file', async () => {
    // The trust bundle is world-readable and handed to the sandboxed child:
    // a private key sitting next to the cert must never reach it.
    const ca = createMitmCA({ extraCaCertPaths: [combined] })
    try {
      const bundle = readFileSync(ca.trustBundlePath, 'utf8')
      expect(bundle).toContain(certPem.trim())
      expect(bundle).not.toContain('PRIVATE KEY')
    } finally {
      await disposeMitmCA(ca)
    }
  })
})
