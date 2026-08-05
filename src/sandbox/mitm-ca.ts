/**
 * MITM CA loader/generator for the in-process TLS-terminating proxy.
 *
 * The CA is supplied via `network.tlsTerminate.{caCertPath,caKeyPath}` (see
 * sandbox-config.ts). If both paths are omitted, SRT generates an ephemeral
 * RSA-2048 self-signed CA into a temp directory; the cert path is what the
 * trust env vars point at. The caller is responsible for cleaning up via
 * `disposeMitmCA()` (SandboxManager.reset() does this).
 */

import forge from 'node-forge'
import { sign as cryptoSign, X509Certificate } from 'node:crypto'
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { rootCertificates, type SecureContext } from 'node:tls'
import { logForDebugging } from '../utils/debug.js'
import type { LeafCert } from './mitm-leaf.js'

const { asn1, pki, md, random, util } = forge

// node-forge exports pki.getTBSCertificate at runtime; @types/node-forge omits it.
const getTBSCertificate = (
  pki as unknown as {
    getTBSCertificate: (c: forge.pki.Certificate) => forge.asn1.Asn1
  }
).getTBSCertificate

/**
 * Matches one PEM CERTIFICATE block. Used to extract just the certificates
 * out of files listed in tlsTerminate.extraCaCertPaths before they are
 * copied into the (world-readable) trust bundle.
 */
const PEM_CERT_BLOCK =
  /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g

export type MitmCA = {
  certPath: string
  keyPath: string
  /**
   * PEM bundle the sandboxed child's trust env vars point at: this CA
   * followed by the host's regular roots (Node's bundled Mozilla store plus
   * the parent's NODE_EXTRA_CA_CERTS, if any) and any configured
   * tlsTerminate.extraCaCertPaths. Most of the per-tool vars
   * (SSL_CERT_FILE, CURL_CA_BUNDLE, REQUESTS_CA_BUNDLE, ...) REPLACE the
   * tool's trust store rather than extend it, so pointing them at the CA
   * alone would leave the child unable to verify any real certificate —
   * which matters for connections SRT does not terminate
   * (tlsTerminate.excludeDomains). Always lives in an SRT-owned temp dir.
   */
  trustBundlePath: string
  certPem: string
  keyPem: string
  /** Parsed CA certificate (issuer for minted leaf certs). */
  cert: forge.pki.Certificate
  /** Parsed CA private key. RSA only. */
  key: forge.pki.rsa.PrivateKey
  /** Per-hostname cache of leaf certs minted against this CA. */
  leafCerts: Map<string, LeafCert>
  /** Per-hostname cache of TLS SecureContexts wrapping the leaf certs. */
  secureContexts: Map<string, SecureContext>
  /**
   * DER-encoded empty CRL signed by this CA. Schannel (Windows System32
   * curl, git's default backend, cargo) checks revocation on every leaf and
   * hard-fails when a CRL Distribution Point can't be reached — see
   * `crlUrl`. Serving this at that URL turns "revocation unknown" into
   * "checked; not revoked" without a per-tool `--ssl-no-revoke` /
   * `schannelCheckRevoke=false` / `CARGO_HTTP_CHECK_REVOKE=false`.
   */
  crlDer: Buffer
  /**
   * URL every minted leaf's `cRLDistributionPoints` extension points at
   * (`http://127.0.0.1:<proxyPort>/srt.crl`). Set by sandbox-manager on
   * Windows once the local mux port is bound; the proxy answers a plain
   * GET on that path with `crlDer`. Left unset on Linux/macOS (child sees
   * the proxy at a different port under bwrap --unshare-net, so a
   * host-namespace URL would be unreachable) and when the HTTP proxy is
   * external — in both cases leaves carry no CDP, i.e. pre-CRL behaviour.
   */
  crlUrl?: string
  /**
   * True when SRT generated this CA into a temp directory. disposeMitmCA()
   * removes that directory; user-supplied CAs are left alone.
   */
  ephemeral: boolean
}

/** Origin-form path the HTTP proxy answers with `crlDer`. */
export const CRL_PATH = '/srt.crl'

/**
 * Return the CA's Subject Key Identifier as raw bytes for use as an
 * authorityKeyIdentifier.keyIdentifier (leaf certs and the CRL both need it).
 *
 * node-forge stores a cert's subjectKeyIdentifier extension value as a *hex
 * string* (both for in-memory certs and certs parsed from PEM), but expects
 * AKI's keyIdentifier as *raw bytes* — passing the hex through verbatim
 * encodes the ASCII hex chars as the key id and the chain fails to verify.
 * If the CA has no SKI extension (e.g. a v1 user-supplied CA), derive the
 * RFC 5280 method-1 value from its public key.
 */
export function caSubjectKeyId(caCert: forge.pki.Certificate): string {
  const ext = caCert.getExtension('subjectKeyIdentifier') as
    | { subjectKeyIdentifier?: string }
    | undefined
  return ext?.subjectKeyIdentifier
    ? util.hexToBytes(ext.subjectKeyIdentifier)
    : caCert.generateSubjectKeyIdentifier().getBytes()
}

/**
 * Drop-in replacement for `cert.sign(key, md.sha256.create())` that computes
 * the RSASSA-PKCS1-v1_5 / SHA-256 signature via Node's native `crypto.sign()`
 * instead of node-forge's pure-JS RSA.
 *
 * node-forge routes RSA *keypair generation* to native `crypto` when available,
 * but its `PrivateKey.sign()` is always pure JS: jsbn `BigInteger.modPow`
 * (~3000 Montgomery squarings for a 2048-bit modulus). On a JIT engine that's
 * ~50–70 ms per signature; on an interpreter or baseline-only tier it can be
 * an order of magnitude worse — and `generateEphemeralCA()` runs on the cold
 * path of every process that constructs a SandboxManager. Native
 * `crypto.sign()` is ~1–2 ms and, because RSASSA-PKCS1-v1_5 is deterministic,
 * produces byte-identical output. See test/sandbox/mitm-ca.test.ts for the
 * byte-for-byte equivalence check.
 */
export function signCertificateNative(
  cert: forge.pki.Certificate,
  keyPem: string,
): void {
  const oid = pki.oids.sha256WithRSAEncryption
  cert.siginfo.algorithmOid = oid
  cert.signatureOid = oid
  cert.tbsCertificate = getTBSCertificate(cert)
  const tbsDer = asn1.toDer(cert.tbsCertificate).getBytes()
  cert.signature = rsaSha256SignNative(tbsDer, keyPem)
  // Match cert.sign()'s side effect so callers that read cert.md see the same
  // populated digest a forge-signed cert would carry.
  cert.md = md.sha256.create()
  cert.md.update(tbsDer)
}

/**
 * RSASSA-PKCS1-v1_5 / SHA-256 sign of a forge binary-string `der` with the
 * PEM-encoded RSA private key `keyPem`, returning the signature as a forge
 * binary string. Native equivalent of `forgeKey.sign(sha256Digest)`.
 */
export function rsaSha256SignNative(der: string, keyPem: string): string {
  return cryptoSign('sha256', Buffer.from(der, 'binary'), keyPem).toString(
    'binary',
  )
}

/**
 * Create a MitmCA. If `caCertPath`/`caKeyPath` are provided, load from disk
 * (throws if either file is missing, unreadable, not PEM, fails to parse, or
 * the key is not RSA). If both are omitted, generate an ephemeral CA into a
 * fresh temp directory.
 *
 * Pure factory: no module-level state. The caller (SandboxManager) owns the
 * returned object and its lifetime.
 */
export function createMitmCA(opts: {
  caCertPath?: string
  caKeyPath?: string
  /**
   * PEM strings for the CA — used when the caller has already read /
   * generated them (e.g. the Windows persistent-CA path). When set,
   * `caCertPath`/`caKeyPath` are recorded on the returned {@link MitmCA}
   * but NOT read from disk.
   */
  caCertPem?: string
  caKeyPem?: string
  /** PEM CA files appended to the trust bundle; unreadable paths skipped. */
  extraCaCertPaths?: string[]
}): MitmCA {
  if (opts.caCertPem && opts.caKeyPem) {
    const v = validateCaPair(opts.caCertPem, opts.caKeyPem)
    if (!v.ok) throw new Error(`tlsTerminate: CA PEM pair: ${v.reason}`)
    return buildMitmCA(opts.caCertPem, opts.caKeyPem, v.cert, v.key, {
      certPath: opts.caCertPath ?? '',
      keyPath: opts.caKeyPath ?? '',
      extraCaCertPaths: opts.extraCaCertPaths,
    })
  }
  if (opts.caCertPath && opts.caKeyPath) {
    return loadCA(opts.caCertPath, opts.caKeyPath, opts.extraCaCertPaths)
  }
  if (opts.caCertPath || opts.caKeyPath) {
    throw new Error(
      'tlsTerminate: caCertPath and caKeyPath must be provided together',
    )
  }
  return generateEphemeralCA(opts.extraCaCertPaths)
}

/**
 * Remove the SRT-owned temp directories for this CA: the trust-bundle dir
 * always, and the cert/key dir too when SRT generated the CA (for an
 * ephemeral CA they are the same directory). User-supplied CA files are
 * left alone.
 */
export async function disposeMitmCA(ca: MitmCA): Promise<void> {
  const dirs = new Set([dirname(ca.trustBundlePath)])
  if (ca.ephemeral) dirs.add(dirname(ca.certPath))
  for (const dir of dirs) {
    try {
      await rm(dir, { recursive: true, force: true })
    } catch (err) {
      logForDebugging(`[mitm-ca] cleanup failed: ${(err as Error).message}`, {
        level: 'warn',
      })
    }
  }
}

/**
 * Write the child-facing trust bundle into `dir` and return its path: the
 * MITM CA first, then the roots the host would normally trust, so HTTPS
 * clients in the sandbox accept proxy-minted leaves AND can still verify the
 * real certificate of any host SRT tunnels opaquely instead of terminating
 * (tlsTerminate.excludeDomains). Bundling Node's root store is best-effort
 * compatibility — a tool with its own CA file config is unaffected. Extra
 * roots from tlsTerminate.extraCaCertPaths go last, with the same append
 * semantics as NODE_EXTRA_CA_CERTS.
 */
function writeTrustBundle(
  dir: string,
  caCertPem: string,
  extraCaCertPaths?: string[],
): string {
  const parts = [caCertPem.trim(), ...rootCertificates]
  // Honour extra roots the parent process trusts (e.g. a corporate CA).
  const extra = process.env.NODE_EXTRA_CA_CERTS
  if (extra) {
    try {
      parts.push(readFileSync(extra, 'utf8').trim())
    } catch {
      // Missing/unreadable NODE_EXTRA_CA_CERTS: ignore, same as Node does.
    }
  }
  // Honour site-local roots from config (tlsTerminate.extraCaCertPaths),
  // e.g. an internal mTLS CA presented by excluded/passthrough hosts. Paths
  // may exist on only some hosts, so a missing file is skipped, not fatal —
  // but log it, or a typo'd path is undiagnosable.
  for (const extraPath of extraCaCertPaths ?? []) {
    let raw: string
    try {
      raw = readFileSync(extraPath, 'utf8')
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code ?? String(err)
      logForDebugging(
        `[mitm-ca] extraCaCertPaths: cannot read ${extraPath} (${code}); ` +
          `skipping`,
        { level: 'warn' },
      )
      continue
    }
    // Append only the CERTIFICATE blocks. The bundle is world-readable
    // (0o644) and handed to the sandboxed child, so anything else the file
    // carries (e.g. the key of a combined cert+key PEM) must not be copied.
    const certs = raw.match(PEM_CERT_BLOCK)
    if (!certs) {
      logForDebugging(
        `[mitm-ca] extraCaCertPaths: ${extraPath} has no PEM CERTIFICATE ` +
          `block; skipping`,
        { level: 'warn' },
      )
      continue
    }
    parts.push(...certs)
  }
  const path = join(dir, 'trust-bundle.crt')
  writeFileSync(path, parts.join('\n') + '\n', { mode: 0o644 })
  return path
}

/**
 * Build a DER-encoded X.509 v2 CRL, signed by `key`, listing zero revoked
 * certificates. `nextUpdate` is the CA's `notAfter` (or now+1d if the CA is
 * already expired) so a single per-session CRL stays fresh for the CA's
 * lifetime.
 *
 * node-forge has no CRL builder, so this hand-assembles the RFC 5280 §5.1
 * `CertificateList` from asn1 primitives — the same approach the library
 * uses internally for certificates. Carries the two extensions RFC 5280
 * §5.2 says conforming issuers MUST include: `authorityKeyIdentifier`
 * (matching the CA's SKI) and `cRLNumber`.
 */
export function generateEmptyCrl(
  cert: forge.pki.Certificate,
  keyPem: string,
): Buffer {
  const SHA256_RSA = pki.oids.sha256WithRSAEncryption
  const sigAlg = () =>
    seq([
      asn1.create(
        C.UNIVERSAL,
        T.OID,
        false,
        asn1.oidToDer(SHA256_RSA).getBytes(),
      ),
      asn1.create(C.UNIVERSAL, T.NULL, false, ''),
    ])

  // extnValue is the DER of the extension's own ASN.1, wrapped in an
  // OCTET STRING at the Extension level.
  const ext = (oid: string, value: forge.asn1.Asn1) =>
    seq([
      asn1.create(C.UNIVERSAL, T.OID, false, asn1.oidToDer(oid).getBytes()),
      asn1.create(
        C.UNIVERSAL,
        T.OCTETSTRING,
        false,
        asn1.toDer(value).getBytes(),
      ),
    ])
  const crlExtensions = asn1.create(C.CONTEXT_SPECIFIC, 0, true, [
    seq([
      // authorityKeyIdentifier ::= SEQUENCE { [0] KeyIdentifier }
      ext(
        pki.oids.authorityKeyIdentifier,
        seq([asn1.create(C.CONTEXT_SPECIFIC, 0, false, caSubjectKeyId(cert))]),
      ),
      // cRLNumber ::= INTEGER — one CRL per CA per session, so a fixed 1.
      ext('2.5.29.20', asn1.create(C.UNIVERSAL, T.INTEGER, false, '\x01')),
    ]),
  ])

  const now = new Date()
  const caEnd = cert.validity.notAfter
  const nextUpdate = caEnd > now ? caEnd : daysFromNow(1)

  const tbsCertList = seq([
    // version v2 == INTEGER 1 (required when crlExtensions is present)
    asn1.create(C.UNIVERSAL, T.INTEGER, false, '\x01'),
    sigAlg(),
    // Issuer Name: RFC 5280 §5.1.2.3 requires this match the CA subject
    // byte-for-byte. node-forge normalises DN attributes on parse (its
    // certificateFromPem re-encodes via distinguishedNameToAsn1 too, so the
    // "original" DER isn't recoverable via the library), which means a
    // user-supplied CA whose subject uses e.g. multi-valued RDNs or a
    // non-canonical string type could produce a differently-encoded issuer
    // here. Schannel matches on AKI keyid (present above) not issuer DN, and
    // the ephemeral CA is generated by the same encoder, so this holds in
    // practice; noted for completeness.
    pki.distinguishedNameToAsn1(cert.subject),
    asn1Time(now),
    asn1Time(nextUpdate),
    // revokedCertificates: OMITTED. RFC 5280: "When there are no revoked
    // certificates, the revoked certificates list MUST be absent."
    crlExtensions,
  ])

  const sig = rsaSha256SignNative(asn1.toDer(tbsCertList).getBytes(), keyPem)

  const crl = seq([
    tbsCertList,
    sigAlg(),
    // BIT STRING: leading 0x00 = zero unused bits.
    asn1.create(C.UNIVERSAL, T.BITSTRING, false, '\x00' + sig),
  ])
  return Buffer.from(asn1.toDer(crl).getBytes(), 'binary')
}

const C = asn1.Class
const T = asn1.Type
function seq(v: forge.asn1.Asn1[]): forge.asn1.Asn1 {
  return asn1.create(C.UNIVERSAL, T.SEQUENCE, true, v)
}
/** UTCTime for years <2050, GeneralizedTime otherwise (RFC 5280 §4.1.2.5). */
function asn1Time(d: Date): forge.asn1.Asn1 {
  return d.getUTCFullYear() < 2050
    ? asn1.create(C.UNIVERSAL, T.UTCTIME, false, asn1.dateToUtcTime(d))
    : asn1.create(
        C.UNIVERSAL,
        T.GENERALIZEDTIME,
        false,
        asn1.dateToGeneralizedTime(d),
      )
}

function loadCA(
  certPath: string,
  keyPath: string,
  extraCaCertPaths?: string[],
): MitmCA {
  const certPem = readPem(certPath, 'CERTIFICATE', 'tlsTerminate.caCertPath')
  const keyPem = readPem(keyPath, 'PRIVATE KEY', 'tlsTerminate.caKeyPath')
  const v = validateCaPair(certPem, keyPem)
  if (!v.ok) {
    throw new Error(`tlsTerminate: CA at ${certPath}: ${v.reason}`)
  }
  logForDebugging(`[mitm-ca] loaded CA from ${certPath}`)
  return buildMitmCA(certPem, keyPem, v.cert, v.key, {
    certPath,
    keyPath,
    extraCaCertPaths,
  })
}

/**
 * Assemble a {@link MitmCA} from an already-parsed cert+key. Shared by
 * `loadCA` (explicit paths), `generateEphemeralCA`, and the Windows
 * persistent-CA path so trust-bundle/CRL/cache setup lives in one place.
 * `certPath`/`keyPath` are recorded verbatim; the trust bundle goes to a
 * fresh mkdtemp so it's always disposable.
 */
function buildMitmCA(
  certPem: string,
  keyPem: string,
  cert: forge.pki.Certificate,
  key: forge.pki.rsa.PrivateKey,
  opts: {
    certPath: string
    keyPath: string
    extraCaCertPaths?: string[]
    ephemeral?: boolean
  },
): MitmCA {
  const bundleDir = mkdtempSync(join(tmpdir(), 'srt-ca-'))
  return {
    certPath: opts.certPath,
    keyPath: opts.keyPath,
    trustBundlePath: writeTrustBundle(
      bundleDir,
      certPem,
      opts.extraCaCertPaths,
    ),
    certPem,
    keyPem,
    cert,
    key,
    leafCerts: new Map(),
    secureContexts: new Map(),
    crlDer: generateEmptyCrl(cert, keyPem),
    ephemeral: opts.ephemeral ?? false,
  }
}

/** Result of {@link generateCa}. PEMs plus the parsed forge objects. */
export type GeneratedCa = {
  certPem: string
  keyPem: string
  /** Parsed certificate — same object the PEM encodes. */
  cert: forge.pki.Certificate
  /** Parsed RSA private key — same object the PEM encodes. */
  key: forge.pki.rsa.PrivateKey
}

/**
 * Generate a self-signed RSA-2048 CA certificate + private key as PEM
 * strings. Pure — no filesystem side effects; the caller decides where (and
 * whether) to persist. This is the primitive under both the ephemeral
 * per-process CA and the Windows persistent CA
 * (`ensurePersistentWindowsCa`).
 *
 * @param opts.cn subject/issuer commonName. Default
 *   `'sandbox-runtime ephemeral CA'`.
 * @param opts.validityDays certificate `notAfter` in days from now.
 *   Default 825 (the CA/B Forum limit for publicly-trusted leaves; not
 *   binding on a private CA, but a reasonable rotation horizon).
 */
export function generateCa(
  opts: { cn?: string; validityDays?: number } = {},
): GeneratedCa {
  const keys = pki.rsa.generateKeyPair(2048)
  const cert = pki.createCertificate()
  cert.publicKey = keys.publicKey
  cert.serialNumber = randomSerial()
  cert.validity.notBefore = daysFromNow(-1)
  cert.validity.notAfter = daysFromNow(opts.validityDays ?? 825)
  const subject = [
    { name: 'commonName', value: opts.cn ?? 'sandbox-runtime ephemeral CA' },
    { name: 'organizationName', value: 'sandbox-runtime' },
  ]
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
  const keyPem = pki.privateKeyToPem(keys.privateKey)
  signCertificateNative(cert, keyPem)
  return {
    certPem: pki.certificateToPem(cert),
    keyPem,
    cert,
    key: keys.privateKey,
  }
}

/**
 * SHA-1 thumbprint of `certPem` as uppercase hex with no separators —
 * the format `srt-win user status` reports (`ca_cert_thumb`) and
 * PowerShell's `Cert:\…\Thumbprint` uses. Throws if `certPem` is not a
 * parseable X.509 certificate.
 */
export function certThumbprint(certPem: string): string {
  return new X509Certificate(certPem).fingerprint
    .replace(/:/g, '')
    .toUpperCase()
}

/** Result of {@link validateCaPair}. */
export type CaPairValidation =
  | {
      ok: true
      thumbprint: string
      notAfter: Date
      /** Parsed certificate — reuse instead of re-parsing `certPem`. */
      cert: forge.pki.Certificate
      /** Parsed RSA private key — reuse instead of re-parsing `keyPem`. */
      key: forge.pki.rsa.PrivateKey
    }
  | { ok: false; reason: string }

/**
 * Check that `certPem` + `keyPem` are a usable RSA CA pair: both parse, the
 * key is RSA (node-forge signs with nothing else), the private key's
 * modulus matches the certificate's public key (i.e. this key actually
 * signs for this cert), and `notBefore` is not in the future — a CA
 * minted while the system clock was ahead and later NTP-corrected would
 * otherwise be permanently not-yet-valid with nothing to trigger a
 * regenerate. Returns the cert's thumbprint and `notAfter` on success so
 * a caller can decide expiry policy without a second parse.
 *
 * Does not throw — a persistence layer that finds an unreadable/mismatched
 * pair on disk treats `{ok: false}` as "regenerate", not a hard error.
 */
export function validateCaPair(
  certPem: string,
  keyPem: string,
): CaPairValidation {
  let cert: forge.pki.Certificate
  let key: forge.pki.PrivateKey
  try {
    cert = pki.certificateFromPem(certPem)
    key = pki.privateKeyFromPem(keyPem)
  } catch (err) {
    return { ok: false, reason: `parse: ${(err as Error).message}` }
  }
  if (!('n' in key) || !('d' in key)) {
    return { ok: false, reason: 'key is not RSA' }
  }
  if (cert.validity.notBefore.getTime() > Date.now()) {
    return {
      ok: false,
      reason: `notBefore ${cert.validity.notBefore.toISOString()} is in the future (clock skew?)`,
    }
  }
  const pub = cert.publicKey as forge.pki.rsa.PublicKey
  if (!('n' in pub) || pub.n.compareTo((key as forge.pki.rsa.PrivateKey).n)) {
    return { ok: false, reason: 'key does not match certificate public key' }
  }
  let thumbprint: string
  try {
    thumbprint = certThumbprint(certPem)
  } catch (err) {
    return { ok: false, reason: `thumbprint: ${(err as Error).message}` }
  }
  return {
    ok: true,
    thumbprint,
    notAfter: cert.validity.notAfter,
    cert,
    key: key as forge.pki.rsa.PrivateKey,
  }
}

function generateEphemeralCA(extraCaCertPaths?: string[]): MitmCA {
  const { certPem, keyPem, cert, key } = generateCa()
  // Write to disk so trust env vars (NODE_EXTRA_CA_CERTS etc.) can point at
  // a real path. mkdtemp gives us an unguessable per-process directory.
  const dir = mkdtempSync(join(tmpdir(), 'srt-ca-'))
  const certPath = join(dir, 'ca.crt')
  const keyPath = join(dir, 'ca.key')
  writeFileSync(certPath, certPem, { mode: 0o644 })
  writeFileSync(keyPath, keyPem, { mode: 0o600 })
  logForDebugging(`[mitm-ca] generated ephemeral CA at ${certPath}`)
  return buildMitmCA(certPem, keyPem, cert, key, {
    certPath,
    keyPath,
    extraCaCertPaths,
    ephemeral: true,
  })
}

function readPem(path: string, label: string, field: string): string {
  let pem: string
  try {
    pem = readFileSync(path, 'utf8')
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code ?? String(err)
    throw new Error(`${field}: cannot read ${path} (${code})`)
  }
  // Accept either the exact label or a prefixed variant (e.g. "RSA PRIVATE KEY",
  // "EC PRIVATE KEY") for the key case.
  if (!new RegExp(`-----BEGIN [A-Z ]*${label}-----`).test(pem)) {
    throw new Error(`${field}: ${path} is not a PEM ${label}`)
  }
  return pem
}

export function randomSerial(): string {
  // 16 random bytes, high bit cleared so the DER INTEGER stays positive.
  const bytes = random.getBytesSync(16)
  const hex = util.bytesToHex(bytes)
  const firstNibble = parseInt(hex[0]!, 16) & 0x7
  return firstNibble.toString(16) + hex.slice(1)
}

export function daysFromNow(days: number): Date {
  const d = new Date()
  d.setDate(d.getDate() + days)
  return d
}
