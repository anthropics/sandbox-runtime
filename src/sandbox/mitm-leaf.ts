/**
 * Per-host leaf certificate minter for the in-process TLS-terminating proxy.
 *
 * Given a MitmCA (see mitm-ca.ts), mints a leaf certificate for a specific
 * hostname on first use and caches it for the lifetime of that CA instance.
 * The leaf is signed by the CA and carries SAN=DNS:<host> (or IP:<addr>),
 * so a client that trusts the CA will accept it for that host.
 */

import forge from 'node-forge'
import { isIP } from 'node:net'
import { createSecureContext, type SecureContext } from 'node:tls'
import { logForDebugging } from '../utils/debug.js'
import {
  caSubjectKeyId,
  daysFromNow,
  randomSerial,
  signCertificateNative,
  type MitmCA,
} from './mitm-ca.js'

const { pki } = forge

export type LeafCert = {
  /** Leaf cert PEM followed by the CA cert PEM (full chain). */
  certPem: string
  /** Leaf private key PEM. */
  keyPem: string
}

/**
 * Mint (or return cached) an RSA-2048 leaf cert for `hostname`, signed by `ca`.
 * The cache lives on `ca.leafCerts`.
 */
export function mintLeafCert(ca: MitmCA, hostname: string): LeafCert {
  const cached = cacheGet(ca.leafCerts, hostname)
  if (cached) return cached

  // One key for every leaf of this CA, as mitmproxy does: a new host name
  // then costs a signature, not an RSA key generation that would hold up
  // every other tunnel. The key never leaves this process.
  const keys = (ca.leafKeyPair ??= pki.rsa.generateKeyPair(2048))
  const cert = pki.createCertificate()
  cert.publicKey = keys.publicKey
  cert.serialNumber = randomSerial()
  const notBefore = daysFromNow(-1)
  cert.validity.notBefore = notBefore
  cert.validity.notAfter = clampValidity(ca.cert, notBefore)
  cert.setSubject([{ name: 'commonName', value: hostname }])
  cert.setIssuer(ca.cert.subject.attributes)
  cert.setExtensions([
    { name: 'basicConstraints', cA: false, critical: true },
    {
      name: 'keyUsage',
      critical: true,
      digitalSignature: true,
      keyEncipherment: true,
    },
    { name: 'extKeyUsage', serverAuth: true },
    { name: 'subjectAltName', altNames: [sanFor(hostname)] },
    { name: 'subjectKeyIdentifier' },
    // Python ≥3.13 enables ssl.VERIFY_X509_STRICT by default, which enforces
    // RFC 5280's "AKI MUST be present on non-self-signed certs". curl/Go/Node
    // don't enforce this, but requests/urllib3/httpx/google-auth all reject
    // a leaf without AKI under 3.13. See caSubjectKeyId() in mitm-ca.ts for
    // why we can't just pass the CA's stored SKI value through.
    { name: 'authorityKeyIdentifier', keyIdentifier: caSubjectKeyId(ca.cert) },
    // Schannel (Windows System32 curl, git's default backend, cargo) checks
    // revocation on the LEAF and hard-fails CRYPT_E_NO_REVOCATION_CHECK when
    // there's no CDP to consult. Point it at the empty CRL the proxy serves
    // on 127.0.0.1 (see MitmCA.crlDer / http-proxy.ts) so the check resolves
    // to "not revoked" instead of "unknown". node-forge encodes CDP with the
    // same {altNames} shape as SAN; type 6 = uniformResourceIdentifier.
    // OpenSSL-backed clients don't check CRLs by default, so a leaf minted
    // before the port is bound (crlUrl unset) works everywhere except
    // Schannel-with-revocation.
    ...(ca.crlUrl
      ? [
          {
            name: 'cRLDistributionPoints',
            altNames: [{ type: 6, value: ca.crlUrl }],
          },
        ]
      : []),
  ])
  signCertificateNative(cert, ca.keyPem)

  const leaf: LeafCert = {
    certPem: pki.certificateToPem(cert) + ca.certPem,
    keyPem: pki.privateKeyToPem(keys.privateKey),
  }
  cacheSet(ca.leafCerts, hostname, leaf, ca.cacheLimit ?? LEAF_CACHE_LIMIT)
  logForDebugging(`[mitm-leaf] minted RSA leaf for ${hostname}`)
  return leaf
}

/**
 * Mint-or-cache a Node TLS SecureContext for `hostname`. Intended as the
 * SNICallback target in the terminating proxy. The cache lives on
 * `ca.secureContexts`.
 */
export function secureContextFor(ca: MitmCA, hostname: string): SecureContext {
  const cached = cacheGet(ca.secureContexts, hostname)
  if (cached) return cached
  const { certPem, keyPem } = mintLeafCert(ca, hostname)
  const ctx = createSecureContext({ cert: certPem, key: keyPem })
  cacheSet(ca.secureContexts, hostname, ctx, ca.cacheLimit ?? LEAF_CACHE_LIMIT)
  return ctx
}

function sanFor(hostname: string): {
  type: number
  value?: string
  ip?: string
} {
  // RFC 5280 GeneralName tags: 2 = dNSName, 7 = iPAddress.
  return isIP(hostname) !== 0
    ? { type: 7, ip: hostname }
    : { type: 2, value: hostname }
}

/**
 * Leaf validity capped at min(CA notAfter, notBefore+99d).
 *
 * 99d sits below every TLS cert validity ceiling we care about: the current
 * (2026-03) CA/B baseline of 200d, the next step-down to 100d in 2027-03, the
 * historical 398d public cap, and the macOS ~825d ceiling that trips
 * errSecCertificateIsNotStandardsCompliant on user-installed roots. Leaves are
 * re-minted per session, so we don't need the headroom.
 *
 * Anchored at notBefore — not now — because notBefore is backdated by 1 day,
 * so `now+Nd` would produce an (N+1)-day span and lose a day of margin.
 */
function clampValidity(caCert: forge.pki.Certificate, notBefore: Date): Date {
  const caEnd = caCert.validity.notAfter
  const max = new Date(notBefore)
  max.setDate(max.getDate() + 99)
  return caEnd < max ? new Date(caEnd) : max
}

/**
 * At most this many host names' leaf certs (and secure contexts) are kept
 * per CA, the least recently used going first: each costs an RSA key, and
 * the names come from the clients.
 */
const LEAF_CACHE_LIMIT = 256

function cacheGet<V>(cache: Map<string, V>, key: string): V | undefined {
  const value = cache.get(key)
  if (value !== undefined) {
    cache.delete(key)
    cache.set(key, value)
  }
  return value
}

function cacheSet<V>(
  cache: Map<string, V>,
  key: string,
  value: V,
  limit: number,
): void {
  cache.set(key, value)
  for (const oldest of cache.keys()) {
    if (cache.size <= limit) break
    cache.delete(oldest)
  }
}
