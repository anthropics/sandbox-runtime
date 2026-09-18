import { describe, test, expect, beforeAll, afterAll } from 'bun:test'
import { createServer as createHttpsServer } from 'node:https'
import type { Server, AddressInfo } from 'node:net'
import type { TLSSocket } from 'node:tls'
import { spawn } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import forge from 'node-forge'
import { createHttpProxyServer } from '../../src/sandbox/http-proxy.js'
import { createMitmCA, disposeMitmCA } from '../../src/sandbox/mitm-ca.js'
import { mintLeafCert } from '../../src/sandbox/mitm-leaf.js'

// Committed test-only CA — see test/fixtures/tls-terminate/README.md.
const FIXTURE_DIR = join(import.meta.dir, '..', 'fixtures', 'tls-terminate')
const CA_CERT = join(FIXTURE_DIR, 'ca.crt')
const CA_KEY = join(FIXTURE_DIR, 'ca.key')
const CA_PEM = readFileSync(CA_CERT, 'utf8')

// Drive the proxy with curl so we exercise a real CONNECT-through-proxy
// client. (Bun's https.request ignores createConnection, so an in-process
// client would bypass the proxy.)
describe('tls-terminate-proxy: end-to-end through createHttpProxyServer', () => {
  const ca = createMitmCA({ caCertPath: CA_CERT, caKeyPath: CA_KEY })

  // Upstream HTTPS server. Uses a leaf cert for 127.0.0.1 signed by the
  // fixture CA; the proxy's outbound https.request trusts it via
  // tlsTerminateUpstreamCA. Leaf-only — Bun's TLS client mis-verifies when
  // the root CA is appended to the server chain.
  let upstream: Server
  let upstreamPort: number
  let proxy: Server
  let proxyPort: number

  beforeAll(async () => {
    const upCert = mintLeafCert(ca, '127.0.0.1')
    const upLeafOnly = upCert.certPem.match(
      /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\r?\n?/,
    )![0]
    upstream = createHttpsServer(
      { cert: upLeafOnly, key: upCert.keyPem },
      (req, res) => {
        if (req.url === '/non-latin1-header') {
          req.socket.write(
            'HTTP/1.1 200 OK\r\n' +
              'Content-Type: application/octet-stream\r\n' +
              'Content-Disposition: attachment; filename="\u4e2d\u6587\u540d.pdf"\r\n' +
              'Content-Length: 6\r\n' +
              'Connection: close\r\n\r\n' +
              'binary',
          )
          return
        }
        let body = ''
        req.on('data', c => (body += c))
        req.on('end', () => {
          res.writeHead(200, {
            'content-type': 'application/json',
            'x-upstream': 'ok',
          })
          res.end(
            JSON.stringify({
              echoed: body,
              path: req.url,
              method: req.method,
              host: req.headers.host,
            }),
          )
        })
      },
    )
    await new Promise<void>(r => upstream.listen(0, '127.0.0.1', r))
    upstreamPort = (upstream.address() as AddressInfo).port

    proxy = createHttpProxyServer({
      filter: () => true,
      mitmCA: ca,
      tlsTerminateUpstreamCA: CA_PEM,
    })
    await new Promise<void>(r => proxy.listen(0, '127.0.0.1', () => r()))
    proxyPort = (proxy.address() as AddressInfo).port
  })

  afterAll(async () => {
    await new Promise<void>(r => proxy.close(() => r()))
    await new Promise<void>(r => upstream.close(() => r()))
  })

  test('terminates client TLS, forwards request, pipes response back', async () => {
    const r = await curlViaProxy(
      proxyPort,
      `https://127.0.0.1:${upstreamPort}/hello?a=1`,
      {
        method: 'POST',
        body: 'hi-from-client',
      },
    )
    expect(r.exit).toBe(0)
    expect(r.status).toBe(200)
    expect(r.headers['x-upstream']).toBe('ok')
    const parsed = JSON.parse(r.body)
    expect(parsed.echoed).toBe('hi-from-client')
    expect(parsed.path).toBe('/hello?a=1')
    expect(parsed.method).toBe('POST')
    expect(parsed.host).toBe(`127.0.0.1:${upstreamPort}`)
    // The client saw a leaf cert issued by our fixture CA — proves termination
    // happened (curl verified the chain via --cacert).
    expect(r.stderr).toMatch(/issuer:.*srt-test-ca/)
  })

  test('GET works (no body)', async () => {
    const r = await curlViaProxy(
      proxyPort,
      `https://127.0.0.1:${upstreamPort}/ping`,
    )
    expect(r.exit).toBe(0)
    expect(r.status).toBe(200)
    expect(JSON.parse(r.body).path).toBe('/ping')
  })

  test('survives and sanitizes non-Latin1 response headers (#490)', async () => {
    const r = await curlViaProxy(
      proxyPort,
      `https://127.0.0.1:${upstreamPort}/non-latin1-header`,
    )
    expect(r.exit).toBe(0)
    expect(r.status).toBe(200)
    expect(r.body).toBe('binary')
    expect(r.headers['content-disposition']).toBeDefined()
  })

  test('serves the empty CRL at GET /srt.crl (Schannel revocation)', async () => {
    // CryptoAPI fetches the leaf's cRLDistributionPoints URL as an
    // origin-form GET over plain HTTP with no Proxy-Authorization, so this
    // route sits before both the auth check and the absolute-URI parse.
    // eslint-disable-next-line eslint-plugin-n/no-unsupported-features/node-builtins -- bun:test runtime has stable fetch
    const res = await fetch(`http://127.0.0.1:${proxyPort}/srt.crl`)
    expect(res.status).toBe(200)
    expect(res.headers.get('content-type')).toBe('application/pkix-crl')
    const body = Buffer.from(await res.arrayBuffer())
    expect(body.equals(ca.crlDer)).toBe(true)
  })

  test('absolute-form request-target is normalized (filterRequest + upstream)', async () => {
    // RFC 7230 §5.3.2 absolute-form. Some clients send this inside CONNECT
    // tunnels; without normalization the host concat produced a malformed
    // hostname like `example.comhttps`.
    const seen: string[] = []
    const p = createHttpProxyServer({
      filter: () => true,
      filterRequest: async r => {
        seen.push(r.url)
        return { action: 'allow' }
      },
      mitmCA: ca,
      tlsTerminateUpstreamCA: CA_PEM,
    })
    await new Promise<void>(r => p.listen(0, '127.0.0.1', () => r()))
    const port = (p.address() as AddressInfo).port
    try {
      const r = await curlViaProxy(
        port,
        `https://127.0.0.1:${upstreamPort}/abs?x=1`,
        { requestTarget: `https://127.0.0.1:${upstreamPort}/abs?x=1` },
      )
      expect(r.exit).toBe(0)
      expect(r.status).toBe(200)
      expect(JSON.parse(r.body).path).toBe('/abs?x=1')
      expect(seen).toEqual([`https://127.0.0.1:${upstreamPort}/abs?x=1`])
      expect(new URL(seen[0]!).hostname).toBe('127.0.0.1')
    } finally {
      await new Promise<void>(r => p.close(() => r()))
    }
  })

  test('upstream connect failure → 502 from the terminating proxy', async () => {
    // Proves we are NOT an opaque tunnel: a tunnel would surface a TLS/TCP
    // error to the client (curl exit 35/56); the terminating proxy speaks
    // HTTP and returns 502 over the established TLS session.
    const r = await curlViaProxy(proxyPort, `https://127.0.0.1:1/`)
    expect(r.exit).toBe(0)
    expect(r.status).toBe(502)
  })

  test('domain filter still gates termination (CONNECT 403)', async () => {
    const blocked = createHttpProxyServer({ filter: () => false, mitmCA: ca })
    await new Promise<void>(r => blocked.listen(0, '127.0.0.1', () => r()))
    const port = (blocked.address() as AddressInfo).port
    try {
      const r = await curlViaProxy(port, `https://127.0.0.1:${upstreamPort}/`)
      // curl: 56 = "Failure when receiving data from the peer" / proxy CONNECT refused
      expect(r.exit).not.toBe(0)
      expect(r.stderr).toMatch(/403/)
    } finally {
      await new Promise<void>(r => blocked.close(() => r()))
    }
  })

  test('without mitmCA, CONNECT is still an opaque tunnel (regression)', async () => {
    const tunnelProxy = createHttpProxyServer({ filter: () => true })
    await new Promise<void>(r => tunnelProxy.listen(0, '127.0.0.1', () => r()))
    const port = (tunnelProxy.address() as AddressInfo).port
    try {
      const r = await curlViaProxy(
        port,
        `https://127.0.0.1:${upstreamPort}/tunnel`,
      )
      expect(r.exit).toBe(0)
      expect(r.status).toBe(200)
      expect(JSON.parse(r.body).path).toBe('/tunnel')
    } finally {
      await new Promise<void>(r => tunnelProxy.close(() => r()))
    }
  })
})

// Regression: same end-to-end path with an SRT-generated ephemeral CA
// (createMitmCA({})). #259 introduced ephemeral CAs; the leaf-minting AKI
// extension turned out to encode the SKI as a hex string (rather than raw
// bytes) for forge-created CAs, breaking chain verification — caught only
// when testing against a non-fixture CA.
describe('tls-terminate-proxy: end-to-end with ephemeral CA', () => {
  test('curl trusts the ephemeral-CA-signed leaf and round-trips', async () => {
    const ca = createMitmCA({})
    // Upstream uses the FIXTURE CA (same as the other describe) so the
    // proxy's outbound `ca:` value is identical across the file — Bun's
    // https.request caches the first `ca:` process-wide. The regression
    // under test is the client-facing leaf (ephemeral CA → curl), which is
    // covered by mitmCA below + curl --cacert pointing at the ephemeral CA.
    const fixtureCA = createMitmCA({ caCertPath: CA_CERT, caKeyPath: CA_KEY })
    const upCert = mintLeafCert(fixtureCA, '127.0.0.1')
    const upLeafOnly = upCert.certPem.match(
      /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\r?\n?/,
    )![0]
    const upstream = createHttpsServer(
      { cert: upLeafOnly, key: upCert.keyPem },
      (req, res) => {
        let body = ''
        req.on('data', c => (body += c))
        req.on('end', () => {
          res.writeHead(200, { 'x-upstream': 'ok' })
          res.end(JSON.stringify({ echoed: body, path: req.url }))
        })
      },
    )
    await new Promise<void>(r => upstream.listen(0, '127.0.0.1', r))
    const upstreamPort = (upstream.address() as AddressInfo).port

    const proxy = createHttpProxyServer({
      filter: () => true,
      mitmCA: ca,
      tlsTerminateUpstreamCA: CA_PEM,
    })
    await new Promise<void>(r => proxy.listen(0, '127.0.0.1', () => r()))
    const proxyPort = (proxy.address() as AddressInfo).port

    try {
      const r = await curlViaProxy(
        proxyPort,
        `https://127.0.0.1:${upstreamPort}/hello?a=1`,
        { method: 'POST', body: 'from-ephemeral', cacert: ca.certPath },
      )
      expect(r.exit).toBe(0)
      expect(r.status).toBe(200)
      expect(r.headers['x-upstream']).toBe('ok')
      const parsed = JSON.parse(r.body)
      expect(parsed.echoed).toBe('from-ephemeral')
      expect(parsed.path).toBe('/hello?a=1')
      expect(r.stderr).toMatch(/issuer:.*sandbox-runtime ephemeral CA/)
    } finally {
      await new Promise<void>(r => proxy.close(() => r()))
      await new Promise<void>(r => upstream.close(() => r()))
      await disposeMitmCA(ca)
    }
  })
})

// Per-host termination opt-out (`shouldTerminateTLS`). The scenario it
// exists for is an mTLS upstream: only the in-sandbox client holds the
// client certificate, and it pins the real upstream CA, so the connection
// can only work if the proxy does NOT re-originate it. The upstream here
// requires and verifies a client cert (`rejectUnauthorized: true`) signed
// by the fixture CA, while the proxy MITMs with a *different* (ephemeral)
// CA — the same shape as srt's ephemeral CA vs a real upstream's PKI.
describe('tls-terminate-proxy: per-host termination opt-out (mTLS upstream)', () => {
  // "Real" PKI the upstream + client belong to (fixture CA).
  const realCA = createMitmCA({ caCertPath: CA_CERT, caKeyPath: CA_KEY })
  // The proxy's MITM CA — deliberately a different CA.
  const proxyCA = createMitmCA({})

  let upstream: Server
  let upstreamPort: number
  let tmpDir: string
  let clientCertPath: string
  let clientKeyPath: string

  beforeAll(async () => {
    const upCert = mintLeafCert(realCA, '127.0.0.1')
    const upLeafOnly = upCert.certPem.match(
      /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\r?\n?/,
    )![0]
    upstream = createHttpsServer(
      {
        cert: upLeafOnly,
        key: upCert.keyPem,
        // True mTLS: the handshake fails unless the peer presents a cert
        // chaining to the fixture CA.
        requestCert: true,
        rejectUnauthorized: true,
        ca: CA_PEM,
      },
      (req, res) => {
        // With rejectUnauthorized: true this handler only runs after the
        // client presented a cert that verified against `ca` — reaching it
        // at all is the mTLS proof. Echo the client CN too where the
        // runtime supports it (Bun's server-side TLSSocket has no
        // getPeerCertificate).
        const tlsSocket = req.socket as TLSSocket
        const clientCN =
          typeof tlsSocket.getPeerCertificate === 'function'
            ? tlsSocket.getPeerCertificate()?.subject?.CN
            : undefined
        res.writeHead(200, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ path: req.url, clientCN: clientCN ?? null }))
      },
    )
    await new Promise<void>(r => upstream.listen(0, '127.0.0.1', r))
    upstreamPort = (upstream.address() as AddressInfo).port

    // Client cert for curl. mintLeafCert only sets EKU serverAuth, which
    // OpenSSL rejects for client authentication, so mint one here.
    const client = mintClientCert(realCA, 'srt-test-client')
    tmpDir = mkdtempSync(join(tmpdir(), 'srt-mtls-test-'))
    clientCertPath = join(tmpDir, 'client.crt')
    clientKeyPath = join(tmpDir, 'client.key')
    writeFileSync(clientCertPath, client.certPem)
    writeFileSync(clientKeyPath, client.keyPem)
  })

  afterAll(async () => {
    await new Promise<void>(r => upstream.close(() => r()))
    await disposeMitmCA(proxyCA)
    rmSync(tmpDir, { recursive: true, force: true })
  })

  const url = () => `https://127.0.0.1:${upstreamPort}/mtls`

  test('terminating proxy cannot reach an mTLS upstream (502): it has no client cert to present', async () => {
    const proxy = createHttpProxyServer({
      filter: () => true,
      mitmCA: proxyCA,
      tlsTerminateUpstreamCA: CA_PEM,
    })
    await new Promise<void>(r => proxy.listen(0, '127.0.0.1', () => r()))
    const port = (proxy.address() as AddressInfo).port
    try {
      // The client cooperates as much as possible: it trusts the MITM CA
      // and offers its client cert. Still fails — the cert is presented to
      // the proxy's listener (which never asks for it), not to the
      // upstream, and the proxy's own outbound leg has no client cert.
      const r = await curlViaProxy(port, url(), {
        cacert: proxyCA.certPath,
        clientCertPath,
        clientKeyPath,
      })
      expect(r.status).toBe(502)
    } finally {
      await new Promise<void>(r => proxy.close(() => r()))
    }
  })

  test('a client that pins the real upstream CA rejects the MITM leaf outright', async () => {
    const proxy = createHttpProxyServer({
      filter: () => true,
      mitmCA: proxyCA,
      tlsTerminateUpstreamCA: CA_PEM,
    })
    await new Promise<void>(r => proxy.listen(0, '127.0.0.1', () => r()))
    const port = (proxy.address() as AddressInfo).port
    try {
      // --cacert is the REAL upstream CA, not the MITM CA: the leaf the
      // proxy mints does not chain to it, so the handshake dies inside the
      // CONNECT tunnel (curl 60). This is what cert-pinning clients hit.
      const r = await curlViaProxy(port, url(), {
        clientCertPath,
        clientKeyPath,
      })
      expect(r.exit).not.toBe(0)
      expect(r.stderr).toMatch(/certificate|issuer/i)
    } finally {
      await new Promise<void>(r => proxy.close(() => r()))
    }
  })

  test('shouldTerminateTLS=false: opaque tunnel, client completes mTLS end-to-end', async () => {
    const seen: Array<[string, number]> = []
    const proxy = createHttpProxyServer({
      filter: () => true,
      mitmCA: proxyCA,
      tlsTerminateUpstreamCA: CA_PEM,
      shouldTerminateTLS: (hostname, port) => {
        seen.push([hostname, port])
        return false
      },
    })
    await new Promise<void>(r => proxy.listen(0, '127.0.0.1', () => r()))
    const port = (proxy.address() as AddressInfo).port
    try {
      // Same pinning client, same client cert — now it works: the tunnel is
      // opaque, so curl handshakes with the real upstream, verifies it
      // against the real CA, and presents its client cert to it.
      const r = await curlViaProxy(port, url(), {
        clientCertPath,
        clientKeyPath,
      })
      expect(r.exit).toBe(0)
      expect(r.status).toBe(200)
      const parsed = JSON.parse(r.body)
      expect(parsed.path).toBe('/mtls')
      // Node reports the verified client cert's CN; Bun's server-side
      // TLSSocket has no getPeerCertificate, so it reports null there.
      if (parsed.clientCN !== null) {
        expect(parsed.clientCN).toBe('srt-test-client')
      }
      // The cert curl saw was the upstream's real one, not a MITM leaf.
      expect(r.stderr).toMatch(/issuer:.*srt-test-ca/)
      expect(r.stderr).not.toMatch(/sandbox-runtime ephemeral CA/)
      expect(seen).toContainEqual(['127.0.0.1', upstreamPort])
    } finally {
      await new Promise<void>(r => proxy.close(() => r()))
    }
  })

  test('shouldTerminateTLS=false without a client cert still fails: the upstream really demands mTLS', async () => {
    // Negative control for the test above — proves the 200 there can only
    // come from curl's client cert being presented and verified end-to-end.
    const proxy = createHttpProxyServer({
      filter: () => true,
      mitmCA: proxyCA,
      tlsTerminateUpstreamCA: CA_PEM,
      shouldTerminateTLS: () => false,
    })
    await new Promise<void>(r => proxy.listen(0, '127.0.0.1', () => r()))
    const port = (proxy.address() as AddressInfo).port
    try {
      const r = await curlViaProxy(port, url())
      // The upstream aborts the handshake inside the opaque tunnel, so curl
      // fails at the TLS layer. (`r.status` would still read 200 here — the
      // proxy's own "200 Connection Established" is the only header block —
      // so the exit code is the meaningful assertion.)
      expect(r.exit).not.toBe(0)
      expect(r.body).toBe('')
    } finally {
      await new Promise<void>(r => proxy.close(() => r()))
    }
  })

  test('shouldTerminateTLS=true keeps terminating (explicit default)', async () => {
    const proxy = createHttpProxyServer({
      filter: () => true,
      mitmCA: proxyCA,
      tlsTerminateUpstreamCA: CA_PEM,
      shouldTerminateTLS: () => true,
    })
    await new Promise<void>(r => proxy.listen(0, '127.0.0.1', () => r()))
    const port = (proxy.address() as AddressInfo).port
    try {
      const r = await curlViaProxy(port, url(), {
        cacert: proxyCA.certPath,
        clientCertPath,
        clientKeyPath,
      })
      expect(r.status).toBe(502)
    } finally {
      await new Promise<void>(r => proxy.close(() => r()))
    }
  })
})

describe('tls-terminate-proxy: extraCaCertPaths lets the client verify an excluded host with a site-local root', () => {
  // The "site-local" PKI: the fixture CA plays the role of an internal root
  // (e.g. an internal mTLS CA) that is in no public root store. The
  // upstream's leaf chains to it.
  const realCA = createMitmCA({ caCertPath: CA_CERT, caKeyPath: CA_KEY })

  let upstream: Server
  let upstreamPort: number

  beforeAll(async () => {
    const upCert = mintLeafCert(realCA, '127.0.0.1')
    const upLeafOnly = upCert.certPem.match(
      /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\r?\n?/,
    )![0]
    upstream = createHttpsServer(
      { cert: upLeafOnly, key: upCert.keyPem },
      (_req, res) => {
        res.writeHead(200, { 'content-type': 'text/plain' })
        res.end('site-local ok')
      },
    )
    await new Promise<void>(r => upstream.listen(0, '127.0.0.1', r))
    upstreamPort = (upstream.address() as AddressInfo).port
  })

  afterAll(async () => {
    await new Promise<void>(r => upstream.close(() => r()))
    await disposeMitmCA(realCA)
  })

  const url = () => `https://127.0.0.1:${upstreamPort}/extra-ca`

  // This is the regression the field exists for: SRT points the sandboxed
  // child's trust env vars (GIT_SSL_CAINFO, SSL_CERT_FILE, ...) at the trust
  // bundle, REPLACING the tool's own CA config. For an excluded
  // (passthrough) host the child does its own handshake against the real
  // certificate, so unless the site-local root is *in the bundle* the host
  // can never be verified from inside the sandbox.
  test('without extraCaCertPaths the bundle cannot verify the upstream (negative control)', async () => {
    const mitmCA = createMitmCA({})
    const proxy = createHttpProxyServer({
      filter: () => true,
      mitmCA,
      shouldTerminateTLS: () => false,
    })
    await new Promise<void>(r => proxy.listen(0, '127.0.0.1', () => r()))
    const port = (proxy.address() as AddressInfo).port
    try {
      const r = await curlViaProxy(port, url(), {
        cacert: mitmCA.trustBundlePath,
      })
      expect(r.exit).not.toBe(0)
      expect(r.stderr).toMatch(/certificate|issuer/i)
    } finally {
      await new Promise<void>(r => proxy.close(() => r()))
      await disposeMitmCA(mitmCA)
    }
  })

  test('with extraCaCertPaths the bundle verifies the real upstream through the opaque tunnel', async () => {
    const mitmCA = createMitmCA({ extraCaCertPaths: [CA_CERT] })
    const proxy = createHttpProxyServer({
      filter: () => true,
      mitmCA,
      shouldTerminateTLS: () => false,
    })
    await new Promise<void>(r => proxy.listen(0, '127.0.0.1', () => r()))
    const port = (proxy.address() as AddressInfo).port
    try {
      const r = await curlViaProxy(port, url(), {
        cacert: mitmCA.trustBundlePath,
      })
      expect(r.exit).toBe(0)
      expect(r.status).toBe(200)
      expect(r.body).toBe('site-local ok')
      // curl saw the upstream's REAL certificate, not a MITM leaf.
      expect(r.stderr).toMatch(/issuer:.*srt-test-ca/)
      expect(r.stderr).not.toMatch(/sandbox-runtime ephemeral CA/)
    } finally {
      await new Promise<void>(r => proxy.close(() => r()))
      await disposeMitmCA(mitmCA)
    }
  })

  test('terminated hosts still verify against the same bundle (MITM CA is first)', async () => {
    const mitmCA = createMitmCA({ extraCaCertPaths: [CA_CERT] })
    const proxy = createHttpProxyServer({
      filter: () => true,
      mitmCA,
      tlsTerminateUpstreamCA: CA_PEM,
    })
    await new Promise<void>(r => proxy.listen(0, '127.0.0.1', () => r()))
    const port = (proxy.address() as AddressInfo).port
    try {
      const r = await curlViaProxy(port, url(), {
        cacert: mitmCA.trustBundlePath,
      })
      expect(r.exit).toBe(0)
      expect(r.status).toBe(200)
      // On the terminated path curl saw the proxy-minted leaf.
      expect(r.stderr).toMatch(/sandbox-runtime ephemeral CA/)
    } finally {
      await new Promise<void>(r => proxy.close(() => r()))
      await disposeMitmCA(mitmCA)
    }
  })
})

/**
 * Mint a clientAuth leaf signed by `ca` for the mTLS tests. Test-only:
 * the production minter (mintLeafCert) is for server-side MITM leaves and
 * intentionally only carries EKU serverAuth.
 */
function mintClientCert(
  ca: ReturnType<typeof createMitmCA>,
  cn: string,
): { certPem: string; keyPem: string } {
  const { pki, md, random, util } = forge
  const keys = pki.rsa.generateKeyPair(2048)
  const cert = pki.createCertificate()
  cert.publicKey = keys.publicKey
  // 16 random bytes, high bit cleared so the DER INTEGER stays positive.
  const hex = util.bytesToHex(random.getBytesSync(16))
  cert.serialNumber = (parseInt(hex[0]!, 16) & 0x7).toString(16) + hex.slice(1)
  const notBefore = new Date()
  notBefore.setDate(notBefore.getDate() - 1)
  const notAfter = new Date()
  notAfter.setDate(notAfter.getDate() + 30)
  cert.validity.notBefore = notBefore
  cert.validity.notAfter = notAfter
  cert.setSubject([{ name: 'commonName', value: cn }])
  cert.setIssuer(ca.cert.subject.attributes)
  cert.setExtensions([
    { name: 'basicConstraints', cA: false, critical: true },
    { name: 'keyUsage', critical: true, digitalSignature: true },
    { name: 'extKeyUsage', clientAuth: true },
    { name: 'subjectKeyIdentifier' },
  ])
  cert.sign(ca.key, md.sha256.create())
  return {
    certPem: pki.certificateToPem(cert),
    keyPem: pki.privateKeyToPem(keys.privateKey),
  }
}

type CurlResult = {
  exit: number
  status: number
  headers: Record<string, string>
  body: string
  stderr: string
}

async function curlViaProxy(
  proxyPort: number,
  url: string,
  opts: {
    method?: string
    body?: string
    cacert?: string
    requestTarget?: string
    /** Client certificate + key, for mTLS upstreams. */
    clientCertPath?: string
    clientKeyPath?: string
  } = {},
): Promise<CurlResult> {
  const args = [
    '-sS',
    '-v', // TLS issuer line goes to stderr
    '--proxy',
    `http://127.0.0.1:${proxyPort}`,
    '--cacert',
    opts.cacert ?? CA_CERT,
    '--max-time',
    '10',
    '-D',
    '-', // dump response headers to stdout before body
    '-X',
    opts.method ?? 'GET',
  ]
  if (opts.body !== undefined) args.push('--data-binary', opts.body)
  if (opts.clientCertPath) args.push('--cert', opts.clientCertPath)
  if (opts.clientKeyPath) args.push('--key', opts.clientKeyPath)
  if (opts.requestTarget) args.push('--request-target', opts.requestTarget)
  args.push(url)

  // Async spawn so the in-process proxy/upstream can service the request.
  const child = spawn('curl', args)
  let out = ''
  let stderr = ''
  child.stdout.setEncoding('utf8').on('data', c => (out += c))
  child.stderr.setEncoding('utf8').on('data', c => (stderr += c))
  // Drain both streams to 'end' before reading the exit code — Bun's
  // ChildProcess 'close' can fire before all 'data' events are delivered.
  await Promise.all([
    new Promise<void>(r => child.stdout.once('end', r)),
    new Promise<void>(r => child.stderr.once('end', r)),
  ])
  const exit = await new Promise<number>(resolve =>
    child.on('close', code => resolve(code ?? 1)),
  )

  // -D - prints headers (possibly multiple blocks: CONNECT response, then the
  // real response) followed by body. Take the LAST header block.
  const sep = out.lastIndexOf('\r\n\r\n')
  const headerPart = sep >= 0 ? out.slice(0, sep) : ''
  const body = sep >= 0 ? out.slice(sep + 4) : out
  const blocks = headerPart.split(/\r\n\r\n/)
  const lastHdr = blocks[blocks.length - 1] ?? ''
  const lines = lastHdr.split('\r\n')
  const statusLine = lines.shift() ?? ''
  const m = /HTTP\/[\d.]+ (\d+)/.exec(statusLine)
  const status = m ? Number(m[1]) : 0
  const headers: Record<string, string> = {}
  for (const line of lines) {
    const i = line.indexOf(':')
    if (i > 0)
      headers[line.slice(0, i).toLowerCase()] = line.slice(i + 1).trim()
  }
  return { exit, status, headers, body, stderr }
}
