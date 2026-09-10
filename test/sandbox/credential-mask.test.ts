import { describe, test, expect, beforeAll, afterAll, spyOn } from 'bun:test'
import {
  createServer as createHttpServer,
  type IncomingHttpHeaders,
} from 'node:http'
import { createServer as createHttpsServer } from 'node:https'
import type { Server, AddressInfo } from 'node:net'
import { spawn, spawnSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import {
  SentinelRegistry,
  SENTINEL_PREFIX,
} from '../../src/sandbox/credential-sentinel.js'
import { createHttpProxyServer } from '../../src/sandbox/http-proxy.js'
import { verifyJwt } from '../../src/sandbox/credential-decode.js'
import { createMitmCA, disposeMitmCA } from '../../src/sandbox/mitm-ca.js'
import { mintLeafCert } from '../../src/sandbox/mitm-leaf.js'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import type { SandboxRuntimeConfig } from '../../src/sandbox/sandbox-config.js'
import { wrapCommandWithSandboxMacOS } from '../../src/sandbox/macos-sandbox-utils.js'
import { isLinux } from '../helpers/platform.js'

// Committed test-only CA — see test/fixtures/tls-terminate/README.md.
const FIXTURE_DIR = join(import.meta.dir, '..', 'fixtures', 'tls-terminate')
const CA_CERT = join(FIXTURE_DIR, 'ca.crt')
const CA_KEY = join(FIXTURE_DIR, 'ca.key')
const CA_PEM = readFileSync(CA_CERT, 'utf8')

const REAL_TOKEN = 'ghp_realsecret_abcdef0123456789'

/** Host matcher for unit tests: exact equality. */
const eq = (h: string, p: string) => h === p
/** Host matcher that always allows — for tests of the substitution itself. */
const any = () => true

describe('SentinelRegistry', () => {
  test('register mints a fake_value_<uuid> sentinel', () => {
    const reg = new SentinelRegistry()
    const s = reg.register('GH_TOKEN', 'hunter2', ['api.github.com'])
    expect(s.startsWith(SENTINEL_PREFIX)).toBe(true)
    // UUID v4 is 36 chars (8-4-4-4-12 with hyphens).
    expect(s.length).toBe(SENTINEL_PREFIX.length + 36)
    expect(reg.lookupReal(s)).toBe('hunter2')
  })

  test('register pads the sentinel to the real value byte length (length-matched)', () => {
    const reg = new SentinelRegistry()
    const real = 'x'.repeat(100)
    const s = reg.register('LONG', real, ['api.github.com'])
    expect(s.startsWith(SENTINEL_PREFIX)).toBe(true)
    expect(Buffer.byteLength(s)).toBe(Buffer.byteLength(real))
    // Padding stays in the sentinel alphabet so the fake still survives
    // shells, JSON, and URLs unquoted.
    expect(s).toMatch(/^[a-z0-9_-]+$/)
    expect(reg.lookupReal(s)).toBe(real)
  })

  test('register never shrinks the sentinel below the base (short real value)', () => {
    const reg = new SentinelRegistry()
    const s = reg.register('SHORT', 'tiny', ['api.github.com'])
    expect(s.length).toBe(SENTINEL_PREFIX.length + 36)
  })

  test('sentinelsForHost returns byte pairs gated per credential', () => {
    const reg = new SentinelRegistry()
    const a = reg.register('A', 'real-a', ['a.example.com'])
    reg.register('B', 'real-b', ['b.example.com'])
    const pairs = reg.sentinelsForHost('a.example.com', eq)
    expect(pairs).toHaveLength(1)
    expect(pairs[0]!.sentinel.toString()).toBe(a)
    expect(pairs[0]!.realValue.toString()).toBe('real-a')
    expect(reg.sentinelsForHost('c.example.com', eq)).toHaveLength(0)
  })

  test('sentinelsForHost reflects a re-registered real value', () => {
    const reg = new SentinelRegistry()
    reg.register('T', 'old-value', ['h.example.com'])
    reg.register('T', 'new-value', ['h.example.com'])
    const pairs = reg.sentinelsForHost('h.example.com', eq)
    expect(pairs).toHaveLength(1)
    expect(pairs[0]!.realValue.toString()).toBe('new-value')
  })

  test('register is idempotent on credential name', () => {
    const reg = new SentinelRegistry()
    const a = reg.register('GH_TOKEN', 'hunter2', ['api.github.com'])
    const b = reg.register('GH_TOKEN', 'hunter2', ['api.github.com'])
    expect(a).toBe(b)
    expect(reg.size).toBe(1)
  })

  test('re-registering a name updates value and hosts but keeps the sentinel', () => {
    const reg = new SentinelRegistry()
    const a = reg.register('T', 'old', ['old.example.com'])
    const b = reg.register('T', 'new', ['new.example.com'])
    expect(b).toBe(a)
    expect(reg.lookupReal(a)).toBe('new')
    const headers: IncomingHttpHeaders = { authorization: a }
    reg.substituteInHeaders(headers, 'new.example.com', eq)
    expect(headers.authorization).toBe('new')
  })

  test('different names get different sentinels even for the same value', () => {
    // Per-credential host gating must apply independently, so two env
    // vars carrying the same secret still need distinct sentinels.
    const reg = new SentinelRegistry()
    const a = reg.register('A', 'same', ['a.example.com'])
    const b = reg.register('B', 'same', ['b.example.com'])
    expect(a).not.toBe(b)
    expect(reg.size).toBe(2)
  })

  test('per-extract file keys (file:<path>#<i>) yield distinct sentinels', () => {
    // Structured file masking registers one sentinel per distinct
    // captured value under a #<i>-suffixed key. The registry must treat
    // these as independent entries so each capture swaps to its own real
    // value at the proxy.
    const reg = new SentinelRegistry()
    const s0 = reg.register('file:/p#0', 'tok-a', ['h.example.com'])
    const s1 = reg.register('file:/p#1', 'tok-b', ['h.example.com'])
    expect(s0).not.toBe(s1)
    expect(reg.lookupReal(s0)).toBe('tok-a')
    expect(reg.lookupReal(s1)).toBe('tok-b')
    expect(reg.size).toBe(2)
  })

  test('clear drops every mapping', () => {
    const reg = new SentinelRegistry()
    const s = reg.register('T', 'x', [])
    reg.clear()
    expect(reg.size).toBe(0)
    expect(reg.lookupReal(s)).toBeUndefined()
  })

  test('substituteInHeaders replaces sentinels in any header value', () => {
    const reg = new SentinelRegistry()
    const s = reg.register('GH_TOKEN', REAL_TOKEN, ['api.github.com'])
    const headers: IncomingHttpHeaders = {
      authorization: `Bearer ${s}`,
      'x-api-key': s,
      'set-cookie': [`token=${s}; Path=/`, 'unrelated=1'],
      'user-agent': 'curl/8',
    }
    reg.substituteInHeaders(headers, 'api.github.com', any)
    expect(headers.authorization).toBe(`Bearer ${REAL_TOKEN}`)
    expect(headers['x-api-key']).toBe(REAL_TOKEN)
    expect(headers['set-cookie']).toEqual([
      `token=${REAL_TOKEN}; Path=/`,
      'unrelated=1',
    ])
    expect(headers['user-agent']).toBe('curl/8')
  })

  test('substituteInHeaders leaves headers without sentinels unchanged', () => {
    const reg = new SentinelRegistry()
    reg.register('GH_TOKEN', REAL_TOKEN, ['api.github.com'])
    const headers: IncomingHttpHeaders = { authorization: 'Bearer plain' }
    reg.substituteInHeaders(headers, 'api.github.com', any)
    expect(headers.authorization).toBe('Bearer plain')
  })

  test("a sentinel only substitutes at its own credential's injectHosts", () => {
    // Anti-laundering: sending GH_TOKEN's sentinel to NPM_TOKEN's host
    // must NOT swap in the GH secret.
    const reg = new SentinelRegistry()
    const gh = reg.register('GH_TOKEN', 'gh-secret', ['api.github.com'])
    const npm = reg.register('NPM_TOKEN', 'npm-secret', ['registry.npmjs.org'])

    const toNpm: IncomingHttpHeaders = { authorization: `Bearer ${gh}` }
    reg.substituteInHeaders(toNpm, 'registry.npmjs.org', eq)
    expect(toNpm.authorization).toBe(`Bearer ${gh}`)

    const toGh: IncomingHttpHeaders = { authorization: `Bearer ${npm}` }
    reg.substituteInHeaders(toGh, 'api.github.com', eq)
    expect(toGh.authorization).toBe(`Bearer ${npm}`)

    // Each credential does swap at its own host.
    const ghOwn: IncomingHttpHeaders = { authorization: `Bearer ${gh}` }
    reg.substituteInHeaders(ghOwn, 'api.github.com', eq)
    expect(ghOwn.authorization).toBe('Bearer gh-secret')

    const npmOwn: IncomingHttpHeaders = { authorization: `Bearer ${npm}` }
    reg.substituteInHeaders(npmOwn, 'registry.npmjs.org', eq)
    expect(npmOwn.authorization).toBe('Bearer npm-secret')
  })

  test('mixed sentinels in one request: only the host-matched one swaps', () => {
    const reg = new SentinelRegistry()
    const gh = reg.register('GH_TOKEN', 'gh-secret', ['api.github.com'])
    const npm = reg.register('NPM_TOKEN', 'npm-secret', ['registry.npmjs.org'])
    const headers: IncomingHttpHeaders = {
      authorization: `Bearer ${gh}`,
      'x-npm-token': npm,
    }
    reg.substituteInHeaders(headers, 'api.github.com', eq)
    expect(headers.authorization).toBe('Bearer gh-secret')
    expect(headers['x-npm-token']).toBe(npm)
  })
})

describe('macOS env preamble for masked credentials', () => {
  test('emits NAME=<sentinel> assignment and not the real value', () => {
    const wrapped = wrapCommandWithSandboxMacOS({
      command: 'true',
      needsNetworkRestriction: false,
      readConfig: undefined,
      writeConfig: { allowOnly: ['/tmp'], denyWithinAllow: [] },
      setEnvVars: { GH_TOKEN: 'fake_value_test-sentinel' },
    })
    expect(wrapped).toContain('GH_TOKEN=fake_value_test-sentinel')
    expect(wrapped.indexOf('GH_TOKEN')).toBeLessThan(
      wrapped.indexOf('sandbox-exec'),
    )
  })

  test('still sandboxes when masked env vars are the only restriction', () => {
    const wrapped = wrapCommandWithSandboxMacOS({
      command: 'echo hi',
      needsNetworkRestriction: false,
      readConfig: undefined,
      writeConfig: undefined,
      setEnvVars: { GH_TOKEN: 'fake_value_x' },
    })
    expect(wrapped).not.toBe('echo hi')
    expect(wrapped).toContain('GH_TOKEN=fake_value_x')
  })
})

/**
 * Proxy-level header injection: drive `createHttpProxyServer` directly
 * with a hand-built mutateHeaders, the same way SandboxManager wires it.
 * Reuses the tls-terminate-proxy.test.ts fixture pattern.
 */
describe('header injection through the TLS-terminating proxy', () => {
  const ca = createMitmCA({ caCertPath: CA_CERT, caKeyPath: CA_KEY })
  const reg = new SentinelRegistry()
  const sentinel = reg.register('GH_TOKEN', REAL_TOKEN, ['127.0.0.1'])

  let upstream: Server
  let upstreamPort: number
  let proxy: Server
  let proxyPort: number
  let lastHeaders: IncomingHttpHeaders | undefined

  beforeAll(async () => {
    const upCert = mintLeafCert(ca, '127.0.0.1')
    const upLeafOnly = upCert.certPem.match(
      /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\r?\n?/,
    )![0]
    upstream = createHttpsServer(
      { cert: upLeafOnly, key: upCert.keyPem },
      (req, res) => {
        lastHeaders = req.headers
        res.writeHead(200, { 'content-type': 'text/plain' })
        res.end('ok')
      },
    )
    await new Promise<void>(r => upstream.listen(0, '127.0.0.1', r))
    upstreamPort = (upstream.address() as AddressInfo).port

    proxy = createHttpProxyServer({
      filter: () => true,
      mitmCA: ca,
      tlsTerminateUpstreamCA: CA_PEM,
      // Per-sentinel host gating lives in the registry now; the closure
      // just forwards destHost.
      mutateHeaders: (headers, destHost) =>
        reg.substituteInHeaders(headers, destHost, eq),
    })
    await new Promise<void>(r => proxy.listen(0, '127.0.0.1', () => r()))
    proxyPort = (proxy.address() as AddressInfo).port
  })

  afterAll(async () => {
    await new Promise<void>(r => proxy.close(() => r()))
    await new Promise<void>(r => upstream.close(() => r()))
    await disposeMitmCA(ca)
  })

  test('upstream receives the real value when the client sends the sentinel', async () => {
    lastHeaders = undefined
    const r = await curlViaProxy(
      proxyPort,
      `https://127.0.0.1:${upstreamPort}/`,
      { headers: ['Authorization: Bearer ' + sentinel] },
    )
    expect(r.exit).toBe(0)
    expect(r.status).toBe(200)
    expect(lastHeaders?.authorization).toBe(`Bearer ${REAL_TOKEN}`)
    // The real value never appears in anything the client (sandbox) sees.
    expect(r.body).not.toContain(REAL_TOKEN)
  })

  test('substitution covers arbitrary header names, not a fixed list', async () => {
    lastHeaders = undefined
    const r = await curlViaProxy(
      proxyPort,
      `https://127.0.0.1:${upstreamPort}/`,
      { headers: ['Private-Token: ' + sentinel] },
    )
    expect(r.exit).toBe(0)
    expect(lastHeaders?.['private-token']).toBe(REAL_TOKEN)
  })

  test('a non-matching destination receives the sentinel unchanged', async () => {
    // Same upstream server; mint a leaf for a second hostname that resolves
    // to 127.0.0.1 (curl --resolve) but is NOT in the injector's match set.
    const altCert = mintLeafCert(ca, 'localhost')
    const altLeaf = altCert.certPem.match(
      /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\r?\n?/,
    )![0]
    const altUpstream = createHttpsServer(
      { cert: altLeaf, key: altCert.keyPem },
      (req, res) => {
        lastHeaders = req.headers
        res.writeHead(200)
        res.end('ok')
      },
    )
    await new Promise<void>(r => altUpstream.listen(0, '127.0.0.1', r))
    const altPort = (altUpstream.address() as AddressInfo).port
    try {
      lastHeaders = undefined
      const r = await curlViaProxy(proxyPort, `https://localhost:${altPort}/`, {
        headers: ['Authorization: Bearer ' + sentinel],
        resolve: `localhost:${altPort}:127.0.0.1`,
      })
      expect(r.exit).toBe(0)
      expect(r.status).toBe(200)
      // Fails closed: the upstream sees the useless fake.
      expect(lastHeaders?.authorization).toBe(`Bearer ${sentinel}`)
      expect(lastHeaders?.authorization).not.toContain(REAL_TOKEN)
    } finally {
      await new Promise<void>(r => altUpstream.close(() => r()))
    }
  })
})

describe('header injection on the plain-HTTP path', () => {
  const reg = new SentinelRegistry()
  const sentinel = reg.register('GH_TOKEN', REAL_TOKEN, ['127.0.0.1'])
  const mutate = (headers: IncomingHttpHeaders, destHost: string) =>
    reg.substituteInHeaders(headers, destHost, eq)

  let upstream: Server
  let upstreamPort: number
  let lastHeaders: IncomingHttpHeaders | undefined

  beforeAll(async () => {
    upstream = createHttpServer((req, res) => {
      lastHeaders = req.headers
      res.writeHead(200)
      res.end('ok')
    })
    await new Promise<void>(r => upstream.listen(0, '127.0.0.1', () => r()))
    upstreamPort = (upstream.address() as AddressInfo).port
  })

  afterAll(async () => {
    await new Promise<void>(r => upstream.close(() => r()))
  })

  test('without mutateHeadersPlaintext the sentinel passes through unchanged', async () => {
    const proxy = createHttpProxyServer({
      filter: () => true,
      mutateHeaders: mutate,
    })
    await new Promise<void>(r => proxy.listen(0, '127.0.0.1', () => r()))
    const port = (proxy.address() as AddressInfo).port
    try {
      lastHeaders = undefined
      const r = await curlViaProxy(port, `http://127.0.0.1:${upstreamPort}/`, {
        headers: ['Authorization: Bearer ' + sentinel],
      })
      expect(r.exit).toBe(0)
      expect(lastHeaders?.authorization).toBe(`Bearer ${sentinel}`)
      expect(lastHeaders?.authorization).not.toContain(REAL_TOKEN)
    } finally {
      await new Promise<void>(r => proxy.close(() => r()))
    }
  })

  test('with mutateHeadersPlaintext the real value is substituted', async () => {
    const proxy = createHttpProxyServer({
      filter: () => true,
      mutateHeadersPlaintext: mutate,
    })
    await new Promise<void>(r => proxy.listen(0, '127.0.0.1', () => r()))
    const port = (proxy.address() as AddressInfo).port
    try {
      lastHeaders = undefined
      const r = await curlViaProxy(port, `http://127.0.0.1:${upstreamPort}/`, {
        headers: ['Authorization: Bearer ' + sentinel],
      })
      expect(r.exit).toBe(0)
      expect(lastHeaders?.authorization).toBe(`Bearer ${REAL_TOKEN}`)
    } finally {
      await new Promise<void>(r => proxy.close(() => r()))
    }
  })
})

/**
 * SandboxManager-level masking on Linux: the sandboxed process sees the
 * sentinel in its environment; the real value never appears in the wrapped
 * command string.
 */
describe.if(isLinux)('env masking on Linux (bwrap)', () => {
  const MASKED_VAR = 'SRT_TEST_MASKED_TOKEN'

  function baseConfig(
    overrides: Partial<SandboxRuntimeConfig> = {},
  ): SandboxRuntimeConfig {
    return {
      network: { allowedDomains: [], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: ['/tmp'], denyWrite: [] },
      ...overrides,
    }
  }

  beforeAll(async () => {
    process.env[MASKED_VAR] = REAL_TOKEN
    await SandboxManager.reset()
    await SandboxManager.initialize(
      baseConfig({
        // injectHosts is unused here (this block tests env-side masking
        // only); the credential defaults to allowedDomains.
        network: { allowedDomains: ['localhost'], deniedDomains: [] },
        credentials: {
          envVars: [{ name: MASKED_VAR, mode: 'mask' }],
          allowPlaintextInject: true,
        },
      }),
    )
  })

  afterAll(async () => {
    await SandboxManager.reset()
    delete process.env[MASKED_VAR]
  })

  test('bwrap argv sets the masked var to a sentinel', async () => {
    const wrapped = await SandboxManager.wrapWithSandbox('true')
    expect(wrapped).toMatch(
      new RegExp(`--setenv ${MASKED_VAR} ${SENTINEL_PREFIX}[0-9a-f-]{36}`),
    )
  })

  test('the real value never appears in the wrapped command string', async () => {
    const wrapped = await SandboxManager.wrapWithSandbox('true')
    expect(wrapped).not.toContain(REAL_TOKEN)
  })

  test('a masked env var that is unset on the host is skipped', async () => {
    await SandboxManager.reset()
    await SandboxManager.initialize(
      baseConfig({
        network: { allowedDomains: ['localhost'], deniedDomains: [] },
        credentials: {
          envVars: [{ name: 'SRT_TEST_NEVER_SET', mode: 'mask' }],
          allowPlaintextInject: true,
        },
      }),
    )
    const wrapped = await SandboxManager.wrapWithSandbox('true')
    expect(wrapped).not.toContain('--setenv SRT_TEST_NEVER_SET')

    // Restore the suite-level config for the remaining tests.
    await SandboxManager.reset()
    process.env[MASKED_VAR] = REAL_TOKEN
    await SandboxManager.initialize(
      baseConfig({
        network: { allowedDomains: ['localhost'], deniedDomains: [] },
        credentials: {
          envVars: [{ name: MASKED_VAR, mode: 'mask' }],
          allowPlaintextInject: true,
        },
      }),
    )
  })

  test('the sandboxed process sees the sentinel, not the real value', async () => {
    const wrapped = await SandboxManager.wrapWithSandbox(
      `printenv ${MASKED_VAR}`,
    )
    const result = spawnSync(wrapped, {
      shell: true,
      encoding: 'utf8',
      timeout: 10000,
      env: { ...process.env, [MASKED_VAR]: REAL_TOKEN },
    })
    expect(result.status).toBe(0)
    expect(result.stdout.trim().startsWith(SENTINEL_PREFIX)).toBe(true)
    expect(result.stdout).not.toContain(REAL_TOKEN)
  })

  test('reset clears the sentinel registry', async () => {
    expect(SandboxManager.getSentinelRegistry().size).toBeGreaterThan(0)
    await SandboxManager.reset()
    expect(SandboxManager.getSentinelRegistry().size).toBe(0)
    // Re-initialize for any following tests.
    process.env[MASKED_VAR] = REAL_TOKEN
    await SandboxManager.initialize(
      baseConfig({
        network: { allowedDomains: ['localhost'], deniedDomains: [] },
        credentials: {
          envVars: [{ name: MASKED_VAR, mode: 'mask' }],
          allowPlaintextInject: true,
        },
      }),
    )
  })
})

/**
 * SandboxManager-level wiring: initialize() builds the injector and wires
 * it into the proxy it starts; wrapWithSandbox() registers the sentinel.
 * Verified by talking to SandboxManager's own proxy port. The bwrap leg
 * (sandbox sees the sentinel) is covered by the previous describe; the
 * TLS leg by the createHttpProxyServer describe. Uses allowPlaintextInject
 * so the upstream doesn't need a system-trusted cert.
 */
describe.if(isLinux)('end-to-end credential masking via SandboxManager', () => {
  const MASKED_VAR = 'SRT_TEST_E2E_TOKEN'
  let upstream: Server
  let upstreamPort: number
  let lastHeaders: IncomingHttpHeaders | undefined

  beforeAll(async () => {
    upstream = createHttpServer((req, res) => {
      lastHeaders = req.headers
      res.writeHead(200)
      res.end('ok')
    })
    await new Promise<void>(r => upstream.listen(0, '127.0.0.1', () => r()))
    upstreamPort = (upstream.address() as AddressInfo).port

    process.env[MASKED_VAR] = REAL_TOKEN
    await SandboxManager.reset()
    await SandboxManager.initialize({
      network: { allowedDomains: ['localhost'], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: ['/tmp'], denyWrite: [] },
      credentials: {
        envVars: [
          { name: MASKED_VAR, mode: 'mask', injectHosts: ['localhost'] },
        ],
        allowPlaintextInject: true,
      },
    })
  })

  afterAll(async () => {
    await SandboxManager.reset()
    delete process.env[MASKED_VAR]
    await new Promise<void>(r => upstream.close(() => r()))
  })

  test('the manager-started proxy substitutes sentinel→real for an injectHost', async () => {
    // wrapWithSandbox registers the sentinel as a side effect.
    const wrapped = await SandboxManager.wrapWithSandbox(
      `printenv ${MASKED_VAR}`,
    )
    expect(wrapped).not.toContain(REAL_TOKEN)
    const sentinel = [...SandboxManager.getSentinelRegistry().entries()].find(
      ([, real]) => real === REAL_TOKEN,
    )?.[0]
    expect(sentinel?.startsWith(SENTINEL_PREFIX)).toBe(true)

    // The sandbox itself reads the sentinel.
    const inSandbox = spawnSync(wrapped, {
      shell: true,
      encoding: 'utf8',
      timeout: 10000,
      env: { ...process.env, [MASKED_VAR]: REAL_TOKEN },
    })
    expect(inSandbox.stdout.trim()).toBe(sentinel)

    // A request carrying the sentinel through SandboxManager's proxy
    // reaches the upstream with the real value.
    const proxyPort = SandboxManager.getProxyPort()!
    const authToken = SandboxManager.getProxyAuthToken()!
    lastHeaders = undefined
    const r = await curlViaProxy(
      proxyPort,
      `http://localhost:${upstreamPort}/`,
      {
        headers: ['Authorization: Bearer ' + sentinel],
        proxyAuth: `srt:${authToken}`,
      },
    )
    expect(r.exit).toBe(0)
    expect(r.status).toBe(200)
    expect(lastHeaders?.authorization).toBe(`Bearer ${REAL_TOKEN}`)
  }, 20000)

  test('a non-injectHost destination through the manager proxy receives the sentinel', async () => {
    // Reconfigure with an injectHosts that does NOT cover localhost.
    await SandboxManager.reset()
    process.env[MASKED_VAR] = REAL_TOKEN
    await SandboxManager.initialize({
      network: {
        allowedDomains: ['localhost', 'api.github.com'],
        deniedDomains: [],
      },
      filesystem: { denyRead: [], allowWrite: ['/tmp'], denyWrite: [] },
      credentials: {
        envVars: [
          { name: MASKED_VAR, mode: 'mask', injectHosts: ['api.github.com'] },
        ],
        allowPlaintextInject: true,
      },
    })
    await SandboxManager.wrapWithSandbox('true')
    const sentinel = [...SandboxManager.getSentinelRegistry().entries()].find(
      ([, real]) => real === REAL_TOKEN,
    )?.[0]

    const proxyPort = SandboxManager.getProxyPort()!
    const authToken = SandboxManager.getProxyAuthToken()!
    lastHeaders = undefined
    const r = await curlViaProxy(
      proxyPort,
      `http://localhost:${upstreamPort}/`,
      {
        headers: ['Authorization: Bearer ' + sentinel],
        proxyAuth: `srt:${authToken}`,
      },
    )
    expect(r.exit).toBe(0)
    expect(lastHeaders?.authorization).toBe(`Bearer ${sentinel}`)
    expect(lastHeaders?.authorization).not.toContain(REAL_TOKEN)
  }, 20000)
})

/**
 * Per-credential injectHosts through SandboxManager: GH_TOKEN and NPM_TOKEN
 * each declare their own per-entry injectHosts. Each sentinel only swaps at
 * its own credential's injectHosts — sending GH_TOKEN's sentinel to
 * NPM_TOKEN's host (or vice versa) must NOT substitute, even though both
 * hosts are allowlisted.
 */
describe.if(isLinux)('per-credential injectHosts via SandboxManager', () => {
  const GH_VAR = 'SRT_TEST_GH_TOKEN'
  const NPM_VAR = 'SRT_TEST_NPM_TOKEN'
  const GH_REAL = 'gh-real-secret'
  const NPM_REAL = 'npm-real-secret'

  // Two upstreams behind two loopback names (a `.localhost` name resolves
  // to loopback locally, and the resolved-address guard lets it): the proxy
  // distinguishes them by the absolute-URI host on the plain-HTTP path,
  // which is what destHost gating sees.
  const GH_HOST = 'localhost'
  const NPM_HOST = 'npm.localhost'

  let ghUp: Server, ghPort: number, ghHeaders: IncomingHttpHeaders | undefined
  let npmUp: Server,
    npmPort: number,
    npmHeaders: IncomingHttpHeaders | undefined
  let ghSentinel: string, npmSentinel: string
  let proxyPort: number, authToken: string

  beforeAll(async () => {
    ghUp = createHttpServer((req, res) => {
      ghHeaders = req.headers
      res.writeHead(200)
      res.end('ok')
    })
    npmUp = createHttpServer((req, res) => {
      npmHeaders = req.headers
      res.writeHead(200)
      res.end('ok')
    })
    await new Promise<void>(r => ghUp.listen(0, '127.0.0.1', () => r()))
    await new Promise<void>(r => npmUp.listen(0, '127.0.0.1', () => r()))
    ghPort = (ghUp.address() as AddressInfo).port
    npmPort = (npmUp.address() as AddressInfo).port

    process.env[GH_VAR] = GH_REAL
    process.env[NPM_VAR] = NPM_REAL
    await SandboxManager.reset()
    await SandboxManager.initialize({
      network: { allowedDomains: [GH_HOST, NPM_HOST], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: ['/tmp'], denyWrite: [] },
      credentials: {
        // Each credential narrows to its own host via per-entry injectHosts.
        envVars: [
          { name: GH_VAR, mode: 'mask', injectHosts: [GH_HOST] },
          { name: NPM_VAR, mode: 'mask', injectHosts: [NPM_HOST] },
        ],
        allowPlaintextInject: true,
      },
    })
    await SandboxManager.wrapWithSandbox('true')
    const reg = SandboxManager.getSentinelRegistry()
    ghSentinel = [...reg.entries()].find(([, r]) => r === GH_REAL)![0]
    npmSentinel = [...reg.entries()].find(([, r]) => r === NPM_REAL)![0]
    proxyPort = SandboxManager.getProxyPort()!
    authToken = SandboxManager.getProxyAuthToken()!
  })

  afterAll(async () => {
    await SandboxManager.reset()
    delete process.env[GH_VAR]
    delete process.env[NPM_VAR]
    await new Promise<void>(r => ghUp.close(() => r()))
    await new Promise<void>(r => npmUp.close(() => r()))
  })

  test('two masked vars register two distinct sentinels', () => {
    expect(ghSentinel).not.toBe(npmSentinel)
    expect(SandboxManager.getSentinelRegistry().size).toBe(2)
  })

  test('GH sentinel swaps at its own per-entry injectHost', async () => {
    ghHeaders = undefined
    const r = await curlViaProxy(proxyPort, `http://${GH_HOST}:${ghPort}/`, {
      headers: ['Authorization: Bearer ' + ghSentinel],
      proxyAuth: `srt:${authToken}`,
    })
    expect(r.exit).toBe(0)
    expect(ghHeaders?.authorization).toBe(`Bearer ${GH_REAL}`)
  }, 20000)

  test('NPM sentinel swaps only at its own per-entry injectHost', async () => {
    npmHeaders = undefined
    const r = await curlViaProxy(proxyPort, `http://${NPM_HOST}:${npmPort}/`, {
      headers: ['Authorization: Bearer ' + npmSentinel],
      proxyAuth: `srt:${authToken}`,
    })
    expect(r.exit).toBe(0)
    expect(npmHeaders?.authorization).toBe(`Bearer ${NPM_REAL}`)

    // Per-entry injectHosts is exclusive: NPM's sentinel sent to GH_HOST
    // (not in NPM's list) stays a fake.
    ghHeaders = undefined
    const r2 = await curlViaProxy(proxyPort, `http://${GH_HOST}:${ghPort}/`, {
      headers: ['Authorization: Bearer ' + npmSentinel],
      proxyAuth: `srt:${authToken}`,
    })
    expect(r2.exit).toBe(0)
    expect(ghHeaders?.authorization).toBe(`Bearer ${npmSentinel}`)
    expect(ghHeaders?.authorization).not.toContain(NPM_REAL)
  }, 20000)

  test("anti-laundering: GH sentinel sent to NPM's host is not swapped", async () => {
    npmHeaders = undefined
    const r = await curlViaProxy(proxyPort, `http://${NPM_HOST}:${npmPort}/`, {
      headers: ['Authorization: Bearer ' + ghSentinel],
      proxyAuth: `srt:${authToken}`,
    })
    expect(r.exit).toBe(0)
    expect(npmHeaders?.authorization).toBe(`Bearer ${ghSentinel}`)
    expect(npmHeaders?.authorization).not.toContain(GH_REAL)
  }, 20000)
})

/**
 * No per-entry injectHosts → defaults to network.allowedDomains.
 * injectHosts is an optional narrowing; absent it, the credential is
 * injectable at *every* host the sandbox can reach. The second test
 * makes the security implication explicit.
 */
describe.if(isLinux)(
  'injectHosts defaults to allowedDomains via SandboxManager',
  () => {
    const VAR = 'SRT_TEST_DEFAULT_TOKEN'
    const REAL = 'default-real-secret'
    const HOST_A = 'localhost'
    const HOST_B = 'host-b.localhost'

    let upA: Server, portA: number, hdrA: IncomingHttpHeaders | undefined
    let upB: Server, portB: number, hdrB: IncomingHttpHeaders | undefined

    beforeAll(async () => {
      upA = createHttpServer((req, res) => {
        hdrA = req.headers
        res.writeHead(200)
        res.end('ok')
      })
      upB = createHttpServer((req, res) => {
        hdrB = req.headers
        res.writeHead(200)
        res.end('ok')
      })
      await new Promise<void>(r => upA.listen(0, '127.0.0.1', () => r()))
      await new Promise<void>(r => upB.listen(0, '127.0.0.1', () => r()))
      portA = (upA.address() as AddressInfo).port
      portB = (upB.address() as AddressInfo).port
    })

    afterAll(async () => {
      await SandboxManager.reset()
      delete process.env[VAR]
      await new Promise<void>(r => upA.close(() => r()))
      await new Promise<void>(r => upB.close(() => r()))
    })

    test('with no injectHosts, sentinel swaps at the sole allowedDomain', async () => {
      process.env[VAR] = REAL
      await SandboxManager.reset()
      await SandboxManager.initialize({
        network: { allowedDomains: [HOST_A], deniedDomains: [] },
        filesystem: { denyRead: [], allowWrite: ['/tmp'], denyWrite: [] },
        credentials: {
          envVars: [{ name: VAR, mode: 'mask' }],
          // No per-entry injectHosts → defaults to allowedDomains.
          allowPlaintextInject: true,
        },
      })
      await SandboxManager.wrapWithSandbox('true')
      const sentinel = [...SandboxManager.getSentinelRegistry().entries()].find(
        ([, r]) => r === REAL,
      )![0]
      const proxyPort = SandboxManager.getProxyPort()!
      const authToken = SandboxManager.getProxyAuthToken()!

      hdrA = undefined
      const r = await curlViaProxy(proxyPort, `http://${HOST_A}:${portA}/`, {
        headers: ['Authorization: Bearer ' + sentinel],
        proxyAuth: `srt:${authToken}`,
      })
      expect(r.exit).toBe(0)
      expect(hdrA?.authorization).toBe(`Bearer ${REAL}`)
    }, 20000)

    test('without injectHosts, credential is injected at every allowedDomain', async () => {
      // Security trade-off made explicit: two reachable hosts, no
      // narrowing → the real value goes to BOTH. A credential intended
      // for one host must set injectHosts to keep it from the other.
      process.env[VAR] = REAL
      await SandboxManager.reset()
      await SandboxManager.initialize({
        network: { allowedDomains: [HOST_A, HOST_B], deniedDomains: [] },
        filesystem: { denyRead: [], allowWrite: ['/tmp'], denyWrite: [] },
        credentials: {
          envVars: [{ name: VAR, mode: 'mask' }],
          allowPlaintextInject: true,
        },
      })
      await SandboxManager.wrapWithSandbox('true')
      const sentinel = [...SandboxManager.getSentinelRegistry().entries()].find(
        ([, r]) => r === REAL,
      )![0]
      const proxyPort = SandboxManager.getProxyPort()!
      const authToken = SandboxManager.getProxyAuthToken()!

      hdrA = undefined
      const ra = await curlViaProxy(proxyPort, `http://${HOST_A}:${portA}/`, {
        headers: ['Authorization: Bearer ' + sentinel],
        proxyAuth: `srt:${authToken}`,
      })
      expect(ra.exit).toBe(0)
      expect(hdrA?.authorization).toBe(`Bearer ${REAL}`)

      hdrB = undefined
      const rb = await curlViaProxy(proxyPort, `http://${HOST_B}:${portB}/`, {
        headers: ['Authorization: Bearer ' + sentinel],
        proxyAuth: `srt:${authToken}`,
      })
      expect(rb.exit).toBe(0)
      expect(hdrB?.authorization).toBe(`Bearer ${REAL}`)
    }, 20000)
  },
)

/**
 * Env-var masking with decode: "jwt" — the variable's whole value is a JWT
 * and the sandbox sees a JWT-shaped fake instead of the bare fake_value_
 * sentinel, so token-parsing clients keep working.
 */
describe.if(isLinux)('env decode: "jwt" masking on Linux (bwrap)', () => {
  const JWT_VAR = 'SRT_TEST_JWT_ENV_TOKEN'
  const b64u = (s: string) => Buffer.from(s, 'utf8').toString('base64url')
  const REAL_JWT =
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' +
    b64u('{"sub":"env-user","iat":1516239022}') +
    '.ZW52LXJlYWwtc2ln'

  function decodeConfig(name: string): SandboxRuntimeConfig {
    return {
      network: { allowedDomains: ['localhost'], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: ['/tmp'], denyWrite: [] },
      credentials: {
        envVars: [{ name, mode: 'mask', decode: 'jwt' }],
        allowPlaintextInject: true,
      },
    }
  }

  afterAll(async () => {
    await SandboxManager.reset()
    delete process.env[JWT_VAR]
  })

  test('the sandbox sees a parseable HS256 fake JWT, never the real one', async () => {
    process.env[JWT_VAR] = REAL_JWT
    await SandboxManager.reset()
    await SandboxManager.initialize(decodeConfig(JWT_VAR))

    const wrapped = await SandboxManager.wrapWithSandbox(`printenv ${JWT_VAR}`)
    expect(wrapped).not.toContain(REAL_JWT)

    const result = spawnSync(wrapped, {
      shell: true,
      encoding: 'utf8',
      timeout: 10000,
      env: { ...process.env, [JWT_VAR]: REAL_JWT },
    })
    expect(result.status).toBe(0)
    const fakeJwt = result.stdout.trim()
    expect(fakeJwt).not.toBe(REAL_JWT)
    expect(fakeJwt).not.toContain(REAL_JWT)

    // The fake is a structurally valid JWT: a tool that parses the token
    // from env (segment count, header, exp) keeps working.
    expect(fakeJwt.split('.')).toHaveLength(3)
    expect(verifyJwt(fakeJwt)).toBe(true)
    const header = JSON.parse(
      Buffer.from(fakeJwt.split('.')[0]!, 'base64url').toString('utf8'),
    ) as Record<string, unknown>
    expect(header).toEqual({ alg: 'HS256', typ: 'JWT' })

    // The registry maps the fake back to the real token for the proxy.
    expect(SandboxManager.getSentinelRegistry().lookupReal(fakeJwt)).toBe(
      REAL_JWT,
    )
  })

  test('a set value that is not a JWT fails open with a loud warning', async () => {
    const NOT_JWT_VAR = 'SRT_TEST_NOT_A_JWT'
    process.env[NOT_JWT_VAR] = 'hunter2-not-a-jwt'
    const warnSpy = spyOn(console, 'warn').mockImplementation(() => {})
    try {
      await SandboxManager.reset()
      await SandboxManager.initialize(decodeConfig(NOT_JWT_VAR))
      const wrapped = await SandboxManager.wrapWithSandbox(
        `printenv ${NOT_JWT_VAR}`,
      )

      // Nothing was masked: no sentinel is set for the var...
      expect(wrapped).not.toContain(`--setenv ${NOT_JWT_VAR}`)
      // ...and the variable is not unset either — the real value passes
      // through to the sandbox (fail-open).
      const result = spawnSync(wrapped, {
        shell: true,
        encoding: 'utf8',
        timeout: 10000,
        env: { ...process.env, [NOT_JWT_VAR]: 'hunter2-not-a-jwt' },
      })
      expect(result.status).toBe(0)
      expect(result.stdout.trim()).toBe('hunter2-not-a-jwt')

      // The fail-open is loud: a stderr warning names the variable.
      const msgs = warnSpy.mock.calls.map(c => c[0] as string)
      const msg = msgs.find(m => m.includes(NOT_JWT_VAR))
      expect(msg).toBeDefined()
      expect(msg).toContain('UNPROTECTED')
      expect(msg).toContain('did not verify')
      expect(msg).toContain('JWT')
    } finally {
      warnSpy.mockRestore()
      delete process.env[NOT_JWT_VAR]
    }
  })

  test('an unset decode var is skipped silently', async () => {
    const warnSpy = spyOn(console, 'warn').mockImplementation(() => {})
    try {
      await SandboxManager.reset()
      await SandboxManager.initialize(decodeConfig('SRT_TEST_JWT_NEVER_SET'))
      const wrapped = await SandboxManager.wrapWithSandbox('true')
      expect(wrapped).not.toContain('--setenv SRT_TEST_JWT_NEVER_SET')
      expect(
        warnSpy.mock.calls.some(c =>
          (c[0] as string).includes('SRT_TEST_JWT_NEVER_SET'),
        ),
      ).toBe(false)
    } finally {
      warnSpy.mockRestore()
    }
  })

  test('regression: without decode, a JWT-valued var gets the plain sentinel', async () => {
    process.env[JWT_VAR] = REAL_JWT
    await SandboxManager.reset()
    await SandboxManager.initialize({
      network: { allowedDomains: ['localhost'], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: ['/tmp'], denyWrite: [] },
      credentials: {
        envVars: [{ name: JWT_VAR, mode: 'mask' }],
        allowPlaintextInject: true,
      },
    })
    const wrapped = await SandboxManager.wrapWithSandbox('true')
    expect(wrapped).toMatch(
      new RegExp(`--setenv ${JWT_VAR} ${SENTINEL_PREFIX}[0-9a-f-]{36}`),
    )
    expect(wrapped).not.toContain(REAL_JWT)
  })
})

/**
 * End-to-end env decode masking: the env var holds a JWT; inside the
 * sandbox the tool reads a structurally valid FAKE JWT; sending it through
 * the manager proxy delivers the REAL JWT to the injectHost, while a
 * non-injectHost receives the fake.
 */
describe.if(isLinux)('end-to-end env decode masking via SandboxManager', () => {
  const JWT_VAR = 'SRT_TEST_E2E_JWT_TOKEN'
  const HOST_A = 'localhost'
  const HOST_B = 'host-b.localhost'

  const b64u = (s: string) => Buffer.from(s, 'utf8').toString('base64url')
  const REAL_JWT =
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' +
    b64u('{"sub":"e2e-env-user","iat":1516239022}') +
    '.ZTJlLWVudi1zaWc'

  let upstream: Server
  let upstreamPort: number
  let lastHeaders: IncomingHttpHeaders | undefined

  beforeAll(async () => {
    upstream = createHttpServer((req, res) => {
      lastHeaders = req.headers
      res.writeHead(200)
      res.end('ok')
    })
    await new Promise<void>(r => upstream.listen(0, '127.0.0.1', () => r()))
    upstreamPort = (upstream.address() as AddressInfo).port

    process.env[JWT_VAR] = REAL_JWT
    await SandboxManager.reset()
    await SandboxManager.initialize({
      network: { allowedDomains: [HOST_A, HOST_B], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: ['/tmp'], denyWrite: [] },
      credentials: {
        envVars: [
          { name: JWT_VAR, mode: 'mask', decode: 'jwt', injectHosts: [HOST_A] },
        ],
        allowPlaintextInject: true,
      },
    })
  })

  afterAll(async () => {
    await SandboxManager.reset()
    delete process.env[JWT_VAR]
    await new Promise<void>(r => upstream.close(() => r()))
  })

  /** Wrap printenv and run it: the fake JWT the sandbox actually sees. */
  function readFakeFromSandbox(wrapped: string): string {
    const result = spawnSync(wrapped, {
      shell: true,
      encoding: 'utf8',
      timeout: 10000,
      env: { ...process.env, [JWT_VAR]: REAL_JWT },
    })
    expect(result.status).toBe(0)
    return result.stdout.trim()
  }

  test('printenv → fake JWT; proxy delivers the real JWT to the injectHost', async () => {
    const wrapped = await SandboxManager.wrapWithSandbox(`printenv ${JWT_VAR}`)
    expect(wrapped).not.toContain(REAL_JWT)
    const fakeJwt = readFakeFromSandbox(wrapped)
    expect(fakeJwt).not.toBe(REAL_JWT)
    expect(verifyJwt(fakeJwt)).toBe(true)

    const proxyPort = SandboxManager.getProxyPort()!
    const authToken = SandboxManager.getProxyAuthToken()!
    lastHeaders = undefined
    const r = await curlViaProxy(
      proxyPort,
      `http://${HOST_A}:${upstreamPort}/`,
      {
        headers: ['Authorization: Bearer ' + fakeJwt],
        proxyAuth: `srt:${authToken}`,
      },
    )
    expect(r.exit).toBe(0)
    expect(r.status).toBe(200)
    expect(lastHeaders?.authorization).toBe(`Bearer ${REAL_JWT}`)
  }, 20000)

  test('a non-injectHost destination receives the fake JWT unchanged', async () => {
    const wrapped = await SandboxManager.wrapWithSandbox(`printenv ${JWT_VAR}`)
    const fakeJwt = readFakeFromSandbox(wrapped)

    const proxyPort = SandboxManager.getProxyPort()!
    const authToken = SandboxManager.getProxyAuthToken()!
    lastHeaders = undefined
    const r = await curlViaProxy(
      proxyPort,
      `http://${HOST_B}:${upstreamPort}/`,
      {
        headers: ['Authorization: Bearer ' + fakeJwt],
        proxyAuth: `srt:${authToken}`,
      },
    )
    expect(r.exit).toBe(0)
    expect(lastHeaders?.authorization).toBe(`Bearer ${fakeJwt}`)
    expect(lastHeaders?.authorization).not.toContain(REAL_JWT)
  }, 20000)
})

/**
 * Env-var claim-level masking (decode: "jwt" + maskClaims): the sandbox
 * sees a rebuilt token whose named claim is a sentinel while every other
 * claim — and the header segment — is real, and the registry carries BOTH
 * mappings (whole fake token → real token, claim sentinel → real claim).
 */
describe.if(isLinux)('env maskClaims masking on Linux (bwrap)', () => {
  const JWT_VAR = 'SRT_TEST_JWT_ENV_CLAIMS'
  const b64u = (s: string) => Buffer.from(s, 'utf8').toString('base64url')
  // Header with a kid so verbatim header reuse is observable (the minted
  // whole-token fake's header has no kid).
  const REAL_HEADER = b64u('{"alg":"RS256","typ":"JWT","kid":"env-key-7"}')
  const REAL_CLAIM = 'env-real-claim-secret-0123456789'
  const REAL_PAYLOAD = {
    sub: 'env-user',
    api_key: REAL_CLAIM,
    aud: 'api.example.com',
    iat: 1516239022,
  }
  const REAL_JWT = `${REAL_HEADER}.${b64u(JSON.stringify(REAL_PAYLOAD))}.ZW52LXJlYWwtc2ln`

  function claimsConfig(
    name: string,
    maskClaims: string[],
  ): SandboxRuntimeConfig {
    return {
      network: { allowedDomains: ['localhost'], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: ['/tmp'], denyWrite: [] },
      credentials: {
        envVars: [{ name, mode: 'mask', decode: 'jwt', maskClaims }],
        allowPlaintextInject: true,
      },
    }
  }

  /** Wrap printenv and run it: the fake JWT the sandbox actually sees. */
  function readFakeFromSandbox(wrapped: string): string {
    const result = spawnSync(wrapped, {
      shell: true,
      encoding: 'utf8',
      timeout: 10000,
      env: { ...process.env, [JWT_VAR]: REAL_JWT },
    })
    expect(result.status).toBe(0)
    return result.stdout.trim()
  }

  function payloadOf(token: string): Record<string, unknown> {
    return JSON.parse(
      Buffer.from(token.split('.')[1]!, 'base64url').toString('utf8'),
    ) as Record<string, unknown>
  }

  afterAll(async () => {
    await SandboxManager.reset()
    delete process.env[JWT_VAR]
  })

  test('named claim is a sentinel, others real, header verbatim, filler signature; both registry mappings exist', async () => {
    process.env[JWT_VAR] = REAL_JWT
    await SandboxManager.reset()
    await SandboxManager.initialize(claimsConfig(JWT_VAR, ['api_key']))

    const wrapped = await SandboxManager.wrapWithSandbox(`printenv ${JWT_VAR}`)
    expect(wrapped).not.toContain(REAL_JWT)
    expect(wrapped).not.toContain(REAL_CLAIM)
    const fakeJwt = readFakeFromSandbox(wrapped)
    expect(fakeJwt).not.toBe(REAL_JWT)
    expect(verifyJwt(fakeJwt)).toBe(true)

    // Header segment reused byte-identical; signature is the fixed filler,
    // never the real signature.
    const [h, , sig] = fakeJwt.split('.')
    expect(h).toBe(REAL_HEADER)
    expect(sig).toBe('c3J0LWZha2U')

    // The named claim is a sentinel; every other claim is real.
    const payload = payloadOf(fakeJwt)
    const claimSentinel = payload.api_key as string
    expect(claimSentinel).toStartWith(SENTINEL_PREFIX)
    expect(payload).toEqual({ ...REAL_PAYLOAD, api_key: claimSentinel })

    // Mapping (a): whole fake token → whole real token (bearer usage).
    const registry = SandboxManager.getSentinelRegistry()
    expect(registry.lookupReal(fakeJwt)).toBe(REAL_JWT)
    // Mapping (b): claim sentinel → real claim value (extracted usage).
    expect(registry.lookupReal(claimSentinel)).toBe(REAL_CLAIM)
    expect(registry.size).toBe(2)
  })

  test('a named claim absent or non-string is skipped; the matched claim still masks', async () => {
    process.env[JWT_VAR] = REAL_JWT
    await SandboxManager.reset()
    await SandboxManager.initialize(
      claimsConfig(JWT_VAR, ['api_key', 'not_present', 'iat']),
    )

    const wrapped = await SandboxManager.wrapWithSandbox(`printenv ${JWT_VAR}`)
    const payload = payloadOf(readFakeFromSandbox(wrapped))
    expect(payload.api_key as string).toStartWith(SENTINEL_PREFIX)
    // Absent and non-string (iat is a number) claims are skipped.
    expect(payload.not_present).toBeUndefined()
    expect(payload.iat).toBe(REAL_PAYLOAD.iat)
    // Only the whole-token mapping and the one matched claim.
    expect(SandboxManager.getSentinelRegistry().size).toBe(2)
  })

  test('no named claim maskable → loud warning, real value passes through (fail-open)', async () => {
    process.env[JWT_VAR] = REAL_JWT
    const warnSpy = spyOn(console, 'warn').mockImplementation(() => {})
    try {
      await SandboxManager.reset()
      await SandboxManager.initialize(claimsConfig(JWT_VAR, ['not_present']))
      const wrapped = await SandboxManager.wrapWithSandbox(
        `printenv ${JWT_VAR}`,
      )

      // Nothing was masked: no sentinel is set for the var...
      expect(wrapped).not.toContain(`--setenv ${JWT_VAR}`)
      // ...and the real value passes through to the sandbox (fail-open).
      expect(readFakeFromSandbox(wrapped)).toBe(REAL_JWT)
      expect(SandboxManager.getSentinelRegistry().size).toBe(0)

      // The fail-open is loud: a stderr warning names the variable.
      const msgs = warnSpy.mock.calls.map(c => c[0] as string)
      const msg = msgs.find(m => m.includes(JWT_VAR))
      expect(msg).toBeDefined()
      expect(msg).toContain('UNPROTECTED')
      expect(msg).toContain('maskClaims')
    } finally {
      warnSpy.mockRestore()
    }
  })
})

/**
 * End-to-end env claim-level masking: the env var holds a JWT with a
 * secret claim; inside the sandbox the tool reads a rebuilt token whose
 * named claim is a sentinel; the proxy substitutes BOTH the whole token
 * (bearer usage) and the extracted claim sentinel (claim-extraction
 * usage) on egress to the injectHost, and neither at a non-injectHost.
 */
describe.if(isLinux)('end-to-end env maskClaims via SandboxManager', () => {
  const JWT_VAR = 'SRT_TEST_E2E_JWT_CLAIMS'
  const HOST_A = 'localhost'
  const HOST_B = 'host-b.localhost'

  const b64u = (s: string) => Buffer.from(s, 'utf8').toString('base64url')
  const REAL_CLAIM = 'e2e-env-claim-secret-0123456789'
  const REAL_JWT =
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' +
    b64u(`{"sub":"e2e-env-user","api_key":"${REAL_CLAIM}","iat":1516239022}`) +
    '.ZTJlLWVudi1jbGFpbXMtc2ln'

  let upstream: Server
  let upstreamPort: number
  let lastHeaders: IncomingHttpHeaders | undefined

  beforeAll(async () => {
    upstream = createHttpServer((req, res) => {
      lastHeaders = req.headers
      res.writeHead(200)
      res.end('ok')
    })
    await new Promise<void>(r => upstream.listen(0, '127.0.0.1', () => r()))
    upstreamPort = (upstream.address() as AddressInfo).port

    process.env[JWT_VAR] = REAL_JWT
    await SandboxManager.reset()
    await SandboxManager.initialize({
      network: { allowedDomains: [HOST_A, HOST_B], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: ['/tmp'], denyWrite: [] },
      credentials: {
        envVars: [
          {
            name: JWT_VAR,
            mode: 'mask',
            decode: 'jwt',
            maskClaims: ['api_key'],
            injectHosts: [HOST_A],
          },
        ],
        allowPlaintextInject: true,
      },
    })
  })

  afterAll(async () => {
    await SandboxManager.reset()
    delete process.env[JWT_VAR]
    await new Promise<void>(r => upstream.close(() => r()))
  })

  /** Wrap printenv and run it: the fake JWT the sandbox actually sees. */
  async function readFakeJwt(): Promise<string> {
    const wrapped = await SandboxManager.wrapWithSandbox(`printenv ${JWT_VAR}`)
    expect(wrapped).not.toContain(REAL_JWT)
    const result = spawnSync(wrapped, {
      shell: true,
      encoding: 'utf8',
      timeout: 10000,
      env: { ...process.env, [JWT_VAR]: REAL_JWT },
    })
    expect(result.status).toBe(0)
    return result.stdout.trim()
  }

  function claimOf(token: string): string {
    const payload = JSON.parse(
      Buffer.from(token.split('.')[1]!, 'base64url').toString('utf8'),
    ) as Record<string, unknown>
    return payload.api_key as string
  }

  test('printenv → claim-masked fake that decodes; bearer usage delivers the whole real token', async () => {
    const fakeJwt = await readFakeJwt()
    expect(fakeJwt).not.toBe(REAL_JWT)
    expect(verifyJwt(fakeJwt)).toBe(true)
    // Header reused verbatim; only the payload changed.
    expect(fakeJwt.split('.')[0]).toBe(REAL_JWT.split('.')[0])
    const payload = JSON.parse(
      Buffer.from(fakeJwt.split('.')[1]!, 'base64url').toString('utf8'),
    ) as Record<string, unknown>
    expect(payload.api_key as string).toStartWith(SENTINEL_PREFIX)
    expect(payload.sub).toBe('e2e-env-user')
    expect(payload.iat).toBe(1516239022)

    // The tool sends the token verbatim → the injectHost receives the
    // whole REAL token.
    const proxyPort = SandboxManager.getProxyPort()!
    const authToken = SandboxManager.getProxyAuthToken()!
    lastHeaders = undefined
    const r = await curlViaProxy(
      proxyPort,
      `http://${HOST_A}:${upstreamPort}/`,
      {
        headers: ['Authorization: Bearer ' + fakeJwt],
        proxyAuth: `srt:${authToken}`,
      },
    )
    expect(r.exit).toBe(0)
    expect(r.status).toBe(200)
    expect(lastHeaders?.authorization).toBe(`Bearer ${REAL_JWT}`)
  }, 20000)

  test('extracted-claim usage: the claim sentinel alone swaps to the real claim value', async () => {
    const sentinel = claimOf(await readFakeJwt())
    expect(sentinel).toStartWith(SENTINEL_PREFIX)

    const proxyPort = SandboxManager.getProxyPort()!
    const authToken = SandboxManager.getProxyAuthToken()!
    lastHeaders = undefined
    const r = await curlViaProxy(
      proxyPort,
      `http://${HOST_A}:${upstreamPort}/`,
      {
        headers: ['Authorization: Bearer ' + sentinel],
        proxyAuth: `srt:${authToken}`,
      },
    )
    expect(r.exit).toBe(0)
    expect(lastHeaders?.authorization).toBe(`Bearer ${REAL_CLAIM}`)
  }, 20000)

  test('a non-injectHost destination receives the fake token and sentinel unchanged', async () => {
    const fakeJwt = await readFakeJwt()

    const proxyPort = SandboxManager.getProxyPort()!
    const authToken = SandboxManager.getProxyAuthToken()!
    lastHeaders = undefined
    let r = await curlViaProxy(proxyPort, `http://${HOST_B}:${upstreamPort}/`, {
      headers: ['Authorization: Bearer ' + fakeJwt],
      proxyAuth: `srt:${authToken}`,
    })
    expect(r.exit).toBe(0)
    expect(lastHeaders?.authorization).toBe(`Bearer ${fakeJwt}`)
    expect(lastHeaders?.authorization).not.toContain(REAL_CLAIM)

    lastHeaders = undefined
    r = await curlViaProxy(proxyPort, `http://${HOST_B}:${upstreamPort}/`, {
      headers: ['Authorization: Bearer ' + claimOf(fakeJwt)],
      proxyAuth: `srt:${authToken}`,
    })
    expect(r.exit).toBe(0)
    expect(lastHeaders?.authorization).toBe(`Bearer ${claimOf(fakeJwt)}`)
    expect(lastHeaders?.authorization).not.toContain(REAL_CLAIM)
  }, 20000)
})

type CurlResult = {
  exit: number
  status: number
  body: string
}

async function curlViaProxy(
  proxyPort: number,
  url: string,
  opts: { headers?: string[]; resolve?: string; proxyAuth?: string } = {},
): Promise<CurlResult> {
  const auth = opts.proxyAuth ? `${opts.proxyAuth}@` : ''
  const args = [
    '-sS',
    '--proxy',
    `http://${auth}127.0.0.1:${proxyPort}`,
    '--max-time',
    '10',
    '-D',
    '-',
  ]
  if (url.startsWith('https://')) args.push('--cacert', CA_CERT)
  for (const h of opts.headers ?? []) args.push('-H', h)
  if (opts.resolve) args.push('--resolve', opts.resolve)
  args.push(url)

  const child = spawn('curl', args)
  let out = ''
  child.stdout.setEncoding('utf8').on('data', c => (out += c))
  child.stderr.setEncoding('utf8').on('data', () => {})
  await Promise.all([
    new Promise<void>(r => child.stdout.once('end', r)),
    new Promise<void>(r => child.stderr.once('end', r)),
  ])
  const exit = await new Promise<number>(r =>
    child.on('close', code => r(code ?? 1)),
  )

  const sep = out.lastIndexOf('\r\n\r\n')
  const headerPart = sep >= 0 ? out.slice(0, sep) : ''
  const body = sep >= 0 ? out.slice(sep + 4) : out
  const blocks = headerPart.split(/\r\n\r\n/)
  const lastHdr = blocks[blocks.length - 1] ?? ''
  const m = /HTTP\/[\d.]+ (\d+)/.exec(lastHdr)
  const status = m ? Number(m[1]) : 0
  return { exit, status, body }
}
