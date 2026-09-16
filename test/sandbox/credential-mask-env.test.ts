import { describe, test, expect, beforeAll, afterAll, spyOn } from 'bun:test'
import { spawn, spawnSync } from 'node:child_process'
import {
  createServer as createHttpServer,
  type IncomingHttpHeaders,
} from 'node:http'
import type { Server, AddressInfo } from 'node:net'
import { buildMaskedEnvVars } from '../../src/sandbox/credential-mask-env.js'
import {
  SentinelRegistry,
  SENTINEL_PREFIX,
} from '../../src/sandbox/credential-sentinel.js'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import { isLinux } from '../helpers/platform.js'

/**
 * Unit tests for structured (extract) env-var masking. Platform-agnostic;
 * these touch only the sentinel registry — the host environment is passed
 * in explicitly so nothing here mutates process.env.
 */

const DB_PASSWORD = 's3cret-real-pw-0123456789'
const DB_URL = `postgres://alice:${DB_PASSWORD}@db.example.com:5432/mydb`
// Capture group 1 = the password span of a userinfo connection string.
const DB_EXTRACT = '://[^:]+:([^@]+)@'

/** Host matcher for unit tests: exact equality. */
const eq = (h: string, p: string) => h === p

describe('buildMaskedEnvVars', () => {
  test('whole-value (no extract): fake value is exactly one sentinel', () => {
    const reg = new SentinelRegistry()
    const { setEnvVars, degradeToUnsetNames } = buildMaskedEnvVars(
      [{ name: 'GH_TOKEN', mode: 'mask' }],
      ['api.github.com'],
      reg,
      { GH_TOKEN: 'ghp_real_secret' },
    )
    expect(degradeToUnsetNames).toHaveLength(0)
    const fake = setEnvVars['GH_TOKEN']!
    expect(fake.startsWith(SENTINEL_PREFIX)).toBe(true)
    // The fake IS the sentinel — nothing else around it.
    expect(fake.length).toBe(SENTINEL_PREFIX.length + 36)
    expect(reg.lookupReal(fake)).toBe('ghp_real_secret')
    expect(reg.size).toBe(1)
  })

  test('DATABASE_URL: only the password span becomes a sentinel', () => {
    const reg = new SentinelRegistry()
    const { setEnvVars } = buildMaskedEnvVars(
      [{ name: 'DATABASE_URL', mode: 'mask', extract: DB_EXTRACT }],
      ['db.example.com'],
      reg,
      { DATABASE_URL: DB_URL },
    )
    const fake = setEnvVars['DATABASE_URL']!
    // Scheme, user, host, port, and database survive byte-for-byte.
    expect(fake.startsWith('postgres://alice:')).toBe(true)
    expect(fake.endsWith('@db.example.com:5432/mydb')).toBe(true)
    // The password is gone; a sentinel sits in its place.
    expect(fake).not.toContain(DB_PASSWORD)
    const m = fake.match(/:\/\/alice:(\S+)@/)
    expect(m![1]!.startsWith(SENTINEL_PREFIX)).toBe(true)
    expect(reg.lookupReal(m![1]!)).toBe(DB_PASSWORD)
    expect(reg.size).toBe(1)
  })

  test('multiple distinct captures get distinct sentinels', () => {
    const reg = new SentinelRegistry()
    const { setEnvVars } = buildMaskedEnvVars(
      [
        {
          name: 'COMPOSITE',
          mode: 'mask',
          extract: '(?:secret|backup)=([^;]+)',
        },
      ],
      ['h.example.com'],
      reg,
      { COMPOSITE: 'id=abc;secret=tok-A;backup=tok-B' },
    )
    const fake = setEnvVars['COMPOSITE']!
    expect(fake).toContain('id=abc;')
    expect(fake).not.toContain('tok-A')
    expect(fake).not.toContain('tok-B')
    const sentinels = fake.match(
      new RegExp(`${SENTINEL_PREFIX}[0-9a-f-]+`, 'g'),
    )!
    expect(sentinels).toHaveLength(2)
    expect(sentinels[0]).not.toBe(sentinels[1])
    expect(reg.lookupReal(sentinels[0]!)).toBe('tok-A')
    expect(reg.lookupReal(sentinels[1]!)).toBe('tok-B')
    expect(reg.size).toBe(2)
  })

  test('an extract sentinel only substitutes at the entry injectHosts', () => {
    const reg = new SentinelRegistry()
    const { setEnvVars } = buildMaskedEnvVars(
      [
        {
          name: 'DATABASE_URL',
          mode: 'mask',
          extract: DB_EXTRACT,
          injectHosts: ['db.example.com'],
        },
      ],
      ['db.example.com', 'evil.example.com'],
      reg,
      { DATABASE_URL: DB_URL },
    )
    const sentinel = setEnvVars['DATABASE_URL']!.match(/:\/\/alice:(\S+)@/)![1]!

    const toDb = { authorization: `Bearer ${sentinel}` }
    reg.substituteInHeaders(toDb, 'db.example.com', eq)
    expect(toDb.authorization).toBe(`Bearer ${DB_PASSWORD}`)

    const toEvil = { authorization: `Bearer ${sentinel}` }
    reg.substituteInHeaders(toEvil, 'evil.example.com', eq)
    expect(toEvil.authorization).toBe(`Bearer ${sentinel}`)
  })

  test('absent injectHosts → defaults to allowedDomains', () => {
    const reg = new SentinelRegistry()
    const { setEnvVars } = buildMaskedEnvVars(
      [{ name: 'DATABASE_URL', mode: 'mask', extract: DB_EXTRACT }],
      ['fallback.example.com'],
      reg,
      { DATABASE_URL: DB_URL },
    )
    const sentinel = setEnvVars['DATABASE_URL']!.match(/:\/\/alice:(\S+)@/)![1]!
    const headers = { authorization: sentinel }
    reg.substituteInHeaders(headers, 'fallback.example.com', eq)
    expect(headers.authorization).toBe(DB_PASSWORD)
  })

  test('a masked var that is unset in the environment is skipped', () => {
    const reg = new SentinelRegistry()
    const { setEnvVars, degradeToUnsetNames } = buildMaskedEnvVars(
      [{ name: 'NEVER_SET', mode: 'mask', extract: DB_EXTRACT }],
      [],
      reg,
      {},
    )
    expect(Object.keys(setEnvVars)).toHaveLength(0)
    expect(degradeToUnsetNames).toHaveLength(0)
    expect(reg.size).toBe(0)
  })

  test('ignores deny-mode entries (the caller unsets them directly)', () => {
    const reg = new SentinelRegistry()
    const { setEnvVars, degradeToUnsetNames } = buildMaskedEnvVars(
      [{ name: 'DATABASE_URL', mode: 'deny' }],
      [],
      reg,
      { DATABASE_URL: DB_URL },
    )
    expect(Object.keys(setEnvVars)).toHaveLength(0)
    expect(degradeToUnsetNames).toHaveLength(0)
    expect(reg.size).toBe(0)
  })

  describe('extract with no match (onExtractNoMatch)', () => {
    const noMatch = {
      name: 'DATABASE_URL',
      mode: 'mask',
      extract: 'nope=(\\S+)',
    } as const
    const env = { DATABASE_URL: DB_URL }

    test('default → "warn": variable passes through, stderr warning', () => {
      const warnSpy = spyOn(console, 'warn').mockImplementation(() => {})
      const reg = new SentinelRegistry()
      const { setEnvVars, degradeToUnsetNames } = buildMaskedEnvVars(
        [noMatch],
        ['db.example.com'],
        reg,
        env,
      )
      // Fail-open: no set, no unset — the entry is skipped entirely so
      // the variable is inherited with its real value.
      expect(Object.keys(setEnvVars)).toHaveLength(0)
      expect(degradeToUnsetNames).toHaveLength(0)
      expect(reg.size).toBe(0)
      // A loud stderr warning surfaces the config error to the operator.
      expect(warnSpy).toHaveBeenCalledTimes(1)
      const msg = warnSpy.mock.calls[0]![0] as string
      expect(msg).toContain('UNPROTECTED')
      expect(msg).toContain('DATABASE_URL')
      expect(msg).toContain('nope=(\\S+)')
      // The warning names the variable but never leaks its value.
      expect(msg).not.toContain(DB_PASSWORD)
      warnSpy.mockRestore()
    })

    test('explicit "warn" matches the default', () => {
      const warnSpy = spyOn(console, 'warn').mockImplementation(() => {})
      const reg = new SentinelRegistry()
      const { setEnvVars, degradeToUnsetNames } = buildMaskedEnvVars(
        [{ ...noMatch, onExtractNoMatch: 'warn' }],
        [],
        reg,
        env,
      )
      expect(Object.keys(setEnvVars)).toHaveLength(0)
      expect(degradeToUnsetNames).toHaveLength(0)
      expect(warnSpy).toHaveBeenCalledTimes(1)
      warnSpy.mockRestore()
    })

    test('"deny": entry degrades to unset (fail-closed)', () => {
      const warnSpy = spyOn(console, 'warn').mockImplementation(() => {})
      const reg = new SentinelRegistry()
      const { setEnvVars, degradeToUnsetNames } = buildMaskedEnvVars(
        [{ ...noMatch, onExtractNoMatch: 'deny' }],
        ['db.example.com'],
        reg,
        env,
      )
      expect(Object.keys(setEnvVars)).toHaveLength(0)
      expect(degradeToUnsetNames).toEqual(['DATABASE_URL'])
      expect(reg.size).toBe(0)
      // No stderr warning — deny is a configured outcome, not a surprise.
      expect(warnSpy).not.toHaveBeenCalled()
      warnSpy.mockRestore()
    })

    test('"error": throws with a clear message', () => {
      const reg = new SentinelRegistry()
      expect(() =>
        buildMaskedEnvVars(
          [{ ...noMatch, onExtractNoMatch: 'error' }],
          [],
          reg,
          env,
        ),
      ).toThrow(/matched nothing.*onExtractNoMatch: "error"/)
    })

    test('onExtractNoMatch is per-entry: one "deny" does not affect a sibling "warn"', () => {
      const warnSpy = spyOn(console, 'warn').mockImplementation(() => {})
      const reg = new SentinelRegistry()
      const { setEnvVars, degradeToUnsetNames } = buildMaskedEnvVars(
        [
          { ...noMatch, onExtractNoMatch: 'deny' },
          { name: 'OTHER', mode: 'mask', extract: 'nope=(\\S+)' },
        ],
        [],
        reg,
        { ...env, OTHER: 'k=v' },
      )
      expect(Object.keys(setEnvVars)).toHaveLength(0)
      expect(degradeToUnsetNames).toEqual(['DATABASE_URL'])
      expect(warnSpy).toHaveBeenCalledTimes(1)
      expect(warnSpy.mock.calls[0]![0] as string).toContain('OTHER')
      warnSpy.mockRestore()
    })
  })
})

/**
 * SandboxManager-level structured env masking on Linux: the sandboxed
 * process sees the structure-preserved fake in its environment; the real
 * credential span never appears in the wrapped command string.
 */
describe.if(isLinux)('structured env masking on Linux (bwrap)', () => {
  const VAR = 'SRT_TEST_DB_URL'

  beforeAll(async () => {
    process.env[VAR] = DB_URL
    await SandboxManager.reset()
    await SandboxManager.initialize({
      network: { allowedDomains: ['localhost'], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: ['/tmp'], denyWrite: [] },
      credentials: {
        envVars: [{ name: VAR, mode: 'mask', extract: DB_EXTRACT }],
        allowPlaintextInject: true,
      },
    })
  })

  afterAll(async () => {
    await SandboxManager.reset()
    delete process.env[VAR]
  })

  test('printenv shows the structure-preserved fake, not the password', async () => {
    const wrapped = await SandboxManager.wrapWithSandbox(`printenv ${VAR}`)
    expect(wrapped).not.toContain(DB_PASSWORD)
    const result = spawnSync(wrapped, {
      shell: true,
      encoding: 'utf8',
      timeout: 10000,
      env: { ...process.env, [VAR]: DB_URL },
    })
    expect(result.status).toBe(0)
    const seen = result.stdout.trim()
    // Scheme, user, host, port, and database survive byte-for-byte.
    expect(seen.startsWith('postgres://alice:')).toBe(true)
    expect(seen.endsWith('@db.example.com:5432/mydb')).toBe(true)
    // The password is gone; a sentinel sits in its place.
    expect(seen).not.toContain(DB_PASSWORD)
    const m = seen.match(/:\/\/alice:(\S+)@/)
    expect(m![1]!.startsWith(SENTINEL_PREFIX)).toBe(true)
    // The host-side registry maps that sentinel back to the password.
    expect(SandboxManager.getSentinelRegistry().lookupReal(m![1]!)).toBe(
      DB_PASSWORD,
    )
  })

  test('whole-value masking (no extract) is unchanged: fake is one bare sentinel', async () => {
    // Regression guard for the pre-extract behaviour: an entry without
    // extract must still swap the ENTIRE value for a single sentinel.
    await SandboxManager.reset()
    process.env[VAR] = DB_URL
    await SandboxManager.initialize({
      network: { allowedDomains: ['localhost'], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: ['/tmp'], denyWrite: [] },
      credentials: {
        envVars: [{ name: VAR, mode: 'mask' }],
        allowPlaintextInject: true,
      },
    })
    const wrapped = await SandboxManager.wrapWithSandbox(`printenv ${VAR}`)
    expect(wrapped).toMatch(
      new RegExp(`--setenv ${VAR} ${SENTINEL_PREFIX}[0-9a-f-]{36}`),
    )
    const result = spawnSync(wrapped, {
      shell: true,
      encoding: 'utf8',
      timeout: 10000,
      env: { ...process.env, [VAR]: DB_URL },
    })
    expect(result.status).toBe(0)
    const seen = result.stdout.trim()
    expect(seen.startsWith(SENTINEL_PREFIX)).toBe(true)
    // DB_URL is longer than the 47-byte base sentinel, so the mint pads the
    // sentinel to the real value's byte length (length-matched sentinels
    // keep Content-Length invariant under body substitution).
    expect(seen.length).toBe(Buffer.byteLength(DB_URL))
    expect(SandboxManager.getSentinelRegistry().lookupReal(seen)).toBe(DB_URL)

    // Restore the suite-level (extract) config for any following tests.
    await SandboxManager.reset()
    process.env[VAR] = DB_URL
    await SandboxManager.initialize({
      network: { allowedDomains: ['localhost'], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: ['/tmp'], denyWrite: [] },
      credentials: {
        envVars: [{ name: VAR, mode: 'mask', extract: DB_EXTRACT }],
        allowPlaintextInject: true,
      },
    })
  })
})

/**
 * Linux integration: an env `extract` pattern that matches nothing follows
 * the entry's `onExtractNoMatch` — default `"warn"` passes the variable
 * through unmasked with a stderr warning; `"deny"` unsets it; `"error"`
 * rejects at wrap time.
 */
describe.if(isLinux)('env extract no-match onExtractNoMatch on Linux', () => {
  const VAR = 'SRT_TEST_NOMATCH_URL'
  const SECRET = 'nomatch-real-secret-0123456789'

  async function init(onExtractNoMatch?: 'warn' | 'deny' | 'error') {
    await SandboxManager.reset()
    process.env[VAR] = SECRET
    await SandboxManager.initialize({
      network: { allowedDomains: ['localhost'], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: ['/tmp'], denyWrite: [] },
      credentials: {
        envVars: [
          {
            name: VAR,
            mode: 'mask',
            extract: 'will_not_match_(\\S+)',
            ...(onExtractNoMatch && { onExtractNoMatch }),
          },
        ],
        allowPlaintextInject: true,
      },
    })
  }

  afterAll(async () => {
    await SandboxManager.reset()
    delete process.env[VAR]
  })

  test('default ("warn"): variable passes through unmasked, stderr warning at wrap', async () => {
    await init()
    const warnSpy = spyOn(console, 'warn').mockImplementation(() => {})
    const wrapped = await SandboxManager.wrapWithSandbox(`printenv ${VAR}`)
    // A loud stderr warning surfaces the config error at wrap time.
    expect(warnSpy).toHaveBeenCalled()
    expect(warnSpy.mock.calls[0]![0] as string).toContain('UNPROTECTED')
    warnSpy.mockRestore()
    // Neither --setenv nor --unsetenv is emitted for the variable — the
    // entry is skipped entirely.
    expect(wrapped).not.toContain(`--setenv ${VAR}`)
    expect(wrapped).not.toContain(`--unsetenv ${VAR}`)
    const result = spawnSync(wrapped, {
      shell: true,
      encoding: 'utf8',
      timeout: 10000,
      env: { ...process.env, [VAR]: SECRET },
    })
    // printenv succeeds and returns the real value: fail-open means the
    // variable is inherited as-is.
    expect(result.status).toBe(0)
    expect(result.stdout.trim()).toBe(SECRET)
  })

  test('"deny": variable unset inside the sandbox (fail-closed)', async () => {
    await init('deny')
    const wrapped = await SandboxManager.wrapWithSandbox(`printenv ${VAR}`)
    // The real value never appears in the wrapped command.
    expect(wrapped).not.toContain(SECRET)
    expect(wrapped).toContain(`--unsetenv ${VAR}`)
    const result = spawnSync(wrapped, {
      shell: true,
      encoding: 'utf8',
      timeout: 10000,
      env: { ...process.env, [VAR]: SECRET },
    })
    // printenv fails: the variable does not exist inside the sandbox.
    expect(result.status).not.toBe(0)
    expect(result.stdout).not.toContain(SECRET)
  })

  test('"error": wrapWithSandbox rejects', async () => {
    await init('error')
    let thrown: unknown
    try {
      await SandboxManager.wrapWithSandbox(`printenv ${VAR}`)
    } catch (e) {
      thrown = e
    }
    expect(thrown).toBeInstanceOf(Error)
    expect((thrown as Error).message).toMatch(
      /matched nothing.*onExtractNoMatch: "error"/,
    )
  })
})

/**
 * End-to-end structured env masking: DATABASE_URL is masked with extract;
 * inside the sandbox a tool parses the password field out of the preserved
 * connection-string structure and sends it as a header; the manager proxy
 * swaps the sentinel to the real password at the injectHost only. Reuses
 * the e2e harness pattern from credential-mask.test.ts (plain HTTP
 * upstream + allowPlaintextInject + the manager's own proxy port).
 */
describe.if(isLinux)(
  'end-to-end structured env masking via SandboxManager',
  () => {
    const VAR = 'SRT_TEST_E2E_DB_URL'
    const HOST_A = 'localhost'
    const HOST_B = 'host-b.localhost'

    let upstream: Server
    let upstreamPort: number
    let lastHeaders: IncomingHttpHeaders | undefined
    let lastBody: string | undefined

    beforeAll(async () => {
      upstream = createHttpServer((req, res) => {
        lastHeaders = req.headers
        let body = ''
        req.on('data', c => (body += c))
        req.on('end', () => {
          lastBody = body
          res.writeHead(200)
          res.end('ok')
        })
      })
      await new Promise<void>(r => upstream.listen(0, '127.0.0.1', () => r()))
      upstreamPort = (upstream.address() as AddressInfo).port

      process.env[VAR] = DB_URL
      await SandboxManager.reset()
      await SandboxManager.initialize({
        network: { allowedDomains: [HOST_A, HOST_B], deniedDomains: [] },
        filesystem: { denyRead: [], allowWrite: ['/tmp'], denyWrite: [] },
        credentials: {
          envVars: [
            {
              name: VAR,
              mode: 'mask',
              extract: DB_EXTRACT,
              injectHosts: [HOST_A],
            },
          ],
          allowPlaintextInject: true,
        },
      })
    })

    afterAll(async () => {
      await SandboxManager.reset()
      delete process.env[VAR]
      await new Promise<void>(r => upstream.close(() => r()))
    })

    function runInSandbox(wrappedCommand: string) {
      return spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 10000,
        env: { ...process.env, [VAR]: DB_URL },
      })
    }

    // Async spawn — spawnSync would block the event loop and the
    // in-process proxy/upstream couldn't accept the connection.
    async function curlViaManagerProxy(
      url: string,
      bearer: string,
      body?: string,
    ): Promise<number> {
      const proxyPort = SandboxManager.getProxyPort()!
      const authToken = SandboxManager.getProxyAuthToken()!
      const args = [
        '-sS',
        '--max-time',
        '10',
        '--proxy',
        `http://srt:${authToken}@127.0.0.1:${proxyPort}`,
        '-H',
        `Authorization: Bearer ${bearer}`,
      ]
      if (body !== undefined) args.push('--data-binary', body)
      args.push(url)
      const child = spawn('curl', args)
      child.stdout.on('data', () => {})
      child.stderr.on('data', () => {})
      return new Promise(r => child.on('close', code => r(code ?? 1)))
    }

    test('parse sentinel from the fake URL → injectHost gets the real password', async () => {
      // bwrap leg: extract the password field from the masked connection
      // string inside the sandbox — the URL parses, and the field value is
      // the sentinel.
      const wrapped = await SandboxManager.wrapWithSandbox(
        `sh -c "printenv ${VAR} | sed -E 's|.*://[^:]+:([^@]+)@.*|\\\\1|'"`,
      )
      expect(wrapped).not.toContain(DB_PASSWORD)
      const result = runInSandbox(wrapped)
      expect(result.status).toBe(0)
      const sentinel = result.stdout.trim()
      expect(sentinel.startsWith(SENTINEL_PREFIX)).toBe(true)
      expect(sentinel).not.toContain(DB_PASSWORD)

      // Proxy leg: the sentinel reaches HOST_A as the real password.
      lastHeaders = undefined
      const exit = await curlViaManagerProxy(
        `http://${HOST_A}:${upstreamPort}/`,
        sentinel,
      )
      expect(exit).toBe(0)
      expect(lastHeaders?.authorization).toBe(`Bearer ${DB_PASSWORD}`)
    }, 20000)

    test('a sentinel in a POST body reaches the injectHost as the real password', async () => {
      const wrapped = await SandboxManager.wrapWithSandbox(
        `sh -c "printenv ${VAR} | sed -E 's|.*://[^:]+:([^@]+)@.*|\\\\1|'"`,
      )
      const sentinel = runInSandbox(wrapped).stdout.trim()
      expect(sentinel.startsWith(SENTINEL_PREFIX)).toBe(true)

      // Body leg: the tool POSTs the credential in a JSON payload instead
      // of a header; the manager proxy substitutes in the body stream.
      lastHeaders = undefined
      lastBody = undefined
      const exit = await curlViaManagerProxy(
        `http://${HOST_A}:${upstreamPort}/`,
        sentinel,
        `{"password":"${sentinel}"}`,
      )
      expect(exit).toBe(0)
      expect(lastBody).toBe(`{"password":"${DB_PASSWORD}"}`)
      expect(lastHeaders?.authorization).toBe(`Bearer ${DB_PASSWORD}`)
    }, 20000)

    test('a non-injectHost destination receives the sentinel unchanged', async () => {
      const wrapped = await SandboxManager.wrapWithSandbox(
        `sh -c "printenv ${VAR} | sed -E 's|.*://[^:]+:([^@]+)@.*|\\\\1|'"`,
      )
      const sentinel = runInSandbox(wrapped).stdout.trim()

      // HOST_B is allowlisted but NOT in this entry's injectHosts. The
      // proxy resolves it to loopback (a `.localhost` name) and forwards
      // the sentinel as-is — fails closed.
      lastHeaders = undefined
      const exit = await curlViaManagerProxy(
        `http://${HOST_B}:${upstreamPort}/`,
        sentinel,
      )
      expect(exit).toBe(0)
      expect(lastHeaders?.authorization).toBe(`Bearer ${sentinel}`)
      expect(lastHeaders?.authorization).not.toContain(DB_PASSWORD)
    }, 20000)
  },
)
