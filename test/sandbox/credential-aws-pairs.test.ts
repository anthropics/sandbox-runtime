import { describe, test, expect, spyOn } from 'bun:test'
import type { IncomingHttpHeaders } from 'node:http'
import {
  AwsPairRegistry,
  createSigv4Planner,
  registerAwsPairs,
} from '../../src/sandbox/credential-aws-pairs.js'
import {
  parseSigv4Authorization,
  sha256Hex,
  signSigv4,
  UNSIGNED_PAYLOAD,
} from '../../src/sandbox/aws-sigv4.js'
import { buildMaskedEnvVars } from '../../src/sandbox/credential-mask-env.js'
import { SentinelRegistry } from '../../src/sandbox/credential-sentinel.js'
import { SandboxRuntimeConfigSchema } from '../../src/sandbox/sandbox-config.js'
import type { CredentialEnvVarConfig } from '../../src/sandbox/sandbox-config.js'

const REAL_AKID = 'AKIAIOSFODNN7EXAMPLE'
const REAL_SECRET = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
const REAL_TOKEN = 'FQoGZXIvYXdzEXAMPLEsessiontoken'

/** Host matcher for tests: exact equality. */
const eq = (h: string, p: string) => h === p

/**
 * Run the real masked-env build so pairs register from the same
 * sentinels the sandbox would see, then register pairs.
 */
function buildPairs(
  envVars: CredentialEnvVarConfig[],
  env: Record<string, string | undefined>,
  opts: {
    awsPairs?: Parameters<typeof registerAwsPairs>[1]
    allowedDomains?: string[]
  } = {},
) {
  const sentinels = new SentinelRegistry()
  const allowedDomains = opts.allowedDomains ?? ['s3.amazonaws.com']
  const { setEnvVars } = buildMaskedEnvVars(
    envVars,
    allowedDomains,
    sentinels,
    env,
  )
  const pairs = new AwsPairRegistry()
  registerAwsPairs(
    envVars,
    opts.awsPairs,
    allowedDomains,
    setEnvVars,
    pairs,
    env,
  )
  return { pairs, setEnvVars, sentinels }
}

const CONVENTIONAL_MASK: CredentialEnvVarConfig[] = [
  { name: 'AWS_ACCESS_KEY_ID', mode: 'mask' },
  { name: 'AWS_SECRET_ACCESS_KEY', mode: 'mask' },
]

describe('registerAwsPairs', () => {
  test('auto-detects the conventional trio when masked whole-value', () => {
    const { pairs, setEnvVars } = buildPairs(
      [...CONVENTIONAL_MASK, { name: 'AWS_SESSION_TOKEN', mode: 'mask' }],
      {
        AWS_ACCESS_KEY_ID: REAL_AKID,
        AWS_SECRET_ACCESS_KEY: REAL_SECRET,
        AWS_SESSION_TOKEN: REAL_TOKEN,
      },
    )
    expect(pairs.size).toBe(1)
    const pair = pairs.lookup(setEnvVars['AWS_ACCESS_KEY_ID']!)
    expect(pair).toMatchObject({
      realAccessKeyId: REAL_AKID,
      realSecretAccessKey: REAL_SECRET,
      realSessionToken: REAL_TOKEN,
      injectHosts: ['s3.amazonaws.com'],
    })
  })

  test('session token is optional', () => {
    const { pairs, setEnvVars } = buildPairs(CONVENTIONAL_MASK, {
      AWS_ACCESS_KEY_ID: REAL_AKID,
      AWS_SECRET_ACCESS_KEY: REAL_SECRET,
    })
    expect(pairs.size).toBe(1)
    expect(
      pairs.lookup(setEnvVars['AWS_ACCESS_KEY_ID']!)?.realSessionToken,
    ).toBeUndefined()
  })

  test('injectHosts comes from the access-key-id entry', () => {
    const { pairs, setEnvVars } = buildPairs(
      [
        {
          name: 'AWS_ACCESS_KEY_ID',
          mode: 'mask',
          injectHosts: ['sts.amazonaws.com'],
        },
        { name: 'AWS_SECRET_ACCESS_KEY', mode: 'mask' },
      ],
      { AWS_ACCESS_KEY_ID: REAL_AKID, AWS_SECRET_ACCESS_KEY: REAL_SECRET },
    )
    expect(pairs.lookup(setEnvVars['AWS_ACCESS_KEY_ID']!)?.injectHosts).toEqual(
      ['sts.amazonaws.com'],
    )
  })

  test('no pair without both members masked and set', () => {
    // Secret env var unset on the host → nothing to link.
    const { pairs } = buildPairs(CONVENTIONAL_MASK, {
      AWS_ACCESS_KEY_ID: REAL_AKID,
    })
    expect(pairs.size).toBe(0)
  })

  test('masked secret without a masked access key id warns loudly', () => {
    const warnSpy = spyOn(console, 'warn').mockImplementation(() => {})
    try {
      const { pairs } = buildPairs(
        [{ name: 'AWS_SECRET_ACCESS_KEY', mode: 'mask' }],
        { AWS_SECRET_ACCESS_KEY: REAL_SECRET },
      )
      expect(pairs.size).toBe(0)
      const msg = warnSpy.mock.calls
        .map(c => c[0] as string)
        .find(m => m.includes('AWS_SECRET_ACCESS_KEY'))
      expect(msg).toBeDefined()
      expect(msg).toContain('re-sign')
    } finally {
      warnSpy.mockRestore()
    }
  })

  test('an extract entry is not usable as a pair member', () => {
    const { pairs } = buildPairs(
      [
        { name: 'AWS_ACCESS_KEY_ID', mode: 'mask', extract: '(AKIA\\w+)' },
        { name: 'AWS_SECRET_ACCESS_KEY', mode: 'mask' },
      ],
      { AWS_ACCESS_KEY_ID: REAL_AKID, AWS_SECRET_ACCESS_KEY: REAL_SECRET },
    )
    expect(pairs.size).toBe(0)
  })

  test('explicit awsPairs links non-standard names', () => {
    const envVars: CredentialEnvVarConfig[] = [
      { name: 'MY_AKID', mode: 'mask' },
      { name: 'MY_SECRET', mode: 'mask' },
      { name: 'MY_TOKEN', mode: 'mask' },
    ]
    const { pairs, setEnvVars } = buildPairs(
      envVars,
      {
        MY_AKID: REAL_AKID,
        MY_SECRET: REAL_SECRET,
        MY_TOKEN: REAL_TOKEN,
      },
      {
        awsPairs: [
          {
            accessKeyIdVar: 'MY_AKID',
            secretAccessKeyVar: 'MY_SECRET',
            sessionTokenVar: 'MY_TOKEN',
          },
        ],
      },
    )
    expect(pairs.size).toBe(1)
    expect(pairs.lookup(setEnvVars['MY_AKID']!)).toMatchObject({
      realAccessKeyId: REAL_AKID,
      realSecretAccessKey: REAL_SECRET,
      realSessionToken: REAL_TOKEN,
    })
  })

  test('an explicit pair naming a conventional var suppresses auto-detection', () => {
    const envVars: CredentialEnvVarConfig[] = [
      ...CONVENTIONAL_MASK,
      { name: 'OTHER_SECRET', mode: 'mask' },
    ]
    const { pairs, setEnvVars } = buildPairs(
      envVars,
      {
        AWS_ACCESS_KEY_ID: REAL_AKID,
        AWS_SECRET_ACCESS_KEY: REAL_SECRET,
        OTHER_SECRET: 'other-secret',
      },
      {
        awsPairs: [
          {
            accessKeyIdVar: 'AWS_ACCESS_KEY_ID',
            secretAccessKeyVar: 'OTHER_SECRET',
          },
        ],
      },
    )
    // Only the explicit pair registered; the conventional trio spec did
    // not additionally fire on the same variables.
    expect(pairs.size).toBe(1)
    expect(
      pairs.lookup(setEnvVars['AWS_ACCESS_KEY_ID']!)?.realSecretAccessKey,
    ).toBe('other-secret')
  })

  test('clear drops every pair', () => {
    const { pairs, setEnvVars } = buildPairs(CONVENTIONAL_MASK, {
      AWS_ACCESS_KEY_ID: REAL_AKID,
      AWS_SECRET_ACCESS_KEY: REAL_SECRET,
    })
    pairs.clear()
    expect(pairs.size).toBe(0)
    expect(pairs.lookup(setEnvVars['AWS_ACCESS_KEY_ID']!)).toBeUndefined()
  })
})

/** A registry with one pair, plus its fake AKID, for planner tests. */
function plannerFixture(opts: { sessionToken?: boolean } = {}) {
  const { pairs, setEnvVars } = buildPairs(
    [
      ...CONVENTIONAL_MASK,
      ...(opts.sessionToken
        ? [{ name: 'AWS_SESSION_TOKEN', mode: 'mask' } as const]
        : []),
    ],
    {
      AWS_ACCESS_KEY_ID: REAL_AKID,
      AWS_SECRET_ACCESS_KEY: REAL_SECRET,
      ...(opts.sessionToken ? { AWS_SESSION_TOKEN: REAL_TOKEN } : {}),
    },
  )
  return { pairs, fakeAkid: setEnvVars['AWS_ACCESS_KEY_ID']! }
}

/** Client-side headers signed with the FAKE credentials, like an SDK would. */
function fakeSignedHeaders(
  fakeAkid: string,
  opts: {
    method?: string
    target?: string
    contentSha?: string
    extra?: IncomingHttpHeaders
    service?: string
  } = {},
): { headers: IncomingHttpHeaders; method: string; target: string } {
  const method = opts.method ?? 'GET'
  const target = opts.target ?? '/'
  const headers: IncomingHttpHeaders = {
    'x-amz-date': '20150830T123600Z',
    ...(opts.contentSha ? { 'x-amz-content-sha256': opts.contentSha } : {}),
    ...opts.extra,
  }
  const signedHeaders = ['host', ...Object.keys(headers)]
  const { authorization } = signSigv4({
    method,
    requestTarget: target,
    headers,
    hostHeader: 's3.amazonaws.com',
    signedHeaders,
    payloadHash: opts.contentSha ?? sha256Hex(''),
    amzDate: '20150830T123600Z',
    scope: {
      date: '20150830',
      region: 'us-east-1',
      service: opts.service ?? 's3',
    },
    accessKeyId: fakeAkid,
    secretAccessKey: 'fake_value_not-the-real-secret',
  })
  headers.authorization = authorization
  return { headers, method, target }
}

describe('createSigv4Planner', () => {
  test('re-signs a header-sigv4 request with the real credentials', () => {
    const { pairs, fakeAkid } = plannerFixture()
    const plan = createSigv4Planner(pairs, undefined, eq)
    const { headers, method, target } = fakeSignedHeaders(fakeAkid)

    const decision = plan(method, target, headers, 's3.amazonaws.com')
    expect(decision?.action).toBe('resign')
    if (decision?.action !== 'resign') return

    // GET signed the empty hash but carries no x-amz-content-sha256 →
    // caller buffers (an empty body) and provides the hash.
    expect(decision.payloadHash).toBeUndefined()
    const fwd: IncomingHttpHeaders = { ...headers }
    delete fwd.host
    decision.apply(fwd, 's3.amazonaws.com', sha256Hex(''))

    const parsed = parseSigv4Authorization(fwd.authorization as string)!
    expect(parsed.accessKeyId).toBe(REAL_AKID)
    expect(parsed.region).toBe('us-east-1')
    expect(parsed.service).toBe('s3')
    // The signature matches an independent re-computation from the REAL
    // secret over the forwarded request.
    const expected = signSigv4({
      method,
      requestTarget: target,
      headers: fwd,
      hostHeader: 's3.amazonaws.com',
      signedHeaders: parsed.signedHeaders,
      payloadHash: sha256Hex(''),
      amzDate: '20150830T123600Z',
      scope: { date: '20150830', region: 'us-east-1', service: 's3' },
      accessKeyId: REAL_AKID,
      secretAccessKey: REAL_SECRET,
    })
    expect(parsed.signature).toBe(expected.signature)
  })

  test('UNSIGNED-PAYLOAD re-signs without needing the body', () => {
    const { pairs, fakeAkid } = plannerFixture()
    const plan = createSigv4Planner(pairs, undefined, eq)
    const { headers, method, target } = fakeSignedHeaders(fakeAkid, {
      method: 'PUT',
      target: '/bucket/key',
      contentSha: UNSIGNED_PAYLOAD,
    })
    const decision = plan(method, target, headers, 's3.amazonaws.com')
    expect(decision?.action).toBe('resign')
    if (decision?.action !== 'resign') return
    expect(decision.payloadHash).toBe(UNSIGNED_PAYLOAD)
    const fwd: IncomingHttpHeaders = { ...headers }
    delete fwd.host
    decision.apply(fwd, 's3.amazonaws.com', UNSIGNED_PAYLOAD)
    // The marker header is preserved, not overwritten with a hash.
    expect(fwd['x-amz-content-sha256']).toBe(UNSIGNED_PAYLOAD)
    expect(fwd.authorization).toContain(`Credential=${REAL_AKID}/`)
  })

  test('injects the real session token and adds it to SignedHeaders', () => {
    const { pairs, fakeAkid } = plannerFixture({ sessionToken: true })
    const plan = createSigv4Planner(pairs, undefined, eq)
    // Client did not send x-amz-security-token at all.
    const { headers, method, target } = fakeSignedHeaders(fakeAkid)
    const decision = plan(method, target, headers, 's3.amazonaws.com')
    expect(decision?.action).toBe('resign')
    if (decision?.action !== 'resign') return
    const fwd: IncomingHttpHeaders = { ...headers }
    delete fwd.host
    decision.apply(fwd, 's3.amazonaws.com', sha256Hex(''))
    expect(fwd['x-amz-security-token']).toBe(REAL_TOKEN)
    const parsed = parseSigv4Authorization(fwd.authorization as string)!
    expect(parsed.signedHeaders).toContain('x-amz-security-token')
  })

  test('replaces a client-sent fake session token with the real one', () => {
    const { pairs, fakeAkid } = plannerFixture({ sessionToken: true })
    const plan = createSigv4Planner(pairs, undefined, eq)
    const { headers, method, target } = fakeSignedHeaders(fakeAkid, {
      extra: { 'x-amz-security-token': 'fake_value_session-sentinel' },
    })
    const decision = plan(method, target, headers, 's3.amazonaws.com')
    expect(decision?.action).toBe('resign')
    if (decision?.action !== 'resign') return
    const fwd: IncomingHttpHeaders = { ...headers }
    delete fwd.host
    decision.apply(fwd, 's3.amazonaws.com', sha256Hex(''))
    expect(fwd['x-amz-security-token']).toBe(REAL_TOKEN)
    const parsed = parseSigv4Authorization(fwd.authorization as string)!
    // Only one occurrence — the client already listed it.
    expect(
      parsed.signedHeaders.filter(h => h === 'x-amz-security-token'),
    ).toHaveLength(1)
  })

  test('a literal x-amz-content-sha256 is pinned to the recomputed hash', () => {
    const { pairs, fakeAkid } = plannerFixture()
    const plan = createSigv4Planner(pairs, undefined, eq)
    const bodyHash = sha256Hex('Param1=value1')
    const { headers, method, target } = fakeSignedHeaders(fakeAkid, {
      method: 'POST',
      contentSha: bodyHash,
    })
    const decision = plan(method, target, headers, 's3.amazonaws.com')
    expect(decision?.action).toBe('resign')
    if (decision?.action !== 'resign') return
    // Literal hash → the proxy must buffer and recompute.
    expect(decision.payloadHash).toBeUndefined()
    const fwd: IncomingHttpHeaders = { ...headers }
    delete fwd.host
    decision.apply(fwd, 's3.amazonaws.com', bodyHash)
    expect(fwd['x-amz-content-sha256']).toBe(bodyHash)
  })

  test('an unmasked (real) access key id is never touched', () => {
    const { pairs } = plannerFixture()
    const plan = createSigv4Planner(pairs, undefined, eq)
    const { headers, method, target } = fakeSignedHeaders(REAL_AKID)
    expect(plan(method, target, headers, 's3.amazonaws.com')).toBeUndefined()
  })

  test('a destination outside injectHosts is untouched', () => {
    const { pairs, fakeAkid } = plannerFixture()
    const plan = createSigv4Planner(pairs, undefined, eq)
    const { headers, method, target } = fakeSignedHeaders(fakeAkid)
    expect(plan(method, target, headers, 'evil.example.com')).toBeUndefined()
  })

  test('non-SigV4 requests are untouched', () => {
    const { pairs } = plannerFixture()
    const plan = createSigv4Planner(pairs, undefined, eq)
    expect(
      plan('GET', '/', { authorization: 'Bearer tok' }, 's3.amazonaws.com'),
    ).toBeUndefined()
    expect(plan('GET', '/', {}, 's3.amazonaws.com')).toBeUndefined()
  })

  test('missing x-amz-date fails closed', () => {
    const { pairs, fakeAkid } = plannerFixture()
    const plan = createSigv4Planner(pairs, undefined, eq)
    const headers: IncomingHttpHeaders = {
      authorization:
        `AWS4-HMAC-SHA256 Credential=${fakeAkid}/20150830/us-east-1/s3/aws4_request, ` +
        'SignedHeaders=host, Signature=ff00',
    }
    const decision = plan('GET', '/', headers, 's3.amazonaws.com')
    expect(decision?.action).toBe('deny')
    if (decision?.action === 'deny') {
      expect(decision.reason).toContain('x-amz-date')
    }
  })

  test('a signed header missing from the request fails closed', () => {
    const { pairs, fakeAkid } = plannerFixture()
    const plan = createSigv4Planner(pairs, undefined, eq)
    const headers: IncomingHttpHeaders = {
      'x-amz-date': '20150830T123600Z',
      authorization:
        `AWS4-HMAC-SHA256 Credential=${fakeAkid}/20150830/us-east-1/s3/aws4_request, ` +
        'SignedHeaders=content-type;host;x-amz-date, Signature=ff00',
    }
    const decision = plan('GET', '/', headers, 's3.amazonaws.com')
    expect(decision?.action).toBe('deny')
    if (decision?.action === 'deny') {
      expect(decision.reason).toContain('content-type')
    }
  })

  describe('policies for non-re-signable shapes', () => {
    function shapes(fakeAkid: string) {
      const streaming = fakeSignedHeaders(fakeAkid, {
        method: 'PUT',
        target: '/bucket/key',
        contentSha: 'STREAMING-AWS4-HMAC-SHA256-PAYLOAD',
      })
      const presigned = {
        method: 'GET',
        target:
          '/key?X-Amz-Algorithm=AWS4-HMAC-SHA256' +
          `&X-Amz-Credential=${encodeURIComponent(`${fakeAkid}/20150830/us-east-1/s3/aws4_request`)}` +
          '&X-Amz-Date=20150830T123600Z&X-Amz-SignedHeaders=host' +
          '&X-Amz-Signature=ff00',
        headers: {} as IncomingHttpHeaders,
      }
      const sigv4a = {
        method: 'GET',
        target: '/',
        headers: {
          'x-amz-date': '20150830T123600Z',
          'x-amz-region-set': '*',
          authorization:
            `AWS4-ECDSA-P256-SHA256 Credential=${fakeAkid}/20150830/s3/aws4_request, ` +
            'SignedHeaders=host;x-amz-date;x-amz-region-set, Signature=ff00',
        } as IncomingHttpHeaders,
      }
      return { streaming, presigned, sigv4a } as const
    }

    test('streaming, presigned, and sigv4a deny by default, naming the knob', () => {
      const { pairs, fakeAkid } = plannerFixture()
      const plan = createSigv4Planner(pairs, undefined, eq)
      const s = shapes(fakeAkid)
      for (const kind of ['streaming', 'presigned', 'sigv4a'] as const) {
        const { method, target, headers } = s[kind]
        const decision = plan(method, target, headers, 's3.amazonaws.com')
        expect(decision?.action).toBe('deny')
        if (decision?.action === 'deny') {
          expect(decision.reason).toContain(kind)
          expect(decision.reason).toContain(`credentials.sigv4.${kind}`)
        }
      }
    })

    test('passthrough forwards each shape un-resigned when configured', () => {
      const { pairs, fakeAkid } = plannerFixture()
      const plan = createSigv4Planner(
        pairs,
        {
          streaming: 'passthrough',
          presigned: 'passthrough',
          sigv4a: 'passthrough',
        },
        eq,
      )
      const s = shapes(fakeAkid)
      for (const kind of ['streaming', 'presigned', 'sigv4a'] as const) {
        const { method, target, headers } = s[kind]
        expect(
          plan(method, target, headers, 's3.amazonaws.com'),
        ).toBeUndefined()
      }
    })

    test('policies are independent per shape', () => {
      const { pairs, fakeAkid } = plannerFixture()
      const plan = createSigv4Planner(pairs, { streaming: 'passthrough' }, eq)
      const s = shapes(fakeAkid)
      expect(
        plan(
          s.streaming.method,
          s.streaming.target,
          s.streaming.headers,
          's3.amazonaws.com',
        ),
      ).toBeUndefined()
      expect(
        plan(
          s.presigned.method,
          s.presigned.target,
          s.presigned.headers,
          's3.amazonaws.com',
        )?.action,
      ).toBe('deny')
    })
  })
})

describe('config validation for awsPairs and sigv4', () => {
  const base = {
    network: {
      allowedDomains: ['s3.amazonaws.com'],
      deniedDomains: [],
      tlsTerminate: { caCertPath: '/tmp/ca.crt', caKeyPath: '/tmp/ca.key' },
    },
    filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
  }

  test('a valid awsPairs + sigv4 config parses', () => {
    const result = SandboxRuntimeConfigSchema.safeParse({
      ...base,
      credentials: {
        envVars: [
          { name: 'MY_AKID', mode: 'mask' },
          { name: 'MY_SECRET', mode: 'mask' },
        ],
        awsPairs: [
          { accessKeyIdVar: 'MY_AKID', secretAccessKeyVar: 'MY_SECRET' },
        ],
        sigv4: { streaming: 'passthrough' },
      },
    })
    expect(result.success).toBe(true)
  })

  test('a pair member must reference a masked envVars entry', () => {
    const result = SandboxRuntimeConfigSchema.safeParse({
      ...base,
      credentials: {
        envVars: [{ name: 'MY_AKID', mode: 'mask' }],
        awsPairs: [
          { accessKeyIdVar: 'MY_AKID', secretAccessKeyVar: 'MISSING_VAR' },
        ],
      },
    })
    expect(result.success).toBe(false)
    expect(JSON.stringify(result.error?.issues)).toContain('MISSING_VAR')
  })

  test('a mode "deny" entry is not a valid pair member', () => {
    const result = SandboxRuntimeConfigSchema.safeParse({
      ...base,
      credentials: {
        envVars: [
          { name: 'MY_AKID', mode: 'mask' },
          { name: 'MY_SECRET', mode: 'deny' },
        ],
        awsPairs: [
          { accessKeyIdVar: 'MY_AKID', secretAccessKeyVar: 'MY_SECRET' },
        ],
      },
    })
    expect(result.success).toBe(false)
  })

  test('an extract/decode entry is not a valid pair member', () => {
    const result = SandboxRuntimeConfigSchema.safeParse({
      ...base,
      credentials: {
        envVars: [
          { name: 'MY_AKID', mode: 'mask', extract: '(AKIA\\w+)' },
          { name: 'MY_SECRET', mode: 'mask' },
        ],
        awsPairs: [
          { accessKeyIdVar: 'MY_AKID', secretAccessKeyVar: 'MY_SECRET' },
        ],
      },
    })
    expect(result.success).toBe(false)
    expect(JSON.stringify(result.error?.issues)).toContain('whole-value')
  })

  test('a variable cannot belong to two pairs', () => {
    const result = SandboxRuntimeConfigSchema.safeParse({
      ...base,
      credentials: {
        envVars: [
          { name: 'A', mode: 'mask' },
          { name: 'B', mode: 'mask' },
          { name: 'C', mode: 'mask' },
        ],
        awsPairs: [
          { accessKeyIdVar: 'A', secretAccessKeyVar: 'B' },
          { accessKeyIdVar: 'C', secretAccessKeyVar: 'B' },
        ],
      },
    })
    expect(result.success).toBe(false)
    expect(JSON.stringify(result.error?.issues)).toContain('more than one')
  })

  test('sigv4 rejects unknown policies and keys', () => {
    expect(
      SandboxRuntimeConfigSchema.safeParse({
        ...base,
        credentials: {
          envVars: [{ name: 'X', mode: 'mask' }],
          sigv4: { streaming: 'allow' },
        },
      }).success,
    ).toBe(false)
    expect(
      SandboxRuntimeConfigSchema.safeParse({
        ...base,
        credentials: {
          envVars: [{ name: 'X', mode: 'mask' }],
          sigv4: { headerSigv4: 'deny' },
        },
      }).success,
    ).toBe(false)
  })
})
