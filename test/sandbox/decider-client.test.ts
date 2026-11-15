import { describe, expect, test } from 'bun:test'
import { PassThrough } from 'node:stream'
import {
  createDecider,
  encodeFrame,
  isEgressEntry,
  reqFrameFields,
} from '../../src/sandbox/decider-client.js'
import { fakeDecider, frameOf, type Frame } from '../helpers/fake-decider.js'

describe('the decider link', () => {
  test('violations kill the link: an unknown id, a duplicate key, a credential header in setHeaders, an empty optional', async () => {
    const cases: Array<[string, (f: Frame) => Buffer]> = [
      [
        'unknown id',
        f =>
          frameOf(
            JSON.stringify({
              t: 'verdict',
              id: Number(f.id) + 7,
              action: 'deny',
              status: 403,
            }),
          ),
      ],
      [
        'duplicate key',
        f =>
          frameOf(
            `{"t":"verdict","id":${f.id},"action":"deny","status":403,"status":404}`,
          ),
      ],
      [
        'credential header set',
        f =>
          frameOf(
            JSON.stringify({
              t: 'verdict',
              id: f.id,
              action: 'allow',
              setHeaders: { authorization: ['Bearer x'] },
            }),
          ),
      ],
      [
        'empty optional',
        f =>
          frameOf(
            JSON.stringify({
              t: 'verdict',
              id: f.id,
              action: 'allow',
              removeHeaders: [],
            }),
          ),
      ],
      [
        'a field the protocol does not have',
        f =>
          frameOf(
            JSON.stringify({
              t: 'verdict',
              id: f.id,
              action: 'allow',
              extra: true,
            }),
          ),
      ],
      [
        'credential header set in another spelling',
        f =>
          frameOf(
            JSON.stringify({
              t: 'verdict',
              id: f.id,
              action: 'allow',
              setHeaders: { x_api_key: ['k'] },
            }),
          ),
      ],
      [
        'framing header removed',
        f =>
          frameOf(
            JSON.stringify({
              t: 'verdict',
              id: f.id,
              action: 'allow',
              removeHeaders: ['content-length'],
            }),
          ),
      ],
      [
        'credential class without a value',
        f =>
          frameOf(
            JSON.stringify({
              t: 'verdict',
              id: f.id,
              action: 'allow',
              cred: 'session-token',
            }),
          ),
      ],
      [
        'status as a string',
        f =>
          frameOf(
            `{"t":"verdict","id":${f.id},"action":"deny","status":"403"}`,
          ),
      ],
      [
        'C1 control in a reason',
        f =>
          frameOf(
            JSON.stringify({
              t: 'verdict',
              id: f.id,
              action: 'deny',
              status: 403,
              reason: 'a\u0085b',
            }),
          ),
      ],
      [
        'upper-case header name',
        f =>
          frameOf(
            JSON.stringify({
              t: 'verdict',
              id: f.id,
              action: 'allow',
              setHeaders: { 'X-A': ['1'] },
            }),
          ),
      ],
      [
        'credential with spaces',
        f =>
          frameOf(
            JSON.stringify({
              t: 'verdict',
              id: f.id,
              action: 'allow',
              cred: 'c',
              credential: ' v ',
            }),
          ),
      ],
      [
        'null',
        f =>
          frameOf(
            `{"t":"verdict","id":${f.id},"action":"deny","status":403,"reason":null}`,
          ),
      ],
    ]
    for (const [name, make] of cases) {
      const toProxy = new PassThrough()
      const fromProxy = new PassThrough()
      let hello = false
      let buf = Buffer.alloc(0)
      fromProxy.on('data', (c: Buffer) => {
        buf = Buffer.concat([buf, c])
        while (buf.length >= 4 && buf.length >= 4 + buf.readUInt32BE(0)) {
          const f = JSON.parse(
            buf.subarray(4, 4 + buf.readUInt32BE(0)).toString(),
          ) as Frame
          buf = buf.subarray(4 + buf.readUInt32BE(0))
          if (!hello) {
            hello = true
            toProxy.write(
              frameOf(
                JSON.stringify({
                  t: 'hello',
                  proto: 1,
                  allowedDomains: [],
                  deniedDomains: [],
                }),
              ),
            )
          } else toProxy.write(make(f))
        }
      })
      const dead: string[] = []
      const decider = createDecider({
        input: toProxy,
        output: fromProxy,
        timeoutMs: 1000,
        onDead: why => dead.push(why),
      })
      await decider.hello
      const v = await decider.filterRequest(
        new Request('https://api.example.test/x'),
      )
      expect(v, name).toMatchObject({ action: 'deny', status: 503 })
      expect(dead, name).toHaveLength(1)
    }
  })

  test('an output stream that closes without an error kills the link', async () => {
    const d = fakeDecider([], () => ({ action: 'allow' }))
    const dead: string[] = []
    const decider = createDecider({
      ...d.streams,
      onDead: why => dead.push(why),
    })
    await decider.hello
    // As Node's socket on the output descriptor ends up when the peer closes
    // its reading end: destroyed, with no error for a later write to report.
    await new Promise<void>(resolve => {
      d.streams.output.once('close', () => resolve())
      d.streams.output.destroy()
    })
    expect(dead).toEqual(['decider closed the output stream'])
    expect(
      await decider.filterRequest(new Request('https://api.example.test/x'), {
        target: { host: 'api.example.test', port: 443 },
      }),
    ).toMatchObject({
      action: 'deny',
      status: 503,
      mark: 'decider_unavailable',
    })
    expect(d.seen).toHaveLength(0)
  })

  test('a credential must be 1 to 8 KiB of printable ASCII without spaces, taken as is', async () => {
    const bad = [
      '',
      'a b',
      'a\tb',
      'ab\r\nX-Evil: 1',
      'a\u0085b',
      '\u00e9',
      'x'.repeat(8193),
    ]
    for (const credential of bad) {
      const d = fakeDecider([], () => ({
        action: 'allow',
        cred: 'session-token',
        credential,
      }))
      const dead: string[] = []
      const decider = createDecider({
        ...d.streams,
        onDead: why => dead.push(why),
      })
      await decider.hello
      const v = await decider.filterRequest(
        new Request('https://api.example.test/x'),
        { target: { host: 'api.example.test', port: 443 } },
      )
      expect(v, JSON.stringify(credential.slice(0, 20))).toMatchObject({
        action: 'deny',
        status: 503,
      })
      expect(dead).toHaveLength(1)
    }
    const d = fakeDecider([], () => ({
      action: 'allow',
      cred: 'session-token',
      credential: '~'.repeat(8192),
    }))
    const decider = createDecider(d.streams)
    await decider.hello
    const v = await decider.filterRequest(
      new Request('https://api.example.test/x'),
      { target: { host: 'api.example.test', port: 443 } },
    )
    expect(v.setHeaders).toContainEqual([
      'authorization',
      'Bearer ' + '~'.repeat(8192),
    ])
    decider.close()
  })

  test('credential placement: Bearer by default, Basic x-access-token for github on github.com', async () => {
    for (const [host, want] of [
      ['api.github.com', 'Bearer tok'],
      [
        'github.com',
        'Basic ' + Buffer.from('x-access-token:tok').toString('base64'),
      ],
    ] as const) {
      const d = fakeDecider([], () => ({
        action: 'allow',
        cred: 'github',
        credential: 'tok',
      }))
      const decider = createDecider({
        ...d.streams,
        credentialPlacements: [
          {
            class: 'github',
            host: 'github.com',
            scheme: 'basic',
            user: 'x-access-token',
          },
        ],
      })
      await decider.hello
      const v = await decider.filterRequest(new Request(`https://${host}/x`), {
        target: { host, port: 443 },
      })
      expect(v.setHeaders).toContainEqual(['authorization', want])
      expect(v.removeHeaders).toEqual(
        expect.arrayContaining([
          'authorization',
          'proxy-authorization',
          'cookie',
          'x-api-key',
        ]),
      )
      decider.close()
    }
  })

  test('the req frame carries the TLS server name when the proxy knows it', async () => {
    const d = fakeDecider([], () => ({ action: 'deny', status: 403 }))
    const decider = createDecider({ ...d.streams, timeoutMs: 2000 })
    await decider.hello
    await decider.filterRequest(new Request('https://api.example.test/x'), {
      sni: 'api.example.test',
    })
    await decider.filterRequest(new Request('https://api.example.test/y'))
    expect(d.seen[0]).toMatchObject({ t: 'req', sni: 'api.example.test' })
    expect('sni' in d.seen[1]!).toBe(false)
    decider.close()
  })

  test("the decider's hello must be exactly proto 1 and both egress lists", async () => {
    const hellos = [
      {
        t: 'hello',
        proto: 1,
        allowedDomains: [],
        deniedDomains: [],
        extra: [],
      },
      { t: 'hello', proto: 2, allowedDomains: [], deniedDomains: [] },
      { t: 'hello', proto: 1, allowedDomains: [] },
      {
        t: 'hello',
        proto: 1,
        allowedDomains: ['Example.test'],
        deniedDomains: [],
      },
      {
        t: 'hello',
        proto: 1,
        allowedDomains: ['a.test', 'a.test'],
        deniedDomains: [],
      },
      { t: 'verdict', id: 1, action: 'deny', status: 403 },
    ]
    for (const h of hellos) {
      const toProxy = new PassThrough()
      const fromProxy = new PassThrough()
      fromProxy.once('data', () => toProxy.write(encodeFrame(h)))
      const dead: string[] = []
      const decider = createDecider({
        input: toProxy,
        output: fromProxy,
        onDead: why => dead.push(why),
      })
      // eslint-disable-next-line @typescript-eslint/await-thenable -- bun:test types .rejects.toThrow() as void; the await is required at runtime
      await expect(decider.hello, JSON.stringify(h)).rejects.toThrow()
      expect(dead, JSON.stringify(h)).toEqual(['bad hello'])
    }
  })
})

describe('reqFrameFields: the decider limits, counted in UTF-8 bytes', () => {
  const at = (target: string, rawHeaders: string[] = []) =>
    reqFrameFields(new Request('https://api.example.test/'), {
      target: { host: 'api.example.test', port: 443 },
      requestTarget: target,
      rawHeaders: ['Host', 'api.example.test', ...rawHeaders],
    })
  test('a 2 MiB query is refused (the whole frame past 1 MiB); a 900 KiB one is not', () => {
    expect(typeof at('/x?' + 'q'.repeat(2 * 1024 * 1024))).toBe('string')
    expect(typeof at('/x?' + 'q'.repeat(900 * 1024))).toBe('object')
  })
  test('a path of 8 KiB in bytes passes; one byte more, in two-byte characters, does not', () => {
    expect(typeof at('/' + '\u00e9'.repeat(4095) + 'a')).toBe('object') // 1 + 8190 + 1 = 8192 bytes
    expect(typeof at('/' + '\u00e9'.repeat(4096))).toBe('string') // 8193 bytes, 4097 UTF-16 units
  })
  test('header bytes: 64 KiB of names and values, each name counted once', () => {
    const big = '\u00e9'.repeat(32767) // 65534 bytes, 32767 UTF-16 units
    expect(typeof at('/', ['x-a', big])).toBe('string') // 3 + 65534 > 65536
    expect(typeof at('/', ['x', big])).toBe('object') // 1 + 65534 <= 65536
    const name = 'n'.repeat(2000)
    const many: string[] = []
    for (let i = 0; i < 40; i++) many.push(name, 'v'.repeat(10))
    expect(typeof at('/', many)).toBe('object') // 2000 + 400, not 40 * 2010
  })
  test('header values: at most 190, Host apart', () => {
    const vals = (n: number) =>
      Array.from({ length: n }, (_, i) => ['x-v', String(i)]).flat()
    expect(typeof at('/', vals(190))).toBe('object')
    expect(typeof at('/', vals(191))).toBe('string')
  })
  test('control characters in a header value, C1 included, are refused', () => {
    expect(typeof at('/', ['x-a', 'a\u0085b'])).toBe('string')
    expect(typeof at('/', ['x-a', 'a\tb'])).toBe('object')
  })
})

describe('isEgressEntry: the entries of the decider hello', () => {
  test.each([
    'api.example.test',
    'api.example.test:443',
    '*.example.test',
    '*.example.test:8443',
    '127.0.0.1',
    '127.0.0.1:80',
    '::1',
    '[::1]:443',
    '[2001:db8::1]',
  ])('accepts %p', entry => {
    expect(isEgressEntry(entry)).toBe(true)
  })
  test.each([
    '',
    '*',
    '*.test',
    'Api.example.test',
    'https://api.example.test',
    'api.example.test/x',
    'api.example.test:0',
    'api.example.test:65536',
    'api.example.test:',
    '[api.example.test]:443',
    '-a.example.test',
    'example.123',
    '1.2.3',
  ])('refuses %p', entry => {
    expect(isEgressEntry(entry)).toBe(false)
  })
})

describe('verdicts past the protocol limits kill the link', () => {
  test('setHeaders past 190 values, removeHeaders past 190 names', async () => {
    const tooMany = (n: number): string[] =>
      Array.from({ length: n }, (_, i) => `x-h-${i}`)
    for (const [label, v, ok] of [
      ['190 removals', { removeHeaders: tooMany(190) }, true],
      ['191 removals', { removeHeaders: tooMany(191) }, false],
      ['190 set values', { setHeaders: { 'x-s': tooMany(190) } }, true],
      ['191 set values', { setHeaders: { 'x-s': tooMany(191) } }, false],
    ] as const) {
      const d = fakeDecider([], () => ({ action: 'allow', ...v }))
      const dead: string[] = []
      const decider = createDecider({
        ...d.streams,
        onDead: why => dead.push(why),
      })
      await decider.hello
      const got = await decider.filterRequest(
        new Request('https://api.example.test/x'),
        { target: { host: 'api.example.test', port: 443 } },
      )
      expect(got.action, label).toBe(ok ? 'allow' : 'deny')
      expect(dead, label).toHaveLength(ok ? 0 : 1)
      decider.close()
    }
  })
})

describe('need_body on a body longer than max', () => {
  test('one branch of a tee whose other branch is still open: cut at max and decided at once', async () => {
    // As decideAndRespond hands it over: the request body is one branch of a
    // tee, and the other (for the upstream) is not read until the verdict.
    const source = new ReadableStream<Uint8Array>({
      start(c) {
        for (let i = 0; i < 32; i++) c.enqueue(new Uint8Array(64 << 10))
      },
    })
    const [forDecider, forUpstream] = source.tee()
    void forUpstream
    const d = fakeDecider([], f =>
      f.t === 'req'
        ? { action: 'need_body', max: 1 << 20 }
        : { action: 'allow' },
    )
    const decider = createDecider(d.streams)
    await decider.hello
    const verdict = await decider.filterRequest(
      new Request('https://api.example.test/x', {
        method: 'POST',
        body: forDecider,
        duplex: 'half',
      }),
      { target: { host: 'api.example.test', port: 443 } },
    )
    expect(verdict.action).toBe('allow')
    const body = d.seen.find(f => f.t === 'body')!
    expect(body.cut).toBe(true)
    expect(Buffer.from(String(body.data), 'base64').length).toBe(1 << 20)
    decider.close()
  }, 10_000)
})

describe('each deny says where it came from (its mark)', () => {
  test('the decider, the proxy past the limits, and the decider unavailable', async () => {
    const d = fakeDecider([], () => ({ action: 'deny', status: 403 }))
    const decider = createDecider(d.streams)
    await decider.hello
    const info = { target: { host: 'api.example.test', port: 443 } }
    expect(
      await decider.filterRequest(
        new Request('https://api.example.test/x'),
        info,
      ),
    ).toMatchObject({ action: 'deny', status: 403, mark: 'decider' })
    expect(
      await decider.filterRequest(new Request('https://api.example.test/'), {
        ...info,
        requestTarget: '/' + 'a'.repeat(9 << 10),
      }),
    ).toMatchObject({ action: 'deny', status: 400, mark: 'bad_request' })
    decider.close()
    expect(
      await decider.filterRequest(
        new Request('https://api.example.test/x'),
        info,
      ),
    ).toMatchObject({
      action: 'deny',
      status: 503,
      mark: 'decider_unavailable',
    })
  })
})
