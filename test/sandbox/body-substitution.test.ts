import { describe, test, expect } from 'bun:test'
import { randomBytes } from 'node:crypto'
import type { IncomingMessage } from 'node:http'
import type { IncomingHttpHeaders } from 'node:http'
import { Writable } from 'node:stream'
import {
  allLengthMatched,
  createBodySubstitutionTransform,
  prepareBodySubstitution,
  type SentinelBufferPair,
} from '../../src/sandbox/body-substitution.js'

const pair = (sentinel: string, real: string): SentinelBufferPair => ({
  sentinel: Buffer.from(sentinel),
  realValue: Buffer.from(real),
})

/** Run `chunks` through a fresh transform and collect the full output. */
async function run(
  pairs: SentinelBufferPair[],
  chunks: Buffer[],
): Promise<Buffer> {
  const t = createBodySubstitutionTransform(pairs)
  const out: Buffer[] = []
  const done = new Promise<void>((resolve, reject) => {
    t.on('end', resolve)
    t.on('error', reject)
  })
  t.on('data', (c: Buffer) => out.push(c))
  for (const c of chunks) t.write(c)
  t.end()
  await done
  return Buffer.concat(out)
}

const SENTINEL = 'fake_value_0f0f0f0f-1111-4222-8333-444455556666'
const REAL = 'ghp_realsecret_abcdef0123456789_padpadpadpadpad' // same length

describe('createBodySubstitutionTransform', () => {
  test('sentinel split across every chunk boundary offset', async () => {
    const body = Buffer.from(`{"key":"${SENTINEL}","other":1}`)
    const expected = Buffer.from(`{"key":"${REAL}","other":1}`)
    for (let i = 0; i <= body.length; i++) {
      const out = await run(
        [pair(SENTINEL, REAL)],
        [body.subarray(0, i), body.subarray(i)],
      )
      expect(out.equals(expected)).toBe(true)
    }
  })

  test('multiple occurrences in one body are all replaced', async () => {
    const body = Buffer.from(`${SENTINEL} and ${SENTINEL}, plus ${SENTINEL}`)
    const out = await run([pair(SENTINEL, REAL)], [body])
    expect(out.toString()).toBe(`${REAL} and ${REAL}, plus ${REAL}`)
  })

  test('sentinel at the very start and very end of the body', async () => {
    const body = Buffer.from(`${SENTINEL}-middle-${SENTINEL}`)
    const out = await run([pair(SENTINEL, REAL)], [body])
    expect(out.toString()).toBe(`${REAL}-middle-${REAL}`)
    // Body that IS exactly one sentinel.
    const only = await run([pair(SENTINEL, REAL)], [Buffer.from(SENTINEL)])
    expect(only.toString()).toBe(REAL)
  })

  test('multiple sentinels of different lengths, interleaved', async () => {
    const short = pair('fake_value_short-aaaa-4bbb-8ccc-ddddeeee', 'tok-A')
    const long = pair(SENTINEL + '_extra_padding_zzz', 'much-longer-real-B')
    const body = Buffer.from(
      `a=${short.sentinel.toString()}&b=${long.sentinel.toString()}&c=${short.sentinel.toString()}`,
    )
    // Feed byte-by-byte to force the hold-back on every boundary.
    const chunks = Array.from({ length: body.length }, (_, i) =>
      body.subarray(i, i + 1),
    )
    const out = await run([short, long], chunks)
    expect(out.toString()).toBe('a=tok-A&b=much-longer-real-B&c=tok-A')
  })

  test('binary body without sentinels passes through byte-identical', async () => {
    const body = randomBytes(64 * 1024)
    const out = await run(
      [pair(SENTINEL, REAL)],
      [body.subarray(0, 100), body.subarray(100, 40000), body.subarray(40000)],
    )
    expect(out.equals(body)).toBe(true)
  })

  test('empty body produces empty output', async () => {
    const out = await run([pair(SENTINEL, REAL)], [])
    expect(out.length).toBe(0)
  })

  test('backpressure: correct output through a slow consumer', async () => {
    const t = createBodySubstitutionTransform([pair(SENTINEL, REAL)])
    const received: Buffer[] = []
    const slow = new Writable({
      highWaterMark: 1024,
      write(chunk: Buffer, _enc, cb) {
        received.push(chunk)
        setImmediate(cb)
      },
    })
    const piece = Buffer.from(`xx${SENTINEL}yy`)
    const total = 4096
    const done = new Promise<void>((resolve, reject) => {
      slow.on('finish', resolve)
      slow.on('error', reject)
      t.on('error', reject)
    })
    t.pipe(slow)
    let sawBackpressure = false
    for (let i = 0; i < total; i++) {
      if (!t.write(piece)) {
        sawBackpressure = true
        await new Promise<void>(r => t.once('drain', r))
      }
    }
    t.end()
    await done
    expect(sawBackpressure).toBe(true)
    expect(Buffer.concat(received).toString()).toBe(`xx${REAL}yy`.repeat(total))
  })
})

describe('allLengthMatched', () => {
  test('true only when every pair has equal byte lengths', () => {
    expect(allLengthMatched([pair(SENTINEL, REAL)])).toBe(true)
    expect(allLengthMatched([pair(SENTINEL, 'short')])).toBe(false)
    expect(allLengthMatched([pair(SENTINEL, REAL), pair('abc', 'de')])).toBe(
      false,
    )
  })
})

describe('prepareBodySubstitution', () => {
  const msg = (method: string, headers: IncomingHttpHeaders = {}) =>
    ({ method, headers }) as IncomingMessage

  test('undefined source or bodyless method → no transform', () => {
    const fwd: IncomingHttpHeaders = { 'content-length': '10' }
    expect(
      prepareBodySubstitution(undefined, msg('POST'), fwd, 'h'),
    ).toBeUndefined()
    expect(
      prepareBodySubstitution(
        () => [pair(SENTINEL, REAL)],
        msg('GET'),
        fwd,
        'h',
      ),
    ).toBeUndefined()
    expect(fwd['content-length']).toBe('10')
  })

  test('GET that declares a body still gets the transform', () => {
    // GET-with-body APIs are legal HTTP and forwarded; only a GET with no
    // declared body keeps the bare pipe.
    const fwd: IncomingHttpHeaders = { 'content-length': '10' }
    const t = prepareBodySubstitution(
      () => [pair(SENTINEL, REAL)],
      msg('GET', { 'content-length': '10' }),
      fwd,
      'h',
    )
    expect(t?.transform).toBeDefined()
    expect(t?.mayChangeLength).toBe(false)
  })

  test('no injectable pairs at the host → no transform, headers untouched', () => {
    const fwd: IncomingHttpHeaders = { 'content-length': '10' }
    expect(
      prepareBodySubstitution(() => [], msg('POST'), fwd, 'h'),
    ).toBeUndefined()
    expect(fwd['content-length']).toBe('10')
  })

  test('Content-Encoding on the request skips substitution (fail-safe)', () => {
    const fwd: IncomingHttpHeaders = { 'content-length': '10' }
    const t = prepareBodySubstitution(
      () => [pair(SENTINEL, REAL)],
      msg('POST', { 'content-encoding': 'gzip' }),
      fwd,
      'h',
    )
    expect(t).toBeUndefined()
    expect(fwd['content-length']).toBe('10')
  })

  test('length-matched pairs keep Content-Length verbatim', () => {
    const fwd: IncomingHttpHeaders = { 'content-length': '10' }
    const t = prepareBodySubstitution(
      () => [pair(SENTINEL, REAL)],
      msg('POST'),
      fwd,
      'h',
    )
    expect(t?.transform).toBeDefined()
    expect(t?.mayChangeLength).toBe(false)
    expect(fwd['content-length']).toBe('10')
  })

  test('non-length-matched pairs keep Content-Length and flag mayChangeLength', () => {
    const fwd: IncomingHttpHeaders = { 'content-length': '10' }
    const t = prepareBodySubstitution(
      () => [pair(SENTINEL, REAL), pair('fake_value_odd-size', 'tiny')],
      msg('POST'),
      fwd,
      'h',
    )
    expect(t?.transform).toBeDefined()
    expect(t?.mayChangeLength).toBe(true)
    expect(fwd['content-length']).toBe('10')
  })
})
