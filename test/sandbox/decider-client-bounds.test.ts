import { describe, expect, test } from 'bun:test'
import { Writable } from 'node:stream'
import {
  createDecider,
  encodeBodyFrame,
  encodeFrame,
} from '../../src/sandbox/decider-client.js'
import { fakeDecider, type Frame } from '../helpers/fake-decider.js'

const URL_ = 'https://api.example.test/upload'
const CTX = { target: { host: 'api.example.test', port: 443 } }
const REFUSED = { action: 'deny', status: 503, mark: 'decider_unavailable' }

function upload(body: string | ReadableStream<Uint8Array>): Request {
  return new Request(URL_, {
    method: 'POST',
    body,
    duplex: 'half',
  } as RequestInit)
}

/** A decider that asks for every body and answers it when `release` runs. */
function holdingDecider(answer: Frame = { action: 'allow' }) {
  const bodies: Frame[] = []
  const held: Array<() => void> = []
  const d = fakeDecider([], f => {
    if (f.t === 'req') return { action: 'need_body', max: 40 }
    bodies.push(f)
    return new Promise<Frame>(res => held.push(() => res(answer)))
  })
  const release = (): void => held.splice(0).forEach(go => go())
  return { d, bodies, release }
}

async function until(cond: () => boolean): Promise<void> {
  for (let i = 0; i < 400 && !cond(); i++) await Bun.sleep(5)
  expect(cond()).toBe(true)
}

describe('body frames', () => {
  test('built in place, they are the bytes encodeFrame gives', () => {
    for (const size of [
      0,
      1,
      2,
      3,
      4,
      (3 << 16) - 1,
      3 << 16,
      (3 << 16) + 1,
      500_001,
    ]) {
      const data = Buffer.alloc(size)
      for (let i = 0; i < size; i++) data[i] = (i * 31 + size) & 0xff
      for (const cut of [false, true]) {
        const plain = encodeFrame({
          t: 'body',
          id: 7,
          data: data.toString('base64'),
          ...(cut ? { cut: true } : {}),
        })
        expect(encodeBodyFrame(7, data, cut).equals(plain)).toBe(true)
      }
    }
  })
})

describe('the budget for bodies held for the decider', () => {
  test('parallel uploads past it are refused, the rest complete, and it empties', async () => {
    const { d, bodies, release } = holdingDecider()
    const decider = createDecider({ ...d.streams, maxBodyBytesHeld: 100 })
    await decider.hello
    const all = [1, 2, 3, 4, 5].map(() =>
      decider.filterRequest(upload('x'.repeat(40)), CTX),
    )
    await until(() => bodies.length === 2)
    expect(decider.bodyBytesHeld()).toBe(80)
    release()
    const got = await Promise.all(all)
    expect(got.filter(g => g.action === 'allow')).toHaveLength(2)
    const refused = got.filter(g => g.action === 'deny')
    expect(refused).toHaveLength(3)
    for (const r of refused) expect(r).toMatchObject(REFUSED)
    // No body of a refused request reached the decider either.
    expect(bodies).toHaveLength(2)
    expect(decider.bodyBytesHeld()).toBe(0)
    const again = decider.filterRequest(upload('y'.repeat(40)), CTX)
    await until(() => bodies.length === 3)
    release()
    expect((await again).action).toBe('allow')
    decider.close()
  })

  test('is given back after a deny, a client abort, a timeout and a dead decider', async () => {
    const { d, bodies, release } = holdingDecider({
      action: 'deny',
      status: 403,
      reason: 'no',
    })
    const dead: string[] = []
    const decider = createDecider({
      ...d.streams,
      maxBodyBytesHeld: 40,
      timeoutMs: 200,
      onDead: why => dead.push(why),
    })
    await decider.hello

    const denied = decider.filterRequest(upload('x'.repeat(40)), CTX)
    await until(() => bodies.length === 1)
    expect(decider.bodyBytesHeld()).toBe(40)
    release()
    expect(await denied).toMatchObject({ action: 'deny', status: 403 })
    expect(dead).toEqual([])
    expect(decider.bodyBytesHeld()).toBe(0)

    let abort!: () => void
    const aborted = decider.filterRequest(
      upload(
        new ReadableStream<Uint8Array>({
          start(c) {
            c.enqueue(new Uint8Array(10))
            abort = () => c.error(new Error('client went away'))
          },
        }),
      ),
      CTX,
    )
    await until(() => decider.bodyBytesHeld() === 40)
    abort()
    expect(await aborted).toMatchObject(REFUSED)
    expect(decider.bodyBytesHeld()).toBe(0)

    // Never answered: the wait for the verdict on the body times out.
    const timedOut = decider.filterRequest(upload('x'.repeat(40)), CTX)
    await until(() => bodies.length === 2)
    expect(await timedOut).toMatchObject(REFUSED)
    expect(decider.bodyBytesHeld()).toBe(0)

    const pending = decider.filterRequest(upload('x'.repeat(40)), CTX)
    await until(() => bodies.length === 3)
    decider.close()
    expect(await pending).toMatchObject(REFUSED)
    expect(decider.bodyBytesHeld()).toBe(0)
    expect(dead).toEqual(['closed'])
  })
})

describe('a decider that stops reading', () => {
  test('is gone once the queue limit is passed, and every pending request is refused', async () => {
    const d = fakeDecider([], () => 'hang')
    let stalled = false
    const output = new Writable({
      write(chunk, _enc, done) {
        if (stalled) return
        d.streams.output.write(chunk)
        done()
      },
    })
    const dead: string[] = []
    const decider = createDecider({
      ...d.streams,
      output,
      maxQueuedBytes: 4000,
      timeoutMs: 60_000,
      onDead: why => dead.push(why),
    })
    await decider.hello
    stalled = true
    const all = Array.from({ length: 200 }, () =>
      decider.filterRequest(new Request(URL_), CTX),
    )
    const got = await Promise.race([Promise.all(all), Bun.sleep(3000)])
    expect(dead).toHaveLength(1)
    expect(dead[0]).toMatch(/^not reading: \d+ bytes queued$/)
    expect(got).toHaveLength(200)
    for (const g of got ?? []) expect(g).toMatchObject(REFUSED)
  })
})
