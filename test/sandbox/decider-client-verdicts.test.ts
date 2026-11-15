import { describe, expect, test } from 'bun:test'
import { createDecider } from '../../src/sandbox/decider-client.js'
import { fakeDecider, frameOf, type Frame } from '../helpers/fake-decider.js'

const URL_ = 'https://api.example.test/upload'
const CTX = { target: { host: 'api.example.test', port: 443 } }
const REFUSED = { action: 'deny', status: 503, mark: 'decider_unavailable' }

function verdict(id: unknown, rest: Frame): Buffer {
  return frameOf(JSON.stringify({ t: 'verdict', id, ...rest }))
}

async function until(cond: () => boolean): Promise<void> {
  for (let i = 0; i < 400 && !cond(); i++) await Bun.sleep(5)
  expect(cond()).toBe(true)
}

describe('verdicts that arrive at an unusual time', () => {
  test('a deny while the body is being read is a deny, and no body is sent', async () => {
    const d = fakeDecider([], f =>
      f.t === 'req' ? { action: 'need_body', max: 40 } : 'hang',
    )
    const dead: string[] = []
    const decider = createDecider({
      ...d.streams,
      onDead: why => dead.push(why),
    })
    await decider.hello
    // A body that never ends: the read is still in flight when the deny comes.
    const body = new ReadableStream<Uint8Array>({
      start: c => c.enqueue(new Uint8Array(10)),
    })
    const decided = decider.filterRequest(
      new Request(URL_, {
        method: 'POST',
        body,
        duplex: 'half',
      } as RequestInit),
      CTX,
    )
    await until(() => decider.bodyBytesHeld() === 40)
    d.streams.input.write(
      verdict(d.seen[0]!.id, { action: 'deny', status: 403, reason: 'no' }),
    )
    expect(await decided).toMatchObject({ action: 'deny', status: 403 })
    expect(d.seen.map(f => f.t)).toEqual(['req'])
    expect(decider.bodyBytesHeld()).toBe(0)
    expect(dead).toEqual([])
  })

  test('an allow for a request that already timed out changes nothing', async () => {
    const d = fakeDecider([], () =>
      d.seen.length === 1 ? 'hang' : { action: 'allow' },
    )
    const dead: string[] = []
    const decider = createDecider({
      ...d.streams,
      timeoutMs: 50,
      onDead: why => dead.push(why),
    })
    await decider.hello
    const timedOut = await decider.filterRequest(new Request(URL_), CTX)
    expect(timedOut).toMatchObject(REFUSED)
    d.streams.input.write(verdict(d.seen[0]!.id, { action: 'allow' }))
    // Frames are read in order, so the answer to the next request shows
    // the late allow was read and dropped: the link is alive and the
    // refusal above stands.
    const next = await decider.filterRequest(new Request(URL_), CTX)
    expect(next).toMatchObject({ action: 'allow' })
    expect(d.seen).toHaveLength(2)
    expect(dead).toEqual([])
  })

  test('a frame longer than the read limit kills the link and refuses what is pending', async () => {
    const d = fakeDecider([], () => 'hang')
    const dead: string[] = []
    const decider = createDecider({
      ...d.streams,
      onDead: why => dead.push(why),
    })
    await decider.hello
    const pending = decider.filterRequest(new Request(URL_), CTX)
    await until(() => d.seen.length === 1)
    const length = Buffer.alloc(4)
    length.writeUInt32BE((1 << 20) + 1)
    d.streams.input.write(length)
    expect(await pending).toMatchObject(REFUSED)
    expect(dead).toEqual(['oversized frame'])
    expect(await decider.filterRequest(new Request(URL_), CTX)).toMatchObject(
      REFUSED,
    )
  })
})
