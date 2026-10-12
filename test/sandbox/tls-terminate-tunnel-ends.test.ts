import { afterEach, beforeAll, describe, expect, test } from 'bun:test'
import { spawn } from 'node:child_process'
import { EventEmitter, once } from 'node:events'
import { join } from 'node:path'
import {
  boundTunnel,
  TUNNEL_TIMEOUTS,
} from '../../src/sandbox/tls-terminate-proxy.js'
import { SERVES_EMITTED_CONNECTIONS } from '../helpers/emitted-connections.js'

// Every way a TLS-terminated tunnel can end frees its slot, its upstream
// connection and the bytes counted for it within a bounded time, whatever
// its client or its upstream does or leaves undone.
//
// The runtimes differ in what their servers do for a connection handed to
// them, so the scenarios (test/fixtures/tunnel-ends.mjs) run as children,
// under Node and under Bun, against dist/.

const FIXTURE = join(import.meta.dir, '..', 'fixtures', 'tunnel-ends.mjs')

type Outcome = {
  status?: number
  second?: number | false
  statuses?: number[]
  advertised?: string
  closedAfterMs: number | 'open'
  closeNotify: boolean
  nextConnect: number
  heldBytes: number
  upstream?: number
  slotFreeAfterMs?: number | 'held'
}

const RUNS = [
  { name: 'Node', bin: 'node', how: 'accepted' },
  ...(SERVES_EMITTED_CONNECTIONS
    ? [
        { name: 'Bun', bin: process.execPath, how: 'accepted' },
        { name: 'Bun', bin: process.execPath, how: 'handed' },
      ]
    : []),
]

/** The children run side by side, from the first that is asked for. */
let runs: Array<Promise<Record<string, Outcome>>> | undefined
const outcomeOf = (i: number): Promise<Record<string, Outcome>> =>
  (runs ??= RUNS.map(({ bin, how }) => run(bin, how)))[i]!

function run(bin: string, how: string): Promise<Record<string, Outcome>> {
  return new Promise((resolve, reject) => {
    const child = spawn(bin, [FIXTURE, how], {
      stdio: ['ignore', 'pipe', 'inherit'],
    })
    let out = ''
    child.stdout.on('data', (d: Buffer) => (out += d.toString()))
    child.once('error', reject)
    child.once('close', () =>
      resolve(JSON.parse(out) as Record<string, Outcome>),
    )
  })
}

/** Timers do not fire early, but the two ends do not start timing at once. */
const EARLY_MS = 100
/** A busy machine. Well under the fixture's GIVE_UP_MS. */
const LATE_MS = 1_500

/** The tunnel closed `ms` (to `lastMs`) on, and nothing of it is left. */
function expectClosed(o: Outcome, ms: number, lastMs = ms): void {
  expect(o.closedAfterMs).toBeNumber()
  expect(o.closedAfterMs as number).toBeGreaterThanOrEqual(ms - EARLY_MS)
  expect(o.closedAfterMs as number).toBeLessThan(lastMs + LATE_MS)
  expect(o).toMatchObject({ nextConnect: 200, heldBytes: 0 })
  if (o.upstream !== undefined) expect(o.upstream).toBe(0)
}

test('the default timeouts', () => {
  expect(TUNNEL_TIMEOUTS).toEqual({
    firstRequestMs: 10_000,
    keepAliveMs: 5_000,
    stalledMs: 300_000,
  })
})

// Under Bun a tunnel's socket does not hold the process once the listener
// is unref'd (under Node it does), so the tunnel's timers must not either.
test.skipIf(!SERVES_EMITTED_CONNECTIONS)(
  'an open tunnel does not keep a process from ending',
  async () => {
    const child = spawn(
      process.execPath,
      [FIXTURE, 'accepted', 'exit with a tunnel open'],
      { stdio: 'inherit' },
    )
    const giveUp = setTimeout(() => child.kill('SIGKILL'), 5_000)
    const [code] = (await once(child, 'exit')) as [number | null]
    clearTimeout(giveUp)
    expect(code).toBe(0)
  },
  10_000,
)

// What no client can be made to time, or Bun 1.4.2 to serve (a second
// request while the first is owed its response), with stand-ins for the parts.
describe('with stand-ins', () => {
  const sleep = (ms: number): Promise<void> =>
    new Promise(r => setTimeout(r, ms))
  const part = (more: object = {}): EventEmitter =>
    Object.assign(new EventEmitter(), more)
  const request = (): EventEmitter => {
    const req = part({ complete: true, unpipe: () => req, resume: () => req })
    return req
  }
  const sockets: EventEmitter[] = []
  afterEach(() => {
    for (const socket of sockets.splice(0)) socket.emit('close')
  })
  /** A tunnel bounded to 40 ms each way, and what is done to it. */
  function tunnel(paused = false, handshakeDone = () => true) {
    const done: string[] = []
    const inner = part()
    const socket = part({
      destroyed: false,
      destroy: () => done.push('destroy'),
    })
    sockets.push(socket)
    const tls = part({
      bytesRead: 7,
      isPaused: () => paused,
      writableEnded: false,
      end: () =>
        Object.assign(tls, { writableEnded: true }) && done.push('end'),
    })
    boundTunnel(
      inner as never,
      tls as never,
      socket as never,
      { firstRequestMs: 40, keepAliveMs: 40, stalledMs: 40 },
      handshakeDone,
    )
    return { done, inner, socket }
  }

  test('a whole request whose last bytes paused its tunnel: closed once it has not moved', async () => {
    const { done, inner, socket } = tunnel(true)
    inner.emit('request', request(), part())
    await sleep(130)
    expect(done[0]).toBe('destroy')
    // And left alone from then on.
    socket.emit('close')
    const calls = done.length
    await sleep(100)
    expect(done).toHaveLength(calls)
  })

  test('a handshake under way is left to its own deadline', async () => {
    let shaken = false
    const { done } = tunnel(false, () => shaken)
    await sleep(100)
    expect(done).toEqual([])
    shaken = true
    await sleep(60)
    expect(done).toEqual(['end'])
  })

  test('idle only once no response is owed', async () => {
    const { done, inner } = tunnel()
    const [first, second] = [part(), part()]
    inner.emit('request', request(), first)
    inner.emit('request', request(), second)
    first.emit('close')
    await sleep(100)
    expect(done).toEqual([])
    second.emit('close')
    await sleep(60)
    expect(done).toEqual(['end'])
    // And no longer there as long again after.
    await sleep(40)
    expect(done).toEqual(['end', 'destroy'])
  })

  test('a tunnel that has closed is not ended', async () => {
    const before = tunnel()
    before.socket.emit('close')
    const after = tunnel()
    const res = part()
    after.inner.emit('request', request(), res)
    Object.assign(after.socket, { destroyed: true }).emit('close')
    res.emit('close')
    await sleep(100)
    expect([before.done, after.done]).toEqual([[], []])
  })
})

describe.each(RUNS.map((r, i) => ({ ...r, i })))(
  '$name, connections $how',
  ({ i }) => {
    let outcome: Record<string, Outcome>
    beforeAll(async () => {
      outcome = await outcomeOf(i)
    }, 60_000)

    test('idle after a response: ended when the time it advertised is up', () => {
      const o = outcome['idle after a response']!
      expect(o).toMatchObject({ status: 200, advertised: 'timeout=1' })
      expectClosed(o, 1_000)
      expect(o.closeNotify).toBe(true)
    })

    test('idle, and its client answers no end: closed as long again after the end', () => {
      const ms = outcome['idle, and the client answers no end']!.slotFreeAfterMs
      expect(ms).toBeNumber()
      expect(ms as number).toBeGreaterThanOrEqual(500 - EARLY_MS)
      expect(ms as number).toBeLessThan(1_000 + LATE_MS)
    })

    test('the time advertised by default is the default timeout', () => {
      expect(outcome['the default Keep-Alive']!.advertised).toBe(
        `timeout=${TUNNEL_TIMEOUTS.keepAliveMs / 1000}`,
      )
    })

    test('each response starts the idle time anew', () => {
      const o = outcome['each response starts the idle time anew']!
      expect(o.statuses).toEqual([200, 200, 200])
      expectClosed(o, 800)
      expect(o.closeNotify).toBe(true)
    })

    // Timed from the end of the handshake; the proxy's time runs from its start.
    test.each(['no request after the handshake', 'half a head'])('%s', name => {
      expectClosed(outcome[name]!, 500, 800)
    })

    test('half a head after a response', () => {
      const o = outcome['half a head after a response']!
      expectClosed(o, 800)
      expect(o.closeNotify).toBe(true)
    })

    test('half a body: closed once it has not moved for the time allowed', () => {
      expectClosed(outcome['half a body']!, 500, 1_000)
    })

    test('a body that trickles in arrives', () => {
      expect(outcome['a body that trickles in']!.status).toBe(200)
    })

    test('a whole request may wait for its answer longer than every timeout', () => {
      expect(
        outcome['an answer that takes longer than every timeout']!.status,
      ).toBe(200)
    })

    // No timeout plays a part: the proxy reads on, and so sees its client go.
    test.each([
      ['answered early', 413],
      ['upstream port closed', 502],
      ['upstream certificate untrusted', 502],
      ['refused for its Host', 421],
      ['refused for its target', 400],
    ])('an upload, %s, whose client leaves', (what, status) => {
      const o = outcome[`${what}, the client leaves`]!
      expect(o.status).toBe(status)
      expectClosed(o, EARLY_MS)
    })

    test('an upload answered early, whose client stays: idle from the answer on', () => {
      const o = outcome['answered early, the client stays']!
      // (The client, busy sending, may see the answer late.)
      expectClosed(o, EARLY_MS, 600)
      expect(o.closeNotify).toBe(true)
    })

    test('an upload answered early, whose client sends it all: the next request is served', () => {
      const o = outcome['answered early, the client sends on and asks again']!
      expect(o).toMatchObject({ status: 413, second: 200, heldBytes: 0 })
    })

    test('an upload the upstream stops taking: closed once it has not moved for the time allowed', () => {
      const o = outcome['an upload the upstream stops taking']!
      expectClosed(o, 500, 1_000)
      expect(o.closeNotify).toBe(false)
    })

    test('an upload the upstream takes in bursts arrives', () => {
      expect(outcome['an upload the upstream takes in bursts']!.status).toBe(
        200,
      )
    })
  },
)
