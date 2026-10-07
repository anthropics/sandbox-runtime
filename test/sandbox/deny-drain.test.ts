import { describe, expect, test } from 'bun:test'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { EventEmitter } from 'node:events'
import { PassThrough } from 'node:stream'
import { drainThenDestroy } from '../../src/sandbox/drain-then-destroy.js'

/**
 * A denial must not tear the connection down while the client is still
 * uploading: closing a socket whose receive side holds unread body bytes
 * makes the kernel send RST, and the client loses the 403 it never read
 * (curl reports a transport failure and a retrying client retries a policy
 * block it must not retry). The teardown drains the remainder of the body
 * first, bounded by a byte cap and a deadline.
 *
 * The OS-level symptom needs a real socket, and reproduces under Node (the
 * published CLI runtime), not under Bun's server teardown — so these tests
 * pin the teardown contract itself: no destroy while the body is arriving,
 * a destroy once the body ends, and a destroy once each bound fires.
 */

/** A fake response whose 'finish' the test can fire at will. */
function fakeRes(): ServerResponse & EventEmitter {
  const res = new EventEmitter() as ServerResponse & EventEmitter
  // @ts-expect-error — only the fields drainThenDestroy reads are provided.
  res.writableFinished = false
  // @ts-expect-error — same.
  res.destroyed = false
  return res
}

function fakeReq(): IncomingMessage & PassThrough {
  const req = new PassThrough() as IncomingMessage & PassThrough
  // The drain only proceeds when the parser has not seen the whole message.
  // @ts-expect-error — same.
  req.complete = false
  return req
}

const tick = () => new Promise(r => setTimeout(r, 0))

describe('drainThenDestroy', () => {
  test('does not destroy until the body ends', async () => {
    const req = fakeReq()
    const res = fakeRes()
    drainThenDestroy(req, res, 1024, 1_000)
    res.emit('finish')
    req.write(Buffer.alloc(256, 0x61))
    await tick()
    // The client is still uploading: the socket must stay open so the 403
    // it has not read survives.
    expect(req.destroyed).toBe(false)
    req.end()
    await tick()
    expect(req.destroyed).toBe(true)
  })

  test('drains data written after the response flushed', async () => {
    const req = fakeReq()
    const res = fakeRes()
    drainThenDestroy(req, res, 1024, 1_000)
    res.emit('finish')
    let seen = 0
    req.on('data', c => (seen += c.length))
    req.write(Buffer.alloc(64, 0x61))
    req.end(Buffer.alloc(64, 0x62))
    await tick()
    expect(seen).toBe(128)
    expect(req.destroyed).toBe(true)
  })

  test('destroys once the byte cap is exceeded, without waiting for the end', async () => {
    const req = fakeReq()
    const res = fakeRes()
    drainThenDestroy(req, res, 128, 1_000)
    res.emit('finish')
    req.write(Buffer.alloc(256, 0x61))
    await tick()
    expect(req.destroyed).toBe(true)
  })

  test('destroys a client that goes idle mid-body', async () => {
    const req = fakeReq()
    const res = fakeRes()
    drainThenDestroy(req, res, 1024, 30, 5_000)
    res.emit('finish')
    req.write(Buffer.alloc(64, 0x61))
    await new Promise(r => setTimeout(r, 80))
    expect(req.destroyed).toBe(true)
  })

  test('data keeps the drain alive past the idle window', async () => {
    const req = fakeReq()
    const res = fakeRes()
    drainThenDestroy(req, res, 1024 * 1024, 50, 5_000)
    res.emit('finish')
    for (let i = 0; i < 10; i++) {
      req.write(Buffer.alloc(8, 0x61))
      await new Promise(r => setTimeout(r, 10))
    }
    expect(req.destroyed).toBe(false)
    req.end()
    await tick()
    expect(req.destroyed).toBe(true)
  })

  test('destroys at the deadline when the client never stops dripping', async () => {
    const req = fakeReq()
    const res = fakeRes()
    // Idle never fires: every chunk resets it. The deadline is the backstop.
    drainThenDestroy(req, res, 1024 * 1024, 5_000, 40)
    res.emit('finish')
    const drip = setInterval(() => {
      if (!req.destroyed) req.write(Buffer.alloc(1, 0x61))
    }, 10)
    await new Promise(r => setTimeout(r, 90))
    clearInterval(drip)
    expect(req.destroyed).toBe(true)
  })

  test('a completed request is destroyed immediately', async () => {
    const req = fakeReq()
    // @ts-expect-error — simulate a request the parser already saw to its end.
    req.complete = true
    const res = fakeRes()
    drainThenDestroy(req, res)
    res.emit('finish')
    expect(req.destroyed).toBe(true)
  })

  test('a flushed response starts the drain immediately', async () => {
    const req = fakeReq()
    const res = fakeRes()
    // @ts-expect-error — same.
    res.writableFinished = true
    drainThenDestroy(req, res, 1024, 1_000)
    req.end()
    await tick()
    expect(req.destroyed).toBe(true)
  })
})
