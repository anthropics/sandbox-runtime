import { describe, expect, test } from 'bun:test'
import { PassThrough, Readable } from 'node:stream'
import { rejects } from 'node:assert/strict'
import {
  BodySubstitutionTooLargeError,
  collectLimitedBody,
  collectSubstitutedBody,
  createBodySubstitutionTransform,
} from '../../src/sandbox/body-substitution.js'

function settled<T>(promise: Promise<T>): Promise<T> {
  return Promise.race([
    promise,
    new Promise<never>((_, reject) => {
      const timer = setTimeout(
        () => reject(new Error('collector did not settle')),
        500,
      )
      timer.unref()
    }),
  ])
}

describe('bounded body collection', () => {
  test('accepts an exact-cap body', async () => {
    const body = Readable.from([Buffer.from('ab'), Buffer.from('cd')])
    expect(await collectLimitedBody(body, 4)).toEqual(Buffer.from('abcd'))
  })

  test('overflow pauses input and releases collection listeners', async () => {
    const body = new PassThrough()
    try {
      const result = collectLimitedBody(body, 3)
      void result.catch(() => {})
      body.write(Buffer.from('four'))
      expect(body.isPaused()).toBe(true)
      await rejects(result, BodySubstitutionTooLargeError)
      expect(body.listenerCount('data')).toBe(0)
      expect(body.listenerCount('end')).toBe(0)
      expect(body.listenerCount('error')).toBe(0)
      expect(body.listenerCount('close')).toBe(0)
    } finally {
      body.destroy()
    }
  })

  test('a premature close without an error rejects', async () => {
    const body = new PassThrough()
    const result = settled(collectLimitedBody(body, 10))
    body.write(Buffer.from('a'))
    body.destroy()
    await rejects(result, /request body closed before end/)
  })

  test('an already destroyed body rejects', async () => {
    const body = new PassThrough()
    body.destroy()
    await rejects(
      settled(collectLimitedBody(body, 10)),
      /request body closed before end/,
    )
  })

  test('source errors reject and release listeners', async () => {
    const body = new PassThrough()
    const error = new Error('upload failed')
    const result = collectLimitedBody(body, 10)
    body.destroy(error)
    await rejects(result, error)
    expect(body.listenerCount('data')).toBe(0)
    expect(body.listenerCount('end')).toBe(0)
    expect(body.listenerCount('close')).toBe(0)
  })
})

describe('bounded substitution collection', () => {
  test('a silently closed source rejects and destroys its transform', async () => {
    const body = new PassThrough()
    const transform = createBodySubstitutionTransform([])
    const result = settled(collectSubstitutedBody(body, transform, 10))
    body.write(Buffer.from('a'))
    body.destroy()
    await rejects(result, /request body closed before end/)
    expect(transform.destroyed).toBe(true)
    expect(body.listenerCount('error')).toBe(0)
    expect(body.listenerCount('close')).toBe(0)
  })

  test('overflow destroys the transform but leaves source teardown to its caller', async () => {
    const body = new PassThrough()
    const transform = createBodySubstitutionTransform([])
    try {
      const result = collectSubstitutedBody(body, transform, 3)
      body.write(Buffer.from('four'))
      await rejects(result, BodySubstitutionTooLargeError)
      expect(transform.destroyed).toBe(true)
      expect(body.destroyed).toBe(false)
      expect(body.isPaused()).toBe(true)
      expect(body.listenerCount('data')).toBe(0)
    } finally {
      body.destroy()
    }
  })
})

test('overflow followed by a queued source error does not escape teardown', async () => {
  const body = new PassThrough()
  body.on('error', () => {})
  const transform = createBodySubstitutionTransform([])
  const result = collectSubstitutedBody(body, transform, 3)
  body.write(Buffer.from('four'))
  body.destroy(new Error('late abort'))
  await rejects(result, BodySubstitutionTooLargeError)
  await new Promise<void>(resolve => setImmediate(resolve))
  expect(transform.destroyed).toBe(true)
})
