import { expect, test } from 'bun:test'
import { EventEmitter } from 'node:events'
import {
  adjustByteBudget,
  createByteBudget,
  gateSocketOnBufferedBody,
} from '../../src/sandbox/emitted-connection.js'

test('a drop in a byte budget wakes each waiter once and empties the set', () => {
  const budget = createByteBudget(100)
  const woken: string[] = []
  adjustByteBudget(budget, 100)
  budget.waiters.add(() => woken.push('a'))
  budget.waiters.add(() => woken.push('b'))

  adjustByteBudget(budget, -40)

  expect(woken).toEqual(['a', 'b'])
  expect(budget.waiters.size).toBe(0)
  expect(budget.used).toBe(60)
})

test('a rise in a byte budget wakes nobody', () => {
  const budget = createByteBudget(100)
  let woken = 0
  budget.waiters.add(() => woken++)

  adjustByteBudget(budget, 10)
  adjustByteBudget(budget, 0)

  expect(woken).toBe(0)
  expect(budget.waiters.size).toBe(1)
})

test('a waiter that waits again while being woken is kept for the next drop', () => {
  const budget = createByteBudget(100)
  let woken = 0
  const waitAgain = (): void => {
    woken++
    budget.waiters.add(waitAgain)
  }
  adjustByteBudget(budget, 100)
  budget.waiters.add(waitAgain)

  adjustByteBudget(budget, -1)
  expect(woken).toBe(1)
  expect(budget.waiters.size).toBe(1)
  adjustByteBudget(budget, -1)
  expect(woken).toBe(2)
})

test('many add and release cycles leave a byte budget empty', () => {
  const budget = createByteBudget(1000)
  for (let i = 1; i <= 500; i++) {
    adjustByteBudget(budget, i)
    budget.waiters.add(() => {})
    adjustByteBudget(budget, -i)
  }
  expect(budget.used).toBe(0)
  expect(budget.waiters.size).toBe(0)
})

test.each(['end', 'close'])(
  "what a gated request holds is given back at its %s, or its socket's close, and the socket is let go of",
  event => {
    for (const from of ['req', 'socket'] as const) {
      const budget = createByteBudget(1000)
      const socket = Object.assign(new EventEmitter(), { pause() {} })
      const req = Object.assign(new EventEmitter(), {
        socket,
        readableLength: 10,
      })
      gateSocketOnBufferedBody(req as never, 100, budget)
      socket.emit('data')
      expect(budget.used).toBe(10)
      if (from === 'req') req.emit(event)
      else socket.emit('close')
      expect(budget.used).toBe(0)
      expect(socket.eventNames()).toEqual([])
    }
  },
)
