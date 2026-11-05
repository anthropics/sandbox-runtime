import { describe, expect, it } from 'bun:test'
import { SandboxViolationStore } from '../../src/sandbox/sandbox-violation-store.js'

function storeWithViolations(): SandboxViolationStore {
  const store = new SandboxViolationStore()
  store.addViolation({
    line: 'deny one',
    timestamp: new Date('2026-01-01T00:00:00Z'),
  })
  store.addViolation({
    line: 'deny two',
    timestamp: new Date('2026-01-01T00:00:01Z'),
  })
  return store
}

describe('SandboxViolationStore.getViolations limit', () => {
  it('returns no events for a zero limit, not the full retained log', () => {
    const store = storeWithViolations()
    expect(store.getViolations(0)).toEqual([])
    expect(store.getCount()).toBe(2)
    expect(store.getTotalCount()).toBe(2)
  })

  it('does not return unrelated retained events for negative limits', () => {
    const store = storeWithViolations()
    expect(store.getViolations(-1)).toEqual([])
    expect(store.getViolations(-100)).toEqual([])
    expect(store.getViolations(Number.NaN)).toEqual([])
  })

  it('preserves omitted and positive limit behaviour', () => {
    const store = storeWithViolations()
    expect(store.getViolations().map(event => event.line)).toEqual([
      'deny one',
      'deny two',
    ])
    expect(store.getViolations(1).map(event => event.line)).toEqual([
      'deny two',
    ])
    expect(store.getViolations(2).map(event => event.line)).toEqual([
      'deny one',
      'deny two',
    ])
    expect(store.getViolations(100).map(event => event.line)).toEqual([
      'deny one',
      'deny two',
    ])
  })
})
