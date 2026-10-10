import { describe, it, expect } from 'bun:test'
import { whichSync } from '../../src/utils/which.js'

/**
 * These tests verify the whichSync utility function.
 *
 * Note: These tests must run in isolation from linux-dependency-error.test.ts
 * which mocks the which.js module globally. Run with:
 *   bun test test/utils/which.test.ts
 *
 * The Node.js fallback is tested separately in which-node-test.mjs
 */
describe('whichSync', () => {
  it('should find existing executables', () => {
    // 'ls' should exist on all Unix systems
    const result = whichSync('ls')
    expect(result).not.toBeNull()
    expect(result).toContain('/ls')
  })

  it('should return null for non-existent executables', () => {
    const result = whichSync('this-command-definitely-does-not-exist-12345')
    expect(result).toBeNull()
  })

  it('should accept an executable absolute path without PATH lookup', () => {
    expect(whichSync(process.execPath)).toBe(process.execPath)
  })

  it('should reject a missing executable absolute path', () => {
    expect(whichSync('/path/that/does/not/exist')).toBeNull()
  })

  it('should find common tools', () => {
    // These should exist in most environments
    const bash = whichSync('bash')
    expect(bash).not.toBeNull()

    const cat = whichSync('cat')
    expect(cat).not.toBeNull()
  })

  it('should be running in Bun environment', () => {
    // Verify we're in Bun - if this fails, Bun.which won't be used
    expect(typeof globalThis.Bun).toBe('object')
    expect(typeof globalThis.Bun.which).toBe('function')
  })

  it('should return same result as Bun.which directly', () => {
    // Verify whichSync returns same result as Bun.which
    // This indirectly confirms Bun.which is being used
    const whichSyncResult = whichSync('ls')
    const bunWhichResult = globalThis.Bun.which('ls')
    expect(whichSyncResult).toBe(bunWhichResult)
  })
})
