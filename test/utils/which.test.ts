import { describe, it, expect } from 'bun:test'
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
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

  it('returns a path-qualified executable without shelling out to which', () => {
    const result = whichSync(process.execPath)
    expect(result).toBe(process.execPath)
  })

  it('returns null for a missing path-qualified executable', () => {
    expect(whichSync('/definitely/missing/srt-bin-xyz')).toBeNull()
  })

  it('returns a path-qualified regular executable file', () => {
    const dir = mkdtempSync(join(tmpdir(), 'which-exec-'))
    try {
      const bin = join(dir, 'tool')
      writeFileSync(bin, '#!/bin/sh\necho ok\n')
      chmodSync(bin, 0o755)
      expect(whichSync(bin)).toBe(bin)
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  it('returns null for a path-qualified directory even when it is executable', () => {
    const dir = mkdtempSync(join(tmpdir(), 'which-dir-'))
    try {
      // Directories need the execute/search bit; confirm +x is set so this
      // would have passed a bare accessSync(X_OK) check.
      chmodSync(dir, 0o755)
      expect(whichSync(dir)).toBeNull()
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  it('throws for a path-qualified regular file without execute permission', () => {
    const dir = mkdtempSync(join(tmpdir(), 'which-nox-'))
    try {
      const file = join(dir, 'not-exec')
      writeFileSync(file, 'not executable\n')
      chmodSync(file, 0o644)
      expect(() => whichSync(file)).toThrow(/Failed to resolve executable.*EACCES/)
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })
})
