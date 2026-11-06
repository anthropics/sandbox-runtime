import { afterAll, afterEach, describe, it, expect } from 'bun:test'
import * as fs from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { whichSync } from '../../src/utils/which.js'

/**
 * These tests verify the whichSync utility function.
 *
 * Note: These tests must run in isolation from linux-dependency-error.test.ts
 * which mocks the which.js module globally. Run with:
 *   bun test test/utils/which.test.ts
 *
 * The same code runs under Node.js: see which-node-test.mjs
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

  it('should return same result as Bun.which directly', () => {
    // Of the PATH the process started with, the only one Bun.which searches
    const whichSyncResult = whichSync('ls')
    const bunWhichResult = globalThis.Bun.which('ls')
    expect(whichSyncResult).toBe(bunWhichResult)
  })
})

describe('whichSync searches PATH in this process', () => {
  const savedPath = process.env.PATH
  const savedCwd = process.cwd()
  const base = fs.realpathSync(fs.mkdtempSync(join(tmpdir(), 'which-test-')))

  function plant(...parts: string[]): string {
    const file = join(base, ...parts)
    fs.mkdirSync(dirname(file), { recursive: true })
    fs.writeFileSync(file, '#!/bin/sh\n', { mode: 0o755 })
    return file
  }

  afterEach(() => {
    process.env.PATH = savedPath
    process.chdir(savedCwd)
  })
  afterAll(() => fs.rmSync(base, { recursive: true, force: true }))

  it('takes the first entry holding an executable regular file of that name', () => {
    fs.mkdirSync(join(base, 'directory', 'tool'), { recursive: true })
    fs.chmodSync(plant('no-x', 'tool'), 0o644)
    fs.symlinkSync('absent', join(dirname(plant('dangling', 'x')), 'tool'))
    const first = plant('first', 'tool')
    plant('second', 'tool')
    // The PATH of the moment, which a spawned child would inherit.
    process.env.PATH = ['directory', 'no-x', 'dangling', 'first', 'second']
      .map(dir => join(base, dir))
      .join(':')
    expect(whichSync('tool')).toBe(first)
    expect(whichSync('tool-that-is-nowhere')).toBeNull()
  })

  it('checks a name with a directory part where it is', () => {
    const tool = plant('elsewhere', 'tool')
    plant('on-path', 'sub', 'tool')
    process.env.PATH = join(base, 'on-path')
    expect(whichSync(tool)).toBe(tool)
    expect(whichSync(`${tool}-absent`)).toBeNull()
    expect(whichSync(dirname(tool))).toBeNull()
    // Relative to the working directory, never to a PATH entry.
    expect(whichSync('sub/tool')).toBeNull()
  })

  it('reads an empty entry as the current directory, an empty PATH as no place', () => {
    process.chdir(dirname(plant('cwd', 'tool')))
    for (const searched of [':/absent', '/absent:', '.']) {
      process.env.PATH = searched
      expect(whichSync('tool')).toBe('./tool')
    }
    process.env.PATH = ''
    expect(whichSync('tool')).toBeNull()
    delete process.env.PATH
    expect(whichSync('tool')).toBeNull()
  })
})
