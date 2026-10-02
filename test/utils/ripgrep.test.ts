import { describe, it, expect } from 'bun:test'
import { writeFileSync, mkdtempSync, rmSync } from 'fs'
import { tmpdir } from 'os'
import { basename, join } from 'path'
import { ripGrep, RipgrepError } from '../../src/utils/ripgrep.js'

describe('ripGrep', () => {
  it('finds matches with default config', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'rg-test-'))
    try {
      writeFileSync(join(dir, 'a.txt'), 'hello\nworld\nfoo')
      const results = await ripGrep(
        ['-l', 'world'],
        dir,
        new AbortController().signal,
      )
      expect(results).toHaveLength(1)
      expect(results[0]).toContain('a.txt')
    } finally {
      rmSync(dir, { recursive: true })
    }
  })

  it('returns empty array on no matches (exit code 1)', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'rg-test-'))
    try {
      writeFileSync(join(dir, 'a.txt'), 'hello')
      const results = await ripGrep(
        ['-l', 'nonexistent-pattern-xyz'],
        dir,
        new AbortController().signal,
      )
      expect(results).toEqual([])
    } finally {
      rmSync(dir, { recursive: true })
    }
  })

  it('passes argv0 to spawn (multicall binary dispatch)', async () => {
    // Spawn node with a script that echoes process.argv0 — shell scripts can't
    // observe argv0 via $0 (shebang loader resets it), but native binaries can.
    const dir = mkdtempSync(join(tmpdir(), 'rg-argv0-'))
    try {
      const script = join(dir, 'echo-argv0.cjs')
      // ripGrep appends target as the last arg; ignore it and print argv0
      writeFileSync(script, 'process.stdout.write(process.argv0)')

      const results = await ripGrep([], dir, new AbortController().signal, {
        command: process.execPath,
        args: [script],
        argv0: 'rg',
      })
      expect(results).toEqual(['rg'])
    } finally {
      rmSync(dir, { recursive: true })
    }
  })

  it('uses execFile path when argv0 is not set', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'rg-noargv0-'))
    try {
      const script = join(dir, 'echo-argv0.cjs')
      writeFileSync(script, 'process.stdout.write(process.argv0)')

      const results = await ripGrep([], dir, new AbortController().signal, {
        command: process.execPath,
        args: [script],
      })
      // Without argv0 override, process.argv0 defaults to the executable path
      expect(results[0]).not.toBe('rg')
      expect(results[0]).toContain(basename(process.execPath))
    } finally {
      rmSync(dir, { recursive: true })
    }
  })

  it('says what had been listed when it rejects', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'rg-listed-'))
    try {
      const script = join(dir, 'lists-then-fails.cjs')
      writeFileSync(
        script,
        "process.stdout.write('one\\ntwo\\nhalf a li'); process.stderr.write('went wrong'); process.exitCode = 2",
      )

      const error: unknown = await ripGrep(
        [],
        dir,
        new AbortController().signal,
        { command: process.execPath, args: [script] },
      ).catch((e: unknown) => e)

      expect(error).toBeInstanceOf(RipgrepError)
      expect((error as RipgrepError).listed).toEqual(['one', 'two'])
      expect((error as RipgrepError).stderr).toBe('went wrong')
    } finally {
      rmSync(dir, { recursive: true })
    }
  })

  it('rejects on exit code > 1', () => {
    expect(
      ripGrep(['--invalid-flag-xyz'], '.', new AbortController().signal),
    ).rejects.toThrow(/ripgrep failed/)
  })
})
