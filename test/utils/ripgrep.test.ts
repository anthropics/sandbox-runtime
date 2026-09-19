import { describe, it, expect } from 'bun:test'
import { chmodSync, mkdirSync, writeFileSync, mkdtempSync, rmSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import { ripGrep, RipgrepError } from '../../src/utils/ripgrep.js'
import { isWindows } from '../helpers/platform.js'

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
      writeFileSync(script, "process.stdout.write(process.argv0 + '\\0')")

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
      writeFileSync(script, "process.stdout.write(process.argv0 + '\\0')")

      const results = await ripGrep([], dir, new AbortController().signal, {
        command: process.execPath,
        args: [script],
      })
      // Without argv0 override, process.argv0 defaults to the executable path
      expect(results[0]).not.toBe('rg')
      expect(results[0]).toContain(process.execPath.split('/').pop())
    } finally {
      rmSync(dir, { recursive: true })
    }
  })

  it('leaves the ripgrep config file out of every run', async () => {
    // RIPGREP_CONFIG_PATH routinely points inside a project, at a file a
    // sandboxed command can write; one --max-filesize line in it is a scan
    // that lists nothing and reports no error for it.
    const dir = mkdtempSync(join(tmpdir(), 'rg-noconfig-'))
    try {
      const script = join(dir, 'echo-args.cjs')
      writeFileSync(
        script,
        "process.stdout.write(process.argv.slice(2).join('\\0') + '\\0')",
      )

      const results = await ripGrep(
        ['--files'],
        dir,
        new AbortController().signal,
        { command: process.execPath, args: [script] },
      )

      expect(results).toContain('--no-config')
    } finally {
      rmSync(dir, { recursive: true })
    }
  })

  it('rejects on exit code > 1', () => {
    expect(
      ripGrep(['--invalid-flag-xyz'], '.', new AbortController().signal),
    ).rejects.toThrow(/ripgrep failed/)
  })

  it.if(!isWindows)(
    'carries what a failed run listed and what it said, whatever the uid',
    async () => {
      // What the caller denies comes off these two, and the run that
      // produces them for real needs a directory this process cannot read —
      // which as root there is none of. A fake rg fails the same way
      // everywhere; the arm below does it with the real one where it can.
      const error = await ripGrep([], '.', new AbortController().signal, {
        command: '/bin/sh',
        args: [
          '-c',
          'printf "/found/a\\0"; ' +
            'printf "rg: /found/locked: Permission denied (os error 13)\\n" >&2; ' +
            'exit 2',
        ],
      }).catch((e: unknown) => e)

      expect(error).toBeInstanceOf(RipgrepError)
      expect((error as RipgrepError).partialMatches).toEqual(['/found/a'])
      expect((error as RipgrepError).stderr).toContain('/found/locked')
      expect((error as RipgrepError).timedOut).toBe(false)
    },
  )

  it.if(!isWindows)(
    'drops a path a killed run was cut off in the middle of',
    async () => {
      const dir = mkdtempSync(join(tmpdir(), 'rg-timeout-'))
      try {
        const error = await ripGrep([], dir, new AbortController().signal, {
          command: '/bin/sh',
          // A complete record, then a truncated one, then a run that outlives
          // the timeout. exec so the kill reaches whatever holds stdout. The
          // budget is far past what starting a shell and printing two records
          // takes on any machine: cut fine, the output would be the empty
          // prefix of a run that had not got to writing it yet.
          args: ['-c', 'printf "/found/a\\0/trunc"; exec sleep 30'],
          timeoutMs: 5_000,
        }).catch((e: unknown) => e)

        expect(error).toBeInstanceOf(RipgrepError)
        expect((error as RipgrepError).timedOut).toBe(true)
        expect((error as RipgrepError).partialMatches).toEqual(['/found/a'])
      } finally {
        rmSync(dir, { recursive: true })
      }
    },
    30_000,
  )

  it.if(!isWindows)(
    'calls a kill that is not the timeout what it was',
    async () => {
      // Ctrl-C to the process group, an OOM kill: a run that ended inside
      // the time it was given did not run out of it, and reporting one as
      // the other tells the operator to look at the wrong thing. Both refuse
      // the wrap upstream either way.
      const error = await ripGrep([], '.', new AbortController().signal, {
        command: '/bin/sh',
        args: ['-c', 'kill -TERM $$'],
        timeoutMs: 60_000,
      }).catch((e: unknown) => e)

      expect(error).toBeInstanceOf(RipgrepError)
      expect((error as RipgrepError).timedOut).toBe(false)
      expect((error as Error).message).toContain('SIGTERM')
      expect((error as Error).message).toContain('inside the 60000 ms')
    },
  )

  it.if(!isWindows)(
    'keeps a path containing a newline in one piece',
    async () => {
      const dir = mkdtempSync(join(tmpdir(), 'rg-newline-'))
      try {
        const results = await ripGrep([], dir, new AbortController().signal, {
          command: '/bin/sh',
          args: ['-c', 'printf "/a/nl\\ndir/.git/HEAD\\0"'],
        })

        expect(results).toEqual(['/a/nl\ndir/.git/HEAD'])
      } finally {
        rmSync(dir, { recursive: true })
      }
    },
  )

  it.if(!isWindows && process.getuid?.() !== 0)(
    'hands back what rg listed before an unreadable directory failed the run',
    async () => {
      const dir = mkdtempSync(join(tmpdir(), 'rg-test-'))
      mkdirSync(join(dir, 'locked'))
      writeFileSync(join(dir, 'a.txt'), 'hello')
      chmodSync(join(dir, 'locked'), 0o000)
      try {
        const error = await ripGrep(
          ['--files'],
          dir,
          new AbortController().signal,
        ).catch((e: unknown) => e)

        expect(error).toBeInstanceOf(RipgrepError)
        expect((error as RipgrepError).partialMatches).toEqual([
          join(dir, 'a.txt'),
        ])
        // The caller denies what rg could not read, so the paths must survive.
        expect((error as RipgrepError).stderr).toContain(join(dir, 'locked'))
        expect((error as RipgrepError).timedOut).toBe(false)
      } finally {
        chmodSync(join(dir, 'locked'), 0o755)
        rmSync(dir, { recursive: true })
      }
    },
  )
})
