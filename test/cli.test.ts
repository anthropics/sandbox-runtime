import { describe, test, expect } from 'bun:test'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { readFileSync } from 'node:fs'

/**
 * Get the path to the CLI entry point
 */
function getCliPath(): string {
  return join(process.cwd(), 'src', 'cli.ts')
}

/**
 * Run the CLI with given arguments and return the result
 */
function runCli(args: string[], options?: { input?: string; debug?: boolean }) {
  const result = spawnSync('bun', ['run', getCliPath(), ...args], {
    encoding: 'utf-8',
    input: options?.input,
    env: {
      ...process.env,
      // Use a non-existent config to get default behavior
      HOME: '/tmp/cli-test-nonexistent',
      // Enable SRT_DEBUG if debug option is set
      ...(options?.debug ? { SRT_DEBUG: 'true' } : {}),
    },
  })
  return {
    stdout: result.stdout,
    stderr: result.stderr,
    status: result.status,
  }
}

describe('CLI', () => {
  describe('-c flag (command string mode)', () => {
    test('executes simple command with -c flag', () => {
      const result = runCli(['-c', 'echo hello'])
      expect(result.stdout.trim()).toBe('hello')
      expect(result.status).toBe(0)
    })

    test('passes command string directly without escaping', () => {
      const result = runCli(['-c', 'echo "hello world"'])
      expect(result.stdout.trim()).toBe('hello world')
      expect(result.status).toBe(0)
    })

    test('handles JSON arguments correctly', () => {
      // This is the main use case - JSON with quotes and special chars
      const result = runCli(['-c', 'echo \'{"key": "value"}\''])
      expect(result.stdout.trim()).toBe('{"key": "value"}')
      expect(result.status).toBe(0)
    })

    test('handles complex JSON with nested objects', () => {
      const json = '{"servers":{"name":"test","type":"sdk"}}'
      const result = runCli(['-c', `echo '${json}'`])
      expect(result.stdout.trim()).toBe(json)
      expect(result.status).toBe(0)
    })

    test('handles shell expansion in -c mode', () => {
      const result = runCli(['-c', 'echo $HOME'])
      // $HOME should be expanded by the shell
      expect(result.stdout.trim()).not.toBe('$HOME')
      expect(result.status).toBe(0)
    })

    test('handles pipes in -c mode', () => {
      const result = runCli(['-c', 'echo "hello world" | wc -w'])
      expect(result.stdout.trim()).toBe('2')
      expect(result.status).toBe(0)
    })

    test('handles command substitution in -c mode', () => {
      const result = runCli(['-c', 'echo "count: $(echo 1 2 3 | wc -w)"'])
      expect(result.stdout.trim()).toContain('3')
      expect(result.status).toBe(0)
    })
  })

  describe('default mode (positional arguments)', () => {
    test('executes simple command with positional args', () => {
      const result = runCli(['echo', 'hello'])
      expect(result.stdout.trim()).toBe('hello')
      expect(result.status).toBe(0)
    })

    test('joins multiple positional arguments with spaces', () => {
      const result = runCli(['echo', 'hello', 'world'])
      expect(result.stdout.trim()).toBe('hello world')
      expect(result.status).toBe(0)
    })

    test('handles arguments with flags', () => {
      const result = runCli(['echo', '-n', 'no newline'])
      // -n flag to echo suppresses newline
      expect(result.stdout).toBe('no newline')
      expect(result.status).toBe(0)
    })

    test('preserves argument boundaries when args contain spaces', () => {
      // Regression for #157: positional args are later run via `bash -c`,
      // so they must be shell-quoted. printf '%s\n' emits one line per
      // arg, which exposes whether "hello world" arrived as one token
      // (correct) or was re-split into "hello" and "world".
      const result = runCli(['printf', '%s\n', 'hello world', 'a b'])
      expect(result.stdout).toBe('hello world\na b\n')
      expect(result.status).toBe(0)
    })

    test('preserves shell metacharacters in positional args', () => {
      // Positional mode is argv-style; metacharacters in an arg are data,
      // not shell syntax (use -c for shell semantics).
      const result = runCli(['printf', '%s', '$HOME;|&'])
      expect(result.stdout).toBe('$HOME;|&')
      expect(result.status).toBe(0)
    })
  })

  describe('error handling', () => {
    test('shows error when no command specified', () => {
      const result = runCli([])
      expect(result.stderr).toContain('No command specified')
      expect(result.status).toBe(1)
    })

    test('shows error when only options provided without command', () => {
      const result = runCli(['-d'])
      expect(result.stderr).toContain('No command specified')
      expect(result.status).toBe(1)
    })
  })

  describe('--settings error handling', () => {
    // The CLI must fail closed when an explicitly requested settings file
    // cannot be used: silently falling back to the default config would run
    // the command without the restrictions the caller asked for (e.g. the
    // credentials deny rules).
    test('refuses to run when an explicit --settings file does not exist', () => {
      const result = runCli([
        '--settings',
        '/nonexistent/srt-settings.json',
        'echo',
        'should-not-run',
      ])
      expect(result.status).toBe(1)
      expect(result.stderr).toContain('Could not load settings')
      expect(result.stdout).not.toContain('should-not-run')
    })

    test('refuses to run when an explicit --settings file fails validation', () => {
      const dir = mkdtempSync(join(tmpdir(), 'srt-cli-settings-'))
      const settingsPath = join(dir, 'invalid.json')
      // Valid JSON, but missing required network/filesystem fields
      writeFileSync(settingsPath, JSON.stringify({ network: {} }))
      try {
        const result = runCli([
          '--settings',
          settingsPath,
          'echo',
          'should-not-run',
        ])
        expect(result.status).toBe(1)
        expect(result.stderr).toContain('Could not load settings')
        expect(result.stdout).not.toContain('should-not-run')
      } finally {
        rmSync(dir, { recursive: true, force: true })
      }
    })
  })

  describe('debug output', () => {
    test('SRT_DEBUG enables debug output for positional args', () => {
      const result = runCli(['echo', 'test'], { debug: true })
      // Debug mode should show additional logging to stderr
      expect(result.stderr).toContain('[SandboxDebug]')
      expect(result.stderr).toContain('Original command')
      expect(result.status).toBe(0)
    })

    test('SRT_DEBUG enables debug output for -c mode', () => {
      const result = runCli(['-c', 'echo test'], { debug: true })
      expect(result.stderr).toContain('[SandboxDebug]')
      expect(result.stderr).toContain('Command string mode')
      expect(result.status).toBe(0)
    })

    test('no debug output without SRT_DEBUG', () => {
      const result = runCli(['echo', 'test'], { debug: false })
      expect(result.stderr).not.toContain('[SandboxDebug]')
      expect(result.status).toBe(0)
    })

    test('--debug flag enables debug output (without SRT_DEBUG env)', () => {
      // Regression for #174: the flag must set the same env var the logger
      // reads. Exercise the flag alone — runCli's {debug:true} option sets
      // SRT_DEBUG directly, which would mask the bug.
      const result = runCli(['--debug', 'echo', 'test'])
      expect(result.stderr).toContain('[SandboxDebug]')
      expect(result.status).toBe(0)
    })
  })

  describe('version', () => {
    test('--version returns the correct version from package.json', () => {
      const packageJson = JSON.parse(
        readFileSync(join(process.cwd(), 'package.json'), 'utf-8'),
      )
      const result = runCli(['--version'])
      expect(result.stdout.trim()).toBe(packageJson.version)
      expect(result.status).toBe(0)
    })
  })
})
