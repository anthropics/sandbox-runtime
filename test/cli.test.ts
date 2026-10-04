import { describe, test, expect } from 'bun:test'
import { spawn, spawnSync } from 'node:child_process'
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { isLinux } from './helpers/platform.js'

/**
 * Get the path to the CLI entry point
 */
function getCliPath(): string {
  return join(process.cwd(), 'src', 'cli.ts')
}

/**
 * Run the CLI with given arguments and return the result
 */
function runCli(
  args: string[],
  options?: { input?: string; debug?: boolean; home?: string },
) {
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    // Default to a non-existent config to get default behavior; `home`
    // points the default settings path at a directory the test set up.
    HOME: options?.home ?? '/tmp/cli-test-nonexistent',
    // Enable SRT_DEBUG if debug option is set
    ...(options?.debug ? { SRT_DEBUG: 'true' } : {}),
  }
  // npm exports npm_package_version to its lifecycle scripts, so it is set
  // whenever the suite runs under `npm test`. The CLI under test is a `srt`
  // binary a user installed, which has no such variable.
  delete env.npm_package_version
  const result = spawnSync('bun', ['run', getCliPath(), ...args], {
    encoding: 'utf-8',
    input: options?.input,
    env,
  })
  return {
    stdout: result.stdout,
    stderr: result.stderr,
    status: result.status,
  }
}

describe('CLI', () => {
  describe('--version', () => {
    test('reports the version in the package manifest', () => {
      const manifest: { version: string } = JSON.parse(
        readFileSync(join(process.cwd(), 'package.json'), 'utf-8'),
      )
      const result = runCli(['--version'])
      expect(result.stdout.trim()).toBe(manifest.version)
      expect(result.status).toBe(0)
    })
  })

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
      expect(result.stderr).toContain('does not exist')
      expect(result.stderr).toContain('--settings asked for')
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
        expect(result.stderr).toContain('does not hold a valid config')
        expect(result.stdout).not.toContain('should-not-run')
      } finally {
        rmSync(dir, { recursive: true, force: true })
      }
    })
  })

  describe('default settings file error handling', () => {
    // Same rule for the default ~/.srt-settings.json: it is optional, but
    // one that is there and does not load must not fall through to the
    // built-in defaults, which are a different config rather than a weaker
    // one — falling back would drop every rule the file did hold.
    function withHome(run: (home: string) => void): void {
      const home = mkdtempSync(join(tmpdir(), 'srt-cli-home-'))
      try {
        run(home)
      } finally {
        rmSync(home, { recursive: true, force: true })
      }
    }

    test('refuses to run when the default settings file fails validation', () => {
      withHome(home => {
        // Valid JSON, but missing required network/filesystem fields
        writeFileSync(
          join(home, '.srt-settings.json'),
          JSON.stringify({ network: {} }),
        )
        const result = runCli(['echo', 'should-not-run'], { home })
        expect(result.status).toBe(1)
        expect(result.stderr).toContain('does not hold a valid config')
        // Names the key that failed, so the file can be fixed from the
        // message alone.
        expect(result.stderr).toContain('filesystem')
        expect(result.stdout).not.toContain('should-not-run')
      })
    })

    test('refuses to run when the default settings file is empty', () => {
      withHome(home => {
        // A file truncated to nothing: falling back to the defaults here
        // would drop rules that were in force before the truncation.
        writeFileSync(join(home, '.srt-settings.json'), '')
        const result = runCli(['echo', 'should-not-run'], { home })
        expect(result.status).toBe(1)
        expect(result.stderr).toContain('is empty')
        expect(result.stdout).not.toContain('should-not-run')
      })
    })

    test('refuses to run when the default settings file is whitespace only', () => {
      withHome(home => {
        writeFileSync(join(home, '.srt-settings.json'), '   \n\t  ')
        const result = runCli(['echo', 'should-not-run'], { home })
        expect(result.status).toBe(1)
        expect(result.stderr).toContain('is empty')
        expect(result.stdout).not.toContain('should-not-run')
      })
    })

    test('refuses to run when the default settings path cannot be read', () => {
      withHome(home => {
        // A directory where the file should be: readFileSync fails with
        // EISDIR, which is not "no settings file" and must not be treated
        // as one.
        mkdirSync(join(home, '.srt-settings.json'))
        const result = runCli(['echo', 'should-not-run'], { home })
        expect(result.status).toBe(1)
        expect(result.stderr).toContain('could not be read')
        expect(result.stderr).toContain('EISDIR')
        expect(result.stdout).not.toContain('should-not-run')
      })
    })

    test('runs with the built-in defaults when there is no settings file', () => {
      withHome(home => {
        const result = runCli(['echo', 'no-settings-file'], { home })
        expect(result.status).toBe(0)
        expect(result.stdout).toContain('no-settings-file')
      })
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

  describe.if(isLinux)('an interrupt before the command has started', () => {
    for (const [when, lastLine] of [
      // The library's handlers are in place, and there is more to wait for.
      ['the sandbox is being initialized', 'Starting HTTP bridge'],
      // The last thing the CLI says before it wraps the command.
      ['the command is being wrapped', 'Original command'],
    ] as const) {
      test(`stops the run while ${when}, and the command is not run`, async () => {
        // Enough directories for the walk of the pattern to outlast the signal.
        const root = mkdtempSync(join(tmpdir(), 'cli-interrupt-'))
        try {
          for (let i = 0; i < 200; i++) {
            for (let j = 0; j < 100; j++) {
              mkdirSync(join(root, 'tree', `d${i}`, `e${j}`), {
                recursive: true,
              })
            }
          }
          const settings = join(root, 'settings.json')
          writeFileSync(
            settings,
            JSON.stringify({
              network: { allowedDomains: [], deniedDomains: [] },
              filesystem: {
                denyRead: [join(root, 'tree', '**/*.pem')],
                allowWrite: [],
                denyWrite: [],
              },
            }),
          )
          const child = spawn(
            'bun',
            ['run', getCliPath(), '-s', settings, 'echo', 'RAN'],
            { env: { ...process.env, SRT_DEBUG: 'true' } },
          )
          let stdout = ''
          let stderr = ''
          let signalled = false
          child.stdout.on('data', (chunk: Buffer) => (stdout += String(chunk)))
          child.stderr.on('data', (chunk: Buffer) => {
            stderr += String(chunk)
            if (!signalled && stderr.includes(lastLine)) {
              signalled = true
              child.kill('SIGINT')
            }
          })
          const status = await new Promise(resolve => child.on('exit', resolve))

          expect(signalled).toBe(true)
          expect(stderr).toContain('interrupted by SIGINT')
          expect(stdout).not.toContain('RAN')
          expect(status).toBe(1)
        } finally {
          rmSync(root, { recursive: true, force: true })
        }
      }, 60_000)
    }
  })

  describe.if(process.platform !== 'win32')('SIGWINCH forwarding', () => {
    test('forwards SIGWINCH to the sandboxed child process', async () => {
      const child = spawn(
        'bun',
        [
          'run',
          getCliPath(),
          '--',
          'sh',
          '-c',
          'trap "echo WINCH_RECEIVED" WINCH; echo READY; while :; do sleep 1; done',
        ],
        { env: { ...process.env, SRT_DEBUG: 'false' } },
      )

      let stdout = ''
      await new Promise<void>((resolve, reject) => {
        const timeout = setTimeout(
          () => reject(new Error('Timed out waiting for READY')),
          10_000,
        )
        child.stdout.on('data', (chunk: Buffer) => {
          stdout += String(chunk)
          if (stdout.includes('READY')) {
            clearTimeout(timeout)
            resolve()
          }
        })
        child.on('error', reject)
      })

      // Send SIGWINCH to the srt CLI process
      child.kill('SIGWINCH')

      // Wait for WINCH_RECEIVED in stdout
      await new Promise<void>((resolve, reject) => {
        const timeout = setTimeout(
          () =>
            reject(
              new Error(
                `Timed out waiting for WINCH_RECEIVED, got stdout: ${stdout}`,
              ),
            ),
          10_000,
        )
        child.stdout.on('data', (chunk: Buffer) => {
          stdout += String(chunk)
          if (stdout.includes('WINCH_RECEIVED')) {
            clearTimeout(timeout)
            resolve()
          }
        })
        child.on('error', reject)
      })

      expect(stdout).toContain('WINCH_RECEIVED')
      child.kill('SIGTERM')
      await new Promise(resolve => child.on('exit', resolve))
    }, 25_000)
  })
})
