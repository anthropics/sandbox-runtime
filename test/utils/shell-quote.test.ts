import { describe, expect, it } from 'bun:test'
import * as fc from 'fast-check'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import * as path from 'node:path'
import { wrapCommandWithSandboxMacOS } from '../../src/sandbox/macos-sandbox-utils.js'
import { quote, quoteForCmd } from '../../src/utils/shell-quote.js'
import { whichSync } from '../../src/utils/which.js'

/**
 * Regression coverage for the `!` corruption bug, plus the round-trip
 * contract a shell quoter must satisfy.
 *
 * The npm `shell-quote` package this module replaces switched to a
 * double-quote + backslash strategy whenever an argument contained a single
 * quote, and in that mode it backslash-escaped `!`. The wrapper string is
 * only ever run through a non-interactive `<shell> -c`, where bash keeps
 * that backslash, so every `!` in the user command reached the program as
 * the two characters `\!`: heredoc-written `if (!x)` became unparseable
 * JavaScript, and `jq 'a != b'` / `awk '!seen[$0]++'` / `find ! -name`
 * filters were silently rewritten. The user command almost always contains
 * a `'`, so this fired on essentially every sandboxed command.
 */
describe('quote', () => {
  // The string-level tests are pure JS and run on every CI leg.
  it('never backslash-escapes ! (the shell-quote regression)', () => {
    // The embedded `'` is what pushed shell-quote into its buggy branch.
    const command = `node -e 'if (!ok) throw new Error("bad")'`
    const quoted = quote(['/bin/bash', '-c', command])
    expect(quoted).toContain('!ok')
    expect(quoted).not.toContain('\\!')
  })

  it('the assembled macOS wrapper never contains a backslash-bang', () => {
    // End to end through the real wrapper builder: the input has no `\!`,
    // and correct POSIX quoting never needs to introduce one.
    const wrapped = wrapCommandWithSandboxMacOS({
      command: `node -e 'if (!ok) throw new Error("bad")'`,
      needsNetworkRestriction: false,
      readConfig: undefined,
      writeConfig: { allowOnly: ['/tmp'], denyWithinAllow: [] },
    })
    expect(wrapped).toContain('!ok')
    expect(wrapped).not.toContain('\\!')
  })

  it('leaves shell-safe words bare and single-quotes the rest', () => {
    expect(quote(['env', 'A=b', '/usr/bin/sandbox-exec', '-p'])).toBe(
      'env A=b /usr/bin/sandbox-exec -p',
    )
    expect(quote([''])).toBe("''")
    expect(quote(['a b'])).toBe("'a b'")
    expect(quote(["don't"])).toBe(`'don'"'"'t'`)
  })

  // The round-trip contract: re-parsing the quoted string with a real POSIX
  // shell must yield exactly the original argument list. This is the test
  // that would have caught the `!` bug on day one. It runs against EVERY
  // POSIX shell available on the machine, not just bash: the wrapper is
  // executed via the caller-supplied `binShell` (frequently zsh on macOS),
  // and zsh has word-position semantics bash does not — e.g. "equals
  // expansion" rewrites or aborts an unquoted word starting with `=` — so a
  // bash-only round-trip structurally cannot detect a zsh-only bug.
  const SHELLS = ['bash', 'zsh', 'sh', 'dash']
    .map(name => whichSync(name))
    .filter(path => path !== null)

  describe.skipIf(SHELLS.length === 0)(
    'round-trips through a real shell',
    () => {
      /**
       * Runs `<shell> -c` on `quote(['printf', '%s\0', ...args])` and splits
       * the NUL-delimited output back into an argument list. printf appends
       * a trailing NUL, hence the final slice.
       */
      function roundTrip(shell: string, args: string[]): string[] {
        const result = spawnSync(
          shell,
          ['-c', quote(['printf', '%s\\0', ...args])],
          { encoding: 'utf8' },
        )
        expect(result.status).toBe(0)
        return result.stdout.split('\0').slice(0, -1)
      }

      for (const shell of SHELLS) {
        describe(shell, () => {
          it('preserves every shell metacharacter byte for byte', () => {
            const args = [
              'if (!ok) { throw new Error("bad") }',
              'a != b',
              '!seen[$0]++',
              "don't",
              '$HOME `id` $(id)',
              '* ? [a-z] ~ # | & ; < > ( )',
              'back\\slash',
              'new\nline',
              'tab\there',
              '!',
              '',
            ]
            expect(roundTrip(shell, args)).toEqual(args)
          })

          it('quotes a leading `=` so zsh equals-expansion cannot fire', () => {
            // zsh rewrites an UNQUOTED word starting with `=` to a command
            // path (`=ls` -> /bin/ls) and aborts the entire command line for
            // an unknown name. quote() must therefore never emit a bare
            // leading-`=` word; `=` elsewhere (A=b) stays bare.
            const args = ['=ls', '=definitely-not-a-command', '==', '=', 'A=b']
            expect(roundTrip(shell, args)).toEqual(args)
          })

          // Each fast-check sample spawns one real shell process, so cap the
          // run count and give the test an explicit budget — the default 5s
          // per-test timeout is not enough on a loaded CI runner.
          it('property: any printable-ASCII argv round-trips exactly', () => {
            fc.assert(
              fc.property(
                fc.array(fc.string(), { minLength: 1, maxLength: 6 }),
                args => {
                  expect(roundTrip(shell, args)).toEqual(args)
                },
              ),
              { numRuns: 25 },
            )
          }, 30_000)
        })
      }
    },
  )
})

/**
 * On Windows the CLI runs its argv through `cmd.exe /d /s /c`, where POSIX
 * single quotes are literal characters: `quote()` wrapped every absolute
 * path in them, so `C:\x\f.js` arrived as `'C:\x\f.js'`.
 */
describe('quoteForCmd', () => {
  it('wraps a program name in plain quotes for cmd', () => {
    expect(quoteForCmd(['C:\\Program Files\\nodejs\\node.exe', 'x'])).toBe(
      '"C:\\Program Files\\nodejs\\node.exe" x',
    )
  })

  it('refuses a program name cmd would read past its quotes', () => {
    for (const name of ['a"b', '%PATH%\\x.exe', 'a\nb']) {
      expect(() => quoteForCmd([name])).toThrow('cannot pass the program name')
    }
  })

  it('leaves a Windows path bare', () => {
    expect(quoteForCmd(['node', 'C:\\Users\\me\\f.js'])).toBe(
      'node C:\\Users\\me\\f.js',
    )
  })

  it('double-quotes and caret-escapes the rest, never single-quotes', () => {
    expect(quoteForCmd(['echo', 'a b'])).toBe('echo ^"a^ b^"')
    expect(quoteForCmd(['echo', "don't"])).toBe(`echo ^"don't^"`)
    expect(quoteForCmd(['echo', 'x & y'])).toBe('echo ^"x^ ^&^ y^"')
  })

  it('doubles backslashes before a quote, as the MSVCRT parser reads them', () => {
    expect(quoteForCmd(['p', 'a\\"b'])).toBe('p ^"a\\\\\\^"b^"')
    expect(quoteForCmd(['p', 'dir\\ x\\'])).toBe('p ^"dir\\^ x\\\\^"')
  })

  describe.skipIf(process.platform !== 'win32')(
    'round-trips through cmd.exe /d /s /c',
    () => {
      const comspec = process.env.ComSpec ?? 'C:\\Windows\\System32\\cmd.exe'
      // A script file, not `-e`: node stops reading its own options at the
      // file name, where after `-e` it still reads an argument such as `- `.
      // Node rather than the test runner, whose default install path has the
      // space the program name's quoting has to carry.
      const printArgv = path.join(
        mkdtempSync(path.join(tmpdir(), 'quote-for-cmd-')),
        'argv.js',
      )
      writeFileSync(
        printArgv,
        'process.stdout.write(JSON.stringify(process.argv.slice(2)))',
      )
      const node = whichSync('node') ?? process.execPath

      /** The command line srt-win builds: post-`/c` content wrapped once. */
      function roundTrip(args: string[]): string[] {
        const command = quoteForCmd([node, printArgv, ...args])
        const result = spawnSync(comspec, ['/d', '/s', '/c', `"${command}"`], {
          encoding: 'utf8',
          windowsVerbatimArguments: true,
        })
        expect(result.status).toBe(0)
        return JSON.parse(result.stdout) as string[]
      }

      it('preserves paths, quotes and cmd metacharacters', () => {
        const args = [
          'C:\\Users\\me\\f.js',
          'C:\\Program Files\\x\\',
          'a "quoted" word',
          'back\\"slash',
          "don't",
          '& | < > ^ ( ) % ! , ; =',
          '%PATH%',
          '',
        ]
        expect(roundTrip(args)).toEqual(args)
      })

      // cmd cannot carry a line break inside a command line, so the
      // property covers printable ASCII only.
      it('property: any printable-ASCII argv round-trips exactly', () => {
        fc.assert(
          fc.property(
            fc.array(
              fc
                .string({ unit: 'binary-ascii' })
                .map(s => s.replace(/[^\x20-\x7e]/g, '')),
              {
                minLength: 1,
                maxLength: 6,
              },
            ),
            args => {
              expect(roundTrip(args)).toEqual(args)
            },
          ),
          { numRuns: 50 },
        )
      }, 60_000)
    },
  )
})
