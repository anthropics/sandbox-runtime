import { describe, test, expect, afterEach, spyOn } from 'bun:test'
import { mkdtempSync, readFileSync, rmSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import {
  CredentialSourceResolver,
  CredentialSourceError,
} from '../../src/sandbox/credential-source.js'
import { buildMaskedEnvVars } from '../../src/sandbox/credential-mask-env.js'
import {
  SentinelRegistry,
  SENTINEL_PREFIX,
} from '../../src/sandbox/credential-sentinel.js'
import {
  registerAwsPairs,
  AwsPairRegistry,
} from '../../src/sandbox/credential-aws-pairs.js'
import { SandboxRuntimeConfigSchema } from '../../src/sandbox/sandbox-config.js'
import type { CredentialSourceConfig } from '../../src/sandbox/sandbox-config.js'

/**
 * Unit tests for `credentials.envVars[].source`. Platform-agnostic: the
 * source commands are this runtime's own binary running a `-e` script, so
 * there is no fixture to install and no shell involved. Nothing here reads
 * or mutates the real process environment: `env` is always passed in.
 */

/** The test runtime, as an absolute path: passes the provenance rule. */
const RUNTIME = process.execPath

function src(
  script: string,
  over: Partial<Omit<CredentialSourceConfig, 'type'>> = {},
): CredentialSourceConfig {
  return { type: 'command', command: RUNTIME, args: ['-e', script], ...over }
}

/** A source that prints `value` with no trailing newline. */
const printing = (value: string) =>
  src(`process.stdout.write(${JSON.stringify(value)})`)

/** Sleep without pulling in a timer library; works under Node and Bun. */
const SLEEP = (ms: number) =>
  `Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,${ms})`

const tmpDirs: string[] = []
function scratchFile(name: string): string {
  const dir = mkdtempSync(path.join(tmpdir(), 'srt-credsource-'))
  tmpDirs.push(dir)
  return path.join(dir, name)
}

afterEach(() => {
  for (const d of tmpDirs.splice(0)) rmSync(d, { recursive: true, force: true })
})

function expectSourceError(fn: () => unknown, code: string): Error {
  try {
    fn()
  } catch (err) {
    expect(err).toBeInstanceOf(CredentialSourceError)
    expect((err as CredentialSourceError).code).toBe(code as never)
    return err as Error
  }
  throw new Error(`expected a CredentialSourceError with code "${code}"`)
}

describe('CredentialSourceResolver', () => {
  test('reads the value off the command stdout', () => {
    const r = new CredentialSourceResolver()
    expect(r.resolve(printing('ghp_real_secret'))).toBe('ghp_real_secret')
    expect(r.size).toBe(1)
  })

  test('strips exactly one trailing newline, the way vault CLIs print', () => {
    const r = new CredentialSourceResolver()
    expect(r.resolve(printing('tok\n'))).toBe('tok')
    // A second newline is part of the value, not framing. `.trim()` would
    // eat it and produce a credential that is wrong but plausible.
    expect(r.resolve(printing('tok\n\n'))).toBe('tok\n')
  })

  test('strips a trailing CRLF', () => {
    const r = new CredentialSourceResolver()
    expect(r.resolve(printing('tok\r\n'))).toBe('tok')
  })

  test('keeps whitespace that is inside the value', () => {
    const r = new CredentialSourceResolver()
    expect(r.resolve(printing('  pad ded  \n'))).toBe('  pad ded  ')
  })

  test('rejects a command that exits 0 with no output', () => {
    const r = new CredentialSourceResolver()
    const err = expectSourceError(
      () => r.resolve(src('process.stdout.write("")')),
      'empty_value',
    )
    expect(err.message).toContain('no output')
  })

  test('rejects a value containing a NUL byte', () => {
    const r = new CredentialSourceResolver()
    expectSourceError(() => r.resolve(printing('tok\u0000en')), 'invalid_value')
  })

  test('keeps the command stderr out of the message, in detail', () => {
    const r = new CredentialSourceResolver()
    const err = expectSourceError(
      () =>
        r.resolve(
          src(
            'process.stderr.write("could not read item\\nsecond line\\n");' +
              'process.exit(3)',
          ),
        ),
      'exit_status',
    ) as CredentialSourceError
    // The message is what the default warning path prints, so a command
    // that put a secret on stderr must not reach it.
    expect(err.message).toBe('exited 3')
    expect(err.message).not.toContain('could not read item')
    // The diagnostic is kept, first line only, for the SRT_DEBUG path.
    expect(err.detail).toBe('could not read item')
    expect(err.detail).not.toContain('second line')
  })

  test('reports a bare command name that is not on PATH', () => {
    const r = new CredentialSourceResolver()
    const err = expectSourceError(
      () =>
        r.resolve({
          type: 'command',
          command: 'srt-no-such-vault-cli-xyz',
        }),
      'not_found',
    )
    expect(err.message).toContain('PATH')
  })

  test('rejects a relative command path', () => {
    const r = new CredentialSourceResolver()
    for (const command of ['./op', '../bin/op', 'bin/op']) {
      const err = expectSourceError(
        () => r.resolve({ type: 'command', command }),
        'relative_command',
      )
      expect(err.message).toContain('working directory')
    }
  })

  test('accepts an absolute command path without consulting PATH', () => {
    const r = new CredentialSourceResolver()
    expect(path.isAbsolute(RUNTIME)).toBe(true)
    expect(r.resolve(printing('abs-ok'))).toBe('abs-ok')
  })

  test('gives the command /dev/null on stdin, so a prompt cannot hang it', () => {
    const r = new CredentialSourceResolver()
    // If stdin were inherited, this would block on the test runner's own
    // stdin instead of reading EOF.
    const value = r.resolve(
      src(
        'const c=require("node:fs").readFileSync(0,"utf8");' +
          'process.stdout.write("len:"+c.length)',
      ),
    )
    expect(value).toBe('len:0')
  })

  test('kills a command that outruns its budget', () => {
    const r = new CredentialSourceResolver()
    const startedAt = Date.now()
    const err = expectSourceError(
      () => r.resolve(src(SLEEP(10_000), { timeoutMs: 300 })),
      'timeout',
    )
    expect(err.message).toContain('300ms')
    // The budget is not a hard wall-clock guarantee (see runCommandSource),
    // but a command that does nothing but sleep must not run to completion.
    expect(Date.now() - startedAt).toBeLessThan(5_000)
  })
})

describe('CredentialSourceResolver caching', () => {
  /**
   * A source that appends one byte to `marker` per run, so a test can count
   * how many times the command actually executed.
   */
  function counting(marker: string, value = 'tok') {
    return src(
      `require("node:fs").appendFileSync(${JSON.stringify(marker)},"x");` +
        `process.stdout.write(${JSON.stringify(value)})`,
    )
  }
  const runs = (marker: string) =>
    existsSync(marker) ? readFileSync(marker, 'utf8').length : 0

  test('runs one source once however many entries ask for it', () => {
    const marker = scratchFile('runs')
    const r = new CredentialSourceResolver()
    const spec = counting(marker)
    for (let i = 0; i < 5; i++) expect(r.resolve(spec)).toBe('tok')
    // The prompt storm this prevents: getCredentialRestrictions runs per
    // wrapped command and again from getFsReadConfig().
    expect(runs(marker)).toBe(1)
  })

  test('a differing timeoutMs alone does not re-run the command', () => {
    const marker = scratchFile('runs')
    const r = new CredentialSourceResolver()
    r.resolve({ ...counting(marker), timeoutMs: 1_000 })
    r.resolve({ ...counting(marker), timeoutMs: 9_000 })
    expect(runs(marker)).toBe(1)
  })

  test('different args are a different source', () => {
    const markerA = scratchFile('a')
    const markerB = scratchFile('b')
    const r = new CredentialSourceResolver()
    expect(r.resolve(counting(markerA, 'a-tok'))).toBe('a-tok')
    expect(r.resolve(counting(markerB, 'b-tok'))).toBe('b-tok')
    expect(runs(markerA)).toBe(1)
    expect(runs(markerB)).toBe(1)
    expect(r.size).toBe(2)
  })

  test('caches a failure instead of re-running the command', () => {
    const marker = scratchFile('runs')
    const r = new CredentialSourceResolver()
    const spec = src(
      `require("node:fs").appendFileSync(${JSON.stringify(marker)},"x");` +
        `process.exit(1)`,
    )
    // A cancelled biometric prompt that re-asks on every later wrap is the
    // same storm with a worse mood.
    expectSourceError(() => r.resolve(spec), 'exit_status')
    expectSourceError(() => r.resolve(spec), 'exit_status')
    expectSourceError(() => r.resolve(spec), 'exit_status')
    expect(runs(marker)).toBe(1)
  })

  test('a larger budget retries after a smaller one timed out', () => {
    const marker = scratchFile('runs')
    const r = new CredentialSourceResolver()
    const slow = (timeoutMs: number) => ({
      ...src(
        `${SLEEP(600)};` +
          `require("node:fs").appendFileSync(${JSON.stringify(marker)},"x");` +
          `process.stdout.write("tok")`,
      ),
      timeoutMs,
    })
    // A timeout answers only the budget it was measured against. An entry
    // prepared to wait longer is asking a different question.
    expectSourceError(() => r.resolve(slow(200)), 'timeout')
    expect(r.resolve(slow(9_000))).toBe('tok')
    expect(runs(marker)).toBe(1)
  })

  test('a budget no larger than the one that timed out reuses the failure', () => {
    const marker = scratchFile('runs')
    const r = new CredentialSourceResolver()
    const slow = (timeoutMs: number) => ({
      ...src(
        `${SLEEP(9_000)};` +
          `require("node:fs").appendFileSync(${JSON.stringify(marker)},"x")`,
      ),
      timeoutMs,
    })
    expectSourceError(() => r.resolve(slow(400)), 'timeout')
    // Equal and smaller budgets would time out too, so do not re-spawn.
    expectSourceError(() => r.resolve(slow(400)), 'timeout')
    expectSourceError(() => r.resolve(slow(100)), 'timeout')
    expect(runs(marker)).toBe(0)
  })

  test('a non-timeout failure is cached whatever the budget', () => {
    const marker = scratchFile('runs')
    const r = new CredentialSourceResolver()
    const failing = (timeoutMs: number) => ({
      ...src(
        `require("node:fs").appendFileSync(${JSON.stringify(marker)},"x");` +
          `process.exit(1)`,
      ),
      timeoutMs,
    })
    // A locked vault fails the same way however long srt waits.
    expectSourceError(() => r.resolve(failing(200)), 'exit_status')
    expectSourceError(() => r.resolve(failing(60_000)), 'exit_status')
    expect(runs(marker)).toBe(1)
  })

  test('claimFailureReport is true once per variable per session', () => {
    const r = new CredentialSourceResolver()
    const spec = printing('x')
    expect(r.claimFailureReport('GH_TOKEN', spec)).toBe(true)
    expect(r.claimFailureReport('GH_TOKEN', spec)).toBe(false)
    // A second variable on the same source is its own report: the operator
    // fixes these per entry.
    expect(r.claimFailureReport('OTHER_TOKEN', spec)).toBe(true)
    r.clear()
    expect(r.claimFailureReport('GH_TOKEN', spec)).toBe(true)
  })

  test('a reused timeout does not quote a budget the caller never set', () => {
    const r = new CredentialSourceResolver()
    const slow = (timeoutMs: number) => ({ ...src(SLEEP(9_000)), timeoutMs })
    expectSourceError(() => r.resolve(slow(500)), 'timeout')
    const err = expectSourceError(() => r.resolve(slow(120)), 'timeout')
    expect(err.message).toContain('120ms')
    expect(err.message).toContain('earlier this session')
  })

  test('clear() drops resolved values and cached failures', () => {
    const marker = scratchFile('runs')
    const r = new CredentialSourceResolver()
    r.resolve(counting(marker))
    expect(r.size).toBe(1)
    r.clear()
    expect(r.size).toBe(0)
    r.resolve(counting(marker))
    expect(runs(marker)).toBe(2)
  })
})

describe('buildMaskedEnvVars with a source', () => {
  test('masks a value the host environment never held', () => {
    const reg = new SentinelRegistry()
    const { setEnvVars, resolvedValues, degradeToUnsetNames } =
      buildMaskedEnvVars(
        [
          {
            name: 'GH_TOKEN',
            mode: 'mask',
            source: printing('ghp_from_vault\n'),
          },
        ],
        ['api.github.com'],
        reg,
        {},
        new CredentialSourceResolver(),
      )
    expect(degradeToUnsetNames).toHaveLength(0)
    const fake = setEnvVars['GH_TOKEN']!
    expect(fake.startsWith(SENTINEL_PREFIX)).toBe(true)
    expect(reg.lookupReal(fake)).toBe('ghp_from_vault')
    expect(resolvedValues['GH_TOKEN']).toBe('ghp_from_vault')
  })

  test('does not consult the host environment when a source is set', () => {
    const reg = new SentinelRegistry()
    const { setEnvVars } = buildMaskedEnvVars(
      [{ name: 'GH_TOKEN', mode: 'mask', source: printing('from-vault') }],
      ['api.github.com'],
      reg,
      { GH_TOKEN: 'stale-export' },
      new CredentialSourceResolver(),
    )
    // Masking the export would inject a credential the operator did not
    // mean, and it would fail upstream with nothing pointing back here.
    expect(reg.lookupReal(setEnvVars['GH_TOKEN']!)).toBe('from-vault')
  })

  test('unsets the variable when the source fails', () => {
    const warn = spyOn(console, 'warn').mockImplementation(() => {})
    try {
      const reg = new SentinelRegistry()
      const { setEnvVars, degradeToUnsetNames } = buildMaskedEnvVars(
        [
          {
            name: 'GH_TOKEN',
            mode: 'mask',
            source: src('process.exit(7)'),
          },
        ],
        ['api.github.com'],
        reg,
        {},
        new CredentialSourceResolver(),
      )
      expect(degradeToUnsetNames).toEqual(['GH_TOKEN'])
      expect(setEnvVars['GH_TOKEN']).toBeUndefined()
      expect(reg.size).toBe(0)
      expect(warn.mock.calls[0]![0]).toContain('GH_TOKEN')
      expect(warn.mock.calls[0]![0]).toContain('UNSET')
    } finally {
      warn.mockRestore()
    }
  })

  test('a failing source unsets even when the real value is exported', () => {
    const warn = spyOn(console, 'warn').mockImplementation(() => {})
    try {
      const reg = new SentinelRegistry()
      const { setEnvVars, degradeToUnsetNames } = buildMaskedEnvVars(
        [
          {
            name: 'GH_TOKEN',
            mode: 'mask',
            source: src('process.exit(7)'),
          },
        ],
        ['api.github.com'],
        reg,
        { GH_TOKEN: 'ghp_real_and_exported' },
        new CredentialSourceResolver(),
      )
      // Falling back to the export would hand the sandbox the real,
      // unmasked credential in the one case the operator asked for it to
      // be hidden. Fail-closed costs a failed command; fail-open costs the
      // credential.
      expect(degradeToUnsetNames).toEqual(['GH_TOKEN'])
      expect(setEnvVars['GH_TOKEN']).toBeUndefined()
    } finally {
      warn.mockRestore()
    }
  })

  test('warns once per variable, not once per wrapped command', () => {
    const warn = spyOn(console, 'warn').mockImplementation(() => {})
    try {
      const resolver = new CredentialSourceResolver()
      const entries = [
        {
          name: 'GH_TOKEN',
          mode: 'mask' as const,
          source: src('process.exit(7)'),
        },
      ]
      // getCredentialRestrictions() runs this per wrapped command.
      for (let i = 0; i < 4; i++) {
        buildMaskedEnvVars(
          entries,
          ['api.github.com'],
          new SentinelRegistry(),
          {},
          resolver,
        )
      }
      expect(warn).toHaveBeenCalledTimes(1)
    } finally {
      warn.mockRestore()
    }
  })

  test('the warning does not carry what the command printed', () => {
    const warn = spyOn(console, 'warn').mockImplementation(() => {})
    try {
      buildMaskedEnvVars(
        [
          {
            name: 'GH_TOKEN',
            mode: 'mask',
            source: src(
              'process.stderr.write("ghp_leaked_via_stderr\\n");process.exit(1)',
            ),
          },
        ],
        ['api.github.com'],
        new SentinelRegistry(),
        {},
        new CredentialSourceResolver(),
      )
      const msg = String(warn.mock.calls[0]![0])
      expect(msg).toContain('GH_TOKEN')
      expect(msg).toContain('exited 1')
      expect(msg).not.toContain('ghp_leaked_via_stderr')
      expect(msg).toContain('SRT_DEBUG')
    } finally {
      warn.mockRestore()
    }
  })

  test('a sourced value that cannot be masked is withheld, not left absent', () => {
    const warn = spyOn(console, 'warn').mockImplementation(() => {})
    try {
      const reg = new SentinelRegistry()
      // decode "jwt" against a value that is not a JWT is a fail-open
      // path. For an env-sourced entry that means "inherit the real
      // value"; a sourced entry has nothing to inherit, and an exported
      // copy alongside it must not be what gets inherited.
      const { setEnvVars, resolvedValues, degradeToUnsetNames } =
        buildMaskedEnvVars(
          [
            {
              name: 'GH_TOKEN',
              mode: 'mask',
              decode: 'jwt',
              source: printing('ghp_not_a_jwt'),
            },
          ],
          ['api.github.com'],
          reg,
          { GH_TOKEN: 'ghp_real_and_exported' },
          new CredentialSourceResolver(),
        )
      expect(degradeToUnsetNames).toEqual(['GH_TOKEN'])
      expect(setEnvVars['GH_TOKEN']).toBeUndefined()
      // Nothing downstream may see a value that was never masked.
      expect(resolvedValues['GH_TOKEN']).toBeUndefined()
      const msg = String(warn.mock.calls[0]![0])
      expect(msg).toContain('UNSET')
      expect(msg).not.toContain('UNPROTECTED')
    } finally {
      warn.mockRestore()
    }
  })

  test('an env-sourced entry still fails open on the same path', () => {
    const warn = spyOn(console, 'warn').mockImplementation(() => {})
    try {
      const { setEnvVars, degradeToUnsetNames } = buildMaskedEnvVars(
        [{ name: 'GH_TOKEN', mode: 'mask', decode: 'jwt' }],
        ['api.github.com'],
        new SentinelRegistry(),
        { GH_TOKEN: 'ghp_not_a_jwt' },
      )
      expect(degradeToUnsetNames).toEqual([])
      expect(setEnvVars['GH_TOKEN']).toBeUndefined()
      expect(String(warn.mock.calls[0]![0])).toContain('UNPROTECTED')
    } finally {
      warn.mockRestore()
    }
  })

  test('a credential named __proto__ still reaches resolvedValues', () => {
    // envVarNameSchema admits it, and on a plain object the assignment
    // would hit Object.prototype's setter and vanish.
    const { resolvedValues } = buildMaskedEnvVars(
      [{ name: '__proto__', mode: 'mask', source: printing('sourced') }],
      ['api.example.com'],
      new SentinelRegistry(),
      {},
      new CredentialSourceResolver(),
    )
    expect(Object.keys(resolvedValues)).toEqual(['__proto__'])
    expect(resolvedValues['__proto__']).toBe('sourced')
  })

  test('reports only sourced values in resolvedValues', () => {
    const reg = new SentinelRegistry()
    const { resolvedValues } = buildMaskedEnvVars(
      [
        { name: 'FROM_ENV', mode: 'mask' },
        { name: 'FROM_SRC', mode: 'mask', source: printing('sourced') },
      ],
      ['api.example.com'],
      reg,
      { FROM_ENV: 'exported' },
      new CredentialSourceResolver(),
    )
    expect(resolvedValues).toEqual({ FROM_SRC: 'sourced' })
  })

  test('structured extract applies to a sourced value', () => {
    const reg = new SentinelRegistry()
    const url = 'postgres://alice:s3cret@db.example.com:5432/mydb'
    const { setEnvVars } = buildMaskedEnvVars(
      [
        {
          name: 'DATABASE_URL',
          mode: 'mask',
          extract: '://[^:]+:([^@]+)@',
          source: printing(`${url}\n`),
        },
      ],
      ['db.example.com'],
      reg,
      {},
      new CredentialSourceResolver(),
    )
    const fake = setEnvVars['DATABASE_URL']!
    expect(fake).toContain('postgres://alice:')
    expect(fake).toContain('@db.example.com:5432/mydb')
    expect(fake).not.toContain('s3cret')
  })

  test('an entry with no source still reads the host environment', () => {
    const reg = new SentinelRegistry()
    const { setEnvVars, resolvedValues } = buildMaskedEnvVars(
      [{ name: 'GH_TOKEN', mode: 'mask' }],
      ['api.github.com'],
      reg,
      { GH_TOKEN: 'ghp_exported' },
    )
    expect(reg.lookupReal(setEnvVars['GH_TOKEN']!)).toBe('ghp_exported')
    expect(resolvedValues).toEqual({})
  })
})

describe('AWS pairing of sourced credentials', () => {
  const awsEntries = [
    {
      name: 'AWS_ACCESS_KEY_ID',
      mode: 'mask' as const,
      source: printing('AKIAREAL000000000000'),
    },
    {
      name: 'AWS_SECRET_ACCESS_KEY',
      mode: 'mask' as const,
      source: printing('realsecret/abcdefghijklmnopqrstuvwxyz01'),
    },
  ]

  function build() {
    const reg = new SentinelRegistry()
    const built = buildMaskedEnvVars(
      awsEntries,
      ['sts.amazonaws.com'],
      reg,
      {},
      new CredentialSourceResolver(),
    )
    return { reg, ...built }
  }

  test('pairs when the resolved values are overlaid on the environment', () => {
    const { setEnvVars, resolvedValues } = build()
    const pairs = new AwsPairRegistry()
    registerAwsPairs(
      awsEntries,
      undefined,
      ['sts.amazonaws.com'],
      setEnvVars,
      pairs,
      {
        ...resolvedValues,
      },
    )
    expect(pairs.size).toBe(1)
    const pair = pairs.lookup(setEnvVars['AWS_ACCESS_KEY_ID']!)
    expect(pair?.realAccessKeyId).toBe('AKIAREAL000000000000')
    expect(pair?.realSecretAccessKey).toBe(
      'realsecret/abcdefghijklmnopqrstuvwxyz01',
    )
  })

  test('without the overlay the pair is skipped, and silently', () => {
    // Regression guard for why the overlay exists. Both variables are
    // masked, so the half-masking warning does not fire; the pair simply
    // never registers and the sandbox signs SigV4 with the placeholder
    // secret against an upstream that can only reject it.
    const warn = spyOn(console, 'warn').mockImplementation(() => {})
    try {
      const { setEnvVars } = build()
      const pairs = new AwsPairRegistry()
      registerAwsPairs(
        awsEntries,
        undefined,
        ['sts.amazonaws.com'],
        setEnvVars,
        pairs,
        {},
      )
      expect(pairs.size).toBe(0)
      expect(warn).not.toHaveBeenCalled()
    } finally {
      warn.mockRestore()
    }
  })
})

describe('source config validation', () => {
  // tlsTerminate is required for any masked entry, and without it these cases
  // would all fail validation for a reason that has nothing to do with
  // `source`.
  const withEnvVars = (envVars: unknown) => ({
    network: {
      allowedDomains: ['api.github.com'],
      deniedDomains: [],
      tlsTerminate: {},
    },
    filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    credentials: { envVars },
  })

  test('accepts a command source on a masked entry', () => {
    const r = SandboxRuntimeConfigSchema.safeParse(
      withEnvVars([
        {
          name: 'GH_TOKEN',
          mode: 'mask',
          source: {
            type: 'command',
            command: 'op',
            args: ['read', 'op://vault/gh/token'],
            timeoutMs: 5000,
          },
        },
      ]),
    )
    expect(r.success).toBe(true)
  })

  test('rejects a source on a deny entry', () => {
    const r = SandboxRuntimeConfigSchema.safeParse(
      withEnvVars([
        {
          name: 'GH_TOKEN',
          mode: 'deny',
          source: { type: 'command', command: 'op' },
        },
      ]),
    )
    expect(r.success).toBe(false)
    expect(JSON.stringify(r.error?.issues)).toContain('source requires mode')
  })

  test('rejects an unknown key inside source', () => {
    const r = SandboxRuntimeConfigSchema.safeParse(
      withEnvVars([
        {
          name: 'GH_TOKEN',
          mode: 'mask',
          source: { type: 'command', command: 'op', shell: true },
        },
      ]),
    )
    expect(r.success).toBe(false)
    expect(JSON.stringify(r.error?.issues)).toContain('shell')
  })

  test('rejects a source with no type discriminator', () => {
    const r = SandboxRuntimeConfigSchema.safeParse(
      withEnvVars([
        { name: 'GH_TOKEN', mode: 'mask', source: { command: 'op' } },
      ]),
    )
    expect(r.success).toBe(false)
  })

  test('rejects an empty command', () => {
    const r = SandboxRuntimeConfigSchema.safeParse(
      withEnvVars([
        {
          name: 'GH_TOKEN',
          mode: 'mask',
          source: { type: 'command', command: '' },
        },
      ]),
    )
    expect(r.success).toBe(false)
  })
})
