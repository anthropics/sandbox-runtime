import { describe, test, expect, beforeAll, afterAll, spyOn } from 'bun:test'
import { spawn, spawnSync } from 'node:child_process'
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import {
  createServer as createHttpServer,
  type IncomingHttpHeaders,
} from 'node:http'
import type { Server, AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { extractAndSubstitute } from '../../src/sandbox/credential-extract.js'
import {
  MaskedFileStore,
  buildMaskedFileBinds,
  MASKED_FILE_STORE_PREFIX,
} from '../../src/sandbox/credential-mask-files.js'
import {
  SentinelRegistry,
  SENTINEL_PREFIX,
} from '../../src/sandbox/credential-sentinel.js'
import { verifyJwt } from '../../src/sandbox/credential-decode.js'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import type { SandboxRuntimeConfig } from '../../src/sandbox/sandbox-config.js'
import { wrapCommandWithSandboxMacOS } from '../../src/sandbox/macos-sandbox-utils.js'
import { isLinux } from '../helpers/platform.js'

/**
 * Unit tests for the fake-file store and bind builder. Platform-agnostic;
 * these touch only the host filesystem and the sentinel registry.
 */

const FIXTURE_DIR = join(tmpdir(), 'srt-credmask-fixture-' + Date.now())
const TOKEN_FILE = join(FIXTURE_DIR, 'gh-token')
const TOKEN_CONTENT = 'ghp_realsecret_abcdef0123456789'
const SUBDIR = join(FIXTURE_DIR, 'aws-dir')

const HOSTS_YML = join(FIXTURE_DIR, 'hosts.yml')
const HOSTS_TOKEN = 'gho_realsecret_zyx9876543210'
const HOSTS_CONTENT =
  'github.com:\n' +
  '    user: alice\n' +
  `    oauth_token: ${HOSTS_TOKEN}\n` +
  '    git_protocol: https\n'

beforeAll(() => {
  mkdirSync(SUBDIR, { recursive: true })
  writeFileSync(TOKEN_FILE, TOKEN_CONTENT)
  writeFileSync(HOSTS_YML, HOSTS_CONTENT)
})

afterAll(() => {
  rmSync(FIXTURE_DIR, { recursive: true, force: true })
})

describe('MaskedFileStore', () => {
  test('lazily creates a temp dir under os.tmpdir()', () => {
    const store = new MaskedFileStore()
    expect(store.dirPath).toBeUndefined()
    const fake = store.write('k', 'sentinel')
    expect(store.dirPath).toBeDefined()
    expect(store.dirPath!.startsWith(tmpdir())).toBe(true)
    expect(store.dirPath!).toContain(MASKED_FILE_STORE_PREFIX)
    expect(readFileSync(fake, 'utf8')).toBe('sentinel')
    store.dispose()
  })

  test('write does not follow a symlink planted at the fake path', () => {
    // Cross-invocation attack: if a prior sandbox run could write the
    // store dir, it could leave `ln -s <victim> 0.fake` behind and the
    // next host-side write() would clobber <victim>. write() must unlink
    // first so the sentinel lands in a fresh regular file.
    const store = new MaskedFileStore()
    const fake = store.write('k', 'first')
    const victim = join(FIXTURE_DIR, 'symlink-victim')
    writeFileSync(victim, 'victim-bytes')
    rmSync(fake)
    symlinkSync(victim, fake)

    store.write('k', 'second')

    expect(readFileSync(victim, 'utf8')).toBe('victim-bytes')
    expect(lstatSync(fake).isSymbolicLink()).toBe(false)
    expect(readFileSync(fake, 'utf8')).toBe('second')
    store.dispose()
  })

  test('write is idempotent on key — same fake path, content overwritten', () => {
    const store = new MaskedFileStore()
    const a = store.write('file:/x', 'first')
    const b = store.write('file:/x', 'second')
    expect(b).toBe(a)
    expect(readFileSync(a, 'utf8')).toBe('second')
    expect(readdirSync(store.dirPath!)).toHaveLength(1)
    store.dispose()
  })

  test('dispose removes the temp dir and is idempotent', () => {
    const store = new MaskedFileStore()
    store.write('k', 'x')
    const dir = store.dirPath!
    expect(existsSync(dir)).toBe(true)
    store.dispose()
    expect(existsSync(dir)).toBe(false)
    expect(store.dirPath).toBeUndefined()
    store.dispose() // no-op, no throw
  })
})

describe('extractAndSubstitute', () => {
  // Deterministic sentinel callback for unit tests: <S0>, <S1>, …
  const S = (_: string, i: number) => `<S${i}>`

  test('single match: capture replaced by sentinel, rest preserved', () => {
    const content = 'github.com:\n  oauth_token: ghp_real\n  user: alice\n'
    const out = extractAndSubstitute(content, 'oauth_token:\\s*(\\S+)', S)
    expect(out).not.toBeNull()
    expect(out!.captures).toEqual(['ghp_real'])
    expect(out!.fakeContent).toBe(
      'github.com:\n  oauth_token: <S0>\n  user: alice\n',
    )
    expect(out!.fakeContent).not.toContain('ghp_real')
  })

  test('multiple distinct matches each get their own sentinel index', () => {
    const content =
      'machine a.example.com password tok-A\n' +
      'machine b.example.com password tok-B\n'
    const out = extractAndSubstitute(content, 'password\\s+(\\S+)', S)!
    expect(out.captures).toEqual(['tok-A', 'tok-B'])
    expect(out.fakeContent).toBe(
      'machine a.example.com password <S0>\n' +
        'machine b.example.com password <S1>\n',
    )
  })

  test('duplicate captures dedupe to one sentinel index', () => {
    const content = 'password tok-X\npassword tok-X\npassword tok-Y\n'
    const out = extractAndSubstitute(content, 'password (\\S+)', S)!
    expect(out.captures).toEqual(['tok-X', 'tok-Y'])
    expect(out.fakeContent).toBe(
      'password <S0>\npassword <S0>\npassword <S1>\n',
    )
  })

  test('returns null when the pattern matches nothing', () => {
    expect(
      extractAndSubstitute('no creds here', 'password (\\S+)', S),
    ).toBeNull()
  })

  test('throws when a match leaves group 1 undefined', () => {
    // Optional group that does not participate — accepting this would
    // mask nothing for that occurrence, so the helper refuses.
    expect(() =>
      extractAndSubstitute('token: \n', 'token: (\\S+)?', S),
    ).toThrow(/capture group 1/)
  })

  test('only the regex-matched span is replaced; coincidental occurrences elsewhere are left intact', () => {
    // The captured value `abc123` also appears in a comment line that the
    // regex does not match. Offset-based replacement touches only group 1
    // of each match, so the comment is preserved byte-for-byte. The old
    // value-based pass would have rewritten both.
    const content =
      'oauth_token: abc123\n' + '# note: the token abc123 is stored above\n'
    const out = extractAndSubstitute(content, 'oauth_token:\\s*(\\S+)', S)!
    expect(out.captures).toEqual(['abc123'])
    expect(out.fakeContent).toBe(
      'oauth_token: <S0>\n' + '# note: the token abc123 is stored above\n',
    )
  })

  test('a capture that is a substring of another does not corrupt the longer one', () => {
    // tok is a prefix of tok-long; offset-based replacement touches only
    // each match's own group-1 span, so neither capture corrupts the other.
    const content = 'a=tok-long b=tok'
    const out = extractAndSubstitute(content, '[ab]=(\\S+)', S)!
    expect(out.captures).toEqual(['tok-long', 'tok'])
    expect(out.fakeContent).toBe('a=<S0> b=<S1>')
  })

  test('overlapping pattern matches are handled by the regex engine, not us', () => {
    // matchAll with /g does not return overlapping matches, so the
    // helper sees only the engine's non-overlapping set. This test pins
    // that assumption: 'aaa' against /(aa)/g matches once at index 0.
    const out = extractAndSubstitute('aaa', '(aa)', S)!
    expect(out.captures).toEqual(['aa'])
    expect(out.fakeContent).toBe('<S0>a')
  })

  test('empty captures are skipped, not turned into sentinels', () => {
    // (\S*) can capture the empty string at end-of-line; a zero-width
    // span has nothing to mask, so the helper leaves it as-is.
    const out = extractAndSubstitute('k=v\nk=\n', 'k=(\\S*)', S)!
    expect(out.captures).toEqual(['v'])
    expect(out.fakeContent).toBe('k=<S0>\nk=\n')
  })

  test('callback receives the captured value and its dedupe index', () => {
    const calls: Array<[string, number]> = []
    extractAndSubstitute('k=A k=B k=A', 'k=(\\S+)', (cap, i) => {
      calls.push([cap, i])
      return '_'
    })
    expect(calls).toEqual([
      ['A', 0],
      ['B', 1],
      ['A', 0],
    ])
  })

  describe('maskDuplicates', () => {
    test('a verbatim duplicate outside the match is also masked when true', () => {
      const content =
        'oauth_token: ghp_supersecret123\n' +
        '# backup copy: ghp_supersecret123\n'
      const out = extractAndSubstitute(content, 'oauth_token:\\s*(\\S+)', S, {
        maskDuplicates: true,
      })!
      expect(out.captures).toEqual(['ghp_supersecret123'])
      expect(out.fakeContent).toBe('oauth_token: <S0>\n# backup copy: <S0>\n')
      expect(out.fakeContent).not.toContain('ghp_supersecret123')
    })

    test('explicit false keeps the offset-only behaviour', () => {
      const content =
        'oauth_token: ghp_supersecret123\n' +
        '# backup copy: ghp_supersecret123\n'
      const out = extractAndSubstitute(content, 'oauth_token:\\s*(\\S+)', S, {
        maskDuplicates: false,
      })!
      expect(out.fakeContent).toBe(
        'oauth_token: <S0>\n# backup copy: ghp_supersecret123\n',
      )
    })

    test('inserted sentinels survive when the capture is a substring of the sentinel literal', () => {
      // The capture `value` is a substring of the sentinel `fake_value_0`.
      // A naive post-pass split/join over the substituted output would
      // re-match inside the sentinels it just inserted and mangle them;
      // spans are computed against the original content instead.
      const content = 'secret: value\n# repeated: value\n'
      const out = extractAndSubstitute(
        content,
        'secret:\\s*(\\S+)',
        () => 'fake_value_0',
        { maskDuplicates: true },
      )!
      expect(out.fakeContent).toBe(
        'secret: fake_value_0\n# repeated: fake_value_0\n',
      )
    })

    test('a short capture also replaces coincidental substrings (documented collateral)', () => {
      // The verbatim scan is raw substring matching — `abc` inside the
      // unrelated word `xabcy` is replaced too. This pins the documented
      // semantics: the option is for long, high-entropy secrets.
      const content = 'token: abc\nword: xabcy\n'
      const out = extractAndSubstitute(content, 'token:\\s*(\\S+)', S, {
        maskDuplicates: true,
      })!
      expect(out.fakeContent).toBe('token: <S0>\nword: x<S0>y\n')
    })

    test('a capture that is a substring of another cannot claim part of the longer one', () => {
      // tok is a substring of tok-long; the verbatim pass runs
      // longest-capture-first, so the duplicated tok-long in the comment
      // is claimed whole by <S0> rather than partially by <S1>.
      const content = 'a=tok-long b=tok\n# dup: tok-long and tok\n'
      const out = extractAndSubstitute(content, '[ab]=(\\S+)', S, {
        maskDuplicates: true,
      })!
      expect(out.captures).toEqual(['tok-long', 'tok'])
      expect(out.fakeContent).toBe('a=<S0> b=<S1>\n# dup: <S0> and <S1>\n')
    })

    test('the duplicate pass does not re-invoke the sentinel callback', () => {
      const calls: Array<[string, number]> = []
      extractAndSubstitute(
        'k=A\n# A again: A\n',
        'k=(\\S+)',
        (cap, i) => {
          calls.push([cap, i])
          return `<S${i}>`
        },
        { maskDuplicates: true },
      )
      expect(calls).toEqual([['A', 0]])
    })

    test('a declined capture (callback returns it unchanged) is not duplicate-scanned', () => {
      // The decode-verification gate declines a candidate by returning the
      // capture itself. Its duplicates must stay unmasked, and its spans
      // must not block another capture's verbatim occurrences.
      const content = 'k=good k=bad\n# dup: good and bad\n'
      const out = extractAndSubstitute(
        content,
        'k=(\\S+)',
        (cap, i) => (cap === 'bad' ? cap : `<S${i}>`),
        { maskDuplicates: true },
      )!
      expect(out.fakeContent).toBe('k=<S0> k=bad\n# dup: <S0> and bad\n')
    })
  })
})

describe('buildMaskedFileBinds', () => {
  test('registers a sentinel keyed on file path and writes it to a fake', () => {
    const reg = new SentinelRegistry()
    const store = new MaskedFileStore()
    const { binds } = buildMaskedFileBinds(
      [{ path: TOKEN_FILE, mode: 'mask' }],
      ['api.github.com'],
      reg,
      store,
    )
    expect(binds).toHaveLength(1)
    expect(binds[0]!.realPath).toBe(realpathSync(TOKEN_FILE))
    const fakeContent = readFileSync(binds[0]!.fakePath, 'utf8')
    expect(fakeContent.startsWith(SENTINEL_PREFIX)).toBe(true)
    // The fake holds the sentinel, never the real bytes.
    expect(fakeContent).not.toContain(TOKEN_CONTENT)
    // The registry maps that sentinel back to the real file content.
    expect(reg.lookupReal(fakeContent)).toBe(TOKEN_CONTENT)
    store.dispose()
  })

  test('a file sentinel only substitutes at its own injectHosts', () => {
    const reg = new SentinelRegistry()
    const store = new MaskedFileStore()
    const { binds } = buildMaskedFileBinds(
      [{ path: TOKEN_FILE, mode: 'mask', injectHosts: ['api.github.com'] }],
      ['api.github.com', 'evil.example.com'],
      reg,
      store,
    )
    const sentinel = readFileSync(binds[0]!.fakePath, 'utf8')
    const eq = (h: string, p: string) => h === p

    const toGh = { authorization: `Bearer ${sentinel}` }
    reg.substituteInHeaders(toGh, 'api.github.com', eq)
    expect(toGh.authorization).toBe(`Bearer ${TOKEN_CONTENT}`)

    const toEvil = { authorization: `Bearer ${sentinel}` }
    reg.substituteInHeaders(toEvil, 'evil.example.com', eq)
    expect(toEvil.authorization).toBe(`Bearer ${sentinel}`)
    store.dispose()
  })

  test('absent injectHosts → defaults to allowedDomains', () => {
    const reg = new SentinelRegistry()
    const store = new MaskedFileStore()
    const { binds } = buildMaskedFileBinds(
      [{ path: TOKEN_FILE, mode: 'mask' }],
      ['fallback.example.com'],
      reg,
      store,
    )
    const sentinel = readFileSync(binds[0]!.fakePath, 'utf8')
    const eq = (h: string, p: string) => h === p
    const headers = { authorization: sentinel }
    reg.substituteInHeaders(headers, 'fallback.example.com', eq)
    expect(headers.authorization).toBe(TOKEN_CONTENT)
    store.dispose()
  })

  test('skips a masked file that does not exist on the host', () => {
    const reg = new SentinelRegistry()
    const store = new MaskedFileStore()
    const { binds, degradeToDenyPaths } = buildMaskedFileBinds(
      [{ path: join(FIXTURE_DIR, 'no-such-file'), mode: 'mask' }],
      [],
      reg,
      store,
    )
    expect(binds).toHaveLength(0)
    expect(degradeToDenyPaths).toHaveLength(0)
    expect(reg.size).toBe(0)
    // No fake was written → store dir was never created.
    expect(store.dirPath).toBeUndefined()
    store.dispose()
  })

  test('skips a masked entry that resolves to a directory', () => {
    const reg = new SentinelRegistry()
    const store = new MaskedFileStore()
    const { binds } = buildMaskedFileBinds(
      [{ path: SUBDIR, mode: 'mask' }],
      [],
      reg,
      store,
    )
    expect(binds).toHaveLength(0)
    expect(reg.size).toBe(0)
    store.dispose()
  })

  test('skips a masked file with non-UTF-8 content', () => {
    // 0xFF is never valid in UTF-8. A utf8 read would silently replace it
    // with U+FFFD and the proxy would inject corrupted bytes; we skip
    // instead so the misconfiguration surfaces.
    const binFile = join(FIXTURE_DIR, 'binary-cred')
    writeFileSync(binFile, Buffer.from([0x67, 0x68, 0x70, 0x5f, 0xff, 0xfe]))
    const reg = new SentinelRegistry()
    const store = new MaskedFileStore()
    const { binds, degradeToDenyPaths } = buildMaskedFileBinds(
      [{ path: binFile, mode: 'mask' }],
      [],
      reg,
      store,
    )
    expect(binds).toHaveLength(0)
    expect(degradeToDenyPaths).toHaveLength(0)
    expect(reg.size).toBe(0)
    store.dispose()
  })

  test('ignores deny-mode entries', () => {
    const reg = new SentinelRegistry()
    const store = new MaskedFileStore()
    const { binds } = buildMaskedFileBinds(
      [{ path: TOKEN_FILE, mode: 'deny' }],
      [],
      reg,
      store,
    )
    expect(binds).toHaveLength(0)
    store.dispose()
  })

  test('extract: fake preserves structure with sentinel substituted in', () => {
    const reg = new SentinelRegistry()
    const store = new MaskedFileStore()
    const { binds, degradeToDenyPaths } = buildMaskedFileBinds(
      [
        {
          path: HOSTS_YML,
          mode: 'mask',
          extract: 'oauth_token:\\s*(\\S+)',
          injectHosts: ['api.github.com'],
        },
      ],
      ['api.github.com'],
      reg,
      store,
    )
    expect(degradeToDenyPaths).toHaveLength(0)
    expect(binds).toHaveLength(1)
    const fake = readFileSync(binds[0]!.fakePath, 'utf8')
    // Structure preserved byte-for-byte except the token span.
    expect(fake).toContain('github.com:\n')
    expect(fake).toContain('    user: alice\n')
    expect(fake).toContain('    git_protocol: https\n')
    expect(fake).not.toContain(HOSTS_TOKEN)
    // The token was replaced by a sentinel registered for #0.
    const m = fake.match(/oauth_token: (\S+)/)
    expect(m![1]!.startsWith(SENTINEL_PREFIX)).toBe(true)
    expect(reg.lookupReal(m![1]!)).toBe(HOSTS_TOKEN)
    expect(reg.size).toBe(1)
    store.dispose()
  })

  test('extract with maskDuplicates: a duplicate in a comment is masked in the fake', () => {
    const dupFile = join(FIXTURE_DIR, 'hosts-dup.yml')
    writeFileSync(
      dupFile,
      `# rotate ${HOSTS_TOKEN} before 2027\n` + HOSTS_CONTENT,
    )
    const reg = new SentinelRegistry()
    const store = new MaskedFileStore()
    const { binds } = buildMaskedFileBinds(
      [
        {
          path: dupFile,
          mode: 'mask',
          extract: 'oauth_token:\\s*(\\S+)',
          maskDuplicates: true,
        },
      ],
      ['api.github.com'],
      reg,
      store,
    )
    expect(binds).toHaveLength(1)
    const fake = readFileSync(binds[0]!.fakePath, 'utf8')
    expect(fake).not.toContain(HOSTS_TOKEN)
    // Both the matched span and the comment duplicate carry the same
    // sentinel, registered once.
    const sentinels = fake.match(new RegExp(`${SENTINEL_PREFIX}\\S+`, 'g'))!
    expect(sentinels).toHaveLength(2)
    expect(new Set(sentinels).size).toBe(1)
    expect(reg.lookupReal(sentinels[0]!)).toBe(HOSTS_TOKEN)
    expect(reg.size).toBe(1)
    store.dispose()
  })

  test('extract without maskDuplicates leaves a comment duplicate intact', () => {
    const dupFile = join(FIXTURE_DIR, 'hosts-dup-off.yml')
    writeFileSync(
      dupFile,
      `# rotate ${HOSTS_TOKEN} before 2027\n` + HOSTS_CONTENT,
    )
    const reg = new SentinelRegistry()
    const store = new MaskedFileStore()
    const { binds } = buildMaskedFileBinds(
      [{ path: dupFile, mode: 'mask', extract: 'oauth_token:\\s*(\\S+)' }],
      ['api.github.com'],
      reg,
      store,
    )
    expect(binds).toHaveLength(1)
    const fake = readFileSync(binds[0]!.fakePath, 'utf8')
    // Default (#326) behaviour: only the regex-matched span is replaced.
    expect(fake).toContain(`# rotate ${HOSTS_TOKEN} before 2027\n`)
    expect(fake).not.toContain(`oauth_token: ${HOSTS_TOKEN}`)
    store.dispose()
  })

  describe('extract with no match (onExtractNoMatch)', () => {
    const noMatch = { path: HOSTS_YML, mode: 'mask', extract: 'nope: (\\S+)' }

    test('default → "warn": file left unprotected, stderr warning', () => {
      const warnSpy = spyOn(console, 'warn').mockImplementation(() => {})
      const reg = new SentinelRegistry()
      const store = new MaskedFileStore()
      const { binds, degradeToDenyPaths } = buildMaskedFileBinds(
        [noMatch] as const,
        ['api.github.com'],
        reg,
        store,
      )
      // Fail-open: no bind, no deny — the entry is skipped entirely so
      // the real file stays readable via the root mount.
      expect(binds).toHaveLength(0)
      expect(degradeToDenyPaths).toHaveLength(0)
      expect(reg.size).toBe(0)
      expect(store.dirPath).toBeUndefined()
      // A loud stderr warning surfaces the config error to the operator.
      expect(warnSpy).toHaveBeenCalledTimes(1)
      const msg = warnSpy.mock.calls[0]![0] as string
      expect(msg).toContain('UNPROTECTED')
      expect(msg).toContain(HOSTS_YML)
      expect(msg).toContain('nope: (\\S+)')
      warnSpy.mockRestore()
      store.dispose()
    })

    test('explicit "warn" matches the default', () => {
      const warnSpy = spyOn(console, 'warn').mockImplementation(() => {})
      const reg = new SentinelRegistry()
      const store = new MaskedFileStore()
      const { binds, degradeToDenyPaths } = buildMaskedFileBinds(
        [{ ...noMatch, onExtractNoMatch: 'warn' }] as const,
        [],
        reg,
        store,
      )
      expect(binds).toHaveLength(0)
      expect(degradeToDenyPaths).toHaveLength(0)
      expect(warnSpy).toHaveBeenCalledTimes(1)
      warnSpy.mockRestore()
      store.dispose()
    })

    test('"deny": entry degrades to read-deny (fail-closed)', () => {
      const warnSpy = spyOn(console, 'warn').mockImplementation(() => {})
      const reg = new SentinelRegistry()
      const store = new MaskedFileStore()
      const { binds, degradeToDenyPaths } = buildMaskedFileBinds(
        [{ ...noMatch, onExtractNoMatch: 'deny' }] as const,
        ['api.github.com'],
        reg,
        store,
      )
      // No bind is emitted (the real file is NOT exposed); the resolved
      // path is reported for the read-deny set.
      expect(binds).toHaveLength(0)
      expect(degradeToDenyPaths).toEqual([realpathSync(HOSTS_YML)])
      expect(reg.size).toBe(0)
      expect(store.dirPath).toBeUndefined()
      // No stderr warning — deny is a configured outcome, not a surprise.
      expect(warnSpy).not.toHaveBeenCalled()
      warnSpy.mockRestore()
      store.dispose()
    })

    test('"error": throws with a clear message', () => {
      const reg = new SentinelRegistry()
      const store = new MaskedFileStore()
      expect(() =>
        buildMaskedFileBinds(
          [{ ...noMatch, onExtractNoMatch: 'error' }] as const,
          [],
          reg,
          store,
        ),
      ).toThrow(/matched nothing.*onExtractNoMatch: "error"/)
      store.dispose()
    })

    test('onExtractNoMatch is per-entry: one "deny" does not affect a sibling "warn"', () => {
      const warnSpy = spyOn(console, 'warn').mockImplementation(() => {})
      const other = join(FIXTURE_DIR, 'other.yml')
      writeFileSync(other, 'k: v\n')
      const reg = new SentinelRegistry()
      const store = new MaskedFileStore()
      const { binds, degradeToDenyPaths } = buildMaskedFileBinds(
        [
          { ...noMatch, onExtractNoMatch: 'deny' },
          { path: other, mode: 'mask', extract: 'nope: (\\S+)' },
        ] as const,
        [],
        reg,
        store,
      )
      expect(binds).toHaveLength(0)
      expect(degradeToDenyPaths).toEqual([realpathSync(HOSTS_YML)])
      expect(warnSpy).toHaveBeenCalledTimes(1)
      expect(warnSpy.mock.calls[0]![0] as string).toContain(other)
      warnSpy.mockRestore()
      store.dispose()
    })
  })
})

describe('buildMaskedFileBinds decode: "jwt"', () => {
  const b64u = (s: string) => Buffer.from(s, 'utf8').toString('base64url')

  // Real-shaped JWTs: HS256 header, JSON payload, garbage signature.
  const REAL_JWT =
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' +
    b64u('{"sub":"1234567890","name":"John Doe","iat":1516239022}') +
    '.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
  const REAL_JWT_2 =
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' +
    b64u('{"sub":"other","iat":1516239022}') +
    '.c2lnbmF0dXJl'
  // Matches the default eyJ-triple pattern but is not a JWT: the first
  // segment decodes to truncated (invalid) JSON.
  const PSEUDO_JWT = `${b64u('{"oops')}.${b64u('{}')}.c2ln`

  const DECODE_DIR = join(tmpdir(), 'srt-credmask-decode-' + Date.now())

  beforeAll(() => {
    mkdirSync(DECODE_DIR, { recursive: true })
  })

  afterAll(() => {
    rmSync(DECODE_DIR, { recursive: true, force: true })
  })

  test('default pattern: a JWT in a JSON credentials file becomes a parseable fake JWT', () => {
    const file = join(DECODE_DIR, 'credentials.json')
    writeFileSync(file, `{"access_token":"${REAL_JWT}","note":"keep"}`)
    const reg = new SentinelRegistry()
    const store = new MaskedFileStore()
    const { binds } = buildMaskedFileBinds(
      [{ path: file, mode: 'mask', decode: 'jwt' }],
      ['api.example.com'],
      reg,
      store,
    )
    expect(binds).toHaveLength(1)
    const fake = readFileSync(binds[0]!.fakePath, 'utf8')
    expect(fake).not.toContain(REAL_JWT)
    // Structure preserved around the swapped span.
    expect(fake).toContain('"note":"keep"')
    const fakeToken = fake.match(/"access_token":"([^"]+)"/)![1]!

    // The fake IS a parseable JWT: three segments, JSON header/payload.
    expect(verifyJwt(fakeToken)).toBe(true)
    const [h, p, sig] = fakeToken.split('.')
    const header = JSON.parse(
      Buffer.from(h!, 'base64url').toString('utf8'),
    ) as Record<string, unknown>
    // HS256 + garbage signature, never alg:none — see mintFakeJwt.
    expect(header).toEqual({ alg: 'HS256', typ: 'JWT' })
    expect(sig).toBe('c3J0LWZha2U')
    const payload = JSON.parse(
      Buffer.from(p!, 'base64url').toString('utf8'),
    ) as { sub: string }
    expect(payload.sub).toContain(SENTINEL_PREFIX)

    // Registry roundtrip: the full fake JWT is the sentinel key.
    expect(reg.lookupReal(fakeToken)).toBe(REAL_JWT)
    store.dispose()
  })

  test('a regex-matched but non-JWT candidate is left untouched', () => {
    const file = join(DECODE_DIR, 'mixed')
    writeFileSync(file, `good: ${REAL_JWT}\nblob: ${PSEUDO_JWT}\n`)
    const reg = new SentinelRegistry()
    const store = new MaskedFileStore()
    const { binds } = buildMaskedFileBinds(
      [{ path: file, mode: 'mask', decode: 'jwt' }],
      ['api.example.com'],
      reg,
      store,
    )
    expect(binds).toHaveLength(1)
    const fake = readFileSync(binds[0]!.fakePath, 'utf8')
    // The real JWT is masked; the over-matched blob is preserved as-is
    // (it is not a JWT, so there is nothing to protect).
    expect(fake).not.toContain(REAL_JWT)
    expect(fake).toContain(`blob: ${PSEUDO_JWT}\n`)
    expect(reg.size).toBe(1)
    store.dispose()
  })

  test('all candidates failing verification → fail-open with warning', () => {
    const warnSpy = spyOn(console, 'warn').mockImplementation(() => {})
    const file = join(DECODE_DIR, 'only-blob')
    writeFileSync(file, `blob: ${PSEUDO_JWT}\n`)
    const reg = new SentinelRegistry()
    const store = new MaskedFileStore()
    const { binds } = buildMaskedFileBinds(
      [{ path: file, mode: 'mask', decode: 'jwt' }],
      ['api.example.com'],
      reg,
      store,
    )
    expect(binds).toHaveLength(0)
    expect(reg.size).toBe(0)
    expect(store.dirPath).toBeUndefined()
    expect(warnSpy).toHaveBeenCalledTimes(1)
    const msg = warnSpy.mock.calls[0]![0] as string
    expect(msg).toContain('UNPROTECTED')
    expect(msg).toContain(file)
    expect(msg).toContain('JWT')
    warnSpy.mockRestore()
    store.dispose()
  })

  test('no candidate matching at all → fail-open with warning', () => {
    const warnSpy = spyOn(console, 'warn').mockImplementation(() => {})
    const file = join(DECODE_DIR, 'no-jwt')
    writeFileSync(file, 'just some plain text\n')
    const reg = new SentinelRegistry()
    const store = new MaskedFileStore()
    const { binds } = buildMaskedFileBinds(
      [{ path: file, mode: 'mask', decode: 'jwt' }],
      ['api.example.com'],
      reg,
      store,
    )
    expect(binds).toHaveLength(0)
    expect(reg.size).toBe(0)
    expect(warnSpy).toHaveBeenCalledTimes(1)
    expect(warnSpy.mock.calls[0]![0] as string).toContain('UNPROTECTED')
    warnSpy.mockRestore()
    store.dispose()
  })

  test('explicit extract wins: only its captures are candidates, verification still applies', () => {
    const file = join(DECODE_DIR, 'tokens.yml')
    writeFileSync(
      file,
      `id_token: ${REAL_JWT}\nother_jwt: ${REAL_JWT_2}\nblob: x\n`,
    )
    const reg = new SentinelRegistry()
    const store = new MaskedFileStore()
    const { binds } = buildMaskedFileBinds(
      [
        {
          path: file,
          mode: 'mask',
          extract: 'id_token:\\s*(\\S+)',
          decode: 'jwt',
        },
      ],
      ['api.example.com'],
      reg,
      store,
    )
    expect(binds).toHaveLength(1)
    const fake = readFileSync(binds[0]!.fakePath, 'utf8')
    // The author's pattern is the candidate source: the other JWT is NOT
    // masked even though the default pattern would have found it.
    expect(fake).not.toContain(`id_token: ${REAL_JWT}`)
    expect(fake).toContain(`other_jwt: ${REAL_JWT_2}\n`)
    const fakeToken = fake.match(/id_token: (\S+)/)![1]!
    expect(verifyJwt(fakeToken)).toBe(true)
    expect(reg.lookupReal(fakeToken)).toBe(REAL_JWT)
    expect(reg.size).toBe(1)
    store.dispose()
  })

  test('decode + maskDuplicates: a verified JWT duplicated in a comment is masked with the same fake', () => {
    const file = join(DECODE_DIR, 'dup-jwt.yml')
    // The comment duplicate is outside the extract pattern's reach; the
    // pseudo-JWT candidate fails verification, so its comment duplicate
    // must stay untouched.
    writeFileSync(
      file,
      `id_token: ${REAL_JWT}\nblob: ${PSEUDO_JWT}\n` +
        `# rotate ${REAL_JWT} before 2027 (blob was ${PSEUDO_JWT})\n`,
    )
    const reg = new SentinelRegistry()
    const store = new MaskedFileStore()
    const { binds } = buildMaskedFileBinds(
      [
        {
          path: file,
          mode: 'mask',
          extract: '(?:id_token|blob):\\s*(\\S+)',
          decode: 'jwt',
          maskDuplicates: true,
        },
      ],
      ['api.example.com'],
      reg,
      store,
    )
    expect(binds).toHaveLength(1)
    const fake = readFileSync(binds[0]!.fakePath, 'utf8')
    expect(fake).not.toContain(REAL_JWT)
    // Both occurrences carry the SAME fake JWT — the duplicate reuses the
    // verified capture's sentinel without re-verification.
    const fakeToken = fake.match(/id_token: (\S+)/)![1]!
    expect(verifyJwt(fakeToken)).toBe(true)
    expect(fake).toContain(`# rotate ${fakeToken} before 2027`)
    expect(reg.lookupReal(fakeToken)).toBe(REAL_JWT)
    // The unverified candidate and its duplicate are left as-is.
    expect(fake).toContain(`blob: ${PSEUDO_JWT}\n`)
    expect(fake).toContain(`(blob was ${PSEUDO_JWT})`)
    expect(reg.size).toBe(1)
    store.dispose()
  })

  test('explicit extract capturing a non-JWT with decode → fail-open with warning', () => {
    const warnSpy = spyOn(console, 'warn').mockImplementation(() => {})
    const file = join(DECODE_DIR, 'not-a-jwt.yml')
    writeFileSync(file, 'id_token: opaque-session-cookie\n')
    const reg = new SentinelRegistry()
    const store = new MaskedFileStore()
    const { binds } = buildMaskedFileBinds(
      [
        {
          path: file,
          mode: 'mask',
          extract: 'id_token:\\s*(\\S+)',
          decode: 'jwt',
        },
      ],
      ['api.example.com'],
      reg,
      store,
    )
    expect(binds).toHaveLength(0)
    expect(reg.size).toBe(0)
    expect(warnSpy).toHaveBeenCalledTimes(1)
    warnSpy.mockRestore()
    store.dispose()
  })

  describe('maskClaims', () => {
    // A JWT whose payload carries a secret in one claim next to
    // claim-reading metadata a client legitimately needs.
    const CLAIMS_PAYLOAD = {
      sub: 'user-1',
      api_key: 'real-claim-secret-0123456789',
      aud: 'api.example.com',
      iat: 1516239022,
    }
    const CLAIMS_JWT =
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' +
      b64u(JSON.stringify(CLAIMS_PAYLOAD)) +
      '.Y2xhaW1zLXNpZw'

    test('masks the named claim inside the token; both registry mappings exist', () => {
      const file = join(DECODE_DIR, 'claims.json')
      writeFileSync(file, `{"id_token":"${CLAIMS_JWT}","note":"keep"}`)
      const reg = new SentinelRegistry()
      const store = new MaskedFileStore()
      const { binds } = buildMaskedFileBinds(
        [{ path: file, mode: 'mask', decode: 'jwt', maskClaims: ['api_key'] }],
        ['api.example.com'],
        reg,
        store,
      )
      expect(binds).toHaveLength(1)
      const fake = readFileSync(binds[0]!.fakePath, 'utf8')
      expect(fake).not.toContain(CLAIMS_JWT)
      expect(fake).not.toContain(CLAIMS_PAYLOAD.api_key)
      expect(fake).toContain('"note":"keep"')

      const fakeToken = fake.match(/"id_token":"([^"]+)"/)![1]!
      expect(verifyJwt(fakeToken)).toBe(true)
      // Header segment reused verbatim; signature is the filler.
      const [h, p, sig] = fakeToken.split('.')
      expect(h).toBe(CLAIMS_JWT.split('.')[0])
      expect(sig).toBe('c3J0LWZha2U')
      const payload = JSON.parse(
        Buffer.from(p!, 'base64url').toString('utf8'),
      ) as Record<string, unknown>
      // The named claim is a sentinel; every other claim is real.
      const claimSentinel = payload.api_key as string
      expect(claimSentinel).toStartWith(SENTINEL_PREFIX)
      expect(payload).toEqual({ ...CLAIMS_PAYLOAD, api_key: claimSentinel })

      // Mapping (a): whole fake token → whole real token (bearer usage).
      expect(reg.lookupReal(fakeToken)).toBe(CLAIMS_JWT)
      // Mapping (b): claim sentinel → real claim value (extracted usage).
      expect(reg.lookupReal(claimSentinel)).toBe(CLAIMS_PAYLOAD.api_key)
      expect(reg.size).toBe(2)
      store.dispose()
    })

    test('a named claim absent from the payload is skipped; matching claims still mask', () => {
      const file = join(DECODE_DIR, 'claims-partial.json')
      writeFileSync(file, `token: ${CLAIMS_JWT}\n`)
      const reg = new SentinelRegistry()
      const store = new MaskedFileStore()
      const { binds } = buildMaskedFileBinds(
        [
          {
            path: file,
            mode: 'mask',
            decode: 'jwt',
            maskClaims: ['api_key', 'not_present', 'iat'],
          },
        ],
        ['api.example.com'],
        reg,
        store,
      )
      expect(binds).toHaveLength(1)
      const fake = readFileSync(binds[0]!.fakePath, 'utf8')
      const fakeToken = fake.match(/token: (\S+)/)![1]!
      const payload = JSON.parse(
        Buffer.from(fakeToken.split('.')[1]!, 'base64url').toString('utf8'),
      ) as Record<string, unknown>
      expect(payload.api_key as string).toStartWith(SENTINEL_PREFIX)
      // Absent and non-string (iat is a number) claims are skipped.
      expect(payload.not_present).toBeUndefined()
      expect(payload.iat).toBe(CLAIMS_PAYLOAD.iat)
      // Only the whole-token mapping and the one matched claim.
      expect(reg.size).toBe(2)
      store.dispose()
    })

    test('no named claim matching in any verified token → onExtractNoMatch (warn)', () => {
      const warnSpy = spyOn(console, 'warn').mockImplementation(() => {})
      const file = join(DECODE_DIR, 'claims-none.json')
      writeFileSync(file, `token: ${CLAIMS_JWT}\n`)
      const reg = new SentinelRegistry()
      const store = new MaskedFileStore()
      const { binds } = buildMaskedFileBinds(
        [
          {
            path: file,
            mode: 'mask',
            decode: 'jwt',
            maskClaims: ['not_present'],
          },
        ],
        ['api.example.com'],
        reg,
        store,
      )
      // The verified JWT has none of the named claims: nothing was
      // masked, so the entry routes through onExtractNoMatch like the
      // no-verified-candidate case.
      expect(binds).toHaveLength(0)
      expect(reg.size).toBe(0)
      expect(warnSpy).toHaveBeenCalledTimes(1)
      const msg = warnSpy.mock.calls[0]![0] as string
      expect(msg).toContain('UNPROTECTED')
      expect(msg).toContain('maskable claims')
      warnSpy.mockRestore()
      store.dispose()
    })

    test('no named claim matching with onExtractNoMatch "deny" → degrades to deny', () => {
      const file = join(DECODE_DIR, 'claims-deny.json')
      writeFileSync(file, `token: ${CLAIMS_JWT}\n`)
      const reg = new SentinelRegistry()
      const store = new MaskedFileStore()
      const { binds, degradeToDenyPaths } = buildMaskedFileBinds(
        [
          {
            path: file,
            mode: 'mask',
            decode: 'jwt',
            maskClaims: ['not_present'],
            onExtractNoMatch: 'deny',
          },
        ],
        ['api.example.com'],
        reg,
        store,
      )
      expect(binds).toHaveLength(0)
      expect(degradeToDenyPaths).toEqual([realpathSync(file)])
      store.dispose()
    })

    test('two JWTs in one file: claim sentinels are per-token', () => {
      const otherJwt =
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' +
        b64u('{"sub":"user-2","api_key":"other-claim-secret"}') +
        '.b3RoZXItc2ln'
      const file = join(DECODE_DIR, 'claims-two.yml')
      writeFileSync(file, `a: ${CLAIMS_JWT}\nb: ${otherJwt}\n`)
      const reg = new SentinelRegistry()
      const store = new MaskedFileStore()
      const { binds } = buildMaskedFileBinds(
        [{ path: file, mode: 'mask', decode: 'jwt', maskClaims: ['api_key'] }],
        ['api.example.com'],
        reg,
        store,
      )
      expect(binds).toHaveLength(1)
      const fake = readFileSync(binds[0]!.fakePath, 'utf8')
      const fakeA = fake.match(/a: (\S+)/)![1]!
      const fakeB = fake.match(/b: (\S+)/)![1]!
      const claimOf = (t: string) =>
        (
          JSON.parse(
            Buffer.from(t.split('.')[1]!, 'base64url').toString('utf8'),
          ) as Record<string, unknown>
        ).api_key as string
      expect(reg.lookupReal(claimOf(fakeA))).toBe(CLAIMS_PAYLOAD.api_key)
      expect(reg.lookupReal(claimOf(fakeB))).toBe('other-claim-secret')
      expect(claimOf(fakeA)).not.toBe(claimOf(fakeB))
      // Two whole-token mappings + two claim mappings.
      expect(reg.size).toBe(4)
      store.dispose()
    })
  })
})

/**
 * Linux integration for structured (extract) masking via SandboxManager:
 * the bound fake preserves the file's structure with the credential span
 * replaced by a sentinel.
 */
describe.if(isLinux)('structured file masking on Linux (extract)', () => {
  const TEST_DIR = join(tmpdir(), 'srt-credmask-extract-' + Date.now())
  const YML_FILE = join(TEST_DIR, 'hosts.yml')
  const YML_TOKEN = 'gho_struct_real_0123456789abcdef'
  const YML_CONTENT =
    'github.com:\n' +
    '    user: alice\n' +
    `    oauth_token: ${YML_TOKEN}\n` +
    '    git_protocol: https\n'

  function runInSandbox(wrappedCommand: string) {
    return spawnSync(wrappedCommand, {
      shell: true,
      encoding: 'utf8',
      timeout: 10000,
    })
  }

  beforeAll(async () => {
    mkdirSync(TEST_DIR, { recursive: true })
    writeFileSync(YML_FILE, YML_CONTENT)
    await SandboxManager.reset()
    await SandboxManager.initialize({
      network: { allowedDomains: ['localhost'], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: ['/tmp'], denyWrite: [] },
      credentials: {
        files: [
          {
            path: YML_FILE,
            mode: 'mask',
            extract: 'oauth_token:\\s*(\\S+)',
          },
        ],
        allowPlaintextInject: true,
      },
    })
  })

  afterAll(async () => {
    await SandboxManager.reset()
    rmSync(TEST_DIR, { recursive: true, force: true })
  })

  test('cat inside the sandbox preserves YAML structure with sentinel', async () => {
    const wrapped = await SandboxManager.wrapWithSandbox(`cat ${YML_FILE}`)
    expect(wrapped).not.toContain(YML_TOKEN)
    const result = runInSandbox(wrapped)
    expect(result.status).toBe(0)
    const seen = result.stdout
    // Every non-credential line is byte-identical to the real file.
    expect(seen).toContain('github.com:\n')
    expect(seen).toContain('    user: alice\n')
    expect(seen).toContain('    git_protocol: https\n')
    // The credential value is gone; a sentinel sits in its place.
    expect(seen).not.toContain(YML_TOKEN)
    const m = seen.match(/oauth_token: (\S+)/)
    expect(m).not.toBeNull()
    expect(m![1]!.startsWith(SENTINEL_PREFIX)).toBe(true)
    // Same line count and same length modulo the swapped span — the
    // rest of the file is untouched.
    expect(seen.split('\n')).toHaveLength(YML_CONTENT.split('\n').length)
    // The host-side registry maps that sentinel back to the real token.
    expect(SandboxManager.getSentinelRegistry().lookupReal(m![1]!)).toBe(
      YML_TOKEN,
    )
  })

  test('the masked file is read-only inside the sandbox', async () => {
    const wrapped = await SandboxManager.wrapWithSandbox(
      `sh -c 'echo pwned > ${YML_FILE}'`,
    )
    const result = runInSandbox(wrapped)
    expect(result.status).not.toBe(0)
    expect(readFileSync(YML_FILE, 'utf8')).toBe(YML_CONTENT)
  })
})

/**
 * Linux integration: an `extract` pattern that matches nothing follows
 * the entry's `onExtractNoMatch` — default `"warn"` leaves the file
 * readable as-is with a stderr warning; `"deny"` makes it unreadable.
 */
describe.if(isLinux)('extract no-match onExtractNoMatch on Linux', () => {
  const TEST_DIR = join(tmpdir(), 'srt-credmask-nomatch-' + Date.now())
  const SECRET_FILE = join(TEST_DIR, 'hosts.yml')
  const SECRET = 'gho_nomatch_real_0123456789'

  async function init(onExtractNoMatch?: 'warn' | 'deny' | 'error') {
    await SandboxManager.reset()
    await SandboxManager.initialize({
      network: { allowedDomains: ['localhost'], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: ['/tmp'], denyWrite: [] },
      credentials: {
        files: [
          {
            path: SECRET_FILE,
            mode: 'mask',
            extract: 'will_not_match_(\\S+)',
            ...(onExtractNoMatch && { onExtractNoMatch }),
          },
        ],
        allowPlaintextInject: true,
      },
    })
  }

  beforeAll(() => {
    mkdirSync(TEST_DIR, { recursive: true })
    writeFileSync(SECRET_FILE, `oauth_token: ${SECRET}\n`)
  })

  afterAll(async () => {
    await SandboxManager.reset()
    rmSync(TEST_DIR, { recursive: true, force: true })
  })

  test('default ("warn"): file readable as-is, stderr warning at wrap', async () => {
    await init()
    const warnSpy = spyOn(console, 'warn').mockImplementation(() => {})
    const wrapped = await SandboxManager.wrapWithSandbox(`cat ${SECRET_FILE}`)
    // A loud stderr warning surfaces the config error at wrap time.
    expect(warnSpy).toHaveBeenCalled()
    expect(warnSpy.mock.calls[0]![0] as string).toContain('UNPROTECTED')
    warnSpy.mockRestore()
    // No fake-file bind and no /dev/null deny bind are emitted for the
    // path — the entry is skipped entirely.
    expect(wrapped).not.toMatch(
      new RegExp(`--ro-bind \\S+ ${SECRET_FILE.replace(/\//g, '\\/')}\\b`),
    )
    const result = spawnSync(wrapped, {
      shell: true,
      encoding: 'utf8',
      timeout: 10000,
    })
    // cat succeeds and returns the real bytes: fail-open means the
    // file is left readable via the root mount.
    expect(result.status).toBe(0)
    expect(result.stdout).toBe(`oauth_token: ${SECRET}\n`)
  })

  test('"deny": file unreadable inside the sandbox (fail-closed)', async () => {
    await init('deny')
    const wrapped = await SandboxManager.wrapWithSandbox(`cat ${SECRET_FILE}`)
    // The real credential never appears in the wrapped command.
    expect(wrapped).not.toContain(SECRET)
    // No --ro-bind <fake> <real> — degraded entries go via denyRead, not
    // the masked-file bind path.
    expect(wrapped).not.toMatch(
      new RegExp(`--ro-bind \\S+\\.fake ${SECRET_FILE.replace(/\//g, '\\/')}`),
    )
    const result = spawnSync(wrapped, {
      shell: true,
      encoding: 'utf8',
      timeout: 10000,
    })
    // cat fails: the file is unreadable inside the sandbox, and the
    // real bytes are never exposed on stdout.
    expect(result.status).not.toBe(0)
    expect(result.stdout).not.toContain(SECRET)
  })

  test('"error": wrapWithSandbox rejects', async () => {
    await init('error')
    let thrown: unknown
    try {
      await SandboxManager.wrapWithSandbox(`cat ${SECRET_FILE}`)
    } catch (e) {
      thrown = e
    }
    expect(thrown).toBeInstanceOf(Error)
    expect((thrown as Error).message).toMatch(
      /matched nothing.*onExtractNoMatch: "error"/,
    )
  })
})

/**
 * macOS: SBPL cannot redirect a read, so a masked file degrades to a
 * (deny file-read* …) rule — same profile output as mode: "deny". The
 * fakePath is unused. Pure string assertion; runs on any platform.
 */
describe('file masking on macOS degrades to read-deny', () => {
  test('profile contains (deny file-read* …) for the masked path', () => {
    const wrapped = wrapCommandWithSandboxMacOS({
      command: 'true',
      needsNetworkRestriction: false,
      readConfig: undefined,
      writeConfig: { allowOnly: ['/tmp'], denyWithinAllow: [] },
      maskedFileBinds: [{ realPath: TOKEN_FILE, fakePath: '/unused' }],
    })
    expect(wrapped).toContain('deny file-read*')
    expect(wrapped).toContain(TOKEN_FILE)
    // The fake path never reaches the profile — SBPL can't bind-mount.
    expect(wrapped).not.toContain('/unused')
  })

  test('still sandboxes when masked files are the only restriction', () => {
    const wrapped = wrapCommandWithSandboxMacOS({
      command: 'echo hi',
      needsNetworkRestriction: false,
      readConfig: undefined,
      writeConfig: undefined,
      maskedFileBinds: [{ realPath: TOKEN_FILE, fakePath: '/unused' }],
    })
    expect(wrapped).not.toBe('echo hi')
    expect(wrapped).toContain('deny file-read*')
  })

  test('an extract-mode masked file still degrades to (deny file-read*)', () => {
    // extract changes only the fake-file CONTENT; the macOS path keys
    // off the bind list, not the content, so structured masking is
    // exactly as unsupported as whole-file masking — the file is denied.
    const reg = new SentinelRegistry()
    const store = new MaskedFileStore()
    const { binds } = buildMaskedFileBinds(
      [
        {
          path: HOSTS_YML,
          mode: 'mask',
          extract: 'oauth_token:\\s*(\\S+)',
        },
      ],
      ['api.github.com'],
      reg,
      store,
    )
    const wrapped = wrapCommandWithSandboxMacOS({
      command: 'true',
      needsNetworkRestriction: false,
      readConfig: undefined,
      writeConfig: { allowOnly: ['/tmp'], denyWithinAllow: [] },
      maskedFileBinds: binds,
    })
    expect(wrapped).toContain('deny file-read*')
    expect(wrapped).toContain(HOSTS_YML)
    expect(wrapped).not.toContain(binds[0]!.fakePath)
    // The real credential never reaches the profile.
    expect(wrapped).not.toContain(HOSTS_TOKEN)
    store.dispose()
  })
})

/**
 * SandboxManager-level file masking on Linux: bwrap binds the fake over
 * the real path; the sandboxed process reads the sentinel; the real bytes
 * never appear in the wrapped command string.
 */
describe.if(isLinux)('file masking on Linux (bwrap)', () => {
  const TEST_DIR = join(tmpdir(), 'srt-credmask-linux-' + Date.now())
  const SECRET_FILE = join(TEST_DIR, 'token')
  const SECRET_CONTENT = 'ghp_linux_real_secret_0123456789'
  const CONTROL_FILE = join(TEST_DIR, 'control.txt')

  function baseConfig(
    overrides: Partial<SandboxRuntimeConfig> = {},
  ): SandboxRuntimeConfig {
    return {
      network: { allowedDomains: ['localhost'], deniedDomains: [] },
      filesystem: {
        denyRead: [],
        allowWrite: [TEST_DIR, '/tmp'],
        denyWrite: [],
      },
      credentials: {
        files: [{ path: SECRET_FILE, mode: 'mask' }],
        allowPlaintextInject: true,
      },
      ...overrides,
    }
  }

  function runInSandbox(wrappedCommand: string) {
    return spawnSync(wrappedCommand, {
      shell: true,
      encoding: 'utf8',
      timeout: 10000,
    })
  }

  beforeAll(async () => {
    mkdirSync(TEST_DIR, { recursive: true })
    writeFileSync(SECRET_FILE, SECRET_CONTENT)
    writeFileSync(CONTROL_FILE, 'control-ok')
    await SandboxManager.reset()
    await SandboxManager.initialize(baseConfig())
  })

  afterAll(async () => {
    await SandboxManager.reset()
    rmSync(TEST_DIR, { recursive: true, force: true })
  })

  describe('bwrap argv generation', () => {
    test('emits --ro-bind <fake> <real> with the sentinel as fake content', async () => {
      const wrapped = await SandboxManager.wrapWithSandbox('true')
      const m = wrapped.match(
        new RegExp(`--ro-bind (\\S+) ${SECRET_FILE.replace(/\//g, '\\/')}\\b`),
      )
      expect(m).not.toBeNull()
      const fakePath = m![1]!
      expect(fakePath).not.toBe('/dev/null')
      const fakeContent = readFileSync(fakePath, 'utf8')
      expect(fakeContent.startsWith(SENTINEL_PREFIX)).toBe(true)
      // The registry maps that sentinel back to the real bytes.
      expect(SandboxManager.getSentinelRegistry().lookupReal(fakeContent)).toBe(
        SECRET_CONTENT,
      )
    })

    test('the real file content never appears in the wrapped command', async () => {
      const wrapped = await SandboxManager.wrapWithSandbox('true')
      expect(wrapped).not.toContain(SECRET_CONTENT)
    })

    test('a masked file that does not exist on the host emits no bind', async () => {
      await SandboxManager.reset()
      await SandboxManager.initialize(
        baseConfig({
          credentials: {
            files: [{ path: join(TEST_DIR, 'no-such-token'), mode: 'mask' }],
            allowPlaintextInject: true,
          },
        }),
      )
      const wrapped = await SandboxManager.wrapWithSandbox('true')
      expect(wrapped).not.toContain('no-such-token')

      // Restore for the remaining tests.
      await SandboxManager.reset()
      await SandboxManager.initialize(baseConfig())
    })

    test('repeat wraps reuse the same fake file (no per-call leak)', async () => {
      await SandboxManager.wrapWithSandbox('true')
      await SandboxManager.wrapWithSandbox('true')
      const dir = SandboxManager.getMaskedFileStore().dirPath!
      expect(readdirSync(dir)).toHaveLength(1)
    })

    test('emits --ro-bind <storeDir> <storeDir> after the allowWrite binds', async () => {
      const wrapped = await SandboxManager.wrapWithSandbox('true')
      const storeDir = SandboxManager.getMaskedFileStore().dirPath!
      // The store-dir ro-bind must overlay any allowWrite covering it,
      // so it must appear after `--bind /tmp /tmp` in argv order.
      const writeBind = wrapped.indexOf('--bind /tmp /tmp')
      const storeBind = wrapped.indexOf(`--ro-bind ${storeDir} ${storeDir}`)
      expect(writeBind).toBeGreaterThan(-1)
      expect(storeBind).toBeGreaterThan(writeBind)
    })
  })

  describe('integration', () => {
    test('cat <maskedFile> inside the sandbox returns the sentinel', async () => {
      const wrapped = await SandboxManager.wrapWithSandbox(`cat ${SECRET_FILE}`)
      const result = runInSandbox(wrapped)
      expect(result.status).toBe(0)
      expect(result.stdout.startsWith(SENTINEL_PREFIX)).toBe(true)
      expect(result.stdout).not.toContain(SECRET_CONTENT)
    })

    test('the masked file is read-only inside the sandbox', async () => {
      // Even though TEST_DIR is in allowWrite, the --ro-bind on the
      // masked path layers on top — overwriting it would expose a way
      // to swap the sentinel for something the proxy might still inject.
      const wrapped = await SandboxManager.wrapWithSandbox(
        `sh -c 'echo pwned > ${SECRET_FILE}'`,
      )
      const result = runInSandbox(wrapped)
      expect(result.status).not.toBe(0)
      // Real file on the host is untouched.
      expect(readFileSync(SECRET_FILE, 'utf8')).toBe(SECRET_CONTENT)
    })

    test('a non-masked sibling file is still readable unchanged', async () => {
      const wrapped = await SandboxManager.wrapWithSandbox(
        `cat ${CONTROL_FILE}`,
      )
      const result = runInSandbox(wrapped)
      expect(result.status).toBe(0)
      expect(result.stdout).toBe('control-ok')
    })

    test('the fake-file store dir is read-only inside the sandbox even under allowWrite', async () => {
      // baseConfig() has allowWrite: ['/tmp'], which covers os.tmpdir()
      // and therefore the store dir. The store-dir ro-bind must overlay
      // it: writing the bind SOURCE from inside the sandbox must fail.
      // (The earlier "masked file is read-only" test only covers the
      // bind DEST.)
      await SandboxManager.wrapWithSandbox('true')
      const storeDir = SandboxManager.getMaskedFileStore().dirPath!
      expect(storeDir.startsWith(tmpdir())).toBe(true)

      const fake = join(storeDir, '0.fake')
      const before = readFileSync(fake, 'utf8')
      const overwrite = await SandboxManager.wrapWithSandbox(
        `sh -c 'echo pwned > ${fake}'`,
      )
      expect(runInSandbox(overwrite).status).not.toBe(0)
      expect(readFileSync(fake, 'utf8')).toBe(before)

      const plant = await SandboxManager.wrapWithSandbox(
        `ln -s /etc/passwd ${join(storeDir, 'evil')}`,
      )
      expect(runInSandbox(plant).status).not.toBe(0)
      expect(existsSync(join(storeDir, 'evil'))).toBe(false)
    })
  })

  test('reset() removes the fake-file temp dir', async () => {
    await SandboxManager.wrapWithSandbox('true')
    const dir = SandboxManager.getMaskedFileStore().dirPath
    expect(dir).toBeDefined()
    expect(existsSync(dir!)).toBe(true)
    await SandboxManager.reset()
    expect(existsSync(dir!)).toBe(false)
    expect(SandboxManager.getMaskedFileStore().dirPath).toBeUndefined()
    // Re-initialize for any following tests.
    await SandboxManager.initialize(baseConfig())
  })
})

/**
 * End-to-end: a token *file* is masked; inside the sandbox a tool reads
 * the file and sends its content as a header. The manager-started proxy
 * substitutes sentinel→real for the file's injectHost only. Reuses the
 * pattern from credential-mask.test.ts (allowPlaintextInject, plain HTTP
 * upstream, SandboxManager's own proxy port).
 */
describe.if(isLinux)('end-to-end file masking via SandboxManager', () => {
  const TEST_DIR = join(tmpdir(), 'srt-credmask-e2e-' + Date.now())
  const SECRET_FILE = join(TEST_DIR, 'token')
  const SECRET_CONTENT = 'ghp_e2e_real_secret_0123456789'
  const HOST_A = 'localhost'
  const HOST_B = 'host-b.localhost'

  let upstream: Server
  let upstreamPort: number
  let lastHeaders: IncomingHttpHeaders | undefined

  beforeAll(async () => {
    mkdirSync(TEST_DIR, { recursive: true })
    writeFileSync(SECRET_FILE, SECRET_CONTENT)

    upstream = createHttpServer((req, res) => {
      lastHeaders = req.headers
      res.writeHead(200)
      res.end('ok')
    })
    await new Promise<void>(r => upstream.listen(0, '127.0.0.1', () => r()))
    upstreamPort = (upstream.address() as AddressInfo).port

    await SandboxManager.reset()
    await SandboxManager.initialize({
      network: { allowedDomains: [HOST_A, HOST_B], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: ['/tmp'], denyWrite: [] },
      credentials: {
        files: [{ path: SECRET_FILE, mode: 'mask', injectHosts: [HOST_A] }],
        allowPlaintextInject: true,
      },
    })
  })

  afterAll(async () => {
    await SandboxManager.reset()
    await new Promise<void>(r => upstream.close(() => r()))
    rmSync(TEST_DIR, { recursive: true, force: true })
  })

  // Async spawn — spawnSync would block the event loop and the
  // in-process proxy/upstream couldn't accept the connection.
  async function curlViaManagerProxy(
    url: string,
    bearer: string,
  ): Promise<number> {
    const proxyPort = SandboxManager.getProxyPort()!
    const authToken = SandboxManager.getProxyAuthToken()!
    const args = [
      '-sS',
      '--max-time',
      '10',
      '--proxy',
      `http://srt:${authToken}@127.0.0.1:${proxyPort}`,
      '-H',
      `Authorization: Bearer ${bearer}`,
    ]
    args.push(url)
    const child = spawn('curl', args)
    child.stdout.on('data', () => {})
    child.stderr.on('data', () => {})
    return new Promise(r => child.on('close', code => r(code ?? 1)))
  }

  test('cat inside the sandbox + manager proxy → injectHost gets real bytes', async () => {
    // bwrap leg: cat inside the sandbox returns the sentinel.
    const wrapped = await SandboxManager.wrapWithSandbox(`cat ${SECRET_FILE}`)
    expect(wrapped).not.toContain(SECRET_CONTENT)
    const inSandbox = spawnSync(wrapped, {
      shell: true,
      encoding: 'utf8',
      timeout: 10000,
    })
    expect(inSandbox.status).toBe(0)
    const sentinel = inSandbox.stdout
    expect(sentinel.startsWith(SENTINEL_PREFIX)).toBe(true)
    expect(sentinel).not.toContain(SECRET_CONTENT)

    // Proxy leg: the same sentinel sent through the manager-started
    // proxy reaches HOST_A (injectHost) as the real file content.
    lastHeaders = undefined
    const exit = await curlViaManagerProxy(
      `http://${HOST_A}:${upstreamPort}/`,
      sentinel,
    )
    expect(exit).toBe(0)
    expect(lastHeaders?.authorization).toBe(`Bearer ${SECRET_CONTENT}`)
  }, 20000)

  test('a non-injectHost destination receives the sentinel unchanged', async () => {
    const wrapped = await SandboxManager.wrapWithSandbox(`cat ${SECRET_FILE}`)
    const sentinel = spawnSync(wrapped, {
      shell: true,
      encoding: 'utf8',
      timeout: 10000,
    }).stdout

    // HOST_B is allowlisted but NOT in this file's injectHosts. The
    // proxy resolves it to loopback (a `.localhost` name) and forwards
    // the sentinel as-is — fails closed.
    lastHeaders = undefined
    const exit = await curlViaManagerProxy(
      `http://${HOST_B}:${upstreamPort}/`,
      sentinel,
    )
    expect(exit).toBe(0)
    expect(lastHeaders?.authorization).toBe(`Bearer ${sentinel}`)
    expect(lastHeaders?.authorization).not.toContain(SECRET_CONTENT)
  }, 20000)
})

/**
 * End-to-end structured (extract) masking: a multi-credential file is
 * masked with a regex; inside the sandbox a tool parses the sentinel out
 * of the preserved structure and sends it as a header; the proxy swaps
 * each sentinel to its own real captured value at the injectHost.
 */
describe.if(isLinux)(
  'end-to-end structured file masking via SandboxManager',
  () => {
    const TEST_DIR = join(tmpdir(), 'srt-credmask-extract-e2e-' + Date.now())
    const HOST_A = 'localhost'
    const HOST_B = 'host-b.localhost'

    // hosts.yml-style: one credential, structure must survive.
    const YML_FILE = join(TEST_DIR, 'hosts.yml')
    const YML_TOKEN = 'gho_e2e_real_0123456789abcdef'
    const YML_CONTENT =
      'github.com:\n' +
      '    user: alice\n' +
      `    oauth_token: ${YML_TOKEN}\n` +
      '    git_protocol: https\n'

    // .netrc-style: two credentials → two sentinels, each must swap to
    // its own real value at the proxy.
    const NETRC_FILE = join(TEST_DIR, 'netrc')
    const NETRC_TOK_A = 'npm_e2e_real_aaaaaaaa'
    const NETRC_TOK_B = 'npm_e2e_real_bbbbbbbb'
    const NETRC_CONTENT =
      `machine a.example.com login alice password ${NETRC_TOK_A}\n` +
      `machine b.example.com login bob password ${NETRC_TOK_B}\n`

    let upstream: Server
    let upstreamPort: number
    let lastHeaders: IncomingHttpHeaders | undefined

    beforeAll(async () => {
      mkdirSync(TEST_DIR, { recursive: true })
      writeFileSync(YML_FILE, YML_CONTENT)
      writeFileSync(NETRC_FILE, NETRC_CONTENT)

      upstream = createHttpServer((req, res) => {
        lastHeaders = req.headers
        res.writeHead(200)
        res.end('ok')
      })
      await new Promise<void>(r => upstream.listen(0, '127.0.0.1', () => r()))
      upstreamPort = (upstream.address() as AddressInfo).port

      await SandboxManager.reset()
      await SandboxManager.initialize({
        network: { allowedDomains: [HOST_A, HOST_B], deniedDomains: [] },
        filesystem: { denyRead: [], allowWrite: ['/tmp'], denyWrite: [] },
        credentials: {
          files: [
            {
              path: YML_FILE,
              mode: 'mask',
              extract: 'oauth_token:\\s*(\\S+)',
              injectHosts: [HOST_A],
            },
            {
              path: NETRC_FILE,
              mode: 'mask',
              extract: 'password\\s+(\\S+)',
              injectHosts: [HOST_A],
            },
          ],
          allowPlaintextInject: true,
        },
      })
    })

    afterAll(async () => {
      await SandboxManager.reset()
      await new Promise<void>(r => upstream.close(() => r()))
      rmSync(TEST_DIR, { recursive: true, force: true })
    })

    function runInSandbox(wrappedCommand: string) {
      return spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 10000,
      })
    }

    async function curlViaManagerProxy(
      url: string,
      bearer: string,
    ): Promise<number> {
      const proxyPort = SandboxManager.getProxyPort()!
      const authToken = SandboxManager.getProxyAuthToken()!
      const args = [
        '-sS',
        '--max-time',
        '10',
        '--proxy',
        `http://srt:${authToken}@127.0.0.1:${proxyPort}`,
        '-H',
        `Authorization: Bearer ${bearer}`,
      ]
      args.push(url)
      const child = spawn('curl', args)
      child.stdout.on('data', () => {})
      child.stderr.on('data', () => {})
      return new Promise(r => child.on('close', code => r(code ?? 1)))
    }

    test('hosts.yml: parse sentinel from structure → upstream gets real token', async () => {
      // bwrap leg: extract the oauth_token field from the masked YAML
      // inside the sandbox — the file parses, and the field value is
      // the sentinel.
      const wrapped = await SandboxManager.wrapWithSandbox(
        `sh -c "grep oauth_token ${YML_FILE} | awk '{print \\$2}'"`,
      )
      expect(wrapped).not.toContain(YML_TOKEN)
      const result = runInSandbox(wrapped)
      expect(result.status).toBe(0)
      const sentinel = result.stdout.trim()
      expect(sentinel.startsWith(SENTINEL_PREFIX)).toBe(true)
      expect(sentinel).not.toContain(YML_TOKEN)

      // Proxy leg: the sentinel reaches HOST_A as the real token.
      lastHeaders = undefined
      const exit = await curlViaManagerProxy(
        `http://${HOST_A}:${upstreamPort}/`,
        sentinel,
      )
      expect(exit).toBe(0)
      expect(lastHeaders?.authorization).toBe(`Bearer ${YML_TOKEN}`)
    }, 20000)

    test('.netrc: two captures → two sentinels, each swaps to its own value', async () => {
      // bwrap leg: read both password fields inside the sandbox.
      const wrapped = await SandboxManager.wrapWithSandbox(
        `sh -c "awk '{print \\$NF}' ${NETRC_FILE}"`,
      )
      const result = runInSandbox(wrapped)
      expect(result.status).toBe(0)
      const [sA, sB] = result.stdout.trim().split('\n')
      expect(sA!.startsWith(SENTINEL_PREFIX)).toBe(true)
      expect(sB!.startsWith(SENTINEL_PREFIX)).toBe(true)
      expect(sA).not.toBe(sB)
      expect(result.stdout).not.toContain(NETRC_TOK_A)
      expect(result.stdout).not.toContain(NETRC_TOK_B)

      // Proxy leg: each sentinel swaps to its own real captured value.
      lastHeaders = undefined
      let exit = await curlViaManagerProxy(
        `http://${HOST_A}:${upstreamPort}/`,
        sA!,
      )
      expect(exit).toBe(0)
      expect(lastHeaders?.authorization).toBe(`Bearer ${NETRC_TOK_A}`)

      lastHeaders = undefined
      exit = await curlViaManagerProxy(`http://${HOST_A}:${upstreamPort}/`, sB!)
      expect(exit).toBe(0)
      expect(lastHeaders?.authorization).toBe(`Bearer ${NETRC_TOK_B}`)
    }, 20000)

    test('an extract sentinel does not substitute at a non-injectHost', async () => {
      const wrapped = await SandboxManager.wrapWithSandbox(
        `sh -c "grep oauth_token ${YML_FILE} | awk '{print \\$2}'"`,
      )
      const sentinel = runInSandbox(wrapped).stdout.trim()

      lastHeaders = undefined
      const exit = await curlViaManagerProxy(
        `http://${HOST_B}:${upstreamPort}/`,
        sentinel,
      )
      expect(exit).toBe(0)
      expect(lastHeaders?.authorization).toBe(`Bearer ${sentinel}`)
      expect(lastHeaders?.authorization).not.toContain(YML_TOKEN)
    }, 20000)
  },
)

/**
 * End-to-end JWT decode masking: a token file holds a JWT; inside the
 * sandbox the tool reads a structurally valid FAKE JWT (parseable header,
 * payload, exp); sending it through the manager proxy delivers the REAL
 * JWT to the injectHost, while a non-injectHost receives the fake.
 */
describe.if(isLinux)('end-to-end JWT decode masking via SandboxManager', () => {
  const TEST_DIR = join(tmpdir(), 'srt-credmask-jwt-e2e-' + Date.now())
  const JWT_FILE = join(TEST_DIR, 'id-token')
  const HOST_A = 'localhost'
  const HOST_B = 'host-b.localhost'

  const b64u = (s: string) => Buffer.from(s, 'utf8').toString('base64url')
  const REAL_JWT =
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' +
    b64u('{"sub":"e2e-user","iat":1516239022}') +
    '.ZTJlLXJlYWwtc2lnbmF0dXJl'

  let upstream: Server
  let upstreamPort: number
  let lastHeaders: IncomingHttpHeaders | undefined

  beforeAll(async () => {
    mkdirSync(TEST_DIR, { recursive: true })
    writeFileSync(JWT_FILE, `${REAL_JWT}\n`)

    upstream = createHttpServer((req, res) => {
      lastHeaders = req.headers
      res.writeHead(200)
      res.end('ok')
    })
    await new Promise<void>(r => upstream.listen(0, '127.0.0.1', () => r()))
    upstreamPort = (upstream.address() as AddressInfo).port

    await SandboxManager.reset()
    await SandboxManager.initialize({
      network: { allowedDomains: [HOST_A, HOST_B], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: ['/tmp'], denyWrite: [] },
      credentials: {
        files: [
          {
            path: JWT_FILE,
            mode: 'mask',
            decode: 'jwt',
            injectHosts: [HOST_A],
          },
        ],
        allowPlaintextInject: true,
      },
    })
  })

  afterAll(async () => {
    await SandboxManager.reset()
    await new Promise<void>(r => upstream.close(() => r()))
    rmSync(TEST_DIR, { recursive: true, force: true })
  })

  async function curlViaManagerProxy(
    url: string,
    bearer: string,
  ): Promise<number> {
    const proxyPort = SandboxManager.getProxyPort()!
    const authToken = SandboxManager.getProxyAuthToken()!
    const args = [
      '-sS',
      '--max-time',
      '10',
      '--proxy',
      `http://srt:${authToken}@127.0.0.1:${proxyPort}`,
      '-H',
      `Authorization: Bearer ${bearer}`,
    ]
    args.push(url)
    const child = spawn('curl', args)
    child.stdout.on('data', () => {})
    child.stderr.on('data', () => {})
    return new Promise(r => child.on('close', code => r(code ?? 1)))
  }

  test('cat → fake JWT inside; proxy delivers the real JWT to the injectHost', async () => {
    // bwrap leg: the sandboxed read returns a structurally valid fake.
    const wrapped = await SandboxManager.wrapWithSandbox(`cat ${JWT_FILE}`)
    expect(wrapped).not.toContain(REAL_JWT)
    const result = spawnSync(wrapped, {
      shell: true,
      encoding: 'utf8',
      timeout: 10000,
    })
    expect(result.status).toBe(0)
    const fakeJwt = result.stdout.trim()
    expect(fakeJwt).not.toBe(REAL_JWT)
    expect(verifyJwt(fakeJwt)).toBe(true)

    // Proxy leg: the fake sent as a bearer token reaches the injectHost
    // as the REAL JWT.
    lastHeaders = undefined
    const exit = await curlViaManagerProxy(
      `http://${HOST_A}:${upstreamPort}/`,
      fakeJwt,
    )
    expect(exit).toBe(0)
    expect(lastHeaders?.authorization).toBe(`Bearer ${REAL_JWT}`)
  }, 20000)

  test('a non-injectHost destination receives the fake JWT unchanged', async () => {
    const wrapped = await SandboxManager.wrapWithSandbox(`cat ${JWT_FILE}`)
    const fakeJwt = spawnSync(wrapped, {
      shell: true,
      encoding: 'utf8',
      timeout: 10000,
    }).stdout.trim()

    lastHeaders = undefined
    const exit = await curlViaManagerProxy(
      `http://${HOST_B}:${upstreamPort}/`,
      fakeJwt,
    )
    expect(exit).toBe(0)
    expect(lastHeaders?.authorization).toBe(`Bearer ${fakeJwt}`)
    expect(lastHeaders?.authorization).not.toContain(REAL_JWT)
  }, 20000)
})

/**
 * End-to-end claim-level JWT masking (`maskClaims`): the sandboxed read
 * returns a token whose named claim is a sentinel while every other claim
 * is real; the proxy substitutes BOTH the whole token (bearer usage) and
 * the extracted claim sentinel (claim-extraction usage) on egress to the
 * injectHost, and neither at a non-injectHost.
 */
describe.if(isLinux)('end-to-end maskClaims via SandboxManager', () => {
  const TEST_DIR = join(tmpdir(), 'srt-credmask-claims-e2e-' + Date.now())
  const JWT_FILE = join(TEST_DIR, 'id-token')
  const HOST_A = 'localhost'
  const HOST_B = 'host-b.localhost'

  const b64u = (s: string) => Buffer.from(s, 'utf8').toString('base64url')
  const REAL_CLAIM = 'e2e-real-claim-secret-0123456789'
  const REAL_JWT =
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' +
    b64u(`{"sub":"e2e-user","api_key":"${REAL_CLAIM}","iat":1516239022}`) +
    '.ZTJlLXJlYWwtc2lnbmF0dXJl'

  let upstream: Server
  let upstreamPort: number
  let lastHeaders: IncomingHttpHeaders | undefined

  beforeAll(async () => {
    mkdirSync(TEST_DIR, { recursive: true })
    writeFileSync(JWT_FILE, `${REAL_JWT}\n`)

    upstream = createHttpServer((req, res) => {
      lastHeaders = req.headers
      res.writeHead(200)
      res.end('ok')
    })
    await new Promise<void>(r => upstream.listen(0, '127.0.0.1', () => r()))
    upstreamPort = (upstream.address() as AddressInfo).port

    await SandboxManager.reset()
    await SandboxManager.initialize({
      network: { allowedDomains: [HOST_A, HOST_B], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: ['/tmp'], denyWrite: [] },
      credentials: {
        files: [
          {
            path: JWT_FILE,
            mode: 'mask',
            decode: 'jwt',
            maskClaims: ['api_key'],
            injectHosts: [HOST_A],
          },
        ],
        allowPlaintextInject: true,
      },
    })
  })

  afterAll(async () => {
    await SandboxManager.reset()
    await new Promise<void>(r => upstream.close(() => r()))
    rmSync(TEST_DIR, { recursive: true, force: true })
  })

  async function curlViaManagerProxy(
    url: string,
    bearer: string,
  ): Promise<number> {
    const proxyPort = SandboxManager.getProxyPort()!
    const authToken = SandboxManager.getProxyAuthToken()!
    const args = [
      '-sS',
      '--max-time',
      '10',
      '--proxy',
      `http://srt:${authToken}@127.0.0.1:${proxyPort}`,
      '-H',
      `Authorization: Bearer ${bearer}`,
    ]
    args.push(url)
    const child = spawn('curl', args)
    child.stdout.on('data', () => {})
    child.stderr.on('data', () => {})
    return new Promise(r => child.on('close', code => r(code ?? 1)))
  }

  /** Read the masked token from inside the sandbox. */
  async function readFakeJwt(): Promise<string> {
    const wrapped = await SandboxManager.wrapWithSandbox(`cat ${JWT_FILE}`)
    expect(wrapped).not.toContain(REAL_JWT)
    const result = spawnSync(wrapped, {
      shell: true,
      encoding: 'utf8',
      timeout: 10000,
    })
    expect(result.status).toBe(0)
    return result.stdout.trim()
  }

  function claimOf(token: string): string {
    const payload = JSON.parse(
      Buffer.from(token.split('.')[1]!, 'base64url').toString('utf8'),
    ) as Record<string, unknown>
    return payload.api_key as string
  }

  test('cat → named claim is a sentinel, other claims real; bearer usage delivers the whole real token', async () => {
    const fakeJwt = await readFakeJwt()
    expect(fakeJwt).not.toBe(REAL_JWT)
    expect(verifyJwt(fakeJwt)).toBe(true)
    // Header reused verbatim; only the payload changed.
    expect(fakeJwt.split('.')[0]).toBe(REAL_JWT.split('.')[0])
    const payload = JSON.parse(
      Buffer.from(fakeJwt.split('.')[1]!, 'base64url').toString('utf8'),
    ) as Record<string, unknown>
    expect(payload.api_key as string).toStartWith(SENTINEL_PREFIX)
    expect(payload.sub).toBe('e2e-user')
    expect(payload.iat).toBe(1516239022)

    // The tool sends the token verbatim → the injectHost receives the
    // whole REAL token.
    lastHeaders = undefined
    const exit = await curlViaManagerProxy(
      `http://${HOST_A}:${upstreamPort}/`,
      fakeJwt,
    )
    expect(exit).toBe(0)
    expect(lastHeaders?.authorization).toBe(`Bearer ${REAL_JWT}`)
  }, 20000)

  test('extracted-claim usage: the claim sentinel alone swaps to the real claim value', async () => {
    const sentinel = claimOf(await readFakeJwt())
    expect(sentinel).toStartWith(SENTINEL_PREFIX)

    lastHeaders = undefined
    const exit = await curlViaManagerProxy(
      `http://${HOST_A}:${upstreamPort}/`,
      sentinel,
    )
    expect(exit).toBe(0)
    expect(lastHeaders?.authorization).toBe(`Bearer ${REAL_CLAIM}`)
  }, 20000)

  test('a non-injectHost destination receives the fake token and sentinel unchanged', async () => {
    const fakeJwt = await readFakeJwt()

    lastHeaders = undefined
    let exit = await curlViaManagerProxy(
      `http://${HOST_B}:${upstreamPort}/`,
      fakeJwt,
    )
    expect(exit).toBe(0)
    expect(lastHeaders?.authorization).toBe(`Bearer ${fakeJwt}`)
    expect(lastHeaders?.authorization).not.toContain(REAL_CLAIM)

    lastHeaders = undefined
    exit = await curlViaManagerProxy(
      `http://${HOST_B}:${upstreamPort}/`,
      claimOf(fakeJwt),
    )
    expect(exit).toBe(0)
    expect(lastHeaders?.authorization).toBe(`Bearer ${claimOf(fakeJwt)}`)
    expect(lastHeaders?.authorization).not.toContain(REAL_CLAIM)
  }, 20000)
})
