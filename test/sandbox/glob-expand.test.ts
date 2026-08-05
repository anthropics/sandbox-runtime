import { describe, it, expect, beforeAll, afterAll } from 'bun:test'
import {
  mkdirSync,
  writeFileSync,
  rmSync,
  existsSync,
  realpathSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  expandGlobPattern,
  expandTilde,
  globToRegex,
} from '../../src/sandbox/sandbox-utils.js'
import {
  containsGlobCharsWin,
  expandWindowsFsPaths,
  stripExtendedPathPrefix,
  isUncPath,
  parseWindowsSandboxError,
  WindowsSandboxError,
} from '../../src/sandbox/windows-sandbox-utils.js'
import { isLinux, isWindows } from '../helpers/platform.js'
import { spawnSync } from 'node:child_process'

/**
 * Helper to get the real path of a file/dir (resolves symlinks like /var -> /private/var on macOS)
 */
function realPath(p: string): string {
  try {
    return realpathSync(p)
  } catch {
    return p
  }
}

// ============================================================================
// Tests for expandGlobPattern()
// ============================================================================

describe('expandGlobPattern', () => {
  // Use raw path for creation, real path for assertions
  const RAW_BASE_DIR = join(tmpdir(), 'glob-expand-test-' + Date.now())
  const RAW_TEST_DIR = join(RAW_BASE_DIR, 'testdir')
  let TEST_DIR: string

  beforeAll(() => {
    // Create test directory structure:
    // testdir/
    //   token.env
    //   secrets.env
    //   readme.txt
    //   config.json
    //   subdir/
    //     nested.env
    //     deep.txt
    //     deeper/
    //       bottom.env
    mkdirSync(join(RAW_TEST_DIR, 'subdir', 'deeper'), { recursive: true })
    writeFileSync(join(RAW_TEST_DIR, 'token.env'), 'TOKEN=secret')
    writeFileSync(join(RAW_TEST_DIR, 'secrets.env'), 'SECRET=value')
    writeFileSync(join(RAW_TEST_DIR, 'readme.txt'), 'readme content')
    writeFileSync(join(RAW_TEST_DIR, 'config.json'), '{}')
    writeFileSync(join(RAW_TEST_DIR, 'subdir', 'nested.env'), 'NESTED=secret')
    writeFileSync(join(RAW_TEST_DIR, 'subdir', 'deep.txt'), 'deep content')
    writeFileSync(
      join(RAW_TEST_DIR, 'subdir', 'deeper', 'bottom.env'),
      'BOTTOM=secret',
    )

    // Resolve real path after creation (handles /var -> /private/var on macOS)
    TEST_DIR = realPath(RAW_TEST_DIR)
  })

  afterAll(() => {
    if (existsSync(RAW_BASE_DIR)) {
      rmSync(RAW_BASE_DIR, { recursive: true, force: true })
    }
  })

  it('should expand *.env to match only .env files in the directory', () => {
    const pattern = join(RAW_TEST_DIR, '*.env')
    const results = expandGlobPattern(pattern)

    // Should match token.env and secrets.env but NOT nested ones
    expect(results).toContain(join(TEST_DIR, 'token.env'))
    expect(results).toContain(join(TEST_DIR, 'secrets.env'))
    expect(results).not.toContain(join(TEST_DIR, 'readme.txt'))
    expect(results).not.toContain(join(TEST_DIR, 'config.json'))
    expect(results).not.toContain(join(TEST_DIR, 'subdir', 'nested.env'))
    expect(results.length).toBe(2)
  })

  it('should expand **/*.env to match .env files recursively', () => {
    const pattern = join(RAW_TEST_DIR, '**/*.env')
    const results = expandGlobPattern(pattern)

    // Should match all .env files recursively
    expect(results).toContain(join(TEST_DIR, 'token.env'))
    expect(results).toContain(join(TEST_DIR, 'secrets.env'))
    expect(results).toContain(join(TEST_DIR, 'subdir', 'nested.env'))
    expect(results).toContain(join(TEST_DIR, 'subdir', 'deeper', 'bottom.env'))
    expect(results).not.toContain(join(TEST_DIR, 'readme.txt'))
    expect(results.length).toBe(4)
  })

  it('should expand ** to match all files recursively', () => {
    const pattern = join(RAW_TEST_DIR, '**')
    const results = expandGlobPattern(pattern)

    // Should match all files and directories
    expect(results.length).toBeGreaterThan(0)
    expect(results).toContain(join(TEST_DIR, 'token.env'))
    expect(results).toContain(join(TEST_DIR, 'readme.txt'))
    expect(results).toContain(join(TEST_DIR, 'subdir', 'nested.env'))
    expect(results).toContain(join(TEST_DIR, 'subdir', 'deeper', 'bottom.env'))
  })

  it('should return empty array for non-existent base directory', () => {
    const pattern = '/nonexistent/path/*.env'
    const results = expandGlobPattern(pattern)
    expect(results).toEqual([])
  })

  it('should return empty array when no files match the pattern', () => {
    const pattern = join(RAW_TEST_DIR, '*.xyz')
    const results = expandGlobPattern(pattern)
    expect(results).toEqual([])
  })

  it('should match directories as well as files', () => {
    const pattern = join(RAW_TEST_DIR, '*')
    const results = expandGlobPattern(pattern)

    // Should include both files and directories (subdir)
    expect(results).toContain(join(TEST_DIR, 'token.env'))
    expect(results).toContain(join(TEST_DIR, 'subdir'))
    expect(results).toContain(join(TEST_DIR, 'readme.txt'))
  })

  it('should handle ? wildcard', () => {
    const pattern = join(RAW_TEST_DIR, '*.tx?')
    const results = expandGlobPattern(pattern)

    expect(results).toContain(join(TEST_DIR, 'readme.txt'))
    expect(results).not.toContain(join(TEST_DIR, 'token.env'))
  })

  it('should match with partial name glob', () => {
    const pattern = join(RAW_TEST_DIR, 'secret*.env')
    const results = expandGlobPattern(pattern)

    expect(results).toContain(join(TEST_DIR, 'secrets.env'))
    expect(results).not.toContain(join(TEST_DIR, 'token.env'))
  })

  // Regression: `\` is a valid filename byte on POSIX, so the
  // shared helper must NOT rewrite it to `/` outside Windows.
  it.if(!isWindows)(
    'should preserve literal backslash in POSIX path components',
    () => {
      const bsDir = join(RAW_TEST_DIR, 'app\\creds')
      mkdirSync(bsDir, { recursive: true })
      writeFileSync(join(bsDir, 'key.pem'), 'k')
      const realBsDir = realPath(bsDir)

      const results = expandGlobPattern(join(bsDir, '*.pem'))
      expect(results).toContain(join(realBsDir, 'key.pem'))
      // The directory `app\creds` must not be confused with `app/creds`.
      expect(results.some(r => r.includes('/app/creds/'))).toBe(false)
    },
  )
})

// ============================================================================
// expandTilde — `~\` form is Windows-only
// ============================================================================

describe('expandTilde', () => {
  it.if(!isWindows)(
    'should NOT expand `~\\` on POSIX (literal filename byte)',
    () => {
      // `~\foo` is a legal relative filename on Linux/macOS and
      // must pass through untouched (it is later cwd-resolved).
      expect(expandTilde('~\\backup')).toBe('~\\backup')
      // `~/` and bare `~` still expand on every platform.
      expect(expandTilde('~/x').startsWith('~')).toBe(false)
      expect(expandTilde('~').startsWith('~')).toBe(false)
    },
  )

  it.if(isWindows)('should expand `~\\` on Windows', () => {
    expect(expandTilde('~\\x').startsWith('~')).toBe(false)
  })
})

// ============================================================================
// stripExtendedPathPrefix — `\\?\` and `\\?\UNC\` shapes
// ============================================================================

describe('stripExtendedPathPrefix', () => {
  it('should strip `\\\\?\\` to a drive-letter path', () => {
    expect(stripExtendedPathPrefix('\\\\?\\C:\\dir\\f.txt')).toBe(
      'C:\\dir\\f.txt',
    )
  })

  it('should strip `\\\\?\\UNC\\` to a `\\\\server\\share` path', () => {
    expect(stripExtendedPathPrefix('\\\\?\\UNC\\srv\\share\\f.txt')).toBe(
      '\\\\srv\\share\\f.txt',
    )
  })

  it('should leave non-extended paths unchanged', () => {
    expect(stripExtendedPathPrefix('C:\\dir\\f.txt')).toBe('C:\\dir\\f.txt')
    expect(stripExtendedPathPrefix('\\\\srv\\share\\f.txt')).toBe(
      '\\\\srv\\share\\f.txt',
    )
  })

  it('should strip `\\\\?\\UNC\\` case-insensitively', () => {
    // Windows accepts the UNC marker in any casing; a case-sensitive
    // strip would leave a cwd-relative `unc\srv\…` (fail-open drop).
    expect(stripExtendedPathPrefix('\\\\?\\unc\\srv\\s\\f')).toBe(
      '\\\\srv\\s\\f',
    )
    expect(stripExtendedPathPrefix('\\\\?\\Unc\\srv\\s\\f')).toBe(
      '\\\\srv\\s\\f',
    )
  })
})

// ============================================================================
// containsGlobCharsWin — `[`/`]` are literal on Windows
// ============================================================================

describe('containsGlobCharsWin', () => {
  it('treats [ and ] as literal filename characters', () => {
    expect(containsGlobCharsWin('C:\\app\\[prod].env')).toBe(false)
  })

  it('still routes * and ? to glob expansion', () => {
    expect(containsGlobCharsWin('C:\\app\\*.env')).toBe(true)
    expect(containsGlobCharsWin('C:\\app\\?.env')).toBe(true)
  })
})

describe('expandWindowsFsPaths literal branch', () => {
  it('drops non-existent grant paths without throwing (single statSync)', () => {
    // The literal branch uses one statSync({throwIfNoEntry:false})
    // rather than existsSync→statSync, so a TOCTOU ENOENT cannot
    // abort initialize().
    const missing = join(tmpdir(), 'srt-no-such-' + Date.now() + '.txt')
    expect(() => expandWindowsFsPaths([missing])).not.toThrow()
    expect(expandWindowsFsPaths([missing])).toEqual([])
    expect(expandWindowsFsPaths([missing], { mode: 'grant' })).toEqual([])
  })

  it('passes non-existent deny paths through for placeholder-create', () => {
    // srt-win acl stamp materializes a placeholder chain and stamps
    // it, so the deny lands on the exact target path.
    const missing = join(tmpdir(), 'srt-no-such-' + Date.now(), 'secret.txt')
    const out = expandWindowsFsPaths([missing], { mode: 'deny' })
    expect(out).toHaveLength(1)
    expect(out[0]).toContain('secret.txt')
  })

  it('still drops non-matching glob deny patterns (glob = match existing)', () => {
    const noMatch = join(tmpdir(), 'srt-no-such-' + Date.now(), '*.txt')
    expect(expandWindowsFsPaths([noMatch], { mode: 'deny' })).toEqual([])
  })

  it('preserves trailing separator on passed-through deny (leaf-is-dir signal)', () => {
    // srt-win reads a trailing `/` or `\` as "materialize the
    // placeholder leaf as a directory" so a later
    // mkdirSync({recursive:true}) on the real path succeeds.
    // normalizePathForSandbox may strip it (path.resolve on
    // Windows, realpath elsewhere), so expandWindowsFsPaths
    // re-applies it from the raw input.
    const base = join(tmpdir(), 'srt-no-such-' + Date.now(), 'hooks')
    for (const raw of [base + '/', base + '\\']) {
      const out = expandWindowsFsPaths([raw], { mode: 'deny' })
      expect(out).toHaveLength(1)
      expect(/[\\/]$/.test(out[0])).toBe(true)
    }
    // No trailing separator ⇒ not re-applied.
    const out = expandWindowsFsPaths([base], { mode: 'deny' })
    expect(/[\\/]$/.test(out[0])).toBe(false)
  })
})

// ============================================================================
// isUncPath — broker never stats `\\server\…` with real-user creds
// ============================================================================

describe('isUncPath', () => {
  it('recognises \\\\server\\share and //server/share', () => {
    expect(isUncPath('\\\\srv\\share\\dir')).toBe(true)
    expect(isUncPath('//srv/share')).toBe(true)
  })

  it('recognises the extended-length \\\\?\\UNC\\… form (any casing)', () => {
    expect(isUncPath('\\\\?\\UNC\\srv\\share\\dir')).toBe(true)
    expect(isUncPath('\\\\?\\unc\\srv\\share')).toBe(true)
    expect(isUncPath('//?/UNC/srv/share')).toBe(true)
    expect(isUncPath('//?/unc/srv/share')).toBe(true)
  })

  it('recognises the device-namespace \\\\.\\UNC\\… form', () => {
    // `\\.\UNC\server\share\…` is a real network access — same SMB
    // round-trip as `\\server\share\…`, different spelling.
    expect(isUncPath('\\\\.\\UNC\\srv\\share\\x')).toBe(true)
    expect(isUncPath('//./UNC/srv/share')).toBe(true)
    expect(isUncPath('\\\\.\\unc\\srv\\share')).toBe(true)
  })

  it('does NOT treat drive-local extended or device paths as UNC', () => {
    // `\\?\C:\…` is a drive-local extended path; `\\.\pipe\…` /
    // `\\.\C:` are local device names — none name a remote host.
    expect(isUncPath('\\\\?\\C:\\dir')).toBe(false)
    expect(isUncPath('\\\\.\\pipe\\x')).toBe(false)
    expect(isUncPath('\\\\.\\C:\\x')).toBe(false)
  })

  it('rejects local drive-letter, relative, and server-only paths', () => {
    expect(isUncPath('C:\\dir')).toBe(false)
    // Relative input: toNamespacedPath resolves against the local
    // cwd → drive-local (or rooted) form → false.
    expect(isUncPath('dir\\file')).toBe(false)
    expect(isUncPath('\\single')).toBe(false)
    // Server without a share is not a valid UNC root.
    expect(isUncPath('\\\\srv')).toBe(false)
  })
})

describe.if(isWindows)('expandWindowsFsPaths UNC pass-raw', () => {
  it('passes UNC literals through without stat (broker never touches SMB)', () => {
    // A non-existent UNC host — if the broker stat'd this it would
    // hang on an SMB timeout. Pass-raw returns the literal verbatim
    // (path.win32.normalize applied); resolution failure surfaces
    // at srt-win stamp/grant time.
    const unc = '\\\\srt-no-such-host\\share\\dir'
    expect(expandWindowsFsPaths([unc])).toEqual([unc])
  })

  it('passes \\\\?\\UNC\\… literal through as \\\\server\\share (post-strip)', () => {
    const ext = '\\\\?\\UNC\\srt-no-such-host\\share\\dir'
    expect(expandWindowsFsPaths([ext])).toEqual([
      '\\\\srt-no-such-host\\share\\dir',
    ])
  })

  it('passes a UNC deny literal raw (srt-win soft-drops, no placeholder)', () => {
    // Composition with the deny placeholder chain: a missing UNC
    // deny target must reach srt-win raw — srt-win's is_unc_path
    // soft-drops it rather than mkdir-ing placeholders on an SMB
    // share. The broker side must not stat or placeholder-mark it.
    const unc = '\\\\srt-no-such-host\\share\\secret'
    expect(expandWindowsFsPaths([unc], { mode: 'deny' })).toEqual([unc])
  })
})

// ============================================================================
// parseWindowsSandboxError — typed error from srt-win exec stderr
// ============================================================================

describe('parseWindowsSandboxError', () => {
  it('parses mapped_drive_cwd JSON line among noise', () => {
    const stderr = [
      'srt-win: launching runner as srt-sandbox (overlay=12 var(s))',
      '{"code":"mapped_drive_cwd","drive":"Z:\\\\","message":"the sandbox cannot start with a mapped/network-drive working directory (Z:\\\\ is DRIVE_REMOTE)"}',
      '',
    ].join('\n')
    const err = parseWindowsSandboxError(stderr)
    expect(err).toBeInstanceOf(WindowsSandboxError)
    expect(err?.code).toBe('mapped_drive_cwd')
    expect(err?.subcommand).toBe('exec')
    expect(err?.drive).toBe('Z:\\')
    expect(err?.message).toContain('DRIVE_REMOTE')
  })

  it('returns undefined when no typed-error line present', () => {
    expect(parseWindowsSandboxError('srt-win: error: something\n')).toBe(
      undefined,
    )
    expect(parseWindowsSandboxError('')).toBe(undefined)
  })
})

// ============================================================================
// Tests for globToRegex() after move to sandbox-utils.ts
// ============================================================================

describe('globToRegex (shared)', () => {
  it('should convert simple wildcard', () => {
    const regex = globToRegex('/tmp/test/*.env')
    expect(new RegExp(regex).test('/tmp/test/token.env')).toBe(true)
    expect(new RegExp(regex).test('/tmp/test/secrets.env')).toBe(true)
    expect(new RegExp(regex).test('/tmp/test/readme.txt')).toBe(false)
    // * should not match across /
    expect(new RegExp(regex).test('/tmp/test/sub/token.env')).toBe(false)
  })

  it('should convert globstar pattern', () => {
    const regex = globToRegex('/tmp/test/**/*.env')
    expect(new RegExp(regex).test('/tmp/test/token.env')).toBe(true)
    expect(new RegExp(regex).test('/tmp/test/sub/token.env')).toBe(true)
    expect(new RegExp(regex).test('/tmp/test/sub/deep/token.env')).toBe(true)
    expect(new RegExp(regex).test('/tmp/test/readme.txt')).toBe(false)
  })

  it('should convert ? wildcard', () => {
    const regex = globToRegex('/tmp/test/file?.txt')
    expect(new RegExp(regex).test('/tmp/test/file1.txt')).toBe(true)
    expect(new RegExp(regex).test('/tmp/test/fileA.txt')).toBe(true)
    expect(new RegExp(regex).test('/tmp/test/file12.txt')).toBe(false)
    // ? should not match /
    expect(new RegExp(regex).test('/tmp/test/file/.txt')).toBe(false)
  })

  it('should handle ** without trailing slash', () => {
    const regex = globToRegex('/tmp/test/**')
    expect(new RegExp(regex).test('/tmp/test/anything')).toBe(true)
    expect(new RegExp(regex).test('/tmp/test/sub/deep/file.txt')).toBe(true)
  })
})

// ============================================================================
// Tests for getFsReadConfig with glob expansion on Linux
// ============================================================================

describe.if(isLinux)('getFsReadConfig with glob patterns on Linux', () => {
  const RAW_BASE_DIR = join(tmpdir(), 'fsread-glob-test-' + Date.now())
  const RAW_TEST_DIR = join(RAW_BASE_DIR, 'testdir')

  beforeAll(() => {
    mkdirSync(RAW_TEST_DIR, { recursive: true })
    writeFileSync(join(RAW_TEST_DIR, 'secret.env'), 'SECRET=value')
    writeFileSync(join(RAW_TEST_DIR, 'token.env'), 'TOKEN=value')
    writeFileSync(join(RAW_TEST_DIR, 'readme.txt'), 'readme')
  })

  afterAll(() => {
    if (existsSync(RAW_BASE_DIR)) {
      rmSync(RAW_BASE_DIR, { recursive: true, force: true })
    }
  })

  it('should expand glob denyRead patterns to concrete paths on Linux', async () => {
    const { SandboxManager } = await import(
      '../../src/sandbox/sandbox-manager.js'
    )

    await SandboxManager.reset()
    await SandboxManager.initialize({
      network: {
        allowedDomains: [],
        deniedDomains: [],
      },
      filesystem: {
        denyRead: [join(RAW_TEST_DIR, '*.env')],
        allowWrite: ['/tmp'],
        denyWrite: [],
      },
    })

    const readConfig = SandboxManager.getFsReadConfig()
    const realTestDir = realPath(RAW_TEST_DIR)

    // Should contain the expanded concrete paths, not the glob pattern
    expect(readConfig.denyOnly).toContain(join(realTestDir, 'secret.env'))
    expect(readConfig.denyOnly).toContain(join(realTestDir, 'token.env'))
    // Should NOT contain the original glob pattern
    const hasGlob = readConfig.denyOnly.some((p: string) => p.includes('*'))
    expect(hasGlob).toBe(false)
    // Should NOT contain non-matching files
    expect(readConfig.denyOnly).not.toContain(join(realTestDir, 'readme.txt'))

    await SandboxManager.reset()
  })

  it('should pass non-glob paths through unchanged on Linux', async () => {
    const { SandboxManager } = await import(
      '../../src/sandbox/sandbox-manager.js'
    )

    await SandboxManager.reset()
    await SandboxManager.initialize({
      network: {
        allowedDomains: [],
        deniedDomains: [],
      },
      filesystem: {
        denyRead: [join(RAW_TEST_DIR, 'secret.env')],
        allowWrite: ['/tmp'],
        denyWrite: [],
      },
    })

    const readConfig = SandboxManager.getFsReadConfig()

    // Literal path should pass through (after normalization)
    expect(readConfig.denyOnly.length).toBe(1)
    expect(readConfig.denyOnly[0]).toContain('secret.env')

    await SandboxManager.reset()
  })

  it('should handle trailing /** by stripping suffix (existing behavior)', async () => {
    const { SandboxManager } = await import(
      '../../src/sandbox/sandbox-manager.js'
    )
    const realTestDir = realPath(RAW_TEST_DIR)

    await SandboxManager.reset()
    await SandboxManager.initialize({
      network: {
        allowedDomains: [],
        deniedDomains: [],
      },
      filesystem: {
        denyRead: [RAW_TEST_DIR + '/**'],
        allowWrite: ['/tmp'],
        denyWrite: [],
      },
    })

    const readConfig = SandboxManager.getFsReadConfig()

    // /** suffix is stripped, leaving the directory path
    // This is the existing behavior - bubblewrap uses tmpfs over the directory
    expect(readConfig.denyOnly.length).toBe(1)
    expect(readConfig.denyOnly[0]).toBe(realTestDir)

    await SandboxManager.reset()
  })
})

// ============================================================================
// Tests for getLinuxGlobPatternWarnings
// ============================================================================

describe.if(isLinux)('getLinuxGlobPatternWarnings after fix', () => {
  it('should NOT warn about denyRead globs on Linux (they are now expanded)', async () => {
    const { SandboxManager } = await import(
      '../../src/sandbox/sandbox-manager.js'
    )

    await SandboxManager.reset()
    await SandboxManager.initialize({
      network: {
        allowedDomains: [],
        deniedDomains: [],
      },
      filesystem: {
        denyRead: ['/tmp/test/*.env'],
        allowWrite: ['/tmp'],
        denyWrite: [],
      },
    })

    const warnings = SandboxManager.getLinuxGlobPatternWarnings()

    // denyRead globs should no longer produce warnings since they are expanded
    expect(warnings).not.toContain('/tmp/test/*.env')
    expect(warnings.length).toBe(0)

    await SandboxManager.reset()
  })

  it('should still warn about allowWrite and denyWrite globs on Linux', async () => {
    const { SandboxManager } = await import(
      '../../src/sandbox/sandbox-manager.js'
    )

    await SandboxManager.reset()
    await SandboxManager.initialize({
      network: {
        allowedDomains: [],
        deniedDomains: [],
      },
      filesystem: {
        denyRead: [],
        allowWrite: ['/tmp/test/*.log'],
        denyWrite: ['/tmp/test/secret_*'],
      },
    })

    const warnings = SandboxManager.getLinuxGlobPatternWarnings()

    // allowWrite and denyWrite globs should still produce warnings
    expect(warnings).toContain('/tmp/test/*.log')
    expect(warnings).toContain('/tmp/test/secret_*')

    await SandboxManager.reset()
  })
})

// ============================================================================
// Integration test: denyRead with glob patterns on Linux via sandbox
// ============================================================================

describe.if(isLinux)('denyRead with glob patterns - Linux integration', () => {
  const RAW_BASE_DIR = join(tmpdir(), 'glob-deny-integ-' + Date.now())
  const RAW_TEST_DIR = join(RAW_BASE_DIR, 'testdir')
  let TEST_DIR: string

  beforeAll(() => {
    mkdirSync(RAW_TEST_DIR, { recursive: true })
    writeFileSync(join(RAW_TEST_DIR, 'secret.env'), 'SECRET_DATA')
    writeFileSync(join(RAW_TEST_DIR, 'token.env'), 'TOKEN_DATA')
    writeFileSync(join(RAW_TEST_DIR, 'readme.txt'), 'PUBLIC_DATA')
    TEST_DIR = realPath(RAW_TEST_DIR)
  })

  afterAll(() => {
    if (existsSync(RAW_BASE_DIR)) {
      rmSync(RAW_BASE_DIR, { recursive: true, force: true })
    }
  })

  it('should block reading files matching *.env glob pattern via sandbox', async () => {
    const { SandboxManager } = await import(
      '../../src/sandbox/sandbox-manager.js'
    )

    await SandboxManager.reset()
    await SandboxManager.initialize({
      network: {
        allowedDomains: [],
        deniedDomains: [],
      },
      filesystem: {
        denyRead: [join(RAW_TEST_DIR, '*.env')],
        allowWrite: ['/tmp'],
        denyWrite: [],
      },
    })

    // Try reading a .env file - should fail
    const command = await SandboxManager.wrapWithSandbox(
      `cat ${join(TEST_DIR, 'secret.env')}`,
    )

    const result = spawnSync(command, {
      shell: true,
      encoding: 'utf8',
      timeout: 5000,
    })

    // The file should be blocked (bound to /dev/null, so empty output or error)
    expect(result.stdout).not.toContain('SECRET_DATA')

    await SandboxManager.reset()
  })

  it('should allow reading files NOT matching glob pattern via sandbox', async () => {
    const { SandboxManager } = await import(
      '../../src/sandbox/sandbox-manager.js'
    )

    await SandboxManager.reset()
    await SandboxManager.initialize({
      network: {
        allowedDomains: [],
        deniedDomains: [],
      },
      filesystem: {
        denyRead: [join(RAW_TEST_DIR, '*.env')],
        allowWrite: ['/tmp'],
        denyWrite: [],
      },
    })

    // Try reading a .txt file - should succeed
    const command = await SandboxManager.wrapWithSandbox(
      `cat ${join(TEST_DIR, 'readme.txt')}`,
    )

    const result = spawnSync(command, {
      shell: true,
      encoding: 'utf8',
      timeout: 5000,
    })

    expect(result.status).toBe(0)
    expect(result.stdout).toContain('PUBLIC_DATA')

    await SandboxManager.reset()
  })

  it('should block reading with literal path (regression test)', async () => {
    const { SandboxManager } = await import(
      '../../src/sandbox/sandbox-manager.js'
    )

    await SandboxManager.reset()
    await SandboxManager.initialize({
      network: {
        allowedDomains: [],
        deniedDomains: [],
      },
      filesystem: {
        denyRead: [join(RAW_TEST_DIR, 'secret.env')],
        allowWrite: ['/tmp'],
        denyWrite: [],
      },
    })

    const command = await SandboxManager.wrapWithSandbox(
      `cat ${join(TEST_DIR, 'secret.env')}`,
    )

    const result = spawnSync(command, {
      shell: true,
      encoding: 'utf8',
      timeout: 5000,
    })

    // Should be blocked
    expect(result.stdout).not.toContain('SECRET_DATA')

    await SandboxManager.reset()
  })

  it('should block reading with ** recursive glob via sandbox', async () => {
    // Create a nested file
    mkdirSync(join(RAW_TEST_DIR, 'nested'), { recursive: true })
    writeFileSync(join(RAW_TEST_DIR, 'nested', 'deep.env'), 'DEEP_SECRET')
    const nestedPath = realPath(join(RAW_TEST_DIR, 'nested', 'deep.env'))

    const { SandboxManager } = await import(
      '../../src/sandbox/sandbox-manager.js'
    )

    await SandboxManager.reset()
    await SandboxManager.initialize({
      network: {
        allowedDomains: [],
        deniedDomains: [],
      },
      filesystem: {
        denyRead: [join(RAW_TEST_DIR, '**/*.env')],
        allowWrite: ['/tmp'],
        denyWrite: [],
      },
    })

    // Try reading nested .env file
    const command = await SandboxManager.wrapWithSandbox(`cat ${nestedPath}`)

    const result = spawnSync(command, {
      shell: true,
      encoding: 'utf8',
      timeout: 5000,
    })

    expect(result.stdout).not.toContain('DEEP_SECRET')

    await SandboxManager.reset()
  })
})

// ============================================================================
// Tests for wrapWithSandbox with glob denyRead via customConfig
// ============================================================================

describe.if(isLinux)('wrapWithSandbox with glob denyRead customConfig', () => {
  const RAW_BASE_DIR = join(tmpdir(), 'wrap-sandbox-glob-test-' + Date.now())
  const RAW_TEST_DIR = join(RAW_BASE_DIR, 'testdir')
  let TEST_DIR: string

  beforeAll(() => {
    mkdirSync(RAW_TEST_DIR, { recursive: true })
    writeFileSync(join(RAW_TEST_DIR, 'secret.env'), 'CUSTOM_SECRET')
    writeFileSync(join(RAW_TEST_DIR, 'readme.txt'), 'CUSTOM_PUBLIC')
    TEST_DIR = realPath(RAW_TEST_DIR)
  })

  afterAll(() => {
    if (existsSync(RAW_BASE_DIR)) {
      rmSync(RAW_BASE_DIR, { recursive: true, force: true })
    }
  })

  it('should expand glob denyRead in customConfig on Linux', async () => {
    const { SandboxManager } = await import(
      '../../src/sandbox/sandbox-manager.js'
    )

    await SandboxManager.reset()
    await SandboxManager.initialize({
      network: {
        allowedDomains: [],
        deniedDomains: [],
      },
      filesystem: {
        denyRead: [],
        allowWrite: ['/tmp'],
        denyWrite: [],
      },
    })

    // Use customConfig with glob denyRead
    const command = await SandboxManager.wrapWithSandbox(
      `cat ${join(TEST_DIR, 'secret.env')}`,
      undefined,
      {
        filesystem: {
          denyRead: [join(RAW_TEST_DIR, '*.env')],
          allowWrite: ['/tmp'],
          denyWrite: [],
        },
      },
    )

    const result = spawnSync(command, {
      shell: true,
      encoding: 'utf8',
      timeout: 5000,
    })

    // Should be blocked
    expect(result.stdout).not.toContain('CUSTOM_SECRET')

    await SandboxManager.reset()
  })
})
