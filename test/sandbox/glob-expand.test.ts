import { describe, it, expect, beforeAll, afterAll, spyOn } from 'bun:test'
import * as fc from 'fast-check'
// The namespace of the same module production binds (sandbox-utils.ts does
// `import * as fs from 'fs'`), so a spy on it is seen by the code under test.
import * as fs from 'fs'
import * as path from 'path'
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  writeFileSync,
  rmSync,
  existsSync,
  realpathSync,
  symlinkSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { basename, join, win32 } from 'node:path'
import { literalReadings } from '../../src/sandbox/path-entries.js'
import type {
  FilesystemPathEntry,
  SandboxRuntimeConfig,
} from '../../src/sandbox/sandbox-config.js'
import {
  expandGlobPattern,
  expandTilde,
  finish,
  finishInTurns,
  globBaseDirIsRoot,
  globPatternBaseDir,
  globToRegex,
  normalizePathForSandbox,
  type Steps,
  walkGlobPattern,
  walkGlobPatternSteps,
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

describe.if(!isWindows)('walkGlobPattern', () => {
  const RAW_BASE = join(tmpdir(), 'glob-walk-test-' + Date.now())

  beforeAll(() => {
    mkdirSync(join(RAW_BASE, 'a', 'build'), { recursive: true })
    writeFileSync(join(RAW_BASE, 'a', 'build', '1.out'), '')
    mkdirSync(join(RAW_BASE, 'elsewhere'))
    symlinkSync(
      join(RAW_BASE, 'elsewhere'),
      join(RAW_BASE, 'a', 'build', 'link'),
    )
  })

  afterAll(() => {
    rmSync(RAW_BASE, { recursive: true, force: true })
  })

  it('evaluates the directory form over the same listing and records symlinks', () => {
    const BASE = realPath(RAW_BASE)
    const walk = walkGlobPattern(join(RAW_BASE, 'a', '**/build/**'), {
      withDirectoryForm: true,
      followSymlinkedDirectories: true,
    })

    expect(walk.matches).toContain(join(BASE, 'a', 'build', '1.out'))
    expect(walk.directoryMatches).toEqual([join(BASE, 'a', 'build')])
    expect([...walk.symlinks]).toEqual([join(BASE, 'a', 'build', 'link')])
    // Only an entry reached through a symlink has a second, real location.
    expect([...walk.realOf]).toEqual([
      [join(BASE, 'a', 'build', 'link'), join(BASE, 'elsewhere')],
    ])
  })

  it('lists no directory matches without the directory form', () => {
    const walk = walkGlobPattern(join(RAW_BASE, 'a', '**/build/**'))
    expect(walk.directoryMatches).toEqual([])
  })

  it('takes a symlinked directory as the match itself without the link option', () => {
    // What the allowRead expansion and the Windows ACL stamp see: the link is
    // a match of its own, and nothing under what it points at is listed, so a
    // link planted in the tree cannot widen an allow list to another tree.
    const BASE = realPath(RAW_BASE)
    const link = join(BASE, 'a', 'build', 'link')
    writeFileSync(join(BASE, 'elsewhere', 'outside.out'), '')
    try {
      const plain = walkGlobPattern(join(RAW_BASE, 'a', '**/build/**'))
      expect(plain.matches).toContain(link)
      expect(plain.matches).not.toContain(join(link, 'outside.out'))
      expect(plain.realOf.get(link)).toBeUndefined()

      const followed = walkGlobPattern(join(RAW_BASE, 'a', '**/build/**'), {
        followSymlinkedDirectories: true,
      })
      // What is found through the link is reported where it really is.
      expect(followed.matches).toContain(join(BASE, 'elsewhere', 'outside.out'))
      expect(followed.matches).not.toContain(join(link, 'outside.out'))
    } finally {
      rmSync(join(BASE, 'elsewhere', 'outside.out'))
    }
  })

  it.if(process.getuid?.() !== 0)(
    'records a symlink whose target cannot be looked at, with no real location',
    () => {
      // chmod 000 on the directory holding the target, which a sandboxed
      // command with write access there can do and undo: stat and realpath
      // both answer EACCES, which is not "nothing is there".
      const root = realPath(mkdtempSync(join(tmpdir(), 'glob-walk-eacces-')))
      const vault = join(root, 'vault')
      const link = join(root, 'certs', 'k')
      try {
        mkdirSync(join(vault, 'inner'), { recursive: true })
        writeFileSync(join(vault, 'inner', 'k'), 'SECRET')
        mkdirSync(join(root, 'certs'))
        symlinkSync(join(vault, 'inner', 'k'), link)
        chmodSync(vault, 0o000)

        const walk = walkGlobPattern(join(root, 'certs', '*'), {
          followSymlinkedDirectories: true,
        })

        expect(walk.matches).toEqual([link])
        expect(walk.symlinks.has(link)).toBe(true)
        expect(walk.uninspectableLinks.has(link)).toBe(true)
        expect(walk.realOf.get(link)).toBeUndefined()

        // A link that leads nowhere at all stays the other case.
        symlinkSync(join(root, 'gone'), join(root, 'certs', 'dangling'))
        const withDangling = walkGlobPattern(join(root, 'certs', '*'), {
          followSymlinkedDirectories: true,
        })
        expect(withDangling.uninspectableLinks).toEqual(new Set([link]))
        // Neither link is a directory the walk failed to list.
        expect(withDangling.unlisted).toEqual([])
      } finally {
        chmodSync(vault, 0o755)
        rmSync(root, { recursive: true, force: true })
      }
    },
  )

  it('reports where a match beneath a symlinked base really is', () => {
    // alias -> the tree, sideways: normalizePathForSandbox keeps the link
    // spelling for the pattern, so every match is spelled through it and
    // the walk reports where it really is.
    const BASE = realPath(RAW_BASE)
    const alias = join(
      RAW_BASE,
      '..',
      'alias-' + Math.random().toString(36).slice(2),
    )
    symlinkSync(BASE, alias)
    try {
      const walk = walkGlobPattern(join(alias, '**/build/**'))
      const match = join(alias, 'a', 'build', '1.out')
      expect(walk.matches).toContain(match)
      expect(walk.realOf.get(match)).toBe(join(BASE, 'a', 'build', '1.out'))
    } finally {
      rmSync(alias)
    }
  })

  it('terminates on a symlink cycle and still lists the tree', () => {
    // build/up -> ..: the link leads back up the tree, and is not listed
    // through.
    const cyc = realPath(mkdtempSync(join(tmpdir(), 'glob-walk-cycle-')))
    try {
      mkdirSync(join(cyc, 'build'))
      writeFileSync(join(cyc, 'build', '1.out'), '')
      symlinkSync('..', join(cyc, 'build', 'up'))

      const walk = walkGlobPattern(join(cyc, '**/build/**'), {
        withDirectoryForm: true,
      })

      expect(walk.matches).toContain(join(cyc, 'build', '1.out'))
      expect(walk.directoryMatches).toEqual([join(cyc, 'build')])
      expect(walk.symlinks.has(join(cyc, 'build', 'up'))).toBe(true)
      // The cycle is not re-entered: nothing appears twice.
      expect(new Set(walk.matches).size).toBe(walk.matches.length)
    } finally {
      rmSync(cyc, { recursive: true, force: true })
    }
  })

  it.if(process.getuid?.() !== 0)(
    'records a directory it cannot list and still lists its siblings',
    () => {
      const root = realPath(mkdtempSync(join(tmpdir(), 'glob-walk-unlisted-')))
      const locked = join(root, 'pkg', 'locked')
      try {
        mkdirSync(join(locked, 'build'), { recursive: true })
        writeFileSync(join(locked, 'build', 'secret.out'), '')
        mkdirSync(join(root, 'pkg', 'open', 'build'), { recursive: true })
        writeFileSync(join(root, 'pkg', 'open', 'build', '1.out'), '')
        // Searchable but not listable: what a sandboxed command with write
        // access to the tree can leave behind for the next wrap.
        chmodSync(locked, 0o311)

        const walk = walkGlobPattern(join(root, '**/build/**'))

        expect(walk.unlisted).toEqual([locked])
        expect(walk.matches).toEqual([
          join(root, 'pkg', 'open', 'build', '1.out'),
        ])
      } finally {
        chmodSync(locked, 0o755)
        rmSync(root, { recursive: true, force: true })
      }
    },
  )

  it('finds nothing, and nothing unlisted, under a base that is not there', () => {
    const walk = walkGlobPattern(join(RAW_BASE, 'nope', '*.env'))
    expect(walk.matches).toEqual([])
    expect(walk.unlisted).toEqual([])
  })

  it.if(process.getuid?.() !== 0)(
    'reports a base directory it cannot reach as unlisted, not as absent',
    () => {
      // The pattern's base is there; an ancestor of it is not searchable, so
      // nothing under it can be enumerated. Read as absent, the deny would
      // vanish for as long as the mode stays that way — and a sandboxed
      // command can set it and put it back.
      const root = realPath(mkdtempSync(join(tmpdir(), 'glob-walk-base-')))
      const closed = join(root, 'closed')
      const base = join(closed, 'certs')
      try {
        mkdirSync(base, { recursive: true })
        writeFileSync(join(base, 'id.pem'), 'KEY')
        chmodSync(closed, 0o000)

        const walk = walkGlobPattern(join(base, '*.pem'))

        expect(walk.matches).toEqual([])
        expect(walk.unlisted).toEqual([base])
      } finally {
        chmodSync(closed, 0o755)
        rmSync(root, { recursive: true, force: true })
      }
    },
  )

  it.if(process.getuid?.() !== 0)(
    'does not try to list a directory the pattern cannot match beneath',
    () => {
      // proj/*.pem matches at one depth only: a directory beneath proj can
      // hold no match, so it is never listed and never reported as
      // unlistable, whatever its mode.
      const root = realPath(mkdtempSync(join(tmpdir(), 'glob-walk-prune-')))
      const proj = join(root, 'proj')
      try {
        mkdirSync(join(proj, 'pgdata'), { recursive: true })
        mkdirSync(join(proj, 'deep', 'x', 'locked'), { recursive: true })
        writeFileSync(join(proj, 'top.pem'), '')
        writeFileSync(join(proj, 'deep', 'x', 'nested.pem'), '')
        chmodSync(join(proj, 'pgdata'), 0o000)
        chmodSync(join(proj, 'deep', 'x', 'locked'), 0o311)

        const walk = walkGlobPattern(join(proj, '*.pem'))
        expect(walk.matches).toEqual([join(proj, 'top.pem')])
        expect(walk.unlisted).toEqual([])

        // A fixed-depth pattern descends only where its segments allow.
        const nested = walkGlobPattern(join(proj, 'de*/x/*.pem'))
        expect(nested.matches).toEqual([join(proj, 'deep', 'x', 'nested.pem')])
        expect(nested.unlisted).toEqual([])

        // From a ** on, every directory can hold a match again.
        const spanning = walkGlobPattern(join(proj, 'deep/**/*.pem'))
        expect(spanning.matches).toEqual([
          join(proj, 'deep', 'x', 'nested.pem'),
        ])
        expect(spanning.unlisted).toEqual([join(proj, 'deep', 'x', 'locked')])
      } finally {
        chmodSync(join(proj, 'pgdata'), 0o755)
        chmodSync(join(proj, 'deep', 'x', 'locked'), 0o755)
        rmSync(root, { recursive: true, force: true })
      }
    },
  )

  it('skips a pattern whose only literal directory is the root', () => {
    // A wildcard in the first path component leaves '/' to start from. The
    // fixture is real and the pattern matches it, so a walk that started at
    // the root would find it: what this pins is the skip, not an empty tree.
    const root = realPath(mkdtempSync(join(tmpdir(), 'glob-walk-root-')))
    try {
      mkdirSync(join(root, 'keys'))
      writeFileSync(join(root, 'keys', 'id.pem'), 'KEY')
      const under = join(root, 'keys', '*.pem')
      expect(expandGlobPattern(under)).toEqual([join(root, 'keys', 'id.pem')])

      // Same file, named from a first-component wildcard: '/t*/…' on a Linux
      // runner, and whatever the first component of the temporary directory
      // is elsewhere.
      const [, first, ...rest] = under.split('/')
      const fromRoot = ['', first!.slice(0, 1) + '*', ...rest].join('/')
      expect(globPatternBaseDir(normalizePathForSandbox(fromRoot))).toBe('/')
      expect(globBaseDirIsRoot('/')).toBe(true)

      const walk = walkGlobPattern(fromRoot)
      expect(walk.matches).toEqual([])
      expect(walk.unlisted).toEqual([])

      // A pattern with no literal component at all is the other half of the
      // rule: no directory to start from, not even the root. (The walk
      // resolves a relative pattern against the working directory first, so
      // this shape reaches it only from a caller that does not.)
      expect(globPatternBaseDir('*.pem')).toBe('')
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  it('starts no walk from the root, and starts one from a drive or a share', () => {
    // '/' holds every filesystem the machine has mounted. A drive root and
    // the root of a UNC share are one volume each, which the entry names.
    for (const none of ['', '/']) {
      expect(globBaseDirIsRoot(none)).toBe(true)
    }
    for (const dir of [
      'C:',
      'c:',
      'D:',
      '//server/share',
      '/home/u',
      'C:/Users',
      'C:/Users/u',
      '//server/share/keys',
      '/s',
    ]) {
      expect(globBaseDirIsRoot(dir)).toBe(false)
    }
  })

  it('leaves no separator on a base a Windows pattern starts from', () => {
    // path.dirname keeps the separator of a root it returns ('C:/'), which
    // split into path components ends in an empty name no position can
    // consume: the pattern would match nothing. Driven through win32's own
    // semantics, so the case is pinned on every runner.
    const dirname = spyOn(path, 'dirname').mockImplementation(win32.dirname)
    try {
      const patterns = [
        'C:/Users*/id.pem',
        'C:/Program*/keys/**',
        'C:/*.pem',
        'D:/**/*.key',
        '//server/share/x*/y',
        '//server/share/*.pem',
        '//server/share/**/.env',
        'C:/Users/u/certs*/id.pem',
      ]
      const bases = patterns.map(pattern => globPatternBaseDir(pattern))
      expect(dirname).toHaveBeenCalled()

      expect(bases).toEqual([
        'C:',
        'C:',
        'C:',
        'D:',
        '//server/share',
        '//server/share',
        '//server/share',
        'C:/Users/u',
      ])
      // A root of either kind is a base like any other.
      expect(bases.map(globBaseDirIsRoot)).toEqual(patterns.map(() => false))
    } finally {
      dirname.mockRestore()
    }
  })

  it.if(isLinux)(
    'walks a pattern whose only literal directory is a drive root',
    () => {
      // A drive stood up on this runner: a directory named `C:` in the
      // working directory, with path.dirname and path.isAbsolute answering as
      // on Windows and 'C:/' resolving to itself. The listing is the walk's.
      const root = realPath(mkdtempSync(join(tmpdir(), 'glob-walk-drive-')))
      const cwd = process.cwd()
      const realpathSync = fs.realpathSync
      const spies = [
        spyOn(path, 'dirname').mockImplementation(win32.dirname),
        spyOn(path, 'isAbsolute').mockImplementation(win32.isAbsolute),
        spyOn(fs, 'realpathSync').mockImplementation(((
          ...args: Parameters<typeof fs.realpathSync>
        ) =>
          args[0] === 'C:/'
            ? 'C:/'
            : realpathSync(...args)) as typeof fs.realpathSync),
      ]
      try {
        mkdirSync(join(root, 'C:', 'Users1', 'deep'), { recursive: true })
        mkdirSync(join(root, 'C:', 'Other'))
        writeFileSync(join(root, 'C:', 'top.pem'), 'KEY')
        writeFileSync(join(root, 'C:', 'Users1', 'id.pem'), 'KEY')
        writeFileSync(join(root, 'C:', 'Users1', 'deep', 'id.pem'), 'KEY')
        writeFileSync(join(root, 'C:', 'Other', 'id.pem'), 'KEY')
        process.chdir(root)

        // A wildcard inside the first component, at its start, and a `**`.
        const middle = walkGlobPattern('C:/Users*/id.pem')
        expect(middle.matches).toEqual(['C:/Users1/id.pem'])
        expect(walkGlobPattern('C:/*.pem').matches).toEqual(['C:/top.pem'])
        expect(walkGlobPattern('C:/**/deep/*.pem').matches).toEqual([
          'C:/Users1/deep/id.pem',
        ])
        // 'C:' on its own is the drive's current directory, not its root:
        // what the filesystem is asked about is 'C:/'. Asked about 'C:', the
        // stand-in answers with its real path instead.
        expect(middle.baseLocation).toBe('C:/')
        // What the ACL stamp is handed, which is nothing when the walk is.
        expect(expandWindowsFsPaths(['C:/Users*/id.pem'])).toEqual([
          'C:/Users1/id.pem',
        ])
      } finally {
        process.chdir(cwd)
        for (const spy of spies) spy.mockRestore()
        rmSync(root, { recursive: true, force: true })
      }
    },
  )

  it('matches a name that holds a line terminator', () => {
    const root = realPath(mkdtempSync(join(tmpdir(), 'glob-walk-newline-')))
    try {
      mkdirSync(join(root, 'build'))
      writeFileSync(join(root, 'build', 'a\nb.out'), '')
      expect(expandGlobPattern(join(root, '**/build/**'))).toEqual([
        join(root, 'build', 'a\nb.out'),
      ])
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  it('follows a chain of links to its end, under names no longer than real ones', () => {
    // d0/next -> d1, d1/next -> d2, …: the spelling of the last directory
    // crosses every link before it. A walk that carried that spelling would
    // match each entry against a longer and longer path; what is found
    // through a link is carried and reported by its real path instead.
    const root = realPath(mkdtempSync(join(tmpdir(), 'glob-walk-chain-')))
    const links = 300
    try {
      for (let i = 0; i <= links; i++) {
        mkdirSync(join(root, `d${i}`))
        writeFileSync(join(root, `d${i}`, 'id.pem'), 'KEY')
      }
      for (let i = 0; i < links; i++) {
        symlinkSync(join('..', `d${i + 1}`), join(root, `d${i}`, 'next'))
      }

      const walk = walkGlobPattern(join(root, 'd0', '**/*.pem'), {
        followSymlinkedDirectories: true,
      })

      expect(walk.unlisted).toEqual([])
      expect(walk.matches.sort()).toEqual(
        Array.from({ length: links + 1 }, (_, i) =>
          join(root, `d${i}`, 'id.pem'),
        ).sort(),
      )
      const longest = join(root, `d${links}`, 'next').length
      for (const seen of walk.symlinks) {
        expect(seen.length).toBeLessThanOrEqual(longest)
      }
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  it.if(isLinux)(
    'looks at a link by a shorter name when its real path is too long to name',
    () => {
      // deep is a real directory whose path is a few bytes short of PATH_MAX,
      // so deep/key.pem cannot be named by its real path at all, only through
      // base/s. The link is a match, and what it leads to has to be found.
      const root = realPath(mkdtempSync(join(tmpdir(), 'glob-walk-long-')))
      let deep = join(root, 'deep')
      while (deep.length < 4090) {
        // At least one character: a zero-length name would join to the same
        // path and the loop would never end.
        const room = 4090 - deep.length - 1
        deep = join(deep, 'd'.repeat(Math.max(1, Math.min(200, room))))
      }
      const viaLink = join(root, 'base', 's', 'key.pem')
      try {
        mkdirSync(deep, { recursive: true })
        mkdirSync(join(root, 'base'))
        writeFileSync(join(root, 'secret.txt'), 'KEY')
        symlinkSync(deep, join(root, 'base', 's'))
        symlinkSync(join(root, 'secret.txt'), viaLink)
        expect(join(deep, 'key.pem').length).toBeGreaterThan(4095)

        const walk = walkGlobPattern(join(root, 'base', '*/*.pem'), {
          followSymlinkedDirectories: true,
        })

        expect(walk.unlisted).toEqual([])
        expect(walk.matches.map(m => walk.realOf.get(m))).toEqual([
          join(root, 'secret.txt'),
        ])
      } finally {
        rmSync(viaLink, { force: true })
        rmSync(root, { recursive: true, force: true })
      }
    },
  )

  it('lists a directory once, whatever the number of names that lead to it', () => {
    // N packages that each link to every other. Every chain of distinct
    // packages spells the same N files differently, which is about e*N! of
    // them (N=12: 1.3 billion) for a tree a sandboxed command can plant. The
    // pattern cannot tell one of those names from another, so each directory
    // is read once and none is given up on.
    const root = realPath(mkdtempSync(join(tmpdir(), 'glob-walk-names-')))
    const names = Array.from({ length: 12 }, (_, i) => `p${i}`)
    try {
      for (const name of names) {
        mkdirSync(join(root, name, 'node_modules'), { recursive: true })
        writeFileSync(join(root, name, 'index.js'), '')
      }
      for (const from of names) {
        for (const to of names) {
          if (from !== to) {
            symlinkSync(join(root, to), join(root, from, 'node_modules', to))
          }
        }
      }
      const listed: string[] = []
      const readdirSync = fs.readdirSync
      const readdirSpy = spyOn(fs, 'readdirSync').mockImplementation(((
        ...args: Parameters<typeof fs.readdirSync>
      ) => {
        listed.push(String(args[0]))
        return readdirSync(...args)
      }) as typeof fs.readdirSync)
      let walk
      try {
        walk = walkGlobPattern(join(root, '**/index.js'), {
          followSymlinkedDirectories: true,
        })
      } finally {
        readdirSpy.mockRestore()
      }

      // The root, and each package and its node_modules: once each.
      expect(listed.sort()).toEqual(
        [
          root,
          ...names.map(name => join(root, name)),
          ...names.map(name => join(root, name, 'node_modules')),
        ].sort(),
      )
      // Each file is found once, under whichever name reached it first.
      expect(walk.matches.map(m => walk.realOf.get(m) ?? m).sort()).toEqual(
        names.map(name => join(root, name, 'index.js')).sort(),
      )
      expect(walk.unlisted).toEqual([])
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  it('lists a directory once for all the patterns handed the same listings', () => {
    const root = realPath(mkdtempSync(join(tmpdir(), 'glob-walk-shared-')))
    try {
      mkdirSync(join(root, 'a', 'b'), { recursive: true })
      writeFileSync(join(root, 'a', '.env'), '')
      writeFileSync(join(root, 'a', 'b', 'id.pem'), '')
      writeFileSync(join(root, 'a', 'b', 'notes.txt'), '')
      const patterns = ['**/.env', '**/*.pem', '**/*.key'].map(p =>
        join(root, p),
      )
      const alone = patterns.map(p => walkGlobPattern(p).matches)

      const listed: string[] = []
      const readdirSync = fs.readdirSync
      const readdirSpy = spyOn(fs, 'readdirSync').mockImplementation(((
        ...args: Parameters<typeof fs.readdirSync>
      ) => {
        listed.push(String(args[0]))
        return readdirSync(...args)
      }) as typeof fs.readdirSync)
      let together
      try {
        const listings = new Map()
        together = patterns.map(p => walkGlobPattern(p, { listings }).matches)
      } finally {
        readdirSpy.mockRestore()
      }

      expect(listed.sort()).toEqual(
        [root, join(root, 'a'), join(root, 'a', 'b')].sort(),
      )
      expect(together).toEqual(alone)
      expect(together.flat().sort()).toEqual(
        [join(root, 'a', '.env'), join(root, 'a', 'b', 'id.pem')].sort(),
      )
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  it.if(process.getuid?.() !== 0)(
    'tries a directory it cannot list once for all the patterns handed the same listings',
    () => {
      const root = realPath(mkdtempSync(join(tmpdir(), 'glob-walk-failed-')))
      const locked = join(root, 'locked')
      const open = join(root, 'open')
      try {
        mkdirSync(open)
        writeFileSync(join(open, 'id.pem'), '')
        mkdirSync(locked)
        chmodSync(locked, 0o000)
        const patterns = ['**/.env', '**/*.pem', '**/*.key'].map(p =>
          join(root, p),
        )
        const alone = patterns.map(p => walkGlobPattern(p).unlisted)

        const tried: string[] = []
        const readdirSync = fs.readdirSync
        const readdirSpy = spyOn(fs, 'readdirSync').mockImplementation(((
          ...args: Parameters<typeof fs.readdirSync>
        ) => {
          const dir = String(args[0])
          const askedBefore = tried.includes(dir)
          tried.push(dir)
          // Absent when the first pattern asks, and there for the others.
          if (dir === open && !askedBefore) {
            throw Object.assign(new Error('gone'), { code: 'ENOENT' })
          }
          return readdirSync(...args)
        }) as typeof fs.readdirSync)
        let together
        try {
          const listings = new Map()
          together = patterns.map(p => walkGlobPattern(p, { listings }))
        } finally {
          readdirSpy.mockRestore()
        }

        expect(tried.filter(dir => dir === locked)).toEqual([locked])
        // Every pattern still has it to deny whole.
        expect(together.map(walk => walk.unlisted)).toEqual(alone)
        expect(alone).toEqual(patterns.map(() => [locked]))
        // An absence denies nothing, so it is nobody's answer but the asker's.
        expect(tried.filter(dir => dir === open)).toEqual([open, open])
        expect(together.map(walk => walk.matches)).toEqual([
          [],
          [join(open, 'id.pem')],
          [],
        ])
      } finally {
        chmodSync(locked, 0o755)
        rmSync(root, { recursive: true, force: true })
      }
    },
  )

  it('lists a directory again under a name the pattern tells apart', () => {
    // vault is reached by its own name, which matches nothing, and through
    // config/secrets, the only spelling `**/secrets/*.pem` matches. However
    // many links lead to it, those are the two ways the pattern can carry
    // on beneath it, and both are listed.
    const root = realPath(mkdtempSync(join(tmpdir(), 'glob-walk-apart-')))
    try {
      mkdirSync(join(root, 'vault'))
      writeFileSync(join(root, 'vault', 'id.pem'), 'KEY')
      for (let i = 0; i < 20; i++) {
        mkdirSync(join(root, `config${i}`))
        symlinkSync(join('..', 'vault'), join(root, `config${i}`, 'secrets'))
        symlinkSync(join('..', 'vault'), join(root, `config${i}`, 'other'))
      }

      const walk = walkGlobPattern(join(root, '**/secrets/*.pem'), {
        followSymlinkedDirectories: true,
      })

      expect(walk.unlisted).toEqual([])
      expect(walk.matches).toEqual([join(root, 'vault', 'id.pem')])
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  it('follows a `**` written against text through a symlinked directory', () => {
    // globToRegex lets `**.pem` and `ce**/x.pem` span directories. Each is
    // two patterns the walk can follow a name at a time (`*.pem` or
    // `*` / `**` / `*.pem`), so what they reach through a link is found like
    // any other match: here certs leads out of the pattern's base.
    const root = realPath(mkdtempSync(join(tmpdir(), 'glob-walk-glued-')))
    try {
      mkdirSync(join(root, 'proj'))
      mkdirSync(join(root, 'outside', 'deep'), { recursive: true })
      writeFileSync(join(root, 'outside', 'x.pem'), 'KEY')
      writeFileSync(join(root, 'outside', 'deep', 'y.pem'), 'KEY')
      writeFileSync(join(root, 'proj', 'z.pem'), 'KEY')
      symlinkSync(join('..', 'outside'), join(root, 'proj', 'certs'))

      const found = (pattern: string): string[] => {
        const walk = walkGlobPattern(join(root, 'proj', pattern), {
          followSymlinkedDirectories: true,
        })
        expect(walk.unlisted).toEqual([])
        return walk.matches.map(m => walk.realOf.get(m) ?? m).sort()
      }

      expect(found('**.pem')).toEqual([
        join(root, 'outside', 'deep', 'y.pem'),
        join(root, 'outside', 'x.pem'),
        join(root, 'proj', 'z.pem'),
      ])
      expect(found('ce**/x.pem')).toEqual([join(root, 'outside', 'x.pem')])
      expect(found('ce**y.pem')).toEqual([
        join(root, 'outside', 'deep', 'y.pem'),
      ])
      // A run of three before a separator is a `*` and then a `**/`.
      expect(found('***/y.pem')).toEqual([
        join(root, 'outside', 'deep', 'y.pem'),
      ])
      expect(found('***/x.pem')).toEqual([join(root, 'outside', 'x.pem')])
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  it('follows a bracket expression that can match a separator', () => {
    // `[s/]` is an `s` within a name or a separator between two, and both
    // readings are followed, through a link as well.
    const root = realPath(mkdtempSync(join(tmpdir(), 'glob-walk-bracket-')))
    try {
      mkdirSync(join(root, 'proj'))
      mkdirSync(join(root, 'outside', 'cert'), { recursive: true })
      writeFileSync(join(root, 'outside', 'cert', 'x.pem'), 'KEY')
      writeFileSync(join(root, 'outside', 'certsx.pem'), 'KEY')
      symlinkSync(join('..', 'outside'), join(root, 'proj', 'lnk'))

      const found = (pattern: string): string[] => {
        const walk = walkGlobPattern(join(root, 'proj', pattern), {
          followSymlinkedDirectories: true,
        })
        return walk.matches.map(m => walk.realOf.get(m) ?? m).sort()
      }

      expect(found('*/cert[s/]x.pem')).toEqual([
        join(root, 'outside', 'cert', 'x.pem'),
        join(root, 'outside', 'certsx.pem'),
      ])
      // A range holds the separator as a set does: `[+-9]` spans `/`.
      expect(found('*/cert[+-9]x.pem')).toEqual([
        join(root, 'outside', 'cert', 'x.pem'),
      ])
      writeFileSync(join(root, 'outside', 'cert9x.pem'), 'KEY')
      expect(found('*/cert[+-9]x.pem')).toEqual([
        join(root, 'outside', 'cert', 'x.pem'),
        join(root, 'outside', 'cert9x.pem'),
      ])
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  it('matches a pattern it cannot split against real paths only', () => {
    // A wildcard inside a bracket expression is rewritten like any other, so
    // `?[*].pem` reads as one character, any run of `[`, `^` or `/`, then
    // `].pem`. Nothing can follow that a name at a time, and no two names
    // for a directory can be told apart, so each is listed under its own
    // name alone.
    const root = realPath(mkdtempSync(join(tmpdir(), 'glob-walk-split-')))
    try {
      mkdirSync(join(root, 'cfg'))
      writeFileSync(join(root, 'cfg', 'a].pem'), 'KEY')
      symlinkSync('cfg', join(root, 'lnk'))
      symlinkSync(join('cfg', 'a].pem'), join(root, 'b].pem'))

      const walk = walkGlobPattern(join(root, '**/?[*].pem'), {
        followSymlinkedDirectories: true,
      })

      expect(walk.matches.sort()).toEqual([
        join(root, 'b].pem'),
        join(root, 'cfg', 'a].pem'),
      ])
      // A link that is itself a match is still resolved, so that a deny
      // lands on what it leads to.
      expect(walk.realOf.get(join(root, 'b].pem'))).toBe(
        join(root, 'cfg', 'a].pem'),
      )
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  it('follows a placeholder name and a second unclosed `[` through a link', () => {
    // Both are plain text to globToRegex, so the walk splits such a pattern
    // like any other: certs leads out of the pattern's base.
    const root = realPath(mkdtempSync(join(tmpdir(), 'glob-walk-text-')))
    try {
      mkdirSync(join(root, 'outside'))
      writeFileSync(join(root, 'outside', 'x.pem'), 'KEY')
      for (const name of ['__GLOBSTAR__', 'a[b[c']) {
        mkdirSync(join(root, 'proj', name), { recursive: true })
        symlinkSync(
          join('..', '..', 'outside'),
          join(root, 'proj', name, 'certs'),
        )

        const walk = walkGlobPattern(join(root, 'proj', name, '*/x.pem'), {
          followSymlinkedDirectories: true,
        })

        expect([name, walk.matches]).toEqual([
          name,
          [join(root, 'outside', 'x.pem')],
        ])
      }
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  it('does not let one name that fails to list answer for the others', () => {
    // A listing can fail for a reason that has nothing to do with the
    // directory (too many open files at that moment). Letting that failure
    // answer for every later name drops every match beneath the directory.
    const root = realPath(mkdtempSync(join(tmpdir(), 'glob-walk-route-')))
    try {
      mkdirSync(join(root, 'pkg', 'certs'), { recursive: true })
      writeFileSync(join(root, 'pkg', 'certs', 'id.pem'), 'KEY')
      symlinkSync(join('pkg', 'certs'), join(root, 'lnk'))

      const certs = join(root, 'pkg', 'certs')
      const readdirSync = fs.readdirSync
      const attempts: string[] = []
      let failuresLeft = 1
      const spy = spyOn(fs, 'readdirSync').mockImplementation(((
        ...args: Parameters<typeof fs.readdirSync>
      ) => {
        const at = String(args[0])
        if (at === certs) {
          attempts.push(at)
          if (failuresLeft > 0) {
            failuresLeft--
            throw Object.assign(new Error('EMFILE: too many open files'), {
              code: 'EMFILE',
            })
          }
        }
        return readdirSync(...args)
      }) as typeof fs.readdirSync)
      try {
        const retried = walkGlobPattern(join(root, '**/*.pem'), {
          followSymlinkedDirectories: true,
        })
        // Two names lead to the directory; the second one lists it.
        expect(spy).toHaveBeenCalled()
        expect(attempts).toHaveLength(2)
        expect(retried.matches.map(m => retried.realOf.get(m) ?? m)).toEqual([
          join(root, 'pkg', 'certs', 'id.pem'),
        ])
        expect(retried.unlisted).toHaveLength(1)

        // Failing under every name, it is tried under each and named once.
        attempts.length = 0
        failuresLeft = Number.POSITIVE_INFINITY
        const gone = walkGlobPattern(join(root, '**/*.pem'), {
          followSymlinkedDirectories: true,
        })
        expect(attempts).toHaveLength(2)
        expect(gone.matches).toEqual([])
        expect(gone.unlisted).toHaveLength(1)
      } finally {
        spy.mockRestore()
      }
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  it('reports the error of the path it looked at, not of a second name', () => {
    // The walk falls back on a shorter name only when the real path is too
    // long to name. Every other errno belongs to the directory: answered
    // from a second name, an unreadable directory reads as absent.
    const root = realPath(mkdtempSync(join(tmpdir(), 'glob-walk-errno-')))
    try {
      const real = join(root, 'deep', 'a', 'b', 'certs')
      mkdirSync(real, { recursive: true })
      writeFileSync(join(real, 'id.pem'), 'KEY')
      symlinkSync(real, join(root, 's'))

      const readdirSync = fs.readdirSync
      const attempts: string[] = []
      const spy = spyOn(fs, 'readdirSync').mockImplementation(((
        ...args: Parameters<typeof fs.readdirSync>
      ) => {
        const at = String(args[0])
        attempts.push(at)
        if (at === real) {
          throw Object.assign(new Error('EACCES: permission denied'), {
            code: 'EACCES',
          })
        }
        if (at === join(root, 's')) {
          throw Object.assign(new Error('ENOENT: no such file or directory'), {
            code: 'ENOENT',
          })
        }
        return readdirSync(...args)
      }) as typeof fs.readdirSync)
      try {
        const walk = walkGlobPattern(join(root, 's', '*.pem'), {
          followSymlinkedDirectories: true,
        })

        expect(spy).toHaveBeenCalled()
        expect(attempts).toEqual([real])
        expect(walk.unlisted).toEqual([join(root, 's')])
        expect(walk.realOf.get(join(root, 's'))).toBe(real)
      } finally {
        spy.mockRestore()
      }
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  it('names the pattern that is no regular expression', () => {
    expect(() => walkGlobPattern('/tmp/certs/[z-a]*.pem')).toThrow(
      /^Glob pattern \S*\/certs\/\[z-a\]\*\.pem does not compile/,
    )
  })
})

// ============================================================================
// A pattern walked beneath an anchor
// ============================================================================

/**
 * The glob dialect has no escape, so a directory whose own name holds `[`,
 * `*` or `?` cannot be spelled inside a pattern: `anchor` says where the name
 * ends and the pattern starts.
 */
describe.if(!isWindows)('a pattern walked beneath an anchor', () => {
  let root: string
  let ordinary: string
  const named = ['[WIP] project', 'build*', 'notes (draft?)']

  beforeAll(() => {
    root = realPath(mkdtempSync(join(tmpdir(), 'glob-anchor-')))
    ordinary = join(root, 'ordinary')
    // `buildX` and `W` are what `build*` and `[WIP]` match as patterns.
    for (const base of [...named, 'ordinary', 'buildX', 'W project']) {
      mkdirSync(join(root, base, 'deep', 'er'), { recursive: true })
      for (const file of ['a]x', 'deep/a]x', 'deep/er/b]x', 'deep/.env']) {
        writeFileSync(join(root, base, file), '')
      }
    }
  })

  afterAll(() => {
    rmSync(root, { recursive: true, force: true })
  })

  const beneath = (base: string, found: string[]): string[] =>
    found.map(match => match.slice(base.length)).sort()

  describe.each(named)('a directory named %p', name => {
    it.each(['/**/.env', '/deep/*', '/de*/.env', '/**/er/*', '/*/*]x'])(
      'finds for %p what the same tail finds beneath an ordinary directory',
      tail => {
        const anchor = join(root, name)
        const expected = beneath(ordinary, expandGlobPattern(ordinary + tail))
        expect(expected.length).toBeGreaterThan(0)
        expect(
          beneath(anchor, expandGlobPattern(anchor + tail, { anchor })),
        ).toEqual(expected)
      },
    )

    it.each([
      ['/**/[a*]x', ['/a]x', '/deep/a]x']],
      ['/[a*]x', ['/a]x']],
      ['/deep/[a*]x', ['/deep/a]x']],
    ])(
      'matches %p, which cannot be split, by its spelling from the anchor on',
      (tail, expected) => {
        // A wildcard inside a bracket expression: the walk matches such a
        // pattern against whole paths, which beneath an anchor start at it.
        const anchor = join(root, name)
        expect(beneath(ordinary, expandGlobPattern(ordinary + tail))).toEqual(
          expected,
        )
        expect(
          beneath(anchor, expandGlobPattern(anchor + tail, { anchor })),
        ).toEqual(expected)
      },
    )
  })

  it.each([
    [
      'another directory of the same length',
      (a: string) => a.replace(/.$/, '_'),
    ],
    ['a longer path than the pattern', (a: string) => `${a}/deep/.env/more`],
    ['a name cut short', (a: string) => a.slice(0, -1)],
    ['the root', () => '/'],
    ['nothing', () => ''],
  ])('throws for an anchor that is %s', (_what, wrong) => {
    // The tail is cut by length: taken as it comes, a wrong anchor would walk
    // another directory and hand back what the tail matches there.
    const anchor = join(root, '[WIP] project')
    expect(() =>
      expandGlobPattern(`${anchor}/deep/.env`, { anchor: wrong(anchor) }),
    ).toThrow(TypeError)
  })

  it('reads no character of the anchor as pattern', () => {
    // Without the anchor the same strings are patterns from end to end.
    const starred = join(root, 'build*')
    expect(expandGlobPattern(`${starred}/deep/.env`).sort()).toEqual([
      join(root, 'build*', 'deep', '.env'),
      join(root, 'buildX', 'deep', '.env'),
    ])
    expect(
      expandGlobPattern(`${starred}/deep/.e*`, { anchor: starred }),
    ).toEqual([join(root, 'build*', 'deep', '.env')])
    const bracketed = join(root, '[WIP] project')
    expect(expandGlobPattern(`${bracketed}/deep/.e*`)).toEqual([
      join(root, 'W project', 'deep', '.env'),
    ])
    expect(
      expandGlobPattern(`${bracketed}/deep/.e*`, { anchor: bracketed }),
    ).toEqual([join(bracketed, 'deep', '.env')])
  })

  it('keeps a trailing separator, with which a pattern matches nothing', () => {
    const anchor = join(root, '[WIP] project')
    expect(expandGlobPattern(`${ordinary}/*/`)).toEqual([])
    expect(expandGlobPattern(`${anchor}/*/`, { anchor })).toEqual([])
  })

  it('starts at the anchor plus the directory the tail itself starts from', () => {
    const anchor = join(root, '[WIP] project')
    expect(walkGlobPattern(`${anchor}/deep/*`, { anchor }).baseLocation).toBe(
      join(anchor, 'deep'),
    )
    const walk = walkGlobPattern(`${anchor}/**/er/**`, {
      anchor,
      withDirectoryForm: true,
    })
    expect(walk.baseLocation).toBe(anchor)
    expect(walk.directoryMatches).toEqual([join(anchor, 'deep', 'er')])
  })
})

// ============================================================================
// expandTilde — `~\` form is Windows-only
// ============================================================================

describe('finishInTurns', () => {
  /** `count` steps of about `ms` each; returns how many it took. */
  function* busy(
    count: number,
    ms: number,
    taken = { steps: 0 },
  ): Steps<number> {
    for (let i = 0; i < count; i++) {
      const until = performance.now() + ms
      while (performance.now() < until);
      taken.steps++
      yield
    }
    return taken.steps
  }

  it('lets the event loop have a turn while the steps go on', async () => {
    const taken = { steps: 0 }
    let stepsWhenTheTimerFired = -1
    setTimeout(() => (stepsWhenTheTimerFired = taken.steps), 0)
    expect(await finishInTurns(busy(30, 3, taken))).toBe(30)
    expect(stepsWhenTheTimerFired).toBeGreaterThan(0)
    expect(stepsWhenTheTimerFired).toBeLessThan(30)
  })

  it('takes no step for a signal already aborted', async () => {
    const taken = { steps: 0 }
    const reason = new Error('stopped')
    expect(
      await finishInTurns(busy(3, 0, taken), AbortSignal.abort(reason)).catch(
        (e: unknown) => e,
      ),
    ).toBe(reason)
    expect(taken.steps).toBe(0)
  })

  it("stops at the next turn with the signal's reason", async () => {
    const taken = { steps: 0 }
    const controller = new AbortController()
    const reason = new Error('stopped')
    setTimeout(() => controller.abort(reason), 0)
    expect(
      await finishInTurns(busy(30, 3, taken), controller.signal).catch(
        (e: unknown) => e,
      ),
    ).toBe(reason)
    expect(taken.steps).toBeLessThan(30)
  })

  it('hands nothing out when the signal is aborted in the last step', async () => {
    const controller = new AbortController()
    const reason = new Error('stopped')
    function* abortsAtTheEnd(): Steps<string> {
      yield
      controller.abort(reason)
      return 'done'
    }
    expect(
      await finishInTurns(abortsAtTheEnd(), controller.signal).catch(
        (e: unknown) => e,
      ),
    ).toBe(reason)
  })

  it('finds what the walk finds on the spot', async () => {
    const root = realPath(mkdtempSync(join(tmpdir(), 'glob-walk-turns-')))
    try {
      mkdirSync(join(root, 'a', 'b'), { recursive: true })
      writeFileSync(join(root, 'a', 'b', 'id.pem'), '')
      symlinkSync(join(root, 'a'), join(root, 'link'))
      const opts = { followSymlinkedDirectories: true, withDirectoryForm: true }
      const pattern = join(root, '**/*.pem')
      const inTurns = await finishInTurns(walkGlobPatternSteps(pattern, opts))
      expect(inTurns).toEqual(walkGlobPattern(pattern, opts))
      expect(inTurns).toEqual(finish(walkGlobPatternSteps(pattern, opts)))
      expect(inTurns.matches).toEqual([join(root, 'a', 'b', 'id.pem')])
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })
})

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
// expandWindowsFsPaths — beneath a directory with brackets in its name
// ============================================================================

/**
 * `[` and `]` are characters of a name on Windows, but the walk that expands
 * a pattern reads them as a character class: beneath such a directory it
 * finds nothing on its own, and the deny or grant is lost. Pinned here on
 * every host; the spellings only Windows has are in the suite below.
 */
describe('expandWindowsFsPaths beneath a directory named [WIP] project', () => {
  let root: string
  let project: string
  let envFiles: string[]

  beforeAll(() => {
    root = realPath(mkdtempSync(join(tmpdir(), 'win-literal-')))
    project = join(root, '[WIP] project')
    mkdirSync(join(project, 'keep'), { recursive: true })
    mkdirSync(join(project, 'sub', 'deep'), { recursive: true })
    envFiles = [
      join(project, '.env'),
      join(project, 'sub', '.env'),
      join(project, 'sub', 'deep', '.env'),
    ]
    for (const file of envFiles) writeFileSync(file, '')
    writeFileSync(join(project, 'sub', 'readme'), '')
  })

  afterAll(() => {
    rmSync(root, { recursive: true, force: true })
  })

  it('takes a path inside it for the path it is', () => {
    const kept = join(project, 'keep')
    expect(expandWindowsFsPaths([kept])).toEqual([kept])
    expect(expandWindowsFsPaths([kept], { mode: 'deny' })).toEqual([kept])
  })

  it('passes a deny for a path inside it that is not there yet, and drops the grant', () => {
    const notYet = join(project, 'not-yet')
    expect(expandWindowsFsPaths([notYet], { mode: 'deny' })).toEqual([notYet])
    expect(expandWindowsFsPaths([notYet], { mode: 'grant' })).toEqual([])
  })

  it.each(['deny', 'grant'] as const)(
    'expands a pattern beneath it (%s)',
    mode => {
      expect(
        expandWindowsFsPaths([`${project}/**/.env`], { mode }).sort(),
      ).toEqual([...envFiles].sort())
      expect(
        expandWindowsFsPaths([`${project}/sub/*`], { mode }).sort(),
      ).toEqual(
        [
          join(project, 'sub', '.env'),
          join(project, 'sub', 'deep'),
          join(project, 'sub', 'readme'),
        ].sort(),
      )
    },
  )

  it.each(['deny', 'grant'] as const)(
    'expands a /** beneath it, the one wildcard the entry has (%s)',
    mode => {
      // Without `*` or `?` the rest is no pattern to Windows, and the walk
      // still reads its brackets as a class.
      expect(
        expandWindowsFsPaths([`${project}/sub/**`], { mode }).sort(),
      ).toEqual(
        [
          join(project, 'sub', '.env'),
          join(project, 'sub', 'deep'),
          join(project, 'sub', 'deep', '.env'),
          join(project, 'sub', 'readme'),
        ].sort(),
      )
      expect(expandWindowsFsPaths([`${project}/**`], { mode })).toHaveLength(7)
    },
  )

  it('lists a path once that more than one reading finds', () => {
    const out = expandWindowsFsPaths(
      [`${project}/**/.env`, `${project}/*/.env`, join(project, 'sub', '.env')],
      { mode: 'deny' },
    )
    expect(out.sort()).toEqual([...envFiles].sort())
  })

  it('takes a marked entry for a literal, whatever it holds', () => {
    const kept = join(project, 'keep')
    const marked: FilesystemPathEntry = { path: kept, literal: true }
    expect(expandWindowsFsPaths([marked])).toEqual([kept])
    const notYet: FilesystemPathEntry = {
      path: join(project, '[later]'),
      literal: true,
    }
    expect(expandWindowsFsPaths([notYet], { mode: 'deny' })).toEqual([
      join(project, '[later]'),
    ])
    expect(expandWindowsFsPaths([notYet], { mode: 'grant' })).toEqual([])
  })

  it('skips a marked entry with a character no Windows name can hold', () => {
    // srt-win refuses `*` and `?` outright, and nothing can have the name.
    for (const path of [`${project}/*.env`, join(project, 'what?')]) {
      const marked: FilesystemPathEntry = { path, literal: true }
      expect(expandWindowsFsPaths([marked], { mode: 'deny' })).toEqual([])
      expect(expandWindowsFsPaths([marked], { mode: 'grant' })).toEqual([])
    }
  })

  it('refuses an entry that is neither a path nor a marked path', () => {
    for (const entry of [
      { path: project },
      { path: project, literal: false },
    ]) {
      expect(() =>
        expandWindowsFsPaths([entry as unknown as FilesystemPathEntry]),
      ).toThrow(TypeError)
    }
  })

  it.if(!isWindows)(
    'does not expand a grant beneath a link that has the name the pattern spells',
    () => {
      const work = join(root, 'work')
      mkdirSync(join(root, 'vault', 'pub'), { recursive: true })
      mkdirSync(work, { recursive: true })
      writeFileSync(join(root, 'vault', 'pub', 'key'), '')
      symlinkSync(join(root, 'vault'), join(work, '[ab]'))
      const pattern = `${work}/[ab]/pub/*`
      expect(expandWindowsFsPaths([pattern], { mode: 'grant' })).toEqual([])
      expect(expandWindowsFsPaths([pattern], { mode: 'deny' })).toEqual([
        join(work, '[ab]', 'pub', 'key'),
      ])
    },
  )

  it.if(!isWindows)(
    'does not expand a grant beneath a link that lies between such a directory and the first wildcard',
    () => {
      const work = join(root, 'work-with-link-inside')
      const vault = join(root, 'vault-behind-link')
      mkdirSync(join(vault, 'deep', 'pub'), { recursive: true })
      mkdirSync(join(work, '[ab]'), { recursive: true })
      symlinkSync(vault, join(work, '[ab]', 'mid'))
      const pattern = `${work}/[ab]/mid/*/pub`
      expect(expandWindowsFsPaths([pattern], { mode: 'grant' })).toEqual([])
      expect(expandWindowsFsPaths([pattern], { mode: 'deny' })).toEqual([
        join(work, '[ab]', 'mid', 'deep', 'pub'),
      ])
    },
  )
})

describe.if(isWindows)(
  'expandWindowsFsPaths beneath a bracketed directory, as Windows spells paths',
  () => {
    let root: string
    let project: string

    beforeAll(() => {
      root = mkdtempSync(join(tmpdir(), 'win-literal-'))
      project = join(root, '[WIP] project')
      mkdirSync(join(project, 'sub', 'deep'), { recursive: true })
      for (const dir of ['', 'sub', join('sub', 'deep')]) {
        writeFileSync(join(project, dir, '.env'), '')
      }
      writeFileSync(join(project, 'sub', 'readme'), '')
    })

    afterAll(() => {
      rmSync(root, { recursive: true, force: true })
    })

    /** Every result names an existing `.env`, and there are three of them. */
    function expectTheEnvFiles(out: string[]): void {
      expect(out.map(p => basename(p))).toEqual(['.env', '.env', '.env'])
      expect(new Set(out.map(p => p.toLowerCase())).size).toBe(3)
      for (const p of out) expect(existsSync(p)).toBe(true)
    }

    it('expands a pattern spelled with a drive letter and backslashes', () => {
      expect(project).toMatch(/^[A-Za-z]:\\/)
      expectTheEnvFiles(
        expandWindowsFsPaths([`${project}\\**\\.env`], { mode: 'deny' }),
      )
    })

    it('expands one spelled with forward slashes and a lower-case drive letter', () => {
      const spelled =
        project[0]!.toLowerCase() + project.slice(1).replace(/\\/g, '/')
      expectTheEnvFiles(
        expandWindowsFsPaths([`${spelled}/**/.env`], { mode: 'deny' }),
      )
      expectTheEnvFiles(
        expandWindowsFsPaths([`${spelled}/**/.env`], { mode: 'grant' }),
      )
    })

    it('expands one spelled with mixed separators and the extended-length prefix', () => {
      expectTheEnvFiles(
        expandWindowsFsPaths([`\\\\?\\${project}/sub/..\\**/.env`], {
          mode: 'deny',
        }),
      )
    })

    it('takes a marked path spelled with backslashes, and skips one with a wildcard', () => {
      const out = expandWindowsFsPaths(
        [
          { path: `${project}\\sub`, literal: true },
          { path: `${project}\\*.env`, literal: true },
        ],
        { mode: 'deny' },
      )
      expect(out.map(p => basename(p))).toEqual(['sub'])
    })

    it('gives a UNC pattern no reading that would probe the share', () => {
      // Deciding on a reading looks at the disk, and looking at a UNC path
      // is a request to the host it names.
      for (const unc of [
        '\\\\srt-no-such-host\\share\\[WIP] project\\**\\.env',
        '\\\\?\\UNC\\srt-no-such-host\\share\\[WIP] project\\*.env',
        '//srt-no-such-host/share/[WIP] project/*.env',
      ]) {
        for (const kind of ['deny', 'allow'] as const) {
          expect(
            literalReadings(unc, kind, { isPattern: containsGlobCharsWin }),
          ).toEqual([])
        }
      }
    })
  },
)

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

/** One character against the body of a `[…]` set, ranges included. */
function setContains(set: string, char: string): boolean {
  for (let i = 0; i < set.length; i++) {
    if (set[i + 1] === '-' && i + 2 < set.length) {
      if (char >= set[i]! && char <= set[i + 2]!) return true
      i += 2
    } else if (set[i] === char) {
      return true
    }
  }
  return false
}

/**
 * The documented glob syntax matched directly, by backtracking rather than
 * by compiling a regex: `*` and `?` stop at a separator, `**` crosses them,
 * `**\/` is zero or more directories, `[…]` is one character from the set
 * and `[!…]` / `[^…]` one outside it, never a separator. Shares nothing with
 * {@link globToRegex}, so the property below is two implementations checking
 * each other.
 */
function referenceGlobMatch(pattern: string, pathText: string): boolean {
  if (pattern === '') return pathText === ''
  if (pattern.startsWith('**/')) {
    const rest = pattern.slice(3)
    if (referenceGlobMatch(rest, pathText)) return true
    for (let i = 0; i < pathText.length; i++) {
      if (pathText[i] !== '/') continue
      if (referenceGlobMatch(rest, pathText.slice(i + 1))) return true
    }
    return false
  }
  if (pattern.startsWith('**')) {
    const rest = pattern.slice(2)
    for (let i = 0; i <= pathText.length; i++) {
      if (referenceGlobMatch(rest, pathText.slice(i))) return true
    }
    return false
  }
  const head = pattern[0]!
  if (head === '*') {
    for (let i = 0; i <= pathText.length; i++) {
      if (i > 0 && pathText[i - 1] === '/') break
      if (referenceGlobMatch(pattern.slice(1), pathText.slice(i))) return true
    }
    return false
  }
  if (head === '?') {
    return (
      pathText.length > 0 &&
      pathText[0] !== '/' &&
      referenceGlobMatch(pattern.slice(1), pathText.slice(1))
    )
  }
  if (head === '[') {
    const negated = pattern[1] === '!' || pattern[1] === '^'
    const members = negated ? 2 : 1
    const close = pattern.indexOf(']', members)
    if (close > members) {
      const char = pathText[0]
      const holds =
        char !== undefined && setContains(pattern.slice(members, close), char)
      return (
        char !== undefined &&
        (negated ? !holds && char !== '/' : holds) &&
        referenceGlobMatch(pattern.slice(close + 1), pathText.slice(1))
      )
    }
  }
  return (
    pathText.length > 0 &&
    pathText[0] === head &&
    referenceGlobMatch(pattern.slice(1), pathText.slice(1))
  )
}

/** The bodies of the bracket sets of a compiled regex. Outside a set a
 *  backslash takes the next character with it; a set runs from a `[` to the
 *  first `]` after it, none being written inside one. */
function compiledSets(regex: string): string[] {
  const sets: string[] = []
  for (let i = 0; i < regex.length; i++) {
    if (regex[i] === '\\') i++
    else if (regex[i] === '[') {
      const close = regex.indexOf(']', i + 1)
      sets.push(regex.slice(i + 1, close))
      i = close
    }
  }
  return sets
}

/**
 * Whether a compiled set is written the way a JavaScript regular expression
 * and the regex engine of a macOS sandbox profile read alike:
 *
 * - a `-` that is a member comes first, after the `^` of a negated set, and
 *   is never all the set holds;
 * - every other `-` is the middle of a range with no `-` at either end;
 * - a backslash, a member to that engine, is written only doubled, as that
 *   member.
 */
function readsAlikeInBothEngines(set: string): boolean {
  const one = String.raw`(?:\\\\|[^\\\]-])`
  return new RegExp(`^\\^?-?(?:${one}(?:-${one})?)+$`).test(set)
}

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

  it('should match one character from a bracket set', () => {
    const digits = globToRegex('/tmp/test/file[0-9].txt')
    expect(new RegExp(digits).test('/tmp/test/file3.txt')).toBe(true)
    expect(new RegExp(digits).test('/tmp/test/fileA.txt')).toBe(false)
    expect(new RegExp(digits).test('/tmp/test/file12.txt')).toBe(false)
    expect(new RegExp(digits).test('/tmp/test/file.txt')).toBe(false)

    const letters = globToRegex('/tmp/test/[a-z]bc.txt')
    expect(new RegExp(letters).test('/tmp/test/abc.txt')).toBe(true)
    expect(new RegExp(letters).test('/tmp/test/Abc.txt')).toBe(false)
    expect(new RegExp(letters).test('/tmp/test/1bc.txt')).toBe(false)
  })

  it('negates a bracket set written with ^ or !', () => {
    // Both spellings used for negation elsewhere (regex `^`, gitignore `!`)
    // negate the set rather than joining it as ordinary characters.
    const caret = globToRegex('/tmp/test/file[^0-9].txt')
    expect(new RegExp(caret).test('/tmp/test/fileA.txt')).toBe(true)
    expect(new RegExp(caret).test('/tmp/test/file3.txt')).toBe(false)

    const bang = globToRegex('/tmp/test/file[!0-9].txt')
    expect(new RegExp(bang).test('/tmp/test/fileA.txt')).toBe(true)
    expect(new RegExp(bang).test('/tmp/test/file3.txt')).toBe(false)

    // The character that negates the set is not also a member of it.
    expect(new RegExp(globToRegex('/tmp/[^^]')).test('/tmp/^')).toBe(false)
    expect(new RegExp(globToRegex('/tmp/[!!]')).test('/tmp/!')).toBe(false)
  })

  it('keeps a negated bracket set within one path component', () => {
    // A negated set is one character of a name, never the separator.
    const regex = globToRegex('/tmp/test[!x]file')
    expect(new RegExp(regex).test('/tmp/test-file')).toBe(true)
    expect(new RegExp(regex).test('/tmp/test/file')).toBe(false)

    // A leading `-` is that character, not a range from the excluded `/`.
    const dash = globToRegex('/tmp/test/[!-a]')
    expect(new RegExp(dash).test('/tmp/test/b')).toBe(true)
    expect(new RegExp(dash).test('/tmp/test/-')).toBe(false)
    expect(new RegExp(dash).test('/tmp/test/a')).toBe(false)
  })

  it('reads each member as itself, and a `-` wherever it stands for itself', () => {
    // What each set holds: a `-` first, last or straight after a range is
    // itself; between two characters it makes a range, and either may be `-`.
    const sets: [body: string, holds: string][] = [
      ['$', '$'],
      ['a-c.', 'abc.'],
      ['.^$+{}()|', '.^$+{}()|'],
      ['+-0', '+,-./0'],
      ['\\', '\\'],
      ['[.', '[.'],
      ['-', '-'],
      ['a-', 'a-'],
      ['-a', '-a'],
      ['ab-', 'ab-'],
      ['-a-', '-a'],
      ['--', '-'],
      ['---', '-'],
      ['a-c-', 'abc-'],
      ['-a-c', '-abc'],
      ['a-c-e', 'abc-e'],
      ['a-c--', 'abc-'],
      ['--0', '-./0'],
      ['--.', '-.'],
      ['+--', '+,-'],
      [',--', ',-'],
      ['a-c--0', 'abc-./0'],
      ['--0-', '-./0'],
      ['-.', '-.'],
      ['.-', '.-'],
      ['$-', '$-'],
      ['-^', '-^'],
      ['\\-', '\\-'],
      ['-\\', '-\\'],
      ['[-', '[-'],
    ]
    const printable = Array.from({ length: 95 }, (_, i) =>
      String.fromCharCode(32 + i),
    )
    for (const [body, holds] of sets) {
      const inside = new RegExp(globToRegex(`/d/[${body}]`))
      const outside = [
        new RegExp(globToRegex(`/d/[!${body}]`)),
        new RegExp(globToRegex(`/d/[^${body}]`)),
      ]
      for (const char of printable) {
        const held = holds.includes(char)
        expect([body, char, inside.test(`/d/${char}`)]).toEqual([
          body,
          char,
          held,
        ])
        for (const regex of outside) {
          expect([body, char, regex.test(`/d/${char}`)]).toEqual([
            body,
            char,
            !held && char !== '/',
          ])
        }
      }
      // One character of one name, never none and never two.
      expect(inside.test('/d/')).toBe(false)
      expect(inside.test(`/d/${holds[0]}${holds[0]}`)).toBe(false)
    }

    // `]` is never a member, so these open no set and are their own text.
    for (const text of ['/d/[]-]', '/d/[!]-]', '/d/[^]-]']) {
      const regex = new RegExp(globToRegex(text))
      expect(regex.test(text)).toBe(true)
      expect(regex.test('/d/-')).toBe(false)
      expect(regex.test('/d/]')).toBe(false)
    }

    // A range written backwards is no regular expression, `-` at an end or not.
    for (const body of ['c-a', 'a--', '--+', '.--', '-a--', 'a-c--+']) {
      expect(() => new RegExp(globToRegex(`/d/[${body}]`))).toThrow()
      expect(() => new RegExp(globToRegex(`/d/[!${body}]`))).toThrow()
    }
  })

  it('writes that `-` first in its set and escapes no member but a backslash', () => {
    // The regex engine of a macOS sandbox profile reads `[^/\-a]` as a range
    // and refuses `[a-]`; first in the set a `-` is the character to it too.
    expect(globToRegex('/d/[!-a]')).toBe('^/d/[^-/a]$')
    expect(globToRegex('/d/[^-a]')).toBe('^/d/[^-/a]$')
    expect(globToRegex('/d/[!-.]')).toBe('^/d/[^-/.]$')
    expect(globToRegex('/d/[!-a-c]')).toBe('^/d/[^-/a-c]$')
    expect(globToRegex('/d/[!a-]')).toBe('^/d/[^-/a]$')
    expect(globToRegex('/d/[!-]')).toBe('^/d/[^-/]$')
    expect(globToRegex('/d/[-a]')).toBe('^/d/[-a]$')
    expect(globToRegex('/d/[a-]')).toBe('^/d/[-a]$')
    expect(globToRegex('/d/[ab-]')).toBe('^/d/[-ab]$')
    expect(globToRegex('/d/[a-c-]')).toBe('^/d/[-a-c]$')
    expect(globToRegex('/d/[-a-c]')).toBe('^/d/[-a-c]$')
    expect(globToRegex('/d/[a-c-e]')).toBe('^/d/[-a-ce]$')
    expect(globToRegex('/d/[-a-]')).toBe('^/d/[-a]$')
    // A set of nothing else is the character, and needs no set.
    expect(globToRegex('/d/[-]')).toBe('^/d/-$')

    // A range that starts or ends at a `-` is that `-` and the rest of it.
    expect(globToRegex('/d/[--0]')).toBe('^/d/[-.-0]$')
    expect(globToRegex('/d/[!--0]')).toBe('^/d/[^-/.-0]$')
    expect(globToRegex('/d/[--.]')).toBe('^/d/[-.]$')
    expect(globToRegex('/d/[+--]')).toBe('^/d/[-+-,]$')
    expect(globToRegex('/d/[!+--]')).toBe('^/d/[^-/+-,]$')
    expect(globToRegex('/d/[,--]')).toBe('^/d/[-,]$')

    // A backslash is the one member not written as it is: before another
    // character it would be one more member to that engine.
    expect(globToRegex('/d/[\\-]')).toBe('^/d/[-\\\\]$')
    expect(globToRegex('/d/[!\\]')).toBe('^/d/[^/\\\\]$')
    expect(globToRegex('/d/[a-c]')).toBe('^/d/[a-c]$')
    expect(globToRegex('/d/[!a-c.]')).toBe('^/d/[^/a-c.]$')
    expect(globToRegex('/d/[!$]')).toBe('^/d/[^/$]$')
    expect(globToRegex('/d/[+-9]')).toBe('^/d/[+-9]$')
    expect(globToRegex('/d/[.^$+{}()|]')).toBe('^/d/[.^$+{}()|]$')

    // A set that holds a wildcard is not read as one, and keeps its `-` first.
    expect(globToRegex('/d/[!-*]')).toBe('^/d/[^-/[^/]*]$')
  })

  it('writes every set the way both regex engines read alike', () => {
    expect(compiledSets('^/d/[^-/a]x\\[y[b-c]$')).toEqual(['^-/a', 'b-c'])
    for (const bad of [
      'a-',
      '^/a-',
      'ab-',
      '^/\\-a',
      'a\\-',
      '-',
      '--0',
      '^/\\$',
      '^/a-c\\.',
      '\\+-9',
    ]) {
      expect([bad, readsAlikeInBothEngines(bad)]).toEqual([bad, false])
    }
    for (const good of [
      '-a',
      '^-/a',
      '^-/.-0',
      '-a-c',
      '^/a-c.',
      '-\\\\',
      '^/$',
      '+-9',
      '^/\\\\',
    ]) {
      expect([good, readsAlikeInBothEngines(good)]).toEqual([good, true])
    }

    // Every set body of up to four of these, in each of the three spellings,
    // except one that is no regular expression (a range written backwards).
    const alphabet = ['-', 'a', 'c', '.', '0', '+', ',', '\\', '^', '$']
    const misread: string[] = []
    let bodies = ['']
    let compiled = 0
    for (let length = 1; length <= 4; length++) {
      bodies = bodies.flatMap(body => alphabet.map(char => body + char))
      for (const body of bodies) {
        for (const lead of ['', '!', '^']) {
          const glob = `/d/[${lead}${body}]x`
          const regex = globToRegex(glob)
          try {
            new RegExp(regex)
          } catch {
            continue
          }
          compiled++
          if (!compiledSets(regex).every(readsAlikeInBothEngines)) {
            misread.push(`${glob} compiles to ${regex}`)
          }
        }
      }
    }
    expect(compiled).toBeGreaterThan(30000)
    expect(misread.slice(0, 10)).toEqual([])
  })

  it('treats a bracket that opens no set as a literal character', () => {
    const unclosed = globToRegex('/tmp/test/file[abc.txt')
    expect(new RegExp(unclosed).test('/tmp/test/file[abc.txt')).toBe(true)
    expect(new RegExp(unclosed).test('/tmp/test/filea.txt')).toBe(false)

    // Every one of them, not only the first.
    const twice = globToRegex('/tmp/test/file[a[b.txt')
    expect(new RegExp(twice).test('/tmp/test/file[a[b.txt')).toBe(true)

    // A set needs a member, so `[]` is two characters of the path.
    const empty = globToRegex('/tmp/test/file[]a.txt')
    expect(new RegExp(empty).test('/tmp/test/file[]a.txt')).toBe(true)

    const stray = globToRegex('/tmp/test/file]a.txt')
    expect(new RegExp(stray).test('/tmp/test/file]a.txt')).toBe(true)
    expect(new RegExp(stray).test('/tmp/test/filea.txt')).toBe(false)
  })

  it('keeps a component spelled like a globstar placeholder literal', () => {
    // A rewrite that parks `**` under a marker and restores it by name
    // turns a directory actually called __GLOBSTAR__ into a wildcard.
    const parked = globToRegex('/tmp/__GLOBSTAR__/x')
    expect(new RegExp(parked).test('/tmp/__GLOBSTAR__/x')).toBe(true)
    expect(new RegExp(parked).test('/tmp/anything/x')).toBe(false)

    const parkedSlash = globToRegex('/tmp/__GLOBSTAR_SLASH__x')
    expect(new RegExp(parkedSlash).test('/tmp/__GLOBSTAR_SLASH__x')).toBe(true)
  })

  it('agrees with a reference matcher over generated patterns and paths', () => {
    // Segments are drawn from the documented syntax only; the corners the
    // cases above pin (an unclosed bracket, a stray `]`, a set with no
    // members) are left out so a disagreement here means the documented
    // syntax itself diverged. A `-` is drawn in every place a set can hold
    // one and, in `[]-]` and `[!]-]`, where it only looks like it.
    const segment = fc.constantFrom(
      '[!-a]',
      '[!-.]',
      '[a-]',
      '[!a-]',
      '[--0]',
      '[!--0]',
      '[+--]',
      '[-]',
      '[a-c-]',
      '[-a-c]',
      '[]-]',
      '[!]-]',
      'a',
      'bc',
      'a*',
      '*b',
      '*',
      '?',
      'a?c',
      '[ab]',
      '[0-9]',
      '[a-c]c',
      '[!ab]',
      '[^0-9]',
      '[!a-c]c',
      '__GLOBSTAR__',
      '__GLOBSTAR_SLASH__b',
      '**',
    )
    const pattern = fc
      .array(segment, { minLength: 1, maxLength: 4 })
      .map(parts => '/' + parts.join('/'))
    const pathText = fc
      .array(
        fc.constantFrom(
          'a',
          'b',
          'c',
          'bc',
          'a1',
          'abc',
          '0',
          'ab',
          '-',
          '.',
          ',',
          '+',
          '[]-]',
          '[!]-]',
          '__GLOBSTAR__',
          '__GLOBSTAR_SLASH__b',
        ),
        { minLength: 1, maxLength: 4 },
      )
      .map(parts => '/' + parts.join('/'))
    fc.assert(
      fc.property(pattern, pathText, (p, f) => {
        return new RegExp(globToRegex(p)).test(f) === referenceGlobMatch(p, f)
      }),
      { numRuns: 200 },
    )
    fc.assert(
      fc.property(pattern, p =>
        compiledSets(globToRegex(p)).every(readsAlikeInBothEngines),
      ),
      { numRuns: 200 },
    )
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

  it('lists a directory once for all the denyRead patterns of a configuration', async () => {
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
        denyRead: ['*.env', '*.txt', '*.pem'].map(p => join(RAW_TEST_DIR, p)),
        allowWrite: ['/tmp'],
        denyWrite: [],
      },
    })

    const realTestDir = realPath(RAW_TEST_DIR)
    const timesListedBy = async (call: () => unknown): Promise<number> => {
      let times = 0
      const readdirSync = fs.readdirSync
      const readdirSpy = spyOn(fs, 'readdirSync').mockImplementation(((
        ...args: Parameters<typeof fs.readdirSync>
      ) => {
        if (String(args[0]) === realTestDir) times++
        return readdirSync(...args)
      }) as typeof fs.readdirSync)
      try {
        await call()
      } finally {
        readdirSpy.mockRestore()
      }
      return times
    }
    try {
      expect(await timesListedBy(() => SandboxManager.getFsReadConfig())).toBe(
        1,
      )
      expect(
        await timesListedBy(() => SandboxManager.wrapWithSandbox('true')),
      ).toBe(1)
    } finally {
      await SandboxManager.reset()
    }
  })

  it.if(process.getuid?.() !== 0)(
    'gives each path once, however many patterns came to it',
    async () => {
      const { SandboxManager } = await import(
        '../../src/sandbox/sandbox-manager.js'
      )
      const root = realPath(mkdtempSync(join(tmpdir(), 'glob-walk-once-')))
      const locked = join(root, 'locked')
      mkdirSync(locked)
      chmodSync(locked, 0o000)
      writeFileSync(join(root, 'id.pem'), '')

      await SandboxManager.reset()
      await SandboxManager.initialize({
        network: { allowedDomains: [], deniedDomains: [] },
        filesystem: {
          // All three could not list `locked`, and two match the file.
          denyRead: ['**/*.pem', '**/id.*', '**/.env'].map(p => join(root, p)),
          allowWrite: [],
          denyWrite: [],
        },
      })
      try {
        expect(SandboxManager.getFsReadConfig().denyOnly).toEqual([
          join(root, 'id.pem'),
          locked,
        ])
      } finally {
        await SandboxManager.reset()
        chmodSync(locked, 0o755)
        rmSync(root, { recursive: true, force: true })
      }
    },
  )

  for (const list of ['denyRead', 'allowRead'] as const) {
    it(`gives up a wrap whose signal is aborted while a ${list} pattern is walked`, async () => {
      const { SandboxManager } = await import(
        '../../src/sandbox/sandbox-manager.js'
      )
      const root = realPath(mkdtempSync(join(tmpdir(), 'glob-walk-abort-')))
      const dirs = Array.from({ length: 12 }, (_, i) => join(root, `d${i}`))
      for (const dir of dirs) mkdirSync(dir)

      await SandboxManager.reset()
      await SandboxManager.initialize({
        network: { allowedDomains: [], deniedDomains: [] },
        filesystem: {
          denyRead: list === 'denyRead' ? [join(root, '**/*.pem')] : [root],
          allowRead: list === 'allowRead' ? [join(root, '**/*.pem')] : [],
          allowWrite: [],
          denyWrite: [],
        },
      })

      // Each listing takes longer than a turn, and the third one aborts.
      const controller = new AbortController()
      const reason = new Error('stopped')
      let listed = 0
      const readdirSync = fs.readdirSync
      const readdirSpy = spyOn(fs, 'readdirSync').mockImplementation(((
        ...args: Parameters<typeof fs.readdirSync>
      ) => {
        if (String(args[0]).startsWith(root)) {
          if (++listed === 3) controller.abort(reason)
          const until = performance.now() + 15
          while (performance.now() < until);
        }
        return readdirSync(...args)
      }) as typeof fs.readdirSync)
      try {
        expect(
          await SandboxManager.wrapWithSandbox(
            'true',
            undefined,
            undefined,
            controller.signal,
          ).catch((e: unknown) => e),
        ).toBe(reason)
        expect(listed).toBe(3)
      } finally {
        readdirSpy.mockRestore()
        await SandboxManager.reset()
        rmSync(root, { recursive: true, force: true })
      }
    })
  }

  it('wraps by one configuration when that is replaced in a turn', async () => {
    const { SandboxManager } = await import(
      '../../src/sandbox/sandbox-manager.js'
    )
    const root = realPath(mkdtempSync(join(tmpdir(), 'glob-walk-replaced-')))
    for (let i = 0; i < 6; i++) {
      mkdirSync(join(root, 'tree', `d${i}`), { recursive: true })
    }
    mkdirSync(join(root, '.git'))
    for (const name of ['first', 'second', '.git/config']) {
      writeFileSync(join(root, name), '')
    }
    // They differ in what the wrap reads before its first turn and after its
    // last: put together, the first's write list and the second's
    // allowGitConfig would leave .git/config writable, which neither does.
    const network = { allowedDomains: [], deniedDomains: [] }
    const allowRead = [join(root, 'tree', '**/*.pem')]
    const first = {
      network,
      filesystem: {
        denyRead: [join(root, 'first')],
        allowRead,
        allowWrite: [root],
        denyWrite: [],
      },
    }
    const second = {
      network,
      filesystem: {
        denyRead: [join(root, 'second')],
        allowRead,
        allowWrite: [],
        denyWrite: [],
        allowGitConfig: true,
      },
    }

    const cwd = process.cwd()
    process.chdir(root)
    await SandboxManager.reset()
    await SandboxManager.initialize(first)

    // Each listing takes longer than a turn; the configuration is replaced
    // while the allowRead pattern, the first to be walked, is under way.
    let listed = 0
    const readdirSync = fs.readdirSync
    const readdirSpy = spyOn(fs, 'readdirSync').mockImplementation(((
      ...args: Parameters<typeof fs.readdirSync>
    ) => {
      if (String(args[0]).startsWith(root)) {
        if (++listed === 2) SandboxManager.updateConfig(second)
        const until = performance.now() + 15
        while (performance.now() < until);
      }
      return readdirSync(...args)
    }) as typeof fs.readdirSync)
    try {
      const disturbed = await SandboxManager.wrapWithSandbox('true')
      readdirSpy.mockRestore()

      expect(listed).toBeGreaterThan(2)
      expect(disturbed).toBe(await SandboxManager.wrapWithSandbox('true'))
      expect(disturbed).toContain(join(root, 'second'))
      expect(disturbed).not.toContain(join(root, 'first'))
    } finally {
      readdirSpy.mockRestore()
      process.chdir(cwd)
      await SandboxManager.reset()
      rmSync(root, { recursive: true, force: true })
    }
  })

  for (const [what, before, after] of [
    [
      'the rule that matches it was installed',
      ['**/.env'],
      ['**/.env', '**/*.pem'],
    ],
    ['the same rules were installed again', ['**/*.pem'], ['**/*.pem']],
  ] as const) {
    // The third listing is in the middle of the walk, the seventh is its
    // last, after which only the check at the end of the wrap can tell.
    it.each([3, 7])(
      `denies a file written during the wrap, before ${what} (in listing %d)`,
      async at => {
        const { SandboxManager } = await import(
          '../../src/sandbox/sandbox-manager.js'
        )
        const root = realPath(mkdtempSync(join(tmpdir(), 'glob-walk-fresh-')))
        for (let i = 0; i < 6; i++) mkdirSync(join(root, `d${i}`))
        const configured = (patterns: readonly string[]) => ({
          network: { allowedDomains: [], deniedDomains: [] },
          filesystem: {
            denyRead: patterns.map(pattern => join(root, pattern)),
            allowWrite: [],
            denyWrite: [],
          },
        })

        await SandboxManager.reset()
        await SandboxManager.initialize(configured(before))

        // Each listing takes longer than a turn. In listing `at`, with `root`
        // long listed, the host writes a file there and then installs rules.
        const listed: string[] = []
        const readdirSync = fs.readdirSync
        const readdirSpy = spyOn(fs, 'readdirSync').mockImplementation(((
          ...args: Parameters<typeof fs.readdirSync>
        ) => {
          if (String(args[0]).startsWith(root)) {
            if (listed.push(String(args[0])) === at) {
              writeFileSync(join(root, 'key.pem'), '')
              SandboxManager.updateConfig(configured(after))
            }
            const until = performance.now() + 15
            while (performance.now() < until);
          }
          return readdirSync(...args)
        }) as typeof fs.readdirSync)
        try {
          const disturbed = await SandboxManager.wrapWithSandbox('true')
          readdirSpy.mockRestore()

          expect(listed[0]).toBe(root)
          expect(disturbed).toContain(join(root, 'key.pem'))
          expect(disturbed).toBe(await SandboxManager.wrapWithSandbox('true'))
          // The first attempt is left at once; the second lists all seven.
          expect(listed.length).toBe(at + 7)
        } finally {
          readdirSpy.mockRestore()
          await SandboxManager.reset()
          rmSync(root, { recursive: true, force: true })
        }
      },
    )
  }

  // A wrap that names mount points names a manifest of its own for them, so
  // two wraps by one policy differ in that name and in nothing else.
  const withoutManifestName = (wrapped: string): string =>
    wrapped.replace(/(srt-mount-points\/)\d+-[0-9a-f]{16}/g, '$1MANIFEST')

  // As above: the third listing is in the middle of the walk, the seventh is
  // its last.
  it.each([3, 7])(
    'wraps from one working directory when the host changes it in a turn (in listing %d)',
    async at => {
      const { SandboxManager } = await import(
        '../../src/sandbox/sandbox-manager.js'
      )
      const root = realPath(mkdtempSync(join(tmpdir(), 'glob-walk-chdir-')))
      for (let i = 0; i < 6; i++)
        mkdirSync(join(root, 'tree', `d${i}`), { recursive: true })
      mkdirSync(join(root, 'from'))
      mkdirSync(join(root, 'to'))
      const cwd = process.cwd()
      process.chdir(join(root, 'from'))

      await SandboxManager.reset()
      await SandboxManager.initialize({
        network: { allowedDomains: [], deniedDomains: [] },
        filesystem: {
          denyRead: [join(root, 'tree', '**/*.pem')],
          allowWrite: ['.'],
          denyWrite: [],
        },
      })

      const listed: string[] = []
      const readdirSync = fs.readdirSync
      const readdirSpy = spyOn(fs, 'readdirSync').mockImplementation(((
        ...args: Parameters<typeof fs.readdirSync>
      ) => {
        if (String(args[0]).startsWith(join(root, 'tree'))) {
          if (listed.push(String(args[0])) === at) {
            process.chdir(join(root, 'to'))
          }
          const until = performance.now() + 15
          while (performance.now() < until);
        }
        return readdirSync(...args)
      }) as typeof fs.readdirSync)
      try {
        const disturbed = await SandboxManager.wrapWithSandbox('true')
        readdirSpy.mockRestore()

        expect(withoutManifestName(disturbed)).toBe(
          withoutManifestName(await SandboxManager.wrapWithSandbox('true')),
        )
        expect(disturbed).toContain(join(root, 'to'))
        expect(disturbed).not.toContain(join(root, 'from'))
        expect(listed.length).toBe(at + 7)
      } finally {
        readdirSpy.mockRestore()
        process.chdir(cwd)
        await SandboxManager.reset()
        rmSync(root, { recursive: true, force: true })
      }
    },
  )

  it('wraps from one working directory when the host changes it while the mandatory denies are looked for', async () => {
    const { SandboxManager } = await import(
      '../../src/sandbox/sandbox-manager.js'
    )
    const root = realPath(mkdtempSync(join(tmpdir(), 'glob-walk-scan-cd-')))
    mkdirSync(join(root, 'from'))
    mkdirSync(join(root, 'to'))
    // Stands in for ripgrep: says that it ran, finds nothing, and takes long
    // enough for the host to move meanwhile.
    const scans = join(root, 'scans')
    const slowScan = join(root, 'slow-scan')
    writeFileSync(slowScan, `#!/bin/sh\necho ran >> ${scans}\nsleep 0.4\n`, {
      mode: 0o755,
    })
    const cwd = process.cwd()
    process.chdir(join(root, 'from'))

    await SandboxManager.reset()
    await SandboxManager.initialize({
      network: { allowedDomains: [], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: ['.'], denyWrite: [] },
      ripgrep: { command: slowScan },
    })
    const moving = setTimeout(() => process.chdir(join(root, 'to')), 150)
    try {
      const disturbed = await SandboxManager.wrapWithSandbox('true')

      expect(fs.readFileSync(scans, 'utf8')).toBe('ran\nran\n')
      expect(withoutManifestName(disturbed)).toBe(
        withoutManifestName(await SandboxManager.wrapWithSandbox('true')),
      )
      expect(disturbed).toContain(join(root, 'to'))
      expect(disturbed).not.toContain(join(root, 'from'))
    } finally {
      clearTimeout(moving)
      process.chdir(cwd)
      await SandboxManager.reset()
      rmSync(root, { recursive: true, force: true })
    }
  })

  it('starts over for a configuration object that is installed a second time', async () => {
    const { SandboxManager } = await import(
      '../../src/sandbox/sandbox-manager.js'
    )
    const DIRECTORIES = 24
    const root = realPath(mkdtempSync(join(tmpdir(), 'glob-walk-again-')))
    for (let i = 0; i < DIRECTORIES; i++) mkdirSync(join(root, `d${i}`))
    // initialize() keeps this very object, so it is the same one afterwards.
    const same = {
      network: { allowedDomains: [], deniedDomains: [] },
      filesystem: {
        denyRead: [join(root, '**/*.pem')],
        allowWrite: [],
        denyWrite: [],
      },
    }

    await SandboxManager.reset()
    await SandboxManager.initialize(same)

    // In the third listing, with `root` long listed, the host writes a file
    // there, and then resets and initializes in the turns that follow.
    const listed: string[] = []
    let listedWhenInstalled: number | undefined
    let installed: Promise<void> | undefined
    const readdirSync = fs.readdirSync
    const readdirSpy = spyOn(fs, 'readdirSync').mockImplementation(((
      ...args: Parameters<typeof fs.readdirSync>
    ) => {
      if (String(args[0]).startsWith(root)) {
        if (listed.push(String(args[0])) === 3) {
          writeFileSync(join(root, 'key.pem'), '')
          installed = SandboxManager.reset().then(() => {
            const initialized = SandboxManager.initialize(same)
            listedWhenInstalled = listed.length
            return initialized
          })
        }
        const until = performance.now() + 15
        while (performance.now() < until);
      }
      return readdirSync(...args)
    }) as typeof fs.readdirSync)
    try {
      const disturbed = await SandboxManager.wrapWithSandbox('true')
      readdirSpy.mockRestore()

      // While the first attempt was still walking, or this shows nothing.
      expect(listedWhenInstalled).toBeLessThan(1 + DIRECTORIES)
      expect(disturbed).toContain(join(root, 'key.pem'))
    } finally {
      readdirSpy.mockRestore()
      await installed
      await SandboxManager.reset()
      rmSync(root, { recursive: true, force: true })
    }
  })

  it('walks without a turn once a wrap has started over twice', async () => {
    const { SandboxManager } = await import(
      '../../src/sandbox/sandbox-manager.js'
    )
    const root = realPath(mkdtempSync(join(tmpdir(), 'glob-walk-churn-')))
    for (let n = 0; n < 8; n++) {
      mkdirSync(join(root, `t${n}`, 'd'), { recursive: true })
      writeFileSync(join(root, `t${n}`, 'd', 'id.pem'), '')
    }
    // Each configuration's pattern has a base no other one lists.
    const configured = (n: number) => ({
      network: { allowedDomains: [], deniedDomains: [] },
      filesystem: {
        denyRead: [join(root, `t${n}`, '**/*.pem')],
        allowWrite: [],
        denyWrite: [],
      },
    })

    await SandboxManager.reset()
    await SandboxManager.initialize(configured(0))

    // Each listing takes longer than a turn and leaves a new configuration
    // for the next turn to bring. The first attempt is left after it has
    // listed t0 and the second after t1; the third walks t2 without a turn,
    // so the configurations its listings leave come too late.
    let replaced = 0
    const listed: string[] = []
    const readdirSync = fs.readdirSync
    const readdirSpy = spyOn(fs, 'readdirSync').mockImplementation(((
      ...args: Parameters<typeof fs.readdirSync>
    ) => {
      if (String(args[0]).startsWith(root)) {
        listed.push(String(args[0]).slice(root.length + 1))
        setImmediate(() => SandboxManager.updateConfig(configured(++replaced)))
        const until = performance.now() + 15
        while (performance.now() < until);
      }
      return readdirSync(...args)
    }) as typeof fs.readdirSync)
    try {
      const wrapped = await SandboxManager.wrapWithSandbox('true')
      readdirSpy.mockRestore()

      expect(listed).toEqual(['t0', 't1', 't2', 't2/d'])
      expect(wrapped).toContain(join(root, 't2', 'd', 'id.pem'))
    } finally {
      readdirSpy.mockRestore()
      await new Promise(resolve => setImmediate(resolve))
      await SandboxManager.reset()
      rmSync(root, { recursive: true, force: true })
    }
  })

  it('gives up a wrap whose signal is aborted while the mandatory denies are looked for', async () => {
    const { SandboxManager } = await import(
      '../../src/sandbox/sandbox-manager.js'
    )
    const root = realPath(mkdtempSync(join(tmpdir(), 'glob-walk-scan-')))
    // Stands in for ripgrep, and outlasts the abort.
    const slowScan = join(root, 'slow-scan')
    writeFileSync(slowScan, '#!/bin/sh\nsleep 5\n', { mode: 0o755 })

    await SandboxManager.reset()
    await SandboxManager.initialize({
      network: { allowedDomains: [], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: [root], denyWrite: [] },
      ripgrep: { command: slowScan },
    })
    const controller = new AbortController()
    const reason = new Error('stopped')
    setTimeout(() => controller.abort(reason), 200)
    try {
      expect(
        await SandboxManager.wrapWithSandbox(
          'true',
          undefined,
          undefined,
          controller.signal,
        ).catch((e: unknown) => e),
      ).toBe(reason)
    } finally {
      await SandboxManager.reset()
      rmSync(root, { recursive: true, force: true })
    }
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

  it('warns about a read pattern with no literal directory to start from', async () => {
    // Expanded, such a pattern would have to start listing at '/', so it is
    // skipped and the entry it came from is silently unenforced. That is the
    // one read glob shape a user has to be told about.
    const { SandboxManager } = await import(
      '../../src/sandbox/sandbox-manager.js'
    )

    await SandboxManager.reset()
    await SandboxManager.initialize({
      network: { allowedDomains: [], deniedDomains: [] },
      filesystem: {
        denyRead: ['/**/*.pem', '/opt*/keys/**', '/tmp/test/*.env'],
        allowRead: ['/et*/ssl'],
        allowWrite: ['/tmp'],
        denyWrite: [],
      },
    })

    const warnings = SandboxManager.getLinuxGlobPatternWarnings()

    expect(warnings.sort()).toEqual(
      ['/**/*.pem', '/et*/ssl', '/opt*/keys/**'].sort(),
    )

    await SandboxManager.reset()
  })

  const initialized = async (
    config: Pick<SandboxRuntimeConfig, 'filesystem' | 'credentials'>,
  ) => {
    const { SandboxManager } = await import(
      '../../src/sandbox/sandbox-manager.js'
    )
    await SandboxManager.reset()
    await SandboxManager.initialize({
      network: { allowedDomains: [], deniedDomains: [] },
      ...config,
    })
    return SandboxManager
  }

  it('warns about such a pattern as the path of a credential file deny', async () => {
    // It joins the read denies and is skipped like one of them.
    const SandboxManager = await initialized({
      filesystem: {
        denyRead: ['/**/.netrc'],
        allowWrite: ['/tmp/test/*.log'],
        denyWrite: [],
      },
      credentials: {
        files: [
          { path: '/**/.netrc', mode: 'deny' },
          { path: '/*/token', mode: 'deny' },
          { path: '/tmp/test/*.key', mode: 'deny' },
          // Always the name of one file.
          { path: '/*/masked', mode: 'mask' },
        ],
      },
    })

    expect(SandboxManager.getLinuxGlobPatternWarnings()).toEqual([
      '/tmp/test/*.log',
      '/**/.netrc',
      '/*/token',
    ])

    await SandboxManager.reset()
  })

  it.each(['denyRead', 'allowRead'] as const)(
    'tells such a pattern from every other %s entry',
    async list => {
      const skipped = ['/**/.ssh/**', '/*/x', '/*', '/*/**', '/ho*/x']
      const applied: FilesystemPathEntry[] = [
        '**/.ssh/**', // starts at the working directory
        '~/**/.env',
        '/home/**/x',
        '/home/x',
        '/**', // `/`, once the trailing `/**` is dropped
        { path: '/**/.ssh/**', literal: true },
      ]
      const SandboxManager = await initialized({
        filesystem: {
          denyRead: [],
          allowWrite: [],
          denyWrite: [],
          [list]: [...applied, ...skipped],
        },
      })

      expect(SandboxManager.getLinuxGlobPatternWarnings()).toEqual(skipped)

      await SandboxManager.reset()
    },
  )
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
