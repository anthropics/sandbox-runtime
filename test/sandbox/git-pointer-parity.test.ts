import { describe, it, expect, beforeAll, afterAll } from 'bun:test'
import { spawnSync } from 'node:child_process'
import {
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import {
  basename,
  dirname,
  isAbsolute,
  join,
  relative,
  resolve,
  sep,
} from 'node:path'
import {
  GitMetadataError,
  gitFileDenyPaths,
} from '../../src/sandbox/mandatory-deny-paths.js'
import { isLinux, isWindows } from '../helpers/platform.js'

/**
 * Differential tests for the `.git` pointer and `commondir` parsing in
 * mandatory-deny-paths.ts, which re-implements git's own (see the comment on
 * gitMetadataPath there for why it is not a call to git). Hand-written cases
 * only check the shapes their author thought of; what matters here is that
 * there is no shape this resolves confidently to one directory while git
 * opens another. So every case is resolved twice — once by gitFileDenyPaths,
 * once by `git rev-parse` run in the pointer's own directory — and the rule
 * is: wherever git follows the pointer, that directory's hooks and config
 * are in the deny list, or the wrap was refused outright. Denying more than
 * git follows is fine; denying less is the bug.
 *
 * Skipped where git is not installed. Windows is out of scope for this file
 * (mandatory-deny-paths serves the Linux and macOS backends) and several
 * shapes here — a newline in a directory name, bytes that are not valid
 * UTF-8 — cannot exist there.
 */
const HAS_GIT =
  spawnSync('git', ['--version'], { encoding: 'utf8' }).status === 0

describe.if(!isWindows && HAS_GIT)('git pointer parsing parity', () => {
  let root: string
  let caseCount = 0

  beforeAll(() => {
    root = realpathSync(mkdtempSync(join(tmpdir(), 'git-pointer-parity-')))
  })

  afterAll(() => {
    rmSync(root, { recursive: true, force: true })
  })

  /** What precedes the path. Only `gitdir: ` at byte 0 is one git follows. */
  const PREFIXES = {
    plain: Buffer.from('gitdir: '),
    noSpace: Buffer.from('gitdir:'),
    twoSpaces: Buffer.from('gitdir:  '),
    tab: Buffer.from('gitdir:\t'),
    leadingSpace: Buffer.from(' gitdir: '),
    byteOrderMark: Buffer.concat([
      Buffer.from([0xef, 0xbb, 0xbf]),
      Buffer.from('gitdir: '),
    ]),
    upperCase: Buffer.from('GITDIR: '),
  }

  /**
   * What follows it. git strips `\n` and `\r` from the end of the file and
   * nothing else, and the path ends at the first NUL.
   */
  const TRAILERS = {
    none: Buffer.alloc(0),
    newline: Buffer.from('\n'),
    crlf: Buffer.from('\r\n'),
    mixedEndings: Buffer.from('\n\r\n\r'),
    nineThousandNewlines: Buffer.from('\n'.repeat(9000)),
    sixtyFourKiBOfNewlines: Buffer.from('\n'.repeat(64 * 1024)),
    trailingSpaces: Buffer.from('   \n'),
    secondLine: Buffer.from('\nnot-a-git-dir\n'),
    embeddedNul: Buffer.from('\0/elsewhere\n'),
  }

  /** How the target is spelled. Every component of each exists on disk. */
  const SPELLINGS = {
    absolute: (_checkout: string, target: string): string => target,
    relative: (checkout: string, target: string): string =>
      relative(checkout, target),
    dotSlash: (checkout: string, target: string): string =>
      `./${relative(checkout, target)}`,
    doubledSlash: (checkout: string, target: string): string =>
      relative(checkout, target).replace('/', '//'),
    trailingSlash: (checkout: string, target: string): string =>
      `${relative(checkout, target)}/`,
    backThroughDotDot: (checkout: string, target: string): string =>
      join('..', basename(checkout), '..', relative(dirname(checkout), target)),
  }

  /**
   * The target's shape. git follows a pointer only to a directory its
   * `is_git_directory` accepts: a valid HEAD, plus objects/ and refs/ found
   * through the target's own `commondir`.
   */
  const TARGETS = {
    gitDir: (caseDir: string): string => makeGitDir(join(caseDir, 'target')),
    realGitInit: (caseDir: string): string => {
      const repo = join(caseDir, 'initialized')
      expect(runGit(caseDir, ['init', '-q', repo])).not.toBeUndefined()
      return join(repo, '.git')
    },
    headIsASymlink: (caseDir: string): string => {
      const gitDir = makeGitDir(join(caseDir, 'target'))
      rmSync(join(gitDir, 'HEAD'))
      symlinkSync('refs/heads/main', join(gitDir, 'HEAD'))
      return gitDir
    },
    symlinkToAGitDir: (caseDir: string): string => {
      const gitDir = makeGitDir(join(caseDir, 'real-target'))
      const link = join(caseDir, 'target')
      symlinkSync(gitDir, link)
      return link
    },
    throughASymlinkedParent: (caseDir: string): string => {
      const gitDir = makeGitDir(join(caseDir, 'real', 'target'))
      symlinkSync(dirname(gitDir), join(caseDir, 'link'))
      return join(caseDir, 'link', basename(gitDir))
    },
    /** HEAD and a commondir, no objects/ or refs/: a linked worktree's. */
    worktreeGitDir: (caseDir: string): string => {
      const main = makeGitDir(join(caseDir, 'main.git'))
      const worktree = join(main, 'worktrees', 'wt')
      mkdirSync(join(worktree, 'hooks'), { recursive: true })
      writeFileSync(join(worktree, 'HEAD'), 'ref: refs/heads/main\n')
      writeFileSync(join(worktree, 'commondir'), '../..\n')
      return worktree
    },
    ordinaryDirectory: (caseDir: string): string => {
      const target = join(caseDir, 'target')
      mkdirSync(join(target, 'config'), { recursive: true })
      return target
    },
    absent: (caseDir: string): string => join(caseDir, 'target'),
    nameHoldsANewline: (caseDir: string): string =>
      makeGitDir(join(caseDir, 'two\nlines')),
    nameIsNotAscii: (caseDir: string): string =>
      makeGitDir(join(caseDir, 'ziel-日本-🌱')),
  }

  interface PointerCase {
    prefix: keyof typeof PREFIXES
    spelling: keyof typeof SPELLINGS
    trailer: keyof typeof TRAILERS
    target: keyof typeof TARGETS
    /** Pad the file with newline bytes to exactly this size. */
    padTo?: number
    /** The `.git` file is a symlink to the regular file holding the bytes. */
    pointerIsASymlink?: boolean
  }

  const MAX_GITFILE_SIZE = 1024 * 1024

  /** A directory git's `is_git_directory` accepts. */
  function makeGitDir(gitDir: string): string {
    mkdirSync(join(gitDir, 'objects'), { recursive: true })
    mkdirSync(join(gitDir, 'refs'), { recursive: true })
    mkdirSync(join(gitDir, 'hooks'), { recursive: true })
    writeFileSync(join(gitDir, 'HEAD'), 'ref: refs/heads/main\n')
    return gitDir
  }

  /**
   * git, with the host's configuration and environment kept out of it, so
   * what it resolves is the pointer file and nothing else. Returns its
   * output with the single newline it adds removed — a directory name may
   * end in a space or hold a newline of its own — or undefined when it
   * failed, which for `rev-parse` here means it did not follow the pointer.
   */
  function runGit(cwd: string, args: string[]): string | undefined {
    const env: NodeJS.ProcessEnv = {
      ...process.env,
      HOME: root,
      GIT_CONFIG_NOSYSTEM: '1',
      GIT_CONFIG_GLOBAL: '/dev/null',
      GIT_CONFIG_SYSTEM: '/dev/null',
      GIT_TERMINAL_PROMPT: '0',
    }
    for (const name of [
      'GIT_DIR',
      'GIT_WORK_TREE',
      'GIT_COMMON_DIR',
      'GIT_OBJECT_DIRECTORY',
      'GIT_ALTERNATE_OBJECT_DIRECTORIES',
      'GIT_INDEX_FILE',
      'GIT_CEILING_DIRECTORIES',
      'GIT_DISCOVERY_ACROSS_FILESYSTEM',
      'GIT_NAMESPACE',
      'GIT_CONFIG',
      'GIT_CONFIG_COUNT',
    ]) {
      delete env[name]
    }
    const result = spawnSync(
      'git',
      ['-c', 'core.fsmonitor=', '-c', 'core.hooksPath=/dev/null', ...args],
      { cwd, env, encoding: 'utf8' },
    )
    if (result.status !== 0) return undefined
    return result.stdout.endsWith('\n')
      ? result.stdout.slice(0, -1)
      : result.stdout
  }

  /** The directory `git rev-parse <arg>` names in `checkout`, if any. */
  function gitResolves(checkout: string, arg: string): string | undefined {
    const printed = runGit(checkout, ['rev-parse', arg])
    if (printed === undefined || printed === '') return undefined
    const absolute = isAbsolute(printed) ? printed : resolve(checkout, printed)
    const real = realPathOrSelf(absolute)
    // Discovery walks up from cwd when a pointer is merely absent, so a
    // repository above the scratch tree is not this pointer's target.
    return real.startsWith(root + sep) ? real : undefined
  }

  function realPathOrSelf(target: string): string {
    try {
      return realpathSync(target)
    } catch {
      return target
    }
  }

  /** Each deny path, keyed by the real directory it sits in. */
  function coverage(denyPaths: string[]): Set<string> {
    return new Set(
      denyPaths.map(p => join(realPathOrSelf(dirname(p)), basename(p))),
    )
  }

  const GUARDED_NAMES = ['hooks', 'config', 'config.worktree', 'commondir']

  type Verdict = 'checked' | 'refused' | 'not-followed'

  function assertParity(
    label: string,
    pointer: string,
    checkout: string,
  ): Verdict {
    let denyPaths: string[]
    try {
      denyPaths = gitFileDenyPaths(pointer, false)
    } catch (err) {
      if (!(err instanceof GitMetadataError)) throw err
      // Refusing to sandbox covers everything, including what git follows.
      return 'refused'
    }
    const gitDir = gitResolves(checkout, '--absolute-git-dir')
    if (gitDir === undefined) return 'not-followed'
    const commonDir = gitResolves(checkout, '--git-common-dir')
    const covered = coverage(denyPaths)
    const missing = [gitDir, commonDir]
      .filter((d): d is string => d !== undefined)
      .flatMap(d => GUARDED_NAMES.map(name => join(d, name)))
      .filter(p => !covered.has(p))
    expect({ label, missing }).toEqual({ label, missing: [] })
    return 'checked'
  }

  /** Build one case on disk and resolve it both ways. */
  function runPointerCase(spec: PointerCase, labelPrefix = ''): Verdict {
    const label = labelPrefix + JSON.stringify(spec)
    const caseDir = join(root, `pointer-${caseCount++}`)
    const checkout = join(caseDir, 'checkout')
    mkdirSync(checkout, { recursive: true })

    const target = TARGETS[spec.target](caseDir)
    const spelled = SPELLINGS[spec.spelling](checkout, target)
    let contents = Buffer.concat([
      PREFIXES[spec.prefix],
      Buffer.from(spelled),
      TRAILERS[spec.trailer],
    ])
    if (spec.padTo !== undefined && contents.length < spec.padTo) {
      contents = Buffer.concat([
        contents,
        Buffer.from('\n'.repeat(spec.padTo - contents.length)),
      ])
    }

    const pointer = join(checkout, '.git')
    if (spec.pointerIsASymlink === true) {
      const regular = join(checkout, 'pointer-file')
      writeFileSync(regular, contents)
      symlinkSync(regular, pointer)
    } else {
      writeFileSync(pointer, contents)
    }
    return assertParity(label, pointer, checkout)
  }

  const FIXED_CASES: PointerCase[] = [
    {
      prefix: 'plain',
      spelling: 'relative',
      trailer: 'newline',
      target: 'gitDir',
    },
    {
      prefix: 'plain',
      spelling: 'relative',
      trailer: 'none',
      target: 'gitDir',
    },
    {
      prefix: 'plain',
      spelling: 'absolute',
      trailer: 'newline',
      target: 'gitDir',
    },
    {
      prefix: 'plain',
      spelling: 'dotSlash',
      trailer: 'newline',
      target: 'gitDir',
    },
    {
      prefix: 'plain',
      spelling: 'doubledSlash',
      trailer: 'newline',
      target: 'gitDir',
    },
    {
      prefix: 'plain',
      spelling: 'trailingSlash',
      trailer: 'newline',
      target: 'gitDir',
    },
    {
      prefix: 'plain',
      spelling: 'backThroughDotDot',
      trailer: 'newline',
      target: 'gitDir',
    },
    {
      prefix: 'plain',
      spelling: 'relative',
      trailer: 'crlf',
      target: 'gitDir',
    },
    {
      prefix: 'plain',
      spelling: 'relative',
      trailer: 'mixedEndings',
      target: 'gitDir',
    },
    // The reported bypass: padding past the bound this used to read to.
    {
      prefix: 'plain',
      spelling: 'relative',
      trailer: 'nineThousandNewlines',
      target: 'gitDir',
    },
    {
      prefix: 'plain',
      spelling: 'absolute',
      trailer: 'sixtyFourKiBOfNewlines',
      target: 'gitDir',
    },
    // The size git accepts for a gitfile, exactly and one byte past it.
    {
      prefix: 'plain',
      spelling: 'relative',
      trailer: 'none',
      target: 'gitDir',
      padTo: MAX_GITFILE_SIZE,
    },
    {
      prefix: 'plain',
      spelling: 'relative',
      trailer: 'none',
      target: 'gitDir',
      padTo: MAX_GITFILE_SIZE + 1,
    },
    {
      prefix: 'plain',
      spelling: 'relative',
      trailer: 'trailingSpaces',
      target: 'gitDir',
    },
    {
      prefix: 'plain',
      spelling: 'relative',
      trailer: 'secondLine',
      target: 'gitDir',
    },
    {
      prefix: 'plain',
      spelling: 'relative',
      trailer: 'embeddedNul',
      target: 'gitDir',
    },
    {
      prefix: 'noSpace',
      spelling: 'relative',
      trailer: 'newline',
      target: 'gitDir',
    },
    {
      prefix: 'twoSpaces',
      spelling: 'relative',
      trailer: 'newline',
      target: 'gitDir',
    },
    {
      prefix: 'tab',
      spelling: 'relative',
      trailer: 'newline',
      target: 'gitDir',
    },
    {
      prefix: 'leadingSpace',
      spelling: 'relative',
      trailer: 'newline',
      target: 'gitDir',
    },
    {
      prefix: 'byteOrderMark',
      spelling: 'relative',
      trailer: 'newline',
      target: 'gitDir',
    },
    {
      prefix: 'upperCase',
      spelling: 'relative',
      trailer: 'newline',
      target: 'gitDir',
    },
    {
      prefix: 'plain',
      spelling: 'relative',
      trailer: 'newline',
      target: 'realGitInit',
    },
    {
      prefix: 'plain',
      spelling: 'absolute',
      trailer: 'newline',
      target: 'realGitInit',
    },
    {
      prefix: 'plain',
      spelling: 'relative',
      trailer: 'newline',
      target: 'headIsASymlink',
    },
    {
      prefix: 'plain',
      spelling: 'relative',
      trailer: 'newline',
      target: 'symlinkToAGitDir',
    },
    {
      prefix: 'plain',
      spelling: 'relative',
      trailer: 'newline',
      target: 'throughASymlinkedParent',
    },
    {
      prefix: 'plain',
      spelling: 'relative',
      trailer: 'newline',
      target: 'worktreeGitDir',
    },
    {
      prefix: 'plain',
      spelling: 'absolute',
      trailer: 'nineThousandNewlines',
      target: 'worktreeGitDir',
    },
    {
      prefix: 'plain',
      spelling: 'relative',
      trailer: 'newline',
      target: 'ordinaryDirectory',
    },
    {
      prefix: 'plain',
      spelling: 'relative',
      trailer: 'newline',
      target: 'absent',
    },
    {
      prefix: 'plain',
      spelling: 'relative',
      trailer: 'newline',
      target: 'nameHoldsANewline',
    },
    {
      prefix: 'plain',
      spelling: 'absolute',
      trailer: 'newline',
      target: 'nameIsNotAscii',
    },
    {
      prefix: 'plain',
      spelling: 'relative',
      trailer: 'newline',
      target: 'gitDir',
      pointerIsASymlink: true,
    },
    {
      prefix: 'plain',
      spelling: 'relative',
      trailer: 'nineThousandNewlines',
      target: 'gitDir',
      pointerIsASymlink: true,
    },
  ]

  it('resolves a corpus of pointer shapes the way git does', () => {
    const verdicts = FIXED_CASES.map(runPointerCase)
    // A corpus git followed nothing in would assert nothing at all.
    expect(verdicts.filter(v => v === 'checked').length).toBeGreaterThan(10)
  }, 120_000)

  it('resolves randomly mixed pointer shapes the way git does', () => {
    // Deterministic, so a failing mix is reproducible from the seed below.
    const seed = 0x515
    const random = mulberry32(seed)
    const specs: PointerCase[] = Array.from({ length: 150 }, () => ({
      // Weighted to the one prefix git follows: the others are worth some
      // cases, but they all stop at the same place.
      prefix:
        random() < 0.5
          ? 'plain'
          : pick(random, Object.keys(PREFIXES) as (keyof typeof PREFIXES)[]),
      spelling: pick(
        random,
        Object.keys(SPELLINGS) as (keyof typeof SPELLINGS)[],
      ),
      trailer: pick(random, Object.keys(TRAILERS) as (keyof typeof TRAILERS)[]),
      target: pick(random, Object.keys(TARGETS) as (keyof typeof TARGETS)[]),
      ...(random() < 0.1
        ? { padTo: MAX_GITFILE_SIZE + (random() < 0.5 ? 0 : 1) }
        : {}),
      pointerIsASymlink: random() < 0.1,
    }))
    const verdicts = specs.map((spec, index) =>
      runPointerCase(spec, `seed ${seed}, case ${index}: `),
    )
    expect(verdicts.filter(v => v === 'checked').length).toBeGreaterThan(20)
  }, 300_000)

  // Linux only: the target has to exist for git to follow it, and macOS
  // filesystems refuse a name that is not valid UTF-8 (EILSEQ on mkdir). The
  // refusal itself is platform-independent and covered everywhere by the
  // unit case in mandatory-deny-paths.test.ts, which needs no such target.
  it.if(isLinux)(
    'refuses to sandbox on a pointer whose path is not valid UTF-8',
    () => {
      // The one shape with no honest answer: the bytes name a directory git
      // opens and a JavaScript string of them names a different one, so there
      // is nothing to put in the deny list.
      const caseDir = join(root, `pointer-${caseCount++}`)
      const checkout = join(caseDir, 'checkout')
      mkdirSync(checkout, { recursive: true })
      const target = Buffer.concat([
        Buffer.from(join(caseDir, 'target-')),
        Buffer.from([0xff]),
      ])
      mkdirSync(Buffer.concat([target, Buffer.from('/objects')]), {
        recursive: true,
      })
      mkdirSync(Buffer.concat([target, Buffer.from('/refs')]), {
        recursive: true,
      })
      writeFileSync(
        Buffer.concat([target, Buffer.from('/HEAD')]),
        'ref: refs/heads/main\n',
      )
      const pointer = join(checkout, '.git')
      writeFileSync(
        pointer,
        Buffer.concat([Buffer.from('gitdir: '), target, Buffer.from('\n')]),
      )

      // git follows it, so anything short of refusing would be a deny list
      // for a directory other than the one whose hooks run.
      expect(
        runGit(checkout, ['rev-parse', '--absolute-git-dir']),
      ).not.toBeUndefined()
      expect(() => gitFileDenyPaths(pointer, false)).toThrow(GitMetadataError)
    },
  )

  /** The same shapes in a linked worktree's `commondir`, which has no prefix. */
  interface CommonDirCase {
    spelling: keyof typeof SPELLINGS
    trailer: keyof typeof TRAILERS
    /** Bytes before the path. git trims none of them. */
    leading: string
    padTo?: number
  }

  function runCommonDirCase(spec: CommonDirCase): Verdict {
    const label = JSON.stringify(spec)
    const caseDir = join(root, `commondir-${caseCount++}`)
    const checkout = join(caseDir, 'checkout')
    mkdirSync(checkout, { recursive: true })
    const main = makeGitDir(join(caseDir, 'main.git'))
    const worktree = join(main, 'worktrees', 'wt')
    mkdirSync(join(worktree, 'hooks'), { recursive: true })
    writeFileSync(join(worktree, 'HEAD'), 'ref: refs/heads/main\n')

    let contents = Buffer.concat([
      Buffer.from(spec.leading),
      Buffer.from(SPELLINGS[spec.spelling](worktree, main)),
      TRAILERS[spec.trailer],
    ])
    if (spec.padTo !== undefined && contents.length < spec.padTo) {
      contents = Buffer.concat([
        contents,
        Buffer.from('\n'.repeat(spec.padTo - contents.length)),
      ])
    }
    writeFileSync(join(worktree, 'commondir'), contents)

    const pointer = join(checkout, '.git')
    writeFileSync(pointer, `gitdir: ${worktree}\n`)
    return assertParity(label, pointer, checkout)
  }

  it('resolves a corpus of commondir shapes the way git does', () => {
    const verdicts: Verdict[] = []
    // Every trailer against each way of leading the path — git trims none of
    // it — and then every spelling of the path itself.
    for (const leading of ['', ' ', '\t']) {
      for (const trailer of Object.keys(
        TRAILERS,
      ) as (keyof typeof TRAILERS)[]) {
        verdicts.push(
          runCommonDirCase({ leading, spelling: 'relative', trailer }),
        )
      }
    }
    for (const spelling of Object.keys(
      SPELLINGS,
    ) as (keyof typeof SPELLINGS)[]) {
      verdicts.push(
        runCommonDirCase({ leading: '', spelling, trailer: 'newline' }),
      )
    }
    verdicts.push(
      runCommonDirCase({
        leading: '',
        spelling: 'relative',
        trailer: 'none',
        padTo: MAX_GITFILE_SIZE,
      }),
    )
    expect(verdicts.filter(v => v === 'checked').length).toBeGreaterThan(10)
  }, 300_000)

  it('refuses to sandbox on a commondir past the size it reads', () => {
    // git reads commondir whole, with no bound of its own, so a file past
    // this one still names the git directory whose hooks a commit runs.
    const caseDir = join(root, `commondir-${caseCount++}`)
    const checkout = join(caseDir, 'checkout')
    mkdirSync(checkout, { recursive: true })
    const main = makeGitDir(join(caseDir, 'main.git'))
    const worktree = join(main, 'worktrees', 'wt')
    mkdirSync(join(worktree, 'hooks'), { recursive: true })
    writeFileSync(join(worktree, 'HEAD'), 'ref: refs/heads/main\n')
    writeFileSync(
      join(worktree, 'commondir'),
      '../..'.padEnd(MAX_GITFILE_SIZE + 1, '\n'),
    )
    const pointer = join(checkout, '.git')
    writeFileSync(pointer, `gitdir: ${worktree}\n`)

    expect(() => gitFileDenyPaths(pointer, false)).toThrow(GitMetadataError)
  })
})

function mulberry32(seed: number): () => number {
  let state = seed
  return () => {
    state = (state + 0x6d2b79f5) | 0
    let t = Math.imul(state ^ (state >>> 15), 1 | state)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

function pick<T>(random: () => number, values: readonly T[]): T {
  const value = values[Math.floor(random() * values.length)]
  if (value === undefined) throw new Error('nothing to pick from')
  return value
}
