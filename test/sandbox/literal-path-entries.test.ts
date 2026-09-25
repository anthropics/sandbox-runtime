import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  spyOn,
} from 'bun:test'
import { spawnSync } from 'node:child_process'
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { connect } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import { wrapCommandWithSandboxLinux } from '../../src/sandbox/linux-sandbox-utils.js'
import * as linuxViolationMonitorModule from '../../src/sandbox/linux-violation-monitor.js'
import {
  type LinuxViolationMonitorOptions,
  startLinuxSandboxViolationMonitor,
} from '../../src/sandbox/linux-violation-monitor.js'
import { wrapCommandWithSandboxMacOS } from '../../src/sandbox/macos-sandbox-utils.js'
import {
  literalReadings,
  type PathReading,
  pathEntryKey,
  readNamesOf,
  splitPathEntries,
  writeNamesOf,
  writeRootsOf,
} from '../../src/sandbox/path-entries.js'
import type { FilesystemPathEntry } from '../../src/sandbox/sandbox-config.js'
import {
  denyGlobRegex,
  expandGlobPattern,
  getDefaultWritePaths,
  globToRegex,
  normalizePathForSandbox,
} from '../../src/sandbox/sandbox-utils.js'
import {
  loadConfig,
  loadConfigFromString,
} from '../../src/utils/config-loader.js'
import { bwrapCanNamespace } from '../helpers/bwrap-namespace.js'
import { isLinux, isWindows } from '../helpers/platform.js'

/**
 * A directory may hold `*`, `?`, `[` or `]` in its name. An entry of
 * `denyRead`, `allowRead`, `allowWrite` or `denyWrite` that lies inside one
 * has those characters in it, and read as a pattern alone it matches
 * nothing: the deny is lost and the allow opens nothing. Such an entry is
 * read as the pattern AND as the path it spells wherever the part that holds
 * the characters exists on disk; an entry marked `{ path, literal: true }`
 * is a path and nothing else.
 *
 * The Linux suites run real commands under bubblewrap. The macOS suites
 * read the generated profile, which is string building and runs on any
 * POSIX host; nothing here runs a profile under sandbox-exec.
 */

/** The folder every suite works in: a name a pattern reads as a class. */
const PROJECT = '[WIP] project'

const WRAP_TIMEOUT_MS = 60_000
const RUN_TIMEOUT_MS = 15_000

function freshRoot(): string {
  return realpathSync(mkdtempSync(join(tmpdir(), 'literal-paths-')))
}

/** A path as one shell word. */
function q(p: string): string {
  return `'${p.replace(/'/g, `'\\''`)}'`
}

/** `text` as it appears inside a regular expression that matches it. */
function escapedForRegex(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

/**
 * The filter a spelling compiles to when its characters are read as a
 * pattern, which is the reading every entry with glob characters has.
 */
function patternFilter(spelling: string, kind: 'allow' | 'deny'): string {
  const compile = kind === 'deny' ? denyGlobRegex : globToRegex
  return `(regex ${JSON.stringify(compile(normalizePathForSandbox(spelling)))})`
}

const subpath = (p: string): string => `(subpath ${JSON.stringify(p)})`
const literalFilter = (p: string): string => `(literal ${JSON.stringify(p)})`

/** Every `(regex "…")` the profile emits. */
function emittedRegexes(profile: string): RegExp[] {
  return [...profile.matchAll(/\(regex ("(?:[^"\\]|\\.)*")\)/g)].map(
    match => new RegExp(JSON.parse(match[1]!) as string),
  )
}

/** Every `(subpath "…")` the profile emits. */
function emittedSubpaths(profile: string): string[] {
  return [...profile.matchAll(/\(subpath ("(?:[^"\\]|\\.)*")\)/g)].map(
    match => JSON.parse(match[1]!) as string,
  )
}

/** The rule of `profile` that starts with `head`, up to its closing line. */
function ruleOf(profile: string, head: string): string {
  const start = profile.indexOf(head)
  if (start < 0) return ''
  const end = profile.indexOf('(with message', start)
  return profile.slice(start, end)
}

function macProfile(
  readConfig: { denyOnly: string[]; allowWithinDeny?: string[] } | undefined,
  writeConfig: { allowOnly: string[]; denyWithinAllow: string[] } | undefined,
): string {
  return wrapCommandWithSandboxMacOS({
    command: 'true',
    needsNetworkRestriction: false,
    readConfig,
    writeConfig,
  })
}

const noNetwork = { allowedDomains: [], deniedDomains: [] }

type FilesystemLists = {
  denyRead?: FilesystemPathEntry[]
  allowRead?: FilesystemPathEntry[]
  allowWrite?: FilesystemPathEntry[]
  denyWrite?: FilesystemPathEntry[]
}

async function initialize(filesystem: FilesystemLists): Promise<void> {
  await SandboxManager.reset()
  await SandboxManager.initialize(
    {
      network: noNetwork,
      filesystem: {
        denyRead: [],
        allowWrite: [],
        denyWrite: [],
        ...filesystem,
      },
    },
    undefined,
    false,
  )
}

/**
 * Runs `payload` under the policy, behind an `echo BOOTED`, so a sandbox
 * that failed to start cannot read as a payload that was refused.
 */
async function sandboxed(
  filesystem: FilesystemLists,
  payload: string,
  opts: { cwd: string; perWrap?: FilesystemLists; keepMountPoints?: boolean },
): Promise<{ stdout: string; stderr: string }> {
  await initialize(opts.perWrap ? {} : filesystem)
  const wrapped = await SandboxManager.wrapWithSandbox(
    `echo BOOTED; ${payload}`,
    undefined,
    opts.perWrap
      ? {
          filesystem: {
            denyRead: [],
            allowWrite: [],
            denyWrite: [],
            ...opts.perWrap,
          },
        }
      : undefined,
  )
  const result = spawnSync(wrapped, {
    shell: true,
    encoding: 'utf8',
    cwd: opts.cwd,
    timeout: RUN_TIMEOUT_MS,
  })
  if (!opts.keepMountPoints) SandboxManager.cleanupAfterCommand()
  expect(result.stdout).toContain('BOOTED')
  return { stdout: result.stdout, stderr: result.stderr }
}

// ============================================================================
// Deciding the reading
// ============================================================================

describe.if(!isWindows)('literalReadings', () => {
  let root: string
  let project: string
  const savedCwd = process.cwd()

  beforeAll(() => {
    root = freshRoot()
    project = join(root, PROJECT)
    mkdirSync(join(project, 'keep'), { recursive: true })
    mkdirSync(join(project, 'src'), { recursive: true })
    mkdirSync(join(project, '[ab]'), { recursive: true })
    writeFileSync(join(project, 'file'), '')
    mkdirSync(join(root, 'plain', '[ab]'), { recursive: true })
    mkdirSync(join(root, 'plain', 'a'), { recursive: true })
    mkdirSync(join(root, 'plain', 'b'), { recursive: true })
    mkdirSync(join(root, 'star'), { recursive: true })
    writeFileSync(join(root, 'star', '*.env'), '')
    writeFileSync(join(root, 'star', 'a.env'), '')
    for (const name of [
      'open[bracket',
      'close]bracket',
      'build*',
      'notes (draft?)',
      'curly{a,b}',
    ]) {
      mkdirSync(join(root, name, 'out'), { recursive: true })
    }
    mkdirSync(join(root, 'target', 'keep'), { recursive: true })
    symlinkSync(join(root, 'target'), join(root, 'li[n]k'))
    symlinkSync(join(root, 'nowhere'), join(root, 'dang[l]ing'))
    mkdirSync(join(project, 'real'), { recursive: true })
    symlinkSync(join(root, 'target'), join(project, 'linked'))
  })

  afterAll(() => {
    process.chdir(savedCwd)
    rmSync(root, { recursive: true, force: true })
  })

  afterEach(() => {
    process.chdir(savedCwd)
  })

  const name = (path: string): PathReading => ({ glob: false, path })
  const beneath = (anchor: string, tail: string): PathReading => ({
    glob: true,
    anchor,
    path: anchor + tail,
  })
  const bothKinds = (spelling: string) => ({
    deny: literalReadings(spelling, 'deny'),
    allow: literalReadings(spelling, 'allow'),
  })
  const forBoth = (readings: PathReading[]) => ({
    deny: readings,
    allow: readings,
  })

  it('reads a path inside the folder as the name it spells', () => {
    expect(bothKinds(project)).toEqual(forBoth([name(project)]))
    expect(bothKinds(join(project, 'keep'))).toEqual(
      forBoth([name(join(project, 'keep'))]),
    )
  })

  it('does not ask for what follows the glob characters to exist', () => {
    const notYet = join(project, 'keep', 'not-there-yet')
    expect(bothKinds(notYet)).toEqual(forBoth([name(notYet)]))
  })

  it('reads a pattern beneath the folder as that pattern beneath its name', () => {
    expect(bothKinds(`${project}/**/.env`)).toEqual(
      forBoth([beneath(project, '/**/.env')]),
    )
    expect(bothKinds(`${project}/*.pem`)).toEqual(
      forBoth([beneath(project, '/*.pem')]),
    )
  })

  it('takes the longest run of directories that exists as the anchor', () => {
    expect(bothKinds(`${project}/src/**/.env`)).toEqual(
      forBoth([beneath(join(project, 'src'), '/**/.env')]),
    )
    expect(bothKinds(`${project}/absent/**/.env`)).toEqual(
      forBoth([beneath(project, '/absent/**/.env')]),
    )
  })

  it('reads a wildcard as a name only when a file has that very name', () => {
    expect(bothKinds(join(root, 'star', '*.env'))).toEqual(
      forBoth([name(join(root, 'star', '*.env'))]),
    )
    expect(bothKinds(join(root, 'plain', '*.env'))).toEqual(forBoth([]))
  })

  it('sets a trailing /** aside for the decision and gives it back to a pattern', () => {
    expect(bothKinds(`${project}/**`)).toEqual(forBoth([name(project)]))
    expect(bothKinds(`${project}/keep/**`)).toEqual(
      forBoth([name(join(project, 'keep'))]),
    )
    expect(bothKinds(`${project}/**/build/**`)).toEqual(
      forBoth([beneath(project, '/**/build/**')]),
    )
  })

  it('strips a trailing separator from a name and keeps it in a pattern', () => {
    expect(bothKinds(`${project}/keep/`)).toEqual(
      forBoth([name(join(project, 'keep'))]),
    )
    expect(bothKinds(`${project}/*/`)).toEqual(
      forBoth([beneath(project, '/*/')]),
    )
  })

  it('folds a parent reference in a name', () => {
    expect(bothKinds(`${project}/keep/../src`)).toEqual(
      forBoth([name(join(project, 'src'))]),
    )
  })

  it('leaves a relative name inside a bracketed cwd alone', () => {
    process.chdir(project)
    // No glob character in what the caller wrote: it is a name already, and
    // every backend takes it for one.
    expect(bothKinds('./keep')).toEqual(forBoth([]))
    expect(bothKinds('keep')).toEqual(forBoth([]))
  })

  it('reads a relative pattern inside a bracketed cwd beneath the cwd', () => {
    process.chdir(project)
    expect(bothKinds('**/.env')).toEqual(
      forBoth([beneath(project, '/**/.env')]),
    )
    expect(bothKinds('./*.env')).toEqual(forBoth([beneath(project, '/*.env')]))
    expect(bothKinds('src/**/.env')).toEqual(
      forBoth([beneath(join(project, 'src'), '/**/.env')]),
    )
  })

  it('reads a ~ spelling beneath a home directory with brackets in its name', () => {
    const home = join(root, PROJECT)
    const script = `
      const { literalReadings } = await import(${JSON.stringify(
        join(import.meta.dir, '../../src/sandbox/path-entries.ts'),
      )})
      console.log(JSON.stringify({
        name: literalReadings('~/keep', 'deny'),
        pattern: literalReadings('~/**/.env', 'deny'),
        allow: literalReadings('~/src/*.ts', 'allow'),
      }))`
    const result = spawnSync(process.execPath, ['-e', script], {
      env: { ...process.env, HOME: home },
      encoding: 'utf8',
      timeout: WRAP_TIMEOUT_MS,
    })
    expect(result.status).toBe(0)
    expect(JSON.parse(result.stdout.trim().split('\n').at(-1) ?? '')).toEqual({
      name: [],
      pattern: [beneath(home, '/**/.env')],
      allow: [beneath(join(home, 'src'), '/*.ts')],
    })
  })

  it.each(['open[bracket', 'close]bracket', 'build*', 'notes (draft?)'])(
    'reads a path inside a directory named %p as a name',
    dir => {
      const inside = join(root, dir, 'out')
      expect(bothKinds(inside)).toEqual(forBoth([name(inside)]))
    },
  )

  it('adds nothing for braces, which are no glob characters', () => {
    expect(bothKinds(join(root, 'curly{a,b}', 'out'))).toEqual(forBoth([]))
  })

  it('adds nothing for an entry without glob characters', () => {
    expect(bothKinds(join(root, 'plain', 'a'))).toEqual(forBoth([]))
    expect(bothKinds(join(root, 'absent'))).toEqual(forBoth([]))
  })

  it('adds nothing for a pattern none of which exists as a name', () => {
    expect(bothKinds(join(root, 'plain', '**', '.env'))).toEqual(forBoth([]))
    expect(bothKinds(join(root, '[nope]', 'x'))).toEqual(forBoth([]))
    expect(bothKinds(join(root, 'plain', '[xy]', 'key'))).toEqual(forBoth([]))
  })

  it('reads [ab] as the class and as the directory of that name', () => {
    // The pattern reading, which covers `a` and `b`, is the one every entry
    // has; the name is what this adds.
    const inClass = join(root, 'plain', '[ab]', 'secret')
    expect(bothKinds(inClass)).toEqual(forBoth([name(inClass)]))
  })

  it('gives one reading for each name the entry may hold, the longest first', () => {
    expect(bothKinds(`${project}/[ab]/secret`)).toEqual(
      forBoth([
        name(join(project, '[ab]', 'secret')),
        beneath(project, '/[ab]/secret'),
      ]),
    )
    expect(bothKinds(`${project}/[ab]/**/.env`)).toEqual(
      forBoth([
        beneath(join(project, '[ab]'), '/**/.env'),
        beneath(project, '/[ab]/**/.env'),
      ]),
    )
  })

  it('never turns one reading into another when a directory appears', () => {
    const entry = `${project}/[cd]/**/.env`
    const before = literalReadings(entry, 'deny')
    expect(before).toEqual([beneath(project, '/[cd]/**/.env')])
    mkdirSync(join(project, '[cd]'))
    try {
      const after = literalReadings(entry, 'deny')
      expect(after).toEqual([
        beneath(join(project, '[cd]'), '/**/.env'),
        ...before,
      ])
    } finally {
      rmSync(join(project, '[cd]'), { recursive: true, force: true })
    }
  })

  it('anchors a pattern at the nearest directory when a file is in the way', () => {
    // As beneath any folder: the walk then finds the file where it looked
    // for a directory.
    expect(literalReadings(`${project}/file/**/x`, 'deny')).toEqual([
      beneath(project, '/file/**/x'),
    ])
  })

  describe('a prefix that is a symbolic link', () => {
    it('counts for a deny, which can only deny more', () => {
      const inside = join(root, 'li[n]k', 'keep')
      expect(literalReadings(inside, 'deny')).toEqual([name(inside)])
      expect(literalReadings(`${root}/li[n]k/**/x`, 'deny')).toEqual([
        beneath(join(root, 'li[n]k'), '/**/x'),
      ])
    })

    it('does not count for an allow, which would open what it points at', () => {
      expect(literalReadings(join(root, 'li[n]k', 'keep'), 'allow')).toEqual([])
      expect(literalReadings(join(root, 'li[n]k'), 'allow')).toEqual([])
      expect(literalReadings(`${root}/li[n]k/**/x`, 'allow')).toEqual([])
    })

    it('counts for a deny when it dangles, as a name and not as a directory', () => {
      const dangling = join(root, 'dang[l]ing')
      expect(literalReadings(dangling, 'deny')).toEqual([name(dangling)])
      expect(literalReadings(`${dangling}/**/x`, 'deny')).toEqual([])
      expect(literalReadings(dangling, 'allow')).toEqual([])
      expect(literalReadings(`${dangling}/**/x`, 'allow')).toEqual([])
    })

    it('ends the name of an allow wherever it lies after the glob characters', () => {
      const through = join(project, 'linked', 'keep')
      expect(literalReadings(through, 'deny')).toEqual([name(through)])
      expect(literalReadings(through, 'allow')).toEqual([])
      expect(literalReadings(join(project, 'real', 'keep'), 'allow')).toEqual([
        name(join(project, 'real', 'keep')),
      ])
    })

    it('ends the pattern of an allow when it lies before the first pattern component', () => {
      // The walk starts at the folder followed by `linked`, resolved: it
      // would list what the link points at.
      for (const tail of ['/linked/*/x', '/linked/*', '/real/../linked/**/x']) {
        expect(literalReadings(project + tail, 'allow')).toEqual([])
      }
      expect(literalReadings(`${project}/linked/*/x`, 'deny')).toEqual([
        beneath(join(project, 'linked'), '/*/x'),
      ])
      // Not there yet is no link, and neither is a directory.
      expect(literalReadings(`${project}/absent/sub/*`, 'allow')).toEqual([
        beneath(project, '/absent/sub/*'),
      ])
      expect(literalReadings(`${project}/real/*/x`, 'allow')).toEqual([
        beneath(join(project, 'real'), '/*/x'),
      ])
      // From the first pattern component on, the walk meets the link itself
      // and does not list it.
      expect(literalReadings(`${project}/*/linked/x`, 'allow')).toEqual([
        beneath(project, '/*/linked/x'),
      ])
    })
  })

  it.skipIf(process.getuid?.() === 0)(
    'takes a path it cannot look at as present for a deny and absent for an allow',
    () => {
      const locked = join(root, 'locked')
      const inside = join(locked, '[x]', 'secret')
      mkdirSync(join(locked, '[x]'), { recursive: true })
      chmodSync(locked, 0o000)
      try {
        expect(literalReadings(inside, 'deny')).toEqual([name(inside)])
        expect(literalReadings(inside, 'allow')).toEqual([])
      } finally {
        chmodSync(locked, 0o755)
      }
    },
  )

  describe('a pattern beneath the folder', () => {
    let ordinary: string

    beforeAll(() => {
      ordinary = join(root, 'ordinary')
      for (const base of [project, ordinary]) {
        mkdirSync(join(base, 'deep', 'er'), { recursive: true })
        for (const file of ['a]x', 'deep/a]x', 'deep/er/b]x', 'deep/.env']) {
          writeFileSync(join(base, file), '')
        }
      }
    })

    const found = (base: string, tail: string, kind: 'allow' | 'deny') =>
      literalReadings(base + tail, kind)
        .flatMap(reading =>
          reading.glob
            ? expandGlobPattern(reading.path, { anchor: reading.anchor })
            : [],
        )
        .map(match => match.slice(base.length))
        .sort()

    it.each(['/**/.env', '/deep/*', '/**/er/*', '/*/*]x'])(
      'finds for %p what the same pattern finds beneath an ordinary folder',
      tail => {
        const expected = expandGlobPattern(ordinary + tail)
          .map(match => match.slice(ordinary.length))
          .sort()
        expect(expected.length).toBeGreaterThan(0)
        expect(found(project, tail, 'deny')).toEqual(expected)
        expect(found(project, tail, 'allow')).toEqual(expected)
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
        // pattern against whole paths, and beneath an anchor those are paths
        // from the anchor on.
        expect(
          expandGlobPattern(ordinary + tail)
            .map(match => match.slice(ordinary.length))
            .sort(),
        ).toEqual(expected)
        expect(found(project, tail, 'deny')).toEqual(expected)
        expect(found(project, tail, 'allow')).toEqual(expected)
      },
    )

    it('keeps a trailing separator, with which a pattern matches nothing', () => {
      expect(expandGlobPattern(`${ordinary}/*/`)).toEqual([])
      expect(found(project, '/*/', 'allow')).toEqual([])
      expect(found(project, '/*/', 'deny')).toEqual([])
    })
  })
})

describe('path entries as configured', () => {
  it('tells spellings from marked paths', () => {
    expect(
      splitPathEntries([
        '/a/*.env',
        { path: '/a/*.env', literal: true },
        '/b',
        { path: '~/c', literal: true },
      ]),
    ).toEqual({ spelled: ['/a/*.env', '/b'], marked: ['/a/*.env', '~/c'] })
    expect(splitPathEntries(undefined)).toEqual({ spelled: [], marked: [] })
  })

  it.each([
    ['an object without the mark', { path: '/a' }],
    ['a mark that is not true', { path: '/a', literal: false }],
    ['a mark that is a string', { path: '/a', literal: 'true' }],
    ['a path that is not a string', { path: 1, literal: true }],
    ['an empty path', { path: '', literal: true }],
    ['null', null],
    ['a number', 1],
    ['a list', ['/a']],
  ])('refuses %s rather than guess', (_what, entry) => {
    // initialize() does not run the schema, so this is the only check an
    // embedder's hand-built config meets.
    expect(() =>
      splitPathEntries([entry as unknown as FilesystemPathEntry]),
    ).toThrow(TypeError)
  })

  it('keys a marked path apart from the same spelling, and by value', () => {
    expect(pathEntryKey('/a')).not.toBe(
      pathEntryKey({ path: '/a', literal: true }),
    )
    expect(pathEntryKey({ path: '/a', literal: true })).toBe(
      pathEntryKey(structuredClone({ path: '/a', literal: true as const })),
    )
  })

  it('folds the literal lists into the lists they are more entries of', () => {
    expect(
      readNamesOf({
        denyOnly: ['/d'],
        allowWithinDeny: ['/d/a'],
        unlistableDenyDirs: ['/u'],
        literalDenyOnly: ['/l*'],
        literalAllowWithinDeny: ['/d/l*'],
      }),
    ).toEqual({
      denyOnly: ['/d', '/l*'],
      allowWithinDeny: ['/d/a', '/d/l*'],
      unlistableDenyDirs: ['/u'],
    })
    expect(readNamesOf({ denyOnly: ['/d'] })).toEqual({ denyOnly: ['/d'] })
    expect(
      readNamesOf({ denyOnly: [], literalAllowWithinDeny: ['/a'] }),
    ).toEqual({ denyOnly: [], allowWithinDeny: ['/a'] })
    expect(
      writeNamesOf({
        allowOnly: ['/w'],
        denyWithinAllow: ['/w/d'],
        literalAllowOnly: ['/l*'],
        literalDenyWithinAllow: ['/w/l*'],
      }),
    ).toEqual({ allowOnly: ['/w', '/l*'], denyWithinAllow: ['/w/d', '/w/l*'] })
    expect(readNamesOf(undefined)).toBeUndefined()
    expect(writeNamesOf(undefined)).toBeUndefined()
  })

  it('counts a marked allow among what a write config allows', () => {
    expect(
      writeRootsOf({ allowOnly: ['/w'], literalAllowOnly: ['/l*'] }),
    ).toEqual(['/w', '/l*'])
    expect(writeRootsOf({ allowOnly: ['/w'] })).toEqual(['/w'])
  })
})

// ============================================================================
// Linux: real commands under bubblewrap
// ============================================================================

describe.if(isLinux)(
  'Linux: entries inside a folder named [WIP] project',
  () => {
    const CAN_RUN = bwrapCanNamespace()
    const savedCwd = process.cwd()
    let root: string
    let project: string

    beforeEach(() => {
      root = freshRoot()
      project = join(root, PROJECT)
      mkdirSync(join(project, 'keep'), { recursive: true })
      mkdirSync(join(project, 'real'), { recursive: true })
      mkdirSync(join(project, 'secrets', 'public'), { recursive: true })
      mkdirSync(join(project, 'sub', 'deep'), { recursive: true })
      writeFileSync(join(project, 'keep', 'file'), 'original\n')
      writeFileSync(join(project, 'real', 'file'), 'original\n')
      writeFileSync(join(project, 'secret.txt'), 'SECRET-FILE\n')
      writeFileSync(join(project, 'secrets', 'key'), 'SECRET-DIR\n')
      writeFileSync(join(project, 'secrets', 'public', 'ok'), 'PUBLIC\n')
      writeFileSync(join(project, '.env'), 'ENV-TOP\n')
      writeFileSync(join(project, 'sub', '.env'), 'ENV-SUB\n')
      writeFileSync(join(project, 'sub', 'deep', '.env'), 'ENV-DEEP\n')
      writeFileSync(join(project, 'sub', 'readme'), 'README\n')
      // Outside every allowed path, so the scan for dangerous files in the
      // working directory adds no binds of its own.
      process.chdir(root)
    })

    afterEach(async () => {
      process.chdir(savedCwd)
      SandboxManager.cleanupAfterCommand()
      await SandboxManager.reset()
      rmSync(root, { recursive: true, force: true })
    })

    it.skipIf(!CAN_RUN)(
      'makes the project writable when it is allowed',
      async () => {
        const { stdout } = await sandboxed(
          { allowWrite: [project] },
          `echo hi > ${q(join(project, 'new'))} && echo WROTE`,
          { cwd: root },
        )
        expect(stdout).toContain('WROTE')
        expect(readFileSync(join(project, 'new'), 'utf8')).toBe('hi\n')
      },
      WRAP_TIMEOUT_MS,
    )

    it.skipIf(!CAN_RUN)(
      'enforces a denyWrite inside it',
      async () => {
        const kept = join(project, 'keep', 'file')
        const { stdout } = await sandboxed(
          { allowWrite: [root], denyWrite: [join(project, 'keep')] },
          `echo tampered > ${q(kept)} && echo WROTE; ` +
            `echo fine > ${q(join(project, 'sub', 'other'))} && echo SIBLING`,
          { cwd: root },
        )
        expect(stdout).not.toContain('WROTE')
        expect(stdout).toContain('SIBLING')
        expect(readFileSync(kept, 'utf8')).toBe('original\n')
      },
      WRAP_TIMEOUT_MS,
    )

    it.skipIf(!CAN_RUN)(
      'hides a denyRead file and a denyRead directory inside it',
      async () => {
        const { stdout } = await sandboxed(
          { denyRead: [join(project, 'secret.txt'), join(project, 'secrets')] },
          `cat ${q(join(project, 'secret.txt'))} ${q(join(project, 'secrets', 'key'))}; ` +
            `cat ${q(join(project, 'sub', 'readme'))}`,
          { cwd: root },
        )
        expect(stdout).not.toContain('SECRET-FILE')
        expect(stdout).not.toContain('SECRET-DIR')
        expect(stdout).toContain('README')
      },
      WRAP_TIMEOUT_MS,
    )

    it.skipIf(!CAN_RUN)(
      'opens an allowRead carve-out inside a denied directory',
      async () => {
        const { stdout } = await sandboxed(
          {
            denyRead: [join(project, 'secrets')],
            allowRead: [join(project, 'secrets', 'public')],
          },
          `cat ${q(join(project, 'secrets', 'key'))} ${q(join(project, 'secrets', 'public', 'ok'))}`,
          { cwd: root },
        )
        expect(stdout).not.toContain('SECRET-DIR')
        expect(stdout).toContain('PUBLIC')
      },
      WRAP_TIMEOUT_MS,
    )

    it.skipIf(!CAN_RUN).each(['build*', 'notes (draft?)'])(
      'opens a carve-out inside a folder named %p, whose name a pattern matches as itself',
      async name => {
        // The deny is spelled without a `/**`: with one it is the pattern as
        // well in such a folder, under which every entry beneath the
        // directory keeps a mask of its own.
        const folder = join(root, name)
        mkdirSync(join(folder, 'secrets', 'public'), { recursive: true })
        writeFileSync(join(folder, 'secrets', 'key'), 'SECRET-DIR\n')
        writeFileSync(join(folder, 'secrets', 'public', 'ok'), 'PUBLIC\n')
        const { stdout } = await sandboxed(
          {
            denyRead: [join(folder, 'secrets')],
            allowRead: [join(folder, 'secrets', 'public')],
          },
          `cat ${q(join(folder, 'secrets', 'key'))} ${q(join(folder, 'secrets', 'public', 'ok'))}`,
          { cwd: root },
        )
        expect(stdout).not.toContain('SECRET-DIR')
        expect(stdout).toContain('PUBLIC')
      },
      WRAP_TIMEOUT_MS,
    )

    it.skipIf(!CAN_RUN)(
      'masks .env at every depth for a recursive deny beneath it',
      async () => {
        const { stdout } = await sandboxed(
          { denyRead: [`${project}/**/.env`] },
          `cat ${q(join(project, '.env'))} ${q(join(project, 'sub', '.env'))} ${q(join(project, 'sub', 'deep', '.env'))}; ` +
            `cat ${q(join(project, 'sub', 'readme'))}`,
          { cwd: root },
        )
        expect(stdout).not.toMatch(/ENV-(TOP|SUB|DEEP)/)
        expect(stdout).toContain('README')
      },
      WRAP_TIMEOUT_MS,
    )

    it.skipIf(!CAN_RUN)(
      'masks the same for a relative recursive deny when it is the cwd',
      async () => {
        process.chdir(project)
        const { stdout } = await sandboxed(
          { denyRead: ['**/.env'] },
          `cat .env sub/.env sub/deep/.env; cat sub/readme`,
          { cwd: project },
        )
        expect(stdout).not.toMatch(/ENV-(TOP|SUB|DEEP)/)
        expect(stdout).toContain('README')
      },
      WRAP_TIMEOUT_MS,
    )

    it.skipIf(!CAN_RUN)(
      'applies a deny beneath an allow that is spelled through a parent reference',
      async () => {
        // The allow is recorded where it resolves to. Left as spelled, the
        // deny beneath it would be judged outside every allowed path and
        // skipped.
        const denied = join(project, 'real', 'file')
        const { stdout } = await sandboxed(
          {
            allowWrite: [`${project}/keep/../real`],
            denyWrite: [denied],
          },
          `echo tampered > ${q(denied)} && echo WROTE; ` +
            `echo fine > ${q(join(project, 'real', 'other'))} && echo SIBLING`,
          { cwd: root },
        )
        expect(stdout).not.toContain('WROTE')
        expect(stdout).toContain('SIBLING')
        expect(readFileSync(denied, 'utf8')).toBe('original\n')
      },
      WRAP_TIMEOUT_MS,
    )

    it('keeps the entries in the write config and resolves the read ones', async () => {
      await initialize({
        denyRead: [join(project, 'secret.txt'), `${project}/**/.env`],
        allowRead: [join(project, 'secrets', 'public')],
        allowWrite: [project],
        denyWrite: [join(project, 'keep'), `${project}/**/*.lock`],
      })
      const write = SandboxManager.getFsWriteConfig()
      expect(write.allowOnly).toContain(project)
      // Write lists take no pattern on Linux, beneath this folder or any other.
      expect(write.denyWithinAllow).toEqual([join(project, 'keep')])
      const read = SandboxManager.getFsReadConfig()
      expect(read.denyOnly).toEqual([
        join(project, 'secret.txt'),
        join(project, '.env'),
        join(project, 'sub', '.env'),
        join(project, 'sub', 'deep', '.env'),
      ])
      expect(read.allowWithinDeny).toEqual([join(project, 'secrets', 'public')])
    })

    it('still reports every write entry whose pattern is not applied', async () => {
      // Whether an entry is also a name depends on the disk, which the
      // command can change; what is reported does not.
      await initialize({
        allowWrite: [project, { path: join(root, 'marked*'), literal: true }],
        denyWrite: [join(project, 'keep'), `${project}/**/*.lock`],
        denyRead: [`${project}/**/.env`, { path: '/*/x', literal: true }],
      })
      expect(SandboxManager.getLinuxGlobPatternWarnings()).toEqual([
        project,
        join(project, 'keep'),
        `${project}/**/*.lock`,
      ])
    })

    it.skipIf(!CAN_RUN)(
      'takes the strings a direct caller hands the wrapper as names',
      async () => {
        const kept = join(project, 'keep', 'file')
        const wrapped = await wrapCommandWithSandboxLinux({
          command:
            `echo BOOTED; echo tampered > ${q(kept)} && echo WROTE; ` +
            `cat ${q(join(project, 'secret.txt'))}; ` +
            `echo fine > ${q(join(project, 'new'))} && echo SIBLING`,
          needsNetworkRestriction: false,
          readConfig: { denyOnly: [join(project, 'secret.txt')] },
          writeConfig: {
            allowOnly: [`${project}/`],
            denyWithinAllow: [join(project, 'keep')],
          },
        })
        const result = spawnSync(wrapped, {
          shell: true,
          encoding: 'utf8',
          cwd: root,
          timeout: RUN_TIMEOUT_MS,
        })
        expect(result.stdout).toContain('BOOTED')
        expect(result.stdout).not.toContain('WROTE')
        expect(result.stdout).not.toContain('SECRET-FILE')
        expect(result.stdout).toContain('SIBLING')
        expect(readFileSync(kept, 'utf8')).toBe('original\n')
      },
      WRAP_TIMEOUT_MS,
    )

    it.skipIf(!CAN_RUN).each([
      ['*/../keep', 'keep/file'],
      ['[ab]/..', 'secret.txt'],
    ])(
      'makes nothing writable for a direct caller that spells %p, which is not there',
      async (tail, target) => {
        // Nothing beneath the project is named `*` or `[ab]`. Resolved as a
        // name the string loses the component with its parent reference, and
        // what is left names a directory that is there.
        const kept = join(project, target)
        const before = readFileSync(kept, 'utf8')
        const wrapped = await wrapCommandWithSandboxLinux({
          command: `echo BOOTED; echo tampered > ${q(kept)} && echo WROTE; echo END`,
          needsNetworkRestriction: false,
          readConfig: { denyOnly: [] },
          writeConfig: {
            allowOnly: [`${project}/${tail}`],
            denyWithinAllow: [],
          },
        })
        const result = spawnSync(wrapped, {
          shell: true,
          encoding: 'utf8',
          cwd: root,
          timeout: RUN_TIMEOUT_MS,
        })
        expect(result.stdout).toContain('BOOTED')
        expect(result.stdout).not.toContain('WROTE')
        expect(result.stdout).toContain('END')
        expect(readFileSync(kept, 'utf8')).toBe(before)
      },
      WRAP_TIMEOUT_MS,
    )

    it.skipIf(!CAN_RUN)(
      'makes a path writable that is spelled through a folder that is not there, as beneath any folder',
      async () => {
        // The project's own name holds the glob characters and exists, so the
        // string is the name of a path; a name is resolved, parent reference
        // and all.
        const { stdout } = await sandboxed(
          { allowWrite: [`${project}/absent/../real`] },
          `echo hi > ${q(join(project, 'real', 'new'))} && echo WROTE; ` +
            `echo hi > ${q(join(project, 'keep', 'new'))} && echo ESCAPED`,
          { cwd: root },
        )
        expect(stdout).toContain('WROTE')
        expect(stdout).not.toContain('ESCAPED')
      },
      WRAP_TIMEOUT_MS,
    )
  },
)

/**
 * What exists is looked at when a command is wrapped, and an earlier command
 * may have put it there. A deny takes every reading that may hold, so
 * nothing the command creates can switch one off. An allow takes the path
 * only as itself: a link with the name an entry spells is not the path.
 */
describe.if(isLinux)(
  'Linux: what a command can change before the next wrap',
  () => {
    const CAN_RUN = bwrapCanNamespace()
    const savedCwd = process.cwd()
    let root: string
    let work: string
    let vault: string

    beforeEach(() => {
      root = freshRoot()
      work = join(root, 'work')
      vault = join(root, 'vault')
      mkdirSync(join(work, 'proj', 'pub'), { recursive: true })
      mkdirSync(join(vault, 'pub'), { recursive: true })
      mkdirSync(join(vault, 'deep', 'pub'), { recursive: true })
      writeFileSync(join(work, 'proj', 'pub', 'ok'), 'PROJECT-PUBLIC\n')
      writeFileSync(join(vault, 'pub', 'key'), 'VAULT-SECRET\n')
      writeFileSync(join(vault, 'deep', 'pub', 'key'), 'VAULT-DEEP-SECRET\n')
      process.chdir(root)
    })

    afterEach(async () => {
      process.chdir(savedCwd)
      SandboxManager.cleanupAfterCommand()
      await SandboxManager.reset()
      rmSync(root, { recursive: true, force: true })
    })

    const readVault = (): string =>
      `cat ${q(join(vault, 'pub', 'key'))} ${q(join(vault, 'deep', 'pub', 'key'))} 2>/dev/null; echo END`

    it.skipIf(!CAN_RUN).each([
      ['work/*/pub', '*'],
      ['work/*/**/pub', '*'],
      ['work/[ab]/pub', '[ab]'],
      ['work/?/pub', '?'],
    ])(
      'does not open a denied directory through a link named like %p spells it',
      async (entry, linkName) => {
        const policy = {
          denyRead: [vault],
          allowRead: [join(root, entry)],
          allowWrite: [work],
        }
        // The command may write `work`, so it can plant the link itself.
        const planted = await sandboxed(
          policy,
          `ln -s ${q(vault)} ${q(join(work, linkName))} && echo PLANTED`,
          { cwd: root },
        )
        expect(planted.stdout).toContain('PLANTED')
        await initialize(policy)
        const allowed = SandboxManager.getFsReadConfig().allowWithinDeny ?? []
        expect(allowed.filter(p => p.includes(linkName))).toEqual([])
        const { stdout } = await sandboxed(policy, readVault(), { cwd: root })
        expect(stdout).not.toContain('SECRET')
        expect(stdout).toContain('END')
      },
      WRAP_TIMEOUT_MS,
    )

    it.skipIf(!CAN_RUN)(
      'does not open one through a link further along the path either',
      async () => {
        const policy = {
          denyRead: [vault],
          allowRead: [join(work, '[ab]', 'mid', 'pub')],
          allowWrite: [work],
        }
        const planted = await sandboxed(
          policy,
          `mkdir ${q(join(work, '[ab]'))} && ln -s ${q(vault)} ${q(join(work, '[ab]', 'mid'))} && echo PLANTED`,
          { cwd: root },
        )
        expect(planted.stdout).toContain('PLANTED')
        const { stdout } = await sandboxed(policy, readVault(), { cwd: root })
        expect(stdout).not.toContain('SECRET')
      },
      WRAP_TIMEOUT_MS,
    )

    it.skipIf(!CAN_RUN).each([
      ['[ab]/mid/*/pub', '[ab]', 'mid'],
      ['[ab]/mid/**/key', '[ab]', 'mid'],
      ['*/dist/*', '*', 'dist'],
    ])(
      'does not open a denied directory through a link that a pattern spelled %p starts beneath',
      async (entry, dirName, linkName) => {
        // The directory is one the command made, with the name the entry
        // spells, and the link inside it is what the pattern would be walked
        // from.
        const policy = {
          denyRead: [vault],
          allowRead: [join(work, entry)],
          allowWrite: [work],
        }
        const planted = await sandboxed(
          policy,
          `mkdir ${q(join(work, dirName))} && ln -s ${q(vault)} ${q(join(work, dirName, linkName))} && echo PLANTED`,
          { cwd: root },
        )
        expect(planted.stdout).toContain('PLANTED')
        await initialize(policy)
        expect(SandboxManager.getFsReadConfig().allowWithinDeny).toEqual([])
        const { stdout } = await sandboxed(policy, readVault(), { cwd: root })
        expect(stdout).not.toContain('SECRET')
        expect(stdout).toContain('END')
      },
      WRAP_TIMEOUT_MS,
    )

    it.skipIf(!CAN_RUN)(
      'hides a file for a read deny spelled through a link with glob characters in its name',
      async () => {
        // For a deny a link of that name counts: the entry names the file,
        // by whichever of its names the command asks for it.
        const target = join(root, 'target')
        mkdirSync(target)
        writeFileSync(join(target, 'token'), 'THROUGH-LINK\n')
        symlinkSync(target, join(root, 'li[n]k'))
        const entry = join(root, 'li[n]k', 'token')
        const policy = { denyRead: [entry] }
        await initialize(policy)
        expect(SandboxManager.getFsReadConfig().denyOnly).toEqual([entry])
        const { stdout } = await sandboxed(
          policy,
          `cat ${q(entry)} ${q(join(target, 'token'))} 2>/dev/null; echo END`,
          { cwd: root },
        )
        expect(stdout).not.toContain('THROUGH-LINK')
        expect(stdout).toContain('END')
      },
      WRAP_TIMEOUT_MS,
    )

    it('adds no name for a write allow spelled through a link with glob characters in its name', async () => {
      symlinkSync(vault, join(work, '[ab]'))
      await initialize({
        allowWrite: [join(work, '[ab]', 'pub'), join(work, '[ab]')],
      })
      expect(
        SandboxManager.getFsWriteConfig().allowOnly.filter(p =>
          p.startsWith(root),
        ),
      ).toEqual([])
    })

    it.skipIf(!CAN_RUN)(
      'keeps a class deny in force when a directory with the name of the class appears',
      async () => {
        const bracketed = join(root, PROJECT)
        mkdirSync(join(bracketed, 'a'), { recursive: true })
        writeFileSync(join(bracketed, 'a', '.env'), 'ENV-A\n')
        const policy = {
          denyRead: [`${bracketed}/[ab]/**/.env`],
          allowWrite: [bracketed],
        }
        const read = `cat ${q(join(bracketed, 'a', '.env'))} ${q(join(bracketed, '[ab]', '.env'))} 2>/dev/null; echo END`
        expect(
          (await sandboxed(policy, read, { cwd: root })).stdout,
        ).not.toContain('ENV-')
        const made = await sandboxed(
          policy,
          `mkdir ${q(join(bracketed, '[ab]'))} && echo ENV-LITERAL > ${q(join(bracketed, '[ab]', '.env'))} && echo MADE`,
          { cwd: root },
        )
        expect(made.stdout).toContain('MADE')
        expect(
          (await sandboxed(policy, read, { cwd: root })).stdout,
        ).not.toContain('ENV-')
      },
      WRAP_TIMEOUT_MS,
    )

    it.skipIf(!CAN_RUN || process.getuid?.() === 0)(
      'keeps a write deny in force when the folder cannot be looked at',
      async () => {
        const locked = join(root, 'locked')
        const kept = join(locked, PROJECT, 'keep')
        mkdirSync(kept, { recursive: true })
        writeFileSync(join(kept, 'file'), 'original\n')
        chmodSync(locked, 0o000)
        try {
          // The command runs as the same user, so it can undo the chmod.
          const { stdout } = await sandboxed(
            { allowWrite: [root], denyWrite: [kept] },
            `chmod 755 ${q(locked)}; echo tampered > ${q(join(kept, 'file'))} && echo WROTE; echo END`,
            { cwd: root },
          )
          expect(stdout).not.toContain('WROTE')
          expect(stdout).toContain('END')
        } finally {
          chmodSync(locked, 0o755)
        }
        expect(readFileSync(join(kept, 'file'), 'utf8')).toBe('original\n')
      },
      WRAP_TIMEOUT_MS,
    )

    it.skipIf(!CAN_RUN || process.getuid?.() === 0)(
      'takes any write deny with glob characters for the path it spells when the folder cannot be looked at',
      async () => {
        // Whether anything in the folder has the name cannot be told, so an
        // ordinary pattern is taken for a path as well, and is applied like
        // a path that is not there: the name is kept from being created, and
        // what the pattern would match is no more denied than anywhere else.
        const locked = join(root, 'locked')
        mkdirSync(locked)
        writeFileSync(join(locked, 'a.pem'), 'original\n')
        const wrapsWith = async (
          name: string,
        ): Promise<{ denied: string[]; stdout: string }> => {
          const policy = {
            allowWrite: [root],
            denyWrite: [join(locked, name)],
          }
          chmodSync(locked, 0o000)
          try {
            await initialize(policy)
            const denied = SandboxManager.getFsWriteConfig().denyWithinAllow
            const { stdout } = await sandboxed(
              policy,
              `chmod 755 ${q(locked)}; echo x > ${q(join(locked, name))} && echo CREATED; ` +
                `echo t >> ${q(join(locked, 'a.pem'))} && echo WROTE; echo END`,
              { cwd: root },
            )
            return { denied, stdout }
          } finally {
            chmodSync(locked, 0o755)
          }
        }
        const leftBy = async (name: string): Promise<string[]> => {
          const policy = {
            allowWrite: [root],
            denyWrite: [join(locked, name)],
          }
          chmodSync(locked, 0o000)
          try {
            await sandboxed(policy, 'echo RAN', { cwd: root })
          } finally {
            chmodSync(locked, 0o755)
          }
          const left = readdirSync(locked).filter(entry => entry !== 'a.pem')
          for (const entry of left) {
            rmSync(join(locked, entry), { recursive: true, force: true })
          }
          return left
        }

        for (const name of ['absent', '*.pem']) {
          const { denied, stdout } = await wrapsWith(name)
          expect(denied).toEqual([join(locked, name)])
          expect(stdout).not.toContain('CREATED')
          expect(stdout).toContain('WROTE')
          expect(stdout).toContain('END')
          expect(existsSync(join(locked, name))).toBe(false)
        }
        // The folder cannot be cleaned by the host while it cannot be looked
        // at, for a name and for a pattern alike.
        const leftByName = await leftBy('absent')
        expect(await leftBy('*.pem')).toEqual(
          leftByName.map(entry => (entry === 'absent' ? '*.pem' : entry)),
        )
      },
      WRAP_TIMEOUT_MS,
    )
  },
)

// ============================================================================
// macOS: the generated profile
// ============================================================================

describe.if(!isWindows)(
  'macOS profile: entries inside a folder named [WIP] project',
  () => {
    let root: string
    let project: string

    beforeAll(() => {
      root = freshRoot()
      project = join(root, PROJECT)
      mkdirSync(join(project, 'keep'), { recursive: true })
      mkdirSync(join(project, 'secrets', 'public'), { recursive: true })
      mkdirSync(join(project, 'sub'), { recursive: true })
      writeFileSync(join(project, 'secret.txt'), '')
      writeFileSync(join(project, '.env'), '')
    })

    afterAll(() => {
      rmSync(root, { recursive: true, force: true })
    })

    it('allows writes to the project by subpath', () => {
      const profile = macProfile(undefined, {
        allowOnly: [project],
        denyWithinAllow: [],
      })
      const allow = ruleOf(profile, '(allow file-write*')
      expect(allow).toContain(subpath(project))
      // The pattern reading is still there, as for any entry.
      expect(allow).toContain(patternFilter(project, 'allow'))
    })

    it('denies a write inside it by subpath, and pins the folder', () => {
      const kept = join(project, 'keep')
      const profile = macProfile(undefined, {
        allowOnly: [root],
        denyWithinAllow: [kept],
      })
      expect(ruleOf(profile, '(deny file-write*')).toContain(subpath(kept))
      const pinned = ruleOf(
        profile,
        '(deny file-write-unlink file-write-create',
      )
      expect(pinned).toContain(subpath(kept))
      expect(pinned).toContain(literalFilter(project))
      expect(profile).toContain(patternFilter(kept, 'deny'))
    })

    it('denies a read of a file and of a directory inside it by subpath', () => {
      const file = join(project, 'secret.txt')
      const dir = join(project, 'secrets')
      const profile = macProfile({ denyOnly: [file, dir] }, undefined)
      const deny = ruleOf(profile, '(deny file-read*')
      expect(deny).toContain(subpath(file))
      expect(deny).toContain(subpath(dir))
      expect(deny).toContain(patternFilter(file, 'deny'))
    })

    it('re-allows a carve-out inside a denied directory by subpath', () => {
      const dir = join(project, 'secrets')
      const open = join(dir, 'public')
      const profile = macProfile(
        { denyOnly: [dir], allowWithinDeny: [open] },
        undefined,
      )
      expect(ruleOf(profile, '(allow file-read*\n')).toContain(subpath(open))
      // A deny nested in an allow lands again after it; here the allow is the
      // nested one, so the deny is not repeated by name.
      const denies = profile.split('(deny file-read*\n')
      expect(denies[1]).toContain(subpath(dir))
    })

    it('denies a recursive pattern beneath it with the folder escaped', () => {
      const profile = macProfile(
        { denyOnly: [`${project}/**/.env`] },
        undefined,
      )
      const anchored = `^${escapedForRegex(project)}/(.*/)?\\.env(/.*)?$`
      expect(profile).toContain(`(regex ${JSON.stringify(anchored)})`)
      expect(profile).toContain(patternFilter(`${project}/**/.env`, 'deny'))
      const regexes = emittedRegexes(profile)
      for (const denied of [
        '.env',
        'sub/.env',
        'sub/deep/.env',
        '.env/inside',
      ]) {
        expect(regexes.some(re => re.test(join(project, denied)))).toBe(true)
      }
      expect(regexes.some(re => re.test(join(project, 'sub', 'readme')))).toBe(
        false,
      )
      expect(
        ruleOf(profile, '(deny file-write-unlink file-write-create'),
      ).toContain(literalFilter(project))
    })

    it('takes the project as a write root for the rules that keep denied paths in place', () => {
      const profile = macProfile(
        { denyOnly: [join(project, 'secrets')] },
        { allowOnly: [project], denyWithinAllow: [] },
      )
      expect(
        ruleOf(profile, '(allow file-write-unlink file-write-create'),
      ).toContain(subpath(project))
      const tail = profile.slice(
        profile.indexOf('keep read-denied paths inside write roots in place'),
      )
      expect(tail).toContain(subpath(join(project, 'secrets')))
    })

    it('adds no reading for a link with the name an allow spells', () => {
      const work = join(root, 'work')
      mkdirSync(join(root, 'vault', 'pub'), { recursive: true })
      mkdirSync(work, { recursive: true })
      symlinkSync(join(root, 'vault'), join(work, '[ab]'))
      const entry = join(work, '[ab]', 'pub')
      const asAllow = macProfile(
        { denyOnly: [join(root, 'vault')], allowWithinDeny: [entry] },
        { allowOnly: [entry], denyWithinAllow: [] },
      )
      expect(emittedSubpaths(asAllow)).not.toContain(entry)
      expect(emittedSubpaths(asAllow)).not.toContain(join(root, 'vault', 'pub'))
      const asDeny = macProfile({ denyOnly: [entry] }, undefined)
      expect(ruleOf(asDeny, '(deny file-read*')).toContain(subpath(entry))
      const asWriteDeny = macProfile(undefined, {
        allowOnly: [root],
        denyWithinAllow: [entry],
      })
      expect(ruleOf(asWriteDeny, '(deny file-write*')).toContain(subpath(entry))
    })

    it('compiles an entry as before when none of it is a name on disk', () => {
      const profile = macProfile(
        { denyOnly: ['/srv/[ab]/secrets', '/srv/**/.env'] },
        { allowOnly: ['/srv/build*'], denyWithinAllow: ['/srv/*.lock'] },
      )
      expect(
        emittedSubpaths(profile).filter(p => p.startsWith('/srv')),
      ).toEqual([])
    })
  },
)

// ============================================================================
// Both readings are both
// ============================================================================

describe.if(!isWindows)('an entry that is a pattern and a name', () => {
  const CAN_RUN = isLinux && bwrapCanNamespace()
  const savedCwd = process.cwd()
  let root: string
  let entry: string
  const dirs = ['[ab]', 'a', 'b', 'c']

  beforeAll(() => {
    root = freshRoot()
    entry = join(root, '[ab]', 'secret')
    for (const dir of dirs) {
      mkdirSync(join(root, dir), { recursive: true })
      writeFileSync(join(root, dir, 'secret'), `SECRET-${dir}\n`)
    }
    process.chdir(root)
  })

  afterAll(async () => {
    process.chdir(savedCwd)
    await SandboxManager.reset()
    rmSync(root, { recursive: true, force: true })
  })

  it.if(isLinux)(
    'resolves to the class matches and to the name on Linux',
    async () => {
      await initialize({ denyRead: [entry] })
      expect(SandboxManager.getFsReadConfig().denyOnly.sort()).toEqual(
        ['[ab]', 'a', 'b'].map(dir => join(root, dir, 'secret')).sort(),
      )
    },
  )

  it.if(isLinux)(
    'lists a path once that the pattern and the name both give',
    async () => {
      const starred = join(root, 'c', '*')
      writeFileSync(starred, '')
      try {
        await initialize({ denyRead: [starred], allowRead: [starred] })
        const read = SandboxManager.getFsReadConfig()
        const both = [join(root, 'c', '*'), join(root, 'c', 'secret')].sort()
        expect([...read.denyOnly].sort()).toEqual(both)
        expect([...(read.allowWithinDeny ?? [])].sort()).toEqual(both)
      } finally {
        rmSync(starred)
      }
    },
  )

  it.skipIf(!CAN_RUN)(
    'denies all three under bubblewrap',
    async () => {
      const { stdout } = await sandboxed(
        { denyRead: [entry] },
        dirs.map(dir => `cat ${q(join(root, dir, 'secret'))}`).join('; '),
        { cwd: root },
      )
      expect(stdout).not.toMatch(/SECRET-(\[ab\]|a|b)\n/)
      expect(stdout).toContain('SECRET-c')
    },
    WRAP_TIMEOUT_MS,
  )

  it('covers all three in the macOS profile', () => {
    const profile = macProfile({ denyOnly: [entry] }, undefined)
    const deny = ruleOf(profile, '(deny file-read*')
    const regexes = emittedRegexes(deny)
    const subpaths = emittedSubpaths(deny)
    const covered = (p: string): boolean =>
      regexes.some(re => re.test(p)) ||
      subpaths.some(s => p === s || p.startsWith(s + '/'))
    for (const dir of ['[ab]', 'a', 'b']) {
      expect(covered(join(root, dir, 'secret'))).toBe(true)
    }
    expect(covered(join(root, 'c', 'secret'))).toBe(false)
  })
})

// ============================================================================
// Entries with no such name on disk: nothing changes
// ============================================================================

/**
 * Ordinary entries and ordinary patterns, under a root that does not exist.
 * The expectations are what the code gave for them before an entry could
 * have a second reading; they must stay what they are, byte for byte. That
 * goes for every entry none of whose glob characters can be part of a name
 * on disk. Beneath a directory that cannot be looked at they can, for all
 * anyone can tell, and there a deny is also the path it spells: see "takes
 * any write deny with glob characters for the path it spells" above.
 */
describe.if(!isWindows)(
  'entries none of which is a name with glob characters',
  () => {
    const ROOT = '/srt-literal-path-entries'
    const lists = {
      denyRead: [
        `${ROOT}/secrets`,
        `${ROOT}/home/.ssh/**`,
        `${ROOT}/proj/**/.env`,
        `${ROOT}/proj/*.pem`,
        `${ROOT}/proj/[ab]/key`,
        `${ROOT}/proj/file?.txt`,
        `${ROOT}/proj/**/build/**`,
      ],
      allowRead: [
        `${ROOT}/secrets/public`,
        `${ROOT}/proj/**/public`,
        `${ROOT}/home/.ssh/known_hosts`,
      ],
      allowWrite: [
        `${ROOT}/proj`,
        `${ROOT}/out/**`,
        `${ROOT}/build/*`,
        `${ROOT}/cache/[0-9]`,
      ],
      denyWrite: [
        `${ROOT}/proj/.git`,
        `${ROOT}/proj/**/node_modules`,
        `${ROOT}/proj/locked/**`,
        `${ROOT}/proj/?.lock`,
      ],
    }
    const savedCwd = process.cwd()

    beforeAll(() => {
      // The built-in write denies are spelled from the working directory and
      // its ancestors. From the root they are the same on every host.
      process.chdir('/')
    })

    afterAll(async () => {
      process.chdir(savedCwd)
      await SandboxManager.reset()
    })

    it.if(isLinux)(
      'gives the read and write config it gave before',
      async () => {
        await initialize(lists)
        const read = SandboxManager.getFsReadConfig()
        expect(read.denyOnly).toEqual([
          '/srt-literal-path-entries/secrets',
          '/srt-literal-path-entries/home/.ssh',
        ])
        expect(read.allowWithinDeny).toEqual([
          '/srt-literal-path-entries/secrets/public',
          '/srt-literal-path-entries/home/.ssh/known_hosts',
        ])
        expect(read.unlistableDenyDirs).toEqual([])
        expect(Object.keys(read).sort()).toEqual([
          'allowWithinDeny',
          'denyOnly',
          'unlistableDenyDirs',
        ])

        const write = SandboxManager.getFsWriteConfig()
        expect(write.allowOnly).toEqual([
          ...getDefaultWritePaths(),
          '/srt-literal-path-entries/proj',
          '/srt-literal-path-entries/out',
        ])
        expect(write.denyWithinAllow).toEqual([
          '/srt-literal-path-entries/proj/.git',
          '/srt-literal-path-entries/proj/locked',
        ])
        expect('literalAllowOnly' in write).toBe(false)
        // Absent or empty: the two mean the same for this list.
        expect(write.literalDenyWithinAllow ?? []).toEqual([])

        expect(SandboxManager.getLinuxGlobPatternWarnings()).toEqual([
          '/srt-literal-path-entries/build/*',
          '/srt-literal-path-entries/cache/[0-9]',
          '/srt-literal-path-entries/proj/**/node_modules',
          '/srt-literal-path-entries/proj/?.lock',
        ])
      },
    )

    it('gives the macOS file rules it gave before', () => {
      const wrapped = macProfile(
        { denyOnly: lists.denyRead, allowWithinDeny: lists.allowRead },
        { allowOnly: lists.allowWrite, denyWithinAllow: lists.denyWrite },
      )
      expect(fileRulesOf(wrapped)).toBe(EXPECTED_MACOS_FILE_RULES)
    })
  },
)

/**
 * The file rules of the profile inside a wrapped command, with the log tag,
 * which differs from one process to the next, replaced.
 */
function fileRulesOf(wrapped: string): string {
  const from = wrapped.indexOf('; File read')
  const to = wrapped.indexOf("' ", from)
  return wrapped.slice(from, to).replace(/CMD64_.*?_SBX/g, '<tag>')
}

const EXPECTED_MACOS_FILE_RULES = String.raw`; File read
(allow file-read*)
(deny file-read*
  (subpath "/srt-literal-path-entries/secrets")
  (regex "^/srt-literal-path-entries/home/\\.ssh/.*(/.*)?$")
  (regex "^/srt-literal-path-entries/proj/(.*/)?\\.env(/.*)?$")
  (regex "^/srt-literal-path-entries/proj/[^/]*\\.pem(/.*)?$")
  (regex "^/srt-literal-path-entries/proj/[ab]/key(/.*)?$")
  (regex "^/srt-literal-path-entries/proj/file[^/]\\.txt(/.*)?$")
  (regex "^/srt-literal-path-entries/proj/(.*/)?build/.*(/.*)?$")
  (with message "<tag>"))
(allow file-read*
  (subpath "/srt-literal-path-entries/secrets/public")
  (regex "^/srt-literal-path-entries/proj/(.*/)?public$")
  (subpath "/srt-literal-path-entries/home/.ssh/known_hosts")
  (with message "<tag>"))
(deny file-read*
  (require-all (regex "^/srt-literal-path-entries/home/\\.ssh/.*(/.*)?$") (require-not (subpath "/srt-literal-path-entries/home/.ssh/known_hosts")))
  (regex "^/srt-literal-path-entries/proj/(.*/)?\\.env(/.*)?$")
  (regex "^/srt-literal-path-entries/proj/[^/]*\\.pem(/.*)?$")
  (regex "^/srt-literal-path-entries/proj/[ab]/key(/.*)?$")
  (regex "^/srt-literal-path-entries/proj/file[^/]\\.txt(/.*)?$")
  (regex "^/srt-literal-path-entries/proj/(.*/)?build/.*(/.*)?$")
  (with message "<tag>"))
(allow file-read-metadata
  (vnode-type DIRECTORY))
(deny file-write-unlink file-write-create
  (subpath "/srt-literal-path-entries/secrets")
  (literal "/srt-literal-path-entries")
  (regex "^/srt-literal-path-entries/home/\\.ssh/.*(/.*)?$")
  (literal "/srt-literal-path-entries/home/.ssh")
  (literal "/srt-literal-path-entries/home")
  (regex "^/srt-literal-path-entries/proj/(.*/)?\\.env(/.*)?$")
  (literal "/srt-literal-path-entries/proj")
  (regex "^/srt-literal-path-entries/proj/[^/]*\\.pem(/.*)?$")
  (regex "^/srt-literal-path-entries/proj/[ab]/key(/.*)?$")
  (regex "^/srt-literal-path-entries/proj/file[^/]\\.txt(/.*)?$")
  (regex "^/srt-literal-path-entries/proj/(.*/)?build/.*(/.*)?$")
  (with message "<tag>"))
(allow file-write-unlink file-write-create
  (subpath "/srt-literal-path-entries/proj")
  (regex "^/srt-literal-path-entries/out/.*$")
  (regex "^/srt-literal-path-entries/build/[^/]*$")
  (regex "^/srt-literal-path-entries/cache/[0-9]$")
  (with message "<tag>"))

; File write
(allow file-write*
  (subpath "/srt-literal-path-entries/proj")
  (regex "^/srt-literal-path-entries/out/.*$")
  (regex "^/srt-literal-path-entries/build/[^/]*$")
  (regex "^/srt-literal-path-entries/cache/[0-9]$")
  (with message "<tag>"))
(deny file-write*
  (subpath "/srt-literal-path-entries/proj/.git")
  (regex "^/srt-literal-path-entries/proj/(.*/)?node_modules(/.*)?$")
  (regex "^/srt-literal-path-entries/proj/locked/.*(/.*)?$")
  (regex "^/srt-literal-path-entries/proj/[^/]\\.lock(/.*)?$")
  (subpath "/.gitconfig")
  (regex "^/(.*/)?\\.gitconfig(/.*)?$")
  (subpath "/.gitmodules")
  (regex "^/(.*/)?\\.gitmodules(/.*)?$")
  (subpath "/.bashrc")
  (regex "^/(.*/)?\\.bashrc(/.*)?$")
  (subpath "/.bash_profile")
  (regex "^/(.*/)?\\.bash_profile(/.*)?$")
  (subpath "/.zshrc")
  (regex "^/(.*/)?\\.zshrc(/.*)?$")
  (subpath "/.zprofile")
  (regex "^/(.*/)?\\.zprofile(/.*)?$")
  (subpath "/.profile")
  (regex "^/(.*/)?\\.profile(/.*)?$")
  (subpath "/.ripgreprc")
  (regex "^/(.*/)?\\.ripgreprc(/.*)?$")
  (subpath "/.mcp.json")
  (regex "^/(.*/)?\\.mcp\\.json(/.*)?$")
  (subpath "/.vscode")
  (regex "^/(.*/)?\\.vscode/.*(/.*)?$")
  (subpath "/.idea")
  (regex "^/(.*/)?\\.idea/.*(/.*)?$")
  (subpath "/.claude/commands")
  (regex "^/(.*/)?\\.claude/commands/.*(/.*)?$")
  (subpath "/.claude/agents")
  (regex "^/(.*/)?\\.claude/agents/.*(/.*)?$")
  (subpath "/.git/hooks")
  (regex "^/(.*/)?\\.git/hooks/.*(/.*)?$")
  (subpath "/.git/config")
  (regex "^/(.*/)?\\.git/config(/.*)?$")
  (with message "<tag>"))
(deny file-write-unlink file-write-create
  (subpath "/srt-literal-path-entries/proj/.git")
  (literal "/srt-literal-path-entries/proj")
  (literal "/srt-literal-path-entries")
  (regex "^/srt-literal-path-entries/proj/(.*/)?node_modules(/.*)?$")
  (regex "^/srt-literal-path-entries/proj/locked/.*(/.*)?$")
  (literal "/srt-literal-path-entries/proj/locked")
  (regex "^/srt-literal-path-entries/proj/[^/]\\.lock(/.*)?$")
  (subpath "/.gitconfig")
  (regex "^/(.*/)?\\.gitconfig(/.*)?$")
  (subpath "/.gitmodules")
  (regex "^/(.*/)?\\.gitmodules(/.*)?$")
  (subpath "/.bashrc")
  (regex "^/(.*/)?\\.bashrc(/.*)?$")
  (subpath "/.bash_profile")
  (regex "^/(.*/)?\\.bash_profile(/.*)?$")
  (subpath "/.zshrc")
  (regex "^/(.*/)?\\.zshrc(/.*)?$")
  (subpath "/.zprofile")
  (regex "^/(.*/)?\\.zprofile(/.*)?$")
  (subpath "/.profile")
  (regex "^/(.*/)?\\.profile(/.*)?$")
  (subpath "/.ripgreprc")
  (regex "^/(.*/)?\\.ripgreprc(/.*)?$")
  (subpath "/.mcp.json")
  (regex "^/(.*/)?\\.mcp\\.json(/.*)?$")
  (subpath "/.vscode")
  (regex "^/(.*/)?\\.vscode/.*(/.*)?$")
  (subpath "/.idea")
  (regex "^/(.*/)?\\.idea/.*(/.*)?$")
  (subpath "/.claude/commands")
  (literal "/.claude")
  (regex "^/(.*/)?\\.claude/commands/.*(/.*)?$")
  (subpath "/.claude/agents")
  (regex "^/(.*/)?\\.claude/agents/.*(/.*)?$")
  (subpath "/.git/hooks")
  (literal "/.git")
  (regex "^/(.*/)?\\.git/hooks/.*(/.*)?$")
  (subpath "/.git/config")
  (regex "^/(.*/)?\\.git/config(/.*)?$")
  (with message "<tag>"))

; File read: keep read-denied paths inside write roots in place
(deny file-write-unlink
  (require-all (regex "^/srt-literal-path-entries/home/\\.ssh/.*(/.*)?$") (require-not (subpath "/srt-literal-path-entries/home/.ssh/known_hosts")))
  (regex "^/srt-literal-path-entries/proj/(.*/)?\\.env(/.*)?$")
  (regex "^/srt-literal-path-entries/proj/[^/]*\\.pem(/.*)?$")
  (regex "^/srt-literal-path-entries/proj/[ab]/key(/.*)?$")
  (regex "^/srt-literal-path-entries/proj/file[^/]\\.txt(/.*)?$")
  (regex "^/srt-literal-path-entries/proj/(.*/)?build/.*(/.*)?$")
  (with message "<tag>"))`

// ============================================================================
// The marker
// ============================================================================

describe.if(!isWindows)('an entry marked literal', () => {
  const CAN_RUN = isLinux && bwrapCanNamespace()
  const savedCwd = process.cwd()
  let root: string
  let dir: string
  let starred: string

  beforeEach(() => {
    root = freshRoot()
    dir = join(root, 'x')
    starred = join(dir, '*.env')
    mkdirSync(dir, { recursive: true })
    writeFileSync(join(dir, 'a.env'), 'ENV-A\n')
    process.chdir(root)
  })

  afterEach(async () => {
    process.chdir(savedCwd)
    SandboxManager.cleanupAfterCommand()
    await SandboxManager.reset()
    rmSync(root, { recursive: true, force: true })
  })

  const marked = (path: string): FilesystemPathEntry => ({
    path,
    literal: true,
  })

  it('travels in the literal lists, as spelled, and is never expanded', async () => {
    await initialize({
      denyRead: [marked(starred), marked('~/x/[y]')],
      allowRead: [marked(join(dir, 'a?'))],
      allowWrite: [marked(join(root, 'out*')), root],
      denyWrite: [marked(join(root, 'keep/**'))],
    })
    const read = SandboxManager.getFsReadConfig()
    expect(read.denyOnly).toEqual([])
    expect(read.allowWithinDeny).toEqual([])
    expect(read.literalDenyOnly).toEqual([starred, '~/x/[y]'])
    expect(read.literalAllowWithinDeny).toEqual([join(dir, 'a?')])
    const write = SandboxManager.getFsWriteConfig()
    expect(write.allowOnly).toEqual([...getDefaultWritePaths(), root])
    expect(write.literalAllowOnly).toEqual([join(root, 'out*')])
    expect(write.denyWithinAllow).toEqual([])
    // A `/**` at the end of a marked path is part of the name.
    expect(write.literalDenyWithinAllow).toEqual([join(root, 'keep/**')])
    if (isLinux)
      expect(SandboxManager.getLinuxGlobPatternWarnings()).toEqual([])
  })

  it.skipIf(!CAN_RUN)(
    'denies the file of that name and not what the pattern would match',
    async () => {
      const read = `cat ${q(join(dir, 'a.env'))}; cat ${q(starred)} 2>/dev/null; echo END`
      const before = await sandboxed({ denyRead: [marked(starred)] }, read, {
        cwd: root,
      })
      expect(before.stdout).toContain('ENV-A')
      writeFileSync(starred, 'ENV-STAR\n')
      const after = await sandboxed({ denyRead: [marked(starred)] }, read, {
        cwd: root,
      })
      expect(after.stdout).toContain('ENV-A')
      expect(after.stdout).not.toContain('ENV-STAR')
    },
    WRAP_TIMEOUT_MS,
  )

  it('compiles to a subpath and to no regex in the macOS profile', () => {
    const profile = wrapCommandWithSandboxMacOS({
      command: 'true',
      needsNetworkRestriction: false,
      readConfig: {
        denyOnly: [],
        literalDenyOnly: [starred],
        literalAllowWithinDeny: [join(dir, 'a?')],
      },
      writeConfig: {
        allowOnly: [],
        denyWithinAllow: [],
        literalAllowOnly: [join(root, 'out*')],
        literalDenyWithinAllow: [join(root, 'keep[1]')],
      },
    })
    expect(ruleOf(profile, '(deny file-read*')).toContain(subpath(starred))
    expect(ruleOf(profile, '(allow file-read*\n')).toContain(
      subpath(join(dir, 'a?')),
    )
    expect(ruleOf(profile, '(allow file-write*')).toContain(
      subpath(join(root, 'out*')),
    )
    expect(ruleOf(profile, '(deny file-write*')).toContain(
      subpath(join(root, 'keep[1]')),
    )
    // What the characters of each path would match as a pattern is matched
    // by no regex of the profile.
    const regexes = emittedRegexes(profile)
    for (const matched of [
      join(dir, 'a.env'),
      join(dir, 'ab'),
      join(root, 'outX'),
      join(root, 'keep1'),
    ]) {
      expect(regexes.some(re => re.test(matched))).toBe(false)
    }
  })

  it('is a read restriction on its own in the macOS profile', () => {
    const wrapped = wrapCommandWithSandboxMacOS({
      command: 'true',
      needsNetworkRestriction: false,
      readConfig: { denyOnly: [], literalDenyOnly: [starred] },
      writeConfig: undefined,
    })
    expect(wrapped).toContain(subpath(starred))
  })

  it.skipIf(!CAN_RUN)(
    'is a read restriction on its own for the Linux wrapper',
    async () => {
      writeFileSync(starred, 'ENV-STAR\n')
      const wrapped = await wrapCommandWithSandboxLinux({
        command: `cat ${q(starred)} ${q(join(dir, 'a.env'))}`,
        needsNetworkRestriction: false,
        readConfig: { denyOnly: [], literalDenyOnly: [starred] },
        writeConfig: undefined,
      })
      const result = spawnSync(wrapped, {
        shell: true,
        encoding: 'utf8',
        cwd: root,
        timeout: RUN_TIMEOUT_MS,
      })
      expect(result.stdout).toContain('ENV-A')
      expect(result.stdout).not.toContain('ENV-STAR')
    },
    WRAP_TIMEOUT_MS,
  )

  it.skipIf(!CAN_RUN)(
    'makes a marked path writable, and a marked path inside it read-only',
    async () => {
      const out = join(root, 'out*')
      mkdirSync(join(out, 'keep[1]'), { recursive: true })
      writeFileSync(join(out, 'keep[1]', 'file'), 'original\n')
      mkdirSync(join(root, 'outside'))
      const { stdout } = await sandboxed(
        {
          allowWrite: [marked(out)],
          denyWrite: [marked(join(out, 'keep[1]'))],
        },
        `echo hi > ${q(join(out, 'new'))} && echo WROTE; ` +
          `echo tampered > ${q(join(out, 'keep[1]', 'file'))} && echo TAMPERED; ` +
          `echo hi > ${q(join(root, 'outside', 'new'))} && echo ESCAPED`,
        { cwd: root },
      )
      expect(stdout).toContain('WROTE')
      expect(stdout).not.toContain('TAMPERED')
      expect(stdout).not.toContain('ESCAPED')
      expect(readFileSync(join(out, 'keep[1]', 'file'), 'utf8')).toBe(
        'original\n',
      )
    },
    WRAP_TIMEOUT_MS,
  )

  it.skipIf(!CAN_RUN)(
    'denies a write to a path that is not there yet, in a folder that is not there yet',
    async () => {
      // An absent deny path gets a placeholder at its first missing
      // component, which keeps the command from creating it; the placeholder
      // is removed from the host once the command is done.
      const folder = join(root, '[new]')
      const secret = join(folder, 'secret')
      const { stdout } = await sandboxed(
        { allowWrite: [root], denyWrite: [marked(secret)] },
        `mkdir -p ${q(folder)} 2>/dev/null; echo x > ${q(secret)} && echo CREATED; ` +
          `echo fine > ${q(join(root, 'other'))} && echo SIBLING`,
        { cwd: root, keepMountPoints: true },
      )
      expect(stdout).not.toContain('CREATED')
      expect(stdout).toContain('SIBLING')
      expect(existsSync(secret)).toBe(false)
      SandboxManager.cleanupAfterCommand()
      expect(existsSync(folder)).toBe(false)
    },
    WRAP_TIMEOUT_MS,
  )

  it.skipIf(!CAN_RUN)(
    'denies a read of a path that is not there yet from the wrap after it appears',
    async () => {
      // Nothing is mounted for a read deny whose path is absent, marked or
      // not: there is nothing to hide. The path is looked at again for the
      // next command.
      const late = join(root, '[late]', 'secret')
      const policy = { denyRead: [marked(late)] }
      const read = `cat ${q(late)} 2>/dev/null; echo END`
      expect((await sandboxed(policy, read, { cwd: root })).stdout).toContain(
        'END',
      )
      mkdirSync(join(root, '[late]'))
      writeFileSync(late, 'LATE-SECRET\n')
      const { stdout } = await sandboxed(policy, read, { cwd: root })
      expect(stdout).not.toContain('LATE-SECRET')
    },
    WRAP_TIMEOUT_MS,
  )

  it.skipIf(!CAN_RUN)(
    'keeps the masks of a deny pattern beneath a marked allow',
    async () => {
      // The matches of a deny pattern are collapsed: one that a directory
      // match above it already hides gets no mount of its own, unless a path
      // that is bound back over that directory lies between the two. A
      // marked allow is bound back like any other, so the match beneath it
      // has to keep its mask.
      const vault = join(root, 'tree', 'vault.key')
      const open = join(vault, 'open[1]')
      mkdirSync(open, { recursive: true })
      writeFileSync(join(vault, 'top'), 'TOP\n')
      writeFileSync(join(open, 'ok'), 'OPEN\n')
      writeFileSync(join(open, 'inner.key'), 'INNER\n')
      const { stdout } = await sandboxed(
        {
          denyRead: [`${root}/tree/**/*.key`],
          allowRead: [marked(open)],
        },
        `cat ${q(join(vault, 'top'))} ${q(join(open, 'inner.key'))} 2>/dev/null; ` +
          `cat ${q(join(open, 'ok'))}`,
        { cwd: root },
      )
      expect(stdout).not.toContain('TOP')
      expect(stdout).not.toContain('INNER')
      expect(stdout).toContain('OPEN')
    },
    WRAP_TIMEOUT_MS,
  )

  it.skipIf(!CAN_RUN)(
    'keeps them beneath a marked write allow too',
    async () => {
      const vault = join(root, 'tree', 'vault.key')
      const out = join(vault, 'out[1]')
      mkdirSync(out, { recursive: true })
      writeFileSync(join(vault, 'top'), 'TOP\n')
      writeFileSync(join(out, 'inner.key'), 'INNER\n')
      const { stdout } = await sandboxed(
        {
          denyRead: [`${root}/tree/**/*.key`],
          allowWrite: [marked(out)],
        },
        `cat ${q(join(vault, 'top'))} ${q(join(out, 'inner.key'))} 2>/dev/null; ` +
          `echo hi > ${q(join(out, 'new'))} && echo WROTE`,
        { cwd: root },
      )
      expect(stdout).not.toContain('TOP')
      expect(stdout).not.toContain('INNER')
      expect(stdout).toContain('WROTE')
    },
    WRAP_TIMEOUT_MS,
  )

  it.skipIf(!CAN_RUN)(
    'reaches the wrap from a per-command config',
    async () => {
      writeFileSync(starred, 'ENV-STAR\n')
      const { stdout } = await sandboxed(
        {},
        `cat ${q(join(dir, 'a.env'))}; cat ${q(starred)} 2>/dev/null; echo END`,
        { cwd: root, perWrap: { denyRead: [marked(starred)] } },
      )
      expect(stdout).toContain('ENV-A')
      expect(stdout).not.toContain('ENV-STAR')
    },
    WRAP_TIMEOUT_MS,
  )

  it.skipIf(!CAN_RUN)(
    'reaches the wrap from a per-command config in each of the four lists',
    async () => {
      const out = join(root, 'out*')
      const kept = join(out, 'keep[1]', 'file')
      const secrets = join(root, 'secrets?')
      const open = join(secrets, 'open[1]')
      mkdirSync(join(out, 'keep[1]'), { recursive: true })
      mkdirSync(open, { recursive: true })
      writeFileSync(kept, 'original\n')
      writeFileSync(join(secrets, 'key'), 'SECRET\n')
      writeFileSync(join(open, 'ok'), 'OPEN\n')
      const { stdout } = await sandboxed(
        {},
        `echo hi > ${q(join(out, 'new'))} && echo WROTE; ` +
          `echo tampered > ${q(kept)} && echo TAMPERED; ` +
          `cat ${q(join(secrets, 'key'))} ${q(join(open, 'ok'))} 2>/dev/null; echo END`,
        {
          cwd: root,
          perWrap: {
            denyRead: [marked(secrets)],
            allowRead: [marked(open)],
            allowWrite: [marked(out)],
            denyWrite: [marked(join(out, 'keep[1]'))],
          },
        },
      )
      expect(stdout).toContain('WROTE')
      expect(stdout).not.toContain('TAMPERED')
      expect(stdout).not.toContain('SECRET')
      expect(stdout).toContain('OPEN')
      expect(stdout).toContain('END')
      expect(readFileSync(kept, 'utf8')).toBe('original\n')
    },
    WRAP_TIMEOUT_MS,
  )

  it.if(isLinux)(
    'is in the lists the violation monitor judges a write by',
    async () => {
      const out = join(root, 'out*')
      const kept = join(out, 'keep[1]')
      mkdirSync(kept, { recursive: true })
      let handedOver: LinuxViolationMonitorOptions | undefined
      const spy = spyOn(
        linuxViolationMonitorModule,
        'startLinuxSandboxViolationMonitor',
      ).mockImplementation((_callback, opts) => {
        handedOver = opts
        return {
          observeSocketPath: undefined,
          ready: Promise.resolve(),
          stop: () => {},
        }
      })
      try {
        await SandboxManager.reset()
        await SandboxManager.initialize(
          {
            network: noNetwork,
            filesystem: {
              denyRead: [],
              allowWrite: [marked(out)],
              denyWrite: [marked(kept)],
            },
          },
          undefined,
          true,
        )
      } finally {
        spy.mockRestore()
      }
      expect(handedOver?.allowWritePaths).toContain(out)
      expect(handedOver?.denyWritePaths).toContain(kept)

      // The listener itself, with what the manager handed over: a write the
      // sandbox permits is no violation, and one it refuses is.
      const lines: string[] = []
      const monitor = startLinuxSandboxViolationMonitor(
        violation => lines.push(violation.line),
        handedOver!,
      )
      await monitor.ready
      try {
        await new Promise<void>((resolve, reject) => {
          const client = connect(monitor.observeSocketPath!, () => {
            client.write(
              [join(out, 'new'), join(kept, 'file')]
                .map(path => JSON.stringify({ syscall: 'openat', path }))
                .join('\n') + '\n',
            )
            client.end()
          })
          client.on('close', () => resolve())
          client.on('error', reject)
        })
        await new Promise(resolve => setTimeout(resolve, 50))
        expect(lines).toEqual([`deny openat ${join(kept, 'file')}`])
      } finally {
        monitor.stop()
      }
    },
    WRAP_TIMEOUT_MS,
  )

  it('comes back from getConfig() and updateConfig() as it went in', async () => {
    const filesystem = {
      denyRead: [marked(starred), join(dir, 'plain')],
      allowRead: [marked(join(dir, 'a?'))],
      allowWrite: [marked(join(root, 'out*'))],
      denyWrite: [marked(join(root, 'keep[1]'))],
    }
    await initialize(filesystem)
    expect(SandboxManager.getConfig()?.filesystem).toEqual(filesystem)
    const updated = {
      ...filesystem,
      denyRead: [marked(join(dir, '[later]'))],
    }
    SandboxManager.updateConfig({ network: noNetwork, filesystem: updated })
    expect(SandboxManager.getConfig()?.filesystem).toEqual(updated)
    expect(SandboxManager.getFsReadConfig().literalDenyOnly).toEqual([
      join(dir, '[later]'),
    ])
  })

  it('comes back from a settings file and from a control line as it went in', () => {
    const config = {
      network: noNetwork,
      filesystem: {
        denyRead: [marked(starred), '/plain/*.pem'],
        allowRead: [marked('~/a?')],
        allowWrite: [marked('./out*')],
        denyWrite: [marked(join(root, 'keep[1]/'))],
      },
    }
    const file = join(root, 'settings.json')
    writeFileSync(file, JSON.stringify(config))
    const loaded = loadConfig(file)
    expect(loaded.kind).toBe('ok')
    expect(loaded.kind === 'ok' && loaded.config.filesystem).toEqual(
      config.filesystem,
    )
    expect(loadConfigFromString(JSON.stringify(config))?.filesystem).toEqual(
      config.filesystem,
    )
  })

  it('is refused by a settings file when the mark is not the mark', () => {
    const file = join(root, 'settings.json')
    writeFileSync(
      file,
      JSON.stringify({
        network: noNetwork,
        filesystem: {
          denyRead: [{ path: starred, literal: false }],
          allowWrite: [],
          denyWrite: [],
        },
      }),
    )
    const loaded = loadConfig(file)
    expect(loaded.kind).toBe('invalid')
    expect(loaded.kind === 'invalid' && loaded.reason).toContain(
      'filesystem.denyRead.0: Expected a path, or { "path": "<path>", "literal": true }',
    )
  })

  it('is refused at the wrap when a config that skipped the schema holds half a mark', async () => {
    await initialize({
      denyRead: [{ path: starred } as unknown as FilesystemPathEntry],
    })
    const refusal = 'must be a path, or { path, literal: true }'
    expect(() => SandboxManager.getFsReadConfig()).toThrow(refusal)
    expect(() => SandboxManager.getFsWriteConfig()).toThrow(refusal)
    // eslint-disable-next-line @typescript-eslint/await-thenable -- bun:test types .rejects.toThrow() as void; the await is required at runtime
    await expect(SandboxManager.wrapWithSandbox('true')).rejects.toThrow(
      refusal,
    )
  })
})

describe.if(!isWindows)(
  'default write paths under read rules with a name in them',
  () => {
    const script = (body: string): string => `
    const { getDefaultWritePaths } = await import(${JSON.stringify(
      join(import.meta.dir, '../../src/sandbox/sandbox-utils.ts'),
    )})
    const { SandboxManager } = await import(${JSON.stringify(
      join(import.meta.dir, '../../src/sandbox/sandbox-manager.ts'),
    )})
    const kept = paths => paths.filter(p => p.endsWith('/debug') || p.endsWith('/_logs')).map(p => p.split('/').slice(-2).join('/'))
    ${body}`

    function under(home: string, body: string): unknown {
      const result = spawnSync(process.execPath, ['-e', script(body)], {
        env: { ...process.env, HOME: home },
        encoding: 'utf8',
        timeout: WRAP_TIMEOUT_MS,
      })
      if (result.status !== 0) throw new Error(result.stderr)
      return JSON.parse(result.stdout.trim().split('\n').at(-1) ?? '')
    }

    let root: string

    beforeAll(() => {
      root = freshRoot()
      for (const home of ['home', '[home]']) {
        mkdirSync(join(root, home, '.claude', 'debug'), { recursive: true })
        mkdirSync(join(root, home, '.npm', '_logs'), { recursive: true })
      }
    })

    afterAll(() => {
      rmSync(root, { recursive: true, force: true })
    })

    it('drops a directory a marked deny covers and keeps one a marked allow re-opens', () => {
      expect(
        under(
          join(root, 'home'),
          `console.log(JSON.stringify({
          denied: kept(getDefaultWritePaths({ denyRead: [{ path: '~/.claude', literal: true }] })),
          reopened: kept(getDefaultWritePaths({
            denyRead: [{ path: '~/.claude', literal: true }],
            allowRead: [{ path: '~/.claude/debug', literal: true }],
          })),
          asPattern: kept(getDefaultWritePaths({ denyRead: [{ path: '~/.c*', literal: true }] })),
        }))`,
        ),
      ).toEqual({
        denied: ['.npm/_logs'],
        reopened: ['.npm/_logs', '.claude/debug'],
        asPattern: ['.npm/_logs', '.claude/debug'],
      })
    })

    it('counts a deny spelled inside a home directory with brackets in its name', () => {
      const home = join(root, '[home]')
      expect(
        under(
          home,
          `const config = filesystem => ({ network: { allowedDomains: [], deniedDomains: [] }, filesystem: { allowWrite: [], denyWrite: [], ...filesystem } })
        await SandboxManager.initialize(config({ denyRead: [${JSON.stringify(join(home, '.claude'))}] }), undefined, false)
        const denied = kept(SandboxManager.getFsWriteConfig().allowOnly)
        await SandboxManager.reset()
        await SandboxManager.initialize(config({
          denyRead: [${JSON.stringify(join(home, '.claude'))}],
          allowRead: [${JSON.stringify(join(home, '.claude', 'debug'))}],
        }), undefined, false)
        const reopened = kept(SandboxManager.getFsWriteConfig().allowOnly)
        await SandboxManager.reset()
        console.log(JSON.stringify({ denied, reopened }))
        process.exit(0)`,
        ),
      ).toEqual({
        denied: ['.npm/_logs'],
        reopened: ['.npm/_logs', '.claude/debug'],
      })
    })
  },
)
