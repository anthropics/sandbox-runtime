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
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
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
  readNamesOf,
  samePathEntries,
  splitPathEntries,
  writeNamesOf,
  writeRootsOf,
} from '../../src/sandbox/path-entries.js'
import type { FilesystemPathEntry } from '../../src/sandbox/sandbox-config.js'
import { getDefaultWritePaths } from '../../src/sandbox/sandbox-utils.js'
import {
  loadConfig,
  loadConfigFromString,
} from '../../src/utils/config-loader.js'
import { bwrapCanNamespace } from '../helpers/bwrap-namespace.js'
import { isLinux, isWindows } from '../helpers/platform.js'

/**
 * Entries marked `{ path, literal: true }`, and what the Linux wrapper does
 * with a name that holds `*`, `?`, `[` or `]`: see
 * src/sandbox/path-entries.ts.
 *
 * The Linux suites run real commands under bubblewrap. The macOS suites read
 * the generated profile on any POSIX host; none runs it under sandbox-exec.
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

const subpath = (p: string): string => `(subpath ${JSON.stringify(p)})`

function emittedRegexes(profile: string): RegExp[] {
  return [...profile.matchAll(/\(regex ("(?:[^"\\]|\\.)*")\)/g)].map(
    match => new RegExp(JSON.parse(match[1]!) as string),
  )
}

/** The rule of `profile` that starts with `head`, up to its closing line. */
function ruleOf(profile: string, head: string): string {
  const start = profile.indexOf(head)
  if (start < 0) return ''
  const end = profile.indexOf('(with message', start)
  return profile.slice(start, end)
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
    // initialize() runs no schema: this is a hand-built config's only check.
    expect(() =>
      splitPathEntries([entry as unknown as FilesystemPathEntry]),
    ).toThrow(TypeError)
  })

  it('tells a marked path from the same spelling, and compares by value', () => {
    const marked = { path: '/a', literal: true as const }
    expect(samePathEntries(['/a'], [marked])).toBe(false)
    // updateConfig() clones the config, so the same entry is a new object.
    expect(
      samePathEntries(['/b', marked], [structuredClone(marked), '/b']),
    ).toBe(true)
    expect(samePathEntries([marked], [marked, marked])).toBe(false)
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
// Linux: the mounts the wrapper asks for
// ============================================================================

/**
 * bubblewrap takes no patterns, so every path the wrapper is handed is a
 * name, and a name is resolved: a trailing separator or `/.` dropped, a
 * parent reference folded. Read as a pattern again, a name with glob
 * characters keeps its spelling, and each case below loses its mount.
 */
describe.if(isLinux)(
  'Linux wrapper: a name with glob characters, however it is spelled',
  () => {
    let root: string
    let project: string
    let sub: string
    let file: string

    beforeAll(() => {
      root = freshRoot()
      project = join(root, PROJECT)
      sub = join(project, 'sub')
      file = join(sub, 'file')
      mkdirSync(join(sub, 'in'), { recursive: true })
      writeFileSync(file, '')
    })

    afterAll(() => {
      rmSync(root, { recursive: true, force: true })
    })

    type Wrap = Parameters<typeof wrapCommandWithSandboxLinux>[0]
    const mounts = (
      readConfig: Wrap['readConfig'],
      writeConfig: Wrap['writeConfig'],
    ): Promise<string> =>
      wrapCommandWithSandboxLinux({
        command: 'true',
        needsNetworkRestriction: false,
        readConfig,
        writeConfig,
      })
    const mount = (flag: string, source: string, dest = source): string =>
      `${flag} ${q(source)} ${q(dest)}`

    it.each([
      ['a trailing /.', (p: string) => `${p}/.`],
      ['a trailing separator', (p: string) => `${p}/`],
    ])(
      'binds an allowRead path back under its own name, spelled with %s',
      async (_how, spell) => {
        for (const path of [sub, file]) {
          const command = await mounts(
            { denyOnly: [project], allowWithinDeny: [spell(path)] },
            undefined,
          )
          expect(command).toContain(mount('--ro-bind', path))
        }
      },
    )

    it.each([
      ['a trailing separator', (p: string) => `${p}/`],
      ['a trailing /.', (p: string) => `${p}/.`],
      [
        'a folder that is not there',
        (p: string) => p.replace('/sub', '/absent/../sub'),
      ],
    ])('masks a denyRead file spelled with %s', async (_how, spell) => {
      const command = await mounts({ denyOnly: [spell(file)] }, undefined)
      expect(command).toContain(`--ro-bind /dev/null ${q(file)}`)
    })

    it('takes a denyRead that leads to the root for the root', async () => {
      const allowWithinDeny = ['/usr', '/etc', '/bin', '/lib', '/lib64']
      const up = '/..'.repeat(project.split('/').length)
      const tmpfsMounts = (command: string): string[] =>
        [...command.matchAll(/--tmpfs (\S+)/g)].map(match => match[1]!)
      const forRoot = tmpfsMounts(
        await mounts({ denyOnly: ['/'], allowWithinDeny }, undefined),
      )
      expect(forRoot.length).toBeGreaterThan(1)
      expect(
        tmpfsMounts(
          await mounts(
            { denyOnly: [project + up], allowWithinDeny },
            undefined,
          ),
        ),
      ).toEqual(forRoot)
    })

    it('applies a denyWrite beneath an allowOnly path spelled through a parent reference', async () => {
      // The allow is recorded where it resolves to: left as spelled, the
      // deny beneath it would be judged outside every allowed path.
      const command = await mounts(undefined, {
        allowOnly: [`${sub}/in/..`],
        denyWithinAllow: [file],
      })
      expect(command).toContain(mount('--bind', sub))
      expect(command).toContain(mount('--ro-bind', file))
    })

    it.each([
      ['a trailing separator', (p: string) => `${p}/`],
      ['a parent reference', (p: string) => p.replace('/sub', '/sub/in/..')],
    ])(
      'binds a denyWrite beneath a denied directory once, spelled with %s',
      async (_how, spell) => {
        // The directory's own read-only bind covers it, as it does for a path
        // without glob characters.
        const command = await mounts(undefined, {
          allowOnly: [root],
          denyWithinAllow: [project, spell(sub)],
        })
        expect(command).toContain(mount('--ro-bind', project))
        expect(command).not.toContain(mount('--ro-bind', sub))
      },
    )

    it('needs no placeholder beneath a denied directory spelled through a read-denied one', async () => {
      // The directory is recorded where it resolves to. By its spelling the
      // read deny on `hidden` would seem to cover it, and the placeholder
      // kept for that reason cannot be created beneath a read-only bind.
      const hidden = join(project, 'hidden')
      mkdirSync(hidden, { recursive: true })
      const absent = join(sub, 'absent')
      const command = await mounts(
        { denyOnly: [hidden] },
        {
          allowOnly: [root],
          denyWithinAllow: [`${hidden}/../sub`, absent],
        },
      )
      expect(command).toContain(mount('--ro-bind', sub))
      expect(command).not.toContain(`--ro-bind /dev/null ${q(absent)}`)
    })
  },
)

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
      writeFileSync(join(project, 'keep', 'file'), 'original\n')
      writeFileSync(join(project, 'secret.txt'), 'SECRET-FILE\n')
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
        // Nothing is named `*` or `[ab]`. Resolved as a name, the string would
        // lose that component to its parent reference and name what is there.
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
  },
)

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
    // No regex of the profile matches what a path would match as a pattern.
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
      // component, which is removed from the host once the command is done.
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
      // not; the path is looked at again for the next command.
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
      // A match of a deny pattern that a directory match above it already
      // hides gets no mount of its own, unless a path bound back over that
      // directory lies between the two. A marked allow is one such path.
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
      mkdirSync(join(root, 'home', '.claude', 'debug'), { recursive: true })
      mkdirSync(join(root, 'home', '.npm', '_logs'), { recursive: true })
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
  },
)
