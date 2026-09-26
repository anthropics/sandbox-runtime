import { describe, it, expect, beforeAll, afterAll, spyOn } from 'bun:test'
// The namespace the library binds, so a spy on it is seen by the code under
// test.
import * as sandboxUtils from '../../src/sandbox/sandbox-utils.js'
import {
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { spawnSync } from 'node:child_process'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { expandReadDenyGlobLinux } from '../../src/sandbox/read-deny-glob.js'
import {
  GLOB_WALK_MAX_ENTRIES,
  GLOB_WALK_TIMEOUT_MS,
  GlobWalkBudgetError,
  newGlobWalkBudget,
  walkGlobPattern,
} from '../../src/sandbox/sandbox-utils.js'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import { LinuxSandboxProfileError } from '../../src/sandbox/linux-sandbox-utils.js'
import { isLinux, isWindows } from '../helpers/platform.js'
import { bwrapCanNamespace } from '../helpers/bwrap-namespace.js'
import { countMounts } from '../helpers/bwrap-argv.js'

/**
 * `root/start/next -> ../pool/d1`, `pool/d1/next -> ../d2` and so on, each
 * `pool/d<i>` holding a `.env`: `links` directories that nothing but the link
 * before them leads to from `start`.
 */
function plantChain(root: string, links: number): void {
  mkdirSync(join(root, 'start'), { recursive: true })
  mkdirSync(join(root, 'pool'))
  symlinkSync(join('..', 'pool', 'd1'), join(root, 'start', 'next'))
  for (let i = 1; i <= links; i++) {
    mkdirSync(join(root, 'pool', `d${i}`))
    writeFileSync(join(root, 'pool', `d${i}`, '.env'), '')
    if (i < links) {
      symlinkSync(join('..', `d${i + 1}`), join(root, 'pool', `d${i}`, 'next'))
    }
  }
}

/** What `fn` throws, or undefined when it returns. */
function thrownBy(fn: () => unknown): unknown {
  try {
    fn()
  } catch (error) {
    return error
  }
  return undefined
}

describe.if(!isWindows)(
  'a read-deny glob and a link to a directory beside the project',
  () => {
    // project/out -> ../outside, and outside/deep/.env: `project/**/.env`
    // matches the file as project/out/deep/.env, and no other name for it
    // lies under the project.
    let ROOT: string
    let project: string
    let secret: string
    const hasBwrap = isLinux && bwrapCanNamespace()

    beforeAll(() => {
      ROOT = realpathSync(mkdtempSync(join(tmpdir(), 'deny-glob-beside-')))
      project = join(ROOT, 'project')
      secret = join(ROOT, 'outside', 'deep', '.env')
      mkdirSync(project)
      mkdirSync(join(ROOT, 'outside', 'deep'), { recursive: true })
      writeFileSync(join(project, '.env'), 'INSIDE\n')
      writeFileSync(secret, 'SECRET\n')
      writeFileSync(join(ROOT, 'outside', 'deep', 'notes.txt'), 'NOTES\n')
      symlinkSync(join('..', 'outside'), join(project, 'out'))
    })

    afterAll(async () => {
      await SandboxManager.reset()
      rmSync(ROOT, { recursive: true, force: true })
    })

    it('denies a match behind the link, where it really is', () => {
      expect(expandReadDenyGlobLinux(join(project, '**/.env'), [])).toEqual([
        secret,
        join(project, '.env'),
      ])
    })

    it.skipIf(!hasBwrap)(
      'hides the match from the sandbox under both names',
      async () => {
        // BOOTED first: a sandbox that refuses to start prints nothing, which
        // would read as every file hidden.
        const result = spawnSync(
          await SandboxManager.wrapWithSandbox(
            [
              'echo BOOTED',
              `cat ${join(project, 'out', 'deep', '.env')} 2>/dev/null || echo HIDDEN`,
              `cat ${secret} 2>/dev/null || echo HIDDEN`,
              `cat ${join(project, 'out', 'deep', 'notes.txt')}`,
            ].join('; '),
            undefined,
            {
              filesystem: {
                denyRead: [join(project, '**/.env')],
                allowWrite: [],
                denyWrite: [],
              },
            },
          ),
          { shell: true, encoding: 'utf8', timeout: 15000 },
        )

        expect(result.stderr ?? '').not.toContain('bwrap:')
        expect(result.stdout.trim().split('\n')).toEqual([
          'BOOTED',
          'HIDDEN',
          'HIDDEN',
          'NOTES',
        ])
      },
    )
  },
)

describe.if(!isWindows)('the budget of a glob walk', () => {
  let ROOT: string
  /** Twelve directories of four files, one of them a match: 60 entries. */
  let TREE: string
  let TREE_ENTRIES: number

  function plantTree(name: string): string {
    const tree = join(ROOT, name)
    for (let d = 0; d < 12; d++) {
      mkdirSync(join(tree, `d${d}`), { recursive: true })
      for (const f of ['.env', 'a', 'b', 'c']) {
        writeFileSync(join(tree, `d${d}`, f), '')
      }
    }
    return tree
  }

  beforeAll(() => {
    ROOT = realpathSync(mkdtempSync(join(tmpdir(), 'deny-glob-budget-')))
    TREE = plantTree('tree')
    TREE_ENTRIES = walkGlobPattern(join(TREE, '**/.env')).entriesExamined
  })

  afterAll(() => {
    rmSync(ROOT, { recursive: true, force: true })
  })

  it('defaults to two million entries and ten seconds', () => {
    expect(GLOB_WALK_MAX_ENTRIES).toBe(2_000_000)
    expect(GLOB_WALK_TIMEOUT_MS).toBe(10_000)
    const budget = newGlobWalkBudget()
    expect(budget.maxEntries).toBe(2_000_000)
    // Rounded: the deadline is a clock reading plus ten seconds, and a
    // floating-point sum less the reading need not be ten seconds exactly.
    expect(Math.round(budget.deadline - budget.startedAt)).toBe(10_000)
    expect(budget.entries).toBe(0)
  })

  it('counts every entry it looks at, with or without a budget', () => {
    expect(TREE_ENTRIES).toBe(12 + 12 * 4)
    const budget = newGlobWalkBudget()
    const walk = walkGlobPattern(join(TREE, '**/.env'), { budget })
    expect(walk.entriesExamined).toBe(TREE_ENTRIES)
    expect(walk.directoriesListed).toBe(13)
    expect(budget.entries).toBe(TREE_ENTRIES)
  })

  it('throws when the tree holds more entries than the budget, and hands nothing back', () => {
    const pattern = join(TREE, '**/.env')
    // Exactly enough is enough.
    expect(
      expandReadDenyGlobLinux(pattern, [], undefined, {
        budget: newGlobWalkBudget({ maxEntries: TREE_ENTRIES }),
      }),
    ).toHaveLength(12)

    const budget = newGlobWalkBudget({ maxEntries: TREE_ENTRIES - 1 })
    let mounts: string[] | undefined
    const error = thrownBy(() => {
      mounts = expandReadDenyGlobLinux(pattern, [], undefined, { budget })
    })

    expect(mounts).toBeUndefined()
    expect(error).toBeInstanceOf(GlobWalkBudgetError)
    const budgetError = error as GlobWalkBudgetError
    expect(budgetError.exhausted).toBe('entries')
    expect(budgetError.pattern).toBe(pattern)
    // The directory it was in when the count ran out, which is one of the
    // tree's own.
    expect(budgetError.directory.startsWith(TREE + '/')).toBe(true)
    expect(budgetError.entries).toBe(TREE_ENTRIES)
    expect(budgetError.maxEntries).toBe(TREE_ENTRIES - 1)
    expect(budgetError.elapsedMs).toBeGreaterThanOrEqual(0)
    expect(budgetError.message).toContain(pattern)
    expect(budgetError.message).toContain(budgetError.directory)
    // The walk itself throws the same, whoever calls it.
    expect(() =>
      walkGlobPattern(pattern, {
        budget: newGlobWalkBudget({ maxEntries: 5 }),
      }),
    ).toThrow(GlobWalkBudgetError)
  })

  it('throws when the deadline has passed before it starts', () => {
    const pattern = join(TREE, '**/.env')
    let mounts: string[] | undefined
    const error = thrownBy(() => {
      mounts = expandReadDenyGlobLinux(pattern, [], undefined, {
        budget: newGlobWalkBudget({ timeoutMs: 0 }),
      })
    })

    expect(mounts).toBeUndefined()
    expect(error).toBeInstanceOf(GlobWalkBudgetError)
    const budgetError = error as GlobWalkBudgetError
    expect(budgetError.exhausted).toBe('time')
    expect(budgetError.pattern).toBe(pattern)
    expect(budgetError.directory).toBe(TREE)
    expect(budgetError.entries).toBe(0)
    expect(budgetError.timeoutMs).toBe(0)
  })

  it('throws when the deadline passes while it walks', () => {
    // A clock that moves a second each time it is read, and the walk reads
    // it before each listing and at each entry. The budget is made at 1 s;
    // the tree and its twelve entries take the readings up to 14 s, and each
    // of the first two directories beneath it five more, up to 24 s. The
    // next reading, before the third is listed, is past the deadline.
    let now = 0
    const clock = spyOn(performance, 'now').mockImplementation(
      () => (now += 1000),
    )
    try {
      const pattern = join(TREE, '**/.env')
      const budget = newGlobWalkBudget({ timeoutMs: 23_500 })
      const error = thrownBy(() => walkGlobPattern(pattern, { budget }))

      expect(error).toBeInstanceOf(GlobWalkBudgetError)
      const budgetError = error as GlobWalkBudgetError
      expect(budgetError.exhausted).toBe('time')
      expect(budgetError.directory.startsWith(TREE + '/')).toBe(true)
      expect(budgetError.entries).toBe(12 + 2 * 4)
    } finally {
      clock.mockRestore()
    }
  })

  it('throws inside a directory of few entries, at the entry the deadline passes on', () => {
    // The clock is read at every entry, not every so many: a name can be
    // slow to match, and a directory of forty such names must not be walked
    // to its end long after the time is up. One reading a second again: the
    // budget is made at 1 s, the listing is at 2 s, and the fourth entry, at
    // 6 s, is past the deadline.
    const few = join(ROOT, 'few')
    mkdirSync(few)
    for (let f = 0; f < 40; f++) writeFileSync(join(few, `f${f}`), '')
    let now = 0
    const clock = spyOn(performance, 'now').mockImplementation(
      () => (now += 1000),
    )
    try {
      const budget = newGlobWalkBudget({ timeoutMs: 4500 })
      const error = thrownBy(() =>
        walkGlobPattern(join(few, '*.env'), { budget }),
      )

      expect(error).toBeInstanceOf(GlobWalkBudgetError)
      const budgetError = error as GlobWalkBudgetError
      expect(budgetError.exhausted).toBe('time')
      expect(budgetError.directory).toBe(few)
      expect(budgetError.entries).toBe(4)
    } finally {
      clock.mockRestore()
    }
  })

  it('is spent by every expansion it is handed to', () => {
    const second = plantTree('second')
    const budget = newGlobWalkBudget({ maxEntries: TREE_ENTRIES + 10 })

    expect(
      expandReadDenyGlobLinux(join(TREE, '**/.env'), [], undefined, {
        budget,
      }),
    ).toHaveLength(12)
    expect(budget.entries).toBe(TREE_ENTRIES)

    // The second tree fits a budget of its own, and does not fit what the
    // first expansion left of this one.
    expect(
      expandReadDenyGlobLinux(join(second, '**/.env'), [], undefined, {
        budget: newGlobWalkBudget({ maxEntries: TREE_ENTRIES + 10 }),
      }),
    ).toHaveLength(12)
    const error = thrownBy(() =>
      expandReadDenyGlobLinux(join(second, '**/.env'), [], undefined, {
        budget,
      }),
    )
    expect(error).toBeInstanceOf(GlobWalkBudgetError)
    expect((error as GlobWalkBudgetError).pattern).toBe(join(second, '**/.env'))
    expect((error as GlobWalkBudgetError).entries).toBe(TREE_ENTRIES + 11)
  })

  it('throws on a tree that only links inside it lead through', () => {
    // start/next -> ../pool/d1, d1/next -> ../d2, …: a tree a command
    // allowed to write there can make as long as it likes. `start*` names
    // start alone, so nothing but the links leads into pool.
    const chain = join(ROOT, 'chain')
    const links = 40
    plantChain(chain, links)
    const pattern = join(chain, 'start*', '**/.env')
    const whole = walkGlobPattern(pattern, {
      followSymlinkedDirectories: true,
    })
    expect(whole.matches).toHaveLength(links)
    // chain holds start and pool; every other entry was met through a link.
    expect(whole.entriesExamined).toBe(2 + 2 * links)

    let mounts: string[] | undefined
    const error = thrownBy(() => {
      mounts = expandReadDenyGlobLinux(pattern, [], undefined, {
        budget: newGlobWalkBudget({ maxEntries: whole.entriesExamined - 1 }),
      })
    })

    expect(mounts).toBeUndefined()
    expect(error).toBeInstanceOf(GlobWalkBudgetError)
    expect((error as GlobWalkBudgetError).directory).toBe(
      join(chain, 'pool', `d${links}`),
    )
  })

  it('is spent on what a link to a directory beside the project leads to', () => {
    // linked/bigtree -> tree: the link is the one entry under the directory
    // the pattern starts from, and what it leads to holds sixty.
    const proj = join(ROOT, 'linked')
    mkdirSync(proj)
    symlinkSync(join('..', 'tree'), join(proj, 'bigtree'))
    const pattern = join(proj, '**/.env')
    const whole = newGlobWalkBudget({ maxEntries: 1 + TREE_ENTRIES })
    expect(
      expandReadDenyGlobLinux(pattern, [], undefined, { budget: whole }),
    ).toHaveLength(12)
    expect(whole.entries).toBe(1 + TREE_ENTRIES)

    let mounts: string[] | undefined
    const error = thrownBy(() => {
      mounts = expandReadDenyGlobLinux(pattern, [], undefined, {
        budget: newGlobWalkBudget({ maxEntries: TREE_ENTRIES }),
      })
    })

    expect(mounts).toBeUndefined()
    expect(error).toBeInstanceOf(GlobWalkBudgetError)
    const budgetError = error as GlobWalkBudgetError
    expect(budgetError.exhausted).toBe('entries')
    expect(budgetError.pattern).toBe(pattern)
    // Named where it really is, as what is found in it would be.
    expect(budgetError.directory.startsWith(TREE + '/')).toBe(true)
  })

  it('does not take a spent budget for a directory that could not be listed', () => {
    // An error from the listing itself marks the directory to be denied as
    // a whole; the budget's error is not one of those, whether the entries
    // ran out or the time did. The time is looked at right before each
    // listing: taken for a listing that failed, it would deny the tree as a
    // whole and hand that back.
    for (const limits of [{ maxEntries: 20 }, { timeoutMs: 0 }]) {
      const unlistable = new Set<string>()
      let mounts: string[] | undefined
      const error = thrownBy(() => {
        mounts = expandReadDenyGlobLinux(
          join(TREE, '**/.env'),
          [],
          unlistable,
          { budget: newGlobWalkBudget(limits) },
        )
      })

      expect(error).toBeInstanceOf(GlobWalkBudgetError)
      expect(mounts).toBeUndefined()
      expect([...unlistable]).toEqual([])
    }
  })
})

describe.if(isLinux)('a read-deny glob past its budget, at the manager', () => {
  let ROOT: string
  let PROJ: string
  let OTHER: string
  const newBudget = sandboxUtils.newGlobWalkBudget

  /** Has the manager make its budgets with these limits instead. */
  function withBudgetOf<T>(
    limits: { maxEntries?: number; timeoutMs?: number },
    fn: (made: () => number) => Promise<T>,
  ): Promise<T> {
    const spy = spyOn(sandboxUtils, 'newGlobWalkBudget').mockImplementation(
      () => newBudget(limits),
    )
    return fn(() => spy.mock.calls.length).finally(() => spy.mockRestore())
  }

  function plantProject(name: string): string {
    const proj = join(ROOT, name)
    for (let d = 0; d < 10; d++) {
      mkdirSync(join(proj, `pkg${d}`), { recursive: true })
      for (const f of ['.env', 'index.js', 'readme.md']) {
        writeFileSync(join(proj, `pkg${d}`, f), '')
      }
    }
    return proj
  }

  function filesystemOf(denyRead: string[]) {
    return { filesystem: { denyRead, allowWrite: [], denyWrite: [] } }
  }

  /** The wrapped command, or what the wrap threw: never both. */
  async function wrapOf(
    denyRead: string[],
  ): Promise<{ wrapped?: string; error?: unknown }> {
    try {
      return {
        wrapped: await SandboxManager.wrapWithSandbox(
          'echo hello',
          undefined,
          filesystemOf(denyRead),
        ),
      }
    } catch (error) {
      return { error }
    }
  }

  beforeAll(() => {
    ROOT = realpathSync(mkdtempSync(join(tmpdir(), 'deny-glob-manager-')))
    PROJ = plantProject('proj')
    OTHER = plantProject('other')
  })

  afterAll(async () => {
    await SandboxManager.reset()
    rmSync(ROOT, { recursive: true, force: true })
  })

  it('wraps an ordinary project with the default budget', async () => {
    const { wrapped, error } = await wrapOf([join(PROJ, '**/.env')])

    expect(error).toBeUndefined()
    for (let d = 0; d < 10; d++) {
      expect(wrapped).toContain(
        `--ro-bind /dev/null ${join(PROJ, `pkg${d}`, '.env')}`,
      )
    }
  })

  it('refuses the wrap, and returns no command, when the tree is past the budget', async () => {
    const pattern = join(PROJ, '**/.env')
    const { wrapped, error } = await withBudgetOf({ maxEntries: 25 }, () =>
      wrapOf([pattern]),
    )

    expect(wrapped).toBeUndefined()
    expect(error).toBeInstanceOf(LinuxSandboxProfileError)
    const profileError = error as LinuxSandboxProfileError
    expect(profileError.code).toBe('deny_glob_too_large')
    expect(profileError.message).toContain(`"${pattern}"`)
    expect(profileError.message).toContain('25 directory entries')
    expect(profileError.message).toContain('narrow the pattern')
    expect(profileError.cause).toBeInstanceOf(GlobWalkBudgetError)
    const cause = profileError.cause as GlobWalkBudgetError
    expect(cause.exhausted).toBe('entries')
    expect(profileError.message).toContain(cause.directory)
    // What a caller builds its own message from, read off `.cause` as plain
    // fields: it needs neither the class nor the text of the message.
    const fields: Record<string, unknown> = { ...cause }
    expect(fields).toEqual({
      name: 'GlobWalkBudgetError',
      pattern,
      directory: expect.stringMatching(new RegExp(`^${PROJ}(/|$)`)),
      exhausted: 'entries',
      entries: 26,
      elapsedMs: expect.any(Number),
      maxEntries: 25,
      timeoutMs: 10_000,
    })
    // A rejected promise, which is how every caller of the wrap meets it.
    await withBudgetOf({ maxEntries: 25 }, async () => {
      // eslint-disable-next-line @typescript-eslint/await-thenable -- bun:test types .rejects.toThrow() as void; the await is required at runtime
      await expect(
        SandboxManager.wrapWithSandbox(
          'echo hello',
          undefined,
          filesystemOf([pattern]),
        ),
      ).rejects.toThrow(LinuxSandboxProfileError)
    })
  })

  it('refuses the wrap when the time is up', async () => {
    const { wrapped, error } = await withBudgetOf({ timeoutMs: 0 }, () =>
      wrapOf([join(PROJ, '**/.env')]),
    )

    expect(wrapped).toBeUndefined()
    expect(error).toBeInstanceOf(LinuxSandboxProfileError)
    expect((error as LinuxSandboxProfileError).code).toBe('deny_glob_too_large')
    expect((error as LinuxSandboxProfileError).message).toContain(
      'the time ran out',
    )
  })

  it('gives the patterns of one wrap one budget between them', async () => {
    const first = join(PROJ, '**/.env')
    const second = join(OTHER, '**/.env')
    // Each tree is 40 entries: either fits 60, and the two do not.
    await withBudgetOf({ maxEntries: 60 }, async made => {
      expect((await wrapOf([first])).error).toBeUndefined()
      expect((await wrapOf([second])).error).toBeUndefined()
      expect(made()).toBe(2)

      const { wrapped, error } = await wrapOf([first, second])

      expect(made()).toBe(3)
      expect(wrapped).toBeUndefined()
      expect(error).toBeInstanceOf(LinuxSandboxProfileError)
      expect((error as LinuxSandboxProfileError).code).toBe(
        'deny_glob_too_large',
      )
      // The pattern that was being expanded when the budget ran out.
      expect((error as LinuxSandboxProfileError).message).toContain(
        `"${second}"`,
      )
    })
  })

  it('refuses the wrap over a tree that only links inside it lead through', async () => {
    const chain = join(ROOT, 'chain')
    plantChain(chain, 30)
    const pattern = join(chain, 'start*', '**/.env')
    expect((await wrapOf([pattern])).wrapped).toContain(
      `--ro-bind /dev/null ${join(chain, 'pool', 'd30', '.env')}`,
    )

    // chain itself holds two entries: the rest of the twenty go on what the
    // links lead to.
    const { wrapped, error } = await withBudgetOf({ maxEntries: 20 }, () =>
      wrapOf([pattern]),
    )

    expect(wrapped).toBeUndefined()
    expect(error).toBeInstanceOf(LinuxSandboxProfileError)
    expect((error as LinuxSandboxProfileError).code).toBe('deny_glob_too_large')
    expect(
      ((error as LinuxSandboxProfileError).cause as GlobWalkBudgetError)
        .directory,
    ).toStartWith(join(chain, 'pool') + '/')
  })

  it('refuses the wrap over a tree that a link leads to from beside it', async () => {
    const proj = join(ROOT, 'linked')
    mkdirSync(join(proj, 'src'), { recursive: true })
    writeFileSync(join(proj, '.env'), '')
    symlinkSync(join('..', 'other'), join(proj, 'bigtree'))
    const pattern = join(proj, '**/.env')
    // With room for it, what the link leads to is walked and masked.
    const roomy = await wrapOf([pattern])
    expect(roomy.error).toBeUndefined()
    for (const masked of [join(proj, '.env'), join(OTHER, 'pkg0', '.env')]) {
      expect(
        countMounts(roomy.wrapped!, '--ro-bind', '/dev/null', masked),
      ).toBe(1)
    }

    // proj itself holds three entries, and OTHER forty.
    const { wrapped, error } = await withBudgetOf({ maxEntries: 30 }, () =>
      wrapOf([pattern]),
    )

    expect(wrapped).toBeUndefined()
    expect(error).toBeInstanceOf(LinuxSandboxProfileError)
    expect((error as LinuxSandboxProfileError).code).toBe('deny_glob_too_large')
    expect((error as LinuxSandboxProfileError).message).toContain(
      `"${pattern}"`,
    )
    const cause = (error as LinuxSandboxProfileError).cause
    expect(cause).toBeInstanceOf(GlobWalkBudgetError)
    expect((cause as GlobWalkBudgetError).directory).toMatch(
      new RegExp(`^${OTHER}(/|$)`),
    )
  })

  it('refuses the read configuration the same way', async () => {
    const pattern = join(PROJ, '**/.env')
    await SandboxManager.reset()
    await SandboxManager.initialize({
      network: { allowedDomains: [], deniedDomains: [] },
      filesystem: { denyRead: [pattern], allowWrite: [], denyWrite: [] },
    })
    try {
      expect(SandboxManager.getFsReadConfig().denyOnly).toHaveLength(10)

      const error = await withBudgetOf({ maxEntries: 25 }, async () =>
        thrownBy(() => SandboxManager.getFsReadConfig()),
      )

      expect(error).toBeInstanceOf(LinuxSandboxProfileError)
      expect((error as LinuxSandboxProfileError).code).toBe(
        'deny_glob_too_large',
      )
      expect((error as LinuxSandboxProfileError).message).toContain(
        `"${pattern}"`,
      )
    } finally {
      await SandboxManager.reset()
    }
  })
})

describe.if(!isWindows)('the debug line of a read-deny expansion', () => {
  let ROOT: string

  beforeAll(() => {
    ROOT = realpathSync(mkdtempSync(join(tmpdir(), 'deny-glob-debug-')))
    mkdirSync(join(ROOT, 'proj', 'src'), { recursive: true })
    mkdirSync(join(ROOT, 'outside'))
    writeFileSync(join(ROOT, 'proj', '.env'), '')
    writeFileSync(join(ROOT, 'proj', 'src', '.env'), '')
    writeFileSync(join(ROOT, 'proj', 'src', 'index.js'), '')
    symlinkSync(join('..', 'outside'), join(ROOT, 'proj', 'out'))
  })

  afterAll(() => {
    rmSync(ROOT, { recursive: true, force: true })
  })

  /** What the debug logger printed while `fn` ran, at every level. */
  function debugLinesOf(fn: () => void, debug: string | undefined): string[] {
    const lines: string[] = []
    const savedDebug = process.env.SRT_DEBUG
    if (debug === undefined) delete process.env.SRT_DEBUG
    else process.env.SRT_DEBUG = debug
    const record = (...parts: unknown[]): void => {
      lines.push(parts.map(String).join(' '))
    }
    const spies = [
      spyOn(console, 'warn').mockImplementation(record),
      spyOn(console, 'error').mockImplementation(record),
    ]
    try {
      fn()
      return lines
    } finally {
      for (const spy of spies) spy.mockRestore()
      if (savedDebug === undefined) delete process.env.SRT_DEBUG
      else process.env.SRT_DEBUG = savedDebug
    }
  }

  it('says once what the expansion cost and found', () => {
    const pattern = join(ROOT, 'proj', '**/.env')
    const lines = debugLinesOf(
      () => void expandReadDenyGlobLinux(pattern, []),
      '1',
    )

    const summary = lines.filter(line => line.includes('Expanded denyRead'))
    expect(summary).toHaveLength(1)
    // proj, proj/src and what proj/out leads to listed; .env, src and out in
    // the first, .env and index.js in the second, nothing in the third.
    const timed = summary[0]!.replace(/ in \d+ ms: /, ' in <n> ms: ')
    expect(timed).not.toBe(summary[0])
    expect(timed).toEndWith(
      `Expanded denyRead glob "${pattern}" in <n> ms: 2 matches -> 2 mounts; ` +
        `directories listed: 3, entries looked at: 5`,
    )
  })

  it('says nothing without SRT_DEBUG', () => {
    expect(
      debugLinesOf(
        () => void expandReadDenyGlobLinux(join(ROOT, 'proj', '**/.env'), []),
        undefined,
      ),
    ).toEqual([])
  })
})
