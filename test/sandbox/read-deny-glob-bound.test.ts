import {
  afterAll,
  afterEach,
  beforeAll,
  describe,
  expect,
  it,
  mock,
  spyOn,
} from 'bun:test'
// The namespace the library binds, so the code under test sees a spy on it.
import * as fs from 'fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { expandReadDenyGlobLinux } from '../../src/sandbox/read-deny-glob.js'
import {
  FilesystemConfigSchema,
  type SandboxRuntimeConfig,
} from '../../src/sandbox/sandbox-config.js'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import {
  type GlobWalkListings,
  newGlobWalkBudget,
  walkGlobPattern,
} from '../../src/sandbox/sandbox-utils.js'
import { isLinux, isWindows } from '../helpers/platform.js'

const DIRECTORIES = 6
/** What a planted tree holds: its directories, and the four files in each. */
const ENTRIES = DIRECTORIES * 5
let ROOT: string
let TREE: string
/** Matches the `.env` in each directory of TREE. */
let PATTERN: string

/** `ROOT/<name>`: d0 to d5, a `.env` and three other files in each. */
function plantTree(name: string): string {
  for (let d = 0; d < DIRECTORIES; d++) {
    fs.mkdirSync(join(ROOT, name, `d${d}`), { recursive: true })
    for (const file of ['.env', 'a', 'b', 'c']) {
      fs.writeFileSync(join(ROOT, name, `d${d}`, file), '')
    }
  }
  return join(ROOT, name)
}

/** Has the clock move a millisecond each time it is read. */
function tickingClock(): void {
  let now = 0
  spyOn(performance, 'now').mockImplementation(() => ++now)
}

/** Has every listing answer what `listed` makes of it. */
function listingsThrough(
  listed: (dir: string, entries: fs.Dirent[]) => unknown[],
): void {
  const { readdirSync } = fs
  spyOn(fs, 'readdirSync').mockImplementation(((
    ...args: Parameters<typeof readdirSync>
  ) =>
    listed(
      String(args[0]),
      readdirSync(...args) as unknown as fs.Dirent[],
    )) as unknown as typeof readdirSync)
}

/** What `run` throws or rejects with: undefined when it does neither. */
async function refusalOf(run: () => unknown): Promise<unknown> {
  try {
    await run()
    return undefined
  } catch (error) {
    return error
  }
}

beforeAll(() => {
  ROOT = fs.realpathSync(fs.mkdtempSync(join(tmpdir(), 'deny-glob-budget-')))
  TREE = plantTree('tree')
  PATTERN = join(TREE, '**/.env')
})

afterEach(() => {
  mock.restore()
})

afterAll(() => {
  fs.rmSync(ROOT, { recursive: true, force: true })
})

describe.if(!isWindows)('the budget of a glob walk', () => {
  const expand = (pattern: string, maxEntries: number): string[] =>
    expandReadDenyGlobLinux(pattern, [], undefined, {
      budget: newGlobWalkBudget({ maxEntries }),
    })

  it('is charged for every entry read from disk, matched or not, and not for one another walk has read', () => {
    const budget = newGlobWalkBudget()
    const listings: GlobWalkListings = new Map()
    for (const pattern of [PATTERN, join(TREE, '**/a')]) {
      walkGlobPattern(pattern, { budget, listings })
      expect(budget.entries).toBe(ENTRIES)
    }
    // Not handed what they read, so it reads the tree again.
    walkGlobPattern(PATTERN, { budget })
    expect(budget.entries).toBe(2 * ENTRIES)
  })

  it('throws at the entry past maxEntries, and says where it was', async () => {
    // Exactly enough is enough.
    expect(expand(PATTERN, ENTRIES)).toHaveLength(DIRECTORIES)

    expect(await refusalOf(() => expand(PATTERN, ENTRIES - 1))).toMatchObject({
      name: 'GlobWalkBudgetError',
      message: expect.stringContaining(PATTERN),
      pattern: PATTERN,
      directory: expect.stringContaining(TREE + '/'),
      exhausted: 'entries',
      entries: ENTRIES,
      elapsedMs: expect.any(Number),
      maxEntries: ENTRIES - 1,
      timeoutMs: 60_000,
    })
  })

  it('is charged for what links lead to, one after another, named where it really is', async () => {
    // linked/out -> ../hop and hop/on -> ../tree: an entry each, and the tree.
    // A command allowed to write there can make the way as long as it likes.
    fs.mkdirSync(join(ROOT, 'linked'))
    fs.mkdirSync(join(ROOT, 'hop'))
    fs.symlinkSync(join('..', 'hop'), join(ROOT, 'linked', 'out'))
    fs.symlinkSync(join('..', 'tree'), join(ROOT, 'hop', 'on'))
    const pattern = join(ROOT, 'linked', '**/.env')

    expect(expand(pattern, 2 + ENTRIES)).toEqual(expand(PATTERN, ENTRIES))
    expect(await refusalOf(() => expand(pattern, 1 + ENTRIES))).toMatchObject({
      pattern,
      directory: expect.stringContaining(TREE + '/'),
    })
  })

  // The budget is made at 1 ms, so the reading at n ms finds n - 1 gone: at 2
  // the tree is about to be listed, from 3 to 8 its entries are met, at 9 and
  // from 10 to 13 the same for a directory in it, and at 14 for the next.
  it.each([
    ['before the first listing', 1, false, /tree$/, 0],
    ['at an entry, not at every so many', 4, false, /tree$/, 3],
    ['at an entry another pattern has read', 4, true, /tree$/, 0],
    ['after a step, before the next listing', 13, false, /tree\/d\d$/, 6 + 4],
  ])(
    'throws once the time is up: %s',
    async (_when, timeoutMs, read, directory, entries) => {
      const listings: GlobWalkListings = new Map()
      if (read) walkGlobPattern(join(TREE, '**/a'), { listings })
      tickingClock()
      const budget = newGlobWalkBudget({ timeoutMs })

      expect(
        await refusalOf(() => walkGlobPattern(PATTERN, { budget, listings })),
      ).toMatchObject({
        exhausted: 'time',
        directory: expect.stringMatching(directory),
        entries,
      })
    },
  )

  it('throws before an entry whose type has to be asked for, and not as a directory that could not be listed', async () => {
    // Listed the way some NFS and FUSE mounts list: names, and no types.
    const untyped: ProxyHandler<fs.Dirent> = {
      get: ({ name }, key) => (key === 'name' ? name : () => false),
    }
    const listed: string[] = []
    listingsThrough((dir, entries) => {
      listed.push(dir)
      return entries.map(e => new Proxy(e, untyped))
    })
    const asked = spyOn(fs, 'lstatSync')
    tickingClock()
    const budget = newGlobWalkBudget({ timeoutMs: 4 })

    expect(
      await refusalOf(() => walkGlobPattern(PATTERN, { budget })),
    ).toMatchObject({ exhausted: 'time', directory: TREE, entries: 0 })
    expect(asked).toHaveBeenCalledTimes(2)

    // Nor as a real path that could not be read, which is asked for again by
    // a shorter name that led to it.
    fs.mkdirSync(join(ROOT, 'v'))
    fs.symlinkSync(TREE, join(ROOT, 'v', 'l'))
    listed.length = 0
    expect(
      await refusalOf(() =>
        expandReadDenyGlobLinux(join(ROOT, 'v', '**/.env'), [], undefined, {
          budget: newGlobWalkBudget({ timeoutMs: 6 }),
        }),
      ),
    ).toMatchObject({ exhausted: 'time', directory: TREE })
    expect(listed).toEqual([join(ROOT, 'v'), TREE])
  })
})

describe.if(isLinux)('the budget of a read configuration', () => {
  function configOf(
    denyReadGlobBudget: object | undefined,
    lists: { denyRead?: string[]; allowRead?: string[] } = {},
    credentials?: SandboxRuntimeConfig['credentials'],
  ): SandboxRuntimeConfig {
    return {
      network: { allowedDomains: [], deniedDomains: [] },
      filesystem: {
        denyRead: [],
        allowWrite: [],
        denyWrite: [],
        ...lists,
        denyReadGlobBudget,
      },
      credentials,
    }
  }

  afterAll(() => SandboxManager.reset())

  describe.each([
    ['getFsReadConfig()', () => SandboxManager.getFsReadConfig()],
    ['wrapWithSandbox()', () => SandboxManager.wrapWithSandbox('true')],
    ['wrapWithSandboxArgv()', () => SandboxManager.wrapWithSandboxArgv('true')],
  ])('worked out by %s', (_way, workOut) => {
    /** What refuses it, if anything does, in a session of that configuration. */
    const refusalUnder = (
      ...config: Parameters<typeof configOf>
    ): Promise<unknown> => {
      SandboxManager.updateConfig(configOf(...config))
      return refusalOf(workOut)
    }

    it.each([
      [{ maxEntries: ENTRIES - 1 }, 'entries'],
      [{ timeoutMs: 1 }, 'time'],
    ])('is refused past %o', async (limits, exhausted) => {
      const held = { maxEntries: 20_000_000, timeoutMs: 60_000, ...limits }
      tickingClock()

      const refusal = await refusalUnder(limits, { denyRead: [PATTERN] })

      expect(refusal).toMatchObject({
        name: 'LinuxSandboxProfileError',
        code: 'deny_glob_too_large',
        cause: {
          name: 'GlobWalkBudgetError',
          pattern: PATTERN,
          exhausted,
          ...held,
        },
      })
      for (const part of [
        `"${PATTERN}"`,
        `the ${exhausted} ran out`,
        `of ${held.maxEntries} directory entries`,
        `of ${held.timeoutMs} ms`,
        `while listing ${TREE}`,
        'narrow the pattern',
        'or raise filesystem.denyReadGlobBudget',
      ]) {
        expect(String(refusal)).toContain(part)
      }
    })

    it.each<[string, string, (pattern: string) => [object, object?]]>([
      ['allowRead', 'tree', p => [{ allowRead: [p] }]],
      [
        'credentials.files',
        'tree',
        p => [{}, { files: [{ path: p, mode: 'deny' }] }],
      ],
      // Walked beneath an anchor: the folder, brackets and all, is a name.
      ['denyRead', 'pk[g]s', p => [{ denyRead: [p] }]],
    ])(
      'holds a pattern of %s, in %s, to it',
      async (_list, folder, listing) => {
        const pattern = join(plantTree(folder), '**/.env')

        expect(
          await refusalUnder({ maxEntries: 1000 }, ...listing(pattern)),
        ).toBeUndefined()
        expect(
          await refusalUnder({ maxEntries: ENTRIES - 1 }, ...listing(pattern)),
        ).toMatchObject({ code: 'deny_glob_too_large', cause: { pattern } })
      },
    )

    it('has one for all its patterns, charged once for a tree that two denyRead patterns go through', async () => {
      const limits = { maxEntries: ENTRIES }
      const other = join(plantTree('other'), '**/.env')

      expect(
        await refusalUnder(limits, { denyRead: [PATTERN, join(TREE, '**/a')] }),
      ).toBeUndefined()
      for (const lists of [
        { denyRead: [PATTERN, other] },
        { allowRead: [PATTERN, other] },
        { allowRead: [PATTERN], denyRead: [other] },
      ]) {
        // The pattern that was being expanded when the budget ran out.
        expect(await refusalUnder(limits, lists)).toMatchObject({
          cause: { pattern: other, entries: ENTRIES + 1 },
        })
      }
    })

    // NaN would never be reached, and a misspelt key would leave the default.
    it.each([{ maxEntries: NaN }, { timeoutMs: '1000' }, { maxEntires: 1 }])(
      'fails on limits that no schema has seen: %o',
      async limits => {
        expect(await refusalUnder(limits)).toMatchObject({
          message: expect.stringMatching(/filesystem[^]*denyReadGlobBudget/),
        })
      },
    )
  })

  it('takes the limits of one wrap over those of the session, initialized or updated, one by one', async () => {
    const lists = { denyRead: [PATTERN] }
    const refusalWith = (limits?: object): Promise<unknown> => {
      const own = configOf(limits, lists)
      return refusalOf(() =>
        SandboxManager.wrapWithSandbox('true', undefined, own),
      )
    }
    await SandboxManager.reset()
    await SandboxManager.initialize(
      configOf({ maxEntries: ENTRIES - 1, timeoutMs: 1234 }, lists),
    )

    expect(await refusalWith()).toMatchObject({
      cause: { maxEntries: ENTRIES - 1, timeoutMs: 1234 },
    })
    expect(
      await refusalWith({ maxEntries: ENTRIES - 2, timeoutMs: undefined }),
    ).toMatchObject({ cause: { maxEntries: ENTRIES - 2, timeoutMs: 1234 } })
    expect(await refusalWith({ maxEntries: ENTRIES })).toBeUndefined()

    SandboxManager.updateConfig(configOf({ maxEntries: ENTRIES }, lists))
    expect(await refusalWith()).toBeUndefined()
    expect(await refusalWith({ maxEntries: ENTRIES - 1 })).toMatchObject({
      cause: { maxEntries: ENTRIES - 1, timeoutMs: 60_000 },
    })
  })

  // The allowRead walk lists every directory, and then the denyRead walk does.
  it.each([
    ['allowRead', 2],
    ['denyRead', DIRECTORIES + 1 + 2],
  ])(
    'starts over under the budget of a configuration that arrives during the %s walk, with nothing spent',
    async (_walk, arrivesAt) => {
      const lists = { allowRead: [join(TREE, '**/a')], denyRead: [PATTERN] }
      const refusalUnderLate = (maxEntries: number): Promise<unknown> => {
        mock.restore()
        SandboxManager.updateConfig(configOf(undefined, lists))
        let listed = 0
        listingsThrough((dir, entries) => {
          if (dir.startsWith(TREE) && ++listed === arrivesAt) {
            SandboxManager.updateConfig(configOf({ maxEntries }, lists))
          }
          return entries
        })
        return refusalOf(() => SandboxManager.wrapWithSandbox('true'))
      }

      expect(await refusalUnderLate(ENTRIES - 1)).toMatchObject({
        cause: { maxEntries: ENTRIES - 1 },
      })
      // What the two walks of one attempt read, and no more.
      expect(await refusalUnderLate(2 * ENTRIES)).toBeUndefined()
    },
  )
})

describe('filesystem.denyReadGlobBudget in the schema', () => {
  it.each([
    [true, undefined],
    [true, { maxEntries: 1 }],
    [true, { timeoutMs: 120_000 }],
    [true, { maxEntries: 50_000_000, timeoutMs: 1 }],
    [false, { maxEntries: 0 }],
    [false, { maxEntries: 1.5 }],
    [false, { maxEntries: '1000' }],
    [false, { maxEntries: Infinity }],
    [false, { maxEntires: 1 }],
    [false, { timeoutMs: 0 }],
    [false, { timeoutMs: 0.5 }],
    [false, 1000],
  ])(
    'takes positive integers, either or both, and nothing else: %p for %o',
    (taken, budget) => {
      expect(
        FilesystemConfigSchema.safeParse({
          denyRead: [],
          allowWrite: [],
          denyWrite: [],
          denyReadGlobBudget: budget,
        }).success,
      ).toBe(taken)
    },
  )
})
