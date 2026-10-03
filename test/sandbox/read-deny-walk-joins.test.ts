import { afterAll, beforeAll, describe, expect, it, spyOn } from 'bun:test'
import * as fs from 'fs'
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from 'fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { LinuxSandboxProfileError } from '../../src/sandbox/linux-sandbox-utils.js'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import {
  GlobWalkBudgetError,
  type GlobWalkListings,
  newGlobWalkBudget,
  walkGlobPattern,
  walkGlobPatternSteps,
} from '../../src/sandbox/sandbox-utils.js'
import { isLinux } from '../helpers/platform.js'

/**
 * Where the walk's budget, its shared listings and its steps meet. Each has
 * its own suite; these are the choices that only exist between them.
 */
describe('the read-deny walk: budget, shared listings and steps together', () => {
  const DIRECTORIES = 6
  const PLAIN_FILES = 10
  let ROOT: string
  /** Every entry below ROOT: the directories, and the files in each. */
  const ENTRIES = DIRECTORIES * (1 + PLAIN_FILES + 1)

  beforeAll(() => {
    ROOT = realpathSync(mkdtempSync(join(tmpdir(), 'walk-joins-')))
    for (let d = 0; d < DIRECTORIES; d++) {
      mkdirSync(join(ROOT, `d${d}`))
      writeFileSync(join(ROOT, `d${d}`, 'key.pem'), '')
      for (let f = 0; f < PLAIN_FILES; f++) {
        writeFileSync(join(ROOT, `d${d}`, `plain${f}.txt`), '')
      }
    }
  })

  afterAll(async () => {
    await SandboxManager.reset()
    rmSync(ROOT, { recursive: true, force: true })
  })

  /** Holds the thread for longer than a turn lasts. */
  const outlastATurn = (): void => {
    const until = performance.now() + 15
    while (performance.now() < until);
  }

  it('charges the budget for an entry the pattern cannot match', () => {
    const budget = newGlobWalkBudget()

    walkGlobPattern(join(ROOT, '**/*.pem'), { budget })

    expect(budget.entries).toBe(ENTRIES)
    expect(() =>
      walkGlobPattern(join(ROOT, '**/*.pem'), {
        // More than the entries that match or are directories, and fewer
        // than there are.
        budget: newGlobWalkBudget({ maxEntries: DIRECTORIES * 2 + 1 }),
      }),
    ).toThrow(GlobWalkBudgetError)
  })

  it('charges the budget for an entry read from a listing another pattern made', () => {
    const budget = newGlobWalkBudget()
    const listings: GlobWalkListings = new Map()
    const readdir = spyOn(fs, 'readdirSync')
    try {
      walkGlobPattern(join(ROOT, '**/*.pem'), { budget, listings })
      const listed = readdir.mock.calls.length
      walkGlobPattern(join(ROOT, '**/*.txt'), { budget, listings })

      expect(listed).toBe(DIRECTORIES + 1)
      expect(readdir.mock.calls.length).toBe(listed)
      expect(budget.entries).toBe(ENTRIES * 2)
    } finally {
      readdir.mockRestore()
    }
  })

  it('reads the clock after a step and before the listing that follows it', () => {
    const steps = walkGlobPatternSteps(join(ROOT, '**/*.pem'), {
      budget: newGlobWalkBudget({ timeoutMs: 5 }),
    })
    expect(steps.next().done).toBe(false)
    // What a turn given to other work can take.
    outlastATurn()
    const readdir = spyOn(fs, 'readdirSync')
    try {
      expect(() => steps.next()).toThrow(GlobWalkBudgetError)
      expect(readdir.mock.calls.length).toBe(0)
    } finally {
      readdir.mockRestore()
    }
  })

  describe.if(isLinux)('through the wrap', () => {
    const network = { allowedDomains: [], deniedDomains: [] }
    const filesystemWith = (
      denyReadGlobBudget: { maxEntries: number } | undefined,
    ): {
      denyRead: string[]
      allowRead: string[]
      allowWrite: string[]
      denyWrite: string[]
      denyReadGlobBudget?: { maxEntries: number }
    } => ({
      denyRead: [join(ROOT, '**/*.pem')],
      // Walked first, and in turns, so that there is a turn to act in.
      allowRead: [join(ROOT, '**/*.none')],
      allowWrite: [],
      denyWrite: [],
      ...(denyReadGlobBudget === undefined ? {} : { denyReadGlobBudget }),
    })
    /** Runs `act` in the listing below ROOT that `at` counts to, the second
     *  unless told otherwise, each outlasting a turn. */
    const duringTheWalk = (
      act: () => void,
      at = 2,
    ): { restore: () => void } => {
      let listed = 0
      const readdirSync = fs.readdirSync
      const spy = spyOn(fs, 'readdirSync').mockImplementation(((
        ...args: Parameters<typeof fs.readdirSync>
      ) => {
        if (String(args[0]).startsWith(ROOT)) {
          if (++listed === at) act()
          outlastATurn()
        }
        return readdirSync(...args)
      }) as typeof fs.readdirSync)
      return { restore: () => spy.mockRestore() }
    }
    const outcomeOf = (wrap: Promise<string>): Promise<unknown> =>
      wrap.catch((error: unknown) => error)

    it('lists a directory once for all the denyRead patterns of a configuration, and charges each pattern for it', async () => {
      await SandboxManager.reset()
      await SandboxManager.initialize({
        network,
        filesystem: {
          denyRead: [join(ROOT, '**/*.pem'), join(ROOT, '**/*.txt')],
          allowWrite: [],
          denyWrite: [],
          // Enough for one pattern and not for two.
          denyReadGlobBudget: { maxEntries: ENTRIES + 1 },
        },
      })
      const readdir = spyOn(fs, 'readdirSync')
      const listedBelowRoot = (): number =>
        readdir.mock.calls.filter(([dir]) => String(dir).startsWith(ROOT))
          .length
      try {
        expect(() => SandboxManager.getFsReadConfig()).toThrow(
          LinuxSandboxProfileError,
        )
        expect(listedBelowRoot()).toBe(DIRECTORIES + 1)

        SandboxManager.updateConfig({
          network,
          filesystem: {
            denyRead: [join(ROOT, '**/*.pem'), join(ROOT, '**/*.txt')],
            allowWrite: [],
            denyWrite: [],
          },
        })
        readdir.mockClear()
        await SandboxManager.wrapWithSandbox('true')
        expect(listedBelowRoot()).toBe(DIRECTORIES + 1)
      } finally {
        readdir.mockRestore()
      }
    })

    it('gives up for the signal, not for the budget, when both have run out', async () => {
      await SandboxManager.reset()
      await SandboxManager.initialize({
        network,
        filesystem: filesystemWith({ maxEntries: 1 }),
      })
      const stopped = new AbortController()
      const reason = new Error('stopped by the user')
      const walk = duringTheWalk(() => stopped.abort(reason))
      try {
        expect(
          await outcomeOf(
            SandboxManager.wrapWithSandbox(
              'true',
              undefined,
              undefined,
              stopped.signal,
            ),
          ),
        ).toBe(reason)
      } finally {
        walk.restore()
      }
    })

    it('takes the budget of the configuration that replaced the one it started with', async () => {
      await SandboxManager.reset()
      await SandboxManager.initialize({
        network,
        filesystem: filesystemWith(undefined),
      })
      const walk = duringTheWalk(() =>
        SandboxManager.updateConfig({
          network,
          filesystem: filesystemWith({ maxEntries: 1 }),
        }),
      )
      try {
        const disturbed = await outcomeOf(
          SandboxManager.wrapWithSandbox('true'),
        )
        walk.restore()

        expect(disturbed).toBeInstanceOf(LinuxSandboxProfileError)
        expect((disturbed as LinuxSandboxProfileError).code).toBe(
          'deny_glob_too_large',
        )
        const undisturbed = await outcomeOf(
          SandboxManager.wrapWithSandbox('true'),
        )
        expect((undisturbed as LinuxSandboxProfileError).code).toBe(
          'deny_glob_too_large',
        )
      } finally {
        walk.restore()
      }
    })

    it('takes the budget of a configuration that arrives during the denyRead walk', async () => {
      await SandboxManager.reset()
      await SandboxManager.initialize({
        network,
        filesystem: filesystemWith(undefined),
      })
      // In the denyRead walk, which comes after the allowRead one has listed
      // every directory, and which began under a budget that has room. The
      // case above never gets there: its first attempt reads the new budget.
      const walk = duringTheWalk(
        () =>
          SandboxManager.updateConfig({
            network,
            filesystem: filesystemWith({ maxEntries: ENTRIES - 1 }),
          }),
        DIRECTORIES + 1 + 2,
      )
      try {
        const disturbed = await outcomeOf(
          SandboxManager.wrapWithSandbox('true'),
        )
        expect(disturbed).toBeInstanceOf(LinuxSandboxProfileError)
        expect((disturbed as LinuxSandboxProfileError).code).toBe(
          'deny_glob_too_large',
        )
      } finally {
        walk.restore()
      }
    })
  })
})
