import { describe, it, expect, beforeEach, afterEach, spyOn } from 'bun:test'
import * as fs from 'fs'
import {
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  wrapCommandWithSandboxLinux,
  cleanupBwrapMountPoints,
  LinuxSandboxProfileError,
} from '../../src/sandbox/linux-sandbox-utils.js'
import {
  SubmoduleWalkBudgetError,
  gitDirDenies,
  gitDirTreeDenies,
  gitFileDenies,
} from '../../src/sandbox/mandatory-deny-paths.js'
import type { GitDirDenies } from '../../src/sandbox/mandatory-deny-paths.js'
import {
  NO_COLLAPSE,
  collapseEverything,
  collapseFurther,
} from '../../src/sandbox/linux-deny-collapse.js'
import type { SubmoduleDenyPlan } from '../../src/sandbox/linux-deny-collapse.js'
import { withCapturedWarnings } from '../helpers/captured-warnings.js'
import { isLinux, isWindows } from '../helpers/platform.js'

function makeGitDir(gitDir: string): string {
  mkdirSync(join(gitDir, 'hooks'), { recursive: true })
  writeFileSync(join(gitDir, 'HEAD'), 'ref: refs/heads/main')
  writeFileSync(join(gitDir, 'config'), '[core]\n')
  return gitDir
}

/**
 * The passes a profile that does not fit is built in. Each one builds the
 * whole profile again, so what bounds the passes bounds the wrap: a
 * repository a command can make must not decide how many there are.
 */
describe.if(isLinux)('Passes over a profile that does not fit', () => {
  let dir: string
  /** A write root of its own with nothing under it, which is what makes the
   *  passes countable: see `wrapCountingPasses`. */
  let passMarker: string
  const savedCwd = process.cwd()

  beforeEach(() => {
    dir = realpathSync(mkdtempSync(join(tmpdir(), 'srt-collapse-passes-')))
    passMarker = join(dir, 'pass-marker')
    mkdirSync(passMarker)
  })

  afterEach(() => {
    process.chdir(savedCwd)
    cleanupBwrapMountPoints({ force: true })
    rmSync(dir, { recursive: true, force: true })
  })

  /** A repository with `count` submodule git directories, named so that
   *  sorted order is the order they were made in. */
  function makeSuperproject(
    checkout: string,
    count: number,
  ): { checkout: string; subs: string[] } {
    const gitDir = makeGitDir(join(checkout, '.git'))
    const subs: string[] = []
    for (let i = 0; i < count; i++) {
      const name = `s${String(i).padStart(5, '0')}`
      subs.push(makeGitDir(join(gitDir, 'modules', name)))
    }
    return { checkout, subs }
  }

  /** The mount words of a wrap: the argument file where the profile is past
   *  what a command line carries, the line itself where it is not. */
  function mountWords(command: string): string[] {
    const profile = /\/proc\/\d+\/fd\/\d+/.exec(command)?.[0]
    if (profile === undefined) return command.split(/\s+/)
    const words = readFileSync(profile, 'utf8').split('\0')
    words.pop()
    return words
  }

  /**
   * One wrap from the working directory with `writeRoot` what the command may
   * write, and how many times its profile was built: every pass looks once at
   * whether each write root exists, and nothing else in a wrap asks that of a
   * write root that holds nothing, which is what the marker is.
   *
   * `spentWords` is how the budget is set: each name to unset is two words
   * bubblewrap parses before the mounts, counted as they are, so what is left
   * for the mounts shrinks by exactly that much.
   */
  async function wrapCountingPasses(
    writeRoot: string,
    spentWords: number,
  ): Promise<{ outcome: unknown; passes: number; warnings: string[] }> {
    const realExistsSync = fs.existsSync
    let passes = 0
    const spy = spyOn(fs, 'existsSync').mockImplementation(((
      p: fs.PathLike,
    ) => {
      if (String(p) === passMarker) passes++
      return realExistsSync(p)
    }) as typeof fs.existsSync)
    try {
      const { result, warnings } = await withCapturedWarnings(() =>
        wrapCommandWithSandboxLinux({
          command: 'true',
          needsNetworkRestriction: false,
          // No seccomp helper, whose presence differs by machine.
          allowAllUnixSockets: true,
          readConfig: undefined,
          writeConfig: {
            allowOnly: [writeRoot, passMarker],
            denyWithinAllow: [],
          },
          unsetEnvVars: Array.from(
            { length: spentWords / 2 },
            (_, i) => `SRT_SPENT_${i}`,
          ),
          // A refusal is an outcome like any other here: what it was is for
          // the caller to say.
        }).catch((refusal: unknown) => refusal),
      )
      return { outcome: result, passes, warnings }
    } finally {
      spy.mockRestore()
    }
  }

  const didNotFit = (warnings: string[]): boolean =>
    warnings.some(warning => warning.includes('did not fit'))

  it('stops stepping where a deeper level gives no words back', async () => {
    // Four hundred submodule git directories the command may not write: no
    // deny of theirs takes a mount, since the read-only root already holds
    // them, so degrading one gives back nothing. The words that do not fit
    // are the root's and the write root's own binds, which nothing degrades.
    // Stepping through such a plan an entry at a time builds the profile four
    // hundred times over to arrive where it was always going to.
    const writeRoot = join(dir, 'work')
    mkdirSync(writeRoot)

    // Where the profile stops fitting is the same for one submodule as for
    // four hundred - none of them costs a word - so it is found on the small
    // repository: the least that can be spent before the mounts for the wrap
    // to say its profile did not fit.
    const probe = makeSuperproject(join(dir, 'probe'), 1)
    process.chdir(probe.checkout)
    let fits = 0
    let doesNotFit = 9000
    while (doesNotFit - fits > 2) {
      const spent = 2 * Math.floor((fits + doesNotFit) / 4)
      if (didNotFit((await wrapCountingPasses(writeRoot, spent)).warnings)) {
        doesNotFit = spent
      } else {
        fits = spent
      }
    }
    expect((await wrapCountingPasses(writeRoot, fits)).passes).toBe(1)

    const { checkout } = makeSuperproject(join(dir, 'repo'), 400)
    process.chdir(checkout)
    const { outcome, passes, warnings } = await wrapCountingPasses(
      writeRoot,
      doesNotFit,
    )

    // One pass that does not fit, one a step deeper that is no shorter, and
    // one at the last level, which is what is returned.
    expect(didNotFit(warnings)).toBe(true)
    expect(passes).toBeGreaterThan(1)
    expect(passes).toBeLessThanOrEqual(3)
    // Wrapped all the same: the few words the mounts are over by are inside
    // what is kept back for the words that come after them.
    expect(typeof outcome).toBe('string')
  }, 120000)

  it('goes to the level the steps would have run out at', () => {
    // Two repositories, three submodule git directories and two: whatever a
    // step is asked to give back, the steps end where every one of the five
    // and both `modules` directories are denied whole, and nowhere short of
    // it or past it.
    const repository = (
      modulesDir: string,
      names: string[],
    ): SubmoduleDenyPlan['repositories'][number] => ({
      modulesDir,
      wholeDirDenies: [],
      gitDirs: names.map(name => ({
        gitDir: join(modulesDir, name),
        denyPaths: [
          join(modulesDir, name, 'hooks'),
          join(modulesDir, name, 'config'),
        ],
        escapingDenyPaths: [],
        linkedEntryDirs: [],
        chainHops: [],
      })),
    })
    const repositories = [
      repository(join(dir, 'repo', '.git', 'modules'), ['a', 'b', 'c']),
      repository(join(dir, 'repo', 'nested', '.git', 'modules'), ['d', 'e']),
    ]
    const plan: SubmoduleDenyPlan = {
      denyPaths: repositories.flatMap(each =>
        each.gitDirs.flatMap(submodule => submodule.denyPaths),
      ),
      repositories,
      chainHops: [],
    }

    for (const mountsOver of [1, 3, 100]) {
      let level = NO_COLLAPSE
      for (
        let deeper = collapseFurther(plan, level, mountsOver);
        deeper !== undefined;
        deeper = collapseFurther(plan, level, mountsOver)
      ) {
        level = deeper
      }
      expect(collapseEverything(plan)).toEqual(level)
    }
    expect(collapseEverything(plan)).toEqual({
      wholeGitDirs: 5,
      wholeModulesDirs: 2,
    })
  })

  it('still stops at the first level that fits where stepping does give words back', async () => {
    // A hundred submodule git directories the command MAY write, in a budget
    // that holds some of them precise and not all: each one degraded gives
    // back the twelve words of its four denies, so every twelve words less
    // to spend on mounts degrades exactly one more, and never the lot.
    const { checkout, subs } = makeSuperproject(join(dir, 'repo'), 100)
    process.chdir(checkout)

    const preciseAt = async (
      spentWords: number,
    ): Promise<{ precise: string[]; passes: number }> => {
      const { outcome, passes } = await wrapCountingPasses(checkout, spentWords)
      expect(outcome).toBeTypeOf('string')
      const denied = new Set(mountWords(outcome as string))
      const precise = subs.filter(sub => denied.has(join(sub, 'hooks')))
      // The first in sorted order keep their precise denies, and every one
      // after them is one read-only bind of the git directory.
      expect(precise).toEqual(subs.slice(0, precise.length))
      for (const sub of subs.slice(precise.length)) {
        expect(denied.has(sub)).toBe(true)
      }
      return { precise, passes }
    }

    const spent = 8000
    const first = await preciseAt(spent)
    expect(first.precise.length).toBeGreaterThan(1)
    expect(first.precise.length).toBeLessThan(subs.length - 1)
    // Measured, not predicted: the level the count alone starts from is not
    // the one that fits, and the passes after it are what find that.
    expect(first.passes).toBeGreaterThan(1)
    expect(first.passes).toBeLessThanOrEqual(4)

    const tighter = await preciseAt(spent + 12)
    expect(tighter.precise.length).toBe(first.precise.length - 1)
    const looser = await preciseAt(spent - 12)
    expect(looser.precise.length).toBe(first.precise.length + 1)
  }, 120000)
})

/**
 * A symlink chain, and the path a `.git` pointer or a `commondir` names, are
 * walked a component at a time, and how many components there are is up to
 * whoever wrote them: a link's target runs to four thousand bytes and a
 * pointer file to a megabyte. The walk of them spends the same budget the
 * rest of the enumeration does, and running out of it is the same refusal.
 */
describe.if(!isWindows)(
  'Chains and pointer values inside the time budget',
  () => {
    let dir: string
    const savedCwd = process.cwd()

    beforeEach(() => {
      dir = realpathSync(mkdtempSync(join(tmpdir(), 'srt-chain-budget-')))
    })

    afterEach(() => {
      process.chdir(savedCwd)
      cleanupBwrapMountPoints({ force: true })
      rmSync(dir, { recursive: true, force: true })
    })

    /** What a wrap was refused with, or undefined where it was not refused:
     *  the command it would have returned is not what these tests look at. */
    async function refusalOf(
      params: Parameters<typeof wrapCommandWithSandboxLinux>[0],
    ): Promise<LinuxSandboxProfileError | undefined> {
      try {
        await wrapCommandWithSandboxLinux(params)
        return undefined
      } catch (err) {
        if (err instanceof LinuxSandboxProfileError) return err
        throw err
      }
    }

    /** One step of a path that goes nowhere: into `a` and back out. */
    const DETOUR = 'a/../'

    /**
     * Sixteen links in `holder`, each leading to the next through eight hundred
     * detours and the last to a real directory: a chain the kernel follows in
     * one stat, and a walk by hand takes some thirteen thousand lstats for.
     * Sixteen is well inside the forty links the kernel follows, so that a
     * stat through the chain answers the same way every time. Returns the
     * first link.
     */
    function makeLongChain(holder: string): string {
      const links = 16
      mkdirSync(join(holder, 'a'), { recursive: true })
      mkdirSync(join(holder, 'end'))
      for (let i = 0; i < links; i++) {
        symlinkSync(
          DETOUR.repeat(800) + (i + 1 < links ? `l${i + 1}` : 'end'),
          join(holder, `l${i}`),
        )
      }
      return join(holder, 'l0')
    }

    /** A repository whose `.git/modules` holds `count` git directories with
     *  every entry that is denied a link into one long chain. */
    function makeChainedSubmodules(count: number): {
      checkout: string
      gitDir: string
    } {
      const checkout = join(dir, 'repo')
      const gitDir = makeGitDir(join(checkout, '.git'))
      const chain = makeLongChain(join(gitDir, 'chain'))
      for (let i = 0; i < count; i++) {
        const sub = join(gitDir, 'modules', `s${String(i).padStart(3, '0')}`)
        mkdirSync(sub, { recursive: true })
        writeFileSync(join(sub, 'HEAD'), 'ref: refs/heads/main')
        for (const entry of [
          'hooks',
          'config',
          'commondir',
          'config.worktree',
        ]) {
          symlinkSync(chain, join(sub, entry))
        }
      }
      return { checkout, gitDir }
    }

    it('stops in the middle of a chain rather than at the end of the last one', () => {
      // Forty-eight git directories, four chains each: some two and a half
      // million lstats, which is seconds of this process doing nothing else.
      const { gitDir } = makeChainedSubmodules(48)

      const started = Date.now()
      const error = (() => {
        try {
          gitDirTreeDenies(gitDir, false, { deadline: Date.now() + 100 })
          return undefined
        } catch (err) {
          return err
        }
      })()
      const took = Date.now() - started

      expect(error).toBeInstanceOf(SubmoduleWalkBudgetError)
      expect((error as SubmoduleWalkBudgetError).code).toBe(
        'submodule_walk_budget_exhausted',
      )
      expect((error as Error).message).toContain(join(gitDir, 'modules'))
      expect(took).toBeLessThan(2000)
    }, 120000)

    it.if(isLinux)(
      'refuses the wrap where the chains outlast its budget',
      async () => {
        const { checkout, gitDir } = makeChainedSubmodules(48)
        process.chdir(checkout)

        const started = Date.now()
        const refusal = await refusalOf({
          command: 'true',
          needsNetworkRestriction: false,
          readConfig: undefined,
          writeConfig: { allowOnly: [checkout], denyWithinAllow: [] },
          ripgrepConfig: { command: 'rg', timeoutMs: 100 },
        })
        const took = Date.now() - started

        expect(refusal?.code).toBe('deny_scan_failed')
        expect(refusal?.message).toContain(join(gitDir, 'modules'))
        expect(took).toBeLessThan(2000)
      },
      120000,
    )

    it('stops in the middle of the path a pointer names', () => {
      // A megabyte of detours, just under the size git accepts for a `.git`
      // file: two hundred thousand lstats for one pointer.
      const checkout = join(dir, 'checkout')
      mkdirSync(join(checkout, 'a'), { recursive: true })
      makeGitDir(join(checkout, 'gd'))
      const pointer = join(checkout, '.git')
      writeFileSync(pointer, `gitdir: ${DETOUR.repeat(200000)}gd\n`)

      // Time enough to start on it and not to finish: what stops the walk is
      // the look at the clock it takes as the components go by.
      const error = (() => {
        try {
          gitFileDenies(pointer, false, Date.now() + 25)
          return undefined
        } catch (err) {
          return err
        }
      })()
      expect(error).toBeInstanceOf(SubmoduleWalkBudgetError)
      expect((error as Error).message).toContain('path components still to go')
      // The value itself is not what the message carries.
      expect((error as Error).message.length).toBeLessThan(2000)

      // A budget already spent stops it before the file is read at all, and
      // stops at a `.git` file that is no pointer as well: that one starts no
      // walk, and a tree full of them is still as many reads as there are.
      expect(() => gitFileDenies(pointer, false, Date.now() - 1)).toThrow(
        SubmoduleWalkBudgetError,
      )
      const plain = join(dir, 'plain', '.git')
      mkdirSync(join(dir, 'plain'))
      writeFileSync(plain, 'not a pointer\n')
      expect(gitFileDenies(plain, false).denyPaths).toEqual([plain])
      expect(() => gitFileDenies(plain, false, Date.now() - 1)).toThrow(
        SubmoduleWalkBudgetError,
      )
      // Given the time, it is walked to its end like any other.
      expect(gitFileDenies(pointer, false).denyPaths).toContain(
        join(checkout, 'gd', 'hooks'),
      )
    }, 120000)

    it.if(isLinux)(
      'gives the pointer files a scan lists one budget between them',
      async () => {
        // One large pointer, and forty names for it: a hard link costs a
        // command nothing, and each name is a `.git` file the scan lists.
        const checkout = join(dir, 'repo')
        makeGitDir(join(checkout, '.git'))
        const first = join(checkout, 'w00')
        mkdirSync(join(first, 'a'), { recursive: true })
        writeFileSync(
          join(first, '.git'),
          `gitdir: ${DETOUR.repeat(100000)}gd\n`,
        )
        const pointers = [join(first, '.git')]
        for (let i = 1; i < 40; i++) {
          const worktree = join(checkout, `w${String(i).padStart(2, '0')}`)
          mkdirSync(join(worktree, 'a'), { recursive: true })
          linkSync(join(first, '.git'), join(worktree, '.git'))
          pointers.push(join(worktree, '.git'))
        }
        // A stand-in for ripgrep that lists them and exits, so that what the
        // budget is spent on is the pointers and not the scan.
        const scan = join(dir, 'scan.sh')
        writeFileSync(
          scan,
          `#!/bin/sh\nprintf '%s\\0' ${pointers.map(p => JSON.stringify(p)).join(' ')}\n`,
          { mode: 0o755 },
        )
        process.chdir(checkout)

        const started = Date.now()
        const refusal = await refusalOf({
          command: 'true',
          needsNetworkRestriction: false,
          readConfig: undefined,
          writeConfig: { allowOnly: [checkout], denyWithinAllow: [] },
          ripgrepConfig: { command: scan, timeoutMs: 500 },
        })
        const took = Date.now() - started

        expect(refusal?.code).toBe('deny_scan_failed')
        // The pointers' budget, not the scan's own timeout.
        expect(refusal?.message).not.toContain('did not finish')
        expect(refusal?.message).toContain(checkout)
        expect(took).toBeLessThan(4000)
      },
      120000,
    )

    it('resolves an ordinary chain exactly as it always has', () => {
      // hooks -> ../first -> second -> .githooks: three links, short targets.
      const gitDir = makeGitDir(join(dir, 'repo', '.git'))
      const landing = join(dir, 'repo', '.githooks')
      const first = join(dir, 'repo', 'first')
      const second = join(dir, 'repo', 'second')
      mkdirSync(landing, { recursive: true })
      symlinkSync('.githooks', second)
      symlinkSync('second', first)
      rmSync(join(gitDir, 'hooks'), { recursive: true })
      symlinkSync('../first', join(gitDir, 'hooks'))

      const expected: GitDirDenies = {
        denyPaths: [
          join(gitDir, 'hooks'),
          landing,
          first,
          second,
          join(gitDir, 'commondir'),
          join(gitDir, 'config'),
          join(gitDir, 'config.worktree'),
        ],
        escapingDenyPaths: [landing, first, second],
        linkedEntryDirs: [gitDir],
        chainHops: [first, second].map(link => ({
          kind: 'entry',
          chain: 'resolved',
          source: join(gitDir, 'hooks'),
          link,
          holder: join(dir, 'repo'),
        })),
      }
      expect(gitDirDenies(gitDir, false)).toEqual(expected)
      expect(gitDirDenies(gitDir, false, Date.now() + 60000)).toEqual(expected)

      // And the same chain in a pointer's value: through a linked directory
      // to the git directory behind it.
      const real = makeGitDir(join(dir, 'real', 'gd'))
      symlinkSync(join(dir, 'real'), join(dir, 'repo', 'through'))
      const pointer = join(dir, 'repo', 'worktree', '.git')
      mkdirSync(join(dir, 'repo', 'worktree'))
      writeFileSync(pointer, 'gitdir: ../through/gd\n')
      const through = join(dir, 'repo', 'through')
      const expectedPointer: GitDirDenies = {
        denyPaths: [
          pointer,
          through,
          join(through, 'gd', 'hooks'),
          join(through, 'gd', 'commondir'),
          join(through, 'gd', 'config'),
          join(through, 'gd', 'config.worktree'),
        ],
        escapingDenyPaths: [],
        linkedEntryDirs: [],
        chainHops: [
          {
            kind: 'pointer',
            chain: 'resolved',
            source: pointer,
            link: through,
            holder: join(dir, 'repo'),
          },
        ],
      }
      expect(real).toBe(join(dir, 'real', 'gd'))
      expect(gitFileDenies(pointer, false)).toEqual(expectedPointer)
      expect(gitFileDenies(pointer, false, Date.now() + 60000)).toEqual(
        expectedPointer,
      )
    })
  },
)
