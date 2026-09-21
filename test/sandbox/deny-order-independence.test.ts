import { describe, it, expect, beforeEach, afterEach } from 'bun:test'
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import {
  wrapCommandWithSandboxLinux,
  cleanupBwrapMountPoints,
} from '../../src/sandbox/linux-sandbox-utils.js'
import { isLinux } from '../helpers/platform.js'
import { mountsOf } from '../helpers/bwrap-argv.js'

/**
 * The empty directory mounted over an absent deny path's first missing
 * component is made fresh for the wrap that needs one, so its name differs
 * between any two wraps of the same configuration and says nothing about
 * the plan.
 */
const EMPTY_MOUNT_SOURCE = /\S*claude-empty-[A-Za-z0-9]+/g

/**
 * A profile's mounts as the multiset two passes are compared on: the
 * mandatory-deny scan takes ripgrep's hits in thread order, so emission
 * order varies from one wrap to the next on one revision too.
 */
function mountMultiset(command: string): string[] {
  return mountsOf(command)
    .map(mount => mount.replace(EMPTY_MOUNT_SOURCE, '<empty mount source>'))
    .sort()
}

/**
 * A deny set protects the same paths whichever order the caller wrote it
 * down in. The mounts a profile carries must therefore be the same for a
 * denyWithinAllow list and for its reverse.
 *
 * They were not. The deny loop deduplicates entries on the path they resolve
 * to, and skips an existing deny path that a denied directory above it
 * already re-binds read-only -- but it asked whether the entry IN HAND was
 * reached through a symlink, and only the first spelling of a destination
 * ever reaches that question. A deny set naming one destination twice, once
 * directly and once through a symlink, under a deny on a directory above it,
 * therefore bound that destination read-only or not according to which of
 * the two spellings the caller happened to list first.
 *
 * Neither answer left anything writable: the covering directory's own
 * read-only bind is emitted after every allow bind and holds the whole
 * subtree either way. What was wrong is that the plan was not a function of
 * the deny SET, which is what makes it testable at all.
 */
describe.if(isLinux)('Deny order independence', () => {
  let BASE: string
  const savedCwd = process.cwd()

  beforeEach(() => {
    // realpathSync so the deny paths the wrapper resolves are spelled the way
    // the fixture spells them, even where tmpdir is itself a symlink.
    BASE = realpathSync(mkdtempSync(join(tmpdir(), 'deny-order-')))
  })

  afterEach(() => {
    process.chdir(savedCwd)
    cleanupBwrapMountPoints({ force: true })
    rmSync(BASE, { recursive: true, force: true })
  })

  /**
   * The mounts one configuration produces with its deny list as given and
   * reversed. The tree is rebuilt before each pass: a wrap leaves mount
   * points on the host for absent deny paths, and the second pass must not
   * see the first pass's.
   */
  async function bothOrders(
    tree: () => void,
    allowOnly: string[],
    denyWithinAllow: string[],
  ): Promise<{ forward: string[]; reversed: string[] }> {
    const pass = async (denies: string[]): Promise<string[]> => {
      rmSync(BASE, { recursive: true, force: true })
      mkdirSync(BASE, { recursive: true })
      tree()
      // Outside the allowed area, so the mandatory-deny scan adds no binds
      // of its own to reason about.
      process.chdir(BASE)
      const mounts = mountMultiset(
        await wrapCommandWithSandboxLinux({
          command: 'true',
          needsNetworkRestriction: false,
          writeConfig: { allowOnly, denyWithinAllow: denies },
        }),
      )
      process.chdir(savedCwd)
      cleanupBwrapMountPoints({ force: true })
      return mounts
    }
    return {
      forward: await pass(denyWithinAllow),
      reversed: await pass([...denyWithinAllow].reverse()),
    }
  }

  it('binds a file named both directly and through a symlink, either order', async () => {
    const AREA = join(BASE, 'area')
    const FILE = join(AREA, 'settings.json')
    const LINK = join(AREA, 'link')
    const { forward, reversed } = await bothOrders(
      () => {
        mkdirSync(AREA, { recursive: true })
        writeFileSync(FILE, '{}\n')
        symlinkSync(FILE, LINK)
      },
      [AREA],
      // The deny on AREA is what covers FILE. Without it neither spelling is
      // skipped and both orders agree for free.
      [AREA, FILE, LINK],
    )
    expect(reversed).toEqual(forward)
    // Both orders give the answer the deny set gives when only the symlinked
    // spelling is listed: the destination keeps its own bind.
    expect(forward).toContain(`--ro-bind ${FILE} ${FILE}`)
    expect(forward).toContain(`--ro-bind ${AREA} ${AREA}`)
  })

  it('binds a directory named through a chain that leaves the allowed area, either order', async () => {
    const AREA = join(BASE, 'area')
    const HOOKS = join(AREA, 'repo', '.git', 'hooks')
    const OUTSIDE = join(BASE, 'outside')
    const { forward, reversed } = await bothOrders(
      () => {
        mkdirSync(HOOKS, { recursive: true })
        mkdirSync(OUTSIDE, { recursive: true })
        // area/away -> outside, outside/to-hooks -> area/repo/.git/hooks: the
        // chain leaves the allowed area and comes back into it.
        symlinkSync(HOOKS, join(OUTSIDE, 'to-hooks'))
        symlinkSync(OUTSIDE, join(AREA, 'away'))
      },
      [AREA],
      [AREA, HOOKS, join(AREA, 'away', 'to-hooks')],
    )
    expect(reversed).toEqual(forward)
    expect(forward).toContain(`--ro-bind ${HOOKS} ${HOOKS}`)
    expect(forward).toContain(`--ro-bind ${AREA} ${AREA}`)
  })

  it('leaves a deny set with no covering directory alone, either order', async () => {
    const AREA = join(BASE, 'area')
    const FILE = join(AREA, 'settings.json')
    const LINK = join(AREA, 'link')
    const { forward, reversed } = await bothOrders(
      () => {
        mkdirSync(AREA, { recursive: true })
        writeFileSync(FILE, '{}\n')
        symlinkSync(FILE, LINK)
      },
      [AREA],
      [FILE, LINK],
    )
    expect(reversed).toEqual(forward)
    expect(forward).toContain(`--ro-bind ${FILE} ${FILE}`)
  })
})

/**
 * The same property over random trees. The shapes are the ones the deny loop
 * branches on: symlinks to directories and to files, dangling links, a self
 * cycle, git directories whose hooks are reached through a link, worktree
 * pointer files, leftover read-only mount points, absent leaves under absent
 * parents; with a random allow list, a random deny list (entries sometimes
 * spelled with a trailing slash), a random read-deny list on top, and the
 * working directory inside the tree.
 *
 * Bounded and seeded, so a failing tree replays: this range is one the
 * unfixed loop disagreed with itself on.
 */
describe.if(isLinux)('Deny order independence over random trees', () => {
  const FIRST_SEED = 800
  const SEEDS = 120

  let ROOT: string
  const savedCwd = process.cwd()

  beforeEach(() => {
    ROOT = realpathSync(mkdtempSync(join(tmpdir(), 'deny-order-trees-')))
  })

  afterEach(() => {
    process.chdir(savedCwd)
    cleanupBwrapMountPoints({ force: true })
    rmSync(ROOT, { recursive: true, force: true })
  })

  /** mulberry32, so a tree is a function of its seed alone. */
  function rng(seed: number): () => number {
    let a = seed >>> 0
    return () => {
      a = (a + 0x6d2b79f5) >>> 0
      let t = Math.imul(a ^ (a >>> 15), 1 | a)
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296
    }
  }

  const NAMES = [
    '.git',
    'hooks',
    'config',
    'config.worktree',
    'commondir',
    'modules',
    'worktrees',
    'src',
    'sub',
    'deep',
    'a',
    'b',
    '.env',
    '.bashrc',
    '.gitconfig',
    'link',
    'dangling',
    'loop',
    'stale',
    'file.txt',
  ]

  type Tree = {
    dirs: string[]
    files: string[]
    links: string[]
    absent: string[]
  }

  type Config = {
    allowOnly: string[]
    denyWithinAllow: string[]
    readConfig?: { denyOnly: string[]; allowWithinDeny: string[] }
    allowGitConfig: boolean
    allowAllUnixSockets: boolean
  }

  /**
   * Rebuild ROOT from scratch for `seed`. Any one mkdir, write or symlink can
   * lose the name to something the generator already put there, which is a
   * shape worth having: such a failure just leaves that entry out.
   */
  function buildTree(seed: number): Tree {
    const r = rng(seed)
    const pick = <T>(xs: T[]): T => xs[Math.floor(r() * xs.length)] as T
    rmSync(ROOT, { recursive: true, force: true })
    mkdirSync(ROOT, { recursive: true })
    const dirs: string[] = [ROOT]
    const files: string[] = []
    const links: string[] = []
    const absent: string[] = []

    const dirCount = 3 + Math.floor(r() * 8)
    for (let i = 0; i < dirCount; i++) {
      const dir = join(pick(dirs), pick(NAMES))
      try {
        mkdirSync(dir, { recursive: true })
        dirs.push(dir)
      } catch {
        // a file already sits there
      }
    }
    const fileCount = 3 + Math.floor(r() * 8)
    for (let i = 0; i < fileCount; i++) {
      const file = join(pick(dirs), pick(NAMES))
      try {
        writeFileSync(file, 'x')
        files.push(file)
      } catch {
        // a directory already sits there
      }
    }

    // A git directory, sometimes with a commondir, sometimes named by a
    // worktree pointer file, sometimes with its hooks behind a link.
    const gitDir = join(pick(dirs), '.git')
    try {
      mkdirSync(join(gitDir, 'hooks'), { recursive: true })
      writeFileSync(join(gitDir, 'config'), '[core]\n')
      writeFileSync(join(gitDir, 'HEAD'), 'ref: refs/heads/main\n')
      dirs.push(gitDir, join(gitDir, 'hooks'))
      if (r() < 0.4) {
        writeFileSync(join(gitDir, 'commondir'), '../..\n')
        files.push(join(gitDir, 'commondir'))
      }
      if (r() < 0.4) {
        const pointerDir = join(ROOT, 'wt')
        mkdirSync(pointerDir, { recursive: true })
        writeFileSync(join(pointerDir, '.git'), `gitdir: ${gitDir}\n`)
        dirs.push(pointerDir)
        files.push(join(pointerDir, '.git'))
      }
      if (r() < 0.4) {
        const real = join(ROOT, 'realhooks')
        mkdirSync(real, { recursive: true })
        rmSync(join(gitDir, 'hooks'), { recursive: true, force: true })
        symlinkSync(real, join(gitDir, 'hooks'))
        links.push(join(gitDir, 'hooks'))
        dirs.push(real)
      }
    } catch {
      // something is already there
    }

    // Symlinks: to a directory, to a file, dangling, and a self cycle.
    const linkCount = 1 + Math.floor(r() * 5)
    for (let i = 0; i < linkCount; i++) {
      const link = join(pick(dirs), `l${i}`)
      const kind = r()
      try {
        if (kind < 0.35) symlinkSync(pick(dirs), link)
        else if (kind < 0.6 && files.length > 0) symlinkSync(pick(files), link)
        else if (kind < 0.85) symlinkSync(join(ROOT, 'nowhere'), link)
        else symlinkSync(link, link)
        links.push(link)
      } catch {
        // name taken
      }
    }

    // Mount points an earlier sandbox would have left behind.
    const staleCount = Math.floor(r() * 3)
    for (let i = 0; i < staleCount; i++) {
      const stale = join(pick(dirs), `.stale${i}`)
      try {
        writeFileSync(stale, '')
        chmodSync(stale, 0o444)
        files.push(stale)
      } catch {
        // name taken
      }
    }

    // Paths that do not exist: a leaf, and a leaf under an absent parent.
    for (let i = 0; i < 3; i++) {
      absent.push(join(pick(dirs), `absent${i}`))
      absent.push(join(pick(dirs), `gone${i}`, 'leaf'))
    }
    return { dirs, files, links, absent }
  }

  /** The configuration for `seed`, drawn from what its tree holds. */
  function configFor(seed: number, tree: Tree): Config {
    const r = rng(seed ^ 0x5bf03635)
    const pick = <T>(xs: T[]): T => xs[Math.floor(r() * xs.length)] as T
    const some = <T>(xs: T[], count: number): T[] => {
      const out: T[] = []
      for (let i = 0; i < count && xs.length > 0; i++) out.push(pick(xs))
      return out
    }
    const all = [...tree.dirs, ...tree.files, ...tree.links, ...tree.absent]
    const allowOnly =
      r() < 0.15 ? [ROOT] : some(tree.dirs, 1 + Math.floor(r() * 2))
    const globs = ['/*.txt', '/**/*.env', '/[ab].*', '/?.txt', '/**/hooks']
    const denyOnly = some(all, Math.floor(r() * 3)).map(p =>
      r() < 0.3 ? p + pick(globs) : p,
    )
    return {
      allowOnly,
      denyWithinAllow: some(all, Math.floor(r() * 6)).map(p =>
        r() < 0.15 ? `${p}/` : p,
      ),
      readConfig:
        r() < 0.4
          ? undefined
          : { denyOnly, allowWithinDeny: some(tree.dirs, Math.floor(r() * 2)) },
      allowGitConfig: r() < 0.25,
      allowAllUnixSockets: r() < 0.5,
    }
  }

  it('produces the same mounts for a deny list and its reverse', async () => {
    /** The tree is rebuilt before each pass: a wrap leaves mount points on
     * the host for absent deny paths, and the second pass must not see the
     * first pass's. Undefined for a tree whose deny list has nothing to
     * reorder. */
    const pass = async (
      seed: number,
      reverse: boolean,
    ): Promise<string[] | undefined> => {
      const config = configFor(seed, buildTree(seed))
      if (config.denyWithinAllow.length < 2) return undefined
      process.chdir(ROOT)
      const mounts = mountMultiset(
        await wrapCommandWithSandboxLinux({
          command: 'true',
          needsNetworkRestriction: false,
          readConfig: config.readConfig,
          writeConfig: {
            allowOnly: config.allowOnly,
            denyWithinAllow: reverse
              ? [...config.denyWithinAllow].reverse()
              : config.denyWithinAllow,
          },
          allowGitConfig: config.allowGitConfig,
          allowAllUnixSockets: config.allowAllUnixSockets,
        }),
      )
      process.chdir(savedCwd)
      cleanupBwrapMountPoints({ force: true })
      return mounts
    }

    const disagreed: number[] = []
    let compared = 0
    for (let i = 0; i < SEEDS; i++) {
      const seed = FIRST_SEED + i
      const forward = await pass(seed, false)
      if (forward === undefined) continue
      const reversed = await pass(seed, true)
      if (reversed === undefined) continue
      compared++
      if (forward.join('\n') !== reversed.join('\n')) disagreed.push(seed)
    }
    expect(disagreed).toEqual([])
    // A generator that stopped producing trees with two deny entries would
    // pass for free.
    expect(compared).toBeGreaterThan(SEEDS / 2)
  }, 300000)
})
