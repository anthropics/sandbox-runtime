import { describe, it, expect, beforeEach, afterEach, spyOn } from 'bun:test'
import { spawnSync } from 'node:child_process'
import {
  chmodSync,
  existsSync,
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
import { lastMountAt } from '../helpers/bwrap-argv.js'
import { bwrapCanNamespace } from '../helpers/bwrap-namespace.js'
import { isLinux, isWindows } from '../helpers/platform.js'
import { macGetMandatoryDenyEntries } from '../../src/sandbox/macos-sandbox-utils.js'
import {
  cleanupBwrapMountPoints,
  wrapCommandWithSandboxLinux,
} from '../../src/sandbox/linux-sandbox-utils.js'
import {
  SubmoduleWalkBudgetError,
  gitDirDenyPaths,
  gitDirTreeDenies,
  gitDirTreeDenyPaths,
  submoduleGitDirs,
} from '../../src/sandbox/mandatory-deny-paths.js'

/**
 * The walk of a `.git/modules` where one directory is two things at once: a
 * git directory by what it holds, and a segment of a submodule's name by what
 * lies under it.
 *
 * A submodule named `vendor/lib` keeps its git directory at
 * `.git/modules/vendor/lib`, so `.git/modules/vendor` is an ordinary directory
 * a sandboxed command can write, and what makes a directory a git directory
 * to the walk is the NAME of one entry in it. A command that leaves a `HEAD`
 * in `vendor` must not end the walk there: the submodule beneath it would go
 * without its denies for every command after that one.
 */

/** The names the walk takes for what git itself keeps in a git directory. */
const GIT_OWN_NAMES = [
  'objects',
  'refs',
  'logs',
  'hooks',
  'info',
  'worktrees',
  'lfs',
  'rr-cache',
]

/** A submodule git directory as `git clone` leaves one. */
function makeGitDir(gitDir: string): string {
  mkdirSync(join(gitDir, 'hooks'), { recursive: true })
  mkdirSync(join(gitDir, 'objects'), { recursive: true })
  writeFileSync(join(gitDir, 'HEAD'), 'ref: refs/heads/main\n')
  writeFileSync(join(gitDir, 'config'), '[core]\n')
  return gitDir
}

describe('The .git/modules walk beneath what looks like a git directory', () => {
  let dir: string
  let modules: string

  beforeEach(() => {
    dir = realpathSync(mkdtempSync(join(tmpdir(), 'git-modules-walk-')))
    modules = join(dir, 'modules')
  })

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true })
  })

  it('finds the submodule beneath a name segment a command left a marker in', () => {
    // Each of the four names, as the emptiest thing a command can leave.
    const expected: string[] = []
    for (const marker of ['HEAD', 'config', 'hooks', 'objects']) {
      const vendor = join(modules, `vendor-${marker}`)
      const lib = makeGitDir(join(vendor, 'lib'))
      writeFileSync(join(vendor, marker), '')
      // The segment is recorded too. The markers only ever deny more, and a
      // HEAD alone is also what a git directory looks like with the rest of
      // it moved aside, so what the segment was denied by before it still is.
      expected.push(vendor, lib)
    }

    const scan = submoduleGitDirs(modules)

    expect(scan).toEqual({
      gitDirs: expected.sort(),
      unreadableDirs: [],
      linkedEntryDirs: [],
      chainHops: [],
    })
    const denies = gitDirTreeDenyPaths(gitDirTreeDenies(dir, false))
    for (const marker of ['HEAD', 'config', 'hooks', 'objects']) {
      const lib = join(modules, `vendor-${marker}`, 'lib')
      for (const deny of gitDirDenyPaths(lib, false)) {
        expect(denies).toContain(deny)
      }
    }
  })

  it('finds it several segments further down as well', () => {
    const deep = makeGitDir(join(modules, 'a', 'b', 'c', 'lib'))
    writeFileSync(join(modules, 'a', 'HEAD'), '')
    writeFileSync(join(modules, 'a', 'b', 'config'), '')

    expect(submoduleGitDirs(modules).gitDirs).toEqual([
      join(modules, 'a'),
      join(modules, 'a', 'b'),
      deep,
    ])
  })

  it('finds a submodule whose own name is one of the markers', () => {
    // `x/config`: the git directory is a DIRECTORY named config, which makes
    // `x` look like a git directory with no help from any command.
    const x = join(modules, 'x')
    const sub = makeGitDir(join(x, 'config'))

    const scan = submoduleGitDirs(modules)

    // Both. The deny `x` gets for its `config` is the submodule's git
    // directory whole, which is all the submodule had before and costs it its
    // git writes in the sandbox; its own hooks and config are now named too.
    expect(scan.gitDirs).toEqual([x, sub])
    const denies = gitDirTreeDenyPaths(gitDirTreeDenies(dir, false))
    for (const deny of gitDirDenyPaths(sub, false)) {
      expect(denies).toContain(deny)
    }
  })

  it('finds a submodule named like one of the directories git keeps, beneath such a segment', () => {
    // `vendor/lfs`, `vendor/refs` and the rest: not walked into where they
    // are git's own, which a `HEAD` left in `vendor` would otherwise make
    // them. What this file protects is what tells the two apart: git keeps
    // no `config` and no `hooks` in any of its own directories.
    const expected: string[] = []
    for (const name of GIT_OWN_NAMES) {
      const vendor = join(modules, `vendor-${name}`)
      const sub = makeGitDir(join(vendor, name))
      writeFileSync(join(vendor, 'HEAD'), '')
      expected.push(vendor, sub)
    }

    expect(submoduleGitDirs(modules).gitDirs).toEqual(expected.sort())
  })

  it('never takes the directory it was asked to walk for a git directory', () => {
    // A `.git/modules` is as writable as any segment under it, and its
    // entries are submodule names whatever else is left beside them.
    const expected = GIT_OWN_NAMES.map(name => makeGitDir(join(modules, name)))
    writeFileSync(join(modules, 'HEAD'), '')
    writeFileSync(join(modules, 'config'), '')
    const nested = makeGitDir(join(modules, 'objects', 'modules', 'refs'))
    writeFileSync(join(modules, 'objects', 'modules', 'HEAD'), '')

    expect(submoduleGitDirs(modules).gitDirs).toEqual(
      [...expected, nested].sort(),
    )
  })

  it('does not walk into what git itself keeps in a git directory', () => {
    // A real submodule git directory with everything in it that is large:
    // loose objects fanned out over 256 directories, refs and their logs, an
    // LFS store, rerere's cache and a linked worktree. Each holds something
    // shaped like a git directory, which a walk into it would record.
    const sub = makeGitDir(join(modules, 'sub'))
    for (let i = 0; i < 256; i++) {
      mkdirSync(join(sub, 'objects', i.toString(16).padStart(2, '0')))
    }
    mkdirSync(join(sub, 'objects', 'pack'))
    mkdirSync(join(sub, 'objects', 'info'))
    mkdirSync(join(sub, 'refs', 'heads'), { recursive: true })
    mkdirSync(join(sub, 'logs', 'refs', 'heads'), { recursive: true })
    // Every repository with a reflog has this one, and an LFS store keeps
    // its own `objects`: neither makes a git directory of what holds it.
    writeFileSync(join(sub, 'logs', 'HEAD'), '')
    mkdirSync(join(sub, 'lfs', 'objects'), { recursive: true })
    mkdirSync(join(sub, 'info'))
    for (const inside of [
      'objects/ab',
      'objects/pack',
      'refs/heads',
      'logs/refs',
      'lfs/objects',
      'hooks',
      'info',
      'rr-cache',
      'worktrees',
    ]) {
      makeGitDir(join(sub, inside, 'planted'))
    }

    expect(submoduleGitDirs(modules)).toEqual({
      gitDirs: [sub],
      unreadableDirs: [],
      linkedEntryDirs: [],
      chainHops: [],
    })
  })

  it.if(!isWindows)(
    'does not follow a link that is one of those directories',
    () => {
      // A rerere cache shared between clones. Following an entry that is a
      // symlink denies the directory holding it whole, which here would be an
      // ordinary submodule's git directory.
      const sub = makeGitDir(join(modules, 'sub'))
      const shared = join(dir, 'shared-rr-cache')
      mkdirSync(shared)
      symlinkSync(shared, join(sub, 'rr-cache'))

      expect(submoduleGitDirs(modules)).toEqual({
        gitDirs: [sub],
        unreadableDirs: [],
        linkedEntryDirs: [],
        chainHops: [],
      })
    },
  )

  it.if(!isWindows)(
    'leaves a link at one of a git directory own entries to that directory',
    () => {
      // `config`, `commondir` and `config.worktree` are read as the git
      // directory's entries, a link at one included, by what denies them, and
      // both ends of such a link are held there. Followed here as well, the
      // same chain would be walked a second time and what it leads to taken
      // for a submodule of its own.
      const sub = makeGitDir(join(modules, 'sub'))
      const elsewhere = makeGitDir(join(dir, 'elsewhere'))
      rmSync(join(sub, 'config'))
      symlinkSync(elsewhere, join(sub, 'config'))
      symlinkSync(elsewhere, join(sub, 'commondir'))
      symlinkSync(elsewhere, join(sub, 'config.worktree'))

      expect(submoduleGitDirs(modules)).toEqual({
        gitDirs: [sub],
        unreadableDirs: [],
        linkedEntryDirs: [],
        chainHops: [],
      })
    },
  )

  it('walks what else a git directory holds, and finds nothing in an ordinary one', () => {
    // Directories that are neither git's own large ones nor `modules`: the
    // empty `branches` of an older template, a rebase in progress.
    const sub = makeGitDir(join(modules, 'sub'))
    mkdirSync(join(sub, 'branches'))
    mkdirSync(join(sub, 'rebase-merge'))
    writeFileSync(join(sub, 'rebase-merge', 'head-name'), 'refs/heads/main\n')
    const inner = makeGitDir(join(sub, 'modules', 'dep'))

    expect(submoduleGitDirs(modules)).toEqual({
      gitDirs: [sub, inner],
      unreadableDirs: [],
      linkedEntryDirs: [],
      chainHops: [],
    })
  })

  it.if(!isWindows)(
    'follows a symlinked entry beneath such a segment like any other',
    () => {
      const elsewhere = makeGitDir(join(dir, 'elsewhere'))
      const vendor = join(modules, 'vendor')
      mkdirSync(vendor, { recursive: true })
      symlinkSync(elsewhere, join(vendor, 'lib'))
      writeFileSync(join(vendor, 'HEAD'), '')

      const scan = submoduleGitDirs(modules)

      expect(scan.gitDirs).toEqual([vendor, join(vendor, 'lib')])
      expect(scan.linkedEntryDirs).toEqual([vendor])
    },
  )

  it.if(!isWindows && process.getuid?.() !== 0)(
    'denies a directory beneath such a segment that it could not list',
    () => {
      const vendor = join(modules, 'vendor')
      const locked = join(vendor, 'locked')
      makeGitDir(join(locked, 'deep'))
      writeFileSync(join(vendor, 'HEAD'), '')
      chmodSync(locked, 0o000)
      try {
        const scan = submoduleGitDirs(modules)

        expect(scan.gitDirs).toEqual([vendor])
        expect(scan.unreadableDirs).toEqual([locked])
      } finally {
        chmodSync(locked, 0o755)
      }
    },
  )

  it('keeps looking at the clock beneath such a segment', () => {
    // A thousand entries under a segment that looks like a git directory,
    // and a clock that moves once each time the walk looks at it: the walk
    // looks once per so many entries, so it gets past the root on the first
    // look and has to run out somewhere among the thousand.
    const vendor = join(modules, 'vendor')
    mkdirSync(vendor, { recursive: true })
    writeFileSync(join(vendor, 'HEAD'), '')
    for (let i = 0; i < 1000; i++) {
      writeFileSync(join(vendor, `f${i}`), '')
    }

    let now = 0
    const clock = spyOn(Date, 'now').mockImplementation(() => now++)
    try {
      expect(() => submoduleGitDirs(modules, 1)).toThrow(
        SubmoduleWalkBudgetError,
      )
    } finally {
      clock.mockRestore()
    }
  })

  it.if(!isWindows)(
    'names the literals of such a submodule for Seatbelt as well',
    () => {
      // Seatbelt's glob for `.git/modules/*` stops at one segment, so the
      // literals read off this walk are all a `vendor/lib` has there.
      const checkout = join(dir, 'repo')
      makeGitDir(join(checkout, '.git'))
      const vendor = join(checkout, '.git', 'modules', 'vendor')
      const lib = makeGitDir(join(vendor, 'lib'))
      const saved = process.cwd()
      process.chdir(checkout)
      try {
        const literals = (): string[] =>
          macGetMandatoryDenyEntries(false)
            .filter(entry => !entry.glob)
            .map(entry => entry.path)

        const before = literals()
        writeFileSync(join(vendor, 'HEAD'), '')
        const after = literals()

        for (const deny of gitDirDenyPaths(lib, false)) {
          expect(before).toContain(deny)
          expect(after).toContain(deny)
        }
      } finally {
        process.chdir(saved)
      }
    },
  )
})

describe.if(isLinux)(
  'A marker left in a segment of a submodule name, under bubblewrap',
  () => {
    const LIVE = bwrapCanNamespace()
    let dir: string
    let checkout: string
    let vendor: string
    let lib: string
    const savedCwd = process.cwd()

    beforeEach(() => {
      dir = realpathSync(mkdtempSync(join(tmpdir(), 'git-modules-walk-live-')))
      // A superproject with one submodule named `vendor/lib`, and no checkout
      // of it: the scan of the work tree has no `.git` pointer file to reach
      // the git directory by, so the walk of `.git/modules` is what covers it.
      checkout = join(dir, 'repo')
      makeGitDir(join(checkout, '.git'))
      vendor = join(checkout, '.git', 'modules', 'vendor')
      lib = makeGitDir(join(vendor, 'lib'))
      writeFileSync(join(checkout, 'work.txt'), 'one\n')
      process.chdir(checkout)
    })

    afterEach(() => {
      process.chdir(savedCwd)
      cleanupBwrapMountPoints({ force: true })
      rmSync(dir, { recursive: true, force: true })
    })

    function wrap(command: string): Promise<string> {
      return wrapCommandWithSandboxLinux({
        command,
        needsNetworkRestriction: false,
        allowAllUnixSockets: true,
        readConfig: undefined,
        writeConfig: { allowOnly: [checkout], denyWithinAllow: [] },
      })
    }

    it('still binds the hooks and config of the submodule beneath it read-only', async () => {
      writeFileSync(join(vendor, 'HEAD'), '')

      const command = await wrap('true')

      for (const name of ['hooks', 'config']) {
        const deny = join(lib, name)
        expect(lastMountAt(command, deny)).toBe(`--ro-bind ${deny} ${deny}`)
      }
      // The two that are not there take a mount all the same: a placeholder
      // git reads as it reads the file's absence.
      for (const name of ['commondir', 'config.worktree']) {
        expect(lastMountAt(command, join(lib, name))).toBeDefined()
      }
    })

    it.if(LIVE)(
      'holds them against the command after the one that left the marker',
      async () => {
        const run = (command: string) =>
          spawnSync(command, {
            shell: true,
            encoding: 'utf8',
            timeout: 30000,
            cwd: checkout,
            env: { ...process.env, LC_ALL: 'C' },
          })

        // `vendor` is no git directory and nothing denies a write to it.
        const first = run(
          await wrap(
            'echo BOOTED; : > .git/modules/vendor/HEAD && echo PLANTED',
          ),
        )
        expect(first.stdout).toContain('BOOTED')
        expect(first.stdout).toContain('PLANTED')
        expect(existsSync(join(vendor, 'HEAD'))).toBe(true)

        // No cleanup in between: the second wrap walks the tree exactly as
        // the first command left it.
        const second = run(
          await wrap(
            'echo BOOTED; ' +
              "{ echo '[core]' >> .git/modules/vendor/lib/config; } 2>&1 || echo CONFIG_DENIED; " +
              '{ echo x > .git/modules/vendor/lib/hooks/pre-commit; } 2>&1 || echo HOOK_DENIED; ' +
              'echo two >> work.txt && echo WORK_WRITTEN; ' +
              'echo DONE',
          ),
        )
        expect(second.stdout).toContain('BOOTED')
        expect(second.stdout).toContain('DONE')
        expect(second.stdout).toContain('CONFIG_DENIED')
        expect(second.stdout).toContain('HOOK_DENIED')
        expect(second.stdout).toContain('Read-only file system')
        expect(second.stdout).toContain('WORK_WRITTEN')
        expect(readFileSync(join(lib, 'config'), 'utf8')).toBe('[core]\n')
        expect(existsSync(join(lib, 'hooks', 'pre-commit'))).toBe(false)
        expect(readFileSync(join(checkout, 'work.txt'), 'utf8')).toBe(
          'one\ntwo\n',
        )
      },
      60000,
    )
  },
)
