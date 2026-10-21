import { describe, it, expect, beforeEach, afterEach, spyOn } from 'bun:test'
import * as fs from 'fs'
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
import { basename, join } from 'node:path'
import { lastMountAt } from '../helpers/bwrap-argv.js'
import { bwrapCanNamespace } from '../helpers/bwrap-namespace.js'
import { isLinux, isWindows } from '../helpers/platform.js'
import { macGetMandatoryDenyEntries } from '../../src/sandbox/macos-sandbox-utils.js'
import {
  cleanupBwrapMountPoints,
  wrapCommandWithSandboxLinux,
} from '../../src/sandbox/linux-sandbox-utils.js'
import {
  GitMetadataError,
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
    // Each of the names, as the emptiest thing of its kind a command can leave.
    const markers = ['HEAD', 'config', 'commondir', 'hooks/', 'objects/']
    const expected: string[] = []
    for (const marker of markers) {
      const vendor = join(modules, `vendor-${basename(marker)}`)
      const lib = makeGitDir(join(vendor, 'lib'))
      if (marker.endsWith('/')) mkdirSync(join(vendor, marker))
      else writeFileSync(join(vendor, marker), '')
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
    for (const gitDir of expected) {
      expect(denies).toEqual(
        expect.arrayContaining(gitDirDenyPaths(gitDir, false)),
      )
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

  it('takes a marker for one only as the kind of entry git reads there', () => {
    // `x/config` and `x/HEAD`: each git directory is a DIRECTORY of that name.
    // Taken for a git directory, `x` would be denied its `config` whole, which
    // costs that submodule its git writes with no help from any command.
    const subs = ['HEAD', 'commondir', 'config'].map(name =>
      makeGitDir(join(modules, 'x', name)),
    )
    writeFileSync(join(modules, 'x', 'objects'), '')

    expect(submoduleGitDirs(modules).gitDirs).toEqual(subs)
  })

  it('finds a submodule named hooks, and denies it whole', () => {
    // A directory is what git reads there, so `x` is recorded as well.
    const x = join(modules, 'x')
    const sub = makeGitDir(join(x, 'hooks'))

    expect(submoduleGitDirs(modules).gitDirs).toEqual([x, sub])
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

    expect(submoduleGitDirs(modules).gitDirs).toEqual(expected.sort())
  })

  it('takes the modules of a git directory for what it holds', () => {
    // Where `lib` keeps its own submodules, and the submodule `vendor/modules`
    // once a command has left a `HEAD` in `vendor`: nothing tells the two apart.
    const lib = makeGitDir(join(modules, 'lib'))
    const nested = makeGitDir(join(lib, 'modules', 'nested'))
    const vendor = join(modules, 'vendor')
    const named = makeGitDir(join(vendor, 'modules'))
    writeFileSync(join(vendor, 'HEAD'), '')

    expect(submoduleGitDirs(modules).gitDirs).toEqual([
      lib,
      nested,
      vendor,
      named,
    ])
  })

  it('takes every entry of the modules of a git directory for a name', () => {
    // As in the directory it was asked to walk, whatever a command left beside
    // them: taken for git's own, `lfs` would hide the submodule `lfs/client`.
    const lib = makeGitDir(join(modules, 'lib'))
    const nested = makeGitDir(join(lib, 'modules', 'lfs', 'client'))
    writeFileSync(join(lib, 'modules', 'HEAD'), '')

    expect(submoduleGitDirs(modules).gitDirs).toEqual([
      lib,
      join(lib, 'modules'),
      nested,
    ])
  })

  describe.if(!isWindows)('a directory that links lead to as well', () => {
    /** A link to `target` on either side of every other name here, whichever
     *  way the walk goes through them. */
    function linkFromBothSides(target: string): void {
      for (const name of ['a', 'z']) {
        mkdirSync(join(modules, name), { recursive: true })
        symlinkSync(target, join(modules, name, 'link'))
      }
    }

    it('is listed once more at most, and each link held by its own name', () => {
      // How many links and how much they lead to are a command's to choose.
      const lib = makeGitDir(join(modules, 'lib'))
      linkFromBothSides('../lib')
      const list = spyOn(fs, 'readdirSync')
      try {
        const scan = submoduleGitDirs(modules)

        expect(scan.gitDirs).toContain(lib)
        expect(scan.gitDirs.length).toBeLessThanOrEqual(2)
        expect(scan.chainHops.map(hop => hop.link).sort()).toEqual([
          join(modules, 'a', 'link'),
          join(modules, 'z', 'link'),
        ])
        expect(
          list.mock.calls.filter(
            call => realpathSync(String(call[0])) === realpathSync(lib),
          ).length,
        ).toBeLessThanOrEqual(2)
      } finally {
        list.mockRestore()
      }
    })

    it('is listed once more at most where it is taken for what git keeps', () => {
      const store = join(modules, 'store')
      mkdirSync(store, { recursive: true })
      for (const name of ['a', 'b', 'y', 'z']) {
        const gitDir = join(modules, name)
        mkdirSync(gitDir)
        writeFileSync(join(gitDir, 'HEAD'), '')
        symlinkSync('../store', join(gitDir, 'objects'))
      }
      const list = spyOn(fs, 'readdirSync')
      try {
        submoduleGitDirs(modules)

        expect(
          list.mock.calls.filter(
            call => realpathSync(String(call[0])) === realpathSync(store),
          ).length,
        ).toBeLessThanOrEqual(2)
      } finally {
        list.mockRestore()
      }
    })

    it.if(process.getuid?.() !== 0)(
      'is denied whole where it is, where it cannot be listed',
      () => {
        // The name of the link holds the link, and on Linux is no deny at all.
        const locked = join(dir, 'locked')
        mkdirSync(locked)
        mkdirSync(modules)
        symlinkSync(locked, join(modules, 'link'))
        chmodSync(locked, 0o311)
        try {
          expect(submoduleGitDirs(modules).unreadableDirs).toEqual([
            realpathSync(locked),
          ])
        } finally {
          chmodSync(locked, 0o755)
        }
      },
    )

    it('is walked from where it is', () => {
      const lib = makeGitDir(join(modules, 'vendor', 'deep', 'lib'))
      linkFromBothSides('../vendor/deep')

      expect(submoduleGitDirs(modules).gitDirs).toContain(lib)
    })

    it('is so where the walk was asked for by another name itself', () => {
      makeGitDir(join(modules, 'vendor', 'deep', 'lib'))
      linkFromBothSides('../vendor/deep')
      symlinkSync(dir, `${dir}-alias`)
      try {
        expect(
          submoduleGitDirs(join(`${dir}-alias`, 'modules')).gitDirs,
        ).toContain(join(`${dir}-alias`, 'modules', 'vendor', 'deep', 'lib'))
      } finally {
        rmSync(`${dir}-alias`)
      }
    })

    it('is walked as each thing that it is reached as', () => {
      // All of it lies elsewhere, so nothing is walked from where it is.
      const lib = makeGitDir(join(dir, 'elsewhere', 'lib'))
      makeGitDir(join(lib, 'modules', 'lfs', 'client'))
      writeFileSync(join(lib, 'modules', 'HEAD'), '')
      linkFromBothSides(join(lib, 'modules'))
      symlinkSync(lib, join(modules, 'lib'))

      expect(submoduleGitDirs(modules).gitDirs).toContain(
        join(modules, 'lib', 'modules', 'lfs', 'client'),
      )
    })
  })

  it('takes no nested submodule named hooks for the hooks of a git directory', () => {
    // It would be denied whole, with no help from any command.
    const lib = makeGitDir(join(modules, 'lib'))
    const nested = ['hooks', 'objects'].map(name =>
      makeGitDir(join(lib, 'modules', name)),
    )

    expect(submoduleGitDirs(modules).gitDirs).toEqual([lib, ...nested])
  })

  it.if(!isWindows)('nor one that is kept behind a link', () => {
    const lib = makeGitDir(join(modules, 'lib'))
    mkdirSync(join(lib, 'modules'))
    symlinkSync(
      makeGitDir(join(dir, 'store', 'hooks.git')),
      join(lib, 'modules', 'hooks'),
    )

    expect(submoduleGitDirs(modules).gitDirs).toEqual([
      lib,
      join(lib, 'modules', 'hooks'),
    ])
  })

  describe.if(!isWindows)('what cannot be named', () => {
    const NO_TEXT = Buffer.from([0x63, 0x61, 0x66, 0xe9])

    it('has the directory holding a link to it denied whole, where nothing is there', () => {
      // A command can make one here, so it costs what any link here does, and
      // not every command after it.
      const linked = join(modules, 'linked')
      mkdirSync(linked, { recursive: true })
      symlinkSync(NO_TEXT, join(linked, 'x'))

      expect(submoduleGitDirs(modules)).toEqual({
        gitDirs: [],
        unreadableDirs: [linked],
        linkedEntryDirs: [],
        chainHops: [],
      })
    })

    it('has that directory denied where it really is', () => {
      // The name of a link holds the link, and on Linux is no deny at all.
      const store = join(dir, 'store')
      mkdirSync(store)
      mkdirSync(modules)
      symlinkSync(NO_TEXT, join(store, 'x'))
      symlinkSync(store, join(modules, 'link'))

      expect(submoduleGitDirs(modules).unreadableDirs).toEqual([store])
    })

    // The macOS file systems take no such name.
    it.if(isLinux)('has the directory holding it denied whole', () => {
      // Where it really is as well.
      const named = [join(modules, 'named'), join(dir, 'store')]
      for (const holder of named) {
        mkdirSync(holder, { recursive: true })
        mkdirSync(Buffer.concat([Buffer.from(`${holder}/`), NO_TEXT]))
      }
      symlinkSync(join(dir, 'store'), join(modules, 'link'))

      expect(submoduleGitDirs(modules).unreadableDirs).toEqual(named)
    })

    it.if(isLinux)(
      'passes over a link that leads to a file of such a name',
      () => {
        // As over any link to a file: git opens no git directory there.
        mkdirSync(modules)
        writeFileSync(Buffer.concat([Buffer.from(`${dir}/`), NO_TEXT]), '')
        symlinkSync(
          Buffer.concat([Buffer.from('../'), NO_TEXT]),
          join(modules, 'x'),
        )

        expect(submoduleGitDirs(modules)).toEqual({
          gitDirs: [],
          unreadableDirs: [],
          linkedEntryDirs: [],
          chainHops: [],
        })
      },
    )

    it.if(isLinux)('refuses where a link leads to it', () => {
      // What is there cannot be denied, and the host's git follows the link.
      mkdirSync(modules)
      mkdirSync(Buffer.concat([Buffer.from(`${dir}/`), NO_TEXT]))
      symlinkSync(
        Buffer.concat([Buffer.from('../'), NO_TEXT]),
        join(modules, 'x'),
      )

      expect(() => submoduleGitDirs(modules)).toThrow(GitMetadataError)
    })
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

  it.if(!isWindows && process.getuid?.() !== 0)(
    'fails closed where a link it cannot look behind really leads',
    () => {
      // `..` after a link is the parent of where the link leads, not of the
      // directory that holds it.
      const elsewhere = join(dir, 'elsewhere')
      const locked = join(elsewhere, 'locked')
      mkdirSync(join(elsewhere, 'deep'), { recursive: true })
      mkdirSync(join(locked, 'inner'), { recursive: true })
      mkdirSync(modules)
      symlinkSync(join(elsewhere, 'deep'), join(modules, 'via'))
      symlinkSync('via/../locked/inner', join(modules, 'x'))
      chmodSync(locked, 0o000)
      try {
        expect(submoduleGitDirs(modules).unreadableDirs).toEqual([locked])
      } finally {
        chmodSync(locked, 0o755)
      }
    },
  )

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
