import { describe, it, expect, beforeEach, afterEach } from 'bun:test'
import { spawnSync } from 'node:child_process'
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { bwrapCanNamespace } from '../helpers/bwrap-namespace.js'
import { isLinux, isWindows } from '../helpers/platform.js'
import { macGetMandatoryDenyEntries } from '../../src/sandbox/macos-sandbox-utils.js'
import {
  cleanupBwrapMountPoints,
  linuxGetCwdMandatoryDenyPaths,
  wrapCommandWithSandboxLinux,
} from '../../src/sandbox/linux-sandbox-utils.js'
import {
  GitMetadataError,
  SubmoduleWalkBudgetError,
  gitDirDenyPaths,
  gitDirTreeDenies,
  gitDirTreeDenyPaths,
  gitFileDenyPaths,
} from '../../src/sandbox/mandatory-deny-paths.js'
import * as denyCollapse from '../../src/sandbox/linux-deny-collapse.js'
import type { SubmoduleDenyPlan } from '../../src/sandbox/linux-deny-collapse.js'

/**
 * A linked worktree's git directory, `<main>/.git/worktrees/<id>`, is reached
 * from two ends: through the `.git` pointer file of the worktree's checkout,
 * and from the repository that keeps it. Its `commondir` names the directory
 * whose hooks and config git runs in that worktree, so both ends have to hold
 * it, and neither may depend on an entry a wrapped command can move aside.
 */
describe.if(!isWindows)('Linked worktree git directories', () => {
  /** Everything the live arms need: a sandbox that starts. */
  const LIVE = isLinux && bwrapCanNamespace()
  const HAS_GIT = Bun.which('git') !== null
  const NOT_ROOT = process.getuid?.() !== 0
  /** For a case that has git itself make its fixture, several spawns of it. */
  const GIT_FIXTURE_TIMEOUT_MS = 60000
  let dir: string
  const savedCwd = process.cwd()

  beforeEach(() => {
    // Real, so a temporary directory that is itself reached through a
    // symlink does not make every path here two paths.
    dir = realpathSync(mkdtempSync(join(tmpdir(), 'git-worktree-denies-')))
  })

  afterEach(() => {
    process.chdir(savedCwd)
    cleanupBwrapMountPoints({ force: true })
    rmSync(dir, { recursive: true, force: true })
  })

  /** A directory git would accept as a repository's git directory. */
  function makeGitDir(gitDir: string): string {
    mkdirSync(join(gitDir, 'hooks'), { recursive: true })
    mkdirSync(join(gitDir, 'objects'), { recursive: true })
    mkdirSync(join(gitDir, 'refs'), { recursive: true })
    writeFileSync(join(gitDir, 'HEAD'), 'ref: refs/heads/main\n')
    writeFileSync(join(gitDir, 'config'), '[core]\n')
    return gitDir
  }

  /**
   * What `git worktree add` leaves: the worktree's git directory under the
   * main one, and the checkout whose `.git` file names it.
   */
  function makeLinkedWorktree(
    mainGitDir: string,
    id: string,
    checkout: string,
  ): { worktreeGitDir: string; pointer: string } {
    const worktreeGitDir = join(mainGitDir, 'worktrees', id)
    mkdirSync(worktreeGitDir, { recursive: true })
    writeFileSync(join(worktreeGitDir, 'HEAD'), 'ref: refs/heads/wt\n')
    writeFileSync(join(worktreeGitDir, 'commondir'), '../..\n')
    writeFileSync(join(worktreeGitDir, 'gitdir'), `${join(checkout, '.git')}\n`)
    mkdirSync(checkout, { recursive: true })
    const pointer = join(checkout, '.git')
    writeFileSync(pointer, `gitdir: ${worktreeGitDir}\n`)
    return { worktreeGitDir, pointer }
  }

  function git(cwd: string, args: string[]): void {
    const result = spawnSync(
      'git',
      [
        '-c',
        'user.name=t',
        '-c',
        'user.email=t@t',
        '-c',
        'commit.gpgsign=false',
        '-c',
        'core.hooksPath=/dev/null',
        '-c',
        'init.defaultBranch=main',
        ...args,
      ],
      {
        cwd,
        encoding: 'utf8',
        timeout: 30000,
        env: {
          ...process.env,
          HOME: dir,
          GIT_CONFIG_NOSYSTEM: '1',
          GIT_CONFIG_GLOBAL: '/dev/null',
          LC_ALL: 'C',
        },
      },
    )
    if (result.status !== 0) {
      throw new Error(`git ${args.join(' ')} failed: ${result.stderr}`)
    }
  }

  /**
   * A repository with one commit and a linked worktree checked out BESIDE it,
   * both made by git itself: the worktree's `.git` file is outside the main
   * checkout, and only its git directory is inside.
   */
  function gitRepoWithWorktreeBeside(): {
    main: string
    worktreeGitDir: string
  } {
    const main = join(dir, 'main')
    mkdirSync(main, { recursive: true })
    git(main, ['init', '-q', '.'])
    writeFileSync(join(main, 'index.js'), 'console.log(1)\n')
    git(main, ['add', 'index.js'])
    git(main, ['commit', '-q', '-m', 'one'])
    git(main, ['worktree', 'add', '-q', '-b', 'wt', join(dir, 'wt')])
    return { main, worktreeGitDir: join(main, '.git', 'worktrees', 'wt') }
  }

  function wrap(command: string, allowOnly: string[]): Promise<string> {
    return wrapCommandWithSandboxLinux({
      command,
      needsNetworkRestriction: false,
      allowAllUnixSockets: true,
      readConfig: undefined,
      writeConfig: { allowOnly, denyWithinAllow: [] },
    })
  }

  function run(wrapped: string, cwd: string): string {
    const result = spawnSync(wrapped, {
      shell: true,
      encoding: 'utf8',
      timeout: 60000,
      cwd,
    })
    return `${result.stdout}${result.stderr}`
  }

  describe('reached through the pointer', () => {
    it('keeps the denies behind the pointer with HEAD moved aside', () => {
      // HEAD is the one marker a worktree's git directory holds, and it is
      // no deny path: a command can rename it. Where the directory is says
      // what it is all the same.
      const mainGitDir = makeGitDir(join(dir, 'main', '.git'))
      const { worktreeGitDir, pointer } = makeLinkedWorktree(
        mainGitDir,
        'wt',
        join(dir, 'wt'),
      )
      renameSync(join(worktreeGitDir, 'HEAD'), join(worktreeGitDir, 'H'))

      expect(gitFileDenyPaths(pointer, false)).toEqual([
        pointer,
        ...gitDirDenyPaths(worktreeGitDir, false),
        // And the commondir is still followed: the hooks a commit in the
        // worktree runs are the main repository's.
        ...gitDirDenyPaths(mainGitDir, false),
      ])
    })

    it("keeps them for a bare repository's worktree, by the commondir it still holds", () => {
      // `main.git/worktrees/wt` is nowhere only git puts a directory, so what
      // it holds has to say: `commondir` is there beside HEAD, and unlike
      // HEAD it is a deny path, which a command cannot move aside.
      const bare = makeGitDir(join(dir, 'main.git'))
      const { worktreeGitDir, pointer } = makeLinkedWorktree(
        bare,
        'wt',
        join(dir, 'wt'),
      )
      renameSync(join(worktreeGitDir, 'HEAD'), join(worktreeGitDir, 'H'))

      expect(gitFileDenyPaths(pointer, false)).toEqual([
        pointer,
        ...gitDirDenyPaths(worktreeGitDir, false),
        ...gitDirDenyPaths(bare, false),
      ])
    })

    it('carries them into the macOS entries where the working directory is the worktree', () => {
      // Profile generation is pure string building, so this runs anywhere.
      const mainGitDir = makeGitDir(join(dir, 'main', '.git'))
      const checkout = join(dir, 'wt')
      const { worktreeGitDir } = makeLinkedWorktree(mainGitDir, 'wt', checkout)
      renameSync(join(worktreeGitDir, 'HEAD'), join(worktreeGitDir, 'H'))
      process.chdir(checkout)

      const literals = macGetMandatoryDenyEntries(false, [dir])
        .filter(entry => !entry.glob)
        .map(entry => entry.path)

      expect(literals).toContain(join(worktreeGitDir, 'commondir'))
      expect(literals).toContain(join(mainGitDir, 'hooks'))
      expect(literals).toContain(join(mainGitDir, 'config'))
    })

    it('keeps them with nothing left in the directory at all', () => {
      const mainGitDir = makeGitDir(join(dir, 'main', '.git'))
      const { worktreeGitDir, pointer } = makeLinkedWorktree(
        mainGitDir,
        'wt',
        join(dir, 'wt'),
      )
      for (const name of ['HEAD', 'commondir', 'gitdir']) {
        rmSync(join(worktreeGitDir, name))
      }

      expect(gitFileDenyPaths(pointer, false)).toEqual([
        pointer,
        ...gitDirDenyPaths(worktreeGitDir, false),
      ])
    })

    it('keeps the denies of a submodule git directory with its markers moved aside', () => {
      const mainGitDir = makeGitDir(join(dir, 'main', '.git'))
      const submodule = makeGitDir(join(mainGitDir, 'modules', 'vendor', 'lib'))
      renameSync(join(submodule, 'HEAD'), join(submodule, 'H'))
      renameSync(join(submodule, 'objects'), join(submodule, 'o'))
      const checkout = join(dir, 'main', 'vendor', 'lib')
      mkdirSync(checkout, { recursive: true })
      const pointer = join(checkout, '.git')
      writeFileSync(pointer, 'gitdir: ../../.git/modules/vendor/lib\n')

      expect(gitFileDenyPaths(pointer, false)).toEqual([
        pointer,
        ...gitDirDenyPaths(submodule, false),
      ])
    })

    it('goes by where the directory really is, not by how the pointer spells it', () => {
      // `x/.git` is a link a command made, so the path the pointer writes has
      // the shape of a worktree's git directory and the directory it reaches
      // is an ordinary one of the project.
      const project = join(dir, 'project')
      mkdirSync(join(project, 'web', 'worktrees', 'a', 'config'), {
        recursive: true,
      })
      mkdirSync(join(project, 'x'), { recursive: true })
      symlinkSync('../web', join(project, 'x', '.git'))
      mkdirSync(join(project, 'y'), { recursive: true })
      const pointer = join(project, 'y', '.git')
      writeFileSync(pointer, 'gitdir: ../x/.git/worktrees/a\n')

      const denyPaths = gitFileDenyPaths(pointer, false)

      expect(denyPaths).toContain(pointer)
      expect(
        denyPaths.filter(denyPath =>
          realPathOrSelf(denyPath).startsWith(join(project, 'web') + '/'),
        ),
      ).toEqual([])
    })

    it('leaves a worktrees directory that no .git holds alone', () => {
      mkdirSync(join(dir, 'data', 'worktrees', 'a', 'config'), {
        recursive: true,
      })
      mkdirSync(join(dir, 'checkout'), { recursive: true })
      const pointer = join(dir, 'checkout', '.git')
      writeFileSync(pointer, 'gitdir: ../data/worktrees/a\n')

      expect(gitFileDenyPaths(pointer, false)).toEqual([pointer])
    })

    for (const mainGitDirName of ['.git', 'main.git']) {
      it.if(LIVE)(
        `holds commondir for the command after one that moved HEAD aside (${mainGitDirName})`,
        async () => {
          // The working directory is the linked worktree, and the write roots
          // hold the main repository as well: the layout a commit from inside
          // the sandbox needs. Once for a repository with a work tree of its
          // own, once for a bare one.
          const mainGitDir = makeGitDir(join(dir, 'main', mainGitDirName))
          const checkout = join(dir, 'wt')
          const { worktreeGitDir } = makeLinkedWorktree(
            mainGitDir,
            'wt',
            checkout,
          )
          const commondir = join(worktreeGitDir, 'commondir')
          process.chdir(checkout)

          const first = run(
            await wrap(
              `mv ${join(worktreeGitDir, 'HEAD')} ${join(worktreeGitDir, 'H')} && echo MOVED`,
              [dir],
            ),
            checkout,
          )
          expect(first).toContain('MOVED')
          expect(existsSync(join(worktreeGitDir, 'HEAD'))).toBe(false)
          cleanupBwrapMountPoints({ force: true })

          const second = run(
            await wrap(
              'echo BOOTED; ' +
                `echo ../../../planted > ${commondir} || echo COMMONDIR_HELD; ` +
                `mkdir ${join(mainGitDir, 'hooks', 'x')} || echo MAIN_HOOKS_HELD; ` +
                'echo ok > notes.txt && echo WORK_TREE_WRITTEN',
              [dir],
            ),
            checkout,
          )

          expect(second).toContain('BOOTED')
          expect(second).toContain('COMMONDIR_HELD')
          expect(second).toContain('MAIN_HOOKS_HELD')
          expect(second).toContain('WORK_TREE_WRITTEN')
          expect(readFileSync(commondir, 'utf8')).toBe('../..\n')
          expect(readFileSync(join(checkout, 'notes.txt'), 'utf8')).toBe('ok\n')
        },
        120000,
      )
    }
  })

  describe('a git directory kept outside any .git', () => {
    // Where it is says nothing about one of these, so what it holds has to,
    // and one marker has to be enough: neither of the two below holds both a
    // HEAD and an objects.
    it("is followed where it is a bare repository's linked worktree", () => {
      // HEAD and commondir, and no objects of its own. A repository made with
      // --separate-git-dir keeps its linked worktrees the same way.
      const bare = makeGitDir(join(dir, 'main.git'))
      const { worktreeGitDir, pointer } = makeLinkedWorktree(
        bare,
        'wt',
        join(dir, 'wt'),
      )

      expect(gitFileDenyPaths(pointer, false)).toEqual([
        pointer,
        ...gitDirDenyPaths(worktreeGitDir, false),
        ...gitDirDenyPaths(bare, false),
      ])
    })

    it('is followed where its objects live elsewhere', () => {
      // HEAD and refs, which is all git itself asks of the directory when the
      // object store is named by the environment.
      const gitDir = join(dir, 'store')
      mkdirSync(join(gitDir, 'refs'), { recursive: true })
      writeFileSync(join(gitDir, 'HEAD'), 'ref: refs/heads/main\n')
      mkdirSync(join(dir, 'checkout'), { recursive: true })
      const pointer = join(dir, 'checkout', '.git')
      writeFileSync(pointer, 'gitdir: ../store\n')

      expect(gitFileDenyPaths(pointer, false)).toEqual([
        pointer,
        ...gitDirDenyPaths(gitDir, false),
      ])
    })
  })

  describe('reached from the repository that keeps it', () => {
    /** What is denied inside a worktree's git directory from this end. */
    function heldFiles(worktreeGitDir: string): string[] {
      return ['commondir', 'config.worktree', 'gitdir'].map(name =>
        join(worktreeGitDir, name),
      )
    }

    it.if(HAS_GIT)(
      'denies commondir, gitdir and config.worktree of a worktree checked out elsewhere',
      () => {
        const { main, worktreeGitDir } = gitRepoWithWorktreeBeside()

        const denyPaths = gitDirTreeDenyPaths(
          gitDirTreeDenies(join(main, '.git'), false),
        )

        for (const held of heldFiles(worktreeGitDir)) {
          expect(denyPaths).toContain(held)
        }
        // Nothing else in there: HEAD, index and logs are what git in that
        // worktree writes on every checkout and commit.
        expect(
          denyPaths.filter(denyPath => denyPath.startsWith(worktreeGitDir)),
        ).toEqual(heldFiles(worktreeGitDir))
      },
      GIT_FIXTURE_TIMEOUT_MS,
    )

    it.if(HAS_GIT)(
      'leaves config.worktree where config writes are allowed',
      () => {
        const { main, worktreeGitDir } = gitRepoWithWorktreeBeside()

        const denyPaths = gitDirTreeDenyPaths(
          gitDirTreeDenies(join(main, '.git'), true),
        )

        expect(denyPaths).toContain(join(worktreeGitDir, 'commondir'))
        expect(denyPaths).toContain(join(worktreeGitDir, 'gitdir'))
        expect(denyPaths).not.toContain(join(worktreeGitDir, 'config.worktree'))
      },
      GIT_FIXTURE_TIMEOUT_MS,
    )

    it.if(HAS_GIT && isLinux)(
      'carries them into the Linux deny list',
      () => {
        const { main, worktreeGitDir } = gitRepoWithWorktreeBeside()
        process.chdir(main)

        const denyPaths = linuxGetCwdMandatoryDenyPaths(false, [main])

        for (const held of heldFiles(worktreeGitDir)) {
          expect(denyPaths).toContain(held)
        }
      },
      GIT_FIXTURE_TIMEOUT_MS,
    )

    it.if(HAS_GIT)(
      'carries them into the macOS entries as literals',
      () => {
        // Profile generation is pure string building, so this runs anywhere.
        const { main, worktreeGitDir } = gitRepoWithWorktreeBeside()
        process.chdir(main)

        const literals = macGetMandatoryDenyEntries(false, [main])
          .filter(entry => !entry.glob)
          .map(entry => entry.path)

        for (const held of heldFiles(worktreeGitDir)) {
          expect(literals).toContain(held)
        }
        expect(literals.length).toBe(new Set(literals).size)
      },
      GIT_FIXTURE_TIMEOUT_MS,
    )

    it.if(HAS_GIT && LIVE)(
      'refuses a rewrite of commondir, and leaves the rest of the repository writable',
      async () => {
        const { main, worktreeGitDir } = gitRepoWithWorktreeBeside()
        const commondir = join(worktreeGitDir, 'commondir')
        const before = readFileSync(commondir, 'utf8')
        process.chdir(main)

        const output = run(
          await wrap(
            'echo BOOTED; ' +
              `echo ../../../planted > ${commondir} || echo COMMONDIR_HELD; ` +
              `echo /elsewhere/.git > ${join(worktreeGitDir, 'gitdir')} || echo GITDIR_HELD; ` +
              `echo '[core]' > ${join(worktreeGitDir, 'config.worktree')} || echo WORKTREE_CONFIG_HELD; ` +
              `mv ${worktreeGitDir} ${worktreeGitDir}.aside || echo DIRECTORY_HELD; ` +
              `echo x > ${join(worktreeGitDir, 'ORIG_HEAD')} && echo REST_WRITTEN; ` +
              'echo ok > notes.txt && echo WORK_TREE_WRITTEN',
            [main],
          ),
          main,
        )

        expect(output).toContain('BOOTED')
        expect(output).toContain('COMMONDIR_HELD')
        expect(output).toContain('GITDIR_HELD')
        expect(output).toContain('WORKTREE_CONFIG_HELD')
        expect(output).toContain('DIRECTORY_HELD')
        expect(output).toContain('REST_WRITTEN')
        expect(output).toContain('WORK_TREE_WRITTEN')
        expect(readFileSync(commondir, 'utf8')).toBe(before)

        // The mount point an absent config.worktree took goes with the rest.
        cleanupBwrapMountPoints({ force: true })
        expect(existsSync(join(worktreeGitDir, 'config.worktree'))).toBe(false)
      },
      120000,
    )

    it('denies what the commondir of one names, where that is another git directory', () => {
      const mainGitDir = makeGitDir(join(dir, 'main', '.git'))
      const { worktreeGitDir } = makeLinkedWorktree(
        mainGitDir,
        'wt',
        join(dir, 'wt'),
      )
      const other = makeGitDir(join(dir, 'other.git'))
      writeFileSync(join(worktreeGitDir, 'commondir'), `${other}\n`)

      const denyPaths = gitDirTreeDenyPaths(gitDirTreeDenies(mainGitDir, false))

      for (const held of gitDirDenyPaths(other, false)) {
        expect(denyPaths).toContain(held)
      }
    })

    it('refuses on a commondir whose target cannot be worked out, as from a pointer', () => {
      // The directory whose hooks git runs in that worktree is then unknown,
      // and sandboxing on the rest would leave it writable.
      const mainGitDir = makeGitDir(join(dir, 'main', '.git'))
      const { worktreeGitDir } = makeLinkedWorktree(
        mainGitDir,
        'wt',
        join(dir, 'wt'),
      )
      writeFileSync(
        join(worktreeGitDir, 'commondir'),
        Buffer.from([0x2f, 0xff, 0xfe, 0x0a]),
      )

      expect(() => gitDirTreeDenies(mainGitDir, false)).toThrow(
        GitMetadataError,
      )
    })

    it('names nothing twice for a commondir that names the repository itself', () => {
      const mainGitDir = makeGitDir(join(dir, 'main', '.git'))
      makeLinkedWorktree(mainGitDir, 'wt', join(dir, 'wt'))

      const denyPaths = gitDirTreeDenyPaths(gitDirTreeDenies(mainGitDir, false))

      expect(denyPaths.length).toBe(new Set(denyPaths).size)
    })

    it('holds a worktree git directory that holds nothing yet', () => {
      // Where it is says what it is, from this end as from the other.
      const mainGitDir = makeGitDir(join(dir, 'main', '.git'))
      const empty = join(mainGitDir, 'worktrees', 'empty')
      mkdirSync(empty, { recursive: true })

      const denyPaths = gitDirTreeDenyPaths(gitDirTreeDenies(mainGitDir, false))

      for (const held of heldFiles(empty)) {
        expect(denyPaths).toContain(held)
      }
    })

    it('denies the directory holding an entry that is a symlink, and what it leads to', () => {
      const mainGitDir = makeGitDir(join(dir, 'main', '.git'))
      const worktrees = join(mainGitDir, 'worktrees')
      mkdirSync(worktrees, { recursive: true })
      const elsewhere = join(dir, 'elsewhere')
      mkdirSync(elsewhere, { recursive: true })
      symlinkSync(elsewhere, join(worktrees, 'linked'))

      const tree = gitDirTreeDenies(mainGitDir, false)

      expect(tree.linkedEntryDirs).toContain(worktrees)
      expect(gitDirTreeDenyPaths(tree)).toContain(
        join(worktrees, 'linked', 'commondir'),
      )
    })

    it.if(NOT_ROOT)('denies a worktrees directory it cannot list whole', () => {
      const mainGitDir = makeGitDir(join(dir, 'main', '.git'))
      makeLinkedWorktree(mainGitDir, 'wt', join(dir, 'wt'))
      const worktrees = join(mainGitDir, 'worktrees')
      chmodSync(worktrees, 0o000)
      try {
        const tree = gitDirTreeDenies(mainGitDir, false)

        expect(tree.unreadableDirs).toContain(worktrees)
        expect(gitDirTreeDenyPaths(tree)).toContain(worktrees)
      } finally {
        chmodSync(worktrees, 0o755)
      }
    })

    it('refuses rather than hand back a listing that ran out of its time', () => {
      const mainGitDir = makeGitDir(join(dir, 'main', '.git'))
      makeLinkedWorktree(mainGitDir, 'wt', join(dir, 'wt'))

      expect(() =>
        gitDirTreeDenies(mainGitDir, false, { deadline: Date.now() - 1 }),
      ).toThrow(SubmoduleWalkBudgetError)
    })

    it("denies the same for a linked worktree a submodule's git directory keeps", () => {
      // `git worktree add` inside a submodule puts the worktree's git
      // directory under the SUBMODULE's, `.git/modules/<name>/worktrees/<id>`,
      // and its `commondir` is as writable there as under the repository's
      // own `.git/worktrees`.
      const mainGitDir = makeGitDir(join(dir, 'main', '.git'))
      const submodule = makeGitDir(join(mainGitDir, 'modules', 'lib'))
      const { worktreeGitDir } = makeLinkedWorktree(
        submodule,
        'wt',
        join(dir, 'lib-wt'),
      )

      const denies = gitDirTreeDenies(mainGitDir, false)
      const denyPaths = gitDirTreeDenyPaths(denies)

      for (const name of ['commondir', 'gitdir', 'config.worktree']) {
        expect(denyPaths).toContain(join(worktreeGitDir, name))
      }
      // They belong to the submodule, so a bind of its git directory, which
      // they are all under, stands in for them where the profile is degraded.
      const found = denies.submodules.find(each => each.gitDir === submodule)
      expect(found?.denyPaths).toContain(join(worktreeGitDir, 'commondir'))
      expect(found?.escapingDenyPaths).not.toContain(
        join(worktreeGitDir, 'commondir'),
      )
    })

    it("carries a submodule's linked worktrees into the macOS entries", () => {
      const checkout = join(dir, 'main')
      const mainGitDir = makeGitDir(join(checkout, '.git'))
      const submodule = makeGitDir(join(mainGitDir, 'modules', 'lib'))
      const { worktreeGitDir } = makeLinkedWorktree(
        submodule,
        'wt',
        join(dir, 'lib-wt'),
      )

      process.chdir(checkout)
      const literals = macGetMandatoryDenyEntries(false, [checkout])
        .filter(entry => !entry.glob)
        .map(entry => entry.path)

      expect(literals).toContain(join(worktreeGitDir, 'commondir'))
      expect(literals).toContain(join(worktreeGitDir, 'gitdir'))
    })

    it('costs a submodule with no linked worktrees nothing', () => {
      const mainGitDir = makeGitDir(join(dir, 'main', '.git'))
      const submodule = makeGitDir(join(mainGitDir, 'modules', 'lib'))

      const denies = gitDirTreeDenies(mainGitDir, false)

      expect(gitDirTreeDenyPaths(denies)).toEqual([
        ...gitDirDenyPaths(mainGitDir, false),
        ...gitDirDenyPaths(submodule, false),
      ])
    })

    it('costs a repository with no linked worktrees nothing', () => {
      // An absent `.git/worktrees` is never denied: a mount point planted at
      // one stops `git worktree add` working in that repository.
      const mainGitDir = makeGitDir(join(dir, 'main', '.git'))
      const denies = gitDirTreeDenies(mainGitDir, false)

      expect(gitDirTreeDenyPaths(denies)).toEqual(
        gitDirDenyPaths(mainGitDir, false),
      )
      expect(denyCollapse.repositoryWorktrees(denies)).toBeUndefined()
    })
  })

  describe('past what the profile can carry', () => {
    /** The plan a wrap builds for one repository that has no submodules. */
    function planFor(mainGitDir: string): SubmoduleDenyPlan {
      const denies = gitDirTreeDenies(mainGitDir, false)
      expect(denyCollapse.repositorySubmodules(denies)).toBeUndefined()
      const worktrees = denyCollapse.repositoryWorktrees(denies)
      if (worktrees === undefined) throw new Error('no linked worktrees found')
      return {
        denyPaths: gitDirTreeDenyPaths(denies),
        repositories: [worktrees],
        chainHops: denies.chainHops,
      }
    }

    it("folds a worktree's git directory into one bind, and keeps what its commondir names", () => {
      const mainGitDir = makeGitDir(join(dir, 'main', '.git'))
      const first = makeLinkedWorktree(mainGitDir, 'a', join(dir, 'a'))
      const last = makeLinkedWorktree(mainGitDir, 'b', join(dir, 'b'))
      const other = makeGitDir(join(dir, 'other.git'))
      writeFileSync(join(last.worktreeGitDir, 'commondir'), `${other}\n`)
      const plan = planFor(mainGitDir)

      const denies = denyCollapse.collapsedDenyPaths(plan, {
        wholeGitDirs: 1,
        wholeModulesDirs: 0,
      })

      // The last in sorted order is the one degraded.
      expect(denies).toContain(last.worktreeGitDir)
      expect(denies).not.toContain(join(last.worktreeGitDir, 'commondir'))
      expect(denies).toContain(join(first.worktreeGitDir, 'commondir'))
      expect(denies).not.toContain(first.worktreeGitDir)
      // No bind of the worktree's git directory covers these.
      for (const kept of [
        ...gitDirDenyPaths(other, false),
        ...gitDirDenyPaths(mainGitDir, false),
      ]) {
        expect(denies).toContain(kept)
      }
    })

    it('takes every one of them with a bind of worktrees, and says which it was', () => {
      const mainGitDir = makeGitDir(join(dir, 'main', '.git'))
      const first = makeLinkedWorktree(mainGitDir, 'a', join(dir, 'a'))
      makeLinkedWorktree(mainGitDir, 'b', join(dir, 'b'))
      const plan = planFor(mainGitDir)
      const level = { wholeGitDirs: 2, wholeModulesDirs: 1 }

      const denies = denyCollapse.collapsedDenyPaths(plan, level)

      expect(denies).toContain(join(mainGitDir, 'worktrees'))
      expect(denies).not.toContain(first.worktreeGitDir)
      expect(denies).not.toContain(join(first.worktreeGitDir, 'commondir'))
      for (const kept of gitDirDenyPaths(mainGitDir, false)) {
        expect(denies).toContain(kept)
      }
      const told = denyCollapse.describeCollapse(plan, level)
      expect(told).toContain('2 of the 2 linked worktree git directories')
      expect(told).toContain(join(mainGitDir, 'worktrees'))
      expect(told).not.toContain('submodule')
    })

    it.if(isLinux)(
      'degrades a worktrees directory a command filled rather than refusing every command after it',
      async () => {
        // Nine hundred, each three denies and a pin: past what bubblewrap
        // parses, so the tail is one read-only bind each.
        const main = join(dir, 'main')
        const mainGitDir = makeGitDir(join(main, '.git'))
        const worktreeGitDirs: string[] = []
        for (let i = 0; i < 900; i++) {
          const id = `w${String(i).padStart(5, '0')}`
          worktreeGitDirs.push(
            makeLinkedWorktree(mainGitDir, id, join(dir, 'checkouts', id))
              .worktreeGitDir,
          )
        }
        const precise = worktreeGitDirs[0] as string
        const collapsed = worktreeGitDirs[worktreeGitDirs.length - 1] as string
        process.chdir(main)

        const command = await wrap(
          'echo BOOTED; ' +
            `echo x > ${join(collapsed, 'commondir')} || echo COLLAPSED_HELD; ` +
            `echo x > ${join(precise, 'commondir')} || echo PRECISE_HELD; ` +
            `echo x > ${join(precise, 'ORIG_HEAD')} && echo PRECISE_REST_WRITTEN; ` +
            'echo ok > notes.txt && echo WORK_TREE_WRITTEN',
          [main],
        )

        const words = mountWords(command)
        expect(words.length).toBeLessThan(9000)
        const mounted = (dest: string): boolean =>
          words.some(
            (word, at) =>
              word === '--ro-bind' &&
              words[at + 1] === dest &&
              words[at + 2] === dest,
          )
        expect(mounted(join(precise, 'commondir'))).toBe(true)
        expect(mounted(join(collapsed, 'commondir'))).toBe(false)
        expect(mounted(collapsed)).toBe(true)

        if (LIVE) {
          const output = run(command, main)
          expect(output).toContain('BOOTED')
          expect(output).toContain('COLLAPSED_HELD')
          expect(output).toContain('PRECISE_HELD')
          expect(output).toContain('PRECISE_REST_WRITTEN')
          expect(output).toContain('WORK_TREE_WRITTEN')
        }
      },
      300000,
    )
  })

  /** The mount words of a wrap: the argument file where the profile is past
   *  what a command line carries, the line itself where it is not. */
  function mountWords(command: string): string[] {
    const profile = /\/proc\/\d+\/fd\/\d+/.exec(command)?.[0]
    if (profile === undefined) return command.split(/\s+/)
    const words = readFileSync(profile, 'utf8').split('\0')
    words.pop()
    return words
  }

  function realPathOrSelf(target: string): string {
    try {
      return realpathSync(target)
    } catch {
      return target
    }
  }
})
