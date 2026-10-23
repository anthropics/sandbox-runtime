import { describe, it, expect, beforeEach, afterEach, spyOn } from 'bun:test'
import * as fs from 'fs'
import { spawnSync } from 'node:child_process'
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  wrapCommandWithSandboxLinux,
  cleanupBwrapMountPoints,
  LinuxSandboxProfileError,
} from '../../src/sandbox/linux-sandbox-utils.js'
import { indexOfMount, lastMountAt } from '../helpers/bwrap-argv.js'
import { bwrapCanNamespace } from '../helpers/bwrap-namespace.js'
import { writeManifest } from '../helpers/mount-point-fixtures.js'
import { isLinux } from '../helpers/platform.js'
import { usePrivateManifestDirectory } from '../helpers/private-manifest-directory.js'

/**
 * A git directory this process cannot write takes no mount point for the
 * files git reads back, so the wrap denies it with one read-only bind of the
 * directory. That bind has to be the only one the deny binds put there. One
 * that needs a mount point made inside the directory either follows the bind,
 * where bubblewrap cannot create it on a read-only mount and the command
 * never starts, or precedes it, where bubblewrap creates it in a directory
 * this process can never take it out of again.
 *
 * Root writes a 0555 directory like any other, so nothing here applies to it.
 */
describe.if(isLinux && process.getuid?.() !== 0)(
  'Linux sandbox — a git directory denied whole takes no other deny bind',
  () => {
    /** Echoed by every command that runs for real, so nothing concludes
     *  anything from a sandbox that never started. */
    const BOOTED = 'BOOTED'
    const LIVE = bwrapCanNamespace()
    const runtime = usePrivateManifestDirectory()
    const savedCwd = process.cwd()
    let dir: string
    let project: string
    let gitDir: string

    beforeEach(() => {
      dir = realpathSync(mkdtempSync(join(tmpdir(), 'git-dir-whole-')))
      project = join(dir, 'project')
      gitDir = join(project, 'x', '.git')
    })

    afterEach(() => {
      process.chdir(savedCwd)
      cleanupBwrapMountPoints({ force: true })
      // Or the temporary directory cannot be removed.
      if (existsSync(gitDir)) chmodSync(gitDir, 0o755)
      if (existsSync(project)) chmodSync(project, 0o755)
      rmSync(dir, { recursive: true, force: true })
    })

    /**
     * A repository nested in the project whose git directory holds `entries`
     * beside its HEAD (a directory for null, a file of those bytes otherwise)
     * and is then made unwritable. Whichever of `hooks`, `commondir`, `config`
     * and `config.worktree` is not named is an absent deny path, which needs
     * a mount point.
     */
    function makeUnwritableGitDir(
      entries: Record<string, string | null>,
    ): void {
      mkdirSync(gitDir, { recursive: true })
      writeFileSync(join(gitDir, 'HEAD'), 'ref: refs/heads/main')
      for (const [name, contents] of Object.entries(entries)) {
        if (contents === null) mkdirSync(join(gitDir, name))
        else writeFileSync(join(gitDir, name), contents)
      }
      chmodSync(gitDir, 0o555)
    }

    function wrapInProject(
      command = 'true',
      readConfig?: { denyOnly: string[]; allowWithinDeny: string[] },
    ): Promise<string> {
      process.chdir(project)
      return wrapCommandWithSandboxLinux({
        command,
        needsNetworkRestriction: false,
        allowAllUnixSockets: true,
        readConfig,
        writeConfig: { allowOnly: ['.'], denyWithinAllow: [] },
      })
    }

    /**
     * Every mount emitted after the write root's own bind that lands on the
     * git directory or inside it, as the words it was emitted with. An
     * ancestor pin spells the directory's own bind too, but before the write
     * root's. indexOfMount refuses a command whose mount words went to the
     * argument file, where nothing here could see them.
     */
    function denyBindsOnGitDir(command: string): string[] {
      const writeRootBind = indexOfMount(command, '--bind', project, project)
      expect(writeRootBind).toBeGreaterThan(-1)
      const argv = command.split(/\s+/)
      const found: string[] = []
      for (let i = writeRootBind + 3; i < argv.length; i++) {
        const words =
          argv[i] === '--tmpfs' ? 2 : /^--(ro-)?bind$/.test(argv[i]!) ? 3 : 0
        const dest = argv[i + words - 1]
        if (
          words > 0 &&
          dest !== undefined &&
          (dest === gitDir || dest.startsWith(`${gitDir}/`))
        ) {
          found.push(argv.slice(i, i + words).join(' '))
        }
      }
      return found
    }

    function run(command: string): { status: number | null; output: string } {
      const result = spawnSync(command, {
        shell: true,
        encoding: 'utf8',
        timeout: 30000,
        cwd: project,
        env: { ...process.env, LC_ALL: 'C' },
      })
      return {
        status: result.status,
        output: `${result.stdout}${result.stderr}`,
      }
    }

    it('emits no placeholder inside the git directory after the bind of it', async () => {
      // `hooks` is there, and comes before `commondir`, which is what finds
      // that the directory takes no mount point; `config` is not there, and
      // its turn comes after. A placeholder for it then is a file bubblewrap
      // has to create on the read-only mount it has just made.
      // `config.worktree` adds no second bind of the directory.
      makeUnwritableGitDir({ hooks: null })

      const command = await wrapInProject()

      expect(denyBindsOnGitDir(command)).toEqual([
        `--ro-bind ${gitDir} ${gitDir}`,
      ])
      expect(readdirSync(gitDir).sort()).toEqual(['HEAD', 'hooks'])
    })

    it('emits none where no redirect file comes after it either', async () => {
      // A `config.worktree` of the caller's own takes a bind from itself and
      // never asks the directory for a mount point, so nothing after the
      // absent `config` finds the directory unwritable a second time.
      makeUnwritableGitDir({
        hooks: null,
        'config.worktree': '[core]\n',
      })

      expect(denyBindsOnGitDir(await wrapInProject())).toEqual([
        `--ro-bind ${gitDir} ${gitDir}`,
      ])
    })

    it('binds each from itself where nothing has to be made', async () => {
      const entries = {
        hooks: null,
        config: '[core]\n',
        commondir: '.\n',
        'config.worktree': '',
      }
      makeUnwritableGitDir(entries)

      expect(denyBindsOnGitDir(await wrapInProject()).sort()).toEqual(
        Object.keys(entries)
          .map(name => `--ro-bind ${join(gitDir, name)} ${join(gitDir, name)}`)
          .sort(),
      )
    })

    it('emits no placeholder inside the git directory before the bind of it', async () => {
      // No `hooks` either: its placeholder is buffered ahead of `commondir`,
      // and bubblewrap, which can write the directory where this process
      // cannot, would create a mount point no cleanup here could remove.
      makeUnwritableGitDir({})

      expect(denyBindsOnGitDir(await wrapInProject())).toEqual([
        `--ro-bind ${gitDir} ${gitDir}`,
      ])
    })

    it('still takes away a redirect file a killed wrap left in the directory', async () => {
      // A `commondir` a killed wrap left holding the placeholder is named
      // again without writing to the directory; `config.worktree`, which is
      // absent, is what finds the directory unwritable. The file takes no bind
      // of its own, like every other inside the directory, and is named all
      // the same: once the directory can be written again it goes with the
      // rest of this wrap's mount points.
      makeUnwritableGitDir({ hooks: null, commondir: '.\n' })
      writeManifest(runtime.manifestDir(), [join(gitDir, 'commondir')])

      expect(denyBindsOnGitDir(await wrapInProject())).toEqual([
        `--ro-bind ${gitDir} ${gitDir}`,
      ])
      chmodSync(gitDir, 0o755)
      cleanupBwrapMountPoints({ force: true })
      expect(readdirSync(gitDir).sort()).toEqual(['HEAD', 'hooks'])
    })

    it('emits none under a directory that is denied for reading either', async () => {
      // The tmpfs over the directory above hides the bind of the git
      // directory until the project is bound back, which is a reason to keep
      // any other placeholder. Not this one: it is a file this process cannot
      // write, and every plan of the wrap would find that out anew.
      makeUnwritableGitDir({ hooks: null })

      const binds = denyBindsOnGitDir(
        await wrapInProject('true', {
          denyOnly: [dir],
          allowWithinDeny: [project],
        }),
      )

      // `hooks` is there: a bind of it needs nothing made.
      expect(new Set(binds)).toEqual(
        new Set(
          [gitDir, join(gitDir, 'hooks')].map(d => `--ro-bind ${d} ${d}`),
        ),
      )
      expect(readdirSync(gitDir).sort()).toEqual(['HEAD', 'hooks'])
    })

    it.each(['EACCES', 'EPERM', 'EROFS', 'ENOSPC', 'EDQUOT'])(
      'goes by a refusal that asking did not foretell (%s)',
      async code => {
        // access(2) answers for the mode. An immutable directory, a file system
        // that maps owners or a full one says yes there and no to the write,
        // after the manifest is published. The next plan of the same wrap has
        // to know, and of every such directory at once: a wrap has few plans.
        const gitDirs = ['x', 'y', 'z', 'w'].map(name =>
          join(project, name, '.git'),
        )
        for (const each of gitDirs) {
          mkdirSync(join(each, 'hooks'), { recursive: true })
          writeFileSync(join(each, 'HEAD'), 'ref: refs/heads/main')
        }
        const real = fs.writeFileSync
        let refused = 0
        const write = spyOn(fs, 'writeFileSync').mockImplementation(((
          ...args: Parameters<typeof fs.writeFileSync>
        ) => {
          if (/\/(commondir|config\.worktree)$/.test(String(args[0]))) {
            refused++
            throw Object.assign(new Error(code), { code })
          }
          return real(...args)
        }) as typeof fs.writeFileSync)

        const command = await wrapInProject().finally(() => write.mockRestore())

        expect(denyBindsOnGitDir(command)).toEqual([
          `--ro-bind ${gitDir} ${gitDir}`,
        ])
        for (const each of gitDirs) {
          expect(lastMountAt(command, each)).toBe(`--ro-bind ${each} ${each}`)
          expect(readdirSync(each).sort()).toEqual(['HEAD', 'hooks'])
        }
        // Once a directory has refused one file it is not asked for the other.
        expect(refused).toBe(gitDirs.length)
      },
    )

    it('refuses the command where the git directory holds the work tree', async () => {
      // `x/.git` names the project itself as its git directory. Denied whole,
      // that would take everything the command may write.
      mkdirSync(join(project, 'x'), { recursive: true })
      mkdirSync(join(project, 'objects'))
      mkdirSync(join(project, 'refs'))
      writeFileSync(join(project, 'HEAD'), 'ref: refs/heads/main')
      writeFileSync(join(project, 'x', '.git'), 'gitdir: ..\n')
      chmodSync(project, 0o555)

      const refusal: unknown = await wrapInProject().catch(
        (err: unknown) => err,
      )

      expect(refusal).toBeInstanceOf(LinuxSandboxProfileError)
      expect((refusal as LinuxSandboxProfileError).code).toBe(
        'deny_placeholder_unavailable',
      )
      expect(readdirSync(project).sort()).toEqual([
        'HEAD',
        'objects',
        'refs',
        'x',
      ])
    })

    it.if(LIVE)(
      'runs the command, with the git directory read-only and the work tree writable',
      async () => {
        makeUnwritableGitDir({ hooks: null })

        const first = run(
          await wrapInProject(
            `echo ${BOOTED}; echo x > x/.git/probe; echo ok > x/work.txt && echo WORK_OK`,
          ),
        )

        expect(first.output).toContain(BOOTED)
        expect(first.status).toBe(0)
        expect(first.output).toContain('Read-only file system')
        expect(first.output).toContain('WORK_OK')
        expect(existsSync(join(gitDir, 'probe'))).toBe(false)
        expect(existsSync(join(project, 'x', 'work.txt'))).toBe(true)

        // Not something one command can do to the next: the directory is as
        // unwritable to the second as it was to the first.
        cleanupBwrapMountPoints()
        const second = run(await wrapInProject(`echo ${BOOTED}`))
        expect(second.output).toContain(BOOTED)
        expect(second.status).toBe(0)
        expect(readdirSync(gitDir).sort()).toEqual(['HEAD', 'hooks'])
      },
    )

    it.if(LIVE)(
      'runs the command under a directory that is denied for reading',
      async () => {
        makeUnwritableGitDir({ hooks: null })

        const result = run(
          await wrapInProject(
            `echo ${BOOTED}; echo x > x/.git/commondir; echo ok > x/work.txt && echo WORK_OK`,
            { denyOnly: [dir], allowWithinDeny: [project] },
          ),
        )

        expect(result.output).toContain(BOOTED)
        expect(result.status).toBe(0)
        expect(result.output).toContain('Read-only file system')
        expect(result.output).toContain('WORK_OK')
        cleanupBwrapMountPoints()
        expect(readdirSync(gitDir).sort()).toEqual(['HEAD', 'hooks'])
      },
    )

    it.if(LIVE)(
      'leaves nothing behind in a git directory with no hooks either',
      async () => {
        makeUnwritableGitDir({})

        const result = run(
          await wrapInProject(
            `echo ${BOOTED}; mkdir x/.git/hooks || echo HOOKS_DENIED`,
          ),
        )

        expect(result.output).toContain(BOOTED)
        expect(result.status).toBe(0)
        expect(result.output).toContain('HOOKS_DENIED')
        cleanupBwrapMountPoints()
        expect(readdirSync(gitDir)).toEqual(['HEAD'])
      },
    )
  },
)
