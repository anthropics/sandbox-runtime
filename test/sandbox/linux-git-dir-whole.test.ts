import { describe, it, expect, beforeEach, afterEach } from 'bun:test'
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
} from '../../src/sandbox/linux-sandbox-utils.js'
import { indexOfMount } from '../helpers/bwrap-argv.js'
import { bwrapCanNamespace } from '../helpers/bwrap-namespace.js'
import { isLinux } from '../helpers/platform.js'

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

    function wrapInProject(command = 'true'): Promise<string> {
      process.chdir(project)
      return wrapCommandWithSandboxLinux({
        command,
        needsNetworkRestriction: false,
        allowAllUnixSockets: true,
        readConfig: undefined,
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
      // `hooks` is there, and is emitted before `commondir` finds that the
      // directory takes no mount point; `config` is not there, and its turn
      // comes after. A placeholder for it then is a file bubblewrap has to
      // create on the read-only mount it has just made. `config.worktree`
      // finds nothing left to do, and adds no second bind of the directory.
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

    it('emits no placeholder inside the git directory before the bind of it', async () => {
      // No `hooks` either: its placeholder is buffered ahead of `commondir`,
      // and bubblewrap, which can write the directory where this process
      // cannot, would create a mount point no cleanup here could remove.
      makeUnwritableGitDir({})

      expect(denyBindsOnGitDir(await wrapInProject())).toEqual([
        `--ro-bind ${gitDir} ${gitDir}`,
      ])
    })

    it('still takes away a redirect file it claimed before the directory went whole', async () => {
      // A `commondir` a killed wrap left holding the placeholder is claimed
      // without writing to the directory; `config.worktree`, which is absent,
      // is what finds the directory unwritable. The bind the claim emitted is
      // taken back with every other inside the directory, and the claim
      // stands: once the directory can be written again the file goes with
      // the rest of this wrap's mount points.
      makeUnwritableGitDir({ hooks: null, commondir: '.\n' })

      expect(denyBindsOnGitDir(await wrapInProject())).toEqual([
        `--ro-bind ${gitDir} ${gitDir}`,
      ])
      chmodSync(gitDir, 0o755)
      cleanupBwrapMountPoints({ force: true })
      expect(readdirSync(gitDir).sort()).toEqual(['HEAD', 'hooks'])
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
