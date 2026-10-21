import {
  describe,
  it,
  expect,
  beforeAll,
  afterAll,
  beforeEach,
  afterEach,
  spyOn,
} from 'bun:test'
import { spawn, spawnSync } from 'node:child_process'
import {
  chmodSync,
  mkdirSync,
  readdirSync,
  mkdtempSync,
  renameSync,
  rmdirSync,
  rmSync,
  writeFileSync,
  readFileSync,
  symlinkSync,
  readlinkSync,
  existsSync,
  lstatSync,
  statSync,
  realpathSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { basename, join } from 'node:path'
import { getPlatform } from '../../src/utils/platform.js'
import {
  indexOfMount,
  lastIndexOfMount,
  lastMountAt,
  manifestOf,
} from '../helpers/bwrap-argv.js'
import { bwrapCanNamespace } from '../helpers/bwrap-namespace.js'
import { withCapturedWarnings } from '../helpers/captured-warnings.js'
import {
  wrapCommandWithSandboxMacOS,
  macGetMandatoryDenyEntries,
} from '../../src/sandbox/macos-sandbox-utils.js'
import {
  wrapCommandWithSandboxLinux,
  cleanupBwrapMountPoints,
  linuxGetCwdMandatoryDenyPaths,
  linuxGetMonitorCwdDenyPaths,
  LinuxSandboxProfileError,
  unreadableDirectories,
  type LinuxSandboxParams,
} from '../../src/sandbox/linux-sandbox-utils.js'
import {
  GitMetadataError,
  SubmoduleWalkBudgetError,
  gitDirDenies,
  gitDirDenyPaths,
  gitDirTreeDenies,
  gitDirTreeDenyPaths,
  gitFileDenies,
  gitRedirectPlaceholder,
  submoduleGitDirs,
} from '../../src/sandbox/mandatory-deny-paths.js'
import {
  NO_COLLAPSE,
  collapseFurther,
  collapsedDenyPaths,
  describeCollapse,
  degradableGitDirs,
} from '../../src/sandbox/linux-deny-collapse.js'
import type { SubmoduleDenyPlan } from '../../src/sandbox/linux-deny-collapse.js'
import {
  DANGEROUS_FILES,
  getDangerousDirectories,
} from '../../src/sandbox/sandbox-utils.js'
import { isLinux, isSupportedPlatform, isWindows } from '../helpers/platform.js'
import { quote } from '../../src/utils/shell-quote.js'
import type { RipgrepConfig } from '../../src/utils/ripgrep.js'

/**
 * Integration tests for mandatory deny paths.
 *
 * These tests verify that dangerous files (.bashrc, .gitconfig, etc.) and
 * directories (.git/hooks, .vscode, etc.) are blocked from writes even when
 * they're within an allowed write path.
 *
 * IMPORTANT: The mandatory deny patterns are relative to process.cwd().
 * Tests must chdir to TEST_DIR before generating sandbox commands.
 */

describe.if(isSupportedPlatform)(
  'Mandatory Deny Paths - Integration Tests',
  () => {
    const TEST_DIR = join(tmpdir(), `mandatory-deny-integration-${Date.now()}`)
    // A read-denied region outside cwd, so the read section emits its
    // operation-specific unlink/create rules (which a deny has to survive).
    const READ_DENY_DIR = join(
      tmpdir(),
      `mandatory-deny-readdeny-${Date.now()}`,
    )
    const ORIGINAL_CONTENT = 'ORIGINAL'
    const MODIFIED_CONTENT = 'MODIFIED'
    /** Written into every directory getDangerousDirectories() names. */
    const DIRECTORY_PROBE_FILE = 'probe.txt'
    let originalCwd: string

    beforeAll(() => {
      originalCwd = process.cwd()
      mkdirSync(TEST_DIR, { recursive: true })
      mkdirSync(READ_DENY_DIR, { recursive: true })
      writeFileSync(join(READ_DENY_DIR, 'secret.txt'), ORIGINAL_CONTENT)

      for (const name of DANGEROUS_FILES) {
        writeFileSync(join(TEST_DIR, name), ORIGINAL_CONTENT)
      }

      // Create .git with hooks and config
      mkdirSync(join(TEST_DIR, '.git', 'hooks'), { recursive: true })
      writeFileSync(join(TEST_DIR, '.git', 'config'), ORIGINAL_CONTENT)
      writeFileSync(
        join(TEST_DIR, '.git', 'hooks', 'pre-commit'),
        ORIGINAL_CONTENT,
      )
      writeFileSync(join(TEST_DIR, '.git', 'HEAD'), 'ref: refs/heads/main')

      for (const dir of getDangerousDirectories()) {
        mkdirSync(join(TEST_DIR, dir), { recursive: true })
        writeFileSync(
          join(TEST_DIR, dir, DIRECTORY_PROBE_FILE),
          ORIGINAL_CONTENT,
        )
      }

      // Create a safe file that SHOULD be writable
      writeFileSync(join(TEST_DIR, 'safe-file.txt'), ORIGINAL_CONTENT)

      // Create safe files within .git that SHOULD be writable (not hooks/config)
      mkdirSync(join(TEST_DIR, '.git', 'objects'), { recursive: true })
      mkdirSync(join(TEST_DIR, '.git', 'refs', 'heads'), { recursive: true })
      writeFileSync(
        join(TEST_DIR, '.git', 'objects', 'test-obj'),
        ORIGINAL_CONTENT,
      )
      writeFileSync(
        join(TEST_DIR, '.git', 'refs', 'heads', 'main'),
        ORIGINAL_CONTENT,
      )
      writeFileSync(join(TEST_DIR, '.git', 'index'), ORIGINAL_CONTENT)

      // A nested repository directly under cwd, with `nested/` gitignored:
      // its config sits at the default scan depth, its hook files one past
      // it, and an ignore file must not hide either from the scan.
      mkdirSync(join(TEST_DIR, 'nested', '.git', 'hooks'), { recursive: true })
      mkdirSync(join(TEST_DIR, 'nested', 'src'), { recursive: true })
      writeFileSync(
        join(TEST_DIR, 'nested', '.git', 'HEAD'),
        'ref: refs/heads/main',
      )
      writeFileSync(
        join(TEST_DIR, 'nested', '.git', 'config'),
        ORIGINAL_CONTENT,
      )
      writeFileSync(
        join(TEST_DIR, 'nested', '.git', 'hooks', 'pre-commit'),
        ORIGINAL_CONTENT,
      )
      writeFileSync(join(TEST_DIR, 'nested', 'src', 'ok.txt'), ORIGINAL_CONTENT)
      writeFileSync(join(TEST_DIR, '.gitignore'), 'nested/\nlib/\n')
      // The nested repository has a submodule of its own.
      mkdirSync(join(TEST_DIR, 'nested', '.git', 'modules', 'dep', 'hooks'), {
        recursive: true,
      })
      writeFileSync(
        join(TEST_DIR, 'nested', '.git', 'modules', 'dep', 'HEAD'),
        'ref: x',
      )
      // A submodule: its git directory lives under cwd's .git/modules and its
      // checkout has a .git FILE pointing there.
      mkdirSync(join(TEST_DIR, '.git', 'modules', 'lib', 'hooks'), {
        recursive: true,
      })
      writeFileSync(join(TEST_DIR, '.git', 'modules', 'lib', 'HEAD'), 'ref: x')
      writeFileSync(
        join(TEST_DIR, '.git', 'modules', 'lib', 'config'),
        ORIGINAL_CONTENT,
      )
      writeFileSync(
        join(TEST_DIR, '.git', 'modules', 'lib', 'hooks', 'pre-commit'),
        ORIGINAL_CONTENT,
      )
      mkdirSync(join(TEST_DIR, 'lib'), { recursive: true })
      writeFileSync(
        join(TEST_DIR, 'lib', '.git'),
        'gitdir: ../.git/modules/lib',
      )
      // A linked worktree of this repository checked out inside it: its
      // .git file points at .git/worktrees/wt, whose commondir is the main
      // .git, so the hooks a commit in the worktree runs are the main ones.
      mkdirSync(join(TEST_DIR, '.git', 'worktrees', 'wt'), { recursive: true })
      writeFileSync(join(TEST_DIR, '.git', 'worktrees', 'wt', 'HEAD'), 'ref: x')
      writeFileSync(
        join(TEST_DIR, '.git', 'worktrees', 'wt', 'commondir'),
        '../..\n',
      )
      mkdirSync(join(TEST_DIR, 'wt-checkout'), { recursive: true })
      writeFileSync(
        join(TEST_DIR, 'wt-checkout', '.git'),
        `gitdir: ${join(TEST_DIR, '.git', 'worktrees', 'wt')}`,
      )
      // A checkout whose .git pointer carries 9,000 newline bytes after the
      // path. git strips them and follows the pointer, so its target needs
      // the same denies an unpadded pointer's does.
      mkdirSync(join(TEST_DIR, 'padded-target', 'hooks'), { recursive: true })
      writeFileSync(
        join(TEST_DIR, 'padded-target', 'HEAD'),
        'ref: refs/heads/main',
      )
      writeFileSync(join(TEST_DIR, 'padded-target', 'config'), ORIGINAL_CONTENT)
      mkdirSync(join(TEST_DIR, 'padded-checkout'), { recursive: true })
      writeFileSync(
        join(TEST_DIR, 'padded-checkout', '.git'),
        `gitdir: ${join(TEST_DIR, 'padded-target')}${'\n'.repeat(9000)}`,
      )
      // A nested .claude/commands one level down (a name spanning two
      // segments), within reach only of a deeper scan.
      mkdirSync(join(TEST_DIR, 'pkg', '.claude', 'commands'), {
        recursive: true,
      })
      writeFileSync(
        join(TEST_DIR, 'pkg', '.claude', 'commands', 'x.md'),
        ORIGINAL_CONTENT,
      )
      // A working directory whose own location has a dangerous name in it.
      mkdirSync(join(TEST_DIR, '.vscode', 'ext', 'foo', 'sub'), {
        recursive: true,
      })
      writeFileSync(
        join(TEST_DIR, '.vscode', 'ext', 'foo', 'sub', '.gitconfig'),
        ORIGINAL_CONTENT,
      )

      // Create safe file within .claude that SHOULD be writable (not commands/agents)
      writeFileSync(
        join(TEST_DIR, '.claude', 'some-other-file.txt'),
        ORIGINAL_CONTENT,
      )
    })

    afterAll(() => {
      process.chdir(originalCwd)
      rmSync(TEST_DIR, { recursive: true, force: true })
      rmSync(READ_DENY_DIR, { recursive: true, force: true })
    })

    beforeEach(() => {
      // Must be in TEST_DIR for mandatory deny patterns to apply correctly
      process.chdir(TEST_DIR)
    })

    afterEach(() => {
      // Reset the active-sandbox counter and scrub any leftover mount points so
      // each test starts clean. Tests that don't explicitly call
      // cleanupBwrapMountPoints() would otherwise leak the counter.
      cleanupBwrapMountPoints({ force: true })
    })

    interface SandboxRunOptions {
      mandatoryDenySearchDepth?: number
      allowGitConfig?: boolean
      allowOnly?: string[]
      /**
       * A read config makes the read section emit its own
       * operation-specific unlink/create rules, which the write section's
       * denies have to survive.
       */
      readConfig?: { denyOnly: string[]; allowWithinDeny?: string[] }
      ripgrepArgs?: string[]
    }

    async function runSandboxed(
      command: string,
      opts: SandboxRunOptions = {},
    ): Promise<{ success: boolean; stderr: string; stdout: string }> {
      const platform = getPlatform()

      // Allow writes to current directory, but mandatory denies should still block dangerous files
      const writeConfig = {
        allowOnly: opts.allowOnly ?? ['.'],
        denyWithinAllow: [], // Empty - relying on mandatory denies
      }

      let wrappedCommand: string
      if (platform === 'macos') {
        wrappedCommand = wrapCommandWithSandboxMacOS({
          command,
          needsNetworkRestriction: false,
          readConfig: opts.readConfig,
          writeConfig,
          allowGitConfig: opts.allowGitConfig,
        })
      } else {
        wrappedCommand = await wrapCommandWithSandboxLinux({
          command,
          needsNetworkRestriction: false,
          readConfig: opts.readConfig,
          writeConfig,
          mandatoryDenySearchDepth: opts.mandatoryDenySearchDepth,
          allowGitConfig: opts.allowGitConfig,
          ripgrepConfig: { command: 'rg', args: opts.ripgrepArgs ?? [] },
        })
      }

      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 10000,
      })

      return {
        success: result.status === 0,
        stderr: result.stderr || '',
        stdout: result.stdout || '',
      }
    }

    /**
     * The write did not land. On Linux the mount point for an absent deny
     * path stays until the cleanup: bwrap's own empty file, or, for a file
     * git reads back, the placeholder the wrap wrote there (`expected`). On
     * macOS nothing is created.
     */
    function expectNotWritten(absolutePath: string, expected = ''): void {
      const content = existsSync(absolutePath)
        ? readFileSync(absolutePath, 'utf8')
        : ''
      expect(content).toBe(isLinux ? expected : '')
    }

    async function runSandboxedWrite(
      filePath: string,
      content: string,
      opts: SandboxRunOptions = {},
    ): Promise<{ success: boolean; stderr: string; stdout: string }> {
      return runSandboxed(`echo '${content}' > '${filePath}'`, opts)
    }

    describe('Dangerous files should be blocked', () => {
      for (const name of DANGEROUS_FILES) {
        it(`blocks writes to ${name}`, async () => {
          const result = await runSandboxedWrite(name, MODIFIED_CONTENT)

          expect(result.success).toBe(false)
          expect(readFileSync(name, 'utf8')).toBe(ORIGINAL_CONTENT)
        })
      }
    })

    describe('Git hooks and config should be blocked', () => {
      it('blocks writes to .git/config', async () => {
        const result = await runSandboxedWrite('.git/config', MODIFIED_CONTENT)

        expect(result.success).toBe(false)
        expect(readFileSync('.git/config', 'utf8')).toBe(ORIGINAL_CONTENT)
      })

      it('blocks writes to .git/hooks/pre-commit', async () => {
        const result = await runSandboxedWrite(
          '.git/hooks/pre-commit',
          MODIFIED_CONTENT,
        )

        expect(result.success).toBe(false)
        expect(readFileSync('.git/hooks/pre-commit', 'utf8')).toBe(
          ORIGINAL_CONTENT,
        )
      })
    })

    describe('Nested repositories, submodules and worktree pointers', () => {
      /**
       * One write each, refused: `left` is what is at the path afterwards. On
       * Linux the mount point of an absent deny path stays until the clean-up,
       * bubblewrap's own empty file or what the wrap wrote for git to read; on
       * macOS nothing is created.
       */
      it.each<{
        what: string
        file: string
        left: string | { absent: true } | { mountPoint: string }
        opts?: SandboxRunOptions
      }>([
        {
          what: "a nested repository's config, gitignored or not",
          file: 'nested/.git/config',
          left: ORIGINAL_CONTENT,
        },
        {
          what: "a nested repository's existing hook, at the default depth",
          file: 'nested/.git/hooks/pre-commit',
          left: ORIGINAL_CONTENT,
        },
        {
          // The scan does not go by .git/config then, and the hook files lie
          // one level past the default depth.
          what: "a nested repository's hook with config writes allowed",
          file: 'nested/.git/hooks/pre-commit',
          left: ORIGINAL_CONTENT,
          opts: { allowGitConfig: true },
        },
        {
          what: 'a new hook in a nested repository',
          file: 'nested/.git/hooks/post-checkout',
          left: { absent: true },
        },
        {
          what: "a submodule's config under .git/modules",
          file: '.git/modules/lib/config',
          left: ORIGINAL_CONTENT,
        },
        {
          what: "a new hook in a submodule's git directory",
          file: '.git/modules/lib/hooks/post-checkout',
          left: { absent: true },
        },
        {
          what: "a new hook in a nested repository's submodule",
          file: 'nested/.git/modules/dep/hooks/post-checkout',
          left: { absent: true },
        },
        {
          what: "a submodule checkout's .git file",
          file: 'lib/.git',
          left: 'gitdir: ../.git/modules/lib',
        },
        {
          // git reads hooks and config through it, so a write here moves every
          // other deny to a directory of the command's choosing.
          what: "a commondir in the repository's git directory",
          file: '.git/commondir',
          left: { mountPoint: '.\n' },
        },
        {
          what: "a commondir in a submodule's git directory",
          file: '.git/modules/lib/commondir',
          left: { mountPoint: '.\n' },
        },
        {
          what: "a commondir in a nested repository's",
          file: 'nested/.git/commondir',
          left: { mountPoint: '.\n' },
        },
        {
          // Read on top of .git/config wherever extensions.worktreeConfig is on.
          what: '.git/config.worktree',
          file: '.git/config.worktree',
          left: { mountPoint: '' },
        },
      ])('blocks writing $what', async ({ file, left, opts }) => {
        const result = await runSandboxedWrite(file, MODIFIED_CONTENT, opts)

        expect(result.success).toBe(false)
        const isMade =
          typeof left === 'string' || ('mountPoint' in left && isLinux)
        expect(existsSync(file)).toBe(isMade)
        if (isMade) {
          expect(readFileSync(file, 'utf8')).toBe(
            typeof left === 'string'
              ? left
              : (left as { mountPoint: string }).mountPoint,
          )
        }
      })

      it('finds a nested repository with no file directly inside its .git', async () => {
        // The scan recognises a repository by a regular file directly inside
        // its .git. With config writes allowed a command can delete every
        // one of them — HEAD, config, index, description, packed-refs — and
        // hide the repository from the next command's scan, so the walk
        // looks for the directory itself instead.
        for (const sub of ['hooks', 'objects', 'refs']) {
          mkdirSync(join('emptied', '.git', sub), { recursive: true })
        }
        try {
          const result = await runSandboxedWrite(
            'emptied/.git/hooks/pre-commit',
            MODIFIED_CONTENT,
            { allowGitConfig: true },
          )

          expect(result.success).toBe(false)
          expect(existsSync('emptied/.git/hooks/pre-commit')).toBe(false)
        } finally {
          rmSync('emptied', { recursive: true, force: true })
        }
      })

      it('keeps the rest of a nested repository writable', async () => {
        const result = await runSandboxedWrite(
          'nested/src/ok.txt',
          MODIFIED_CONTENT,
        )

        expect(result.success).toBe(true)
        expect(readFileSync('nested/src/ok.txt', 'utf8').trim()).toBe(
          MODIFIED_CONTENT,
        )
      })

      it.if(isLinux && process.getuid?.() !== 0)(
        'keeps what the scan found when a directory under cwd is unreadable',
        async () => {
          mkdirSync('unreadable', { mode: 0o000 })
          try {
            const result = await runSandboxedWrite(
              'nested/.git/config',
              MODIFIED_CONTENT,
            )

            expect(result.success).toBe(false)
            expect(readFileSync('nested/.git/config', 'utf8')).toBe(
              ORIGINAL_CONTENT,
            )
          } finally {
            chmodSync('unreadable', 0o755)
            rmSync('unreadable', { recursive: true, force: true })
          }
        },
      )

      it('blocks removing an existing .git pointer file', async () => {
        const result = await runSandboxed('rm -f lib/.git', {
          readConfig: { denyOnly: [READ_DENY_DIR] },
        })

        expect(result.success).toBe(false)
        expect(readFileSync('lib/.git', 'utf8')).toBe(
          'gitdir: ../.git/modules/lib',
        )
      })

      it('blocks renaming a file over an existing .git pointer', async () => {
        writeFileSync(join(TEST_DIR, 'lib', 'decoy'), 'gitdir: /tmp/elsewhere')
        try {
          const result = await runSandboxed('mv -f lib/decoy lib/.git', {
            readConfig: { denyOnly: [READ_DENY_DIR] },
          })

          expect(result.success).toBe(false)
          expect(readFileSync('lib/.git', 'utf8')).toBe(
            'gitdir: ../.git/modules/lib',
          )
        } finally {
          rmSync(join(TEST_DIR, 'lib', 'decoy'), { force: true })
        }
      })

      it('still removes an ordinary file with the same read config', async () => {
        writeFileSync(join(TEST_DIR, 'lib', 'plain.txt'), ORIGINAL_CONTENT)
        try {
          const result = await runSandboxed('rm -f lib/plain.txt', {
            readConfig: { denyOnly: [READ_DENY_DIR] },
          })

          expect(result.success).toBe(true)
          expect(existsSync(join(TEST_DIR, 'lib', 'plain.txt'))).toBe(false)
        } finally {
          rmSync(join(TEST_DIR, 'lib', 'plain.txt'), { force: true })
        }
      })

      it('allows .git/config.worktree when allowGitConfig is true', async () => {
        try {
          const result = await runSandboxedWrite(
            '.git/config.worktree',
            'bare = false',
            { allowGitConfig: true },
          )

          expect(result.success).toBe(true)
        } finally {
          rmSync(join(TEST_DIR, '.git', 'config.worktree'), { force: true })
        }
      })

      it('finds a submodule git directory whose HEAD was moved aside', async () => {
        const head = join(TEST_DIR, '.git', 'modules', 'lib', 'HEAD')
        renameSync(head, `${head}.bak`)
        try {
          const result = await runSandboxedWrite(
            '.git/modules/lib/hooks/pre-commit',
            MODIFIED_CONTENT,
          )

          expect(result.success).toBe(false)
          expect(
            readFileSync(
              join(TEST_DIR, '.git', 'modules', 'lib', 'hooks', 'pre-commit'),
              'utf8',
            ),
          ).toBe(ORIGINAL_CONTENT)
        } finally {
          renameSync(`${head}.bak`, head)
        }
      })

      it.if(isLinux)(
        'finds a nested repository whose HEAD was moved aside',
        async () => {
          // With allowGitConfig the scan does not look for config either, and
          // the hook files are one level past the default depth: the
          // repository has to be recognised by whatever else its .git holds.
          const head = join(TEST_DIR, 'nested', '.git', 'HEAD')
          renameSync(head, `${head}.bak`)
          try {
            const result = await runSandboxedWrite(
              'nested/.git/hooks/pre-commit',
              MODIFIED_CONTENT,
              { allowGitConfig: true },
            )

            expect(result.success).toBe(false)
            expect(readFileSync('nested/.git/hooks/pre-commit', 'utf8')).toBe(
              ORIGINAL_CONTENT,
            )
          } finally {
            renameSync(`${head}.bak`, head)
          }
        },
      )

      it.if(isLinux)(
        'does not follow a .git file that names an ordinary directory',
        async () => {
          // `gitdir: ..` from app/tools would otherwise make app/config and
          // app/hooks — an ordinary Rails-shaped tree — read-only.
          mkdirSync(join(TEST_DIR, 'app', 'config'), { recursive: true })
          mkdirSync(join(TEST_DIR, 'app', 'tools'), { recursive: true })
          writeFileSync(join(TEST_DIR, 'app', 'tools', '.git'), 'gitdir: ..')
          try {
            const result = await runSandboxedWrite(
              'app/config/settings.yml',
              MODIFIED_CONTENT,
            )

            expect(result.success).toBe(true)
          } finally {
            rmSync(join(TEST_DIR, 'app'), { recursive: true, force: true })
          }
        },
      )

      it.if(isLinux)(
        'blocks filling in the git directory a dangling .git file names',
        async () => {
          mkdirSync(join(TEST_DIR, 'dangling'), { recursive: true })
          writeFileSync(
            join(TEST_DIR, 'dangling', '.git'),
            'gitdir: ../dangling-gitdir',
          )
          try {
            const result = await runSandboxed(
              'mkdir -p dangling-gitdir/hooks && echo X > dangling-gitdir/hooks/pre-commit',
            )

            expect(result.success).toBe(false)
            expect(
              existsSync(
                join(TEST_DIR, 'dangling-gitdir', 'hooks', 'pre-commit'),
              ),
            ).toBe(false)
          } finally {
            rmSync(join(TEST_DIR, 'dangling'), { recursive: true, force: true })
            rmSync(join(TEST_DIR, 'dangling-gitdir'), {
              recursive: true,
              force: true,
            })
          }
        },
      )

      it.if(isLinux)(
        'refuses to sandbox at all when the scan does not finish',
        async () => {
          // One complete path, one the run was cut off in the middle of, and
          // then a run that outlives its timeout: what it did not reach is
          // unknown, so there is nothing safe to wrap the next command with.
          const error = await wrapCommandWithSandboxLinux({
            command: 'echo hi',
            needsNetworkRestriction: false,
            readConfig: undefined,
            writeConfig: { allowOnly: ['.'], denyWithinAllow: [] },
            ripgrepConfig: {
              command: '/bin/sh',
              args: [
                '-c',
                'printf "%s\\0%s" "$PWD/a/.git/HEAD" "$PWD/b/.gi"; exec sleep 30',
              ],
              timeoutMs: 200,
            },
          }).catch((e: unknown) => e)

          expect(error).toBeInstanceOf(LinuxSandboxProfileError)
          expect((error as LinuxSandboxProfileError).code).toBe(
            'deny_scan_failed',
          )
          expect((error as Error).message).toMatch(/did not finish/)
        },
      )

      it.if(isLinux && process.getuid?.() !== 0)(
        'denies a directory the scan could not read',
        async () => {
          mkdirSync(join(TEST_DIR, 'locked', '.git', 'hooks'), {
            recursive: true,
          })
          writeFileSync(
            join(TEST_DIR, 'locked', '.git', 'HEAD'),
            'ref: refs/heads/main',
          )
          chmodSync(join(TEST_DIR, 'locked'), 0o000)
          try {
            const result = await runSandboxed(
              'echo BOOTED; chmod 755 locked && echo X > locked/.git/hooks/pre-commit',
            )

            // The sandbox ran, and the directory it could not read is
            // read-only inside it, so the chmod that would open it fails.
            expect(result.stdout).toContain('BOOTED')
            expect(result.success).toBe(false)
            expect(result.stderr).not.toBe('')
          } finally {
            chmodSync(join(TEST_DIR, 'locked'), 0o755)
            rmSync(join(TEST_DIR, 'locked'), { recursive: true, force: true })
          }
        },
      )

      /**
       * What the scan does when it fails, driven by a fake rg: the run that
       * fails for real needs a directory this process cannot read, and as
       * root — which CI is — there is none, so none of this would be
       * exercised there. The last arm is the real thing, where the uid allows.
       */
      describe.if(isLinux)('when the scan fails', () => {
        /** Echoed by every command that runs for real, so nothing concludes
         *  anything from a sandbox that never started. */
        const BOOTED = 'BOOTED'

        const wrapWith = (
          ripgrepConfig: RipgrepConfig,
          abortSignal?: AbortSignal,
        ): Promise<string> =>
          wrapCommandWithSandboxLinux({
            command: 'echo hi',
            needsNetworkRestriction: false,
            readConfig: undefined,
            writeConfig: { allowOnly: ['.'], denyWithinAllow: [] },
            ripgrepConfig,
            abortSignal,
          })

        /** A fake rg: `matches` NUL-terminated on stdout, `stderr`, exit 2. */
        const failingRipgrep = (
          matches: string[],
          stderr: string,
        ): RipgrepConfig => ({
          command: '/bin/sh',
          args: [
            '-c',
            `printf '%s\\0' ${quote(matches)}; ` +
              // %s, not the format string: a backslash in a directory's name
              // reaches rg's stderr as itself and must reach this one too.
              `printf '%s' ${quote([stderr])} >&2; exit 2`,
          ],
        })

        /**
         * The deny bind of `denyPath`, as the wrapper spells it in the
         * command. Matched as text because a directory's name is chosen by
         * whoever made it: a space, a colon or a newline in one is
         * shell-quoted, and the argv helpers refuse a token of that shape.
         */
        const denyBindOf = (denyPath: string): string =>
          `--ro-bind ${quote([denyPath])} ${quote([denyPath])}`

        /**
         * The part of the command that carries the denies: everything after
         * the writable bind of the working directory. An ancestor pin is
         * spelled with the same words as a deny bind and sits before that
         * bind, buried under it, so only position tells the two apart.
         */
        function denySectionOf(command: string): string {
          const cwd = quote([process.cwd()])
          const writeRoot = `--bind ${cwd} ${cwd}`
          const at = command.indexOf(writeRoot)
          expect(at).toBeGreaterThan(-1)
          return command.slice(at + writeRoot.length)
        }

        const nestedConfig = (): string =>
          join(process.cwd(), 'nested', '.git', 'config')

        /** An unreadable directory, and the line real rg prints about it. */
        function lockDirectory(name: string): {
          path: string
          stderr: string
          release: () => void
        } {
          const locked = join(process.cwd(), name)
          mkdirSync(locked, { recursive: true })
          chmodSync(locked, 0o000)
          return {
            path: locked,
            stderr: `rg: ${locked}: Permission denied (os error 13)\n`,
            release: () => {
              chmodSync(locked, 0o755)
              rmSync(locked, { recursive: true, force: true })
            },
          }
        }

        it('refuses the wrap when the failure names no error code', async () => {
          // Nothing here stands in for a failure of this shape, so what the
          // run never reached would stay writable — and the raw line goes in
          // the message, since only a command run outside the sandbox can
          // act on it.
          const error = await wrapWith(
            failingRipgrep([nestedConfig()], 'rg: unrecognized option --frob'),
          ).catch((e: unknown) => e)

          expect(error).toBeInstanceOf(LinuxSandboxProfileError)
          expect((error as LinuxSandboxProfileError).code).toBe(
            'deny_scan_failed',
          )
          expect((error as Error).message).toMatch(
            /failed for a reason no deny stands in for/,
          )
          expect((error as Error).message).toContain(
            'rg: unrecognized option --frob',
          )
          expect((error as Error).message).toMatch(/was not run/)
        })

        it('refuses the wrap on an error code no deny stands in for', async () => {
          const error = await wrapWith(
            failingRipgrep(
              [nestedConfig()],
              'rg: /proc/self/fd/9: Input/output error (os error 5)\n',
            ),
          ).catch((e: unknown) => e)

          expect((error as LinuxSandboxProfileError).code).toBe(
            'deny_scan_failed',
          )
          expect((error as Error).message).toContain('(os error 5)')
        })

        it('refuses the wrap when the run said nothing at all', async () => {
          const error = await wrapWith(
            failingRipgrep([nestedConfig()], ''),
          ).catch((e: unknown) => e)

          expect((error as LinuxSandboxProfileError).code).toBe(
            'deny_scan_failed',
          )
          expect((error as Error).message).toContain('(nothing on stderr)')
        })

        it('carries on when the run only lost entries it had listed', async () => {
          // A file the command deleted while rg walked. There is nothing at
          // that path to deny, and mounting one would plant a file on the
          // host exactly where the command removed one.
          const vanished = join(process.cwd(), 'nested', 'src', 'gone.txt')
          const config = nestedConfig()
          const command = await wrapWith(
            failingRipgrep(
              [config],
              `rg: ${vanished}: No such file or directory (os error 2)\n`,
            ),
          )

          expect(lastMountAt(command, config)).toBe(
            `--ro-bind ${config} ${config}`,
          )
          expect(lastMountAt(command, vanished)).toBeUndefined()
          expect(existsSync(vanished)).toBe(false)
        })

        it('refuses the wrap when nothing unreadable is there to deny', async () => {
          // rg said it could not read something and the walk finds every
          // directory readable: the run failed over something this cannot
          // see, and nothing stands in for that.
          const error = await wrapWith(
            failingRipgrep(
              [nestedConfig()],
              `rg: ${join(process.cwd(), 'nested')}: Permission denied (os error 13)\n`,
            ),
          ).catch((e: unknown) => e)

          expect((error as LinuxSandboxProfileError).code).toBe(
            'deny_scan_failed',
          )
          expect((error as Error).message).toMatch(/none is there now/)
        })

        describe.if(process.getuid?.() !== 0)(
          'with a directory this process really cannot read',
          () => {
            it('denies the unreadable directory and nothing beside it', async () => {
              // The name holds rg's own separator. Cut at it, the path reads
              // as the directory above — which is readable, was scanned, and
              // must not be denied — and the unreadable one never is.
              const parent = join(process.cwd(), 'src: x')
              mkdirSync(parent, { recursive: true })
              const locked = lockDirectory(join('src: x', 'locked'))
              try {
                const command = await wrapWith(
                  failingRipgrep([nestedConfig()], locked.stderr),
                )

                const denies = denySectionOf(command)
                expect(denies).toContain(denyBindOf(locked.path))
                expect(denies).not.toContain(denyBindOf(parent))
              } finally {
                locked.release()
                rmSync(parent, { recursive: true, force: true })
              }
            })

            it('never denies the working directory over a name', async () => {
              const parent = join(process.cwd(), '.: x')
              mkdirSync(parent, { recursive: true })
              const locked = lockDirectory(join('.: x', 'locked'))
              try {
                const command = await wrapWith(
                  failingRipgrep([nestedConfig()], locked.stderr),
                )

                const denies = denySectionOf(command)
                expect(denies).toContain(denyBindOf(locked.path))
                expect(denies).not.toContain(denyBindOf(process.cwd()))
              } finally {
                locked.release()
                rmSync(parent, { recursive: true, force: true })
              }
            })

            it('denies a name ending in a space, which no trim survives', async () => {
              const locked = lockDirectory('locked ')
              try {
                const command = await wrapWith(
                  failingRipgrep([nestedConfig()], locked.stderr),
                )

                expect(denySectionOf(command)).toContain(
                  denyBindOf(locked.path),
                )
              } finally {
                locked.release()
              }
            })

            it('denies a name holding a newline whole, rather than refusing', async () => {
              const locked = lockDirectory('bad\nname')
              try {
                const command = await wrapWith(
                  failingRipgrep([nestedConfig()], locked.stderr),
                )

                expect(denySectionOf(command)).toContain(
                  denyBindOf(locked.path),
                )
              } finally {
                locked.release()
              }
            })

            it('denies what it can read of a run that both lost and was refused', async () => {
              const vanished = join(process.cwd(), 'nested', 'gone.txt')
              const locked = lockDirectory('mixed-locked')
              try {
                const command = await wrapWith(
                  failingRipgrep(
                    [nestedConfig()],
                    `rg: ${vanished}: No such file or directory (os error 2)\n${locked.stderr}`,
                  ),
                )

                expect(denySectionOf(command)).toContain(
                  denyBindOf(locked.path),
                )
                expect(lastMountAt(command, vanished)).toBeUndefined()
              } finally {
                locked.release()
              }
            })

            it('accounts for an unreadable directory at the depth the scan stops at', async () => {
              // ripgrep opens a directory that sits AT its --max-depth to
              // list it, and reports one it cannot read. This walk stops a
              // level above, so it found nothing for that EACCES and the
              // wrap was refused - over a layout as ordinary as a
              // `docker/data/postgres/base` another user owns. Nothing below
              // such a directory is in the scan's reach on either side, so it
              // is accounted for with nothing to deny.
              const locked = lockDirectory(
                join('docker', 'data', 'postgres', 'base'),
              )
              try {
                const command = await wrapWith(
                  failingRipgrep([nestedConfig()], locked.stderr),
                )

                const denies = denySectionOf(command)
                expect(denies).not.toContain(denyBindOf(locked.path))
                // And nothing widened to stand in for it.
                expect(denies).not.toContain(
                  denyBindOf(join(process.cwd(), 'docker', 'data', 'postgres')),
                )
                expect(denies).toContain(denyBindOf(nestedConfig()))
              } finally {
                locked.release()
              }
            })

            it('refuses a run killed inside its budget, whatever it reported', async () => {
              // Every code this run printed is one a deny stands in for, and
              // the directory it named is really there - so the listing
              // would be used, if the run had finished. It did not: a kill
              // that is not the timeout (an OOM kill, a signal to the
              // process group) stops the listing wherever it arrived, and
              // what lies past that is unknown however complete the stderr
              // looks. An unreadable directory is one `chmod 000` a command
              // can leave behind, so taking the two together would be a
              // fail-open with a plantable half.
              const locked = lockDirectory('killed-mid-listing')
              try {
                const error = await wrapWith({
                  command: '/bin/sh',
                  args: [
                    '-c',
                    `printf '%s\\0' ${quote([nestedConfig()])}; ` +
                      `printf '%s' ${quote([locked.stderr])} >&2; ` +
                      'kill -KILL $$',
                  ],
                  timeoutMs: 30000,
                }).catch((e: unknown) => e)

                expect(error).toBeInstanceOf(LinuxSandboxProfileError)
                expect((error as LinuxSandboxProfileError).code).toBe(
                  'deny_scan_failed',
                )
                expect((error as Error).message).toMatch(
                  /was killed by SIGKILL before it finished/,
                )
                // Named as what it was: nothing here ran out of time.
                expect((error as Error).message).not.toMatch(/did not finish/)
              } finally {
                locked.release()
              }
            })
          },
        )

        it('refuses the wrap when the scan could not be run at all', async () => {
          const error = await wrapWith({
            command: join(TEST_DIR, 'no-such-ripgrep'),
          }).catch((e: unknown) => e)

          expect(error).toBeInstanceOf(LinuxSandboxProfileError)
          expect((error as LinuxSandboxProfileError).code).toBe(
            'deny_scan_failed',
          )
          expect((error as Error).message).toMatch(/could not be run/)
        })

        it("lets the caller's own abort through as itself", async () => {
          const controller = new AbortController()
          controller.abort()

          const error = await wrapWith(
            { command: '/bin/sh', args: ['-c', 'true'] },
            controller.signal,
          ).catch((e: unknown) => e)

          expect((error as Error).name).toBe('AbortError')
          expect(error).not.toBeInstanceOf(LinuxSandboxProfileError)
        })

        it.if(process.getuid?.() !== 0 && bwrapCanNamespace())(
          'denies a nested repository the real rg could not walk past',
          async () => {
            const cwd = process.cwd()
            // Named with rg's own separator between a path and its message,
            // so the whole round trip runs against a name that defeats
            // reading paths out of stderr.
            const blind = join(cwd, 'a: b')
            const hook = join(cwd, 'nested', '.git', 'hooks', 'pre-commit')
            const wrap = (command: string): Promise<string> =>
              wrapCommandWithSandboxLinux({
                command,
                needsNetworkRestriction: false,
                allowAllUnixSockets: true,
                readConfig: undefined,
                writeConfig: { allowOnly: [cwd], denyWithinAllow: [] },
              })
            const run = (command: string) =>
              spawnSync(command, {
                shell: true,
                encoding: 'utf8',
                timeout: 30000,
                cwd,
              })

            mkdirSync(blind, { recursive: true })
            try {
              // The first command leaves a directory the next command's scan
              // cannot read: that scan fails, and the hooks of the nested
              // repository beside it must be denied all the same.
              const first = run(
                await wrap(`echo ${BOOTED} && chmod 000 ${quote([blind])}`),
              )
              expect(first.stdout).toContain(BOOTED)
              expect(first.status).toBe(0)
              cleanupBwrapMountPoints({ force: true })

              const second = run(
                await wrap(
                  `echo ${BOOTED}; echo X > ${hook} || echo DENIED; ` +
                    `chmod 755 ${quote([blind])} || echo BLIND_DENIED`,
                ),
              )
              expect(second.stdout).toContain(BOOTED)
              expect(second.stdout).toContain('DENIED')
              // The directory the scan could not read is read-only inside the
              // sandbox, so the command cannot open it up for the next scan.
              expect(second.stdout).toContain('BLIND_DENIED')
              expect(readFileSync(hook, 'utf8')).toBe(ORIGINAL_CONTENT)
            } finally {
              chmodSync(blind, 0o755)
              rmSync(blind, { recursive: true, force: true })
            }
          },
          60000,
        )
      })

      it.if(isLinux)(
        'scans with the ripgrep config file left out of it',
        async () => {
          // RIPGREP_CONFIG_PATH routinely points inside a project, at a file
          // a sandboxed command can write, and one line of it is enough to
          // make the scan list nothing and report no error for it.
          const rc = join(TEST_DIR, 'scan.rgrc')
          writeFileSync(rc, '--max-filesize=1\n')
          const saved = process.env.RIPGREP_CONFIG_PATH
          process.env.RIPGREP_CONFIG_PATH = rc
          try {
            const result = await runSandboxedWrite(
              'nested/.git/hooks/pre-commit',
              MODIFIED_CONTENT,
            )

            expect(result.success).toBe(false)
            expect(readFileSync('nested/.git/hooks/pre-commit', 'utf8')).toBe(
              ORIGINAL_CONTENT,
            )
          } finally {
            if (saved === undefined) delete process.env.RIPGREP_CONFIG_PATH
            else process.env.RIPGREP_CONFIG_PATH = saved
            rmSync(rc, { force: true })
          }
        },
      )

      it('still lets a command create a .git file where none exists', async () => {
        mkdirSync('fresh-checkout', { recursive: true })
        try {
          const result = await runSandboxedWrite(
            'fresh-checkout/.git',
            'gitdir: ../.git/modules/fresh',
          )

          expect(result.success).toBe(true)
          expect(readFileSync('fresh-checkout/.git', 'utf8').trim()).toBe(
            'gitdir: ../.git/modules/fresh',
          )
        } finally {
          rmSync('fresh-checkout', { recursive: true, force: true })
        }
      })

      it('does not let a .git file be created outside the allowed write paths', async () => {
        const opts = { allowOnly: [join(TEST_DIR, 'nested', 'src')] }
        mkdirSync('unlisted', { recursive: true })
        try {
          const pointer = await runSandboxedWrite(
            'unlisted/.git',
            'gitdir: /tmp/elsewhere',
            opts,
          )
          expect(pointer.success).toBe(false)
          expect(existsSync('unlisted/.git')).toBe(false)

          const control = await runSandboxedWrite(
            'nested/src/ok.txt',
            MODIFIED_CONTENT,
            opts,
          )
          expect(control.success).toBe(true)
        } finally {
          rmSync('unlisted', { recursive: true, force: true })
        }
      })

      describe('from a linked worktree checkout', () => {
        const opts = { allowOnly: [TEST_DIR] }
        beforeEach(() => {
          process.chdir(join(TEST_DIR, 'wt-checkout'))
        })
        afterEach(() => {
          rmSync(join(TEST_DIR, 'wt-checkout', 'notes.txt'), { force: true })
        })

        it("blocks the main repository's hooks, which the worktree's commits run", async () => {
          const hook = join(TEST_DIR, '.git', 'hooks', 'pre-commit')
          const denied = await runSandboxedWrite(hook, MODIFIED_CONTENT, opts)
          expect(denied.success).toBe(false)
          expect(readFileSync(hook, 'utf8')).toBe(ORIGINAL_CONTENT)

          const control = await runSandboxedWrite(
            'notes.txt',
            MODIFIED_CONTENT,
            opts,
          )
          expect(control.success).toBe(true)
        })

        it("blocks rewriting the worktree's commondir", async () => {
          // It names the git directory whose hooks and config a commit here
          // runs, so it chooses what the denies below apply to.
          const commondir = join(
            TEST_DIR,
            '.git',
            'worktrees',
            'wt',
            'commondir',
          )
          const denied = await runSandboxedWrite(commondir, '../../decoy', opts)

          expect(denied.success).toBe(false)
          expect(readFileSync(commondir, 'utf8')).toBe('../..\n')
        })

        it("blocks repointing the checkout's own .git file", async () => {
          const original = readFileSync('.git', 'utf8')
          const result = await runSandboxedWrite(
            '.git',
            'gitdir: /tmp/elsewhere',
            opts,
          )

          expect(result.success).toBe(false)
          expect(readFileSync('.git', 'utf8')).toBe(original)
        })
      })

      describe('from a checkout whose pointer is padded with newlines', () => {
        // git strips them from the end of the file and follows the pointer,
        // so reading less of the file than git does would leave the target's
        // hooks and config writable.
        const opts = { allowOnly: [TEST_DIR] }
        beforeEach(() => {
          process.chdir(join(TEST_DIR, 'padded-checkout'))
        })
        afterEach(() => {
          rmSync(join(TEST_DIR, 'padded-checkout', 'notes.txt'), {
            force: true,
          })
        })

        it("blocks the padded pointer's target, as an unpadded one's", async () => {
          const config = join(TEST_DIR, 'padded-target', 'config')
          const denied = await runSandboxedWrite(config, MODIFIED_CONTENT, opts)
          expect(denied.success).toBe(false)
          expect(readFileSync(config, 'utf8')).toBe(ORIGINAL_CONTENT)

          const hook = join(TEST_DIR, 'padded-target', 'hooks', 'pre-commit')
          const hookWrite = await runSandboxedWrite(
            hook,
            MODIFIED_CONTENT,
            opts,
          )
          expect(hookWrite.success).toBe(false)
          expectNotWritten(hook)

          const control = await runSandboxedWrite(
            'notes.txt',
            MODIFIED_CONTENT,
            opts,
          )
          expect(control.success).toBe(true)
        })
      })

      it("matches dangerous names below cwd only, not in cwd's own location", async () => {
        process.chdir(join(TEST_DIR, '.vscode', 'ext', 'foo'))

        const denied = await runSandboxedWrite(
          'sub/.gitconfig',
          MODIFIED_CONTENT,
        )
        expect(denied.success).toBe(false)
        expect(readFileSync('sub/.gitconfig', 'utf8')).toBe(ORIGINAL_CONTENT)

        const control = await runSandboxedWrite('sub/ok.txt', MODIFIED_CONTENT)
        expect(control.success).toBe(true)
      })

      it('denies a nested .claude/commands as a directory once the scan reaches it', async () => {
        // pkg/.claude/commands/x.md is four segments deep: found with a
        // depth of 4 (macOS matches by pattern at any depth), and then the
        // whole directory is read-only, new files included.
        const existing = await runSandboxedWrite(
          'pkg/.claude/commands/x.md',
          MODIFIED_CONTENT,
          { mandatoryDenySearchDepth: 4 },
        )
        expect(existing.success).toBe(false)
        expect(readFileSync('pkg/.claude/commands/x.md', 'utf8')).toBe(
          ORIGINAL_CONTENT,
        )

        const created = await runSandboxedWrite(
          'pkg/.claude/commands/new.md',
          MODIFIED_CONTENT,
          { mandatoryDenySearchDepth: 4 },
        )
        expect(created.success).toBe(false)
        expect(existsSync('pkg/.claude/commands/new.md')).toBe(false)
      })
    })

    describe('Dangerous directories should be blocked', () => {
      for (const dir of getDangerousDirectories()) {
        it(`blocks writes to ${dir}/`, async () => {
          const target = `${dir}/${DIRECTORY_PROBE_FILE}`
          const result = await runSandboxedWrite(target, MODIFIED_CONTENT)

          expect(result.success).toBe(false)
          expect(readFileSync(target, 'utf8')).toBe(ORIGINAL_CONTENT)
        })
      }
    })

    describe('The same names below the working directory', () => {
      /** What holds files the host runs or trusts, and a file in each. */
      const heldIn = new Map([
        ['.git/hooks', 'pre-commit'],
        ...getDangerousDirectories().map(
          dir => [dir, DIRECTORY_PROBE_FILE] as const,
        ),
      ])
      const existing = [
        ...DANGEROUS_FILES,
        '.git/config',
        ...[...heldIn].map(([dir, file]) => `${dir}/${file}`),
      ]
      const populate = (container: string): void => {
        for (const dir of heldIn.keys()) {
          mkdirSync(join(TEST_DIR, container, dir), { recursive: true })
        }
        for (const name of [...existing, 'safe-file.txt']) {
          writeFileSync(join(TEST_DIR, container, name), ORIGINAL_CONTENT)
        }
      }
      // How far the default depth reaches on Linux: every name in `sub`, and
      // the files alone in `a/b`.
      const covered = [
        ['sub', existing],
        ['a/b', DANGEROUS_FILES],
      ] as const
      const beyond = 'a/b/c'
      beforeAll(() => ['sub', 'a/b', beyond].forEach(populate))

      for (const [container, names] of covered) {
        for (const name of names) {
          it(`blocks writes to ${container}/${name}`, async () => {
            const target = `${container}/${name}`
            const result = await runSandboxedWrite(target, MODIFIED_CONTENT)

            expect(result.success).toBe(false)
            expect(readFileSync(target, 'utf8')).toBe(ORIGINAL_CONTENT)
          })
        }
        it(`allows writes to ${container}/safe-file.txt`, async () => {
          const target = `${container}/safe-file.txt`
          const result = await runSandboxedWrite(target, MODIFIED_CONTENT)

          expect(result.success).toBe(true)
          expect(readFileSync(target, 'utf8').trim()).toBe(MODIFIED_CONTENT)
        })
      }

      for (const dir of heldIn.keys()) {
        it(`blocks a new file in sub/${dir}/`, async () => {
          const target = `sub/${dir}/new-file`
          const result = await runSandboxedWrite(target, MODIFIED_CONTENT)

          expect(result.success).toBe(false)
          expect(existsSync(target)).toBe(false)
        })
      }

      for (const state of ['empty', 'missing']) {
        it(`blocks a new hook in a repository whose hooks directory is ${state}`, async () => {
          const repository = `hooks-${state}`
          const hooks = `${repository}/.git/hooks`
          mkdirSync(join(TEST_DIR, repository, '.git'), { recursive: true })
          writeFileSync(
            join(TEST_DIR, repository, '.git', 'HEAD'),
            'ref: refs/heads/main',
          )
          if (state === 'empty') mkdirSync(join(TEST_DIR, hooks))

          const result = await runSandboxed(
            `mkdir -p '${hooks}' && echo x > '${hooks}/pre-commit'`,
          )

          expect(result.success).toBe(false)
          expect(existsSync(`${hooks}/pre-commit`)).toBe(false)
          // The rest of the repository is still the command's to write.
          expect(
            (await runSandboxedWrite(`${repository}/.git/HEAD`, 'x')).success,
          ).toBe(true)
        })
      }

      for (const [file, line] of [
        ['.gitignore', 'sub/'],
        ['.ignore', '*'],
      ] as const) {
        it(`blocks them all the same when ${file} holds ${line}`, async () => {
          writeFileSync(join(TEST_DIR, file), `${line}\n`)
          try {
            for (const name of ['sub/.bashrc', 'sub/.git/hooks/pre-commit']) {
              const result = await runSandboxedWrite(name, MODIFIED_CONTENT)

              expect([name, result.success]).toEqual([name, false])
              expect(readFileSync(name, 'utf8')).toBe(ORIGINAL_CONTENT)
            }
          } finally {
            rmSync(join(TEST_DIR, file))
          }
        })
      }

      it.if(isLinux)(
        "blocks them all the same whatever ripgrep's configuration file says",
        async () => {
          const configuration = join(TEST_DIR, 'ripgrep-configuration')
          writeFileSync(configuration, '--glob=!sub\n')
          process.env.RIPGREP_CONFIG_PATH = configuration
          try {
            const result = await runSandboxedWrite(
              'sub/.bashrc',
              MODIFIED_CONTENT,
            )

            expect(result.success).toBe(false)
            expect(readFileSync('sub/.bashrc', 'utf8')).toBe(ORIGINAL_CONTENT)
          } finally {
            delete process.env.RIPGREP_CONFIG_PATH
            rmSync(configuration)
          }
        },
      )

      it('blocks them all the same beside a directory that cannot be read', async () => {
        const unreadable = join(TEST_DIR, 'unreadable')
        mkdirSync(unreadable, { mode: 0o000 })
        try {
          for (const name of ['sub/.bashrc', 'sub/.git/hooks/pre-commit']) {
            const result = await runSandboxedWrite(name, MODIFIED_CONTENT)

            expect([name, result.success]).toEqual([name, false])
            expect(readFileSync(name, 'utf8')).toBe(ORIGINAL_CONTENT)
          }
        } finally {
          rmdirSync(unreadable)
        }
      })

      for (const [directory, mode] of [
        ['locked', 0o000],
        ['locked/.git', 0o000],
        // As deep as one of the names can itself lie.
        ['locked/.claude/commands', 0o000],
        // Can be listed, and nothing in it looked at.
        ['locked', 0o444],
        // The other way about.
        ['locked', 0o111],
      ] as const) {
        // With one thread, as on one CPU, ripgrep words what it says otherwise.
        for (const threads of [[], ['-j1']]) {
          it(`blocks them all the same in locked/ when ${directory} has mode ${mode.toString(8)} (rg ${threads.join()})`, async () => {
            const names = [
              '.bashrc',
              '.git/config',
              '.git/hooks/pre-commit',
              `.claude/commands/${DIRECTORY_PROBE_FILE}`,
            ]
            populate('locked')
            try {
              for (const name of names) {
                // Each time: a command that is not held gives the mode back.
                chmodSync(join(TEST_DIR, directory), mode)
                const result = await runSandboxed(
                  `chmod 755 locked '${directory}'; echo x > 'locked/${name}'`,
                  { ripgrepArgs: threads },
                )

                expect([name, result.success]).toEqual([name, false])
              }
            } finally {
              chmodSync(join(TEST_DIR, directory), 0o755)
            }
            for (const name of names) {
              expect(readFileSync(`locked/${name}`, 'utf8')).toBe(
                ORIGINAL_CONTENT,
              )
            }
          })
        }
      }

      // root reads a directory of any mode.
      it.if(isLinux && process.getuid?.() !== 0)(
        'finds what cannot be read on the file system, whatever ripgrep says',
        async () => {
          const project = join(TEST_DIR, 'hints')
          const outside = join(TEST_DIR, 'hints-outside')
          for (const directory of [
            join(project, 'is-readable'),
            join(project, 'really-locked'),
            join(project, 'locked: too'),
            join(project, 'locked\\so'),
            join(project, 'one-thread'),
            join(project, 'no-prefix'),
            join(project, 'listed-only/child'),
            join(project, 'entered-only'),
            join(project, 'a/b/c/too-deep'),
            join(outside, 'behind-a-link'),
          ]) {
            mkdirSync(directory, { recursive: true })
          }
          symlinkSync(outside, join(project, 'link'))
          const locked = [
            join(project, 'really-locked'),
            join(project, 'locked: too'),
            join(project, 'locked\\so'),
            join(project, 'one-thread'),
            join(project, 'no-prefix'),
            join(project, 'a/b/c/too-deep'),
            join(outside, 'behind-a-link'),
          ]
          // What a name in the tree could make ripgrep say.
          const said = [
            'is-readable',
            'really-locked',
            'a/b/c/too-deep',
            'link/behind-a-link',
            '../hints-outside/behind-a-link',
            'not-there/at-all',
            'entered-only/not-there',
            'locked: too',
            'locked\\so',
            'listed-only/child',
          ].map(
            name => `rg: ${project}/${name}: Permission denied (os error 13)`,
          )
          said.push(
            `rg: ${project}/one-thread: IO error for operation on ${project}/one-thread: Permission denied (os error 13)`,
            `${project}/no-prefix: Permission denied (os error 13)`,
          )
          const standIn = join(TEST_DIR, 'says-it-could-not-read')
          const asked = join(TEST_DIR, 'was-asked')
          writeFileSync(
            standIn,
            [
              '#!/bin/sh',
              `printf '%s\\n' "$@" > '${asked}'`,
              ...said.map(line => `echo '${line}' >&2`),
              'exit 2',
            ].join('\n'),
            { mode: 0o755 },
          )
          process.chdir(project)
          locked.forEach(directory => chmodSync(directory, 0o000))
          chmodSync(join(project, 'listed-only'), 0o444)
          chmodSync(join(project, 'entered-only'), 0o111)
          try {
            const wrapped = await wrapCommandWithSandboxLinux({
              command: 'true',
              needsNetworkRestriction: false,
              readConfig: undefined,
              writeConfig: { allowOnly: ['.'], denyWithinAllow: [] },
              ripgrepConfig: { command: standIn },
            })

            const found = unreadableDirectories(project, 3, Date.now() + 10_000)
            expect(found.own.sort()).toEqual(
              [
                'really-locked',
                'locked: too',
                'locked\\so',
                'listed-only',
                'entered-only',
                'one-thread',
                'no-prefix',
              ]
                .map(name => join(project, name))
                .sort(),
            )
            // As deep as ripgrep opens a directory, and looks at nothing in.
            expect(found.leftAlone).toBe(1)
            // Nobody else's mode can be given back from inside.
            const uid = process.getuid!()
            const getuid = spyOn(process, 'getuid').mockReturnValue(uid + 1)
            try {
              expect(
                unreadableDirectories(project, 3, Date.now() + 10_000),
              ).toEqual({ own: [], leftAlone: 8 })
            } finally {
              getuid.mockRestore()
            }
            expect(wrapped).toContain('really-locked')
            for (const name of ['is-readable', 'behind-a-link', 'too-deep']) {
              expect(wrapped).not.toContain(name)
            }
            expect(readFileSync(asked, 'utf8').split('\n')).toEqual(
              expect.arrayContaining(['--no-ignore', '--no-config']),
            )
          } finally {
            for (const directory of [
              ...locked,
              join(project, 'listed-only'),
              join(project, 'entered-only'),
            ]) {
              chmodSync(directory, 0o755)
            }
          }
        },
      )

      it.if(isLinux)(
        'takes no directory above the working directory for one of the names',
        async () => {
          const project = join(TEST_DIR, 'above', '.idea', 'project')
          mkdirSync(join(project, 'sub'), { recursive: true })
          writeFileSync(join(project, 'sub', '.bashrc'), ORIGINAL_CONTENT)
          process.chdir(project)

          expect((await runSandboxedWrite('sub/.bashrc', 'x')).success).toBe(
            false,
          )
          expect((await runSandboxedWrite('safe-file.txt', 'x')).success).toBe(
            true,
          )
        },
      )

      for (const [container, names] of [
        ['a/b', existing.filter(name => name.includes('/'))],
        [beyond, existing],
      ] as const) {
        it.if(isLinux)(
          `looks no deeper than the depth says: ${names.length} names in ${container}/`,
          async () => {
            for (const name of names) {
              const target = `${container}/${name}`
              const result = await runSandboxedWrite(target, MODIFIED_CONTENT)

              expect([target, result.success]).toEqual([target, true])
            }
          },
          60_000,
        )
      }
    })

    describe('Safe files should still be writable', () => {
      it('allows writes to regular files', async () => {
        const result = await runSandboxedWrite(
          'safe-file.txt',
          MODIFIED_CONTENT,
        )

        expect(result.success).toBe(true)
        expect(readFileSync('safe-file.txt', 'utf8').trim()).toBe(
          MODIFIED_CONTENT,
        )
      })

      it('allows writes to .git/objects (not hooks/config)', async () => {
        const result = await runSandboxedWrite(
          '.git/objects/test-obj',
          MODIFIED_CONTENT,
        )

        expect(result.success).toBe(true)
        expect(readFileSync('.git/objects/test-obj', 'utf8').trim()).toBe(
          MODIFIED_CONTENT,
        )
      })

      it('allows writes to .git/refs/heads (not hooks/config)', async () => {
        const result = await runSandboxedWrite(
          '.git/refs/heads/main',
          MODIFIED_CONTENT,
        )

        expect(result.success).toBe(true)
        expect(readFileSync('.git/refs/heads/main', 'utf8').trim()).toBe(
          MODIFIED_CONTENT,
        )
      })

      it('allows writes to .git/index (not hooks/config)', async () => {
        const result = await runSandboxedWrite('.git/index', MODIFIED_CONTENT)

        expect(result.success).toBe(true)
        expect(readFileSync('.git/index', 'utf8').trim()).toBe(MODIFIED_CONTENT)
      })

      it('allows writes to .claude/ files outside commands/agents', async () => {
        const result = await runSandboxedWrite(
          '.claude/some-other-file.txt',
          MODIFIED_CONTENT,
        )

        expect(result.success).toBe(true)
        expect(readFileSync('.claude/some-other-file.txt', 'utf8').trim()).toBe(
          MODIFIED_CONTENT,
        )
      })
    })

    describe('allowGitConfig option', () => {
      async function runSandboxedWriteWithGitConfig(
        filePath: string,
        content: string,
        allowGitConfig: boolean,
      ): Promise<{ success: boolean; stderr: string }> {
        const platform = getPlatform()
        const command = `echo '${content}' > '${filePath}'`

        const writeConfig = {
          allowOnly: ['.'],
          denyWithinAllow: [],
        }

        let wrappedCommand: string
        if (platform === 'macos') {
          wrappedCommand = wrapCommandWithSandboxMacOS({
            command,
            needsNetworkRestriction: false,
            readConfig: undefined,
            writeConfig,
            allowGitConfig,
          })
        } else {
          wrappedCommand = await wrapCommandWithSandboxLinux({
            command,
            needsNetworkRestriction: false,
            readConfig: undefined,
            writeConfig,
            allowGitConfig,
          })
        }

        const result = spawnSync(wrappedCommand, {
          shell: true,
          encoding: 'utf8',
          timeout: 10000,
        })

        return {
          success: result.status === 0,
          stderr: result.stderr || '',
        }
      }

      it('blocks writes to .git/config when allowGitConfig is false (default)', async () => {
        // Reset .git/config to original content
        writeFileSync('.git/config', ORIGINAL_CONTENT)

        const result = await runSandboxedWriteWithGitConfig(
          '.git/config',
          MODIFIED_CONTENT,
          false,
        )

        expect(result.success).toBe(false)
        expect(readFileSync('.git/config', 'utf8')).toBe(ORIGINAL_CONTENT)
      })

      it('allows writes to .git/config when allowGitConfig is true', async () => {
        // Reset .git/config to original content
        writeFileSync('.git/config', ORIGINAL_CONTENT)

        const result = await runSandboxedWriteWithGitConfig(
          '.git/config',
          MODIFIED_CONTENT,
          true,
        )

        expect(result.success).toBe(true)
        expect(readFileSync('.git/config', 'utf8').trim()).toBe(
          MODIFIED_CONTENT,
        )
      })

      it('still blocks writes to .git/hooks even when allowGitConfig is true', async () => {
        // Reset pre-commit to original content
        writeFileSync('.git/hooks/pre-commit', ORIGINAL_CONTENT)

        const result = await runSandboxedWriteWithGitConfig(
          '.git/hooks/pre-commit',
          MODIFIED_CONTENT,
          true,
        )

        expect(result.success).toBe(false)
        expect(readFileSync('.git/hooks/pre-commit', 'utf8')).toBe(
          ORIGINAL_CONTENT,
        )
      })
    })

    describe.if(isLinux)(
      'Non-existent deny path protection and cleanup (Linux only)',
      () => {
        // This tests that:
        // 1. Non-existent deny paths within writable areas are blocked by mounting
        //    /dev/null at the first non-existent component
        // 2. The mount point artifacts bwrap creates on the host are cleaned up
        //    by cleanupBwrapMountPoints()
        //
        // Background: When bwrap does --ro-bind /dev/null /nonexistent/path, it
        // creates an empty file on the host as a mount point. Without cleanup,
        // these "ghost dotfiles" persist and pollute the working directory.

        async function runSandboxedWriteWithDenyPaths(
          command: string,
          denyPaths: string[],
        ): Promise<{ success: boolean; stdout: string; stderr: string }> {
          const platform = getPlatform()
          if (platform !== 'linux') {
            return { success: true, stdout: '', stderr: '' }
          }

          const writeConfig = {
            allowOnly: ['.'],
            denyWithinAllow: denyPaths,
          }

          const wrappedCommand = await wrapCommandWithSandboxLinux({
            command,
            needsNetworkRestriction: false,
            readConfig: undefined,
            writeConfig,
            enableWeakerNestedSandbox: true,
          })

          const result = spawnSync(wrappedCommand, {
            shell: true,
            encoding: 'utf8',
            timeout: 10000,
          })

          return {
            success: result.status === 0,
            stdout: result.stdout || '',
            stderr: result.stderr || '',
          }
        }

        // --- Security: deny path blocking ---

        it('blocks creation of non-existent file when parent dir exists', async () => {
          // .claude directory exists from beforeAll setup
          // .claude/settings.json does NOT exist
          const nonExistentFile = '.claude/settings.json'

          const result = await runSandboxedWriteWithDenyPaths(
            `echo '{"hooks":{}}' > '${nonExistentFile}'`,
            [join(TEST_DIR, nonExistentFile)],
          )

          expect(result.success).toBe(false)
          // Verify file content was NOT written (bwrap creates empty mount point)
          const content = readFileSync(nonExistentFile, 'utf8')
          expect(content).toBe('')

          cleanupBwrapMountPoints()
        })

        it('blocks creation of non-existent file when parent dir also does not exist', async () => {
          const nonExistentPath = 'nonexistent-dir/settings.json'

          const result = await runSandboxedWriteWithDenyPaths(
            `mkdir -p nonexistent-dir && echo '{"hooks":{}}' > '${nonExistentPath}'`,
            [join(TEST_DIR, nonExistentPath)],
          )

          expect(result.success).toBe(false)
          // bwrap mounts an empty read-only directory at first non-existent
          // intermediate component, blocking mkdir inside it
          const stat = statSync('nonexistent-dir')
          expect(stat.isDirectory()).toBe(true)

          cleanupBwrapMountPoints()
        })

        it('blocks creation of deeply nested non-existent path', async () => {
          const nonExistentPath = 'a/b/c/file.txt'

          const result = await runSandboxedWriteWithDenyPaths(
            `mkdir -p a/b/c && echo 'test' > '${nonExistentPath}'`,
            [join(TEST_DIR, nonExistentPath)],
          )

          expect(result.success).toBe(false)
          // bwrap mounts an empty read-only directory at 'a', blocking the
          // entire subtree
          const stat = statSync('a')
          expect(stat.isDirectory()).toBe(true)

          cleanupBwrapMountPoints()
        })

        // --- Cleanup: mount point artifact removal ---

        it('cleanupBwrapMountPoints removes mount point artifacts', async () => {
          const nonExistentPath = 'cleanup-test-dir/file.txt'

          await runSandboxedWriteWithDenyPaths(
            `echo test > '${nonExistentPath}'`,
            [join(TEST_DIR, nonExistentPath)],
          )

          // Mount point artifact should exist on host after bwrap exits
          expect(existsSync('cleanup-test-dir')).toBe(true)

          // Clean up
          cleanupBwrapMountPoints()

          // Artifact should be gone
          expect(existsSync('cleanup-test-dir')).toBe(false)
        })

        it('cleanupBwrapMountPoints removes multiple mount points from a single command', async () => {
          // Two non-existent deny paths in different subtrees
          const path1 = 'ghost-dir-a/secret.txt'
          const path2 = 'ghost-dir-b/secret.txt'

          await runSandboxedWriteWithDenyPaths(
            `mkdir -p ghost-dir-a ghost-dir-b`,
            [join(TEST_DIR, path1), join(TEST_DIR, path2)],
          )

          // Both mount point artifacts should exist
          expect(existsSync('ghost-dir-a')).toBe(true)
          expect(existsSync('ghost-dir-b')).toBe(true)

          cleanupBwrapMountPoints()

          // Both should be cleaned up
          expect(existsSync('ghost-dir-a')).toBe(false)
          expect(existsSync('ghost-dir-b')).toBe(false)
        })

        it('cleanupBwrapMountPoints preserves non-empty directories', async () => {
          const nonExistentPath = 'preserve-test-dir/file.txt'

          await runSandboxedWriteWithDenyPaths(
            `echo test > '${nonExistentPath}'`,
            [join(TEST_DIR, nonExistentPath)],
          )

          // Simulate something else creating content in the mount point directory
          // (e.g., another process created files here legitimately)
          const mountPoint = join(TEST_DIR, 'preserve-test-dir')
          if (existsSync(mountPoint)) {
            // Create a file inside — cleanup should NOT delete non-empty directories
            writeFileSync(join(mountPoint, 'real-file.txt'), 'real content')
          }

          cleanupBwrapMountPoints()

          // Directory with real content should be preserved
          if (existsSync(mountPoint)) {
            expect(statSync(mountPoint).isDirectory()).toBe(true)
            const content = readFileSync(
              join(mountPoint, 'real-file.txt'),
              'utf8',
            )
            expect(content).toBe('real content')
            // Manual cleanup for this test
            rmSync(mountPoint, { recursive: true, force: true })
          }
        })

        it('cleanupBwrapMountPoints is safe to call when there are no mount points', () => {
          // Should not throw
          cleanupBwrapMountPoints()
          cleanupBwrapMountPoints()
        })

        // --- Concurrent sandbox mount point cleanup ---
        //
        // When two sandboxed commands run concurrently and one finishes first,
        // cleanupBwrapMountPoints() must NOT delete mount point files that the
        // still-running sandbox depends on. Deleting a mountpoint's dentry on the
        // host detaches the bind mount in the child namespace, so the deny rule
        // stops applying inside the still-running sandbox.

        it('defers mount point cleanup while another sandbox is still running', async () => {
          const raceDir = join(TEST_DIR, 'race-test')
          mkdirSync(raceDir, { recursive: true })
          mkdirSync(join(raceDir, '.claude'), { recursive: true })

          const originalDir = process.cwd()
          process.chdir(raceDir)

          try {
            const protectedFile = join(raceDir, '.claude', 'settings.json')
            const writeConfig = {
              allowOnly: ['.'],
              denyWithinAllow: [protectedFile],
            }

            // Sandbox A: long-running command that sleeps then tries to write
            // to the denied path. The write should be blocked.
            // allowAllUnixSockets skips seccomp (environment-dependent) while
            // keeping the filesystem isolation we're testing.
            const wrappedA = await wrapCommandWithSandboxLinux({
              command: `sleep 2; echo '{"hooks":{}}' > .claude/settings.json`,
              needsNetworkRestriction: false,
              readConfig: undefined,
              writeConfig,
              enableWeakerNestedSandbox: true,
              allowAllUnixSockets: true,
            })

            const childA = spawn(wrappedA, { shell: true })
            const exitA = new Promise<number | null>(resolve => {
              childA.on('exit', code => resolve(code))
            })

            // Wait for bwrap A to start and create the mount point on the host
            await new Promise(r => setTimeout(r, 500))
            expect(existsSync(protectedFile)).toBe(true)

            // Sandbox B: short command. When it finishes, the caller invokes
            // cleanupBwrapMountPoints() — simulating the real-world race.
            const wrappedB = await wrapCommandWithSandboxLinux({
              command: 'true',
              needsNetworkRestriction: false,
              readConfig: undefined,
              writeConfig,
              enableWeakerNestedSandbox: true,
              allowAllUnixSockets: true,
            })
            spawnSync(wrappedB, {
              shell: true,
              encoding: 'utf8',
              timeout: 10000,
            })

            // This is what the caller does after every command completes.
            // Without deferral, this would delete sandbox A's mount point too.
            cleanupBwrapMountPoints()

            // Wait for sandbox A to attempt its write
            await exitA

            // The deny rule must have held — the file should not contain the
            // write from sandbox A. If cleanup had deleted the mount point
            // early, A's bind mount would have detached and the write would
            // have landed on the host.
            const content = existsSync(protectedFile)
              ? readFileSync(protectedFile, 'utf8')
              : ''
            expect(content).not.toContain('hooks')

            cleanupBwrapMountPoints()
          } finally {
            process.chdir(originalDir)
            rmSync(raceDir, { recursive: true, force: true })
          }
        }, 15000)

        it('defers cleanup when two sandboxes share the same non-existent deny path', async () => {
          const raceDir = join(TEST_DIR, 'race-test-2')
          mkdirSync(raceDir, { recursive: true })
          mkdirSync(join(raceDir, '.claude'), { recursive: true })

          const originalDir = process.cwd()
          process.chdir(raceDir)

          try {
            const protectedFile = join(raceDir, '.claude', 'settings.json')
            const writeConfig = {
              allowOnly: ['.'],
              denyWithinAllow: [protectedFile],
            }

            // Generate both wrapped commands BEFORE spawning, so both see the
            // deny path as non-existent and both add it to bwrapMountPoints.
            const wrappedA = await wrapCommandWithSandboxLinux({
              command: `sleep 2; echo WRITTEN > .claude/settings.json`,
              needsNetworkRestriction: false,
              readConfig: undefined,
              writeConfig,
              enableWeakerNestedSandbox: true,
              allowAllUnixSockets: true,
            })
            const wrappedB = await wrapCommandWithSandboxLinux({
              command: 'sleep 0.5',
              needsNetworkRestriction: false,
              readConfig: undefined,
              writeConfig,
              enableWeakerNestedSandbox: true,
              allowAllUnixSockets: true,
            })

            const childA = spawn(wrappedA, { shell: true })
            const exitA = new Promise<number | null>(resolve => {
              childA.on('exit', code => resolve(code))
            })

            // Sandbox B runs and finishes first
            spawnSync(wrappedB, {
              shell: true,
              encoding: 'utf8',
              timeout: 10000,
            })
            cleanupBwrapMountPoints()

            await exitA

            const content = existsSync(protectedFile)
              ? readFileSync(protectedFile, 'utf8')
              : ''
            expect(content).not.toContain('WRITTEN')

            cleanupBwrapMountPoints()
          } finally {
            process.chdir(originalDir)
            rmSync(raceDir, { recursive: true, force: true })
          }
        }, 15000)

        it('deferred cleanup runs once all concurrent sandboxes finish', async () => {
          const raceDir = join(TEST_DIR, 'race-test-3')
          mkdirSync(raceDir, { recursive: true })
          mkdirSync(join(raceDir, '.claude'), { recursive: true })

          const originalDir = process.cwd()
          process.chdir(raceDir)

          try {
            const protectedFile = join(raceDir, '.claude', 'settings.json')
            const writeConfig = {
              allowOnly: ['.'],
              denyWithinAllow: [protectedFile],
            }

            const wrappedA = await wrapCommandWithSandboxLinux({
              command: 'sleep 1',
              needsNetworkRestriction: false,
              readConfig: undefined,
              writeConfig,
              enableWeakerNestedSandbox: true,
              allowAllUnixSockets: true,
            })
            const wrappedB = await wrapCommandWithSandboxLinux({
              command: 'true',
              needsNetworkRestriction: false,
              readConfig: undefined,
              writeConfig,
              enableWeakerNestedSandbox: true,
              allowAllUnixSockets: true,
            })

            const childA = spawn(wrappedA, { shell: true })
            const exitA = new Promise<void>(resolve => {
              childA.on('exit', () => resolve())
            })

            await new Promise(r => setTimeout(r, 300))
            expect(existsSync(protectedFile)).toBe(true)

            spawnSync(wrappedB, {
              shell: true,
              encoding: 'utf8',
              timeout: 10000,
            })
            cleanupBwrapMountPoints()

            // Cleanup deferred — mount point still present while A runs
            expect(existsSync(protectedFile)).toBe(true)

            await exitA
            cleanupBwrapMountPoints()

            // Both sandboxes done — mount point now cleaned up
            expect(existsSync(protectedFile)).toBe(false)
          } finally {
            process.chdir(originalDir)
            rmSync(raceDir, { recursive: true, force: true })
          }
        }, 15000)

        // The caller runs no cleanup for a wrap that threw, so what was
        // deferred to that wrap has nobody else to let go of it. A command that
        // ran and has ended is let go of by any clean-up call; what waits for
        // the count is the manifest of one that was wrapped and never started.

        const wrapInCwd = (
          command: string,
          failing?: Partial<LinuxSandboxParams>,
        ): Promise<string> =>
          wrapCommandWithSandboxLinux({
            command,
            needsNetworkRestriction: false,
            readConfig: undefined,
            writeConfig: { allowOnly: ['.'], denyWithinAllow: [] },
            enableWeakerNestedSandbox: true,
            allowAllUnixSockets: true,
            ...failing,
          })

        it.each(['aborted', 'refused'])(
          'runs the cleanup deferred to a wrap that is then %s',
          async how => {
            const raceDir = join(TEST_DIR, 'race-test-4')
            mkdirSync(raceDir, { recursive: true })
            process.chdir(raceDir)

            try {
              const manifestA = manifestOf(await wrapInCwd('true')) ?? ''
              expect(existsSync(manifestA)).toBe(true)

              // B is still looking for the mandatory denies when A's caller
              // cleans up, and nothing tells that call from one for B.
              const controller = new AbortController()
              const wrappedB = wrapInCwd('true', {
                abortSignal: controller.signal,
                binShell: how === 'refused' ? 'no-such-shell' : undefined,
              })
              cleanupBwrapMountPoints()
              expect(existsSync(manifestA)).toBe(true)

              if (how === 'aborted') controller.abort(new Error('stopped'))
              expect(await wrappedB.catch((e: unknown) => e)).toBeInstanceOf(
                Error,
              )
              expect(existsSync(manifestA)).toBe(false)
              expect(readdirSync(raceDir)).toEqual([])
            } finally {
              process.chdir(TEST_DIR)
              rmSync(raceDir, { recursive: true, force: true })
            }
          },
        )

        it('forgets the mount points planned by a wrap that is then refused', async () => {
          const raceDir = join(TEST_DIR, 'race-test-6')
          mkdirSync(raceDir, { recursive: true })
          process.chdir(raceDir)

          try {
            expect(
              await wrapInCwd('true', { binShell: 'no-such-shell' }).catch(
                (e: unknown) => e,
              ),
            ).toBeInstanceOf(Error)

            // bwrap never ran, so this is no mount point: the host made it.
            writeFileSync('.mcp.json', '')
            spawnSync(await wrapInCwd('true'), { shell: true, timeout: 10000 })
            cleanupBwrapMountPoints()
            expect(readdirSync(raceDir)).toEqual(['.mcp.json'])
          } finally {
            process.chdir(TEST_DIR)
            rmSync(raceDir, { recursive: true, force: true })
          }
        })

        it.each([
          ['aborted', 'counted along with it'],
          ['aborted', 'started since a forced cleanup'],
          ['handed out', 'started since a forced cleanup'],
        ])(
          'a wrap that is %s leaves the mount points of a running sandbox %s',
          async (how, which) => {
            const raceDir = join(TEST_DIR, 'race-test-5')
            mkdirSync(raceDir, { recursive: true })
            process.chdir(raceDir)
            // Stands in for ripgrep, and goes on until told to end.
            const heldScan = join(raceDir, 'held-scan')
            writeFileSync(
              heldScan,
              `#!/bin/sh\nuntil [ -e '${raceDir}/scanned' ]; do sleep 0.1; done\n`,
              { mode: 0o755 },
            )

            try {
              const controller = new AbortController()
              const wrappedB = wrapInCwd('true', {
                abortSignal: controller.signal,
                ripgrepConfig: { command: heldScan },
              })
              if (which !== 'counted along with it') {
                cleanupBwrapMountPoints({ force: true })
              }

              // C runs throughout, and tries a denied name once told to.
              const childC = spawn(
                await wrapInCwd(
                  'until [ -e go ]; do sleep 0.1; done; echo WRITTEN > .bashrc',
                ),
                { shell: true },
              )
              const exitC = new Promise<void>(resolve => {
                childC.on('exit', () => resolve())
              })
              while (!existsSync('.bashrc')) {
                await new Promise(r => setTimeout(r, 50))
              }

              if (how === 'aborted') {
                controller.abort(new Error('stopped'))
                expect(await wrappedB.catch((e: unknown) => e)).toBeInstanceOf(
                  Error,
                )
              } else {
                writeFileSync('scanned', '')
                spawnSync(await wrappedB, { shell: true, timeout: 10000 })
                cleanupBwrapMountPoints()
              }
              expect(existsSync('.bashrc')).toBe(true)

              // C is still counted, so the next command to end defers to it.
              spawnSync(await wrapInCwd('true'), {
                shell: true,
                timeout: 10000,
              })
              cleanupBwrapMountPoints()
              expect(existsSync('.bashrc')).toBe(true)

              writeFileSync('go', '')
              await exitC
              expect(readFileSync('.bashrc', 'utf8')).toBe('')

              cleanupBwrapMountPoints()
              expect(existsSync('.bashrc')).toBe(false)
            } finally {
              process.chdir(TEST_DIR)
              rmSync(raceDir, { recursive: true, force: true })
            }
          },
          15000,
        )

        // A running sandbox answers for its own mount points, so what a count
        // that is one short costs is the start of a command that is wrapped and
        // has not started: bubblewrap refuses to start without its manifest.
        it.each(['aborted', 'handed out'])(
          'a wrap from before a forced cleanup that is %s leaves the manifest of a command wrapped since',
          async how => {
            const raceDir = join(TEST_DIR, 'race-test-9')
            mkdirSync(raceDir, { recursive: true })
            process.chdir(raceDir)
            const heldScan = join(raceDir, 'held-scan')
            writeFileSync(
              heldScan,
              `#!/bin/sh\nuntil [ -e '${raceDir}/scanned' ]; do sleep 0.1; done\n`,
              { mode: 0o755 },
            )

            try {
              const controller = new AbortController()
              const wrappedB = wrapInCwd('true', {
                abortSignal: controller.signal,
                ripgrepConfig: { command: heldScan },
              })
              cleanupBwrapMountPoints({ force: true })
              const commandC = await wrapInCwd('echo STARTED')

              if (how === 'aborted') {
                controller.abort(new Error('stopped'))
                expect(await wrappedB.catch((e: unknown) => e)).toBeInstanceOf(
                  Error,
                )
              } else {
                writeFileSync('scanned', '')
                spawnSync(await wrappedB, { shell: true, timeout: 10000 })
                cleanupBwrapMountPoints()
              }

              const ranC = spawnSync(commandC, {
                shell: true,
                encoding: 'utf8',
                timeout: 10000,
              })
              expect(ranC.stdout).toContain('STARTED')
              cleanupBwrapMountPoints()
              expect(existsSync('.bashrc')).toBe(false)
            } finally {
              process.chdir(TEST_DIR)
              rmSync(raceDir, { recursive: true, force: true })
            }
          },
          15000,
        )

        it('leaves nothing of a directory mount point that another sandbox was wrapped under', async () => {
          const raceDir = join(TEST_DIR, 'race-test-7')
          mkdirSync(raceDir, { recursive: true })
          process.chdir(raceDir)

          try {
            const childT = spawn(
              await wrapInCwd('until [ -e go ]; do sleep 0.1; done'),
              { shell: true },
            )
            const exitT = new Promise<void>(resolve => {
              childT.on('exit', () => resolve())
            })
            while (!existsSync('.claude')) {
              await new Promise(r => setTimeout(r, 50))
            }

            // T's .claude is there by now, so X's mount points go inside it.
            // They are collected once X has ended; the directory is T's still.
            spawnSync(await wrapInCwd('true'), { shell: true, timeout: 10000 })
            cleanupBwrapMountPoints()
            expect(readdirSync('.claude')).toEqual([])

            writeFileSync('go', '')
            await exitT
            cleanupBwrapMountPoints()
            expect(readdirSync(raceDir)).toEqual(['go'])

            spawnSync(await wrapInCwd('true'), { shell: true, timeout: 10000 })
            cleanupBwrapMountPoints()
            expect(readdirSync(raceDir)).toEqual(['go'])
          } finally {
            process.chdir(TEST_DIR)
            rmSync(raceDir, { recursive: true, force: true })
          }
        }, 15000)

        it('takes only its own where the host has written at a mount point or inside one', async () => {
          const raceDir = join(TEST_DIR, 'race-test-8')
          mkdirSync(raceDir, { recursive: true })
          process.chdir(raceDir)

          try {
            // The second is wrapped with the first's .claude there.
            spawnSync(await wrapInCwd('true'), { shell: true, timeout: 10000 })
            spawnSync(await wrapInCwd('true'), { shell: true, timeout: 10000 })
            expect(readdirSync('.claude')).not.toEqual([])
            writeFileSync('.claude/kept', '')
            rmSync('.bashrc')
            writeFileSync('.bashrc', 'kept')

            cleanupBwrapMountPoints()
            cleanupBwrapMountPoints()
            expect(readdirSync(raceDir).sort()).toEqual(['.bashrc', '.claude'])
            expect(readdirSync('.claude')).toEqual(['kept'])
            expect(readFileSync('.bashrc', 'utf8')).toBe('kept')
          } finally {
            process.chdir(TEST_DIR)
            rmSync(raceDir, { recursive: true, force: true })
          }
        })

        it('non-existent .git/hooks deny does not turn .git into a file, breaking git', async () => {
          // When .git doesn't exist yet, denying .git/hooks causes
          // findFirstNonExistentComponent to return .git itself. bwrap then does
          // --ro-bind /dev/null .git, creating .git as a FILE (not a directory).
          // Inside the sandbox, every git command fails because .git is a file.

          // Use a clean directory with NO .git
          const noGitDir = join(TEST_DIR, 'no-git-dir')
          mkdirSync(noGitDir, { recursive: true })

          const originalDir = process.cwd()
          process.chdir(noGitDir)

          try {
            const writeConfig = {
              allowOnly: ['.'],
              denyWithinAllow: [] as string[],
            }

            // This calls linuxGetMandatoryDenyPaths which unconditionally adds
            // .git/hooks to the deny list. When .git doesn't exist,
            // findFirstNonExistentComponent returns .git and bwrap mounts
            // /dev/null there — making .git a file.
            const wrappedCommand = await wrapCommandWithSandboxLinux({
              command: 'git init && git status',
              needsNetworkRestriction: false,
              readConfig: undefined,
              writeConfig,
              enableWeakerNestedSandbox: true,
            })

            const result = spawnSync(wrappedCommand, {
              shell: true,
              encoding: 'utf8',
              timeout: 10000,
            })

            // git init + git status should succeed — .git must be creatable as
            // a directory, not blocked by a /dev/null file mount.
            expect(result.status).toBe(0)

            cleanupBwrapMountPoints()
          } finally {
            process.chdir(originalDir)
            rmSync(noGitDir, { recursive: true, force: true })
          }
        })

        it('git worktree with .git as a file does not break sandboxed commands', async () => {
          // Reproduces the bug reported by nvidia/netflix with git worktrees:
          // In a worktree, .git is a FILE (e.g., "gitdir: /path/to/.git/worktrees/foo"),
          // not a directory. The mandatory deny list includes .git/hooks, but since
          // .git is a file, .git/hooks doesn't exist. The non-existent path handling
          // tries to mount /dev/null at .git/hooks, but bwrap can't create a mount
          // point under .git because it's a file — causing every command to fail.

          const worktreeDir = join(TEST_DIR, 'fake-worktree')
          mkdirSync(worktreeDir, { recursive: true })

          // Simulate a git worktree: .git is a file, not a directory
          writeFileSync(
            join(worktreeDir, '.git'),
            'gitdir: /tmp/fake-main-repo/.git/worktrees/my-branch',
          )

          const originalDir = process.cwd()
          process.chdir(worktreeDir)

          try {
            const writeConfig = {
              allowOnly: ['.'],
              denyWithinAllow: [] as string[],
            }

            // .git is a pointer file here, so it goes through
            // gitFileDenyPaths: the file itself and the hooks and config it
            // leads to are denied, and nothing is mounted under the file
            // (bwrap could not create a mount point there).
            const wrappedCommand = await wrapCommandWithSandboxLinux({
              command: 'echo hello',
              needsNetworkRestriction: false,
              readConfig: undefined,
              writeConfig,
              enableWeakerNestedSandbox: true,
            })

            const result = spawnSync(wrappedCommand, {
              shell: true,
              encoding: 'utf8',
              timeout: 10000,
            })

            // A simple echo should succeed — the .git-as-file worktree layout
            // should not cause the sandbox to fail.
            expect(result.status).toBe(0)
            expect(result.stdout.trim()).toBe('hello')
            cleanupBwrapMountPoints()
          } finally {
            process.chdir(originalDir)
            rmSync(worktreeDir, { recursive: true, force: true })
          }
        })

        it('does not leave ghost dotfiles after command + cleanup cycle', async () => {
          // This is the exact scenario from issue #85: running a sandboxed command
          // should NOT leave .bashrc, .gitconfig, etc. in the working directory.
          //
          // The mandatory deny list includes paths like ~/.bashrc, ~/.gitconfig.
          // When CWD is within an allowed write path and these dotfiles don't exist
          // in CWD, the old code left empty mount point files behind.

          // Use a clean subdirectory with no dotfiles
          const cleanDir = join(TEST_DIR, 'clean-subdir')
          mkdirSync(cleanDir, { recursive: true })

          const originalDir = process.cwd()
          process.chdir(cleanDir)

          try {
            // Run a simple command through the sandbox
            const writeConfig = {
              allowOnly: ['.'],
              denyWithinAllow: [] as string[],
            }

            const wrappedCommand = await wrapCommandWithSandboxLinux({
              command: 'echo hello',
              needsNetworkRestriction: false,
              readConfig: undefined,
              writeConfig,
              enableWeakerNestedSandbox: true,
            })

            spawnSync(wrappedCommand, {
              shell: true,
              encoding: 'utf8',
              timeout: 10000,
            })

            // Run cleanup (as the CLI / Claude Code would)
            cleanupBwrapMountPoints()

            // Verify no ghost dotfiles were left behind
            const { readdirSync } = await import('node:fs')
            const files = readdirSync(cleanDir)
            const ghostDotfiles = files.filter(f => f.startsWith('.'))
            expect(ghostDotfiles).toEqual([])
          } finally {
            process.chdir(originalDir)
            rmSync(cleanDir, { recursive: true, force: true })
          }
        })
      },
    )

    describe.if(isLinux)(
      'Symlink replacement attack protection (Linux only)',
      () => {
        // This tests the fix for symlink replacement attacks where an attacker
        // could delete a symlink and create a real directory with malicious content

        async function runSandboxedCommandWithDenyPaths(
          command: string,
          denyPaths: string[],
        ): Promise<{ success: boolean; stdout: string; stderr: string }> {
          const platform = getPlatform()
          if (platform !== 'linux') {
            return { success: true, stdout: '', stderr: '' }
          }

          const writeConfig = {
            allowOnly: ['.'],
            denyWithinAllow: denyPaths,
          }

          const wrappedCommand = await wrapCommandWithSandboxLinux({
            command,
            needsNetworkRestriction: false,
            readConfig: undefined,
            writeConfig,
          })

          const result = spawnSync(wrappedCommand, {
            shell: true,
            encoding: 'utf8',
            timeout: 10000,
          })

          return {
            success: result.status === 0,
            stdout: result.stdout || '',
            stderr: result.stderr || '',
          }
        }

        // bwrap mount destinations resolve symlinks, so a deny path crossing
        // a directory symlink is canonicalized and the deny applied to the
        // resolved target (resolve-before-mask). Masking the raw symlink
        // with /dev/null instead made bwrap abort at startup, failing every
        // sandboxed command whenever .claude was a symlink. The guarantees
        // around a deny path whose parent stays writable are unchanged from
        // the non-symlink case.
        it('denies writes through a symlinked .claude directory', async () => {
          // Setup: Create a symlink .claude -> decoy (simulating malicious git repo)
          const decoyDir = 'symlink-decoy'
          const claudeSymlink = 'symlink-claude'
          mkdirSync(decoyDir, { recursive: true })
          writeFileSync(join(decoyDir, 'settings.json'), '{}')
          symlinkSync(decoyDir, claudeSymlink)

          try {
            // The deny path is the settings.json through the symlink
            const denyPath = join(TEST_DIR, claudeSymlink, 'settings.json')

            // The sandbox must start despite the directory symlink in the
            // deny path (bwrap used to abort on the /dev/null symlink mask).
            const benign = await runSandboxedCommandWithDenyPaths('true', [
              denyPath,
            ])
            expect(benign.success).toBe(true)

            // Writing through the symlink must fail: the deny lands on the
            // resolved target, the inode the write actually reaches.
            const result = await runSandboxedCommandWithDenyPaths(
              `echo '{"hooks":{}}' > ${claudeSymlink}/settings.json`,
              [denyPath],
            )
            expect(result.success).toBe(false)
            expect(readFileSync(join(decoyDir, 'settings.json'), 'utf8')).toBe(
              '{}',
            )
          } finally {
            // Cleanup
            rmSync(claudeSymlink, { force: true })
            rmSync(decoyDir, { recursive: true, force: true })
          }
        })

        it('denies writes to a file reached through a directory symlink', async () => {
          // Setup: Create a symlink
          const targetDir = 'symlink-target-dir'
          const symlinkPath = 'protected-symlink'
          mkdirSync(targetDir, { recursive: true })
          writeFileSync(join(targetDir, 'file.txt'), 'content')
          symlinkSync(targetDir, symlinkPath)

          try {
            const denyPath = join(TEST_DIR, symlinkPath, 'file.txt')

            // Assert the sandbox starts first: a write-denied assertion alone
            // also passes when bwrap aborts, which is the failure this deny
            // path used to cause.
            const benign = await runSandboxedCommandWithDenyPaths('true', [
              denyPath,
            ])
            expect(benign.success).toBe(true)

            // The file is write-protected both through the symlink and via
            // its resolved path.
            for (const writePath of [
              `${symlinkPath}/file.txt`,
              `${targetDir}/file.txt`,
            ]) {
              const result = await runSandboxedCommandWithDenyPaths(
                `echo tampered > ${writePath}`,
                [denyPath],
              )
              expect(result.success).toBe(false)
            }
            expect(readFileSync(join(targetDir, 'file.txt'), 'utf8')).toBe(
              'content',
            )
          } finally {
            rmSync(symlinkPath, { force: true })
            rmSync(targetDir, { recursive: true, force: true })
          }
        })
      },
    )
  },
)

describe('macGetMandatoryDenyEntries - Unit Tests', () => {
  it('includes .git/config in deny patterns when allowGitConfig is false', () => {
    const patterns = macGetMandatoryDenyEntries(false).map(e => e.path)

    // Should include .git/config pattern
    const hasGitConfigPattern = patterns.some(
      p => p.includes('.git/config') || p.endsWith('.git/config'),
    )
    expect(hasGitConfigPattern).toBe(true)
  })

  it('excludes .git/config from deny patterns when allowGitConfig is true', () => {
    const patterns = macGetMandatoryDenyEntries(true).map(e => e.path)

    // Should NOT include .git/config pattern
    const hasGitConfigPattern = patterns.some(
      p => p.includes('.git/config') || p.endsWith('.git/config'),
    )
    expect(hasGitConfigPattern).toBe(false)
  })

  it('always includes .git/hooks in deny patterns regardless of allowGitConfig', () => {
    const patternsWithoutGitConfig = macGetMandatoryDenyEntries(false).map(
      e => e.path,
    )
    const patternsWithGitConfig = macGetMandatoryDenyEntries(true).map(
      e => e.path,
    )

    // Both should include .git/hooks pattern
    const hasHooksPatternFalse = patternsWithoutGitConfig.some(p =>
      p.includes('.git/hooks'),
    )
    const hasHooksPatternTrue = patternsWithGitConfig.some(p =>
      p.includes('.git/hooks'),
    )

    expect(hasHooksPatternFalse).toBe(true)
    expect(hasHooksPatternTrue).toBe(true)
  })

  it.if(!isWindows)(
    'carries a symlinked entry as the link, the target and the git directory',
    () => {
      // A Seatbelt filter matches where the write lands, so the entry's own
      // path covers the link and the target needs an entry of its own; the
      // git directory whole is what keeps the link from being replaced,
      // which on macOS the unlink re-deny of a literal entry does as well.
      const dir = realpathSync(mkdtempSync(join(tmpdir(), 'mac-git-deny-')))
      const saved = process.cwd()
      try {
        const gitDir = join(dir, '.git')
        mkdirSync(gitDir, { recursive: true })
        writeFileSync(join(gitDir, 'HEAD'), 'ref: refs/heads/main')
        const shared = join(dir, 'shared-hooks')
        mkdirSync(shared, { recursive: true })
        symlinkSync(shared, join(gitDir, 'hooks'))
        process.chdir(dir)

        const paths = macGetMandatoryDenyEntries(false)
          .filter(entry => !entry.glob)
          .map(entry => entry.path)

        expect(paths).toContain(join(gitDir, 'hooks'))
        expect(paths).toContain(shared)
        // Not the git directory whole: a Seatbelt filter matches the link's
        // own path for a rename or an unlink, so the entry covers it, and
        // git writes in the repository go on working.
        expect(paths).not.toContain(gitDir)
      } finally {
        process.chdir(saved)
        rmSync(dir, { recursive: true, force: true })
      }
    },
  )

  it.if(!isWindows)('names every hop of a chain, and denies none whole', () => {
    // A Seatbelt filter matches the name a rename or an unlink uses, so each
    // hop's own path is the whole handle on it there: no directory is denied
    // whole for one, and git goes on working in the repository.
    const dir = realpathSync(mkdtempSync(join(tmpdir(), 'mac-git-chain-')))
    const saved = process.cwd()
    try {
      const gitDir = join(dir, '.git')
      mkdirSync(gitDir, { recursive: true })
      writeFileSync(join(gitDir, 'HEAD'), 'ref: refs/heads/main')
      const landing = join(dir, '.githooks')
      mkdirSync(landing, { recursive: true })
      const hop = join(dir, 'hooks-link')
      symlinkSync('.githooks', hop)
      symlinkSync('../hooks-link', join(gitDir, 'hooks'))
      process.chdir(dir)

      const paths = macGetMandatoryDenyEntries(false)
        .filter(entry => !entry.glob)
        .map(entry => entry.path)

      expect(paths).toContain(join(gitDir, 'hooks'))
      expect(paths).toContain(hop)
      expect(paths).toContain(landing)
      // Neither the git directory nor the directory holding the hop: holding
      // a link by the directory around it is the other backend's answer.
      expect(paths).not.toContain(gitDir)
      expect(paths).not.toContain(dir)
    } finally {
      process.chdir(saved)
      rmSync(dir, { recursive: true, force: true })
    }
  })

  it.if(!isWindows)("names every hop of a pointer's own path", () => {
    // The same answer where the chain is the VALUE of a `.git` pointer file
    // rather than an entry of a git directory: each link the path goes
    // through is a name of its own, and nothing is denied whole for it.
    const dir = realpathSync(mkdtempSync(join(tmpdir(), 'mac-git-pointer-')))
    const saved = process.cwd()
    try {
      const checkout = join(dir, 'checkout')
      mkdirSync(checkout, { recursive: true })
      const gitDir = join(dir, 'real', 'gd')
      mkdirSync(join(gitDir, 'hooks'), { recursive: true })
      writeFileSync(join(gitDir, 'HEAD'), 'ref: refs/heads/main')
      const hop = join(checkout, 'linkdir')
      symlinkSync(join(dir, 'real'), hop)
      writeFileSync(join(checkout, '.git'), 'gitdir: linkdir/gd\n')
      process.chdir(checkout)

      const paths = macGetMandatoryDenyEntries(false)
        .filter(entry => !entry.glob)
        .map(entry => entry.path)

      expect(paths).toContain(join(checkout, '.git'))
      expect(paths).toContain(hop)
      expect(paths).toContain(join(hop, 'gd', 'hooks'))
      expect(paths).not.toContain(checkout)
    } finally {
      process.chdir(saved)
      rmSync(dir, { recursive: true, force: true })
    }
  })

  it.if(!isWindows)(
    "names a pointer's git directory by the landing as well as through the link",
    () => {
      // The link spelling holds the link's own name and nothing under it,
      // because Seatbelt compares its filters against the path an operation
      // resolved to; the landing holds every write that reaches the git
      // directory, by either spelling. Both, or half the chain is open.
      const dir = realpathSync(mkdtempSync(join(tmpdir(), 'mac-git-landing-')))
      const saved = process.cwd()
      try {
        const checkout = join(dir, 'checkout')
        mkdirSync(checkout, { recursive: true })
        const gitDir = join(dir, 'real', 'gd')
        mkdirSync(join(gitDir, 'hooks'), { recursive: true })
        writeFileSync(join(gitDir, 'HEAD'), 'ref: refs/heads/main')
        const hop = join(checkout, 'linkdir')
        symlinkSync(join(dir, 'real'), hop)
        writeFileSync(join(checkout, '.git'), 'gitdir: linkdir/gd\n')
        process.chdir(checkout)

        const paths = macGetMandatoryDenyEntries(false)
          .filter(entry => !entry.glob)
          .map(entry => entry.path)

        // Through the link: the hop's own name, and the git directory's
        // files as the pointer spells them.
        expect(paths).toContain(hop)
        expect(paths).toContain(join(hop, 'gd', 'hooks'))
        expect(paths).toContain(join(hop, 'gd', 'config'))
        // And the same files where the kernel puts them, absent ones
        // included: `commondir` and `config.worktree` are not there, and
        // creating one is what the deny blocks.
        expect(paths).toContain(join(gitDir, 'hooks'))
        expect(paths).toContain(join(gitDir, 'config'))
        expect(paths).toContain(join(gitDir, 'commondir'))
        expect(paths).toContain(join(gitDir, 'config.worktree'))
        // One entry per spelling and no more.
        expect(paths.length).toBe(new Set(paths).size)
      } finally {
        process.chdir(saved)
        rmSync(dir, { recursive: true, force: true })
      }
    },
  )

  it.if(!isWindows)('never denies what a chain HOP leads to', () => {
    // A hop's own name is the whole handle on it: what it leads to is a
    // directory nothing asked to deny - the `/private/var` a `/var/folders`
    // pointer walks through - and denying that would take the checkout and
    // everything beside it read-only. What lies past the hop is held by the
    // git directory's own deny paths, which do carry both spellings.
    const dir = realpathSync(mkdtempSync(join(tmpdir(), 'mac-git-hop-')))
    const saved = process.cwd()
    try {
      const checkout = join(dir, 'checkout')
      mkdirSync(checkout, { recursive: true })
      const shared = join(dir, 'shared')
      const gitDir = join(shared, 'gd')
      mkdirSync(join(gitDir, 'hooks'), { recursive: true })
      writeFileSync(join(gitDir, 'HEAD'), 'ref: refs/heads/main')
      const hop = join(checkout, 'linkdir')
      symlinkSync(shared, hop)
      writeFileSync(join(checkout, '.git'), 'gitdir: linkdir/gd\n')
      process.chdir(checkout)

      const paths = macGetMandatoryDenyEntries(false)
        .filter(pathEntry => !pathEntry.glob)
        .map(pathEntry => pathEntry.path)

      expect(paths).toContain(hop)
      expect(paths).toContain(join(gitDir, 'hooks'))
      expect(paths).not.toContain(shared)
      expect(paths).not.toContain(dir)
      expect(paths).not.toContain(checkout)
    } finally {
      process.chdir(saved)
      rmSync(dir, { recursive: true, force: true })
    }
  })

  it.if(!isWindows)('names every link a looping entry went through', () => {
    // A filter matches the name an unlink or a rename uses, so each link of
    // the loop is held by its own name here and nothing else is needed: the
    // command that would make `.git/hooks` reach a directory has to remove
    // one of them first.
    const dir = realpathSync(mkdtempSync(join(tmpdir(), 'mac-git-loop-')))
    const saved = process.cwd()
    try {
      const gitDir = join(dir, '.git')
      mkdirSync(gitDir, { recursive: true })
      writeFileSync(join(gitDir, 'HEAD'), 'ref: refs/heads/main')
      const links = join(dir, 'links')
      mkdirSync(links, { recursive: true })
      symlinkSync('b', join(links, 'a'))
      symlinkSync('a', join(links, 'b'))
      symlinkSync('../links/a', join(gitDir, 'hooks'))
      process.chdir(dir)

      const paths = macGetMandatoryDenyEntries(false)
        .filter(pathEntry => !pathEntry.glob)
        .map(pathEntry => pathEntry.path)

      expect(paths).toContain(join(links, 'a'))
      expect(paths).toContain(join(links, 'b'))
      // What a hop leads to is never denied, and a loop leads nowhere to
      // deny in the first place: the directory holding the links stays out.
      expect(paths).not.toContain(links)
      expect(paths.length).toBe(new Set(paths).size)
    } finally {
      process.chdir(saved)
      rmSync(dir, { recursive: true, force: true })
    }
  })

  it.if(!isWindows)(
    'names a submodule reached through a symlinked modules entry both ways',
    () => {
      // A symlinked ENTRY of `.git/modules` puts the whole submodule git
      // directory behind a link, so every file denied inside it is spelled
      // through that link. The entry's own name is what an unlink of it
      // uses; where it leads is what a hook written into that submodule
      // matches.
      const dir = realpathSync(mkdtempSync(join(tmpdir(), 'mac-git-module-')))
      const saved = process.cwd()
      try {
        const gitDir = join(dir, '.git')
        mkdirSync(join(gitDir, 'modules'), { recursive: true })
        writeFileSync(join(gitDir, 'HEAD'), 'ref: refs/heads/main')
        const submodule = join(dir, 'elsewhere')
        mkdirSync(join(submodule, 'hooks'), { recursive: true })
        writeFileSync(join(submodule, 'HEAD'), 'ref: refs/heads/main')
        const entry = join(gitDir, 'modules', 'lib')
        symlinkSync(submodule, entry)
        process.chdir(dir)

        const paths = macGetMandatoryDenyEntries(false)
          .filter(pathEntry => !pathEntry.glob)
          .map(pathEntry => pathEntry.path)

        expect(paths).toContain(join(entry, 'hooks'))
        expect(paths).toContain(join(entry, 'config'))
        expect(paths).toContain(join(submodule, 'hooks'))
        expect(paths).toContain(join(submodule, 'config'))
        expect(paths).toContain(join(submodule, 'config.worktree'))
        expect(paths.length).toBe(new Set(paths).size)
      } finally {
        process.chdir(saved)
        rmSync(dir, { recursive: true, force: true })
      }
    },
  )

  it.if(!isWindows)(
    'names the hops of a symlinked entry once, landing and all',
    () => {
      // The chain of a symlinked entry is walked from a resolved directory,
      // so each hop and the landing are already the paths the kernel reaches:
      // nothing here has a second spelling, and nothing is named twice.
      const dir = realpathSync(mkdtempSync(join(tmpdir(), 'mac-git-entry-')))
      const saved = process.cwd()
      try {
        const gitDir = join(dir, '.git')
        mkdirSync(gitDir, { recursive: true })
        writeFileSync(join(gitDir, 'HEAD'), 'ref: refs/heads/main')
        const landing = join(dir, '.githooks')
        mkdirSync(landing, { recursive: true })
        const hop = join(dir, 'hooks-link')
        symlinkSync('.githooks', hop)
        symlinkSync('../hooks-link', join(gitDir, 'hooks'))
        process.chdir(dir)

        const paths = macGetMandatoryDenyEntries(false)
          .filter(pathEntry => !pathEntry.glob)
          .map(pathEntry => pathEntry.path)

        expect(paths).toContain(join(gitDir, 'hooks'))
        expect(paths).toContain(hop)
        expect(paths).toContain(landing)
        expect(paths.length).toBe(new Set(paths).size)
      } finally {
        process.chdir(saved)
        rmSync(dir, { recursive: true, force: true })
      }
    },
  )

  it.if(!isWindows)(
    'leaves an ordinary repository named exactly once per path',
    () => {
      // Nothing on the way is a symlink, so the walk lands where the path was
      // written and the second spelling is the first: no repository without
      // one pays a single extra rule for this.
      const dir = realpathSync(mkdtempSync(join(tmpdir(), 'mac-git-plain-')))
      const saved = process.cwd()
      try {
        const gitDir = join(dir, '.git')
        mkdirSync(join(gitDir, 'hooks'), { recursive: true })
        writeFileSync(join(gitDir, 'HEAD'), 'ref: refs/heads/main')
        process.chdir(dir)

        const paths = macGetMandatoryDenyEntries(false)
          .filter(entry => !entry.glob)
          .map(entry => entry.path)

        expect(paths).toContain(join(gitDir, 'hooks'))
        expect(paths.length).toBe(new Set(paths).size)
      } finally {
        process.chdir(saved)
        rmSync(dir, { recursive: true, force: true })
      }
    },
  )

  it('defaults to blocking .git/config when no argument provided', () => {
    const patterns = macGetMandatoryDenyEntries().map(e => e.path)

    const hasGitConfigPattern = patterns.some(
      p => p.includes('.git/config') || p.endsWith('.git/config'),
    )
    expect(hasGitConfigPattern).toBe(true)
  })
})
// Read by the Linux and macOS backends alone.
describe.if(!isWindows)('Git metadata deny paths - Unit Tests', () => {
  let dir: string
  const savedCwd = process.cwd()

  beforeEach(() => {
    // Real, so a temporary directory that is itself reached through a
    // symlink (macOS /var) does not make every path here two paths.
    dir = realpathSync(mkdtempSync(join(tmpdir(), 'git-deny-paths-')))
  })

  afterEach(() => {
    process.chdir(savedCwd)
    cleanupBwrapMountPoints({ force: true })
    rmSync(dir, { recursive: true, force: true })
  })

  /** A directory git would accept as a git directory. */
  function makeGitDir(gitDir: string): string {
    mkdirSync(join(gitDir, 'hooks'), { recursive: true })
    writeFileSync(join(gitDir, 'HEAD'), 'ref: refs/heads/main')
    return gitDir
  }

  /** A checkout whose `.git` file holds exactly `contents`. */
  function writePointer(checkout: string, contents: string | Buffer): string {
    mkdirSync(join(dir, checkout), { recursive: true })
    const pointer = join(dir, checkout, '.git')
    writeFileSync(pointer, contents)
    return pointer
  }

  function makePointer(checkout: string, target: string): string {
    return writePointer(checkout, `gitdir: ${target}\n`)
  }

  it('denies commondir in every git directory, and config.worktree with config', () => {
    expect(gitDirDenyPaths('/repo/.git', false)).toEqual([
      '/repo/.git/hooks',
      '/repo/.git/commondir',
      '/repo/.git/config',
      '/repo/.git/config.worktree',
    ])
    expect(gitDirDenyPaths('/repo/.git', true)).toEqual([
      '/repo/.git/hooks',
      '/repo/.git/commondir',
    ])
  })

  it('denies a git directory whole where an entry is a symlink, and what the link leads to', () => {
    // The deny of the entry lands where the link points - the Linux bind
    // resolves the path, a Seatbelt filter matches where the write goes -
    // so the link's own path carries nothing, and it sits in a directory
    // the sandbox can write. The git directory whole is the handle on it.
    const gitDir = makeGitDir(join(dir, 'repo', '.git'))
    const shared = join(dir, 'repo', 'shared-hooks')
    mkdirSync(shared, { recursive: true })
    rmSync(join(gitDir, 'hooks'), { recursive: true })
    symlinkSync(shared, join(gitDir, 'hooks'))

    const denies = gitDirDenies(gitDir, false)

    expect(denies.denyPaths).toEqual([
      join(gitDir, 'hooks'),
      shared,
      join(gitDir, 'commondir'),
      join(gitDir, 'config'),
      join(gitDir, 'config.worktree'),
    ])
    // What a read-only bind of the git directory would not cover, and so
    // what a degrade of it has to keep.
    expect(denies.escapingDenyPaths).toEqual([shared])
    // What holds the link, for the backend whose denies resolve.
    expect(denies.linkedEntryDirs).toEqual([gitDir])
  })

  it('leaves an ordinary git directory exactly as it was', () => {
    const gitDir = makeGitDir(join(dir, 'repo', '.git'))
    writeFileSync(join(gitDir, 'config'), '[core]\n')

    expect(gitDirDenies(gitDir, false)).toEqual({
      denyPaths: gitDirDenyPaths(gitDir, false),
      escapingDenyPaths: [],
      linkedEntryDirs: [],
      chainHops: [],
    })
  })

  it('keeps a link inside the git directory out of the escaping set', () => {
    // hooks -> hooks.real, both under the git directory: the bind that
    // denies the directory whole covers the target as well, so a degrade
    // has nothing to keep.
    const gitDir = makeGitDir(join(dir, 'repo', '.git'))
    mkdirSync(join(gitDir, 'hooks.real'), { recursive: true })
    rmSync(join(gitDir, 'hooks'), { recursive: true })
    symlinkSync(join(gitDir, 'hooks.real'), join(gitDir, 'hooks'))

    const denies = gitDirDenies(gitDir, false)

    expect(denies.linkedEntryDirs).toEqual([gitDir])
    expect(denies.escapingDenyPaths).toEqual([])
  })

  it('denies where a DANGLING entry lands, so the target cannot be created', () => {
    // The link is there and its target is not: a command can create the
    // target and the host's git runs what it finds there. Denying the
    // landing is what blocks creating it.
    const gitDir = makeGitDir(join(dir, 'repo', '.git'))
    const landing = join(dir, 'repo', 'not-there-yet')
    rmSync(join(gitDir, 'hooks'), { recursive: true })
    symlinkSync(landing, join(gitDir, 'hooks'))

    const denies = gitDirDenies(gitDir, false)

    expect(denies.denyPaths).toContain(landing)
    expect(denies.linkedEntryDirs).toEqual([gitDir])
    expect(denies.escapingDenyPaths).toEqual([landing])
  })

  it('follows a chain of dangling links to where a write through it would land, and holds the hop', () => {
    // The landing's deny blocks creating it and the entry's deny holds the
    // entry; the link in between is held by neither, and a command that
    // points it elsewhere moves where the chain lands without touching
    // either end.
    const gitDir = makeGitDir(join(dir, 'repo', '.git'))
    const landing = join(dir, 'repo', 'end')
    const middle = join(dir, 'repo', 'middle')
    symlinkSync(landing, middle)
    rmSync(join(gitDir, 'hooks'), { recursive: true })
    symlinkSync(middle, join(gitDir, 'hooks'))

    const denies = gitDirDenies(gitDir, false)

    expect(denies.denyPaths).toContain(landing)
    expect(denies.denyPaths).toContain(middle)
    expect(denies.escapingDenyPaths).toContain(middle)
    expect(denies.chainHops).toEqual([
      {
        kind: 'entry',
        chain: 'resolved',
        source: join(gitDir, 'hooks'),
        link: middle,
        holder: join(dir, 'repo'),
      },
    ])
  })

  it('carries every hop of a two-link chain', () => {
    // hooks -> ../hooks-link -> .githooks: the entry and the landing are
    // denied, and the link between them is a name of its own.
    const gitDir = makeGitDir(join(dir, 'repo', '.git'))
    const landing = join(dir, 'repo', '.githooks')
    const hop = join(dir, 'repo', 'hooks-link')
    mkdirSync(landing, { recursive: true })
    symlinkSync('.githooks', hop)
    rmSync(join(gitDir, 'hooks'), { recursive: true })
    symlinkSync('../hooks-link', join(gitDir, 'hooks'))

    const denies = gitDirDenies(gitDir, false)

    expect(denies.denyPaths).toEqual([
      join(gitDir, 'hooks'),
      landing,
      hop,
      join(gitDir, 'commondir'),
      join(gitDir, 'config'),
      join(gitDir, 'config.worktree'),
    ])
    // No bind of the git directory covers either, so a degrade keeps both.
    expect(denies.escapingDenyPaths).toEqual([landing, hop])
    expect(denies.chainHops).toEqual([
      {
        kind: 'entry',
        chain: 'resolved',
        source: join(gitDir, 'hooks'),
        link: hop,
        holder: join(dir, 'repo'),
      },
    ])
  })

  it('names a symlinked directory component on the way as a hop', () => {
    // hooks -> ../shared/hooks with shared -> shared-real: the hop is a
    // directory in the middle of the path, not a second link at the end,
    // and retargeting it moves the chain just the same.
    const gitDir = makeGitDir(join(dir, 'repo', '.git'))
    const real = join(dir, 'repo', 'shared-real')
    mkdirSync(join(real, 'hooks'), { recursive: true })
    const hop = join(dir, 'repo', 'shared')
    symlinkSync('shared-real', hop)
    rmSync(join(gitDir, 'hooks'), { recursive: true })
    symlinkSync('../shared/hooks', join(gitDir, 'hooks'))

    const denies = gitDirDenies(gitDir, false)

    expect(denies.denyPaths).toContain(join(real, 'hooks'))
    expect(denies.denyPaths).toContain(hop)
    expect(denies.chainHops).toEqual([
      {
        kind: 'entry',
        chain: 'resolved',
        source: join(gitDir, 'hooks'),
        link: hop,
        holder: join(dir, 'repo'),
      },
    ])
  })

  it('leaves a hop inside the git directory to the whole-directory deny', () => {
    // hooks -> hooks-link -> ../.githooks, with the hop under the git
    // directory: the bind that denies the directory whole already holds
    // it, so it needs no directory of its own and a degrade may drop it.
    // Its own path is still named, for the backend that has no such bind.
    const gitDir = makeGitDir(join(dir, 'repo', '.git'))
    const landing = join(dir, 'repo', '.githooks')
    const hop = join(gitDir, 'hooks-link')
    mkdirSync(landing, { recursive: true })
    symlinkSync('../.githooks', hop)
    rmSync(join(gitDir, 'hooks'), { recursive: true })
    symlinkSync('hooks-link', join(gitDir, 'hooks'))

    const denies = gitDirDenies(gitDir, false)

    expect(denies.denyPaths).toContain(hop)
    expect(denies.escapingDenyPaths).toEqual([landing])
    expect(denies.chainHops).toEqual([
      {
        kind: 'entry',
        chain: 'resolved',
        source: join(gitDir, 'hooks'),
        link: hop,
        holder: undefined,
      },
    ])
    expect(denies.linkedEntryDirs).toEqual([gitDir])
  })

  it.if(process.getuid?.() !== 0)(
    'holds the hops of a chain it could read where a later one cannot be',
    () => {
      // The chain runs into a directory this process cannot search, so what
      // is behind it is unknown and the git directory is denied whole for
      // it. The hop it DID read is held as a resolved chain's is.
      const gitDir = makeGitDir(join(dir, 'repo', '.git'))
      const locked = join(dir, 'repo', 'locked')
      const hop = join(dir, 'repo', 'mid')
      mkdirSync(locked, { recursive: true })
      symlinkSync(join(locked, 'target'), hop)
      rmSync(join(gitDir, 'hooks'), { recursive: true })
      symlinkSync('../mid', join(gitDir, 'hooks'))
      chmodSync(locked, 0o000)
      try {
        const denies = gitDirDenies(gitDir, false)

        expect(denies.denyPaths).toContain(join(gitDir, 'hooks'))
        expect(denies.denyPaths).toContain(hop)
        expect(denies.escapingDenyPaths).toContain(hop)
        expect(denies.linkedEntryDirs).toEqual([gitDir])
        expect(denies.chainHops).toEqual([
          {
            kind: 'entry',
            chain: 'resolved',
            source: join(gitDir, 'hooks'),
            link: hop,
            holder: join(dir, 'repo'),
          },
        ])
      } finally {
        chmodSync(locked, 0o755)
      }
    },
  )

  it('denies the git directory whole for an entry that is a symlink loop, and nothing behind it', () => {
    // A loop reaches nothing: there is nothing to deny at the other end,
    // and nothing a command can create through it. Replacing the link is
    // what the whole-directory deny is for.
    const gitDir = makeGitDir(join(dir, 'repo', '.git'))
    rmSync(join(gitDir, 'hooks'), { recursive: true })
    symlinkSync(join(gitDir, 'hooks'), join(gitDir, 'hooks'))

    const denies = gitDirDenies(gitDir, false)

    expect(denies.denyPaths).toEqual([
      join(gitDir, 'commondir'),
      join(gitDir, 'config'),
      join(gitDir, 'config.worktree'),
    ])
    expect(denies.linkedEntryDirs).toEqual([gitDir])
    expect(denies.escapingDenyPaths).toEqual([])
    // A link onto itself is the one link of its own chain, and the whole
    // deny of the directory holding it covers that: no hop is left over.
    expect(denies.chainHops).toEqual([])
  })

  it('holds the links a looping entry goes through, which are what makes it loop', () => {
    // hooks -> ../links/a, a -> b, b -> a. The entry reaches nothing while
    // that stands, and the whole-directory deny holds the entry, but the
    // two links are ordinary work-tree names: a command that puts a
    // directory at either one makes the chain reach it, and the host's git
    // runs what is inside. Every link the walk visited before it gave up is
    // therefore a hop, named once however many times the loop met it.
    const gitDir = makeGitDir(join(dir, 'repo', '.git'))
    const links = join(dir, 'repo', 'links')
    mkdirSync(links, { recursive: true })
    symlinkSync('b', join(links, 'a'))
    symlinkSync('a', join(links, 'b'))
    rmSync(join(gitDir, 'hooks'), { recursive: true })
    symlinkSync('../links/a', join(gitDir, 'hooks'))

    const denies = gitDirDenies(gitDir, false)

    expect(denies.denyPaths).toContain(join(links, 'a'))
    expect(denies.denyPaths).toContain(join(links, 'b'))
    // Neither is under the git directory, so a degrade to one bind of it
    // must not drop them.
    expect(denies.escapingDenyPaths).toEqual([
      join(links, 'a'),
      join(links, 'b'),
    ])
    expect(denies.linkedEntryDirs).toEqual([gitDir])
    expect(denies.chainHops).toEqual([
      {
        kind: 'entry',
        chain: 'unresolvable',
        source: join(gitDir, 'hooks'),
        link: join(links, 'a'),
        holder: links,
      },
      {
        kind: 'entry',
        chain: 'unresolvable',
        source: join(gitDir, 'hooks'),
        link: join(links, 'b'),
        holder: links,
      },
    ])
  })

  it('holds the hops before a loop it runs into', () => {
    // Two ordinary hops and then the loop: the chain gives up in the middle,
    // and the links it walked to get there are held like any others.
    const gitDir = makeGitDir(join(dir, 'repo', '.git'))
    const links = join(dir, 'repo', 'links')
    mkdirSync(links, { recursive: true })
    symlinkSync('second', join(links, 'first'))
    symlinkSync('loopA', join(links, 'second'))
    symlinkSync('loopB', join(links, 'loopA'))
    symlinkSync('loopA', join(links, 'loopB'))
    rmSync(join(gitDir, 'hooks'), { recursive: true })
    symlinkSync('../links/first', join(gitDir, 'hooks'))

    const denies = gitDirDenies(gitDir, false)

    expect(denies.chainHops.map(hop => hop.link)).toEqual([
      join(links, 'first'),
      join(links, 'second'),
      join(links, 'loopA'),
      join(links, 'loopB'),
    ])
    expect(denies.chainHops.every(hop => hop.chain === 'unresolvable')).toBe(
      true,
    )
  })

  it('leaves a loop confined to the git directory to the whole-directory deny', () => {
    // Both links live under the git directory, which is denied whole for
    // the entry anyway: each hop names no holder of its own, and nothing a
    // command can write is left over.
    const gitDir = makeGitDir(join(dir, 'repo', '.git'))
    symlinkSync('inner-b', join(gitDir, 'inner-a'))
    symlinkSync('inner-a', join(gitDir, 'inner-b'))
    rmSync(join(gitDir, 'hooks'), { recursive: true })
    symlinkSync('inner-a', join(gitDir, 'hooks'))

    const denies = gitDirDenies(gitDir, false)

    expect(denies.linkedEntryDirs).toEqual([gitDir])
    expect(denies.escapingDenyPaths).toEqual([])
    expect(denies.chainHops).toEqual([
      {
        kind: 'entry',
        chain: 'unresolvable',
        source: join(gitDir, 'hooks'),
        link: join(gitDir, 'inner-a'),
        holder: undefined,
      },
      {
        kind: 'entry',
        chain: 'unresolvable',
        source: join(gitDir, 'hooks'),
        link: join(gitDir, 'inner-b'),
        holder: undefined,
      },
    ])
  })

  it('holds a modules directory that is a symlink', () => {
    // `modules` is no deny path of its own - denying it whole would take
    // every submodule git directory under it read-only - but removing the
    // link and putting a directory in its place aims every submodule this
    // repository has at hooks nothing denied. So it is held the way a hop is:
    // its own name for the backend that matches a rename, and this git
    // directory denied whole for the one whose denies resolve.
    const gitDir = makeGitDir(join(dir, 'repo', '.git'))
    const elsewhere = join(dir, 'repo', 'nm')
    mkdirSync(elsewhere, { recursive: true })
    symlinkSync('../nm', join(gitDir, 'modules'))

    const denies = gitDirDenies(gitDir, false)

    expect(denies.denyPaths).toContain(join(gitDir, 'modules'))
    // Never what it leads to: that is a tree of submodule git directories,
    // each with precise denies of its own.
    expect(denies.denyPaths).not.toContain(elsewhere)
    expect(denies.linkedEntryDirs).toEqual([gitDir])
    expect(denies.chainHops).toEqual([
      {
        kind: 'entry',
        chain: 'resolved',
        source: join(gitDir, 'modules'),
        link: join(gitDir, 'modules'),
        holder: undefined,
      },
    ])
  })

  it('leaves an ordinary modules directory out of the denies entirely', () => {
    // The other half: a real `modules` is where every submodule git
    // directory lives, and each of those is denied precisely. Naming it
    // would take them all read-only.
    const gitDir = makeGitDir(join(dir, 'repo', '.git'))
    mkdirSync(join(gitDir, 'modules', 'lib'), { recursive: true })

    const denies = gitDirDenies(gitDir, false)

    expect(denies.denyPaths).toEqual(gitDirDenyPaths(gitDir, false))
    expect(denies.linkedEntryDirs).toEqual([])
    expect(denies.chainHops).toEqual([])
  })

  it("holds a submodule's own modules directory, and the chain past it", () => {
    // The shape the whole of this exists for: a submodule git directory
    // whose own `modules` leads out of the repository through a link.
    const gitDir = makeGitDir(join(dir, 'repo', '.git'))
    const submodule = makeGitDir(join(gitDir, 'modules', 'foo'))
    const links = join(dir, 'repo', 'links')
    mkdirSync(join(dir, 'repo', 'nm', 'bar'), { recursive: true })
    mkdirSync(links, { recursive: true })
    symlinkSync('../nm', join(links, 'hop'))
    symlinkSync('../../../links/hop', join(submodule, 'modules'))

    const denies = gitDirDenies(submodule, false)

    expect(denies.denyPaths).toContain(join(submodule, 'modules'))
    expect(denies.linkedEntryDirs).toEqual([submodule])
    // The link in the middle is a hop like any other, held by the
    // directory it sits in.
    expect(denies.chainHops.map(hop => hop.link)).toEqual([
      join(submodule, 'modules'),
      join(links, 'hop'),
    ])
    expect(denies.chainHops.map(hop => hop.holder)).toEqual([undefined, links])
  })

  it('holds the hops of an entry whose chain names something too long to exist', () => {
    // ENAMETOOLONG, not a loop: the chain reaches nothing all the same, and
    // the link it went through is a name a command can point elsewhere.
    const gitDir = makeGitDir(join(dir, 'repo', '.git'))
    const hop = join(dir, 'repo', 'hop')
    symlinkSync(`../${'n'.repeat(300)}`, hop)
    rmSync(join(gitDir, 'hooks'), { recursive: true })
    symlinkSync('../hop', join(gitDir, 'hooks'))

    const denies = gitDirDenies(gitDir, false)

    expect(denies.linkedEntryDirs).toEqual([gitDir])
    expect(denies.chainHops).toEqual([
      {
        kind: 'entry',
        chain: 'unresolvable',
        source: join(gitDir, 'hooks'),
        link: hop,
        holder: join(dir, 'repo'),
      },
    ])
  })

  it.if(process.getuid?.() !== 0)(
    'takes an entry it cannot look at for one that needs both denies',
    () => {
      // lstat refused: whether it is a link is unknown, so the entry keeps
      // the deny it has (and keeps it through a degrade, in case it is one)
      // and the git directory is denied whole as a link would need. `modules`
      // and `worktrees` are in the same position, and named for the backend
      // that holds a link by its own name.
      const gitDir = makeGitDir(join(dir, 'repo', '.git'))
      chmodSync(gitDir, 0o000)
      try {
        const denies = gitDirDenies(gitDir, false)

        expect(denies.denyPaths).toEqual([
          ...gitDirDenyPaths(gitDir, false),
          join(gitDir, 'modules'),
          join(gitDir, 'worktrees'),
        ])
        expect(denies.linkedEntryDirs).toEqual([gitDir])
        expect(denies.escapingDenyPaths).toEqual(gitDirDenyPaths(gitDir, false))
      } finally {
        chmodSync(gitDir, 0o755)
      }
    },
  )

  it('denies whole a git directory a pointer leads to, where an entry of it is a symlink', () => {
    // A pointer's target is a git directory like any other: the link
    // inside it is replaceable where nothing holds the directory around
    // it, and the backend whose denies resolve needs that held.
    const gitDir = makeGitDir(join(dir, 'gitdir'))
    const shared = join(dir, 'shared-hooks')
    mkdirSync(shared, { recursive: true })
    rmSync(join(gitDir, 'hooks'), { recursive: true })
    symlinkSync(shared, join(gitDir, 'hooks'))
    const pointer = makePointer('checkout', '../gitdir')

    const denies = gitFileDenies(pointer, false)

    expect(denies.denyPaths).toContain(shared)
    expect(denies.linkedEntryDirs).toEqual([gitDir])
    // The list a backend that needs none of that emits is what it was.
    expect(gitFileDenies(pointer, false).denyPaths).toEqual(denies.denyPaths)
  })

  it('denies the directory holding a symlinked modules entry, and where a dangling one lands', () => {
    // The walk follows the link and denies the git directory it reaches;
    // the link itself stays replaceable in a writable `modules`, and a
    // pointer that names it would then find whatever was put in its place.
    const gitDir = makeGitDir(join(dir, 'repo', '.git'))
    const modules = join(gitDir, 'modules')
    const outside = makeGitDir(join(dir, 'elsewhere'))
    mkdirSync(modules, { recursive: true })
    symlinkSync(outside, join(modules, 'lib'))
    const landing = join(dir, 'repo', 'not-there-yet')
    symlinkSync(landing, join(modules, 'gone'))

    const scan = submoduleGitDirs(modules)

    expect(scan.linkedEntryDirs).toEqual([modules])
    expect(scan.gitDirs).toEqual([join(modules, 'lib'), landing].sort())
    const tree = gitDirTreeDenies(gitDir, false)
    expect(tree.linkedEntryDirs).toEqual([modules])
    expect(gitDirTreeDenyPaths(tree)).toContain(join(landing, 'hooks'))
  })

  it('holds the hops between a symlinked modules entry and the git directory it reaches', () => {
    // modules/lib -> ../../mid -> elsewhere: the deny of `modules` holds
    // the entry and the git directory it reaches keeps its own denies, but
    // the link in between sits in the work tree and moves the whole chain.
    const gitDir = makeGitDir(join(dir, 'repo', '.git'))
    const modules = join(gitDir, 'modules')
    const outside = makeGitDir(join(dir, 'elsewhere'))
    const hop = join(dir, 'repo', 'mid')
    mkdirSync(modules, { recursive: true })
    symlinkSync(outside, hop)
    symlinkSync(hop, join(modules, 'lib'))

    const scan = submoduleGitDirs(modules)

    expect(scan.linkedEntryDirs).toEqual([modules])
    expect(scan.chainHops).toEqual([
      // The entry itself, for the backend that holds a link by its name.
      {
        kind: 'entry',
        chain: 'resolved',
        source: join(modules, 'lib'),
        link: join(modules, 'lib'),
        holder: undefined,
      },
      {
        kind: 'entry',
        chain: 'resolved',
        source: join(modules, 'lib'),
        link: hop,
        holder: join(dir, 'repo'),
      },
    ])
    // The hop's own path has no other list to sit in, so the flat form is
    // where a backend reads it.
    const tree = gitDirTreeDenies(gitDir, false)
    expect(gitDirTreeDenyPaths(tree)).toContain(hop)
    expect(tree.chainHops).toEqual(scan.chainHops)
  })

  it('gives the files git reads a placeholder that is no redirect', () => {
    // `.` is the git directory itself, which is where git looks when there
    // is no commondir, and no config.worktree reads as an empty one does.
    expect(gitRedirectPlaceholder('/repo/.git/commondir')).toBe('.\n')
    expect(gitRedirectPlaceholder('/repo/.git/config.worktree')).toBe('')
    expect(gitRedirectPlaceholder('/repo/.git/config')).toBeUndefined()
    expect(gitRedirectPlaceholder('/repo/.git/hooks')).toBeUndefined()
  })

  it('follows a pointer to the git directory it names', () => {
    const gitDir = makeGitDir(join(dir, 'gitdir'))
    const pointer = makePointer('checkout', '../gitdir')

    expect(gitFileDenies(pointer, false).denyPaths).toEqual([
      pointer,
      ...gitDirDenyPaths(gitDir, false),
    ])
  })

  it("follows a linked worktree's commondir as well", () => {
    const main = makeGitDir(join(dir, 'main.git'))
    const worktreeGitDir = makeGitDir(join(dir, 'main.git', 'worktrees', 'wt'))
    writeFileSync(join(worktreeGitDir, 'commondir'), '../..\n')
    const pointer = makePointer('wt-checkout', worktreeGitDir)

    expect(gitFileDenies(pointer, false).denyPaths).toEqual([
      pointer,
      ...gitDirDenyPaths(worktreeGitDir, false),
      ...gitDirDenyPaths(main, false),
    ])
  })

  it('leaves a pointer that names an ordinary directory alone', () => {
    // `gitdir: ..` from app/tools would otherwise deny app/config and
    // app/hooks, which are an ordinary tree and not a git directory.
    mkdirSync(join(dir, 'app', 'config'), { recursive: true })
    const pointer = makePointer(join('app', 'tools'), '..')

    expect(gitFileDenies(pointer, false).denyPaths).toEqual([pointer])
  })

  it('blocks the git directory a dangling pointer names from being filled in', () => {
    const pointer = makePointer('checkout', '../not-created-yet')

    expect(gitFileDenies(pointer, false).denyPaths).toEqual([
      pointer,
      ...gitDirDenyPaths(join(dir, 'not-created-yet'), false),
    ])
  })

  it('follows a pointer padded with the newline bytes git strips', () => {
    const gitDir = makeGitDir(join(dir, 'gitdir'))
    const pointer = writePointer(
      'checkout',
      `gitdir: ${gitDir}${'\n'.repeat(9000)}`,
    )

    // git strips them from the end of the whole file, so this is a pointer
    // it follows; reading less of the file than git does would leave the
    // target's hooks and config out of the deny list.
    expect(gitFileDenies(pointer, false).denyPaths).toEqual([
      pointer,
      ...gitDirDenyPaths(gitDir, false),
    ])
  })

  it('counts trailing spaces as part of the path, as git does', () => {
    const gitDir = makeGitDir(join(dir, 'gitdir'))
    const padded = `${gitDir}${' '.repeat(200)}`
    const pointer = writePointer('checkout', `gitdir: ${padded}\n`)

    // Nothing is trimmed but the newline, so the pointer names a directory
    // that does not exist — denied against being created, not confused for
    // the real git directory next to it.
    expect(gitFileDenies(pointer, false).denyPaths).toEqual([
      pointer,
      ...gitDirDenyPaths(padded, false),
    ])
  })

  it('follows a pointer to a path no file can occupy nowhere', () => {
    // Past the filesystem's name limit: git's own stat of it fails, and a
    // sandboxed command cannot create a git directory there either, so
    // there is nothing below the pointer to deny.
    const gitDir = makeGitDir(join(dir, 'gitdir'))
    const pointer = writePointer(
      'checkout',
      `gitdir: ${gitDir}${' '.repeat(9000)}\n`,
    )

    expect(gitFileDenies(pointer, false).denyPaths).toEqual([pointer])
  })

  it('follows a pointer of the largest size git accepts, and no larger', () => {
    const gitDir = makeGitDir(join(dir, 'gitdir'))
    const maxSize = 1024 * 1024
    const head = `gitdir: ${gitDir}`

    const atBound = writePointer(
      'checkout',
      head + '\n'.repeat(maxSize - head.length),
    )
    expect(statSync(atBound).size).toBe(maxSize)
    expect(gitFileDenies(atBound, false).denyPaths).toEqual([
      atBound,
      ...gitDirDenyPaths(gitDir, false),
    ])

    // One byte more is a .git file git refuses outright, so it leads nowhere.
    const pastBound = writePointer(
      'past-bound',
      head + '\n'.repeat(maxSize + 1 - head.length),
    )
    expect(statSync(pastBound).size).toBe(maxSize + 1)
    expect(gitFileDenies(pastBound, false).denyPaths).toEqual([pastBound])
  })

  it('takes a path that spans lines whole, as git does', () => {
    // Only the newline bytes at the END of the file are stripped, so one in
    // the middle is part of the directory name.
    const gitDir = makeGitDir(join(dir, 'two\nlines'))
    const pointer = writePointer('checkout', `gitdir: ${gitDir}\n`)

    expect(gitFileDenies(pointer, false).denyPaths).toEqual([
      pointer,
      ...gitDirDenyPaths(gitDir, false),
    ])
  })

  it('stops the path at the first NUL byte, as a C string does', () => {
    const gitDir = makeGitDir(join(dir, 'gitdir'))
    const pointer = writePointer(
      'checkout',
      `gitdir: ${gitDir}\0/../elsewhere\n`,
    )

    expect(gitFileDenies(pointer, false).denyPaths).toEqual([
      pointer,
      ...gitDirDenyPaths(gitDir, false),
    ])
  })

  it('strips a CRLF line ending', () => {
    const gitDir = makeGitDir(join(dir, 'gitdir'))
    const pointer = writePointer('checkout', `gitdir: ${gitDir}\r\n`)

    expect(gitFileDenies(pointer, false).denyPaths).toEqual([
      pointer,
      ...gitDirDenyPaths(gitDir, false),
    ])
  })

  it('refuses to sandbox at all on a path that is not valid UTF-8', () => {
    // Decoded, those bytes name a different directory than git opens, so
    // there is no deny list to be had — and sandboxing without one would
    // leave the hooks git runs writable.
    const gitDir = makeGitDir(join(dir, 'gitdir'))
    const pointer = writePointer(
      'checkout',
      Buffer.concat([
        Buffer.from(`gitdir: ${gitDir}`),
        Buffer.from([0xff]),
        Buffer.from('\n'),
      ]),
    )

    expect(() => gitFileDenies(pointer, false).denyPaths).toThrow(
      GitMetadataError,
    )
  })

  it("follows a commondir padded past the pointer's own bound", () => {
    const main = makeGitDir(join(dir, 'main.git'))
    const worktreeGitDir = makeGitDir(join(dir, 'main.git', 'worktrees', 'wt'))
    writeFileSync(
      join(worktreeGitDir, 'commondir'),
      `../..${'\n'.repeat(9000)}`,
    )
    const pointer = makePointer('wt-checkout', worktreeGitDir)

    expect(gitFileDenies(pointer, false).denyPaths).toEqual([
      pointer,
      ...gitDirDenyPaths(worktreeGitDir, false),
      ...gitDirDenyPaths(main, false),
    ])
  })

  it('does not trim a commondir, which git reads byte for byte', () => {
    const main = makeGitDir(join(dir, 'main.git'))
    const worktreeGitDir = makeGitDir(join(dir, 'main.git', 'worktrees', 'wt'))
    // A leading space makes this a relative path beginning with a space,
    // which is where git looks too — not the main git directory.
    writeFileSync(join(worktreeGitDir, 'commondir'), ` ${main}\n`)
    const pointer = makePointer('wt-checkout', worktreeGitDir)

    const denyPaths = gitFileDenies(pointer, false).denyPaths
    expect(denyPaths).toEqual([
      pointer,
      ...gitDirDenyPaths(worktreeGitDir, false),
      ...gitDirDenyPaths(join(worktreeGitDir, ` ${main}`), false),
    ])
    expect(denyPaths).not.toContain(join(main, 'hooks'))
  })

  it('denies where a .. after a symlink lands, the lexical path and the link between', () => {
    // checkout/hop is real/side, so the kernel reads hop/../evil as
    // real/evil while folding it on paper gives checkout/evil. git opens
    // the first; denying only the second leaves its hooks writable. The
    // link itself is a third thing: retargeting it moves where git lands
    // without touching the pointer file or either directory.
    const physical = makeGitDir(join(dir, 'real', 'evil'))
    mkdirSync(join(dir, 'real', 'side'), { recursive: true })
    const pointer = writePointer('checkout', 'gitdir: hop/../evil\n')
    const hop = join(dir, 'checkout', 'hop')
    symlinkSync(join(dir, 'real', 'side'), hop)

    const denies = gitFileDenies(pointer, false)

    expect(denies.denyPaths).toEqual([
      pointer,
      hop,
      ...gitDirDenyPaths(join(dir, 'checkout', 'evil'), false),
      ...gitDirDenyPaths(physical, false),
    ])
    expect(denies.chainHops).toEqual([
      {
        kind: 'pointer',
        chain: 'resolved',
        source: pointer,
        link: hop,
        holder: join(dir, 'checkout'),
      },
    ])
    expect(gitFileDenies(pointer, false).denyPaths).toEqual(denies.denyPaths)
  })

  it('denies both when both are git directories', () => {
    const lexical = makeGitDir(join(dir, 'checkout', 'evil'))
    const physical = makeGitDir(join(dir, 'real', 'evil'))
    mkdirSync(join(dir, 'real', 'side'), { recursive: true })
    const pointer = writePointer('checkout', 'gitdir: hop/../evil\n')
    symlinkSync(join(dir, 'real', 'side'), join(dir, 'checkout', 'hop'))

    expect(gitFileDenies(pointer, false).denyPaths).toEqual([
      pointer,
      join(dir, 'checkout', 'hop'),
      ...gitDirDenyPaths(lexical, false),
      ...gitDirDenyPaths(physical, false),
    ])
  })

  it('walks a chain of symlinks as the kernel does', () => {
    // first is second, second is an absolute path to real/side/deeper. Both
    // links are on the way to what git opens, and each is held.
    const physical = makeGitDir(join(dir, 'real', 'evil'))
    mkdirSync(join(dir, 'real', 'side', 'deeper'), { recursive: true })
    const pointer = writePointer('checkout', 'gitdir: first/../../evil\n')
    const first = join(dir, 'checkout', 'first')
    const second = join(dir, 'checkout', 'second')
    symlinkSync('second', first)
    symlinkSync(join(dir, 'real', 'side', 'deeper'), second)

    const denies = gitFileDenies(pointer, false)

    expect(denies.denyPaths).toEqual([
      pointer,
      first,
      second,
      ...gitDirDenyPaths(join(dir, 'evil'), false),
      ...gitDirDenyPaths(physical, false),
    ])
    // In the order the walk met them, each named where the kernel reached it.
    expect(denies.chainHops.map(hop => hop.link)).toEqual([first, second])
    expect(denies.chainHops.map(hop => hop.holder)).toEqual([
      join(dir, 'checkout'),
      join(dir, 'checkout'),
    ])
  })

  it('takes the rest of a path as written past what is not there', () => {
    // The kernel cannot traverse a missing directory, so nothing after it
    // redirects the path: gone/x is denied against being created, and so
    // is the lexical checkout/x. The link it did read is held all the same.
    const pointer = writePointer('checkout', 'gitdir: hop/../x\n')
    const hop = join(dir, 'checkout', 'hop')
    symlinkSync('gone/deeper', hop)

    const denies = gitFileDenies(pointer, false)

    expect(denies.denyPaths).toEqual([
      pointer,
      hop,
      ...gitDirDenyPaths(join(dir, 'checkout', 'x'), false),
      ...gitDirDenyPaths(join(dir, 'checkout', 'gone', 'x'), false),
    ])
    expect(denies.chainHops).toEqual([
      {
        kind: 'pointer',
        chain: 'resolved',
        source: pointer,
        link: hop,
        holder: join(dir, 'checkout'),
      },
    ])
  })

  it('denies what it can reach when symlinks loop', () => {
    const pointer = writePointer('checkout', 'gitdir: loopA/../evil\n')
    symlinkSync(join(dir, 'checkout', 'loopB'), join(dir, 'checkout', 'loopA'))
    symlinkSync(join(dir, 'checkout', 'loopA'), join(dir, 'checkout', 'loopB'))

    // A value the kernel cannot walk to an end names no git directory: git
    // opens nothing through it, and the lexical fold is not a fallback git
    // takes. The links it walked are the whole of what a command can move,
    // and the checkout - which a fail-closed deny of the deepest directory
    // still reachable would take whole, over a file a sandboxed command may
    // create - stays writable.
    const denies = gitFileDenies(pointer, false)

    expect(denies.denyPaths).toEqual([
      pointer,
      join(dir, 'checkout', 'loopA'),
      join(dir, 'checkout', 'loopB'),
    ])
    expect(denies.chainHops).toEqual([
      {
        kind: 'pointer',
        chain: 'unresolvable',
        source: pointer,
        link: join(dir, 'checkout', 'loopA'),
        holder: join(dir, 'checkout'),
      },
      {
        kind: 'pointer',
        chain: 'unresolvable',
        source: pointer,
        link: join(dir, 'checkout', 'loopB'),
        holder: join(dir, 'checkout'),
      },
    ])
  })

  it('never widens a looping pointer value to a write root', () => {
    // The shape a sandboxed command can plant in one write: a .git file
    // whose value runs into a loop in the checkout itself. Nothing here
    // names the checkout or any directory above it, so the commands after
    // it still write the project; the pointer file and the loop's links
    // are what they cannot touch.
    const pointer = writePointer('checkout', 'gitdir: loop/gd\n')
    symlinkSync('loop2', join(dir, 'checkout', 'loop'))
    symlinkSync('loop', join(dir, 'checkout', 'loop2'))

    const denies = gitFileDenies(pointer, false)

    expect(denies.denyPaths).toEqual([
      pointer,
      join(dir, 'checkout', 'loop'),
      join(dir, 'checkout', 'loop2'),
    ])
    expect(denies.denyPaths).not.toContain(join(dir, 'checkout'))
    expect(denies.denyPaths).not.toContain(dir)
    expect(denies.linkedEntryDirs).toEqual([])
  })

  it('resolves a commondir the same way', () => {
    const worktreeGitDir = makeGitDir(join(dir, 'wt.git'))
    const physical = makeGitDir(join(dir, 'real', 'common'))
    const hop = join(worktreeGitDir, 'hop')
    mkdirSync(join(dir, 'real', 'side'), { recursive: true })
    symlinkSync(join(dir, 'real', 'side'), hop)
    writeFileSync(join(worktreeGitDir, 'commondir'), 'hop/../common\n')
    const pointer = makePointer('wt-checkout', worktreeGitDir)

    const denies = gitFileDenies(pointer, false)

    expect(denies.denyPaths).toEqual([
      pointer,
      ...gitDirDenyPaths(worktreeGitDir, false),
      hop,
      ...gitDirDenyPaths(join(worktreeGitDir, 'common'), false),
      ...gitDirDenyPaths(physical, false),
    ])
    // The file that named the path is the commondir, not the pointer: it is
    // what a reader has to look at to see where the chain starts.
    expect(denies.chainHops).toEqual([
      {
        kind: 'pointer',
        chain: 'resolved',
        source: join(worktreeGitDir, 'commondir'),
        link: hop,
        holder: worktreeGitDir,
      },
    ])
  })

  it('resolves a .. against the directory the pointer file is really in', () => {
    // The checkout is reached through a symlink, so `..` pops the
    // directory the kernel is in and not the one the path was spelled
    // from — nested/target, not dir/target.
    const physical = makeGitDir(join(dir, 'nested', 'target'))
    mkdirSync(join(dir, 'nested', 'checkout'), { recursive: true })
    symlinkSync(join(dir, 'nested', 'checkout'), join(dir, 'link'))
    const pointer = join(dir, 'link', '.git')
    writeFileSync(pointer, 'gitdir: ../target\n')

    const denies = gitFileDenies(pointer, false)

    expect(denies.denyPaths).toEqual([
      pointer,
      ...gitDirDenyPaths(join(dir, 'target'), false),
      ...gitDirDenyPaths(physical, false),
    ])
    // The link ABOVE the pointer file is where this checkout lives, not a
    // hop of the chain its value walks: the walk starts where the kernel
    // already is, so nothing here is held for it.
    expect(denies.chainHops).toEqual([])
  })

  it('holds a symlinked directory component of a value with no .. in it', () => {
    // `gitdir: linkdir/gd` reaches the git directory through `linkdir`,
    // and git opens what the link leads to. Nothing else in the deny list
    // names the link, so without this a command retargets it and every
    // later git run in this checkout reads a git directory of its choosing.
    makeGitDir(join(dir, 'realdir', 'gd'))
    const pointer = writePointer('checkout', 'gitdir: linkdir/gd\n')
    const hop = join(dir, 'checkout', 'linkdir')
    symlinkSync(join(dir, 'realdir'), hop)

    const denies = gitFileDenies(pointer, false)

    expect(denies.denyPaths).toEqual([
      pointer,
      hop,
      ...gitDirDenyPaths(join(hop, 'gd'), false),
    ])
    expect(denies.chainHops).toEqual([
      {
        kind: 'pointer',
        chain: 'resolved',
        source: pointer,
        link: hop,
        holder: join(dir, 'checkout'),
      },
    ])
  })

  it('holds a link of a value that leads nowhere yet', () => {
    // `mid` is there and what it names is not: the deny goes where the path
    // lands, so a command cannot fill that git directory in, and the link is
    // held so it cannot be aimed at one that already exists either.
    const pointer = writePointer('checkout', 'gitdir: mid/gitdir\n')
    const hop = join(dir, 'checkout', 'mid')
    symlinkSync('gone', hop)

    const denies = gitFileDenies(pointer, false)

    expect(denies.denyPaths).toEqual([
      pointer,
      hop,
      ...gitDirDenyPaths(join(hop, 'gitdir'), false),
    ])
    expect(denies.chainHops).toEqual([
      {
        kind: 'pointer',
        chain: 'resolved',
        source: pointer,
        link: hop,
        holder: join(dir, 'checkout'),
      },
    ])
  })

  it.if(process.getuid?.() !== 0)(
    'holds the link it read where what lies past it cannot be',
    () => {
      // The chain runs into a directory this process cannot search, so the
      // git directory is failed closed on the deepest ancestor it can reach
      // and the link it DID read is held as any other is.
      const locked = join(dir, 'checkout', 'locked')
      mkdirSync(join(locked, 'inner'), { recursive: true })
      const pointer = writePointer('checkout', 'gitdir: mid/gitdir\n')
      const hop = join(dir, 'checkout', 'mid')
      symlinkSync(join(locked, 'inner'), hop)
      chmodSync(locked, 0o000)
      try {
        const denies = gitFileDenies(pointer, false)

        expect(denies.denyPaths).toEqual([pointer, hop, join(dir, 'checkout')])
        expect(denies.chainHops).toEqual([
          {
            kind: 'pointer',
            chain: 'resolved',
            source: pointer,
            link: hop,
            holder: join(dir, 'checkout'),
          },
        ])
      } finally {
        chmodSync(locked, 0o755)
      }
    },
  )

  it('refuses to sandbox at all on a commondir past the size it reads', () => {
    // git reads commondir whole and with no bound of its own, so one this
    // large still names the git directory whose hooks a commit here runs.
    const worktreeGitDir = makeGitDir(join(dir, 'wt.git'))
    writeFileSync(
      join(worktreeGitDir, 'commondir'),
      '../main.git'.padEnd(1024 * 1024 + 1, '\n'),
    )
    const pointer = makePointer('wt-checkout', worktreeGitDir)

    expect(() => gitFileDenies(pointer, false).denyPaths).toThrow(
      GitMetadataError,
    )
  })

  /**
   * A whole-directory deny is what a backend falls back on for a tree it
   * cannot enumerate or a link it has no other handle on, and every producer
   * of one reads paths a sandboxed command can write. One that lands on the
   * working directory or a write root takes the project read-only for every
   * command after the one that arranged it, and nothing inside the sandbox
   * can undo it: a denial of service planted by the code the sandbox
   * contains. None is emitted, whichever producer asked.
   */
  describe.if(isLinux)('a deny that would take the work tree whole', () => {
    /** A directory git accepts and whose `hooks` is a link, which is what
     *  makes whatever holds it a git directory denied WHOLE. */
    function makeLinkedGitDir(gitDir: string): string {
      mkdirSync(gitDir, { recursive: true })
      writeFileSync(join(gitDir, 'HEAD'), 'ref: refs/heads/main')
      symlinkSync('nowhere', join(gitDir, 'hooks'))
      return gitDir
    }

    /** `linuxGetCwdMandatoryDenyPaths` from `checkout`. */
    function denyPathsIn(checkout: string, allowWritePaths: string[]) {
      process.chdir(checkout)
      return linuxGetCwdMandatoryDenyPaths(false, allowWritePaths)
    }

    it('never denies the working directory a pointer of its own names', () => {
      // One write plants it: `.git` naming the checkout, whose `hooks` is a
      // link. The checkout is then a git directory with a symlinked entry,
      // which is denied whole - and that is the project.
      const checkout = makeLinkedGitDir(join(dir, 'repo'))
      writeFileSync(join(checkout, '.git'), 'gitdir: .\n')

      const denyPaths = denyPathsIn(checkout, [checkout])

      expect(denyPaths).not.toContain(checkout)
      // What the deny was holding keeps its own two ends.
      expect(denyPaths).toContain(join(checkout, 'hooks'))
    })

    it('never denies an ancestor of the working directory', () => {
      const parent = makeLinkedGitDir(join(dir, 'outer'))
      const checkout = join(parent, 'repo')
      mkdirSync(checkout, { recursive: true })
      writeFileSync(join(checkout, '.git'), 'gitdir: ..\n')

      const denyPaths = denyPathsIn(checkout, [checkout])

      expect(denyPaths).not.toContain(parent)
    })

    it('never denies a second write root', () => {
      const checkout = join(dir, 'repo')
      mkdirSync(checkout, { recursive: true })
      const other = makeLinkedGitDir(join(dir, 'other'))
      writeFileSync(join(checkout, '.git'), `gitdir: ${other}\n`)

      const denyPaths = denyPathsIn(checkout, [checkout, other])

      expect(denyPaths).not.toContain(other)
    })

    it('never denies a directory that holds a write root', () => {
      const checkout = join(dir, 'repo')
      mkdirSync(checkout, { recursive: true })
      const container = makeLinkedGitDir(join(dir, 'container'))
      const secondRoot = join(container, 'inner')
      mkdirSync(secondRoot, { recursive: true })
      writeFileSync(join(checkout, '.git'), `gitdir: ${container}\n`)

      const denyPaths = denyPathsIn(checkout, [checkout, secondRoot])

      expect(denyPaths).not.toContain(container)
    })

    it('still denies an ordinary directory whole', () => {
      // The guard is about the work tree and nothing else: a git directory
      // beside it keeps the deny that holds its symlinked entry.
      const checkout = join(dir, 'repo')
      mkdirSync(checkout, { recursive: true })
      const gitDir = makeLinkedGitDir(join(checkout, 'gitdir-real'))
      writeFileSync(join(checkout, '.git'), 'gitdir: gitdir-real\n')

      const denyPaths = denyPathsIn(checkout, [checkout])

      expect(denyPaths).toContain(gitDir)
    })

    it('never denies the working directory a modules entry is linked to', () => {
      // The same end state through the `.git/modules` walk, and with no
      // pointer file: the entry is followed, the checkout has an entry named
      // `hooks` so the walk takes it for a git directory, and its `hooks` is
      // a link - so the entry's own git directory, which resolves to the
      // checkout, is denied whole.
      const checkout = join(dir, 'repo')
      const gitDir = join(checkout, '.git')
      mkdirSync(join(gitDir, 'modules'), { recursive: true })
      writeFileSync(join(gitDir, 'HEAD'), 'ref: refs/heads/main')
      symlinkSync('nowhere', join(checkout, 'hooks'))
      symlinkSync('../..', join(gitDir, 'modules', 'x'))

      const denyPaths = denyPathsIn(checkout, [checkout])

      // By where each lands, not by how it is spelled: a bind resolves its
      // destination, so `.git/modules/x` IS the checkout here.
      expect(
        denyPaths.map(denyPath => {
          try {
            return realpathSync(denyPath)
          } catch {
            return denyPath
          }
        }),
      ).not.toContain(checkout)
    })
  })

  it.if(isLinux)(
    'hands the monitor plain deny paths for a repository it cannot read',
    () => {
      // The violation monitor starts once for the session, so one
      // repository whose metadata cannot be resolved must not take the whole
      // start-up with it. Every wrap in it is still refused.
      const worktreeGitDir = makeGitDir(join(dir, 'wt.git'))
      writeFileSync(
        join(worktreeGitDir, 'commondir'),
        '../main.git'.padEnd(1024 * 1024 + 1, '\n'),
      )
      const pointer = makePointer('wt-checkout', worktreeGitDir)
      const checkout = join(dir, 'wt-checkout')
      process.chdir(checkout)
      expect(() => linuxGetCwdMandatoryDenyPaths(false)).toThrow(
        GitMetadataError,
      )

      const monitored = linuxGetMonitorCwdDenyPaths(false)

      expect(monitored).toContain(pointer)
      expect(monitored).toContain(join(checkout, '.bashrc'))
      // A pointer file is itself the deny; the hooks and config of a git
      // directory that is not there are not denies the wrapper makes.
      expect(monitored).not.toContain(join(pointer, 'hooks'))
    },
  )

  it.if(isLinux)('gives the monitor no git denies without a .git', () => {
    // A mount at an absent .git would block `git init`, so the wrapper makes
    // none there and the monitor must not judge writes against four it will
    // never see refused.
    const checkout = join(dir, 'no-repo')
    mkdirSync(checkout, { recursive: true })
    process.chdir(checkout)
    const monitored = linuxGetMonitorCwdDenyPaths(false)

    expect(monitored).toContain(join(checkout, '.bashrc'))
    expect(monitored).not.toContain(join(checkout, '.git', 'hooks'))
    expect(monitored).not.toContain(join(checkout, '.git', 'config'))
  })

  it.if(process.getuid?.() !== 0)(
    'refuses to sandbox at all on a commondir it cannot read',
    () => {
      // Returning the denies gathered so far would leave the main
      // repository's hooks — the ones this worktree's commits run — writable
      // for the next command, which is what made this worth planting.
      const main = makeGitDir(join(dir, 'main.git'))
      const worktreeGitDir = makeGitDir(join(main, 'worktrees', 'wt'))
      const commondir = join(worktreeGitDir, 'commondir')
      writeFileSync(commondir, '../..\n')
      chmodSync(commondir, 0o000)
      const pointer = makePointer('wt-checkout', worktreeGitDir)
      try {
        expect(() => gitFileDenies(pointer, false).denyPaths).toThrow(
          GitMetadataError,
        )
      } finally {
        chmodSync(commondir, 0o644)
      }
    },
  )

  it.if(process.getuid?.() !== 0)(
    'denies a git directory it cannot read whole, rather than refusing',
    () => {
      // Refusing every command in the checkout would be a brick one chmod
      // plants; the directory is denied whole instead, and nothing under it
      // stays writable. The repository that keeps it is as writable as it was,
      // and its `commondir` cannot be read to name it (0o000, 0o444), or was not
      // since the directory could not be listed (0o311, through which git still
      // opens it): where the directory is names it.
      const main = makeGitDir(join(dir, 'main.git'))
      const worktreeGitDir = makeGitDir(join(main, 'worktrees', 'wt'))
      writeFileSync(join(worktreeGitDir, 'commondir'), '../..\n')
      const pointer = makePointer('wt-checkout', worktreeGitDir)
      try {
        for (const mode of [0o000, 0o311, 0o444]) {
          chmodSync(worktreeGitDir, mode)
          expect(gitFileDenies(pointer, false)).toMatchObject({
            denyPaths: [
              pointer,
              worktreeGitDir,
              ...gitDirDenyPaths(main, false),
            ],
            gitDirs: [main],
          })
        }
      } finally {
        chmodSync(worktreeGitDir, 0o755)
      }
      // Nowhere else does git keep what belongs to the directory two up.
      const elsewhere = makeGitDir(join(main, 'kept', 'wt'))
      const other = makePointer('other-checkout', elsewhere)
      chmodSync(elsewhere, 0o000)
      try {
        expect(gitFileDenies(other, false).denyPaths).toEqual([
          other,
          elsewhere,
        ])
      } finally {
        chmodSync(elsewhere, 0o755)
      }
    },
  )

  it.if(isLinux)(
    'carries an unresolvable pointer to the wrap as a typed refusal',
    async () => {
      // A sandboxed command can write one of these, and the command that
      // would delete it is refused too, so the caller has to be able to tell
      // this case from the others and the message has to name the file.
      const gitDir = makeGitDir(join(dir, 'gitdir'))
      const pointer = writePointer(
        'checkout',
        Buffer.concat([
          Buffer.from(`gitdir: ${gitDir}`),
          Buffer.from([0xff]),
          Buffer.from('\n'),
        ]),
      )
      process.chdir(join(dir, 'checkout'))
      const error = await wrapCommandWithSandboxLinux({
        command: 'echo hi',
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig: { allowOnly: ['.'], denyWithinAllow: [] },
      }).catch((e: unknown) => e)

      expect(error).toBeInstanceOf(LinuxSandboxProfileError)
      expect((error as LinuxSandboxProfileError).code).toBe(
        'deny_git_metadata_unreadable',
      )
      expect((error as Error).message).toContain(pointer)
    },
  )

  it('names itself, and carries a code, wherever it surfaces', () => {
    // macOS has no profile-error type of its own, so this IS the refusal the
    // caller branches on there; it is exported from the package root.
    const error = new GitMetadataError('x')

    expect(error.name).toBe('GitMetadataError')
    expect(error.code).toBe('git_metadata_unreadable')
  })

  it('does not block on a FIFO left where a git directory keeps its commondir', () => {
    const gitDir = makeGitDir(join(dir, 'gitdir'))
    expect(spawnSync('mkfifo', [join(gitDir, 'commondir')]).status).toBe(0)
    const pointer = makePointer('checkout', '../gitdir')

    expect(gitFileDenies(pointer, false).denyPaths).toEqual([
      pointer,
      ...gitDirDenyPaths(gitDir, false),
    ])
  })

  it('does not block on a FIFO left where a pointer file goes', () => {
    mkdirSync(join(dir, 'checkout'), { recursive: true })
    const pointer = join(dir, 'checkout', '.git')
    expect(spawnSync('mkfifo', [pointer]).status).toBe(0)

    expect(gitFileDenies(pointer, false).denyPaths).toEqual([pointer])
  })

  it('recognises a submodule git directory without a HEAD', () => {
    const gitDir = join(dir, 'modules', 'lib')
    mkdirSync(join(gitDir, 'hooks'), { recursive: true })

    expect(submoduleGitDirs(join(dir, 'modules'))).toEqual({
      gitDirs: [gitDir],
      unreadableDirs: [],
      linkedEntryDirs: [],
      chainHops: [],
    })
  })

  it('walks a submodule name that spans several segments, and nested ones', () => {
    const outer = makeGitDir(join(dir, 'modules', 'vendor', 'lib'))
    const inner = makeGitDir(join(outer, 'modules', 'dep'))

    const scan = submoduleGitDirs(join(dir, 'modules'))
    expect(scan.gitDirs.sort()).toEqual([outer, inner].sort())
  })

  it('follows a symlinked entry under modules', () => {
    const gitDir = makeGitDir(join(dir, 'elsewhere'))
    mkdirSync(join(dir, 'modules'), { recursive: true })
    symlinkSync(gitDir, join(dir, 'modules', 'lib'))

    expect(submoduleGitDirs(join(dir, 'modules')).gitDirs).toEqual([
      join(dir, 'modules', 'lib'),
    ])
  })

  it.if(process.getuid?.() !== 0)(
    'denies a directory under modules it could not list',
    () => {
      const locked = join(dir, 'modules', 'locked')
      makeGitDir(join(locked, 'deep'))
      chmodSync(locked, 0o000)
      try {
        const scan = submoduleGitDirs(join(dir, 'modules'))
        expect(scan.gitDirs).toEqual([])
        expect(scan.unreadableDirs).toEqual([locked])
      } finally {
        chmodSync(locked, 0o755)
      }
    },
  )

  /**
   * A submodule name is a path and submodules nest, so how deep a real tree
   * can go is a question about the repository and not about this walk: what
   * bounds the walk is the time it is given, and what stops it looping is
   * where each directory really is.
   */
  it('walks a chain hundreds of directories deep, and denies every level', () => {
    // Submodules each nested inside the one above, two directories of
    // `<name>/modules` per level: deep enough to overflow a recursive walk's
    // own stack on some runtimes. How many levels fit is what the platform's
    // longest path leaves room for once the temporary directory has had its
    // share - macOS stops at 1024 bytes, and a path past it cannot be opened
    // at all, while Windows stops at 260 and is left out here.
    const budget = getPlatform() === 'macos' ? 950 : 4000
    const levels = Math.floor((budget - dir.length) / '/x/modules'.length)
    expect(levels).toBeGreaterThan(50)

    const gitDirs: string[] = []
    let at = join(dir, 'modules')
    for (let level = 0; level < levels; level++) {
      at = join(at, 'x')
      makeGitDir(at)
      gitDirs.push(at)
      at = join(at, 'modules')
    }

    const scan = submoduleGitDirs(join(dir, 'modules'))
    expect(scan.unreadableDirs).toEqual([])
    expect(scan.gitDirs).toEqual([...gitDirs].sort())
    const denies = gitDirTreeDenyPaths(gitDirTreeDenies(dir, false))
    for (const gitDir of gitDirs) {
      expect(denies).toContain(join(gitDir, 'hooks'))
      expect(denies).toContain(join(gitDir, 'config'))
    }
  })

  it('ends at a symlink pointing back into the tree', () => {
    // modules/a/back -> modules, which the walk would follow for ever if it
    // did not record where each directory really is.
    mkdirSync(join(dir, 'modules', 'a'), { recursive: true })
    symlinkSync(join(dir, 'modules'), join(dir, 'modules', 'a', 'back'))
    const gitDir = makeGitDir(join(dir, 'modules', 'a', 'lib'))

    expect(submoduleGitDirs(join(dir, 'modules'))).toMatchObject({
      gitDirs: [gitDir],
      unreadableDirs: [],
      linkedEntryDirs: [join(dir, 'modules', 'a')],
    })
  })

  it('denies nothing for a symlink loop, which leads nowhere', () => {
    // A loop cannot be stat'ed at all (ELOOP) and reaches no directory, so
    // there is nothing behind it to deny - and denying what HOLDS it would
    // hand every command a way to take every submodule beside it read-only.
    mkdirSync(join(dir, 'modules'), { recursive: true })
    symlinkSync(join(dir, 'modules', 'b'), join(dir, 'modules', 'a'))
    symlinkSync(join(dir, 'modules', 'a'), join(dir, 'modules', 'b'))
    const gitDir = makeGitDir(join(dir, 'modules', 'lib'))

    expect(submoduleGitDirs(join(dir, 'modules'))).toEqual({
      gitDirs: [gitDir],
      unreadableDirs: [],
      linkedEntryDirs: [],
      chainHops: [],
    })
  })

  it('costs one command nothing to plant thousands of loops', () => {
    mkdirSync(join(dir, 'modules'), { recursive: true })
    for (let i = 0; i < 2800; i++) {
      symlinkSync(`s${i}`, join(dir, 'modules', `s${i}`))
    }
    const gitDir = makeGitDir(join(dir, 'modules', 'lib'))

    expect(submoduleGitDirs(join(dir, 'modules'))).toEqual({
      gitDirs: [gitDir],
      unreadableDirs: [],
      linkedEntryDirs: [],
      chainHops: [],
    })
  }, 30000)

  it.if(process.getuid?.() !== 0)(
    'denies where a symlinked entry leads, and the directory holding the link',
    () => {
      // Two links into a directory this process cannot search. What is BEHIND
      // them is unknown, so that deny is the deepest directory that can be
      // reached towards them - the locked directory itself - and not the
      // `modules` that holds the links, which would take every submodule
      // beside them over one unreadable target. One entry, not three: the
      // same path is reached by the listing of `locked` and by each of the
      // two links. The links THEMSELVES are another matter: neither deny
      // lands on a link's own path, and `modules` is writable, so the
      // directory holding them is denied for their sake.
      const locked = join(dir, 'modules', 'locked')
      const sibling = makeGitDir(join(dir, 'modules', 'lib'))
      mkdirSync(locked, { recursive: true })
      symlinkSync(join(locked, 'one'), join(dir, 'modules', 'a'))
      symlinkSync(join(locked, 'two'), join(dir, 'modules', 'b'))
      chmodSync(locked, 0o000)
      try {
        expect(submoduleGitDirs(join(dir, 'modules'))).toMatchObject({
          gitDirs: [sibling],
          unreadableDirs: [locked],
          linkedEntryDirs: [join(dir, 'modules')],
        })
      } finally {
        chmodSync(locked, 0o755)
      }
    },
  )

  it('refuses rather than hand back a walk that ran out of its time', () => {
    makeGitDir(join(dir, 'modules', 'a', 'lib'))
    makeGitDir(join(dir, 'modules', 'b', 'lib'))

    // A deadline already past: the first directory the walk takes off its
    // stack is where it stops.
    expect(() =>
      submoduleGitDirs(join(dir, 'modules'), Date.now() - 1),
    ).toThrow(SubmoduleWalkBudgetError)
    const error = (() => {
      try {
        submoduleGitDirs(join(dir, 'modules'), Date.now() - 1)
        return undefined
      } catch (err) {
        return err as SubmoduleWalkBudgetError
      }
    })()
    expect(error?.code).toBe('submodule_walk_budget_exhausted')
    expect(error?.message).toContain(join(dir, 'modules'))
  })

  it('looks at the clock inside one wide directory, not only between directories', () => {
    // A `.git/modules` a command filled is one directory, and none of these
    // entries is one to walk into.
    const modules = join(dir, 'modules')
    mkdirSync(modules, { recursive: true })
    for (let i = 0; i < 300; i++) writeFileSync(join(modules, `f${i}`), '')
    const deadline = Date.now() + 60000
    let looks = 0
    const now = spyOn(Date, 'now').mockImplementation(() =>
      looks++ === 0 ? deadline - 1 : deadline + 1,
    )
    try {
      expect(() => submoduleGitDirs(modules, deadline)).toThrow(
        SubmoduleWalkBudgetError,
      )
    } finally {
      now.mockRestore()
    }
  })

  it.if(isLinux)(
    'refuses the wrap where the modules walk runs out of its time',
    async () => {
      const checkout = join(dir, 'repo')
      const gitDir = makeGitDir(join(checkout, '.git'))
      // Enough submodules that the walk cannot get through them inside the
      // millisecond below, whatever the machine: it is the walk that must
      // run out here, not the scan, which runs after it.
      for (let i = 0; i < 400; i++) {
        makeGitDir(join(gitDir, 'modules', `s${String(i).padStart(4, '0')}`))
      }

      process.chdir(checkout)
      const error = await wrapCommandWithSandboxLinux({
        command: 'echo hi',
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig: { allowOnly: [checkout], denyWithinAllow: [] },
        // The walk shares the scan's budget, so one millisecond of it is
        // all the walk gets.
        ripgrepConfig: { command: 'rg', timeoutMs: 1 },
      }).catch((e: unknown) => e)

      expect(error).toBeInstanceOf(LinuxSandboxProfileError)
      expect((error as LinuxSandboxProfileError).code).toBe('deny_scan_failed')
      expect((error as Error).message).toContain(join(gitDir, 'modules'))
    },
    30000,
  )

  it.if(isLinux)(
    'gives a walk made after the scan a budget of its own',
    async () => {
      // The scan has a timeout of its own and may use all of it. What a slow one
      // left would refuse a repository whose submodules a walk gets through in
      // microseconds. Here the clock jumps past the first budget as the scan
      // ends.
      const checkout = join(dir, 'repo')
      makeGitDir(join(checkout, '.git'))
      const nestedGitDir = makeGitDir(join(checkout, 'nested', '.git'))
      const nestedSub = makeGitDir(join(nestedGitDir, 'modules', 'lib'))
      // A stand-in for ripgrep that reports the nested repository and exits.
      const scan = join(dir, 'scan.sh')
      const scanned = join(dir, 'scanned')
      writeFileSync(
        scan,
        `#!/bin/sh\nprintf '%s\\0' ${JSON.stringify(join(nestedGitDir, 'config'))}\n: > ${JSON.stringify(scanned)}\n`,
        { mode: 0o755 },
      )
      const realNow = Date.now
      const now = spyOn(Date, 'now').mockImplementation(
        () => realNow() + (existsSync(scanned) ? 60000 : 0),
      )

      const originalCwd = process.cwd()
      process.chdir(checkout)
      try {
        const command = await wrapCommandWithSandboxLinux({
          command: 'true',
          needsNetworkRestriction: false,
          readConfig: undefined,
          writeConfig: { allowOnly: [checkout], denyWithinAllow: [] },
          ripgrepConfig: { command: scan, timeoutMs: 30000 },
        })
        expect(command).toContain(join(nestedSub, 'hooks'))
      } finally {
        now.mockRestore()
        cleanupBwrapMountPoints({ force: true })
        process.chdir(originalCwd)
      }
    },
    60000,
  )

  it.if(isLinux)(
    'keeps a deeply nested git directory writable except for its hooks and config',
    async () => {
      const checkout = join(dir, 'repo')
      const gitDir = makeGitDir(join(checkout, '.git'))
      const deep = join(
        gitDir,
        'modules',
        ...Array.from({ length: 12 }, () => 'x'),
      )
      makeGitDir(deep)
      mkdirSync(join(deep, 'objects'), { recursive: true })
      // And one more level under it, so that what the deny of a git
      // directory's own submodules covers is pinned as well.
      const deeper = makeGitDir(join(deep, 'modules', 'lib'))

      process.chdir(checkout)
      const wrap = (command: string): Promise<string> =>
        wrapCommandWithSandboxLinux({
          command,
          needsNetworkRestriction: false,
          readConfig: undefined,
          writeConfig: { allowOnly: [checkout], denyWithinAllow: [] },
        })

      // No deny covering the git directory whole, which would take its
      // objects, refs and index with it. An ancestor pin spells that same
      // self-bind, so where it sits is what tells the two apart: pins are
      // spliced in before the write root's own bind, which makes the tree
      // writable again, and a deny bind is emitted after it.
      const command = await wrap('true')
      const writeRootBind = indexOfMount(command, '--bind', checkout, checkout)
      expect(writeRootBind).toBeGreaterThan(-1)
      expect(lastIndexOfMount(command, '--ro-bind', deep, deep)).toBeLessThan(
        writeRootBind,
      )
      expect(command).toContain(`--ro-bind ${join(deep, 'hooks')} `)
      // Its own submodule is denied by path too, and neither it nor the
      // `modules` directory holding it is denied whole: a bind there would
      // take that submodule's objects, refs and index with it. Only the
      // ancestor pins spell those, and they sit before the write root's
      // own bind.
      expect(command).toContain(`--ro-bind ${join(deeper, 'hooks')} `)
      expect(
        lastIndexOfMount(command, '--ro-bind', deeper, deeper),
      ).toBeLessThan(writeRootBind)
      const modules = join(deep, 'modules')
      expect(
        lastIndexOfMount(command, '--ro-bind', modules, modules),
      ).toBeLessThan(writeRootBind)

      // Where bwrap can run, prove it: what git needs writable in that
      // submodule still is, and what makes a write into code is not.
      if (bwrapCanNamespace()) {
        const result = spawnSync(
          await wrap(
            `sh -c 'echo o > ${join(deep, 'objects', 'x')} && ` +
              `! echo h > ${join(deep, 'hooks', 'x')} && ` +
              `! echo c > ${join(deep, 'config')} && ` +
              `! echo h > ${join(deeper, 'hooks', 'x')} && ` +
              `echo SRT_DEEP_OK'`,
          ),
          { shell: true, encoding: 'utf8', timeout: 30000, cwd: checkout },
        )
        expect(result.stdout).toContain('SRT_DEEP_OK')
      }
    },
    60000,
  )

  it('denies a deeply nested git directory by literal path on macOS', () => {
    const checkout = join(dir, 'repo')
    const gitDir = makeGitDir(join(checkout, '.git'))
    const deep = join(
      gitDir,
      'modules',
      ...Array.from({ length: 12 }, () => 'x'),
    )
    makeGitDir(deep)
    const deeper = makeGitDir(join(deep, 'modules', 'lib'))

    process.chdir(checkout)
    // Profile generation is pure string building, so this runs anywhere.
    const profile = wrapCommandWithSandboxMacOS({
      command: 'true',
      needsNetworkRestriction: false,
      readConfig: undefined,
      writeConfig: { allowOnly: [checkout], denyWithinAllow: [] },
    })
    expect(profile).toContain(`(subpath "${join(deep, 'hooks')}")`)
    expect(profile).toContain(`(subpath "${join(deeper, 'hooks')}")`)
    // No deny covering either git directory whole, which would take its
    // objects, refs and index with it. Seatbelt has no argument cap, so
    // nothing is ever collapsed there.
    expect(profile).not.toContain(`(subpath "${deep}")`)
    expect(profile).not.toContain(`(subpath "${deeper}")`)
  })
})

/**
 * bubblewrap parses at most 9000 words and takes three for each mount, so a
 * repository with enough submodules asks for more than the profile can carry.
 * The ceiling is not this library's to lift; refusing every command in such a
 * repository is the wrong answer to it, so the denies are degraded instead -
 * precise while the profile fits, then a whole git directory at a time, then
 * the `modules` directory whole. What decides is the profile the wrap built,
 * so the wraps below are Linux's; Seatbelt has no cap of the kind.
 */
describe.if(isSupportedPlatform)(
  'Submodule denies past the argument cap',
  () => {
    /** Everything the live arms need: a sandbox that starts, and a git. */
    const LIVE = isLinux && bwrapCanNamespace() && Bun.which('git') !== null
    let dir: string
    const savedCwd = process.cwd()

    beforeEach(() => {
      dir = realpathSync(mkdtempSync(join(tmpdir(), 'srt-submodule-budget-')))
    })

    afterEach(() => {
      process.chdir(savedCwd)
      cleanupBwrapMountPoints({ force: true })
      rmSync(dir, { recursive: true, force: true })
    })

    function makeGitDir(gitDir: string): string {
      mkdirSync(join(gitDir, 'hooks'), { recursive: true })
      writeFileSync(join(gitDir, 'HEAD'), 'ref: refs/heads/main')
      writeFileSync(join(gitDir, 'config'), '[core]\n')
      return gitDir
    }

    /** A repository whose .git/modules holds `count` submodule git
     *  directories, named so that sorted order is the order they were made
     *  in. `checkouts` gives each one the `.git` pointer file a checked-out
     *  submodule has, which costs a bind and a pin no collapse can save. */
    function makeSuperproject(
      count: number,
      options: { checkouts?: boolean } = {},
    ): { checkout: string; subs: string[] } {
      const checkout = join(dir, 'repo')
      const gitDir = makeGitDir(join(checkout, '.git'))
      const subs: string[] = []
      for (let i = 0; i < count; i++) {
        const name = `s${String(i).padStart(5, '0')}`
        subs.push(makeGitDir(join(gitDir, 'modules', name)))
        if (options.checkouts !== true) continue
        mkdirSync(join(checkout, name), { recursive: true })
        writeFileSync(
          join(checkout, name, '.git'),
          `gitdir: ../.git/modules/${name}\n`,
        )
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

    describe('what a degraded level denies', () => {
      /** A plan as the wrap builds one: the deny paths in the order they were
       *  found, and the submodule git directories they can be folded into. */
      function planFor(
        modulesDir: string,
        gitDirNames: string[],
        extra: string[] = [],
        escaping: (gitDir: string) => string[] = () => [],
      ): SubmoduleDenyPlan {
        const gitDirs = gitDirNames.map(name => {
          const gitDir = join(modulesDir, name)
          const escapingDenyPaths = escaping(gitDir)
          return {
            gitDir,
            denyPaths: [
              join(gitDir, 'hooks'),
              join(gitDir, 'commondir'),
              join(gitDir, 'config'),
              join(gitDir, 'config.worktree'),
              ...escapingDenyPaths,
            ],
            escapingDenyPaths,
            linkedEntryDirs: [],
            chainHops: [],
          }
        })
        return {
          denyPaths: [...extra, ...gitDirs.flatMap(sub => sub.denyPaths)],
          repositories: [{ modulesDir, gitDirs, wholeDirDenies: [] }],
          chainHops: [],
        }
      }

      it('leaves the list exactly as it was where nothing is degraded', () => {
        const plan = planFor(join(dir, '.git', 'modules'), ['a', 'b'])
        expect(collapsedDenyPaths(plan, NO_COLLAPSE)).toEqual(plan.denyPaths)
      })

      it('folds a degraded git directory in wherever its deny paths came from', () => {
        // A checked-out submodule's `.git` pointer names the same git
        // directory the walk of `.git/modules` reached, so the pointer's own
        // deny sits in the list beside denies that are the git directory's:
        // collapsing it has to take those and leave the pointer, which names
        // a file and has nothing to collapse into.
        const modules = join(dir, '.git', 'modules')
        const pointer = join(dir, 'b', '.git')
        const plan = planFor(modules, ['a', 'b'], [pointer])

        const denies = collapsedDenyPaths(plan, {
          wholeGitDirs: 1,
          wholeModulesDirs: 0,
        })

        expect(denies).toContain(pointer)
        expect(denies).toContain(join(modules, 'a', 'hooks'))
        // The last in sorted order is the one degraded, so two wraps of one
        // tree degrade the same submodules.
        expect(denies).toContain(join(modules, 'b'))
        expect(denies).not.toContain(join(modules, 'b', 'hooks'))
        expect(denies).not.toContain(join(modules, 'b', 'config'))
      })

      it('keeps what a symlinked entry leads to when the git directory goes whole', () => {
        // The one read-only bind that replaces a submodule's precise denies
        // covers what is under the git directory. A symlinked entry leads
        // out of it, and dropping that deny leaves one write through the
        // link landing on hooks the host's git runs.
        const modules = join(dir, '.git', 'modules')
        const planted = join(dir, 'planted')
        const plan = planFor(modules, ['a', 'b'], [], gitDir =>
          gitDir === join(modules, 'b') ? [planted] : [],
        )

        const denies = collapsedDenyPaths(plan, {
          wholeGitDirs: 1,
          wholeModulesDirs: 0,
        })

        expect(denies).toContain(join(modules, 'b'))
        expect(denies).toContain(planted)
        expect(denies).not.toContain(join(modules, 'b', 'hooks'))
      })

      it('keeps it under a modules directory denied whole as well', () => {
        const modules = join(dir, '.git', 'modules')
        const planted = join(dir, 'planted')
        const plan = planFor(modules, ['a', 'b'], [], gitDir =>
          gitDir === join(modules, 'b') ? [planted] : [],
        )

        const denies = collapsedDenyPaths(plan, {
          wholeGitDirs: 2,
          wholeModulesDirs: 1,
        })

        expect(denies).toContain(modules)
        expect(denies).toContain(planted)
        expect(denies).not.toContain(join(modules, 'b', 'hooks'))
        expect(denies).not.toContain(join(modules, 'a', 'hooks'))
      })

      it('counts a kept deny as a mount the step does not give back', () => {
        // Three denies each, of which one leads out of the git directory and
        // is kept: a step gives back two mounts, not three, so one that has
        // to find three takes both git directories.
        const modules = join(dir, '.git', 'modules')
        const gitDirs = ['a', 'b'].map(name => {
          const gitDir = join(modules, name)
          const planted = join(dir, 'planted', name)
          return {
            gitDir,
            denyPaths: [join(gitDir, 'hooks'), planted, join(gitDir, 'config')],
            escapingDenyPaths: [planted],
            linkedEntryDirs: [],
            chainHops: [],
          }
        })
        const plan: SubmoduleDenyPlan = {
          denyPaths: gitDirs.flatMap(submodule => submodule.denyPaths),
          repositories: [{ modulesDir: modules, gitDirs, wholeDirDenies: [] }],
          chainHops: [],
        }

        expect(collapseFurther(plan, NO_COLLAPSE, 2)).toEqual({
          wholeGitDirs: 1,
          wholeModulesDirs: 0,
        })
        expect(collapseFurther(plan, NO_COLLAPSE, 3)).toEqual({
          wholeGitDirs: 2,
          wholeModulesDirs: 0,
        })
      })

      it('adds the bind of a git directory that is a deny path already once', () => {
        // A git directory holding a symlinked entry is denied whole by the
        // producer, so it is in the list before any degrade reaches it.
        const modules = join(dir, '.git', 'modules')
        const gitDir = join(modules, 'b')
        const plan = planFor(modules, ['a', 'b'])
        const withWhole: SubmoduleDenyPlan = {
          chainHops: [],
          denyPaths: [gitDir, ...plan.denyPaths],
          repositories: plan.repositories.map(repository => ({
            ...repository,
            gitDirs: repository.gitDirs.map(submodule =>
              submodule.gitDir === gitDir
                ? { ...submodule, denyPaths: [gitDir, ...submodule.denyPaths] }
                : submodule,
            ),
          })),
        }

        const denies = collapsedDenyPaths(withWhole, {
          wholeGitDirs: 1,
          wholeModulesDirs: 0,
        })

        expect(denies.filter(deny => deny === gitDir)).toEqual([gitDir])
      })

      it('runs out, which is what too_many_arguments is left for', () => {
        const plan = planFor(join(dir, '.git', 'modules'), ['a', 'b'])
        const everything = { wholeGitDirs: 2, wholeModulesDirs: 1 }
        expect(collapseFurther(plan, NO_COLLAPSE, 1)).toEqual({
          wholeGitDirs: 1,
          wholeModulesDirs: 0,
        })
        expect(collapseFurther(plan, everything, 1)).toBeUndefined()
      })

      it('names the repositories it degraded, and counts every level', () => {
        const modules = join(dir, '.git', 'modules')
        const plan = planFor(modules, ['a', 'b'])

        expect(describeCollapse(plan, NO_COLLAPSE)).toBe('')
        const told = describeCollapse(plan, {
          wholeGitDirs: 2,
          wholeModulesDirs: 1,
        })
        expect(told).toContain('2 of the 2 submodule git directories')
        expect(told).toContain(modules)
      })

      it('says nothing about submodules a whole-directory deny already took', () => {
        // An entry of this `.git/modules` is a symlink, so the directory is
        // denied whole before anything is degraded and every submodule under
        // it is read-only already. A degrade of them takes nothing away, and
        // saying that it did names a cost the profile never paid.
        const modules = join(dir, '.git', 'modules')
        mkdirSync(join(modules, 'a'), { recursive: true })
        mkdirSync(join(modules, 'b'), { recursive: true })
        const plan = planFor(modules, ['a', 'b'])
        const held: SubmoduleDenyPlan = {
          ...plan,
          repositories: plan.repositories.map(repository => ({
            ...repository,
            wholeDirDenies: [modules],
          })),
        }

        expect(
          describeCollapse(held, { wholeGitDirs: 2, wholeModulesDirs: 1 }),
        ).toBe('')
      })

      it('has nothing to degrade, and nothing to deny, for a repository with no submodules', () => {
        // An absent `.git/modules` is not a directory to deny: a /dev/null
        // mount point planted at one stops `git submodule add` working in
        // that repository, and is left behind by a killed wrap.
        const gitDir = makeGitDir(join(dir, 'repo', '.git'))
        const denies = gitDirTreeDenies(gitDir, false)

        expect(degradableGitDirs(denies)).toEqual([])
        expect(gitDirTreeDenyPaths(denies)).not.toContain(
          join(gitDir, 'modules'),
        )
      })

      it.if(!isWindows)(
        'keeps a repository denied whole for its own symlinked entry out of the plan',
        () => {
          // The git directory is denied whole because its `hooks` is a link.
          // That is not a submodule deny, and it is no reason to give a
          // repository with no submodules a `.git/modules` to degrade.
          const gitDir = makeGitDir(join(dir, 'repo', '.git'))
          const shared = join(dir, 'repo', 'shared-hooks')
          mkdirSync(shared, { recursive: true })
          rmSync(join(gitDir, 'hooks'), { recursive: true })
          symlinkSync(shared, join(gitDir, 'hooks'))
          const denies = gitDirTreeDenies(gitDir, false)

          expect(denies.linkedEntryDirs).toEqual([gitDir])
          expect(degradableGitDirs(denies)).toEqual([])
        },
      )

      it.if(!isWindows)(
        'keeps the deny of an entry whose real path is outside a modules directory denied whole',
        () => {
          // A read-only bind of `modules` covers what is really under it. An
          // entry the walk reached through a symlink can be anywhere, and
          // leaving it to that bind would leave its hooks writable.
          const gitDir = makeGitDir(join(dir, 'repo', '.git'))
          const inside = makeGitDir(join(gitDir, 'modules', 'a'))
          const outside = makeGitDir(join(dir, 'elsewhere'))
          const link = join(gitDir, 'modules', 'b')
          symlinkSync(outside, link)

          const tree = gitDirTreeDenies(gitDir, false)
          const plan: SubmoduleDenyPlan = {
            denyPaths: gitDirTreeDenyPaths(tree),
            repositories: degradableGitDirs(tree),
            chainHops: [],
          }
          expect(plan.repositories).toHaveLength(1)

          const denies = collapsedDenyPaths(plan, {
            wholeGitDirs: 2,
            wholeModulesDirs: 1,
          })

          expect(denies).toContain(join(gitDir, 'modules'))
          expect(denies).toContain(link)
          expect(denies).not.toContain(inside)
          expect(denies).not.toContain(join(inside, 'hooks'))
        },
      )
    })

    it.if(isLinux)(
      'wraps a command in a repository with 2000 submodules',
      async () => {
        const { checkout, subs } = makeSuperproject(2000)
        process.chdir(checkout)
        const wrap = (): Promise<string> =>
          wrapCommandWithSandboxLinux({
            command: 'true',
            needsNetworkRestriction: false,
            readConfig: undefined,
            writeConfig: { allowOnly: [checkout], denyWithinAllow: [] },
          })

        const command = await wrap()
        expect(command).toContain('bwrap')

        // The mounts are past what one command line carries at this size, so
        // they are in the argument file bwrap reads - which is where its own
        // cap on parsed words is spent. Under it, with room to spare for the
        // handful still on the line.
        const words = mountWords(command)
        expect(words.length).toBeLessThan(9000)

        // The first submodules in sorted order keep their precise denies; the
        // rest are denied whole, one read-only bind of the git directory each.
        // (A git directory bound whole is spelled like its own ancestor pin, so
        // what tells the two apart is whether the hooks have a deny of their
        // own.)
        const denied = new Set(words)
        const precise = subs.filter(sub => denied.has(join(sub, 'hooks')))
        expect(precise.length).toBeGreaterThan(0)
        expect(precise.length).toBeLessThan(subs.length)
        expect(precise).toEqual(subs.slice(0, precise.length))
        for (const sub of subs.slice(precise.length))
          expect(denied.has(sub)).toBe(true)
        const last = subs[subs.length - 1] as string
        expect(denied.has(last)).toBe(true)
        expect(denied.has(join(last, 'hooks'))).toBe(false)

        // Two wraps of one tree agree, so a second command in it is sandboxed
        // exactly as the first was.
        const again = await wrap()
        const profileAgain = /\/proc\/\d+\/fd\/\d+/.exec(again)?.[0]
        expect(readFileSync(profileAgain as string, 'utf8')).toBe(
          readFileSync(
            /\/proc\/\d+\/fd\/\d+/.exec(command)?.[0] as string,
            'utf8',
          ),
        )

        // The violation monitor works the working directory's own denies out
        // for itself, once for the session, and degrades none of them: it
        // reports the path inside a submodule git directory that a wrap has
        // by then denied whole, which is a write refused either way.
        const monitorDenies = new Set(linuxGetMonitorCwdDenyPaths(false))
        expect(monitorDenies.has(join(subs[0] as string, 'hooks'))).toBe(true)
        expect(monitorDenies.has(join(last, 'hooks'))).toBe(true)
        expect(monitorDenies.has(last)).toBe(false)

        // Seatbelt has no such cap: every submodule keeps its precise denies
        // there, whatever this repository costs bubblewrap. Read off the
        // entries rather than the profile text, which folds same-shaped
        // literals into alternation regexes at this size.
        const macEntries = new Set(
          macGetMandatoryDenyEntries(false).map(entry => entry.path),
        )
        for (const sub of [subs[0] as string, last]) {
          expect(macEntries.has(join(sub, 'hooks'))).toBe(true)
          expect(macEntries.has(sub)).toBe(false)
        }
      },
      300000,
    )

    it.if(isLinux)(
      'degrades a repository of checked-out submodules, and refuses where even that is not enough',
      async () => {
        // A checked-out submodule costs what a bare one does and two mounts
        // more that no collapse saves: the `.git` pointer file's own bind and
        // the pin of the directory holding it. So this shape, and not a bare
        // `.git/modules`, is the one that can still reach the cap.
        const wrap = (checkout: string): Promise<string> =>
          wrapCommandWithSandboxLinux({
            command: 'true',
            needsNetworkRestriction: false,
            readConfig: undefined,
            writeConfig: { allowOnly: [checkout], denyWithinAllow: [] },
          })

        for (const count of [300, 700]) {
          const { checkout, subs } = makeSuperproject(count, {
            checkouts: true,
          })
          process.chdir(checkout)
          const words = mountWords(await wrap(checkout))
          expect(words.length).toBeLessThan(9000)
          // Every pointer file is denied whatever was degraded under it.
          const denied = new Set(words)
          for (const sub of subs) {
            expect(denied.has(join(checkout, basename(sub), '.git'))).toBe(true)
          }
          process.chdir(savedCwd)
          rmSync(checkout, { recursive: true, force: true })
          cleanupBwrapMountPoints({ force: true })
        }

        const { checkout } = makeSuperproject(1600, { checkouts: true })
        process.chdir(checkout)
        const error = await wrap(checkout).catch((e: unknown) => e)
        expect(error).toBeInstanceOf(LinuxSandboxProfileError)
        expect((error as LinuxSandboxProfileError).code).toBe(
          'too_many_arguments',
        )
      },
      600000,
    )

    it.if(isLinux)(
      'degrades multi-segment and nested submodule names like any other',
      async () => {
        // A submodule's name is its path, so one can sit several segments
        // down and hold submodules of its own. Each extra segment is another
        // directory to pin, which the profile pays for and the model of what
        // a submodule costs never saw.
        const checkout = join(dir, 'repo')
        const gitDir = makeGitDir(join(checkout, '.git'))
        const subs: string[] = []
        for (let i = 0; i < 700; i++) {
          const name = `s${String(i).padStart(5, '0')}`
          subs.push(makeGitDir(join(gitDir, 'modules', `vendor${i}`, name)))
        }
        let nested = subs[0] as string
        for (let level = 0; level < 20; level++) {
          nested = makeGitDir(join(nested, 'modules', 'inner'))
          subs.push(nested)
        }
        process.chdir(checkout)

        const words = mountWords(
          await wrapCommandWithSandboxLinux({
            command: 'true',
            needsNetworkRestriction: false,
            readConfig: undefined,
            writeConfig: { allowOnly: [checkout], denyWithinAllow: [] },
          }),
        )
        expect(words.length).toBeLessThan(9000)
        const denied = new Set(words)
        const precise = subs.filter(sub => denied.has(join(sub, 'hooks')))
        expect(precise.length).toBeGreaterThan(0)
        expect(precise.length).toBeLessThan(subs.length)
      },
      300000,
    )

    it.if(LIVE)(
      'holds a collapsed submodule read-only while the rest of the tree works',
      async () => {
        const git = Bun.which('git') as string
        // Seven hundred real submodule git directories, made here rather than
        // cloned: past what precise denies fit in, so the tail is collapsed.
        const checkout = join(dir, 'repo')
        mkdirSync(checkout, { recursive: true })
        const run = (...args: string[]): void => {
          const r = spawnSync(git, args, { encoding: 'utf8', timeout: 60000 })
          expect(r.status).toBe(0)
        }
        run('-c', 'init.defaultBranch=main', 'init', '-q', checkout)
        writeFileSync(join(checkout, 'index.js'), 'console.log(1)\n')
        run('-C', checkout, 'add', 'index.js')
        run(
          '-C',
          checkout,
          '-c',
          'user.name=t',
          '-c',
          'user.email=t@t',
          '-c',
          'commit.gpgsign=false',
          '-c',
          'core.hooksPath=/dev/null',
          'commit',
          '-q',
          '-m',
          'one',
        )
        const subs: string[] = []
        for (let i = 0; i < 700; i++) {
          subs.push(
            makeGitDir(
              join(
                checkout,
                '.git',
                'modules',
                `s${String(i).padStart(5, '0')}`,
              ),
            ),
          )
        }
        process.chdir(checkout)

        const collapsed = subs[subs.length - 1] as string
        const precise = subs[0] as string
        const command = await wrapCommandWithSandboxLinux({
          command:
            'echo BOOTED; ' +
            `! echo x > ${join(collapsed, 'hooks', 'pre-commit')} || echo COLLAPSED_HOOK_WRITABLE; ` +
            `! echo x > ${join(precise, 'hooks', 'pre-commit')} || echo PRECISE_HOOK_WRITABLE; ` +
            // A rename of the collapsed git directory itself is what the
            // ancestor pins are there to stop: the deny would otherwise move
            // with it and a fresh directory take its place.
            `! mv ${collapsed} ${collapsed}.moved || echo COLLAPSED_RENAMABLE; ` +
            `echo ok > ${join(checkout, 'index.js')} || echo PROJECT_FILE_READONLY; ` +
            `${git} status --porcelain > /dev/null || echo GIT_STATUS_FAILED; ` +
            'echo DONE',
          needsNetworkRestriction: false,
          allowAllUnixSockets: true,
          readConfig: undefined,
          writeConfig: { allowOnly: [checkout], denyWithinAllow: [] },
        })
        const result = spawnSync(command, {
          shell: true,
          encoding: 'utf8',
          timeout: 120000,
          cwd: checkout,
        })

        expect(result.stdout).toContain('BOOTED')
        expect(result.stdout).toContain('DONE')
        expect(result.stdout).not.toContain('COLLAPSED_HOOK_WRITABLE')
        expect(result.stdout).not.toContain('PRECISE_HOOK_WRITABLE')
        expect(result.stdout).not.toContain('COLLAPSED_RENAMABLE')
        expect(result.stdout).not.toContain('PROJECT_FILE_READONLY')
        expect(result.stdout).not.toContain('GIT_STATUS_FAILED')

        // And the host's git still works in the superproject afterwards.
        cleanupBwrapMountPoints({ force: true })
        const status = spawnSync(git, ['status', '--porcelain'], {
          cwd: checkout,
          encoding: 'utf8',
          timeout: 60000,
        })
        expect(status.status).toBe(0)
      },
      300000,
    )

    it.if(LIVE)(
      'keeps the hooks of a symlinked submodule entry where `modules` is denied whole',
      async () => {
        // Three thousand submodules is past what one read-only bind each
        // fits in, which is the level that puts the whole tree behind a
        // single bind over `.git/modules`.
        const checkout = join(dir, 'repo')
        const gitDir = makeGitDir(join(checkout, '.git'))
        for (let i = 0; i < 3000; i++) {
          makeGitDir(join(gitDir, 'modules', `s${String(i).padStart(5, '0')}`))
        }
        const outside = makeGitDir(join(dir, 'elsewhere'))
        symlinkSync(outside, join(gitDir, 'modules', 'zz-linked'))
        process.chdir(checkout)

        const command = await wrapCommandWithSandboxLinux({
          command:
            'echo BOOTED; ' +
            `! echo x > ${join(outside, 'hooks', 'pre-commit')} || echo LINKED_HOOK_WRITABLE; ` +
            `! echo x > ${join(gitDir, 'modules', 's00000', 'hooks', 'x')} || echo MODULES_WRITABLE; ` +
            'echo DONE',
          needsNetworkRestriction: false,
          allowAllUnixSockets: true,
          readConfig: undefined,
          writeConfig: { allowOnly: [checkout, outside], denyWithinAllow: [] },
        })
        // The whole tree behind one bind. The linked entry is not covered by
        // it, since a deny lands where the link really points, and what it
        // points at is a write root: binding that whole would take a
        // directory the command was given away from it, so it keeps the
        // denies of its own entries instead.
        const words = mountWords(command)
        const mounted = (source: string, dest: string): boolean =>
          words.some(
            (word, at) =>
              word === '--ro-bind' &&
              words[at + 1] === source &&
              words[at + 2] === dest,
          )
        expect(mounted(join(gitDir, 'modules'), join(gitDir, 'modules'))).toBe(
          true,
        )
        expect(mounted(outside, outside)).toBe(false)
        expect(mounted(join(outside, 'hooks'), join(outside, 'hooks'))).toBe(
          true,
        )
        expect(mounted(join(outside, 'config'), join(outside, 'config'))).toBe(
          true,
        )

        const result = spawnSync(command, {
          shell: true,
          encoding: 'utf8',
          timeout: 120000,
          cwd: checkout,
        })
        expect(result.stdout).toContain('BOOTED')
        expect(result.stdout).toContain('DONE')
        expect(result.stdout).not.toContain('LINKED_HOOK_WRITABLE')
        expect(result.stdout).not.toContain('MODULES_WRITABLE')
      },
      300000,
    )

    it.if(LIVE)(
      'holds a symlinked hooks and a symlinked modules entry where nothing is degraded',
      async () => {
        // One small repository: every deny is precise. The links are what
        // the precise denies cannot land on, so the git directory holding
        // one, and the `modules` holding the other, are denied whole - and
        // the repository still reads.
        const git = Bun.which('git') as string
        const checkout = join(dir, 'repo')
        mkdirSync(checkout, { recursive: true })
        const run = (...args: string[]): void => {
          const r = spawnSync(git, args, { encoding: 'utf8', timeout: 60000 })
          expect(r.status).toBe(0)
        }
        run('-c', 'init.defaultBranch=main', 'init', '-q', checkout)
        const gitDir = join(checkout, '.git')
        writeFileSync(join(checkout, 'f.txt'), 'one\n')
        const shared = join(checkout, 'shared-hooks')
        mkdirSync(shared, { recursive: true })
        rmSync(join(gitDir, 'hooks'), { recursive: true })
        symlinkSync(shared, join(gitDir, 'hooks'))
        const outside = makeGitDir(join(dir, 'elsewhere'))
        const entry = join(gitDir, 'modules', 'lib')
        mkdirSync(join(gitDir, 'modules'), { recursive: true })
        symlinkSync(outside, entry)
        process.chdir(checkout)

        const command = await wrapCommandWithSandboxLinux({
          command:
            'echo BOOTED; ' +
            `! echo x > ${join(shared, 'post-commit')} || echo THROUGH_LINK_WRITABLE; ` +
            `! rm -f ${join(gitDir, 'hooks')} || echo HOOKS_LINK_UNLINKABLE; ` +
            `! mv ${join(gitDir, 'hooks')} ${join(gitDir, 'hooks.moved')} || echo HOOKS_LINK_RENAMABLE; ` +
            `! rm -f ${entry} || echo MODULES_LINK_UNLINKABLE; ` +
            `! echo x > ${join(outside, 'hooks', 'post-commit')} || echo LINKED_GIT_DIR_WRITABLE; ` +
            `echo ok > ${join(checkout, 'f.txt')} || echo PROJECT_FILE_READONLY; ` +
            `${git} -C ${checkout} status --porcelain > /dev/null || echo GIT_STATUS_FAILED; ` +
            'echo DONE',
          needsNetworkRestriction: false,
          allowAllUnixSockets: true,
          readConfig: undefined,
          writeConfig: { allowOnly: [checkout, outside], denyWithinAllow: [] },
        })
        const result = spawnSync(command, {
          shell: true,
          encoding: 'utf8',
          timeout: 120000,
          cwd: checkout,
        })

        expect(result.stdout).toContain('BOOTED')
        expect(result.stdout).toContain('DONE')
        expect(result.stdout).not.toContain('THROUGH_LINK_WRITABLE')
        expect(result.stdout).not.toContain('HOOKS_LINK_UNLINKABLE')
        expect(result.stdout).not.toContain('HOOKS_LINK_RENAMABLE')
        expect(result.stdout).not.toContain('MODULES_LINK_UNLINKABLE')
        expect(result.stdout).not.toContain('LINKED_GIT_DIR_WRITABLE')
        expect(result.stdout).not.toContain('PROJECT_FILE_READONLY')
        expect(result.stdout).not.toContain('GIT_STATUS_FAILED')
        expect(readFileSync(join(checkout, 'f.txt'), 'utf8')).toBe('ok\n')
      },
      300000,
    )

    /**
     * A chain between a git directory entry and what it leads to is held hop
     * by hop: each hop's own path is a deny path, and on this backend, whose
     * denies resolve, the directory holding each is denied whole as the git
     * directory itself is. Where that directory is the working directory or
     * a write root there is nothing to bind over it, and the wrap says so
     * instead.
     */
    describe('a chain with a hop in the middle', () => {
      /** A repository whose `hooks` reaches `.githooks` through `hop`. */
      function makeChain(holder: string): {
        checkout: string
        gitDir: string
        hop: string
        landing: string
      } {
        const checkout = join(dir, 'repo')
        const gitDir = makeGitDir(join(checkout, '.git'))
        const landing = join(checkout, '.githooks')
        mkdirSync(landing, { recursive: true })
        mkdirSync(holder, { recursive: true })
        const hop = join(holder, 'hop')
        symlinkSync(landing, hop)
        rmSync(join(gitDir, 'hooks'), { recursive: true })
        symlinkSync(hop, join(gitDir, 'hooks'))
        return { checkout, gitDir, hop, landing }
      }

      it.if(isLinux)(
        'binds the directory holding the hop read-only where it is a subdirectory',
        async () => {
          const checkout = join(dir, 'repo')
          const holder = join(checkout, 'links')
          const { gitDir, landing } = makeChain(holder)
          process.chdir(checkout)

          const command = await wrapCommandWithSandboxLinux({
            command: 'true',
            needsNetworkRestriction: false,
            readConfig: undefined,
            writeConfig: { allowOnly: [checkout], denyWithinAllow: [] },
          })

          // A deny bind is emitted after the write root's own bind; an
          // ancestor pin spells the same words before it.
          const writeRootBind = indexOfMount(
            command,
            '--bind',
            checkout,
            checkout,
          )
          expect(writeRootBind).toBeGreaterThan(-1)
          expect(
            lastIndexOfMount(command, '--ro-bind', holder, holder),
          ).toBeGreaterThan(writeRootBind)
          // The two ends keep what they had: the git directory whole, and
          // the landing on its own.
          expect(
            lastIndexOfMount(command, '--ro-bind', gitDir, gitDir),
          ).toBeGreaterThan(writeRootBind)
          expect(
            lastIndexOfMount(command, '--ro-bind', landing, landing),
          ).toBeGreaterThan(writeRootBind)
        },
        60000,
      )

      it.if(isLinux)(
        'holds a symlinked directory component by its holder, not by what it leads to',
        async () => {
          // hooks -> links/shared/hooks with shared -> shared-real. A bind
          // at the hop's own path would land on `shared-real` and take a
          // whole directory nothing asked to deny; the directory holding the
          // link is what holds it.
          const checkout = join(dir, 'repo')
          const gitDir = makeGitDir(join(checkout, '.git'))
          const real = join(checkout, 'shared-real')
          mkdirSync(join(real, 'hooks'), { recursive: true })
          const holder = join(checkout, 'links')
          mkdirSync(holder, { recursive: true })
          const hop = join(holder, 'shared')
          symlinkSync(real, hop)
          rmSync(join(gitDir, 'hooks'), { recursive: true })
          symlinkSync(join(hop, 'hooks'), join(gitDir, 'hooks'))
          process.chdir(checkout)

          const command = await wrapCommandWithSandboxLinux({
            command: 'true',
            needsNetworkRestriction: false,
            readConfig: undefined,
            writeConfig: { allowOnly: [checkout], denyWithinAllow: [] },
          })

          const writeRootBind = indexOfMount(
            command,
            '--bind',
            checkout,
            checkout,
          )
          expect(writeRootBind).toBeGreaterThan(-1)
          expect(
            lastIndexOfMount(command, '--ro-bind', holder, holder),
          ).toBeGreaterThan(writeRootBind)
          // The landing keeps its own deny; the directory above it is only
          // ever the ancestor pin, which is spliced in before that bind.
          expect(
            lastIndexOfMount(
              command,
              '--ro-bind',
              join(real, 'hooks'),
              join(real, 'hooks'),
            ),
          ).toBeGreaterThan(writeRootBind)
          expect(
            lastIndexOfMount(command, '--ro-bind', real, real),
          ).toBeLessThan(writeRootBind)
        },
        60000,
      )

      it.if(isLinux)(
        'warns rather than bind where the directory holding the hop is the working directory',
        async () => {
          const checkout = join(dir, 'repo')
          const { gitDir, hop } = makeChain(checkout)
          process.chdir(checkout)

          const { result: command, warnings } = await withCapturedWarnings(() =>
            wrapCommandWithSandboxLinux({
              command: 'true',
              needsNetworkRestriction: false,
              readConfig: undefined,
              writeConfig: { allowOnly: [checkout], denyWithinAllow: [] },
            }),
          )

          const writeRootBind = indexOfMount(
            command,
            '--bind',
            checkout,
            checkout,
          )
          expect(writeRootBind).toBeGreaterThan(-1)
          // Nothing read-only over the write root after its own bind: that
          // would take the whole tree the sandbox exists to let a command
          // write. Only the pins spell it, and they come before.
          expect(
            lastIndexOfMount(command, '--ro-bind', checkout, checkout),
          ).toBeLessThan(writeRootBind)
          const told = warnings.join('\n')
          expect(told).toContain(join(gitDir, 'hooks'))
          expect(told).toContain(hop)
        },
        60000,
      )

      it.if(LIVE)(
        'refuses every way to move a hop a subdirectory holds',
        async () => {
          const git = Bun.which('git') as string
          const checkout = join(dir, 'repo')
          mkdirSync(checkout, { recursive: true })
          const run = (...args: string[]): void => {
            const r = spawnSync(git, args, { encoding: 'utf8', timeout: 60000 })
            expect(r.status).toBe(0)
          }
          run('-c', 'init.defaultBranch=main', 'init', '-q', checkout)
          const holder = join(checkout, 'links')
          const { gitDir, hop, landing } = makeChain(holder)
          writeFileSync(join(checkout, 'f.txt'), 'one\n')
          const evil = join(checkout, 'evil-hooks')
          mkdirSync(evil, { recursive: true })
          process.chdir(checkout)

          const command = await wrapCommandWithSandboxLinux({
            command:
              'echo BOOTED; ' +
              `! ln -sfn ${evil} ${hop} || echo HOP_RETARGETABLE; ` +
              `! mv ${hop} ${hop}.aside || echo HOP_RENAMABLE; ` +
              `! rm -f ${hop} || echo HOP_UNLINKABLE; ` +
              `! mkdir ${join(holder, 'other')} || echo HOLDER_WRITABLE; ` +
              `! rm -f ${join(gitDir, 'hooks')} || echo ENTRY_UNLINKABLE; ` +
              `! echo x > ${join(landing, 'post-commit')} || echo THROUGH_LINK_WRITABLE; ` +
              `echo ok > ${join(checkout, 'f.txt')} || echo PROJECT_FILE_READONLY; ` +
              `${git} -C ${checkout} status --porcelain > /dev/null || echo GIT_STATUS_FAILED; ` +
              'echo DONE',
            needsNetworkRestriction: false,
            allowAllUnixSockets: true,
            readConfig: undefined,
            writeConfig: { allowOnly: [checkout], denyWithinAllow: [] },
          })
          const result = spawnSync(command, {
            shell: true,
            encoding: 'utf8',
            timeout: 120000,
            cwd: checkout,
          })

          expect(result.stdout).toContain('BOOTED')
          expect(result.stdout).toContain('DONE')
          expect(result.stdout).not.toContain('HOP_RETARGETABLE')
          expect(result.stdout).not.toContain('HOP_RENAMABLE')
          expect(result.stdout).not.toContain('HOP_UNLINKABLE')
          expect(result.stdout).not.toContain('HOLDER_WRITABLE')
          expect(result.stdout).not.toContain('ENTRY_UNLINKABLE')
          expect(result.stdout).not.toContain('THROUGH_LINK_WRITABLE')
          expect(result.stdout).not.toContain('PROJECT_FILE_READONLY')
          expect(result.stdout).not.toContain('GIT_STATUS_FAILED')
          expect(readFileSync(join(checkout, 'f.txt'), 'utf8')).toBe('ok\n')
          // The host still resolves the chain where it did.
          expect(readlinkSync(hop)).toBe(landing)
          expect(existsSync(join(landing, 'post-commit'))).toBe(false)
        },
        300000,
      )

      /**
       * A checkout whose `.git` is a POINTER FILE naming its git directory
       * through `hop`: the same chain from the other producer, since a
       * pointer's value is a path the kernel walks like any other.
       */
      function makePointerChain(holder: string): {
        checkout: string
        pointer: string
        hop: string
        gitDir: string
      } {
        const checkout = join(dir, 'repo')
        const gitDir = makeGitDir(join(checkout, 'gitdir-real'))
        mkdirSync(holder, { recursive: true })
        const hop = join(holder, 'hop')
        symlinkSync(gitDir, hop)
        const pointer = join(checkout, '.git')
        writeFileSync(pointer, `gitdir: ${hop}\n`)
        return { checkout, pointer, hop, gitDir }
      }

      it.if(isLinux)(
        "binds the directory holding a hop of a pointer's value read-only",
        async () => {
          const checkout = join(dir, 'repo')
          const holder = join(checkout, 'links')
          const { pointer, gitDir } = makePointerChain(holder)
          process.chdir(checkout)

          const command = await wrapCommandWithSandboxLinux({
            command: 'true',
            needsNetworkRestriction: false,
            readConfig: undefined,
            writeConfig: { allowOnly: [checkout], denyWithinAllow: [] },
          })

          const writeRootBind = indexOfMount(
            command,
            '--bind',
            checkout,
            checkout,
          )
          expect(writeRootBind).toBeGreaterThan(-1)
          expect(
            lastIndexOfMount(command, '--ro-bind', holder, holder),
          ).toBeGreaterThan(writeRootBind)
          // The two ends keep what they had: the pointer file itself, and the
          // hooks of the git directory its value reaches — spelled where the
          // deny RESOLVES to, which is what a bind can be put on.
          expect(
            lastIndexOfMount(command, '--ro-bind', pointer, pointer),
          ).toBeGreaterThan(writeRootBind)
          expect(
            lastIndexOfMount(
              command,
              '--ro-bind',
              join(gitDir, 'hooks'),
              join(gitDir, 'hooks'),
            ),
          ).toBeGreaterThan(writeRootBind)
        },
        60000,
      )

      it.if(isLinux)(
        "warns where the working directory holds a hop of a pointer's value",
        async () => {
          const checkout = join(dir, 'repo')
          const { pointer, hop } = makePointerChain(checkout)
          process.chdir(checkout)

          const { result: command, warnings } = await withCapturedWarnings(() =>
            wrapCommandWithSandboxLinux({
              command: 'true',
              needsNetworkRestriction: false,
              readConfig: undefined,
              writeConfig: { allowOnly: [checkout], denyWithinAllow: [] },
            }),
          )

          const writeRootBind = indexOfMount(
            command,
            '--bind',
            checkout,
            checkout,
          )
          expect(writeRootBind).toBeGreaterThan(-1)
          expect(
            lastIndexOfMount(command, '--ro-bind', checkout, checkout),
          ).toBeLessThan(writeRootBind)
          const told = warnings.join('\n')
          // Named as what it is: the path a pointer file leads through.
          expect(told).toContain(pointer)
          expect(told).toContain(hop)
        },
        60000,
      )

      it.if(LIVE)(
        "refuses every way to move a hop of a pointer's value a subdirectory holds",
        async () => {
          const git = Bun.which('git') as string
          const checkout = join(dir, 'repo')
          mkdirSync(checkout, { recursive: true })
          const run = (...args: string[]): void => {
            const r = spawnSync(git, args, { encoding: 'utf8', timeout: 60000 })
            expect(r.status).toBe(0)
          }
          run('-c', 'init.defaultBranch=main', 'init', '-q', checkout)
          // The repository git just made, reached through a link: its `.git`
          // becomes the pointer file naming it.
          const gitDir = join(checkout, 'gitdir-real')
          renameSync(join(checkout, '.git'), gitDir)
          const holder = join(checkout, 'links')
          mkdirSync(holder, { recursive: true })
          const hop = join(holder, 'hop')
          symlinkSync(gitDir, hop)
          const pointer = join(checkout, '.git')
          writeFileSync(pointer, `gitdir: ${hop}\n`)
          writeFileSync(join(checkout, 'f.txt'), 'one\n')
          const evil = makeGitDir(join(checkout, 'evil-gitdir'))
          process.chdir(checkout)

          const command = await wrapCommandWithSandboxLinux({
            command:
              'echo BOOTED; ' +
              `! ln -sfn ${evil} ${hop} || echo HOP_RETARGETABLE; ` +
              `! mv ${hop} ${hop}.aside || echo HOP_RENAMABLE; ` +
              `! rm -f ${hop} || echo HOP_UNLINKABLE; ` +
              `! mkdir ${join(holder, 'other')} || echo HOLDER_WRITABLE; ` +
              `! echo x > ${pointer} || echo POINTER_WRITABLE; ` +
              `! echo x > ${join(gitDir, 'hooks', 'post-commit')} || echo HOOKS_WRITABLE; ` +
              `echo ok > ${join(checkout, 'f.txt')} || echo PROJECT_FILE_READONLY; ` +
              `${git} -C ${checkout} status --porcelain > /dev/null || echo GIT_STATUS_FAILED; ` +
              'echo DONE',
            needsNetworkRestriction: false,
            allowAllUnixSockets: true,
            readConfig: undefined,
            writeConfig: { allowOnly: [checkout], denyWithinAllow: [] },
          })
          const result = spawnSync(command, {
            shell: true,
            encoding: 'utf8',
            timeout: 120000,
            cwd: checkout,
          })

          expect(result.stdout).toContain('BOOTED')
          expect(result.stdout).toContain('DONE')
          expect(result.stdout).not.toContain('HOP_RETARGETABLE')
          expect(result.stdout).not.toContain('HOP_RENAMABLE')
          expect(result.stdout).not.toContain('HOP_UNLINKABLE')
          expect(result.stdout).not.toContain('HOLDER_WRITABLE')
          expect(result.stdout).not.toContain('POINTER_WRITABLE')
          expect(result.stdout).not.toContain('HOOKS_WRITABLE')
          expect(result.stdout).not.toContain('PROJECT_FILE_READONLY')
          expect(result.stdout).not.toContain('GIT_STATUS_FAILED')
          expect(readFileSync(join(checkout, 'f.txt'), 'utf8')).toBe('ok\n')
          // The host still resolves the pointer where it did.
          expect(readlinkSync(hop)).toBe(gitDir)
        },
        300000,
      )

      it.if(LIVE)(
        "records that a hop of a pointer's value in the working directory can still be retargeted",
        async () => {
          // The same limit from the other producer, pinned as a fact: no bind
          // holds a link the working directory itself holds, so the wrap warns
          // and the retarget lands. The pointer file and the git directory it
          // named are held all the same.
          const checkout = join(dir, 'repo')
          const { pointer, hop, gitDir } = makePointerChain(checkout)
          const evil = makeGitDir(join(checkout, 'evil-gitdir'))
          process.chdir(checkout)

          const { result: command, warnings } = await withCapturedWarnings(() =>
            wrapCommandWithSandboxLinux({
              command:
                'echo BOOTED; ' +
                `ln -sfn ${evil} ${hop} || echo HOP_HELD; ` +
                `! echo x > ${pointer} || echo POINTER_WRITABLE; ` +
                `! echo x > ${join(gitDir, 'hooks', 'post-commit')} || echo HOOKS_WRITABLE; ` +
                'echo DONE',
              needsNetworkRestriction: false,
              allowAllUnixSockets: true,
              readConfig: undefined,
              writeConfig: { allowOnly: [checkout], denyWithinAllow: [] },
            }),
          )
          const result = spawnSync(command, {
            shell: true,
            encoding: 'utf8',
            timeout: 120000,
            cwd: checkout,
          })

          expect(warnings.join('\n')).toContain(hop)
          expect(result.stdout).toContain('BOOTED')
          expect(result.stdout).toContain('DONE')
          expect(result.stdout).not.toContain('POINTER_WRITABLE')
          expect(result.stdout).not.toContain('HOOKS_WRITABLE')
          // Honestly recorded: the hop moved, so the host's git would now read
          // the git directory the command chose.
          expect(result.stdout).not.toContain('HOP_HELD')
          expect(readlinkSync(hop)).toBe(evil)
        },
        300000,
      )

      it.if(LIVE)(
        'records that a hop the working directory holds can still be retargeted',
        async () => {
          // The limit, pinned as a fact rather than left to be found: there
          // is no bind that holds this link, so the wrap warns and the
          // retarget lands. Both ends of the chain are held all the same.
          const checkout = join(dir, 'repo')
          const { gitDir, hop, landing } = makeChain(checkout)
          const evil = join(checkout, 'evil-hooks')
          mkdirSync(evil, { recursive: true })
          process.chdir(checkout)

          const { result: command, warnings } = await withCapturedWarnings(() =>
            wrapCommandWithSandboxLinux({
              command:
                'echo BOOTED; ' +
                `ln -sfn ${evil} ${hop} || echo HOP_HELD; ` +
                `! rm -f ${join(gitDir, 'hooks')} || echo ENTRY_UNLINKABLE; ` +
                `! echo x > ${join(landing, 'post-commit')} || echo THROUGH_LINK_WRITABLE; ` +
                'echo DONE',
              needsNetworkRestriction: false,
              allowAllUnixSockets: true,
              readConfig: undefined,
              writeConfig: { allowOnly: [checkout], denyWithinAllow: [] },
            }),
          )
          const result = spawnSync(command, {
            shell: true,
            encoding: 'utf8',
            timeout: 120000,
            cwd: checkout,
          })

          expect(warnings.join('\n')).toContain(hop)
          expect(result.stdout).toContain('BOOTED')
          expect(result.stdout).toContain('DONE')
          expect(result.stdout).not.toContain('ENTRY_UNLINKABLE')
          expect(result.stdout).not.toContain('THROUGH_LINK_WRITABLE')
          // Honestly recorded: the hop moved, so the host's git would now
          // resolve `.git/hooks` to the directory the command chose.
          expect(result.stdout).not.toContain('HOP_HELD')
          expect(readlinkSync(hop)).toBe(evil)
        },
        300000,
      )
    })

    /**
     * A chain that reaches NOTHING - a loop, or a name no file can occupy -
     * has no landing to deny, so the links it goes through are the whole of
     * what holds it. Each is a name a command replaces with a directory to
     * make the chain reach one, which is why a hop this backend cannot bind
     * is a refusal here rather than the warning a resolved chain gets.
     */
    describe('a chain that reaches nothing', () => {
      /** A repository whose `hooks` runs into a two-link loop in `holder`. */
      function makeLoop(holder: string): {
        checkout: string
        gitDir: string
        first: string
        second: string
      } {
        const checkout = join(dir, 'repo')
        const gitDir = makeGitDir(join(checkout, '.git'))
        mkdirSync(holder, { recursive: true })
        const first = join(holder, 'a')
        const second = join(holder, 'b')
        symlinkSync('b', first)
        symlinkSync('a', second)
        rmSync(join(gitDir, 'hooks'), { recursive: true })
        symlinkSync(first, join(gitDir, 'hooks'))
        return { checkout, gitDir, first, second }
      }

      it.if(isLinux)(
        'binds the directory holding a loop read-only where it is a subdirectory',
        async () => {
          const checkout = join(dir, 'repo')
          const holder = join(checkout, 'links')
          const { gitDir } = makeLoop(holder)
          process.chdir(checkout)

          const command = await wrapCommandWithSandboxLinux({
            command: 'true',
            needsNetworkRestriction: false,
            readConfig: undefined,
            writeConfig: { allowOnly: [checkout], denyWithinAllow: [] },
          })

          const writeRootBind = indexOfMount(
            command,
            '--bind',
            checkout,
            checkout,
          )
          expect(writeRootBind).toBeGreaterThan(-1)
          expect(
            lastIndexOfMount(command, '--ro-bind', holder, holder),
          ).toBeGreaterThan(writeRootBind)
          // The entry keeps what it had: the git directory denied whole.
          expect(
            lastIndexOfMount(command, '--ro-bind', gitDir, gitDir),
          ).toBeGreaterThan(writeRootBind)
        },
        60000,
      )

      it.if(isLinux)(
        'refuses the command where the working directory holds the loop',
        async () => {
          // There is no bind for the link and no far end to fall back on, so
          // the answer a resolved chain gets - warn, and rely on both ends -
          // holds nothing here. This is what such a repository got before any
          // of these denies existed: the deny path could not be resolved and
          // the wrap failed closed.
          const checkout = join(dir, 'repo')
          const { gitDir, first } = makeLoop(checkout)
          process.chdir(checkout)

          const error = await wrapCommandWithSandboxLinux({
            command: 'true',
            needsNetworkRestriction: false,
            readConfig: undefined,
            writeConfig: { allowOnly: [checkout], denyWithinAllow: [] },
          }).catch((e: unknown) => e)

          expect(error).toBeInstanceOf(LinuxSandboxProfileError)
          expect((error as LinuxSandboxProfileError).code).toBe(
            'deny_unresolvable_git_entry',
          )
          // The entry, the link and the directory holding it: each of the
          // three ways out the message names works on one of them.
          expect((error as Error).message).toContain(join(gitDir, 'hooks'))
          expect((error as Error).message).toContain(first)
          expect((error as Error).message).toContain(checkout)
        },
        60000,
      )

      it.if(isLinux)(
        'never denies the working directory for a pointer value that loops',
        async () => {
          // A `.git` FILE is something a sandboxed command may write, so
          // failing closed on the deepest directory still reachable towards
          // its value would let one command lock every later one out of the
          // project. The pointer file and the loop's links are denied; the
          // checkout is not, and nothing is refused.
          const checkout = join(dir, 'repo')
          mkdirSync(checkout, { recursive: true })
          const first = join(checkout, 'a')
          symlinkSync('b', first)
          symlinkSync('a', join(checkout, 'b'))
          const pointer = join(checkout, '.git')
          writeFileSync(pointer, 'gitdir: a/gd\n')
          process.chdir(checkout)

          const { result: command, warnings } = await withCapturedWarnings(() =>
            wrapCommandWithSandboxLinux({
              command: 'true',
              needsNetworkRestriction: false,
              readConfig: undefined,
              writeConfig: { allowOnly: [checkout], denyWithinAllow: [] },
            }),
          )

          const writeRootBind = indexOfMount(
            command,
            '--bind',
            checkout,
            checkout,
          )
          expect(writeRootBind).toBeGreaterThan(-1)
          expect(
            lastIndexOfMount(command, '--ro-bind', checkout, checkout),
          ).toBeLessThan(writeRootBind)
          expect(
            lastIndexOfMount(command, '--ro-bind', pointer, pointer),
          ).toBeGreaterThan(writeRootBind)
          expect(warnings.join('\n')).toContain(pointer)
        },
        60000,
      )

      it.if(LIVE)(
        'refuses every way to make a loop a subdirectory holds reach a directory',
        async () => {
          const checkout = join(dir, 'repo')
          const holder = join(checkout, 'links')
          const { gitDir, first, second } = makeLoop(holder)
          writeFileSync(join(checkout, 'f.txt'), 'one\n')
          const evil = join(checkout, 'evil-hooks')
          mkdirSync(evil, { recursive: true })
          process.chdir(checkout)

          const command = await wrapCommandWithSandboxLinux({
            command:
              'echo BOOTED; ' +
              `! rm -f ${first} || echo LINK_UNLINKABLE; ` +
              `! mv ${second} ${second}.aside || echo LINK_RENAMABLE; ` +
              `! ln -sfn ${evil} ${first} || echo LINK_RETARGETABLE; ` +
              `! mkdir -p ${join(holder, 'a', 'x')} || echo LINK_REPLACEABLE_BY_DIR; ` +
              `! echo x > ${join(holder, 'a')} || echo LINK_REPLACEABLE_BY_FILE; ` +
              `! rm -f ${join(gitDir, 'hooks')} || echo ENTRY_UNLINKABLE; ` +
              `echo ok > ${join(checkout, 'f.txt')} || echo PROJECT_FILE_READONLY; ` +
              'echo DONE',
            needsNetworkRestriction: false,
            allowAllUnixSockets: true,
            readConfig: undefined,
            writeConfig: { allowOnly: [checkout], denyWithinAllow: [] },
          })
          const result = spawnSync(command, {
            shell: true,
            encoding: 'utf8',
            timeout: 120000,
            cwd: checkout,
          })

          expect(result.stdout).toContain('BOOTED')
          expect(result.stdout).toContain('DONE')
          expect(result.stdout).not.toContain('LINK_UNLINKABLE')
          expect(result.stdout).not.toContain('LINK_RENAMABLE')
          expect(result.stdout).not.toContain('LINK_RETARGETABLE')
          expect(result.stdout).not.toContain('LINK_REPLACEABLE_BY_DIR')
          expect(result.stdout).not.toContain('LINK_REPLACEABLE_BY_FILE')
          expect(result.stdout).not.toContain('ENTRY_UNLINKABLE')
          expect(result.stdout).not.toContain('PROJECT_FILE_READONLY')
          expect(readFileSync(join(checkout, 'f.txt'), 'utf8')).toBe('ok\n')
          // The loop is where it was: `.git/hooks` still reaches nothing.
          expect(readlinkSync(first)).toBe('b')
          expect(readlinkSync(second)).toBe('a')
        },
        300000,
      )

      it.if(LIVE)(
        'leaves the project writable for the command after one that plants a looping pointer',
        async () => {
          // Two wraps, as a session runs them. The first writes a `.git` file
          // whose value runs into a loop in the working directory - an
          // ordinary write inside the write root, and one creating a `.git`
          // is deliberately allowed to make. The second still writes the
          // project: what it cannot touch is the pointer file itself, which
          // is removed from outside the sandbox.
          const checkout = join(dir, 'repo')
          mkdirSync(checkout, { recursive: true })
          writeFileSync(join(checkout, 'f.txt'), 'one\n')
          process.chdir(checkout)
          const pointer = join(checkout, '.git')

          const plant = await wrapCommandWithSandboxLinux({
            command:
              `ln -sfn b ${join(checkout, 'a')} && ` +
              `ln -sfn a ${join(checkout, 'b')} && ` +
              `printf 'gitdir: a/gd\\n' > ${pointer} && echo PLANTED`,
            needsNetworkRestriction: false,
            allowAllUnixSockets: true,
            readConfig: undefined,
            writeConfig: { allowOnly: [checkout], denyWithinAllow: [] },
          })
          const planted = spawnSync(plant, {
            shell: true,
            encoding: 'utf8',
            timeout: 120000,
            cwd: checkout,
          })
          expect(planted.stdout).toContain('PLANTED')
          cleanupBwrapMountPoints({ force: true })

          const { result: after, warnings } = await withCapturedWarnings(() =>
            wrapCommandWithSandboxLinux({
              command:
                'echo BOOTED; ' +
                `echo ok > ${join(checkout, 'f.txt')} || echo PROJECT_FILE_READONLY; ` +
                `mkdir -p ${join(checkout, 'sub')} || echo SUBDIR_UNCREATABLE; ` +
                `! echo x > ${pointer} || echo POINTER_WRITABLE; ` +
                `! rm -f ${pointer} || echo POINTER_REMOVABLE; ` +
                'echo DONE',
              needsNetworkRestriction: false,
              allowAllUnixSockets: true,
              readConfig: undefined,
              writeConfig: { allowOnly: [checkout], denyWithinAllow: [] },
            }),
          )
          const result = spawnSync(after, {
            shell: true,
            encoding: 'utf8',
            timeout: 120000,
            cwd: checkout,
          })

          expect(result.stdout).toContain('BOOTED')
          expect(result.stdout).toContain('DONE')
          // The project is the command's, as it was before the plant.
          expect(result.stdout).not.toContain('PROJECT_FILE_READONLY')
          expect(result.stdout).not.toContain('SUBDIR_UNCREATABLE')
          expect(readFileSync(join(checkout, 'f.txt'), 'utf8')).toBe('ok\n')
          // The pointer file is not: it stays until it is removed from
          // outside the sandbox, and the wrap says which file that is.
          expect(result.stdout).not.toContain('POINTER_WRITABLE')
          expect(result.stdout).not.toContain('POINTER_REMOVABLE')
          expect(warnings.join('\n')).toContain(pointer)
        },
        300000,
      )
    })

    /**
     * Every whole-directory deny is a stand-in read off paths a sandboxed
     * command can write, so each is a way to aim one at the project itself.
     * None of them may: the deny is dropped where what is beneath it is
     * known, and the command refused where it is not.
     */
    describe('a deny aimed at the project', () => {
      const NOT_ROOT = isLinux && process.getuid?.() !== 0

      it.if(LIVE)(
        'leaves the project writable after a pointer that names the checkout',
        async () => {
          // One command: a `.git` file naming the checkout, and an entry
          // named `hooks` that is a link, which makes the checkout a git
          // directory with a symlinked entry - denied WHOLE before this.
          const checkout = join(dir, 'repo')
          mkdirSync(checkout, { recursive: true })
          writeFileSync(join(checkout, 'f.txt'), 'one\n')
          process.chdir(checkout)

          const plant = await wrapCommandWithSandboxLinux({
            command:
              `printf 'ref: refs/heads/main\\n' > ${join(checkout, 'HEAD')} && ` +
              `ln -sfn nowhere ${join(checkout, 'hooks')} && ` +
              `printf 'gitdir: .\\n' > ${join(checkout, '.git')} && echo PLANTED`,
            needsNetworkRestriction: false,
            allowAllUnixSockets: true,
            readConfig: undefined,
            writeConfig: { allowOnly: [checkout], denyWithinAllow: [] },
          })
          expect(
            spawnSync(plant, {
              shell: true,
              encoding: 'utf8',
              timeout: 120000,
              cwd: checkout,
            }).stdout,
          ).toContain('PLANTED')
          cleanupBwrapMountPoints({ force: true })

          const after = await wrapCommandWithSandboxLinux({
            command:
              'echo BOOTED; ' +
              `echo ok > ${join(checkout, 'f.txt')} || echo PROJECT_FILE_READONLY; ` +
              `mkdir -p ${join(checkout, 'sub')} || echo SUBDIR_UNCREATABLE; ` +
              'echo DONE',
            needsNetworkRestriction: false,
            allowAllUnixSockets: true,
            readConfig: undefined,
            writeConfig: { allowOnly: [checkout], denyWithinAllow: [] },
          })
          const result = spawnSync(after, {
            shell: true,
            encoding: 'utf8',
            timeout: 120000,
            cwd: checkout,
          })

          expect(result.stdout).toContain('BOOTED')
          expect(result.stdout).toContain('DONE')
          expect(result.stdout).not.toContain('PROJECT_FILE_READONLY')
          expect(result.stdout).not.toContain('SUBDIR_UNCREATABLE')
          expect(readFileSync(join(checkout, 'f.txt'), 'utf8')).toBe('ok\n')
        },
        300000,
      )

      it.if(LIVE)(
        'leaves the project writable after a modules entry linked at the checkout',
        async () => {
          // The same end state with no pointer file at all: the walk follows
          // `.git/modules/x` to the checkout, which has an entry named
          // `hooks`, so it reads as a git directory whose entry is a link.
          const checkout = join(dir, 'repo')
          const gitDir = join(checkout, '.git')
          mkdirSync(join(gitDir, 'modules'), { recursive: true })
          writeFileSync(join(gitDir, 'HEAD'), 'ref: refs/heads/main')
          writeFileSync(join(checkout, 'f.txt'), 'one\n')
          process.chdir(checkout)

          const plant = await wrapCommandWithSandboxLinux({
            command:
              `ln -sfn nowhere ${join(checkout, 'hooks')} && ` +
              `ln -sfn ../.. ${join(gitDir, 'modules', 'x')} && echo PLANTED`,
            needsNetworkRestriction: false,
            allowAllUnixSockets: true,
            readConfig: undefined,
            writeConfig: { allowOnly: [checkout], denyWithinAllow: [] },
          })
          expect(
            spawnSync(plant, {
              shell: true,
              encoding: 'utf8',
              timeout: 120000,
              cwd: checkout,
            }).stdout,
          ).toContain('PLANTED')
          cleanupBwrapMountPoints({ force: true })

          const after = await wrapCommandWithSandboxLinux({
            command:
              'echo BOOTED; ' +
              `echo ok > ${join(checkout, 'f.txt')} || echo PROJECT_FILE_READONLY; ` +
              'echo DONE',
            needsNetworkRestriction: false,
            allowAllUnixSockets: true,
            readConfig: undefined,
            writeConfig: { allowOnly: [checkout], denyWithinAllow: [] },
          })
          const result = spawnSync(after, {
            shell: true,
            encoding: 'utf8',
            timeout: 120000,
            cwd: checkout,
          })

          expect(result.stdout).toContain('BOOTED')
          expect(result.stdout).toContain('DONE')
          expect(result.stdout).not.toContain('PROJECT_FILE_READONLY')
          expect(readFileSync(join(checkout, 'f.txt'), 'utf8')).toBe('ok\n')
        },
        300000,
      )

      it.if(NOT_ROOT)(
        'refuses rather than deny a working directory it cannot list',
        async () => {
          // The one whole-directory deny nothing stands in for: what is
          // beneath an unlistable directory is unknown, so dropping it would
          // run the command against an unscanned tree and keeping it locks
          // the project. Refusing names the directory, and one chmod outside
          // the sandbox lifts it.
          const checkout = join(dir, 'repo')
          mkdirSync(checkout, { recursive: true })
          process.chdir(checkout)
          // Searchable, so chdir and the walk's own lstat still work, and
          // unreadable, so neither rg nor the walk can list it.
          chmodSync(checkout, 0o100)
          try {
            const error = await wrapCommandWithSandboxLinux({
              command: 'true',
              needsNetworkRestriction: false,
              readConfig: undefined,
              writeConfig: { allowOnly: [checkout], denyWithinAllow: [] },
            }).catch((e: unknown) => e)

            expect(error).toBeInstanceOf(LinuxSandboxProfileError)
            expect((error as LinuxSandboxProfileError).code).toBe(
              'deny_scan_failed',
            )
            expect((error as Error).message).toContain(checkout)
          } finally {
            chmodSync(checkout, 0o755)
          }
        },
        60000,
      )

      it.if(LIVE && NOT_ROOT)(
        'keeps wrapping a tree holding a directory that is readable but not searchable',
        async () => {
          // mode 0400: its entries list, and nothing in it can be reached.
          // The walk comes here for the CHILD whose own listing failed, and
          // recording that child - a path the host cannot stat either - asks
          // bubblewrap for a file mount at what is really a directory, which
          // fails every later wrap with an untyped error.
          const checkout = join(dir, 'repo')
          const readable = join(checkout, 'a')
          mkdirSync(join(readable, 'nested', '.git'), { recursive: true })
          writeFileSync(
            join(readable, 'nested', '.git', 'HEAD'),
            'ref: refs/heads/main\n',
          )
          writeFileSync(join(checkout, 'f.txt'), 'one\n')
          process.chdir(checkout)
          chmodSync(readable, 0o400)
          try {
            const command = await wrapCommandWithSandboxLinux({
              command:
                'echo BOOTED; ' +
                `echo ok > ${join(checkout, 'f.txt')} || echo PROJECT_FILE_READONLY; ` +
                `! mkdir ${join(readable, 'x')} || echo UNSEARCHABLE_WRITABLE; ` +
                'echo DONE',
              needsNetworkRestriction: false,
              allowAllUnixSockets: true,
              readConfig: undefined,
              writeConfig: { allowOnly: [checkout], denyWithinAllow: [] },
            })
            const result = spawnSync(command, {
              shell: true,
              encoding: 'utf8',
              timeout: 120000,
              cwd: checkout,
            })

            expect(result.stdout).toContain('BOOTED')
            expect(result.stdout).toContain('DONE')
            expect(result.stderr).not.toContain('Is a directory')
            expect(result.stdout).not.toContain('PROJECT_FILE_READONLY')
            // The directory that cannot be seen through is denied whole.
            expect(result.stdout).not.toContain('UNSEARCHABLE_WRITABLE')
          } finally {
            chmodSync(readable, 0o755)
          }
        },
        300000,
      )

      it.if(NOT_ROOT)(
        'wraps a project holding an unreadable directory at the scan depth limit',
        async () => {
          // ripgrep opens a directory that sits AT its --max-depth to list
          // it, and reports one it cannot read; this walk stops a level
          // above, so a directory another user owns exactly that far down -
          // a `docker/data/postgres`, mode 0700 - was an EACCES the walk
          // found nothing for, and every command in the project refused.
          const checkout = join(dir, 'repo')
          const deep = join(checkout, 'docker', 'data', 'postgres')
          mkdirSync(deep, { recursive: true })
          writeFileSync(join(checkout, 'f.txt'), 'one\n')
          process.chdir(checkout)
          chmodSync(deep, 0o000)
          try {
            const command = await wrapCommandWithSandboxLinux({
              command: 'true',
              needsNetworkRestriction: false,
              readConfig: undefined,
              writeConfig: { allowOnly: [checkout], denyWithinAllow: [] },
            })

            expect(command).toContain('bwrap')
          } finally {
            chmodSync(deep, 0o755)
          }
        },
        60000,
      )
    })

    /**
     * `modules` is where a git directory keeps the git directories of its
     * submodules. It is no deny path of its own - that would take every one
     * of them read-only - but it is an entry a command can replace, and
     * replacing it aims every submodule this repository has at hooks nothing
     * denied. It is held the way a chain hop is.
     */
    describe('a modules directory that is a symlink', () => {
      it.if(LIVE)(
        "refuses a directory put in place of a submodule's modules link",
        async () => {
          const checkout = join(dir, 'repo')
          const gitDir = makeGitDir(join(checkout, '.git'))
          const submodule = makeGitDir(join(gitDir, 'modules', 'foo'))
          const outside = join(checkout, 'nm')
          makeGitDir(join(outside, 'bar'))
          symlinkSync('../../../nm', join(submodule, 'modules'))
          writeFileSync(join(checkout, 'f.txt'), 'one\n')
          process.chdir(checkout)

          const command = await wrapCommandWithSandboxLinux({
            command:
              'echo BOOTED; ' +
              `! echo x > ${join(outside, 'bar', 'hooks', 'post-checkout')} || echo THROUGH_LINK_WRITABLE; ` +
              `! echo x > ${join(submodule, 'hooks', 'post-checkout')} || echo SUBMODULE_HOOKS_WRITABLE; ` +
              `! rm ${join(submodule, 'modules')} || echo MODULES_LINK_REMOVABLE; ` +
              // The reviewer's own sequence: replace the link with a real
              // directory of the same name and write the hook into it.
              `! { rm ${join(submodule, 'modules')} && ` +
              `mkdir -p ${join(submodule, 'modules', 'bar', 'hooks')} && ` +
              `echo x > ${join(submodule, 'modules', 'bar', 'hooks', 'post-checkout')}; } || echo MODULES_REPLACED; ` +
              `echo ok > ${join(checkout, 'f.txt')} || echo PROJECT_FILE_READONLY; ` +
              'echo DONE',
            needsNetworkRestriction: false,
            allowAllUnixSockets: true,
            readConfig: undefined,
            writeConfig: { allowOnly: [checkout], denyWithinAllow: [] },
          })
          const result = spawnSync(command, {
            shell: true,
            encoding: 'utf8',
            timeout: 120000,
            cwd: checkout,
          })

          expect(result.stdout).toContain('BOOTED')
          expect(result.stdout).toContain('DONE')
          expect(result.stdout).not.toContain('THROUGH_LINK_WRITABLE')
          expect(result.stdout).not.toContain('SUBMODULE_HOOKS_WRITABLE')
          expect(result.stdout).not.toContain('MODULES_LINK_REMOVABLE')
          expect(result.stdout).not.toContain('MODULES_REPLACED')
          expect(result.stdout).not.toContain('PROJECT_FILE_READONLY')
          // Nothing of it reached the host: the link is where it was, and
          // there is no hook at either end of it.
          expect(lstatSync(join(submodule, 'modules')).isSymbolicLink()).toBe(
            true,
          )
          expect(
            existsSync(join(outside, 'bar', 'hooks', 'post-checkout')),
          ).toBe(false)
        },
        300000,
      )

      it.if(LIVE)(
        'costs the repository its sandboxed git writes when a command plants the link',
        async () => {
          // The price of holding the link, recorded rather than left to be
          // found: an ordinary repository has no `.git/modules`, and an
          // absent one is deliberately not denied (a mount there would stop
          // `git submodule add`). So one `ln -s` makes `.git` a git
          // directory with a symlinked entry, which is denied whole from the
          // next wrap on - and nothing inside the sandbox can remove the
          // link, because `.git` is read-only by then.
          const git = Bun.which('git') as string
          const checkout = join(dir, 'repo')
          mkdirSync(checkout, { recursive: true })
          expect(
            spawnSync(
              git,
              ['-c', 'init.defaultBranch=main', 'init', '-q', checkout],
              { encoding: 'utf8', timeout: 60000 },
            ).status,
          ).toBe(0)
          writeFileSync(join(checkout, 'f.txt'), 'one\n')
          process.chdir(checkout)

          const plant = await wrapCommandWithSandboxLinux({
            command: `ln -sfn nowhere ${join(checkout, '.git', 'modules')} && echo PLANTED`,
            needsNetworkRestriction: false,
            allowAllUnixSockets: true,
            readConfig: undefined,
            writeConfig: { allowOnly: [checkout], denyWithinAllow: [] },
          })
          expect(
            spawnSync(plant, {
              shell: true,
              encoding: 'utf8',
              timeout: 120000,
              cwd: checkout,
            }).stdout,
          ).toContain('PLANTED')
          cleanupBwrapMountPoints({ force: true })

          const after = await wrapCommandWithSandboxLinux({
            command:
              'echo BOOTED; ' +
              `${git} -C ${checkout} status --porcelain > /dev/null || echo GIT_STATUS_FAILED; ` +
              `echo two > ${join(checkout, 'f.txt')} || echo PROJECT_FILE_READONLY; ` +
              `${git} -C ${checkout} add f.txt && ${git} -C ${checkout} -c user.email=a@b -c user.name=n commit -q -m x && echo GIT_COMMIT_WORKED; ` +
              `! rm ${join(checkout, '.git', 'modules')} || echo LINK_REMOVABLE; ` +
              `! echo x > ${join(checkout, '.git', 'hooks', 'post-commit')} || echo HOOK_PLANTABLE; ` +
              'echo DONE',
            needsNetworkRestriction: false,
            allowAllUnixSockets: true,
            readConfig: undefined,
            writeConfig: { allowOnly: [checkout], denyWithinAllow: [] },
          })
          const result = spawnSync(after, {
            shell: true,
            encoding: 'utf8',
            timeout: 120000,
            cwd: checkout,
          })

          expect(result.stdout).toContain('BOOTED')
          expect(result.stdout).toContain('DONE')
          // The work tree is the command's, and reading the repository works.
          expect(result.stdout).not.toContain('PROJECT_FILE_READONLY')
          expect(result.stdout).not.toContain('GIT_STATUS_FAILED')
          // What it costs: everything that writes the git directory.
          expect(result.stdout).not.toContain('GIT_COMMIT_WORKED')
          expect(result.stdout).not.toContain('LINK_REMOVABLE')
          expect(result.stdout).not.toContain('HOOK_PLANTABLE')
        },
        300000,
      )
    })
  },
)
