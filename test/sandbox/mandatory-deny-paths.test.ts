import {
  describe,
  it,
  expect,
  beforeAll,
  afterAll,
  beforeEach,
  afterEach,
} from 'bun:test'
import { spawn, spawnSync } from 'node:child_process'
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  renameSync,
  rmSync,
  writeFileSync,
  readFileSync,
  symlinkSync,
  existsSync,
  statSync,
  realpathSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { getPlatform } from '../../src/utils/platform.js'
import {
  wrapCommandWithSandboxMacOS,
  macGetMandatoryDenyPatterns,
} from '../../src/sandbox/macos-sandbox-utils.js'
import {
  wrapCommandWithSandboxLinux,
  cleanupBwrapMountPoints,
} from '../../src/sandbox/linux-sandbox-utils.js'
import {
  GitMetadataError,
  gitDirDenyPaths,
  gitFileDenyPaths,
  submoduleGitDirs,
} from '../../src/sandbox/mandatory-deny-paths.js'
import { isLinux, isSupportedPlatform, isWindows } from '../helpers/platform.js'

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
    let originalCwd: string

    beforeAll(() => {
      originalCwd = process.cwd()
      mkdirSync(TEST_DIR, { recursive: true })
      mkdirSync(READ_DENY_DIR, { recursive: true })
      writeFileSync(join(READ_DENY_DIR, 'secret.txt'), ORIGINAL_CONTENT)

      // Create ALL dangerous files from DANGEROUS_FILES
      writeFileSync(join(TEST_DIR, '.bashrc'), ORIGINAL_CONTENT)
      writeFileSync(join(TEST_DIR, '.bash_profile'), ORIGINAL_CONTENT)
      writeFileSync(join(TEST_DIR, '.gitconfig'), ORIGINAL_CONTENT)
      writeFileSync(join(TEST_DIR, '.gitmodules'), ORIGINAL_CONTENT)
      writeFileSync(join(TEST_DIR, '.zshrc'), ORIGINAL_CONTENT)
      writeFileSync(join(TEST_DIR, '.zprofile'), ORIGINAL_CONTENT)
      writeFileSync(join(TEST_DIR, '.profile'), ORIGINAL_CONTENT)
      writeFileSync(join(TEST_DIR, '.ripgreprc'), ORIGINAL_CONTENT)
      writeFileSync(join(TEST_DIR, '.mcp.json'), ORIGINAL_CONTENT)

      // Create .git with hooks and config
      mkdirSync(join(TEST_DIR, '.git', 'hooks'), { recursive: true })
      writeFileSync(join(TEST_DIR, '.git', 'config'), ORIGINAL_CONTENT)
      writeFileSync(
        join(TEST_DIR, '.git', 'hooks', 'pre-commit'),
        ORIGINAL_CONTENT,
      )
      writeFileSync(join(TEST_DIR, '.git', 'HEAD'), 'ref: refs/heads/main')

      // Create .vscode
      mkdirSync(join(TEST_DIR, '.vscode'), { recursive: true })
      writeFileSync(
        join(TEST_DIR, '.vscode', 'settings.json'),
        ORIGINAL_CONTENT,
      )

      // Create .idea
      mkdirSync(join(TEST_DIR, '.idea'), { recursive: true })
      writeFileSync(join(TEST_DIR, '.idea', 'workspace.xml'), ORIGINAL_CONTENT)

      // Create .claude/commands and .claude/agents (should be blocked)
      mkdirSync(join(TEST_DIR, '.claude', 'commands'), { recursive: true })
      mkdirSync(join(TEST_DIR, '.claude', 'agents'), { recursive: true })
      writeFileSync(
        join(TEST_DIR, '.claude', 'commands', 'test.md'),
        ORIGINAL_CONTENT,
      )
      writeFileSync(
        join(TEST_DIR, '.claude', 'agents', 'test-agent.md'),
        ORIGINAL_CONTENT,
      )

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
    }

    async function runSandboxed(
      command: string,
      opts: SandboxRunOptions = {},
    ): Promise<{ success: boolean; stderr: string }> {
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

    /**
     * The write did not land. On Linux bwrap leaves the empty file it
     * mounted over the absent deny path; on macOS nothing is created.
     */
    function expectNotWritten(absolutePath: string): void {
      const content = existsSync(absolutePath)
        ? readFileSync(absolutePath, 'utf8')
        : ''
      expect(content).toBe('')
    }

    async function runSandboxedWrite(
      filePath: string,
      content: string,
      opts: SandboxRunOptions = {},
    ): Promise<{ success: boolean; stderr: string }> {
      return runSandboxed(`echo '${content}' > '${filePath}'`, opts)
    }

    describe('Dangerous files should be blocked', () => {
      it('blocks writes to .bashrc', async () => {
        const result = await runSandboxedWrite('.bashrc', MODIFIED_CONTENT)

        expect(result.success).toBe(false)
        expect(readFileSync('.bashrc', 'utf8')).toBe(ORIGINAL_CONTENT)
      })

      it('blocks writes to .gitconfig', async () => {
        const result = await runSandboxedWrite('.gitconfig', MODIFIED_CONTENT)

        expect(result.success).toBe(false)
        expect(readFileSync('.gitconfig', 'utf8')).toBe(ORIGINAL_CONTENT)
      })

      it('blocks writes to .zshrc', async () => {
        const result = await runSandboxedWrite('.zshrc', MODIFIED_CONTENT)

        expect(result.success).toBe(false)
        expect(readFileSync('.zshrc', 'utf8')).toBe(ORIGINAL_CONTENT)
      })

      it('blocks writes to .mcp.json', async () => {
        const result = await runSandboxedWrite('.mcp.json', MODIFIED_CONTENT)

        expect(result.success).toBe(false)
        expect(readFileSync('.mcp.json', 'utf8')).toBe(ORIGINAL_CONTENT)
      })

      it('blocks writes to .bash_profile', async () => {
        const result = await runSandboxedWrite(
          '.bash_profile',
          MODIFIED_CONTENT,
        )

        expect(result.success).toBe(false)
        expect(readFileSync('.bash_profile', 'utf8')).toBe(ORIGINAL_CONTENT)
      })

      it('blocks writes to .zprofile', async () => {
        const result = await runSandboxedWrite('.zprofile', MODIFIED_CONTENT)

        expect(result.success).toBe(false)
        expect(readFileSync('.zprofile', 'utf8')).toBe(ORIGINAL_CONTENT)
      })

      it('blocks writes to .profile', async () => {
        const result = await runSandboxedWrite('.profile', MODIFIED_CONTENT)

        expect(result.success).toBe(false)
        expect(readFileSync('.profile', 'utf8')).toBe(ORIGINAL_CONTENT)
      })

      it('blocks writes to .gitmodules', async () => {
        const result = await runSandboxedWrite('.gitmodules', MODIFIED_CONTENT)

        expect(result.success).toBe(false)
        expect(readFileSync('.gitmodules', 'utf8')).toBe(ORIGINAL_CONTENT)
      })

      it('blocks writes to .ripgreprc', async () => {
        const result = await runSandboxedWrite('.ripgreprc', MODIFIED_CONTENT)

        expect(result.success).toBe(false)
        expect(readFileSync('.ripgreprc', 'utf8')).toBe(ORIGINAL_CONTENT)
      })
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
      it("blocks writes to a nested repository's .git/config even when gitignored", async () => {
        const result = await runSandboxedWrite(
          'nested/.git/config',
          MODIFIED_CONTENT,
        )

        expect(result.success).toBe(false)
        expect(readFileSync('nested/.git/config', 'utf8')).toBe(
          ORIGINAL_CONTENT,
        )
      })

      it("blocks writes to a nested repository's existing hook at the default depth", async () => {
        const result = await runSandboxedWrite(
          'nested/.git/hooks/pre-commit',
          MODIFIED_CONTENT,
        )

        expect(result.success).toBe(false)
        expect(readFileSync('nested/.git/hooks/pre-commit', 'utf8')).toBe(
          ORIGINAL_CONTENT,
        )
      })

      it("blocks a nested repository's hooks when only its HEAD is within the scan depth", async () => {
        // With allowGitConfig the scan does not look for .git/config, and the
        // hook files lie one level past the default depth.
        const result = await runSandboxedWrite(
          'nested/.git/hooks/pre-commit',
          MODIFIED_CONTENT,
          { allowGitConfig: true },
        )

        expect(result.success).toBe(false)
        expect(readFileSync('nested/.git/hooks/pre-commit', 'utf8')).toBe(
          ORIGINAL_CONTENT,
        )
      })

      it('blocks creating a new hook in a nested repository', async () => {
        const result = await runSandboxedWrite(
          'nested/.git/hooks/post-checkout',
          MODIFIED_CONTENT,
        )

        expect(result.success).toBe(false)
        expect(existsSync('nested/.git/hooks/post-checkout')).toBe(false)
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

      it("blocks writes to a submodule's config under .git/modules", async () => {
        const result = await runSandboxedWrite(
          '.git/modules/lib/config',
          MODIFIED_CONTENT,
        )

        expect(result.success).toBe(false)
        expect(readFileSync('.git/modules/lib/config', 'utf8')).toBe(
          ORIGINAL_CONTENT,
        )
      })

      it("blocks creating a hook in a submodule's git directory", async () => {
        const result = await runSandboxedWrite(
          '.git/modules/lib/hooks/post-checkout',
          MODIFIED_CONTENT,
        )

        expect(result.success).toBe(false)
        expect(existsSync('.git/modules/lib/hooks/post-checkout')).toBe(false)
      })

      it("blocks creating a hook in a nested repository's submodule", async () => {
        const result = await runSandboxedWrite(
          'nested/.git/modules/dep/hooks/post-checkout',
          MODIFIED_CONTENT,
        )

        expect(result.success).toBe(false)
        expect(existsSync('nested/.git/modules/dep/hooks/post-checkout')).toBe(
          false,
        )
      })

      it("blocks repointing a submodule checkout's .git file", async () => {
        const result = await runSandboxedWrite(
          'lib/.git',
          'gitdir: /tmp/elsewhere',
        )

        expect(result.success).toBe(false)
        expect(readFileSync('lib/.git', 'utf8')).toBe(
          'gitdir: ../.git/modules/lib',
        )
      })

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

      it("blocks creating a commondir in the repository's git directory", async () => {
        // git reads hooks and config through commondir, so a write here
        // moves every deny below to a directory of the command's choosing.
        const result = await runSandboxedWrite('.git/commondir', 'decoy')

        expect(result.success).toBe(false)
        expectNotWritten(join(TEST_DIR, '.git', 'commondir'))
      })

      it("blocks creating a commondir in a submodule's git directory", async () => {
        const result = await runSandboxedWrite(
          '.git/modules/lib/commondir',
          'decoy',
        )

        expect(result.success).toBe(false)
        expectNotWritten(join(TEST_DIR, '.git', 'modules', 'lib', 'commondir'))
      })

      it("blocks creating a nested repository's commondir", async () => {
        const result = await runSandboxedWrite('nested/.git/commondir', 'decoy')

        expect(result.success).toBe(false)
        expectNotWritten(join(TEST_DIR, 'nested', '.git', 'commondir'))
      })

      it('blocks creating .git/config.worktree', async () => {
        // Read instead of .git/config wherever extensions.worktreeConfig is
        // on, which `git sparse-checkout init` turns on.
        const result = await runSandboxedWrite(
          '.git/config.worktree',
          'fsmonitor = touch pwned',
        )

        expect(result.success).toBe(false)
        expectNotWritten(join(TEST_DIR, '.git', 'config.worktree'))
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

          expect(error).toBeInstanceOf(Error)
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
              'chmod 755 locked && echo X > locked/.git/hooks/pre-commit',
            )

            expect(result.success).toBe(false)
            expect(result.stderr).not.toBe('')
          } finally {
            chmodSync(join(TEST_DIR, 'locked'), 0o755)
            rmSync(join(TEST_DIR, 'locked'), { recursive: true, force: true })
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
      it('blocks writes to .vscode/', async () => {
        const result = await runSandboxedWrite(
          '.vscode/settings.json',
          MODIFIED_CONTENT,
        )

        expect(result.success).toBe(false)
        expect(readFileSync('.vscode/settings.json', 'utf8')).toBe(
          ORIGINAL_CONTENT,
        )
      })

      it('blocks writes to .claude/commands/', async () => {
        const result = await runSandboxedWrite(
          '.claude/commands/test.md',
          MODIFIED_CONTENT,
        )

        expect(result.success).toBe(false)
        expect(readFileSync('.claude/commands/test.md', 'utf8')).toBe(
          ORIGINAL_CONTENT,
        )
      })

      it('blocks writes to .claude/agents/', async () => {
        const result = await runSandboxedWrite(
          '.claude/agents/test-agent.md',
          MODIFIED_CONTENT,
        )

        expect(result.success).toBe(false)
        expect(readFileSync('.claude/agents/test-agent.md', 'utf8')).toBe(
          ORIGINAL_CONTENT,
        )
      })

      it('blocks writes to .idea/', async () => {
        const result = await runSandboxedWrite(
          '.idea/workspace.xml',
          MODIFIED_CONTENT,
        )

        expect(result.success).toBe(false)
        expect(readFileSync('.idea/workspace.xml', 'utf8')).toBe(
          ORIGINAL_CONTENT,
        )
      })
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

describe('macGetMandatoryDenyPatterns - Unit Tests', () => {
  it('includes .git/config in deny patterns when allowGitConfig is false', () => {
    const patterns = macGetMandatoryDenyPatterns(false)

    // Should include .git/config pattern
    const hasGitConfigPattern = patterns.some(
      p => p.includes('.git/config') || p.endsWith('.git/config'),
    )
    expect(hasGitConfigPattern).toBe(true)
  })

  it('excludes .git/config from deny patterns when allowGitConfig is true', () => {
    const patterns = macGetMandatoryDenyPatterns(true)

    // Should NOT include .git/config pattern
    const hasGitConfigPattern = patterns.some(
      p => p.includes('.git/config') || p.endsWith('.git/config'),
    )
    expect(hasGitConfigPattern).toBe(false)
  })

  it('always includes .git/hooks in deny patterns regardless of allowGitConfig', () => {
    const patternsWithoutGitConfig = macGetMandatoryDenyPatterns(false)
    const patternsWithGitConfig = macGetMandatoryDenyPatterns(true)

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

  it('defaults to blocking .git/config when no argument provided', () => {
    const patterns = macGetMandatoryDenyPatterns()

    const hasGitConfigPattern = patterns.some(
      p => p.includes('.git/config') || p.endsWith('.git/config'),
    )
    expect(hasGitConfigPattern).toBe(true)
  })
})
describe('Git metadata deny paths - Unit Tests', () => {
  let dir: string

  beforeEach(() => {
    // Real, so a temporary directory that is itself reached through a
    // symlink (macOS /var) does not make every path here two paths.
    dir = realpathSync(mkdtempSync(join(tmpdir(), 'git-deny-paths-')))
  })

  afterEach(() => {
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

  it('follows a pointer to the git directory it names', () => {
    const gitDir = makeGitDir(join(dir, 'gitdir'))
    const pointer = makePointer('checkout', '../gitdir')

    expect(gitFileDenyPaths(pointer, false)).toEqual([
      pointer,
      ...gitDirDenyPaths(gitDir, false),
    ])
  })

  it("follows a linked worktree's commondir as well", () => {
    const main = makeGitDir(join(dir, 'main.git'))
    const worktreeGitDir = makeGitDir(join(dir, 'main.git', 'worktrees', 'wt'))
    writeFileSync(join(worktreeGitDir, 'commondir'), '../..\n')
    const pointer = makePointer('wt-checkout', worktreeGitDir)

    expect(gitFileDenyPaths(pointer, false)).toEqual([
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

    expect(gitFileDenyPaths(pointer, false)).toEqual([pointer])
  })

  it('blocks the git directory a dangling pointer names from being filled in', () => {
    const pointer = makePointer('checkout', '../not-created-yet')

    expect(gitFileDenyPaths(pointer, false)).toEqual([
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
    expect(gitFileDenyPaths(pointer, false)).toEqual([
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
    expect(gitFileDenyPaths(pointer, false)).toEqual([
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

    expect(gitFileDenyPaths(pointer, false)).toEqual([pointer])
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
    expect(gitFileDenyPaths(atBound, false)).toEqual([
      atBound,
      ...gitDirDenyPaths(gitDir, false),
    ])

    // One byte more is a .git file git refuses outright, so it leads nowhere.
    const pastBound = writePointer(
      'past-bound',
      head + '\n'.repeat(maxSize + 1 - head.length),
    )
    expect(statSync(pastBound).size).toBe(maxSize + 1)
    expect(gitFileDenyPaths(pastBound, false)).toEqual([pastBound])
  })

  it.if(!isWindows)('takes a path that spans lines whole, as git does', () => {
    // Only the newline bytes at the END of the file are stripped, so one in
    // the middle is part of the directory name.
    const gitDir = makeGitDir(join(dir, 'two\nlines'))
    const pointer = writePointer('checkout', `gitdir: ${gitDir}\n`)

    expect(gitFileDenyPaths(pointer, false)).toEqual([
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

    expect(gitFileDenyPaths(pointer, false)).toEqual([
      pointer,
      ...gitDirDenyPaths(gitDir, false),
    ])
  })

  it('strips a CRLF line ending', () => {
    const gitDir = makeGitDir(join(dir, 'gitdir'))
    const pointer = writePointer('checkout', `gitdir: ${gitDir}\r\n`)

    expect(gitFileDenyPaths(pointer, false)).toEqual([
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

    expect(() => gitFileDenyPaths(pointer, false)).toThrow(GitMetadataError)
  })

  it("follows a commondir padded past the pointer's own bound", () => {
    const main = makeGitDir(join(dir, 'main.git'))
    const worktreeGitDir = makeGitDir(join(dir, 'main.git', 'worktrees', 'wt'))
    writeFileSync(
      join(worktreeGitDir, 'commondir'),
      `../..${'\n'.repeat(9000)}`,
    )
    const pointer = makePointer('wt-checkout', worktreeGitDir)

    expect(gitFileDenyPaths(pointer, false)).toEqual([
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

    const denyPaths = gitFileDenyPaths(pointer, false)
    expect(denyPaths).toEqual([
      pointer,
      ...gitDirDenyPaths(worktreeGitDir, false),
      ...gitDirDenyPaths(join(worktreeGitDir, ` ${main}`), false),
    ])
    expect(denyPaths).not.toContain(join(main, 'hooks'))
  })

  it.if(!isWindows)(
    'denies where a .. after a symlink lands, and the lexical path too',
    () => {
      // checkout/hop is real/side, so the kernel reads hop/../evil as
      // real/evil while folding it on paper gives checkout/evil. git opens
      // the first; denying only the second leaves its hooks writable.
      const physical = makeGitDir(join(dir, 'real', 'evil'))
      mkdirSync(join(dir, 'real', 'side'), { recursive: true })
      const pointer = writePointer('checkout', 'gitdir: hop/../evil\n')
      symlinkSync(join(dir, 'real', 'side'), join(dir, 'checkout', 'hop'))

      expect(gitFileDenyPaths(pointer, false)).toEqual([
        pointer,
        ...gitDirDenyPaths(join(dir, 'checkout', 'evil'), false),
        ...gitDirDenyPaths(physical, false),
      ])
    },
  )

  it.if(!isWindows)('denies both when both are git directories', () => {
    const lexical = makeGitDir(join(dir, 'checkout', 'evil'))
    const physical = makeGitDir(join(dir, 'real', 'evil'))
    mkdirSync(join(dir, 'real', 'side'), { recursive: true })
    const pointer = writePointer('checkout', 'gitdir: hop/../evil\n')
    symlinkSync(join(dir, 'real', 'side'), join(dir, 'checkout', 'hop'))

    expect(gitFileDenyPaths(pointer, false)).toEqual([
      pointer,
      ...gitDirDenyPaths(lexical, false),
      ...gitDirDenyPaths(physical, false),
    ])
  })

  it.if(!isWindows)('walks a chain of symlinks as the kernel does', () => {
    // first is second, second is an absolute path to real/side/deeper.
    const physical = makeGitDir(join(dir, 'real', 'evil'))
    mkdirSync(join(dir, 'real', 'side', 'deeper'), { recursive: true })
    const pointer = writePointer('checkout', 'gitdir: first/../../evil\n')
    symlinkSync('second', join(dir, 'checkout', 'first'))
    symlinkSync(
      join(dir, 'real', 'side', 'deeper'),
      join(dir, 'checkout', 'second'),
    )

    expect(gitFileDenyPaths(pointer, false)).toEqual([
      pointer,
      ...gitDirDenyPaths(join(dir, 'evil'), false),
      ...gitDirDenyPaths(physical, false),
    ])
  })

  it.if(!isWindows)(
    'takes the rest of a path as written past what is not there',
    () => {
      // The kernel cannot traverse a missing directory, so nothing after it
      // redirects the path: gone/x is denied against being created, and so
      // is the lexical checkout/x.
      const pointer = writePointer('checkout', 'gitdir: hop/../x\n')
      symlinkSync('gone/deeper', join(dir, 'checkout', 'hop'))

      expect(gitFileDenyPaths(pointer, false)).toEqual([
        pointer,
        ...gitDirDenyPaths(join(dir, 'checkout', 'x'), false),
        ...gitDirDenyPaths(join(dir, 'checkout', 'gone', 'x'), false),
      ])
    },
  )

  it.if(!isWindows)('denies what it can reach when symlinks loop', () => {
    const pointer = writePointer('checkout', 'gitdir: loopA/../evil\n')
    symlinkSync(join(dir, 'checkout', 'loopB'), join(dir, 'checkout', 'loopA'))
    symlinkSync(join(dir, 'checkout', 'loopA'), join(dir, 'checkout', 'loopB'))

    // Past the hop limit the walk stops on the loop itself, which is where
    // the deny goes: the whole directory that still reads.
    expect(gitFileDenyPaths(pointer, false)).toEqual([
      pointer,
      ...gitDirDenyPaths(join(dir, 'checkout', 'evil'), false),
      join(dir, 'checkout'),
    ])
  })

  it.if(!isWindows)('resolves a commondir the same way', () => {
    const worktreeGitDir = makeGitDir(join(dir, 'wt.git'))
    const physical = makeGitDir(join(dir, 'real', 'common'))
    mkdirSync(join(dir, 'real', 'side'), { recursive: true })
    symlinkSync(join(dir, 'real', 'side'), join(worktreeGitDir, 'hop'))
    writeFileSync(join(worktreeGitDir, 'commondir'), 'hop/../common\n')
    const pointer = makePointer('wt-checkout', worktreeGitDir)

    expect(gitFileDenyPaths(pointer, false)).toEqual([
      pointer,
      ...gitDirDenyPaths(worktreeGitDir, false),
      ...gitDirDenyPaths(join(worktreeGitDir, 'common'), false),
      ...gitDirDenyPaths(physical, false),
    ])
  })

  it.if(!isWindows)(
    'resolves a .. against the directory the pointer file is really in',
    () => {
      // The checkout is reached through a symlink, so `..` pops the
      // directory the kernel is in and not the one the path was spelled
      // from — nested/target, not dir/target.
      const physical = makeGitDir(join(dir, 'nested', 'target'))
      mkdirSync(join(dir, 'nested', 'checkout'), { recursive: true })
      symlinkSync(join(dir, 'nested', 'checkout'), join(dir, 'link'))
      const pointer = join(dir, 'link', '.git')
      writeFileSync(pointer, 'gitdir: ../target\n')

      expect(gitFileDenyPaths(pointer, false)).toEqual([
        pointer,
        ...gitDirDenyPaths(join(dir, 'target'), false),
        ...gitDirDenyPaths(physical, false),
      ])
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

    expect(() => gitFileDenyPaths(pointer, false)).toThrow(GitMetadataError)
  })

  it.if(!isWindows)(
    'does not block on a FIFO left where a git directory keeps its commondir',
    () => {
      const gitDir = makeGitDir(join(dir, 'gitdir'))
      expect(spawnSync('mkfifo', [join(gitDir, 'commondir')]).status).toBe(0)
      const pointer = makePointer('checkout', '../gitdir')

      expect(gitFileDenyPaths(pointer, false)).toEqual([
        pointer,
        ...gitDirDenyPaths(gitDir, false),
      ])
    },
  )

  it.if(!isWindows)(
    'does not block on a FIFO left where a pointer file goes',
    () => {
      mkdirSync(join(dir, 'checkout'), { recursive: true })
      const pointer = join(dir, 'checkout', '.git')
      expect(spawnSync('mkfifo', [pointer]).status).toBe(0)

      expect(gitFileDenyPaths(pointer, false)).toEqual([pointer])
    },
  )

  it('recognises a submodule git directory without a HEAD', () => {
    const gitDir = join(dir, 'modules', 'lib')
    mkdirSync(join(gitDir, 'hooks'), { recursive: true })

    expect(submoduleGitDirs(join(dir, 'modules'))).toEqual({
      gitDirs: [gitDir],
      unreadableDirs: [],
    })
  })

  it('walks a submodule name that spans several segments, and nested ones', () => {
    const outer = makeGitDir(join(dir, 'modules', 'vendor', 'lib'))
    const inner = makeGitDir(join(outer, 'modules', 'dep'))

    const scan = submoduleGitDirs(join(dir, 'modules'))
    expect(scan.gitDirs.sort()).toEqual([outer, inner].sort())
  })

  it.if(!isWindows)('follows a symlinked entry under modules', () => {
    const gitDir = makeGitDir(join(dir, 'elsewhere'))
    mkdirSync(join(dir, 'modules'), { recursive: true })
    symlinkSync(gitDir, join(dir, 'modules', 'lib'))

    expect(submoduleGitDirs(join(dir, 'modules')).gitDirs).toEqual([
      join(dir, 'modules', 'lib'),
    ])
  })

  it.if(!isWindows && process.getuid?.() !== 0)(
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

  it('stops walking modules at its own depth bound', () => {
    // Deeper than the bound: a name of 12 segments, which no real submodule
    // has, and which a symlink loop could otherwise spin on.
    const deep = join(dir, 'modules', ...Array.from({ length: 12 }, () => 'x'))
    makeGitDir(deep)

    expect(submoduleGitDirs(join(dir, 'modules')).gitDirs).toEqual([])
  })

  it('denies the directory the modules walk stopped at', () => {
    // A git directory one level past the bound: the walk never sees it, so
    // the directory it stopped at is denied whole instead.
    const bound = join(dir, 'modules', ...Array.from({ length: 10 }, () => 'x'))
    makeGitDir(join(bound, 'deep'))

    const scan = submoduleGitDirs(join(dir, 'modules'))
    expect(scan.gitDirs).toEqual([])
    expect(scan.unreadableDirs).toEqual([bound])
  })
})
