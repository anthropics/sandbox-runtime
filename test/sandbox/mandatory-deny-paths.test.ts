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
  readdirSync,
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
import { dirname, join } from 'node:path'
import { getPlatform } from '../../src/utils/platform.js'
import {
  indexOfMount,
  lastIndexOfMount,
  lastMountAt,
} from '../helpers/bwrap-argv.js'
import { bwrapCanNamespace } from '../helpers/bwrap-namespace.js'
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
} from '../../src/sandbox/linux-sandbox-utils.js'
import {
  GitMetadataError,
  SubmoduleDenyBudget,
  SubmoduleWalkBudgetError,
  gitDirDenyPaths,
  gitDirTreeDenyPaths,
  gitFileDenyPaths,
  gitRedirectPlaceholder,
  submoduleGitDirs,
} from '../../src/sandbox/mandatory-deny-paths.js'
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
        expectNotWritten(join(TEST_DIR, '.git', 'commondir'), '.\n')
      })

      it("blocks creating a commondir in a submodule's git directory", async () => {
        const result = await runSandboxedWrite(
          '.git/modules/lib/commondir',
          'decoy',
        )

        expect(result.success).toBe(false)
        expectNotWritten(
          join(TEST_DIR, '.git', 'modules', 'lib', 'commondir'),
          '.\n',
        )
      })

      it("blocks creating a nested repository's commondir", async () => {
        const result = await runSandboxedWrite('nested/.git/commondir', 'decoy')

        expect(result.success).toBe(false)
        expectNotWritten(join(TEST_DIR, 'nested', '.git', 'commondir'), '.\n')
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

  it('defaults to blocking .git/config when no argument provided', () => {
    const patterns = macGetMandatoryDenyEntries().map(e => e.path)

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
      const originalCwd = process.cwd()
      process.chdir(checkout)
      try {
        expect(() => linuxGetCwdMandatoryDenyPaths(false)).toThrow(
          GitMetadataError,
        )

        const monitored = linuxGetMonitorCwdDenyPaths(false)

        expect(monitored).toContain(pointer)
        expect(monitored).toContain(join(checkout, '.bashrc'))
        // A pointer file is itself the deny; the hooks and config of a git
        // directory that is not there are not denies the wrapper makes.
        expect(monitored).not.toContain(join(pointer, 'hooks'))
      } finally {
        process.chdir(originalCwd)
      }
    },
  )

  it.if(isLinux)('gives the monitor no git denies without a .git', () => {
    // A mount at an absent .git would block `git init`, so the wrapper makes
    // none there and the monitor must not judge writes against four it will
    // never see refused.
    const checkout = join(dir, 'no-repo')
    mkdirSync(checkout, { recursive: true })
    const originalCwd = process.cwd()
    process.chdir(checkout)
    try {
      const monitored = linuxGetMonitorCwdDenyPaths(false)

      expect(monitored).toContain(join(checkout, '.bashrc'))
      expect(monitored).not.toContain(join(checkout, '.git', 'hooks'))
      expect(monitored).not.toContain(join(checkout, '.git', 'config'))
    } finally {
      process.chdir(originalCwd)
    }
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
        expect(() => gitFileDenyPaths(pointer, false)).toThrow(GitMetadataError)
      } finally {
        chmodSync(commondir, 0o644)
      }
    },
  )

  it.if(process.getuid?.() !== 0)(
    'denies a git directory it cannot read whole, rather than refusing',
    () => {
      // git, running as the same user, cannot read through it either, so the
      // repository is already broken for everyone. Refusing every command in
      // the checkout would be a brick one chmod plants; the directory is
      // denied whole instead, and nothing under it stays writable.
      const main = makeGitDir(join(dir, 'main.git'))
      const worktreeGitDir = makeGitDir(join(main, 'worktrees', 'wt'))
      writeFileSync(join(worktreeGitDir, 'commondir'), '../..\n')
      const pointer = makePointer('wt-checkout', worktreeGitDir)
      chmodSync(worktreeGitDir, 0o000)
      try {
        expect(gitFileDenyPaths(pointer, false)).toEqual([
          pointer,
          worktreeGitDir,
        ])
      } finally {
        chmodSync(worktreeGitDir, 0o755)
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
      const originalCwd = process.cwd()
      process.chdir(join(dir, 'checkout'))
      try {
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
      } finally {
        process.chdir(originalCwd)
      }
    },
  )

  it('names itself, and carries a code, wherever it surfaces', () => {
    // macOS has no profile-error type of its own, so this IS the refusal the
    // caller branches on there; it is exported from the package root.
    const error = new GitMetadataError('x')

    expect(error.name).toBe('GitMetadataError')
    expect(error.code).toBe('git_metadata_unreadable')
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

  /**
   * A submodule name is a path and submodules nest, so how deep a real tree
   * can go is a question about the repository and not about this walk. There
   * is no depth bound: what bounds the walk is the time it is given, and what
   * stops it looping is where each directory really is.
   */
  it('walks a chain 200 directories deep, and denies every level of it', () => {
    // A hundred submodules each nested inside the one above, which is two
    // hundred directories of `<name>/modules` below .git/modules — far past
    // any bound the walk used to have, and enough of its own stack to
    // overflow a recursive one on some runtimes.
    const gitDirs: string[] = []
    let at = join(dir, 'modules')
    for (let level = 0; level < 100; level++) {
      at = join(at, 'x')
      makeGitDir(at)
      gitDirs.push(at)
      at = join(at, 'modules')
    }

    const scan = submoduleGitDirs(join(dir, 'modules'))
    expect(scan.unreadableDirs).toEqual([])
    expect(scan.gitDirs).toEqual([...gitDirs].sort())
    // Every level's hooks and config, not just the ones above a bound.
    const denies = gitDirTreeDenyPaths(dir, false)
    for (const gitDir of gitDirs) {
      expect(denies).toContain(join(gitDir, 'hooks'))
      expect(denies).toContain(join(gitDir, 'config'))
    }
  })

  it.if(!isWindows)('ends at a symlink pointing back into the tree', () => {
    // modules/a/back -> modules, which the walk would follow for ever if it
    // did not record where each directory really is.
    mkdirSync(join(dir, 'modules', 'a'), { recursive: true })
    symlinkSync(join(dir, 'modules'), join(dir, 'modules', 'a', 'back'))
    const gitDir = makeGitDir(join(dir, 'modules', 'a', 'lib'))

    expect(submoduleGitDirs(join(dir, 'modules'))).toEqual({
      gitDirs: [gitDir],
      unreadableDirs: [],
    })
  })

  it.if(!isWindows)('ends at a symlink loop, denying it whole', () => {
    // A loop cannot be stat'ed at all (ELOOP), which reads as unreadable
    // rather than as absent: the deepest directory the walk can reach for it
    // is denied whole.
    mkdirSync(join(dir, 'modules'), { recursive: true })
    symlinkSync(join(dir, 'modules', 'b'), join(dir, 'modules', 'a'))
    symlinkSync(join(dir, 'modules', 'a'), join(dir, 'modules', 'b'))

    expect(submoduleGitDirs(join(dir, 'modules'))).toEqual({
      gitDirs: [],
      unreadableDirs: [join(dir, 'modules'), join(dir, 'modules')],
    })
  })

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
    expect(error?.name).toBe('SubmoduleWalkBudgetError')
    expect(error?.code).toBe('submodule_walk_budget_exhausted')
    expect(error?.message).toContain(join(dir, 'modules'))
  })

  it.if(isLinux)(
    'refuses the wrap where the modules walk runs out of its time',
    async () => {
      const checkout = join(dir, 'repo')
      const gitDir = makeGitDir(join(checkout, '.git'))
      makeGitDir(join(gitDir, 'modules', 'lib'))

      const originalCwd = process.cwd()
      process.chdir(checkout)
      try {
        const error = await wrapCommandWithSandboxLinux({
          command: 'echo hi',
          needsNetworkRestriction: false,
          readConfig: undefined,
          writeConfig: { allowOnly: [checkout], denyWithinAllow: [] },
          // The walk shares the scan's budget, so one millisecond of it is
          // gone before the walk starts.
          ripgrepConfig: { command: 'rg', timeoutMs: 1 },
        }).catch((e: unknown) => e)

        expect(error).toBeInstanceOf(LinuxSandboxProfileError)
        expect((error as LinuxSandboxProfileError).code).toBe(
          'deny_scan_failed',
        )
      } finally {
        cleanupBwrapMountPoints({ force: true })
        process.chdir(originalCwd)
      }
    },
    30000,
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

      const originalCwd = process.cwd()
      process.chdir(checkout)
      try {
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
        const writeRootBind = indexOfMount(
          command,
          '--bind',
          checkout,
          checkout,
        )
        expect(writeRootBind).toBeGreaterThan(-1)
        expect(lastIndexOfMount(command, '--ro-bind', deep, deep)).toBeLessThan(
          writeRootBind,
        )
        expect(command).toContain(`--ro-bind ${join(deep, 'hooks')} `)

        // Where bwrap can run, prove it: what git needs writable in that
        // submodule still is, and what makes a write into code is not.
        if (bwrapCanNamespace()) {
          const result = spawnSync(
            await wrap(
              `sh -c 'echo o > ${join(deep, 'objects', 'x')} && ` +
                `! echo h > ${join(deep, 'hooks', 'x')} && ` +
                `! echo c > ${join(deep, 'config')} && ` +
                `echo SRT_DEEP_OK'`,
            ),
            { shell: true, encoding: 'utf8', timeout: 30000, cwd: checkout },
          )
          expect(result.stdout).toContain('SRT_DEEP_OK')
        }
      } finally {
        cleanupBwrapMountPoints({ force: true })
        process.chdir(originalCwd)
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

    const originalCwd = process.cwd()
    process.chdir(checkout)
    try {
      // Profile generation is pure string building, so this runs anywhere.
      const profile = wrapCommandWithSandboxMacOS({
        command: 'true',
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig: { allowOnly: [checkout], denyWithinAllow: [] },
      })
      expect(profile).toContain(`(subpath "${join(deep, 'hooks')}")`)
      // No deny covering the git directory whole, which would take its
      // objects, refs and index with it. Seatbelt has no argument cap, so
      // nothing is ever collapsed there.
      expect(profile).not.toContain(`(subpath "${deep}")`)
    } finally {
      process.chdir(originalCwd)
    }
  })
})

/**
 * bubblewrap parses at most 9000 words and takes three for each mount, so a
 * repository with thousands of submodules asks for more than it can be given.
 * The ceiling is not this library's to lift; refusing every command in such a
 * repository is the wrong answer to it, so the denies are degraded instead -
 * precise while they fit, then a whole git directory at a time, then the
 * `modules` directory whole. Seatbelt has no such cap, so none of this
 * applies on macOS.
 */
describe.if(isSupportedPlatform)(
  'Submodule denies past the argument cap',
  () => {
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

    /** A repository whose .git/modules holds `count` submodule git directories,
     *  named so that sorted order is the order they were made in. */
    function makeSuperproject(count: number): {
      checkout: string
      subs: string[]
    } {
      const checkout = join(dir, 'repo')
      const gitDir = makeGitDir(join(checkout, '.git'))
      const subs: string[] = []
      for (let i = 0; i < count; i++) {
        subs.push(
          makeGitDir(join(gitDir, 'modules', `s${String(i).padStart(5, '0')}`)),
        )
      }
      return { checkout, subs }
    }

    it('keeps the precise denies that fit and denies the rest of the submodules whole', () => {
      const { checkout, subs } = makeSuperproject(5)
      const gitDir = join(checkout, '.git')
      // One mount for every submodule at its cheapest, one for the `modules`
      // directory's own ancestor pin, and enough left over to upgrade two of
      // them to their four precise denies.
      const budget = new SubmoduleDenyBudget(5 + 1 + 2 * 4)

      const denies = gitDirTreeDenyPaths(gitDir, false, { budget })

      expect(budget.preciseGitDirs).toBe(2)
      expect(budget.wholeGitDirs).toBe(3)
      expect(budget.wholeModulesDirs).toEqual([])
      expect(budget.collapsed).toBe(true)
      for (const sub of subs.slice(0, 2)) {
        expect(denies).toContain(join(sub, 'hooks'))
        expect(denies).toContain(join(sub, 'config'))
        expect(denies).toContain(join(sub, 'commondir'))
        expect(denies).toContain(join(sub, 'config.worktree'))
        expect(denies).not.toContain(sub)
      }
      // The last in sorted order are the ones collapsed, so two wraps of one
      // tree collapse the same submodules.
      for (const sub of subs.slice(2)) {
        expect(denies).toContain(sub)
        expect(denies).not.toContain(join(sub, 'hooks'))
      }
      // The repository's own denies are never collapsed: it is one git
      // directory however many submodules it has.
      expect(denies).toContain(join(gitDir, 'hooks'))
    })

    it('denies the modules directory whole where not even one bind each fits', () => {
      const { checkout, subs } = makeSuperproject(5)
      const gitDir = join(checkout, '.git')
      const modules = join(gitDir, 'modules')
      const budget = new SubmoduleDenyBudget(5)

      const denies = gitDirTreeDenyPaths(gitDir, false, { budget })

      expect(budget.wholeModulesDirs).toEqual([modules])
      expect(budget.preciseGitDirs).toBe(0)
      expect(budget.wholeGitDirs).toBe(0)
      expect(denies).toContain(modules)
      for (const sub of subs) expect(denies).not.toContain(sub)
      expect(denies).toContain(join(gitDir, 'hooks'))
    })

    it('serves the repositories that ask first, which is what a nested one gets', () => {
      // One budget is spent across the whole wrap: the working directory's own
      // repository first and the nested repositories the scan found after it,
      // so it is the last of them that collapses.
      const first = makeGitDir(join(dir, 'first', '.git'))
      const second = makeGitDir(join(dir, 'second', '.git'))
      for (const gitDir of [first, second]) {
        for (let i = 0; i < 3; i++) makeGitDir(join(gitDir, 'modules', `s${i}`))
      }
      // Room for the first repository's three submodules precisely, and for
      // one bind each of the second's.
      const budget = new SubmoduleDenyBudget(3 + 1 + 3 * 4 + 3 + 1)

      gitDirTreeDenyPaths(first, false, { budget })
      expect(budget.preciseGitDirs).toBe(3)
      expect(budget.wholeGitDirs).toBe(0)

      const denies = gitDirTreeDenyPaths(second, false, { budget })
      expect(budget.preciseGitDirs).toBe(3)
      expect(budget.wholeGitDirs).toBe(3)
      expect(denies).toContain(join(second, 'modules', 's2'))
    })

    it('leaves every submodule its precise denies where no budget is given', () => {
      // Which is the macOS answer: its profile has no cap to stay under.
      const { checkout, subs } = makeSuperproject(5)

      const denies = gitDirTreeDenyPaths(join(checkout, '.git'), false)

      for (const sub of subs) {
        expect(denies).toContain(join(sub, 'hooks'))
        expect(denies).not.toContain(sub)
      }
    })

    it('says what it collapsed, once, naming the level', () => {
      const budget = new SubmoduleDenyBudget(0)
      expect(budget.collapsed).toBe(false)
      budget.preciseGitDirs = 300
      budget.wholeGitDirs = 1700
      budget.wholeModulesDirs.push('/repo/.git/modules')

      expect(budget.collapsed).toBe(true)
      expect(budget.describeCollapse()).toContain('1700 of 2000')
      expect(budget.describeCollapse()).toContain('/repo/.git/modules')
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

        // Before this it was refused up front with too_many_arguments, and
        // every command in the repository with it.
        const command = await wrap()
        expect(command).toContain('bwrap')

        // The mounts are past what one command line carries at this size, so
        // they are in the argument file bwrap reads - which is where its own
        // cap on parsed words is spent. Under it, with room to spare for the
        // handful still on the line.
        const profile = /\/proc\/\d+\/fd\/\d+/.exec(command)?.[0]
        expect(profile).toBeDefined()
        const words = readFileSync(profile as string, 'utf8').split('\0')
        words.pop()
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
          readFileSync(profile as string, 'utf8'),
        )

        // The violation monitor judges a refused write against the working
        // directory's own denies, which it works out for itself: it has to
        // collapse where the wrap collapsed or it would report the wrong path.
        const monitorDenies = new Set(linuxGetMonitorCwdDenyPaths(false))
        expect(monitorDenies.has(join(subs[0] as string, 'hooks'))).toBe(true)
        expect(monitorDenies.has(last)).toBe(true)

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
      'holds a collapsed submodule read-only while the rest of the tree works',
      async () => {
        const git = Bun.which('git')
        if (!bwrapCanNamespace() || git === null) return

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
  },
)

/**
 * Denying a path that is not there means mounting something at it, and two of
 * these the host's git reads back: it refuses to run at all against a
 * `commondir` it cannot read, and neither a bound /dev/null nor an empty file
 * is one. So these denies write their own mount point, holding what git
 * concludes with no file there, and bind a read-only copy of the same bytes
 * over it: the host's git keeps working for as long as the command runs, and
 * the sandbox's does too.
 */
describe.if(isLinux)('Placeholders for the files git reads', () => {
  /** Echoed by every command that runs for real, so nothing concludes
   *  anything from a sandbox that never started. */
  const BOOTED = 'BOOTED'
  /** Imported by the child process below, which wraps and is then killed. */
  const LINUX_BACKEND_SOURCE = new URL(
    '../../src/sandbox/linux-sandbox-utils.ts',
    import.meta.url,
  ).pathname
  const LIVE = bwrapCanNamespace() && Bun.which('git') !== null
  /** Enough to commit without a hook, an identity or a signature. */
  const IDENT = [
    '-c',
    'user.name=t',
    '-c',
    'user.email=t@t',
    '-c',
    'commit.gpgsign=false',
    '-c',
    'core.hooksPath=/dev/null',
  ]
  let dir: string
  const savedCwd = process.cwd()
  const savedTmpdir = process.env.TMPDIR

  beforeEach(() => {
    dir = realpathSync(mkdtempSync(join(tmpdir(), 'git-redirect-')))
  })

  afterEach(() => {
    process.chdir(savedCwd)
    // Forced cleanup also empties the placeholder store, so no case here
    // leaves one of its directories behind.
    cleanupBwrapMountPoints({ force: true })
    if (savedTmpdir === undefined) delete process.env.TMPDIR
    else process.env.TMPDIR = savedTmpdir
    rmSync(dir, { recursive: true, force: true })
  })

  /** A checkout whose `.git` git would accept, wrapped with it as the cwd. */
  function makeCheckout(name: string): string {
    const checkout = join(dir, name)
    mkdirSync(join(checkout, '.git', 'hooks'), { recursive: true })
    writeFileSync(join(checkout, '.git', 'HEAD'), 'ref: refs/heads/main')
    writeFileSync(join(checkout, '.git', 'config'), '[core]\n')
    return checkout
  }

  function wrapIn(
    checkout: string,
    command = 'true',
    opts: { denyWithinAllow?: string[]; allowOnly?: string[] } = {},
  ): Promise<string> {
    process.chdir(checkout)
    return wrapCommandWithSandboxLinux({
      command,
      needsNetworkRestriction: false,
      allowAllUnixSockets: true,
      readConfig: undefined,
      writeConfig: {
        allowOnly: opts.allowOnly ?? [checkout],
        denyWithinAllow: opts.denyWithinAllow ?? [],
      },
    })
  }

  /**
   * What bwrap is given to mount at `dest`, of the words `--flag src dest`.
   * Throws where nothing is mounted there, so an assertion about the source
   * cannot pass, or read as undefined, on a wrap that emitted no such mount.
   */
  function mountSource(command: string, dest: string): string {
    const mount = lastMountAt(command, dest)
    if (mount === undefined) {
      throw new Error(`nothing is mounted at ${dest}`)
    }
    const [, source, mounted] = mount.split(' ')
    if (source === undefined || mounted !== dest) {
      throw new Error(`the mount at ${dest} has no source: ${mount}`)
    }
    return source
  }

  function git(
    cwd: string,
    args: string[],
  ): { status: number | null; stdout: string } {
    const result = spawnSync('git', args, {
      cwd,
      encoding: 'utf8',
      timeout: 30000,
      env: { ...process.env, LC_ALL: 'C' },
    })
    return { status: result.status, stdout: `${result.stdout}${result.stderr}` }
  }

  /** A repository with one commit, made by git itself. */
  function gitRepo(name: string): string {
    const repo = join(dir, name)
    mkdirSync(repo, { recursive: true })
    expect(
      git(repo, ['-c', 'init.defaultBranch=main', 'init', '-q', '.']),
    ).toMatchObject({ status: 0 })
    writeFileSync(join(repo, 'index.js'), 'console.log(1)\n')
    expect(git(repo, ['add', 'index.js'])).toMatchObject({ status: 0 })
    expect(git(repo, [...IDENT, 'commit', '-q', '-m', 'one'])).toMatchObject({
      status: 0,
    })
    return repo
  }

  async function waitFor(ready: () => boolean, what: string): Promise<void> {
    for (let attempt = 0; attempt < 200; attempt++) {
      if (ready()) return
      await new Promise(resolve => setTimeout(resolve, 50))
    }
    throw new Error(`timed out waiting for ${what}`)
  }

  it('binds a commondir that is not there from a placeholder holding "."', async () => {
    const checkout = makeCheckout('repo')
    const commondir = join(checkout, '.git', 'commondir')

    const source = mountSource(await wrapIn(checkout), commondir)

    expect(source).not.toBe('/dev/null')
    expect(readFileSync(source, 'utf8')).toBe('.\n')
    // The mount point is this wrapper's own rather than the empty file
    // bubblewrap would make: it is what the HOST's git reads meanwhile.
    expect(readFileSync(commondir, 'utf8')).toBe('.\n')
  })

  it('reads the placeholder off the file, not off the deny entry', async () => {
    // A caller's own deny for the same file comes first and wins the dedup,
    // so the decision has to be made from the path the entry resolves to. An
    // entry's own spelling does not name the file: /dev/null lands there
    // instead, and the repository loses every git command for the wrap.
    const checkout = makeCheckout('repo')
    const commondir = join(checkout, '.git', 'commondir')

    const command = await wrapIn(checkout, 'true', {
      denyWithinAllow: ['./.git/commondir/'],
    })

    expect(readFileSync(mountSource(command, commondir), 'utf8')).toBe('.\n')
  })

  it('binds a commondir that is there from itself', async () => {
    const checkout = makeCheckout('repo')
    const commondir = join(checkout, '.git', 'commondir')
    writeFileSync(commondir, '../..\n')

    expect(mountSource(await wrapIn(checkout), commondir)).toBe(commondir)

    cleanupBwrapMountPoints({ force: true })
    expect(readFileSync(commondir, 'utf8')).toBe('../..\n')
  })

  it('takes its own mount point away, and a changed one never', async () => {
    const checkout = makeCheckout('repo')
    const commondir = join(checkout, '.git', 'commondir')

    await wrapIn(checkout)
    cleanupBwrapMountPoints({ force: true })
    expect(existsSync(commondir)).toBe(false)

    // A mount point something has written a real redirect into is not this
    // wrapper's to remove, the same way an empty one that gained content is
    // not: the cleanup compares what is there with what it wrote.
    await wrapIn(checkout)
    // Taken over by something that wanted a real redirect there, mode and
    // all: what the mount point holds is no longer what this wrote.
    chmodSync(commondir, 0o644)
    writeFileSync(commondir, '../..\n')
    cleanupBwrapMountPoints({ force: true })
    expect(readFileSync(commondir, 'utf8')).toBe('../..\n')
  })

  it('repairs a commondir left empty rather than covering it', async () => {
    // The shape bubblewrap's own ensure_file() leaves, which the wrap takes
    // for a mount point an earlier sandbox left behind and covers with
    // /dev/null — the one thing a commondir must never be covered with.
    const checkout = makeCheckout('repo')
    const commondir = join(checkout, '.git', 'commondir')
    writeFileSync(commondir, '', { mode: 0o444 })

    const source = mountSource(await wrapIn(checkout), commondir)

    expect(source).not.toBe('/dev/null')
    expect(readFileSync(source, 'utf8')).toBe('.\n')
    expect(readFileSync(commondir, 'utf8')).toBe('.\n')
    cleanupBwrapMountPoints({ force: true })
    expect(existsSync(commondir)).toBe(false)
  })

  it('claims a commondir already holding the placeholder, and binds the store', async () => {
    // What a killed process leaves: nothing in memory knows the file is a
    // mount point, but nothing else writes exactly those bytes there, so the
    // next wrap claims it and removes it. The bind comes off the store, not
    // off the file: another process wrapping a command in this repository
    // claims the same file, and its cleanup would leave this bind sourceless.
    const checkout = makeCheckout('repo')
    const commondir = join(checkout, '.git', 'commondir')
    writeFileSync(commondir, '.\n')

    const source = mountSource(await wrapIn(checkout), commondir)
    expect(source).not.toBe(commondir)
    expect(readFileSync(source, 'utf8')).toBe('.\n')

    cleanupBwrapMountPoints({ force: true })
    expect(existsSync(commondir)).toBe(false)
  })

  it('claims the config.worktree a killed wrap of its own left behind', async () => {
    // The wrapper's own leftover, not a hand-made one: an empty
    // config.worktree is a legitimate file nothing here may remove, so the
    // mount point is written with the mode bubblewrap gives its own and is
    // recognised by that shape alone once the process holding it is gone.
    const checkout = makeCheckout('repo')
    const configWorktree = join(checkout, '.git', 'config.worktree')
    const script = join(dir, 'killed-wrap.ts')
    writeFileSync(
      script,
      [
        `import { wrapCommandWithSandboxLinux } from ${JSON.stringify(LINUX_BACKEND_SOURCE)}`,
        `process.chdir(${JSON.stringify(checkout)})`,
        'await wrapCommandWithSandboxLinux({',
        "  command: 'true',",
        '  needsNetworkRestriction: false,',
        '  allowAllUnixSockets: true,',
        '  readConfig: undefined,',
        `  writeConfig: { allowOnly: [${JSON.stringify(checkout)}], denyWithinAllow: [] },`,
        '})',
        // No exit event, so nothing of that wrap's cleanup runs.
        "process.kill(process.pid, 'SIGKILL')",
      ].join('\n'),
    )

    const killed = spawnSync(process.execPath, [script], {
      encoding: 'utf8',
      timeout: 60000,
    })
    expect(`${killed.signal} ${killed.stderr}`).toBe('SIGKILL ')
    expect(readFileSync(configWorktree, 'utf8')).toBe('')

    await wrapIn(checkout)
    cleanupBwrapMountPoints({ force: true })
    expect(existsSync(configWorktree)).toBe(false)
  })

  it('leaves alone an empty config.worktree it did not leave there', async () => {
    // An empty config.worktree reads as no worktree config at all, so one is
    // legitimate and this wrapper never claims it — unless it has the shape
    // bubblewrap leaves, which nothing writing a config on purpose does.
    const checkout = makeCheckout('repo')
    const legitimate = join(checkout, '.git', 'config.worktree')
    writeFileSync(legitimate, '', { mode: 0o644 })

    expect(mountSource(await wrapIn(checkout), legitimate)).toBe(legitimate)

    cleanupBwrapMountPoints({ force: true })
    expect(existsSync(legitimate)).toBe(true)

    // The shape bubblewrap leaves, which nothing writing a config on
    // purpose has: read-only, empty, one link.
    chmodSync(legitimate, 0o444)
    await wrapIn(checkout)
    cleanupBwrapMountPoints({ force: true })
    expect(existsSync(legitimate)).toBe(false)
  })

  it('leaves a zero-byte commondir a host git is mid-write on', async () => {
    // git creates commondir and writes it as two steps, so an empty one with
    // write bits is a file another process owns right now — not the shape
    // bubblewrap leaves. The sandbox still gets a commondir it can read, off
    // the store, and the host's file is neither rewritten nor removed.
    const checkout = makeCheckout('repo')
    const commondir = join(checkout, '.git', 'commondir')
    writeFileSync(commondir, '', { mode: 0o644 })

    const source = mountSource(await wrapIn(checkout), commondir)
    expect(source).not.toBe(commondir)
    expect(source).not.toBe('/dev/null')
    expect(readFileSync(source, 'utf8')).toBe('.\n')
    expect(readFileSync(commondir, 'utf8')).toBe('')

    cleanupBwrapMountPoints({ force: true })
    expect(existsSync(commondir)).toBe(true)
    expect(readFileSync(commondir, 'utf8')).toBe('')
  })

  it.if(process.getuid?.() !== 0)(
    'denies a git directory whole when it takes no mount point',
    async () => {
      // A vendored checkout the wrapper cannot write: refusing every command
      // in the tree would be a brick a sandboxed command can plant with one
      // chmod, and a read-only bind of the directory needs nothing written to
      // the host, costs what was already unwritable, and closes that route.
      const checkout = makeCheckout('repo')
      const gitDir = join(checkout, '.git')
      chmodSync(gitDir, 0o555)
      try {
        const command = await wrapIn(checkout)

        expect(lastMountAt(command, gitDir)).toBe(
          `--ro-bind ${gitDir} ${gitDir}`,
        )
        expect(existsSync(join(gitDir, 'commondir'))).toBe(false)
        expect(existsSync(join(gitDir, 'config.worktree'))).toBe(false)
      } finally {
        chmodSync(gitDir, 0o755)
      }
    },
  )

  it('leaves no mount point behind when the wrap itself throws', async () => {
    // The files git reads back are written before bubblewrap is reached, and
    // the caller does not clean up after a wrap that threw.
    const checkout = makeCheckout('repo')
    const commondir = join(checkout, '.git', 'commondir')

    const refusal = await wrapIn(checkout, 'true', {
      denyWithinAllow: Array.from({ length: 4000 }, (_unused, n) =>
        join(checkout, `deny-${n}`),
      ),
    }).then(
      () => undefined,
      (err: unknown) => err,
    )

    expect(refusal).toBeInstanceOf(LinuxSandboxProfileError)
    expect((refusal as LinuxSandboxProfileError).code).toBe(
      'too_many_arguments',
    )
    expect(existsSync(commondir)).toBe(false)
  })

  it('leaves every other absent deny on /dev/null', async () => {
    const checkout = makeCheckout('repo')

    expect(mountSource(await wrapIn(checkout), join(checkout, '.bashrc'))).toBe(
      '/dev/null',
    )
  })

  it('mints one placeholder file for the process, not one per wrap', async () => {
    process.env.TMPDIR = dir
    const checkout = makeCheckout('repo')
    const commondir = join(checkout, '.git', 'commondir')
    const stores = new Set<string>()

    for (let wrap = 0; wrap < 20; wrap++) {
      const command = await wrapIn(checkout)
      stores.add(dirname(mountSource(command, commondir)))
      // Not forced: the store is per process, so a batch of wraps ending
      // must not empty it — and the mount point goes, so the next wrap
      // takes the absent-path branch again.
      cleanupBwrapMountPoints()
    }

    expect(stores.size).toBe(1)
    // One file per distinct placeholder, whatever the number of wraps: the
    // repository's absent commondir and its absent config.worktree.
    expect(readdirSync([...stores][0]!)).toHaveLength(2)
  })

  it('refuses the command when no placeholder can be written', async () => {
    // Decided once, logged once, and fail-closed: /dev/null is the only
    // deny left, and it costs the repository every git command. Refusing
    // says so; sandboxing behind it would not.
    const checkout = makeCheckout('repo')
    // So that no deny needs the shared empty directory, whose own source
    // this temp directory would break first.
    mkdirSync(join(checkout, '.claude'))
    const notADirectory = join(dir, 'not-a-directory')
    writeFileSync(notADirectory, '')
    process.env.TMPDIR = notADirectory

    const refusal = await wrapIn(checkout).then(
      () => undefined,
      (err: unknown) => err,
    )

    expect(refusal).toBeInstanceOf(LinuxSandboxProfileError)
    expect((refusal as LinuxSandboxProfileError).code).toBe(
      'deny_placeholder_unavailable',
    )
  })

  it.if(LIVE)(
    'keeps the placeholder out of the reach of the sandboxed command',
    async () => {
      // The store sits under $TMPDIR, which is routinely inside an allowed
      // write path; the bind exposes the source file itself, so a command
      // able to rewrite it would choose what git reads at the denied path.
      process.env.TMPDIR = dir
      const repo = gitRepo('repo')
      const commondir = join(repo, '.git', 'commondir')
      const source = mountSource(
        await wrapIn(repo, 'true', {
          allowOnly: [repo, dir],
        }),
        commondir,
      )
      cleanupBwrapMountPoints()

      const probe = [
        `echo ${BOOTED}`,
        `chmod 666 ${source} 2>&1 || echo CHMOD_REFUSED`,
        `echo poison > ${source} 2>&1 || echo WRITE_REFUSED`,
        `cat ${source}`,
        `git rev-parse --git-common-dir`,
      ].join('; ')
      const command = await wrapIn(repo, probe, { allowOnly: [repo, dir] })
      // Memoised by content, so the command names the source this wrap binds.
      expect(mountSource(command, commondir)).toBe(source)

      const run = spawnSync(command, {
        shell: true,
        encoding: 'utf8',
        timeout: 30000,
        cwd: repo,
        env: { ...process.env, LC_ALL: 'C' },
      })
      const output = `${run.stdout}${run.stderr}`

      expect(output).toContain(BOOTED)
      expect(output).toContain('Read-only file system')
      expect(output).toContain('CHMOD_REFUSED')
      expect(output).toContain('WRITE_REFUSED')
      expect(output).not.toContain('poison')
      // git still resolves its own git directory as its common directory.
      expect(output).toContain(join(repo, '.git'))
    },
  )

  it.if(LIVE)(
    "keeps the host's git working while a wrapped command runs",
    async () => {
      const sub = gitRepo('sub')
      const repo = gitRepo('repo')
      expect(
        git(repo, [
          '-c',
          'protocol.file.allow=always',
          ...IDENT,
          'submodule',
          'add',
          '-q',
          sub,
          'lib',
        ]),
      ).toMatchObject({ status: 0 })
      expect(git(repo, [...IDENT, 'commit', '-q', '-m', 'lib'])).toMatchObject({
        status: 0,
      })
      expect(
        git(repo, ['worktree', 'add', '-q', join(dir, 'wt')]),
      ).toMatchObject({ status: 0 })
      const commondir = join(repo, '.git', 'commondir')
      const submoduleCommondir = join(
        repo,
        '.git',
        'modules',
        'lib',
        'commondir',
      )

      // Runs until the host releases it, so the host's git is exercised with
      // the sandbox up and the mount points in place.
      const command = await wrapIn(
        repo,
        `echo ${BOOTED} > up; i=0; while [ ! -f release ] && [ $i -lt 200 ]; do sleep 0.1; i=$((i+1)); done; echo ${BOOTED}`,
      )
      const child = spawn(command, {
        shell: true,
        cwd: repo,
        stdio: 'ignore',
      })
      try {
        await waitFor(
          () => existsSync(join(repo, 'up')),
          'the sandbox to start',
        )

        // Both mount points are on the host, holding a redirect git accepts.
        expect(readFileSync(commondir, 'utf8')).toBe('.\n')
        expect(readFileSync(submoduleCommondir, 'utf8')).toBe('.\n')
        for (const args of [
          ['status', '--porcelain'],
          ['log', '--oneline'],
          ['worktree', 'list'],
          ['rev-parse', '--git-common-dir'],
        ]) {
          expect({ args, ...git(repo, args) }).toMatchObject({ status: 0 })
        }
        expect(
          git(repo, [
            ...IDENT,
            'commit',
            '--allow-empty',
            '-q',
            '-m',
            'during',
          ]),
        ).toMatchObject({ status: 0 })
        expect(git(join(repo, 'lib'), ['status', '--porcelain'])).toMatchObject(
          {
            status: 0,
          },
        )
      } finally {
        writeFileSync(join(repo, 'release'), '')
        await new Promise(resolve => child.on('close', resolve))
      }
      expect(child.exitCode).toBe(0)

      cleanupBwrapMountPoints()
      expect(existsSync(commondir)).toBe(false)
      expect(existsSync(submoduleCommondir)).toBe(false)
      expect(git(repo, ['status', '--porcelain'])).toMatchObject({ status: 0 })
    },
  )

  it.if(LIVE)(
    'leaves a killed wrap behind a commondir git reads, and repairs an empty one',
    async () => {
      const repo = gitRepo('repo')
      const commondir = join(repo, '.git', 'commondir')

      // What a killed process leaves now: the host's git works on it, and
      // the next wrap takes it away.
      writeFileSync(commondir, '.\n')
      expect(git(repo, ['status', '--porcelain'])).toMatchObject({ status: 0 })
      expect(git(repo, ['log', '--oneline'])).toMatchObject({ status: 0 })
      await wrapIn(repo)
      cleanupBwrapMountPoints()
      expect(existsSync(commondir)).toBe(false)

      // What an older release leaves: git refuses every command in the
      // repository until the next wrap rewrites it.
      writeFileSync(commondir, '', { mode: 0o444 })
      const broken = git(repo, ['status', '--porcelain'])
      expect(broken.status).not.toBe(0)
      expect(broken.stdout).toContain('commondir')

      await wrapIn(repo)
      expect(readFileSync(commondir, 'utf8')).toBe('.\n')
      expect(git(repo, ['status', '--porcelain'])).toMatchObject({ status: 0 })
      cleanupBwrapMountPoints()
      expect(existsSync(commondir)).toBe(false)
      expect(git(repo, ['status', '--porcelain'])).toMatchObject({ status: 0 })
    },
  )

  it.if(LIVE)(
    'leaves git working across wraps, and the commondir unwritable',
    async () => {
      const repo = gitRepo('repo')

      const run = (command: string) =>
        spawnSync(command, {
          shell: true,
          encoding: 'utf8',
          timeout: 30000,
          cwd: repo,
          env: { ...process.env, LC_ALL: 'C' },
        })
      // By name: the dotfile denies stub their absent paths, and the mount
      // points bwrap leaves for them are not files `git add -A` can stage.
      const commit = (file: string) =>
        `echo ${BOOTED} && git add ${file} && git ${IDENT.join(' ')} ` +
        `commit -q -m ${file} && echo COMMIT_OK`

      writeFileSync(join(repo, 'one.js'), 'console.log(1)\n')
      const first = run(await wrapIn(repo, commit('one.js')))
      expect(first.stdout).toContain(BOOTED)
      expect(first.status).toBe(0)
      expect(first.stdout).toContain('COMMIT_OK')

      // No cleanupBwrapMountPoints() in between: the first wrap's mount point
      // for the absent commondir is still sitting in the git directory, and
      // the second wrap's scan finds it there.
      writeFileSync(join(repo, 'two.js'), 'console.log(2)\n')
      const second = run(await wrapIn(repo, commit('two.js')))
      expect(second.stdout).toContain(BOOTED)
      expect(second.status).toBe(0)
      expect(second.stdout).toContain('COMMIT_OK')

      const write = run(
        await wrapIn(repo, 'echo ../decoy > .git/commondir || echo DENIED'),
      )
      expect(write.stdout).toContain('DENIED')
      expect(existsSync(join(repo, '.git', 'commondir'))).toBe(true)
      cleanupBwrapMountPoints({ force: true })
      expect(existsSync(join(repo, '.git', 'commondir'))).toBe(false)
    },
  )
})
