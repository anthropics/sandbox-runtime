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
  rmdirSync,
  rmSync,
  writeFileSync,
  readFileSync,
  symlinkSync,
  existsSync,
  statSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { getPlatform } from '../../src/utils/platform.js'
import {
  wrapCommandWithSandboxMacOS,
  macGetMandatoryDenyEntries,
} from '../../src/sandbox/macos-sandbox-utils.js'
import {
  wrapCommandWithSandboxLinux,
  cleanupBwrapMountPoints,
  unreadableDirectories,
  type LinuxSandboxParams,
} from '../../src/sandbox/linux-sandbox-utils.js'
import {
  DANGEROUS_FILES,
  getDangerousDirectories,
} from '../../src/sandbox/sandbox-utils.js'
import { isLinux, isSupportedPlatform } from '../helpers/platform.js'

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
    const ORIGINAL_CONTENT = 'ORIGINAL'
    const MODIFIED_CONTENT = 'MODIFIED'
    /** Written into every directory getDangerousDirectories() names. */
    const DIRECTORY_PROBE_FILE = 'probe.txt'
    let originalCwd: string

    beforeAll(() => {
      originalCwd = process.cwd()
      mkdirSync(TEST_DIR, { recursive: true })

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

      // Create safe file within .claude that SHOULD be writable (not commands/agents)
      writeFileSync(
        join(TEST_DIR, '.claude', 'some-other-file.txt'),
        ORIGINAL_CONTENT,
      )
    })

    afterAll(() => {
      process.chdir(originalCwd)
      rmSync(TEST_DIR, { recursive: true, force: true })
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

    function runSandboxedWrite(
      filePath: string,
      content: string,
    ): Promise<{ success: boolean; stderr: string }> {
      return runSandboxed(`echo '${content}' > '${filePath}'`)
    }

    async function runSandboxed(
      command: string,
      ripgrepArgs: string[] = [],
    ): Promise<{ success: boolean; stderr: string }> {
      const platform = getPlatform()

      // Allow writes to current directory, but mandatory denies should still block dangerous files
      const writeConfig = {
        allowOnly: ['.'],
        denyWithinAllow: [], // Empty - relying on mandatory denies
      }

      let wrappedCommand: string
      if (platform === 'macos') {
        wrappedCommand = wrapCommandWithSandboxMacOS({
          command,
          needsNetworkRestriction: false,
          readConfig: undefined,
          writeConfig,
        })
      } else {
        wrappedCommand = await wrapCommandWithSandboxLinux({
          command,
          needsNetworkRestriction: false,
          readConfig: undefined,
          writeConfig,
          ripgrepConfig: { command: 'rg', args: ripgrepArgs },
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
                  threads,
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
        'takes what ripgrep says it could not read for a hint only',
        async () => {
          const project = join(TEST_DIR, 'hints')
          const outside = join(TEST_DIR, 'hints-outside')
          for (const directory of [
            join(project, 'is-readable'),
            join(project, 'really-locked'),
            join(project, 'locked: too'),
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

            expect(unreadableDirectories(said.join('\n'), project, 3)).toEqual([
              join(project, 'really-locked'),
              join(project, 'locked: too'),
              join(project, 'listed-only'),
              join(project, 'one-thread'),
              join(project, 'no-prefix'),
            ])
            // Nobody else's mode can be given back from inside.
            const uid = process.getuid!()
            const getuid = spyOn(process, 'getuid').mockReturnValue(uid + 1)
            try {
              expect(
                unreadableDirectories(said.join('\n'), project, 3),
              ).toEqual([])
            } finally {
              getuid.mockRestore()
            }
            expect(wrapped).toContain('really-locked')
            expect(readFileSync(asked, 'utf8').split('\n')).toEqual(
              expect.arrayContaining([
                '--no-ignore',
                '--no-config',
                '--line-buffered',
              ]),
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

        // The caller runs no cleanup for a wrap that threw, so a removal
        // deferred to that wrap has nobody else to run it.

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
              spawnSync(await wrapInCwd('true'), {
                shell: true,
                timeout: 10000,
              })
              expect(readdirSync(raceDir)).toContain('.bashrc')

              // B is still looking for the mandatory denies when A's caller
              // cleans up.
              const controller = new AbortController()
              const wrappedB = wrapInCwd('true', {
                abortSignal: controller.signal,
                binShell: how === 'refused' ? 'no-such-shell' : undefined,
              })
              cleanupBwrapMountPoints()
              expect(readdirSync(raceDir)).toContain('.bashrc')

              if (how === 'aborted') controller.abort(new Error('stopped'))
              expect(await wrappedB.catch((e: unknown) => e)).toBeInstanceOf(
                Error,
              )
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
            spawnSync(await wrapInCwd('true'), { shell: true, timeout: 10000 })
            cleanupBwrapMountPoints()
            expect(readdirSync('.claude')).not.toEqual([])

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

            // linuxGetMandatoryDenyPaths adds .git/hooks to deny list.
            // .git exists as a file, so .git/hooks doesn't exist.
            // The code will try to mount /dev/null at .git/hooks, but bwrap
            // can't create a mount point there because .git is a file.
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
