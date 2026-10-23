import { describe, it, expect, afterAll, beforeAll } from 'bun:test'
import { spawnSync } from 'node:child_process'
import {
  mkdirSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { wrapCommandWithSandboxMacOS } from '../../src/sandbox/macos-sandbox-utils.js'
import { isMacOS } from '../helpers/platform.js'

/**
 * A `gitdir:` pointer whose value goes through a symlink, run under
 * sandbox-exec.
 *
 * Seatbelt compares its filters against the path an operation RESOLVED to,
 * while the path in the filter is compared as a string, so the pointer's own
 * spelling of the git directory — `<checkout>/linkdir/gd/hooks` — matches
 * nothing at all, and the deny that blocks a write to the hooks git will
 * actually run has to name where the link lands. The link's own name still
 * needs its own spelling, for the unlink that would point the chain
 * somewhere else. The generator emits both; these run them.
 *
 * The profile-level counterparts are in mandatory-deny-paths.test.ts and run
 * on every POSIX host.
 */

interface ChainTree {
  /** Write root, so only the denies are under test. */
  root: string
  /** The checkout, and the working directory. */
  checkout: string
  /** `<checkout>/linkdir` -> `<root>/real`. */
  link: string
  /** `<root>/real/gd`, where the pointer really lands. */
  gitDir: string
}

function chainTree(): ChainTree {
  const root = join(realpathSync(tmpdir()), `git-chain-landing-${Date.now()}`)
  const checkout = join(root, 'checkout')
  const gitDir = join(root, 'real', 'gd')
  mkdirSync(join(gitDir, 'hooks'), { recursive: true })
  mkdirSync(checkout, { recursive: true })
  writeFileSync(join(gitDir, 'HEAD'), 'ref: refs/heads/main\n')
  writeFileSync(join(checkout, '.git'), 'gitdir: linkdir/gd\n')
  const link = join(checkout, 'linkdir')
  symlinkSync(join(root, 'real'), link)
  return { root, checkout, link, gitDir }
}

describe.if(isMacOS)(
  'macOS sandbox: a pointer whose value walks through a symlink',
  () => {
    let tree: ChainTree
    let originalCwd: string

    beforeAll(() => {
      originalCwd = process.cwd()
      tree = chainTree()
      process.chdir(tree.checkout)
    })

    afterAll(() => {
      process.chdir(originalCwd)
      rmSync(tree.root, { recursive: true, force: true })
    })

    function run(command: string): { status: number | null; stderr: string } {
      const result = spawnSync(
        wrapCommandWithSandboxMacOS({
          command,
          needsNetworkRestriction: false,
          readConfig: undefined,
          writeConfig: { allowOnly: [tree.root], denyWithinAllow: [] },
        }),
        {
          shell: true,
          encoding: 'utf8',
          timeout: 10000,
          // Assert on the message, so pin the language it is written in.
          env: { ...process.env, LC_ALL: 'C' },
        },
      )
      return { status: result.status, stderr: result.stderr || '' }
    }

    function expectRefused(command: string): void {
      const result = run(command)
      expect(result.status).not.toBe(0)
      expect(result.stderr.toLowerCase()).toContain('operation not permitted')
    }

    it('allows an ordinary write in the checkout (sanity check)', () => {
      const result = run(
        `echo ok > ${JSON.stringify(join(tree.checkout, 'file.txt'))}`,
      )
      expect(result.status).toBe(0)
    })

    it('refuses a hook written through the spelling the pointer uses', () => {
      expectRefused(
        `echo x > ${JSON.stringify(join(tree.link, 'gd', 'hooks', 'pre-commit'))}`,
      )
    })

    it('refuses the same hook written at the landing', () => {
      expectRefused(
        `echo x > ${JSON.stringify(join(tree.gitDir, 'hooks', 'pre-commit'))}`,
      )
    })

    it('refuses a commondir created at the landing', () => {
      // Not there at all, which is the point: the file git reads to move the
      // hooks and config it runs elsewhere is denied so it cannot be made.
      expectRefused(
        `echo . > ${JSON.stringify(join(tree.gitDir, 'commondir'))}`,
      )
    })

    it('refuses to unlink the link the pointer walks through', () => {
      expectRefused(`rm ${JSON.stringify(tree.link)}`)
    })

    it('refuses to rename the link aside', () => {
      expectRefused(
        `mv ${JSON.stringify(tree.link)} ${JSON.stringify(join(tree.checkout, 'moved'))}`,
      )
    })
  },
)
