import { describe, it, expect, afterAll, beforeAll } from 'bun:test'
import { spawnSync } from 'node:child_process'
import { mkdirSync, realpathSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { wrapCommandWithSandboxMacOS } from '../../src/sandbox/macos-sandbox-utils.js'
import { isMacOS, isWindows } from '../helpers/platform.js'

/**
 * A path the library computed is a name on disk, not a pattern: the
 * mandatory write denies are joined onto the cwd, and a cwd may contain
 * `[`, `*` or `?`. Compiled as a glob, `a[b/c]d` turns into a
 * one-character class and the filter stops matching the directory it was
 * built from, so the deny covers nothing. The `**\/.git/hooks/**` pattern
 * does not make up for it: it covers what is inside the directory, never
 * the directory vnode, which is what `mv` and `ln -s` operate on.
 *
 * The profile tests only inspect generated SBPL and run on every POSIX
 * host; the enforcement tests run the profile under sandbox-exec.
 */

/** `<root>/a[b/c]d` — brackets a glob would read as one character class. */
const BRACKET_SEGMENTS = ['a[b', 'c]d'] as const

interface BracketTree {
  /** Bracket-free write root, so only the deny is under test. */
  root: string
  /** The bracketed working directory. */
  work: string
  /** `<work>/.git/hooks`, the mandatory deny under test. */
  hooks: string
}

function bracketTree(prefix: string): BracketTree {
  const root = join(realpathSync(tmpdir()), `${prefix}-${Date.now()}`)
  const work = join(root, ...BRACKET_SEGMENTS)
  const hooks = join(work, '.git', 'hooks')
  mkdirSync(hooks, { recursive: true })
  return { root, work, hooks }
}

function wrap(tree: BracketTree, command: string): string {
  return wrapCommandWithSandboxMacOS({
    command,
    needsNetworkRestriction: false,
    readConfig: undefined,
    writeConfig: { allowOnly: [tree.root], denyWithinAllow: [] },
  })
}

describe.if(!isWindows)(
  'macOS profile: mandatory denies under a bracketed cwd',
  () => {
    let tree: BracketTree
    let originalCwd: string

    beforeAll(() => {
      originalCwd = process.cwd()
      tree = bracketTree('bracket-deny-profile')
      process.chdir(tree.work)
    })

    afterAll(() => {
      process.chdir(originalCwd)
      rmSync(tree.root, { recursive: true, force: true })
    })

    it('denies the git hooks directory by subpath, not by regex', () => {
      const profile = wrap(tree, 'true')
      expect(profile).toContain(`(subpath ${JSON.stringify(tree.hooks)})`)
      expect(profile).not.toContain(`(regex "^${tree.hooks}`)
    })

    it('keeps the cwd literal in the subtree patterns', () => {
      const profile = wrap(tree, 'true')
      // `**\/.git/hooks/**` is anchored at the cwd, so only the tail is a
      // pattern; the cwd itself is escaped into the regex.
      const anchor = tree.work.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
      const expected = `^${anchor}/(.*/)?\\.git/hooks/.*(/.*)?$`
      expect(profile).toContain(`(regex ${JSON.stringify(expected)})`)
    })

    it('denies every cwd-joined dangerous path by subpath', () => {
      const profile = wrap(tree, 'true')
      for (const name of ['.gitconfig', '.zshrc', '.vscode', '.git/config']) {
        expect(profile).toContain(
          `(subpath ${JSON.stringify(join(tree.work, name))})`,
        )
      }
    })

    it('still compiles a bracket pattern the caller wrote as a regex', () => {
      const profile = wrapCommandWithSandboxMacOS({
        command: 'true',
        needsNetworkRestriction: false,
        readConfig: { denyOnly: ['/srv/[ab]/secrets'] },
        writeConfig: undefined,
      })
      expect(profile).toContain('(regex "^/srv/[ab]/secrets(/.*)?$")')
      expect(profile).not.toContain('(subpath "/srv/[ab]/secrets")')
    })
  },
)

describe.if(isMacOS)(
  'macOS sandbox: a bracketed cwd keeps its git hooks directory',
  () => {
    let tree: BracketTree
    let originalCwd: string

    beforeAll(() => {
      originalCwd = process.cwd()
      tree = bracketTree('bracket-deny-exec')
      writeFileSync(join(tree.hooks, 'pre-commit'), '#!/bin/sh\n')
      process.chdir(tree.work)
    })

    afterAll(() => {
      process.chdir(originalCwd)
      rmSync(tree.root, { recursive: true, force: true })
    })

    function run(command: string): { status: number | null; stderr: string } {
      const result = spawnSync(wrap(tree, command), {
        shell: true,
        encoding: 'utf8',
        timeout: 10000,
      })
      return { status: result.status, stderr: result.stderr || '' }
    }

    it('allows writes elsewhere under the write root (sanity check)', () => {
      const result = run(`echo ok > ${JSON.stringify(join(tree.work, 'file'))}`)
      expect(result.status).toBe(0)
    })

    it('refuses to move the hooks directory out of the way', () => {
      const moved = join(tree.work, '.git', 'hooks-moved')
      const result = run(
        `mv ${JSON.stringify(tree.hooks)} ${JSON.stringify(moved)}`,
      )
      expect(result.status).not.toBe(0)
      expect(result.stderr.toLowerCase()).toContain('operation not permitted')
    })
  },
)
