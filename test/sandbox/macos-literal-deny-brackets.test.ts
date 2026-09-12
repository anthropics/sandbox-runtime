import { describe, it, expect, afterAll, beforeAll } from 'bun:test'
import { spawnSync } from 'node:child_process'
import { mkdirSync, realpathSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { wrapCommandWithSandboxMacOS } from '../../src/sandbox/macos-sandbox-utils.js'
import {
  MaskedFileStore,
  buildMaskedFileBinds,
} from '../../src/sandbox/credential-mask-files.js'
import { SentinelRegistry } from '../../src/sandbox/credential-sentinel.js'
import { isMacOS, isWindows } from '../helpers/platform.js'

/**
 * A path the library computed is a name on disk, not a pattern: the
 * mandatory write denies are joined onto the cwd, a caller's relative
 * spelling is resolved against it, and a cwd may contain `[`, `*` or `?`.
 * Compiled as a glob, `a[b/c]d` turns into a one-character class and the
 * filter stops matching the directory it was built from, so the deny
 * covers nothing. The `**\/.git/hooks/**` pattern does not make up for
 * it: it covers what is inside the directory, never the directory vnode,
 * which is what `mv` and `ln -s` operate on.
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

/**
 * The filter `literalPath` compiles to when its `[`, `*` or `?` are read
 * as glob syntax — spelled the way the generator spells it, with the
 * regex metacharacters that are not glob syntax escaped. `tail` is
 * `(/.*)?$` for a deny (which extends over the subtree) and `$` for an
 * allow. This is the text these rules must NOT contain.
 */
function sniffedFilter(literalPath: string, tail: string): string {
  const escaped = literalPath.replace(/[.^$+{}()|\\]/g, '\\$&')
  return `(regex ${JSON.stringify(`^${escaped}${tail}`)})`
}

/** Every `(regex "…")` filter the profile emits. */
function emittedRegexes(profile: string): string[] {
  return [...profile.matchAll(/\(regex ("[^"]*")\)/g)].map(
    match => JSON.parse(match[1]!) as string,
  )
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
      expect(profile).not.toContain(sniffedFilter(tree.hooks, '(/.*)?$'))
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

/**
 * A caller's relative or `~` spelling is resolved against a directory the
 * library picked, which splices that directory's own name into the path.
 * Read back as glob syntax, the caller's own deny stops matching the file
 * it named and its write root stops covering the project.
 */
describe.if(!isWindows)(
  'macOS profile: caller spellings resolved under a bracketed cwd',
  () => {
    let tree: BracketTree
    let secrets: string
    let originalCwd: string

    beforeAll(() => {
      originalCwd = process.cwd()
      tree = bracketTree('bracket-relative-profile')
      secrets = join(tree.work, 'secrets')
      mkdirSync(secrets, { recursive: true })
      process.chdir(tree.work)
    })

    afterAll(() => {
      process.chdir(originalCwd)
      rmSync(tree.root, { recursive: true, force: true })
    })

    function wrapRelative(): string {
      return wrapCommandWithSandboxMacOS({
        command: 'true',
        needsNetworkRestriction: false,
        readConfig: { denyOnly: ['./secrets'], allowWithinDeny: [] },
        writeConfig: { allowOnly: ['.'], denyWithinAllow: ['secrets'] },
      })
    }

    it('denies a relative read-deny by subpath', () => {
      const profile = wrapRelative()
      expect(profile).toContain(`(subpath ${JSON.stringify(secrets)})`)
      expect(profile).not.toContain(sniffedFilter(secrets, '(/.*)?$'))
    })

    it('denies a relative write-deny by subpath', () => {
      const profile = wrapRelative()
      const writeSection = profile.slice(profile.indexOf('; File write'))
      expect(writeSection).toContain(`(subpath ${JSON.stringify(secrets)})`)
      expect(writeSection).not.toContain(sniffedFilter(secrets, '(/.*)?$'))
    })

    it('makes the working directory itself the write root', () => {
      const profile = wrapRelative()
      expect(profile).toContain(`(subpath ${JSON.stringify(tree.work)})`)
      expect(profile).not.toContain(sniffedFilter(tree.work, '$'))
    })
  },
)

/**
 * A `*` in the cwd goes the other way: compiled as a glob it matches
 * sibling directories the deny was never meant to reach.
 */
describe.if(!isWindows)(
  'macOS profile: a cwd whose name contains a star',
  () => {
    let root: string
    let work: string
    let originalCwd: string

    beforeAll(() => {
      originalCwd = process.cwd()
      root = join(realpathSync(tmpdir()), `star-deny-profile-${Date.now()}`)
      work = join(root, 's*t')
      mkdirSync(work, { recursive: true })
      mkdirSync(join(root, 'sZZt'), { recursive: true })
      process.chdir(work)
    })

    afterAll(() => {
      process.chdir(originalCwd)
      rmSync(root, { recursive: true, force: true })
    })

    it('denies the cwd-joined path by subpath and spares the sibling', () => {
      const profile = wrapCommandWithSandboxMacOS({
        command: 'true',
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig: { allowOnly: [root], denyWithinAllow: [] },
      })
      expect(profile).toContain(
        `(subpath ${JSON.stringify(join(work, '.zshrc'))})`,
      )
      const sibling = join(root, 'sZZt', '.zshrc')
      for (const regex of emittedRegexes(profile)) {
        expect(new RegExp(regex).test(sibling)).toBe(false)
      }
    })
  },
)

/**
 * A masked credential file is a file the library opened, on both routes:
 * the bind list, and the degrade-to-deny list an entry lands on when its
 * extract pattern stops matching under `onExtractNoMatch: "deny"`.
 */
describe.if(!isWindows)(
  'macOS profile: a masked credential file under a bracketed directory',
  () => {
    let tree: BracketTree
    let credential: string

    beforeAll(() => {
      tree = bracketTree('bracket-credential-profile')
      credential = join(tree.work, 'hosts.yml')
      writeFileSync(credential, 'oauth_token: gho_notarealtoken_0123456789\n')
    })

    afterAll(() => {
      rmSync(tree.root, { recursive: true, force: true })
    })

    function wrapMasked(params: {
      maskedFileBinds?: Array<{ realPath: string; fakePath: string }>
      degradeToDenyPaths?: readonly string[]
    }): string {
      return wrapCommandWithSandboxMacOS({
        command: 'true',
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig: { allowOnly: [tree.root], denyWithinAllow: [] },
        ...params,
      })
    }

    it('denies a masked path by subpath', () => {
      const store = new MaskedFileStore()
      const { binds } = buildMaskedFileBinds(
        [{ path: credential, mode: 'mask' }],
        [],
        new SentinelRegistry(),
        store,
      )
      expect(binds).toHaveLength(1)
      const profile = wrapMasked({ maskedFileBinds: binds })
      expect(profile).toContain(`(subpath ${JSON.stringify(credential)})`)
      expect(profile).not.toContain(sniffedFilter(credential, '(/.*)?$'))
      store.dispose()
    })

    it('denies a path that degraded to deny by subpath', () => {
      const store = new MaskedFileStore()
      const { binds, degradeToDenyPaths } = buildMaskedFileBinds(
        [
          {
            path: credential,
            mode: 'mask',
            extract: 'will_not_match_(\\S+)',
            onExtractNoMatch: 'deny',
          },
        ],
        [],
        new SentinelRegistry(),
        store,
      )
      expect(binds).toHaveLength(0)
      expect(degradeToDenyPaths).toEqual([credential])
      const profile = wrapMasked({ degradeToDenyPaths })
      expect(profile).toContain(`(subpath ${JSON.stringify(credential)})`)
      expect(profile).not.toContain(sniffedFilter(credential, '(/.*)?$'))
      store.dispose()
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
        // Assert on the message, so pin the language it is written in.
        env: { ...process.env, LC_ALL: 'C' },
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

describe.if(isMacOS)(
  'macOS sandbox: a bracketed working directory as the write root',
  () => {
    let tree: BracketTree
    let originalCwd: string

    beforeAll(() => {
      originalCwd = process.cwd()
      tree = bracketTree('bracket-relative-exec')
      mkdirSync(join(tree.work, 'secrets'), { recursive: true })
      process.chdir(tree.work)
    })

    afterAll(() => {
      process.chdir(originalCwd)
      rmSync(tree.root, { recursive: true, force: true })
    })

    function run(command: string, allowOnly: string[]): number | null {
      return spawnSync(
        wrapCommandWithSandboxMacOS({
          command,
          needsNetworkRestriction: false,
          readConfig: undefined,
          writeConfig: { allowOnly, denyWithinAllow: ['secrets'] },
        }),
        {
          shell: true,
          encoding: 'utf8',
          timeout: 10000,
          env: { ...process.env, LC_ALL: 'C' },
        },
      ).status
    }

    it('writes into the project directory the caller allowed', () => {
      expect(
        run(`echo ok > ${JSON.stringify(join(tree.work, 'file'))}`, ['.']),
      ).toBe(0)
    })

    it('refuses to write inside the directory the caller denied', () => {
      // Write root without brackets, so the deny is the only thing that
      // can refuse this write.
      const key = join(tree.work, 'secrets', 'key')
      expect(run(`echo x > ${JSON.stringify(key)}`, [tree.root])).not.toBe(0)
    })
  },
)
