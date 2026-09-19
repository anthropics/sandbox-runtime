import { describe, it, expect, afterAll, beforeAll } from 'bun:test'
import { spawnSync } from 'node:child_process'
import {
  chmodSync,
  mkdirSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { wrapCommandWithSandboxMacOS } from '../../src/sandbox/macos-sandbox-utils.js'
import {
  MaskedFileStore,
  buildMaskedFileBinds,
} from '../../src/sandbox/credential-mask-files.js'
import { SentinelRegistry } from '../../src/sandbox/credential-sentinel.js'
import {
  denyGlobRegex,
  normalizePathForSandbox,
} from '../../src/sandbox/sandbox-utils.js'
import { isMacOS, isWindows } from '../helpers/platform.js'

/**
 * A path the library computed is a name on disk, not a pattern: the
 * mandatory write denies are joined onto the cwd, a caller's relative
 * spelling is resolved against it, and a cwd may contain `[`, `*` or `?`.
 * Compiled as a glob, `a[b/c]d` turns into a one-character class and the
 * filter stops matching the directory it was built from, so the deny
 * covers nothing. The `**\/.git/hooks` pattern does not make up for it:
 * it hangs off the same cwd, so the same bracket pair takes it out too.
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
      // `**\/.git/hooks` is anchored at the cwd, so only the tail is a
      // pattern; the cwd itself is escaped into the regex.
      const anchor = tree.work.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
      const expected = `^${anchor}/(.*/)?\\.git/hooks(/.*)?$`
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
      openModulesTree(tree)
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

/**
 * `<work>/.git` as a directory, with a submodule git directory and a
 * directory the `.git/modules` walk stops at, each named across a bracket
 * pair the way a submodule name can be: a submodule's name is its path, so
 * `a[b/c]d` is an ordinary one, and it is the sandboxed command that chooses
 * it.
 */
interface ModulesTree {
  /** Bracket-free write root, so only the denies are under test. */
  root: string
  /** The bracketed working directory. */
  work: string
  /** `<work>/.git/modules/s[m/o]d`, a submodule git directory. */
  submodule: string
  /** `<work>/.git/modules/u[n/r]d`, where the walk stops. */
  unreadable: string
}

function modulesTree(prefix: string): ModulesTree {
  const root = join(realpathSync(tmpdir()), `${prefix}-${Date.now()}`)
  const work = join(root, ...BRACKET_SEGMENTS)
  const modules = join(work, '.git', 'modules')
  const submodule = join(modules, 's[m', 'o]d')
  const unreadable = join(modules, 'u[n', 'r]d')
  mkdirSync(join(submodule, 'hooks'), { recursive: true })
  mkdirSync(join(submodule, 'objects'), { recursive: true })
  writeFileSync(join(submodule, 'HEAD'), 'ref: refs/heads/main\n')
  writeFileSync(join(work, '.git', 'HEAD'), 'ref: refs/heads/main\n')
  mkdirSync(unreadable, { recursive: true })
  // A directory the walk cannot list, which is denied whole rather than left
  // writable with a git directory possibly inside. Restored by
  // `openModulesTree` before the tree is removed - and before a sandboxed
  // write into it is what has to be refused.
  chmodSync(unreadable, 0o000)
  return { root, work, submodule, unreadable }
}

/** A walk cannot be kept out of a directory it owns as root, so the record
 *  the two cases below are about is not there for one. */
const CAN_LOCK_A_DIRECTORY = process.getuid?.() !== 0

/** Gives `tree.unreadable` its permissions back, so that what refuses a write
 *  into it is the sandbox and not the mode, and so that it can be removed. */
function openModulesTree(tree: ModulesTree): void {
  chmodSync(tree.unreadable, 0o755)
}

/**
 * `<work>/.git` as a pointer file, naming a git directory whose `commondir`
 * names another. Every directory here is one the file's own contents chose.
 */
interface PointerTree {
  root: string
  work: string
  /** The `.git` pointer file in the cwd. */
  pointer: string
  /** `<root>/g[h/i]j`, the git directory the pointer names. */
  gitDir: string
  /** `<root>/c[o/m]n`, the git directory its `commondir` names. */
  commonDir: string
}

function pointerTree(prefix: string): PointerTree {
  const root = join(realpathSync(tmpdir()), `${prefix}-${Date.now()}`)
  const work = join(root, ...BRACKET_SEGMENTS)
  const gitDir = join(root, 'g[h', 'i]j')
  const commonDir = join(root, 'c[o', 'm]n')
  mkdirSync(work, { recursive: true })
  mkdirSync(gitDir, { recursive: true })
  mkdirSync(commonDir, { recursive: true })
  writeFileSync(join(gitDir, 'HEAD'), 'ref: refs/heads/main\n')
  writeFileSync(join(commonDir, 'HEAD'), 'ref: refs/heads/main\n')
  writeFileSync(join(gitDir, 'commondir'), `${commonDir}\n`)
  const pointer = join(work, '.git')
  writeFileSync(pointer, `gitdir: ${gitDir}\n`)
  return { root, work, pointer, gitDir, commonDir }
}

/** The four paths inside a git directory the mandatory denies name. */
const GIT_DIR_LEAVES = ['hooks', 'commondir', 'config', 'config.worktree']

/**
 * The git directories the macOS denies cover are read off the filesystem,
 * and what they are called is up to the sandboxed command. Compiled as a
 * glob, `[m/o]` is a one-character class, so a deny built from
 * `.git/modules/s[m/o]d` matches neither that directory nor anything else —
 * and a `.gitmodules` naming that submodule makes the host's next
 * `git submodule update --init` run whatever hook was planted in it.
 */
describe.if(!isWindows)(
  'macOS profile: git directories read off disk under a bracketed cwd',
  () => {
    let tree: ModulesTree
    let originalCwd: string

    beforeAll(() => {
      originalCwd = process.cwd()
      tree = modulesTree('bracket-modules-profile')
      process.chdir(tree.work)
    })

    afterAll(() => {
      process.chdir(originalCwd)
      openModulesTree(tree)
      rmSync(tree.root, { recursive: true, force: true })
    })

    function profile(): string {
      return wrapCommandWithSandboxMacOS({
        command: 'true',
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig: { allowOnly: [tree.root], denyWithinAllow: [] },
      })
    }

    it('denies a submodule git directory by subpath', () => {
      const text = profile()
      for (const leaf of GIT_DIR_LEAVES) {
        const denied = join(tree.submodule, leaf)
        expect(text).toContain(`(subpath ${JSON.stringify(denied)})`)
        expect(text).not.toContain(sniffedFilter(denied, '(/.*)?$'))
      }
    })

    it.if(CAN_LOCK_A_DIRECTORY)(
      'denies the directory the walk could not list by subpath',
      () => {
        const text = profile()
        expect(text).toContain(`(subpath ${JSON.stringify(tree.unreadable)})`)
        expect(text).not.toContain(sniffedFilter(tree.unreadable, '(/.*)?$'))
      },
    )

    it('leaves no regex carrying a bracket read off the filesystem', () => {
      // A spelling sniffed as a pattern keeps its brackets verbatim, since
      // they are the glob syntax it is taken to be asking for. An anchored
      // pattern escapes the part of it the library built.
      const regexes = emittedRegexes(profile())
      expect(regexes.length).toBeGreaterThan(0)
      for (const regex of regexes) {
        for (const opening of ['s[m/', 'u[n/', 'a[b/']) {
          expect(regex).not.toContain(opening)
        }
      }
    })

    it('anchors the nested-repository patterns at the escaped cwd', () => {
      const anchor = tree.work.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
      const text = profile()
      // A nested repository, and a nested repository's submodule, have no
      // path on disk to enumerate: they are matched by pattern, hung off the
      // cwd, which is escaped into the regex like any other literal.
      expect(text).toContain(
        `(regex ${JSON.stringify(`^${anchor}/(.*/)?\\.git/modules/[^/]*/hooks(/.*)?$`)})`,
      )
      // Same for the `.git` pointer filter, matched by vnode type.
      expect(text).toContain(
        `(regex ${JSON.stringify(`^${anchor}/(.*/)?\\.git$`)})`,
      )
    })
  },
)

/**
 * A pointer file's target, and the target its `commondir` names, are paths
 * the sandboxed command wrote into a file. Both are followed the way git
 * follows them, and both are names on disk once followed.
 */
describe.if(!isWindows)(
  'macOS profile: a bracketed git directory named by a pointer file',
  () => {
    let tree: PointerTree
    let originalCwd: string

    beforeAll(() => {
      originalCwd = process.cwd()
      tree = pointerTree('bracket-pointer-profile')
      process.chdir(tree.work)
    })

    afterAll(() => {
      process.chdir(originalCwd)
      rmSync(tree.root, { recursive: true, force: true })
    })

    it('denies the pointer and both git directories by subpath', () => {
      const text = wrapCommandWithSandboxMacOS({
        command: 'true',
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig: { allowOnly: [tree.root], denyWithinAllow: [] },
      })
      const denied = [
        tree.pointer,
        ...GIT_DIR_LEAVES.map(leaf => join(tree.gitDir, leaf)),
        ...GIT_DIR_LEAVES.map(leaf => join(tree.commonDir, leaf)),
      ]
      for (const path of denied) {
        expect(text).toContain(`(subpath ${JSON.stringify(path)})`)
        expect(text).not.toContain(sniffedFilter(path, '(/.*)?$'))
      }
    })
  },
)

describe.if(isMacOS)(
  'macOS sandbox: a bracketed submodule git directory keeps its hooks',
  () => {
    let tree: ModulesTree
    let originalCwd: string

    beforeAll(() => {
      originalCwd = process.cwd()
      tree = modulesTree('bracket-modules-exec')
      process.chdir(tree.work)
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

    it('writes elsewhere in that git directory (sanity check)', () => {
      const target = join(tree.submodule, 'objects', 'written')
      const result = run(`echo ok > ${JSON.stringify(target)}`)
      expect(result.status).toBe(0)
    })

    it('refuses a hook planted in that git directory', () => {
      const target = join(tree.submodule, 'hooks', 'pre-commit')
      const result = run(`echo planted > ${JSON.stringify(target)}`)
      expect(result.status).not.toBe(0)
      expect(result.stderr.toLowerCase()).toContain('operation not permitted')
    })

    it.if(CAN_LOCK_A_DIRECTORY)(
      'refuses a write in the directory the walk could not list',
      () => {
        const target = join(tree.unreadable, 'planted')
        // The profile is built while the directory is locked, which is what
        // puts the deny in it; the mode is then given back, so that what
        // refuses the write is the sandbox.
        const command = wrapCommandWithSandboxMacOS({
          command: `echo planted > ${JSON.stringify(target)}`,
          needsNetworkRestriction: false,
          readConfig: undefined,
          writeConfig: { allowOnly: [tree.root], denyWithinAllow: [] },
        })
        openModulesTree(tree)
        const result = spawnSync(command, {
          shell: true,
          encoding: 'utf8',
          timeout: 10000,
          env: { ...process.env, LC_ALL: 'C' },
        })
        expect(result.status).not.toBe(0)
        expect((result.stderr || '').toLowerCase()).toContain(
          'operation not permitted',
        )
      },
    )
  },
)

/**
 * The deny-glob compiler exists twice on purpose: a string-taking one in
 * `sandbox-utils.ts`, where a caller's configured spelling is all pattern,
 * and the entry-taking wrapper here, which splices an anchor back in as an
 * escaped literal. Taking the string one everywhere drops the anchor from
 * every macOS deny regex and puts the bracket bypass back, so both halves
 * are pinned: the anchor survives, and the wrapper stays in step with the
 * helper it delegates to.
 */
describe.if(!isWindows)(
  'macOS deny regexes: anchor and shared compiler',
  () => {
    let tree: BracketTree
    let originalCwd: string

    beforeAll(() => {
      originalCwd = process.cwd()
      tree = bracketTree('bracket-deny-anchor')
      process.chdir(tree.work)
    })

    afterAll(() => {
      process.chdir(originalCwd)
      rmSync(tree.root, { recursive: true, force: true })
    })

    it('escapes the cwd brackets in every regex the profile emits', () => {
      const regexes = emittedRegexes(wrap(tree, 'true'))
      expect(regexes.length).toBeGreaterThan(0)
      for (const regex of regexes) {
        // The cwd reaches a regex only as an escaped literal: unescaped, its
        // `a[b/c]d` is a one-character class and the rule matches nothing it
        // was built from. Escaped, the segments read `a\[b` and `c\]d`.
        expect(regex).not.toContain(`${BRACKET_SEGMENTS[0]}/`)
        expect(regex).not.toContain(BRACKET_SEGMENTS[1])
      }
    })

    it('anchors the mandatory subtree patterns at the cwd', () => {
      const anchor = tree.work.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
      const regexes = emittedRegexes(wrap(tree, 'true'))
      const anchored = regexes.filter(regex => regex.startsWith(`^${anchor}/`))
      expect(anchored.length).toBeGreaterThan(0)
      // `**/.git/hooks` covers a nested repository's hooks under the real
      // working directory, and nothing under the two directories the bracket
      // class would have matched instead.
      const nested = join(tree.work, 'vendor/lib/.git/hooks/pre-commit')
      expect(anchored.some(regex => new RegExp(regex).test(nested))).toBe(true)
      for (const decoy of ['abd', 'acd']) {
        const sibling = join(tree.root, decoy, 'lib/.git/hooks/pre-commit')
        for (const regex of regexes) {
          expect(new RegExp(regex).test(sibling)).toBe(false)
        }
      }
    })

    it('compiles a caller glob through the shared string helper', () => {
      const spelling = join(tree.root, 'logs', '*.pem')
      const profile = wrapCommandWithSandboxMacOS({
        command: 'true',
        needsNetworkRestriction: false,
        readConfig: { denyOnly: [spelling] },
        writeConfig: undefined,
      })
      expect(emittedRegexes(profile)).toContain(
        denyGlobRegex(normalizePathForSandbox(spelling)),
      )
    })
  },
)
