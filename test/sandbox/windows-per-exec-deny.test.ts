import { describe, it, expect, beforeEach, afterEach } from 'bun:test'
import {
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { join, resolve } from 'node:path'
import { tmpdir } from 'node:os'
import {
  DANGEROUS_FILES,
  getDangerousDirectories,
} from '../../src/sandbox/sandbox-utils.js'
import { windowsGetMandatoryDenyPaths } from '../../src/sandbox/windows-sandbox-utils.js'
import { computeWindowsPerExecDenySet } from '../../src/sandbox/sandbox-manager.js'

// Which paths a Windows command is denied: plain path computations, so these
// run on every platform. What a deny costs a sandboxed write is M1-M31 of
// test/sandbox/winsrt.test.ts.

let root: string

function repo(dir: string, withConfig = true) {
  mkdirSync(join(dir, '.git', 'hooks'), { recursive: true })
  if (withConfig) writeFileSync(join(dir, '.git', 'config'), '')
}

beforeEach(() => {
  // `.native` also expands an 8.3 name, as the code under test does.
  root = realpathSync.native(mkdtempSync(join(tmpdir(), 'win-deny-')))
})
afterEach(() => {
  rmSync(root, { recursive: true, force: true })
})

describe('windowsGetMandatoryDenyPaths', () => {
  it('collects cwd-level and nested targets within depth', () => {
    repo(root)
    writeFileSync(join(root, '.bashrc'), '')
    mkdirSync(join(root, '.vscode'))
    mkdirSync(join(root, '.claude', 'commands'), { recursive: true })
    repo(join(root, 'packages'))
    mkdirSync(join(root, 'packages', '.idea'), { recursive: true })
    mkdirSync(join(root, 'packages', 'app', '.idea'), { recursive: true })
    const got = new Set(windowsGetMandatoryDenyPaths(root))
    for (const p of [
      join(root, '.git', 'hooks'),
      join(root, '.git', 'config'),
      join(root, '.bashrc'),
      join(root, '.vscode'),
      join(root, '.claude', 'commands'),
      join(root, 'packages', '.git', 'hooks'),
      join(root, 'packages', '.git', 'config'),
      join(root, 'packages', '.idea'),
    ]) {
      expect(got.has(p)).toBe(true)
    }
    expect(got.has(join(root, 'packages', 'app', '.idea'))).toBe(false)
    expect(got.has(join(root, '.git'))).toBe(false)
    expect(got.has(join(root, '.claude'))).toBe(false)
  })

  it('takes every name of the shared definitions that is there, and nothing else', () => {
    const names = [
      ...DANGEROUS_FILES.filter(n => n !== '.profile'),
      ...getDangerousDirectories().filter(n => n !== '.idea'),
      '.git/hooks',
      '.git/config',
    ]
    repo(root)
    for (const n of DANGEROUS_FILES) {
      if (names.includes(n)) writeFileSync(join(root, n), '')
    }
    for (const n of getDangerousDirectories()) {
      if (names.includes(n)) mkdirSync(join(root, n), { recursive: true })
    }
    writeFileSync(join(root, 'app.js'), '')
    expect(windowsGetMandatoryDenyPaths(root).sort()).toEqual(
      names.map(n => resolve(root, n)).sort(),
    )
  })

  it('returns only existing paths', () => {
    mkdirSync(join(root, '.git'))
    expect(windowsGetMandatoryDenyPaths(root)).toEqual([])
  })

  it('respects maxDepth and skips node_modules; cwd is always covered', () => {
    repo(join(root, 'a', 'b'))
    repo(join(root, 'a'))
    repo(join(root, 'node_modules', 'pkg'))
    repo(root)
    const d3 = windowsGetMandatoryDenyPaths(root, { maxDepth: 3 })
    expect(d3).toContain(join(root, 'a', '.git', 'hooks'))
    expect(d3).not.toContain(join(root, 'a', 'b', '.git', 'hooks'))
    expect(d3.some(p => p.includes('node_modules'))).toBe(false)
    const d2 = windowsGetMandatoryDenyPaths(root, { maxDepth: 2 })
    expect(d2).toEqual(
      expect.arrayContaining([
        join(root, '.git', 'hooks'),
        join(root, '.git', 'config'),
      ]),
    )
    expect(d2.some(p => p.startsWith(join(root, 'a')))).toBe(false)
  })

  it("takes the working directory's own names whatever the depth", () => {
    repo(root)
    mkdirSync(join(root, '.claude', 'agents'), { recursive: true })
    repo(join(root, 'a'))
    expect(windowsGetMandatoryDenyPaths(root, { maxDepth: 1 }).sort()).toEqual([
      join(root, '.claude', 'agents'),
      join(root, '.git', 'config'),
      join(root, '.git', 'hooks'),
    ])
  })

  /** `main`, and its linked worktree `wt`. Returns `wt`'s own git directory. */
  function linkedWorktree(): string {
    repo(join(root, 'main'))
    const gitDir = join(root, 'main', '.git', 'worktrees', 'wt')
    mkdirSync(gitDir, { recursive: true })
    writeFileSync(join(gitDir, 'commondir'), '../..\n')
    mkdirSync(join(root, 'wt'))
    writeFileSync(join(root, 'wt', '.git'), `gitdir: ${gitDir}\n`)
    return gitDir
  }
  const inWt = (opts: { roots: string[]; allowGitConfig?: boolean }) =>
    windowsGetMandatoryDenyPaths(join(root, 'wt'), {
      grantRoots: () => opts.roots,
      allowGitConfig: opts.allowGitConfig,
    })

  it("a linked worktree: the `.git` file, and the common directory's hooks and config", () => {
    linkedWorktree()
    expect(inWt({ roots: [root] })).toEqual([
      join(root, 'wt', '.git'),
      join(root, 'main', '.git', 'hooks'),
      join(root, 'main', '.git', 'config'),
    ])
    expect(inWt({ roots: [root], allowGitConfig: true })).toEqual([
      join(root, 'wt', '.git'),
      join(root, 'main', '.git', 'hooks'),
    ])
  })

  it("a submodule: the `.git` file, and its own directory's, by a relative path", () => {
    repo(root)
    const own = join(root, '.git', 'modules', 'sub')
    mkdirSync(join(own, 'hooks'), { recursive: true })
    writeFileSync(join(own, 'config'), '')
    mkdirSync(join(root, 'sub'))
    writeFileSync(join(root, 'sub', '.git'), 'gitdir: ../.git/modules/sub\r\n')
    const got = windowsGetMandatoryDenyPaths(root, { grantRoots: () => [root] })
    expect(got).toEqual(
      expect.arrayContaining([
        join(root, 'sub', '.git'),
        join(own, 'hooks'),
        join(own, 'config'),
      ]),
    )
  })

  it('outside the granted roots only the `.git` file is denied, and nothing is read there', () => {
    const gitDir = linkedWorktree()
    const file = [join(root, 'wt', '.git')]
    expect(inWt({ roots: [join(root, 'wt')] })).toEqual(file)
    expect(inWt({ roots: [] })).toEqual(file)
    // The worktree's own directory granted, the common one not.
    mkdirSync(join(gitDir, 'hooks'))
    expect(inWt({ roots: [gitDir] })).toEqual([...file, join(gitDir, 'hooks')])
    // A sibling whose name only starts like a root.
    expect(inWt({ roots: [join(root, 'ma')] })).toEqual(file)
    // Its `commondir` leads back under a root: read, it would show.
    repo(join(root, 'in'))
    mkdirSync(join(root, 'out'))
    writeFileSync(join(root, 'out', 'commondir'), '../in/.git\n')
    writeFileSync(file[0]!, 'gitdir: ../out\n')
    expect(inWt({ roots: [join(root, 'wt'), join(root, 'in')] })).toEqual(file)
  })

  it('a `.git` file that cannot be followed is still denied itself', () => {
    linkedWorktree()
    const file = join(root, 'wt', '.git')
    for (const text of [
      '',
      'not a pointer\n',
      '\ngitdir: ../main/.git\n',
      'gitdir: ../gone\n',
      // A UNC form, which `path.resolve` would fold into a path under the root.
      `gitdir: //${join(root, 'main', '.git').replace(/^\//, '')}\n`,
      `gitdir: ../main/.git\n${'#'.repeat(4096)}`,
    ]) {
      writeFileSync(file, text)
      expect(inWt({ roots: [root] })).toEqual([file])
    }
  })

  it.skipIf(process.platform === 'win32')(
    'a `commondir` that is a link is not read',
    () => {
      const gitDir = linkedWorktree()
      writeFileSync(join(root, 'target'), '../..\n')
      rmSync(join(gitDir, 'commondir'))
      symlinkSync(join(root, 'target'), join(gitDir, 'commondir'))
      expect(inWt({ roots: [root] })).toEqual([join(root, 'wt', '.git')])
    },
  )

  it.skipIf(process.platform === 'win32')(
    'real paths are compared: a root spelled through a link counts, a directory that leads out through one does not',
    () => {
      linkedWorktree()
      const alias = `${root}-alias`
      symlinkSync(root, alias)
      try {
        expect(inWt({ roots: [alias] })).toContain(
          join(root, 'main', '.git', 'hooks'),
        )
      } finally {
        rmSync(alias)
      }
      symlinkSync(join(root, 'main', '.git'), join(root, 'wt', 'out'))
      writeFileSync(join(root, 'wt', '.git'), 'gitdir: out\n')
      expect(inWt({ roots: [join(root, 'wt')] })).toEqual([
        join(root, 'wt', '.git'),
      ])
    },
  )

  it('allowGitConfig leaves .git/config out', () => {
    repo(root)
    const got = windowsGetMandatoryDenyPaths(root, { allowGitConfig: true })
    expect(got).toEqual([join(root, '.git', 'hooks')])
  })

  it('matches names case-insensitively', () => {
    mkdirSync(join(root, '.VSCode'))
    writeFileSync(join(root, '.ZshRC'), '')
    const got = windowsGetMandatoryDenyPaths(root)
    expect(got).toContain(join(root, '.VSCode'))
    expect(got).toContain(join(root, '.ZshRC'))
  })
})

describe('computeWindowsPerExecDenySet', () => {
  const cfg = (fs: Record<string, unknown>) =>
    ({
      filesystem: { allowWrite: [root], denyRead: [], denyWrite: [], ...fs },
      network: { allowedDomains: [], deniedDomains: [] },
    }) as never

  it("keeps the session's own denies apart from what only customConfig asks for", () => {
    repo(root)
    const [secret, notes, key] = ['secret.txt', 'notes.txt', 'key.txt'].map(n =>
      join(root, n),
    )
    for (const f of [secret, notes, key]) writeFileSync(f, '')
    const hooks = join(root, '.git', 'hooks')
    expect(
      computeWindowsPerExecDenySet(
        cfg({ denyRead: [secret] }),
        // `secret` and `hooks` are the session's already.
        {
          filesystem: {
            denyRead: [key, secret],
            denyWrite: [notes, hooks, key],
          },
        } as never,
        root,
      ),
    ).toEqual({
      denyRead: [secret],
      denyWrite: [hooks, join(root, '.git', 'config')],
      extraDenyRead: [key],
      extraDenyWrite: [notes],
    })
  })

  it('follows a `.git` file under allowWrite only', () => {
    repo(join(root, 'main'))
    mkdirSync(join(root, 'wt'))
    writeFileSync(join(root, 'wt', '.git'), 'gitdir: ../main/.git\n')
    const hooks = join(root, 'main', '.git', 'hooks')
    const at = (allowWrite: string[]) =>
      computeWindowsPerExecDenySet(
        cfg({ allowWrite }),
        undefined,
        join(root, 'wt'),
      ).denyWrite
    expect(at([root])).toContain(hooks)
    expect(at([join(root, 'wt')])).toEqual([join(root, 'wt', '.git')])
  })

  it('a denyRead target is not duplicated as denyWrite', () => {
    repo(root)
    const set = computeWindowsPerExecDenySet(
      cfg({ denyRead: [join(root, '.git', 'config')] }),
      undefined,
      root,
    )
    expect(set.denyRead).toEqual([join(root, '.git', 'config')])
    expect(set.denyWrite).not.toContain(join(root, '.git', 'config'))
  })

  it('honors allowGitConfig and mandatoryDenySearchDepth', () => {
    repo(root)
    repo(join(root, 'a', 'b'))
    const c = {
      ...(cfg({ allowGitConfig: true }) as object),
      mandatoryDenySearchDepth: 2,
    } as never
    const set = computeWindowsPerExecDenySet(c, undefined, root)
    expect(set.denyWrite).toEqual([join(root, '.git', 'hooks')])
  })

  it('filesystem.disabled yields an empty set', () => {
    repo(root)
    const none = {
      denyRead: [],
      denyWrite: [],
      extraDenyRead: [],
      extraDenyWrite: [],
    }
    expect(
      computeWindowsPerExecDenySet(cfg({ disabled: true }), undefined, root),
    ).toEqual(none)
    expect(
      computeWindowsPerExecDenySet(
        cfg({}),
        { filesystem: { disabled: true } } as never,
        root,
      ),
    ).toEqual(none)
  })
})
