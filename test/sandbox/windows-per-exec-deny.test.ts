import { describe, it, expect, beforeEach, afterEach } from 'bun:test'
import {
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { windowsGetMandatoryDenyPaths } from '../../src/sandbox/windows-sandbox-utils.js'
import { computeWindowsPerExecDenySet } from '../../src/sandbox/sandbox-manager.js'

let root: string

function repo(dir: string, withConfig = true) {
  mkdirSync(join(dir, '.git', 'hooks'), { recursive: true })
  if (withConfig) writeFileSync(join(dir, '.git', 'config'), '')
}

beforeEach(() => {
  root = realpathSync(mkdtempSync(join(tmpdir(), 'win-deny-')))
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

  it('merges mandatory, session and per-exec denies', () => {
    repo(root)
    const secret = join(root, 'secret.txt')
    const notes = join(root, 'notes.txt')
    writeFileSync(secret, '')
    writeFileSync(notes, '')
    const set = computeWindowsPerExecDenySet(
      cfg({ denyRead: [secret] }),
      { filesystem: { denyWrite: [notes] } } as never,
      root,
    )
    expect(set.denyRead).toEqual([secret])
    expect(set.denyWrite).toEqual(
      expect.arrayContaining([
        notes,
        join(root, '.git', 'hooks'),
        join(root, '.git', 'config'),
      ]),
    )
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
      ...cfg({ allowGitConfig: true }),
      mandatoryDenySearchDepth: 2,
    } as never
    const set = computeWindowsPerExecDenySet(c, undefined, root)
    expect(set.denyWrite).toEqual([join(root, '.git', 'hooks')])
  })

  it('filesystem.disabled yields an empty set', () => {
    repo(root)
    expect(
      computeWindowsPerExecDenySet(cfg({ disabled: true }), undefined, root),
    ).toEqual({
      denyRead: [],
      denyWrite: [],
    })
    expect(
      computeWindowsPerExecDenySet(
        cfg({}),
        { filesystem: { disabled: true } } as never,
        root,
      ),
    ).toEqual({ denyRead: [], denyWrite: [] })
  })
})
