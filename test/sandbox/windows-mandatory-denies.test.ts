import { afterAll, beforeAll, describe, expect, it } from 'bun:test'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import {
  DANGEROUS_FILES,
  getDangerousDirectories,
} from '../../src/sandbox/sandbox-utils.js'
import { windowsGetCwdMandatoryDenyPaths } from '../../src/sandbox/windows-sandbox-utils.js'

/**
 * The Windows mandatory write denies, which `computeWindowsFsAccessSet` unions
 * into the session's `denyWrite` stamp. The producer is a plain path
 * computation over the working directory, so it runs on every platform and
 * these rows do too; what a stamped deny then costs a sandboxed write is in
 * test/sandbox/winsrt.test.ts, on the Windows legs.
 */
describe('windowsGetCwdMandatoryDenyPaths', () => {
  let root: string
  let originalCwd: string

  // One tree carrying: every dangerous file but `.profile`, every dangerous
  // directory but `.idea`, a `.git` directory with hooks and config, an
  // ordinary project file, and a nested repository.
  beforeAll(() => {
    originalCwd = process.cwd()
    root = mkdtempSync(join(tmpdir(), 'srt-winmand-'))
    for (const name of DANGEROUS_FILES) {
      if (name === '.profile') continue
      writeFileSync(join(root, name), 'x')
    }
    for (const name of getDangerousDirectories()) {
      if (name === '.idea') continue
      mkdirSync(join(root, name), { recursive: true })
    }
    mkdirSync(join(root, '.git', 'hooks'), { recursive: true })
    writeFileSync(join(root, '.git', 'config'), '[core]\n')
    writeFileSync(join(root, 'app.js'), 'x')
    mkdirSync(join(root, 'nested', '.git', 'hooks'), { recursive: true })
    writeFileSync(join(root, 'nested', '.bashrc'), 'x')
  })

  afterAll(() => {
    process.chdir(originalCwd)
    rmSync(root, { recursive: true, force: true })
  })

  function denies(allowGitConfig = false): string[] {
    process.chdir(root)
    try {
      return windowsGetCwdMandatoryDenyPaths(allowGitConfig)
    } finally {
      process.chdir(originalCwd)
    }
  }

  it('returns every dangerous name that is there, resolved against the cwd', () => {
    process.chdir(root)
    const cwd = process.cwd()
    process.chdir(originalCwd)
    const got = denies()
    for (const name of DANGEROUS_FILES) {
      if (name === '.profile') continue
      expect(got).toContain(resolve(cwd, name))
    }
    for (const name of getDangerousDirectories()) {
      if (name === '.idea') continue
      expect(got).toContain(resolve(cwd, name))
    }
    expect(got).toContain(resolve(cwd, '.git/hooks'))
    expect(got).toContain(resolve(cwd, '.git/config'))
  })

  it('leaves out a name that is not there, and the ordinary project file', () => {
    const got = denies()
    expect(got.some(p => p.endsWith('.profile'))).toBe(false)
    expect(got.some(p => p.endsWith('.idea'))).toBe(false)
    expect(got.some(p => p.endsWith('app.js'))).toBe(false)
  })

  it('allowGitConfig keeps the hooks deny and drops the config one', () => {
    const got = denies(true)
    expect(got.some(p => p.endsWith(join('.git', 'hooks')))).toBe(true)
    expect(got.some(p => p.endsWith(join('.git', 'config')))).toBe(false)
  })

  it('leaves out a nested repository: the set is the working directory only', () => {
    const got = denies()
    expect(got.some(p => p.includes(join('nested', '.git')))).toBe(false)
    expect(got.some(p => p.includes(join('nested', '.bashrc')))).toBe(false)
  })

  it('a `.git` pointer file yields no git denies and does not throw', () => {
    const worktree = mkdtempSync(join(tmpdir(), 'srt-winmand-wt-'))
    writeFileSync(join(worktree, '.git'), `gitdir: ${join(root, '.git')}\n`)
    writeFileSync(join(worktree, '.bashrc'), 'x')
    process.chdir(worktree)
    try {
      const cwd = process.cwd()
      const got = windowsGetCwdMandatoryDenyPaths()
      expect(got).toEqual([resolve(cwd, '.bashrc')])
    } finally {
      process.chdir(originalCwd)
      rmSync(worktree, { recursive: true, force: true })
    }
  })

  it('an empty working directory yields nothing to stamp', () => {
    const empty = mkdtempSync(join(tmpdir(), 'srt-winmand-empty-'))
    process.chdir(empty)
    try {
      expect(windowsGetCwdMandatoryDenyPaths()).toEqual([])
    } finally {
      process.chdir(originalCwd)
      rmSync(empty, { recursive: true, force: true })
    }
  })
})
