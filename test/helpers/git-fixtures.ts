import { mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

export type MainWorktreeFixture = {
  rootDir: string
  worktreeDir: string
  commonDir: string
}

export type LinkedWorktreeFixture = MainWorktreeFixture & {
  worktreeGitDir: string
}

/** Synthetic Git metadata for write probes and deliberately malformed layouts. */
export function createLinkedWorktreeFixture(
  baseDir: string,
  name: string,
  originalContent: string,
): LinkedWorktreeFixture {
  const rootDir = join(baseDir, name)
  const commonDir = join(rootDir, 'main-repo', '.git')
  const worktreeDir = join(rootDir, 'worktree')
  const worktreeGitDir = join(commonDir, 'worktrees', 'feature')
  mkdirSync(join(commonDir, 'hooks'), { recursive: true })
  mkdirSync(join(commonDir, 'refs', 'heads'), { recursive: true })
  mkdirSync(join(commonDir, 'objects'), { recursive: true })
  mkdirSync(worktreeGitDir, { recursive: true })
  mkdirSync(worktreeDir, { recursive: true })
  writeFileSync(join(commonDir, 'HEAD'), 'ref: refs/heads/main\n')
  writeFileSync(join(worktreeGitDir, 'HEAD'), 'ref: refs/heads/feature\n')
  writeFileSync(join(commonDir, 'config'), originalContent)
  writeFileSync(join(commonDir, 'config.worktree'), originalContent)
  writeFileSync(join(commonDir, 'hooks', 'pre-commit'), originalContent)
  writeFileSync(join(commonDir, 'refs', 'heads', 'main'), originalContent)
  const dotGitPath = join(worktreeDir, '.git')
  writeFileSync(join(worktreeGitDir, 'commondir'), '../..')
  writeFileSync(join(worktreeGitDir, 'config.worktree'), originalContent)
  writeFileSync(join(worktreeGitDir, 'gitdir'), dotGitPath)
  writeFileSync(dotGitPath, `gitdir: ${worktreeGitDir}`)
  return { rootDir, worktreeDir, commonDir, worktreeGitDir }
}

export function createMainWorktreeFixture(
  baseDir: string,
  name: string,
  originalContent: string,
): MainWorktreeFixture {
  const rootDir = join(baseDir, name)
  const worktreeDir = join(rootDir, 'worktree')
  const commonDir = join(worktreeDir, '.git')
  mkdirSync(join(commonDir, 'hooks'), { recursive: true })
  mkdirSync(join(commonDir, 'refs', 'heads'), { recursive: true })
  mkdirSync(join(commonDir, 'objects'), { recursive: true })
  writeFileSync(join(commonDir, 'HEAD'), 'ref: refs/heads/main\n')
  writeFileSync(join(commonDir, 'config'), originalContent)
  writeFileSync(join(commonDir, 'hooks', 'pre-commit'), originalContent)
  writeFileSync(join(commonDir, 'refs', 'heads', 'main'), originalContent)
  return { rootDir, worktreeDir, commonDir }
}

export async function withWorktreeFixture<T extends MainWorktreeFixture>(
  fixture: T,
  testFn: (fixture: T) => Promise<void> | void,
): Promise<void> {
  const originalDir = process.cwd()
  try {
    process.chdir(fixture.worktreeDir)
    await testFn(fixture)
  } finally {
    process.chdir(originalDir)
    rmSync(fixture.rootDir, { recursive: true, force: true })
  }
}
