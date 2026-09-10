import * as fs from 'fs'
import * as path from 'path'
import { logForDebugging } from '../utils/debug.js'

/** The path is absent, as opposed to unreadable or otherwise unverifiable. */
function isAbsenceError(err: unknown): boolean {
  const code = (err as NodeJS.ErrnoException | undefined)?.code
  return code === 'ENOENT' || code === 'ENOTDIR'
}

/**
 * The paths inside a git directory through which a write becomes code the
 * host's git runs later: hooks/ always, config (core.fsmonitor, core.editor,
 * core.hooksPath and the like) unless the caller allows it.
 */
export function gitDirDenyPaths(
  gitDir: string,
  allowGitConfig: boolean,
): string[] {
  return allowGitConfig
    ? [path.join(gitDir, 'hooks')]
    : [path.join(gitDir, 'hooks'), path.join(gitDir, 'config')]
}

/**
 * Deny paths for a `.git` file, the `gitdir:` pointer of a linked worktree or
 * submodule checkout: the file itself plus the hooks/ and config git reads
 * through it (the named git directory's, or for a linked worktree its
 * commondir's and the worktree's own config.worktree).
 */
export function gitFileDenyPaths(
  gitFile: string,
  allowGitConfig: boolean,
): string[] {
  const denyPaths = [gitFile]
  try {
    const target = fs
      .readFileSync(gitFile, 'utf8')
      .match(/^gitdir:\s*(.+?)\s*$/m)?.[1]
    if (target === undefined) return denyPaths
    const gitDir = path.resolve(path.dirname(gitFile), target)
    if (!fs.statSync(gitDir).isDirectory()) return denyPaths
    let hooksAndConfigDir = gitDir
    try {
      const common = fs.readFileSync(path.join(gitDir, 'commondir'), 'utf8')
      hooksAndConfigDir = path.resolve(gitDir, common.trim())
      if (!allowGitConfig) {
        denyPaths.push(path.join(gitDir, 'config.worktree'))
      }
    } catch (err) {
      // No commondir: a submodule's (or standalone) git directory.
      if (!isAbsenceError(err)) throw err
    }
    denyPaths.push(...gitDirDenyPaths(hooksAndConfigDir, allowGitConfig))
  } catch (err) {
    // A dangling pointer names nothing git would read. Any other failure
    // leaves the hooks/config behind the pointer undenied.
    if (!isAbsenceError(err)) {
      logForDebugging(
        `[Sandbox] Could not follow ${gitFile}, denying only the file itself: ${err}`,
        { level: 'warn' },
      )
    }
  }
  return denyPaths
}

/**
 * Git directories of the submodules under `modulesDir` (a repository's
 * .git/modules), nested submodules included. A submodule's name is its path,
 * so one can sit several levels down (modules/vendor/lib), hence the walk.
 */
export function submoduleGitDirs(
  modulesDir: string,
  maxDepth: number,
): string[] {
  const found: string[] = []
  const pending = [{ dir: modulesDir, depth: 0 }]
  for (let next = pending.pop(); next !== undefined; next = pending.pop()) {
    const { dir, depth } = next
    let entries: fs.Dirent[]
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true })
    } catch (err) {
      // Absent is the common case: no submodules, or none nested in this one.
      if (!isAbsenceError(err)) {
        logForDebugging(
          `[Sandbox] Could not list ${dir}, submodule git directories beneath it are not denied: ${err}`,
          { level: 'warn' },
        )
      }
      continue
    }
    for (const entry of entries) {
      if (!entry.isDirectory()) continue
      const child = path.join(dir, entry.name)
      if (fs.existsSync(path.join(child, 'HEAD'))) {
        found.push(child)
        if (depth + 1 < maxDepth) {
          pending.push({ dir: path.join(child, 'modules'), depth: depth + 1 })
        }
      } else if (depth + 1 < maxDepth) {
        pending.push({ dir: child, depth: depth + 1 })
      }
    }
  }
  return found
}
