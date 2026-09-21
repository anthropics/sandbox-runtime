import * as fs from 'node:fs'
import * as path from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  isAtOrUnder,
  normalizePathForSandbox,
  pathSpellings,
} from './sandbox-utils.js'

/**
 * The library's own files, as a thing to write-deny.
 *
 * The host side of the library runs with the user's full authority, outside
 * any sandbox, so it must not execute a file the sandbox policy lets the
 * wrapped command write. That holds for its own code as much as for any
 * program it runs. Installed as a dependency of a project, the library lives
 * in `<project>/node_modules/`, and the project is usually what `allowWrite`
 * names. A wrapped command could then rewrite `dist/*.js` here, the bundled
 * seccomp helper, or one of the packages this one loads, and the next `srt`
 * run would execute the result outside any sandbox.
 *
 * So the directories this copy was loaded from are denied to every wrapped
 * command whenever they lie inside a path it may write: the package's own
 * directory and the directory of every package it depends on at run time,
 * found the way the module loader finds them. Nothing is denied for a copy
 * that is not installed under a `node_modules` (a checkout of this
 * repository, where the tree is the project being worked on), and nothing
 * where the library has been compiled into an application, since there is
 * then no file on disk to protect.
 */

type PackageManifest = {
  name?: string
  dependencies?: Record<string, string>
  optionalDependencies?: Record<string, string>
}

function readManifest(dir: string): PackageManifest | undefined {
  try {
    const parsed: unknown = JSON.parse(
      fs.readFileSync(path.join(dir, 'package.json'), 'utf8'),
    )
    return typeof parsed === 'object' && parsed !== null
      ? (parsed as PackageManifest)
      : undefined
  } catch {
    return undefined
  }
}

/** Where `name` is loaded from by code in `fromDir`: the nearest
 *  `node_modules/<name>` on the way up that holds a package. */
function resolveDependency(fromDir: string, name: string): string | undefined {
  for (let dir = fromDir; ; dir = path.dirname(dir)) {
    const candidate = path.join(dir, 'node_modules', name)
    if (readManifest(candidate) !== undefined) return candidate
    if (dir === path.dirname(dir)) return undefined
  }
}

/** A sanity bound on the walk of the dependency graph: this package has four
 *  dependencies and they have a handful between them. */
const MAX_PACKAGES = 200

/**
 * The directory of the installed package `moduleFile` belongs to, and of every
 * package it depends on at run time, each once. Empty when that package is
 * not installed under a `node_modules`, or is not on disk at all.
 *
 * `moduleFile` is a file two levels below the package root, as every module
 * of `src/sandbox` and `dist/sandbox` is.
 */
export function installedPackageDirs(moduleFile: string): string[] {
  const packageRoot = path.resolve(path.dirname(moduleFile), '..', '..')
  if (!packageRoot.split(path.sep).includes('node_modules')) return []
  if (readManifest(packageRoot) === undefined) return []

  const found = new Set<string>([packageRoot])
  const pending = [packageRoot]
  for (let dir = pending.shift(); dir !== undefined; dir = pending.shift()) {
    const manifest = readManifest(dir)
    for (const name of [
      ...Object.keys(manifest?.dependencies ?? {}),
      ...Object.keys(manifest?.optionalDependencies ?? {}),
    ]) {
      if (found.size >= MAX_PACKAGES) return [...found]
      const resolved = resolveDependency(dir, name)
      if (resolved !== undefined && !found.has(resolved)) {
        found.add(resolved)
        pending.push(resolved)
      }
    }
  }
  return [...found]
}

// An install does not move while the process that was loaded from it runs.
let ownInstall: string[] | undefined

function thisLibrarysInstall(): string[] {
  if (ownInstall === undefined) {
    try {
      ownInstall = installedPackageDirs(fileURLToPath(import.meta.url))
    } catch {
      // No file location at all: loaded from somewhere that is not a file.
      ownInstall = []
    }
  }
  return ownInstall
}

/**
 * The write-denies a wrap adds for the library's own files: those of
 * `packageDirs` (by default this copy's, see {@link installedPackageDirs})
 * that lie at or under one of `allowedWritePaths`, judged both as the paths
 * are spelled and as they resolve. A directory no allowed write path
 * contains is read-only in the sandbox already and costs nothing here.
 */
export function ownFilesWriteDenies(
  allowedWritePaths: readonly string[],
  packageDirs: readonly string[] = thisLibrarysInstall(),
): string[] {
  if (packageDirs.length === 0) return []
  const writable = allowedWritePaths.flatMap(allowed =>
    pathSpellings(normalizePathForSandbox(allowed)).filter(form =>
      path.isAbsolute(form),
    ),
  )
  return packageDirs.filter(dir =>
    pathSpellings(dir).some(form =>
      writable.some(allowed => isAtOrUnder(form, allowed)),
    ),
  )
}
