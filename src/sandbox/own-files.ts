import * as fs from 'node:fs'
import * as path from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  containsGlobCharsForPlatform,
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
 * So what this copy is loaded from is denied to every wrapped command whenever
 * it lies inside a path the command may write:
 *
 * - the package's own directory and the directory of every package it depends
 *   on at run time, found the way the module loader finds them;
 * - every place the loader looks for one of those packages BEFORE the place it
 *   is found. A scoped package is asked for its dependency in
 *   `node_modules/@scope/node_modules/` ahead of the hoisted copy, and that
 *   directory does not exist, so a command could create it and be loaded
 *   instead. A path that is not there yet can be denied like any other;
 * - the package's launchers in `node_modules/.bin/`, which are links kept in a
 *   directory the command may write and are what `npx` and `npm run` start.
 *   Seatbelt denies such a name; on Linux a mount cannot hold a link's own
 *   name (it lands on what the link leads to), so there a launcher can still
 *   be re-pointed, and starting the library by the package's own path, or
 *   from an install outside the write paths, is what avoids it.
 *
 * These are names the library read off the disk, not spellings a caller
 * wrote, so they travel as literal paths: a project directory with `[` or `*`
 * in its name is not read as a pattern.
 *
 * Nothing is denied for a copy that is not installed under a `node_modules`
 * (a checkout of this repository, where the tree is the project being worked
 * on), and nothing where the library has been compiled into an application,
 * since there is then no file on disk to protect. What starts the library is
 * outside this: a program of the caller's own that loads it is found from
 * wherever that program is.
 */

type PackageManifest = {
  name?: string
  bin?: string | Record<string, string>
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

function exists(p: string): boolean {
  try {
    fs.lstatSync(p)
    return true
  } catch {
    return false
  }
}

/**
 * Where `name` is loaded from by code in `fromDir`: the nearest
 * `node_modules/<name>` on the way up that holds a package. `passed` is every
 * place looked at before that one. The CommonJS loader does not look for a
 * `node_modules` inside a directory that is itself called `node_modules`; the
 * ES module one does, and this package is one, so every level counts here.
 */
function resolveDependency(
  fromDir: string,
  name: string,
): { found: string | undefined; passed: string[] } {
  const passed: string[] = []
  for (let dir = fromDir; ; dir = path.dirname(dir)) {
    const candidate = path.join(dir, 'node_modules', name)
    if (readManifest(candidate) !== undefined) {
      return { found: candidate, passed }
    }
    passed.push(candidate)
    if (dir === path.dirname(dir)) return { found: undefined, passed: [] }
  }
}

/** The deepest part of `absent` that can be denied in its place: the first
 *  component of it that does not exist, which is what would have to be
 *  created for anything to appear at `absent`. */
function firstMissing(absent: string): string {
  let missing = absent
  for (
    let parent = path.dirname(missing);
    parent !== missing && !exists(parent);
    parent = path.dirname(parent)
  ) {
    missing = parent
  }
  return missing
}

/** The launchers npm made for the package at `packageRoot`: one link in the
 *  `.bin` beside it for each name its manifest declares. */
function launchersOf(packageRoot: string, manifest: PackageManifest): string[] {
  const names =
    typeof manifest.bin === 'string'
      ? [path.basename(manifest.name ?? packageRoot)]
      : Object.keys(manifest.bin ?? {})
  // node_modules/<name> or node_modules/@scope/<name>
  const holder = path.basename(path.dirname(packageRoot)).startsWith('@')
    ? path.dirname(path.dirname(packageRoot))
    : path.dirname(packageRoot)
  return names
    .map(name => path.join(holder, '.bin', name))
    .filter(launcher => exists(launcher))
}

/** A sanity bound on the walk of the dependency graph: this package has four
 *  dependencies and they have a handful between them. */
const MAX_PACKAGES = 200

/**
 * What the installed package `moduleFile` belongs to is loaded from, each path
 * once: its directory and that of every package it depends on at run time,
 * the places the loader looks for those before it finds them, and the
 * package's launchers. Empty when that package is not installed under a
 * `node_modules`, or is not on disk at all.
 *
 * `moduleFile` is a file two levels below the package root, as every module
 * of `src/sandbox` and `dist/sandbox` is.
 */
export function installedPackagePaths(moduleFile: string): string[] {
  const packageRoot = path.resolve(path.dirname(moduleFile), '..', '..')
  if (!packageRoot.split(path.sep).includes('node_modules')) return []
  const own = readManifest(packageRoot)
  if (own === undefined) return []

  const packages = new Set<string>([packageRoot])
  const lookedAtFirst = new Set<string>()
  const pending = [packageRoot]
  walk: for (
    let dir = pending.shift();
    dir !== undefined;
    dir = pending.shift()
  ) {
    const manifest = readManifest(dir)
    for (const name of [
      ...Object.keys(manifest?.dependencies ?? {}),
      ...Object.keys(manifest?.optionalDependencies ?? {}),
    ]) {
      if (packages.size >= MAX_PACKAGES) break walk
      const { found, passed } = resolveDependency(dir, name)
      if (found === undefined) continue
      for (const earlier of passed) lookedAtFirst.add(firstMissing(earlier))
      if (!packages.has(found)) {
        packages.add(found)
        pending.push(found)
      }
    }
  }
  // A place inside one of the packages is denied with it.
  const outsideEvery = (p: string): boolean =>
    ![...packages].some(dir => isAtOrUnder(p, dir))
  return [
    ...packages,
    ...[...lookedAtFirst].filter(outsideEvery),
    ...launchersOf(packageRoot, own),
  ]
}

// An install does not move while the process that was loaded from it runs.
let ownInstall: string[] | undefined

function thisLibrarysInstall(): string[] {
  if (ownInstall === undefined) {
    try {
      ownInstall = installedPackagePaths(fileURLToPath(import.meta.url))
    } catch {
      // No file location at all: loaded from somewhere that is not a file.
      ownInstall = []
    }
  }
  return ownInstall
}

/**
 * The write-denies a wrap adds for the library's own files: those of
 * `installPaths` (by default this copy's, see {@link installedPackagePaths})
 * that lie at or under one of `allowedWritePaths`, judged both as the paths
 * are spelled and as they resolve. A path no allowed write path contains is
 * read-only in the sandbox already and costs nothing here. Where an allowed
 * write path is a pattern there is no judging by containment, and all of
 * them are denied: a deny on what cannot be written anyway changes nothing.
 * They are literal paths: see
 * `FsWriteRestrictionConfig.literalDenyWithinAllow`.
 */
export function ownFilesWriteDenies(
  allowedWritePaths: readonly string[],
  installPaths: readonly string[] = thisLibrarysInstall(),
): string[] {
  if (installPaths.length === 0) return []
  if (allowedWritePaths.some(containsGlobCharsForPlatform)) {
    return [...installPaths]
  }
  const writable = allowedWritePaths.flatMap(allowed =>
    pathSpellings(normalizePathForSandbox(allowed)).filter(form =>
      path.isAbsolute(form),
    ),
  )
  return installPaths.filter(installed =>
    pathSpellings(installed).some(form =>
      writable.some(allowed => isAtOrUnder(form, allowed)),
    ),
  )
}
