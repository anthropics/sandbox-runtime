import * as fs from 'node:fs'
import * as path from 'node:path'

/** One place `PATH` says a program could be. */
export type PathCandidate = {
  /** The `PATH` entry, as spelled; the empty entry means the current directory. */
  entry: string
  /** The file that entry would hold, made absolute. */
  file: string
}

/** A name with a directory part names one file; it is not searched for. */
export function isPathQualified(bin: string): boolean {
  return bin.includes('/') || bin.includes(path.sep)
}

/**
 * `file` is a regular file this process may execute: what a `PATH` search
 * accepts. A directory of the right name, a file without the execute bit and
 * a dangling link are all passed over, as a shell passes over them.
 */
export function isExecutableFile(file: string): boolean {
  try {
    fs.accessSync(file, fs.constants.X_OK)
    return fs.statSync(file).isFile()
  } catch {
    return false
  }
}

/**
 * Where `PATH` says a program called `bin` could be, in search order, whether
 * or not anything is there. `PATH` is read when called, so a caller that
 * changed `process.env.PATH` is searched the way a child it spawns would be.
 * An unset or empty `PATH` names no place at all.
 */
export function* pathCandidates(
  bin: string,
  pathVar: string = process.env.PATH ?? '',
): Generator<PathCandidate> {
  if (pathVar === '') return
  for (const entry of pathVar.split(path.delimiter)) {
    yield { entry, file: path.resolve(entry === '' ? '.' : entry, bin) }
  }
}

/**
 * Find the path to an executable, as the `which` command would, without
 * running one: a `which` program is itself found through `PATH`, so running
 * it executes whatever file of that name comes first there. The search is
 * done in this process, identically under Node.js and Bun: the first `PATH`
 * entry holding a regular file of that name this process may execute.
 *
 * `Bun.which` is not used although it also runs nothing. Called without an
 * explicit `PATH` it searches the one the process started with, not the
 * current `process.env.PATH` a spawned child inherits, and it passes over an
 * empty entry, which POSIX reads as the current directory. One search for
 * both runtimes means they cannot come to disagree about what is found.
 *
 * A name with a directory part is checked where it is and returned as given.
 *
 * Every `PATH` entry counts, the ones a sandboxed command may write among
 * them, so this is for a program that will run with the sandbox's authority.
 * One the library runs on the host is found with `findHostHelper`.
 *
 * @param bin - The name of the executable to find
 * @returns The full path to the executable, or null if not found
 */
export function whichSync(bin: string): string | null {
  if (isPathQualified(bin)) {
    return isExecutableFile(bin) ? bin : null
  }
  for (const { file } of pathCandidates(bin)) {
    if (isExecutableFile(file)) return file
  }
  return null
}
