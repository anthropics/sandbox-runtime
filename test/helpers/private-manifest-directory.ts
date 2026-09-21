import { afterAll, beforeAll } from 'bun:test'
import { chmodSync, mkdtempSync, realpathSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { forgetMountPointManifestDirectory } from '../../src/sandbox/bwrap-mount-manifests.js'
import { cleanupBwrapMountPoints } from '../../src/sandbox/linux-sandbox-utils.js'

/**
 * Gives the enclosing `describe` a runtime directory of its own for the mount
 * point manifests, for as long as its tests run.
 *
 * The manifests of every srt process of a user live in one directory, and a
 * collect reads, judges and removes all of them. A test that lists that
 * directory, attacks it from inside a sandbox or asserts on what is left in it
 * would otherwise be doing so to whatever else that user is running on the
 * machine, and be failed by it in turn. `$XDG_RUNTIME_DIR` is where the library
 * looks first, and child processes inherit it, so pointing it at a fresh
 * directory moves this process and everything it spawns at once.
 *
 * It also starts the `describe` with no wrap of this process outstanding, and
 * leaves it so. The library counts the wraps it has handed out and releases
 * nothing of this process's until each has been cleaned up after; the count is
 * the module's, shared by every test file of one run, and other suites wrap
 * without cleaning up. A test that expects one clean-up to take its mount point
 * away would otherwise pass or fail by which file ran before it.
 *
 * Call it inside the `describe` callback. Returns where the manifests go.
 */
export function usePrivateManifestDirectory(): { manifestDir(): string } {
  const saved = process.env.XDG_RUNTIME_DIR
  let runtimeDir: string | undefined

  beforeAll(() => {
    // In the directory the earlier suites used, before it is left behind.
    cleanupBwrapMountPoints({ force: true })
    runtimeDir = realpathSync(mkdtempSync(join(tmpdir(), 'srt-test-runtime-')))
    chmodSync(runtimeDir, 0o700)
    process.env.XDG_RUNTIME_DIR = runtimeDir
    forgetMountPointManifestDirectory()
  })

  afterAll(() => {
    cleanupBwrapMountPoints({ force: true })
    if (saved === undefined) delete process.env.XDG_RUNTIME_DIR
    else process.env.XDG_RUNTIME_DIR = saved
    forgetMountPointManifestDirectory()
    if (runtimeDir !== undefined) {
      rmSync(runtimeDir, { recursive: true, force: true })
    }
  })

  return {
    manifestDir: () => {
      if (runtimeDir === undefined) {
        throw new Error('asked for before the tests began')
      }
      return join(runtimeDir, 'srt-mount-points')
    },
  }
}
