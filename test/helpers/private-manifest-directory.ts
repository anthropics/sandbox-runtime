import { afterAll, afterEach, beforeAll } from 'bun:test'
import {
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { forgetMountPointManifestDirectory } from '../../src/sandbox/bwrap-mount-manifests.js'
import { cleanupBwrapMountPoints } from '../../src/sandbox/linux-sandbox-utils.js'

/** Field 22 of a /proc/PID/stat line: when that process started. */
const startOf = (stat: string): string | undefined =>
  stat
    .slice(stat.lastIndexOf(')') + 1)
    .trim()
    .split(' ')[19]

/**
 * Kills every bubblewrap that is still on a started record in `dir`, and its
 * sandbox with it: a test that failed half way must not leave one polling. Then
 * empties `dir`. Only bubblewrap: a test may put any process on a record, itself
 * included.
 */
function endSandboxesOnRecord(dir: string): void {
  const attempt = <T>(what: () => T): T | undefined => {
    try {
      return what()
    } catch {
      // No directory, no record, or the process is gone: nothing to end.
      return undefined
    }
  }
  for (const name of attempt(() => readdirSync(dir)) ?? []) {
    const file = join(dir, name)
    // A test may plant a FIFO there, and reading one waits for a writer.
    if (
      !name.endsWith('.started') ||
      !attempt(() => lstatSync(file).isFile())
    ) {
      continue
    }
    const record = attempt(() => readFileSync(file, 'utf8')) ?? ''
    for (const line of record.split('\n')) {
      const pid = /^\d+/.exec(line)?.[0]
      const now = attempt(() => readFileSync(`/proc/${pid}/stat`, 'utf8'))
      if (now?.includes(' (bwrap) ') && startOf(now) === startOf(line)) {
        attempt(() => process.kill(Number(pid), 'SIGKILL'))
      }
    }
  }
  for (const name of attempt(() => readdirSync(dir)) ?? []) {
    attempt(() => rmSync(join(dir, name), { recursive: true, force: true }))
  }
}

/**
 * Gives the enclosing `describe` a runtime directory and a temp dir of its own,
 * for as long as its tests run.
 *
 * The manifests of every srt process of a user live in one directory, and a
 * collect reads, judges and removes all of them, so a test that lists or
 * attacks that directory would otherwise act on whatever else the user is
 * running. The library looks under `$XDG_RUNTIME_DIR` first, and every wrap
 * that restricts writes makes the directory under the temp dir as well, so both
 * are replaced, before anything is cleaned up: nothing is made or removed in
 * the directories the user's own processes keep.
 *
 * It also starts the `describe` with no wrap of this process outstanding, and
 * leaves it so: the library's count of wraps is shared by every test file of a
 * run, and other suites wrap without cleaning up. After each test it ends
 * whatever sandbox is still on record there and empties the directory, so no
 * test finds what an earlier one left.
 *
 * Call it inside the `describe` callback. Returns where the manifests go.
 */
export function usePrivateManifestDirectory(): { manifestDir(): string } {
  const replaced = ['XDG_RUNTIME_DIR', 'TMPDIR'] as const
  const saved = replaced.map(name => process.env[name])
  let base: string | undefined

  beforeAll(() => {
    base = realpathSync(mkdtempSync(join(tmpdir(), 'srt-test-')))
    for (const name of replaced) {
      process.env[name] = join(base, name)
      mkdirSync(process.env[name], { mode: 0o700 })
    }
    forgetMountPointManifestDirectory()
    cleanupBwrapMountPoints({ force: true })
  })

  afterEach(() => {
    if (base !== undefined) {
      endSandboxesOnRecord(join(base, 'XDG_RUNTIME_DIR', 'srt-mount-points'))
    }
  })

  afterAll(() => {
    cleanupBwrapMountPoints({ force: true })
    replaced.forEach((name, i) => {
      if (saved[i] === undefined) delete process.env[name]
      else process.env[name] = saved[i]
    })
    forgetMountPointManifestDirectory()
    if (base !== undefined) {
      rmSync(base, { recursive: true, force: true })
    }
  })

  return {
    manifestDir: () => {
      if (base === undefined) {
        throw new Error('asked for before the tests began')
      }
      return join(base, 'XDG_RUNTIME_DIR', 'srt-mount-points')
    },
  }
}
