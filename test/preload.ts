import { afterAll } from 'bun:test'
import { mkdirSync, mkdtempSync, realpathSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

// Every wrap that restricts writes makes, binds and collects in the per-user
// directories the mount point manifests are kept in, under $XDG_RUNTIME_DIR and
// the temp dir. The run is given both of its own before any test file is
// loaded, so that no suite acts on what else the user is running. A `describe`
// that lists or attacks the manifests takes its own on top of these (see
// helpers/private-manifest-directory.ts).
if (process.platform === 'linux') {
  // Short names: suites keep Unix sockets beneath these, and a socket's path is
  // limited to 108 bytes.
  const base = realpathSync(mkdtempSync(join(tmpdir(), 'srt-')))
  for (const [name, dir] of [
    ['XDG_RUNTIME_DIR', 'x'],
    ['TMPDIR', 't'],
  ] as const) {
    process.env[name] = join(base, dir)
    mkdirSync(process.env[name], { mode: 0o700 })
  }
  // Once, after the last test file.
  afterAll(() => rmSync(base, { recursive: true, force: true }))
}
