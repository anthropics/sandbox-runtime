import { describe, it, expect, afterAll, beforeAll } from 'bun:test'
import { spawnSync } from 'node:child_process'
import {
  chmodSync,
  constants,
  copyFileSync,
  mkdirSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { wrapCommandWithSandboxMacOS } from '../../src/sandbox/macos-sandbox-utils.js'
import { isMacOS, isWindows } from '../helpers/platform.js'

/**
 * A read deny on a program also stops the program from running.
 *
 * Seatbelt checks `process-exec` separately from `file-read*`, and the
 * profile allows `process-exec` everywhere. A deny that named only
 * `file-read*` left a denied binary runnable by its own path: `cat` of it
 * failed, `cp` of it failed, and `/path/to/it` ran. On Linux the same
 * config hides the file, so it cannot be run there. These tests hold the
 * macOS profile to the same answer.
 *
 * The profile tests only inspect generated SBPL and run on every POSIX
 * host; the enforcement tests run the profile under sandbox-exec.
 */

/** What a copy of the runner prints for `--version` when it does run. */
const VERSION = spawnSync(process.execPath, ['--version'], {
  encoding: 'utf8',
}).stdout.trim()

interface Tree {
  root: string
  /** A copy of the runner's binary the config denies reading. */
  denied: string
  /** A second copy nothing denies: the control. */
  free: string
  /** A directory denied as a whole … */
  vault: string
  /** … with this one directory re-allowed inside it. */
  open: string
  /** A copy of the runner's binary inside the denied directory. */
  vaulted: string
  /** A copy of the runner's binary inside the re-allowed directory. */
  opened: string
  /** A shell script the config denies reading. */
  script: string
}

function makeTree(prefix: string): Tree {
  const root = join(realpathSync(tmpdir()), `${prefix}-${Date.now()}`)
  const vault = join(root, 'vault')
  const open = join(vault, 'open')
  mkdirSync(open, { recursive: true })
  const tree: Tree = {
    root,
    denied: join(root, 'denied-bin'),
    free: join(root, 'free-bin'),
    vault,
    open,
    vaulted: join(vault, 'bin'),
    opened: join(open, 'bin'),
    script: join(root, 'denied-script'),
  }
  if (isMacOS) {
    for (const copy of [tree.denied, tree.free, tree.vaulted, tree.opened]) {
      // The runner's own binary: macOS kills a copy of a system binary
      // such as /bin/echo before it runs, sandbox or none. Cloned where
      // the volume can, so four copies cost nothing.
      copyFileSync(process.execPath, copy, constants.COPYFILE_FICLONE)
      chmodSync(copy, 0o755)
    }
  }
  writeFileSync(tree.script, '#!/bin/sh\necho script-ran\n')
  chmodSync(tree.script, 0o755)
  return tree
}

function wrap(tree: Tree, command: string): string {
  return wrapCommandWithSandboxMacOS({
    command,
    needsNetworkRestriction: false,
    readConfig: {
      denyOnly: [tree.denied, tree.script, tree.vault],
      allowWithinDeny: [tree.open],
    },
    writeConfig: { allowOnly: [tree.root], denyWithinAllow: [] },
  })
}

function run(tree: Tree, command: string) {
  const result = spawnSync(wrap(tree, command), {
    shell: true,
    encoding: 'utf8',
    timeout: 15000,
  })
  return {
    status: result.status,
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
  }
}

describe.if(!isWindows)('macOS profile: a read deny covers exec', () => {
  let tree: Tree

  beforeAll(() => {
    tree = makeTree('read-deny-exec-profile')
  })

  afterAll(() => {
    rmSync(tree.root, { recursive: true, force: true })
  })

  it('denies exec and executable mapping with every read deny', () => {
    const profile = wrap(tree, 'true')
    expect(profile).toContain(
      '(deny file-read* process-exec* file-map-executable\n',
    )
    // No read deny is left that names reading alone.
    expect(profile).not.toContain('(deny file-read*\n')
  })

  it('gives exec back with a re-allow inside a deny', () => {
    const profile = wrap(tree, 'true')
    expect(profile).toContain(
      '(allow file-read* process-exec* file-map-executable\n',
    )
    expect(profile).not.toContain('(allow file-read*\n')
  })

  it('leaves exec alone when nothing is read-denied', () => {
    const profile = wrapCommandWithSandboxMacOS({
      command: 'true',
      needsNetworkRestriction: false,
      readConfig: { denyOnly: [], allowWithinDeny: [] },
      writeConfig: { allowOnly: [tree.root], denyWithinAllow: [] },
    })
    expect(profile).toContain('(allow process-exec)')
    expect(profile).not.toContain('process-exec*')
  })
})

describe.if(isMacOS)('macOS enforcement: a read-denied program', () => {
  let tree: Tree

  beforeAll(() => {
    tree = makeTree('read-deny-exec-run')
  })

  afterAll(() => {
    rmSync(tree.root, { recursive: true, force: true })
  })

  it('runs when nothing denies it (the control)', () => {
    const result = run(tree, `${JSON.stringify(tree.free)} --version`)
    expect(result.status).toBe(0)
    expect(result.stdout.trim()).toBe(VERSION)
  })

  it('does not run when named by its path', () => {
    const result = run(tree, `${JSON.stringify(tree.denied)} --version`)
    expect(result.status).not.toBe(0)
    expect(result.stdout).not.toContain(VERSION)
    expect(result.stderr).toContain('Operation not permitted')
  })

  it('does not run through env, a link, or another shell', () => {
    const link = join(tree.root, 'link-to-denied')
    symlinkSync(tree.denied, link)
    for (const command of [
      `/usr/bin/env ${JSON.stringify(tree.denied)} --version`,
      `${JSON.stringify(link)} --version`,
      `/bin/sh -c '${tree.denied} --version'`,
    ]) {
      const result = run(tree, command)
      expect(result.status).not.toBe(0)
      expect(result.stdout).not.toContain(VERSION)
    }
  })

  it('does not run as a script by its interpreter line', () => {
    const result = run(tree, JSON.stringify(tree.script))
    expect(result.status).not.toBe(0)
    expect(result.stdout).not.toContain('script-ran')
  })

  it('cannot be copied out and run', () => {
    const copy = join(tree.root, 'copied-bin')
    const result = run(
      tree,
      `cp ${JSON.stringify(tree.denied)} ${JSON.stringify(copy)} && ${JSON.stringify(copy)} --version`,
    )
    expect(result.status).not.toBe(0)
    expect(result.stdout).not.toContain(VERSION)
  })

  it('does not run from inside a denied directory', () => {
    const result = run(tree, `${JSON.stringify(tree.vaulted)} --version`)
    expect(result.status).not.toBe(0)
    expect(result.stdout).not.toContain(VERSION)
  })

  it('runs from a directory re-allowed inside the denied one', () => {
    const result = run(tree, `${JSON.stringify(tree.opened)} --version`)
    expect(result.status).toBe(0)
    expect(result.stdout.trim()).toBe(VERSION)
  })
})
