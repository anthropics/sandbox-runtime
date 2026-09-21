import { describe, it, expect, beforeEach, afterEach } from 'bun:test'
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { whichSync } from '../../src/utils/which.js'

/**
 * These tests verify the whichSync utility function.
 *
 * Note: These tests must run in isolation from linux-dependency-error.test.ts
 * which mocks the which.js module globally. Run with:
 *   bun test test/utils/which.test.ts
 *
 * The search is the same code under Node.js; which-node-test.mjs runs it there.
 */
describe('whichSync', () => {
  it('should find existing executables', () => {
    // 'ls' should exist on all Unix systems
    const result = whichSync('ls')
    expect(result).not.toBeNull()
    expect(result).toContain('/ls')
  })

  it('should return null for non-existent executables', () => {
    const result = whichSync('this-command-definitely-does-not-exist-12345')
    expect(result).toBeNull()
  })

  it('should find common tools', () => {
    // These should exist in most environments
    const bash = whichSync('bash')
    expect(bash).not.toBeNull()

    const cat = whichSync('cat')
    expect(cat).not.toBeNull()
  })

  it('agrees with Bun.which on the PATH the process started with', () => {
    // Bun.which is no longer what whichSync calls (it does not follow a
    // changed process.env.PATH), but for an unchanged PATH the two searches
    // must find the same file.
    expect(whichSync('ls')).toBe(globalThis.Bun.which('ls'))
  })
})

describe('whichSync searches PATH in this process', () => {
  let base: string
  const savedPath = process.env.PATH

  // An executable that leaves `marker` behind if anything ever runs it.
  function plant(file: string, marker: string): void {
    writeFileSync(file, `#!/bin/sh\necho ran > '${marker}'\nexit 0\n`)
    chmodSync(file, 0o755)
  }

  beforeEach(() => {
    base = realpathSync(mkdtempSync(join(tmpdir(), 'which-test-')))
  })

  afterEach(() => {
    process.env.PATH = savedPath
    rmSync(base, { recursive: true, force: true })
  })

  it('runs no `which` program: one planted first on PATH is never executed', () => {
    const planted = join(base, 'planted')
    const marker = join(base, 'which-was-run')
    mkdirSync(planted)
    plant(join(planted, 'which'), marker)
    process.env.PATH = `${planted}:${savedPath}`

    const sh = whichSync('sh')

    expect(existsSync(marker)).toBe(false)
    expect(sh).not.toBeNull()
    expect(sh).toMatch(/\/sh$/)
    expect(sh!.startsWith(planted)).toBe(false)
  })

  it('takes the first entry holding an executable regular file of that name', () => {
    const asDirectory = join(base, 'as-directory')
    const notExecutable = join(base, 'not-executable')
    const first = join(base, 'first')
    const second = join(base, 'second')
    mkdirSync(join(asDirectory, 'tool'), { recursive: true })
    mkdirSync(notExecutable)
    writeFileSync(join(notExecutable, 'tool'), '#!/bin/sh\n')
    chmodSync(join(notExecutable, 'tool'), 0o644)
    for (const dir of [first, second]) {
      mkdirSync(dir)
      plant(join(dir, 'tool'), join(base, 'unused'))
    }
    process.env.PATH = [asDirectory, notExecutable, first, second].join(':')

    expect(whichSync('tool')).toBe(join(first, 'tool'))
  })

  it('checks a name with a directory part where it is, without searching', () => {
    const elsewhere = join(base, 'elsewhere')
    const onPath = join(base, 'on-path')
    mkdirSync(elsewhere)
    mkdirSync(join(onPath, 'sub'), { recursive: true })
    plant(join(elsewhere, 'tool'), join(base, 'unused'))
    plant(join(onPath, 'sub', 'tool'), join(base, 'unused'))
    process.env.PATH = onPath

    // Returned as given when it is an executable file, PATH or no PATH.
    expect(whichSync(join(elsewhere, 'tool'))).toBe(join(elsewhere, 'tool'))
    expect(whichSync(process.execPath)).toBe(process.execPath)
    expect(whichSync(join(elsewhere, 'absent'))).toBeNull()
    expect(whichSync('/path/that/does/not/exist')).toBeNull()
    // A relative name with a directory part is relative to the working
    // directory, never to a PATH entry.
    expect(whichSync('sub/tool')).toBeNull()
    // A directory is not an executable file.
    expect(whichSync(elsewhere)).toBeNull()
  })

  it('finds nothing on an empty or unset PATH, or for a name that is nowhere', () => {
    const dir = join(base, 'dir')
    mkdirSync(dir)
    plant(join(dir, 'tool'), join(base, 'unused'))

    process.env.PATH = dir
    expect(whichSync('tool')).toBe(join(dir, 'tool'))
    expect(whichSync('tool-that-is-nowhere')).toBeNull()

    process.env.PATH = ''
    expect(whichSync('tool')).toBeNull()

    delete process.env.PATH
    expect(whichSync('tool')).toBeNull()
  })

  it('reads an empty entry as the current directory and answers with an absolute path', () => {
    const dir = join(base, 'cwd')
    mkdirSync(dir)
    plant(join(dir, 'tool'), join(base, 'unused'))
    const savedCwd = process.cwd()
    process.chdir(dir)
    try {
      process.env.PATH = ':/nonexistent-for-test'
      expect(whichSync('tool')).toBe(join(dir, 'tool'))
      process.env.PATH = '.'
      expect(whichSync('tool')).toBe(join(dir, 'tool'))
    } finally {
      process.chdir(savedCwd)
    }
  })

  it('follows a PATH changed in this process, as a spawned child would', () => {
    const dir = join(base, 'added-later')
    mkdirSync(dir)
    plant(join(dir, 'tool-added-later'), join(base, 'unused'))

    expect(whichSync('tool-added-later')).toBeNull()
    process.env.PATH = `${dir}:${savedPath}`
    expect(whichSync('tool-added-later')).toBe(join(dir, 'tool-added-later'))
  })
})
