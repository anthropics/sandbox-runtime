import { afterEach, describe, expect, it } from 'bun:test'
import {
  chmodSync,
  lstatSync,
  mkdtempSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { ensureSandboxTempDirectory } from '../../src/sandbox/sandbox-temp-dir.js'

const directories: string[] = []

function tempDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), 'srt-temp-dir-'))
  directories.push(directory)
  return directory
}

afterEach(() => {
  for (const directory of directories.splice(0)) {
    rmSync(directory, { recursive: true, force: true })
  }
})

describe.skipIf(process.platform === 'win32')('ensureSandboxTempDirectory', () => {
  it('creates a private directory and accepts it on subsequent calls', () => {
    const directory = join(tempDirectory(), 'agents')
    ensureSandboxTempDirectory(directory)
    ensureSandboxTempDirectory(directory)

    const stat = lstatSync(directory)
    expect(stat.isDirectory()).toBe(true)
    expect(stat.mode & 0o777).toBe(0o700)
    writeFileSync(join(directory, 'temp-file'), 'ok')
  })

  it('rejects a symlink without changing its target', () => {
    const parent = tempDirectory()
    const target = join(parent, 'target')
    ensureSandboxTempDirectory(target)
    const link = join(parent, 'agents')
    symlinkSync(target, link)

    expect(() => ensureSandboxTempDirectory(link)).toThrow('real directory')
    expect(lstatSync(target).mode & 0o777).toBe(0o700)
  })

  it('rejects a path occupied by a file', () => {
    const file = join(tempDirectory(), 'agents')
    writeFileSync(file, 'existing')

    expect(() => ensureSandboxTempDirectory(file)).toThrow()
  })

  it('rejects directories writable by other users without changing permissions', () => {
    const directory = join(tempDirectory(), 'agents')
    ensureSandboxTempDirectory(directory)
    chmodSync(directory, 0o777)

    expect(() => ensureSandboxTempDirectory(directory)).toThrow(
      'writable by other users',
    )
    expect(lstatSync(directory).mode & 0o777).toBe(0o777)
  })
})
