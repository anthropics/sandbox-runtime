import { describe, test, expect, beforeEach, afterEach, spyOn } from 'bun:test'
import * as which from '../../src/utils/which.js'
import * as platform from '../../src/utils/platform.js'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'

// SandboxManager.checkDependencies() must only require ripgrep on Linux,
// where linuxGetMandatoryDenyPaths() actually invokes it. macOS seatbelt
// profiles take regex patterns directly and never spawn rg — see #156.

let whichSpy: ReturnType<typeof spyOn>
let platformSpy: ReturnType<typeof spyOn>

beforeEach(() => {
  whichSpy = spyOn(which, 'whichSync')
  platformSpy = spyOn(platform, 'getPlatform')
})

afterEach(() => {
  whichSpy.mockRestore()
  platformSpy.mockRestore()
})

describe('SandboxManager.checkDependencies: ripgrep', () => {
  test('macOS: no error when rg is missing', () => {
    platformSpy.mockReturnValue('macos')
    whichSpy.mockImplementation((bin: string) =>
      bin === 'rg' ? null : `/usr/bin/${bin}`,
    )

    const result = SandboxManager.checkDependencies()

    expect(result.errors).not.toContain('ripgrep (rg) not found')
  })

  test('linux: errors when rg is missing', () => {
    platformSpy.mockReturnValue('linux')
    whichSpy.mockImplementation((bin: string) =>
      bin === 'rg' ? null : `/usr/bin/${bin}`,
    )

    const result = SandboxManager.checkDependencies()

    expect(result.errors).toContain('ripgrep (rg) not found')
  })

  test('linux: honours explicit ripgrepConfig.command', () => {
    platformSpy.mockReturnValue('linux')
    whichSpy.mockImplementation((bin: string) =>
      bin === 'custom-rg' ? null : `/usr/bin/${bin}`,
    )

    const result = SandboxManager.checkDependencies({ command: 'custom-rg' })

    expect(result.errors).toContain('ripgrep (custom-rg) not found')
  })
})

describe('SandboxManager.checkDependenciesAsync', () => {
  test('returns a Promise and matches the sync result (POSIX)', async () => {
    platformSpy.mockReturnValue('linux')
    whichSpy.mockImplementation((bin: string) =>
      bin === 'rg' ? null : `/usr/bin/${bin}`,
    )

    const p = SandboxManager.checkDependenciesAsync()
    expect(p).toBeInstanceOf(Promise)
    expect(await p).toEqual(SandboxManager.checkDependencies())
  })

  test('honours explicit ripgrepConfig.command', async () => {
    platformSpy.mockReturnValue('linux')
    whichSpy.mockImplementation((bin: string) =>
      bin === 'custom-rg' ? null : `/usr/bin/${bin}`,
    )

    const result = await SandboxManager.checkDependenciesAsync({
      command: 'custom-rg',
    })

    expect(result.errors).toContain('ripgrep (custom-rg) not found')
  })
})
