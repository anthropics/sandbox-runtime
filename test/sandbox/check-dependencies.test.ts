import { describe, test, expect, beforeEach, afterEach, spyOn } from 'bun:test'
import * as which from '../../src/utils/which.js'
import * as platform from '../../src/utils/platform.js'
import * as seccomp from '../../src/sandbox/generate-seccomp-filter.js'
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

describe('SandboxManager.checkDependencies with seccompConfig', () => {
  const customApply = '/opt/custom/apply-seccomp'
  const warning = 'seccomp not available - unix socket access not restricted'
  let seccompSpy: ReturnType<typeof spyOn>
  let seccompAsyncSpy: ReturnType<typeof spyOn>

  beforeEach(() => {
    platformSpy.mockReturnValue('linux')
    whichSpy.mockImplementation((bin: string) => `/usr/bin/${bin}`)
    // Only the caller's custom location has the helper.
    const lookup = (p?: string) => (p === customApply ? p : null)
    seccompSpy = spyOn(seccomp, 'getApplySeccompBinaryPath')
    seccompSpy.mockImplementation(lookup)
    seccompAsyncSpy = spyOn(seccomp, 'getApplySeccompBinaryPathAsync')
    seccompAsyncSpy.mockImplementation(async (p?: string) => lookup(p))
  })

  afterEach(() => {
    seccompSpy.mockRestore()
    seccompAsyncSpy.mockRestore()
  })

  test('warns when the helper is only at a custom path and none is passed', () => {
    expect(SandboxManager.checkDependencies().warnings).toContain(warning)
  })

  test('honours explicit seccompConfig.applyPath before initialize()', () => {
    const result = SandboxManager.checkDependencies(undefined, {
      applyPath: customApply,
    })
    expect(result.warnings).not.toContain(warning)
  })

  test('async: honours explicit seccompConfig.applyPath', async () => {
    const result = await SandboxManager.checkDependenciesAsync(undefined, {
      applyPath: customApply,
    })
    expect(result.warnings).not.toContain(warning)
    expect(seccompAsyncSpy).toHaveBeenCalledWith(customApply)
  })
})
