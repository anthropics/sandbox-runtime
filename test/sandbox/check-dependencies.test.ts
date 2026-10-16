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

describe('SandboxManager.checkDependencies: seccomp', () => {
  let applySpy: ReturnType<typeof spyOn>

  beforeEach(() => {
    platformSpy.mockReturnValue('linux')
    whichSpy.mockImplementation((bin: string) => `/usr/bin/${bin}`)
    applySpy = spyOn(seccomp, 'getApplySeccompBinaryPath').mockImplementation(
      (path?: string) =>
        path === '/custom/apply-seccomp' ? '/custom/apply-seccomp' : null,
    )
  })

  afterEach(() => {
    applySpy.mockRestore()
  })

  test('linux: warns when seccomp helper missing without explicit config', () => {
    const result = SandboxManager.checkDependencies()
    expect(result.warnings).toContain(
      'seccomp not available - unix socket access not restricted',
    )
  })

  test('linux: honours explicit seccompConfig.applyPath', () => {
    const result = SandboxManager.checkDependencies(undefined, {
      applyPath: '/custom/apply-seccomp',
    })
    expect(result.warnings).not.toContain(
      'seccomp not available - unix socket access not restricted',
    )
  })

  test('linux: honours explicit seccompConfig.argv0', () => {
    const result = SandboxManager.checkDependencies(undefined, {
      argv0: 'custom-argv0',
    })
    expect(result.warnings).not.toContain(
      'seccomp not available - unix socket access not restricted',
    )
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

  test('linux: honours explicit seccompConfig.applyPath in async check', async () => {
    platformSpy.mockReturnValue('linux')
    whichSpy.mockImplementation((bin: string) => `/usr/bin/${bin}`)
    const applyAsyncSpy = spyOn(
      seccomp,
      'getApplySeccompBinaryPathAsync',
    ).mockResolvedValue('/custom/apply-seccomp')
    const applySyncSpy = spyOn(
      seccomp,
      'getApplySeccompBinaryPath',
    ).mockImplementation((path?: string) =>
      path === '/custom/apply-seccomp' ? '/custom/apply-seccomp' : null,
    )

    try {
      const result = await SandboxManager.checkDependenciesAsync(undefined, {
        applyPath: '/custom/apply-seccomp',
      })
      expect(applyAsyncSpy).toHaveBeenCalledWith('/custom/apply-seccomp')
      expect(result.warnings).not.toContain(
        'seccomp not available - unix socket access not restricted',
      )
    } finally {
      applyAsyncSpy.mockRestore()
      applySyncSpy.mockRestore()
    }
  })
})
