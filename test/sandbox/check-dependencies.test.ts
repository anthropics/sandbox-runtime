import { describe, test, expect, beforeEach, afterEach, spyOn } from 'bun:test'
import * as which from '../../src/utils/which.js'
import * as platform from '../../src/utils/platform.js'
import * as linux from '../../src/sandbox/linux-sandbox-utils.js'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import type { SandboxRuntimeConfig } from '../../src/sandbox/sandbox-config.js'

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

// What the Linux check finds about the limit on user namespaces is read here,
// as data, and this is the one place where that check and the wrap are both
// fed from the configuration. Lose an option on the way and the check reports
// a limit that the wrap, which does get the option, does not impose.
describe('SandboxManager.checkDependencies: the limit on user namespaces', () => {
  const OPTIONS = [
    'allowAllUnixSockets',
    'allowNestedUserNamespaces',
    'enableWeakerNestedSandbox',
  ] as const
  const configured = (
    on: readonly (typeof OPTIONS)[number][],
  ): SandboxRuntimeConfig => ({
    network: {
      allowedDomains: [],
      deniedDomains: [],
      allowAllUnixSockets: on.includes('allowAllUnixSockets') || undefined,
    },
    filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    allowNestedUserNamespaces:
      on.includes('allowNestedUserNamespaces') || undefined,
    enableWeakerNestedSandbox:
      on.includes('enableWeakerNestedSandbox') || undefined,
  })
  // The configuration outlives a reset, and so this file's tests.
  let before: SandboxRuntimeConfig | undefined

  beforeEach(() => {
    platformSpy.mockReturnValue('linux')
    before = SandboxManager.getConfig()
  })

  afterEach(() => {
    SandboxManager.updateConfig(before ?? configured([]))
  })

  test('hands the Linux check each option from its own place in the configuration, and hands on what the check found', async () => {
    const found = {
      errors: [],
      warnings: ['said by the Linux check'],
      features: { usernsLimit: 'unknown' as const },
      details: [
        {
          code: 'helper_lacks_userns_limit' as const,
          level: 'warning' as const,
          message: 'said by the Linux check',
        },
      ],
    }
    const linuxSpy = spyOn(linux, 'checkLinuxDependencies').mockReturnValue(
      found,
    )
    try {
      for (const on of OPTIONS) {
        SandboxManager.updateConfig(configured([on]))
        for (const result of [
          SandboxManager.checkDependencies(),
          await SandboxManager.checkDependenciesAsync(),
        ]) {
          expect(result.features).toEqual(found.features)
          expect(result.details).toEqual(found.details)
          expect(result.warnings).toContain('said by the Linux check')
          const given = linuxSpy.mock.lastCall?.[0] ?? {}
          for (const option of OPTIONS) {
            expect(given[option] ?? false).toBe(option === on)
          }
        }
      }
    } finally {
      linuxSpy.mockRestore()
    }
  })

  // The same through the real check, for the two answers that do not depend
  // on what is installed.
  test('a limit the configuration gives up is reported as not in force, and as nothing to warn about', () => {
    SandboxManager.updateConfig(configured(['allowNestedUserNamespaces']))

    const result = SandboxManager.checkDependencies()

    expect(result.features).toEqual({ usernsLimit: false })
    expect(result.details).toEqual([])
  })

  test('no helper in use under enableWeakerNestedSandbox is reported by code', () => {
    SandboxManager.updateConfig(
      configured(['allowAllUnixSockets', 'enableWeakerNestedSandbox']),
    )

    const result = SandboxManager.checkDependencies()

    expect(result.features).toEqual({ usernsLimit: false })
    expect(result.details?.map(d => d.code)).toEqual([
      'no_userns_limit_in_weaker_nested_sandbox',
    ])
    expect(result.warnings).toContain(
      result.details?.[0]?.message ?? 'no such warning',
    )
  })
})
