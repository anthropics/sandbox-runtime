import { describe, test, expect, beforeEach, afterEach, spyOn } from 'bun:test'
import { readFileSync } from 'node:fs'
import * as which from '../../src/utils/which.js'
import * as seccomp from '../../src/sandbox/generate-seccomp-filter.js'
import {
  capabilityArgs,
  checkLinuxDependencies,
  getLinuxDependencyStatus,
} from '../../src/sandbox/linux-sandbox-utils.js'

// checkLinuxDependencies reads the real process's permitted set, so gate the
// uid-0 warning test on this process not already holding CAP_SETFCAP (bit
// 31). True for a non-root CI user, and on platforms without /proc.
const lacksSetfcap = (() => {
  try {
    const capPrm = readFileSync('/proc/self/status', 'utf8').match(
      /^CapPrm:\s*([0-9a-fA-F]+)/m,
    )
    return capPrm ? ((BigInt('0x' + capPrm[1]) >> 31n) & 1n) === 0n : true
  } catch {
    return true
  }
})()

// Spies set up in beforeEach, torn down in afterEach. Each test overrides
// just the piece it's exercising. spyOn patches the export binding, so
// linux-sandbox-utils' own imports see the replacement.
let whichSpy: ReturnType<typeof spyOn>
let applySpy: ReturnType<typeof spyOn>

beforeEach(() => {
  whichSpy = spyOn(which, 'whichSync').mockImplementation(
    (bin: string) => `/usr/bin/${bin}`,
  )
  applySpy = spyOn(seccomp, 'getApplySeccompBinaryPath').mockReturnValue(
    '/path/to/apply-seccomp',
  )
})

afterEach(() => {
  whichSpy.mockRestore()
  applySpy.mockRestore()
})

describe('checkLinuxDependencies', () => {
  test('returns no errors or warnings when all dependencies present', () => {
    const result = checkLinuxDependencies()

    expect(result.errors).toEqual([])
    expect(result.warnings).toEqual([])
  })

  test('returns error when bwrap missing', () => {
    whichSpy.mockImplementation((bin: string) =>
      bin === 'bwrap' ? null : `/usr/bin/${bin}`,
    )

    const result = checkLinuxDependencies()

    expect(result.errors).toContain('bubblewrap (bwrap) not installed')
    expect(result.errors.length).toBe(1)
  })

  test('returns error when socat missing', () => {
    whichSpy.mockImplementation((bin: string) =>
      bin === 'socat' ? null : `/usr/bin/${bin}`,
    )

    const result = checkLinuxDependencies()

    expect(result.errors).toContain('socat not installed')
    expect(result.errors.length).toBe(1)
  })

  test('returns multiple errors when both bwrap and socat missing', () => {
    whichSpy.mockReturnValue(null)

    const result = checkLinuxDependencies()

    expect(result.errors).toContain('bubblewrap (bwrap) not installed')
    expect(result.errors).toContain('socat not installed')
    expect(result.errors.length).toBe(2)
  })

  test('returns warning when apply-seccomp missing', () => {
    applySpy.mockReturnValue(null)

    const result = checkLinuxDependencies()

    expect(result.warnings).toContain(
      'seccomp not available - unix socket access not restricted',
    )
  })

  test.if(typeof process.geteuid === 'function' && lacksSetfcap)(
    'warns when a uid-0 caller has no CAP_SETFCAP',
    () => {
      using euidSpy = spyOn(process, 'geteuid').mockReturnValue(0)

      const result = checkLinuxDependencies()

      expect(euidSpy).toHaveBeenCalled()
      expect(result.errors).toEqual([])
      expect(result.warnings.find(w => w.includes('CAP_SETFCAP'))).toMatch(
        /uid 0.*non-root user/s,
      )
    },
  )

  test('passes custom applyPath through to the resolver', () => {
    checkLinuxDependencies({ seccompConfig: { applyPath: '/custom/apply' } })

    expect(applySpy).toHaveBeenCalledWith('/custom/apply')
  })

  test('argv0 mode: no seccomp warning even when binary lookup would fail', () => {
    applySpy.mockReturnValue(null)

    const result = checkLinuxDependencies({
      seccompConfig: {
        argv0: 'apply-seccomp',
        applyPath: '/proc/self/fd/3',
      },
    })

    expect(result.warnings).toEqual([])
    expect(applySpy).not.toHaveBeenCalled()
  })

  test('explicit bwrapPath: skips PATH lookup, errors when not executable', () => {
    const result = checkLinuxDependencies({ bwrapPath: '/no/such/bwrap' })

    expect(result.errors).toContain(
      'bubblewrap (bwrap) not executable at /no/such/bwrap',
    )
    // socat still falls back to PATH
    expect(result.errors.length).toBe(1)
    expect(whichSpy).not.toHaveBeenCalledWith('bwrap')
  })

  test('explicit socatPath: skips PATH lookup, errors when not executable', () => {
    const result = checkLinuxDependencies({ socatPath: '/no/such/socat' })

    expect(result.errors).toContain('socat not executable at /no/such/socat')
    expect(whichSpy).not.toHaveBeenCalledWith('socat')
  })

  test('explicit bwrapPath: ok when path is executable', () => {
    // /bin/sh exists and is executable on every Linux system
    const result = checkLinuxDependencies({ bwrapPath: '/bin/sh' })

    expect(result.errors).toEqual([])
    expect(whichSpy).not.toHaveBeenCalledWith('bwrap')
  })
})

describe('capabilityArgs', () => {
  test('non-root caller: drops everything, never adds', () => {
    for (const usesSeccompHelper of [true, false]) {
      expect(
        capabilityArgs({ euid: 1000, hasSetfcap: true, usesSeccompHelper }),
      ).toEqual(['--cap-drop', 'ALL'])
    }
  })

  test('uid 0 under the helper, holding CAP_SETFCAP: keeps it', () => {
    expect(
      capabilityArgs({ euid: 0, hasSetfcap: true, usesSeccompHelper: true }),
    ).toEqual(['--cap-drop', 'ALL', '--cap-add', 'CAP_SETFCAP'])
  })

  test('uid 0 without the helper: nothing to keep it for', () => {
    expect(
      capabilityArgs({ euid: 0, hasSetfcap: true, usesSeccompHelper: false }),
    ).toEqual(['--cap-drop', 'ALL'])
  })

  test('uid 0 missing CAP_SETFCAP: adds nothing and warns', () => {
    using warnSpy = spyOn(console, 'warn').mockImplementation(() => {})
    const debug = process.env.SRT_DEBUG
    process.env.SRT_DEBUG = '1'
    try {
      for (const usesSeccompHelper of [true, false]) {
        expect(
          capabilityArgs({ euid: 0, hasSetfcap: false, usesSeccompHelper }),
        ).toEqual(['--cap-drop', 'ALL'])
      }
    } finally {
      if (debug === undefined) delete process.env.SRT_DEBUG
      else process.env.SRT_DEBUG = debug
    }

    expect(warnSpy).toHaveBeenCalledTimes(2)
    expect(warnSpy.mock.calls[0]?.[0]).toMatch(
      /uid 0 without CAP_SETFCAP.*non-root user/s,
    )
  })
})

describe('getLinuxDependencyStatus', () => {
  test('reports all available when everything installed', () => {
    const status = getLinuxDependencyStatus()

    expect(status.hasBwrap).toBe(true)
    expect(status.hasSocat).toBe(true)
    expect(status.hasSeccompApply).toBe(true)
  })

  test('reports bwrap unavailable when not installed', () => {
    whichSpy.mockImplementation((bin: string) =>
      bin === 'bwrap' ? null : `/usr/bin/${bin}`,
    )

    const status = getLinuxDependencyStatus()

    expect(status.hasBwrap).toBe(false)
    expect(status.hasSocat).toBe(true)
  })

  test('reports socat unavailable when not installed', () => {
    whichSpy.mockImplementation((bin: string) =>
      bin === 'socat' ? null : `/usr/bin/${bin}`,
    )

    const status = getLinuxDependencyStatus()

    expect(status.hasSocat).toBe(false)
    expect(status.hasBwrap).toBe(true)
  })

  test('reports seccomp unavailable when apply binary missing', () => {
    applySpy.mockReturnValue(null)

    const status = getLinuxDependencyStatus()

    expect(status.hasSeccompApply).toBe(false)
    expect(status.hasBwrap).toBe(true)
    expect(status.hasSocat).toBe(true)
  })

  test('argv0 mode: hasSeccompApply is true without touching disk', () => {
    applySpy.mockReturnValue(null)

    const status = getLinuxDependencyStatus({
      seccompConfig: {
        argv0: 'apply-seccomp',
        applyPath: '/does/not/exist',
      },
    })

    expect(status.hasSeccompApply).toBe(true)
    expect(applySpy).not.toHaveBeenCalled()
  })

  test('explicit binary paths bypass PATH lookup', () => {
    whichSpy.mockReturnValue(null)

    const status = getLinuxDependencyStatus({
      bwrapPath: '/bin/sh',
      socatPath: '/no/such/socat',
    })

    expect(status.hasBwrap).toBe(true)
    expect(status.hasSocat).toBe(false)
    expect(whichSpy).not.toHaveBeenCalledWith('bwrap')
    expect(whichSpy).not.toHaveBeenCalledWith('socat')
  })
})
