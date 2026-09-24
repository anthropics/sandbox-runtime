import { describe, test, expect, beforeEach, afterEach, spyOn } from 'bun:test'
import * as childProcess from 'node:child_process'
import * as which from '../../src/utils/which.js'
import * as seccomp from '../../src/sandbox/generate-seccomp-filter.js'
import {
  CAP_SETFCAP,
  CAP_SETFCAP_MISSING_MESSAGE,
  boundingCapabilitiesFromStatus,
  capabilityArgs,
  checkLinuxDependencies,
  getLinuxDependencyStatus,
  processHasBoundingCapability,
  uid0SandboxError,
} from '../../src/sandbox/linux-sandbox-utils.js'

// The uid-0 path reads this process's real bounding set, so gate the tests
// that need it absent on the same predicate the code uses. True for a
// bounding set without CAP_SETFCAP, and on platforms without /proc.
const lacksSetfcap = !processHasBoundingCapability(CAP_SETFCAP)

// Spies set up in beforeEach, torn down in afterEach. Each test overrides
// just the piece it's exercising. spyOn patches the export binding, so
// linux-sandbox-utils' own imports see the replacement.
let whichSpy: ReturnType<typeof spyOn>
let applySpy: ReturnType<typeof spyOn>
let euidSpy: ReturnType<typeof spyOn> | undefined
let spawnSyncSpy: ReturnType<typeof spyOn>

// A bwrap that exits `status`, so the uid-0 probe never runs a real binary.
const bwrapExiting = (status: number, stderr = '') =>
  ({ status, signal: null, pid: 1, output: [], stdout: '', stderr }) as never

beforeEach(() => {
  whichSpy = spyOn(which, 'whichSync').mockImplementation(
    (bin: string) => `/usr/bin/${bin}`,
  )
  applySpy = spyOn(seccomp, 'getApplySeccompBinaryPath').mockReturnValue(
    '/path/to/apply-seccomp',
  )
  // Pin the euid so only the tests that ask for uid 0 reach that branch;
  // otherwise the result depends on who runs the suite.
  euidSpy = process.geteuid
    ? spyOn(process, 'geteuid').mockReturnValue(1000)
    : undefined
  spawnSyncSpy = spyOn(childProcess, 'spawnSync').mockReturnValue(
    bwrapExiting(0),
  )
})

afterEach(() => {
  whichSpy.mockRestore()
  applySpy.mockRestore()
  euidSpy?.mockRestore()
  spawnSyncSpy.mockRestore()
})

describe('checkLinuxDependencies', () => {
  test('returns no errors or warnings when all dependencies present', () => {
    const result = checkLinuxDependencies()

    expect(result.errors).toEqual([])
    expect(result.warnings).toEqual([])
    // A non-root caller is never asked about capabilities.
    expect(spawnSyncSpy).not.toHaveBeenCalled()
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

  // Wired both ways without gating on the box: a uid-0 caller probes exactly
  // when this process's own bounding set lacks CAP_SETFCAP.
  test.if(process.geteuid !== undefined)(
    'a uid-0 caller probes bubblewrap iff its bounding set lacks CAP_SETFCAP',
    () => {
      euidSpy?.mockReturnValue(0)
      whichSpy.mockImplementation((bin: string) =>
        bin === 'bwrap' ? '/usr/bin/bwrap-wiring' : `/usr/bin/${bin}`,
      )

      const result = checkLinuxDependencies()

      expect(spawnSyncSpy.mock.calls.length > 0).toBe(lacksSetfcap)
      expect(result.errors).toEqual([])
      expect(result.warnings).toEqual([])
    },
  )

  test('a missing bwrap is blamed on the binary, not on capabilities', () => {
    euidSpy?.mockReturnValue(0)
    whichSpy.mockImplementation((bin: string) =>
      bin === 'bwrap' ? null : `/usr/bin/${bin}`,
    )

    const result = checkLinuxDependencies()

    expect(result.errors).toEqual(['bubblewrap (bwrap) not installed'])
    expect(spawnSyncSpy).not.toHaveBeenCalled()
  })

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

// The euid, the capability and bubblewrap's own verdict are all injected
// here, so these run on any box whatever capabilities the suite holds.
describe('uid0SandboxError', () => {
  const REFUSAL = 'bwrap: setting up uid map: Operation not permitted'

  test('uid 0 without CAP_SETFCAP, bubblewrap refuses: the named error', () => {
    spawnSyncSpy.mockReturnValue(bwrapExiting(1, `${REFUSAL}\n`))

    expect(
      uid0SandboxError({
        euid: 0,
        hasSetfcap: false,
        bwrap: '/usr/bin/bwrap-refuses',
      }),
    ).toBe(`${CAP_SETFCAP_MISSING_MESSAGE} (bubblewrap: ${REFUSAL})`)
    expect(spawnSyncSpy.mock.calls[0]?.[1]).toEqual([
      '--unshare-user',
      '--dev-bind',
      '/',
      '/',
      'true',
    ])
  })

  test('uid 0 without CAP_SETFCAP on a kernel that maps uid 0 anyway: nothing', () => {
    spawnSyncSpy.mockReturnValue(bwrapExiting(0))

    expect(
      uid0SandboxError({
        euid: 0,
        hasSetfcap: false,
        bwrap: '/usr/bin/bwrap-allows',
      }),
    ).toBeNull()
    expect(spawnSyncSpy).toHaveBeenCalled()
  })

  test('the probe that cannot run leaves the prediction unaided', () => {
    spawnSyncSpy.mockReturnValue({
      status: null,
      signal: 'SIGTERM',
      pid: 1,
      output: [],
      stdout: '',
      stderr: '',
      error: new Error('spawnSync ETIMEDOUT'),
    } as never)

    expect(
      uid0SandboxError({
        euid: 0,
        hasSetfcap: false,
        bwrap: '/usr/bin/bwrap-timeout',
      }),
    ).toBe(CAP_SETFCAP_MISSING_MESSAGE)
  })

  test('probes each bwrap at most once, however often it is asked', () => {
    spawnSyncSpy.mockReturnValue(bwrapExiting(1, REFUSAL))
    const args = {
      euid: 0,
      hasSetfcap: false,
      bwrap: '/usr/bin/bwrap-probed-once',
    }

    expect(uid0SandboxError(args)).toBe(uid0SandboxError(args))
    expect(spawnSyncSpy).toHaveBeenCalledTimes(1)
  })

  test('nothing to report without all three of uid 0, no capability, a bwrap', () => {
    expect(
      uid0SandboxError({ euid: 1000, hasSetfcap: false, bwrap: '/usr/bin/b' }),
    ).toBeNull()
    expect(
      uid0SandboxError({ euid: undefined, hasSetfcap: false, bwrap: '/x' }),
    ).toBeNull()
    expect(
      uid0SandboxError({ euid: 0, hasSetfcap: true, bwrap: '/usr/bin/b' }),
    ).toBeNull()
    expect(
      uid0SandboxError({ euid: 0, hasSetfcap: false, bwrap: null }),
    ).toBeNull()
    expect(spawnSyncSpy).not.toHaveBeenCalled()
  })
})

// bwrap is reached by execve, and for a euid-0 caller the kernel recomputes
// the permitted set from CapBnd | CapInh. CapPrm is therefore not the answer.
describe('boundingCapabilitiesFromStatus', () => {
  const status = ({
    bnd,
    inh = '0000000000000000',
    prm = '0000000000000000',
  }: {
    bnd: string
    inh?: string
    prm?: string
  }) =>
    `Name:\tsrt\nCapInh:\t${inh}\nCapPrm:\t${prm}\nCapEff:\t${prm}\nCapBnd:\t${bnd}\n`
  const WITH = '00000000a82c75fb' // bit 31 set
  const WITHOUT = '00000000282c75fb' // same, bit 31 cleared
  const hasSetfcap = (s: string) =>
    (((boundingCapabilitiesFromStatus(s) ?? 0n) >> BigInt(CAP_SETFCAP)) &
      1n) ===
    1n

  test('bounding set has it, permitted set does not: exec restores it', () => {
    expect(hasSetfcap(status({ bnd: WITH, prm: WITHOUT }))).toBe(true)
  })

  test('permitted set has it, bounding set does not: exec drops it', () => {
    expect(hasSetfcap(status({ bnd: WITHOUT, prm: WITH }))).toBe(false)
  })

  test('inheritable set alone is enough', () => {
    expect(hasSetfcap(status({ bnd: WITHOUT, inh: WITH }))).toBe(true)
  })

  test('neither set has it', () => {
    expect(hasSetfcap(status({ bnd: WITHOUT, inh: WITHOUT }))).toBe(false)
  })

  test('a status without the lines is undefined, not zero', () => {
    expect(boundingCapabilitiesFromStatus('Name:\tsrt\n')).toBeUndefined()
    expect(
      boundingCapabilitiesFromStatus('Name:\tsrt\nCapBnd:\t00000000a82c75fb\n'),
    ).toBeUndefined()
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

  // Pure: the missing-capability case is reported by the caller, once per
  // process, not from an argument builder run for every wrapped command.
  test('uid 0 missing CAP_SETFCAP: adds nothing and says nothing', () => {
    const warnSpy = spyOn(console, 'warn').mockImplementation(() => {})
    const errorSpy = spyOn(console, 'error').mockImplementation(() => {})
    const debug = process.env.SRT_DEBUG
    process.env.SRT_DEBUG = '1'
    try {
      for (const usesSeccompHelper of [true, false]) {
        expect(
          capabilityArgs({ euid: 0, hasSetfcap: false, usesSeccompHelper }),
        ).toEqual(['--cap-drop', 'ALL'])
      }

      expect(warnSpy).not.toHaveBeenCalled()
      expect(errorSpy).not.toHaveBeenCalled()
    } finally {
      if (debug === undefined) delete process.env.SRT_DEBUG
      else process.env.SRT_DEBUG = debug
      warnSpy.mockRestore()
      errorSpy.mockRestore()
    }
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
