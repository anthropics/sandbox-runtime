import { afterEach, beforeEach, describe, expect, it, spyOn } from 'bun:test'
import type { Mock } from 'bun:test'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import type { SandboxRuntimeConfig } from '../../src/sandbox/sandbox-config.js'
import * as platform from '../../src/utils/platform.js'
import * as wutils from '../../src/sandbox/windows-sandbox-utils.js'
import * as httpProxy from '../../src/sandbox/http-proxy.js'
import type { WindowsAclAuditResult } from '../../src/sandbox/windows-sandbox-utils.js'

/**
 * Lifecycle races between the Windows world-writable audit (an
 * `srt-win acl audit` subprocess that stamps deny_ww session holds
 * under this process's PID) and initialize()/reset(). Platform and
 * every srt-win touchpoint are stubbed, so these run on any OS —
 * they exercise the ORDERING contracts in sandbox-manager.ts:
 *
 *  1. initialize() dedups concurrent callers onto
 *     initializationPromise, so the audit must settle INSIDE that
 *     promise — a deduped caller returning earlier would get an
 *     exec window before the deny stamps land.
 *  2. reset() must not sweep ACLs while the audit subprocess may
 *     still stamp: a stamp landing after the sweep is stranded
 *     until process exit (crash recovery only reaps rows whose
 *     holder died — this process is the holder and alive).
 *  3. A failed network init rethrows promptly (not after the
 *     audit's settlement), and a retry initialize() waits out the
 *     scheduled teardown before stamping anew, so the teardown's
 *     sweep can't strip the retry's fresh holds.
 */

function deferred<T>(): { promise: Promise<T>; resolve: (v: T) => void } {
  let resolve!: (v: T) => void
  const promise = new Promise<T>(r => {
    resolve = r
  })
  return { promise, resolve }
}

async function until(cond: () => boolean, ms = 3000): Promise<void> {
  const start = Date.now()
  while (!cond()) {
    if (Date.now() - start > ms) {
      throw new Error('until(): condition not reached in time')
    }
    await new Promise(r => setTimeout(r, 5))
  }
}

/** Observe settlement without consuming the rejection. */
function track(p: Promise<unknown>): { settled: boolean; rejected: boolean } {
  const s = { settled: false, rejected: false }
  p.then(
    () => {
      s.settled = true
    },
    () => {
      s.settled = true
      s.rejected = true
    },
  )
  return s
}

function auditResult(): WindowsAclAuditResult {
  return {
    candidates: 3,
    scanned: 3,
    flagged: ['C:\\ww'],
    stamped: ['C:\\ww'],
    failed: [],
    nullDaclRefused: 0,
    budget: {
      wallExpired: false,
      daclReads: 3,
      daclExhausted: false,
      skipped: 0,
      dirsTruncated: 0,
      unreadable: 0,
      reparseSkipped: 0,
      remoteSkipped: 0,
      rootsSkippedNonLocal: 0,
    },
  }
}

// External proxy ports on both sides -> initialize() starts no local
// proxy at all, so the network phase completes without binding
// anything and the audit is the only pending work.
function externalPortsConfig(): SandboxRuntimeConfig {
  return {
    network: {
      allowedDomains: ['example.com'],
      deniedDomains: [],
      httpProxyPort: 39997,
      socksProxyPort: 39998,
    },
    filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
  }
}

// No external ports -> initialize() must start the local mux, whose
// first step (createHttpProxyServer) test 3 makes throw.
function localProxyConfig(): SandboxRuntimeConfig {
  return {
    network: { allowedDomains: ['example.com'], deniedDomains: [] },
    filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
  }
}

describe('windows world-writable audit lifecycle races (stubbed srt-win)', () => {
  let spies: { mockRestore(): void }[] = []
  let auditSpy: Mock<typeof wutils.auditWindowsWorldWritable>
  let revokeSpy: Mock<typeof wutils.revokeWindowsAcl>
  let restoreSpy: Mock<typeof wutils.restoreWindowsAcl>

  beforeEach(async () => {
    await SandboxManager.reset()
    spies = []
    spies.push(spyOn(platform, 'getPlatform').mockReturnValue('windows'))
    spies.push(
      spyOn(wutils, 'resolveSrtWin').mockReturnValue({
        exe: 'srt-win-test-stub',
        prependArgs: [],
      }),
    )
    spies.push(
      spyOn(wutils, 'checkWindowsDependenciesAsync').mockResolvedValue({
        errors: [],
        warnings: [],
      }),
    )
    spies.push(
      spyOn(wutils, 'getWindowsSandboxUserStatusAsync').mockResolvedValue({
        provisioned: true,
        sid: 'S-1-5-21-1-2-3-1004',
        groupExists: true,
        groupSid: 'S-1-5-21-1-2-3-1005',
        inBuiltinUsers: true,
        inSandboxGroup: true,
        hiddenFromLogon: true,
        credPresent: true,
      } as Awaited<ReturnType<typeof wutils.getWindowsSandboxUserStatusAsync>>),
    )
    spies.push(
      spyOn(wutils, 'verifyWindowsWfpEgress').mockResolvedValue(
        {} as Awaited<ReturnType<typeof wutils.verifyWindowsWfpEgress>>,
      ),
    )
    spies.push(spyOn(wutils, 'expandWindowsFsPaths').mockReturnValue([]))
    spies.push(spyOn(wutils, 'grantWindowsAcl').mockReturnValue(undefined))
    spies.push(spyOn(wutils, 'stampWindowsAcl').mockReturnValue(undefined))
    revokeSpy = spyOn(wutils, 'revokeWindowsAcl').mockReturnValue([])
    spies.push(revokeSpy)
    restoreSpy = spyOn(wutils, 'restoreWindowsAcl').mockReturnValue([])
    spies.push(restoreSpy)
    auditSpy = spyOn(wutils, 'auditWindowsWorldWritable')
    spies.push(auditSpy)
  })

  afterEach(async () => {
    // Reset while the stubs are still installed (the teardown path
    // calls the stubbed revoke/restore), THEN restore the spies.
    await SandboxManager.reset()
    for (const s of spies) {
      s.mockRestore()
    }
  })

  it('a deduped initialize() caller waits for the audit to settle', async () => {
    const d = deferred<WindowsAclAuditResult | undefined>()
    auditSpy.mockImplementation(() => d.promise)

    const p1 = SandboxManager.initialize(externalPortsConfig())
    const s1 = track(p1)
    await until(() => auditSpy.mock.calls.length === 1)

    // Concurrent caller lands on the dedup path
    // (`await initializationPromise; return`).
    const p2 = SandboxManager.initialize(externalPortsConfig())
    const s2 = track(p2)

    // Neither caller may resolve while the audit subprocess is still
    // running: its deny_ww stamps are part of what initialize()
    // promises. (Everything else — network phase included — is done;
    // the audit is the only pending work.)
    await new Promise(r => setTimeout(r, 50))
    expect(s1.settled).toBe(false)
    expect(s2.settled).toBe(false)

    d.resolve(auditResult())
    await p1
    await p2
    expect(s1.rejected).toBe(false)
    expect(s2.rejected).toBe(false)
  })

  it('reset() during initialize() defers the sweep until the audit settles (zero stranded rows)', async () => {
    const d = deferred<WindowsAclAuditResult | undefined>()
    auditSpy.mockImplementation(() => d.promise)

    const p1 = SandboxManager.initialize(externalPortsConfig())
    void track(p1)
    await until(() => auditSpy.mock.calls.length === 1)

    // External reset() racing initialize()'s tail.
    const resetP = SandboxManager.reset()
    const resetTracked = track(resetP)

    // The sweep must NOT run while the audit subprocess may still be
    // stamping — a stamp landing after the sweep would be stranded
    // until process exit.
    await new Promise(r => setTimeout(r, 50))
    expect(revokeSpy.mock.calls.length).toBe(0)
    expect(restoreSpy.mock.calls.length).toBe(0)
    expect(resetTracked.settled).toBe(false)

    // Audit settles (its stamps are now all on disk) -> the sweep
    // runs and releases every row this holder has, late stamps
    // included.
    d.resolve(auditResult())
    await resetP
    expect(revokeSpy.mock.calls.length).toBe(1)
    expect(restoreSpy.mock.calls.length).toBe(1)
    expect(revokeSpy.mock.calls[0]?.[0]?.sandboxUserSid).toBe(
      'S-1-5-21-1-2-3-1004',
    )
    // initialize() settles too (either order is fine — the audit it
    // was waiting on has resolved). Swallow a potential rejection:
    // the concurrent reset() tore the session down under it.
    await p1.catch(() => {})
  })

  it('failed network init rethrows promptly; a retry waits out the teardown before re-stamping', async () => {
    const d1 = deferred<WindowsAclAuditResult | undefined>()
    const d2 = deferred<WindowsAclAuditResult | undefined>()
    auditSpy
      .mockImplementationOnce(() => d1.promise)
      .mockImplementationOnce(() => d2.promise)
    const boom = spyOn(httpProxy, 'createHttpProxyServer').mockImplementation(
      () => {
        throw new Error('port bind conflict (test)')
      },
    )
    spies.push(boom)

    // Local-proxy config -> the network phase throws immediately.
    const p1 = SandboxManager.initialize(localProxyConfig())
    // The failure must surface while the audit is still UNRESOLVED —
    // the fast-failure contract (a port-bind conflict must not
    // present as a hang on the audit's settlement). Under the old
    // await-audit-then-rethrow code this await never returns and the
    // test times out.
    const err = await p1.then(
      () => undefined,
      (e: unknown) => e,
    )
    expect(err).toBeInstanceOf(Error)
    expect((err as Error).message).toContain('port bind conflict (test)')
    expect(auditSpy.mock.calls.length).toBe(1)
    // The internally scheduled reset() is parked behind the audit;
    // no sweep yet.
    expect(restoreSpy.mock.calls.length).toBe(0)

    // Retry with a config whose network phase succeeds. It must NOT
    // stamp (or start its audit) until the pending teardown drained
    // — the teardown's sweep releases by SID + holder PID and would
    // strip the retry's fresh holds.
    const p2 = SandboxManager.initialize(externalPortsConfig())
    const s2 = track(p2)
    await new Promise(r => setTimeout(r, 50))
    expect(auditSpy.mock.calls.length).toBe(1)
    expect(s2.settled).toBe(false)

    // Old audit settles -> teardown sweeps -> retry proceeds.
    d1.resolve(undefined)
    await until(() => auditSpy.mock.calls.length === 2)
    expect(restoreSpy.mock.calls.length).toBe(1)

    d2.resolve(auditResult())
    await p2
    expect(s2.rejected).toBe(false)
  })
})
