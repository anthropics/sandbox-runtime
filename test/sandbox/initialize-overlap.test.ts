import { describe, it, expect, beforeAll, afterAll, afterEach } from 'bun:test'
import { mkdtempSync, readdirSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import type { SandboxRuntimeConfig } from '../../src/sandbox/sandbox-config.js'
import { isLinux, isMacOS } from '../helpers/platform.js'

// initialize() generates the ephemeral TLS-terminate CA's key on the thread
// pool, so it awaits (tens of ms) before it claims its in-flight slot. An
// initialize() or wrapWithSandbox() that lands in that window must wait for
// the running initialization, not race it.

function tlsConfig(): SandboxRuntimeConfig {
  return {
    network: {
      allowedDomains: ['example.com'],
      deniedDomains: [],
      tlsTerminate: {},
    },
    filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
  }
}

describe.if(isLinux || isMacOS)('initialize() overlapping calls', () => {
  // A private TMPDIR makes the srt-ca-* directories this test creates the
  // only ones counted, whatever else is running on the machine. Kept short:
  // the proxies' unix socket paths live under it too.
  let scratch: string
  let savedTmpdir: string | undefined

  const caDirs = () =>
    readdirSync(tmpdir()).filter(name => name.startsWith('srt-ca-'))
  const sleep = (ms: number) => new Promise(r => setTimeout(r, ms))

  beforeAll(() => {
    savedTmpdir = process.env.TMPDIR
    scratch = mkdtempSync('/tmp/srt-overlap-')
    process.env.TMPDIR = scratch
  })

  afterEach(async () => {
    await SandboxManager.reset()
  })

  afterAll(() => {
    if (savedTmpdir === undefined) delete process.env.TMPDIR
    else process.env.TMPDIR = savedTmpdir
    rmSync(scratch, { recursive: true, force: true })
  })

  // 0: back to back; 1: after a timer tick, i.e. while the key is generating.
  it.each([0, 1])(
    'a second call %ims after the first joins it: one CA, none left after reset',
    async gap => {
      const first = SandboxManager.initialize(tlsConfig())
      if (gap > 0) await sleep(gap)
      const second = SandboxManager.initialize(tlsConfig())
      await Promise.all([first, second])

      // One initialization → one CA (its key dir and its trust-bundle dir).
      const ca = SandboxManager.getMitmCA()!
      expect(ca).toBeDefined()
      expect(caDirs().length).toBe(2)

      await SandboxManager.reset()
      expect(caDirs()).toEqual([])
    },
  )

  it('wrapWithSandbox during initialize() waits for it and is fully wired', async () => {
    const init = SandboxManager.initialize(tlsConfig())
    await sleep(1)
    const wrapped = await SandboxManager.wrapWithSandbox('true')
    await init

    // Wrapped before init finished, the command would carry neither the
    // proxy wiring nor the CA trust bundle.
    const ca = SandboxManager.getMitmCA()!
    expect(wrapped).toContain(ca.trustBundlePath)
  })

  it('a failed initialize() does not block the one queued behind it', async () => {
    const bad = SandboxManager.initialize({
      ...tlsConfig(),
      network: {
        allowedDomains: ['example.com'],
        deniedDomains: [],
        tlsTerminate: { caCertPath: '/nonexistent/ca.crt' },
      },
    })
    const good = SandboxManager.initialize(tlsConfig())

    // Message of the rejection, or undefined if the promise resolved.
    const rejection = await bad.then(
      () => undefined,
      (e: unknown) => (e as Error).message,
    )
    expect(rejection).toMatch(/must be provided together/)
    await good
    expect(SandboxManager.getMitmCA()?.ephemeral).toBe(true)
  })
})
