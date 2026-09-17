import { afterAll, beforeAll, describe, expect, it } from 'bun:test'
import { spawn } from 'node:child_process'
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { homedir, tmpdir } from 'node:os'
import { join } from 'node:path'
import { createServer, type Server } from 'node:net'
import type { AddressInfo } from 'node:net'
import { isWindows } from '../helpers/platform.js'
import { spawnAsync } from '../helpers/spawn.js'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import {
  WindowsSandboxError,
  getSrtWinPath,
  resolveSrtWin,
  installWindowsSandbox,
  uninstallWindowsSandbox,
} from '../../src/sandbox/windows-sandbox-utils.js'
import type { SandboxRuntimeConfig } from '../../src/sandbox/sandbox-config.js'

/**
 * Windows sandbox BOUNDARY verification matrix.
 *
 * Backend-agnostic: every test drives the public SandboxManager
 * surface (`wrapWithSandboxArgv` + spawn `shell:false`) and asserts
 * the boundary srt promises, not the mechanism that enforces it. The
 * suite prints which backend `initialize()` selected; run it on a
 * BaseContainer-capable machine (Windows 11 25H2+ with the OS feature
 * enabled, `@microsoft/mxc-sdk` installed) to verify the MXC path, or
 * on any other Windows machine (after `npx sandbox-runtime
 * windows-install`) to verify srt-win. Overlap with winsrt.test.ts is
 * deliberate — this file is the checklist for manual verification of
 * a new backend, so it must stand alone.
 *
 * The matrix:
 *
 *   B — network egress
 *     B1 allowed domain reachable through the proxy
 *     B2 non-allowed domain blocked at the proxy
 *     B3 raw TCP to an external IP (ignores proxy env) blocked   ← the
 *        mandatory-vs-cooperative litmus: a cooperative-only fence
 *        passes B1/B2 and FAILS B3
 *     B4 loopback to an arbitrary non-proxy port blocked
 *     B5 loopback to the proxy port reachable                    ← the
 *        MXC `allowedPeers` question: our mux proxy is a plain host
 *        process, not an AppContainer
 *     B6 direct UDP/53 to an external resolver blocked
 *   C — filesystem reads
 *     C1 reads work broadly (system drive)
 *     C2 session denyRead unreadable (inside a read-granted tree, so
 *        deny-overrides-grant precedence is exercised)
 *     C3 per-exec denyRead unreadable
 *     C4 credential file (mode:'deny') unreadable
 *   D — filesystem writes
 *     D1 write inside allowWrite succeeds
 *     D2 write to %TEMP% succeeds
 *     D3 write outside all grants fails
 *     D4 denyWrite inside allowWrite: write blocked
 *     D5 delete of a write-denied file blocked
 *     D6 cwd is not implicitly writable
 *     D7 per-exec allowWrite (MXC-only capability; srt-win throws)
 *   E — environment & credentials
 *     E1 broker environment not inherited by the child
 *     E2 mode:'mask' env var: child sees a sentinel, not the value
 *     E3 mode:'deny' env var absent in the child
 *     E4 proxy env vars + GIT_CONFIG_* overlay present
 *   F — process lifecycle
 *     F1 exit code propagation
 *     F2 stdout/stderr separation
 *     F3 kill chain: broker killed → sandboxed tree dies
 *     F4 PowerShell starts (UI policy)
 *   G — tlsTerminate (MXC only here; srt-win's flow needs the
 *        install-time trust-ca step and is covered in winsrt.test.ts)
 *     G1 OpenSSL-backed client trusts via the env CA layer
 *     G2 schannel client (System32 curl.exe) trusts — answers whether
 *        a BaseContainer child sees the user's CurrentUser\Root store
 */

const FIXTURE_SECRET = 'BOUNDARY-SECRET-4d1f'

let root: string // read-granted fixture tree (inside %TEMP%)
let allowWriteDir: string // write-granted
let denyReadFile: string // session read deny, inside `root`
let denyWriteFile: string // session write deny, inside `allowWriteDir`
let perExecDenyFile: string // denied per-exec only
let credFile: string // credentials.files mode:'deny'
/**
 * TCP connect probe as inline `node -e` — no script FILE, because node
 * realpaths a script's path and lstats every ancestor, and under
 * srt-win the sandbox user has no metadata rights on the broker's
 * profile chain (the child died at startup with EPERM before ever
 * touching the network, turning block rows into false passes). The JS
 * is single-quoted throughout so the outer double quotes are the sole
 * quoting level through cmd /s /c. PROBE-START lets callers prove the
 * probe RAN — a block row asserts "started AND not connected", never
 * just a non-zero exit.
 */
function connectProbeCmd(host: string, port: number): string {
  // process.exitCode + natural drain, never process.exit(): Windows
  // pipes stdout asynchronously, and exit() right after console.log
  // races the buffered write — dropping the very markers the rows
  // assert on (a blocked connect errors within milliseconds of the
  // PROBE-START write).
  const js =
    `const n=require('net');console.log('PROBE-START');` +
    `const s=n.connect(${port},'${host}');` +
    `const t=setTimeout(()=>{process.exitCode=2;s.destroy()},5000);` +
    `s.on('connect',()=>{console.log('CONNECTED');process.exitCode=0;` +
    `clearTimeout(t);s.destroy()});` +
    `s.on('error',e=>{console.error(String(e));process.exitCode=1;` +
    `clearTimeout(t)})`
  return `node -e "${js}"`
}
const profileProbeDir = join(homedir(), `srt-boundary-probe-${process.pid}`)
// D6's cwd lives under the REAL USER's profile, not the repo
// checkout: CI work directories (D:\a\...) carry permissive ACLs
// that legitimately let the srt-win sandbox user write — srt-win is
// deny-list + user isolation, not allow-list, so "cwd unwritable"
// only holds where the machine's own ACLs say so. A profile-owned
// dir is unwritable under BOTH backends: srt-win's child has no
// rights on the real user's profile, and under mxc it is readable
// (system-drive grant) but not in allowWrite.
const cwdProbeDir = join(homedir(), `srt-boundary-cwd-${process.pid}`)
let installedHere = false // this run performed windows-install → uninstall after

// srt-win resolution is explicit post-`srt_win_not_found` typed errors:
// there is no implicit binary fallback. On a BaseContainer-capable
// machine WITHOUT the srt-win binary this stays undefined — selection
// goes to mxc and srt-win is never resolved; if selection lands on
// srt-win anyway, initialize() fails with the actionable
// srt_win_not_found message.
const SRT_WIN_PATH = (() => {
  if (!isWindows) return undefined
  try {
    return getSrtWinPath()
  } catch {
    return undefined
  }
})()

function createBoundaryConfig(): SandboxRuntimeConfig {
  return {
    network: {
      allowedDomains: ['example.com'],
      deniedDomains: [],
    },
    windows: SRT_WIN_PATH ? { srtWin: { path: SRT_WIN_PATH } } : undefined,
    filesystem: {
      allowRead: [root],
      allowWrite: [allowWriteDir],
      denyRead: [denyReadFile],
      denyWrite: [denyWriteFile],
    },
    credentials: {
      files: [{ path: credFile, mode: 'deny' }],
      envVars: [
        { name: 'SRT_BOUNDARY_MASKED', mode: 'mask' },
        { name: 'SRT_BOUNDARY_DENIED', mode: 'deny' },
      ],
    },
  }
}

type RunResult = { stdout: string; stderr: string; status: number | null }

async function runSandboxed(
  command: string,
  opts: {
    timeoutMs?: number
    customConfig?: Partial<SandboxRuntimeConfig>
    cwd?: string
    extraBrokerEnv?: Record<string, string>
  } = {},
): Promise<RunResult> {
  const { argv, env } = await SandboxManager.wrapWithSandboxArgv(
    command,
    undefined,
    opts.customConfig,
    undefined,
    opts.cwd,
  )
  return spawnAsync(argv[0], argv.slice(1), {
    timeout: opts.timeoutMs ?? 60_000,
    cwd: opts.cwd,
    env: opts.extraBrokerEnv ? { ...env, ...opts.extraBrokerEnv } : env,
  })
}

/** ALLOW rows may retry once — a network blip is not a fence break. */
async function runSandboxedUntil(
  command: string,
  ok: (r: RunResult) => boolean,
  attempts = 2,
): Promise<RunResult> {
  let last: RunResult = { stdout: '', stderr: '', status: null }
  for (let i = 0; i < attempts; i++) {
    last = await runSandboxed(command)
    if (ok(last)) return last
  }
  return last
}

function expectStatus(label: string, r: RunResult, allowed: number[]): void {
  if (allowed.includes(r.status ?? -999)) return
  throw new Error(
    `${label}: exit ${r.status} not in [${allowed.join(',')}] · ` +
      `stdout=${JSON.stringify(r.stdout)} · stderr=${JSON.stringify(r.stderr)}`,
  )
}

/**
 * BLOCK rows assert only not-success: the exact failure code varies
 * by backend and build. Single-shot, never retried.
 */
function expectBlocked(label: string, r: RunResult): void {
  if (r.status !== 0) return
  throw new Error(
    `${label}: expected the sandbox to block this, but it exited 0 · ` +
      `stdout=${JSON.stringify(r.stdout)}`,
  )
}

function hasTool(name: string): boolean {
  // skipIf() arguments evaluate at collection time on every platform;
  // where.exe only exists on Windows.
  if (!isWindows) return false
  const r = Bun.spawnSync(['where.exe', name])
  return r.exitCode === 0
}

describe.if(isWindows)('Windows sandbox boundaries', () => {
  beforeAll(async () => {
    root = mkdtempSync(join(tmpdir(), 'srt-boundary-'))
    allowWriteDir = join(root, 'allow-write')
    mkdirSync(allowWriteDir)
    denyReadFile = join(root, 'deny-read.txt')
    writeFileSync(denyReadFile, FIXTURE_SECRET)
    denyWriteFile = join(allowWriteDir, 'deny-write.txt')
    writeFileSync(denyWriteFile, 'original-content')
    perExecDenyFile = join(root, 'per-exec-deny.txt')
    writeFileSync(perExecDenyFile, FIXTURE_SECRET)
    credFile = join(root, 'cred.txt')
    writeFileSync(credFile, FIXTURE_SECRET)
    // Must exist so the BROKER spawn (real user) succeeds and D6
    // exercises the CHILD's write, not a spawn-on-missing-cwd error.
    mkdirSync(cwdProbeDir, { recursive: true })
    process.env.SRT_BOUNDARY_MASKED = FIXTURE_SECRET
    process.env.SRT_BOUNDARY_DENIED = FIXTURE_SECRET

    try {
      await SandboxManager.initialize(createBoundaryConfig())
    } catch (e) {
      // srt-win selected on a machine without the one-time install:
      // self-provision (one UAC prompt) and retry. Never reached on a
      // BaseContainer host — the mxc path needs no install. The
      // not-provisioned path implies srt-win resolved, so the binary
      // path is necessarily known here.
      if (!/provisioned|windows-install/i.test((e as Error).message)) throw e
      if (SRT_WIN_PATH === undefined) throw e
      installWindowsSandbox({
        srtWin: resolveSrtWin({ path: SRT_WIN_PATH }),
      })
      installedHere = true
      await SandboxManager.initialize(createBoundaryConfig())
    }
    const backend = SandboxManager.getWindowsBackend?.()
    console.error(`[boundaries] using ${backend?.backend} (${backend?.reason})`)
    // Install + double initialize + wxc-exec --probe exceed bun's 5s
    // default hook timeout (same class as winsrt's beforeAll).
  }, 180_000)

  afterAll(async () => {
    await SandboxManager.reset()
    if (installedHere && SRT_WIN_PATH !== undefined) {
      uninstallWindowsSandbox({
        srtWin: resolveSrtWin({ path: SRT_WIN_PATH }),
      })
    }
    delete process.env.SRT_BOUNDARY_MASKED
    delete process.env.SRT_BOUNDARY_DENIED
    rmSync(root, { recursive: true, force: true })
    rmSync(profileProbeDir, { recursive: true, force: true })
    rmSync(cwdProbeDir, { recursive: true, force: true })
  }, 120_000)

  // ── B: network egress ────────────────────────────────────────────

  it('B1: allowed domain reachable through the proxy', async () => {
    const r = await runSandboxedUntil(
      'curl.exe -fsS -o NUL https://example.com',
      x => x.status === 0,
    )
    expectStatus('B1', r, [0])
  }, 90_000)

  it('B2: non-allowed domain blocked at the proxy', async () => {
    const r = await runSandboxed('curl.exe -fsS -o NUL https://api.github.com')
    expectBlocked('B2', r)
  }, 90_000)

  it.skipIf(!hasTool('node'))(
    'B3: raw TCP to an external IP is blocked (proxy-env bypass)',
    async () => {
      // 1.1.1.1:443 answers instantly when reachable, so exit 0 here
      // means the egress fence does not bind raw sockets — the
      // cooperative-proxy failure mode.
      const r = await runSandboxed(connectProbeCmd('1.1.1.1', 443))
      // A missing PROBE-START means the child never ran (spawn/env
      // problem), NOT a network verdict — deliberate: a silent
      // can't-even-start must read as red, never as "blocked".
      expect(r.stdout).toContain('PROBE-START')
      expect(r.stdout).not.toContain('CONNECTED')
      expectBlocked('B3', r)
    },
    30_000,
  )

  it.skipIf(!hasTool('node'))(
    'B4: loopback to an arbitrary non-proxy port is blocked',
    async () => {
      // A live host-process listener OUTSIDE the proxy port range —
      // reaching it would mean the loopback escape is broader than
      // the proxy. The ephemeral range (49152+) contains the WFP
      // loopback permit (default 60080–60089, which srt-win PERMITs
      // for any process), so re-roll a listener that lands inside it.
      let server: Server = createServer(() => {})
      await new Promise<void>(res => server.listen(0, '127.0.0.1', res))
      let port = (server.address() as AddressInfo).port
      while (port >= 60080 && port <= 60089) {
        server.close()
        server = createServer(() => {})
        await new Promise<void>(res => server.listen(0, '127.0.0.1', res))
        port = (server.address() as AddressInfo).port
      }
      try {
        const r = await runSandboxed(connectProbeCmd('127.0.0.1', port))
        // See B3: PROBE-START missing = child never ran, not blocked.
        expect(r.stdout).toContain('PROBE-START')
        expect(r.stdout).not.toContain('CONNECTED')
        expectBlocked('B4', r)
      } finally {
        server.close()
      }
    },
    30_000,
  )

  it.skipIf(!hasTool('node'))(
    'B5: loopback to the proxy port is reachable',
    async () => {
      // The load-bearing MXC question: the mux proxy is a plain host
      // process, not an AppContainer peer.
      const port = SandboxManager.getProxyPort()
      expect(port).toBeDefined()
      const r = await runSandboxed(connectProbeCmd('127.0.0.1', port!))
      expectStatus('B5', r, [0])
      expect(r.stdout).toContain('CONNECTED')
    },
    30_000,
  )

  it.skipIf(!hasTool('nslookup'))(
    'B6: direct UDP/53 to an external resolver is blocked',
    async () => {
      const r = await runSandboxed('nslookup -timeout=3 example.com 8.8.8.8')
      // nslookup's exit code is unreliable across builds, and its
      // header ECHOES the queried server ("Server: UnKnown /
      // Address: 8.8.8.8") even on total timeout — matching on
      // Address: alone reads the echo as an answer. A real answer
      // carries a "Name:" section; the row holds if none appeared.
      const answered = /Name:\s/.test(r.stdout)
      // Blocked UDP shows as query timeouts (en-US output; the one
      // localization-sensitive assertion in the file). Neither an
      // answer NOR timeouts — e.g. a REFUSED/SERVFAIL response —
      // means a packet round-tripped: egress open, row red.
      const timedOut = /timed?[- ]?out/i.test(r.stdout)
      if (answered || !timedOut) {
        throw new Error(
          `B6: direct DNS to 8.8.8.8 succeeded · stdout=${JSON.stringify(r.stdout)}`,
        )
      }
    },
    30_000,
  )

  // ── C: filesystem reads ──────────────────────────────────────────

  it('C1: reads work broadly (system drive)', async () => {
    const r = await runSandboxed('type C:\\Windows\\win.ini')
    expectStatus('C1', r, [0])
    expect(r.stdout.length).toBeGreaterThan(0)
  }, 60_000)

  it('C2: session denyRead is unreadable (deny overrides read grant)', async () => {
    const r = await runSandboxed(`type "${denyReadFile}"`)
    expectBlocked('C2', r)
    expect(r.stdout).not.toContain(FIXTURE_SECRET)
  }, 60_000)

  it('C3: per-exec denyRead is unreadable', async () => {
    const r = await runSandboxed(`type "${perExecDenyFile}"`, {
      customConfig: {
        filesystem: {
          denyRead: [perExecDenyFile],
          denyWrite: [],
          allowWrite: [],
        },
      },
    })
    expectBlocked('C3', r)
    expect(r.stdout).not.toContain(FIXTURE_SECRET)
  }, 60_000)

  it("C4: credential file (mode:'deny') is unreadable", async () => {
    const r = await runSandboxed(`type "${credFile}"`)
    expectBlocked('C4', r)
    expect(r.stdout).not.toContain(FIXTURE_SECRET)
  }, 60_000)

  // ── D: filesystem writes ─────────────────────────────────────────

  it('D1: write inside allowWrite succeeds', async () => {
    const target = join(allowWriteDir, 'd1.txt')
    const r = await runSandboxed(`echo d1-mark > "${target}"`)
    expectStatus('D1', r, [0])
    expect(readFileSync(target, 'utf8')).toContain('d1-mark')
  }, 60_000)

  it('D2: write to %TEMP% succeeds', async () => {
    // %TEMP% resolves inside the CHILD (sealed env / own profile), so
    // verify via a sandboxed read-back rather than the broker's fs.
    const r = await runSandboxed(
      'echo d2-mark > "%TEMP%\\srt-d2.txt" && type "%TEMP%\\srt-d2.txt"',
    )
    expectStatus('D2', r, [0])
    expect(r.stdout).toContain('d2-mark')
  }, 60_000)

  it('D3: write outside all grants fails', async () => {
    const r = await runSandboxed(
      `mkdir "${profileProbeDir}" && echo x > "${profileProbeDir}\\d3.txt"`,
    )
    expectBlocked('D3', r)
    expect(existsSync(join(profileProbeDir, 'd3.txt'))).toBe(false)
  }, 60_000)

  it('D4: denyWrite inside allowWrite blocks the write', async () => {
    const r = await runSandboxed(`echo overwritten > "${denyWriteFile}"`)
    expectBlocked('D4', r)
    expect(readFileSync(denyWriteFile, 'utf8')).toContain('original-content')
  }, 60_000)

  it('D5: delete of a write-denied file is blocked', async () => {
    const r = await runSandboxed(`del /f /q "${denyWriteFile}"`)
    // `del` can exit 0 while printing an access-denied line; the
    // boundary is the file surviving.
    void r
    expect(existsSync(denyWriteFile)).toBe(true)
    expect(readFileSync(denyWriteFile, 'utf8')).toContain('original-content')
  }, 60_000)

  it('D6: cwd is not implicitly writable', async () => {
    const r = await runSandboxed(`echo x > d6-probe.txt`, {
      cwd: cwdProbeDir,
    })
    expectBlocked('D6', r)
    expect(existsSync(join(cwdProbeDir, 'd6-probe.txt'))).toBe(false)
  }, 60_000)

  it('D7: per-exec allowWrite (mxc grants it; srt-win rejects it)', async () => {
    const perExecDir = join(root, 'per-exec-write')
    mkdirSync(perExecDir, { recursive: true })
    const target = join(perExecDir, 'd7.txt')
    const backend = SandboxManager.getWindowsBackend?.()?.backend
    const perExecFs = {
      filesystem: { allowWrite: [perExecDir], denyRead: [], denyWrite: [] },
    }
    if (backend === 'mxc') {
      const r = await runSandboxed(`echo d7-mark > "${target}"`, {
        customConfig: perExecFs,
      })
      expectStatus('D7', r, [0])
      expect(readFileSync(target, 'utf8')).toContain('d7-mark')
    } else {
      // eslint-disable-next-line @typescript-eslint/await-thenable
      await expect(
        runSandboxed(`echo d7-mark > "${target}"`, {
          customConfig: perExecFs,
        }),
      ).rejects.toThrow(/allowRead\/allowWrite/)
    }
  }, 60_000)

  // ── E: environment & credentials ─────────────────────────────────

  it('E1: broker environment is not inherited by the child', async () => {
    const r = await runSandboxed('echo [%SRT_BOUNDARY_BROKER_ONLY%]', {
      extraBrokerEnv: { SRT_BOUNDARY_BROKER_ONLY: FIXTURE_SECRET },
    })
    expectStatus('E1', r, [0])
    // cmd echoes the literal %NAME% when the variable is unset.
    expect(r.stdout).toContain('[%SRT_BOUNDARY_BROKER_ONLY%]')
    expect(r.stdout).not.toContain(FIXTURE_SECRET)
  }, 60_000)

  it("E2: mode:'mask' env var arrives as a sentinel", async () => {
    const r = await runSandboxed('echo [%SRT_BOUNDARY_MASKED%]')
    expectStatus('E2', r, [0])
    expect(r.stdout).not.toContain(FIXTURE_SECRET) // not the real value
    expect(r.stdout).not.toContain('[%SRT_BOUNDARY_MASKED%]') // but set
  }, 60_000)

  it("E3: mode:'deny' env var is absent in the child", async () => {
    const r = await runSandboxed('echo [%SRT_BOUNDARY_DENIED%]')
    expectStatus('E3', r, [0])
    expect(r.stdout).toContain('[%SRT_BOUNDARY_DENIED%]')
    expect(r.stdout).not.toContain(FIXTURE_SECRET)
  }, 60_000)

  it('E4: proxy env + GIT_CONFIG_* overlay present in the child', async () => {
    const r = await runSandboxed('set')
    expectStatus('E4', r, [0])
    expect(r.stdout).toMatch(/HTTP_PROXY=http:\/\/.+:\d+/)
    expect(r.stdout).toMatch(/HTTPS_PROXY=http:\/\/.+:\d+/)
    expect(r.stdout).toContain('GIT_CONFIG_KEY_0=')
    expect(r.stdout).toContain('safe.directory')
  }, 60_000)

  // ── F: process lifecycle ─────────────────────────────────────────

  it('F1: exit code propagation', async () => {
    const r = await runSandboxed('exit 7')
    expectStatus('F1', r, [7])
  }, 60_000)

  it('F2: stdout/stderr separation', async () => {
    const r = await runSandboxed('echo OUT-MARK& echo ERR-MARK 1>&2')
    expectStatus('F2', r, [0])
    expect(r.stdout).toContain('OUT-MARK')
    expect(r.stderr).toContain('ERR-MARK')
  }, 60_000)

  it('F3: kill chain — broker killed, sandboxed tree dies', async () => {
    // `waitfor` parks until its signal or /T expires; it exists on
    // every Windows SKU. Kill the broker mid-wait, then confirm no
    // waitfor.exe survives (racy against unrelated waitfors, hence
    // the retry loop and the generous poll budget).
    const { argv, env } = await SandboxManager.wrapWithSandboxArgv(
      'waitfor SrtBoundarySig /t 90',
    )
    const broker = spawn(argv[0], argv.slice(1), { env, stdio: 'ignore' })
    await new Promise(res => setTimeout(res, 5_000))
    broker.kill()
    let alive = true
    for (let i = 0; i < 15 && alive; i++) {
      await new Promise(res => setTimeout(res, 1_000))
      const t = Bun.spawnSync([
        'tasklist',
        '/FI',
        'IMAGENAME eq waitfor.exe',
        '/FO',
        'CSV',
        '/NH',
      ])
      alive = t.stdout.toString().toLowerCase().includes('waitfor.exe')
    }
    expect(alive).toBe(false)
  }, 60_000)

  it('F4: PowerShell starts (UI policy)', async () => {
    const { argv, env } = await SandboxManager.wrapWithSandboxArgv(
      'Write-Output PS-MARK',
      'powershell',
    )
    const r = await spawnAsync(argv[0], argv.slice(1), {
      timeout: 60_000,
      env,
    })
    expectStatus('F4', r, [0])
    expect(r.stdout).toContain('PS-MARK')
  }, 90_000)
})

// ── G: tlsTerminate ─────────────────────────────────────────────────
//
// Separate describe: needs its own initialize() cycle. Runs only when
// the mxc backend is selected — srt-win's tlsTerminate needs the
// install-time `srt-win user trust-ca` step and is covered by
// winsrt.test.ts. G2 is the open manual question: does a BaseContainer
// child see the invoking user's CurrentUser\Root store?

describe.if(isWindows)('Windows sandbox boundaries: tlsTerminate', () => {
  let mxcSelected = false

  beforeAll(async () => {
    await SandboxManager.reset()
    try {
      await SandboxManager.initialize({
        ...createBoundaryConfig(),
        network: {
          allowedDomains: ['example.com'],
          deniedDomains: [],
          tlsTerminate: {},
        },
      })
      const backend = SandboxManager.getWindowsBackend?.()?.backend
      mxcSelected = backend === 'mxc'
      console.error(
        `[boundaries tls] using ${backend}` +
          (mxcSelected ? '' : ' — G rows skipped (covered by winsrt.test.ts)'),
      )
    } catch (e) {
      // Only srt-win-flavored initialize failures are an expected
      // miss here — that path's tls flow lives in winsrt.test.ts
      // with the install-time trust-ca step. Discriminators: the
      // typed WindowsSandboxError family (trust-ca gates,
      // provisioning — thrown only by srt-win machinery), the
      // persistent-CA reconcile, and the explicit-path thumbprint
      // gate messages. Anything else — including any failure on an
      // mxc host, the suite's actual target — stays loud. Backend
      // state can't discriminate here: network-phase failures reset
      // the manager, clearing the selection, before this catch runs.
      const msg = e instanceof Error ? e.message : String(e)
      const srtWinFlavored =
        e instanceof WindowsSandboxError ||
        /^ensurePersistentWindowsCa|^tlsTerminate on Windows/.test(msg)
      if (!srtWinFlavored) throw e
      console.error(
        `[boundaries tls] srt-win tls init failed — G rows skipped: ${msg}`,
      )
    }
  }, 120_000)

  afterAll(async () => {
    await SandboxManager.reset()
  }, 60_000)

  const GIT_CURL = 'C:\\Program Files\\Git\\mingw64\\bin\\curl.exe'

  it.skipIf(!existsSync(GIT_CURL))(
    'G1: OpenSSL-backed client trusts the MITM leaf via env CA',
    async () => {
      if (!mxcSelected) {
        console.error(
          '[boundaries tls] SKIPPED (not mxc) — this pass proves nothing',
        )
        return
      }
      const { argv, env } = await SandboxManager.wrapWithSandboxArgv(
        `"${GIT_CURL}" -fsS -o NUL https://example.com`,
      )
      const r = await spawnAsync(argv[0], argv.slice(1), {
        timeout: 60_000,
        env,
      })
      expectStatus('G1', r, [0])
    },
    90_000,
  )

  it('G2: schannel client (System32 curl.exe) trusts the MITM leaf', async () => {
    if (!mxcSelected) {
      console.error(
        '[boundaries tls] SKIPPED (not mxc) — this pass proves nothing',
      )
      return
    }
    // --ssl-no-revoke isolates the trust question from the known
    // CRL-fetch-through-the-fence issue (see README). A TLS trust
    // failure here means BaseContainer children do NOT see the
    // user's Root store — tlsTerminate then needs an MXC-era trust
    // story before schannel/.NET tools work.
    const { argv, env } = await SandboxManager.wrapWithSandboxArgv(
      'curl.exe -fsS --ssl-no-revoke -o NUL https://example.com',
    )
    const r = await spawnAsync(argv[0], argv.slice(1), {
      timeout: 60_000,
      env,
    })
    expectStatus('G2', r, [0])
  }, 90_000)
})
