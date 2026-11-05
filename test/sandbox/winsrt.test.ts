import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  spyOn,
} from 'bun:test'
import * as child_process from 'node:child_process'
import * as fs from 'node:fs'
import { spawn, spawnSync } from 'node:child_process'
import { EventEmitter } from 'node:events'
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { homedir, tmpdir } from 'node:os'
import { dirname, isAbsolute, join } from 'node:path'
import * as net from 'node:net'
import { createServer, type Server } from 'node:net'
import type { AddressInfo } from 'node:net'
import { isMacOS, isWindows } from '../helpers/platform.js'
import { spawnAsync } from '../helpers/spawn.js'
import {
  SandboxManager,
  windowsProfileReadWarningsOf,
} from '../../src/sandbox/sandbox-manager.js'
import type {
  CredentialFileConfig,
  SandboxRuntimeConfig,
  SrtWinConfig,
} from '../../src/sandbox/sandbox-config.js'
import {
  SandboxRuntimeConfigSchema,
  WindowsConfigSchema,
} from '../../src/sandbox/sandbox-config.js'
import { CA_TRUST_VARS } from '../../src/sandbox/sandbox-utils.js'
import { certThumbprint } from '../../src/sandbox/mitm-ca.js'
import * as platform from '../../src/utils/platform.js'
import { overrideEmittedConnectionProbe } from '../../src/sandbox/emitted-connection.js'
import * as winUtils from '../../src/sandbox/windows-sandbox-utils.js'
import {
  getSrtWinPath,
  getWindowsWfpStatus,
  getWindowsWfpStatusAsync,
  getWindowsSandboxUserStatus,
  getWindowsSandboxUserStatusAsync,
  checkWindowsSandboxStatus,
  checkWindowsSandboxStatusAsync,
  checkWindowsDependencies,
  checkWindowsDependenciesAsync,
  installWindowsSandbox,
  installWindowsSandboxAsync,
  uninstallWindowsSandbox,
  WindowsSandboxError,
  verifyWindowsWfpEgress,
  windowsTrustCa,
  windowsTrustCaAsync,
  ensurePersistentWindowsCa,
  windowsStateDir,
  wrapCommandWithSandboxWindows,
  mergeWindowsEnv,
  parseWindowsBinShell,
  rankWindowsFsAccess,
  resolveSrtWin,
  buildGitConfigEnv,
  SRT_WIN_DISPATCH_ARG1,
  DEFAULT_WINDOWS_PROXY_PORT_RANGE,
  VENDORED_SRT_WIN_EXE,
  WINDOWS_ALLOW_LOOPBACK_EFFECT,
  WINDOWS_LOOPBACK_NO_PROXY,
  WINDOWS_LOOPBACK_PROBE_PORT,
  type WindowsWfpVerifyResult,
  type WindowsAclGrantOptions,
  type WindowsAclStampOptions,
  type WindowsFsAccessSet,
} from '../../src/sandbox/windows-sandbox-utils.js'
import type { SeclogonDisabledError } from '../../src/sandbox/windows-sandbox-utils.js'

/**
 * Windows network-sandbox integration tests.
 *
 * The sandboxed child runs as the dedicated `srt-sandbox` user via
 * the two-hop launch (`CreateProcessWithLogonW`). beforeAll
 * provisions that account + the user-SID-keyed WFP filters under a
 * dedicated test sublayer; afterAll uninstalls.
 *
 * Real end-to-end (the actual fence) is also covered by
 * `vendor/srt-win-src/ci/smoke-exec.ps1` which runs before this file
 * in CI; this suite proves the TS layer wires correctly on top.
 */

// Dedicated test sublayer (distinct from smoke.ps1's b2e8a6c4-… and
// smoke-exec.ps1's 5b0e64f4-… so the three suites are independent).
const TEST_SUBLAYER = '7c1f0e90-3a2b-4f5d-9e8c-1d2e3f4a5b6c'

// Match smoke-exec.ps1's range; the WFP install below uses it.
const PORT_RANGE: readonly [number, number] = DEFAULT_WINDOWS_PROXY_PORT_RANGE

// Bash userland gates (Group E). git-for-windows ships the first;
// msys2 wget only exists on runners with msys2 installed.
const GIT_BASH = 'C:\\Program Files\\Git\\usr\\bin\\bash.exe'
const MSYS2_WGET = 'C:\\msys64\\usr\\bin\\wget.exe'

/**
 * All PATH hits for `name` via `where.exe` (Windows only). `where`
 * lists every match, one per line — a per-user shim
 * (`%LOCALAPPDATA%`, `~/.cargo/bin`) can shadow a machine-wide
 * install, so callers that need a sandbox-reachable path scan the
 * list, not just the first hit.
 */
function whereAll(name: string): string[] {
  if (!isWindows) return []
  const r = spawnSync('where', [name], { encoding: 'utf8', timeout: 5_000 })
  if (r.status !== 0) return []
  return r.stdout.split(/\r?\n/).filter(s => s.trim().length > 0)
}

/** True if `name` resolves on PATH (via `where.exe`). */
function hasTool(name: string): boolean {
  return whereAll(name).length > 0
}

/**
 * Locate a sandbox-reachable OpenSSL-backend curl. On x64
 * git-for-windows ships `mingw64\bin\curl.exe` (typically OpenSSL);
 * on ARM64 the bundled curl is `clangarm64\bin\curl.exe` and is
 * Schannel — so this returns `undefined` there and G3 skips. Probed
 * via `curl --version` since the build flavour, not the path,
 * decides. All candidate paths are machine-wide (Program Files /
 * msys2 root), so the sandbox user can launch them.
 */
function findOpenSslCurl(): string | undefined {
  if (!isWindows) return undefined
  for (const c of [
    'C:\\Program Files\\Git\\mingw64\\bin\\curl.exe',
    'C:\\Program Files\\Git\\clangarm64\\bin\\curl.exe',
    'C:\\msys64\\mingw64\\bin\\curl.exe',
  ]) {
    if (!existsSync(c)) continue
    const r = spawnSync(c, ['--version'], { encoding: 'utf8', timeout: 5_000 })
    if (r.status === 0 && /OpenSSL/i.test(r.stdout)) return c
  }
  return undefined
}
const OPENSSL_CURL = findOpenSslCurl()

/**
 * First `where.exe` hit for `name` that lives OUTSIDE the broker's
 * user profile — the srt-sandbox user has no rights on
 * `C:\Users\<broker>\…`, so a per-user install (rustup's
 * `~/.cargo/bin`, `%LOCALAPPDATA%`, py launcher shims) is
 * unreachable from the sandboxed child even though the broker's
 * PATH is forwarded. Scans ALL hits so a per-user shim doesn't
 * shadow a machine-wide install further down the list. Used to
 * gate G-rows on tools the child can actually launch.
 */
function sandboxReachable(name: string): string | undefined {
  const prof = process.env.USERPROFILE?.toLowerCase()
  for (const p of whereAll(name)) {
    if (prof && p.toLowerCase().startsWith(prof)) continue
    return p
  }
  return undefined
}
const GIT = sandboxReachable('git')
const NODE = sandboxReachable('node')
const PYTHON = sandboxReachable('python')

/** Whether Git Bash's `curl` is OpenSSL (on ARM64 it is Schannel only). */
const GIT_BASH_CURL_HAS_OPENSSL =
  isWindows &&
  existsSync(GIT_BASH) &&
  /OpenSSL/i.test(
    spawnSync(GIT_BASH, ['-c', 'curl --version'], {
      encoding: 'utf8',
      timeout: 10_000,
    }).stdout ?? '',
  )

/** System32 `curl.exe`: the Schannel build that ships with Windows. */
const SYSTEM32_CURL = `${process.env.SystemRoot ?? 'C:\\Windows'}\\System32\\curl.exe`

/** `node -e` source: GET `https://<host>/` via a hand-made proxy CONNECT. */
function nodeGetThroughProxy(host: string): string {
  return [
    `const u=new URL(process.env.HTTPS_PROXY);`,
    `const auth='Basic '+Buffer.from(u.username+':'+u.password).toString('base64');`,
    `require('http').request({host:u.hostname,port:u.port,method:'CONNECT',path:'${host}:443',headers:{'Proxy-Authorization':auth}})`,
    `.on('connect',(res,sock)=>{`,
    ` if(res.statusCode!==200){console.error('CONNECT:'+res.statusCode);process.exit(3)}`,
    ` require('https').get({host:'${host}',path:'/',socket:sock,agent:false},`,
    `  r=>{console.log('STATUS:'+r.statusCode);process.exit(r.statusCode===200?0:1)})`,
    ` .on('error',e=>{console.error('TLS:'+(e.code||e.message));process.exit(2)})`,
    // Every address tried, not only the first error: `localhost` is two.
    `}).on('error',e=>require('dns').lookup(u.hostname,{all:true},(_,found)=>{`,
    ` console.error('CONN:'+(e.code||e.message)+' tried '+(e.errors||[e]).map(x=>x.code+'@'+x.address+':'+x.port).join(',')`,
    `  +'; '+u.hostname+' is '+JSON.stringify((found||[]).map(x=>x.address))`,
    `  +'; node '+process.version+', autoSelectFamily '+require('net').getDefaultAutoSelectFamily());`,
    ` process.exit(3)})).end()`,
  ].join('')
}

/** Whether the sandbox account can launch a client with its own TLS stack. */
const HAS_OWN_TLS_CLIENT = OPENSSL_CURL !== undefined || NODE !== undefined

/** A sandboxed HTTPS request through the proxy with such a client. */
function ownTlsGet(host: string): string {
  return OPENSSL_CURL !== undefined
    ? `"${OPENSSL_CURL}" -sS -m 15 -o NUL -w "%{http_code}" https://${host}/`
    : `"${NODE}" -e "${nodeGetThroughProxy(host)}"`
}
const got200 = (r: { stdout: string }): boolean =>
  /(?:^|STATUS:)200$/.test(r.stdout.trim())

/** What an `srt-win` of this tree says it does. */
const SRT_WIN_CAPABILITIES = [
  'profile-deny-expansion',
  'profile-session-grant-check',
  'kept-grant-holders',
  'read-deny-except',
  'exec-holder',
]
const CURRENT_PROFILE_GRANT = JSON.stringify({
  record_version: 1,
  capabilities: SRT_WIN_CAPABILITIES,
  state: 'current',
  extra_exclusions: [],
  exclusions: ['Z:\\no-such-profile\\.ssh'],
  ungranted_only: [],
  paths: [],
  env: {},
})

const SUITE_HOOKS_EXE = process.env.SRT_WIN_TEST_HOOKS_EXE
const SUITE_HAS_PROFILE =
  isWindows && !!SUITE_HOOKS_EXE && !!process.env.SRT_WIN_TEST_PROFILE
function suiteSrtWinPath(): string {
  return SUITE_HAS_PROFILE ? SUITE_HOOKS_EXE! : getSrtWinPath()
}
/** Spread into every real install of this file. */
const SUITE_INSTALL: { skipProfileGrant?: boolean } = SUITE_HAS_PROFILE
  ? {}
  : { skipProfileGrant: true }
if (isWindows && !SUITE_HAS_PROFILE) {
  console.error(
    '[winsrt] SRT_WIN_TEST_HOOKS_EXE / SRT_WIN_TEST_PROFILE are not set: ' +
      'installs skip the profile read grant, and sessions run without it',
  )
}
if (SUITE_HAS_PROFILE) {
  const initialize = SandboxManager.initialize.bind(SandboxManager)
  SandboxManager.initialize = async (cfg, ...rest) => {
    if (cfg.windows?.srtWin?.path === SUITE_HOOKS_EXE) {
      spawnSync(
        SUITE_HOOKS_EXE,
        [SRT_WIN_DISPATCH_ARG1, 'profile', 'grant', '--quiet'],
        { encoding: 'utf8', timeout: 120_000 },
      )
    }
    return initialize(cfg, ...rest)
  }
}

/** Whether `node` on PATH reads NODE_USE_ENV_PROXY (22.21+, 24.5+). */
function nodeReadsProxyEnv(): boolean {
  if (!hasTool('node')) return false
  const r = spawnSync('node', ['-p', 'process.versions.node'], {
    encoding: 'utf8',
  })
  if (r.status !== 0) return false
  const [major = 0, minor = 0] = r.stdout.trim().split('.').map(Number)
  return (
    (major === 22 && minor >= 21) || (major === 24 && minor >= 5) || major > 24
  )
}

// Direct helper calls (and SandboxManager configs) must thread an
// explicit srt-win path — there is no ambient vendor fallback.
// getSrtWinPath() picks the built exe (vendored or cargo
// target/release) on the CI runner.
const TEST_SRT_WIN = isWindows
  ? resolveSrtWin({ path: suiteSrtWinPath() })
  : undefined

function createTestConfig(
  allowedDomains: string[] = ['example.com'],
): SandboxRuntimeConfig {
  return {
    network: {
      allowedDomains,
      deniedDomains: [],
    },
    filesystem: {
      denyRead: [],
      allowRead: [],
      allowWrite: [],
      denyWrite: [],
    },
    windows: {
      sublayerGuid: TEST_SUBLAYER,
      proxyPortRange: [PORT_RANGE[0], PORT_RANGE[1]],
      srtWin: isWindows ? { path: suiteSrtWinPath() } : undefined,
    },
  }
}

/** Run a command inside the Windows sandbox and capture output. */
async function runSandboxed(
  command: string,
  timeoutMs = 60_000,
  extraEnv?: Record<string, string>,
): Promise<{
  stdout: string
  stderr: string
  status: number | null
}> {
  const { argv, env } = await SandboxManager.wrapWithSandboxArgv(command)
  // The child reaches the proxy via the runner's --env overlay; the
  // returned `env` is the BROKER's spawn env (proxy vars also there
  // for diagnostics, but the runner's overlay is what the child sees).
  return spawnAsync(argv[0], argv.slice(1), {
    timeout: timeoutMs,
    env: extraEnv ? { ...env, ...extraEnv } : env,
  })
}

type RunResult = { stdout: string; stderr: string; status: number | null }

/** The names that are in `names` more than once ignoring case. */
function repeatedIgnoringCase(names: string[]): string[] {
  const seen = new Set<string>()
  const repeated = new Set<string>()
  for (const name of names) {
    const folded = name.toUpperCase()
    if (seen.has(folded)) repeated.add(folded)
    seen.add(folded)
  }
  return [...repeated]
}

/** The variable names in the output of cmd's `set`. */
function namesInSetOutput(out: string): string[] {
  return out
    .split(/\r?\n/)
    .filter(line => /^[^=]+=/.test(line))
    .map(line => line.slice(0, line.indexOf('=')))
}

/**
 * Run a sandboxed command up to `attempts` times until `ok` holds.
 * For ALLOW rows only (they hit live hosts; a registry/network blip
 * should not read as a security regression). NEVER use on BLOCK
 * rows — those must stay single-shot so a fluke "allowed" can't be
 * retried away.
 */
async function runSandboxedUntil(
  command: string,
  ok: (r: RunResult) => boolean,
  attempts = 2,
  timeoutMs = 60_000,
): Promise<RunResult> {
  let last: RunResult = { stdout: '', stderr: '', status: null }
  for (let i = 0; i < attempts; i++) {
    last = await runSandboxed(command, timeoutMs)
    if (ok(last)) return last
  }
  return last
}

/**
 * Assert the sandboxed run exited with one of `allowed`; on failure
 * throw with captured stdout+stderr so a CI failure self-explains
 * (curl/tool errors go to stderr — keep `-sS` on curl rows).
 */
function expectStatus(label: string, r: RunResult, allowed: number[]): void {
  if (allowed.includes(r.status ?? -999)) return
  throw new Error(
    `${label}: exit ${r.status} not in [${allowed.join(',')}] · ` +
      `stdout=${JSON.stringify(r.stdout)} · stderr=${JSON.stringify(r.stderr)}`,
  )
}

/**
 * Assert a sandboxed BLOCK row did NOT succeed (exit 0 = the egress
 * reached the host = fence broken). The exact failure code varies by
 * platform/build (DNS-resolve, resolver-thread, connect, TLS, …), so
 * assert only not-success and capture stderr for diagnosis —
 * enumerating codes is cross-platform whack-a-mole. Do NOT re-tighten.
 */
function expectEgressBlocked(label: string, r: RunResult): void {
  if (r.status !== 0) return
  throw new Error(
    `${label}: direct/blocked egress unexpectedly SUCCEEDED (exit 0) · ` +
      `stdout=${JSON.stringify(r.stdout)} · stderr=${JSON.stringify(r.stderr)}`,
  )
}

interface BoundListener {
  port: number
  close: () => Promise<void>
}

function listenOn(port: number): Promise<BoundListener> {
  return new Promise((resolve, reject) => {
    // Minimal HTTP/1.1 responder so a sandboxed `curl` that REACHES
    // it exits 0. A raw-TCP "ok\n" reply makes curl exit non-zero on
    // HTTP-parse failure even though the TCP connect — the
    // loopback-PERMIT we're proving — succeeded.
    const srv: Server = createServer(sock => {
      sock.on('data', () => {
        sock.end(
          'HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nok\n',
        )
      })
      sock.on('error', () => {})
    })
    srv.once('error', reject)
    srv.listen(port, '127.0.0.1', () => {
      const actual = (srv.address() as AddressInfo).port
      resolve({
        port: actual,
        close: () =>
          new Promise<void>(r => {
            srv.close(() => r())
          }),
      })
    })
  })
}

/**
 * Bind the first free port from `candidates`, retrying on
 * EADDRINUSE. Used by the IN-range loopback row (C6) where the
 * candidate list is the proxy range minus the live proxy ports.
 */
async function bindFirstFree(candidates: number[]): Promise<BoundListener> {
  let lastErr: unknown
  for (const p of candidates) {
    try {
      return await listenOn(p)
    } catch (e) {
      lastErr = e
      if ((e as NodeJS.ErrnoException)?.code !== 'EADDRINUSE') throw e
    }
  }
  throw new Error(
    `no free port among ${candidates.join(',')}: ${(lastErr as Error)?.message}`,
  )
}

/**
 * Bind an ephemeral loopback port (the OS picks) and return it
 * provided it falls OUTSIDE the WFP-allowed proxy port range. If
 * the assigned port lands in the range (the Windows ephemeral pool
 * 49152–65535 overlaps it), close and retry — capped at 5; the
 * chance of all 5 landing in a 10-port window of ~16k is
 * effectively zero.
 */
async function bindOutOfRange(): Promise<BoundListener> {
  for (let i = 0; i < 5; i++) {
    const l = await listenOn(0)
    if (l.port < PORT_RANGE[0] || l.port > PORT_RANGE[1]) {
      return l
    }
    await l.close()
  }
  throw new Error(
    `bindOutOfRange: 5 ephemeral binds all landed in ` +
      `[${PORT_RANGE[0]}, ${PORT_RANGE[1]}]`,
  )
}

// Pure-JS object test — runs on all platforms. `srtWin.path` is
// pointed at the test runner's own executable so binary resolution
// passes its existence check on non-Windows hosts.
/**
 * Whether `argv` is one of the `srt-win` calls a session makes without
 * blocking: `acl grant --persistent`, `acl forget`, `profile forget`,
 * `profile status`.
 */
function madeWithoutBlocking(argv: readonly string[]): boolean {
  const own = argv.filter(a => a !== SRT_WIN_DISPATCH_ARG1)
  return (
    (own[0] === 'acl' &&
      (own[1] === 'forget' ||
        (own[1] === 'grant' && own.includes('--persistent')))) ||
    (own[0] === 'profile' && (own[1] === 'forget' || own[1] === 'status'))
  )
}

/**
 * A fake child for an asynchronous `srt-win` call, answered by the test's
 * `spawnSync` mock once its stdin has been written.
 */
function asyncChildAnsweredBySync(exe: string, argv: readonly string[]) {
  const mkStream = () => {
    const s = new EventEmitter() as EventEmitter & {
      setEncoding(e: string): typeof s
      end(d?: string): void
    }
    s.setEncoding = () => s
    s.end = () => {}
    return s
  }
  const child = Object.assign(new EventEmitter(), {
    stdout: mkStream(),
    stderr: mkStream(),
    stdin: mkStream(),
    kill: () => true,
  })
  child.stdin.end = (input?: string) => {
    setImmediate(() => {
      const r = child_process.spawnSync(exe, [...argv], {
        input,
      }) as unknown as {
        status: number | null
        stdout?: string
        stderr?: string
      }
      if (r.stdout) child.stdout.emit('data', r.stdout)
      if (r.stderr) child.stderr.emit('data', r.stderr)
      child.emit('close', r.status, null)
    })
  }
  return child
}

describe('wrapCommandWithSandboxWindows (pure, all platforms)', () => {
  it('argv shape: srtWin.path → [path, --srt-win, exec, …]; --env overlay before --', () => {
    // Mirrors real usage: SandboxManager.initialize() resolves once
    // and threads the SrtWinSpawn handle to every spawn site.
    const srtWin = resolveSrtWin({ path: process.execPath })
    const on = wrapCommandWithSandboxWindows({
      command: 'exit 0',
      httpProxyPort: 60080,
      srtWin,
    })
    // `path` verbatim at argv[0]; the multicall sentinel at argv[1]
    // is what an embedder's dispatcher routes on. `run_from_args`
    // strips it, so the standalone binary accepts it harmlessly.
    expect(on.argv[0]).toBe(process.execPath)
    expect(on.argv[1]).toBe(SRT_WIN_DISPATCH_ARG1)
    expect(on.argv[2]).toBe('exec')
    // Two-hop overlay rides on --env: PATH + the single-sourced
    // proxy set. Values follow each --env as KEY=VALUE.
    const envArgs = on.argv.filter((_, i) => on.argv[i - 1] === '--env')
    expect(envArgs.some(e => e.startsWith('PATH='))).toBe(true)
    expect(envArgs).toContain('http_proxy=http://localhost:60080')
    // No caCertPath passed → CA-bundle vars absent from the overlay.
    // (G1 below covers the caCertPath-set case.)
    expect(envArgs.some(e => e.startsWith('NODE_EXTRA_CA_CERTS='))).toBe(false)
    // Every --env must precede `--` (clap stops parsing after it).
    expect(on.argv.lastIndexOf('--env')).toBeLessThan(on.argv.indexOf('--'))
    // Obsolete same-user flags must NOT appear.
    for (const dead of [
      '--as-sandbox-user',
      '--group-sid',
      '--name',
      '--holder-pid',
      '--skip-group-check',
    ]) {
      expect(on.argv).not.toContain(dead)
    }
  })

  it('argv: --quiet on by default, before --; quiet:false omits it', () => {
    const srtWin = resolveSrtWin({ path: process.execPath })
    const on = wrapCommandWithSandboxWindows({ command: 'x', srtWin })
    expect(on.argv).toContain('--quiet')
    expect(on.argv.indexOf('--quiet')).toBeLessThan(on.argv.indexOf('--'))
    const off = wrapCommandWithSandboxWindows({
      command: 'x',
      quiet: false,
      srtWin,
    })
    expect(off.argv).not.toContain('--quiet')
  })

  it('the exec argv: the token flag, one --write-root per root, the denies, then the command', () => {
    const srtWin = resolveSrtWin({ path: process.execPath })
    const { argv } = wrapCommandWithSandboxWindows({
      command: 'git fetch',
      cwd: 'C:\\work\\repo',
      caCertPath: 'C:/bundle.pem',
      denyRead: ['C:\\secret'],
      denyWrite: ['C:\\work\\repo\\.git\\hooks'],
      writeRoots: ['C:\\work\\repo', 'D:\\other tree'],
      setEnvVars: {},
      binShell: { exe: 'C:\\sh.exe', args: ['-c'] },
      srtWin,
    })
    const dashes = argv.indexOf('--')
    const flags = argv
      .slice(0, dashes)
      .filter((a, i, all) => !(a === '--env' || all[i - 1] === '--env'))
    expect(flags).toEqual([
      process.execPath,
      SRT_WIN_DISPATCH_ARG1,
      'exec',
      '--quiet',
      '--write-restricted-token',
      '--write-root',
      'C:\\work\\repo',
      '--write-root',
      'D:\\other tree',
      '--deny-read',
      'C:\\secret',
      '--deny-write',
      'C:\\work\\repo\\.git\\hooks',
    ])
    expect(argv.slice(dashes)).toEqual(['--', 'C:\\sh.exe', '-c', 'git fetch'])
    const envArgs = argv.filter((_, i) => argv[i - 1] === '--env')
    expect(envArgs).toContain('GIT_CONFIG_COUNT=5')
    expect(envArgs).toContain('GIT_CONFIG_KEY_4=http.sslBackend')
    expect(envArgs).toContain('GIT_CONFIG_VALUE_4=openssl')
    // The schannel knobs stay (harmless under the OpenSSL backend).
    expect(envArgs).toContain('GIT_CONFIG_KEY_2=http.schannelUseSSLCAInfo')
  })

  it('no write roots: the token flag alone, once, before --', () => {
    const srtWin = resolveSrtWin({ path: process.execPath })
    const { argv } = wrapCommandWithSandboxWindows({
      command: 'git fetch',
      cwd: 'C:\\work\\repo',
      srtWin,
    })
    expect(argv.filter(a => a === '--write-restricted-token')).toHaveLength(1)
    expect(argv).not.toContain('--write-root')
    expect(argv.indexOf('--write-restricted-token')).toBeLessThan(
      argv.indexOf('--'),
    )
  })

  it('resolveSrtWin: explicit path → used verbatim, sentinel prepend', () => {
    const set = resolveSrtWin({ path: process.execPath })
    expect(set.exe).toBe(process.execPath)
    expect(set.prependArgs).toEqual([SRT_WIN_DISPATCH_ARG1])
    // The TS const must mirror the Rust `srt_win::SRT_WIN_DISPATCH_ARG1`.
    expect(SRT_WIN_DISPATCH_ARG1).toBe('--srt-win')
  })

  it('resolveSrtWin: missing explicit path is named (no fallback)', () => {
    expect(() => resolveSrtWin({ path: '/nonexistent/srt-win.exe' })).toThrow(
      /windows\.srtWin\.path is set to '.+' but the file does not exist/,
    )
  })

  it('resolveSrtWin: no path → throws naming VENDORED_SRT_WIN_EXE', () => {
    // No implicit vendor fallback — the message tells the embedder
    // how to opt in explicitly.
    expect(() => resolveSrtWin()).toThrow(
      /set windows\.srtWin\.path[\s\S]*VENDORED_SRT_WIN_EXE/,
    )
    // {} (path absent at runtime despite the type) hits the same
    // no-path branch; cast keeps tsc-test clean.
    expect(() => resolveSrtWin({} as SrtWinConfig)).toThrow(
      /VENDORED_SRT_WIN_EXE/,
    )
  })

  it('VENDORED_SRT_WIN_EXE: absolute path to the arch-specific vendored exe', () => {
    expect(isAbsolute(VENDORED_SRT_WIN_EXE)).toBe(true)
    expect(VENDORED_SRT_WIN_EXE.split(/[\\/]/).slice(-4)).toEqual([
      'vendor',
      'srt-win',
      process.arch,
      'srt-win.exe',
    ])
  })

  it('drops NO_PROXY/no_proxy from the --env overlay (WFP fences direct loopback)', () => {
    const srtWin = resolveSrtWin({ path: process.execPath })
    const { argv } = wrapCommandWithSandboxWindows({
      command: 'curl http://127.0.0.1:9000/',
      httpProxyPort: 60080,
      socksProxyPort: 60080,
      srtWin,
    })
    const envArgs = argv.filter((_, i) => argv[i - 1] === '--env')
    // On POSIX, NO_PROXY=localhost,127.0.0.1,… lets the child connect
    // directly (seatbelt/bwrap allow loopback). On Windows the WFP
    // fence blocks direct loopback outside the proxy-port PERMIT
    // range, so NO_PROXY would make every localhost request fail. The
    // returned `env` is the BROKER spawn env (spreads process.env, so
    // may inherit a host NO_PROXY — irrelevant, srt-win runs as the
    // real user); only the `--env` overlay reaches the sandboxed child.
    expect(envArgs.some(e => e.startsWith('NO_PROXY='))).toBe(false)
    expect(envArgs.some(e => e.startsWith('no_proxy='))).toBe(false)
    // The proxy vars themselves survive — only the bypass list is dropped.
    expect(envArgs.some(e => e.startsWith('https_proxy='))).toBe(true)
  })

  it('the --env overlay names each variable once ignoring case', () => {
    const srtWin = resolveSrtWin({ path: process.execPath })
    const { argv } = wrapCommandWithSandboxWindows({
      command: 'exit 0',
      httpProxyPort: 60080,
      socksProxyPort: 60081,
      caCertPath: 'C:\\ca\\bundle.pem',
      setEnvVars: {
        Https_Proxy: 'http://caller.invalid',
        Path: 'C:\\caller',
        NODE_USE_ENV_PROXY: '1',
      },
      srtWin,
    })
    const envArgs = argv.filter((_, i) => argv[i - 1] === '--env')
    const names = envArgs.map(e => e.slice(0, e.indexOf('=')))
    expect(repeatedIgnoringCase(names)).toEqual([])
    expect(envArgs).toContain('http_proxy=http://localhost:60080')
    expect(envArgs).toContain('all_proxy=http://localhost:60080')
    expect(envArgs).toContain('grpc_proxy=http://localhost:60080')
    expect(envArgs).toContain('ftp_proxy=socks5h://localhost:60081')
    expect(envArgs).toContain('RSYNC_PROXY=localhost:60081')
    expect(envArgs).toContain('https_proxy=http://localhost:60080')
    expect(envArgs).toContain('NODE_USE_ENV_PROXY=1')
    expect(envArgs).toContain('Path=C:\\caller')
    expect(names).toContain('DOCKER_HTTP_PROXY')
  })

  it('mergeWindowsEnv: a later layer replaces a name in any case', () => {
    expect(
      mergeWindowsEnv(
        { PATH: 'a', HTTP_PROXY: 'one', NODE_USE_ENV_PROXY: '1', Gone: 'x' },
        { Path: 'b', http_proxy: 'two', rsync_proxy: 'h:1', GONE: undefined },
        { Http_Proxy: 'three', node_use_env_proxy: '0', NO_PROXY: '' },
      ),
    ).toEqual({
      Path: 'b',
      http_proxy: 'three',
      node_use_env_proxy: '0',
      Gone: 'x',
      RSYNC_PROXY: 'h:1',
      no_proxy: '',
    })
  })

  it('mergeWindowsEnv: an undefined value in a later layer erases nothing', () => {
    const merged = mergeWindowsEnv(
      { PATH: 'C:\\Windows', Kept: 'x' },
      { Path: undefined, KEPT: undefined, Absent: undefined },
    )
    expect(merged).toEqual({ PATH: 'C:\\Windows', Kept: 'x' })
    expect(Object.keys(merged)).toEqual(['PATH', 'Kept'])
  })

  it('allowLoopback: passed to exec before --, and absent without it', () => {
    const srtWin = resolveSrtWin({ path: process.execPath })
    const { argv } = wrapCommandWithSandboxWindows({
      command: 'x',
      allowLoopback: true,
      srtWin,
    })
    const at = argv.indexOf('--allow-loopback')
    expect(at).toBeGreaterThan(argv.indexOf('exec'))
    expect(at).toBeLessThan(argv.indexOf('--'))
    for (const off of [{}, { allowLoopback: false }]) {
      const without = wrapCommandWithSandboxWindows({
        command: 'x',
        ...off,
        srtWin,
      })
      expect(without.argv).not.toContain('--allow-loopback')
    }
  })

  it('allowLoopback: no_proxy names the loopback hosts, and only those', () => {
    const srtWin = resolveSrtWin({ path: process.execPath })
    const proxied = {
      command: 'curl http://127.0.0.1:3000/',
      httpProxyPort: 60080,
      socksProxyPort: 60080,
      srtWin,
    }
    const envOf = (argv: string[]) =>
      argv.filter((_, i) => argv[i - 1] === '--env')
    const envArgs = envOf(
      wrapCommandWithSandboxWindows({ ...proxied, allowLoopback: true }).argv,
    )
    // Only the loopback hosts: the private-network entries of the POSIX
    // list stay out, as the fence still blocks those destinations.
    expect(WINDOWS_LOOPBACK_NO_PROXY).toBe('localhost,127.0.0.1,::1')
    // Under the one spelling every proxy variable has: lower case, once.
    expect(envArgs.filter(e => /^no_proxy=/i.test(e))).toEqual([
      `no_proxy=${WINDOWS_LOOPBACK_NO_PROXY}`,
    ])
    expect(envArgs.some(e => e.startsWith('https_proxy='))).toBe(true)
    const closed = envOf(wrapCommandWithSandboxWindows(proxied).argv)
    expect(closed.some(e => /^no_proxy=/i.test(e))).toBe(false)
    const bare = wrapCommandWithSandboxWindows({
      command: 'x',
      allowLoopback: true,
      srtWin,
    })
    expect(bare.argv.some(a => /^no_proxy=/i.test(a))).toBe(false)
  })

  it('NODE_USE_ENV_PROXY=1 rides the --env overlay with the HTTP proxy, unless the caller names it', () => {
    const srtWin = resolveSrtWin({ path: process.execPath })
    const proxied = {
      command: 'node app.js',
      httpProxyPort: 60080,
      socksProxyPort: 60080,
      proxyAuthToken: 'tok',
      srtWin,
    }
    const named = (p: Parameters<typeof wrapCommandWithSandboxWindows>[0]) => {
      const { argv } = wrapCommandWithSandboxWindows(p)
      return argv
        .filter((_, i) => argv[i - 1] === '--env')
        .filter(e => e.toUpperCase().startsWith('NODE_USE_ENV_PROXY='))
    }
    expect(named(proxied)).toEqual(['NODE_USE_ENV_PROXY=1'])
    expect(
      named({ ...proxied, setEnvVars: { NODE_USE_ENV_PROXY: '0' } }),
    ).toEqual(['NODE_USE_ENV_PROXY=0'])
    // Windows reads names ignoring case: one entry, the caller's.
    expect(
      named({ ...proxied, setEnvVars: { node_use_env_proxy: '' } }),
    ).toEqual(['node_use_env_proxy='])
    expect(
      named({ command: 'node app.js', socksProxyPort: 60081, srtWin }),
    ).toEqual([])
    expect(named({ command: 'node app.js', srtWin })).toEqual([])
  })
})

describe('parseWindowsBinShell (pure, all platforms)', () => {
  it('maps tokens/paths to {exe,args} and rejects the rest', () => {
    // Default + bare tokens.
    const cmd = parseWindowsBinShell(undefined)
    expect(cmd.exe).toMatch(/System32[\\/]cmd\.exe$/)
    expect(cmd.args).toEqual(['/d', '/s', '/c'])
    expect(parseWindowsBinShell('cmd')).toEqual(cmd)
    expect(parseWindowsBinShell('pwsh')).toEqual({
      exe: 'pwsh.exe',
      args: ['-NoProfile', '-Command'],
    })
    expect(parseWindowsBinShell('PowerShell').exe).toMatch(
      /System32[\\/]WindowsPowerShell[\\/]v1\.0[\\/]powershell\.exe$/,
    )
    // Absolute bash/sh path → keep verbatim, `-c`.
    for (const p of [
      'C:\\Program Files\\Git\\bin\\bash.exe',
      'C:\\Program Files\\Git\\usr\\bin\\bash.exe',
      'C:\\Program Files\\Git\\bin\\sh.exe',
    ]) {
      expect(parseWindowsBinShell(p)).toEqual({ exe: p, args: ['-c'] })
    }
    // Absolute pwsh/powershell path → keep verbatim, PS flags.
    // (Formerly threw — now the caller's resolved install is honoured.)
    const pwshAbs = 'C:\\Program Files\\PowerShell\\7\\pwsh.exe'
    expect(parseWindowsBinShell(pwshAbs)).toEqual({
      exe: pwshAbs,
      args: ['-NoProfile', '-Command'],
    })
    // Object form: passthrough with absolute-exe validation only.
    const obj = { exe: pwshAbs, args: ['-NoProfile', '-EncodedCommand'] }
    expect(parseWindowsBinShell(obj)).toBe(obj)
    expect(() =>
      parseWindowsBinShell({ exe: 'pwsh.exe', args: ['-Command'] }),
    ).toThrow(/binShell\.exe must be an absolute path/)
    // Bare bash: caller must pass the resolved absolute install path
    // (PATH-resolved 'bash' could be WSL, not Git Bash).
    expect(() => parseWindowsBinShell('bash')).toThrow(/absolute/)
    // Relative-with-directory: never silently degrade.
    expect(() => parseWindowsBinShell('bin\\bash.exe')).toThrow(
      /bare token or an absolute path/,
    )
    // Unknown values fail loud rather than silently routing to cmd.exe.
    expect(() => parseWindowsBinShell('zsh')).toThrow(/unrecognised binShell/)
    expect(() =>
      parseWindowsBinShell('C:\\Program Files\\Git\\git-bash.exe'),
    ).toThrow(/unrecognised binShell/)
  })
})

describe('WINDOWS_INSTALL_COMMAND (pure, all platforms)', () => {
  const repoRoot = join(import.meta.dir, '../..')

  it('runs this package', () => {
    const pkg = JSON.parse(
      readFileSync(join(repoRoot, 'package.json'), 'utf8'),
    ) as { name: string; bin: Record<string, string> }
    expect(winUtils.WINDOWS_INSTALL_COMMAND).toBe(
      `npx ${pkg.name} windows-install`,
    )
    // npx picks the bin itself only while they all point at one file.
    expect(new Set(Object.values(pkg.bin)).size).toBe(1)
  })

  it('is the only spelling in src/ and the README', () => {
    const otherSpelling =
      /npx\s+(-\S+\s+)*sandbox-runtime|(?<!@anthropic-ai\/)sandbox-runtime\s+windows-/
    const sources = fs
      .readdirSync(join(repoRoot, 'src'), { recursive: true, encoding: 'utf8' })
      .filter(file => file.endsWith('.ts'))
      .map(file => join('src', file))
    const offenders = ['README.md', ...sources].filter(file =>
      otherSpelling.test(readFileSync(join(repoRoot, file), 'utf8')),
    )
    expect(offenders).toEqual([])
  })
})

describe('WindowsSandboxError (pure, all platforms)', () => {
  it('carries a stable .code and is instanceof Error', () => {
    const e = new WindowsSandboxError('install_config_conflict', 'x')
    expect(e).toBeInstanceOf(Error)
    expect(e).toBeInstanceOf(WindowsSandboxError)
    expect(e.code).toBe('install_config_conflict')
    expect(e.name).toBe('WindowsSandboxError')
    expect(e.message).toBe('x')
    expect(e.subcommand).toBeUndefined()
    // Spawn-helper throws set .subcommand to args[0].
    const s = new WindowsSandboxError('srt_win_timeout', 'y', 'install')
    expect(s.subcommand).toBe('install')
  })

  it('parseWindowsBinShell throws with .code = bin_shell_invalid', () => {
    // Consumers branch on `.code` instead of prose-matching `.message`.
    let err: unknown
    try {
      parseWindowsBinShell('zsh')
    } catch (e) {
      err = e
    }
    expect(err).toBeInstanceOf(WindowsSandboxError)
    expect((err as WindowsSandboxError).code).toBe('bin_shell_invalid')
  })
})

describe('WindowsConfigSchema.sandboxUser (pure, all platforms)', () => {
  it('accepts a valid name and rejects empty / >20 chars', () => {
    expect(
      WindowsConfigSchema.safeParse({ sandboxUser: 'srt-sb-custom' }).success,
    ).toBe(true)
    expect(WindowsConfigSchema.safeParse({}).success).toBe(true)
    // Windows local usernames are capped at 20 (LM20_UNLEN).
    expect(
      WindowsConfigSchema.safeParse({ sandboxUser: 'a'.repeat(21) }).success,
    ).toBe(false)
    expect(WindowsConfigSchema.safeParse({ sandboxUser: '' }).success).toBe(
      false,
    )
  })
})

describe('network.allowLocalBinding on Windows (pure, all platforms)', () => {
  it('the one port that stays blocked is the one srt-win leaves out of the permit', () => {
    // `LOOPBACK_PROBE_PORT` in the Rust source, parsed as text: the two
    // constants are kept by hand and must not drift.
    const rust = readFileSync(
      join(import.meta.dir, '../../vendor/srt-win-src/src/wfp.rs'),
      'utf8',
    )
    const m = /pub const LOOPBACK_PROBE_PORT: u16 = (\d+);/.exec(rust)
    expect(m).not.toBeNull()
    expect(Number(m![1])).toBe(WINDOWS_LOOPBACK_PROBE_PORT)
    expect(WINDOWS_LOOPBACK_PROBE_PORT).toBe(1)
    // One constant, not a list.
    expect(rust.match(/pub const LOOPBACK_\w*PORTS?\b/g)).toEqual([
      'pub const LOOPBACK_PROBE_PORT',
    ])
  })

  it('the effect text says loopback is open, names the one blocked port and the way off the machine', () => {
    expect(WINDOWS_ALLOW_LOOPBACK_EFFECT).toMatch(/^Loopback is open/)
    expect(WINDOWS_ALLOW_LOOPBACK_EFFECT).toMatch(/every TCP and UDP port/)
    expect(WINDOWS_ALLOW_LOOPBACK_EFFECT).toContain(
      `port ${WINDOWS_LOOPBACK_PROBE_PORT} alone stays blocked`,
    )
    expect(WINDOWS_ALLOW_LOOPBACK_EFFECT).toMatch(/forwarder/)
    expect(WINDOWS_ALLOW_LOOPBACK_EFFECT).toMatch(/off the machine/)
  })

  it('there is no loopback port range: the schema drops the key like any unknown one', () => {
    // WindowsConfigSchema is not strict, so the key is dropped like
    // any other unknown one — it configures nothing.
    const r = SandboxRuntimeConfigSchema.safeParse({
      network: { allowedDomains: [], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
      windows: { loopbackPortRange: [3000, 3099] },
    })
    expect(r.success).toBe(true)
    if (r.success) {
      expect(r.data.windows).toEqual({})
      expect(r.data.network.allowLocalBinding).toBeUndefined()
    }
    expect(
      WindowsConfigSchema.safeParse({ loopbackPortRange: 'x' }).success,
    ).toBe(true)
  })
})

describe('WindowsConfigSchema (pure, all platforms)', () => {
  it('has no writeRestrictedToken option: a config that still sets it parses without it', () => {
    expect('writeRestrictedToken' in WindowsConfigSchema.shape).toBe(false)
    expect(
      WindowsConfigSchema.parse({ writeRestrictedToken: false }),
    ).not.toHaveProperty('writeRestrictedToken')
  })
})

describe('buildGitConfigEnv (pure, all platforms)', () => {
  it('emits safe.directory (dir + dir/*) + schannel knobs; forward slashes; deduped', () => {
    const env = buildGitConfigEnv({
      safeDirs: ['C:\\work\\repo', 'C:/work/repo', 'C:\\other'],
      schannelCa: true,
    })
    // 2 unique dirs × (exact + `<dir>/*`) + 2 schannel knobs = 6.
    expect(env.GIT_CONFIG_COUNT).toBe('6')
    expect(env.GIT_CONFIG_KEY_0).toBe('safe.directory')
    expect(env.GIT_CONFIG_VALUE_0).toBe('C:/work/repo')
    expect(env.GIT_CONFIG_VALUE_1).toBe('C:/work/repo/*')
    expect(env.GIT_CONFIG_VALUE_2).toBe('C:/other')
    expect(env.GIT_CONFIG_VALUE_3).toBe('C:/other/*')
    expect(env.GIT_CONFIG_KEY_4).toBe('http.schannelUseSSLCAInfo')
    expect(env.GIT_CONFIG_VALUE_4).toBe('true')
    expect(env.GIT_CONFIG_KEY_5).toBe('http.schannelCheckRevoke')
    expect(env.GIT_CONFIG_VALUE_5).toBe('false')
  })

  it('composes with an existing GIT_CONFIG_COUNT in baseEnv', () => {
    const env = buildGitConfigEnv({
      safeDirs: ['C:/w'],
      schannelCa: false,
      baseEnv: { GIT_CONFIG_COUNT: '2' },
    })
    // Continues numbering at 2; new total 4 (dir + dir/*). KEY_0/1
    // are the caller's.
    expect(env.GIT_CONFIG_KEY_2).toBe('safe.directory')
    expect(env.GIT_CONFIG_VALUE_2).toBe('C:/w')
    expect(env.GIT_CONFIG_VALUE_3).toBe('C:/w/*')
    expect(env.GIT_CONFIG_COUNT).toBe('4')
    expect(env.GIT_CONFIG_KEY_0).toBeUndefined()
  })

  it('collapses to safe.directory=* above the wildcard threshold', () => {
    const env = buildGitConfigEnv({
      safeDirs: Array.from({ length: 20 }, (_, i) => `C:/d${i}`),
      schannelCa: false,
    })
    expect(env.GIT_CONFIG_COUNT).toBe('1')
    expect(env.GIT_CONFIG_VALUE_0).toBe('*')
  })

  it('returns {} when nothing to emit', () => {
    expect(buildGitConfigEnv({ safeDirs: [], schannelCa: false })).toEqual({})
  })

  it('http.sslBackend=openssl appears only with opensslBackend', () => {
    const values = (env: Record<string, string>) =>
      Object.entries(env)
        .filter(([k]) => k.startsWith('GIT_CONFIG_KEY_'))
        .map(([k, v]) => `${v}=${env[k.replace('KEY', 'VALUE')]}`)
    const off = buildGitConfigEnv({ safeDirs: ['C:/r'], schannelCa: true })
    expect(values(off)).not.toContain('http.sslBackend=openssl')
    expect(
      values(
        buildGitConfigEnv({
          safeDirs: ['C:/r'],
          schannelCa: true,
          opensslBackend: false,
        }),
      ),
    ).toEqual(values(off))
    const on = buildGitConfigEnv({
      safeDirs: ['C:/r'],
      schannelCa: true,
      opensslBackend: true,
    })
    // Appended last, so every earlier entry keeps its index.
    expect(values(on)).toEqual([...values(off), 'http.sslBackend=openssl'])
    expect(on.GIT_CONFIG_COUNT).toBe(String(Number(off.GIT_CONFIG_COUNT) + 1))
    expect(buildGitConfigEnv({ safeDirs: [], opensslBackend: true })).toEqual({
      GIT_CONFIG_COUNT: '1',
      GIT_CONFIG_KEY_0: 'http.sslBackend',
      GIT_CONFIG_VALUE_0: 'openssl',
    })
    // The caller's GIT_CONFIG_COUNT=0 opt-out still wins.
    expect(
      buildGitConfigEnv({
        safeDirs: [],
        opensslBackend: true,
        baseEnv: { GIT_CONFIG_COUNT: '0' },
      }),
    ).toEqual({})
  })

  it('wrapCommandWithSandboxWindows: GIT_CONFIG_* rides the --env overlay', () => {
    const srtWin = resolveSrtWin({ path: process.execPath })
    const { argv } = wrapCommandWithSandboxWindows({
      command: 'git status',
      cwd: 'C:\\work\\repo',
      allowWrite: ['C:\\work\\other'],
      caCertPath: 'C:/bundle.pem',
      srtWin,
    })
    const envArgs = argv.filter((_, i) => argv[i - 1] === '--env')
    // safe.directory entries, the schannel knobs, then the OpenSSL backend.
    expect(envArgs).toContain('GIT_CONFIG_COUNT=7')
    expect(envArgs).toContain('GIT_CONFIG_KEY_6=http.sslBackend')
    expect(envArgs).toContain('GIT_CONFIG_VALUE_6=openssl')
    expect(envArgs).toContain('GIT_CONFIG_KEY_0=safe.directory')
    expect(envArgs).toContain('GIT_CONFIG_VALUE_0=C:/work/repo')
    expect(envArgs).toContain('GIT_CONFIG_VALUE_1=C:/work/repo/*')
    expect(envArgs).toContain('GIT_CONFIG_VALUE_2=C:/work/other')
    expect(envArgs).toContain('GIT_CONFIG_KEY_4=http.schannelUseSSLCAInfo')
    expect(envArgs).toContain('GIT_CONFIG_KEY_5=http.schannelCheckRevoke')
    // All --env precede `--` (clap stops parsing after it).
    expect(argv.lastIndexOf('--env')).toBeLessThan(argv.indexOf('--'))
  })

  it('wrapCommandWithSandboxWindows: gitSafeDirectories flows to safe.directory without allowWrite', () => {
    const srtWin = resolveSrtWin({ path: process.execPath })
    const { argv } = wrapCommandWithSandboxWindows({
      command: 'git status',
      cwd: 'C:\\repo\\sub\\dir',
      gitSafeDirectories: ['C:\\repo'],
      srtWin,
    })
    const envArgs = argv.filter((_, i) => argv[i - 1] === '--env')
    // No schannel knobs (no caCertPath), and the OpenSSL backend entry.
    expect(envArgs).toContain('GIT_CONFIG_COUNT=5')
    expect(envArgs).toContain('GIT_CONFIG_KEY_4=http.sslBackend')
    expect(envArgs).toContain('GIT_CONFIG_KEY_0=safe.directory')
    expect(envArgs).toContain('GIT_CONFIG_VALUE_0=C:/repo/sub/dir')
    expect(envArgs).toContain('GIT_CONFIG_VALUE_1=C:/repo/sub/dir/*')
    expect(envArgs).toContain('GIT_CONFIG_KEY_2=safe.directory')
    expect(envArgs).toContain('GIT_CONFIG_VALUE_2=C:/repo')
    expect(envArgs).toContain('GIT_CONFIG_VALUE_3=C:/repo/*')
    // No --allow-write flag exists on `srt-win exec`; the write grant
    // is session-level. Assert gitSafeDirectories didn't leak into a
    // per-exec deny/allow flag either.
    expect(argv.join(' ')).not.toMatch(/--(allow|deny)-\w+ C:[/\\]repo\b/)
  })

  it('root safeDir keeps its trailing slash; explicit COUNT=0 is an opt-out', () => {
    const env = buildGitConfigEnv({ safeDirs: ['C:\\'], schannelCa: false })
    // `C:` alone is drive-relative-cwd, not the root — git wants `C:/`.
    // Glob is `C:/*` (single slash — `//*` never wildmatches).
    expect(env.GIT_CONFIG_VALUE_0).toBe('C:/')
    expect(env.GIT_CONFIG_VALUE_1).toBe('C:/*')
    // POSIX root: `/` must not strip to `` (git's list-reset sentinel).
    const posix = buildGitConfigEnv({ safeDirs: ['/'], schannelCa: false })
    expect(posix.GIT_CONFIG_VALUE_0).toBe('/')
    expect(posix.GIT_CONFIG_VALUE_1).toBe('/*')
    // Explicit GIT_CONFIG_COUNT=0 in baseEnv → respect the opt-out.
    expect(
      buildGitConfigEnv({
        safeDirs: ['C:/w'],
        schannelCa: true,
        baseEnv: { GIT_CONFIG_COUNT: '0' },
      }),
    ).toEqual({})
  })

  it.if(isMacOS)(
    'wrapCommandWithSandboxMacOS: gitSafeDirectories alone still emits GIT_CONFIG_*',
    async () => {
      // Repo owned by another unix user + filesystem.disabled: no
      // net/fs/env restriction, only safe.directory. The early-return
      // gate must NOT swallow the emit.
      const { wrapCommandWithSandboxMacOS } = await import(
        '../../src/sandbox/macos-sandbox-utils.js'
      )
      const wrapped = wrapCommandWithSandboxMacOS({
        command: 'git status',
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig: undefined,
        gitSafeDirectories: ['/repo'],
      })
      expect(wrapped).toContain('GIT_CONFIG_KEY_0=safe.directory')
      expect(wrapped).toContain('GIT_CONFIG_VALUE_0=/repo')
      expect(wrapped).not.toBe('git status')
    },
  )
})

// ════════════════════════════════════════════════════════════════════
// Async variants — sync/async parity (pure, all platforms)
// ════════════════════════════════════════════════════════════════════
// These pin the *Async twins to the same argv shape and result mapping
// as the sync originals by spying on child_process.spawn/spawnSync.
// The srtWin handle points at the test runner's own executable so
// resolveSrtWin's existence check passes on non-Windows hosts; the
// spies intercept before any real process is spawned.

describe('windowsStateDir (pure, all platforms)', () => {
  // Mirrors srt-win's state_db::state_dir(): the machine-wide
  // %ProgramData%\sandbox-runtime, a pure env-derived path (no fs
  // probing — the elevated install creates it).
  let savedProgramData: string | undefined

  beforeAll(() => {
    savedProgramData = process.env.ProgramData
  })
  afterAll(() => {
    if (savedProgramData === undefined) delete process.env.ProgramData
    else process.env.ProgramData = savedProgramData
  })

  it('joins %ProgramData%\\sandbox-runtime', () => {
    process.env.ProgramData = 'C:\\ProgramData'
    expect(windowsStateDir()).toBe('C:\\ProgramData\\sandbox-runtime')
  })

  it('throws when ProgramData is unset', () => {
    delete process.env.ProgramData
    expect(() => windowsStateDir()).toThrow('ProgramData')
  })
})

describe('rankWindowsFsAccess (pure, all platforms)', () => {
  type Lists = Parameters<typeof rankWindowsFsAccess>[0]
  const rank = (lists: Partial<Lists>): WindowsFsAccessSet =>
    rankWindowsFsAccess({
      allowRead: [],
      allowWrite: [],
      denyRead: [],
      denyWrite: [],
      credentialDeny: [],
      ...lists,
    })

  // On no disk, so compared as spelled.
  const W = 'C:\\srt-w'
  const D = 'C:\\srt-w\\d'
  const SUB = 'C:\\srt-w\\d\\sub'
  const SUB2 = 'C:\\srt-w\\d\\sub2'
  const BESIDE = 'C:\\srt-w\\dx'

  it.each<[string, Partial<Lists>, Partial<WindowsFsAccessSet>]>([
    [
      'allowWrite around a denyWrite: write',
      { allowWrite: [W], denyWrite: [D] },
      { grantWrite: [W], denyWrite: [D] },
    ],
    [
      'allowWrite beside a denyWrite: write',
      { allowWrite: [BESIDE], denyWrite: [D] },
      { grantWrite: [BESIDE], denyWrite: [D] },
    ],
    [
      'allowWrite beneath a denyWrite: read',
      { allowWrite: [SUB], denyWrite: [D] },
      { grantRead: [SUB], denyWrite: [D] },
    ],
    [
      'allowWrite at a denyWrite: read',
      { allowWrite: [D], denyWrite: [D] },
      { grantRead: [D], denyWrite: [D] },
    ],
    [
      'allowWrite around and beneath a denyWrite: write, read',
      { allowWrite: [W, SUB], denyWrite: [D] },
      { grantWrite: [W], grantRead: [SUB], denyWrite: [D] },
    ],
    [
      'a path in allowRead too is granted once',
      { allowRead: [SUB], allowWrite: [SUB], denyWrite: [D] },
      { grantRead: [SUB], denyWrite: [D] },
    ],
    [
      'allowRead beneath a denyWrite: read',
      { allowRead: [SUB], denyWrite: [D] },
      { grantRead: [SUB], denyWrite: [D] },
    ],
    [
      'allowRead at and beneath a denyRead: read',
      { allowRead: [D, SUB], denyRead: [D] },
      { grantRead: [D, SUB], denyRead: [D] },
    ],
    [
      'allowWrite beneath a denyRead: write',
      { allowWrite: [SUB], denyRead: [D] },
      { grantWrite: [SUB], denyRead: [D] },
    ],
    [
      'allowRead and allowWrite around a credential deny: read, write',
      { allowRead: [W], allowWrite: [W], credentialDeny: [D] },
      { grantRead: [W], grantWrite: [W], denyRead: [D] },
    ],
    [
      'allowRead and allowWrite at or beneath a credential deny: nothing',
      { allowRead: [D, SUB], allowWrite: [D, SUB2], credentialDeny: [D] },
      { denyRead: [D] },
    ],
    [
      'allowWrite beneath a denyWrite and a credential deny: nothing',
      { allowWrite: [SUB], denyWrite: [D], credentialDeny: [W] },
      { denyRead: [W], denyWrite: [D] },
    ],
    [
      'a credential deny that is in denyRead too is stamped once',
      { allowRead: [SUB], denyRead: [D], credentialDeny: [D] },
      { denyRead: [D] },
    ],
    [
      'a held write grant beneath a denyWrite: write-denied at its own path',
      {
        denyWrite: [D],
        held: { grantRead: [SUB2], grantWrite: [W, SUB, BESIDE] },
      },
      { denyWrite: [D, SUB] },
    ],
    [
      'held grants at or beneath a credential deny: read-denied at their own',
      {
        credentialDeny: [D],
        held: { grantRead: [W, D, SUB], grantWrite: [SUB2, BESIDE] },
      },
      { denyRead: [D, SUB, SUB2] },
    ],
    [
      'held grants beneath a denyRead: as they are',
      { denyRead: [D], held: { grantRead: [SUB], grantWrite: [SUB2] } },
      { denyRead: [D] },
    ],
  ])('%s', (_name, lists, want) => {
    expect(rank(lists)).toEqual({
      grantRead: [],
      grantWrite: [],
      denyRead: [],
      denyWrite: [],
      ...want,
    })
  })

  const isBeneath = (deny: string, grant: string): boolean =>
    rank({ allowRead: [grant], credentialDeny: [deny] }).grantRead.length === 0

  it.each<[string, string, boolean]>([
    [D, 'c:\\SRT-W\\D\\Sub', true],
    [D + '\\', SUB, true],
    ['C:/srt-w/d', SUB, true],
    [D, 'C:/srt-w//d/sub/', true],
    ['C:\\srt-w\\x\\..\\d', SUB, true],
    ['\\\\?\\' + D, SUB, true],
    ['C:\\', SUB, true],
    [D, BESIDE, false],
    [D, 'D:\\srt-w\\d\\sub', false],
    [SUB, D, false],
    ['\\\\srv\\share\\d', '\\\\SRV\\Share\\D\\sub', true],
    ['\\\\?\\UNC\\srv\\share\\d', '\\\\srv\\share\\d\\sub', true],
    ['\\\\srv\\share\\d', '\\\\srv\\share2\\d\\sub', false],
  ])('as spelled, beneath %p is %p: %p', (deny, grant, beneath) => {
    expect(isBeneath(deny, grant)).toBe(beneath)
  })

  it('a UNC path is not looked up', () => {
    const lookup = spyOn(realpathSync, 'native')
    try {
      expect(isBeneath('\\\\srv\\share', '//srv/share/sub')).toBe(true)
      expect(isBeneath('\\\\?\\UNC\\srv\\share', D)).toBe(false)
      expect(lookup.mock.calls).toEqual([[D]])
    } finally {
      lookup.mockRestore()
    }
  })

  describe('on disk', () => {
    let spelled: string
    let root: string

    beforeAll(() => {
      spelled = mkdtempSync(join(tmpdir(), 'srt-rank-'))
      root = realpathSync.native(spelled)
      mkdirSync(join(root, 'd', 'sub'), { recursive: true })
      mkdirSync(join(root, 'e', 'sub'), { recursive: true })
      symlinkSync(join(root, 'd'), join(root, 'to-d'), 'junction')
      symlinkSync(join(root, 'e'), join(root, 'd', 'to-e'), 'junction')
    })

    afterAll(() => {
      try {
        rmSync(root, { recursive: true, force: true })
      } catch {
        // Not every runtime removes a junction.
      }
    })

    it.each<[string, string, boolean]>([
      ['d', 'd/sub', true],
      ['d', 'e/sub', false],
      ['d', 'to-d/sub', true],
      ['to-d', 'd/sub', true],
      ['to-d', 'to-d', true],
      ['e', 'd/to-e/sub', true],
      ['d', 'd/to-e/sub', false],
      ['absent', 'd/sub', false],
    ])('beneath %p is %p: %p', (deny, grant, beneath) => {
      expect(isBeneath(join(root, deny), join(root, grant))).toBe(beneath)
    })

    it('a path counts as it resolves, however the temp folder is spelled', () => {
      console.error(`[winsrt rank] spelled=${spelled} resolved=${root}`)
      expect(isBeneath(join(spelled, 'd'), join(root, 'd', 'sub'))).toBe(true)
      expect(isBeneath(join(root, 'd'), join(spelled, 'd', 'sub'))).toBe(true)
      expect(
        isBeneath(join(root, 'd').toUpperCase(), join(root, 'd', 'sub')),
      ).toBe(true)
    })

    it('a path is handed on as it was spelled', () => {
      const grant = join(root, 'to-d', 'sub')
      expect(
        rank({ allowWrite: [grant], denyWrite: [join(root, 'd')] }).grantRead,
      ).toEqual([grant])
    })
  })
})

// Run once per child-token mode; not on Windows, where the L-rows make the calls.
describe.if(!isWindows)('what srt-win is handed (platform spy)', () => {
  const spies: Array<ReturnType<typeof spyOn>> = []
  let granted: Pick<WindowsAclGrantOptions, 'read' | 'write'> | undefined
  let stamped:
    | Pick<WindowsAclStampOptions, 'denyRead' | 'denyWrite'>
    | undefined
  let root: string
  let d: string
  let sub: string
  let sub2: string
  let token: string

  const configOf = (
    filesystem: Partial<SandboxRuntimeConfig['filesystem']>,
    files: CredentialFileConfig[] = [],
  ): SandboxRuntimeConfig => ({
    // External proxy ports: nothing is bound.
    network: {
      allowedDomains: [],
      deniedDomains: [],
      httpProxyPort: 1,
      socksProxyPort: 1,
    },
    filesystem: { denyRead: [], allowWrite: [], denyWrite: [], ...filesystem },
    credentials: { files },
    windows: { srtWin: { path: process.execPath } },
  })

  /** The values of `flag` in what one command is wrapped to. */
  const flagged = async (
    flag: '--deny-read' | '--deny-write',
    customConfig?: Partial<SandboxRuntimeConfig>,
  ): Promise<string[]> => {
    const { argv } = await SandboxManager.wrapWithSandboxArgv(
      'rem',
      undefined,
      customConfig,
    )
    return argv.flatMap((a, i) => (a === flag ? [argv[i + 1]] : []))
  }

  beforeEach(() => {
    granted = stamped = undefined
    root = realpathSync.native(mkdtempSync(join(tmpdir(), 'srt-handed-')))
    d = join(root, 'd')
    sub = join(d, 'sub')
    sub2 = join(d, 'sub2')
    token = join(d, 'token')
    mkdirSync(sub, { recursive: true })
    mkdirSync(sub2)
    writeFileSync(token, 'token-content')
    spies.push(
      spyOn(platform, 'getPlatform').mockReturnValue('windows'),
      spyOn(winUtils, 'checkWindowsDependenciesAsync').mockResolvedValue({
        errors: [],
        warnings: [],
      }),
      spyOn(winUtils, 'getWindowsSandboxUserStatusAsync').mockResolvedValue({
        provisioned: true,
        sid: 'S-1-5-21-1',
        groupExists: true,
        inBuiltinUsers: true,
        inSandboxGroup: true,
        hiddenFromLogon: true,
        credPresent: true,
        realUserSid: 'S-1-5-21-3',
        caCertThumb: certThumbprint(readFileSync(CA_CERT, 'utf8')),
        caCertPem: readFileSync(CA_CERT, 'utf8'),
        capabilities: SRT_WIN_CAPABILITIES,
      }),
      spyOn(winUtils, 'verifyWindowsWfpEgress').mockResolvedValue({
        target: '',
        stderr: '',
        probes: {
          plain: 'blocked',
          anonymous: 'blocked',
          anonymousLoopback: 'blocked',
          denyOnly: 'blocked',
          lowIntegrity: 'blocked',
          lowIntegrityLoopback: 'blocked',
          untrustedIntegrity: 'blocked',
          untrustedIntegrityLoopback: 'blocked',
        },
        residuals: [],
        warnings: [],
      }),
      spyOn(winUtils, 'getWindowsProfileReadStatus').mockReturnValue({
        state: 'current',
        capabilities: SRT_WIN_CAPABILITIES,
        notGranted: [],
        selfClosed: [],
        unverifiable: [],
        unprotected: [],
        staleAllow: [],
        replacedFiles: [],
        extraExclusions: [],
        exclusions: [],
        ungrantedOnly: [],
        counts: { containers: 0, granted: 0, files: 0, denied: 0 },
        env: {},
        paths: [],
      }),
      spyOn(winUtils, 'getWindowsProfileReadStatusAsync').mockResolvedValue({
        state: 'current',
        capabilities: SRT_WIN_CAPABILITIES,
        notGranted: [],
        selfClosed: [],
        unverifiable: [],
        unprotected: [],
        staleAllow: [],
        replacedFiles: [],
        extraExclusions: [],
        exclusions: [],
        ungrantedOnly: [],
        counts: { containers: 0, granted: 0, files: 0, denied: 0 },
        env: {},
        paths: [],
      }),
      // One call with all four lists, recorded as the grant and stamp it stands for.
      spyOn(winUtils, 'grantWindowsAclPersistent').mockImplementation(
        async o => {
          if (o.read.length > 0 || o.write.length > 0) {
            granted = { read: o.read, write: o.write }
          }
          if (o.denyRead.length > 0 || o.denyWrite.length > 0) {
            stamped = { denyRead: o.denyRead, denyWrite: o.denyWrite }
          }
        },
      ),
      spyOn(winUtils, 'revokeWindowsAclChecked').mockReturnValue({
        complete: true,
        outcomes: [],
        pending: [],
      }),
      spyOn(winUtils, 'restoreWindowsAcl').mockReturnValue([]),
    )
  })

  afterEach(async () => {
    await SandboxManager.reset()
    for (const spy of spies.splice(0)) spy.mockRestore()
    rmSync(root, { recursive: true, force: true })
  })

  const VERIFY_OK: WindowsWfpVerifyResult = {
    target: '',
    stderr: '',
    probes: {
      plain: 'blocked',
      anonymous: 'blocked',
      anonymousLoopback: 'blocked',
      denyOnly: 'blocked',
      lowIntegrity: 'blocked',
      lowIntegrityLoopback: 'blocked',
      untrustedIntegrity: 'blocked',
      untrustedIntegrityLoopback: 'blocked',
    },
    residuals: [],
    warnings: [],
  }
  const withLoopback = (allowLocalBinding?: boolean): SandboxRuntimeConfig => {
    const base = configOf({})
    return { ...base, network: { ...base.network, allowLocalBinding } }
  }
  /** Whether one command is wrapped with `--allow-loopback`. */
  const opensLoopback = async (
    customConfig?: Partial<SandboxRuntimeConfig>,
  ): Promise<boolean> => {
    const { argv } = await SandboxManager.wrapWithSandboxArgv(
      'rem',
      undefined,
      customConfig,
    )
    return argv.slice(0, argv.indexOf('--')).includes('--allow-loopback')
  }

  it('allowLocalBinding: the session mode reaches the fence probe and every exec', async () => {
    const verify = spyOn(winUtils, 'verifyWindowsWfpEgress')
    spies.push(verify)
    verify.mockClear()
    await SandboxManager.initialize(withLoopback(true))
    expect(verify.mock.calls.at(-1)?.[0]).toMatchObject({ allowLoopback: true })
    expect(await opensLoopback()).toBe(true)
  })

  it('allowLocalBinding: unset or false, the probe is told loopback is closed and there is no flag', async () => {
    const verify = spyOn(winUtils, 'verifyWindowsWfpEgress')
    spies.push(verify)
    for (const off of [undefined, false]) {
      await SandboxManager.reset()
      await SandboxManager.initialize(withLoopback(off))
      expect(await opensLoopback()).toBe(false)
    }
    for (const call of verify.mock.calls) {
      expect(call[0]?.allowLoopback).toBe(false)
    }
  })

  it('allowLocalBinding: the probe runs again when the configured mode changes, not otherwise', async () => {
    const verify = spyOn(winUtils, 'verifyWindowsWfpEgress')
    spies.push(verify)
    await SandboxManager.initialize(withLoopback(true))
    verify.mockClear()
    // Same mode: the fence is install-scoped, one probe covers it.
    await SandboxManager.reset()
    await SandboxManager.initialize(withLoopback(true))
    expect(verify.mock.calls.length).toBe(0)
    // The other mode, and back: each is probed.
    await SandboxManager.reset()
    await SandboxManager.initialize(withLoopback())
    expect(verify.mock.calls.length).toBe(1)
    expect(verify.mock.calls[0][0]?.allowLoopback).toBe(false)
    await SandboxManager.reset()
    await SandboxManager.initialize(withLoopback(true))
    expect(verify.mock.calls.length).toBe(2)
    expect(verify.mock.calls[1][0]?.allowLoopback).toBe(true)
  })

  it('allowLocalBinding: a mismatch the dependency check finds is the typed error, before anything is probed or granted', async () => {
    const mismatch =
      'WFP filters under sublayer (default) do not match ' +
      'network.allowLocalBinding (installed: loopback closed; configured: open)'
    const deps = spyOn(winUtils, 'checkWindowsDependenciesAsync')
    const verify = spyOn(winUtils, 'verifyWindowsWfpEgress')
    spies.push(deps, verify)
    deps.mockResolvedValueOnce({
      errors: [mismatch],
      warnings: [],
      loopbackMismatch: mismatch,
    })
    verify.mockClear()
    const err = await SandboxManager.initialize(withLoopback(true)).catch(
      e => e as WindowsSandboxError,
    )
    expect(err).toBeInstanceOf(WindowsSandboxError)
    expect((err as WindowsSandboxError).code).toBe('wfp_loopback_mismatch')
    expect((err as WindowsSandboxError).message).toBe(mismatch)
    expect(verify.mock.calls.length).toBe(0)
  })

  it('allowLocalBinding: a session whose mode is not the installed one does not start, in either direction', async () => {
    const verify = spyOn(winUtils, 'verifyWindowsWfpEgress')
    spies.push(verify)
    for (const open of [true, false]) {
      await SandboxManager.reset()
      // Leave the other mode verified, so this one has to be probed.
      verify.mockResolvedValue(VERIFY_OK)
      await SandboxManager.initialize(withLoopback(!open))
      await SandboxManager.reset()
      const refusal = new WindowsSandboxError(
        'wfp_loopback_mismatch',
        'WFP egress fence does not match network.allowLocalBinding — re-run ' +
          'the install',
      )
      verify.mockRejectedValue(refusal)
      const err = await SandboxManager.initialize(withLoopback(open)).catch(
        e => e as WindowsSandboxError,
      )
      expect(err).toBe(refusal)
      // Nothing was left initialized to wrap a command with.
      expect(SandboxManager.getConfig()).toBeUndefined()
      // The refusal is not remembered as a pass: the same mode is
      // probed again once the install has been re-run.
      verify.mockClear()
      verify.mockResolvedValue(VERIFY_OK)
      await SandboxManager.initialize(withLoopback(open))
      expect(verify.mock.calls.length).toBe(1)
      expect(await opensLoopback()).toBe(open)
    }
  })

  it('allowLocalBinding: a command asking for the mode the session did not verify is refused before any launch', async () => {
    const network = { allowedDomains: [], deniedDomains: [] }
    for (const open of [false, true]) {
      await SandboxManager.reset()
      await SandboxManager.initialize(withLoopback(open))
      const err = await opensLoopback({
        network: { ...network, allowLocalBinding: !open },
      }).catch(e => e as WindowsSandboxError)
      expect(err).toBeInstanceOf(WindowsSandboxError)
      expect((err as WindowsSandboxError).code).toBe('wfp_loopback_mismatch')
      expect((err as WindowsSandboxError).message).toMatch(
        /reset\(\) then initialize\(\)/,
      )
      // The session's own mode, stated or not, still runs.
      expect(
        await opensLoopback({
          network: { ...network, allowLocalBinding: open },
        }),
      ).toBe(open)
      expect(await opensLoopback({ network })).toBe(open)
    }
  })

  it('allowLocalBinding: updateConfig cannot change the mode; commands are refused until the session is initialized again', async () => {
    await SandboxManager.initialize(withLoopback())
    SandboxManager.updateConfig(withLoopback(true))
    const err = await opensLoopback().catch(e => e as WindowsSandboxError)
    expect((err as WindowsSandboxError).code).toBe('wfp_loopback_mismatch')
    // Back to the verified mode: commands run again.
    SandboxManager.updateConfig(withLoopback())
    expect(await opensLoopback()).toBe(false)
    // reset() and initialize() with the new value is the way to change it.
    await SandboxManager.reset()
    await SandboxManager.initialize(withLoopback(true))
    expect(await opensLoopback()).toBe(true)
  })

  it('the session: an allowWrite beneath a denyWrite is a read grant', async () => {
    await SandboxManager.initialize(
      configOf({ allowWrite: [root, sub], denyWrite: [d] }),
    )
    expect(granted).toMatchObject({ read: [sub], write: [root] })
    expect(stamped).toMatchObject({ denyRead: [], denyWrite: [d] })
  })

  it('the session: an allowRead beneath a denyRead is granted', async () => {
    await SandboxManager.initialize(
      configOf({ allowRead: [sub], denyRead: [d] }),
    )
    expect(granted).toMatchObject({ read: [sub], write: [] })
    expect(stamped).toMatchObject({ denyRead: [d], denyWrite: [] })
  })

  it('the session: nothing is granted beneath a credential deny', async () => {
    await SandboxManager.initialize(
      configOf({ allowRead: [sub], allowWrite: [root, sub2] }, [
        { path: d, mode: 'deny' },
      ]),
    )
    expect(granted).toMatchObject({ read: [], write: [root] })
    expect(stamped).toMatchObject({ denyRead: [d], denyWrite: [] })
  })

  it.each<[string, Omit<CredentialFileConfig, 'path'>]>([
    ['masked', { mode: 'mask' }],
    [
      'masked with no match',
      { mode: 'mask', extract: 'absent-(text)', onExtractNoMatch: 'deny' },
    ],
  ])('the session: a %s file is a credential deny', async (_name, entry) => {
    await SandboxManager.initialize(
      configOf({ allowRead: [token], allowWrite: [root] }, [
        { path: token, ...entry },
      ]),
    )
    expect(granted).toMatchObject({ read: [], write: [root] })
    expect(stamped).toMatchObject({ denyRead: [token], denyWrite: [] })
    expect(await flagged('--deny-read')).toEqual([])
  })

  it('the session: filesystem.disabled leaves a masked file denied, and that alone', async () => {
    await SandboxManager.initialize(
      configOf({ disabled: true, allowWrite: [root], denyWrite: [d] }, [
        { path: token, mode: 'mask' },
        { path: sub, mode: 'deny' },
      ]),
    )
    expect(granted ?? { read: [], write: [] }).toMatchObject({
      read: [],
      write: [],
    })
    expect(stamped).toMatchObject({ denyRead: [token], denyWrite: [] })
  })

  it('onExtractNoMatch "error": initialize() resolves and the wrap throws', async () => {
    await SandboxManager.initialize(
      configOf({ allowWrite: [root] }, [
        {
          path: token,
          mode: 'mask',
          extract: 'absent-(text)',
          onExtractNoMatch: 'error',
        },
      ]),
    )
    expect(granted).toMatchObject({ write: [root] })
    // eslint-disable-next-line @typescript-eslint/await-thenable -- bun:test types .rejects.toThrow() as void; the await is required at runtime
    await expect(flagged('--deny-read')).rejects.toThrow(/onExtractNoMatch/)
  })

  it('one command: a file masked since initialize() is denied', async () => {
    const late = join(root, 'late')
    await SandboxManager.initialize(
      configOf({ allowWrite: [root] }, [{ path: late, mode: 'mask' }]),
    )
    expect(stamped).toBeUndefined()
    expect(await flagged('--deny-read')).toEqual([])
    writeFileSync(late, 'late-content')
    expect(await flagged('--deny-read')).toEqual([late])
  })

  it('one command: a masked file of its own is denied, filesystem.disabled or not', async () => {
    await SandboxManager.initialize(configOf({ allowWrite: [root] }))
    const credentials = { files: [{ path: token, mode: 'mask' as const }] }
    expect(await flagged('--deny-read', { credentials })).toEqual([token])
    expect(
      await flagged('--deny-read', {
        credentials,
        filesystem: {
          disabled: true,
          denyRead: [sub],
          allowWrite: [],
          denyWrite: [],
        },
      }),
    ).toEqual([token])
  })

  it("one command: its denyWrite reaches the session's write grants beneath it", async () => {
    await SandboxManager.initialize(
      configOf({ allowRead: [sub2], allowWrite: [root, sub] }),
    )
    const filesystem = { denyRead: [], allowWrite: [], denyWrite: [d] }
    expect(await flagged('--deny-write', { filesystem })).toEqual([d, sub])
    expect(await flagged('--deny-read', { filesystem })).toEqual([])
  })

  it("one command: its credential deny reaches the session's grants beneath it", async () => {
    await SandboxManager.initialize(
      configOf({ allowRead: [sub], allowWrite: [root, sub2] }),
    )
    const credentials = { files: [{ path: d, mode: 'deny' as const }] }
    expect(await flagged('--deny-read', { credentials })).toEqual([
      d,
      sub,
      sub2,
    ])
  })

  it("one command: its denyRead leaves the session's grants beneath it", async () => {
    await SandboxManager.initialize(
      configOf({ allowRead: [sub], allowWrite: [sub2] }),
    )
    const filesystem = { denyRead: [d], allowWrite: [], denyWrite: [] }
    expect(await flagged('--deny-read', { filesystem })).toEqual([d])
    expect(await flagged('--deny-write', { filesystem })).toEqual([])
  })

  it('one command: a credential deny on a path the session read-denies', async () => {
    await SandboxManager.initialize(
      configOf({ allowRead: [sub], denyRead: [d] }),
    )
    const credentials = { files: [{ path: d, mode: 'deny' as const }] }
    expect(await flagged('--deny-read', { credentials })).toEqual([sub])
  })

  it("tlsTerminate does not require the CA in the sandbox user's store", async () => {
    spies.push(spyOn(winUtils, 'getWindowsSandboxCaCert').mockReturnValue(null))
    const base = configOf({})
    // Past the runtime's own TLS check, which this is not about.
    overrideEmittedConnectionProbe(() => true)
    try {
      await SandboxManager.initialize({
        ...base,
        network: {
          ...base.network,
          tlsTerminate: { caCertPath: CA_CERT, caKeyPath: CA_KEY },
        },
      })
      expect(SandboxManager.getMitmCA()).toBeDefined()
    } finally {
      overrideEmittedConnectionProbe(undefined)
    }
  })

  it("the library's trust bundle is granted beneath a credential deny", async () => {
    const above = { path: tmpdir(), mode: 'deny' as const }
    const base = configOf({ allowRead: [sub] }, [above])
    await SandboxManager.initialize({
      ...base,
      network: {
        ...base.network,
        tlsTerminate: { caCertPath: CA_CERT, caKeyPath: CA_KEY },
      },
    })
    const own = dirname(SandboxManager.getMitmCA()!.trustBundlePath)
    expect(granted).toMatchObject({ read: [own], write: [] })
    expect(
      await flagged('--deny-read', {
        credentials: { files: [{ path: dirname(own), mode: 'deny' }] },
      }),
    ).not.toContain(own)
  })
})

describe('windows-sandbox-utils async twins (pure, all platforms)', () => {
  const RAW_USER = JSON.stringify({
    user: {
      exists: true,
      sid: 'S-1-5-21-1',
      group_exists: true,
      group_sid: 'S-1-5-21-2',
      in_builtin_users: true,
      in_sandbox_group: true,
      hidden_from_logon: true,
    },
    cred_present: true,
    capabilities: SRT_WIN_CAPABILITIES,
    marker_version: 1,
    real_user_sid: 'S-1-5-21-3',
    ca_cert_thumb: null,
    ca_cert_pem: null,
  })
  const RAW_WFP = JSON.stringify({
    state: 'installed',
    filters: 4,
    port_range: [60080, 60089],
    user_sid: 'S-1-5-21-1',
  })
  // `srt-win status` (combined readback after install).
  const RAW_STATUS = JSON.stringify({
    user: JSON.parse(RAW_USER),
    wfp: JSON.parse(RAW_WFP),
  })
  const stdoutFor = (argv: readonly string[]): string =>
    argv.includes('user')
      ? RAW_USER
      : argv.includes('wfp')
        ? RAW_WFP
        : argv.includes('status')
          ? RAW_STATUS
          : ''

  let spawnSpy: ReturnType<typeof spyOn>
  let spawnSyncSpy: ReturnType<typeof spyOn>

  // Minimal ChildProcess stand-in for runSrtWinAsync's surface:
  // stdout/stderr readable-like, stdin writable-like, once/on,
  // close, kill. `delayMs: Infinity` = never closes on its own
  // (only via kill(), which closes with (null, 'SIGTERM') the way
  // a real killed child does).
  function mkFakeChild(
    stdout: string,
    status: number,
    delayMs = 0,
    onClose?: () => void,
    stderr = '',
  ) {
    const mkStream = () => {
      const s = new EventEmitter() as EventEmitter & {
        setEncoding(e: string): typeof s
        end(d?: string): void
      }
      s.setEncoding = () => s
      s.end = () => {}
      return s
    }
    const child = new EventEmitter() as EventEmitter & {
      stdout: ReturnType<typeof mkStream>
      stderr: ReturnType<typeof mkStream>
      stdin: ReturnType<typeof mkStream>
      kill(): boolean
    }
    child.stdout = mkStream()
    child.stderr = mkStream()
    child.stdin = mkStream()
    child.kill = () => {
      setImmediate(() => child.emit('close', null, 'SIGTERM'))
      return true
    }
    const fire = () => {
      onClose?.()
      child.stdout.emit('data', stdout)
      if (stderr) child.stderr.emit('data', stderr)
      child.emit('close', status, null)
    }
    if (delayMs === Infinity) {
      // wait for kill()
    } else if (delayMs > 0) setTimeout(fire, delayMs)
    else setImmediate(fire)
    return child
  }

  const stubSpawn = (
    behaviour: (argv: readonly string[]) => {
      status: number
      stdout: string
      stderr?: string
    },
    delayMs = 0,
    onClose?: () => void,
  ) => {
    spawnSyncSpy = spyOn(child_process, 'spawnSync').mockImplementation(((
      _exe: string,
      argv: readonly string[],
    ) => {
      const b = behaviour(argv)
      return {
        status: b.status,
        stdout: b.stdout,
        stderr: b.stderr ?? '',
        error: null,
      }
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    }) as any)
    spawnSpy = spyOn(child_process, 'spawn').mockImplementation(((
      _exe: string,
      argv: readonly string[],
    ) => {
      const b = behaviour(argv)
      return mkFakeChild(b.stdout, b.status, delayMs, onClose, b.stderr)
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    }) as any)
  }

  afterEach(() => {
    spawnSpy?.mockRestore()
    spawnSyncSpy?.mockRestore()
  })

  it('verifyWindowsWfpEgress always probes with --write-restricted-token', async () => {
    const target = '127.0.0.1:49999'
    stubSpawn(() => ({
      status: 0,
      stdout: JSON.stringify({ egress_probe: 'blocked', target }),
    }))
    const srtWin = resolveSrtWin({ path: process.execPath })
    await verifyWindowsWfpEgress({ target, srtWin })
    // Through the async spawn: a session start must not block the event loop.
    expect(spawnSyncSpy.mock.calls).toHaveLength(0)
    expect(spawnSpy.mock.calls.map((c: unknown[]) => c[1])).toEqual([
      [
        SRT_WIN_DISPATCH_ARG1,
        'wfp',
        'verify',
        '--target',
        target,
        '--write-restricted-token',
      ],
    ])
  })

  it('verifyWindowsWfpEgress: one --write-root per root, after the token flag', async () => {
    const target = '127.0.0.1:49999'
    stubSpawn(() => ({
      status: 0,
      stdout: JSON.stringify({ egress_probe: 'blocked', target }),
    }))
    const srtWin = resolveSrtWin({ path: process.execPath })
    await verifyWindowsWfpEgress({
      target,
      writeRoots: ['C:\\a', 'C:\\b'],
      srtWin,
    })
    expect(spawnSpy.mock.calls.map((c: unknown[]) => c[1])).toEqual([
      [
        SRT_WIN_DISPATCH_ARG1,
        'wfp',
        'verify',
        '--target',
        target,
        '--write-restricted-token',
        '--write-root',
        'C:\\a',
        '--write-root',
        'C:\\b',
      ],
    ])
  })

  const answerAsyncBySync = () =>
    spawnSpy.mockImplementation(((exe: string, argv: readonly string[]) =>
      asyncChildAnsweredBySync(exe, argv)) as never)

  it('grantWindowsAclPersistent: one acl grant --persistent with grants and denies on stdin; any non-zero exit throws', async () => {
    const srtWin = resolveSrtWin({ path: process.execPath })
    const opts = {
      sandboxUserSid: 'S-1-5-21-1',
      holderPid: 4242,
      read: ['C:\\bundle'],
      write: ['C:\\work\\repo'],
      denyRead: ['C:\\work\\repo\\.env'],
      denyWrite: ['C:\\work\\repo\\.git\\hooks'],
      srtWin,
    }
    stubSpawn(() => ({ status: 0, stdout: '' }))
    answerAsyncBySync()
    const pending = winUtils.grantWindowsAclPersistent(opts)
    expect(pending).toBeInstanceOf(Promise)
    expect(spawnSyncSpy.mock.calls).toHaveLength(0)
    await pending
    expect(spawnSyncSpy.mock.calls).toHaveLength(1)
    const [, argv, spawnOpts] = spawnSyncSpy.mock.calls[0] as [
      string,
      string[],
      { input: string },
    ]
    expect(argv).toEqual([
      SRT_WIN_DISPATCH_ARG1,
      'acl',
      'grant',
      '--holder-pid',
      '4242',
      '--sandbox-user-sid',
      'S-1-5-21-1',
      '--persistent',
    ])
    expect(JSON.parse(spawnOpts.input)).toEqual({
      read: opts.read,
      write: opts.write,
      denyRead: opts.denyRead,
      denyWrite: opts.denyWrite,
    })
    // 2 = an input was skipped; 1 = a capability SID or DACL step failed.
    for (const status of [1, 2]) {
      spawnSyncSpy.mockRestore()
      spawnSpy.mockRestore()
      stubSpawn(() => ({ status, stdout: '' }))
      answerAsyncBySync()
      let thrown: unknown
      try {
        await winUtils.grantWindowsAclPersistent(opts)
      } catch (e) {
        thrown = e
      }
      expect(thrown).toBeInstanceOf(WindowsSandboxError)
      expect((thrown as WindowsSandboxError).code).toBe('acl_grant_failed')
    }
  })

  it('user status: persistent_grants is surfaced unless it says "none"; an unknown state is not "none"', () => {
    const srtWin = resolveSrtWin({ path: process.execPath })
    const statusWith = (persistent_grants: unknown) => {
      spawnSyncSpy?.mockRestore()
      spawnSpy?.mockRestore()
      stubSpawn(() => ({
        status: 0,
        stdout: JSON.stringify({ ...JSON.parse(RAW_USER), persistent_grants }),
      }))
      return getWindowsSandboxUserStatus({ srtWin }).persistentGrants
    }
    // An srt-win without the feature, and one with nothing kept.
    expect(statusWith(undefined)).toBeUndefined()
    expect(statusWith({ state: 'none', roots: [] })).toBeUndefined()
    expect(
      statusWith({ state: 'present', roots: ['C:\\a'], reason: 'r' }),
    ).toEqual({ state: 'present', roots: ['C:\\a'], reason: 'r' })
    expect(statusWith({ state: 'unknown', roots: [], reason: 'r' })).toEqual({
      state: 'unknown',
      roots: [],
      reason: 'r',
    })
    expect(statusWith({ state: 'someLaterState' })).toEqual({
      state: 'unknown',
      roots: [],
    })
  })

  it('verifyWindowsWfpEgress rejects every outcome but blocked', async () => {
    const target = '127.0.0.1:49999'
    const srtWin = resolveSrtWin({ path: process.execPath })
    // 3 = connected, 2 = unreachable, 1 = no probe child was created.
    for (const [status, probe, code] of [
      [3, 'connected', 'wfp_fence_inactive'],
      [2, 'unreachable', 'wfp_verify_inconclusive'],
      [1, 'error', 'wfp_verify_inconclusive'],
    ] as const) {
      spawnSyncSpy?.mockRestore()
      spawnSpy?.mockRestore()
      stubSpawn(() => ({
        status,
        stdout: JSON.stringify({ egress_probe: probe, target }),
      }))
      let thrown: unknown
      try {
        await verifyWindowsWfpEgress({ target, srtWin })
      } catch (e) {
        thrown = e
      }
      expect(thrown).toBeInstanceOf(WindowsSandboxError)
      expect((thrown as WindowsSandboxError).code).toBe(code)
    }
  })

  it('getWindowsSandboxUserStatus{,Async}: identical argv + identical result', async () => {
    stubSpawn(argv => ({ status: 0, stdout: stdoutFor(argv) }))
    const srtWin = resolveSrtWin({ path: process.execPath })
    const sync = getWindowsSandboxUserStatus({ srtWin })
    const asyn = await getWindowsSandboxUserStatusAsync({ srtWin })
    expect(asyn).toEqual(sync)
    expect(spawnSyncSpy.mock.calls[0].slice(0, 2)).toEqual(
      spawnSpy.mock.calls[0].slice(0, 2),
    )
    expect(spawnSpy.mock.calls[0][1]).toEqual([
      SRT_WIN_DISPATCH_ARG1,
      'user',
      'status',
    ])
    expect(spawnSpy.mock.calls[0][2]).toMatchObject({ windowsHide: true })
  })

  it('getWindowsProfileReadStatus{,Async}: identical argv + identical result', async () => {
    stubSpawn(() => ({
      status: 0,
      stdout: JSON.stringify({ state: 'none', record_version: 1 }),
    }))
    const srtWin = resolveSrtWin({ path: process.execPath })
    const sync = winUtils.getWindowsProfileReadStatus({ paths: true, srtWin })
    const asyn = await winUtils.getWindowsProfileReadStatusAsync({
      paths: true,
      srtWin,
    })
    expect(asyn).toEqual(sync)
    expect(spawnSpy.mock.calls[0][1]).toEqual(spawnSyncSpy.mock.calls[0][1])
    expect(spawnSpy.mock.calls[0][1]).toEqual([
      SRT_WIN_DISPATCH_ARG1,
      'profile',
      'status',
      '--paths',
    ])
  })

  it('getWindowsWfpStatus{,Async}: identical argv + identical result', async () => {
    stubSpawn(argv => ({ status: 0, stdout: stdoutFor(argv) }))
    const srtWin = resolveSrtWin({ path: process.execPath })
    const sl = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
    const sync = getWindowsWfpStatus({ sublayerGuid: sl, srtWin })
    const asyn = await getWindowsWfpStatusAsync({ sublayerGuid: sl, srtWin })
    expect(asyn).toEqual(sync)
    expect(spawnSpy.mock.calls[0][1]).toEqual(spawnSyncSpy.mock.calls[0][1])
    expect(spawnSpy.mock.calls[0][1]).toEqual([
      SRT_WIN_DISPATCH_ARG1,
      'wfp',
      'status',
      '--sublayer-guid',
      sl,
    ])
  })

  it('checkWindowsSandboxStatus{,Async}: identical argv + identical result', async () => {
    stubSpawn(argv => ({ status: 0, stdout: stdoutFor(argv) }))
    const srtWin = resolveSrtWin({ path: process.execPath })
    const sl = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
    const sync = checkWindowsSandboxStatus({ sublayerGuid: sl, srtWin })
    const asyn = await checkWindowsSandboxStatusAsync({
      sublayerGuid: sl,
      srtWin,
    })
    expect(asyn).toEqual(sync)
    expect(spawnSpy.mock.calls[0][1]).toEqual(spawnSyncSpy.mock.calls[0][1])
    expect(spawnSpy.mock.calls[0][1]).toEqual([
      SRT_WIN_DISPATCH_ARG1,
      'status',
      '--sublayer-guid',
      sl,
    ])
  })

  it('installWindowsSandbox{,Async}: identical install argv (all opts)', async () => {
    stubSpawn(argv => ({ status: 0, stdout: stdoutFor(argv) }))
    const srtWin = resolveSrtWin({ path: process.execPath })
    const opts = {
      sublayerGuid: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
      proxyPortRange: [60080, 60089] as const,
      sandboxUser: 'srt-sb-test',
      force: true,
      skipProfileGrant: true,
      srtWin,
    }
    const sync = installWindowsSandbox(opts)
    const asyn = await installWindowsSandboxAsync(opts)
    expect(asyn).toEqual(sync)
    // First call to each spy is the `install` invocation.
    const syncArgv = spawnSyncSpy.mock.calls[0][1]
    const asynArgv = spawnSpy.mock.calls[0][1]
    expect(asynArgv).toEqual(syncArgv)
    expect(asynArgv).toEqual([
      SRT_WIN_DISPATCH_ARG1,
      'install',
      '--sublayer-guid',
      opts.sublayerGuid,
      '--proxy-port-range',
      '60080-60089',
      '--sandbox-user',
      'srt-sb-test',
      '--force',
    ])
  })

  it('installWindowsSandbox: default timeout ≥ UAC TTL; opts.timeoutMs overrides', () => {
    stubSpawn(argv => ({ status: 0, stdout: stdoutFor(argv) }))
    const srtWin = resolveSrtWin({ path: process.execPath })
    // Default: 120 s (matches UAC consent auto-dismiss). The async
    // variant computes its budget through the same installTimeoutMs
    // helper (it arms its own timer instead of a spawn option, so
    // there is no opts.timeout to observe there).
    installWindowsSandbox({ srtWin, skipProfileGrant: true })
    expect(spawnSyncSpy.mock.calls[0][2].timeout).toBe(120_000)
    // Explicit override.
    installWindowsSandbox({
      srtWin,
      timeoutMs: 300_000,
      skipProfileGrant: true,
    })
    expect(spawnSyncSpy.mock.calls.at(-2)?.[2].timeout).toBe(300_000)
  })

  it('uninstallWindowsSandbox: the default timeout covers the removal of the kept grants; --keep-user removes none', () => {
    stubSpawn(argv => ({ status: 0, stdout: stdoutFor(argv) }))
    const srtWin = resolveSrtWin({ path: process.execPath })
    uninstallWindowsSandbox({ srtWin })
    expect(spawnSyncSpy.mock.calls.at(-1)?.[2].timeout).toBe(
      120_000 + 30 * 60_000,
    )
    uninstallWindowsSandbox({ srtWin, keepUser: true })
    expect(spawnSyncSpy.mock.calls.at(-1)?.[2].timeout).toBe(120_000)
    uninstallWindowsSandbox({ srtWin, timeoutMs: 5_000 })
    expect(spawnSyncSpy.mock.calls.at(-1)?.[2].timeout).toBe(5_000)
  })

  it('installWindowsSandbox{,Async}: timeout → identical install_timeout error', async () => {
    const srtWin = resolveSrtWin({ path: process.execPath })
    // Sync: spawnSync kills at `timeout` and reports ETIMEDOUT.
    spawnSyncSpy = spyOn(child_process, 'spawnSync').mockImplementation(
      (() => ({
        status: null,
        signal: 'SIGTERM',
        stdout: '',
        stderr: '',
        error: Object.assign(new Error('spawnSync ETIMEDOUT'), {
          code: 'ETIMEDOUT',
        }),
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
      })) as any,
    )
    // Async: child never closes on its own; runSrtWinAsync's own
    // timer kills it (close(null, 'SIGTERM')).
    spawnSpy = spyOn(child_process, 'spawn').mockImplementation(
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (() => mkFakeChild('', 0, Infinity)) as any,
    )
    const grab = async (fn: () => unknown): Promise<WindowsSandboxError> => {
      try {
        await fn()
      } catch (e) {
        return e as WindowsSandboxError
      }
      throw new Error('expected a timeout throw')
    }
    const syncErr = await grab(() =>
      installWindowsSandbox({ srtWin, timeoutMs: 30 }),
    )
    const asynErr = await grab(() =>
      installWindowsSandboxAsync({ srtWin, timeoutMs: 30 }),
    )
    for (const e of [syncErr, asynErr]) {
      expect(e).toBeInstanceOf(WindowsSandboxError)
      expect(e.code).toBe('install_timeout')
      expect(e.message).toMatch(/UAC prompt may still be open/)
      expect(e.message).toMatch(/timed out after 30ms \(killed by SIGTERM\)/)
    }
    expect(asynErr.message).toBe(syncErr.message)
  })

  it('getWindowsSandboxUserStatus{,Async}: non-zero exit → identical typed error', async () => {
    stubSpawn(() => ({ status: 1, stdout: '' }))
    const srtWin = resolveSrtWin({ path: process.execPath })
    const errs: WindowsSandboxError[] = []
    try {
      getWindowsSandboxUserStatus({ srtWin })
    } catch (e) {
      errs.push(e as WindowsSandboxError)
    }
    try {
      await getWindowsSandboxUserStatusAsync({ srtWin })
    } catch (e) {
      errs.push(e as WindowsSandboxError)
    }
    expect(errs).toHaveLength(2)
    for (const e of errs) {
      expect(e).toBeInstanceOf(WindowsSandboxError)
      expect(e.code).toBe('srt_win_nonzero')
      expect(e.subcommand).toBe('user')
    }
    expect(errs[1].message).toBe(errs[0].message)
  })

  it('installWindowsSandbox{,Async}: exit 10 → both return {cancelled:true}', async () => {
    stubSpawn(argv => ({
      status: argv[1] === 'install' ? 10 : 0,
      stdout: stdoutFor(argv),
    }))
    const srtWin = resolveSrtWin({ path: process.execPath })
    const sync = installWindowsSandbox({ srtWin })
    const asyn = await installWindowsSandboxAsync({ srtWin })
    expect(sync.cancelled).toBe(true)
    expect(asyn).toEqual(sync)
  })

  it('installWindowsSandbox{,Async}: exit 13 → both throw the same message', async () => {
    stubSpawn(() => ({ status: 13, stdout: '' }))
    const srtWin = resolveSrtWin({ path: process.execPath })
    let syncMsg = ''
    let asynMsg = ''
    try {
      installWindowsSandbox({ srtWin })
    } catch (e) {
      syncMsg = (e as Error).message
    }
    try {
      await installWindowsSandboxAsync({ srtWin })
    } catch (e) {
      asynMsg = (e as Error).message
    }
    expect(syncMsg).toMatch(/already exist.*different/i)
    expect(asynMsg).toBe(syncMsg)
  })

  it('installWindowsSandbox{,Async}: exit 13 → both throw install_config_conflict', async () => {
    stubSpawn(() => ({ status: 13, stdout: '' }))
    const srtWin = resolveSrtWin({ path: process.execPath })
    const codes: string[] = []
    try {
      installWindowsSandbox({ srtWin })
    } catch (e) {
      codes.push((e as WindowsSandboxError).code)
    }
    try {
      await installWindowsSandboxAsync({ srtWin })
    } catch (e) {
      codes.push((e as WindowsSandboxError).code)
    }
    expect(codes).toEqual([
      'install_config_conflict',
      'install_config_conflict',
    ])
  })

  it('checkWindowsDependencies{,Async}: identical result (ok, unprovisioned, spawn-fail)', async () => {
    const srtWin = resolveSrtWin({ path: process.execPath })
    // ok
    stubSpawn(argv => ({ status: 0, stdout: stdoutFor(argv) }))
    expect(await checkWindowsDependenciesAsync({ srtWin })).toEqual(
      checkWindowsDependencies({ srtWin }),
    )
    spawnSpy.mockRestore()
    spawnSyncSpy.mockRestore()
    // user not provisioned → same errors[]
    const unprov = JSON.stringify({
      ...JSON.parse(RAW_USER),
      user: { ...JSON.parse(RAW_USER).user, exists: false },
      cred_present: false,
    })
    stubSpawn(argv => ({
      status: 0,
      stdout: argv.includes('user') ? unprov : RAW_WFP,
    }))
    const sync = checkWindowsDependencies({ srtWin })
    const asyn = await checkWindowsDependenciesAsync({ srtWin })
    expect(sync.errors.length).toBe(1)
    expect(asyn).toEqual(sync)
    spawnSpy.mockRestore()
    spawnSyncSpy.mockRestore()
    // user-status probe non-zero → same short-circuit; sync variant
    // must NOT spawn wfp-status (pins the pre-existing behaviour).
    stubSpawn(argv => ({
      status: argv.includes('user') ? 1 : 0,
      stdout: argv.includes('user') ? '' : RAW_WFP,
    }))
    const syncFail = checkWindowsDependencies({ srtWin })
    expect(spawnSyncSpy.mock.calls.length).toBe(1)
    const asynFail = await checkWindowsDependenciesAsync({ srtWin })
    expect(syncFail.errors[0]).toMatch(/user status failed/)
    expect(asynFail).toEqual(syncFail)
  })

  it('checkWindowsDependencies{,Async}: seclogon state → error / silent', async () => {
    const srtWin = resolveSrtWin({ path: process.execPath })
    const withSeclogon = (seclogon: string | undefined) =>
      JSON.stringify({ ...JSON.parse(RAW_USER), seclogon })
    const run = async (seclogon: string | undefined) => {
      stubSpawn(argv => ({
        status: 0,
        stdout: argv.includes('user') ? withSeclogon(seclogon) : RAW_WFP,
      }))
      const sync = checkWindowsDependencies({ srtWin })
      const asyn = await checkWindowsDependenciesAsync({ srtWin })
      expect(asyn).toEqual(sync)
      spawnSpy.mockRestore()
      spawnSyncSpy.mockRestore()
      return sync
    }

    const disabled = await run('disabled')
    expect(disabled.errors.length).toBe(1)
    expect(disabled.errors[0]).toMatch(/Secondary Logon service.*is disabled/)
    expect(disabled.errors[0]).toMatch(
      /administrator must set its startup type to Manual/,
    )
    expect(disabled.warnings).toEqual([])

    const missing = await run('missing')
    expect(missing.errors.length).toBe(1)
    expect(missing.errors[0]).toMatch(/Secondary Logon service.*not present/)

    // Unreadable proves nothing: the launch itself is the ground truth.
    expect(await run('cannot-read')).toEqual({ errors: [], warnings: [] })

    expect(await run('ok')).toEqual({ errors: [], warnings: [] })
    // Field absent: an srt-win built before the probe existed.
    expect(await run(undefined)).toEqual({ errors: [], warnings: [] })
    // A value this build does not know is not an opinion either.
    expect(await run('starting')).toEqual({ errors: [], warnings: [] })
  })

  it('getWindowsSandboxUserStatus: seclogon passes through; absent stays absent', () => {
    const srtWin = resolveSrtWin({ path: process.execPath })
    stubSpawn(() => ({
      status: 0,
      stdout: JSON.stringify({ ...JSON.parse(RAW_USER), seclogon: 'disabled' }),
    }))
    expect(getWindowsSandboxUserStatus({ srtWin }).seclogon).toBe('disabled')
    spawnSyncSpy.mockRestore()
    spawnSpy.mockRestore()
    stubSpawn(() => ({ status: 0, stdout: RAW_USER }))
    expect('seclogon' in getWindowsSandboxUserStatus({ srtWin })).toBe(false)
  })

  // `stubSpawn` has no stderr, so these stub spawnSync / spawn directly.
  const SECLOGON_STDERR =
    'srt-win: launching runner\n' +
    '{"code":"seclogon_disabled","state":"disabled","message":"the sandbox cannot start: the Windows Secondary Logon service (seclogon) is disabled."}'
  const stubSpawnResult = (status: number, stderr: string) => {
    spawnSyncSpy = spyOn(child_process, 'spawnSync').mockImplementation(
      (() => ({
        status,
        stdout: '',
        stderr,
        error: null,
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
      })) as any,
    )
    spawnSpy = spyOn(child_process, 'spawn').mockImplementation((() => {
      // Close on a timer so the stderr chunk lands first.
      const child = mkFakeChild('', status, 5)
      setImmediate(() => child.stderr.emit('data', stderr))
      return child
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    }) as any)
  }
  const thrownBy = async (fn: () => unknown): Promise<WindowsSandboxError> => {
    try {
      await fn()
    } catch (e) {
      return e as WindowsSandboxError
    }
    throw new Error('expected a throw')
  }

  it('verifyWindowsWfpEgress: exit 18 + typed stderr → seclogon_disabled, not wfp_verify_unparseable', async () => {
    const srtWin = resolveSrtWin({ path: process.execPath })
    const verify = () =>
      verifyWindowsWfpEgress({ target: '127.0.0.1:9', srtWin })
    stubSpawnResult(18, SECLOGON_STDERR)
    const e = await thrownBy(verify)
    expect(e).toBeInstanceOf(WindowsSandboxError)
    expect(e.code).toBe('seclogon_disabled')
    expect(e.subcommand).toBe('wfp')
    expect((e as SeclogonDisabledError).state).toBe('disabled')
    expect(e.message).toMatch(
      /Secondary Logon service \(seclogon\) is disabled/,
    )
    spawnSyncSpy.mockRestore()
    spawnSpy.mockRestore()

    // The exit code gates the parse; every shape still throws.
    stubSpawnResult(1, SECLOGON_STDERR)
    expect((await thrownBy(verify)).code).toBe('wfp_verify_unparseable')
    spawnSyncSpy.mockRestore()
    spawnSpy.mockRestore()
    stubSpawnResult(18, 'srt-win: error: something else')
    expect((await thrownBy(verify)).code).toBe('wfp_verify_unparseable')
  })

  it('windowsTrustCa{,Async}: exit 18 + typed stderr → seclogon_disabled', async () => {
    const srtWin = resolveSrtWin({ path: process.execPath })
    stubSpawnResult(18, SECLOGON_STDERR)
    const sync = await thrownBy(() => windowsTrustCa('C:\\ca.pem', { srtWin }))
    const asyn = await thrownBy(() =>
      windowsTrustCaAsync('C:\\ca.pem', { srtWin }),
    )
    expect(sync.code).toBe('seclogon_disabled')
    expect(sync.subcommand).toBe('user')
    expect(asyn.code).toBe(sync.code)
    expect(asyn.message).toBe(sync.message)
    spawnSyncSpy.mockRestore()
    spawnSpy.mockRestore()
    stubSpawnResult(1, 'srt-win: error: CA install runner exited 1')
    expect(
      (await thrownBy(() => windowsTrustCa('C:\\ca.pem', { srtWin }))).code,
    ).toBe('trust_ca_failed')
  })

  it('checkWindowsDependencies: an install of a newer setup version is not offered an upgrade', () => {
    const srtWin = resolveSrtWin({ path: process.execPath })
    const newer = JSON.stringify({
      ...JSON.parse(RAW_USER),
      marker_version: 4,
      setup_version: 3,
    })
    stubSpawn(argv => ({
      status: 0,
      stdout: argv.includes('user') ? newer : RAW_WFP,
    }))
    const r = checkWindowsDependencies({ srtWin })
    expect(r.errors).toHaveLength(1)
    expect(r.errors[0]).toMatch(
      /set up by a newer release \(setup version 4; this release needs 3\)/,
    )
    expect(r.errors[0]).toContain('install --force')
    expect(r.errors[0]).not.toMatch(/upgrade it in place/)
    spawnSpy.mockRestore()
    spawnSyncSpy.mockRestore()
  })

  it('checkWindowsDependencies{,Async}: an install of another setup version asks for a re-install, not a first install', async () => {
    const srtWin = resolveSrtWin({ path: process.execPath })
    const stale = JSON.stringify({
      ...JSON.parse(RAW_USER),
      marker_version: 2,
      setup_version: 3,
    })
    stubSpawn(argv => ({
      status: 0,
      stdout: argv.includes('user') ? stale : RAW_WFP,
    }))
    const sync = checkWindowsDependencies({ srtWin })
    const asyn = await checkWindowsDependenciesAsync({ srtWin })
    expect(asyn).toEqual(sync)
    expect(sync.errors).toHaveLength(1)
    expect(sync.errors[0]).toMatch(/setup version 2; this release needs 3/)
    expect(sync.errors[0]).toMatch(/Re-run the install to upgrade it in place/)
    expect(sync.errors[0]).toContain(
      'npx @anthropic-ai/sandbox-runtime windows-install',
    )
    expect(sync.errors[0]).not.toMatch(/not provisioned|one-time install/i)
    spawnSpy.mockRestore()
    spawnSyncSpy.mockRestore()
    for (const versions of [{ marker_version: 3, setup_version: 3 }, {}]) {
      const ok = JSON.stringify({ ...JSON.parse(RAW_USER), ...versions })
      stubSpawn(argv => ({
        status: 0,
        stdout: argv.includes('user') ? ok : RAW_WFP,
      }))
      expect(checkWindowsDependencies({ srtWin }).errors).toEqual([])
      spawnSpy.mockRestore()
      spawnSyncSpy.mockRestore()
    }
  })

  it('checkWindowsDependenciesAsync: probes run concurrently', async () => {
    const srtWin = resolveSrtWin({ path: process.execPath })
    let inFlight = 0
    let maxInFlight = 0
    stubSpawn(
      argv => {
        inFlight++
        maxInFlight = Math.max(maxInFlight, inFlight)
        return { status: 0, stdout: stdoutFor(argv) }
      },
      20,
      () => inFlight--,
    )
    await checkWindowsDependenciesAsync({ srtWin })
    expect(maxInFlight).toBe(2)
  })

  it('installWindowsSandbox{,Async}: allowLoopback becomes --allow-loopback', async () => {
    stubSpawn(argv => ({ status: 0, stdout: stdoutFor(argv) }))
    const srtWin = resolveSrtWin({ path: process.execPath })
    const opts = {
      proxyPortRange: [60080, 60089] as const,
      allowLoopback: true,
      force: true,
      srtWin,
    }
    installWindowsSandbox(opts)
    await installWindowsSandboxAsync(opts)
    expect(spawnSpy.mock.calls[0][1]).toEqual(spawnSyncSpy.mock.calls[0][1])
    expect(spawnSyncSpy.mock.calls[0][1]).toEqual([
      SRT_WIN_DISPATCH_ARG1,
      'install',
      '--proxy-port-range',
      '60080-60089',
      '--allow-loopback',
      '--force',
    ])
    // Without the option (or with it false) the flag is absent.
    for (const off of [{}, { allowLoopback: false }]) {
      spawnSyncSpy.mockClear()
      installWindowsSandbox({ ...off, srtWin })
      expect(spawnSyncSpy.mock.calls[0][1]).toEqual([
        SRT_WIN_DISPATCH_ARG1,
        'install',
      ])
    }
  })

  it('installWindowsSandbox{,Async}: an srt-win that does not know --allow-loopback is reported as too old, not as a usage error', async () => {
    // What an argument parser that predates the flag prints.
    const usage =
      "error: unexpected argument '--allow-loopback' found\n\n" +
      'Usage: srt-win install [OPTIONS]\n'
    stubSpawn(() => ({ status: 2, stdout: '', stderr: usage }))
    const srtWin = resolveSrtWin({ path: process.execPath })
    let err: unknown
    try {
      installWindowsSandbox({ allowLoopback: true, srtWin })
    } catch (e) {
      err = e
    }
    expect(err).toBeInstanceOf(WindowsSandboxError)
    expect((err as WindowsSandboxError).code).toBe('srt_win_too_old')
    expect((err as WindowsSandboxError).message).toMatch(/srt-win is too old/)
    const asyncErr = await installWindowsSandboxAsync({
      allowLoopback: true,
      srtWin,
    }).catch(e => e as WindowsSandboxError)
    expect((asyncErr as WindowsSandboxError).code).toBe('srt_win_too_old')
  })

  const rawWfp = (over: Record<string, unknown>): string =>
    JSON.stringify({ ...JSON.parse(RAW_WFP), ...over })

  it('getWindowsWfpStatus{,Async}: reports whether the install opens loopback', async () => {
    const srtWin = resolveSrtWin({ path: process.execPath })
    stubSpawn(() => ({
      status: 0,
      stdout: rawWfp({ filters: 8, allow_loopback: true }),
    }))
    const sync = getWindowsWfpStatus({ srtWin })
    expect(sync.allowLoopback).toBe(true)
    expect(sync.portRange).toEqual([60080, 60089])
    expect(await getWindowsWfpStatusAsync({ srtWin })).toEqual(sync)
    spawnSpy.mockRestore()
    spawnSyncSpy.mockRestore()
    // `false`, and an srt-win that predates the field (which cannot
    // have opened loopback), both read as closed.
    for (const over of [{ allow_loopback: false }, {}]) {
      stubSpawn(() => ({ status: 0, stdout: rawWfp(over) }))
      expect(getWindowsWfpStatus({ srtWin }).allowLoopback).toBe(false)
      spawnSpy.mockRestore()
      spawnSyncSpy.mockRestore()
    }
  })

  it('checkWindowsDependencies{,Async}: an install whose loopback mode is not the configured one is an error naming the reinstall, in either direction', async () => {
    const srtWin = resolveSrtWin({ path: process.execPath })
    const cases: Array<{
      installed: boolean
      configured: boolean
      state: string
      expect: RegExp
      command: string
    }> = [
      {
        installed: false,
        configured: true,
        state: 'installed',
        expect: /installed: loopback closed; configured: open/,
        command: 'windows-install --allow-loopback --force',
      },
      {
        installed: true,
        configured: false,
        state: 'installed',
        expect: /installed: loopback open; configured: closed/,
        command: 'windows-install --force',
      },
      // Non-elevated: the mode comes from the install record.
      {
        installed: true,
        configured: false,
        state: 'cannot-read',
        expect: /installed: loopback open; configured: closed/,
        command: 'windows-install --force',
      },
      {
        installed: false,
        configured: true,
        state: 'cannot-read',
        expect: /installed: loopback closed; configured: open/,
        command: 'windows-install --allow-loopback --force',
      },
    ]
    for (const c of cases) {
      stubSpawn(argv => ({
        status: 0,
        stdout: argv.includes('user')
          ? RAW_USER
          : rawWfp({ state: c.state, allow_loopback: c.installed }),
      }))
      const opts = { srtWin, allowLoopback: c.configured }
      const sync = checkWindowsDependencies(opts)
      expect(sync.errors.length).toBe(1)
      expect(sync.errors[0]).toMatch(/do not match network\.allowLocalBinding/)
      expect(sync.errors[0]).toMatch(c.expect)
      expect(sync.errors[0]).toContain(c.command)
      expect(await checkWindowsDependenciesAsync(opts)).toEqual(sync)
      spawnSpy.mockRestore()
      spawnSyncSpy.mockRestore()
    }
  })

  it('checkWindowsDependencies{,Async}: a matching loopback mode, or none to compare, is not an error — and open loopback is always said', async () => {
    const srtWin = resolveSrtWin({ path: process.execPath })
    const run = async (installed: boolean, allowLoopback?: boolean) => {
      stubSpawn(argv => ({
        status: 0,
        stdout: argv.includes('user')
          ? RAW_USER
          : rawWfp({ allow_loopback: installed }),
      }))
      const sync = checkWindowsDependencies({ srtWin, allowLoopback })
      expect(
        await checkWindowsDependenciesAsync({ srtWin, allowLoopback }),
      ).toEqual(sync)
      spawnSpy.mockRestore()
      spawnSyncSpy.mockRestore()
      return sync
    }
    expect((await run(true, true)).errors).toEqual([])
    expect((await run(false, false)).errors).toEqual([])
    // The caller did not say what is configured: nothing to compare.
    expect((await run(true)).errors).toEqual([])
    expect((await run(false)).errors).toEqual([])
    expect((await run(true, true)).warnings).toContain(
      WINDOWS_ALLOW_LOOPBACK_EFFECT,
    )
    expect((await run(true)).warnings).toContain(WINDOWS_ALLOW_LOOPBACK_EFFECT)
    expect((await run(false, false)).warnings).not.toContain(
      WINDOWS_ALLOW_LOOPBACK_EFFECT,
    )
  })

  const verifyOut = (over: Record<string, unknown> = {}): string =>
    JSON.stringify({
      egress_probe: 'blocked',
      anonymous_probe: 'blocked',
      anonymous_loopback_probe: 'blocked',
      deny_only_probe: 'blocked',
      low_integrity_probe: 'blocked',
      low_integrity_loopback_probe: 'blocked',
      untrusted_integrity_probe: 'blocked',
      untrusted_integrity_loopback_probe: 'blocked',
      target: '127.0.0.1:49999',
      anonymous_target: '10.0.0.5:49999',
      residuals: [],
      runner_exit: 16777216,
      ...over,
    })
  const runVerify = (status: number, stdout: string) => {
    stubSpawn(() => ({ status, stdout }))
    return verifyWindowsWfpEgress({
      target: '127.0.0.1:49999',
      srtWin: resolveSrtWin({ path: process.execPath }),
    })
  }
  const verifyCode = async (status: number, stdout: string) => {
    try {
      await runVerify(status, stdout)
    } catch (e) {
      return e instanceof WindowsSandboxError ? e.code : `not typed: ${e}`
    }
    return 'resolved'
  }

  it('verifyWindowsWfpEgress: passes --target and reports every attempt separately', async () => {
    const r = await runVerify(0, verifyOut())
    expect(spawnSpy.mock.calls[0][1]).toEqual([
      SRT_WIN_DISPATCH_ARG1,
      'wfp',
      'verify',
      '--target',
      '127.0.0.1:49999',
      '--write-restricted-token',
    ])
    expect(r.probes).toEqual({
      plain: 'blocked',
      anonymous: 'blocked',
      anonymousLoopback: 'blocked',
      denyOnly: 'blocked',
      lowIntegrity: 'blocked',
      lowIntegrityLoopback: 'blocked',
      untrustedIntegrity: 'blocked',
      untrustedIntegrityLoopback: 'blocked',
    })
    expect(r.residuals).toEqual([])
    expect(r.warnings).toEqual([])
  })

  it('verifyWindowsWfpEgress: the anonymous off-loopback attempt is asked for only on request', async () => {
    stubSpawn(() => ({ status: 0, stdout: verifyOut() }))
    await verifyWindowsWfpEgress({
      target: '127.0.0.1:49999',
      anonymousEgress: true,
      srtWin: resolveSrtWin({ path: process.execPath }),
    })
    expect(spawnSpy.mock.calls[0][1]).toEqual([
      SRT_WIN_DISPATCH_ARG1,
      'wfp',
      'verify',
      '--target',
      '127.0.0.1:49999',
      '--anonymous-egress',
      '--write-restricted-token',
    ])
  })

  it('verifyWindowsWfpEgress: residuals resolve, named, each with a warning — never a silent pass', async () => {
    const r = await runVerify(
      0,
      verifyOut({
        anonymous_probe: 'refused',
        anonymous_loopback_probe: 'connected',
        deny_only_probe: 'connected',
        residuals: [
          'anonymous-egress',
          'anonymous-loopback',
          'deny-only-user-sid',
        ],
      }),
    )
    expect(r.probes.anonymous).toBe('refused')
    expect(r.probes.anonymousLoopback).toBe('connected')
    expect(r.probes.denyOnly).toBe('connected')
    expect(r.residuals).toEqual([
      'anonymous-egress',
      'anonymous-loopback',
      'deny-only-user-sid',
    ])
    expect(r.warnings.length).toBe(3)
    expect(r.warnings[0]).toMatch(/anonymous-egress/)
    expect(r.warnings[1]).toMatch(/anonymous-loopback/)
    expect(r.warnings[2]).toMatch(/deny-only-user-sid/)
  })

  it('verifyWindowsWfpEgress: a residual name this version does not know is dropped', async () => {
    const r = await runVerify(
      0,
      verifyOut({ residuals: ['anonymous-egress', 'something-newer'] }),
    )
    expect(r.residuals).toEqual(['anonymous-egress'])
    expect(r.warnings.length).toBe(1)
  })

  it('verifyWindowsWfpEgress: a skipped anonymous attempt resolves with nothing to report', async () => {
    const r = await runVerify(
      0,
      verifyOut({ anonymous_probe: 'skipped', anonymous_target: null }),
    )
    expect(r.probes.anonymous).toBe('skipped')
    expect(r.residuals).toEqual([])
    expect(r.warnings).toEqual([])
  })

  it('verifyWindowsWfpEgress: the plain attempt connecting rejects (wfp_fence_inactive)', async () => {
    expect(await verifyCode(3, verifyOut({ egress_probe: 'connected' }))).toBe(
      'wfp_fence_inactive',
    )
  })

  it('verifyWindowsWfpEgress: the anonymous attempt getting out is a residual, never a failure', async () => {
    for (const through of ['connected', 'refused'] as const) {
      const r = await runVerify(
        0,
        verifyOut({
          anonymous_probe: through,
          residuals: ['anonymous-egress'],
        }),
      )
      expect(r.probes.anonymous).toBe(through)
      expect(r.probes.plain).toBe('blocked')
      expect(r.residuals).toEqual(['anonymous-egress'])
      expect(r.warnings.length).toBe(1)
      expect(r.warnings[0]).toMatch(/anonymous-egress/)
      expect(r.warnings[0]).toMatch(/not fenced/)
      spawnSpy.mockRestore()
      spawnSyncSpy.mockRestore()
    }
    // Whatever else it reports, it does not decide the result.
    for (const other of ['blocked', 'unreachable', 'error']) {
      expect(await verifyCode(0, verifyOut({ anonymous_probe: other }))).toBe(
        'resolved',
      )
      spawnSpy.mockRestore()
      spawnSyncSpy.mockRestore()
    }
  })

  it('verifyWindowsWfpEgress: a lowered-integrity attempt getting out rejects and says which', async () => {
    const cases: [string, RegExp][] = [
      [
        'low_integrity_probe',
        /low-integrity copy of its token to 10\.0\.0\.5:49999/,
      ],
      [
        'low_integrity_loopback_probe',
        /low-integrity copy of its token to 127\.0\.0\.1:49999/,
      ],
      [
        'untrusted_integrity_probe',
        /untrusted-integrity copy of its token to 10\.0\.0\.5:49999/,
      ],
      [
        'untrusted_integrity_loopback_probe',
        /untrusted-integrity copy of its token to 127\.0\.0\.1:49999/,
      ],
    ]
    for (const [field, says] of cases) {
      // Exit 0 as well as 3: an attempt reported as through rejects
      // whatever the exit code says.
      for (const status of [3, 0]) {
        for (const through of ['connected', 'refused']) {
          const err = await runVerify(
            status,
            verifyOut({ [field]: through }),
          ).catch(e => e as WindowsSandboxError)
          expect(err).toBeInstanceOf(WindowsSandboxError)
          expect((err as WindowsSandboxError).code).toBe('wfp_fence_inactive')
          expect((err as WindowsSandboxError).message).toMatch(says)
          spawnSpy.mockRestore()
          spawnSyncSpy.mockRestore()
        }
      }
    }
  })

  it('verifyWindowsWfpEgress: a lowered token that could not be set up resolves, named as a residual', async () => {
    const r = await runVerify(
      0,
      verifyOut({
        low_integrity_loopback_probe: 'error',
        residuals: ['lowered-integrity-unprobed'],
      }),
    )
    expect(r.probes.plain).toBe('blocked')
    expect(r.probes.lowIntegrityLoopback).toBe('error')
    expect(r.residuals).toEqual(['lowered-integrity-unprobed'])
    expect(r.warnings.length).toBe(1)
    expect(r.warnings[0]).toMatch(/could not be set up/)
    spawnSpy.mockRestore()
    spawnSyncSpy.mockRestore()
    // A plain attempt that is itself inconclusive still rejects.
    expect(
      await verifyCode(
        2,
        verifyOut({
          egress_probe: 'error',
          low_integrity_loopback_probe: 'error',
        }),
      ),
    ).toBe('wfp_verify_inconclusive')
  })

  it('verifyWindowsWfpEgress: skipped off-loopback lowered-integrity attempts resolve with a warning', async () => {
    const r = await runVerify(
      0,
      verifyOut({
        anonymous_probe: 'skipped',
        low_integrity_probe: 'skipped',
        untrusted_integrity_probe: 'skipped',
        anonymous_target: null,
      }),
    )
    expect(r.probes.lowIntegrity).toBe('skipped')
    expect(r.probes.lowIntegrityLoopback).toBe('blocked')
    expect(r.warnings.length).toBe(1)
    expect(r.warnings[0]).toMatch(/lowered-integrity/)
  })

  const openOut = (over: Record<string, unknown> = {}): string =>
    verifyOut({
      target: '127.0.0.1:50123',
      egress_target: `127.0.0.1:${WINDOWS_LOOPBACK_PROBE_PORT}`,
      anonymous_target: '10.0.0.5:50123',
      allow_loopback: true,
      anonymous_loopback_probe: 'skipped',
      deny_only_probe: 'skipped',
      open_loopback_probe: 'connected',
      loopback_notice: 'loopback is open',
      ...over,
    })
  const runOpenVerify = (status: number, stdout: string) => {
    stubSpawn(() => ({ status, stdout }))
    return verifyWindowsWfpEgress({
      target: '127.0.0.1:50123',
      allowLoopback: true,
      srtWin: resolveSrtWin({ path: process.execPath }),
    })
  }

  it('verifyWindowsWfpEgress: allowLoopback is passed as --allow-loopback, the open-loopback attempt is reported, and the result says loopback is open', async () => {
    const r = await runOpenVerify(0, openOut())
    expect(spawnSpy.mock.calls[0][1]).toEqual([
      SRT_WIN_DISPATCH_ARG1,
      'wfp',
      'verify',
      '--target',
      '127.0.0.1:50123',
      '--allow-loopback',
      '--write-restricted-token',
    ])
    expect(r.probes).toEqual({
      plain: 'blocked',
      anonymous: 'blocked',
      anonymousLoopback: 'skipped',
      denyOnly: 'skipped',
      lowIntegrity: 'blocked',
      lowIntegrityLoopback: 'blocked',
      untrustedIntegrity: 'blocked',
      untrustedIntegrityLoopback: 'blocked',
      openLoopback: 'connected',
    })
    expect(r.warnings).toEqual([WINDOWS_ALLOW_LOOPBACK_EFFECT])
  })

  it('verifyWindowsWfpEgress: with loopback closed there is no flag, no open-loopback attempt and no such warning', async () => {
    for (const off of [{}, { allowLoopback: false }]) {
      stubSpawn(() => ({ status: 0, stdout: verifyOut() }))
      const r = await verifyWindowsWfpEgress({
        target: '127.0.0.1:49999',
        ...off,
        srtWin: resolveSrtWin({ path: process.execPath }),
      })
      expect(spawnSpy.mock.calls[0][1]).not.toContain('--allow-loopback')
      expect(r.probes.openLoopback).toBeUndefined()
      expect(r.warnings).toEqual([])
      spawnSpy.mockRestore()
      spawnSyncSpy.mockRestore()
    }
  })

  it('verifyWindowsWfpEgress: with loopback open, a lowered-integrity attempt getting out names the target it was aimed at', async () => {
    const err = await runOpenVerify(
      3,
      openOut({ low_integrity_probe: 'connected' }),
    ).catch(e => e as WindowsSandboxError)
    expect((err as WindowsSandboxError).code).toBe('wfp_fence_inactive')
    expect((err as WindowsSandboxError).message).toMatch(
      /low-integrity copy of its token to 10\.0\.0\.5:50123/,
    )
    spawnSpy.mockRestore()
    spawnSyncSpy.mockRestore()
  })

  it('verifyWindowsWfpEgress: with loopback open, only the filter refusing the reserved port passes', async () => {
    const reserved = `127\\.0\\.0\\.1:${WINDOWS_LOOPBACK_PROBE_PORT}`
    // Refused by the stack (slowly or not), connected, or no answer in
    // time: the block did not fire, whatever the exit code says.
    for (const [status, plain] of [
      [3, 'refused'],
      [3, 'connected'],
      [3, 'unreachable'],
      [0, 'refused'],
      [0, 'unreachable'],
      [2, 'unreachable'],
    ] as const) {
      const err = await runOpenVerify(
        status,
        openOut({ egress_probe: plain }),
      ).catch(e => e as WindowsSandboxError)
      expect(err).toBeInstanceOf(WindowsSandboxError)
      expect((err as WindowsSandboxError).code).toBe('wfp_fence_inactive')
      expect((err as WindowsSandboxError).message).toMatch(
        new RegExp(`from the sandbox user to ${reserved}`),
      )
      spawnSpy.mockRestore()
      spawnSyncSpy.mockRestore()
    }
    // No connect was made at all: not a pass either.
    for (const plain of ['error', 'skipped']) {
      expect(
        await runOpenVerify(0, openOut({ egress_probe: plain })).then(
          () => 'resolved',
          e => (e as WindowsSandboxError).code,
        ),
      ).toBe('wfp_verify_inconclusive')
      spawnSpy.mockRestore()
      spawnSyncSpy.mockRestore()
    }
    // A lowered-integrity copy reaching the reserved port is named there.
    const leak = await runOpenVerify(
      3,
      openOut({ low_integrity_loopback_probe: 'refused' }),
    ).catch(e => e as WindowsSandboxError)
    expect((leak as WindowsSandboxError).message).toMatch(
      new RegExp(`low-integrity copy of its token to ${reserved}`),
    )
    spawnSpy.mockRestore()
    spawnSyncSpy.mockRestore()
    // With loopback closed, no answer from the listener stays inconclusive.
    expect(
      await verifyCode(2, verifyOut({ egress_probe: 'unreachable' })),
    ).toBe('wfp_verify_inconclusive')
  })

  /**
   * Stand-in for net.createServer. `taken` ports fail to listen; a
   * listen on port 0 is handed the next of `ephemeral`.
   */
  const fakeServers = (taken: number[], ephemeral: number[] = []) => {
    const asked: number[] = []
    const closed: number[] = []
    const spy = spyOn(net, 'createServer').mockImplementation((() => {
      let port = -1
      const s = new EventEmitter() as EventEmitter & {
        listen(p: number): void
        address(): { port: number }
        close(): void
      }
      s.listen = (p: number) => {
        asked.push(p)
        port = p === 0 ? ephemeral.shift()! : p
        setImmediate(() =>
          taken.includes(port)
            ? s.emit('error', new Error('EADDRINUSE'))
            : s.emit('listening'),
        )
      }
      s.address = () => ({ port })
      s.close = () => void closed.push(port)
      return s
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    }) as any)
    return { asked, closed, spy }
  }

  it('verifyWindowsWfpEgress: with loopback open the listener is likewise an ephemeral port outside the proxy range', async () => {
    const servers = fakeServers([], [60085, 49999])
    try {
      stubSpawn(() => ({ status: 0, stdout: openOut() }))
      await verifyWindowsWfpEgress({
        allowLoopback: true,
        srtWin: resolveSrtWin({ path: process.execPath }),
      })
      const argv = spawnSpy.mock.calls[0][1] as string[]
      // The proxy range is reachable with loopback closed too, so a
      // listener there would not show that loopback is open.
      expect(argv[argv.indexOf('--target') + 1]).toBe('127.0.0.1:49999')
      expect(argv).not.toContain('--proxy-port-range')
      expect(servers.closed).toEqual([60085, 49999])
    } finally {
      servers.spy.mockRestore()
    }
  })

  it('verifyWindowsWfpEgress: with loopback closed the listener is an ephemeral port outside the proxy range', async () => {
    const servers = fakeServers([], [60085, 49999])
    try {
      stubSpawn(() => ({ status: 0, stdout: verifyOut() }))
      await verifyWindowsWfpEgress({
        srtWin: resolveSrtWin({ path: process.execPath }),
      })
      const argv = spawnSpy.mock.calls[0][1] as string[]
      expect(argv[argv.indexOf('--target') + 1]).toBe('127.0.0.1:49999')
      expect(servers.asked).toEqual([0, 0])
      expect(servers.closed).toEqual([60085, 49999])
    } finally {
      servers.spy.mockRestore()
    }
  })

  it('checkWindowsDependencies: the suggested install carries the configured loopback mode and install options', () => {
    const srtWin = resolveSrtWin({ path: process.execPath })
    const errorsFor = (wfp: Record<string, unknown>, opts: object) => {
      stubSpawn(argv => ({
        status: 0,
        stdout: argv.includes('user') ? RAW_USER : rawWfp(wfp),
      }))
      const { errors } = checkWindowsDependencies({ srtWin, ...opts })
      spawnSpy.mockRestore()
      spawnSyncSpy.mockRestore()
      return errors
    }
    // Filters whose loopback mode is not the recorded one: one
    // reinstall for the configuration, replacing what is there.
    const [drifted] = errorsFor(
      { state: 'loopback-mismatch', allow_loopback: false, hint: 'x' },
      { allowLoopback: true },
    )
    expect(drifted).toContain('is not the one the install recorded')
    expect(drifted).toContain('windows-install --allow-loopback --force')
    expect(drifted.match(/one UAC prompt/g)?.length).toBe(1)
    // Not installed: nothing to replace, and the other options are named.
    const [absent] = errorsFor(
      { state: 'absent', filters: 0 },
      {
        allowLoopback: true,
        sublayerGuid: '11111111-2222-3333-4444-555555555555',
        proxyPortRange: [3000, 3010],
        sandboxUser: 'alt-sandbox',
      },
    )
    expect(absent).toContain(
      'windows-install --sublayer-guid 11111111-2222-3333-4444-555555555555 ' +
        '--proxy-port-range 3000-3010 --sandbox-user alt-sandbox ' +
        '--allow-loopback\n',
    )
    // A mode mismatch on a current install: the same options, with --force.
    const [mismatch] = errorsFor(
      { state: 'installed', allow_loopback: false },
      { allowLoopback: true, proxyPortRange: [3000, 3010] },
    )
    expect(mismatch).toContain(
      'windows-install --proxy-port-range 3000-3010 --allow-loopback --force',
    )
  })

  it('verifyWindowsWfpEgress: a loopback mode that is not the installed one rejects (wfp_loopback_mismatch) with the install command for this session, in either direction', async () => {
    const hint =
      "the network fence on this machine does not match this session's " +
      'loopback mode (installed: closed; configured: open)'
    const err = await runOpenVerify(
      19,
      JSON.stringify({
        egress_probe: 'not-run',
        target: '127.0.0.1:50123',
        allow_loopback_mismatch: true,
        allow_loopback: true,
        hint,
      }),
    ).catch(e => e as WindowsSandboxError)
    expect(err).toBeInstanceOf(WindowsSandboxError)
    expect((err as WindowsSandboxError).code).toBe('wfp_loopback_mismatch')
    expect((err as WindowsSandboxError).message).toMatch(
      /does not match network\.allowLocalBinding/,
    )
    expect((err as WindowsSandboxError).message).toContain(hint)
    expect((err as WindowsSandboxError).message).toContain(
      'npx @anthropic-ai/sandbox-runtime windows-install --allow-loopback --force',
    )
    spawnSpy.mockRestore()
    spawnSyncSpy.mockRestore()
    // Configured closed while the install is open: the command that closes it.
    const closed = await runVerify(
      19,
      JSON.stringify({
        egress_probe: 'not-run',
        target: '127.0.0.1:49999',
        allow_loopback_mismatch: true,
        allow_loopback: false,
        hint: 'installed: open; configured: closed',
      }),
    ).catch(e => e as WindowsSandboxError)
    expect((closed as WindowsSandboxError).code).toBe('wfp_loopback_mismatch')
    expect((closed as WindowsSandboxError).message).toContain(
      '`npx @anthropic-ai/sandbox-runtime windows-install --force`',
    )
  })

  it('verifyWindowsWfpEgress: an srt-win that does not know --allow-loopback rejects as too old', async () => {
    stubSpawn(() => ({
      status: 2,
      stdout: '',
      stderr:
        "error: unexpected argument '--allow-loopback' found\n\n" +
        'Usage: srt-win wfp verify --target <TARGET>\n',
    }))
    const err = await verifyWindowsWfpEgress({
      target: '127.0.0.1:50123',
      allowLoopback: true,
      srtWin: resolveSrtWin({ path: process.execPath }),
    }).catch(e => e as WindowsSandboxError)
    expect(err).toBeInstanceOf(WindowsSandboxError)
    expect((err as WindowsSandboxError).code).toBe('srt_win_too_old')
    expect((err as WindowsSandboxError).message).toMatch(
      /too old for network\.allowLocalBinding/,
    )
  })

  it('verifyWindowsWfpEgress: loopback found closed where it is recorded open rejects (wfp_loopback_mismatch)', async () => {
    const err = await runOpenVerify(
      19,
      openOut({
        open_loopback_probe: 'blocked',
        allow_loopback_mismatch: true,
        hint: 'the network fence on this machine does not open loopback',
      }),
    ).catch(e => e as WindowsSandboxError)
    expect((err as WindowsSandboxError).code).toBe('wfp_loopback_mismatch')
    expect((err as WindowsSandboxError).message).toMatch(
      /does not open loopback/,
    )
    expect((err as WindowsSandboxError).message).toContain(
      'windows-install --allow-loopback --force',
    )
  })

  it('verifyWindowsWfpEgress: an inconclusive open-loopback attempt rejects', async () => {
    expect(
      await runOpenVerify(
        2,
        openOut({ open_loopback_probe: 'unreachable' }),
      ).then(
        () => 'resolved',
        e => (e as WindowsSandboxError).code,
      ),
    ).toBe('wfp_verify_inconclusive')
  })

  it('verifyWindowsWfpEgress: inconclusive and unparseable runs reject', async () => {
    expect(
      await verifyCode(2, verifyOut({ egress_probe: 'unreachable' })),
    ).toBe('wfp_verify_inconclusive')
    spawnSpy.mockRestore()
    spawnSyncSpy.mockRestore()
    expect(
      await verifyCode(
        1,
        verifyOut({
          egress_probe: 'error',
          anonymous_probe: 'error',
          anonymous_loopback_probe: 'error',
          deny_only_probe: 'error',
        }),
      ),
    ).toBe('wfp_verify_inconclusive')
    spawnSpy.mockRestore()
    spawnSyncSpy.mockRestore()
    expect(await verifyCode(0, '')).toBe('wfp_verify_unparseable')
  })

  it('verifyWindowsWfpEgress: exit 0 without a blocked plain attempt does not resolve', async () => {
    const { egress_probe: _dropped, ...withoutPlain } = JSON.parse(
      verifyOut(),
    ) as Record<string, unknown>
    for (const stdout of [
      JSON.stringify(withoutPlain),
      verifyOut({ egress_probe: 'novel' }),
      verifyOut({ egress_probe: 'skipped' }),
    ]) {
      expect(await verifyCode(0, stdout)).toBe('wfp_verify_inconclusive')
      spawnSpy.mockRestore()
      spawnSyncSpy.mockRestore()
    }
  })

  it('verifyWindowsWfpEgress: a residual named beside a failing exit still rejects', async () => {
    // Residuals qualify a pass only; they never soften a failure.
    expect(
      await verifyCode(
        3,
        verifyOut({
          egress_probe: 'connected',
          residuals: ['deny-only-user-sid'],
        }),
      ),
    ).toBe('wfp_fence_inactive')
  })
})

describe('Windows write roots are granted once and kept (pure, all platforms)', () => {
  const SID = 'S-1-5-21-1'
  const RAW_USER = {
    user: {
      exists: true,
      sid: SID,
      group_exists: true,
      group_sid: 'S-1-5-21-2',
      in_builtin_users: true,
      in_sandbox_group: true,
      hidden_from_logon: true,
    },
    cred_present: true,
    marker_version: 1,
    real_user_sid: 'S-1-5-21-3',
    ca_cert_thumb: null,
    ca_cert_pem: null,
  }
  const RAW_WFP = {
    state: 'installed',
    filters: 4,
    port_range: [60080, 60089],
    user_sid: SID,
  }
  type SyncResult = { status: number; stdout: string; stderr: string }
  const exit = (status: number, stdout = ''): SyncResult => ({
    status,
    stdout,
    stderr: '',
  })

  /** What `user status` adds about kept grants; `undefined` = no field. */
  let persistentGrants: unknown
  /** What `user status` says srt-win does; `undefined` = no field. */
  let capabilities: string[] | undefined = SRT_WIN_CAPABILITIES
  /** `marker_version` / `setup_version` overrides for `user status`. */
  let setupVersions: { marker_version?: number; setup_version?: number }
  /** The sandbox account of this test: the fence check is kept per account. */
  let sid = SID
  let accounts = 0
  const stdoutFor = (argv: readonly string[]): string => {
    const user = {
      ...RAW_USER,
      user: { ...RAW_USER.user, sid },
      ...setupVersions,
      ...(persistentGrants !== undefined && {
        persistent_grants: persistentGrants,
      }),
      ...(capabilities !== undefined && { capabilities }),
    }
    return argv.includes('profile')
      ? CURRENT_PROFILE_GRANT
      : argv.includes('user')
        ? JSON.stringify(user)
        : argv.includes('wfp')
          ? JSON.stringify(RAW_WFP)
          : argv.includes('status')
            ? JSON.stringify({ user, wfp: RAW_WFP })
            : ''
  }
  /** Every `acl` spawn: subcommand, flags after it, parsed stdin. */
  let acl: { sub: string; argv: string[]; stdin: unknown }[]
  /** spawnSync result per `acl` subcommand; default exit 0, `[]`. */
  let aclResult: Record<string, SyncResult>
  /** Arguments of every fence probe. */
  let verifyCalls: Parameters<typeof winUtils.verifyWindowsWfpEgress>[0][]
  let verifyResult: () => Promise<unknown>
  let spies: { mockRestore(): void }[]
  let dir: string

  const subs = () => acl.map(c => c.sub)

  beforeEach(() => {
    sid = `${SID}-${++accounts}`
    persistentGrants = undefined
    capabilities = SRT_WIN_CAPABILITIES
    setupVersions = {}
    acl = []
    aclResult = {}
    verifyCalls = []
    verifyResult = () => Promise.resolve({ outcome: 'blocked' })
    dir = mkdtempSync(join(tmpdir(), 'srt-persist-'))
    mkdirSync(join(dir, 'secret'))
    spies = [
      spyOn(platform, 'getPlatform').mockReturnValue('windows'),
      spyOn(winUtils, 'verifyWindowsWfpEgress').mockImplementation(((
        o: Parameters<typeof winUtils.verifyWindowsWfpEgress>[0],
      ) => {
        verifyCalls.push(o)
        return verifyResult()
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
      }) as any),
      spyOn(child_process, 'spawn').mockImplementation(((
        _exe: string,
        argv: readonly string[],
      ) => {
        if (madeWithoutBlocking(argv))
          return asyncChildAnsweredBySync(_exe, argv)
        const mkStream = () => {
          const s = new EventEmitter() as EventEmitter & {
            setEncoding(e: string): typeof s
            end(d?: string): void
          }
          s.setEncoding = () => s
          s.end = () => {}
          return s
        }
        const child = Object.assign(new EventEmitter(), {
          stdout: mkStream(),
          stderr: mkStream(),
          stdin: mkStream(),
          kill: () => true,
        })
        setImmediate(() => {
          child.stdout.emit('data', stdoutFor(argv))
          child.emit('close', 0, null)
        })
        return child
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
      }) as any),
      // Sync spawns: every `acl` call.
      spyOn(child_process, 'spawnSync').mockImplementation(((
        _exe: string,
        argv: readonly string[],
        opts: { input?: string },
      ) => {
        if (!argv.includes('acl')) return exit(0, stdoutFor(argv))
        const at = argv.indexOf('acl') + 1
        acl.push({
          sub: argv[at],
          argv: argv.slice(at + 1),
          stdin: opts.input === undefined ? undefined : JSON.parse(opts.input),
        })
        return aclResult[argv[at]] ?? exit(0, '[]')
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
      }) as any),
    ]
  })

  afterEach(async () => {
    aclResult = {}
    await SandboxManager.reset()
    for (const s of spies) s.mockRestore()
    rmSync(dir, { recursive: true, force: true })
  })

  const config = (): SandboxRuntimeConfig => ({
    network: {
      allowedDomains: [],
      deniedDomains: [],
      httpProxyPort: 1,
      socksProxyPort: 2,
    },
    filesystem: {
      denyRead: [join(dir, 'secret')],
      allowRead: [],
      allowWrite: [dir],
      denyWrite: [],
    },
    windows: { srtWin: { path: process.execPath } },
  })
  const rejection = async (
    cfg: SandboxRuntimeConfig,
  ): Promise<WindowsSandboxError> => {
    try {
      await SandboxManager.initialize(cfg)
    } catch (e) {
      return e as WindowsSandboxError
    }
    throw new Error('expected initialize() to reject')
  }

  describe('session start', () => {
    it('one acl grant --persistent carries roots and denies; no per-session grant or stamp; the probe gets the roots; exec gets --write-root', async () => {
      await SandboxManager.initialize(config())
      expect(subs()).toEqual(['grant'])
      expect(acl[0].argv).toContain('--persistent')
      const stdin = acl[0].stdin as Record<string, string[]>
      expect(stdin.write).toHaveLength(1)
      expect(stdin.denyRead).toHaveLength(1)
      expect(stdin.read).toEqual([])
      expect(stdin.denyWrite).toEqual([])
      // The probe runs after the grant: the capability SIDs exist only then.
      expect(verifyCalls).toHaveLength(1)
      expect(verifyCalls[0]?.writeRoots).toEqual(stdin.write)

      const { argv } = await SandboxManager.wrapWithSandboxArgv('echo x')
      const at = argv.indexOf('--write-restricted-token')
      expect(argv.slice(at, at + 3)).toEqual([
        '--write-restricted-token',
        '--write-root',
        stdin.write[0],
      ])
      expect(at + 3).toBeLessThanOrEqual(argv.indexOf('--'))
      // git is steered to the backend that works under this token.
      const envArgs = argv.filter((_, i) => argv[i - 1] === '--env')
      expect(envArgs.join(' ')).toMatch(
        /GIT_CONFIG_KEY_(\d+)=http\.sslBackend GIT_CONFIG_VALUE_\1=openssl/,
      )
    })

    it('reset() releases only what was per-session; nothing forgets the roots', async () => {
      await SandboxManager.initialize(config())
      await SandboxManager.reset()
      expect(subs()).toEqual(['grant', 'revoke', 'restore'])
      expect(subs()).not.toContain('forget')
    })

    it('the fence is probed once per sandbox account, not on every initialize()', async () => {
      await SandboxManager.initialize(config())
      await SandboxManager.reset()
      await SandboxManager.initialize(config())
      expect(verifyCalls).toHaveLength(1)
      expect(verifyCalls[0]?.writeRoots).toHaveLength(1)
      // Another account (a reinstall) is probed again.
      await SandboxManager.reset()
      sid = `${SID}-other-${accounts}`
      await SandboxManager.initialize(config())
      expect(verifyCalls).toHaveLength(2)
    })

    it('a probe that is not blocked is not remembered', async () => {
      verifyResult = () =>
        Promise.reject(
          new WindowsSandboxError('wfp_fence_inactive', 'connected'),
        )
      await rejection(config())
      verifyResult = () => Promise.resolve({ outcome: 'blocked' })
      await SandboxManager.initialize(config())
      expect(verifyCalls).toHaveLength(2)
    })

    it('a session with nothing to grant still probes, with no roots', async () => {
      const cfg = config()
      cfg.filesystem = {
        denyRead: [],
        allowRead: [],
        allowWrite: [],
        denyWrite: [],
      }
      await SandboxManager.initialize(cfg)
      expect(subs()).toEqual(['grant'])
      expect(acl[0].stdin).toEqual({
        read: [],
        write: [],
        denyRead: [],
        denyWrite: [],
      })
      expect(verifyCalls).toHaveLength(1)
      expect(verifyCalls[0]?.writeRoots).toEqual([])
      const { argv } = await SandboxManager.wrapWithSandboxArgv('echo x')
      expect(argv).toContain('--write-restricted-token')
      expect(argv).not.toContain('--write-root')
      expect(argv[argv.indexOf('--held-by') + 1]).toBe(`${process.pid}`)
      await SandboxManager.reset()
      expect(subs()).toEqual(['grant', 'revoke', 'restore'])
    })

    for (const status of [1, 2]) {
      it('acl grant --persistent exits ${status} → initialize() rejects; no fallback to a per-session grant, no probe, no command', async () => {
        aclResult.grant = exit(status)
        const e = await rejection(config())
        expect(e.code).toBe('acl_grant_failed')
        expect(subs().filter(s => s === 'grant')).toHaveLength(1)
        expect(subs()).not.toContain('stamp')
        expect(acl[0].argv).toContain('--persistent')
        expect(verifyCalls).toHaveLength(0)
        expect(SandboxManager.getConfig()).toBeUndefined()
      })
    }

    it('the probe is not blocked → initialize() rejects and releases what it granted', async () => {
      verifyResult = () =>
        Promise.reject(
          new WindowsSandboxError('wfp_fence_inactive', 'connected'),
        )
      const e = await rejection(config())
      expect(e.code).toBe('wfp_fence_inactive')
      expect(SandboxManager.getConfig()).toBeUndefined()
      expect(subs()).toEqual(['grant', 'revoke', 'restore'])
      expect(acl[0].argv).toContain('--persistent')
      expect(verifyCalls).toHaveLength(1)
    })

    it('with kept grants reported: nothing is forgotten', async () => {
      persistentGrants = { state: 'present', roots: [dir] }
      await SandboxManager.initialize(config())
      expect(subs()).toEqual(['grant'])
    })
  })

  it('a wrap outside a session gets the write-restricted token, with no roots', async () => {
    const { argv } = await SandboxManager.wrapWithSandboxArgv(
      'echo x',
      undefined,
      { windows: { srtWin: { path: process.execPath } } },
    )
    expect(argv).toContain('--write-restricted-token')
    expect(argv).not.toContain('--write-root')
  })

  describe('setup version', () => {
    it('an install of another setup version → initialize() asks for a re-install and makes no acl call', async () => {
      setupVersions = { marker_version: 2, setup_version: 3 }
      persistentGrants = { state: 'present', roots: ['C:\\kept'] }
      const stale = (e: Error) => {
        expect(e.message).toMatch(/setup version 2; this release needs 3/)
        expect(e.message).toMatch(/Re-run the install/)
        expect(e.message).toContain(
          'npx @anthropic-ai/sandbox-runtime windows-install',
        )
        expect(e.message).not.toMatch(/not provisioned|one-time install/i)
        expect(subs()).toEqual([])
        expect(verifyCalls).toHaveLength(0)
      }
      // The dependency check reports it first, as the typed error.
      const first = await rejection(config())
      expect(first).toBeInstanceOf(WindowsSandboxError)
      expect(first.code).toBe('reinstall_required')
      stale(first)
      // initialize() holds on its own reading of the install too.
      const deps = spyOn(
        winUtils,
        'checkWindowsDependenciesAsync',
      ).mockResolvedValue({ errors: [], warnings: [] })
      try {
        const e = await rejection(config())
        expect(e).toBeInstanceOf(WindowsSandboxError)
        expect(e.code).toBe('reinstall_required')
        stale(e)
        expect(SandboxManager.getConfig()).toBeUndefined()
      } finally {
        deps.mockRestore()
      }
    })
  })

  it('the install is of this setup version, or srt-win reports none: initialize() proceeds', async () => {
    for (const v of [{ marker_version: 3, setup_version: 3 }, {}]) {
      setupVersions = v
      acl = []
      await SandboxManager.initialize(config())
      expect(subs()).toEqual(['grant'])
      await SandboxManager.reset()
    }
  })
})

describe('Windows session ACLs: restore gated on a completed revoke (pure, all platforms)', () => {
  /** The `acl` call a session start makes. */
  const START = ['grant']
  /** What initialize() rejects with when it fails. */
  const START_FAILED = 'acl_grant_failed'
  const SID = 'S-1-5-21-1'
  // spawnSync is stubbed, so any existing file does.
  const STUB_SRT_WIN = resolveSrtWin({ path: process.execPath })
  const RAW_USER = {
    user: {
      exists: true,
      sid: SID,
      group_exists: true,
      group_sid: 'S-1-5-21-2',
      in_builtin_users: true,
      in_sandbox_group: true,
      hidden_from_logon: true,
    },
    cred_present: true,
    capabilities: SRT_WIN_CAPABILITIES,
    marker_version: 1,
    real_user_sid: 'S-1-5-21-3',
    ca_cert_thumb: null,
    ca_cert_pem: null,
  }
  const RAW_WFP = {
    state: 'installed',
    filters: 4,
    port_range: [60080, 60089],
    user_sid: SID,
  }
  const stdoutFor = (argv: readonly string[]): string =>
    argv.includes('profile')
      ? CURRENT_PROFILE_GRANT
      : argv.includes('user')
        ? JSON.stringify(RAW_USER)
        : argv.includes('wfp')
          ? JSON.stringify(RAW_WFP)
          : argv.includes('status')
            ? JSON.stringify({ user: RAW_USER, wfp: RAW_WFP })
            : ''

  type SyncResult = {
    status: number | null
    stdout: string
    stderr: string
    error: Error | null
    signal?: string
  }
  const exit = (status: number, stdout: string): SyncResult => ({
    status,
    stdout,
    stderr: '',
    error: null,
  })
  // What spawnSync reports when it kills the child at `timeout`.
  const TIMED_OUT: SyncResult = {
    status: null,
    signal: 'SIGTERM',
    stdout: '',
    stderr: '',
    error: Object.assign(new Error('spawnSync ETIMEDOUT'), {
      code: 'ETIMEDOUT',
    }),
  }
  type Revoke = [how: string, result: () => SyncResult]
  const reports = (status: string, path = 'p'): SyncResult =>
    exit(
      0,
      JSON.stringify([
        { path: 'released', status: 'revoked' },
        { path, status },
      ]),
    )
  // Thunks: `dir` exists only inside a test.
  const INCOMPLETE_REVOKES: Revoke[] = [
    ['exits non-zero', () => exit(1, '[{"path":"p","status":"revoked"}]')],
    ['times out', () => TIMED_OUT],
    ['prints unparseable output', () => exit(0, 'not json')],
    ['prints JSON that is not a list', () => exit(0, '{}')],
    ['lists an outcome with no status', () => exit(0, '[{"path":"p"}]')],
    // The last status is one this code has never heard of.
    ...['unreadable', 'failed', 'mismatch', 'someLaterStatus'].map(
      (st): Revoke => [`reports "${st}" for a path`, () => reports(st)],
    ),
    // What an older srt-win says about a path it could not open.
    [
      'reports "missing" for a path that still exists',
      () => reports('missing', dir),
    ],
  ]
  const COMPLETE_REVOKES: Revoke[] = [
    ['releases nothing', () => exit(0, '[]')],
    ...['revoked', 'stillHeld', 'downgraded', 'relocated', 'noRow'].map(
      (st): Revoke => [`reports "${st}" for a path`, () => reports(st)],
    ),
    [
      'reports "missing" for a path that is gone',
      () => reports('missing', join(dir, 'gone')),
    ],
    ['reports "gone" for a path that exists again', () => reports('gone', dir)],
  ]

  /** `acl` subcommands spawned, in order. */
  let aclCalls: string[]
  /** spawnSync result per `acl` subcommand; default exit 0, `[]`. */
  let aclResult: Record<string, SyncResult>
  let spies: { mockRestore(): void }[]
  let dir: string

  beforeEach(() => {
    aclCalls = []
    aclResult = {}
    dir = mkdtempSync(join(tmpdir(), 'srt-acl-gate-'))
    mkdirSync(join(dir, 'secret'))
    spies = [
      spyOn(platform, 'getPlatform').mockReturnValue('windows'),
      // The WFP probe binds a listener and is once-per-process.
      spyOn(winUtils, 'verifyWindowsWfpEgress').mockResolvedValue({
        outcome: 'blocked',
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
      } as any),
      spyOn(child_process, 'spawn').mockImplementation(((
        _exe: string,
        argv: readonly string[],
      ) => {
        if (madeWithoutBlocking(argv))
          return asyncChildAnsweredBySync(_exe, argv)
        const mkStream = () => {
          const s = new EventEmitter() as EventEmitter & {
            setEncoding(e: string): typeof s
            end(d?: string): void
          }
          s.setEncoding = () => s
          s.end = () => {}
          return s
        }
        const child = Object.assign(new EventEmitter(), {
          stdout: mkStream(),
          stderr: mkStream(),
          stdin: mkStream(),
          kill: () => true,
        })
        setImmediate(() => {
          child.stdout.emit('data', stdoutFor(argv))
          child.emit('close', 0, null)
        })
        return child
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
      }) as any),
      spyOn(child_process, 'spawnSync').mockImplementation(((
        _exe: string,
        argv: readonly string[],
      ) => {
        if (!argv.includes('acl')) return exit(0, stdoutFor(argv))
        const sub = argv[argv.indexOf('acl') + 1]
        aclCalls.push(sub)
        return aclResult[sub] ?? exit(0, '[]')
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
      }) as any),
    ]
  })

  afterEach(async () => {
    aclResult = {}
    await SandboxManager.reset()
    for (const s of spies) s.mockRestore()
    rmSync(dir, { recursive: true, force: true })
  })

  const config = (): SandboxRuntimeConfig => ({
    network: {
      allowedDomains: [],
      deniedDomains: [],
      httpProxyPort: 1,
      socksProxyPort: 2,
    },
    filesystem: {
      denyRead: [join(dir, 'secret')],
      allowRead: [],
      allowWrite: [dir],
      denyWrite: [],
    },
    windows: { srtWin: { path: process.execPath } },
  })

  /** initialize() whose `acl grant` fails, so its failure cleanup runs. */
  const failingInitialize = async (): Promise<WindowsSandboxError> => {
    aclResult.grant = exit(2, '')
    try {
      await SandboxManager.initialize(config())
    } catch (e) {
      return e as WindowsSandboxError
    }
    throw new Error('expected initialize() to reject')
  }

  /** The handler registerCleanup() put on SIGINT and SIGTERM. */
  const signalHandler = (): (() => unknown) => {
    const onTerm = new Set(process.listeners('SIGTERM') as unknown[])
    const h = (process.listeners('SIGINT') as unknown[]).filter(l =>
      onTerm.has(l),
    )
    expect(h.length).toBe(1)
    return h[0] as () => unknown
  }

  /** The listener registerCleanup() put on 'exit'. */
  const exitListener = (): (() => unknown) => {
    const h = (process.listeners('exit') as unknown[]).filter(l =>
      /\bcleanupHandler\(\)/.test(String(l)),
    )
    expect(h.length).toBe(1)
    return h[0] as () => unknown
  }

  /** Both ways the process runs the release on its way out. */
  const ON_THE_WAY_OUT: [string, () => () => unknown][] = [
    ['signal handler', signalHandler],
    ["'exit' listener", exitListener],
  ]

  const NO_RESTORE = [...START, 'revoke']
  const WITH_RESTORE = [...START, 'revoke', 'restore']

  for (const [how, result] of INCOMPLETE_REVOKES) {
    it(`reset(): revoke ${how} → restore is not spawned`, async () => {
      await SandboxManager.initialize(config())
      aclResult.revoke = result()
      await SandboxManager.reset()
      expect(aclCalls).toEqual(NO_RESTORE)
    })

    it(`initialize() failure cleanup: revoke ${how} → restore is not spawned`, async () => {
      aclResult.revoke = result()
      const e = await failingInitialize()
      // Still rejects with the original failure.
      expect(e.code).toBe(START_FAILED)
      expect(aclCalls).toEqual(NO_RESTORE)
      expect(SandboxManager.getConfig()).toBeUndefined()
    })

    for (const [which, handler] of ON_THE_WAY_OUT) {
      it(`${which}: revoke ${how} → restore is not spawned`, async () => {
        await SandboxManager.initialize(config())
        aclResult.revoke = result()
        const done = handler()()
        // Synchronous: decided before the handler returns.
        expect(aclCalls).toEqual(NO_RESTORE)
        await done
        expect(aclCalls).toEqual(NO_RESTORE)
      })
    }
  }

  for (const [how, result] of COMPLETE_REVOKES) {
    it(`reset(): revoke ${how} → restore runs`, async () => {
      await SandboxManager.initialize(config())
      aclResult.revoke = result()
      await SandboxManager.reset()
      expect(aclCalls).toEqual(WITH_RESTORE)
    })

    it(`initialize() failure cleanup: revoke ${how} → restore runs`, async () => {
      aclResult.revoke = result()
      const e = await failingInitialize()
      expect(e.code).toBe(START_FAILED)
      expect(aclCalls).toEqual(WITH_RESTORE)
    })

    for (const [which, handler] of ON_THE_WAY_OUT) {
      it(`${which}: revoke ${how} → restore runs`, async () => {
        await SandboxManager.initialize(config())
        aclResult.revoke = result()
        const done = handler()()
        expect(aclCalls).toEqual(WITH_RESTORE)
        await done
      })
    }
  }

  it('reset(): a complete revoke after an incomplete one → restore runs', async () => {
    await SandboxManager.initialize(config())
    aclResult.revoke = reports('unreadable')
    await SandboxManager.reset()
    expect(aclCalls).toEqual(NO_RESTORE)
    aclCalls = []
    aclResult = {}
    await SandboxManager.initialize(config())
    await SandboxManager.reset()
    expect(aclCalls).toEqual(WITH_RESTORE)
  })

  it('restoreWindowsAcl surfaces a refusal by srt-win', () => {
    aclResult.restore = exit(1, '[{"path":"p","status":"grantPending"}]')
    expect(
      winUtils.restoreWindowsAcl({ sandboxUserSid: SID, srtWin: STUB_SRT_WIN }),
    ).toEqual([{ path: 'p', status: 'grantPending' }])
    expect(aclCalls).toEqual(['restore'])
  })

  it('revokeWindowsAclChecked names the paths whose grant may be left', () => {
    aclResult.revoke = reports('unreadable', 'C:\\tree')
    const r = winUtils.revokeWindowsAclChecked({
      sandboxUserSid: SID,
      srtWin: STUB_SRT_WIN,
    })
    expect(r.complete).toBe(false)
    expect(r.pending).toEqual(['C:\\tree'])
  })

  it('reset(): a restore that fails after a completed revoke stays best-effort', async () => {
    await SandboxManager.initialize(config())
    aclResult.restore = exit(1, 'boom')
    await SandboxManager.reset()
    expect(aclCalls).toEqual(WITH_RESTORE)
  })
})

describe.if(isWindows)('Windows sandbox: srt-win helpers', () => {
  it('getSrtWinPath resolves to an existing binary', () => {
    const p = getSrtWinPath()
    expect(existsSync(p)).toBe(true)
    expect(p).toMatch(/srt-win\.exe$/i)
  })

  it('wrapCommandWithSandboxWindows: binShell={exe,args} → [exe, ...args, cmd] (not cmd.exe)', () => {
    const cmd = `echo 'a b' && printf '%s' x | cat`
    const bashPath = 'C:\\Program Files\\Git\\bin\\bash.exe'
    const { argv } = wrapCommandWithSandboxWindows({
      command: cmd,
      binShell: parseWindowsBinShell(bashPath),
      srtWin: TEST_SRT_WIN,
    })
    expect(argv.slice(-3)).toEqual([bashPath, '-c', cmd])
    expect(argv).not.toContain('/c')
    expect(argv.join(' ')).not.toMatch(/cmd\.exe/i)
  })

  it('getWindowsWfpStatus reports absent for a never-installed sublayer', () => {
    const ws = getWindowsWfpStatus({
      sublayerGuid: '11111111-2222-3333-4444-555555555555',
      srtWin: TEST_SRT_WIN,
    })
    expect(ws.state).toBe('absent')
    expect(ws.filters).toBe(0)
  })

  it('async twins: real-spawn parity with sync (status + dependency check)', async () => {
    // No spies — this drives the real srt-win.exe via spawn() and
    // spawnSync() and asserts the async result equals the sync one.
    const sl = '11111111-2222-3333-4444-555555555555'
    expect(
      await getWindowsWfpStatusAsync({
        sublayerGuid: sl,
        srtWin: TEST_SRT_WIN,
      }),
    ).toEqual(getWindowsWfpStatus({ sublayerGuid: sl, srtWin: TEST_SRT_WIN }))
    expect(
      await getWindowsSandboxUserStatusAsync({ srtWin: TEST_SRT_WIN }),
    ).toEqual(getWindowsSandboxUserStatus({ srtWin: TEST_SRT_WIN }))
    expect(
      await checkWindowsDependenciesAsync({
        sublayerGuid: sl,
        srtWin: TEST_SRT_WIN,
      }),
    ).toEqual(
      checkWindowsDependencies({ sublayerGuid: sl, srtWin: TEST_SRT_WIN }),
    )
  }, 30_000)

  // The non-elevated readiness check that initialize() runs.
  // Hermetic sublayer + full-uninstall in finally so the
  // round-trips test below starts from an unprovisioned state.
  it('verifyWindowsWfpEgress: blocked after install; throws after uninstall --keep-user', async () => {
    const sl = '6a1e0f80-2b3c-4d5e-9f8a-1b2c3d4e5f60'
    installWindowsSandbox({
      ...SUITE_INSTALL,
      sublayerGuid: sl,
      proxyPortRange: PORT_RANGE,
      srtWin: TEST_SRT_WIN,
    })
    try {
      // Fence active: WFP block-user filter fires at
      // ALE_AUTH_CONNECT before any packet leaves → WSAEACCES. The
      // probe binds a local out-of-range loopback listener; no
      // external host involved.
      const v = await verifyWindowsWfpEgress({
        proxyPortRange: PORT_RANGE,
        srtWin: TEST_SRT_WIN,
      })
      expect(v.target).toMatch(/^127\.0\.0\.1:\d+$/)
      // Filters removed, sandbox user kept → fence inactive →
      // throws. This is the throw initialize() relays when a stale
      // install (user provisioned, filters since removed) would
      // otherwise run every exec with full egress. The regex
      // matches both the exit-3 (`is not active`) and exit-2
      // (`could not be verified`) messages — either is correct
      // fail-closed behaviour.
      uninstallWindowsSandbox({
        ...SUITE_INSTALL,
        sublayerGuid: sl,
        keepUser: true,
        srtWin: TEST_SRT_WIN,
      })
      // eslint-disable-next-line @typescript-eslint/await-thenable -- bun:test types .rejects.toThrow() as void; the await is required at runtime
      await expect(
        verifyWindowsWfpEgress({
          proxyPortRange: PORT_RANGE,
          srtWin: TEST_SRT_WIN,
        }),
      ).rejects.toThrow(/WFP egress fence/i)
    } finally {
      uninstallWindowsSandbox({
        ...SUITE_INSTALL,
        sublayerGuid: sl,
        srtWin: TEST_SRT_WIN,
      })
    }
  }, 60_000)

  it('installWindowsSandbox round-trips user + wfp under a fresh sublayer', () => {
    // The runner is admin (precondition asserted by smoke-exec.ps1),
    // so srt-win install runs without a UAC prompt and `cancelled`
    // is never set.
    const sl = '8d2f1e91-4b3c-5a6e-af9d-2e3f4a5b6c7d'
    try {
      const r = installWindowsSandbox({
        ...SUITE_INSTALL,
        sublayerGuid: sl,
        proxyPortRange: PORT_RANGE,
        srtWin: TEST_SRT_WIN,
      })
      expect(r.cancelled).toBeUndefined()
      expect(r.wfp.state).toBe('installed')
      expect(r.wfp.filters).toBeGreaterThanOrEqual(4)
      expect(r.wfp.portRange).toEqual([PORT_RANGE[0], PORT_RANGE[1]])
      // Sandbox user provisioned alongside the WFP.
      expect(r.user.provisioned).toBe(true)
      expect(r.user.sid).toMatch(/^S-1-5-21-/)
      expect(r.user.groupExists).toBe(true)
      expect(r.user.inBuiltinUsers).toBe(true)
      expect(r.user.inSandboxGroup).toBe(true)
      expect(r.user.credPresent).toBe(true)
      // Keep in sync with SETUP_VERSION (vendor/srt-win-src/src/install.rs).
      expect(r.user.markerVersion).toBe(3)
      expect(r.user.setupVersion).toBe(3)
      expect(r.wfp.userSid).toBe(r.user.sid)
      // Combined `srt-win status` returns the same objects the two
      // per-noun calls do (one spawn instead of two).
      const c = checkWindowsSandboxStatus({
        sublayerGuid: sl,
        srtWin: TEST_SRT_WIN,
      })
      expect(c.wfp).toEqual(
        getWindowsWfpStatus({ sublayerGuid: sl, srtWin: TEST_SRT_WIN }),
      )
      expect(c.user).toEqual(
        getWindowsSandboxUserStatus({ srtWin: TEST_SRT_WIN }),
      )
      // Idempotent re-run with the SAME config also succeeds.
      const r2 = installWindowsSandbox({
        ...SUITE_INSTALL,
        sublayerGuid: sl,
        proxyPortRange: PORT_RANGE,
        srtWin: TEST_SRT_WIN,
      })
      expect(r2.cancelled).toBeUndefined()
      expect(r2.wfp.state).toBe('installed')
    } finally {
      uninstallWindowsSandbox({
        ...SUITE_INSTALL,
        sublayerGuid: sl,
        srtWin: TEST_SRT_WIN,
      })
    }
    expect(
      getWindowsWfpStatus({ sublayerGuid: sl, srtWin: TEST_SRT_WIN }).state,
    ).toBe('absent')
    const u = getWindowsSandboxUserStatus({ srtWin: TEST_SRT_WIN })
    expect(u.provisioned).toBe(false)
    expect(u.credPresent).toBe(false)
    expect(u.markerVersion).toBeUndefined()
  })

  it('installWindowsSandbox refuses different-config without force (exit 13)', () => {
    const sl = '9e3a2fa2-5c4d-6b7f-ba0e-3f4a5b6c7d8e'
    try {
      installWindowsSandbox({
        ...SUITE_INSTALL,
        sublayerGuid: sl,
        proxyPortRange: PORT_RANGE,
        srtWin: TEST_SRT_WIN,
      })
      // Re-install with a DIFFERENT port range under the same
      // sublayer without force → exit 13 → throw with a stable
      // .code (message text is diagnostic and may change).
      let err: unknown
      try {
        installWindowsSandbox({
          ...SUITE_INSTALL,
          sublayerGuid: sl,
          proxyPortRange: [PORT_RANGE[0], PORT_RANGE[0] + 1],
          srtWin: TEST_SRT_WIN,
        })
      } catch (e) {
        err = e
      }
      expect(err).toBeInstanceOf(WindowsSandboxError)
      expect((err as WindowsSandboxError).code).toBe('install_config_conflict')
      // With force → succeeds and replaces.
      const r = installWindowsSandbox({
        ...SUITE_INSTALL,
        sublayerGuid: sl,
        proxyPortRange: [PORT_RANGE[0], PORT_RANGE[0] + 1],
        force: true,
        srtWin: TEST_SRT_WIN,
      })
      expect(r.wfp.portRange).toEqual([PORT_RANGE[0], PORT_RANGE[0] + 1])
    } finally {
      uninstallWindowsSandbox({
        ...SUITE_INSTALL,
        sublayerGuid: sl,
        srtWin: TEST_SRT_WIN,
      })
    }
  })

  it('initialize() throws when sandbox user is not provisioned', async () => {
    // After the previous uninstall, the user is absent.
    // eslint-disable-next-line @typescript-eslint/await-thenable -- bun:test types .rejects.toThrow() as void; the await is required at runtime
    await expect(SandboxManager.initialize(createTestConfig())).rejects.toThrow(
      /sandbox user is not provisioned.*windows-install/is,
    )
    await SandboxManager.reset()
  })

  it('initialize() with filesystem.denyRead applies the DENY ACE', async () => {
    // Re-provision so the not-provisioned gate doesn't fire first.
    installWindowsSandbox({
      ...SUITE_INSTALL,
      sublayerGuid: TEST_SUBLAYER,
      proxyPortRange: PORT_RANGE,
      srtWin: TEST_SRT_WIN,
    })
    const scratch = mkdtempSync(join(tmpdir(), 'srt-fsdeny-'))
    const f = join(scratch, 'secret.txt')
    writeFileSync(f, 'x')
    try {
      const cfg = createTestConfig()
      cfg.filesystem.denyRead = [f]
      await SandboxManager.initialize(cfg)
      // The DENY-ACE mechanism is now wired (no longer throws); the
      // actual deny enforcement is covered by H6. Here we just
      // assert the lifecycle (initialize → reset) round-trips.
      await SandboxManager.reset()
    } finally {
      rmSync(scratch, { recursive: true, force: true })
      // Leave the install in place for the network describe below.
    }
    // 60s: install + initialize() runs verifyWindowsWfpEgress(); first
    // call after a fresh user-provision creates the seclogon profile
    // (~8s on the CI runner), same budget as the verify test above.
  }, 60_000)

  it('initialize() verifies the fence under the write-restricted token and exec carries the flag', async () => {
    installWindowsSandbox({
      ...SUITE_INSTALL,
      sublayerGuid: TEST_SUBLAYER,
      proxyPortRange: PORT_RANGE,
      srtWin: TEST_SRT_WIN,
    })
    await SandboxManager.initialize(createTestConfig())
    try {
      const { argv, env } =
        await SandboxManager.wrapWithSandboxArgv('echo WR-TOKEN-OK')
      expect(argv).toContain('--write-restricted-token')
      expect(argv.indexOf('--write-restricted-token')).toBeLessThan(
        argv.indexOf('--'),
      )
      const envArgs = argv.filter((_, i) => argv[i - 1] === '--env')
      const backendKey = envArgs.find(e => e.endsWith('=http.sslBackend'))
      expect(backendKey).toMatch(/^GIT_CONFIG_KEY_\d+=http\.sslBackend$/)
      expect(envArgs).toContain(
        `${backendKey!.split('=')[0].replace('KEY', 'VALUE')}=openssl`,
      )
      const r = await spawnAsync(argv[0], argv.slice(1), {
        timeout: 60_000,
        env,
      })
      expectStatus('write-restricted echo', r, [0])
      expect(r.stdout).toContain('WR-TOKEN-OK')
    } finally {
      await SandboxManager.reset()
    }
  }, 120_000)

  it('a write root is writable to its own session only and readable from any, is kept at reset(), and is removed by acl forget --all', async () => {
    installWindowsSandbox({
      ...SUITE_INSTALL,
      sublayerGuid: TEST_SUBLAYER,
      proxyPortRange: PORT_RANGE,
      srtWin: TEST_SRT_WIN,
    })
    // Long-form paths: the sandbox account cannot resolve an 8.3 component.
    const rootA = realpathSync.native(mkdtempSync(join(tmpdir(), 'srt-wr-a-')))
    const rootB = realpathSync.native(mkdtempSync(join(tmpdir(), 'srt-wr-b-')))
    const withRoots = (roots: string[]): SandboxRuntimeConfig => {
      const cfg = createTestConfig()
      cfg.filesystem.allowWrite = roots
      return cfg
    }
    const write = async (file: string): Promise<boolean> => {
      const { argv, env } = await SandboxManager.wrapWithSandboxArgv(
        `echo X> "${file}"`,
      )
      await spawnAsync(argv[0], argv.slice(1), { timeout: 60_000, env })
      return existsSync(file)
    }
    const read = async (file: string): Promise<string> =>
      (await runSandboxed(`type "${file}"`)).stdout
    const kept = () =>
      getWindowsSandboxUserStatus({ srtWin: TEST_SRT_WIN }).persistentGrants
    try {
      writeFileSync(join(rootA, 'seed.txt'), 'SEED-IN-A')
      writeFileSync(join(rootB, 'seed.txt'), 'SEED-IN-B')
      await SandboxManager.initialize(withRoots([rootA]))
      expect(await write(join(rootA, 'own.txt'))).toBe(true)
      await SandboxManager.reset()
      // The grant outlives the session.
      expect(kept()?.state).toBe('present')
      expect(kept()?.roots).toHaveLength(1)

      // A session given only B cannot write A, which keeps its grant.
      await SandboxManager.initialize(withRoots([rootB]))
      expect(await write(join(rootB, 'own.txt'))).toBe(true)
      expect(await write(join(rootA, 'from-b.txt'))).toBe(false)
      expect(await read(join(rootA, 'seed.txt'))).toContain('SEED-IN-A')
      await SandboxManager.reset()
      expect(kept()?.roots).toHaveLength(2)

      const forget = spawnSync(
        TEST_SRT_WIN!.exe,
        [...TEST_SRT_WIN!.prependArgs, 'acl', 'forget', '--all'],
        { encoding: 'utf8', timeout: 120_000 },
      )
      expect(forget.status).toBe(0)
      expect(kept()).toBeUndefined()
      // With the grants gone, no session's token writes or reads A.
      await SandboxManager.initialize(withRoots([rootB]))
      expect(await write(join(rootA, 'after.txt'))).toBe(false)
      expect(await read(join(rootA, 'seed.txt'))).not.toContain('SEED-IN-A')
    } finally {
      await SandboxManager.reset()
      rmSync(rootA, { recursive: true, force: true })
      rmSync(rootB, { recursive: true, force: true })
    }
  }, 240_000)

  it('an install of the previous setup version: nothing is granted or run until the install is re-run, which upgrades it in place', async () => {
    installWindowsSandbox({
      ...SUITE_INSTALL,
      sublayerGuid: TEST_SUBLAYER,
      proxyPortRange: PORT_RANGE,
      srtWin: TEST_SRT_WIN,
    })
    const root = realpathSync.native(mkdtempSync(join(tmpdir(), 'srt-v2-')))
    const cfg = createTestConfig()
    cfg.filesystem.allowWrite = [root]
    const status = () => getWindowsSandboxUserStatus({ srtWin: TEST_SRT_WIN })
    const current = status().setupVersion!
    // What a release with the previous setup version leaves behind.
    const setMarker = (v: number) => {
      const r = spawnSync(
        'reg',
        [
          'add',
          'HKLM\\SOFTWARE\\sandbox-runtime',
          '/v',
          'MarkerVersion',
          '/t',
          'REG_DWORD',
          '/d',
          `${v}`,
          '/f',
          '/reg:64',
        ],
        { encoding: 'utf8', timeout: 10_000 },
      )
      if (r.status !== 0) throw new Error(`reg add: ${r.stderr || r.stdout}`)
    }
    setMarker(current - 1)
    try {
      expect(status().markerVersion).toBe(current - 1)
      const deps = await checkWindowsDependenciesAsync({
        sublayerGuid: TEST_SUBLAYER,
        srtWin: TEST_SRT_WIN,
      })
      expect(deps.errors).toHaveLength(1)
      expect(deps.errors[0]).toMatch(/Re-run the install/)
      expect(deps.errors[0]).not.toMatch(/not provisioned/i)
      // eslint-disable-next-line @typescript-eslint/await-thenable -- bun:test types .rejects.toThrow() as void; the await is required at runtime
      await expect(SandboxManager.initialize(cfg)).rejects.toThrow(
        /Re-run the install/,
      )
      await SandboxManager.reset()
      // Roots other rows kept are not this row's business.
      const keptBefore = status().persistentGrants?.roots ?? []
      const grant = spawnSync(
        TEST_SRT_WIN!.exe,
        [
          ...TEST_SRT_WIN!.prependArgs,
          'acl',
          'grant',
          '--holder-pid',
          `${process.pid}`,
          '--sandbox-user-sid',
          status().sid!,
          '--persistent',
        ],
        {
          encoding: 'utf8',
          timeout: 60_000,
          input: JSON.stringify({
            read: [],
            write: [root],
            denyRead: [],
            denyWrite: [],
          }),
        },
      )
      expect(grant.status).toBe(15)
      expect(grant.stderr).toMatch(/re-run `srt-win install`/)
      expect(status().persistentGrants?.roots ?? []).toEqual(keptBefore)
      {
        const { argv, env } = wrapCommandWithSandboxWindows({
          command: 'echo V2-RAN',
          quiet: false,
          srtWin: TEST_SRT_WIN,
        })
        // The broker holds the same line with and without the token flag.
        for (const a of [
          argv,
          argv.filter(x => x !== '--write-restricted-token'),
        ]) {
          const r = await spawnAsync(a[0], a.slice(1), { timeout: 60_000, env })
          expect(r.status).toBe(15)
          expect(r.stdout).not.toContain('V2-RAN')
          expect(r.stderr).toMatch(/re-run `srt-win install`/)
        }
      }

      // The repair: the same install command, which upgrades in place.
      const r = installWindowsSandbox({
        ...SUITE_INSTALL,
        sublayerGuid: TEST_SUBLAYER,
        proxyPortRange: PORT_RANGE,
        srtWin: TEST_SRT_WIN,
      })
      expect(r.user.markerVersion).toBe(current)
      await SandboxManager.initialize(cfg)
      const ran = await runSandboxed(`echo X> "${join(root, 'after.txt')}"`)
      expectStatus('after the upgrade', ran, [0])
      expect(existsSync(join(root, 'after.txt'))).toBe(true)
    } finally {
      await SandboxManager.reset()
      if (status().markerVersion !== current) setMarker(current)
      rmSync(root, { recursive: true, force: true })
    }
  }, 240_000)
})

describe.if(isWindows)('Windows sandbox: SandboxManager network', () => {
  let sbSid: string

  beforeAll(async () => {
    // Checkpoints to stderr (flushed synchronously) so that if the
    // runtime faults mid-setup the LAST line in the CI log
    // localizes the faulting step.
    console.error('[winsrt beforeAll] start')
    // Full install under the test sublayer — provisions
    // srt-sandbox + cred + user-SID WFP filters. Idempotent (the
    // helpers describe above may have left it installed).
    console.error('[winsrt beforeAll] install: begin')
    const r = installWindowsSandbox({
      ...SUITE_INSTALL,
      sublayerGuid: TEST_SUBLAYER,
      proxyPortRange: PORT_RANGE,
      srtWin: TEST_SRT_WIN,
    })
    if (!r.user.provisioned || !r.user.sid || !r.user.credPresent) {
      throw new Error(
        `srt-sandbox not provisioned after install: ${JSON.stringify(r.user)}`,
      )
    }
    sbSid = r.user.sid
    console.error('[winsrt beforeAll] install: done')
    expect(r.wfp.state).toBe('installed')
    expect(r.wfp.portRange).toEqual([PORT_RANGE[0], PORT_RANGE[1]])

    console.error('[winsrt beforeAll] SandboxManager.initialize: begin')
    await SandboxManager.initialize(createTestConfig())
    console.error('[winsrt beforeAll] done')
    // Install and uninstall each run an elevated srt-win that can outlast
    // bun's 5s default hook timeout; a hook that times out is killed
    // mid-run and fails the suite.
  }, 120_000)

  afterAll(async () => {
    await SandboxManager.reset()
    uninstallWindowsSandbox({
      ...SUITE_INSTALL,
      sublayerGuid: TEST_SUBLAYER,
      srtWin: TEST_SRT_WIN,
    })
  }, 60_000)

  it('wrapWithSandbox() throws on Windows (use wrapWithSandboxArgv)', async () => {
    // eslint-disable-next-line @typescript-eslint/await-thenable -- bun:test types .rejects.toThrow() as void; the await is required at runtime
    await expect(SandboxManager.wrapWithSandbox('echo hi')).rejects.toThrow(
      /wrapWithSandboxArgv/,
    )
  })

  it('wrapWithSandboxArgv returns argv carrying the --env overlay', async () => {
    const { argv } = await SandboxManager.wrapWithSandboxArgv('echo hi')
    expect(argv[0]).toMatch(/srt-win\.exe$/i)
    expect(argv).toContain('exec')
    // Proxy ports ride as --env KEY=VALUE pairs to the runner.
    const envArgs = argv.filter((_, i) => argv[i - 1] === '--env')
    const httpProxy = envArgs.find(e => e.startsWith('http_proxy='))
    const allProxy = envArgs.find(e => e.startsWith('all_proxy='))
    expect(httpProxy).toMatch(/^http_proxy=http:\/\/.+:\d+$/)
    expect(allProxy).toMatch(/^all_proxy=http:\/\/.+:\d+$/)
    expect(
      repeatedIgnoringCase(envArgs.map(e => e.slice(0, e.indexOf('=')))),
    ).toEqual([])
    const httpPort = Number(httpProxy!.split(':').pop())
    expect(httpPort).toBeGreaterThanOrEqual(PORT_RANGE[0])
    expect(httpPort).toBeLessThanOrEqual(PORT_RANGE[1])
    // The FULL set rides along, not just the standard trio.
    expect(envArgs.some(e => e.startsWith('DOCKER_HTTP_PROXY='))).toBe(true)
    // Last element is the user's command, passed verbatim to cmd /c.
    expect(argv.slice(-4)).toEqual(['/d', '/s', '/c', 'echo hi'])
  })

  it('proxy ports match what SandboxManager reports', () => {
    const httpPort = SandboxManager.getProxyPort()
    const socksPort = SandboxManager.getSocksProxyPort()
    expect(httpPort).toBeGreaterThanOrEqual(PORT_RANGE[0])
    expect(httpPort).toBeLessThanOrEqual(PORT_RANGE[1])
    expect(socksPort).toBeGreaterThanOrEqual(PORT_RANGE[0])
    expect(socksPort).toBeLessThanOrEqual(PORT_RANGE[1])
  })

  // ════════════════════════════════════════════════════════════════
  // Group H — two-hop launch fundamentals
  // ════════════════════════════════════════════════════════════════

  it('H1: child runs as srt-sandbox (different user SID)', async () => {
    const r = await runSandboxed('whoami /user /FO CSV /NH')
    expectStatus('H1', r, [0])
    expect(r.stdout).toContain(sbSid)
  }, 60_000)

  it('H2: stdout marker pipes through runner to broker', async () => {
    const r = await runSandboxed('echo H2-STDOUT-MARK')
    expectStatus('H2', r, [0])
    expect(r.stdout).toContain('H2-STDOUT-MARK')
  }, 60_000)

  it('H3: USERPROFILE isolated to srt-sandbox', async () => {
    const r = await runSandboxed('echo %USERPROFILE%')
    expectStatus('H3', r, [0])
    expect(r.stdout.toLowerCase()).toContain('srt-sandbox')
  }, 60_000)

  // ════════════════════════════════════════════════════════════════
  // Group N — one name per variable in the child's environment
  // ════════════════════════════════════════════════════════════════

  it('N1: no name is in the child environment twice ignoring case', async () => {
    const r = await runSandboxed('set')
    expectStatus('N1', r, [0])
    const names = namesInSetOutput(r.stdout)
    expect(repeatedIgnoringCase(names)).toEqual([])
    for (const name of [
      'http_proxy',
      'https_proxy',
      'all_proxy',
      'grpc_proxy',
      'ftp_proxy',
      'RSYNC_PROXY',
    ]) {
      expect(names).toContain(name)
    }
  }, 60_000)

  it('N2: clearing a proxy variable clears it', async () => {
    const r = await runSandboxed(
      'set "HTTPS_PROXY=" & set https_proxy & echo N2-DONE',
    )
    expect(r.stdout).toContain('N2-DONE')
    expect(r.stdout).not.toMatch(/^https_proxy=/im)
  }, 60_000)

  it('N3: .NET can load the child environment', async () => {
    const r = await runSandboxed(
      'powershell -NoProfile -Command "(New-Object System.Diagnostics.ProcessStartInfo).EnvironmentVariables.Count"',
      120_000,
    )
    expectStatus('N3', r, [0])
    expect(r.stdout.trim()).toMatch(/^\d+$/)
  }, 150_000)

  it('N4: Start-Process -RedirectStandardOutput starts its command', async () => {
    const r = await runSandboxed(
      `powershell -NoProfile -Command "$o = Join-Path $env:TEMP 'srt-n4-out.txt'; Start-Process cmd -ArgumentList '/c','echo N4-OK' -RedirectStandardOutput $o -Wait -NoNewWindow; Get-Content $o; Remove-Item $o"`,
      120_000,
    )
    if (!r.stdout.includes('N4-OK')) {
      throw new Error(
        `N4: redirected output not found · status=${r.status} · ` +
          `stdout=${JSON.stringify(r.stdout)} · stderr=${JSON.stringify(r.stderr.slice(-2000))}`,
      )
    }
  }, 150_000)

  // ════════════════════════════════════════════════════════════════
  // Group B — egress via real tools (allowed → reaches host via proxy)
  // ════════════════════════════════════════════════════════════════
  // Each row that needs hosts beyond example.com calls updateConfig()
  // first: the JS proxy's filter reads config.network.allowedDomains
  // live, so the allowlist changes without rebinding the proxies.

  // TLS rows use `ownTlsGet`: Schannel curl fails under the default token.
  it.skipIf(!HAS_OWN_TLS_CLIENT)(
    'B1: a client with its own TLS stack reaches an allowedDomains host → 200 via proxy',
    async () => {
      SandboxManager.updateConfig(createTestConfig(['example.com']))
      const r = await runSandboxedUntil(ownTlsGet('example.com'), got200)
      expectStatus('B1', r, [0])
      expect(got200(r)).toBe(true)
    },
    90_000,
  )

  it('N1: System32 curl (Schannel) gets no response from an allowed host under the default token', async () => {
    SandboxManager.updateConfig(createTestConfig(['example.com']))
    if (HAS_OWN_TLS_CLIENT) {
      const ok = await runSandboxedUntil(ownTlsGet('example.com'), got200)
      expectStatus('N1 control', ok, [0])
    }
    // Not retried: curl fails with no HTTP status to report.
    const r = await runSandboxed(
      `"${SYSTEM32_CURL}" -sS -m 15 -o NUL -w "%{http_code}" https://example.com/`,
    )
    console.error(
      `[winsrt N1] exit=${r.status} stdout=${JSON.stringify(r.stdout)} ` +
        `stderr=${JSON.stringify(r.stderr)}`,
    )
    expect(r.status).not.toBe(0)
    expect(r.stdout.trim()).toBe('000')
  }, 120_000)

  it.skipIf(!HAS_OWN_TLS_CLIENT)(
    'B2: a NON-allowed host is refused by the proxy, from a client that reaches an allowed one',
    async () => {
      SandboxManager.updateConfig(createTestConfig(['example.com']))
      const allowed = await runSandboxedUntil(ownTlsGet('example.com'), got200)
      expect(got200(allowed)).toBe(true)
      const r = await runSandboxed(ownTlsGet('google.com'))
      expect(r.status).not.toBe(0)
      expect(got200(r)).toBe(false)
      // The proxy's own refusal, not a client that failed otherwise.
      expect(r.stderr + r.stdout).toMatch(/CONNECT:403|\b403\b/)
    },
    120_000,
  )

  it.skipIf(!HAS_OWN_TLS_CLIENT)(
    'B3: a SECOND allowed host (github.com) → 200',
    async () => {
      SandboxManager.updateConfig(
        createTestConfig(['example.com', 'github.com']),
      )
      const r = await runSandboxedUntil(ownTlsGet('github.com'), got200)
      expectStatus('B3', r, [0])
      expect(got200(r)).toBe(true)
    },
    90_000,
  )

  it.skipIf(!hasTool('node'))(
    'B5: node https.get direct egress is BLOCKED (proxy env not honoured)',
    async () => {
      // An agent of the script's own reads no proxy variable: a DIRECT connect.
      SandboxManager.updateConfig(createTestConfig(['example.com']))
      const r = await runSandboxed(
        `node -e "const s=Date.now();const h=require('https');h.get('https://example.com',{agent:new h.Agent()},r=>{console.log('OK:'+r.statusCode);process.exit(0)}).on('error',e=>{console.log('ERR:'+e.code);process.exit(1)});setTimeout(()=>{console.log('TIMEOUT');process.exit(2)},6000)"`,
      )
      expect(r.stdout.startsWith('OK:')).toBe(false)
    },
    60_000,
  )

  it.skipIf(!nodeReadsProxyEnv())(
    'B6: node https.get to an allowedDomains host → 200 via proxy (NODE_USE_ENV_PROXY)',
    async () => {
      SandboxManager.updateConfig(createTestConfig(['example.com']))
      const r = await runSandboxedUntil(
        `node -e "const s=Date.now();require('https').get('https://example.com',r=>{console.log('OK:'+r.statusCode);process.exit(0)}).on('error',e=>{console.log('ERR:'+e.code);process.exit(1)});setTimeout(()=>{console.log('TIMEOUT');process.exit(2)},6000)"`,
        x => x.stdout.trim() === 'OK:200',
      )
      expectStatus('B6', r, [0])
      expect(r.stdout.trim()).toBe('OK:200')
    },
    90_000,
  )

  it.skipIf(!nodeReadsProxyEnv())(
    'B7: node fetch to an allowedDomains host → 200 via proxy (NODE_USE_ENV_PROXY)',
    async () => {
      SandboxManager.updateConfig(createTestConfig(['example.com']))
      const r = await runSandboxedUntil(
        `node -e "fetch('https://example.com').then(r=>{console.log('OK:'+r.status);process.exit(0)},e=>{console.log('ERR:'+e.message);process.exit(1)});setTimeout(()=>{console.log('TIMEOUT');process.exit(2)},15000)"`,
        x => x.stdout.trim() === 'OK:200',
      )
      expectStatus('B7', r, [0])
      expect(r.stdout.trim()).toBe('OK:200')
    },
    90_000,
  )

  it.skipIf(!nodeReadsProxyEnv())(
    'B8: with NODE_USE_ENV_PROXY cleared in the command, node fetch goes direct → BLOCKED',
    async () => {
      // The runner hands the child a `*_PROXY` name in both cases, and
      // `set "NAME="` removes one entry: both are cleared.
      SandboxManager.updateConfig(createTestConfig(['example.com']))
      const r = await runSandboxed(
        `set "NODE_USE_ENV_PROXY=" & set "node_use_env_proxy=" & node -e "console.log('ENV:'+(process.env.NODE_USE_ENV_PROXY===undefined?'unset':process.env.NODE_USE_ENV_PROXY)+' NODE:'+process.version);fetch('https://example.com').then(r=>{console.log('OK:'+r.status);process.exit(0)},e=>{console.log('ERR:'+e.message);process.exit(1)});setTimeout(()=>{console.log('TIMEOUT');process.exit(2)},8000)"`,
      )
      // The premise first: node must have started without the variable.
      if (!/^ENV:unset NODE:v\d+/m.test(r.stdout)) {
        throw new Error(
          `B8: the variable was not cleared for node · status=${r.status} · ` +
            `stdout=${JSON.stringify(r.stdout)} · stderr=${JSON.stringify(r.stderr.slice(-2000))}`,
        )
      }
      expect(r.stdout).not.toMatch(/^OK:/m)
    },
    60_000,
  )

  // ════════════════════════════════════════════════════════════════
  // Group C — direct-egress / bypass resistance
  // ════════════════════════════════════════════════════════════════

  it('C1: powershell Test-NetConnection 1.1.1.1:80 → blocked at WFP', async () => {
    SandboxManager.updateConfig(createTestConfig(['example.com']))
    const r = await runSandboxed(
      `powershell -NoProfile -Command "$ErrorActionPreference='SilentlyContinue'; (Test-NetConnection 1.1.1.1 -Port 80 -WarningAction SilentlyContinue).TcpTestSucceeded"`,
    )
    expect(r.stdout.trim().toLowerCase()).not.toBe('true')
  }, 60_000)

  it('C4: curl --noproxy "*" strips env → WFP still BLOCKS', async () => {
    // KEY: clearing the proxy env makes curl attempt direct egress;
    // WFP must still refuse it. Pairs with B5 as the "env-var bypass
    // doesn't defeat WFP" proof.
    SandboxManager.updateConfig(createTestConfig(['example.com']))
    // Plain HTTP: a TLS failure must not stand in for the fence.
    const r = await runSandboxed(
      'curl --noproxy "*" -sS -m 5 -o NUL -w "%{http_code}" http://example.com/',
    )
    expectEgressBlocked('C4', r)
    expect(r.stdout.trim()).not.toBe('200')
  }, 60_000)

  it.skipIf(!hasTool('node'))(
    'C5: node raw socket to 1.1.1.1:80 → not CONNECTED',
    async () => {
      SandboxManager.updateConfig(createTestConfig(['example.com']))
      const r = await runSandboxed(
        `node -e "const s=require('net').connect(80,'1.1.1.1');s.setTimeout(4000);s.on('connect',()=>{console.log('CONNECTED');process.exit(0)});s.on('error',e=>{console.log('ERR:'+e.code);process.exit(1)});s.on('timeout',()=>{console.log('TIMEOUT');process.exit(2)})"`,
      )
      expect(r.stdout.includes('CONNECTED')).toBe(false)
    },
    60_000,
  )

  // ── loopback port-range fence ────────────────────────────────────

  it('C6: child reaches an IN-range loopback port (loopback PERMIT)', async () => {
    const httpP = SandboxManager.getProxyPort()
    const socksP = SandboxManager.getSocksProxyPort()
    const candidates: number[] = []
    for (let p = PORT_RANGE[1]; p >= PORT_RANGE[0]; p--) {
      if (p !== httpP && p !== socksP) candidates.push(p)
    }
    const l = await bindFirstFree(candidates)
    try {
      const r = await runSandboxed(
        `curl -sS -m 5 -o NUL -w "%{http_code}" --noproxy "*" http://127.0.0.1:${l.port}`,
      )
      expectStatus('C6', r, [0])
    } finally {
      await l.close()
    }
  }, 60_000)

  it('C7: child BLOCKED from an OUT-of-range loopback port', async () => {
    const l = await bindOutOfRange()
    try {
      expect(l.port < PORT_RANGE[0] || l.port > PORT_RANGE[1]).toBe(true)
      const r = await runSandboxed(
        `curl -sS -m 5 -o NUL -w "%{http_code}" --noproxy "*" http://127.0.0.1:${l.port}`,
      )
      expectEgressBlocked('C7', r)
    } finally {
      await l.close()
    }
  }, 60_000)

  // ════════════════════════════════════════════════════════════════
  // Group D — the proxy port is not an open relay
  // ════════════════════════════════════════════════════════════════

  it.skipIf(!hasTool('curl'))(
    'D2: host curl --socks5 to proxy is not an open relay (disallowed host refused)',
    async () => {
      const socksPort = SandboxManager.getSocksProxyPort()
      const token = SandboxManager.getProxyAuthToken()
      expect(socksPort).toBeGreaterThan(0)
      expect(token).toBeTruthy()

      // Drive curl through the SOCKS proxy to a LOCAL responder via
      // ASYNC spawn. spawnSync blocks bun's event loop, but the SOCKS
      // proxy runs IN this process — self-deadlock → timeout.
      const l = await listenOn(0)
      SandboxManager.updateConfig(createTestConfig(['127.0.0.1']))
      const socks = (host: string, withAuth = true): string[] => [
        '--socks5-hostname',
        withAuth
          ? `srt:${token}@127.0.0.1:${socksPort}`
          : `127.0.0.1:${socksPort}`,
        '-sS',
        '-m',
        '5',
        '-o',
        'NUL',
        '-w',
        '%{http_code}',
        host,
      ]
      try {
        // Host process WITHOUT the secret → refused at the SOCKS
        // handshake.
        const noAuth = await spawnAsync(
          'curl',
          socks(`http://127.0.0.1:${l.port}`, false),
          { timeout: 10_000 },
        )
        expect(noAuth.status).not.toBe(0)

        // Allowed dest reached THROUGH the proxy.
        const ok = await spawnAsync(
          'curl',
          socks(`http://127.0.0.1:${l.port}`),
          { timeout: 10_000 },
        )
        if (ok.stdout.trim() !== '200') {
          throw new Error(
            `D2 allowed: expected 200 · status=${ok.status} · ` +
              `stdout=${JSON.stringify(ok.stdout)} · ` +
              `stderr=${JSON.stringify(ok.stderr)}`,
          )
        }

        // Disallowed dest → refused by the filter PRE-DIAL.
        const blocked = await spawnAsync('curl', socks('https://google.com'), {
          timeout: 10_000,
        })
        expectEgressBlocked('D2 disallowed', blocked)
      } finally {
        await l.close()
      }
    },
  )

  // ════════════════════════════════════════════════════════════════
  // Group E — bash userland (gated; skip if absent)
  // ════════════════════════════════════════════════════════════════

  it.skipIf(!existsSync(GIT_BASH))(
    'E1: git-bash curl to an allowed host → 200',
    async () => {
      SandboxManager.updateConfig(createTestConfig(['example.com']))
      // Plain HTTP where Git Bash's curl is the Schannel build (ARM64).
      const scheme = GIT_BASH_CURL_HAS_OPENSSL ? 'https' : 'http'
      console.error(`[winsrt E1] ${scheme}`)
      const r = await runSandboxedUntil(
        `"${GIT_BASH}" -c "curl -s -m 15 -o /dev/null -w '%{http_code}' ${scheme}://example.com"`,
        x => x.stdout.trim() === '200',
      )
      expect(r.stdout.trim()).toBe('200')
    },
    90_000,
  )

  it.skipIf(!existsSync(GIT_BASH))(
    'E4: binShell=bash.exe — direct egress BLOCKED',
    async () => {
      SandboxManager.updateConfig(createTestConfig(['example.com']))
      const cmd = `curl --noproxy '*' -sS -m 5 https://example.com`
      const { argv, env } = await SandboxManager.wrapWithSandboxArgv(
        cmd,
        GIT_BASH,
      )
      expect(argv.slice(-3)).toEqual([GIT_BASH, '-c', cmd])
      const r = await spawnAsync(argv[0], argv.slice(1), {
        timeout: 60_000,
        env,
      })
      expectEgressBlocked('E4', r)
    },
    90_000,
  )

  it.skipIf(!existsSync(GIT_BASH))(
    'E5: binShell=bash.exe — &&, single-quote, pipe survive argv round-trip',
    async () => {
      const cmd = `printf '%s ' one && printf '%s' two | tr a-z A-Z`
      const { argv, env } = await SandboxManager.wrapWithSandboxArgv(
        cmd,
        GIT_BASH,
      )
      expect(argv.slice(-3)).toEqual([GIT_BASH, '-c', cmd])
      const r = await spawnAsync(argv[0], argv.slice(1), {
        timeout: 60_000,
        env,
      })
      expectStatus('E5', r, [0])
      expect(r.stdout.trim()).toBe('one TWO')
    },
    90_000,
  )

  it.skipIf(!existsSync(GIT_BASH))(
    'E6: git-bash sees one http_proxy, in lower case',
    async () => {
      const r = await runSandboxed(
        `"${GIT_BASH}" -c "/usr/bin/env | /usr/bin/grep -i '^http_proxy=' | /usr/bin/wc -l; /usr/bin/env | /usr/bin/grep -c '^http_proxy='"`,
      )
      expectStatus('E6', r, [0])
      expect(r.stdout.split(/\r?\n/).map(l => l.trim())).toEqual(['1', '1', ''])
    },
    90_000,
  )

  it.skipIf(!existsSync(GIT_BASH))(
    'E7: .NET started from git-bash can load its environment',
    async () => {
      const r = await runSandboxed(
        `"${GIT_BASH}" -c "powershell.exe -NoProfile -Command '(New-Object System.Diagnostics.ProcessStartInfo).EnvironmentVariables.Count'"`,
        120_000,
      )
      expectStatus('E7', r, [0])
      expect(r.stdout.trim()).toMatch(/^\d+$/)
    },
    150_000,
  )

  // `-O -`: an MSYS program handed `NUL` creates a FILE of that name instead.
  it.skipIf(!existsSync(MSYS2_WGET))(
    'E3: msys2 wget to an allowed host → 200',
    async () => {
      SandboxManager.updateConfig(createTestConfig(['example.com']))
      const r = await runSandboxed(
        `"${MSYS2_WGET}" -O - --server-response --timeout=15 https://example.com`,
      )
      if (!/HTTP\/[\d.]+ 200/.test(r.stderr + r.stdout)) {
        throw new Error(
          `E3 wget via proxy: no HTTP 200 seen · status=${r.status} · ` +
            `stderr=${JSON.stringify(r.stderr.slice(-2000))}`,
        )
      }
    },
    90_000,
  )

  // Group Z — the null device under the default child token

  /** Run `command` under `shell` in the sandbox; the output must be `want`. */
  async function nullDeviceRow(
    id: string,
    shell: string | undefined,
    command: string,
    want: string,
  ): Promise<void> {
    const sh = parseWindowsBinShell(shell)
    const host = await spawnAsync(sh.exe, [...sh.args, command], {
      timeout: 60_000,
      cwd: tmpdir(),
    })
    const raw = (label: string, r: RunResult): string =>
      `${label}: exit=${r.status} stdout=${JSON.stringify(r.stdout)} ` +
      `stderr=${JSON.stringify(r.stderr)}`
    if (host.status !== 0 || host.stdout.trim() !== want) {
      throw new Error(
        `${id}: the command does not work OUTSIDE the sandbox either, so ` +
          `this row says nothing about the child token · ${raw('unsandboxed', host)}`,
      )
    }
    const { argv, env } = await SandboxManager.wrapWithSandboxArgv(
      command,
      shell,
    )
    expect(argv).toContain('--write-restricted-token')
    expect(argv).not.toContain('--write-root')
    const r = await spawnAsync(argv[0], argv.slice(1), {
      timeout: 60_000,
      env,
    })
    console.error(`[winsrt ${id}] ${raw('sandboxed', r)}`)
    if (r.status !== 0 || r.stdout.trim() !== want) {
      throw new Error(
        `${id}: \`${command}\` under the default child token · ` +
          `${raw('sandboxed', r)} · ${raw('unsandboxed', host)}`,
      )
    }
  }

  it.skipIf(!existsSync(GIT_BASH))(
    'Z1: Git Bash — stdout redirected to /dev/null',
    () => nullDeviceRow('Z1', GIT_BASH, 'echo x > /dev/null && echo ok', 'ok'),
    90_000,
  )

  it.skipIf(!existsSync(GIT_BASH))(
    'Z2: Git Bash — stderr redirected to /dev/null',
    () =>
      nullDeviceRow(
        'Z2',
        GIT_BASH,
        'ls /nonexistent 2>/dev/null; echo done',
        'done',
      ),
    90_000,
  )

  it(
    'Z3: cmd — stdout redirected to NUL',
    () => nullDeviceRow('Z3', undefined, 'echo x > NUL && echo ok', 'ok'),
    90_000,
  )

  it(
    "Z4: PowerShell — 'x' | Out-File NUL",
    () => nullDeviceRow('Z4', 'powershell', "'x' | Out-File NUL; 'ok'", 'ok'),
    90_000,
  )

  it(
    "Z5: PowerShell — 'x' > $null",
    () => nullDeviceRow('Z5', 'powershell', "'x' > $null; 'ok'", 'ok'),
    90_000,
  )

  for (const [id, out] of [
    ['Z6', '/dev/null'],
    ['Z7', '-'],
  ] as const) {
    it.skipIf(!existsSync(MSYS2_WGET))(
      `${id}: msys2 wget -O ${out} to an allowed host → 200`,
      async () => {
        SandboxManager.updateConfig(createTestConfig(['example.com']))
        const r = await runSandboxed(
          `"${MSYS2_WGET}" -O ${out} --server-response --timeout=15 https://example.com`,
        )
        console.error(
          `[winsrt ${id}] exit=${r.status} stderr=${JSON.stringify(r.stderr.slice(-600))}`,
        )
        if (r.status !== 0 || !/HTTP\/[\d.]+ 200/.test(r.stderr + r.stdout)) {
          throw new Error(
            `${id}: wget -O ${out} under the default child token · ` +
              `exit=${r.status} · stdout=${JSON.stringify(r.stdout.slice(-2000))} · ` +
              `stderr=${JSON.stringify(r.stderr.slice(-2000))}`,
          )
        }
      },
      90_000,
    )
  }

  it.skipIf(!hasTool('nslookup'))(
    'C2: nslookup with explicit server → direct UDP 53 blocked',
    async () => {
      // nslookup does its OWN direct UDP-53 query (bypasses the DNS
      // Client service), so the child's token hits the WFP
      // block-user filter.
      // NOTE: this is the DIRECT-DNS path; resolution via getaddrinfo
      // (Dnscache) is a separate, documented residual — see R1 below.
      SandboxManager.updateConfig(createTestConfig(['example.com']))
      const r = await runSandboxed('nslookup example.com 1.1.1.1')
      // Don't lean on exit code (varies across Windows builds) or on
      // the generic "Address:" line (nslookup prints the SERVER's own
      // address before any answer). Assert the resolved-NAME answer
      // section is absent AND a failure signature is present.
      expect(r.stdout).not.toMatch(/Name:\s*example\.com/i)
      expect(r.stdout + r.stderr).toMatch(
        /timed out|can't find|no response|request to .* failed|server failed/i,
      )
    },
    20_000,
  )

  // ════════════════════════════════════════════════════════════════
  // Residual pins (documented Windows limitations — NOT bugs)
  // ════════════════════════════════════════════════════════════════
  // These fail loudly if a future change accidentally CLOSES a
  // documented residual.

  it.skipIf(!hasTool('node'))(
    'R1: DNS resolution via getaddrinfo/Dnscache is NOT fenced',
    async () => {
      // getaddrinfo → DNS Client service (NetworkService token) does
      // the wire query, so ALE_USER_ID never sees the child. The
      // child can therefore resolve ARBITRARY names (a DNS-exfil
      // channel) even for hosts it cannot connect to. Resolve a
      // non-allowlisted name to make the point.
      SandboxManager.updateConfig(createTestConfig(['example.com']))
      const r = await runSandboxed(
        `node -e "require('dns').lookup('google.com',(e,a)=>{console.log(e?'ERR:'+e.code:'OK:'+a);process.exit(e?1:0)})"`,
      )
      expect(r.stdout.startsWith('OK:')).toBe(true)
    },
    20_000,
  )

  it('R2: ICMP (ping) is NOT fenced', async () => {
    SandboxManager.updateConfig(createTestConfig(['example.com']))
    const r = await runSandboxed('ping -n 1 -w 3000 8.8.8.8')
    // ICMP doesn't traverse ALE_AUTH_CONNECT, so the design can't
    // fence it. A regression that DID start blocking ICMP would make
    // ping report "General failure" — assert we never see that.
    expect(r.stdout).not.toMatch(/General failure/i)
  }, 60_000)
})

describe.if(isWindows)(
  'Windows sandbox: two-hop sandbox-user launch (H-rows)',
  () => {
    let exe: string
    let sbSid: string

    beforeAll(() => {
      exe = suiteSrtWinPath()
      // Full install under the test sublayer — provisions
      // srt-sandbox + cred + user-SID WFP filters. Idempotent.
      const inst = spawnSync(
        exe,
        [
          'install',
          '--sublayer-guid',
          TEST_SUBLAYER,
          '--proxy-port-range',
          `${PORT_RANGE[0]}-${PORT_RANGE[1]}`,
        ],
        { encoding: 'utf8' },
      )
      if (inst.status !== 0) {
        throw new Error(`srt-win install failed: ${inst.stderr || inst.stdout}`)
      }
      if (SUITE_HAS_PROFILE) {
        const grant = spawnSync(exe, ['profile', 'grant', '--quiet'], {
          encoding: 'utf8',
        })
        if (grant.status !== 0) {
          throw new Error(
            `srt-win profile grant failed: ${grant.stderr || grant.stdout}`,
          )
        }
      }
      const us = getWindowsSandboxUserStatus({ srtWin: TEST_SRT_WIN })
      if (!us.provisioned || !us.sid || !us.credPresent) {
        throw new Error(
          `srt-sandbox not provisioned after install: ${JSON.stringify(us)}`,
        )
      }
      sbSid = us.sid
    }, 60_000)

    // 60s: `srt-win uninstall` removes the sandbox user account +
    // WFP filters and can exceed bun's 5s default hook timeout
    // when a runner child from a prior test is still draining.
    afterAll(() => {
      spawnSync(exe, ['uninstall', '--sublayer-guid', TEST_SUBLAYER], {
        encoding: 'utf8',
        timeout: 55_000,
      })
    }, 60_000)

    async function rexec(tail: string) {
      const { argv, env } = wrapCommandWithSandboxWindows({
        command: tail,
        srtWin: TEST_SRT_WIN,
      })
      return spawnAsync(argv[0], argv.slice(1), {
        env,
        timeout: 60_000,
      })
    }

    it('H1: child runs as srt-sandbox (different user SID)', async () => {
      const r = await rexec('whoami /user /FO CSV /NH')
      expect(r.status).toBe(0)
      expect(r.stdout).toContain(sbSid)
    }, 60_000)

    it('H2: stdout marker pipes through runner to broker', async () => {
      const r = await rexec('echo H2-STDOUT-MARK')
      expect(r.status).toBe(0)
      expect(r.stdout).toContain('H2-STDOUT-MARK')
    }, 60_000)

    it('H3: USERPROFILE isolated to srt-sandbox', async () => {
      const r = await rexec('echo %USERPROFILE%')
      expect(r.status).toBe(0)
      expect(r.stdout.toLowerCase()).toContain('srt-sandbox')
    }, 60_000)

    it('H4: direct outbound blocked by F-USER-BLOCK', async () => {
      const r = await rexec(
        'set "HTTP_PROXY=" & set "HTTPS_PROXY=" & set "ALL_PROXY=" & ' +
          'curl -sS -m 5 -o NUL -w "%{http_code}" http://example.com/',
      )
      // Plain HTTP, so any non-zero exit is the fence and not TLS.
      expect(r.status).not.toBe(0)
      expect(r.stdout.trim()).not.toBe('200')
    }, 60_000)

    it('H-kill-chain: taskkill /F on the broker reaps the sandboxed child (Job kill-on-close)', async () => {
      // Proves the broker→runner→child Job kill-chain survives a
      // hard broker kill. waitfor.exe blocks 30s for a signal that
      // never arrives; the nonce in its cmdline lets us find OUR
      // instance via CIM regardless of what else is on the runner.
      const nonce = `SrtKc${process.pid}x${Date.now()}`
      // quiet:false — the seclogon-job note in logon.rs is the
      // breadcrumb for the documented `AssignProcessToJobObject →
      // ERROR_NOT_SUPPORTED` degrade path; without it a flake here
      // has zero diagnostic.
      const { argv, env } = wrapCommandWithSandboxWindows({
        command: `waitfor /t 30 ${nonce}`,
        quiet: false,
        srtWin: TEST_SRT_WIN,
      })
      const broker = spawn(argv[0], argv.slice(1), { env })
      let stderr = ''
      broker.stdout?.on('data', () => {})
      broker.stderr?.setEncoding('utf8').on('data', d => (stderr += d))
      const closed = new Promise<void>(r => broker.once('close', () => r()))
      const findChild = (): number | undefined => {
        const r = spawnSync(
          'powershell',
          [
            '-NoProfile',
            '-Command',
            `(Get-CimInstance Win32_Process -Filter "Name='waitfor.exe'" | ` +
              `Where-Object { $_.CommandLine -like '*${nonce}*' }).ProcessId`,
          ],
          { encoding: 'utf8', timeout: 10_000 },
        )
        const pid = parseInt((r.stdout ?? '').trim(), 10)
        return Number.isFinite(pid) && pid > 0 ? pid : undefined
      }
      let childPid: number | undefined
      try {
        // Poll for the sandboxed waitfor.exe (up to ~15s: CPWLW +
        // profile load can be slow on a cold runner).
        for (let i = 0; i < 30 && childPid === undefined; i++) {
          await new Promise(r => setTimeout(r, 500))
          childPid = findChild()
        }
        if (childPid === undefined) {
          throw new Error(
            `H-kill-chain: sandboxed waitfor.exe (${nonce}) never appeared ` +
              `— broker.pid=${broker.pid} stderr=${JSON.stringify(stderr)}`,
          )
        }
        // Hard-kill the BROKER. The Job kill-chain (broker Job →
        // runner → runner Job → child) must reap the whole tree; a
        // surviving child would mean a broker crash orphans a
        // sandboxed process.
        const kill = spawnSync('taskkill', ['/PID', String(broker.pid), '/F'], {
          encoding: 'utf8',
          timeout: 10_000,
        })
        if (kill.status !== 0) {
          throw new Error(
            `taskkill /F broker(${broker.pid}) failed: ` +
              `${kill.stderr || kill.stdout}`,
          )
        }
        await closed
        for (let i = 0; i < 20; i++) {
          if (findChild() === undefined) {
            // Cleared so the finally's belt-and-suspenders taskkill
            // doesn't fire on a dead PID (which a busy runner may
            // have already reused).
            childPid = undefined
            return
          }
          await new Promise(r => setTimeout(r, 500))
        }
        throw new Error(
          `H-kill-chain: sandboxed child pid=${childPid} survived ` +
            `taskkill /F on broker(${broker.pid}) — Job kill-chain ` +
            `broken. stderr=${JSON.stringify(stderr)}`,
        )
      } finally {
        // Belt-and-suspenders reap so a failure doesn't leak the
        // child into the next test.
        if (childPid !== undefined) {
          spawnSync('taskkill', ['/PID', String(childPid), '/T', '/F'], {
            timeout: 5_000,
          })
        }
        broker.kill()
      }
    }, 90_000)

    describe('files', () => {
      // ── H5-H8: FS parity via SandboxManager (grant + deny ACEs) ──
      let hScratch: string
      let hSecret: string
      let hSibling: string

      type FsOverrides = Partial<SandboxRuntimeConfig['filesystem']>
      function createFsTestConfig(fs: FsOverrides): SandboxRuntimeConfig {
        const base = createTestConfig()
        return { ...base, filesystem: { ...base.filesystem, ...fs } }
      }

      async function rexecSandboxed(cmd: string, fs: FsOverrides) {
        await SandboxManager.initialize(createFsTestConfig(fs))
        try {
          const wrapped = await SandboxManager.wrapWithSandboxArgv(cmd)
          return await spawnAsync(wrapped.argv[0], wrapped.argv.slice(1), {
            env: wrapped.env,
            timeout: 60_000,
          })
        } finally {
          await SandboxManager.reset()
        }
      }

      it('H5: allowWrite grants the working tree — child reads sibling', async () => {
        hScratch = mkdtempSync(join(tmpdir(), 'srt-h-'))
        hSecret = join(hScratch, 'secret.txt')
        hSibling = join(hScratch, 'sibling.txt')
        writeFileSync(hSecret, 'SECRET')
        writeFileSync(hSibling, 'SIBLING')
        const r = await rexecSandboxed(`type "${hSibling}"`, {
          allowWrite: [hScratch],
        })
        if (r.status !== 0 || !r.stdout.includes('SIBLING')) {
          throw new Error(
            `H5: child read sibling under allowWrite tree failed — ` +
              `exit=${r.status} stderr=${JSON.stringify(r.stderr)} ` +
              `stdout=${JSON.stringify(r.stdout)}`,
          )
        }
      }, 90_000)

      it('H6: allowWrite + denyRead — secret denied, sibling readable', async () => {
        const r = await rexecSandboxed(
          `type "${hSecret}" & echo --SEP-- & type "${hSibling}"`,
          { allowWrite: [hScratch], denyRead: [hSecret] },
        )
        if (r.stdout.includes('SECRET')) {
          throw new Error(
            `H6: child read the denyRead target — ` +
              `stdout=${JSON.stringify(r.stdout)}`,
          )
        }
        if (!r.stdout.includes('SIBLING')) {
          throw new Error(
            `H6: sibling unreadable post-stamp — ` +
              `stdout=${JSON.stringify(r.stdout)} stderr=${JSON.stringify(r.stderr)}`,
          )
        }
      }, 90_000)

      it('H-denyWrite: child cannot write the denyWrite target', async () => {
        // denyWrite blocks writes and leaves reads open (acl.rs
        // DenyMask::WriteDeny strips SYNCHRONIZE); this asserts the
        // write half, smoke-aces A2 the read half.
        const hCfg = join(hScratch, 'cfg.txt')
        writeFileSync(hCfg, 'CONFIG-V1')
        const w = await rexecSandboxed(`echo POISONED>"${hCfg}"`, {
          allowWrite: [hScratch],
          denyWrite: [hCfg],
        })
        const after = readFileSync(hCfg, 'utf8')
        if (after !== 'CONFIG-V1') {
          throw new Error(
            `H-denyWrite: target was modified — ` +
              `content=${JSON.stringify(after)} exit=${w.status} ` +
              `stderr=${JSON.stringify(w.stderr)}`,
          )
        }
      }, 90_000)

      it('H7: no allowWrite — child has no rights on real-user file', async () => {
        // H5's root keeps its grant, and a kept root is readable.
        const never = mkdtempSync(join(tmpdir(), 'srt-h7-'))
        const file = join(never, 'mine.txt')
        writeFileSync(file, 'NEVER-GRANTED')
        try {
          const r = await rexecSandboxed(`type "${file}"`, {})
          if (r.status === 0 || r.stdout.includes('NEVER-GRANTED')) {
            throw new Error(
              `H7: child read a real-user file with no grant — ` +
                `exit=${r.status} stdout=${JSON.stringify(r.stdout)}`,
            )
          }
        } finally {
          rmSync(never, { recursive: true, force: true })
        }
      }, 90_000)

      it('H-glob: per-exec denyRead glob — expanded TS-side, both denied, restored', async () => {
        // Per-exec denyRead globs must go through expandWindowsFsPaths,
        // the same chokepoint as session-level: srt-win's
        // canonicalize_path rejects a raw glob.
        const dir = mkdtempSync(join(tmpdir(), 'srt-hglob-'))
        const a = join(dir, 'glob-a.secret')
        const b = join(dir, 'glob-b.secret')
        writeFileSync(a, 'GLOB-A')
        writeFileSync(b, 'GLOB-B')
        await SandboxManager.initialize(
          createFsTestConfig({ allowWrite: [dir] }),
        )
        try {
          const { argv, env } = await SandboxManager.wrapWithSandboxArgv(
            `type "${a}" & echo --SEP-- & type "${b}"`,
            undefined,
            {
              filesystem: {
                denyRead: [join(dir, 'glob-*.secret')],
                allowWrite: [],
                denyWrite: [],
              },
            },
          )
          // Glob expanded TS-side: exactly two --deny-read flags;
          // no glob char survives onto the argv (Rust would
          // hard-fail otherwise).
          const denyIdx = argv.flatMap((x, i) =>
            x === '--deny-read' ? [i] : [],
          )
          if (denyIdx.length !== 2) {
            throw new Error(
              `H-glob: expected 2 --deny-read flags after glob expand; ` +
                `got ${denyIdx.length}: ${JSON.stringify(argv)}`,
            )
          }
          for (const i of denyIdx) {
            if (argv[i + 1].includes('*') || argv[i + 1].includes('?')) {
              throw new Error(
                `H-glob: glob char survived into --deny-read value ` +
                  `'${argv[i + 1]}' — per-exec expand not applied`,
              )
            }
          }
          const r = await spawnAsync(argv[0], argv.slice(1), {
            env,
            timeout: 60_000,
          })
          if (r.stdout.includes('GLOB-A') || r.stdout.includes('GLOB-B')) {
            throw new Error(
              `H-glob: child read a glob-expanded deny target — ` +
                `stdout=${JSON.stringify(r.stdout)} stderr=${JSON.stringify(r.stderr)}`,
            )
          }
          // Per-exec restore: a fresh child (no customConfig) under
          // the same session can read both — proves the per-exec
          // stamp was lifted on child exit, not leaked onto disk.
          const wf = await SandboxManager.wrapWithSandboxArgv(
            `type "${a}" & type "${b}"`,
          )
          const rR = await spawnAsync(wf.argv[0], wf.argv.slice(1), {
            env: wf.env,
            timeout: 60_000,
          })
          if (!rR.stdout.includes('GLOB-A') || !rR.stdout.includes('GLOB-B')) {
            throw new Error(
              `H-glob: per-exec stamp NOT restored — fresh child still ` +
                `denied. stdout=${JSON.stringify(rR.stdout)} ` +
                `stderr=${JSON.stringify(rR.stderr)}`,
            )
          }
        } finally {
          await SandboxManager.reset()
          rmSync(dir, { recursive: true, force: true })
        }
      }, 120_000)

      it('H8: reset() keeps the write root granted — to no sandbox-user ACE', async () => {
        // After H5/H6/H7's reset() calls, the root's DACL must NOT
        // carry an explicit ACE for the sandbox user.
        const out = spawnSync('icacls', [hScratch], {
          encoding: 'utf8',
          timeout: 5_000,
        })
        if (out.stdout.includes(sbSid) || out.stdout.includes('srt-sandbox')) {
          throw new Error(
            `H8: srt-sandbox ACE still on '${hScratch}' after reset(): ` +
              out.stdout,
          )
        }
        // A kept grant carries the root's own `S-1-0-1936880739-…` SID.
        expect(out.stdout.includes('S-1-0-1936880739-')).toBe(true)
        rmSync(hScratch, { recursive: true, force: true })
      }, 30_000)

      // ── L-rows: how the lists rank against each other ──
      // A tree per row: d\own.txt, d\sub\in.txt, beside\b.txt, and to-d, a
      // junction to d. Each row logs what it ran, so a job log tells a row
      // that ran from one that was skipped.
      describe('L-rows: how the lists rank', () => {
        let spelled: string
        let root: string
        const at = (rel: string): string => join(root, rel)
        const CONTENT: Record<string, string> = {
          'd/own.txt': 'IN-D',
          'd/sub/in.txt': 'IN-SUB',
          'beside/b.txt': 'IN-BESIDE',
        }

        beforeEach(() => {
          spelled = mkdtempSync(join(tmpdir(), 'srt-l-'))
          root = realpathSync.native(spelled)
          for (const [rel, content] of Object.entries(CONTENT)) {
            mkdirSync(dirname(at(rel)), { recursive: true })
            writeFileSync(at(rel), content)
          }
          symlinkSync(at('d'), at('to-d'), 'junction')
        })

        afterEach(() => {
          try {
            rmSync(root, { recursive: true, force: true })
          } catch {
            // Not every runtime removes a junction.
          }
        })

        type Expected = {
          /** A file of CONTENT, and whether the command reads it. */
          reads?: Record<string, boolean>
          /** A file, there or not, and whether the command writes it. */
          writes?: Record<string, boolean>
        }

        /** One command that tries all of `expected`, held against it. */
        async function tryAll(
          id: string,
          expected: Expected,
          customConfig?: Partial<SandboxRuntimeConfig>,
        ): Promise<void> {
          const reads = Object.entries(expected.reads ?? {})
          const writes = Object.entries(expected.writes ?? {})
          const { argv, env } = await SandboxManager.wrapWithSandboxArgv(
            [
              'echo RAN',
              // `type` lists the folder first; `<` opens the file alone.
              ...reads.map(
                ([rel]) => `type "${at(rel)}" & more < "${at(rel)}"`,
              ),
              ...writes.map(([rel]) => `echo WROTE>"${at(rel)}"`),
            ].join(' & '),
            undefined,
            customConfig,
          )
          const r = await spawnAsync(argv[0], argv.slice(1), {
            env,
            timeout: 60_000,
          })
          const found = {
            reads: Object.fromEntries(
              reads.map(([rel]) => [rel, r.stdout.includes(CONTENT[rel])]),
            ),
            writes: Object.fromEntries(
              writes.map(([rel]) => [
                rel,
                existsSync(at(rel)) &&
                  readFileSync(at(rel), 'utf8').includes('WROTE'),
              ]),
            ),
          }
          console.error(
            `[winsrt ${id}] ran: exit=${r.status} found=${JSON.stringify(found)} ` +
              `stderr=${JSON.stringify(r.stderr)}`,
          )
          expect(r.stdout).toContain('RAN')
          expect(found).toEqual({
            reads: expected.reads ?? {},
            writes: expected.writes ?? {},
          })
        }

        /** `run` in a session of these lists. */
        async function inSession(
          fs: FsOverrides,
          files: CredentialFileConfig[],
          run: () => Promise<void>,
        ): Promise<void> {
          await SandboxManager.initialize({
            ...createFsTestConfig(fs),
            credentials: { files },
          })
          try {
            await run()
          } finally {
            await SandboxManager.reset()
          }
          for (const rel of ['.', 'beside', 'd', 'd/own.txt', 'd/sub']) {
            const acl = spawnSync('icacls', [at(rel)], {
              encoding: 'utf8',
              timeout: 5_000,
            }).stdout
            expect(acl).toContain(root)
            expect(acl).not.toContain(sbSid)
            expect(acl).not.toContain('srt-sandbox')
          }
        }

        type Lists = Partial<
          Record<
            'allowRead' | 'allowWrite' | 'denyRead' | 'denyWrite',
            string[]
          >
        >
        it.each<[string, string, Lists, CredentialFileConfig[], Expected]>([
          [
            'L1',
            'a denyWrite inside an allowWrite: written around, read within',
            { allowWrite: ['.'], denyWrite: ['d'] },
            [],
            {
              reads: { 'd/own.txt': true, 'd/sub/in.txt': true },
              writes: {
                'new.txt': true,
                'd/new.txt': false,
                'd/sub/new.txt': false,
              },
            },
          ],
          [
            'L2',
            'an allowWrite beneath a denyWrite: read, not written; beside it: written',
            { allowWrite: ['d/sub', 'beside'], denyWrite: ['d'] },
            [],
            {
              reads: { 'd/sub/in.txt': true, 'beside/b.txt': true },
              writes: {
                'd/sub/new.txt': false,
                'd/sub/in.txt': false,
                'beside/new.txt': true,
              },
            },
          ],
          [
            'L3',
            'an allowWrite around and beneath a denyWrite: written around alone',
            { allowWrite: ['.', 'd/sub'], denyWrite: ['d'] },
            [],
            {
              reads: { 'd/sub/in.txt': true },
              writes: { 'new.txt': true, 'd/sub/new.txt': false },
            },
          ],
          [
            'L4',
            'an allowWrite beneath a denyWrite, named through a junction',
            { allowWrite: ['to-d/sub'], denyWrite: ['d'] },
            [],
            {
              reads: { 'd/sub/in.txt': true },
              writes: { 'd/sub/new.txt': false },
            },
          ],
          [
            'L5',
            'an allowRead beneath a denyRead: read',
            { allowRead: ['d/sub', 'beside'], denyRead: ['d'] },
            [],
            {
              reads: {
                'd/sub/in.txt': true,
                'd/own.txt': false,
                'beside/b.txt': true,
              },
            },
          ],
          [
            'L6',
            'a credential deny inside an allowWrite: neither read nor written',
            { allowWrite: ['.'] },
            [{ path: 'd', mode: 'deny' }],
            {
              reads: {
                'd/own.txt': false,
                'd/sub/in.txt': false,
                'beside/b.txt': true,
              },
              writes: { 'd/new.txt': false, 'new.txt': true },
            },
          ],
          [
            'L7',
            'an allowRead beneath a credential deny: not read',
            { allowRead: ['d/sub', 'beside'] },
            [{ path: 'd', mode: 'deny' }],
            { reads: { 'd/sub/in.txt': false, 'beside/b.txt': true } },
          ],
          [
            'L8',
            'an allowWrite beneath a credential deny: neither read nor written',
            { allowWrite: ['d/sub', 'beside'] },
            [{ path: 'd', mode: 'deny' }],
            {
              reads: { 'd/sub/in.txt': false, 'beside/b.txt': true },
              writes: { 'd/sub/new.txt': false, 'beside/new.txt': true },
            },
          ],
          [
            'L9',
            'a masked file inside an allowWrite: neither read nor written',
            { allowWrite: ['.'] },
            [{ path: 'd/own.txt', mode: 'mask' }],
            {
              reads: { 'd/own.txt': false, 'd/sub/in.txt': true },
              writes: { 'd/own.txt': false, 'd/new.txt': true },
            },
          ],
          [
            'L10',
            'a masked file that is an allowRead too: not read',
            { allowRead: ['d/own.txt', 'beside'] },
            [{ path: 'd/own.txt', mode: 'mask' }],
            { reads: { 'd/own.txt': false, 'beside/b.txt': true } },
          ],
          [
            'L11',
            'a masked file with no match, to be denied: not read',
            { allowWrite: ['.'] },
            [
              {
                path: 'd/own.txt',
                mode: 'mask',
                extract: 'absent-(text)',
                onExtractNoMatch: 'deny',
              },
            ],
            { reads: { 'd/own.txt': false, 'd/sub/in.txt': true } },
          ],
        ])(
          '%s: %s',
          async (id, _name, lists, files, expected) => {
            await inSession(
              Object.fromEntries(
                Object.entries(lists).map(([list, rels]) => [
                  list,
                  rels.map(at),
                ]),
              ),
              files.map(f => ({ ...f, path: at(f.path) })),
              () => tryAll(id, expected),
            )
          },
          90_000,
        )

        it('L12: an allowWrite beneath a denyWrite, each spelled its own way', async () => {
          console.error(`[winsrt L12] spelled=${spelled} resolved=${root}`)
          await inSession(
            {
              allowWrite: [at('d/sub').toUpperCase()],
              denyWrite: [join(spelled, 'd')],
            },
            [],
            () =>
              tryAll('L12', {
                reads: { 'd/sub/in.txt': true },
                writes: { 'd/sub/new.txt': false },
              }),
          )
        }, 90_000)

        it("L13: one command's denyWrite over the session's allowWrite, for that command", async () => {
          await inSession({ allowWrite: [at('d/sub')] }, [], async () => {
            await tryAll(
              'L13 with',
              {
                reads: { 'd/sub/in.txt': true },
                writes: { 'd/sub/new.txt': false },
              },
              {
                filesystem: {
                  denyRead: [],
                  allowWrite: [],
                  denyWrite: [at('d')],
                },
              },
            )
            await tryAll('L13 without', {
              writes: { 'd/sub/new.txt': true },
            })
          })
        }, 120_000)

        it("L14: one command's credential deny over the session's grants, for that command", async () => {
          await inSession(
            { allowRead: [at('d/sub')], allowWrite: [at('beside')] },
            [],
            async () => {
              await tryAll(
                'L14 with',
                { reads: { 'd/sub/in.txt': false, 'beside/b.txt': true } },
                {
                  credentials: { files: [{ path: at('d'), mode: 'deny' }] },
                },
              )
              await tryAll('L14 without', {
                reads: { 'd/sub/in.txt': true },
              })
            },
          )
        }, 120_000)
      })
    })
  },
)

// ────────────────────────────────────────────────────────────────────
// Group G — tlsTerminate CA trust via env vars
// ────────────────────────────────────────────────────────────────────
//
// The TLS-terminating proxy itself is platform-agnostic (covered by
// tls-terminate-proxy.test.ts); these rows prove the sandboxed
// CHILD trusts the proxy-minted certs
// via the env vars `generateProxyEnvVars` emits when `caCertPath` is
// set. Schannel clients (System32 curl, IWR, .NET) get no credentials
// under the sandbox's token, so only tools with their own TLS stack
// are covered.
//
// Tool/row selection follows per-tool ground-truth probes run on
// win-x64 and win-arm64. In particular: Schannel `curl.exe`
// (System32, and the ARM64 git-bundled clangarm64 build) ignores
// `CURL_CA_BUNDLE`, so the curl row gates on an OpenSSL build being
// present; git defaults to the schannel backend (which ignores
// `GIT_SSL_CAINFO`), so the git row forces `http.sslBackend=openssl`.

// Committed test-only CA — see test/fixtures/tls-terminate/README.md.
const TLS_FIXTURE_DIR = join(import.meta.dir, '..', 'fixtures', 'tls-terminate')
const CA_CERT = join(TLS_FIXTURE_DIR, 'ca.crt')
const CA_KEY = join(TLS_FIXTURE_DIR, 'ca.key')

/**
 * True if `<mod>` imports under the sandbox-reachable python's
 * SYSTEM site-packages. `PYTHONNOUSERSITE=1` hides the broker's
 * per-user site (`%APPDATA%\Python`) so the probe approximates
 * what the srt-sandbox child sees — a module installed only via
 * `pip install --user` on the broker would otherwise pass the
 * gate but fail inside the sandbox.
 */
function hasPythonModule(mod: string): boolean {
  if (PYTHON === undefined) return false
  const r = spawnSync(PYTHON, ['-c', `import ${mod}`], {
    encoding: 'utf8',
    timeout: 10_000,
    env: { ...process.env, PYTHONNOUSERSITE: '1' },
  })
  return r.status === 0
}

function createTlsTestConfig(allowedDomains: string[]): SandboxRuntimeConfig {
  const base = createTestConfig(allowedDomains)
  return {
    ...base,
    network: {
      ...base.network,
      tlsTerminate: { caCertPath: CA_CERT, caKeyPath: CA_KEY },
    },
  }
}

// G1/G1b — env-injection layer (pure, all platforms). Mirrors
// tls-terminate-trust-env.test.ts at the same assertion depth, but
// against the Windows wrapper's `{argv, env}` shape instead of a
// shell string.
describe('wrapCommandWithSandboxWindows tlsTerminate trust env (pure, all platforms)', () => {
  function wrap(caCertPath?: string): {
    env: NodeJS.ProcessEnv
    envArgs: string[]
  } {
    const r = wrapCommandWithSandboxWindows({
      command: 'echo',
      httpProxyPort: 60080,
      socksProxyPort: 60080,
      caCertPath,
      srtWin: resolveSrtWin({ path: process.execPath }),
    })
    return {
      env: r.env,
      envArgs: r.argv.filter((_, i) => r.argv[i - 1] === '--env'),
    }
  }

  it('G1: env carries every CA_TRUST_VARS entry, forward-slashed', () => {
    // Probe with backslashes; the wrapper must normalise.
    const winPath = 'C:\\srt\\trust-bundle.crt'
    const { env, envArgs } = wrap(winPath)
    const want = 'C:/srt/trust-bundle.crt'
    for (const v of CA_TRUST_VARS) {
      expect(env[v]).toBe(want)
      // Same value rides the runner's --env overlay (what the child sees).
      expect(envArgs).toContain(`${v}=${want}`)
    }
    // Forward-slash means no backslash survives anywhere in the value.
    expect(env.SSL_CERT_FILE).not.toContain('\\')
  })

  it('G1b: env does not override CA_TRUST_VARS when caCertPath unset', () => {
    // The returned env inherits process.env, so the var may exist
    // (some CI runners pre-set NODE_EXTRA_CA_CERTS). What we assert
    // is that the wrapper did not ADD it — value equals whatever
    // the host already had, and it is NOT in the --env overlay.
    const { env, envArgs } = wrap(undefined)
    for (const v of CA_TRUST_VARS) {
      expect(env[v]).toBe(process.env[v])
      expect(envArgs.some(e => e.startsWith(`${v}=`))).toBe(false)
    }
  })
})

describe.if(isWindows)('Windows sandbox: tlsTerminate (G)', () => {
  // Allowed domains for the live tool rows. Each tool's row resets
  // the allowlist via updateConfig (live-swap; the proxy reads it
  // per-request) so this superset just bounds initialize().
  const TLS_ALLOWED = [
    'example.com',
    'github.com',
    'crates.io',
    'static.crates.io',
    'index.crates.io',
  ]

  beforeAll(async () => {
    console.error('[winsrt G beforeAll] start')
    // Reuse the network/file describes' WFP install (already
    // present in CI from the earlier suites; install when running
    // this describe in isolation).
    const wfp = getWindowsWfpStatus({
      sublayerGuid: TEST_SUBLAYER,
      srtWin: TEST_SRT_WIN,
    })
    if (wfp.state !== 'installed') {
      installWindowsSandbox({
        ...SUITE_INSTALL,
        sublayerGuid: TEST_SUBLAYER,
        proxyPortRange: PORT_RANGE,
        srtWin: TEST_SRT_WIN,
      })
    }
    // tlsTerminate on Windows requires the fixture CA to be
    // installed in the sandbox user's CurrentUser\Root
    // (initialize() gates on the thumbprint match). Idempotent —
    // replaces any prior install.
    windowsTrustCa(CA_CERT, { srtWin: TEST_SRT_WIN })
    await SandboxManager.initialize(createTlsTestConfig(TLS_ALLOWED))
    // Sanity: tlsTerminate config produced a CA + trust bundle.
    const ca = SandboxManager.getMitmCA()
    expect(ca?.trustBundlePath).toBeTruthy()
    console.error('[winsrt G beforeAll] done')
    // 120s: install re-provisions the sandbox user (H-rows'
    // afterAll uninstalled it), then trust-ca creates the user's
    // profile (LOGON_WITH_PROFILE) on first call — both can exceed
    // bun's 5s default hook timeout.
  }, 120_000)

  afterAll(async () => {
    await SandboxManager.reset()
    // Mirror the network + H-rows describes: leave no WFP filters,
    // sandbox user, or fixture CA behind. The P-group below
    // re-provisions if it needs to; in CI `cleanup.ps1` sweeps
    // regardless.
    uninstallWindowsSandbox({
      ...SUITE_INSTALL,
      sublayerGuid: TEST_SUBLAYER,
      srtWin: TEST_SRT_WIN,
    })
  }, 60_000)

  it('G2: child sees SSL_CERT_FILE and can read the trust bundle', async () => {
    // Mirrors tls-terminate-trust-env.test.ts row 3. The path is
    // emitted with forward slashes (so it survives msys2 and is
    // accepted by every CreateFileW caller); cmd's `type` BUILTIN
    // does its own path parsing and rejects `/`, so flip them back
    // to `\` via cmd's `%VAR:/=\%` substitution for this one
    // builtin. writeTrustBundle puts the CA first, then system
    // roots — assert the path landed and the PEM header is present.
    const r = await runSandboxed(
      `echo %SSL_CERT_FILE% && type "%SSL_CERT_FILE:/=\\%"`,
    )
    expectStatus('G2', r, [0])
    const bundle = SandboxManager.getMitmCA()!.trustBundlePath.replace(
      /\\/g,
      '/',
    )
    const out = r.stdout.replace(/\r/g, '')
    const firstLine = out.split('\n')[0].trim()
    expect(firstLine).toBe(bundle)
    expect(out).toContain('-----BEGIN CERTIFICATE-----')
  })

  it.skipIf(OPENSSL_CURL === undefined)(
    'G3: OpenSSL curl trusts the MITM CA via CURL_CA_BUNDLE',
    async () => {
      SandboxManager.updateConfig(createTlsTestConfig(['example.com']))
      // -v so stderr carries `issuer:` for the MITM-proof assertion;
      // -sS so transfer noise is suppressed but errors still print.
      const r = await runSandboxedUntil(
        `"${OPENSSL_CURL}" -sS -v -o NUL https://example.com/`,
        x => x.status === 0,
      )
      expectStatus('G3', r, [0])
      // The leaf is minted by our CA — issuer CN is the fixture's.
      expect(r.stderr).toMatch(/issuer:.*srt-test-ca/i)
    },
    60_000,
  )

  it.skipIf(GIT === undefined)(
    'G4: git (-c http.sslBackend=openssl) trusts the MITM CA via GIT_SSL_CAINFO',
    async () => {
      SandboxManager.updateConfig(
        createTlsTestConfig(['example.com', 'github.com']),
      )
      // git's default backend on Windows is schannel, which IGNORES
      // GIT_SSL_CAINFO unless `http.schannelUseSSLCAInfo=true`; the
      // openssl backend honors it directly. git-via-proxy is heavier
      // than curl (smart-HTTP), so 45s/attempt + 120s overall.
      const r = await runSandboxedUntil(
        `"${GIT}" -c http.sslBackend=openssl ls-remote https://github.com/git/git.git HEAD`,
        x => x.status === 0 && /HEAD/.test(x.stdout),
        2,
        45_000,
      )
      expectStatus('G4', r, [0])
      expect(r.stdout).toMatch(/HEAD/)
    },
    120_000,
  )

  it.skipIf(NODE === undefined)(
    'G5: node trusts the MITM CA via NODE_EXTRA_CA_CERTS (extends)',
    async () => {
      SandboxManager.updateConfig(createTlsTestConfig(['example.com']))
      // A bare fetch honors the proxy env vars only on releases that read
      // NODE_USE_ENV_PROXY, so on any release we tunnel explicitly:
      // http CONNECT to the proxy (read from `HTTPS_PROXY`,
      // including the auth token), then `https.get` over the
      // resulting socket. `https.get` validates the proxy-minted
      // cert against the system roots + NODE_EXTRA_CA_CERTS, so a
      // missing/unreadable bundle surfaces as
      // UNABLE_TO_VERIFY_LEAF_SIGNATURE on the inner request.
      // NODE_EXTRA_CA_CERTS failures are a one-time startup
      // warning, NOT a hard error — assert the MITM'd request
      // returns 200, not just that node ran.
      const bundle = SandboxManager.getMitmCA()!.trustBundlePath
      const script = nodeGetThroughProxy('example.com')
      const r = await runSandboxedUntil(
        `"${NODE}" -e "${script}"`,
        x => x.status === 0,
      )
      expectStatus(`G5 (bundle=${bundle} exists=${existsSync(bundle)})`, r, [0])
      expect(r.stdout).toContain('STATUS:200')
    },
    60_000,
  )

  it.skipIf(!hasPythonModule('requests'))(
    'G6: python requests trusts the MITM CA via REQUESTS_CA_BUNDLE',
    async () => {
      SandboxManager.updateConfig(createTlsTestConfig(['example.com']))
      const r = await runSandboxedUntil(
        `"${PYTHON}" -c "import requests; print('STATUS:'+str(requests.get('https://example.com/').status_code))"`,
        x => x.status === 0,
      )
      expectStatus('G6', r, [0])
      expect(r.stdout).toContain('STATUS:200')
    },
    60_000,
  )

  it.skipIf(PYTHON === undefined)(
    'G7: python stdlib trusts the MITM CA via SSL_CERT_FILE',
    async () => {
      // On Windows `SSL_CERT_FILE` is ADDITIVE for cpython
      // (load_default_certs also loads the Windows store), unlike
      // on POSIX where it replaces. Either way the MITM'd request
      // verifies against our CA.
      SandboxManager.updateConfig(createTlsTestConfig(['example.com']))
      const r = await runSandboxedUntil(
        `"${PYTHON}" -c "import urllib.request as u; print('STATUS:'+str(u.urlopen('https://example.com/').status))"`,
        x => x.status === 0,
      )
      expectStatus('G7', r, [0])
      expect(r.stdout).toContain('STATUS:200')
    },
    60_000,
  )

  // Last: it replaces the session the rows above share.
  it('G10: beneath a credential deny the trust bundle is read, what lies beside it is not', async () => {
    const scratch = realpathSync.native(mkdtempSync(join(tmpdir(), 'srt-g10-')))
    const beside = join(scratch, 'beside.txt')
    writeFileSync(beside, 'IN-BESIDE')
    await SandboxManager.reset()
    const temp = process.env.TEMP
    try {
      // The bundle gets a folder of its own in the temp folder.
      process.env.TEMP = scratch
      await SandboxManager.initialize({
        ...createTlsTestConfig(['example.com']),
        credentials: { files: [{ path: scratch, mode: 'deny' }] },
      })
      const bundle = SandboxManager.getMitmCA()!.trustBundlePath
      expect(dirname(dirname(bundle))).toBe(scratch)
      const r = await runSandboxed(
        `echo RAN & type "%SSL_CERT_FILE:/=\\%" & type "${beside}"`,
      )
      console.error(
        `[winsrt G10] ran: exit=${r.status} bundle=${bundle} ` +
          `stdout=${r.stdout.length} chars stderr=${JSON.stringify(r.stderr)}`,
      )
      expect(r.stdout).toContain('RAN')
      expect(r.stdout).toContain('-----BEGIN CERTIFICATE-----')
      expect(r.stdout).not.toContain('IN-BESIDE')
    } finally {
      process.env.TEMP = temp
      await SandboxManager.reset()
      rmSync(scratch, { recursive: true, force: true })
    }
  }, 120_000)
})

// ────────────────────────────────────────────────────────────────────
// Group P — persistent CA (`ensurePersistentWindowsCa` +
// `initialize()` auto-load with `tlsTerminate: {}`).
//
// Separate describe from G: G's beforeAll pins the fixture CA
// (explicit caCertPath); this group exercises the no-explicit-path
// branch that generates-if-absent under `windowsStateDir()/ca`.
// ────────────────────────────────────────────────────────────────────

describe.if(isWindows)('Windows sandbox: persistent CA (P)', () => {
  // bun evaluates describe bodies even under `.if(false)` — guard the
  // top-level const so `windowsStateDir()` (throws without
  // ProgramData) doesn't run on macOS/Linux.
  const caDir = isWindows ? join(windowsStateDir(), 'ca') : ''

  beforeAll(async () => {
    console.error('[winsrt P beforeAll] start')
    // G's afterAll uninstalled — re-provision (own sublayer).
    const wfp = getWindowsWfpStatus({
      sublayerGuid: TEST_SUBLAYER,
      srtWin: TEST_SRT_WIN,
    })
    if (wfp.state !== 'installed') {
      installWindowsSandbox({
        ...SUITE_INSTALL,
        sublayerGuid: TEST_SUBLAYER,
        proxyPortRange: PORT_RANGE,
        srtWin: TEST_SRT_WIN,
      })
    }
    // Start from a clean slate so P1's `generated: true` is
    // deterministic across repeated local runs.
    rmSync(caDir, { recursive: true, force: true })
    console.error('[winsrt P beforeAll] done')
  }, 120_000)

  afterAll(async () => {
    await SandboxManager.reset()
    rmSync(caDir, { recursive: true, force: true })
    // Last describe in the file → owns final teardown.
    uninstallWindowsSandbox({
      ...SUITE_INSTALL,
      sublayerGuid: TEST_SUBLAYER,
      srtWin: TEST_SRT_WIN,
    })
  }, 60_000)

  it('P1: idempotent — first call generates, second reuses (temp dir)', async () => {
    // Scoped to a scratch dir so this row is hermetic irrespective
    // of what P2/P3 write to the default location.
    const dir = mkdtempSync(join(tmpdir(), 'srt-persist-ca-'))
    const srtWin = TEST_SRT_WIN
    try {
      const status = getWindowsSandboxUserStatus({ srtWin })
      const a = await ensurePersistentWindowsCa({ dir, status, srtWin })
      expect(a.generated).toBe(true)
      expect(a.trusted).toBe(true)
      expect(a.thumbprint).toMatch(/^[0-9A-F]{40}$/)
      expect(a.certPem).toContain('BEGIN CERTIFICATE')
      expect(a.keyPem).toContain('PRIVATE KEY')
      // ca.json is the atomic source of truth; cert.pem/key.pem are
      // derived siblings.
      expect(existsSync(join(dir, 'ca.json'))).toBe(true)
      expect(existsSync(a.certPath)).toBe(true)
      expect(existsSync(a.keyPath)).toBe(true)
      // Second call: same PEMs, same thumb, no regenerate. `trusted`
      // is false — the first call's trust step recorded this thumb
      // in install.db, so the reconcile finds it already installed.
      const b = await ensurePersistentWindowsCa({
        dir,
        status: getWindowsSandboxUserStatus({ srtWin }),
        srtWin,
      })
      expect(b.generated).toBe(false)
      expect(b.trusted).toBe(false)
      expect(b.thumbprint).toBe(a.thumbprint)
      expect(b.certPem).toBe(a.certPem)
      // Corrupt ca.json → regenerates (no throw).
      writeFileSync(join(dir, 'ca.json'), 'not json')
      const c = await ensurePersistentWindowsCa({ dir, status, srtWin })
      expect(c.generated).toBe(true)
      expect(c.thumbprint).not.toBe(a.thumbprint)
      // `force` regenerates even with a valid pair on disk (via
      // tmp+rename, so ca.json is always a matched pair).
      const d = await ensurePersistentWindowsCa({
        dir,
        status,
        srtWin,
        force: true,
      })
      expect(d.generated).toBe(true)
      expect(d.thumbprint).not.toBe(c.thumbprint)
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  }, 120_000)

  it('P2: initialize() with tlsTerminate:{} auto-loads the persistent CA', async () => {
    // No caCertPath/caKeyPath → the Windows branch of initialize()
    // calls ensurePersistentWindowsCa(), then createMitmCA on its
    // paths. First run generates; the returned MitmCA's certPath
    // must be under the state-dir `ca/` (not a mkdtemp `srt-ca-`).
    const cfg = createTestConfig(['example.com'])
    await SandboxManager.initialize({
      ...cfg,
      network: { ...cfg.network, tlsTerminate: {} },
    })
    const ca = SandboxManager.getMitmCA()
    expect(ca).toBeTruthy()
    expect(ca!.ephemeral).toBe(false)
    // Case-insensitive prefix match — Windows path casing varies.
    expect(ca!.certPath.toLowerCase()).toBe(
      join(caDir, 'cert.pem').toLowerCase(),
    )
    // `srt-win user status` now reports the same thumb the session
    // CA carries — proves ensurePersistentWindowsCa's trust step
    // landed and the initialize() gate would have passed the
    // explicit-path check too.
    const u = getWindowsSandboxUserStatus({ srtWin: TEST_SRT_WIN })
    expect(u.caCertThumb).toBeTruthy()
  }, 60_000)

  it.skipIf(!HAS_OWN_TLS_CLIENT)(
    'P3: a client with its own TLS stack trusts the persistent CA end-to-end',
    async () => {
      const r = await runSandboxedUntil(ownTlsGet('example.com'), got200)
      expectStatus('P3', r, [0])
      expect(got200(r)).toBe(true)
    },
    90_000,
  )

  it('P4: ca.json (key custody) is unreadable from inside the sandbox', async () => {
    // The `ca/` dir inherits the state-dir's `(OI)(CI)` real-user
    // -only DACL + `sandbox-runtime-users` DENY. `type` from inside
    // the sandbox must fail. Gate on stdout NOT containing the PEM
    // header (cmd `type` exit codes are unreliable on access-denied).
    const jsonPath = join(caDir, 'ca.json')
    // Broker (real user) CAN read it.
    expect(readFileSync(jsonPath, 'utf8')).toContain('PRIVATE KEY')
    const r = await runSandboxed(`type "${jsonPath}"`)
    expect(r.stdout).not.toContain('PRIVATE KEY')
    // stderr should carry the access-denied — tolerant match.
    expect(`${r.stdout} ${r.stderr}`).toMatch(/denied|Access is denied/i)
  }, 30_000)
})

describe('Windows profile read grant (pure, all platforms)', () => {
  const SID = 'S-1-5-21-1'
  const REAL_USER = 'S-1-5-21-3'
  type SyncResult = { status: number; stdout: string; stderr: string }
  const exit = (status: number, stdout = '', stderr = ''): SyncResult => ({
    status,
    stdout,
    stderr,
  })

  /**
   * `profile_grant` of `user status`; `undefined` = no field. A grant
   * is recorded unless a row says otherwise.
   */
  let briefGrant: unknown
  /** `real_user_sid` of `user status`. */
  let realUserSid: string
  /** `session_user_sid` of `user status`; `null` = cannot be told. */
  let sessionUserSid: string | null
  /** stdout of `profile status`. */
  let profileStatus: Record<string, unknown>
  /** Every sync `acl` / `profile` spawn, in order. */
  let calls: { cmd: string; sub: string; argv: string[]; stdin: unknown }[]
  let syncResult: Record<string, SyncResult>
  /** Every async spawn's argv (after the dispatch sentinel). */
  let asyncCalls: string[][]
  /** What an async `profile grant` does; `code: null` never exits. */
  let grantRun: { stderr: string[]; stdout: string; code: number | null }
  /** Exit code of `install`, sync and async. */
  let installCode: number
  let spies: { mockRestore(): void }[]
  /**
   * Stands in for the profile directory, in the form `srt-win` records a
   * path in (links resolved, 8.3 names expanded, the case on disk).
   */
  let home: string
  /**
   * The same directory as the temp directory spells it, which on
   * Windows can be through a short name and on macOS is through a
   * link: a spelling a session configuration may well use.
   */
  let homeAsSpelled: string
  /** A write root outside it. */
  let work: string

  /** The final-path lookup the library and `srt-win` both use. */
  const canonical = (p: string): string => {
    try {
      // eslint-disable-next-line no-restricted-properties
      return realpathSync.native(p)
    } catch (e) {
      return `<${(e as NodeJS.ErrnoException).code ?? 'error'}: ${p}>`
    }
  }
  /**
   * What a failed row needs to be read without a Windows machine: the
   * paths as given, as resolved, the record they were measured
   * against, and what the functions under test made of them.
   */
  const explain = (paths: readonly string[]): string =>
    JSON.stringify(
      {
        platform: process.platform,
        tmpdir: tmpdir(),
        homeAsSpelled,
        home,
        paths: paths.map(p => ({ given: p, resolved: canonical(p) })),
        exclusions: exclusions(),
        ungrantedOnly: ungrantedOnly(),
        recorded: recorded(),
        conflicts: winUtils.windowsProfileExclusionConflicts(paths, lists()),
        conflictsAsWrite: winUtils.windowsProfileExclusionConflicts(
          paths,
          lists(),
          { write: true },
        ),
        calls: calls.map(c => `${c.cmd} ${c.sub}`),
      },
      null,
      1,
    )
  /** Run assertions; on failure, say what they were about. */
  const explained = async <T>(
    paths: readonly string[],
    run: () => T | Promise<T>,
  ): Promise<T> => {
    try {
      return await run()
    } catch (e) {
      const err = e as Error
      err.message = `${err.message}\n--- context ---\n${explain(paths)}`
      throw err
    }
  }

  const names = () => calls.map(c => `${c.cmd} ${c.sub}`)
  const stdinOf = (name: string) =>
    calls.find(c => `${c.cmd} ${c.sub}` === name)?.stdin as
      | Record<string, string[]>
      | undefined
  const rec = (kind: string, ...rel: string[]) => ({
    path: join(home, ...rel),
    kind,
  })
  /** The grant as recorded for `home`. */
  /** More recorded paths, for one test. */
  let extraRecorded: ReturnType<typeof rec>[] = []
  const recorded = () => [
    ...extraRecorded,
    rec('container'),
    rec('granted', 'Documents'),
    rec('file', '.npmrc'),
    rec('container', '.cargo'),
    rec('file', '.cargo', 'config.toml'),
    rec('denied', '.cargo', 'credentials.toml'),
    rec('denied', '.ssh'),
  ]
  /** The made-up profile's temporary directory. */
  const temp = () => join(home, 'AppData', 'Local', 'Temp')
  /**
   * What the grant protects: built-in entries, one added one, and an
   * added one inside the temporary directory.
   */
  /** More recorded exclusions, for one test. */
  let extraExclusions: string[] = []
  const exclusions = () => [
    ...extraExclusions,
    join(home, '.ssh'),
    join(home, '.cargo', 'credentials.toml'),
    join(home, 'NTUSER.DAT*'),
    join(home, 'AppData', 'Local', '*', 'EBWebView'),
    join(home, '.myapp'),
    join(temp(), 'keys'),
  ]
  /** What it leaves ungranted without denying it. */
  const ungrantedOnly = () => [temp()]
  const lists = () => ({
    exclusions: exclusions(),
    ungrantedOnly: ungrantedOnly(),
  })
  /**
   * What `srt-win` says it does, in `user status` and in `profile
   * status`; `undefined` = an srt-win that does not say.
   */
  let brokerCapabilities: string[] | undefined = SRT_WIN_CAPABILITIES
  const current = (extra: string[] = ['.myapp']) => ({
    record_version: 1,
    ...(brokerCapabilities !== undefined && {
      capabilities: brokerCapabilities,
    }),
    state: 'current',
    profile: home,
    list_version: 1,
    recorded_list_version: 1,
    extra_exclusions: extra,
    exclusions: exclusions(),
    ungranted_only: ungrantedOnly(),
    containers: 2,
    granted: 1,
    files: 2,
    denied: 2,
    env: { NPM_CONFIG_USERCONFIG: join(home, '.npmrc') },
    paths: recorded(),
  })
  const grantJson = () =>
    JSON.stringify({
      profile: home,
      list_version: 1,
      complete: true,
      containers: 4,
      granted: 30,
      files: 6,
      denied: 50,
      placeholders: 20,
      writes: 90,
      unchanged: 0,
      removed: 1,
      skipped: [{ path: join(home, 'link'), reason: 'reparse point' }],
      failed: [],
      elapsed_ms: 1234,
    })

  beforeEach(() => {
    briefGrant = { state: 'present' }
    realUserSid = REAL_USER
    sessionUserSid = REAL_USER
    calls = []
    syncResult = {}
    asyncCalls = []
    installCode = 0
    homeAsSpelled = mkdtempSync(join(tmpdir(), 'srt-profile-'))
    home = canonical(homeAsSpelled)
    work = canonical(mkdtempSync(join(tmpdir(), 'srt-profile-work-')))
    mkdirSync(join(home, 'Documents', 'sub'), { recursive: true })
    mkdirSync(join(home, '.cargo'))
    mkdirSync(join(home, '.ssh', 'keys'), { recursive: true })
    mkdirSync(join(home, '.myapp'))
    mkdirSync(join(home, 'AppData', 'Local', 'App', 'EBWebView'), {
      recursive: true,
    })
    mkdirSync(join(home, 'AppData', 'Local', 'App', 'data'))
    mkdirSync(join(temp(), 'session', 'work'), { recursive: true })
    mkdirSync(join(temp(), 'keys', 'sub'), { recursive: true })
    writeFileSync(join(home, '.npmrc'), '//feed/:_authToken=t\n')
    writeFileSync(join(home, '.cargo', 'config.toml'), '')
    brokerCapabilities = SRT_WIN_CAPABILITIES
    profileStatus = current()
    grantRun = { stderr: [], stdout: grantJson(), code: 0 }
    const stdoutFor = (argv: readonly string[]): string => {
      const user = {
        user: {
          exists: true,
          sid: SID,
          group_exists: true,
          group_sid: 'S-1-5-21-2',
          in_builtin_users: true,
          in_sandbox_group: true,
          hidden_from_logon: true,
        },
        cred_present: true,
        marker_version: 1,
        real_user_sid: realUserSid,
        session_user_sid: sessionUserSid,
        ca_cert_thumb: null,
        ca_cert_pem: null,
        ...(briefGrant !== undefined && { profile_grant: briefGrant }),
        ...(brokerCapabilities !== undefined && {
          capabilities: brokerCapabilities,
        }),
      }
      const wfp = {
        state: 'installed',
        filters: 4,
        port_range: [60080, 60089],
        user_sid: SID,
      }
      return argv.includes('install')
        ? ''
        : argv.includes('user')
          ? JSON.stringify(user)
          : argv.includes('wfp')
            ? JSON.stringify(wfp)
            : argv.includes('status')
              ? JSON.stringify({ user, wfp })
              : ''
    }
    spies = [
      spyOn(platform, 'getPlatform').mockReturnValue('windows'),
      spyOn(winUtils, 'verifyWindowsWfpEgress').mockImplementation((() =>
        Promise.resolve({ outcome: 'blocked' })) as never),
      spyOn(child_process, 'spawn').mockImplementation(((
        _exe: string,
        argv: readonly string[],
      ) => {
        if (madeWithoutBlocking(argv))
          return asyncChildAnsweredBySync(_exe, argv)
        const own = argv.filter(a => a !== SRT_WIN_DISPATCH_ARG1)
        asyncCalls.push([...own])
        const mkStream = () => {
          const s = new EventEmitter() as EventEmitter & {
            setEncoding(e: string): typeof s
            end(d?: string): void
          }
          s.setEncoding = () => s
          s.end = () => {}
          return s
        }
        const child = Object.assign(new EventEmitter(), {
          stdout: mkStream(),
          stderr: mkStream(),
          stdin: mkStream(),
          kill: () => {
            setImmediate(() => child.emit('close', null, 'SIGTERM'))
            return true
          },
        })
        if (own[0] === 'profile') {
          if (grantRun.code !== null) {
            setImmediate(() => {
              for (const chunk of grantRun.stderr) {
                child.stderr.emit('data', chunk)
              }
              child.stdout.emit('data', grantRun.stdout)
              child.emit('close', grantRun.code, null)
            })
          }
        } else {
          setImmediate(() => {
            child.stdout.emit('data', stdoutFor(argv))
            child.emit('close', own[0] === 'install' ? installCode : 0, null)
          })
        }
        return child
      }) as never),
      spyOn(child_process, 'spawnSync').mockImplementation(((
        _exe: string,
        argv: readonly string[],
        opts: { input?: string },
      ) => {
        const own = argv.filter(a => a !== SRT_WIN_DISPATCH_ARG1)
        const [cmd, sub] = own
        if (cmd === 'install') {
          calls.push({ cmd, sub: '', argv: own.slice(1), stdin: undefined })
          return exit(installCode)
        }
        if (cmd !== 'acl' && cmd !== 'profile') {
          return syncResult[cmd] ?? exit(0, stdoutFor(argv))
        }
        calls.push({
          cmd,
          sub,
          argv: own.slice(2),
          stdin: opts.input === undefined ? undefined : JSON.parse(opts.input),
        })
        const key = `${cmd} ${sub}`
        if (syncResult[key]) return syncResult[key]
        if (key === 'profile status') {
          return exit(0, JSON.stringify(profileStatus))
        }
        if (key === 'profile grant') return exit(0, grantJson())
        return exit(0, cmd === 'acl' ? '[]' : '{}')
      }) as never),
    ]
  })

  afterEach(async () => {
    syncResult = {}
    await SandboxManager.reset()
    for (const s of spies) s.mockRestore()
    rmSync(home, { recursive: true, force: true })
    rmSync(work, { recursive: true, force: true })
  })

  const config = (
    windows: Partial<NonNullable<SandboxRuntimeConfig['windows']>> = {},
    filesystem: Partial<SandboxRuntimeConfig['filesystem']> = {},
  ): SandboxRuntimeConfig => ({
    network: {
      allowedDomains: [],
      deniedDomains: [],
      httpProxyPort: 1,
      socksProxyPort: 2,
    },
    filesystem: {
      denyRead: [],
      allowRead: [],
      allowWrite: [work],
      denyWrite: [],
      ...filesystem,
    },
    windows: { srtWin: { path: process.execPath }, ...windows },
  })
  const pathsOf = (cfg: SandboxRuntimeConfig): string[] =>
    [
      ...(cfg.filesystem.allowRead ?? []),
      ...cfg.filesystem.allowWrite,
      ...cfg.filesystem.denyRead,
    ].filter((p): p is string => typeof p === 'string')
  const rejection = async (
    cfg: SandboxRuntimeConfig,
    options?: Parameters<typeof SandboxManager.initialize>[3],
  ): Promise<WindowsSandboxError> => {
    try {
      await SandboxManager.initialize(cfg, undefined, false, options)
    } catch (e) {
      return e as WindowsSandboxError
    }
    throw new Error(
      `expected initialize() to reject\n--- context ---\n` +
        `options: ${JSON.stringify(options)}\n${explain(pathsOf(cfg))}`,
    )
  }

  describe('a default session: initialize() checks the record and never writes the grant', () => {
    it('a current grant: one `profile status`, without the path list, then the session as usual', async () => {
      // The status is read without blocking the event loop.
      const blocking = spyOn(winUtils, 'getWindowsProfileReadStatus')
      spies.push(blocking)
      await SandboxManager.initialize(config())
      expect(names()).toEqual(['profile status', 'acl grant'])
      expect(blocking).not.toHaveBeenCalled()
      expect(calls[0].argv).toEqual([])
      expect(asyncCalls.some(a => a[0] === 'profile')).toBe(false)
      expect(names()).not.toContain('profile grant')
      expect(names()).not.toContain('profile forget')
      const { argv } = await SandboxManager.wrapWithSandboxArgv('echo x')
      expect(argv).toContain('--write-restricted-token')
      expect(SandboxManager.getWindowsProfileRead()).toBe('granted')
      await SandboxManager.reset()
      expect(SandboxManager.getWindowsProfileRead()).toBeUndefined()
    })

    for (const [what, brief, status] of [
      ['user status reports none', { state: 'none' }, undefined],
      ['an srt-win that does not report it', undefined, undefined],
      [
        'user status reports one and the record turns out empty',
        { state: 'present' },
        { state: 'none', record_version: 1 },
      ],
    ] as const) {
      it(`no grant recorded (${what}): the session runs as it did before the feature, and the profile is not readable`, async () => {
        briefGrant = brief
        if (status) profileStatus = status
        await SandboxManager.initialize(
          config({}, { denyRead: [home], allowRead: [join(home, '.ssh')] }),
        )
        expect(names()).toEqual(
          status ? ['profile status', 'acl grant'] : ['acl grant'],
        )
        expect(stdinOf('acl grant')).toMatchObject({
          read: [join(home, '.ssh')],
          denyRead: [home],
        })
        expect(calls.at(-1)?.argv).toContain('--persistent')
        expect(asyncCalls.some(a => a[0] === 'profile')).toBe(false)
        expect(SandboxManager.getWindowsProfileRead()).toBe('absent')
        const { argv } = await SandboxManager.wrapWithSandboxArgv('echo x')
        expect(argv).toContain('--write-restricted-token')
      })
    }

    it('profile forget, then a session: it runs again, without reading the profile', async () => {
      await SandboxManager.initialize(config())
      expect(SandboxManager.getWindowsProfileRead()).toBe('granted')
      await SandboxManager.reset()
      winUtils.forgetWindowsProfileRead({
        srtWin: { exe: process.execPath, prependArgs: [] },
      })
      briefGrant = { state: 'none' }
      calls = []
      await SandboxManager.initialize(config())
      expect(names()).toEqual(['acl grant'])
      expect(SandboxManager.getWindowsProfileRead()).toBe('absent')
      profileStatus = { state: 'none', record_version: 1 }
      expect(
        winUtils.windowsProfileReadEnv(
          winUtils.getWindowsProfileReadStatus({
            srtWin: { exe: process.execPath, prependArgs: [] },
          }),
        ),
      ).toEqual({})
    })

    for (const [state, reason] of [
      ['outdated', 'made with list version 0; this build has 1'],
      ['incomplete', 'the last run did not finish'],
      ['unknown', 'access denied'],
      ['fine-probably', undefined],
    ] as const) {
      it(`a recorded grant that is ${state} → profile_grant_outdated; not refreshed, nothing granted`, async () => {
        profileStatus = { ...current(), state, ...(reason && { reason }) }
        const e = await rejection(config())
        expect(e.code).toBe('profile_grant_outdated')
        if (reason) expect(e.message).toContain(reason)
        expect(e.message).toContain('grantWindowsProfileRead()')
        expect(e.message).toContain('forgetWindowsProfileRead()')
        expect(names()).toEqual(['profile status'])
        expect(asyncCalls.some(a => a[0] === 'profile')).toBe(false)
        expect(SandboxManager.getConfig()).toBeUndefined()
      })
    }

    for (const [what, patch] of [
      ['no exclusion list', { exclusions: undefined }],
      ['an empty exclusion list', { exclusions: [] }],
      ['an exclusion list that is not a list', { exclusions: 'C:\\x' }],
      ['an exclusion list with a non-string in it', { exclusions: ['a', 1] }],
      ['an exclusion list with an empty entry', { exclusions: [''] }],
      ['no ungranted-only list', { ungranted_only: undefined }],
      ['an ungranted-only list that is not a list', { ungranted_only: {} }],
      ['no record version', { record_version: undefined }],
      ['a newer record version', { record_version: 2 }],
      ['an older record version', { record_version: 0 }],
      ['a record version that is not a number', { record_version: '1' }],
    ] as const) {
      it(`a current grant reported with ${what} → profile_grant_outdated, not an unchecked session`, async () => {
        profileStatus = { ...current(), ...patch }
        const st = winUtils.getWindowsProfileReadStatus({
          srtWin: { exe: process.execPath, prependArgs: [] },
        })
        expect(st.state).toBe('outdated')
        expect(st.reason).toBeTruthy()
        expect(st.env).toEqual({})
        calls = []
        const e = await rejection(
          config({}, { allowRead: [join(home, 'Documents')] }),
        )
        expect(e.code).toBe('profile_grant_outdated')
        expect(names()).toEqual(['profile status'])
        expect(SandboxManager.getConfig()).toBeUndefined()
        expect(SandboxManager.getWindowsProfileRead()).toBeUndefined()
      })
    }

    it('`profile status` failing → initialize() rejects; nothing granted', async () => {
      syncResult['profile status'] = exit(1, '', 'boom')
      const e = await rejection(config())
      expect(e.code).toBe('srt_win_nonzero')
      expect(names()).toEqual(['profile status'])
      expect(SandboxManager.getConfig()).toBeUndefined()
    })

    it('there is no setting for it: the schema has no profile key', () => {
      expect(Object.keys(WindowsConfigSchema.shape)).not.toContain(
        'profileRead',
      )
      expect(Object.keys(WindowsConfigSchema.shape)).not.toContain(
        'profileReadExclude',
      )
    })
  })

  describe('a session read deny against the grant', () => {
    const denyRead = async (
      ...paths: string[]
    ): Promise<string[] | undefined> => {
      await SandboxManager.initialize(config({}, { denyRead: paths }))
      return stdinOf('acl grant')?.denyRead
    }

    it('on the profile directory, a container, a granted directory or a path beneath one: the deny itself, once', async () => {
      for (const p of [
        home,
        join(home, '.cargo'),
        join(home, 'Documents'),
        join(home, 'Documents', 'sub'),
      ]) {
        calls = []
        expect(await denyRead(p)).toEqual([p])
        await SandboxManager.reset()
      }
    })

    it('the record is not asked for path by path: status is read without the path list', async () => {
      await denyRead(home)
      const status = calls.find(c => c.cmd === 'profile' && c.sub === 'status')
      expect(status?.argv).toEqual([])
    })

    it('denyRead of the profile directory holds for that session only: the next one stamps nothing', async () => {
      await denyRead(home)
      await SandboxManager.reset()
      expect(names()).toEqual([
        'profile status',
        'acl grant',
        'acl revoke',
        'acl restore',
      ])
      calls = []
      await SandboxManager.initialize(config())
      expect(names()).toEqual(['profile status', 'acl grant'])
      expect(stdinOf('acl grant')?.denyRead).toEqual([])
    })

    it("a write root with a read-denied file inside it: the session starts, and the deny is the session's, not a recorded exclusion", async () => {
      const proj = join(home, 'proj')
      mkdirSync(proj)
      writeFileSync(join(proj, '.env'), 'TOKEN=x')
      const cfg = config(
        {},
        { allowWrite: [proj], denyRead: [join(proj, '.env')] },
      )
      await SandboxManager.initialize(cfg)
      expect(stdinOf('acl grant')).toMatchObject({
        write: [proj],
        denyRead: [join(proj, '.env')],
      })
      expect(names()).toEqual(['profile status', 'acl grant'])
      const { argv } = await SandboxManager.wrapWithSandboxArgv('echo x')
      expect(argv.filter((_, i) => argv[i - 1] === '--write-root')).toEqual([
        proj,
      ])
      await SandboxManager.reset()
      calls = []
      await SandboxManager.initialize(cfg)
      expect(stdinOf('acl grant')).toMatchObject({ write: [proj] })
      expect(
        (winUtils as Record<string, unknown>).windowsProfileReadExclusions,
      ).toBeUndefined()
    })

    it('a grant recorded with such a file as an added exclusion refuses the root until the added list is replaced', async () => {
      const proj = join(home, 'proj')
      mkdirSync(proj)
      extraExclusions = [join(proj, '.env')]
      profileStatus = current()
      try {
        const e = await rejection(
          config({}, { allowWrite: [proj], denyRead: [join(proj, '.env')] }),
        )
        expect(e.code).toBe('profile_exclusion_read_grant')
      } finally {
        extraExclusions = []
      }
    })

    it('outside the profile: only its own path', async () => {
      const other = join(work, 'secret')
      mkdirSync(other)
      expect(await denyRead(other)).toEqual([other])
    })

    it('a credentials file, mode deny and mode mask alike, is a read deny on the granted file', async () => {
      for (const mode of ['deny', 'mask'] as const) {
        calls = []
        const cfg = config()
        cfg.credentials = { files: [{ path: join(home, '.npmrc'), mode }] }
        await SandboxManager.initialize(cfg)
        expect(stdinOf('acl grant')?.denyRead).toEqual([join(home, '.npmrc')])
        expect(stdinOf('acl grant')?.read).toEqual([])
        await SandboxManager.reset()
      }
    })

    it('read denies and session allows: the ranking matches the table srt-win is tested against', () => {
      const table = readFileSync(
        join(
          __dirname,
          '..',
          '..',
          'vendor',
          'srt-win-src',
          'tests',
          'data',
          'read-deny-cases.txt',
        ),
        'utf8',
      )
      const at = (p: string) => {
        const t = p.trim()
        if (!t.startsWith('P')) throw new Error(`'${t}' is not beneath P`)
        return 'C:\\Users\\me' + t.slice(1)
      }
      const list = (v: string) =>
        v
          .split(' | ')
          .map(x => x.trim())
          .filter(x => x !== '')
          .map(at)
      type Case = Record<
        | 'read'
        | 'write'
        | 'deny'
        | 'credential'
        | 'handed-read'
        | 'handed-write'
        | 'handed-deny'
        | 'except'
        | 'expect',
        string[]
      > & { name: string; reduced: boolean }
      const blank = (name: string): Case => ({
        name,
        read: [],
        write: [],
        deny: [],
        credential: [],
        'handed-read': [],
        'handed-write': [],
        'handed-deny': [],
        except: [],
        expect: [],
        reduced: false,
      })
      const recorded: { path: string; kind: string }[] = []
      const cases: Case[] = []
      for (const raw of table.split(/\r?\n/)) {
        const line = raw.trim()
        if (line === '' || line.startsWith('#')) continue
        const colon = line.indexOf(':')
        const key = line.slice(0, colon)
        const value = line.slice(colon + 1).trim()
        if (key === 'recorded') {
          for (const item of value.split(' | ')) {
            const [kind, ...rest] = item.trim().split(' ')
            recorded.push({ kind: kind!, path: at(rest.join(' ')) })
          }
        } else if (key === 'case') {
          cases.push(blank(value))
        } else {
          const c = cases[cases.length - 1]!
          expect(Object.keys(c)).toContain(key)
          c[key as Exclude<keyof Case, 'name' | 'reduced'>] = list(value)
          if (key === 'except') c.reduced = true
        }
      }
      expect(cases.length).toBeGreaterThanOrEqual(12)
      const key = (p: string) =>
        p.toLowerCase().replace(/\\+$/, '').split('\\').join('/')
      const covers = (dir: string, p: string) =>
        key(p) === key(dir) || key(p).startsWith(key(dir) + '/')
      const depth = (p: string) => key(p).split('/').length
      for (const c of cases) {
        const ranked = winUtils.rankWindowsFsAccess({
          allowRead: c.read,
          allowWrite: c.write,
          denyRead: c.deny,
          denyWrite: [],
          credentialDeny: c.credential,
        })
        expect({
          name: c.name,
          read: ranked.grantRead,
          write: ranked.grantWrite,
          deny: ranked.denyRead,
        }).toEqual({
          name: c.name,
          read: c['handed-read'],
          write: c['handed-write'],
          deny: c['handed-deny'],
        })
        const allows = [...ranked.grantRead, ...ranked.grantWrite]
        const denied = recorded
          .filter(r => ['container', 'granted', 'file'].includes(r.kind))
          .filter(r => {
            const best = (list: string[]) =>
              Math.max(
                0,
                ...list.filter(e => covers(e, r.path)).map(e => depth(e)),
              )
            const deny = best(ranked.denyRead)
            return deny > 0 && deny >= best(allows)
          })
          .map(r => r.path)
        expect({ name: c.name, denied: denied.sort() }).toEqual({
          name: c.name,
          denied: [...c.expect].sort(),
        })
        const sent = winUtils.windowsGrantsBeneathDenies(
          allows,
          ranked.denyRead,
        )
        if (c.reduced) {
          expect({ name: c.name, sent: [...sent].sort() }).toEqual({
            name: c.name,
            sent: [...c.except].sort(),
          })
        }
        const asSrtWinDenies = (grants: readonly string[]) =>
          recorded
            .filter(r => ['container', 'granted', 'file'].includes(r.kind))
            .filter(r =>
              ranked.denyRead.some(
                d =>
                  key(d) === key(r.path) ||
                  (covers(d, r.path) &&
                    !grants.some(
                      g =>
                        covers(d, g) && key(g) !== key(d) && covers(g, r.path),
                    )),
              ),
            )
            .map(r => r.path)
            .sort()
        expect({ name: c.name, denied: asSrtWinDenies(sent) }).toEqual({
          name: c.name,
          denied: [...c.expect].sort(),
        })
        expect(asSrtWinDenies(allows)).toEqual([...c.expect].sort())
      }
    })

    it('a per-command read deny is sent with the session grants that lie beneath it', async () => {
      const proj = join(home, 'proj')
      const lib = join(home, 'Documents', 'lib')
      mkdirSync(proj)
      mkdirSync(lib, { recursive: true })
      await SandboxManager.initialize(
        config({}, { allowWrite: [proj], allowRead: [lib] }),
      )
      const { argv } = await SandboxManager.wrapWithSandboxArgv(
        'echo x',
        undefined,
        config({}, { denyRead: [home, proj], allowWrite: [] }),
      )
      const flag = (name: string) => argv.filter((_, i) => argv[i - 1] === name)
      expect(flag('--deny-read')).toEqual([home, proj])
      expect(new Set(flag('--deny-read-except'))).toEqual(new Set([proj, lib]))
      const plain = await SandboxManager.wrapWithSandboxArgv(
        'echo x',
        undefined,
        config({}, { denyRead: [join(home, '.cargo')], allowWrite: [] }),
      )
      expect(plain.argv).not.toContain('--deny-read-except')
    })

    it('the stamps cannot be written → initialize() rejects', async () => {
      syncResult['acl grant'] = exit(1, '', 'access denied')
      const e = await rejection(config({}, { denyRead: [home] }))
      expect(e.code).toBe('acl_grant_failed')
      expect(SandboxManager.getConfig()).toBeUndefined()
    })

    it('a per-command read deny above thousands of recorded paths is one argument, not one per path', async () => {
      const big = Array.from({ length: 4000 }, (_, i) =>
        rec(
          i % 2 ? 'granted' : 'file',
          'AppData',
          'Local',
          `application-${i % 50}`,
          `entry-with-a-long-name-${i}`,
        ),
      )
      expect(big.map(r => r.path).join(' --deny-read ').length).toBeGreaterThan(
        32_767,
      )
      extraRecorded = big
      profileStatus = current()
      try {
        await SandboxManager.initialize(config())
        mkdirSync(join(home, 'AppData'), { recursive: true })
        const cfg = config(
          {},
          {
            denyRead: [join(home, 'AppData'), join(home, '.cargo')],
            allowWrite: [],
          },
        )
        const { argv } = await SandboxManager.wrapWithSandboxArgv(
          'echo x',
          undefined,
          cfg,
        )
        const denied = argv.filter((_, i) => argv[i - 1] === '--deny-read')
        expect(denied).toEqual([join(home, 'AppData'), join(home, '.cargo')])
        expect(argv.some(a => a.includes('entry-with-a-long-name'))).toBe(false)
        expect(argv.join(' ').length).toBeLessThan(8000)
      } finally {
        extraRecorded = []
      }
    })
  })

  describe('a session allowRead against the exclusions the grant recorded', () => {
    const allowRead = (...paths: string[]) => config({}, { allowRead: paths })
    const refused = async (
      cfg: SandboxRuntimeConfig,
      options?: Parameters<typeof SandboxManager.initialize>[3],
    ) => {
      const e = await rejection(cfg, options)
      await explained(pathsOf(cfg), () => {
        expect(e).toBeInstanceOf(WindowsSandboxError)
        expect(`${e.code}: ${e.message}`).toStartWith(
          'profile_exclusion_read_grant: ',
        )
        expect(names()).toEqual(['profile status'])
        expect(SandboxManager.getConfig()).toBeUndefined()
      })
      return e
    }

    it('equal to an exclusion → refused', async () => {
      const e = await refused(allowRead(join(home, '.ssh')))
      expect(e.message).toContain('is the excluded')
    })

    it('inside an exclusion → refused', async () => {
      const e = await refused(allowRead(join(home, '.ssh', 'keys')))
      expect(e.message).toContain('lies inside the excluded')
    })

    it('above an exclusion → refused: a store created again beneath it would inherit the grant', async () => {
      const e = await refused(allowRead(home))
      expect(e.message).toContain('contains the excluded')
    })

    it('an exclusion added when the grant was made, not a built-in one → refused', async () => {
      await refused(allowRead(join(home, '.myapp')))
    })

    it('the exclusions are the recorded ones, not a list of this library’s', async () => {
      profileStatus = { ...current(), exclusions: [join(home, '.myapp')] }
      await SandboxManager.initialize(allowRead(join(home, '.ssh')))
      expect(stdinOf('acl grant')?.read).toEqual([join(home, '.ssh')])
    })

    it('a wildcard entry: the matching directory and the one above it → refused; its sibling is granted', async () => {
      const app = join(home, 'AppData', 'Local', 'App')
      await refused(allowRead(join(app, 'EBWebView')))
      await SandboxManager.reset()
      calls = []
      await refused(allowRead(app))
      await SandboxManager.reset()
      calls = []
      await SandboxManager.initialize(allowRead(join(app, 'data')))
      expect(stdinOf('acl grant')?.read).toEqual([join(app, 'data')])
    })

    describe('the look beneath a path above a wildcard entry', () => {
      const own = () => ({
        exclusions: [join(home, 'apps', '*', '*', 'store')],
        ungrantedOnly: [],
      })
      const apps = () => join(home, 'apps')
      const check = (p: string, write = false) =>
        winUtils.windowsProfileExclusionConflicts([p], own(), { write })

      it('admits a path that was looked at and holds no match, or is not there', () => {
        mkdirSync(join(apps(), 'a', 'b', 'other'), { recursive: true })
        writeFileSync(join(apps(), 'file'), '')
        expect(check(apps())).toEqual([])
        expect(check(join(apps(), 'a'))).toEqual([])
        expect(check(join(apps(), 'not-yet'))).toEqual([])
        expect(check(join(apps(), 'file', 'x'))).toEqual([])
        mkdirSync(join(apps(), 'a', 'b', 'store'))
        expect(check(apps())).toMatchObject([{ relation: 'above' }])
        expect(check(apps())[0]!.unexamined).toBeUndefined()
        expect(check(join(apps(), 'a'), true)).toMatchObject([
          { relation: 'above', access: 'write' },
        ])
      })

      const failing = (
        code: string,
        on: 'realpath' | 'lstat' | 'readdir',
        match: (p: string) => boolean,
      ) => {
        const err = () =>
          Object.assign(new Error(`${code}: simulated`), { code })
        if (on === 'realpath') {
          const real = fs.realpathSync.native
          return spyOn(fs.realpathSync, 'native').mockImplementation(((
            p: string,
          ) => {
            if (match(String(p))) throw err()
            return real(p)
          }) as typeof fs.realpathSync.native)
        }
        const real = fs[`${on}Sync`] as (...a: unknown[]) => unknown
        return spyOn(fs, `${on}Sync`).mockImplementation(((
          p: unknown,
          ...rest: unknown[]
        ) => {
          if (match(String(p))) throw err()
          return real(p, ...rest)
        }) as never)
      }

      for (const [code, on, where] of [
        ['EACCES', 'readdir', 'the path itself'],
        ['EIO', 'readdir', 'the path itself'],
        ['EPERM', 'lstat', 'the path itself'],
        ['EACCES', 'realpath', 'the path itself'],
        ['EIO', 'realpath', 'the path itself'],
        ['ELOOP', 'realpath', 'the path itself'],
        ['EACCES', 'readdir', 'a level beneath it'],
        ['EBUSY', 'lstat', 'a level beneath it'],
      ] as const) {
        it(`refuses when ${on} fails with ${code} on ${where}`, () => {
          mkdirSync(join(apps(), 'a', 'b'), { recursive: true })
          const target =
            where === 'the path itself' ? apps() : join(apps(), 'a')
          const spy = failing(code, on, p => p === target)
          try {
            for (const write of [false, true]) {
              const got = check(apps(), write)
              expect(got).toMatchObject([{ relation: 'above' }])
              expect(got[0]!.unexamined).toContain(code)
            }
          } finally {
            spy.mockRestore()
          }
          expect(check(apps())).toEqual([])
        })
      }

      it('a level that is not there, or not a directory, is no match and no failure', () => {
        mkdirSync(join(apps(), 'a'), { recursive: true })
        for (const code of ['ENOENT', 'ENOTDIR']) {
          const spy = failing(code, 'readdir', p => p === join(apps(), 'a'))
          try {
            expect(check(apps())).toEqual([])
          } finally {
            spy.mockRestore()
          }
        }
      })

      it('refuses a path that turns out to be a link when it is listed', () => {
        mkdirSync(apps(), { recursive: true })
        const real = fs.lstatSync
        const spy = spyOn(fs, 'lstatSync').mockImplementation(((
          p: unknown,
          ...rest: unknown[]
        ) => {
          const st = (real as (...a: unknown[]) => fs.Stats)(p, ...rest)
          if (String(p) === apps()) st.isSymbolicLink = () => true
          return st
        }) as never)
        try {
          expect(check(apps())[0]?.unexamined).toContain('is a link')
        } finally {
          spy.mockRestore()
        }
      })

      it('never opens, lists or resolves a path on a share or in the device namespace', () => {
        const spies = [
          spyOn(fs.realpathSync, 'native'),
          spyOn(fs, 'realpathSync'),
          spyOn(fs, 'lstatSync'),
          spyOn(fs, 'statSync'),
          spyOn(fs, 'readdirSync'),
          spyOn(fs, 'existsSync'),
        ]
        try {
          for (const p of [
            '\\\\server\\share\\x',
            '\\\\?\\UNC\\server\\share\\x',
            '\\\\.\\UNC\\server\\share\\x',
            '//server/share/x',
            '\\\\?\\GLOBALROOT\\Device\\Mup\\server\\share',
            '\\\\.\\pipe\\x',
          ]) {
            for (const write of [false, true]) {
              expect(
                winUtils.windowsProfileExclusionConflicts([p], lists(), {
                  write,
                }),
              ).toEqual([])
            }
          }
          const shared = {
            exclusions: [
              '\\\\?\\UNC\\server\\profiles\\me\\AppData\\Local\\*\\EBWebView',
            ],
            ungrantedOnly: [],
          }
          for (const p of [
            '\\\\server\\profiles\\me\\AppData\\Local\\tool',
            '\\\\?\\UNC\\server\\profiles\\me\\AppData\\Local\\tool',
          ]) {
            const got = winUtils.windowsProfileExclusionConflicts([p], shared)
            expect(got).toMatchObject([{ relation: 'above' }])
            expect(got[0]!.unexamined).toContain('not on a local drive')
          }
          for (const s of spies) expect(s).not.toHaveBeenCalled()
        } finally {
          for (const s of spies) s.mockRestore()
        }
      })
    })

    it('a wildcard entry refuses a directory above it only while something beneath it matches', async () => {
      const tool = join(home, 'AppData', 'Local', 'npm-cache')
      mkdirSync(join(tool, 'bin'), { recursive: true })
      await SandboxManager.initialize(
        config({}, { allowRead: [tool], allowWrite: [join(tool, 'bin')] }),
      )
      expect(stdinOf('acl grant')).toMatchObject({
        read: [tool],
        write: [join(tool, 'bin')],
      })
      await SandboxManager.reset()
      mkdirSync(join(tool, 'EBWebView'))
      calls = []
      await refused(allowRead(tool))
      await SandboxManager.reset()
      calls = []
      await refused(config({}, { allowWrite: [tool] }))
      const deep = join(home, 'AppData', 'Local', 'deep')
      mkdirSync(join(deep, 'x', 'EBWebView'), { recursive: true })
      const linked = join(home, 'AppData', 'Local', 'linked')
      mkdirSync(linked)
      symlinkSync(
        join(tool, 'EBWebView'),
        join(linked, 'elsewhere'),
        'junction',
      )
      await explained([deep, linked], () => {
        expect(
          winUtils.windowsProfileExclusionConflicts([deep, linked], lists()),
        ).toEqual([])
      })
    })

    it('a link that resolves into an excluded store → refused (a junction, and a name spelled like an 8.3 short name: both are resolved by the final-path lookup)', async () => {
      for (const name of ['to-ssh', 'SSH~1']) {
        calls = []
        const link = join(home, 'Documents', name)
        symlinkSync(join(home, '.ssh'), link, 'junction')
        const e = await refused(allowRead(link))
        expect(e.message).toContain('is the excluded')
        await SandboxManager.reset()
      }
      calls = []
      const e = await refused(allowRead(join(homeAsSpelled, '.ssh')))
      expect(e.message).toContain('is the excluded')
    })

    it('another case → refused', async () => {
      expect(
        winUtils.windowsProfileExclusionConflicts([join(home, '.ssh')], {
          exclusions: [join(home, '.SSH').toUpperCase()],
          ungrantedOnly: [],
        }),
      ).toHaveLength(1)
      const upper = join(home, '.SSH')
      if (existsSync(upper)) {
        await refused(allowRead(upper))
      }
    })

    it('the embedder’s override admits an excluded path and one inside it, by the object it resolves to', async () => {
      const link = join(home, 'Documents', 'to-ssh')
      symlinkSync(join(home, '.ssh'), link, 'junction')
      for (const [path, override] of [
        [join(home, '.ssh'), join(home, '.ssh')],
        [join(home, '.ssh', 'keys'), join(home, '.ssh', 'keys')],
        [link, join(home, '.ssh')],
      ]) {
        calls = []
        await SandboxManager.initialize(allowRead(path), undefined, false, {
          dangerouslyAllowReadOfProfileExclusions: [override],
        })
        expect(stdinOf('acl grant')?.read).toEqual([path])
        const argv = calls.find(c => c.sub === 'grant')?.argv ?? []
        expect(
          argv.slice(argv.indexOf('--allow-profile-exclusion')).slice(0, 2),
        ).toEqual(['--allow-profile-exclusion', override])
        await SandboxManager.reset()
      }
    })

    it('without the override srt-win is given no such flag', async () => {
      await SandboxManager.initialize(allowRead(join(home, 'Documents')))
      expect(calls.find(c => c.sub === 'grant')?.argv).not.toContain(
        '--allow-profile-exclusion',
      )
    })

    describe('write roots are measured the same way, with no override', () => {
      const allowWrite = (...paths: string[]) =>
        config({}, { allowWrite: paths })

      it('a write root that is a protected path → refused', async () => {
        const e = await refused(allowWrite(join(home, '.ssh')))
        expect(e.message).toContain('allowWrite')
        expect(e.message).toContain('is the excluded')
      })

      it('a write root inside a protected path → refused', async () => {
        const e = await refused(allowWrite(join(home, '.ssh', 'keys')))
        expect(e.message).toContain('lies inside the excluded')
      })

      it('a write root above a protected path (the profile directory, AppData) → refused, with the way out', async () => {
        for (const root of [
          home,
          join(home, 'AppData'),
          join(home, '.cargo'),
        ]) {
          calls = []
          const e = await refused(allowWrite(root))
          expect(e.message).toContain('contains')
          expect(e.message).toContain('narrower working directory')
          await SandboxManager.reset()
        }
      })

      it('the override admits no write root: not the path, not inside it, not above it', async () => {
        for (const root of [
          join(home, '.ssh'),
          join(home, '.ssh', 'keys'),
          home,
        ]) {
          calls = []
          await refused(allowWrite(root), {
            dangerouslyAllowReadOfProfileExclusions: [root],
          })
          await SandboxManager.reset()
        }
      })

      it('one refused write root refuses the session: nothing else is granted either', async () => {
        await refused(allowWrite(work, join(home, '.ssh')))
      })

      it('the temporary directory itself → refused; a directory inside it is a write root as usual', async () => {
        const e = await refused(allowWrite(temp()))
        expect(e.message).toContain('not granted as a whole')
        await SandboxManager.reset()
        calls = []
        await SandboxManager.initialize(allowWrite(join(temp(), 'session')))
        expect(stdinOf('acl grant')?.write).toEqual([join(temp(), 'session')])
      })

      it('a write root that reaches no exclusion, inside the profile or out, is granted', async () => {
        const project = join(home, 'Documents', 'sub')
        await SandboxManager.initialize(allowWrite(project, work))
        expect(new Set(stdinOf('acl grant')?.write)).toEqual(
          new Set([project, work]),
        )
      })

      it('the function: a write path is never admitted', () => {
        const conflicts = (write: boolean) =>
          winUtils.windowsProfileExclusionConflicts(
            [join(home, '.ssh')],
            lists(),
            { override: [join(home, '.ssh')], write },
          )
        expect(conflicts(false)).toEqual([])
        expect(conflicts(true)).toMatchObject([
          { access: 'write', kind: 'protected', relation: 'equal' },
        ])
      })
    })

    it('the override admits only what it names', async () => {
      await refused(allowRead(join(home, '.ssh'), join(home, '.myapp')), {
        dangerouslyAllowReadOfProfileExclusions: [join(home, '.ssh')],
      })
      await SandboxManager.reset()
      calls = []
      await refused(allowRead(join(home, '.ssh', 'keys')), {
        dangerouslyAllowReadOfProfileExclusions: [join(home, '.ssh')],
      })
    })

    it('the override never admits a path above an exclusion', async () => {
      const e = await refused(allowRead(home), {
        dangerouslyAllowReadOfProfileExclusions: [home],
      })
      expect(e.message).toContain('contains the excluded')
    })

    describe('the temporary directory: ungranted as a whole, not closed to a session', () => {
      it('a directory inside it is granted: where a session stages its own', async () => {
        const session = join(temp(), 'session')
        await SandboxManager.initialize(
          allowRead(session, join(session, 'work')),
        )
        expect(new Set(stdinOf('acl grant')?.read)).toEqual(
          new Set([session, join(session, 'work')]),
        )
      })

      it('the directory itself → refused: the grant would cover everything in it', async () => {
        const e = await refused(allowRead(temp()))
        expect(e.message).toContain('not granted as a whole')
        expect(e.message).toContain('grant a directory inside it')
      })

      it('a directory above it → refused', async () => {
        await refused(allowRead(join(home, 'AppData')))
      })

      it('a protected path inside it stays protected: itself and what is inside it → refused', async () => {
        const e = await refused(allowRead(join(temp(), 'keys')))
        expect(e.message).toContain('is the excluded')
        await SandboxManager.reset()
        calls = []
        await refused(allowRead(join(temp(), 'keys', 'sub')))
      })

      it('the override does not admit the directory itself', async () => {
        await refused(allowRead(temp()), {
          dangerouslyAllowReadOfProfileExclusions: [temp()],
        })
      })

      it('the library’s own grant, a fresh directory in the temporary directory, collides with nothing', () => {
        const bundleDir = join(temp(), 'srt-ca-AbC123')
        mkdirSync(bundleDir)
        expect(
          winUtils.windowsProfileExclusionConflicts([bundleDir], lists()),
        ).toEqual([])
      })
    })

    it('the override is not a configuration key', () => {
      const r = WindowsConfigSchema.safeParse({
        dangerouslyAllowReadOfProfileExclusions: ['x'],
      })
      expect(r.success && Object.keys(r.data)).not.toContain(
        'dangerouslyAllowReadOfProfileExclusions',
      )
    })

    it('a path that reaches no exclusion is granted as before', async () => {
      const docs = join(home, 'Documents', 'sub')
      await SandboxManager.initialize(allowRead(docs, work))
      expect(new Set(stdinOf('acl grant')?.read)).toEqual(new Set([docs, work]))
    })
  })

  describe('the srt-win a session runs through, and the session it records', () => {
    describe('an srt-win that is not the build this library was made with', () => {
      const old = (caps: string[] | undefined) => {
        brokerCapabilities = caps
        profileStatus = current()
      }

      const states: [string, () => void][] = [
        ['a grant is recorded', () => {}],
        [
          'no grant is recorded',
          () => {
            profileStatus = { state: 'none' }
            briefGrant = { state: 'none' }
          },
        ],
        [
          'user status does not say whether one is',
          () => {
            briefGrant = undefined
          },
        ],
      ]
      for (const [state, arrange] of states) {
        for (const [what, caps, missing] of [
          ['has no capabilities field', undefined, 'profile-deny-expansion'],
          [
            'reports something that is not a list',
            'all',
            'profile-deny-expansion',
          ],
          ['reports an empty list', [], 'profile-deny-expansion'],
          [
            'lacks the deny expansion',
            ['kept-grant-holders', 'profile-session-grant-check', 'other'],
            'profile-deny-expansion',
          ],
          [
            'lacks the holder check',
            ['profile-deny-expansion', 'profile-session-grant-check'],
            'kept-grant-holders',
          ],
          [
            'lacks its own exclusion check',
            ['profile-deny-expansion', 'kept-grant-holders'],
            'profile-session-grant-check',
          ],
        ] as const) {
          it(`${state} and srt-win ${what}: srt_win_outdated, nothing granted`, async () => {
            old(caps as string[] | undefined)
            arrange()
            for (const cfg of [
              config(),
              config({}, { denyRead: [home] }),
              config({}, { allowWrite: [] }),
            ]) {
              calls = []
              const e = await rejection(cfg)
              expect(e).toBeInstanceOf(WindowsSandboxError)
              expect(e.code).toBe('srt_win_outdated')
              expect(e.message).toContain(`'${missing}'`)
              expect(names()).toEqual([])
              expect(SandboxManager.getConfig()).toBeUndefined()
            }
          })
        }

        it(`${state} and srt-win lists every capability: the session starts`, async () => {
          old(SRT_WIN_CAPABILITIES)
          arrange()
          await SandboxManager.initialize(config({}, { denyRead: [home] }))
          expect(stdinOf('acl grant')?.denyRead).toEqual([home])
        })
      }

      it('a per-command read deny is checked against the srt-win it will run through, each one, and a no is asked again', async () => {
        const other = join(work, 'other-srt-win.exe')
        writeFileSync(other, 'x')
        const via = (path?: string) =>
          SandboxManager.wrapWithSandboxArgv('echo x', undefined, {
            ...config({}, { denyRead: [join(home, '.cargo')], allowWrite: [] }),
            ...(path && { windows: { srtWin: { path } } }),
          })
        const refusedBy = async (path?: string) => {
          try {
            await via(path)
          } catch (e) {
            return (e as WindowsSandboxError).code
          }
          return undefined
        }
        const asked = () => names().filter(n => n === 'profile status').length
        old(undefined)
        expect(await refusedBy()).toBe('srt_win_outdated')
        expect(asked()).toBe(1)
        old(SRT_WIN_CAPABILITIES)
        const { argv } = await via()
        expect(argv.filter((_, i) => argv[i - 1] === '--deny-read')).toEqual([
          join(home, '.cargo'),
        ])
        expect(asked()).toBe(2)
        await via()
        expect(asked()).toBe(2)
        old(undefined)
        expect(await refusedBy(other)).toBe('srt_win_outdated')
        expect(asked()).toBe(3)
        old(SRT_WIN_CAPABILITIES)
        expect(await refusedBy(other)).toBeUndefined()
        expect(asked()).toBe(4)
        await via(other)
        await via()
        expect(asked()).toBe(4)
        writeFileSync(other, 'replaced with something longer')
        await via(other)
        expect(asked()).toBe(5)
        await SandboxManager.reset()
        calls = []
        old(undefined)
        let code: string | undefined
        try {
          await SandboxManager.wrapWithSandboxArgv(
            'echo x',
            undefined,
            config({}, { allowWrite: [] }),
          )
        } catch (e) {
          code = (e as WindowsSandboxError).code
        }
        expect(code).toBe('srt_win_outdated')
        expect(names()).toEqual(['profile status'])
      })

      it("within a session a per-command srt-win that differs from the session's is asked too", async () => {
        await SandboxManager.initialize(config())
        const other = join(work, 'other-srt-win.exe')
        writeFileSync(other, 'x')
        const cfg = (path?: string) => ({
          ...config({}, { denyRead: [join(home, '.cargo')], allowWrite: [] }),
          ...(path && { windows: { srtWin: { path } } }),
        })
        calls = []
        await SandboxManager.wrapWithSandboxArgv('echo x', undefined, cfg())
        expect(names()).toEqual([])
        old(undefined)
        let code: string | undefined
        try {
          await SandboxManager.wrapWithSandboxArgv(
            'echo x',
            undefined,
            cfg(other),
          )
        } catch (e) {
          code = (e as WindowsSandboxError).code
        }
        expect(code).toBe('srt_win_outdated')
        expect(names()).toEqual(['profile status'])
      })

      it('a grant made after initialize(): a per-command deny on the profile directory is handed over as srt-win expands it', async () => {
        profileStatus = { state: 'none' }
        briefGrant = { state: 'none' }
        await SandboxManager.initialize(config({}, { allowWrite: [] }))
        expect(SandboxManager.getWindowsProfileRead()).toBe('absent')
        profileStatus = current()
        briefGrant = { state: 'present' }
        calls = []
        const { argv } = await SandboxManager.wrapWithSandboxArgv(
          'echo x',
          undefined,
          config({}, { denyRead: [home], allowWrite: [] }),
        )
        expect(argv.filter((_, i) => argv[i - 1] === '--deny-read')).toEqual([
          home,
        ])
        expect(argv).toContain('--write-restricted-token')
        expect(names()).toEqual([])
      })
    })

    it('a session registers as a holder of the grant even with nothing to grant, and releases it at reset', async () => {
      const cfg = config({}, { allowWrite: [] })
      await SandboxManager.initialize(cfg)
      expect(SandboxManager.getWindowsProfileRead()).toBe('granted')
      expect(names()).toEqual(['profile status', 'acl grant'])
      expect(calls[1].argv).toContain('--persistent')
      expect(calls[1].argv).toContain(`${process.pid}`)
      expect(stdinOf('acl grant')).toEqual({
        read: [],
        write: [],
        denyRead: [],
        denyWrite: [],
      })
      await SandboxManager.reset()
      expect(names().slice(2)).toEqual(['acl revoke', 'acl restore'])
      calls = []
      profileStatus = { state: 'none' }
      briefGrant = { state: 'none' }
      await SandboxManager.initialize(cfg)
      expect(SandboxManager.getWindowsProfileRead()).toBe('absent')
      expect(names()).toEqual(['acl grant'])
      expect(calls[0].argv).toContain('--persistent')
      const inSession = await SandboxManager.wrapWithSandboxArgv('echo x')
      expect(inSession.argv[inSession.argv.indexOf('--held-by') + 1]).toBe(
        `${process.pid}`,
      )
      await SandboxManager.reset()
      expect(names()).toEqual(['acl grant', 'acl revoke', 'acl restore'])
      calls = []
      profileStatus = { state: 'none', capabilities: SRT_WIN_CAPABILITIES }
      const alone = await SandboxManager.wrapWithSandboxArgv(
        'echo x',
        undefined,
        config({}, { allowWrite: [] }),
      )
      expect(alone.argv).toContain('--write-restricted-token')
      expect(alone.argv).not.toContain('--held-by')
      expect(names()).toEqual(['profile status'])
    })

    it('a recorded grant is kept, not removed', async () => {
      briefGrant = { state: 'present' }
      await SandboxManager.initialize(config())
      expect(names()).toEqual(['profile status', 'acl grant'])
    })
  })

  describe('the install applies the grant', () => {
    const srtWin = { exe: process.execPath, prependArgs: [] }

    it('installWindowsSandboxAsync: after the elevated step, the grant runs as this process, with progress and the exclusions', async () => {
      grantRun.stderr = [
        'srt-win: profile grant: 1/2 top-level item(s) done\n',
        'srt-win: profile grant: 2/2 top-level item(s) done\n',
      ]
      const progress: string[] = []
      const r = await winUtils.installWindowsSandboxAsync({
        srtWin,
        profileExclude: ['.myapp'],
        onProfileGrantProgress: l => progress.push(l),
      })
      expect(asyncCalls.map(a => a.slice(0, 2).join(' '))).toEqual([
        'install',
        'status',
        'profile grant',
      ])
      expect(asyncCalls[2]).toEqual([
        'profile',
        'grant',
        '--json',
        '--exclude',
        '.myapp',
      ])
      expect(progress).toHaveLength(2)
      expect(r.profileGrant).toEqual({
        applied: true,
        userSid: REAL_USER,
        result: expect.objectContaining({ profile: home, granted: 30 }),
      })
      expect(r.user.provisioned).toBe(true)
    })

    it('installWindowsSandbox (sync): the same calls, progress delivered at the end', () => {
      syncResult['profile grant'] = exit(
        0,
        grantJson(),
        'srt-win: profile grant: 1/1 top-level item(s) done',
      )
      const progress: string[] = []
      const r = installWindowsSandbox({
        srtWin,
        profileExclude: ['.myapp'],
        onProfileGrantProgress: l => progress.push(l),
      })
      expect(names()).toEqual(['install ', 'profile grant'])
      expect(calls[1].argv).toEqual(['--json', '--exclude', '.myapp'])
      expect(progress).toEqual([
        'srt-win: profile grant: 1/1 top-level item(s) done',
      ])
      expect(r.profileGrant?.applied).toBe(true)
    })

    it('a re-run of an existing install refreshes the grant: the grant call is the same', async () => {
      await winUtils.installWindowsSandboxAsync({ srtWin })
      await winUtils.installWindowsSandboxAsync({ srtWin })
      expect(
        asyncCalls.filter(a => a[0] === 'profile').map(a => a.join(' ')),
      ).toEqual(['profile grant --json', 'profile grant --json'])
    })

    it('a cancelled elevation prompt: nothing was installed, no grant is attempted', async () => {
      installCode = 10
      const r = await winUtils.installWindowsSandboxAsync({ srtWin })
      expect(r.cancelled).toBe(true)
      expect(r.profileGrant).toBeUndefined()
      expect(asyncCalls.some(a => a[0] === 'profile')).toBe(false)
      expect(installWindowsSandbox({ srtWin }).profileGrant).toBeUndefined()
      expect(names()).not.toContain('profile grant')
    })

    it('a failed elevated step: no grant is attempted', async () => {
      installCode = 14
      // eslint-disable-next-line @typescript-eslint/await-thenable -- bun:test types .rejects.toMatchObject() as void; the await is required at runtime
      await expect(
        winUtils.installWindowsSandboxAsync({ srtWin }),
      ).rejects.toMatchObject({ code: 'install_user_failed' })
      expect(asyncCalls.some(a => a[0] === 'profile')).toBe(false)
    })

    it('an install run as a service account leaves the grant unapplied and says so', async () => {
      for (const sid of ['S-1-5-18', 'S-1-5-19', 'S-1-5-20']) {
        realUserSid = sid
        asyncCalls = []
        calls = []
        const r = await winUtils.installWindowsSandboxAsync({ srtWin })
        expect(r.profileGrant).toEqual({
          applied: false,
          reason: expect.stringContaining('service account'),
        })
        expect(asyncCalls.some(a => a[0] === 'profile')).toBe(false)
        expect(installWindowsSandbox({ srtWin }).profileGrant?.applied).toBe(
          false,
        )
        expect(names()).not.toContain('profile grant')
      }
    })

    it('skipProfileGrant: installed without the grant, and the next initialize() reports it missing', async () => {
      const r = await winUtils.installWindowsSandboxAsync({
        srtWin,
        skipProfileGrant: true,
      })
      expect(r.profileGrant).toEqual({
        applied: false,
        reason: expect.stringContaining('skipProfileGrant'),
      })
      expect(asyncCalls.some(a => a[0] === 'profile')).toBe(false)
      briefGrant = { state: 'none' }
      await SandboxManager.initialize(config())
      expect(SandboxManager.getWindowsProfileRead()).toBe('absent')
    })

    it('the grant is announced once, right before it is applied, and not when it is skipped', async () => {
      const notices: string[] = []
      const onProfileGrantStart = (n: string) => notices.push(n)
      await winUtils.installWindowsSandboxAsync({ srtWin, onProfileGrantStart })
      installWindowsSandbox({ srtWin, onProfileGrantStart })
      expect(notices).toHaveLength(2)
      expect(notices[0]).toBe(winUtils.windowsProfileGrantNotice(homedir()))
      for (const said of [
        homedir(),
        'readable to sandboxed commands',
        'except',
        '.npmrc',
        'pip.ini',
        'NuGet.Config',
        'settings.xml',
        'gradle.properties',
        '.gitconfig',
        '--skip-profile-grant',
        'profile forget',
      ]) {
        expect(notices[0]).toContain(said)
      }
      expect(notices[0]).not.toContain('\n')
      await winUtils.installWindowsSandboxAsync({
        srtWin,
        onProfileGrantStart,
        skipProfileGrant: true,
      })
      sessionUserSid = 'S-1-5-21-9-9-9-1001'
      await winUtils.installWindowsSandboxAsync({ srtWin, onProfileGrantStart })
      expect(notices).toHaveLength(2)
    })

    it('whose profile: only the session owner’s own install grants', async () => {
      const skip = winUtils.windowsProfileGrantSkipReason
      const me = 'S-1-5-21-1-2-3-1001'
      const admin = 'S-1-5-21-1-2-3-500'
      expect(skip({ realUserSid: me, sessionUserSid: me })).toBeUndefined()
      expect(
        skip({ realUserSid: me, sessionUserSid: me.toLowerCase() }),
      ).toBeUndefined()
      expect(skip({ realUserSid: admin, sessionUserSid: me })).toMatch(
        /in a session that belongs to/,
      )
      expect(skip({ realUserSid: me })).toMatch(/could not be determined/)
      for (const sid of ['S-1-5-18', 'S-1-5-19', 'S-1-5-20']) {
        expect(skip({ realUserSid: sid, sessionUserSid: sid })).toMatch(
          /service account/,
        )
        expect(skip({ realUserSid: sid })).toMatch(/service account/)
      }
      expect(
        skip(
          { realUserSid: me, sessionUserSid: me },
          { skipProfileGrant: true },
        ),
      ).toMatch(/skipProfileGrant/)
      for (const [sid, why] of [
        [admin, /session that belongs to/],
        [null, /could not be determined/],
      ] as const) {
        sessionUserSid = sid
        asyncCalls = []
        const r = await winUtils.installWindowsSandboxAsync({ srtWin })
        expect(r.profileGrant?.applied).toBe(false)
        expect(
          r.profileGrant?.applied === false && r.profileGrant.reason,
        ).toMatch(why)
        expect(asyncCalls.some(a => a[0] === 'profile')).toBe(false)
      }
      sessionUserSid = admin
      expect(getWindowsSandboxUserStatus({ srtWin }).sessionUserSid).toBe(admin)
      sessionUserSid = null
      expect(
        getWindowsSandboxUserStatus({ srtWin }).sessionUserSid,
      ).toBeUndefined()
    })

    it('the grant fails → profile_grant_failed, saying the sandbox itself is installed', async () => {
      grantRun = {
        stderr: ['an excluded directory could not be denied'],
        stdout: '',
        code: 1,
      }
      const e = (await winUtils
        .installWindowsSandboxAsync({ srtWin })
        .catch(e => e)) as WindowsSandboxError
      expect(e).toBeInstanceOf(WindowsSandboxError)
      expect(e.code).toBe('profile_grant_failed')
      expect(e.message).toContain('is installed, but')
      expect(e.message).toContain('could not be denied')
      syncResult['profile grant'] = exit(1, '', 'boom')
      expect(() => installWindowsSandbox({ srtWin })).toThrow(
        expect.objectContaining({ code: 'profile_grant_failed' }),
      )
    })

    it('the grant has its own timeout', async () => {
      grantRun = { stderr: [], stdout: '', code: null }
      const e = (await winUtils
        .installWindowsSandboxAsync({ srtWin, profileGrantTimeoutMs: 20 })
        .catch(e => e)) as WindowsSandboxError
      expect(e.code).toBe('profile_grant_failed')
      expect(e.message).toContain('did not finish in time')
      expect(e.message).toContain('20ms')
    })
  })

  describe('the exported calls', () => {
    const srtWin = { exe: process.execPath, prependArgs: [] }

    it('grantWindowsProfileRead: argv, progress lines, result', async () => {
      grantRun.stderr = [
        'srt-win: profile grant: 1/3 top-level item(s) done\nsrt-win: profile gr',
        'ant: 2/3 top-level item(s) done\n',
        'srt-win: profile grant: 3/3 top-level item(s) done',
      ]
      const progress: string[] = []
      const r = await winUtils.grantWindowsProfileRead({
        exclude: [join(home, '.myapp'), '.other'],
        onProgress: l => progress.push(l),
        srtWin,
      })
      expect(asyncCalls).toEqual([
        [
          'profile',
          'grant',
          '--json',
          '--exclude',
          join(home, '.myapp'),
          '--exclude',
          '.other',
        ],
      ])
      expect(progress).toEqual([
        'srt-win: profile grant: 1/3 top-level item(s) done',
        'srt-win: profile grant: 2/3 top-level item(s) done',
        'srt-win: profile grant: 3/3 top-level item(s) done',
      ])
      expect(r).toEqual({
        profile: home,
        containers: 4,
        granted: 30,
        files: 6,
        denied: 50,
        placeholders: 20,
        writes: 90,
        unchanged: 0,
        removed: 1,
        skipped: [{ path: join(home, 'link'), reason: 'reparse point' }],
        notGranted: [],
        selfClosed: [],
        unverifiable: [],
        unprotected: [],
        staleAllow: [],
        forgottenRoots: [],
        elapsedMs: 1234,
      })
    })

    describe('objects in the profile that its user may not change', () => {
      const item = (rel: string, reason: string) => ({
        path: join(home, rel),
        reason,
      })
      const classes = () => ({
        not_granted: [item('AppData/Roaming/Microsoft/Installer', 'no right')],
        self_closed: [item('.ssh', 'closed by its own access list')],
        unverifiable: [
          {
            ...item('.kube', 'cannot be read'),
            caller_reads: false,
            cause: 'acl_unreadable',
          },
        ],
        unprotected: [item('.docker', 'readable by its own access list')],
      })

      it('the grant succeeds and reports them by class', async () => {
        syncResult['profile grant'] = undefined as never
        const json = {
          ...JSON.parse(grantJson()),
          ...classes(),
          forgotten_roots: [item('.config', 'lies above an exclusion')],
        }
        grantRun = { code: 0, stderr: [], stdout: JSON.stringify(json) }
        const r = await winUtils.grantWindowsProfileRead({ srtWin })
        expect(r.notGranted).toEqual(classes().not_granted)
        expect(r.selfClosed).toEqual(classes().self_closed)
        expect(r.unverifiable).toEqual([
          {
            ...item('.kube', 'cannot be read'),
            callerReads: false,
            cause: 'acl_unreadable',
          },
        ])
        expect(r.unprotected).toEqual(classes().unprotected)
        expect(r.staleAllow).toEqual([])
        expect(r.forgottenRoots).toEqual([
          { path: join(home, '.config'), reason: 'lies above an exclusion' },
        ])
      })

      it('the status lists them, and the grant is current all the same', () => {
        profileStatus = { ...current(), ...classes() }
        const st = winUtils.getWindowsProfileReadStatus({ srtWin })
        expect(st.state).toBe('current')
        expect(st.notGranted).toEqual(classes().not_granted)
        expect(st.selfClosed).toEqual(classes().self_closed)
        expect(
          st.unverifiable.map(i => [i.path, i.callerReads, i.cause]),
        ).toEqual([[join(home, '.kube'), false, 'acl_unreadable']])
        expect(st.unprotected).toEqual(classes().unprotected)
        profileStatus = { ...current(), unprotected: 'yes', self_closed: [7] }
        const plain = winUtils.getWindowsProfileReadStatus({ srtWin })
        expect(plain.unprotected).toEqual([])
        expect(plain.selfClosed).toEqual([])
        expect(plain.notGranted).toEqual([])
      })

      it('a session starts on such a grant; what was found is surfaced as typed warnings that claim no more than that', async () => {
        const unverifiable = (
          rel: string,
          caller_reads: boolean | 'unknown',
          cause: string,
        ) => ({ ...item(rel, `reason of ${rel}`), caller_reads, cause })
        profileStatus = {
          ...current(),
          ...classes(),
          unverifiable: [
            unverifiable('.kube', false, 'acl_unreadable'),
            unverifiable('.oci', true, 'acl_unreadable'),
            unverifiable('.snowsql', 'unknown', 'account_unknown'),
            unverifiable('.kaggle', 'unknown', 'not_local'),
          ],
          stale_allow: [item('Old', 'could not be removed')],
        }
        await SandboxManager.initialize(config())
        expect(SandboxManager.getWindowsProfileRead()).toBe('granted')
        const warnings = SandboxManager.getWindowsProfileReadWarnings()
        expect(warnings.map(w => w.code)).toEqual([
          'profile_exclusion_unprotected',
          'profile_exclusion_unverifiable',
          'profile_stale_allow',
        ])
        const [open, unknown, stale] = warnings
        expect(open!.paths.map(p => p.path)).toEqual([
          join(home, '.docker'),
          join(home, '.oci'),
        ])
        expect(open!.message).toContain('by their own access lists')
        expect(open!.message).toContain('you can read all the same')
        expect(open!.message).toContain(join(home, '.oci'))
        expect(unknown!.paths.map(p => p.path)).toEqual([
          join(home, '.kube'),
          join(home, '.snowsql'),
          join(home, '.kaggle'),
        ])
        expect(unknown!.paths[0]).toEqual({
          path: join(home, '.kube'),
          reason: 'reason of .kube',
          callerReads: false,
          cause: 'acl_unreadable',
        })
        expect(unknown!.message).toContain(
          'you cannot read their content either',
        )
        expect(unknown!.message).toContain('the sandbox account is not known')
        expect(unknown!.message).toContain('were not examined')
        expect(unknown!.message).not.toContain(join(home, '.oci'))
        for (const w of warnings) {
          expect(w.message).not.toMatch(/probabl|unlikely/i)
        }
        expect(stale!.paths).toEqual([item('Old', 'could not be removed')])
        await SandboxManager.reset()
        expect(SandboxManager.getWindowsProfileReadWarnings()).toEqual([])
        expect(
          windowsProfileReadWarningsOf({
            unprotected: [],
            unverifiable: [
              {
                path: 'p',
                reason: 'r',
                callerReads: false,
                cause: 'acl_unreadable',
              },
            ],
            staleAllow: [],
          }).map(w => [w.code, w.message.includes('not known')]),
        ).toEqual([['profile_exclusion_unverifiable', false]])
        profileStatus = {
          ...current(),
          ...classes(),
          unprotected: [],
          unverifiable: [],
        }
        await SandboxManager.initialize(config())
        expect(SandboxManager.getWindowsProfileReadWarnings()).toEqual([])
      })

      it('a command that runs into a profile grant in progress is told so', () => {
        syncResult['profile status'] = exit(25, '', 'srt-win: error: …')
        let thrown: unknown
        try {
          winUtils.getWindowsProfileReadStatus({ srtWin })
        } catch (e) {
          thrown = e
        }
        expect((thrown as WindowsSandboxError).code).toBe(
          'profile_operation_in_progress',
        )
        const parsed = winUtils.parseWindowsSandboxError(
          'srt-win: error: busy\n' +
            '{"code":"profile_operation_in_progress","message":"in progress"}',
        )
        expect(parsed?.code).toBe('profile_operation_in_progress')
        const ended = winUtils.parseWindowsSandboxError(
          'srt-win: error: the session that started this command ended\n' +
            '{"code":"session_ended","message":"the session ended"}',
        )
        expect(ended?.code).toBe('session_ended')
        expect(winUtils.SRT_WIN_EXIT_SESSION_ENDED).toBe(26)
      })

      it('a grant that live sessions block is its own typed error', async () => {
        grantRun = {
          code: 24,
          stderr: [
            'srt-win: error: profile grant: 1 sandbox session(s) or command(s) are running (process 7).',
          ],
          stdout: JSON.stringify({
            held_by: [
              { pid: 7, kind: 'profile', path: '(profile)' },
              { pid: 7, kind: 'deny', path: 'C:\\work\\.env' },
              { pid: 8, kind: 'deny_satisfied', path: 'C:\\closed' },
              { pid: 9, kind: 'grant', path: 'C:\\tmp\\x' },
            ],
          }),
        }
        let thrown: unknown
        try {
          await winUtils.grantWindowsProfileRead({ srtWin })
        } catch (e) {
          thrown = e
        }
        expect((thrown as WindowsSandboxError).code).toBe(
          'profile_grant_blocked_by_session',
        )
        const said = (thrown as WindowsSandboxError).message
        expect(said).toContain('process 7 is a sandbox session or command')
        expect(said).toContain(
          'process 7 holds a session deny on C:\\work\\.env',
        )
        expect(said).toContain('process 8 holds a session deny on C:\\closed')
        expect(said).toContain('process 9 holds a session grant on C:\\tmp\\x')
        expect(said).not.toContain('kept')
        expect(said).toContain('What was granted before is as it was')
      })

      const heldBy = JSON.stringify({
        held_by: [{ pid: 7, kind: 'profile', path: '(profile)' }],
      })
      const thrownBy = async (f: () => unknown) => {
        try {
          await f()
        } catch (e) {
          return e as WindowsSandboxError
        }
        return undefined
      }
      it.each<[string, string, () => unknown]>([
        [
          'uninstallWindowsSandbox',
          'uninstall',
          () => uninstallWindowsSandbox({ srtWin }),
        ],
        [
          'forgetWindowsProfileRead',
          'profile forget',
          () => winUtils.forgetWindowsProfileRead({ srtWin }),
        ],
        [
          'forgetWindowsProfileReadAsync',
          'profile forget',
          () => winUtils.forgetWindowsProfileReadAsync({ srtWin }),
        ],
      ])(
        '%s: exit 22 is kept_grants_in_use, exit 25 profile_operation_in_progress',
        async (_name, key, call) => {
          syncResult[key] = exit(22, heldBy, 'srt-win: error: …')
          const held = await thrownBy(call)
          expect(held?.code).toBe('kept_grants_in_use')
          expect(held?.message).toContain(
            'process 7 is a sandbox session or command',
          )
          expect(held?.message).toContain('removed nothing')
          syncResult[key] = exit(25, '', 'srt-win: error: …')
          expect((await thrownBy(call))?.code).toBe(
            'profile_operation_in_progress',
          )
        },
      )

      it('an install whose grant is refused beside other activity says so, under that code: nothing was written', async () => {
        for (const [code, want] of [
          [24, 'profile_grant_blocked_by_session'],
          [25, 'profile_operation_in_progress'],
        ] as const) {
          syncResult['profile grant'] = exit(code, heldBy, 'srt-win: error: …')
          const sync = await thrownBy(() => installWindowsSandbox({ srtWin }))
          expect(sync?.code).toBe(want)
          expect(sync?.message).toContain('The Windows sandbox is installed.')
          expect(sync?.message).not.toContain('No session starts')
          grantRun = { code, stderr: [], stdout: heldBy }
          const asynchronous = await thrownBy(() =>
            winUtils.installWindowsSandboxAsync({ srtWin }),
          )
          expect(asynchronous?.code).toBe(want)
          expect(asynchronous?.message).not.toContain('No session starts')
        }
      })

      it('a status asked while a profile operation runs is that, not an interrupted grant', async () => {
        profileStatus = {
          state: 'in_progress',
          capabilities: SRT_WIN_CAPABILITIES,
        }
        const direct = await thrownBy(() =>
          winUtils.getWindowsProfileReadStatus({ srtWin }),
        )
        expect(direct?.code).toBe('profile_operation_in_progress')
        briefGrant = { state: 'present' }
        const e = await rejection(config())
        expect(e.code).toBe('profile_operation_in_progress')
      })

      it('a configuration file replaced since the grant is named in a warning of its own', () => {
        const replaced = join(home, '.gitconfig')
        profileStatus = { ...current(), replaced_files: [replaced, 7] }
        // A list with anything but paths in it is no list.
        expect(
          winUtils.getWindowsProfileReadStatus({ srtWin }).replacedFiles,
        ).toEqual([])
        profileStatus = { ...current(), replaced_files: [replaced] }
        const st = winUtils.getWindowsProfileReadStatus({ srtWin })
        expect(st.replacedFiles).toEqual([replaced])
        const warnings = windowsProfileReadWarningsOf(st)
        expect(warnings.map(w => w.code)).toEqual(['profile_file_replaced'])
        expect(warnings[0]!.paths.map(p => p.path)).toEqual([replaced])
        expect(warnings[0]!.message).toContain('grantWindowsProfileRead()')
        // One that says nothing of them has none.
        profileStatus = current()
        expect(
          windowsProfileReadWarningsOf(
            winUtils.getWindowsProfileReadStatus({ srtWin }),
          ),
        ).toEqual([])
      })

      it('a path open through an entry this product wrote is the strongest warning, with what was found about the entry', async () => {
        const ours = {
          ...item(
            '.aws',
            'it is excluded now, and … icacls "…" /remove:g "*S-1-5-21-9"',
          ),
          protected_exclusion: true,
          entry: 'explicit',
        }
        const copy = {
          ...item('.azure', '… icacls "…" /inheritance:e'),
          protected_exclusion: true,
          entry: 'inherited',
        }
        const left = {
          ...item('Old', 'it is no longer part of the grant, and …'),
          protected_exclusion: false,
          entry: 'explicit',
        }
        profileStatus = {
          ...current(),
          ...classes(),
          unverifiable: [],
          unprotected: [...classes().unprotected, ours, copy],
          stale_allow: [left, { ...item('Odd', 'r'), entry: 'sideways' }],
        }
        const st = winUtils.getWindowsProfileReadStatus({ srtWin })
        expect(
          st.unprotected.map(i => [i.path, i.protectedExclusion, i.entry]),
        ).toEqual([
          [join(home, '.docker'), undefined, undefined],
          [join(home, '.aws'), true, 'explicit'],
          [join(home, '.azure'), true, 'inherited'],
        ])
        expect(
          st.staleAllow.map(i => [i.path, i.protectedExclusion, i.entry]),
        ).toEqual([
          [join(home, 'Old'), false, 'explicit'],
          [join(home, 'Odd'), undefined, undefined],
        ])
        const [open, stale] = windowsProfileReadWarningsOf(st)
        expect(open!.code).toBe('profile_exclusion_unprotected')
        expect(open!.paths.map(p => p.path)).toEqual([
          join(home, '.aws'),
          join(home, '.azure'),
          join(home, '.docker'),
        ])
        expect(open!.message).toMatch(
          /2 READABLE THROUGH AN ENTRY THIS PRODUCT WROTE .*icacls.*; 1 by their own access lists/,
        )
        expect(stale!.code).toBe('profile_stale_allow')
        expect(stale!.message).toContain('None is on the exclusion list')
        const [plain] = windowsProfileReadWarningsOf({
          unprotected: [st.unprotected[0]!],
          unverifiable: [],
          staleAllow: [],
        })
        expect(plain!.message).not.toContain('THIS PRODUCT WROTE')
      })
    })

    it('the grants sent with a per-command deny are the topmost ones, each once', () => {
      const p = (...rel: string[]) => join(home, ...rel)
      mkdirSync(p('Documents', 'a', 'b'), { recursive: true })
      const many = Array.from({ length: 400 }, (_, i) =>
        p('Documents', 'a', `generated-${i}`),
      )
      expect(
        winUtils.windowsGrantsBeneathDenies(
          [
            p('Documents', 'a'),
            ...many,
            p('Documents', 'a', 'b'),
            p('Documents', 'a'),
            p('.cargo'),
            work,
          ],
          [home],
        ),
      ).toEqual([p('Documents', 'a'), p('.cargo')])
      expect(winUtils.windowsGrantsBeneathDenies([home], [home])).toEqual([])
    })

    it('grantWindowsProfileRead: a refresh names no exclusion and drops none; replacing them is explicit', async () => {
      await winUtils.grantWindowsProfileRead({ srtWin })
      await winUtils.grantWindowsProfileRead({
        srtWin,
        exclude: ['.only'],
        replaceExclusions: true,
      })
      expect(asyncCalls).toEqual([
        ['profile', 'grant', '--json'],
        [
          'profile',
          'grant',
          '--json',
          '--exclude',
          '.only',
          '--replace-excludes',
        ],
      ])
    })

    it('grantWindowsProfileRead: non-zero exit → profile_grant_failed with srt-win’s words', async () => {
      grantRun = {
        stderr: ['an excluded directory could not be denied'],
        stdout: '',
        code: 1,
      }
      const e = (await winUtils
        .grantWindowsProfileRead({ srtWin })
        .catch(e => e)) as WindowsSandboxError
      expect(e).toBeInstanceOf(WindowsSandboxError)
      expect(e.code).toBe('profile_grant_failed')
      expect(e.message).toContain('could not be denied')
    })

    it('grantWindowsProfileRead: the timeout is the caller’s', async () => {
      grantRun = { stderr: [], stdout: '', code: null }
      const e = (await winUtils
        .grantWindowsProfileRead({ srtWin, timeoutMs: 20 })
        .catch(e => e)) as WindowsSandboxError
      expect(e.code).toBe('srt_win_timeout')
      expect(e.message).toContain('20ms')
    })

    it('forgetWindowsProfileRead: argv; a failure is profile_forget_failed', () => {
      winUtils.forgetWindowsProfileRead({ srtWin })
      expect(names()).toEqual(['profile forget'])
      expect(calls[0].argv).toEqual(['--json'])
      syncResult['profile forget'] = exit(1, '', 'still recorded')
      expect(() => winUtils.forgetWindowsProfileRead({ srtWin })).toThrow(
        expect.objectContaining({ code: 'profile_forget_failed' }),
      )
    })

    it('getWindowsProfileReadStatus: argv and mapping', () => {
      profileStatus = {
        ...current(),
        env: {
          NPM_CONFIG_USERCONFIG: 'C:\\Users\\me\\.npmrc',
          GIT_CONFIG_GLOBAL: 'C:\\Users\\me\\.gitconfig',
          TEMP: 'C:\\Users\\me\\AppData\\Local\\Temp',
          USERPROFILE: 'C:\\Users\\me',
          GRADLE_USER_HOME: 'C:\\Users\\me\\.gradle',
        },
        paths: [...recorded(), { path: 'x', kind: 'something-new' }],
      }
      const st = winUtils.getWindowsProfileReadStatus({ srtWin })
      expect(calls[0].argv).toEqual([])
      expect(st.state).toBe('current')
      expect(st.profile).toBe(home)
      expect(st.extraExclusions).toEqual(['.myapp'])
      expect(st.exclusions).toEqual(exclusions())
      expect(st.ungrantedOnly).toEqual(ungrantedOnly())
      expect(st.counts).toEqual({
        containers: 2,
        granted: 1,
        files: 2,
        denied: 2,
      })
      expect(st.env).toEqual({
        NPM_CONFIG_USERCONFIG: 'C:\\Users\\me\\.npmrc',
        GIT_CONFIG_GLOBAL: 'C:\\Users\\me\\.gitconfig',
      })
      expect(st.paths).toEqual(recorded() as never)
      winUtils.getWindowsProfileReadStatus({ srtWin, paths: true })
      expect(calls[1].argv).toEqual(['--paths'])
      profileStatus = { ...profileStatus, state: 'outdated' }
      expect(winUtils.getWindowsProfileReadStatus({ srtWin }).env).toEqual({})
      profileStatus = { state: 'brand-new' }
      const odd = winUtils.getWindowsProfileReadStatus({ srtWin })
      expect(odd.state).toBe('unknown')
      expect(odd.exclusions).toEqual([])
      expect(odd.ungrantedOnly).toEqual([])
    })

    it('windowsProfileExclusionConflicts: equal, inside, above, wildcards, and what is unrelated', () =>
      explained(
        [
          join(home, '.ssh'),
          join(home, '.ssh', 'keys'),
          home,
          join(home, '.cargo'),
          join(home, 'AppData', 'Local', 'App', 'EBWebView'),
          join(home, 'Documents'),
          temp(),
          join(temp(), 'session'),
          join(temp(), 'keys'),
          work,
        ],
        () => {
          const hit = (p: string) =>
            winUtils.windowsProfileExclusionConflicts([p], lists())[0]
          const rel = (p: string) => hit(p)?.relation
          expect(rel(join(home, '.ssh'))).toBe('equal')
          expect(rel(join(home, '.ssh', 'keys'))).toBe('inside')
          expect(rel(home)).toBe('above')
          expect(rel(join(home, '.cargo'))).toBe('above')
          expect(rel(join(home, '.cargo', 'credentials.toml'))).toBe('equal')
          expect(rel(join(home, 'ntuser.dat.LOG1'))).toBe('equal')
          expect(rel(join(home, 'AppData', 'Local'))).toBe('above')
          expect(rel(join(home, 'AppData', 'Local', 'App', 'EBWebView'))).toBe(
            'equal',
          )
          expect(rel(join(home, 'Documents'))).toBeUndefined()
          expect(rel(join(home, '.sshx'))).toBeUndefined()
          expect(
            rel(join(home, 'AppData', 'Local', 'App', 'data')),
          ).toBeUndefined()
          expect(rel(work)).toBeUndefined()
          expect(hit(join(home, '.ssh'))?.kind).toBe('protected')
          expect(hit(temp())).toMatchObject({
            kind: 'ungranted-only',
            relation: 'equal',
          })
          expect(rel(join(temp(), 'session'))).toBeUndefined()
          expect(rel(join(temp(), 'session', 'work'))).toBeUndefined()
          expect(hit(join(temp(), 'keys'))).toMatchObject({
            kind: 'protected',
            relation: 'equal',
          })
          expect(hit(join(temp(), 'keys', 'sub'))).toMatchObject({
            kind: 'protected',
            relation: 'inside',
          })
          expect(
            winUtils.windowsProfileExclusionConflicts(
              [join(home, '.ssh', 'keys')],
              {
                exclusions: ['\\\\?\\' + join(home, '.ssh')],
                ungrantedOnly: [],
              },
            )[0]?.relation,
          ).toBe('inside')
        },
      ))

    it('windowsProfileReadEnv: the pointers, minus what the embedder sets itself; none without a current grant', () => {
      const status = (
        state: winUtils.WindowsProfileGrantState,
      ): winUtils.WindowsProfileGrantStatus => ({
        state,
        capabilities: [],
        notGranted: [],
        selfClosed: [],
        unverifiable: [],
        unprotected: [],
        staleAllow: [],
        replacedFiles: [],
        extraExclusions: [],
        exclusions: [],
        ungrantedOnly: [],
        counts: { containers: 0, granted: 0, files: 0, denied: 0 },
        env: {
          NPM_CONFIG_USERCONFIG: 'n',
          GIT_CONFIG_GLOBAL: 'g',
          PIP_CONFIG_FILE: 'p',
          MAVEN_ARGS: 'm',
          RUSTUP_HOME: 'r',
          CARGO_HOME: 'c',
          GRADLE_USER_HOME: 'x',
        },
      })
      expect(winUtils.WINDOWS_PROFILE_READ_ENV_VARS).toEqual([
        'NPM_CONFIG_USERCONFIG',
        'GIT_CONFIG_GLOBAL',
        'PIP_CONFIG_FILE',
        'MAVEN_ARGS',
        'RUSTUP_HOME',
        'CARGO_HOME',
      ])
      expect(winUtils.windowsProfileReadEnv(status('current'))).toEqual({
        NPM_CONFIG_USERCONFIG: 'n',
        GIT_CONFIG_GLOBAL: 'g',
        PIP_CONFIG_FILE: 'p',
        MAVEN_ARGS: 'm',
        RUSTUP_HOME: 'r',
        CARGO_HOME: 'c',
      })
      expect(
        winUtils.windowsProfileReadEnv(status('current'), {
          cargo_home: 'D:\\cargo',
          RUSTUP_HOME: 'D:\\rustup',
        }),
      ).toEqual({
        NPM_CONFIG_USERCONFIG: 'n',
        GIT_CONFIG_GLOBAL: 'g',
        PIP_CONFIG_FILE: 'p',
        MAVEN_ARGS: 'm',
      })
      expect(
        winUtils.windowsProfileReadEnv(status('current'), {
          GIT_CONFIG_GLOBAL: 'C:\\mine\\gitconfig',
          maven_args: '-o',
          PIP_CONFIG_FILE: undefined,
        }),
      ).toEqual({
        NPM_CONFIG_USERCONFIG: 'n',
        PIP_CONFIG_FILE: 'p',
        RUSTUP_HOME: 'r',
        CARGO_HOME: 'c',
      })
      for (const s of ['none', 'outdated', 'incomplete', 'unknown'] as const) {
        expect(winUtils.windowsProfileReadEnv(status(s))).toEqual({})
      }
      for (const v of [
        'USERPROFILE',
        'HOME',
        'APPDATA',
        'LOCALAPPDATA',
        'TEMP',
        'TMP',
      ]) {
        expect(winUtils.WINDOWS_PROFILE_READ_ENV_VARS).not.toContain(v)
      }
    })

    it('the library sets none of the pointers by itself', async () => {
      await SandboxManager.initialize(config())
      const { argv } = await SandboxManager.wrapWithSandboxArgv('echo x')
      const envNames = argv
        .filter((_, i) => argv[i - 1] === '--env')
        .map(kv => kv.slice(0, kv.indexOf('=')))
      for (const v of [
        ...winUtils.WINDOWS_PROFILE_READ_ENV_VARS,
        'USERPROFILE',
        'HOME',
        'APPDATA',
        'LOCALAPPDATA',
        'TEMP',
        'TMP',
      ]) {
        expect(envNames).not.toContain(v)
      }
    })

    it('user status: the grant is reported unless srt-win says there is none', () => {
      const get = (g: unknown) => {
        briefGrant = g
        return getWindowsSandboxUserStatus({ srtWin }).profileGrant
      }
      expect(get(undefined)).toBeUndefined()
      expect(get({ state: 'none' })).toBeUndefined()
      expect(get({ state: 'present' })).toEqual({ state: 'present' })
      expect(get({ state: 'unknown', reason: 'r' })).toEqual({
        state: 'unknown',
        reason: 'r',
      })
      expect(get({ state: 'newer' })).toEqual({ state: 'unknown' })
    })
  })
})
