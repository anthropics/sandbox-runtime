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
import { tmpdir } from 'node:os'
import { dirname, isAbsolute, join } from 'node:path'
import { createServer, type Server } from 'node:net'
import type { AddressInfo } from 'node:net'
import { isMacOS, isWindows } from '../helpers/platform.js'
import { spawnAsync } from '../helpers/spawn.js'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import type {
  CredentialFileConfig,
  SandboxRuntimeConfig,
  SrtWinConfig,
} from '../../src/sandbox/sandbox-config.js'
import { WindowsConfigSchema } from '../../src/sandbox/sandbox-config.js'
import { CA_TRUST_VARS } from '../../src/sandbox/sandbox-utils.js'
import { certThumbprint } from '../../src/sandbox/mitm-ca.js'
import * as platform from '../../src/utils/platform.js'
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
  ensurePersistentWindowsCa,
  windowsStateDir,
  wrapCommandWithSandboxWindows,
  parseWindowsBinShell,
  rankWindowsFsAccess,
  resolveSrtWin,
  buildGitConfigEnv,
  SRT_WIN_DISPATCH_ARG1,
  DEFAULT_WINDOWS_PROXY_PORT_RANGE,
  VENDORED_SRT_WIN_EXE,
  type WindowsAclGrantOptions,
  type WindowsAclStampOptions,
  type WindowsFsAccessSet,
} from '../../src/sandbox/windows-sandbox-utils.js'

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
const CARGO = sandboxReachable('cargo')

/**
 * Whether the `curl` Git Bash runs has an OpenSSL backend. On ARM64
 * the bundled build is Schannel only, which cannot complete a TLS
 * handshake under the default (write-restricted) child token.
 */
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

/**
 * `node -e` source that requests `https://<host>/` through the
 * session's proxy and prints `STATUS:<code>`; exit 0 on 200. Node's
 * own clients do not read the proxy variables, so the tunnel is made
 * by hand: a CONNECT to the proxy named by `HTTPS_PROXY` (with its
 * token), then `https.get` over that socket. Node brings its own TLS
 * stack (OpenSSL), so this works under either child token.
 */
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

/**
 * Whether the runner has a client with its own TLS stack that the
 * sandbox account can launch: an OpenSSL curl, or node.
 */
const HAS_OWN_TLS_CLIENT = OPENSSL_CURL !== undefined || NODE !== undefined

/**
 * A sandboxed command that requests `https://<host>/` through the
 * proxy with such a client — the kind that works under the default
 * child token, where Schannel does not. Its output ends in `200` on
 * success ({@link got200}).
 */
function ownTlsGet(host: string): string {
  return OPENSSL_CURL !== undefined
    ? `"${OPENSSL_CURL}" -sS -m 15 -o NUL -w "%{http_code}" https://${host}/`
    : `"${NODE}" -e "${nodeGetThroughProxy(host)}"`
}
const got200 = (r: { stdout: string }): boolean =>
  /(?:^|STATUS:)200$/.test(r.stdout.trim())

/**
 * `cfg` with `windows.writeRestrictedToken: false`: a session under
 * the ordinary child token, with per-session grants. For the rows
 * that are about that token — Schannel clients, and the per-session
 * grant / revoke plumbing.
 */
function onOrdinaryToken(cfg: SandboxRuntimeConfig): SandboxRuntimeConfig {
  return { ...cfg, windows: { ...cfg.windows, writeRestrictedToken: false } }
}

// Direct helper calls (and SandboxManager configs) must thread an
// explicit srt-win path — there is no ambient vendor fallback.
// getSrtWinPath() picks the built exe (vendored or cargo
// target/release) on the CI runner.
const TEST_SRT_WIN = isWindows
  ? resolveSrtWin({ path: getSrtWinPath() })
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
      srtWin: isWindows ? { path: getSrtWinPath() } : undefined,
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
    expect(envArgs).toContain('HTTP_PROXY=http://localhost:60080')
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

  it('writeRestrictedToken unset is true: argv and env are identical, and carry the token flag and the git backend entry', () => {
    const srtWin = resolveSrtWin({ path: process.execPath })
    const base = {
      command: 'git fetch',
      httpProxyPort: 60080,
      cwd: 'C:\\work\\repo',
      caCertPath: 'C:/bundle.pem',
      denyRead: ['C:\\secret'],
      writeRoots: ['C:\\work\\repo'],
      srtWin,
    }
    const unset = wrapCommandWithSandboxWindows(base)
    const on = wrapCommandWithSandboxWindows({
      ...base,
      writeRestrictedToken: true,
    })
    expect(unset.argv).toEqual(on.argv)
    expect(unset.env).toEqual(on.env)
    expect(unset.argv).toContain('--write-restricted-token')
    expect(unset.argv).toContain('--write-root')
    expect(unset.argv).toContain('GIT_CONFIG_VALUE_4=openssl')
  })

  it('writeRestrictedToken false: the ordinary-token argv, exactly', () => {
    const srtWin = resolveSrtWin({ path: process.execPath })
    const { argv } = wrapCommandWithSandboxWindows({
      command: 'git fetch',
      cwd: 'C:\\work\\repo',
      caCertPath: 'C:/bundle.pem',
      denyRead: ['C:\\secret'],
      denyWrite: ['C:\\work\\repo\\.git\\hooks'],
      writeRoots: ['C:\\work\\repo'],
      setEnvVars: {},
      binShell: { exe: 'C:\\sh.exe', args: ['-c'] },
      writeRestrictedToken: false,
      srtWin,
    })
    // Everything between the fixed head and `--`, with the --env
    // values (which follow the host's PATH and the generated proxy
    // set) reduced to their names.
    const dashes = argv.indexOf('--')
    const flags = argv
      .slice(0, dashes)
      .map((a, i) => (argv[i - 1] === '--env' ? a.split('=')[0] : a))
      .filter((a, i, all) => !(a === '--env' || all[i - 1] === '--env'))
    expect(flags).toEqual([
      process.execPath,
      SRT_WIN_DISPATCH_ARG1,
      'exec',
      '--quiet',
      '--deny-read',
      'C:\\secret',
      '--deny-write',
      'C:\\work\\repo\\.git\\hooks',
    ])
    expect(argv.slice(dashes)).toEqual(['--', 'C:\\sh.exe', '-c', 'git fetch'])
    // No token flag, no write root, no git backend entry: two
    // safe.directory entries and the two schannel knobs.
    const envArgs = argv.filter((_, i) => argv[i - 1] === '--env')
    expect(envArgs).toContain('GIT_CONFIG_COUNT=4')
    expect(envArgs.join(' ')).not.toContain('http.sslBackend')
    expect(argv).not.toContain('--write-restricted-token')
    expect(argv).not.toContain('--write-root')
  })

  it('writeRestrictedToken: --write-restricted-token reaches exec, before --, and nothing else differs from the false argv but the git backend entry', () => {
    const srtWin = resolveSrtWin({ path: process.execPath })
    const base = {
      command: 'git fetch',
      httpProxyPort: 60080,
      cwd: 'C:\\work\\repo',
      caCertPath: 'C:/bundle.pem',
      srtWin,
    }
    const off = wrapCommandWithSandboxWindows({
      ...base,
      writeRestrictedToken: false,
    })
    const on = wrapCommandWithSandboxWindows(base)
    // An srt-win option, so it must sit before `--`: after it the
    // flag would be handed to the sandboxed command instead.
    const flagAt = on.argv.indexOf('--write-restricted-token')
    expect(flagAt).toBeGreaterThan(on.argv.indexOf('exec'))
    expect(flagAt).toBeLessThan(on.argv.indexOf('--'))
    expect(on.argv.filter(a => a === '--write-restricted-token')).toHaveLength(
      1,
    )
    // The only differences from the ordinary-token argv: the flag, one
    // more git config entry, and the count that covers it.
    const added = on.argv.filter(a => !off.argv.includes(a))
    expect(added.sort()).toEqual(
      [
        '--write-restricted-token',
        'GIT_CONFIG_COUNT=5',
        'GIT_CONFIG_KEY_4=http.sslBackend',
        'GIT_CONFIG_VALUE_4=openssl',
      ].sort(),
    )
    const removed = off.argv.filter(a => !on.argv.includes(a))
    expect(removed).toEqual(['GIT_CONFIG_COUNT=4'])
    // The schannel knobs stay (harmless under the OpenSSL backend).
    expect(on.argv).toContain('GIT_CONFIG_KEY_2=http.schannelUseSSLCAInfo')
  })

  it('writeRoots: one --write-root per root, right after the token flag; ignored under the ordinary token', () => {
    const srtWin = resolveSrtWin({ path: process.execPath })
    const base = {
      command: 'git fetch',
      httpProxyPort: 60080,
      cwd: 'C:\\work\\repo',
      denyWrite: ['C:\\work\\repo\\.git\\hooks'],
      srtWin,
    }
    const roots = ['C:\\work\\repo', 'D:\\other tree']
    const none = wrapCommandWithSandboxWindows(base)
    const on = wrapCommandWithSandboxWindows({ ...base, writeRoots: roots })
    const at = on.argv.indexOf('--write-restricted-token')
    expect(on.argv.slice(at, at + 5)).toEqual([
      '--write-restricted-token',
      '--write-root',
      roots[0],
      '--write-root',
      roots[1],
    ])
    // srt-win options: before `--`, and the per-exec denies are
    // still there, unchanged.
    expect(at + 5).toBeLessThanOrEqual(on.argv.indexOf('--deny-write'))
    expect(on.argv.indexOf('--deny-write')).toBeLessThan(on.argv.indexOf('--'))
    // Nothing else changes.
    expect([...on.argv.slice(0, at + 1), ...on.argv.slice(at + 5)]).toEqual(
      none.argv,
    )
    expect(on.env).toEqual(none.env)
    // The ordinary token has no capability SIDs to carry.
    const plain = { ...base, writeRestrictedToken: false }
    const off = wrapCommandWithSandboxWindows({ ...plain, writeRoots: roots })
    expect(off.argv).toEqual(wrapCommandWithSandboxWindows(plain).argv)
    expect(off.argv).not.toContain('--write-root')
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
    expect(envArgs.some(e => e.startsWith('HTTPS_PROXY='))).toBe(true)
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

describe('WindowsConfigSchema.writeRestrictedToken (pure, all platforms)', () => {
  it('is an optional boolean; unset means on, only false turns it off', () => {
    // Left unset by the schema: the default is applied where the
    // option is read, by one function.
    const none = WindowsConfigSchema.parse({})
    expect(none.writeRestrictedToken).toBeUndefined()
    const enabled = winUtils.windowsWriteRestrictedTokenEnabled
    expect(enabled(undefined)).toBe(true)
    expect(enabled(none)).toBe(true)
    expect(enabled({ writeRestrictedToken: true })).toBe(true)
    expect(enabled({ writeRestrictedToken: false })).toBe(false)
    expect(WindowsConfigSchema.shape.writeRestrictedToken.description).toMatch(
      /^Default true/,
    )
    expect(
      WindowsConfigSchema.parse({ writeRestrictedToken: true })
        .writeRestrictedToken,
    ).toBe(true)
    expect(
      WindowsConfigSchema.parse({ writeRestrictedToken: false })
        .writeRestrictedToken,
    ).toBe(false)
    // A truthy non-boolean must not switch the token shape on.
    for (const bad of ['true', 1, 'yes', null]) {
      expect(
        WindowsConfigSchema.safeParse({ writeRestrictedToken: bad }).success,
      ).toBe(false)
    }
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
    // On its own (no safe dirs, no schannel knobs) it is still emitted.
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
    // safe.directory (dir + dir/*) for cwd + each allowWrite entry,
    // the two schannel knobs (schannelCa keyed on caCertPath), then
    // the OpenSSL backend the default child token needs.
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
    // cwd (dir + dir/*) + gitSafeDirectories (dir + dir/*), no schannel
    // knobs (no caCertPath), and the OpenSSL backend entry. The repo
    // top-level reaches safe.directory without appearing in allowWrite.
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

// The manager's Windows path with the helper calls recorded, not made. Not on
// Windows: the L-rows below make them there, and initialize() under a stub
// would use up the one egress check a process makes.
// Run once per child-token mode. The lists are ranked the same way in
// both; what differs is the call that carries them: one `acl grant
// --persistent` by default, a grant and a stamp with
// `windows.writeRestrictedToken: false`.
function whatSrtWinIsHanded(writeRestrictedToken: false | undefined): void {
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
    windows: {
      srtWin: { path: process.execPath },
      ...(writeRestrictedToken === false && { writeRestrictedToken }),
    },
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
      spyOn(winUtils, 'grantWindowsAcl').mockImplementation(o => {
        expect(writeRestrictedToken).toBe(false)
        granted = o
      }),
      spyOn(winUtils, 'stampWindowsAcl').mockImplementation(o => {
        expect(writeRestrictedToken).toBe(false)
        stamped = o
      }),
      // The default: one call with all four lists. Recorded as the
      // grant and the stamp it stands for, each only when it has
      // something in it, as the two separate calls are made.
      spyOn(winUtils, 'grantWindowsAclPersistent').mockImplementation(o => {
        expect(writeRestrictedToken).toBeUndefined()
        if (o.read.length > 0 || o.write.length > 0) {
          granted = { read: o.read, write: o.write }
        }
        if (o.denyRead.length > 0 || o.denyWrite.length > 0) {
          stamped = { denyRead: o.denyRead, denyWrite: o.denyWrite }
        }
      }),
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
    expect(granted).toBeUndefined()
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
}
describe.if(!isWindows)('what srt-win is handed (platform spy)', () =>
  whatSrtWinIsHanded(undefined),
)
describe.if(!isWindows)(
  'what srt-win is handed, writeRestrictedToken: false (platform spy)',
  () => whatSrtWinIsHanded(false),
)

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
      child.emit('close', status, null)
    }
    if (delayMs === Infinity) {
      // wait for kill()
    } else if (delayMs > 0) setTimeout(fire, delayMs)
    else setImmediate(fire)
    return child
  }

  const stubSpawn = (
    behaviour: (argv: readonly string[]) => { status: number; stdout: string },
    delayMs = 0,
    onClose?: () => void,
  ) => {
    spawnSyncSpy = spyOn(child_process, 'spawnSync').mockImplementation(((
      _exe: string,
      argv: readonly string[],
    ) => {
      const b = behaviour(argv)
      return { status: b.status, stdout: b.stdout, stderr: '', error: null }
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    }) as any)
    spawnSpy = spyOn(child_process, 'spawn').mockImplementation(((
      _exe: string,
      argv: readonly string[],
    ) => {
      const b = behaviour(argv)
      return mkFakeChild(b.stdout, b.status, delayMs, onClose)
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    }) as any)
  }

  afterEach(() => {
    spawnSpy?.mockRestore()
    spawnSyncSpy?.mockRestore()
  })

  it('verifyWindowsWfpEgress: --write-restricted-token unless writeRestrictedToken is false', async () => {
    const target = '127.0.0.1:49999'
    stubSpawn(() => ({
      status: 0,
      stdout: JSON.stringify({ egress_probe: 'blocked', target }),
    }))
    const srtWin = resolveSrtWin({ path: process.execPath })
    await verifyWindowsWfpEgress({ target, srtWin })
    await verifyWindowsWfpEgress({
      target,
      writeRestrictedToken: false,
      srtWin,
    })
    await verifyWindowsWfpEgress({ target, writeRestrictedToken: true, srtWin })
    const plain = [SRT_WIN_DISPATCH_ARG1, 'wfp', 'verify', '--target', target]
    expect(spawnSyncSpy.mock.calls.map((c: unknown[]) => c[1])).toEqual([
      [...plain, '--write-restricted-token'],
      plain,
      [...plain, '--write-restricted-token'],
    ])
  })

  it('verifyWindowsWfpEgress: writeRoots ride with the token flag, unset or true, and never without it', async () => {
    const target = '127.0.0.1:49999'
    stubSpawn(() => ({
      status: 0,
      stdout: JSON.stringify({ egress_probe: 'blocked', target }),
    }))
    const srtWin = resolveSrtWin({ path: process.execPath })
    const writeRoots = ['C:\\a', 'C:\\b']
    await verifyWindowsWfpEgress({
      target,
      writeRestrictedToken: true,
      writeRoots,
      srtWin,
    })
    await verifyWindowsWfpEgress({ target, writeRoots, srtWin })
    await verifyWindowsWfpEgress({
      target,
      writeRestrictedToken: false,
      writeRoots,
      srtWin,
    })
    const plain = [SRT_WIN_DISPATCH_ARG1, 'wfp', 'verify', '--target', target]
    const withRoots = [
      ...plain,
      '--write-restricted-token',
      '--write-root',
      'C:\\a',
      '--write-root',
      'C:\\b',
    ]
    expect(spawnSyncSpy.mock.calls.map((c: unknown[]) => c[1])).toEqual([
      withRoots,
      withRoots,
      plain,
    ])
  })

  it('grantWindowsAclPersistent: one acl grant --persistent with grants and denies on stdin; any non-zero exit throws', () => {
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
    winUtils.grantWindowsAclPersistent(opts)
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
    // 2 = an input was skipped; 1 = a capability SID, a DACL read or
    // a DACL write failed. Neither is a session.
    for (const status of [1, 2]) {
      spawnSyncSpy.mockRestore()
      spawnSpy.mockRestore()
      stubSpawn(() => ({ status, stdout: '' }))
      let thrown: unknown
      try {
        winUtils.grantWindowsAclPersistent(opts)
      } catch (e) {
        thrown = e
      }
      expect(thrown).toBeInstanceOf(WindowsSandboxError)
      expect((thrown as WindowsSandboxError).code).toBe('acl_grant_failed')
    }
  })

  it('forgetWindowsPersistentGrants: acl forget --all; a non-zero exit throws acl_forget_failed', () => {
    const srtWin = resolveSrtWin({ path: process.execPath })
    stubSpawn(() => ({ status: 0, stdout: '' }))
    winUtils.forgetWindowsPersistentGrants({ srtWin })
    expect(spawnSyncSpy.mock.calls.map((c: unknown[]) => c[1])).toEqual([
      [SRT_WIN_DISPATCH_ARG1, 'acl', 'forget', '--all'],
    ])
    spawnSyncSpy.mockRestore()
    spawnSpy.mockRestore()
    stubSpawn(() => ({ status: 1, stdout: '' }))
    let thrown: unknown
    try {
      winUtils.forgetWindowsPersistentGrants({ srtWin })
    } catch (e) {
      thrown = e
    }
    expect(thrown).toBeInstanceOf(WindowsSandboxError)
    expect((thrown as WindowsSandboxError).code).toBe('acl_forget_failed')
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

  it('verifyWindowsWfpEgress with writeRestrictedToken rejects every outcome but blocked', async () => {
    const target = '127.0.0.1:49999'
    const srtWin = resolveSrtWin({ path: process.execPath })
    // 3 = the probe child connected (fence open for this token);
    // 2 = unreachable; 1 = the probe child could not be created
    // (e.g. the restricted token could not be built) → `error`.
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
        await verifyWindowsWfpEgress({
          target,
          writeRestrictedToken: true,
          srtWin,
        })
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
    installWindowsSandbox({ srtWin })
    expect(spawnSyncSpy.mock.calls[0][2].timeout).toBe(120_000)
    // Explicit override.
    installWindowsSandbox({ srtWin, timeoutMs: 300_000 })
    expect(spawnSyncSpy.mock.calls.at(-2)?.[2].timeout).toBe(300_000)
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
    expect(sync.errors[0]).toContain('npx sandbox-runtime windows-install')
    expect(sync.errors[0]).not.toMatch(/not provisioned|one-time install/i)
    spawnSpy.mockRestore()
    spawnSyncSpy.mockRestore()
    // The same version on both sides, and an srt-win that reports
    // none: no error.
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

  // ── fence revision: status ──────────────────────────────────────
  // What `srt-win wfp status` prints for a filter set written by an
  // earlier build (elevated: read off the filters; non-elevated: read
  // off the install record).
  const RAW_WFP_OUTDATED = JSON.stringify({
    state: 'outdated',
    filters: 4,
    port_range: [60080, 60089],
    user_sid: 'S-1-5-21-1',
    hint: 'the network fence on this machine is out of date',
  })

  it('getWindowsWfpStatus{,Async}: an out-of-date fence maps to state "outdated" with its hint', async () => {
    stubSpawn(argv => ({
      status: 0,
      stdout: argv.includes('user') ? RAW_USER : RAW_WFP_OUTDATED,
    }))
    const srtWin = resolveSrtWin({ path: process.execPath })
    const sync = getWindowsWfpStatus({ srtWin })
    expect(sync).toEqual({
      state: 'outdated',
      filters: 4,
      portRange: [60080, 60089],
      userSid: 'S-1-5-21-1',
      hint: 'the network fence on this machine is out of date',
    })
    expect(await getWindowsWfpStatusAsync({ srtWin })).toEqual(sync)
  })

  it('checkWindowsDependencies{,Async}: an out-of-date fence is an error naming the reinstall', async () => {
    stubSpawn(argv => ({
      status: 0,
      stdout: argv.includes('user') ? RAW_USER : RAW_WFP_OUTDATED,
    }))
    const srtWin = resolveSrtWin({ path: process.execPath })
    const sync = checkWindowsDependencies({ srtWin })
    expect(sync.errors.length).toBe(1)
    expect(sync.errors[0]).toMatch(/out of date/)
    expect(sync.errors[0]).toMatch(/windows-install/)
    expect(await checkWindowsDependenciesAsync({ srtWin })).toEqual(sync)
  })

  // ── fence probe: verify result handling ─────────────────────────
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
    expect(spawnSyncSpy.mock.calls[0][1]).toEqual([
      SRT_WIN_DISPATCH_ARG1,
      'wfp',
      'verify',
      '--target',
      '127.0.0.1:49999',
      // The default token is the write-restricted one, and the probe
      // runs under the token the session's commands get.
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

  it('verifyWindowsWfpEgress: a lowered token that could not be assumed rejects (not a block)', async () => {
    expect(
      await verifyCode(2, verifyOut({ low_integrity_loopback_probe: 'error' })),
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

  it('verifyWindowsWfpEgress: an out-of-date fence rejects (wfp_fence_outdated) with the reinstall hint', async () => {
    const out = JSON.stringify({
      egress_probe: 'not-run',
      target: '127.0.0.1:49999',
      outdated: true,
      hint: 'the network fence on this machine is out of date (revision 1)',
    })
    const err = await runVerify(19, out).catch(e => e as WindowsSandboxError)
    expect(err).toBeInstanceOf(WindowsSandboxError)
    expect((err as WindowsSandboxError).code).toBe('wfp_fence_outdated')
    expect((err as WindowsSandboxError).message).toMatch(/revision 1/)
    expect((err as WindowsSandboxError).message).toMatch(/windows-install/)
  })

  it("verifyWindowsWfpEgress: a token the kernel refused is reported as denied, and srt-win's exit code decides", async () => {
    // Under the write-restricted token srt-win exits 0: the identity
    // is closed to the session's commands.
    const r = await runVerify(
      0,
      verifyOut({
        anonymous_probe: 'denied',
        anonymous_loopback_probe: 'denied',
        low_integrity_probe: 'denied',
        write_restricted_token: true,
      }),
    )
    expect(r.probes.anonymous).toBe('denied')
    expect(r.probes.anonymousLoopback).toBe('denied')
    expect(r.probes.lowIntegrity).toBe('denied')
    expect(r.probes.plain).toBe('blocked')
    expect(r.residuals).toEqual([])
    // Not mistaken for a skipped attempt.
    expect(r.warnings).toEqual([])
    spawnSpy.mockRestore()
    spawnSyncSpy.mockRestore()
    // Under the ordinary token srt-win exits 2 for the same report.
    expect(await verifyCode(2, verifyOut({ anonymous_probe: 'denied' }))).toBe(
      'wfp_verify_inconclusive',
    )
    spawnSpy.mockRestore()
    spawnSyncSpy.mockRestore()
    // A word this version does not know reads as `error`.
    const odd = await runVerify(0, verifyOut({ deny_only_probe: 'novel' }))
    expect(odd.probes.denyOnly).toBe('error')
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

// ════════════════════════════════════════════════════════════════════
// Release ordering — no deny restore unless the revoke completed
// (pure, all platforms)
// ════════════════════════════════════════════════════════════════════
// Revoke takes the session's ALLOW grants off, restore takes its DENY
// stamps off. Running the restore after a revoke that failed, timed
// out, was only partial or reported a grant it could not release
// would leave a grant on disk with the stamps gone — and once that
// has happened, no later revoke in the process unlocks the restore.
// These drive the real SandboxManager with the platform pinned to
// Windows and both child_process entry points stubbed.

describe('Windows write-restricted token, the default: write roots are granted once and kept (pure, all platforms)', () => {
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
  /** `marker_version` / `setup_version` overrides for `user status`. */
  let setupVersions: { marker_version?: number; setup_version?: number }
  const stdoutFor = (argv: readonly string[]): string => {
    const user = {
      ...RAW_USER,
      ...setupVersions,
      ...(persistentGrants !== undefined && {
        persistent_grants: persistentGrants,
      }),
    }
    return argv.includes('user')
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
    persistentGrants = undefined
    setupVersions = {}
    acl = []
    aclResult = {}
    verifyCalls = []
    verifyResult = () => Promise.resolve({ outcome: 'blocked' })
    winUtils.clearWindowsAclIncompleteRevokesForTesting()
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
      // Async spawns: `user status` / `status` at initialize().
      spyOn(child_process, 'spawn').mockImplementation(((
        _exe: string,
        argv: readonly string[],
      ) => {
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
    winUtils.clearWindowsAclIncompleteRevokesForTesting()
    for (const s of spies) s.mockRestore()
    rmSync(dir, { recursive: true, force: true })
  })

  // Write root `dir`, deny on `dir/secret`; both proxy ports external
  // so initialize() binds nothing.
  const config = (writeRestrictedToken?: boolean): SandboxRuntimeConfig => ({
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
    windows: {
      srtWin: { path: process.execPath },
      ...(writeRestrictedToken !== undefined && { writeRestrictedToken }),
    },
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

  // Unset and `true` are the same session, call for call.
  const ON: [string, true | undefined][] = [
    ['default (option unset)', undefined],
    ['option true', true],
  ]

  for (const [mode, opt] of ON) {
    it(`${mode}: one acl grant --persistent carries roots and denies; no per-session grant or stamp; the probe gets the roots; exec gets --write-root`, async () => {
      await SandboxManager.initialize(config(opt))
      expect(subs()).toEqual(['grant'])
      expect(acl[0].argv).toContain('--persistent')
      const stdin = acl[0].stdin as Record<string, string[]>
      expect(stdin.write).toHaveLength(1)
      expect(stdin.denyRead).toHaveLength(1)
      expect(stdin.read).toEqual([])
      expect(stdin.denyWrite).toEqual([])
      // The probe runs after the grant (the capability SIDs exist only
      // then), under the token the commands get.
      expect(verifyCalls).toHaveLength(1)
      expect(verifyCalls[0]?.writeRestrictedToken).toBe(true)
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

    it(`${mode}: reset() releases only what was per-session; nothing forgets the roots`, async () => {
      await SandboxManager.initialize(config(opt))
      await SandboxManager.reset()
      expect(subs()).toEqual(['grant', 'revoke', 'restore'])
      expect(subs()).not.toContain('forget')
    })

    it(`${mode}: every initialize() probes the fence again, with that session's roots`, async () => {
      await SandboxManager.initialize(config(opt))
      await SandboxManager.reset()
      await SandboxManager.initialize(config(opt))
      expect(verifyCalls).toHaveLength(2)
      for (const v of verifyCalls) {
        expect(v?.writeRestrictedToken).toBe(true)
        expect(v?.writeRoots).toHaveLength(1)
      }
    })

    it(`${mode}: a session with nothing to grant still probes, with no roots`, async () => {
      const cfg = config(opt)
      cfg.filesystem = {
        denyRead: [],
        allowRead: [],
        allowWrite: [],
        denyWrite: [],
      }
      await SandboxManager.initialize(cfg)
      expect(subs()).toEqual([])
      expect(verifyCalls).toHaveLength(1)
      expect(verifyCalls[0]?.writeRoots).toEqual([])
      const { argv } = await SandboxManager.wrapWithSandboxArgv('echo x')
      expect(argv).toContain('--write-restricted-token')
      expect(argv).not.toContain('--write-root')
    })

    for (const status of [1, 2]) {
      it(`${mode}: acl grant --persistent exits ${status} → initialize() rejects; no fallback to a per-session grant, no probe, no command`, async () => {
        aclResult.grant = exit(status)
        const e = await rejection(config(opt))
        expect(e.code).toBe('acl_grant_failed')
        // One grant attempt, then only the release of whatever was
        // per-session.
        expect(subs().filter(s => s === 'grant')).toHaveLength(1)
        expect(subs()).not.toContain('stamp')
        expect(acl[0].argv).toContain('--persistent')
        expect(verifyCalls).toHaveLength(0)
        expect(SandboxManager.getConfig()).toBeUndefined()
      })
    }

    it(`${mode}: the probe is not blocked → initialize() rejects, and nothing probes or grants again for the ordinary token`, async () => {
      verifyResult = () =>
        Promise.reject(
          new WindowsSandboxError('wfp_fence_inactive', 'connected'),
        )
      const e = await rejection(config(opt))
      expect(e.code).toBe('wfp_fence_inactive')
      expect(SandboxManager.getConfig()).toBeUndefined()
      expect(subs()).toEqual(['grant', 'revoke', 'restore'])
      expect(acl[0].argv).toContain('--persistent')
      expect(verifyCalls).toHaveLength(1)
      expect(verifyCalls[0]?.writeRestrictedToken).toBe(true)
    })

    it(`${mode} with kept grants reported: nothing is forgotten`, async () => {
      persistentGrants = { state: 'present', roots: [dir] }
      await SandboxManager.initialize(config(opt))
      expect(subs()).toEqual(['grant'])
    })
  }

  it('unset and true: the same acl calls, the same probe, the same wrapped argv', async () => {
    const session = async (opt: true | undefined) => {
      acl = []
      verifyCalls = []
      await SandboxManager.initialize(config(opt))
      const { argv } = await SandboxManager.wrapWithSandboxArgv('echo x')
      await SandboxManager.reset()
      return {
        acl,
        probes: verifyCalls.map(v => ({
          writeRestrictedToken: v?.writeRestrictedToken,
          writeRoots: v?.writeRoots,
        })),
        argv,
      }
    }
    const unset = await session(undefined)
    expect(await session(true)).toEqual(unset)
    expect(unset.argv).toContain('--write-restricted-token')
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

  it('a per-command option that differs from the session is refused, in either direction', async () => {
    const wrap = (writeRestrictedToken: boolean) =>
      SandboxManager.wrapWithSandboxArgv('echo x', undefined, {
        windows: { srtWin: { path: process.execPath }, writeRestrictedToken },
      })
    await SandboxManager.initialize(config())
    expect((await wrap(true)).argv).toContain('--write-restricted-token')
    // eslint-disable-next-line @typescript-eslint/await-thenable -- bun:test types .rejects.toThrow() as void; the await is required at runtime
    await expect(wrap(false)).rejects.toThrow(/Per-command/)
    await SandboxManager.reset()
    await SandboxManager.initialize(config(false))
    expect((await wrap(false)).argv).not.toContain('--write-restricted-token')
    // eslint-disable-next-line @typescript-eslint/await-thenable -- bun:test types .rejects.toThrow() as void; the await is required at runtime
    await expect(wrap(true)).rejects.toThrow(/Per-command/)
  })

  it('option false, no kept grants reported: the per-session calls and the ordinary-token argv, exactly — no forget, no --persistent, no token flag', async () => {
    for (const reported of [undefined, { state: 'none', roots: [] }]) {
      persistentGrants = reported
      acl = []
      await SandboxManager.initialize(config(false))
      expect(acl.map(c => [c.sub, ...c.argv])).toEqual([
        ['grant', '--holder-pid', `${process.pid}`, '--sandbox-user-sid', SID],
        ['stamp', '--holder-pid', `${process.pid}`, '--sandbox-user-sid', SID],
      ])
      const granted = acl[0].stdin as Record<string, string[]>
      expect(Object.keys(granted).sort()).toEqual(['read', 'write'])
      expect(granted.write).toHaveLength(1)
      // The fence is probed once per process for this token; whenever
      // it is, it is with the ordinary token and no roots.
      for (const v of verifyCalls) {
        expect(v?.writeRestrictedToken).toBe(false)
        expect(v?.writeRoots).toBeUndefined()
      }
      const { argv } = await SandboxManager.wrapWithSandboxArgv(
        'echo x',
        { exe: 'C:\\sh.exe', args: ['-c'] },
        undefined,
        undefined,
        dir,
      )
      // Head and tail in full; between them only --env pairs.
      expect(argv.slice(0, 4)).toEqual([
        process.execPath,
        SRT_WIN_DISPATCH_ARG1,
        'exec',
        '--quiet',
      ])
      const dashes = argv.indexOf('--')
      expect(argv.slice(dashes)).toEqual(['--', 'C:\\sh.exe', '-c', 'echo x'])
      const between = argv.slice(4, dashes)
      expect(between.filter((_, i) => i % 2 === 0)).toEqual(
        between.filter((_, i) => i % 2 === 0).map(() => '--env'),
      )
      expect(argv.join(' ')).not.toContain('http.sslBackend')
      expect(argv).not.toContain('--write-restricted-token')
      expect(argv).not.toContain('--write-root')
      await SandboxManager.reset()
    }
  })

  for (const reported of [
    { state: 'present', roots: ['C:\\kept'] },
    // The marker or the database cannot be read: grants may exist.
    { state: 'unknown', roots: [], reason: 'state database is missing' },
    // A state this code does not know is not "none".
    { state: 'someLaterState' },
  ]) {
    it(`option false, kept grants ${reported.state}: they are forgotten before anything is granted`, async () => {
      persistentGrants = reported
      await SandboxManager.initialize(config(false))
      expect(subs()).toEqual(['forget', 'grant', 'stamp'])
      expect(acl[0].argv).toEqual(['--all'])
    })

    it(`option false, kept grants ${reported.state}: forget fails → initialize() rejects with nothing granted, and does not fall back to the write-restricted token`, async () => {
      persistentGrants = reported
      aclResult.forget = exit(1)
      const e = await rejection(config(false))
      expect(e.code).toBe('acl_forget_failed')
      expect(subs()).toEqual(['forget'])
      expect(verifyCalls).toHaveLength(0)
      expect(SandboxManager.getConfig()).toBeUndefined()
    })
  }

  // An install made by a release with another setup version: srt-win
  // would refuse to launch on it, so nothing may be granted — least of
  // all a grant that is kept.
  for (const [mode, opt] of [...ON, ['option false', false]] as [
    string,
    boolean | undefined,
  ][]) {
    it(`${mode}: an install of another setup version → initialize() asks for a re-install and makes no acl call`, async () => {
      setupVersions = { marker_version: 2, setup_version: 3 }
      persistentGrants = { state: 'present', roots: ['C:\\kept'] }
      const stale = (e: Error) => {
        expect(e.message).toMatch(/setup version 2; this release needs 3/)
        expect(e.message).toMatch(/Re-run the install/)
        expect(e.message).toContain('npx sandbox-runtime windows-install')
        expect(e.message).not.toMatch(/not provisioned|one-time install/i)
        expect(subs()).toEqual([])
        expect(verifyCalls).toHaveLength(0)
      }
      // The dependency check reports it first.
      stale(await rejection(config(opt)))
      // And initialize() holds on its own reading of the install, should
      // the dependency check have seen another.
      const deps = spyOn(
        winUtils,
        'checkWindowsDependenciesAsync',
      ).mockResolvedValue({ errors: [], warnings: [] })
      try {
        const e = await rejection(config(opt))
        expect(e).toBeInstanceOf(WindowsSandboxError)
        expect(e.code).toBe('reinstall_required')
        stale(e)
        expect(SandboxManager.getConfig()).toBeUndefined()
      } finally {
        deps.mockRestore()
      }
    })
  }

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

// Run once per child-token mode: the release at the end of a session
// is the same revoke-then-restore in both. By default the session
// starts with one `acl grant --persistent`; with
// `windows.writeRestrictedToken: false`, with a grant and a stamp.
function restoreGatedOnACompletedRevoke(
  writeRestrictedToken: false | undefined,
): void {
  const perSession = writeRestrictedToken === false
  /** The `acl` calls a session start makes. */
  const START = perSession ? ['grant', 'stamp'] : ['grant']
  /** The last of them, and what initialize() rejects with when it fails. */
  const LAST_START_CALL = perSession ? 'stamp' : 'grant'
  const START_FAILED = perSession ? 'acl_stamp_failed' : 'acl_grant_failed'
  const SID = 'S-1-5-21-1'
  // For direct helper calls; spawnSync is stubbed, so any existing
  // file does.
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
    argv.includes('user')
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
  // A revoke that exits 0 and lists one released path plus `path`
  // with `status`.
  const reports = (status: string, path = 'p'): SyncResult =>
    exit(
      0,
      JSON.stringify([
        { path: 'released', status: 'revoked' },
        { path, status },
      ]),
    )
  // The ways a revoke does not complete. (Thunks: `dir` exists only
  // inside a test.)
  const INCOMPLETE_REVOKES: Revoke[] = [
    // Partial: srt-win lists the paths it did revoke and exits 1.
    ['exits non-zero', () => exit(1, '[{"path":"p","status":"revoked"}]')],
    ['times out', () => TIMED_OUT],
    ['prints unparseable output', () => exit(0, 'not json')],
    ['prints JSON that is not a list', () => exit(0, '{}')],
    ['lists an outcome with no status', () => exit(0, '[{"path":"p"}]')],
    // Statuses outside the allow-list — the last one is a status this
    // code has never heard of.
    ...['unreadable', 'failed', 'mismatch', 'someLaterStatus'].map(
      (st): Revoke => [`reports "${st}" for a path`, () => reports(st)],
    ),
    // What an srt-win without "unreadable" says about a path it could
    // not open.
    [
      'reports "missing" for a path that still exists',
      () => reports('missing', dir),
    ],
  ]
  // The ways it does.
  const COMPLETE_REVOKES: Revoke[] = [
    ['releases nothing', () => exit(0, '[]')],
    ...['revoked', 'stillHeld', 'downgraded', 'relocated', 'noRow'].map(
      (st): Revoke => [`reports "${st}" for a path`, () => reports(st)],
    ),
    [
      'reports "missing" for a path that is gone',
      () => reports('missing', join(dir, 'gone')),
    ],
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
    winUtils.clearWindowsAclIncompleteRevokesForTesting()
    dir = mkdtempSync(join(tmpdir(), 'srt-acl-gate-'))
    mkdirSync(join(dir, 'secret'))
    spies = [
      spyOn(platform, 'getPlatform').mockReturnValue('windows'),
      // The WFP probe binds a listener and is once-per-process; it is
      // not what these tests are about.
      spyOn(winUtils, 'verifyWindowsWfpEgress').mockResolvedValue({
        outcome: 'blocked',
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
      } as any),
      // Async spawns: `user status` / `status` at initialize().
      spyOn(child_process, 'spawn').mockImplementation(((
        _exe: string,
        argv: readonly string[],
      ) => {
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
    winUtils.clearWindowsAclIncompleteRevokesForTesting()
    for (const s of spies) s.mockRestore()
    rmSync(dir, { recursive: true, force: true })
  })

  // Grant on `dir`, deny stamp on `dir/secret`; both proxy ports
  // external so initialize() binds nothing.
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
    windows: {
      srtWin: { path: process.execPath },
      ...(perSession && { writeRestrictedToken: false }),
    },
  })

  /** initialize() whose last `acl` call fails, so its failure cleanup runs. */
  const failingInitialize = async (): Promise<WindowsSandboxError> => {
    aclResult[LAST_START_CALL] = exit(2, '')
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

  /**
   * The listener registerCleanup() put on 'exit'. It is a function of
   * its own, which starts with the handler the signals get and then
   * removes what reset() only reaches after its first await.
   */
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

  // Once a revoke was incomplete, a later revoke that finds nothing
  // wrong must not unlock the restore: the grant the first one left
  // may no longer be recorded anywhere.
  describe('after one incomplete revoke in this process', () => {
    beforeEach(async () => {
      await SandboxManager.initialize(config())
      aclResult.revoke = reports('unreadable')
      await SandboxManager.reset()
      expect(aclCalls).toEqual(NO_RESTORE)
      expect(winUtils.windowsAclIncompleteRevoke()).toEqual(['p'])
      aclCalls = []
      aclResult = {}
    })

    it('reset(): a later clean revoke → restore is still not spawned', async () => {
      await SandboxManager.initialize(config())
      await SandboxManager.reset()
      expect(aclCalls).toEqual(NO_RESTORE)
    })

    it('initialize() failure cleanup: a later clean revoke → restore is still not spawned', async () => {
      const e = await failingInitialize()
      expect(e.code).toBe(START_FAILED)
      expect(aclCalls).toEqual(NO_RESTORE)
    })

    for (const [which, handler] of ON_THE_WAY_OUT) {
      it(`${which}: a later clean revoke → restore is still not spawned`, async () => {
        await SandboxManager.initialize(config())
        const done = handler()()
        expect(aclCalls).toEqual(NO_RESTORE)
        await done
        expect(aclCalls).toEqual(NO_RESTORE)
      })
    }

    it('restoreWindowsAcl itself refuses for that holder, and only that holder', () => {
      const o = { sandboxUserSid: SID, srtWin: STUB_SRT_WIN }
      expect(winUtils.restoreWindowsAcl(o)).toBeUndefined()
      expect(aclCalls).toEqual([])
      expect(
        winUtils.restoreWindowsAcl({ ...o, holderPid: process.pid + 1 }),
      ).toEqual([])
      expect(aclCalls).toEqual(['restore'])
    })
  })

  it('revokeWindowsAcl followed by restoreWindowsAcl: an incomplete revoke blocks the restore', () => {
    const o = { sandboxUserSid: SID, srtWin: STUB_SRT_WIN }
    aclResult.revoke = reports('unreadable')
    expect(winUtils.revokeWindowsAcl(o)?.map(e => e.status)).toEqual([
      'revoked',
      'unreadable',
    ])
    expect(winUtils.restoreWindowsAcl(o)).toBeUndefined()
    expect(aclCalls).toEqual(['revoke'])
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
}
describe('Windows session ACLs: restore gated on a completed revoke (pure, all platforms)', () =>
  restoreGatedOnACompletedRevoke(undefined))
describe('Windows session ACLs, writeRestrictedToken: false: restore gated on a completed revoke (pure, all platforms)', () =>
  restoreGatedOnACompletedRevoke(false))

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
      sublayerGuid: sl,
      proxyPortRange: PORT_RANGE,
      srtWin: TEST_SRT_WIN,
    })
    try {
      // Fence active: WFP block-user filter fires at
      // ALE_AUTH_CONNECT before any packet leaves → WSAEACCES. The
      // probe binds a local out-of-range loopback listener; no
      // external host involved.
      // Probed under both child tokens: the default (write-restricted)
      // one, by a lockdown child holding it, and the ordinary one.
      for (const writeRestrictedToken of [undefined, false]) {
        const v = await verifyWindowsWfpEgress({
          proxyPortRange: PORT_RANGE,
          writeRestrictedToken,
          srtWin: TEST_SRT_WIN,
        })
        expect(v.target).toMatch(/^127\.0\.0\.1:\d+$/)
      }
      // Filters removed, sandbox user kept → fence inactive →
      // throws. This is the throw initialize() relays when a stale
      // install (user provisioned, filters since removed) would
      // otherwise run every exec with full egress. The regex
      // matches both the exit-3 (`is not active`) and exit-2
      // (`could not be verified`) messages — either is correct
      // fail-closed behaviour.
      uninstallWindowsSandbox({
        sublayerGuid: sl,
        keepUser: true,
        srtWin: TEST_SRT_WIN,
      })
      for (const writeRestrictedToken of [undefined, false]) {
        // eslint-disable-next-line @typescript-eslint/await-thenable -- bun:test types .rejects.toThrow() as void; the await is required at runtime
        await expect(
          verifyWindowsWfpEgress({
            proxyPortRange: PORT_RANGE,
            writeRestrictedToken,
            srtWin: TEST_SRT_WIN,
          }),
        ).rejects.toThrow(/WFP egress fence/i)
      }
    } finally {
      uninstallWindowsSandbox({ sublayerGuid: sl, srtWin: TEST_SRT_WIN })
    }
  }, 60_000)

  it('installWindowsSandbox round-trips user + wfp under a fresh sublayer', () => {
    // The runner is admin (precondition asserted by smoke-exec.ps1),
    // so srt-win install runs without a UAC prompt and `cancelled`
    // is never set.
    const sl = '8d2f1e91-4b3c-5a6e-af9d-2e3f4a5b6c7d'
    try {
      const r = installWindowsSandbox({
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
        sublayerGuid: sl,
        proxyPortRange: PORT_RANGE,
        srtWin: TEST_SRT_WIN,
      })
      expect(r2.cancelled).toBeUndefined()
      expect(r2.wfp.state).toBe('installed')
    } finally {
      uninstallWindowsSandbox({ sublayerGuid: sl, srtWin: TEST_SRT_WIN })
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
        sublayerGuid: sl,
        proxyPortRange: [PORT_RANGE[0], PORT_RANGE[0] + 1],
        force: true,
        srtWin: TEST_SRT_WIN,
      })
      expect(r.wfp.portRange).toEqual([PORT_RANGE[0], PORT_RANGE[0] + 1])
    } finally {
      uninstallWindowsSandbox({ sublayerGuid: sl, srtWin: TEST_SRT_WIN })
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

  it('default token: initialize() verifies the fence with it, exec carries the flag, a per-command override is refused; writeRestrictedToken: false gives the ordinary token back', async () => {
    installWindowsSandbox({
      sublayerGuid: TEST_SUBLAYER,
      proxyPortRange: PORT_RANGE,
      srtWin: TEST_SRT_WIN,
    })
    // No option set. Runs `wfp verify --write-restricted-token` for
    // real: a lockdown child holding the restricted token must be
    // refused by the fence, or this throws.
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
      // The session's token shape is the one the fence was verified
      // for; a command cannot switch to the other one.
      // eslint-disable-next-line @typescript-eslint/await-thenable -- bun:test types .rejects.toThrow() as void; the await is required at runtime
      await expect(
        SandboxManager.wrapWithSandboxArgv('echo x', undefined, {
          windows: { writeRestrictedToken: false },
        }),
      ).rejects.toThrow(/Per-command windows\.writeRestrictedToken/)
    } finally {
      await SandboxManager.reset()
    }
    // The opt-out: the ordinary token, under which a Schannel client
    // completes its handshake.
    await SandboxManager.initialize(onOrdinaryToken(createTestConfig()))
    try {
      const { argv } = await SandboxManager.wrapWithSandboxArgv('echo x')
      expect(argv).not.toContain('--write-restricted-token')
      expect(argv).not.toContain('--write-root')
      expect(argv.join(' ')).not.toContain('http.sslBackend')
      const r = await runSandboxedUntil(
        `"${SYSTEM32_CURL}" -sS -m 15 -o NUL -w "%{http_code}" https://example.com/`,
        got200,
      )
      expectStatus('ordinary-token System32 curl', r, [0])
      expect(r.stdout.trim()).toBe('200')
      // eslint-disable-next-line @typescript-eslint/await-thenable -- bun:test types .rejects.toThrow() as void; the await is required at runtime
      await expect(
        SandboxManager.wrapWithSandboxArgv('echo x', undefined, {
          windows: { writeRestrictedToken: true },
        }),
      ).rejects.toThrow(/Per-command windows\.writeRestrictedToken/)
    } finally {
      await SandboxManager.reset()
    }
  }, 180_000)

  it('default token: a write root is writable to its own session only and readable from any, is kept at reset(), and is removed by a session with writeRestrictedToken: false', async () => {
    installWindowsSandbox({
      sublayerGuid: TEST_SUBLAYER,
      proxyPortRange: PORT_RANGE,
      srtWin: TEST_SRT_WIN,
    })
    // Long-form paths: the sandbox account cannot resolve an 8.3
    // component of the runner's profile.
    const rootA = realpathSync.native(mkdtempSync(join(tmpdir(), 'srt-wr-a-')))
    const rootB = realpathSync.native(mkdtempSync(join(tmpdir(), 'srt-wr-b-')))
    // No option set: the default.
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

      // A session given only B: A still carries its grant, and this
      // session cannot write there. It can read there.
      await SandboxManager.initialize(withRoots([rootB]))
      expect(await write(join(rootB, 'own.txt'))).toBe(true)
      expect(await write(join(rootA, 'from-b.txt'))).toBe(false)
      expect(await read(join(rootA, 'seed.txt'))).toContain('SEED-IN-A')
      await SandboxManager.reset()
      expect(kept()?.roots).toHaveLength(2)

      // Opted out: the kept grants are removed before anything is
      // granted, and A works as a per-session root again.
      await SandboxManager.initialize(onOrdinaryToken(withRoots([rootA])))
      expect(kept()).toBeUndefined()
      expect(await write(join(rootA, 'off.txt'))).toBe(true)
      expect(await write(join(rootB, 'off.txt'))).toBe(false)
      expect(await read(join(rootA, 'seed.txt'))).toContain('SEED-IN-A')
      expect(await read(join(rootB, 'seed.txt'))).not.toContain('SEED-IN-B')
    } finally {
      await SandboxManager.reset()
      rmSync(rootA, { recursive: true, force: true })
      rmSync(rootB, { recursive: true, force: true })
    }
  }, 240_000)

  it('an install of the previous setup version: nothing is granted or run until the install is re-run, which upgrades it in place', async () => {
    installWindowsSandbox({
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
      for (const c of [cfg, onOrdinaryToken(cfg)]) {
        // eslint-disable-next-line @typescript-eslint/await-thenable -- bun:test types .rejects.toThrow() as void; the await is required at runtime
        await expect(SandboxManager.initialize(c)).rejects.toThrow(
          /Re-run the install/,
        )
        await SandboxManager.reset()
      }
      // srt-win holds the same line by itself: no grant is kept, and
      // nothing is launched, under either token.
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
      expect(status().persistentGrants).toBeUndefined()
      for (const writeRestrictedToken of [undefined, false]) {
        const { argv, env } = wrapCommandWithSandboxWindows({
          command: 'echo V2-RAN',
          writeRestrictedToken,
          quiet: false,
          srtWin: TEST_SRT_WIN,
        })
        const r = await spawnAsync(argv[0], argv.slice(1), {
          timeout: 60_000,
          env,
        })
        expect(r.status).toBe(15)
        expect(r.stdout).not.toContain('V2-RAN')
        expect(r.stderr).toMatch(/re-run `srt-win install`/)
      }

      // The repair: the same install command, which upgrades in place.
      const r = installWindowsSandbox({
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
    const httpProxy = envArgs.find(e => e.startsWith('HTTP_PROXY='))
    const allProxy = envArgs.find(e => e.startsWith('ALL_PROXY='))
    expect(httpProxy).toMatch(/^HTTP_PROXY=http:\/\/.+:\d+$/)
    expect(allProxy).toMatch(/^ALL_PROXY=http:\/\/.+:\d+$/)
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
  // Group B — egress via real tools (allowed → reaches host via proxy)
  // ════════════════════════════════════════════════════════════════
  // Each row that needs hosts beyond example.com calls updateConfig()
  // first: the JS proxy's filter reads config.network.allowedDomains
  // live, so the allowlist changes without rebinding the proxies.

  // The session runs under the default (write-restricted) child
  // token, so the rows that must complete a TLS handshake use a client
  // with its own TLS stack (`ownTlsGet`). System32 curl is Schannel:
  // N1 pins that it does not get through under this token, and its
  // working path under the ordinary token is covered by the opt-out
  // row of the helpers describe and by the G8 / P3 rows.
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
    // The host is allowed and reachable: where there is one, a client
    // with its own TLS stack gets its 200 from the same session first.
    if (HAS_OWN_TLS_CLIENT) {
      const ok = await runSandboxedUntil(ownTlsGet('example.com'), got200)
      expectStatus('N1 control', ok, [0])
    }
    // Not retried, and judged on the outcome alone: curl fails and has
    // no HTTP status to report. The error text is Windows' to choose.
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

  it('B2: powershell Invoke-WebRequest to a NON-allowed host → blocked', async () => {
    SandboxManager.updateConfig(createTestConfig(['example.com']))
    const r = await runSandboxed(
      `powershell -NoProfile -Command "$ProgressPreference='SilentlyContinue'; try { (Invoke-WebRequest https://google.com -UseBasicParsing -TimeoutSec 8).StatusCode } catch { 'ERR' }"`,
    )
    expect(r.stdout.trim()).not.toBe('200')
  }, 60_000)

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
      // KEY: Node's built-in https does NOT read HTTPS_PROXY, so it
      // attempts a DIRECT connect. The user-SID WFP filter must
      // refuse it. This is the load-bearing proof that WFP — not the
      // proxy env vars — is the real network boundary.
      SandboxManager.updateConfig(createTestConfig(['example.com']))
      const r = await runSandboxed(
        `node -e "const s=Date.now();require('https').get('https://example.com',r=>{console.log('OK:'+r.statusCode);process.exit(0)}).on('error',e=>{console.log('ERR:'+e.code);process.exit(1)});setTimeout(()=>{console.log('TIMEOUT');process.exit(2)},6000)"`,
      )
      expect(r.stdout.startsWith('OK:')).toBe(false)
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
    // doesn't defeat WFP" proof. The refusal is of the TCP connect,
    // which comes before any TLS handshake, so it is the fence's
    // whichever TLS backend the curl on PATH has.
    SandboxManager.updateConfig(createTestConfig(['example.com']))
    const r = await runSandboxed(
      'curl --noproxy "*" -sS -m 5 https://example.com',
    )
    expectEgressBlocked('C4', r)
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
      // HTTPS where Git Bash's curl has its own TLS stack. Where it is
      // the Schannel build (ARM64), which the default child token
      // leaves without a handshake, the same request over plain HTTP:
      // the row is about the bash userland reaching the proxy.
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

  // `-O -`: the body goes to stdout, so the row does not depend on
  // any output file. (An MSYS-runtime program handed the Win32 name
  // `NUL` creates a FILE of that name in its working directory rather
  // than opening the null device; the working directory is not one of
  // this session's write roots. The Z-rows below pin the devices.)
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

  // ════════════════════════════════════════════════════════════════
  // Group Z — the null device under the default child token
  // ════════════════════════════════════════════════════════════════
  // Discarding output must work for a command that can write nowhere:
  // this session has no write roots and the working directory is not
  // writable to it. Each row opens the null device for writing the way
  // its shell or runtime does — cmd and PowerShell by the Win32 name,
  // Git Bash and msys2 programs through the MSYS runtime's /dev/null —
  // and must run to its last word. The same command is first run
  // unsandboxed: a row whose command the shell itself rejects says
  // nothing about the sandbox, and fails as such.

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
      exe = getSrtWinPath()
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
          'curl -sS -m 5 https://example.com',
      )
      // Exit-code only — see B/C convention: any non-zero is fenced.
      expect(r.status).not.toBe(0)
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

    for (const ordinaryToken of [false, true]) {
      describe(
        ordinaryToken
          ? 'files, writeRestrictedToken: false'
          : 'files, default token',
        () => {
          // ── H5-H8: FS parity via SandboxManager (grant + deny ACEs) ──
          // The G-rows in smoke-exec.ps1 exercise the srt-win primitives
          // directly; these check the SandboxManager plumbing on top, once
          // per child token. By default: initialize() → one persistent grant
          // carrying the denies → reset() → release of what was per-session,
          // the write roots kept. With `writeRestrictedToken: false`:
          // grant + stamp → reset() → revoke + restore.
          let hScratch: string
          let hSecret: string
          let hSibling: string

          type FsOverrides = Partial<SandboxRuntimeConfig['filesystem']>
          function createFsTestConfig(fs: FsOverrides): SandboxRuntimeConfig {
            const base = ordinaryToken
              ? onOrdinaryToken(createTestConfig())
              : createTestConfig()
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
            // A directory no session was ever given: under the default token
            // H5's root keeps its grant after reset(), and a kept root is
            // readable from any session.
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
              if (
                !rR.stdout.includes('GLOB-A') ||
                !rR.stdout.includes('GLOB-B')
              ) {
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

          it(
            ordinaryToken
              ? 'H8: reset() revokes the grant — sandbox-user ACE gone'
              : 'H8: reset() keeps the write root granted — to no sandbox-user ACE',
            async () => {
              // After H5/H6/H7's reset() calls, the root's DACL must NOT
              // carry an explicit ACE for the sandbox user.
              const out = spawnSync('icacls', [hScratch], {
                encoding: 'utf8',
                timeout: 5_000,
              })
              if (
                out.stdout.includes(sbSid) ||
                out.stdout.includes('srt-sandbox')
              ) {
                throw new Error(
                  `H8: srt-sandbox ACE still on '${hScratch}' after reset(): ` +
                    out.stdout,
                )
              }
              // The kept grant is recognisable by the identifier of its own
              // that the root got (`S-1-0-1936880739-…`, which resolves to
              // no name). Under the ordinary token there is none.
              expect(out.stdout.includes('S-1-0-1936880739-')).toBe(
                !ordinaryToken,
              )
              rmSync(hScratch, { recursive: true, force: true })
            },
            30_000,
          )

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

            /**
             * `run` in a session of these lists, which leaves no ACE for the
             * sandbox user behind (what the default token keeps is granted to
             * the sandbox group and to the root's own identifier).
             */
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
        },
      )
    }
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
// set. Schannel-level trust (System32 curl, IWR, .NET) comes from
// the install-time `srt-win user trust-ca` write into the sandbox
// user's `CurrentUser\Root`; the env-var layer here covers the
// OpenSSL-backed tools.
//
// Tool/row selection follows per-tool ground-truth probes run on
// win-x64 and win-arm64. In particular: Schannel `curl.exe`
// (System32, and the ARM64 git-bundled clangarm64 build) ignores
// `CURL_CA_BUNDLE`, so the curl row gates on an OpenSSL build being
// present; git defaults to the schannel backend (which ignores
// `GIT_SSL_CAINFO`), so the git row forces `http.sslBackend=openssl`;
// cargo's vendored Schannel libcurl honors `CARGO_HTTP_CAINFO`.
// Schannel's revocation check on the leaf is satisfied by the CDP →
// empty CRL the proxy serves at `/srt.crl` — no per-tool
// `--ssl-no-revoke` / `schannelCheckRevoke=false` /
// `CARGO_HTTP_CHECK_REVOKE=false` needed.

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
      // Node's built-in `fetch` (undici) does NOT honor proxy env
      // vars, so a bare fetch goes direct and the WFP fence blocks
      // it (the B5 row pins exactly this). To prove
      // NODE_EXTRA_CA_CERTS is honored we tunnel explicitly:
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

// The rows of group G whose client is Schannel. Schannel hands no
// credentials to the default (write-restricted) child token, so these
// run in a session of their own with `writeRestrictedToken: false`:
// the trust path they prove — the CA in the sandbox user's
// `CurrentUser\Root`, revocation through the served CRL — is the one
// a host that opts out gets.
describe.if(isWindows)(
  'Windows sandbox: tlsTerminate, Schannel clients under the ordinary token (G8)',
  () => {
    beforeAll(async () => {
      console.error('[winsrt G8 beforeAll] start')
      // G's afterAll uninstalled — re-provision and trust the fixture
      // CA again (the trust went with the account's profile).
      installWindowsSandbox({
        sublayerGuid: TEST_SUBLAYER,
        proxyPortRange: PORT_RANGE,
        srtWin: TEST_SRT_WIN,
      })
      windowsTrustCa(CA_CERT, { srtWin: TEST_SRT_WIN })
      await SandboxManager.initialize(
        onOrdinaryToken(
          createTlsTestConfig(['example.com', 'github.com', 'crates.io']),
        ),
      )
      const { argv } = await SandboxManager.wrapWithSandboxArgv('echo x')
      expect(argv).not.toContain('--write-restricted-token')
      console.error('[winsrt G8 beforeAll] done')
    }, 120_000)

    afterAll(async () => {
      await SandboxManager.reset()
      uninstallWindowsSandbox({
        sublayerGuid: TEST_SUBLAYER,
        srtWin: TEST_SRT_WIN,
      })
    }, 60_000)

    it('G8: System32 curl (Schannel) trusts via the sandbox-user Root install, NOT CURL_CA_BUNDLE', async () => {
      // Schannel curl ignores CURL_CA_BUNDLE/SSL_CERT_FILE by design
      // — trust comes from the sandbox user's `CurrentUser\Root`,
      // which `windowsTrustCa` populated in beforeAll. Revocation is
      // checked on the LEAF: minted leaves carry a CDP pointing at the
      // proxy's `/srt.crl` (empty CRL), so no `--ssl-no-revoke` needed.
      SandboxManager.updateConfig(
        onOrdinaryToken(createTlsTestConfig(['example.com'])),
      )
      const r = await runSandboxedUntil(
        `"${SYSTEM32_CURL}" -sS -o NUL -w "%{http_code}" https://example.com/`,
        x => x.status === 0,
      )
      expectStatus('G8', r, [0])
      expect(r.stdout).toContain('200')
    }, 60_000)

    it.skipIf(GIT === undefined)(
      'G8b: git schannel backend passes revocation via the served CRL (no schannelCheckRevoke=false)',
      async () => {
        // Trust: `-c http.schannelUseSSLCAInfo=true` makes git-schannel
        // honor `GIT_SSL_CAINFO` (the trust bundle #346 emits). Without
        // it, git-for-windows' patched http.c clears sslCAInfo so
        // schannel reads the Windows store — but on the CI runner that
        // path hits SEC_E_UNTRUSTED_ROOT (system-gitconfig drift; the
        // store-trust path is proven by G8's curl row).
        // Revocation: what this row TESTS — the leaf's CDP → empty CRL
        // on the proxy port means NO `http.schannelCheckRevoke=false`
        // is needed. `-c http.sslBackend=schannel` is explicit so the
        // row is hermetic against the runner's default backend.
        // git-via-proxy is heavier than curl (smart-HTTP), so
        // 45s/attempt + 120s overall.
        SandboxManager.updateConfig(
          onOrdinaryToken(createTlsTestConfig(['example.com', 'github.com'])),
        )
        const r = await runSandboxedUntil(
          `"${GIT}" -c http.sslBackend=schannel -c http.schannelUseSSLCAInfo=true ` +
            `ls-remote https://github.com/git/git.git HEAD`,
          x => x.status === 0 && /HEAD/.test(x.stdout),
          2,
          45_000,
        )
        if (r.status !== 0) {
          // Diagnostic: dump the effective git http.* config so a
          // failure names the runner's system-gitconfig state.
          const cfg = await runSandboxed(
            `"${GIT}" config --list --show-origin 2>&1 | findstr /i "ssl schannel backend"`,
          )
          r.stderr += `\n[G8b diag: git http config]\n${cfg.stdout}${cfg.stderr}`
        }
        expectStatus('G8b', r, [0])
        expect(r.stdout).toMatch(/HEAD/)
      },
      120_000,
    )

    it.skipIf(CARGO === undefined)(
      'G9: cargo trusts the MITM CA via CARGO_HTTP_CAINFO',
      async () => {
        // cargo's vendored libcurl is Schannel but honors `CAINFO`
        // (replace semantics). Revocation is satisfied by the leaf's
        // CDP → empty CRL served on the proxy port, so no
        // `CARGO_HTTP_CHECK_REVOKE=false` needed. Skips when cargo
        // lives under the broker's profile (`~/.cargo/bin` on GHA
        // runners) — srt-sandbox cannot read it; see
        // `sandboxReachable`.
        SandboxManager.updateConfig(
          onOrdinaryToken(
            createTlsTestConfig([
              'crates.io',
              'static.crates.io',
              'index.crates.io',
            ]),
          ),
        )
        const r = await runSandboxedUntil(
          `"${CARGO}" search serde --limit 1`,
          x => x.status === 0 && /serde/.test(x.stdout),
          2,
          30_000,
        )
        expectStatus('G9', r, [0])
        expect(r.stdout).toMatch(/serde/)
      },
      120_000,
    )
  },
)

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
    // Under the ordinary token: P3, which shares this session, proves
    // the trust with a Schannel client.
    const cfg = onOrdinaryToken(createTestConfig(['example.com']))
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

  it('P3: schannel trusts the persistent CA end-to-end (System32 curl)', async () => {
    // Mirrors G8 but with the persistent (not fixture) CA — the
    // load-bearing proof that an embedder passing `tlsTerminate:{}`
    // gets working schannel-level trust with zero orchestration.
    expect(
      (await SandboxManager.wrapWithSandboxArgv('echo x')).argv,
    ).not.toContain('--write-restricted-token')
    const r = await runSandboxedUntil(
      `"${SYSTEM32_CURL}" -sS -o NUL -w "%{http_code}" https://example.com/`,
      x => x.status === 0,
    )
    expectStatus('P3', r, [0])
    expect(r.stdout).toContain('200')
  }, 60_000)

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
