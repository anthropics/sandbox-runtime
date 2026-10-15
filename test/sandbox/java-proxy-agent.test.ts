import { describe, it, expect, afterAll } from 'bun:test'
import { spawnSync } from 'node:child_process'
import { existsSync } from 'node:fs'
import { createServer, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import { join } from 'node:path'
import {
  buildJavaToolOptions,
  getJavaProxyAgentJarPathAsync,
  JAVA_PROXY_AGENT_JAR_NAME,
} from '../../src/sandbox/java-proxy-agent.js'
import {
  getGlobalNpmPaths,
  getGlobalNpmPathsAsync,
} from '../../src/sandbox/generate-seccomp-filter.js'
import { wrapCommandWithSandboxMacOS } from '../../src/sandbox/macos-sandbox-utils.js'
import {
  resolveSrtWin,
  wrapCommandWithSandboxWindows,
} from '../../src/sandbox/windows-sandbox-utils.js'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import type { SandboxRuntimeConfig } from '../../src/sandbox/sandbox-config.js'
import { spawnAsync } from '../helpers/spawn.js'
import { isLinux, isMacOS } from '../helpers/platform.js'

describe('buildJavaToolOptions', () => {
  it('returns undefined when there is nothing to set', () => {
    expect(buildJavaToolOptions({})).toBeUndefined()
    expect(buildJavaToolOptions({ flags: [], inherited: '' })).toBeUndefined()
  })

  it('emits -javaagent for the jar path', () => {
    expect(buildJavaToolOptions({ agentJarPath: '/tmp/x/a.jar' })).toBe(
      '-javaagent:/tmp/x/a.jar',
    )
  })

  it('double-quotes a jar path containing whitespace', () => {
    // The JVM tokenizes JAVA_TOOL_OPTIONS on whitespace but honours quotes.
    expect(buildJavaToolOptions({ agentJarPath: '/tmp/a b/a.jar' })).toBe(
      '"-javaagent:/tmp/a b/a.jar"',
    )
  })

  it('preserves the inherited value and appends flags once', () => {
    expect(
      buildJavaToolOptions({
        agentJarPath: '/j.jar',
        flags: ['-Dfoo=1', '-Dbar=2'],
        inherited: '-Xmx1g -Dbar=2',
      }),
    ).toBe('-javaagent:/j.jar -Xmx1g -Dbar=2 -Dfoo=1')
  })

  it('drops the inherited value when JAVA_TOOL_OPTIONS is denied', () => {
    expect(
      buildJavaToolOptions({
        agentJarPath: '/j.jar',
        inherited: '-Dsecret=1',
        unsetEnvVars: ['JAVA_TOOL_OPTIONS'],
      }),
    ).toBe('-javaagent:/j.jar')
  })

  it('still emits flags alone (no agent) for the macOS IPv4 case', () => {
    expect(
      buildJavaToolOptions({ flags: ['-Djava.net.preferIPv4Stack=true'] }),
    ).toBe('-Djava.net.preferIPv4Stack=true')
  })
})

// The jar is a build artifact (vendor/java-proxy-agent/srt-proxy-agent.jar,
// `npm run build:java-agent`, needs a JDK) and is not in git; CI builds it
// before `bun test`. Suites that need it on disk self-skip otherwise.
const jarPath = await getJavaProxyAgentJarPathAsync()

describe('getJavaProxyAgentJarPathAsync', () => {
  it('prefers an existing explicit path, and falls back past a missing one', async () => {
    const explicit = join(
      import.meta.dir,
      '..',
      'fixtures',
      'java-proxy-agent',
      'ProxyProbe.java',
    )
    expect(await getJavaProxyAgentJarPathAsync(explicit)).toBe(explicit)
    // A distinct missing path is its own cache key, so this runs the full
    // lookup (including the async global-npm fallback) rather than a hit.
    // Either the vendor jar (when built) or null — never the bogus path.
    expect(
      await getJavaProxyAgentJarPathAsync('/nonexistent/async-agent.jar'),
    ).toBe(jarPath)
  })

  it('getGlobalNpmPathsAsync shares the sync cache and fallbacks', async () => {
    const asyncPaths = await getGlobalNpmPathsAsync()
    expect(getGlobalNpmPaths()).toBe(asyncPaths)
    expect(asyncPaths).toContain(
      join('/usr', 'lib', 'node_modules', '@anthropic-ai', 'sandbox-runtime'),
    )
  })

  it.if(jarPath !== null)('finds the built jar under vendor/', () => {
    expect(
      jarPath!.endsWith(
        join('vendor', 'java-proxy-agent', JAVA_PROXY_AGENT_JAR_NAME),
      ),
    ).toBe(true)
    expect(existsSync(jarPath!)).toBe(true)
  })
})

describe.if(isMacOS)('macOS wrapper', () => {
  it('injects the agent and the IPv4 flag into JAVA_TOOL_OPTIONS', () => {
    // The IPv4 flag rides along whenever a proxy port is advertised: without
    // it Java's dual-stack socket reaches the proxy as ::ffff:127.0.0.1 and
    // Seatbelt denies the connect the agent just set up.
    const wrapped = wrapCommandWithSandboxMacOS({
      command: 'true',
      needsNetworkRestriction: true,
      httpProxyPort: 3128,
      javaAgentJarPath: '/tmp/srt-java-x/srt-proxy-agent.jar',
      readConfig: undefined,
      writeConfig: undefined,
    })
    expect(wrapped).toContain(
      'JAVA_TOOL_OPTIONS=-javaagent:/tmp/srt-java-x/srt-proxy-agent.jar -Djava.net.preferIPv4Stack=true',
    )
  })

  it('keeps the IPv4 flag alone for allowLocalBinding without a proxy', () => {
    const wrapped = wrapCommandWithSandboxMacOS({
      command: 'true',
      needsNetworkRestriction: true,
      allowLocalBinding: true,
      readConfig: undefined,
      writeConfig: undefined,
    })
    expect(wrapped).toContain(
      'JAVA_TOOL_OPTIONS=-Djava.net.preferIPv4Stack=true',
    )
  })

  it('omits JAVA_TOOL_OPTIONS when loopback is unreachable anyway', () => {
    const wrapped = wrapCommandWithSandboxMacOS({
      command: 'true',
      needsNetworkRestriction: true,
      readConfig: undefined,
      writeConfig: undefined,
    })
    expect(wrapped).not.toContain('JAVA_TOOL_OPTIONS')
  })
})

// Pure object test — the Windows wrapper only builds an argv, so this runs
// on every platform (srtWin.path is the test runner's own executable so the
// existence check passes). What the child's environment receives is the
// `--env` overlay plus the `--env-stdin` frame; the returned `env` is the
// broker's. JAVA_TOOL_OPTIONS can carry the broker's own value (-D secrets
// included), so it must reach the child through the frame only.
describe('Windows wrapper (pure, all platforms)', () => {
  const JAR = 'C:\\srt\\java-agent-x\\srt-proxy-agent.jar'
  const TOKEN = 'tok-secret-not-for-argv'

  function wrap(
    extra: Partial<Parameters<typeof wrapCommandWithSandboxWindows>[0]> = {},
    inherited?: string,
  ) {
    const saved = process.env.JAVA_TOOL_OPTIONS
    if (inherited === undefined) delete process.env.JAVA_TOOL_OPTIONS
    else process.env.JAVA_TOOL_OPTIONS = inherited
    try {
      const r = wrapCommandWithSandboxWindows({
        command: 'mvn -q verify',
        httpProxyPort: 60080,
        socksProxyPort: 60080,
        proxyAuthToken: TOKEN,
        srtWin: resolveSrtWin({ path: process.execPath }),
        ...extra,
      })
      const envArgs = r.argv.filter((_, i) => r.argv[i - 1] === '--env')
      const frame: [string, string][] = r.stdinPayload
        ? JSON.parse(r.stdinPayload.subarray(4).toString('utf8'))
        : []
      // Never on argv, in any form: command lines are readable by
      // same-user sibling processes.
      expect(envArgs.some(e => /^JAVA_TOOL_OPTIONS=/i.test(e))).toBe(false)
      for (const a of r.argv) {
        expect(a).not.toContain('-javaagent:')
        if (inherited) expect(a).not.toContain(inherited)
      }
      return {
        ...r,
        frame,
        jto: frame
          .filter(([k]) => k === 'JAVA_TOOL_OPTIONS')
          .map(([k, v]) => `${k}=${v}`),
      }
    } finally {
      if (saved === undefined) delete process.env.JAVA_TOOL_OPTIONS
      else process.env.JAVA_TOOL_OPTIONS = saved
    }
  }

  it('injects the agent through the stdin frame: native path, no IPv4 flag', () => {
    // No -Djava.net.preferIPv4Stack=true: the WFP loopback PERMIT matches
    // the IPv4 connect a dual-stack socket makes (see the wrapper).
    expect(wrap({ javaAgentJarPath: JAR }).jto).toEqual([
      `JAVA_TOOL_OPTIONS=-javaagent:${JAR}`,
    ])
  })

  it('keeps the credential off JAVA_TOOL_OPTIONS and off argv: it rides the stdin frame', () => {
    const { argv, env, frame, jto } = wrap(
      { javaAgentJarPath: JAR },
      '-Dbroker.secret=hunter2',
    )
    expect(jto[0]).not.toContain('@')
    for (const a of argv) expect(a).not.toContain(TOKEN)
    // The broker (srt-win) is not a JVM: the variable is dropped from its
    // spawn env rather than left as one more same-user-readable copy.
    expect(env.JAVA_TOOL_OPTIONS).toBeUndefined()
    // What the agent reads at JVM start: the proxy endpoint in the
    // loopback port range, with the per-session token as its password.
    const https = frame.find(([k]) => k === 'HTTPS_PROXY')![1]
    expect(https).toMatch(
      new RegExp(`^http://[^:@]+:${TOKEN}@localhost:60080$`),
    )
    expect(frame.find(([k]) => k === 'HTTP_PROXY')![1]).toBe(https)
  })

  it('still uses the frame when there is no auth token (external proxy)', () => {
    const { argv, stdinPayload, frame } = wrap({
      javaAgentJarPath: JAR,
      proxyAuthToken: undefined,
    })
    expect(argv).toContain('--env-stdin')
    expect(stdinPayload).toBeDefined()
    expect(frame).toEqual([['JAVA_TOOL_OPTIONS', `-javaagent:${JAR}`]])
  })

  it('composes with an existing JAVA_TOOL_OPTIONS, agent first', () => {
    expect(
      wrap({ javaAgentJarPath: JAR }, '-Dfile.encoding=UTF-8 -Xmx1g').jto,
    ).toEqual([
      `JAVA_TOOL_OPTIONS=-javaagent:${JAR} -Dfile.encoding=UTF-8 -Xmx1g`,
    ])
  })

  it('drops the existing value when JAVA_TOOL_OPTIONS is a denied credential', () => {
    expect(
      wrap(
        { javaAgentJarPath: JAR, unsetEnvVars: ['JAVA_TOOL_OPTIONS'] },
        '-Dsecret=1',
      ).jto,
    ).toEqual([`JAVA_TOOL_OPTIONS=-javaagent:${JAR}`])
  })

  it('composes against a mask sentinel rather than the real value', () => {
    const { argv, jto } = wrap(
      {
        javaAgentJarPath: JAR,
        setEnvVars: { JAVA_TOOL_OPTIONS: '-Dkey=SENTINEL' },
      },
      '-Dkey=real-secret',
    )
    expect(jto).toEqual([`JAVA_TOOL_OPTIONS=-javaagent:${JAR} -Dkey=SENTINEL`])
    for (const a of argv) expect(a).not.toContain('real-secret')
    // The sentinel is overridden in the frame, not also left on --env:
    // srt-win requires the two channels' keys to be disjoint.
    for (const a of argv) expect(a).not.toContain('SENTINEL')
  })

  it('double-quotes a jar path containing whitespace', () => {
    const spaced = 'C:\\Users\\A B\\Temp\\srt-java-agent-x\\srt-proxy-agent.jar'
    expect(wrap({ javaAgentJarPath: spaced }).jto).toEqual([
      `JAVA_TOOL_OPTIONS="-javaagent:${spaced}"`,
    ])
  })

  it('omits JAVA_TOOL_OPTIONS when there is no jar, even if the broker has one', () => {
    // Without the agent nothing of the broker's is forwarded: the child
    // keeps whatever its own profile environment carries.
    const off = wrap({}, '-Dbroker.only=1')
    expect(off.jto).toEqual([])
    // …and the broker's own env is not touched either.
    expect(off.env.JAVA_TOOL_OPTIONS).toBe('-Dbroker.only=1')
    expect(wrap({}).jto).toEqual([])
  })
})

describe.if((isLinux || isMacOS) && jarPath !== null)('sandboxed child', () => {
  afterAll(async () => {
    await SandboxManager.reset()
  })

  it('sees JAVA_TOOL_OPTIONS pointing at a readable agent jar', async () => {
    const config: SandboxRuntimeConfig = {
      network: { allowedDomains: ['example.com'], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    }
    await SandboxManager.initialize(config)
    const wrapped = await SandboxManager.wrapWithSandbox(
      // The agent flag comes first; macOS appends -Djava.net.preferIPv4Stack.
      'sh -c \'echo "JTO=$JAVA_TOOL_OPTIONS"; jar="${JAVA_TOOL_OPTIONS#-javaagent:}"; jar="${jar%% *}"; test -r "$jar" && echo READABLE; echo "HP=$HTTPS_PROXY"\'',
    )
    const result = await spawnAsync(wrapped, {
      shell: true,
      encoding: 'utf8',
      timeout: 15000,
    })
    expect(result.status).toBe(0)
    expect(result.stdout).toContain(`JTO=-javaagent:${jarPath}`)
    expect(result.stdout).toContain('READABLE')
    // The credential rides in HTTPS_PROXY, never in JAVA_TOOL_OPTIONS.
    expect(result.stdout).toMatch(/^HP=http:\/\/srt[^:]*:[0-9a-f]{32}@/m)
    const jto = /^JTO=(.*)$/m.exec(result.stdout)![1]
    expect(jto).not.toContain('@')
  })
})

// ---------------------------------------------------------------------------
// End-to-end against a real JVM (needs a JDK >= 11 for the single-file
// source launcher). Skipped when none is available; CI installs one.

function findJava(): string | undefined {
  const candidates = [
    process.env.JAVA_HOME ? join(process.env.JAVA_HOME, 'bin', 'java') : '',
    'java',
  ].filter(Boolean)
  for (const java of candidates) {
    const r = spawnSync(java, ['-version'], { encoding: 'utf8' })
    if (r.status !== 0) continue
    // `openjdk version "21.0.1"` / `java version "1.8.0_392"`
    const m = /version "(\d+)(?:\.(\d+))?/.exec(r.stderr + r.stdout)
    if (!m) continue
    const major = m[1] === '1' ? Number(m[2]) : Number(m[1])
    if (major >= 11) return java
  }
  return undefined
}

const java = findJava()
const PROBE = join(
  import.meta.dir,
  '..',
  'fixtures',
  'java-proxy-agent',
  'ProxyProbe.java',
)

describe.if(java !== undefined && jarPath !== null)(
  'agent inside a JVM',
  () => {
    const proxyEnv = (proxyPort: number) => ({
      ...process.env,
      JAVA_TOOL_OPTIONS: `-javaagent:${jarPath}`,
      // Same shape generateProxyEnvVars emits: percent-encoded username
      // (base64 command suffix), hex token.
      HTTPS_PROXY: `http://srt.YWJj%2Bx%3D%3D:deadbeef@localhost:${proxyPort}`,
      HTTP_PROXY: `http://srt.YWJj%2Bx%3D%3D:deadbeef@localhost:${proxyPort}`,
      NO_PROXY:
        'localhost,127.0.0.1,::1,169.254.0.0/16,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16',
    })

    // spawnAsync, not spawnSync: the proxy tests below talk to an in-process
    // server, and spawnSync would block the loop it runs on (see helpers).
    function runProbe(args: string[], env: NodeJS.ProcessEnv) {
      return spawnAsync(java!, [PROBE, ...args], { env, timeout: 60000 })
    }

    it('translates the proxy env vars into system properties + Authenticator', async () => {
      const r = await runProbe(['props', 'localhost', '3128'], proxyEnv(3128))
      expect(r.status).toBe(0)
      expect(r.stderr).toContain('Picked up JAVA_TOOL_OPTIONS')
      expect(r.stdout).toContain('https.proxyHost=localhost')
      expect(r.stdout).toContain('https.proxyPort=3128')
      expect(r.stdout).toContain('http.proxyHost=localhost')
      expect(r.stdout).toContain('jdk.http.auth.tunneling.disabledSchemes=\n')
      // Percent-decoded username, raw token; both requestor overloads answer;
      // any other endpoint gets nothing.
      expect(r.stdout).toContain('auth.proxy=srt.YWJj+x==:deadbeef')
      expect(r.stdout).toContain('auth.server=srt.YWJj+x==')
      expect(r.stdout).toContain('auth.other=null')
      // NO_PROXY → nonProxyHosts: proxy for the world, direct for loopback and
      // private ranges (172.16/12 expands to 172.16.* … 172.31.*).
      expect(r.stdout).toMatch(/http\.nonProxyHosts=.*172\.31\.\*/)
      expect(r.stdout).toMatch(/select\.https=\[HTTP @ localhost.*:3128\]/)
      expect(r.stdout).toContain('select.localhost=[DIRECT]')
      expect(r.stdout).toContain('select.private=[DIRECT]')
    })

    it('leaves explicitly set proxy properties alone', async () => {
      const env = proxyEnv(3128)
      env.JAVA_TOOL_OPTIONS = `-Dhttps.proxyHost=other -Dhttps.proxyPort=9 ${env.JAVA_TOOL_OPTIONS}`
      const r = await runProbe(['props', 'localhost', '3128'], env)
      expect(r.status).toBe(0)
      expect(r.stdout).toContain('https.proxyHost=other')
      expect(r.stdout).toContain('https.proxyPort=9')
    })

    it('does nothing without proxy env vars', async () => {
      const env: NodeJS.ProcessEnv = {
        ...process.env,
        JAVA_TOOL_OPTIONS: `-javaagent:${jarPath}`,
      }
      for (const k of [
        'HTTPS_PROXY',
        'https_proxy',
        'HTTP_PROXY',
        'http_proxy',
        'NO_PROXY',
        'no_proxy',
      ]) {
        delete env[k]
      }
      const r = await runProbe(['props', 'localhost', '3128'], env)
      expect(r.status).toBe(0)
      expect(r.stdout).toContain('https.proxyHost=null')
      expect(r.stdout).toContain('auth.proxy=null')
      expect(r.stdout).toContain('select.https=[DIRECT]')
    })

    describe('against a challenging proxy', () => {
      let proxy: Server | undefined
      let proxyPort = 0
      const seen: Array<{ method: string; url: string; auth?: string }> = []

      async function startProxy() {
        proxy = createServer((req, res) => {
          seen.push({
            method: req.method!,
            url: req.url!,
            auth: req.headers['proxy-authorization'],
          })
          if (!req.headers['proxy-authorization']) {
            res.writeHead(407, { 'Proxy-Authenticate': 'Basic realm="srt"' })
            res.end()
            return
          }
          res.writeHead(200, { 'Content-Length': '2' })
          res.end('ok')
        })
        proxy.on('connect', (req, sock) => {
          seen.push({
            method: 'CONNECT',
            url: req.url!,
            auth: req.headers['proxy-authorization'],
          })
          if (!req.headers['proxy-authorization']) {
            sock.end(
              'HTTP/1.1 407 Proxy Authentication Required\r\n' +
                'Proxy-Authenticate: Basic realm="srt"\r\n' +
                'Content-Length: 0\r\n\r\n',
            )
            return
          }
          // Accept the tunnel, then hang up: the JVM's TLS handshake fails,
          // which is fine — the assertion is on the CONNECT it sent.
          sock.end('HTTP/1.1 200 OK\r\n\r\n')
        })
        proxyPort = await new Promise<number>((resolve, reject) => {
          proxy!.on('error', reject)
          proxy!.listen(0, '127.0.0.1', () =>
            resolve((proxy!.address() as AddressInfo).port),
          )
        })
      }

      afterAll(async () => {
        if (proxy) await new Promise<void>(r => proxy!.close(() => r()))
      })

      const expectedAuth =
        'Basic ' + Buffer.from('srt.YWJj+x==:deadbeef').toString('base64')

      it('answers a 407 on a plain-HTTP request with the credential', async () => {
        await startProxy()
        seen.length = 0
        const r = await runProbe(
          ['connect', 'http://example.invalid/'],
          proxyEnv(proxyPort),
        )
        expect(r.status).toBe(0)
        expect(r.stdout).toContain('code=200')
        expect(seen.map(s => s.method)).toEqual(['GET', 'GET'])
        expect(seen[0].auth).toBeUndefined()
        expect(seen[1].auth).toBe(expectedAuth)
      })

      it('answers a 407 on CONNECT with Basic (tunneling scheme re-enabled)', async () => {
        seen.length = 0
        const r = await runProbe(
          ['connect', 'https://example.invalid/'],
          proxyEnv(proxyPort),
        )
        expect(r.status).toBe(0)
        const connects = seen.filter(s => s.method === 'CONNECT')
        expect(connects.length).toBeGreaterThanOrEqual(2)
        expect(connects[0].url).toBe('example.invalid:443')
        expect(connects[0].auth).toBeUndefined()
        expect(connects[1].auth).toBe(expectedAuth)
      })
    })
  },
)
