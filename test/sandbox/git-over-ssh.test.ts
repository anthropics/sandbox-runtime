import { afterAll, beforeAll, describe, expect, it, spyOn } from 'bun:test'
import { spawn, spawnSync } from 'node:child_process'
import { createHash, randomBytes } from 'node:crypto'
import { once } from 'node:events'
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { connect, createServer } from 'node:net'
import type { AddressInfo, Server, Socket } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createHttpProxyServer } from '../../src/sandbox/http-proxy.js'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import {
  generateProxyEnvVars,
  sshConnectScript,
} from '../../src/sandbox/sandbox-utils.js'
import * as platform from '../../src/utils/platform.js'
import { quote } from '../../src/utils/shell-quote.js'
import { bwrapCanNamespaceNetwork } from '../helpers/bwrap-namespace.js'
import { isLinux, isMacOS, isWindows } from '../helpers/platform.js'
import { spawnAsync } from '../helpers/spawn.js'
import type { RunResult } from '../helpers/spawn.js'

/**
 * git over ssh through the authenticating proxy, with nothing outside this
 * host: an unprivileged sshd on loopback, a scratch repository, the real
 * ssh, git and proxy.
 *
 * macOS gets its own ProxyCommand (`sshConnectScript`). Everything but its
 * `nc` is portable, so the script is driven on Linux too, with the nc found
 * there. Two things differ and are marked below: the nc of macOS leaves as
 * soon as the network side ends, netcat-openbsd only once its stdin has
 * ended as well; and the nc of macOS half-closes the socket at the end of
 * stdin, which netcat-openbsd does only under -N.
 */

const NC = existsSync('/usr/bin/nc') ? '/usr/bin/nc' : Bun.which('nc')
const SSHD = existsSync('/usr/sbin/sshd') ? '/usr/sbin/sshd' : Bun.which('sshd')
const absent = (tools: Record<string, unknown>): string => {
  const names = Object.keys(tools).filter(name => !tools[name])
  return names.length > 0 ? ` [SKIPPED: no ${names.join(', ')}]` : ''
}
const NO_SCRIPT = isWindows ? ' [SKIPPED: Windows]' : absent({ nc: NC })
const NO_SSH =
  NO_SCRIPT ||
  absent({
    sshd: SSHD,
    ssh: Bun.which('ssh'),
    'ssh-keygen': Bun.which('ssh-keygen'),
    git: Bun.which('git'),
  })
const NO_SANDBOX =
  NO_SSH ||
  (isLinux
    ? absent({
        'network namespaces': bwrapCanNamespaceNetwork(),
        socat: Bun.which('socat'),
      })
    : '')

const SHELLS = [
  '/bin/sh',
  '/bin/bash',
  '/bin/zsh',
  '/bin/dash',
  '/bin/ksh',
  '/bin/tcsh',
  '/bin/csh',
  Bun.which('fish'),
].filter((s): s is string => s !== null && existsSync(s))

const TOKEN = '0123456789abcdef0123456789abcdef'
const basicOf = (token: string): string =>
  Buffer.from(`srt.Zm9v:${token}`).toString('base64')

/** Well under every test's own limit: what "promptly" means below. */
const PROMPT_MS = 15_000
const TEST_MS = 90_000

function listen(server: Server): Promise<number> {
  return new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () =>
      resolve((server.address() as AddressInfo).port),
    )
  })
}

/** A loopback port nothing listens on. */
async function freePort(): Promise<number> {
  const server = createServer()
  const port = await listen(server)
  await new Promise(resolve => server.close(resolve))
  return port
}

/**
 * The library's HTTP proxy, requiring TOKEN; `asked` is what reached its
 * filter, which takes its time, as one that asks somebody does.
 */
async function startProxy(allowedPort: number): Promise<{
  port: number
  asked: string[]
  close: () => void
}> {
  const asked: string[] = []
  const proxy = createHttpProxyServer({
    filter: async (port, host, _socket, encodedCommand, explain) => {
      asked.push(`${host}:${port} ${encodedCommand}`)
      await new Promise(resolve => setTimeout(resolve, 200))
      explain?.('not today')
      return host === '127.0.0.1' && port === allowedPort
    },
    proxyAuthToken: TOKEN,
  })
  return {
    port: await listen(proxy),
    asked,
    close: () => {
      proxy.close()
      proxy.closeAllConnections()
    },
  }
}

/** The two variables macOS is given, whatever host this runs on. */
function macosVars(proxyPort: number, token = TOKEN): Record<string, string> {
  const spy = spyOn(platform, 'getPlatform').mockReturnValue('macos')
  try {
    const vars = Object.fromEntries(
      generateProxyEnvVars(proxyPort, proxyPort, undefined, token, true, 'Zm9v')
        .filter(v => /^(GIT_SSH_COMMAND|SRT_SSH_PROXY_COMMAND)=/.test(v))
        .map(v => [v.slice(0, v.indexOf('=')), v.slice(v.indexOf('=') + 1)]),
    )
    return NC === '/usr/bin/nc'
      ? vars
      : {
          ...vars,
          SRT_SSH_PROXY_COMMAND: sshConnectScript(
            proxyPort,
            basicOf(token),
            NC!,
          ),
        }
  } finally {
    spy.mockRestore()
  }
}

/** A running ProxyCommand, held the way ssh holds one: both pipes open. */
function hold(argv: string[], env: Record<string, string>) {
  const child = spawn(argv[0]!, argv.slice(1), {
    env: { ...process.env, ...env },
  })
  const out: Buffer[] = []
  let err = ''
  child.stdout.on('data', (d: Buffer) => out.push(d))
  child.stderr.on('data', (d: Buffer) => (err += d.toString()))
  child.stdin.on('error', () => {})
  const started = Date.now()
  const outEnded = once(child.stdout, 'end').then(() => Date.now() - started)
  const exited = once(child, 'close').then(([code]) => code as number | null)
  return {
    child,
    stdout: () => Buffer.concat(out),
    stderr: () => err,
    /** Resolves to the time it took stdout to end. */
    outEnded,
    exited,
    /** What ssh does: once its input has ended, it closes its output and goes. */
    async leaveLikeSsh(): Promise<{ ms: number; code: number | null }> {
      const ms = await outEnded
      child.stdin.end()
      return { ms, code: await exited }
    },
  }
}

/** The script with `host` and `port` as ssh's %h and %p, past every shell. */
const runScript = (
  script: string,
  host: string,
  port: string,
  sh = ['/bin/sh'],
  env: Record<string, string> = {},
) =>
  hold([...sh, '-c', 'eval "$SRT_SSH_PROXY_COMMAND"', 'sh', host, port], {
    ...env,
    SRT_SSH_PROXY_COMMAND: script,
  })

/**
 * A shell whose `[a-z]` follows the locale, where there is one: bash does up
 * to 4.2, which is the /bin/sh of macOS, and later when asked to.
 */
const UTF8 = { LC_ALL: 'en_US.UTF-8' }
const COLLATING_SH = [
  ['/bin/sh'],
  ['/bin/bash', '--posix', '+O', 'globasciiranges'],
].find(
  ([sh, ...options]) =>
    !isWindows &&
    spawnSync(sh!, [...options, '-c', 'case \u00fc in [a-z]) exit 7;; esac'], {
      env: UTF8,
    }).status === 7,
)

async function until(what: string, done: () => boolean): Promise<void> {
  const deadline = Date.now() + PROMPT_MS
  while (!done()) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`)
    await new Promise(resolve => setTimeout(resolve, 10))
  }
}

describe.skipIf(NO_SCRIPT !== '')(`sshConnectScript${NO_SCRIPT}`, () => {
  const servers: Server[] = []
  const sockets: Socket[] = []
  const closers: Array<() => void> = []

  /** A TCP server that records what it is sent, per connection. */
  async function tcp(onData: (sock: Socket, all: Buffer) => void): Promise<{
    port: number
    received: Buffer[]
  }> {
    const received: Buffer[] = []
    const server = createServer({ allowHalfOpen: true }, sock => {
      const i = received.push(Buffer.alloc(0)) - 1
      sockets.push(sock)
      sock.on('error', () => {})
      sock.on('data', d => {
        received[i] = Buffer.concat([received[i]!, d])
        onData(sock, received[i])
      })
    })
    servers.push(server)
    return { port: await listen(server), received }
  }

  afterAll(() => {
    for (const s of sockets) s.destroy()
    for (const s of servers) s.close()
    for (const close of closers) close()
  })

  const EVERY_BYTE = Buffer.concat(
    Array<Buffer>(64).fill(
      Buffer.from(Array.from({ length: 256 }, (_, i) => i)),
    ),
  )
  const OK = 'HTTP/1.1 200 Connection Established\r\n\r\n'
  /** Answers a whole request head with `reply`, and leaves. */
  const answer =
    (reply: string) =>
    (sock: Socket, all: Buffer): void => {
      if (all.includes('\r\n\r\n') && !sock.writableEnded) sock.end(reply)
    }
  const headFor = (authority: string): string =>
    `CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\n` +
    `Proxy-Authorization: Basic ${basicOf(TOKEN)}\r\n\r\n`

  it(
    'sends one CONNECT with the credential, then every byte both ways and nothing else',
    async () => {
      const head = headFor('git.example.com:22')
      const up = Buffer.concat([Buffer.from('SSH-2.0-up\r\n'), EVERY_BYTE])
      const down = Buffer.concat([Buffer.from('SSH-2.0-down\r\n'), EVERY_BYTE])
      let answered = false
      const proxy = await tcp((sock, all) => {
        if (!answered && all.includes('\r\n\r\n')) {
          answered = true
          sock.write(OK)
          sock.write(down)
        }
        if (all.length >= head.length + up.length) sock.end()
      })
      const t = runScript(
        sshConnectScript(proxy.port, basicOf(TOKEN), NC!),
        'git.example.com',
        '22',
      )
      t.child.stdin.write(up)
      await until('the download', () => t.stdout().length >= down.length)
      t.child.stdin.end()
      expect(await t.exited).toBe(0)
      expect(proxy.received).toHaveLength(1)
      expect(proxy.received[0]!.toString('latin1')).toBe(
        head + up.toString('latin1'),
      )
      expect(t.stdout().equals(down)).toBe(true)
      expect(t.stderr()).toBe('')
    },
    TEST_MS,
  )

  it(
    'brackets an IPv6 literal',
    async () => {
      const proxy = await tcp(answer(OK))
      const t = runScript(
        sshConnectScript(proxy.port, basicOf(TOKEN), NC!),
        '2001:db8::1',
        '2222',
      )
      await until('the request', () => proxy.received.length > 0)
      t.child.stdin.end()
      expect(await t.exited).toBe(0)
      expect(proxy.received[0]!.toString()).toBe(headFor('[2001:db8::1]:2222'))
    },
    TEST_MS,
  )

  it(
    'refuses a host or port that is not plainly one, before it connects',
    async () => {
      const proxy = await tcp(() => {})
      const script = sshConnectScript(proxy.port, basicOf(TOKEN), NC!)
      const hosts = [
        '',
        'a\r\nX-Injected: 1',
        'a\nb',
        'a\rb',
        'a b',
        'a\tb',
        "a'b",
        'a"b',
        'a$b',
        'a`b`',
        'a%b',
        'a%sb',
        'a\\b',
        'a/b',
        'a@b',
        'a;b',
        'a*',
        'a?',
        '[::1]',
        'a:22 HTTP/1.1',
        'b\u00fccher.example',
      ]
      for (const host of hosts) {
        const t = runScript(script, host, '22')
        expect([host, await t.leaveLikeSsh().then(r => r.code)]).toEqual([
          host,
          1,
        ])
        expect(t.stderr()).toBe('sandbox proxy: bad host\n')
        expect(t.stdout()).toHaveLength(0)
      }
      for (const port of ['', '22x', '2 2', '22\r\n', '22\nX: 1', '-1', '%s']) {
        const t = runScript(script, 'a.example', port)
        expect([port, await t.leaveLikeSsh().then(r => r.code)]).toEqual([
          port,
          1,
        ])
        expect(t.stderr()).toBe('sandbox proxy: bad port\n')
      }
      expect(proxy.received).toHaveLength(0)
    },
    TEST_MS,
  )

  it.skipIf(!COLLATING_SH)(
    `what a letter is does not follow the locale${absent({ 'shell that collates by locale': COLLATING_SH })}`,
    async () => {
      const proxy = await tcp(() => {})
      const t = runScript(
        sshConnectScript(proxy.port, basicOf(TOKEN), NC!),
        'b\u00fccher.example',
        '22',
        COLLATING_SH,
        UTF8,
      )
      expect((await t.leaveLikeSsh()).code).toBe(1)
      expect(t.stderr()).toBe('sandbox proxy: bad host\n')
      expect(proxy.received).toHaveLength(0)
    },
    TEST_MS,
  )

  it(
    'a refusal ends what ssh reads promptly, while ssh still holds its end open, and says why',
    async () => {
      const closedPort = await freePort()
      const proxy = await startProxy(closedPort)
      closers.push(proxy.close)
      const cases: Array<[string, string, string, string]> = [
        [
          'not on the list',
          sshConnectScript(proxy.port, basicOf(TOKEN), NC!),
          String(closedPort - 1),
          '403 not today',
        ],
        [
          'a wrong token',
          sshConnectScript(proxy.port, basicOf('wrong'), NC!),
          String(closedPort),
          '407 Proxy Authentication Required',
        ],
        [
          'allowed, nothing there',
          sshConnectScript(proxy.port, basicOf(TOKEN), NC!),
          String(closedPort),
          '502 Bad Gateway',
        ],
        [
          'the proxy gone',
          sshConnectScript(await freePort(), basicOf(TOKEN), NC!),
          String(closedPort),
          'no answer',
        ],
      ]
      for (const [what, script, port, why] of cases) {
        const t = runScript(script, '127.0.0.1', port)
        t.child.stdin.write('SSH-2.0-client\r\n')
        const { ms, code } = await t.leaveLikeSsh()
        expect([what, code, t.stderr()]).toEqual([
          what,
          1,
          `sandbox proxy: 127.0.0.1:${port}: ${why}\n`,
        ])
        expect(t.stdout()).toHaveLength(0)
        expect(ms).toBeLessThan(PROMPT_MS)
      }
      // The wrong token never reached the allow list.
      expect(proxy.asked).toEqual([
        `127.0.0.1:${closedPort - 1} Zm9v`,
        `127.0.0.1:${closedPort} Zm9v`,
      ])
    },
    TEST_MS,
  )

  it(
    'the end of what ssh writes reaches the far side, whose last words still arrive',
    async () => {
      const far = await tcp(() => {})
      servers[servers.length - 1]!.on('connection', (sock: Socket) => {
        sock.write('hello, ')
        sock.on('end', () => sock.end('last words'))
      })
      const proxy = await startProxy(far.port)
      closers.push(proxy.close)
      const t = runScript(
        // See the head of this file.
        sshConnectScript(
          proxy.port,
          basicOf(TOKEN),
          isMacOS ? NC! : `${NC} -N`,
        ),
        '127.0.0.1',
        String(far.port),
      )
      // Not before the tunnel is up: until then the proxy takes an end of
      // input for a client that has gone, and ssh never sends one so early.
      await until('the tunnel', () => t.stdout().length > 0)
      t.child.stdin.end('first words')
      expect(await t.exited).toBe(0)
      expect(far.received[0]!.toString()).toBe('first words')
      expect(t.stdout().toString()).toBe('hello, last words')
      expect(t.stderr()).toBe('')
    },
    TEST_MS,
  )

  // See the head of this file: netcat-openbsd stays until its stdin ends.
  it.skipIf(!isMacOS)(
    'the far side leaving ends what ssh reads, while ssh still holds its end open (the nc of macOS)',
    async () => {
      const far = await tcp(sock => sock.end('bye'))
      const proxy = await startProxy(far.port)
      closers.push(proxy.close)
      const t = runScript(
        sshConnectScript(proxy.port, basicOf(TOKEN), NC!),
        '127.0.0.1',
        String(far.port),
      )
      t.child.stdin.write('hello')
      const { ms, code } = await t.leaveLikeSsh()
      expect(t.stdout().toString()).toBe('bye')
      expect([code, t.stderr()]).toEqual([0, ''])
      expect(ms).toBeLessThan(PROMPT_MS)
    },
    TEST_MS,
  )

  it(
    'no process of a live tunnel has the credential in its arguments, and none outlives ssh',
    async () => {
      const far = await tcp(sock => sock.write('up'))
      servers[servers.length - 1]!.on('connection', (sock: Socket) =>
        sock.on('end', () => sock.end()),
      )
      const proxy = await startProxy(far.port)
      closers.push(proxy.close)
      // See the head of this file.
      const nc = isMacOS ? NC! : `${NC} -N`
      const t = runScript(
        sshConnectScript(proxy.port, basicOf(TOKEN), nc),
        '127.0.0.1',
        String(far.port),
      )
      const ps = (): string =>
        spawnSync('ps', ['-A', '-ww', '-o', 'args'], { encoding: 'utf8' })
          .stdout
      t.child.stdin.write('hello')
      await until('the tunnel', () => t.stdout().length > 0)
      const live = ps()
      expect(live).toContain(`${nc} 127.0.0.1 ${proxy.port}`)
      expect(live).not.toContain(TOKEN)
      expect(live).not.toContain(basicOf(TOKEN))

      // ssh killed: both its ends of the pipes go at once.
      t.child.stdin.destroy()
      t.child.stdout.destroy()
      await until(
        'the helpers to leave',
        () => !ps().includes(` 127.0.0.1 ${proxy.port}`),
      )
      await t.exited
      expect(t.stderr()).toBe('')
    },
    TEST_MS,
  )

  /** ssh's arguments, split from GIT_SSH_COMMAND by a shell, as git has it done. */
  function proxyCommandOf(gitSshCommand: string): string {
    const r = spawnSync(
      '/bin/sh',
      ['-c', `ssh() { printf '%s\\n' "$@"; }; ${gitSshCommand}`],
      { encoding: 'utf8' },
    )
    const option = r.stdout.split('\n').find(a => a.startsWith('ProxyCommand='))
    return option!.slice('ProxyCommand='.length)
  }

  /** What ssh hands to `$SHELL -c`. */
  const expandedBySsh = (command: string, host: string, port: string): string =>
    'exec ' +
    command.replace(/%([hp%])/g, (_, c: string) =>
      c === 'h' ? host : c === 'p' ? port : '%',
    )

  for (const shell of SHELLS) {
    it(
      `SHELL=${shell}: a host name is one word, whatever it holds`,
      async () => {
        const dir = mkdtempSync(join(tmpdir(), 'srt-ssh-word-'))
        const marker = join(dir, 'ran')
        try {
          const proxy = await tcp(answer(OK))
          const vars = macosVars(proxy.port)
          const command = proxyCommandOf(vars.GIT_SSH_COMMAND!)
          const env = { SRT_SSH_PROXY_COMMAND: vars.SRT_SSH_PROXY_COMMAND! }

          const plain = hold(
            [shell, '-c', expandedBySsh(command, 'a.example', '22')],
            env,
          )
          await until('the request', () => proxy.received.length > 0)
          plain.child.stdin.end()
          expect([await plain.exited, plain.stderr()]).toEqual([0, ''])
          expect(proxy.received.map(String)).toEqual([headFor('a.example:22')])

          // OpenSSH 9.6 and later refuse these themselves; earlier ones hand
          // them over. (A single quote ends the word in any spelling.)
          for (const host of [
            `$(echo >>${marker})`,
            `\`echo >>${marker}\``,
            `a;echo >>${marker}`,
            `a|echo >>${marker}`,
            `a&echo >>${marker}`,
            `a\necho >>${marker}`,
            'a b',
            'a"b',
            'a\\',
            'a!b',
            '$HOME',
            '*',
          ]) {
            const t = hold(
              [shell, '-c', expandedBySsh(command, host, '22')],
              env,
            )
            expect([host, (await t.leaveLikeSsh()).code === 0]).toEqual([
              host,
              false,
            ])
          }
          expect(existsSync(marker)).toBe(false)
          expect(proxy.received).toHaveLength(1)
        } finally {
          rmSync(dir, { recursive: true, force: true })
        }
      },
      TEST_MS,
    )
  }
})

describe.skipIf(NO_SSH !== '')(`git over ssh${NO_SSH}`, () => {
  const BLOB_BYTES = 24 << 20
  let dir: string
  let sshd: ReturnType<typeof spawn> | undefined
  let sshdPort: number
  let sshdLog = ''
  let blobSha256: string
  let head: string
  let packs: { upload: string; receive: string }
  let url: (port?: number) => string

  const git = (...args: string[]): string => {
    const r = spawnSync('git', args, { encoding: 'utf8' })
    if (r.status !== 0) throw new Error(`git ${args.join(' ')}: ${r.stderr}`)
    return r.stdout.trim()
  }
  /** Commits `file` in the work tree, outside any sandbox. */
  const commit = (file: string): string => {
    const work = ['-C', join(dir, 'work'), '-c', 'core.compression=0']
    git(...work, 'add', file)
    git(
      ...work,
      ...['-c', 'user.name=t', '-c', 'user.email=t@example.com'],
      ...['commit', '-q', '-m', file],
    )
    return git(...work, 'rev-parse', 'HEAD')
  }
  const sha256 = (file: string): string =>
    createHash('sha256').update(readFileSync(file)).digest('hex')

  /** Everything a red macOS leg has to go on. */
  function explain(what: string, r: RunResult): string {
    return (
      `${what}: status ${r.status}, signal ${r.signal}\n` +
      `--- stdout\n${r.stdout}\n--- stderr\n${r.stderr}\n` +
      `--- sshd\n${sshdLog.slice(-3000)}\n` +
      `--- sandbox violations\n${SandboxManager.getSandboxViolationStore()
        .getViolations()
        .map(v => v.line)
        .join('\n')}`
    )
  }

  async function startSshd(): Promise<void> {
    for (let attempt = 1; ; attempt++) {
      sshdPort = await freePort()
      sshdLog = ''
      writeFileSync(
        join(dir, 'sshd_config'),
        [
          `Port ${sshdPort}`,
          'ListenAddress 127.0.0.1',
          `HostKey ${dir}/host_key`,
          `PidFile ${dir}/sshd.pid`,
          `AuthorizedKeysFile ${dir}/authorized_keys`,
          'StrictModes no',
          'UsePAM no',
          'PasswordAuthentication no',
          'LogLevel VERBOSE',
          '',
        ].join('\n'),
      )
      const child = spawn(SSHD!, ['-D', '-e', '-f', join(dir, 'sshd_config')], {
        stdio: ['ignore', 'ignore', 'pipe'],
      })
      child.stderr.on('data', (d: Buffer) => (sshdLog += d.toString()))
      const deadline = Date.now() + PROMPT_MS
      while (child.exitCode === null && Date.now() < deadline) {
        const listening = await new Promise<boolean>(resolve => {
          const probe = connect(sshdPort, '127.0.0.1')
          probe.once('error', () => resolve(false))
          probe.once('connect', () => {
            probe.destroy()
            resolve(true)
          })
        })
        if (listening) {
          sshd = child
          return
        }
        await new Promise(resolve => setTimeout(resolve, 100))
      }
      child.kill()
      if (attempt === 3) throw new Error(`sshd did not start:\n${sshdLog}`)
    }
  }

  beforeAll(async () => {
    dir = realpathSync(mkdtempSync(join(tmpdir(), 'srt-git-ssh-')))
    for (const key of ['host_key', 'id']) {
      spawnSync('ssh-keygen', [
        ...['-q', '-t', 'ed25519', '-N', '', '-f'],
        join(dir, key),
      ])
    }
    writeFileSync(
      join(dir, 'authorized_keys'),
      readFileSync(join(dir, 'id.pub')),
    )
    await startSshd()
    writeFileSync(
      join(dir, 'known_hosts'),
      `[127.0.0.1]:${sshdPort} ${readFileSync(join(dir, 'host_key.pub'), 'utf8')}`,
    )
    writeFileSync(
      join(dir, 'ssh_config'),
      [
        `IdentityFile ${dir}/id`,
        'IdentitiesOnly yes',
        'IdentityAgent none',
        `UserKnownHostsFile ${dir}/known_hosts`,
        'GlobalKnownHostsFile /dev/null',
        'StrictHostKeyChecking yes',
        'BatchMode yes',
        '',
      ].join('\n'),
    )

    git('init', '-q', '--bare', join(dir, 'repo.git'))
    git('init', '-q', join(dir, 'work'))
    writeFileSync(join(dir, 'work', 'blob'), randomBytes(BLOB_BYTES))
    blobSha256 = sha256(join(dir, 'work', 'blob'))
    head = commit('blob')
    git(
      ...['-C', join(dir, 'work'), 'push', '-q'],
      ...[join(dir, 'repo.git'), 'HEAD:refs/heads/main'],
    )
    // By path: what sshd puts on PATH need not hold the git under test.
    const execPath = git('--exec-path')
    packs = {
      upload: join(execPath, 'git-upload-pack'),
      receive: join(execPath, 'git-receive-pack'),
    }
    url = (port = sshdPort) => `ssh://127.0.0.1:${port}${dir}/repo.git`

    console.log(
      `git over ssh: ${spawnSync('ssh', ['-V'], { encoding: 'utf8' }).stderr.trim()}; ` +
        `${git('--version')}; sshd ${SSHD}; nc ${NC}; shells ${SHELLS.join(' ')}`,
    )
  }, TEST_MS)

  afterAll(() => {
    sshd?.kill()
    if (dir) rmSync(dir, { recursive: true, force: true })
  })

  describe('the macOS variables, run as git runs them', () => {
    let proxy: Awaited<ReturnType<typeof startProxy>>

    beforeAll(async () => {
      proxy = await startProxy(sshdPort)
    })
    afterAll(() => proxy?.close())

    const run = (
      shell: string,
      vars: Record<string, string>,
      ...args: string[]
    ): Promise<RunResult> =>
      spawnAsync('git', args, {
        env: {
          ...process.env,
          ...vars,
          GIT_SSH_COMMAND: `${vars.GIT_SSH_COMMAND} -F ${dir}/ssh_config`,
          SHELL: shell,
        },
        timeout: TEST_MS / 2,
      })

    for (const shell of SHELLS) {
      it(
        `SHELL=${shell}: ls-remote`,
        async () => {
          proxy.asked.length = 0
          const r = await run(
            shell,
            macosVars(proxy.port),
            ...['ls-remote', '--upload-pack', packs.upload, url(), 'main'],
          )
          expect(explain(shell, r)).toStartWith(`${shell}: status 0,`)
          expect(r.stdout).toBe(`${head}\trefs/heads/main\n`)
          expect(r.stderr).toBe('')
          // Attributed to the command, as every other client's requests are.
          expect(proxy.asked).toEqual([`127.0.0.1:${sshdPort} Zm9v`])
        },
        TEST_MS,
      )
    }

    it(
      'a wrong token is refused promptly, and ssh says who refused',
      async () => {
        const started = Date.now()
        const r = await run(
          '/bin/sh',
          macosVars(proxy.port, 'wrong'),
          ...['ls-remote', '--upload-pack', packs.upload, url(), 'main'],
        )
        expect(Date.now() - started).toBeLessThan(PROMPT_MS)
        expect(r.status).toBe(128)
        expect(r.stderr).toContain(
          `sandbox proxy: 127.0.0.1:${sshdPort}: 407 Proxy Authentication Required\n`,
        )
      },
      TEST_MS,
    )

    it(
      'a host that ssh lets through and printf would rewrite goes nowhere',
      async () => {
        proxy.asked.length = 0
        const r = await run(
          '/bin/sh',
          macosVars(proxy.port),
          ...['ls-remote', '--upload-pack', packs.upload],
          `ssh://127.0%s.0.1:${sshdPort}${dir}/repo.git`,
        )
        expect(r.status).toBe(128)
        expect(r.stderr).toContain('sandbox proxy: bad host\n')
        expect(proxy.asked).toEqual([])
      },
      TEST_MS,
    )
  })

  describe.skipIf(NO_SANDBOX !== '')(`inside the sandbox${NO_SANDBOX}`, () => {
    const DENY_REASON = 'ssh to this port is blocked; use an https:// remote'
    const ASK_REASON = 'asked, and refused'
    let deniedPort: number

    beforeAll(async () => {
      deniedPort = await freePort()
      await SandboxManager.reset()
      await SandboxManager.initialize(
        {
          // The literal with its port: a name that resolves to loopback is
          // refused, and a literal is an explicit choice.
          network: {
            allowedDomains: [`127.0.0.1:${sshdPort}`],
            deniedDomains: [`127.0.0.1:${deniedPort}`],
            deniedDomainReasons: { [`127.0.0.1:${deniedPort}`]: DENY_REASON },
          },
          filesystem: { denyRead: [], allowWrite: [dir], denyWrite: [] },
        },
        // A refusal that comes late, when ssh has long sent its first bytes.
        async () => {
          await new Promise(resolve => setTimeout(resolve, 500))
          return { allow: false, reason: ASK_REASON }
        },
      )
    }, TEST_MS)

    afterAll(async () => {
      await SandboxManager.reset()
    })

    const CONFIG = (): string => quote(['-F', join(dir, 'ssh_config')])
    /** What the sandbox injects, plus where this test's keys are. */
    const injected = (): string =>
      `GIT_SSH_COMMAND="$GIT_SSH_COMMAND "${quote([CONFIG()])}`
    /**
     * The macOS variables in place of the injected ones. On Linux the proxy
     * is the sandbox's own listener on 3128.
     */
    const macos = (token = SandboxManager.getProxyAuthToken()!): string => {
      const vars = macosVars(
        isLinux ? 3128 : SandboxManager.getProxyPort()!,
        token,
      )
      return quote([
        'env',
        `SRT_SSH_PROXY_COMMAND=${vars.SRT_SSH_PROXY_COMMAND}`,
        `GIT_SSH_COMMAND=${vars.GIT_SSH_COMMAND} ${CONFIG()}`,
      ])
    }

    async function sandboxed(
      vars: string,
      ...args: string[]
    ): Promise<RunResult & { ms: number; command: string }> {
      const command = `${vars} git ${quote(args)}`
      const started = Date.now()
      const r = await spawnAsync(
        await SandboxManager.wrapWithSandbox(command),
        { timeout: TEST_MS / 2 },
      )
      return { ...r, ms: Date.now() - started, command }
    }

    // On its own, so that a profile that does not let the script's nc out is
    // told from everything else that can go wrong further down.
    it(
      'nc reaches the proxy on 127.0.0.1',
      async () => {
        const port = isLinux ? 3128 : SandboxManager.getProxyPort()!
        const r = await spawnAsync(
          await SandboxManager.wrapWithSandbox(
            // The sleep holds nc's stdin open, as ssh does, until the answer.
            `{ printf 'GET http://x.invalid/ HTTP/1.1\\r\\nHost: x.invalid\\r\\nConnection: close\\r\\n\\r\\n'; sleep 2; } | ${NC} -v 127.0.0.1 ${port}`,
          ),
          { timeout: TEST_MS / 2 },
        )
        expect(explain('nc', r)).toStartWith('nc: status 0,')
        expect(r.stdout).toStartWith('HTTP/1.1 407 ')
      },
      TEST_MS,
    )

    const spellings: Array<[string, () => string]> = [
      [`as injected on ${isMacOS ? 'macOS' : 'Linux'}`, injected],
      // On macOS that is the injected one already.
      ...(isLinux
        ? [['the macOS spelling, forced', macos] as [string, () => string]]
        : []),
    ]

    for (const [spelling, vars] of spellings) {
      const n = spellings.findIndex(s => s[0] === spelling)

      it(
        `${spelling}: ls-remote`,
        async () => {
          const r = await sandboxed(
            vars(),
            ...['ls-remote', '--upload-pack', packs.upload, url(), 'main'],
          )
          expect(explain(spelling, r)).toStartWith(`${spelling}: status 0,`)
          expect(r.stdout).toBe(`${head}\trefs/heads/main\n`)
        },
        TEST_MS,
      )

      it(
        `${spelling}: clones ${BLOB_BYTES >> 20} MiB intact`,
        async () => {
          const dest = join(dir, `clone-${n}`)
          const r = await sandboxed(
            vars(),
            ...['clone', '-q', '--upload-pack', packs.upload, url(), dest],
          )
          expect(explain(spelling, r)).toStartWith(`${spelling}: status 0,`)
          expect(sha256(join(dest, 'blob'))).toBe(blobSha256)
        },
        TEST_MS,
      )

      it(
        `${spelling}: pushes ${BLOB_BYTES >> 20} MiB intact`,
        async () => {
          // A blob the far side does not have yet.
          const file = join(dir, 'work', `up-${n}`)
          writeFileSync(file, randomBytes(BLOB_BYTES))
          commit(`up-${n}`)
          const r = await sandboxed(
            vars(),
            ...['-C', join(dir, 'work'), '-c', 'core.compression=0'],
            ...['push', '-q', '--receive-pack', packs.receive],
            ...[url(), `HEAD:refs/heads/pushed-${n}`],
          )
          expect(explain(spelling, r)).toStartWith(`${spelling}: status 0,`)
          const arrived = spawnSync(
            'git',
            [
              '-C',
              join(dir, 'repo.git'),
              'cat-file',
              'blob',
              `pushed-${n}:up-${n}`,
            ],
            { maxBuffer: 2 * BLOB_BYTES },
          )
          expect(
            createHash('sha256').update(arrived.stdout).digest('hex'),
          ).toBe(sha256(file))
        },
        TEST_MS,
      )

      /** How the ProxyCommand of this spelling words a 403. */
      const refusal = (port: number, reason: string): string =>
        vars === injected && isLinux
          ? ` CONNECT 127.0.0.1:${port}: ${reason}\n` // socat
          : `sandbox proxy: 127.0.0.1:${port}: 403 ${reason}\n`

      it(
        `${spelling}: a destination on the deny list is refused in the words configured for it`,
        async () => {
          const r = await sandboxed(
            vars(),
            ...['ls-remote', '--upload-pack', packs.upload, url(deniedPort)],
          )
          expect(r.status).toBe(128)
          expect(r.ms).toBeLessThan(PROMPT_MS)
          expect(r.stderr).toContain(refusal(deniedPort, DENY_REASON))
        },
        TEST_MS,
      )

      it(
        `${spelling}: a destination on no list is refused, late, in the words of whoever was asked`,
        async () => {
          const other = await freePort()
          const r = await sandboxed(
            vars(),
            ...['ls-remote', '--upload-pack', packs.upload, url(other)],
          )
          expect(r.status).toBe(128)
          expect(r.ms).toBeLessThan(PROMPT_MS)
          expect(r.stdout).toBe('')
          expect(r.stderr).toContain(refusal(other, ASK_REASON))
          if (vars === injected) {
            // The user name that went with the token names the command.
            expect(
              SandboxManager.getSandboxViolationStore()
                .getViolationsForCommand(r.command)
                .map(v => v.line),
            ).toContain(
              `deny network-outbound 127.0.0.1:${other} (${ASK_REASON})`,
            )
          }
        },
        TEST_MS,
      )
    }

    it(
      'the macOS spelling: a wrong token is refused promptly',
      async () => {
        const r = await sandboxed(
          macos('wrong'),
          ...['ls-remote', '--upload-pack', packs.upload, url()],
        )
        expect(r.status).toBe(128)
        expect(r.ms).toBeLessThan(PROMPT_MS)
        expect(r.stderr).toContain(
          `sandbox proxy: 127.0.0.1:${sshdPort}: 407 Proxy Authentication Required\n`,
        )
      },
      TEST_MS,
    )

    it(
      'the macOS spelling: a host that ssh lets through and printf would rewrite goes nowhere',
      async () => {
        const r = await sandboxed(
          macos(),
          ...['ls-remote', '--upload-pack', packs.upload],
          `ssh://127.0%s.0.1:${sshdPort}${dir}/repo.git`,
        )
        expect(r.status).toBe(128)
        expect(r.stderr).toContain('sandbox proxy: bad host\n')
      },
      TEST_MS,
    )
  })
})
