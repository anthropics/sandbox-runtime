import { describe, it, expect, beforeAll, afterAll } from 'bun:test'
import { spawn, spawnSync } from 'node:child_process'
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  symlinkSync,
} from 'node:fs'
import { createServer, type Server } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { getApplySeccompBinaryPath } from '../../src/sandbox/generate-seccomp-filter.js'
import { wrapCommandWithSandboxLinux } from '../../src/sandbox/linux-sandbox-utils.js'
import { startLinuxSandboxViolationMonitor } from '../../src/sandbox/linux-violation-monitor.js'
import { isLinux } from '../helpers/platform.js'

/**
 * `network.allowUnixSockets` on Linux: apply-seccomp brokers every
 * connect()/bind()/listen() through its supervisor and lets a unix connect
 * through only when the canonical target is inside an allow-listed path.
 *
 * These tests drive the apply-seccomp binary directly (no bwrap), which is
 * where the enforcement lives. The kernel floor is 5.6 — below it
 * apply-seccomp says so and blocks unix sockets outright, so the assertions
 * here are written against the brokered behavior CI runs on.
 */

let applySeccomp: string | null = null
let dir = ''
let allowedDir = ''
let allowedSock = ''
let otherSock = ''
let servers: Server[] = []
/** Accept counters — the verdict for the TOCTOU runs is "the forbidden
 *  listener accepted nothing", which only the servers can report. */
let allowedAccepts = 0
let otherAccepts = 0
let tcpPort = 0

/** Run `python3 -c CODE` under apply-seccomp with the given allow entries. */
function runProbe(
  allow: string[],
  code: string,
): { status: number | null; stdout: string; stderr: string } {
  const args = allow.flatMap(p => ['--allow-unix-connect', p])
  const r = spawnSync(applySeccomp!, [...args, '--', 'python3', '-c', code], {
    stdio: 'pipe',
    timeout: 30000,
  })
  return {
    status: r.status,
    stdout: r.stdout?.toString() ?? '',
    stderr: r.stderr?.toString() ?? '',
  }
}

/** Probe helper: python that prints `label: ok` or `label: <ERRNO>`. */
const probe = (label: string, body: string) => `
import socket, errno
def report(fn):
    try:
        fn()
        print("${label}: ok")
    except OSError as e:
        print("${label}: " + str(errno.errorcode.get(e.errno)))
${body}
`

function listen(path: string, onAccept: () => void): Promise<Server> {
  const s = createServer(c => {
    onAccept()
    c.end()
  })
  return new Promise(res => s.listen(path, () => res(s)))
}

function listenTcp(): Promise<Server> {
  const s = createServer(c => c.end())
  return new Promise(res =>
    s.listen(0, '127.0.0.1', () => {
      const a = s.address()
      tcpPort = typeof a === 'object' && a ? a.port : 0
      res(s)
    }),
  )
}

// File-scope so the fixtures outlive the first describe block: the TOCTOU
// runs below need the same two listeners and their accept counters.
beforeAll(async () => {
  if (!isLinux) return
  applySeccomp = getApplySeccompBinaryPath()
  expect(applySeccomp).toBeTruthy()
  expect(existsSync(applySeccomp!)).toBe(true)

  dir = mkdtempSync(join(tmpdir(), 'srt-uds-'))
  allowedDir = join(dir, 'allowed')
  allowedSock = join(allowedDir, 'ok.sock')
  otherSock = join(dir, 'other.sock')
  mkdirSync(allowedDir, { recursive: true })
  servers = [
    await listen(allowedSock, () => (allowedAccepts += 1)),
    await listen(otherSock, () => (otherAccepts += 1)),
    await listenTcp(),
  ]
})

afterAll(() => {
  if (!isLinux) return
  for (const s of servers) s.close()
  rmSync(dir, { recursive: true, force: true })
})

describe.if(isLinux)('allowUnixSockets (Linux brokered connect)', () => {
  it('connects to a socket inside an allow-listed directory', () => {
    const r = runProbe(
      [allowedDir],
      probe(
        'connect',
        `report(lambda: socket.socket(socket.AF_UNIX, socket.SOCK_STREAM).connect("${allowedSock}"))`,
      ),
    )
    expect(r.stdout.trim()).toBe('connect: ok')
  })

  it('refuses a socket outside the allowlist', () => {
    const r = runProbe(
      [allowedDir],
      probe(
        'connect',
        `report(lambda: socket.socket(socket.AF_UNIX, socket.SOCK_STREAM).connect("${otherSock}"))`,
      ),
    )
    expect(r.stdout.trim()).toBe('connect: EPERM')
    // The command's own stderr says why, in policy terms.
    expect(r.stderr).toContain('not in the allowed unix socket paths')
  })

  it('resolves a symlink before matching, in both directions', () => {
    const intoAllowed = join(dir, 'into-allowed.sock')
    const outOfAllowed = join(allowedDir, 'escape.sock')
    symlinkSync(allowedSock, intoAllowed)
    symlinkSync(otherSock, outOfAllowed)

    const viaLink = runProbe(
      [allowedDir],
      probe(
        'connect',
        `report(lambda: socket.socket(socket.AF_UNIX, socket.SOCK_STREAM).connect("${intoAllowed}"))`,
      ),
    )
    expect(viaLink.stdout.trim()).toBe('connect: ok')

    const escape = runProbe(
      [allowedDir],
      probe(
        'connect',
        `report(lambda: socket.socket(socket.AF_UNIX, socket.SOCK_STREAM).connect("${outOfAllowed}"))`,
      ),
    )
    expect(escape.stdout.trim()).toBe('connect: EPERM')
  })

  it('resolves a relative path against the calling process, not the supervisor', () => {
    const allowed = runProbe(
      [allowedDir],
      `import os\nos.chdir("${allowedDir}")\n` +
        probe(
          'connect',
          `report(lambda: socket.socket(socket.AF_UNIX, socket.SOCK_STREAM).connect("ok.sock"))`,
        ),
    )
    expect(allowed.stdout.trim()).toBe('connect: ok')

    const denied = runProbe(
      [allowedDir],
      `import os\nos.chdir("${dir}")\n` +
        probe(
          'connect',
          `report(lambda: socket.socket(socket.AF_UNIX, socket.SOCK_STREAM).connect("other.sock"))`,
        ),
    )
    expect(denied.stdout.trim()).toBe('connect: EPERM')
  })

  it('refuses the abstract namespace, which has no path to allow', () => {
    const r = runProbe(
      [allowedDir],
      probe(
        'abstract',
        `report(lambda: socket.socket(socket.AF_UNIX, socket.SOCK_STREAM).connect("\\0srt-test-abstract"))`,
      ),
    )
    expect(r.stdout.trim()).toBe('abstract: EPERM')
  })

  it('refuses unix bind() and listen(), so the sandbox serves nothing', () => {
    const newSock = join(allowedDir, 'mine.sock')
    const r = runProbe(
      [allowedDir],
      probe(
        'bind',
        `report(lambda: socket.socket(socket.AF_UNIX, socket.SOCK_STREAM).bind("${newSock}"))\n` +
          `import os\nprint("exists:", os.path.exists("${newSock}"))`,
      ),
    )
    expect(r.stdout).toContain('bind: EPERM')
    expect(r.stdout).toContain('exists: False')

    // SO_PASSCRED makes the kernel autobind an abstract name behind bind()'s
    // back when a connect fails, so listen() has to be refused separately.
    const autobind = runProbe(
      [allowedDir],
      `
import socket, errno
s = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
s.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
try:
    s.connect("${allowedSock}")
except OSError:
    pass
try:
    s.listen(5)
    print("listen: ok")
except OSError as e:
    print("listen: " + str(errno.errorcode.get(e.errno)))
`,
    )
    expect(autobind.stdout.trim()).toBe('listen: EPERM')
  })

  it('refuses datagram unix sockets, including the SOCK_RAW spelling', () => {
    const r = runProbe(
      [allowedDir],
      probe(
        'x',
        `
for name, t in (("stream", socket.SOCK_STREAM), ("dgram", socket.SOCK_DGRAM), ("raw", socket.SOCK_RAW)):
    try:
        socket.socketpair(socket.AF_UNIX, t)
        print("pair-" + name + ": ok")
    except OSError as e:
        print("pair-" + name + ": " + str(errno.errorcode.get(e.errno)))
try:
    socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    print("socket-dgram: ok")
except OSError as e:
    print("socket-dgram: " + str(errno.errorcode.get(e.errno)))
`,
      ),
    )
    expect(r.stdout).toContain('pair-stream: ok')
    expect(r.stdout).toContain('pair-dgram: EPERM')
    // unix_create() maps SOCK_RAW onto SOCK_DGRAM, so it is the same channel.
    expect(r.stdout).toContain('pair-raw: EPERM')
    expect(r.stdout).toContain('socket-dgram: EPERM')
  })

  it('refuses seccomp(SECCOMP_FILTER_FLAG_NEW_LISTENER)', () => {
    // Load-bearing: notifications go to the most recently installed
    // listener, so a workload that could install one would receive its own
    // connect() traps and answer CONTINUE. Denying this is what makes a
    // dead supervisor fail closed instead of open.
    const r = runProbe(
      [allowedDir],
      `
import ctypes, errno, os, platform, struct
libc = ctypes.CDLL(None, use_errno=True)
class Fprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]
allow = ctypes.create_string_buffer(struct.pack("HBBI", 0x06, 0, 0, 0x7fff0000))
prog = Fprog(1, ctypes.cast(allow, ctypes.c_void_p))
nr = 317 if platform.machine() == "x86_64" else 277
libc.prctl(38, 1, 0, 0, 0)
r = libc.syscall(nr, 1, 1 << 3, ctypes.byref(prog))
print("new_listener: " + ("ok" if r >= 0 else str(errno.errorcode.get(ctypes.get_errno()))))
`,
    )
    expect(r.stdout.trim()).toBe('new_listener: EPERM')
  })

  it('leaves TCP connect, bind and listen alone', () => {
    const r = runProbe(
      [allowedDir],
      `
import socket, errno
srv = socket.socket()
try:
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    print("tcp-bind-listen: ok")
    c = socket.socket()
    c.connect(srv.getsockname())
    print("tcp-connect: ok")
except OSError as e:
    print("tcp: " + str(errno.errorcode.get(e.errno)))
`,
    )
    expect(r.stdout).toContain('tcp-bind-listen: ok')
    expect(r.stdout).toContain('tcp-connect: ok')
  })

  it('ignores an allow entry that does not exist', () => {
    const r = runProbe(
      [join(allowedDir, 'not-there.sock')],
      probe(
        'connect',
        `report(lambda: socket.socket(socket.AF_UNIX, socket.SOCK_STREAM).connect("${allowedSock}"))`,
      ),
    )
    // Every entry dropped means no allowlist at all: back to blocking
    // socket(AF_UNIX) outright, which is the conservative direction.
    expect(r.stdout.trim()).toBe('connect: EPERM')
    expect(r.stderr).toContain('does not exist')
  })

  it('blocks unix sockets outright when no allowlist is given (unchanged default)', () => {
    const r = runProbe(
      [],
      probe(
        'socket',
        `report(lambda: socket.socket(socket.AF_UNIX, socket.SOCK_STREAM))`,
      ),
    )
    expect(r.stdout.trim()).toBe('socket: EPERM')
  })

  // Both features trap syscalls to the same user-notification listener (the
  // kernel allows only one per task), so they have to be exercised together:
  // filesystem traps are continued into the kernel and reported, while
  // connect() is answered by the supervisor and never continued.
  it('reports write attempts while still enforcing the socket allowlist', async () => {
    const applySeccompPath = getApplySeccompBinaryPath()
    expect(applySeccompPath).toBeTruthy()

    const violations: string[] = []
    const monitor = startLinuxSandboxViolationMonitor(
      v => violations.push(v.line),
      { allowWritePaths: ['/tmp/srt-allowed-writes'], denyWritePaths: [] },
    )
    await monitor.ready
    expect(monitor.observeSocketPath).toBeDefined()

    try {
      const r = spawnSync(
        applySeccompPath!,
        [
          '--allow-unix-connect',
          allowedDir,
          '--',
          'python3',
          '-c',
          `
import socket
socket.socket(socket.AF_UNIX, socket.SOCK_STREAM).connect("${allowedSock}")
print("connect: ok")
try:
    open("/etc/srt-should-not-write", "w")
except OSError:
    pass
try:
    socket.socket(socket.AF_UNIX, socket.SOCK_STREAM).connect("${otherSock}")
    print("other: ok")
except OSError:
    print("other: denied")
`,
        ],
        {
          stdio: 'pipe',
          timeout: 30000,
          env: { ...process.env, SRT_OBSERVE_SOCK: monitor.observeSocketPath },
        },
      )
      expect(r.stdout?.toString()).toContain('connect: ok')
      expect(r.stdout?.toString()).toContain('other: denied')

      await new Promise(res => setTimeout(res, 200))
      expect(
        violations.some(l => l.includes('/etc/srt-should-not-write')),
      ).toBe(true)
    } finally {
      monitor.stop()
    }
  })

  it('keeps servicing calls from grandchildren and forwards the exit status', () => {
    const r = spawnSync(
      applySeccomp!,
      [
        '--allow-unix-connect',
        allowedDir,
        '--',
        'sh',
        '-c',
        `sh -c 'python3 -c "import socket; socket.socket(socket.AF_UNIX, socket.SOCK_STREAM).connect(\\"${allowedSock}\\"); print(\\"grandchild: ok\\")"' ; exit 7`,
      ],
      { stdio: 'pipe', timeout: 30000 },
    )
    expect(r.stdout?.toString()).toContain('grandchild: ok')
    expect(r.status).toBe(7)
  })
})

describe.if(isLinux)('allowUnixSockets under TOCTOU pressure', () => {
  // The broker is only sound because it never answers
  // SECCOMP_USER_NOTIF_FLAG_CONTINUE for connect(): the kernel would re-read
  // the caller's memory and fd table after the check, and a sibling thread
  // can change both. These runs are that sibling thread. They are the
  // regression test for the property, not a demonstration of it — if someone
  // later "simplifies" the supervisor into inspect-then-continue, the
  // forbidden listener starts accepting and this fails.
  const RACE_SECONDS = 2

  let raceBin = ''
  let haveCompiler = false

  beforeAll(() => {
    raceBin = join(dir, 'uds-race')
    const src = join(import.meta.dir, '..', 'fixtures', 'uds-race.c')
    const r = spawnSync('gcc', ['-O2', '-pthread', '-o', raceBin, src], {
      stdio: 'pipe',
      timeout: 60000,
    })
    // gcc is present on the Linux CI legs (they build the seccomp helper).
    haveCompiler = r.status === 0
    if (!haveCompiler) {
      console.warn(
        `[unix-socket-allowlist] skipping race tests: gcc unavailable ` +
          `(${r.stderr?.toString().trim().slice(0, 200)})`,
      )
    }
  })

  /** Count of connections each fixture socket has accepted so far. */
  const accepted = () => ({ allowed: allowedAccepts, forbidden: otherAccepts })

  // Must be async: the listeners live in THIS process, so a synchronous
  // spawn would block the event loop and nothing would ever be accepted —
  // the counters would stay at zero and the test would pass vacuously.
  const runRace = async (
    mode: 'addr' | 'dup2',
  ): Promise<{
    out: string
    before: ReturnType<typeof accepted>
    after: ReturnType<typeof accepted>
  }> => {
    const before = accepted()
    const args = [
      mode,
      allowedSock,
      otherSock,
      String(RACE_SECONDS),
      ...(mode === 'dup2' ? [String(tcpPort)] : []),
    ]
    const child = spawn(
      applySeccomp!,
      ['--allow-unix-connect', allowedDir, '--', raceBin, ...args],
      { stdio: ['ignore', 'pipe', 'pipe'] },
    )
    let out = ''
    child.stdout.on('data', (c: Buffer) => (out += c.toString()))
    await new Promise<void>(res => child.on('close', () => res()))
    // Let the last accepts drain before reading the counters.
    await new Promise(res => setTimeout(res, 250))
    return { out, before, after: accepted() }
  }

  const parse = (out: string, key: string): number =>
    Number(new RegExp(`${key}=(\\d+)`).exec(out)?.[1] ?? -1)

  it('never connects to a forbidden socket while the sockaddr is rewritten', async () => {
    if (!haveCompiler) return
    const { out, before, after } = await runRace('addr')

    // The forbidden listener is the verdict.
    expect(after.forbidden).toBe(before.forbidden)
    expect(parse(out, 'violations')).toBe(0)
    // Non-vacuity: the run has to have actually raced and actually connected,
    // or "nothing reached the forbidden socket" would be true for free.
    expect(parse(out, 'iterations')).toBeGreaterThan(1000)
    expect(parse(out, 'connected')).toBeGreaterThan(100)
    expect(after.allowed).toBeGreaterThan(before.allowed + 100)
  }, 60_000)

  it('never connects to a forbidden socket while the fd number is dup2-swapped', async () => {
    if (!haveCompiler) return
    // Swapping an AF_UNIX socket over an AF_INET fd is what makes
    // "check the family, then let the kernel continue" unsound.
    const { out, before, after } = await runRace('dup2')

    expect(after.forbidden).toBe(before.forbidden)
    expect(parse(out, 'violations')).toBe(0)
    // Non-vacuity: in this mode the successful connects are the TCP ones
    // (the unix half of the flip always targets the forbidden path), so the
    // allowed unix listener is expected to stay untouched.
    expect(parse(out, 'iterations')).toBeGreaterThan(1000)
    expect(parse(out, 'connected')).toBeGreaterThan(100)
  }, 60_000)
})

describe.if(isLinux)('allowUnixSockets (wrapper arguments)', () => {
  const base = {
    command: 'echo hi',
    needsNetworkRestriction: false,
    writeConfig: { allowOnly: ['/tmp/srt-writable'], denyWithinAllow: [] },
  }

  it('passes existing, non-writable entries to apply-seccomp', async () => {
    const socketDir = mkdtempSync(join(tmpdir(), 'srt-uds-arg-'))
    try {
      const wrapped = await wrapCommandWithSandboxLinux({
        ...base,
        allowUnixSockets: [socketDir],
      })
      expect(wrapped).toContain('--allow-unix-connect')
      expect(wrapped).toContain(socketDir)
    } finally {
      rmSync(socketDir, { recursive: true, force: true })
    }
  })

  it('drops an entry the sandbox can also write', async () => {
    const socketDir = mkdtempSync(join(tmpdir(), 'srt-uds-writable-'))
    try {
      const wrapped = await wrapCommandWithSandboxLinux({
        ...base,
        writeConfig: { allowOnly: [socketDir], denyWithinAllow: [] },
        allowUnixSockets: [socketDir],
      })
      // A writable allow-listed directory is one hard link away from every
      // other socket this user owns, so it is not passed through.
      expect(wrapped).not.toContain('--allow-unix-connect')
    } finally {
      rmSync(socketDir, { recursive: true, force: true })
    }
  })

  it('keeps an entry that a denyWrite carve-out covers', async () => {
    const parent = mkdtempSync(join(tmpdir(), 'srt-uds-carve-'))
    const socketDir = join(parent, 'sockets')
    try {
      mkdirSync(socketDir)
      const wrapped = await wrapCommandWithSandboxLinux({
        ...base,
        writeConfig: { allowOnly: [parent], denyWithinAllow: [socketDir] },
        allowUnixSockets: [socketDir],
      })
      expect(wrapped).toContain('--allow-unix-connect')
    } finally {
      rmSync(parent, { recursive: true, force: true })
    }
  })

  it('drops an entry under a glob write root', async () => {
    const parent = mkdtempSync(join(tmpdir(), 'srt-uds-glob-'))
    const socketDir = join(parent, 'sockets')
    try {
      mkdirSync(socketDir)
      const wrapped = await wrapCommandWithSandboxLinux({
        ...base,
        // A glob write root is reduced to the directory it starts from, so
        // an entry underneath it is still recognized as writable.
        writeConfig: { allowOnly: [`${parent}/**`], denyWithinAllow: [] },
        allowUnixSockets: [socketDir],
      })
      expect(wrapped).not.toContain('--allow-unix-connect')
    } finally {
      rmSync(parent, { recursive: true, force: true })
    }
  })

  it('drops an entry that does not exist', async () => {
    const wrapped = await wrapCommandWithSandboxLinux({
      ...base,
      allowUnixSockets: ['/definitely/not/here.sock'],
    })
    expect(wrapped).not.toContain('--allow-unix-connect')
  })

  it('drops every entry when the sandbox restricts writes nowhere', async () => {
    const socketDir = mkdtempSync(join(tmpdir(), 'srt-uds-nowrite-'))
    try {
      // No writeConfig at all: bwrap restricts writes nowhere, so any socket
      // the command can reach can be hard-linked into the allowed directory.
      const wrapped = await wrapCommandWithSandboxLinux({
        command: 'echo hi',
        needsNetworkRestriction: true,
        allowUnixSockets: [socketDir],
      })
      expect(wrapped).not.toContain('--allow-unix-connect')
    } finally {
      rmSync(socketDir, { recursive: true, force: true })
    }
  })

  it('drops every entry when filesystem isolation is off (allowOnly "/")', async () => {
    const socketDir = mkdtempSync(join(tmpdir(), 'srt-uds-fsoff-'))
    try {
      // `filesystem.disabled` resolves to this write config. "/" must survive
      // canonicalization as the root it is, or every entry looks unwritable.
      const wrapped = await wrapCommandWithSandboxLinux({
        ...base,
        writeConfig: { allowOnly: ['/'], denyWithinAllow: [] },
        allowUnixSockets: [socketDir],
      })
      expect(wrapped).not.toContain('--allow-unix-connect')
    } finally {
      rmSync(socketDir, { recursive: true, force: true })
    }
  })

  it('passes nothing when allowAllUnixSockets disables the filter', async () => {
    const socketDir = mkdtempSync(join(tmpdir(), 'srt-uds-all-'))
    try {
      const wrapped = await wrapCommandWithSandboxLinux({
        ...base,
        allowUnixSockets: [socketDir],
        allowAllUnixSockets: true,
      })
      expect(wrapped).not.toContain('--allow-unix-connect')
      expect(wrapped).not.toContain('apply-seccomp')
    } finally {
      rmSync(socketDir, { recursive: true, force: true })
    }
  })
})
