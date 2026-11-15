import { describe, it, expect, beforeAll } from 'bun:test'
import { spawnSync } from 'node:child_process'
import { existsSync } from 'node:fs'
import { getApplySeccompBinaryPath } from '../../src/sandbox/generate-seccomp-filter.js'
import {
  wrapCommandWithSandboxLinux,
  checkLinuxDependencies,
} from '../../src/sandbox/linux-sandbox-utils.js'
import { isLinux } from '../helpers/platform.js'

/**
 * Tests for the nested PID namespace isolation in apply-seccomp.
 *
 * apply-seccomp creates a nested user+PID+mount namespace so that the
 * sandboxed command cannot see — and therefore cannot ptrace or patch
 * via /proc/N/mem — any process that runs without the seccomp filter
 * (bwrap's init, the bash wrapper, and the socat proxy helpers).
 *
 * These tests exercise apply-seccomp directly and through the full
 * bwrap wrapper to verify both layers hold.
 */

let applySeccomp: string | null = null

function runApplySeccomp(
  args: string[],
  opts: { timeout?: number } = {},
): { status: number | null; stdout: string; stderr: string } {
  const r = spawnSync(applySeccomp!, args, {
    stdio: 'pipe',
    timeout: opts.timeout ?? 10000,
  })
  return {
    status: r.status,
    stdout: r.stdout?.toString() ?? '',
    stderr: r.stderr?.toString() ?? '',
  }
}

describe.if(isLinux)('apply-seccomp PID namespace isolation', () => {
  beforeAll(() => {
    applySeccomp = getApplySeccompBinaryPath()
    // On Linux CI with the vendor binary present this always resolves.
    // If null, every test below would silently no-op — fail here.
    expect(applySeccomp).toBeTruthy()
    expect(existsSync(applySeccomp!)).toBe(true)
  })

  // ------------------------------------------------------------------
  // Basic process-model sanity
  // ------------------------------------------------------------------

  it('runs the command as PID 2 under an apply-seccomp init (PID 1)', () => {
    const r = runApplySeccomp([
      'sh',
      '-c',
      'echo "self=$$"; echo "init=$(cat /proc/1/comm)"',
    ])
    expect(r.status).toBe(0)
    expect(r.stdout).toContain('self=2')
    expect(r.stdout).toMatch(/init=apply-seccomp/)
  })

  it('shows only the inner namespace in /proc', () => {
    const r = runApplySeccomp([
      'sh',
      '-c',
      'ls /proc | grep -E "^[0-9]+$" | sort -n',
    ])
    expect(r.status).toBe(0)
    const pids = r.stdout
      .trim()
      .split('\n')
      .map(s => parseInt(s, 10))
    // PID 1 is apply-seccomp init, PID 2 is sh; ls/grep/sort add a few more.
    // What matters is that none of the host's PIDs leak in.
    expect(pids[0]).toBe(1)
    expect(Math.max(...pids)).toBeLessThan(20)
  })

  it('forwards exit codes from the inner command', () => {
    expect(runApplySeccomp(['sh', '-c', 'exit 0']).status).toBe(0)
    expect(runApplySeccomp(['sh', '-c', 'exit 1']).status).toBe(1)
    expect(runApplySeccomp(['sh', '-c', 'exit 42']).status).toBe(42)
    expect(runApplySeccomp(['sh', '-c', 'exit 127']).status).toBe(127)
  })

  it('forwards signal exits as 128+signo', () => {
    const r = runApplySeccomp(['sh', '-c', 'kill -TERM $$'])
    expect(r.status).toBe(128 + 15)
  })

  it('forwards SIGTERM from the outside through both inits to the command', () => {
    // PID 1 drops signals it has no handler for. apply-seccomp's inner init
    // must install handlers so SIGTERM from the caller actually reaches the
    // workload.
    const r = spawnSync(
      'timeout',
      ['--preserve-status', '-s', 'TERM', '1', applySeccomp!, 'sleep', '10'],
      { stdio: 'pipe', timeout: 10000 },
    )
    expect(r.status).toBe(128 + 15)
  })

  it('reaps orphaned grandchildren without leaking zombies', () => {
    // Spawn a grandchild that outlives its parent; inner init (PID 1)
    // must reap it. If reaping is broken this either hangs or leaves
    // the grandchild running — the timeout catches both.
    const r = runApplySeccomp(['sh', '-c', '(sleep 0.2 &) ; exit 7'], {
      timeout: 5000,
    })
    expect(r.status).toBe(7)
  })

  it('exits when the main command exits, even with a long-running background process', () => {
    // Inner init must return as soon as the worker exits, not wait for
    // reparented background children. PID 1 exiting tears down the
    // namespace and SIGKILLs the straggler.
    const r = runApplySeccomp(['sh', '-c', 'sleep 100 & exit 5'], {
      timeout: 3000,
    })
    expect(r.status).toBe(5)
  })

  // ------------------------------------------------------------------
  // Seccomp still applies inside the nested namespace
  // ------------------------------------------------------------------

  it('blocks AF_UNIX socket creation', () => {
    const r = runApplySeccomp([
      'python3',
      '-c',
      'import socket; socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)',
    ])
    expect(r.status).not.toBe(0)
    expect(r.stderr.toLowerCase()).toMatch(
      /permission denied|operation not permitted/,
    )
  })

  it('allows AF_INET socket creation', () => {
    const r = runApplySeccomp([
      'python3',
      '-c',
      'import socket; socket.socket(socket.AF_INET, socket.SOCK_STREAM); print("ok")',
    ])
    expect(r.status).toBe(0)
    expect(r.stdout).toContain('ok')
  })

  it('blocks io_uring_setup (IORING_OP_SOCKET bypass of socket() filter)', () => {
    // IORING_OP_SOCKET (Linux 5.19+) creates sockets in kernel context,
    // bypassing seccomp's socket() rule. The filter must block
    // io_uring_setup so no ring can be created.
    const r = runApplySeccomp([
      'python3',
      '-c',
      [
        'import ctypes, os',
        'libc = ctypes.CDLL(None, use_errno=True)',
        'p = (ctypes.c_byte * 256)()',
        'fd = libc.syscall(425, 4, p)  # __NR_io_uring_setup',
        'err = ctypes.get_errno()',
        'print(f"fd={fd} errno={err}")',
        'exit(1 if fd >= 0 else 0)',
      ].join('\n'),
    ])
    expect(r.status).toBe(0)
    expect(r.stdout).toMatch(/fd=-1 errno=1\b/) // EPERM
  })

  it('blocks io_uring_enter (covers inherited ring fd)', () => {
    const r = runApplySeccomp([
      'python3',
      '-c',
      [
        'import ctypes',
        'libc = ctypes.CDLL(None, use_errno=True)',
        'r = libc.syscall(426, 99, 0, 0, 0, 0, 0)  # __NR_io_uring_enter',
        'print(f"r={r} errno={ctypes.get_errno()}")',
      ].join('\n'),
    ])
    // EPERM (1) from seccomp, not EBADF (9) from a bad fd — seccomp runs first.
    expect(r.stdout).toMatch(/r=-1 errno=1\b/)
  })

  // ------------------------------------------------------------------
  // PID 1 is not controllable from the sandboxed command
  // ------------------------------------------------------------------

  it('denies ptrace(PTRACE_ATTACH) against PID 1', () => {
    const r = runApplySeccomp([
      'python3',
      '-c',
      [
        'import ctypes, os',
        'libc = ctypes.CDLL(None, use_errno=True)',
        'r = libc.ptrace(16, 1, 0, 0)  # PTRACE_ATTACH',
        'err = ctypes.get_errno()',
        'print(f"r={r} errno={err}")',
        'exit(0 if r != 0 else 1)',
      ].join('\n'),
    ])
    expect(r.status).toBe(0)
    expect(r.stdout).toMatch(/r=-1 errno=(1|13)/) // EPERM or EACCES
  })

  it('denies opening /proc/1/mem for writing', () => {
    const r = runApplySeccomp([
      'python3',
      '-c',
      [
        'try:',
        '    open("/proc/1/mem", "r+b")',
        '    print("OPENED")',
        '    exit(1)',
        'except PermissionError:',
        '    print("DENIED")',
        '    exit(0)',
      ].join('\n'),
    ])
    expect(r.status).toBe(0)
    expect(r.stdout).toContain('DENIED')
  })

  it('runs the user command with zero effective capabilities', () => {
    // bwrap passes CAP_SYS_ADMIN (ambient) so apply-seccomp can nest a
    // PID+mount namespace. apply-seccomp must clear the ambient set before
    // exec so the workload cannot, e.g., umount /proc to reveal the outer
    // namespace underneath.
    const r = runApplySeccomp(['grep', 'CapEff', '/proc/self/status'])
    expect(r.status).toBe(0)
    expect(r.stdout).toMatch(/CapEff:\s*0+$/m)
  })

  it('denies umount(/proc) from the user command', () => {
    const r = runApplySeccomp([
      'python3',
      '-c',
      [
        'import ctypes, os',
        'libc = ctypes.CDLL(None, use_errno=True)',
        'r = libc.umount2(b"/proc", 0)',
        'print(f"r={r} errno={ctypes.get_errno()}")',
        'exit(0 if r < 0 else 1)',
      ].join('\n'),
    ])
    expect(r.status).toBe(0)
    expect(r.stdout).toMatch(/r=-1 errno=1\b/) // EPERM
  })

  it('denies process_vm_writev against PID 1', () => {
    const r = runApplySeccomp([
      'python3',
      '-c',
      [
        'import ctypes, os',
        'libc = ctypes.CDLL(None, use_errno=True)',
        'class iovec(ctypes.Structure):',
        '    _fields_ = [("base", ctypes.c_void_p), ("len", ctypes.c_size_t)]',
        'buf = ctypes.create_string_buffer(b"x")',
        'local = iovec(ctypes.cast(buf, ctypes.c_void_p).value, 1)',
        'remote = iovec(0x1000, 1)',
        'r = libc.process_vm_writev(1, ctypes.byref(local), 1, ctypes.byref(remote), 1, 0)',
        'err = ctypes.get_errno()',
        'print(f"r={r} errno={err}")',
        // EPERM (1) from PR_SET_DUMPABLE=0, or ESRCH (3) if check happens first.
        'exit(0 if r < 0 and err in (1, 3, 13) else 1)',
      ].join('\n'),
    ])
    expect(r.status).toBe(0)
  })
})

describe.if(isLinux)(
  'Full bwrap integration — outer processes are unreachable',
  () => {
    beforeAll(() => {
      applySeccomp = getApplySeccompBinaryPath()
      expect(applySeccomp).toBeTruthy()
      // CI apt-installs bwrap and socat; if missing the suite would no-op.
      expect(checkLinuxDependencies().errors).toEqual([])
    })

    it('hides outer-namespace helpers (socat analogue) from the inner command', async () => {
      // Spawn a background `sleep` in the outer bwrap namespace (stand-in for
      // socat), then run apply-seccomp. The inner command must not see `sleep`
      // in /proc.
      const wrapped = await wrapCommandWithSandboxLinux({
        command: [
          'sleep 30 &',
          'SLEEP_OUTER=$!',
          'for p in /proc/[0-9]*; do cat "$p/comm" 2>/dev/null; done | grep -qx sleep',
          'OUTER_SAW=$?',
          `${applySeccomp} sh -c '` +
            'for p in /proc/[0-9]*; do cat "$p/comm" 2>/dev/null; done | grep -qx sleep; ' +
            'echo "INNER_SAW=$?"' +
            `'`,
          'kill $SLEEP_OUTER 2>/dev/null',
          'echo "OUTER_SAW=$OUTER_SAW"',
        ].join('\n'),
        needsNetworkRestriction: false,
        writeConfig: { allowOnly: ['/tmp'], denyWithinAllow: [] },
        allowAllUnixSockets: true, // we invoke apply-seccomp ourselves here
        // ... and it makes a user namespace of its own, which a wrap with no
        // helper in it otherwise has bubblewrap refuse (--disable-userns).
        allowNestedUserNamespaces: true,
      })

      const r = spawnSync('bash', ['-c', wrapped], {
        stdio: 'pipe',
        timeout: 15000,
      })
      const out = r.stdout?.toString() ?? ''
      // Outer namespace sees the sleep (grep exit 0), inner does not (grep exit 1).
      expect(out).toContain('OUTER_SAW=0')
      expect(out).toContain('INNER_SAW=1')
    })

    it('cannot ptrace the real bwrap init from inside the sandbox', async () => {
      // With the normal wrapper (seccomp on), PID 1 from the user command's
      // view is apply-seccomp's non-dumpable init, not bwrap.
      const wrapped = await wrapCommandWithSandboxLinux({
        command: [
          'python3 -c "',
          'import ctypes, os',
          'libc = ctypes.CDLL(None, use_errno=True)',
          'r = libc.ptrace(16, 1, 0, 0)',
          'err = ctypes.get_errno()',
          'comm = open(\\"/proc/1/comm\\").read().strip()',
          'print(f\\"ptrace={r} errno={err} pid1={comm}\\")',
          '"',
        ].join('\n'),
        needsNetworkRestriction: false,
        writeConfig: { allowOnly: ['/tmp'], denyWithinAllow: [] },
      })

      const r = spawnSync('bash', ['-c', wrapped], {
        stdio: 'pipe',
        timeout: 15000,
      })
      const out = r.stdout?.toString() ?? ''
      expect(out).toMatch(/ptrace=-1/)
      expect(out).toMatch(/pid1=apply-seccomp/)
    })

    it('cannot open bwrap /proc/1/mem from inside the sandbox', async () => {
      const wrapped = await wrapCommandWithSandboxLinux({
        command:
          'python3 -c "open(\\"/proc/1/mem\\", \\"r+b\\")" 2>&1 || echo BLOCKED',
        needsNetworkRestriction: false,
        writeConfig: { allowOnly: ['/tmp'], denyWithinAllow: [] },
      })

      const r = spawnSync('bash', ['-c', wrapped], {
        stdio: 'pipe',
        timeout: 15000,
      })
      const out = r.stdout?.toString() ?? ''
      expect(out).toContain('BLOCKED')
      expect(out.toLowerCase()).toMatch(/permission denied/)
    })
  },
)
