import { afterAll, beforeAll, describe, expect, it } from 'bun:test'
import { spawnSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { getApplySeccompBinaryPath } from '../../src/sandbox/generate-seccomp-filter.js'
import {
  checkLinuxDependencies,
  wrapCommandWithSandboxLinux,
  type LinuxSandboxParams,
} from '../../src/sandbox/linux-sandbox-utils.js'
import { startLinuxSandboxViolationMonitor } from '../../src/sandbox/linux-violation-monitor.js'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import { sanitizeUnregisteredCommandKey } from '../../src/sandbox/sandbox-violation-store.js'
import { quote } from '../../src/utils/shell-quote.js'
import { bwrapCanNamespaceNetwork } from '../helpers/bwrap-namespace.js'
import { isLinux } from '../helpers/platform.js'
import { spawnAsync } from '../helpers/spawn.js'

/**
 * allowUnixSocketCreation keeps the seccomp helper and leaves only its AF_UNIX
 * rule out. Each assertion is on the errno, as in seccomp-vsock-block.test.ts,
 * and INIT names PID 1 of the command's PID namespace: the helper when it is
 * in the chain, bubblewrap when it is not.
 */
const PROBE = [
  'import ctypes, errno, os, socket',
  'def attempt(label, family, kind):',
  '    try:',
  '        socket.socket(family, kind).close()',
  '        print(label + "=OK")',
  '    except OSError as e:',
  '        print(label + "=" + errno.errorcode.get(e.errno, str(e.errno)))',
  'attempt("UNIX", socket.AF_UNIX, socket.SOCK_STREAM)',
  'attempt("UNIX_DGRAM", socket.AF_UNIX, socket.SOCK_DGRAM)',
  'attempt("VSOCK", socket.AF_VSOCK, socket.SOCK_STREAM)',
  // io_uring_setup(4, &params): 425 on both x86_64 and aarch64.
  'libc = ctypes.CDLL(None, use_errno=True)',
  'params = ctypes.create_string_buffer(120)',
  'fd = libc.syscall(ctypes.c_long(425), ctypes.c_uint(4), params)',
  'print("IO_URING=" + ("OK" if fd >= 0 else errno.errorcode.get(ctypes.get_errno(), "?")))',
  'print("ENV=" + os.environ.get("SRT_ALLOW_UNIX_SOCKETS", "unset"))',
  'print("INIT=" + open("/proc/1/comm").read().strip())',
].join('\n')

const ALLOWED =
  'UNIX=OK\nUNIX_DGRAM=OK\nVSOCK=EPERM\nIO_URING=EPERM\nENV=unset\n'
const REFUSED =
  'UNIX=EPERM\nUNIX_DGRAM=EPERM\nVSOCK=EPERM\nIO_URING=EPERM\nENV=unset\n'

describe.if(isLinux)('apply-seccomp with SRT_ALLOW_UNIX_SOCKETS', () => {
  let applySeccomp: string

  const underHelper = (value: string | undefined) => {
    const env = { ...process.env }
    delete env.SRT_ALLOW_UNIX_SOCKETS
    if (value !== undefined) env.SRT_ALLOW_UNIX_SOCKETS = value
    return spawnSync(applySeccomp, ['python3', '-c', PROBE], {
      encoding: 'utf8',
      env,
      timeout: 10000,
    })
  }

  beforeAll(() => {
    applySeccomp = getApplySeccompBinaryPath()!
    expect(applySeccomp).toBeTruthy()
  })

  it('with 1, allows Unix sockets and keeps VM sockets and io_uring refused', () => {
    const r = underHelper('1')
    expect(r.stdout).toContain(ALLOWED)
    expect(r.stdout).toContain('INIT=apply-seccomp')
    expect(r.status).toBe(0)
  })

  it('with any other value, or none, refuses Unix sockets as before', () => {
    for (const value of [undefined, '0', '', 'yes', 'true', ' 1']) {
      const r = underHelper(value)
      expect(r.stdout).toContain(REFUSED)
      expect(r.status).toBe(0)
    }
  })
})

describe.if(isLinux)('allowUnixSocketCreation in the Linux sandbox', () => {
  const wrap = (params: Partial<LinuxSandboxParams>) =>
    wrapCommandWithSandboxLinux({
      command: quote(['python3', '-c', PROBE]),
      needsNetworkRestriction: false,
      writeConfig: { allowOnly: ['/tmp'], denyWithinAllow: [] },
      ...params,
    })

  const run = (wrapped: string) =>
    spawnAsync(wrapped, { shell: true, encoding: 'utf8', timeout: 15000 })

  beforeAll(async () => {
    expect(checkLinuxDependencies().errors).toEqual([])
    await SandboxManager.reset()
  })

  afterAll(async () => {
    await SandboxManager.reset()
  })

  it('tells the helper what the configuration says, whatever was inherited', async () => {
    expect(await wrap({ allowUnixSocketCreation: true })).toContain(
      'SRT_ALLOW_UNIX_SOCKETS=1 SRT_ALLOW_NESTED_USERNS=0 ',
    )
    expect(await wrap({})).toContain(
      'SRT_ALLOW_UNIX_SOCKETS=0 SRT_ALLOW_NESTED_USERNS=0 ',
    )
    expect(await wrap({})).toContain('--unsetenv SRT_ALLOW_UNIX_SOCKETS')
  })

  it('lets the command make Unix sockets, with the helper still in the chain', async () => {
    const r = await run(await wrap({ allowUnixSocketCreation: true }))
    expect(r.stdout).toContain(ALLOWED)
    expect(r.stdout).toContain('INIT=apply-seccomp')
    expect(r.status).toBe(0)
  })

  it('without it, refuses them as before', async () => {
    const r = await run(await wrap({}))
    expect(r.stdout).toContain(REFUSED)
    expect(r.stdout).toContain('INIT=apply-seccomp')
    expect(r.status).toBe(0)
  })

  it('is ignored beside allowAllUnixSockets, which runs no helper', async () => {
    const wrapped = await wrap({
      allowAllUnixSockets: true,
      allowUnixSocketCreation: true,
    })
    expect(wrapped).not.toContain('SRT_ALLOW_UNIX_SOCKETS=1')
    const r = await run(wrapped)
    expect(r.stdout).toContain('UNIX=OK')
    expect(r.stdout).not.toContain('INIT=apply-seccomp')
    expect(r.status).toBe(0)
  })

  it('still reports blocked writes', async () => {
    const work = mkdtempSync(join(tmpdir(), 'srt-unix-'))
    const allow = join(work, 'rw')
    const deny = join(work, 'ro')
    mkdirSync(allow)
    mkdirSync(deny)
    const lines: string[] = []
    const monitor = startLinuxSandboxViolationMonitor(v => lines.push(v.line), {
      allowWritePaths: [allow, '/dev'],
      denyWritePaths: [deny],
      resolveCommandText: sanitizeUnregisteredCommandKey,
    })
    await monitor.ready
    try {
      const wrapped = await wrap({
        command: `echo a > ${quote([`${allow}/ok`])}; echo b > ${quote([`${deny}/bad`])}`,
        writeConfig: { allowOnly: [allow], denyWithinAllow: [] },
        allowUnixSocketCreation: true,
        observeSocketPath: monitor.observeSocketPath,
      })
      await run(wrapped)
      await new Promise(r => setTimeout(r, 100))
      expect(lines).toContain(`deny openat ${deny}/bad`)
      expect(lines.some(l => l.includes(`${allow}/ok`))).toBe(false)
    } finally {
      monitor.stop()
      rmSync(work, { recursive: true, force: true })
    }
  })

  it.skipIf(!bwrapCanNamespaceNetwork())(
    'is read from the network configuration, in a network-restricted sandbox',
    async () => {
      await SandboxManager.initialize({
        network: {
          allowedDomains: [],
          deniedDomains: [],
          allowUnixSocketCreation: true,
        },
        filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
      })
      const wrapped = await SandboxManager.wrapWithSandbox(
        quote(['python3', '-c', PROBE]),
      )
      expect(wrapped).toContain('--unshare-net')
      expect(wrapped).toContain('SRT_ALLOW_UNIX_SOCKETS=1 ')

      const r = await run(wrapped)
      expect(r.stdout).toContain(ALLOWED)
      expect(r.stdout).toContain('INIT=apply-seccomp')
      expect(r.status).toBe(0)
    },
    40000,
  )
})
