import { afterAll, beforeAll, describe, expect, it } from 'bun:test'
import { spawnSync } from 'node:child_process'
import { getApplySeccompBinaryPath } from '../../src/sandbox/generate-seccomp-filter.js'
import {
  checkLinuxDependencies,
  wrapCommandWithSandboxLinux,
} from '../../src/sandbox/linux-sandbox-utils.js'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import { quote } from '../../src/utils/shell-quote.js'
import { bwrapCanNamespaceNetwork } from '../helpers/bwrap-namespace.js'
import { isLinux } from '../helpers/platform.js'
import { spawnAsync } from '../helpers/spawn.js'

/**
 * Every vsock assertion is on the errno. seccomp answers before the kernel
 * looks at the family, so under the filter the result is EPERM whether or not
 * the host has a vsock transport. Without the rule the kernel answers with a
 * socket, ENODEV or EAFNOSUPPORT, unless a container runtime's own seccomp
 * profile already refuses the family.
 */

// Prints `<label>=OK` or `<label>=<errno name>` for each socket() attempt.
const ATTEMPT = [
  'import errno, socket',
  'def attempt(label, family, kind):',
  '    try:',
  '        socket.socket(family, kind).close()',
  '        print(label + "=OK")',
  '    except OSError as e:',
  '        print(label + "=" + errno.errorcode.get(e.errno, str(e.errno)))',
]

const VSOCK_ATTEMPTS = [
  ...ATTEMPT,
  'attempt("STREAM", socket.AF_VSOCK, socket.SOCK_STREAM)',
  'attempt("DGRAM", socket.AF_VSOCK, socket.SOCK_DGRAM)',
  'attempt("SEQPACKET", socket.AF_VSOCK, socket.SOCK_SEQPACKET)',
].join('\n')

const VSOCK_REFUSED = 'STREAM=EPERM\nDGRAM=EPERM\nSEQPACKET=EPERM\n'

describe.if(isLinux)('apply-seccomp refuses AF_VSOCK sockets', () => {
  let applySeccomp: string

  const underFilter = (script: string) =>
    spawnSync(applySeccomp, ['python3', '-c', script], {
      encoding: 'utf8',
      timeout: 10000,
    })

  beforeAll(() => {
    applySeccomp = getApplySeccompBinaryPath()!
    expect(applySeccomp).toBeTruthy()
  })

  it('answers EPERM for every socket type', () => {
    const r = underFilter(VSOCK_ATTEMPTS)
    expect(r.stdout).toContain(VSOCK_REFUSED)
    expect(r.status).toBe(0)
  })

  it('answers EPERM when the upper half of the domain register is set', () => {
    // The kernel reads the domain as a 32-bit int, so a raw syscall that sets
    // bits above it still asks for AF_VSOCK. The rule has to mask them off.
    const r = underFilter(
      [
        'import ctypes, errno, platform, socket',
        'nr = {"x86_64": 41, "aarch64": 198}[platform.machine()]',
        'libc = ctypes.CDLL(None, use_errno=True)',
        'domain = ctypes.c_ulong(socket.AF_VSOCK | (1 << 32) | (1 << 63))',
        'fd = libc.syscall(ctypes.c_long(nr), domain, ctypes.c_ulong(1), ctypes.c_ulong(0))',
        'print("fd=%d errno=%s" % (fd, errno.errorcode.get(ctypes.get_errno())))',
      ].join('\n'),
    )
    expect(r.stdout).toContain('fd=-1 errno=EPERM')
    expect(r.status).toBe(0)
  })

  it('leaves other socket families alone', () => {
    const r = underFilter(
      [
        ...ATTEMPT,
        'attempt("INET", socket.AF_INET, socket.SOCK_STREAM)',
        'attempt("INET_DGRAM", socket.AF_INET, socket.SOCK_DGRAM)',
        'attempt("INET6", socket.AF_INET6, socket.SOCK_STREAM)',
        'attempt("NETLINK", socket.AF_NETLINK, socket.SOCK_RAW)',
        'attempt("BELOW", socket.AF_VSOCK - 1, socket.SOCK_STREAM)',
        'attempt("ABOVE", socket.AF_VSOCK + 1, socket.SOCK_STREAM)',
      ].join('\n'),
    )
    expect(r.stdout).toContain('INET=OK')
    expect(r.stdout).toContain('INET_DGRAM=OK')
    expect(r.stdout).toContain('NETLINK=OK')
    // A host with IPv6 turned off answers EAFNOSUPPORT here by itself.
    expect(r.stdout).not.toContain('INET6=EPERM')
    // AF_VSOCK's neighbours, NFC and KCM: the kernel refuses a stream socket of
    // either with another errno, so EPERM would mean the rule matches too much.
    expect(r.stdout).not.toContain('BELOW=EPERM')
    expect(r.stdout).not.toContain('ABOVE=EPERM')
    expect(r.status).toBe(0)
  })
})

describe.if(isLinux)('AF_VSOCK in the full Linux sandbox', () => {
  beforeAll(async () => {
    expect(checkLinuxDependencies().errors).toEqual([])
    await SandboxManager.reset()
  })

  afterAll(async () => {
    await SandboxManager.reset()
  })

  it('is refused when the network is not restricted', async () => {
    const wrapped = await wrapCommandWithSandboxLinux({
      command: quote(['python3', '-c', VSOCK_ATTEMPTS]),
      needsNetworkRestriction: false,
      writeConfig: { allowOnly: ['/tmp'], denyWithinAllow: [] },
    })

    const r = await spawnAsync(wrapped, {
      shell: true,
      encoding: 'utf8',
      timeout: 15000,
    })
    expect(r.stdout).toContain(VSOCK_REFUSED)
    expect(r.status).toBe(0)
  })

  it.skipIf(!bwrapCanNamespaceNetwork())(
    'is refused in a network-restricted sandbox whose proxies still answer',
    async () => {
      // Nothing is allowed, so no request leaves the host: the HTTP proxy's 403
      // and the SOCKS proxy's method selection show the command reaches both.
      await SandboxManager.initialize({
        network: { allowedDomains: [], deniedDomains: [] },
        filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
      })

      const script = [
        VSOCK_ATTEMPTS,
        'import os, urllib.error, urllib.parse, urllib.request',
        'try:',
        '    urllib.request.urlopen("http://denied.example/", timeout=10)',
        'except urllib.error.HTTPError as e:',
        '    print("HTTP=%d" % e.code)',
        'socks = urllib.parse.urlparse(os.environ["FTP_PROXY"])',
        'conn = socket.create_connection((socks.hostname, socks.port), timeout=10)',
        'conn.sendall(bytes([5, 1, 2]))',
        'print("SOCKS=" + conn.recv(2).hex())',
      ].join('\n')
      const wrapped = await SandboxManager.wrapWithSandbox(
        quote(['python3', '-c', script]),
      )
      expect(wrapped).toContain('--unshare-net')

      const r = await spawnAsync(wrapped, {
        shell: true,
        encoding: 'utf8',
        timeout: 30000,
      })
      expect(r.stdout).toContain(VSOCK_REFUSED)
      expect(r.stdout).toContain('HTTP=403')
      // VER=5 and a method: the SOCKS proxy's own reply to the greeting.
      expect(r.stdout).toMatch(/^SOCKS=05[0-9a-f]{2}$/m)
      expect(r.status).toBe(0)
    },
    40000,
  )
})
