import { connect, createServer as createTcpServer } from 'node:net'
import { once } from 'node:events'
import { execFile, spawn } from 'node:child_process'
import { afterEach, describe, expect, it } from 'bun:test'
import { createSocksProxyServer } from '../../src/sandbox/socks-proxy.js'
import { SandboxManager } from '../../src/index.js'
import { isMacOS } from '../helpers/platform.js'

/**
 * A client that cannot authenticate (offers only the no-auth method, like
 * BSD `nc -X 5`) must never be tunnelled, and the refusal must be legible:
 * SSH destinations get an in-band SSH disconnect carrying the policy
 * reason; everything else gets the SOCKS "connection not allowed" reply.
 */
describe('SOCKS unauthenticated probe', () => {
  let tcp: ReturnType<typeof createTcpServer> | undefined
  let wrapper: ReturnType<typeof createSocksProxyServer> | undefined

  afterEach(async () => {
    await wrapper?.close()
    tcp?.close()
    tcp = undefined
    wrapper = undefined
  })

  async function startServer(opts: {
    deniedReason?: string
    onProbe?: (port: number, host: string) => void
    onFilter?: () => void
  }): Promise<number> {
    wrapper = createSocksProxyServer({
      filter: () => {
        opts.onFilter?.()
        return true
      },
      proxyAuthToken: 'tok-123',
      probeUnauthenticated: async (port, host) => {
        opts.onProbe?.(port, host)
        return opts.deniedReason !== undefined
          ? { deniedReason: opts.deniedReason }
          : {}
      },
    })
    const w = wrapper
    tcp = createTcpServer(socket => w.handleConnection(socket))
    tcp.listen(0, '127.0.0.1')
    await once(tcp, 'listening')
    return (tcp.address() as { port: number }).port
  }

  function socksConnect(host: string, port: number): Buffer {
    const hostBytes = Buffer.from(host, 'utf8')
    return Buffer.concat([
      Buffer.from([0x05, 0x01, 0x00, 0x03, hostBytes.length]),
      hostBytes,
      Buffer.from([(port >> 8) & 0xff, port & 0xff]),
    ])
  }

  async function drive(
    serverPort: number,
    target: { host: string; port: number },
  ): Promise<Buffer> {
    const sock = connect(serverPort, '127.0.0.1')
    await once(sock, 'connect')
    // Greeting: only the no-auth method — an unauthenticatable client.
    sock.write(Buffer.from([0x05, 0x01, 0x00]))
    const chunks: Buffer[] = []
    sock.on('data', d => chunks.push(d))
    // Method selection arrives, then send CONNECT.
    await new Promise(r => setTimeout(r, 50))
    sock.write(socksConnect(target.host, target.port))
    await once(sock, 'close')
    return Buffer.concat(chunks)
  }

  it('port-22 deny: SOCKS success then SSH banner + DISCONNECT with the reason; filter never consulted', async () => {
    const probed: string[] = []
    let filterCalls = 0
    const port = await startServer({
      deniedReason: 'ssh to this host is blocked; use an https remote',
      onProbe: (p, h) => probed.push(`${h}:${p}`),
      onFilter: () => filterCalls++,
    })
    const out = await drive(port, { host: 'denied.test', port: 22 })

    // 05 00 (method), then 10-byte success reply, then SSH bytes.
    expect(out.subarray(0, 2)).toEqual(Buffer.from([0x05, 0x00]))
    expect(out.subarray(2, 4)).toEqual(Buffer.from([0x05, 0x00]))
    const ssh = out.subarray(12)
    const text = ssh.toString('utf8')
    expect(text.startsWith('SSH-2.0-')).toBe(true)
    expect(text).toContain('ssh to this host is blocked; use an https remote')
    // Well-formed plaintext DISCONNECT after the identification line.
    const pkt = ssh.subarray(ssh.indexOf('\n') + 1)
    const packetLength = pkt.readUInt32BE(0)
    expect((4 + packetLength) % 8).toBe(0)
    expect(pkt[5]).toBe(0x01) // SSH_MSG_DISCONNECT
    expect(pkt.readUInt32BE(6)).toBe(1) // HOST_NOT_ALLOWED_TO_CONNECT
    expect(probed).toEqual(['denied.test:22'])
    // The authenticated-path filter (which may prompt) is never reached.
    expect(filterCalls).toBe(0)
  })

  it('port-22 non-denied: SSH disconnect says the proxy requires authentication', async () => {
    const port = await startServer({})
    const out = await drive(port, { host: 'allowed.test', port: 22 })
    const text = out.toString('latin1')
    expect(text).toContain('SSH-2.0-')
    expect(text).toContain('requires authentication')
  })

  it('non-22 target: plain SOCKS refusal, no SSH bytes, no tunnel', async () => {
    const port = await startServer({ deniedReason: 'nope' })
    const out = await drive(port, { host: 'denied.test', port: 443 })
    expect(out.subarray(0, 2)).toEqual(Buffer.from([0x05, 0x00]))
    // Reply status 0x02 = connection not allowed by ruleset.
    expect(out[3]).toBe(0x02)
    expect(out.toString('latin1')).not.toContain('SSH-2.0-')
  })

  // The ProxyCommand helper used by the ssh tests below must outlive the
  // proxy's close: the proxy sends banner + DISCONNECT and closes at once,
  // while ssh only reads the DISCONNECT after it has written its own
  // KEXINIT into the helper's stdin. A helper that exits on socket close
  // races that write; when ssh loses (a busy CI runner), it dies with
  // "Broken pipe" and never prints the reason. Reproduced here without
  // ssh: play ssh's part with a deliberately late write, and require the
  // helper to still be running when it lands (the parent-side write itself
  // reports nothing useful once the child is gone), then to exit as soon as
  // its stdin is closed — not on a fallback timer.
  it('ProxyCommand helper stays alive until its stdin closes, even after the proxy hangs up', async () => {
    const port = await startServer({ deniedReason: 'late-write reason' })
    const child = spawn(
      process.execPath,
      [
        `${import.meta.dir}/../helpers/socks-noauth-pipe.ts`,
        String(port),
        'denied.test',
        '22',
      ],
      { stdio: ['pipe', 'pipe', 'inherit'] },
    )
    let exitCode: number | null | undefined
    const exited = once(child, 'exit').then(([code]) => {
      exitCode = code as number | null
    })
    child.stdin.on('error', () => {})
    const stdout: Buffer[] = []
    const firstData = once(child.stdout, 'data')
    child.stdout.on('data', d => stdout.push(d))
    await firstData
    // By now the proxy has closed the socket; give the helper ample time to
    // (wrongly) exit on that.
    await new Promise(r => setTimeout(r, 200))
    expect(exitCode).toBeUndefined()
    child.stdin.write('SSH-2.0-client\r\n')
    const stdinClosedAt = Date.now()
    child.stdin.end()
    await exited
    expect(exitCode).toBe(0)
    expect(Date.now() - stdinClosedAt).toBeLessThan(1000)
    expect(Buffer.concat(stdout).toString('latin1')).toContain(
      'late-write reason',
    )
  })

  it('a client offering username/password still gets the authenticated flow', async () => {
    const port = await startServer({})
    const sock = connect(port, '127.0.0.1')
    await once(sock, 'connect')
    sock.write(Buffer.from([0x05, 0x02, 0x00, 0x02]))
    const [reply] = (await once(sock, 'data')) as [Buffer]
    // Library selects username/password (0x02), not the probe's 0x00.
    expect(reply.subarray(0, 2)).toEqual(Buffer.from([0x05, 0x02]))
    sock.destroy()
  })
})

/**
 * The end-to-end claim: real `ssh` through a no-auth SOCKS ProxyCommand
 * against a denied host prints the configured reason instead of an opaque
 * tunnel failure. The ProxyCommand is our own minimal no-auth SOCKS pipe
 * (test/helpers/socks-noauth-pipe.ts) rather than `nc -X 5`: it exercises
 * the identical wire behavior while being independent of which netcat
 * flavor the host ships (GNU/nmap variants lack -X and fail instantly).
 * macOS-gated for a real OpenSSH; the wire path itself is covered
 * cross-platform by the raw-socket tests above.
 */
describe.if(isMacOS)('ssh-over-nc against the real sandbox proxy', () => {
  afterEach(async () => {
    await SandboxManager.reset()
  })

  function runSsh(port: number, host: string): Promise<string> {
    return new Promise(resolve => {
      execFile(
        'ssh',
        [
          '-o',
          `ProxyCommand=${process.execPath} ${import.meta.dir}/../helpers/socks-noauth-pipe.ts ${port} %h %p`,
          '-o',
          'StrictHostKeyChecking=no',
          '-o',
          'ConnectTimeout=10',
          `git@${host}`,
        ],
        { timeout: 15000 },
        (_err, _stdout, stderr) => resolve(stderr),
      )
    })
  }

  it('denied host: ssh stderr carries the configured deny reason', async () => {
    await SandboxManager.initialize({
      network: {
        allowedDomains: [],
        deniedDomains: ['ssh-blocked.example:22'],
        deniedDomainReasons: {
          'ssh-blocked.example:22':
            'ssh to this destination is blocked by sandbox policy; switch the remote to https://example.invalid/ORG/REPO.git',
        },
      },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    })
    const stderr = await runSsh(
      SandboxManager.getProxyPort()!,
      'ssh-blocked.example',
    )
    expect(stderr).toContain('ssh to this destination is blocked')
    expect(stderr).not.toContain('authentication method negotiation failed')
    // Recorded (unattributed) so the violation surfaces to observers too.
    const lines = SandboxManager.getSandboxViolationStore()
      .getViolations()
      .map(v => v.line)
    expect(lines.some(l => l.includes('ssh-blocked.example:22'))).toBe(true)
  })

  it('non-denied host: ssh stderr says the proxy requires authentication', async () => {
    await SandboxManager.initialize({
      network: { allowedDomains: ['anything.example'], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    })
    const stderr = await runSsh(
      SandboxManager.getProxyPort()!,
      'anything.example',
    )
    expect(stderr).toContain('requires authentication')
  })
})
