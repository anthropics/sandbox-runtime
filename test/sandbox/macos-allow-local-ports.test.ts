import { describe, it, expect } from 'bun:test'
import { spawnSync } from 'node:child_process'
import * as net from 'node:net'
import { wrapCommandWithSandboxMacOS } from '../../src/sandbox/macos-sandbox-utils.js'
import { isMacOS } from '../helpers/platform.js'
import { spawnAsync } from '../helpers/spawn.js'

/**
 * Tests for the opt-in allowLocalPorts option (macOS only).
 *
 * allowLocalBinding opens every loopback port; allowLocalPorts admits a
 * declared list of loopback TCP ports (bind, accept, connect) and nothing
 * else, so a host can hand a sandboxed process one port (a devtools port,
 * a dev server) without opening the rest.
 */

function wrapCommand(
  command: string,
  allowLocalPorts?: number[],
  allowLocalBinding?: boolean,
): string {
  return wrapCommandWithSandboxMacOS({
    command,
    needsNetworkRestriction: true,
    allowLocalPorts,
    allowLocalBinding,
    readConfig: undefined,
    writeConfig: undefined,
  })
}

function runInSandbox(
  pythonCode: string,
  allowLocalPorts: number[],
): ReturnType<typeof spawnSync> {
  const wrappedCommand = wrapCommand(
    `python3 -c "${pythonCode}"`,
    allowLocalPorts,
  )
  return spawnSync(wrappedCommand, {
    shell: true,
    encoding: 'utf8',
    timeout: 10000,
  })
}

/** Reserve a free loopback port on the host, then release it for the test. */
async function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer()
    srv.on('error', reject)
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address() as net.AddressInfo
      srv.close(() => resolve(port))
    })
  })
}

// AF_INET bind to a fixed loopback port
const bindIPv4 = (port: number) =>
  `import socket; s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(('127.0.0.1', ${port})); print('BOUND'); s.close()`

// AF_INET6 dual-stack bind (IPV6_V6ONLY=0, same as Java ServerSocketChannel.open())
const bindIPv6DualStack = (port: number) =>
  `import socket; s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0); s.bind(('::ffff:127.0.0.1', ${port})); print('BOUND'); s.close()`

// Bind a listener on a fixed loopback port and connect to it from a sibling
// AF_INET socket in the same sandboxed process (bind + inbound + outbound).
const loopbackIPC = (port: number) => `
import socket, threading
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('127.0.0.1', ${port})); srv.listen(1)
def serve():
    c, _ = srv.accept(); c.send(b'HI'); c.close()
threading.Thread(target=serve, daemon=True).start()
cli = socket.socket(); cli.settimeout(3)
cli.connect(('127.0.0.1', ${port}))
print('IPC', cli.recv(2).decode())
`

// Outbound connect to a listener the host owns (the devtools-port shape).
const connectLoopback = (port: number) =>
  `import socket; s = socket.socket(); s.settimeout(3); s.connect(('127.0.0.1', ${port})); print('CONNECTED', s.recv(2).decode())`

describe.if(isMacOS)(
  'macOS Seatbelt allowLocalPorts profile generation',
  () => {
    it('emits bind, inbound and outbound rules for each declared port', () => {
      const wrapped = wrapCommand('echo test', [9222, 3000])

      for (const port of [9222, 3000]) {
        expect(wrapped).toContain(
          `(allow network-bind (local ip "localhost:${port}"))`,
        )
        expect(wrapped).toContain(
          `(allow network-inbound (local ip "localhost:${port}"))`,
        )
        expect(wrapped).toContain(
          `(allow network-outbound (remote ip "localhost:${port}"))`,
        )
      }
    })

    it('emits no port rules when the list is empty or absent', () => {
      const unset = wrapCommand('echo test')
      const empty = wrapCommand('echo test', [])

      expect(empty).toBe(unset)
      expect(unset).not.toContain('localhost:')
    })

    it('does not open every port the way allowLocalBinding does', () => {
      const wrapped = wrapCommand('echo test', [9222])

      expect(wrapped).not.toContain('(local ip "*:*")')
      expect(wrapped).not.toContain('localhost:*')
    })

    it('composes with allowLocalBinding', () => {
      const wrapped = wrapCommand('echo test', [9222], true)

      expect(wrapped).toContain('(allow network-bind (local ip "*:*"))')
      expect(wrapped).toContain(
        '(allow network-outbound (remote ip "localhost:9222"))',
      )
    })

    it('forces the JVM onto the IPv4 stack so its loopback sockets match', () => {
      const wrapped = wrapCommand('true', [9222])

      expect(wrapped).toContain(
        'JAVA_TOOL_OPTIONS=-Djava.net.preferIPv4Stack=true',
      )
    })
  },
)

describe.if(isMacOS)('macOS Seatbelt allowLocalPorts', () => {
  it('allows bind, accept and connect on a declared port', async () => {
    const port = await freePort()
    const result = runInSandbox(loopbackIPC(port), [port])

    expect(result.status).toBe(0)
    expect(result.stdout).toContain('IPC HI')
  })

  it('allows connecting to a host-owned listener on a declared port', async () => {
    const port = await freePort()
    const server = net.createServer(socket => {
      socket.end('HI')
    })
    await new Promise<void>(resolve =>
      server.listen(port, '127.0.0.1', () => resolve()),
    )
    try {
      // spawnAsync: the child talks back to a server on this event loop.
      const result = await spawnAsync(
        wrapCommand(`python3 -c "${connectLoopback(port)}"`, [port]),
        { shell: true, encoding: 'utf8', timeout: 10000 },
      )

      expect(result.status).toBe(0)
      expect(result.stdout).toContain('CONNECTED HI')
    } finally {
      await new Promise<void>(resolve => server.close(() => resolve()))
    }
  })

  it('refuses bind on an undeclared port', async () => {
    const declared = await freePort()
    const undeclared = await freePort()
    const result = runInSandbox(bindIPv4(undeclared), [declared])

    expect(result.status).not.toBe(0)
    expect(result.stderr).toContain('Operation not permitted')
  })

  it('refuses connect to an undeclared port', async () => {
    const declared = await freePort()
    const undeclared = await freePort()
    const result = runInSandbox(connectLoopback(undeclared), [declared])

    expect(result.status).not.toBe(0)
    expect(result.stderr).toContain('Operation not permitted')
  })

  it('does not match a dual-stack bind (documented caveat)', async () => {
    // The per-port rule uses Seatbelt's "localhost" token on purpose (it
    // never admits a LAN-facing bind), so ::ffff:127.0.0.1 is not matched;
    // a dual-stack runtime must bind AF_INET.
    const port = await freePort()
    const result = runInSandbox(bindIPv6DualStack(port), [port])

    expect(result.status).not.toBe(0)
  })
})
