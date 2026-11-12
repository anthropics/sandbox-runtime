import { afterAll, beforeAll, describe, expect, it } from 'bun:test'
import { spawn, spawnSync } from 'node:child_process'
import { existsSync, readdirSync } from 'node:fs'
import { createServer, type AddressInfo, type Server } from 'node:net'
import { tmpdir } from 'node:os'
import { SandboxRuntimeConfigSchema } from '../../src/sandbox/sandbox-config.js'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import { isLinux } from '../helpers/platform.js'
import { bwrapCanNamespaceNetwork } from '../helpers/bwrap-namespace.js'

const has = (program: string): boolean =>
  spawnSync('which', [program]).status === 0

const base = {
  network: { allowedDomains: [], deniedDomains: [] },
  filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
}

describe('network.reachHostPorts config', () => {
  it('takes a list of ports', () => {
    const result = SandboxRuntimeConfigSchema.safeParse({
      ...base,
      network: { ...base.network, reachHostPorts: [5432, 6379] },
    })
    expect(result.success).toBe(true)
  })

  for (const port of [3128, 1080]) {
    it(`refuses ${port}, which a proxy relay takes inside the sandbox`, () => {
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        network: { ...base.network, reachHostPorts: [port] },
      })
      expect(result.success).toBe(false)
    })
  }

  for (const port of [0, 65536, 1.5]) {
    it(`refuses ${port}, which is not a TCP port`, () => {
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        network: { ...base.network, reachHostPorts: [port] },
      })
      expect(result.success).toBe(false)
    })
  }
})

/** A server on the host loopback that greets each client with its name. */
async function greeter(
  name: string,
): Promise<{ server: Server; port: number }> {
  const server = createServer(socket => socket.end(`${name}\n`))
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
  return { server, port: (server.address() as AddressInfo).port }
}

/** Runs a wrapped command without blocking this process, whose servers
 *  must keep answering while it runs. */
function run(wrapped: string): Promise<{ stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(wrapped, { shell: true })
    let stdout = ''
    let stderr = ''
    child.stdout.on('data', d => (stdout += d))
    child.stderr.on('data', d => (stderr += d))
    const timer = setTimeout(() => child.kill('SIGKILL'), 30000)
    child.on('error', reject)
    child.on('close', () => {
      clearTimeout(timer)
      resolve({ stdout, stderr })
    })
  })
}

/** Connects to each port at `host` and prints the greeting or "refused".
 *  bash's /dev/tcp dials directly, ignoring the proxy, as a database
 *  client does. */
const dial = (host: string, ports: number[]): string =>
  ports
    .map(
      p =>
        `( exec 3<>/dev/tcp/${host}/${p} && read -r g <&3 && echo "${p} $g" ) 2>/dev/null || echo "${p} refused"`,
    )
    .join('; ')

const hostSockets = (): string[] =>
  readdirSync(tmpdir()).filter(f => f.startsWith('claude-host-'))

describe.if(isLinux && bwrapCanNamespaceNetwork() && has('socat'))(
  'network.reachHostPorts on Linux',
  () => {
    let listed: { server: Server; port: number }
    let other: { server: Server; port: number }

    beforeAll(async () => {
      listed = await greeter('listed')
      other = await greeter('other')
      await SandboxManager.reset()
      await SandboxManager.initialize({
        ...base,
        network: { ...base.network, reachHostPorts: [listed.port] },
      })
    })

    afterAll(async () => {
      await SandboxManager.reset()
      listed.server.close()
      other.server.close()
    })

    it('reaches a listed host port directly, and no other', async () => {
      const wrapped = await SandboxManager.wrapWithSandbox(
        dial('127.0.0.1', [listed.port, other.port]),
      )
      const { stdout, stderr } = await run(wrapped)
      expect(stderr).not.toContain('bwrap:')
      expect(stdout.trim().split('\n')).toEqual([
        `${listed.port} listed`,
        `${other.port} refused`,
      ])
    })

    it('reaches it on ::1 too', async () => {
      const wrapped = await SandboxManager.wrapWithSandbox(
        dial('::1', [listed.port]),
      )
      const { stdout } = await run(wrapped)
      expect(stdout.trim()).toBe(`${listed.port} listed`)
    })

    it('refuses the port without the entry', async () => {
      const wrapped = await SandboxManager.wrapWithSandbox(
        dial('127.0.0.1', [listed.port]),
        undefined,
        { network: { ...base.network, reachHostPorts: [] } },
      )
      const { stdout } = await run(wrapped)
      expect(stdout.trim()).toBe(`${listed.port} refused`)
    })

    it('takes the port from a per-command config', async () => {
      const wrapped = await SandboxManager.wrapWithSandbox(
        dial('127.0.0.1', [listed.port, other.port]),
        undefined,
        { network: { ...base.network, reachHostPorts: [other.port] } },
      )
      const { stdout } = await run(wrapped)
      expect(stdout.trim().split('\n')).toEqual([
        `${listed.port} refused`,
        `${other.port} other`,
      ])
    })

    it('serves many connections through one bridge', async () => {
      const wrapped = await SandboxManager.wrapWithSandbox(
        dial('127.0.0.1', Array(20).fill(listed.port)),
      )
      const { stdout } = await run(wrapped)
      const lines = stdout.trim().split('\n')
      expect(lines).toHaveLength(20)
      expect(new Set(lines)).toEqual(new Set([`${listed.port} listed`]))
    })

    it('removes the host bridges on reset', async () => {
      await SandboxManager.wrapWithSandbox('true')
      const before = hostSockets()
      expect(before.length).toBeGreaterThan(0)
      await SandboxManager.reset()
      for (const f of before) expect(existsSync(`${tmpdir()}/${f}`)).toBe(false)
      await SandboxManager.initialize({
        ...base,
        network: { ...base.network, reachHostPorts: [listed.port] },
      })
    })
  },
)
