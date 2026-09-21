import { describe, it, expect, afterEach, beforeEach, spyOn } from 'bun:test'
import {
  SandboxManager,
  SandboxRuntimeConfigSchema,
  type SandboxAskCallback,
  type SandboxRuntimeConfig,
} from '../../src/index.js'
import { connect, createServer, type AddressInfo, type Server } from 'net'
import { randomBytes } from 'node:crypto'
import { getPlatform } from '../../src/utils/platform.js'
import {
  encodeSandboxedCommand,
  proxyUsernameFor,
} from '../../src/sandbox/sandbox-utils.js'
import { spawnAsync } from '../helpers/spawn.js'
import { isLinux, isMacOS } from '../helpers/platform.js'

/**
 * Helper to make a CONNECT request through the proxy using raw TCP
 */
function proxyRequest(
  proxyPort: number,
  targetHost: string,
  withAuth = true,
): Promise<{ allowed: boolean; statusCode?: number; response?: string }> {
  return new Promise(resolve => {
    const token = withAuth ? SandboxManager.getProxyAuthToken() : undefined
    const auth = token
      ? `Proxy-Authorization: Basic ${Buffer.from(`srt:${token}`).toString('base64')}\r\n`
      : ''
    const socket = connect(proxyPort, '127.0.0.1', () => {
      socket.write(
        `CONNECT ${targetHost}:443 HTTP/1.1\r\nHost: ${targetHost}:443\r\n${auth}\r\n`,
      )
    })

    let data = ''
    socket.on('data', chunk => {
      data += chunk.toString()
      // Check if we have a complete HTTP response line
      if (data.includes('\r\n')) {
        socket.destroy()
        const statusMatch = data.match(/HTTP\/1\.\d (\d+)/)
        const statusCode = statusMatch ? parseInt(statusMatch[1]) : 0
        resolve({
          allowed: statusCode === 200,
          statusCode,
          response: data,
        })
      }
    })

    socket.on('error', err => {
      resolve({ allowed: false, response: err.message })
    })

    socket.setTimeout(2000, () => {
      socket.destroy()
      resolve({ allowed: false, response: 'timeout' })
    })
  })
}

describe('proxy auth + network deny semantics', () => {
  beforeEach(async () => {
    await SandboxManager.reset()
  })
  afterEach(async () => {
    await SandboxManager.reset()
  })

  it('407s a CONNECT without the per-session auth token', async () => {
    await SandboxManager.initialize({
      network: { allowedDomains: ['example.com'], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    })
    const port = SandboxManager.getProxyPort()!
    const noAuth = await proxyRequest(port, 'example.com', false)
    expect(noAuth.statusCode).toBe(407)
    const withAuth = await proxyRequest(port, 'example.com', true)
    expect(withAuth.allowed).toBe(true)
  })

  it('deniedDomains "*" denies every host', async () => {
    await SandboxManager.initialize({
      network: { allowedDomains: ['example.com'], deniedDomains: ['*'] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    })
    const port = SandboxManager.getProxyPort()!
    expect((await proxyRequest(port, 'example.com')).statusCode).toBe(403)
    expect((await proxyRequest(port, 'other.net')).statusCode).toBe(403)
  })

  it("reports a deniedDomains entry's deniedDomainReasons text in the violation line", async () => {
    await SandboxManager.initialize({
      network: {
        allowedDomains: ['example.com'],
        deniedDomains: ['github.com', 'evil.net'],
        deniedDomainReasons: {
          'github.com':
            'SSH pushes to GitHub are blocked; use an https:// remote',
        },
      },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    })
    const port = SandboxManager.getProxyPort()!
    const store = SandboxManager.getSandboxViolationStore()
    store.clear()

    expect((await proxyRequest(port, 'github.com')).statusCode).toBe(403)
    // No reason for this entry → the generic one.
    expect((await proxyRequest(port, 'evil.net')).statusCode).toBe(403)

    const lines = store.getViolations().map(v => v.line)
    expect(lines).toContain(
      'deny network-outbound github.com:443 (SSH pushes to GitHub are blocked; use an https:// remote)',
    )
    expect(lines).toContain(
      'deny network-outbound evil.net:443 (host is on the deny list)',
    )
  })

  it('honors ignoreViolations for proxy-recorded network denials', async () => {
    await SandboxManager.initialize({
      network: {
        allowedDomains: [],
        deniedDomains: ['ignored.test', 'kept.test'],
      },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
      ignoreViolations: { '*': ['ignored.test'] },
    })
    const port = SandboxManager.getProxyPort()!
    const store = SandboxManager.getSandboxViolationStore()
    store.clear()

    expect((await proxyRequest(port, 'ignored.test')).statusCode).toBe(403)
    expect((await proxyRequest(port, 'kept.test')).statusCode).toBe(403)

    // The deny still happens (403), only the recorded violation is dropped.
    const lines = store.getViolations().map(v => v.line)
    expect(lines.some(l => l.includes('ignored.test'))).toBe(false)
    expect(lines).toContain(
      'deny network-outbound kept.test:443 (host is on the deny list)',
    )
  })

  it('redacts the query string from filterRequest deny lines', async () => {
    await SandboxManager.initialize({
      network: {
        allowedDomains: ['blocked.test'],
        deniedDomains: [],
        filterRequest: async () => ({
          action: 'deny',
          reason: 'policy says no',
        }),
      },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    })
    const port = SandboxManager.getProxyPort()!
    const store = SandboxManager.getSandboxViolationStore()
    store.clear()

    // Plain-HTTP GET through the proxy so filterRequest sees (and denies) it
    // without any upstream connection.
    await new Promise<void>(resolve => {
      const token = SandboxManager.getProxyAuthToken()
      const auth = Buffer.from(`srt:${token}`).toString('base64')
      const socket = connect(port, '127.0.0.1', () => {
        socket.write(
          `GET http://alice:PASSW0RD@blocked.test/x?access_token=SECRET123 HTTP/1.1\r\n` +
            `Host: blocked.test\r\n` +
            `Proxy-Authorization: Basic ${auth}\r\n` +
            `Connection: close\r\n\r\n`,
        )
      })
      socket.on('data', () => socket.destroy())
      socket.on('close', () => resolve())
      socket.on('error', () => resolve())
      socket.setTimeout(2000, () => {
        socket.destroy()
        resolve()
      })
    })

    const lines = store.getViolations().map(v => v.line)
    expect(lines).toContain(
      'deny http-request GET http://blocked.test/x?… (policy says no)',
    )
    const joined = lines.join('\n')
    expect(joined).not.toContain('SECRET123')
    // userinfo (name:pass@) is dropped along with the query.
    expect(joined).not.toContain('PASSW0RD')
    expect(joined).not.toContain('alice')
  })

  // The embedder bug this option exists for: Claude Code wraps an assembled
  // `source <snapshot> ... && eval '<cmd>'` string but looks violations up by
  // the raw `<cmd>`, so the stored key (first 100 chars of boilerplate) never
  // equalled the lookup key and no <sandbox_violations> block was produced.
  it.if(isMacOS || isLinux)(
    'commandId/commandText: attributed under the id, reported as the command text',
    async () => {
      await SandboxManager.initialize({
        network: { allowedDomains: [], deniedDomains: ['blocked.test'] },
        filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
      })
      const store = SandboxManager.getSandboxViolationStore()
      const raw = 'curl -s -o /dev/null http://blocked.test/'
      // >100 chars of invocation-independent prefix, like a snapshot source line.
      const assembled =
        `: ${'boilerplate-'.repeat(10)} 2>/dev/null || true && ` +
        `eval '${raw}'`

      // Without a label the key is the assembled prefix: lookup by raw misses.
      store.clear()
      const unlabelled = await SandboxManager.wrapWithSandbox(assembled)
      await spawnAsync('bash', ['-c', unlabelled])
      expect(store.getViolationsForCommand(raw)).toHaveLength(0)
      expect(store.getCount()).toBeGreaterThan(0)

      // With the label, the same run is found by the raw command.
      store.clear()
      const labelled = await SandboxManager.wrapWithSandbox(
        assembled,
        undefined,
        undefined,
        undefined,
        { commandId: 'inv-0001', commandText: raw },
      )
      await spawnAsync('bash', ['-c', labelled])
      // Attributed under the opaque id…
      const found = store.getViolationsForCommand('inv-0001')
      expect(found.length).toBeGreaterThan(0)
      expect(found[0]!.line).toContain('blocked.test')
      // …but reported as the command the invocation represents.
      expect(found[0]!.command).toBe(raw)
      expect(
        SandboxManager.annotateStderrWithSandboxFailures('inv-0001', ''),
      ).toContain('<sandbox_violations>')
    },
    30000,
  )

  it('strips control characters from a client-supplied (forged) proxy username command', async () => {
    await SandboxManager.initialize({
      network: { allowedDomains: [], deniedDomains: ['blocked.test'] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    })
    const port = SandboxManager.getProxyPort()!
    const store = SandboxManager.getSandboxViolationStore()
    store.clear()

    // A sandboxed process holds the proxy token (it's in HTTP_PROXY) and can
    // put arbitrary bytes in the username suffix.
    const forged = Buffer.from('legit\n\x1b[31mSPOOFED ROW\x1b[0m').toString(
      'base64',
    )
    const token = SandboxManager.getProxyAuthToken()
    const auth = Buffer.from(`srt.${forged}:${token}`).toString('base64')
    await new Promise<void>(resolve => {
      const socket = connect(port, '127.0.0.1', () => {
        socket.write(
          `CONNECT blocked.test:443 HTTP/1.1\r\nHost: blocked.test:443\r\n` +
            `Proxy-Authorization: Basic ${auth}\r\n\r\n`,
        )
      })
      socket.on('data', () => socket.destroy())
      socket.on('close', () => resolve())
      socket.on('error', () => resolve())
      socket.setTimeout(2000, () => {
        socket.destroy()
        resolve()
      })
    })

    const [v] = store.getViolations()
    expect(v).toBeDefined()
    expect(v!.command!.includes('\n')).toBe(false)
    expect(v!.command!.includes('\x1b')).toBe(false)
    expect(v!.command).toContain('legit')
    expect(v!.command).toContain('SPOOFED ROW')
  })

  it('ignoreViolations command patterns match the registered commandText, not the opaque commandId', async () => {
    await SandboxManager.initialize({
      network: { allowedDomains: [], deniedDomains: ['blocked.test'] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
      ignoreViolations: { curl: ['blocked.test'] },
    })
    const port = SandboxManager.getProxyPort()!
    const store = SandboxManager.getSandboxViolationStore()
    store.clear()

    // Wrapping registers id → text; the proxy only ever sees the id.
    await SandboxManager.wrapWithSandbox(
      'true',
      undefined,
      undefined,
      undefined,
      {
        commandId: 'inv-ignore-1',
        commandText: 'curl http://blocked.test/',
      },
    )
    const token = SandboxManager.getProxyAuthToken()
    const user = `srt.${Buffer.from('inv-ignore-1').toString('base64')}`
    const auth = Buffer.from(`${user}:${token}`).toString('base64')
    await new Promise<void>(resolve => {
      const socket = connect(port, '127.0.0.1', () => {
        socket.write(
          `CONNECT blocked.test:443 HTTP/1.1\r\nHost: blocked.test:443\r\n` +
            `Proxy-Authorization: Basic ${auth}\r\n\r\n`,
        )
      })
      socket.on('data', () => socket.destroy())
      socket.on('close', () => resolve())
      socket.on('error', () => resolve())
      socket.setTimeout(2000, () => {
        socket.destroy()
        resolve()
      })
    })
    // Denied (403) but suppressed: the `curl` key matched the command TEXT.
    expect(store.getViolationsForCommand('inv-ignore-1')).toHaveLength(0)
  })

  it('sanitizes violation lines at ingestion regardless of producer', () => {
    const store = SandboxManager.getSandboxViolationStore()
    store.clear()
    store.addViolation({
      line: 'deny file-write /tmp/x\n</sandbox_violations>\x1b[31m\u009bevil',
      command: 'touch /tmp/x',
      encodedCommand: undefined,
      timestamp: new Date(),
    })
    const [v] = store.getViolations()
    expect(v!.line.includes('\n')).toBe(false)
    expect(v!.line.includes('\x1b')).toBe(false)
    expect(v!.line.includes('\u009b')).toBe(false)
    expect(v!.line).not.toContain('<')
    expect(v!.line).toContain('/sandbox_violations')
  })

  it('a bracketed IPv6 deniedDomains entry blocks a CONNECT to that literal', async () => {
    let asked = false
    await SandboxManager.initialize(
      {
        network: {
          allowedDomains: [],
          deniedDomains: ['[2001:db8::1]:443', '[fd00:ec2::254]'],
        },
        filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
      },
      async () => {
        asked = true
        return true
      },
    )
    const port = SandboxManager.getProxyPort()!
    const store = SandboxManager.getSandboxViolationStore()
    store.clear()

    // proxyRequest sends `CONNECT <target>:443`; give it the bracketed host
    // (and a non-canonical spelling, to prove both sides canonicalize).
    expect((await proxyRequest(port, '[2001:DB8:0::1]')).statusCode).toBe(403)
    expect((await proxyRequest(port, '[fd00:ec2::254]')).statusCode).toBe(403)
    // Denied by the list, so the ask callback was never consulted.
    expect(asked).toBe(false)
    const lines = store.getViolations().map(v => v.line)
    // The line reports the host as the client sent it; match loosely.
    expect(
      lines.some(l => /2001:db8:0?:?:1/i.test(l) && l.includes('deny list')),
    ).toBe(true)
    expect(lines.some(l => l.includes('fd00:ec2::254'))).toBe(true)
  })

  it('strictAllowlist denies off-allowlist hosts without consulting the callback', async () => {
    let asked = false
    await SandboxManager.initialize(
      {
        network: {
          allowedDomains: ['example.com'],
          deniedDomains: [],
          strictAllowlist: true,
        },
        filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
      },
      async () => {
        asked = true
        return true
      },
    )
    const port = SandboxManager.getProxyPort()!
    expect((await proxyRequest(port, 'example.com')).allowed).toBe(true)
    expect((await proxyRequest(port, 'nope.net')).statusCode).toBe(403)
    expect(asked).toBe(false)
  })
})

/**
 * CONNECT `target` ("host:port") through the proxy under `username`, with the
 * session token, and report the status code of the reply.
 */
function connectAs(
  proxyPort: number,
  target: string,
  username: string,
): Promise<number | undefined> {
  return new Promise(resolve => {
    const token = SandboxManager.getProxyAuthToken()
    const auth = Buffer.from(`${username}:${token}`).toString('base64')
    const socket = connect(proxyPort, '127.0.0.1', () => {
      socket.write(
        `CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n` +
          `Proxy-Authorization: Basic ${auth}\r\n\r\n`,
      )
    })
    let data = ''
    socket.on('data', chunk => {
      data += chunk.toString()
      if (data.includes('\r\n')) {
        socket.destroy()
        const status = data.match(/HTTP\/1\.\d (\d+)/)
        resolve(status ? parseInt(status[1]) : undefined)
      }
    })
    socket.on('error', () => resolve(undefined))
    socket.setTimeout(2000, () => {
      socket.destroy()
      resolve(undefined)
    })
  })
}

/**
 * A listener on loopback for the proxy to dial, so an allow is observed as a
 * 200 without leaving the machine. An IP-literal destination is dialled as
 * it is, with no name to resolve and nothing for the resolved-address check
 * to refuse.
 */
function listenOnLoopback(): Promise<{ server: Server; target: string }> {
  return new Promise(resolve => {
    const server = createServer(socket => socket.on('error', () => {}))
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address() as AddressInfo
      resolve({ server, target: `127.0.0.1:${port}` })
    })
  })
}

/** An id of the kind the API asks for: 16 random bytes, 22 characters. */
const randomCommandId = (): string => randomBytes(16).toString('base64url')

/** The proxy username a wrap given this commandId puts in the proxy URLs. */
const usernameFor = (commandId: string): string =>
  proxyUsernameFor(encodeSandboxedCommand(commandId))

const NO_FILESYSTEM_RULES = { denyRead: [], allowWrite: [], denyWrite: [] }

const violationLines = (): string[] =>
  SandboxManager.getSandboxViolationStore()
    .getViolations()
    .map(v => v.line)

describe('per-command network allow lists', () => {
  let loopback: { server: Server; target: string }
  let asked: string[]
  const denyAndRecord: SandboxAskCallback = async ({ host, port }) => {
    asked.push(`${host}:${port}`)
    return false
  }

  async function start(
    network: Partial<SandboxRuntimeConfig['network']>,
    callback?: SandboxAskCallback,
  ): Promise<number> {
    await SandboxManager.initialize(
      {
        network: { allowedDomains: [], deniedDomains: [], ...network },
        filesystem: NO_FILESYSTEM_RULES,
      },
      callback,
    )
    SandboxManager.getSandboxViolationStore().clear()
    return SandboxManager.getProxyPort()!
  }

  beforeEach(async () => {
    await SandboxManager.reset()
    loopback = await listenOnLoopback()
    asked = []
  })

  afterEach(async () => {
    await SandboxManager.reset()
    loopback.server.close()
  })

  it('lifts the default deny for the id the connection presents, and for no other', async () => {
    const port = await start({})
    const registered = randomCommandId()
    SandboxManager.registerCommandNetworkLists(registered, {
      allowedDomains: [loopback.target],
    })

    expect(
      await connectAs(port, loopback.target, usernameFor(registered)),
    ).toBe(200)
    // An id nothing was registered under, and no id at all, see the
    // configured lists alone.
    expect(
      await connectAs(port, loopback.target, usernameFor(randomCommandId())),
    ).toBe(403)
    expect(await connectAs(port, loopback.target, 'srt')).toBe(403)
    expect(violationLines()).toEqual([
      `deny network-outbound ${loopback.target} (host is not on the allow list)`,
      `deny network-outbound ${loopback.target} (host is not on the allow list)`,
    ])
  })

  it('is consulted before the ask callback, which still decides every host it does not list', async () => {
    const port = await start({}, denyAndRecord)
    const registered = randomCommandId()
    SandboxManager.registerCommandNetworkLists(registered, {
      allowedDomains: [loopback.target],
    })

    expect(
      await connectAs(port, loopback.target, usernameFor(registered)),
    ).toBe(200)
    expect(asked).toEqual([])

    expect(
      await connectAs(port, 'unlisted.test:443', usernameFor(registered)),
    ).toBe(403)
    expect(await connectAs(port, loopback.target, 'srt')).toBe(403)
    expect(asked).toEqual(['unlisted.test:443', loopback.target])
  })

  it('uses the grammar of network.allowedDomains: a port suffix narrows an entry, a wildcard widens it', async () => {
    const port = await start({}, denyAndRecord)
    const registered = randomCommandId()
    const [host, listeningPort] = loopback.target.split(':')
    // Any port but the listener's, and still a valid one: the listener can be
    // handed 65535, the top of the range.
    const anotherPort =
      Number(listeningPort) === 65535 ? 65534 : Number(listeningPort) + 1
    SandboxManager.registerCommandNetworkLists(registered, {
      allowedDomains: [`${host}:${anotherPort}`, '*.wild.test'],
    })

    // Listed for another port only, so the callback is asked and denies.
    expect(
      await connectAs(port, loopback.target, usernameFor(registered)),
    ).toBe(403)
    expect(asked).toEqual([loopback.target])
    // The wildcard matches a subdomain (the filter allows; the dial then
    // fails, which is not a 403) and, as in the configuration, not the apex.
    expect(
      await connectAs(port, 'a.wild.test:443', usernameFor(registered)),
    ).not.toBe(403)
    expect(
      await connectAs(port, 'wild.test:443', usernameFor(registered)),
    ).toBe(403)
    expect(asked).toEqual([loopback.target, 'wild.test:443'])
  })

  it('never overrides a configured deniedDomains entry', async () => {
    const port = await start({ deniedDomains: ['127.0.0.1'] }, denyAndRecord)
    const registered = randomCommandId()
    SandboxManager.registerCommandNetworkLists(registered, {
      allowedDomains: [loopback.target],
    })

    expect(
      await connectAs(port, loopback.target, usernameFor(registered)),
    ).toBe(403)
    expect(violationLines()).toEqual([
      `deny network-outbound ${loopback.target} (host is on the deny list)`,
    ])
    expect(asked).toEqual([])
  })

  it('is ignored entirely under strictAllowlist', async () => {
    const port = await start({ strictAllowlist: true }, denyAndRecord)
    const registered = randomCommandId()
    SandboxManager.registerCommandNetworkLists(registered, {
      allowedDomains: [loopback.target],
    })

    expect(
      await connectAs(port, loopback.target, usernameFor(registered)),
    ).toBe(403)
    expect(violationLines()).toEqual([
      `deny network-outbound ${loopback.target} (host is not on the allow list)`,
    ])
    expect(asked).toEqual([])
  })

  it('never enters network.*, so the configured allow list does not grow', async () => {
    await start({ allowedDomains: ['example.com'] })
    SandboxManager.registerCommandNetworkLists(randomCommandId(), {
      allowedDomains: [loopback.target, 'percommand.test'],
    })

    expect(SandboxManager.getConfig()?.network.allowedDomains).toEqual([
      'example.com',
    ])
    expect(SandboxManager.getNetworkRestrictionConfig().allowedHosts).toEqual([
      'example.com',
    ])
  })

  it('stops applying once unregistered; unregistering an id that has no list changes nothing', async () => {
    const port = await start({})
    const registered = randomCommandId()
    SandboxManager.registerCommandNetworkLists(registered, {
      allowedDomains: [loopback.target],
    })

    SandboxManager.unregisterCommandNetworkLists(randomCommandId())
    // Registering refuses what is not a string; unregistering has nothing to
    // refuse, since no list can be registered under it, and lets it pass so
    // that a cleanup path never throws.
    for (const notAString of [null, undefined, 42]) {
      expect(() =>
        SandboxManager.unregisterCommandNetworkLists(
          notAString as unknown as string,
        ),
      ).not.toThrow()
    }
    expect(
      await connectAs(port, loopback.target, usernameFor(registered)),
    ).toBe(200)

    SandboxManager.unregisterCommandNetworkLists(registered)
    expect(
      await connectAs(port, loopback.target, usernameFor(registered)),
    ).toBe(403)
    // Twice is as good as once.
    SandboxManager.unregisterCommandNetworkLists(registered)
  })

  it('replaces the list when an id is registered again', async () => {
    const port = await start({})
    const registered = randomCommandId()
    SandboxManager.registerCommandNetworkLists(registered, {
      allowedDomains: [loopback.target],
    })
    SandboxManager.registerCommandNetworkLists(registered, {
      allowedDomains: ['elsewhere.test'],
    })

    expect(
      await connectAs(port, loopback.target, usernameFor(registered)),
    ).toBe(403)
  })

  it('keeps the list it validated when the caller changes its array afterwards', async () => {
    const port = await start({})
    const registered = randomCommandId()
    const entries = ['elsewhere.test']
    SandboxManager.registerCommandNetworkLists(registered, {
      allowedDomains: entries,
    })
    entries.push(loopback.target)

    expect(
      await connectAs(port, loopback.target, usernameFor(registered)),
    ).toBe(403)
  })

  it('forgets every list on reset', async () => {
    await start({})
    const registered = randomCommandId()
    SandboxManager.registerCommandNetworkLists(registered, {
      allowedDomains: [loopback.target],
    })

    await SandboxManager.reset()
    const port = await start({})
    expect(
      await connectAs(port, loopback.target, usernameFor(registered)),
    ).toBe(403)
  })

  it('refuses an id shorter than 22 characters, and says what an id has to be', () => {
    const lists = { allowedDomains: ['example.com'] }
    for (const tooShort of ['', '1', 'inv-0001', 'a'.repeat(21)]) {
      expect(() =>
        SandboxManager.registerCommandNetworkLists(tooShort, lists),
      ).toThrow(/at least 22 characters/)
    }
    expect(() =>
      SandboxManager.registerCommandNetworkLists('a'.repeat(21), lists),
    ).toThrow(/only thing that binds a proxy connection to this allow list/)
    expect(() =>
      SandboxManager.registerCommandNetworkLists('a'.repeat(21), lists),
    ).toThrow(/random .* never derived from the command text/)
    // A JavaScript caller's null or number is no id either.
    for (const notAString of [null, undefined, 1e21]) {
      expect(() =>
        SandboxManager.registerCommandNetworkLists(
          notAString as unknown as string,
          lists,
        ),
      ).toThrow(/at least 22 characters/)
    }
    // The floor itself is accepted, and an empty or absent list is a list.
    SandboxManager.registerCommandNetworkLists('a'.repeat(22), lists)
    SandboxManager.registerCommandNetworkLists(randomCommandId(), {})
    SandboxManager.registerCommandNetworkLists(randomCommandId(), {
      allowedDomains: [],
    })
    // So is no second argument at all, which a JavaScript caller can pass.
    expect(() =>
      SandboxManager.registerCommandNetworkLists(
        randomCommandId(),
        undefined as unknown as { allowedDomains?: string[] },
      ),
    ).not.toThrow()
  })

  it('does not repeat the id in the error it throws', () => {
    const almost = 'secret-id-0123456789x'
    expect(almost).toHaveLength(21)
    let message = ''
    try {
      SandboxManager.registerCommandNetworkLists(almost, {})
    } catch (error) {
      message = (error as Error).message
    }
    expect(message).not.toBe('')
    expect(message).not.toContain(almost)
  })

  // Accepted and refused by one predicate, so the two can only agree; this
  // pins that a list arriving at run time cannot carry an entry the
  // configuration would have refused, and the other way round.
  it.each([
    ['example.com', true],
    ['*.example.com', true],
    ['api.example.com:443', true],
    ['localhost', true],
    ['127.0.0.1:3000', true],
    ['[::1]', true],
    ['[2001:db8::1]:443', true],
    ['*', false],
    ['*:443', false],
    ['*.com', false],
    ['https://example.com', false],
    ['example.com/path', false],
    ['example.com:0', false],
    ['example.com:443.evil.test', false],
    ['2001:db8::1', false],
    ['nodots', false],
    ['', false],
  ])(
    'accepts the entry %p exactly when network.allowedDomains does (%p)',
    (entry, valid) => {
      expect(
        SandboxRuntimeConfigSchema.safeParse({
          network: { allowedDomains: [entry], deniedDomains: [] },
          filesystem: NO_FILESYSTEM_RULES,
        }).success,
      ).toBe(valid)
      const register = () =>
        SandboxManager.registerCommandNetworkLists(randomCommandId(), {
          allowedDomains: [entry],
        })
      if (valid) {
        expect(register).not.toThrow()
      } else {
        expect(register).toThrow(/invalid allowedDomains entry/)
      }
    },
  )

  it('refuses an entry that is not a string, and a list that is not an array', () => {
    for (const entry of [null, undefined, 443, { host: 'example.com' }]) {
      expect(() =>
        SandboxManager.registerCommandNetworkLists(randomCommandId(), {
          allowedDomains: [entry as unknown as string],
        }),
      ).toThrow(/invalid allowedDomains entry/)
    }
    expect(() =>
      SandboxManager.registerCommandNetworkLists(randomCommandId(), {
        allowedDomains: 'example.com' as unknown as string[],
      }),
    ).toThrow(/must be an array/)
  })

  it('registers nothing when any entry is invalid', async () => {
    const port = await start({})
    const registered = randomCommandId()
    expect(() =>
      SandboxManager.registerCommandNetworkLists(registered, {
        allowedDomains: [loopback.target, '*.com'],
      }),
    ).toThrow(/invalid allowedDomains entry "\*\.com"/)

    expect(
      await connectAs(port, loopback.target, usernameFor(registered)),
    ).toBe(403)
  })

  // An id is normalised before it keys the map, and what the proxy receives
  // is decoded rather than compared as bytes. Each case here is an id or a
  // username that differs from the registered one byte for byte and reaches
  // its list all the same, or looks alike and does not.
  describe('ids that differ byte for byte from the registered one', () => {
    it('share a list when they agree on their first 100 characters', async () => {
      const port = await start({})
      const prefix = randomBytes(75).toString('base64url')
      expect(prefix).toHaveLength(100)
      SandboxManager.registerCommandNetworkLists(`${prefix}-first`, {
        allowedDomains: [loopback.target],
      })

      // A wrap given this other id mints the same username: the key is cut
      // to 100 characters before it is encoded.
      expect(usernameFor(`${prefix}-second`)).toBe(
        usernameFor(`${prefix}-first`),
      )
      expect(
        await connectAs(port, loopback.target, usernameFor(`${prefix}-second`)),
      ).toBe(200)

      // A username carrying all 105 characters was not minted here; it
      // decodes to a longer key, which nothing is registered under.
      const uncut = Buffer.from(`${prefix}-first`).toString('base64')
      expect(await connectAs(port, loopback.target, `srt.${uncut}`)).toBe(403)

      // And unregistering either id removes the one list they share.
      SandboxManager.unregisterCommandNetworkLists(`${prefix}-second`)
      expect(
        await connectAs(port, loopback.target, usernameFor(`${prefix}-first`)),
      ).toBe(403)
    })

    it('reach the list through any base64 spelling of the same bytes', async () => {
      const port = await start({})
      // 22 characters that encode with padding and with both of the
      // characters the URL-safe alphabet spells differently.
      const registered = 'id?>id?>id?>id?>id?>~~'
      const minted = encodeSandboxedCommand(registered)
      expect(minted).toMatch(/[+/]/)
      expect(minted).toMatch(/=$/)
      SandboxManager.registerCommandNetworkLists(registered, {
        allowedDomains: [loopback.target],
      })

      const unpadded = minted.replace(/=+$/, '')
      const urlSafe = unpadded.replace(/\+/g, '-').replace(/\//g, '_')
      for (const spelling of [minted, unpadded, urlSafe]) {
        expect(await connectAs(port, loopback.target, `srt.${spelling}`)).toBe(
          200,
        )
      }
    })

    it('share a list when they differ only in an unpaired surrogate', async () => {
      const port = await start({})
      const stem = randomCommandId()
      // Neither half of a surrogate pair can be encoded on its own; each
      // becomes U+FFFD, so both ids normalise to one key.
      SandboxManager.registerCommandNetworkLists(`${stem}\ud800`, {
        allowedDomains: [loopback.target],
      })

      expect(
        await connectAs(port, loopback.target, usernameFor(`${stem}\udfff`)),
      ).toBe(200)
      expect(
        await connectAs(port, loopback.target, usernameFor(`${stem}\ufffd`)),
      ).toBe(200)
      // The stem alone is a different key.
      expect(await connectAs(port, loopback.target, usernameFor(stem))).toBe(
        403,
      )
    })

    it('do not reach it by differing in case', async () => {
      const port = await start({})
      const registered = `${randomCommandId()}abc`
      SandboxManager.registerCommandNetworkLists(registered, {
        allowedDomains: [loopback.target],
      })

      expect(
        await connectAs(
          port,
          loopback.target,
          usernameFor(registered.toUpperCase()),
        ),
      ).toBe(403)
    })
  })
})

describe('ask callback answers', () => {
  let loopback: { server: Server; target: string }

  /** One CONNECT to the loopback listener, decided by `answer` alone. */
  async function decideWith(
    answer: unknown,
  ): Promise<{ status: number | undefined; lines: string[] }> {
    await SandboxManager.initialize(
      {
        network: { allowedDomains: [], deniedDomains: [] },
        filesystem: NO_FILESYSTEM_RULES,
      },
      (async () => answer) as SandboxAskCallback,
    )
    SandboxManager.getSandboxViolationStore().clear()
    const status = await connectAs(
      SandboxManager.getProxyPort()!,
      loopback.target,
      'srt',
    )
    return { status, lines: violationLines() }
  }

  const deniedBecause = (reason: string): string[] => [
    `deny network-outbound ${loopback.target} (${reason})`,
  ]

  beforeEach(async () => {
    await SandboxManager.reset()
    loopback = await listenOnLoopback()
  })

  afterEach(async () => {
    await SandboxManager.reset()
    loopback.server.close()
  })

  it('declares that it reads a denial with a reason', () => {
    expect(SandboxManager.askCallbackDenyReason).toBe(true)
  })

  it('allows on true', async () => {
    expect(await decideWith(true)).toEqual({ status: 200, lines: [] })
  })

  it('denies on false, with the generic reason', async () => {
    expect(await decideWith(false)).toEqual({
      status: 403,
      lines: deniedBecause('user denied'),
    })
  })

  it('denies on { allow: false, reason }, and reports that reason', async () => {
    const callback: SandboxAskCallback = async () => ({
      allow: false,
      reason: 'not listed for this command; list the host and run it again',
    })
    expect(await decideWith(await callback({ host: '', port: 0 }))).toEqual({
      status: 403,
      lines: deniedBecause(
        'not listed for this command; list the host and run it again',
      ),
    })
  })

  it.each([
    ['an empty reason', { allow: false, reason: '' }],
    ['a reason of nothing but whitespace', { allow: false, reason: ' \n\t ' }],
    ['no reason', { allow: false }],
    ['a reason that is not a string', { allow: false, reason: 42 }],
  ])('denies with the generic reason on %s', async (_name, answer) => {
    expect(await decideWith(answer)).toEqual({
      status: 403,
      lines: deniedBecause('user denied'),
    })
  })

  // Every one of these was an allow while the filter tested truthiness.
  it.each([
    ['the number 1', 1],
    ['a non-empty string', 'yes'],
    ['an empty object', {}],
    ['an empty array', []],
    ['an object that says allow: true', { allow: true }],
    ['the string "true"', 'true'],
    // A reason is reported only for an answer that says allow: false. One
    // that says otherwise was not written as the explanation of a denial.
    [
      'an object that says allow: true and gives a reason',
      { allow: true, reason: 'approved for this session' },
    ],
    [
      'an object that gives a reason and no allow',
      { reason: 'no verdict given' },
    ],
    [
      'an object whose allow is falsy but not false',
      { allow: 0, reason: 'zero is not false' },
    ],
  ])(
    'denies on a truthy answer that is not true: %s',
    async (_name, answer) => {
      expect(await decideWith(answer)).toEqual({
        status: 403,
        lines: deniedBecause('user denied'),
      })
    },
  )

  it.each([
    ['undefined', undefined],
    ['null', null],
    ['zero', 0],
  ])(
    'denies on a falsy answer that is not false: %s',
    async (_name, answer) => {
      expect(await decideWith(answer)).toEqual({
        status: 403,
        lines: deniedBecause('user denied'),
      })
    },
  )

  it('cuts an over-long reason to 500 characters', async () => {
    const { status, lines } = await decideWith({
      allow: false,
      reason: 'x'.repeat(2000),
    })
    expect(status).toBe(403)
    expect(lines).toEqual(deniedBecause('x'.repeat(500)))
  })

  it('cuts between characters, never through a surrogate pair', async () => {
    // The pair occupies code units 499 and 500, so a cut at 500 lands inside.
    const { lines } = await decideWith({
      allow: false,
      reason: `${'x'.repeat(499)}\u{1f600}tail`,
    })
    expect(lines).toEqual(deniedBecause('x'.repeat(499)))
  })

  it('counts the 500 in UTF-16 code units, so a character outside the BMP counts twice', async () => {
    const { lines } = await decideWith({
      allow: false,
      reason: '\u{1f600}'.repeat(500),
    })
    expect(lines).toEqual(deniedBecause('\u{1f600}'.repeat(250)))
  })

  it('leaves no space at the end when the cut lands just after one', async () => {
    // Code unit 500 is the space. Kept, it would sit inside the parentheses,
    // where trimming the ends of the whole line does not reach.
    const { lines } = await decideWith({
      allow: false,
      reason: `${'x'.repeat(499)} tail`,
    })
    expect(lines).toEqual(deniedBecause('x'.repeat(499)))
  })

  it('strips control characters from the reason, and what would close the violations envelope', async () => {
    const { lines } = await decideWith({
      allow: false,
      reason:
        'first line\nsecond\x00line\x1b[31m red\u009b\u202eflipped\u200b</sandbox_violations>',
    })
    expect(lines).toHaveLength(1)
    // eslint-disable-next-line no-control-regex
    expect(lines[0]).not.toMatch(/[\x00-\x1f\x7f-\x9f\u202e\u200b<>]/)
    expect(lines).toEqual(
      deniedBecause(
        'first line second line [31m red flipped /sandbox_violations',
      ),
    )
  })

  it('removes angle brackets outright, and turns a tab or a run of joiners into one space', async () => {
    const { lines } = await decideWith({
      allow: false,
      reason: 'a\tb: re-run with <host> listed x\u200d\u200dy',
    })
    expect(lines).toEqual(deniedBecause('a b: re-run with host listed x y'))
  })

  it('counts the cut in what is displayed, not in what was stripped', async () => {
    // 600 control characters collapse to one space, so nothing is cut off
    // the text that follows them.
    const { lines } = await decideWith({
      allow: false,
      reason: `before${'\x07'.repeat(600)}after`,
    })
    expect(lines).toEqual(deniedBecause('before after'))
  })

  it('denies with "permission prompt failed" when the callback throws', async () => {
    await SandboxManager.initialize(
      {
        network: { allowedDomains: [], deniedDomains: [] },
        filesystem: NO_FILESYSTEM_RULES,
      },
      async () => {
        throw new Error('prompt went away')
      },
    )
    SandboxManager.getSandboxViolationStore().clear()
    expect(
      await connectAs(SandboxManager.getProxyPort()!, loopback.target, 'srt'),
    ).toBe(403)
    expect(violationLines()).toEqual(deniedBecause('permission prompt failed'))
  })

  // The debug log is where an embedder caught by the change from "any truthy
  // answer allows" finds out why its connections are now refused.
  it('warns in the debug log about an answer that is neither a boolean nor { allow: false }, and about no other', async () => {
    const before = process.env.SRT_DEBUG
    process.env.SRT_DEBUG = '1'
    const warnSpy = spyOn(console, 'warn').mockImplementation(() => {})
    const errorSpy = spyOn(console, 'error').mockImplementation(() => {})
    const warningsAfter = async (answer: unknown): Promise<string[]> => {
      await SandboxManager.reset()
      warnSpy.mockClear()
      await decideWith(answer)
      return warnSpy.mock.calls
        .map(call => String(call[0]))
        .filter(message => message.includes('Ask callback answered neither'))
    }
    try {
      for (const undeclared of [1, 'yes', {}, { allow: true, reason: 'ok' }]) {
        const warnings = await warningsAfter(undeclared)
        expect(warnings).toHaveLength(1)
        expect(warnings[0]).toContain('treating it as a denial')
        expect(warnings[0]).toContain(loopback.target)
      }
      for (const declared of [true, false, { allow: false, reason: 'no' }]) {
        expect(await warningsAfter(declared)).toEqual([])
      }
    } finally {
      warnSpy.mockRestore()
      errorSpy.mockRestore()
      if (before === undefined) {
        delete process.env.SRT_DEBUG
      } else {
        process.env.SRT_DEBUG = before
      }
    }
  })
})

describe('SandboxManager.updateConfig', () => {
  beforeEach(async () => {
    await SandboxManager.reset()
  })

  afterEach(async () => {
    await SandboxManager.reset()
  })

  it('should handle updateConfig called before initialize', async () => {
    // updateConfig before initialize - should not throw
    SandboxManager.updateConfig({
      network: { allowedDomains: ['example.com'], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    })

    // Config should be set
    expect(SandboxManager.getConfig()).toBeDefined()

    // But network infrastructure not ready
    expect(SandboxManager.getProxyPort()).toBeUndefined()

    // Initialize should still work and respect the pre-set config
    await SandboxManager.initialize({
      network: { allowedDomains: ['other.com'], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    })

    // initialize() overwrites config
    const config = SandboxManager.getConfig()
    expect(config?.network.allowedDomains).toContain('other.com')
    expect(config?.network.allowedDomains).not.toContain('example.com')
  })

  it('should update network restriction config dynamically', async () => {
    // Initialize with no allowed domains
    await SandboxManager.initialize({
      network: { allowedDomains: [], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    })

    // Initial state: allowlist configured with zero entries. The getter must
    // preserve the empty array — consumers distinguish "no allowlist
    // configured" (undefined) from "allowlist configured, nothing allowed".
    expect(SandboxManager.getNetworkRestrictionConfig().allowedHosts).toEqual(
      [],
    )

    // Update config to allow example.com
    SandboxManager.updateConfig({
      network: { allowedDomains: ['example.com'], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    })

    // Config should now reflect the update
    const config = SandboxManager.getNetworkRestrictionConfig()
    expect(config.allowedHosts).toContain('example.com')
  })

  it('should handle moving domain from allowlist to denylist', async () => {
    // Initialize with example.com allowed
    await SandboxManager.initialize({
      network: { allowedDomains: ['example.com'], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    })

    let config = SandboxManager.getNetworkRestrictionConfig()
    expect(config.allowedHosts).toContain('example.com')
    expect(config.deniedHosts).toBeUndefined()

    // Move to denylist
    SandboxManager.updateConfig({
      network: { allowedDomains: [], deniedDomains: ['example.com'] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    })

    config = SandboxManager.getNetworkRestrictionConfig()
    expect(config.allowedHosts).toEqual([])
    expect(config.deniedHosts).toContain('example.com')

    // Move back to allowlist
    SandboxManager.updateConfig({
      network: { allowedDomains: ['example.com'], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    })

    config = SandboxManager.getNetworkRestrictionConfig()
    expect(config.allowedHosts).toContain('example.com')
    expect(config.deniedHosts).toBeUndefined()
  })

  it('should handle updating to empty allowlist', async () => {
    // Initialize with example.com allowed
    await SandboxManager.initialize({
      network: { allowedDomains: ['example.com'], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    })

    expect(SandboxManager.getNetworkRestrictionConfig().allowedHosts).toContain(
      'example.com',
    )

    // Update to empty allowlist (should block all)
    SandboxManager.updateConfig({
      network: { allowedDomains: [], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    })

    // The getter preserves the explicitly-empty allowlist so consumers can
    // tell a configured block-all apart from no restriction at all
    expect(SandboxManager.getNetworkRestrictionConfig().allowedHosts).toEqual(
      [],
    )

    // Verify the actual config still exists
    const fullConfig = SandboxManager.getConfig()
    expect(fullConfig).toBeDefined()
    expect(fullConfig?.network.allowedDomains).toEqual([])
  })

  it('preserves filterRequest across updateConfig (structuredClone cannot clone functions)', () => {
    const filterRequest = async () => ({ action: 'allow' as const })
    // Must not throw: structuredClone(fn) throws DataCloneError; the
    // function is pulled out, the rest is cloned, then the reference is
    // restored.
    SandboxManager.updateConfig({
      network: { allowedDomains: [], deniedDomains: [], filterRequest },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    })
    expect(SandboxManager.getConfig()?.network.filterRequest).toBe(
      filterRequest,
    )
  })
})

describe('SandboxManager.updateConfig proxy filtering', () => {
  afterEach(async () => {
    await SandboxManager.reset()
  })

  it('should allow then block domain after config update', async () => {
    // Initialize with example.com allowed
    await SandboxManager.initialize({
      network: { allowedDomains: ['example.com'], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    })

    const proxyPort = SandboxManager.getProxyPort()
    expect(proxyPort).toBeDefined()

    // Should be allowed initially
    const result1 = await proxyRequest(proxyPort!, 'example.com')
    expect(result1.allowed).toBe(true)

    // Update to block example.com (empty allowlist)
    SandboxManager.updateConfig({
      network: { allowedDomains: [], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    })

    // Should now be blocked
    const result2 = await proxyRequest(proxyPort!, 'example.com')
    expect(result2.allowed).toBe(false)
  })

  it('should block then allow domain after config update', async () => {
    // Initialize with empty allowlist (blocks all)
    await SandboxManager.initialize({
      network: { allowedDomains: [], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    })

    const proxyPort = SandboxManager.getProxyPort()
    expect(proxyPort).toBeDefined()

    // Should be blocked initially
    const result1 = await proxyRequest(proxyPort!, 'example.com')
    expect(result1.allowed).toBe(false)

    // Update to allow example.com
    SandboxManager.updateConfig({
      network: { allowedDomains: ['example.com'], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    })

    // Should now be allowed
    const result2 = await proxyRequest(proxyPort!, 'example.com')
    expect(result2.allowed).toBe(true)
  })

  it('should handle moving domain between allow and deny lists', async () => {
    // Initialize with example.com allowed
    await SandboxManager.initialize({
      network: { allowedDomains: ['example.com'], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    })

    const proxyPort = SandboxManager.getProxyPort()
    expect(proxyPort).toBeDefined()

    // Should be allowed initially
    const result1 = await proxyRequest(proxyPort!, 'example.com')
    expect(result1.allowed).toBe(true)

    // Move to denylist
    SandboxManager.updateConfig({
      network: { allowedDomains: [], deniedDomains: ['example.com'] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    })

    // Should now be blocked
    const result2 = await proxyRequest(proxyPort!, 'example.com')
    expect(result2.allowed).toBe(false)

    // Move back to allowlist
    SandboxManager.updateConfig({
      network: { allowedDomains: ['example.com'], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    })

    // Should be allowed again
    const result3 = await proxyRequest(proxyPort!, 'example.com')
    expect(result3.allowed).toBe(true)
  })

  it('should handle rapid config updates', async () => {
    await SandboxManager.initialize({
      network: { allowedDomains: ['example.com'], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    })

    const proxyPort = SandboxManager.getProxyPort()
    expect(proxyPort).toBeDefined()

    // Rapid updates
    for (let i = 0; i < 5; i++) {
      SandboxManager.updateConfig({
        network: { allowedDomains: [], deniedDomains: [] },
        filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
      })

      SandboxManager.updateConfig({
        network: { allowedDomains: ['example.com'], deniedDomains: [] },
        filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
      })
    }

    // Final state should allow example.com
    const result = await proxyRequest(proxyPort!, 'example.com')
    expect(result.allowed).toBe(true)
  })
})

/**
 * Integration tests using wrapWithSandbox() to verify sandbox wrapper generation
 * and actual network behavior with sandboxed curl commands.
 */
describe('SandboxManager.updateConfig integration (wrapWithSandbox)', () => {
  afterEach(async () => {
    await SandboxManager.reset()
  })

  it.if(isLinux)(
    'should block then allow domain after updateConfig with sandboxed curl',
    async () => {
      // Initialize with empty allowlist (blocks all)
      await SandboxManager.initialize({
        network: { allowedDomains: [], deniedDomains: [] },
        filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
      })

      // First request should be blocked
      const cmd1 = await SandboxManager.wrapWithSandbox(
        'curl -s --max-time 3 http://example.com 2>&1',
      )
      const result1 = await spawnAsync(cmd1, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })
      const output1 = (result1.stdout + result1.stderr).toLowerCase()
      // With empty allowlist, network is completely blocked (no proxy)
      expect(output1).not.toContain('example domain')

      // Update config to allow example.com
      SandboxManager.updateConfig({
        network: { allowedDomains: ['example.com'], deniedDomains: [] },
        filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
      })

      // Second request should succeed
      // Note: wrapWithSandbox() generates new command with updated config
      const cmd2 = await SandboxManager.wrapWithSandbox(
        'curl -s --max-time 5 http://example.com 2>&1',
      )
      const result2 = await spawnAsync(cmd2, {
        shell: true,
        encoding: 'utf8',
        timeout: 10000,
      })

      expect(result2.status).toBe(0)
      expect(result2.stdout).toContain('Example Domain')
    },
    20000,
  )

  it.if(isLinux)(
    'should allow then block domain after updateConfig with sandboxed curl',
    async () => {
      // Initialize with example.com allowed
      await SandboxManager.initialize({
        network: { allowedDomains: ['example.com'], deniedDomains: [] },
        filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
      })

      // First request should succeed
      const cmd1 = await SandboxManager.wrapWithSandbox(
        'curl -s --max-time 5 http://example.com 2>&1',
      )
      const result1 = await spawnAsync(cmd1, {
        shell: true,
        encoding: 'utf8',
        timeout: 10000,
      })
      expect(result1.status).toBe(0)
      expect(result1.stdout).toContain('Example Domain')

      // Update config to block all
      SandboxManager.updateConfig({
        network: { allowedDomains: [], deniedDomains: [] },
        filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
      })

      // Second request should be blocked
      const cmd2 = await SandboxManager.wrapWithSandbox(
        'curl -s --max-time 3 http://example.com 2>&1',
      )
      const result2 = await spawnAsync(cmd2, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })
      const output2 = (result2.stdout + result2.stderr).toLowerCase()
      expect(output2).not.toContain('example domain')
    },
    20000,
  )

  it.if(isLinux)(
    'should allow network via curl after updateConfig when started with empty allowlist',
    async () => {
      // Initialize with EMPTY allowlist
      await SandboxManager.initialize({
        network: { allowedDomains: [], deniedDomains: [] },
        filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
      })

      // Update config to allow example.com
      SandboxManager.updateConfig({
        network: { allowedDomains: ['example.com'], deniedDomains: [] },
        filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
      })

      // Full integration: sandboxed curl should work
      const cmd = await SandboxManager.wrapWithSandbox(
        'curl -s --max-time 5 http://example.com 2>&1',
      )
      const result = await spawnAsync(cmd, {
        shell: true,
        encoding: 'utf8',
        timeout: 10000,
      })

      expect(result.status).toBe(0)
      expect(result.stdout).toContain('Example Domain')
    },
    20000,
  )

  /**
   * This test verifies the exact user scenario:
   * 1. Start sandbox with allowedDomains: [], deniedDomains: ["example.com"]
   * 2. Generate wrapper (should include proxy config even with empty allowlist)
   * 3. Update config to allow example.com
   * 4. Proxy should now allow requests (tested via raw TCP)
   *
   * The fix: even with empty allowlist, wrapper includes proxy config so
   * updateConfig() can enable network access for sandboxed processes.
   */
  it('should allow network after updateConfig when started with empty allowlist and denylist', async () => {
    // Initialize with empty allowlist, example.com in denylist (user's exact scenario)
    await SandboxManager.initialize({
      network: { allowedDomains: [], deniedDomains: ['example.com'] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    })

    // Wrapper should include proxy config even with empty allowlist
    const cmd = await SandboxManager.wrapWithSandbox('echo test')
    const platform = getPlatform()
    if (platform === 'macos') {
      expect(cmd).toContain('HTTP_PROXY')
    } else if (platform === 'linux') {
      expect(cmd).toMatch(/HTTP_PROXY|\.sock/)
    }

    // Proxy should be running
    const proxyPort = SandboxManager.getProxyPort()
    expect(proxyPort).toBeDefined()

    // Initially, example.com should be blocked (empty allowlist = block all)
    const blockedResult = await proxyRequest(proxyPort!, 'example.com')
    expect(blockedResult.allowed).toBe(false)

    // Update config to allow example.com
    SandboxManager.updateConfig({
      network: { allowedDomains: ['example.com'], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    })

    // Now example.com should be allowed
    const allowedResult = await proxyRequest(proxyPort!, 'example.com')
    expect(allowedResult.allowed).toBe(true)
  })

  /**
   * This test verifies the core fix: sandbox wrapper should include proxy config
   * even with empty allowlist, enabling dynamic updates.
   */
  it('should include proxy in sandbox wrapper even with empty allowlist', async () => {
    // Initialize with EMPTY allowlist - this is the bug scenario
    await SandboxManager.initialize({
      network: { allowedDomains: [], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    })

    // Get the sandbox wrapper command
    const wrapper = await SandboxManager.wrapWithSandbox('echo test')

    // The wrapper should include proxy configuration
    // On macOS: HTTP_PROXY and HTTPS_PROXY env vars
    // On Linux: socket paths
    const platform = getPlatform()
    if (platform === 'macos') {
      expect(wrapper).toContain('HTTP_PROXY')
      expect(wrapper).toContain('HTTPS_PROXY')
    } else if (platform === 'linux') {
      // Linux uses unix sockets, check for socket paths or proxy env vars
      expect(wrapper).toMatch(/HTTP_PROXY|http_proxy|\.sock/)
    }
  })
})
