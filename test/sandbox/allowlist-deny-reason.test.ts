import { afterEach, beforeEach, describe, expect, it } from 'bun:test'
import { connect } from 'node:net'
import { once } from 'node:events'
import { SandboxManager, SandboxRuntimeConfigSchema } from '../../src/index.js'

/**
 * `network.allowlistDenyReason`: the deployer's text for a destination that
 * is on no list at all, the one denial `deniedDomainReasons` cannot key a
 * reason on.
 */

const REASON =
  'blocked by sandbox policy; ask the user to add the host to allowedDomains'
const GENERIC = 'host is not on the allow list'

const NO_FILESYSTEM_RULES = { denyRead: [], allowWrite: [], denyWrite: [] }

async function start(allowlistDenyReason?: string): Promise<number> {
  await SandboxManager.initialize({
    network: {
      allowedDomains: [],
      deniedDomains: [],
      strictAllowlist: true,
      ...(allowlistDenyReason === undefined ? {} : { allowlistDenyReason }),
    },
    filesystem: NO_FILESYSTEM_RULES,
  })
  SandboxManager.getSandboxViolationStore().clear()
  return SandboxManager.getProxyPort()!
}

/** The whole reply to a request written over one connection. */
async function exchange(proxyPort: number, request: string): Promise<string> {
  const token = SandboxManager.getProxyAuthToken()
  const auth = Buffer.from(`srt:${token}`).toString('base64')
  const socket = connect(proxyPort, '127.0.0.1')
  await once(socket, 'connect')
  socket.write(request.replace('__AUTH__', auth))
  const chunks: Buffer[] = []
  socket.on('data', chunk => chunks.push(chunk))
  socket.on('error', () => {})
  await once(socket, 'close')
  return Buffer.concat(chunks).toString('utf8')
}

const connectRequest =
  'CONNECT blocked.test:443 HTTP/1.1\r\n' +
  'Host: blocked.test:443\r\n' +
  'Proxy-Authorization: Basic __AUTH__\r\n\r\n'

const httpRequest =
  'GET http://blocked.test/x HTTP/1.1\r\n' +
  'Host: blocked.test\r\n' +
  'Proxy-Authorization: Basic __AUTH__\r\n' +
  'Connection: close\r\n\r\n'

const violationLines = (): string[] =>
  SandboxManager.getSandboxViolationStore()
    .getViolations()
    .map(v => v.line)

describe('network.allowlistDenyReason', () => {
  beforeEach(async () => {
    await SandboxManager.reset()
  })

  afterEach(async () => {
    await SandboxManager.reset()
  })

  it('answers a refused CONNECT with the configured reason as the status phrase', async () => {
    const port = await start(REASON)

    expect(await exchange(port, connectRequest)).toContain(
      `HTTP/1.1 403 ${REASON}\r\n`,
    )
    expect(violationLines()).toEqual([
      `deny network-outbound blocked.test:443 (${REASON})`,
    ])
  })

  it('answers a refused plain-HTTP request with it as the body', async () => {
    const port = await start(REASON)

    const reply = await exchange(port, httpRequest)

    expect(reply).toContain('HTTP/1.1 403')
    expect(reply).toContain('X-Proxy-Error: blocked-by-allowlist')
    expect(reply.split('\r\n\r\n')[1]).toBe(`${REASON}\n`)
    expect(violationLines()).toEqual([
      `deny network-outbound blocked.test:80 (${REASON})`,
    ])
  })

  it('keeps the generic reason when the field is unset', async () => {
    const port = await start()

    expect(await exchange(port, connectRequest)).toContain(
      `HTTP/1.1 403 ${GENERIC}\r\n`,
    )
    expect(violationLines()).toEqual([
      `deny network-outbound blocked.test:443 (${GENERIC})`,
    ])
  })

  it('is rejected empty by the config schema', () => {
    const parse = (allowlistDenyReason: string) =>
      SandboxRuntimeConfigSchema.safeParse({
        network: {
          allowedDomains: [],
          deniedDomains: [],
          allowlistDenyReason,
        },
        filesystem: NO_FILESYSTEM_RULES,
      }).success

    expect(parse('')).toBe(false)
    expect(parse(REASON)).toBe(true)
  })
})
