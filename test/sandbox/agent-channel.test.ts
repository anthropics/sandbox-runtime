import { describe, it, expect } from 'bun:test'
import { PassThrough, Duplex } from 'node:stream'
import {
  SandboxAgentChannel,
  blockedMessageFromViolation,
  AGENT_CHANNEL_PROTOCOL_VERSION,
} from '../../src/sandbox/agent-channel.js'

/**
 * A two-ended in-memory transport: `sandboxSide` is handed to the channel,
 * `agent` is the test's view of the wire.
 */
function makeTransport(): {
  sandboxSide: Duplex
  agent: {
    send: (message: object) => void
    sendRaw: (bytes: string) => void
    received: () => Promise<object[]>
    close: () => void
  }
} {
  const toAgent = new PassThrough()
  const toSandbox = new PassThrough()
  const sandboxSide = Duplex.from({ readable: toSandbox, writable: toAgent })

  let received = ''
  toAgent.on('data', chunk => {
    received += chunk.toString()
  })

  return {
    sandboxSide,
    agent: {
      send: message => {
        toSandbox.write(JSON.stringify(message) + '\n')
      },
      sendRaw: bytes => {
        toSandbox.write(bytes)
      },
      received: async () => {
        // Let pending stream callbacks drain.
        await new Promise(resolve => setTimeout(resolve, 10))
        return received
          .split('\n')
          .filter(line => line.trim())
          .map(line => JSON.parse(line) as object)
      },
      close: () => {
        toSandbox.end()
      },
    },
  }
}

function agentHello(): object {
  return { type: 'hello', protocol_version: AGENT_CHANNEL_PROTOCOL_VERSION }
}

async function makeReadyChannel(): Promise<{
  channel: SandboxAgentChannel
  agent: ReturnType<typeof makeTransport>['agent']
}> {
  const { sandboxSide, agent } = makeTransport()
  const channel = new SandboxAgentChannel(sandboxSide)
  agent.send(agentHello())
  await new Promise(resolve => setTimeout(resolve, 10))
  expect(channel.isReady()).toBe(true)
  return { channel, agent }
}

describe('SandboxAgentChannel', () => {
  it('begins the handshake by sending hello', async () => {
    const { sandboxSide, agent } = makeTransport()
    new SandboxAgentChannel(sandboxSide)
    const messages = await agent.received()
    expect(messages[0]).toEqual({
      type: 'hello',
      protocol_version: AGENT_CHANNEL_PROTOCOL_VERSION,
    })
  })

  it('denies asks without sending anything before the agent hello', async () => {
    const { sandboxSide, agent } = makeTransport()
    const channel = new SandboxAgentChannel(sandboxSide)
    expect(channel.isReady()).toBe(false)
    const allowed = await channel.ask(
      { type: 'network', host: 'example.com', port: 443 },
      'connect',
      'Connecting to example.com:443',
    )
    expect(allowed).toBe(false)
    const messages = await agent.received()
    expect(messages).toHaveLength(1) // only the hello
  })

  it('resolves an ask as allow when the agent allows', async () => {
    const { channel, agent } = await makeReadyChannel()

    const pending = channel.ask(
      { type: 'network', host: 'api.github.com', port: 443 },
      'connect',
      'Connecting to api.github.com:443',
    )
    const messages = await agent.received()
    const request = messages.find(
      message => (message as { type?: string }).type === 'permission_request',
    ) as {
      id: string
      resource: object
      operation: string
      description: string
    }
    expect(request).toBeDefined()
    expect(request.resource).toEqual({
      type: 'network',
      host: 'api.github.com',
      port: 443,
    })
    expect(request.operation).toBe('connect')
    expect(request.description).toBe('Connecting to api.github.com:443')

    agent.send({
      type: 'permission_response',
      id: request.id,
      behavior: 'allow',
    })
    expect(await pending).toBe(true)
  })

  it('resolves an ask as deny when the agent denies', async () => {
    const { channel, agent } = await makeReadyChannel()
    const pending = channel.ask(
      { type: 'network', host: 'example.com', port: 443 },
      'connect',
      'Connecting to example.com:443',
    )
    const messages = await agent.received()
    const request = messages.find(
      message => (message as { type?: string }).type === 'permission_request',
    ) as { id: string }
    agent.send({
      type: 'permission_response',
      id: request.id,
      behavior: 'deny',
    })
    expect(await pending).toBe(false)
  })

  it('treats any behavior other than allow as deny', async () => {
    const { channel, agent } = await makeReadyChannel()
    const pending = channel.ask(
      { type: 'network', host: 'example.com', port: 443 },
      'connect',
      'Connecting to example.com:443',
    )
    const messages = await agent.received()
    const request = messages.find(
      message => (message as { type?: string }).type === 'permission_request',
    ) as { id: string }
    agent.send({
      type: 'permission_response',
      id: request.id,
      behavior: 'yes-please',
    })
    expect(await pending).toBe(false)
  })

  it('matches out-of-order responses to their requests by id', async () => {
    const { channel, agent } = await makeReadyChannel()
    const first = channel.ask(
      { type: 'network', host: 'a.example', port: 443 },
      'connect',
      'a',
    )
    const second = channel.ask(
      { type: 'network', host: 'b.example', port: 443 },
      'connect',
      'b',
    )
    const messages = await agent.received()
    const requests = messages.filter(
      message => (message as { type?: string }).type === 'permission_request',
    ) as Array<{ id: string; resource: { host: string } }>
    expect(requests).toHaveLength(2)
    const forA = requests.find(
      request => request.resource.host === 'a.example',
    )!
    const forB = requests.find(
      request => request.resource.host === 'b.example',
    )!
    // Answer the second request first.
    agent.send({ type: 'permission_response', id: forB.id, behavior: 'allow' })
    agent.send({ type: 'permission_response', id: forA.id, behavior: 'deny' })
    expect(await second).toBe(true)
    expect(await first).toBe(false)
  })

  it('survives malformed JSON and unknown message types', async () => {
    const { channel, agent } = await makeReadyChannel()
    agent.sendRaw('{ not json }\n')
    agent.send({ type: 'brand-new-thing', payload: 42 })
    agent.send({
      type: 'permission_response',
      id: 'pr_unknown',
      behavior: 'allow',
    })
    await new Promise(resolve => setTimeout(resolve, 10))
    expect(channel.isReady()).toBe(true)

    const pending = channel.ask(
      { type: 'network', host: 'example.com', port: 443 },
      'connect',
      'still works',
    )
    const messages = await agent.received()
    const request = messages.find(
      message => (message as { type?: string }).type === 'permission_request',
    ) as { id: string }
    agent.send({
      type: 'permission_response',
      id: request.id,
      behavior: 'allow',
    })
    expect(await pending).toBe(true)
  })

  it('never becomes ready on a protocol version mismatch', async () => {
    const { sandboxSide, agent } = makeTransport()
    const channel = new SandboxAgentChannel(sandboxSide)
    agent.send({ type: 'hello', protocol_version: 999 })
    await new Promise(resolve => setTimeout(resolve, 10))
    expect(channel.isReady()).toBe(false)
    const allowed = await channel.ask(
      { type: 'network', host: 'example.com', port: 443 },
      'connect',
      'Connecting to example.com:443',
    )
    expect(allowed).toBe(false)
  })

  it('resolves pending asks as deny when the channel closes', async () => {
    const { channel, agent } = await makeReadyChannel()
    const pending = channel.ask(
      { type: 'network', host: 'example.com', port: 443 },
      'connect',
      'Connecting to example.com:443',
    )
    await agent.received() // wait for the request to go out
    agent.close()
    expect(await pending).toBe(false)
    expect(channel.isReady()).toBe(false)
    expect(
      await channel.ask(
        { type: 'network', host: 'example.com', port: 443 },
        'connect',
        'after close',
      ),
    ).toBe(false)
  })

  it('queues blocked notifications until the handshake completes', async () => {
    const { sandboxSide, agent } = makeTransport()
    const channel = new SandboxAgentChannel(sandboxSide)
    channel.notifyBlocked({
      resource: { type: 'file', path: '/etc/hosts' },
      operation: 'write',
      description: 'Writing to /etc/hosts',
    })
    let messages = await agent.received()
    expect(
      messages.filter(m => (m as { type?: string }).type === 'blocked'),
    ).toHaveLength(0)

    agent.send(agentHello())
    messages = await agent.received()
    const blocked = messages.filter(
      m => (m as { type?: string }).type === 'blocked',
    )
    expect(blocked).toHaveLength(1)
    expect(blocked[0]).toEqual({
      type: 'blocked',
      resource: { type: 'file', path: '/etc/hosts' },
      operation: 'write',
      description: 'Writing to /etc/hosts',
    })
  })

  it('sends blocked notifications immediately once ready', async () => {
    const { channel, agent } = await makeReadyChannel()
    channel.notifyBlocked({
      resource: { type: 'network', host: 'example.com', port: 443 },
      operation: 'connect',
      description: 'Connecting to example.com:443 was blocked by the sandbox',
    })
    const messages = await agent.received()
    const blocked = messages.filter(
      m => (m as { type?: string }).type === 'blocked',
    )
    expect(blocked).toHaveLength(1)
  })

  it('closes the channel when the peer floods without newlines', async () => {
    const { sandboxSide, agent } = makeTransport()
    const channel = new SandboxAgentChannel(sandboxSide)
    agent.send(agentHello())
    await new Promise(resolve => setTimeout(resolve, 10))
    agent.sendRaw('x'.repeat(2 * 1024 * 1024))
    await new Promise(resolve => setTimeout(resolve, 10))
    expect(channel.isReady()).toBe(false)
  })
})

describe('blockedMessageFromViolation', () => {
  it('parses a proxy network deny', () => {
    const blocked = blockedMessageFromViolation(
      'deny network-outbound api.github.com:443 (host is not on the allow list)',
    )
    expect(blocked).toEqual({
      resource: { type: 'network', host: 'api.github.com', port: 443 },
      operation: 'connect',
      description:
        'Connecting to api.github.com:443 was blocked by the sandbox ' +
        '(host is not on the allow list)',
    })
  })

  it('suppresses denies the agent itself made', () => {
    expect(
      blockedMessageFromViolation(
        'deny network-outbound api.github.com:443 (user denied)',
      ),
    ).toBeUndefined()
  })

  it('parses a seatbelt file-write deny with a process prefix', () => {
    const blocked = blockedMessageFromViolation(
      'bash(4242) deny(1) file-write-data /etc/hosts',
    )
    expect(blocked).toEqual({
      resource: { type: 'file', path: '/etc/hosts' },
      operation: 'write',
      description:
        'Writing to /etc/hosts, which the sandbox policy does not allow',
    })
  })

  it('parses a seatbelt file-read deny', () => {
    const blocked = blockedMessageFromViolation(
      'deny(1) file-read-data /etc/passwd',
    )
    expect(blocked).toEqual({
      resource: { type: 'file', path: '/etc/passwd' },
      operation: 'read',
      description:
        'Reading /etc/passwd, which the sandbox policy does not allow',
    })
  })

  it('parses a Linux seccomp observer line as a file write', () => {
    const blocked = blockedMessageFromViolation('deny unlink /etc/hosts')
    expect(blocked).toEqual({
      resource: { type: 'file', path: '/etc/hosts' },
      operation: 'write',
      description:
        'Writing to /etc/hosts, which the sandbox policy does not allow',
    })
  })

  it('passes through unrecognized deny operations', () => {
    const blocked = blockedMessageFromViolation(
      'deny(1) mach-lookup com.apple.diagnostics',
    )
    expect(blocked).toEqual({
      resource: { type: 'unknown' },
      operation: 'mach-lookup',
      description:
        'mach-lookup com.apple.diagnostics, which the sandbox policy ' +
        'does not allow',
    })
  })

  it('produces identical messages for the same denial from different processes', () => {
    const fromBash = blockedMessageFromViolation(
      'bash(101) deny(1) sysctl-read kern.iossupportversion',
    )
    const fromCurl = blockedMessageFromViolation(
      'curl(202) deny(1) sysctl-read kern.iossupportversion',
    )
    expect(fromBash).toEqual(fromCurl!)
  })

  it('still reports lines it cannot parse at all', () => {
    const line = 'something completely unexpected'
    const blocked = blockedMessageFromViolation(line)
    expect(blocked).toEqual({
      resource: { type: 'unknown' },
      operation: 'unknown',
      description: line,
    })
  })
})
