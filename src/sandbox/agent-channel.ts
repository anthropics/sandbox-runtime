import type { Duplex } from 'stream'
import { logForDebugging } from '../utils/debug.js'

/**
 * Sandbox side of the Sandbox-Agent channel.
 *
 * A sandbox policy is written before the wrapped program runs, so it cannot
 * bend to what the program turns out to need. When the wrapped program is an
 * agent, it can be asked: the channel lets the sandbox forward requests its
 * policy does not cover to the agent for a context-aware allow/deny, and lets
 * the sandbox tell the agent what was blocked so the agent can react to a
 * denial instead of misdiagnosing it.
 *
 * Transport: a Unix socket (in the CLI, one end of a socketpair inherited by
 * the wrapped command; the sandbox tells the agent which file descriptor via
 * the SANDBOX_AGENT_CHANNEL_FD environment variable). Messages are
 * newline-delimited JSON.
 *
 * Protocol (version 1):
 *
 *   sandbox → agent
 *     {"type":"hello","protocol_version":1}
 *     {"type":"permission_request","id":"pr_1","resource":{...},
 *      "operation":"connect","description":"..."}
 *     {"type":"blocked","resource":{...},"operation":"write",
 *      "description":"..."}
 *
 *   agent → sandbox
 *     {"type":"hello","protocol_version":1}
 *     {"type":"permission_response","id":"pr_1","behavior":"allow"|"deny"}
 *
 * The sandbox begins the handshake by sending its hello as soon as the
 * channel opens. Until the agent's hello arrives, the sandbox asks nothing
 * and denies whatever its policy does not cover; `blocked` notifications
 * produced in that window are queued and flushed once the handshake
 * completes.
 *
 * Neither resource `type` nor `operation` is a fixed vocabulary — what a
 * sandbox governs is up to that sandbox. Agents must gracefully handle types
 * they do not know about; `description` is what lets them prompt about them
 * anyway.
 */

export const AGENT_CHANNEL_PROTOCOL_VERSION = 1

/**
 * Environment variable naming the file descriptor the agent should speak the
 * channel protocol on.
 */
export const SANDBOX_AGENT_CHANNEL_FD_ENV_VAR = 'SANDBOX_AGENT_CHANNEL_FD'

/**
 * A resource a permission_request or blocked message is about. `type` is an
 * open set ('file', 'network', ...); other fields depend on the type.
 */
export interface AgentChannelResource {
  type: string
  [key: string]: unknown
}

export interface AgentChannelBlockedMessage {
  resource: AgentChannelResource
  operation: string
  description: string
}

/**
 * Lines the agent may send without a trailing newline are not messages yet;
 * cap how much of one we will buffer before declaring the peer broken. A
 * broken channel fails safe: every ask denies.
 */
const MAX_LINE_BYTES = 1024 * 1024

/**
 * Cap on `blocked` notifications queued while waiting for the agent's hello.
 * Matches SandboxViolationStore's own tail size.
 */
const MAX_QUEUED_BLOCKED = 100

export class SandboxAgentChannel {
  private readonly stream: Duplex
  private buffer = ''
  private handshaken = false
  private closed = false
  private nextRequestId = 1
  private readonly pending = new Map<string, (allowed: boolean) => void>()
  private queuedBlocked: AgentChannelBlockedMessage[] = []

  constructor(stream: Duplex) {
    this.stream = stream
    stream.on('data', (chunk: Buffer | string) => this.onData(chunk))
    stream.on('error', err => {
      logForDebugging(`Agent channel error: ${err.message}`)
      this.close()
    })
    stream.on('end', () => this.close())
    stream.on('close', () => this.close())
    // The sandbox begins the handshake.
    this.send({
      type: 'hello',
      protocol_version: AGENT_CHANNEL_PROTOCOL_VERSION,
    })
  }

  /**
   * Whether the agent has completed the handshake (sent a hello with a
   * protocol version we speak) and the channel is still open.
   */
  isReady(): boolean {
    return this.handshaken && !this.closed
  }

  /**
   * Ask the agent to decide a request the sandbox policy does not cover.
   * Resolves true only when the agent answers allow. Denies without asking
   * when the handshake has not completed or the channel is gone — the
   * channel never widens what a policy alone would have allowed.
   */
  ask(
    resource: AgentChannelResource,
    operation: string,
    description: string,
  ): Promise<boolean> {
    if (!this.isReady()) {
      logForDebugging(
        `Agent channel not ready, denying ${operation} on ${JSON.stringify(resource)}`,
      )
      return Promise.resolve(false)
    }
    const id = `pr_${this.nextRequestId++}`
    return new Promise<boolean>(resolve => {
      this.pending.set(id, resolve)
      this.send({
        type: 'permission_request',
        id,
        resource,
        operation,
        description,
      })
    })
  }

  /**
   * Tell the agent the sandbox blocked an action, so it can steer the model
   * rather than let it misread the failure. Queued until the handshake
   * completes; dropped once the channel is gone.
   */
  notifyBlocked(message: AgentChannelBlockedMessage): void {
    if (this.closed) {
      return
    }
    if (!this.handshaken) {
      if (this.queuedBlocked.length < MAX_QUEUED_BLOCKED) {
        this.queuedBlocked.push(message)
      }
      return
    }
    this.send({ type: 'blocked', ...message })
  }

  /**
   * Close the channel. Pending asks resolve to deny; later asks deny
   * immediately.
   */
  close(): void {
    if (this.closed) {
      return
    }
    this.closed = true
    for (const resolve of this.pending.values()) {
      resolve(false)
    }
    this.pending.clear()
    this.queuedBlocked = []
    this.stream.destroy()
  }

  private onData(chunk: Buffer | string): void {
    if (this.closed) {
      return
    }
    this.buffer += chunk.toString()
    let newlineIndex: number
    while ((newlineIndex = this.buffer.indexOf('\n')) !== -1) {
      const line = this.buffer.slice(0, newlineIndex)
      this.buffer = this.buffer.slice(newlineIndex + 1)
      if (line.trim()) {
        this.handleLine(line)
      }
    }
    if (this.buffer.length > MAX_LINE_BYTES) {
      logForDebugging(
        'Agent channel peer sent an over-long line without a newline, closing',
      )
      this.close()
    }
  }

  private handleLine(line: string): void {
    let message: unknown
    try {
      message = JSON.parse(line)
    } catch {
      logForDebugging(`Agent channel ignoring unparseable line: ${line}`)
      return
    }
    if (typeof message !== 'object' || message === null) {
      return
    }
    const msg = message as Record<string, unknown>
    switch (msg.type) {
      case 'hello': {
        if (msg.protocol_version === AGENT_CHANNEL_PROTOCOL_VERSION) {
          this.handshaken = true
          const queued = this.queuedBlocked
          this.queuedBlocked = []
          for (const blocked of queued) {
            this.send({ type: 'blocked', ...blocked })
          }
        } else {
          // An agent speaking a version we don't understand never becomes
          // ready: asks keep denying, exactly as if no agent were attached.
          logForDebugging(
            `Agent channel hello with unsupported protocol_version ` +
              `${JSON.stringify(msg.protocol_version)}, ignoring`,
          )
        }
        break
      }
      case 'permission_response': {
        const id = msg.id
        if (typeof id !== 'string') {
          return
        }
        const resolve = this.pending.get(id)
        if (!resolve) {
          logForDebugging(
            `Agent channel permission_response for unknown id ${id}, ignoring`,
          )
          return
        }
        this.pending.delete(id)
        // Anything other than an explicit allow is a deny.
        resolve(msg.behavior === 'allow')
        break
      }
      default:
        // Unknown message types are ignored so future protocol additions
        // don't break older sandboxes — the mirror of the requirement that
        // agents tolerate resource types they do not know.
        logForDebugging(
          `Agent channel ignoring unknown message type: ${JSON.stringify(msg.type)}`,
        )
    }
  }

  private send(message: object): void {
    if (this.closed || this.stream.destroyed) {
      return
    }
    try {
      this.stream.write(JSON.stringify(message) + '\n')
    } catch (err) {
      logForDebugging(
        `Agent channel write failed: ${err instanceof Error ? err.message : String(err)}`,
      )
      this.close()
    }
  }
}

/**
 * Translate a SandboxViolationStore line into a `blocked` message, or
 * undefined when the agent should not be told about it.
 *
 * Violation lines come from three producers with different shapes:
 *   - the network proxy:       `deny network-outbound HOST:PORT (REASON)`
 *   - the macOS log monitor:   `PROC(PID) deny(1) file-write-data /etc/hosts`
 *   - the Linux seccomp observer: `deny SYSCALL /path` (write intents only)
 *
 * Lines whose proxy reason is `user denied` are suppressed: with the channel
 * wired as the ask callback, that deny came from the agent itself, and the
 * sandbox should not report the agent's own decision back to it as a block.
 */
export function blockedMessageFromViolation(
  line: string,
): AgentChannelBlockedMessage | undefined {
  // Proxy network deny.
  const network = line.match(/^deny network-outbound (.+):(\d+) \((.*)\)$/)
  if (network) {
    const [, host, port, reason] = network
    if (reason === 'user denied') {
      return undefined
    }
    return {
      resource: { type: 'network', host, port: Number(port) },
      operation: 'connect',
      description: `Connecting to ${host}:${port} was blocked by the sandbox (${reason})`,
    }
  }

  // Seatbelt (`deny(1) OP REST`, possibly prefixed by process name) and the
  // Linux seccomp observer (`deny SYSCALL /path`).
  const generic = line.match(/(?:^|\s)deny(?:\(\d+\))?\s+(\S+)\s+(.+)$/)
  if (generic) {
    const [, op, rest] = generic
    if (op.startsWith('file-')) {
      const operation = op.includes('write')
        ? 'write'
        : op.includes('read')
          ? 'read'
          : op
      return {
        resource: { type: 'file', path: rest },
        operation,
        description: describeFileBlock(operation, rest),
      }
    }
    if (rest.startsWith('/') && !op.includes('-')) {
      // Linux observer lines carry a bare syscall name and an absolute
      // path. The observer only reports write-intent syscalls, so 'write'
      // is the truthful generic operation; the raw line keeps the detail.
      return {
        resource: { type: 'file', path: rest },
        operation: 'write',
        description: describeFileBlock('write', rest),
      }
    }
    // Anything else the platform mediates (mach-lookup, unix sockets,
    // process-exec, ...): pass it along so the agent can still surface it,
    // per the open resource vocabulary. The description deliberately drops
    // any process-name prefix so identical denials from different processes
    // produce identical messages (which the CLI dedupes).
    return {
      resource: { type: 'unknown' },
      operation: op,
      description: `${op} ${rest}, which the sandbox policy does not allow`,
    }
  }

  // Not a shape we recognize — still worth telling the agent about.
  return {
    resource: { type: 'unknown' },
    operation: 'unknown',
    description: line,
  }
}

function describeFileBlock(operation: string, path: string): string {
  if (operation === 'write') {
    return `Writing to ${path}, which the sandbox policy does not allow`
  }
  if (operation === 'read') {
    return `Reading ${path}, which the sandbox policy does not allow`
  }
  return `${operation} on ${path}, which the sandbox policy does not allow`
}
