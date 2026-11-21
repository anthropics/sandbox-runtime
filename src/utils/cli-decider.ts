import { InvalidArgumentError } from 'commander'
import * as fs from 'fs'
import type { Readable, Writable } from 'node:stream'
import {
  createDecider,
  type Decider,
  type DeciderHello,
} from '../sandbox/decider-client.js'
import {
  DEFAULT_CREDENTIAL_PLACEMENTS,
  openFdStreams,
} from '../sandbox/proxy-only.js'
import type { FilterRequestCallback } from '../sandbox/request-filter.js'
import type { SandboxRuntimeConfig } from '../sandbox/sandbox-config.js'

/**
 * Default per-verdict timeout (ms) for an external decider attached via CLI,
 * matching `createDecider` in `src/sandbox/decider-client.ts`.
 */
export const DEFAULT_DECIDER_TIMEOUT_MS = 5000

const MAX_DECIDER_TIMEOUT_MS = 600_000

/**
 * Parse an inherited descriptor option (`--control-fd`, `--decider-fd`,
 * `--decider-in`, `--decider-out`): an integer >= 3.
 */
export function parseInheritedFd(value: string): number {
  // Number() alone would also take '0x10', '3e0' and ' 5 '.
  if (!/^\d+$/.test(value) || Number(value) < 3) {
    throw new InvalidArgumentError(
      'must be an integer file descriptor >= 3 (0-2 are stdin, stdout and stderr).',
    )
  }
  return Number(value)
}

/**
 * Parse `--decider-timeout-ms`: an integer in 1..600000 ms.
 */
export function parseDeciderTimeoutMs(value: string): number {
  if (!/^\d+$/.test(value)) {
    throw new InvalidArgumentError(
      `must be an integer between 1 and ${MAX_DECIDER_TIMEOUT_MS}.`,
    )
  }
  const ms = Number(value)
  if (!Number.isSafeInteger(ms) || ms < 1 || ms > MAX_DECIDER_TIMEOUT_MS) {
    throw new InvalidArgumentError(
      `must be an integer between 1 and ${MAX_DECIDER_TIMEOUT_MS}.`,
    )
  }
  return ms
}

export interface CliDeciderFlagInput {
  deciderFd?: number
  deciderIn?: number
  deciderOut?: number
  deciderTimeoutMs?: number
  controlFd?: number
}

export interface ResolvedCliDeciderSpec {
  inFd: number
  outFd: number
  fds: readonly number[]
  timeoutMs: number
}

/**
 * Validate and normalize `--decider-fd` / `--decider-in` / `--decider-out` /
 * `--decider-timeout-ms` CLI options. Returns `undefined` when no decider flag
 * was passed; throws on invalid combinations, descriptor collisions with
 * `--control-fd`, or unsupported platforms.
 */
export function resolveCliDeciderSpec(
  input: CliDeciderFlagInput,
  platform: NodeJS.Platform = process.platform,
): ResolvedCliDeciderSpec | undefined {
  const { deciderFd, deciderIn, deciderOut, deciderTimeoutMs, controlFd } =
    input
  const hasAny =
    deciderFd !== undefined ||
    deciderIn !== undefined ||
    deciderOut !== undefined

  if (!hasAny) {
    if (deciderTimeoutMs !== undefined) {
      throw new Error(
        '--decider-timeout-ms requires --decider-fd or --decider-in/--decider-out.',
      )
    }
    return undefined
  }

  if (
    deciderFd !== undefined &&
    (deciderIn !== undefined || deciderOut !== undefined)
  ) {
    throw new Error(
      '--decider-fd cannot be combined with --decider-in or --decider-out.',
    )
  }

  if ((deciderIn !== undefined) !== (deciderOut !== undefined)) {
    throw new Error('--decider-in and --decider-out must be provided together.')
  }

  if (
    deciderIn !== undefined &&
    deciderOut !== undefined &&
    deciderIn === deciderOut
  ) {
    throw new Error(
      '--decider-in and --decider-out must be distinct file descriptors; use --decider-fd for a bidirectional socket.',
    )
  }

  const inFd = deciderFd ?? deciderIn!
  const outFd = deciderFd ?? deciderOut!
  const fds = inFd === outFd ? [inFd] : [inFd, outFd]

  if (controlFd !== undefined && fds.includes(controlFd)) {
    throw new Error(
      '--control-fd cannot share a file descriptor with --decider-fd, --decider-in, or --decider-out.',
    )
  }

  if (platform === 'win32') {
    throw new Error(
      '--decider-fd / --decider-in / --decider-out use inherited POSIX file descriptors and are not supported on Windows.',
    )
  }

  return {
    inFd,
    outFd,
    fds,
    timeoutMs: deciderTimeoutMs ?? DEFAULT_DECIDER_TIMEOUT_MS,
  }
}

/**
 * stdio for the sandboxed command: the three standard streams, plus
 * `/dev/null` over every inherited control or decider descriptor slot (>= 3),
 * so nothing inside the sandbox can read policy updates or spoof verdicts.
 *
 * The displacement is what matters on Linux. On macOS libuv spawns through
 * posix_spawn with POSIX_SPAWN_CLOEXEC_DEFAULT, which already keeps every
 * descriptor the caller did not list out of the child.
 */
export function buildSandboxedStdio(
  displacedFds: readonly number[],
  openNull: () => number = () => fs.openSync('/dev/null', 'r'),
): Array<'inherit' | 'ignore' | number> {
  const stdio: Array<'inherit' | 'ignore' | number> = [
    'inherit',
    'inherit',
    'inherit',
  ]
  const uniqueFds = [...new Set(displacedFds.filter(fd => fd >= 3))].sort(
    (a, b) => a - b,
  )
  if (uniqueFds.length === 0) {
    return stdio
  }
  const displacedSet = new Set(uniqueFds)
  const maxFd = uniqueFds[uniqueFds.length - 1]
  // 'ignore' past fd 2 leaves a slot as it is rather than closing it, so each
  // inherited channel slot needs a descriptor of its own to displace it with.
  // Only close-on-exec keeps an inherited descriptor out of an exec'd command,
  // and uv_disable_stdio_inheritance() stops at the first closed number above
  // 15, so `--decider-fd 20` with 16-19 closed would otherwise leave the
  // channel live in the sandbox.
  for (let fd = 3; fd <= maxFd; fd++) {
    stdio.push(displacedSet.has(fd) ? openNull() : 'ignore')
  }
  return stdio
}

/**
 * Assert that a `SandboxRuntimeConfig` does not conflict with an external
 * decider before opening descriptors or awaiting the decider's `hello`:
 *
 * - `network.httpProxyPort` is refused: SRT skips starting its own HTTP proxy
 *   when an external proxy port is configured, so the decider would never be
 *   consulted.
 * - `network.allowedDomains` in `--settings` must be empty when an external
 *   decider is attached, so the decider's `hello.allowedDomains` is the single
 *   allowlist source and neither source silently widens or drops the other.
 */
export function assertDeciderCompatibleConfig(
  config: SandboxRuntimeConfig,
): void {
  if (config.network.httpProxyPort !== undefined) {
    throw new Error(
      'network.httpProxyPort cannot be combined with an external decider: SRT does not start its own HTTP proxy when httpProxyPort is set.',
    )
  }
  if (config.network.allowedDomains.length > 0) {
    throw new Error(
      'network.allowedDomains in settings must be empty when using an external decider; the decider supplies allowedDomains in its hello frame.',
    )
  }
}

/**
 * Merge a decider's `hello` egress lists and `filterRequest` callback into a
 * `SandboxRuntimeConfig`, failing closed on policy conflicts.
 * `network.deniedDomains` from `--settings` and `hello.deniedDomains` are
 * unioned (monotonic fail-closed: a domain denied by either stays denied).
 */
export function applyDeciderHelloToConfig(
  config: SandboxRuntimeConfig,
  hello: DeciderHello,
  filterRequest: FilterRequestCallback,
): SandboxRuntimeConfig {
  assertDeciderCompatibleConfig(config)

  const deniedDomains = Array.from(
    new Set([...config.network.deniedDomains, ...hello.deniedDomains]),
  )

  return {
    ...config,
    network: {
      ...config.network,
      allowedDomains: [...hello.allowedDomains],
      deniedDomains,
      filterRequest,
    },
  }
}

/**
 * Validate and open the inherited decider descriptor(s) into Node/Bun streams.
 */
export function openDeciderFdStreams(spec: ResolvedCliDeciderSpec): {
  input: Readable
  output: Writable
} {
  // Ask the kernel whether the descriptor(s) are open (and readable for the
  // input end) before handing them to libuv/Bun so closed/write-only fds fail
  // fast with a clear message before SandboxManager.initialize() runs.
  fs.readvSync(spec.inFd, [Buffer.alloc(0)])
  fs.fstatSync(spec.inFd)
  if (spec.outFd !== spec.inFd) {
    fs.fstatSync(spec.outFd)
    return {
      input: openFdStreams(spec.inFd).input,
      output: openFdStreams(spec.outFd).output,
    }
  }
  return openFdStreams(spec.inFd)
}

/**
 * Connect to an external decider over the given streams and await its v1
 * `hello` handshake fail-closed. `onDead` only fires for disconnects/protocol
 * violations *after* the initial hello has succeeded; pre-hello failures
 * reject the returned promise directly.
 */
export async function connectCliDecider(options: {
  streams: { input: Readable; output: Writable }
  timeoutMs?: number
  onDead?: (why: string) => void
}): Promise<{ decider: Decider; hello: DeciderHello }> {
  let ready = false
  let closedByCaller = false
  const rawDecider = createDecider({
    input: options.streams.input,
    output: options.streams.output,
    timeoutMs: options.timeoutMs ?? DEFAULT_DECIDER_TIMEOUT_MS,
    credentialPlacements: DEFAULT_CREDENTIAL_PLACEMENTS,
    onDead: why => {
      if (ready && !closedByCaller) {
        options.onDead?.(why)
      }
    },
  })

  const decider: Decider = {
    hello: rawDecider.hello,
    filterRequest: rawDecider.filterRequest,
    bodyBytesHeld: rawDecider.bodyBytesHeld,
    close: () => {
      closedByCaller = true
      rawDecider.close()
    },
  }

  try {
    const hello = await decider.hello
    ready = true
    return { decider, hello }
  } catch (err) {
    decider.close()
    throw err
  }
}
