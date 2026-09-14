import { spawn as nodeSpawn } from 'node:child_process'
import { logForDebugging } from '../utils/debug.js'
import type { SandboxViolationEvent } from './macos-sandbox-utils.js'
import { sanitizeViolationText } from './sandbox-violation-store.js'

/**
 * Forward sandbox violations to the host's system log via `logger(1)`.
 *
 * The seatbelt kernel already writes every macOS deny to the unified log, so
 * `log stream --predicate 'eventMessage ENDSWITH "_SBX"'` shows filesystem
 * and mach-lookup violations without any help from srt. Proxy denials (both
 * platforms) and seccomp denials (Linux) are decided in the srt process and
 * have no native log line: without this sink the only signals are a 403 in
 * the sandboxed client and, when the embedder surfaces the store, a
 * <sandbox_violations> block. Users watching the log stream to work out why
 * a tool failed see nothing.
 *
 * stderr is deliberately not used. The srt host shares a terminal with the
 * sandboxed child and any host stderr output corrupts TUI rendering (Claude
 * Code being the primary embedder). `logger` is spawned detached with stdio
 * ignored, so nothing reaches the terminal.
 *
 * Message shape (one physical line, bounded length):
 *
 *   srt proxy deny network-outbound api.example.com:443 (host is not on the allow list) cmd="curl https://api.example.com" _SBX
 *
 * On macOS the trailing ` _SBX` token lets the message land in the same
 * `ENDSWITH "_SBX"` stream as the kernel's seatbelt lines. It cannot feed
 * back into the srt log monitor: that monitor's predicate ends with the
 * per-session `_<random>_SBX` suffix, and the space before `_SBX` here
 * guarantees no such match. On Linux the token is omitted (syslog / journald
 * have no equivalent convention).
 */

/** Minimal surface of a spawned child that the sink relies on. */
export interface SpawnedLogger {
  on(event: 'error', listener: (err: Error) => void): unknown
  on(event: 'exit', listener: () => void): unknown
  unref(): void
}

export type LoggerSpawner = (command: string, args: string[]) => SpawnedLogger

export interface SystemLogOptions {
  /** `process.platform` unless overridden by tests. */
  platform?: NodeJS.Platform
  /** Spawner for the `logger` binary; injected by tests. */
  spawn?: LoggerSpawner
}

export interface SystemLogViolationSinkOptions extends SystemLogOptions {
  /**
   * Upper bound on concurrently running `logger` processes. A burst of
   * denials (a tool retrying a blocked host in a tight loop) must not fork a
   * process per event without limit; events beyond the cap are dropped and
   * counted rather than queued.
   */
  maxInFlight?: number
}

export interface SystemLogViolationSink {
  /** Receive one violation. Never throws, never writes to stdio. */
  handle(event: SandboxViolationEvent): void
  /** Number of events dropped because the in-flight cap was reached. */
  readonly dropped: number
  /** Number of events handed to `logger`. */
  readonly written: number
}

/** Tag recognised by the `ENDSWITH "_SBX"` predicate used for macOS seatbelt lines. */
const MACOS_TAG = '_SBX'
/** Syslog implementations traditionally cap a message near 1024 bytes. */
const MAX_MESSAGE_CHARS = 1000
const MAX_COMMAND_CHARS = 200
const DEFAULT_MAX_IN_FLIGHT = 16

const defaultSpawn: LoggerSpawner = (command, args) =>
  nodeSpawn(command, args, { detached: true, stdio: 'ignore' })

/**
 * Producers whose denials the kernel already writes to the system log. The
 * sink skips these so the log stream does not show every macOS deny twice.
 */
const NATIVELY_LOGGED_SOURCES = new Set<SandboxViolationEvent['source']>([
  'seatbelt',
])

/** Platforms with a `logger(1)` this module knows how to drive. */
export function systemLogSupported(platform: NodeJS.Platform): boolean {
  return platform === 'darwin' || platform === 'linux'
}

/**
 * Append the macOS `_SBX` tag (space-separated, see the module comment) and
 * bound the line so it survives traditional syslog limits. Exported for
 * tests.
 */
export function tagSystemLogMessage(
  message: string,
  platform: NodeJS.Platform,
): string {
  const suffix = platform === 'darwin' ? ` ${MACOS_TAG}` : ''
  const budget = MAX_MESSAGE_CHARS - suffix.length
  let body = sanitizeViolationText(message)
  if (body.length > budget) {
    body = `${body.slice(0, budget - 3)}...`
  }
  return body + suffix
}

/**
 * Format one violation as a single bounded line for `logger`.
 * Exported for tests; `line` is expected to be store-sanitized already, the
 * command text is sanitized and truncated here.
 */
export function formatSystemLogMessage(
  event: SandboxViolationEvent,
  platform: NodeJS.Platform,
): string {
  const source = event.source ?? 'sandbox'
  let message = `srt ${source} ${sanitizeViolationText(event.line)}`
  if (event.command) {
    let cmd = sanitizeViolationText(event.command).replace(/"/g, "'")
    if (cmd.length > MAX_COMMAND_CHARS) {
      cmd = `${cmd.slice(0, MAX_COMMAND_CHARS - 3)}...`
    }
    message += ` cmd="${cmd}"`
  }
  return tagSystemLogMessage(message, platform)
}

/**
 * Hand one already-tagged line to `logger -t srt`, detached, with stdio
 * ignored. Returns the child so callers can track its lifetime, or
 * `undefined` when the platform has no `logger(1)`. A synchronous spawn
 * failure is reported via `onError` rather than thrown; asynchronous child
 * errors (typically ENOENT) reach the same callback.
 */
export function writeSystemLogLine(
  message: string,
  options: SystemLogOptions & { onError?: (err: Error) => void } = {},
): SpawnedLogger | undefined {
  const platform = options.platform ?? process.platform
  if (!systemLogSupported(platform)) return undefined
  const spawn = options.spawn ?? defaultSpawn
  let child: SpawnedLogger
  try {
    child = spawn('logger', ['-t', 'srt', message])
  } catch (err) {
    options.onError?.(err instanceof Error ? err : new Error(String(err)))
    return undefined
  }
  child.on('error', (err: Error) => options.onError?.(err))
  child.unref()
  return child
}

/**
 * Create a sink, or `undefined` on platforms without `logger(1)` (Windows).
 * The returned `handle` is suitable for `SandboxViolationStore.onViolation`.
 */
export function createSystemLogViolationSink(
  options: SystemLogViolationSinkOptions = {},
): SystemLogViolationSink | undefined {
  const platform = options.platform ?? process.platform
  if (!systemLogSupported(platform)) {
    logForDebugging(
      `[Sandbox System Log] not supported on ${platform}; violations will not be forwarded`,
      { level: 'warn' },
    )
    return undefined
  }
  const spawn = options.spawn ?? defaultSpawn
  const maxInFlight = options.maxInFlight ?? DEFAULT_MAX_IN_FLIGHT

  let inFlight = 0
  let dropped = 0
  let written = 0
  // Set after the first spawn failure (typically ENOENT: no `logger` on
  // PATH). Every later event would fail the same way, so stop trying rather
  // than fork-and-fail per denial.
  let disabled = false

  const handle = (event: SandboxViolationEvent): void => {
    if (disabled) return
    if (NATIVELY_LOGGED_SOURCES.has(event.source)) return
    if (inFlight >= maxInFlight) {
      dropped++
      logForDebugging(
        `[Sandbox System Log] dropped violation (in-flight cap ${maxInFlight} reached)`,
        { level: 'warn' },
      )
      return
    }
    let settled = false
    const settle = (): void => {
      if (settled) return
      settled = true
      inFlight--
    }
    const child = writeSystemLogLine(formatSystemLogMessage(event, platform), {
      platform,
      spawn,
      onError: err => {
        settle()
        disabled = true
        logForDebugging(
          `[Sandbox System Log] logger failed, disabling: ${err.message}`,
          { level: 'error' },
        )
      },
    })
    if (!child) return
    inFlight++
    written++
    child.on('exit', settle)
  }

  return {
    handle,
    get dropped() {
      return dropped
    },
    get written() {
      return written
    },
  }
}
