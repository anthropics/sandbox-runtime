import { InvalidArgumentError } from 'commander'
import * as fs from 'fs'
import * as net from 'net'
import * as readline from 'readline'
import type { SandboxRuntimeConfig } from '../sandbox/sandbox-config.js'
import { loadConfigFromString } from './config-loader.js'
import { logForDebugging } from './debug.js'

/**
 * Default timeout for connecting to a Windows named pipe passed via
 * `--control-pipe`. Long enough for a busy supervisor to accept, short
 * enough that a stalled or misconfigured pipe fails fast instead of hanging.
 */
export const DEFAULT_CONTROL_PIPE_TIMEOUT_MS = 5000

const LOCAL_NAMED_PIPE_PREFIX = '\\\\.\\pipe\\'

function hasControlChar(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i)
    if (code < 0x20 || code === 0x7f) {
      return true
    }
  }
  return false
}

/**
 * Parse --control-fd: an integer descriptor number >= 3.
 */
export function parseControlFd(value: string): number {
  // Number() alone would also take '0x10', '3e0' and ' 5 '.
  if (!/^\d+$/.test(value) || Number(value) < 3) {
    throw new InvalidArgumentError(
      'must be an integer file descriptor >= 3 (0-2 are stdin, stdout and stderr).',
    )
  }
  return Number(value)
}

/**
 * Parse --control-pipe: a local Windows named pipe path (`\\.\pipe\<name>`).
 *
 * Remote UNC pipe paths (`\\server\pipe\...`), relative paths, forward
 * slashes, empty names, path traversal segments, and control characters are
 * rejected so srt never connects to a remote SMB endpoint or an ambiguous path.
 */
export function parseControlPipe(value: string): string {
  if (!value.toLowerCase().startsWith(LOCAL_NAMED_PIPE_PREFIX)) {
    throw new InvalidArgumentError(
      'must be a local Windows named pipe path (\\\\.\\pipe\\<name>).',
    )
  }

  const pipeName = value.slice(LOCAL_NAMED_PIPE_PREFIX.length)
  if (
    pipeName.length === 0 ||
    hasControlChar(pipeName) ||
    pipeName.includes('/')
  ) {
    throw new InvalidArgumentError(
      'must be a local Windows named pipe path (\\\\.\\pipe\\<name>).',
    )
  }

  const segments = pipeName.split('\\')
  if (segments.some(seg => seg === '' || seg === '.' || seg === '..')) {
    throw new InvalidArgumentError(
      'must be a local Windows named pipe path (\\\\.\\pipe\\<name>).',
    )
  }

  return `${LOCAL_NAMED_PIPE_PREFIX}${pipeName}`
}

/**
 * A readable stream over the control fd (macOS and Linux). A pipe or socket is
 * read through a libuv stream handle, driven by the event loop:
 * fs.createReadStream would park a threadpool thread in a blocking read(2)
 * that process.exit() then waits for, so srt would outlive the wrapped command
 * until the parent closed the fd. Anything else keeps the fs stream, which is
 * right for a regular file (its reads never block) and leaves a tty with the
 * old wait. Under Bun, net.Socket({ fd }) reads nothing, and Bun's fs stream
 * does not hold exit, so the fs stream serves every fd kind there.
 *
 * A libuv handle switches the fd's open file description to non-blocking
 * mode, from the moment srt opens it and for good (Node restores only fds
 * 0-2 at exit). A parent that shares that description (a shell
 * `exec 3<fifo`, a Python pass_fds of an fd it keeps using) then sees
 * EAGAIN on its own blocking reads, so hand srt a dedicated pipe end.
 */
export function openControlFd(
  fd: number,
  options?: { platform?: NodeJS.Platform },
): NodeJS.ReadableStream {
  const platform = options?.platform ?? process.platform
  if (platform === 'win32') {
    throw new Error(
      '--control-fd is not supported on Windows; use --control-pipe \\\\.\\pipe\\<name> instead',
    )
  }

  // fstat succeeds on descriptors srt can never read a byte from — one
  // opened write-only, the write end of a pipe — and a reader over those
  // fails only once the command is already running. A zero-length readv(2)
  // asks the kernel whether a read is permitted at all without performing
  // one: EBADF for those, 0 for every readable kind, on both node and bun,
  // without blocking on an empty pipe or consuming a byte of a full one.
  fs.readvSync(fd, [Buffer.alloc(0)])
  const stat = fs.fstatSync(fd)
  if (!process.versions.bun && (stat.isFIFO() || stat.isSocket())) {
    try {
      return new net.Socket({ fd, readable: true, writable: false }).unref()
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code
      if (code !== 'ERR_INVALID_FD_TYPE') {
        // ERR_INVALID_FD_TYPE is the only refusal that leaves the fd
        // untouched (a datagram or seqpacket socket, which the fs stream
        // still reads, one read(2) per datagram). Every other failure comes
        // out of uv_pipe_open, which has already switched the fd to
        // non-blocking mode: an fs stream over it would read EAGAIN
        // forever, so no fallback is left to take.
        throw new Error(
          `could not be adopted as a stream (${code ?? String(err)})`,
        )
      }
      logForDebugging(
        `Control fd ${fd} is not a stream socket (${err instanceof Error ? err.message : String(err)}); reading it through fs`,
      )
    }
  }
  return fs.createReadStream('', { fd })
}

/**
 * Connect to a Windows named pipe created by the supervisor (`--control-pipe`).
 *
 * The returned socket is paused and unref'd upon connection:
 * - Pausing buffers any initial updates written by the supervisor while
 *   `SandboxManager.initialize()` is still running so they are delivered once
 *   the reader attaches rather than lost or overwritten.
 * - Unref'ing ensures srt exits with the wrapped command without waiting for
 *   the supervisor to close the pipe.
 */
export function openControlPipe(
  pipePath: string,
  options?: { timeoutMs?: number; platform?: NodeJS.Platform },
): Promise<net.Socket> {
  const platform = options?.platform ?? process.platform
  if (platform !== 'win32') {
    return Promise.reject(
      new Error(
        '--control-pipe is only supported on Windows; use --control-fd on macOS and Linux',
      ),
    )
  }

  const timeoutMs = options?.timeoutMs ?? DEFAULT_CONTROL_PIPE_TIMEOUT_MS

  return new Promise((resolve, reject) => {
    const socket = net.connect({ path: pipePath })
    let settled = false

    const timer = setTimeout(() => {
      if (settled) {
        return
      }
      settled = true
      socket.removeListener('connect', onConnect)
      socket.removeListener('error', onError)
      socket.destroy()
      reject(
        new Error(
          `timed out after ${timeoutMs}ms waiting to connect to ${pipePath}`,
        ),
      )
    }, timeoutMs)
    timer.unref()

    function onConnect(): void {
      if (settled) {
        return
      }
      settled = true
      clearTimeout(timer)
      socket.removeListener('error', onError)
      socket.pause()
      socket.unref()
      resolve(socket)
    }

    function onError(err: Error): void {
      if (settled) {
        return
      }
      settled = true
      clearTimeout(timer)
      socket.removeListener('connect', onConnect)
      socket.destroy()
      reject(err)
    }

    socket.once('connect', onConnect)
    socket.once('error', onError)
  })
}

export interface ControlChannelCallbacks {
  onConfig: (config: SandboxRuntimeConfig) => void
  onInvalidLine?: (line: string) => void
  onFatalError: (err: Error) => void
  onPostUpdateError?: (err: Error) => void
}

export interface ControlChannelController {
  /** Begin reading newline-delimited JSON updates from the opened stream. */
  startReading(): void
  /** True once a pre-update stream error triggered fail-closed teardown. */
  readonly failed: boolean
  /** True once at least one line (valid, invalid, or blank) was read. */
  readonly receivedAnyLine: boolean
  /** Close the line reader and destroy the underlying stream if supported. */
  close(): void
}

/**
 * Attach fail-closed error handling immediately to an opened control stream,
 * then start consuming newline-delimited JSON config updates when
 * `startReading()` is called (after `SandboxManager.initialize()`).
 */
export function createControlChannel(
  stream: NodeJS.ReadableStream,
  callbacks: ControlChannelCallbacks,
): ControlChannelController {
  let receivedAnyLine = false
  let errorReported = false
  let failed = false
  let closed = false
  let reader: readline.Interface | null = null

  function handleError(err: Error): void {
    // Attached both to the stream and to the reader: the stream is live from
    // the moment the fd or pipe is opened, which is before the reader exists,
    // and readline re-emits an input error on the reader as well. The channel
    // is gone after the first error either way, so it is reported once.
    if (closed || errorReported) {
      return
    }
    errorReported = true
    if (receivedAnyLine) {
      // The channel did deliver. The config last applied stays in force, so
      // the command keeps running under it.
      callbacks.onPostUpdateError?.(err)
      return
    }
    // Nothing ever came through: fail closed rather than running the command
    // without the control channel the caller asked for.
    failed = true
    callbacks.onFatalError(err)
  }

  stream.on('error', handleError)

  return {
    get failed(): boolean {
      return failed
    },
    get receivedAnyLine(): boolean {
      return receivedAnyLine
    },
    startReading(): void {
      if (closed || reader !== null) {
        return
      }
      reader = readline.createInterface({
        input: stream,
        crlfDelay: Infinity,
      })
      reader.on('line', line => {
        receivedAnyLine = true
        const newConfig = loadConfigFromString(line)
        if (newConfig) {
          callbacks.onConfig(newConfig)
        } else if (line.trim()) {
          callbacks.onInvalidLine?.(line)
        }
      })
      reader.on('error', handleError)
      // Explicitly resume streams that were paused upon connection (e.g.
      // Windows named pipes) so lines buffered during initialize() drain now.
      stream.resume()
    },
    close(): void {
      if (closed) {
        return
      }
      closed = true
      reader?.close()
      reader = null
      stream.removeListener('error', handleError)
      if ('destroy' in stream && typeof stream.destroy === 'function') {
        // Attach a no-op listener before destroying so late teardown errors
        // cannot surface as uncaught exceptions during process exit.
        stream.on('error', () => {})
        ;(stream as { destroy: () => void }).destroy()
      }
    },
  }
}
