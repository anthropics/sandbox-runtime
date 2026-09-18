import { spawn } from 'child_process'
import { text } from 'node:stream/consumers'
import { whichSync } from './which.js'

export interface RipgrepConfig {
  command: string
  args?: string[]
  /** Override argv[0] when spawning (for multicall binaries that dispatch on argv[0]) */
  argv0?: string
  /** How long the run may take before it is killed (default: 10 s). */
  timeoutMs?: number
}

const DEFAULT_RIPGREP_TIMEOUT_MS = 10_000

/**
 * Check if ripgrep (rg) is available synchronously
 * Returns true if rg is installed, false otherwise
 */
export function hasRipgrepSync(): boolean {
  return whichSync('rg') !== null
}

/**
 * ripgrep exited with an error status. `partialMatches` is what it listed
 * before that: rg reports an unreadable directory with exit code 2 after
 * printing every match it could reach, and names each one in `stderr`.
 * `timedOut` says the run was killed instead of finishing, so what it listed
 * is a prefix of an unknown whole rather than everything it could reach.
 */
export class RipgrepError extends Error {
  readonly partialMatches: string[]
  readonly stderr: string
  readonly timedOut: boolean

  constructor(
    message: string,
    partialMatches: string[],
    stderr: string,
    timedOut: boolean,
  ) {
    super(message)
    this.partialMatches = partialMatches
    this.stderr = stderr
    this.timedOut = timedOut
  }
}

/**
 * Execute ripgrep with the given arguments.
 *
 * The run is `--null`-delimited: a path may contain a newline, and a run cut
 * short by the timeout can end mid-path, so line splitting would turn one
 * path into two and hand back a truncated one. Output is split on NUL and an
 * unterminated tail is dropped.
 *
 * @param args Command-line arguments to pass to rg
 * @param target Target directory or file to search
 * @param abortSignal AbortSignal to cancel the operation
 * @param config Ripgrep configuration (command and optional args)
 * @returns Array of matching paths
 * @throws RipgrepError if ripgrep exits with non-zero status (except exit code 1 which means no matches)
 */
export async function ripGrep(
  args: string[],
  target: string,
  abortSignal: AbortSignal,
  config: RipgrepConfig = { command: 'rg' },
): Promise<string[]> {
  const {
    command,
    args: commandArgs = [],
    argv0,
    timeoutMs = DEFAULT_RIPGREP_TIMEOUT_MS,
  } = config

  const child = spawn(command, [...commandArgs, '--null', ...args, target], {
    argv0,
    signal: abortSignal,
    timeout: timeoutMs,
    windowsHide: true,
  })

  const [stdout, stderr, exit] = await Promise.all([
    text(child.stdout),
    text(child.stderr),
    new Promise<{ code: number | null; signal: NodeJS.Signals | null }>(
      (resolve, reject) => {
        child.on('close', (code, signal) => resolve({ code, signal }))
        child.on('error', reject)
      },
    ),
  ])

  const matches = splitNullDelimited(stdout)
  if (exit.code === 0) {
    return matches
  }
  if (exit.code === 1) {
    // Exit code 1 means "no matches found" - this is normal
    return []
  }
  // A null exit code means the child was killed rather than exiting. An
  // abort rejects through the error handler above, so here it is the timeout.
  const timedOut = exit.code === null
  throw new RipgrepError(
    timedOut
      ? `ripgrep was killed by ${exit.signal ?? 'a signal'} after ${timeoutMs} ms: ${stderr}`
      : `ripgrep failed with exit code ${exit.code}: ${stderr}`,
    matches,
    stderr,
    timedOut,
  )
}

/** NUL-terminated records, dropping an unterminated (truncated) last one. */
function splitNullDelimited(output: string): string[] {
  const records = output.split('\0')
  // A complete run ends with a terminator, so the tail is empty; anything
  // else is a record the run was cut off in the middle of.
  records.pop()
  return records.filter(Boolean)
}
