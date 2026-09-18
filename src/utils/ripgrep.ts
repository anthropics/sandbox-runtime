import { spawn } from 'child_process'
import { text } from 'node:stream/consumers'
import { whichSync } from './which.js'

export interface RipgrepConfig {
  command: string
  args?: string[]
  /** Override argv[0] when spawning (for multicall binaries that dispatch on argv[0]) */
  argv0?: string
  /**
   * How long the run may take before it is killed (default:
   * {@link DEFAULT_RIPGREP_TIMEOUT_MS}).
   */
  timeoutMs?: number
}

export const DEFAULT_RIPGREP_TIMEOUT_MS = 10_000

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
 * `timedOut` says the run lasted as long as it was given and was killed for
 * it, so what it listed is a prefix of an unknown whole rather than
 * everything it could reach. A run killed by anything else says so in its
 * message and is not a timeout.
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

  const startedAt = Date.now()
  const child = spawn(
    // --no-config: RIPGREP_CONFIG_PATH routinely points inside a project, at
    // a file a sandboxed command can write, and one line of it
    // (--max-filesize=1) is enough to make a scan return nothing at all and
    // no error with it.
    command,
    [...commandArgs, '--no-config', '--null', ...args, target],
    {
      argv0,
      signal: abortSignal,
      timeout: timeoutMs,
      windowsHide: true,
    },
  )

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
  // A null exit code means the child was killed rather than exiting. The
  // timeout is one reason for that and not the only one — a Ctrl-C to the
  // process group, an OOM kill — so it is the one this claims only where the
  // run actually lasted as long as it was given. The rest are reported as
  // what they were; upstream refuses either way, with an accurate message.
  const killed = exit.code === null
  const elapsedMs = Date.now() - startedAt
  const timedOut = killed && elapsedMs >= timeoutMs
  const killedBy = exit.signal ?? 'a signal'
  const failure = timedOut
    ? `ripgrep was killed by ${killedBy} after ${elapsedMs} ms, the ${timeoutMs} ms it was given`
    : killed
      ? `ripgrep was killed by ${killedBy} after ${elapsedMs} ms, inside the ${timeoutMs} ms it was given`
      : `ripgrep failed with exit code ${exit.code}`
  throw new RipgrepError(`${failure}: ${stderr}`, matches, stderr, timedOut)
}

/** NUL-terminated records, dropping an unterminated (truncated) last one. */
function splitNullDelimited(output: string): string[] {
  const records = output.split('\0')
  // A complete run ends with a terminator, so the tail is empty; anything
  // else is a record the run was cut off in the middle of.
  records.pop()
  return records.filter(Boolean)
}
