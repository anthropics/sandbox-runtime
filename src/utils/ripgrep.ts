import { spawn } from 'child_process'
import { text } from 'node:stream/consumers'

export interface RipgrepConfig {
  command: string
  args?: string[]
  /** Override argv[0] when spawning (for multicall binaries that dispatch on argv[0]) */
  argv0?: string
}

/**
 * Execute ripgrep with the given arguments
 * @param args Command-line arguments to pass to rg
 * @param target Target directory or file to search
 * @param abortSignal AbortSignal to cancel the operation
 * @param config Ripgrep configuration (command and optional args)
 * @returns Array of matching lines (one per line of output)
 * @throws RipgrepError if ripgrep exits with non-zero status (except exit code 1 which means no matches)
 */
export async function ripGrep(
  args: string[],
  target: string,
  abortSignal: AbortSignal,
  config: RipgrepConfig = { command: 'rg' },
): Promise<string[]> {
  const { command, args: commandArgs = [], argv0 } = config

  const child = spawn(command, [...commandArgs, ...args, target], {
    argv0,
    signal: abortSignal,
    timeout: 10_000,
    windowsHide: true,
  })

  const [stdout, stderr, code] = await Promise.all([
    text(child.stdout),
    text(child.stderr),
    new Promise<number | null>((resolve, reject) => {
      child.on('close', resolve)
      child.on('error', reject)
    }),
  ])

  if (code === 0) {
    return stdout.trim().split('\n').filter(Boolean)
  }
  if (code === 1) {
    // Exit code 1 means "no matches found" - this is normal
    return []
  }
  // Whole lines only: killed, it can leave half of one.
  throw new RipgrepError(
    `ripgrep failed with exit code ${code}: ${stderr}`,
    stdout.split('\n').slice(0, -1).filter(Boolean),
    stderr,
  )
}

/** ripgrep ended otherwise than by finding something or nothing. */
export class RipgrepError extends Error {
  constructor(
    message: string,
    /** What it had listed by then. */
    readonly listed: string[],
    /** What it said went wrong. The paths in it are the tree's own text. */
    readonly stderr: string,
  ) {
    super(message)
    this.name = 'RipgrepError'
  }
}
