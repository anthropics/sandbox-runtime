import { spawn } from 'child_process'
import { text } from 'node:stream/consumers'
import { whichSync } from './which.js'

export interface RipgrepConfig {
  command: string
  args?: string[]
  /** Override argv[0] when spawning (for multicall binaries that dispatch on argv[0]) */
  argv0?: string
}

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
 * printing every match it could reach.
 */
export class RipgrepError extends Error {
  readonly partialMatches: string[]

  constructor(message: string, partialMatches: string[]) {
    super(message)
    this.partialMatches = partialMatches
  }
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

  const matches = stdout.trim().split('\n').filter(Boolean)
  if (code === 0) {
    return matches
  }
  if (code === 1) {
    // Exit code 1 means "no matches found" - this is normal
    return []
  }
  throw new RipgrepError(
    `ripgrep failed with exit code ${code}: ${stderr}`,
    matches,
  )
}
