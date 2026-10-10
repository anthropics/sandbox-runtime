import { spawnSync } from 'node:child_process'
import { accessSync, constants as fsConstants } from 'node:fs'
import { isAbsolute } from 'node:path'

/**
 * Find the path to an executable, similar to the `which` command.
 * Uses Bun.which when running in Bun, falls back to spawnSync for Node.js.
 *
 * @param bin - The name of the executable to find
 * @returns The full path to the executable, or null if not found
 */
export function whichSync(bin: string): string | null {
  // A caller-supplied absolute path is already resolved. Avoid invoking an
  // external `which` process, which can time out or be unavailable in a
  // restricted environment, and verify the path can actually be executed.
  if (isAbsolute(bin)) {
    try {
      accessSync(bin, fsConstants.X_OK)
      return bin
    } catch {
      return null
    }
  }

  // Check if we're running in Bun
  if (typeof globalThis.Bun !== 'undefined') {
    return globalThis.Bun.which(bin)
  }

  // Fallback to Node.js implementation
  const result = spawnSync('which', [bin], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'ignore'],
    timeout: 1000,
  })

  if (result.status === 0 && result.stdout) {
    return result.stdout.trim()
  }

  return null
}
