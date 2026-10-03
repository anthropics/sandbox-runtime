import { spawnSync } from 'node:child_process'
import { accessSync, constants } from 'node:fs'
import path from 'node:path'

function isPathQualified(bin: string): boolean {
  return path.isAbsolute(bin) || bin.includes('/') || bin.includes('\\')
}

function resolvePathQualified(bin: string): string | null {
  try {
    accessSync(bin, constants.X_OK)
    return bin
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code
    if (code === 'ENOENT') {
      return null
    }
    throw new Error(
      `Failed to resolve executable '${bin}'${code ? `: ${code}` : ''}`,
    )
  }
}

/**
 * Find the path to an executable, similar to the `which` command.
 * Uses Bun.which when running in Bun, falls back to spawnSync for Node.js.
 *
 * Path-qualified names (absolute or containing a separator) skip `which`.
 * Node fallback timeouts and permission errors throw instead of returning null.
 *
 * @param bin - The name of the executable to find
 * @returns The full path to the executable, or null if not found
 */
export function whichSync(bin: string): string | null {
  if (isPathQualified(bin)) {
    return resolvePathQualified(bin)
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

  if (result.error) {
    const code = (result.error as NodeJS.ErrnoException).code
    if (code === 'ETIMEDOUT' || result.signal) {
      throw new Error(`Timed out resolving executable '${bin}' in PATH`)
    }
    if (code === 'EACCES') {
      throw new Error(`Permission denied resolving executable '${bin}'`)
    }
    return null
  }

  if (result.status === 0 && result.stdout) {
    return result.stdout.trim()
  }

  return null
}
