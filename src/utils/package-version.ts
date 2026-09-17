import * as fs from 'node:fs'

let cached: string | undefined

/**
 * The version from this package's own package.json, resolved relative to
 * the built module (dist/utils/ -> package root) so it is correct for an
 * npm install, a global install, and an in-tree build alike.
 * `process.env.npm_package_version` is only set when running under an npm
 * script, which is never the case for an installed `srt` binary.
 * Returns 'unknown' rather than throwing: callers use this for diagnostics.
 */
export function getPackageVersion(): string {
  if (cached !== undefined) return cached
  try {
    const pkg = JSON.parse(
      fs.readFileSync(new URL('../../package.json', import.meta.url), 'utf-8'),
    ) as { version?: unknown }
    cached = typeof pkg.version === 'string' ? pkg.version : 'unknown'
  } catch {
    cached = 'unknown'
  }
  return cached
}
