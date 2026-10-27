import * as fs from 'node:fs'
import * as path from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  isAtOrUnder,
  normalizePathForSandbox,
  pathSpellings,
} from './sandbox-utils.js'

/**
 * A warning when a sandboxed command could rewrite this copy of the library:
 * the host side runs unsandboxed, so whoever may write
 * `<project>/node_modules/` decides what the next run there executes.
 *
 * That is when the package directory holding `moduleFile` lies at or under one
 * of `allowedWritePaths`, as spelled or where it really is. Undefined
 * otherwise, and for a copy not under a `node_modules` (a checkout, which is
 * the project being worked on) or with no manifest on disk (compiled into an
 * application). An allowed write path that is a pattern is not judged.
 */
export function ownInstallWarning(
  allowedWritePaths: readonly string[],
  moduleFile: string = fileURLToPath(import.meta.url),
): string | undefined {
  let root = path.dirname(moduleFile)
  while (!fs.existsSync(path.join(root, 'package.json'))) {
    if (root === path.dirname(root)) return undefined
    root = path.dirname(root)
  }
  if (!root.split(path.sep).includes('node_modules')) return undefined

  const writable = allowedWritePaths.flatMap(allowed =>
    pathSpellings(normalizePathForSandbox(allowed)),
  )
  const covered = pathSpellings(root).some(form =>
    writable.some(allowed => isAtOrUnder(form, allowed)),
  )
  return covered
    ? `sandbox-runtime is installed in ${root}, where a sandboxed command ` +
        `can write it - install it outside the allowed write paths`
    : undefined
}
