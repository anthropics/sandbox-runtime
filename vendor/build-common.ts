import { spawnSync } from 'node:child_process'
import { mkdirSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const nodeArchToDir: Record<string, string> = {
  x64: 'x64',
  arm64: 'arm64',
  ppc64: 'ppc64le', // Node.js reports 'ppc64' on ppc64le Linux; our BPF is LE-only
}

/**
 * Common preamble for `vendor/<helper>/build.ts` scripts: platform
 * guard, arch resolution, derive `SRC` (sibling source dir under
 * `vendor/`) and `OUT` (per-arch output dir next to the build script),
 * and create `OUT`. Exits the process on a guard failure.
 */
export function setup(opts: {
  /** `import.meta.url` of the calling build script. */
  importMetaUrl: string
  /** Only run on this platform; bail with a clear error otherwise. */
  requirePlatform: NodeJS.Platform
  /** Sibling directory under `vendor/` holding the source to build. */
  srcDirName: string
}): { SRC: string; OUT: string; arch: string } {
  if (process.platform !== opts.requirePlatform) {
    console.error(
      `${opts.srcDirName} build: ${opts.requirePlatform} only ` +
        `(running on ${process.platform})`,
    )
    process.exit(1)
  }
  const arch = nodeArchToDir[process.arch]
  if (!arch) {
    console.error(`${opts.srcDirName} build: unsupported arch ${process.arch}`)
    process.exit(1)
  }
  const here = dirname(fileURLToPath(opts.importMetaUrl))
  const SRC = join(here, '..', opts.srcDirName)
  const OUT = join(here, arch)
  mkdirSync(OUT, { recursive: true })
  return { SRC, OUT, arch }
}

/**
 * Spawn `argv` synchronously with inherited stdio. Exits the process
 * on spawn failure (`r.error`) or non-zero exit / signal termination.
 */
export function run(argv: string[]): void {
  const [cmd, ...args] = argv
  const r = spawnSync(cmd, args, { stdio: 'inherit' })
  if (r.error) {
    console.error(`${argv.join(' ')} failed to spawn: ${r.error.message}`)
    process.exit(1)
  }
  if (r.status !== 0) {
    console.error(`${argv.join(' ')} exited ${r.status ?? r.signal}`)
    process.exit(1)
  }
}
