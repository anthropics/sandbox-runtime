/**
 * Builds test/smoke/embedder.ts the ways an embedding application is built and
 * runs each result: `npm run test:bundled`, after `npm run build`.
 *
 * Two forms, both minified with identifiers shortened and compiled to bytecode
 * in one executable: one flat file, and code-split ESM chunks, where modules
 * are evaluated in another order and the library sits in a chunk of its own.
 *
 * Each executable is copied, with the seccomp helper this checkout built, into
 * an empty directory and run from there. Nothing of the package is on disk
 * around it then, which is how an embedded copy runs: a lookup that starts
 * from the library's own location finds nothing, and has to be one the
 * configuration already answered.
 *
 * On Linux each is run twice: told where the helper file is, and as a
 * multicall executable that carries the helper and ripgrep itself and is
 * started under their names (see embedder.ts), which is how an application
 * that has both compiled in reaches them.
 */
import { spawnSync } from 'node:child_process'
import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdtempSync,
  realpathSync,
  rmSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const repo = process.cwd()
const entry = join(repo, 'test', 'smoke', 'embedder.ts')
if (!existsSync(join(repo, 'dist', 'index.js'))) {
  console.error('dist/ is not built: run `npm run build` first')
  process.exit(1)
}

const FORMS: Array<{ name: string; flags: string[] }> = [
  { name: 'one file', flags: [] },
  { name: 'split ESM chunks', flags: ['--splitting', '--format=esm'] },
]

const builtHelper = join(
  repo,
  'vendor',
  'seccomp',
  process.arch === 'arm64' ? 'arm64' : 'x64',
  'apply-seccomp',
)

let failed = false
for (const form of FORMS) {
  const home = realpathSync(mkdtempSync(join(tmpdir(), 'srt-embedder-')))
  try {
    const program = join(home, 'embedder')
    const build = spawnSync(
      process.execPath,
      [
        'build',
        '--compile',
        '--minify',
        '--bytecode',
        ...form.flags,
        entry,
        '--outfile',
        program,
      ],
      { cwd: repo, encoding: 'utf8' },
    )
    if (build.status !== 0) {
      console.error(
        `== ${form.name}: did not build\n${build.stdout}${build.stderr}`,
      )
      failed = true
      continue
    }

    const env: Record<string, string | undefined> = { ...process.env }
    delete env.SRT_SMOKE_APPLY_SECCOMP
    if (process.platform === 'linux' && existsSync(builtHelper)) {
      const helper = join(home, 'apply-seccomp')
      copyFileSync(builtHelper, helper)
      chmodSync(helper, 0o755)
      env.SRT_SMOKE_APPLY_SECCOMP = helper
    }

    const modes: Array<{ name: string; env: typeof env }> = [
      { name: form.name, env },
    ]
    const ripgrep = Bun.which('rg')
    if (env.SRT_SMOKE_APPLY_SECCOMP !== undefined && ripgrep !== null) {
      modes.push({
        name: `${form.name}, helper and ripgrep reached through argv0`,
        env: { ...env, SRT_SMOKE_MULTICALL: '1', SRT_SMOKE_RG: ripgrep },
      })
    }
    for (const mode of modes) {
      console.log(`== ${mode.name}`)
      const run = spawnSync(program, [], {
        cwd: home,
        env: mode.env,
        encoding: 'utf8',
        timeout: 300000,
      })
      process.stdout.write(run.stdout)
      process.stderr.write(run.stderr)
      if (run.status !== 0 || !run.stdout.includes('SMOKE OK')) {
        console.error(`== ${mode.name}: FAILED (status ${String(run.status)})`)
        failed = true
      }
    }
  } finally {
    rmSync(home, { recursive: true, force: true })
  }
}
process.exit(failed ? 1 : 0)
