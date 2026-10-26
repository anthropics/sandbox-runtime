import { afterAll, beforeAll, describe, expect, test } from 'bun:test'
import { spawnSync } from 'node:child_process'
import { copyFileSync, mkdtempSync, realpathSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { isLinux, isWindows } from '../helpers/platform.js'

/**
 * Compiles embedder.ts, which says why, the ways an embedding application is
 * built, and runs each result from an empty directory, so that nothing of the
 * package is on disk around it. Not quite nothing: a bundle records where its
 * modules were when it was built, so on the machine that built it a lookup
 * from the library's own location still reaches this checkout.
 */
describe.skipIf(isWindows).each([
  { form: 'one file', flags: [] },
  // Modules are evaluated in another order, the library in a chunk of its own.
  { form: 'split ESM chunks', flags: ['--splitting', '--format=esm'] },
])('the built package, minified and as bytecode in $form', ({ flags }) => {
  let home: string

  beforeAll(() => {
    home = realpathSync(mkdtempSync(join(tmpdir(), 'srt-embedder-')))
    const build = spawnSync(
      process.execPath,
      [
        ...['build', '--compile', '--minify', '--bytecode', ...flags],
        join(import.meta.dir, 'embedder.ts'),
        ...['--outfile', join(home, 'embedder')],
      ],
      { encoding: 'utf8' },
    )
    expect(
      `status ${build.status}\n${build.stdout}${build.stderr}`,
    ).toStartWith('status 0\n')
    if (isLinux) {
      copyFileSync(
        join(
          import.meta.dir,
          '../../vendor/seccomp',
          process.arch,
          'apply-seccomp',
        ),
        join(home, 'apply-seccomp'),
      )
    }
  }, 120_000)

  afterAll(() => rmSync(home, { recursive: true, force: true }))

  test.each([
    { how: 'told where the seccomp helper is', multicall: undefined },
    ...(isLinux
      ? [
          {
            how: 'reaching the helper and ripgrep through argv0',
            multicall: '1',
          },
        ]
      : []),
  ])(
    'wraps a command, $how',
    ({ multicall }) => {
      const run = spawnSync(join(home, 'embedder'), [], {
        cwd: home,
        env: {
          ...process.env,
          SRT_SMOKE_APPLY_SECCOMP: join(home, 'apply-seccomp'),
          SRT_SMOKE_MULTICALL: multicall,
        },
        encoding: 'utf8',
      })
      expect(`${run.stdout}${run.stderr}${String(run.error ?? '')}`).toEndWith(
        'SMOKE OK\n',
      )
      expect(run.status).toBe(0)
    },
    120_000,
  )
})
