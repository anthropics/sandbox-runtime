import { describe, it, expect, beforeEach, afterEach } from 'bun:test'
import { spawnSync } from 'node:child_process'
import {
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { isLinux, isMacOS } from '../helpers/platform.js'

// Committed test-only CA — see test/fixtures/tls-terminate/README.md.
const FIXTURE_DIR = join(import.meta.dir, '..', 'fixtures', 'tls-terminate')
const TIMEOUT_MS = 60_000

/**
 * reset() is asynchronous and a process 'exit' handler is not waited for, so
 * a host that ends with process.exit() gets no further than reset()'s first
 * await. What the library put in the temp directory must be gone all the same.
 */
describe.if(isLinux || isMacOS)('temp objects when the process ends', () => {
  let BASE: string
  let TMP: string // the child's temp directory, and nobody else's

  beforeEach(() => {
    BASE = mkdtempSync(join(tmpdir(), 'srt-exit-'))
    TMP = join(BASE, 't')
    mkdirSync(TMP)
    writeFileSync(join(BASE, 'token'), 'dummy\n')
    // A bridge that never removes its own socket. Whether the real one does
    // is a matter of timing, which would leave the outcome to chance.
    writeFileSync(
      join(BASE, 'socat'),
      '#!/bin/sh\nexec socat "$1,unlink-close=0" "$2"\n',
      { mode: 0o755 },
    )
  })

  afterEach(() => {
    rmSync(BASE, { recursive: true, force: true })
  })

  /** The library's objects among `names`, by kind: `srt-ca-Ab12Cd` is an `srt-ca`. */
  const kinds = (names: string[]): string[] =>
    names.flatMap(name => /^(srt|claude)-[a-z]+/.exec(name)?.[0] ?? []).sort()

  const START = `await SandboxManager.initialize(config)
      await SandboxManager.wrapWithSandbox('true')`

  /**
   * Runs a process that initializes with `tlsTerminate` and wraps a command
   * (or runs another `start`), and then runs `ending`. Returns what the
   * library has in its temp directory just before `ending`, and once the
   * process is gone.
   */
  function endWith(
    ending: string,
    tlsTerminate: { caCertPath?: string; caKeyPath?: string } = {},
    start = START,
  ): { before: string[]; after: string[] } {
    const script = `
      const { readdirSync } = await import('node:fs')
      const { SandboxManager } = await import(${JSON.stringify(
        join(import.meta.dir, '../../src/sandbox/sandbox-manager.ts'),
      )})
      const config = {
        network: {
          allowedDomains: ['example.com'],
          deniedDomains: [],
          tlsTerminate: ${JSON.stringify(tlsTerminate)},
        },
        filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
        credentials: {
          files: [{ path: ${JSON.stringify(join(BASE, 'token'))}, mode: 'mask' }],
        },
        socatPath: ${JSON.stringify(join(BASE, 'socat'))},
      }
      ${start}
      console.log(JSON.stringify(readdirSync(${JSON.stringify(TMP)})))
      ${ending}`
    const result = spawnSync(process.execPath, ['-e', script], {
      cwd: BASE,
      env: { ...process.env, TMPDIR: TMP, SRT_DEBUG: '' },
      encoding: 'utf8',
      timeout: TIMEOUT_MS,
    })
    expect(result.stderr).toBe('')
    expect(result.status).toBe(0)
    return {
      before: kinds(
        JSON.parse(result.stdout.trim().split('\n').at(-1) ?? '') as string[],
      ),
      after: kinds(readdirSync(TMP)),
    }
  }

  // The bridge's socket, the trust bundle, the masked credential file, the
  // proxy's socket.
  const ALWAYS = [
    ...(isLinux ? ['claude-http'] : []),
    'srt-ca',
    'srt-credmask',
    'srt-mux',
  ]

  it.each([
    ['without reset()', 'process.exit(0)'],
    ['with reset() under way', 'void SandboxManager.reset(); process.exit(0)'],
    ['after reset()', 'await SandboxManager.reset(); process.exit(0)'],
  ])(
    'are all gone when it exits %s',
    (_when, ending) => {
      const { before, after } = endWith(ending)

      // The second `srt-ca` holds the generated CA and its private key.
      expect(before).toEqual([...ALWAYS, 'srt-ca'].sort())
      expect(after).toEqual([])
    },
    TIMEOUT_MS,
  )

  /** An initialize() that is rejected after it has made its CA. */
  const rejected = (args: string): string =>
    `await SandboxManager.initialize(${args}).then(() => process.exit(3), () => {})`
  const NO_BWRAP = rejected(`{ ...config, bwrapPath: '/nonexistent/bwrap' }`)

  // Both fail before anything is registered to run at 'exit'.
  it.skipIf(!isLinux).each([
    ['a dependency is missing', NO_BWRAP],
    [
      'the violation monitor cannot start',
      rejected(
        `{ ...config, filesystem: { ...config.filesystem, denyWrite: [{ path: '/x' }] } }, undefined, true`,
      ),
    ],
  ])(
    'are gone as soon as initialize() fails because %s',
    (_why, start) => {
      expect(endWith('process.exit(0)', {}, start)).toEqual({
        before: [],
        after: [],
      })
    },
    TIMEOUT_MS,
  )

  it.each([
    ['', START, [...ALWAYS, 'srt-ca'].sort()],
    ...(isLinux
      ? [[' after a failed initialize()', NO_BWRAP, ['srt-ca']]]
      : []),
  ] as [string, string, string[]][])(
    'do not include a CA pair the configuration names, whatever it is called%s',
    (_when, start, expectedBefore) => {
      const theirs = join(TMP, 'srt-ca-theirs')
      mkdirSync(theirs)
      for (const file of ['ca.crt', 'ca.key']) {
        copyFileSync(join(FIXTURE_DIR, file), join(theirs, file))
      }

      const { before, after } = endWith(
        'process.exit(0)',
        {
          caCertPath: join(theirs, 'ca.crt'),
          caKeyPath: join(theirs, 'ca.key'),
        },
        start,
      )

      expect(before).toEqual(expectedBefore)
      expect(after).toEqual(['srt-ca'])
      expect(readdirSync(theirs).sort()).toEqual(['ca.crt', 'ca.key'])
    },
    TIMEOUT_MS,
  )
})
