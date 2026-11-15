import { describe, it, expect, beforeAll, afterAll } from 'bun:test'
import { spawnSync } from 'node:child_process'
import {
  existsSync,
  mkdirSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { wrapCommandWithSandboxMacOS } from '../../src/sandbox/macos-sandbox-utils.js'
import type { FsWriteRestrictionConfig } from '../../src/sandbox/sandbox-schemas.js'
import { isMacOS } from '../helpers/platform.js'

/**
 * The Seatbelt profile is passed to sandbox-exec in argv, so its size counts
 * against ARG_MAX (1 MiB on macOS) for every sandboxed exec. These tests pin
 * that a configuration with several hundred denied paths stays under half of
 * that limit, and that the resulting profile still spawns and enforces each
 * kind of path filter it contains (subpath, literal ancestor, regex).
 */
describe.if(isMacOS)('macOS Seatbelt profile size', () => {
  const MACOS_ARG_MAX = 1024 * 1024
  const GROUPS = 200

  const TEST_BASE_DIR = join(
    realpathSync(tmpdir()),
    'seatbelt-size-test-' + Date.now(),
  )
  const ALLOWED_DIR = join(TEST_BASE_DIR, 'allowed')
  const groupDir = (i: number) =>
    join(ALLOWED_DIR, 'nested', 'groups', `g${String(i).padStart(4, '0')}`)
  // One group dir exists on disk so a denied write reaches the sandbox
  // check instead of failing with ENOENT on the parent.
  const PROBED_GROUP = groupDir(150)

  const denyWithinAllow: string[] = []
  for (let i = 0; i < GROUPS; i++) {
    denyWithinAllow.push(
      join(groupDir(i), 'a.conf'),
      join(groupDir(i), 'a.conf.lock'),
      join(groupDir(i), 'b'),
    )
  }
  denyWithinAllow.push(join(ALLOWED_DIR, '**', '*.key'))
  const writeConfig: FsWriteRestrictionConfig = {
    allowOnly: [ALLOWED_DIR],
    denyWithinAllow,
  }

  beforeAll(() => {
    mkdirSync(PROBED_GROUP, { recursive: true })
  })

  afterAll(() => {
    if (existsSync(TEST_BASE_DIR)) {
      rmSync(TEST_BASE_DIR, { recursive: true, force: true })
    }
  })

  it(`fits ${GROUPS * 3} deny paths in under half of ARG_MAX`, () => {
    const wrappedCommand = wrapCommandWithSandboxMacOS({
      command: 'true',
      needsNetworkRestriction: false,
      readConfig: undefined,
      writeConfig,
    })

    expect(Buffer.byteLength(wrappedCommand)).toBeLessThan(MACOS_ARG_MAX / 2)

    // Same-shaped groups fold into regexes: far below one filter per path.

    expect(Buffer.byteLength(wrappedCommand)).toBeLessThan(64 * 1024)
  })

  it('spawns and enforces subpath, literal-ancestor and regex filters', () => {
    const allowedFile = join(PROBED_GROUP, 'other')
    const deniedFile = join(PROBED_GROUP, 'a.conf')
    const deniedByGlob = join(PROBED_GROUP, 'x.key')
    const wrappedCommand = wrapCommandWithSandboxMacOS({
      command: `touch ${allowedFile}; touch ${deniedFile}; touch ${deniedByGlob}; mv ${PROBED_GROUP} ${PROBED_GROUP}.moved`,
      needsNetworkRestriction: false,
      readConfig: undefined,
      writeConfig,
    })

    const result = spawnSync('/bin/bash', ['-c', wrappedCommand], {
      encoding: 'utf8',
      timeout: 30000,
    })

    expect(result.error).toBeUndefined()
    expect(existsSync(allowedFile)).toBe(true)
    expect(existsSync(deniedFile)).toBe(false)
    expect(existsSync(deniedByGlob)).toBe(false)
    expect(existsSync(`${PROBED_GROUP}.moved`)).toBe(false)
    expect(result.stderr).toContain(`${deniedFile}: Operation not permitted`)
    expect(result.stderr).toContain(`${deniedByGlob}: Operation not permitted`)
    expect(result.stderr).toContain(
      `${PROBED_GROUP}.moved: Operation not permitted`,
    )
  })

  // Glob denyRead entries are now rendered up to four times (base deny,
  // re-emit after allowRead, move-blocking, trailing unlink re-deny). Pin
  // the size at a few hundred of them, check the profile still compiles and
  // enforces, and log how long wrapping + sandbox-exec startup take so a
  // regression in either shows up in CI output.
  it(`fits ${GROUPS * 2 + 100} glob denyRead entries and still enforces them`, () => {
    const denyOnly: string[] = []
    for (let i = 0; i < GROUPS; i++) {
      denyOnly.push(
        join(groupDir(i), '**', '*.secret'),
        join(groupDir(i), '**', '.env'),
      )
    }
    for (let i = 0; i < 100; i++) {
      denyOnly.push(join(ALLOWED_DIR, `area${i}`, '**', 'credentials'))
    }
    const secretFile = join(PROBED_GROUP, 'x.secret')
    const plainFile = join(PROBED_GROUP, 'x.plain')
    writeFileSync(secretFile, 'SIZE_TEST_SECRET')
    writeFileSync(plainFile, 'SIZE_TEST_PLAIN')

    const wrapStart = performance.now()
    const wrappedCommand = wrapCommandWithSandboxMacOS({
      command: `cat ${plainFile}; cat ${secretFile}; mv ${secretFile} ${secretFile}.moved; true`,
      needsNetworkRestriction: false,
      readConfig: { denyOnly, allowWithinDeny: [ALLOWED_DIR] },
      writeConfig: { allowOnly: [ALLOWED_DIR], denyWithinAllow: [] },
    })
    const wrapMs = performance.now() - wrapStart
    expect(Buffer.byteLength(wrappedCommand)).toBeLessThan(MACOS_ARG_MAX / 2)

    const spawnStart = performance.now()
    const result = spawnSync('/bin/bash', ['-c', wrappedCommand], {
      encoding: 'utf8',
      timeout: 30000,
    })
    const spawnMs = performance.now() - spawnStart
    console.log(
      `[record] ${denyOnly.length} glob denies: profile ${Buffer.byteLength(wrappedCommand)} bytes, ` +
        `wrap ${wrapMs.toFixed(1)}ms, sandbox-exec+command ${spawnMs.toFixed(0)}ms`,
    )

    expect(result.error).toBeUndefined()
    expect(result.status).toBe(0)
    expect(result.stdout).toContain('SIZE_TEST_PLAIN')
    expect(result.stdout).not.toContain('SIZE_TEST_SECRET')
    expect(existsSync(secretFile)).toBe(true)
    expect(existsSync(`${secretFile}.moved`)).toBe(false)
  })
})
