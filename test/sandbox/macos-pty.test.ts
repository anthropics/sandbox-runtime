import { describe, it, expect, beforeAll, afterAll } from 'bun:test'
import { spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, rmSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { wrapCommandWithSandboxMacOS } from '../../src/sandbox/macos-sandbox-utils.js'
import type { FsWriteRestrictionConfig } from '../../src/sandbox/sandbox-schemas.js'
import { isMacOS } from '../helpers/platform.js'

describe.if(isMacOS)('macOS Seatbelt PTY Support', () => {
  const TEST_BASE_DIR = join(tmpdir(), 'seatbelt-pty-test-' + Date.now())

  beforeAll(() => {
    mkdirSync(TEST_BASE_DIR, { recursive: true })
  })

  afterAll(() => {
    if (existsSync(TEST_BASE_DIR)) {
      rmSync(TEST_BASE_DIR, { recursive: true, force: true })
    }
  })

  it('should allow PTY operations when allowPty is true', () => {
    const outputFile = join(TEST_BASE_DIR, 'pty-output.txt')

    const writeConfig: FsWriteRestrictionConfig = {
      allowOnly: [TEST_BASE_DIR],
      denyWithinAllow: [],
    }

    // Use 'script' command which requires PTY allocation
    const wrappedCommand = wrapCommandWithSandboxMacOS({
      command: `script -q ${outputFile} echo "pty works"`,
      needsNetworkRestriction: false,
      readConfig: undefined,
      writeConfig,
      allowPty: true,
    })

    const result = spawnSync(wrappedCommand, {
      shell: true,
      encoding: 'utf8',
      timeout: 10000,
    })

    expect(result.status).toBe(0)
    expect(existsSync(outputFile)).toBe(true)
    const content = readFileSync(outputFile, 'utf8')
    expect(content).toContain('pty works')
  })

  it('should block PTY operations when allowPty is false', () => {
    const outputFile = join(TEST_BASE_DIR, 'pty-blocked.txt')

    const writeConfig: FsWriteRestrictionConfig = {
      allowOnly: [TEST_BASE_DIR],
      denyWithinAllow: [],
    }

    const wrappedCommand = wrapCommandWithSandboxMacOS({
      command: `script -q ${outputFile} echo "should fail"`,
      needsNetworkRestriction: false,
      readConfig: undefined,
      writeConfig,
      allowPty: false,
    })

    const result = spawnSync(wrappedCommand, {
      shell: true,
      encoding: 'utf8',
      timeout: 10000,
    })

    expect(result.status).not.toBe(0)
  })
})
