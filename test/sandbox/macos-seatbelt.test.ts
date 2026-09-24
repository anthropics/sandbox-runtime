import { describe, it, expect, beforeAll, afterAll } from 'bun:test'
import { spawnSync } from 'node:child_process'
import {
  existsSync,
  mkdirSync,
  rmSync,
  writeFileSync,
  readFileSync,
  realpathSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { wrapCommandWithSandboxMacOS } from '../../src/sandbox/macos-sandbox-utils.js'
import { isMacOS } from '../helpers/platform.js'
import type {
  FsReadRestrictionConfig,
  FsWriteRestrictionConfig,
} from '../../src/sandbox/sandbox-schemas.js'

/**
 * Tests for macOS Seatbelt read bypass vulnerability
 *
 * Issue: Files protected by read deny rules could be exfiltrated by moving them
 * to readable locations using the mv command. The rename() syscall was not blocked
 * by file-read* rules.
 *
 * Fix: Added file-write-unlink deny rules to block rename/move operations on:
 * 1. The denied files/directories themselves
 * 2. All ancestor directories (to prevent moving parent directories)
 *
 * These tests use the actual sandbox profile generation code to ensure real-world coverage.
 */

describe.if(isMacOS)('macOS Seatbelt Read Bypass Prevention', () => {
  const TEST_BASE_DIR = join(tmpdir(), 'seatbelt-test-' + Date.now())
  const TEST_DENIED_DIR = join(TEST_BASE_DIR, 'denied-dir')
  const TEST_SECRET_FILE = join(TEST_DENIED_DIR, 'secret.txt')
  const TEST_SECRET_CONTENT = 'SECRET_CREDENTIAL_DATA'
  const TEST_MOVED_FILE = join(TEST_BASE_DIR, 'moved-secret.txt')
  const TEST_MOVED_DIR = join(TEST_BASE_DIR, 'moved-denied-dir')

  // Additional test files for glob pattern testing
  const TEST_GLOB_DIR = join(TEST_BASE_DIR, 'glob-test')
  const TEST_GLOB_FILE1 = join(TEST_GLOB_DIR, 'secret1.txt')
  const TEST_GLOB_FILE2 = join(TEST_GLOB_DIR, 'secret2.log')
  const TEST_GLOB_MOVED = join(TEST_BASE_DIR, 'moved-glob.txt')

  beforeAll(() => {
    // Create test directory structure
    mkdirSync(TEST_DENIED_DIR, { recursive: true })
    writeFileSync(TEST_SECRET_FILE, TEST_SECRET_CONTENT)

    // Create glob test files
    mkdirSync(TEST_GLOB_DIR, { recursive: true })
    writeFileSync(TEST_GLOB_FILE1, 'GLOB_SECRET_1')
    writeFileSync(TEST_GLOB_FILE2, 'GLOB_SECRET_2')
  })

  afterAll(() => {
    // Clean up test directory
    if (existsSync(TEST_BASE_DIR)) {
      rmSync(TEST_BASE_DIR, { recursive: true, force: true })
    }
  })

  describe('Literal Path - Direct File Move Prevention', () => {
    it('should block moving a read-denied file to a readable location', () => {
      // Use actual read restriction config with literal path
      const readConfig: FsReadRestrictionConfig = {
        denyOnly: [TEST_DENIED_DIR],
      }

      // Generate actual sandbox command using our production code
      const wrappedCommand = wrapCommandWithSandboxMacOS({
        command: `mv ${TEST_SECRET_FILE} ${TEST_MOVED_FILE}`,
        needsNetworkRestriction: false,
        readConfig,
        writeConfig: undefined,
      })

      // Verify the file exists before test
      expect(existsSync(TEST_SECRET_FILE)).toBe(true)

      // Execute the wrapped command
      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // The move should fail with operation not permitted
      expect(result.status).not.toBe(0)
      const output = (result.stderr || '').toLowerCase()
      expect(output).toContain('operation not permitted')

      // Verify the file was NOT moved
      expect(existsSync(TEST_SECRET_FILE)).toBe(true)
      expect(existsSync(TEST_MOVED_FILE)).toBe(false)
    })

    it('should still block reading the file (sanity check)', () => {
      // Use actual read restriction config
      const readConfig: FsReadRestrictionConfig = {
        denyOnly: [TEST_DENIED_DIR],
      }

      // Generate actual sandbox command
      const wrappedCommand = wrapCommandWithSandboxMacOS({
        command: `cat ${TEST_SECRET_FILE}`,
        needsNetworkRestriction: false,
        readConfig,
        writeConfig: undefined,
      })

      // Execute the wrapped command
      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // The read should fail
      expect(result.status).not.toBe(0)
      const output = (result.stderr || '').toLowerCase()
      expect(output).toContain('operation not permitted')

      // Should NOT see the secret content
      expect(result.stdout).not.toContain(TEST_SECRET_CONTENT)
    })
  })

  describe('Literal Path - Ancestor Directory Move Prevention', () => {
    it('should block moving an ancestor directory of a read-denied file', () => {
      // Use actual read restriction config
      const readConfig: FsReadRestrictionConfig = {
        denyOnly: [TEST_DENIED_DIR],
      }

      // Generate actual sandbox command
      const wrappedCommand = wrapCommandWithSandboxMacOS({
        command: `mv ${TEST_DENIED_DIR} ${TEST_MOVED_DIR}`,
        needsNetworkRestriction: false,
        readConfig,
        writeConfig: undefined,
      })

      // Verify the directory exists before test
      expect(existsSync(TEST_DENIED_DIR)).toBe(true)

      // Execute the wrapped command
      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // The move should fail
      expect(result.status).not.toBe(0)
      const output = (result.stderr || '').toLowerCase()
      expect(output).toContain('operation not permitted')

      // Verify the directory was NOT moved
      expect(existsSync(TEST_DENIED_DIR)).toBe(true)
      expect(existsSync(TEST_MOVED_DIR)).toBe(false)
    })

    it('should block moving the grandparent directory', () => {
      // Deny reading a specific file deep in the hierarchy
      const readConfig: FsReadRestrictionConfig = {
        denyOnly: [TEST_SECRET_FILE],
      }

      const movedBaseDir = join(tmpdir(), 'moved-base-' + Date.now())

      // Try to move the grandparent directory (TEST_BASE_DIR)
      const wrappedCommand = wrapCommandWithSandboxMacOS({
        command: `mv ${TEST_BASE_DIR} ${movedBaseDir}`,
        needsNetworkRestriction: false,
        readConfig,
        writeConfig: undefined,
      })

      // Execute the wrapped command
      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // The move should fail because TEST_BASE_DIR is an ancestor of TEST_SECRET_FILE
      expect(result.status).not.toBe(0)
      const output = (result.stderr || '').toLowerCase()
      expect(output).toContain('operation not permitted')

      // Verify the directory was NOT moved
      expect(existsSync(TEST_BASE_DIR)).toBe(true)
      expect(existsSync(movedBaseDir)).toBe(false)
    })
  })

  describe('Glob Pattern - File Move Prevention', () => {
    it('should block moving files matching a glob pattern (*.txt)', () => {
      // Use glob pattern that matches all .txt files in glob-test directory
      const globPattern = join(TEST_GLOB_DIR, '*.txt')

      const readConfig: FsReadRestrictionConfig = {
        denyOnly: [globPattern],
      }

      // Try to move a .txt file that matches the pattern
      const wrappedCommand = wrapCommandWithSandboxMacOS({
        command: `mv ${TEST_GLOB_FILE1} ${TEST_GLOB_MOVED}`,
        needsNetworkRestriction: false,
        readConfig,
        writeConfig: undefined,
      })

      // Verify file exists
      expect(existsSync(TEST_GLOB_FILE1)).toBe(true)

      // Execute the wrapped command
      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // The move should fail for .txt file
      expect(result.status).not.toBe(0)
      const output = (result.stderr || '').toLowerCase()
      expect(output).toContain('operation not permitted')

      // Verify the file was NOT moved
      expect(existsSync(TEST_GLOB_FILE1)).toBe(true)
      expect(existsSync(TEST_GLOB_MOVED)).toBe(false)
    })

    it('should still block reading files matching the glob pattern', () => {
      // Use glob pattern
      const globPattern = join(TEST_GLOB_DIR, '*.txt')

      const readConfig: FsReadRestrictionConfig = {
        denyOnly: [globPattern],
      }

      // Try to read a file matching the glob
      const wrappedCommand = wrapCommandWithSandboxMacOS({
        command: `cat ${TEST_GLOB_FILE1}`,
        needsNetworkRestriction: false,
        readConfig,
        writeConfig: undefined,
      })

      // Execute the wrapped command
      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // The read should fail
      expect(result.status).not.toBe(0)
      const output = (result.stderr || '').toLowerCase()
      expect(output).toContain('operation not permitted')

      // Should NOT see the content
      expect(result.stdout).not.toContain('GLOB_SECRET_1')
    })

    it('should block moving the parent directory containing glob-matched files', () => {
      // Use glob pattern
      const globPattern = join(TEST_GLOB_DIR, '*.txt')

      const readConfig: FsReadRestrictionConfig = {
        denyOnly: [globPattern],
      }

      const movedGlobDir = join(TEST_BASE_DIR, 'moved-glob-dir')

      // Try to move the parent directory
      const wrappedCommand = wrapCommandWithSandboxMacOS({
        command: `mv ${TEST_GLOB_DIR} ${movedGlobDir}`,
        needsNetworkRestriction: false,
        readConfig,
        writeConfig: undefined,
      })

      // Execute the wrapped command
      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // The move should fail because TEST_GLOB_DIR is an ancestor of the glob pattern
      expect(result.status).not.toBe(0)
      const output = (result.stderr || '').toLowerCase()
      expect(output).toContain('operation not permitted')

      // Verify the directory was NOT moved
      expect(existsSync(TEST_GLOB_DIR)).toBe(true)
      expect(existsSync(movedGlobDir)).toBe(false)
    })
  })

  describe('Glob Pattern - Recursive Patterns', () => {
    it('should block moving files matching a recursive glob pattern (**/*.txt)', () => {
      // Create nested directory structure
      const nestedDir = join(TEST_GLOB_DIR, 'nested')
      const nestedFile = join(nestedDir, 'nested-secret.txt')
      mkdirSync(nestedDir, { recursive: true })
      writeFileSync(nestedFile, 'NESTED_SECRET')

      // Use recursive glob pattern
      const globPattern = join(TEST_GLOB_DIR, '**/*.txt')

      const readConfig: FsReadRestrictionConfig = {
        denyOnly: [globPattern],
      }

      const movedNested = join(TEST_BASE_DIR, 'moved-nested.txt')

      // Try to move the nested file
      const wrappedCommand = wrapCommandWithSandboxMacOS({
        command: `mv ${nestedFile} ${movedNested}`,
        needsNetworkRestriction: false,
        readConfig,
        writeConfig: undefined,
      })

      // Execute the wrapped command
      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // The move should fail
      expect(result.status).not.toBe(0)
      const output = (result.stderr || '').toLowerCase()
      expect(output).toContain('operation not permitted')

      // Verify the file was NOT moved
      expect(existsSync(nestedFile)).toBe(true)
      expect(existsSync(movedNested)).toBe(false)
    })
  })
})

describe.if(isMacOS)('macOS Seatbelt Write Bypass Prevention', () => {
  const TEST_BASE_DIR = join(tmpdir(), 'seatbelt-write-test-' + Date.now())
  const TEST_ALLOWED_DIR = join(TEST_BASE_DIR, 'allowed')
  const TEST_DENIED_DIR = join(TEST_ALLOWED_DIR, 'secrets')
  const TEST_DENIED_FILE = join(TEST_DENIED_DIR, 'secret.txt')
  const TEST_ORIGINAL_CONTENT = 'ORIGINAL_CONTENT'
  const TEST_MODIFIED_CONTENT = 'MODIFIED_CONTENT'

  // Additional test paths
  const TEST_RENAMED_DIR = join(TEST_BASE_DIR, 'renamed-secrets')

  // Glob pattern test paths
  const TEST_GLOB_DIR = join(TEST_ALLOWED_DIR, 'glob-test')
  const TEST_GLOB_SECRET1 = join(TEST_GLOB_DIR, 'secret1.txt')
  const TEST_GLOB_SECRET2 = join(TEST_GLOB_DIR, 'secret2.log')
  const TEST_GLOB_RENAMED = join(TEST_BASE_DIR, 'renamed-glob')

  beforeAll(() => {
    // Create test directory structure
    mkdirSync(TEST_DENIED_DIR, { recursive: true })
    mkdirSync(TEST_GLOB_DIR, { recursive: true })

    // Create test files with original content
    writeFileSync(TEST_DENIED_FILE, TEST_ORIGINAL_CONTENT)
    writeFileSync(TEST_GLOB_SECRET1, TEST_ORIGINAL_CONTENT)
    writeFileSync(TEST_GLOB_SECRET2, TEST_ORIGINAL_CONTENT)
  })

  afterAll(() => {
    // Clean up test directory
    if (existsSync(TEST_BASE_DIR)) {
      rmSync(TEST_BASE_DIR, { recursive: true, force: true })
    }
  })

  describe('Literal Path - Direct Directory Move Prevention', () => {
    it('should block write bypass via directory rename (mv a c, write c/b, mv c a)', () => {
      // Allow writing to TEST_ALLOWED_DIR but deny TEST_DENIED_DIR
      const writeConfig: FsWriteRestrictionConfig = {
        allowOnly: [TEST_ALLOWED_DIR],
        denyWithinAllow: [TEST_DENIED_DIR],
      }

      // Step 1: Try to rename the denied directory
      const mvCommand1 = wrapCommandWithSandboxMacOS({
        command: `mv ${TEST_DENIED_DIR} ${TEST_RENAMED_DIR}`,
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig,
      })

      const result1 = spawnSync(mvCommand1, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // The move should fail
      expect(result1.status).not.toBe(0)
      const output1 = (result1.stderr || '').toLowerCase()
      expect(output1).toContain('operation not permitted')

      // Verify the directory was NOT moved
      expect(existsSync(TEST_DENIED_DIR)).toBe(true)
      expect(existsSync(TEST_RENAMED_DIR)).toBe(false)
    })

    it('should still block direct writes to denied paths (sanity check)', () => {
      const writeConfig: FsWriteRestrictionConfig = {
        allowOnly: [TEST_ALLOWED_DIR],
        denyWithinAllow: [TEST_DENIED_DIR],
      }

      // Try to write directly to the denied file
      const wrappedCommand = wrapCommandWithSandboxMacOS({
        command: `echo "${TEST_MODIFIED_CONTENT}" > ${TEST_DENIED_FILE}`,
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig,
      })

      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // The write should fail
      expect(result.status).not.toBe(0)
      const output = (result.stderr || '').toLowerCase()
      expect(output).toContain('operation not permitted')

      // Verify the file was NOT modified
      const content = readFileSync(TEST_DENIED_FILE, 'utf8')
      expect(content).toBe(TEST_ORIGINAL_CONTENT)
    })
  })

  describe('Literal Path - Ancestor Directory Move Prevention', () => {
    it('should block moving an ancestor directory of a write-denied path', () => {
      const writeConfig: FsWriteRestrictionConfig = {
        allowOnly: [TEST_ALLOWED_DIR],
        denyWithinAllow: [TEST_DENIED_FILE],
      }

      const movedAllowedDir = join(TEST_BASE_DIR, 'moved-allowed')

      // Try to move the parent directory (TEST_ALLOWED_DIR)
      const wrappedCommand = wrapCommandWithSandboxMacOS({
        command: `mv ${TEST_ALLOWED_DIR} ${movedAllowedDir}`,
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig,
      })

      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // The move should fail because TEST_ALLOWED_DIR is an ancestor
      expect(result.status).not.toBe(0)
      const output = (result.stderr || '').toLowerCase()
      expect(output).toContain('operation not permitted')

      // Verify the directory was NOT moved
      expect(existsSync(TEST_ALLOWED_DIR)).toBe(true)
      expect(existsSync(movedAllowedDir)).toBe(false)
    })

    it('should block moving the grandparent directory', () => {
      const writeConfig: FsWriteRestrictionConfig = {
        allowOnly: [TEST_ALLOWED_DIR],
        denyWithinAllow: [TEST_DENIED_FILE],
      }

      const movedBaseDir = join(tmpdir(), 'moved-write-base-' + Date.now())

      // Try to move the grandparent directory (TEST_BASE_DIR)
      const wrappedCommand = wrapCommandWithSandboxMacOS({
        command: `mv ${TEST_BASE_DIR} ${movedBaseDir}`,
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig,
      })

      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // The move should fail because TEST_BASE_DIR is an ancestor
      expect(result.status).not.toBe(0)
      const output = (result.stderr || '').toLowerCase()
      expect(output).toContain('operation not permitted')

      // Verify the directory was NOT moved
      expect(existsSync(TEST_BASE_DIR)).toBe(true)
      expect(existsSync(movedBaseDir)).toBe(false)
    })
  })

  describe('Glob Pattern - File Move Prevention', () => {
    it('should block write bypass via moving glob-matched files', () => {
      // Allow writing to TEST_ALLOWED_DIR but deny *.txt files in glob-test
      const globPattern = join(TEST_GLOB_DIR, '*.txt')

      const writeConfig: FsWriteRestrictionConfig = {
        allowOnly: [TEST_ALLOWED_DIR],
        denyWithinAllow: [globPattern],
      }

      // Try to move a .txt file
      const mvCommand = wrapCommandWithSandboxMacOS({
        command: `mv ${TEST_GLOB_SECRET1} ${join(TEST_BASE_DIR, 'moved-secret.txt')}`,
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig,
      })

      const result = spawnSync(mvCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // The move should fail
      expect(result.status).not.toBe(0)
      const output = (result.stderr || '').toLowerCase()
      expect(output).toContain('operation not permitted')

      // Verify the file was NOT moved
      expect(existsSync(TEST_GLOB_SECRET1)).toBe(true)
    })

    it('should still block direct writes to glob-matched files', () => {
      const globPattern = join(TEST_GLOB_DIR, '*.txt')

      const writeConfig: FsWriteRestrictionConfig = {
        allowOnly: [TEST_ALLOWED_DIR],
        denyWithinAllow: [globPattern],
      }

      // Try to write to a glob-matched file
      const wrappedCommand = wrapCommandWithSandboxMacOS({
        command: `echo "${TEST_MODIFIED_CONTENT}" > ${TEST_GLOB_SECRET1}`,
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig,
      })

      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // The write should fail
      expect(result.status).not.toBe(0)
      const output = (result.stderr || '').toLowerCase()
      expect(output).toContain('operation not permitted')

      // Verify the file was NOT modified
      const content = readFileSync(TEST_GLOB_SECRET1, 'utf8')
      expect(content).toBe(TEST_ORIGINAL_CONTENT)
    })

    it('should block moving the parent directory containing glob-matched files', () => {
      const globPattern = join(TEST_GLOB_DIR, '*.txt')

      const writeConfig: FsWriteRestrictionConfig = {
        allowOnly: [TEST_ALLOWED_DIR],
        denyWithinAllow: [globPattern],
      }

      // Try to move the parent directory
      const wrappedCommand = wrapCommandWithSandboxMacOS({
        command: `mv ${TEST_GLOB_DIR} ${TEST_GLOB_RENAMED}`,
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig,
      })

      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // The move should fail
      expect(result.status).not.toBe(0)
      const output = (result.stderr || '').toLowerCase()
      expect(output).toContain('operation not permitted')

      // Verify the directory was NOT moved
      expect(existsSync(TEST_GLOB_DIR)).toBe(true)
      expect(existsSync(TEST_GLOB_RENAMED)).toBe(false)
    })
  })

  describe('Glob Pattern - Recursive Patterns', () => {
    it('should block moving files matching a recursive glob pattern (**/*.txt)', () => {
      // Create nested directory structure
      const nestedDir = join(TEST_GLOB_DIR, 'nested')
      const nestedFile = join(nestedDir, 'nested-secret.txt')
      mkdirSync(nestedDir, { recursive: true })
      writeFileSync(nestedFile, TEST_ORIGINAL_CONTENT)

      // Use recursive glob pattern
      const globPattern = join(TEST_GLOB_DIR, '**/*.txt')

      const writeConfig: FsWriteRestrictionConfig = {
        allowOnly: [TEST_ALLOWED_DIR],
        denyWithinAllow: [globPattern],
      }

      const movedNested = join(TEST_BASE_DIR, 'moved-nested.txt')

      // Try to move the nested file
      const wrappedCommand = wrapCommandWithSandboxMacOS({
        command: `mv ${nestedFile} ${movedNested}`,
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig,
      })

      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // The move should fail
      expect(result.status).not.toBe(0)
      const output = (result.stderr || '').toLowerCase()
      expect(output).toContain('operation not permitted')

      // Verify the file was NOT moved
      expect(existsSync(nestedFile)).toBe(true)
      expect(existsSync(movedNested)).toBe(false)
    })
  })
})

/**
 * Tests for Seatbelt symlink-creation bypass on protected ancestors.
 *
 * Issue: generateMoveBlockingRules() emitted (deny file-write-unlink) for
 * protected paths and their ancestor directories, but not file-write-create.
 * If a protected path's ancestor directory did not yet exist, a sandboxed
 * command could create it as a symlink pointing at attacker-controlled content,
 * since (allow file-write* (subpath <cwd>)) is not overridden by a
 * file-write-unlink-only deny on the ancestor literal.
 *
 * Fix: Emit (deny file-write-create ...) alongside every (deny file-write-unlink ...)
 * in generateMoveBlockingRules(), and re-allow it for write-allowed paths in
 * generateReadRules() to preserve normal file creation in the project directory.
 */
describe.if(isMacOS)(
  'macOS Seatbelt Symlink Creation Bypass Prevention',
  () => {
    // Use the canonical tmpdir (/private/var/... on macOS) so the deny rules —
    // whose paths cannot be realpath-resolved because they don't exist yet —
    // match the canonical syscall paths Seatbelt evaluates.
    const TEST_BASE_DIR = join(
      realpathSync(tmpdir()),
      'seatbelt-create-test-' + Date.now(),
    )
    const TEST_ALLOWED_DIR = join(TEST_BASE_DIR, 'allowed')
    // Protected directory that does NOT exist on disk
    const TEST_DENIED_PARENT = join(TEST_ALLOWED_DIR, '.claude')
    const TEST_DENIED_FILE = join(TEST_DENIED_PARENT, 'settings.json')
    const TEST_DECOY_DIR = join(TEST_ALLOWED_DIR, 'decoy')

    beforeAll(() => {
      mkdirSync(TEST_ALLOWED_DIR, { recursive: true })
      mkdirSync(TEST_DECOY_DIR, { recursive: true })
      writeFileSync(join(TEST_DECOY_DIR, 'settings.json'), '{"evil":true}')
    })

    afterAll(() => {
      if (existsSync(TEST_BASE_DIR)) {
        rmSync(TEST_BASE_DIR, { recursive: true, force: true })
      }
    })

    it('should emit file-write-create deny rules for protected ancestors', () => {
      const writeConfig: FsWriteRestrictionConfig = {
        allowOnly: [TEST_ALLOWED_DIR],
        denyWithinAllow: [TEST_DENIED_FILE],
      }

      const wrappedCommand = wrapCommandWithSandboxMacOS({
        command: 'true',
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig,
      })

      expect(wrappedCommand).toContain(
        `(deny file-write-unlink file-write-create\n` +
          `  (subpath ${JSON.stringify(TEST_DENIED_FILE)})\n` +
          `  (literal ${JSON.stringify(TEST_DENIED_PARENT)})\n`,
      )
    })

    it('should block creating a symlink at a non-existent protected ancestor', () => {
      const writeConfig: FsWriteRestrictionConfig = {
        allowOnly: [TEST_ALLOWED_DIR],
        denyWithinAllow: [TEST_DENIED_FILE],
      }

      expect(existsSync(TEST_DENIED_PARENT)).toBe(false)

      const wrappedCommand = wrapCommandWithSandboxMacOS({
        command: `ln -s ${TEST_DECOY_DIR} ${TEST_DENIED_PARENT}`,
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig,
      })

      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      expect(result.status).not.toBe(0)
      const output = (result.stderr || '').toLowerCase()
      expect(output).toContain('operation not permitted')
      expect(existsSync(TEST_DENIED_PARENT)).toBe(false)
    })

    it('should still allow creating ordinary files in the write-allowed directory', () => {
      const writeConfig: FsWriteRestrictionConfig = {
        allowOnly: [TEST_ALLOWED_DIR],
        denyWithinAllow: [TEST_DENIED_FILE],
      }

      const newFile = join(TEST_ALLOWED_DIR, 'ordinary.txt')
      const wrappedCommand = wrapCommandWithSandboxMacOS({
        command: `echo hello > ${newFile}`,
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig,
      })

      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      expect(result.status).toBe(0)
      expect(existsSync(newFile)).toBe(true)
      expect(readFileSync(newFile, 'utf8').trim()).toBe('hello')
    })
  },
)

/**
 * Tests for Unix domain socket support in network-restricted sandbox.
 *
 * Issue: When allowedDomains is set, the sandbox enters restricted network mode.
 * The previous implementation used (allow network* (subpath "/")) to allow Unix
 * sockets, but socket(AF_UNIX, SOCK_STREAM, 0) is a system-socket operation that
 * doesn't reference a filesystem path, so (subpath ...) can't match it.
 * This caused Gradle (FileLockContentionHandler), Docker, and other tools that
 * create Unix domain sockets to fail with "Operation not permitted".
 *
 * Fix: Use (allow system-socket (socket-domain AF_UNIX)) for socket creation,
 * and (allow network-bind/network-outbound (local/remote unix-socket ...)) for
 * bind/connect operations.
 */
describe.if(isMacOS)('macOS Seatbelt Unix Domain Socket Support', () => {
  const TEST_BASE_DIR = join(
    tmpdir(),
    'seatbelt-unix-socket-test-' + Date.now(),
  )

  beforeAll(() => {
    mkdirSync(TEST_BASE_DIR, { recursive: true })
  })

  afterAll(() => {
    if (existsSync(TEST_BASE_DIR)) {
      rmSync(TEST_BASE_DIR, { recursive: true, force: true })
    }
  })

  it('should allow Unix domain socket creation and communication with allowAllUnixSockets', () => {
    const socketPath = join(TEST_BASE_DIR, 'test.sock')
    const scriptPath = join(TEST_BASE_DIR, 'test_socket.py')

    // Write Python script to a file to avoid shell quoting issues
    writeFileSync(
      scriptPath,
      [
        'import socket, os',
        `sock_path = '${socketPath}'`,
        'if os.path.exists(sock_path):',
        '    os.unlink(sock_path)',
        'server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)',
        'server.bind(sock_path)',
        'server.listen(1)',
        'client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)',
        'client.connect(sock_path)',
        'conn, _ = server.accept()',
        "client.send(b'SOCKET_OK')",
        'data = conn.recv(1024)',
        'print(data.decode())',
        'client.close()',
        'conn.close()',
        'server.close()',
        'os.unlink(sock_path)',
      ].join('\n'),
    )

    const writeConfig: FsWriteRestrictionConfig = {
      allowOnly: [TEST_BASE_DIR],
      denyWithinAllow: [],
    }

    const wrappedCommand = wrapCommandWithSandboxMacOS({
      command: `python3 ${scriptPath}`,
      needsNetworkRestriction: true,
      allowAllUnixSockets: true,
      readConfig: undefined,
      writeConfig,
    })

    const result = spawnSync(wrappedCommand, {
      shell: true,
      encoding: 'utf8',
      timeout: 10000,
    })

    expect(result.status).toBe(0)
    expect(result.stdout.trim()).toBe('SOCKET_OK')
  })

  it('should allow Unix domain socket creation with specific allowUnixSockets paths', () => {
    const socketPath = join(TEST_BASE_DIR, 'specific.sock')
    const scriptPath = join(TEST_BASE_DIR, 'test_specific_socket.py')

    writeFileSync(
      scriptPath,
      [
        'import socket, os',
        `sock_path = '${socketPath}'`,
        'if os.path.exists(sock_path):',
        '    os.unlink(sock_path)',
        'server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)',
        'server.bind(sock_path)',
        'server.listen(1)',
        'client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)',
        'client.connect(sock_path)',
        'conn, _ = server.accept()',
        "client.send(b'SPECIFIC_OK')",
        'data = conn.recv(1024)',
        'print(data.decode())',
        'client.close()',
        'conn.close()',
        'server.close()',
        'os.unlink(sock_path)',
      ].join('\n'),
    )

    const writeConfig: FsWriteRestrictionConfig = {
      allowOnly: [TEST_BASE_DIR],
      denyWithinAllow: [],
    }

    const wrappedCommand = wrapCommandWithSandboxMacOS({
      command: `python3 ${scriptPath}`,
      needsNetworkRestriction: true,
      allowUnixSockets: [TEST_BASE_DIR],
      readConfig: undefined,
      writeConfig,
    })

    const result = spawnSync(wrappedCommand, {
      shell: true,
      encoding: 'utf8',
      timeout: 10000,
    })

    expect(result.status).toBe(0)
    expect(result.stdout.trim()).toBe('SPECIFIC_OK')
  })

  it('should block Unix domain socket bind when neither allowAllUnixSockets nor allowUnixSockets is set', () => {
    const socketPath = join(TEST_BASE_DIR, 'blocked.sock')
    const scriptPath = join(TEST_BASE_DIR, 'test_blocked_socket.py')

    // This script should fail at bind() because Unix socket paths are not allowed
    writeFileSync(
      scriptPath,
      [
        'import socket, os, sys',
        `sock_path = '${socketPath}'`,
        'if os.path.exists(sock_path):',
        '    os.unlink(sock_path)',
        'try:',
        '    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)',
        '    s.bind(sock_path)',
        "    print('BIND_OK')",
        '    s.close()',
        '    os.unlink(sock_path)',
        'except OSError as e:',
        "    print(f'BLOCKED:{e}')",
        '    sys.exit(1)',
      ].join('\n'),
    )

    const writeConfig: FsWriteRestrictionConfig = {
      allowOnly: [TEST_BASE_DIR],
      denyWithinAllow: [],
    }

    const wrappedCommand = wrapCommandWithSandboxMacOS({
      command: `python3 ${scriptPath}`,
      needsNetworkRestriction: true,
      // Neither allowAllUnixSockets nor allowUnixSockets
      readConfig: undefined,
      writeConfig,
    })

    const result = spawnSync(wrappedCommand, {
      shell: true,
      encoding: 'utf8',
      timeout: 10000,
    })

    // Socket bind should be blocked
    expect(result.status).not.toBe(0)
    expect(result.stdout).toContain('BLOCKED:')
  })
})

describe.if(isMacOS)('macOS Seatbelt Process Enumeration', () => {
  it('should allow enumerating all process IDs (kern.proc.all sysctl)', () => {
    // This tests that psutil.pids() and similar process enumeration works.
    // The kern.proc.all sysctl is used by psutil to list all PIDs on the system.
    // Use case: IPython kernel shutdown needs to enumerate child processes.
    const wrappedCommand = wrapCommandWithSandboxMacOS({
      command: 'ps -axo pid=',
      needsNetworkRestriction: false,
      readConfig: undefined,
      writeConfig: undefined,
    })

    const result = spawnSync(wrappedCommand, {
      shell: true,
      encoding: 'utf8',
      timeout: 5000,
    })

    // The command should succeed
    expect(result.status).toBe(0)

    // Should return a list of PIDs (at least the current process)
    const pids = result.stdout
      .trim()
      .split('\n')
      .filter(line => line.trim())
    expect(pids.length).toBeGreaterThan(0)

    // Each line should be a valid PID (numeric)
    for (const pid of pids) {
      expect(parseInt(pid.trim(), 10)).toBeGreaterThan(0)
    }
  })
})

describe.if(isMacOS)('macOS Seatbelt allowMachLookup', () => {
  it('should emit global-name and global-name-prefix rules for configured services', () => {
    const wrappedCommand = wrapCommandWithSandboxMacOS({
      command: 'true',
      needsNetworkRestriction: true,
      allowMachLookup: [
        'com.apple.CoreSimulator.CoreSimulatorService',
        '2BUA8C4S2C.com.1password.*',
      ],
      readConfig: undefined,
      writeConfig: undefined,
    })

    expect(wrappedCommand).toContain(
      '(allow mach-lookup (global-name "com.apple.CoreSimulator.CoreSimulatorService"))',
    )
    expect(wrappedCommand).toContain(
      '(allow mach-lookup (global-name-prefix "2BUA8C4S2C.com.1password."))',
    )
  })

  it('should emit a syntactically valid profile with allowMachLookup set', () => {
    const wrappedCommand = wrapCommandWithSandboxMacOS({
      command: 'true',
      needsNetworkRestriction: true,
      allowMachLookup: ['com.example.service', 'com.example.prefix.*', '*'],
      readConfig: undefined,
      writeConfig: undefined,
    })

    const result = spawnSync(wrappedCommand, {
      shell: true,
      encoding: 'utf8',
      timeout: 5000,
    })

    expect(result.status).toBe(0)
  })
})
