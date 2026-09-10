import { describe, it, expect, beforeEach, afterEach } from 'bun:test'
import { spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, rmSync, unlinkSync, lstatSync } from 'node:fs'
import { join } from 'node:path'
import { wrapCommandWithSandboxMacOS } from '../../src/sandbox/macos-sandbox-utils.js'
import {
  isAtOrUnder,
  isSymlinkOutsideBoundary,
  normalizePathForSandbox,
} from '../../src/sandbox/sandbox-utils.js'
import type { FsWriteRestrictionConfig } from '../../src/sandbox/sandbox-schemas.js'

/**
 * Tests for macOS Seatbelt symlink boundary validation
 *
 * These tests verify that symlink resolution in sandbox profile generation
 * correctly validates path boundaries. When a symlink points to a broader
 * scope (e.g., a parent directory or root), the original path should be
 * preserved rather than the resolved path.
 */

import { isMacOS } from '../helpers/platform.js'

/**
 * Safely remove /tmp/claude if it exists (file, directory, or symlink)
 */
function cleanupTmpClaude(): void {
  const paths = ['/tmp/claude', '/private/tmp/claude']
  for (const p of paths) {
    try {
      if (existsSync(p) || lstatSync(p).isSymbolicLink()) {
        const stat = lstatSync(p)
        if (stat.isSymbolicLink() || stat.isFile()) {
          unlinkSync(p)
        } else if (stat.isDirectory()) {
          rmSync(p, { recursive: true, force: true })
        }
      }
    } catch {
      // Path doesn't exist, ignore
    }
  }
}

describe.if(isMacOS)('macOS Seatbelt Symlink Boundary Validation', () => {
  // Use unique test directories per run
  // Use /private/tmp (not os.tmpdir()) so test paths are outside any
  // default-allowed write location
  const TEST_ID = Date.now()
  const TEST_BASE_DIR = `/private/tmp/symlink-boundary-test-${TEST_ID}`
  const WORKSPACE_DIR = join(TEST_BASE_DIR, 'workspace')
  // Use a path that is outside the allowed write paths
  const OUTSIDE_WORKSPACE_FILE = `/private/tmp/outside-allowed-${TEST_ID}.txt`
  const TEST_CONTENT = 'TEST_CONTENT'

  beforeEach(() => {
    // Clean up any existing /tmp/claude symlink from previous runs
    cleanupTmpClaude()

    // Create fresh test directory structure
    if (existsSync(TEST_BASE_DIR)) {
      rmSync(TEST_BASE_DIR, { recursive: true, force: true })
    }
    mkdirSync(WORKSPACE_DIR, { recursive: true })
  })

  afterEach(() => {
    // Clean up /tmp/claude
    cleanupTmpClaude()

    // Clean up test directories and files
    if (existsSync(TEST_BASE_DIR)) {
      rmSync(TEST_BASE_DIR, { recursive: true, force: true })
    }
    if (existsSync(OUTSIDE_WORKSPACE_FILE)) {
      unlinkSync(OUTSIDE_WORKSPACE_FILE)
    }
  })

  describe('Symlink Boundary Enforcement', () => {
    it('should preserve original path when symlink points to root', () => {
      // Step 1: Verify sandbox correctly blocks writes outside workspace
      console.log('\n=== Step 1: Initial write attempt (should be blocked) ===')

      const writeConfig: FsWriteRestrictionConfig = {
        allowOnly: [WORKSPACE_DIR, '/tmp/claude', '/private/tmp/claude'],
        denyWithinAllow: [],
      }

      const initialWriteCommand = wrapCommandWithSandboxMacOS({
        command: `echo "${TEST_CONTENT}" > ${OUTSIDE_WORKSPACE_FILE}`,
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig,
      })

      const initialResult = spawnSync(initialWriteCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // This should fail - can't write outside workspace
      expect(initialResult.status).not.toBe(0)
      expect(existsSync(OUTSIDE_WORKSPACE_FILE)).toBe(false)
      console.log('✓ Initial write correctly blocked')

      // Step 2: Create symlink /tmp/claude -> /
      console.log('\n=== Step 2: Creating symlink /tmp/claude -> / ===')

      const symlinkCommand = wrapCommandWithSandboxMacOS({
        command: 'ln -s / /tmp/claude',
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig,
      })

      const symlinkResult = spawnSync(symlinkCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // Creating the symlink should succeed (we're writing to /tmp/claude which is allowed)
      expect(symlinkResult.status).toBe(0)

      // Verify symlink was created
      const stat = lstatSync('/tmp/claude')
      expect(stat.isSymbolicLink()).toBe(true)
      console.log('✓ Symlink created: /tmp/claude -> /')

      // Step 3: Verify sandbox still blocks writes outside workspace
      console.log(
        '\n=== Step 3: Second write attempt (should still be blocked) ===',
      )

      // Generate a NEW sandbox profile - symlink resolution should be bounded
      const secondWriteCommand = wrapCommandWithSandboxMacOS({
        command: `echo "${TEST_CONTENT}" > ${OUTSIDE_WORKSPACE_FILE}`,
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig,
      })

      const secondResult = spawnSync(secondWriteCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // The symlink should NOT cause /tmp/claude to resolve to / in the profile
      expect(secondResult.status).not.toBe(0)
      expect(existsSync(OUTSIDE_WORKSPACE_FILE)).toBe(false)
      console.log('✓ Write correctly blocked with symlink boundary validation')

      console.log('\n=== Summary ===')
      console.log('Symlink boundary validation working correctly')
    })

    it('should block writes outside workspace when /tmp/claude does not exist', () => {
      // Ensure /tmp/claude doesn't exist
      cleanupTmpClaude()
      expect(existsSync('/tmp/claude')).toBe(false)

      const writeConfig: FsWriteRestrictionConfig = {
        allowOnly: [WORKSPACE_DIR, '/tmp/claude', '/private/tmp/claude'],
        denyWithinAllow: [],
      }

      const wrappedCommand = wrapCommandWithSandboxMacOS({
        command: `echo "test" > ${OUTSIDE_WORKSPACE_FILE}`,
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig,
      })

      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // Should fail - can't write outside workspace
      expect(result.status).not.toBe(0)
      expect(existsSync(OUTSIDE_WORKSPACE_FILE)).toBe(false)
    })

    it('should block writes outside workspace when /tmp/claude is a regular directory', () => {
      // Create /tmp/claude as a regular directory
      cleanupTmpClaude()
      mkdirSync('/tmp/claude', { recursive: true })

      const stat = lstatSync('/tmp/claude')
      expect(stat.isDirectory()).toBe(true)
      expect(stat.isSymbolicLink()).toBe(false)

      const writeConfig: FsWriteRestrictionConfig = {
        allowOnly: [WORKSPACE_DIR, '/tmp/claude', '/private/tmp/claude'],
        denyWithinAllow: [],
      }

      const wrappedCommand = wrapCommandWithSandboxMacOS({
        command: `echo "test" > ${OUTSIDE_WORKSPACE_FILE}`,
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig,
      })

      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // Should fail - can't write outside workspace
      expect(result.status).not.toBe(0)
      expect(existsSync(OUTSIDE_WORKSPACE_FILE)).toBe(false)
    })

    it('should block writes via symlink traversal path', () => {
      // Create symlink /tmp/claude -> /
      cleanupTmpClaude()
      spawnSync('ln', ['-s', '/', '/tmp/claude'], { encoding: 'utf8' })

      const stat = lstatSync('/tmp/claude')
      expect(stat.isSymbolicLink()).toBe(true)

      // This file path goes through /tmp/claude (the symlink) to reach a location
      // that would be outside the allowed write paths if symlink was followed
      const traversalPath =
        '/tmp/claude/tmp/traversal-write-' + TEST_ID + '.txt'

      const writeConfig: FsWriteRestrictionConfig = {
        allowOnly: [WORKSPACE_DIR, '/tmp/claude', '/private/tmp/claude'],
        denyWithinAllow: [],
      }

      const wrappedCommand = wrapCommandWithSandboxMacOS({
        command: `echo "test" > ${traversalPath}`,
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig,
      })

      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // The sandbox should NOT resolve /tmp/claude to / in the profile
      const realPath = `/tmp/traversal-write-${TEST_ID}.txt`

      expect(result.status).not.toBe(0)
      expect(existsSync(realPath)).toBe(false)
      console.log('✓ Symlink traversal write blocked')
    })
  })

  describe('isSymlinkOutsideBoundary Integration', () => {
    it('should reject symlink resolution that broadens scope', () => {
      // Create symlink pointing to root
      cleanupTmpClaude()
      spawnSync('ln', ['-s', '/', '/tmp/claude'], { encoding: 'utf8' })

      const writeConfig: FsWriteRestrictionConfig = {
        allowOnly: [WORKSPACE_DIR, '/tmp/claude', '/private/tmp/claude'],
        denyWithinAllow: [],
      }

      // Writing outside workspace should fail regardless of symlink state
      const wrappedCommand = wrapCommandWithSandboxMacOS({
        command: `echo "should fail" > ${OUTSIDE_WORKSPACE_FILE}`,
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig,
      })

      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      console.log('\nTesting symlink boundary validation:')
      console.log(`Exit code: ${result.status}`)
      console.log(`File exists: ${existsSync(OUTSIDE_WORKSPACE_FILE)}`)

      expect(result.status).not.toBe(0)
      expect(existsSync(OUTSIDE_WORKSPACE_FILE)).toBe(false)
      console.log('✓ Symlink boundary validation working correctly')
    })
  })
})

/**
 * Unit tests for isSymlinkOutsideBoundary() function
 */
describe('isSymlinkOutsideBoundary Unit Tests', () => {
  describe('Outside Boundary Detection', () => {
    it('should detect when symlink points to root', () => {
      expect(isSymlinkOutsideBoundary('/tmp/claude', '/')).toBe(true)
      expect(isSymlinkOutsideBoundary('/private/tmp/claude', '/')).toBe(true)
      expect(isSymlinkOutsideBoundary('/home/user/data', '/')).toBe(true)
    })

    it('should detect when symlink points to ancestor directory', () => {
      expect(isSymlinkOutsideBoundary('/tmp/claude/data', '/tmp')).toBe(true)
      expect(isSymlinkOutsideBoundary('/tmp/claude/data', '/tmp/claude')).toBe(
        true,
      )
      expect(isSymlinkOutsideBoundary('/home/user/project/src', '/home')).toBe(
        true,
      )
      expect(
        isSymlinkOutsideBoundary('/home/user/project/src', '/home/user'),
      ).toBe(true)
    })

    it('should detect when resolved path is very short', () => {
      expect(isSymlinkOutsideBoundary('/tmp/claude', '/tmp')).toBe(true)
      expect(isSymlinkOutsideBoundary('/var/data', '/var')).toBe(true)
      expect(isSymlinkOutsideBoundary('/usr/local/bin', '/usr')).toBe(true)
    })

    it('should detect when symlink points to unrelated directory', () => {
      // Symlink pointing to home directory or other unrelated paths
      expect(isSymlinkOutsideBoundary('/tmp/claude', '/Users/dworken')).toBe(
        true,
      )
      expect(isSymlinkOutsideBoundary('/tmp/claude', '/home/user')).toBe(true)
      expect(isSymlinkOutsideBoundary('/tmp/claude', '/etc')).toBe(true)
      expect(isSymlinkOutsideBoundary('/tmp/claude', '/opt/data')).toBe(true)
      expect(isSymlinkOutsideBoundary('/var/data', '/Users/someone/data')).toBe(
        true,
      )
    })
  })

  describe('Valid Resolutions', () => {
    it('should allow resolution to same path', () => {
      expect(isSymlinkOutsideBoundary('/tmp/claude', '/tmp/claude')).toBe(false)
      expect(isSymlinkOutsideBoundary('/home/user', '/home/user')).toBe(false)
    })

    it('should allow macOS /tmp -> /private/tmp canonical resolution', () => {
      expect(
        isSymlinkOutsideBoundary('/tmp/claude', '/private/tmp/claude'),
      ).toBe(false)
      expect(
        isSymlinkOutsideBoundary(
          '/tmp/claude/data',
          '/private/tmp/claude/data',
        ),
      ).toBe(false)
    })

    it('should allow macOS /var -> /private/var canonical resolution', () => {
      expect(
        isSymlinkOutsideBoundary(
          '/var/folders/xx/yy',
          '/private/var/folders/xx/yy',
        ),
      ).toBe(false)
    })

    it('should allow resolution to deeper path (more specific)', () => {
      expect(
        isSymlinkOutsideBoundary('/tmp/claude', '/tmp/claude/actual'),
      ).toBe(false)
      expect(isSymlinkOutsideBoundary('/home/user', '/home/user/real')).toBe(
        false,
      )
    })
  })

  describe('Edge Cases', () => {
    it('should handle paths with trailing slashes', () => {
      // path.normalize removes trailing slashes, so these should work
      expect(isSymlinkOutsideBoundary('/tmp/claude/', '/')).toBe(true)
    })

    it('should handle private paths resolving to themselves', () => {
      expect(
        isSymlinkOutsideBoundary('/private/tmp/claude', '/private/tmp/claude'),
      ).toBe(false)
      expect(
        isSymlinkOutsideBoundary('/private/var/data', '/private/var/data'),
      ).toBe(false)
    })
  })
})

describe('isAtOrUnder', () => {
  it('contains by path segment, root included', () => {
    expect(isAtOrUnder('/a/b', '/a')).toBe(true)
    expect(isAtOrUnder('/a', '/a')).toBe(true)
    expect(isAtOrUnder('/ab', '/a')).toBe(false)
    expect(isAtOrUnder('/x', '/')).toBe(true)
    expect(isAtOrUnder('/', '/')).toBe(true)
    expect(isAtOrUnder('/', '/a')).toBe(false)
  })
})

/**
 * Tests for glob pattern symlink boundary validation
 */
describe.if(isMacOS)('Glob Pattern Symlink Boundary', () => {
  function cleanupTmpClaude(): void {
    const paths = ['/tmp/claude', '/private/tmp/claude']
    for (const p of paths) {
      try {
        const stat = lstatSync(p)
        if (stat.isSymbolicLink() || stat.isFile()) {
          unlinkSync(p)
        } else if (stat.isDirectory()) {
          rmSync(p, { recursive: true, force: true })
        }
      } catch {
        // Path doesn't exist, ignore
      }
    }
  }

  it('should preserve original glob pattern when base directory symlink points to root', () => {
    // Clean up and create symlink
    cleanupTmpClaude()
    spawnSync('ln', ['-s', '/', '/tmp/claude'], { encoding: 'utf8' })

    // Test that glob pattern doesn't resolve to /**
    const result = normalizePathForSandbox('/tmp/claude/**')

    // Should keep original pattern, not resolve to /**
    expect(result).toBe('/tmp/claude/**')
    expect(result).not.toBe('/**')

    // Clean up
    cleanupTmpClaude()
  })

  it('should preserve original glob pattern when base directory symlink points to parent', () => {
    // Clean up and create symlink pointing to /tmp (parent)
    cleanupTmpClaude()
    spawnSync('ln', ['-s', '/tmp', '/tmp/claude'], { encoding: 'utf8' })

    // Test that glob pattern doesn't resolve to /tmp/**
    const result = normalizePathForSandbox('/tmp/claude/**')

    // Should keep original pattern
    expect(result).toBe('/tmp/claude/**')
    expect(result).not.toBe('/tmp/**')

    // Clean up
    cleanupTmpClaude()
  })
})
