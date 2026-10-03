/**
 * Test whichSync behavior in Node.js environment
 * Run with: node --experimental-vm-modules test/utils/which-node.test.mjs
 */

import assert from 'node:assert'
import { spawnSync } from 'node:child_process'

// Verify we're running in Node.js, not Bun
assert.strictEqual(
  typeof globalThis.Bun,
  'undefined',
  'This test must run in Node.js, not Bun',
)

console.log('Running whichSync Node.js fallback tests...')

// Build the project first to get the JS output
const buildResult = spawnSync('npm', ['run', 'build'], {
  cwd: process.cwd(),
  stdio: 'inherit',
})

if (buildResult.status !== 0) {
  console.error('Build failed')
  process.exit(1)
}

// Dynamically import the built module
const { whichSync } = await import('../../dist/utils/which.js')

// Test 1: Should find existing executable
const lsPath = whichSync('ls')
assert.ok(lsPath !== null, 'whichSync should find ls')
assert.ok(
  lsPath.includes('/ls'),
  `Expected path to contain /ls, got: ${lsPath}`,
)
console.log('✓ Found ls at:', lsPath)

// Test 2: Should return null for non-existent executable
const nonExistent = whichSync('this-command-definitely-does-not-exist-12345')
assert.strictEqual(
  nonExistent,
  null,
  'Should return null for non-existent command',
)
console.log('✓ Returns null for non-existent command')

// Test 3: Should find bash
const bashPath = whichSync('bash')
assert.ok(bashPath !== null, 'whichSync should find bash')
console.log('✓ Found bash at:', bashPath)

// Test 4: Verify spawnSync is being used (by checking behavior matches which command)
const whichResult = spawnSync('which', ['ls'], { encoding: 'utf8' })
const expectedPath = whichResult.stdout.trim()
assert.strictEqual(
  lsPath,
  expectedPath,
  'whichSync output should match which command',
)
console.log('✓ Output matches which command')

// Test 5: Absolute paths should not depend on an external `which` process
const absoluteNodePath = whichSync(process.execPath)
assert.strictEqual(
  absoluteNodePath,
  process.execPath,
  'whichSync should accept an executable absolute path directly',
)
console.log('✓ Accepted executable absolute path directly')

// Test 6: Missing absolute paths should still be rejected
assert.strictEqual(
  whichSync('/path/that/does/not/exist'),
  null,
  'whichSync should reject a missing absolute path',
)
console.log('✓ Rejected missing absolute path')

console.log('\n✅ All Node.js fallback tests passed!')
