/**
 * Test whichSync behavior in Node.js environment
 * Run with: node test/utils/which-node-test.mjs
 */

import assert from 'node:assert'
import { spawnSync } from 'node:child_process'
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

// Verify we're running in Node.js, not Bun
assert.strictEqual(
  typeof globalThis.Bun,
  'undefined',
  'This test must run in Node.js, not Bun',
)

console.log('Running whichSync Node.js tests...')

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

// Test 4: The search in this process finds what the which command finds
const whichResult = spawnSync('which', ['ls'], { encoding: 'utf8' })
const expectedPath = whichResult.stdout.trim()
assert.strictEqual(
  lsPath,
  expectedPath,
  'whichSync output should match which command',
)
console.log('✓ Output matches which command')

// Test 5: No which command is run: one first on PATH, where a sandboxed
// command may have left it, would run on the host
const planted = mkdtempSync(join(tmpdir(), 'which-node-test-'))
const savedPath = process.env.PATH
try {
  writeFileSync(join(planted, 'which'), `#!/bin/sh\ntouch '${planted}/ran'\n`, {
    mode: 0o755,
  })
  process.env.PATH = `${planted}:${savedPath}`
  assert.strictEqual(whichSync('ls'), lsPath)
  assert.ok(!existsSync(join(planted, 'ran')), 'the planted which was run')
} finally {
  process.env.PATH = savedPath
  rmSync(planted, { recursive: true, force: true })
}
console.log('✓ Runs no which command')

console.log('\n✅ All Node.js tests passed!')
