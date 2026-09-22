/**
 * Test whichSync, and the search for host-side helpers built on it, in a real
 * Node.js process. The search is one piece of code for Node.js and Bun; this
 * runs it under the runtime the Bun test suite cannot.
 * Run with: node test/utils/which-node-test.mjs
 */

import assert from 'node:assert'
import { spawnSync } from 'node:child_process'
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
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

// Dynamically import the built modules
const { whichSync } = await import('../../dist/utils/which.js')
const { findHostHelper } = await import('../../dist/sandbox/host-helpers.js')

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

// Test 4: The in-process search finds what the `which` command finds
const whichResult = spawnSync('which', ['ls'], { encoding: 'utf8' })
const expectedPath = whichResult.stdout.trim()
assert.strictEqual(
  lsPath,
  expectedPath,
  'whichSync output should match which command',
)
console.log('✓ Output matches which command')

// The remaining tests change PATH, and restore it at the end.
const savedPath = process.env.PATH
const base = realpathSync(mkdtempSync(join(tmpdir(), 'which-node-test-')))
// An executable that leaves `marker` behind if anything ever runs it.
function plant(file, marker) {
  writeFileSync(file, `#!/bin/sh\necho ran > '${marker}'\nexit 0\n`)
  chmodSync(file, 0o755)
}

try {
  // Test 5: No `which` program is run. One planted first on PATH, where a
  // sandboxed command may have left it, must never be executed.
  const planted = join(base, 'planted')
  const whichMarker = join(base, 'which-was-run')
  mkdirSync(planted)
  plant(join(planted, 'which'), whichMarker)
  process.env.PATH = `${planted}:${savedPath}`
  const shPath = whichSync('sh')
  assert.ok(
    !existsSync(whichMarker),
    'the `which` planted first on PATH must not have been executed',
  )
  assert.ok(shPath !== null && /\/sh$/.test(shPath), `found sh at ${shPath}`)
  assert.ok(!shPath.startsWith(planted), 'sh is not taken from the planted dir')
  console.log('✓ Finds sh without running the `which` planted first on PATH')

  // Test 6: First executable regular file; a directory of that name and a
  // file without the execute bit are passed over.
  const asDirectory = join(base, 'as-directory')
  const notExecutable = join(base, 'not-executable')
  const first = join(base, 'first')
  const second = join(base, 'second')
  mkdirSync(join(asDirectory, 'tool'), { recursive: true })
  mkdirSync(notExecutable)
  writeFileSync(join(notExecutable, 'tool'), '#!/bin/sh\n')
  chmodSync(join(notExecutable, 'tool'), 0o644)
  for (const dir of [first, second]) {
    mkdirSync(dir)
    plant(join(dir, 'tool'), join(base, 'unused'))
  }
  process.env.PATH = [asDirectory, notExecutable, first, second].join(':')
  assert.strictEqual(whichSync('tool'), join(first, 'tool'))
  console.log('✓ Takes the first executable regular file of that name')

  // Test 7: A name with a directory part is checked where it is
  assert.strictEqual(whichSync(process.execPath), process.execPath)
  assert.strictEqual(whichSync(join(second, 'tool')), join(second, 'tool'))
  assert.strictEqual(whichSync('/path/that/does/not/exist'), null)
  assert.strictEqual(whichSync(first), null, 'a directory is not a program')
  console.log('✓ Path-qualified names are checked directly, not searched for')

  // Test 8: Nothing on an empty PATH
  process.env.PATH = ''
  assert.strictEqual(whichSync('tool'), null)
  console.log('✓ Finds nothing on an empty PATH')

  // Test 9: A helper this library runs on the host is not taken from a
  // directory the sandboxed command may write, however early on PATH, nor
  // through a link that leads into one.
  const project = join(base, 'project')
  const projectBin = join(project, 'node_modules', '.bin')
  const safe = join(base, 'safe')
  const linked = join(base, 'linked')
  const helperMarker = join(base, 'helper-was-run')
  mkdirSync(projectBin, { recursive: true })
  mkdirSync(safe)
  mkdirSync(linked)
  plant(join(projectBin, 'srt-test-helper'), helperMarker)
  plant(join(safe, 'srt-test-helper'), join(base, 'unused'))
  symlinkSync(
    join(projectBin, 'srt-test-helper'),
    join(linked, 'srt-test-helper'),
  )
  process.env.PATH = [projectBin, linked, safe].join(':')
  assert.strictEqual(
    whichSync('srt-test-helper'),
    join(projectBin, 'srt-test-helper'),
  )
  const search = findHostHelper('srt-test-helper', [project])
  assert.strictEqual(search.path, join(safe, 'srt-test-helper'))
  assert.deepStrictEqual(
    search.skipped.map(s => s.candidate),
    [join(projectBin, 'srt-test-helper'), join(linked, 'srt-test-helper')],
  )
  assert.strictEqual(
    findHostHelper('srt-test-helper', undefined).path,
    join(projectBin, 'srt-test-helper'),
    'no write restriction: the plain search',
  )
  process.env.PATH = [projectBin, linked].join(':')
  assert.strictEqual(findHostHelper('srt-test-helper', [project]).path, null)
  assert.ok(!existsSync(helperMarker), 'no candidate was executed')
  console.log('✓ Host helpers are found outside the allowed write paths')
} finally {
  process.env.PATH = savedPath
  rmSync(base, { recursive: true, force: true })
}

console.log('\n✅ All Node.js tests passed!')
