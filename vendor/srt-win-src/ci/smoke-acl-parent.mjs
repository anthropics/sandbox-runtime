// Opt-in ACL-only regression against an EXISTING SRT installation. Never
// installs/uninstalls accounts, changes WFP, or starts a sandboxed command.
// Usage: node smoke-acl-parent.mjs <srt-win.exe> [--profile]
// --profile additionally stamps an owned empty direct child of the real profile;
// use only on an idle test host after the synthetic regressions pass.
import assert from 'node:assert/strict'
import { spawn, spawnSync, execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { once } from 'node:events'
import {
  mkdtempSync,
  mkdirSync,
  writeFileSync,
  readFileSync,
  realpathSync,
  rmSync,
  rmdirSync,
  linkSync,
  lstatSync,
} from 'node:fs'
import { homedir, tmpdir } from 'node:os'
import { basename, dirname, join, resolve } from 'node:path'

assert.equal(process.platform, 'win32', 'Windows only')
assert.ok(process.argv[2], 'Pass the helper executable explicitly')
assert.ok(
  process.argv.length === 3 ||
    (process.argv.length === 4 && process.argv[3] === '--profile'),
)
const helper = realpathSync(resolve(process.argv[2]))
const powershell = join(
  process.env.SystemRoot,
  'System32/WindowsPowerShell/v1.0/powershell.exe',
)
const sha256 = value => createHash('sha256').update(value).digest('hex')
const status = JSON.parse(
  execFileSync(helper, ['user', 'status'], {
    encoding: 'utf8',
    timeout: 15_000,
  }),
)
const sid = status.marker_user_sid
assert.equal(
  status.user?.exists,
  true,
  'An existing SRT installation is required',
)
assert.equal(status.user?.sid, sid, 'Installed account identity mismatch')
assert.match(sid, /^S-1-5-21-(?:\d+-){3}\d+$/)
const report = {
  helperSha256: sha256(readFileSync(helper)),
  cases: [],
  autoInheritanceFlagNormalized: false,
  cleanupComplete: false,
}
const allocations = []
const holders = new Set([process.pid])
const children = []
const hostSnapshots = []
let testFailure
const cleanupFailures = []

function acls(paths) {
  const source = `
    $ErrorActionPreference = 'Stop'
    $rows = @(($env:SRT_ACL_TEST_PATHS | ConvertFrom-Json) | ForEach-Object {
      $acl = Get-Acl -LiteralPath $_
      $entries = @($acl.Access | Where-Object {
        -not $_.IsInherited -and $_.IdentityReference.Translate(
          [System.Security.Principal.SecurityIdentifier]).Value -eq $env:SRT_ACL_TEST_SID
      } | ForEach-Object { [pscustomobject]@{
        type = $_.AccessControlType.ToString(); rights = [int]$_.FileSystemRights
        inheritance = [int]$_.InheritanceFlags
      } })
      [pscustomobject]@{ sddl = $acl.GetSecurityDescriptorSddlForm(
        [System.Security.AccessControl.AccessControlSections]'Owner,Group,Access'); explicit = $entries }
    })
    ConvertTo-Json -InputObject $rows -Depth 5 -Compress
  `
  // A PowerShell 7 parent can export a PSModulePath incompatible with Windows
  // PowerShell 5. Let the child derive its own built-in module search path.
  const env = {
    ...process.env,
    SRT_ACL_TEST_PATHS: JSON.stringify(paths),
    SRT_ACL_TEST_SID: sid,
  }
  for (const key of Object.keys(env)) {
    if (key.toLowerCase() === 'psmodulepath') delete env[key]
  }
  return JSON.parse(
    execFileSync(
      powershell,
      ['-NoProfile', '-NonInteractive', '-Command', source],
      {
        encoding: 'utf8',
        timeout: 15_000,
        env,
      },
    ),
  )
}

function assertRestored(actual, expected) {
  assert.equal(actual.length, expected.length)
  actual.forEach((acl, index) => {
    const before = expected[index]
    assert.deepEqual(acl.explicit, before.explicit)
    if (acl.sddl === before.sddl) return
    // Both Windows security writers can set SE_DACL_AUTO_INHERITED on
    // first use. Permit ONLY that 0 -> 1 transition, and report it. Owner,
    // group, protection (P), inheritance requests (AR), ACE flags/order and
    // masks must match exactly; never clear protection to make cleanup pass.
    const normalized = before.sddl.replace(/D:((?:P|AR)*)(?=\(|$)/, 'D:$1AI')
    assert.notEqual(normalized, before.sddl, 'Unexpected descriptor change')
    assert.equal(acl.sddl, normalized, 'ACL was not restored')
    report.autoInheritanceFlagNormalized = true
  })
}

function call(args, input, expected = 0) {
  const start = performance.now()
  const result = spawnSync(helper, args, {
    input: input === undefined ? undefined : JSON.stringify(input),
    encoding: 'utf8',
    timeout: 15_000,
    maxBuffer: 1024 * 1024,
  })
  assert.ifError(result.error)
  assert.equal(result.status, expected, `helper ${args[1]}: ${result.stderr}`)
  return { elapsedMs: performance.now() - start, stdout: result.stdout }
}
const stamp = (paths, pid = process.pid, expected = 0) =>
  call(
    ['acl', 'stamp', '--holder-pid', String(pid), '--sandbox-user-sid', sid],
    { denyWrite: paths },
    expected,
  )
const restore = pid =>
  call([
    'acl',
    'restore',
    '--holder-pid',
    String(pid),
    '--sandbox-user-sid',
    sid,
    '--json',
  ])

function allocate(parent) {
  const canonicalParent = realpathSync(parent)
  const path = mkdtempSync(join(canonicalParent, 'srt-acl-parent-cli-'))
  assert.equal(realpathSync(path), path)
  const allocation = {
    path,
    parent: canonicalParent,
    paths: [path],
    before: null,
  }
  allocations.push(allocation)
  return allocation
}

async function holder() {
  const child = spawn(
    process.execPath,
    ['-e', 'process.stdin.resume(); setTimeout(() => process.exit(0), 60000)'],
    { stdio: ['pipe', 'ignore', 'inherit'] },
  )
  await once(child, 'spawn')
  holders.add(child.pid)
  children.push(child)
  return child
}

async function stop(child) {
  if (child.exitCode !== null || child.signalCode !== null) return
  const exited = once(child, 'exit')
  child.kill()
  await exited
}

try {
  const fixture = allocate(tmpdir())
  const files = ['a.txt', 'b.txt', 'fresh.txt', 'linked.txt'].map(name =>
    join(fixture.path, name),
  )
  files.forEach(path => writeFileSync(path, 'sentinel', { flag: 'wx' }))
  linkSync(files[3], join(fixture.path, 'alias.txt'))
  fixture.paths.push(...files, join(fixture.path, 'alias.txt'))
  fixture.before = acls(fixture.paths)
  assert.ok(
    fixture.before.every(acl => acl.explicit.length === 0),
    'Unexpected pre-existing sandbox ACE',
  )
  const peer = await holder()
  const measured = stamp(files.slice(0, 2))
  stamp([files[0]], peer.pid)
  const releaseA = JSON.parse(restore(process.pid).stdout)
  assert.ok(releaseA.some(row => row.status === 'stillHeld'))
  let [parent, a, b] = acls(fixture.paths.slice(0, 3))
  assert.deepEqual(parent.explicit, [
    { type: 'Deny', rights: 64, inheritance: 0 },
  ])
  assert.equal(a.explicit.length, 1)
  assert.equal(b.explicit.length, 0)
  restore(peer.pid)
  assertRestored(acls(fixture.paths), fixture.before)
  report.cases.push({
    name: 'multiple-live-holders',
    passed: true,
    stampMs: measured.elapsedMs,
  })

  stamp([files[0]])
  stamp(files.slice(2), process.pid, 1) // Hardlink refusal after a fresh deny.
  ;[parent, a, b] = acls([fixture.path, files[0], files[2]])
  assert.equal(parent.explicit.length, 1)
  assert.equal(a.explicit.length, 1)
  assert.equal(b.explicit.length, 0)
  restore(process.pid)
  assertRestored(acls(fixture.paths), fixture.before)
  report.cases.push({ name: 'failed-batch-rollback', passed: true })

  const doomed = await holder()
  stamp([files[0]], doomed.pid)
  assert.equal(acls([files[0]])[0].explicit.length, 1)
  await stop(doomed)
  const recovery = JSON.parse(call(['acl', 'recover', '--json']).stdout)
  assert.ok(recovery.deadBrokers >= 1)
  assert.ok(recovery.acesRevoked >= 2)
  assertRestored(acls(fixture.paths), fixture.before)
  report.cases.push({ name: 'dead-holder-recovery', passed: true, ...recovery })

  if (process.argv[3] === '--profile') {
    const profile = realpathSync(homedir())
    const profileBefore = acls([profile])[0]
    assert.equal(
      profileBefore.explicit.length,
      0,
      'Profile has existing sandbox holds; use an idle host',
    )
    hostSnapshots.push({ path: profile, before: profileBefore })
    const owned = allocate(profile)
    const nested = join(owned.path, 'nested')
    mkdirSync(nested)
    owned.paths.push(nested)
    owned.before = acls(owned.paths)
    for (const [name, target] of [
      ['nested', nested],
      ['direct-profile-child', owned.path],
    ]) {
      const applied = stamp([target])
      const released = restore(process.pid)
      const profileAfter = acls([profile])[0]
      assertRestored([profileAfter], [profileBefore])
      assertRestored(acls(owned.paths), owned.before)
      report.cases.push({
        name,
        passed: true,
        stampMs: applied.elapsedMs,
        restoreMs: released.elapsedMs,
        profileAclRestored: true,
        profileDescriptorByteEquivalent:
          profileAfter.sddl === profileBefore.sddl,
      })
    }
  }
} catch (error) {
  testFailure = error
} finally {
  for (const pid of holders) {
    try {
      restore(pid)
    } catch (error) {
      cleanupFailures.push(error)
    }
  }
  for (const child of children) {
    try {
      await stop(child)
    } catch (error) {
      cleanupFailures.push(error)
    }
  }
  for (const host of hostSnapshots) {
    try {
      assertRestored(acls([host.path]), [host.before])
    } catch (error) {
      cleanupFailures.push(error)
    }
  }
  for (const allocation of allocations) {
    try {
      assert.equal(
        cleanupFailures.length,
        0,
        'ACL cleanup not acknowledged; preserving fixtures',
      )
      assert.ok(allocation.before, 'Setup incomplete; preserving fixture')
      assertRestored(acls(allocation.paths), allocation.before)
      for (const path of allocation.paths) {
        const entry = lstatSync(path)
        assert.equal(entry.isSymbolicLink(), false)
        if (entry.isFile()) assert.equal(readFileSync(path, 'utf8'), 'sentinel')
      }
      assert.equal(realpathSync(allocation.path), allocation.path)
      assert.equal(dirname(allocation.path), allocation.parent)
      assert.ok(basename(allocation.path).startsWith('srt-acl-parent-cli-'))
      assert.equal(lstatSync(allocation.path).isSymbolicLink(), false)
      if (allocation.parent === realpathSync(homedir())) {
        // The profile case contains only these two owned empty directories.
        rmdirSync(join(allocation.path, 'nested'))
        rmdirSync(allocation.path)
      } else {
        rmSync(allocation.path, { recursive: true })
      }
    } catch (error) {
      cleanupFailures.push(error)
    }
  }
  report.cleanupComplete = cleanupFailures.length === 0
  console.log(JSON.stringify(report, null, 2))
}
if (cleanupFailures.length) {
  throw new AggregateError(
    testFailure ? [testFailure, ...cleanupFailures] : cleanupFailures,
    'ACL cleanup failed; fixtures preserved',
  )
}
if (testFailure) throw testFailure
