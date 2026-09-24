/**
 * End-to-end: run srt as uid 0 inside a container with
 * enableWeakerNestedSandbox and verify the sandbox enforces.
 *
 * Gated on SRT_E2E_DOCKER so `npm test` on the host jobs skips it. CI runs it
 * twice in one container — once holding CAP_SYS_ADMIN, once under
 * `capsh --drop=cap_sys_admin` — because a uid-0 caller is what the
 * capability drop exists for.
 *
 * Invoked by CI via:
 *   docker run --rm \
 *     --security-opt seccomp=unconfined --security-opt apparmor=unconfined \
 *     -v "$PWD:/work" -w /work -e SRT_E2E_DOCKER=1 \
 *     ubuntu:24.04 bash -c '<setup> && bun test test/docker-weak-sandbox.test.ts'
 */

import { describe, it, expect, beforeAll, afterAll } from 'bun:test'
import { spawnSync } from 'node:child_process'
import {
  mkdirSync,
  rmSync,
  writeFileSync,
  readFileSync,
  existsSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const inDocker = process.env.SRT_E2E_DOCKER === '1'

describe.if(inDocker)('srt end-to-end as uid 0 in a container', () => {
  const WORK = join(tmpdir(), `srt-e2e-${Date.now()}`)
  const ALLOWED = join(WORK, 'allowed')
  const DENIED = join(WORK, 'denied')
  const SECRET = join(WORK, 'secret')
  const CONFIG = join(WORK, 'srt.json')
  // Same policy without the seccomp helper: the command then runs in bwrap's
  // own namespaces, where --cap-drop ALL is the only thing between it and the
  // deny mounts.
  const CONFIG_NO_SECCOMP = join(WORK, 'srt-no-seccomp.json')
  // umount(8) reports through /proc/self/mountinfo, which under the helper
  // belongs to another pid namespace; call the syscall so the kernel's own
  // errno is what the test reads.
  const UMOUNT_PROBE = join(WORK, 'umount-probe.py')

  const srt = (cmd: string, config: string = CONFIG) =>
    spawnSync('node', ['dist/cli.js', '-s', config, '-c', cmd], {
      encoding: 'utf8',
      timeout: 15000,
    })

  // Marker first, so a run in which srt never launched cannot pass on the
  // negative assertions alone. Each step then labels its own exit status, so
  // one step succeeding cannot hide behind another's failure, and the script
  // exits with the write's status so `r.status` still reports the escape.
  const escapeAttempt = (out: string) =>
    `echo SANDBOX-RAN; python3 ${UMOUNT_PROBE} / ${SECRET}; ` +
    `mount -o remount,bind,rw / 2>&1; echo "remount-rc=$?"; ` +
    `cat ${join(SECRET, 'key')} 2>&1; echo "read-secret-rc=$?"; ` +
    `echo bad > ${out} 2>&1; w=$?; echo "write-denied-rc=$w"; exit $w`

  // Each labelled step must have failed: present in the output, non-zero.
  const refusedEveryStep = (stdout: string) => {
    expect(stdout).toMatch(/^remount-rc=[1-9][0-9]*$/m)
    expect(stdout).toMatch(/^read-secret-rc=[1-9][0-9]*$/m)
    expect(stdout).toMatch(/^write-denied-rc=[1-9][0-9]*$/m)
  }

  beforeAll(() => {
    mkdirSync(ALLOWED, { recursive: true })
    mkdirSync(DENIED, { recursive: true })
    mkdirSync(SECRET, { recursive: true })
    writeFileSync(join(SECRET, 'key'), 'TOPSECRET')
    writeFileSync(
      UMOUNT_PROBE,
      [
        'import ctypes, errno, os, sys',
        "libc = ctypes.CDLL('libc.so.6', use_errno=True)",
        'for target in sys.argv[1:]:',
        '    ctypes.set_errno(0)',
        '    rc = libc.umount2(target.encode(), 0)',
        '    e = ctypes.get_errno()',
        "    print('umount2 %s rc=%d errno=%s (%s)' % (",
        '        target, rc, errno.errorcode.get(e, str(e)), os.strerror(e)))',
        '',
      ].join('\n'),
    )
    const policy = {
      filesystem: {
        denyRead: [SECRET],
        allowWrite: [ALLOWED],
        denyWrite: [],
      },
      enableWeakerNestedSandbox: true,
    }
    writeFileSync(
      CONFIG,
      JSON.stringify({
        ...policy,
        network: { allowedDomains: [], deniedDomains: [] },
      }),
    )
    writeFileSync(
      CONFIG_NO_SECCOMP,
      JSON.stringify({
        ...policy,
        network: {
          allowedDomains: [],
          deniedDomains: [],
          allowAllUnixSockets: true,
        },
      }),
    )
  })

  afterAll(() => {
    rmSync(WORK, { recursive: true, force: true })
  })

  it('writes to allowWrite dir', () => {
    const out = join(ALLOWED, 'out')
    const r = srt(`echo ok > ${out}`)
    expect(r.status).toBe(0)
    expect(readFileSync(out, 'utf8').trim()).toBe('ok')
  })

  it('blocks write outside allowWrite', () => {
    const out = join(DENIED, 'out')
    const r = srt(`echo bad > ${out}`)
    expect(r.status).not.toBe(0)
    expect(existsSync(out)).toBe(false)
  })

  it('seccomp blocks AF_UNIX socket creation', () => {
    const r = srt('python3 -c "import socket; socket.socket(socket.AF_UNIX)"')
    expect(r.status).not.toBe(0)
    expect(r.stderr.toLowerCase()).toMatch(
      /permission denied|operation not permitted/,
    )
  })

  it('seccomp allows AF_INET socket creation', () => {
    const r = srt('python3 -c "import socket; socket.socket(socket.AF_INET)"')
    expect(r.status).toBe(0)
  })

  // Under the helper the command holds a full capability set in the helper's
  // nested user namespace, so what refuses the unmount is EINVAL: the mounts
  // it inherited were copied across a user-namespace boundary and are locked.
  it('leaves the command no way to unmount a deny (seccomp helper)', () => {
    const out = join(DENIED, 'escaped')
    const r = srt(escapeAttempt(out))

    expect(r.stdout).toContain('SANDBOX-RAN')
    expect(r.stdout).toContain('umount2 / rc=-1 errno=EINVAL')
    expect(r.stdout).toContain(`umount2 ${SECRET} rc=-1 errno=EINVAL`)
    refusedEveryStep(r.stdout)
    expect(r.status).not.toBe(0)
    expect(r.stdout).not.toContain('TOPSECRET')
    expect(existsSync(out)).toBe(false)
  })

  // Without the helper there is no nested namespace and no locked copies:
  // --cap-drop ALL is the whole barrier, and the kernel refuses with EPERM
  // because the command holds no CAP_SYS_ADMIN in bwrap's user namespace.
  it('leaves the command no way to unmount a deny (no seccomp helper)', () => {
    const out = join(DENIED, 'escaped-no-seccomp')
    const r = srt(escapeAttempt(out), CONFIG_NO_SECCOMP)

    expect(r.stdout).toContain('SANDBOX-RAN')
    expect(r.stdout).toContain('umount2 / rc=-1 errno=EPERM')
    expect(r.stdout).toContain(`umount2 ${SECRET} rc=-1 errno=EPERM`)
    refusedEveryStep(r.stdout)
    expect(r.status).not.toBe(0)
    expect(r.stdout).not.toContain('TOPSECRET')
    expect(existsSync(out)).toBe(false)
  })
})
