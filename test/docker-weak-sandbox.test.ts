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
  // The helper, with the command allowed namespaces of its own: the helper's
  // namespace filter is left out, so the kernel's own refusals show again.
  const CONFIG_NESTED_USERNS = join(WORK, 'srt-nested-userns.json')
  // umount(8) reports through /proc/self/mountinfo, which under the helper
  // belongs to another pid namespace; call the syscall so the kernel's own
  // errno is what the test reads.
  const UMOUNT_PROBE = join(WORK, 'umount-probe.py')
  // A file inside the write root that the policy write-denies: a deny that is
  // a mount over a path the command could otherwise write.
  const PROTECTED = join(ALLOWED, 'protected.txt')
  // What a uid-0 command can do INSTEAD of unmounting a deny: make its copy
  // of the mount tree private, put a tmpfs on a directory it may write, make
  // that the root, and let go of the old root lazily. Every deny is a mount,
  // so in the command's namespace no name is a mount point any more. A
  // lookup through a directory descriptor opened beforehand still crosses
  // the denies (the kernel keeps locked mounts connected inside a tree that
  // was let go lazily), but a RENAME of the denied name does not look through
  // it: it is refused only while that name is a mount point in the caller's
  // own namespace. So the denied file is moved aside and a new one written
  // in its place. None of the four calls needs a new namespace for this
  // caller, which already holds CAP_SYS_ADMIN in the helper's.
  const DISPLACE_PROBE = join(WORK, 'displace-probe.py')
  const NEW_ROOT = join(ALLOWED, 'new-root')
  // The calls the namespace filter refuses that an unmount or a remount does
  // not make: pivot_root, and the newer mount interface. Each with arguments
  // the kernel can only turn down, so that what comes back says who answered.
  // Only a caller holding CAP_SYS_ADMIN over its mount namespace can tell: the
  // kernel says EPERM to anyone else before it looks at them.
  const MOUNT_CALLS_PROBE = join(WORK, 'mount-calls-probe.py')
  const MOUNT_CALLS = [
    'pivot_root',
    'move_mount',
    'fsopen',
    'fsconfig',
    'fsmount',
    'fspick',
  ]
  const UNIX_SOCKET_PROBE = join(WORK, 'unix-socket-probe.py')

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
    writeFileSync(PROTECTED, 'original\n')
    writeFileSync(
      DISPLACE_PROBE,
      [
        'import ctypes, errno, os, sys',
        "libc = ctypes.CDLL('libc.so.6', use_errno=True)",
        'work, new_root = sys.argv[1], sys.argv[2]',
        'MS_REC, MS_PRIVATE, MNT_DETACH = 0x4000, 1 << 18, 2',
        'def step(name, call, *args):',
        '    ctypes.set_errno(0)',
        '    rc = call(*args)',
        '    e = ctypes.get_errno()',
        "    print('%s rc=%d errno=%s' % (name, rc, errno.errorcode.get(e, str(e)) if rc else '-'))",
        '# Opened while the denies are all still in place.',
        "held = os.open(os.path.join(work, 'allowed'), os.O_RDONLY | os.O_DIRECTORY)",
        "step('make-private', libc.mount, None, b'/', None, MS_REC | MS_PRIVATE, None)",
        'os.makedirs(os.path.join(new_root), exist_ok=True)',
        "step('tmpfs', libc.mount, b'tmpfs', new_root.encode(), b'tmpfs', 0, None)",
        "old = os.path.join(new_root, 'old')",
        'try:',
        '    os.mkdir(old)',
        'except OSError:',
        '    pass',
        "step('pivot_root', libc.pivot_root, new_root.encode(), old.encode())",
        'try:',
        "    os.chdir('/')",
        'except OSError:',
        '    pass',
        "step('detach-old-root', libc.umount2, b'/old', MNT_DETACH)",
        '# The denied name moved aside and written afresh, through the descriptor.',
        'try:',
        "    os.rename('protected.txt', 'protected.old', src_dir_fd=held, dst_dir_fd=held)",
        "    fd = os.open('protected.txt', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644, dir_fd=held)",
        "    os.write(fd, b'replaced\\n')",
        "    print('replace-protected: done')",
        'except OSError as e:',
        "    print('replace-protected refused (%s)' % errno.errorcode.get(e.errno, str(e.errno)))",
        '',
      ].join('\n'),
    )
    writeFileSync(
      MOUNT_CALLS_PROBE,
      [
        'import ctypes, errno',
        "libc = ctypes.CDLL('libc.so.6', use_errno=True)",
        'def said(name, call, *args):',
        '    ctypes.set_errno(0)',
        '    rc = call(*args)',
        '    e = ctypes.get_errno()',
        "    print('%s %s' % (name, 'ok' if rc >= 0 else errno.errorcode.get(e, str(e))))",
        '# The old call has a number of its own on each architecture and a name in',
        '# every libc; the new ones share their numbers and have names only in a',
        '# recent one.',
        "said('pivot_root', libc.pivot_root, b'/', b'/')",
        "said('move_mount', libc.syscall, 429, -1, b'', -1, b'', 0)",
        "said('fsopen', libc.syscall, 430, None, 0)",
        "said('fsconfig', libc.syscall, 431, -1, 0, None, None, 0)",
        "said('fsmount', libc.syscall, 432, -1, 0, 0)",
        "said('fspick', libc.syscall, 433, -1, b'', 0)",
        '',
      ].join('\n'),
    )
    writeFileSync(
      UNIX_SOCKET_PROBE,
      [
        'import errno, socket',
        'try:',
        '    socket.socket(socket.AF_UNIX).close()',
        "    print('unix-socket: made')",
        'except OSError as e:',
        "    print('unix-socket: refused %s' % errno.errorcode.get(e.errno, str(e.errno)))",
        '',
      ].join('\n'),
    )
    const policy = {
      filesystem: {
        denyRead: [SECRET],
        allowWrite: [ALLOWED],
        denyWrite: [PROTECTED],
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
      CONFIG_NESTED_USERNS,
      JSON.stringify({
        ...policy,
        allowNestedUserNamespaces: true,
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

  // Allowing a command namespaces of its own leaves out the namespace filter
  // and nothing else: the helper's two filters are separate so that this one
  // stays. The run without the helper shows the probe can tell.
  it('seccomp still blocks AF_UNIX socket creation where namespaces are allowed', () => {
    const probe = `echo SANDBOX-RAN; python3 ${UNIX_SOCKET_PROBE}`
    const r = srt(probe, CONFIG_NESTED_USERNS)
    expect(r.stdout).toContain('SANDBOX-RAN')
    expect(r.stdout).toContain('unix-socket: refused EPERM')

    const control = srt(probe, CONFIG_NO_SECCOMP)
    expect(control.stdout).toContain('SANDBOX-RAN')
    expect(control.stdout).toContain('unix-socket: made')
  })

  // What the dependency check says about the helper it has from the helper,
  // which it runs for that inside bubblewrap and never as this process. Two
  // things about that show only here. This job's /proc is masked the way an
  // unprivileged container's is, so bubblewrap cannot mount a fresh one, and
  // the question must get through without. And the caller is uid 0, which
  // bubblewrap lets keep its capabilities in the new namespace unless told to
  // drop them: a file put in the helper's place says what it was left with.
  it('asks the helper what it supports inside bubblewrap, with no fresh /proc and no capabilities', () => {
    const standIn = join(WORK, 'stand-in-helper')
    writeFileSync(
      standIn,
      [
        '#!/bin/sh',
        'echo "caps=$(sed -n \'s/^CapEff:[[:space:]]*//p\' /proc/self/status)"',
        'echo userns-limit',
        '',
      ].join('\n'),
      { mode: 0o755 },
    )
    const asked = spawnSync(
      'node',
      [
        '-e',
        [
          'Promise.all([',
          "  import('./dist/index.js'),",
          "  import('./dist/sandbox/linux-sandbox-utils.js'),",
          ']).then(([srt, linux]) => {',
          '  const check = srt.SandboxManager.checkDependencies()',
          '  const standIn = linux.probeSeccompHelperFeatures({ applyPath: process.argv[1] })',
          '  console.log(JSON.stringify({',
          '    usernsLimit: check.features.usernsLimit,',
          '    codes: check.details.map(detail => detail.code),',
          '    standIn: standIn === null ? null : [...standIn],',
          '  }))',
          '})',
        ].join('\n'),
        standIn,
      ],
      { encoding: 'utf8', timeout: 30000 },
    )
    if (asked.status !== 0) {
      throw new Error(`the check did not run: ${asked.stderr}`)
    }
    const said = JSON.parse(asked.stdout) as {
      usernsLimit: boolean | 'unknown'
      codes: string[]
      standIn: string[] | null
    }
    expect(said.usernsLimit).toBe(true)
    expect(said.codes).toEqual([])
    expect(said.standIn).toContain('userns-limit')
    expect(said.standIn?.find(word => word.startsWith('caps='))).toMatch(
      /^caps=0+$/,
    )
  })

  // Under the helper the command holds a full capability set in the helper's
  // nested user namespace, and the first thing that refuses the unmount is
  // the helper's namespace filter, which answers every call that changes a
  // mount tree with EPERM before the kernel looks at the mount. For this
  // caller, uid 0, that filter is the barrier that counts: it could raise the
  // user-namespace limit again, and needs no new namespace to try.
  it('leaves the command no way to unmount a deny (seccomp helper)', () => {
    const out = join(DENIED, 'escaped')
    const r = srt(escapeAttempt(out))

    expect(r.stdout).toContain('SANDBOX-RAN')
    expect(r.stdout).toContain('umount2 / rc=-1 errno=EPERM')
    expect(r.stdout).toContain(`umount2 ${SECRET} rc=-1 errno=EPERM`)
    refusedEveryStep(r.stdout)
    expect(r.status).not.toBe(0)
    expect(r.stdout).not.toContain('TOPSECRET')
    expect(existsSync(out)).toBe(false)
  })

  // The calls of that filter which the attempt above does not make. Their
  // control is further down, under the configuration that allows namespaces.
  it('refuses the rest of the calls that change a mount tree (seccomp helper)', () => {
    const r = srt(`echo SANDBOX-RAN; python3 ${MOUNT_CALLS_PROBE}`)
    expect(r.stdout).toContain('SANDBOX-RAN')
    for (const call of MOUNT_CALLS) {
      expect(r.stdout).toMatch(new RegExp(`^${call} EPERM$`, 'm'))
    }
  })

  // This job's /proc is masked the way an unprivileged container's is, so the
  // helper cannot mount a fresh one and the command still sees the helper's
  // outer process, which shares its user namespace. The command holds a full
  // capability set there; what keeps it out of that process is that the
  // helper made itself non-dumpable before it forked.
  it('cannot open the memory of the helper process it can see (seccomp helper)', () => {
    const probe = join(WORK, 'helper-mem-probe.py')
    writeFileSync(
      probe,
      [
        'import os',
        'seen = 0',
        "for pid in filter(str.isdigit, os.listdir('/proc')):",
        '    try:',
        "        name = open('/proc/%s/comm' % pid).read().strip()",
        '    except OSError:',
        '        continue',
        "    if name != 'apply-seccomp' or int(pid) == os.getpid():",
        '        continue',
        '    seen += 1',
        "    for what in ('mem', 'environ'):",
        '        try:',
        "            os.close(os.open('/proc/%s/%s' % (pid, what), os.O_RDWR if what == 'mem' else os.O_RDONLY))",
        "            print('helper %s OPENED' % what)",
        '        except OSError as e:',
        "            print('helper %s refused' % what)",
        "print('helpers-seen=%d' % seen)",
        '',
      ].join('\n'),
    )
    const r = srt(`echo SANDBOX-RAN; python3 ${probe}`)
    expect(r.stdout).toContain('SANDBOX-RAN')
    // If none is visible here the fresh /proc was mounted after all and there
    // is nothing to reach; otherwise every one seen must refuse.
    expect(r.stdout).toMatch(/^helpers-seen=\d+$/m)
    expect(r.stdout).not.toContain('OPENED')
  })

  it('refuses the command a user namespace of its own (seccomp helper)', () => {
    const r = srt('echo SANDBOX-RAN; unshare -U true; echo "unshare-rc=$?"')
    expect(r.stdout).toContain('SANDBOX-RAN')
    expect(r.stdout).toMatch(/^unshare-rc=[1-9][0-9]*$/m)
  })

  // With the filter left out, what refuses a plain unmount is the kernel: the
  // mounts the command inherited were copied across a user-namespace boundary
  // and are locked, which reads EINVAL. The two barriers are separate, and
  // this is the older one still standing on its own. It is not the whole of
  // what this caller can try: see the two cases after the next one.
  it('still has the kernel refuse a plain unmount of a deny (seccomp helper, namespaces allowed)', () => {
    const out = join(DENIED, 'escaped-nested-userns')
    const r = srt(escapeAttempt(out), CONFIG_NESTED_USERNS)

    expect(r.stdout).toContain('SANDBOX-RAN')
    expect(r.stdout).toContain('umount2 / rc=-1 errno=EINVAL')
    expect(r.stdout).toContain(`umount2 ${SECRET} rc=-1 errno=EINVAL`)
    refusedEveryStep(r.stdout)
    expect(r.status).not.toBe(0)
    expect(r.stdout).not.toContain('TOPSECRET')
    expect(existsSync(out)).toBe(false)
  })

  // The same six calls with the filter left out: the kernel looks at the
  // arguments and says what is wrong with them, which is never EPERM for this
  // caller. So EPERM above is the filter, one rule for each.
  it('has the kernel answer the rest of the calls that change a mount tree (seccomp helper, namespaces allowed)', () => {
    const r = srt(
      `echo SANDBOX-RAN; python3 ${MOUNT_CALLS_PROBE}`,
      CONFIG_NESTED_USERNS,
    )
    expect(r.stdout).toContain('SANDBOX-RAN')
    for (const call of MOUNT_CALLS) {
      expect(r.stdout).toMatch(new RegExp(`^${call} E[A-Z]+$`, 'm'))
      expect(r.stdout).not.toMatch(new RegExp(`^${call} EPERM$`, 'm'))
    }
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

  // The route that needs no unmount and, for this caller, no namespace. Under
  // the helper every one of its four calls is one the namespace filter
  // refuses, so it stops at the first and the descriptor leads where it did.
  it('refuses every step of putting another root in place of the denies (seccomp helper)', () => {
    const r = srt(
      `echo SANDBOX-RAN; python3 ${DISPLACE_PROBE} ${WORK} ${NEW_ROOT}`,
    )

    expect(r.stdout).toContain('SANDBOX-RAN')
    for (const step of [
      'make-private',
      'tmpfs',
      'pivot_root',
      'detach-old-root',
    ]) {
      expect(r.stdout).toContain(`${step} rc=-1 errno=EPERM`)
    }
    // The name is still a mount point where the command is, so it stays put.
    expect(r.stdout).toContain('replace-protected refused (EBUSY)')
    expect(readFileSync(PROTECTED, 'utf8')).toBe('original\n')
    expect(existsSync(join(ALLOWED, 'protected.old'))).toBe(false)
  })

  // The control for the case above: with the command allowed namespaces of
  // its own the filter is left out, the same four calls go through, and the
  // denied file is replaced on the host. That is what
  // allowNestedUserNamespaces gives up for a uid-0 caller, and it shows the
  // probe can tell.
  it('lets that through where namespaces are allowed, which is what the option gives up', () => {
    try {
      const r = srt(
        `echo SANDBOX-RAN; python3 ${DISPLACE_PROBE} ${WORK} ${NEW_ROOT}`,
        CONFIG_NESTED_USERNS,
      )

      expect(r.stdout).toContain('SANDBOX-RAN')
      for (const step of [
        'make-private',
        'tmpfs',
        'pivot_root',
        'detach-old-root',
      ]) {
        expect(r.stdout).toContain(`${step} rc=0`)
      }
      expect(r.stdout).toContain('replace-protected: done')
      expect(readFileSync(PROTECTED, 'utf8')).toBe('replaced\n')
      expect(readFileSync(join(ALLOWED, 'protected.old'), 'utf8')).toBe(
        'original\n',
      )
    } finally {
      rmSync(join(ALLOWED, 'protected.old'), { force: true })
      writeFileSync(PROTECTED, 'original\n')
    }
  })
})
