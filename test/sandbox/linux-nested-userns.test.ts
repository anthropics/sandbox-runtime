import { describe, it, expect, beforeEach, afterEach } from 'bun:test'
import { spawn, spawnSync } from 'node:child_process'
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  cleanupBwrapMountPoints,
  wrapCommandWithSandboxLinux,
} from '../../src/sandbox/linux-sandbox-utils.js'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import type { SandboxRuntimeConfig } from '../../src/sandbox/sandbox-config.js'
import { getApplySeccompBinaryPath } from '../../src/sandbox/generate-seccomp-filter.js'
import { isLinux } from '../helpers/platform.js'
import { bwrapCanNamespace } from '../helpers/bwrap-namespace.js'

/**
 * A sandboxed command that can create a user namespace can undo the write
 * denies (see NESTED_USERNS_ENV in linux-sandbox-utils.ts), so it must not be
 * able to unless the caller allows it.
 *
 * CHAIN does the whole thing rather than stopping at the first call, so that
 * the arms which expect it to fail would see the file replaced if it did
 * not, and the arm which allows it shows that it then does replace the file.
 */
const CHAIN = String.raw`
import ctypes, errno, os, platform, sys
libc = ctypes.CDLL(None, use_errno=True)
CLONE_NEWNS, CLONE_NEWUSER = 0x00020000, 0x10000000
MS_REC, MS_PRIVATE, MNT_DETACH = 16384, 1 << 18, 2
PIVOT_ROOT = {'x86_64': 155, 'aarch64': 41}[platform.machine()]
project = sys.argv[1]
uid, gid = os.getuid(), os.getgid()
# Before anything else: a handle on the directory holding the denied file.
holder = os.open(os.path.join(project, '.git'), os.O_PATH | os.O_DIRECTORY)

def name(e):
    return errno.errorcode.get(e, str(e))

def replace():
    try:
        os.rename('config', 'config.aside', src_dir_fd=holder, dst_dir_fd=holder)
        fd = os.open('config', os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644, dir_fd=holder)
        os.write(fd, b'[core]\n\tplanted = true\n')
        os.close(fd)
        return 'replaced'
    except OSError as e:
        return 'refused ' + name(e.errno)

def call(what, rc):
    if rc != 0:
        raise OSError(ctypes.get_errno(), what)

print('in-the-sandbox-namespaces:', replace())
try:
    call('unshare', libc.unshare(CLONE_NEWUSER | CLONE_NEWNS))
    print('new-namespaces: ok')
    open('/proc/self/setgroups', 'w').write('deny')
    open('/proc/self/uid_map', 'w').write('0 %d 1' % uid)
    open('/proc/self/gid_map', 'w').write('0 %d 1' % gid)
    call('make-private', libc.mount(None, b'/', None, MS_REC | MS_PRIVATE, None))
    onto = b'/usr' if os.path.isdir('/usr') else b'/tmp'
    call('tmpfs', libc.mount(b'tmpfs', onto, b'tmpfs', 0, None))
    os.chdir(onto)
    os.mkdir('old')
    call('pivot_root', libc.syscall(PIVOT_ROOT, b'.', b'old'))
    call('detach', libc.umount2(b'/old', MNT_DETACH))
    print('in-its-own-namespaces:', replace())
except OSError as e:
    print('new-namespaces: refused %s at %s' % (name(e.errno), e.strerror))
`

// What the other of the helper's two filters refuses. Allowing a command
// namespaces of its own takes one filter away, not both.
const UNIX_SOCKET = String.raw`
import errno, socket
try:
    socket.socket(socket.AF_UNIX).close()
    print('unix-socket: made')
except OSError as e:
    print('unix-socket: refused', errno.errorcode.get(e.errno, e.errno))
`

describe.if(isLinux)(
  'Linux sandbox — the command stays in the namespaces made for it',
  () => {
    let BASE: string
    let PROJECT: string
    let SCRIPT: string
    const savedCwd = process.cwd()
    const ORIGINAL = '[core]\n\trepositoryformatversion = 0\n'

    const BWRAP_CAN_NAMESPACE = bwrapCanNamespace()
    // Built in CI; absent elsewhere, where the arms that need it must skip
    // visibly rather than quietly run without the seccomp stage.
    const APPLY_SECCOMP = getApplySeccompBinaryPath()
    const PYTHON = Bun.which('python3')
    const CAN_RUN_CHAIN =
      BWRAP_CAN_NAMESPACE &&
      PYTHON !== null &&
      (process.arch === 'x64' || process.arch === 'arm64')

    beforeEach(() => {
      BASE = realpathSync(mkdtempSync(join(tmpdir(), 'nested-userns-')))
      PROJECT = join(BASE, 'project')
      mkdirSync(join(PROJECT, '.git', 'hooks'), { recursive: true })
      writeFileSync(join(PROJECT, '.git', 'config'), ORIGINAL)
      SCRIPT = join(BASE, 'chain.py')
      writeFileSync(SCRIPT, CHAIN)
      process.chdir(PROJECT)
    })

    afterEach(() => {
      process.chdir(savedCwd)
      cleanupBwrapMountPoints({ force: true })
      rmSync(BASE, { recursive: true, force: true })
    })

    function wrap(
      command: string,
      options: {
        allowNestedUserNamespaces?: boolean
        allowAllUnixSockets?: boolean
      } = {},
    ): Promise<string> {
      return wrapCommandWithSandboxLinux({
        command,
        needsNetworkRestriction: false,
        readConfig: { denyOnly: [], allowWithinDeny: [] },
        writeConfig: { allowOnly: [PROJECT], denyWithinAllow: [] },
        ...options,
      })
    }

    function run(command: string, env: NodeJS.ProcessEnv = process.env) {
      return spawnSync(command, {
        shell: true,
        encoding: 'utf8',
        timeout: 30000,
        env,
      })
    }

    const hostConfig = () =>
      readFileSync(join(PROJECT, '.git', 'config'), 'utf8')

    // The seccomp lines of a process's status file, which anyone may read.
    function seccompStatus(pid: number | 'self') {
      const status = readFileSync(`/proc/${pid}/status`, 'utf8')
      const line = (name: string) => {
        const found = new RegExp(`^${name}:\\s*(\\d+)$`, 'm').exec(status)
        return found ? Number(found[1]) : undefined
      }
      return {
        mode: line('Seccomp'),
        // Linux 5.9 and later.
        filters: line('Seccomp_filters'),
        noNewPrivs: line('NoNewPrivs'),
      }
    }

    // Starts the helper on its own with a command that stays a while, and
    // reads those lines for the process that was started: the outer half.
    async function outerHalfSeccompStatus(allowNestedUserNamespaces: boolean) {
      const env = { ...process.env }
      delete env.SRT_ALLOW_NESTED_USERNS
      if (allowNestedUserNamespaces) env.SRT_ALLOW_NESTED_USERNS = '1'
      const child = spawn(APPLY_SECCOMP!, ['/bin/sleep', '3'], {
        stdio: ['ignore', 'ignore', 'pipe'],
        env,
      })
      let stderr = ''
      child.stderr.on('data', (d: Buffer) => (stderr += d.toString()))
      // Listened for from the start: a helper that has already gone by the
      // time the wait below is over emitted its event then.
      const ended = new Promise<string>(resolve => {
        child.once('exit', (code, signal) =>
          resolve(`exited (code=${code}, signal=${signal})`),
        )
        child.once('error', err => resolve(`failed to spawn: ${err.message}`))
      })
      try {
        // Setting up is a handful of system calls.
        const early = await Promise.race([
          ended,
          new Promise<undefined>(resolve => setTimeout(resolve, 500)),
        ])
        if (early !== undefined) {
          throw new Error(
            `the helper ${early} before it could be looked at; stderr: ${stderr.trim() || '(empty)'}`,
          )
        }
        return seccompStatus(child.pid!)
      } finally {
        child.kill('SIGKILL')
        await ended
      }
    }

    // ---- what the wrap emits -------------------------------------------

    it('clears the helper variable on every wrap, whatever is asked for', async () => {
      for (const allowNestedUserNamespaces of [undefined, false, true]) {
        const command = await wrap('true', { allowNestedUserNamespaces })
        expect(command).toContain('--unsetenv SRT_ALLOW_NESTED_USERNS')
      }
    })

    // ---- the helper's outer half ------------------------------------------

    it.if(APPLY_SECCOMP !== null)(
      "the helper's outer half takes the namespaces filter as well, and leaves it out where namespaces are allowed",
      async () => {
        // Counted from what this process is under itself, which a container
        // or a sandboxed shell may have put there.
        const own = seccompStatus('self')
        const kept = await outerHalfSeccompStatus(false)
        expect(kept.mode).toBe(2)
        expect(kept.noNewPrivs).toBe(1)
        if (own.filters !== undefined) {
          expect(kept.filters).toBe(own.filters + 1)
        }
        // The control: nothing is added, so the filter seen above is the
        // one the option takes away.
        const lifted = await outerHalfSeccompStatus(true)
        expect(lifted.mode).toBe(own.mode)
        expect(lifted.filters).toBe(own.filters)
      },
      15000,
    )

    // ---- from the configuration to the wrap -----------------------------

    // On the helper's own command line, which holds against a shell start-up
    // file the caller's environment names (see helperEnvironmentPrefix).
    it.if(APPLY_SECCOMP !== null)(
      'SandboxManager hands the option from its configuration to the wrap',
      async () => {
        const configured = (
          allowNestedUserNamespaces?: boolean,
        ): SandboxRuntimeConfig => ({
          network: { allowedDomains: [], deniedDomains: [] },
          filesystem: { denyRead: [], allowWrite: [PROJECT], denyWrite: [] },
          allowNestedUserNamespaces,
        })
        const before = SandboxManager.getConfig()
        try {
          SandboxManager.updateConfig(configured(true))
          expect(await SandboxManager.wrapWithSandbox('true')).toContain(
            `SRT_ALLOW_NESTED_USERNS=1 ${APPLY_SECCOMP}`,
          )
          SandboxManager.updateConfig(configured())
          expect(await SandboxManager.wrapWithSandbox('true')).toContain(
            `SRT_ALLOW_NESTED_USERNS=0 ${APPLY_SECCOMP}`,
          )
        } finally {
          // The configuration outlives a reset, and the next file's tests.
          SandboxManager.updateConfig(before ?? configured())
        }
      },
    )

    // ---- live ------------------------------------------------------------

    it.if(CAN_RUN_CHAIN && APPLY_SECCOMP !== null)(
      'with the helper: a new user namespace is refused and the denied file is not replaced (live bwrap)',
      async () => {
        // The caller's own environment must not be able to lift it.
        const result = run(await wrap(`${PYTHON} ${SCRIPT} ${PROJECT}`), {
          ...process.env,
          SRT_ALLOW_NESTED_USERNS: '1',
        })
        const said = `${result.stdout}${result.stderr}`
        expect(said).toContain('in-the-sandbox-namespaces: refused EBUSY')
        // EPERM, the filter's answer, which comes before the kernel looks at
        // the limit (that one reads ENOSPC).
        expect(said).toContain('new-namespaces: refused EPERM at unshare')
        expect(said).not.toContain('in-its-own-namespaces: replaced')
        expect(hostConfig()).toBe(ORIGINAL)
      },
      60000,
    )

    it.if(CAN_RUN_CHAIN && APPLY_SECCOMP !== null)(
      'with the helper: both means are in force, each call answered by the filter and not by the kernel (live bwrap)',
      async () => {
        // Every call below is made so that the kernel, asked, would say
        // something other than EPERM to a command with no capabilities: bad
        // arguments are looked at before permission, open_tree of "/" needs
        // none, and a second user namespace under a limit of zero is ENOSPC.
        // So EPERM is the filter, and a filter missing the rule for one of
        // these shows here. The other five (pivot_root, move_mount, fsopen,
        // fsmount, fspick) the kernel itself answers with EPERM for a caller
        // without the capability, so only the generator's test pins them.
        const probe = [
          'import ctypes, errno, os, platform',
          'libc = ctypes.CDLL(None, use_errno=True)',
          'arch = platform.machine()',
          "NR = {'clone': {'x86_64': 56, 'aarch64': 220}[arch], 'setns': {'x86_64': 308, 'aarch64': 268}[arch],",
          "      'unshare': {'x86_64': 272, 'aarch64': 97}[arch], 'clone3': 435, 'open_tree': 428, 'fsconfig': 431,",
          "      'mount_setattr': 442}",
          'def said(label, rc):',
          "    print(label, 'ok' if rc >= 0 else errno.errorcode.get(ctypes.get_errno()))",
          "print('limit', open('/proc/sys/user/max_user_namespaces').read().strip())",
          'NEWUSER, SIGCHLD, AT_FDCWD = 0x10000000, 17, -100',
          "said('unshare', libc.unshare(NEWUSER))",
          // High bits set beside the flag: the rule masks, it does not compare.
          "said('unshare-high-bits', libc.syscall(NR['unshare'], ctypes.c_ulong(NEWUSER | (1 << 40))))",
          "said('clone', libc.syscall(NR['clone'], ctypes.c_ulong(NEWUSER | SIGCHLD), None, None, None, None))",
          "said('clone3', libc.syscall(NR['clone3'], None, 0))",
          "said('setns', libc.syscall(NR['setns'], -1, 0))",
          "said('open_tree', libc.syscall(NR['open_tree'], AT_FDCWD, b'/', 0))",
          "said('mount', libc.mount(None, None, None, 0, None))",
          "said('umount2', libc.umount2(None, 0))",
          // The descriptor is looked at before the caller: EINVAL.
          "said('fsconfig', libc.syscall(NR['fsconfig'], -1, 0, None, None, 0))",
          "said('mount_setattr', libc.syscall(NR['mount_setattr'], -1, b'', 0, None, 0))",
          // Newer than the libseccomp the helper is commonly built with, so
          // it is in the filter by number; a kernel without it says ENOSYS.
          "said('open_tree_attr', libc.syscall(467, AT_FDCWD, b'/', 0, None, 0))",
          // Not refused: a plain fork.
          'pid = os.fork()',
          'if pid == 0: os._exit(0)',
          "said('fork', os.waitpid(pid, 0)[1])",
        ].join('\n')
        writeFileSync(join(BASE, 'probe.py'), probe)
        const result = run(await wrap(`${PYTHON} ${join(BASE, 'probe.py')}`))
        const said = `${result.stdout}${result.stderr}`
        expect(said).toContain('limit 0')
        for (const call of [
          'unshare',
          'unshare-high-bits',
          'clone',
          'setns',
          'open_tree',
          'mount',
          'umount2',
          'fsconfig',
          'mount_setattr',
          'open_tree_attr',
        ]) {
          expect(said).toContain(`${call} EPERM`)
        }
        expect(said).toContain('clone3 ENOSYS')
        expect(said).toContain('fork ok')
      },
      60000,
    )

    it.if(CAN_RUN_CHAIN)(
      "the same calls get the kernel's own answers where nothing refuses them, so EPERM above is the filter (live bwrap)",
      async () => {
        // The control for the test above: no helper, and namespaces allowed,
        // so the filter is not there.
        const probe = [
          'import ctypes, errno, platform',
          'libc = ctypes.CDLL(None, use_errno=True)',
          'arch = platform.machine()',
          'def said(label, rc):',
          "    print(label, 'ok' if rc >= 0 else errno.errorcode.get(ctypes.get_errno()))",
          "said('setns', libc.syscall({'x86_64': 308, 'aarch64': 268}[arch], -1, 0))",
          "said('open_tree', libc.syscall(428, -100, b'/', 0))",
          "said('mount', libc.mount(None, None, None, 0, None))",
          "said('fsconfig', libc.syscall(431, -1, 0, None, None, 0))",
          "said('mount_setattr', libc.syscall(442, -1, b'', 0, None, 0))",
        ].join('\n')
        writeFileSync(join(BASE, 'control.py'), probe)
        writeFileSync(join(BASE, 'unix-socket.py'), UNIX_SOCKET)
        const result = run(
          await wrap(
            `${PYTHON} ${join(BASE, 'control.py')}; ${PYTHON} ${join(BASE, 'unix-socket.py')}`,
            { allowAllUnixSockets: true, allowNestedUserNamespaces: true },
          ),
        )
        const said = `${result.stdout}${result.stderr}`
        expect(said).toContain('setns EBADF')
        expect(said).toContain('open_tree ok')
        expect(said).not.toContain('mount EPERM')
        expect(said).toContain('fsconfig EINVAL')
        expect(said).not.toContain('mount_setattr EPERM')
        // And with neither filter there, a Unix socket can be had.
        expect(said).toContain('unix-socket: made')
      },
      60000,
    )

    it.if(CAN_RUN_CHAIN && APPLY_SECCOMP !== null)(
      'with the helper: threads and child processes still start (live bwrap)',
      async () => {
        const program = [
          'import subprocess, threading',
          'seen = []',
          'threads = [threading.Thread(target=lambda: seen.append(1)) for _ in range(8)]',
          '[t.start() for t in threads]; [t.join() for t in threads]',
          "print('threads', len(seen), subprocess.run(['echo', 'child'], capture_output=True, text=True).stdout.strip())",
        ].join('\n')
        writeFileSync(join(BASE, 'program.py'), program)
        const result = run(await wrap(`${PYTHON} ${join(BASE, 'program.py')}`))
        expect(result.stdout).toContain('threads 8 child')
      },
      60000,
    )

    it.if(CAN_RUN_CHAIN && APPLY_SECCOMP !== null)(
      'with the helper and namespaces allowed: the same chain does replace the file (live bwrap)',
      async () => {
        writeFileSync(join(BASE, 'unix-socket.py'), UNIX_SOCKET)
        const result = run(
          await wrap(
            `echo "seen=[\${SRT_ALLOW_NESTED_USERNS:-unset}]"; ` +
              `${PYTHON} ${join(BASE, 'unix-socket.py')}; ` +
              `${PYTHON} ${SCRIPT} ${PROJECT}`,
            { allowNestedUserNamespaces: true },
          ),
        )
        const said = `${result.stdout}${result.stderr}`
        // The helper was told, and took the variable out before the command.
        expect(said).toContain('seen=[unset]')
        // Only the namespaces filter is left out. The other one stays.
        expect(said).toContain('unix-socket: refused EPERM')
        expect(said).toContain('new-namespaces: ok')
        expect(said).toContain('in-its-own-namespaces: replaced')
        // This is what the refusals above prevent.
        expect(hostConfig()).toContain('planted = true')
      },
      60000,
    )
  },
)
