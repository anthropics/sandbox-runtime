import { describe, it, expect, beforeEach, afterEach } from 'bun:test'
import { spawnSync } from 'node:child_process'
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
  bwrapCanDisableUserns,
  checkLinuxDependencies,
  cleanupBwrapMountPoints,
  HELPER_FEATURES_PROBE_ARGUMENT,
  planUsernsLimit,
  probeSeccompHelperFeatures,
  wrapCommandWithSandboxLinux,
} from '../../src/sandbox/linux-sandbox-utils.js'
import { getApplySeccompBinaryPath } from '../../src/sandbox/generate-seccomp-filter.js'
import { whichSync } from '../../src/utils/which.js'
import { isLinux } from '../helpers/platform.js'
import { bwrapCanNamespace } from '../helpers/bwrap-namespace.js'

/**
 * A write deny is a read-only bind, and a bind protects a path only in the
 * mount namespace it was made in. Creating a user namespace takes no
 * capability and gives its creator a full set over a private copy of the
 * mount tree, from which every bind can be detached at once; a directory
 * opened beforehand then reaches the denied names with nothing over them. So
 * the sandboxed command must not be able to make one, unless the caller asks
 * for that and takes the consequence.
 *
 * CHAIN below does the whole thing rather than stopping at the first call, so
 * that the arms which expect it to fail would see the file replaced if it did
 * not, and the arm which allows it shows that it then does replace the file:
 * a test of a refusal is worth what its counterpart proves it can detect.
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
    const BWRAP = whichSync('bwrap')
    const BWRAP_DISABLES_USERNS = BWRAP !== null && bwrapCanDisableUserns(BWRAP)

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

    // ---- what the wrap emits -------------------------------------------

    it('clears both of the helper variables on every wrap, whatever is asked for', async () => {
      for (const allowNestedUserNamespaces of [undefined, false, true]) {
        const command = await wrap('true', { allowNestedUserNamespaces })
        expect(command).toContain('--unsetenv SRT_ALLOW_NESTED_USERNS')
        expect(command).toContain('--unsetenv SRT_HELPER_FEATURES')
      }
    })

    it.if(APPLY_SECCOMP !== null)(
      'starts the helper with both variables assigned on its own command line, from the configuration',
      async () => {
        // An assignment before a command holds whatever ran between bubblewrap
        // clearing the variable and the helper starting, a shell start-up
        // file the caller's environment names included.
        const helper = APPLY_SECCOMP!
        expect(await wrap('true')).toContain(
          `SRT_ALLOW_NESTED_USERNS=0 SRT_HELPER_FEATURES=0 ${helper}`,
        )
        expect(
          await wrap('true', { allowNestedUserNamespaces: true }),
        ).toContain(`SRT_ALLOW_NESTED_USERNS=1 SRT_HELPER_FEATURES=0 ${helper}`)
      },
    )

    it.if(BWRAP_DISABLES_USERNS)(
      'gives bubblewrap --disable-userns exactly when there is no helper and namespaces are not allowed',
      async () => {
        expect(await wrap('true', { allowAllUnixSockets: true })).toContain(
          '--disable-userns',
        )
        expect(
          await wrap('true', {
            allowAllUnixSockets: true,
            allowNestedUserNamespaces: true,
          }),
        ).not.toContain('--disable-userns')
      },
    )

    it.if(APPLY_SECCOMP !== null)(
      'never gives bubblewrap --disable-userns beside the helper, which makes a namespace of its own',
      async () => {
        expect(await wrap('true')).not.toContain('--disable-userns')
      },
    )

    // ---- one decision, shared by the wrap and the dependency check ------

    it('decides who imposes the limit in one place', () => {
      const bwrap = BWRAP_DISABLES_USERNS ? BWRAP : null
      const plan = (
        usesSeccompHelper: boolean,
        allowNestedUserNamespaces?: boolean,
        enableWeakerNestedSandbox?: boolean,
      ) =>
        planUsernsLimit({
          usesSeccompHelper,
          allowNestedUserNamespaces,
          enableWeakerNestedSandbox,
          bwrap,
        })
      expect(plan(true)).toEqual({ by: 'helper' })
      // The helper's filter does not depend on /proc/sys being writable.
      expect(plan(true, false, true)).toEqual({ by: 'helper' })
      expect(plan(true, true)).toEqual({ by: 'nobody', because: 'allowed' })
      expect(plan(false, true)).toEqual({ by: 'nobody', because: 'allowed' })
      expect(plan(false, false, true)).toEqual({
        by: 'nobody',
        because: 'weaker-nested-sandbox',
      })
      expect(plan(false)).toEqual(
        bwrap === null
          ? { by: 'nobody', because: 'bwrap-cannot' }
          : { by: 'bwrap' },
      )
    })

    it('the dependency check never reports a limit the wrap would not impose', async () => {
      // No helper and enableWeakerNestedSandbox: bubblewrap is not given the
      // option there, so the check must not say the limit is in force.
      const command = await wrapCommandWithSandboxLinux({
        command: 'true',
        needsNetworkRestriction: false,
        readConfig: { denyOnly: [], allowWithinDeny: [] },
        writeConfig: { allowOnly: [PROJECT], denyWithinAllow: [] },
        allowAllUnixSockets: true,
        enableWeakerNestedSandbox: true,
      })
      expect(command).not.toContain('--disable-userns')
      const check = checkLinuxDependencies({
        allowAllUnixSockets: true,
        enableWeakerNestedSandbox: true,
      })
      expect(check.features?.usernsLimit).toBe(false)
      const detail = (check.details ?? []).find(
        d => d.code === 'no_userns_limit_in_weaker_nested_sandbox',
      )
      expect(detail?.level).toBe('warning')
      expect(check.warnings).toContain(detail?.message ?? 'no such warning')

      // Given up on purpose: not in force, and not worth a warning.
      const allowed = checkLinuxDependencies({
        allowNestedUserNamespaces: true,
      })
      expect(allowed.features?.usernsLimit).toBe(false)
      expect(allowed.details).toEqual([])
    })

    it.if(BWRAP_DISABLES_USERNS)(
      'with no helper, the check reports the limit exactly when the wrap passes bubblewrap the option',
      async () => {
        expect(await wrap('true', { allowAllUnixSockets: true })).toContain(
          '--disable-userns',
        )
        expect(
          checkLinuxDependencies({ allowAllUnixSockets: true }).features
            ?.usernsLimit,
        ).toBe(true)
      },
    )

    // ---- what the helper says about itself -----------------------------

    it.if(APPLY_SECCOMP !== null)(
      'the helper built from this tree reports the limit, and the dependency check passes it on as data',
      () => {
        expect(probeSeccompHelperFeatures()?.has('userns-limit') ?? false).toBe(
          true,
        )
        const check = checkLinuxDependencies()
        expect(check.features?.usernsLimit).toBe(true)
        expect(
          (check.details ?? []).some(
            d => d.code === 'helper_lacks_userns_limit',
          ),
        ).toBe(false)
      },
    )

    it("asks with a name no PATH is searched for, and asks nothing of a helper that is part of the caller's binary", () => {
      // A helper that does not know the question tries to run its argument,
      // on the host. With a slash in it no PATH is searched, and nothing can
      // be created in the root of procfs.
      expect(HELPER_FEATURES_PROBE_ARGUMENT).toMatch(/^\/proc\/[^/]+$/)
      // Its applyPath only has to mean something inside the sandbox, so it is
      // not run from here at all: /bin/true would answer, and is not asked.
      const embedded = { argv0: 'apply-seccomp', applyPath: '/bin/true' }
      expect(probeSeccompHelperFeatures(embedded)).toBeNull()
      expect(
        checkLinuxDependencies({ seccompConfig: embedded }).features
          ?.usernsLimit,
      ).toBe('unknown')
    })

    it('a helper that does not answer the question is reported by code, not only in words', () => {
      // Stands in for one built before the question existed: it ignores the
      // variable and fails to run the name it was given.
      const old = join(BASE, 'old-helper')
      writeFileSync(old, '#!/bin/sh\nexec "$@"\n', { mode: 0o755 })
      expect(probeSeccompHelperFeatures({ applyPath: old })?.size).toBe(0)
      const check = checkLinuxDependencies({
        seccompConfig: { applyPath: old },
      })
      expect(check.features?.usernsLimit).toBe(false)
      const detail = (check.details ?? []).find(
        d => d.code === 'helper_lacks_userns_limit',
      )
      expect(detail?.level).toBe('warning')
      expect(check.warnings).toContain(detail?.message ?? 'no such warning')
      // Not worth a warning to a caller who has given the limit up.
      expect(
        checkLinuxDependencies({
          seccompConfig: { applyPath: old },
          allowNestedUserNamespaces: true,
        }).details,
      ).toEqual([])
    })

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
        // the limit (that one reads ENOSPC, as in the arm with no helper).
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
        // So EPERM is the filter, and a filter missing a rule shows here.
        const probe = [
          'import ctypes, errno, os, platform',
          'libc = ctypes.CDLL(None, use_errno=True)',
          'arch = platform.machine()',
          "NR = {'clone': {'x86_64': 56, 'aarch64': 220}[arch], 'setns': {'x86_64': 308, 'aarch64': 268}[arch],",
          "      'unshare': {'x86_64': 272, 'aarch64': 97}[arch], 'clone3': 435, 'open_tree': 428, 'mount_setattr': 442}",
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
          "said('mount_setattr', libc.syscall(NR['mount_setattr'], -1, b'', 0, None, 0))",
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
          'mount_setattr',
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
        // so neither the filter nor bubblewrap's limit is there.
        const probe = [
          'import ctypes, errno, platform',
          'libc = ctypes.CDLL(None, use_errno=True)',
          'arch = platform.machine()',
          'def said(label, rc):',
          "    print(label, 'ok' if rc >= 0 else errno.errorcode.get(ctypes.get_errno()))",
          "said('setns', libc.syscall({'x86_64': 308, 'aarch64': 268}[arch], -1, 0))",
          "said('open_tree', libc.syscall(428, -100, b'/', 0))",
          "said('mount', libc.mount(None, None, None, 0, None))",
          "said('mount_setattr', libc.syscall(442, -1, b'', 0, None, 0))",
        ].join('\n')
        writeFileSync(join(BASE, 'control.py'), probe)
        const result = run(
          await wrap(`${PYTHON} ${join(BASE, 'control.py')}`, {
            allowAllUnixSockets: true,
            allowNestedUserNamespaces: true,
          }),
        )
        const said = `${result.stdout}${result.stderr}`
        expect(said).toContain('setns EBADF')
        expect(said).toContain('open_tree ok')
        expect(said).not.toContain('mount EPERM')
        expect(said).not.toContain('mount_setattr EPERM')
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
        const result = run(
          await wrap(
            `echo "seen=[\${SRT_ALLOW_NESTED_USERNS:-unset}]"; ${PYTHON} ${SCRIPT} ${PROJECT}`,
            { allowNestedUserNamespaces: true },
          ),
        )
        const said = `${result.stdout}${result.stderr}`
        // The helper was told, and took the variable out again before the
        // command: it is the helper's business, not the command's.
        expect(said).toContain('seen=[unset]')
        expect(said).toContain('new-namespaces: ok')
        expect(said).toContain('in-its-own-namespaces: replaced')
        // This is what the refusals above prevent.
        expect(hostConfig()).toContain('planted = true')
      },
      60000,
    )

    it.if(CAN_RUN_CHAIN && BWRAP_DISABLES_USERNS)(
      'without the helper: bubblewrap refuses the new namespace and the file is not replaced (live bwrap)',
      async () => {
        const result = run(
          await wrap(`${PYTHON} ${SCRIPT} ${PROJECT}`, {
            allowAllUnixSockets: true,
          }),
        )
        const said = `${result.stdout}${result.stderr}`
        expect(said).not.toContain('bwrap:')
        expect(said).toContain('in-the-sandbox-namespaces: refused EBUSY')
        expect(said).toMatch(
          /new-namespaces: refused (ENOSPC|EPERM) at unshare/,
        )
        expect(hostConfig()).toBe(ORIGINAL)
      },
      60000,
    )
  },
)
