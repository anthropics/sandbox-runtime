import { describe, it, expect, afterAll } from 'bun:test'
import { spawnSync } from 'node:child_process'
import {
  wrapCommandWithSandboxLinux,
  cleanupBwrapMountPoints,
  type LinuxSandboxParams,
} from '../../src/sandbox/linux-sandbox-utils.js'
import { quote } from '../../src/utils/shell-quote.js'
import {
  bwrapCanNamespace,
  bwrapCanNamespaceNetwork,
} from '../helpers/bwrap-namespace.js'
import { isLinux } from '../helpers/platform.js'

// Raw syscalls: glibc wraps no keyring call, and keyutils may not be installed.
// The process keyring dies with the probe, so nothing outlives a run.
// setsockopt gets no socket: EBADF means the filter let the call through.
const PROBE = quote([
  'python3',
  '-c',
  `
import ctypes, errno, os
libc = ctypes.CDLL(None, use_errno=True)
add_key, request_key, keyctl, setsockopt = {'x86_64': (248, 249, 250, 54), 'aarch64': (217, 218, 219, 208)}[os.uname().machine]
KEY_SPEC_PROCESS_KEYRING, KEYCTL_GET_KEYRING_ID = -2, 0
SOL_ALG, ALG_SET_KEY, ALG_SET_KEY_BY_KEY_SERIAL = 279, 1, 7
SOL_SOCKET, SO_SNDBUF = 1, 7
def attempt(name, *args):
    result = libc.syscall(*args)
    print(name, 'ok' if result >= 0 else errno.errorcode[ctypes.get_errno()])
attempt('add_key', add_key, b'user', b'srt-test', b'x', 1, KEY_SPEC_PROCESS_KEYRING)
attempt('request_key', request_key, b'user', b'srt-test', None, 0)
attempt('keyctl', keyctl, KEYCTL_GET_KEYRING_ID, KEY_SPEC_PROCESS_KEYRING, 0)
attempt('key_by_serial', setsockopt, -1, SOL_ALG, ALG_SET_KEY_BY_KEY_SERIAL, None, 0)
attempt('key_by_serial_high_level', setsockopt, -1, ctypes.c_long(1 << 32 | SOL_ALG), ALG_SET_KEY_BY_KEY_SERIAL, None, 0)
attempt('key_by_serial_high_option', setsockopt, -1, SOL_ALG, ctypes.c_long(1 << 32 | ALG_SET_KEY_BY_KEY_SERIAL), None, 0)
attempt('own_key', setsockopt, -1, SOL_ALG, ALG_SET_KEY, None, 0)
attempt('so_sndbuf', setsockopt, -1, SOL_SOCKET, SO_SNDBUF, None, 0)
`,
])

const REFUSED = [
  'add_key EPERM',
  'request_key EPERM',
  'keyctl EPERM',
  'key_by_serial EPERM',
  'key_by_serial_high_level EPERM',
  'key_by_serial_high_option EPERM',
  'own_key EBADF',
  'so_sndbuf EBADF',
  '',
].join('\n')

describe.if(isLinux && bwrapCanNamespace())(
  'seccomp filter: kernel keyrings',
  () => {
    afterAll(() => cleanupBwrapMountPoints({ force: true }))

    async function runInSandbox(
      command: string,
      overrides: Partial<LinuxSandboxParams> = {},
    ) {
      const wrapped = await wrapCommandWithSandboxLinux({
        command,
        needsNetworkRestriction: false,
        writeConfig: { allowOnly: [], denyWithinAllow: [] },
        ...overrides,
      })
      return spawnSync('bash', ['-c', wrapped], {
        encoding: 'utf8',
        timeout: 5000,
      })
    }

    async function expectRefused(overrides?: Partial<LinuxSandboxParams>) {
      expect(await runInSandbox(PROBE, overrides)).toMatchObject({
        status: 0,
        stdout: REFUSED,
      })
    }

    it('refuses each call', () => expectRefused())

    it.skipIf(!bwrapCanNamespaceNetwork() || !Bun.which('socat'))(
      'refuses each call when the network is restricted',
      // The relays need only a path that exists: nothing dials them.
      () =>
        expectRefused({
          needsNetworkRestriction: true,
          httpSocketPath: '/dev/null',
          socksSocketPath: '/dev/null',
        }),
    )

    it('refuses each call with nested user namespaces allowed', () =>
      expectRefused({ allowNestedUserNamespaces: true }))

    it('allowAllUnixSockets lifts the rule', async () => {
      expect(
        await runInSandbox(PROBE, { allowAllUnixSockets: true }),
      ).toMatchObject({
        status: 0,
        stdout: [
          'add_key ok',
          'request_key ok',
          'keyctl ok',
          'key_by_serial EBADF',
          'key_by_serial_high_level EBADF',
          'key_by_serial_high_option EBADF',
          'own_key EBADF',
          'so_sndbuf EBADF',
          '',
        ].join('\n'),
      })
    })

    it('leaves ordinary tools working', async () => {
      expect(
        await runInSandbox('node -e 0 && python3 -c pass && git --version'),
      ).toMatchObject({ status: 0 })
    })
  },
)
