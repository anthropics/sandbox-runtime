import { describe, it, expect, beforeAll, afterAll } from 'bun:test'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import type { SandboxRuntimeConfig } from '../../src/sandbox/sandbox-config.js'
import { wrapCommandWithSandboxLinux } from '../../src/sandbox/linux-sandbox-utils.js'
import { wrapCommandWithSandboxMacOS } from '../../src/sandbox/macos-sandbox-utils.js'
import {
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { isLinux, isMacOS, isSupportedPlatform } from '../helpers/platform.js'

/**
 * Create a test configuration with network access
 */
function createTestConfig(): SandboxRuntimeConfig {
  return {
    network: {
      allowedDomains: ['example.com', 'api.github.com'],
      deniedDomains: [],
    },
    filesystem: {
      denyRead: ['~/.ssh'],
      allowWrite: ['.', '/tmp'],
      denyWrite: ['.env'],
    },
  }
}

describe.if(isSupportedPlatform)('wrapWithSandbox customConfig', () => {
  beforeAll(async () => {
    await SandboxManager.initialize(createTestConfig())
  })

  afterAll(async () => {
    await SandboxManager.reset()
  })

  describe('without customConfig', () => {
    it('uses main config values', async () => {
      const command = 'echo hello'
      const wrapped = await SandboxManager.wrapWithSandbox(command)

      // Should wrap the command (not return it as-is)
      expect(wrapped).not.toBe(command)
      expect(wrapped.length).toBeGreaterThan(command.length)
    })
  })

  describe('with customConfig filesystem overrides', () => {
    it('uses custom allowWrite when provided', async () => {
      const command = 'echo hello'
      const wrapped = await SandboxManager.wrapWithSandbox(command, undefined, {
        filesystem: {
          denyRead: [],
          allowWrite: [], // Override to block all writes
          denyWrite: [],
        },
      })

      // Should still wrap the command
      expect(wrapped).not.toBe(command)
      expect(wrapped.length).toBeGreaterThan(command.length)
    })

    it('uses custom denyRead when provided', async () => {
      const command = 'cat /etc/passwd'
      const wrapped = await SandboxManager.wrapWithSandbox(command, undefined, {
        filesystem: {
          denyRead: ['/etc/passwd'], // Block this specific file
          allowWrite: [],
          denyWrite: [],
        },
      })

      expect(wrapped).not.toBe(command)
    })
  })

  describe('with customConfig network overrides', () => {
    it('keeps proxy routing when the custom allowlist is empty', async () => {
      const command = 'curl https://example.com'
      const wrapped = await SandboxManager.wrapWithSandbox(command, undefined, {
        network: { allowedDomains: [], deniedDomains: [] },
      })

      expect(wrapped).not.toBe(command)
      expect(wrapped).toContain('HTTP_PROXY')
      expect(SandboxManager.getNetworkRestrictionConfig().allowedHosts).toEqual(
        createTestConfig().network.allowedDomains,
      )
    })

    it('uses main config network when customConfig.network is undefined', async () => {
      const command = 'echo hello'
      const wrapped = await SandboxManager.wrapWithSandbox(command, undefined, {
        filesystem: {
          denyRead: [],
          allowWrite: [],
          denyWrite: [],
        },
        // network is not provided, should use main config
      })

      expect(wrapped).not.toBe(command)
    })
  })

  describe('readonly mode simulation', () => {
    it('can restrict writes without replacing session proxy policy', async () => {
      const command = 'ls -la'

      // This is what BashTool passes for readonly commands
      const readonlyConfig = {
        network: {
          allowedDomains: [], // Session proxy policy remains in force
          deniedDomains: [],
        },
        filesystem: {
          denyRead: [],
          allowWrite: [], // Block all writes
          denyWrite: [],
        },
      }

      const wrapped = await SandboxManager.wrapWithSandbox(
        command,
        undefined,
        readonlyConfig,
      )

      // Should wrap the command with restrictions
      expect(wrapped).not.toBe(command)
      expect(wrapped.length).toBeGreaterThan(command.length)
    })
  })

  describe('partial config merging', () => {
    it('only overrides specified filesystem fields', async () => {
      const command = 'echo test'

      // Only override allowWrite, should use main config for denyRead/denyWrite
      const wrapped = await SandboxManager.wrapWithSandbox(command, undefined, {
        filesystem: {
          denyRead: [], // Override denyRead
          allowWrite: ['/custom/path'], // Override allowWrite
          denyWrite: [], // Override denyWrite
        },
      })

      expect(wrapped).not.toBe(command)
    })

    it('accepts custom network lists without changing session policy', async () => {
      const command = 'echo test'

      // Custom domains request routing but do not replace proxy policy.
      const wrapped = await SandboxManager.wrapWithSandbox(command, undefined, {
        network: {
          allowedDomains: ['custom.example.com'],
          deniedDomains: [],
        },
      })

      expect(wrapped).not.toBe(command)
    })
  })
})

// Profile/command generation only. No proxies, native sandbox or Apple Events execution.
describe.if(isMacOS || isLinux)(
  'wrapWithSandbox command-policy overrides',
  () => {
    type Value = boolean | number | string[]
    let directory: string
    let previousCwd: string
    let base: SandboxRuntimeConfig
    const booleanFields = isMacOS
      ? [
          'network.allowAllUnixSockets',
          'network.allowLocalBinding',
          'filesystem.allowGitConfig',
          'allowPty',
          'enableWeakerNetworkIsolation',
          'allowAppleEvents',
        ]
      : [
          'network.allowAllUnixSockets',
          'filesystem.allowGitConfig',
          'enableWeakerNestedSandbox',
        ]
    const cases: { field: string; session: Value; overrides: Value[] }[] = [
      ...booleanFields.flatMap(field => [
        { field, session: false, overrides: [true] },
        { field, session: true, overrides: [false] },
      ]),
      ...(isMacOS
        ? [
            {
              field: 'network.allowMachLookup',
              session: ['com.example.srt.session'],
              overrides: [['com.example.srt.invocation'], []],
            },
            {
              field: 'network.allowUnixSockets',
              session: ['/tmp/srt-session.sock'],
              overrides: [['/tmp/srt-invocation.sock'], []],
            },
          ]
        : [
            { field: 'mandatoryDenySearchDepth', session: 1, overrides: [3] },
            { field: 'mandatoryDenySearchDepth', session: 3, overrides: [1] },
          ]),
    ]

    beforeAll(() => {
      previousCwd = process.cwd()
      directory = realpathSync(mkdtempSync(join(tmpdir(), 'srt-policy-')))
      for (const name of ['.git/hooks', 'reef/cave'])
        mkdirSync(join(directory, name), { recursive: true })
      for (const name of [
        '.git/config',
        'octopus.secret',
        'starfish.lock',
        'reef/cave/.bashrc',
      ])
        writeFileSync(join(directory, name), '')
      process.chdir(directory)
      base = {
        network: { allowedDomains: [], deniedDomains: [] },
        filesystem: {
          denyRead: [join(directory, 'octopus.secret')],
          allowWrite: [directory],
          denyWrite: [join(directory, 'starfish.lock')],
        },
        // Deterministic, non-executed helper prefix. No native helper discovery.
        seccomp: { applyPath: '/srt-profile-only', argv0: 'apply-seccomp' },
      }
    })

    afterAll(async () => {
      try {
        await SandboxManager.reset()
      } finally {
        process.chdir(previousCwd)
        rmSync(directory, { recursive: true, force: true })
      }
    })

    it.each(cases)(
      '$field with session $session',
      async ({ field, session, overrides }) => {
        const policy = withField(base, field, session)
        SandboxManager.updateConfig(policy)
        const original = await SandboxManager.wrapWithSandbox(
          'true',
          '/bin/bash',
        )
        const getters = () => [
          SandboxManager.getAllowUnixSockets(),
          SandboxManager.getAllowLocalBinding(),
          SandboxManager.getAllowMachLookup(),
          SandboxManager.getEnableWeakerNestedSandbox(),
          SandboxManager.getFsWriteConfig(),
        ]
        const sessionGetters = structuredClone(getters())
        const snapshot = structuredClone(SandboxManager.getConfig())
        assertPolicy(original, field, session)
        assertPolicy(
          await SandboxManager.wrapWithSandbox('true', '/bin/bash', {}),
          field,
          session,
        )
        for (const value of overrides) {
          const custom = withField(base, field, value)
          const customSnapshot = structuredClone(custom)
          const wrapped = await SandboxManager.wrapWithSandbox(
            'true',
            '/bin/bash',
            custom,
          )
          assertPolicy(wrapped, field, value)
          expect(wrapped).toContain(join(directory, '.git/hooks'))
          expect(wrapped).toContain(join(directory, 'octopus.secret'))
          expect(wrapped).toContain(join(directory, 'starfish.lock'))
          if (isLinux) {
            expect(wrapped).toContain('--unshare-pid')
            expect(wrapped).toContain('--unshare-user')
          } else {
            expect(wrapped).toContain('(global-name "com.apple.system.logger")')
            expect(wrapped).not.toContain('(allow network*)')
          }
          expect(SandboxManager.getConfig()).toEqual(snapshot)
          expect(getters()).toEqual(sessionGetters)
          expect(custom).toEqual(customSnapshot)
          assertPolicy(
            await SandboxManager.wrapWithSandbox('true', '/bin/bash'),
            field,
            session,
          )
        }
      },
    )

    function assertPolicy(wrapped: string, field: string, value: Value): void {
      if (Array.isArray(value)) {
        const names =
          field === 'network.allowMachLookup'
            ? ['com.example.srt.session', 'com.example.srt.invocation']
            : ['/tmp/srt-session.sock', '/tmp/srt-invocation.sock']
        for (const name of names) {
          const rules =
            field === 'network.allowMachLookup'
              ? [`(allow mach-lookup (global-name "${name}"))`]
              : [
                  `(allow network-bind (local unix-socket (subpath "${name}")))`,
                  `(allow network-outbound (remote unix-socket (subpath "${name}")))`,
                ]
          for (const rule of rules) {
            if (value.includes(name)) expect(wrapped).toContain(rule)
            else expect(wrapped).not.toContain(rule)
          }
        }
        return
      }
      const rules: Record<string, string> = {
        'network.allowAllUnixSockets': isMacOS
          ? '(path-regex #"^/")'
          : 'ARGV0=apply-seccomp',
        'network.allowLocalBinding': '(allow network-bind (local ip "*:*"))',
        'filesystem.allowGitConfig': join(directory, '.git/config'),
        allowPty: '(allow pseudo-tty)',
        enableWeakerNetworkIsolation: '(global-name "com.apple.trustd.agent")',
        allowAppleEvents: '(allow appleevent-send)',
        enableWeakerNestedSandbox: '--bind /proc /proc',
        mandatoryDenySearchDepth: join(directory, 'reef/cave/.bashrc'),
      }
      const enabled =
        field === 'mandatoryDenySearchDepth' ? value === 3 : Boolean(value)
      const inverse =
        field === 'filesystem.allowGitConfig' ||
        (field === 'network.allowAllUnixSockets' && isLinux)
      expect(wrapped.includes(rules[field]!)).toBe(inverse ? !enabled : enabled)
    }

    // Set one field without replacing its enclosing network/filesystem block.
    function withField(
      policy: SandboxRuntimeConfig,
      field: string,
      value: Value,
    ): SandboxRuntimeConfig {
      const result = structuredClone(policy)
      const [section, key] = field.split('.')
      const target = (
        key ? result[section as keyof SandboxRuntimeConfig] : result
      ) as Record<string, unknown>
      target[key ?? section!] = value
      return result
    }
  },
)

/**
 * Tests for restriction pattern semantics
 *
 * These test the platform functions directly to verify:
 * - Read (deny-only): undefined or empty denyOnly = no restrictions
 * - Write (allow-only): undefined = no restrictions, any config = restrictions
 * - Network: needsNetworkRestriction = false means no network sandbox
 */
describe('restriction pattern semantics', () => {
  const command = 'echo hello'

  describe('no sandboxing needed (early return)', () => {
    it.if(isLinux)(
      'returns command unchanged when no restrictions on Linux',
      async () => {
        // No network, empty read deny, no write config = no sandboxing
        const result = await wrapCommandWithSandboxLinux({
          command,
          needsNetworkRestriction: false,
          readConfig: { denyOnly: [] },
          writeConfig: undefined,
        })

        expect(result).toBe(command)
      },
    )

    it.if(isMacOS)(
      'returns command unchanged when no restrictions on macOS',
      () => {
        // No network, empty read deny, no write config = no sandboxing
        const result = wrapCommandWithSandboxMacOS({
          command,
          needsNetworkRestriction: false,
          readConfig: { denyOnly: [] },
          writeConfig: undefined,
        })

        expect(result).toBe(command)
      },
    )

    it.if(isLinux)(
      'returns command unchanged with undefined readConfig on Linux',
      async () => {
        const result = await wrapCommandWithSandboxLinux({
          command,
          needsNetworkRestriction: false,
          readConfig: undefined,
          writeConfig: undefined,
        })

        expect(result).toBe(command)
      },
    )

    it.if(isMacOS)(
      'returns command unchanged with undefined readConfig on macOS',
      () => {
        const result = wrapCommandWithSandboxMacOS({
          command,
          needsNetworkRestriction: false,
          readConfig: undefined,
          writeConfig: undefined,
        })

        expect(result).toBe(command)
      },
    )
  })

  describe('read restrictions (deny-only pattern)', () => {
    it.if(isLinux)(
      'empty denyOnly means no read restrictions on Linux',
      async () => {
        // Only write restrictions, empty read = should sandbox but no read rules
        const result = await wrapCommandWithSandboxLinux({
          command,
          needsNetworkRestriction: false,
          readConfig: { denyOnly: [] },
          writeConfig: { allowOnly: ['/tmp'], denyWithinAllow: [] },
        })

        // Should wrap because of write restrictions
        expect(result).not.toBe(command)
        expect(result).toContain('bwrap')
      },
    )

    it.if(isLinux)(
      'secure branch always passes --unshare-user and --cap-drop ALL',
      async () => {
        // bwrap only auto-creates a userns when EUID != 0; a root parent
        // would otherwise leave the sandboxed command with initial-userns
        // caps and be able to remount over --ro-bind / /. The default
        // (secure) config must force the userns and drop caps explicitly.
        const result = await wrapCommandWithSandboxLinux({
          command,
          needsNetworkRestriction: false,
          readConfig: { denyOnly: [] },
          writeConfig: { allowOnly: ['/tmp'], denyWithinAllow: [] },
        })

        expect(result).toContain('--unshare-user')
        expect(result).toContain('--cap-drop ALL')
      },
    )

    it.if(isLinux)(
      'weaker branch passes --unshare-user and drops capabilities too',
      async () => {
        const result = await wrapCommandWithSandboxLinux({
          command,
          needsNetworkRestriction: false,
          readConfig: { denyOnly: [] },
          writeConfig: { allowOnly: ['/tmp'], denyWithinAllow: [] },
          enableWeakerNestedSandbox: true,
        })

        expect(result).toContain('--unshare-user')
        expect(result).toContain('--cap-drop ALL')
        expect(result).toContain('--bind /proc /proc')
        expect(result).not.toContain('--proc /proc')
        if (process.geteuid?.() !== 0) {
          expect(result).not.toContain('--cap-add')
        }
      },
    )

    it.if(isLinux)(
      'non-empty denyOnly means has read restrictions on Linux',
      async () => {
        const result = await wrapCommandWithSandboxLinux({
          command,
          needsNetworkRestriction: false,
          readConfig: { denyOnly: ['/secret'] },
          writeConfig: undefined,
        })

        // Should wrap because of read restrictions
        expect(result).not.toBe(command)
        expect(result).toContain('bwrap')
      },
    )
  })

  describe('explicit binary paths (Linux)', () => {
    it.if(isLinux)('uses bwrapPath for the outer command', async () => {
      const result = await wrapCommandWithSandboxLinux({
        command,
        needsNetworkRestriction: false,
        readConfig: { denyOnly: [] },
        writeConfig: { allowOnly: ['/tmp'], denyWithinAllow: [] },
        bwrapPath: '/opt/bw/bwrap',
      })

      expect(result.startsWith('/opt/bw/bwrap ')).toBe(true)
      expect(result.startsWith('bwrap ')).toBe(false)
    })

    it.if(isLinux)('uses socatPath inside the sandbox script', async () => {
      const httpSock = join(tmpdir(), `srt-test-http-${process.pid}.sock`)
      const socksSock = join(tmpdir(), `srt-test-socks-${process.pid}.sock`)
      writeFileSync(httpSock, '')
      writeFileSync(socksSock, '')
      try {
        const result = await wrapCommandWithSandboxLinux({
          command,
          needsNetworkRestriction: true,
          httpSocketPath: httpSock,
          socksSocketPath: socksSock,
          readConfig: { denyOnly: [] },
          writeConfig: { allowOnly: ['/tmp'], denyWithinAllow: [] },
          socatPath: '/opt/sc/socat',
        })

        expect(result).toContain('/opt/sc/socat')
        expect(result).toContain('TCP-LISTEN:3128')
      } finally {
        rmSync(httpSock, { force: true })
        rmSync(socksSock, { force: true })
      }
    })
  })

  describe('write restrictions (allow-only pattern)', () => {
    it.if(isLinux)(
      'undefined writeConfig means no write restrictions on Linux',
      async () => {
        // Has read restrictions but no write = should sandbox
        const result = await wrapCommandWithSandboxLinux({
          command,
          needsNetworkRestriction: false,
          readConfig: { denyOnly: ['/secret'] },
          writeConfig: undefined,
        })

        expect(result).not.toBe(command)
      },
    )

    it.if(isLinux)(
      'empty allowOnly means maximally restrictive (has restrictions) on Linux',
      async () => {
        // Empty allowOnly = no writes allowed = has restrictions
        const result = await wrapCommandWithSandboxLinux({
          command,
          needsNetworkRestriction: false,
          readConfig: { denyOnly: [] },
          writeConfig: { allowOnly: [], denyWithinAllow: [] },
        })

        // Should wrap because empty allowOnly is still a restriction
        expect(result).not.toBe(command)
        expect(result).toContain('bwrap')
      },
    )

    it.if(isMacOS)('any writeConfig means has restrictions on macOS', () => {
      const result = wrapCommandWithSandboxMacOS({
        command,
        needsNetworkRestriction: false,
        readConfig: { denyOnly: [] },
        writeConfig: { allowOnly: [], denyWithinAllow: [] },
      })

      // Should wrap because writeConfig is defined
      expect(result).not.toBe(command)
      expect(result).toContain('sandbox-exec')
    })
  })

  describe('network restrictions', () => {
    it.if(isLinux)(
      'needsNetworkRestriction false skips network sandbox on Linux',
      async () => {
        const result = await wrapCommandWithSandboxLinux({
          command,
          needsNetworkRestriction: false,
          readConfig: { denyOnly: ['/secret'] },
          writeConfig: undefined,
        })

        // Should wrap for filesystem but not include network args
        expect(result).not.toBe(command)
        expect(result).not.toContain('--unshare-net')
      },
    )

    it.if(isMacOS)(
      'needsNetworkRestriction false skips network sandbox on macOS',
      () => {
        const result = wrapCommandWithSandboxMacOS({
          command,
          needsNetworkRestriction: false,
          readConfig: { denyOnly: ['/secret'] },
          writeConfig: undefined,
        })

        // Should wrap for filesystem
        expect(result).not.toBe(command)
        expect(result).toContain('sandbox-exec')
      },
    )

    // Tests for the empty allowedDomains fix (CVE fix)
    // Empty allowedDomains should block all network, not allow all
    it.if(isLinux)(
      'needsNetworkRestriction true without proxy sockets blocks all network on Linux',
      async () => {
        // Network restriction enabled but no proxy sockets = block all network
        const result = await wrapCommandWithSandboxLinux({
          command,
          needsNetworkRestriction: true,
          httpSocketPath: undefined, // No proxy available
          socksSocketPath: undefined, // No proxy available
          readConfig: { denyOnly: [] },
          writeConfig: { allowOnly: ['/tmp'], denyWithinAllow: [] },
        })

        // Should wrap with --unshare-net to block all network
        expect(result).not.toBe(command)
        expect(result).toContain('bwrap')
        expect(result).toContain('--unshare-net')
        // Should NOT contain proxy-related environment variables since no proxy
        expect(result).not.toContain('HTTP_PROXY')
      },
    )

    it.if(isMacOS)(
      'needsNetworkRestriction true without proxy ports blocks all network on macOS',
      () => {
        // Network restriction enabled but no proxy ports = block all network
        const result = wrapCommandWithSandboxMacOS({
          command,
          needsNetworkRestriction: true,
          httpProxyPort: undefined, // No proxy available
          socksProxyPort: undefined, // No proxy available
          readConfig: { denyOnly: [] },
          writeConfig: { allowOnly: ['/tmp'], denyWithinAllow: [] },
        })

        // Should wrap with sandbox-exec
        expect(result).not.toBe(command)
        expect(result).toContain('sandbox-exec')
        // The sandbox profile should NOT contain "(allow network*)" since restrictions are enabled
        // Note: We can't easily check the profile content, but we verify it doesn't skip sandboxing
      },
    )

    it.if(isLinux)(
      'needsNetworkRestriction true with proxy allows filtered network on Linux',
      async () => {
        // Create temporary socket files for the test
        const fs = await import('fs')
        const os = await import('os')
        const path = await import('path')
        const tmpDir = os.tmpdir()
        const httpSocket = path.join(tmpDir, `test-http-${Date.now()}.sock`)
        const socksSocket = path.join(tmpDir, `test-socks-${Date.now()}.sock`)

        // Create dummy socket files
        fs.writeFileSync(httpSocket, '')
        fs.writeFileSync(socksSocket, '')

        try {
          const result = await wrapCommandWithSandboxLinux({
            command,
            needsNetworkRestriction: true,
            httpSocketPath: httpSocket,
            socksSocketPath: socksSocket,
            httpProxyPort: 3128,
            socksProxyPort: 1080,
            readConfig: { denyOnly: [] },
            writeConfig: { allowOnly: ['/tmp'], denyWithinAllow: [] },
          })

          // Should wrap with network namespace isolation
          expect(result).not.toBe(command)
          expect(result).toContain('bwrap')
          expect(result).toContain('--unshare-net')
          // Should bind the socket files
          expect(result).toContain(httpSocket)
          expect(result).toContain(socksSocket)
        } finally {
          // Cleanup
          fs.unlinkSync(httpSocket)
          fs.unlinkSync(socksSocket)
        }
      },
    )

    it.if(isMacOS)(
      'needsNetworkRestriction true with proxy allows filtered network on macOS',
      () => {
        const result = wrapCommandWithSandboxMacOS({
          command,
          needsNetworkRestriction: true,
          httpProxyPort: 3128,
          socksProxyPort: 1080,
          readConfig: { denyOnly: [] },
          writeConfig: { allowOnly: ['/tmp'], denyWithinAllow: [] },
        })

        // Should wrap with sandbox-exec and proxy env vars
        expect(result).not.toBe(command)
        expect(result).toContain('sandbox-exec')
        // Should set proxy environment variables
        expect(result).toContain('HTTP_PROXY')
        expect(result).toContain('HTTPS_PROXY')
      },
    )
  })
})

// Empty custom lists still request isolation and proxy routing. They do not
// replace the proxy's session allowlist or prove that traffic is denied.
describe('empty custom allowedDomains network routing', () => {
  const command = 'curl https://example.com'

  describe('SandboxManager.wrapWithSandbox with empty allowedDomains', () => {
    beforeAll(async () => {
      // Initialize with domains so proxy starts, then test with empty customConfig
      await SandboxManager.initialize({
        network: {
          allowedDomains: ['example.com'],
          deniedDomains: [],
        },
        filesystem: {
          denyRead: [],
          allowWrite: ['/tmp'],
          denyWrite: [],
        },
      })
    })

    afterAll(async () => {
      await SandboxManager.reset()
    })

    it.if(isLinux)(
      'empty custom allowedDomains retains network isolation on Linux',
      async () => {
        const result = await SandboxManager.wrapWithSandbox(
          command,
          undefined,
          {
            network: {
              allowedDomains: [], // Session proxy policy remains in force
              deniedDomains: [],
            },
            filesystem: {
              denyRead: [],
              allowWrite: ['/tmp'],
              denyWrite: [],
            },
          },
        )

        // With the fix, empty allowedDomains should trigger network isolation
        expect(result).not.toBe(command)
        expect(result).toContain('bwrap')
        expect(result).toContain('--unshare-net')
      },
    )

    it.if(isMacOS)(
      'empty custom allowedDomains retains network isolation on macOS',
      async () => {
        const result = await SandboxManager.wrapWithSandbox(
          command,
          undefined,
          {
            network: {
              allowedDomains: [], // Session proxy policy remains in force
              deniedDomains: [],
            },
            filesystem: {
              denyRead: [],
              allowWrite: ['/tmp'],
              denyWrite: [],
            },
          },
        )

        // With the fix, empty allowedDomains should trigger sandbox
        expect(result).not.toBe(command)
        expect(result).toContain('sandbox-exec')
      },
    )

    it('non-empty allowedDomains still works correctly', async () => {
      const result = await SandboxManager.wrapWithSandbox(command, undefined, {
        network: {
          allowedDomains: ['example.com'], // Specific domain allowed
          deniedDomains: [],
        },
        filesystem: {
          denyRead: [],
          allowWrite: ['/tmp'],
          denyWrite: [],
        },
      })

      // Should still wrap with sandbox
      expect(result).not.toBe(command)
      // Should have proxy environment variables for filtering
      expect(result).toContain('HTTP_PROXY')
    })

    it('undefined network config in customConfig falls back to main config', async () => {
      const result = await SandboxManager.wrapWithSandbox(command, undefined, {
        // No network config - should fall back to main config which has example.com
        filesystem: {
          denyRead: [],
          allowWrite: ['/tmp'],
          denyWrite: [],
        },
      })

      // Should wrap with sandbox using main config's network settings
      expect(result).not.toBe(command)
      // Main config has example.com, so proxy should be set up
      expect(result).toContain('HTTP_PROXY')
    })
  })
})

describe('allowWrite glob suffix handling', () => {
  const command = 'echo hello'

  it('allowWrite with /** suffix includes path in sandbox command', async () => {
    const testDir = join(tmpdir(), `srt-test-glob-allow-${Date.now()}`)
    mkdirSync(testDir, { recursive: true })

    try {
      await SandboxManager.reset()
      await SandboxManager.initialize({
        network: { allowedDomains: [], deniedDomains: [] },
        filesystem: {
          denyRead: [],
          allowWrite: [`${testDir}/**`],
          denyWrite: [],
        },
      })

      const result = await SandboxManager.wrapWithSandbox(command)

      expect(result).not.toBe(command)
      expect(result).toContain(testDir)
    } finally {
      await SandboxManager.reset()
      rmSync(testDir, { recursive: true, force: true })
    }
  })

  it('denyWrite with /** suffix within allowed parent includes both paths', async () => {
    const parentDir = join(tmpdir(), `srt-test-glob-deny-${Date.now()}`)
    const childDir = join(parentDir, 'denied')
    mkdirSync(childDir, { recursive: true })

    try {
      await SandboxManager.reset()
      await SandboxManager.initialize({
        network: { allowedDomains: [], deniedDomains: [] },
        filesystem: {
          denyRead: [],
          allowWrite: [parentDir],
          denyWrite: [`${childDir}/**`],
        },
      })

      const result = await SandboxManager.wrapWithSandbox(command)

      expect(result).not.toBe(command)
      expect(result).toContain(parentDir)
      expect(result).toContain(childDir)
    } finally {
      await SandboxManager.reset()
      rmSync(parentDir, { recursive: true, force: true })
    }
  })

  // Regression: two denyWrite entries that converge to the same path after
  // normalizePathForSandbox() produced a duplicate --ro-bind /dev/null <dest>.
  // Second bind finds a char device at <dest>; bwrap's ensure_file() doesn't
  // short-circuit on S_ISCHR and falls through to creat() on a read-only mount.
  it.if(isLinux)(
    'dedups denyWrite entries that normalize to the same path (Linux)',
    async () => {
      const parentDir = join(tmpdir(), `srt-test-dup-deny-${Date.now()}`)
      const childFile = join(parentDir, 'dup.txt')
      mkdirSync(parentDir, { recursive: true })
      writeFileSync(childFile, '')

      try {
        await SandboxManager.reset()
        await SandboxManager.initialize({
          network: { allowedDomains: [], deniedDomains: [] },
          filesystem: {
            denyRead: [],
            allowWrite: [parentDir],
            // Trailing slash and bare form both realpath to childFile
            denyWrite: [childFile, childFile + '/'],
          },
        })

        const result = await SandboxManager.wrapWithSandbox(command)

        // One --ro-bind <path> <path> contains the path twice (src + dest);
        // the two spellings of the same file must not each emit a bind.
        const occurrences = result.split(childFile).length - 1
        expect(occurrences).toBe(2)
      } finally {
        await SandboxManager.reset()
        rmSync(parentDir, { recursive: true, force: true })
      }
    },
  )

  // A path in both denyRead and denyWrite: the /dev/null read mask must win.
  // denyWrite's --ro-bind is emitted after the denyRead masks, so a host-file
  // bind at the same destination would re-expose the contents.
  it.if(isLinux)(
    'does not let denyWrite unmask a denyRead /dev/null bind (Linux)',
    async () => {
      const parentDir = join(tmpdir(), `srt-test-unmask-${Date.now()}`)
      const secret = join(parentDir, 'secret.txt')
      mkdirSync(parentDir, { recursive: true })
      writeFileSync(secret, '')

      try {
        await SandboxManager.reset()
        await SandboxManager.initialize({
          network: { allowedDomains: [], deniedDomains: [] },
          filesystem: {
            denyRead: [secret],
            allowWrite: [parentDir],
            denyWrite: [secret],
          },
        })

        const result = await SandboxManager.wrapWithSandbox(command)

        // The /dev/null mask is what we want; the host-file bind is what we don't.
        expect(result).toContain(`--ro-bind /dev/null ${secret}`)
        expect(result).not.toContain(`--ro-bind ${secret} ${secret}`)
      } finally {
        await SandboxManager.reset()
        rmSync(parentDir, { recursive: true, force: true })
      }
    },
  )

  // A file listed in denyRead stays denied even when allowRead covers its
  // parent directory: a containing allow does not absorb a file-level deny.
  it.if(isLinux)(
    'file-level denyRead survives a parent-directory allowRead (Linux)',
    async () => {
      const parentDir = join(tmpdir(), `srt-test-file-deny-${Date.now()}`)
      const secret = join(parentDir, '.env')
      mkdirSync(parentDir, { recursive: true })
      writeFileSync(secret, '')

      try {
        await SandboxManager.reset()
        await SandboxManager.initialize({
          network: { allowedDomains: [], deniedDomains: [] },
          filesystem: {
            denyRead: [secret],
            allowRead: [parentDir],
            allowWrite: [parentDir],
            denyWrite: [],
          },
        })

        const result = await SandboxManager.wrapWithSandbox(command)

        expect(result).toContain(`--ro-bind /dev/null ${secret}`)
      } finally {
        await SandboxManager.reset()
        rmSync(parentDir, { recursive: true, force: true })
      }
    },
  )

  // denyRead entries are sorted shallow-first before mounting, so a file-deny
  // listed before its ancestor dir-deny still lands on top of the ancestor's
  // tmpfs + re-allow binds.
  it.if(isLinux)(
    'file-deny survives ancestor dir-deny listed after it in denyRead (Linux)',
    async () => {
      const parentDir = join(tmpdir(), `srt-test-order-${Date.now()}`)
      const projectDir = join(parentDir, 'project')
      const envFile = join(projectDir, '.env')
      mkdirSync(projectDir, { recursive: true })
      writeFileSync(envFile, '')

      try {
        await SandboxManager.reset()
        await SandboxManager.initialize({
          network: { allowedDomains: [], deniedDomains: [] },
          filesystem: {
            // File deliberately listed before the dir that contains it
            denyRead: [envFile, parentDir],
            allowRead: [projectDir],
            allowWrite: [projectDir],
            denyWrite: [],
          },
        })

        const result = await SandboxManager.wrapWithSandbox(command)

        // The /dev/null mask must come after the tmpfs + ro-bind in arg order.
        const tmpfsAt = result.indexOf(`--tmpfs ${parentDir}`)
        const maskAt = result.indexOf(`--ro-bind /dev/null ${envFile}`)
        expect(tmpfsAt).toBeGreaterThan(-1)
        expect(maskAt).toBeGreaterThan(tmpfsAt)
      } finally {
        await SandboxManager.reset()
        rmSync(parentDir, { recursive: true, force: true })
      }
    },
  )

  // Regression: a directory in both denyRead and denyWrite (e.g. ~/.ssh with
  // Read + Edit/Write deny rules), under an allowed write root, got its
  // denyWrite --ro-bind <dir> <dir> emitted after its own denyRead --tmpfs,
  // exposing the real contents read-only. The tmpfs alone enforces both
  // denies: contents hidden, writes land in the ephemeral tmpfs.
  it.if(isLinux)(
    'denyWrite bind does not re-expose a denyRead tmpfs over the same dir (Linux)',
    async () => {
      const parentDir = join(tmpdir(), `srt-test-dir-both-${Date.now()}`)
      const sshDir = join(parentDir, '.ssh')
      mkdirSync(sshDir, { recursive: true })
      writeFileSync(join(sshDir, 'id_rsa'), '')

      try {
        await SandboxManager.reset()
        await SandboxManager.initialize({
          network: { allowedDomains: [], deniedDomains: [] },
          filesystem: {
            denyRead: [sshDir],
            allowWrite: [parentDir],
            denyWrite: [sshDir],
          },
        })

        const result = await SandboxManager.wrapWithSandbox(command)

        // The tmpfs is what we want; the host-dir bind is what we don't.
        expect(result).toContain(`--tmpfs ${sshDir}`)
        expect(result).not.toContain(`--ro-bind ${sshDir} ${sshDir}`)
      } finally {
        await SandboxManager.reset()
        rmSync(parentDir, { recursive: true, force: true })
      }
    },
  )

  // The ancestor variant of the same stacking bug: a denyWrite dir that
  // contains a denyRead dir re-exposes it when the write-deny ro-bind lands
  // after the tmpfs. The tmpfs must be re-applied on top.
  it.if(isLinux)(
    'denyRead tmpfs survives a denyWrite bind over an ancestor dir (Linux)',
    async () => {
      const parentDir = join(tmpdir(), `srt-test-dir-ancestor-${Date.now()}`)
      const secretsDir = join(parentDir, 'secrets')
      const innerDir = join(secretsDir, 'inner')
      mkdirSync(innerDir, { recursive: true })
      writeFileSync(join(innerDir, 'key.pem'), '')

      try {
        await SandboxManager.reset()
        await SandboxManager.initialize({
          network: { allowedDomains: [], deniedDomains: [] },
          filesystem: {
            denyRead: [innerDir],
            allowWrite: [parentDir],
            denyWrite: [secretsDir],
          },
        })

        const result = await SandboxManager.wrapWithSandbox(command)

        // The write-deny bind on the ancestor stays, and the read-deny tmpfs
        // must land after it in arg order so the kernel stacks it on top.
        const bindAt = result.indexOf(`--ro-bind ${secretsDir} ${secretsDir}`)
        const tmpfsAt = result.lastIndexOf(`--tmpfs ${innerDir}`)
        expect(bindAt).toBeGreaterThan(-1)
        expect(tmpfsAt).toBeGreaterThan(bindAt)
      } finally {
        await SandboxManager.reset()
        rmSync(parentDir, { recursive: true, force: true })
      }
    },
  )

  // File variant of the case above: a read-denied file gets a /dev/null bind,
  // and a denyWrite ro-bind over an ancestor would re-expose the real file.
  // The /dev/null mask must land again after the ancestor bind.
  it.if(isLinux)(
    'denyRead file mask survives a denyWrite bind over an ancestor dir (Linux)',
    async () => {
      const parentDir = join(tmpdir(), `srt-test-file-ancestor-${Date.now()}`)
      const secretsDir = join(parentDir, 'secrets')
      const keyFile = join(secretsDir, 'key.pem')
      mkdirSync(secretsDir, { recursive: true })
      writeFileSync(keyFile, '')

      try {
        await SandboxManager.reset()
        await SandboxManager.initialize({
          network: { allowedDomains: [], deniedDomains: [] },
          filesystem: {
            denyRead: [keyFile],
            allowWrite: [parentDir],
            denyWrite: [secretsDir],
          },
        })

        const result = await SandboxManager.wrapWithSandbox(command)

        const bindAt = result.indexOf(`--ro-bind ${secretsDir} ${secretsDir}`)
        const maskAt = result.lastIndexOf(`--ro-bind /dev/null ${keyFile}`)
        expect(bindAt).toBeGreaterThan(-1)
        expect(maskAt).toBeGreaterThan(bindAt)
      } finally {
        await SandboxManager.reset()
        rmSync(parentDir, { recursive: true, force: true })
      }
    },
  )

  // The #190 case must keep working: a denyRead tmpfs over an ancestor of an
  // allowed write path wipes denyWrite binds under that write path; they are
  // restored by emitting denyWrite after the denyRead re-binds. The tmpfs
  // skip above must not drop them — the write path re-bind re-exposed them.
  it.if(isLinux)(
    'denyWrite under a re-bound write path survives an ancestor denyRead tmpfs (Linux)',
    async () => {
      const parentDir = join(tmpdir(), `srt-test-190-${Date.now()}`)
      const projectDir = join(parentDir, 'project')
      const hooksDir = join(projectDir, 'hooks')
      mkdirSync(hooksDir, { recursive: true })

      try {
        await SandboxManager.reset()
        await SandboxManager.initialize({
          network: { allowedDomains: [], deniedDomains: [] },
          filesystem: {
            denyRead: [parentDir],
            allowWrite: [projectDir],
            denyWrite: [hooksDir],
          },
        })

        const result = await SandboxManager.wrapWithSandbox(command)

        // Order must be: tmpfs ancestor → re-bind write path → deny hooks.
        // The write path is bound twice (allowWrite, then the re-bind after
        // the tmpfs wiped it) — the re-bind is the last occurrence.
        const tmpfsAt = result.indexOf(`--tmpfs ${parentDir}`)
        const rebindAt = result.lastIndexOf(
          `--bind ${projectDir} ${projectDir}`,
        )
        const denyAt = result.indexOf(`--ro-bind ${hooksDir} ${hooksDir}`)
        expect(tmpfsAt).toBeGreaterThan(-1)
        expect(rebindAt).toBeGreaterThan(tmpfsAt)
        expect(denyAt).toBeGreaterThan(rebindAt)
      } finally {
        await SandboxManager.reset()
        rmSync(parentDir, { recursive: true, force: true })
      }
    },
  )
})
