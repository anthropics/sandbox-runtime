import { describe, test, expect } from 'bun:test'
import { SandboxRuntimeConfigSchema } from '../src/sandbox/sandbox-config.js'

describe('Config Validation', () => {
  const validConfig = {
    network: {
      allowedDomains: [],
      deniedDomains: [],
    },
    filesystem: {
      denyRead: [],
      allowWrite: [],
      denyWrite: [],
    },
  }

  test('should validate a valid minimal config', () => {
    const result = SandboxRuntimeConfigSchema.safeParse(validConfig)
    expect(result.success).toBe(true)
  })

  test('should validate a config with valid domains', () => {
    const config = {
      network: {
        allowedDomains: ['example.com', '*.github.com', 'localhost'],
        deniedDomains: ['evil.com'],
      },
      filesystem: {
        denyRead: [],
        allowWrite: [],
        denyWrite: [],
      },
    }

    const result = SandboxRuntimeConfigSchema.safeParse(config)
    expect(result.success).toBe(true)
  })

  test('should reject invalid domain patterns', () => {
    const config = {
      network: {
        allowedDomains: ['not-a-domain'],
        deniedDomains: [],
      },
      filesystem: {
        denyRead: [],
        allowWrite: [],
        denyWrite: [],
      },
    }

    const result = SandboxRuntimeConfigSchema.safeParse(config)
    expect(result.success).toBe(false)
  })

  test('should reject domain with protocol', () => {
    const config = {
      network: {
        allowedDomains: ['https://example.com'],
        deniedDomains: [],
      },
      filesystem: {
        denyRead: [],
        allowWrite: [],
        denyWrite: [],
      },
    }

    const result = SandboxRuntimeConfigSchema.safeParse(config)
    expect(result.success).toBe(false)
  })

  test('should reject empty filesystem paths', () => {
    const config = {
      network: {
        allowedDomains: [],
        deniedDomains: [],
      },
      filesystem: {
        denyRead: [''],
        allowWrite: [],
        denyWrite: [],
      },
    }

    const result = SandboxRuntimeConfigSchema.safeParse(config)
    expect(result.success).toBe(false)
  })

  test('should validate config with optional fields', () => {
    const config = {
      network: {
        allowedDomains: ['example.com'],
        deniedDomains: [],
        allowUnixSockets: ['/var/run/docker.sock'],
        allowAllUnixSockets: false,
        allowLocalBinding: true,
      },
      filesystem: {
        denyRead: ['/etc/shadow'],
        allowWrite: ['/tmp'],
        denyWrite: ['/etc'],
      },
      ignoreViolations: {
        '*': ['/usr/bin'],
        'git push': ['/usr/bin/nc'],
      },
      enableWeakerNestedSandbox: true,
      enableWeakerNetworkIsolation: false,
    }

    const result = SandboxRuntimeConfigSchema.safeParse(config)
    expect(result.success).toBe(true)
  })

  test('should reject missing required fields', () => {
    const config = {
      network: {
        allowedDomains: [],
      },
      filesystem: {
        denyRead: [],
      },
    }

    const result = SandboxRuntimeConfigSchema.safeParse(config)
    expect(result.success).toBe(false)
  })

  test('should reject unknown top-level keys', () => {
    // A typo like `denyWriteTypo` must fail loudly instead of being
    // silently stripped while the operator believes the policy is
    // enforced (issue #434).
    const config = {
      ...validConfig,
      denyWriteTypo: ['/Users/me'],
    }

    const result = SandboxRuntimeConfigSchema.safeParse(config)
    expect(result.success).toBe(false)
    if (!result.success) {
      const messages = result.error.issues.map(issue => issue.message)
      expect(messages.some(message => message.includes('denyWriteTypo'))).toBe(
        true,
      )
    }
  })

  test('should still reject unknown top-level keys alongside valid config', () => {
    const config = {
      ...validConfig,
      allowEverything: true,
    }

    const result = SandboxRuntimeConfigSchema.safeParse(config)
    expect(result.success).toBe(false)
  })

  test('should validate wildcard domains correctly', () => {
    const validWildcards = ['*.example.com', '*.github.io', '*.co.uk']

    const invalidWildcards = [
      '*example.com', // Missing dot after asterisk
      '*.com', // No subdomain
      '*.', // Invalid format
    ]

    for (const domain of validWildcards) {
      const config = {
        network: { allowedDomains: [domain], deniedDomains: [] },
        filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
      }
      const result = SandboxRuntimeConfigSchema.safeParse(config)
      expect(result.success).toBe(true)
    }

    for (const domain of invalidWildcards) {
      const config = {
        network: { allowedDomains: [domain], deniedDomains: [] },
        filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
      }
      const result = SandboxRuntimeConfigSchema.safeParse(config)
      expect(result.success).toBe(false)
    }
  })

  test('should accept ":port" suffixes on allowed/denied domains', () => {
    const valid = [
      'example.com:443',
      '[::1]',
      '[::1]:443',
      '[2001:db8::1]:8443',
      '*.example.com:8080',
      'localhost:3000',
      'example.com:65535',
      'example.com:1',
    ]
    for (const domain of valid) {
      const result = SandboxRuntimeConfigSchema.safeParse({
        network: { allowedDomains: [domain], deniedDomains: [] },
        filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
      })
      expect(result.success).toBe(true)
    }

    // deniedDomains additionally accepts a bare "*" with a port.
    const denyOnly = SandboxRuntimeConfigSchema.safeParse({
      network: { allowedDomains: [], deniedDomains: ['*:22'] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    })
    expect(denyOnly.success).toBe(true)

    const invalid = [
      'example.com:0', // port out of range → suffix not a port → ":" in host
      'example.com:65536',
      'example.com:0443', // leading zero
      'example.com:abc',
      'example.com:80:443',
      'example.com:', // empty suffix
      '*:22', // "*" is deny-only, still rejected in allowedDomains
      '::1', // IPv6 literals must be bracketed
      'fd00:ec2::254',
      '2001:db8::1:443', // ambiguous — is 443 a port or the last hextet?
      '[::1', // unterminated bracket
      '[::1]:0',
      '[not-an-ip]',
    ]
    for (const domain of invalid) {
      const result = SandboxRuntimeConfigSchema.safeParse({
        network: { allowedDomains: [domain], deniedDomains: [] },
        filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
      })
      expect(result.success).toBe(false)
    }
  })

  test('should validate config with enableWeakerNetworkIsolation', () => {
    const config = {
      network: {
        allowedDomains: ['example.com'],
        deniedDomains: [],
      },
      filesystem: {
        denyRead: [],
        allowWrite: [],
        denyWrite: [],
      },
      enableWeakerNetworkIsolation: true,
    }

    const result = SandboxRuntimeConfigSchema.safeParse(config)
    expect(result.success).toBe(true)
    if (result.success) {
      expect(result.data.enableWeakerNetworkIsolation).toBe(true)
    }
  })

  test('should validate config with allowAppleEvents', () => {
    const config = {
      network: {
        allowedDomains: ['example.com'],
        deniedDomains: [],
      },
      filesystem: {
        denyRead: [],
        allowWrite: [],
        denyWrite: [],
      },
      allowAppleEvents: true,
    }

    const result = SandboxRuntimeConfigSchema.safeParse(config)
    expect(result.success).toBe(true)
    if (result.success) {
      expect(result.data.allowAppleEvents).toBe(true)
    }
  })

  test('should validate config with custom ripgrep command', () => {
    const config = {
      network: {
        allowedDomains: [],
        deniedDomains: [],
      },
      filesystem: {
        denyRead: [],
        allowWrite: [],
        denyWrite: [],
      },
      ripgrep: {
        command: '/usr/local/bin/rg',
      },
    }

    const result = SandboxRuntimeConfigSchema.safeParse(config)
    expect(result.success).toBe(true)
    if (result.success) {
      expect(result.data.ripgrep?.command).toBe('/usr/local/bin/rg')
    }
  })

  test('should validate config with custom ripgrep command and args', () => {
    const config = {
      network: {
        allowedDomains: [],
        deniedDomains: [],
      },
      filesystem: {
        denyRead: [],
        allowWrite: [],
        denyWrite: [],
      },
      ripgrep: {
        command: 'claude',
        args: ['--ripgrep'],
      },
    }

    const result = SandboxRuntimeConfigSchema.safeParse(config)
    expect(result.success).toBe(true)
    if (result.success) {
      expect(result.data.ripgrep?.command).toBe('claude')
      expect(result.data.ripgrep?.args).toEqual(['--ripgrep'])
    }
  })

  test('should accept valid allowMachLookup entries', () => {
    const config = {
      network: {
        allowedDomains: [],
        deniedDomains: [],
        allowMachLookup: [
          '2BUA8C4S2C.com.1password.*',
          'com.apple.CoreSimulator.CoreSimulatorService',
          '*',
        ],
      },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    }

    const result = SandboxRuntimeConfigSchema.safeParse(config)
    expect(result.success).toBe(true)
  })

  test.each(['com.*.foo', 'com.example.**'])(
    'should reject allowMachLookup entry with non-trailing wildcard: %s',
    entry => {
      const config = {
        network: {
          allowedDomains: [],
          deniedDomains: [],
          allowMachLookup: [entry],
        },
        filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
      }

      const result = SandboxRuntimeConfigSchema.safeParse(config)
      expect(result.success).toBe(false)
    },
  )

  test('should use default ripgrep command when not specified', () => {
    const config = {
      network: {
        allowedDomains: [],
        deniedDomains: [],
      },
      filesystem: {
        denyRead: [],
        allowWrite: [],
        denyWrite: [],
      },
    }

    const result = SandboxRuntimeConfigSchema.safeParse(config)
    expect(result.success).toBe(true)
    if (result.success) {
      expect(result.data.ripgrep).toBeUndefined()
    }
  })

  describe('bwrapPath / socatPath', () => {
    const base = {
      network: { allowedDomains: [], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    }

    test('accepts absolute paths', () => {
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        bwrapPath: '/usr/local/bin/bwrap',
        socatPath: '/opt/tools/socat',
      })
      expect(result.success).toBe(true)
    })

    test('rejects relative bwrapPath', () => {
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        bwrapPath: 'bwrap',
      })
      expect(result.success).toBe(false)
      if (!result.success) {
        expect(result.error.issues[0]?.message).toContain('must be absolute')
      }
    })

    test('rejects relative socatPath', () => {
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        socatPath: './bin/socat',
      })
      expect(result.success).toBe(false)
    })

    test('rejects empty bwrapPath', () => {
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        bwrapPath: '',
      })
      expect(result.success).toBe(false)
    })
  })

  describe('credentials', () => {
    const base = {
      network: { allowedDomains: [], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    }

    test('is optional — config without it validates and stays undefined', () => {
      const result = SandboxRuntimeConfigSchema.safeParse(base)
      expect(result.success).toBe(true)
      if (result.success) {
        expect(result.data.credentials).toBeUndefined()
      }
    })

    test('accepts file and env var entries with deny mode', () => {
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        credentials: {
          files: [
            { path: '~/.netrc', mode: 'deny' },
            { path: '~/.aws', mode: 'deny' },
          ],
          envVars: [
            { name: 'AWS_SECRET_ACCESS_KEY', mode: 'deny' },
            { name: 'GH_TOKEN', mode: 'deny' },
          ],
        },
      })
      expect(result.success).toBe(true)
      if (result.success) {
        expect(result.data.credentials?.files).toHaveLength(2)
        expect(result.data.credentials?.envVars).toHaveLength(2)
      }
    })

    test('rejects mode "allow" — no longer a valid mode', () => {
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        credentials: {
          files: [{ path: '~/.aws', mode: 'allow' }],
        },
      })
      expect(result.success).toBe(false)
    })

    test('accepts an empty credentials object', () => {
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        credentials: {},
      })
      expect(result.success).toBe(true)
    })

    test('accepts mode "mask" for files when tlsTerminate is enabled', () => {
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        network: {
          allowedDomains: ['api.github.com'],
          deniedDomains: [],
          tlsTerminate: {},
        },
        credentials: {
          files: [{ path: '~/.config/gh/token', mode: 'mask' }],
        },
      })
      expect(result.success).toBe(true)
    })

    test('rejects mode "mask" for files without tlsTerminate', () => {
      // Same TLS-or-allowPlaintextInject gate as for env vars — the
      // substitution path is identical.
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        network: { allowedDomains: ['api.github.com'], deniedDomains: [] },
        credentials: {
          files: [{ path: '~/.config/gh/token', mode: 'mask' }],
        },
      })
      expect(result.success).toBe(false)
      if (!result.success) {
        const messages = result.error.issues.map(i => i.message).join('\n')
        expect(messages).toContain('tlsTerminate')
      }
    })

    test('injectHosts covered by a port-scoped allowedDomains entry', () => {
      // ":port" narrows the allow to one port but the host is still
      // reachable, so it counts as coverage; injectHosts itself stays
      // host-only.
      const ok = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        network: {
          allowedDomains: ['api.github.com:443'],
          deniedDomains: [],
          tlsTerminate: {},
        },
        credentials: {
          files: [
            {
              path: '~/.config/gh/token',
              mode: 'mask',
              injectHosts: ['api.github.com'],
            },
          ],
        },
      })
      expect(ok.success).toBe(true)

      const bad = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        network: {
          allowedDomains: ['api.github.com:443'],
          deniedDomains: [],
          tlsTerminate: {},
        },
        credentials: {
          files: [
            {
              path: '~/.config/gh/token',
              mode: 'mask',
              injectHosts: ['api.github.com:443'],
            },
          ],
        },
      })
      expect(bad.success).toBe(false)
    })

    test('accepts a masked file with per-entry injectHosts', () => {
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        network: {
          allowedDomains: ['api.github.com'],
          deniedDomains: [],
          tlsTerminate: {},
        },
        credentials: {
          files: [
            {
              path: '~/.config/gh/token',
              mode: 'mask',
              injectHosts: ['api.github.com'],
            },
          ],
        },
      })
      expect(result.success).toBe(true)
    })

    test('rejects a masked file whose per-entry injectHosts is explicitly empty', () => {
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        network: {
          allowedDomains: ['api.github.com'],
          deniedDomains: [],
          tlsTerminate: {},
        },
        credentials: {
          files: [
            { path: '~/.config/gh/token', mode: 'mask', injectHosts: [] },
          ],
        },
      })
      expect(result.success).toBe(false)
      if (!result.success) {
        const messages = result.error.issues.map(i => i.message).join('\n')
        expect(messages).toContain('masked but never injected')
      }
    })

    test('rejects per-entry file injectHosts not reachable via allowedDomains', () => {
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        network: {
          allowedDomains: ['api.github.com'],
          deniedDomains: [],
          tlsTerminate: {},
        },
        credentials: {
          files: [
            {
              path: '~/.npmrc-token',
              mode: 'mask',
              injectHosts: ['registry.npmjs.org'],
            },
          ],
        },
      })
      expect(result.success).toBe(false)
      if (!result.success) {
        const issue = result.error.issues.find(i =>
          i.path.join('.').startsWith('credentials.files.0.injectHosts'),
        )
        expect(issue?.message).toContain('registry.npmjs.org')
        expect(issue?.message).toContain('network.allowedDomains')
      }
    })

    test('accepts a masked file with an extract regex', () => {
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        network: {
          allowedDomains: ['api.github.com'],
          deniedDomains: [],
          tlsTerminate: {},
        },
        credentials: {
          files: [
            {
              path: '~/.config/gh/hosts.yml',
              mode: 'mask',
              extract: 'oauth_token:\\s*(\\S+)',
            },
          ],
        },
      })
      expect(result.success).toBe(true)
    })

    test('rejects an extract value that is not a valid regex', () => {
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        network: {
          allowedDomains: ['api.github.com'],
          deniedDomains: [],
          tlsTerminate: {},
        },
        credentials: {
          files: [
            { path: '~/.config/gh/hosts.yml', mode: 'mask', extract: '(' },
          ],
        },
      })
      expect(result.success).toBe(false)
      if (!result.success) {
        const issue = result.error.issues.find(
          i => i.path.join('.') === 'credentials.files.0.extract',
        )
        expect(issue?.message).toContain('not a valid regular expression')
      }
    })

    test('rejects an extract regex with no capturing group', () => {
      // Group 1 is the contract for "what to mask"; a pattern without
      // one would mask nothing and is almost certainly a mistake.
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        network: {
          allowedDomains: ['api.github.com'],
          deniedDomains: [],
          tlsTerminate: {},
        },
        credentials: {
          files: [
            {
              path: '~/.config/gh/hosts.yml',
              mode: 'mask',
              extract: 'oauth_token:\\s*\\S+',
            },
          ],
        },
      })
      expect(result.success).toBe(false)
      if (!result.success) {
        const issue = result.error.issues.find(
          i => i.path.join('.') === 'credentials.files.0.extract',
        )
        expect(issue?.message).toContain('capturing group')
      }
    })

    test('a non-capturing group does not satisfy the extract group requirement', () => {
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        network: {
          allowedDomains: ['api.github.com'],
          deniedDomains: [],
          tlsTerminate: {},
        },
        credentials: {
          files: [
            { path: '~/.netrc', mode: 'mask', extract: 'password (?:\\S+)' },
          ],
        },
      })
      expect(result.success).toBe(false)
    })

    test('extract on a deny-mode entry is accepted (ignored)', () => {
      // Mirrors the injectHosts-on-deny precedent: harmless, so no error.
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        network: { allowedDomains: ['api.github.com'], deniedDomains: [] },
        credentials: {
          files: [
            { path: '~/.netrc', mode: 'deny', extract: 'password (\\S+)' },
          ],
        },
      })
      expect(result.success).toBe(true)
    })

    test('accepts a masked file with decode "jwt" and no extract', () => {
      // extract is optional with decode — the built-in JWT pattern is used.
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        network: {
          allowedDomains: ['api.github.com'],
          deniedDomains: [],
          tlsTerminate: {},
        },
        credentials: {
          files: [
            { path: '~/.config/app/credentials', mode: 'mask', decode: 'jwt' },
          ],
        },
      })
      expect(result.success).toBe(true)
    })

    test('accepts decode combined with an explicit extract pattern', () => {
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        network: {
          allowedDomains: ['api.github.com'],
          deniedDomains: [],
          tlsTerminate: {},
        },
        credentials: {
          files: [
            {
              path: '~/.config/app/credentials',
              mode: 'mask',
              extract: 'id_token:\\s*(\\S+)',
              decode: 'jwt',
            },
          ],
        },
      })
      expect(result.success).toBe(true)
    })

    test('rejects an unknown decode encoding', () => {
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        network: { allowedDomains: ['api.github.com'], deniedDomains: [] },
        credentials: {
          files: [
            {
              path: '~/.config/app/credentials',
              mode: 'mask',
              decode: 'base64',
            },
          ],
        },
      })
      expect(result.success).toBe(false)
      if (!result.success) {
        const issue = result.error.issues.find(
          i => i.path.join('.') === 'credentials.files.0.decode',
        )
        expect(issue).toBeDefined()
      }
    })

    test('decode on a deny-mode entry is accepted (ignored)', () => {
      // Mirrors the extract/injectHosts-on-deny precedent.
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        network: { allowedDomains: ['api.github.com'], deniedDomains: [] },
        credentials: {
          files: [
            { path: '~/.config/app/credentials', mode: 'deny', decode: 'jwt' },
          ],
        },
      })
      expect(result.success).toBe(true)
    })

    test('accepts maskClaims alongside decode "jwt"', () => {
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        network: {
          allowedDomains: ['api.github.com'],
          deniedDomains: [],
          tlsTerminate: {},
        },
        credentials: {
          files: [
            {
              path: '~/.config/app/credentials',
              mode: 'mask',
              decode: 'jwt',
              maskClaims: ['api_key', 'secret'],
            },
          ],
        },
      })
      expect(result.success).toBe(true)
      if (result.success) {
        expect(result.data.credentials?.files?.[0]?.maskClaims).toEqual([
          'api_key',
          'secret',
        ])
      }
    })

    test('rejects maskClaims without decode', () => {
      // maskClaims names fields inside a decoded payload; without decode
      // there is nothing to look inside.
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        network: {
          allowedDomains: ['api.github.com'],
          deniedDomains: [],
          tlsTerminate: {},
        },
        credentials: {
          files: [
            {
              path: '~/.config/app/credentials',
              mode: 'mask',
              maskClaims: ['api_key'],
            },
          ],
        },
      })
      expect(result.success).toBe(false)
      if (!result.success) {
        const issue = result.error.issues.find(
          i => i.path.join('.') === 'credentials.files.0.maskClaims',
        )
        expect(issue?.message).toContain('requires decode')
      }
    })

    test('rejects an explicitly empty maskClaims', () => {
      // Same posture as an explicitly empty injectHosts.
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        network: {
          allowedDomains: ['api.github.com'],
          deniedDomains: [],
          tlsTerminate: {},
        },
        credentials: {
          files: [
            {
              path: '~/.config/app/credentials',
              mode: 'mask',
              decode: 'jwt',
              maskClaims: [],
            },
          ],
        },
      })
      expect(result.success).toBe(false)
      if (!result.success) {
        const messages = result.error.issues.map(i => i.message).join('\n')
        expect(messages).toContain('explicitly empty')
      }
    })

    test('rejects an empty string in maskClaims', () => {
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        network: {
          allowedDomains: ['api.github.com'],
          deniedDomains: [],
          tlsTerminate: {},
        },
        credentials: {
          files: [
            {
              path: '~/.config/app/credentials',
              mode: 'mask',
              decode: 'jwt',
              maskClaims: [''],
            },
          ],
        },
      })
      expect(result.success).toBe(false)
    })

    test('maskClaims with decode on a deny-mode entry is accepted (ignored)', () => {
      // Mirrors the decode-on-deny precedent: mode "deny" ignores masking
      // options; the decode requirement is structural, not mode-dependent.
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        network: { allowedDomains: ['api.github.com'], deniedDomains: [] },
        credentials: {
          files: [
            {
              path: '~/.config/app/credentials',
              mode: 'deny',
              decode: 'jwt',
              maskClaims: ['api_key'],
            },
          ],
        },
      })
      expect(result.success).toBe(true)
    })

    test.each(['warn', 'deny', 'error'] as const)(
      'accepts onExtractNoMatch: "%s"',
      onExtractNoMatch => {
        const result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          network: {
            allowedDomains: ['api.github.com'],
            deniedDomains: [],
            tlsTerminate: {},
          },
          credentials: {
            files: [
              {
                path: '~/.config/gh/hosts.yml',
                mode: 'mask',
                extract: 'oauth_token:\\s*(\\S+)',
                onExtractNoMatch,
              },
            ],
          },
        })
        expect(result.success).toBe(true)
      },
    )

    test('rejects an invalid onExtractNoMatch value', () => {
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        network: {
          allowedDomains: ['api.github.com'],
          deniedDomains: [],
          tlsTerminate: {},
        },
        credentials: {
          files: [
            {
              path: '~/.config/gh/hosts.yml',
              mode: 'mask',
              extract: 'oauth_token:\\s*(\\S+)',
              onExtractNoMatch: 'ignore',
            },
          ],
        },
      })
      expect(result.success).toBe(false)
      if (!result.success) {
        const issue = result.error.issues.find(
          i => i.path.join('.') === 'credentials.files.0.onExtractNoMatch',
        )
        expect(issue).toBeDefined()
      }
    })

    test('accepts maskDuplicates alongside extract', () => {
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        network: {
          allowedDomains: ['api.github.com'],
          deniedDomains: [],
          tlsTerminate: {},
        },
        credentials: {
          files: [
            {
              path: '~/.config/gh/hosts.yml',
              mode: 'mask',
              extract: 'oauth_token:\\s*(\\S+)',
              maskDuplicates: true,
            },
          ],
        },
      })
      expect(result.success).toBe(true)
      if (result.success) {
        expect(result.data.credentials?.files?.[0]?.maskDuplicates).toBe(true)
      }
    })

    test('maskDuplicates without extract is accepted (ignored)', () => {
      // Mirrors the injectHosts-on-deny precedent: harmless, so no error.
      // Whole-file masking already replaces all content, so the option
      // has nothing to add.
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        network: {
          allowedDomains: ['api.github.com'],
          deniedDomains: [],
          tlsTerminate: {},
        },
        credentials: {
          files: [
            { path: '~/.config/gh/token', mode: 'mask', maskDuplicates: true },
          ],
        },
      })
      expect(result.success).toBe(true)
    })

    test('maskDuplicates on a deny-mode entry is accepted (ignored)', () => {
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        network: { allowedDomains: ['api.github.com'], deniedDomains: [] },
        credentials: {
          files: [{ path: '~/.netrc', mode: 'deny', maskDuplicates: true }],
        },
      })
      expect(result.success).toBe(true)
    })

    test('rejects a non-boolean maskDuplicates', () => {
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        network: {
          allowedDomains: ['api.github.com'],
          deniedDomains: [],
          tlsTerminate: {},
        },
        credentials: {
          files: [
            {
              path: '~/.netrc',
              mode: 'mask',
              extract: 'password (\\S+)',
              maskDuplicates: 'yes',
            },
          ],
        },
      })
      expect(result.success).toBe(false)
      if (!result.success) {
        const issue = result.error.issues.find(
          i => i.path.join('.') === 'credentials.files.0.maskDuplicates',
        )
        expect(issue).toBeDefined()
      }
    })

    test('accepts a masked env var with an extract regex', () => {
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        network: {
          allowedDomains: ['db.example.com'],
          deniedDomains: [],
          tlsTerminate: {},
        },
        credentials: {
          envVars: [
            {
              name: 'DATABASE_URL',
              mode: 'mask',
              extract: '://[^:]+:([^@]+)@',
            },
          ],
        },
      })
      expect(result.success).toBe(true)
    })

    test('rejects an env extract value that is not a valid regex', () => {
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        network: {
          allowedDomains: ['db.example.com'],
          deniedDomains: [],
          tlsTerminate: {},
        },
        credentials: {
          envVars: [{ name: 'DATABASE_URL', mode: 'mask', extract: '(' }],
        },
      })
      expect(result.success).toBe(false)
      if (!result.success) {
        const issue = result.error.issues.find(
          i => i.path.join('.') === 'credentials.envVars.0.extract',
        )
        expect(issue?.message).toContain('not a valid regular expression')
      }
    })

    test('rejects an env extract regex with no capturing group', () => {
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        network: {
          allowedDomains: ['db.example.com'],
          deniedDomains: [],
          tlsTerminate: {},
        },
        credentials: {
          envVars: [
            { name: 'DATABASE_URL', mode: 'mask', extract: '://\\S+@' },
          ],
        },
      })
      expect(result.success).toBe(false)
      if (!result.success) {
        const issue = result.error.issues.find(
          i => i.path.join('.') === 'credentials.envVars.0.extract',
        )
        expect(issue?.message).toContain('capturing group')
      }
    })

    test('extract on a deny-mode env var is accepted (ignored)', () => {
      // Mirrors the files precedent (and injectHosts-on-deny): harmless,
      // so no error.
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        network: { allowedDomains: ['db.example.com'], deniedDomains: [] },
        credentials: {
          envVars: [
            { name: 'DATABASE_URL', mode: 'deny', extract: ':([^@]+)@' },
          ],
        },
      })
      expect(result.success).toBe(true)
    })

    test.each(['warn', 'deny', 'error'] as const)(
      'accepts onExtractNoMatch: "%s" on an env var',
      onExtractNoMatch => {
        const result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          network: {
            allowedDomains: ['db.example.com'],
            deniedDomains: [],
            tlsTerminate: {},
          },
          credentials: {
            envVars: [
              {
                name: 'DATABASE_URL',
                mode: 'mask',
                extract: '://[^:]+:([^@]+)@',
                onExtractNoMatch,
              },
            ],
          },
        })
        expect(result.success).toBe(true)
      },
    )

    test('rejects an invalid onExtractNoMatch value on an env var', () => {
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        network: {
          allowedDomains: ['db.example.com'],
          deniedDomains: [],
          tlsTerminate: {},
        },
        credentials: {
          envVars: [
            {
              name: 'DATABASE_URL',
              mode: 'mask',
              extract: '://[^:]+:([^@]+)@',
              onExtractNoMatch: 'ignore',
            },
          ],
        },
      })
      expect(result.success).toBe(false)
      if (!result.success) {
        const issue = result.error.issues.find(
          i => i.path.join('.') === 'credentials.envVars.0.onExtractNoMatch',
        )
        expect(issue).toBeDefined()
      }
    })

    test('rejects mode "mask" on a directory path (trailing slash)', () => {
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        network: {
          allowedDomains: ['api.github.com'],
          deniedDomains: [],
          tlsTerminate: {},
        },
        credentials: {
          files: [{ path: '~/.aws/', mode: 'mask' }],
        },
      })
      expect(result.success).toBe(false)
      if (!result.success) {
        const issue = result.error.issues.find(
          i => i.path.join('.') === 'credentials.files.0.path',
        )
        expect(issue?.message).toContain('single file')
        expect(issue?.message).toContain('directory')
      }
    })

    test('accepts mode "mask" for env vars when tlsTerminate is enabled', () => {
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        network: {
          allowedDomains: ['api.github.com'],
          deniedDomains: [],
          tlsTerminate: {},
        },
        credentials: {
          envVars: [{ name: 'GH_TOKEN', mode: 'mask' }],
        },
      })
      expect(result.success).toBe(true)
    })

    test('rejects mode "mask" for env vars without tlsTerminate', () => {
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        network: { allowedDomains: ['api.github.com'], deniedDomains: [] },
        credentials: {
          envVars: [{ name: 'GH_TOKEN', mode: 'mask' }],
        },
      })
      expect(result.success).toBe(false)
      if (!result.success) {
        const messages = result.error.issues.map(i => i.message).join('\n')
        expect(messages).toContain('tlsTerminate')
        expect(messages).toContain('allowPlaintextInject')
      }
    })

    test('allowPlaintextInject permits mask without tlsTerminate', () => {
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        network: { allowedDomains: ['api.github.com'], deniedDomains: [] },
        credentials: {
          envVars: [{ name: 'GH_TOKEN', mode: 'mask' }],
          allowPlaintextInject: true,
        },
      })
      expect(result.success).toBe(true)
    })

    test('accepts a masked env var with no injectHosts (defaults to allowedDomains)', () => {
      // No per-entry injectHosts — the credential defaults to
      // network.allowedDomains (injection at every reachable host).
      // injectHosts is an optional narrowing.
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        network: {
          allowedDomains: ['api.github.com'],
          deniedDomains: [],
          tlsTerminate: {},
        },
        credentials: {
          envVars: [{ name: 'GH_TOKEN', mode: 'mask' }],
        },
      })
      expect(result.success).toBe(true)
    })

    test('rejects a masked env var whose per-entry injectHosts is explicitly empty', () => {
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        network: {
          allowedDomains: ['api.github.com'],
          deniedDomains: [],
          tlsTerminate: {},
        },
        credentials: {
          envVars: [{ name: 'GH_TOKEN', mode: 'mask', injectHosts: [] }],
        },
      })
      // An explicit empty list would mean "mask but never inject", which
      // is self-contradictory.
      expect(result.success).toBe(false)
      if (!result.success) {
        const messages = result.error.issues.map(i => i.message).join('\n')
        expect(messages).toContain('explicitly empty')
        expect(messages).toContain('masked but never injected')
      }
    })

    test('rejects block-level credentials.injectHosts (removed key)', () => {
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        network: {
          allowedDomains: ['api.github.com'],
          deniedDomains: [],
          tlsTerminate: {},
        },
        credentials: {
          envVars: [{ name: 'GH_TOKEN', mode: 'mask' }],
          injectHosts: ['api.github.com'],
        },
      })
      // The block-level default no longer exists; the schema is strict so
      // a stale config fails rather than silently widening the credential
      // to every allowedDomain.
      expect(result.success).toBe(false)
      if (!result.success) {
        const issue = result.error.issues.find(
          i => i.path.join('.') === 'credentials',
        )
        expect(issue?.message).toContain('injectHosts')
      }
    })

    test('accepts a masked env var with per-entry injectHosts', () => {
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        network: {
          allowedDomains: ['registry.npmjs.org'],
          deniedDomains: [],
          tlsTerminate: {},
        },
        credentials: {
          envVars: [
            {
              name: 'NPM_TOKEN',
              mode: 'mask',
              injectHosts: ['registry.npmjs.org'],
            },
          ],
        },
      })
      expect(result.success).toBe(true)
    })

    test('rejects per-entry injectHosts not reachable via allowedDomains', () => {
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        network: {
          allowedDomains: ['api.github.com'],
          deniedDomains: [],
          tlsTerminate: {},
        },
        credentials: {
          envVars: [
            {
              name: 'NPM_TOKEN',
              mode: 'mask',
              injectHosts: ['registry.npmjs.org'],
            },
          ],
        },
      })
      expect(result.success).toBe(false)
      if (!result.success) {
        const issue = result.error.issues.find(i =>
          i.path.join('.').startsWith('credentials.envVars.0.injectHosts'),
        )
        expect(issue?.message).toContain('registry.npmjs.org')
        expect(issue?.message).toContain('network.allowedDomains')
      }
    })

    test('rejects overly-broad wildcards in per-entry injectHosts', () => {
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        network: { ...base.network, tlsTerminate: {} },
        credentials: {
          envVars: [{ name: 'GH_TOKEN', mode: 'mask', injectHosts: ['*.com'] }],
        },
      })
      expect(result.success).toBe(false)
    })

    test('injectHosts on a deny-mode entry is accepted (ignored)', () => {
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        network: { allowedDomains: ['api.github.com'], deniedDomains: [] },
        credentials: {
          envVars: [
            { name: 'GH_TOKEN', mode: 'deny', injectHosts: ['api.github.com'] },
          ],
        },
      })
      expect(result.success).toBe(true)
    })

    test('accepts a masked env var with decode "jwt"', () => {
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        network: {
          allowedDomains: ['api.github.com'],
          deniedDomains: [],
          tlsTerminate: {},
        },
        credentials: {
          envVars: [{ name: 'CI_JOB_JWT', mode: 'mask', decode: 'jwt' }],
        },
      })
      expect(result.success).toBe(true)
    })

    test('rejects an unknown decode encoding on an env var entry', () => {
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        network: {
          allowedDomains: ['api.github.com'],
          deniedDomains: [],
          tlsTerminate: {},
        },
        credentials: {
          envVars: [{ name: 'CI_JOB_JWT', mode: 'mask', decode: 'base64' }],
        },
      })
      expect(result.success).toBe(false)
      if (!result.success) {
        const issue = result.error.issues.find(
          i => i.path.join('.') === 'credentials.envVars.0.decode',
        )
        expect(issue).toBeDefined()
      }
    })

    test('decode on a deny-mode env var entry is accepted (ignored)', () => {
      // Mirrors the extract/injectHosts-on-deny precedent: harmless, so
      // no error.
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        network: { allowedDomains: ['api.github.com'], deniedDomains: [] },
        credentials: {
          envVars: [{ name: 'CI_JOB_JWT', mode: 'deny', decode: 'jwt' }],
        },
      })
      expect(result.success).toBe(true)
    })

    test('accepts maskClaims alongside decode "jwt" on an env var', () => {
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        network: {
          allowedDomains: ['api.github.com'],
          deniedDomains: [],
          tlsTerminate: {},
        },
        credentials: {
          envVars: [
            {
              name: 'CI_JOB_JWT',
              mode: 'mask',
              decode: 'jwt',
              maskClaims: ['api_key', 'secret'],
            },
          ],
        },
      })
      expect(result.success).toBe(true)
      if (result.success) {
        expect(result.data.credentials?.envVars?.[0]?.maskClaims).toEqual([
          'api_key',
          'secret',
        ])
      }
    })

    test('rejects maskClaims without decode on an env var', () => {
      // maskClaims names fields inside a decoded payload; without decode
      // there is nothing to look inside.
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        network: {
          allowedDomains: ['api.github.com'],
          deniedDomains: [],
          tlsTerminate: {},
        },
        credentials: {
          envVars: [
            { name: 'CI_JOB_JWT', mode: 'mask', maskClaims: ['api_key'] },
          ],
        },
      })
      expect(result.success).toBe(false)
      if (!result.success) {
        const issue = result.error.issues.find(
          i => i.path.join('.') === 'credentials.envVars.0.maskClaims',
        )
        expect(issue?.message).toContain('requires decode')
      }
    })

    test('rejects an explicitly empty maskClaims on an env var', () => {
      // Same posture as an explicitly empty injectHosts.
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        network: {
          allowedDomains: ['api.github.com'],
          deniedDomains: [],
          tlsTerminate: {},
        },
        credentials: {
          envVars: [
            {
              name: 'CI_JOB_JWT',
              mode: 'mask',
              decode: 'jwt',
              maskClaims: [],
            },
          ],
        },
      })
      expect(result.success).toBe(false)
      if (!result.success) {
        const messages = result.error.issues.map(i => i.message).join('\n')
        expect(messages).toContain('explicitly empty')
      }
    })

    test('rejects an empty string in maskClaims on an env var', () => {
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        network: {
          allowedDomains: ['api.github.com'],
          deniedDomains: [],
          tlsTerminate: {},
        },
        credentials: {
          envVars: [
            {
              name: 'CI_JOB_JWT',
              mode: 'mask',
              decode: 'jwt',
              maskClaims: [''],
            },
          ],
        },
      })
      expect(result.success).toBe(false)
    })

    test('maskClaims with decode on a deny-mode env var entry is accepted (ignored)', () => {
      // Mirrors the decode-on-deny precedent: mode "deny" ignores masking
      // options; the decode requirement is structural, not mode-dependent.
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        network: { allowedDomains: ['api.github.com'], deniedDomains: [] },
        credentials: {
          envVars: [
            {
              name: 'CI_JOB_JWT',
              mode: 'deny',
              decode: 'jwt',
              maskClaims: ['api_key'],
            },
          ],
        },
      })
      expect(result.success).toBe(true)
    })

    test('accepts per-entry injectHosts that are a subset of allowedDomains', () => {
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        network: {
          allowedDomains: ['api.github.com', 'github.com', '*.amazonaws.com'],
          deniedDomains: [],
          tlsTerminate: {},
        },
        credentials: {
          envVars: [
            {
              name: 'GH_TOKEN',
              mode: 'mask',
              injectHosts: ['api.github.com', '*.amazonaws.com'],
            },
          ],
        },
      })
      expect(result.success).toBe(true)
    })

    test('accepts an exact injectHost covered by a wildcard allowedDomain', () => {
      // The injectHosts ⊆ allowedDomains check is semantic coverage, not
      // literal string membership — api.github.com is reachable via
      // *.github.com, so this must validate.
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        network: {
          allowedDomains: ['*.github.com'],
          deniedDomains: [],
          tlsTerminate: {},
        },
        credentials: {
          envVars: [
            {
              name: 'GH_TOKEN',
              mode: 'mask',
              injectHosts: ['api.github.com'],
            },
          ],
        },
      })
      expect(result.success).toBe(true)
    })

    test('accepts a wildcard injectHost covered by a broader allowed wildcard', () => {
      // Every host under *.api.github.com is also under *.github.com.
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        network: {
          allowedDomains: ['*.github.com'],
          deniedDomains: [],
          tlsTerminate: {},
        },
        credentials: {
          envVars: [
            {
              name: 'GH_TOKEN',
              mode: 'mask',
              injectHosts: ['*.api.github.com'],
            },
          ],
        },
      })
      expect(result.success).toBe(true)
    })

    test('rejects a wildcard injectHost not covered by an exact allowedDomain', () => {
      // *.github.com would inject at gist.github.com, which is not
      // reachable when allowedDomains only contains api.github.com.
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        network: {
          allowedDomains: ['api.github.com'],
          deniedDomains: [],
          tlsTerminate: {},
        },
        credentials: {
          envVars: [
            {
              name: 'GH_TOKEN',
              mode: 'mask',
              injectHosts: ['*.github.com'],
            },
          ],
        },
      })
      expect(result.success).toBe(false)
      if (!result.success) {
        const issue = result.error.issues.find(i =>
          i.path.join('.').startsWith('credentials.envVars.0.injectHosts'),
        )
        expect(issue?.message).toContain('*.github.com')
        expect(issue?.message).toContain('not reachable')
      }
    })

    test('rejects an exact injectHost not covered by an unrelated wildcard', () => {
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        network: {
          allowedDomains: ['*.example.com'],
          deniedDomains: [],
          tlsTerminate: {},
        },
        credentials: {
          envVars: [
            {
              name: 'GH_TOKEN',
              mode: 'mask',
              injectHosts: ['api.github.com'],
            },
          ],
        },
      })
      expect(result.success).toBe(false)
      if (!result.success) {
        const issue = result.error.issues.find(i =>
          i.path.join('.').startsWith('credentials.envVars.0.injectHosts'),
        )
        expect(issue?.message).toContain('api.github.com')
        expect(issue?.message).toContain('not reachable')
      }
    })

    test('rejects unknown modes', () => {
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        credentials: {
          files: [{ path: '~/.netrc', mode: 'block' }],
        },
      })
      expect(result.success).toBe(false)
    })

    test('rejects empty file paths', () => {
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        credentials: {
          files: [{ path: '', mode: 'deny' }],
        },
      })
      expect(result.success).toBe(false)
    })

    test.each(['', 'FOO=BAR', 'FOO BAR', '--bind', '-u', '1FOO', 'FOO.BAR'])(
      'rejects invalid env var name: %j',
      name => {
        const result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          credentials: {
            envVars: [{ name, mode: 'deny' }],
          },
        })
        expect(result.success).toBe(false)
      },
    )

    test.each(['_FOO', 'FOO_BAR2'])('accepts valid env var name: %j', name => {
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        credentials: {
          envVars: [{ name, mode: 'deny' }],
        },
      })
      expect(result.success).toBe(true)
    })
  })

  describe('network.tlsTerminate', () => {
    const base = {
      network: { allowedDomains: [], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    }

    test('is optional — config without it validates', () => {
      expect(SandboxRuntimeConfigSchema.safeParse(base).success).toBe(true)
    })

    test('accepts caCertPath + caKeyPath', () => {
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        network: {
          ...base.network,
          tlsTerminate: { caCertPath: '/etc/ca.crt', caKeyPath: '/etc/ca.key' },
        },
      })
      expect(result.success).toBe(true)
    })

    test('rejects when caKeyPath is missing', () => {
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        network: {
          ...base.network,
          tlsTerminate: { caCertPath: '/etc/ca.crt' },
        },
      })
      expect(result.success).toBe(false)
    })

    test('rejects empty caCertPath', () => {
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        network: {
          ...base.network,
          tlsTerminate: { caCertPath: '', caKeyPath: '/etc/ca.key' },
        },
      })
      expect(result.success).toBe(false)
    })

    describe('excludeDomains', () => {
      test('accepts exact and wildcard patterns', () => {
        const result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          network: {
            allowedDomains: ['*.mtls.example.com', 'pinned.example.com'],
            deniedDomains: [],
            tlsTerminate: {
              excludeDomains: ['*.mtls.example.com', 'pinned.example.com'],
            },
          },
        })
        expect(result.success).toBe(true)
      })

      test('rejects invalid domain patterns', () => {
        const result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          network: {
            ...base.network,
            tlsTerminate: { excludeDomains: ['https://example.com'] },
          },
        })
        expect(result.success).toBe(false)
      })

      test('rejects a bare "*" (would silently disable termination)', () => {
        const result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          network: {
            ...base.network,
            tlsTerminate: { excludeDomains: ['*'] },
          },
        })
        expect(result.success).toBe(false)
      })

      test('rejects a masked credential whose explicit injectHosts entry is fully covered by excludeDomains', () => {
        // Injection only happens on the terminated path, so an injectHost
        // that can never be terminated can never receive the credential —
        // the upstream would get the placeholder.
        const result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          network: {
            allowedDomains: ['*.example.com'],
            deniedDomains: [],
            tlsTerminate: { excludeDomains: ['*.internal.example.com'] },
          },
          credentials: {
            envVars: [
              {
                name: 'TOKEN',
                mode: 'mask',
                injectHosts: ['api.internal.example.com'],
              },
            ],
          },
        })
        expect(result.success).toBe(false)
        if (!result.success) {
          const issue = result.error.issues.find(i =>
            i.path.join('.').startsWith('credentials.envVars.0.injectHosts'),
          )
          expect(issue?.message).toContain('excludeDomains')
          expect(issue?.message).toContain('api.internal.example.com')
        }
      })

      test('accepts an explicit wildcard injectHosts that merely overlaps excludeDomains', () => {
        // Only mtls.example.com is opaque-tunnelled; every other
        // *.example.com host still gets the credential. Not a
        // contradiction — must not be rejected.
        const result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          network: {
            allowedDomains: ['*.example.com'],
            deniedDomains: [],
            tlsTerminate: { excludeDomains: ['mtls.example.com'] },
          },
          credentials: {
            envVars: [
              { name: 'TOKEN', mode: 'mask', injectHosts: ['*.example.com'] },
            ],
          },
        })
        expect(result.success).toBe(true)
      })

      test('rejects a masked credential with default injectHosts when excludeDomains covers every allowed domain', () => {
        // Effective injectHosts = allowedDomains, all of which are excluded
        // from termination: the credential could never be injected anywhere.
        const result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          network: {
            allowedDomains: ['*.example.com', 'pinned.example.net'],
            deniedDomains: [],
            tlsTerminate: {
              excludeDomains: ['*.example.com', 'pinned.example.net'],
            },
          },
          credentials: {
            envVars: [{ name: 'TOKEN', mode: 'mask' }],
          },
        })
        expect(result.success).toBe(false)
        if (!result.success) {
          const messages = result.error.issues.map(i => i.message).join('\n')
          expect(messages).toContain('never be injected')
        }
      })

      test('a masked credential with default (absent) injectHosts coexists with a partial excludeDomains', () => {
        // Default injectHosts = allowedDomains. Excluded hosts simply do not
        // get the credential; that is not an error.
        const result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          network: {
            allowedDomains: ['*.example.com'],
            deniedDomains: [],
            tlsTerminate: { excludeDomains: ['mtls.example.com'] },
          },
          credentials: {
            envVars: [{ name: 'TOKEN', mode: 'mask' }],
          },
        })
        expect(result.success).toBe(true)
      })

      test('explicit injectHosts disjoint from excludeDomains is accepted', () => {
        const result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          network: {
            allowedDomains: ['*.example.com'],
            deniedDomains: [],
            tlsTerminate: { excludeDomains: ['mtls.example.com'] },
          },
          credentials: {
            envVars: [
              { name: 'TOKEN', mode: 'mask', injectHosts: ['api.example.com'] },
            ],
          },
        })
        expect(result.success).toBe(true)
      })
    })

    describe('extraCaCertPaths', () => {
      test('accepts a list of paths and round-trips it', () => {
        const result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          network: {
            ...base.network,
            tlsTerminate: {
              extraCaCertPaths: ['/etc/site-local-roots.pem', '/etc/extra.pem'],
            },
          },
        })
        expect(result.success).toBe(true)
        if (result.success) {
          expect(result.data.network.tlsTerminate?.extraCaCertPaths).toEqual([
            '/etc/site-local-roots.pem',
            '/etc/extra.pem',
          ])
        }
      })

      test('is optional', () => {
        const result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          network: { ...base.network, tlsTerminate: {} },
        })
        expect(result.success).toBe(true)
        if (result.success) {
          expect(
            result.data.network.tlsTerminate?.extraCaCertPaths,
          ).toBeUndefined()
        }
      })

      test('rejects an empty path', () => {
        const result = SandboxRuntimeConfigSchema.safeParse({
          ...base,
          network: {
            ...base.network,
            tlsTerminate: { extraCaCertPaths: [''] },
          },
        })
        expect(result.success).toBe(false)
      })
    })
  })
})
