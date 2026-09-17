import { describe, it, expect, beforeAll, afterAll } from 'bun:test'
import { spawnSync } from 'node:child_process'
import {
  existsSync,
  mkdtempSync,
  mkdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import { _test as sshConfigDenyTest } from '../../src/sandbox/ssh-config-deny.js'
import type { SandboxRuntimeConfig } from '../../src/sandbox/sandbox-config.js'
import { wrapCommandWithSandboxMacOS } from '../../src/sandbox/macos-sandbox-utils.js'
import { normalizePathForSandbox } from '../../src/sandbox/sandbox-utils.js'
import { loadConfig } from '../../src/utils/config-loader.js'
import { isLinux, isMacOS, isSupportedPlatform } from '../helpers/platform.js'

/**
 * Tests for the `credentials` config section (mode: deny).
 *
 * File entries with mode: deny are unioned into the read-deny set; env var
 * entries with mode: deny are unset inside the sandbox. The credentials
 * block itself applies no implicit defaults; the separate ssh-config key
 * protection contributes its own denyRead arm (pointed at an empty temp
 * home below so these exact-set assertions stay hermetic).
 *
 * HOME is pointed at an empty temp dir for the whole file: the exact-set
 * assertions below would otherwise pick up the runner's real ~/.ssh via the
 * ssh-config key protection (which is additive by design and covered by its
 * own suite).
 */
const hermeticHome = mkdtempSync(join(tmpdir(), 'cred-deny-home-'))
beforeAll(() => {
  sshConfigDenyTest.homedirOverride = hermeticHome
})
afterAll(() => {
  sshConfigDenyTest.homedirOverride = undefined
  rmSync(hermeticHome, { recursive: true, force: true })
})

function baseConfig(
  overrides: Partial<SandboxRuntimeConfig> = {},
): SandboxRuntimeConfig {
  return {
    network: { allowedDomains: [], deniedDomains: [] },
    filesystem: { denyRead: [], allowWrite: ['/tmp'], denyWrite: [] },
    ...overrides,
  }
}

describe.if(isSupportedPlatform)(
  'credential read-deny normalization (getFsReadConfig)',
  () => {
    afterAll(async () => {
      await SandboxManager.reset()
    })

    it('applies only caller-supplied denyRead without a credentials block', async () => {
      await SandboxManager.reset()
      await SandboxManager.initialize(
        baseConfig({
          filesystem: {
            denyRead: ['/some/secret'],
            allowWrite: ['/tmp'],
            denyWrite: [],
          },
        }),
      )

      const readConfig = SandboxManager.getFsReadConfig()
      expect(readConfig.denyOnly).toEqual(['/some/secret'])

      await SandboxManager.reset()
    })

    it('denies nothing beyond the declared entries', async () => {
      await SandboxManager.reset()
      // Only an env var deny is declared — no implicit file read-denies
      // (e.g. ~/.netrc) may appear.
      await SandboxManager.initialize(
        baseConfig({
          credentials: {
            envVars: [{ name: 'GH_TOKEN', mode: 'deny' }],
          },
        }),
      )

      const readConfig = SandboxManager.getFsReadConfig()
      expect(readConfig.denyOnly).toEqual([])

      await SandboxManager.reset()
    })

    it('unions credential deny entries with caller-supplied denyRead', async () => {
      await SandboxManager.reset()
      await SandboxManager.initialize(
        baseConfig({
          filesystem: {
            denyRead: ['/some/secret'],
            allowWrite: ['/tmp'],
            denyWrite: [],
          },
          credentials: {
            files: [{ path: '~/.config/gcloud', mode: 'deny' }],
          },
        }),
      )

      const readConfig = SandboxManager.getFsReadConfig()
      // Caller denyRead survives and the credential deny entry is added
      expect(readConfig.denyOnly).toContain('/some/secret')
      expect(readConfig.denyOnly).toContain('~/.config/gcloud')

      await SandboxManager.reset()
    })

    it('feeds credential deny paths into the macOS profile as file-read denies', async () => {
      await SandboxManager.reset()
      await SandboxManager.initialize(
        baseConfig({
          credentials: {
            files: [{ path: '~/.netrc', mode: 'deny' }],
          },
        }),
      )

      // Profile generation is pure string construction, so it can be
      // exercised on any platform even though sandbox-exec only runs on macOS.
      const wrapped = wrapCommandWithSandboxMacOS({
        command: 'true',
        needsNetworkRestriction: false,
        readConfig: SandboxManager.getFsReadConfig(),
        writeConfig: undefined,
      })

      expect(wrapped).toContain('deny file-read*')
      expect(wrapped).toContain('.netrc')

      await SandboxManager.reset()
    })
  },
)

describe('macOS env -u preamble generation', () => {
  it('emits env -u flags before sandbox-exec for denied env vars', () => {
    const wrapped = wrapCommandWithSandboxMacOS({
      command: 'true',
      needsNetworkRestriction: false,
      readConfig: undefined,
      writeConfig: { allowOnly: ['/tmp'], denyWithinAllow: [] },
      unsetEnvVars: ['GH_TOKEN', 'AWS_SECRET_ACCESS_KEY'],
    })

    expect(
      wrapped.startsWith('env -u GH_TOKEN -u AWS_SECRET_ACCESS_KEY '),
    ).toBe(true)
    // The -u flags must precede the VAR=VALUE assignments and sandbox-exec.
    expect(wrapped.indexOf('-u GH_TOKEN')).toBeLessThan(
      wrapped.indexOf('SANDBOX_RUNTIME'),
    )
    expect(wrapped.indexOf('-u GH_TOKEN')).toBeLessThan(
      wrapped.indexOf('sandbox-exec'),
    )
  })

  it('still sandboxes when env unsets are the only restriction', () => {
    const command = 'echo hello'
    const wrapped = wrapCommandWithSandboxMacOS({
      command,
      needsNetworkRestriction: false,
      readConfig: undefined,
      writeConfig: undefined,
      unsetEnvVars: ['GH_TOKEN'],
    })

    expect(wrapped).not.toBe(command)
    expect(wrapped).toContain('env -u GH_TOKEN')
  })

  it('emits no -u flags when no env vars are denied', () => {
    const wrapped = wrapCommandWithSandboxMacOS({
      command: 'true',
      needsNetworkRestriction: false,
      readConfig: undefined,
      writeConfig: { allowOnly: ['/tmp'], denyWithinAllow: [] },
      unsetEnvVars: [],
    })

    expect(wrapped).not.toContain(' -u ')
  })
})

/**
 * Drive the same pipeline the CLI uses on macOS — settings file → loadConfig →
 * SandboxManager.initialize → wrapWithSandbox — with process.platform forced
 * to 'darwin' so the macOS branch is exercised on Linux CI too. Asserts the
 * credential restrictions actually reach the final wrapped command.
 */
describe.if(isSupportedPlatform)(
  'macOS wrapped command via the manager (settings-file config)',
  () => {
    const TEST_DIR = join(tmpdir(), 'credential-deny-darwin-' + Date.now())
    const SECRET_FILE = join(TEST_DIR, 'secret-token.txt')
    const SETTINGS_FILE = join(TEST_DIR, 'credentials.json')
    let platformDescriptor: PropertyDescriptor | undefined

    const escapeRegExp = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
    // Matches (subpath "<path>") as any of the filters listed under a
    // (deny file-read* …) rule. The profile is embedded byte-literal inside
    // a single-quoted argument, so the inner quotes appear exactly as
    // written (never backslash-escaped).
    const denyReadRule = (p: string) =>
      new RegExp(
        String.raw`\(deny file-read\*(\n  \([^\n]*\))*\n  \(subpath "` +
          escapeRegExp(p) +
          '"',
      )

    beforeAll(async () => {
      mkdirSync(TEST_DIR, { recursive: true })
      writeFileSync(SECRET_FILE, 'token-abc\n')
      writeFileSync(
        SETTINGS_FILE,
        JSON.stringify({
          network: { allowedDomains: [], deniedDomains: [] },
          filesystem: { denyRead: [], allowWrite: ['.'], denyWrite: [] },
          credentials: {
            files: [{ path: SECRET_FILE, mode: 'deny' }],
            envVars: [{ name: 'MY_API_TOKEN', mode: 'deny' }],
          },
        }),
      )

      platformDescriptor = Object.getOwnPropertyDescriptor(process, 'platform')
      Object.defineProperty(process, 'platform', { value: 'darwin' })

      const config = loadConfig(SETTINGS_FILE)
      if (!config) {
        throw new Error(`Settings file failed to load: ${SETTINGS_FILE}`)
      }
      await SandboxManager.reset()
      await SandboxManager.initialize(config)
    })

    afterAll(async () => {
      await SandboxManager.reset()
      if (platformDescriptor) {
        Object.defineProperty(process, 'platform', platformDescriptor)
      }
      if (existsSync(TEST_DIR)) {
        rmSync(TEST_DIR, { recursive: true, force: true })
      }
    })

    it('unsets the denied env var before assignments and sandbox-exec', async () => {
      const wrapped = await SandboxManager.wrapWithSandbox(
        'printenv MY_API_TOKEN',
      )

      expect(wrapped.startsWith('env -u MY_API_TOKEN ')).toBe(true)
      // -u must precede the first NAME=VALUE assignment and sandbox-exec so
      // BSD env still treats it as an option.
      expect(wrapped.indexOf('-u MY_API_TOKEN')).toBeLessThan(
        wrapped.indexOf('SANDBOX_RUNTIME'),
      )
      expect(wrapped.indexOf('-u MY_API_TOKEN')).toBeLessThan(
        wrapped.indexOf('sandbox-exec'),
      )
    })

    it('denies reads of the declared credential file in the profile', async () => {
      const wrapped = await SandboxManager.wrapWithSandbox(`cat ${SECRET_FILE}`)

      expect(wrapped).toContain('sandbox-exec')
      expect(wrapped).toMatch(
        denyReadRule(normalizePathForSandbox(SECRET_FILE)),
      )
      // No implicit denies: undeclared credential paths stay out of the profile.
      expect(wrapped).not.toMatch(
        denyReadRule(normalizePathForSandbox('~/.netrc')),
      )
    })
  },
)

/**
 * macOS end-to-end: actually run sandbox-exec with a settings-file config and
 * verify the credential deny rules hold at runtime. Skipped on Linux; runs on
 * the macOS CI legs.
 */
describe.if(isMacOS)('credential deny on macOS (sandbox-exec)', () => {
  const TEST_DIR = join(tmpdir(), 'credential-deny-macos-' + Date.now())
  const SECRET_FILE = join(TEST_DIR, 'secret-token.txt')
  const CONTROL_FILE = join(TEST_DIR, 'control.txt')
  const SETTINGS_FILE = join(TEST_DIR, 'credentials.json')
  const DENIED_ENV_VAR = 'SRT_TEST_SECRET_TOKEN'
  const ALLOWED_ENV_VAR = 'SRT_TEST_VISIBLE_VALUE'

  // process.env mutations don't reach children spawned by bun without an
  // explicit env option, so the credential vars are passed per-spawn instead.
  const childEnv = {
    ...process.env,
    [DENIED_ENV_VAR]: 'super-secret-value',
    [ALLOWED_ENV_VAR]: 'visible-value',
  }

  function runInSandbox(wrappedCommand: string) {
    return spawnSync(wrappedCommand, {
      shell: true,
      encoding: 'utf8',
      timeout: 10000,
      env: childEnv,
    })
  }

  beforeAll(async () => {
    mkdirSync(TEST_DIR, { recursive: true })
    writeFileSync(SECRET_FILE, 'token-abc\n')
    writeFileSync(CONTROL_FILE, 'control-ok\n')
    writeFileSync(
      SETTINGS_FILE,
      JSON.stringify({
        network: { allowedDomains: [], deniedDomains: [] },
        filesystem: {
          denyRead: [],
          allowWrite: [TEST_DIR, '/tmp'],
          denyWrite: [],
        },
        credentials: {
          files: [{ path: SECRET_FILE, mode: 'deny' }],
          envVars: [{ name: DENIED_ENV_VAR, mode: 'deny' }],
        },
      }),
    )

    const config = loadConfig(SETTINGS_FILE)
    if (!config) {
      throw new Error(`Settings file failed to load: ${SETTINGS_FILE}`)
    }
    await SandboxManager.reset()
    await SandboxManager.initialize(config)
  })

  afterAll(async () => {
    await SandboxManager.reset()
    if (existsSync(TEST_DIR)) {
      rmSync(TEST_DIR, { recursive: true, force: true })
    }
  })

  it('a denied env var is absent inside the sandbox', async () => {
    const wrapped = await SandboxManager.wrapWithSandbox(
      `printenv ${DENIED_ENV_VAR}`,
    )
    const result = runInSandbox(wrapped)

    expect(result.status).not.toBe(0)
    expect(result.stdout).not.toContain('super-secret-value')
  })

  it('a non-denied env var is still inherited inside the sandbox', async () => {
    const wrapped = await SandboxManager.wrapWithSandbox(
      `printenv ${ALLOWED_ENV_VAR}`,
    )
    const result = runInSandbox(wrapped)

    expect(result.status).toBe(0)
    expect(result.stdout).toContain('visible-value')
  })

  it('a denied credential file is unreadable inside the sandbox', async () => {
    const wrapped = await SandboxManager.wrapWithSandbox(`cat ${SECRET_FILE}`)
    const result = runInSandbox(wrapped)

    expect(result.status).not.toBe(0)
    expect(result.stdout).not.toContain('token-abc')
    expect((result.stderr || '').toLowerCase()).toContain(
      'operation not permitted',
    )
  })

  it('a non-credential file in the same directory is still readable', async () => {
    const wrapped = await SandboxManager.wrapWithSandbox(`cat ${CONTROL_FILE}`)
    const result = runInSandbox(wrapped)

    expect(result.status).toBe(0)
    expect(result.stdout).toContain('control-ok')
  })
})

describe.if(isLinux)('credential deny on Linux (bwrap)', () => {
  const TEST_DIR = join(tmpdir(), 'credential-deny-test-' + Date.now())
  const SECRET_FILE = join(TEST_DIR, 'fake-netrc')
  const SECRET_DIR = join(TEST_DIR, 'fake-aws')
  const SECRET_DIR_FILE = join(SECRET_DIR, 'credentials')
  // Symlinked credential file (dotfile-manager layout): the deny entry names
  // the symlink, the secret bytes live at the target.
  const SECRET_LINK_TARGET = join(TEST_DIR, 'dotfiles-netrc')
  const SECRET_LINK = join(TEST_DIR, 'symlinked-netrc')
  const SECRET_CONTENT = 'machine github.com password hunter2'
  const DENIED_ENV_VAR = 'SRT_TEST_SECRET_TOKEN'
  const ALLOWED_ENV_VAR = 'SRT_TEST_VISIBLE_VALUE'

  // process.env mutations don't reach children spawned by bun without an
  // explicit env option, so the credential vars are passed per-spawn instead.
  const childEnv = {
    ...process.env,
    [DENIED_ENV_VAR]: 'super-secret-value',
    [ALLOWED_ENV_VAR]: 'visible-value',
  }

  function runInSandbox(wrappedCommand: string) {
    return spawnSync(wrappedCommand, {
      shell: true,
      encoding: 'utf8',
      timeout: 10000,
      env: childEnv,
    })
  }

  beforeAll(async () => {
    mkdirSync(SECRET_DIR, { recursive: true })
    writeFileSync(SECRET_FILE, SECRET_CONTENT)
    writeFileSync(SECRET_DIR_FILE, SECRET_CONTENT)
    writeFileSync(SECRET_LINK_TARGET, SECRET_CONTENT)
    symlinkSync(SECRET_LINK_TARGET, SECRET_LINK)

    await SandboxManager.reset()
    await SandboxManager.initialize(
      baseConfig({
        filesystem: {
          denyRead: [],
          allowWrite: [TEST_DIR, '/tmp'],
          denyWrite: [],
        },
        credentials: {
          files: [
            { path: SECRET_FILE, mode: 'deny' },
            { path: SECRET_DIR, mode: 'deny' },
            { path: SECRET_LINK, mode: 'deny' },
          ],
          envVars: [{ name: DENIED_ENV_VAR, mode: 'deny' }],
        },
      }),
    )
  })

  afterAll(async () => {
    await SandboxManager.reset()
    if (existsSync(TEST_DIR)) {
      rmSync(TEST_DIR, { recursive: true, force: true })
    }
  })

  describe('bwrap argv generation', () => {
    it('emits a /dev/null bind for a denied credential file', async () => {
      const wrapped = await SandboxManager.wrapWithSandbox('true')

      expect(wrapped).toContain(`--ro-bind /dev/null ${SECRET_FILE}`)
      expect(wrapped).toContain(`--tmpfs ${SECRET_DIR}`)
    })

    it('denies the resolved target when a denied credential file is a symlink', async () => {
      const wrapped = await SandboxManager.wrapWithSandbox('true')

      // bwrap rejects symlink bind destinations, so the deny bind lands on
      // the symlink's target instead of the symlink path itself.
      expect(wrapped).toContain(`--ro-bind /dev/null ${SECRET_LINK_TARGET}`)
      expect(wrapped).not.toContain(`--ro-bind /dev/null ${SECRET_LINK} `)
    })

    it('emits --unsetenv for a denied credential env var', async () => {
      const wrapped = await SandboxManager.wrapWithSandbox('true')

      expect(wrapped).toContain(`--unsetenv ${DENIED_ENV_VAR}`)
      expect(wrapped).not.toContain(`--unsetenv ${ALLOWED_ENV_VAR}`)
    })

    it('honors a credentials block passed via customConfig', async () => {
      const wrapped = await SandboxManager.wrapWithSandbox('true', undefined, {
        filesystem: {
          denyRead: [],
          allowWrite: ['/tmp'],
          denyWrite: [],
        },
        credentials: {
          files: [{ path: SECRET_FILE, mode: 'deny' }],
          envVars: [{ name: 'CUSTOM_ONLY_TOKEN', mode: 'deny' }],
        },
      })

      expect(wrapped).toContain(`--ro-bind /dev/null ${SECRET_FILE}`)
      expect(wrapped).toContain('--unsetenv CUSTOM_ONLY_TOKEN')
    })
  })

  describe('integration', () => {
    it('a denied credential file reads back empty inside the sandbox', async () => {
      const wrapped = await SandboxManager.wrapWithSandbox(`cat ${SECRET_FILE}`)
      const result = runInSandbox(wrapped)

      // The /dev/null bind makes the file readable but empty
      expect(result.stdout).not.toContain('hunter2')
      expect(result.stdout.trim()).toBe('')
    })

    it('a denied symlinked credential file reads back empty inside the sandbox', async () => {
      const wrapped = await SandboxManager.wrapWithSandbox(`cat ${SECRET_LINK}`)
      const result = runInSandbox(wrapped)

      // The symlink resolves to the denied target inside the mount namespace
      expect(result.stdout).not.toContain('hunter2')
      expect(result.stdout.trim()).toBe('')
    })

    it('a file inside a denied credential directory is unreadable inside the sandbox', async () => {
      const wrapped = await SandboxManager.wrapWithSandbox(
        `cat ${SECRET_DIR_FILE}`,
      )
      const result = runInSandbox(wrapped)

      // The tmpfs mount hides the directory contents entirely
      expect(result.status).not.toBe(0)
      expect(result.stdout).not.toContain('hunter2')
    })

    it('a denied env var is absent inside the sandbox', async () => {
      const wrapped = await SandboxManager.wrapWithSandbox(
        `printenv ${DENIED_ENV_VAR}`,
      )
      const result = runInSandbox(wrapped)

      expect(result.status).not.toBe(0)
      expect(result.stdout).not.toContain('super-secret-value')
    })

    it('a non-denied env var is still inherited inside the sandbox', async () => {
      const wrapped = await SandboxManager.wrapWithSandbox(
        `printenv ${ALLOWED_ENV_VAR}`,
      )
      const result = runInSandbox(wrapped)

      expect(result.status).toBe(0)
      expect(result.stdout).toContain('visible-value')
    })
  })
})
