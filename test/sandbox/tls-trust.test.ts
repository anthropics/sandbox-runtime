import { afterAll, afterEach, describe, expect, it } from 'bun:test'
import { spawnSync } from 'node:child_process'
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, relative } from 'node:path'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import type { SandboxRuntimeConfig } from '../../src/sandbox/sandbox-config.js'
import type { TlsTrustInfo } from '../../src/index.js'
import { quote } from '../../src/utils/shell-quote.js'
import { isLinux, isMacOS } from '../helpers/platform.js'

describe.if(isLinux || isMacOS)('TLS trust and CA source protection', () => {
  const scratch = realpathSync(mkdtempSync(join(tmpdir(), 'srt-trust-')))
  const fixture = join(import.meta.dir, '../fixtures/tls-terminate')
  const certPem = readFileSync(join(fixture, 'ca.crt'), 'utf8')
  const keyPem = readFileSync(join(fixture, 'ca.key'), 'utf8')
  const certPath = join(scratch, 'ca[cert].pem')
  const keyPath = join(scratch, 'ca[key].pem')
  const extraPath = join(scratch, 'extra[ca].pem')
  const parentPath = join(scratch, 'parent[ca].pem')
  const keyLink = join(scratch, 'key-link')
  const neighbor = join(scratch, 'cak.pem')
  writeFileSync(neighbor, 'neighbor')
  for (const path of [certPath, extraPath, parentPath]) {
    writeFileSync(path, certPem + keyPem)
  }
  writeFileSync(keyPath, keyPem)
  symlinkSync(keyPath, keyLink)

  const config = (
    filesystem: Partial<SandboxRuntimeConfig['filesystem']> = {},
  ): SandboxRuntimeConfig => ({
    network: {
      allowedDomains: [],
      deniedDomains: [],
      tlsTerminate: {
        caCertPath: relative(process.cwd(), certPath),
        caKeyPath: relative(process.cwd(), keyPath),
        extraCaCertPaths: [relative(process.cwd(), extraPath)],
      },
    },
    filesystem: { denyRead: [], allowWrite: [], denyWrite: [], ...filesystem },
  })

  async function start(
    filesystem: Partial<SandboxRuntimeConfig['filesystem']> = {},
  ): Promise<void> {
    const previous = process.env.NODE_EXTRA_CA_CERTS
    process.env.NODE_EXTRA_CA_CERTS = parentPath
    try {
      await SandboxManager.initialize(config(filesystem))
    } finally {
      if (previous === undefined) delete process.env.NODE_EXTRA_CA_CERTS
      else process.env.NODE_EXTRA_CA_CERTS = previous
    }
  }

  async function read(
    path: string,
    customConfig?: Partial<SandboxRuntimeConfig>,
  ): Promise<{ status: number | null; stdout: string }> {
    const command = await SandboxManager.wrapWithSandbox(
      quote(['cat', path]),
      undefined,
      customConfig,
    )
    const result = spawnSync(command, {
      shell: true,
      encoding: 'utf8',
      timeout: 10000,
    })
    return { status: result.status, stdout: result.stdout }
  }

  afterEach(() => SandboxManager.reset())
  afterAll(() => rmSync(scratch, { recursive: true, force: true }))

  it('returns only immutable public trust information for the active session', async () => {
    expect(SandboxManager.getTlsTrust()).toBeUndefined()
    await start()
    const trust: TlsTrustInfo = SandboxManager.getTlsTrust()!
    expect(trust).toStrictEqual({
      caCertPem: certPem,
      trustBundlePath: expect.any(String),
    })
    expect(Object.isFrozen(trust)).toBe(true)
    expect(SandboxManager.getTlsTrust()).not.toBe(trust)
    await SandboxManager.reset()
    expect({
      trust: SandboxManager.getTlsTrust(),
      bundleExists: existsSync(trust.trustBundlePath),
    }).toStrictEqual({ trust: undefined, bundleExists: false })
    expect(
      [certPath, keyPath, extraPath, parentPath].map(existsSync),
    ).toStrictEqual([true, true, true, true])
  })

  it.each(['default', 'directory', 'exact', 'write'] as const)(
    'denies every CA source with %s allowances',
    async allowance => {
      const sources = [certPath, keyPath, extraPath, parentPath]
      await start({
        allowRead:
          allowance === 'directory'
            ? [scratch]
            : allowance === 'exact'
              ? sources.map(path => ({ path, literal: true }))
              : [],
        allowWrite: allowance === 'write' ? [scratch] : [],
      })
      for (const path of [...sources, keyLink]) {
        expect(await read(path)).toStrictEqual({
          status: isLinux ? 0 : 1,
          stdout: '',
        })
      }
      expect(await read(neighbor)).toStrictEqual({
        status: 0,
        stdout: 'neighbor',
      })
      const bundle = SandboxManager.getTlsTrust()!.trustBundlePath
      expect(await read(bundle)).toStrictEqual({
        status: 0,
        stdout: readFileSync(bundle, 'utf8'),
      })
    },
  )

  it('preserves a caller credential glob with the same spelling as a CA source', async () => {
    await SandboxManager.initialize({
      ...config(),
      credentials: { files: [{ path: keyPath, mode: 'deny' }] },
    })
    expect(await read(neighbor)).toStrictEqual({
      status: isLinux ? 0 : 1,
      stdout: '',
    })
  })

  it('keeps the active sources denied under command overrides and config updates', async () => {
    await start()
    const next = config({
      allowRead: [{ path: keyPath, literal: true }],
      allowWrite: [scratch],
    })
    next.network.tlsTerminate = {}
    SandboxManager.updateConfig(next)
    expect(await read(keyPath, { filesystem: next.filesystem })).toStrictEqual({
      status: isLinux ? 0 : 1,
      stdout: '',
    })
    expect(
      SandboxManager.getFsReadConfig().literalCredentialDenyOnly?.includes(
        keyPath,
      ),
    ).toBe(true)
  })

  it.each(['directory', 'glob'] as const)(
    'keeps the bundle readable under a %s deny',
    async kind => {
      await start()
      const bundle = SandboxManager.getTlsTrust()!.trustBundlePath
      const denyRead = [
        kind === 'directory' ? dirname(bundle) : join(dirname(bundle), '*.crt'),
      ]
      expect(
        await read(bundle, {
          filesystem: { denyRead, allowWrite: [], denyWrite: [] },
        }),
      ).toStrictEqual({ status: 0, stdout: readFileSync(bundle, 'utf8') })
    },
  )

  it('skips unreadable optional roots without denying their directories', async () => {
    const sentinel = join(scratch, 'sentinel')
    writeFileSync(sentinel, 'readable')
    const cfg = config()
    cfg.network.tlsTerminate!.extraCaCertPaths = [
      scratch,
      join(scratch, 'absent.pem'),
    ]
    await SandboxManager.initialize(cfg)
    expect(await read(sentinel)).toStrictEqual({
      status: 0,
      stdout: 'readable',
    })
  })

  it('preserves the disabled-filesystem bypass without copying private material', async () => {
    await start({ disabled: true })
    expect(await read(keyPath)).toStrictEqual({ status: 0, stdout: keyPem })
    const bundle = SandboxManager.getTlsTrust()!.trustBundlePath
    expect(readFileSync(bundle, 'utf8')).not.toContain('PRIVATE KEY')
    expect(SandboxManager.getFsReadConfig()).toStrictEqual({
      denyOnly: [],
      allowWithinDeny: [],
    })
  })
})
