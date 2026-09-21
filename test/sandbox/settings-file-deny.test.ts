import { describe, test, expect, afterEach } from 'bun:test'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, writeFileSync, existsSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import type { SandboxRuntimeConfig } from '../../src/sandbox/sandbox-config.js'
import { isSupportedPlatform } from '../helpers/platform.js'

/**
 * srt trusts its settings file to define the sandbox on the next run. If a
 * broad write grant covers that file's directory (allowWrite: ["~"], "/"),
 * a sandboxed process could otherwise rewrite the file and, for example, set
 * allowAppleEvents to escape on the next run. SandboxManager denies writes to
 * the settings path it was initialized with, within the allowed region.
 */
describe.if(isSupportedPlatform)('settings-file write deny', () => {
  const dirs: string[] = []

  const lab = () => {
    const d = mkdtempSync(join(tmpdir(), 'srt-settings-deny-'))
    dirs.push(d)
    return d
  }

  const cfg = (dir: string): SandboxRuntimeConfig => ({
    network: { allowedDomains: [], deniedDomains: [] },
    filesystem: {
      allowRead: [],
      // Grant writes to the whole lab dir, which contains the settings file.
      allowWrite: [dir],
      denyRead: [],
      denyWrite: [],
    },
  })

  afterEach(async () => {
    await SandboxManager.reset()
    for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true })
  })

  test('a write to the settings file is denied even though its dir is writable', async () => {
    const dir = lab()
    const settings = join(dir, '.srt-settings.json')
    writeFileSync(settings, JSON.stringify(cfg(dir)))

    await SandboxManager.initialize(cfg(dir), undefined, undefined, settings)
    const wrapped = await SandboxManager.wrapWithSandbox(
      `printf tampered > ${settings}`,
    )
    const result = spawnSync(wrapped, {
      shell: true,
      encoding: 'utf8',
      timeout: 10000,
    })

    expect(result.status).not.toBe(0)
    // The file still holds the original config, not "tampered".
    expect(existsSync(settings)).toBe(true)
    expect(spawnSync('cat', [settings], { encoding: 'utf8' }).stdout).not.toBe(
      'tampered',
    )
  })

  test('a sibling write in the same allowed dir still succeeds (deny is narrow)', async () => {
    const dir = lab()
    const settings = join(dir, '.srt-settings.json')
    writeFileSync(settings, JSON.stringify(cfg(dir)))
    const sibling = join(dir, 'ok.txt')

    await SandboxManager.initialize(cfg(dir), undefined, undefined, settings)
    const wrapped = await SandboxManager.wrapWithSandbox(
      `printf ok > ${sibling}`,
    )
    const result = spawnSync(wrapped, {
      shell: true,
      encoding: 'utf8',
      timeout: 10000,
    })

    expect(result.status).toBe(0)
    expect(existsSync(sibling)).toBe(true)
  })

  test('with no settings path (embedder-supplied config), nothing extra is denied', async () => {
    const dir = lab()
    const target = join(dir, 'target.txt')

    // No fourth argument: an embedder passing its own config object.
    await SandboxManager.initialize(cfg(dir))
    const wrapped = await SandboxManager.wrapWithSandbox(
      `printf ok > ${target}`,
    )
    const result = spawnSync(wrapped, {
      shell: true,
      encoding: 'utf8',
      timeout: 10000,
    })

    expect(result.status).toBe(0)
    expect(existsSync(target)).toBe(true)
  })
})
