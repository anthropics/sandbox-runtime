import { afterAll, beforeAll, describe, expect, it } from 'bun:test'
import { spawnSync } from 'node:child_process'
import {
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { join } from 'node:path'
import { wrapCommandWithSandboxMacOS } from '../../src/sandbox/macos-sandbox-utils.js'
import {
  isSymlinkOutsideBoundary,
  normalizePathForSandbox,
} from '../../src/sandbox/sandbox-utils.js'
import { isMacOS, isWindows } from '../helpers/platform.js'

describe.if(!isWindows)('system symlink root boundaries', () => {
  it.each(['/tmp', '/var'])('accepts the exact canonical root for %s', root => {
    expect(isSymlinkOutsideBoundary(root, '/private' + root)).toBe(false)
    expect(isSymlinkOutsideBoundary(root + '/', '/private' + root + '/')).toBe(
      false,
    )
    expect(
      isSymlinkOutsideBoundary(root + '/child', '/private' + root + '/child'),
    ).toBe(false)
  })

  it.each([
    ['/tmp', '/'],
    ['/var', '/private'],
    ['/tmp', '/private/var'],
    ['/var', '/private/tmp'],
    ['/tmp-other', '/private/tmp-other'],
    ['/various', '/private/various'],
    ['/tmp/child', '/private/tmp'],
    ['/var/child', '/private/var'],
  ])('still rejects %s resolving to %s', (original, resolved) => {
    expect(isSymlinkOutsideBoundary(original, resolved)).toBe(true)
  })
})

describe.if(isMacOS)('macOS system symlink root rules', () => {
  let tmpFixture: string
  let varFixture: string

  beforeAll(() => {
    tmpFixture = mkdtempSync('/private/tmp/srt-system-root-')
    varFixture = mkdtempSync('/private/var/tmp/srt-system-root-')
  })

  afterAll(() => {
    rmSync(tmpFixture, { recursive: true, force: true })
    rmSync(varFixture, { recursive: true, force: true })
  })

  it.each(['/tmp', '/var'])('canonicalizes the existing %s root', root => {
    expect(normalizePathForSandbox(root)).toBe(realpathSync(root))
    expect(normalizePathForSandbox(root + '/')).toBe(realpathSync(root))
    expect(normalizePathForSandbox(root + '/*')).toBe(realpathSync(root) + '/*')
  })

  it.each(['/tmp', '/var'])(
    'allows writes through both spellings of %s',
    root => {
      const fixture = root === '/tmp' ? tmpFixture : varFixture
      for (const [index, directory] of [
        fixture,
        fixture.slice('/private'.length),
      ].entries()) {
        const file = join(directory, `allowed-${index}`)
        const command = wrapCommandWithSandboxMacOS({
          command: `printf allowed > ${JSON.stringify(file)}`,
          needsNetworkRestriction: false,
          readConfig: undefined,
          writeConfig: { allowOnly: [root], denyWithinAllow: [] },
        })
        const result = spawnSync(command, {
          shell: true,
          encoding: 'utf8',
          timeout: 10000,
        })
        expect(result.error).toBeUndefined()
        expect(result.status).toBe(0)
        expect(readFileSync(file, 'utf8')).toBe('allowed')
      }
    },
  )

  it.each(['/tmp', '/var'])('retains explicit write denies under %s', root => {
    const fixture = root === '/tmp' ? tmpFixture : varFixture
    const protectedFile = join(fixture, 'protected')
    writeFileSync(protectedFile, 'unchanged')
    const command = wrapCommandWithSandboxMacOS({
      command: `printf changed > ${JSON.stringify(protectedFile)}`,
      needsNetworkRestriction: false,
      readConfig: undefined,
      writeConfig: { allowOnly: [root], denyWithinAllow: [protectedFile] },
    })
    const result = spawnSync(command, {
      shell: true,
      encoding: 'utf8',
      timeout: 10000,
    })
    expect(result.error).toBeUndefined()
    expect(result.status).not.toBe(0)
    expect(result.stderr).toContain('Operation not permitted')
    expect(readFileSync(protectedFile, 'utf8')).toBe('unchanged')
  })

  it.each(['/tmp', '/var'])('does not allow writes outside %s', root => {
    const otherFixture = root === '/tmp' ? varFixture : tmpFixture
    const outsideFile = join(otherFixture, 'outside')
    writeFileSync(outsideFile, 'unchanged')
    const command = wrapCommandWithSandboxMacOS({
      command: `printf changed > ${JSON.stringify(outsideFile)}`,
      needsNetworkRestriction: false,
      readConfig: undefined,
      writeConfig: { allowOnly: [root], denyWithinAllow: [] },
    })
    const result = spawnSync(command, {
      shell: true,
      encoding: 'utf8',
      timeout: 10000,
    })
    expect(result.error).toBeUndefined()
    expect(result.status).not.toBe(0)
    expect(result.stderr).toContain('Operation not permitted')
    expect(readFileSync(outsideFile, 'utf8')).toBe('unchanged')
  })
})
