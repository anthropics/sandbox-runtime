import { describe, it, expect, afterAll } from 'bun:test'
import { homedir } from 'node:os'
import { join } from 'node:path'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import { getDefaultWritePaths } from '../../src/sandbox/sandbox-utils.js'
import { isLinux, isMacOS } from '../helpers/platform.js'

const npmLogs = join(homedir(), '.npm/_logs')
const claudeDebug = join(homedir(), '.claude/debug')

/**
 * The two home directories among the default write paths are conveniences
 * the caller never asked for; one that a read-deny covers must not be bound
 * back over that deny. The paths the sandbox itself needs are never dropped.
 */
describe('getDefaultWritePaths', () => {
  it('drops a home convenience a read-deny covers, however the deny is spelled', () => {
    for (const deny of [homedir(), '~/', '~/**', join(homedir(), '**')]) {
      const paths = getDefaultWritePaths([deny])
      expect(paths).not.toContain(npmLogs)
      expect(paths).not.toContain(claudeDebug)
    }
    expect(getDefaultWritePaths([npmLogs])).toEqual(
      getDefaultWritePaths().filter(p => p !== npmLogs),
    )
  })

  it('drops a home convenience under a directory a glob matches', () => {
    const paths = getDefaultWritePaths([join(homedir(), '.n*')])
    expect(paths).not.toContain(npmLogs)
    expect(paths).toContain(claudeDebug)
  })

  it('keeps a convenience beside, not beneath, what is read-denied', () => {
    const kept = getDefaultWritePaths([
      join(homedir(), '.npmrc'),
      join(homedir(), '.np'),
      join(homedir(), '**/*.log'),
    ])
    expect(kept).toContain(npmLogs)
    expect(kept).toContain(claudeDebug)
  })

  it('keeps the paths the sandbox itself needs under any read-deny', () => {
    for (const deny of ['/', '/**', '/tmp', '/private/tmp', '/dev']) {
      expect(getDefaultWritePaths([deny])).toEqual(
        expect.arrayContaining(
          getDefaultWritePaths().filter(
            p => p !== npmLogs && p !== claudeDebug,
          ),
        ),
      )
    }
  })
})

describe.if(isLinux || isMacOS)('default write paths in SandboxManager', () => {
  afterAll(async () => {
    await SandboxManager.reset()
  })

  it('leaves out a home convenience under a filesystem or credential read-deny', async () => {
    await SandboxManager.reset()
    await SandboxManager.initialize({
      network: { allowedDomains: [], deniedDomains: [] },
      filesystem: {
        denyRead: [join(homedir(), '.npm')],
        allowWrite: [],
        denyWrite: [],
      },
      credentials: {
        files: [{ path: join(homedir(), '.claude'), mode: 'deny' }],
      },
    })

    const { allowOnly } = SandboxManager.getFsWriteConfig()
    expect(allowOnly).not.toContain(npmLogs)
    expect(allowOnly).not.toContain(claudeDebug)
    expect(allowOnly).toContain('/tmp/claude')

    const wrapped = await SandboxManager.wrapWithSandbox('true')
    expect(wrapped).not.toContain(npmLogs)
    expect(wrapped).not.toContain(claudeDebug)
  })
})
