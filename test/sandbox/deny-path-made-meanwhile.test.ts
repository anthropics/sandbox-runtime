import { describe, it, expect, beforeEach, afterEach, spyOn } from 'bun:test'
import * as fs from 'fs'
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import {
  wrapCommandWithSandboxLinux,
  cleanupBwrapMountPoints,
} from '../../src/sandbox/linux-sandbox-utils.js'
import { isLinux } from '../helpers/platform.js'
import { countMounts } from '../helpers/bwrap-argv.js'

/**
 * An absent deny path is blocked by a mount point bubblewrap makes on the
 * host. Two processes wrapping in one project deny the same absent paths, so
 * one's bubblewrap can make that file between two looks of the other's wrap.
 */
describe.if(isLinux)('A deny path made while the wrap is looking', () => {
  let base: string
  let area: string
  const savedCwd = process.cwd()

  beforeEach(() => {
    cleanupBwrapMountPoints({ force: true })
    base = realpathSync(mkdtempSync(join(tmpdir(), 'deny-meanwhile-')))
    area = join(base, 'area')
    mkdirSync(area)
    process.chdir(area)
  })

  afterEach(() => {
    process.chdir(savedCwd)
    cleanupBwrapMountPoints({ force: true })
    rmSync(base, { recursive: true, force: true })
  })

  const wrap = (deny: string): Promise<string> =>
    wrapCommandWithSandboxLinux({
      command: 'true',
      needsNetworkRestriction: false,
      readConfig: { denyOnly: [] },
      writeConfig: { allowOnly: [area], denyWithinAllow: [deny] },
    })

  it('still binds over a path that was absent when asked and is a file a moment later', async () => {
    const denied = join(area, 'denied.lock')
    const exists = fs.existsSync
    let made = false
    // What another sandbox's bubblewrap does: an empty read-only file.
    const spy = spyOn(fs, 'existsSync').mockImplementation(((
      p: fs.PathLike,
    ) => {
      const was = exists(p)
      if (p === denied && !made) {
        made = true
        writeFileSync(denied, '')
        chmodSync(denied, 0o444)
      }
      return was
    }) as typeof fs.existsSync)
    let wrapped: string
    try {
      wrapped = await wrap(denied)
    } finally {
      spy.mockRestore()
    }

    expect(made).toBe(true)
    expect(countMounts(wrapped, '--ro-bind', '/dev/null', denied)).toBe(1)
  })

  it('still leaves alone a path beneath a file, which can never be created', async () => {
    writeFileSync(join(area, '.git'), 'gitdir: elsewhere\n')
    const denied = join(area, '.git', 'hooks')

    const wrapped = await wrap(denied)

    expect(wrapped).not.toContain(denied)
  })
})
