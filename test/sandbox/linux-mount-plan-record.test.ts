import { describe, it, expect, afterEach } from 'bun:test'
import {
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { wrapCommandWithSandboxLinux } from '../../src/sandbox/linux-sandbox-utils.js'
import { isLinux } from '../helpers/platform.js'

// Argument-level checks; nothing here executes bwrap.
describe.if(isLinux)('Linux sandbox — mount-plan record and ordering', () => {
  const baseParams = {
    command: 'true',
    needsNetworkRestriction: false,
    allowAllUnixSockets: true,
  }

  const created: string[] = []
  afterEach(() => {
    for (const dir of created.splice(0)) {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  function tempTree(files: Record<string, string>): string {
    const proj = realpathSync(mkdtempSync(join(tmpdir(), 'mount-plan-')))
    created.push(proj)
    for (const [rel, content] of Object.entries(files)) {
      mkdirSync(dirname(join(proj, rel)), { recursive: true })
      writeFileSync(join(proj, rel), content)
    }
    return proj
  }

  it('preserves a carve-out under a denyRead dir when the inner deny mounts later', async () => {
    const proj = tempTree({ 'data/build/logs/keep.txt': 'x' })
    const data = join(proj, 'data')
    const build = join(proj, 'data', 'build')
    const logs = join(proj, 'data', 'build', 'logs')
    const wrapped = await wrapCommandWithSandboxLinux({
      ...baseParams,
      readConfig: { denyOnly: [data, logs], allowWithinDeny: [] },
      writeConfig: { allowOnly: [build], denyWithinAllow: [] },
    })
    // The restore is a second occurrence of the allowWrite bind, after the
    // outer tmpfs; the deeper tmpfs mounts after the restore and on top.
    const bind = `--bind ${build} ${build}`
    const restoreIdx = wrapped.lastIndexOf(bind)
    // Space-terminated: data is a string prefix of logs.
    expect(restoreIdx).toBeGreaterThan(wrapped.indexOf(`--tmpfs ${data} `))
    expect(wrapped.indexOf(`--tmpfs ${logs}`)).toBeGreaterThan(restoreIdx)
  })

  it('pins inside a carve-out whose restore was vetoed; the pin stays beneath the tmpfs', async () => {
    const proj = tempTree({
      'a/t/w/secret-dir/s.txt': 'x',
      'a/t/w/deep/file.txt': 'x',
    })
    // Raw spelling sorts shallow; canonical target is deep inside the
    // carve-out, so the carve-out's restore would bury it.
    symlinkSync(join(proj, 'a/t/w/secret-dir'), join(proj, 's'))
    const wrapped = await wrapCommandWithSandboxLinux({
      ...baseParams,
      readConfig: {
        denyOnly: [join(proj, 's'), join(proj, 'a/t')],
        allowWithinDeny: [],
      },
      writeConfig: {
        allowOnly: [join(proj, 'a/t/w')],
        denyWithinAllow: [join(proj, 'a/t/w/deep/file.txt')],
      },
    })
    const wBind = `--bind ${join(proj, 'a/t/w')} ${join(proj, 'a/t/w')}`
    const tmpfsIdx = wrapped.indexOf(`--tmpfs ${join(proj, 'a/t')}`)
    expect(wrapped.lastIndexOf(wBind)).toBeLessThan(tmpfsIdx)
    const deepPin = `--ro-bind ${join(proj, 'a/t/w/deep')} ${join(proj, 'a/t/w/deep')}`
    expect(wrapped).toContain(deepPin)
    expect(wrapped.indexOf(deepPin)).toBeLessThan(wrapped.indexOf(wBind))
    expect(wrapped.indexOf(deepPin)).toBeLessThan(tmpfsIdx)
  })

  it('emits a deny bind whose region a later unit re-exposed', async () => {
    const proj = tempTree({ 'p/q/w/.git/config': 'x' })
    const W = join(proj, 'p/q/w')
    const cfg = join(proj, 'p/q/w/.git/config')
    // s hides W first; p/q hides it again with its restore vetoed; W's own
    // unit then re-binds W host content, so the deny bind is still needed.
    symlinkSync(W, join(proj, 's'))
    const wrapped = await wrapCommandWithSandboxLinux({
      ...baseParams,
      readConfig: {
        denyOnly: [join(proj, 's'), join(proj, 'p/q'), W],
        allowWithinDeny: [],
      },
      writeConfig: { allowOnly: [W], denyWithinAllow: [cfg] },
    })
    const wBind = `--bind ${W} ${W}`
    expect(wrapped.lastIndexOf(wBind)).toBeGreaterThan(
      wrapped.indexOf(`--tmpfs ${W}`),
    )
    expect(wrapped).toContain(`--ro-bind ${cfg} ${cfg}`)
    const gitPin = `--ro-bind ${join(proj, 'p/q/w/.git')} ${join(proj, 'p/q/w/.git')}`
    expect(wrapped).toContain(gitPin)
    // The pin sits beneath W's first (allow) bind and every tmpfs.
    expect(wrapped.indexOf(gitPin)).toBeLessThan(wrapped.indexOf(wBind))
    expect(wrapped.indexOf(gitPin)).toBeLessThan(
      wrapped.indexOf(`--tmpfs ${join(proj, 's')}`),
    )
  })

  it('resolves a symlink-spelled denyRead directory after the mandatory-deny scan, not before it', async () => {
    // link points at old/ when the wrap starts and at now/ once the scan (a
    // stand-in for ripgrep that retargets it) has run. bwrap mounts the tmpfs
    // where the link points at spawn time, so the write path beneath that
    // target is the one the tmpfs wipes and the one to restore.
    const proj = tempTree({ 'old/w/f': 'x', 'now/w/f': 'x' })
    const link = join(proj, 'link')
    symlinkSync(join(proj, 'old'), link)
    const retarget = join(proj, 'retarget.sh')
    writeFileSync(
      retarget,
      `#!/bin/sh\nln -sfn ${join(proj, 'now')} ${link}\nexit 1\n`,
      { mode: 0o755 },
    )
    const nowW = join(proj, 'now/w')
    const wrapped = await wrapCommandWithSandboxLinux({
      ...baseParams,
      ripgrepConfig: { command: retarget },
      readConfig: { denyOnly: [link], allowWithinDeny: [] },
      writeConfig: { allowOnly: [nowW], denyWithinAllow: [] },
    })
    const bind = `--bind ${nowW} ${nowW}`
    expect(wrapped.lastIndexOf(bind)).toBeGreaterThan(
      wrapped.indexOf(`--tmpfs ${link}`),
    )
  })

  it('keeps a symlink-spelled file mask when a denyWrite names its canonical location', async () => {
    const proj = tempTree({ 'data/secrets/key.pem': 'SECRET' })
    symlinkSync(join(proj, 'data/secrets'), join(proj, 'secrets'))
    const rawSpelling = join(proj, 'secrets', 'key.pem')
    const canonical = join(proj, 'data', 'secrets', 'key.pem')
    const wrapped = await wrapCommandWithSandboxLinux({
      ...baseParams,
      readConfig: { denyOnly: [rawSpelling], allowWithinDeny: [] },
      writeConfig: { allowOnly: [proj], denyWithinAllow: [canonical] },
    })
    expect(wrapped).toContain(`--ro-bind /dev/null ${rawSpelling}`)
    expect(wrapped).not.toContain(`--ro-bind ${canonical} ${canonical}`)
  })

  it('emits a deny bind whose raw route is buried but whose canonical location is exposed', async () => {
    const proj = tempTree({ 'x/W/secret': 'SECRET', 'z/foo': 'host-content' })
    // W's restore is vetoed (an earlier-sorted mask sits inside it), so the
    // raw route reads as covered, but the bind mounts at the canonical dest.
    symlinkSync(join(proj, 'x/W/secret'), join(proj, 's'))
    symlinkSync(join(proj, 'z'), join(proj, 'x/W/link2'))
    const canonicalFoo = join(proj, 'z', 'foo')
    const wrapped = await wrapCommandWithSandboxLinux({
      ...baseParams,
      readConfig: {
        denyOnly: [join(proj, 's'), join(proj, 'x')],
        allowWithinDeny: [],
      },
      writeConfig: {
        allowOnly: [proj, join(proj, 'x/W')],
        denyWithinAllow: [join(proj, 'x/W/link2/foo')],
      },
    })
    expect(wrapped).toContain(`--ro-bind /dev/null ${join(proj, 'x/W/secret')}`)
    expect(wrapped).toContain(`--ro-bind ${canonicalFoo} ${canonicalFoo}`)
  })

  it('pins the canonical parents of a symlink-spelled denyRead file mask beneath the mask, which is emitted once', async () => {
    const proj = tempTree({
      'data/secrets/key.pem': 'SECRET',
      'data/other/thing.txt': 'x',
    })
    symlinkSync(join(proj, 'data/secrets'), join(proj, 'secrets'))
    const rawSpelling = join(proj, 'secrets', 'key.pem')
    const canonicalParent = join(proj, 'data', 'secrets')
    const wrapped = await wrapCommandWithSandboxLinux({
      ...baseParams,
      readConfig: { denyOnly: [rawSpelling], allowWithinDeny: [] },
      writeConfig: {
        allowOnly: [proj],
        denyWithinAllow: [join(proj, 'data/other/thing.txt')],
      },
    })
    const parentPin = `--ro-bind ${canonicalParent} ${canonicalParent}`
    const dataPin = `--ro-bind ${join(proj, 'data')} ${join(proj, 'data')}`
    expect(wrapped).toContain(parentPin)
    expect(wrapped).toContain(dataPin)
    const maskBind = `--ro-bind /dev/null ${rawSpelling}`
    const first = wrapped.indexOf(maskBind)
    expect(first).toBeGreaterThan(-1)
    // No pin lands over the mask, so it is never re-applied.
    expect(wrapped.lastIndexOf(maskBind)).toBe(first)
    expect(wrapped.indexOf(parentPin)).toBeLessThan(first)
    expect(wrapped.indexOf(dataPin)).toBeLessThan(
      wrapped.indexOf(`--bind ${proj} ${proj}`),
    )
  })
})
