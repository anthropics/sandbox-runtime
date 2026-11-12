import { afterEach, beforeEach, describe, expect, it } from 'bun:test'
import {
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  cleanupBwrapMountPoints,
  linuxGetCwdMandatoryDenyPaths,
  wrapCommandWithSandboxLinux,
} from '../../src/sandbox/linux-sandbox-utils.js'
import {
  macGetMandatoryDenyEntries,
  wrapCommandWithSandboxMacOS,
} from '../../src/sandbox/macos-sandbox-utils.js'
import {
  createLinkedWorktreeFixture,
  type LinkedWorktreeFixture,
} from '../helpers/git-fixtures.js'
import { indexOfMount, lastMountAt } from '../helpers/bwrap-argv.js'
import { isWindows } from '../helpers/platform.js'

/** Profile generation only: neither backend's returned command is executed. */
describe.if(!isWindows)('Git common directory profiles', () => {
  let root: string
  let fixture: LinkedWorktreeFixture
  const cwd = process.cwd()

  beforeEach(() => {
    root = realpathSync(mkdtempSync(join(tmpdir(), 'git-common-profiles-')))
    fixture = createLinkedWorktreeFixture(root, 'linked', 'ORIGINAL')
    process.chdir(fixture.worktreeDir)
  })

  afterEach(() => {
    cleanupBwrapMountPoints({ force: true })
    process.chdir(cwd)
    rmSync(root, { recursive: true, force: true })
  })

  it('exposes common denies to both mandatory-deny consumers even with malformed HEAD', () => {
    writeFileSync(join(fixture.worktreeGitDir, 'HEAD'), 'not a Git HEAD\n')
    rmSync(join(fixture.commonDir, 'config.worktree'))
    for (const allowGitConfig of [false, true]) {
      const expected = [join(fixture.commonDir, 'hooks')]
      if (!allowGitConfig)
        expected.push(
          join(fixture.commonDir, 'config'),
          join(fixture.commonDir, 'config.worktree'),
          join(fixture.worktreeGitDir, 'config.worktree'),
        )
      expect(linuxGetCwdMandatoryDenyPaths(allowGitConfig)).toEqual(
        expect.arrayContaining(expected),
      )
      expect(macGetMandatoryDenyEntries(allowGitConfig)).toEqual(
        expect.arrayContaining(expected.map(path => ({ glob: false, path }))),
      )
    }
  })

  for (const allowGitConfig of [false, true]) {
    it(`emits Linux grants before explicit and mandatory denies, config allowed=${allowGitConfig}`, async () => {
      const { commonDir, worktreeGitDir } = fixture
      const ref = join(commonDir, 'refs', 'heads', 'main')
      const secret = join(commonDir, 'secret')
      const mainConfig = join(commonDir, 'config.worktree')
      rmSync(mainConfig)
      writeFileSync(secret, 'MOON')
      const wrapped = await wrapCommandWithSandboxLinux({
        command: 'true',
        needsNetworkRestriction: false,
        bwrapPath: '/not-executed/bwrap',
        allowAllUnixSockets: true,
        readConfig: { denyOnly: [secret] },
        writeConfig: { allowOnly: ['.'], denyWithinAllow: [ref] },
        allowGitCommonDir: true,
        allowGitConfig,
      })
      const grant = indexOfMount(wrapped, '--bind', commonDir, commonDir)
      expect(grant).toBeGreaterThan(-1)
      for (const target of [
        ref,
        join(commonDir, 'hooks'),
        ...(!allowGitConfig
          ? [join(commonDir, 'config'), join(worktreeGitDir, 'config.worktree')]
          : []),
      ]) {
        expect(
          indexOfMount(wrapped, '--ro-bind', target, target),
        ).toBeGreaterThan(grant)
      }
      // A read-denied file inside the new grant is not exposed by its bind.
      expect(lastMountAt(wrapped, secret)).toBe(`--ro-bind /dev/null ${secret}`)
      expect(lastMountAt(wrapped, mainConfig)).toBe(
        allowGitConfig ? undefined : `--ro-bind /dev/null ${mainConfig}`,
      )
      if (allowGitConfig) {
        expect(lastMountAt(wrapped, join(commonDir, 'config'))).toBeUndefined()
        expect(
          lastMountAt(wrapped, join(worktreeGitDir, 'config.worktree')),
        ).toBeUndefined()
      }
    })
  }

  it('keeps macOS grants literal, groups sibling config denies, and retains movement protection', () => {
    const odd = createLinkedWorktreeFixture(root, '[moon]*?', 'ORIGINAL')
    process.chdir(odd.worktreeDir)
    const secret = join(odd.commonDir, 'refs', 'secret')
    writeFileSync(secret, 'MOON')
    const siblings = ['one', 'two', 'three', '[star]?']
    for (const name of siblings)
      mkdirSync(join(odd.commonDir, 'worktrees', name))
    const wrapped = wrapCommandWithSandboxMacOS({
      command: 'true',
      needsNetworkRestriction: false,
      readConfig: { denyOnly: [secret] },
      writeConfig: {
        allowOnly: ['.'],
        denyWithinAllow: [],
        literalDenyWithinAllow: [join(odd.commonDir, 'refs', 'heads')],
      },
      allowGitCommonDir: true,
    })
    const write = wrapped.slice(wrapped.indexOf('; File write'))
    const denyAt = write.indexOf('(deny file-write*')
    expect(write.slice(0, denyAt)).toContain(
      `(subpath ${JSON.stringify(odd.commonDir)})`,
    )
    expect(write.slice(denyAt)).toContain(
      `(subpath ${JSON.stringify(join(odd.commonDir, 'hooks'))})`,
    )
    expect(write.slice(denyAt)).toContain(
      `(subpath ${JSON.stringify(join(odd.commonDir, 'config'))})`,
    )
    expect(write.slice(denyAt)).toContain(
      `(subpath ${JSON.stringify(join(odd.commonDir, 'config.worktree'))})`,
    )
    expect(write.slice(denyAt)).toContain(
      `(subpath ${JSON.stringify(join(odd.commonDir, 'refs', 'heads'))})`,
    )
    const regexes = [...write.matchAll(/\(regex ("(?:[^"\\]|\\.)*")\)/g)].map(
      match => new RegExp(JSON.parse(match[1]) as string),
    )
    for (const name of [...siblings, 'feature']) {
      const dir = join(odd.commonDir, 'worktrees', name)
      expect(regexes.some(re => re.test(join(dir, 'config.worktree')))).toBe(
        true,
      )
      expect(regexes.some(re => re.test(dir))).toBe(true)
      expect(regexes.some(re => re.test(join(dir, 'index')))).toBe(false)
    }
    const trailing = write.slice(write.indexOf('; File read: keep read-denied'))
    expect(trailing).toContain('(deny file-write-unlink')
    expect(trailing).toContain(`(subpath ${JSON.stringify(secret)})`)
  })

  it('denies the absent target of a dangling hooks link inside the extra grant', async () => {
    const hooks = join(fixture.commonDir, 'hooks')
    const target = join(fixture.commonDir, 'future-hooks')
    rmSync(hooks, { recursive: true })
    symlinkSync('future-hooks', hooks)
    const params = {
      command: 'true',
      needsNetworkRestriction: false,
      readConfig: undefined,
      writeConfig: { allowOnly: ['.'], denyWithinAllow: [] },
      allowGitCommonDir: true,
      allowGitConfig: true,
    }
    const mac = wrapCommandWithSandboxMacOS(params)
    const denies = mac.slice(mac.indexOf('(deny file-write*'))
    expect(denies).toContain(`(subpath ${JSON.stringify(target)})`)
    const linux = await wrapCommandWithSandboxLinux({
      ...params,
      bwrapPath: '/not-executed/bwrap',
      allowAllUnixSockets: true,
    })
    expect(lastMountAt(linux, target)).toBe(`--ro-bind /dev/null ${target}`)
  })

  it('leaves disabled filesystem policy disabled in both wrappers', async () => {
    const params = {
      command: 'true',
      needsNetworkRestriction: false,
      readConfig: undefined,
      writeConfig: undefined,
      allowGitCommonDir: true,
    }
    expect(wrapCommandWithSandboxMacOS(params)).toBe('true')
    expect(await wrapCommandWithSandboxLinux(params)).toBe('true')
  })
})
