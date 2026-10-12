import { afterEach, beforeEach, describe, expect, it } from 'bun:test'
import { spawnSync } from 'node:child_process'
import {
  mkdirSync,
  mkdtempSync,
  realpathSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join, relative } from 'node:path'
import {
  createLinkedWorktreeFixture,
  createMainWorktreeFixture,
} from '../helpers/git-fixtures.js'
import {
  getGitDirs,
  getLinkedGitCommonDir,
  getGitCommonDirDenyPaths,
  resolveGitCommonDirWriteAccess,
} from '../../src/sandbox/sandbox-utils.js'
import { writeNamesOf } from '../../src/sandbox/path-entries.js'
import { isWindows } from '../helpers/platform.js'

describe.if(!isWindows)('Git common directory resolution', () => {
  let root: string
  const cwd = process.cwd()

  beforeEach(() => {
    root = realpathSync(mkdtempSync(join(tmpdir(), 'git-dirs-')))
  })

  afterEach(() => {
    process.chdir(cwd)
    rmSync(root, { recursive: true, force: true })
  })

  it('keeps the main worktree local, even with a hostile commondir', () => {
    const { worktreeDir, commonDir } = createMainWorktreeFixture(
      root,
      'main',
      'ORIGINAL',
    )
    const expected = { gitDir: commonDir, commonDir }
    expect(getGitDirs(worktreeDir)).toEqual(expected)
    writeFileSync(join(commonDir, 'commondir'), root)
    expect(getGitDirs(worktreeDir)).toEqual(expected)
    process.chdir(worktreeDir)
    const base = { allowOnly: [], denyWithinAllow: [] }
    expect(resolveGitCommonDirWriteAccess(base, true)).toEqual(base)
  })

  it('resolves a linked worktree from a subdirectory and relative metadata', () => {
    const { worktreeDir, commonDir, worktreeGitDir } =
      createLinkedWorktreeFixture(root, 'linked', 'ORIGINAL')
    const sub = join(worktreeDir, 'src', 'deep')
    mkdirSync(sub, { recursive: true })
    writeFileSync(
      join(worktreeDir, '.git'),
      `gitdir: ${relative(worktreeDir, worktreeGitDir)}\n`,
    )
    writeFileSync(
      join(worktreeGitDir, 'gitdir'),
      `${relative(worktreeGitDir, join(worktreeDir, '.git'))}\n`,
    )
    expect(getGitDirs(sub)).toEqual({ gitDir: worktreeGitDir, commonDir })
    process.chdir(sub)
    const base = { allowOnly: [], denyWithinAllow: [] }
    for (const head of [
      'ref: refs/heads/unborn',
      'a'.repeat(40),
      'b'.repeat(64),
    ]) {
      writeFileSync(join(worktreeGitDir, 'HEAD'), `${head}\n`)
      const granted = resolveGitCommonDirWriteAccess(base, true)
      expect(granted.literalAllowOnly).toEqual([commonDir])
    }
  })

  it('leaves separate git dirs and unverified common dirs without extra scope', () => {
    const worktreeDir = join(root, 'worktree')
    const gitDir = join(root, 'separate')
    mkdirSync(worktreeDir)
    mkdirSync(gitDir)
    writeFileSync(join(worktreeDir, '.git'), `gitdir: ${gitDir}`)
    expect(getGitDirs(worktreeDir)).toEqual({ gitDir, commonDir: gitDir })
    writeFileSync(join(gitDir, 'commondir'), '..')
    expect(getGitDirs(worktreeDir)).toEqual({ gitDir, commonDir: gitDir })
  })

  for (const attack of [
    'foreign-backlink',
    'missing-backlink',
    'missing-head',
    'malformed-head',
    'missing-objects',
    'missing-refs',
    'symlink-dotgit',
    'symlink-commondir',
    'symlink-backlink',
    'symlink-registry',
    'symlink-gitdir',
    'malformed-dotgit',
    'empty-dotgit',
    'missing-common',
    'cyclic-common',
    'link-dotdot',
  ] as const) {
    it(`grants no extra scope for ${attack}`, () => {
      const fixture = createLinkedWorktreeFixture(root, 'hostile', 'ORIGINAL')
      const { worktreeDir, commonDir, worktreeGitDir } = fixture
      const dotGit = join(worktreeDir, '.git')
      const commondir = join(worktreeGitDir, 'commondir')
      const backlink = join(worktreeGitDir, 'gitdir')
      const replaceWithLink = (p: string) => {
        renameSync(p, `${p}-saved`)
        symlinkSync(`${p}-saved`, p)
      }
      switch (attack) {
        case 'foreign-backlink':
          writeFileSync(backlink, join(commonDir, 'config'))
          break
        case 'missing-backlink':
          rmSync(backlink)
          break
        case 'missing-head':
          rmSync(join(worktreeGitDir, 'HEAD'))
          break
        case 'malformed-head':
          writeFileSync(join(worktreeGitDir, 'HEAD'), 'not a Git HEAD\n')
          break
        case 'missing-objects':
          rmSync(join(commonDir, 'objects'), { recursive: true })
          break
        case 'missing-refs':
          rmSync(join(commonDir, 'refs'), { recursive: true })
          break
        case 'symlink-dotgit':
          replaceWithLink(dotGit)
          break
        case 'symlink-commondir':
          replaceWithLink(commondir)
          break
        case 'symlink-backlink':
          replaceWithLink(backlink)
          break
        case 'symlink-registry':
          replaceWithLink(join(commonDir, 'worktrees'))
          break
        case 'symlink-gitdir': {
          renameSync(worktreeGitDir, join(root, 'outside'))
          symlinkSync(join(root, 'outside'), worktreeGitDir)
          writeFileSync(join(root, 'outside', 'commondir'), commonDir)
          break
        }
        case 'malformed-dotgit':
          writeFileSync(dotGit, 'not a gitdir:')
          break
        case 'empty-dotgit':
          writeFileSync(dotGit, 'gitdir: ')
          break
        case 'missing-common':
          writeFileSync(commondir, '/no-such-common-dir')
          break
        case 'cyclic-common': {
          symlinkSync('loop', join(worktreeGitDir, 'loop'))
          writeFileSync(commondir, 'loop')
          break
        }
        case 'link-dotdot': {
          // Lexically folding link/.. would return the verified commonDir.
          const outside = join(root, 'other', 'child')
          mkdirSync(outside, { recursive: true })
          symlinkSync(outside, join(commonDir, 'link'))
          writeFileSync(commondir, '../../link/..')
          break
        }
      }
      const dirs = getGitDirs(worktreeDir)
      if (
        [
          'missing-head',
          'malformed-head',
          'missing-objects',
          'missing-refs',
        ].includes(attack)
      ) {
        expect(getGitCommonDirDenyPaths(dirs)).toContain(
          join(commonDir, 'config'),
        )
        expect(getGitCommonDirDenyPaths(dirs)).toContain(
          join(commonDir, 'hooks'),
        )
      } else {
        expect(getLinkedGitCommonDir(dirs)).toBeUndefined()
      }
      process.chdir(worktreeDir)
      expect(
        resolveGitCommonDirWriteAccess(
          { allowOnly: [], denyWithinAllow: [] },
          true,
        ).literalAllowOnly,
      ).toBeUndefined()
    })
  }

  it('does not grant an ordinary parent from fabricated worktree relationships', () => {
    const project = join(root, 'ordinary-parent', 'worktrees', 'project')
    mkdirSync(project, { recursive: true })
    writeFileSync(join(project, '.git'), 'gitdir: .\n')
    writeFileSync(join(project, 'commondir'), '../..\n')
    writeFileSync(join(project, 'gitdir'), '.git\n')
    process.chdir(project)
    expect(
      resolveGitCommonDirWriteAccess(
        { allowOnly: ['.'], denyWithinAllow: [] },
        true,
      ).literalAllowOnly,
    ).toBeUndefined()
  })

  it('does not grant a foreign worktree by copying its .git file', () => {
    const { worktreeGitDir } = createLinkedWorktreeFixture(
      root,
      'foreign',
      'ORIGINAL',
    )
    const attacker = join(root, 'attacker')
    mkdirSync(attacker)
    writeFileSync(join(attacker, '.git'), `gitdir: ${worktreeGitDir}`)
    expect(getGitDirs(attacker)).toBeUndefined()
  })

  it('returns undefined outside a checkout or for missing metadata', () => {
    expect(getGitDirs(root)).toBeUndefined()
    expect(getGitDirs(join(root, 'missing'))).toBeUndefined()
  })

  it('keeps computed grants and denies literal and preserves caller lists', () => {
    const { worktreeDir, commonDir, worktreeGitDir } =
      createLinkedWorktreeFixture(root, '[moon]*?', 'ORIGINAL')
    const sibling = join(commonDir, 'worktrees', '[star]?')
    mkdirSync(sibling)
    process.chdir(worktreeDir)
    const base = {
      allowOnly: ['.'],
      literalAllowOnly: [worktreeDir],
      denyWithinAllow: [join(commonDir, 'refs')],
    }
    const before = structuredClone(base)
    const result = resolveGitCommonDirWriteAccess(base, true)
    expect(result.literalAllowOnly).toEqual([worktreeDir, commonDir])
    expect(new Set(result.literalDenyWithinAllow)).toEqual(
      new Set([
        join(commonDir, 'hooks'),
        join(commonDir, 'config'),
        join(commonDir, 'config.worktree'),
        join(sibling, 'config.worktree'),
        join(worktreeGitDir, 'config.worktree'),
      ]),
    )
    expect(writeNamesOf(result)?.allowOnly).toContain(commonDir)
    expect(base).toEqual(before)
    expect(
      resolveGitCommonDirWriteAccess(base, false).literalAllowOnly,
    ).toEqual([worktreeDir])
    expect(
      resolveGitCommonDirWriteAccess(base, true, true).literalDenyWithinAllow,
    ).toEqual([join(commonDir, 'hooks')])
    expect(resolveGitCommonDirWriteAccess(undefined, true)).toBeUndefined()
    expect(getGitCommonDirDenyPaths(getGitDirs(), false)).toEqual(
      result.literalDenyWithinAllow!,
    )
  })

  it('denies existing and dangling hooks/config links by both name and target', () => {
    const fixture = createLinkedWorktreeFixture(root, 'linked', 'ORIGINAL')
    for (const target of [
      join(fixture.commonDir, 'hooks'),
      join(fixture.commonDir, 'config'),
      join(fixture.commonDir, 'config.worktree'),
      join(fixture.worktreeGitDir, 'config.worktree'),
    ]) {
      renameSync(target, `${target}-real`)
      symlinkSync(`${target}-real`, target)
      const denies = getGitCommonDirDenyPaths(getGitDirs(fixture.worktreeDir))
      expect(denies).toContain(target)
      expect(denies).toContain(`${target}-real`)
      rmSync(`${target}-real`, { recursive: true })
      expect(
        getGitCommonDirDenyPaths(getGitDirs(fixture.worktreeDir)),
      ).toContain(`${target}-real`)
    }
    const alias = join(fixture.commonDir, 'worktrees', 'alias')
    symlinkSync('..', alias)
    const denies = getGitCommonDirDenyPaths(getGitDirs(fixture.worktreeDir))
    expect(denies).toContain(join(alias, 'config.worktree'))
    expect(denies).toContain(join(fixture.commonDir, 'config.worktree'))
  })

  it('agrees with Git for a real linked checkout without reading personal config', () => {
    const home = join(root, 'home')
    const main = join(root, 'main')
    const linked = join(root, 'linked')
    mkdirSync(home)
    mkdirSync(main)
    const git = (args: string[], cwd = main) => {
      const result = spawnSync('git', args, {
        cwd,
        encoding: 'utf8',
        timeout: 10000,
        env: {
          PATH: process.env.PATH,
          HOME: home,
          XDG_CONFIG_HOME: home,
          GIT_CONFIG_NOSYSTEM: '1',
          GIT_CONFIG_GLOBAL: '/dev/null',
          GIT_TERMINAL_PROMPT: '0',
        },
      })
      expect(result.status).toBe(0)
      return result.stdout.trim()
    }
    git(['init', '-q', '--template='])
    git([
      '-c',
      'user.name=Moon',
      '-c',
      'user.email=moon@example.invalid',
      '-c',
      'commit.gpgSign=false',
      'commit',
      '-q',
      '--allow-empty',
      '-m',
      'moon',
    ])
    git(['worktree', 'add', '-q', '-b', 'moon', linked])
    expect(getGitDirs(linked)).toEqual({
      gitDir: git(['rev-parse', '--absolute-git-dir'], linked),
      commonDir: git(
        ['rev-parse', '--path-format=absolute', '--git-common-dir'],
        linked,
      ),
    })
  })
})
