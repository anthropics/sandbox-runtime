import { describe, it, expect, beforeAll, afterAll, spyOn } from 'bun:test'
// The namespaces the library binds, so a spy on one is seen by the code under
// test.
import * as fs from 'fs'
import * as sandboxUtils from '../../src/sandbox/sandbox-utils.js'
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { spawnSync } from 'node:child_process'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { expandReadDenyGlobLinux } from '../../src/sandbox/read-deny-glob.js'
import {
  GLOB_WALK_MAX_ENTRIES,
  GLOB_WALK_TIMEOUT_MS,
  GlobWalkBudgetError,
  expandGlobPattern,
  newGlobWalkBudget,
  walkGlobPattern,
} from '../../src/sandbox/sandbox-utils.js'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import { LinuxSandboxProfileError } from '../../src/sandbox/linux-sandbox-utils.js'
import { isLinux, isWindows } from '../helpers/platform.js'
import { bwrapCanNamespace } from '../helpers/bwrap-namespace.js'
import { countMounts, indexOfMount } from '../helpers/bwrap-argv.js'

/** Every directory `fn` had listed, in order, one entry per listing. */
function listedDuring<T>(fn: () => T): { result: T; listed: string[] } {
  const listed: string[] = []
  const readdirSync = fs.readdirSync
  const spy = spyOn(fs, 'readdirSync').mockImplementation(((
    ...args: Parameters<typeof fs.readdirSync>
  ) => {
    listed.push(String(args[0]))
    return readdirSync(...args)
  }) as typeof fs.readdirSync)
  try {
    return { result: fn(), listed }
  } finally {
    spy.mockRestore()
  }
}

/**
 * `root/start/next -> ../pool/d1`, `pool/d1/next -> ../d2` and so on, each
 * `pool/d<i>` holding a `.env`: `links` directories that nothing but the link
 * before them leads to from `start`.
 */
function plantChain(root: string, links: number): void {
  mkdirSync(join(root, 'start'), { recursive: true })
  mkdirSync(join(root, 'pool'))
  symlinkSync(join('..', 'pool', 'd1'), join(root, 'start', 'next'))
  for (let i = 1; i <= links; i++) {
    mkdirSync(join(root, 'pool', `d${i}`))
    writeFileSync(join(root, 'pool', `d${i}`, '.env'), '')
    if (i < links) {
      symlinkSync(join('..', `d${i + 1}`), join(root, 'pool', `d${i}`, 'next'))
    }
  }
}

/** What `fn` throws, or undefined when it returns. */
function thrownBy(fn: () => unknown): unknown {
  try {
    fn()
  } catch (error) {
    return error
  }
  return undefined
}

describe.if(!isWindows)('a read-deny glob and a link out of its tree', () => {
  let ROOT: string
  let PROJ: string
  let OUTSIDE: string

  beforeAll(() => {
    ROOT = realpathSync(mkdtempSync(join(tmpdir(), 'deny-glob-bound-')))
    PROJ = join(ROOT, 'proj')
    OUTSIDE = join(ROOT, 'outside')
    mkdirSync(join(PROJ, 'src'), { recursive: true })
    mkdirSync(join(PROJ, 'sub'))
    writeFileSync(join(PROJ, '.env'), 'A=1')
    writeFileSync(join(PROJ, 'src', '.env'), 'B=2')
    // What a pattern that starts at proj must not go looking for: each of
    // these matches `**/.env` by name.
    mkdirSync(join(OUTSIDE, 'deep'), { recursive: true })
    writeFileSync(join(OUTSIDE, '.env'), 'C=3')
    writeFileSync(join(OUTSIDE, 'deep', '.env'), 'D=4')
  })

  afterAll(() => {
    rmSync(ROOT, { recursive: true, force: true })
  })

  /** A project of its own beside OUTSIDE, for a case that plants links. */
  function project(name: string): string {
    const proj = join(ROOT, name)
    mkdirSync(join(proj, 'src'), { recursive: true })
    mkdirSync(join(proj, 'sub'))
    writeFileSync(join(proj, '.env'), 'A=1')
    writeFileSync(join(proj, 'src', '.env'), 'B=2')
    return proj
  }

  it('does not list what a link out of the tree leads to', () => {
    const proj = project('p-out')
    symlinkSync(join('..', 'outside'), join(proj, 'rel'))
    symlinkSync(OUTSIDE, join(proj, 'abs'))
    // A directory beside the tree whose path begins with the tree's own.
    const sibling = project('p-out-sibling')
    symlinkSync(sibling, join(proj, 'sib'))

    const unfollowedLinks = new Map<string, string>()
    const { result: mounts, listed } = listedDuring(() =>
      expandReadDenyGlobLinux(join(proj, '**/.env'), [], undefined, {
        unfollowedLinks,
      }),
    )

    // Only what is in the tree, and neither .env behind the links.
    expect(mounts).toEqual([join(proj, '.env'), join(proj, 'src', '.env')])
    // Not read, under any name.
    expect(listed.sort()).toEqual(
      [proj, join(proj, 'src'), join(proj, 'sub')].sort(),
    )
    // Each link that was left is handed back with where it leads.
    const left: [string, string][] = [
      [join(proj, 'abs'), OUTSIDE],
      [join(proj, 'rel'), OUTSIDE],
      [join(proj, 'sib'), sibling],
    ]
    expect([...unfollowedLinks].sort()).toEqual(left)
    expect(
      [
        ...walkGlobPattern(join(proj, '**/.env'), {
          followSymlinkedDirectories: true,
        }).unfollowedLinks,
      ].sort(),
    ).toEqual(left)
  })

  it('does not report a link back up the tree as one that left it', () => {
    // up -> .. leads above the directory the pattern starts from. That is
    // the older rule's link: not listed through, and not one of these.
    const proj = project('p-up')
    symlinkSync('..', join(proj, 'src', 'up'))
    symlinkSync(ROOT, join(proj, 'top'))

    const unfollowedLinks = new Map<string, string>()
    const { result: mounts, listed } = listedDuring(() =>
      expandReadDenyGlobLinux(join(proj, '**/.env'), [], undefined, {
        unfollowedLinks,
      }),
    )

    expect(mounts).toEqual([join(proj, '.env'), join(proj, 'src', '.env')])
    expect(listed.sort()).toEqual(
      [proj, join(proj, 'src'), join(proj, 'sub')].sort(),
    )
    expect([...unfollowedLinks]).toEqual([])
  })

  it('judges a link by where it resolves, not by how it is written', () => {
    const proj = project('p-spelled')
    // Written from inside the tree, it still leads out of it.
    symlinkSync('./sub/../../outside', join(proj, 'dotted'))
    // So does one that names a path inside the tree which is itself a link
    // out of it.
    symlinkSync(join('..', '..', 'outside'), join(proj, 'sub', 'exit'))
    symlinkSync(join('sub', 'exit'), join(proj, 'hop'))
    // Written out of the tree and back, it leads to a directory inside it.
    symlinkSync(join('..', 'p-spelled', 'src'), join(proj, 'back'))

    const unfollowedLinks = new Map<string, string>()
    const { result: mounts, listed } = listedDuring(() =>
      expandReadDenyGlobLinux(join(proj, '*/.env'), [], undefined, {
        unfollowedLinks,
      }),
    )

    expect(mounts).toEqual([join(proj, 'src', '.env')])
    expect(listed.filter(dir => dir.startsWith(OUTSIDE))).toEqual([])
    expect([...unfollowedLinks].sort()).toEqual([
      [join(proj, 'dotted'), OUTSIDE],
      [join(proj, 'hop'), OUTSIDE],
    ])
    // `back` is the only name `b*` matches, so src/.env is found through it.
    expect(expandReadDenyGlobLinux(join(proj, 'b*/.env'), [])).toEqual([
      join(proj, 'src', '.env'),
    ])
  })

  it('still finds a match behind a link that stays inside the tree, once, where it really is', () => {
    const proj = project('p-in')
    symlinkSync('src', join(proj, 'alias'))

    const unfollowedLinks = new Map<string, string>()
    // `a*` matches the link alone: the file is reached through it.
    expect(
      expandReadDenyGlobLinux(join(proj, 'a*/.env'), [], undefined, {
        unfollowedLinks,
      }),
    ).toEqual([join(proj, 'src', '.env')])
    // `**` reaches it by both names, and it is listed and mounted once.
    const { result: mounts, listed } = listedDuring(() =>
      expandReadDenyGlobLinux(join(proj, '**/.env'), [], undefined, {
        unfollowedLinks,
      }),
    )
    expect(mounts).toEqual([join(proj, '.env'), join(proj, 'src', '.env')])
    expect(listed.filter(dir => dir === join(proj, 'src'))).toHaveLength(1)
    expect([...unfollowedLinks]).toEqual([])
  })

  it('finds a file that only a link inside the tree leads to', () => {
    // tlink -> sub, and `t*` matches the link and not sub: the link is the
    // only way the pattern has to sub/.env, so a walk that followed no link
    // would find nothing.
    const proj = join(ROOT, 'p-route')
    mkdirSync(join(proj, 'sub'), { recursive: true })
    writeFileSync(join(proj, 'sub', '.env'), 'A=1')
    symlinkSync(join(proj, 'sub'), join(proj, 'tlink'))

    const unfollowedLinks = new Map<string, string>()
    expect(
      expandReadDenyGlobLinux(join(proj, 't*/**/.env'), [], undefined, {
        unfollowedLinks,
      }),
    ).toEqual([join(proj, 'sub', '.env')])
    expect([...unfollowedLinks]).toEqual([])
  })

  it('takes the tree to be the directory the pattern starts from, not the one above it', () => {
    // src/shared -> ../shared: the pattern that starts at src does not reach
    // shared/.env, and the one that starts at the project does.
    const proj = join(ROOT, 'p-base')
    mkdirSync(join(proj, 'src'), { recursive: true })
    mkdirSync(join(proj, 'shared'))
    writeFileSync(join(proj, 'src', '.env'), 'A=1')
    writeFileSync(join(proj, 'shared', '.env'), 'B=2')
    symlinkSync(join('..', 'shared'), join(proj, 'src', 'shared'))

    const unfollowedLinks = new Map<string, string>()
    expect(
      expandReadDenyGlobLinux(join(proj, 'src', '**/.env'), [], undefined, {
        unfollowedLinks,
      }),
    ).toEqual([join(proj, 'src', '.env')])
    expect([...unfollowedLinks]).toEqual([
      [join(proj, 'src', 'shared'), join(proj, 'shared')],
    ])
    expect(expandReadDenyGlobLinux(join(proj, '**/.env'), [])).toEqual([
      join(proj, 'shared', '.env'),
      join(proj, 'src', '.env'),
    ])
  })

  it('takes the tree to be where the pattern really starts, when it starts from a link', () => {
    // entry -> p-aliased: the pattern is spelled through the link, and the
    // tree is the directory it leads to. A link inside that directory stays
    // inside the tree, and one out of it leaves.
    const proj = project('p-aliased')
    const entry = join(ROOT, 'entry')
    symlinkSync(proj, entry)
    symlinkSync('src', join(proj, 'alias'))
    symlinkSync(OUTSIDE, join(proj, 'away'))

    const unfollowedLinks = new Map<string, string>()
    expect(
      expandReadDenyGlobLinux(join(entry, 'a*/.env'), [], undefined, {
        unfollowedLinks,
      }),
    ).toEqual([join(proj, 'src', '.env')])
    expect([...unfollowedLinks]).toEqual([[join(entry, 'away'), OUTSIDE]])
  })

  it('still denies what a link leads to when the link itself matches', () => {
    const proj = project('p-own')
    mkdirSync(join(OUTSIDE, 'vault', 'inner'), { recursive: true })
    writeFileSync(join(OUTSIDE, 'vault', 'inner', 'id.pem'), 'KEY')
    writeFileSync(join(OUTSIDE, 'key.pem'), 'KEY')
    mkdirSync(join(proj, 'certs'))
    symlinkSync(join(OUTSIDE, 'key.pem'), join(proj, 'certs', 'key.pem'))
    symlinkSync(join(OUTSIDE, 'vault'), join(proj, 'certs', 'vault.pem'))

    const unfollowedLinks = new Map<string, string>()
    const { result: mounts, listed } = listedDuring(() =>
      expandReadDenyGlobLinux(join(proj, 'certs', '*.pem'), [], undefined, {
        unfollowedLinks,
      }),
    )

    // A file and a directory, each denied where the link leads.
    expect(mounts).toEqual([join(OUTSIDE, 'key.pem'), join(OUTSIDE, 'vault')])
    expect(listed).toEqual([join(proj, 'certs')])
    // The pattern has nothing to match beneath `*.pem`, so there was nothing
    // to follow and nothing is reported as left.
    expect([...unfollowedLinks]).toEqual([])

    // The same with a pattern that carries on beneath the link: the target
    // is denied as a whole and not listed.
    const beneath = listedDuring(() =>
      expandReadDenyGlobLinux(join(proj, 'certs', '**/*'), [], undefined, {
        unfollowedLinks,
      }),
    )
    expect(beneath.result).toEqual([
      join(OUTSIDE, 'key.pem'),
      join(OUTSIDE, 'vault'),
    ])
    expect(beneath.listed).toEqual([join(proj, 'certs')])
    expect([...unfollowedLinks]).toEqual([
      [join(proj, 'certs', 'vault.pem'), join(OUTSIDE, 'vault')],
    ])
  })

  it('denies the target of a directory-form link out of the tree as a whole, without listing it', () => {
    const proj = project('p-form')
    const outsideBuild = join(OUTSIDE, 'artifacts', 'build')
    mkdirSync(join(outsideBuild, 'nested'), { recursive: true })
    writeFileSync(join(outsideBuild, '1.out'), '')
    writeFileSync(join(outsideBuild, 'nested', '2.out'), '')
    mkdirSync(join(proj, 'pkg', 'build'), { recursive: true })
    writeFileSync(join(proj, 'pkg', 'build', '0.out'), '')
    mkdirSync(join(proj, 'linked'))
    symlinkSync(outsideBuild, join(proj, 'linked', 'build'))

    const unfollowedLinks = new Map<string, string>()
    const { result: mounts, listed } = listedDuring(() =>
      expandReadDenyGlobLinux(join(proj, '**/build/**'), [], undefined, {
        unfollowedLinks,
      }),
    )

    expect(mounts).toEqual([outsideBuild, join(proj, 'pkg', 'build')])
    expect(listed.filter(dir => dir.startsWith(OUTSIDE))).toEqual([])
    expect([...unfollowedLinks]).toEqual([
      [join(proj, 'linked', 'build'), outsideBuild],
    ])
  })

  it('does not list what a link that only passes through leads to, whatever is allowed beneath it', () => {
    // bigtree is no match of `**/.env`: nothing out there is denied, so an
    // allowed path out there has no mount to be bound back over, and nothing
    // beneath it to mask again.
    const proj = project('p-pass')
    symlinkSync(OUTSIDE, join(proj, 'bigtree'))
    const pattern = join(proj, '**/.env')

    for (const allowed of [
      [OUTSIDE],
      [join(OUTSIDE, 'deep')],
      // Written through the link.
      [join(proj, 'bigtree', 'deep')],
      [join(OUTSIDE, 'deep'), OUTSIDE, ROOT],
    ]) {
      const unlistable = new Set<string>()
      const unfollowedLinks = new Map<string, string>()
      const { result: mounts, listed } = listedDuring(() =>
        expandReadDenyGlobLinux(pattern, allowed, unlistable, {
          unfollowedLinks,
        }),
      )

      expect(mounts).toEqual([join(proj, '.env'), join(proj, 'src', '.env')])
      expect(listed.sort()).toEqual(
        [proj, join(proj, 'src'), join(proj, 'sub')].sort(),
      )
      expect([...unfollowedLinks]).toEqual([[join(proj, 'bigtree'), OUTSIDE]])
      expect([...unlistable]).toEqual([])
    }
  })

  /**
   * `<name>/proj` beside `<name>/store`, with `proj/pkg/build -> store/build`
   * and `proj/certs/vault.pem -> store/vault`. Each target holds `public`,
   * the allowed path, and `private`, with files in both that the patterns
   * here match. `store/build-cache` lies beside the targets, under a name
   * that begins with one of theirs.
   */
  function plantStore(name: string): { top: string; proj: string } {
    const top = join(ROOT, name)
    const proj = join(top, 'proj')
    for (const dir of ['build', 'vault']) {
      mkdirSync(join(top, 'store', dir, 'public', 'deep'), { recursive: true })
      mkdirSync(join(top, 'store', dir, 'private'))
      writeFileSync(join(top, 'store', dir, 'public', 'id.pem'), 'KEY')
      writeFileSync(join(top, 'store', dir, 'public', 'note.txt'), 'NOTE')
      writeFileSync(
        join(top, 'store', dir, 'public', 'deep', 'more.pem'),
        'KEY',
      )
      writeFileSync(join(top, 'store', dir, 'private', 'id.pem'), 'KEY')
    }
    mkdirSync(join(top, 'store', 'build-cache', 'public'), { recursive: true })
    mkdirSync(join(proj, 'pkg'), { recursive: true })
    mkdirSync(join(proj, 'certs'))
    symlinkSync(join(top, 'store', 'build'), join(proj, 'pkg', 'build'))
    symlinkSync(join(top, 'store', 'vault'), join(proj, 'certs', 'vault.pem'))
    return { top, proj }
  }

  /** A link of plantStore that matches in the directory form, and one that
   *  matches by its own name: the pattern, the link and where it leads. */
  function matchedLinksOf(
    top: string,
    proj: string,
  ): (readonly [string, string, string])[] {
    return [
      [
        join(proj, '**/build/**'),
        join(proj, 'pkg', 'build'),
        join(top, 'store', 'build'),
      ],
      [
        join(proj, 'certs', '**/*.pem'),
        join(proj, 'certs', 'vault.pem'),
        join(top, 'store', 'vault'),
      ],
    ]
  }

  it('does not list what a matched link out of the tree leads to when nothing allowed lies beneath it', () => {
    // The target is denied as a whole, and what is in it is not looked at.
    // Nothing is handed back as unlistable, which is for a directory whose
    // listing failed: an allowed path beneath the target's mount comes back.
    const { top, proj } = plantStore('p-whole')
    const store = join(top, 'store')

    for (const [pattern, link, target] of matchedLinksOf(top, proj)) {
      for (const allowed of [
        [],
        // Above the target, beside it, and in the tree.
        [store],
        [join(store, 'build-cache', 'public'), join(store, 'vault-cache')],
        [proj, top],
      ]) {
        const unlistable = new Set<string>()
        const unfollowedLinks = new Map<string, string>()
        const { result: mounts, listed } = listedDuring(() =>
          expandReadDenyGlobLinux(pattern, allowed, unlistable, {
            unfollowedLinks,
          }),
        )

        expect(mounts).toEqual([target])
        expect(listed.filter(dir => dir.startsWith(store))).toEqual([])
        expect(unfollowedLinks.get(link)).toBe(target)
        expect([...unlistable]).toEqual([])
      }
    }
  })

  it('does not list what a matched link out of the tree leads to when an allowed path lies beneath it', () => {
    // The allowed path comes back over the target's mount as it is written,
    // as it does beneath a directory denied literally. What the pattern
    // matches under it through the link's name was not looked for, and has
    // no mount of its own: id.pem beneath `public` is what a pattern gives
    // up by starting beside the directory and not above it.
    const { top, proj } = plantStore('p-allowed')
    const store = join(top, 'store')

    for (const [pattern, link, target] of matchedLinksOf(top, proj)) {
      for (const allowed of [
        [join(target, 'public')],
        // Written through the link.
        [join(link, 'public')],
        [join(target, 'public', 'deep'), join(target, 'private')],
        // The target itself.
        [target],
        [link],
      ]) {
        const unlistable = new Set<string>()
        const unfollowedLinks = new Map<string, string>()
        const { result: mounts, listed } = listedDuring(() =>
          expandReadDenyGlobLinux(pattern, allowed, unlistable, {
            unfollowedLinks,
          }),
        )

        expect(mounts).toEqual([target])
        expect(listed.filter(dir => dir.startsWith(store))).toEqual([])
        expect(unfollowedLinks.get(link)).toBe(target)
        expect([...unlistable]).toEqual([])
      }
    }

    // Started above both ends of the link, the target is in the tree and is
    // listed: every entry beneath the allowed path is a match and keeps a
    // mount of its own, the ones in `deep` under that of `deep`.
    const build = join(store, 'build')
    const unfollowedLinks = new Map<string, string>()
    expect(
      expandReadDenyGlobLinux(
        join(top, '**/build/**'),
        [join(build, 'public')],
        undefined,
        { unfollowedLinks },
      ),
    ).toEqual([
      build,
      join(build, 'public'),
      join(build, 'public', 'deep'),
      join(build, 'public', 'id.pem'),
      join(build, 'public', 'note.txt'),
    ])
    expect([...unfollowedLinks]).toEqual([])
  })

  it('keeps a link a match wherever it leads, and reports the ones that leave the tree', () => {
    const { top, proj } = plantStore('p-forms')
    const build = join(top, 'store', 'build')
    // Beside the link out of the tree, one that matches and stays in the
    // tree, and one that matches and leads back up it.
    const real = join(proj, 'pkg', 'real', 'build')
    mkdirSync(real, { recursive: true })
    writeFileSync(join(real, '0.out'), '')
    mkdirSync(join(proj, 'in'))
    mkdirSync(join(proj, 'up'))
    symlinkSync(real, join(proj, 'in', 'build'))
    symlinkSync(top, join(proj, 'up', 'build'))

    const { result: walk, listed } = listedDuring(() =>
      walkGlobPattern(join(proj, '**/build/**'), {
        withDirectoryForm: true,
        followSymlinkedDirectories: true,
      }),
    )

    // Each is a match in the directory form, which denies what it leads to.
    for (const [link, target] of [
      [join(proj, 'in', 'build'), real],
      [join(proj, 'up', 'build'), top],
      [join(proj, 'pkg', 'build'), build],
    ] as const) {
      expect(walk.directoryMatches).toContain(link)
      expect(walk.realOf.get(link)).toBe(target)
    }
    // Nothing is listed but the tree, and nothing found but what is in it.
    expect(listed.filter(dir => !dir.startsWith(proj))).toEqual([])
    expect(walk.matches).toEqual([join(real, '0.out')])
    // The links that leave, matched or not: not the one that leads back up.
    expect([...walk.unfollowedLinks].sort()).toEqual([
      [join(proj, 'certs', 'vault.pem'), join(top, 'store', 'vault')],
      [join(proj, 'pkg', 'build'), build],
    ])
  })

  /** What an expansion returns and reports, with the directories it listed
   *  at or beneath `outside`. */
  function expandedBeside(
    outside: string,
    pattern: string,
    allowed: string[],
  ): {
    mounts: string[]
    listed: string[]
    unlistable: string[]
    unfollowedLinks: [string, string][]
  } {
    const unlistable = new Set<string>()
    const unfollowedLinks = new Map<string, string>()
    const { result: mounts, listed } = listedDuring(() =>
      expandReadDenyGlobLinux(pattern, allowed, unlistable, {
        unfollowedLinks,
      }),
    )
    return {
      mounts,
      listed: listed.filter(dir => dir.startsWith(outside)).sort(),
      unlistable: [...unlistable],
      unfollowedLinks: [...unfollowedLinks].sort(),
    }
  }

  it('never comes to a link inside what a matched link out of the tree leads to', () => {
    // keys/d.pem -> out/d is a match of `**/keys/*.pem` by its own name:
    // out/d is denied as a whole and not listed, so pub/keys -> stuff in
    // there is never come to. Neither is x/keys -> out/d/pub/stuff listed
    // through, which leads from the tree into what d.pem denies. x.pem,
    // which the pattern matches as pub/keys/x.pem and as x/keys/x.pem alone,
    // has no mount, whether or not `pub` is allowed.
    const top = join(ROOT, 'p-inner')
    const proj = join(top, 'proj')
    const d = join(top, 'out', 'd')
    mkdirSync(join(d, 'keys'), { recursive: true })
    mkdirSync(join(d, 'pub', 'stuff'), { recursive: true })
    writeFileSync(join(d, 'keys', 'a.pem'), 'KEY')
    writeFileSync(join(d, 'pub', 'stuff', 'x.pem'), 'KEY')
    symlinkSync('stuff', join(d, 'pub', 'keys'))
    mkdirSync(join(proj, 'keys'), { recursive: true })
    mkdirSync(join(proj, 'x'))
    symlinkSync(d, join(proj, 'keys', 'd.pem'))
    symlinkSync(join(d, 'pub', 'stuff'), join(proj, 'x', 'keys'))

    for (const allowed of [[], [join(d, 'pub')], [d]]) {
      expect(
        expandedBeside(join(top, 'out'), join(proj, '**/keys/*.pem'), allowed),
      ).toEqual({
        mounts: [d],
        listed: [],
        unlistable: [],
        unfollowedLinks: [
          [join(proj, 'keys', 'd.pem'), d],
          [join(proj, 'x', 'keys'), join(d, 'pub', 'stuff')],
        ],
      })
    }

    // Neither to one in there that is a match itself and leads on: build ->
    // o1 denies o1, and o2, which o1/pub/build leads to, is not denied.
    const chain = join(ROOT, 'p-chain')
    const o1 = join(chain, 'o1')
    const o2 = join(chain, 'o2')
    const o3 = join(chain, 'o3')
    for (const [dir, file] of [
      [o1, 'a.txt'],
      [o2, 'b.txt'],
      [o3, 'c.txt'],
    ] as const) {
      mkdirSync(join(dir, 'pub'), { recursive: true })
      writeFileSync(join(dir, 'pub', file), '')
    }
    mkdirSync(join(chain, 'proj'))
    symlinkSync(o1, join(chain, 'proj', 'build'))
    symlinkSync(o2, join(o1, 'pub', 'build'))
    symlinkSync(o3, join(o2, 'pub', 'build'))

    for (const allowed of [
      [],
      [join(o1, 'pub')],
      [join(o1, 'pub'), join(o2, 'pub')],
    ]) {
      expect(
        expandedBeside(chain, join(chain, 'proj', '**/build/**'), allowed),
      ).toEqual({
        mounts: [o1],
        listed: [join(chain, 'proj')],
        unlistable: [],
        unfollowedLinks: [[join(chain, 'proj', 'build'), o1]],
      })
    }
    // A pattern that starts above them all follows each link in turn.
    expect(expandReadDenyGlobLinux(join(chain, '**/build/**'), [])).toEqual([
      o1,
      o2,
      o3,
    ])
  })

  it('hands back nothing for a link that only passes through, or that the pattern ends at', () => {
    const { top, proj } = plantStore('p-through')
    const vault = join(top, 'store', 'vault')
    writeFileSync(join(proj, 'id.pem'), 'KEY')

    // Neither link is a match: nothing out there is denied, so there is
    // nothing for an allowed path to be bound back over.
    const passedThrough = new Set<string>()
    const unfollowedLinks = new Map<string, string>()
    expect(
      expandReadDenyGlobLinux(
        join(proj, '**/id.pem'),
        [join(vault, 'public')],
        passedThrough,
        { unfollowedLinks },
      ),
    ).toEqual([join(proj, 'id.pem')])
    expect([...unfollowedLinks.keys()].sort()).toEqual([
      join(proj, 'certs', 'vault.pem'),
      join(proj, 'pkg', 'build'),
    ])
    expect([...passedThrough]).toEqual([])

    // The link is a match and the pattern has nothing to match beneath it:
    // no listing is called for, whatever is allowed in there, so nothing is
    // missing from the deny, and the allowed path comes back as under a
    // literal deny of the link.
    const endedAt = new Set<string>()
    const { result: mounts, listed } = listedDuring(() =>
      expandReadDenyGlobLinux(
        join(proj, 'certs', '*.pem'),
        [join(vault, 'public')],
        endedAt,
      ),
    )
    expect(mounts).toEqual([vault])
    expect(listed).toEqual([join(proj, 'certs')])
    expect([...endedAt]).toEqual([])
  })

  it('hands back nothing for a link that passes through to beneath what another link denies', () => {
    // a/x.pem -> out is a match the pattern ends at: out is denied as a
    // whole, as a literal deny of the link would deny it, with nothing to
    // list there. b -> out/sub only passes through. It is no match, so it
    // reports nothing, although a mount hides where it leads: the allowed
    // path out/sub is bound back, and k.pem beneath it, which only a
    // listing through b would have found, gets no mount of its own.
    const top = join(ROOT, 'p-beneath')
    const proj = join(top, 'proj')
    const out = join(top, 'out')
    mkdirSync(join(out, 'sub'), { recursive: true })
    writeFileSync(join(out, 'sub', 'k.pem'), 'KEY')
    mkdirSync(join(proj, 'a'), { recursive: true })
    symlinkSync(out, join(proj, 'a', 'x.pem'))
    symlinkSync(join(out, 'sub'), join(proj, 'b'))

    const unlistable = new Set<string>()
    const unfollowedLinks = new Map<string, string>()
    const { result: mounts, listed } = listedDuring(() =>
      expandReadDenyGlobLinux(
        join(proj, '*/*.pem'),
        [join(out, 'sub')],
        unlistable,
        { unfollowedLinks },
      ),
    )
    expect(mounts).toEqual([out])
    expect(listed.filter(dir => dir.startsWith(out))).toEqual([])
    expect([...unfollowedLinks]).toEqual([[join(proj, 'b'), join(out, 'sub')]])
    expect([...unlistable]).toEqual([])
  })

  it('hands back nothing for the mount that hides what a matched link out of the tree leads to', () => {
    // up/build -> top leads back up, and denies top as a whole. a/build ->
    // top/store leaves the tree beside it: store is denied too, under top's
    // mount, and is not listed. top is not handed back for it, wherever the
    // allowed path lies: that would keep a path beneath top from coming
    // back.
    const top = join(ROOT, 'p-hidden')
    const proj = join(top, 'proj')
    for (const dir of ['store', 'other']) {
      mkdirSync(join(top, dir, 'public'), { recursive: true })
      writeFileSync(join(top, dir, 'public', 'ok.txt'), 'PUBLIC')
    }
    mkdirSync(join(proj, 'up'), { recursive: true })
    mkdirSync(join(proj, 'a'))
    symlinkSync(top, join(proj, 'up', 'build'))
    symlinkSync(join(top, 'store'), join(proj, 'a', 'build'))

    for (const allowed of [
      join(top, 'other', 'public'),
      join(top, 'store', 'public'),
    ]) {
      const unlistable = new Set<string>()
      const unfollowedLinks = new Map<string, string>()
      const { result: mounts, listed } = listedDuring(() =>
        expandReadDenyGlobLinux(
          join(proj, '**/build/**'),
          [allowed],
          unlistable,
          { unfollowedLinks },
        ),
      )

      expect(mounts).toEqual([top])
      expect(listed.filter(dir => !dir.startsWith(proj))).toEqual([])
      expect([...unlistable]).toEqual([])
      expect([...unfollowedLinks]).toEqual([
        [join(proj, 'a', 'build'), join(top, 'store')],
      ])
    }
  })

  it('does not find a file in the tree by a name that leaves the tree and comes back', () => {
    // leave -> ../out/hop is not listed through, so back -> ../../proj/deep
    // out there is never met. `*/*/.env` matches deep/.env as
    // leave/back/.env and by no other name: the file is inside the tree,
    // and is not denied.
    const top = join(ROOT, 'p-return')
    const proj = join(top, 'proj')
    const hop = join(top, 'out', 'hop')
    mkdirSync(join(proj, 'deep'), { recursive: true })
    mkdirSync(hop, { recursive: true })
    writeFileSync(join(proj, 'deep', '.env'), 'A=1')
    symlinkSync(join('..', 'out', 'hop'), join(proj, 'leave'))
    symlinkSync(join('..', '..', 'proj', 'deep'), join(hop, 'back'))

    const unfollowedLinks = new Map<string, string>()
    const { result: mounts, listed } = listedDuring(() =>
      expandReadDenyGlobLinux(join(proj, '*/*/.env'), [], undefined, {
        unfollowedLinks,
      }),
    )

    expect(mounts).toEqual([])
    expect(listed.filter(dir => dir.startsWith(join(top, 'out')))).toEqual([])
    expect([...unfollowedLinks]).toEqual([[join(proj, 'leave'), hop]])
    // A pattern that matches the file by a name inside the tree denies it.
    expect(expandReadDenyGlobLinux(join(proj, '*/.env'), [])).toEqual([
      join(proj, 'deep', '.env'),
    ])

    // The same where the link out there has the name the pattern asks for:
    // src/vendor -> ../vendor and vendor/secrets -> ../src/data, so
    // `**/secrets/*.pem` matches data/key.pem as vendor/secrets/key.pem.
    const src = join(ROOT, 'p-named', 'src')
    const vendor = join(ROOT, 'p-named', 'vendor')
    mkdirSync(join(src, 'data'), { recursive: true })
    mkdirSync(vendor)
    writeFileSync(join(src, 'data', 'key.pem'), 'KEY')
    symlinkSync(join('..', 'vendor'), join(src, 'vendor'))
    symlinkSync(join('..', 'src', 'data'), join(vendor, 'secrets'))

    expect(expandReadDenyGlobLinux(join(src, '**/secrets/*.pem'), [])).toEqual(
      [],
    )
    expect(expandReadDenyGlobLinux(join(src, '**/*.pem'), [])).toEqual([
      join(src, 'data', 'key.pem'),
    ])
  })

  it('costs no listing of a large tree a link leads out to', () => {
    const proj = project('p-cost')
    const big = join(ROOT, 'big')
    for (let d = 0; d < 30; d++) {
      mkdirSync(join(big, `d${d}`), { recursive: true })
      for (let f = 0; f < 100; f++) {
        writeFileSync(join(big, `d${d}`, f === 0 ? '.env' : `f${f}`), '')
      }
    }
    const pattern = join(proj, '**/.env')
    const without = listedDuring(() =>
      walkGlobPattern(pattern, { followSymlinkedDirectories: true }),
    )

    symlinkSync(big, join(proj, 'bigtree'))
    const withLink = listedDuring(() =>
      walkGlobPattern(pattern, { followSymlinkedDirectories: true }),
    )

    // The same listings, and one entry more to look at: the link itself.
    expect(withLink.listed.sort()).toEqual(without.listed.sort())
    expect(withLink.listed).toHaveLength(3)
    expect(withLink.result.directoriesListed).toBe(3)
    expect(withLink.result.entriesExamined).toBe(
      without.result.entriesExamined + 1,
    )
    expect(withLink.result.matches).toEqual(without.result.matches)
    expect([...withLink.result.unfollowedLinks]).toEqual([
      [join(proj, 'bigtree'), big],
    ])
    // The expansion lists no more than the walk, whatever is allowed out
    // there.
    for (const allowed of [[], [join(big, 'd0')], [big]]) {
      const expanded = listedDuring(() =>
        expandReadDenyGlobLinux(pattern, allowed),
      )
      expect(expanded.listed.sort()).toEqual(without.listed.sort())
    }
    // The tree is there to be found by a pattern that names it.
    expect(expandGlobPattern(join(big, '**/.env'))).toHaveLength(30)
  })

  it('hands a link back under each spelling the pattern came to it by', () => {
    // twice -> p-twice, and the pattern is spelled through it. src is
    // listed as twice/src, and again by its real path for d/l -> ../src,
    // one component further on in the pattern: src/o, which leaves the
    // tree, is met under both names.
    const proj = join(ROOT, 'p-twice')
    const spelled = join(ROOT, 'twice')
    mkdirSync(join(proj, 'src'), { recursive: true })
    mkdirSync(join(proj, 'd'))
    symlinkSync(proj, spelled)
    symlinkSync(OUTSIDE, join(proj, 'src', 'o'))
    symlinkSync(join('..', 'src'), join(proj, 'd', 'l'))

    const unfollowedLinks = new Map<string, string>()
    expandReadDenyGlobLinux(join(spelled, '*/*/*/x'), [], undefined, {
      unfollowedLinks,
    })
    expect([...unfollowedLinks]).toEqual([
      [join(proj, 'src', 'o'), OUTSIDE],
      [join(spelled, 'src', 'o'), OUTSIDE],
    ])

    // Spelled by its real path, the pattern comes to it by one name.
    unfollowedLinks.clear()
    expandReadDenyGlobLinux(join(proj, '*/*/*/x'), [], undefined, {
      unfollowedLinks,
    })
    expect([...unfollowedLinks]).toEqual([[join(proj, 'src', 'o'), OUTSIDE]])
  })

  it('still leaves a link alone without the link option', () => {
    // What the allowRead expansion and the Windows ACL stamp get: the link
    // as a match of its own, nothing resolved and nothing reported.
    const proj = project('p-plain')
    symlinkSync(OUTSIDE, join(proj, 'out'))

    const walk = walkGlobPattern(join(proj, '*'))

    expect(walk.matches).toContain(join(proj, 'out'))
    expect(walk.realOf.get(join(proj, 'out'))).toBeUndefined()
    expect([...walk.unfollowedLinks]).toEqual([])
  })
})

describe.if(!isWindows)('the budget of a glob walk', () => {
  let ROOT: string
  /** Twelve directories of four files, one of them a match: 60 entries. */
  let TREE: string
  let TREE_ENTRIES: number

  function plantTree(name: string): string {
    const tree = join(ROOT, name)
    for (let d = 0; d < 12; d++) {
      mkdirSync(join(tree, `d${d}`), { recursive: true })
      for (const f of ['.env', 'a', 'b', 'c']) {
        writeFileSync(join(tree, `d${d}`, f), '')
      }
    }
    return tree
  }

  beforeAll(() => {
    ROOT = realpathSync(mkdtempSync(join(tmpdir(), 'deny-glob-budget-')))
    TREE = plantTree('tree')
    TREE_ENTRIES = walkGlobPattern(join(TREE, '**/.env')).entriesExamined
  })

  afterAll(() => {
    rmSync(ROOT, { recursive: true, force: true })
  })

  it('defaults to two million entries and ten seconds', () => {
    expect(GLOB_WALK_MAX_ENTRIES).toBe(2_000_000)
    expect(GLOB_WALK_TIMEOUT_MS).toBe(10_000)
    const budget = newGlobWalkBudget()
    expect(budget.maxEntries).toBe(2_000_000)
    // Rounded: the deadline is a clock reading plus ten seconds, and a
    // floating-point sum less the reading need not be ten seconds exactly.
    expect(Math.round(budget.deadline - budget.startedAt)).toBe(10_000)
    expect(budget.entries).toBe(0)
  })

  it('counts every entry it looks at, with or without a budget', () => {
    expect(TREE_ENTRIES).toBe(12 + 12 * 4)
    const budget = newGlobWalkBudget()
    const walk = walkGlobPattern(join(TREE, '**/.env'), { budget })
    expect(walk.entriesExamined).toBe(TREE_ENTRIES)
    expect(walk.directoriesListed).toBe(13)
    expect(budget.entries).toBe(TREE_ENTRIES)
  })

  it('throws when the tree holds more entries than the budget, and hands nothing back', () => {
    const pattern = join(TREE, '**/.env')
    // Exactly enough is enough.
    expect(
      expandReadDenyGlobLinux(pattern, [], undefined, {
        budget: newGlobWalkBudget({ maxEntries: TREE_ENTRIES }),
      }),
    ).toHaveLength(12)

    const budget = newGlobWalkBudget({ maxEntries: TREE_ENTRIES - 1 })
    let mounts: string[] | undefined
    const error = thrownBy(() => {
      mounts = expandReadDenyGlobLinux(pattern, [], undefined, { budget })
    })

    expect(mounts).toBeUndefined()
    expect(error).toBeInstanceOf(GlobWalkBudgetError)
    const budgetError = error as GlobWalkBudgetError
    expect(budgetError.exhausted).toBe('entries')
    expect(budgetError.pattern).toBe(pattern)
    // The directory it was in when the count ran out, which is one of the
    // tree's own.
    expect(budgetError.directory.startsWith(TREE + '/')).toBe(true)
    expect(budgetError.entries).toBe(TREE_ENTRIES)
    expect(budgetError.maxEntries).toBe(TREE_ENTRIES - 1)
    expect(budgetError.elapsedMs).toBeGreaterThanOrEqual(0)
    expect(budgetError.message).toContain(pattern)
    expect(budgetError.message).toContain(budgetError.directory)
    // The walk itself throws the same, whoever calls it.
    expect(() =>
      walkGlobPattern(pattern, {
        budget: newGlobWalkBudget({ maxEntries: 5 }),
      }),
    ).toThrow(GlobWalkBudgetError)
  })

  it('throws when the deadline has passed before it starts', () => {
    const pattern = join(TREE, '**/.env')
    let mounts: string[] | undefined
    const error = thrownBy(() => {
      mounts = expandReadDenyGlobLinux(pattern, [], undefined, {
        budget: newGlobWalkBudget({ timeoutMs: 0 }),
      })
    })

    expect(mounts).toBeUndefined()
    expect(error).toBeInstanceOf(GlobWalkBudgetError)
    const budgetError = error as GlobWalkBudgetError
    expect(budgetError.exhausted).toBe('time')
    expect(budgetError.pattern).toBe(pattern)
    expect(budgetError.directory).toBe(TREE)
    expect(budgetError.entries).toBe(0)
    expect(budgetError.timeoutMs).toBe(0)
  })

  it('throws when the deadline passes while it walks', () => {
    // A clock that moves a second each time it is read, and the walk reads
    // it before each listing and at each entry. The budget is made at 1 s;
    // the tree and its twelve entries take the readings up to 14 s, and each
    // of the first two directories beneath it five more, up to 24 s. The
    // next reading, before the third is listed, is past the deadline.
    let now = 0
    const clock = spyOn(performance, 'now').mockImplementation(
      () => (now += 1000),
    )
    try {
      const pattern = join(TREE, '**/.env')
      const budget = newGlobWalkBudget({ timeoutMs: 23_500 })
      const error = thrownBy(() => walkGlobPattern(pattern, { budget }))

      expect(error).toBeInstanceOf(GlobWalkBudgetError)
      const budgetError = error as GlobWalkBudgetError
      expect(budgetError.exhausted).toBe('time')
      expect(budgetError.directory.startsWith(TREE + '/')).toBe(true)
      expect(budgetError.entries).toBe(12 + 2 * 4)
    } finally {
      clock.mockRestore()
    }
  })

  it('throws inside a directory of few entries, at the entry the deadline passes on', () => {
    // The clock is read at every entry, not every so many: a name can be
    // slow to match, and a directory of forty such names must not be walked
    // to its end long after the time is up. One reading a second again: the
    // budget is made at 1 s, the listing is at 2 s, and the fourth entry, at
    // 6 s, is past the deadline.
    const few = join(ROOT, 'few')
    mkdirSync(few)
    for (let f = 0; f < 40; f++) writeFileSync(join(few, `f${f}`), '')
    let now = 0
    const clock = spyOn(performance, 'now').mockImplementation(
      () => (now += 1000),
    )
    try {
      const budget = newGlobWalkBudget({ timeoutMs: 4500 })
      const error = thrownBy(() =>
        walkGlobPattern(join(few, '*.env'), { budget }),
      )

      expect(error).toBeInstanceOf(GlobWalkBudgetError)
      const budgetError = error as GlobWalkBudgetError
      expect(budgetError.exhausted).toBe('time')
      expect(budgetError.directory).toBe(few)
      expect(budgetError.entries).toBe(4)
    } finally {
      clock.mockRestore()
    }
  })

  it('is spent by every expansion it is handed to', () => {
    const second = plantTree('second')
    const budget = newGlobWalkBudget({ maxEntries: TREE_ENTRIES + 10 })

    expect(
      expandReadDenyGlobLinux(join(TREE, '**/.env'), [], undefined, {
        budget,
      }),
    ).toHaveLength(12)
    expect(budget.entries).toBe(TREE_ENTRIES)

    // The second tree fits a budget of its own, and does not fit what the
    // first expansion left of this one.
    expect(
      expandReadDenyGlobLinux(join(second, '**/.env'), [], undefined, {
        budget: newGlobWalkBudget({ maxEntries: TREE_ENTRIES + 10 }),
      }),
    ).toHaveLength(12)
    const error = thrownBy(() =>
      expandReadDenyGlobLinux(join(second, '**/.env'), [], undefined, {
        budget,
      }),
    )
    expect(error).toBeInstanceOf(GlobWalkBudgetError)
    expect((error as GlobWalkBudgetError).pattern).toBe(join(second, '**/.env'))
    expect((error as GlobWalkBudgetError).entries).toBe(TREE_ENTRIES + 11)
  })

  it('throws on a tree that only links inside it lead through', () => {
    // start/next -> ../pool/d1, d1/next -> ../d2, …, all beneath the
    // directory the pattern starts from, so every link is followed: a tree a
    // command allowed to write there can make as long as it likes. `start*`
    // names start alone, so nothing but the links leads into pool.
    const chain = join(ROOT, 'chain')
    const links = 40
    plantChain(chain, links)
    const pattern = join(chain, 'start*', '**/.env')
    const whole = walkGlobPattern(pattern, {
      followSymlinkedDirectories: true,
    })
    expect(whole.matches).toHaveLength(links)
    expect([...whole.unfollowedLinks]).toEqual([])
    // chain holds start and pool; every other entry was met through a link.
    expect(whole.entriesExamined).toBe(2 + 2 * links)

    let mounts: string[] | undefined
    const error = thrownBy(() => {
      mounts = expandReadDenyGlobLinux(pattern, [], undefined, {
        budget: newGlobWalkBudget({ maxEntries: whole.entriesExamined - 1 }),
      })
    })

    expect(mounts).toBeUndefined()
    expect(error).toBeInstanceOf(GlobWalkBudgetError)
    expect((error as GlobWalkBudgetError).directory).toBe(
      join(chain, 'pool', `d${links}`),
    )
  })

  it('is not spent on what a link out of the tree leads to, matched or not', () => {
    // linked/build -> tree: the link is the one entry of the pattern's own
    // tree, and what it leads to holds sixty. A budget of one entry is
    // enough, whatever is allowed out there.
    const proj = join(ROOT, 'linked')
    mkdirSync(proj)
    symlinkSync(TREE, join(proj, 'build'))

    for (const allowed of [[], [join(TREE, 'd0')], [TREE]]) {
      // The link is a match: what it leads to is denied as a whole.
      const matched = newGlobWalkBudget({ maxEntries: 1 })
      expect(
        expandReadDenyGlobLinux(join(proj, '**/build/**'), allowed, undefined, {
          budget: matched,
        }),
      ).toEqual([TREE])
      expect(matched.entries).toBe(1)

      // The link only passes through: nothing out there is denied.
      const passedThrough = newGlobWalkBudget({ maxEntries: 1 })
      expect(
        expandReadDenyGlobLinux(join(proj, '**/.env'), allowed, undefined, {
          budget: passedThrough,
        }),
      ).toEqual([])
      expect(passedThrough.entries).toBe(1)
    }
  })

  it('does not take a spent budget for a directory that could not be listed', () => {
    // An error from the listing itself marks the directory to be denied as
    // a whole; the budget's error is not one of those, whether the entries
    // ran out or the time did. The time is looked at right before each
    // listing: taken for a listing that failed, it would deny the tree as a
    // whole and hand that back.
    for (const limits of [{ maxEntries: 20 }, { timeoutMs: 0 }]) {
      const unlistable = new Set<string>()
      let mounts: string[] | undefined
      const error = thrownBy(() => {
        mounts = expandReadDenyGlobLinux(
          join(TREE, '**/.env'),
          [],
          unlistable,
          { budget: newGlobWalkBudget(limits) },
        )
      })

      expect(error).toBeInstanceOf(GlobWalkBudgetError)
      expect(mounts).toBeUndefined()
      expect([...unlistable]).toEqual([])
    }
  })
})

describe.if(isLinux)('a read-deny glob past its budget, at the manager', () => {
  let ROOT: string
  let PROJ: string
  let OTHER: string
  const newBudget = sandboxUtils.newGlobWalkBudget

  /** Has the manager make its budgets with these limits instead. */
  function withBudgetOf<T>(
    limits: { maxEntries?: number; timeoutMs?: number },
    fn: (made: () => number) => Promise<T>,
  ): Promise<T> {
    const spy = spyOn(sandboxUtils, 'newGlobWalkBudget').mockImplementation(
      () => newBudget(limits),
    )
    return fn(() => spy.mock.calls.length).finally(() => spy.mockRestore())
  }

  function plantProject(name: string): string {
    const proj = join(ROOT, name)
    for (let d = 0; d < 10; d++) {
      mkdirSync(join(proj, `pkg${d}`), { recursive: true })
      for (const f of ['.env', 'index.js', 'readme.md']) {
        writeFileSync(join(proj, `pkg${d}`, f), '')
      }
    }
    return proj
  }

  function filesystemOf(
    denyRead: string[],
    allowed: { allowRead?: string[]; allowWrite?: string[] } = {},
  ) {
    return {
      filesystem: { denyRead, allowWrite: [], denyWrite: [], ...allowed },
    }
  }

  /** The wrapped command, or what the wrap threw: never both. */
  async function wrapOf(
    denyRead: string[],
    allowed: { allowRead?: string[]; allowWrite?: string[] } = {},
  ): Promise<{ wrapped?: string; error?: unknown }> {
    try {
      return {
        wrapped: await SandboxManager.wrapWithSandbox(
          'echo hello',
          undefined,
          filesystemOf(denyRead, allowed),
        ),
      }
    } catch (error) {
      return { error }
    }
  }

  beforeAll(() => {
    ROOT = realpathSync(mkdtempSync(join(tmpdir(), 'deny-glob-manager-')))
    PROJ = plantProject('proj')
    OTHER = plantProject('other')
  })

  afterAll(async () => {
    await SandboxManager.reset()
    rmSync(ROOT, { recursive: true, force: true })
  })

  it('wraps an ordinary project with the default budget', async () => {
    const { wrapped, error } = await wrapOf([join(PROJ, '**/.env')])

    expect(error).toBeUndefined()
    for (let d = 0; d < 10; d++) {
      expect(wrapped).toContain(
        `--ro-bind /dev/null ${join(PROJ, `pkg${d}`, '.env')}`,
      )
    }
  })

  it('refuses the wrap, and returns no command, when the tree is past the budget', async () => {
    const pattern = join(PROJ, '**/.env')
    const { wrapped, error } = await withBudgetOf({ maxEntries: 25 }, () =>
      wrapOf([pattern]),
    )

    expect(wrapped).toBeUndefined()
    expect(error).toBeInstanceOf(LinuxSandboxProfileError)
    const profileError = error as LinuxSandboxProfileError
    expect(profileError.code).toBe('deny_glob_too_large')
    expect(profileError.message).toContain(`"${pattern}"`)
    expect(profileError.message).toContain('25 directory entries')
    expect(profileError.message).toContain('narrow the pattern')
    expect(profileError.cause).toBeInstanceOf(GlobWalkBudgetError)
    const cause = profileError.cause as GlobWalkBudgetError
    expect(cause.exhausted).toBe('entries')
    expect(profileError.message).toContain(cause.directory)
    // What a caller builds its own message from, read off `.cause` as plain
    // fields: it needs neither the class nor the text of the message.
    const fields: Record<string, unknown> = { ...cause }
    expect(fields).toEqual({
      name: 'GlobWalkBudgetError',
      pattern,
      directory: expect.stringMatching(new RegExp(`^${PROJ}(/|$)`)),
      exhausted: 'entries',
      entries: 26,
      elapsedMs: expect.any(Number),
      maxEntries: 25,
      timeoutMs: 10_000,
    })
    // A rejected promise, which is how every caller of the wrap meets it.
    await withBudgetOf({ maxEntries: 25 }, async () => {
      // eslint-disable-next-line @typescript-eslint/await-thenable -- bun:test types .rejects.toThrow() as void; the await is required at runtime
      await expect(
        SandboxManager.wrapWithSandbox(
          'echo hello',
          undefined,
          filesystemOf([pattern]),
        ),
      ).rejects.toThrow(LinuxSandboxProfileError)
    })
  })

  it('refuses the wrap when the time is up', async () => {
    const { wrapped, error } = await withBudgetOf({ timeoutMs: 0 }, () =>
      wrapOf([join(PROJ, '**/.env')]),
    )

    expect(wrapped).toBeUndefined()
    expect(error).toBeInstanceOf(LinuxSandboxProfileError)
    expect((error as LinuxSandboxProfileError).code).toBe('deny_glob_too_large')
    expect((error as LinuxSandboxProfileError).message).toContain(
      'the time ran out',
    )
  })

  it('gives the patterns of one wrap one budget between them', async () => {
    const first = join(PROJ, '**/.env')
    const second = join(OTHER, '**/.env')
    // Each tree is 40 entries: either fits 60, and the two do not.
    await withBudgetOf({ maxEntries: 60 }, async made => {
      expect((await wrapOf([first])).error).toBeUndefined()
      expect((await wrapOf([second])).error).toBeUndefined()
      expect(made()).toBe(2)

      const { wrapped, error } = await wrapOf([first, second])

      expect(made()).toBe(3)
      expect(wrapped).toBeUndefined()
      expect(error).toBeInstanceOf(LinuxSandboxProfileError)
      expect((error as LinuxSandboxProfileError).code).toBe(
        'deny_glob_too_large',
      )
      // The pattern that was being expanded when the budget ran out.
      expect((error as LinuxSandboxProfileError).message).toContain(
        `"${second}"`,
      )
    })
  })

  it('refuses the wrap over a tree that only links inside it lead through', async () => {
    const chain = join(ROOT, 'chain')
    plantChain(chain, 30)
    const pattern = join(chain, 'start*', '**/.env')
    expect((await wrapOf([pattern])).wrapped).toContain(
      `--ro-bind /dev/null ${join(chain, 'pool', 'd30', '.env')}`,
    )

    // chain itself holds two entries: the rest of the twenty go on what the
    // links lead to.
    const { wrapped, error } = await withBudgetOf({ maxEntries: 20 }, () =>
      wrapOf([pattern]),
    )

    expect(wrapped).toBeUndefined()
    expect(error).toBeInstanceOf(LinuxSandboxProfileError)
    expect((error as LinuxSandboxProfileError).code).toBe('deny_glob_too_large')
    expect(
      ((error as LinuxSandboxProfileError).cause as GlobWalkBudgetError)
        .directory,
    ).toStartWith(join(chain, 'pool') + '/')
  })

  it('does not spend the budget on a tree a link leads out to', async () => {
    const proj = join(ROOT, 'linked')
    mkdirSync(join(proj, 'src'), { recursive: true })
    writeFileSync(join(proj, '.env'), '')
    symlinkSync(OTHER, join(proj, 'bigtree'))

    // Three entries in the tree; OTHER holds forty. The link only passes
    // through, so that holds whatever is allowed out there.
    for (const allowed of [
      {},
      { allowRead: [join(OTHER, 'pkg0')] },
      { allowWrite: [OTHER] },
    ]) {
      const { wrapped, error } = await withBudgetOf({ maxEntries: 3 }, () =>
        wrapOf([join(proj, '**/.env')], allowed),
      )

      expect(error).toBeUndefined()
      expect(wrapped).toContain(`--ro-bind /dev/null ${join(proj, '.env')}`)
      expect(wrapped).not.toContain(join(OTHER, 'pkg0', '.env'))
    }
  })

  it('does not spend the budget on what a matched link out of the tree leads to', async () => {
    const proj = join(ROOT, 'matched')
    mkdirSync(proj)
    symlinkSync(OTHER, join(proj, 'build'))
    const pattern = join(proj, '**/build/**')

    // One entry in the tree, the link; OTHER holds forty. It is denied as a
    // whole for the cost of the link, whatever is allowed beneath it, and an
    // allowed path in there comes back with nothing beneath it masked.
    for (const allowed of [
      {},
      { allowRead: [join(OTHER, 'pkg0')] },
      { allowWrite: [join(OTHER, 'pkg0')] },
    ]) {
      const { wrapped, error } = await withBudgetOf({ maxEntries: 1 }, () =>
        wrapOf([pattern], allowed),
      )

      expect(error).toBeUndefined()
      expect(countMounts(wrapped!, '--tmpfs', OTHER)).toBe(1)
      expect(
        countMounts(
          wrapped!,
          '--ro-bind',
          '/dev/null',
          join(OTHER, 'pkg0', '.env'),
        ),
      ).toBe(0)
    }
  })

  it('says in the read configuration which links its patterns left unfollowed', async () => {
    const proj = join(ROOT, 'told')
    mkdirSync(join(proj, 'src'), { recursive: true })
    writeFileSync(join(proj, '.env'), '')
    symlinkSync(OTHER, join(proj, 'bigtree'))
    symlinkSync(join(proj, 'src'), join(proj, 'alias'))
    const recursive = join(proj, '**/.env')
    const shallow = join(proj, '*/.env')
    await SandboxManager.reset()
    await SandboxManager.initialize({
      network: { allowedDomains: [], deniedDomains: [] },
      filesystem: {
        // A literal entry and a pattern with nothing to say are in the list
        // to show they add nothing.
        denyRead: [recursive, join(proj, 'src'), shallow, join(PROJ, '*.key')],
        allowWrite: [],
        denyWrite: [],
      },
    })
    try {
      // Once for each pattern that came to the link and would have carried
      // on beneath it; the link that stays in the tree is followed and is
      // not among them.
      expect(SandboxManager.getFsReadConfig().unfollowedDenyLinks).toEqual([
        { pattern: recursive, link: join(proj, 'bigtree'), target: OTHER },
        { pattern: shallow, link: join(proj, 'bigtree'), target: OTHER },
      ])
    } finally {
      await SandboxManager.reset()
    }

    await SandboxManager.initialize({
      network: { allowedDomains: [], deniedDomains: [] },
      filesystem: {
        denyRead: [join(PROJ, '**/.env')],
        allowWrite: [],
        denyWrite: [],
      },
    })
    try {
      expect(SandboxManager.getFsReadConfig().unfollowedDenyLinks).toEqual([])
    } finally {
      await SandboxManager.reset()
    }
  })

  it('says of a matched link out of the tree that it was left, and not that it could not be listed', async () => {
    const proj = join(ROOT, 'through')
    mkdirSync(proj)
    symlinkSync(OTHER, join(proj, 'build'))
    const pattern = join(proj, '**/build/**')
    const readConfigWith = async (allowRead: string[]) => {
      await SandboxManager.reset()
      await SandboxManager.initialize({
        network: { allowedDomains: [], deniedDomains: [] },
        filesystem: {
          denyRead: [pattern],
          allowRead,
          allowWrite: [],
          denyWrite: [],
        },
      })
      try {
        return SandboxManager.getFsReadConfig()
      } finally {
        await SandboxManager.reset()
      }
    }

    // The same with an allowed path beneath what it leads to and without:
    // OTHER is denied as a whole, and nothing in it has a mount of its own.
    for (const allowRead of [[], [join(OTHER, 'pkg0')]]) {
      expect(await readConfigWith(allowRead)).toEqual({
        denyOnly: [OTHER],
        allowWithinDeny: allowRead,
        unlistableDenyDirs: [],
        unfollowedDenyLinks: [
          { pattern, link: join(proj, 'build'), target: OTHER },
        ],
      })
    }
  })

  it('refuses the read configuration the same way', async () => {
    const pattern = join(PROJ, '**/.env')
    await SandboxManager.reset()
    await SandboxManager.initialize({
      network: { allowedDomains: [], deniedDomains: [] },
      filesystem: { denyRead: [pattern], allowWrite: [], denyWrite: [] },
    })
    try {
      expect(SandboxManager.getFsReadConfig().denyOnly).toHaveLength(10)

      const error = await withBudgetOf({ maxEntries: 25 }, async () =>
        thrownBy(() => SandboxManager.getFsReadConfig()),
      )

      expect(error).toBeInstanceOf(LinuxSandboxProfileError)
      expect((error as LinuxSandboxProfileError).code).toBe(
        'deny_glob_too_large',
      )
      expect((error as LinuxSandboxProfileError).message).toContain(
        `"${pattern}"`,
      )
    } finally {
      await SandboxManager.reset()
    }
  })
})

describe.if(isLinux)(
  'an allowed path beneath what a matched link out of the tree leads to',
  () => {
    // site/proj/build -> site/outside/build, which holds `pub`, the allowed
    // path, and `priv`. A pattern that starts at proj denies outside/build
    // as a whole and does not list it, so the allowed path comes back as it
    // is written, as beneath a directory denied literally: nothing beneath
    // it is masked again.
    let ROOT: string
    let site: string
    let proj: string
    let build: string
    let carveOut: string
    const hasBwrap = bwrapCanNamespace()

    beforeAll(() => {
      ROOT = realpathSync(mkdtempSync(join(tmpdir(), 'deny-glob-allowed-')))
      site = join(ROOT, 'site')
      proj = join(site, 'proj')
      build = join(site, 'outside', 'build')
      carveOut = join(build, 'pub')
      mkdirSync(carveOut, { recursive: true })
      mkdirSync(join(build, 'priv'))
      writeFileSync(join(carveOut, 'ok.txt'), 'PUBLIC\n')
      writeFileSync(join(build, 'priv', 'secret.txt'), 'SECRET\n')
      writeFileSync(join(site, 'outside', 'beside.txt'), 'BESIDE\n')
      mkdirSync(proj)
      symlinkSync(build, join(proj, 'build'))
    })

    afterAll(async () => {
      await SandboxManager.reset()
      rmSync(ROOT, { recursive: true, force: true })
    })

    function wrap(
      command: string,
      filesystem: {
        denyRead: string[]
        allowRead?: string[]
        allowWrite?: string[]
      },
    ): Promise<string> {
      return SandboxManager.wrapWithSandbox(command, undefined, {
        filesystem: { allowWrite: [], denyWrite: [], ...filesystem },
      })
    }

    /** What the commands print in the sandbox, a line each, after BOOTED: a
     *  sandbox that refuses to start prints nothing, which would read as
     *  every file hidden. */
    async function linesOf(
      commands: string[],
      filesystem: Parameters<typeof wrap>[1],
    ): Promise<string[]> {
      const result = spawnSync(
        await wrap(['echo BOOTED', ...commands].join('; '), filesystem),
        { shell: true, encoding: 'utf8', timeout: 15000 },
      )
      expect(result.stderr ?? '').not.toContain('bwrap:')
      return result.stdout.trim().split('\n')
    }

    it('is bound back as it is written, with nothing beneath it masked', async () => {
      const wrapped = await wrap('true', {
        denyRead: [join(proj, '**/build/**')],
        allowRead: [carveOut],
      })

      const hidden = indexOfMount(wrapped, '--tmpfs', build)
      expect(hidden).toBeGreaterThan(-1)
      expect(
        indexOfMount(wrapped, '--ro-bind', carveOut, carveOut),
      ).toBeGreaterThan(hidden)
      expect(
        countMounts(
          wrapped,
          '--ro-bind',
          '/dev/null',
          join(carveOut, 'ok.txt'),
        ),
      ).toBe(0)

      // Started above both ends of the link, the pattern finds ok.txt: the
      // path is bound back, with the file masked beneath it.
      const listed = await wrap('true', {
        denyRead: [join(site, '**/build/**')],
        allowRead: [carveOut],
      })
      const boundBack = indexOfMount(listed, '--ro-bind', carveOut, carveOut)
      expect(boundBack).toBeGreaterThan(-1)
      expect(
        indexOfMount(
          listed,
          '--ro-bind',
          '/dev/null',
          join(carveOut, 'ok.txt'),
        ),
      ).toBeGreaterThan(boundBack)

      // With nothing allowed beneath it, the target's mount is all there is.
      const whole = await wrap('true', {
        denyRead: [join(proj, '**/build/**')],
      })
      expect(countMounts(whole, '--tmpfs', build)).toBe(1)
      expect(whole).not.toContain(carveOut)
    })

    it.skipIf(!hasBwrap)(
      'serves what is in it, and nothing else in there, by either name',
      async () => {
        const reads = [
          `cat ${join(carveOut, 'ok.txt')} 2>/dev/null || echo HIDDEN`,
          `cat ${join(proj, 'build', 'pub', 'ok.txt')} 2>/dev/null || echo HIDDEN`,
          `cat ${join(build, 'priv', 'secret.txt')} 2>/dev/null || echo HIDDEN`,
          `cat ${join(proj, 'build', 'priv', 'secret.txt')} 2>/dev/null || echo HIDDEN`,
          `cat ${join(site, 'outside', 'beside.txt')}`,
        ]

        expect(
          await linesOf(reads, {
            denyRead: [join(proj, '**/build/**')],
            allowRead: [carveOut],
          }),
        ).toEqual(['BOOTED', 'PUBLIC', 'PUBLIC', 'HIDDEN', 'HIDDEN', 'BESIDE'])

        // Nothing allowed beneath it: the target is hidden as a whole.
        expect(
          await linesOf(reads, { denyRead: [join(proj, '**/build/**')] }),
        ).toEqual(['BOOTED', 'HIDDEN', 'HIDDEN', 'HIDDEN', 'HIDDEN', 'BESIDE'])

        // Started above both ends of the link, the pattern masks ok.txt
        // beneath the allowed path, under either name.
        expect(
          await linesOf(reads, {
            denyRead: [join(site, '**/build/**')],
            allowRead: [carveOut],
          }),
        ).toEqual(['BOOTED', 'HIDDEN', 'HIDDEN', 'HIDDEN', 'HIDDEN', 'BESIDE'])
      },
    )

    it.skipIf(!hasBwrap)(
      'can be written to, where the link hides a directory of temporary files',
      async () => {
        // job/tmp -> scratch/tmp under `**/tmp/**`, and scratch/tmp/work
        // allowed for writing: the directory is hidden, and the command can
        // still write where it was told it may, and read what was there.
        const job = join(ROOT, 'job')
        const tmp = join(ROOT, 'scratch', 'tmp')
        const allowed = join(tmp, 'work')
        mkdirSync(join(job, 'src'), { recursive: true })
        mkdirSync(allowed, { recursive: true })
        writeFileSync(join(tmp, 'other.txt'), 'OTHER\n')
        writeFileSync(join(allowed, 'old.txt'), 'OLD\n')
        symlinkSync(tmp, join(job, 'tmp'))

        expect(
          await linesOf(
            [
              `(echo WRITTEN > ${join(allowed, 'out')}) 2>/dev/null && echo WRITE-OK || echo WRITE-FAILED`,
              `cat ${join(allowed, 'out')} 2>/dev/null || echo HIDDEN`,
              `cat ${join(allowed, 'old.txt')} 2>/dev/null || echo HIDDEN`,
              `cat ${join(tmp, 'other.txt')} 2>/dev/null || echo HIDDEN`,
            ],
            { denyRead: [join(job, '**/tmp/**')], allowWrite: [allowed] },
          ),
        ).toEqual(['BOOTED', 'WRITE-OK', 'WRITTEN', 'OLD', 'HIDDEN'])
        expect(existsSync(join(allowed, 'out'))).toBe(true)
        expect(readFileSync(join(allowed, 'out'), 'utf8')).toBe('WRITTEN\n')
      },
    )

    it.skipIf(!hasBwrap)(
      'leaves the working directory in place beneath a mount that hides a target beside it',
      async () => {
        // up/build -> top leads back up and hides top, the working
        // directory with it, which is allowed for writing and bound back.
        // a/build -> top/store leaves the tree beside it, and is not listed:
        // that must not cost the working directory its way back.
        const top = join(ROOT, 'top')
        const cwd = join(top, 'proj')
        mkdirSync(join(top, 'store', 'public'), { recursive: true })
        writeFileSync(join(top, 'store', 'public', 'ok.txt'), 'PUBLIC\n')
        writeFileSync(join(top, 'beside.txt'), 'BESIDE\n')
        mkdirSync(join(cwd, 'up'), { recursive: true })
        mkdirSync(join(cwd, 'a'))
        writeFileSync(join(cwd, 'main.c'), 'SOURCE\n')
        symlinkSync(top, join(cwd, 'up', 'build'))
        symlinkSync(join(top, 'store'), join(cwd, 'a', 'build'))

        expect(
          await linesOf(
            [
              `cat ${join(cwd, 'main.c')} 2>/dev/null || echo HIDDEN`,
              `(echo WRITTEN > ${join(cwd, 'out')}) 2>/dev/null && echo WRITE-OK || echo WRITE-FAILED`,
              `cat ${join(top, 'store', 'public', 'ok.txt')} 2>/dev/null || echo HIDDEN`,
              `cat ${join(top, 'beside.txt')} 2>/dev/null || echo HIDDEN`,
            ],
            { denyRead: [join(cwd, '**/build/**')], allowWrite: [cwd] },
          ),
        ).toEqual(['BOOTED', 'SOURCE', 'WRITE-OK', 'HIDDEN', 'HIDDEN'])
        expect(readFileSync(join(cwd, 'out'), 'utf8')).toBe('WRITTEN\n')
      },
    )
  },
)

describe.if(isLinux)(
  'a file in the tree that the pattern names only by a way out of the tree and back',
  () => {
    // proj/leave -> ../out/hop, and out/hop/back -> ../../proj/deep:
    // `proj/*/*/.env` matches proj/deep/.env as leave/back/.env alone. The
    // link out of the tree is not listed through, so the file is not found,
    // and what is given up is a file inside the tree.
    let ROOT: string
    let proj: string
    let byItsOwnName: string
    let byTheWayRound: string
    const hasBwrap = bwrapCanNamespace()

    beforeAll(() => {
      ROOT = realpathSync(mkdtempSync(join(tmpdir(), 'deny-glob-return-')))
      proj = join(ROOT, 'proj')
      byItsOwnName = join(proj, 'deep', '.env')
      byTheWayRound = join(proj, 'leave', 'back', '.env')
      mkdirSync(join(proj, 'deep'), { recursive: true })
      mkdirSync(join(ROOT, 'out', 'hop'), { recursive: true })
      writeFileSync(byItsOwnName, 'SECRET\n')
      symlinkSync(join('..', 'out', 'hop'), join(proj, 'leave'))
      symlinkSync(
        join('..', '..', 'proj', 'deep'),
        join(ROOT, 'out', 'hop', 'back'),
      )
    })

    afterAll(async () => {
      await SandboxManager.reset()
      rmSync(ROOT, { recursive: true, force: true })
    })

    function wrap(command: string, denyRead: string): Promise<string> {
      return SandboxManager.wrapWithSandbox(command, undefined, {
        filesystem: { denyRead: [denyRead], allowWrite: [], denyWrite: [] },
      })
    }

    it('gets no mount', async () => {
      const wrapped = await wrap('true', join(proj, '*/*/.env'))
      expect(countMounts(wrapped, '--ro-bind', '/dev/null', byItsOwnName)).toBe(
        0,
      )

      // A pattern that matches it by a name inside the tree masks it.
      const named = await wrap('true', join(proj, '*/.env'))
      expect(countMounts(named, '--ro-bind', '/dev/null', byItsOwnName)).toBe(1)
    })

    it.skipIf(!hasBwrap)('is served under both names', async () => {
      // Each command says BOOTED first: a sandbox that refuses to start
      // prints nothing, which would read as every file hidden.
      const linesUnder = async (denyRead: string): Promise<string[]> => {
        const result = spawnSync(
          await wrap(
            [
              'echo BOOTED',
              `cat ${byTheWayRound} || echo HIDDEN`,
              `cat ${byItsOwnName} || echo HIDDEN`,
            ].join('; '),
            denyRead,
          ),
          { shell: true, encoding: 'utf8', timeout: 15000 },
        )
        expect(result.stderr ?? '').not.toContain('bwrap:')
        return result.stdout.trim().split('\n')
      }

      expect(await linesUnder(join(proj, '*/*/.env'))).toEqual([
        'BOOTED',
        'SECRET',
        'SECRET',
      ])
      // Matched by a name inside the tree, it is hidden under every name.
      expect(await linesUnder(join(proj, '*/.env'))).toEqual([
        'BOOTED',
        'HIDDEN',
        'HIDDEN',
      ])
    })
  },
)

describe.if(isLinux)(
  'a file written under the name of a directory that a command moved out of the tree',
  () => {
    // proj/src/config holds nothing that `proj/src/**/.env` matches, so a
    // command that may write the project can move it to proj/moved and leave
    // proj/src/config -> ../moved/config in its place. A .env written under
    // that name afterwards lies outside the tree. proj/src/held holds a
    // masked file, which keeps it where it is.
    let ROOT: string
    let proj: string
    let config: string
    let held: string
    const hasBwrap = bwrapCanNamespace()

    beforeAll(() => {
      ROOT = realpathSync(mkdtempSync(join(tmpdir(), 'deny-glob-moved-')))
      proj = join(ROOT, 'proj')
      config = join(proj, 'src', 'config')
      held = join(proj, 'src', 'held')
      mkdirSync(config, { recursive: true })
      mkdirSync(held)
      mkdirSync(join(proj, 'moved'))
      writeFileSync(join(config, 'settings.json'), '{}\n')
      writeFileSync(join(held, '.env'), 'HELD\n')
    })

    afterAll(async () => {
      await SandboxManager.reset()
      rmSync(ROOT, { recursive: true, force: true })
    })

    /** What the commands print in the sandbox, a line each, after BOOTED. */
    async function linesOf(
      commands: string[],
      denyRead: string,
    ): Promise<string[]> {
      const result = spawnSync(
        await SandboxManager.wrapWithSandbox(
          ['echo BOOTED', ...commands].join('; '),
          undefined,
          {
            filesystem: {
              denyRead: [denyRead],
              allowWrite: [proj],
              denyWrite: [],
            },
          },
        ),
        { shell: true, encoding: 'utf8', timeout: 15000 },
      )
      expect(result.stderr ?? '').not.toContain('bwrap:')
      return result.stdout.trim().split('\n')
    }

    it.skipIf(!hasBwrap)(
      'is served, and the link left in its place is handed back',
      async () => {
        const pattern = join(proj, 'src', '**/.env')
        const moved = (dir: string, name: string): string =>
          `(mv ${dir} ${join(proj, 'moved', name)} && ` +
          `ln -s ${join('..', 'moved', name)} ${dir}) 2>/dev/null ` +
          `&& echo MOVED || echo REFUSED`
        expect(
          await linesOf(
            [moved(config, 'config'), moved(held, 'held')],
            pattern,
          ),
        ).toEqual(['BOOTED', 'MOVED', 'REFUSED'])
        expect(realpathSync(config)).toBe(join(proj, 'moved', 'config'))
        expect(realpathSync(held)).toBe(held)

        writeFileSync(join(config, '.env'), 'LATER\n')
        const reads = [
          `cat ${join(config, '.env')} 2>/dev/null || echo HIDDEN`,
          `cat ${join(held, '.env')} 2>/dev/null || echo HIDDEN`,
        ]
        expect(await linesOf(reads, pattern)).toEqual([
          'BOOTED',
          'LATER',
          'HIDDEN',
        ])
        const unfollowedLinks = new Map<string, string>()
        expect(
          expandReadDenyGlobLinux(pattern, [proj], undefined, {
            unfollowedLinks,
          }),
        ).toEqual([join(held, '.env')])
        expect([...unfollowedLinks]).toEqual([
          [config, join(proj, 'moved', 'config')],
        ])

        // A pattern that starts above both ends of the link masks it.
        expect(await linesOf(reads, join(proj, '**/.env'))).toEqual([
          'BOOTED',
          'HIDDEN',
          'HIDDEN',
        ])
      },
    )
  },
)

describe.if(!isWindows)('the debug line of a read-deny expansion', () => {
  let ROOT: string

  beforeAll(() => {
    ROOT = realpathSync(mkdtempSync(join(tmpdir(), 'deny-glob-debug-')))
    mkdirSync(join(ROOT, 'proj', 'src'), { recursive: true })
    mkdirSync(join(ROOT, 'outside'))
    writeFileSync(join(ROOT, 'proj', '.env'), '')
    writeFileSync(join(ROOT, 'proj', 'src', '.env'), '')
    writeFileSync(join(ROOT, 'proj', 'src', 'index.js'), '')
    symlinkSync(join('..', 'outside'), join(ROOT, 'proj', 'out'))
  })

  afterAll(() => {
    rmSync(ROOT, { recursive: true, force: true })
  })

  /** What the debug logger printed while `fn` ran, at every level. */
  function debugLinesOf(fn: () => void, debug: string | undefined): string[] {
    const lines: string[] = []
    const savedDebug = process.env.SRT_DEBUG
    if (debug === undefined) delete process.env.SRT_DEBUG
    else process.env.SRT_DEBUG = debug
    const record = (...parts: unknown[]): void => {
      lines.push(parts.map(String).join(' '))
    }
    const spies = [
      spyOn(console, 'warn').mockImplementation(record),
      spyOn(console, 'error').mockImplementation(record),
    ]
    try {
      fn()
      return lines
    } finally {
      for (const spy of spies) spy.mockRestore()
      if (savedDebug === undefined) delete process.env.SRT_DEBUG
      else process.env.SRT_DEBUG = savedDebug
    }
  }

  it('says once what the expansion cost and found', () => {
    const pattern = join(ROOT, 'proj', '**/.env')
    const lines = debugLinesOf(
      () => void expandReadDenyGlobLinux(pattern, []),
      '1',
    )

    const summary = lines.filter(line => line.includes('Expanded denyRead'))
    expect(summary).toHaveLength(1)
    // proj and proj/src listed; .env, src and out in one, .env and index.js
    // in the other.
    const timed = summary[0]!.replace(/ in \d+ ms: /, ' in <n> ms: ')
    expect(timed).not.toBe(summary[0])
    expect(timed).toEndWith(
      `Expanded denyRead glob "${pattern}" in <n> ms: 2 matches -> 2 mounts; ` +
        `directories listed: 2, entries looked at: 5, ` +
        `links out of the tree left unfollowed: 1 ` +
        `(first: ${join(ROOT, 'proj', 'out')} -> ${join(ROOT, 'outside')})`,
    )
    // The walk says which link it left, in its own line.
    expect(
      lines.filter(
        line =>
          line.includes('Not following symlink') &&
          line.includes(join(ROOT, 'proj', 'out')) &&
          line.includes(`it leads out of ${join(ROOT, 'proj')}`),
      ),
    ).toHaveLength(1)
  })

  it('hands the links it left back by name, and names the first of them, whatever order they are listed in', () => {
    const proj = join(ROOT, 'ordered')
    mkdirSync(proj)
    for (const name of ['m', 'z', 'a']) {
      symlinkSync(join(ROOT, 'outside'), join(proj, name))
    }
    const pattern = join(proj, '**/.env')
    const byName = ['a', 'm', 'z'].map(name => join(proj, name))
    const readdirSync = fs.readdirSync

    for (const backwards of [false, true]) {
      const spy = spyOn(fs, 'readdirSync').mockImplementation(((
        ...args: Parameters<typeof fs.readdirSync>
      ) => {
        const entries = readdirSync(...args)
        // Listed with their types, as the walk lists: sorted where they are.
        const after = backwards ? -1 : 1
        ;(entries as unknown as fs.Dirent[]).sort((x, y) =>
          x.name < y.name ? -after : after,
        )
        return entries
      }) as typeof fs.readdirSync)
      try {
        // The walk meets them in the order the directory lists them.
        expect([
          ...walkGlobPattern(pattern, {
            followSymlinkedDirectories: true,
          }).unfollowedLinks.keys(),
        ]).toEqual(backwards ? [...byName].reverse() : byName)

        const unfollowedLinks = new Map<string, string>()
        const lines = debugLinesOf(
          () =>
            void expandReadDenyGlobLinux(pattern, [], undefined, {
              unfollowedLinks,
            }),
          '1',
        )
        expect([...unfollowedLinks.keys()]).toEqual(byName)
        const summary = lines.filter(line => line.includes('Expanded denyRead'))
        expect(summary).toHaveLength(1)
        expect(summary[0]).toEndWith(
          `links out of the tree left unfollowed: 3 ` +
            `(first: ${byName[0]} -> ${join(ROOT, 'outside')})`,
        )
      } finally {
        spy.mockRestore()
      }
    }
  })

  it('names no link when none was left', () => {
    const lines = debugLinesOf(
      () => void expandReadDenyGlobLinux(join(ROOT, 'proj', 'src', '*'), []),
      '1',
    )

    const summary = lines.filter(line => line.includes('Expanded denyRead'))
    expect(summary).toHaveLength(1)
    expect(summary[0]).toEndWith(
      ' ms: 2 matches -> 2 mounts; directories listed: 1, entries looked at: 2, links out of the tree left unfollowed: 0',
    )
  })

  it('says nothing without SRT_DEBUG', () => {
    expect(
      debugLinesOf(
        () => void expandReadDenyGlobLinux(join(ROOT, 'proj', '**/.env'), []),
        undefined,
      ),
    ).toEqual([])
  })
})
