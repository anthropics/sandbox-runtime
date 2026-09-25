import { describe, it, expect, beforeAll, afterAll, spyOn } from 'bun:test'
// The namespaces the library binds, so a spy on one is seen by the code under
// test.
import * as fs from 'fs'
import * as sandboxUtils from '../../src/sandbox/sandbox-utils.js'
import {
  mkdirSync,
  mkdtempSync,
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
import { countMounts } from '../helpers/bwrap-argv.js'

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

  /**
   * `<name>/proj` beside `<name>/store`, with `proj/pkg/build -> store/build`
   * and `proj/certs/vault.pem -> store/vault`. Each target holds `public`,
   * the allowed path, with a file in it that the patterns here match.
   */
  function plantStore(name: string): { top: string; proj: string } {
    const top = join(ROOT, name)
    const proj = join(top, 'proj')
    for (const dir of ['build', 'vault']) {
      mkdirSync(join(top, 'store', dir, 'public'), { recursive: true })
      writeFileSync(join(top, 'store', dir, 'public', 'id.pem'), 'KEY')
    }
    mkdirSync(join(proj, 'pkg'), { recursive: true })
    mkdirSync(join(proj, 'certs'))
    symlinkSync(join(top, 'store', 'build'), join(proj, 'pkg', 'build'))
    symlinkSync(join(top, 'store', 'vault'), join(proj, 'certs', 'vault.pem'))
    return { top, proj }
  }

  it('hands back what a matched link out of the tree leads to as a directory to bind nothing back beneath', () => {
    // The target is denied as a whole and was not listed, so id.pem beneath
    // the allowed path was never found: bound back, the path would show it.
    const { top, proj } = plantStore('p-closed')
    const build = join(top, 'store', 'build')
    const vault = join(top, 'store', 'vault')

    // A link that matches in the directory form, and one by its own name.
    for (const [pattern, target] of [
      [join(proj, '**/build/**'), build],
      [join(proj, 'certs', '**/*.pem'), vault],
    ] as const) {
      const unlistable = new Set<string>()
      const { result: mounts, listed } = listedDuring(() =>
        expandReadDenyGlobLinux(pattern, [join(target, 'public')], unlistable),
      )

      expect(mounts).toEqual([target])
      expect(listed.filter(dir => dir.startsWith(join(top, 'store')))).toEqual(
        [],
      )
      expect([...unlistable]).toEqual([target])
    }

    // Started above both ends of the link, the target is listed: the allowed
    // path is bound back, and what the pattern matches beneath it keeps its
    // own mount.
    const unlistable = new Set<string>()
    expect(
      expandReadDenyGlobLinux(
        join(top, '**/build/**'),
        [join(build, 'public')],
        unlistable,
      ),
    ).toEqual([build, join(build, 'public'), join(build, 'public', 'id.pem')])
    expect([...unlistable]).toEqual([])
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
    // no listing was called for, so nothing is missing from the deny, and
    // the allowed path comes back as under a literal deny of the link.
    const endedAt = new Set<string>()
    expect(
      expandReadDenyGlobLinux(
        join(proj, 'certs', '*.pem'),
        [join(vault, 'public')],
        endedAt,
      ),
    ).toEqual([vault])
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
    expect(
      expandReadDenyGlobLinux(
        join(proj, '*/*.pem'),
        [join(out, 'sub')],
        unlistable,
        { unfollowedLinks },
      ),
    ).toEqual([out])
    expect([...unfollowedLinks]).toEqual([[join(proj, 'b'), join(out, 'sub')]])
    expect([...unlistable]).toEqual([])
  })

  it('hands back the mount that hides what a matched link out of the tree leads to', () => {
    // up/build -> top leads back up, and denies top as a whole. a/build ->
    // top/store leaves the tree beside it: store is denied too and was not
    // listed, and the mount that hides it is top's.
    const top = join(ROOT, 'p-hidden')
    const proj = join(top, 'proj')
    mkdirSync(join(top, 'store', 'public'), { recursive: true })
    writeFileSync(join(top, 'store', 'public', 'ok.txt'), 'PUBLIC')
    mkdirSync(join(proj, 'up'), { recursive: true })
    mkdirSync(join(proj, 'a'))
    symlinkSync(top, join(proj, 'up', 'build'))
    symlinkSync(join(top, 'store'), join(proj, 'a', 'build'))

    const unlistable = new Set<string>()
    expect(
      expandReadDenyGlobLinux(
        join(proj, '**/build/**'),
        [join(top, 'store', 'public')],
        unlistable,
      ),
    ).toEqual([top])
    expect([...unlistable]).toEqual([top])
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
    // The tree is there to be found by a pattern that names it.
    expect(expandGlobPattern(join(big, '**/.env'))).toHaveLength(30)
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

  function filesystemOf(denyRead: string[]) {
    return { filesystem: { denyRead, allowWrite: [], denyWrite: [] } }
  }

  /** The wrapped command, or what the wrap threw: never both. */
  async function wrapOf(
    denyRead: string[],
  ): Promise<{ wrapped?: string; error?: unknown }> {
    try {
      return {
        wrapped: await SandboxManager.wrapWithSandbox(
          'echo hello',
          undefined,
          filesystemOf(denyRead),
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

    // Three entries in the tree; OTHER holds forty.
    const { wrapped, error } = await withBudgetOf({ maxEntries: 3 }, () =>
      wrapOf([join(proj, '**/.env')]),
    )

    expect(error).toBeUndefined()
    expect(wrapped).toContain(`--ro-bind /dev/null ${join(proj, '.env')}`)
    expect(wrapped).not.toContain(join(OTHER, 'pkg0', '.env'))
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
    // proj/pkg/build -> store/build, and allowRead store/build/public. The
    // pattern that starts at proj denies store/build as a whole without
    // listing it, so ok.txt beneath the allowed path has no mask of its own:
    // the path is not bound back.
    let ROOT: string
    let proj: string
    let build: string
    let carveOut: string
    const hasBwrap = bwrapCanNamespace()

    beforeAll(() => {
      ROOT = realpathSync(mkdtempSync(join(tmpdir(), 'deny-glob-closed-')))
      proj = join(ROOT, 'proj')
      build = join(ROOT, 'store', 'build')
      carveOut = join(build, 'public')
      mkdirSync(carveOut, { recursive: true })
      writeFileSync(join(build, 'secret.out'), 'SECRET')
      writeFileSync(join(carveOut, 'ok.txt'), 'PUBLIC')
      writeFileSync(join(ROOT, 'store', 'beside.txt'), 'BESIDE')
      mkdirSync(join(proj, 'pkg'), { recursive: true })
      symlinkSync(build, join(proj, 'pkg', 'build'))
    })

    afterAll(async () => {
      await SandboxManager.reset()
      rmSync(ROOT, { recursive: true, force: true })
    })

    function wrap(command: string, denyRead: string): Promise<string> {
      return SandboxManager.wrapWithSandbox(command, undefined, {
        filesystem: {
          denyRead: [denyRead],
          allowRead: [carveOut],
          allowWrite: [],
          denyWrite: [],
        },
      })
    }

    it('is not bound back', async () => {
      const wrapped = await wrap('true', join(proj, '**/build/**'))

      expect(countMounts(wrapped, '--tmpfs', build)).toBe(1)
      expect(countMounts(wrapped, '--ro-bind', carveOut, carveOut)).toBe(0)

      // Started above both ends of the link, the pattern finds ok.txt: the
      // path is bound back, with the file masked beneath it.
      const listed = await wrap('true', join(ROOT, '**/build/**'))
      expect(
        countMounts(listed, '--ro-bind', carveOut, carveOut),
      ).toBeGreaterThan(0)
      expect(
        countMounts(listed, '--ro-bind', '/dev/null', join(carveOut, 'ok.txt')),
      ).toBe(1)
    })

    it.skipIf(!hasBwrap)(
      'serves no file beneath it, by either name',
      async () => {
        // Each command says BOOTED first: a sandbox that refuses to start
        // prints nothing, which would read as every file hidden.
        const result = spawnSync(
          await wrap(
            [
              'echo BOOTED',
              `cat ${join(carveOut, 'ok.txt')} || echo HIDDEN`,
              `cat ${join(proj, 'pkg', 'build', 'public', 'ok.txt')} || echo HIDDEN`,
              `cat ${join(build, 'secret.out')} || echo HIDDEN`,
              `cat ${join(ROOT, 'store', 'beside.txt')}`,
            ].join('; '),
            join(proj, '**/build/**'),
          ),
          { shell: true, encoding: 'utf8', timeout: 15000 },
        )

        expect(result.stderr ?? '').not.toContain('bwrap:')
        expect(result.stdout.trim().split('\n')).toEqual([
          'BOOTED',
          'HIDDEN',
          'HIDDEN',
          'HIDDEN',
          'BESIDE',
        ])
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
