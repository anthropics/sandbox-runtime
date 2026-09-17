import { describe, it, expect, beforeAll, afterAll, spyOn } from 'bun:test'
// The namespace the library binds, so a spy on it is seen by the code under
// test (see linux-ancestor-pin-errno.test.ts).
import * as fs from 'fs'
import {
  chmodSync,
  existsSync,
  lstatSync,
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
import { expandGlobPattern } from '../../src/sandbox/sandbox-utils.js'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import {
  wrapCommandWithSandboxLinux,
  cleanupBwrapMountPoints,
} from '../../src/sandbox/linux-sandbox-utils.js'
import { isLinux, isWindows } from '../helpers/platform.js'
import { bwrapCanNamespace } from '../helpers/bwrap-namespace.js'
import { countMounts, lastIndexOfMount } from '../helpers/bwrap-argv.js'
import { withCapturedWarnings } from '../helpers/captured-warnings.js'

describe.if(!isWindows)('expandReadDenyGlobLinux (collapse)', () => {
  let ROOT: string

  beforeAll(() => {
    ROOT = realpathSync(mkdtempSync(join(tmpdir(), 'deny-glob-rules-')))
    // build/ and its string-prefix sibling build-cache/, each with a nested
    // directory.
    for (const dir of ['build', 'build-cache']) {
      mkdirSync(join(ROOT, dir, 'sub'), { recursive: true })
      writeFileSync(join(ROOT, dir, '1.out'), '')
      writeFileSync(join(ROOT, dir, 'sub', '2.out'), '')
    }
  })

  afterAll(() => {
    rmSync(ROOT, { recursive: true, force: true })
  })

  it('does not treat a string-prefix sibling as an ancestor', () => {
    const mounts = expandReadDenyGlobLinux(join(ROOT, 'build*/**'), [])
    expect(mounts).toEqual([join(ROOT, 'build'), join(ROOT, 'build-cache')])
  })

  it('treats a re-exposer AT the covering directory as re-exposing everything beneath it', () => {
    // denyRead and allowRead naming the same directory: its tmpfs is bound
    // back at once, so every match beneath needs its own mount.
    const build = join(ROOT, 'build')
    const mounts = expandReadDenyGlobLinux(join(ROOT, 'build*/**'), [build])
    expect(mounts).toEqual([
      build,
      join(ROOT, 'build-cache'),
      join(build, '1.out'),
      join(build, 'sub'),
    ])
  })

  it('ignores re-exposers below the candidate or unrelated to it', () => {
    const mounts = expandReadDenyGlobLinux(join(ROOT, 'build*/**'), [
      join(ROOT, 'build', 'sub', '2.out', 'deeper'),
      join(ROOT, 'buildx'),
      '/elsewhere',
    ])
    expect(mounts).toEqual([join(ROOT, 'build'), join(ROOT, 'build-cache')])
  })

  it.if(process.getuid?.() !== 0)(
    'denies a directory it cannot list as a whole',
    () => {
      // Searchable but not listable (what a sandboxed command with write
      // access to the tree can leave for the next wrap): the matches beneath
      // it cannot be found, so the directory itself is the mount.
      const locked = join(ROOT, 'locked')
      mkdirSync(join(locked, 'build'), { recursive: true })
      writeFileSync(join(locked, 'build', 'secret.out'), '')
      chmodSync(locked, 0o311)
      try {
        const mounts = expandReadDenyGlobLinux(join(ROOT, '**/build/**'), [])
        expect(mounts).toContain(locked)
        expect(mounts).toContain(join(ROOT, 'build'))
      } finally {
        chmodSync(locked, 0o755)
        rmSync(locked, { recursive: true, force: true })
      }
    },
  )

  it.if(process.getuid?.() !== 0)(
    'leaves alone an unlistable directory the pattern cannot match beneath',
    () => {
      // certs/*.pem matches at one depth: certs/pgdata (a volume owned by
      // another user, say) holds no match whatever it contains, and as a
      // tmpfs it would be an empty directory whose writes go nowhere.
      const certs = join(ROOT, 'certs')
      mkdirSync(join(certs, 'pgdata'), { recursive: true })
      writeFileSync(join(certs, 'top.pem'), '')
      chmodSync(join(certs, 'pgdata'), 0o000)
      try {
        expect(expandReadDenyGlobLinux(join(certs, '*.pem'), [])).toEqual([
          join(certs, 'top.pem'),
        ])
      } finally {
        chmodSync(join(certs, 'pgdata'), 0o755)
        rmSync(certs, { recursive: true, force: true })
      }
    },
  )

  it('warns once per mount that lands outside the pattern it came from', async () => {
    // A matched link decides what is hidden for the whole sandbox: the
    // pattern names config/, the mount goes on a database directory nothing
    // in the configuration mentions.
    const outside = join(ROOT, 'pgdata')
    const config = join(ROOT, 'config')
    mkdirSync(join(outside, 'base'), { recursive: true })
    mkdirSync(config, { recursive: true })
    writeFileSync(join(config, 'app.conf'), '')
    symlinkSync(outside, join(config, 'data'))
    try {
      const { result, warnings } = await withCapturedWarnings(async () =>
        expandReadDenyGlobLinux(join(config, '*'), []),
      )

      expect(result).toContain(outside)
      const escaped = warnings.filter(line => line.includes(outside))
      expect(escaped).toHaveLength(1)
      expect(escaped[0]).toContain(join(config, '*'))
      expect(escaped[0]).toContain(join(config, 'data'))
      // What stays inside the pattern's own base is not worth a warning.
      expect(
        warnings.filter(line => line.includes(join(config, 'app.conf'))),
      ).toEqual([])
    } finally {
      rmSync(outside, { recursive: true, force: true })
      rmSync(config, { recursive: true, force: true })
    }
  })

  it('warns when a pattern still needs more mounts than the threshold after collapsing', async () => {
    // The expansion is never truncated — that would silently un-deny paths —
    // so a broad pattern is reported rather than cut short.
    const many = join(ROOT, 'many')
    mkdirSync(many, { recursive: true })
    for (let i = 0; i <= 256; i++) writeFileSync(join(many, `${i}.key`), '')
    try {
      const { result, warnings } = await withCapturedWarnings(async () =>
        expandReadDenyGlobLinux(join(many, '*.key'), []),
      )

      expect(result).toHaveLength(257)
      expect(
        warnings.filter(line => line.includes('after collapsing')),
      ).toHaveLength(1)

      const { warnings: quiet } = await withCapturedWarnings(async () =>
        expandReadDenyGlobLinux(join(many, '1?.key'), []),
      )
      expect(quiet.filter(line => line.includes('after collapsing'))).toEqual(
        [],
      )
    } finally {
      rmSync(many, { recursive: true, force: true })
    }
  })
})

describe.if(!isWindows)('expandReadDenyGlobLinux (symlinks)', () => {
  let ROOT: string
  let OUTSIDE: string

  beforeAll(() => {
    ROOT = realpathSync(mkdtempSync(join(tmpdir(), 'deny-glob-symlink-')))
    OUTSIDE = join(ROOT, 'outside')
    mkdirSync(OUTSIDE)
    writeFileSync(join(OUTSIDE, 'secret.txt'), '')
    writeFileSync(join(OUTSIDE, 'key.pem'), '')
    // pkg/a/build: a real file plus a directory symlink and a file symlink
    // that both point outside the tree.
    mkdirSync(join(ROOT, 'pkg', 'a', 'build'), { recursive: true })
    writeFileSync(join(ROOT, 'pkg', 'a', 'build', '1.out'), '')
    symlinkSync(OUTSIDE, join(ROOT, 'pkg', 'a', 'build', 'link'))
    symlinkSync(
      join(OUTSIDE, 'key.pem'),
      join(ROOT, 'pkg', 'a', 'build', 'key.pem'),
    )
    // pkg/empty/build: exists but holds nothing.
    mkdirSync(join(ROOT, 'pkg', 'empty', 'build'), { recursive: true })
    // pkg/linked/build: a symlink NAMED build, to a real build dir.
    mkdirSync(join(ROOT, 'pkg', 'linked'))
    symlinkSync(
      join(ROOT, 'pkg', 'a', 'build'),
      join(ROOT, 'pkg', 'linked', 'build'),
    )
  })

  /**
   * A fixture directory of its own for a case that plants a tree: four of
   * the tests here glob the whole of ROOT, and would otherwise see whatever
   * another case left in it.
   */
  const caseRoots: string[] = []
  function caseRoot(name: string): string {
    const dir = realpathSync(mkdtempSync(join(tmpdir(), `deny-glob-${name}-`)))
    caseRoots.push(dir)
    return dir
  }

  afterAll(() => {
    for (const dir of [ROOT, ...caseRoots]) {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  it('mounts a symlink beneath a collapsed directory at its target', () => {
    // The denyRead loop emits the covering directory's tmpfs first, which
    // replaces the link with an empty directory inside the sandbox, so a
    // mount kept under the link spelling would land there and hide
    // nothing. The target is listed in its own right and kept instead.
    const build = join(ROOT, 'pkg', 'a', 'build')
    const mounts = expandReadDenyGlobLinux(join(ROOT, '**/build/**'), [])

    expect(mounts).toContain(build)
    expect(mounts).not.toContain(join(build, '1.out'))
    // Directory symlink: its target is the mount, and what the listing
    // found beneath the link collapses under it.
    expect(mounts).toContain(OUTSIDE)
    expect(mounts).not.toContain(join(build, 'link'))
    expect(mounts).not.toContain(join(build, 'link', 'secret.txt'))
    // File symlink: its target, already under the resolved directory.
    expect(mounts).not.toContain(join(build, 'key.pem'))
    expect(mounts).not.toContain(join(OUTSIDE, 'key.pem'))
  })

  it('keeps the resolved carve-out beneath a link strictly below the covering directory', () => {
    // pkg/a/build/link -> outside, with allowRead written against the
    // target: outside/ is denied as a whole, its carve-out and the
    // entries beneath keep their own mounts, and nothing else beneath it.
    mkdirSync(join(OUTSIDE, 'pub'))
    writeFileSync(join(OUTSIDE, 'pub', 'x.txt'), '')
    try {
      const mounts = expandReadDenyGlobLinux(
        join(ROOT, 'pkg', 'a', '**/build/**'),
        [join(OUTSIDE, 'pub')],
      )

      expect(mounts).toContain(join(ROOT, 'pkg', 'a', 'build'))
      expect(mounts).toContain(OUTSIDE)
      expect(mounts).toContain(join(OUTSIDE, 'pub'))
      expect(mounts).toContain(join(OUTSIDE, 'pub', 'x.txt'))
      expect(mounts).not.toContain(join(OUTSIDE, 'secret.txt'))
    } finally {
      rmSync(join(OUTSIDE, 'pub'), { recursive: true })
    }
  })

  it('gives an empty matched directory no mount', () => {
    const mounts = expandReadDenyGlobLinux(join(ROOT, '**/build/**'), [])
    expect(mounts).not.toContain(join(ROOT, 'pkg', 'empty', 'build'))
  })

  it('lists a directory symlink that is itself the covering directory where it really is', () => {
    // pkg/linked/build -> pkg/a/build: one mount, on the target, which is
    // where the deny loop would put an entry spelled through the link.
    const linked = join(ROOT, 'pkg', 'linked', 'build')
    const mounts = expandReadDenyGlobLinux(join(ROOT, '**/build/**'), [])

    expect(mounts).toContain(join(ROOT, 'pkg', 'a', 'build'))
    expect(mounts).not.toContain(linked)
    expect(mounts).not.toContain(join(linked, '1.out'))
  })

  it('lists a link named like the pattern segment with its target', () => {
    // proj/config/secrets -> ../vault: the target is a real directory the
    // walk also reaches by its own name, which matches nothing; the link is
    // the only spelling the pattern matches, so both names have to be
    // listed. The target is where the mount lands.
    const shal = caseRoot('shallow')
    mkdirSync(join(shal, 'proj', 'vault'), { recursive: true })
    writeFileSync(join(shal, 'proj', 'vault', 'secret.out'), '')
    mkdirSync(join(shal, 'proj', 'config'))
    symlinkSync(join('..', 'vault'), join(shal, 'proj', 'config', 'secrets'))

    const mounts = expandReadDenyGlobLinux(join(shal, '**/secrets/**'), [])

    expect(mounts).toEqual([join(shal, 'proj', 'vault')])
  })

  it('lists every match where it really is when the base is a symlink', () => {
    // alias -> ROOT, sideways: normalizePathForSandbox keeps the link
    // spelling for the pattern, so every match is spelled through it. The
    // mounts go where the matches really are, and a carve-out counts the
    // same whether it is written through the alias or not.
    const alias = join(
      ROOT,
      '..',
      `alias-${Math.random().toString(36).slice(2)}`,
    )
    symlinkSync(ROOT, alias)
    try {
      const build = join('pkg', 'a', 'build')
      const carveOut = join(ROOT, build, 'public')
      mkdirSync(carveOut, { recursive: true })
      writeFileSync(join(carveOut, 'ok.txt'), '')

      const real = expandReadDenyGlobLinux(join(alias, '**/build/**'), [
        carveOut,
      ])
      expect(real).toContain(join(ROOT, build))
      expect(real).toContain(carveOut)
      expect(real).toContain(join(carveOut, 'ok.txt'))
      expect(real).not.toContain(join(ROOT, build, '1.out'))
      expect(real.filter(m => m.startsWith(alias + '/'))).toEqual([])

      expect(
        expandReadDenyGlobLinux(join(alias, '**/build/**'), [
          join(alias, build, 'public'),
        ]),
      ).toEqual(real)
    } finally {
      rmSync(alias)
      rmSync(join(ROOT, 'pkg', 'a', 'build', 'public'), { recursive: true })
    }
  })

  it('denies what holds a link to the root, never the root', () => {
    // build/root -> /: denied where it resolves, that would be a tmpfs over
    // every top-level directory; denied at the link, a mount bwrap refuses,
    // so that no later command starts while the link exists. The directory
    // holding it is denied instead, as for an entry that cannot be
    // inspected — here build, which the pattern denies anyway.
    const rooted = caseRoot('rooted')
    mkdirSync(join(rooted, 'build'), { recursive: true })
    writeFileSync(join(rooted, 'build', '1.out'), '')
    symlinkSync('/', join(rooted, 'build', 'root'))

    const mounts = expandReadDenyGlobLinux(join(rooted, '**/build/**'), [])

    expect(mounts).toEqual([join(rooted, 'build')])

    // The same when the link is itself the matched directory: the mount goes
    // on the directory holding it.
    mkdirSync(join(rooted, 'img'))
    symlinkSync('/', join(rooted, 'img', 'build'))
    expect(
      expandReadDenyGlobLinux(join(rooted, 'img', '**/build/**'), []),
    ).toEqual([join(rooted, 'img')])
  })

  it('denies the target of a directory-form link the walk did not descend', () => {
    // pkg/x/y/build -> pkg/x names a directory on its own descent chain, so
    // the walk lists nothing beneath it; it is still a match, and its target
    // is what a literal deny of the link would deny.
    const ancestry = caseRoot('ancestry')
    mkdirSync(join(ancestry, 'x', 'y'), { recursive: true })
    writeFileSync(join(ancestry, 'x', 'src.ts'), '')
    symlinkSync(join('..'), join(ancestry, 'x', 'y', 'build'))

    const mounts = expandReadDenyGlobLinux(join(ancestry, '**/build/**'), [])

    expect(mounts).toContain(join(ancestry, 'x'))
  })

  it('denies through a link back to the tree', () => {
    // build/up -> ..: the target is the whole tree the link reaches, as a
    // literal deny of the link would have it; the walk itself stops at the
    // link.
    const esc = caseRoot('escape')
    mkdirSync(join(esc, 'build'), { recursive: true })
    writeFileSync(join(esc, 'build', '1.out'), '')
    symlinkSync('..', join(esc, 'build', 'up'))

    const mounts = expandReadDenyGlobLinux(join(esc, '**/build/**'), [])

    expect(mounts).toEqual([esc])
  })

  describe('carve-out through a symlink (pnpm layout)', () => {
    // node_modules/foo -> ../.pnpm/foo@1/node_modules/foo, the shape pnpm
    // installs; the glob matches both the link and the real tree.
    let pnpmRoot: string
    let real: string
    let link: string
    beforeAll(() => {
      pnpmRoot = caseRoot('pnpm')
      real = join(pnpmRoot, '.pnpm', 'foo@1', 'node_modules', 'foo')
      link = join(pnpmRoot, 'node_modules', 'foo')
      mkdirSync(join(real, 'public'), { recursive: true })
      writeFileSync(join(real, 'index.js'), '')
      writeFileSync(join(real, 'public', 'ok.txt'), '')
      mkdirSync(join(pnpmRoot, 'node_modules'))
      symlinkSync(join('..', '.pnpm', 'foo@1', 'node_modules', 'foo'), link)
    })

    for (const spelling of ['link', 'resolved'] as const) {
      it(`keeps what lies beneath a carve-out written against the ${spelling} spelling`, () => {
        const mounts = expandReadDenyGlobLinux(
          join(pnpmRoot, '**/node_modules/foo/**'),
          [join(spelling === 'link' ? link : real, 'public')],
        )

        // The package, the carve-out and what lies beneath it, where they
        // are; index.js is hidden by the package's tmpfs.
        expect(mounts).toEqual([
          real,
          join(real, 'public'),
          join(real, 'public', 'ok.txt'),
        ])
      })
    }

    it('is not defeated by a re-exposer above the covering directory', () => {
      // allowWrite ['.'] (the README's example) names the project root,
      // which re-exposes nothing beneath a tmpfs, so the package still
      // collapses to its two spellings.
      const mounts = expandReadDenyGlobLinux(
        join(pnpmRoot, '**/node_modules/foo/**'),
        [pnpmRoot],
      )

      expect(mounts).toEqual([real])
    })
  })

  it('keeps a match beneath a carve-out that only a second link leads to', () => {
    // proj/build -> store/nm and store/nm/keep -> ../keep: y.txt is matched
    // as proj/build/keep/pub/y.txt but lives at store/keep/pub/y.txt, which
    // no spelled ancestor of the match contains. Collapsing along the
    // spelling would drop it under proj/build and lose the mask beneath the
    // carve-out.
    const chain = caseRoot('chain')
    const proj = join(chain, 'proj')
    const store = join(chain, 'store')
    mkdirSync(proj, { recursive: true })
    mkdirSync(join(store, 'nm'), { recursive: true })
    mkdirSync(join(store, 'keep', 'pub'), { recursive: true })
    writeFileSync(join(store, 'keep', 'pub', 'y.txt'), '')
    writeFileSync(join(store, 'nm', 'z.out'), '')
    symlinkSync(join(store, 'nm'), join(proj, 'build'))
    symlinkSync(join('..', 'keep'), join(store, 'nm', 'keep'))

    const mounts = expandReadDenyGlobLinux(join(proj, '**/build/**'), [
      join(store, 'keep', 'pub'),
    ])

    expect(mounts).toEqual([
      join(store, 'keep'),
      join(store, 'keep', 'pub'),
      join(store, 'keep', 'pub', 'y.txt'),
      join(store, 'nm'),
    ])
  })

  it('drops a matched link that does not resolve', () => {
    const dangling = caseRoot('dangling')
    mkdirSync(join(dangling, 'build'), { recursive: true })
    writeFileSync(join(dangling, 'build', '1.out'), '')
    symlinkSync(join(dangling, 'gone'), join(dangling, 'build', 'lost'))

    expect(expandReadDenyGlobLinux(join(dangling, '**/build/lo*'), [])).toEqual(
      [],
    )
  })
})

describe.if(isLinux)(
  'expandReadDenyGlobLinux (bwrap wiring through a symlink)',
  () => {
    // The pnpm layout again, driven through the real Linux wrapper: no tmpfs
    // may land on a symlink (bubblewrap 0.12 refuses to start), and the
    // carve-out must be the last word on the package's inode.
    let ROOT: string
    let pnpmRoot: string
    let real: string
    let link: string
    const savedCwd = process.cwd()
    const hasBwrap = bwrapCanNamespace()

    /**
     * Run a wrapped command and hold it to having started. A sandbox that
     * refuses to start prints nothing, which every assertion about what it
     * hides would otherwise read as a pass, so each command under test says
     * BOOTED first.
     */
    function runBooted(wrapped: string): string {
      const result = spawnSync(wrapped, {
        shell: true,
        encoding: 'utf8',
        timeout: 15000,
      })
      expect(result.stderr ?? '').not.toContain('bwrap:')
      expect(result.stdout).toContain('BOOTED')
      return result.stdout
    }

    /** `ln -s` a case's second test can call again over its own fixture. */
    function ensureLink(target: string, linkPath: string): void {
      try {
        symlinkSync(target, linkPath)
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code !== 'EEXIST') throw err
      }
    }

    beforeAll(() => {
      ROOT = realpathSync(mkdtempSync(join(tmpdir(), 'deny-glob-bwrap-')))
      pnpmRoot = join(ROOT, 'pnpm')
      real = join(pnpmRoot, '.pnpm', 'foo@1', 'node_modules', 'foo')
      link = join(pnpmRoot, 'node_modules', 'foo')
      mkdirSync(join(real, 'public'), { recursive: true })
      writeFileSync(join(real, 'index.js'), 'secret')
      writeFileSync(join(real, 'public', 'ok.txt'), 'public')
      mkdirSync(join(pnpmRoot, 'node_modules'))
      symlinkSync(join('..', '.pnpm', 'foo@1', 'node_modules', 'foo'), link)
      process.chdir(ROOT)
    })

    afterAll(() => {
      process.chdir(savedCwd)
      cleanupBwrapMountPoints({ force: true })
      rmSync(ROOT, { recursive: true, force: true })
    })

    async function wrap(command: string, carveOut: string): Promise<string> {
      return wrapCommandWithSandboxLinux({
        command,
        needsNetworkRestriction: false,
        readConfig: {
          denyOnly: expandReadDenyGlobLinux(
            join(pnpmRoot, '**/node_modules/foo/**'),
            [carveOut],
          ),
          allowWithinDeny: [carveOut],
        },
        writeConfig: { allowOnly: [], denyWithinAllow: [] },
      })
    }

    for (const spelling of ['link', 'target'] as const) {
      const carveOutOf = () => join(spelling === 'link' ? link : real, 'public')
      it(`mounts no tmpfs on a symlink and re-binds the carve-out last (allowRead in ${spelling} spelling)`, async () => {
        const carveOut = carveOutOf()
        const wrapped = await wrap('echo hello', carveOut)
        const ops = wrapped.split(' --').map(op => op.trim())

        const tmpfsDests = ops
          .filter(op => op.startsWith('tmpfs '))
          .map(op => op.slice('tmpfs '.length))
        expect(tmpfsDests).toContain(real)
        expect(tmpfsDests).not.toContain(link)
        for (const dest of tmpfsDests) {
          expect(lstatSync(dest).isSymbolicLink()).toBe(false)
        }
        // One tmpfs per inode, and the carve-out's bind after the last one
        // that covers it.
        expect(tmpfsDests.filter(d => d === real)).toHaveLength(1)
        const lastTmpfs = Math.max(
          ...ops.flatMap((op, i) => (op.startsWith('tmpfs ') ? [i] : [])),
        )
        // The carve-out goes back at the name it is, read from where that
        // name resolves: both are inside the package's real location.
        const reBind = ops.lastIndexOf(
          `ro-bind ${join(real, 'public')} ${join(real, 'public')}`,
        )
        expect(reBind).toBeGreaterThan(lastTmpfs)
      })

      it.skipIf(!hasBwrap)(
        `serves the package empty but for the carve-out, in both spellings (allowRead in ${spelling} spelling)`,
        async () => {
          const stdout = runBooted(
            await wrap(
              [
                'echo BOOTED',
                `ls ${link}`,
                `ls ${real}`,
                `cat ${join(link, 'public', 'ok.txt')} | wc -c`,
                `[ -e ${join(link, 'index.js')} ] && echo INDEX_VISIBLE || echo INDEX_HIDDEN`,
              ].join('; '),
              carveOutOf(),
            ),
          )
          expect(stdout.trim().split('\n')).toEqual([
            'BOOTED',
            'public',
            'public',
            '0',
            'INDEX_HIDDEN',
          ])
        },
      )
    }

    it('honours a file carve-out written in the link spelling', async () => {
      // The glob lists index.js under both spellings; only the link spelling
      // is in allowRead. Neither twin may be masked, and the carve-out is
      // bound back over the package tmpfs.
      const carveOut = join(link, 'index.js')
      const wrapped = await wrapCommandWithSandboxLinux({
        command: 'true',
        needsNetworkRestriction: false,
        readConfig: {
          denyOnly: expandReadDenyGlobLinux(
            join(pnpmRoot, '**/node_modules/foo/**'),
            [carveOut],
          ),
          allowWithinDeny: [carveOut],
        },
        writeConfig: { allowOnly: [], denyWithinAllow: [] },
      })

      expect(wrapped).toContain(
        `--ro-bind ${join(real, 'index.js')} ${join(real, 'index.js')}`,
      )
      expect(wrapped).not.toContain(`/dev/null ${join(real, 'index.js')}`)
      expect(wrapped).not.toContain(`/dev/null ${carveOut}`)
    })

    it('re-applies the tmpfs after a denyWrite bind that contains its target', async () => {
      // denyWrite names the pnpm store, which contains the package's real
      // location but not its link spelling; the bind lands after the tmpfs
      // and would re-expose the package read-only without a re-application.
      const store = join(pnpmRoot, '.pnpm')
      const wrapped = await wrapCommandWithSandboxLinux({
        command: 'true',
        needsNetworkRestriction: false,
        readConfig: {
          denyOnly: expandReadDenyGlobLinux(
            join(pnpmRoot, '**/node_modules/foo/**'),
            [],
          ),
        },
        writeConfig: { allowOnly: [pnpmRoot], denyWithinAllow: [store] },
      })

      const storeBind = lastIndexOfMount(wrapped, '--ro-bind', store, store)
      expect(storeBind).toBeGreaterThan(-1)
      expect(lastIndexOfMount(wrapped, '--tmpfs', real)).toBeGreaterThan(
        storeBind,
      )
    })

    it('does not re-apply a tmpfs over its carve-out when a denyWrite bind covers only the link spelling', async () => {
      // w/d/link -> realdir (outside the write root w). denyWrite [w/d]
      // contains the link's spelling but not where the tmpfs landed
      // (realdir), so the bind re-exposes nothing; re-applying the tmpfs
      // there anyway would re-bind realdir/pub over the mask on
      // realdir/pub/secret.txt and leave the file readable.
      const caseRoot = join(ROOT, 'f4')
      const realdir = join(caseRoot, 'realdir')
      const writeRoot = join(caseRoot, 'w')
      const linkInWriteRoot = join(writeRoot, 'd', 'link')
      mkdirSync(join(realdir, 'pub'), { recursive: true })
      writeFileSync(join(realdir, 'pub', 'secret.txt'), 'secret')
      mkdirSync(join(writeRoot, 'd'), { recursive: true })
      symlinkSync(realdir, linkInWriteRoot)

      const wrapped = await wrapCommandWithSandboxLinux({
        command: 'true',
        needsNetworkRestriction: false,
        readConfig: {
          denyOnly: [linkInWriteRoot, join(realdir, 'pub', 'secret.txt')],
          allowWithinDeny: [join(realdir, 'pub')],
        },
        writeConfig: {
          allowOnly: [writeRoot],
          denyWithinAllow: [join(writeRoot, 'd')],
        },
        mandatoryDenySearchDepth: 1,
      })

      const mask = `--ro-bind /dev/null ${join(realdir, 'pub', 'secret.txt')}`
      const carveOut = `--ro-bind ${join(realdir, 'pub')} ${join(realdir, 'pub')}`
      expect(wrapped).toContain(mask)
      // One tmpfs on the target, and the mask is the last word on the file:
      // no carve-out re-bind after it.
      expect(countMounts(wrapped, '--tmpfs', realdir)).toBe(1)
      expect(wrapped).toContain(carveOut)
      expect(wrapped.lastIndexOf(mask)).toBeGreaterThan(
        wrapped.lastIndexOf(carveOut),
      )
    })

    it('re-binds a literal carve-out written against the target of a denied link', async () => {
      const viaLink = await wrapCommandWithSandboxLinux({
        command: 'true',
        needsNetworkRestriction: false,
        readConfig: {
          denyOnly: [link],
          allowWithinDeny: [join(real, 'public')],
        },
        writeConfig: { allowOnly: [], denyWithinAllow: [] },
      })
      expect(countMounts(viaLink, '--tmpfs', real)).toBeGreaterThan(0)
      expect(viaLink).toContain(
        `--ro-bind ${join(real, 'public')} ${join(real, 'public')}`,
      )
    })

    it('re-binds a carve-out written beneath the link a directory is denied by, at its target', async () => {
      const viaLink = await wrapCommandWithSandboxLinux({
        command: 'true',
        needsNetworkRestriction: false,
        readConfig: {
          denyOnly: [link],
          allowWithinDeny: [join(link, 'public')],
        },
        writeConfig: { allowOnly: [], denyWithinAllow: [] },
      })
      expect(countMounts(viaLink, '--tmpfs', real)).toBeGreaterThan(0)
      expect(viaLink).toContain(
        `--ro-bind ${join(real, 'public')} ${join(real, 'public')}`,
      )
    })

    // denyRead [real] + allowRead [link/public]: the name `public` lives in
    // the denied directory whichever way it is reached, and the bind goes
    // where it is (bwrap refuses a symlink as a destination and, before 0.12,
    // an absolute one anywhere in it).
    function wrapCarveOutThroughOutsideLink(command: string): Promise<string> {
      return wrapCommandWithSandboxLinux({
        command,
        needsNetworkRestriction: false,
        readConfig: {
          denyOnly: [real],
          allowWithinDeny: [join(link, 'public')],
        },
        writeConfig: { allowOnly: [], denyWithinAllow: [] },
      })
    }

    it('re-binds a carve-out written through a symlinked directory outside the denied one, at its target', async () => {
      const wrapped = await wrapCarveOutThroughOutsideLink('true')
      expect(countMounts(wrapped, '--tmpfs', real)).toBeGreaterThan(0)
      expect(wrapped).toContain(
        `--ro-bind ${join(real, 'public')} ${join(real, 'public')}`,
      )
    })

    it.skipIf(!hasBwrap)(
      'serves that carve-out and nothing else of the denied directory',
      async () => {
        const stdout = runBooted(
          await wrapCarveOutThroughOutsideLink(
            `echo BOOTED; cat ${join(link, 'public', 'ok.txt')}; cat ${join(real, 'index.js')} || echo HIDDEN`,
          ),
        )
        expect(stdout).toBe('BOOTED\npublicHIDDEN\n')
      },
    )

    describe('an allowRead that only leads into a denied directory', () => {
      // What an allowRead entry resolves to never decides which deny it
      // carves out of: a sandboxed command with write access to where the
      // entry lives can point it anywhere.

      function wrapAllowReadLinkToDeniedDir(command: string): Promise<string> {
        const home = join(ROOT, 'g1', 'home')
        const proj = join(ROOT, 'g1', 'proj')
        mkdirSync(join(home, '.ssh'), { recursive: true })
        writeFileSync(join(home, '.ssh', 'id_rsa'), 'KEY')
        mkdirSync(proj, { recursive: true })
        ensureLink(join(home, '.ssh'), join(proj, 'docs'))
        return wrapCommandWithSandboxLinux({
          command,
          needsNetworkRestriction: false,
          readConfig: {
            denyOnly: [join(home, '.ssh')],
            allowWithinDeny: [join(proj, 'docs')],
          },
          writeConfig: { allowOnly: [proj], denyWithinAllow: [] },
          mandatoryDenySearchDepth: 1,
        })
      }

      it('does not bind a denied directory back through an allowRead symlink to it', async () => {
        const wrapped = await wrapAllowReadLinkToDeniedDir('true')

        expect(
          countMounts(wrapped, '--tmpfs', join(ROOT, 'g1', 'home', '.ssh')),
        ).toBeGreaterThan(0)
        expect(wrapped).not.toContain(
          `--ro-bind ${join(ROOT, 'g1', 'proj', 'docs')}`,
        )
      })

      it.skipIf(!hasBwrap)(
        'serves nothing of that denied directory under either name',
        async () => {
          const home = join(ROOT, 'g1', 'home')
          const proj = join(ROOT, 'g1', 'proj')
          const stdout = runBooted(
            await wrapAllowReadLinkToDeniedDir(
              `echo BOOTED; cat ${join(home, '.ssh', 'id_rsa')} ${join(proj, 'docs', 'id_rsa')} || echo HIDDEN`,
            ),
          )
          expect(stdout).not.toContain('KEY')
          expect(stdout).toContain('HIDDEN')
        },
      )

      function wrapAllowReadLinkToDeniedFile(command: string): Promise<string> {
        const aws = join(ROOT, 'g2', 'aws')
        const proj = join(ROOT, 'g2', 'proj')
        mkdirSync(aws, { recursive: true })
        writeFileSync(join(aws, 'credentials'), 'CREDS')
        mkdirSync(proj, { recursive: true })
        ensureLink(join(aws, 'credentials'), join(proj, 'cfg.json'))
        return wrapCommandWithSandboxLinux({
          command,
          needsNetworkRestriction: false,
          readConfig: {
            denyOnly: [join(aws, 'credentials')],
            allowWithinDeny: [join(proj, 'cfg.json')],
          },
          writeConfig: { allowOnly: [proj], denyWithinAllow: [] },
          mandatoryDenySearchDepth: 1,
        })
      }

      it('keeps the mask on a denied file an allowRead symlink points at', async () => {
        const wrapped = await wrapAllowReadLinkToDeniedFile('true')

        expect(wrapped).toContain(
          `--ro-bind /dev/null ${join(ROOT, 'g2', 'aws', 'credentials')}`,
        )
      })

      it.skipIf(!hasBwrap)(
        'serves that file through neither name',
        async () => {
          const aws = join(ROOT, 'g2', 'aws')
          const proj = join(ROOT, 'g2', 'proj')
          const stdout = runBooted(
            await wrapAllowReadLinkToDeniedFile(
              `echo BOOTED; cat ${join(aws, 'credentials')} ${join(proj, 'cfg.json')}; echo END`,
            ),
          )
          expect(stdout).not.toContain('CREDS')
          expect(stdout).toContain('END')
        },
      )

      // denyRead **/.env* with allowRead **/.env.example, and
      // sub/.env.example -> ../.env planted: both patterns match the link,
      // which names the link, not .env.
      function wrapPlantedExampleLink(command: string): Promise<string> {
        const proj = join(ROOT, 'g3', 'proj')
        mkdirSync(join(proj, 'sub'), { recursive: true })
        writeFileSync(join(proj, '.env'), 'ENVSECRET')
        writeFileSync(join(proj, '.env.example'), 'EXAMPLE')
        ensureLink(join('..', '.env'), join(proj, 'sub', '.env.example'))
        const allowWithinDeny = expandGlobPattern(join(proj, '**/.env.example'))
        expect(allowWithinDeny).toContain(join(proj, 'sub', '.env.example'))
        return wrapCommandWithSandboxLinux({
          command,
          needsNetworkRestriction: false,
          readConfig: {
            denyOnly: expandReadDenyGlobLinux(
              join(proj, '**/.env*'),
              allowWithinDeny,
            ),
            allowWithinDeny,
          },
          writeConfig: { allowOnly: [proj], denyWithinAllow: [] },
          mandatoryDenySearchDepth: 1,
        })
      }

      it('does not lift a file mask for an allowRead symlink that a pattern also matches', async () => {
        const proj = join(ROOT, 'g3', 'proj')
        const wrapped = await wrapPlantedExampleLink('true')

        expect(wrapped).toContain(`--ro-bind /dev/null ${join(proj, '.env')}`)
        expect(wrapped).not.toContain(`/dev/null ${join(proj, '.env.example')}`)
      })

      it.skipIf(!hasBwrap)(
        'serves the example file and not what the planted link points at',
        async () => {
          const proj = join(ROOT, 'g3', 'proj')
          const stdout = runBooted(
            await wrapPlantedExampleLink(
              `echo BOOTED; cat ${join(proj, '.env.example')}; cat ${join(proj, 'sub', '.env.example')} ${join(proj, '.env')}; echo END`,
            ),
          )
          expect(stdout).toContain('EXAMPLE')
          expect(stdout).not.toContain('ENVSECRET')
        },
      )

      // denyRead [denied, outside/sub] + allowRead [denied/lnk], denied/lnk ->
      // ../outside: bound back at denied/lnk, `outside` would be readable
      // there whatever is denied inside it. It was never hidden by the
      // tmpfs on `denied`, so there is nothing to restore.
      const outsideTreeOrders = [
        ['the denied directory first', 0],
        ['the link spelling first', 1],
      ] as const
      function outsideTreeDenyOnly(order: number): string[] {
        const denied = join(ROOT, 's1', 'D')
        const outside = join(ROOT, 's1', 'e')
        mkdirSync(denied, { recursive: true })
        mkdirSync(join(outside, 'sub'), { recursive: true })
        writeFileSync(join(outside, 'sub', 'secret'), 'secret')
        ensureLink(join('..', 'e'), join(denied, 'lnk'))
        return order === 0
          ? [denied, join(outside, 'sub')]
          : [join(denied, 'lnk', 'sub'), denied]
      }
      function wrapOutsideTree(
        command: string,
        order: number,
      ): Promise<string> {
        const denied = join(ROOT, 's1', 'D')
        return wrapCommandWithSandboxLinux({
          command,
          needsNetworkRestriction: false,
          readConfig: {
            denyOnly: outsideTreeDenyOnly(order),
            allowWithinDeny: [join(denied, 'lnk')],
          },
          writeConfig: { allowOnly: [], denyWithinAllow: [] },
        })
      }

      for (const [orderName, index] of outsideTreeOrders) {
        it(`does not show a tree outside the denied directory under a name inside it, with ${orderName}`, async () => {
          const denied = join(ROOT, 's1', 'D')
          const outside = join(ROOT, 's1', 'e')
          const wrapped = await wrapOutsideTree('true', index)

          expect(countMounts(wrapped, '--tmpfs', denied)).toBeGreaterThan(0)
          expect(
            countMounts(wrapped, '--tmpfs', join(outside, 'sub')),
          ).toBeGreaterThan(0)
          expect(wrapped).not.toContain(`--ro-bind ${join(denied, 'lnk')}`)
        })

        it.skipIf(!hasBwrap)(
          `serves nothing of that tree under either name, with ${orderName}`,
          async () => {
            const denied = join(ROOT, 's1', 'D')
            const outside = join(ROOT, 's1', 'e')
            const stdout = runBooted(
              await wrapOutsideTree(
                `echo BOOTED; cat ${join(denied, 'lnk', 'sub', 'secret')} ${join(outside, 'sub', 'secret')} || echo HIDDEN`,
                index,
              ),
            )
            expect(stdout).not.toContain('secret')
            expect(stdout).toContain('HIDDEN')
          },
        )
      }

      // denyRead [target/private, denied] + allowRead [denied/x,
      // denied/x/lnk], denied/x/lnk -> target: denied/x is bound back from
      // the host, live link included, so `target` is reached through it as on
      // the host and target/private stays denied. A bind of denied/x/lnk
      // would land on `target` and bury that deny.
      function wrapLinkInsideCarveOut(command: string): Promise<string> {
        const denied = join(ROOT, 's3', 'D')
        const target = join(ROOT, 's3', 't')
        mkdirSync(join(denied, 'x'), { recursive: true })
        mkdirSync(join(target, 'private'), { recursive: true })
        writeFileSync(join(target, 'f'), 'T')
        writeFileSync(join(target, 'private', 'key'), 'KEY')
        ensureLink(join('..', '..', 't'), join(denied, 'x', 'lnk'))
        return wrapCommandWithSandboxLinux({
          command,
          needsNetworkRestriction: false,
          readConfig: {
            denyOnly: [join(target, 'private'), denied],
            allowWithinDeny: [join(denied, 'x'), join(denied, 'x', 'lnk')],
          },
          writeConfig: { allowOnly: [], denyWithinAllow: [] },
        })
      }

      it('leaves a link inside a carve-out to lead where it leads, without a mount of its own', async () => {
        const wrapped = await wrapLinkInsideCarveOut('true')

        expect(wrapped).not.toContain(
          `--ro-bind ${join(ROOT, 's3', 'D', 'x', 'lnk')}`,
        )
      })

      it.skipIf(!hasBwrap)(
        'reads through that link as on the host, and still denies what it leads into',
        async () => {
          const denied = join(ROOT, 's3', 'D')
          const target = join(ROOT, 's3', 't')
          const stdout = runBooted(
            await wrapLinkInsideCarveOut(
              `echo BOOTED; cat ${join(denied, 'x', 'lnk', 'f')}; cat ${join(target, 'private', 'key')} ${join(denied, 'x', 'lnk', 'private', 'key')} || echo HIDDEN`,
            ),
          )
          expect(stdout).toBe('BOOTED\nTHIDDEN\n')
        },
      )
    })

    // l1 -> a/b, a/b/l2 -> t: l1/l2/f is t/f. Mounted where it really is, it
    // is denied under every name, in either order of the two entries.
    function wrapTwoLinkSpellings(
      command: string,
      reversed: boolean,
    ): Promise<string> {
      const caseRoot = join(ROOT, 's7')
      mkdirSync(join(caseRoot, 'a', 'b'), { recursive: true })
      mkdirSync(join(caseRoot, 't'), { recursive: true })
      writeFileSync(join(caseRoot, 't', 'f'), 'FCONTENT')
      ensureLink(join('a', 'b'), join(caseRoot, 'l1'))
      ensureLink(join('..', '..', 't'), join(caseRoot, 'a', 'b', 'l2'))
      const denied = [join(caseRoot, 'l1', 'l2', 'f'), join(caseRoot, 'a', 'b')]
      return wrapCommandWithSandboxLinux({
        command,
        needsNetworkRestriction: false,
        readConfig: {
          denyOnly: reversed ? [...denied].reverse() : denied,
          allowWithinDeny: [join(caseRoot, 'a', 'b', 'l2')],
        },
        writeConfig: { allowOnly: [], denyWithinAllow: [] },
      })
    }

    for (const reversed of [false, true]) {
      const order = reversed ? 'the directory first' : 'the file first'

      it(`denies a path the same way whatever spelling names it, with ${order}`, async () => {
        const caseRoot = join(ROOT, 's7')
        const wrapped = await wrapTwoLinkSpellings('true', reversed)

        expect(wrapped).toContain(
          `--ro-bind /dev/null ${join(caseRoot, 't', 'f')}`,
        )
        expect(
          countMounts(wrapped, '--tmpfs', join(caseRoot, 'a', 'b')),
        ).toBeGreaterThan(0)
      })

      it.skipIf(!hasBwrap)(
        `serves that path through neither spelling, with ${order}`,
        async () => {
          const caseRoot = join(ROOT, 's7')
          const stdout = runBooted(
            await wrapTwoLinkSpellings(
              `echo BOOTED; cat ${join(caseRoot, 'l1', 'l2', 'f')} ${join(caseRoot, 't', 'f')}; echo END`,
              reversed,
            ),
          )
          expect(stdout).toBe('BOOTED\nEND\n')
        },
      )
    }

    // x/secrets/latest -> .. (x, an allowed write root): the deny of the link
    // is a deny of x, which the write bind cancels; mounted after x/secrets
    // it would wipe that tmpfs and bind the secrets back.
    function wrapLinkBackUpToWriteRoot(
      command: string,
      reversed: boolean,
    ): Promise<string> {
      const writeRoot = join(ROOT, 's5', 'x')
      mkdirSync(join(writeRoot, 'secrets'), { recursive: true })
      writeFileSync(join(writeRoot, 'secrets', 'key'), 'KEY')
      ensureLink('..', join(writeRoot, 'secrets', 'latest'))
      const denied = [
        join(writeRoot, 'secrets'),
        join(writeRoot, 'secrets', 'latest'),
      ]
      return wrapCommandWithSandboxLinux({
        command,
        needsNetworkRestriction: false,
        readConfig: { denyOnly: reversed ? [...denied].reverse() : denied },
        writeConfig: { allowOnly: [writeRoot], denyWithinAllow: [] },
        mandatoryDenySearchDepth: 1,
      })
    }

    for (const reversed of [false, true]) {
      const order = reversed ? 'the link first' : 'the directory first'

      it(`mounts a directory that a link inside a denied directory leads back up to before that directory, with ${order}`, async () => {
        const writeRoot = join(ROOT, 's5', 'x')
        const wrapped = await wrapLinkBackUpToWriteRoot('true', reversed)

        expect(
          lastIndexOfMount(wrapped, '--tmpfs', join(writeRoot, 'secrets')),
        ).toBeGreaterThan(
          lastIndexOfMount(wrapped, '--bind', writeRoot, writeRoot),
        )
      })

      it.skipIf(!hasBwrap)(
        `hides those secrets from the write root, with ${order}`,
        async () => {
          const writeRoot = join(ROOT, 's5', 'x')
          const stdout = runBooted(
            await wrapLinkBackUpToWriteRoot(
              `echo BOOTED; cat ${join(writeRoot, 'secrets', 'key')} || echo HIDDEN`,
              reversed,
            ),
          )
          expect(stdout).toBe('BOOTED\nHIDDEN\n')
        },
      )
    }

    // denied/L -> ../T with denyRead [denied, denied/L/sub] and allowWrite
    // [T/sub/writable]: T/sub/writable is bound back once, where it is, under
    // the deny binds and masks that protect it. Bound a second time beneath
    // denied/L it would be writable there with none of them on top.
    function wrapWritePathUnderLink(command: string): Promise<string> {
      const denied = join(ROOT, 's6', 'D')
      const target = join(ROOT, 's6', 'T')
      const writable = join(target, 'sub', 'w')
      mkdirSync(denied, { recursive: true })
      mkdirSync(join(writable, '.git', 'hooks'), { recursive: true })
      writeFileSync(join(writable, '.env'), 'ENV')
      ensureLink(join('..', 'T'), join(denied, 'L'))
      return wrapCommandWithSandboxLinux({
        command,
        needsNetworkRestriction: false,
        readConfig: {
          denyOnly: [denied, join(denied, 'L', 'sub'), join(writable, '.env')],
          allowWithinDeny: [join(denied, 'L')],
        },
        writeConfig: {
          allowOnly: [writable],
          denyWithinAllow: [join(writable, '.git', 'hooks')],
        },
        mandatoryDenySearchDepth: 1,
      })
    }

    it('binds an allowed write path back only where it really is', async () => {
      const writable = join(ROOT, 's6', 'T', 'sub', 'w')
      const wrapped = await wrapWritePathUnderLink('true')

      const binds = wrapped
        .split(' --')
        .filter(op => op.startsWith(`bind ${writable} `))
        .map(op => op.trim())
      expect(binds.length).toBeGreaterThan(0)
      expect([...new Set(binds)]).toEqual([`bind ${writable} ${writable}`])
    })

    it.skipIf(!hasBwrap)(
      'writes to that path through neither name, and reads its denied file through neither',
      async () => {
        const denied = join(ROOT, 's6', 'D')
        const writable = join(ROOT, 's6', 'T', 'sub', 'w')
        const stdout = runBooted(
          await wrapWritePathUnderLink(
            `echo BOOTED; touch ${join(denied, 'L', 'sub', 'w', '.git', 'hooks', 'pre-commit')} ${join(writable, '.git', 'hooks', 'pre-commit')} && echo WRITTEN; cat ${join(denied, 'L', 'sub', 'w', '.env')} ${join(writable, '.env')} || echo HIDDEN`,
          ),
        )
        expect(stdout).not.toContain('WRITTEN')
        expect(stdout).not.toContain('ENV')
        expect(stdout).toContain('HIDDEN')
      },
    )

    // ln -> real/secretdir and real/secretdir/out -> elsewhere/hooks:
    // denyWrite [real/secretdir/out] protects elsewhere/hooks, which the
    // tmpfs on real/secretdir does not hide.
    function wrapDenyWriteThroughDeniedDir(command: string): Promise<string> {
      const caseRoot = join(ROOT, 's8', 'root')
      const hooks = join(caseRoot, 'elsewhere', 'hooks')
      mkdirSync(join(caseRoot, 'real', 'secretdir'), { recursive: true })
      mkdirSync(hooks, { recursive: true })
      ensureLink(join(caseRoot, 'real', 'secretdir'), join(caseRoot, 'ln'))
      ensureLink(hooks, join(caseRoot, 'real', 'secretdir', 'out'))
      return wrapCommandWithSandboxLinux({
        command,
        needsNetworkRestriction: false,
        readConfig: { denyOnly: [join(caseRoot, 'ln')] },
        writeConfig: {
          allowOnly: [caseRoot],
          denyWithinAllow: [join(caseRoot, 'real', 'secretdir', 'out')],
        },
        mandatoryDenySearchDepth: 1,
      })
    }

    it('keeps a denyWrite bind whose path only passes through a read-denied directory', async () => {
      const caseRoot = join(ROOT, 's8', 'root')
      const hooks = join(caseRoot, 'elsewhere', 'hooks')
      const wrapped = await wrapDenyWriteThroughDeniedDir('true')

      expect(
        countMounts(wrapped, '--tmpfs', join(caseRoot, 'real', 'secretdir')),
      ).toBeGreaterThan(0)
      expect(wrapped).toContain(`--ro-bind ${hooks} ${hooks}`)
    })

    it.skipIf(!hasBwrap)('refuses the write that bind protects', async () => {
      const hooks = join(ROOT, 's8', 'root', 'elsewhere', 'hooks')
      const stdout = runBooted(
        await wrapDenyWriteThroughDeniedDir(
          `echo BOOTED; touch ${join(hooks, 'x')} && echo WRITTEN || echo DENIED`,
        ),
      )
      expect(stdout).toBe('BOOTED\nDENIED\n')
    })

    it('re-applies one mask for a file denied through a symlinked directory', async () => {
      // writeRoot/lnk -> real, denyRead [writeRoot/lnk/secret], denyWrite
      // [writeRoot]: the mask sits on writeRoot/real/secret alone, so the
      // bind of writeRoot re-exposes one file and one mask goes back (a
      // second on the same inode aborts bwrap before 0.5).
      const writeRoot = join(ROOT, 's10', 'W')
      mkdirSync(join(writeRoot, 'real'), { recursive: true })
      writeFileSync(join(writeRoot, 'real', 'secret'), 'S')
      symlinkSync('real', join(writeRoot, 'lnk'))
      const wrapped = await wrapCommandWithSandboxLinux({
        command: 'true',
        needsNetworkRestriction: false,
        readConfig: { denyOnly: [join(writeRoot, 'lnk', 'secret')] },
        writeConfig: { allowOnly: [writeRoot], denyWithinAllow: [writeRoot] },
        mandatoryDenySearchDepth: 1,
      })
      const mask = `--ro-bind /dev/null ${join(writeRoot, 'real', 'secret')}`
      const afterDenyBind = wrapped.slice(
        wrapped.lastIndexOf(`--ro-bind ${writeRoot} ${writeRoot}`),
      )
      expect(afterDenyBind.split(mask)).toHaveLength(2)
      expect(wrapped).not.toContain(
        `/dev/null ${join(writeRoot, 'lnk', 'secret')}`,
      )
    })

    // denyRead **/.env with the working directory an allowed write root and
    // mode 0311 (what a sandboxed command can leave behind): the .env files
    // beneath it cannot be enumerated, so the directory is denied whole, and
    // binding the write root back over that tmpfs would show every one of
    // them unmasked.
    function unlistableCwd(): string {
      const cwd = join(ROOT, 's11', 'cwd')
      mkdirSync(join(cwd, 'svc'), { recursive: true })
      writeFileSync(join(cwd, '.env'), 'ENV1')
      writeFileSync(join(cwd, 'svc', '.env'), 'ENV2')
      chmodSync(cwd, 0o311)
      return cwd
    }
    async function wrapUnlistableCwd(command: string): Promise<string> {
      const cwd = unlistableCwd()
      const unlistableDenyDirs = new Set<string>()
      const denyOnly = expandReadDenyGlobLinux(
        join(cwd, '**/.env'),
        [cwd],
        unlistableDenyDirs,
      )
      expect(denyOnly).toEqual([cwd])
      expect([...unlistableDenyDirs]).toEqual([cwd])
      return wrapCommandWithSandboxLinux({
        command,
        needsNetworkRestriction: false,
        readConfig: {
          denyOnly,
          unlistableDenyDirs: [...unlistableDenyDirs],
        },
        writeConfig: { allowOnly: [cwd], denyWithinAllow: [] },
        mandatoryDenySearchDepth: 1,
      })
    }

    it.if(process.getuid?.() !== 0)(
      'restores nothing beneath a directory the glob expansion could not list',
      async () => {
        try {
          const cwd = join(ROOT, 's11', 'cwd')
          const wrapped = await wrapUnlistableCwd('true')

          expect(
            wrapped.slice(wrapped.indexOf(`--tmpfs ${cwd} `)),
          ).not.toContain(`--bind ${cwd} ${cwd}`)
        } finally {
          chmodSync(join(ROOT, 's11', 'cwd'), 0o755)
        }
      },
    )

    it.if(process.getuid?.() !== 0 && hasBwrap)(
      'serves none of the files beneath it',
      async () => {
        try {
          const cwd = join(ROOT, 's11', 'cwd')
          const stdout = runBooted(
            await wrapUnlistableCwd(
              `echo BOOTED; cat ${join(cwd, '.env')} ${join(cwd, 'svc', '.env')} || echo HIDDEN`,
            ),
          )
          expect(stdout).not.toContain('ENV1')
          expect(stdout).not.toContain('ENV2')
          expect(stdout).toContain('HIDDEN')
        } finally {
          chmodSync(join(ROOT, 's11', 'cwd'), 0o755)
        }
      },
    )

    it.if(process.getuid?.() !== 0)(
      'keeps the carve-outs of a literal deny of a directory it cannot list',
      async () => {
        // The same directory, denied literally: nothing was enumerated under
        // it, so nothing is missing from the deny either, and the allowed
        // write path inside it is bound back as on any other denied
        // directory. Without that bind the build writes into the tmpfs and
        // loses its output when the command exits.
        const cwd = join(ROOT, 's15', 'cwd')
        const out = join(cwd, 'out')
        mkdirSync(out, { recursive: true })
        writeFileSync(join(cwd, '.env'), 'ENV')
        chmodSync(cwd, 0o311)
        try {
          const wrapped = await wrapCommandWithSandboxLinux({
            command: 'true',
            needsNetworkRestriction: false,
            readConfig: { denyOnly: [cwd] },
            writeConfig: { allowOnly: [out], denyWithinAllow: [] },
            mandatoryDenySearchDepth: 1,
          })

          const tmpfs = wrapped.lastIndexOf(`--tmpfs ${cwd} `)
          expect(tmpfs).toBeGreaterThan(-1)
          expect(
            wrapped.indexOf(`--bind ${out} ${out} `, tmpfs),
          ).toBeGreaterThan(tmpfs)
        } finally {
          chmodSync(cwd, 0o755)
        }
      },
    )

    // proj/pkg is readable but not searchable (0600): its entries can be
    // listed, so the pattern matches pkg/.env and finds pkg/build, but
    // neither can be stat'ed. Skipped as absent, both would be readable once
    // the mode is put back.
    async function wrapUninspectableEntries(command: string): Promise<string> {
      const proj = join(ROOT, 's12', 'proj')
      const pkg = join(proj, 'pkg')
      mkdirSync(join(pkg, 'build'), { recursive: true })
      writeFileSync(join(pkg, '.env'), 'ENV')
      writeFileSync(join(pkg, 'build', 'o'), 'OUT')
      chmodSync(pkg, 0o600)
      const denyOnly = [
        ...expandReadDenyGlobLinux(join(proj, '**/build/**'), [proj]),
        ...expandReadDenyGlobLinux(join(proj, '**/.env'), [proj]),
      ]
      expect(denyOnly).toContain(join(pkg, '.env'))
      return wrapCommandWithSandboxLinux({
        command,
        needsNetworkRestriction: false,
        readConfig: { denyOnly },
        writeConfig: { allowOnly: [proj], denyWithinAllow: [] },
        mandatoryDenySearchDepth: 1,
      })
    }

    it.if(process.getuid?.() !== 0)(
      'hides the nearest directory it can inspect when an entry cannot be looked at',
      async () => {
        const pkg = join(ROOT, 's12', 'proj', 'pkg')
        try {
          expect(
            countMounts(await wrapUninspectableEntries('true'), '--tmpfs', pkg),
          ).toBeGreaterThan(0)
        } finally {
          chmodSync(pkg, 0o755)
        }
      },
    )

    it.if(process.getuid?.() !== 0 && hasBwrap)(
      'serves neither entry once the command puts the mode back',
      async () => {
        const pkg = join(ROOT, 's12', 'proj', 'pkg')
        try {
          const stdout = runBooted(
            await wrapUninspectableEntries(
              `echo BOOTED; chmod 755 ${pkg}; cat ${join(pkg, '.env')} ${join(pkg, 'build', 'o')} || echo HIDDEN`,
            ),
          )
          expect(stdout).not.toContain('ENV')
          expect(stdout).not.toContain('OUT')
          expect(stdout).toContain('HIDDEN')
        } finally {
          chmodSync(pkg, 0o755)
        }
      },
    )

    /**
     * A matched link whose target is there but cannot be looked at: the
     * shape a sandboxed command leaves behind by making the target's
     * directory unsearchable, which it can undo from inside the next
     * sandbox. Dropped as "does not resolve", the deny would vanish for
     * exactly that command. EACCES is injected through fs spies, since a
     * root container sees no real one; the sandboxed command itself then
     * runs against the real filesystem.
     */
    async function wrapUninspectableLinkTarget(
      command: string,
    ): Promise<{ wrapped: string; certs: string; link: string }> {
      const caseRootDir = join(ROOT, 's16')
      const certs = join(caseRootDir, 'certs')
      const secret = join(caseRootDir, 'secret')
      const link = join(certs, 'k')
      mkdirSync(certs, { recursive: true })
      mkdirSync(secret, { recursive: true })
      writeFileSync(join(secret, 'k'), 'KEYBYTES')
      ensureLink(join('..', 'secret', 'k'), link)

      const unreachable = (p: string): boolean =>
        p === link || p.startsWith(secret + '/') || p === secret
      const eacces = (p: fs.PathLike): never => {
        throw Object.assign(new Error(`EACCES: permission denied, '${p}'`), {
          code: 'EACCES',
        })
      }
      const realStat = fs.statSync
      const realRealpath = fs.realpathSync
      const spies = [
        spyOn(fs, 'statSync').mockImplementation(((
          p: fs.PathLike,
          ...rest: unknown[]
        ) =>
          unreachable(String(p))
            ? eacces(p)
            : (realStat as (...a: unknown[]) => unknown)(
                p,
                ...rest,
              )) as typeof fs.statSync),
        spyOn(fs, 'realpathSync').mockImplementation(((
          p: fs.PathLike,
          ...rest: unknown[]
        ) =>
          unreachable(String(p))
            ? eacces(p)
            : (realRealpath as (...a: unknown[]) => unknown)(
                p,
                ...rest,
              )) as typeof fs.realpathSync),
      ]
      try {
        const wrapped = await wrapCommandWithSandboxLinux({
          command,
          needsNetworkRestriction: false,
          readConfig: {
            denyOnly: expandReadDenyGlobLinux(join(certs, '*'), []),
          },
          writeConfig: { allowOnly: [caseRootDir], denyWithinAllow: [] },
          mandatoryDenySearchDepth: 1,
        })
        return { wrapped, certs, link }
      } finally {
        for (const spy of spies) spy.mockRestore()
      }
    }

    it('hides what holds a matched link whose target cannot be looked at', async () => {
      const { wrapped, certs, link } = await wrapUninspectableLinkTarget('true')

      // The deny reaches the mount loop under the link's own spelling, where
      // the stand-in rule hides the nearest directory that can be inspected.
      expect(countMounts(wrapped, '--tmpfs', certs)).toBeGreaterThan(0)
      expect(countMounts(wrapped, '--tmpfs', link)).toBe(0)
    })

    it.skipIf(!hasBwrap)(
      'serves that link nothing, even once the command can look at the target again',
      async () => {
        const { wrapped, link } = await wrapUninspectableLinkTarget(
          `echo BOOTED; cat ${join(ROOT, 's16', 'certs', 'k')} || echo HIDDEN; ls ${join(ROOT, 's16', 'certs')}`,
        )
        const stdout = runBooted(wrapped)

        expect(stdout).not.toContain('KEYBYTES')
        expect(stdout).toContain('HIDDEN')
        expect(link).toBe(join(ROOT, 's16', 'certs', 'k'))
      },
    )

    // A sandboxed command with write access under the pattern's base can
    // plant a link to the root; a mount on it, or on what it resolves to,
    // would stop every later command. The directory holding it is hidden
    // instead, by the same rule as an entry that cannot be inspected.
    function wrapLinkToRoot(command: string): Promise<string> {
      const proj = join(ROOT, 's13', 'proj')
      mkdirSync(join(proj, 'img'), { recursive: true })
      writeFileSync(join(proj, 'img', 'note.txt'), 'NOTE')
      ensureLink('/', join(proj, 'img', 'build'))
      return wrapCommandWithSandboxLinux({
        command,
        needsNetworkRestriction: false,
        readConfig: {
          denyOnly: [
            ...expandReadDenyGlobLinux(join(proj, '**/build/**'), []),
            // Named literally, the loop applies the same rule.
            join(proj, 'img', 'build'),
          ],
        },
        writeConfig: { allowOnly: [], denyWithinAllow: [] },
        allowAllUnixSockets: true,
      })
    }

    it('hides the directory holding a matched link to / instead of the root', async () => {
      const img = join(ROOT, 's13', 'proj', 'img')
      const wrapped = await wrapLinkToRoot('true')

      expect(countMounts(wrapped, '--tmpfs', img)).toBeGreaterThan(0)
      expect(countMounts(wrapped, '--tmpfs', join(img, 'build'))).toBe(0)
      // A --tmpfs / would wipe every mount before it and boot the command on
      // an empty tree, so it is never emitted, whatever a link resolves to.
      expect(countMounts(wrapped, '--tmpfs', '/')).toBe(0)
    })

    it('keeps a link to / out of the read-deny prediction', async () => {
      // The prediction says where the loop will mount a tmpfs, and every
      // covering deny directory lies under '/'. Predicted there, no deny
      // stub could be skipped anywhere on the host, and a write-denied
      // checkout would refuse to start: bubblewrap cannot create a stub's
      // mount point inside a read-only bind. A link to the root is predicted
      // at the directory holding it, where the loop mounts it.
      const work = join(ROOT, 's17', 'work')
      const proj = join(work, 'proj')
      mkdirSync(join(proj, 'img'), { recursive: true })
      ensureLink('/', join(proj, 'img', 'build'))

      const wrapped = await wrapCommandWithSandboxLinux({
        command: 'true',
        needsNetworkRestriction: false,
        readConfig: { denyOnly: [join(proj, 'img', 'build')] },
        writeConfig: {
          allowOnly: [work],
          denyWithinAllow: [proj, join(proj, '.claude', 'settings.json')],
        },
        mandatoryDenySearchDepth: 1,
      })

      expect(
        countMounts(wrapped, '--tmpfs', join(proj, 'img')),
      ).toBeGreaterThan(0)
      expect(countMounts(wrapped, '--tmpfs', '/')).toBe(0)
      // The absent deny path under the read-only bind of proj keeps no stub.
      expect(
        wrapped
          .split(' --')
          .filter(op => op.includes(` ${join(proj, '.claude')}`)),
      ).toEqual([])
    })

    it.skipIf(!hasBwrap)('starts, with that directory hidden', async () => {
      const img = join(ROOT, 's13', 'proj', 'img')
      const stdout = runBooted(
        await wrapLinkToRoot(
          `echo BOOTED; cat ${join(img, 'note.txt')} || echo HIDDEN; ls /`,
        ),
      )
      expect(stdout).not.toContain('NOTE')
      expect(stdout).toContain('HIDDEN')
      // The root itself is untouched: the command can still list it.
      expect(stdout).toContain('usr')
    })

    // denyWrite [proj, proj/.claude/settings.json (absent)] + denyRead
    // proj/**/build/**: collapsed, the pattern is a tmpfs beneath the
    // write-denied directory. The absent deny path is uncreatable under
    // proj's read-only bind either way, and a stub for it would have bwrap
    // create a mount point inside that bind and abort.
    async function wrapWriteDeniedCheckout(command: string): Promise<string> {
      const work = join(ROOT, 's14', 'work')
      const proj = join(work, 'proj')
      mkdirSync(join(proj, 'pkg', 'build'), { recursive: true })
      writeFileSync(join(proj, 'pkg', 'build', '1.out'), 'OUT')
      const cwd = process.cwd()
      process.chdir(proj)
      try {
        return await wrapCommandWithSandboxLinux({
          command,
          needsNetworkRestriction: false,
          readConfig: {
            denyOnly: expandReadDenyGlobLinux(join(proj, '**/build/**'), [
              work,
            ]),
          },
          writeConfig: {
            allowOnly: [work],
            denyWithinAllow: [proj, join(proj, '.claude', 'settings.json')],
          },
          mandatoryDenySearchDepth: 1,
        })
      } finally {
        process.chdir(cwd)
      }
    }

    it('keeps no deny stub in a write-denied checkout with a denyRead pattern matching a directory inside it', async () => {
      const proj = join(ROOT, 's14', 'work', 'proj')
      const wrapped = await wrapWriteDeniedCheckout('true')

      const projBind = lastIndexOfMount(wrapped, '--ro-bind', proj, proj)
      expect(projBind).toBeGreaterThan(-1)
      // No stub: nothing is mounted at or beneath proj/.claude.
      expect(
        wrapped
          .slice(0, wrapped.indexOf(' --dev '))
          .split(' --')
          .filter(op => op.includes(` ${join(proj, '.claude')}`)),
      ).toEqual([])
      expect(
        lastIndexOfMount(wrapped, '--tmpfs', join(proj, 'pkg', 'build')),
      ).toBeGreaterThan(projBind)
    })

    it.skipIf(!hasBwrap)(
      'starts such a checkout, with the directory hidden and the absent deny path uncreatable',
      async () => {
        const proj = join(ROOT, 's14', 'work', 'proj')
        const stdout = runBooted(
          await wrapWriteDeniedCheckout(
            `echo BOOTED; mkdir ${join(proj, '.claude')} || echo UNCREATABLE; cat ${join(proj, 'pkg', 'build', '1.out')} || echo HIDDEN`,
          ),
        )
        expect(stdout).toBe('BOOTED\nUNCREATABLE\nHIDDEN\n')
      },
    )

    // denyRead [cfg, cfg/token], cfg/token -> ../secrets/token: the link
    // vanishes with cfg's tmpfs, but the file it named is the target, which
    // stays reachable by its own name and must be masked there.
    function wrapFileLinkBeneathDeniedDir(command: string): Promise<string> {
      const cfg = join(ROOT, 's9', 'cfg')
      const secrets = join(ROOT, 's9', 'secrets')
      mkdirSync(cfg, { recursive: true })
      mkdirSync(secrets, { recursive: true })
      writeFileSync(join(secrets, 'token'), 'TOKEN')
      ensureLink(join('..', 'secrets', 'token'), join(cfg, 'token'))
      return wrapCommandWithSandboxLinux({
        command,
        needsNetworkRestriction: false,
        readConfig: { denyOnly: [cfg, join(cfg, 'token')] },
        writeConfig: { allowOnly: [], denyWithinAllow: [] },
      })
    }

    it('still masks the target of a file symlink listed beneath a denied directory', async () => {
      const secrets = join(ROOT, 's9', 'secrets')
      const wrapped = await wrapFileLinkBeneathDeniedDir('true')

      expect(wrapped).toContain(`--ro-bind /dev/null ${join(secrets, 'token')}`)
    })

    it.skipIf(!hasBwrap)(
      'serves that target masked under its own name',
      async () => {
        const secrets = join(ROOT, 's9', 'secrets')
        const stdout = runBooted(
          await wrapFileLinkBeneathDeniedDir(
            `echo BOOTED; cat ${join(secrets, 'token')}; echo END`,
          ),
        )
        expect(stdout).not.toContain('TOKEN')
        expect(stdout).toContain('END')
      },
    )

    describe('a directory deny plus per-file entries beneath it', () => {
      let big: string
      let keys: string[]
      beforeAll(() => {
        big = join(ROOT, 'big')
        mkdirSync(join(big, 'keep'), { recursive: true })
        keys = ['a.key', 'b.key', 'keep/c.key'].map(k => join(big, k))
        for (const k of keys) writeFileSync(k, '')
      })

      it('costs one tmpfs', async () => {
        const collapsed = await wrapCommandWithSandboxLinux({
          command: 'true',
          needsNetworkRestriction: false,
          readConfig: { denyOnly: [big, ...keys] },
          writeConfig: { allowOnly: [], denyWithinAllow: [] },
        })
        expect(countMounts(collapsed, '--tmpfs', big)).toBe(1)
        expect(collapsed).not.toContain(`/dev/null ${big}/`)
      })

      it('keeps the masks beneath a carve-out', async () => {
        const carved = await wrapCommandWithSandboxLinux({
          command: 'true',
          needsNetworkRestriction: false,
          readConfig: {
            denyOnly: [big, ...keys],
            allowWithinDeny: [join(big, 'keep')],
          },
          writeConfig: { allowOnly: [], denyWithinAllow: [] },
        })
        expect(carved).toContain(
          `--ro-bind /dev/null ${join(big, 'keep', 'c.key')}`,
        )
        expect(carved).not.toContain(`/dev/null ${join(big, 'a.key')}`)
      })
    })
  },
)

describe.if(isLinux)('expandReadDenyGlobLinux (filesystem)', () => {
  let ROOT: string
  const PKGS = ['a', 'b', 'c']

  beforeAll(() => {
    ROOT = realpathSync(mkdtempSync(join(tmpdir(), 'deny-glob-collapse-')))
    // pkg/{a,b,c}/build/{1..5}.out plus a nested dir and a source file each
    for (const pkg of PKGS) {
      const build = join(ROOT, 'pkg', pkg, 'build')
      mkdirSync(join(build, 'nested'), { recursive: true })
      for (let i = 1; i <= 5; i++) writeFileSync(join(build, `${i}.out`), '')
      writeFileSync(join(build, 'nested', 'deep.out'), '')
      writeFileSync(join(ROOT, 'pkg', pkg, 'index.ts'), '')
    }
    // A FILE named build must not be swept up by the directory form.
    writeFileSync(join(ROOT, 'pkg', 'build'), '')
    // Something for an allowRead carve-out to re-expose.
    mkdirSync(join(ROOT, 'pkg', 'a', 'build', 'public'))
    writeFileSync(join(ROOT, 'pkg', 'a', 'build', 'public', 'ok.txt'), '')
  })

  afterAll(() => {
    rmSync(ROOT, { recursive: true, force: true })
  })

  it('collapses <root>/**/build/** to one mount per build directory', () => {
    const pattern = join(ROOT, '**/build/**')
    expect(expandGlobPattern(pattern).length).toBeGreaterThanOrEqual(15)

    const mounts = expandReadDenyGlobLinux(pattern, [])

    expect(mounts).toEqual(PKGS.map(pkg => join(ROOT, 'pkg', pkg, 'build')))
  })

  it('keeps per-entry mounts under an allowRead carve-out inside a collapsed dir', () => {
    const pattern = join(ROOT, '**/build/**')
    const carveOut = join(ROOT, 'pkg', 'a', 'build', 'public')

    const mounts = expandReadDenyGlobLinux(pattern, [carveOut])

    for (const pkg of PKGS) {
      expect(mounts).toContain(join(ROOT, 'pkg', pkg, 'build'))
    }
    expect(mounts).not.toContain(join(ROOT, 'pkg', 'a', 'build', '1.out'))
    expect(mounts).not.toContain(join(ROOT, 'pkg', 'b', 'build', 'nested'))
    // What the carve-out binds back keeps its own masks.
    expect(mounts).toContain(carveOut)
    expect(mounts).toContain(join(carveOut, 'ok.txt'))
  })

  it('normalizes an allowRead carve-out spelling before collapsing against it', async () => {
    // The trailing slash is stripped before the collapse compares, so the
    // carve-out still keeps the file's own mask beneath the build tmpfs.
    const carveOut = join(ROOT, 'pkg', 'a', 'build', 'public')
    try {
      const wrapped = await SandboxManager.wrapWithSandbox(
        'echo hello',
        undefined,
        {
          filesystem: {
            denyRead: [join(ROOT, '**/build/**')],
            allowRead: [carveOut + '/'],
            allowWrite: [],
            denyWrite: [],
          },
        },
      )

      expect(
        countMounts(wrapped, '--tmpfs', join(ROOT, 'pkg', 'a', 'build')),
      ).toBeGreaterThan(0)
      expect(wrapped).toContain(
        `--ro-bind /dev/null ${join(carveOut, 'ok.txt')}`,
      )
      expect(wrapped).not.toContain(
        `--ro-bind /dev/null ${join(ROOT, 'pkg', 'b', 'build')}/`,
      )
    } finally {
      await SandboxManager.reset()
    }
  })

  it('seeds the ancestor pins from a collapsed directory', async () => {
    // Every tmpfs the collapse adds is an ordinary read-deny unit, so the
    // directories between it and the allowed write root are pinned: the
    // package directory above a collapsed build/ cannot be renamed aside to
    // strip the deny off it.
    const pkgDir = join(ROOT, 'pkg', 'a')
    const build = join(pkgDir, 'build')
    const wrapped = await wrapCommandWithSandboxLinux({
      command: 'echo hello',
      needsNetworkRestriction: false,
      readConfig: {
        denyOnly: expandReadDenyGlobLinux(join(ROOT, '**/build/**'), []),
        allowWithinDeny: [],
      },
      writeConfig: { allowOnly: [ROOT], denyWithinAllow: [] },
    })

    const pin = `--ro-bind ${pkgDir} ${pkgDir}`
    expect(wrapped).toContain(pin)
    // Beneath the write root's own bind, and so beneath the tmpfs too.
    expect(wrapped.indexOf(pin)).toBeLessThan(
      wrapped.indexOf(`--bind ${ROOT} ${ROOT}`),
    )
    expect(countMounts(wrapped, '--tmpfs', build)).toBeGreaterThan(0)
  })

  it.skipIf(!bwrapCanNamespace())(
    'refuses to rename the package directory above a collapsed build directory',
    async () => {
      const pkgDir = join(ROOT, 'pkg', 'b')
      const wrapped = await wrapCommandWithSandboxLinux({
        command: `sh -c 'echo BOOTED; mv ${pkgDir} ${pkgDir}-moved 2>&1; echo DONE'`,
        needsNetworkRestriction: false,
        readConfig: {
          denyOnly: expandReadDenyGlobLinux(join(ROOT, '**/build/**'), []),
          allowWithinDeny: [],
        },
        writeConfig: { allowOnly: [ROOT], denyWithinAllow: [] },
      })
      const result = spawnSync(wrapped, {
        shell: true,
        encoding: 'utf8',
        timeout: 15000,
      })

      expect(result.stderr ?? '').not.toContain('bwrap:')
      expect(result.stdout).toContain('BOOTED')
      expect(result.stdout).toContain('DONE')
      expect(result.stdout).toMatch(/busy/i)
      expect(existsSync(`${pkgDir}-moved`)).toBe(false)
    },
  )

  it('restores a write path read-only when a write deny inside a collapsed directory is dropped', async () => {
    // The collapsed tmpfs hides the write deny's own destination, so that
    // bind is dropped rather than re-exposing the read-denied directory
    // around it — and the allowed write path the tmpfs restored beneath that
    // destination comes back read-only, where the deny leaves it.
    const build = join(ROOT, 'pkg', 'c', 'build')
    const denied = join(build, 'nested')
    const writable = join(denied, 'out')
    mkdirSync(writable, { recursive: true })
    const wrapped = await wrapCommandWithSandboxLinux({
      command: 'echo hello',
      needsNetworkRestriction: false,
      readConfig: {
        denyOnly: expandReadDenyGlobLinux(join(ROOT, '**/build/**'), []),
        allowWithinDeny: [],
      },
      writeConfig: {
        allowOnly: [ROOT, writable],
        denyWithinAllow: [denied],
      },
    })

    const tmpfs = wrapped.lastIndexOf(`--tmpfs ${build} `)
    expect(tmpfs).toBeGreaterThan(-1)
    // The deny's own bind is dropped (its ancestor pin, spelled the same,
    // sits beneath the write root's bind, so only what follows the tmpfs
    // counts).
    expect(wrapped.indexOf(`--ro-bind ${denied} ${denied}`, tmpfs)).toBe(-1)
    // The tmpfs put the write path back writable; the dropped bind puts it
    // back read-only on top, which is where the deny leaves it.
    const writableBind = wrapped.indexOf(
      `--bind ${writable} ${writable}`,
      tmpfs,
    )
    const readOnlyRestore = wrapped.lastIndexOf(
      `--ro-bind ${writable} ${writable}`,
    )
    expect(writableBind).toBeGreaterThan(tmpfs)
    expect(readOnlyRestore).toBeGreaterThan(writableBind)
  })

  it('leaves a masked file inside a collapsed directory to its mask', async () => {
    // The dropped write-deny bind restores what the tmpfs put back beneath
    // it, but never a masked file: binding the real file read-only there
    // would land above its mask and serve the real bytes.
    const build = join(ROOT, 'pkg', 'a', 'build')
    const secret = join(build, 'cred.json')
    writeFileSync(secret, 'REAL-CREDENTIAL\n')
    const store = mkdtempSync(join(tmpdir(), 'deny-glob-store-'))
    const fake = join(store, 'cred.json.fake')
    writeFileSync(fake, 'SENTINEL\n')
    try {
      const wrapped = await wrapCommandWithSandboxLinux({
        command: 'echo hello',
        needsNetworkRestriction: false,
        readConfig: {
          denyOnly: expandReadDenyGlobLinux(join(ROOT, '**/build/**'), [
            secret,
          ]),
          allowWithinDeny: [],
        },
        writeConfig: { allowOnly: [ROOT, secret], denyWithinAllow: [build] },
        maskedFileBinds: [{ realPath: secret, fakePath: fake }],
        maskedFileStoreDir: store,
      })

      expect(wrapped).toContain(`--ro-bind ${fake} ${secret}`)
      expect(wrapped).not.toContain(`--ro-bind ${secret} ${secret}`)
      const mask = wrapped.lastIndexOf(`--ro-bind ${fake} ${secret}`)
      expect(wrapped.indexOf(`--bind ${secret} ${secret}`, mask)).toBe(-1)
    } finally {
      rmSync(store, { recursive: true, force: true })
      rmSync(secret, { force: true })
    }
  })

  it('leaves a pattern without a trailing /** to collapse only among its own matches', () => {
    // **/*.out matches files only: nothing to collapse under.
    const pattern = join(ROOT, '**/*.out')
    const mounts = expandReadDenyGlobLinux(pattern, [])
    expect(mounts.length).toBe(expandGlobPattern(pattern).length)
    expect(mounts.length).toBe(PKGS.length * 6)
  })

  it('reaches bwrap as directory tmpfs mounts, and a non-glob deny is untouched', async () => {
    const literalFile = join(ROOT, 'pkg', 'a', 'index.ts')
    try {
      const wrapped = await SandboxManager.wrapWithSandbox(
        'echo hello',
        undefined,
        {
          filesystem: {
            denyRead: [join(ROOT, '**/build/**'), literalFile],
            allowWrite: [],
            denyWrite: [],
          },
        },
      )

      for (const pkg of PKGS) {
        expect(
          countMounts(wrapped, '--tmpfs', join(ROOT, 'pkg', pkg, 'build')),
        ).toBeGreaterThan(0)
      }
      for (const pkg of PKGS) {
        expect(wrapped).not.toContain(
          `--ro-bind /dev/null ${join(ROOT, 'pkg', pkg, 'build')}/`,
        )
      }
      expect(wrapped).toContain(`--ro-bind /dev/null ${literalFile}`)
    } finally {
      await SandboxManager.reset()
    }
  })
})

describe.if(isLinux)(
  'expandReadDenyGlobLinux (coverage behind a directory link)',
  () => {
    // The walk descends symlinked directories and reports each match where it
    // really lives, so a deny glob covers what it matches whichever spelling
    // found it, and one mount stands for every spelling. These cases are the
    // ones a walk that does not follow links loses outright.
    let ROOT: string
    let BASE: string
    let LNK: string
    let ABS: string
    let REALKEY: string
    const CAN_RUN = bwrapCanNamespace()

    beforeAll(() => {
      ROOT = realpathSync(mkdtempSync(join(tmpdir(), 'deny-glob-links-')))
      // A link named by the pattern's own wildcard segment.
      BASE = join(ROOT, 'base')
      mkdirSync(join(BASE, 'real', 'cfg'), { recursive: true })
      REALKEY = join(BASE, 'real', 'cfg', 'key.txt')
      writeFileSync(REALKEY, 'KEYBYTES\n')
      LNK = join(BASE, 'lnk')
      symlinkSync(join('real', 'cfg'), LNK)
      ABS = join(BASE, 'abs')
      symlinkSync(join(BASE, 'real', 'cfg'), ABS)
      // A link whose target is outside the pattern's base directory.
      mkdirSync(join(ROOT, 'out', 'config', 'dev'), { recursive: true })
      mkdirSync(join(ROOT, 'out', 'shared', 'prod'), { recursive: true })
      writeFileSync(join(ROOT, 'out', 'config', 'dev', 'key'), 'DEVKEY\n')
      writeFileSync(join(ROOT, 'out', 'shared', 'prod', 'key'), 'PRODKEY\n')
      symlinkSync(
        join('..', 'shared', 'prod'),
        join(ROOT, 'out', 'config', 'prod'),
      )
      // The same, with an absolute target.
      mkdirSync(join(ROOT, 'absout', 'config'), { recursive: true })
      mkdirSync(join(ROOT, 'absout', 'elsewhere', 'prod'), { recursive: true })
      writeFileSync(join(ROOT, 'absout', 'elsewhere', 'prod', 'key'), 'ABS\n')
      symlinkSync(
        join(ROOT, 'absout', 'elsewhere', 'prod'),
        join(ROOT, 'absout', 'config', 'prod'),
      )
      // A package linked out of node_modules, as a workspace install leaves it.
      mkdirSync(join(ROOT, 'store', 'node_modules', 'other'), {
        recursive: true,
      })
      mkdirSync(join(ROOT, 'store', 'packages', 'pkg'), { recursive: true })
      writeFileSync(
        join(ROOT, 'store', 'node_modules', 'other', 'index.js'),
        'OTHER\n',
      )
      writeFileSync(join(ROOT, 'store', 'packages', 'pkg', 'index.js'), 'PKG\n')
      symlinkSync(
        join('..', 'packages', 'pkg'),
        join(ROOT, 'store', 'node_modules', 'pkg'),
      )
      // A link to its own directory, and two links into each other.
      mkdirSync(join(ROOT, 'cycles', 'a'), { recursive: true })
      mkdirSync(join(ROOT, 'cycles', 'b'), { recursive: true })
      writeFileSync(join(ROOT, 'cycles', 'a', 'key.txt'), 'AKEY\n')
      writeFileSync(join(ROOT, 'cycles', 'b', 'key.txt'), 'BKEY\n')
      symlinkSync('.', join(ROOT, 'cycles', 'self'))
      symlinkSync(join('..', 'b'), join(ROOT, 'cycles', 'a', 'l1'))
      symlinkSync(join('..', 'a'), join(ROOT, 'cycles', 'b', 'l2'))
      // build/ as a link, and a build/ directory behind a link.
      mkdirSync(join(ROOT, 'builds', 'pkg1', 'build'), { recursive: true })
      mkdirSync(join(ROOT, 'builds', 'linked'), { recursive: true })
      mkdirSync(join(ROOT, 'builds', 'pkg2'), { recursive: true })
      mkdirSync(join(ROOT, 'builds', 'pkg3'), { recursive: true })
      mkdirSync(join(ROOT, 'builds', 'realpkg', 'build'), { recursive: true })
      writeFileSync(join(ROOT, 'builds', 'pkg1', 'build', 'f'), 'ONE\n')
      writeFileSync(join(ROOT, 'builds', 'linked', 'f'), 'LINKED\n')
      writeFileSync(join(ROOT, 'builds', 'realpkg', 'build', 'f'), 'BEHIND\n')
      symlinkSync(join('..', 'linked'), join(ROOT, 'builds', 'pkg2', 'build'))
      symlinkSync(join('..', 'realpkg'), join(ROOT, 'builds', 'pkg3', 'lnk'))
    })

    afterAll(() => {
      rmSync(ROOT, { recursive: true, force: true })
    })

    const LINK_PATTERNS = [
      ['the wildcard segment names the link', 'l*/key.txt'],
      ['a bare star names the link', '*/key.txt'],
      ['a globstar reaches the link by name', '**/lnk/key.txt'],
      ['a globstar tail matches below the link', '**/key.txt'],
      ['the tail names the target directory', '**/cfg/key.txt'],
      ['the pattern spans depths through the link', 'l*/**/key.txt'],
      ['the link has an absolute target inside the base', 'a*/key.txt'],
    ] as const

    it.each(LINK_PATTERNS)(
      'covers the file behind a directory link when %s',
      (_why, tail) => {
        expect(expandReadDenyGlobLinux(join(BASE, tail), [])).toEqual([REALKEY])
      },
    )

    it('mounts a match behind a link whose target is outside the pattern base, at its target', () => {
      const mounts = expandReadDenyGlobLinux(
        join(ROOT, 'out', 'config', '*', 'key'),
        [],
      )

      expect(mounts).toEqual([
        join(ROOT, 'out', 'config', 'dev', 'key'),
        join(ROOT, 'out', 'shared', 'prod', 'key'),
      ])
    })

    it('mounts a match behind an absolute-target link outside the base, at its target', () => {
      const mounts = expandReadDenyGlobLinux(
        join(ROOT, 'absout', 'config', '*', 'key'),
        [],
      )

      expect(mounts).toEqual([join(ROOT, 'absout', 'elsewhere', 'prod', 'key')])
    })

    it('mounts a package linked out of node_modules where the package really is', () => {
      const mounts = expandReadDenyGlobLinux(
        join(ROOT, 'store', 'node_modules', '**', 'index.js'),
        [],
      )

      expect(mounts).toEqual([
        join(ROOT, 'store', 'node_modules', 'other', 'index.js'),
        join(ROOT, 'store', 'packages', 'pkg', 'index.js'),
      ])
    })

    it('terminates on a link to its own directory and on two links into each other', () => {
      const mounts = expandReadDenyGlobLinux(
        join(ROOT, 'cycles', '**', 'key.txt'),
        [],
      )

      expect(mounts).toEqual([
        join(ROOT, 'cycles', 'a', 'key.txt'),
        join(ROOT, 'cycles', 'b', 'key.txt'),
      ])
    })

    it('collapses a linked build directory, and one behind a link, onto their targets', () => {
      const mounts = expandReadDenyGlobLinux(
        join(ROOT, 'builds', '**', 'build', '**'),
        [],
      )

      expect(mounts).toEqual([
        join(ROOT, 'builds', 'linked'),
        join(ROOT, 'builds', 'pkg1', 'build'),
        join(ROOT, 'builds', 'realpkg', 'build'),
      ])
    })

    for (const [why, tail] of LINK_PATTERNS) {
      it.skipIf(!CAN_RUN)(
        `serves the file through neither spelling when ${why}`,
        async () => {
          const wrapped = await wrapCommandWithSandboxLinux({
            command: `sh -c 'echo BOOTED; cat ${join(LNK, 'key.txt')} 2>&1; cat ${REALKEY} 2>&1; cat ${join(ABS, 'key.txt')} 2>&1'`,
            needsNetworkRestriction: false,
            readConfig: {
              denyOnly: expandReadDenyGlobLinux(join(BASE, tail), []),
              allowWithinDeny: [],
            },
            writeConfig: { allowOnly: [], denyWithinAllow: [] },
            allowAllUnixSockets: true,
          })
          const result = spawnSync(wrapped, {
            shell: true,
            encoding: 'utf8',
            timeout: 15000,
          })

          expect(result.stderr ?? '').not.toContain('bwrap:')
          expect(result.stdout).toContain('BOOTED')
          expect(result.stdout).not.toContain('KEYBYTES')
        },
      )
    }
  },
)
