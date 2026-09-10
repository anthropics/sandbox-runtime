import { describe, it, expect, beforeAll, afterAll } from 'bun:test'
import {
  chmodSync,
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

  afterAll(() => {
    rmSync(ROOT, { recursive: true, force: true })
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
    // walk reaches first by its own name, which matches nothing; the link
    // is the only spelling the pattern matches, so the walk must list
    // through it (a global visited set would not). The target is where the
    // mount lands.
    const shal = join(ROOT, 'shal')
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

  it('never denies the root through a link to it', () => {
    // build/root -> /: denied where it resolves, that would be a tmpfs over
    // every top-level directory; denied at the link, a mount bwrap refuses,
    // so that no later command starts while the link exists. It is dropped.
    const rooted = join(ROOT, 'rooted')
    mkdirSync(join(rooted, 'build'), { recursive: true })
    writeFileSync(join(rooted, 'build', '1.out'), '')
    symlinkSync('/', join(rooted, 'build', 'root'))

    const mounts = expandReadDenyGlobLinux(join(rooted, '**/build/**'), [])

    expect(mounts).toEqual([join(rooted, 'build')])

    // The same when the link is itself the matched directory.
    mkdirSync(join(rooted, 'img'))
    symlinkSync('/', join(rooted, 'img', 'build'))
    expect(
      expandReadDenyGlobLinux(join(rooted, 'img', '**/build/**'), []),
    ).toEqual([])
  })

  it('denies the target of a directory-form link the walk did not descend', () => {
    // u/x/y/build -> u/x names a directory on its own descent chain, so the
    // walk lists nothing beneath it; it is still a match, and its target is
    // what a literal deny of the link would deny.
    const u = join(ROOT, 'u')
    mkdirSync(join(u, 'x', 'y'), { recursive: true })
    writeFileSync(join(u, 'x', 'src.ts'), '')
    symlinkSync(join('..'), join(u, 'x', 'y', 'build'))

    const mounts = expandReadDenyGlobLinux(join(u, '**/build/**'), [])

    expect(mounts).toContain(join(u, 'x'))
  })

  it('denies through a link back to the tree', () => {
    // build/up -> ..: the target is the whole tree the link reaches, as a
    // literal deny of the link would have it; the walk itself stops at the
    // link.
    const esc = join(ROOT, 'esc')
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
      pnpmRoot = join(ROOT, 'pnpm')
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
    const chain = join(ROOT, 'chain')
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
    const dangling = join(ROOT, 'dangling')
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
    const hasBwrap = spawnSync('bwrap', ['--version']).status === 0

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
      it(`mounts no tmpfs on a symlink and re-binds the carve-out last (allowRead in ${spelling} spelling)`, async () => {
        const carveOut = join(spelling === 'link' ? link : real, 'public')
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
        const reBind = ops.lastIndexOf(
          `ro-bind ${carveOut} ${join(real, 'public')}`,
        )
        expect(reBind).toBeGreaterThan(lastTmpfs)

        if (hasBwrap) {
          // Inside: the package is empty but for the carve-out, in both
          // spellings; the entries beneath the carve-out keep their masks.
          const run = spawnSync(
            await wrap(
              [
                `ls ${link}`,
                `ls ${real}`,
                `cat ${join(link, 'public', 'ok.txt')} | wc -c`,
                `[ -e ${join(link, 'index.js')} ] && echo INDEX_VISIBLE || echo INDEX_HIDDEN`,
              ].join('; '),
              carveOut,
            ),
            { shell: true, encoding: 'utf8', timeout: 15000, cwd: ROOT },
          )
          expect(run.stderr ?? '').not.toContain('symlink destination')
          expect(run.status).toBe(0)
          expect(run.stdout.trim().split('\n')).toEqual([
            'public',
            'public',
            '0',
            'INDEX_HIDDEN',
          ])
        }
      })
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
        `--ro-bind ${carveOut} ${join(real, 'index.js')}`,
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

      const storeBind = wrapped.lastIndexOf(`--ro-bind ${store} ${store}`)
      expect(storeBind).toBeGreaterThan(-1)
      expect(wrapped.lastIndexOf(`--tmpfs ${real}`)).toBeGreaterThan(storeBind)
    })

    it('does not re-apply a tmpfs over its carve-out when a denyWrite bind covers only the link spelling', async () => {
      // w/d/link -> realdir (outside the write root w). denyWrite [w/d]
      // contains the link's spelling but not where the tmpfs landed
      // (realdir), so the bind re-exposes nothing; re-applying the tmpfs
      // there anyway would re-bind realdir/pub over the mask on
      // realdir/pub/secret.txt and leave the file readable.
      const R = join(ROOT, 'f4')
      const realdir = join(R, 'realdir')
      const W = join(R, 'w')
      const S = join(W, 'd', 'link')
      mkdirSync(join(realdir, 'pub'), { recursive: true })
      writeFileSync(join(realdir, 'pub', 'secret.txt'), 'secret')
      mkdirSync(join(W, 'd'), { recursive: true })
      symlinkSync(realdir, S)

      const wrapped = await wrapCommandWithSandboxLinux({
        command: 'true',
        needsNetworkRestriction: false,
        readConfig: {
          denyOnly: [S, join(realdir, 'pub', 'secret.txt')],
          allowWithinDeny: [join(realdir, 'pub')],
        },
        writeConfig: { allowOnly: [W], denyWithinAllow: [join(W, 'd')] },
        mandatoryDenySearchDepth: 1,
      })

      const mask = `--ro-bind /dev/null ${join(realdir, 'pub', 'secret.txt')}`
      const carveOut = `--ro-bind ${join(realdir, 'pub')} ${join(realdir, 'pub')}`
      expect(wrapped).toContain(mask)
      // One tmpfs on the target, and the mask is the last word on the file:
      // no carve-out re-bind after it.
      expect(wrapped.split(`--tmpfs ${realdir} `)).toHaveLength(2)
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
      expect(viaLink).toContain(`--tmpfs ${real}`)
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
      expect(viaLink).toContain(`--tmpfs ${real}`)
      expect(viaLink).toContain(
        `--ro-bind ${join(link, 'public')} ${join(real, 'public')}`,
      )
    })

    it('re-binds a carve-out written through a symlinked directory outside the denied one, at its target', async () => {
      // denyRead [real] + allowRead [link/public]: the name `public` lives in
      // the denied directory whichever way it is reached, and the bind goes
      // where it is (bwrap refuses a symlink as a destination and, before
      // 0.12, an absolute one anywhere in it).
      const wrapped = await wrapCommandWithSandboxLinux({
        command: `cat ${join(link, 'public', 'ok.txt')}; cat ${join(real, 'index.js')} || echo HIDDEN`,
        needsNetworkRestriction: false,
        readConfig: {
          denyOnly: [real],
          allowWithinDeny: [join(link, 'public')],
        },
        writeConfig: { allowOnly: [], denyWithinAllow: [] },
      })
      expect(wrapped).toContain(`--tmpfs ${real}`)
      expect(wrapped).toContain(
        `--ro-bind ${join(link, 'public')} ${join(real, 'public')}`,
      )
      if (hasBwrap) {
        const run = spawnSync(wrapped, {
          shell: true,
          encoding: 'utf8',
          timeout: 15000,
        })
        expect(run.stdout).toBe('publicHIDDEN\n')
      }
    })

    describe('an allowRead that only leads into a denied directory', () => {
      // What an allowRead entry resolves to never decides which deny it
      // carves out of: a sandboxed command with write access to where the
      // entry lives can point it anywhere.
      function run(wrapped: string): string {
        return spawnSync(wrapped, {
          shell: true,
          encoding: 'utf8',
          timeout: 15000,
        }).stdout
      }

      it('does not bind a denied directory back through an allowRead symlink to it', async () => {
        const home = join(ROOT, 'g1', 'home')
        const proj = join(ROOT, 'g1', 'proj')
        mkdirSync(join(home, '.ssh'), { recursive: true })
        writeFileSync(join(home, '.ssh', 'id_rsa'), 'KEY')
        mkdirSync(proj, { recursive: true })
        symlinkSync(join(home, '.ssh'), join(proj, 'docs'))

        const wrapped = await wrapCommandWithSandboxLinux({
          command: `cat ${join(home, '.ssh', 'id_rsa')} ${join(proj, 'docs', 'id_rsa')} || echo HIDDEN`,
          needsNetworkRestriction: false,
          readConfig: {
            denyOnly: [join(home, '.ssh')],
            allowWithinDeny: [join(proj, 'docs')],
          },
          writeConfig: { allowOnly: [proj], denyWithinAllow: [] },
          mandatoryDenySearchDepth: 1,
        })

        expect(wrapped).toContain(`--tmpfs ${join(home, '.ssh')}`)
        expect(wrapped).not.toContain(`--ro-bind ${join(proj, 'docs')}`)
        if (hasBwrap) {
          const stdout = run(wrapped)
          expect(stdout).not.toContain('KEY')
          expect(stdout).toContain('HIDDEN')
        }
      })

      it('keeps the mask on a denied file an allowRead symlink points at', async () => {
        const aws = join(ROOT, 'g2', 'aws')
        const proj = join(ROOT, 'g2', 'proj')
        mkdirSync(aws, { recursive: true })
        writeFileSync(join(aws, 'credentials'), 'CREDS')
        mkdirSync(proj, { recursive: true })
        symlinkSync(join(aws, 'credentials'), join(proj, 'cfg.json'))

        const wrapped = await wrapCommandWithSandboxLinux({
          command: `cat ${join(aws, 'credentials')} ${join(proj, 'cfg.json')}; echo END`,
          needsNetworkRestriction: false,
          readConfig: {
            denyOnly: [join(aws, 'credentials')],
            allowWithinDeny: [join(proj, 'cfg.json')],
          },
          writeConfig: { allowOnly: [proj], denyWithinAllow: [] },
          mandatoryDenySearchDepth: 1,
        })

        expect(wrapped).toContain(
          `--ro-bind /dev/null ${join(aws, 'credentials')}`,
        )
        if (hasBwrap) expect(run(wrapped)).not.toContain('CREDS')
      })

      it('does not lift a file mask for an allowRead symlink that a pattern also matches', async () => {
        // denyRead **/.env* with allowRead **/.env.example, and
        // sub/.env.example -> ../.env planted: both patterns match the link,
        // which names the link, not .env.
        const proj = join(ROOT, 'g3', 'proj')
        mkdirSync(join(proj, 'sub'), { recursive: true })
        writeFileSync(join(proj, '.env'), 'ENVSECRET')
        writeFileSync(join(proj, '.env.example'), 'EXAMPLE')
        symlinkSync(join('..', '.env'), join(proj, 'sub', '.env.example'))
        const allowWithinDeny = expandGlobPattern(join(proj, '**/.env.example'))
        expect(allowWithinDeny).toContain(join(proj, 'sub', '.env.example'))

        const wrapped = await wrapCommandWithSandboxLinux({
          command: `cat ${join(proj, '.env.example')}; cat ${join(proj, 'sub', '.env.example')} ${join(proj, '.env')}; echo END`,
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

        expect(wrapped).toContain(`--ro-bind /dev/null ${join(proj, '.env')}`)
        expect(wrapped).not.toContain(`/dev/null ${join(proj, '.env.example')}`)
        if (hasBwrap) {
          const stdout = run(wrapped)
          expect(stdout).toContain('EXAMPLE')
          expect(stdout).not.toContain('ENVSECRET')
        }
      })

      it('does not show a tree outside the denied directory under a name inside it', async () => {
        // denyRead [D, e/sub] + allowRead [D/lnk], D/lnk -> ../e: bound back
        // at D/lnk, e would be readable there whatever is denied inside it.
        // e was never hidden by D's tmpfs, so there is nothing to restore.
        const D = join(ROOT, 's1', 'D')
        const e = join(ROOT, 's1', 'e')
        mkdirSync(D, { recursive: true })
        mkdirSync(join(e, 'sub'), { recursive: true })
        writeFileSync(join(e, 'sub', 'secret'), 'secret')
        symlinkSync(join('..', 'e'), join(D, 'lnk'))
        for (const denyOnly of [
          [D, join(e, 'sub')],
          [join(D, 'lnk', 'sub'), D],
        ]) {
          const wrapped = await wrapCommandWithSandboxLinux({
            command: `cat ${join(D, 'lnk', 'sub', 'secret')} ${join(e, 'sub', 'secret')} || echo HIDDEN`,
            needsNetworkRestriction: false,
            readConfig: { denyOnly, allowWithinDeny: [join(D, 'lnk')] },
            writeConfig: { allowOnly: [], denyWithinAllow: [] },
          })
          expect(wrapped).toContain(`--tmpfs ${D}`)
          expect(wrapped).toContain(`--tmpfs ${join(e, 'sub')}`)
          expect(wrapped).not.toContain(`--ro-bind ${join(D, 'lnk')}`)
          if (hasBwrap) {
            const stdout = run(wrapped)
            expect(stdout).not.toContain('secret')
            expect(stdout).toContain('HIDDEN')
          }
        }
      })

      it('leaves a link inside a carve-out to lead where it leads, without a mount of its own', async () => {
        // denyRead [t/private, D] + allowRead [D/x, D/x/lnk], D/x/lnk -> t:
        // D/x is bound back from the host, live link included, so t is
        // reached through it as on the host and t/private stays denied. A
        // bind of D/x/lnk would land on t and bury that deny.
        const D = join(ROOT, 's3', 'D')
        const t = join(ROOT, 's3', 't')
        mkdirSync(join(D, 'x'), { recursive: true })
        mkdirSync(join(t, 'private'), { recursive: true })
        writeFileSync(join(t, 'f'), 'T')
        writeFileSync(join(t, 'private', 'key'), 'KEY')
        symlinkSync(join('..', '..', 't'), join(D, 'x', 'lnk'))
        const wrapped = await wrapCommandWithSandboxLinux({
          command: `cat ${join(D, 'x', 'lnk', 'f')}; cat ${join(t, 'private', 'key')} ${join(D, 'x', 'lnk', 'private', 'key')} || echo HIDDEN`,
          needsNetworkRestriction: false,
          readConfig: {
            denyOnly: [join(t, 'private'), D],
            allowWithinDeny: [join(D, 'x'), join(D, 'x', 'lnk')],
          },
          writeConfig: { allowOnly: [], denyWithinAllow: [] },
        })
        expect(wrapped).not.toContain(`--ro-bind ${join(D, 'x', 'lnk')}`)
        if (hasBwrap) {
          const run = spawnSync(wrapped, {
            shell: true,
            encoding: 'utf8',
            timeout: 15000,
          })
          expect(run.stderr ?? '').not.toContain('symlink destination')
          expect(run.stdout).toBe('THIDDEN\n')
        }
      })
    })

    it('denies a path the same way whatever order and spelling name it', async () => {
      // l1 -> a/b, a/b/l2 -> t: l1/l2/f is t/f. Mounted where it really is,
      // it is denied under every name, in either order of the two entries.
      const R = join(ROOT, 's7')
      mkdirSync(join(R, 'a', 'b'), { recursive: true })
      mkdirSync(join(R, 't'))
      writeFileSync(join(R, 't', 'f'), 'FCONTENT')
      symlinkSync(join('a', 'b'), join(R, 'l1'))
      symlinkSync(join('..', '..', 't'), join(R, 'a', 'b', 'l2'))
      const denied = [join(R, 'l1', 'l2', 'f'), join(R, 'a', 'b')]
      for (const denyOnly of [denied, [...denied].reverse()]) {
        const wrapped = await wrapCommandWithSandboxLinux({
          command: `cat ${join(R, 'l1', 'l2', 'f')} ${join(R, 't', 'f')}; echo END`,
          needsNetworkRestriction: false,
          readConfig: { denyOnly, allowWithinDeny: [join(R, 'a', 'b', 'l2')] },
          writeConfig: { allowOnly: [], denyWithinAllow: [] },
        })
        expect(wrapped).toContain(`--ro-bind /dev/null ${join(R, 't', 'f')}`)
        expect(wrapped).toContain(`--tmpfs ${join(R, 'a', 'b')}`)
        if (hasBwrap) {
          const run = spawnSync(wrapped, {
            shell: true,
            encoding: 'utf8',
            timeout: 15000,
          })
          expect(run.stdout).toBe('END\n')
        }
      }
    })

    it('mounts a directory that a link inside a denied directory leads back up to before that directory', async () => {
      // x/secrets/latest -> .. (x, an allowed write root): the deny of the
      // link is a deny of x, which the write bind cancels; mounted after
      // x/secrets it would wipe that tmpfs and bind the secrets back.
      const x = join(ROOT, 's5', 'x')
      mkdirSync(join(x, 'secrets'), { recursive: true })
      writeFileSync(join(x, 'secrets', 'key'), 'KEY')
      symlinkSync('..', join(x, 'secrets', 'latest'))
      const denied = [join(x, 'secrets'), join(x, 'secrets', 'latest')]
      for (const denyOnly of [denied, [...denied].reverse()]) {
        const wrapped = await wrapCommandWithSandboxLinux({
          command: `cat ${join(x, 'secrets', 'key')} || echo HIDDEN`,
          needsNetworkRestriction: false,
          readConfig: { denyOnly },
          writeConfig: { allowOnly: [x], denyWithinAllow: [] },
          mandatoryDenySearchDepth: 1,
        })
        expect(
          wrapped.lastIndexOf(`--tmpfs ${join(x, 'secrets')} `),
        ).toBeGreaterThan(wrapped.lastIndexOf(`--bind ${x} ${x} `))
        if (hasBwrap) {
          const run = spawnSync(wrapped, {
            shell: true,
            encoding: 'utf8',
            timeout: 15000,
          })
          expect(run.stdout).toBe('HIDDEN\n')
        }
      }
    })

    it('binds an allowed write path back only where it really is', async () => {
      // D/L -> ../T with denyRead [D, D/L/sub] and allowWrite [T/sub/w]:
      // T/sub/w is bound back once, at T/sub/w, under the deny binds and
      // masks that protect it. Bound a second time beneath D/L it would be
      // writable there with none of them on top.
      const D = join(ROOT, 's6', 'D')
      const T = join(ROOT, 's6', 'T')
      const w = join(T, 'sub', 'w')
      mkdirSync(D, { recursive: true })
      mkdirSync(join(w, '.git', 'hooks'), { recursive: true })
      writeFileSync(join(w, '.env'), 'ENV')
      symlinkSync(join('..', 'T'), join(D, 'L'))
      const wrapped = await wrapCommandWithSandboxLinux({
        command: `touch ${join(D, 'L', 'sub', 'w', '.git', 'hooks', 'pre-commit')} ${join(w, '.git', 'hooks', 'pre-commit')} && echo WRITTEN; cat ${join(D, 'L', 'sub', 'w', '.env')} ${join(w, '.env')} || echo HIDDEN`,
        needsNetworkRestriction: false,
        readConfig: {
          denyOnly: [D, join(D, 'L', 'sub'), join(w, '.env')],
          allowWithinDeny: [join(D, 'L')],
        },
        writeConfig: {
          allowOnly: [w],
          denyWithinAllow: [join(w, '.git', 'hooks')],
        },
        mandatoryDenySearchDepth: 1,
      })
      const binds = wrapped
        .split(' --')
        .filter(op => op.startsWith(`bind ${w} `))
      expect(binds.every(op => op.trim() === `bind ${w} ${w}`)).toBe(true)
      if (hasBwrap) {
        const run = spawnSync(wrapped, {
          shell: true,
          encoding: 'utf8',
          timeout: 15000,
        })
        expect(run.stdout).not.toContain('WRITTEN')
        expect(run.stdout).not.toContain('ENV')
        expect(run.stdout).toContain('HIDDEN')
      }
    })

    it('keeps a denyWrite bind whose path only passes through a read-denied directory', async () => {
      // ln -> real/secretdir and real/secretdir/out -> elsewhere/hooks:
      // denyWrite [real/secretdir/out] protects elsewhere/hooks, which the
      // tmpfs on real/secretdir does not hide.
      const root = join(ROOT, 's8', 'root')
      const hooks = join(root, 'elsewhere', 'hooks')
      mkdirSync(join(root, 'real', 'secretdir'), { recursive: true })
      mkdirSync(hooks, { recursive: true })
      symlinkSync(join(root, 'real', 'secretdir'), join(root, 'ln'))
      symlinkSync(hooks, join(root, 'real', 'secretdir', 'out'))
      const wrapped = await wrapCommandWithSandboxLinux({
        command: `touch ${join(hooks, 'x')} && echo WRITTEN || echo DENIED`,
        needsNetworkRestriction: false,
        readConfig: { denyOnly: [join(root, 'ln')] },
        writeConfig: {
          allowOnly: [root],
          denyWithinAllow: [join(root, 'real', 'secretdir', 'out')],
        },
        mandatoryDenySearchDepth: 1,
      })
      expect(wrapped).toContain(`--tmpfs ${join(root, 'real', 'secretdir')}`)
      expect(wrapped).toContain(`--ro-bind ${hooks} ${hooks}`)
      if (hasBwrap) {
        const run = spawnSync(wrapped, {
          shell: true,
          encoding: 'utf8',
          timeout: 15000,
        })
        expect(run.stdout).toBe('DENIED\n')
      }
    })

    it('re-applies one mask for a file denied through a symlinked directory', async () => {
      // W/lnk -> real, denyRead [W/lnk/secret], denyWrite [W]: the mask sits
      // on W/real/secret alone, so the bind of W re-exposes one file and one
      // mask goes back (a second on the same inode aborts bwrap before 0.5).
      const W = join(ROOT, 's10', 'W')
      mkdirSync(join(W, 'real'), { recursive: true })
      writeFileSync(join(W, 'real', 'secret'), 'S')
      symlinkSync('real', join(W, 'lnk'))
      const wrapped = await wrapCommandWithSandboxLinux({
        command: 'true',
        needsNetworkRestriction: false,
        readConfig: { denyOnly: [join(W, 'lnk', 'secret')] },
        writeConfig: { allowOnly: [W], denyWithinAllow: [W] },
        mandatoryDenySearchDepth: 1,
      })
      const mask = `--ro-bind /dev/null ${join(W, 'real', 'secret')}`
      const afterDenyBind = wrapped.slice(
        wrapped.lastIndexOf(`--ro-bind ${W} ${W}`),
      )
      expect(afterDenyBind.split(mask)).toHaveLength(2)
      expect(wrapped).not.toContain(`/dev/null ${join(W, 'lnk', 'secret')}`)
    })

    it.if(process.getuid?.() !== 0)(
      'restores nothing beneath a read-denied directory it cannot list',
      async () => {
        // denyRead **/.env with the working directory an allowed write root
        // and mode 0311 (what a sandboxed command can leave behind): the
        // .env files beneath it cannot be enumerated, so the directory is
        // denied whole, and binding the write root back over that tmpfs
        // would show every one of them unmasked.
        const cwd = join(ROOT, 's11', 'cwd')
        mkdirSync(join(cwd, 'svc'), { recursive: true })
        writeFileSync(join(cwd, '.env'), 'ENV1')
        writeFileSync(join(cwd, 'svc', '.env'), 'ENV2')
        chmodSync(cwd, 0o311)
        try {
          const denyOnly = expandReadDenyGlobLinux(join(cwd, '**/.env'), [cwd])
          expect(denyOnly).toEqual([cwd])
          const wrapped = await wrapCommandWithSandboxLinux({
            command: `cat ${join(cwd, '.env')} ${join(cwd, 'svc', '.env')} || echo HIDDEN`,
            needsNetworkRestriction: false,
            readConfig: { denyOnly },
            writeConfig: { allowOnly: [cwd], denyWithinAllow: [] },
            mandatoryDenySearchDepth: 1,
          })
          expect(
            wrapped.slice(wrapped.indexOf(`--tmpfs ${cwd}`)),
          ).not.toContain(`--bind ${cwd} ${cwd}`)
          if (hasBwrap) {
            const run = spawnSync(wrapped, {
              shell: true,
              encoding: 'utf8',
              timeout: 15000,
            })
            expect(run.stdout).not.toContain('ENV')
            expect(run.stdout).toContain('HIDDEN')
          }
        } finally {
          chmodSync(cwd, 0o755)
        }
      },
    )

    it.if(process.getuid?.() !== 0)(
      'hides the nearest directory it can inspect when an entry cannot be looked at',
      async () => {
        // proj/pkg is readable but not searchable (0600): its entries can be
        // listed, so the pattern matches pkg/.env and finds pkg/build, but
        // neither can be stat'ed. Skipped as absent, both would be readable
        // once the mode is put back.
        const proj = join(ROOT, 's12', 'proj')
        const pkg = join(proj, 'pkg')
        mkdirSync(join(pkg, 'build'), { recursive: true })
        writeFileSync(join(pkg, '.env'), 'ENV')
        writeFileSync(join(pkg, 'build', 'o'), 'OUT')
        chmodSync(pkg, 0o600)
        try {
          const denyOnly = [
            ...expandReadDenyGlobLinux(join(proj, '**/build/**'), [proj]),
            ...expandReadDenyGlobLinux(join(proj, '**/.env'), [proj]),
          ]
          expect(denyOnly).toContain(join(pkg, '.env'))
          const wrapped = await wrapCommandWithSandboxLinux({
            command: `chmod 755 ${pkg}; cat ${join(pkg, '.env')} ${join(pkg, 'build', 'o')} || echo HIDDEN`,
            needsNetworkRestriction: false,
            readConfig: { denyOnly },
            writeConfig: { allowOnly: [proj], denyWithinAllow: [] },
            mandatoryDenySearchDepth: 1,
          })
          expect(wrapped).toContain(`--tmpfs ${pkg}`)
          if (hasBwrap) {
            const run = spawnSync(wrapped, {
              shell: true,
              encoding: 'utf8',
              timeout: 15000,
            })
            expect(run.stdout).not.toContain('ENV')
            expect(run.stdout).not.toContain('OUT')
            expect(run.stdout).toContain('HIDDEN')
          }
        } finally {
          chmodSync(pkg, 0o755)
        }
      },
    )

    it('starts with a matched link to / in the tree', async () => {
      // A sandboxed command with write access under the pattern's base can
      // plant such a link; a mount on it would stop every later command.
      const proj = join(ROOT, 's13', 'proj')
      mkdirSync(join(proj, 'img'), { recursive: true })
      symlinkSync('/', join(proj, 'img', 'build'))
      const wrapped = await wrapCommandWithSandboxLinux({
        command: 'echo STARTED',
        needsNetworkRestriction: false,
        readConfig: {
          denyOnly: [
            ...expandReadDenyGlobLinux(join(proj, '**/build/**'), []),
            // Named literally, the link is skipped by the loop as well.
            join(proj, 'img', 'build'),
          ],
        },
        writeConfig: { allowOnly: [], denyWithinAllow: [] },
      })
      expect(wrapped).not.toContain(`--tmpfs ${join(proj, 'img', 'build')}`)
      if (hasBwrap) {
        const run = spawnSync(wrapped, {
          shell: true,
          encoding: 'utf8',
          timeout: 15000,
        })
        expect(run.stdout).toBe('STARTED\n')
      }
    })

    it('still masks the target of a file symlink listed beneath a denied directory', async () => {
      // denyRead [cfg, cfg/token], cfg/token -> ../secrets/token: the link
      // vanishes with cfg's tmpfs, but the file it named is the target,
      // which stays reachable by its own name and must be masked there.
      const cfg = join(ROOT, 's9', 'cfg')
      const secrets = join(ROOT, 's9', 'secrets')
      mkdirSync(cfg, { recursive: true })
      mkdirSync(secrets, { recursive: true })
      writeFileSync(join(secrets, 'token'), 'TOKEN')
      symlinkSync(join('..', 'secrets', 'token'), join(cfg, 'token'))
      const wrapped = await wrapCommandWithSandboxLinux({
        command: `cat ${join(secrets, 'token')}; echo`,
        needsNetworkRestriction: false,
        readConfig: { denyOnly: [cfg, join(cfg, 'token')] },
        writeConfig: { allowOnly: [], denyWithinAllow: [] },
      })
      expect(wrapped).toContain(`--ro-bind /dev/null ${join(secrets, 'token')}`)
      if (hasBwrap) {
        const run = spawnSync(wrapped, {
          shell: true,
          encoding: 'utf8',
          timeout: 15000,
        })
        expect(run.status).toBe(0)
        expect(run.stdout).not.toContain('TOKEN')
      }
    })

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
        expect(collapsed.split(`--tmpfs ${big}`)).toHaveLength(2)
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

      expect(wrapped).toContain(`--tmpfs ${join(ROOT, 'pkg', 'a', 'build')}`)
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
        expect(wrapped).toContain(`--tmpfs ${join(ROOT, 'pkg', pkg, 'build')}`)
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
