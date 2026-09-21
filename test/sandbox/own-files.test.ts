import { afterEach, beforeEach, describe, expect, it } from 'bun:test'
import { spawnSync } from 'node:child_process'
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  readlinkSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { wrapCommandWithSandboxMacOS } from '../../src/sandbox/macos-sandbox-utils.js'
import {
  installedPackagePaths,
  ownFilesWriteDenies,
} from '../../src/sandbox/own-files.js'
import { bwrapCanNamespace } from '../helpers/bwrap-namespace.js'
import { isLinux, isWindows } from '../helpers/platform.js'

/**
 * The library installed as a dependency of a project lives inside the
 * project, and the project is what a wrapped command may write. Its own files,
 * and the packages it loads, are what the host runs the next time `srt` is
 * started there, so they are write-denied to every wrapped command.
 */
describe('The library own files under a write path', () => {
  let dir: string

  beforeEach(() => {
    dir = realpathSync(mkdtempSync(join(tmpdir(), 'own-files-')))
  })

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true })
  })

  /** `from` copied to `to`, a file or a whole tree, links followed. */
  function copyTree(from: string, to: string): void {
    if (!statSync(from).isDirectory()) {
      mkdirSync(dirname(to), { recursive: true })
      copyFileSync(from, to)
      return
    }
    mkdirSync(to, { recursive: true })
    for (const name of readdirSync(from)) {
      copyTree(join(from, name), join(to, name))
    }
  }

  /** A package directory holding a manifest. */
  function makePackage(
    at: string,
    manifest: Record<string, unknown> = {},
  ): string {
    mkdirSync(at, { recursive: true })
    writeFileSync(join(at, 'package.json'), JSON.stringify(manifest))
    return at
  }

  /** `<project>/node_modules/@scope/lib` with a module two levels down, the
   *  way every module of dist/sandbox is. Returns that module's path. */
  function installLibrary(
    project: string,
    dependencies: Record<string, string>,
  ): { root: string; moduleFile: string } {
    const root = makePackage(join(project, 'node_modules', '@scope', 'lib'), {
      name: '@scope/lib',
      dependencies,
    })
    mkdirSync(join(root, 'dist', 'sandbox'), { recursive: true })
    const moduleFile = join(root, 'dist', 'sandbox', 'own-files.js')
    writeFileSync(moduleFile, '')
    return { root, moduleFile }
  }

  describe('finding what it was loaded from', () => {
    it('finds the package, what it depends on, and what those depend on', () => {
      const project = join(dir, 'project')
      const { root, moduleFile } = installLibrary(project, { a: '1', b: '1' })
      // Hoisted beside it, nested under it, and one a dependency brings.
      const a = makePackage(join(project, 'node_modules', 'a'), {
        dependencies: { c: '1' },
      })
      const b = makePackage(join(root, 'node_modules', 'b'))
      const c = makePackage(join(project, 'node_modules', 'c'))
      // Installed and not depended on: not this library's to deny.
      makePackage(join(project, 'node_modules', 'unrelated'))

      expect(installedPackagePaths(moduleFile).sort()).toEqual(
        [
          root,
          a,
          b,
          c,
          // Where `a` and `c` are looked for before the hoisted copies are
          // reached. Neither directory exists, so either could be made.
          join(project, 'node_modules', '@scope', 'node_modules'),
          join(project, 'node_modules', 'node_modules'),
        ].sort(),
      )
    })

    it('counts a place looked at first by the name that would be made there', () => {
      // The hoisted copy is a level further up, as in a workspace, and the
      // project has a node_modules of its own: what could be planted is one
      // entry in it, not the directory.
      const workspace = join(dir, 'workspace')
      const project = join(workspace, 'packages', 'app')
      const { root, moduleFile } = installLibrary(project, { a: '1' })
      const a = makePackage(join(workspace, 'node_modules', 'a'))

      expect(installedPackagePaths(moduleFile).sort()).toEqual(
        [
          root,
          a,
          join(project, 'node_modules', '@scope', 'node_modules'),
          join(project, 'node_modules', 'node_modules'),
          join(project, 'node_modules', 'a'),
          join(workspace, 'packages', 'node_modules'),
        ].sort(),
      )
    })

    it('counts everywhere a dependency that is not installed could be put', () => {
      // Declared and absent, as an optional dependency may be: the loader
      // would take a copy from any level on the way up.
      const project = join(dir, 'project')
      const root = makePackage(join(project, 'node_modules', 'lib'), {
        name: 'lib',
        optionalDependencies: { extra: '1' },
      })
      mkdirSync(join(root, 'dist', 'sandbox'), { recursive: true })

      const found = installedPackagePaths(join(root, 'dist', 'sandbox', 'm.js'))
      expect(found).toContain(root)
      expect(found).toContain(join(project, 'node_modules', 'extra'))
      expect(found).toContain(join(project, 'node_modules', 'node_modules'))
      // Inside the package it is denied with the package.
      expect(found).not.toContain(join(root, 'node_modules'))
      // And of those, a wrap takes the ones it could be made in.
      expect(ownFilesWriteDenies([project], found).sort()).toEqual(
        [
          root,
          join(project, 'node_modules', 'extra'),
          join(project, 'node_modules', 'node_modules'),
        ].sort(),
      )
    })

    it('counts the launchers npm made for it, and no other', () => {
      const project = join(dir, 'project')
      const root = makePackage(join(project, 'node_modules', '@scope', 'lib'), {
        name: '@scope/lib',
        bin: { lib: 'dist/cli.js', absent: 'x.js' },
      })
      mkdirSync(join(root, 'dist', 'sandbox'), { recursive: true })
      mkdirSync(join(project, 'node_modules', '.bin'), { recursive: true })
      const launcher = join(project, 'node_modules', '.bin', 'lib')
      symlinkSync('../@scope/lib/dist/cli.js', launcher)
      writeFileSync(join(project, 'node_modules', '.bin', 'other'), '')

      expect(
        installedPackagePaths(join(root, 'dist', 'sandbox', 'm.js')).sort(),
      ).toEqual([root, launcher].sort())

      // A manifest that names one launcher by a string calls it after the
      // package.
      const plain = makePackage(join(project, 'node_modules', 'tool'), {
        name: 'tool',
        bin: 'cli.js',
      })
      mkdirSync(join(plain, 'dist', 'sandbox'), { recursive: true })
      writeFileSync(join(project, 'node_modules', '.bin', 'tool'), '')
      expect(
        installedPackagePaths(join(plain, 'dist', 'sandbox', 'm.js')).sort(),
      ).toEqual([plain, join(project, 'node_modules', '.bin', 'tool')].sort())
    })

    it('prefers the copy nearest the package that asks, as the loader does', () => {
      const project = join(dir, 'project')
      const { root, moduleFile } = installLibrary(project, { a: '1' })
      makePackage(join(project, 'node_modules', 'a'))
      const nested = makePackage(join(root, 'node_modules', 'a'))

      expect(installedPackagePaths(moduleFile).sort()).toEqual(
        [root, nested].sort(),
      )
    })

    it('ends on a dependency cycle', () => {
      const project = join(dir, 'project')
      const { root, moduleFile } = installLibrary(project, { a: '1' })
      const a = makePackage(join(project, 'node_modules', 'a'), {
        dependencies: { b: '1' },
      })
      const b = makePackage(join(project, 'node_modules', 'b'), {
        dependencies: { a: '1' },
      })

      expect(installedPackagePaths(moduleFile).sort()).toEqual(
        [
          root,
          a,
          b,
          join(project, 'node_modules', '@scope', 'node_modules'),
          join(project, 'node_modules', 'node_modules'),
        ].sort(),
      )
    })

    it('finds nothing for a checkout, which is the project being worked on', () => {
      const checkout = makePackage(join(dir, 'checkout'), {
        dependencies: { a: '1' },
      })
      makePackage(join(checkout, 'node_modules', 'a'))
      mkdirSync(join(checkout, 'src', 'sandbox'), { recursive: true })

      expect(
        installedPackagePaths(join(checkout, 'src', 'sandbox', 'own-files.ts')),
      ).toEqual([])
    })

    it('finds nothing where there is no package on disk', () => {
      expect(
        installedPackagePaths(
          join(dir, 'node_modules', 'gone', 'dist', 'sandbox', 'own-files.js'),
        ),
      ).toEqual([])
      // Compiled into an application: the module has a location, not a file.
      expect(
        installedPackagePaths('/$bunfs/root/node_modules/x/dist/sandbox/m.js'),
      ).toEqual([])
    })

    it('finds nothing for this repository itself', () => {
      // The default argument, from a checkout: nothing to deny, so running
      // the suite here is not what is under test anywhere else.
      expect(ownFilesWriteDenies(['/'])).toEqual([])
    })
  })

  describe('which of them a wrap denies', () => {
    it('denies the ones inside a path the command may write, and no other', () => {
      const project = join(dir, 'project')
      const elsewhere = join(dir, 'elsewhere', 'node_modules', 'far')
      const inside = [
        join(project, 'node_modules', '@scope', 'lib'),
        join(project, 'node_modules', 'a'),
      ]
      for (const each of [...inside, elsewhere]) makePackage(each)

      expect(ownFilesWriteDenies([project], [...inside, elsewhere])).toEqual(
        inside,
      )
      expect(ownFilesWriteDenies([join(dir, 'other')], inside)).toEqual([])
      expect(ownFilesWriteDenies([], inside)).toEqual([])
    })

    it('denies all of them where an allowed write path is a pattern', () => {
      // A pattern cannot be judged by containment, and a deny on what is not
      // writable anyway changes nothing.
      const inside = join(dir, 'project', 'node_modules', 'lib')
      const elsewhere = join(dir, 'elsewhere', 'node_modules', 'far')
      expect(
        ownFilesWriteDenies([join(dir, 'pro*')], [inside, elsewhere]),
      ).toEqual([inside, elsewhere])
    })

    it.if(!isWindows)(
      'reaches the macOS profile as names, whatever characters they hold',
      () => {
        // A project directory a pattern would read as a character class.
        const project = join(dir, 'pro[j]ect')
        const lib = makePackage(join(project, 'node_modules', 'lib'))
        const denies = ownFilesWriteDenies([project], [lib])
        expect(denies).toEqual([lib])

        const profile = wrapCommandWithSandboxMacOS({
          command: 'true',
          needsNetworkRestriction: false,
          readConfig: undefined,
          writeConfig: {
            allowOnly: [dir],
            denyWithinAllow: [],
            literalDenyWithinAllow: denies,
          },
        })
        expect(profile).toContain(`(subpath ${JSON.stringify(lib)})`)
        expect(profile).not.toContain('pro[j]ect/node_modules/lib(/.*)?$')
      },
    )

    it.if(!isWindows)('goes by where a path really is, on both sides', () => {
      // The project reached through a link, and named that way to the wrap.
      const project = join(dir, 'real-project')
      const lib = makePackage(join(project, 'node_modules', 'lib'))
      symlinkSync(project, join(dir, 'link'))

      expect(ownFilesWriteDenies([join(dir, 'link')], [lib])).toEqual([lib])
      expect(
        ownFilesWriteDenies(
          [project],
          [join(dir, 'link', 'node_modules', 'lib')],
        ),
      ).toEqual([join(dir, 'link', 'node_modules', 'lib')])
    })
  })

  /**
   * The real thing: the BUILT package copied into a project's node_modules
   * with what it depends on, run from there with the project writable.
   */
  describe('installed in a project and run from there', () => {
    const REPO = join(dirname(new URL(import.meta.url).pathname), '..', '..')
    const BUILT = existsSync(join(REPO, 'dist', 'cli.js'))
    const CAN_WRAP = !isWindows && (!isLinux || bwrapCanNamespace())
    const NODE = Bun.which('node')

    it.if(BUILT && CAN_WRAP && NODE !== null)(
      'leaves the command unable to change the library or what it loads',
      () => {
        const project = join(dir, 'project')
        const installed = join(
          project,
          'node_modules',
          '@anthropic-ai',
          'sandbox-runtime',
        )
        mkdirSync(installed, { recursive: true })
        for (const part of ['dist', 'vendor', 'package.json']) {
          if (existsSync(join(REPO, part))) {
            copyTree(join(REPO, part), join(installed, part))
          }
        }
        const manifest = JSON.parse(
          readFileSync(join(REPO, 'package.json'), 'utf8'),
        ) as { dependencies?: Record<string, string> }
        for (const name of Object.keys(manifest.dependencies ?? {})) {
          copyTree(
            realpathSync(join(REPO, 'node_modules', name)),
            join(project, 'node_modules', name),
          )
        }
        mkdirSync(join(project, 'node_modules', '.bin'), { recursive: true })
        const launcher = join(project, 'node_modules', '.bin', 'srt')
        symlinkSync('../@anthropic-ai/sandbox-runtime/dist/cli.js', launcher)
        const scope = join(project, 'node_modules', '@anthropic-ai')
        const settings = join(dir, 'settings.json')
        writeFileSync(
          settings,
          JSON.stringify({
            network: { allowedDomains: [], deniedDomains: [] },
            filesystem: { denyRead: [], allowWrite: [project], denyWrite: [] },
          }),
        )
        const entry = join(installed, 'dist', 'index.js')
        const dependency = join(project, 'node_modules', 'zod', 'package.json')
        const before = {
          entry: readFileSync(entry, 'utf8'),
          dependency: readFileSync(dependency, 'utf8'),
        }

        const run = spawnSync(
          NODE!,
          [
            join(installed, 'dist', 'cli.js'),
            '-s',
            settings,
            '-c',
            [
              'echo BOOTED',
              `echo w > ${join(project, 'work.txt')} && echo WORK-WRITTEN`,
              `echo x >> ${entry} 2>/dev/null && echo LIBRARY-CHANGED || echo LIBRARY-DENIED`,
              `echo x >> ${dependency} 2>/dev/null && echo DEPENDENCY-CHANGED || echo DEPENDENCY-DENIED`,
              `mv ${installed} ${installed}.aside 2>/dev/null && echo LIBRARY-MOVED || echo MOVE-DENIED`,
              // Nor by way of what holds it: every directory between the
              // package and the write root is held in place with it, so a
              // fresh tree cannot be put where the loader looks.
              `mv ${join(project, 'node_modules', '@anthropic-ai')} ${join(project, 'node_modules', 'scope.aside')} 2>/dev/null && echo SCOPE-MOVED || echo SCOPE-MOVE-DENIED`,
              `mv ${join(project, 'node_modules')} ${join(project, 'node_modules.aside')} 2>/dev/null && echo NODE-MODULES-MOVED || echo NODE-MODULES-MOVE-DENIED`,
              `mkdir -p ${join(project, 'node_modules', 'unrelated')} && echo OTHER-PACKAGE-ADDED`,
              // Nor by putting a package where the loader looks first: beside
              // the library inside its scope, and one level above that.
              `mkdir -p ${join(scope, 'node_modules', 'zod')} 2>/dev/null && echo SCOPE-SHADOW-MADE || echo SCOPE-SHADOW-DENIED`,
              `mkdir -p ${join(project, 'node_modules', 'node_modules', 'zod')} 2>/dev/null && echo UPPER-SHADOW-MADE || echo UPPER-SHADOW-DENIED`,
              // Nor through a second name for the same file, made where
              // writing is allowed.
              `ln ${entry} ${join(project, 'alias.js')} 2>/dev/null && echo x >> ${join(project, 'alias.js')} && echo ALIAS-WRITTEN || echo ALIAS-DENIED`,
              // Nor by re-pointing what npx and npm run start.
              `rm -f ${launcher} 2>/dev/null; ln -sf /bin/true ${launcher} 2>/dev/null && echo LAUNCHER-REPLACED || echo LAUNCHER-DENIED`,
              `ln -s /bin/true ${join(project, 'node_modules', '.bin', 'other')} && echo OTHER-LAUNCHER-ADDED`,
            ].join('; '),
          ],
          { cwd: project, encoding: 'utf8', timeout: 60000 },
        )
        const output = `${run.stdout}${run.stderr}`

        expect(output).toContain('BOOTED')
        expect(output).toContain('WORK-WRITTEN')
        expect(output).toContain('LIBRARY-DENIED')
        expect(output).toContain('DEPENDENCY-DENIED')
        expect(output).toContain('MOVE-DENIED')
        expect(output).toContain('SCOPE-MOVE-DENIED')
        expect(output).toContain('NODE-MODULES-MOVE-DENIED')
        // The rest of node_modules is the project's to change.
        expect(output).toContain('OTHER-PACKAGE-ADDED')
        expect(output).toContain('ALIAS-DENIED')
        expect(output).toContain('SCOPE-SHADOW-DENIED')
        expect(output).toContain('UPPER-SHADOW-DENIED')
        // A launcher is a link, and on Linux a link's own name cannot be held
        // by a mount (one lands on what it leads to), so there it is the
        // stated limit; Seatbelt denies the name itself.
        if (!isLinux) expect(output).toContain('LAUNCHER-DENIED')
        expect(output).toContain('OTHER-LAUNCHER-ADDED')
        expect(readFileSync(entry, 'utf8')).toBe(before.entry)
        expect(readFileSync(dependency, 'utf8')).toBe(before.dependency)
        expect(existsSync(`${installed}.aside`)).toBe(false)
        expect(existsSync(join(project, 'node_modules.aside'))).toBe(false)
        expect(existsSync(join(installed, 'dist', 'cli.js'))).toBe(true)
        if (!isLinux) {
          expect(readlinkSync(launcher)).toBe(
            '../@anthropic-ai/sandbox-runtime/dist/cli.js',
          )
        }
        // Nothing the run put in place to hold those names stays behind.
        expect(existsSync(join(scope, 'node_modules'))).toBe(false)
        expect(existsSync(join(project, 'node_modules', 'node_modules'))).toBe(
          false,
        )
      },
      120000,
    )
  })
})
