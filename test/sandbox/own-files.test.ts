import { afterEach, beforeEach, describe, expect, it } from 'bun:test'
import { spawnSync } from 'node:child_process'
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import {
  installedPackageDirs,
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

      expect(installedPackageDirs(moduleFile).sort()).toEqual(
        [root, a, b, c].sort(),
      )
    })

    it('prefers the copy nearest the package that asks, as the loader does', () => {
      const project = join(dir, 'project')
      const { root, moduleFile } = installLibrary(project, { a: '1' })
      makePackage(join(project, 'node_modules', 'a'))
      const nested = makePackage(join(root, 'node_modules', 'a'))

      expect(installedPackageDirs(moduleFile).sort()).toEqual(
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

      expect(installedPackageDirs(moduleFile).sort()).toEqual(
        [root, a, b].sort(),
      )
    })

    it('finds nothing for a checkout, which is the project being worked on', () => {
      const checkout = makePackage(join(dir, 'checkout'), {
        dependencies: { a: '1' },
      })
      makePackage(join(checkout, 'node_modules', 'a'))
      mkdirSync(join(checkout, 'src', 'sandbox'), { recursive: true })

      expect(
        installedPackageDirs(join(checkout, 'src', 'sandbox', 'own-files.ts')),
      ).toEqual([])
    })

    it('finds nothing where there is no package on disk', () => {
      expect(
        installedPackageDirs(
          join(dir, 'node_modules', 'gone', 'dist', 'sandbox', 'own-files.js'),
        ),
      ).toEqual([])
      // Compiled into an application: the module has a location, not a file.
      expect(
        installedPackageDirs('/$bunfs/root/node_modules/x/dist/sandbox/m.js'),
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
        expect(readFileSync(entry, 'utf8')).toBe(before.entry)
        expect(readFileSync(dependency, 'utf8')).toBe(before.dependency)
        expect(existsSync(`${installed}.aside`)).toBe(false)
        expect(existsSync(join(project, 'node_modules.aside'))).toBe(false)
        expect(existsSync(join(installed, 'dist', 'cli.js'))).toBe(true)
      },
      120000,
    )
  })
})
