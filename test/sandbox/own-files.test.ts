import { afterEach, beforeEach, describe, expect, it } from 'bun:test'
import { spawnSync } from 'node:child_process'
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { ownInstallWarning } from '../../src/sandbox/own-files.js'
import type { FilesystemPathEntry } from '../../src/sandbox/sandbox-config.js'
import { isWindows } from '../helpers/platform.js'

/** A copy of the library a sandboxed command may write is warned about, not
 *  denied: src/sandbox/own-files.ts says why. */
describe.skipIf(isWindows)('The library installed under a write path', () => {
  let dir: string
  let project: string

  beforeEach(() => {
    dir = realpathSync(mkdtempSync(join(tmpdir(), 'own-files-')))
    project = join(dir, 'project')
  })

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true })
  })

  /** A package at `root`; returns a module inside it. */
  function makePackage(root: string): string {
    mkdirSync(join(root, 'dist'), { recursive: true })
    writeFileSync(join(root, 'package.json'), '{}')
    return join(root, 'dist', 'own-files.js')
  }

  /** npm: `<project>/node_modules/<name>`. */
  function npmLayout(name: string): { root: string; link: string } {
    const root = join(project, 'node_modules', name)
    mkdirSync(root, { recursive: true })
    return { root, link: root }
  }

  /** pnpm: `node_modules/.pnpm/<id>/node_modules/<name>`, behind a link. */
  function pnpmLayout(name: string): { root: string; link: string } {
    const store = join(project, 'node_modules', '.pnpm', 'x@1', 'node_modules')
    const [root, link] = [store, join(project, 'node_modules')].map(holder =>
      join(holder, name),
    )
    mkdirSync(root, { recursive: true })
    mkdirSync(dirname(link), { recursive: true })
    symlinkSync(root, link)
    return { root, link }
  }

  describe('whether to warn', () => {
    for (const layout of [npmLayout, pnpmLayout]) {
      it(`warns with the project writable: ${layout.name}`, () => {
        const { root, link } = layout('@scope/lib')
        const moduleFile = makePackage(root)
        expect(ownInstallWarning([project], moduleFile)).toContain(root)
        // As the loader spells it under --preserve-symlinks.
        expect(
          ownInstallWarning([project], moduleFile.replace(root, link)),
        ).toContain(link)
      })
    }

    it('goes by where a path really is, on both sides', () => {
      const moduleFile = makePackage(npmLayout('lib').root)
      const link = join(dir, 'link')
      symlinkSync(project, link)
      expect(ownInstallWarning([link], moduleFile)).toBeDefined()
      expect(
        ownInstallWarning([project], moduleFile.replace(project, link)),
      ).toBeDefined()
    })

    it('does not warn where no write path covers the copy', () => {
      const moduleFile = makePackage(npmLayout('lib').root)
      // Nothing, a directory beside it, a name that merely starts the same.
      for (const allowed of [[], [join(project, 'src')], [join(dir, 'pro')]]) {
        expect(ownInstallWarning(allowed, moduleFile)).toBeUndefined()
      }
      // An install outside the project, as a global one is.
      const global = makePackage(join(dir, 'lib', 'node_modules', 'lib'))
      expect(ownInstallWarning([project], global)).toBeUndefined()
      expect(ownInstallWarning([join(dir, 'lib')], global)).toBeDefined()
    })

    it('does not warn for a checkout, which is the project being worked on', () => {
      expect(ownInstallWarning([dir], makePackage(project))).toBeUndefined()
      // Nor for this repository: no other test sees the warning.
      expect(ownInstallWarning(['/'])).toBeUndefined()
    })

    it('does not warn where there is no package on disk', () => {
      // Compiled into an application: the module has a location, not a file.
      expect(
        ownInstallWarning(['/'], '/$bunfs/root/node_modules/x/dist/m.js'),
      ).toBeUndefined()
    })
  })

  /** The library's source placed in a project as a package manager would
   *  place it, and loaded from there. */
  describe('loaded from a project', () => {
    const REPO = join(import.meta.dir, '..', '..')
    const MANIFEST = join(REPO, 'package.json')
    const NAME = '@anthropic-ai/sandbox-runtime'

    /** The source placed by `layout`, its dependencies beside it. */
    function install(layout: typeof npmLayout): { root: string; link: string } {
      const { root, link } = layout(NAME)
      spawnSync('cp', ['-R', join(REPO, 'src'), MANIFEST, root])
      symlinkSync(join(REPO, 'vendor'), join(root, 'vendor'))
      const manifest = JSON.parse(readFileSync(MANIFEST, 'utf8')) as {
        dependencies: Record<string, string>
      }
      for (const name of Object.keys(manifest.dependencies)) {
        const beside = join(root.slice(0, -NAME.length), name)
        mkdirSync(dirname(beside), { recursive: true })
        symlinkSync(realpathSync(join(REPO, 'node_modules', name)), beside)
      }
      return { root, link }
    }

    /**
     * Runs `body` in the project and returns the JSON it prints. It has `s`,
     * the manager of the copy at `link`; `filesystem`, a policy with
     * `allowWrite`; and `warnings()`, the dependency check's under a policy.
     */
    function run(
      link: string,
      allowWrite: FilesystemPathEntry,
      body: string,
    ): { printed: unknown; stderr: string } {
      const child = spawnSync(
        process.execPath,
        [
          '-e',
          `const { SandboxManager: s } = await import(${JSON.stringify(join(link, 'src', 'index.ts'))})
           const filesystem = { denyRead: [], allowWrite: [${JSON.stringify(allowWrite)}], denyWrite: [] }
           const warnings = filesystem => {
             s.updateConfig({ network: { allowedDomains: [], deniedDomains: [] }, filesystem })
             return s.checkDependencies().warnings
           }
           ${body}`,
        ],
        {
          cwd: project,
          encoding: 'utf8',
          env: { ...process.env, SRT_DEBUG: '1' },
          timeout: 60000,
        },
      )
      if (child.status !== 0) throw new Error(child.stderr)
      return { printed: JSON.parse(child.stdout), stderr: child.stderr }
    }

    const spelled = (path: string): FilesystemPathEntry => path
    const marked = (path: string): FilesystemPathEntry => ({
      path,
      literal: true,
    })

    for (const [layout, entry] of [
      [npmLayout, spelled],
      [pnpmLayout, spelled],
      [npmLayout, marked],
    ] as const) {
      it(`is reported by the dependency check and logged once: ${layout.name}, write path ${entry.name}`, () => {
        const { root, link } = install(layout)
        const { printed, stderr } = run(
          link,
          entry(project),
          `await s.wrapWithSandbox('true', undefined, { filesystem })
           await s.wrapWithSandbox('true', undefined, { filesystem })
           console.log(JSON.stringify([
             warnings(filesystem),
             warnings({ ...filesystem, disabled: true }),
           ]))`,
        )

        const about = (text: string): boolean => text.includes(`${root},`)
        const [enabled, disabled] = printed as string[][]
        expect(enabled.filter(about)).toHaveLength(1)
        // No path is outside the write paths when every path may be written.
        expect(disabled.filter(about)).toEqual([])
        expect(stderr.split('\n').filter(about)).toHaveLength(1)
      }, 120000)
    }

    it('leaves a malformed entry to whoever enforces the config', () => {
      const { root, link } = install(npmLayout)
      const { printed } = run(
        link,
        project,
        `console.log(JSON.stringify([
           warnings({ ...filesystem, denyRead: [{ path: '/x' }] }),
           [await s.wrapWithSandbox('true').catch(e => e.message)],
         ]))`,
      )
      const [warnings, [wrap]] = printed as string[][]
      expect(warnings.filter(w => w.includes(root))).toEqual([])
      expect(wrap).toContain('must be a path, or { path, literal: true }')
    }, 120000)

    it('says nothing where the working directory is gone', () => {
      const { root, link } = install(npmLayout)
      const gone = join(dir, 'gone')
      mkdirSync(gone)
      const { printed } = run(
        link,
        project,
        `process.chdir(${JSON.stringify(gone)})
         require('node:fs').rmdirSync(${JSON.stringify(gone)})
         console.log(JSON.stringify(warnings({ ...filesystem, allowWrite: ['.'] })))`,
      )
      expect((printed as string[]).filter(w => w.includes(root))).toEqual([])
    }, 120000)

    it('fails neither call site, whatever goes wrong in it', () => {
      const { root, link } = install(npmLayout)
      writeFileSync(
        join(root, 'src', 'sandbox', 'own-files.ts'),
        `export function ownInstallWarning() { throw new Error('thrown') }`,
      )
      const { printed } = run(
        link,
        project,
        `const wrapped = await s.wrapWithSandbox('true', undefined, { filesystem })
         console.log(JSON.stringify([typeof wrapped, typeof warnings(filesystem)]))`,
      )
      expect(printed).toEqual(['string', 'object'])
    }, 120000)
  })
})
