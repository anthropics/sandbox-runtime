import { describe, it, expect, beforeEach, afterEach } from 'bun:test'
import { spawnSync } from 'node:child_process'
import {
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import {
  wrapCommandWithSandboxLinux,
  cleanupBwrapMountPoints,
  linuxGetCwdMandatoryDenyPaths,
} from '../../src/sandbox/linux-sandbox-utils.js'
import { isLinux } from '../helpers/platform.js'
import { countMounts, lastMountAt } from '../helpers/bwrap-argv.js'
import { bwrapCanNamespace } from '../helpers/bwrap-namespace.js'

/**
 * Nothing can be created below a file, for as long as the file is there. So a
 * file above a write deny is kept there, in a directory the command may write.
 */
describe.if(isLinux)('A file above a write deny', () => {
  const POINTER = 'gitdir: elsewhere\n'
  let base: string
  let area: string
  const savedCwd = process.cwd()

  beforeEach(() => {
    cleanupBwrapMountPoints({ force: true })
    base = realpathSync(mkdtempSync(join(tmpdir(), 'file-above-deny-')))
    area = join(base, 'area')
    mkdirSync(area)
    process.chdir(area)
  })

  afterEach(() => {
    process.chdir(savedCwd)
    cleanupBwrapMountPoints({ force: true })
    rmSync(base, { recursive: true, force: true })
  })

  const wrap = (
    command = 'true',
    denyWithinAllow: string[] = [],
    allowOnly = [area],
  ): Promise<string> =>
    wrapCommandWithSandboxLinux({
      command,
      needsNetworkRestriction: false,
      readConfig: { denyOnly: [] },
      writeConfig: { allowOnly, denyWithinAllow },
    })
  const held = (wrapped: string, file: string): number =>
    countMounts(wrapped, '--ro-bind', file, file)

  describe('in the plan', () => {
    it('a .git that is a file is bound onto itself, once, and nothing below it', async () => {
      writeFileSync(join(area, '.git'), POINTER)
      const wrapped = await wrap()
      expect(held(wrapped, join(area, '.git'))).toBe(1)
      expect(wrapped).not.toContain(join(area, '.git', 'hooks'))
      expect(wrapped).not.toContain(join(area, '.git', 'config'))
    })

    // Rewritten, it sends the host's git to a git directory of the command's
    // own. A checkout that recurses into submodules is refused with it.
    it('one below the working directory is bound onto itself as well', async () => {
      mkdirSync(join(area, 'sub'))
      writeFileSync(join(area, 'sub', '.git'), POINTER)
      expect(held(await wrap(), join(area, 'sub', '.git'))).toBe(1)
    })

    it('a .git that is a directory is denied as before', async () => {
      mkdirSync(join(area, '.git', 'hooks'), { recursive: true })
      writeFileSync(join(area, '.git', 'config'), '')
      const wrapped = await wrap()
      expect(held(wrapped, join(area, '.git', 'hooks'))).toBe(1)
      expect(held(wrapped, join(area, '.git', 'config'))).toBe(1)
    })

    it('no .git at all: nothing is laid there', async () => {
      const wrapped = await wrap()
      expect(lastMountAt(wrapped, join(area, '.git'))).toBeUndefined()
      expect(wrapped).not.toContain(`${join(area, '.git')}/`)
    })

    // Read without the scan too, which would find the file as well.
    it.each([
      ['a file', ['.git']],
      [
        'a directory',
        ['.git/hooks', '.git/commondir', '.git/config', '.git/config.worktree'],
      ],
      ['not there', []],
    ])('what follows from the cwd alone, .git being %s', (what, denied) => {
      if (what === 'a file') writeFileSync(join(area, '.git'), POINTER)
      if (what === 'a directory') mkdirSync(join(area, '.git'))
      expect(
        linuxGetCwdMandatoryDenyPaths().filter(p =>
          /\/\.git(\/|$)/.test(p.slice(area.length)),
        ),
      ).toEqual(denied.map(name => join(area, name)))
    })

    it('two denies below one file: one bind', async () => {
      writeFileSync(join(area, 'f'), 'mine')
      const wrapped = await wrap('true', [
        join(area, 'f', 'x'),
        join(area, 'f', 'y', 'z'),
      ])
      expect(held(wrapped, join(area, 'f'))).toBe(1)
    })

    it('a file that is denied itself too: one bind', async () => {
      writeFileSync(join(area, 'f'), 'mine')
      for (const denies of [
        [join(area, 'f'), join(area, 'f', 'x')],
        [join(area, 'f', 'x'), join(area, 'f')],
      ]) {
        expect(held(await wrap('true', denies), join(area, 'f'))).toBe(1)
      }
    })

    it('where the command may not write, nothing is laid', async () => {
      writeFileSync(join(base, 'f'), 'mine')
      expect(await wrap('true', [join(base, 'f', 'x')])).not.toContain(
        join(base, 'f'),
      )
    })

    it('where it may write the file and not its directory, the file is not held', async () => {
      const f = join(base, 'f')
      writeFileSync(f, 'mine')
      const wrapped = await wrap('true', [join(f, 'x')], [f])
      expect(held(wrapped, f)).toBe(0)
      expect(lastMountAt(wrapped, f)).toBe(`--bind ${f} ${f}`)
    })
  })

  describe.if(bwrapCanNamespace())('in the sandbox', () => {
    const run = async (
      command: string,
      denies: string[] = [],
      allowOnly?: string[],
    ): Promise<string> => {
      const r = spawnSync(await wrap(command, denies, allowOnly), {
        shell: true,
        encoding: 'utf8',
        timeout: 20_000,
      })
      cleanupBwrapMountPoints()
      expect(r.stderr).not.toContain('bwrap:')
      return r.stdout.trim()
    }
    // Each way of putting something else at the name, and what it is after.
    const REPLACE = (name: string): string =>
      `mv ${name} aside 2>/dev/null; echo mv=$?; rm -rf ${name} 2>/dev/null; echo rm=$?; ` +
      `mkdir -p ${name}/hooks 2>/dev/null; echo mkdir=$?; echo x > ${name} 2>/dev/null; echo write=$?`
    const REFUSED = 'mv=1\nrm=1\nmkdir=1\nwrite=1'

    it('a .git that is a file stays one', async () => {
      writeFileSync(join(area, '.git'), POINTER)
      expect(await run(REPLACE('.git'))).toBe(REFUSED)
      expect(readFileSync(join(area, '.git'), 'utf8')).toBe(POINTER)
    })

    it('a command beside it runs, and writes what it may', async () => {
      writeFileSync(join(area, '.git'), POINTER)
      expect(await run('cat .git; echo mine > new; cat new')).toBe(
        `${POINTER}mine`,
      )
    })

    it('a configured deny below a file: the file stays', async () => {
      writeFileSync(join(area, 'f'), 'mine')
      expect(await run(REPLACE('f'), [join(area, 'f', 'x')])).toBe(REFUSED)
      expect(readFileSync(join(area, 'f'), 'utf8')).toBe('mine')
    })

    it('a file that alone may be written is written, and stays one', async () => {
      const f = join(base, 'f')
      writeFileSync(f, 'mine')
      expect(
        await run(
          `echo more >> ${f}; echo append=$?; cd ${base}; ${REPLACE('f')}`,
          [join(f, 'x')],
          [f],
        ),
      ).toBe('append=0\nmv=1\nrm=1\nmkdir=1\nwrite=0')
      expect(readFileSync(f, 'utf8')).toBe('x\n')
    })

    it('a protected name that leads through a file: the file stays', async () => {
      writeFileSync(join(area, 'f'), 'mine')
      symlinkSync('f/x', join(area, '.bashrc'))
      expect(await run(REPLACE('f'))).toBe(REFUSED)
      expect(readFileSync(join(area, 'f'), 'utf8')).toBe('mine')
    })

    // An empty one looks like a mount point bubblewrap has made.
    it.each([
      ['.git', POINTER, []],
      ['f', 'mine', ['f/x']],
      ['f', '', ['f/x']],
    ])(
      "%s holding %p is the caller's own afterwards: there, as it was, and writable",
      async (name, content, denies) => {
        writeFileSync(join(area, name), content, { mode: 0o644 })
        await run(
          'true',
          denies.map(d => join(area, d)),
        )
        cleanupBwrapMountPoints({ force: true })
        expect(readFileSync(join(area, name), 'utf8')).toBe(content)
        expect(lstatSync(join(area, name)).mode & 0o777).toBe(0o644)
        writeFileSync(join(area, name), 'changed')
      },
    )
  })
})
