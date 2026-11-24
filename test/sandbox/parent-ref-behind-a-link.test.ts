import { describe, it, expect, beforeEach, afterEach } from 'bun:test'
import { spawnSync } from 'node:child_process'
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { wrapCommandWithSandboxLinux } from '../../src/sandbox/linux-sandbox-utils.js'
import { wrapCommandWithSandboxMacOS } from '../../src/sandbox/macos-sandbox-utils.js'
import { normalizePathForSandbox } from '../../src/sandbox/sandbox-utils.js'
import { bwrapCanNamespace } from '../helpers/bwrap-namespace.js'
import { isLinux, isMacOS, isWindows } from '../helpers/platform.js'

/**
 * A `..` behind a link in a configured name is the parent of where the link
 * leads, as the kernel and realpath(3) read it, not the directory that holds
 * the link. A caller that checks a grant with realpath(3) before handing it
 * over checks the directory that is then granted.
 *
 *   BASE/home/inner -> deep/in         so BASE/home/inner/.. is BASE/home/deep
 *   BASE/home/out   -> BASE/other/in   so BASE/home/out/..   is BASE/other
 *
 * That is what the name names wherever it lies, outside the directory that
 * holds the link too: no spelling of it without the `..` is there to keep.
 * Where the kernel has no answer for the name, it is read in text.
 */
describe.if(!isWindows)('A .. behind a link in a configured name', () => {
  let BASE: string
  let HOME: string // holds the links
  let DEEP: string // in HOME, where `inner/..` leads
  let OTHER: string // beside HOME, where `out/..` leads
  const savedCwd = process.cwd()

  beforeEach(() => {
    // Where the temp dir really is: macOS names it through a link.
    BASE = realpathSync(mkdtempSync(join(tmpdir(), 'parent-ref-')))
    HOME = join(BASE, 'home')
    DEEP = join(HOME, 'deep')
    OTHER = join(BASE, 'other')
    mkdirSync(join(DEEP, 'in'), { recursive: true })
    mkdirSync(join(OTHER, 'in'), { recursive: true })
    symlinkSync('deep/in', join(HOME, 'inner'))
    symlinkSync(join(OTHER, 'in'), join(HOME, 'out'))
    for (const dir of [HOME, DEEP, OTHER]) {
      writeFileSync(join(dir, 'file'), 'original')
    }
  })

  afterEach(() => {
    process.chdir(savedCwd)
    rmSync(BASE, { recursive: true, force: true })
  })

  it('is the parent of where the link leads, as the kernel has it', () => {
    const spelled = `${HOME}/inner/..`

    expect(normalizePathForSandbox(spelled)).toBe(DEEP)
    expect(statSync(spelled).ino).toBe(statSync(DEEP).ino)
  })

  it.each([
    ['inner/..', ''],
    ['./inner/..', ''],
    ['../home/inner/..//', ''],
    ['inner/../../inner/..', ''],
    ['not-there/../deep', ''],
    ['file/../deep/not-there/..', ''],
  ])('is that for the relative name %s too', (given, under) => {
    process.chdir(HOME)

    expect(normalizePathForSandbox(given)).toBe(DEEP + under)
  })

  it('is that in the directory a pattern starts from', () => {
    expect(normalizePathForSandbox(`${HOME}/inner/../*.txt`)).toBe(
      `${DEEP}/*.txt`,
    )
  })

  it('takes back in text a name that is not there', () => {
    expect(normalizePathForSandbox(`${HOME}/not-there/../deep`)).toBe(DEEP)
  })

  it.each([
    ['out/..', () => OTHER],
    ['out/../file', () => `${OTHER}/file`],
    ['out/../*.txt', () => `${OTHER}/*.txt`],
    ['inner/../file', () => `${DEEP}/file`],
    ['out/../../home/out/../..', () => BASE],
  ])(
    'is that for %s too, which leads away from what it spells in text',
    (given, real) => {
      expect(normalizePathForSandbox(`${HOME}/${given}`)).toBe(real())
      process.chdir(HOME)
      expect(normalizePathForSandbox(given)).toBe(real())
    },
  )

  // The kernel has no answer for these, so the text is all there is to read.
  it.each([
    ['not-there', '/..', ''],
    ['not-there', '/../deep', '/deep'],
    ['not-there', '/../*.txt', '/*.txt'],
    ['../not-there', '/..', ''],
    ['/not-there', '/..', ''],
    ['/not-there/deeper', '/..', ''],
    ['round', '/..', ''],
    ['round/in', '/../deep', '/deep'],
  ])(
    'folds in text behind a link to %s, which leads nowhere: round%s',
    (target, given, under) => {
      symlinkSync(target, join(HOME, 'round'))

      expect(normalizePathForSandbox(`${HOME}/round${given}`)).toBe(
        HOME + under,
      )
    },
  )

  // realpath(3) has no answer for these either: a name in them is not there,
  // or is a file.
  it.each([
    ['/etc', 'round/../not-there/..', ''],
    ['/etc', 'not-there/../round/..', ''],
    ['../other/in', 'round/../not-there/..', ''],
    ['../other/in', 'round/../file/..', ''],
    ['../other/in', 'round/../not-there/../deep', '/deep'],
  ])(
    'folds every .. in text, behind a link to %s too, where one of them has nothing to go up from: %s',
    (target, given, under) => {
      symlinkSync(target, join(HOME, 'round'))

      expect(normalizePathForSandbox(`${HOME}/${given}`)).toBe(HOME + under)
      process.chdir(HOME)
      expect(normalizePathForSandbox(given)).toBe(HOME + under)
    },
  )

  it('folds a relative name in text where neither reading names what is there', () => {
    symlinkSync('../absent', join(HOME, 'round'))
    process.chdir(HOME)

    expect(normalizePathForSandbox('round/../absent')).toBe(`${HOME}/absent`)
  })

  it.each(['out/../absent', 'out/../absent/*.txt'])(
    'keeps %s as written, which is not there in either reading',
    given => {
      expect(normalizePathForSandbox(`${HOME}/${given}`)).toBe(
        `${HOME}/${given}`,
      )
    },
  )

  // root searches a directory of any mode.
  it.if(process.getuid?.() !== 0)(
    'is the directory that cannot be searched, for a .. behind a name in it',
    () => {
      mkdirSync(join(HOME, 'shut', 'in'), { recursive: true })
      chmodSync(join(HOME, 'shut'), 0o600)
      try {
        expect(normalizePathForSandbox(`${HOME}/shut/in/..`)).toBe(
          `${HOME}/shut`,
        )
      } finally {
        chmodSync(join(HOME, 'shut'), 0o700)
      }
    },
  )

  it('is the root where the link leads to a directory in the root', () => {
    symlinkSync('/etc', join(HOME, 'etc'))

    expect(normalizePathForSandbox(`${HOME}/etc/..`)).toBe('/')
  })

  // Seatbelt compares the path the kernel resolved, which holds no `..`.
  describe('as a deny, in the Seatbelt profile', () => {
    /** The profile for a command with BASE as its one write root. */
    const profile = (
      read: { denyOnly: string[] },
      write: { denyWithinAllow: string[]; literalDenyWithinAllow?: string[] },
    ): string =>
      wrapCommandWithSandboxMacOS({
        command: 'true',
        needsNetworkRestriction: false,
        readConfig: read,
        writeConfig: { allowOnly: [BASE], ...write },
      })

    it.each([
      ['a write deny', { denyWithinAllow: ['out/..'] }],
      [
        'a write deny that is no pattern',
        { denyWithinAllow: [], literalDenyWithinAllow: ['out/..'] },
      ],
    ])('names %s where it leads as well', (_, write) => {
      process.chdir(HOME)

      const said = profile({ denyOnly: [] }, write)

      expect(said).toContain(`(subpath "${OTHER}")`)
      expect(said).not.toContain(`(subpath "${HOME}")`)
    })

    it.each([
      ['a write deny', false],
      ['a read deny', true],
    ])(
      'names %s that goes up from a link that leads nowhere where the text folds it',
      (_, isRead) => {
        symlinkSync('not-there', join(HOME, 'nowhere'))
        const denied = [`${HOME}/nowhere/..`]

        const said = profile(
          { denyOnly: isRead ? denied : [] },
          { denyWithinAllow: isRead ? [] : denied },
        )

        expect(said).toContain(`(subpath "${HOME}")`)
      },
    )
  })

  // The working directory is a real path, whatever name it was entered by.
  it.each([
    ['..', '/other'],
    ['../file', '/other/file'],
    ['../not-there', '/other/not-there'],
    ['./../..//', ''],
  ])(
    'goes up from the working directory for %s, which opens the name',
    (given, under) => {
      process.chdir(`${HOME}/out`)

      expect(normalizePathForSandbox(given)).toBe(BASE + under)
    },
  )

  describe.if((isLinux && bwrapCanNamespace()) || isMacOS)(
    'in the sandbox',
    () => {
      /** What a command said that tries to change the file in each of
       *  `dirs`, with `root` as its one write root and `denied` denied
       *  within it. */
      async function tried(
        root: string,
        dirs: string[],
        denied: string[] = [],
      ): Promise<string> {
        const attempts = dirs.map(
          dir =>
            `if ( echo changed > '${dir}/file' ) 2>/dev/null; then echo WROTE; else echo refused; fi`,
        )
        const options = {
          // Shows first that the sandbox itself started.
          command: ['echo started', ...attempts].join('; '),
          needsNetworkRestriction: false,
          readConfig: { denyOnly: [] },
          writeConfig: { allowOnly: [root], denyWithinAllow: denied },
        }
        const wrapped = isLinux
          ? await wrapCommandWithSandboxLinux(options)
          : wrapCommandWithSandboxMacOS(options)
        const result = spawnSync(wrapped, {
          shell: true,
          encoding: 'utf8',
          timeout: 30000,
          // Under no write root, so nothing of the working directory's is
          // protected or made.
          cwd: BASE,
        })
        return String(result.stdout ?? '') + String(result.stderr ?? '')
      }
      const holds = (dir: string): string =>
        readFileSync(join(dir, 'file'), 'utf8')

      it('grants the parent of where the link leads, not the directory that holds the link', async () => {
        expect(await tried(`${HOME}/inner/..`, [DEEP, HOME])).toBe(
          'started\nWROTE\nrefused\n',
        )
        expect([holds(DEEP), holds(HOME)]).toEqual(['changed\n', 'original'])
      })

      it('grants it where the link leads out of the directory that holds it too', async () => {
        expect(await tried(`${HOME}/out/..`, [OTHER, HOME])).toBe(
          'started\nWROTE\nrefused\n',
        )
        expect([holds(OTHER), holds(HOME)]).toEqual(['changed\n', 'original'])
      })

      it('hides, as a read deny, where the link leads up to and not the directory that holds the link', async () => {
        const options = {
          command: `echo started; cat '${OTHER}/file' 2>/dev/null || echo hidden; cat '${HOME}/file'`,
          needsNetworkRestriction: false,
          readConfig: { denyOnly: [`${HOME}/out/..`] },
          writeConfig: { allowOnly: [], denyWithinAllow: [] },
        }
        const wrapped = isLinux
          ? await wrapCommandWithSandboxLinux(options)
          : wrapCommandWithSandboxMacOS(options)
        const { stdout } = spawnSync(wrapped, {
          shell: true,
          encoding: 'utf8',
          timeout: 30000,
          cwd: BASE,
        })

        expect(stdout).toBe('started\nhidden\noriginal')
      })

      it('hides, as a read deny, the directory a link that leads nowhere goes up to', async () => {
        symlinkSync('not-there', join(HOME, 'nowhere'))
        const options = {
          command: `echo started; cat '${HOME}/file' 2>/dev/null || echo hidden; cat '${OTHER}/file'`,
          needsNetworkRestriction: false,
          readConfig: { denyOnly: [`${HOME}/nowhere/..`] },
          writeConfig: { allowOnly: [], denyWithinAllow: [] },
        }
        const wrapped = isLinux
          ? await wrapCommandWithSandboxLinux(options)
          : wrapCommandWithSandboxMacOS(options)
        const { stdout } = spawnSync(wrapped, {
          shell: true,
          encoding: 'utf8',
          timeout: 30000,
          cwd: BASE,
        })

        expect(stdout).toBe('started\nhidden\noriginal')
      })

      it('denies, as a write deny, where the link leads up to and not the directory that holds the link', async () => {
        expect(await tried(BASE, [OTHER, HOME], [`${HOME}/out/..`])).toBe(
          'started\nrefused\nWROTE\n',
        )
        expect([holds(OTHER), holds(HOME)]).toEqual(['original', 'changed\n'])
      })
    },
  )
})
