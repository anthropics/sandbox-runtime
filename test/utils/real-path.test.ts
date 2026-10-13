import {
  afterAll,
  afterEach,
  beforeAll,
  describe,
  expect,
  it,
  spyOn,
} from 'bun:test'
import * as fc from 'fast-check'
import { spawnSync } from 'node:child_process'
import * as fs from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, relative, resolve } from 'node:path'
import { realPathOf } from '../../src/utils/real-path.js'
import { isWindows } from '../helpers/platform.js'

/** What a call gives: its value, or the code of what it throws. */
function answer(call: () => string): string {
  try {
    return call()
  } catch (error) {
    return String((error as NodeJS.ErrnoException).code)
  }
}

describe.if(!isWindows)('realPathOf', () => {
  let root: string
  const savedCwd = process.cwd()
  /** As written: `join` would fold what `p` holds. */
  const at = (p: string): string => `${root}/${p}`

  beforeAll(() => {
    root = fs.realpathSync(fs.mkdtempSync(join(tmpdir(), 'real-path-')))
    for (const dir of [
      'a\\b/in',
      'a/b/in',
      'alone\\',
      'plain/in',
      'shut\\/in',
    ]) {
      fs.mkdirSync(at(dir), { recursive: true })
    }
    for (const file of [
      'a\\b/file',
      'a/b/file',
      'alone\\/file',
      'plain/file',
      'file',
    ]) {
      fs.writeFileSync(at(file), '')
    }
    for (const [link, target] of [
      ['to-it', 'a\\b'],
      ['to-it-from-the-root', at('a\\b')],
      ['a\\b/out', '../plain'],
      ['a\\b/up-behind-a-link', 'out/../file'],
      ['a\\b/slashes', './/in/.//'],
      ['a\\b/nowhere', 'not-there'],
      ['a\\b/round', 'round'],
      ['a\\b/up-from-a-file', 'file/..'],
      ['a\\b/in-a-file', 'file/.'],
      ['a\\b/file-as-a-directory', 'file/'],
      ['a\\b/up-from-shut', '../shut\\/..'],
      ['a\\b/1', 'file'],
    ]) {
      fs.symlinkSync(target!, at(link!))
    }
    for (let i = 2; i <= 41; i++) fs.symlinkSync(`${i - 1}`, at(`a\\b/${i}`))
    fs.chmodSync(at('shut\\'), 0o600)
  })

  afterEach(() => process.chdir(savedCwd))

  afterAll(() => {
    fs.chmodSync(at('shut\\'), 0o700)
    fs.rmSync(root, { recursive: true, force: true })
  })

  it.each([
    // The name itself, with another file where slashes would lead or none.
    ['a\\b', 'a\\b'],
    ['a\\b/file', 'a\\b/file'],
    ['alone\\', 'alone\\'],
    ['a/b/file', 'a/b/file'],
    // Links to it, from it and in it.
    ['to-it/file', 'a\\b/file'],
    ['to-it-from-the-root/in', 'a\\b/in'],
    ['a\\b/out/file', 'plain/file'],
    ['a\\b/40', 'a\\b/file'],
    // In a link's target `..` is the parent of where the way has led.
    ['a\\b/up-behind-a-link', 'file'],
    ['a\\b/slashes', 'a\\b/in'],
    // In the name given they are folded in text.
    ['a\\b/out/../file', 'a\\b/file'],
    ['a\\b/file/../in', 'a\\b/in'],
    ['a\\b/not-there/..', 'a\\b'],
    ['a\\b/./in//', 'a\\b/in'],
    ['a\\b/..', ''],
    ['a\\b/file/', 'a\\b/file'],
  ])('%s is %s', (given, real) => {
    expect(realPathOf(at(given))).toBe(resolve(at(real)))
  })

  it.each([
    ['a\\b/not-there', 'ENOENT'],
    ['not\\there', 'ENOENT'],
    ['a\\b/nowhere', 'ENOENT'],
    ['a\\b/nowhere/in', 'ENOENT'],
    ['a\\b/file/in', 'ENOTDIR'],
    ['a\\b/up-from-a-file', 'ENOTDIR'],
    ['a\\b/in-a-file', 'ENOTDIR'],
    ['a\\b/file-as-a-directory', 'ENOTDIR'],
    ['a\\b/round', 'ELOOP'],
    ['a\\b/round/in', 'ELOOP'],
    ['a\\b/41', 'ELOOP'],
    [`a\\b/${'n'.repeat(256)}`, 'ENAMETOOLONG'],
  ])('%s fails with %s', (given, code) => {
    expect(answer(() => realPathOf(at(given)))).toBe(code)
  })

  // root searches a directory of any mode.
  it.if(process.getuid?.() !== 0).each(['shut\\/in', 'a\\b/up-from-shut'])(
    '%s fails with EACCES',
    given => {
      expect(answer(() => realPathOf(at(given)))).toBe('EACCES')
    },
  )

  it('says which path had too many links', () => {
    expect(() => realPathOf(at('a\\b/round'))).toThrow(
      expect.objectContaining({ syscall: 'realpath', path: at('a\\b/round') }),
    )
  })

  it.each([
    ['a\\b', 'file', 'a\\b/file'],
    ['a\\b', '.', 'a\\b'],
    ['a\\b', '..', ''],
    ['a\\b/in', '../out/file', 'plain/file'],
    ['alone\\', '.', 'alone\\'],
    ['alone\\', 'file', 'alone\\/file'],
    ['plain', '../a\\b/file', 'a\\b/file'],
    ['plain', 'file', 'plain/file'],
  ])('in %s, %s is %s', (cwd, given, real) => {
    process.chdir(at(cwd))

    expect(realPathOf(given)).toBe(resolve(at(real)))
  })

  it('is the root for the root', () => {
    fs.symlinkSync('/', at('a\\b/root'))

    expect(realPathOf(at('a\\b/root'))).toBe('/')
    expect(realPathOf(at('a\\b/root/..'))).toBe(at('a\\b'))
    expect(realPathOf(at('a\\b/root/../..'))).toBe(root)
  })

  describe('what it asks', () => {
    const CALLS = ['realpathSync', 'lstatSync', 'readlinkSync'] as const
    function asked(given: string): string[] {
      const calls: string[] = []
      const spies = CALLS.map(call => {
        const real = fs[call] as (...args: unknown[]) => unknown
        return spyOn(fs, call).mockImplementation(((...args: unknown[]) => {
          calls.push(`${call} ${String(args[0])}`)
          return real(...args)
        }) as never)
      })
      try {
        realPathOf(given)
      } finally {
        spies.forEach(spy => spy.mockRestore())
      }
      return calls
    }

    it.each(['plain/file', 'to-it/file', 'plain/../plain//in/'])(
      'hands %s, which holds no backslash, to realpathSync as it is',
      given => {
        expect(asked(at(given))[0]).toBe(`realpathSync ${at(given)}`)
      },
    )

    it('asks about each component once where the name holds one', () => {
      const above = [...root.matchAll(/(?<=.)\/|$/g)].map(
        cut => `lstatSync ${root.slice(0, cut.index)}`,
      )

      expect(asked(at('a\\b/out/file'))).toEqual([
        'lstatSync /.',
        ...above,
        `lstatSync ${at('a\\b')}`,
        `lstatSync ${at('a\\b/out')}`,
        `readlinkSync ${at('a\\b/out')}`,
        `lstatSync ${at('a\\b')}/.`,
        `lstatSync ${at('plain')}`,
        `lstatSync ${at('plain/file')}`,
      ])
    })

    it('hands every name to realpathSync on Windows, where a backslash separates', () => {
      const platform = Object.getOwnPropertyDescriptor(process, 'platform')!
      Object.defineProperty(process, 'platform', { value: 'win32' })
      try {
        expect(asked(at('to-it'))).toContain(`realpathSync ${at('to-it')}`)
        expect(answer(() => asked(at('a\\b')).join())).not.toContain(
          'lstatSync',
        )
      } finally {
        Object.defineProperty(process, 'platform', platform)
      }
    })
  })
})

/**
 * Trees of directories, files and links whose names hold backslashes, beside
 * what the same names lead to with slashes. No file has two names but by a
 * link, so its real path is the one path to it that crosses none.
 */
describe.if(!isWindows)('property: realPathOf', () => {
  const NAMES = ['a', 'b', 'a\\b', 'b\\', '\\a', '..\\a']
  const segments = (maxLength: number) =>
    fc.array(fc.constantFrom(...NAMES, ...NAMES, '..', '..', '.', ''), {
      maxLength,
    })
  /** Where an entry goes, by the index of an earlier one, its name, and what
   *  it is: a link leads to an earlier entry or along `way`, from the root
   *  of the tree or from where it lies. */
  const entry = fc.record({
    inside: fc.nat(),
    name: fc.constantFrom(...NAMES),
    kind: fc.constantFrom('directory', 'directory', 'file', 'link', 'link'),
    to: fc.option(fc.nat()),
    way: segments(4),
    fromRoot: fc.boolean(),
  })
  const IN_NODE = `
    import fs from 'node:fs'
    const { realPathOf } = await import(process.argv[1])
    const answer = call => { try { return call() } catch (error) { return error.code } }
    const { paths, askNode } = JSON.parse(fs.readFileSync(0, 'utf8'))
    console.log(JSON.stringify(paths.map(p => [
      (askNode || p.includes('\\\\')) && answer(() => realPathOf(p)),
      askNode && answer(() => fs.realpathSync(p))])))`
  /** The file the kernel finds at `p`, or the code it refuses with. */
  const fileAt = (p: string): string =>
    answer(() => {
      const { dev, ino } = fs.statSync(p)
      return `${dev}:${ino}`
    })
  const linksOnTheWayTo = (p: string): string[] =>
    [...p.matchAll(/(?<=.)\/|$/g)]
      .map(cut => p.slice(0, cut.index))
      .filter(upTo => fs.lstatSync(upTo).isSymbolicLink())

  it('leads where the kernel leads and crosses no link, and is what Node gives', () => {
    fc.assert(
      fc.property(
        fc.constantFrom('real-path-', 'real\\path-'),
        fc.array(entry, { minLength: 8, maxLength: 24 }),
        fc.array(fc.tuple(fc.nat(), segments(3)), {
          minLength: 30,
          maxLength: 30,
        }),
        (prefix, entries, questions) => {
          const root = fs.mkdtempSync(join(fs.realpathSync(tmpdir()), prefix))
          try {
            const directories = [root]
            const made = [root]
            const pick = (from: string[], n: number) => from[n % from.length]!
            const isName = (s: string) => !['', '.', '..'].includes(s)
            let upBehindAName = false
            for (const { inside, name, kind, to, way, fromRoot } of entries) {
              const p = join(pick(directories, inside), name)
              if (fs.existsSync(p) || made.includes(p)) continue
              if (kind === 'directory') {
                fs.mkdirSync(p)
                directories.push(p)
              } else if (kind === 'file') {
                fs.writeFileSync(p, '')
              } else {
                const led = to === null ? way.join('/') : pick(made, to)
                const target =
                  to === null
                    ? (fromRoot ? `${root}/` : '') + led
                    : fromRoot
                      ? led
                      : relative(dirname(p), led)
                if (target === '') continue
                fs.symlinkSync(target, p)
                upBehindAName ||=
                  to === null &&
                  way.some((s, i) => s === '..' && way.slice(0, i).some(isName))
              }
              made.push(p)
            }
            // What a slash after a file's name does is each runtime's own.
            const paths = questions.map(([from, way]) =>
              [pick(made, from), ...way].join('/').replace(/\/+$/, ''),
            )
            // Node folds a link's target in text, so where one goes up from
            // behind a name its own answer can differ, or never come. It is
            // also what realPathOf gives there for a name with no backslash.
            const askNode = !upBehindAName
            const { stdout, stderr, error } = spawnSync(
              'node',
              [
                '--experimental-strip-types',
                '--no-warnings',
                '--input-type=module',
                '-e',
                IN_NODE,
                resolve(import.meta.dirname, '../../src/utils/real-path.ts'),
              ],
              {
                input: JSON.stringify({ paths, askNode }),
                encoding: 'utf8',
                timeout: 20_000,
              },
            )
            expect([error, stderr]).toEqual([undefined, ''])
            const inNode = JSON.parse(stdout) as string[][]
            paths.forEach((p, i) => {
              const real = answer(() => realPathOf(p))
              expect([p, real.startsWith('/') ? fileAt(real) : real]).toEqual([
                p,
                fileAt(resolve(p)),
              ])
              if (real.startsWith('/')) {
                expect([p, resolve(real), linksOnTheWayTo(real)]).toEqual([
                  p,
                  real,
                  [],
                ])
              }
              const [there, own] = inNode[i]!
              if (askNode || p.includes('\\')) {
                expect([p, there]).toEqual([p, real])
              }
              if (askNode) expect([p, own]).toEqual([p, real])
            })
          } finally {
            fs.rmSync(root, { recursive: true, force: true })
          }
        },
      ),
      { numRuns: 60 },
    )
  }, 120_000)
})
