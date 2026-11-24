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
import { realPathOf, wayTo } from '../../src/utils/real-path.js'
import { isLinux, isMacOS, isWindows } from '../helpers/platform.js'

/** What a call gives: its value, or the code of what it throws. */
function answer(call: () => string): string {
  try {
    return call()
  } catch (error) {
    return String((error as NodeJS.ErrnoException).code)
  }
}

/** The file the kernel finds at `p`, or the code it refuses with. */
function fileAt(p: string): string {
  return answer(() => {
    const { dev, ino } = fs.statSync(p)
    return `${dev}:${ino}`
  })
}

/**
 * The absolute path `p` as realPathOf reads it: as the kernel does where the
 * kernel has an answer for all of it, and folded in text where it has none.
 */
function asRead(p: string): string {
  const whole = `/${p
    .split('/')
    .filter(name => name !== '' && name !== '.')
    .join('/')}`
  return fileAt(whole).includes(':') ? whole : resolve(p)
}

/**
 * For each of `paths`, in Node: what realPathOf gives, what the C library
 * gives for the name as it is read and, if asked for, Node's own answer. The
 * child is ended hard: a call that does not return hears no signal.
 */
function inNode(paths: string[], askNode = false): string[][] {
  const { stdout, stderr, error } = spawnSync(
    'node',
    [
      '--max-old-space-size=256',
      '--experimental-strip-types',
      '--no-warnings',
      '--input-type=module',
      '-e',
      `
    import fs from 'node:fs'
    const { realPathOf } = await import(process.argv[1])
    const answer = call => { try { return call() } catch (error) { return error.code } }
    const { paths, read, askNode } = JSON.parse(fs.readFileSync(0, 'utf8'))
    console.log(JSON.stringify(paths.map((p, i) => [
      answer(() => realPathOf(p)),
      answer(() => fs.realpathSync.native(read[i])),
      askNode && answer(() => fs.realpathSync(p))])))`,
      resolve(import.meta.dirname, '../../src/utils/real-path.ts'),
    ],
    {
      input: JSON.stringify({ paths, read: paths.map(asRead), askNode }),
      encoding: 'utf8',
      timeout: 20_000,
      killSignal: 'SIGKILL',
    },
  )
  expect([error, stderr]).toEqual([undefined, ''])
  return JSON.parse(stdout) as string[][]
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
      'a/up-and-in/in',
      'alone\\',
      'plain/in',
      'shut\\/in',
    ]) {
      fs.mkdirSync(at(dir), { recursive: true })
    }
    for (const file of [
      'a\\b/file',
      'a/b/file',
      'a/file',
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
      ['plain/out', '../a/b'],
      ['plain/up-behind-a-link', 'out/../file'],
      ['plain/up-and-in', 'out/../up-and-in/in'],
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

  const IS = [
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
    ['plain/up-behind-a-link', 'a/file'],
    ['plain/up-and-in', 'a/up-and-in/in'],
    // In the name given it is that too, where the kernel has an answer for
    // the name: behind a link, the parent of where the link leads.
    ['a\\b/out/../file', 'file'],
    ['a\\b/out/../a\\b/out/..', ''],
    ['to-it/../plain/out/../..', ''],
    ['a\\b/in/../file', 'a\\b/file'],
    ['plain/out/../file', 'a/file'],
    ['plain/out/../../plain/out/..', 'a'],
    ['plain/in/../file', 'plain/file'],
    // Where it has none, they are folded in text.
    ['a\\b/out/../not-there/..', 'a\\b'],
    ['a\\b/nowhere/..', 'a\\b'],
    ['a\\b/round/..', 'a\\b'],
    ['a\\b/1/..', 'a\\b'],
    ['a\\b/file/../in', 'a\\b/in'],
    ['a\\b/not-there/..', 'a\\b'],
    ['a\\b/./in//', 'a\\b/in'],
    ['a\\b/..', ''],
    ['a\\b/file/', 'a\\b/file'],
    ['plain/out/../not-there/../file', 'plain/file'],
    ['plain/file/../in', 'plain/in'],
    ['plain/not-there/..', 'plain'],
    ['plain/./in//', 'plain/in'],
    ['plain/file/', 'plain/file'],
  ] as const
  it.each(IS)('%s is %s', (given, real) => {
    expect(realPathOf(at(given))).toBe(resolve(at(real)))
  })

  const FAILS = [
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
    ['plain/not-there', 'ENOENT'],
    ['plain/file/in', 'ENOTDIR'],
    [`plain/${'n'.repeat(256)}`, 'ENAMETOOLONG'],
  ] as const
  it.each(FAILS)('%s fails with %s', (given, code) => {
    expect(answer(() => realPathOf(at(given)))).toBe(code)
  })

  it('gives all of that in Node too', () => {
    expect(
      inNode([...IS, ...FAILS].map(([given]) => at(given))).map(
        ([there]) => there,
      ),
    ).toEqual([
      ...IS.map(([, real]) => resolve(at(real))),
      ...FAILS.map(([, code]) => code),
    ])
  }, 30_000)

  // macOS lets no such name be made.
  it.if(isLinux)(
    'refuses a way through a name that is no text, and takes U+FFFD in a name for itself, in Node too',
    () => {
      const bytes = Buffer.concat([Buffer.from('../bytes-'), Buffer.of(0xff)])
      fs.mkdirSync(Buffer.concat([Buffer.from(at('plain/')), bytes]))
      fs.mkdirSync(at('bytes-\uFFFD'))
      const rows = ['plain', 'a\\b'].flatMap(dir => {
        fs.symlinkSync(bytes, at(`${dir}/to-bytes`))
        fs.symlinkSync('../bytes-\uFFFD', at(`${dir}/to-text`))
        return [
          [at(`${dir}/to-bytes`), 'EILSEQ'],
          [at(`${dir}/to-text`), at('bytes-\uFFFD')],
        ] as const
      })
      const expected = rows.map(([, real]) => real)

      expect(rows.map(([p]) => answer(() => realPathOf(p)))).toEqual(expected)
      expect(inNode(rows.map(([p]) => p)).map(([there]) => there)).toEqual(
        expected,
      )
    },
    30_000,
  )

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

  it.each([
    ['plain/file', 'plain/file', []],
    ['a\\b/out/file', 'plain/file', []],
    ['plain/not-there/in', 'plain', ['not-there', 'in']],
    ['plain/file/in/deep', 'plain/file', ['in', 'deep']],
    ['a\\b/nowhere/in', 'a\\b', ['not-there', 'in']],
    ['plain/out/not-there/../x', 'a/b', ['not-there', '..', 'x']],
  ])('the way to %s leads as far as %s and leaves %j', (to, real, rest) => {
    expect(wayTo(at(to))).toMatchObject({ real: at(real), rest })
  })

  // root searches a directory of any mode.
  it.if(process.getuid?.() !== 0).each([
    ['shut\\/in/deep', ['in', 'deep']],
    ['a\\b/up-from-shut/x', ['..', 'x']],
  ])(
    'the way to %s stops at the directory that is shut and leaves %j',
    (to, rest) => {
      expect(wayTo(at(to))).toMatchObject({
        real: at('shut\\'),
        rest,
        notThere: { code: 'EACCES' },
      })
    },
  )

  it.each([
    ['a\\b/round', 'ELOOP'],
    ['a\\b/up-from-a-file', 'ENOTDIR'],
  ])('the way to %s fails with %s', (to, code) => {
    expect(answer(() => wayTo(at(to)).real)).toBe(code)
  })

  it('is the root for the root', () => {
    fs.symlinkSync('/', at('a\\b/root'))

    expect(realPathOf(at('a\\b/root'))).toBe('/')
    expect(realPathOf(at('a\\b/root/..'))).toBe('/')
    expect(realPathOf(at('a\\b/root/../..'))).toBe('/')
  })

  describe('what it asks', () => {
    function asked(given: string): string[] {
      const calls: string[] = []
      const watch = (holder: object, call: string) => {
        const held = holder as Record<string, (...args: unknown[]) => unknown>
        const real = held[call]!
        return spyOn(held, call).mockImplementation((...args: unknown[]) => {
          calls.push(`${call} ${String(args[0])}`)
          return real(...args)
        })
      }
      const native = watch(fs.realpathSync, 'native')
      const spies = [
        native,
        Object.assign(watch(fs, 'realpathSync'), { native }),
        watch(fs, 'lstatSync'),
        watch(fs, 'readlinkSync'),
      ]
      try {
        realPathOf(given)
      } finally {
        spies.forEach(spy => spy.mockRestore())
      }
      return calls
    }

    it.each(['plain/file', 'to-it/file', 'plain/.//in/'])(
      'asks once about %s, which holds no backslash and no .., folded in text',
      given => {
        expect(asked(at(given))).toEqual([`native ${resolve(at(given))}`])
      },
    )

    /** One question about the root, and one about each name on the way to
     *  the tree. */
    const above = (): string[] => [
      'lstatSync /.',
      ...[...root.matchAll(/(?<=.)\/|$/g)].map(
        cut => `lstatSync ${root.slice(0, cut.index)}`,
      ),
    ]

    it('asks about each component where the name holds a .., which not every runtime leaves to the kernel', () => {
      expect(asked(at('to-it/../plain'))).toEqual([
        ...above(),
        `lstatSync ${at('to-it')}`,
        `readlinkSync ${at('to-it')}`,
        `lstatSync ${at('a\\b')}`,
        `lstatSync ${at('a\\b')}/.`,
        `lstatSync ${at('plain')}`,
      ])
    })

    it('asks once more, about the name folded in text, where the kernel has no answer for it', () => {
      expect(asked(at('plain/not-there/../file'))).toEqual([
        ...above(),
        `lstatSync ${at('plain')}`,
        `lstatSync ${at('plain/not-there')}`,
        `native ${at('plain/file')}`,
      ])
    })

    it('asks about each component once where the name holds a backslash', () => {
      expect(asked(at('a\\b/out/file'))).toEqual([
        ...above(),
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
        expect(asked(at('to-it//'))).toEqual([`realpathSync ${at('to-it//')}`])
        expect(answer(() => asked(at('a\\b')).join())).not.toContain(
          'lstatSync',
        )
      } finally {
        Object.defineProperty(process, 'platform', platform)
      }
    })
  })
})

// How a volume that folds case, and a volume mounted into another, are spelled
// is the system's to say: logged, and held to naming the same file.
describe.if(isMacOS)('realPathOf on macOS', () => {
  it('names the file it was asked about, in Node too', () => {
    const root = fs.mkdtempSync(join(tmpdir(), 'Real-Path-'))
    try {
      fs.writeFileSync(join(root, 'File'), '')
      const paths = [
        root,
        join(root, 'File'),
        join(root, 'file'),
        join(root.toLowerCase(), 'FILE'),
        join('/System/Volumes/Data', fs.realpathSync(root), 'File'),
      ].filter(p => fs.existsSync(p))
      const answers = inNode(paths)
      paths.forEach((p, i) => {
        const [here, there] = [realPathOf(p), answers[i]![0]!]
        console.log(
          `${p}: ${here}${there === here ? '' : `; in Node ${there}`}`,
        )
        expect([p, fileAt(here), fileAt(there)]).toEqual([
          p,
          fileAt(p),
          fileAt(p),
        ])
      })
    } finally {
      fs.rmSync(root, { recursive: true, force: true })
    }
  }, 30_000)
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
  const linksOnTheWayTo = (p: string): string[] =>
    [...p.matchAll(/(?<=.)\/|$/g)]
      .map(cut => p.slice(0, cut.index))
      .filter(upTo => fs.lstatSync(upTo).isSymbolicLink())

  it('leads where the kernel leads and crosses no link, in Node too, and is what the C library gives', () => {
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
            const paths = questions.map(([from, way]) =>
              [pick(made, from), ...way].join('/'),
            )
            // Node folds a link's target in text, so where one goes up from
            // behind a name its own answer can differ, or never come.
            const askNode = !upBehindAName
            const answers = inNode(paths, askNode)
            // Node folds a `..` behind a link in text as well.
            const goesUp = paths.map(p => asRead(p) !== resolve(p))
            paths.forEach((p, i) => {
              const real = answer(() => realPathOf(p))
              expect([p, real.startsWith('/') ? fileAt(real) : real]).toEqual([
                p,
                fileAt(asRead(p)),
              ])
              if (real.startsWith('/')) {
                expect([p, resolve(real), linksOnTheWayTo(real)]).toEqual([
                  p,
                  real,
                  [],
                ])
              }
              const [there, library, own] = answers[i]!
              // Not every C library asks whether what a link's target goes on
              // from is a directory.
              if (isMacOS && real === 'ENOTDIR') {
                if (library !== real) console.log(`${p}: ${library}`)
                return
              }
              expect([p, there, library]).toEqual([p, real, real])
              if (askNode && !goesUp[i]) expect([p, own]).toEqual([p, real])
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
