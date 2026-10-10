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
import { bwrapCanNamespaceNetwork } from '../helpers/bwrap-namespace.js'
import { isLinux, isMacOS } from '../helpers/platform.js'

/**
 * A rule spelled through a link applies where the kernel leads, on every
 * runtime: these rows run the built CLI, in Node and in this one.
 *
 * In a link's target `..` is the parent of where the way has led, which
 * behind another link is not the directory the link lies in. And a target can
 * hold bytes that are no text, which no rule and no mount can spell.
 */

const CLI_PATH = join(process.cwd(), 'dist', 'cli.js')
const RUNTIMES = [
  ['node', ['node', '--max-old-space-size=256']],
  ['bun', [process.execPath]],
] as const
const APPENDED = 'appended'
const canRun = isMacOS || (isLinux && bwrapCanNamespaceNetwork())

let root: string

beforeEach(() => {
  root = realpathSync(mkdtempSync(join(tmpdir(), 'links-up-')))
  for (const file of [
    'here/file',
    'elsewhere/file',
    'elsewhere/in/other',
    'elsewhere/down/in/file',
  ]) {
    mkdirSync(dirname(join(root, file)), { recursive: true })
    writeFileSync(join(root, file), `<${file}>`)
  }
  symlinkSync('../elsewhere/in', join(root, 'here/link'))
  symlinkSync('link/../file', join(root, 'here/up'))
  symlinkSync('link/../down/in', join(root, 'here/down'))
})

afterEach(() => {
  rmSync(root, { recursive: true, force: true })
})

/**
 * Which of `files`, given from `root`, a command run by the CLI can read, or
 * append to, by its own account: a placeholder is gone when it has ended. The CLI is ended hard past its time, and the command runs behind
 * an `echo BOOTED`, so neither can read as a command that was refused: a
 * sandbox that is to refuse to start is said not to `boot`. What the command
 * does `first`, it does in `root`.
 */
function reach(
  argv: readonly string[],
  policy: object,
  does: 'read' | 'append',
  files: string[],
  boots: boolean | 'or not' = true,
  first = 'true',
): string[] {
  const settings = join(root, 'settings.json')
  writeFileSync(
    settings,
    JSON.stringify({
      network: { allowedDomains: [], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
      ...policy,
    }),
  )
  const command = ['echo BOOTED', `( ${first} ) 2>/dev/null`]
    .concat(
      files.map(file =>
        does === 'read'
          ? `cat '${root}/${file}'`
          : `( echo ${APPENDED} >> '${root}/${file}' ) && echo '<${file}>'`,
      ),
    )
    .join('; ')
  const { stdout, error } = spawnSync(
    argv[0]!,
    [...argv.slice(1), CLI_PATH, '-s', settings, '-c', command],
    { encoding: 'utf8', timeout: 20_000, killSignal: 'SIGKILL', cwd: root },
  )
  expect(error).toBeUndefined()
  if (boots !== 'or not') expect(stdout.includes('BOOTED')).toBe(boots)
  return files.filter(file => stdout.includes(`<${file}>`))
}

const denyRead = (...entries: string[]) => ({
  filesystem: { denyRead: entries, allowWrite: [], denyWrite: [] },
})
const denyWrite = (entry: string) => ({
  filesystem: { denyRead: [], allowWrite: [root], denyWrite: [entry] },
})

describe.if(canRun).each(RUNTIMES)(
  'a rule through a link whose target goes up from behind a link, in %s',
  (_, argv) => {
    const files = ['elsewhere/file', 'elsewhere/down/in/file', 'here/file']
    const but = (file: string) => files.filter(other => other !== file)

    it('denyRead of a file refuses the file the kernel finds there', () => {
      expect(
        reach(argv, denyRead(join(root, 'here/up')), 'read', files),
      ).toEqual(but('elsewhere/file'))
    }, 60_000)

    it('a credentials deny refuses the file the kernel finds there', () => {
      const credentials = {
        files: [{ path: join(root, 'here/up'), mode: 'deny' }],
      }
      expect(reach(argv, { credentials }, 'read', files)).toEqual(
        but('elsewhere/file'),
      )
    }, 60_000)

    it('denyRead of a directory hides the directory the kernel finds there', () => {
      expect(
        reach(argv, denyRead(join(root, 'here/down')), 'read', files),
      ).toEqual(but('elsewhere/down/in/file'))
    }, 60_000)

    it('a command that goes up from behind a link is held where the kernel leads', () => {
      reach(argv, denyWrite(join(root, 'elsewhere/down')), 'append', [
        'here/link/../down/in/file',
        'here/link/../file',
      ])

      expect(readFileSync(join(root, 'elsewhere/down/in/file'), 'utf8')).toBe(
        '<elsewhere/down/in/file>',
      )
      expect(readFileSync(join(root, 'elsewhere/file'), 'utf8')).toContain(
        APPENDED,
      )
    }, 60_000)

    // Only bubblewrap is handed what a pattern finds, and only its write
    // denies are followed through a link.
    it.if(isLinux)(
      'a denyRead pattern refuses what it reaches through the link',
      () => {
        expect(
          reach(argv, denyRead(join(root, 'here/**/file')), 'read', files),
        ).toEqual(['elsewhere/file'])
      },
      60_000,
    )

    it.if(isLinux).each([
      ['here/up', 'elsewhere/file'],
      ['here/down/file', 'elsewhere/down/in/file'],
    ])(
      'denyWrite of %s keeps %s as it is',
      (entry, kept) => {
        expect(
          reach(argv, denyWrite(join(root, entry)), 'append', files),
        ).toEqual(but(kept))
      },
      60_000,
    )

    it.if(isLinux).each([
      ['up', 'link/../made'],
      ['up and down again', 'link/../down/made'],
    ])(
      'denyWrite of a link that leads %s to what is not there keeps it from being made',
      (_, target) => {
        symlinkSync(target, join(root, 'here/new'))

        expect(
          reach(argv, denyWrite(join(root, 'here/new')), 'append', [
            'here/new',
            ...files,
          ]),
        ).toEqual(files)
      },
      60_000,
    )
  },
)

// macOS lets no such name be made.
describe.if(isLinux && canRun).each(RUNTIMES)(
  'a rule through a link to a name that is no text, in %s',
  (_, argv) => {
    const files = ['here/to-bytes/file', 'bytes-\uFFFD/file']

    beforeEach(() => {
      const bytes = Buffer.concat([Buffer.from('bytes-'), Buffer.of(0xff)])
      mkdirSync(Buffer.concat([Buffer.from(`${root}/`), bytes]))
      mkdirSync(join(root, 'bytes-\uFFFD'))
      symlinkSync(
        Buffer.concat([Buffer.from('../'), bytes]),
        join(root, 'here/to-bytes'),
      )
      for (const file of files) writeFileSync(join(root, file), `<${file}>`)
    })

    it('denyRead keeps the file the kernel finds there from being read', () => {
      const policy = {
        filesystem: {
          denyRead: [join(root, files[0]!)],
          allowWrite: [root],
          denyWrite: [],
        },
      }
      // Whether a mount can be put on the spelling is bubblewrap's to say:
      // 0.12 cannot, and then nothing runs.
      expect(reach(argv, policy, 'read', files, 'or not')).not.toContain(
        files[0]!,
      )
    }, 60_000)

    it('denyWrite of a link to what is not there yet keeps it from being made', () => {
      symlinkSync(
        Buffer.concat([Buffer.from('../elsewhere/'), Buffer.of(0xff)]),
        join(root, 'here/new'),
      )

      // Whether a mount can be put on the link itself is bubblewrap's to say.
      expect(
        reach(
          argv,
          denyWrite(join(root, 'here/new')),
          'append',
          ['here/new'],
          'or not',
        ),
      ).toEqual([])
    }, 60_000)

    it.each(['file', 'not-there'])(
      'denyWrite of %s there lets nothing run that could write it',
      name => {
        const file = `here/to-bytes/${name}`
        expect(
          reach(argv, denyWrite(join(root, file)), 'append', [file], false),
        ).toEqual([])
      },
      60_000,
    )
  },
)

/**
 * A way can be cut short at a name that is not there: a directory a target
 * lacks, a link on the way that is missing or dangles in its turn. Whoever
 * makes that name decides where the way goes on, so it is what is held.
 */
describe.if(isLinux && canRun).each(RUNTIMES)(
  'a write deny on a link whose way is cut short, in %s',
  (_, argv) => {
    const bytes = `"$(printf 'n\\377')"`

    it.each([
      [
        'the directories a dangling hop lacks',
        { hop: 'lacking/in', name: 'hop/../made' },
        'mkdir -p lacking/in',
      ],
      [
        'a hop that is not there, as a link',
        { name: 'hop/../made' },
        'ln -s elsewhere/in hop',
      ],
      [
        'a hop that is not there, as a directory',
        { name: 'hop/../made' },
        'mkdir hop',
      ],
      [
        'what a dangling hop leads to, as a link',
        { hop: 'lacking', name: 'hop/../made' },
        'ln -s elsewhere/in lacking',
      ],
      [
        'what the second of two dangling hops lacks',
        { hop: 'second/x', second: 'lacking/y', name: 'hop/made' },
        'mkdir -p lacking/y/x',
      ],
      [
        'what the third of three dangling hops lacks',
        {
          hop: 'second/x',
          second: 'third/y',
          third: 'lacking/z',
          name: 'hop/../made',
        },
        'mkdir -p lacking/z/y/x',
      ],
      [
        'a name that a built-in deny holds as a directory',
        { name: '.claude/../made' },
        'true',
      ],
    ])(
      'holds when the command makes %s',
      (_, links, first) => {
        for (const [link, target] of Object.entries(links)) {
          symlinkSync(target, join(root, link))
        }

        expect(
          reach(
            argv,
            denyWrite(join(root, 'name')),
            'append',
            ['name', 'here/file'],
            true,
            first,
          ),
        ).toEqual(['here/file'])
      },
      60_000,
    )

    it('holds where a hop leads out of the write root', () => {
      symlinkSync('../../lacking/in', join(root, 'here/hop'))
      symlinkSync('hop/made', join(root, 'here/name'))
      const policy = {
        filesystem: {
          denyRead: [],
          allowWrite: [join(root, 'here')],
          denyWrite: [join(root, 'here/name')],
        },
      }

      expect(
        reach(
          argv,
          policy,
          'append',
          ['here/name', 'here/file'],
          true,
          'mkdir -p lacking/in',
        ),
      ).toEqual(['here/file'])
    }, 60_000)

    it('lets nothing run that could write it where a hop leads to a name that is no text', () => {
      symlinkSync(
        Buffer.concat([Buffer.from('n'), Buffer.of(0xff), Buffer.from('/in')]),
        join(root, 'hop'),
      )
      symlinkSync('hop/../made', join(root, 'name'))

      expect(
        reach(
          argv,
          denyWrite(join(root, 'name')),
          'append',
          ['name'],
          false,
          `mkdir -p ${bytes}/in`,
        ),
      ).toEqual([])
    }, 60_000)

    it('leaves the rest of the project to a command where a built-in deny is a link to what is not built yet', () => {
      symlinkSync('build/vscode', join(root, '.vscode'))

      expect(
        reach(
          argv,
          denyWrite(join(root, 'not-there')),
          'append',
          ['.vscode/settings.json', 'build/vscode/settings.json', 'here/file'],
          true,
          'mkdir -p build/vscode',
        ),
      ).toEqual(['here/file'])
    }, 60_000)
  },
)
