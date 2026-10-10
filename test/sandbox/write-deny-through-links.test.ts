import { describe, it, expect, beforeEach, afterEach } from 'bun:test'
import { spawnSync } from 'node:child_process'
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readlinkSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { getApplySeccompBinaryPath } from '../../src/sandbox/generate-seccomp-filter.js'
import {
  cleanupBwrapMountPoints,
  getLinuxUnheldLinks,
  wrapCommandWithSandboxLinux,
} from '../../src/sandbox/linux-sandbox-utils.js'
import { wrapCommandWithSandboxMacOS } from '../../src/sandbox/macos-sandbox-utils.js'
import { followLinks } from '../../src/sandbox/sandbox-utils.js'
import { bwrapCanNamespace } from '../helpers/bwrap-namespace.js'
import { withCapturedWarnings } from '../helpers/captured-warnings.js'
import { isLinux, isMacOS, isWindows } from '../helpers/platform.js'

/**
 * A write deny on a path with a symbolic link on the way to it, the last name
 * included, holds what the links lead to and the links themselves. Everything
 * beside them stays as writable as it was.
 *
 * Every link here is made on the host before the command is wrapped.
 */

let BASE: string
let ROOT: string // the one write root
let OUTSIDE: string // beside it, under no write root

/** Link name in ROOT -> what it says. */
const LINKS = {
  name: 'conf/x',
  'holder/commands': '../shared/commands',
  dangling: 'later',
  way: 'real',
  first: 'middle',
  middle: 'conf/y',
  'other-link': 'conf/z',
}
const FILES = [
  'conf/x',
  'conf/y',
  'conf/z',
  'shared/commands/file',
  'real/secret',
  'beside',
]
const ABSENT = ['later', 'real/absent', 'shared/commands/new']
const DENIED = [
  'name',
  'holder/commands',
  'dangling',
  'way/secret',
  'way/absent',
  'first',
]

beforeEach(() => {
  if (isWindows) return
  // Where the temp dir really is: macOS names it through a link.
  BASE = realpathSync(mkdtempSync(join(tmpdir(), 'write-deny-links-')))
  ROOT = join(BASE, 'root')
  OUTSIDE = join(BASE, 'outside')
  for (const dir of ['conf', 'shared/commands', 'real', 'holder']) {
    mkdirSync(join(ROOT, dir), { recursive: true })
  }
  mkdirSync(OUTSIDE)
  for (const file of FILES) writeFileSync(join(ROOT, file), 'original')
  for (const [link, says] of Object.entries(LINKS)) {
    symlinkSync(says, join(ROOT, link))
  }
})

afterEach(() => {
  if (isWindows) return
  if (isLinux) cleanupBwrapMountPoints({ force: true })
  rmSync(BASE, { recursive: true, force: true })
})

const inRoot = (names: string[]): string[] => names.map(n => join(ROOT, n))

describe.if(!isWindows)('the links on the way to a path', () => {
  it.each<[string, string[], string]>([
    ['beside', [], 'beside'],
    ['name', ['name'], 'conf/x'],
    ['holder/commands/file', ['holder/commands'], 'shared/commands/file'],
    ['dangling', ['dangling'], 'later'],
    ['way/absent/deeper', ['way'], 'real/absent/deeper'],
    ['first', ['first', 'middle'], 'conf/y'],
    ['absent/name', [], 'absent/name'],
  ])('%s: %p, ending at %s', (p, links, end) => {
    expect(followLinks(join(ROOT, p))).toEqual({
      links: inRoot(links),
      end: join(ROOT, end),
    })
  })

  it('reads `..` in a target as the parent of the directory reached', () => {
    symlinkSync(join(ROOT, 'shared', 'commands'), join(ROOT, 'absolute'))
    symlinkSync('absolute/../made', join(ROOT, 'up'))
    expect(followLinks(join(ROOT, 'up'))).toEqual({
      links: inRoot(['up', 'absolute']),
      end: join(ROOT, 'shared', 'made'),
    })
  })

  it('names a link where it lies, whatever it was reached through', () => {
    symlinkSync(ROOT, join(OUTSIDE, 'to-root'))
    expect(followLinks(join(OUTSIDE, 'to-root', 'name'))).toEqual({
      links: [join(OUTSIDE, 'to-root'), join(ROOT, 'name')],
      end: join(ROOT, 'conf', 'x'),
    })
  })

  // Not every file system takes such a target.
  it.if(isLinux)('has no end past a target that is no text', () => {
    symlinkSync(Buffer.from([0x78, 0xff]), join(ROOT, 'bytes'))
    expect(followLinks(join(ROOT, 'bytes', 'file'))).toEqual({
      links: inRoot(['bytes']),
      end: undefined,
    })
  })

  it('has no end for links that lead in a circle', () => {
    symlinkSync('circle-b', join(ROOT, 'circle-a'))
    symlinkSync('circle-a', join(ROOT, 'circle-b'))
    expect(followLinks(join(ROOT, 'circle-a')).end).toBeUndefined()
  })
})

describe.if((isLinux && bwrapCanNamespace()) || isMacOS)(
  'A write deny on a path with a link on the way',
  () => {
    /** What `attempt` came to, run in ROOT with every one of `denied` denied. */
    async function outcomeOf(
      attempt: string,
      denied = DENIED,
    ): Promise<string> {
      const options = {
        command: `cd ${ROOT} && echo started && if ( ${attempt} ); then echo DONE; else echo refused; fi`,
        needsNetworkRestriction: false,
        readConfig: { denyOnly: [] },
        writeConfig: { allowOnly: [ROOT], denyWithinAllow: inRoot(denied) },
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
        cwd: OUTSIDE,
      })
      const said = `${result.stdout}${result.stderr}`
      console.log(`${attempt}\n  ${said.trim().split('\n').join('\n  ')}`)
      expect(said).toContain('started')
      if (isLinux) cleanupBwrapMountPoints({ force: true })
      return said.includes('DONE') ? 'DONE' : 'refused'
    }

    it.each([
      ['a write through the link', 'echo changed >> name'],
      [
        'a write to what it leads to, by its own path',
        'echo changed >> conf/x',
      ],
      ['removing the link', 'rm name'],
      ['renaming a file over the link', 'echo new > made && mv -f made name'],
      ['renaming the link away', 'mv name aside'],
      ['making the link anew', 'ln -sfn beside name'],
      ['removing what it leads to', 'rm conf/x'],
      ['renaming the directory of what it leads to', 'mv conf aside'],
      [
        'a create beneath a link to a directory',
        'echo n > holder/commands/new',
      ],
      ['the same by its own path', 'echo new > shared/commands/new'],
      ['removing a link to a directory', 'rm holder/commands'],
      ['renaming the directory that holds the link', 'mv holder aside'],
      ['a create through a dangling link', 'echo new > dangling'],
      ['a create of what it leads to, by its own path', 'echo new > later'],
      ['removing a dangling link', 'rm dangling'],
      ['a write beneath a link on the way', 'echo changed >> way/secret'],
      ['the same by its own path', 'echo changed >> real/secret'],
      ['a create beneath a link on the way', 'echo new > way/absent'],
      ['the same by its own path', 'echo new > real/absent'],
      ['removing a link on the way', 'rm way'],
      ['a write through two links', 'echo changed >> first'],
      ['removing the second of two links', 'rm middle'],
      ['renaming a file over it', 'echo new > made && mv -f made middle'],
    ])('refuses %s: %s', async (_what, attempt) => {
      expect(await outcomeOf(attempt)).toBe('refused')

      for (const [link, says] of Object.entries(LINKS)) {
        expect(lstatSync(join(ROOT, link)).isSymbolicLink()).toBe(true)
        expect(readlinkSync(join(ROOT, link))).toBe(says)
      }
      for (const file of FILES) {
        expect(readFileSync(join(ROOT, file), 'utf8')).toBe('original')
      }
      for (const name of ABSENT)
        expect(existsSync(join(ROOT, name))).toBe(false)
    })

    it.each([
      ['a write to a file beside the link', 'echo changed >> beside'],
      ['removing it', 'rm beside'],
      ['a create beside the link', 'echo new > new && echo new > holder/new'],
      ['a write beside what the link leads to', 'echo changed >> conf/z'],
      ['replacing a link no deny leads through', 'ln -sfn beside other-link'],
      [
        'reading the link, and through it',
        'test "$(readlink name)$(cat name)$(ls holder/commands)" = conf/xoriginalfile',
      ],
    ])('allows %s: %s', async (_what, attempt) => {
      expect(await outcomeOf(attempt)).toBe('DONE')
    })

    it.each([
      'rm .bashrc',
      'echo changed >> conf/x',
      'rm .claude/commands',
      'echo new > shared/commands/new',
    ])(
      'refuses the same of a name denied in every working directory: %s',
      async attempt => {
        mkdirSync(join(ROOT, '.claude'))
        symlinkSync('conf/x', join(ROOT, '.bashrc'))
        symlinkSync('../shared/commands', join(ROOT, '.claude', 'commands'))
        const cwd = process.cwd()
        process.chdir(ROOT)
        try {
          expect(await outcomeOf(attempt, [])).toBe('refused')
        } finally {
          process.chdir(cwd)
        }
      },
    )
  },
)

// Profile text only, so it runs on every POSIX host.
describe.if(!isWindows)('Seatbelt profile', () => {
  /** The filters of the rule that denies `operations`, one to a line. */
  const deniedBy = (operations: string, denyWithinAllow: string[]): string => {
    const profile = wrapCommandWithSandboxMacOS({
      command: 'true',
      needsNetworkRestriction: false,
      readConfig: undefined,
      writeConfig: { allowOnly: [ROOT], denyWithinAllow },
    })
    const at = profile.indexOf(`(deny ${operations}\n`)
    expect(at).toBeGreaterThan(-1)
    return profile.slice(at, profile.indexOf('(with message', at))
  }
  const subpath = (name: string): string =>
    `  (subpath "${join(ROOT, name)}")\n`
  const literal = (name: string): string =>
    `  (literal "${join(ROOT, name)}")\n`

  it.each([
    ['name', 'conf/x'],
    ['holder/commands', 'shared/commands'],
    ['dangling', 'later'],
    ['way/secret', 'real/secret'],
    ['way/absent', 'real/absent'],
    ['first', 'conf/y'],
  ])('a deny on %s is one on %s too', (written, end) => {
    const denies = deniedBy('file-write*', inRoot([written]))
    expect(denies).toContain(subpath(written))
    expect(denies).toContain(subpath(end))
  })

  it('so is one on a name denied in every working directory', () => {
    symlinkSync('conf/x', join(ROOT, '.bashrc'))
    const cwd = process.cwd()
    process.chdir(ROOT)
    try {
      expect(deniedBy('file-write*', [])).toContain(subpath('conf/x'))
    } finally {
      process.chdir(cwd)
    }
  })

  it('a pattern deny starts from both spellings of its directory', () => {
    const denies = deniedBy('file-write*', [join(ROOT, 'way', '*.key')])
    const matches = (file: string): boolean =>
      [...denies.matchAll(/^ {2}\(regex (".*")\)$/gm)].some(([, text]) =>
        new RegExp(JSON.parse(text!) as string).test(join(ROOT, file)),
      )
    expect(matches('way/a.key')).toBe(true)
    expect(matches('real/a.key')).toBe(true)
    expect(matches('conf/a.key')).toBe(false)
  })

  it('every link on the way, and what holds it, is kept in place', () => {
    mkdirSync(join(ROOT, 'elsewhere'))
    symlinkSync('../conf/x', join(ROOT, 'elsewhere', 'hop'))
    symlinkSync('elsewhere/hop', join(ROOT, 'far'))
    const kept = deniedBy(
      'file-write-unlink file-write-create',
      inRoot(['first', 'far']),
    )
    for (const name of ['middle', 'elsewhere/hop', 'elsewhere', 'conf']) {
      expect(kept).toContain(literal(name))
    }
    expect(kept).not.toContain(join(ROOT, 'other-link'))
  })
})

describe.if(isLinux)('what the seccomp helper is asked to hold', () => {
  const wrap = (
    denyWithinAllow: string[],
    rest: Partial<Parameters<typeof wrapCommandWithSandboxLinux>[0]> = {},
  ): Promise<string> =>
    wrapCommandWithSandboxLinux({
      command: 'echo started',
      needsNetworkRestriction: false,
      readConfig: { denyOnly: [] },
      writeConfig: { allowOnly: [ROOT], denyWithinAllow },
      ...rest,
    })
  const held = (wrapped: string): string[] =>
    [...wrapped.matchAll(/--hold-link (\S+)/g)].map(match => match[1]!)

  it('each link once, where it lies', async () => {
    symlinkSync(ROOT, join(OUTSIDE, 'to-root'))
    expect(
      held(
        await wrap([
          ...inRoot(['first', 'way/secret', 'way/absent']),
          join(OUTSIDE, 'to-root', 'middle'),
        ]),
      ).sort(),
    ).toEqual(inRoot(['first', 'middle', 'way']))
  })

  it('none for a path with no link on the way', async () => {
    expect(held(await wrap(inRoot(['beside', 'conf/x', 'absent'])))).toEqual([])
  })

  it('none that lies where the command cannot write', async () => {
    symlinkSync(join(ROOT, 'conf', 'x'), join(OUTSIDE, 'into-root'))
    expect(held(await wrap([join(OUTSIDE, 'into-root')]))).toEqual([])
  })

  it('none in the directories the sandbox mounts anew', async () => {
    expect(
      held(
        await wrap(['/proc/self/cwd/file'], {
          writeConfig: {
            allowOnly: ['/'],
            denyWithinAllow: ['/proc/self/cwd/file'],
          },
        }),
      ),
    ).toEqual([])
  })

  it.if(bwrapCanNamespace())(
    'none that a read deny hides, and the command starts',
    async () => {
      const wrapped = await wrap(inRoot(['holder/commands', 'name']), {
        readConfig: { denyOnly: [join(ROOT, 'holder')] },
      })
      expect(held(wrapped)).toEqual(inRoot(['name']))
      expect(
        spawnSync(wrapped, { shell: true, encoding: 'utf8', cwd: OUTSIDE })
          .stdout,
      ).toBe('started\n')
    },
  )

  it.if(bwrapCanNamespace())(
    'none that is bound back by itself into a directory a read deny hides',
    async () => {
      mkdirSync(join(ROOT, 'holder', 'inner'))
      symlinkSync('inner', join(ROOT, 'holder', 'to-inner'))
      const wrapped = await wrap(inRoot(['holder/to-inner/file']), {
        readConfig: {
          denyOnly: [join(ROOT, 'holder')],
          allowWithinDeny: inRoot(['holder/to-inner']),
        },
      })
      expect(held(wrapped)).toEqual([])
      expect(
        spawnSync(wrapped, { shell: true, encoding: 'utf8', cwd: OUTSIDE })
          .stdout,
      ).toBe('started\n')
    },
  )

  it('the directories above a held link are pinned', async () => {
    const holder = join(ROOT, 'holder')
    expect(await wrap(inRoot(['holder/commands']))).toContain(
      `--ro-bind ${holder} ${holder} `,
    )
  })

  describe('where nothing can hold them', () => {
    /** Runs its words, as a helper built before the option does. */
    const olderHelper = (): string => {
      const helper = join(OUTSIDE, 'older-helper')
      writeFileSync(helper, '#!/bin/sh\nexec "$@"\n')
      chmodSync(helper, 0o755)
      return helper
    }

    it.each<[string, () => Parameters<typeof wrap>[1]]>([
      ['no helper in use', () => ({ allowAllUnixSockets: true })],
      ['an older one', () => ({ seccompConfig: { applyPath: olderHelper() } })],
    ])('%s: they are named, and the command starts', async (_what, rest) => {
      const links = inRoot(['first', 'middle'])
      expect(getLinuxUnheldLinks()).not.toContain(links[0])

      const { result: wrapped, warnings } = await withCapturedWarnings(() =>
        wrap(inRoot(['first']), rest()),
      )

      expect(held(wrapped)).toEqual([])
      expect(getLinuxUnheldLinks()).toEqual(expect.arrayContaining(links))
      for (const link of links) {
        expect(warnings.some(line => line.includes(`${link},`))).toBe(true)
      }
      if (bwrapCanNamespace()) {
        expect(
          spawnSync(wrapped, { shell: true, encoding: 'utf8', cwd: OUTSIDE })
            .stdout,
        ).toBe('started\n')
      }
    })

    it('a helper run under another name is asked under it, and again after no answer', async () => {
      const multicall = join(OUTSIDE, 'multicall')
      const seccompConfig = { applyPath: multicall, argv0: 'apply-seccomp' }
      expect(held(await wrap(inRoot(['name']), { seccompConfig }))).toEqual([])

      writeFileSync(
        multicall,
        `#!/bin/sh\n[ "$ARGV0" = apply-seccomp ] && exec ${getApplySeccompBinaryPath()} "$@"\n`,
      )
      chmodSync(multicall, 0o755)
      expect(held(await wrap(inRoot(['name']), { seccompConfig }))).toEqual(
        inRoot(['name']),
      )
    })

    it('asking an older helper runs no program of that name', async () => {
      const program = join(ROOT, '--holds-links')
      writeFileSync(program, `#!/bin/sh\necho ran > ${ROOT}/ran\n`)
      chmodSync(program, 0o755)
      const [cwd, PATH] = [process.cwd(), process.env.PATH]
      process.chdir(ROOT)
      process.env.PATH = `${ROOT}:.:${PATH}`
      try {
        await wrap(inRoot(['name']), {
          seccompConfig: { applyPath: olderHelper() },
        })
      } finally {
        process.chdir(cwd)
        process.env.PATH = PATH
      }
      expect(existsSync(join(ROOT, 'ran'))).toBe(false)
    })
  })
})

describe.if(isLinux && bwrapCanNamespace())('the seccomp helper', () => {
  const helper = (): string => getApplySeccompBinaryPath()!
  const run = (
    program: string,
    words: string[],
  ): { status: number | null; said: string } => {
    const result = spawnSync(program, words, {
      encoding: 'utf8',
      timeout: 30000,
      cwd: ROOT,
    })
    return { status: result.status, said: result.stdout + result.stderr }
  }
  /** umount2() with UMOUNT_NOFOLLOW, which reaches a mount on a link. */
  const UNMOUNT = [
    'python3',
    '-c',
    [
      'import ctypes, errno, sys',
      'libc = ctypes.CDLL(None, use_errno=True)',
      'r = libc.umount2(sys.argv[1].encode(), 8)',
      'print("unmounted" if r == 0 else errno.errorcode[ctypes.get_errno()])',
    ].join('\n'),
  ]

  it('says that it holds links', () => {
    expect(run(helper(), ['--holds-links'])).toEqual({ status: 0, said: '' })
  })

  it.each([
    ['a file', 'beside', 'not a symbolic link'],
    ['nothing', 'absent', 'No such file or directory'],
  ])('runs no command where %s is at the name', (_what, name, why) => {
    const { status, said } = run(helper(), [
      '--hold-link',
      join(ROOT, name),
      'echo',
      'started',
    ])
    expect(status).toBe(1)
    expect(said).toContain(why)
    expect(said).not.toContain('started')
  })

  it.each([
    ['this user', [], 'EPERM'],
    ['uid 0, with every capability in its namespace', ['-Ur'], 'EINVAL'],
  ])('a command of %s cannot take the hold off', (_who, as, errno) => {
    const link = join(ROOT, 'name')
    const { said } = run('unshare', [
      ...as,
      helper(),
      '--hold-link',
      link,
      ...UNMOUNT,
      link,
    ])
    expect(said.trim()).toBe(errno)
  })

  it('holds a link on a file system mounted with flags of its own', () => {
    const link = join(OUTSIDE, 'link')
    const { said } = run('unshare', [
      ...['-Urm', 'sh', '-c'],
      `mount -t tmpfs -o noexec,noatime none ${OUTSIDE} && ln -s x ${link} && ` +
        `exec ${helper()} --hold-link ${link} rm ${link}`,
    ])
    expect(said).toContain('Device or resource busy')
  })

  it.each(['--ro-bind', '--bind', '--dev-bind'])(
    'a bubblewrap the command starts with %s / / starts, and the hold holds there',
    bind => {
      const { said } = run(helper(), [
        ...inRoot(['name', 'way', 'dangling']).flatMap(l => ['--hold-link', l]),
        ...['bwrap', bind, '/', '/', '--bind', ROOT, ROOT, '--dev', '/dev'],
        ...['sh', '-c', 'echo started; rm name way dangling'],
      ])
      expect(said).toContain('started')
      expect(said.match(/Device or resource busy/g)).toHaveLength(3)
    },
  )
})
