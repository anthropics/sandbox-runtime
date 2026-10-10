import { describe, it, expect, beforeEach, afterEach, spyOn } from 'bun:test'
import * as fs from 'fs'
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
import { homedir, tmpdir } from 'node:os'
import { join, relative } from 'node:path'
import type { LinuxUnheldLinkReason } from '../../src/index.js'
import * as seccomp from '../../src/sandbox/generate-seccomp-filter.js'
import {
  cleanupBwrapMountPoints,
  forgetLinuxUnheldLinks,
  getLinuxUnheldLinks,
  wrapCommandWithSandboxLinux,
} from '../../src/sandbox/linux-sandbox-utils.js'
import { wrapCommandWithSandboxMacOS } from '../../src/sandbox/macos-sandbox-utils.js'
import {
  SandboxRuntimeConfigSchema,
  type SandboxRuntimeConfig,
} from '../../src/sandbox/sandbox-config.js'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import { followLinks } from '../../src/sandbox/sandbox-utils.js'
import { bwrapCanNamespace } from '../helpers/bwrap-namespace.js'
import { withCapturedWarnings } from '../helpers/captured-warnings.js'
import { isLinux, isMacOS, isWindows } from '../helpers/platform.js'

/**
 * A deny on a path with a symbolic link on the way to it, the last name
 * included, covers what the links lead to and keeps the links where they are.
 * Everything beside them stays as writable as it was.
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
  blank: '/dev/null',
  out: '/dev/stdout',
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
  'blank',
  'out',
]
/** No mode keeps uid 0 from looking. */
const modesCount = process.getuid?.() !== 0

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
  chmodSync(join(ROOT, 'holder'), 0o755)
  rmSync(BASE, { recursive: true, force: true })
})

const inRoot = (names: string[]): string[] => names.map(n => join(ROOT, n))

/** `run` with ROOT for the working directory of this process. */
async function fromRoot<T>(run: () => T | Promise<T>): Promise<T> {
  const cwd = process.cwd()
  process.chdir(ROOT)
  try {
    return await run()
  } finally {
    process.chdir(cwd)
  }
}

/** An executable file in OUTSIDE that holds `script`. */
function program(name: string, script: string): string {
  const file = join(OUTSIDE, name)
  writeFileSync(file, `#!/bin/sh\n${script}\n`)
  chmodSync(file, 0o755)
  return file
}

describe.if(!isWindows)('the links on the way to a path', () => {
  it.each<[string, string[], string]>([
    ['beside', [], 'beside'],
    ['name', ['name'], 'conf/x'],
    ['holder/commands/file', ['holder/commands'], 'shared/commands/file'],
    ['dangling', ['dangling'], 'later'],
    ['way/absent/deeper', ['way'], 'real/absent/deeper'],
    ['first', ['first', 'middle'], 'conf/y'],
    ['absent/name', [], 'absent/name'],
    ['beside/name', [], 'beside/name'],
    ['./way/./secret/', ['way'], 'real/secret'],
  ])('%s: %p, ending at %s', (p, links, end) => {
    expect(followLinks(join(ROOT, p))).toEqual({
      links: inRoot(links),
      end: join(ROOT, end),
    })
  })

  it('takes a name with a NUL byte, which no call takes, as written', () => {
    expect(followLinks(join(ROOT, 'way', 'nul\0byte'))).toEqual({
      links: inRoot(['way']),
      end: join(ROOT, 'real', 'nul\0byte'),
    })
  })

  it('reads `..` in a target as the parent of the directory reached', () => {
    symlinkSync(join(ROOT, 'shared', 'commands'), join(ROOT, 'absolute'))
    symlinkSync('./absolute/../made', join(ROOT, 'up'))
    expect(followLinks(join(ROOT, 'up'))).toEqual({
      links: inRoot(['up', 'absolute']),
      end: join(ROOT, 'shared', 'made'),
    })
  })

  it('folds `..` in the path it is given in text', () => {
    expect(followLinks(`${ROOT}/holder/commands/../name`)).toEqual({
      links: [],
      end: join(ROOT, 'holder', 'name'),
    })
  })

  it('takes a relative path from the working directory', async () => {
    expect(await fromRoot(() => followLinks('name').end)).toBe(
      join(ROOT, 'conf', 'x'),
    )
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

  it('follows as many links as the Linux kernel, and has no end past them', () => {
    symlinkSync('beside', join(ROOT, 'hop-1'))
    for (let i = 2; i <= 41; i++) {
      symlinkSync(`hop-${i - 1}`, join(ROOT, `hop-${i}`))
    }
    expect(followLinks(join(ROOT, 'hop-40')).end).toBe(join(ROOT, 'beside'))
    expect(followLinks(join(ROOT, 'hop-41')).end).toBeUndefined()
    // macOS gives up sooner, at 32: what is denied past that is denied in vain.
    if (isLinux) {
      expect(() => readFileSync(join(ROOT, 'hop-40'))).not.toThrow()
    }
    expect(() => readFileSync(join(ROOT, 'hop-41'))).toThrow('ELOOP')
  })

  it.if(modesCount)(
    'stops at a directory it cannot look in, and says which',
    () => {
      chmodSync(join(ROOT, 'holder'), 0)
      symlinkSync('holder/commands', join(ROOT, 'to-holder'))
      expect(followLinks(join(ROOT, 'to-holder', 'file'))).toEqual({
        links: inRoot(['to-holder']),
        end: undefined,
        unsearched: join(ROOT, 'holder'),
      })
    },
  )

  it.each([
    ['ENOENT', undefined],
    ['EINVAL', undefined],
    ['EIO', ''],
    ['ESTALE', ''],
    ['ENAMETOOLONG', ''],
  ])('a look that fails with %s: could not look in %p', (code, unsearched) => {
    const spy = spyOn(fs, 'readlinkSync').mockImplementation(() => {
      throw Object.assign(new Error(code), { code })
    })
    try {
      expect(followLinks(join(ROOT, 'name')).unsearched).toBe(
        unsearched === undefined ? undefined : ROOT,
      )
    } finally {
      spy.mockRestore()
    }
  })

  it('never gives the root for the directory it could not look in', () => {
    const spy = spyOn(fs, 'lstatSync').mockImplementation(() => {
      throw Object.assign(new Error('EIO'), { code: 'EIO' })
    })
    try {
      expect(followLinks(ROOT)).toEqual({ links: [], end: undefined })
    } finally {
      spy.mockRestore()
    }
  })

  it('looks at a name once for all the paths that share a map', () => {
    const looked = new Map<string, string | null>()
    followLinks(join(ROOT, 'name'), looked)
    expect(looked.get(ROOT)).toBeNull()
    expect(looked.get(join(ROOT, 'name'))).toBe('conf/x')
    expect(looked.get(join(ROOT, 'conf', 'x'))).toBeNull()

    rmSync(join(ROOT, 'name'))
    expect(followLinks(join(ROOT, 'name'), looked).links).toEqual(
      inRoot(['name']),
    )
    expect(followLinks(join(ROOT, 'name')).links).toEqual([])
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
        // Linux mounts a read deny where it resolves, under the /dev it then
        // makes anew, and bubblewrap before 0.5.0 takes no device to mount on.
        readConfig: { denyOnly: isMacOS ? inRoot(['blank']) : [] },
        writeConfig: {
          allowOnly: [ROOT, '/dev/null', '/dev/stdout'],
          denyWithinAllow: inRoot(denied),
        },
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
      ['removing a link to a device', 'rm blank'],
      ['making it anew', 'ln -sfn beside out'],
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
      ['a write to a device a denied name leads to', 'echo x > /dev/null'],
      ['a read of it', 'cat /dev/null'],
    ])('allows %s: %s', async (_what, attempt) => {
      expect(await outcomeOf(attempt)).toBe('DONE')
    })

    it.each([
      ['refused', 'rm .bashrc'],
      ['refused', 'echo changed >> conf/x'],
      ['refused', 'rm .claude/commands'],
      ['refused', 'echo new > shared/commands/new'],
      ['refused', 'rm .zshrc'],
      ['DONE', 'echo x > /dev/null'],
    ])(
      'the same of the names denied in every working directory: %s: %s',
      async (outcome, attempt) => {
        mkdirSync(join(ROOT, '.claude'))
        symlinkSync('conf/x', join(ROOT, '.bashrc'))
        symlinkSync('/dev/null', join(ROOT, '.zshrc'))
        symlinkSync('../shared/commands', join(ROOT, '.claude', 'commands'))
        expect(await fromRoot(() => outcomeOf(attempt, []))).toBe(outcome)
      },
    )

    it.if(modesCount)(
      'keeps a directory that cannot be looked in as it is, mode and all',
      async () => {
        expect(await outcomeOf('chmod 000 holder')).toBe('DONE')
        expect(
          await outcomeOf(
            'chmod 755 holder; rm holder/commands || rm -r holder',
          ),
        ).toBe('refused')

        expect(lstatSync(join(ROOT, 'holder')).mode & 0o777).toBe(0)
        chmodSync(join(ROOT, 'holder'), 0o755)
        expect(readlinkSync(join(ROOT, 'holder', 'commands'))).toBe(
          LINKS['holder/commands'],
        )
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
  const KEPT = 'file-write-unlink file-write-create'
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

  it('so is one on a name denied in every working directory', async () => {
    symlinkSync('conf/x', join(ROOT, '.bashrc'))
    expect(await fromRoot(() => deniedBy('file-write*', []))).toContain(
      subpath('conf/x'),
    )
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
    const kept = deniedBy(KEPT, inRoot(['first', 'far']))
    for (const name of ['middle', 'elsewhere/hop', 'elsewhere', 'conf']) {
      expect(kept).toContain(literal(name))
    }
    expect(kept).not.toContain(join(ROOT, 'other-link'))
  })

  it('nothing among the devices is denied or kept, and the link to it is kept', () => {
    symlinkSync('/dev', join(ROOT, 'devices'))
    const denied = inRoot(['blank', 'out', 'devices'])
    for (const operations of ['file-write*', KEPT]) {
      expect(deniedBy(operations, denied)).not.toContain('"/dev')
    }
    for (const name of ['blank', 'out', 'devices']) {
      expect(deniedBy(KEPT, denied)).toContain(literal(name))
    }
  })

  it('nor is a device hidden by a read deny on a link to it', () => {
    const profile = wrapCommandWithSandboxMacOS({
      command: 'true',
      needsNetworkRestriction: false,
      readConfig: { denyOnly: inRoot(['blank', 'name']) },
      writeConfig: undefined,
    })
    const at = profile.indexOf('(deny file-read*\n')
    const denies = profile.slice(at, profile.indexOf('(with message', at))
    expect(denies).toContain(subpath('conf/x'))
    expect(denies).not.toContain('"/dev')
  })

  it.if(modesCount)(
    'a directory that cannot be looked in is denied whole',
    () => {
      chmodSync(join(ROOT, 'holder'), 0)
      expect(deniedBy('file-write*', inRoot(['holder/commands']))).toContain(
        subpath('holder'),
      )
      expect(deniedBy('file-write*', inRoot(['name']))).not.toContain(
        subpath('holder'),
      )
    },
  )
})

type LinuxOptions = Parameters<typeof wrapCommandWithSandboxLinux>[0]

/** `denyWithinAllow` denied in ROOT, wrapped for Linux. */
const wrapLinux = (
  denyWithinAllow: string[],
  rest: Partial<LinuxOptions> = {},
): Promise<string> =>
  wrapCommandWithSandboxLinux({
    command: 'echo started',
    needsNetworkRestriction: false,
    readConfig: { denyOnly: [] },
    writeConfig: { allowOnly: [ROOT], denyWithinAllow },
    ...rest,
  })

const stdoutOf = (wrapped: string): string =>
  spawnSync(wrapped, {
    shell: true,
    encoding: 'utf8',
    cwd: OUTSIDE,
    timeout: 30000,
  }).stdout

/**
 * The words a wrap hands the seccomp helper before the command, as [link,
 * target] pairs. Read by the shells themselves, through every level of
 * quoting, and with no namespace made: a stand-in for bubblewrap runs what
 * follows `--`, and one for the helper prints its words and runs nothing.
 */
async function heldBy(
  denyWithinAllow: string[],
  rest: Partial<LinuxOptions> = {},
): Promise<Array<[string, string]>> {
  const words = stdoutOf(
    await wrapLinux(denyWithinAllow, {
      bwrapPath: program(
        'bwrap-stand-in',
        'while [ "$1" != -- ]; do shift; done; shift; exec "$@"',
      ),
      seccompConfig: {
        applyPath: program('helper-stand-in', `printf '%s\\0' "$@"`),
        holdsLinks: true,
      },
      ...rest,
    }),
  ).split('\0')
  const held: Array<[string, string]> = []
  for (let i = 0; words[i] === '--hold-link'; i += 3) {
    held.push([words[i + 1]!, words[i + 2]!])
  }
  expect(words.slice(3 * held.length + 1)).toEqual(['-c', 'echo started', ''])
  return held.sort()
}
/** LINKS' names as {@link heldBy} gives them. */
const pairs = (...names: Array<keyof typeof LINKS>): Array<[string, string]> =>
  names.sort().map(name => [join(ROOT, name), LINKS[name]])

describe.if(isLinux)('what the seccomp helper is asked to hold', () => {
  it('each link once, where it lies, with what it says', async () => {
    symlinkSync(ROOT, join(OUTSIDE, 'to-root'))
    expect(
      await heldBy([
        ...inRoot(['first', 'way/secret', 'way/absent']),
        join(OUTSIDE, 'to-root', 'middle'),
      ]),
    ).toEqual(pairs('first', 'middle', 'way'))
  })

  it('whatever characters the name and the target hold', async () => {
    const odd = [
      "sp ace'quote",
      'new\nline',
      '$(echo x)`y`',
      '--hold-link',
      '!',
    ]
    for (const name of odd) symlinkSync(`to ${name}`, join(ROOT, name))
    expect(await heldBy(inRoot(odd))).toEqual(
      odd.sort().map(name => [join(ROOT, name), `to ${name}`]),
    )
  })

  it('with no word on a target that is no text', async () => {
    symlinkSync(Buffer.from([0x78, 0xff]), join(ROOT, 'bytes'))
    expect(await heldBy(inRoot(['bytes']))).toEqual([[join(ROOT, 'bytes'), '']])
  })

  it('for a deny written from the home or the working directory', async () => {
    const fromHome = `~/${relative(homedir(), join(ROOT, 'way', 'x'))}`
    expect(await fromRoot(() => heldBy(['name', fromHome]))).toEqual(
      pairs('name', 'way'),
    )
  })

  it('for a name denied in every working directory', async () => {
    symlinkSync('conf/x', join(ROOT, '.bashrc'))
    expect(await fromRoot(() => heldBy([]))).toEqual([
      [join(ROOT, '.bashrc'), 'conf/x'],
    ])
  })

  it('for a link that leads out of every write root, or to a device', async () => {
    symlinkSync(OUTSIDE, join(ROOT, 'leads-out'))
    expect(await heldBy(inRoot(['leads-out/file', 'blank']))).toEqual([
      ...pairs('blank'),
      [join(ROOT, 'leads-out'), OUTSIDE],
    ])
  })

  it('under a write root that is the root', async () => {
    expect(
      await heldBy([], {
        writeConfig: { allowOnly: ['/'], denyWithinAllow: inRoot(['name']) },
      }),
    ).toEqual(pairs('name'))
  })

  it('none for a path with no link on the way', async () => {
    expect(await heldBy(inRoot(['beside', 'conf/x', 'absent']))).toEqual([])
  })

  it('none that lies where the command cannot write', async () => {
    symlinkSync(join(ROOT, 'conf', 'x'), join(OUTSIDE, 'into-root'))
    expect(await heldBy([join(OUTSIDE, 'into-root')])).toEqual([])
  })

  it('none in the directories the sandbox mounts anew', async () => {
    expect(
      await heldBy([], {
        writeConfig: {
          allowOnly: ['/'],
          denyWithinAllow: ['/proc/self/cwd/file', join(ROOT, 'out')],
        },
      }),
    ).toEqual(pairs('out'))
  })

  it('none that a read deny hides', async () => {
    const options = { readConfig: { denyOnly: [join(ROOT, 'holder')] } }
    const denied = inRoot(['holder/commands', 'name'])
    expect(await heldBy(denied, options)).toEqual(pairs('name'))
    if (bwrapCanNamespace()) {
      expect(stdoutOf(await wrapLinux(denied, options))).toBe('started\n')
    }
  })

  it('none that is bound back by itself into a directory a read deny hides', async () => {
    mkdirSync(join(ROOT, 'holder', 'inner'))
    symlinkSync('inner', join(ROOT, 'holder', 'to-inner'))
    const options = {
      readConfig: {
        denyOnly: [join(ROOT, 'holder')],
        allowWithinDeny: inRoot(['holder/to-inner']),
      },
    }
    const denied = inRoot(['holder/to-inner/file'])
    expect(await heldBy(denied, options)).toEqual([])
    if (bwrapCanNamespace()) {
      expect(stdoutOf(await wrapLinux(denied, options))).toBe('started\n')
    }
  })

  it('the directories above a held link are pinned', async () => {
    const holder = join(ROOT, 'holder')
    expect(await wrapLinux(inRoot(['holder/commands']))).toContain(
      `--ro-bind ${holder} ${holder} `,
    )
  })

  it.if(modesCount)(
    'a directory that cannot be looked in is bound read-only in place of the path',
    async () => {
      const holder = join(ROOT, 'holder')
      chmodSync(holder, 0)
      const { result: wrapped, warnings } = await withCapturedWarnings(() =>
        wrapLinux(inRoot(['holder/commands', 'holder/other'])),
      )
      // Beneath the write root's bind it is a pin, after it a deny.
      expect(
        wrapped.lastIndexOf(`--ro-bind ${holder} ${holder} `),
      ).toBeGreaterThan(wrapped.indexOf(`--bind ${ROOT} ${ROOT} `))
      expect(wrapped).not.toContain(`${holder}/`)
      expect(warnings.join()).toContain(`denying ${holder} whole`)
    },
  )

  it.each<[string, (name: string) => Partial<LinuxOptions>]>([
    ['a read deny', name => ({ readConfig: { denyOnly: [name] } })],
    [
      'a match of a read-deny pattern',
      name => ({ readConfig: { denyOnly: [], matchedLinks: [name] } }),
    ],
    [
      'a masked file',
      name => ({ maskedFileBinds: [{ realPath: name, fakePath: '/fakes/0' }] }),
    ],
  ])('the links on the way to %s', async (_what, options) => {
    expect(await heldBy([], options(join(ROOT, 'first')))).toEqual(
      pairs('first', 'middle'),
    )
  })

  it('a link that leads to nothing yet, for a read deny on it', async () => {
    expect(
      await heldBy([], { readConfig: { denyOnly: inRoot(['dangling']) } }),
    ).toEqual(pairs('dangling'))
  })

  it('a read deny that is where it resolves to is not walked', async () => {
    const spy = spyOn(fs, 'lstatSync')
    try {
      await wrapLinux([], { readConfig: { denyOnly: inRoot(['conf/x']) } })
      expect(
        spy.mock.calls.filter(([p]) => String(p).startsWith(ROOT)),
      ).toEqual([])
    } finally {
      spy.mockRestore()
    }
  })

  it('a refusal for length says how much of it names links', async () => {
    const wrap = (denied: string[]): Promise<string> =>
      wrapLinux(denied, { command: 'a'.repeat(2 ** 21) }).then(
        () => 'wrapped',
        (error: Error) => error.message,
      )
    const words = `--hold-link ${ROOT}/name conf/x`
    expect(await wrap(inRoot(['name']))).toContain(
      `At least ${words.length} of them are not the caller's`,
    )
    expect(await wrap([])).toMatch(/the limit here is \d+\)$/)
  })
})

describe.if(isLinux)('where no link is held', () => {
  beforeEach(forgetLinuxUnheldLinks)

  /** A helper that notes each time it is run, then does as `script` says. */
  const noting = (script: string): string =>
    program('noting-helper', `echo run >> ${OUTSIDE}/runs\n${script}`)
  const runs = (): number =>
    existsSync(join(OUTSIDE, 'runs'))
      ? readFileSync(join(OUTSIDE, 'runs'), 'utf8').split('\n').length - 1
      : 0
  /** As a helper built before the option does. */
  const RUNS_ITS_WORDS = 'exec "$@"'
  /** `helper` for the one this library finds for itself. */
  const found = (helper: string): { mockRestore(): void } =>
    spyOn(seccomp, 'getApplySeccompBinaryPath').mockReturnValue(helper)
  const unheld = (
    reason: LinuxUnheldLinkReason,
  ): ReturnType<typeof getLinuxUnheldLinks> =>
    inRoot(['first', 'middle']).map(path => ({ path, reason }))

  it.each<[LinuxUnheldLinkReason, string, () => Partial<LinuxOptions>]>([
    ['no_helper', 'no helper runs', () => ({ allowAllUnixSockets: true })],
    [
      'told_no',
      'the caller says its helper does not hold links',
      () => ({
        seccompConfig: { applyPath: noting('exit 0'), holdsLinks: false },
      }),
    ],
    [
      'told_no',
      'the caller turns holding off',
      () => ({ seccompConfig: { holdsLinks: false } }),
    ],
    [
      'not_told',
      "the helper is the caller's, which says nothing",
      () => ({ seccompConfig: { applyPath: noting('exit 0') } }),
    ],
    [
      'not_told',
      'the same of one that is run under another name',
      () => ({
        seccompConfig: { applyPath: noting('exit 0'), argv0: 'apply-seccomp' },
      }),
    ],
  ])(
    '%s, %s: they are named, nothing is run to find out, and the command starts',
    async (reason, _what, rest) => {
      const { result: wrapped, warnings } = await withCapturedWarnings(() =>
        wrapLinux(inRoot(['first']), rest()),
      )

      expect(wrapped).not.toContain('--hold-link')
      expect(getLinuxUnheldLinks()).toEqual(unheld(reason))
      for (const { path } of unheld(reason)) {
        expect(
          warnings.some(l => l.includes(`${path},`) && l.includes(reason)),
        ).toBe(true)
      }
      expect(runs()).toBe(0)
      if (bwrapCanNamespace() && !wrapped.includes('noting-helper')) {
        expect(stdoutOf(wrapped)).toBe('started\n')
      }
    },
  )

  it("the caller's word that its helper holds links is taken, and nothing is run", async () => {
    const wrapped = await wrapLinux(inRoot(['first']), {
      seccompConfig: {
        applyPath: '/proc/self/fd/3',
        argv0: 'apply-seccomp',
        holdsLinks: true,
      },
    })
    expect(wrapped).toContain(
      `ARGV0=apply-seccomp /proc/self/fd/3 --hold-link ${ROOT}/first middle `,
    )
    expect(getLinuxUnheldLinks()).toEqual([])
  })

  it('a helper the library found for itself is asked once', async () => {
    const spy = found(noting(RUNS_ITS_WORDS))
    try {
      for (const _ of [1, 2]) {
        expect(await wrapLinux(inRoot(['first']))).not.toContain('--hold-link')
        expect(getLinuxUnheldLinks()).toEqual(unheld('older_helper'))
      }
    } finally {
      spy.mockRestore()
    }
    expect(runs()).toBe(1)
  })

  it('it is not asked where there is nothing to hold', async () => {
    const spy = found(noting(RUNS_ITS_WORDS))
    try {
      await wrapLinux(inRoot(['beside']))
    } finally {
      spy.mockRestore()
    }
    expect(runs()).toBe(0)
  })

  it.each([
    ['ends by a signal', 'kill -9 $$', 0o755, 2],
    ['cannot be started', '', 0o644, 0],
  ])(
    'one that %s is asked twice, and again at the next wrap',
    async (_what, script, mode, perWrap) => {
      const helper = noting(script)
      chmodSync(helper, mode)
      const spy = found(helper)
      try {
        for (const wraps of [1, 2]) {
          const { warnings } = await withCapturedWarnings(() =>
            wrapLinux(inRoot(['first'])),
          )
          expect(getLinuxUnheldLinks()).toEqual(unheld('no_answer'))
          expect(
            warnings.filter(l => l.includes('gave no answer')),
          ).toHaveLength(2)
          expect(runs()).toBe(perWrap * wraps)
        }
      } finally {
        spy.mockRestore()
      }
    },
  )

  it('asking an older helper runs no program of that name', async () => {
    const named = join(ROOT, '--holds-links')
    writeFileSync(named, `#!/bin/sh\necho ran > ${ROOT}/ran\n`)
    chmodSync(named, 0o755)
    const PATH = process.env.PATH
    process.env.PATH = `${ROOT}:.:${PATH}`
    const spy = found(noting(RUNS_ITS_WORDS))
    try {
      await fromRoot(() => wrapLinux(inRoot(['name'])))
    } finally {
      spy.mockRestore()
      process.env.PATH = PATH
    }
    expect(runs()).toBe(1)
    expect(existsSync(join(ROOT, 'ran'))).toBe(false)
  })

  it('a link is listed by the latest wrap that met it', async () => {
    await wrapLinux(inRoot(['first']), { allowAllUnixSockets: true })
    expect(await wrapLinux(inRoot(['middle']))).toContain('--hold-link')
    expect(getLinuxUnheldLinks()).toEqual(unheld('no_helper').slice(0, 1))
  })

  it('a wrap that throws names none', async () => {
    const wrap = wrapLinux(inRoot(['first']), {
      allowAllUnixSockets: true,
      binShell: 'no-such-shell',
    })
    expect(wrap).rejects.toThrow('no-such-shell')
    await wrap.catch(() => {})
    expect(getLinuxUnheldLinks()).toEqual([])
  })

  describe('as the manager lists them', () => {
    const config = (allowAllUnixSockets: boolean): SandboxRuntimeConfig => ({
      network: { allowedDomains: [], deniedDomains: [], allowAllUnixSockets },
      filesystem: {
        denyRead: [],
        allowWrite: [ROOT],
        denyWrite: inRoot(['first']),
      },
    })
    afterEach(() => SandboxManager.reset())

    it('takes the word on the helper from the configuration', async () => {
      const { seccomp: parsed } = SandboxRuntimeConfigSchema.parse({
        ...config(false),
        seccomp: { holdsLinks: false },
      })
      expect(parsed).toEqual({ holdsLinks: false })
      await SandboxManager.initialize({ ...config(false), seccomp: parsed })
      await SandboxManager.wrapWithSandbox('true')
      expect(SandboxManager.getLinuxUnheldLinks()).toEqual(unheld('told_no'))
    })

    it('lists them', async () => {
      await SandboxManager.initialize(config(true))
      await SandboxManager.wrapWithSandbox('true')
      expect(SandboxManager.getLinuxUnheldLinks()).toEqual(unheld('no_helper'))
    })

    it.each<[string, () => void | Promise<void>]>([
      ['reset()', () => SandboxManager.reset()],
      ['updateConfig()', () => SandboxManager.updateConfig(config(true))],
    ])('%s empties the list', async (_what, act) => {
      await SandboxManager.initialize(config(true))
      await SandboxManager.wrapWithSandbox('true')
      expect(SandboxManager.getLinuxUnheldLinks()).not.toEqual([])
      await act()
      expect(SandboxManager.getLinuxUnheldLinks()).toEqual([])
    })
  })
})

describe.if(isLinux && bwrapCanNamespace())('the seccomp helper', () => {
  const helper = (): string => seccomp.getApplySeccompBinaryPath()!
  const run = (
    runnable: string,
    words: string[],
  ): { status: number | null; said: string } => {
    const result = spawnSync(runnable, words, {
      encoding: 'utf8',
      timeout: 30000,
      cwd: ROOT,
    })
    return { status: result.status, said: result.stdout + result.stderr }
  }
  const holding = (...names: Array<keyof typeof LINKS>): string[] =>
    names.flatMap(name => ['--hold-link', join(ROOT, name), LINKS[name]])
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
    ['a file is at the name', 'beside', '', 'not a symbolic link'],
    ['nothing is at the name', 'absent', '', 'No such file or directory'],
    ['the link says more', 'name', 'conf', 'leads elsewhere than it did'],
    ['the link says less', 'name', 'conf/xy', 'leads elsewhere than it did'],
    [
      'the link says another thing',
      'name',
      'conf/y',
      'leads elsewhere than it did',
    ],
  ])('runs no command where %s, and says why', (_what, name, target, why) => {
    expect(
      run(helper(), ['--hold-link', join(ROOT, name), target, 'echo', 'ran']),
    ).toEqual({
      status: 1,
      said: `apply-seccomp: --hold-link ${join(ROOT, name)}: ${why}\n`,
    })
  })

  it('holds a link it is given no word on', () => {
    expect(
      run(helper(), ['--hold-link', join(ROOT, 'name'), '', 'rm', 'name']).said,
    ).toContain('Device or resource busy')
  })

  it.each([
    ['this user', [], 'EPERM'],
    ['uid 0, with every capability in its namespace', ['-Ur'], 'EINVAL'],
  ])('a command of %s cannot unmount the hold', (_who, as, errno) => {
    const { said } = run('unshare', [
      ...as,
      helper(),
      ...holding('name'),
      ...UNMOUNT,
      join(ROOT, 'name'),
    ])
    expect(said.trim()).toBe(errno)
  })

  it('a hold keeps the flags of the file system that holds the link', () => {
    const link = join(OUTSIDE, 'link')
    const { said } = run('unshare', [
      ...['-Urm', 'sh', '-c'],
      `mount -t tmpfs -o noexec,noatime,nosymfollow none ${OUTSIDE} && ` +
        `echo read > ${OUTSIDE}/x && ln -s x ${link} && ` +
        `exec ${helper()} --hold-link ${link} x sh -c 'rm ${link}; cat ${link}'`,
    ])
    expect(said).toContain('Device or resource busy')
    expect(said).toContain('Too many levels of symbolic links')
    expect(said).not.toContain('read')
  })

  it.each(['--ro-bind', '--bind', '--dev-bind'])(
    'a bubblewrap the command starts with %s / / starts, and the hold holds there',
    bind => {
      const { said } = run(helper(), [
        ...holding('name', 'way', 'dangling'),
        ...['bwrap', bind, '/', '/', '--bind', ROOT, ROOT, '--dev', '/dev'],
        ...['sh', '-c', 'echo started; rm name way dangling'],
      ])
      expect(said).toContain('started')
      expect(said.match(/Device or resource busy/g)).toHaveLength(3)
    },
  )

  it('a link that says another thing by the time the command runs: nothing runs', async () => {
    const wrapped = await wrapLinux(inRoot(['name']))
    rmSync(join(ROOT, 'name'))
    symlinkSync('conf/z', join(ROOT, 'name'))
    const result = spawnSync(wrapped, { shell: true, encoding: 'utf8' })
    expect(result.stdout).toBe('')
    expect(result.stderr).toContain(
      `apply-seccomp: --hold-link ${ROOT}/name: leads elsewhere than it did`,
    )
  })
})

describe.if(isLinux && bwrapCanNamespace())(
  'A read deny on a name that is a link, over two commands',
  () => {
    const SECRET = 'secret-content'
    afterEach(() => SandboxManager.reset())

    it.each<
      [string, string, (name: string) => Partial<SandboxRuntimeConfig>, string]
    >([
      ['denyRead', 'file', name => ({ filesystem: lists([name]) }), ''],
      ['denyRead', 'dir', name => ({ filesystem: lists([name]) }), '/file'],
      [
        'a denyRead pattern',
        'file',
        name => ({ filesystem: lists([`${name}*`]) }),
        '',
      ],
      [
        'a credential deny',
        'file',
        path => ({ credentials: { files: [{ path, mode: 'deny' }] } }),
        '',
      ],
      [
        'a credential mask',
        'file',
        path => ({ credentials: { files: [{ path, mode: 'mask' }] } }),
        '',
      ],
    ])(
      '%s on a link to a %s: the name stays, and what it leads to stays hidden',
      async (_kind, leadsTo, listing, inside) => {
        mkdirSync(join(OUTSIDE, 'dir'))
        writeFileSync(join(OUTSIDE, 'file'), SECRET)
        writeFileSync(join(OUTSIDE, 'dir', 'file'), SECRET)
        const name = join(ROOT, 'linked')
        symlinkSync(join(OUTSIDE, leadsTo), name)
        await SandboxManager.initialize({
          network: { allowedDomains: [], deniedDomains: [] },
          filesystem: lists([]),
          ...listing(name),
        })
        const saidBy = async (command: string): Promise<string> => {
          const said = stdoutOf(
            await SandboxManager.wrapWithSandbox(`echo ran; ${command}`),
          )
          SandboxManager.cleanupAfterCommand()
          expect(said).toStartWith('ran\n')
          return said
        }

        await saidBy(`rm ${name}; mv ${name} ${name}-aside; echo x > ${name}`)
        expect(readlinkSync(name)).toBe(join(OUTSIDE, leadsTo))
        expect(
          await saidBy(`cat ${join(OUTSIDE, leadsTo)}${inside}`),
        ).not.toContain(SECRET)
      },
    )

    function lists(denyRead: string[]): SandboxRuntimeConfig['filesystem'] {
      return { denyRead, allowWrite: [ROOT], denyWrite: [] }
    }
  },
)
