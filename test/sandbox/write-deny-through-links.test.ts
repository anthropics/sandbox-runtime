import {
  describe,
  it,
  expect,
  beforeEach,
  afterEach,
  mock,
  spyOn,
} from 'bun:test'
import * as fs from 'fs'
import { spawnSync, type SpawnSyncReturns } from 'node:child_process'
import { homedir, tmpdir } from 'node:os'
import { join, relative } from 'node:path'
import type { LinuxUnheldLink } from '../../src/index.js'
import * as seccomp from '../../src/sandbox/generate-seccomp-filter.js'
import { wrapCommandWithSandboxLinux } from '../../src/sandbox/linux-sandbox-utils.js'
import { wrapCommandWithSandboxMacOS } from '../../src/sandbox/macos-sandbox-utils.js'
import { SandboxRuntimeConfigSchema } from '../../src/sandbox/sandbox-config.js'
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

const CWD = process.cwd()
// Where the temp dir really is: macOS names it through a link.
const BASE = join(fs.realpathSync(tmpdir()), `write-deny-links-${process.pid}`)
const ROOT = join(BASE, 'root') // the one write root
const OUTSIDE = join(BASE, 'outside') // beside it, under no write root
const HOLDER = join(ROOT, 'holder')
const inRoot = (names: string[]): string[] => names.map(n => join(ROOT, n))

/** Link name in ROOT -> what it says. A deny leads through every one. */
const LINKS = {
  name: 'conf/x',
  'holder/commands': '../shared/commands',
  dangling: 'later',
  way: 'real',
  here: '.',
  first: 'middle',
  middle: 'conf/y',
  up: 'in/to/../../real/secret',
  past: 'lost/../gone/../name',
  deep: 'void/deeper/../../real/secret',
  far: 'holder/blank',
  'holder/blank': '/dev/null',
  out: '/dev/stdout',
}
type Link = keyof typeof LINKS
const said = (names: Link[]): string[][] => names.map(n => [n, LINKS[n]])
/**
 * A name in ROOT, the links on the way to it and where they lead; then the
 * directories the way goes up from, and the names that are not there and that
 * it goes up from all the same.
 */
const WAYS: Array<[string, Link[], string, string[], string[]]> = [
  ['name', ['name'], 'conf/x', [], []],
  ['holder/commands', ['holder/commands'], 'shared/commands', ['holder'], []],
  ['dangling', ['dangling'], 'later', [], []],
  ['way/secret', ['way'], 'real/secret', [], []],
  ['way/absent', ['way'], 'real/absent', [], []],
  // A link is named where it lies, whatever it was reached through.
  ['here/name', ['here', 'name'], 'conf/x', [], []],
  ['first', ['first', 'middle'], 'conf/y', [], []],
  ['up', ['up'], 'real/secret', ['in/to', 'in'], []],
  ['past', ['past', 'name'], 'conf/x', [], ['lost', 'gone']],
  // Further on among names that are not there: it ends at the first.
  ['deep', ['deep'], 'void', [], []],
]
const DENIED = inRoot([...WAYS.map(([name]) => name), 'far', 'out'])
const FILES = ['conf/x', 'conf/y', 'conf/z', 'real/secret', 'beside']
const ABSENT = ['later', 'real/absent', 'shared/commands/new', 'lost', 'gone']
/** EBUSY, as glibc words it ("Device or resource busy") or musl. */
const BUSY = /resource busy/i
/** No mode keeps uid 0 from looking. */
const modesCount = process.getuid?.() !== 0
const namespaces = isLinux && bwrapCanNamespace()

beforeEach(() => {
  if (isWindows) return
  for (const dir of ['conf', 'shared/commands', 'real', 'holder', 'in/to']) {
    fs.mkdirSync(join(ROOT, dir), { recursive: true })
  }
  fs.mkdirSync(OUTSIDE)
  for (const file of FILES) fs.writeFileSync(join(ROOT, file), 'original')
  for (const [link, says] of Object.entries(LINKS)) {
    fs.symlinkSync(says, join(ROOT, link))
  }
})

afterEach(async () => {
  if (isWindows) return
  mock.restore()
  process.chdir(CWD)
  // Removes what bubblewrap made to mount on, and empties the list of links.
  await SandboxManager.reset()
  fs.chmodSync(HOLDER, 0o755)
  fs.rmSync(BASE, { recursive: true, force: true })
})

/** `command`, run by a shell: unless told otherwise under no write root, so
 *  that nothing of the working directory's is protected or made. */
const run = (command: string, cwd = OUTSIDE): SpawnSyncReturns<string> =>
  spawnSync(command, { shell: true, encoding: 'utf8', cwd, timeout: 30000 })

type Options = Parameters<typeof wrapCommandWithSandboxLinux>[0] &
  Parameters<typeof wrapCommandWithSandboxMacOS>[0]
type Rest = Partial<Options>

/** `denyWithinAllow` denied in ROOT, the write root beside two devices. */
function denying(denyWithinAllow: string[], rest?: Rest): Options {
  const allowOnly = [ROOT, '/dev/null', '/dev/stdout']
  return {
    command: 'echo started',
    needsNetworkRestriction: false,
    readConfig: { denyOnly: [] },
    writeConfig: { allowOnly, denyWithinAllow },
    ...rest,
  }
}

describe.if(!isWindows)('the links on the way to a path', () => {
  /** What is said of `p`, a name in ROOT, with the names in ROOT again. */
  const followed = (p: string): object => {
    const { links, left, ...rest } = followLinks(`${ROOT}/${p}`)
    const told = JSON.stringify({ links: [...links], left: [...left], ...rest })
    return JSON.parse(told.split(`${ROOT}/`).join('')) as object
  }
  const NONE = { left: [], passed: [] }

  it.each<(typeof WAYS)[number]>([
    ...WAYS,
    ['beside', [], 'beside', [], []],
    ['absent/name', [], 'absent/name', [], []],
    ['beside/name', [], 'beside/name', [], []],
    ['way/absent/deeper', ['way'], 'real/absent/deeper', [], []],
    // Folded in text, as everywhere a configured name is read.
    ['./way/./secret/', ['way'], 'real/secret', [], []],
    ['holder/commands/../name', [], 'holder/name', [], []],
  ])('%s: %p, ending at %s', (p, links, end, left, passed) => {
    expect(followed(p)).toEqual({ links: said(links), left, passed, end })
  })

  it.each([
    ['longer than a name can be', 'a'.repeat(300)],
    ['with a NUL byte', 'nul\0byte'],
  ])('a name %s: nothing can be there, so it has looked', (_what, name) => {
    expect(followed(`way/${name}`)).toEqual({ links: said(['way']), ...NONE })
  })

  // Not every file system takes such a target.
  it.if(isLinux)('has no end past a target that is no text', () => {
    fs.symlinkSync(Buffer.from([0x78, 0xff]), join(ROOT, 'raw'))
    expect(followed('raw/file')).toEqual({ links: [['raw', '']], ...NONE })
  })

  it('follows 40 links, and has no end past them, where the kernel gives up too', () => {
    for (let i = 1; i <= 41; i++) {
      fs.symlinkSync(i > 1 ? `hop-${i - 1}` : 'beside', join(ROOT, `hop-${i}`))
    }
    expect(followed('hop-40')).toMatchObject({ end: 'beside' })
    expect(Object.keys(followed('hop-41'))).toEqual(['links', 'left', 'passed'])
    expect(() => fs.readFileSync(join(ROOT, 'hop-41'))).toThrow('ELOOP')
  })

  it.if(modesCount)('says which directory it could not look in', () => {
    fs.chmodSync(HOLDER, 0)
    fs.symlinkSync('holder/commands/../made', join(ROOT, 'via'))
    expect(followed('via')).toMatchObject({ ...NONE, unsearched: 'holder' })
  })

  const failing = (at?: fs.PathLike): never => {
    throw Object.assign(new Error('EIO'), { code: 'EIO', path: at })
  }

  it('looks again where a look fails', () => {
    spyOn(fs, 'readlinkSync').mockImplementationOnce(failing)
    expect(followed('name')).toMatchObject({ end: 'conf/x' })
  })

  it('where that fails too: the directory of what it looked at', () => {
    spyOn(fs, 'readlinkSync').mockImplementation(failing)
    expect(followed('way/secret')).toMatchObject({ unsearched: ROOT })
  })

  it('and does not say where: the directory of the path as written', () => {
    spyOn(fs, 'readlinkSync').mockImplementation(() => failing())
    expect(followed('way/secret')).toMatchObject({ unsearched: 'way' })
  })

  it('in the root: no directory, which would stand in for everything', () => {
    spyOn(fs, 'lstatSync').mockImplementation(failing)
    expect(followed('name')).toEqual({ links: [], ...NONE })
  })
})

describe.if(namespaces || isMacOS)('a deny with a link on the way', () => {
  /** What `attempt` came to, run in ROOT with every one of `denied` denied. */
  async function outcomeOf(attempt: string, denied = DENIED): Promise<string> {
    const options = denying(denied, {
      command: `cd ${ROOT} && if ( ${attempt} ); then echo DONE; else echo refused; fi`,
      // Linux mounts a read deny where it resolves, under the /dev it then
      // makes anew, and bubblewrap before 0.5.0 takes no device to mount on.
      readConfig: { denyOnly: isMacOS ? inRoot(['far']) : [] },
    })
    const { stdout } = run(
      isLinux
        ? await wrapCommandWithSandboxLinux(options)
        : wrapCommandWithSandboxMacOS(options),
    )
    SandboxManager.cleanupAfterCommand()
    return stdout.trim()
  }

  it.each([
    ...Object.keys(LINKS).flatMap(link => [
      `rm ${link}`,
      `mv ${link} aside`,
      `ln -sfn beside ${link}`,
    ]),
    ...['name', 'dangling', 'middle'].map(
      link => `echo new > made && mv -f made ${link}`,
    ),
    // A write or a create through the links, and by the path they lead to.
    ...[...new Set(WAYS.flatMap(([name, , end]) => [name, end]))].map(
      at => `echo changed >> ${at} || echo new > ${at}/new`,
    ),
    'rm conf/x',
    // The directories above a link and above what it leads to, those the way
    // goes up from, and the names that are not there.
    'mv holder aside',
    'mv conf aside',
    'mv in/to aside',
    'mv in aside',
    'mkdir lost',
    'ln -s conf gone',
  ])('refuses: %s', async attempt => {
    expect(await outcomeOf(attempt)).toBe('refused')

    for (const [link, says] of Object.entries(LINKS)) {
      expect(fs.readlinkSync(join(ROOT, link))).toBe(says)
    }
    for (const file of FILES) {
      expect(fs.readFileSync(join(ROOT, file), 'utf8')).toBe('original')
    }
    expect(inRoot(ABSENT).filter(fs.existsSync)).toEqual([])
  })

  it.each([
    'echo changed >> beside && rm beside',
    'echo new > new && echo new > holder/new',
    'echo changed >> conf/z',
    'ln -s conf/z free && ln -sfn beside free',
    'test "$(readlink name)$(cat name way/secret)" = conf/xoriginaloriginal',
    'echo x > /dev/null && cat /dev/null',
  ])('allows: %s', async attempt => {
    expect(await outcomeOf(attempt)).toBe('DONE')
  })

  it.each(['rm .bashrc', 'echo changed >> conf/z', 'rm .claude/commands'])(
    'the same of the names denied in every working directory: %s',
    async attempt => {
      fs.mkdirSync(join(ROOT, '.claude'))
      fs.symlinkSync('conf/z', join(ROOT, '.bashrc'))
      fs.symlinkSync('../shared/commands', join(ROOT, '.claude', 'commands'))
      process.chdir(ROOT)
      expect(await outcomeOf(attempt, [])).toBe('refused')
    },
  )

  it.if(modesCount)('a directory it cannot look in is kept whole', async () => {
    expect(await outcomeOf('chmod 000 holder')).toBe('DONE')
    const undoing = 'chmod 755 holder; rm holder/commands || rm -r holder'
    expect(await outcomeOf(undoing)).toBe('refused')
    expect(fs.lstatSync(HOLDER).mode & 0o777).toBe(0)
    fs.chmodSync(HOLDER, 0o755)
    expect(fs.readdirSync(HOLDER).sort()).toEqual(['blank', 'commands'])
  })
})

// Profile text only, so it runs on every POSIX host.
describe.if(!isWindows)('Seatbelt profile', () => {
  /** The filters of the rule that denies `ops`, one to a line. */
  function deniedBy(ops: string, write: string[], read: string[] = []): string {
    const profile = wrapCommandWithSandboxMacOS(
      denying(write, { readConfig: { denyOnly: read } }),
    )
    const at = profile.indexOf(`(deny ${ops}\n`)
    expect(at).toBeGreaterThan(-1)
    return profile.slice(at, profile.indexOf('(with message', at))
  }
  const KEPT = 'file-write-unlink file-write-create'
  const subpath = (name: string): string => `(subpath "${join(ROOT, name)}")\n`
  const literal = (name: string): string => `(literal "${join(ROOT, name)}")\n`

  it.each(WAYS)('%s keeps %p, denies %s', (name, links, end, left, passed) => {
    const denies = deniedBy('file-write*', inRoot([name]))
    for (const at of [name, end, ...passed]) {
      expect(denies).toContain(subpath(at))
    }
    const kept = deniedBy(KEPT, inRoot([name]))
    for (const at of [...links, ...left]) expect(kept).toContain(literal(at))
  })

  it('so is one on a name denied in every working directory', () => {
    fs.symlinkSync('conf/x', join(ROOT, '.bashrc'))
    process.chdir(ROOT)
    expect(deniedBy('file-write*', [])).toContain(subpath('conf/x'))
  })

  it('a pattern deny starts from both spellings of its directory', () => {
    const denies = deniedBy('file-write*', inRoot(['way/*.key']))
    const matches = (file: string): boolean =>
      [...denies.matchAll(/^ {2}\(regex (".*")\)$/gm)].some(([, text]) =>
        new RegExp(JSON.parse(text!) as string).test(join(ROOT, file)),
      )
    expect(matches('way/a.key')).toBe(true)
    expect(matches('real/a.key')).toBe(true)
    expect(matches('conf/a.key')).toBe(false)
  })

  it('nothing among the devices is denied or kept; the links to them are kept, and what holds one', () => {
    fs.symlinkSync('/dev', join(ROOT, 'devices'))
    const denied = inRoot(['far', 'out', 'devices'])
    const kept = deniedBy(KEPT, denied)
    expect(deniedBy('file-write*', denied) + kept).not.toContain('"/dev')
    for (const name of ['far', 'holder/blank', 'holder', 'out', 'devices']) {
      expect(kept).toContain(literal(name))
    }
  })

  it('nor is a device hidden by a read deny on a link to it', () => {
    const denies = deniedBy('file-read*', [], inRoot(['far', 'name']))
    expect(denies).toContain(subpath('conf/x'))
    expect(denies).not.toContain('"/dev')
  })

  it.if(modesCount)('a directory it cannot look in is denied whole', () => {
    fs.chmodSync(HOLDER, 0)
    expect(deniedBy('file-write*', inRoot(['holder/commands']))).toContain(
      subpath('holder'),
    )
  })
})

function wrapLinux(denied: string[], rest?: Rest): Promise<string> {
  return wrapCommandWithSandboxLinux(denying(denied, rest))
}

/** An executable file in OUTSIDE that holds `script`. */
function program(name: string, script: string): string {
  const file = join(OUTSIDE, name)
  fs.writeFileSync(file, `#!/bin/sh\n${script}\n`, { mode: 0o755 })
  return file
}

/**
 * The words a wrap hands the seccomp helper before the command, as [link in
 * ROOT, target] pairs. Read by the shells themselves, through every level of
 * quoting, and with no namespace made: a stand-in for bubblewrap runs what
 * follows `--`, three words, and one for the helper only prints its words.
 */
async function heldBy(denied: string[], rest?: Rest): Promise<string[][]> {
  const bwrapPath = program('bwrap-stand-in', 'shift $(($# - 3)); exec "$@"')
  const applyPath = program('helper-stand-in', `printf '%s\\0' "$@"`)
  const seccompConfig = { applyPath, holdsLinks: true }
  const wrapped = await wrapLinux(denied, { bwrapPath, seccompConfig, ...rest })
  const words = run(wrapped).stdout.split('\0')
  const held: string[][] = []
  for (let i = 0; words[i] === '--hold-link'; i += 3) {
    held.push([relative(ROOT, words[i + 1]!), words[i + 2]!])
  }
  expect(words.slice(3 * held.length + 1)).toEqual(['-c', 'echo started', ''])
  return held.sort()
}

describe.if(isLinux)('what the seccomp helper is asked to hold', () => {
  it('each link once, with what it says; none for a path with no link on the way, or that lies where the command cannot write', async () => {
    fs.symlinkSync(join(ROOT, 'conf', 'x'), join(OUTSIDE, 'in'))
    const none = [...inRoot(['beside', 'absent']), join(OUTSIDE, 'in')]
    expect(await heldBy([...DENIED, ...none])).toEqual(
      Object.entries(LINKS).sort(),
    )
  })

  it('whatever characters the name and the target hold, U+FFFD too, with no word on a target that is no text', async () => {
    const odd = ["sp ace'quote", 'new\nline', '$(echo x)`y`', 'x�y']
    for (const name of odd) fs.symlinkSync(`to ${name}`, join(ROOT, name))
    fs.symlinkSync(Buffer.from([0x78, 0xff]), join(ROOT, 'bytes'))
    expect(await heldBy(inRoot([...odd, 'bytes']))).toEqual(
      [...odd.map(name => [name, `to ${name}`]), ['bytes', '']].sort(),
    )
  })

  it('for a deny written from the home or the working directory, and a name denied in every one', async () => {
    fs.symlinkSync('conf/x', join(ROOT, '.bashrc'))
    process.chdir(ROOT)
    const fromHome = `~/${relative(homedir(), join(ROOT, 'way', 'x'))}`
    expect(await heldBy(['name', fromHome])).toEqual([
      ['.bashrc', 'conf/x'],
      ...said(['name', 'way']),
    ])
  })

  it('under a write root that is the root, but none in the directories the sandbox mounts anew', async () => {
    const denyWithinAllow = ['/proc/self/cwd/file', ...inRoot(['name', 'out'])]
    expect(
      await heldBy([], { writeConfig: { allowOnly: ['/'], denyWithinAllow } }),
    ).toEqual(said(['name', 'out']))
  })

  it('none in a directory that a read deny hides, though the link is bound back by itself', async () => {
    fs.mkdirSync(join(HOLDER, 'inner'))
    fs.symlinkSync('inner', join(HOLDER, 'to-inner'))
    const denied = inRoot(['holder/to-inner/file', 'holder/commands', 'name'])
    const allowWithinDeny = [join(HOLDER, 'to-inner')]
    const hiding = { readConfig: { denyOnly: [HOLDER], allowWithinDeny } }
    expect(await heldBy(denied, hiding)).toEqual(said(['name']))
    if (namespaces) {
      expect(run(await wrapLinux(denied, hiding)).stdout).toBe('started\n')
    }
  })

  // In place of the paths in it.
  it.if(modesCount)('denies a directory it cannot look in whole', async () => {
    fs.chmodSync(HOLDER, 0)
    const { result: wrapped, warnings } = await withCapturedWarnings(() =>
      wrapLinux(inRoot(['holder/commands', 'holder/other'])),
    )
    // Beneath the write root's bind it is a pin, after it a deny.
    expect(
      wrapped.lastIndexOf(`--ro-bind ${HOLDER} ${HOLDER} `),
    ).toBeGreaterThan(wrapped.indexOf(`--bind ${ROOT} ${ROOT} `))
    expect(wrapped).not.toContain(`${HOLDER}/`)
    expect(warnings.join()).toContain(`denying ${HOLDER} whole`)
  })

  it('the links on the way to a read deny, one that leads to nothing yet too, to a match of a read-deny pattern and to a masked file', async () => {
    const [realPath, ...denyOnly] = inRoot(['way/secret', 'first', 'dangling'])
    expect(
      await heldBy([], {
        readConfig: { denyOnly, matchedLinks: inRoot(['name']) },
        maskedFileBinds: [{ realPath: realPath!, fakePath: '/fakes/0' }],
      }),
    ).toEqual(said(['dangling', 'first', 'middle', 'name', 'way']))
  })

  it('a read deny that is where it resolves to is not walked', async () => {
    const { calls } = spyOn(fs, 'lstatSync').mock
    await wrapLinux([], { readConfig: { denyOnly: inRoot(['conf/x']) } })
    expect(calls.filter(([p]) => String(p).startsWith(ROOT))).toEqual([])
  })

  it('a refusal for length says how much of it names links', async () => {
    const refusal = (denied: string[]): Promise<string> =>
      wrapLinux(denied, { command: 'a'.repeat(2 ** 21) }).catch(String)
    const words = `--hold-link ${ROOT}/name conf/x`
    expect(await refusal(inRoot(['name']))).toContain(
      `At least ${words.length} of them are not the caller's`,
    )
    expect(await refusal([])).toMatch(/the limit here is \d+\)$/)
  })
})

type Config = Parameters<typeof SandboxManager.initialize>[0]

/** ROOT for the one write root, and `first` denied in it. */
const config = (denyRead: string[], rest: Partial<Config> = {}): Config => ({
  network: { allowedDomains: [], deniedDomains: [] },
  filesystem: { denyRead, allowWrite: [ROOT], denyWrite: inRoot(['first']) },
  ...rest,
})

describe.if(isLinux)('where no link is held', () => {
  const [NEWER, OLDER] = [join(OUTSIDE, 'newer'), join(OUTSIDE, 'older')]
  const listed = SandboxManager.getLinuxUnheldLinks
  type Reason = LinuxUnheldLink['reason']
  const unheld = (reason: Reason, ...names: string[]): LinuxUnheldLink[] =>
    inRoot(names).map(path => ({ path, reason }))

  // The reason if any, `seccomp`, and the helper the library finds for itself.
  // The links are named, what holds one is not pinned for it either, and no
  // helper is run to find out.
  it.each<[Reason | '', Options['seccompConfig'], string]>([
    ['no_helper', {}, ''],
    ['told_no', { holdsLinks: false }, ''],
    ['told_no', { applyPath: NEWER, holdsLinks: false }, ''],
    ['not_told', { applyPath: NEWER }, ''],
    // What the library finds where nothing is at the path says nothing of it.
    ['not_told', { applyPath: '/in/the/sandbox', argv0: 'apply-seccomp' }, ''],
    ['', { applyPath: OLDER, holdsLinks: true }, ''],
    ['', {}, NEWER],
    ['older_helper', {}, OLDER],
    ['no_answer', {}, OUTSIDE],
  ])('"%s", told %j and finding "%s"', async (reason, seccompConfig, own) => {
    // One names the option that says so, one runs its words as older builds do.
    program('newer', `echo run > ${OUTSIDE}/run # --holds-links`)
    program('older', `echo run > ${OUTSIDE}/run; exec "$@"`)
    if (own) spyOn(seccomp, 'getApplySeccompBinaryPath').mockReturnValue(own)
    const allowAllUnixSockets = reason === 'no_helper'
    const { result: wrapped, warnings } = await withCapturedWarnings(() =>
      wrapLinux(inRoot(['far']), { seccompConfig, allowAllUnixSockets }),
    )

    for (const words of ['--hold-link', `--ro-bind ${HOLDER} ${HOLDER} `]) {
      expect(wrapped.includes(words)).toBe(reason === '')
    }
    const links = reason ? unheld(reason, 'far', 'holder/blank') : []
    expect(listed()).toEqual(links)
    for (const { path } of links) {
      expect(
        warnings.some(l => l.includes(`${path},`) && l.includes(reason)),
      ).toBe(true)
    }
    expect(fs.existsSync(join(OUTSIDE, 'run'))).toBe(false)
    if (namespaces && !seccompConfig?.applyPath && !own) {
      expect(run(wrapped).stdout).toBe('started\n')
    }
  })

  it.each<[string, () => void | Promise<void>]>([
    ['reset()', () => SandboxManager.reset()],
    ['updateConfig()', () => SandboxManager.updateConfig(config([]))],
  ])('listed by the latest wrap to meet it, until %s', async (_what, act) => {
    await wrapLinux(inRoot(['first']), { allowAllUnixSockets: true })
    await wrapLinux(inRoot(['first']), { seccompConfig: { holdsLinks: false } })
    expect(await wrapLinux(inRoot(['middle']))).toContain('--hold-link')
    expect(listed()).toEqual(unheld('told_no', 'first'))
    await act()
    expect(listed()).toEqual([])
  })

  it('a wrap that throws names none', async () => {
    const throwing = { allowAllUnixSockets: true, binShell: 'no-such-shell' }
    const refusal = await wrapLinux(inRoot(['first']), throwing).catch(String)
    expect(refusal).toContain('no-such-shell')
    expect(listed()).toEqual([])
  })

  it('what the way goes up from is pinned all the same where the command can replace no link on it', async () => {
    fs.symlinkSync(`${ROOT}/${LINKS.up}`, join(OUTSIDE, 'up'))
    const wrapped = await wrapLinux([join(OUTSIDE, 'up')], {
      seccompConfig: { holdsLinks: false },
    })
    for (const dir of inRoot(['in', 'in/to'])) {
      expect(wrapped).toContain(`--ro-bind ${dir} ${dir} `)
    }
    expect(listed()).toEqual([])
  })

  it('the manager takes the word on the helper from the configuration, and names the links its patterns match', async () => {
    await SandboxManager.initialize(
      SandboxRuntimeConfigSchema.parse(
        config(inRoot(['nam*', 'besid*']), { seccomp: { holdsLinks: false } }),
      ),
    )
    expect(SandboxManager.getFsReadConfig().matchedLinks).toEqual(
      inRoot(['name']),
    )
    await SandboxManager.wrapWithSandbox('true')
    expect(listed()).toEqual(unheld('told_no', 'first', 'middle', 'name'))
  })
})

describe.if(namespaces)('the seccomp helper', () => {
  const helper = (): string => seccomp.getApplySeccompBinaryPath()!
  /** For a shell in ROOT. With no word on what the first of them says. */
  const HOLDS =
    '--hold-link name "" --hold-link way real --hold-link dangling later'
  /** Lifts the helper's namespaces filter, which refuses every mount call. */
  const NAMESPACES_ALLOWED = 'SRT_ALLOW_NESTED_USERNS=1'
  const ELSEWHERE = 'leads elsewhere than it did'

  it('says that it holds links', () => {
    expect(run(`${helper()} --holds-links`).status).toBe(0)
  })

  it.each([
    ['a file is at the name', 'beside', '""', 'not a symbolic link'],
    ['nothing is at the name', 'absent', '""', 'No such file or directory'],
    ['the link says more', 'name', 'conf', ELSEWHERE],
    ['the link says less', 'name', 'conf/xy', ELSEWHERE],
    ['the link says another thing', 'name', 'conf/y', ELSEWHERE],
  ])('runs no command where %s, and says why', (_what, name, target, why) => {
    expect(
      run(`${helper()} --hold-link ${name} ${target} echo ran 2>&1`, ROOT),
    ).toMatchObject({
      status: 1,
      stdout: `apply-seccomp: --hold-link ${name}: ${why} (seccomp.holdsLinks: false in the sandbox configuration holds no link)\n`,
    })
  })

  // It has every capability in its namespace. The filter refuses the unmount;
  // where it is lifted, the lock does.
  it.each([
    ['', 'EPERM'],
    [NAMESPACES_ALLOWED, 'EINVAL'],
  ])('%s a command of uid 0 cannot unmount the hold', (env, errno) => {
    // umount2() with UMOUNT_NOFOLLOW, which reaches a mount on a link.
    const unmount =
      'import ctypes, errno; ctypes.CDLL(None, use_errno=True).umount2(b"name", 8); print(errno.errorcode[ctypes.get_errno()])'
    const { stdout } = run(
      `${env} unshare -Ur ${helper()} ${HOLDS} sh -c 'python3 -c "$0"; rm name 2>&1' '${unmount}'`,
      ROOT,
    )
    expect(stdout).toStartWith(`${errno}\n`)
    expect(stdout).toMatch(BUSY)
  })

  it('a hold keeps the flags of the file system that holds the link', () => {
    const { stdout } = run(
      `unshare -Urm sh -c 'mount -t tmpfs -o noexec,noatime,nosymfollow none ${OUTSIDE} && ` +
        `cd ${OUTSIDE} && echo read > x && ln -s x link && ` +
        `exec ${helper()} --hold-link link x sh -c "rm link; cat link"' 2>&1`,
    )
    expect(stdout).toMatch(BUSY)
    expect(stdout).toContain('Too many levels of symbolic links')
    expect(stdout).not.toContain('read')
  })

  it.each(['--ro-bind', '--bind', '--dev-bind'])(
    'a bubblewrap the command may start, with %s / /, starts, and the hold holds there',
    bind => {
      const { stdout } = run(
        `${NAMESPACES_ALLOWED} ${helper()} ${HOLDS} bwrap ${bind} / / --bind ${ROOT} ${ROOT} --dev /dev sh -c 'echo started; rm name way dangling' 2>&1`,
        ROOT,
      )
      expect(stdout).toContain('started')
      expect(stdout.match(new RegExp(BUSY, 'gi'))).toHaveLength(3)
    },
  )

  it('a link that says another thing by the time the command runs: nothing runs', async () => {
    const wrapped = await wrapLinux(inRoot(['name']))
    fs.rmSync(join(ROOT, 'name'))
    fs.symlinkSync('conf/z', join(ROOT, 'name'))
    expect(run(wrapped)).toMatchObject({
      stdout: '',
      stderr: expect.stringContaining(`--hold-link ${ROOT}/name: ${ELSEWHERE}`),
    })
  })
})

// The name stays, and what it leads to stays hidden.
describe.if(namespaces)('a read deny on a link, over two commands', () => {
  it.each<[string, string, string[], Array<'deny' | 'mask'>]>([
    ['denyRead', 'file', [''], []],
    ['denyRead', 'dir', [''], []],
    ['a denyRead pattern', 'file', ['*'], []],
    ['a credential deny', 'file', [], ['deny']],
    ['a credential mask', 'file', [], ['mask']],
  ])('%s on a link to a %s', async (_kind, leadsTo, endings, modes) => {
    const [name, target] = [join(ROOT, 'linked'), join(OUTSIDE, leadsTo)]
    fs.mkdirSync(join(OUTSIDE, 'dir'))
    fs.writeFileSync(join(OUTSIDE, 'file'), 'secret')
    fs.writeFileSync(join(OUTSIDE, 'dir', 'file'), 'secret')
    fs.symlinkSync(target, name)
    const files = modes.map(mode => ({ path: name, mode }))
    const denied = endings.map(ending => name + ending)
    await SandboxManager.initialize(config(denied, { credentials: { files } }))
    const saidBy = async (command: string): Promise<string> => {
      const { stdout } = run(
        await SandboxManager.wrapWithSandbox(`echo ran; ${command}`),
      )
      SandboxManager.cleanupAfterCommand()
      expect(stdout).toStartWith('ran\n')
      return stdout
    }

    await saidBy(`rm ${name}; mv ${name} ${name}-aside; echo x > ${name}`)
    expect(fs.readlinkSync(name)).toBe(target)
    expect(await saidBy(`cat ${target} ${target}/file`)).not.toContain('secret')
  })
})
