import { describe, it, expect, beforeAll, afterAll } from 'bun:test'
import {
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import {
  wrapCommandWithSandboxLinux,
  checkLinuxDependencies,
  cleanupBwrapMountPoints,
  OLDEST_FULLY_SUPPORTED_BWRAP_VERSION,
} from '../../src/sandbox/linux-sandbox-utils.js'
import { isLinux } from '../helpers/platform.js'

/**
 * One mount per destination.
 *
 * A file mask is a `--ro-bind` of something other than the destination
 * itself: the `/dev/null` a read deny puts over a file, the fake a
 * credential mask puts there, the `/dev/null` that covers an absent write
 * deny. Two of them at one destination, with nothing between that mounts at
 * or above it, is a mount whose only effect is to replace the one before it —
 * and bubblewrap before 0.5.0 refuses to start on it, because its
 * `ensure_file()` accepts only a regular file as the mount point for a file
 * bind and creates one over anything else, which on the read-only mount the
 * first mask just made fails with "Can't create file at <dest>: Permission
 * denied". Spellings of one path converge on one destination, so a corpus
 * that spells the same file several ways is where these appear.
 *
 * A mask re-applied after a later bind re-exposed the real file is NOT one of
 * these: that bind sits between the two and puts a mount point back.
 */
describe.if(isLinux)('One mount per destination', () => {
  let BASE: string
  let AREA: string
  let PROJ: string
  let SECRET: string
  let OTHER: string
  let SUB: string
  let LINK: string
  let FAKES: string
  const savedCwd = process.cwd()

  beforeAll(() => {
    BASE = realpathSync(mkdtempSync(join(tmpdir(), 'one-mount-')))
    AREA = join(BASE, 'area')
    PROJ = join(AREA, 'proj')
    SECRET = join(PROJ, 'secret.txt')
    OTHER = join(PROJ, 'other.txt')
    SUB = join(PROJ, 'sub')
    mkdirSync(SUB, { recursive: true })
    writeFileSync(SECRET, 'secret\n')
    writeFileSync(OTHER, 'other\n')
    writeFileSync(join(SUB, 'inner.txt'), 'inner\n')
    LINK = join(BASE, 'link')
    symlinkSync(PROJ, LINK)
    FAKES = join(BASE, 'fakes')
    mkdirSync(FAKES)
    writeFileSync(join(FAKES, '0.fake'), 'fake-0\n')
    writeFileSync(join(FAKES, '1.fake'), 'fake-1\n')
    // Keep cwd outside the allowlist, so the mandatory-deny scan adds no
    // mounts of its own to reason about.
    process.chdir(BASE)
  })

  afterAll(() => {
    process.chdir(savedCwd)
    cleanupBwrapMountPoints({ force: true })
    rmSync(BASE, { recursive: true, force: true })
  })

  type Mount = { index: number; flag: string; source?: string; dest: string }

  /** Every mount in the wrapped command, in the order bwrap applies them. */
  function mountsOf(command: string): Mount[] {
    const argv = command.split(/\s+/)
    const mounts: Mount[] = []
    for (const [index, flag] of argv.entries()) {
      if (flag === '--tmpfs' && argv[index + 1] !== undefined) {
        mounts.push({ index, flag, dest: argv[index + 1]! })
      } else if (
        (flag === '--bind' ||
          flag === '--ro-bind' ||
          flag === '--dev-bind' ||
          flag === '--bind-try' ||
          flag === '--ro-bind-try') &&
        argv[index + 2] !== undefined
      ) {
        mounts.push({
          index,
          flag,
          source: argv[index + 1]!,
          dest: argv[index + 2]!,
        })
      }
    }
    return mounts
  }

  const isAtOrUnder = (candidate: string, root: string): boolean =>
    root === '/' || candidate === root || candidate.startsWith(`${root}/`)

  /** A mask puts foreign content at the destination, so its source is not the
   * destination. A bind of a path onto itself (an allowed write path, a write
   * deny's read-only re-bind, the root) is not one, and neither is a tmpfs. */
  const isFileMask = (mount: Mount): boolean =>
    mount.flag === '--ro-bind' &&
    mount.source !== undefined &&
    mount.source !== mount.dest

  /**
   * Destinations given two file masks with nothing between them that mounts
   * at or above the destination. Rendered as text so a failure names the
   * mounts rather than reporting a count.
   */
  function maskedTwiceOver(command: string): string[] {
    const mounts = mountsOf(command)
    const masksByDest = new Map<string, Mount[]>()
    for (const mount of mounts.filter(isFileMask)) {
      const seen = masksByDest.get(mount.dest) ?? []
      seen.push(mount)
      masksByDest.set(mount.dest, seen)
    }
    const offences: string[] = []
    for (const [dest, masks] of masksByDest) {
      for (let i = 1; i < masks.length; i++) {
        const previous = masks[i - 1]!
        const current = masks[i]!
        const between = mounts.some(
          mount =>
            mount.index > previous.index &&
            mount.index < current.index &&
            isAtOrUnder(dest, mount.dest),
        )
        if (!between) {
          offences.push(
            `${dest}: ${previous.flag} ${previous.source} then ${current.flag} ${current.source}, nothing in between`,
          )
        }
      }
    }
    return offences
  }

  function wrap({
    denyRead = [],
    allowRead = [],
    allowWrite = [AREA],
    denyWrite = [],
    maskedFileBinds,
  }: {
    denyRead?: string[]
    allowRead?: string[]
    allowWrite?: string[]
    denyWrite?: string[]
    maskedFileBinds?: Array<{ realPath: string; fakePath: string }>
  }): Promise<string> {
    return wrapCommandWithSandboxLinux({
      command: 'true',
      needsNetworkRestriction: false,
      readConfig: { denyOnly: denyRead, allowWithinDeny: allowRead },
      writeConfig: { allowOnly: allowWrite, denyWithinAllow: denyWrite },
      maskedFileBinds,
      maskedFileStoreDir: maskedFileBinds === undefined ? undefined : FAKES,
    })
  }

  // Each entry spells one place more than once, through the routes a caller
  // and the credentials block reach it by: a tilde is expanded before this
  // function sees it, so the spellings that survive to here are the absolute
  // ones, a doubled slash, a trailing slash and a symlinked directory.
  const corpus = (): Array<{ what: string; wrapped: Promise<string> }> => [
    {
      what: 'one file denied under two absolute spellings',
      wrapped: wrap({ denyRead: [SECRET, `/${SECRET}`] }),
    },
    {
      what: 'one file denied directly and through a symlinked directory',
      wrapped: wrap({ denyRead: [SECRET, join(LINK, 'secret.txt')] }),
    },
    {
      what: 'one file denied with and without a trailing slash',
      wrapped: wrap({ denyRead: [SECRET, `${SECRET}/`] }),
    },
    {
      what: 'one file denied three ways at once',
      wrapped: wrap({
        denyRead: [SECRET, `/${SECRET}`, join(LINK, 'secret.txt')],
      }),
    },
    {
      what: 'a denied file that is also a masked credential file',
      wrapped: wrap({
        denyRead: [SECRET],
        maskedFileBinds: [
          { realPath: SECRET, fakePath: join(FAKES, '0.fake') },
        ],
      }),
    },
    {
      what: 'a denied file masked through a symlinked directory',
      wrapped: wrap({
        denyRead: [SECRET],
        maskedFileBinds: [
          {
            realPath: join(LINK, 'secret.txt'),
            fakePath: join(FAKES, '0.fake'),
          },
        ],
      }),
    },
    {
      what: 'one file masked twice under two spellings',
      wrapped: wrap({
        maskedFileBinds: [
          { realPath: SECRET, fakePath: join(FAKES, '0.fake') },
          {
            realPath: join(LINK, 'secret.txt'),
            fakePath: join(FAKES, '1.fake'),
          },
        ],
      }),
    },
    {
      what: 'two denied spellings and two masked spellings of one file',
      wrapped: wrap({
        denyRead: [SECRET, join(LINK, 'secret.txt')],
        maskedFileBinds: [
          { realPath: SECRET, fakePath: join(FAKES, '0.fake') },
          {
            realPath: join(LINK, 'secret.txt'),
            fakePath: join(FAKES, '1.fake'),
          },
        ],
      }),
    },
    {
      what: 'a denied file under a write deny that re-exposes it',
      wrapped: wrap({ denyRead: [SECRET], denyWrite: [PROJ] }),
    },
    {
      what: 'a masked file under a write deny that re-exposes it',
      wrapped: wrap({
        denyWrite: [PROJ],
        maskedFileBinds: [
          { realPath: SECRET, fakePath: join(FAKES, '0.fake') },
        ],
      }),
    },
    {
      what: 'a denied directory and a denied file inside it',
      wrapped: wrap({ denyRead: [SUB, join(SUB, 'inner.txt')] }),
    },
    {
      what: 'two absent write denies sharing one missing component',
      wrapped: wrap({
        denyWrite: [join(PROJ, 'gone', 'a'), join(PROJ, 'gone', 'b')],
      }),
    },
    {
      what: 'a file denied for reading and for writing',
      wrapped: wrap({ denyRead: [SECRET], denyWrite: [SECRET] }),
    },
    {
      what: 'a masked file that is also an allowed write path',
      wrapped: wrap({
        allowWrite: [AREA, SECRET],
        maskedFileBinds: [
          { realPath: SECRET, fakePath: join(FAKES, '0.fake') },
        ],
      }),
    },
    {
      what: 'a denied file beside a masked one under a write deny',
      wrapped: wrap({
        denyRead: [SECRET, `${SECRET}/`],
        denyWrite: [PROJ],
        maskedFileBinds: [{ realPath: OTHER, fakePath: join(FAKES, '1.fake') }],
      }),
    },
  ]

  it('masks each destination once across the whole corpus', async () => {
    const offences: string[] = []
    for (const { what, wrapped } of corpus()) {
      for (const offence of maskedTwiceOver(await wrapped)) {
        offences.push(`${what} -> ${offence}`)
      }
    }
    expect(offences).toEqual([])
  })

  it('still masks a file denied under several spellings', async () => {
    const command = await wrap({
      denyRead: [SECRET, `${SECRET}/`, join(LINK, 'secret.txt')],
    })
    expect(command).toContain(`--ro-bind /dev/null ${SECRET}`)
  })

  it('leaves a denied file to the credential mask that covers it', async () => {
    // Both name one file. The mask is the mount bubblewrap leaves in force,
    // and it hides the real bytes as the read deny asked; a /dev/null mask
    // under it would only be replaced.
    const command = await wrap({
      denyRead: [SECRET],
      maskedFileBinds: [{ realPath: SECRET, fakePath: join(FAKES, '0.fake') }],
    })
    expect(command).toContain(`--ro-bind ${join(FAKES, '0.fake')} ${SECRET}`)
    expect(command).not.toContain(`--ro-bind /dev/null ${SECRET}`)
  })

  it('keeps the last fake where two entries name one file', async () => {
    // bwrap applies mounts in order, so the second of two masks at one
    // destination was the one in force; that is the one kept.
    const command = await wrap({
      maskedFileBinds: [
        { realPath: SECRET, fakePath: join(FAKES, '0.fake') },
        { realPath: join(LINK, 'secret.txt'), fakePath: join(FAKES, '1.fake') },
      ],
    })
    expect(command).toContain(`--ro-bind ${join(FAKES, '1.fake')} ${SECRET}`)
    expect(command).not.toContain(
      `--ro-bind ${join(FAKES, '0.fake')} ${SECRET}`,
    )
  })

  it('re-applies a mask a write deny re-exposed, above that deny', async () => {
    const command = await wrap({ denyRead: [SECRET], denyWrite: [PROJ] })
    const argv = command.split(/\s+/)
    const masks = argv.flatMap((word, index) =>
      word === '--ro-bind' &&
      argv[index + 1] === '/dev/null' &&
      argv[index + 2] === SECRET
        ? [index]
        : [],
    )
    // The last such bind. Array.prototype.findLastIndex is ES2023, and the
    // tests compile against the ES2020 library.
    const denyBind = argv
      .map(
        (word, index) =>
          word === '--ro-bind' &&
          argv[index + 1] === PROJ &&
          argv[index + 2] === PROJ,
      )
      .lastIndexOf(true)
    expect(masks.length).toBe(2)
    expect(masks[0]).toBeLessThan(denyBind)
    expect(masks[1]).toBeGreaterThan(denyBind)
  })
})

describe.if(isLinux)('Reporting an older bubblewrap', () => {
  let BASE: string

  const stubBwrap = (name: string, version: string): string => {
    const path = join(BASE, name)
    writeFileSync(path, `#!/bin/sh\necho "bubblewrap ${version}"\n`, {
      mode: 0o755,
    })
    return path
  }

  beforeAll(() => {
    BASE = realpathSync(mkdtempSync(join(tmpdir(), 'bwrap-version-')))
  })

  afterAll(() => {
    rmSync(BASE, { recursive: true, force: true })
  })

  it('warns, naming the version, about an older bubblewrap', () => {
    const { warnings, errors } = checkLinuxDependencies({
      bwrapPath: stubBwrap('old', '0.4.1'),
    })
    expect(
      warnings.some(
        warning =>
          warning.includes('0.4.1') &&
          warning.includes(OLDEST_FULLY_SUPPORTED_BWRAP_VERSION),
      ),
    ).toBe(true)
    // A warning, not a refusal: every other configuration starts on it.
    expect(errors.some(error => error.includes('0.4.1'))).toBe(false)
  })

  it('says nothing about a bubblewrap new enough for everything', () => {
    const { warnings } = checkLinuxDependencies({
      bwrapPath: stubBwrap('new', '0.11.2'),
    })
    expect(
      warnings.some(warning => warning.includes('bubblewrap 0.11.2')),
    ).toBe(false)
  })

  it('says nothing when the version cannot be asked for', () => {
    const path = join(BASE, 'mute')
    writeFileSync(path, '#!/bin/sh\nexit 3\n', { mode: 0o755 })
    const { warnings } = checkLinuxDependencies({ bwrapPath: path })
    expect(
      warnings.some(warning =>
        warning.includes(OLDEST_FULLY_SUPPORTED_BWRAP_VERSION),
      ),
    ).toBe(false)
  })
})
