import { describe, it, expect, beforeAll, beforeEach, afterAll } from 'bun:test'
import { spawnSync } from 'node:child_process'
import {
  mkdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { homedir, tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import type {
  FilesystemPathEntry,
  SandboxRuntimeConfig,
} from '../../src/sandbox/sandbox-config.js'
import type { FsReadRestrictionConfig } from '../../src/sandbox/sandbox-schemas.js'
import { wrapCommandWithSandboxMacOS } from '../../src/sandbox/macos-sandbox-utils.js'
import { isAtOrUnder } from '../../src/sandbox/sandbox-utils.js'
import {
  countMounts,
  indexOfMount,
  lastIndexOfMount,
  lastMountAt,
} from '../helpers/bwrap-argv.js'
import { withCapturedWarnings } from '../helpers/captured-warnings.js'
import { isLinux, isMacOS, isWindows } from '../helpers/platform.js'

/**
 * How the lists that decide what a command reads rank against each other:
 * `filesystem.denyRead`, `filesystem.allowRead`, `filesystem.allowWrite` and
 * `credentials.files`.
 */

const CONTENT = 'file-content'
const ROOT = join(
  isWindows ? tmpdir() : realpathSync(tmpdir()),
  'read-list-precedence-' + Date.now(),
)
const VAULT = join(ROOT, 'vault')
const V1 = join(VAULT, 'v1')
const TOKEN = join(V1, 'token')
const SIBLING = join(V1, 'sibling')
const BRACKETS = join(VAULT, '[v1.2]')
const BRACKETS_TOKEN = join(BRACKETS, 'token')
const DIR = join(VAULT, 'dir')
const DEEP = join(DIR, 'deep')
const DEEP_TOKEN = join(DEEP, 'token')
const SUB = join(VAULT, 'sub')
const NETRC = join(SUB, '.netrc')
const TOKEN_LINK = join(VAULT, 'link-to-token')
const DIR_LINK = join(VAULT, 'link-to-dir')
const BRACKETS_LINK = join(VAULT, 'link-to-brackets')
const VAULT_LINK = join(ROOT, 'link-to-vault')
const LINKED_DIR = join(VAULT_LINK, 'dir')
const ROOT_LINK = join(ROOT, 'link-to-root')
const JAR = join(ROOT, 'agent', 'agent.jar')

const CREDENTIAL = {
  'credential deny': { mode: 'deny' },
  'credential mask': { mode: 'mask' },
  'credential mask with no match': {
    mode: 'mask',
    extract: 'absent-(text)',
    onExtractNoMatch: 'deny',
  },
} as const
type Kind = 'denyRead' | keyof typeof CREDENTIAL
const KINDS = ['denyRead', ...Object.keys(CREDENTIAL)] as Kind[]
type Lists = {
  denyRead?: string[]
  allowRead?: FilesystemPathEntry[]
  allowWrite?: string[]
}

/** `entry` listed in one of KINDS, beside the other lists. */
function configOf(
  kind: Kind,
  entry: string,
  lists: Lists,
): Pick<SandboxRuntimeConfig, 'filesystem' | 'credentials'> {
  return {
    filesystem: {
      denyRead: [
        ...(lists.denyRead ?? []),
        ...(kind === 'denyRead' ? [entry] : []),
      ],
      allowRead: lists.allowRead ?? [],
      allowWrite: lists.allowWrite ?? [],
      denyWrite: [],
    },
    credentials: {
      files: kind === 'denyRead' ? [] : [{ path: entry, ...CREDENTIAL[kind] }],
    },
  }
}

const network = { allowedDomains: [], deniedDomains: [] }
const nothingListed = { denyRead: [], allowWrite: [], denyWrite: [] }
const short = (text: string): string => text.split(ROOT + '/').join('')
const stdoutOf = (wrapped: string): string =>
  spawnSync(wrapped, { shell: true, encoding: 'utf8', timeout: 10000 }).stdout

describe.if(!isWindows)('precedence between the read lists', () => {
  beforeAll(() => {
    for (const file of [
      TOKEN,
      SIBLING,
      BRACKETS_TOKEN,
      DEEP_TOKEN,
      NETRC,
      JAR,
    ]) {
      mkdirSync(dirname(file), { recursive: true })
      writeFileSync(file, CONTENT)
    }
    symlinkSync(TOKEN, TOKEN_LINK)
    symlinkSync(DIR, DIR_LINK)
    symlinkSync(BRACKETS, BRACKETS_LINK)
    symlinkSync(VAULT, VAULT_LINK)
    symlinkSync('/', ROOT_LINK)
  })

  afterAll(async () => {
    await SandboxManager.reset()
    rmSync(ROOT, { recursive: true, force: true })
  })

  describe.if(isLinux || isMacOS)('what a command reads', () => {
    beforeAll(async () => {
      await SandboxManager.reset()
      await SandboxManager.initialize({ network, filesystem: nothingListed })
    })

    // The entry, the other lists, the file read, and its state with the entry
    // in each of KINDS: R readable, U unreadable, M masked, - not asked.
    // A write path is bound, and so readable, on Linux alone.
    const W = isLinux ? 'R' : 'U'
    const rows: Array<[string, Lists, string, string]> = [
      [TOKEN, {}, TOKEN, 'UUMU'],
      [TOKEN, {}, SIBLING, 'RRRR'],
      [TOKEN, { allowRead: [TOKEN] }, TOKEN, 'RUMU'],
      [TOKEN, { allowRead: [V1] }, TOKEN, 'UUMU'],
      [TOKEN, { allowRead: [join(V1, '*')] }, TOKEN, 'RUMU'],
      [TOKEN, { allowRead: [{ path: TOKEN, literal: true }] }, TOKEN, 'RUMU'],
      [TOKEN, { allowWrite: [TOKEN] }, TOKEN, 'UUMU'],
      [TOKEN, { allowWrite: [V1] }, TOKEN, 'UUMU'],
      [TOKEN, { denyRead: [VAULT] }, TOKEN, 'UUMU'],
      [TOKEN, { denyRead: [VAULT], allowRead: [TOKEN] }, TOKEN, 'RUMU'],
      [TOKEN, { denyRead: [VAULT], allowRead: [V1] }, TOKEN, 'UUMU'],
      [TOKEN, { denyRead: [VAULT], allowRead: [V1] }, SIBLING, 'RRRR'],
      [TOKEN, { denyRead: [VAULT], allowRead: [join(V1, '*')] }, TOKEN, 'RUMU'],
      [
        TOKEN,
        { denyRead: [VAULT], allowRead: [TOKEN_LINK, TOKEN] },
        TOKEN_LINK,
        '-UUU',
      ],
      [
        BRACKETS_TOKEN,
        { denyRead: [VAULT], allowRead: [join(BRACKETS, '*')] },
        BRACKETS_TOKEN,
        'RUMU',
      ],
      [TOKEN, { allowRead: [TOKEN_LINK] }, TOKEN, 'UUMU'],
      [TOKEN_LINK, {}, TOKEN, 'UUMU'],
      [TOKEN_LINK, { denyRead: [VAULT], allowRead: [TOKEN] }, TOKEN, 'RUMU'],
      [join(VAULT_LINK, 'v1', 'token'), {}, TOKEN, 'UUMU'],
      [join(VAULT_LINK, 'v1', 'token'), {}, SIBLING, 'RRRR'],
      [DIR, {}, DEEP_TOKEN, 'UU--'],
      [DIR, { allowRead: [DIR] }, DEEP_TOKEN, 'RU--'],
      [DIR, { allowRead: [DEEP] }, DEEP_TOKEN, 'RU--'],
      [DIR, { allowRead: [DEEP_TOKEN] }, DEEP_TOKEN, 'RU--'],
      [DIR, { allowRead: [join(DIR_LINK, 'deep')] }, DEEP_TOKEN, 'RU--'],
      [DIR, { allowRead: [join(DIR_LINK, 'deep', '*')] }, DEEP_TOKEN, 'RU--'],
      [DIR, { allowRead: [DIR_LINK] }, DEEP_TOKEN, 'UU--'],
      [DIR, { allowWrite: [DIR] }, DEEP_TOKEN, `${W}U--`],
      [DIR, { allowWrite: [DEEP] }, DEEP_TOKEN, `${W}U--`],
      [DIR, { allowWrite: [VAULT] }, DEEP_TOKEN, 'UU--'],
      [DIR, { allowWrite: [DIR_LINK] }, join(DIR_LINK, 'deep/token'), 'UU--'],
      [
        DIR,
        { denyRead: [VAULT], allowRead: [DIR_LINK] },
        join(DIR_LINK, 'deep/token'),
        'UU--',
      ],
      [DIR, { denyRead: [VAULT], allowRead: [VAULT] }, DEEP_TOKEN, 'UU--'],
      [DIR, { denyRead: [VAULT], allowRead: [DEEP] }, DEEP_TOKEN, 'RU--'],
      [DIR, { denyRead: [VAULT], allowWrite: [DEEP] }, DEEP_TOKEN, `${W}U--`],
      [DIR_LINK, {}, DEEP_TOKEN, 'UU--'],
      [DIR_LINK, { allowRead: [DEEP] }, DEEP_TOKEN, 'RU--'],
      [
        LINKED_DIR,
        { allowRead: [join(LINKED_DIR, 'deep')] },
        DEEP_TOKEN,
        'RU--',
      ],
      [
        join(LINKED_DIR, 'deep'),
        { denyRead: [VAULT_LINK], allowRead: [LINKED_DIR] },
        DEEP_TOKEN,
        'UU--',
      ],
      [join(VAULT, '**', '.netrc'), {}, NETRC, 'UU--'],
      [join(VAULT, '**', '.netrc'), { allowRead: [NETRC] }, NETRC, 'RU--'],
      [join(VAULT, '**', '.netrc'), { allowRead: [SUB] }, NETRC, 'UU--'],
      [join(VAULT, '**', '.netrc'), { allowWrite: [NETRC] }, NETRC, 'UU--'],
      [join(VAULT_LINK, '**', '.netrc'), {}, NETRC, 'UU--'],
    ]

    for (const [entry, lists, file, states] of rows) {
      KINDS.forEach((kind, i) => {
        const state = states[i]
        if (state === '-') return
        const name = `${kind} ${entry} ${JSON.stringify(lists)}: ${file} ${state}`
        it(short(name), async () => {
          const wrapped = await SandboxManager.wrapWithSandbox(
            // 'ran' tells a command that read nothing from one that never ran.
            `echo ran; cat '${file}'`,
            undefined,
            configOf(kind, entry, lists),
          )
          const stdout = stdoutOf(wrapped)
          if (state === 'R') expect(stdout).toBe(`ran\n${CONTENT}`)
          else if (state === 'M' && isLinux) {
            expect(stdout).toMatch(/^ran\nfake_value_/)
          } else expect(stdout).toBe('ran\n')
        })
      })
    }

    it('the lists of the session rank as those of one command', async () => {
      for (const [kind, stdout] of [
        ['denyRead', `ran\n${CONTENT}`],
        ['credential deny', 'ran\n'],
      ] as const) {
        await SandboxManager.reset()
        await SandboxManager.initialize({
          network,
          ...configOf(kind, TOKEN, { allowRead: [TOKEN] }),
        })
        expect(
          stdoutOf(
            await SandboxManager.wrapWithSandbox(`echo ran; cat '${TOKEN}'`),
          ),
        ).toBe(stdout)
      }
    })
  })

  describe.if(isLinux || isMacOS)('what a command moves', () => {
    const BOX = join(ROOT, 'box')
    const OUT = join(ROOT, 'out')

    beforeAll(async () => {
      await SandboxManager.reset()
      await SandboxManager.initialize({ network, filesystem: nothingListed })
    })

    beforeEach(() => {
      for (const dir of [BOX, OUT])
        rmSync(dir, { recursive: true, force: true })
      mkdirSync(join(BOX, 'dir'), { recursive: true })
      mkdirSync(OUT)
      for (const file of ['dir/token', 'token', 'plain', '.netrc']) {
        writeFileSync(join(BOX, file), CONTENT)
      }
    })

    // In BOX: the entry, the write path, what is moved out. Then what is read
    // of it, and whether it is there.
    it.each<[Kind, string, string, string, string, boolean]>([
      ['credential deny', 'token', '', 'plain', '', true],
      ['credential deny', 'token', '', 'token', '', false],
      ['credential deny', 'token', 'token', 'token', '', false],
      ['credential mask', 'token', 'token', 'token', '', false],
      ['credential deny', 'dir', 'dir', 'dir/token', '', false],
      ['credential deny', 'dir', 'dir', 'dir', 'token', false],
      ['credential deny', 'dir', '', '', 'dir/token', false],
      ['credential deny', '**/.netrc', '.netrc', '.netrc', '', false],
    ])(
      '%s on %p, allowWrite on %p: %p moved out, %p read: %p',
      async (kind, entry, allowWrite, moved, read, arrives) => {
        const to = join(OUT, 'moved')
        const stdout = stdoutOf(
          await SandboxManager.wrapWithSandbox(
            `echo ran; mv '${join(BOX, moved)}' '${to}'; cat '${join(to, read)}'`,
            undefined,
            configOf(kind, join(BOX, entry), {
              allowWrite: [join(BOX, allowWrite), OUT],
            }),
          ),
        )
        expect(stdout.startsWith('ran\n')).toBe(true)
        expect(stdout.includes(CONTENT)).toBe(arrives)
      },
    )
  })

  describe.if(isLinux || isMacOS)("the library's own files", () => {
    beforeAll(async () => {
      await SandboxManager.reset()
      await SandboxManager.initialize({
        network: { ...network, tlsTerminate: {} },
        filesystem: nothingListed,
        javaAgentJarPath: JAR,
      })
    })

    const reading = (
      command: string,
      kind: Kind,
      entry: string,
    ): Promise<string> =>
      SandboxManager.wrapWithSandbox(
        command,
        undefined,
        configOf(kind, entry, {}),
      ).then(stdoutOf)

    for (const kind of ['denyRead', 'credential deny'] as const) {
      it(`${kind} on their folders: they are readable, what lies beside them is not`, async () => {
        const { trustBundlePath, certPath, keyPath } =
          SandboxManager.getMitmCA()!
        for (const own of [trustBundlePath, certPath, JAR]) {
          expect(await reading(`head -c 10 '${own}'`, kind, dirname(own))).toBe(
            readFileSync(own, 'utf8').slice(0, 10),
          )
        }
        expect(dirname(keyPath)).toBe(dirname(certPath))
        expect(
          await reading(`echo ran; cat '${keyPath}'`, kind, dirname(certPath)),
        ).toBe('ran\n')
      })

      it(`${kind} on a pattern that matches it: the trust bundle is readable`, async () => {
        const { trustBundlePath } = SandboxManager.getMitmCA()!
        expect(
          await reading(
            'head -c 10 "$SSL_CERT_FILE"',
            kind,
            join(dirname(trustBundlePath), '*.crt'),
          ),
        ).toBe('-----BEGIN')
      })
    }

    it.if(isLinux)('the debug log names none of them', async () => {
      const { trustBundlePath } = SandboxManager.getMitmCA()!
      const { warnings } = await withCapturedWarnings(() =>
        reading('true', 'credential deny', dirname(trustBundlePath)),
      )
      expect(warnings.filter(w => w.includes('not bound back'))).toEqual([])
    })
  })

  describe.if(isLinux || isMacOS)('the configs the manager reports', () => {
    const logs = join(homedir(), '.npm', '_logs')

    it.each<[Kind, FilesystemPathEntry[], boolean]>([
      ['denyRead', [], false],
      ['denyRead', ['~/.npm/_logs'], true],
      ['denyRead', ['~/.npm'], true],
      ['credential deny', [], false],
      ['credential deny', ['~/.npm/_logs'], false],
      ['credential deny', ['~/.npm'], false],
    ])(
      '%s ~/.npm, allowRead %j: ~/.npm/_logs a default write path: %p',
      async (kind, allowRead, listed) => {
        await SandboxManager.reset()
        await SandboxManager.initialize({
          network,
          ...configOf(kind, '~/.npm', { allowRead }),
        })
        const { allowOnly } = SandboxManager.getFsWriteConfig()
        expect(allowOnly.includes(logs)).toBe(listed)
      },
    )

    it.if(isLinux)('lists what a credential pattern expands to', async () => {
      await SandboxManager.reset()
      await SandboxManager.initialize({
        network,
        ...configOf('credential deny', join(VAULT, '**', '.netrc'), {
          denyRead: [V1],
        }),
      })
      const read = SandboxManager.getFsReadConfig()
      expect(read.denyOnly).toEqual([V1, NETRC])
      expect(read.credentialDenyOnly).toEqual([NETRC])
    })
  })

  describe.if(isLinux)('bubblewrap mounts', () => {
    beforeAll(async () => {
      await SandboxManager.reset()
      await SandboxManager.initialize({ network, filesystem: nothingListed })
    })

    const wrap = (kind: Kind, entry: string, lists: Lists): Promise<string> =>
      SandboxManager.wrapWithSandbox(
        'true',
        undefined,
        configOf(kind, entry, lists),
      )

    it('a file deny is mounted after the folder above it is bound back', async () => {
      for (const kind of ['denyRead', 'credential deny'] as const) {
        const wrapped = await wrap(kind, TOKEN, {
          denyRead: [VAULT],
          allowRead: [V1],
        })
        const boundBack = indexOfMount(wrapped, '--ro-bind', V1, V1)
        expect(boundBack).toBeGreaterThan(-1)
        expect(
          indexOfMount(wrapped, '--ro-bind', '/dev/null', TOKEN),
        ).toBeGreaterThan(boundBack)
      }
    })

    it('an allowRead on a denied file decides its last mount by the kind of deny', async () => {
      const lists = { allowRead: [TOKEN] }
      expect(lastMountAt(await wrap('denyRead', TOKEN, lists), TOKEN)).toBe(
        undefined,
      )
      expect(
        lastMountAt(await wrap('credential deny', TOKEN, lists), TOKEN),
      ).toBe(`--ro-bind /dev/null ${TOKEN}`)
    })

    it('a denied folder binds an allowRead file back by the kind of deny on the file', async () => {
      const lists = { denyRead: [VAULT], allowRead: [TOKEN] }
      for (const [kind, binds] of [
        ['denyRead', 1],
        ['credential deny', 0],
      ] as const) {
        const wrapped = await wrap(kind, TOKEN, lists)
        expect(countMounts(wrapped, '--tmpfs', VAULT)).toBe(1)
        expect(countMounts(wrapped, '--ro-bind', TOKEN, TOKEN)).toBe(binds)
      }
    })

    const boundBack = async (...config: Parameters<typeof wrap>) =>
      countMounts(await wrap(...config), '--ro-bind', DEEP, DEEP)

    // However the directory and the path beneath it are spelled, and whether
    // or not a denied folder lies around them.
    for (const entry of [DIR, DIR_LINK]) {
      for (const deep of [DEEP, join(DIR_LINK, 'deep')]) {
        for (const denyRead of [[], [VAULT]]) {
          const where = short(`${entry}, ${deep}, denyRead [${denyRead}]`)

          it(`read paths beneath a denied directory: ${where}`, async () => {
            const lists = { denyRead, allowRead: [deep] }
            expect(await boundBack('denyRead', entry, lists)).toBe(1)
            expect(await boundBack('credential deny', entry, lists)).toBe(0)
          })
        }
      }

      it(`write paths beneath a denied directory: ${short(entry)}`, async () => {
        for (const denyRead of [[], [VAULT]]) {
          const lists = { denyRead, allowWrite: [DEEP] }
          const tmpfs = denyRead[0] ?? DIR
          const plain = await wrap('denyRead', entry, lists)
          expect(lastIndexOfMount(plain, '--bind', DEEP, DEEP)).toBeGreaterThan(
            indexOfMount(plain, '--tmpfs', tmpfs),
          )
          const credential = await wrap('credential deny', entry, lists)
          expect(countMounts(credential, '--bind', DEEP, DEEP)).toBe(1)
          expect(indexOfMount(credential, '--bind', DEEP, DEEP)).toBeLessThan(
            indexOfMount(credential, '--tmpfs', tmpfs),
          )
        }
      })
    }

    it.each<[Lists]>([
      [{ allowRead: [DEEP] }],
      [{ allowWrite: [DEEP] }],
      [{ allowRead: [DEEP, V1], allowWrite: [DEEP, V1] }],
    ])(
      'the debug log names once a path at or beneath a credential deny: %j',
      async lists => {
        for (const [kind, lines] of [
          ['denyRead', []],
          [
            'credential deny',
            [
              `[SandboxDebug] [Sandbox Linux] ${DEEP} is at or beneath the credential deny ${DIR}: not bound back`,
            ],
          ],
        ] as const) {
          const { warnings } = await withCapturedWarnings(() =>
            wrap(kind, DIR_LINK, lists),
          )
          expect(warnings.filter(w => w.includes('not bound back'))).toEqual([
            ...lines,
          ])
        }
      },
    )

    it('an entry on the root takes its exceptions by its kind', async () => {
      const top = await wrap('denyRead', '/', { allowRead: ['/usr'] })
      expect(countMounts(top, '--tmpfs', '/usr')).toBe(0)
      const inner = await wrap('denyRead', '/', { allowRead: ['/usr/bin'] })
      expect(countMounts(inner, '--tmpfs', '/usr')).toBe(1)
      expect(countMounts(inner, '--ro-bind', '/usr/bin', '/usr/bin')).toBe(1)

      for (const allowRead of [['/usr'], ['/usr/bin']]) {
        const wrapped = await wrap('credential deny', '/', { allowRead })
        expect(countMounts(wrapped, '--tmpfs', '/usr')).toBe(1)
        expect(
          countMounts(wrapped, '--ro-bind', allowRead[0]!, allowRead[0]!),
        ).toBe(0)
      }
    })
  })

  // Profile text only, so it runs on every POSIX host.
  describe('Seatbelt profile', () => {
    const profileOf = (
      readConfig: FsReadRestrictionConfig,
      rest: { allowWrite?: string[]; masked?: string } = {},
    ): string =>
      wrapCommandWithSandboxMacOS({
        command: 'true',
        needsNetworkRestriction: false,
        readConfig,
        writeConfig: rest.allowWrite && {
          allowOnly: rest.allowWrite,
          denyWithinAllow: [],
        },
        maskedFileBinds: rest.masked
          ? [{ realPath: rest.masked, fakePath: '/fakes/0' }]
          : [],
      })

    /** The file-read* denies that come after the allowRead rule. */
    const lateDenies = (profile: string): string => {
      const allowAt = profile.indexOf('(allow file-read*\n')
      expect(allowAt).toBeGreaterThan(-1)
      return profile.slice(
        allowAt,
        profile.indexOf('(allow file-read-metadata'),
      )
    }

    /** Whether a filter of the first file-read* rule of `action` matches. */
    const firstRule =
      (action: 'allow' | 'deny') =>
      (profile: string, file: string): boolean => {
        const at = profile.indexOf(`(${action} file-read*\n`)
        return profile
          .slice(at, profile.indexOf('(with message', at))
          .split('\n')
          .some(line => {
            const [, kind, text] =
              /^ {2}\((subpath|regex) (".*")\)$/.exec(line) ?? []
            if (text === undefined) return false
            const value = JSON.parse(text) as string
            return kind === 'regex'
              ? new RegExp(value).test(file)
              : isAtOrUnder(file, value)
          })
      }
    const denies = firstRule('deny')
    const allows = firstRule('allow')

    /** The trailing file-write-unlink deny rule, or '' when there is none. */
    const unlinkDenies = (
      readConfig: FsReadRestrictionConfig,
      allowWrite: string[],
      masked?: string,
    ): string => {
      const profile = profileOf(readConfig, { allowWrite, masked })
      const at = profile.indexOf('; File read: keep read-denied')
      return at < 0 ? '' : profile.slice(at)
    }

    const asCredential = (
      config: FsReadRestrictionConfig,
    ): FsReadRestrictionConfig => ({
      ...config,
      credentialDenyOnly: config.denyOnly,
    })

    it.each([['/vault/v1/token'], ['/vault/v1/*'], ['/vault/v1/token/part']])(
      'a literal deny beside an allow on %s comes after it by its kind',
      allow => {
        const config = {
          denyOnly: ['/vault/v1/token'],
          allowWithinDeny: [allow],
        }
        const filter = '(deny file-read*\n  (subpath "/vault/v1/token")\n'
        expect(lateDenies(profileOf(config))).not.toContain(filter)
        expect(lateDenies(profileOf(asCredential(config)))).toContain(filter)
      },
    )

    it('a credential deny on a name with brackets comes after the allows as that name', () => {
      expect(
        lateDenies(
          profileOf(
            asCredential({
              denyOnly: [BRACKETS_TOKEN],
              allowWithinDeny: [join(BRACKETS, '*')],
            }),
          ),
        ),
      ).toContain(`  (subpath "${BRACKETS_TOKEN}")\n`)
    })

    it('a pattern deny has an allow it covers subtracted by its kind', () => {
      const config = {
        denyOnly: ['/vault/**/.netrc'],
        allowWithinDeny: ['/vault/sub/.netrc'],
      }
      const carved = '(require-not (subpath "/vault/sub/.netrc"))'
      expect(lateDenies(profileOf(config))).toContain(carved)
      const late = lateDenies(profileOf(asCredential(config)))
      expect(late).toContain('  (regex "^/vault/(.*/)?\\\\.netrc(/.*)?$")\n')
      expect(late).not.toContain(carved)
    })

    it('a masked file is denied after the allows', () => {
      expect(
        lateDenies(
          profileOf(
            { denyOnly: [], allowWithinDeny: ['/vault/v1/token'] },
            { masked: '/vault/v1/token' },
          ),
        ),
      ).toContain('(deny file-read*\n  (subpath "/vault/v1/token")\n')
    })

    it("the library's own files are subtracted from a credential deny", () => {
      const bundle = '/tmp-x/srt-ca-1/trust-bundle.crt'
      const late = lateDenies(
        profileOf(
          asCredential({
            denyOnly: ['/tmp-x', '/tmp-x/**/*.crt', '/elsewhere'],
            allowWithinDeny: ['/tmp-x/other', bundle],
            ownAllowWithinDeny: [bundle],
          }),
        ),
      )
      const minusBundle = ` (require-not (subpath "${bundle}")))\n`
      expect(late).toContain(`  (require-all (subpath "/tmp-x")${minusBundle}`)
      expect(late).toContain(
        `  (require-all (regex "^/tmp-x/(.*/)?[^/]*\\\\.crt(/.*)?$")${minusBundle}`,
      )
      expect(late).toContain('  (subpath "/elsewhere")\n')
      expect(late).not.toContain('(require-not (subpath "/tmp-x/other"))')
    })

    it('a deny is emitted under both spellings of its path', () => {
      for (const as of [(c: FsReadRestrictionConfig) => c, asCredential]) {
        const profile = profileOf(
          as({
            denyOnly: [
              TOKEN_LINK,
              join(VAULT_LINK, 'dir'),
              join(VAULT_LINK, '**', '.netrc'),
              join(BRACKETS_LINK, '*'),
              ROOT_LINK,
            ],
          }),
        )
        for (const file of [
          TOKEN_LINK,
          TOKEN,
          DEEP_TOKEN,
          NETRC,
          BRACKETS_TOKEN,
        ]) {
          expect(denies(profile, file)).toBe(true)
        }
        expect(denies(profile, SIBLING)).toBe(false)
      }
    })

    it('a masked file is denied under both spellings of its path', () => {
      const profile = profileOf({ denyOnly: [] }, { masked: TOKEN_LINK })
      expect(denies(profile, TOKEN_LINK)).toBe(true)
      expect(denies(profile, TOKEN)).toBe(true)
    })

    it.each<[string, string, boolean]>([
      [join(LINKED_DIR, 'deep'), join(LINKED_DIR, 'deep', 'token'), true],
      [join(LINKED_DIR, 'deep'), DEEP_TOKEN, true],
      [join(LINKED_DIR, 'deep', '*'), DEEP_TOKEN, true],
      [join(DIR_LINK, '*'), DEEP, true],
      [join(BRACKETS_LINK, '*'), BRACKETS_TOKEN, true],
      [DIR_LINK, DEEP_TOKEN, false],
      [TOKEN_LINK, TOKEN, false],
      [join(ROOT_LINK, '*'), ROOT, false],
    ])(
      'an allow is emitted under both spellings of its name: %s, %s: %p',
      (allow, file, matches) => {
        const profile = profileOf({
          denyOnly: [VAULT],
          allowWithinDeny: [allow],
        })
        expect(allows(profile, file)).toBe(matches)
      },
    )

    it('both spellings of an allow count against the denies around it', () => {
      const nested = { denyOnly: [DEEP], allowWithinDeny: [LINKED_DIR] }
      expect(lateDenies(profileOf(nested))).toContain(`  (subpath "${DEEP}")\n`)

      const minus = (allow: string): string =>
        `(require-not (subpath "${allow}"))`
      const covered = {
        denyOnly: [join(VAULT, '**', 'token')],
        allowWithinDeny: [join(LINKED_DIR, 'deep', 'token')],
      }
      expect(lateDenies(profileOf(covered))).toContain(minus(DEEP_TOKEN))
      expect(unlinkDenies(covered, [VAULT])).toContain(minus(DEEP_TOKEN))
      expect(
        unlinkDenies(
          { denyOnly: [DIR], allowWithinDeny: [join(LINKED_DIR, 'deep')] },
          [VAULT],
        ),
      ).toContain(minus(DEEP))

      const own = join(VAULT_LINK, 'v1', 'sibling')
      expect(
        lateDenies(
          profileOf(
            asCredential({
              denyOnly: [VAULT],
              allowWithinDeny: [own],
              ownAllowWithinDeny: [own],
            }),
          ),
        ),
      ).toContain(`  (require-all (subpath "${VAULT}") ${minus(SIBLING)})\n`)
    })

    it.each([
      ['/work/dir', '(subpath "/work/dir")', '/work/dir/token'],
      [
        '/work/**/.netrc',
        '(regex "^/work/(.*/)?\\\\.netrc(/.*)?$")',
        '/work/sub/.netrc',
      ],
    ])(
      'what a deny on %s covers in a write root is kept in place, with exceptions by its kind',
      (deny, filter, inside) => {
        for (const lists of [
          { allowWithinDeny: [inside], allowWrite: ['/work'] },
          { allowWithinDeny: [], allowWrite: ['/work', inside] },
        ]) {
          const config = {
            denyOnly: [deny],
            allowWithinDeny: lists.allowWithinDeny,
          }
          const plain = unlinkDenies(config, lists.allowWrite)
          expect(plain).toContain(
            `  (require-all ${filter} (require-not (subpath "${inside}")))\n`,
          )
          expect(plain).not.toContain('(literal "/work")')
          const credential = unlinkDenies(
            asCredential(config),
            lists.allowWrite,
          )
          expect(credential).toContain(`  ${filter}\n`)
          expect(credential).toContain('  (literal "/work")\n')
          expect(credential).not.toContain('require-not')
        }
      },
    )

    it('a deny at or above a write root is kept in place by its kind', () => {
      for (const allowWrite of ['/vault/dir', '/vault/dir/cache']) {
        const config = { denyOnly: ['/vault/dir'] }
        expect(unlinkDenies(config, [allowWrite])).toBe('')
        expect(unlinkDenies(asCredential(config), [allowWrite])).toContain(
          '  (subpath "/vault/dir")\n',
        )
      }
      expect(
        unlinkDenies({ denyOnly: [] }, ['/vault/token'], '/vault/token'),
      ).toContain('  (subpath "/vault/token")\n')
    })
  })
})
