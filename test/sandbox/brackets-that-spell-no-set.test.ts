import { afterAll, beforeAll, describe, expect, it } from 'bun:test'
import { spawnSync } from 'node:child_process'
import { mkdirSync, realpathSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { wrapCommandWithSandboxMacOS } from '../../src/sandbox/macos-sandbox-utils.js'
import type { SandboxRuntimeConfig } from '../../src/sandbox/sandbox-config.js'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import { bwrapCanNamespace } from '../helpers/bwrap-namespace.js'
import { isLinux, isMacOS, isWindows } from '../helpers/platform.js'

/**
 * An entry with brackets that spell no set of characters, because a range in
 * them runs backwards (`[user-id]`: `r-i`). A route folder is named so. The
 * brackets are the text they are, in every list and on every platform, and
 * the rest of the entry is the pattern it was.
 */

const ROOT = join(
  isWindows ? tmpdir() : realpathSync(tmpdir()),
  'brackets-no-set-' + Date.now(),
)
const TREE = join(ROOT, 'tree')

/** The files a command tries, each under the letter it answers with. */
const FILES = {
  S: '[user-id]/secret',
  E: '[user-id]/a.env',
  D: 'deep/[user-id]/a.env',
  // What a set of the letters between the brackets would match.
  U: 'u/a.env',
  P: 'plain',
}
const ALL = Object.keys(FILES).join('')
const without = (letters: string): string =>
  [...ALL].filter(letter => !letters.includes(letter)).join('')

/** An entry beneath TREE, the files it covers, and the regular expression it is. */
const ENTRIES: Array<[string, string, string]> = [
  ['[z-a]', '', '\\[z-a\\]'],
  ['[user-id]', 'SE', '\\[user-id\\]'],
  ['[user-id]/secret', 'S', '\\[user-id\\]/secret'],
  ['**/[user-id]/*.env', 'ED', '(.*/)?\\[user-id\\]/[^/]*\\.env'],
]

type Policy = Pick<SandboxRuntimeConfig, 'filesystem' | 'credentials'>
const nothingListed = { denyRead: [], allowWrite: [], denyWrite: [] }

/** A list: the policy with `entry` in it, and what is left of ALL to a command
 *  that reads, or writes, when the entry covers `covered`. */
const LISTS: Record<
  string,
  {
    policy: (entry: string) => Policy
    writes?: true
    left: (covered: string) => string
  }
> = {
  denyRead: {
    policy: entry => ({ filesystem: { ...nothingListed, denyRead: [entry] } }),
    left: without,
  },
  'credential deny': {
    policy: entry => ({
      filesystem: nothingListed,
      credentials: { files: [{ path: entry, mode: 'deny' }] },
    }),
    left: without,
  },
  allowRead: {
    policy: entry => ({
      filesystem: { ...nothingListed, denyRead: [TREE], allowRead: [entry] },
    }),
    left: covered => covered,
  },
  denyWrite: {
    policy: entry => ({
      filesystem: { ...nothingListed, allowWrite: [TREE], denyWrite: [entry] },
    }),
    writes: true,
    left: without,
  },
  allowWrite: {
    policy: entry => ({
      filesystem: { ...nothingListed, allowWrite: [entry] },
    }),
    writes: true,
    left: covered => covered,
  },
}

const stdoutOf = (wrapped: string): string =>
  spawnSync(wrapped, { shell: true, encoding: 'utf8', timeout: 20000 }).stdout

const CASES = Object.entries(LISTS).flatMap(([list, how]) =>
  ENTRIES.map(([entry, covered, source]) => ({
    list,
    entry,
    covered,
    source,
    ...how,
  })),
)

describe.if(!isWindows)('brackets that spell no set of characters', () => {
  beforeAll(() => {
    for (const file of Object.values(FILES)) {
      mkdirSync(dirname(join(TREE, file)), { recursive: true })
      writeFileSync(join(TREE, file), 'content')
    }
  })

  afterAll(() => {
    rmSync(ROOT, { recursive: true, force: true })
  })

  describe.if((isLinux && bwrapCanNamespace()) || isMacOS)(
    'what a command reads and writes',
    () => {
      beforeAll(async () => {
        await SandboxManager.reset()
        await SandboxManager.initialize({
          network: { allowedDomains: [], deniedDomains: [] },
          filesystem: nothingListed,
        })
      })

      afterAll(async () => {
        await SandboxManager.reset()
      })

      it.each(CASES)(
        '$list $entry',
        async ({ entry, covered, policy, writes, left }) => {
          const attempts = Object.entries(FILES).map(([letter, file]) => {
            const path = `'${join(TREE, file)}'`
            // Opened to append and left as it is.
            const attempt = writes ? `: >> ${path}` : `cat ${path} > /dev/null`
            return `( ${attempt} ) 2> /dev/null && printf ${letter}`
          })
          const wrapped = await SandboxManager.wrapWithSandbox(
            // 'ran' tells a command that was refused all from one that never ran.
            `echo ran; ${attempts.join('; ')}`,
            undefined,
            policy(join(TREE, entry)),
          )
          // Linux takes no pattern in a write list, whatever it holds.
          const applies = !(isLinux && writes && entry.includes('*'))
          expect(stdoutOf(wrapped)).toBe(`ran\n${left(applies ? covered : '')}`)
        },
        60000,
      )

      it('an ordinary relative pattern, from inside such a folder', async () => {
        const cwd = process.cwd()
        process.chdir(join(TREE, '[user-id]'))
        try {
          const wrapped = await SandboxManager.wrapWithSandbox(
            'echo ran; cat a.env secret',
            undefined,
            { filesystem: { ...nothingListed, denyRead: ['*.env'] } },
          )
          expect(stdoutOf(wrapped)).toBe('ran\ncontent')
        } finally {
          process.chdir(cwd)
        }
      }, 60000)

      it.if(isLinux)('reports the lists of the session', async () => {
        await SandboxManager.reset()
        await SandboxManager.initialize({
          network: { allowedDomains: [], deniedDomains: [] },
          filesystem: {
            ...nothingListed,
            denyRead: [join(TREE, '**/[user-id]/*.env'), join(TREE, '[z-a]')],
            allowRead: [join(TREE, '[user-id]/secret')],
          },
        })
        const { denyOnly, allowWithinDeny } = SandboxManager.getFsReadConfig()
        expect(denyOnly.sort()).toEqual([
          join(TREE, FILES.E),
          join(TREE, FILES.D),
        ])
        expect(allowWithinDeny).toEqual([join(TREE, FILES.S)])
      })
    },
  )

  // Read on any POSIX host. The builder compiles some of them itself, and
  // Seatbelt is handed them all.
  it.each(CASES)(
    'macOS profile, $list $entry: every regex compiles',
    ({ list, entry, source, policy }) => {
      const { filesystem, credentials } = policy(join(TREE, entry))
      const credentialDenyOnly = credentials?.files?.map(file => file.path)
      const profile = wrapCommandWithSandboxMacOS({
        command: 'true',
        needsNetworkRestriction: false,
        readConfig: {
          denyOnly: [
            ...(filesystem.denyRead as string[]),
            ...(credentialDenyOnly ?? []),
          ],
          credentialDenyOnly,
          allowWithinDeny: filesystem.allowRead as string[] | undefined,
        },
        writeConfig: {
          allowOnly: filesystem.allowWrite as string[],
          denyWithinAllow: filesystem.denyWrite as string[],
        },
      })
      const regexes = [
        ...profile.matchAll(/\(regex ("(?:[^"\\]|\\.)*")\)/g),
      ].map(match => JSON.parse(match[1]!) as string)
      for (const regex of regexes) expect(() => new RegExp(regex)).not.toThrow()
      expect(regexes.map(regex => regex.split('/tree/')[1])).toContain(
        source + (list.startsWith('allow') ? '$' : '(/.*)?$'),
      )
    },
  )
})
