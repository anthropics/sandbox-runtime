import { afterEach, beforeEach, describe, expect, it } from 'bun:test'
import { spawnSync } from 'node:child_process'
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { basename, dirname, join } from 'node:path'
import { wrapCommandWithSandboxMacOS } from '../../src/sandbox/macos-sandbox-utils.js'
import type { SandboxRuntimeConfig } from '../../src/sandbox/sandbox-config.js'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import {
  normalizePathForSandbox,
  pathSpellings,
} from '../../src/sandbox/sandbox-utils.js'
import { bwrapCanNamespaceNetwork } from '../helpers/bwrap-namespace.js'
import { isLinux, isMacOS, isWindows } from '../helpers/platform.js'

/**
 * Off Windows a backslash is a character of a file name like any other:
 * `a\b` is one name, and `a/b` is another file. A rule that names the one
 * applies to it, however it is spelled, and leaves the other alone.
 */

const APPENDED = 'appended'
const canRun = isMacOS || (isLinux && bwrapCanNamespaceNetwork())

let root: string
const savedCwd = process.cwd()

beforeEach(() => {
  root = realpathSync(mkdtempSync(join(tmpdir(), 'backslash-')))
})

afterEach(async () => {
  process.chdir(savedCwd)
  await SandboxManager.reset()
  rmSync(root, { recursive: true, force: true })
})

type Policy = Omit<Partial<SandboxRuntimeConfig>, 'filesystem'> & {
  filesystem?: Partial<SandboxRuntimeConfig['filesystem']>
}

/**
 * Which of `files`, given from `root`, a command in the sandbox can read, or
 * append to. Each is made first, holding its own name, unless `absent`. The
 * command runs behind an `echo BOOTED`, so a sandbox that failed to start
 * cannot read as a command that was refused.
 */
async function reach(
  policy: Policy,
  does: 'read' | 'append',
  files: string[],
  absent = false,
): Promise<string[]> {
  for (const file of files) {
    mkdirSync(dirname(join(root, file)), { recursive: true })
    if (!absent) writeFileSync(join(root, file), `<${file}>`)
  }
  await SandboxManager.initialize(
    {
      network: { allowedDomains: [], deniedDomains: [] },
      ...policy,
      filesystem: {
        denyRead: [],
        allowWrite: [],
        denyWrite: [],
        ...policy.filesystem,
      },
    },
    undefined,
    false,
  )
  const wrapped = await SandboxManager.wrapWithSandbox(
    ['echo BOOTED']
      .concat(
        files.map(file =>
          does === 'read'
            ? `cat '${join(root, file)}'`
            : `echo ${APPENDED} >> '${join(root, file)}'`,
        ),
      )
      .join('; '),
  )
  const { stdout } = spawnSync(wrapped, {
    shell: true,
    encoding: 'utf8',
    timeout: 15_000,
  })
  SandboxManager.cleanupAfterCommand()
  expect(stdout).toContain('BOOTED')
  return files.filter(file =>
    does === 'read'
      ? stdout.includes(`<${file}>`)
      : existsSync(join(root, file)) &&
        readFileSync(join(root, file), 'utf8').includes(APPENDED),
  )
}

const credential = (path: string, mode: 'deny' | 'mask'): Policy => ({
  network: { allowedDomains: ['localhost'], deniedDomains: [] },
  credentials: { files: [{ path, mode }], allowPlaintextInject: true },
})

/** Each kind of rule as the policy that holds it for `entry`, what a command
 *  then tries, and whether the rule leaves it `entry` or everything else. */
const RULES: Array<
  [string, (entry: string) => Policy, 'read' | 'append', 'it' | 'the rest']
> = [
  ['denyRead', e => ({ filesystem: { denyRead: [e] } }), 'read', 'the rest'],
  [
    'a denyRead pattern',
    e => ({ filesystem: { denyRead: [`${dirname(e)}/**/${basename(e)}`] } }),
    'read',
    'the rest',
  ],
  ['a credentials deny', e => credential(e, 'deny'), 'read', 'the rest'],
  ['a credentials mask', e => credential(e, 'mask'), 'read', 'the rest'],
  [
    'allowRead',
    e => ({ filesystem: { denyRead: [join(root, 'tree')], allowRead: [e] } }),
    'read',
    'it',
  ],
  [
    'an allowRead pattern',
    e => ({
      filesystem: {
        denyRead: [join(root, 'tree')],
        allowRead: [e.replace('\\', '*')],
      },
    }),
    'read',
    'it',
  ],
  [
    'denyWrite',
    e => ({ filesystem: { allowWrite: [root], denyWrite: [e] } }),
    'append',
    'the rest',
  ],
  ['allowWrite', e => ({ filesystem: { allowWrite: [e] } }), 'append', 'it'],
]

describe.if(canRun)('a rule on a name that holds a backslash', () => {
  for (const [rule, policy, does, leaves] of RULES) {
    for (const name of ['a\\b', 'c\\d/file']) {
      for (const through of ['tree', 'link']) {
        // Of the write rules only a deny for bubblewrap is followed through a
        // link, whatever the name.
        if (
          does === 'append' &&
          through === 'link' &&
          !(isLinux && rule === 'denyWrite')
        ) {
          continue
        }
        for (const other of [name.replace('\\', '/'), 'plain']) {
          it(`${rule} of ${through}/${name}, beside tree/${other}, leaves ${leaves} within reach`, async () => {
            symlinkSync('tree', join(root, 'link'))
            const files = [`tree/${name}`, `tree/${other}`]

            expect(
              await reach(policy(join(root, through, name)), does, files),
            ).toEqual([files[leaves === 'it' ? 0 : 1]!])
          }, 60_000)
        }
      }
    }
  }

  for (const other of ['c/d/file', 'plain']) {
    it(`denyWrite of tree/c\\d/file, which is not there, beside tree/${other}, leaves the rest within reach`, async () => {
      expect(
        await reach(
          {
            filesystem: {
              allowWrite: [root],
              denyWrite: [join(root, 'tree/c\\d/file')],
            },
          },
          'append',
          ['tree/c\\d/file', `tree/${other}`],
          true,
        ),
      ).toEqual([`tree/${other}`])
    }, 60_000)
  }

  it('keeps the shell start-up file of a working directory with such a name read-only', async () => {
    mkdirSync(join(root, 'pro\\ject'))
    process.chdir(join(root, 'pro\\ject'))

    expect(
      await reach({ filesystem: { allowWrite: [root] } }, 'append', [
        'pro\\ject/.bashrc',
        'pro\\ject/plain',
        'pro/ject/.bashrc',
      ]),
    ).toEqual(['pro\\ject/plain', 'pro/ject/.bashrc'])
  }, 60_000)

  it('keeps a shell start-up file in a directory with such a name, beneath the working directory, read-only', async () => {
    process.chdir(root)

    expect(
      await reach({ filesystem: { allowWrite: [root] } }, 'append', [
        'c\\d/.bashrc',
        'c\\d/plain',
        'c/d/.bashrc',
      ]),
    ).toEqual(['c\\d/plain'])
  }, 60_000)

  // Only bubblewrap is handed what a pattern finds; Seatbelt matches paths.
  it.if(isLinux)(
    'denies what a denyRead pattern reaches through a link in a directory with such a name',
    async () => {
      mkdirSync(join(root, 'tree/c\\d'), { recursive: true })
      symlinkSync(join(root, 'elsewhere'), join(root, 'tree/c\\d/link'))

      expect(
        await reach(
          { filesystem: { denyRead: [join(root, 'tree/**/file')] } },
          'read',
          ['elsewhere/file', 'elsewhere/plain'],
        ),
      ).toEqual(['elsewhere/plain'])
    },
    60_000,
  )
})

describe.if(!isWindows)('a name that holds a backslash, behind a link', () => {
  beforeEach(() => {
    mkdirSync(join(root, 'tree/a/b'), { recursive: true })
    mkdirSync(join(root, 'tree/a\\b'))
    symlinkSync('tree', join(root, 'link'))
  })

  it('is spelled as written and as it really is', () => {
    expect(pathSpellings(join(root, 'link/a\\b'))).toEqual([
      join(root, 'link/a\\b'),
      join(root, 'tree/a\\b'),
    ])
  })

  it.each(['', '/**/file'])(
    'is normalized with a parent reference before it folded (%s)',
    tail => {
      expect(normalizePathForSandbox(`${root}/tree/a/../a\\b${tail}`)).toBe(
        `${root}/tree/a\\b${tail}`,
      )
    },
  )

  it('is denied in a Seatbelt profile where it really is', () => {
    const profile = wrapCommandWithSandboxMacOS({
      command: 'true',
      needsNetworkRestriction: false,
      readConfig: { denyOnly: [join(root, 'link/a\\b')] },
      writeConfig: undefined,
    })

    expect(profile).toContain(
      `(subpath ${JSON.stringify(join(root, 'tree/a\\b'))})`,
    )
    expect(profile).not.toContain(join(root, 'tree/a/b'))
  })
})
