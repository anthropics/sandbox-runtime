import { afterEach, beforeEach, describe, expect, it } from 'bun:test'
import {
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { ownInstallWarning } from '../../src/sandbox/own-files.js'
import type { SandboxRuntimeConfig } from '../../src/sandbox/sandbox-config.js'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import { withCapturedWarnings } from '../helpers/captured-warnings.js'
import { isLinux } from '../helpers/platform.js'

type Lists = Partial<
  Record<'denyRead' | 'allowRead' | 'allowWrite' | 'denyWrite', string[]>
>

/** What leads there, from which working directory, with `R` for the root. */
const ROWS: Array<[string, string, Lists, ('deny' | 'mask')?]> = [
  ['the working directory', 'link', { allowWrite: ['.'] }],
  ['a write root', 'plain', { allowWrite: ['R/link'] }],
  ['a write root beneath it', 'plain', { allowWrite: ['R/link/sub'] }],
  ['denyRead', 'plain', { denyRead: ['R/link/file'] }],
  ['a denyRead pattern from it', 'plain', { denyRead: ['R/link/**/file'] }],
  ['a denyRead pattern that comes to it', 'plain', { denyRead: ['R/**/file'] }],
  ['allowRead', 'plain', { denyRead: ['R'], allowRead: ['R/link/file'] }],
  [
    'an allowRead pattern',
    'plain',
    { denyRead: ['R'], allowRead: ['R/*/file'] },
  ],
  ['denyWrite', 'plain', { allowWrite: ['R'], denyWrite: ['R/link/file'] }],
  [
    'a denyWrite pattern',
    'plain',
    { allowWrite: ['R'], denyWrite: ['R/**/file'] },
  ],
  [
    'a built-in deny, a link to a directory',
    'directory',
    { allowWrite: ['.'] },
  ],
  ['a built-in deny, a link to a file', 'file', { allowWrite: ['.'] }],
  [
    'a built-in deny, a link to nothing yet',
    'not-there',
    { allowWrite: ['.'] },
  ],
  ['a built-in deny beneath the working directory', '.', { allowWrite: ['.'] }],
  ['a credentials deny', 'plain', {}, 'deny'],
  ['a credentials mask', 'plain', {}, 'mask'],
]

/**
 * A name can hold bytes that are no text, and a link can lead to one. No
 * string spells where that is, which is for the mounts of one command to deal
 * with: setting the sandbox up, and asking it what it holds, go on as ever.
 *
 * macOS lets no such name be made.
 */
describe.if(isLinux)(
  'a configuration that leads to a name that is no text',
  () => {
    const savedCwd = process.cwd()
    let root: string
    const bytes = (before: string, after = ''): Buffer =>
      Buffer.concat([Buffer.from(before), Buffer.of(0xff), Buffer.from(after)])

    beforeEach(() => {
      root = realpathSync(mkdtempSync(join(tmpdir(), 'no-text-')))
      mkdirSync(bytes(`${root}/n`, '/sub'), { recursive: true })
      symlinkSync(bytes('n'), join(root, 'link'))
      writeFileSync(join(root, 'link/file'), '')
      writeFileSync(join(root, 'link/.bashrc'), '')
      mkdirSync(join(root, 'plain'))
      for (const [project, name, target] of [
        ['directory', '.vscode', bytes('../n')],
        ['file', '.bashrc', bytes('../n', '/file')],
        ['not-there', '.mcp.json', bytes('../n', '/not-there')],
      ] as const) {
        mkdirSync(join(root, project))
        symlinkSync(target, join(root, project, name))
      }
    })

    afterEach(async () => {
      process.chdir(savedCwd)
      await SandboxManager.reset()
      rmSync(root, { recursive: true, force: true })
    })

    const configOf = (
      lists: Lists,
      mode?: 'deny' | 'mask',
    ): SandboxRuntimeConfig => ({
      network: { allowedDomains: ['localhost'], deniedDomains: [] },
      filesystem: {
        denyRead: [],
        allowWrite: [],
        denyWrite: [],
        ...Object.fromEntries(
          Object.entries(lists).map(([list, entries]) => [
            list,
            entries.map(entry => entry.replace(/^R/, root)),
          ]),
        ),
      },
      ...(mode && {
        credentials: {
          files: [{ path: join(root, 'link/file'), mode }],
          allowPlaintextInject: true,
        },
      }),
    })

    for (const [what, cwd, lists, mode] of ROWS) {
      it(`is set up, changed and asked about: ${what}`, async () => {
        process.chdir(join(root, cwd))
        const config = configOf(lists, mode)

        await SandboxManager.initialize(config, undefined, false)
        SandboxManager.updateConfig(configOf({}))
        SandboxManager.updateConfig(config)

        expect(SandboxManager.getFsReadConfig()).toBeObject()
        expect(SandboxManager.getFsWriteConfig()).toBeObject()
        expect(SandboxManager.checkDependencies().errors).toEqual([])
      })
    }

    it('is judged for whether it lets the library itself be written', () => {
      mkdirSync(join(root, 'link/node_modules/library'), { recursive: true })
      writeFileSync(join(root, 'link/node_modules/library/package.json'), '{}')

      expect(
        ownInstallWarning(
          [join(root, 'link')],
          join(root, 'link/node_modules/library/index.js'),
        ),
      ).toBeString()
    })

    it('says why a read deny is mounted on its spelling', async () => {
      await SandboxManager.initialize(
        configOf({ denyRead: ['R/link/file'] }),
        undefined,
        false,
      )

      const { warnings } = await withCapturedWarnings(() =>
        SandboxManager.wrapWithSandbox('true'),
      )
      SandboxManager.cleanupAfterCommand()

      expect(warnings.filter(said => said.includes('cannot be told'))).toEqual([
        expect.stringMatching(new RegExp(`${root}/link/file .*EILSEQ`)),
      ])
    })
  },
)
