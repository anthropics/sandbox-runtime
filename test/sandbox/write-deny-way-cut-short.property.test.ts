import { afterAll, describe, expect, it } from 'bun:test'
import * as fc from 'fast-check'
import { spawnSync } from 'node:child_process'
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  symlinkSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import { bwrapCanNamespace } from '../helpers/bwrap-namespace.js'
import { isLinux } from '../helpers/platform.js'

/**
 * Trees of directories and links in a write root, with a write deny on a link
 * that leads nowhere yet. A command in the real sandbox then makes every name
 * that is not there, as a directory, a link or a file, and tries the denied
 * name after each round. It replaces nothing that is there.
 */
describe.if(isLinux && bwrapCanNamespace())(
  'property: a write deny on a link that leads nowhere yet',
  () => {
    const savedCwd = process.cwd()
    const NAMES = ['a', 'b', 'c']
    const beneath = (places: string[]): string[] =>
      places.flatMap(place => NAMES.map(name => `${place}/${name}`))
    /** Every path of up to three names, a directory before what it holds. */
    const PLACES = [NAMES, beneath(NAMES), beneath(beneath(NAMES))].flat()
    const target = fc
      .array(fc.constantFrom(...NAMES, '..', '..'), {
        minLength: 1,
        maxLength: 4,
      })
      .map(names => names.join('/'))
    const MAKES = {
      directory: 'mkdir "$place"',
      // Its parent is another than that of the name it is made at.
      link: 'ln -s "$PWD/far/away" "$place"',
      file: ': > "$place"',
    }
    const make = fc.constantFrom(...Object.values(MAKES))

    afterAll(async () => {
      process.chdir(savedCwd)
      await SandboxManager.reset()
    })

    it('holds whatever the command makes', async () => {
      let started = 0
      await fc.assert(
        fc.asyncProperty(
          target,
          fc.array(fc.tuple(fc.constantFrom(...PLACES), fc.option(target)), {
            maxLength: 8,
          }),
          fc.array(make, {
            minLength: PLACES.length,
            maxLength: PLACES.length,
          }),
          async (denied, entries, mixed) => {
            for (const makes of [
              PLACES.map(() => MAKES.directory),
              PLACES.map(() => MAKES.link),
              mixed,
            ]) {
              const root = realpathSync(mkdtempSync(join(tmpdir(), 'cut-')))
              try {
                const work = join(root, 'outer', 'work')
                mkdirSync(work, { recursive: true })
                for (const [place, leadsTo] of entries) {
                  try {
                    if (leadsTo === null) mkdirSync(join(work, place))
                    else symlinkSync(leadsTo, join(work, place))
                  } catch {
                    // Taken, or nothing holds it: the tree goes without.
                  }
                }
                symlinkSync(denied, join(work, 'name'))
                fc.pre(!existsSync(join(work, 'name')))

                process.chdir(root)
                await SandboxManager.reset()
                await SandboxManager.initialize(
                  {
                    network: { allowedDomains: [], deniedDomains: [] },
                    filesystem: {
                      denyRead: [],
                      allowWrite: [work],
                      denyWrite: [join(work, 'name')],
                    },
                  },
                  undefined,
                  false,
                )
                const wrapped = await SandboxManager.wrapWithSandbox(
                  [
                    `echo STARTED; cd '${work}'; mkdir -p far/away`,
                    'for round in 1 2 3; do',
                    ...PLACES.map(
                      (place, i) =>
                        `place=${place}; [ -e $place ] || [ -L $place ] || ${makes[i]}`,
                    ),
                    '( echo written >> name ) && echo WRITTEN',
                    'done 2>/dev/null',
                  ].join('\n'),
                )
                const { stdout } = spawnSync(wrapped, {
                  shell: true,
                  encoding: 'utf8',
                  timeout: 20_000,
                })
                SandboxManager.cleanupAfterCommand()

                // A sandbox that does not start writes nothing either.
                if (stdout !== '') started++
                expect([stdout, existsSync(join(work, 'name'))]).toEqual([
                  stdout === '' ? '' : 'STARTED\n',
                  false,
                ])
              } finally {
                process.chdir(savedCwd)
                rmSync(root, { recursive: true, force: true })
              }
            }
          },
        ),
        // Every look at a smaller tree is three more sandboxes.
        { numRuns: 25, endOnFailure: true },
      )
      expect(started).toBeGreaterThan(0)
    }, 300_000)
  },
)
