import { describe, it, expect, afterEach, spyOn } from 'bun:test'
import { spawnSync } from 'node:child_process'
import * as fs from 'fs'
import {
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  wrapCommandWithSandboxLinux,
  cleanupBwrapMountPoints,
} from '../../src/sandbox/linux-sandbox-utils.js'
import { isLinux } from '../helpers/platform.js'

// A pin is left out, without aborting the wrap, when a component of its path
// is missing or cannot be lstat'ed. EACCES is injected through an fs spy (a
// root container sees no real one). Nothing here executes bwrap.
describe.if(isLinux)(
  'Linux sandbox — ancestor pins that cannot be made',
  () => {
    const created: string[] = []
    const spies: Array<{ mockRestore: () => void }> = []
    afterEach(() => {
      for (const spy of spies.splice(0)) spy.mockRestore()
      cleanupBwrapMountPoints({ force: true })
      for (const dir of created.splice(0)) {
        rmSync(dir, { recursive: true, force: true })
      }
    })

    function makeTree(): string {
      // proj/a/b/.git/config: pins expected for a, a/b, a/b/.git
      const proj = realpathSync(mkdtempSync(join(tmpdir(), 'pin-errno-')))
      created.push(proj)
      mkdirSync(join(proj, 'a', 'b', '.git'), { recursive: true })
      writeFileSync(join(proj, 'a', 'b', '.git', 'config'), '[core]\n')
      return proj
    }

    async function wrap(
      proj: string,
      extra: Partial<Parameters<typeof wrapCommandWithSandboxLinux>[0]> = {},
    ): Promise<string> {
      return wrapCommandWithSandboxLinux({
        command: 'true',
        needsNetworkRestriction: false,
        allowAllUnixSockets: true,
        writeConfig: {
          allowOnly: [proj],
          denyWithinAllow: [join(proj, 'a', 'b', '.git', 'config')],
        },
        ...extra,
      })
    }

    /** Make lstatSync(target) throw EACCES; returns how often it was hit. */
    function failLstatOn(target: string): () => number {
      const realLstat = fs.lstatSync
      let hits = 0
      spies.push(
        spyOn(fs, 'lstatSync').mockImplementation(((
          p: fs.PathLike,
          ...rest: unknown[]
        ) => {
          if (String(p) === target) {
            hits++
            throw Object.assign(new Error('EACCES: permission denied'), {
              code: 'EACCES',
            })
          }
          return (realLstat as (...a: unknown[]) => unknown)(p, ...rest)
        }) as typeof fs.lstatSync),
      )
      return () => hits
    }

    it('leaves out every pin through a component that cannot be inspected, and still builds the wrap', async () => {
      const proj = makeTree()
      const component = join(proj, 'a')
      const lstatHits = failLstatOn(component)

      const wrapped = await wrap(proj)

      expect(lstatHits()).toBeGreaterThan(0)
      for (const dir of [
        component,
        join(proj, 'a', 'b'),
        join(proj, 'a', 'b', '.git'),
      ]) {
        expect(wrapped).not.toContain(`--ro-bind ${dir} ${dir}`)
      }
      const cfg = join(proj, 'a', 'b', '.git', 'config')
      expect(wrapped).toContain(`--ro-bind ${cfg} ${cfg}`)
    })

    it('leaves out the pin of a missing directory and pins the existing one above it', async () => {
      // A credential mask is emitted whether or not its file exists, so its
      // ancestors are the one walk that can cross a missing directory.
      const proj = makeTree()
      const missing = join(proj, 'a', 'missing')
      const fakePath = join(proj, 'fake-token')
      writeFileSync(fakePath, 'FAKE\n')

      const wrapped = await wrap(proj, {
        maskedFileBinds: [{ realPath: join(missing, 'token'), fakePath }],
      })

      expect(wrapped).not.toContain(`--ro-bind ${missing} ${missing}`)
      const above = join(proj, 'a')
      expect(wrapped).toContain(`--ro-bind ${above} ${above}`)
    })

    it('pins the ancestors of a FIFO denyRead entry (every non-directory is masked)', async () => {
      const proj = makeTree()
      mkdirSync(join(proj, 'secrets'))
      const fifoPath = join(proj, 'secrets', 'pipe.fifo')
      const mk = spawnSync('mkfifo', [fifoPath])
      if (mk.status !== 0) {
        throw new Error('mkfifo unavailable')
      }

      const wrapped = await wrap(proj, {
        readConfig: { denyOnly: [fifoPath], allowWithinDeny: [] },
      })

      const maskedDir = join(proj, 'secrets')
      expect(wrapped).toContain(`--ro-bind ${maskedDir} ${maskedDir}`)
      expect(wrapped).toContain(`--ro-bind /dev/null ${fifoPath}`)
    })

    it('pins nothing for a denyRead file that does not exist', async () => {
      // secrets exists, so only the missing file decides: an unmasked entry
      // must not pin its parent.
      const proj = makeTree()
      const parent = join(proj, 'secrets')
      mkdirSync(parent)

      const wrapped = await wrap(proj, {
        readConfig: { denyOnly: [join(parent, 'gone')], allowWithinDeny: [] },
      })

      expect(wrapped).not.toContain(`--ro-bind ${parent} ${parent}`)
    })
  },
)
