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

// What is emitted for paths that are missing or cannot be inspected: a missing
// directory gets no pin, and one that exists but cannot be stat'ed is
// protected anyway. EACCES is injected through an fs spy (a root container
// sees no real one). Nothing here executes bwrap.
describe.if(isLinux)(
  'Linux sandbox — pins and read denies on paths that cannot be inspected',
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

    /** Make statSync(p) throw EACCES where matches(p); returns the hit count. */
    function failStatWhere(matches: (p: string) => boolean): () => number {
      const realStat = fs.statSync
      let hits = 0
      spies.push(
        spyOn(fs, 'statSync').mockImplementation(((
          p: fs.PathLike,
          ...rest: unknown[]
        ) => {
          if (matches(String(p))) {
            hits++
            throw Object.assign(new Error('EACCES: permission denied'), {
              code: 'EACCES',
            })
          }
          return (realStat as (...a: unknown[]) => unknown)(p, ...rest)
        }) as typeof fs.statSync),
      )
      return () => hits
    }

    it('still pins a directory that exists but cannot be inspected', async () => {
      const proj = makeTree()
      const uninspectable = join(proj, 'a', 'b')
      const statHits = failStatWhere(p => p === uninspectable)

      const wrapped = await wrap(proj)

      expect(statHits()).toBeGreaterThan(0)
      for (const dir of [
        join(proj, 'a'),
        uninspectable,
        join(proj, 'a', 'b', '.git'),
      ]) {
        expect(wrapped).toContain(`--ro-bind ${dir} ${dir}`)
      }
    })

    it('hides the deepest inspectable directory above a denyRead path that cannot be inspected', async () => {
      // chmod 000 on cfg/secrets by an earlier command: the key cannot be
      // stat'ed, but the next command can chmod it back and read it.
      const proj = makeTree()
      const secrets = join(proj, 'cfg', 'secrets')
      mkdirSync(join(secrets, 'pub'), { recursive: true })
      writeFileSync(join(secrets, 'key'), 'K')
      const statHits = failStatWhere(p => p.startsWith(secrets + '/'))

      const wrapped = await wrap(proj, {
        readConfig: {
          denyOnly: [join(secrets, 'key')],
          allowWithinDeny: [join(secrets, 'pub')],
        },
      })

      expect(statHits()).toBeGreaterThan(0)
      expect(wrapped).toContain(`--tmpfs ${secrets} `)
      // Nothing beneath the stand-in can be vouched for, so nothing returns.
      expect(wrapped).not.toContain(join(secrets, 'pub'))
      expect(wrapped).not.toContain(join(secrets, 'key'))
      const cfg = join(proj, 'cfg')
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

    it.if(Bun.which('mkfifo') !== null)(
      'pins the ancestors of a FIFO denyRead entry (every non-directory is masked)',
      async () => {
        const proj = makeTree()
        mkdirSync(join(proj, 'secrets'))
        const fifoPath = join(proj, 'secrets', 'pipe.fifo')
        expect(spawnSync('mkfifo', [fifoPath]).status).toBe(0)

        const wrapped = await wrap(proj, {
          readConfig: { denyOnly: [fifoPath], allowWithinDeny: [] },
        })

        const maskedDir = join(proj, 'secrets')
        expect(wrapped).toContain(`--ro-bind ${maskedDir} ${maskedDir}`)
        expect(wrapped).toContain(`--ro-bind /dev/null ${fifoPath}`)
      },
    )

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

    it('mounts nothing for a denyRead path uninspectable all the way up to "/"', async () => {
      // A dead network mount answers every ancestor with ENOTCONN/ESTALE/EIO,
      // so the stand-in walk reaches '/', where stat succeeds. '/' as the
      // stand-in means --tmpfs /, which wipes every mount before it and the
      // second pivot promotes: the command boots on an empty tree.
      const proj = makeTree()
      const statHits = failStatWhere(p => p === '/mnt' || p.startsWith('/mnt/'))

      const wrapped = await wrap(proj, {
        readConfig: { denyOnly: ['/mnt/share/secrets'], allowWithinDeny: [] },
      })

      expect(statHits()).toBeGreaterThan(0)
      const argv = wrapped.split(/\s+/)
      expect(
        argv.some((token, i) => token === '--tmpfs' && argv[i + 1] === '/'),
      ).toBe(false)
    })
  },
)
