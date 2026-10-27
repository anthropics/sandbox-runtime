import { describe, it, expect, beforeEach, afterEach } from 'bun:test'
import { spawnSync } from 'node:child_process'
import {
  existsSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { wrapCommandWithSandboxLinux } from '../../src/sandbox/linux-sandbox-utils.js'
import { wrapCommandWithSandboxMacOS } from '../../src/sandbox/macos-sandbox-utils.js'
import { bwrapCanNamespace } from '../helpers/bwrap-namespace.js'
import { isLinux, isMacOS } from '../helpers/platform.js'

/**
 * A write is judged by where it lands, not by the name it was asked for by:
 * every symbolic link on the way is followed first. So a link inside a write
 * root that leads out of it gives a command nothing, whoever made the link
 * and whenever, and a link outside every write root that leads into one is a
 * way in like any other name. On Linux that is the mount table's doing (the
 * file system is bound read-only and the write roots writable over it); on
 * macOS it is Seatbelt's, which compares the path the kernel resolved.
 *
 * Every link here is made on the host before the command is wrapped, and
 * every target a write is refused at exists, holds `original`, and must
 * still hold it afterwards.
 */
describe.if((isLinux && bwrapCanNamespace()) || isMacOS)(
  'A write through a link is judged by where it lands',
  () => {
    let BASE: string
    let ROOT: string // the one write root
    let OUTSIDE: string // beside it, under no write root

    beforeEach(() => {
      // Where the temp dir really is: macOS names it through a link.
      BASE = realpathSync(mkdtempSync(join(tmpdir(), 'write-through-links-')))
      ROOT = join(BASE, 'root')
      OUTSIDE = join(BASE, 'outside')
      mkdirSync(join(ROOT, 'inner'), { recursive: true })
      mkdirSync(join(OUTSIDE, 'dir'), { recursive: true })
      writeFileSync(join(ROOT, 'inner', 'file'), 'original')
      writeFileSync(join(OUTSIDE, 'file'), 'original')
      writeFileSync(join(OUTSIDE, 'dir', 'file'), 'original')
    })

    afterEach(() => {
      rmSync(BASE, { recursive: true, force: true })
    })

    /** What `command` said and how it ended, run with ROOT as its one write
     *  root and nothing denied within it. */
    async function run(
      command: string,
    ): Promise<{ status: number | null; said: string }> {
      const options = {
        command,
        needsNetworkRestriction: false,
        readConfig: { denyOnly: [] },
        writeConfig: { allowOnly: [ROOT], denyWithinAllow: [] },
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
      return {
        status: result.status,
        said: String(result.stdout ?? '') + String(result.stderr ?? ''),
      }
    }

    /** A command that tries `attempt` and says how it went, after showing
     *  that the sandbox itself started. */
    const trying = (attempt: string): string =>
      `echo started; if ( ${attempt} ) 2>/dev/null; then echo WROTE; else echo refused; fi`

    it('refuses a write through a link in the write root to a file outside it', async () => {
      const link = join(ROOT, 'link-to-file')
      symlinkSync(join(OUTSIDE, 'file'), link)

      const { said } = await run(trying(`echo changed > ${link}`))

      expect(said).toContain('started')
      expect(said).toContain('refused')
      expect(readFileSync(join(OUTSIDE, 'file'), 'utf8')).toBe('original')
    })

    it('refuses a write and a create beneath a link in the write root to a directory outside it', async () => {
      const link = join(ROOT, 'link-to-dir')
      symlinkSync(join(OUTSIDE, 'dir'), link)

      const written = await run(trying(`echo changed > ${link}/file`))
      expect(written.said).toContain('started')
      expect(written.said).toContain('refused')
      expect(readFileSync(join(OUTSIDE, 'dir', 'file'), 'utf8')).toBe(
        'original',
      )

      const created = await run(trying(`echo new > ${link}/new`))
      expect(created.said).toContain('started')
      expect(created.said).toContain('refused')
      expect(existsSync(join(OUTSIDE, 'dir', 'new'))).toBe(false)
    })

    it('refuses a rename onto a file outside the write root, through a linked directory', async () => {
      const link = join(ROOT, 'link-to-dir')
      symlinkSync(join(OUTSIDE, 'dir'), link)

      const { said } = await run(
        trying(`echo changed > ${ROOT}/made && mv ${ROOT}/made ${link}/file`),
      )

      expect(said).toContain('started')
      expect(said).toContain('refused')
      expect(readFileSync(join(OUTSIDE, 'dir', 'file'), 'utf8')).toBe(
        'original',
      )
    })

    it('refuses a create through a link in the write root to a name outside it that is not there', async () => {
      const link = join(ROOT, 'dangling')
      symlinkSync(join(OUTSIDE, 'not-there'), link)

      const { said } = await run(trying(`echo new > ${link}`))

      expect(said).toContain('started')
      expect(said).toContain('refused')
      expect(existsSync(join(OUTSIDE, 'not-there'))).toBe(false)
    })

    it('refuses the same through a link the command makes itself', async () => {
      const link = join(ROOT, 'made-inside')

      const { said } = await run(
        `ln -s ${join(OUTSIDE, 'file')} ${link} && ${trying(`echo changed > ${link}`)}`,
      )

      expect(said).toContain('started')
      expect(said).toContain('refused')
      expect(readFileSync(join(OUTSIDE, 'file'), 'utf8')).toBe('original')
    })

    it('allows a write through a link in the write root that stays in it', async () => {
      const link = join(ROOT, 'link-inside')
      symlinkSync(join(ROOT, 'inner', 'file'), link)

      const { said } = await run(trying(`echo changed > ${link}`))

      expect(said).toContain('WROTE')
      expect(readFileSync(join(ROOT, 'inner', 'file'), 'utf8')).toBe(
        'changed\n',
      )
    })

    it('allows a write through a link outside every write root that leads into one', async () => {
      const link = join(OUTSIDE, 'link-into-root')
      symlinkSync(join(ROOT, 'inner', 'file'), link)

      const { said } = await run(trying(`echo changed > ${link}`))

      expect(said).toContain('WROTE')
      expect(readFileSync(join(ROOT, 'inner', 'file'), 'utf8')).toBe(
        'changed\n',
      )
    })

    // A hard link is not a link that is followed: it is a second name for
    // the file itself. On Linux the name inside the write root is as good as
    // any, and the file is written through it although its other name is
    // outside. macOS is left out on purpose: which of a file's names Seatbelt
    // is handed is the system's choice, and nothing here depends on it.
    it.if(isLinux)(
      'allows a write through a second name in the write root for a file that also has one outside it',
      async () => {
        const name = join(ROOT, 'second-name')
        linkSync(join(OUTSIDE, 'file'), name)

        const { said } = await run(trying(`echo changed > ${name}`))

        expect(said).toContain('WROTE')
        expect(readFileSync(join(OUTSIDE, 'file'), 'utf8')).toBe('changed\n')
      },
    )

    // Such a name has to be there already. The write root is a mount of its
    // own inside the sandbox, and link(2) does not cross mounts.
    it.if(isLinux)(
      'does not let the command give a file outside the write root a second name in it',
      async () => {
        const name = join(ROOT, 'second-name')

        const { said } = await run(
          trying(`ln ${join(OUTSIDE, 'file')} ${name}`).replace(
            'WROTE',
            'LINKED',
          ),
        )

        expect(said).toContain('started')
        expect(said).toContain('refused')
        expect(existsSync(name)).toBe(false)
      },
    )
  },
)
