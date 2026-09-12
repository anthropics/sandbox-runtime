import { describe, it, expect, beforeEach, afterEach } from 'bun:test'
import { spawnSync } from 'node:child_process'
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  symlinkSync,
} from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import {
  wrapCommandWithSandboxLinux,
  cleanupBwrapMountPoints,
} from '../../src/sandbox/linux-sandbox-utils.js'
import { isLinux } from '../helpers/platform.js'

/**
 * Regression tests for symlinked deny paths (resolve-before-mask).
 *
 * In the common dotfiles setup, .claude (or the parent of .mcp.json) is a
 * symlink to a real directory. Deny paths crossing such a symlink used to be
 * masked with `--ro-bind /dev/null <symlink>`, which bwrap rejects at
 * startup ("Is a directory" for relative link targets, ENOENT for absolute
 * ones) — so every sandboxed command failed. Deny paths must instead be
 * canonicalized through symlinks and the deny applied to the resolved
 * target, which is the inode writes through the symlink actually reach.
 */
describe.if(isLinux)('Symlinked deny paths (resolve-before-mask)', () => {
  // realpathSync so exact-string assertions hold even when tmpdir itself
  // contains symlinks.
  let BASE: string
  let AREA: string // allowed write area
  let PROJ: string // project dir containing the symlinks
  let DOTFILES: string // real directory the symlinks point into

  const hasBwrap = spawnSync('bwrap', ['--version']).status === 0

  beforeEach(() => {
    BASE = realpathSync(mkdtempSync(join(tmpdir(), 'symlinked-deny-')))
    AREA = join(BASE, 'area')
    PROJ = join(AREA, 'proj')
    DOTFILES = join(AREA, 'dotfiles')
    mkdirSync(join(DOTFILES, 'claude', 'commands'), { recursive: true })
    mkdirSync(join(DOTFILES, 'claude', 'agents'), { recursive: true })
    mkdirSync(PROJ, { recursive: true })
  })

  afterEach(() => {
    cleanupBwrapMountPoints({ force: true })
    rmSync(BASE, { recursive: true, force: true })
  })

  async function wrap(
    denyPaths: string[],
    readDenyPaths: string[] = [],
  ): Promise<string> {
    return wrapCommandWithSandboxLinux({
      command: 'echo hello',
      needsNetworkRestriction: false,
      readConfig: { denyOnly: readDenyPaths },
      writeConfig: {
        allowOnly: [AREA],
        denyWithinAllow: denyPaths,
      },
    })
  }

  it('denies the resolved target for a .claude directory symlink with a relative target', async () => {
    const claudeLink = join(PROJ, '.claude')
    symlinkSync(join('..', 'dotfiles', 'claude'), claudeLink)

    const result = await wrap([join(PROJ, '.claude', 'commands')])
    const resolved = join(DOTFILES, 'claude', 'commands')

    // No /dev/null bind onto the raw symlink path (bwrap aborts on those).
    expect(result).not.toContain(`--ro-bind /dev/null ${claudeLink}`)
    // The resolved target is write-denied instead.
    expect(result).toContain(`--ro-bind ${resolved} ${resolved}`)
  })

  it('denies the resolved target for a .claude directory symlink with an absolute target', async () => {
    const claudeLink = join(PROJ, '.claude')
    symlinkSync(join(DOTFILES, 'claude'), claudeLink)

    const result = await wrap([join(PROJ, '.claude', 'commands')])
    const resolved = join(DOTFILES, 'claude', 'commands')

    expect(result).not.toContain(`--ro-bind /dev/null ${claudeLink}`)
    expect(result).toContain(`--ro-bind ${resolved} ${resolved}`)
  })

  it('blocks creation of .mcp.json at the resolved location when its parent is a symlink', async () => {
    // proj2 is a symlink to a real directory; .mcp.json does not exist yet.
    const realProj = join(AREA, 'real-proj')
    mkdirSync(realProj)
    const projLink = join(AREA, 'proj2')
    symlinkSync(realProj, projLink)

    const result = await wrap([join(projLink, '.mcp.json')])

    // The creation-blocking mask must land at the resolved parent, not the
    // raw symlinked path.
    expect(result).not.toContain(`/dev/null ${join(projLink, '.mcp.json')}`)
    expect(result).toContain(
      `--ro-bind /dev/null ${join(realProj, '.mcp.json')}`,
    )
  })

  it('follows a dangling symlink so the deny lands where a write would create the file', async () => {
    // .mcp.json -> <AREA>/nowhere.json (target does not exist). A write
    // through the link would create the target, so that is what gets masked.
    const danglingLink = join(PROJ, '.mcp.json')
    const linkTarget = join(AREA, 'nowhere.json')
    symlinkSync(linkTarget, danglingLink)

    const result = await wrap([danglingLink])

    expect(result).not.toContain(`/dev/null ${danglingLink}`)
    expect(result).toContain(`--ro-bind /dev/null ${linkTarget}`)
  })

  it('fails closed on a symlink cycle rather than dropping the deny', async () => {
    // An unresolvable deny path must not silently disappear: masking the
    // symlink makes bwrap refuse to start, rather than sandboxing the
    // command with the path unprotected.
    const a = join(PROJ, 'cycle-a')
    const b = join(PROJ, 'cycle-b')
    symlinkSync(a, b)
    symlinkSync(b, a)

    const result = await wrap([join(a, '.mcp.json')])

    expect(result).toContain(`--ro-bind /dev/null ${a}`)
  })

  it('emits the symlink mask only once for several denies sharing a cyclic ancestor', async () => {
    // Two --ro-bind /dev/null onto the same dest make bwrap's ensure_file()
    // fall through to creat() on a read-only mount.
    const claudeLink = join(PROJ, '.claude')
    const other = join(PROJ, '.claude-x')
    symlinkSync(other, claudeLink)
    symlinkSync(claudeLink, other)

    const result = await wrap([
      join(claudeLink, 'commands'),
      join(claudeLink, 'agents'),
    ])

    const masks = result.split(`--ro-bind /dev/null ${claudeLink}`).length - 1
    expect(masks).toBe(1)
  })

  it('does not re-expose a read-denied directory reached through a symlink', async () => {
    // denyRead mounts a tmpfs on the raw (symlinked) dir, while the denyWrite
    // dest is canonicalized. If the two are compared by raw string the
    // denyWrite --ro-bind lands on top of the tmpfs and re-exposes the real,
    // read-denied contents.
    const claudeLink = join(PROJ, '.claude')
    symlinkSync(join('..', 'dotfiles', 'claude'), claudeLink)

    const result = await wrap([join(claudeLink, 'commands')], [claudeLink])
    const resolved = join(DOTFILES, 'claude', 'commands')

    expect(result).toContain(`--tmpfs ${claudeLink}`)
    expect(result).not.toContain(`--ro-bind ${resolved} ${resolved}`)
  })

  it('resolves the mandatory .claude deny paths when cwd/.claude is a symlink', async () => {
    const claudeLink = join(PROJ, '.claude')
    symlinkSync(join('..', 'dotfiles', 'claude'), claudeLink)

    const originalCwd = process.cwd()
    process.chdir(PROJ)
    try {
      // No explicit denyWithinAllow: the mandatory deny paths (cwd-relative
      // .claude/commands, .claude/agents, .mcp.json, ...) trigger the bug.
      const result = await wrap([])

      expect(result).not.toContain(`--ro-bind /dev/null ${claudeLink}`)
      for (const sub of ['commands', 'agents']) {
        const resolved = join(DOTFILES, 'claude', sub)
        expect(result).toContain(`--ro-bind ${resolved} ${resolved}`)
      }
    } finally {
      process.chdir(originalCwd)
    }
  })

  it('resolves the mandatory .git/hooks deny path when hooks is a symlink to a directory', async () => {
    // A repo that shares its hooks: .git/hooks -> ../hooks (#221). The
    // mandatory deny is cwd-relative, so cwd has to be the repo.
    mkdirSync(join(PROJ, '.git'))
    mkdirSync(join(PROJ, 'hooks'))
    const hooksLink = join(PROJ, '.git', 'hooks')
    symlinkSync(join('..', 'hooks'), hooksLink)

    const originalCwd = process.cwd()
    process.chdir(PROJ)
    try {
      const result = await wrap([])

      expect(result).not.toContain(`--ro-bind /dev/null ${hooksLink}`)
      const resolved = join(PROJ, 'hooks')
      expect(result).toContain(`--ro-bind ${resolved} ${resolved}`)
    } finally {
      process.chdir(originalCwd)
    }
  })

  it('denies the resolved target for a denyWrite entry that is a symlink to a directory', async () => {
    // .claude/skills -> ../../dotfiles/skills (#314): the entry itself is
    // the symlink, not an ancestor of the deny path.
    mkdirSync(join(DOTFILES, 'skills'))
    mkdirSync(join(PROJ, '.claude'))
    const skillsLink = join(PROJ, '.claude', 'skills')
    symlinkSync(join('..', '..', 'dotfiles', 'skills'), skillsLink)

    const result = await wrap([skillsLink])
    const resolved = join(DOTFILES, 'skills')

    expect(result).not.toContain(`--ro-bind /dev/null ${skillsLink}`)
    expect(result).toContain(`--ro-bind ${resolved} ${resolved}`)
  })

  it.if(hasBwrap)(
    'e2e: sandbox starts with a symlinked .claude and still denies writes through it',
    async () => {
      const claudeLink = join(PROJ, '.claude')
      symlinkSync(join('..', 'dotfiles', 'claude'), claudeLink)

      const run = async (command: string) => {
        const wrapped = await wrapCommandWithSandboxLinux({
          command,
          needsNetworkRestriction: false,
          readConfig: { denyOnly: [] },
          writeConfig: {
            allowOnly: [AREA],
            denyWithinAllow: [
              join(PROJ, '.claude', 'commands'),
              join(PROJ, '.claude', 'agents'),
            ],
          },
        })
        return spawnSync(wrapped, {
          shell: true,
          encoding: 'utf8',
          timeout: 10000,
          cwd: PROJ,
        })
      }

      // Before the fix bwrap aborted at startup for every command.
      const ok = await run('echo e2e-ok')
      expect(ok.stderr).not.toContain("Can't create file")
      expect(ok.status).toBe(0)
      expect(ok.stdout).toContain('e2e-ok')

      // Writes through the symlinked path hit the denied resolved target.
      const denied = await run(
        `sh -c 'echo evil > ${join(claudeLink, 'commands', 'evil.md')}'`,
      )
      expect(denied.status).not.toBe(0)
      expect(existsSync(join(DOTFILES, 'claude', 'commands', 'evil.md'))).toBe(
        false,
      )

      // The rest of the allowed area stays writable.
      const allowed = await run(`sh -c 'echo ok > ${join(PROJ, 'ok.txt')}'`)
      expect(allowed.status).toBe(0)
      expect(existsSync(join(PROJ, 'ok.txt'))).toBe(true)
    },
  )

  it.if(hasBwrap)(
    'e2e: a cyclic .claude stops the sandbox instead of leaving the path writable',
    async () => {
      const claudeLink = join(PROJ, '.claude')
      const other = join(PROJ, '.claude-x')
      symlinkSync(other, claudeLink)
      symlinkSync(claudeLink, other)

      const wrapped = await wrapCommandWithSandboxLinux({
        command: `rm -f .claude && mkdir -p .claude/commands && echo planted > ${join(
          PROJ,
          '.claude',
          'commands',
          'planted.md',
        )}`,
        needsNetworkRestriction: false,
        readConfig: { denyOnly: [] },
        writeConfig: {
          allowOnly: [AREA],
          denyWithinAllow: [join(PROJ, '.claude', 'commands')],
        },
      })
      const result = spawnSync(wrapped, {
        shell: true,
        encoding: 'utf8',
        timeout: 10000,
        cwd: PROJ,
      })

      expect(result.status).not.toBe(0)
      expect(existsSync(join(PROJ, '.claude', 'commands', 'planted.md'))).toBe(
        false,
      )
    },
  )
})
