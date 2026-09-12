import { describe, it, expect } from 'bun:test'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, realpathSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { wrapCommandWithSandboxMacOS } from '../../src/sandbox/macos-sandbox-utils.js'
import { normalizePathForSandbox } from '../../src/sandbox/sandbox-utils.js'
import { isWindows } from '../helpers/platform.js'

/**
 * Interior non-canonical spellings.
 *
 * realpath canonicalises a path that exists, so '/a//b' and '/a/./b' only
 * reach the backends verbatim when their target does not exist — which for a
 * deny is the case the deny is for (a credential file that appears later).
 * Seatbelt compares the kernel's canonical path, so a rule spelled that way
 * matches nothing and denies nothing, silently: with sandbox-exec, `(deny
 * file-read* (subpath "<T>/x//dir"))` and `(literal "<T>/x//dir/f.txt")` both
 * allow the read. The chokepoint therefore collapses '//' runs, '/.'
 * components and the trailing run after expansion, for non-glob POSIX
 * spellings. '..' is left to realpath: folding it lexically can aim the rule
 * at a different file than the kernel would reach through a symlink.
 *
 * The Linux backend rebuilds its destinations with path.dirname/join, so it
 * canonicalises these spellings on its own; the argv was already right.
 */
describe.if(!isWindows)('normalizePathForSandbox interior spellings', () => {
  // An absent base, so realpath never rescues the spelling.
  const ABSENT = '/srt-no-such-root/dir'

  it('collapses slash runs, "." components and the trailing run', () => {
    expect(normalizePathForSandbox(`${ABSENT}//x`)).toBe(`${ABSENT}/x`)
    expect(normalizePathForSandbox(`${ABSENT}///x`)).toBe(`${ABSENT}/x`)
    expect(normalizePathForSandbox(`${ABSENT}/./x`)).toBe(`${ABSENT}/x`)
    expect(normalizePathForSandbox(`${ABSENT}/././x`)).toBe(`${ABSENT}/x`)
    expect(normalizePathForSandbox(`${ABSENT}/x/.`)).toBe(`${ABSENT}/x`)
    expect(normalizePathForSandbox(`${ABSENT}/.//x//`)).toBe(`${ABSENT}/x`)
    // A leading '//' is collapsed with the rest: POSIX allows an
    // implementation to treat it specially, neither backend does.
    expect(normalizePathForSandbox(`/${ABSENT}/x`)).toBe(`${ABSENT}/x`)
    // Nothing collapses to the empty string.
    expect(normalizePathForSandbox('//')).toBe('/')
    expect(normalizePathForSandbox('/.')).toBe('/')
  })

  it('keeps a ".." component in an absent path verbatim', () => {
    expect(normalizePathForSandbox(`${ABSENT}/sub/../x`)).toBe(
      `${ABSENT}/sub/../x`,
    )
  })

  it('leaves glob spellings untouched', () => {
    expect(normalizePathForSandbox(`${ABSENT}//x/*`)).toBe(`${ABSENT}//x/*`)
    expect(normalizePathForSandbox(`${ABSENT}/./x/*`)).toBe(`${ABSENT}/./x/*`)
  })

  it('canonicalises a home directory spelled with a trailing slash', () => {
    // `ENV HOME=/root/` in a Dockerfile is enough to reintroduce the slash:
    // the strip runs before expansion, so '~/x' would otherwise reach the
    // backends as '/root//x'. bun reads $HOME once at start-up, so this
    // runs in a child with HOME set rather than assigning process.env.
    const home = realpathSync(mkdtempSync(join(tmpdir(), 'srt-home-')))
    try {
      const module = new URL(
        '../../src/sandbox/sandbox-utils.ts',
        import.meta.url,
      ).href
      const child = spawnSync(
        process.execPath,
        [
          '-e',
          `const m = await import(${JSON.stringify(module)})\n` +
            `console.log(JSON.stringify([m.normalizePathForSandbox('~'), m.normalizePathForSandbox('~/x')]))`,
        ],
        {
          encoding: 'utf8',
          timeout: 20000,
          env: { ...process.env, HOME: `${home}/` },
        },
      )
      expect(child.stderr ?? '').toBe('')
      expect(child.status).toBe(0)
      expect(JSON.parse(child.stdout)).toEqual([home, `${home}/x`])
    } finally {
      rmSync(home, { recursive: true, force: true })
    }
  }, 30000)
})

describe.if(!isWindows)('macOS profile: interior spellings', () => {
  it('emits the canonical subpath for an absent slash-run deny', () => {
    const profile = wrapCommandWithSandboxMacOS({
      command: 'true',
      needsNetworkRestriction: false,
      readConfig: { denyOnly: ['/srt-no-such-root/a//b'], allowWithinDeny: [] },
      writeConfig: undefined,
    })
    expect(profile).toContain('(subpath "/srt-no-such-root/a/b")')
    expect(profile).not.toContain('/srt-no-such-root/a//b')
  })
})
