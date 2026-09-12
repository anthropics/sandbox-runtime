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
 * allow the read. The chokepoint therefore collapses '//' runs and '/.'
 * components after expansion, on POSIX, plus the trailing run for the
 * spellings where it is not semantic. '..' is left to realpath: folding it
 * lexically can aim the rule at a different file than the kernel would reach
 * through a symlink.
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

  it('collapses the interior of a glob spelling too', () => {
    expect(normalizePathForSandbox(`${ABSENT}//x/*`)).toBe(`${ABSENT}/x/*`)
    expect(normalizePathForSandbox(`${ABSENT}/./x/*.pem`)).toBe(
      `${ABSENT}/x/*.pem`,
    )
    expect(normalizePathForSandbox(`${ABSENT}//**/x`)).toBe(`${ABSENT}/**/x`)
    expect(normalizePathForSandbox('//**/x')).toBe('/**/x')
  })

  it('keeps what is semantic in a glob spelling', () => {
    // A slash after a glob segment compiles to a different regex, and a '**'
    // segment is left as it is.
    expect(normalizePathForSandbox(`${ABSENT}/x/*/`)).toBe(`${ABSENT}/x/*/`)
    expect(normalizePathForSandbox(`${ABSENT}/**/*.pem`)).toBe(
      `${ABSENT}/**/*.pem`,
    )
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
            `console.log(JSON.stringify([m.normalizePathForSandbox('~'), m.normalizePathForSandbox('~/x'), m.normalizePathForSandbox('~/x/*.key')]))`,
        ],
        {
          encoding: 'utf8',
          timeout: 20000,
          env: { ...process.env, HOME: `${home}/` },
        },
      )
      expect(child.stderr ?? '').toBe('')
      expect(child.status).toBe(0)
      expect(JSON.parse(child.stdout)).toEqual([
        home,
        `${home}/x`,
        `${home}/x/*.key`,
      ])
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

  it('compiles a deny glob spelled with a slash run like the clean one', () => {
    const profileFor = (deny: string): string =>
      wrapCommandWithSandboxMacOS({
        command: 'true',
        needsNetworkRestriction: false,
        readConfig: { denyOnly: [deny], allowWithinDeny: [] },
        writeConfig: undefined,
      })

    const spelled = profileFor('/srt-no-such-root/a//*.pem')
    expect(spelled).toBe(profileFor('/srt-no-such-root/a/*.pem'))
    expect(spelled).not.toContain('/srt-no-such-root/a//')
  })
})
