import { describe, it, expect, beforeAll, afterAll, spyOn } from 'bun:test'
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
 * reach the backends verbatim when their target is absent — which for a deny
 * is the case the deny is for (a credential file that appears later). Seatbelt
 * then compares the kernel's canonical path, so such a filter matches nothing,
 * silently. '..' is left to realpath: folding it lexically can aim the rule
 * past a symlink at a file the kernel would never reach.
 */
// An absent path under a real directory, so no realpath can rescue a spelling
// under it and its own spelling is fixed. `scratch` is the working directory
// the child processes below run in.
let ABSENT: string
let absentRoot: string
let scratch: string

beforeAll(() => {
  absentRoot = realpathSync(mkdtempSync(join(tmpdir(), 'srt-absent-')))
  ABSENT = join(absentRoot, 'no-such-dir')
  scratch = realpathSync(mkdtempSync(join(tmpdir(), 'srt-scratch-')))
})

afterAll(() => {
  rmSync(absentRoot, { recursive: true, force: true })
  rmSync(scratch, { recursive: true, force: true })
})

/**
 * normalizePathForSandbox in a child with $HOME set to `home`: $HOME is read
 * once at start-up, so it cannot be changed in this process. The environment
 * is scrubbed so the parent's SRT_DEBUG does not put sandbox debug output on
 * the child's stderr.
 */
function normalizeWithHome(
  home: string,
  patterns: string[],
): { homedir: string; results: string[]; tildeBindsRoot: boolean } {
  const module = new URL('../../src/sandbox/sandbox-utils.ts', import.meta.url)
    .href
  const linuxModule = new URL(
    '../../src/sandbox/linux-sandbox-utils.ts',
    import.meta.url,
  ).href
  const child = spawnSync(
    process.execPath,
    [
      '-e',
      `const os = await import('node:os')\n` +
        `const m = await import(${JSON.stringify(module)})\n` +
        `const linux = await import(${JSON.stringify(linuxModule)})\n` +
        `const argv = process.platform === 'linux' ? await linux.wrapCommandWithSandboxLinux({\n` +
        `  command: 'true', needsNetworkRestriction: false, readConfig: undefined,\n` +
        `  writeConfig: { allowOnly: ['~'], denyWithinAllow: [] },\n` +
        `}) : ''\n` +
        `console.log(JSON.stringify({ homedir: os.homedir(), results: ${JSON.stringify(
          patterns,
        )}.map(p => m.normalizePathForSandbox(p)), tildeBindsRoot: / --bind \\/ \\/ /.test(argv) }))`,
    ],
    {
      encoding: 'utf8',
      timeout: 20000,
      env: { PATH: process.env.PATH ?? '', HOME: home },
      // Its own directory: the Linux wrap scans the working directory and may
      // leave mount-point stubs there, which this process would not clean up.
      cwd: scratch,
    },
  )
  expect(child.status).toBe(0)
  expect(child.stderr ?? '').toBe('')
  return JSON.parse(child.stdout)
}

describe.if(!isWindows)('normalizePathForSandbox interior spellings', () => {
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

  it('leaves a dot-file segment alone', () => {
    // The '/.' drop is gated on a following '/', so a name that merely starts
    // with a dot, and '...', survive.
    expect(normalizePathForSandbox(`${ABSENT}/.ssh/id_rsa`)).toBe(
      `${ABSENT}/.ssh/id_rsa`,
    )
    expect(normalizePathForSandbox(`${ABSENT}/.../b`)).toBe(`${ABSENT}/.../b`)
    expect(normalizePathForSandbox(`${ABSENT}/.*/x`)).toBe(`${ABSENT}/.*/x`)
  })

  it('keeps a ".." component in an absent path verbatim', () => {
    expect(normalizePathForSandbox(`${ABSENT}/sub/../x`)).toBe(
      `${ABSENT}/sub/../x`,
    )
    // Including in a glob spelling, which returns before the realpath below.
    expect(normalizePathForSandbox(`${ABSENT}/sub/../*.pem`)).toBe(
      `${ABSENT}/sub/../*.pem`,
    )
  })

  it('says so when a glob spelling keeps an unfoldable ".."', () => {
    // The glob branch returns before the realpath below, so this line is the
    // only notice that the compiled rule may match nothing. It names the
    // spelling that reaches the backend, not the one the caller passed.
    const lines: string[] = []
    const warn = spyOn(console, 'warn').mockImplementation(message => {
      lines.push(String(message))
    })
    const debug = process.env.SRT_DEBUG
    process.env.SRT_DEBUG = '1'
    try {
      normalizePathForSandbox(`${ABSENT}//sub/../*.pem`)
    } finally {
      if (debug === undefined) delete process.env.SRT_DEBUG
      else process.env.SRT_DEBUG = debug
      warn.mockRestore()
    }
    const logged = lines.join('\n')
    expect(logged).toContain(`${ABSENT}/sub/../*.pem`)
    expect(logged).not.toContain(`${ABSENT}//`)
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
    // backends as '/root//x'.
    const created = mkdtempSync(join(tmpdir(), 'srt-home-'))
    try {
      const home = realpathSync(created)
      const { results } = normalizeWithHome(`${home}/`, [
        '~',
        '~/x',
        '~/x/*.key',
      ])
      expect(results).toEqual([home, `${home}/x`, `${home}/x/*.key`])
    } finally {
      rmSync(created, { recursive: true, force: true })
    }
  }, 30000)

  it('does not expand a tilde into the filesystem root under an empty HOME', () => {
    // An empty $HOME makes homedir(), and so expandTilde('~'), empty; '' must
    // not fall through to '/' here or at the Linux backend's own trailing-run
    // strip, either of which turns `allowWrite: ['~']` into a whole-filesystem
    // write grant. Only a runtime whose homedir() honours an empty $HOME
    // reaches that at all: node does, bun falls back to the passwd entry.
    const { homedir, results, tildeBindsRoot } = normalizeWithHome('', ['~'])
    expect(results[0]).not.toBe('/')
    expect(results[0]).toBe(homedir)
    expect(tildeBindsRoot).toBe(false)
  }, 30000)
})

describe.if(!isWindows)('macOS profile: interior spellings', () => {
  it('emits the canonical subpath for an absent slash-run deny', () => {
    const profile = wrapCommandWithSandboxMacOS({
      command: 'true',
      needsNetworkRestriction: false,
      readConfig: { denyOnly: [`${ABSENT}/a//b`], allowWithinDeny: [] },
      writeConfig: undefined,
    })
    expect(profile).toContain(`(subpath "${ABSENT}/a/b")`)
    expect(profile).not.toContain(`${ABSENT}/a//b`)
  })

  it('compiles a deny glob spelled with a slash run like the clean one', () => {
    const profileFor = (deny: string): string =>
      wrapCommandWithSandboxMacOS({
        command: 'true',
        needsNetworkRestriction: false,
        readConfig: { denyOnly: [deny], allowWithinDeny: [] },
        writeConfig: undefined,
      })

    const spelled = profileFor(`${ABSENT}/a//*.pem`)
    expect(spelled).toBe(profileFor(`${ABSENT}/a/*.pem`))
    expect(spelled).not.toContain(`${ABSENT}/a//`)
  })
})
