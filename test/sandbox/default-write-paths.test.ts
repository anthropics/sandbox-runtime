import { describe, it, expect, afterAll, beforeAll } from 'bun:test'
import { spawnSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { homedir, tmpdir } from 'node:os'
import { join } from 'node:path'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import {
  getDefaultWritePaths,
  isAtOrUnder,
} from '../../src/sandbox/sandbox-utils.js'
import { isLinux, isMacOS, isWindows } from '../helpers/platform.js'

const REPO_ROOT = join(import.meta.dir, '../..')
const NPM_LOGS = '.npm/_logs'
const CLAUDE_DEBUG = '.claude/debug'
const SANDBOX_OWN = [
  '/dev/stdout',
  '/dev/stderr',
  '/dev/null',
  '/dev/tty',
  '/dev/dtracehelper',
  '/dev/autofs_nowait',
  '/tmp/claude',
  '/private/tmp/claude',
]

/**
 * The two home directories among the default write paths are conveniences
 * the caller never asked for; one that a read-deny covers must not be bound
 * back over that deny. What the sandbox itself needs is never dropped.
 */
describe.if(!isWindows)('getDefaultWritePaths', () => {
  const home = homedir()
  const npmLogs = join(home, NPM_LOGS)
  const claudeDebug = join(home, CLAUDE_DEBUG)

  it('is the whole list when given no read rules', () => {
    expect(getDefaultWritePaths()).toEqual([
      ...SANDBOX_OWN,
      npmLogs,
      claudeDebug,
    ])
    expect(getDefaultWritePaths({ denyRead: [] })).toEqual(
      getDefaultWritePaths(),
    )
  })

  it.each([home, '~/', '~/**', join(home, '**'), '/', '/**'])(
    'drops both home conveniences, and nothing else, under denyRead %s',
    deny => {
      expect(getDefaultWritePaths({ denyRead: [deny] })).toEqual(SANDBOX_OWN)
    },
  )

  it.each(['/tmp', '/private/tmp', '/dev'])(
    'drops nothing under denyRead %s',
    deny => {
      expect(getDefaultWritePaths({ denyRead: [deny] })).toEqual(
        getDefaultWritePaths(),
      )
    },
  )

  it('leaves nothing under a read-denied home', () => {
    expect(
      getDefaultWritePaths({ denyRead: ['~'] }).filter(p =>
        isAtOrUnder(p, home),
      ),
    ).toEqual([])
  })

  it('drops only the convenience a deny names', () => {
    expect(getDefaultWritePaths({ denyRead: [npmLogs] })).toEqual([
      ...SANDBOX_OWN,
      claudeDebug,
    ])
  })

  it('drops a convenience under a directory a glob matches', () => {
    expect(getDefaultWritePaths({ denyRead: [join(home, '.n*')] })).toEqual([
      ...SANDBOX_OWN,
      claudeDebug,
    ])
  })

  it('keeps a convenience beside, not beneath, what is read-denied', () => {
    expect(
      getDefaultWritePaths({
        denyRead: [
          join(home, '.npmrc'),
          join(home, '.np'),
          join(home, '**/*.log'),
        ],
      }),
    ).toEqual(getDefaultWritePaths())
  })

  it('compares an entry whose brackets are no valid class as a literal', () => {
    expect(
      getDefaultWritePaths({ denyRead: [join(home, 'backup[2024-01-15]')] }),
    ).toEqual(getDefaultWritePaths())
  })

  it.each([
    {
      name: 'an allowRead above the directory, beneath the deny',
      denyRead: ['~'],
      allowRead: ['~/.claude'],
      kept: [claudeDebug],
    },
    {
      name: 'an allowRead of the directory itself',
      denyRead: ['~/.npm'],
      allowRead: ['~/.npm/_logs/**'],
      kept: [npmLogs, claudeDebug],
    },
    {
      name: 'no allowRead above the deny',
      denyRead: ['~/.claude'],
      allowRead: ['~'],
      kept: [npmLogs],
    },
    {
      name: 'no glob allowRead',
      denyRead: ['~'],
      allowRead: ['~/.c*'],
      kept: [],
    },
  ])('counts $name as re-opening it', ({ denyRead, allowRead, kept }) => {
    expect(getDefaultWritePaths({ denyRead, allowRead })).toEqual([
      ...SANDBOX_OWN,
      ...kept,
    ])
  })
})

/**
 * Runs `script` (an ES module body) under bun with HOME set to `fakeHome`
 * and returns the JSON it prints last. os.homedir() does not follow a HOME
 * changed at runtime, so these cases need a process of their own.
 */
function runWithHome(fakeHome: string, script: string): unknown {
  const result = spawnSync(process.execPath, ['-e', script], {
    cwd: REPO_ROOT,
    env: { ...process.env, HOME: fakeHome },
    encoding: 'utf8',
    timeout: 60_000,
  })
  if (result.status !== 0) {
    throw new Error(`exit ${result.status}: ${result.stderr}`)
  }
  return JSON.parse(result.stdout.trim().split('\n').at(-1) ?? '')
}

describe.if(isLinux || isMacOS)(
  'default write paths under another HOME',
  () => {
    let fakeHome: string

    beforeAll(() => {
      // On macOS tmpdir() is under /var, which normalizes to /private/var.
      fakeHome = mkdtempSync(join(tmpdir(), 'srt-home-'))
      mkdirSync(join(fakeHome, '.npm'))
      mkdirSync(join(fakeHome, CLAUDE_DEBUG), { recursive: true })
    })

    afterAll(() => {
      rmSync(fakeHome, { recursive: true, force: true })
    })

    it('drops a convenience directory that does not exist yet', () => {
      const paths = runWithHome(
        fakeHome,
        `const { getDefaultWritePaths } = await import('./src/sandbox/sandbox-utils.ts')
       console.log(JSON.stringify(getDefaultWritePaths({ denyRead: ['~/.npm'] })))`,
      )
      expect(paths).toEqual([...SANDBOX_OWN, join(fakeHome, CLAUDE_DEBUG)])
    })

    /** Whether the wrapped command makes `dir` writable. */
    function grantsWrite(wrapped: string, dir: string): boolean {
      if (isLinux) return wrapped.includes(`--bind ${dir} ${dir}`)
      const rule = wrapped.slice(wrapped.indexOf('(allow file-write*'))
      return rule.slice(0, rule.indexOf('(with message')).includes(dir)
    }

    it('reaches getFsWriteConfig() and the wrapped command', () => {
      mkdirSync(join(fakeHome, NPM_LOGS), { recursive: true })
      const { allowOnly, wrapped, reopened } = runWithHome(
        fakeHome,
        `const { SandboxManager } = await import('./src/sandbox/sandbox-manager.ts')
       const filesystem = { denyRead: ['~/.npm'], allowWrite: [], denyWrite: [] }
       await SandboxManager.initialize({
         network: { allowedDomains: [], deniedDomains: [] },
         filesystem,
         credentials: { files: [{ path: '~/.claude', mode: 'deny' }] },
       })
       const out = {
         allowOnly: SandboxManager.getFsWriteConfig().allowOnly,
         wrapped: await SandboxManager.wrapWithSandbox('true'),
         reopened: await SandboxManager.wrapWithSandbox('true', undefined, {
           filesystem: { ...filesystem, allowRead: ['~/.npm/_logs'] },
         }),
       }
       await SandboxManager.reset()
       process.stdout.write(JSON.stringify(out) + '\\n', () => process.exit(0))`,
      ) as { allowOnly: string[]; wrapped: string; reopened: string }

      // A filesystem deny and a credential file deny each drop theirs.
      expect(allowOnly).toEqual(SANDBOX_OWN)
      expect(grantsWrite(wrapped, join(fakeHome, NPM_LOGS))).toBe(false)
      expect(grantsWrite(wrapped, join(fakeHome, CLAUDE_DEBUG))).toBe(false)
      // A per-call allowRead of the directory keeps its write allow.
      expect(grantsWrite(reopened, join(fakeHome, NPM_LOGS))).toBe(true)
    })
  },
)

describe.if(isLinux)('getFsWriteConfig() stays a plain getter', () => {
  let dir: string

  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), 'srt-write-getter-'))
    writeFileSync(join(dir, 'a.env'), 'A=1')
    writeFileSync(join(dir, 'backup[2024-01-15].env'), 'B=2')
    writeFileSync(join(dir, 'hosts.yml'), 'k: v\n')
  })

  afterAll(async () => {
    await SandboxManager.reset()
    rmSync(dir, { recursive: true, force: true })
  })

  it('is untouched by what a denyRead glob expands to, or by a credential mask', async () => {
    await SandboxManager.reset()
    await SandboxManager.initialize({
      network: { allowedDomains: [], deniedDomains: [] },
      filesystem: {
        denyRead: [join(dir, '**/*.env')],
        allowWrite: [],
        denyWrite: [],
      },
      credentials: {
        files: [
          {
            path: join(dir, 'hosts.yml'),
            mode: 'mask',
            extract: 'nope: (\\S+)',
            onExtractNoMatch: 'error',
          },
        ],
      },
    })

    expect(SandboxManager.getFsWriteConfig().allowOnly).toEqual(
      getDefaultWritePaths(),
    )
  })

  it('wraps when a denyRead glob matches a file name with brackets', async () => {
    await SandboxManager.reset()
    await SandboxManager.initialize({
      network: { allowedDomains: [], deniedDomains: [] },
      filesystem: {
        denyRead: [join(dir, '**/*.env')],
        allowWrite: [],
        denyWrite: [],
      },
    })

    expect(await SandboxManager.wrapWithSandbox('true')).toContain(
      join(dir, 'backup[2024-01-15].env'),
    )
  })
})
