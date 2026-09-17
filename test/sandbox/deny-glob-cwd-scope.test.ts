import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'bun:test'
import { spawnSync } from 'node:child_process'
import {
  mkdirSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
  readFileSync,
  existsSync,
  realpathSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { wrapCommandWithSandboxMacOS } from '../../src/sandbox/macos-sandbox-utils.js'
import { isMacOS } from '../helpers/platform.js'

type Policy = { denyWrite?: string[]; denyRead?: string[] }

type SandboxRun = {
  command: string
  executed: boolean
  success: boolean
  stdout: string
  stderr: string
  status: number | null
  signal: string | null
  error: string | undefined
}

/**
 * Failure text for the controls' sentinel assertion. A bare
 * `Expected: true / Received: false` would not say whether the profile was
 * rejected, the spawn failed or the command timed out.
 */
const explainMissingSentinel = (run: SandboxRun): string =>
  `the sandbox never ran the command, so a rejected profile, a spawn failure or a timeout would read as a denial:\n${JSON.stringify(run, null, 2)}`

/**
 * On macOS, location-independent deny globs such as `**\/.env` are normalized
 * against `process.cwd()`. These tests show that they apply beneath cwd but not
 * to a matching path in a sibling directory inside the same allowed root, and
 * that the compiled rule carries cwd. See #432.
 *
 * Bun accepts any throw in `it.failing` as the expected failure, so those bodies
 * return early when the sandbox did not run. An infrastructure failure then
 * surfaces as "marked failing but passed" instead of as a passing test.
 */
describe.if(isMacOS)('deny globs outside process.cwd()', () => {
  const ORIGINAL = 'ORIGINAL'
  const MODIFIED = 'MODIFIED'
  const STARTED = '__DENY_GLOB_CWD_SCOPE_STARTED__'

  let tempRoot: string
  let allowedRoot: string
  let projectDir: string
  let outsideDir: string
  let originalCwd: string

  beforeAll(() => {
    originalCwd = process.cwd()
    // Timestamp-based roots can collide when runs start in the same millisecond.
    tempRoot = mkdtempSync(join(tmpdir(), 'deny-glob-cwd-scope-'))
    // Resolve macOS's symlinked temp path to the canonical path Seatbelt sees.
    allowedRoot = realpathSync(tempRoot)
    projectDir = join(allowedRoot, 'proj')
    outsideDir = join(allowedRoot, 'outside')
  })

  afterAll(() => {
    process.chdir(originalCwd)
    rmSync(tempRoot, { recursive: true, force: true })
  })

  beforeEach(() => {
    process.chdir(originalCwd)
    rmSync(projectDir, { recursive: true, force: true })
    rmSync(outsideDir, { recursive: true, force: true })
    mkdirSync(join(projectDir, 'sub'), { recursive: true })
    mkdirSync(join(outsideDir, 'newdir'), { recursive: true })

    writeFileSync(join(projectDir, '.env'), ORIGINAL)
    writeFileSync(join(projectDir, 'sub', '.env'), ORIGINAL)
    writeFileSync(join(outsideDir, '.env'), ORIGINAL)
    writeFileSync(join(projectDir, 'secret.txt'), ORIGINAL)
    writeFileSync(join(outsideDir, 'secret.txt'), ORIGINAL)
    writeFileSync(join(projectDir, 'sub', '.zshrc'), ORIGINAL)
    writeFileSync(join(outsideDir, '.zshrc'), ORIGINAL)
    mkdirSync(join(outsideDir, 'repo', '.git', 'hooks'), { recursive: true })
    // Left absent to exercise `file-write-create`: `outside/newdir/.env` and
    // `outside/repo/.git/hooks/pre-commit`.

    process.chdir(projectDir)
  })

  function runSandboxed(command: string, policy: Policy): SandboxRun {
    const prefix = `${STARTED}\n`

    const wrappedCommand = wrapCommandWithSandboxMacOS({
      command: `printf '%s\\n' '${STARTED}'; ${command}`,
      needsNetworkRestriction: false,
      readConfig: policy.denyRead
        ? { denyOnly: policy.denyRead, allowWithinDeny: [] }
        : undefined,
      writeConfig: {
        allowOnly: [allowedRoot],
        denyWithinAllow: policy.denyWrite ?? [],
      },
    })

    const result = spawnSync(wrappedCommand, {
      shell: true,
      encoding: 'utf8',
      timeout: 10000,
    })

    const rawStdout = result.stdout ?? ''
    // Requiring the sentinel keeps sandbox startup failures from masquerading
    // as denied operations.
    const markerSeen = rawStdout.startsWith(prefix)
    const executed =
      result.error === undefined && result.signal === null && markerSeen

    return {
      command,
      executed,
      success: executed && result.status === 0,
      stdout: markerSeen ? rawStdout.slice(prefix.length) : rawStdout,
      stderr: result.stderr ?? '',
      status: result.status,
      signal: result.signal,
      error: result.error?.message,
    }
  }

  /** `echo MODIFIED > target` inside the sandbox. */
  const runWrite = (target: string, policy: Policy): SandboxRun =>
    runSandboxed(`echo '${MODIFIED}' > '${target}'`, policy)

  /** `cat target` inside the sandbox. */
  const runRead = (target: string, policy: Policy): SandboxRun =>
    runSandboxed(`cat '${target}'`, policy)

  describe('user-written denyWrite glob', () => {
    it('control: blocks an overwrite under cwd', () => {
      const target = join(projectDir, 'sub', '.env')

      const result = runWrite(target, { denyWrite: ['**/.env'] })

      expect(result.executed, explainMissingSentinel(result)).toBe(true)
      expect(result.success).toBe(false)
      expect(readFileSync(target, 'utf8').trim()).toBe(ORIGINAL)
    })

    it('control: a write under cwd matching no deny entry succeeds', () => {
      // Same target as the control above with an empty deny list, so the denial
      // there is attributable to the entry and not to something else.
      const target = join(projectDir, 'sub', '.env')

      const result = runWrite(target, { denyWrite: [] })

      expect(result.executed, explainMissingSentinel(result)).toBe(true)
      expect(result.success).toBe(true)
      expect(readFileSync(target, 'utf8').trim()).toBe(MODIFIED)
    })

    it('control: an absolute entry outside cwd is enforced', () => {
      const target = join(outsideDir, '.env')

      const result = runWrite(target, { denyWrite: [target] })

      expect(result.executed, explainMissingSentinel(result)).toBe(true)
      expect(result.success).toBe(false)
      expect(readFileSync(target, 'utf8').trim()).toBe(ORIGINAL)
    })

    it('control: an absolute-prefixed glob outside cwd is enforced', () => {
      // Same wildcard, absolute prefix: normalizePathForSandbox() leaves it
      // alone. Glob handling itself still reaches outside cwd.
      const target = join(outsideDir, '.env')

      const result = runWrite(target, {
        denyWrite: [join(allowedRoot, '**', '.env')],
      })

      expect(result.executed, explainMissingSentinel(result)).toBe(true)
      expect(result.success).toBe(false)
      expect(readFileSync(target, 'utf8').trim()).toBe(ORIGINAL)
    })

    it('control: a write outside cwd matching no deny entry succeeds', () => {
      // Prevents a blanket write failure from satisfying every write assertion.
      const target = join(outsideDir, 'safe.txt')
      writeFileSync(target, ORIGINAL)

      const result = runWrite(target, { denyWrite: ['**/.env'] })

      expect(result.executed, explainMissingSentinel(result)).toBe(true)
      expect(result.success).toBe(true)
      expect(readFileSync(target, 'utf8').trim()).toBe(MODIFIED)
    })

    it.failing(
      'blocks an overwrite outside cwd but inside the allowed write root',
      () => {
        const target = join(outsideDir, '.env')

        const result = runWrite(target, { denyWrite: ['**/.env'] })

        if (!result.executed) return

        expect(result.success).toBe(false)
        expect(readFileSync(target, 'utf8').trim()).toBe(ORIGINAL)
      },
    )

    it.failing(
      'blocks creating a new file outside cwd (file-write-create)',
      () => {
        const target = join(outsideDir, 'newdir', '.env')

        const result = runWrite(target, { denyWrite: ['**/.env'] })

        if (!result.executed) return

        expect(result.success).toBe(false)
        expect(existsSync(target)).toBe(false)
      },
    )
  })

  describe('user-written denyRead glob', () => {
    it('control: denies reading a matched file under cwd', () => {
      const target = join(projectDir, 'secret.txt')

      const result = runRead(target, { denyRead: ['**/secret.txt'] })

      expect(result.executed, explainMissingSentinel(result)).toBe(true)
      expect(result.success).toBe(false)
      expect(result.stdout).not.toContain(ORIGINAL)
    })

    it('control: a read under cwd matching no deny entry succeeds', () => {
      // Same target as the control above; unlike the denial assertions this one
      // also fails if the fixture went missing.
      const target = join(projectDir, 'secret.txt')

      const result = runRead(target, { denyRead: ['**/nomatch.txt'] })

      expect(result.executed, explainMissingSentinel(result)).toBe(true)
      expect(result.success).toBe(true)
      expect(result.stdout).toContain(ORIGINAL)
    })

    it('control: an absolute entry outside cwd is enforced', () => {
      const target = join(outsideDir, 'secret.txt')

      const result = runRead(target, { denyRead: [target] })

      expect(result.executed, explainMissingSentinel(result)).toBe(true)
      expect(result.success).toBe(false)
      expect(result.stdout).not.toContain(ORIGINAL)
    })

    it('control: an absolute-prefixed read glob outside cwd is enforced', () => {
      // The other outside-cwd read control is a plain absolute path, which
      // compiles to `subpath`. This one takes the `regex` branch.
      const target = join(outsideDir, 'secret.txt')

      const result = runRead(target, {
        denyRead: [join(allowedRoot, '**', 'secret.txt')],
      })

      expect(result.executed, explainMissingSentinel(result)).toBe(true)
      expect(result.success).toBe(false)
      expect(result.stdout).not.toContain(ORIGINAL)
    })

    it('control: a read outside cwd matching no deny entry succeeds', () => {
      // Prevents a blanket read failure from satisfying every read assertion.
      const target = join(outsideDir, 'public.txt')
      writeFileSync(target, ORIGINAL)

      const result = runRead(target, { denyRead: ['**/secret.txt'] })

      expect(result.executed, explainMissingSentinel(result)).toBe(true)
      expect(result.success).toBe(true)
      expect(result.stdout).toContain(ORIGINAL)
    })

    it.failing('denies reading a matched file outside cwd', () => {
      const target = join(outsideDir, 'secret.txt')

      const result = runRead(target, { denyRead: ['**/secret.txt'] })

      if (!result.executed) return

      expect(result.success).toBe(false)
      expect(result.stdout).not.toContain(ORIGINAL)
    })
  })

  describe('the compiled rule', () => {
    it('control: carries cwd, which is the scope these cases pin', () => {
      // The behavioural cases above show the effect; this one shows the cause,
      // so a change in scope is attributable rather than inferred.
      const profile = wrapCommandWithSandboxMacOS({
        command: 'true',
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig: {
          allowOnly: [allowedRoot],
          denyWithinAllow: ['**/.env'],
        },
      })

      expect(profile).toContain(`^${projectDir}/(.*/)?`)
    })
  })

  describe('built-in mandatory deny (same normalization)', () => {
    it('control: blocks an overwrite of .zshrc under cwd', () => {
      // Under `sub/`, not at cwd itself: macGetMandatoryDenyPatterns() pushes
      // both `path.resolve(cwd, name)` and `**/<name>`, and only a nested target
      // pins the glob entry. Without this the two cases below stay green even if
      // the built-in list stopped being applied at all.
      const target = join(projectDir, 'sub', '.zshrc')

      const result = runWrite(target, {})

      expect(result.executed, explainMissingSentinel(result)).toBe(true)
      expect(result.success).toBe(false)
      expect(readFileSync(target, 'utf8').trim()).toBe(ORIGINAL)
    })

    it.failing('blocks an overwrite of .zshrc outside cwd', () => {
      const target = join(outsideDir, '.zshrc')

      const result = runWrite(target, {})

      if (!result.executed) return

      expect(result.success).toBe(false)
      expect(readFileSync(target, 'utf8').trim()).toBe(ORIGINAL)
    })

    it.failing('blocks creating .git/hooks/pre-commit outside cwd', () => {
      const target = join(outsideDir, 'repo', '.git', 'hooks', 'pre-commit')

      const result = runWrite(target, {})

      if (!result.executed) return

      expect(result.success).toBe(false)
      expect(existsSync(target)).toBe(false)
    })
  })
})
