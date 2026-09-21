/**
 * Credential value sources.
 *
 * A `credentials.envVars` entry with `mode: "mask"` reads its real value
 * from the host environment. That works, but it means the plaintext has to
 * be exported into srt's own parent process before srt can hide it:
 * `export GH_TOKEN=$(op read op://vault/gh/token)` puts the credential in
 * exactly the place the sentinel exists to keep it out of, where every
 * sibling process of the same user can read it out of `/proc` or `ps -E`.
 *
 * A `source` names where the real value comes from instead. srt runs the
 * command, reads the value off its stdout, registers a sentinel for it and
 * sets the fake inside the sandbox. The value never exists as an exported
 * variable, and the vault CLI is the only process that ever holds it
 * besides srt itself.
 *
 * **The command runs on the host, outside the sandbox, with srt's own
 * privileges**, before any sandbox exists to confine it. That is inherent:
 * a vault CLI needs the network, the keychain and the user's session to do
 * its job, none of which it would have inside. What follows from it is that
 * whoever can write the settings file chooses a command srt will execute.
 * See the provenance rules in {@link resolveExecutable}, and `filesystem`
 * write rules covering the settings file itself.
 */

import { spawnSync } from 'node:child_process'
import path from 'node:path'
import { logForDebugging } from '../utils/debug.js'
import { whichSync } from '../utils/which.js'
import type { CredentialSourceConfig } from './sandbox-config.js'

/** Wall-clock budget for one source command when none is configured. */
export const DEFAULT_CREDENTIAL_SOURCE_TIMEOUT_MS = 10_000

/**
 * Cap on a source command's stdout. A credential is a token, not a
 * payload; the cap keeps a runaway command from ballooning the wrap's
 * memory before the timeout can fire.
 */
export const MAX_CREDENTIAL_SOURCE_BYTES = 1024 * 1024

export type CredentialSourceErrorCode =
  /** `command` has a path separator but is not absolute. */
  | 'relative_command'
  /** A bare `command` name is not on PATH. */
  | 'not_found'
  /** The process never started (ENOENT, EACCES, EPERM, ...). */
  | 'spawn_failed'
  /** Killed at the configured `timeoutMs`. */
  | 'timeout'
  /** Ran, exited non-zero or on a signal. */
  | 'exit_status'
  /** stdout exceeded {@link MAX_CREDENTIAL_SOURCE_BYTES}. */
  | 'too_large'
  /** Ran, exited zero, produced nothing. */
  | 'empty_value'
  /** Ran, produced bytes that cannot be an environment variable value. */
  | 'invalid_value'

/**
 * A source that did not produce a value.
 *
 * The message is scoped to the command, never to the variable that asked
 * for it: one source can back several variables and the failure is cached
 * against the command, so naming the first variable to ask would misreport
 * every later one. Callers add their own variable name when they report.
 *
 * The message never carries stdout, because a command can fail *after*
 * writing a partial credential.
 */
export class CredentialSourceError extends Error {
  constructor(
    readonly code: CredentialSourceErrorCode,
    message: string,
  ) {
    super(message)
    this.name = 'CredentialSourceError'
  }
}

/** Stable cache key for a source spec: the process it would run. */
function specKey(source: CredentialSourceConfig): string {
  // `timeoutMs` is deliberately not part of the key. It is a budget for
  // the command, not part of its identity, so two entries that differ
  // only in their budget must not run the vault CLI twice.
  return JSON.stringify([source.type, source.command, source.args ?? []])
}

/**
 * Resolve `command` to the absolute executable srt will spawn.
 *
 * A name with no separator is looked up on PATH. A name *with* a separator
 * must be absolute: a relative path resolves against whatever working
 * directory srt happens to have been started in, which the operator who
 * wrote the settings file does not control and an attacker who can drop a
 * file into a build directory sometimes does.
 *
 * This is a provenance rule, not a sandbox: PATH itself is inherited, so a
 * bare name is only as trustworthy as the environment srt runs in. It
 * removes the cheapest way to aim the spawn, and leaves the expensive ones
 * to the write rules over the settings file.
 */
function resolveExecutable(command: string): string {
  const hasSeparator =
    command.includes('/') ||
    (process.platform === 'win32' && command.includes('\\'))
  if (hasSeparator) {
    if (!path.isAbsolute(command)) {
      throw new CredentialSourceError(
        'relative_command',
        `command "${command}" is a relative path. Use an absolute path, ` +
          `or a bare executable name to resolve it on PATH. A relative ` +
          `path resolves against srt's working directory, which is not ` +
          `the settings file's directory and is not stable.`,
      )
    }
    return command
  }
  const found = whichSync(command)
  if (found === null) {
    throw new CredentialSourceError(
      'not_found',
      `command "${command}" was not found on PATH.`,
    )
  }
  return found
}

/**
 * Strip the one trailing newline a vault CLI adds, and nothing else.
 *
 * `op read`, `vault kv get -field=`, `gcloud auth print-access-token` and
 * `pass show` all terminate their output with a single newline. A blanket
 * `.trim()` would also eat leading and trailing whitespace that is part of
 * the credential, and a credential that is wrong in a way that still looks
 * like a credential fails far from here: at the upstream, as a 401 with
 * no hint that srt corrupted it. One newline is the documented contract;
 * everything else is the value.
 */
function decodeValue(stdout: Buffer): string {
  let end = stdout.length
  if (end > 0 && stdout[end - 1] === 0x0a) {
    end -= 1
    if (end > 0 && stdout[end - 1] === 0x0d) end -= 1
  }
  const buf = stdout.subarray(0, end)
  if (buf.includes(0x00)) {
    throw new CredentialSourceError(
      'invalid_value',
      `produced a value containing a NUL byte, which cannot be carried ` +
        `in an environment variable.`,
    )
  }
  if (buf.length === 0) {
    throw new CredentialSourceError(
      'empty_value',
      `exited 0 but produced no output on stdout.`,
    )
  }
  return buf.toString('utf8')
}

/** First line of a command's stderr, bounded, for an error message. */
function firstStderrLine(stderr: Buffer | null): string {
  if (!stderr || stderr.length === 0) return ''
  const line = stderr.toString('utf8').split('\n', 1)[0]!.trim()
  if (line.length === 0) return ''
  return line.length > 200 ? `${line.slice(0, 200)}…` : line
}

/**
 * Run one source command and return its value.
 *
 * **On the timeout.** `timeoutMs` is enforced by `spawnSync`, which kills
 * the child at the deadline and then keeps blocking until the child's
 * stdio pipes close. Those are not the same instant: a command that
 * spawned a background grandchild holding stdout can return well past its
 * budget (measured at 4026ms against a 300ms budget), and a command whose
 * grandchild never exits can hold the wrap open indefinitely. Node offers
 * no synchronous wait that bounds this, so it is a real limitation rather
 * than a fixed one: `killSignal` is `SIGKILL` so the child itself cannot
 * sit on a caught SIGTERM, the elapsed time is reported in the error so
 * the number an operator sees is the real one, and a source command should
 * not fork anything that outlives it.
 */
function runCommandSource(
  source: CredentialSourceConfig,
  exePath: string,
): string {
  const timeoutMs = source.timeoutMs ?? DEFAULT_CREDENTIAL_SOURCE_TIMEOUT_MS
  const args = source.args ?? []
  const startedAt = Date.now()
  const r = spawnSync(exePath, args, {
    // stdin is /dev/null, not inherited: a vault CLI that would prompt for
    // a passphrase reads EOF and fails in its own error path instead of
    // blocking the wrap on a terminal nobody is watching.
    stdio: ['ignore', 'pipe', 'pipe'],
    timeout: timeoutMs,
    killSignal: 'SIGKILL',
    maxBuffer: MAX_CREDENTIAL_SOURCE_BYTES,
    windowsHide: true,
    // No shell: `command` is an executable and `args` are argv entries,
    // never a string parsed for metacharacters.
    shell: false,
  })
  const elapsedMs = Date.now() - startedAt

  if (r.error) {
    const code = (r.error as NodeJS.ErrnoException).code
    if (code === 'ETIMEDOUT') {
      throw new CredentialSourceError(
        'timeout',
        `timed out after ${timeoutMs}ms` +
          (r.signal ? ` (killed by ${r.signal})` : '') +
          (elapsedMs > timeoutMs ? `; returned after ${elapsedMs}ms` : ''),
      )
    }
    if (code === 'ENOBUFS') {
      throw new CredentialSourceError(
        'too_large',
        `produced more than ${MAX_CREDENTIAL_SOURCE_BYTES} bytes on ` +
          `stdout. A credential source must print the value alone.`,
      )
    }
    throw new CredentialSourceError(
      'spawn_failed',
      `could not be run (${code ?? 'unknown error'}): ${r.error.message}`,
    )
  }

  if (r.status !== 0) {
    const detail = firstStderrLine(r.stderr)
    throw new CredentialSourceError(
      'exit_status',
      (r.status === null ? `was killed by ${r.signal}` : `exited ${r.status}`) +
        (detail ? `: ${detail}` : ''),
    )
  }

  const value = decodeValue(r.stdout ?? Buffer.alloc(0))
  logForDebugging(
    `[credential-source] ${exePath} (${args.length} arg(s)) produced ` +
      `${value.length} chars in ${elapsedMs}ms`,
  )
  return value
}

/**
 * Resolves credential sources at most once each per session.
 *
 * The cache is the point. `getCredentialRestrictions` is reached from
 * `wrapWithSandbox` (every wrapped command), `wrapWithSandboxArgv` and
 * `getFsReadConfig` (a getter callers reach from permission checks and
 * render paths), so an uncached `source` spawns its vault CLI once per
 * wrapped command and again per getter call, measured at 6 spawns for 4
 * wraps plus 2 `getFsReadConfig()` calls in one session. For a backend
 * with a biometric or passphrase prompt that is not a slow wrap, it is an
 * unusable one: a prompt storm the operator cannot dismiss.
 *
 * Failures are cached too, and for the same reason: a cancelled biometric
 * prompt that re-asks on every subsequent wrap is the same storm with a
 * worse mood. A failed source stays failed for the session.
 *
 * Values live in process memory only, never written to disk and never
 * logged, and are dropped on teardown with the sentinel registry.
 */
export class CredentialSourceResolver {
  private readonly values = new Map<string, string>()
  private readonly failures = new Map<string, CredentialSourceError>()
  private readonly exePaths = new Map<string, string>()

  /**
   * The real value for `source`, running its command at most once per
   * session.
   *
   * @throws CredentialSourceError when the command did not produce a
   *   value: on the first attempt and, from cache, on every later one.
   */
  resolve(source: CredentialSourceConfig): string {
    const key = specKey(source)
    const cached = this.values.get(key)
    if (cached !== undefined) return cached
    const failed = this.failures.get(key)
    if (failed !== undefined) throw failed

    try {
      let exePath = this.exePaths.get(source.command)
      if (exePath === undefined) {
        exePath = resolveExecutable(source.command)
        this.exePaths.set(source.command, exePath)
      }
      const value = runCommandSource(source, exePath)
      this.values.set(key, value)
      return value
    } catch (err) {
      const e =
        err instanceof CredentialSourceError
          ? err
          : new CredentialSourceError(
              'spawn_failed',
              err instanceof Error ? err.message : String(err),
            )
      this.failures.set(key, e)
      throw e
    }
  }

  /** Number of distinct sources resolved to a value this session. */
  get size(): number {
    return this.values.size
  }

  /** Drop every resolved value and cached failure. Called on teardown. */
  clear(): void {
    this.values.clear()
    this.failures.clear()
    this.exePaths.clear()
  }
}
