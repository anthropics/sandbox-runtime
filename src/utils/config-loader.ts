import * as fs from 'fs'
import {
  SandboxRuntimeConfigSchema,
  type SandboxRuntimeConfig,
} from '../sandbox/sandbox-config.js'

/**
 * Parse and validate sandbox configuration from a string
 * Used for parsing config from control fd (JSON lines protocol)
 */
export function loadConfigFromString(
  content: string,
): SandboxRuntimeConfig | null {
  if (!content.trim()) {
    return null
  }

  try {
    const parsed = JSON.parse(content)
    const result = SandboxRuntimeConfigSchema.safeParse(parsed)
    if (!result.success) {
      return null
    }
    return result.data
  } catch {
    return null
  }
}

/**
 * Why a settings file did not yield a config. Only `missing` is a reason to
 * run with the built-in defaults; the rest name a file whose rules would be
 * silently dropped by doing so. `reason` is a printable sentence naming the
 * path — key paths and validator messages, never the file's values.
 */
export type LoadConfigResult =
  | { kind: 'ok'; config: SandboxRuntimeConfig }
  | { kind: 'missing' }
  | { kind: 'empty' }
  | { kind: 'unreadable'; reason: string }
  | { kind: 'invalid'; reason: string }

/**
 * Load and validate sandbox configuration from a file.
 */
export function loadConfig(filePath: string): LoadConfigResult {
  let content: string
  try {
    // Read first and classify the failure: an existence check ahead of it
    // would call a file that is there but unsearchable, or a $HOME that is
    // a file, "missing" — the one answer that falls back to the defaults.
    content = fs.readFileSync(filePath, 'utf-8')
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code
    if (code === 'ENOENT') {
      return { kind: 'missing' }
    }
    return {
      kind: 'unreadable',
      reason: `${filePath} could not be read (${code ?? String(error)}).`,
    }
  }

  if (content.trim() === '') {
    return { kind: 'empty' }
  }

  let parsed: unknown
  try {
    parsed = JSON.parse(content)
  } catch (error) {
    return {
      kind: 'invalid',
      reason: `${filePath} is not valid JSON: ${(error as Error).message}`,
    }
  }

  const result = SandboxRuntimeConfigSchema.safeParse(parsed)
  if (!result.success) {
    const issues = result.error.issues
      .map(issue => `${issue.path.join('.') || '(root)'}: ${issue.message}`)
      .join('; ')
    return {
      kind: 'invalid',
      reason: `${filePath} does not hold a valid config — ${issues}`,
    }
  }

  return { kind: 'ok', config: result.data }
}
