import * as fs from 'fs'
import { z } from 'zod/v3'
import {
  SandboxRuntimeConfigSchema,
  type SandboxRuntimeConfig,
} from '../sandbox/sandbox-config.js'

/**
 * LTIC fork: surface unrecognized settings keys instead of silently
 * stripping them.
 *
 * Zod's default object behavior drops unknown keys, so a mistyped key
 * (`allowAllDomainz`) or a key from a different srt build (fork keys like
 * `network.allowAllDomains` on stock srt, or newer upstream keys on an
 * older build) validates "successfully" while the intended restriction or
 * grant is silently lost. A network config that looks default-allow can
 * actually be deny-all. These helpers walk the parsed JSON against the
 * schema and name every key the validator does not know, so the mismatch
 * is loud at startup rather than discovered from sandbox behavior.
 */
function unwrapSchema(schema: z.ZodTypeAny): z.ZodTypeAny {
  for (;;) {
    if (schema instanceof z.ZodOptional || schema instanceof z.ZodNullable) {
      schema = schema.unwrap() as z.ZodTypeAny
    } else if (schema instanceof z.ZodDefault) {
      schema = schema.removeDefault() as z.ZodTypeAny
    } else if (schema instanceof z.ZodEffects) {
      schema = schema.innerType() as z.ZodTypeAny
    } else {
      return schema
    }
  }
}

function collectUnrecognized(
  value: unknown,
  schema: z.ZodTypeAny,
  path: string,
  out: string[],
): void {
  const s = unwrapSchema(schema)
  if (
    s instanceof z.ZodObject &&
    value !== null &&
    typeof value === 'object' &&
    !Array.isArray(value)
  ) {
    const shape = s.shape as Record<string, z.ZodTypeAny>
    for (const [key, child] of Object.entries(value)) {
      const childPath = path ? `${path}.${key}` : key
      const childSchema = shape[key]
      if (childSchema) {
        collectUnrecognized(child, childSchema, childPath, out)
      } else {
        out.push(childPath)
      }
    }
  } else if (s instanceof z.ZodArray && Array.isArray(value)) {
    for (const [i, item] of value.entries()) {
      collectUnrecognized(item, s.element as z.ZodTypeAny, `${path}[${i}]`, out)
    }
  }
  // Unions, records, and primitives: keys can't be attributed to a single
  // shape, so they are left to the schema itself (the union members that
  // need it are .strict() and fail the parse outright).
}

/**
 * Names every key in a parsed settings object that the config schema does
 * not recognize (dot-separated paths, e.g. "network.allowAllDomainz").
 * Exported for tests.
 */
export function collectUnrecognizedConfigKeys(parsed: unknown): string[] {
  const out: string[] = []
  collectUnrecognized(parsed, SandboxRuntimeConfigSchema, '', out)
  return out
}

function warnUnrecognizedKeys(parsed: unknown, source: string): void {
  const unknown = collectUnrecognizedConfigKeys(parsed)
  if (unknown.length === 0) return
  console.error(
    `[sandbox-runtime] WARNING: unrecognized settings key(s) in ${source}: ` +
      `${unknown.join(', ')}. Unrecognized keys are IGNORED — the ` +
      'restriction or grant they were meant to express is not in effect. ' +
      'Check for typos or an srt build mismatch (`srt --version`).',
  )
}

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
    warnUnrecognizedKeys(parsed, 'control-fd config update')
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

  warnUnrecognizedKeys(parsed, filePath)

  return { kind: 'ok', config: result.data }
}
