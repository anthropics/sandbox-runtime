import { type SandboxViolationEvent } from './macos-sandbox-utils.js'
import { type IgnoreViolationsConfig } from './sandbox-config.js'
import {
  encodeSandboxedCommand,
  SANDBOXED_COMMAND_KEY_LENGTH,
} from './sandbox-utils.js'

/**
 * In-memory tail for sandbox violations
 */
export class SandboxViolationStore {
  private violations: SandboxViolationEvent[] = []
  private totalCount = 0
  private readonly maxSize = 100
  private listeners: Set<(violations: SandboxViolationEvent[]) => void> =
    new Set()

  addViolation(violation: SandboxViolationEvent): void {
    // Every producer funnels through here (seatbelt log lines and seccomp
    // events embed raw paths, which may legally contain `<`, `>` or
    // newlines; proxy lines carry embedder-supplied reasons), so `line` is
    // reduced to one physical, tag-free line here rather than per producer.
    this.violations.push({
      ...violation,
      line: sanitizeViolationText(violation.line),
    })
    this.totalCount++
    if (this.violations.length > this.maxSize) {
      this.violations = this.violations.slice(-this.maxSize)
    }
    this.notifyListeners()
  }

  getViolations(limit?: number): SandboxViolationEvent[] {
    if (limit === undefined) {
      return [...this.violations]
    }
    return this.violations.slice(-limit)
  }

  getCount(): number {
    return this.violations.length
  }

  getTotalCount(): number {
    return this.totalCount
  }

  getViolationsForCommand(command: string): SandboxViolationEvent[] {
    const commandBase64 = encodeSandboxedCommand(command)
    return this.violations.filter(v => v.encodedCommand === commandBase64)
  }

  clear(): void {
    this.violations = []
    // Don't reset totalCount when clearing
    this.notifyListeners()
  }

  subscribe(
    listener: (violations: SandboxViolationEvent[]) => void,
  ): () => void {
    this.listeners.add(listener)
    listener(this.getViolations())
    return () => {
      this.listeners.delete(listener)
    }
  }

  private notifyListeners(): void {
    // Always notify with all violations so listeners can track the full count
    const violations = this.getViolations()
    this.listeners.forEach(listener => listener(violations))
  }
}

/**
 * Whether a violation should be suppressed by the user's `ignoreViolations`
 * config: `'*'` patterns apply to every command, other keys are matched as
 * substrings of the (decoded) command. `line` is the violation text the
 * patterns are substring-matched against. Shared by every violation
 * producer (macOS log monitor, Linux seccomp observer, proxy denies) so a
 * pattern suppresses the same event regardless of which one saw it.
 */
export function shouldIgnoreViolation(
  line: string,
  command: string | undefined,
  ignoreViolations: IgnoreViolationsConfig | undefined,
): boolean {
  if (!ignoreViolations) {
    return false
  }
  const wildcardPatterns = ignoreViolations['*'] ?? []
  if (wildcardPatterns.some(p => line.includes(p))) {
    return true
  }
  if (command === undefined) {
    return false
  }
  for (const [pattern, patterns] of Object.entries(ignoreViolations)) {
    if (
      pattern !== '*' &&
      command.includes(pattern) &&
      patterns.some(p => line.includes(p))
    ) {
      return true
    }
  }
  return false
}

/**
 * Four kinds of code point that make stored text render as something other
 * than what it says: the control characters (C0, DEL and C1 — the latter
 * covers the 8-bit CSI/OSC introducers); the U+2028/U+2029 line terminators;
 * the bidi controls (embedding, override, isolate, and U+061C); and the
 * zero-width invisibles, the Tags block among them. Not a complete account
 * of what Unicode can be made to do to a renderer.
 */
/* eslint-disable no-control-regex -- stripping control chars is the point */
const DISPLAY_UNSAFE_CHARACTERS =
  /[\x00-\x1f\x7f-\x9f\u00ad\u061c\u200b-\u200f\u2028\u2029\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff\u{e0000}-\u{e007f}]+/gu
/* eslint-enable no-control-regex */

/**
 * Collapse those to spaces and drop the angle brackets that would close an
 * embedder's <sandbox_violations> envelope early, so that what is stored is
 * what is displayed. Shared by the store (for `line`) and by the
 * unregistered-key fallback, so the two carry the same guarantee.
 */
function sanitizeViolationText(text: string): string {
  return text
    .replace(DISPLAY_UNSAFE_CHARACTERS, ' ')
    .replace(/[<>]/g, '')
    .trim()
}

/**
 * What a violation reports for an attribution key no invocation registered.
 * Such a key arrived over a carrier the sandboxed process can write, so it
 * is bytes rather than text: sanitize it and cut it to the length a key this
 * process minted can have — the carriers are bounded far more loosely than
 * that (an HTTP proxy header budget is kilobytes).
 */
export function sanitizeUnregisteredCommandKey(decodedKey: string): string {
  return cutBetweenCharacters(
    sanitizeViolationText(decodedKey),
    SANDBOXED_COMMAND_KEY_LENGTH,
  )
}

/**
 * How much of a denial reason supplied by the ask callback a violation line
 * carries, in UTF-16 code units (what `String.prototype.length` counts, so a
 * character outside the Basic Multilingual Plane counts as two). The reason
 * is prose for whoever reads the violation, a model included: a few sentences
 * fit, a document does not.
 */
export const MAX_DENIAL_REASON_LENGTH = 500

/**
 * A denial reason the ask callback supplied, as a violation line may carry
 * it: sanitized like the rest of the line, and cut so that one answer cannot
 * flood the text a model reads. The store sanitizes the whole line again at
 * ingestion; doing it here first means the cut counts what is displayed. The
 * cut can land just after a space, and the reason sits inside parentheses
 * where the store's own trim of the line's ends does not reach, so the end is
 * trimmed again here.
 */
export function sanitizeDenialReason(reason: string): string {
  return cutBetweenCharacters(
    sanitizeViolationText(reason),
    MAX_DENIAL_REASON_LENGTH,
  ).trimEnd()
}

function cutBetweenCharacters(text: string, length: number): string {
  const cut = text.slice(0, length)
  // A cut by UTF-16 code unit can land between a surrogate pair; the lone
  // high surrogate left behind renders as a replacement character.
  return /[\uD800-\uDBFF]$/.test(cut) ? cut.slice(0, -1) : cut
}
