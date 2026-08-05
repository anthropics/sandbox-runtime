import { type SandboxViolationEvent } from './macos-sandbox-utils.js'
import { type IgnoreViolationsConfig } from './sandbox-config.js'
import { encodeSandboxedCommand } from './sandbox-utils.js'

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
    this.violations.push(violation)
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
