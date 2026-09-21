// Filesystem restriction configs (internal structures built from permission rules)

/**
 * Read restriction config using a "deny then allow-back" pattern.
 *
 * Semantics:
 * - `undefined` = no restrictions (allow all reads)
 * - `{denyOnly: []}` = no restrictions (empty deny list = allow all reads)
 * - `{denyOnly: [...paths]}` = deny reads from these paths, allow all others
 * - `{denyOnly: [...paths], allowWithinDeny: [...paths]}` = deny reads from
 *   denyOnly paths, but re-allow reads within allowWithinDeny paths.
 *   Most-specific entry wins: an allowWithinDeny path re-opens the denied
 *   region it sits inside, while a denyOnly entry that is itself more
 *   specific than the allow it lands in — a literal nested under an
 *   allowed directory, or a glob such as `**\/.env` matching files inside
 *   one — stays denied.
 *
 * This is maximally permissive by default - only explicitly denied paths are blocked.
 */
export interface FsReadRestrictionConfig {
  denyOnly: string[]
  allowWithinDeny?: string[]
  /**
   * The `denyOnly` entries that stand for a directory a glob expansion could
   * not list. Nothing is bound back beneath one — neither an
   * `allowWithinDeny` path nor an allowed write path — because what the
   * pattern matches under such a path was never found and would come back
   * unmasked. Linux only: the other backends match globs natively.
   */
  unlistableDenyDirs?: string[]
}

/**
 * Write restriction config using an "allow-only" pattern.
 *
 * Semantics:
 * - `undefined` = no restrictions (allow all writes)
 * - `{allowOnly: [], denyWithinAllow: []}` = maximally restrictive (deny ALL writes)
 * - `{allowOnly: [...paths], denyWithinAllow: [...]}` = allow writes only to these paths,
 *   with exceptions for denyWithinAllow
 *
 * This is maximally restrictive by default - only explicitly allowed paths are writable.
 * Note: Empty `allowOnly` means NO paths are writable (unlike read's empty denyOnly).
 */
export interface FsWriteRestrictionConfig {
  allowOnly: string[]
  denyWithinAllow: string[]
}

/**
 * Credential restriction config (internal structure built from the
 * `credentials` config section).
 *
 * - `denyReadPaths`: paths to merge into the read-deny set
 *   (FsReadRestrictionConfig.denyOnly), unioned with caller-supplied denyRead.
 * - `unsetEnvVars`: environment variable names to unset inside the sandbox.
 * - `setEnvVars`: environment variables to set inside the sandbox to a
 *   sentinel value (overrides the inherited real value).
 * - `maskedFileBinds`: (realPath → fakePath) pairs for whole-file masking;
 *   the platform layer binds fakePath over realPath read-only so the
 *   sandbox reads a sentinel instead of the real bytes (Linux only —
 *   macOS degrades these to denyReadPaths).
 * - `maskedFileStoreDir`: host directory holding the fake files. The
 *   Linux layer ro-binds it over itself so the sandbox cannot tamper
 *   with the bind sources regardless of allowWrite.
 * - `degradeToDenyPaths`: the subset of `denyReadPaths` that the library
 *   resolved itself — a masked file whose extract pattern matched nothing
 *   under `onExtractNoMatch: "deny"`. Each names one file that was opened,
 *   so backends must apply it literally rather than as a pattern.
 */
export interface CredentialRestrictionConfig {
  denyReadPaths: string[]
  unsetEnvVars: string[]
  setEnvVars: Record<string, string>
  maskedFileBinds: Array<{ realPath: string; fakePath: string }>
  maskedFileStoreDir: string | undefined
  degradeToDenyPaths: string[]
}

/**
 * Network restriction config (internal structure built from permission rules).
 *
 * This uses an "allow-only" pattern (like write restrictions):
 * - `allowedHosts` = hosts that are explicitly allowed
 * - `deniedHosts` = hosts that are explicitly denied (checked first, before allowedHosts)
 *
 * Semantics:
 * - `undefined` allowedHosts = no allowlist configured
 * - `{allowedHosts: [], deniedHosts: []}` = allowlist configured with zero entries
 * - `{allowedHosts: [...], deniedHosts: [...]}` = apply allow/deny rules
 *
 * Note: Empty `allowedHosts` means no host matches an allow rule (unlike
 * read's empty denyOnly). Whether an unmatched host is denied outright
 * depends on what else may decide it: deniedHosts are checked first and deny
 * unconditionally; under `network.strictAllowlist` a host matching neither
 * list is denied there and then; otherwise it is allowed when the allow list
 * registered for the invocation the connection presents
 * (`SandboxManager.registerCommandNetworkLists`) matches it, and failing
 * that falls through to the registered SandboxAskCallback when one exists,
 * and is denied when no callback is registered. Hosts needing a hard
 * block-all regardless of callback behavior should use a `deniedHosts`
 * wildcard.
 *
 * Entries are the raw config patterns and may carry an optional `:port`
 * suffix (`api.example.com:443`, `*:22`) meaning "this rule applies only
 * to that destination port". Consumers matching hosts themselves should
 * parse the suffix (see `splitDomainPatternPort`) rather than compare the
 * whole string; a deny-all check must accept `*:<port>` as well as `*`.
 */
export interface NetworkRestrictionConfig {
  allowedHosts?: string[]
  deniedHosts?: string[]
}

export type NetworkHostPattern = {
  host: string
  port: number | undefined
}

/**
 * Asked about a host that no configured rule and no per-command allow list
 * decided (never asked under `network.strictAllowlist`). Only the value
 * `true` allows the connection. `false` denies it with the generic reason
 * "user denied". An object `{ allow: false, reason }` denies it with that
 * reason, which is what the violation line for the connection reports. Any
 * other answer, truthy or not, denies with the generic reason: a `reason` on
 * an object that does not say `allow: false` is not reported.
 *
 * The reason is sanitized before it is stored, the way the rest of a
 * violation line is: each run of control characters (line breaks and tabs
 * included) or of invisible ones (zero-width characters, the joiner among
 * them, and bidi controls) becomes one space, `<` and `>` are removed, and
 * the ends are trimmed. It is then cut to 500 UTF-16 code units, what
 * `String.prototype.length` counts. A reason with nothing left after that
 * falls back to "user denied". So write it as one line of plain text, and do
 * not rely on angle brackets around a placeholder.
 *
 * Releases up to v0.0.77 allowed on any truthy answer, so an object answer
 * returned to one of those would be read as an allow. Check
 * `SandboxManager.askCallbackDenyReason` before returning one.
 */
export type SandboxAskCallback = (
  params: NetworkHostPattern,
) => Promise<boolean | { allow: false; reason: string }>
