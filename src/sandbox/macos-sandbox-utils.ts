import { quote } from '../utils/shell-quote.js'
import { spawn } from 'child_process'
import * as path from 'path'
import { logForDebugging } from '../utils/debug.js'
import { whichSync } from '../utils/which.js'
import { buildJavaToolOptions } from './java-proxy-agent.js'
import {
  normalizePathForSandbox,
  generateProxyEnvVars,
  buildPosixGitSafeDirEnv,
  encodeSandboxedCommand,
  decodeSandboxedCommand,
  containsGlobChars,
  globToRegex,
  DANGEROUS_FILES,
  getDangerousDirectories,
} from './sandbox-utils.js'
import { shouldIgnoreViolation } from './sandbox-violation-store.js'

import type {
  FsReadRestrictionConfig,
  FsWriteRestrictionConfig,
} from './sandbox-schemas.js'
import type { IgnoreViolationsConfig } from './sandbox-config.js'

export interface MacOSSandboxParams {
  command: string
  /**
   * Attribution key for this invocation: the string encoded into the
   * seatbelt log tag and the proxy username, and reported as the
   * violation's `command`. Defaults to `command`. Set it when the string
   * you execute differs from the one you will later look violations up by
   * (e.g. you wrap an assembled `source snapshot && eval '<cmd>'` but query
   * `getViolationsForCommand('<cmd>')`).
   */
  commandId?: string
  needsNetworkRestriction: boolean
  httpProxyPort?: number
  socksProxyPort?: number
  /** Per-session proxy auth token; embedded in proxy env URLs. */
  proxyAuthToken?: string
  /** Path to the TLS-termination CA cert; injected as trust env vars. */
  caCertPath?: string
  /** Path to the JVM proxy agent jar; injected via JAVA_TOOL_OPTIONS. */
  javaAgentJarPath?: string
  allowUnixSockets?: string[]
  allowAllUnixSockets?: boolean
  allowLocalBinding?: boolean
  allowMachLookup?: string[]
  readConfig: FsReadRestrictionConfig | undefined
  writeConfig: FsWriteRestrictionConfig | undefined
  /** Environment variable names to unset for the sandboxed child (env -u) */
  unsetEnvVars?: string[]
  /** Environment variables to set for the sandboxed child (env NAME=VALUE) */
  setEnvVars?: Record<string, string>
  /**
   * Whole-file credential masks. SBPL cannot redirect reads, so on macOS
   * these degrade to read-deny on realPath until the DYLD interposer
   * lands. fakePath is unused here.
   */
  maskedFileBinds?: Array<{ realPath: string; fakePath: string }>
  ignoreViolations?: IgnoreViolationsConfig | undefined
  allowPty?: boolean
  allowGitConfig?: boolean
  /**
   * Directories to emit as `safe.directory` via `GIT_CONFIG_*` env
   * vars — see {@link buildPosixGitSafeDirEnv}.
   */
  gitSafeDirectories?: readonly string[]
  enableWeakerNetworkIsolation?: boolean
  allowAppleEvents?: boolean
  binShell?: string
}

/**
 * Get mandatory deny patterns as glob patterns (no filesystem scanning).
 * macOS sandbox profile supports regex/glob matching directly via globToRegex().
 */
export function macGetMandatoryDenyPatterns(allowGitConfig = false): string[] {
  const cwd = process.cwd()
  const denyPaths: string[] = []

  // Dangerous files - static paths in CWD + glob patterns for subtree
  for (const fileName of DANGEROUS_FILES) {
    denyPaths.push(path.resolve(cwd, fileName))
    denyPaths.push(`**/${fileName}`)
  }

  // Dangerous directories
  for (const dirName of getDangerousDirectories()) {
    denyPaths.push(path.resolve(cwd, dirName))
    denyPaths.push(`**/${dirName}/**`)
  }

  // Git hooks are always blocked for security
  denyPaths.push(path.resolve(cwd, '.git/hooks'))
  denyPaths.push('**/.git/hooks/**')

  // Git config - conditionally blocked based on allowGitConfig setting
  if (!allowGitConfig) {
    denyPaths.push(path.resolve(cwd, '.git/config'))
    denyPaths.push('**/.git/config')
  }

  return [...new Set(denyPaths)]
}

export interface SandboxViolationEvent {
  line: string
  command?: string
  encodedCommand?: string
  timestamp: Date
}

export type SandboxViolationCallback = (
  violation: SandboxViolationEvent,
) => void

const sessionSuffix = `_${Math.random().toString(36).slice(2, 11)}_SBX`

/**
 * Generate a unique log tag for sandbox monitoring
 * @param command - The command being executed (will be base64 encoded)
 */
function generateLogTag(command: string): string {
  const encodedCommand = encodeSandboxedCommand(command)
  return `CMD64_${encodedCommand}_END_${sessionSuffix}`
}

/**
 * SBPL path filter for a normalized path: `regex` for glob patterns,
 * `subpath` (the path and everything beneath it) otherwise.
 */
function pathFilter(normalizedPath: string): string {
  return containsGlobChars(normalizedPath)
    ? `(regex ${escapePath(globToRegex(normalizedPath))})`
    : `(subpath ${escapePath(normalizedPath)})`
}

/**
 * Regex for a glob used in a DENY rule: {@link globToRegex} plus an optional
 * `/…` tail, so the deny covers everything beneath each match the way
 * `subpath` does for literals. Callers strip a trailing `/**` before the
 * pattern gets here (removeTrailingGlobSuffix), so `**\/secrets/**` arrives
 * as `**\/secrets` and, matched exactly, would deny only the directory
 * vnode while `secrets/key` stayed readable. This is what the Linux backend
 * already does (a deny masks the whole subtree). Only ever widens a deny.
 */
function denyGlobRegex(normalizedGlob: string): string {
  // globToRegex() always returns '^…$'.
  return globToRegex(normalizedGlob).slice(0, -1) + '(/.*)?$'
}

/** {@link pathFilter} for deny rules: globs get {@link denyGlobRegex}. */
function denyPathFilter(normalizedPath: string): string {
  return containsGlobChars(normalizedPath)
    ? `(regex ${escapePath(denyGlobRegex(normalizedPath))})`
    : `(subpath ${escapePath(normalizedPath)})`
}

/**
 * A concrete path shaped like the ones a glob matches (every glob segment
 * replaced by a literal `x`), used to test whether a deny regex covers the
 * region a glob allow / glob write root points at.
 */
function globSamplePath(normalizedGlob: string): string {
  return normalizedGlob.replace(/\[[^\]]*\]|[*?]+/g, 'x')
}

/**
 * Narrow `filter` so it no longer matches anything covered by `carveOuts`
 * (each an SBPL path filter). Used to re-emit a deny after the allows it
 * would otherwise clobber, minus exactly the allow entries it overlaps —
 * a deny minus carve-outs never matches anything the un-carved deny did
 * not, so this stays deny-only.
 */
function carveFilter(filter: string, carveOuts: readonly string[]): string {
  // Dedupe: the project dir is routinely both an allowRead entry and a
  // write root.
  const unique = [...new Set(carveOuts)]
  if (unique.length === 0) return filter
  const nots = unique.map(c => `(require-not ${c})`).join(' ')
  return `(require-all ${filter} ${nots})`
}

/** One denyOnly / allowWithinDeny / allowWrite entry after normalization. */
interface PathEntry {
  path: string
  glob: boolean
}

function toPathEntry(pathPattern: string): PathEntry {
  const normalized = normalizePathForSandbox(pathPattern)
  return { path: normalized, glob: containsGlobChars(normalized) }
}

/** Does a subtree-extended deny glob regex cover `entry`'s region? */
function denyGlobCovers(denyRegex: RegExp, entry: PathEntry): boolean {
  return denyRegex.test(entry.glob ? globSamplePath(entry.path) : entry.path)
}

/** Is `entry`'s region strictly inside the literal directory `dir`? */
function isStrictlyUnder(entry: PathEntry, dir: string): boolean {
  const probe = entry.glob ? globSamplePath(entry.path) : entry.path
  return probe.startsWith(dir === '/' ? '/' : dir + '/') && probe !== dir
}

/**
 * The read config with every entry normalized once, shared by the read
 * section ({@link generateReadRules}) and the trailing unlink re-denies
 * ({@link generateReadDenyUnlinkRules}) so both reason about the same
 * spellings.
 */
interface ResolvedReadConfig {
  denies: PathEntry[]
  allows: PathEntry[]
  writeRoots: PathEntry[]
}

function resolveReadConfig(
  config: FsReadRestrictionConfig,
  writeAllowPaths: readonly string[] | undefined,
): ResolvedReadConfig {
  return {
    denies: (config.denyOnly || []).map(toPathEntry),
    // Non-glob spellings arrive slash-free from normalizePathForSandbox —
    // the nested-deny re-emit matches by `path + '/'` prefix, which a
    // preserved trailing slash would defeat ('<dir>//').
    allows: (config.allowWithinDeny || []).map(toPathEntry),
    writeRoots: (writeAllowPaths || []).map(toPathEntry),
  }
}

/**
 * The denies that must land AFTER the allowWithinDeny allows, because
 * Seatbelt is last-match-wins and the allow block would otherwise re-open
 * them. Each comes back as the SBPL filter to emit:
 *
 * - A literal deny nested inside a literal allow (`~/proj/secrets` under
 *   `~/proj`), re-emitted as-is.
 * - Every glob deny, minus (`require-not`) each allow entry the glob's own
 *   regex covers. A leaf-shaped glob (`**\/.env`, `/**\/*.key`) covers no
 *   directory allow, so it comes back whole and beats the directory allows
 *   it lands inside — the fix for globs being silently re-allowed. A
 *   region-shaped glob (`~/**\/*` with allowRead carve-outs) covers its
 *   carve-outs, so they are subtracted and its behavior is unchanged. A
 *   glob that covers a specific FILE allow (a user carve-out, or the
 *   TLS-termination trust bundle sandbox-manager adds to allowWithinDeny,
 *   which a `/**\/*.crt` deny would otherwise sever) keeps that one file
 *   readable without any allow being emitted after the denies.
 *
 * Every filter here is a deny or a narrower deny: nothing this function
 * produces can make a path readable that is not readable today. Keep it
 * that way — the moment an `(allow file-read* …)` is appended after this
 * block, every deny above it has to be re-audited against it.
 *
 * The coverage test (denyGlobCovers) fails closed by construction: every
 * carve-out is an entry the allow block above already allows, so an
 * unnecessary carve-out only reproduces today's behavior for that entry,
 * and a missed one (e.g. a glob allow whose sample path the deny regex
 * happens not to match) leaves the deny wider — never opens anything.
 */
function lateReadDenyFilters(resolved: ResolvedReadConfig): {
  filters: string[]
  /** Some emitted glob deny matches "/" itself (a `/*`-shaped pattern). */
  coversRoot: boolean
} {
  const filters: string[] = []
  let coversRoot = false
  const literalAllowDirs = resolved.allows.filter(a => !a.glob).map(a => a.path)
  for (const deny of resolved.denies) {
    if (!deny.glob) {
      if (literalAllowDirs.some(a => deny.path.startsWith(a + '/'))) {
        filters.push(denyPathFilter(deny.path))
      }
      continue
    }
    const denyRegex = new RegExp(denyGlobRegex(deny.path))
    if (denyRegex.test('/')) coversRoot = true
    const carveOuts = resolved.allows
      .filter(a => denyGlobCovers(denyRegex, a))
      .map(a => pathFilter(a.path))
    filters.push(carveFilter(denyPathFilter(deny.path), carveOuts))
  }
  return { filters, coversRoot }
}

/**
 * Directory that bounds where a glob can match: its static prefix, or "/"
 * for a root-anchored pattern like `/**\/*.key`.
 */
function globBaseDir(normalizedGlob: string): string {
  const staticPrefix = normalizedGlob.split(/[*?[\]]/)[0]
  if (!staticPrefix || staticPrefix === '/') return '/'
  return staticPrefix.endsWith('/')
    ? staticPrefix.slice(0, -1)
    : path.dirname(staticPrefix)
}

/**
 * Trailing `(deny file-write-unlink …)` for read-denied paths that the
 * write section may have re-opened. Emitted at the very end of the profile.
 *
 * generateReadRules() blocks moving a read-denied path (and its ancestors)
 * out from under its deny, but then re-allows file-write-unlink /
 * file-write-create for every allowWrite root so `rm` works inside the
 * project (#171). Any read-denied path INSIDE a write root is therefore
 * movable again: `mv .env x; cat x`, or `mv secrets s2; cat s2/key`,
 * defeats both glob and literal denies. This re-denies unlink (rename
 * source / rm) — not create, so new files can still be made; a new `.env`
 * is still read-denied by name — for:
 *
 * - every glob deny whose region intersects a write root, minus the allow
 *   entries and write roots the glob itself covers (a region glob like
 *   `~/**\/*` must not re-block `rm` inside carve-outs it was already
 *   subtracting; a leaf glob like `**\/.env` covers none of them);
 * - every literal deny strictly below a write root, minus any allow entry
 *   or write root nested strictly inside it;
 * - the literal ancestor directories of each of those (for a glob, its
 *   static-prefix directory and that directory's ancestors) that sit
 *   strictly below a write root — the directory vnodes only, so `rm` of
 *   unrelated siblings still works but the enclosing directory cannot be
 *   renamed out from under the deny. Ancestors at or above a write root
 *   are left alone: the deny above already covers them, and re-denying the
 *   root itself would block unrelated `rm`s.
 *
 * A literal deny not below any write root needs nothing: the read
 * section's move-blocking deny still holds for it. Deny-only, like the
 * rest of this file's read handling.
 */
function generateReadDenyUnlinkRules(
  resolved: ResolvedReadConfig,
  logTag: string,
): string[] {
  const { denies, allows, writeRoots } = resolved
  if (writeRoots.length === 0) return []

  const writeRootRegexes = writeRoots
    .filter(w => w.glob)
    .map(w => new RegExp(globToRegex(w.path)))
  const literalWriteRoots = writeRoots.filter(w => !w.glob).map(w => w.path)
  const strictlyBelowWriteRoot = (p: string): boolean =>
    literalWriteRoots.some(w => isStrictlyUnder({ path: p, glob: false }, w)) ||
    writeRootRegexes.some(re => re.test(p))
  const carveOutsInside = (dir: string): string[] =>
    [...allows, ...writeRoots]
      .filter(e => isStrictlyUnder(e, dir))
      .map(e => pathFilter(e.path))

  const filters = new Set<string>()
  const protectDirs = (dirs: string[]): void => {
    for (const dir of dirs) {
      if (strictlyBelowWriteRoot(dir)) {
        filters.add(`(literal ${escapePath(dir)})`)
      }
    }
  }

  for (const deny of denies) {
    if (deny.glob) {
      const baseDir = globBaseDir(deny.path)
      const intersectsWriteRoot =
        writeRootRegexes.length > 0 ||
        literalWriteRoots.some(
          w =>
            baseDir === w ||
            isStrictlyUnder({ path: baseDir, glob: false }, w) ||
            isStrictlyUnder({ path: w, glob: false }, baseDir),
        )
      if (!intersectsWriteRoot) continue
      const denyRegex = new RegExp(denyGlobRegex(deny.path))
      const carveOuts = [...allows, ...writeRoots]
        .filter(e => denyGlobCovers(denyRegex, e))
        .map(e => pathFilter(e.path))
      filters.add(carveFilter(denyPathFilter(deny.path), carveOuts))
      if (baseDir !== '/') {
        protectDirs([baseDir, ...getAncestorDirectories(baseDir)])
      }
    } else {
      if (!strictlyBelowWriteRoot(deny.path)) continue
      filters.add(
        carveFilter(denyPathFilter(deny.path), carveOutsInside(deny.path)),
      )
      protectDirs(getAncestorDirectories(deny.path))
    }
  }

  return renderRule('deny', ['file-write-unlink'], filters, logTag)
}

/**
 * Render one SBPL rule applying `action` for each of `operations` to any
 * path matching one of `filters`, reporting `logTag` on a match. Emits
 * nothing for an empty filter set: a rule with no filter would match every
 * path.
 */
function renderRule(
  action: 'allow' | 'deny',
  operations: readonly string[],
  filters: ReadonlySet<string>,
  logTag: string,
): string[] {
  if (filters.size === 0) return []
  return [
    `(${action} ${operations.join(' ')}`,
    ...[...filters].map(f => `  ${f}`),
    `  (with message "${logTag}"))`,
  ]
}

/**
 * Get all ancestor directories for a path, up to (but not including) root
 * Example: /private/tmp/test/file.txt -> ["/private/tmp/test", "/private/tmp", "/private"]
 */
function getAncestorDirectories(pathStr: string): string[] {
  const ancestors: string[] = []
  let currentPath = path.dirname(pathStr)

  // Walk up the directory tree until we reach root
  while (currentPath !== '/' && currentPath !== '.') {
    ancestors.push(currentPath)
    const parentPath = path.dirname(currentPath)
    // Break if we've reached the top (path.dirname returns the same path for root)
    if (parentPath === currentPath) {
      break
    }
    currentPath = parentPath
  }

  return ancestors
}

/**
 * sandbox-exec rejects a string literal longer than 1025 bytes ("Error
 * reading string"); the regexes built below stay well under that, since
 * one oversized string invalidates the whole profile.
 */
const SBPL_STRING_MAX_BYTES = 900

/**
 * Below this many names, one regex is not shorter than the literal filters
 * it would replace.
 */
const MIN_DENY_GROUP_SIZE = 4

/** Escape a literal path component for use inside a regex. */
function escapeRegexLiteral(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

/**
 * Literal deny paths of the shape `<dir>/<name>/<leaf>` that share `dir` and
 * the same set of leaves, e.g. git's per-worktree registry
 * `<gitdir>/worktrees/<name>/{commondir,config.worktree}` for every
 * registered worktree.
 */
interface LiteralDenyGroup {
  dir: string
  names: string[]
  leaves: string[]
}

/**
 * Fold literal deny paths into {@link LiteralDenyGroup}s. Each group renders
 * as one anchored regex per chunk of names instead of one `subpath` filter
 * per path, so a directory with many same-shaped children costs bytes and
 * profile compile time proportional to the names, not to the repeated
 * absolute prefix (sandbox-exec compiles a few thousand path filters in
 * seconds; a few dozen regexes in milliseconds). Globs, paths that do not
 * fit a group of at least {@link MIN_DENY_GROUP_SIZE} names, and names too
 * long for one regex are returned in `rest` unchanged.
 */
function groupLiteralDenyPaths(normalizedPaths: readonly string[]): {
  groups: LiteralDenyGroup[]
  rest: string[]
} {
  const byDir = new Map<string, Map<string, Set<string>>>()
  for (const p of normalizedPaths) {
    if (containsGlobChars(p)) continue
    const parent = path.dirname(p)
    const dir = path.dirname(parent)
    if (dir === parent || parent === p || dir === '/') continue
    let names = byDir.get(dir)
    if (!names) {
      names = new Map()
      byDir.set(dir, names)
    }
    const name = path.basename(parent)
    let leaves = names.get(name)
    if (!leaves) {
      leaves = new Set()
      names.set(name, leaves)
    }
    leaves.add(path.basename(p))
  }
  const grouped = new Set<string>()
  const groups: LiteralDenyGroup[] = []
  for (const [dir, names] of byDir) {
    const bySignature = new Map<string, LiteralDenyGroup>()
    for (const [name, leafSet] of names) {
      const leaves = [...leafSet].sort()
      const signature = leaves.join('\0')
      let group = bySignature.get(signature)
      if (!group) {
        group = { dir, names: [], leaves }
        bySignature.set(signature, group)
      }
      group.names.push(name)
    }
    for (const group of bySignature.values()) {
      const fixedLength =
        regexLength(groupRegexPrefix(group)) + regexLength(groupDenyTail(group))
      group.names = group.names.filter(
        name =>
          fixedLength + regexLength(escapeRegexLiteral(name)) <=
          SBPL_STRING_MAX_BYTES,
      )
      if (group.names.length < MIN_DENY_GROUP_SIZE) continue
      groups.push(group)
      for (const name of group.names) {
        for (const leaf of group.leaves) {
          grouped.add(path.join(dir, name, leaf))
        }
      }
    }
  }
  return {
    groups,
    rest: normalizedPaths.filter(p => !grouped.has(p)),
  }
}

/** Bytes a regex fragment occupies inside an SBPL string literal. */
function regexLength(fragment: string): number {
  return Buffer.byteLength(escapePath(fragment)) - 2
}

function groupRegexPrefix(group: LiteralDenyGroup): string {
  return `^${escapeRegexLiteral(group.dir)}/(`
}

function groupDenyTail(group: LiteralDenyGroup): string {
  return `)/(${group.leaves.map(escapeRegexLiteral).join('|')})(/.*)?$`
}

/**
 * Regex filters for a {@link LiteralDenyGroup}, chunked so no regex exceeds
 * {@link SBPL_STRING_MAX_BYTES}. `deny` matches each `<dir>/<name>/<leaf>`
 * and everything beneath it (the `subpath` semantics of a literal deny);
 * `pins` match each `<dir>/<name>` directory itself, the move-blocking
 * literal a per-path deny would have added for its parent.
 */
function literalDenyGroupFilters(group: LiteralDenyGroup): {
  deny: string[]
  pins: string[]
} {
  const prefix = groupRegexPrefix(group)
  const denyTail = groupDenyTail(group)
  const pinTail = ')$'
  const fixedLength = regexLength(prefix) + regexLength(denyTail)
  const chunks: string[][] = []
  let chunk: string[] = []
  let chunkLength = 0
  for (const name of group.names.map(escapeRegexLiteral)) {
    const nameLength = regexLength(name) + (chunk.length === 0 ? 0 : 1)
    if (
      chunk.length > 0 &&
      fixedLength + chunkLength + nameLength > SBPL_STRING_MAX_BYTES
    ) {
      chunks.push(chunk)
      chunk = []
      chunkLength = 0
    }
    chunk.push(name)
    chunkLength += chunk.length === 1 ? regexLength(name) : nameLength
  }
  chunks.push(chunk)
  const alternations = chunks.map(names => names.join('|'))
  return {
    deny: alternations.map(
      names => `(regex ${escapePath(prefix + names + denyTail)})`,
    ),
    pins: alternations.map(
      names => `(regex ${escapePath(prefix + names + pinTail)})`,
    ),
  }
}

/**
 * Generate deny rules for file movement (file-write-unlink) and creation
 * (file-write-create) to protect paths. This prevents bypassing read or write
 * restrictions by moving files/directories, and prevents replacing a
 * not-yet-existing protected path (or one of its ancestors) with an
 * attacker-controlled symlink.
 *
 * Emitted as a single rule whose filters are the union over all patterns:
 * protected paths commonly share most of their ancestors, and each distinct
 * filter both costs argv bytes and adds to sandbox-exec's compile time.
 *
 * @param pathPatterns - Array of path patterns to protect (can include globs)
 * @param logTag - Log tag for sandbox violations
 * @returns Array of sandbox profile rule lines
 */
function generateMoveBlockingRules(
  pathPatterns: string[],
  logTag: string,
): string[] {
  return renderRule(
    'deny',
    ['file-write-unlink', 'file-write-create'],
    moveBlockingFilters(pathPatterns.map(normalizePathForSandbox)),
    logTag,
  )
}

/** The filters {@link generateMoveBlockingRules} emits, for normalized paths. */
function moveBlockingFilters(normalizedPaths: readonly string[]): Set<string> {
  const filters = new Set<string>()

  for (const normalizedPath of normalizedPaths) {
    // Block moving/renaming the denied path itself (or files matching the
    // pattern, and anything beneath them)
    filters.add(denyPathFilter(normalizedPath))

    let baseDir: string
    if (containsGlobChars(normalizedPath)) {
      // For glob patterns, block moves of the directory containing the
      // pattern's static prefix, then of its ancestors
      baseDir = globBaseDir(normalizedPath)
      if (baseDir === '/') continue
      filters.add(`(literal ${escapePath(baseDir)})`)
    } else {
      baseDir = normalizedPath
    }

    // Block moves of ancestor directories
    for (const ancestorDir of getAncestorDirectories(baseDir)) {
      filters.add(`(literal ${escapePath(ancestorDir)})`)
    }
  }

  return filters
}

/**
 * Generate filesystem read rules for sandbox profile
 *
 * Supports two layers:
 * 1. denyOnly: deny reads from these paths (broad regions like /Users)
 * 2. allowWithinDeny: re-allow reads within denied regions (like CWD)
 *    allowWithinDeny takes precedence over denyOnly.
 *
 * In Seatbelt profiles, later rules take precedence, so we emit:
 *   (allow file-read*)        ← default: allow everything
 *   (deny file-read* ...)     ← deny everything in denyOnly
 *   (allow file-read* ...)    ← re-allow allowWithinDeny
 *   (deny file-read* ...)     ← re-emit the denies the allows would clobber:
 *                               literal denies nested in an allow, and every
 *                               glob deny minus the allows it covers
 *                               (see lateReadDenyFilters)
 *   (allow file-read* (literal "/"))  ← only if a deny covers "/" itself
 *
 * REVIEW INVARIANT: after the allowWithinDeny block, this function only
 * ever adds denies (or narrows one with require-not). The one exception is
 * the pre-existing literal-"/" re-allow, which matches exactly one vnode.
 * Do not append another `(allow file-read* …)` layer here — every deny
 * above it would then need re-auditing for re-open bypasses.
 */
function generateReadRules(
  resolved: ResolvedReadConfig | undefined,
  logTag: string,
): string[] {
  if (!resolved) {
    return [`(allow file-read*)`]
  }

  const rules: string[] = []

  // Start by allowing everything
  rules.push(`(allow file-read*)`)

  // Then deny specific paths
  const deniesRoot = resolved.denies.some(d => d.path === '/')
  const denyFilters = new Set(resolved.denies.map(d => denyPathFilter(d.path)))
  rules.push(...renderRule('deny', ['file-read*'], denyFilters, logTag))

  // Re-allow specific paths within denied regions (allowWithinDeny takes precedence)
  const allowFilters = new Set(resolved.allows.map(a => pathFilter(a.path)))
  rules.push(...renderRule('allow', ['file-read*'], allowFilters, logTag))

  // Denies the allow block would otherwise win over (last-match-wins) land
  // here, after it. Must stay ahead of the file-read-metadata allow below.
  const late = lateReadDenyFilters(resolved)
  rules.push(
    ...renderRule('deny', ['file-read*'], new Set(late.filters), logTag),
  )

  // (subpath "/") — or a re-emitted `/*`-shaped glob — denies the root inode
  // itself; no allowWithinDeny entry covers "/", so dyld aborts before exec
  // (#190). Re-allow the literal root, after the re-emitted denies so a
  // glob landing later can't take it away again. This exposes `ls /` dirent
  // names but no subtree contents.
  if (deniesRoot || late.coversRoot) {
    rules.push(`(allow file-read* (literal "/"))`)
  }

  // Allow stat/lstat on all directories so that realpath() can traverse
  // path components within denied regions. Without this, C realpath() fails
  // when resolving symlinks because it needs to lstat every intermediate
  // directory (e.g. /Users, /Users/chris) even if only a subdirectory like
  // ~/.local is in allowWithinDeny. This only allows metadata reads on
  // directories — not listing contents (readdir) or reading files.
  if (resolved.denies.length > 0) {
    rules.push(`(allow file-read-metadata`, `  (vnode-type DIRECTORY))`)
  }

  // Block file movement to prevent bypass via mv/rename
  rules.push(
    ...generateMoveBlockingRules(
      resolved.denies.map(d => d.path),
      logTag,
    ),
  )

  // Re-allow file-write-unlink / file-write-create for paths that are explicitly
  // write-allowed. The move-blocking rules above emit broad
  // (deny file-write-unlink (subpath "/Users")) to prevent bypassing read
  // restrictions by moving files out of denied regions.
  // However, in macOS Seatbelt, a specific (deny file-write-unlink) is not overridden
  // by a later (allow file-write*) wildcard — the specific operation deny wins.
  // This means file deletions are blocked even in write-allowed directories like
  // the project directory. We fix this by explicitly re-allowing file-write-unlink
  // and file-write-create for write-allowed paths after the move-blocking deny rules.
  //
  // Note: denyWithinAllow paths are not excluded here because the write section's
  // generateMoveBlockingRules() runs later in the profile and re-denies
  // file-write-unlink for those paths (Seatbelt uses last-match-wins). This
  // depends on read rules being emitted before write rules in generateSandboxProfile().
  //
  // This re-allow also re-opens rename/rm of read-denied paths that sit
  // INSIDE a write root; generateReadDenyUnlinkRules(), emitted at the end
  // of the profile, takes those back.
  const writeAllowFilters = new Set(
    resolved.writeRoots.map(w => pathFilter(w.path)),
  )
  rules.push(
    ...renderRule(
      'allow',
      ['file-write-unlink', 'file-write-create'],
      writeAllowFilters,
      logTag,
    ),
  )

  return rules
}

/**
 * Generate filesystem write rules for sandbox profile
 */
function generateWriteRules(
  config: FsWriteRestrictionConfig | undefined,
  logTag: string,
  allowGitConfig = false,
): string[] {
  if (!config) {
    return [`(allow file-write*)`]
  }

  const rules: string[] = []

  // Generate allow rules
  const allowFilters = new Set<string>()
  for (const pathPattern of config.allowOnly || []) {
    allowFilters.add(pathFilter(normalizePathForSandbox(pathPattern)))
  }
  rules.push(...renderRule('allow', ['file-write*'], allowFilters, logTag))

  // Combine user-specified and mandatory deny patterns (no ripgrep needed on macOS)
  const denyPaths = [
    ...(config.denyWithinAllow || []),
    ...macGetMandatoryDenyPatterns(allowGitConfig),
  ]

  const { groups, rest: ungrouped } = groupLiteralDenyPaths(
    denyPaths.map(normalizePathForSandbox),
  )
  const groupFilters = groups.map(literalDenyGroupFilters)

  const denyFilters = new Set<string>()
  for (const { deny } of groupFilters) {
    for (const filter of deny) denyFilters.add(filter)
  }
  for (const normalizedPath of ungrouped) {
    denyFilters.add(denyPathFilter(normalizedPath))
  }
  rules.push(...renderRule('deny', ['file-write*'], denyFilters, logTag))

  // Block file movement to prevent bypass via mv/rename. A grouped path
  // contributes its regex, the pin for its parent directory, and the
  // literals for the group directory and its ancestors — the same set a
  // per-path filter would add.
  const moveFilters = moveBlockingFilters(ungrouped)
  for (const [index, { deny, pins }] of groupFilters.entries()) {
    for (const filter of [...deny, ...pins]) moveFilters.add(filter)
    const { dir } = groups[index]
    for (const ancestorDir of [dir, ...getAncestorDirectories(dir)]) {
      moveFilters.add(`(literal ${escapePath(ancestorDir)})`)
    }
  }
  rules.push(
    ...renderRule(
      'deny',
      ['file-write-unlink', 'file-write-create'],
      moveFilters,
      logTag,
    ),
  )

  return rules
}

/**
 * Generate complete sandbox profile
 */
function generateSandboxProfile({
  readConfig,
  writeConfig,
  httpProxyPort,
  socksProxyPort,
  needsNetworkRestriction,
  allowUnixSockets,
  allowAllUnixSockets,
  allowLocalBinding,
  allowMachLookup,
  allowPty,
  allowGitConfig = false,
  enableWeakerNetworkIsolation = false,
  allowAppleEvents = false,
  logTag,
}: {
  readConfig: FsReadRestrictionConfig | undefined
  writeConfig: FsWriteRestrictionConfig | undefined
  httpProxyPort?: number
  socksProxyPort?: number
  needsNetworkRestriction: boolean
  allowUnixSockets?: string[]
  allowAllUnixSockets?: boolean
  allowLocalBinding?: boolean
  allowMachLookup?: string[]
  allowPty?: boolean
  allowGitConfig?: boolean
  enableWeakerNetworkIsolation?: boolean
  allowAppleEvents?: boolean
  logTag: string
}): string {
  const profile: string[] = [
    '(version 1)',
    `(deny default (with message "${logTag}"))`,
    '',
    `; LogTag: ${logTag}`,
    '',
    '; Essential permissions - based on Chrome sandbox policy',
    '; Process permissions',
    '(allow process-exec)',
    '(allow process-fork)',
    '(allow process-info* (target same-sandbox))',
    '(allow signal (target same-sandbox))',
    '(allow mach-priv-task-port (target same-sandbox))',
    '',
    '; User preferences',
    '(allow user-preference-read)',
    '',
    '; Mach IPC - specific services only (no wildcard)',
    '(allow mach-lookup',
    '  (global-name "com.apple.audio.systemsoundserver")',
    '  (global-name "com.apple.distributed_notifications@Uv3")',
    '  (global-name "com.apple.FontObjectsServer")',
    '  (global-name "com.apple.fonts")',
    '  (global-name "com.apple.logd")',
    '  (global-name "com.apple.lsd.mapdb")',
    '  (global-name "com.apple.PowerManagement.control")',
    '  (global-name "com.apple.system.logger")',
    '  (global-name "com.apple.system.notification_center")',
    '  (global-name "com.apple.system.opendirectoryd.libinfo")',
    '  (global-name "com.apple.system.opendirectoryd.membership")',
    '  (global-name "com.apple.bsd.dirhelper")',
    '  (global-name "com.apple.securityd.xpc")',
    '  (global-name "com.apple.coreservices.launchservicesd")',
    ')',
    '',
    ...(enableWeakerNetworkIsolation
      ? [
          '; trustd.agent - needed for Go TLS certificate verification (weaker network isolation)',
          '(allow mach-lookup (global-name "com.apple.trustd.agent"))',
        ]
      : []),
    ...(allowAppleEvents
      ? [
          '; Apple Events - opt-in; needed for open/osascript to talk to other apps (appleeventsd)',
          '(allow appleevent-send)',
          '(allow mach-lookup (global-name "com.apple.coreservices.appleevents"))',
          '; Launch Services open requests need the lsopen operation plus, on',
          '; macOS 14/15, coreservicesd and the quarantine resolver - without',
          '; these open fails with -10822 kLSServerCommunicationErr or -54',
          '(allow lsopen)',
          '(allow mach-lookup (global-name "com.apple.CoreServices.coreservicesd"))',
          '(allow mach-lookup (global-name "com.apple.coreservices.quarantine-resolver"))',
        ]
      : []),
    ...(allowMachLookup && allowMachLookup.length > 0
      ? [
          '; User-specified XPC/Mach services',
          ...allowMachLookup.map(name =>
            name.endsWith('*')
              ? `(allow mach-lookup (global-name-prefix ${escapePath(name.slice(0, -1))}))`
              : `(allow mach-lookup (global-name ${escapePath(name)}))`,
          ),
        ]
      : []),
    '',
    '; POSIX IPC - shared memory',
    '(allow ipc-posix-shm)',
    '',
    '; POSIX IPC - semaphores for Python multiprocessing',
    '(allow ipc-posix-sem)',
    '',
    '; IOKit - specific operations only',
    '(allow iokit-open',
    '  (iokit-registry-entry-class "IOSurfaceRootUserClient")',
    '  (iokit-registry-entry-class "RootDomainUserClient")',
    '  (iokit-user-client-class "IOSurfaceSendRight")',
    ')',
    '',
    '; IOKit properties',
    '(allow iokit-get-properties)',
    '',
    "; Specific safe system-sockets, doesn't allow network access",
    '(allow system-socket (require-all (socket-domain AF_SYSTEM) (socket-protocol 2)))',
    '',
    '; sysctl - specific sysctls only',
    '(allow sysctl-read',
    '  (sysctl-name "hw.activecpu")',
    '  (sysctl-name "hw.busfrequency_compat")',
    '  (sysctl-name "hw.byteorder")',
    '  (sysctl-name "hw.cacheconfig")',
    '  (sysctl-name "hw.cachelinesize_compat")',
    '  (sysctl-name "hw.cpufamily")',
    '  (sysctl-name "hw.cpufrequency")',
    '  (sysctl-name "hw.cpufrequency_compat")',
    '  (sysctl-name "hw.cputype")',
    '  (sysctl-name "hw.l1dcachesize_compat")',
    '  (sysctl-name "hw.l1icachesize_compat")',
    '  (sysctl-name "hw.l2cachesize_compat")',
    '  (sysctl-name "hw.l3cachesize_compat")',
    '  (sysctl-name "hw.logicalcpu")',
    '  (sysctl-name "hw.logicalcpu_max")',
    '  (sysctl-name "hw.machine")',
    '  (sysctl-name "hw.memsize")',
    '  (sysctl-name "hw.ncpu")',
    '  (sysctl-name "hw.nperflevels")',
    '  (sysctl-name "hw.packages")',
    '  (sysctl-name "hw.pagesize_compat")',
    '  (sysctl-name "hw.pagesize")',
    '  (sysctl-name "hw.physicalcpu")',
    '  (sysctl-name "hw.physicalcpu_max")',
    '  (sysctl-name "hw.tbfrequency_compat")',
    '  (sysctl-name "hw.vectorunit")',
    '  (sysctl-name "kern.argmax")',
    '  (sysctl-name "kern.bootargs")',
    '  (sysctl-name "kern.hostname")',
    '  (sysctl-name "kern.maxfiles")',
    '  (sysctl-name "kern.maxfilesperproc")',
    '  (sysctl-name "kern.maxproc")',
    '  (sysctl-name "kern.ngroups")',
    '  (sysctl-name "kern.osproductversion")',
    '  (sysctl-name "kern.osrelease")',
    '  (sysctl-name "kern.ostype")',
    '  (sysctl-name "kern.osvariant_status")',
    '  (sysctl-name "kern.osversion")',
    '  (sysctl-name "kern.secure_kernel")',
    '  (sysctl-name "kern.tcsm_available")',
    '  (sysctl-name "kern.tcsm_enable")',
    '  (sysctl-name "kern.usrstack64")',
    '  (sysctl-name "kern.version")',
    '  (sysctl-name "kern.willshutdown")',
    '  (sysctl-name "machdep.cpu.brand_string")',
    '  (sysctl-name "machdep.ptrauth_enabled")',
    '  (sysctl-name "security.mac.lockdown_mode_state")',
    '  (sysctl-name "sysctl.proc_cputype")',
    '  (sysctl-name "vm.loadavg")',
    '  (sysctl-name-prefix "hw.optional.arm")',
    '  (sysctl-name-prefix "hw.optional.arm.")',
    '  (sysctl-name-prefix "hw.optional.armv8_")',
    '  (sysctl-name-prefix "hw.perflevel")',
    '  (sysctl-name-prefix "kern.proc.all")',
    '  (sysctl-name-prefix "kern.proc.pgrp.")',
    '  (sysctl-name-prefix "kern.proc.pid.")',
    '  (sysctl-name-prefix "machdep.cpu.")',
    '  (sysctl-name-prefix "net.routetable.")',
    ')',
    '',
    '; V8 thread calculations',
    '(allow sysctl-write',
    '  (sysctl-name "kern.tcsm_enable")',
    ')',
    '',
    '; Distributed notifications',
    '(allow distributed-notification-post)',
    '',
    '; Specific mach-lookup permissions for security operations',
    '(allow mach-lookup (global-name "com.apple.SecurityServer"))',
    '',
    '; File I/O on device files',
    '(allow file-ioctl (literal "/dev/null"))',
    '(allow file-ioctl (literal "/dev/zero"))',
    '(allow file-ioctl (literal "/dev/random"))',
    '(allow file-ioctl (literal "/dev/urandom"))',
    '(allow file-ioctl (literal "/dev/dtracehelper"))',
    '(allow file-ioctl (literal "/dev/tty"))',
    '',
    '(allow file-ioctl file-read-data file-write-data',
    '  (require-all',
    '    (literal "/dev/null")',
    '    (vnode-type CHARACTER-DEVICE)',
    '  )',
    ')',
    '',
  ]

  // Network rules
  profile.push('; Network')
  if (!needsNetworkRestriction) {
    profile.push('(allow network*)')
  } else {
    // Allow local binding if requested.
    //
    // bind/inbound use (local ip "*:*") instead of "localhost:*" because modern
    // runtimes (Java, etc.) create IPv6 dual-stack sockets by default; binding
    // such a socket to 127.0.0.1 is represented in the kernel as
    // ::ffff:127.0.0.1, which Seatbelt's "localhost" filter does not match.
    // Seatbelt only accepts "localhost" or "*" as the host token, so "*:*" is
    // the only way to admit the IPv4-mapped form. bind/inbound are local
    // operations (no remote endpoint), so wildcarding them does not grant
    // egress.
    //
    // outbound uses (remote ip "localhost:*") so the egress allowlist remains
    // enforced when allowLocalBinding is set (#225, #88). A (local ip ...)
    // filter on network-outbound is evaluated against the source address,
    // which for an unbound socket is INADDR_ANY (0.0.0.0 / ::) at connect()
    // time — Seatbelt's "localhost" matches the any-address, so any
    // (local ip ...) host value admits every outbound connection. (remote ip
    // "localhost:*") matches connect() to 127.0.0.1 and ::1 but not
    // ::ffff:127.0.0.1; runtimes that connect to loopback via dual-stack
    // sockets need to use AF_INET (see JAVA_TOOL_OPTIONS injection below).
    if (allowLocalBinding) {
      profile.push('(allow network-bind (local ip "*:*"))')
      profile.push('(allow network-inbound (local ip "*:*"))')
      profile.push('(allow network-outbound (remote ip "localhost:*"))')
    }
    // Unix domain sockets for local IPC (SSH agent, Docker, Gradle, etc.)
    // Three separate operations must be allowed:
    // 1. system-socket: socket(AF_UNIX, ...) syscall — creates the socket fd (no path context)
    // 2. network-bind: bind() to a local Unix socket path
    // 3. network-outbound: connect() to a remote Unix socket path
    // Note: (subpath ...) and (path-regex ...) are path-based filters that can only match
    // bind/connect operations — socket() creation has no path, so it requires system-socket.
    if (allowAllUnixSockets) {
      // Allow creating AF_UNIX sockets and all Unix socket paths
      profile.push('(allow system-socket (socket-domain AF_UNIX))')
      profile.push(
        '(allow network-bind (local unix-socket (path-regex #"^/")))',
      )
      profile.push(
        '(allow network-outbound (remote unix-socket (path-regex #"^/")))',
      )
    } else if (allowUnixSockets && allowUnixSockets.length > 0) {
      // Allow creating AF_UNIX sockets (required for any Unix socket use)
      profile.push('(allow system-socket (socket-domain AF_UNIX))')
      // Allow specific Unix socket paths
      for (const socketPath of allowUnixSockets) {
        const normalizedPath = normalizePathForSandbox(socketPath)
        profile.push(
          `(allow network-bind (local unix-socket (subpath ${escapePath(normalizedPath)})))`,
        )
        profile.push(
          `(allow network-outbound (remote unix-socket (subpath ${escapePath(normalizedPath)})))`,
        )
      }
    }
    // If both allowAllUnixSockets and allowUnixSockets are false/undefined/empty, Unix sockets are blocked by default

    // Allow localhost TCP operations for the HTTP proxy
    if (httpProxyPort !== undefined) {
      profile.push(
        `(allow network-bind (local ip "localhost:${httpProxyPort}"))`,
      )
      profile.push(
        `(allow network-inbound (local ip "localhost:${httpProxyPort}"))`,
      )
      profile.push(
        `(allow network-outbound (remote ip "localhost:${httpProxyPort}"))`,
      )
    }

    // Allow localhost TCP operations for the SOCKS proxy. Skip when it's
    // the same port as the HTTP proxy (the mux serves both on one port);
    // SBPL accepts duplicate allow clauses but there's no need to emit them.
    if (socksProxyPort !== undefined && socksProxyPort !== httpProxyPort) {
      profile.push(
        `(allow network-bind (local ip "localhost:${socksProxyPort}"))`,
      )
      profile.push(
        `(allow network-inbound (local ip "localhost:${socksProxyPort}"))`,
      )
      profile.push(
        `(allow network-outbound (remote ip "localhost:${socksProxyPort}"))`,
      )
    }
  }
  profile.push('')

  // Read rules
  // Pass write-allowed paths so that move-blocking deny rules in the read section
  // can be overridden for paths where file deletion should be permitted.
  const resolvedRead = readConfig
    ? resolveReadConfig(readConfig, writeConfig?.allowOnly)
    : undefined
  profile.push('; File read')
  profile.push(...generateReadRules(resolvedRead, logTag))
  profile.push('')

  // Write rules
  profile.push('; File write')
  profile.push(...generateWriteRules(writeConfig, logTag, allowGitConfig))

  // Read-denied paths inside write roots: the read section's unlink/create
  // re-allow for write roots (and the write section's file-write* allows)
  // must not leave them renameable. Last in the profile so nothing above
  // can re-open them.
  if (resolvedRead) {
    const unlinkRules = generateReadDenyUnlinkRules(resolvedRead, logTag)
    if (unlinkRules.length > 0) {
      profile.push('')
      profile.push(
        '; File read: keep read-denied paths inside write roots in place',
      )
      profile.push(...unlinkRules)
    }
  }

  // Pseudo-terminal (pty) support
  if (allowPty) {
    profile.push('')
    profile.push('; Pseudo-terminal (pty) support')
    profile.push('(allow pseudo-tty)')
    profile.push('(allow file-ioctl')
    profile.push('  (literal "/dev/ptmx")')
    profile.push('  (regex #"^/dev/ttys")')
    profile.push(')')
    profile.push('(allow file-read* file-write*')
    profile.push('  (literal "/dev/ptmx")')
    profile.push('  (regex #"^/dev/ttys")')
    profile.push(')')
  }

  return profile.join('\n')
}

/**
 * Escape path for sandbox profile using JSON.stringify for proper escaping
 */
function escapePath(pathStr: string): string {
  return JSON.stringify(pathStr)
}

/**
 * Wrap command with macOS sandbox
 */
export function wrapCommandWithSandboxMacOS(
  params: MacOSSandboxParams,
): string {
  const {
    command,
    commandId,
    needsNetworkRestriction,
    httpProxyPort,
    socksProxyPort,
    proxyAuthToken,
    caCertPath,
    javaAgentJarPath,
    allowUnixSockets,
    allowAllUnixSockets,
    allowLocalBinding,
    allowMachLookup,
    readConfig: readConfigIn,
    writeConfig,
    unsetEnvVars,
    setEnvVars,
    maskedFileBinds,
    allowPty,
    allowGitConfig = false,
    gitSafeDirectories,
    enableWeakerNetworkIsolation = false,
    allowAppleEvents = false,
    binShell,
  } = params

  // SBPL cannot redirect a read to different bytes, so whole-file masking
  // degrades to read-deny on macOS: the sandboxed process gets EPERM
  // instead of the sentinel. The DYLD interposer (a later step) lifts
  // this. Folding the masked paths into denyOnly here means the existing
  // generateReadRules() emits the (deny file-read* …) rule unchanged.
  let readConfig = readConfigIn
  if (maskedFileBinds && maskedFileBinds.length > 0) {
    logForDebugging(
      '[Sandbox macOS] file mask degrades to deny on macOS until the ' +
        'interposer lands',
    )
    readConfig = {
      denyOnly: [
        ...(readConfigIn?.denyOnly ?? []),
        ...maskedFileBinds.map(b => b.realPath),
      ],
      allowWithinDeny: readConfigIn?.allowWithinDeny,
    }
  }

  // Determine if we have restrictions to apply
  // Read: denyOnly pattern - empty array means no restrictions
  // Write: allowOnly pattern - undefined means no restrictions, any config means restrictions
  const hasReadRestrictions = readConfig && readConfig.denyOnly.length > 0
  const hasWriteRestrictions = writeConfig !== undefined
  const hasEnvRestrictions =
    (unsetEnvVars !== undefined && unsetEnvVars.length > 0) ||
    (setEnvVars !== undefined && Object.keys(setEnvVars).length > 0)
  const hasGitConfig = (gitSafeDirectories?.length ?? 0) > 0

  // No sandboxing needed
  if (
    !needsNetworkRestriction &&
    !hasReadRestrictions &&
    !hasWriteRestrictions &&
    !hasEnvRestrictions &&
    !hasGitConfig
  ) {
    return command
  }

  // Both correlation carriers (seatbelt log tag, proxy username) encode
  // the attribution key, which is the caller's commandId when the
  // executed string differs from the one violations are looked up by.
  const attributionCommand = commandId ?? command
  const logTag = generateLogTag(attributionCommand)

  const profile = generateSandboxProfile({
    readConfig,
    writeConfig,
    httpProxyPort,
    socksProxyPort,
    needsNetworkRestriction,
    allowUnixSockets,
    allowAllUnixSockets,
    allowLocalBinding,
    allowMachLookup,
    allowPty,
    allowGitConfig,
    enableWeakerNetworkIsolation,
    allowAppleEvents,
    logTag,
  })

  // Generate proxy environment variables using shared utility
  const proxyEnvArgs = generateProxyEnvVars(
    httpProxyPort,
    socksProxyPort,
    caCertPath,
    proxyAuthToken,
    writeConfig === undefined,
    encodeSandboxedCommand(attributionCommand),
  )

  // JAVA_TOOL_OPTIONS carries two things for JVMs in the sandbox:
  //
  // - The proxy agent jar (see java-proxy-agent.ts): JVMs ignore the proxy
  //   env vars above, so the agent translates them into system properties
  //   plus an Authenticator for the proxy credential at JVM start.
  // - -Djava.net.preferIPv4Stack=true whenever the profile lets the child
  //   reach loopback at all (the proxy ports, or allowLocalBinding's
  //   localhost:*): Seatbelt's (remote ip "localhost:N") filter matches
  //   127.0.0.1 and ::1 but not the IPv4-mapped IPv6 form ::ffff:127.0.0.1.
  //   Modern Java defaults to AF_INET6 dual-stack sockets, so a Java client
  //   connecting to 127.0.0.1 reaches the kernel as ::ffff:127.0.0.1 and is
  //   denied ("Operation not permitted") — including its connect to the
  //   proxy the agent just pointed it at. Forcing the IPv4 stack makes Java
  //   open AF_INET sockets so loopback connect matches the filter.
  //
  // Both are composed with any inherited JAVA_TOOL_OPTIONS unless that var
  // is on the credential-deny list, in which case the inherited value is
  // dropped so the deny holds.
  const loopbackReachable =
    needsNetworkRestriction &&
    (allowLocalBinding ||
      httpProxyPort !== undefined ||
      socksProxyPort !== undefined)
  const javaToolOptions = buildJavaToolOptions({
    agentJarPath: javaAgentJarPath,
    flags: loopbackReachable ? ['-Djava.net.preferIPv4Stack=true'] : [],
    unsetEnvVars,
    inherited: process.env.JAVA_TOOL_OPTIONS,
  })
  if (javaToolOptions !== undefined) {
    proxyEnvArgs.push(`JAVA_TOOL_OPTIONS=${javaToolOptions}`)
  }

  // safe.directory (dubious-ownership) — `buildPosixGitSafeDirEnv`
  // composes against the child's actual starting env (process.env
  // inherited under sandbox-exec, unsetEnvVars dropped, setEnvVars
  // overlaid) so an ambient GIT_CONFIG_COUNT is continued, not
  // clobbered.
  if (gitSafeDirectories && gitSafeDirectories.length > 0) {
    const gitCfg = buildPosixGitSafeDirEnv({
      safeDirs: gitSafeDirectories,
      unsetEnvVars,
      setEnvVars,
    })
    for (const [name, value] of Object.entries(gitCfg)) {
      proxyEnvArgs.push(`${name}=${value}`)
    }
  }

  // Use the user's shell (zsh, bash, etc.) to ensure aliases/snapshots work
  // Resolve the full path to the shell binary
  const shellName = binShell || 'bash'
  const shell = whichSync(shellName)
  if (!shell) {
    throw new Error(`Shell '${shellName}' not found in PATH`)
  }

  // Drop denied credential env vars from the inherited environment. The -u
  // flags must precede the VAR=VALUE assignments so SRT's own proxy plumbing
  // vars survive even if a caller lists one of them as a denied credential.
  const unsetEnvArgs = (unsetEnvVars ?? []).flatMap(name => ['-u', name])
  // Masked credentials override the inherited real value with a sentinel.
  // Placed before the proxy plumbing assignments for the same precedence
  // reason as the -u flags.
  const setEnvArgs = Object.entries(setEnvVars ?? {}).map(
    ([name, value]) => `${name}=${value}`,
  )

  // Use `env` command to set environment variables - each VAR=value is a separate
  // argument that quote() escapes properly, avoiding shell quoting issues
  const wrappedCommand = quote([
    'env',
    ...unsetEnvArgs,
    ...setEnvArgs,
    ...proxyEnvArgs,
    '/usr/bin/sandbox-exec',
    '-p',
    profile,
    shell,
    '-c',
    command,
  ])

  logForDebugging(
    `[Sandbox macOS] Applied restrictions - network: ${!!(httpProxyPort || socksProxyPort)}, read: ${
      readConfig
        ? 'allowAllExcept' in readConfig
          ? 'allowAllExcept'
          : 'denyAllExcept'
        : 'none'
    }, write: ${
      writeConfig
        ? 'allowAllExcept' in writeConfig
          ? 'allowAllExcept'
          : 'denyAllExcept'
        : 'none'
    }`,
  )

  return wrappedCommand
}

/**
 * Start monitoring macOS system logs for sandbox violations
 * Look for sandbox-related kernel deny events ending in {logTag}
 */
export function startMacOSSandboxLogMonitor(
  callback: SandboxViolationCallback,
  ignoreViolations?: IgnoreViolationsConfig,
  /** Map a decoded attribution key (commandId) to the command text it
   *  represents; identity when omitted. Applied before ignoreViolations
   *  matching and before the event's `command` is set. */
  resolveCommandText: (decodedId: string) => string = id => id,
): () => void {
  // Pre-compile regex patterns for better performance
  const cmdExtractRegex = /CMD64_(.+?)_END/
  const sandboxExtractRegex = /Sandbox:\s+(.+)$/

  // Stream and filter kernel logs for all sandbox violations
  // We can't filter by specific logTag since it's dynamic per command
  const logProcess = spawn('log', [
    'stream',
    '--predicate',
    `(eventMessage ENDSWITH "${sessionSuffix}")`,
    '--style',
    'compact',
  ])

  logProcess.stdout?.on('data', (data: Buffer) => {
    const lines = data.toString().split('\n')

    // Get violation and command lines
    const violationLine = lines.find(
      line => line.includes('Sandbox:') && line.includes('deny'),
    )
    const commandLine = lines.find(line => line.startsWith('CMD64_'))

    if (!violationLine) return

    // Extract violation details
    const sandboxMatch = violationLine.match(sandboxExtractRegex)
    if (!sandboxMatch?.[1]) return

    const violationDetails = sandboxMatch[1]

    // Try to get command
    let command: string | undefined
    let encodedCommand: string | undefined
    if (commandLine) {
      const cmdMatch = commandLine.match(cmdExtractRegex)
      encodedCommand = cmdMatch?.[1]
      if (encodedCommand) {
        try {
          command = resolveCommandText(decodeSandboxedCommand(encodedCommand))
        } catch {
          // Failed to decode, continue without command
        }
      }
    }

    // Always filter out noisey violations
    if (
      violationDetails.includes('mDNSResponder') ||
      violationDetails.includes('mach-lookup com.apple.diagnosticd') ||
      violationDetails.includes('mach-lookup com.apple.analyticsd')
    ) {
      return
    }

    // Check if we should ignore this violation
    if (shouldIgnoreViolation(violationDetails, command, ignoreViolations)) {
      return
    }

    // Not ignored - report the violation
    callback({
      line: violationDetails,
      command,
      encodedCommand,
      timestamp: new Date(), // We could parse the timestamp from the log but this feels more reliable
    })
  })

  logProcess.stderr?.on('data', (data: Buffer) => {
    logForDebugging(`[Sandbox Monitor] Log stream stderr: ${data.toString()}`)
  })

  logProcess.on('error', (error: Error) => {
    logForDebugging(
      `[Sandbox Monitor] Failed to start log stream: ${error.message}`,
    )
  })

  logProcess.on('exit', (code: number | null) => {
    logForDebugging(`[Sandbox Monitor] Log stream exited with code: ${code}`)
  })

  return () => {
    logForDebugging('[Sandbox Monitor] Stopping log monitor')
    logProcess.kill('SIGTERM')
  }
}
