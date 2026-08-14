import { homedir } from 'os'
import * as path from 'path'
import * as fs from 'fs'
import { logForDebugging } from '../utils/debug.js'
import {
  containsGlobChars,
  expandGlobPattern,
  normalizePathForSandbox,
} from './sandbox-utils.js'

/**
 * ssh_config(5) allows Include chains; both bounds exist so a malicious or
 * self-referential config cannot make config assembly unbounded. OpenSSH
 * itself caps include depth at 16 — we stay below that since legitimate
 * configs rarely nest more than two or three levels.
 */
const MAX_INCLUDE_DEPTH = 8
const MAX_CONFIG_FILES = 64

/**
 * Filenames ssh tries by default when no IdentityFile is configured
 * (ssh_config(5) IdentityFile). Only the private halves — .pub files are not
 * sensitive.
 */
const DEFAULT_IDENTITY_FILES = [
  'id_rsa',
  'id_ecdsa',
  'id_ecdsa_sk',
  'id_ed25519',
  'id_ed25519_sk',
  'id_dsa',
] as const

/**
 * Directives whose argument is a filesystem path holding key material or an
 * equivalent credential: private keys, certificates, and mux sockets (an
 * attacker with access to a ControlPath socket can ride existing sessions).
 */
const PATH_DIRECTIVES = new Set([
  'identityfile',
  'certificatefile',
  'controlpath',
  // An agent socket signs with EVERY loaded key — strictly more
  // credential-equivalent than a single IdentityFile. Provider
  // LIBRARIES (PKCS11Provider/SecurityKeyProvider) are deliberately
  // excluded: they are public code, not secrets, and reading them
  // grants nothing.
  'identityagent',
])

interface SshConfigScanState {
  filesParsed: number
  visitedFiles: Set<string>
  collected: Set<string>
}

/**
 * Split an ssh_config line into tokens. Handles the `Keyword value`,
 * `Keyword=value`, and double-quoted argument forms. Deliberately tolerant:
 * an unterminated quote consumes to end of line rather than erroring, since a
 * malformed config must never fail sandbox config assembly.
 */
export function splitSshConfigLine(line: string): string[] {
  const tokens: string[] = []
  let current = ''
  let inQuotes = false

  for (let i = 0; i < line.length; i++) {
    const ch = line[i]
    if (ch === '"') {
      inQuotes = !inQuotes
      continue
    }
    // '=' separates the keyword from its first argument (`IdentityFile=~/key`,
    // `IdentityFile = ~/key`); inside arguments it is literal.
    const isKeywordEquals =
      ch === '=' &&
      (tokens.length === 0 || (tokens.length === 1 && current.length === 0))
    const isSeparator =
      !inQuotes && (ch === ' ' || ch === '\t' || isKeywordEquals)
    if (isSeparator) {
      if (current.length > 0) {
        tokens.push(current)
        current = ''
      }
      continue
    }
    current += ch
  }
  if (current.length > 0) {
    tokens.push(current)
  }
  return tokens
}

/**
 * Expand tilde and %-tokens in an ssh_config path argument.
 *
 * Only tokens whose value is known statically are expanded: `~`/`%d` (home
 * directory), `%u` (local user), and `%%` (literal percent). Connection-scoped
 * tokens like `%h`/`%r`/`%p` and `${ENV}` references depend on runtime state
 * we cannot know at config-assembly time, so entries containing them are
 * skipped (returns undefined) rather than guessed at.
 */
export function expandSshPathTokens(
  value: string,
  homeDir: string,
): string | undefined {
  let expanded = value
  if (expanded === '~') {
    expanded = homeDir
  } else if (expanded.startsWith('~/')) {
    expanded = homeDir + expanded.slice(1)
  } else if (expanded.startsWith('~')) {
    // ~otheruser expansion requires user database lookups; skip.
    return undefined
  }

  if (expanded.includes('${')) {
    return undefined
  }

  let result = ''
  for (let i = 0; i < expanded.length; i++) {
    const ch = expanded[i]
    if (ch !== '%') {
      result += ch
      continue
    }
    const token = expanded[i + 1]
    if (token === '%') {
      result += '%'
      i++
    } else if (token === 'd') {
      result += homeDir
      i++
    } else if (token === 'u') {
      const user = process.env['USER'] ?? process.env['USERNAME']
      if (!user) {
        return undefined
      }
      result += user
      i++
    } else {
      // Unexpandable token (%h, %r, %p, ...) — skip the whole entry.
      return undefined
    }
  }
  return result
}

/**
 * Expand one `Include` argument to concrete file paths. Relative
 * arguments resolve against `~/.ssh` per ssh_config(5). Glob
 * expansion reuses the library's own {@link expandGlobPattern}
 * (separator- and case-behavior consistent with the rest of config
 * assembly, and bracket-in-filename tolerant on Windows via its
 * platform handling) rather than a hand-rolled readdir+regex.
 */
function expandIncludeArgument(pattern: string, homeDir: string): string[] {
  const expanded = expandSshPathTokens(pattern, homeDir)
  if (expanded === undefined) {
    return []
  }
  const absolute = path.isAbsolute(expanded)
    ? expanded
    : path.join(homeDir, '.ssh', expanded)

  if (!containsGlobChars(absolute)) {
    return [absolute]
  }
  try {
    return expandGlobPattern(absolute)
  } catch {
    return []
  }
}

/**
 * Parse one ssh_config file, collecting path-directive arguments into
 * state.collected and recursing into Include directives. Tolerant by design:
 * unreadable files and malformed lines are skipped, never thrown.
 */
function parseSshConfigFile(
  filePath: string,
  homeDir: string,
  depth: number,
  state: SshConfigScanState,
): void {
  if (depth > MAX_INCLUDE_DEPTH || state.filesParsed >= MAX_CONFIG_FILES) {
    return
  }
  // Track by resolved path so include cycles (a includes b includes a)
  // terminate via the visited set rather than only via the depth bound.
  let resolved: string
  try {
    resolved = fs.realpathSync(filePath)
  } catch {
    return
  }
  if (state.visitedFiles.has(resolved)) {
    return
  }
  state.visitedFiles.add(resolved)
  state.filesParsed++

  let content: string
  try {
    content = fs.readFileSync(resolved, 'utf8')
  } catch {
    return
  }

  for (const rawLine of content.split('\n')) {
    const line = rawLine.trim()
    if (line.length === 0 || line.startsWith('#')) {
      continue
    }
    const tokens = splitSshConfigLine(line)
    if (tokens.length < 2) {
      continue
    }
    const keyword = tokens[0].toLowerCase()

    if (keyword === 'include') {
      // Include accepts multiple patterns on one line.
      for (const pattern of tokens.slice(1)) {
        for (const includePath of expandIncludeArgument(pattern, homeDir)) {
          parseSshConfigFile(includePath, homeDir, depth + 1, state)
        }
      }
      continue
    }

    if (PATH_DIRECTIVES.has(keyword)) {
      // IdentityFile "none" disables defaults; it names no file.
      if (tokens[1].toLowerCase() === 'none') {
        continue
      }
      const expanded = expandSshPathTokens(tokens[1], homeDir)
      if (expanded === undefined) {
        continue
      }
      // Relative IdentityFile/CertificateFile paths are resolved against the
      // directory ssh was started in — unknowable here — so only keep
      // absolute results.
      if (path.isAbsolute(expanded)) {
        state.collected.add(expanded)
      }
    }
  }
}

/**
 * Collect read-deny paths for SSH private key material referenced by the
 * user's ssh config (~/.ssh/config; %USERPROFILE%\.ssh\config on Windows,
 * both via homedir()).
 *
 * ssh configs routinely point IdentityFile/CertificateFile/ControlPath at
 * files OUTSIDE ~/.ssh, so a denyRead entry for ~/.ssh alone does not protect
 * them. This walks the config (including Include chains) and returns every
 * referenced path that exists and is not already under an existing denyRead
 * entry, plus the default key filenames ssh tries when no IdentityFile is
 * set. Purely additive: callers append the result to their effective denyRead
 * set, and any failure yields fewer additions, never removed protection.
 *
 * @param homeDirOverride - Test seam; defaults to os.homedir().
 */
export function collectSshKeyDenyPaths(homeDirOverride?: string): string[] {
  try {
    const homeDir = homeDirOverride ?? _test.homedirOverride ?? homedir()
    const sshDir = path.join(homeDir, '.ssh')

    const state: SshConfigScanState = {
      filesParsed: 0,
      visitedFiles: new Set(),
      collected: new Set(),
    }

    const configPath = path.join(sshDir, 'config')
    if (fs.existsSync(configPath)) {
      parseSshConfigFile(configPath, homeDir, 0, state)
    }

    // Default identity filenames are tried by ssh even with no config file,
    // and this library has no mandatory read denies covering them (its
    // mandatory protections — DANGEROUS_FILES et al. — are write-side only).
    // Gated on the .ssh DIRECTORY existing: within it, names are denied
    // before the keys exist (mid-session keygen stays covered), but a
    // machine with no .ssh at all gets no denies — on Windows, absent deny
    // targets are placeholder-materialized, and planting a .ssh skeleton
    // into every profile that never used ssh is not this feature's call.
    if (fs.existsSync(sshDir)) {
      for (const name of DEFAULT_IDENTITY_FILES) {
        state.collected.add(path.join(sshDir, name))
      }
    }

    const denyPaths: string[] = []
    for (const candidate of state.collected) {
      const normalized = normalizePathForSandbox(candidate)
      // Glob metacharacters are legal filename bytes, but the macOS
      // profile generator would compile such a path as a GLOB and
      // deny the wrong object — a silent loss of protection. Skip
      // loudly instead (the shape is vanishingly rare).
      if (containsGlobChars(normalized)) {
        logForDebugging(
          `[Sandbox] SSH key path contains glob metacharacters, ` +
            `skipping deny: ${normalized}`,
          { level: 'warn' },
        )
        continue
      }
      // Deliberately NOT filtered on existence: a ControlPath mux
      // socket typically appears only when the first master
      // connection opens, and keys can be generated mid-session.
      // Every backend tolerates absent deny entries (seatbelt
      // subpath denies are valid for absent paths; Linux
      // logs-and-skips; Windows materializes a placeholder), so the
      // deny must be in place BEFORE the secret exists.
      denyPaths.push(normalized)
    }
    denyPaths.sort()
    if (denyPaths.length > 0) {
      logForDebugging(
        `[Sandbox] Adding ${denyPaths.length} SSH key path(s) to denyRead`,
      )
    }
    return denyPaths
  } catch (err) {
    // A broken ssh config (or any unexpected fs state) must never fail
    // sandbox config assembly — the result is only ever additive protection.
    logForDebugging(`[Sandbox] SSH config scan failed: ${err}`, {
      level: 'error',
    })
    return []
  }
}

/**
 * Test seam (house convention): suites asserting EXACT deny sets
 * point this at an empty temp home — bun's os.homedir() reads
 * passwd, not $HOME, so an env-var swap cannot make the scan
 * hermetic.
 */
export const _test: { homedirOverride: string | undefined } = {
  homedirOverride: undefined,
}
