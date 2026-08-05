import { quote } from '../utils/shell-quote.js'
import { spawn } from 'child_process'
import * as path from 'path'
import { logForDebugging } from '../utils/debug.js'
import { whichSync } from '../utils/which.js'
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
  commandLabel?: string
  needsNetworkRestriction: boolean
  httpProxyPort?: number
  socksProxyPort?: number
  /** Per-session proxy auth token; embedded in proxy env URLs. */
  proxyAuthToken?: string
  /** Path to the TLS-termination CA cert; injected as trust env vars. */
  caCertPath?: string
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
 * Generate deny rules for file movement (file-write-unlink) and creation
 * (file-write-create) to protect paths. This prevents bypassing read or write
 * restrictions by moving files/directories, and prevents replacing a
 * not-yet-existing protected path (or one of its ancestors) with an
 * attacker-controlled symlink.
 *
 * @param pathPatterns - Array of path patterns to protect (can include globs)
 * @param logTag - Log tag for sandbox violations
 * @returns Array of sandbox profile rule lines
 */
function generateMoveBlockingRules(
  pathPatterns: string[],
  logTag: string,
): string[] {
  const rules: string[] = []
  const ops = ['file-write-unlink', 'file-write-create'] as const

  for (const pathPattern of pathPatterns) {
    const normalizedPath = normalizePathForSandbox(pathPattern)

    if (containsGlobChars(normalizedPath)) {
      // Use regex matching for glob patterns
      const regexPattern = globToRegex(normalizedPath)

      // Block moving/renaming files matching this pattern
      for (const op of ops) {
        rules.push(
          `(deny ${op}`,
          `  (regex ${escapePath(regexPattern)})`,
          `  (with message "${logTag}"))`,
        )
      }

      // For glob patterns, extract the static prefix and block ancestor moves
      // Remove glob characters to get the directory prefix
      const staticPrefix = normalizedPath.split(/[*?[\]]/)[0]
      if (staticPrefix && staticPrefix !== '/') {
        // Get the directory containing the glob pattern
        const baseDir = staticPrefix.endsWith('/')
          ? staticPrefix.slice(0, -1)
          : path.dirname(staticPrefix)

        // Block moves of the base directory itself
        for (const op of ops) {
          rules.push(
            `(deny ${op}`,
            `  (literal ${escapePath(baseDir)})`,
            `  (with message "${logTag}"))`,
          )
        }

        // Block moves of ancestor directories
        for (const ancestorDir of getAncestorDirectories(baseDir)) {
          for (const op of ops) {
            rules.push(
              `(deny ${op}`,
              `  (literal ${escapePath(ancestorDir)})`,
              `  (with message "${logTag}"))`,
            )
          }
        }
      }
    } else {
      // Use subpath matching for literal paths

      // Block moving/renaming the denied path itself
      for (const op of ops) {
        rules.push(
          `(deny ${op}`,
          `  (subpath ${escapePath(normalizedPath)})`,
          `  (with message "${logTag}"))`,
        )
      }

      // Block moves of ancestor directories
      for (const ancestorDir of getAncestorDirectories(normalizedPath)) {
        for (const op of ops) {
          rules.push(
            `(deny ${op}`,
            `  (literal ${escapePath(ancestorDir)})`,
            `  (with message "${logTag}"))`,
          )
        }
      }
    }
  }

  return rules
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
 *   (deny file-read* ...)     ← deny broad regions
 *   (allow file-read* ...)    ← re-allow specific paths within denied regions
 */
function generateReadRules(
  config: FsReadRestrictionConfig | undefined,
  logTag: string,
  writeAllowPaths?: string[],
): string[] {
  if (!config) {
    return [`(allow file-read*)`]
  }

  const rules: string[] = []
  let deniesRoot = false

  // Start by allowing everything
  rules.push(`(allow file-read*)`)

  // Then deny specific paths
  for (const pathPattern of config.denyOnly || []) {
    const normalizedPath = normalizePathForSandbox(pathPattern)

    if (normalizedPath === '/') deniesRoot = true

    if (containsGlobChars(normalizedPath)) {
      // Use regex matching for glob patterns
      const regexPattern = globToRegex(normalizedPath)
      rules.push(
        `(deny file-read*`,
        `  (regex ${escapePath(regexPattern)})`,
        `  (with message "${logTag}"))`,
      )
    } else {
      // Use subpath matching for literal paths
      rules.push(
        `(deny file-read*`,
        `  (subpath ${escapePath(normalizedPath)})`,
        `  (with message "${logTag}"))`,
      )
    }
  }

  // (subpath "/") denies the root inode itself; allowWithinDeny subpaths don't
  // cover "/", so dyld aborts before exec. Re-allow the literal root so path
  // traversal works. This exposes `ls /` dirent names but no subtree contents.
  if (deniesRoot) {
    rules.push(`(allow file-read* (literal "/"))`)
  }

  // Re-allow specific paths within denied regions (allowWithinDeny takes precedence)
  const allowedSubpaths: string[] = []
  for (const pathPattern of config.allowWithinDeny || []) {
    // Non-glob spellings arrive slash-free from normalizePathForSandbox —
    // the nested-deny re-emit below matches by `subpath + '/'` prefix,
    // which a preserved trailing slash would defeat ('<dir>//').
    const normalizedPath = normalizePathForSandbox(pathPattern)

    if (containsGlobChars(normalizedPath)) {
      const regexPattern = globToRegex(normalizedPath)
      rules.push(
        `(allow file-read*`,
        `  (regex ${escapePath(regexPattern)})`,
        `  (with message "${logTag}"))`,
      )
    } else {
      allowedSubpaths.push(normalizedPath)
      rules.push(
        `(allow file-read*`,
        `  (subpath ${escapePath(normalizedPath)})`,
        `  (with message "${logTag}"))`,
      )
    }
  }
  // A literal denyOnly path nested inside a literal allowWithinDeny subpath
  // would otherwise be re-allowed (last-match-wins). Re-emit it so the
  // more-specific deny lands last. Glob denies aren't re-emitted: nesting
  // of regex-vs-subpath isn't decidable here, and the schema's denyReadAlways
  // is the explicit lever for that case.
  for (const denyPath of config.denyOnly || []) {
    if (containsGlobChars(denyPath)) continue
    const normalized = normalizePathForSandbox(denyPath)
    if (allowedSubpaths.some(a => normalized.startsWith(a + '/'))) {
      rules.push(
        `(deny file-read*`,
        `  (subpath ${escapePath(normalized)})`,
        `  (with message "${logTag}"))`,
      )
    }
  }

  // Allow stat/lstat on all directories so that realpath() can traverse
  // path components within denied regions. Without this, C realpath() fails
  // when resolving symlinks because it needs to lstat every intermediate
  // directory (e.g. /Users, /Users/chris) even if only a subdirectory like
  // ~/.local is in allowWithinDeny. This only allows metadata reads on
  // directories — not listing contents (readdir) or reading files.
  if (config.denyOnly.length > 0) {
    rules.push(`(allow file-read-metadata`, `  (vnode-type DIRECTORY))`)
  }

  // Block file movement to prevent bypass via mv/rename
  rules.push(...generateMoveBlockingRules(config.denyOnly || [], logTag))

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
  if (writeAllowPaths && writeAllowPaths.length > 0) {
    for (const pathPattern of writeAllowPaths) {
      const normalizedPath = normalizePathForSandbox(pathPattern)

      for (const op of ['file-write-unlink', 'file-write-create'] as const) {
        if (containsGlobChars(normalizedPath)) {
          const regexPattern = globToRegex(normalizedPath)
          rules.push(
            `(allow ${op}`,
            `  (regex ${escapePath(regexPattern)})`,
            `  (with message "${logTag}"))`,
          )
        } else {
          rules.push(
            `(allow ${op}`,
            `  (subpath ${escapePath(normalizedPath)})`,
            `  (with message "${logTag}"))`,
          )
        }
      }
    }
  }

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
  for (const pathPattern of config.allowOnly || []) {
    const normalizedPath = normalizePathForSandbox(pathPattern)

    if (containsGlobChars(normalizedPath)) {
      // Use regex matching for glob patterns
      const regexPattern = globToRegex(normalizedPath)
      rules.push(
        `(allow file-write*`,
        `  (regex ${escapePath(regexPattern)})`,
        `  (with message "${logTag}"))`,
      )
    } else {
      // Use subpath matching for literal paths
      rules.push(
        `(allow file-write*`,
        `  (subpath ${escapePath(normalizedPath)})`,
        `  (with message "${logTag}"))`,
      )
    }
  }

  // Combine user-specified and mandatory deny patterns (no ripgrep needed on macOS)
  const denyPaths = [
    ...(config.denyWithinAllow || []),
    ...macGetMandatoryDenyPatterns(allowGitConfig),
  ]

  for (const pathPattern of denyPaths) {
    const normalizedPath = normalizePathForSandbox(pathPattern)

    if (containsGlobChars(normalizedPath)) {
      // Use regex matching for glob patterns
      const regexPattern = globToRegex(normalizedPath)
      rules.push(
        `(deny file-write*`,
        `  (regex ${escapePath(regexPattern)})`,
        `  (with message "${logTag}"))`,
      )
    } else {
      // Use subpath matching for literal paths
      rules.push(
        `(deny file-write*`,
        `  (subpath ${escapePath(normalizedPath)})`,
        `  (with message "${logTag}"))`,
      )
    }
  }

  // Block file movement to prevent bypass via mv/rename
  rules.push(...generateMoveBlockingRules(denyPaths, logTag))

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
  const writeAllowPaths = writeConfig?.allowOnly
  profile.push('; File read')
  profile.push(...generateReadRules(readConfig, logTag, writeAllowPaths))
  profile.push('')

  // Write rules
  profile.push('; File write')
  profile.push(...generateWriteRules(writeConfig, logTag, allowGitConfig))

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
    commandLabel,
    needsNetworkRestriction,
    httpProxyPort,
    socksProxyPort,
    proxyAuthToken,
    caCertPath,
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
  // the attribution key, which is the caller's commandLabel when the
  // executed string differs from the one violations are looked up by.
  const attributionCommand = commandLabel ?? command
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

  // Seatbelt's (remote ip "localhost:*") filter — used for the
  // allowLocalBinding outbound rule above — matches 127.0.0.1 and ::1 but not
  // the IPv4-mapped IPv6 form ::ffff:127.0.0.1. Modern Java defaults to
  // AF_INET6 dual-stack sockets, so a Java client connecting to 127.0.0.1
  // reaches the kernel as ::ffff:127.0.0.1 and is denied. Forcing the IPv4
  // stack makes Java open AF_INET sockets so loopback connect matches the
  // Seatbelt filter. The flag is appended after any inherited
  // JAVA_TOOL_OPTIONS unless that var is on the credential-deny list, in
  // which case the inherited value is dropped so the deny holds.
  if (allowLocalBinding && needsNetworkRestriction) {
    const flag = '-Djava.net.preferIPv4Stack=true'
    const denied = (unsetEnvVars ?? []).includes('JAVA_TOOL_OPTIONS')
    const inherited = denied ? '' : (process.env.JAVA_TOOL_OPTIONS ?? '')
    const value = inherited.includes(flag)
      ? inherited
      : [inherited, flag].filter(Boolean).join(' ')
    proxyEnvArgs.push(`JAVA_TOOL_OPTIONS=${value}`)
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
          command = decodeSandboxedCommand(encodedCommand)
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
