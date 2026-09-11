import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import * as fs from 'node:fs'
import { execSync } from 'node:child_process'
import { homedir } from 'node:os'
import { logForDebugging } from '../utils/debug.js'

// Cache for path lookups (key: explicit path or empty string, value: resolved path or null)
const applySeccompPathCache = new Map<string, string | null>()

// Cache for global npm paths (computed once per process)
let cachedGlobalNpmPaths: string[] | null = null

/**
 * Get paths to check for globally installed @anthropic-ai/sandbox-runtime package.
 * This is used as a fallback when the binaries aren't bundled (e.g., native builds).
 */
export function getGlobalNpmPaths(): string[] {
  if (cachedGlobalNpmPaths) return cachedGlobalNpmPaths

  const paths: string[] = []

  // Try to get the actual global npm root
  try {
    const npmRoot = execSync('npm root -g', {
      encoding: 'utf8',
      timeout: 5000,
      stdio: ['pipe', 'pipe', 'ignore'],
    }).trim()
    if (npmRoot) {
      paths.push(join(npmRoot, '@anthropic-ai', 'sandbox-runtime'))
    }
  } catch {
    // npm not available or failed
  }

  // Common global npm locations as fallbacks
  const home = homedir()
  paths.push(
    // npm global (Linux/macOS)
    join('/usr', 'lib', 'node_modules', '@anthropic-ai', 'sandbox-runtime'),
    join(
      '/usr',
      'local',
      'lib',
      'node_modules',
      '@anthropic-ai',
      'sandbox-runtime',
    ),
    // npm global with prefix (common on macOS with homebrew)
    join(
      '/opt',
      'homebrew',
      'lib',
      'node_modules',
      '@anthropic-ai',
      'sandbox-runtime',
    ),
    // User-local npm global
    join(
      home,
      '.npm',
      'lib',
      'node_modules',
      '@anthropic-ai',
      'sandbox-runtime',
    ),
    join(
      home,
      '.npm-global',
      'lib',
      'node_modules',
      '@anthropic-ai',
      'sandbox-runtime',
    ),
  )

  cachedGlobalNpmPaths = paths
  return paths
}

/**
 * Map Node.js process.arch to our vendor directory architecture names
 * Returns null for unsupported architectures
 */
function getVendorArchitecture(): string | null {
  const arch = process.arch as string
  switch (arch) {
    case 'x64':
    case 'x86_64':
      return 'x64'
    case 'arm64':
    case 'aarch64':
      return 'arm64'
    case 'ppc64':
      // Node.js reports 'ppc64' on ppc64le Linux; the BPF filter and
      // apply-seccomp build target the ELFv2 little-endian ABI only, so the
      // vendor directory is named explicitly.
      return 'ppc64le'
    case 'ia32':
    case 'x86':
      // TODO: Add support for 32-bit x86 (ia32)
      // Currently blocked because the seccomp filter does not block the socketcall() syscall,
      // which is used on 32-bit x86 for all socket operations (socket, socketpair, bind, connect, etc.).
      // On 32-bit x86, the direct socket() syscall doesn't exist - instead, all socket operations
      // are multiplexed through socketcall(SYS_SOCKET, ...), socketcall(SYS_SOCKETPAIR, ...), etc.
      //
      // To properly support 32-bit x86, we need to:
      // 1. Build a separate i386 BPF filter (BPF bytecode is architecture-specific)
      // 2. Modify vendor/seccomp-src/seccomp-unix-block.c to conditionally add rules that block:
      //    - socketcall(SYS_SOCKET, [AF_UNIX, ...])
      //    - socketcall(SYS_SOCKETPAIR, [AF_UNIX, ...])
      // 3. This requires complex BPF logic to inspect socketcall's sub-function argument
      //
      // Until then, 32-bit x86 is not supported to avoid a security bypass.
      logForDebugging(
        `[SeccompFilter] 32-bit x86 (ia32) is not currently supported due to missing socketcall() syscall blocking. ` +
          `The current seccomp filter only blocks socket(AF_UNIX, ...), but on 32-bit x86, socketcall() can be used to bypass this.`,
        { level: 'error' },
      )
      return null
    default:
      logForDebugging(
        `[SeccompFilter] Unsupported architecture: ${arch}. Only x64 and arm64 are supported.`,
      )
      return null
  }
}

/**
 * Get local paths to check for seccomp files (bundled or package installs).
 */
function getLocalSeccompPaths(filename: string): string[] {
  const arch = getVendorArchitecture()
  if (!arch) return []

  const baseDir = dirname(fileURLToPath(import.meta.url))
  const relativePath = join('vendor', 'seccomp', arch, filename)

  return [
    join(baseDir, relativePath), // bundled: same directory as bundle (e.g., when bundled into claude-cli)
    join(baseDir, '..', '..', relativePath), // package root: vendor/seccomp/...
    join(baseDir, '..', relativePath), // dist: dist/vendor/seccomp/...
  ]
}

/**
 * Get the path to the apply-seccomp binary from the vendor directory
 * Returns the path if it exists, null otherwise
 *
 * Pre-built apply-seccomp binaries are organized by architecture:
 * - vendor/seccomp/{x64,arm64}/apply-seccomp
 *
 * Tries multiple paths for resilience:
 * 0. Explicit path provided via parameter (checked first if provided)
 * 1. vendor/seccomp/{arch}/apply-seccomp (bundled - when bundled into consuming packages)
 * 2. ../../vendor/seccomp/{arch}/apply-seccomp (package root - standard npm installs)
 * 3. ../vendor/seccomp/{arch}/apply-seccomp (dist/vendor - for bundlers)
 * 4. Global npm install (if seccompBinaryPath not provided) - for native builds
 *
 * @param seccompBinaryPath - Optional explicit path to the apply-seccomp binary. If provided
 *   and exists, it will be used. If not provided, falls back to searching local paths and
 *   then global npm install (for native builds where vendor directory isn't bundled).
 */
export function getApplySeccompBinaryPath(
  seccompBinaryPath?: string,
): string | null {
  const cacheKey = seccompBinaryPath ?? ''
  if (applySeccompPathCache.has(cacheKey)) {
    return applySeccompPathCache.get(cacheKey)!
  }

  const result = findApplySeccompPath(seccompBinaryPath)
  applySeccompPathCache.set(cacheKey, result)
  return result
}

function findApplySeccompPath(seccompBinaryPath?: string): string | null {
  // Check explicit path first (highest priority)
  if (seccompBinaryPath) {
    if (fs.existsSync(seccompBinaryPath)) {
      logForDebugging(
        `[SeccompFilter] Using apply-seccomp binary from explicit path: ${seccompBinaryPath}`,
      )
      return seccompBinaryPath
    }
    logForDebugging(
      `[SeccompFilter] Explicit path provided but file not found: ${seccompBinaryPath}`,
    )
  }

  const arch = getVendorArchitecture()
  if (!arch) {
    logForDebugging(
      `[SeccompFilter] Cannot find apply-seccomp binary: unsupported architecture ${process.arch}`,
    )
    return null
  }

  logForDebugging(
    `[SeccompFilter] Looking for apply-seccomp binary for architecture: ${arch}`,
  )

  // Check local paths first (bundled or package install)
  for (const binaryPath of getLocalSeccompPaths('apply-seccomp')) {
    if (fs.existsSync(binaryPath)) {
      logForDebugging(
        `[SeccompFilter] Found apply-seccomp binary: ${binaryPath} (${arch})`,
      )
      return binaryPath
    }
  }

  // Fallback: check global npm install (for native builds without bundled vendor)
  for (const globalBase of getGlobalNpmPaths()) {
    const binaryPath = join(
      globalBase,
      'vendor',
      'seccomp',
      arch,
      'apply-seccomp',
    )
    if (fs.existsSync(binaryPath)) {
      logForDebugging(
        `[SeccompFilter] Found apply-seccomp binary in global install: ${binaryPath} (${arch})`,
      )
      return binaryPath
    }
  }

  logForDebugging(
    `[SeccompFilter] apply-seccomp binary not found in any expected location (${arch})`,
  )
  return null
}
