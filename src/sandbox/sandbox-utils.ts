import { homedir } from 'os'
import * as path from 'path'
import * as fs from 'fs'
import { getPlatform } from '../utils/platform.js'
import { logForDebugging } from '../utils/debug.js'

/**
 * Dangerous files that should be protected from writes.
 * These files can be used for code execution or data exfiltration.
 */
export const DANGEROUS_FILES = [
  '.gitconfig',
  '.gitmodules',
  '.bashrc',
  '.bash_profile',
  '.zshrc',
  '.zprofile',
  '.profile',
  '.ripgreprc',
  '.mcp.json',
] as const

/**
 * Dangerous directories that should be protected from writes.
 * These directories contain sensitive configuration or executable files.
 */
export const DANGEROUS_DIRECTORIES = ['.git', '.vscode', '.idea'] as const

/**
 * Get the list of dangerous directories to deny writes to.
 * Excludes .git since we need it writable for git operations -
 * instead we block specific paths within .git (hooks and config).
 */
export function getDangerousDirectories(): string[] {
  return [
    ...DANGEROUS_DIRECTORIES.filter(d => d !== '.git'),
    '.claude/commands',
    '.claude/agents',
  ]
}

/**
 * Normalizes a path for case-insensitive comparison.
 * This prevents bypassing security checks using mixed-case paths on case-insensitive
 * filesystems (macOS/Windows) like `.cLauDe/Settings.locaL.json`.
 *
 * We always normalize to lowercase regardless of platform for consistent security.
 * @param path The path to normalize
 * @returns The lowercase path for safe comparison
 */
export function normalizeCaseForComparison(pathStr: string): string {
  return pathStr.toLowerCase()
}

/**
 * `p` is `dir` itself or lies beneath it, by path segment ('/x' is not under
 * '/xy'); root-aware, since '/' + '/' is a prefix of nothing.
 */
export function isAtOrUnder(p: string, dir: string): boolean {
  return p === dir || p.startsWith(dir === '/' ? '/' : dir + '/')
}

/** `p` lies strictly beneath `dir` (isAtOrUnder, excluding `dir` itself). */
export function isStrictlyUnder(p: string, dir: string): boolean {
  return p !== dir && isAtOrUnder(p, dir)
}

/**
 * Check if a path pattern contains glob characters
 */
export function containsGlobChars(pathPattern: string): boolean {
  return (
    pathPattern.includes('*') ||
    pathPattern.includes('?') ||
    pathPattern.includes('[') ||
    pathPattern.includes(']')
  )
}

/**
 * Windows-specific glob-char check. `[` and `]` are NOT
 * metachars here — they are legal in Win32 filenames, so a
 * literal `C:\app\[prod].env` must route to the literal-path
 * branch, not glob expansion (where it would match nothing and
 * be silently dropped). Only `*` and `?` trigger expansion.
 */
export function containsGlobCharsWin(p: string): boolean {
  return p.includes('*') || p.includes('?')
}

/** Platform-appropriate glob-char check. */
function containsGlobCharsForPlatform(p: string): boolean {
  return getPlatform() === 'windows'
    ? containsGlobCharsWin(p)
    : containsGlobChars(p)
}

/**
 * Strip the Win32 `\\?\` extended-path prefix so the residue is
 * a conventional absolute path (drive-letter or UNC) with no `?`
 * for the glob-char check to misclassify. `\\?\UNC\srv\share\f`
 * → `\\srv\share\f`; `\\?\C:\f` → `C:\f`; anything else → input.
 * The UNC marker is matched case-insensitively (Windows accepts
 * `\\?\unc\…` in any casing; a case-sensitive check would fall
 * through to the 4-char strip and yield a cwd-relative residue).
 */
export function stripExtendedPathPrefix(p: string): string {
  if (/^\\\\\?\\unc\\/i.test(p)) return '\\\\' + p.slice(8)
  if (p.startsWith('\\\\?\\')) return p.slice(4)
  return p
}

/**
 * True for a Windows UNC path in any spelling — `\\server\share\…`,
 * extended-length `\\?\UNC\server\share\…`, device-namespace
 * `\\.\UNC\server\share\…` (all any casing, either separator).
 * Delegates path-form normalization to
 * `path.win32.toNamespacedPath` — every UNC spelling canonicalizes
 * to `\\?\UNC\…` — so the check is "namespaced form starts with
 * `\\?\UNC\` (or `\\.\UNC\`)". Drive-local forms (`C:\…`,
 * `\\?\C:\…`), other device paths (`\\.\pipe\…`), relative paths
 * (resolved against a local cwd), and server-only `\\srv` (no
 * share) are all false.
 *
 * The broker uses this to skip `stat`/`realpath` on UNC **literals**
 * (see {@link normalizePathForSandbox}): any such call is an SMB
 * request carrying the **real user's** NTLM credentials to whatever
 * host the path names — a forced-auth / path-encoded-exfil channel
 * if the path is model-influenced. Literals pass through raw
 * (resolution failures surface at `srt-win` stamp/grant time); a
 * UNC **glob** still walks the share with real-user credentials —
 * the user consented by naming their own share in the config.
 * Defense-in-depth: the primary embedder already gates
 * model-provided cwd/paths upstream.
 */
export function isUncPath(p: string): boolean {
  const ns = path.win32.toNamespacedPath(p)
  // Already-namespaced input passes through `toNamespacedPath`
  // verbatim (casing and separators preserved), so match the UNC
  // marker case-insensitively with either separator. `[?.]` also
  // catches the device-namespace `\\.\UNC\…` form — that is a real
  // network access, not a local device.
  return /^[\\/]{2}[?.][\\/]unc[\\/]/i.test(ns)
}

/**
 * Remove trailing /** glob suffix from a path pattern
 * Used to normalize path patterns since /** just means "directory and everything under it"
 */
export function removeTrailingGlobSuffix(pathPattern: string): string {
  const stripped = pathPattern.replace(/\/\*\*$/, '')
  return stripped || '/'
}

/**
 * Check if a symlink resolution crosses expected path boundaries.
 *
 * When resolving symlinks for sandbox path normalization, we need to ensure
 * the resolved path doesn't unexpectedly broaden the scope. This function
 * returns true if the resolved path is an ancestor of the original path
 * or resolves to a system root, which would indicate the symlink points
 * outside expected boundaries.
 *
 * @param originalPath - The original path before symlink resolution
 * @param resolvedPath - The path after fs.realpathSync() resolution
 * @returns true if the resolved path is outside expected boundaries
 */
export function isSymlinkOutsideBoundary(
  originalPath: string,
  resolvedPath: string,
): boolean {
  const normalizedOriginal = path.normalize(originalPath)
  const normalizedResolved = path.normalize(resolvedPath)

  // Same path after normalization - OK
  if (normalizedResolved === normalizedOriginal) {
    return false
  }

  // Handle macOS /tmp -> /private/tmp canonical resolution
  // This is a legitimate system symlink that should be allowed
  // /tmp/claude -> /private/tmp/claude is OK
  // /var/folders/... -> /private/var/folders/... is OK
  if (
    normalizedOriginal.startsWith('/tmp/') &&
    normalizedResolved === '/private' + normalizedOriginal
  ) {
    return false
  }
  if (
    normalizedOriginal.startsWith('/var/') &&
    normalizedResolved === '/private' + normalizedOriginal
  ) {
    return false
  }
  // Also handle the reverse: /private/tmp/... resolving to itself
  if (
    normalizedOriginal.startsWith('/private/tmp/') &&
    normalizedResolved === normalizedOriginal
  ) {
    return false
  }
  if (
    normalizedOriginal.startsWith('/private/var/') &&
    normalizedResolved === normalizedOriginal
  ) {
    return false
  }

  // If resolved path is "/" it's outside expected boundaries
  if (normalizedResolved === '/') {
    return true
  }

  // If resolved path is very short (single component like /tmp, /usr, /var),
  // it's likely outside expected boundaries
  const resolvedParts = normalizedResolved.split('/').filter(Boolean)
  if (resolvedParts.length <= 1) {
    return true
  }

  // If original path starts with resolved path, the resolved path is an ancestor
  // e.g., /tmp/claude -> /tmp means the symlink points to a broader scope
  if (normalizedOriginal.startsWith(normalizedResolved + '/')) {
    return true
  }

  // Also check the canonical form of the original path for macOS
  // e.g., /tmp/claude should also be checked as /private/tmp/claude
  let canonicalOriginal = normalizedOriginal
  if (normalizedOriginal.startsWith('/tmp/')) {
    canonicalOriginal = '/private' + normalizedOriginal
  } else if (normalizedOriginal.startsWith('/var/')) {
    canonicalOriginal = '/private' + normalizedOriginal
  }

  if (
    canonicalOriginal !== normalizedOriginal &&
    canonicalOriginal.startsWith(normalizedResolved + '/')
  ) {
    return true
  }

  // STRICT CHECK: Only allow resolutions that stay within the expected path tree
  // The resolved path must either:
  // 1. Start with the original path (deeper/same) - already covered by returning false below
  // 2. Start with the canonical original (deeper/same under canonical form)
  // 3. BE the canonical form of the original (e.g., /tmp/x -> /private/tmp/x)
  // Any other resolution (e.g., /tmp/claude -> /Users/dworken) is outside expected bounds

  const resolvedStartsWithOriginal = normalizedResolved.startsWith(
    normalizedOriginal + '/',
  )
  const resolvedStartsWithCanonical =
    canonicalOriginal !== normalizedOriginal &&
    normalizedResolved.startsWith(canonicalOriginal + '/')
  const resolvedIsCanonical =
    canonicalOriginal !== normalizedOriginal &&
    normalizedResolved === canonicalOriginal
  const resolvedIsSame = normalizedResolved === normalizedOriginal

  // If resolved path is not within expected tree, it's outside boundary
  if (
    !resolvedIsSame &&
    !resolvedIsCanonical &&
    !resolvedStartsWithOriginal &&
    !resolvedStartsWithCanonical
  ) {
    return true
  }

  // Allow resolution to same directory level or deeper within expected tree
  return false
}

/**
 * Expand a leading `~` to the home directory. Handles bare `~`,
 * `~/…`, and (on Windows only) the `~\…` form so callers don't each
 * open-code the variants. `~\` is gated to Windows because `\` is a
 * valid POSIX filename byte — `~\foo` is a legal relative filename
 * on Linux/macOS and must NOT tilde-expand there.
 */
export function expandTilde(p: string): string {
  if (p === '~') return homedir()
  if (
    p.startsWith('~/') ||
    (process.platform === 'win32' && p.startsWith('~\\'))
  ) {
    return homedir() + p.slice(1)
  }
  return p
}

/**
 * Expand Windows-style `%USERPROFILE%` / `%HOMEDRIVE%` / `%HOMEPATH%`
 * references to the real user's home directory. Case-insensitive;
 * idempotent. Applied by {@link normalizePathForSandbox}'s Windows
 * pre-processing so every filesystem-config path field
 * (`allowRead`/`allowWrite`/`denyRead`/`denyWrite`) accepts these
 * forms uniformly.
 *
 * `%HOMEPATH%` is drive-RELATIVE (`\Users\name`) and `%HOMEDRIVE%` is
 * the drive-only (`C:`) — the split matches how cmd.exe defines them,
 * so `%HOMEDRIVE%%HOMEPATH%` composes to the full home path.
 */
export function expandWindowsEnvRefs(p: string): string {
  const home = homedir()
  const drive = /^[A-Za-z]:/.test(home) ? home.slice(0, 2) : ''
  const homePath = drive ? home.slice(2) : home
  return p
    .replace(/%USERPROFILE%/gi, home)
    .replace(/%HOMEDRIVE%/gi, drive)
    .replace(/%HOMEPATH%/gi, homePath)
}

/**
 * Normalize a path for use in sandbox configurations
 * Handles:
 * - Tilde (~) expansion for home directory
 * - Relative paths (./foo, ../foo, etc.) converted to absolute
 * - Absolute paths remain unchanged
 * - Symlinks are resolved to their real paths for non-glob patterns
 * - Glob patterns preserve wildcards after path normalization
 *
 * Returns the absolute path with symlinks resolved (or normalized glob pattern)
 */
export function normalizePathForSandbox(pathPattern: string): string {
  const cwd = process.cwd()
  // Windows pre-processing: expand `%USERPROFILE%` / `%HOMEDRIVE%` /
  // `%HOMEPATH%`, strip the `\\?\` / `\\?\UNC\` extended prefix (its
  // `?` is a literal, not a glob char), and uppercase the drive
  // letter so `c:\…` and `C:\…` normalize identically.
  if (getPlatform() === 'windows') {
    pathPattern = stripExtendedPathPrefix(expandWindowsEnvRefs(pathPattern))
    if (/^[a-z]:/.test(pathPattern)) {
      pathPattern = pathPattern[0].toUpperCase() + pathPattern.slice(1)
    }
    // UNC literal: return as-is (separators normalised only) — no
    // stat/realpath. A UNC *glob* falls through to the glob walk
    // below (user-trusted share). See {@link isUncPath}.
    if (isUncPath(pathPattern) && !containsGlobCharsWin(pathPattern)) {
      return path.win32.normalize(pathPattern)
    }
  }
  // POSIX: strip trailing slashes from non-glob spellings before any
  // resolution. Consumers on the Linux and macOS paths compare spellings by
  // exact match and `path + '/'` prefixes — which a preserved slash silently
  // defeats ('<dir>//') — and the realpath-acceptance checks below treat a
  // slash-only difference as a mismatch. bwrap binds and sbpl subpath
  // filters treat 'dir' and 'dir/' identically, so only the comparisons
  // change. Glob spellings are left untouched: a slash after a glob segment
  // is semantic ('/x/*/' compiles to a different regex than '/x/*'). On
  // Windows a trailing separator is the directory marker for absent deny
  // targets (srt#404) and must survive.
  if (
    getPlatform() !== 'windows' &&
    pathPattern.endsWith('/') &&
    pathPattern !== '/' &&
    !containsGlobCharsForPlatform(pathPattern)
  ) {
    pathPattern = pathPattern.replace(/\/+$/, '') || '/'
  }
  let normalizedPath = expandTilde(pathPattern)

  if (normalizedPath !== pathPattern) {
    // tilde was expanded above
  } else if (pathPattern.startsWith('./') || pathPattern.startsWith('../')) {
    // Convert relative to absolute based on current working directory
    normalizedPath = path.resolve(cwd, pathPattern)
  } else if (!path.isAbsolute(pathPattern)) {
    // Handle other relative paths (e.g., ".", "..", "foo/bar")
    normalizedPath = path.resolve(cwd, pathPattern)
  }

  // For glob patterns, resolve symlinks for the directory portion only
  if (containsGlobCharsForPlatform(normalizedPath)) {
    // Extract the static directory prefix before glob characters
    // (on Windows, `[`/`]` are literal so only split on `*`/`?`).
    const splitRe = getPlatform() === 'windows' ? /[*?]/ : /[*?[\]]/
    const staticPrefix = normalizedPath.split(splitRe)[0]
    if (staticPrefix && staticPrefix !== '/') {
      // Get the directory containing the glob pattern
      // If staticPrefix ends with /, remove it to get the directory
      const baseDir = staticPrefix.endsWith('/')
        ? staticPrefix.slice(0, -1)
        : path.dirname(staticPrefix)

      // Try to resolve symlinks for the base directory
      try {
        const resolvedBaseDir = fs.realpathSync(baseDir)
        // Validate that resolution stays within expected boundaries
        if (!isSymlinkOutsideBoundary(baseDir, resolvedBaseDir)) {
          // Reconstruct the pattern with the resolved directory
          const patternSuffix = normalizedPath.slice(baseDir.length)
          return resolvedBaseDir + patternSuffix
        }
        // If resolution would broaden scope, keep original pattern
      } catch {
        // If directory doesn't exist or can't be resolved, keep the original pattern
      }
    }
    return normalizedPath
  }

  // Resolve symlinks to real paths to avoid bwrap issues
  // Validate that the resolution stays within expected boundaries
  try {
    const resolvedPath = fs.realpathSync(normalizedPath)

    // Only use resolved path if it doesn't cross boundary (e.g., symlink to parent dir)
    if (isSymlinkOutsideBoundary(normalizedPath, resolvedPath)) {
      // Symlink points outside expected boundaries - keep original path
    } else {
      normalizedPath = resolvedPath
    }
  } catch {
    // If path doesn't exist or can't be resolved, keep the normalized path
  }

  return normalizedPath
}

/**
 * Get recommended system paths that should be writable for commands to work properly
 *
 * WARNING: These default paths are intentionally broad for compatibility but may
 * allow access to files from other processes. In highly security-sensitive
 * environments, you should configure more restrictive write paths.
 */
export function getDefaultWritePaths(): string[] {
  const homeDir = homedir()
  const recommendedPaths = [
    '/dev/stdout',
    '/dev/stderr',
    '/dev/null',
    '/dev/tty',
    '/dev/dtracehelper',
    '/dev/autofs_nowait',
    '/tmp/claude',
    '/private/tmp/claude',
    path.join(homeDir, '.npm/_logs'),
    path.join(homeDir, '.claude/debug'),
  ]

  return recommendedPaths
}

/**
 * Generate proxy environment variables for sandboxed processes
 */
/**
 * Per-tool trust-store env vars set to the TLS-termination CA cert path so
 * HTTPS clients in the sandboxed child accept proxy-minted certs.
 */
export const CA_TRUST_VARS = [
  'NODE_EXTRA_CA_CERTS',
  'SSL_CERT_FILE',
  'CURL_CA_BUNDLE',
  'REQUESTS_CA_BUNDLE',
  'PIP_CERT',
  'GIT_SSL_CAINFO',
  'AWS_CA_BUNDLE',
  'CARGO_HTTP_CAINFO',
  'DENO_CERT',
  // gcloud ignores SSL_CERT_FILE/REQUESTS_CA_BUNDLE; this is its dedicated
  // override (maps to core/custom_ca_certs_file).
  'CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE',
  // Nix-built binaries are patched to read this instead of SSL_CERT_FILE, and
  // it's typically pre-set to the Nix system bundle in the parent env, so we
  // must override it explicitly.
  'NIX_SSL_CERT_FILE',
] as const

export function generateProxyEnvVars(
  httpProxyPort?: number,
  socksProxyPort?: number,
  caCertPath?: string,
  proxyAuthToken?: string,
  skipTmpdir?: boolean,
  encodedCommand?: string,
): string[] {
  // When the proxy requires auth, embed the credential in the URL so clients
  // send Proxy-Authorization automatically. Only the sandbox child sees this
  // env, so the token never reaches host processes.
  //
  // The username carries the per-command encodedCommand so the proxy can
  // attribute denials to a specific invocation (see
  // SandboxViolationStore). Standard base64 is percent-encoded in the URL so
  // `+/=` survive userinfo parsing; clients URL-decode before building the
  // Basic header / RFC 1929 frame, so the proxy receives the raw base64.
  const userRaw = proxyUsernameFor(encodedCommand)
  const userPct =
    userRaw === PROXY_AUTH_USER ? userRaw : encodeURIComponent(userRaw)
  const auth = proxyAuthToken ? `${userPct}:${proxyAuthToken}@` : ''
  const envVars: string[] = [`SANDBOX_RUNTIME=1`]
  // TMPDIR is overridden so temp-file writers land in a path the FS sandbox
  // allows (getDefaultWritePaths). When filesystem policy is disabled
  // (writeConfig === undefined → skipTmpdir), the host TMPDIR is already
  // writable and /tmp/claude may not exist, so leave it untouched.
  // CLAUDE_CODE_TMPDIR is the current name; CLAUDE_TMPDIR is kept for
  // backwards compatibility (#141).
  if (!skipTmpdir) {
    const tmpdir =
      process.env.CLAUDE_CODE_TMPDIR ||
      process.env.CLAUDE_TMPDIR ||
      '/tmp/claude'
    envVars.push(`TMPDIR=${tmpdir}`)
  }

  // When TLS termination is configured, the child only ever sees proxy-minted
  // certs signed by the configured CA. Point the common per-tool trust-store
  // env vars at it so HTTPS clients accept those certs.
  if (caCertPath) {
    for (const v of CA_TRUST_VARS) {
      envVars.push(`${v}=${caCertPath}`)
    }
  }

  // If no proxy ports provided, return minimal env vars
  if (!httpProxyPort && !socksProxyPort) {
    return envVars
  }

  // Always set NO_PROXY to exclude localhost and private networks from
  // proxying. *.local is intentionally absent: under network restriction the
  // child has no usable resolver/routes (bwrap --unshare-net on Linux,
  // loopback-only under seatbelt), so a NO_PROXY match makes the client try
  // direct getaddrinfo() and fail. Routing .local hostnames through the proxy
  // lets the parent resolve them (e.g. Kubernetes *.svc.cluster.local).
  const noProxyAddresses = [
    'localhost',
    '127.0.0.1',
    '::1',
    '169.254.0.0/16', // Link-local
    '10.0.0.0/8', // Private network
    '172.16.0.0/12', // Private network
    '192.168.0.0/16', // Private network
  ].join(',')
  envVars.push(`NO_PROXY=${noProxyAddresses}`)
  envVars.push(`no_proxy=${noProxyAddresses}`)

  if (httpProxyPort) {
    envVars.push(`HTTP_PROXY=http://${auth}localhost:${httpProxyPort}`)
    envVars.push(`HTTPS_PROXY=http://${auth}localhost:${httpProxyPort}`)
    // Lowercase versions for compatibility with some tools
    envVars.push(`http_proxy=http://${auth}localhost:${httpProxyPort}`)
    envVars.push(`https_proxy=http://${auth}localhost:${httpProxyPort}`)
    if (proxyAuthToken) {
      // Pre-send Basic so git never gets a 407 and never invokes a
      // credential helper for the proxy URL (Windows GCM intercepts the
      // challenge and the URL-embedded password doesn't survive it).
      envVars.push(`GIT_CONFIG_PARAMETERS='http.proxyAuthMethod=basic'`)
    }
  }

  // The URL to advertise to clients that need a general-purpose,
  // CONNECT-capable proxy. The mux serves HTTP CONNECT and SOCKS on the same
  // advertised port, so http:// works for everyone: clients that only speak
  // CONNECT get a URL they understand, and anything that actually speaks
  // SOCKS to it still reaches the SOCKS handler. Falls back to socks5h://
  // only when no HTTP proxy port exists, which no current caller configures.
  const connectProxyUrl = httpProxyPort
    ? `http://${auth}localhost:${httpProxyPort}`
    : `socks5h://${auth}localhost:${socksProxyPort}`

  // ALL_PROXY: prefer the HTTP proxy URL over SOCKS. httpx (and similar
  // Python clients) eagerly import `socksio` at client construction when
  // ALL_PROXY is a socks5h:// URL and crash with ImportError in envs that
  // lack the package — before any bytes hit the wire, so the mux's
  // protocol sniffing can't help.
  envVars.push(`ALL_PROXY=${connectProxyUrl}`)
  envVars.push(`all_proxy=${connectProxyUrl}`)

  // gRPC-based tools. gRPC C-core (every google-cloud-* Python client, and
  // grpc-js) only understands HTTP CONNECT proxies. Given a socks5h:// URL it
  // logs "'socks5h' scheme not supported in proxy URI", ignores the var, and
  // resolves the target directly via c-ares — which the sandbox blocks, so
  // the client dies with "address lookup failed / Could not contact DNS
  // servers" instead of falling back to https_proxy. Not gated on
  // socksProxyPort: the value no longer depends on it, and a gRPC client in
  // an HTTP-only sandbox needs this var just as much.
  envVars.push(`GRPC_PROXY=${connectProxyUrl}`)
  envVars.push(`grpc_proxy=${connectProxyUrl}`)

  if (socksProxyPort) {
    // Configure Git to use SSH through the proxy so DNS resolution happens outside the sandbox.
    // ControlMaster/ControlPath are disabled because SSH connection multiplexing breaks inside
    // the sandbox: the mux socket path from the user's ssh config (typically under ~/.ssh) is
    // not an allowed Unix socket path, and OpenSSH treats a mux listener bind failure as fatal
    // even with ControlMaster=auto — it exits right after authentication, before running the
    // git command. Command-line options take precedence over ssh_config, so this neutralizes
    // any user ControlMaster setup. ControlPath=none is needed in addition to ControlMaster=no:
    // with ControlMaster=no alone, ssh still tries to connect to an existing mux socket at the
    // configured ControlPath.
    const sshMuxOverride = '-o ControlMaster=no -o ControlPath=none'
    const platform = getPlatform()
    if (platform === 'macos') {
      // macOS: use BSD nc SOCKS5 proxy support (-X 5 -x). nc has no SOCKS5
      // auth, so when proxyAuthToken is set, git-over-ssh fails at the SOCKS
      // handshake — use git-over-https (HTTP_PROXY carries the credential).
      envVars.push(
        `GIT_SSH_COMMAND=ssh ${sshMuxOverride} -o ProxyCommand='nc -X 5 -x localhost:${socksProxyPort} %h %p'`,
      )
    } else if (platform === 'linux' && httpProxyPort) {
      // Linux: use socat HTTP CONNECT via the HTTP proxy bridge.
      // socat is already a required Linux sandbox dependency, and PROXY: is
      // portable across all socat versions (unlike SOCKS5-CONNECT which needs >= 1.8.0).
      const socatAuth = proxyAuthToken
        ? `,proxyauth=${userRaw}:${proxyAuthToken}`
        : ''
      envVars.push(
        `GIT_SSH_COMMAND=ssh ${sshMuxOverride} -o ProxyCommand='socat - PROXY:localhost:%h:%p,proxyport=${httpProxyPort}${socatAuth}'`,
      )
    }

    // FTP proxy support (use socks5h for DNS resolution through proxy).
    // Deliberately not connectProxyUrl: given an http:// ftp_proxy, curl does
    // not CONNECT-tunnel by default, it gateways the transfer as
    // `GET ftp://host/path HTTP/1.1` to the proxy — which the mux does not
    // implement, and an env var can't ask curl for --proxytunnel. socks5h is
    // transparent at the TCP layer, so it is the value that works here.
    envVars.push(`FTP_PROXY=socks5h://${auth}localhost:${socksProxyPort}`)
    envVars.push(`ftp_proxy=socks5h://${auth}localhost:${socksProxyPort}`)

    // rsync proxy support — RSYNC_PROXY is host:port only, no userinfo. With
    // proxy auth on, rsync via this var fails at the CONNECT (407); use SSH
    // transport or wrap with proxychains instead.
    envVars.push(`RSYNC_PROXY=localhost:${socksProxyPort}`)

    // Database tools NOTE: Most database clients don't have built-in proxy support
    // You typically need to use SSH tunneling or a SOCKS wrapper like tsocks/proxychains

    // Docker CLI uses HTTP for the API
    // This makes Docker use the HTTP proxy for registry operations
    envVars.push(
      `DOCKER_HTTP_PROXY=http://${auth}localhost:${httpProxyPort || socksProxyPort}`,
    )
    envVars.push(
      `DOCKER_HTTPS_PROXY=http://${auth}localhost:${httpProxyPort || socksProxyPort}`,
    )

    // Kubernetes kubectl - uses standard HTTPS_PROXY
    // kubectl respects HTTPS_PROXY which we already set above

    // AWS CLI - uses standard HTTPS_PROXY (v2 supports it well)
    // AWS CLI v2 respects HTTPS_PROXY which we already set above

    // Google Cloud SDK - has specific proxy settings.
    // proxy/type names the protocol the *proxy* speaks, not the traffic it
    // tunnels. Our HTTP CONNECT proxy carries TLS to Google APIs, so the
    // correct value is "http" (gcloud only accepts http, http_no_tunnel,
    // socks4, socks5; "https" is rejected at startup).
    if (httpProxyPort) {
      envVars.push(`CLOUDSDK_PROXY_TYPE=http`)
      envVars.push(`CLOUDSDK_PROXY_ADDRESS=localhost`)
      envVars.push(`CLOUDSDK_PROXY_PORT=${httpProxyPort}`)
      if (proxyAuthToken) {
        envVars.push(`CLOUDSDK_PROXY_USERNAME=${userRaw}`)
        envVars.push(`CLOUDSDK_PROXY_PASSWORD=${proxyAuthToken}`)
      }
    }

    // Azure CLI - uses HTTPS_PROXY
    // Azure CLI respects HTTPS_PROXY which we already set above

    // Terraform - uses standard HTTP/HTTPS proxy vars
    // Terraform respects HTTP_PROXY/HTTPS_PROXY which we already set above

    // gRPC: see GRPC_PROXY above, emitted outside this guard.
  }

  // Do not set HTTP_PROXY/HTTPS_PROXY to SOCKS URLs in the SOCKS-only path:
  // most HTTP clients reject socks*:// in those vars. ALL_PROXY (above)
  // already carries the route for clients that read it.

  return envVars
}

/**
 * `safe.directory` entries above this count collapse to a single
 * `safe.directory=*`. Keeps `GIT_CONFIG_COUNT` (and the argv it rides
 * on) bounded when the safe-dir set is wide.
 */
const SAFE_DIRECTORY_WILDCARD_THRESHOLD = 8

/**
 * Build the `GIT_CONFIG_COUNT` / `GIT_CONFIG_KEY_<n>` /
 * `GIT_CONFIG_VALUE_<n>` env-var set for the sandboxed child.
 *
 * Emits:
 *   - `safe.directory=<dir>` for each entry in `safeDirs` (or one
 *     `safe.directory=*` when the list is long) — inside the sandbox
 *     the working tree is owned by a different user (Windows: the
 *     real user vs `srt-sandbox`; Linux: unmapped uid under
 *     `bwrap --unshare-user`), so git refuses with "detected dubious
 *     ownership" without it.
 *   - `http.schannelUseSSLCAInfo=true` and
 *     `http.schannelCheckRevoke=false` when `schannelCa` (Windows
 *     only) — makes git's schannel backend honor `GIT_SSL_CAINFO`
 *     without `-c http.sslBackend=openssl`. Revocation is disabled
 *     because CryptoAPI CRL/OCSP fetches ignore proxy env and would
 *     be WFP-fenced.
 *
 * Composes with an existing `GIT_CONFIG_COUNT` in `baseEnv` by
 * continuing its numbering; the returned `GIT_CONFIG_COUNT` is the
 * new total. `baseEnv` should reflect what the child will actually
 * see: on Windows the two-hop launch means the broker's own
 * `process.env` never reaches the child, so `baseEnv` is the caller
 * overlay (`WindowsSandboxParams.setEnvVars`); on Linux/macOS the
 * child inherits `process.env`, so callers use
 * {@link buildPosixGitSafeDirEnv} (which folds in `process.env`,
 * `unsetEnvVars`, and `setEnvVars`).
 *
 * Paths are emitted with forward slashes so the value survives
 * msys2's env conversion untouched and native git accepts it (a
 * no-op on POSIX paths).
 */
export function buildGitConfigEnv(opts: {
  safeDirs: readonly string[]
  /** Windows-only schannel knobs; default false. */
  schannelCa?: boolean
  baseEnv?: Readonly<Record<string, string | undefined>>
}): Record<string, string> {
  // An explicit `GIT_CONFIG_COUNT=0` in baseEnv is an opt-out ("no
  // env-level git config") — respect it rather than overwriting.
  if (opts.baseEnv?.GIT_CONFIG_COUNT === '0') return {}
  const parsed = Number.parseInt(opts.baseEnv?.GIT_CONFIG_COUNT ?? '', 10)
  const start = Number.isFinite(parsed) && parsed >= 0 ? parsed : 0
  let n = start
  const out: Record<string, string> = {}
  const emit = (key: string, value: string) => {
    out[`GIT_CONFIG_KEY_${n}`] = key
    out[`GIT_CONFIG_VALUE_${n}`] = value
    n++
  }
  const dirs = [
    ...new Set(
      opts.safeDirs
        .filter((d): d is string => !!d)
        .map(d => {
          const fwd = d.replace(/\\/g, '/')
          const stripped = fwd.replace(/\/+$/, '')
          // Don't strip the trailing slash off a bare root: `C:`
          // is drive-relative-cwd (git wants `C:/`), and `` is
          // git's list-reset sentinel for safe.directory (would
          // wipe preceding entries) — POSIX `/` must stay `/`.
          if (stripped === '' || /^[A-Za-z]:$/.test(stripped)) {
            return `${stripped}/`
          }
          return stripped
        }),
    ),
  ]
  if (dirs.length > SAFE_DIRECTORY_WILDCARD_THRESHOLD) {
    emit('safe.directory', '*')
  } else {
    // git matches safe.directory against the REPO TOP-LEVEL exactly,
    // so a workspace root doesn't cover a nested repo. Emit both the
    // exact path and the `<dir>/*` glob (git ≥2.46) so any repo
    // at-or-under a granted dir is trusted. Roots keep their trailing
    // `/`; don't double it in the glob (`//*` never wildmatches).
    for (const d of dirs) {
      emit('safe.directory', d)
      emit('safe.directory', d.endsWith('/') ? `${d}*` : `${d}/*`)
    }
  }
  if (opts.schannelCa) {
    emit('http.schannelUseSSLCAInfo', 'true')
    emit('http.schannelCheckRevoke', 'false')
  }
  if (n === start) return {}
  out.GIT_CONFIG_COUNT = String(n)
  return out
}

/**
 * POSIX-side wrapper over {@link buildGitConfigEnv} that constructs
 * the correct `baseEnv` for a Linux/macOS sandbox: the child inherits
 * `process.env` under bwrap/sandbox-exec, then `unsetEnvVars` are
 * dropped and `setEnvVars` overlaid — so numbering must continue from
 * whatever `GIT_CONFIG_COUNT` survives that. Shared by
 * `wrapCommandWithSandbox{Linux,MacOS}`.
 */
export function buildPosixGitSafeDirEnv(opts: {
  safeDirs: readonly string[]
  unsetEnvVars?: readonly string[]
  setEnvVars?: Readonly<Record<string, string>>
}): Record<string, string> {
  const baseEnv: Record<string, string | undefined> = {
    GIT_CONFIG_COUNT: process.env.GIT_CONFIG_COUNT,
  }
  for (const k of opts.unsetEnvVars ?? []) delete baseEnv[k]
  Object.assign(baseEnv, opts.setEnvVars ?? {})
  return buildGitConfigEnv({ safeDirs: opts.safeDirs, baseEnv })
}

/**
 * Encode a command for sandbox monitoring
 * Truncates to 100 chars and base64 encodes to avoid parsing issues
 */
export function encodeSandboxedCommand(command: string): string {
  const truncatedCommand = command.slice(0, 100)
  return Buffer.from(truncatedCommand).toString('base64')
}

/**
 * Decode a base64-encoded command from sandbox monitoring
 */
export function decodeSandboxedCommand(encodedCommand: string): string {
  return Buffer.from(encodedCommand, 'base64').toString('utf8')
}

/** Base proxy username; the auth token is the credential, this is a label. */
export const PROXY_AUTH_USER = 'srt'

/**
 * Build the proxy username for a sandboxed command: `srt.<encodedCommand>`
 * so the proxy can attribute a denial to the invocation that triggered it,
 * or bare `srt` when there is nothing to attribute. RFC 1929 caps the
 * SOCKS5 username at 255 bytes; a multibyte command whose 100-code-unit
 * truncation still base64s past that would fail the SOCKS handshake, so
 * fall back to bare `srt` (attribution is lost, connectivity is not).
 */
export function proxyUsernameFor(encodedCommand: string | undefined): string {
  if (!encodedCommand) return PROXY_AUTH_USER
  const user = `${PROXY_AUTH_USER}.${encodedCommand}`
  return Buffer.byteLength(user) <= 255 ? user : PROXY_AUTH_USER
}

/**
 * Inverse of {@link proxyUsernameFor}: extract the encodedCommand suffix
 * from `srt.<encodedCommand>`, or undefined for bare `srt` / anything else.
 * The username is client-controlled inside the sandbox, so a forged suffix
 * can only misattribute a denial in the violation report — it cannot
 * authenticate (the token does that) or reach another command's data.
 */
export function encodedCommandFromProxyUser(
  username: string | undefined,
): string | undefined {
  if (!username || !username.startsWith(`${PROXY_AUTH_USER}.`)) return undefined
  const suffix = username.slice(PROXY_AUTH_USER.length + 1)
  return suffix || undefined
}

/**
 * Convert a glob pattern to a regular expression
 *
 * This implements gitignore-style pattern matching to match the behavior of the
 * `ignore` library used by the permission system.
 *
 * Supported patterns:
 * - * matches any characters except / (e.g., *.ts matches foo.ts but not foo/bar.ts)
 * - ** matches any characters including / (e.g., src/**\/*.ts matches all .ts files in src/)
 * - ? matches any single character except / (e.g., file?.txt matches file1.txt)
 * - [abc] matches any character in the set (e.g., file[0-9].txt matches file3.txt)
 *
 * Exported for testing and shared between macOS sandbox profiles and Linux glob expansion.
 */
export function globToRegex(globPattern: string): string {
  return (
    '^' +
    globPattern
      // Escape regex special characters (except glob chars * ? [ ])
      .replace(/[.^$+{}()|\\]/g, '\\$&')
      // Escape unclosed brackets (no matching ])
      .replace(/\[([^\]]*?)$/g, '\\[$1')
      // Convert glob patterns to regex (order matters - ** before *)
      .replace(/\*\*\//g, '__GLOBSTAR_SLASH__') // Placeholder for **/
      .replace(/\*\*/g, '__GLOBSTAR__') // Placeholder for **
      .replace(/\*/g, '[^/]*') // * matches anything except /
      .replace(/\?/g, '[^/]') // ? matches single character except /
      // Restore placeholders
      .replace(/__GLOBSTAR_SLASH__/g, '(.*/)?') // **/ matches zero or more dirs
      .replace(/__GLOBSTAR__/g, '.*') + // ** matches anything including /
    '$'
  )
}

export interface ExpandGlobOptions {
  /**
   * Match case-insensitively. Set this on Windows where the
   * pattern's static prefix may differ in case from what
   * `readdirSync` returns. Default: false (Linux/macOS callers
   * don't need it).
   */
  caseInsensitive?: boolean
}

/**
 * Expand a glob pattern into concrete file paths.
 *
 * Used on Linux (where bubblewrap doesn't support glob patterns
 * natively) and Windows (point-in-time expansion before `srt-win
 * acl stamp`). Resolves the static directory prefix, lists files
 * recursively, and filters using {@link globToRegex}.
 *
 * @param globPath - A path pattern containing glob characters (e.g., ~/test/*.env)
 * @returns Array of absolute paths matching the glob pattern
 */
export function expandGlobPattern(
  globPath: string,
  opts: ExpandGlobOptions = {},
): string[] {
  // Normalize to `/` separators throughout so {@link globToRegex}
  // (which treats `/` as the segment boundary) and the static-prefix
  // split work on Windows paths. Gated to win32: `\` is a valid
  // filename byte on POSIX, so rewriting it there would change the
  // path (e.g. a Linux directory literally named `app\creds`).
  const toFwd = (s: string) =>
    process.platform === 'win32' ? s.replace(/\\/g, '/') : s
  const normalizedPattern = toFwd(normalizePathForSandbox(globPath))

  // Extract the static directory prefix before any glob characters
  const staticPrefix = normalizedPattern.split(/[*?[\]]/)[0]
  if (!staticPrefix || staticPrefix === '/') {
    logForDebugging(`[Sandbox] Glob pattern too broad, skipping: ${globPath}`)
    return []
  }

  // Get the base directory from the static prefix
  const baseDir = staticPrefix.endsWith('/')
    ? staticPrefix.slice(0, -1)
    : path.dirname(staticPrefix)

  if (!fs.existsSync(baseDir)) {
    logForDebugging(
      `[Sandbox] Base directory for glob does not exist: ${baseDir}`,
    )
    return []
  }

  // Build regex from the normalized glob pattern
  const regex = new RegExp(
    globToRegex(normalizedPattern),
    opts.caseInsensitive ? 'i' : '',
  )

  // List all entries recursively under the base directory
  const results: string[] = []
  try {
    const entries = fs.readdirSync(baseDir, {
      recursive: true,
      withFileTypes: true,
    })

    for (const entry of entries) {
      // Build the full path for this entry
      // entry.parentPath is the directory containing this entry (available in Node 20+/Bun)
      // For compatibility, fall back to entry.path if parentPath is not available
      const parentDir =
        (entry as { parentPath?: string }).parentPath ??
        (entry as { path?: string }).path ??
        baseDir
      const fullPath = path.join(parentDir, entry.name)

      if (regex.test(toFwd(fullPath))) {
        results.push(fullPath)
      }
    }
  } catch (err) {
    logForDebugging(
      `[Sandbox] Error expanding glob pattern ${globPath}: ${err}`,
    )
  }

  return results
}
