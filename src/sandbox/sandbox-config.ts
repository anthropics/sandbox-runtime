/**
 * Configuration for Sandbox Runtime
 * This is the main configuration interface that consumers pass to SandboxManager.initialize()
 */

import type { FilterRequestCallback } from './request-filter.js'

import { isAbsolute } from 'node:path'
import { z } from 'zod'
import { isInjectHostCoveredByAllowedDomains } from './domain-pattern.js'

/**
 * Schema for domain patterns (e.g., "example.com", "*.npmjs.org")
 * Validates that domain patterns are safe and don't include overly broad wildcards
 */
const domainPatternSchema = z.string().refine(
  val => {
    // Reject protocols, paths, ports, etc.
    if (val.includes('://') || val.includes('/') || val.includes(':')) {
      return false
    }

    // Allow localhost
    if (val === 'localhost') return true

    // Allow wildcard domains like *.example.com
    if (val.startsWith('*.')) {
      const domain = val.slice(2)
      // After the *. there must be a valid domain with at least one more dot
      // e.g., *.example.com is valid, *.com is not (too broad)
      if (
        !domain.includes('.') ||
        domain.startsWith('.') ||
        domain.endsWith('.')
      ) {
        return false
      }
      // Count dots - must have at least 2 parts after the wildcard (e.g., example.com)
      const parts = domain.split('.')
      return parts.length >= 2 && parts.every(p => p.length > 0)
    }

    // Reject any other use of wildcards (e.g., *, *., etc.)
    if (val.includes('*')) {
      return false
    }

    // Regular domains must have at least one dot and only valid characters
    return val.includes('.') && !val.startsWith('.') && !val.endsWith('.')
  },
  {
    message:
      'Invalid domain pattern. Must be a valid domain (e.g., "example.com") or wildcard (e.g., "*.example.com"). Overly broad patterns like "*.com" or "*" are not allowed for security reasons.',
  },
)

/**
 * Schema for filesystem paths
 */
const filesystemPathSchema = z.string().min(1, 'Path cannot be empty')

/**
 * Schema for an absolute path to an external binary.
 * Relative paths are rejected to prevent PATH/CWD-based hijacking — these
 * overrides are intended for admin-managed installs at fixed locations.
 */
const binaryPathSchema = z
  .string()
  .min(1, 'Path cannot be empty')
  .refine(val => isAbsolute(val), {
    message: 'Binary path must be absolute',
  })

/**
 * Schema for MITM proxy configuration
 * Allows routing specific domains through an upstream MITM proxy via Unix socket
 */
const MitmProxyConfigSchema = z.object({
  socketPath: z.string().min(1).describe('Unix socket path to the MITM proxy'),
  domains: z
    .array(domainPatternSchema)
    .min(1)
    .describe(
      'Domains to route through the MITM proxy (e.g., ["api.example.com", "*.internal.org"])',
    ),
})

/**
 * Schema for upstream/parent HTTP proxy configuration.
 * Used when SRT itself runs behind a corporate proxy and cannot make direct
 * outbound connections.
 */
const ParentProxyConfigSchema = z.object({
  http: z
    .string()
    .url()
    .optional()
    .describe('Upstream proxy URL for plain HTTP traffic'),
  https: z
    .string()
    .url()
    .optional()
    .describe(
      'Upstream proxy URL for HTTPS/CONNECT traffic (falls back to http if unset)',
    ),
  noProxy: z
    .string()
    .optional()
    .describe(
      'Comma-separated NO_PROXY list (hostname suffixes and CIDR ranges). ' +
        'Matching destinations connect directly instead of via the parent proxy.',
    ),
})

/**
 * Schema for the access mode of a declared credential source.
 *
 * - `deny` — the sandboxed process cannot read the file / does not see the
 *   environment variable.
 * - `mask` — the sandboxed process sees a per-session sentinel value; the
 *   host proxy substitutes sentinel→real on egress to `injectHosts`.
 *   For files this is whole-file masking (Linux only; degrades to `deny`
 *   on macOS — see {@link CredentialFileConfigSchema}).
 */
const credentialModeSchema = z.enum(['deny', 'mask'])

/**
 * Schema for an environment variable name. Restricted to POSIX identifiers so
 * the name can never be parsed as a flag by `env -u` (macOS) or bwrap
 * `--unsetenv` (Linux).
 */
const envVarNameSchema = z
  .string()
  .regex(
    /^[A-Za-z_][A-Za-z0-9_]*$/,
    'Environment variable name must start with a letter or underscore and contain only letters, digits, and underscores',
  )

/**
 * Schema for the optional structured-extraction regex on a masked file.
 *
 * Validates that the string compiles as a JavaScript RegExp and declares at
 * least one capturing group — capture group 1 is the contract for "the
 * credential value to mask". A pattern with zero groups would silently mask
 * nothing useful, so it is rejected at config time rather than at runtime.
 *
 * Group count is determined by appending `|` (alternation with empty) and
 * matching the empty string: the result array length is `1 + groupCount`,
 * which counts capturing groups (including named ones) and ignores
 * non-capturing `(?:…)`.
 */
const extractPatternSchema = z.string().superRefine((val, ctx) => {
  let re: RegExp
  try {
    re = new RegExp(val)
  } catch (err) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: `extract is not a valid regular expression: ${(err as Error).message}`,
    })
    return
  }
  const groupCount = new RegExp(re.source + '|').exec('')!.length - 1
  if (groupCount < 1) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message:
        'extract must contain at least one capturing group — group 1 is ' +
        'the credential value to mask (e.g. "token:\\s*(\\S+)").',
    })
  }
})

/**
 * Schema for a single credential file/directory entry.
 *
 * `mode: "mask"` without `extract` is **whole-file** masking: the entire
 * file content is replaced inside the sandbox with one sentinel string,
 * and the proxy substitutes that sentinel back to the real bytes on egress.
 * This works for files whose content *is* the credential (a token file, a
 * single-line secret).
 *
 * `mode: "mask"` with `extract` is **structured** masking: the regex is
 * applied globally to the real file, capture group 1 of each match is a
 * credential value, and only those captured spans are replaced with
 * sentinels — the rest of the file is preserved byte-for-byte. This lets a
 * tool that parses the file (`.netrc`, JSON/YAML configs) still succeed
 * inside the sandbox while the credential values are protected. If the
 * pattern matches nothing, behaviour is governed by `onExtractNoMatch`
 * (default `"warn"` — the file is left readable as-is and a stderr
 * warning is emitted).
 *
 * `mode: "mask"` with `decode: "jwt"` extends structured masking into
 * encoded values: where `extract` opens plain text to mask a span inside
 * it, `decode` opens the encoding so masking can target fields inside the
 * decoded payload (`maskClaims`):
 *
 * - **Default pattern**: when `extract` is absent, a built-in JWT regex is
 *   used (every JWT starts `eyJ` — base64url of `{"`), so authors don't
 *   hand-write it. An explicit `extract` wins; its group-1 captures are the
 *   candidates.
 * - **Decode-verification**: each candidate must actually BE a JWT (three
 *   segments, JSON header/payload, `alg` in the header) before it is
 *   masked; candidates failing verification are left untouched.
 * - **Claim-level masking** (`maskClaims`): each named top-level payload
 *   claim present with a string value is replaced by its own sentinel and
 *   the token is rebuilt around the modified payload (original header,
 *   filler signature). All other claims stay real, so a client that
 *   decodes the token and reads a non-secret claim keeps working. The
 *   proxy substitutes both the whole rebuilt token (sent as a bearer
 *   credential) and each claim sentinel (extracted and sent alone).
 * - **Whole-token fallback** (no `maskClaims`): the whole decoded value is
 *   treated as the credential — for bearer-style usage where the token
 *   itself is the secret — and replaced with a structurally valid fake JWT
 *   (parseable header/payload, far-future `exp`), so client-side token
 *   parsing inside the sandbox doesn't break. Its header declares
 *   `alg: HS256` (not `alg: none`, which misconfigured validators accept)
 *   with a garbage signature, so any validator the unswapped fake reaches
 *   rejects it.
 * - **No verified candidate**: if nothing matches, no candidate verifies,
 *   or (with `maskClaims`) no named claim matches in any verified token,
 *   behaviour is governed by `onExtractNoMatch` — same as a non-matching
 *   `extract` (default `"warn"`: stderr warning, file left readable
 *   as-is).
 *
 * `maskDuplicates: true` (only meaningful with `extract` or `decode`)
 * additionally replaces every verbatim occurrence of each masked value
 * *outside* the regex-matched spans — for a secret repeated where the
 * regex does not reach (e.g. pasted into a comment). The scan is raw
 * substring matching, so a short or common captured value may also hit
 * unrelated content that happens to contain it; intended for long,
 * high-entropy secrets. Composed with `decode`, only captures that passed
 * verification are scanned — a duplicate is the same value and reuses the
 * verified capture's fake without re-verification.
 *
 * On macOS, SBPL cannot redirect reads, so `mode: "mask"` (with or without
 * `extract`/`decode`) currently degrades to `mode: "deny"` (the file is
 * unreadable inside the sandbox).
 */
export const CredentialFileConfigSchema = z.object({
  path: filesystemPathSchema.describe(
    'Path to a credential file or directory. Supports the same path forms as ' +
      'filesystem.denyRead (absolute paths and ~ expansion).',
  ),
  mode: credentialModeSchema.describe('Access mode for this path'),
  extract: extractPatternSchema
    .optional()
    .describe(
      'Optional regex for structured masking. Applied globally; capture ' +
        'group 1 of each match is masked, the rest of the file is preserved. ' +
        'If the pattern matches nothing, behaviour is governed by ' +
        'onExtractNoMatch (default "warn"). Only meaningful when mode is ' +
        '"mask"; accepted but ignored for "deny".',
    ),
  /**
   * What to do when `extract` matches nothing in the file at runtime —
   * or, with `decode`, when no candidate survives verification.
   *
   * - `"warn"` (default): emit a stderr warning and leave the file
   *   readable as-is inside the sandbox (fail-open). A non-matching
   *   pattern is treated as a config error to surface and fix, not a
   *   reason to break a tool that needs the file when the credential is
   *   legitimately absent.
   * - `"deny"`: degrade the entry to `mode: "deny"` so the file is
   *   unreadable inside the sandbox (fail-closed). The operator declared
   *   this file as containing a credential; if the regex cannot find it,
   *   block access rather than expose it.
   * - `"error"`: throw at wrap time so nothing runs until the operator
   *   fixes the config.
   *
   * Only meaningful when `mode` is `"mask"` and `extract` or `decode` is
   * set; accepted but ignored otherwise.
   */
  onExtractNoMatch: z
    .enum(['warn', 'deny', 'error'])
    .optional()
    .describe(
      'What to do when extract matches nothing (or, with decode, no ' +
        'candidate verifies): "warn" (default — stderr warning, file left ' +
        'readable), "deny" (degrade to mode "deny" — file unreadable), or ' +
        '"error" (throw at wrap time). Only meaningful with mode "mask" ' +
        'and extract or decode set.',
    ),
  decode: z
    .enum(['jwt'])
    .optional()
    .describe(
      'Optional encoded-credential format. "jwt": decodes recognized JWTs ' +
        'so masking can target fields inside them (see maskClaims). ' +
        'Candidates are located with a built-in JWT regex (or the explicit ' +
        'extract pattern, if set) and verified to actually be JWTs before ' +
        'masking. Without maskClaims, the whole decoded value is treated ' +
        'as the credential and replaced with a structurally valid fake ' +
        'JWT, so client-side token parsing keeps working. If no candidate ' +
        'verifies, behaviour is governed by onExtractNoMatch (default ' +
        '"warn"). Only meaningful when mode is "mask"; accepted but ' +
        'ignored for "deny".',
    ),
  /**
   * Names of top-level payload claims to mask inside each decoded value —
   * the claim-level counterpart of `extract`: where `extract` opens plain
   * text to mask a span inside it, `decode` + `maskClaims` opens the
   * encoding to mask a field inside the decoded payload.
   *
   * For each verified JWT candidate, every named claim present with a
   * string value is replaced by its own sentinel and the token is rebuilt
   * around the modified payload (original header, filler signature). All
   * other claims are preserved verbatim, so a tool that decodes the token
   * and reads a non-secret claim (issuer, audience, user id) keeps
   * working while the secret claim is protected. A named claim that is
   * absent or non-string in a given token is skipped. If no named claim
   * matches in any verified token, behaviour is governed by
   * `onExtractNoMatch` — same as no candidate verifying.
   *
   * Requires `decode` (there is no payload to look inside otherwise); an
   * explicitly empty list is rejected — see the superRefine below.
   */
  maskClaims: z
    .array(z.string().min(1))
    .optional()
    .describe(
      'Names of top-level payload claims to mask inside each decoded ' +
        'value, instead of replacing the whole token. Each named claim ' +
        'present with a string value gets its own sentinel; all other ' +
        'claims are preserved so claim-reading clients keep working. ' +
        'Requires decode. If no named claim matches in any verified ' +
        'token, behaviour is governed by onExtractNoMatch (default ' +
        '"warn"). Only meaningful when mode is "mask"; accepted but ' +
        'ignored for "deny".',
    ),
  maskDuplicates: z
    .boolean()
    .optional()
    .describe(
      'If true, verbatim occurrences of each captured credential value ' +
        'outside the regex-matched spans are also replaced with the ' +
        'corresponding sentinel — for a secret repeated where the regex ' +
        'does not reach (e.g. in a comment). Matches raw substrings: short ' +
        'or common credential values may corrupt unrelated content, so ' +
        'this is intended for long, high-entropy secrets. With decode, ' +
        'only values that passed verification are scanned; duplicates ' +
        "reuse the verified value's fake without re-verification. " +
        'Defaults to false. Only meaningful with mode "mask" and extract ' +
        'or decode set; accepted but ignored otherwise.',
    ),
  injectHosts: z
    .array(domainPatternSchema)
    .optional()
    .describe(
      'Optional narrowing of where the proxy substitutes this credential. ' +
        'If unset, defaults to network.allowedDomains — the credential is ' +
        'injected at every reachable host. Only meaningful when mode is ' +
        '"mask"; accepted but ignored for "deny".',
    ),
})

/**
 * Schema for a single credential environment variable entry.
 *
 * `mode: "mask"` replaces the variable's value inside the sandbox with a
 * per-session sentinel; the proxy substitutes sentinel→real on egress to
 * the credential's injectHosts. A masked var that is unset on the host is
 * skipped — there is nothing to protect.
 *
 * `mode: "mask"` without `extract` is **whole-value** masking: the entire
 * value is replaced inside the sandbox with one sentinel string, and the
 * proxy substitutes that sentinel back to the real value on egress. This
 * works for variables whose value *is* the credential (a bare token).
 *
 * `mode: "mask"` with `extract` is **structured** masking: the regex is
 * applied globally to the real value, capture group 1 of each match is a
 * credential value, and only those captured spans are replaced with
 * sentinels — the rest of the value is preserved byte-for-byte. This lets
 * a tool that parses the value (a `DATABASE_URL` connection string, a
 * composite `KEY:SECRET` pair) still succeed inside the sandbox while the
 * credential spans are protected. If the pattern matches nothing,
 * behaviour is governed by `onExtractNoMatch` (default `"warn"` — the
 * variable passes through unmasked and a stderr warning is emitted).
 *
 * `mode: "mask"` with `decode: "jwt"` handles a variable whose whole value
 * is a JWT (CI OIDC tokens, Supabase keys, ...). `decode` opens the encoded
 * value for masking: without claim-level configuration the entire token is
 * replaced by a structurally valid fake JWT — parseable three-segment shape
 * with JSON header/payload and far-future `exp`, so a tool that inspects
 * the token before sending it (segment count, exp, claims) keeps working.
 * The fake's header declares `alg: HS256` — never `alg: none`, which
 * misconfigured validators accept — with a filler signature, so a verifier
 * the unswapped fake ever reaches rejects it cryptographically. The proxy
 * swaps the whole fake token for the real one on egress.
 *
 * `decode: "jwt"` with `maskClaims` masks at the claim level instead: each
 * named top-level payload claim present with a string value is replaced by
 * its own sentinel and the token is rebuilt around the modified payload
 * (original header segment, filler signature). All other claims stay real,
 * so a client that decodes the token and reads a non-secret claim keeps
 * working. The proxy substitutes both the whole rebuilt token (sent as a
 * bearer credential) and each claim sentinel (extracted and sent alone).
 *
 * If the variable is set but its value does not verify as a JWT — or, with
 * `maskClaims`, no named claim is present as a string — nothing was masked:
 * the entry currently fails open — the real value stays in the sandbox
 * environment and a loud stderr warning names the variable.
 */
export const CredentialEnvVarConfigSchema = z.object({
  name: envVarNameSchema.describe('Environment variable name'),
  mode: credentialModeSchema.describe(
    'Access mode for this environment variable',
  ),
  extract: extractPatternSchema
    .optional()
    .describe(
      'Optional regex for structured masking. Applied globally; capture ' +
        'group 1 of each match is masked, the rest of the value is ' +
        'preserved. If the pattern matches nothing, behaviour is governed ' +
        'by onExtractNoMatch (default "warn"). Only meaningful when mode ' +
        'is "mask"; accepted but ignored for "deny".',
    ),
  /**
   * What to do when `extract` matches nothing in the value at runtime.
   *
   * - `"warn"` (default): emit a stderr warning and let the variable pass
   *   through unmasked inside the sandbox (fail-open). A non-matching
   *   pattern is treated as a config error to surface and fix, not a
   *   reason to break a tool that needs the variable when the credential
   *   is legitimately absent from it.
   * - `"deny"`: unset the variable inside the sandbox (fail-closed) — the
   *   env analog of degrading a file to `mode: "deny"`. The operator
   *   declared this variable as containing a credential; if the regex
   *   cannot find it, withhold the value rather than expose it.
   * - `"error"`: throw at wrap time so nothing runs until the operator
   *   fixes the regex.
   *
   * Only meaningful when `mode` is `"mask"` and `extract` is set;
   * accepted but ignored otherwise.
   */
  onExtractNoMatch: z
    .enum(['warn', 'deny', 'error'])
    .optional()
    .describe(
      'What to do when extract matches nothing: "warn" (default — stderr ' +
        'warning, variable passes through unmasked), "deny" (variable ' +
        'unset inside the sandbox), or "error" (throw at wrap time). Only ' +
        'meaningful with mode "mask" and extract set.',
    ),
  decode: z
    .enum(['jwt'])
    .optional()
    .describe(
      'Optional encoded-credential format. "jwt": the variable\'s whole ' +
        'value is verified to actually be a JWT and replaced with a ' +
        'structurally valid fake JWT so client-side token parsing keeps ' +
        'working; the proxy swaps the whole fake token on egress. If the ' +
        'value does not verify, the variable is left unmasked with a ' +
        'stderr warning (fail-open). Only meaningful when mode is "mask"; ' +
        'accepted but ignored for "deny".',
    ),
  /**
   * Names of top-level payload claims to mask inside the decoded value —
   * the env-var counterpart of the `maskClaims` on a file entry: `decode`
   * opens the variable's encoded value so masking can target a field
   * inside the decoded payload instead of replacing the whole token.
   *
   * Every named claim present with a string value is replaced by its own
   * sentinel and the token is rebuilt around the modified payload
   * (original header segment, filler signature). All other claims are
   * preserved verbatim, so a tool that decodes the token and reads a
   * non-secret claim (issuer, audience, user id) keeps working while the
   * secret claim is protected. A named claim that is absent or non-string
   * is skipped. If no named claim matches, nothing was masked and the
   * entry fails open with a stderr warning — same path as a value that
   * does not verify as a JWT.
   *
   * Requires `decode` (there is no payload to look inside otherwise); an
   * explicitly empty list is rejected — see the superRefine below.
   */
  maskClaims: z
    .array(z.string().min(1))
    .optional()
    .describe(
      'Names of top-level payload claims to mask inside the decoded ' +
        'value, instead of replacing the whole token. Each named claim ' +
        'present with a string value gets its own sentinel; all other ' +
        'claims are preserved so claim-reading clients keep working. ' +
        'Requires decode. If no named claim matches, the variable is left ' +
        'unmasked with a stderr warning (fail-open). Only meaningful when ' +
        'mode is "mask"; accepted but ignored for "deny".',
    ),
  injectHosts: z
    .array(domainPatternSchema)
    .optional()
    .describe(
      'Optional narrowing of where the proxy substitutes this credential. ' +
        'If unset, defaults to network.allowedDomains — the credential is ' +
        'injected at every reachable host. Only meaningful when mode is ' +
        '"mask"; accepted but ignored for "deny".',
    ),
})

/**
 * Credentials configuration schema for validation.
 *
 * Declares credential sources (files and environment variables) with a
 * per-source mode:
 * - `deny` blocks the source inside the sandbox (file reads are denied via the
 *   filesystem read-deny mechanism, env vars are unset in the child).
 *
 * Additional modes (e.g. `mask`) will be added in future releases.
 *
 * Only the sources declared here are affected; the section applies no
 * implicit restrictions beyond them.
 */
export const CredentialsConfigSchema = z
  .object({
    files: z
      .array(CredentialFileConfigSchema)
      .optional()
      .describe('Credential files or directories to protect'),
    envVars: z
      .array(CredentialEnvVarConfigSchema)
      .optional()
      .describe('Environment variables to protect'),
    allowPlaintextInject: z
      .boolean()
      .optional()
      .describe(
        'Allow sentinel→real substitution on the plain-HTTP proxy path. ' +
          'Defaults to false: without TLS termination the upstream identity ' +
          'is unverified and the credential travels in cleartext. Set only ' +
          'for trusted-network test fixtures.',
      ),
  })
  // Reject unknown keys so a stale `credentials.injectHosts` (the removed
  // block-level default) fails loudly instead of being silently stripped.
  .strict()

/**
 * Network configuration schema for validation
 */
export const NetworkConfigSchema = z.object({
  allowedDomains: z
    .array(domainPatternSchema)
    .describe('List of allowed domains (e.g., ["github.com", "*.npmjs.org"])'),
  deniedDomains: z
    .array(z.union([z.literal('*'), domainPatternSchema]))
    .describe(
      'List of denied domains. Unlike allowedDomains, a bare "*" is accepted here (deny-all).',
    ),
  strictAllowlist: z
    .boolean()
    .optional()
    .describe(
      'If true, hosts not in allowedDomains are denied without consulting the ask callback. Set this when allowedDomains is policy enforcement, not a prompt-suppression hint.',
    ),
  allowUnixSockets: z
    .array(z.string())
    .optional()
    .describe(
      'macOS only: Unix socket paths to allow. Ignored on Linux (seccomp cannot filter by path).',
    ),
  allowAllUnixSockets: z
    .boolean()
    .optional()
    .describe(
      'If true, allow all Unix sockets (disables blocking on both platforms).',
    ),
  allowLocalBinding: z
    .boolean()
    .optional()
    .describe('Whether to allow binding to local ports (default: false)'),
  allowMachLookup: z
    .array(
      z.string().refine(
        val => {
          const prefix = val.endsWith('*') ? val.slice(0, -1) : val
          return !prefix.includes('*')
        },
        {
          message:
            'Wildcards are only allowed as a single trailing "*" (e.g., "com.example.*" or "*" for all services).',
        },
      ),
    )
    .optional()
    .describe(
      'macOS only: Additional XPC/Mach service names to allow looking up. Supports trailing-wildcard prefix matching (e.g., "2BUA8C4S2C.com.1password.*"). Needed for tools like 1Password CLI, Playwright, or the iOS Simulator that communicate via XPC.',
    ),
  httpProxyPort: z
    .number()
    .int()
    .min(1)
    .max(65535)
    .optional()
    .describe(
      'Port of an external HTTP proxy to use instead of starting a local one. When provided, the library will skip starting its own HTTP proxy and use this port. The external proxy must handle domain filtering.',
    ),
  socksProxyPort: z
    .number()
    .int()
    .min(1)
    .max(65535)
    .optional()
    .describe(
      'Port of an external SOCKS proxy to use instead of starting a local one. When provided, the library will skip starting its own SOCKS proxy and use this port. The external proxy must handle domain filtering.',
    ),
  allowUnauthenticatedSocksProxy: z
    .boolean()
    .optional()
    .describe(
      'Allow unauthenticated access to the local SOCKS proxy. This enables Git-over-SSH with the built-in macOS nc, but lets other local processes use the proxy while it is running.',
    ),
  mitmProxy: MitmProxyConfigSchema.optional().describe(
    'Optional MITM proxy configuration. Routes matching domains through an upstream proxy via Unix socket while SRT still handles allow/deny filtering.',
  ),
  filterRequest: z
    .custom<FilterRequestCallback>(v => typeof v === 'function', {
      message: 'filterRequest must be a function',
    })
    .optional()
    .describe(
      'Per-request filter callback. Receives the parsed HTTP request ' +
        '(web-standard Request) and returns {action, reason?}. Denied ' +
        'requests get a 403 with the reason. If the callback throws, the ' +
        'request is denied. Applies to plain HTTP through the proxy and, ' +
        'when tlsTerminate is configured, to terminated HTTPS. SRT does not ' +
        'provide a policy language; library consumers own matching.',
    ),
  tlsTerminate: z
    .object({
      caCertPath: z
        .string()
        .min(1)
        .optional()
        .describe(
          'Path to a PEM-encoded CA certificate. The sandboxed child is ' +
            'configured to trust this CA, and the TLS-terminating proxy uses ' +
            'it to sign per-host certificates. If omitted, SRT generates an ' +
            'ephemeral CA into a temp directory for the lifetime of the ' +
            'session.',
        ),
      caKeyPath: z
        .string()
        .min(1)
        .optional()
        .describe('Path to the PEM-encoded private key for caCertPath.'),
      excludeDomains: z
        .array(domainPatternSchema)
        .optional()
        .describe(
          'Domain patterns (same syntax as allowedDomains) whose HTTPS ' +
            'connections are NOT terminated. Matching CONNECTs are opaque ' +
            'byte tunnels: still subject to the allow/deny domain lists, ' +
            'but the sandboxed client completes its own TLS handshake with ' +
            'the upstream, so filterRequest and credential injection do not ' +
            'apply to their HTTPS traffic (plain-HTTP requests to the same ' +
            'hosts keep the normal request pipeline). Use for hosts the ' +
            'proxy must not re-originate: ' +
            'mTLS upstreams (only the client holds the client certificate) ' +
            'and clients that pin the upstream certificate and would reject ' +
            'the MITM CA. Hosts still need to be reachable via ' +
            'allowedDomains; this list only changes how they are tunnelled.',
        ),
      extraCaCertPaths: z
        .array(z.string().min(1))
        .optional()
        .describe(
          'Paths to PEM CA certificate files appended to the trust bundle ' +
            'the sandboxed child is pointed at, after the MITM CA and the ' +
            "host's regular roots. Use for site-local roots (e.g. an " +
            'internal mTLS CA) presented by excluded/passthrough hosts, so ' +
            'the child can verify them itself. Only the CERTIFICATE blocks ' +
            'of each file are copied; files that are missing, unreadable, ' +
            'or contain no PEM CERTIFICATE block are skipped (with a debug ' +
            'log), so paths that exist on only some hosts are safe to list.',
        ),
    })
    .refine(o => !o.caCertPath === !o.caKeyPath, {
      message: 'caCertPath and caKeyPath must be provided together',
    })
    .optional()
    .describe(
      '[EXPERIMENTAL] Enable in-process TLS termination so HTTPS ' +
        'request/response bodies are visible to SRT. Provide a CA cert+key, ' +
        'or omit both to have SRT generate an ephemeral one.',
    ),
  parentProxy: ParentProxyConfigSchema.optional().describe(
    "Upstream HTTP proxy for outbound connections. When set, SRT's proxy " +
      'tunnels non-mitmProxy traffic through this parent instead of ' +
      'connecting directly. Falls back to HTTP_PROXY/HTTPS_PROXY/NO_PROXY ' +
      'env vars if unset.',
  ),
})

/**
 * Filesystem configuration schema for validation
 */
export const FilesystemConfigSchema = z.object({
  disabled: z
    .boolean()
    .optional()
    .describe(
      'Disable all filesystem policy enforcement. When true, no read or write rules are emitted: ' +
        'denyRead/allowRead/allowWrite/denyWrite are ignored, and the built-in mandatory write ' +
        'protections (shell rc files and .mcp.json) are NOT applied. Use only when the sandboxed process ' +
        'is trusted with full host filesystem access. Network and credential-env restrictions ' +
        'still apply. On Linux, /dev is still replaced by the bwrap minimal devtmpfs.',
    ),
  denyRead: z.array(filesystemPathSchema).describe('Paths denied for reading'),
  allowRead: z
    .array(filesystemPathSchema)
    .optional()
    .describe(
      'Paths to re-allow reading within denied regions (takes precedence over denyRead). ' +
        'Use with denyRead to deny a broad region then allow back specific subdirectories.',
    ),
  allowWrite: z
    .array(filesystemPathSchema)
    .describe('Paths allowed for writing'),
  denyWrite: z
    .array(filesystemPathSchema)
    .describe('Paths denied for writing (takes precedence over allowWrite)'),
  denyMandatoryCwdFiles: z
    .boolean()
    .optional()
    .describe(
      'Deny writes to the built-in mandatory filenames (.gitconfig, .bashrc, .mcp.json, ...) at the ' +
        'working directory root. Defaults to true. Denying a path that does not exist requires mounting ' +
        '/dev/null over it, so each denied name is visible to readdir and appears in the working tree as ' +
        'a zero-length character device that cannot be read, written or removed while the command runs. ' +
        'Set false to avoid that; these names are still denied at any depth when they already exist.',
    ),
})

/**
 * Configuration schema for ignoring specific sandbox violations
 * Maps command patterns to filesystem paths to ignore violations for.
 */
export const IgnoreViolationsConfigSchema = z
  .record(z.string(), z.array(z.string()))
  .describe(
    'Map of command patterns to filesystem paths to ignore violations for. Use "*" to match all commands',
  )

/**
 * Ripgrep configuration schema
 */
export const RipgrepConfigSchema = z.object({
  command: z.string().describe('The ripgrep command to execute'),
  args: z
    .array(z.string())
    .optional()
    .describe('Additional arguments to pass before ripgrep args'),
  argv0: z
    .string()
    .optional()
    .describe(
      'Override argv[0] when spawning (for multicall binaries that dispatch on argv[0])',
    ),
})

/**
 * Configuration for locating/invoking the `srt-win` helper (Windows
 * only). An embedder that links `srt-win`'s CLI into its own
 * multicall binary points `path` at that binary; spawns then pass
 * `--srt-win` as `argv[1]` (see `SRT_WIN_DISPATCH_ARG1` in
 * `windows-sandbox-utils.ts` / `srt_win::SRT_WIN_DISPATCH_ARG1`) so
 * the embedder's dispatcher can route to `srt_win::run_from_args`.
 * Windows cannot reliably preserve a spoofed `argv[0]` across
 * `CreateProcessWithLogonW` / `ShellExecuteExW(runas)`, so dispatch
 * keys on `argv[1]`, not on `argv[0]` like
 * {@link SeccompConfigSchema} does on Linux.
 */
export const SrtWinConfigSchema = z.object({
  path: z
    .string()
    .min(1)
    .optional()
    .describe(
      'Path to the srt-win binary. When unset, getSrtWinPath() resolves ' +
        'the packaged vendor/srt-win/<arch>/srt-win.exe. When set, the ' +
        'binary is spawned with the `--srt-win` argv[1] sentinel so a ' +
        "multicall dispatcher can route to srt-win's CLI.",
    ),
})

/**
 * Windows-specific configuration schema. See
 * `windows-sandbox-utils.ts` for the install flow these settings
 * must agree with.
 *
 * Canonical: `sublayerGuid`; the `wfpSublayerGuid` alias is resolved
 * at read sites (`sublayerGuid ?? wfpSublayerGuid`) rather than via
 * `.transform()` so this stays a plain `ZodObject` for consumers that
 * `.extend()`/`.shape` it.
 */
export const WindowsConfigSchema = z.object({
  sandboxUser: z
    .string()
    .min(1)
    .max(20, 'Windows local usernames are limited to 20 characters')
    .optional()
    .describe(
      'Name for the dedicated sandbox user account that `srt-win install` ' +
        'creates and the sandboxed child runs as. Default: `srt-sandbox`. ' +
        'Install refuses if an account by this name already exists and ' +
        'srt-win did not create it (it will not rotate the password of an ' +
        'account it does not own). Must match what `srt-win install ' +
        '--sandbox-user` was run with.',
    ),
  sublayerGuid: z
    .string()
    .uuid()
    .optional()
    .describe(
      'WFP sublayer GUID under which the filters were installed. Omit to ' +
        'use the srt-win compile-time default. Set this when filters were ' +
        'installed by enterprise tooling under a custom sublayer.',
    ),
  wfpSublayerGuid: z
    .string()
    .uuid()
    .optional()
    .describe('Deprecated alias for sublayerGuid.'),
  proxyPortRange: z
    .tuple([z.number().int().min(1), z.number().int().max(65535)])
    .refine(([lo, hi]) => lo <= hi && hi - lo <= 64, {
      message: 'low must be ≤ high and range width ≤ 64',
    })
    .optional()
    .describe(
      'Inclusive [low, high] port range the JS mux proxy listeners bind ' +
        'inside. MUST match the range passed to `srt-win install ' +
        '--proxy-port-range` (default 60080–60089) — the WFP loopback ' +
        'permit only covers ports in that range.',
    ),
  srtWin: SrtWinConfigSchema.optional().describe(
    'How to locate/invoke the srt-win helper binary. Omit to resolve the ' +
      'packaged vendor binary; set when embedding srt-win into a multicall ' +
      'binary.',
  ),
})

/**
 * Seccomp configuration schema (Linux only)
 */
export const SeccompConfigSchema = z.object({
  applyPath: z.string().optional().describe('Path to the apply-seccomp binary'),
  argv0: z
    .string()
    .optional()
    .describe(
      'Invoke apply-seccomp as a multicall binary that dispatches on the ' +
        'ARGV0 environment variable. When set, applyPath is used verbatim ' +
        '(no existence check) and the invocation inside bwrap is prefixed ' +
        'with ARGV0=<this value>. The caller is responsible for ensuring ' +
        'applyPath resolves inside the bwrap namespace and that the target ' +
        'binary implements the apply-seccomp interface when ARGV0 matches.',
    ),
})

/**
 * Main configuration schema for Sandbox Runtime validation
 */
export const SandboxRuntimeConfigSchema = z
  .object({
    network: NetworkConfigSchema.describe('Network restrictions configuration'),
    filesystem: FilesystemConfigSchema.describe(
      'Filesystem restrictions configuration',
    ),
    credentials: CredentialsConfigSchema.optional().describe(
      'Credential handling configuration. Only the explicitly declared files ' +
        'and environment variables are restricted.',
    ),
    ignoreViolations: IgnoreViolationsConfigSchema.optional().describe(
      'Optional configuration for ignoring specific violations',
    ),
    enableWeakerNestedSandbox: z
      .boolean()
      .optional()
      .describe('Enable weaker nested sandbox mode (for Docker environments)'),
    enableWeakerNetworkIsolation: z
      .boolean()
      .optional()
      .describe(
        'Enable weaker network isolation to allow access to com.apple.trustd.agent (macOS only). ' +
          'This is needed for Go programs (gh, gcloud, terraform, kubectl, etc.) to verify TLS certificates ' +
          'when using httpProxyPort with a MITM proxy and custom CA. Enabling this opens a potential data ' +
          'exfiltration vector through the trustd service. Only enable if you need Go TLS verification.',
      ),
    allowAppleEvents: z
      .boolean()
      .optional()
      .describe(
        'Allow sending Apple Events and Launch Services open requests from the sandbox (macOS only). ' +
          'Needed for open, osascript, and anything that opens URLs or scripts other apps via AppleScript. ' +
          'This removes code-execution isolation: sandboxed commands can launch other applications ' +
          'unsandboxed with no user prompt (launched apps are not subject to the sandbox filesystem or ' +
          'network restrictions), and can script running apps subject to TCC automation consent. ' +
          'Default: false.',
      ),
    ripgrep: RipgrepConfigSchema.optional().describe(
      'Custom ripgrep configuration (default: { command: "rg" })',
    ),
    mandatoryDenySearchDepth: z
      .number()
      .int()
      .min(1)
      .max(10)
      .optional()
      .describe(
        'Maximum directory depth to search for dangerous files on Linux (default: 3). ' +
          'Higher values provide more protection but slower performance.',
      ),
    allowPty: z
      .boolean()
      .optional()
      .describe('Allow pseudo-terminal (pty) operations (macOS only)'),
    allowBrowserProcess: z
      .boolean()
      .optional()
      .describe(
        'Allow browser process operations (macOS only). Grants the additional Mach IPC, ' +
          'Mach bootstrap registration, and IOKit permissions that Chromium-based browsers ' +
          'need to launch and run inside the sandbox. Required for tools like agent-browser ' +
          'that spawn a Chrome/Chromium subprocess. Without this, Chrome will crash on startup ' +
          'due to denied Mach service lookups and bootstrap registrations.',
      ),
    seccomp: SeccompConfigSchema.optional().describe(
      'Custom seccomp binary paths (Linux only).',
    ),
    bwrapPath: binaryPathSchema
      .optional()
      .describe(
        'Linux only: absolute path to the bwrap (bubblewrap) binary. ' +
          'When set, this path is used directly instead of resolving "bwrap" via PATH.',
      ),
    socatPath: binaryPathSchema
      .optional()
      .describe(
        'Linux only: absolute path to the socat binary. ' +
          'When set, this path is used directly instead of resolving "socat" via PATH.',
      ),
    windows: WindowsConfigSchema.optional().describe(
      'Windows-specific settings (WFP sublayer, proxy port range).',
    ),
  })
  .superRefine((cfg, ctx) => {
    const creds = cfg.credentials
    if (!creds) return

    // Every per-entry injectHosts pattern must be reachable via
    // allowedDomains — semantic (wildcard-aware) coverage, not literal
    // string membership, so `injectHosts: ['api.github.com']` is accepted
    // when `allowedDomains: ['*.github.com']`.
    const allowed = cfg.network.allowedDomains
    const checkSubset = (
      hosts: readonly string[],
      path: (string | number)[],
    ) => {
      for (const [i, host] of hosts.entries()) {
        if (!isInjectHostCoveredByAllowedDomains(host, allowed)) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: [...path, i],
            message:
              `injectHosts entry "${host}" is not reachable via ` +
              `network.allowedDomains — add "${host}" (or a covering ` +
              `wildcard) to allowedDomains, or remove it from injectHosts.`,
          })
        }
      }
    }

    // Per-credential checks. Substitution is gated per sentinel; an entry
    // with no injectHosts defaults to network.allowedDomains (every
    // reachable host), so absence is fine. An *explicit* empty list is
    // rejected — "mask but never inject" is self-contradictory and almost
    // certainly a config mistake. Applies to both env vars and files.
    let hasMasked = false
    const checkMaskedEntry = (
      entry: { mode: string; injectHosts?: string[] },
      path: (string | number)[],
    ) => {
      if (entry.injectHosts) {
        checkSubset(entry.injectHosts, [...path, 'injectHosts'])
      }
      if (entry.mode !== 'mask') return
      hasMasked = true
      // Credential substitution only runs on the TLS-terminated path, so a
      // host covered by tlsTerminate.excludeDomains can never receive the
      // real value — the upstream sees the placeholder. Reject the
      // spellings that are *entirely* self-contradictory:
      //   - an explicit injectHosts entry whose every concrete host is
      //     excluded (isInjectHostCoveredByAllowedDomains is the generic
      //     "pattern fully covered by pattern list" predicate);
      //   - no injectHosts (= every allowedDomain) while excludeDomains
      //     covers all of allowedDomains, i.e. injection could never
      //     happen anywhere.
      // A *partial* overlap is legitimate (excluded hosts simply don't get
      // the credential) and is reported at runtime instead.
      const exclude = cfg.network.tlsTerminate?.excludeDomains
      if (exclude?.length) {
        if (entry.injectHosts) {
          for (const [i, host] of entry.injectHosts.entries()) {
            if (isInjectHostCoveredByAllowedDomains(host, exclude)) {
              ctx.addIssue({
                code: z.ZodIssueCode.custom,
                path: [...path, 'injectHosts', i],
                message:
                  `injectHosts entry "${host}" is entirely covered by ` +
                  `network.tlsTerminate.excludeDomains. Credential ` +
                  `injection only runs on TLS-terminated connections, so ` +
                  `this host would receive the placeholder instead of the ` +
                  `credential. Remove it from one of the two lists.`,
              })
            }
          }
        } else if (
          allowed.length > 0 &&
          allowed.every(p => isInjectHostCoveredByAllowedDomains(p, exclude))
        ) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path,
            message:
              `This masked credential has no injectHosts, so it defaults ` +
              `to network.allowedDomains — but ` +
              `network.tlsTerminate.excludeDomains covers every allowed ` +
              `domain, so it could never be injected anywhere. Credential ` +
              `injection only runs on TLS-terminated connections.`,
          })
        }
      }
      if (entry.injectHosts !== undefined && entry.injectHosts.length === 0) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path,
          message:
            `injectHosts is explicitly empty — the credential would be ` +
            `masked but never injected. Omit injectHosts to default to ` +
            `network.allowedDomains, or list the intended hosts.`,
        })
      }
    }
    for (const [idx, v] of (creds.envVars ?? []).entries()) {
      checkMaskedEntry(v, ['credentials', 'envVars', idx])
      // maskClaims names fields inside a decoded payload; without decode
      // there is no payload to look inside — reject the contradiction
      // loudly rather than silently masking nothing.
      if (v.maskClaims !== undefined && v.decode === undefined) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['credentials', 'envVars', idx, 'maskClaims'],
          message:
            `maskClaims requires decode — it names claims inside the ` +
            `decoded payload. Set decode (e.g. "jwt"), or remove ` +
            `maskClaims to mask the whole value.`,
        })
      }
      // Same posture as an explicitly empty injectHosts: "decode but mask
      // no claims" is self-contradictory and almost certainly a mistake.
      if (v.maskClaims !== undefined && v.maskClaims.length === 0) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['credentials', 'envVars', idx, 'maskClaims'],
          message:
            `maskClaims is explicitly empty — no claim would ever be ` +
            `masked. Omit maskClaims to mask the whole token, or list ` +
            `the claims to protect.`,
        })
      }
    }
    for (const [idx, f] of (creds.files ?? []).entries()) {
      checkMaskedEntry(f, ['credentials', 'files', idx])
      // maskClaims names fields inside a decoded payload; without decode
      // there is no payload to look inside — reject the contradiction
      // loudly rather than silently masking nothing.
      if (f.maskClaims !== undefined && f.decode === undefined) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['credentials', 'files', idx, 'maskClaims'],
          message:
            `maskClaims requires decode — it names claims inside the ` +
            `decoded payload. Set decode (e.g. "jwt"), or remove ` +
            `maskClaims to mask the extracted value whole.`,
        })
      }
      // Same posture as an explicitly empty injectHosts: "decode but mask
      // no claims" is self-contradictory and almost certainly a mistake.
      if (f.maskClaims !== undefined && f.maskClaims.length === 0) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['credentials', 'files', idx, 'maskClaims'],
          message:
            `maskClaims is explicitly empty — no claim would ever be ` +
            `masked. Omit maskClaims to mask the whole token, or list ` +
            `the claims to protect.`,
        })
      }
      // Whole-file masking replaces one file's bytes with one sentinel;
      // a directory has no single content to mask. The hard check is at
      // runtime (stat after path normalization) — this catches the obvious
      // syntactic case (trailing slash) early with a clearer error.
      if (f.mode === 'mask' && f.path.endsWith('/')) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['credentials', 'files', idx, 'path'],
          message:
            `Credential mode "mask" applies to a single file, not a ` +
            `directory. Use mode "deny" for "${f.path}", or point at the ` +
            `credential file inside it.`,
        })
      }
    }

    // Masked credentials require the TLS-terminated proxy path so the real
    // value is only sent to a cert-verified upstream. allowPlaintextInject
    // is the explicit escape hatch.
    if (
      hasMasked &&
      cfg.network.tlsTerminate === undefined &&
      !creds.allowPlaintextInject
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['credentials'],
        message:
          'Credential masking requires network.tlsTerminate so substitution ' +
          'runs only over a verified TLS connection. Enable tlsTerminate, or ' +
          'set credentials.allowPlaintextInject to opt out (not recommended).',
      })
    }
  })

// Export inferred types
export type MitmProxyConfig = z.infer<typeof MitmProxyConfigSchema>
export type ParentProxyConfig = z.infer<typeof ParentProxyConfigSchema>
export type NetworkConfig = z.infer<typeof NetworkConfigSchema>
export type FilesystemConfig = z.infer<typeof FilesystemConfigSchema>
export type CredentialMode = z.infer<typeof credentialModeSchema>
export type CredentialFileConfig = z.infer<typeof CredentialFileConfigSchema>
export type CredentialEnvVarConfig = z.infer<
  typeof CredentialEnvVarConfigSchema
>
export type CredentialsConfig = z.infer<typeof CredentialsConfigSchema>
export type IgnoreViolationsConfig = z.infer<
  typeof IgnoreViolationsConfigSchema
>
export type RipgrepConfig = z.infer<typeof RipgrepConfigSchema>
export type SeccompConfig = z.infer<typeof SeccompConfigSchema>
export type SrtWinConfig = z.infer<typeof SrtWinConfigSchema>
export type WindowsConfig = z.infer<typeof WindowsConfigSchema>
export type SandboxRuntimeConfig = z.infer<typeof SandboxRuntimeConfigSchema>
