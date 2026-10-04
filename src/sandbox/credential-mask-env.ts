/**
 * Credential env-var masking.
 *
 * For a `credentials.envVars` entry with `mode: "mask"`, srt reads the real
 * value from the host environment, registers one or more sentinels in the
 * {@link SentinelRegistry}, and sets the variable to the fake value inside
 * the sandbox (bwrap `--setenv` on Linux, the env preamble on macOS). The
 * proxy substitutes sentinel→real on egress to the entry's injectHosts.
 *
 * Without `extract`, masking is **whole-value**: one sentinel replaces the
 * entire value. With `extract`, masking is **structured**: a regex picks
 * out the credential span(s) and only those are replaced, so a tool that
 * parses the value (e.g. a `DATABASE_URL` connection string) still sees
 * valid syntax. See {@link extractAndSubstitute} and
 * {@link CredentialEnvVarConfigSchema}.
 */

import { randomUUID } from 'node:crypto'
import { logForDebugging } from '../utils/debug.js'
import { maskJwtClaims, mintFakeJwt, verifyJwt } from './credential-decode.js'
import { extractAndSubstitute } from './credential-extract.js'
import { readEnvCaseAware } from './sandbox-utils.js'
import type { CredentialEnvVarConfig } from './sandbox-config.js'
import type { SentinelRegistry } from './credential-sentinel.js'

/**
 * Sentinel-registry key prefix for structured (extract) env-var captures.
 * Whole-value env masking keys on the bare variable name; extract captures
 * key on `env:<NAME>#<i>` so the two forms — and masked files, which use
 * `file:<path>` — can never collide (env var names cannot contain `:`).
 */
const ENV_EXTRACT_KEY_PREFIX = 'env:'

/** Result of {@link buildMaskedEnvVars}. */
export interface MaskedEnvBuildResult {
  /** NAME → fake value to set inside the sandbox. */
  setEnvVars: Record<string, string>
  /**
   * Names of `mode: "mask"` entries that degraded to unset at runtime —
   * populated when `extract` matches nothing and the entry's
   * `onExtractNoMatch` is `"deny"`. Callers union these into the
   * unset-env set so the credential value is withheld rather than
   * exposed (the env analog of a file degrading to `mode: "deny"`).
   */
  degradeToUnsetNames: string[]
}

/**
 * For each `mode: "mask"` env-var entry: read the real value from `env`,
 * build the fake value (whole-value or structured per `extract`), register
 * sentinels in `registry`, and return the set-env map plus any entries
 * that degraded to unset.
 *
 * Whole-value mode (no `extract`): one sentinel keyed on the bare variable
 * name whose real value is the entire env value; the fake value *is* the
 * sentinel.
 *
 * Structured mode (`extract` set): one sentinel per distinct captured
 * value, keyed `env:<NAME>#<i>`; the fake value is the real value with
 * each captured span replaced by its sentinel. If the regex matches
 * nothing, the entry's `onExtractNoMatch` decides:
 * - `"warn"` (default): skip the entry with a loud stderr warning —
 *   fail-open, the variable passes through with its real value;
 * - `"deny"`: push the name to `degradeToUnsetNames` — fail-closed, the
 *   variable is unset inside the sandbox;
 * - `"error"`: throw, so nothing runs until the regex is fixed.
 *
 * Decoded mode (`decode: "jwt"`): the whole value is verified as a JWT
 * and replaced by a JWT-shaped fake registered as a caller-minted
 * sentinel; with `maskClaims`, each named top-level payload claim present
 * with a string value gets its own sentinel (keyed `env:<NAME>#<claim>`)
 * and the token is rebuilt around the modified payload — BOTH the whole
 * rebuilt token and each claim sentinel are registered under the same
 * injectHosts. A value that does not verify — or, with `maskClaims`,
 * verifies but has no named claim present as a string — fails open with a
 * loud stderr warning.
 *
 * A masked variable with no value in `env` is skipped — there is nothing
 * to protect, and emitting an unset (or set) var would change tool
 * behaviour (presence checks would flip).
 *
 * On Windows the host lookup is ordinal case-insensitive (env names
 * are case-insensitive there — a `GiThUb_ToKeN` in the host env IS
 * the `GITHUB_TOKEN` the entry names); POSIX lookups stay exact. See
 * {@link readEnvCaseAware}.
 *
 * `mode: "deny"` entries are ignored here; the caller handles them
 * directly (they need no registry or host environment access).
 */
export function buildMaskedEnvVars(
  envVars: readonly CredentialEnvVarConfig[],
  allowedDomains: readonly string[],
  registry: SentinelRegistry,
  env: Record<string, string | undefined> = process.env,
): MaskedEnvBuildResult {
  const setEnvVars: Record<string, string> = {}
  const degradeToUnsetNames: string[] = []
  for (const v of envVars) {
    if (v.mode !== 'mask') continue
    const real = readEnvCaseAware(env, v.name)
    if (real === undefined) continue

    // Effective injectHosts: per-entry narrows; if unset, default to
    // every reachable host (network.allowedDomains). injectHosts is an
    // *optional narrowing*, not a required allowlist. Trade-off: a
    // masked credential with no injectHosts is injectable at every host
    // the sandbox can reach — narrow it explicitly when the credential
    // should only go to a subset.
    const injectHosts = v.injectHosts ?? allowedDomains

    if (v.decode === 'jwt') {
      if (!verifyJwt(real)) {
        // Nothing was masked — the operator declared the value a JWT but
        // it isn't one. Fail open with a loud warning (parallel to the
        // extract onExtractNoMatch "warn" default).
        const msg =
          `[sandbox-runtime] WARNING: credentials.envVars entry ` +
          `"${v.name}" has decode "jwt" but its value did not verify ` +
          `as a JWT. The variable is left UNPROTECTED (real value ` +
          `visible as-is inside the sandbox). Fix the config or remove ` +
          `the entry.`
        console.warn(msg)
        logForDebugging(msg, { level: 'warn' })
        continue
      }
      if (v.maskClaims?.length) {
        // Claim-level masking: sentinels go INSIDE the payload; the
        // rebuilt fake token is itself registered as a sentinel for the
        // whole real token, so both the bearer path (token sent
        // verbatim) and the extracted-claim path substitute on egress.
        const masked = maskJwtClaims(real, v.maskClaims, (claim, value) =>
          registry.register(
            `${ENV_EXTRACT_KEY_PREFIX}${v.name}#${claim}`,
            value,
            injectHosts,
          ),
        )
        if (masked === null) {
          // A verified JWT none of whose named claims are present as
          // strings: nothing was masked — same fail-open posture as a
          // value that does not verify.
          const msg =
            `[sandbox-runtime] WARNING: credentials.envVars entry ` +
            `"${v.name}" has maskClaims ` +
            `${JSON.stringify(v.maskClaims)} but none is present as a ` +
            `string claim in its JWT value. The variable is left ` +
            `UNPROTECTED (real value visible as-is inside the sandbox). ` +
            `Fix the config or remove the entry.`
          console.warn(msg)
          logForDebugging(msg, { level: 'warn' })
          continue
        }
        const skipped = v.maskClaims.filter(c => !masked.claimSentinels.has(c))
        if (skipped.length > 0) {
          logForDebugging(
            `[credential-mask] env var "${v.name}": maskClaims ` +
              `${JSON.stringify(skipped)} absent or non-string in the ` +
              `JWT — skipped.`,
          )
        }
        setEnvVars[v.name] = registry.registerWithSentinel(
          `${ENV_EXTRACT_KEY_PREFIX}${v.name}`,
          masked.fakeToken,
          real,
          injectHosts,
        )
        continue
      }
      // JWT-shaped fake so token-parsing tools inside the sandbox keep
      // working; the proxy swaps the whole fake token on egress. Keyed
      // env:<NAME> — caller-minted keys stay disjoint from the file:
      // namespace and from plain masked env vars.
      setEnvVars[v.name] = registry.registerWithSentinel(
        `${ENV_EXTRACT_KEY_PREFIX}${v.name}`,
        mintFakeJwt(randomUUID()),
        real,
        injectHosts,
      )
      continue
    }

    if (v.extract === undefined) {
      // Whole-value: one sentinel for the entire value.
      setEnvVars[v.name] = registry.register(v.name, real, injectHosts)
      continue
    }

    const extracted = extractAndSubstitute(real, v.extract, (cap, i) =>
      registry.register(
        `${ENV_EXTRACT_KEY_PREFIX}${v.name}#${i}`,
        cap,
        injectHosts,
      ),
    )
    if (extracted === null) {
      const onNoMatch = v.onExtractNoMatch ?? 'warn'
      if (onNoMatch === 'error') {
        throw new Error(
          `credentials.envVars entry "${v.name}": extract pattern ` +
            `"${v.extract}" matched nothing (onExtractNoMatch: "error"). ` +
            `Fix the regex, change to "warn"/"deny", or remove the entry.`,
        )
      }
      if (onNoMatch === 'deny') {
        // Fail-closed: the operator declared this variable as containing
        // a credential. Masking can't apply — degrade to unset so the
        // sandboxed process cannot read the credential at all.
        logForDebugging(
          `[credential-mask] extract pattern /${v.extract}/ matched ` +
            `nothing in the value of ${v.name} — unsetting the variable.`,
          { level: 'warn' },
        )
        degradeToUnsetNames.push(v.name)
        continue
      }
      // 'warn' (default): fail-open. A non-matching pattern is a config
      // error to surface, not a reason to break a tool that needs the
      // variable. Skip the entry — the variable is inherited with its
      // real value — and warn loudly on stderr so the operator fixes
      // the regex.
      const msg =
        `[sandbox-runtime] WARNING: credentials.envVars entry ` +
        `"${v.name}" has extract pattern "${v.extract}" that matched ` +
        `nothing in the variable's value. The variable is left ` +
        `UNPROTECTED (visible as-is inside the sandbox). Fix the regex, ` +
        `set onExtractNoMatch to "deny" or "error", or remove the entry.`
      console.warn(msg)
      logForDebugging(msg, { level: 'warn' })
      continue
    }
    setEnvVars[v.name] = extracted.fakeContent
  }
  return { setEnvVars, degradeToUnsetNames }
}
