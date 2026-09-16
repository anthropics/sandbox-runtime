/**
 * JVM proxy agent: makes Java tools inside the sandbox honour the proxy.
 *
 * The JVM ignores HTTPS_PROXY/NO_PROXY — proxy selection is driven by the
 * `https.proxyHost` family of system properties, and the credential the
 * proxy requires can only be supplied through `java.net.Authenticator`,
 * which needs code running inside the JVM. Env vars alone can't do that,
 * so gRPC-Java (Bazel's remote cache), Gradle, Maven, etc. either dial the
 * target directly (no route out of the sandbox) or hit the proxy without
 * the token and get a 407.
 *
 * The fix is a tiny `-javaagent` (source in vendor/java-proxy-agent-src,
 * built into vendor/java-proxy-agent/srt-proxy-agent.jar by the release
 * workflow) that, at JVM start-up, translates the proxy env vars into
 * system properties and installs an Authenticator for the proxy endpoint.
 * This module locates that jar — same lookup shape as the apply-seccomp
 * binary — and builds the JAVA_TOOL_OPTIONS value that points every JVM in
 * the sandbox at it. The env var carries only the jar path; the credential
 * stays in HTTPS_PROXY, which the agent reads itself, so the JVM's "Picked
 * up JAVA_TOOL_OPTIONS: …" stderr line leaks nothing.
 */
import { existsSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { logForDebugging } from '../utils/debug.js'
import {
  getGlobalNpmPaths,
  getGlobalNpmPathsAsync,
} from './generate-seccomp-filter.js'

export const JAVA_PROXY_AGENT_JAR_NAME = 'srt-proxy-agent.jar'

const jarPathCache = new Map<string, string | null>()

/**
 * Locate srt-proxy-agent.jar. Order:
 * 0. explicit path (config `javaAgentJarPath`) — used if it exists,
 * 1. vendor/java-proxy-agent/ next to this module (bundled),
 * 2. ../../vendor/java-proxy-agent/ (package root — normal npm install),
 * 3. ../vendor/java-proxy-agent/ (dist/vendor — some bundlers),
 * 4. a global npm install of the package (native builds without vendor/).
 * Returns null when nothing is found; callers then leave JAVA_TOOL_OPTIONS
 * alone (JVMs are simply not proxy-aware, as before) rather than failing.
 */
export function getJavaProxyAgentJarPath(explicitPath?: string): string | null {
  const key = explicitPath ?? ''
  const cached = jarPathCache.get(key)
  if (cached !== undefined) return cached
  const found = findLocalJar(explicitPath) ?? findGlobalJar(getGlobalNpmPaths())
  jarPathCache.set(key, found)
  return found
}

/**
 * Async variant of {@link getJavaProxyAgentJarPath}, used by initialize():
 * same lookup order and cache, but the global-npm fallback resolves
 * `npm root -g` without blocking the event loop.
 */
export async function getJavaProxyAgentJarPathAsync(
  explicitPath?: string,
): Promise<string | null> {
  const key = explicitPath ?? ''
  const cached = jarPathCache.get(key)
  if (cached !== undefined) return cached
  const found =
    findLocalJar(explicitPath) ?? findGlobalJar(await getGlobalNpmPathsAsync())
  jarPathCache.set(key, found)
  return found
}

const JAR_REL_PATH = join(
  'vendor',
  'java-proxy-agent',
  JAVA_PROXY_AGENT_JAR_NAME,
)

/** Steps 0–3 of the lookup; undefined means try the global npm install. */
function findLocalJar(explicitPath?: string): string | undefined {
  if (explicitPath) {
    if (existsSync(explicitPath)) return explicitPath
    logForDebugging(
      `[java-proxy-agent] javaAgentJarPath not found: ${explicitPath}`,
      { level: 'warn' },
    )
  }
  const baseDir = dirname(fileURLToPath(import.meta.url))
  const candidates = [
    join(baseDir, JAR_REL_PATH),
    join(baseDir, '..', '..', JAR_REL_PATH),
    join(baseDir, '..', JAR_REL_PATH),
  ]
  return candidates.find(p => existsSync(p))
}

/** Step 4 of the lookup: a global npm install of the package. */
function findGlobalJar(globalBases: string[]): string | null {
  for (const base of globalBases) {
    const p = join(base, JAR_REL_PATH)
    if (existsSync(p)) return p
  }
  logForDebugging(
    `[java-proxy-agent] ${JAVA_PROXY_AGENT_JAR_NAME} not found; JVMs in the ` +
      `sandbox will not be pointed at the proxy (run \`npm run build:java-agent\`)`,
    { level: 'warn' },
  )
  return null
}

/**
 * Compose the JAVA_TOOL_OPTIONS value for a sandboxed child.
 *
 * `-javaagent:<jar>` is prepended when a jar path is given; `flags` are
 * appended (e.g. macOS's -Djava.net.preferIPv4Stack=true). The parent's
 * own JAVA_TOOL_OPTIONS is preserved unless that var is on the
 * credential-deny list, in which case it is dropped so the deny holds.
 * Flags already present in the inherited value are not duplicated.
 * Returns undefined when there is nothing to set.
 */
export function buildJavaToolOptions(opts: {
  agentJarPath?: string
  flags?: string[]
  unsetEnvVars?: string[]
  inherited?: string
}): string | undefined {
  const denied = (opts.unsetEnvVars ?? []).includes('JAVA_TOOL_OPTIONS')
  const inherited = denied ? '' : (opts.inherited ?? '')
  const parts: string[] = []
  if (opts.agentJarPath) {
    parts.push(javaAgentFlag(opts.agentJarPath))
  }
  if (inherited) parts.push(inherited)
  for (const flag of opts.flags ?? []) {
    if (!inherited.includes(flag) && !parts.includes(flag)) parts.push(flag)
  }
  return parts.length > 0 ? parts.join(' ') : undefined
}

/**
 * The JVM tokenizes JAVA_TOOL_OPTIONS on whitespace but honours double
 * quotes, so a jar path containing whitespace is wrapped in them.
 */
function javaAgentFlag(jarPath: string): string {
  const flag = `-javaagent:${jarPath}`
  return /\s/.test(jarPath) ? `"${flag}"` : flag
}
