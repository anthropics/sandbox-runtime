/**
 * Build the JVM proxy agent (vendor/java-proxy-agent-src) into
 * vendor/java-proxy-agent/srt-proxy-agent.jar.
 *
 * Same model as the seccomp / srt-win helpers: only the source is in git,
 * the artifact is built by the release workflow and shipped in the npm
 * package, and consumers that bundle srt point at their own copy via the
 * `javaAgentJarPath` config key. The jar is reproducible: `jar --date`
 * pins entry timestamps, and STORED entries in a fixed order.
 *
 *   npm run build:java-agent        (needs a JDK >= 17 on PATH or JAVA_HOME)
 */
import { spawnSync } from 'node:child_process'
import {
  mkdtempSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { run } from '../build-common.js'

const here = dirname(fileURLToPath(import.meta.url))
const SRC = join(here, '..', 'java-proxy-agent-src')
const OUT = join(here, 'srt-proxy-agent.jar')
const AGENT_CLASS = 'com.anthropic.srt.ProxyAgent'

const bin = (tool: string) =>
  process.env.JAVA_HOME ? join(process.env.JAVA_HOME, 'bin', tool) : tool
const javac = bin('javac')
const jar = bin('jar')
const version = spawnSync(javac, ['-version'], { encoding: 'utf8' })
if (version.error) {
  console.error(
    `java-proxy-agent build: cannot run ${javac}: ${version.error.message}`,
  )
  process.exit(1)
}

function walk(dir: string): string[] {
  const out: string[] = []
  for (const name of readdirSync(dir).sort()) {
    const p = join(dir, name)
    if (statSync(p).isDirectory()) out.push(...walk(p))
    else out.push(p)
  }
  return out
}

const work = mkdtempSync(join(tmpdir(), 'srt-java-agent-'))
try {
  const classes = join(work, 'classes')
  const sources = walk(SRC).filter(f => f.endsWith('.java'))
  // --release 8: the agent runs inside whatever JVM the sandboxed tool
  // brings, and Java 8 is still common in build tooling.
  run([
    javac,
    '--release',
    '8',
    '-Xlint:all,-options',
    '-Werror',
    '-g:none',
    '-d',
    classes,
    ...sources,
  ])

  const manifest = join(work, 'MANIFEST.MF')
  writeFileSync(
    manifest,
    `Premain-Class: ${AGENT_CLASS}\nAgent-Class: ${AGENT_CLASS}\n`,
  )
  // -0: STORED (no compression). --date: fixed entry timestamps. Entries
  // are added in a fixed order (walk() sorts) so the bytes are reproducible.
  const entries = walk(classes).map(f => f.slice(classes.length + 1))
  run([
    jar,
    '--create',
    '--file',
    OUT,
    '--manifest',
    manifest,
    '--no-compress',
    '--date',
    '1980-01-01T00:00:02Z',
    // -C applies to the single following file, so repeat it per entry.
    ...entries.flatMap(e => ['-C', classes, e]),
  ])
  console.log(`built ${OUT} (${statSync(OUT).size} bytes)`)
} finally {
  rmSync(work, { recursive: true, force: true })
}
