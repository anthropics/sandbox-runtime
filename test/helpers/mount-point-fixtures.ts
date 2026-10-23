import { expect } from 'bun:test'
import { spawnSync } from 'node:child_process'
import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readlinkSync,
  writeFileSync,
} from 'node:fs'
import { join } from 'node:path'
import {
  LinuxSandboxProfileError,
  wrapCommandWithSandboxLinux,
} from '../../src/sandbox/linux-sandbox-utils.js'
import { manifestOf } from './bwrap-argv.js'

/** A process as a manifest, a started record or a pass names one. */
export type Process = { pid: number; start: string }

/** What bubblewrap leaves on the host for `--ro-bind /dev/null <absent>`. */
export function leftover(p: string): void {
  writeFileSync(p, '')
  chmodSync(p, 0o444)
}

/** A pid nothing in this PID namespace has. */
export function deadPid(): number {
  for (let pid = 4194000; pid > 1; pid--) {
    if (!existsSync(`/proc/${pid}`)) return pid
  }
  throw new Error('no free pid')
}

/** Field 22 of a /proc/PID/stat line: when that process started. */
export function startOf(stat: string): string | undefined {
  return stat
    .slice(stat.lastIndexOf(')') + 1)
    .trim()
    .split(' ')[19]
}

export function processAt(pid: number): Process {
  return { pid, start: startOf(readFileSync(`/proc/${pid}/stat`, 'utf8'))! }
}

/** This process, which is running. */
export const thisProcess = (): Process => processAt(process.pid)

/** One that is gone. */
export const aDeadProcess = (): Process => ({ pid: deadPid(), start: '1' })

/**
 * The manifest of a wrap that named `paths`, in `dir`, which is made: written a
 * minute ago, so long past its grace, by a process that is gone. What a killed
 * process leaves. `fields` overrides what it says, and one that is undefined is
 * left out.
 */
export function writeManifest(
  dir: string,
  paths: string[],
  fields: Record<string, unknown> = {},
): string {
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  chmodSync(dir, 0o700)
  const body: Record<string, unknown> = {
    version: 1,
    ...aDeadProcess(),
    ns: readlinkSync('/proc/self/ns/pid'),
    created: Date.now() - 60_000,
    paths,
    sources: [],
    ...fields,
  }
  for (const [key, value] of Object.entries(body)) {
    if (value === undefined) delete body[key]
  }
  const file = join(
    dir,
    `${String(body['pid'])}-${Math.random().toString(16).slice(2).padEnd(16, '0')}.json`,
  )
  writeFileSync(file, JSON.stringify(body), { mode: 0o600 })
  return file
}

/** Where the started record of `manifest` is. */
export const recordOf = (manifest: string): string =>
  manifest.replace(/\.json$/, '.started')

/**
 * The line the wrapper shell records for a process, with a name that holds what
 * a careless reading would trip over.
 */
export function statLine(who: Process): string {
  const after = ['S', ...Array<string>(18).fill('0'), who.start, '0', '0']
  return `${who.pid} (a) b (c) ${after.join(' ')}\n`
}

/** Puts `manifest` on record as started by those processes, in that order. */
export function started(manifest: string, ...by: Process[]): string {
  writeFileSync(recordOf(manifest), by.map(statLine).join(''), { mode: 0o600 })
  return manifest
}

/** The code the wrap was refused with. */
export async function refusal(wrapping: Promise<string>): Promise<unknown> {
  const thrown: unknown = await wrapping.then(
    () => 'the wrap resolved',
    (error: unknown) => error,
  )
  expect(thrown).toBeInstanceOf(LinuxSandboxProfileError)
  return (thrown as LinuxSandboxProfileError).code
}

/** The mount points the wrap named in its manifest, none without one. */
export function namedBy(command: string): string[] {
  const file = manifestOf(command)
  return file === undefined
    ? []
    : (JSON.parse(readFileSync(file, 'utf8')) as { paths: string[] }).paths
}

export function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms))
}

export async function until(
  what: string,
  holds: () => boolean,
  timeoutMs = 30000,
): Promise<void> {
  const deadline = Date.now() + timeoutMs
  while (!holds()) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`)
    await sleep(10)
  }
}

/** Until `file` is there: how a command in a sandbox says how far it has got. */
export const waitFor = (file: string, timeoutMs?: number): Promise<void> =>
  until(file, () => existsSync(file), timeoutMs)

/** `command`, allowed to write `area` but for `deny`. */
export function wrapIn(
  area: string,
  command: string,
  deny: string[],
): Promise<string> {
  return wrapCommandWithSandboxLinux({
    command,
    needsNetworkRestriction: false,
    readConfig: { denyOnly: [] },
    writeConfig: { allowOnly: [area], denyWithinAllow: deny },
  })
}

/**
 * The line by which a process of its own, which has imported the library, does
 * the like: what it is handed is `wrapped`.
 */
export const wrapLine = (
  allowOnly: string[],
  command: string,
  deny: string[],
): string =>
  `const wrapped = await wrapCommandWithSandboxLinux(${JSON.stringify({
    command,
    needsNetworkRestriction: false,
    readConfig: { denyOnly: [] },
    writeConfig: { allowOnly, denyWithinAllow: deny },
  })})`

export function run(command: string): {
  status: number | null
  said: string
  stdout: string
} {
  const r = spawnSync(command, {
    shell: true,
    encoding: 'utf8',
    timeout: 60000,
  })
  return { status: r.status, said: `${r.stdout}${r.stderr}`, stdout: r.stdout }
}

/** Writes a script of those lines to `dir`, for a process of its own. */
export function writeScript(
  dir: string,
  name: string,
  lines: string[],
): string {
  const file = join(dir, name)
  writeFileSync(file, lines.join('\n'))
  return file
}
