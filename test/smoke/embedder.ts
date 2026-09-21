/**
 * What an embedder ships, in miniature. `npm run test:bundled` compiles this
 * program and the BUILT package it imports (dist/, not src/) into one minified
 * file of bytecode, the way an application that embeds the library is built,
 * and runs the result. The suites run the sources unbundled, so nothing else
 * would notice code that leans on a function's name, on its own source text,
 * or on a file that sits beside it on disk.
 *
 * It wraps real commands and checks what they did on the host, and that a
 * refusal still carries the name and the code a caller branches on once every
 * identifier has been shortened. The library is reached through `import()`, so
 * that where the bundle is split into chunks it sits in one of its own.
 *
 * A compiled program has no package directory around it: no `vendor/`, no
 * `node_modules`, no `package.json`, and `import.meta.url` names nothing on
 * disk. The runner (run-bundled.ts) runs it from a directory of its own for
 * that reason, and names the seccomp helper to it in SRT_SMOKE_APPLY_SECCOMP,
 * as an embedder names its own copy to the library.
 *
 * With SRT_SMOKE_MULTICALL=1 it goes one step further, to the arrangement of
 * an embedder that has the helper and ripgrep INSIDE its own executable and
 * reaches them by running itself under another name: `seccomp.argv0` with
 * `applyPath: '/proc/self/fd/3'`, fd 3 being an open handle on the executable
 * that every wrapped command inherits, and `ripgrep.argv0` with the
 * executable as the command. This program plays that executable: started as
 * `apply-seccomp` or as `rg`, it runs the real one (see runAsAnotherProgram).
 * No file path of a helper is given to the library then, and none may be
 * looked for.
 */
import { spawnSync } from 'node:child_process'
import {
  appendFileSync,
  closeSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  realpathSync,
  rmSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { basename, join } from 'node:path'

/**
 * What a multicall executable does first: if it was started under the name of
 * a program it carries, be that program. The library names the helper through
 * the ARGV0 variable, since nothing between it and the exec inside the sandbox
 * can set argv[0], and ripgrep through argv[0] itself.
 */
function runAsAnotherProgram(): void {
  const name = process.env.ARGV0 ?? basename(process.argv0)
  const real =
    name === 'apply-seccomp'
      ? process.env.SRT_SMOKE_APPLY_SECCOMP
      : name === 'rg'
        ? process.env.SRT_SMOKE_RG
        : undefined
  if (name !== 'apply-seccomp' && name !== 'rg') return
  if (real === undefined) {
    console.error(`started as ${name}, and no ${name} to run was named`)
    process.exit(127)
  }
  const log = process.env.SRT_SMOKE_MULTICALL_LOG
  if (log !== undefined) {
    try {
      appendFileSync(log, `${name}\n`)
    } catch {
      // Not writable from where this was started: the run is what matters.
    }
  }
  // The name is this process's, not what it runs.
  const env = { ...process.env }
  delete env.ARGV0
  const ran = spawnSync(real, process.argv.slice(2), { stdio: 'inherit', env })
  if (ran.error !== undefined) {
    console.error(`${name}: ${String(ran.error)}`)
    process.exit(127)
  }
  process.exit(ran.status ?? 128)
}
runAsAnotherProgram()

function check(what: string, ok: boolean, detail = ''): void {
  if (!ok) {
    console.error(`FAILED: ${what}${detail === '' ? '' : `\n${detail}`}`)
    process.exit(1)
  }
  console.log(`ok: ${what}`)
}

// Bytecode is CommonJS, which has no top-level await.
async function main(): Promise<void> {
  const { SandboxManager, LinuxSandboxProfileError } = await import(
    '../../dist/index.js'
  )
  const multicall = process.env.SRT_SMOKE_MULTICALL === '1'
  const applyPath = process.env.SRT_SMOKE_APPLY_SECCOMP
  // Inside a container the host masks /proc, and a sandbox nested in one
  // has to be the weaker kind the library has a setting for; the container
  // job says so the way it says it to the suite it runs.
  const nested =
    process.env.SRT_E2E_DOCKER === '1'
      ? { enableWeakerNestedSandbox: true }
      : {}
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'srt-bundled-smoke-')))
  const work = join(root, 'work')
  const outside = join(root, 'outside')
  mkdirSync(work)
  mkdirSync(outside)

  // How the library is told to reach the helper and ripgrep. Carried inside
  // this executable: fd 3 of every wrapped command is a handle on it, and the
  // shim above writes a line where a wrapped command can write, each time it
  // is started as one of them.
  const multicallLog = join(work, 'multicall.log')
  const self = multicall ? openSync(process.execPath, 'r') : undefined
  if (multicall) process.env.SRT_SMOKE_MULTICALL_LOG = multicallLog
  const tools = multicall
    ? {
        seccomp: { applyPath: '/proc/self/fd/3', argv0: 'apply-seccomp' },
        ripgrep: { command: process.execPath, args: [], argv0: 'rg' },
      }
    : applyPath === undefined
      ? {}
      : { seccomp: { applyPath } }
  const helperExpected = process.platform === 'linux' && 'seccomp' in tools

  try {
    await SandboxManager.initialize({
      network: { allowedDomains: [], deniedDomains: [] },
      filesystem: {
        denyRead: [],
        allowWrite: [work],
        denyWrite: [join(work, 'denied.txt')],
      },
      ...tools,
      ...nested,
    })

    // After initialize, so that the helper the configuration names is the
    // one that is looked for.
    const dependencies = SandboxManager.checkDependencies()
    check(
      'the dependency check finds nothing missing',
      dependencies.errors.length === 0,
      dependencies.errors.join('\n'),
    )

    const wrapped = await SandboxManager.wrapWithSandbox(
      [
        'echo BOOTED',
        `echo allowed > ${join(work, 'allowed.txt')}`,
        `echo denied > ${join(work, 'denied.txt')} 2>/dev/null || echo WRITE-DENIED`,
        `echo outside > ${join(outside, 'x.txt')} 2>/dev/null || echo OUTSIDE-DENIED`,
        '(exec 9<>/dev/tcp/1.1.1.1/80) 2>/dev/null && echo NET-OPEN || echo NET-BLOCKED',
        'grep -q "^Seccomp:[[:space:]]*2" /proc/self/status 2>/dev/null && echo SECCOMP-ON || echo SECCOMP-OFF',
        'exit 7',
      ].join('; '),
    )
    const result = spawnSync(wrapped, {
      shell: true,
      encoding: 'utf8',
      cwd: work,
      timeout: 60000,
      // fd 3 of the command is this executable, where that is how the helper
      // is reached.
      stdio: self === undefined ? 'pipe' : ['ignore', 'pipe', 'pipe', self],
    })
    const output = `${result.stdout}${result.stderr}`
    check('the wrapped command started', output.includes('BOOTED'), output)
    check(
      'a write inside the allowed directory lands',
      existsSync(join(work, 'allowed.txt')) &&
        readFileSync(join(work, 'allowed.txt'), 'utf8') === 'allowed\n',
      output,
    )
    check(
      'a write to a denied path inside it does not',
      output.includes('WRITE-DENIED') &&
        (!existsSync(join(work, 'denied.txt')) ||
          readFileSync(join(work, 'denied.txt'), 'utf8') === ''),
      output,
    )
    check(
      'a write outside it does not',
      output.includes('OUTSIDE-DENIED') && !existsSync(join(outside, 'x.txt')),
      output,
    )
    check(
      'the network is closed',
      output.includes('NET-BLOCKED') && !output.includes('NET-OPEN'),
      output,
    )
    if (helperExpected) {
      check(
        'the command ran under the seccomp filter',
        output.includes('SECCOMP-ON'),
        output,
      )
    }
    if (multicall) {
      const started = existsSync(multicallLog)
        ? readFileSync(multicallLog, 'utf8').split('\n')
        : []
      check(
        'the scan ran ripgrep by starting this executable as rg',
        started.includes('rg'),
        started.join(','),
      )
      check(
        'the command reached the helper by starting this executable as apply-seccomp, through fd 3',
        started.includes('apply-seccomp'),
        started.join(','),
      )
    }
    check(
      "the command's own exit status comes back",
      result.status === 7,
      `status ${String(result.status)}\n${output}`,
    )

    SandboxManager.cleanupAfterCommand()
    check(
      'the mount point for the denied path is gone after the command',
      !existsSync(join(work, 'denied.txt')),
    )

    const config = SandboxManager.getConfig()
    check(
      'the configuration reads back',
      config?.filesystem.allowWrite.includes(work) === true,
    )

    if (process.platform === 'linux') {
      // More absent deny paths than bubblewrap takes arguments for: the wrap
      // is refused before anything is spawned or written.
      SandboxManager.updateConfig({
        network: { allowedDomains: [], deniedDomains: [] },
        filesystem: {
          denyRead: [],
          allowWrite: [work],
          denyWrite: Array.from({ length: 4000 }, (_, i) =>
            join(work, `absent-${i}`),
          ),
        },
        ...tools,
        ...nested,
      })
      const refusal: unknown = await SandboxManager.wrapWithSandbox(
        'true',
      ).then(
        () => undefined,
        (error: unknown) => error,
      )
      check(
        'a profile that does not fit is refused with a typed error',
        refusal instanceof LinuxSandboxProfileError,
        String(refusal),
      )
      const typed = refusal as InstanceType<typeof LinuxSandboxProfileError>
      check(
        'which keeps its name and its code with every identifier shortened',
        typed.name === 'LinuxSandboxProfileError' &&
          typed.code === 'too_many_arguments',
        `name ${typed.name}, code ${String(typed.code)}`,
      )
    }
    console.log('SMOKE OK')
  } finally {
    if (self !== undefined) closeSync(self)
    await SandboxManager.reset()
    rmSync(root, { recursive: true, force: true })
  }
}

main().catch((error: unknown) => {
  console.error(error)
  process.exit(1)
})
