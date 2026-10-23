/**
 * What an embedder ships, in miniature. bundled.test.ts compiles this and the
 * BUILT package (dist/) into one minified executable of bytecode, where a
 * function's name, its source text and the files beside it are all gone. It
 * wraps a real command, checks what that did on the host, and checks that a
 * refusal keeps the name and the code a caller branches on. The library comes
 * through `import()`, so that a split bundle puts it in a chunk of its own.
 *
 * SRT_SMOKE_APPLY_SECCOMP names the seccomp helper. With SRT_SMOKE_MULTICALL=1
 * the helper and ripgrep are reached as by an embedder that carries both: by
 * starting this executable under their names (`seccomp.argv0` with fd 3 open
 * on it, and `ripgrep.argv0`).
 */
import { spawnSync } from 'node:child_process'
import {
  appendFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  realpathSync,
  rmSync,
} from 'node:fs'
import { once } from 'node:events'
import { createServer, type AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { basename, join } from 'node:path'

// The multicall part. The library names the helper in ARGV0, since nothing
// between it and the exec inside the sandbox can set argv[0].
const { ARGV0, ...env } = process.env
const name = ARGV0 === 'apply-seccomp' ? ARGV0 : basename(process.argv0)
if (name === 'apply-seccomp' || name === 'rg') {
  appendFileSync(env.SRT_SMOKE_MULTICALL_LOG ?? '/dev/null', `${name}\n`)
  const ran = spawnSync(
    name === 'rg' ? name : (env.SRT_SMOKE_APPLY_SECCOMP ?? name),
    process.argv.slice(2),
    { stdio: 'inherit', env },
  )
  if (ran.error !== undefined) console.error(`${name}: ${String(ran.error)}`)
  process.exit(ran.status ?? 127)
}

function check(what: string, ok: boolean, detail = ''): void {
  if (!ok) throw new Error(`FAILED: ${what}\n${detail}`)
  console.log(`ok: ${what}`)
}

// Bytecode is CommonJS, which has no top-level await.
async function main(): Promise<void> {
  const { SandboxManager, LinuxSandboxProfileError } = await import(
    '../../dist/index.js'
  )
  const multicall = process.env.SRT_SMOKE_MULTICALL === '1'
  const applyPath = process.env.SRT_SMOKE_APPLY_SECCOMP
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'srt-bundled-smoke-')))
  const work = join(root, 'work')
  const outside = join(root, 'outside')
  mkdirSync(work)
  mkdirSync(outside)
  // Where a wrapped command can write: the helper is started inside.
  const multicallLog = join(work, 'multicall.log')
  if (multicall) process.env.SRT_SMOKE_MULTICALL_LOG = multicallLog

  const config = {
    network: { allowedDomains: [], deniedDomains: [] },
    filesystem: {
      denyRead: [],
      allowWrite: [work],
      denyWrite: [join(work, 'denied.txt')],
    },
    // The container job says it is one the way it says it to its suite.
    enableWeakerNestedSandbox: process.env.SRT_E2E_DOCKER === '1',
    ...(multicall
      ? {
          seccomp: { applyPath: '/proc/self/fd/3', argv0: 'apply-seccomp' },
          ripgrep: { command: process.execPath, args: [], argv0: 'rg' },
        }
      : { seccomp: { applyPath } }),
  }

  try {
    await SandboxManager.initialize(config)

    // After initialize, so that the configured helper is the one looked for.
    const { warnings } = SandboxManager.checkDependencies()
    check(
      'the dependency check finds the seccomp helper',
      !warnings.some(w => w.includes('seccomp')),
      warnings.join('\n'),
    )

    // A listener on the host, which the same words reach from outside the
    // sandbox: without that, "blocked" could mean a shell that cannot connect.
    const listener = createServer().listen(0, '127.0.0.1').unref()
    await once(listener, 'listening')
    const { port } = listener.address() as AddressInfo
    const connect = `(exec 9<>/dev/tcp/127.0.0.1/${port}) 2>/dev/null && echo NET-OPEN || echo NET-BLOCKED`
    check(
      'the listener is reachable from outside the sandbox',
      spawnSync('bash', ['-c', connect], { encoding: 'utf8' }).stdout ===
        'NET-OPEN\n',
    )

    const wrapped = await SandboxManager.wrapWithSandbox(
      [
        'echo BOOTED',
        'echo allowed > allowed.txt',
        'echo denied > denied.txt 2>/dev/null || echo WRITE-DENIED',
        'echo outside > ../outside/x.txt 2>/dev/null || echo OUTSIDE-DENIED',
        connect,
        'grep -q "^Seccomp:[[:space:]]*2" /proc/self/status 2>/dev/null && echo SECCOMP-ON || echo SECCOMP-OFF',
        'exit 7',
      ].join('; '),
    )
    const result = spawnSync(wrapped, {
      shell: true,
      encoding: 'utf8',
      cwd: work,
      timeout: 60000,
      stdio: multicall
        ? ['ignore', 'pipe', 'pipe', openSync(process.execPath, 'r')]
        : 'pipe',
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
    check(
      'the command ran under the seccomp filter',
      process.platform !== 'linux' || output.includes('SECCOMP-ON'),
      output,
    )
    for (const program of multicall ? ['rg', 'apply-seccomp'] : []) {
      const started = readFileSync(multicallLog, 'utf8')
      check(
        `this executable was started as ${program}`,
        started.split('\n').includes(program),
        started,
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
    check(
      'the configuration reads back',
      SandboxManager.getConfig()?.filesystem.allowWrite.includes(work) === true,
    )

    if (process.platform === 'linux') {
      // More absent deny paths than bubblewrap takes arguments for: the wrap
      // is refused before anything is spawned or written.
      SandboxManager.updateConfig({
        ...config,
        filesystem: {
          ...config.filesystem,
          denyWrite: Array.from({ length: 4000 }, (_, i) =>
            join(work, `absent-${i}`),
          ),
        },
      })
      const refusal: unknown = await SandboxManager.wrapWithSandbox(
        'true',
      ).catch((error: unknown) => error)
      check(
        'a profile that does not fit is refused with an error that keeps its type, name and code',
        refusal instanceof LinuxSandboxProfileError &&
          refusal.name === 'LinuxSandboxProfileError' &&
          refusal.code === 'too_many_arguments',
        String(refusal),
      )
    }
    console.log('SMOKE OK')
  } finally {
    await SandboxManager.reset()
    rmSync(root, { recursive: true, force: true })
  }
}

main().catch((error: unknown) => {
  // Not the error itself: the runtime would print the minified source with it.
  console.error(error instanceof Error ? error.stack : error)
  process.exit(1)
})
