/**
 * What an embedder ships, in miniature. `npm run test:bundled` compiles this
 * program and the BUILT package it imports (dist/, not src/) into one minified
 * file of bytecode, the way an application that embeds the library is built,
 * and runs the result. The suites run the sources unbundled, so nothing else
 * would notice code that leans on a function's name, on its own source text,
 * or on a file that sits beside it on disk.
 *
 * It wraps real commands and checks what they did on the host. A compiled
 * program has no `vendor/` beside it, so the seccomp helper is named to the
 * library, as an embedder names its own copy: by SRT_SMOKE_APPLY_SECCOMP, or
 * else the one built in the checkout this is run from.
 */
import { spawnSync } from 'node:child_process'
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { SandboxManager } from '../../dist/index.js'

function check(what: string, ok: boolean, detail = ''): void {
  if (!ok) {
    console.error(`FAILED: ${what}${detail === '' ? '' : `\n${detail}`}`)
    process.exit(1)
  }
  console.log(`ok: ${what}`)
}

// Bytecode is CommonJS, which has no top-level await.
async function main(): Promise<void> {
  // Named by the caller, or the one this checkout built for this machine.
  const built = join(
    process.cwd(),
    'vendor',
    'seccomp',
    process.arch === 'arm64' ? 'arm64' : 'x64',
    'apply-seccomp',
  )
  const applyPath =
    process.env.SRT_SMOKE_APPLY_SECCOMP ??
    (existsSync(built) ? built : undefined)
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'srt-bundled-smoke-')))
  const work = join(root, 'work')
  const outside = join(root, 'outside')
  mkdirSync(work)
  mkdirSync(outside)

  try {
    await SandboxManager.initialize({
      network: { allowedDomains: [], deniedDomains: [] },
      filesystem: {
        denyRead: [],
        allowWrite: [work],
        denyWrite: [join(work, 'denied.txt')],
      },
      ...(applyPath === undefined ? {} : { seccomp: { applyPath } }),
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
        '(exec 3<>/dev/tcp/1.1.1.1/80) 2>/dev/null && echo NET-OPEN || echo NET-BLOCKED',
        'exit 7',
      ].join('; '),
    )
    const result = spawnSync(wrapped, {
      shell: true,
      encoding: 'utf8',
      cwd: work,
      timeout: 60000,
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
    console.log('SMOKE OK')
  } finally {
    await SandboxManager.reset()
    rmSync(root, { recursive: true, force: true })
  }
}

main().catch((error: unknown) => {
  console.error(error)
  process.exit(1)
})
