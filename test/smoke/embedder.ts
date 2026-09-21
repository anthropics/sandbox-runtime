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

  try {
    await SandboxManager.initialize({
      network: { allowedDomains: [], deniedDomains: [] },
      filesystem: {
        denyRead: [],
        allowWrite: [work],
        denyWrite: [join(work, 'denied.txt')],
      },
      ...(applyPath === undefined ? {} : { seccomp: { applyPath } }),
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
        ...(applyPath === undefined ? {} : { seccomp: { applyPath } }),
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
    await SandboxManager.reset()
    rmSync(root, { recursive: true, force: true })
  }
}

main().catch((error: unknown) => {
  console.error(error)
  process.exit(1)
})
