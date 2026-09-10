import { spawn } from 'node:child_process'

type RunOpts = {
  shell?: boolean
  encoding?: 'utf8'
  timeout?: number
  cwd?: string
  env?: NodeJS.ProcessEnv
  /**
   * Bytes written to the child's stdin before EOF (like spawnSync's
   * `input`). Used for `srt-win exec --env-stdin`'s secret-env frame
   * (`wrapWithSandboxArgv`'s `stdinPayload`).
   */
  input?: Buffer | string
}

export type RunResult = {
  stdout: string
  stderr: string
  status: number | null
  signal: NodeJS.Signals | null
}

/**
 * Async stand-in for spawnSync, for tests that drive a wrapped command
 * which talks back to the in-process HTTP/SOCKS proxy. spawnSync would
 * block this event loop while curl waits for that same proxy to respond,
 * which is a self-deadlock — bun 1.3.2+ runs spawnSync on an isolated
 * loop so the main loop's I/O never ticks during the wait.
 *
 * Mirrors enough of spawnSync's surface for the test call sites:
 *   - (cmd, opts)            → shell:true by default
 *   - (cmd, args[], opts)    → argv form, no shell
 *   - opts.timeout           → SIGTERM after N ms (like spawnSync)
 *   - stdin                  → closed immediately (EOF), like spawnSync
 *                              with no `input`
 */
export async function spawnAsync(
  cmd: string,
  argsOrOpts?: readonly string[] | RunOpts,
  maybeOpts?: RunOpts,
): Promise<RunResult> {
  const args = Array.isArray(argsOrOpts) ? argsOrOpts : undefined
  const opts = (Array.isArray(argsOrOpts) ? maybeOpts : argsOrOpts) ?? {}
  const child = args
    ? spawn(cmd, args, { cwd: opts.cwd, env: opts.env })
    : spawn(cmd, { shell: opts.shell ?? true, cwd: opts.cwd, env: opts.env })

  // Match spawnSync: write `input` (if any), then EOF. Without the
  // end(), things like `su` wait for a password on the open pipe.
  // EPIPE (child exited before reading the payload — its exit
  // code/stderr is the real diagnostic) is absorbed ONLY when an
  // `input` was actually written, mirroring
  // src/sandbox/windows-sandbox-utils.ts `writeStdinPayload` (the
  // production writer; local copy so this generic helper stays free
  // of prod imports). Anything else re-emits on the child →
  // unhandled 'error' → the test fails loudly.
  child.stdin?.on('error', (e: NodeJS.ErrnoException) => {
    if (opts.input === undefined || e.code !== 'EPIPE') child.emit('error', e)
  })
  if (opts.input !== undefined) child.stdin?.write(opts.input)
  child.stdin?.end()

  let stdout = ''
  let stderr = ''
  child.stdout?.setEncoding('utf8').on('data', d => (stdout += d))
  child.stderr?.setEncoding('utf8').on('data', d => (stderr += d))

  let timer: ReturnType<typeof setTimeout> | undefined
  let signal: NodeJS.Signals | null = null
  if (opts.timeout) {
    timer = setTimeout(() => {
      signal = 'SIGTERM'
      child.kill('SIGTERM')
    }, opts.timeout)
  }

  const status = await new Promise<number | null>(resolve =>
    child.on('close', code => resolve(code)),
  )
  if (timer) clearTimeout(timer)
  return { stdout, stderr, status, signal }
}
