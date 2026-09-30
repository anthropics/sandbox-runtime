// A second host process: a session of its own, one sandboxed command, and
// that command's result as JSON on stdout. argv[2]: `{ cwd, config, command }`.
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import type { SandboxRuntimeConfig } from '../../src/sandbox/sandbox-config.js'
import { spawnAsync } from './spawn.js'

const { cwd, config, command } = JSON.parse(process.argv[2]) as {
  cwd: string
  config: SandboxRuntimeConfig
  command: string
}
process.chdir(cwd)
await SandboxManager.initialize(config)
try {
  const w = await SandboxManager.wrapWithSandboxArgv(command)
  const r = await spawnAsync(w.argv[0], w.argv.slice(1), {
    env: w.env,
    timeout: 60_000,
  })
  console.log(JSON.stringify(r))
} finally {
  await SandboxManager.reset()
}
process.exit(0)
