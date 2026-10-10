// Run in an isolated Bun process: platform/spawn spies and the exit handler
// must not affect another test. Only the native ACL executable is substituted;
// its replacement is a real delayed subprocess, including stdin and exit codes.
import { spyOn } from 'bun:test'
import * as childProcess from 'node:child_process'
import * as platform from '../../src/utils/platform.js'
import * as windows from '../../src/sandbox/windows-sandbox-utils.js'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import type { SandboxRuntimeConfig } from '../../src/sandbox/sandbox-config.js'

const [mode, logPath] = process.argv.slice(2)
process.env.SRT_DEBUG = '1'
const realSpawn = childProcess.spawn
const realSpawnSync = childProcess.spawnSync
let ticks = 0
const timer = setInterval(() => ticks++, 5)
const calls: { command: string; async: boolean; ticks: number }[] = []
const order: string[] = []
let grantStarted: (() => void) | undefined
let revokeStarted: (() => void) | undefined

spyOn(platform, 'getPlatform').mockReturnValue('windows')
spyOn(windows, 'checkWindowsDependenciesAsync').mockResolvedValue({
  errors: [],
  warnings: [],
})
spyOn(windows, 'getWindowsSandboxUserStatusAsync').mockResolvedValue({
  provisioned: true,
  credPresent: true,
  sid: 'S-1-5-21-test',
} as windows.WindowsSandboxUserStatus)
spyOn(windows, 'verifyWindowsWfpEgress').mockResolvedValue({
  target: '127.0.0.1:1',
  stderr: 'BLOCKED',
})
spyOn(windows, 'expandWindowsFsPaths').mockImplementation(paths =>
  paths.map(path => (typeof path === 'string' ? path : path.path)),
)

function prepare(argv: readonly string[], async: boolean) {
  const command = argv[argv.indexOf('acl') + 1]
  if (!['grant', 'stamp', 'revoke', 'restore'].includes(command)) {
    throw new Error(`Unexpected subprocess: ${argv.join(' ')}`)
  }
  const call = { command, async, ticks: 0 }
  calls.push(call)
  const before = ticks
  order.push(`${command}:start`)
  if (command === 'grant') grantStarted?.()
  if (command === 'revoke') revokeStarted?.()
  const failed = mode === `fail-${command}`
  const releasing = command === 'revoke' || command === 'restore'
  const output = releasing
    ? command === 'restore'
      ? {
          paths: [
            { path: 'secret', status: failed ? 'leftChanged' : 'revoked' },
          ],
          parents: [],
        }
      : [{ path: 'workspace', status: failed ? 'leftChanged' : 'revoked' }]
    : undefined
  const program = `
    const fs = require('node:fs');
    let input = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', chunk => { input += chunk; });
    process.stdin.on('end', () => setTimeout(() => {
      fs.appendFileSync(${JSON.stringify(logPath)}, JSON.stringify({
        command: ${JSON.stringify(command)},
        argv: ${JSON.stringify(argv)},
        input
      }) + '\\n');
      process.stdout.write(${JSON.stringify(output ? JSON.stringify(output) : '')});
      process.stderr.write(${JSON.stringify(failed ? 'some inputs skipped' : '')});
      process.exit(${failed ? 2 : 0});
    }, 80));
  `
  return {
    program,
    done() {
      call.ticks = ticks - before
      order.push(`${command}:end`)
    },
  }
}

spyOn(childProcess, 'spawn').mockImplementation(((
  _exe: string,
  argv: readonly string[],
  options: childProcess.SpawnOptions,
) => {
  const run = prepare(argv, true)
  const child = realSpawn(process.execPath, ['-e', run.program], options)
  child.once('close', run.done)
  return child
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
}) as any)
spyOn(childProcess, 'spawnSync').mockImplementation(((
  _exe: string,
  argv: readonly string[],
  options: childProcess.SpawnSyncOptions,
) => {
  const run = prepare(argv, false)
  const result = realSpawnSync(process.execPath, ['-e', run.program], options)
  run.done()
  return result
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
}) as any)

const config: SandboxRuntimeConfig = {
  network: {
    allowedDomains: [],
    deniedDomains: [],
    httpProxyPort: 60080,
    socksProxyPort: 60081,
  },
  filesystem: {
    allowRead: ['readable'],
    allowWrite: ['workspace'],
    denyRead: ['secret'],
    denyWrite: ['readonly'],
  },
  windows: { srtWin: { path: process.execPath } },
}

let error: { code?: string; message: string } | undefined
try {
  if (mode === 'concurrent-reset') {
    const started = new Promise<void>(resolve => {
      grantStarted = resolve
    })
    const initializing = SandboxManager.initialize(config)
    await started
    await Promise.all([
      initializing,
      SandboxManager.initialize(config),
      SandboxManager.reset(),
      SandboxManager.reset(),
    ])
  } else {
    await SandboxManager.initialize(config)
    if (mode === 'exit') process.exit(0)
    if (mode === 'reinitialize') {
      const started = new Promise<void>(resolve => {
        revokeStarted = resolve
      })
      const resetting = SandboxManager.reset()
      await started
      await Promise.all([resetting, SandboxManager.initialize(config)])
    }
    await SandboxManager.reset()
  }
} catch (e) {
  error = {
    code: (e as windows.WindowsSandboxError).code,
    message: (e as Error).message,
  }
}
// A failed init must have finished rollback before its rejection is observed.
const callsAtCompletion = calls.length
await SandboxManager.reset()
clearInterval(timer)
console.log(JSON.stringify({ calls, order, error, callsAtCompletion }))
