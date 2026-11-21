#!/usr/bin/env node
import pkg from '../package.json' with { type: 'json' }
import { quote } from './utils/shell-quote.js'
import { Command } from 'commander'
import { SandboxManager } from './index.js'
import type { SandboxRuntimeConfig } from './sandbox/sandbox-config.js'
import { spawn, type ChildProcess } from 'child_process'
import { logForDebugging } from './utils/debug.js'
import { loadConfig } from './utils/config-loader.js'
import {
  createControlChannel,
  openControlFd,
  openControlPipe,
  parseControlFd,
  parseControlPipe,
  type ControlChannelController,
} from './utils/control-channel.js'
import * as fs from 'fs'
import * as path from 'path'
import { finished } from 'stream/promises'
import * as os from 'os'

/**
 * Get default config path
 */
function getDefaultConfigPath(): string {
  return path.join(os.homedir(), '.srt-settings.json')
}

/**
 * The version `--version` reports, from the package's own manifest, which
 * sits one directory above both src/cli.ts and dist/cli.js. A static import
 * rather than a runtime require, so a single-file build (`bun build
 * --compile`) embeds it instead of looking for a package.json beside the
 * binary. There is still no fallback: a plausible-looking wrong version is
 * worse than failing, because the README pins behaviour to specific releases.
 */
function getPackageVersion(): string {
  return pkg.version
}

/**
 * How long a command that ignores SIGTERM gets before SIGKILL.
 */
const KILL_GRACE_MS = 2000

/**
 * Exit rather than run under the built-in defaults, naming what that would
 * cost. The defaults are not a weaker version of any settings file — they
 * are a different config, so falling back to them drops rules rather than
 * relaxing them.
 */
function refuseSettings(reason: string, lost: string): never {
  console.error(`Error: ${reason}`)
  console.error(
    `Refusing to run with the built-in defaults, which would drop ${lost}.`,
  )
  process.exit(1)
}

/**
 * What a fall-back to the built-in defaults costs when the file is there.
 */
const FILE_RULES =
  "this file's rules (its denyRead, allowRead and credential entries included)"

/**
 * Create a minimal default config if no config file exists
 */
function getDefaultConfig(): SandboxRuntimeConfig {
  return {
    network: {
      allowedDomains: [],
      deniedDomains: [],
    },
    filesystem: {
      denyRead: [],
      allowRead: [],
      allowWrite: [],
      denyWrite: [],
    },
  }
}

/**
 * stdio for the sandboxed command: the three standard streams, plus
 * /dev/null over the control fd's slot, so nothing inside the sandbox can
 * read the channel that carries the policy confining it.
 *
 * The displacement is what matters on Linux. On macOS libuv spawns through
 * posix_spawn with POSIX_SPAWN_CLOEXEC_DEFAULT, which already keeps every
 * descriptor the caller did not list out of the child.
 */
function sandboxedStdio(
  controlFd: number | undefined,
): Array<'inherit' | 'ignore' | number> {
  const stdio: Array<'inherit' | 'ignore' | number> = [
    'inherit',
    'inherit',
    'inherit',
  ]
  if (controlFd === undefined) {
    return stdio
  }
  // 'ignore' past fd 2 leaves a slot as it is rather than closing it, so the
  // control fd's slot needs a descriptor of its own to displace it with.
  while (stdio.length < controlFd) {
    stdio.push('ignore')
  }
  // Only close-on-exec keeps an inherited descriptor out of an exec'd
  // command, and uv_disable_stdio_inheritance() stops at the first closed
  // number above 15, so `--control-fd 20` with 16-19 closed leaves the
  // channel live in the sandbox. Displacing the slot covers every kind of
  // descriptor, which re-opening the fd privately does not: a unix socket
  // cannot be re-opened through /proc/self/fd at all (ENXIO).
  stdio.push(fs.openSync('/dev/null', 'r'))
  return stdio
}

async function main(): Promise<void> {
  const program = new Command()

  program
    .name('srt')
    .description(
      'Run commands in a sandbox with network and filesystem restrictions',
    )
    .version(getPackageVersion())

  // ── Windows install/uninstall ─────────────────────────────────
  // Self-elevating one-shot install (one UAC prompt). Also
  // available programmatically as installWindowsSandbox().
  program
    .command('windows-install')
    .description(
      'Windows: provision the `srt-sandbox` user account + install WFP ' +
        'filters (one UAC prompt), then make your user profile readable ' +
        'to sandboxed commands, except for credential stores (no ' +
        'elevation; minutes on a large profile the first time). No ' +
        'logout needed. Run it again after upgrading sandbox-runtime ' +
        'when a command asks for it, or to bring the profile read grant ' +
        'up to date: it upgrades the existing install in place.',
    )
    .option('--sublayer-guid <guid>', 'WFP sublayer GUID')
    .option(
      '--proxy-port-range <lo-hi>',
      'loopback PERMIT port range (e.g. 60080-60089)',
    )
    .option(
      '--allow-loopback',
      'let sandboxed commands connect to any localhost port (default: ' +
        'off); must match network.allowLocalBinding',
    )
    .option(
      '--sandbox-user <name>',
      'name for the sandbox user account (default: srt-sandbox)',
    )
    .option('--force', 'replace an existing install with different config')
    .option(
      '--profile-exclude <path>',
      'a path inside your profile to keep unreadable in addition to the ' +
        'built-in exclusions (repeatable)',
      (v: string, acc: string[]) => [...acc, v],
      [] as string[],
    )
    .option(
      '--profile-include <path>',
      'a directory inside your profile to make readable in addition to ' +
        'the built-in list of per-user tool directories (repeatable)',
      (v: string, acc: string[]) => [...acc, v],
      [] as string[],
    )
    .option(
      '--skip-profile-grant',
      'install the account and the filters only; sandboxed commands ' +
        'then read nothing in your profile (use this on a computer other ' +
        'people have accounts on)',
    )
    .action(
      async (o: Record<string, string | boolean | string[] | undefined>) => {
        const {
          installWindowsSandboxAsync,
          resolveSrtWin,
          VENDORED_SRT_WIN_EXE,
          WINDOWS_ALLOW_LOOPBACK_EFFECT,
        } = await import('./sandbox/windows-sandbox-utils.js')
        const range =
          typeof o.proxyPortRange === 'string'
            ? (o.proxyPortRange.split('-').map(Number) as [number, number])
            : undefined
        try {
          const r = await installWindowsSandboxAsync({
            sublayerGuid: o.sublayerGuid as string | undefined,
            proxyPortRange: range,
            allowLoopback: Boolean(o.allowLoopback),
            sandboxUser: o.sandboxUser as string | undefined,
            force: Boolean(o.force),
            skipProfileGrant: Boolean(o.skipProfileGrant),
            profileExclude: o.profileExclude as string[],
            profileInclude: o.profileInclude as string[],
            // One line on what is about to become readable, and how to
            // skip or undo it, before the grant is applied.
            onProfileGrantStart: notice => console.error(notice),
            onProfileGrantProgress: line => console.error(line),
            // Our own CLI opts into the packaged exe explicitly —
            // there is no ambient vendor fallback.
            srtWin: resolveSrtWin({ path: VENDORED_SRT_WIN_EXE }),
          })
          if (r.cancelled) {
            console.error(
              'Install cancelled at the UAC prompt. Nothing changed.',
            )
            process.exit(2)
          }
          console.log(
            `Installed.\n` +
              `  sandbox user: ${r.user.provisioned ? 'provisioned' : 'MISSING'}` +
              (r.user.sid ? ` (${r.user.sid})` : '') +
              `\n` +
              `  WFP:   ${r.wfp.state}, ${r.wfp.filters} filters` +
              (r.wfp.portRange
                ? `, port range ${r.wfp.portRange[0]}-${r.wfp.portRange[1]}`
                : '') +
              `\n` +
              `  profile read grant: ` +
              (r.profileGrant?.applied
                ? `applied to ${r.profileGrant.result.profile} ` +
                  `(${r.profileGrant.result.granted} directories, ` +
                  `${r.profileGrant.result.denied} excluded, ` +
                  `${r.profileGrant.result.skipped.length} skipped)`
                : `NOT applied — ${r.profileGrant?.reason ?? 'unknown'}`) +
              `\n\n` +
              `No logout needed — the WFP filter keys on the dedicated ` +
              `\`srt-sandbox\` user's SID, so your network is unaffected.` +
              (r.wfp.allowLoopback
                ? `\n\n${WINDOWS_ALLOW_LOOPBACK_EFFECT}`
                : ''),
          )
        } catch (e) {
          console.error(`Error: ${(e as Error).message}`)
          process.exit(1)
        }
      },
    )

  program
    .command('windows-uninstall')
    .description(
      'Windows: remove WFP filters + the `srt-sandbox` account (one UAC prompt).',
    )
    .option('--sublayer-guid <guid>', 'WFP sublayer GUID')
    .action(async (o: Record<string, string | undefined>) => {
      const { uninstallWindowsSandbox, resolveSrtWin, VENDORED_SRT_WIN_EXE } =
        await import('./sandbox/windows-sandbox-utils.js')
      try {
        const r = uninstallWindowsSandbox({
          sublayerGuid: o.sublayerGuid,
          srtWin: resolveSrtWin({ path: VENDORED_SRT_WIN_EXE }),
        })
        if (r.cancelled) {
          console.error('Uninstall cancelled at the UAC prompt.')
          process.exit(2)
        }
        console.log('WFP filters and `srt-sandbox` account removed.')
      } catch (e) {
        console.error(`Error: ${(e as Error).message}`)
        process.exit(1)
      }
    })

  program
    .command('proxy')
    .description(
      'Run only the HTTP proxy, deciding every request through an external decider on inherited fds.',
    )
    .allowUnknownOption()
    .helpOption(false)
    .argument('[args...]')
    .action(async (args: string[]) => {
      const { runProxyCli } = await import('./proxy-cli.js')
      await runProxyCli(args)
    })

  // Default command - run command in sandbox
  program
    .argument('[command...]', 'command to run in the sandbox')
    .option('-d, --debug', 'enable debug logging')
    .option(
      '-s, --settings <path>',
      'path to config file (default: ~/.srt-settings.json)',
    )
    .option(
      '-c <command>',
      'run command string directly (like sh -c), no escaping applied',
    )
    .option(
      '--control-fd <fd>',
      'read config updates from an inherited file descriptor >= 3 (JSON lines ' +
        'protocol; give srt a dedicated read-only end — see the README)',
      parseControlFd,
    )
    .option(
      '--control-pipe <path>',
      'Windows: read config updates from a local named pipe (\\\\.\\pipe\\<name>, ' +
        'JSON lines protocol; restrict the pipe DACL to your user SID — see the README)',
      parseControlPipe,
    )
    .allowUnknownOption()
    .action(
      async (
        commandArgs: string[],
        options: {
          debug?: boolean
          settings?: string
          c?: string
          controlFd?: number
          controlPipe?: string
        },
      ) => {
        try {
          // Enable debug logging if requested. logForDebugging() reads
          // SRT_DEBUG (not DEBUG, to avoid clashing with the npm `debug`
          // package and other tools) — keep this in sync with utils/debug.ts.
          if (options.debug) {
            process.env.SRT_DEBUG = 'true'
          }

          // Load config from file
          const configPath = options.settings || getDefaultConfigPath()
          const loaded = loadConfig(configPath)
          let runtimeConfig: SandboxRuntimeConfig
          switch (loaded.kind) {
            case 'ok':
              runtimeConfig = loaded.config
              break
            case 'missing':
              // A settings file that is not there is the documented way to
              // ask for the built-in defaults. One the caller named with
              // --settings is not: those are rules it asked to have applied.
              if (options.settings) {
                refuseSettings(
                  `${configPath} does not exist.`,
                  'the rules --settings asked for',
                )
              }
              logForDebugging(
                `No config found at ${configPath}, using default config`,
              )
              runtimeConfig = getDefaultConfig()
              break
            case 'empty':
              // A file truncated to nothing is exactly the case where
              // falling back would drop rules that were in force yesterday.
              refuseSettings(
                `${configPath} is empty. Delete it, or put a config in it.`,
                FILE_RULES,
              )
              break
            case 'unreadable':
            case 'invalid':
              refuseSettings(loaded.reason, FILE_RULES)
              break
          }

          // Windows: srtWin.path is required (no ambient vendor
          // fallback). When the user's config doesn't set it, this
          // CLI opts into the packaged exe explicitly — that's our
          // code making the choice, not a library default.
          if (
            process.platform === 'win32' &&
            runtimeConfig.windows?.srtWin?.path === undefined
          ) {
            const { VENDORED_SRT_WIN_EXE } = await import(
              './sandbox/windows-sandbox-utils.js'
            )
            runtimeConfig = {
              ...runtimeConfig,
              windows: {
                ...runtimeConfig.windows,
                srtWin: { path: VENDORED_SRT_WIN_EXE },
              },
            }
          }

          // The wrapped command, once it exists: a control channel that
          // dies before it delivers anything takes it down with it.
          let child: Pick<ChildProcess, 'kill'> | undefined
          const controlFd = options.controlFd
          const controlPipe = options.controlPipe

          if (controlFd !== undefined && controlPipe !== undefined) {
            console.error(
              'Error: --control-fd and --control-pipe cannot be used together.',
            )
            process.exit(1)
          }

          const controlKind =
            controlFd !== undefined ? 'control fd' : 'control pipe'
          const controlTarget =
            controlFd !== undefined
              ? `control fd ${controlFd}`
              : `control pipe ${controlPipe}`
          const listeningTarget =
            controlFd !== undefined ? `fd ${controlFd}` : `pipe ${controlPipe}`

          // Open and check the control channel before anything is built: a
          // refusal here has no proxy or Linux bridge to unwind, and
          // process.exit() cannot wait for the async reset() that would.
          let controlChannel: ControlChannelController | null = null
          if (controlFd !== undefined || controlPipe !== undefined) {
            let controlStream: NodeJS.ReadableStream
            if (controlFd !== undefined) {
              try {
                controlStream = openControlFd(controlFd)
              } catch (err) {
                // Same rule as an explicit --settings that will not load: a
                // caller that asked for a control channel gets an error, not
                // a run whose updates — including the ones that tighten the
                // sandbox — quietly go nowhere.
                console.error(
                  `Error: --control-fd ${controlFd} is not usable: ` +
                    `${err instanceof Error ? err.message : String(err)}. ` +
                    'Refusing to run the command without the control channel it asks for.',
                )
                process.exit(1)
              }
            } else {
              try {
                controlStream = await openControlPipe(controlPipe!)
              } catch (err) {
                console.error(
                  `Error: --control-pipe ${controlPipe} is not usable: ` +
                    `${err instanceof Error ? err.message : String(err)}. ` +
                    'Refusing to run the command without the control channel it asks for.',
                )
                process.exit(1)
              }
            }

            controlChannel = createControlChannel(controlStream, {
              onConfig: newConfig => {
                logForDebugging(
                  `Config updated from ${controlKind}: ${JSON.stringify(newConfig)}`,
                )
                SandboxManager.updateConfig(newConfig)
              },
              onInvalidLine: line => {
                // The caller has to learn its update was dropped whether
                // or not it runs srt with --debug; the line itself stays
                // in the debug log rather than on the terminal.
                console.error(
                  `Invalid config on ${controlTarget}: ignored, previous config still in force`,
                )
                logForDebugging(
                  `Invalid config on ${controlKind} (ignored): ${line}`,
                )
              },
              onPostUpdateError: err => {
                console.error(
                  `Error reading ${controlTarget}: ${err.message}. The control channel is closed; no further updates will be applied.`,
                )
              },
              onFatalError: err => {
                console.error(
                  `Error: ${controlTarget} failed before delivering an update: ${err.message}. Refusing to run the command without the control channel it asks for.`,
                )
                if (child === undefined) {
                  process.exit(1)
                }
                if (process.platform === 'win32') {
                  // Terminating srt-win.exe closes its Job Object handle
                  // (JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE), tearing down the
                  // entire sandboxed process tree; MXC's proc.kill() ends
                  // its tree directly as well.
                  child.kill()
                } else {
                  child.kill('SIGTERM')
                  // The child's own exit is what exits srt; this covers a
                  // command that ignores SIGTERM.
                  setTimeout(
                    () => child?.kill('SIGKILL'),
                    KILL_GRACE_MS,
                  ).unref()
                }
              },
            })
          }

          // Cleanup control channel on exit
          process.on('exit', () => {
            controlChannel?.close()
          })

          // Until there is a child to pass an interrupt on to, it stops the
          // run. The library's own handlers, which initialize() installs, only
          // clean up: left to them the command would be run all the same.
          const interrupted = new AbortController()
          const interrupt = (signal: NodeJS.Signals): void =>
            interrupted.abort(new Error(`interrupted by ${signal}`))
          process.once('SIGINT', interrupt)
          process.once('SIGTERM', interrupt)
          const aboutToSpawn = (): void => {
            interrupted.signal.throwIfAborted()
            process.off('SIGINT', interrupt)
            process.off('SIGTERM', interrupt)
          }

          // Initialize sandbox with config
          logForDebugging('Initializing sandbox...')
          try {
            await SandboxManager.initialize(runtimeConfig)
          } catch (err) {
            // The library's own handler resets on the same signal, which
            // cancels initialize(): the interrupt is the reason to report.
            interrupted.signal.throwIfAborted()
            throw err
          }

          // Read config updates only now. The stream has been waiting
          // unread, so nothing the caller wrote meanwhile is lost, and an
          // update applied before initialize() would have been overwritten
          // by it.
          if (controlChannel !== null) {
            controlChannel.startReading()
            // End of input just means the writer closed its end. The
            // command keeps running under the config last applied.
            logForDebugging(
              `Listening for config updates on ${listeningTarget}`,
            )
          }

          // Determine command string based on mode
          let command: string
          if (options.c) {
            // -c mode: use command string directly, no escaping
            command = options.c
            logForDebugging(`Command string mode (-c): ${command}`)
          } else if (commandArgs.length > 0) {
            // Default mode: argv-style invocation. The result is later
            // executed via `bash -c <command>`, so each arg must be
            // shell-quoted to survive that re-parse — a plain join(' ')
            // splits arguments containing whitespace (#157).
            command = quote(commandArgs)
            logForDebugging(`Original command: ${command}`)
          } else {
            console.error(
              'Error: No command specified. Use -c <command> or provide command arguments.',
            )
            process.exit(1)
          }

          logForDebugging(
            JSON.stringify(
              SandboxManager.getNetworkRestrictionConfig(),
              null,
              2,
            ),
          )

          function onCommandExit(
            code: number | null,
            signal: NodeJS.Signals | null,
          ): void {
            // Clean up bwrap mount point artifacts before exiting.
            // On Linux, bwrap creates empty files on the host when protecting
            // non-existent deny paths. This removes them.
            SandboxManager.cleanupAfterCommand()

            if (controlChannel?.failed) {
              // srt killed the command over a dead control channel, so the
              // status it died with is not the run's result.
              process.exit(1)
            }

            if (signal) {
              if (signal === 'SIGINT' || signal === 'SIGTERM') {
                process.exit(0)
              } else {
                console.error(`Process killed by signal: ${signal}`)
                process.exit(1)
              }
            }
            process.exit(code ?? 0)
          }

          // Wrap the command with sandbox restrictions. On Windows
          // the wrapper returns an argv array that MUST be spawned
          // with {shell:false} — that's the boundary keeping the
          // command bytes off the host shell. On other platforms
          // we keep the existing shell-string path.
          if (
            process.platform === 'win32' &&
            SandboxManager.getWindowsBackend?.()?.backend === 'mxc'
          ) {
            // The MXC SDK starts the command itself; there is no argv.
            const spawnSandboxed = SandboxManager.spawnSandboxed
            if (spawnSandboxed === undefined) {
              throw new Error('spawnSandboxed() is not available')
            }
            aboutToSpawn()
            const proc = await spawnSandboxed(command)
            // MXC has no signals: any kill ends the whole tree. Remember
            // which signal asked, so the exit reads as it does elsewhere.
            let killedBy: NodeJS.Signals | null = null
            child = {
              kill: (signal?: NodeJS.Signals | number) => {
                killedBy = typeof signal === 'string' ? signal : 'SIGTERM'
                proc.kill()
                return true
              },
            }
            proc.stdout?.pipe(process.stdout, { end: false })
            proc.stderr?.pipe(process.stderr, { end: false })
            const stdin = proc.stdin
            if (stdin) {
              // The command may exit without reading its input.
              stdin.on('error', () => {})
              process.stdin.pipe(stdin)
            }
            // Exit only once the command's output has been read to the
            // end and written out: a pipe on Windows is asynchronous,
            // and process.exit() would drop what is still queued.
            const drained = Promise.all(
              [proc.stdout, proc.stderr].map(s =>
                s ? finished(s).catch(() => {}) : Promise.resolve(),
              ),
            )
            const flushed = (out: NodeJS.WriteStream): Promise<void> =>
              new Promise(resolve => out.write('', () => resolve()))
            proc
              .wait()
              .then(async ({ exitCode }) => {
                await drained
                await Promise.all([
                  flushed(process.stdout),
                  flushed(process.stderr),
                ])
                onCommandExit(exitCode, killedBy)
              })
              .catch((error: unknown) => {
                console.error(
                  `Failed to execute command: ${error instanceof Error ? error.message : String(error)}`,
                )
                process.exit(1)
              })
          } else if (process.platform === 'win32') {
            // env carries the proxy vars the sandboxed child must inherit.
            const { argv, env } =
              await SandboxManager.wrapWithSandboxArgv(command)
            // No slot to displace: libuv passes only the stdio array's
            // entries to the child as CRT descriptors, so the control fd
            // is not among them (an inheritable HANDLE still reaches the
            // child, but unnamed — nothing there can find it).
            aboutToSpawn()
            const spawned = spawn(argv[0], argv.slice(1), {
              shell: false,
              stdio: 'inherit',
              env,
            })
            child = spawned
            spawned.on('exit', onCommandExit)
            spawned.on('error', error => {
              console.error(`Failed to execute command: ${error.message}`)
              process.exit(1)
            })
          } else {
            // The wrap can take seconds over a large tree.
            const sandboxedCommand = await SandboxManager.wrapWithSandbox(
              command,
              undefined,
              undefined,
              interrupted.signal,
            )
            aboutToSpawn()
            const spawned = spawn(sandboxedCommand, {
              shell: true,
              stdio: sandboxedStdio(controlFd),
            })
            child = spawned
            spawned.on('exit', onCommandExit)
            spawned.on('error', error => {
              console.error(`Failed to execute command: ${error.message}`)
              process.exit(1)
            })
          }

          // Handle cleanup on interrupt
          process.on('SIGINT', () => {
            child?.kill('SIGINT')
          })

          process.on('SIGTERM', () => {
            child?.kill('SIGTERM')
          })
        } catch (error) {
          console.error(
            `Error: ${error instanceof Error ? error.message : String(error)}`,
          )
          process.exit(1)
        }
      },
    )

  program.parse()
}

main().catch(error => {
  console.error('Fatal error:', error)
  process.exit(1)
})
