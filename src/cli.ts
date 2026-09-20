#!/usr/bin/env node
import { quote } from './utils/shell-quote.js'
import { Command, InvalidArgumentError } from 'commander'
import { SandboxManager } from './index.js'
import type { SandboxRuntimeConfig } from './sandbox/sandbox-config.js'
import { spawn, type ChildProcess } from 'child_process'
import { logForDebugging } from './utils/debug.js'
import { loadConfig, loadConfigFromString } from './utils/config-loader.js'
import * as readline from 'readline'
import * as fs from 'fs'
import * as net from 'net'
import * as path from 'path'
import * as os from 'os'

/**
 * Get default config path
 */
function getDefaultConfigPath(): string {
  return path.join(os.homedir(), '.srt-settings.json')
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
 * A readable stream over the control fd. A pipe or socket is read through a
 * libuv stream handle, driven by the event loop: fs.createReadStream would
 * park a threadpool thread in a blocking read(2) that process.exit() then
 * waits for, so srt would outlive the wrapped command until the parent
 * closed the fd. Anything else keeps the fs stream, which is right for a
 * regular file (its reads never block) and leaves a tty with the old wait.
 * Under Bun, net.Socket({ fd }) reads nothing, and Bun's fs stream does not
 * hold exit, so the fs stream serves every fd kind there.
 *
 * A libuv handle switches the fd's open file description to non-blocking
 * mode, from the moment srt opens it and for good (Node restores only fds
 * 0-2 at exit). A parent that shares that description (a shell
 * `exec 3<fifo`, a Python pass_fds of an fd it keeps using) then sees
 * EAGAIN on its own blocking reads, so hand srt a dedicated pipe end.
 */
function openControlFd(fd: number): NodeJS.ReadableStream {
  // fstat succeeds on descriptors srt can never read a byte from — one
  // opened write-only, the write end of a pipe — and a reader over those
  // fails only once the command is already running. A zero-length readv(2)
  // asks the kernel whether a read is permitted at all without performing
  // one: EBADF for those, 0 for every readable kind, on both node and bun,
  // without blocking on an empty pipe or consuming a byte of a full one.
  fs.readvSync(fd, [Buffer.alloc(0)])
  const stat = fs.fstatSync(fd)
  if (!process.versions.bun && (stat.isFIFO() || stat.isSocket())) {
    try {
      return new net.Socket({ fd, readable: true, writable: false }).unref()
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code
      if (code !== 'ERR_INVALID_FD_TYPE') {
        // ERR_INVALID_FD_TYPE is the only refusal that leaves the fd
        // untouched (a datagram or seqpacket socket, which the fs stream
        // still reads, one read(2) per datagram). Every other failure comes
        // out of uv_pipe_open, which has already switched the fd to
        // non-blocking mode: an fs stream over it would read EAGAIN
        // forever, so no fallback is left to take.
        throw new Error(
          `could not be adopted as a stream (${code ?? String(err)})`,
        )
      }
      logForDebugging(
        `Control fd ${fd} is not a stream socket (${err instanceof Error ? err.message : String(err)}); reading it through fs`,
      )
    }
  }
  return fs.createReadStream('', { fd })
}

/**
 * Parse --control-fd: an integer descriptor number >= 3.
 */
function parseControlFd(value: string): number {
  // Number() alone would also take '0x10', '3e0' and ' 5 '.
  if (!/^\d+$/.test(value) || Number(value) < 3) {
    throw new InvalidArgumentError(
      'must be an integer file descriptor >= 3 (0-2 are stdin, stdout and stderr).',
    )
  }
  return Number(value)
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
    .version(process.env.npm_package_version || '1.0.0')

  // ── Windows install/uninstall ─────────────────────────────────
  // Self-elevating one-shot install (one UAC prompt). Also
  // available programmatically as installWindowsSandbox().
  program
    .command('windows-install')
    .description(
      'Windows: provision the `srt-sandbox` user account + install WFP ' +
        'filters (one UAC prompt). No logout needed.',
    )
    .option('--sublayer-guid <guid>', 'WFP sublayer GUID')
    .option(
      '--proxy-port-range <lo-hi>',
      'loopback PERMIT port range (e.g. 60080-60089)',
    )
    .option(
      '--sandbox-user <name>',
      'name for the sandbox user account (default: srt-sandbox)',
    )
    .option('--force', 'replace an existing install with different config')
    .action(async (o: Record<string, string | boolean | undefined>) => {
      const { installWindowsSandbox, resolveSrtWin, VENDORED_SRT_WIN_EXE } =
        await import('./sandbox/windows-sandbox-utils.js')
      const range =
        typeof o.proxyPortRange === 'string'
          ? (o.proxyPortRange.split('-').map(Number) as [number, number])
          : undefined
      try {
        const r = installWindowsSandbox({
          sublayerGuid: o.sublayerGuid as string | undefined,
          proxyPortRange: range,
          sandboxUser: o.sandboxUser as string | undefined,
          force: Boolean(o.force),
          // Our own CLI opts into the packaged exe explicitly —
          // there is no ambient vendor fallback.
          srtWin: resolveSrtWin({ path: VENDORED_SRT_WIN_EXE }),
        })
        if (r.cancelled) {
          console.error('Install cancelled at the UAC prompt. Nothing changed.')
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
            `\n\n` +
            `No logout needed — the WFP filter keys on the dedicated ` +
            `\`srt-sandbox\` user's SID, so your network is unaffected.`,
        )
      } catch (e) {
        console.error(`Error: ${(e as Error).message}`)
        process.exit(1)
      }
    })

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
    .allowUnknownOption()
    .action(
      async (
        commandArgs: string[],
        options: {
          debug?: boolean
          settings?: string
          c?: string
          controlFd?: number
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
          let child: ChildProcess | undefined
          let controlChannelFailed = false
          let receivedAnyLine = false
          let controlErrorReported = false
          const controlFd = options.controlFd

          function onControlError(err: Error): void {
            // Attached both to the stream and to the reader: the stream is
            // live from the moment the fd is opened, which is before the
            // reader exists, and readline re-emits an input error on the
            // reader as well. The channel is gone after the first error
            // either way, so it is reported once.
            if (controlErrorReported) {
              return
            }
            controlErrorReported = true
            if (receivedAnyLine) {
              // The channel did deliver. The config last applied stays in
              // force, so the command keeps running under it.
              console.error(
                `Error reading control fd ${controlFd}: ${err.message}. The control channel is closed; no further updates will be applied.`,
              )
              return
            }
            // Nothing ever came through: this is the descriptor that would
            // not open, found one step later. The caller is sending updates
            // into a channel srt cannot read.
            console.error(
              `Error: control fd ${controlFd} failed before delivering an update: ${err.message}. Refusing to run the command without the control channel it asks for.`,
            )
            controlChannelFailed = true
            if (child === undefined) {
              process.exit(1)
            }
            child.kill('SIGTERM')
            // The child's own exit is what exits srt; this covers a command
            // that ignores SIGTERM.
            setTimeout(() => child?.kill('SIGKILL'), KILL_GRACE_MS).unref()
          }

          // Open and check the control fd before anything is built: a
          // refusal here has no proxy or Linux bridge to unwind, and
          // process.exit() cannot wait for the async reset() that would.
          let controlStream: NodeJS.ReadableStream | undefined
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
            controlStream.on('error', onControlError)
          }

          // Initialize sandbox with config
          logForDebugging('Initializing sandbox...')
          await SandboxManager.initialize(runtimeConfig)

          // Read config updates only now. The stream has been waiting
          // unread, so nothing the caller wrote meanwhile is lost, and an
          // update applied before initialize() would have been overwritten
          // by it.
          let controlReader: readline.Interface | null = null
          if (controlStream !== undefined) {
            controlReader = readline.createInterface({
              input: controlStream,
              crlfDelay: Infinity,
            })

            controlReader.on('line', line => {
              receivedAnyLine = true
              const newConfig = loadConfigFromString(line)
              if (newConfig) {
                logForDebugging(
                  `Config updated from control fd: ${JSON.stringify(newConfig)}`,
                )
                SandboxManager.updateConfig(newConfig)
              } else if (line.trim()) {
                // The caller has to learn its update was dropped whether
                // or not it runs srt with --debug; the line itself stays
                // in the debug log rather than on the terminal.
                console.error(
                  `Invalid config on control fd ${controlFd}: ignored, previous config still in force`,
                )
                logForDebugging(
                  `Invalid config on control fd (ignored): ${line}`,
                )
              }
            })

            controlReader.on('error', onControlError)

            // End of input just means the writer closed its end. The
            // command keeps running under the config last applied.
            logForDebugging(`Listening for config updates on fd ${controlFd}`)
          }

          // Cleanup control reader on exit
          process.on('exit', () => {
            controlReader?.close()
          })

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

          // Wrap the command with sandbox restrictions. On Windows
          // the wrapper returns an argv array that MUST be spawned
          // with {shell:false} — that's the boundary keeping the
          // command bytes off the host shell. On other platforms
          // we keep the existing shell-string path.
          if (process.platform === 'win32') {
            // env carries the proxy vars the sandboxed child must inherit.
            const { argv, env } =
              await SandboxManager.wrapWithSandboxArgv(command)
            // No slot to displace: libuv passes only the stdio array's
            // entries to the child as CRT descriptors, so the control fd
            // is not among them (an inheritable HANDLE still reaches the
            // child, but unnamed — nothing there can find it).
            child = spawn(argv[0], argv.slice(1), {
              shell: false,
              stdio: 'inherit',
              env,
            })
          } else {
            const sandboxedCommand =
              await SandboxManager.wrapWithSandbox(command)
            child = spawn(sandboxedCommand, {
              shell: true,
              stdio: sandboxedStdio(controlFd),
            })
          }

          // Handle process exit
          child.on('exit', (code, signal) => {
            // Clean up bwrap mount point artifacts before exiting.
            // On Linux, bwrap creates empty files on the host when protecting
            // non-existent deny paths. This removes them.
            SandboxManager.cleanupAfterCommand()

            if (controlChannelFailed) {
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
          })

          child.on('error', error => {
            console.error(`Failed to execute command: ${error.message}`)
            process.exit(1)
          })

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
