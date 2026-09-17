#!/usr/bin/env node
import { quote } from './utils/shell-quote.js'
import { Command } from 'commander'
import { SandboxManager } from './index.js'
import type { SandboxRuntimeConfig } from './sandbox/sandbox-config.js'
import type { SandboxAskCallback } from './sandbox/sandbox-schemas.js'
import type { SandboxViolationStore } from './sandbox/sandbox-violation-store.js'
import {
  SandboxAgentChannel,
  blockedMessageFromViolation,
  SANDBOX_AGENT_CHANNEL_FD_ENV_VAR,
} from './sandbox/agent-channel.js'
import { spawn, type StdioOptions } from 'child_process'
import type { Duplex } from 'stream'
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
 * Create a minimal default config if no config file exists
 */
/**
 * Forward new violations from the store to the agent as `blocked` messages.
 * The subscribe callback re-delivers the whole in-memory tail on every
 * change, so the store's monotonic total count is what identifies which
 * entries are new.
 *
 * Identical messages are sent only once: platform monitors report the same
 * boilerplate denial for every process (e.g. seatbelt's sysctl-read), and a
 * once-notified agent gains nothing from repeats — an unthrottled stream
 * can even feed back, since the agent's own handling of a message may trip
 * further violations.
 */
function forwardViolationsToAgent(
  store: SandboxViolationStore,
  channel: SandboxAgentChannel,
): void {
  let seenTotal = store.getTotalCount()
  const sent = new Set<string>()
  const maxSentEntries = 1000
  store.subscribe(violations => {
    const total = store.getTotalCount()
    if (total <= seenTotal) {
      return
    }
    const fresh = violations.slice(-(total - seenTotal))
    seenTotal = total
    for (const violation of fresh) {
      const blocked = blockedMessageFromViolation(violation.line)
      if (!blocked) {
        continue
      }
      const key = JSON.stringify(blocked)
      if (sent.has(key)) {
        continue
      }
      if (sent.size >= maxSentEntries) {
        sent.clear()
      }
      sent.add(key)
      channel.notifyBlocked(blocked)
    }
  })
}

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
  const stat = fs.fstatSync(fd)
  if (!process.versions.bun && (stat.isFIFO() || stat.isSocket())) {
    try {
      return new net.Socket({ fd, readable: true, writable: false }).unref()
    } catch (err) {
      // A socket libuv cannot adopt as a stream (datagram, seqpacket):
      // read it through fs as before, one read(2) per datagram.
      logForDebugging(
        `Control fd ${fd} is not a stream socket (${err instanceof Error ? err.message : String(err)}); reading it through fs`,
      )
    }
  }
  return fs.createReadStream('', { fd })
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
      'read config updates from file descriptor (JSON lines protocol)',
      parseInt,
    )
    .option(
      '--agent-channel',
      'open the Sandbox-Agent channel to the wrapped command on the file ' +
        `descriptor named by ${SANDBOX_AGENT_CHANNEL_FD_ENV_VAR}: the sandbox ` +
        'asks the agent to decide requests the policy does not cover, and ' +
        'reports blocked actions to it (newline-delimited JSON)',
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
          agentChannel?: boolean
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
          let runtimeConfig = loadConfig(configPath)

          if (!runtimeConfig) {
            // An explicitly requested settings file must load successfully —
            // silently falling back to the default config would run the
            // command without the restrictions the caller asked for.
            if (options.settings) {
              console.error(
                `Error: Could not load settings from ${configPath} (missing, unreadable, or invalid). ` +
                  'Refusing to run with the default config.',
              )
              process.exit(1)
            }
            logForDebugging(
              `No config found at ${configPath}, using default config`,
            )
            runtimeConfig = getDefaultConfig()
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

          if (options.agentChannel && process.platform === 'win32') {
            console.error('Error: --agent-channel is not supported on Windows.')
            process.exit(1)
          }

          // The channel is constructed after spawn (its transport is one
          // end of a socketpair created by spawn itself), but the ask
          // callback must be registered at initialize time — so it
          // late-binds to the instance. Asks that race the spawn are
          // denied, same as asks that race the agent's hello.
          let agentChannel: SandboxAgentChannel | undefined
          const askAgentCallback: SandboxAskCallback | undefined =
            options.agentChannel
              ? async ({ host, port }) => {
                  if (!agentChannel) {
                    return false
                  }
                  const destination =
                    port !== undefined ? `${host}:${port}` : host
                  return agentChannel.ask(
                    {
                      type: 'network',
                      host,
                      ...(port !== undefined ? { port } : {}),
                    },
                    'connect',
                    `Connecting to ${destination}`,
                  )
                }
              : undefined

          // Initialize sandbox with config. The violation monitors (macOS
          // log stream / Linux seccomp observer) are what feed `blocked`
          // notifications, so they are only started when the channel is on.
          logForDebugging('Initializing sandbox...')
          await SandboxManager.initialize(
            runtimeConfig,
            askAgentCallback,
            Boolean(options.agentChannel),
          )

          // Set up control fd for dynamic config updates if specified
          let controlReader: readline.Interface | null = null
          if (options.controlFd !== undefined) {
            try {
              controlReader = readline.createInterface({
                input: openControlFd(options.controlFd),
                crlfDelay: Infinity,
              })

              controlReader.on('line', line => {
                const newConfig = loadConfigFromString(line)
                if (newConfig) {
                  logForDebugging(
                    `Config updated from control fd: ${JSON.stringify(newConfig)}`,
                  )
                  SandboxManager.updateConfig(newConfig)
                } else if (line.trim()) {
                  // Only log non-empty lines that failed to parse
                  logForDebugging(
                    `Invalid config on control fd (ignored): ${line}`,
                  )
                }
              })

              controlReader.on('error', err => {
                logForDebugging(`Control fd error: ${err.message}`)
              })

              logForDebugging(
                `Listening for config updates on fd ${options.controlFd}`,
              )
            } catch (err) {
              logForDebugging(
                `Failed to open control fd ${options.controlFd}: ${err instanceof Error ? err.message : String(err)}`,
              )
            }
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
          let child
          if (process.platform === 'win32') {
            // env carries the proxy vars the sandboxed child must inherit.
            const { argv, env } =
              await SandboxManager.wrapWithSandboxArgv(command)
            child = spawn(argv[0], argv.slice(1), {
              shell: false,
              stdio: 'inherit',
              env,
            })
          } else {
            const sandboxedCommand =
              await SandboxManager.wrapWithSandbox(command)
            // With --agent-channel, stdio slot 3 is a socketpair: the child
            // keeps one end as fd 3 (named by SANDBOX_AGENT_CHANNEL_FD) and
            // the parent end becomes the channel transport below.
            const stdio: StdioOptions = options.agentChannel
              ? ['inherit', 'inherit', 'inherit', 'pipe']
              : 'inherit'
            child = spawn(sandboxedCommand, {
              shell: true,
              stdio,
              env: options.agentChannel
                ? { ...process.env, [SANDBOX_AGENT_CHANNEL_FD_ENV_VAR]: '3' }
                : process.env,
            })
            if (options.agentChannel) {
              agentChannel = new SandboxAgentChannel(
                child.stdio[3] as unknown as Duplex,
              )
              forwardViolationsToAgent(
                SandboxManager.getSandboxViolationStore(),
                agentChannel,
              )
            }
          }

          // Handle process exit
          child.on('exit', (code, signal) => {
            // The agent is the child — once it exits nobody is listening,
            // so resolve any in-flight asks as deny and drop the socket.
            agentChannel?.close()

            // Clean up bwrap mount point artifacts before exiting.
            // On Linux, bwrap creates empty files on the host when protecting
            // non-existent deny paths. This removes them.
            SandboxManager.cleanupAfterCommand()

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
            child.kill('SIGINT')
          })

          process.on('SIGTERM', () => {
            child.kill('SIGTERM')
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
