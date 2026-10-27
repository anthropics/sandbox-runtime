/**
 * `srt proxy` argument handling, shared by the `srt` CLI and the
 * standalone proxy entry (proxy-main.ts). Kept free of anything that needs
 * files next to the bundle (vendor/, or package.json read at run time), so
 * it compiles into a single executable. The package manifest is a static
 * import, which a bundler embeds.
 */
import pkg from '../package.json' with { type: 'json' }
import { Command } from 'commander'
import { isIPv4, isIPv6 } from 'node:net'
import {
  openFdStreams,
  readPemFromFd,
  startProxyOnly,
} from './sandbox/proxy-only.js'

export async function runProxyCli(argv: string[]): Promise<void> {
  // `--version` anywhere on the command line prints one line and does nothing
  // else: no other option is parsed, so no descriptor is opened, nothing is
  // read or bound, and the process ends once the line is written.
  if (argv.includes('--version')) {
    process.stdout.write(`srt-proxy ${pkg.version}\n`)
    return
  }
  const program = new Command('srt-proxy')
    .description(
      'Run only the HTTP proxy, deciding every request through an external decider on inherited fds.',
    )
    .option(
      '--listen-fd <fd>',
      'accept connections on this inherited listening socket',
      v => parseInt(v, 10),
    )
    .option(
      '--listen <host:port>',
      'listen on this loopback address instead (development); a non-loopback address needs --listen-any-interface',
    )
    .option(
      '--listen-any-interface',
      'let --listen bind a non-loopback address: the listener is unauthenticated and reachable from other hosts',
    )
    .option('--decider-fd <fd>', 'bidirectional decider stream (a socket)', v =>
      parseInt(v, 10),
    )
    .option(
      '--decider-in <fd>',
      'decider -> proxy stream (with --decider-out)',
      v => parseInt(v, 10),
    )
    .option(
      '--decider-out <fd>',
      'proxy -> decider stream (with --decider-in)',
      v => parseInt(v, 10),
    )
    .option('--lifeline-fd <fd>', 'shut down when this stream ends', v =>
      parseInt(v, 10),
    )
    .option(
      '--ca-fd <fd>',
      'read the TLS-termination CA (key and certificate PEM) from this fd',
      v => parseInt(v, 10),
    )
    .option(
      '--strip-response-header <name...>',
      'response headers never passed back',
    )
    .option(
      '--plaintext-header-set',
      'let allow verdicts set headers on plain-HTTP requests (cleartext)',
    )
    .option('-d, --debug', 'enable debug logging')
    .option(
      '--version',
      'print "srt-proxy <version>" and exit; every other option is ignored',
    )
    .exitOverride(err => {
      process.exit(err.exitCode === 0 ? 0 : 2)
    })
  program.parse(argv, { from: 'user' })
  const o = program.opts<Record<string, unknown>>()
  if (o.debug) process.env.SRT_DEBUG = 'true'
  // Diagnostics: with SRT_PROXY_REPORT_RSS_MS set to a positive integer N,
  // report the resident set size on stderr every N ms, for hosts that cannot
  // read another process's memory use.
  const rssEvery = Number(process.env.SRT_PROXY_REPORT_RSS_MS)
  if (Number.isInteger(rssEvery) && rssEvery > 0) {
    setInterval(() => {
      process.stderr.write(`srt-proxy rss ${process.memoryUsage().rss}\n`)
    }, rssEvery).unref()
  }
  const fail = (msg: string): never => {
    console.error(`srt proxy: ${msg}`)
    process.exit(2)
  }
  const inFd = (o.deciderFd ?? o.deciderIn) as number | undefined
  const outFd = (o.deciderFd ?? o.deciderOut) as number | undefined
  if (inFd === undefined || outFd === undefined)
    fail(
      'a decider is required (--decider-fd, or --decider-in and --decider-out)',
    )
  let listen: { fd: number } | { host: string; port: number }
  if (
    typeof o.listenFd === 'number' &&
    Number.isInteger(o.listenFd) &&
    o.listenFd >= 0
  )
    listen = { fd: o.listenFd }
  else if (typeof o.listen === 'string') {
    const i = o.listen.lastIndexOf(':')
    const rawHost = i < 0 ? '' : o.listen.slice(0, i)
    const host = /^\[.*\]$/.test(rawHost) ? rawHost.slice(1, -1) : rawHost
    const portText = o.listen.slice(i + 1)
    const port = Number(portText)
    if (i < 0 || !/^\d+$/.test(portText) || port > 65535)
      return fail(
        `--listen needs <host:port> with a port from 0 to 65535 (got ${JSON.stringify(o.listen)})`,
      )
    if (!isLoopbackHost(host)) {
      // The listener has no authentication of its own: an empty host binds
      // every interface, so only an explicit flag may leave loopback.
      if (o.listenAnyInterface !== true)
        return fail(
          `--listen ${JSON.stringify(o.listen)} is not a loopback address (127.0.0.0/8, [::1] or localhost); pass --listen-any-interface to bind it anyway`,
        )
      console.error(
        `srt proxy: warning: --listen-any-interface: the listener on ${o.listen} is reachable from other hosts and is unauthenticated`,
      )
    }
    listen = { host, port }
  } else return fail('--listen-fd (or --listen for development) is required')
  try {
    const p = startProxyOnly({
      listen,
      decider:
        inFd === outFd
          ? openFdStreams(inFd!)
          : {
              input: openFdStreams(inFd!).input,
              output: openFdStreams(outFd!).output,
            },
      caPem: typeof o.caFd === 'number' ? readPemFromFd(o.caFd) : undefined,
      lifeline:
        typeof o.lifelineFd === 'number'
          ? openFdStreams(o.lifelineFd).input
          : undefined,
      stripResponseHeaders: o.stripResponseHeader as string[] | undefined,
      plaintextHeaderSet: o.plaintextHeaderSet === true,
      onClosed: why => {
        console.error(`srt proxy: stopped (${why})`)
        process.exit(why.startsWith('start failed') ? 1 : 0)
      },
    })
    process.once('SIGTERM', () => void p.close('SIGTERM'))
    await p.ready
    const a = 'fd' in listen ? null : p.listener.address()
    console.error(
      `srt proxy: serving ${a && typeof a !== 'string' ? `${a.address}:${a.port}` : `fd ${(listen as { fd: number }).fd}`}`,
    )
  } catch (e) {
    fail((e as Error).message)
  }
}

/** Whether a `--listen` host can only be reached from this machine. */
export function isLoopbackHost(host: string): boolean {
  if (host.toLowerCase() === 'localhost') return true
  if (isIPv4(host)) return host.startsWith('127.')
  return isIPv6(host) && /^(0{1,4}:){7}0{0,3}1$|^::0{0,3}1$/.test(host)
}
