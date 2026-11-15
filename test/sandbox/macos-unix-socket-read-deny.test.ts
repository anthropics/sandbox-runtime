import { describe, it, expect, beforeAll, afterAll } from 'bun:test'
import { spawnSync } from 'node:child_process'
import {
  mkdirSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { createServer, type Server } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import { wrapCommandWithSandboxMacOS } from '../../src/sandbox/macos-sandbox-utils.js'
import type { FsReadRestrictionConfig } from '../../src/sandbox/sandbox-schemas.js'
import { isMacOS } from '../helpers/platform.js'

/**
 * Seatbelt does not check file-read* on connect(), so without a rule of its
 * own a command can connect to a Unix socket inside a directory it may not
 * read. Where the command may connect to any socket, the read rules apply to
 * connecting too.
 *
 * The listeners run in the test process. connect() to a listening Unix
 * socket completes in the kernel's backlog, so it succeeds while
 * spawnSync holds the event loop.
 */
describe.if(isMacOS)('macOS: read-denied Unix sockets', () => {
  // Short: sun_path holds 104 bytes.
  const BASE = join(realpathSync(tmpdir()), `srt-uds-${process.pid}`)
  const DENIED = join(BASE, 'denied')
  const REOPENED = join(DENIED, 'reopened')
  const OPEN = join(BASE, 'open')
  const GLOBBED = join(BASE, 'globbed')
  const CLIENT = join(BASE, 'connect.py')

  const SOCKETS = {
    denied: join(DENIED, 'd.sock'),
    reopened: join(REOPENED, 'r.sock'),
    open: join(OPEN, 'o.sock'),
    globbed: join(GLOBBED, 'g.sock'),
  }
  const LINK_TO_DENIED = join(OPEN, 'link.sock')

  const servers: Server[] = []
  let tcpPort = 0

  beforeAll(async () => {
    for (const dir of [REOPENED, OPEN, GLOBBED]) {
      mkdirSync(dir, { recursive: true })
    }
    writeFileSync(
      CLIENT,
      [
        'import socket, sys',
        'for target in sys.argv[1:]:',
        '    family = socket.AF_INET if target.isdigit() else socket.AF_UNIX',
        "    address = ('127.0.0.1', int(target)) if target.isdigit() else target",
        '    s = socket.socket(family, socket.SOCK_STREAM)',
        '    try:',
        '        s.connect(address)',
        "        print(target, 'CONNECTED')",
        '    except OSError as e:',
        "        print(target, 'REFUSED', e.errno)",
        '    finally:',
        '        s.close()',
      ].join('\n'),
    )
    const listen = (server: Server, ...args: unknown[]) =>
      new Promise<void>(resolve => {
        servers.push(server)
        ;(server.listen as (...a: unknown[]) => Server)(...args, resolve)
      })
    for (const path of Object.values(SOCKETS)) {
      await listen(createServer(), path)
    }
    symlinkSync(SOCKETS.denied, LINK_TO_DENIED)
    const tcp = createServer()
    await listen(tcp, 0, '127.0.0.1')
    tcpPort = (tcp.address() as { port: number }).port
  })

  afterAll(() => {
    for (const server of servers) server.close()
    rmSync(BASE, { recursive: true, force: true })
  })

  /** The command that tries to connect to each target: a socket path, or a TCP port on 127.0.0.1. */
  const connectTo = (...targets: string[]) =>
    `python3 ${CLIENT} ${targets.join(' ')}`

  /** What the wrapped command said for each target, keyed by target. */
  function outcomesOf(wrapped: string): Record<string, string> {
    const result = spawnSync(wrapped, {
      shell: true,
      encoding: 'utf8',
      timeout: 10000,
    })
    expect(result.status).toBe(0)
    const outcomes: Record<string, string> = {}
    for (const line of result.stdout.trim().split('\n')) {
      const [target, ...outcome] = line.split(' ')
      outcomes[target] = outcome.join(' ')
    }
    return outcomes
  }

  const readConfig: FsReadRestrictionConfig = {
    denyOnly: [DENIED, `${GLOBBED}/*.sock`],
    allowWithinDeny: [REOPENED],
  }

  describe('with no network restriction', () => {
    const wrap = (command: string) =>
      wrapCommandWithSandboxMacOS({
        command,
        needsNetworkRestriction: false,
        readConfig,
        writeConfig: undefined,
      })

    it('refuses a socket under a denyRead path and allows one elsewhere', () => {
      const outcomes = outcomesOf(wrap(connectTo(SOCKETS.denied, SOCKETS.open)))

      expect(outcomes[SOCKETS.denied]).toBe('REFUSED 1')
      expect(outcomes[SOCKETS.open]).toBe('CONNECTED')
    })

    it('allows a socket that allowRead re-opens inside a denied path', () => {
      const outcomes = outcomesOf(wrap(connectTo(SOCKETS.reopened)))

      expect(outcomes[SOCKETS.reopened]).toBe('CONNECTED')
    })

    it('refuses a socket matched by a denyRead glob', () => {
      const outcomes = outcomesOf(wrap(connectTo(SOCKETS.globbed)))

      expect(outcomes[SOCKETS.globbed]).toBe('REFUSED 1')
    })

    it('refuses a denied socket reached through a symlink outside the deny', () => {
      const outcomes = outcomesOf(wrap(connectTo(LINK_TO_DENIED)))

      expect(outcomes[LINK_TO_DENIED]).toBe('REFUSED 1')
    })

    it('leaves TCP connections alone', () => {
      const outcomes = outcomesOf(wrap(connectTo(String(tcpPort))))

      expect(outcomes[String(tcpPort)]).toBe('CONNECTED')
    })

    it("keeps the resolver's socket reachable under a deny that covers it", () => {
      const resolver = '/private/var/run/mDNSResponder'
      const outcomes = outcomesOf(
        wrapCommandWithSandboxMacOS({
          command: connectTo(resolver),
          needsNetworkRestriction: false,
          readConfig: { denyOnly: ['/private/var/run'] },
          writeConfig: undefined,
        }),
      )

      expect(outcomes[resolver]).toBe('CONNECTED')
    })
  })

  describe('with allowAllUnixSockets under a restricted network', () => {
    it('refuses a socket under a denyRead path and allows one elsewhere', () => {
      const outcomes = outcomesOf(
        wrapCommandWithSandboxMacOS({
          command: connectTo(SOCKETS.denied, SOCKETS.reopened, SOCKETS.open),
          needsNetworkRestriction: true,
          allowAllUnixSockets: true,
          readConfig,
          writeConfig: undefined,
        }),
      )

      expect(outcomes[SOCKETS.denied]).toBe('REFUSED 1')
      expect(outcomes[SOCKETS.reopened]).toBe('CONNECTED')
      expect(outcomes[SOCKETS.open]).toBe('CONNECTED')
    })
  })

  describe('with allowUnixSockets under a restricted network', () => {
    it('still allows a listed socket under a denyRead path', () => {
      const outcomes = outcomesOf(
        wrapCommandWithSandboxMacOS({
          command: connectTo(SOCKETS.denied, SOCKETS.open),
          needsNetworkRestriction: true,
          allowUnixSockets: [SOCKETS.denied],
          readConfig,
          writeConfig: undefined,
        }),
      )

      expect(outcomes[SOCKETS.denied]).toBe('CONNECTED')
      expect(outcomes[SOCKETS.open]).toBe('REFUSED 1')
    })
  })

  describe('through SandboxManager', () => {
    beforeAll(async () => {
      await SandboxManager.initialize({
        network: {
          allowedDomains: [],
          deniedDomains: [],
          allowAllUnixSockets: true,
        },
        filesystem: {
          denyRead: [DENIED],
          allowRead: [REOPENED],
          allowWrite: [],
          denyWrite: [],
        },
      })
    })

    afterAll(async () => {
      await SandboxManager.reset()
    })

    it('applies filesystem.denyRead and allowRead to connecting', async () => {
      const outcomes = outcomesOf(
        await SandboxManager.wrapWithSandbox(
          connectTo(SOCKETS.denied, SOCKETS.reopened, SOCKETS.open),
        ),
      )

      expect(outcomes[SOCKETS.denied]).toBe('REFUSED 1')
      expect(outcomes[SOCKETS.reopened]).toBe('CONNECTED')
      expect(outcomes[SOCKETS.open]).toBe('CONNECTED')
    })
  })
})
