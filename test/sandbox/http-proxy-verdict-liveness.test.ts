import { afterEach, describe, expect, it, spyOn } from 'bun:test'
import type { Server } from 'node:http'
import {
  connect,
  createServer as createNetServer,
  type Server as NetServer,
  type Socket,
} from 'node:net'
import type { Duplex } from 'node:stream'
import { createHttpProxyServer } from '../../src/sandbox/http-proxy.js'

/**
 * Verdict-writer liveness regression tests for the HTTP proxy.
 *
 * Background (idle-CPU incident): the host-allowlist decision
 * (`options.filter`) can take tens of seconds — it may run a
 * model-classifier call or an interactive permission prompt. When the
 * sandboxed client gave up and half-closed mid-decision, the proxy left
 * the descriptor half-open (no close on the EOF path) and later wrote the
 * verdict to the dead descriptor; the resulting EPIPE fed a busy-loop in
 * the embedding runtime (fixed separately in Bun, oven-sh/bun#37076).
 * These tests pin the proxy-side contract:
 *  - CONNECT: EOF during the decision window closes the descriptor
 *    immediately (a CONNECT client that half-closed can never use the
 *    tunnel), and no verdict is ever written to a dead/destroyed socket.
 *  - CONNECT: a write error on the client socket (EPIPE to a peer whose
 *    death was never notified) releases the descriptor instead of only
 *    logging — the layered backstop for best-effort EOF notification.
 *  - CONNECT: verdicts still reach live clients, and established tunnels
 *    still pipe (the decision-window EOF handling is disarmed at handoff).
 *  - Plain HTTP: the verdict is dropped only for a destroyed socket. (The
 *    drop keys on `destroyed`, not on EOF, so a runtime that keeps
 *    half-closed request sockets open — legal HTTP half-close — still
 *    delivers the verdict. Bun 1.4's http.Server destroys the request
 *    socket on client FIN, so delivery is runtime-dependent; the
 *    half-close test below accepts either outcome and pins that neither
 *    crashes nor writes to a dead socket.)
 */

const HOST = '127.0.0.1'

function listen(server: Server | NetServer): Promise<number> {
  return new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, HOST, () => {
      const address = server.address()
      if (address === null || typeof address !== 'object') {
        reject(new Error('server has no port'))
        return
      }
      resolve(address.port)
    })
  })
}

function connectClient(port: number): Socket {
  const client = connect(port, HOST)
  // A test client may be deliberately killed mid-exchange; without a
  // listener the resulting ECONNRESET would fail the test run as an
  // unhandled error.
  client.on('error', () => {})
  return client
}

function collectData(socket: Socket): { received: () => string } {
  const chunks: Buffer[] = []
  socket.on('data', chunk => {
    chunks.push(chunk)
  })
  return { received: () => Buffer.concat(chunks).toString('utf8') }
}

// Poll until `predicate` holds, with failure-time diagnostics so a
// timed-out wait explains itself in CI output.
async function until(
  predicate: () => boolean,
  label: string,
  diagnose?: () => string,
): Promise<void> {
  const deadline = Date.now() + 2_000
  while (!predicate()) {
    if (Date.now() > deadline) {
      const detail = diagnose ? ` [${diagnose()}]` : ''
      throw new Error(`timed out waiting for ${label}${detail}`)
    }
    await Bun.sleep(10)
  }
}

type DecisionCapture = {
  socket: Socket | Duplex
  endSpy: ReturnType<typeof spyOn>
  writeSpy: ReturnType<typeof spyOn>
}

describe('http-proxy verdict-writer liveness', () => {
  const servers: Array<Server | NetServer> = []
  const sockets: Socket[] = []
  // Spies are created inside per-connection filter callbacks, where a
  // `using` binding can't outlive the callback — so they register here and
  // are restored per-test.
  const spies: Array<ReturnType<typeof spyOn>> = []

  afterEach(async () => {
    for (const spy of spies) {
      spy.mockRestore()
    }
    spies.length = 0
    for (const socket of sockets) {
      socket.destroy()
    }
    sockets.length = 0
    await Promise.all(
      servers.map(
        server => new Promise<void>(resolve => server.close(() => resolve())),
      ),
    )
    servers.length = 0
  })

  function startProxy(): {
    portReady: Promise<number>
    decision: Promise<DecisionCapture>
    resolveVerdict: (allow: boolean) => void
  } {
    let capture: (value: DecisionCapture) => void = () => {}
    const decision = new Promise<DecisionCapture>(resolve => {
      capture = resolve
    })
    let resolveVerdict: (allow: boolean) => void = () => {}
    const verdict = new Promise<boolean>(resolve => {
      resolveVerdict = resolve
    })
    const server = createHttpProxyServer({
      filter: (_port, _host, socket) => {
        // Spies installed before the decision await starts: every write the
        // proxy attempts after this point is recorded.
        const endSpy = spyOn(socket, 'end')
        const writeSpy = spyOn(socket, 'write')
        spies.push(endSpy, writeSpy)
        capture({ socket, endSpy, writeSpy })
        return verdict
      },
    })
    servers.push(server)
    return { portReady: listen(server), decision, resolveVerdict }
  }

  it('CONNECT: client EOF mid-decision closes the descriptor immediately and drops the verdict write', async () => {
    const { portReady, decision, resolveVerdict } = startProxy()
    const client = connectClient(await portReady)
    sockets.push(client)
    client.write(
      'CONNECT blocked.decision.invalid:443 HTTP/1.1\r\n' +
        'Host: blocked.decision.invalid:443\r\n\r\n',
    )

    const { socket, endSpy, writeSpy } = await decision
    expect(socket.destroyed).toBe(false)

    // The client gives up mid-decision and half-closes (FIN), exactly like
    // a sandboxed HTTP client hitting its own request timeout.
    client.end()

    // The EOF path must close the proxy-side descriptor NOW — before the
    // decision resolves — not leave it half-open awaiting the verdict.
    await until(
      () => socket.destroyed,
      'proxy-side socket destroy on EOF',
      () =>
        `destroyed=${socket.destroyed} readableFlowing=${
          'readableFlowing' in socket ? socket.readableFlowing : 'n/a'
        } endListeners=${socket.listenerCount('end')} closeListeners=${socket.listenerCount('close')}`,
    )

    // The decision completes after the client is gone (deny, like the
    // incident's classifier verdict). Nothing may be written to the dead
    // descriptor.
    endSpy.mockClear()
    writeSpy.mockClear()
    resolveVerdict(false)
    await Bun.sleep(50)
    expect(endSpy).not.toHaveBeenCalled()
    expect(writeSpy).not.toHaveBeenCalled()
  })

  it('CONNECT: a write error on the client socket releases the descriptor (EPIPE backstop)', async () => {
    // EOF notification on a paused socket is best-effort: a peer can die
    // without the proxy ever seeing 'end' or 'close', and the first sign is
    // the verdict write failing (EPIPE). The error handler must destroy the
    // socket — releasing the descriptor — not just log. This is the layer
    // the incident's busy-loop spun on: a logged-and-leaked dead fd.
    const { portReady, decision, resolveVerdict } = startProxy()
    const client = connectClient(await portReady)
    sockets.push(client)
    client.write(
      'CONNECT blocked.decision.invalid:443 HTTP/1.1\r\n' +
        'Host: blocked.decision.invalid:443\r\n\r\n',
    )

    const { socket } = await decision
    expect(socket.destroyed).toBe(false)

    // Surface a write failure on the proxy-side socket. Emitted directly
    // because a real never-notified peer death is not reproducible
    // deterministically from a loopback test (the kernel usually delivers
    // FIN/RST notifications promptly); the handler's contract is the same
    // regardless of how the error arrives.
    const epipe = Object.assign(new Error('write EPIPE'), { code: 'EPIPE' })
    socket.emit('error', epipe)

    await until(
      () => socket.destroyed,
      'descriptor release after write error',
      () => `destroyed=${socket.destroyed}`,
    )
    resolveVerdict(false)
  })

  it('CONNECT: a live client still receives the deny verdict', async () => {
    const { portReady, decision, resolveVerdict } = startProxy()
    const client = connectClient(await portReady)
    sockets.push(client)
    const { received } = collectData(client)
    client.write(
      'CONNECT blocked.decision.invalid:443 HTTP/1.1\r\n' +
        'Host: blocked.decision.invalid:443\r\n\r\n',
    )

    await decision
    resolveVerdict(false)

    await until(() => received().includes('403 Forbidden'), 'deny verdict')
    await until(() => client.destroyed, 'client teardown after deny')
  })

  it('CONNECT: a live client still gets its tunnel on allow (decision-window EOF handling disarms at handoff)', async () => {
    const echo = createNetServer(socket => {
      socket.on('data', chunk => socket.write(chunk))
      socket.on('error', () => {})
    })
    servers.push(echo)
    const echoPort = await listen(echo)

    const { portReady, decision, resolveVerdict } = startProxy()
    const client = connectClient(await portReady)
    sockets.push(client)
    const { received } = collectData(client)
    client.write(
      `CONNECT ${HOST}:${echoPort} HTTP/1.1\r\nHost: ${HOST}:${echoPort}\r\n\r\n`,
    )

    await decision
    resolveVerdict(true)
    await until(
      () => received().includes('200 Connection Established'),
      'tunnel establishment',
    )

    client.write('ping-through-tunnel')
    await until(
      () => received().includes('ping-through-tunnel'),
      'echoed tunnel bytes',
    )
  })

  // Whether this runtime's CLIENT sockets can still receive data after
  // their own end() — needed to assert reply delivery across a
  // half-closed tunnel. (bun 1.3.13 closes the client fully on end();
  // node and newer bun deliver the late reply.) Probed once against a
  // bare echo-on-FIN server so a client-side runtime limitation doesn't
  // read as a proxy regression.
  async function clientSupportsHalfOpenReceive(): Promise<boolean> {
    const probe = createNetServer(socket => {
      socket.allowHalfOpen = true
      socket.on('error', () => {})
      socket.on('end', () => socket.end('late'))
    })
    servers.push(probe)
    const client = connectClient(await listen(probe))
    sockets.push(client)
    const { received } = collectData(client)
    client.end()
    await Bun.sleep(150)
    return received().includes('late')
  }

  it('CONNECT: a client FIN through an established tunnel reaches the upstream as a clean FIN (EOF handling disarmed at handoff)', async () => {
    // Upstream that answers only once the client's write side closes: the
    // final payload (and the clean 'end') would be lost if the
    // decision-window EOF handler were still armed at tunnel time (it
    // would destroy the client socket on FIN, surfacing upstream as an
    // abrupt close, never a clean FIN after the payload).
    let upstreamGot = ''
    let upstreamSawFin = false
    const lastWord = createNetServer(socket => {
      socket.on('error', () => {})
      socket.on('data', chunk => {
        upstreamGot += chunk.toString('utf8')
      })
      socket.on('end', () => {
        upstreamSawFin = true
        socket.end(`goodbye:${upstreamGot}`)
      })
    })
    servers.push(lastWord)
    const lastWordPort = await listen(lastWord)

    const { portReady, decision, resolveVerdict } = startProxy()
    const client = connectClient(await portReady)
    sockets.push(client)
    const { received } = collectData(client)
    client.write(
      `CONNECT ${HOST}:${lastWordPort} HTTP/1.1\r\nHost: ${HOST}:${lastWordPort}\r\n\r\n`,
    )

    await decision
    resolveVerdict(true)
    await until(
      () => received().includes('200 Connection Established'),
      'tunnel establishment',
    )

    client.write('ping')
    client.end() // FIN through the tunnel — must NOT destroy the socket now
    await until(
      () => upstreamSawFin && upstreamGot === 'ping',
      'payload + clean FIN at the upstream',
      () => `upstreamGot=${JSON.stringify(upstreamGot)} fin=${upstreamSawFin}`,
    )

    // Reply delivery across the half-closed client side is only
    // assertable where the test client itself can receive after end().
    if (await clientSupportsHalfOpenReceive()) {
      await until(
        () => received().includes('goodbye:ping'),
        'reply across the half-closed tunnel',
      )
    }
  })

  it('plain HTTP: FIN mid-decision is delivered or dropped cleanly, never written to a dead socket', async () => {
    const { portReady, decision, resolveVerdict } = startProxy()
    const client = connectClient(await portReady)
    sockets.push(client)
    const { received } = collectData(client)
    client.write(
      'GET http://blocked.decision.invalid/ HTTP/1.1\r\nHost: blocked.decision.invalid\r\n\r\n',
    )
    const { socket, endSpy, writeSpy } = await decision

    // HTTP half-close: the request is complete, the client shuts down its
    // write side and waits for the response.
    client.end()
    await Bun.sleep(50)

    endSpy.mockClear()
    writeSpy.mockClear()
    resolveVerdict(false)
    await Bun.sleep(100)

    if (socket.destroyed) {
      // Bun 1.4: http.Server destroys the request socket on client FIN, so
      // there is nothing to deliver to — the verdict must be dropped with
      // no write to the destroyed socket. (On a runtime with half-open
      // request sockets, the else-branch contract applies instead; a
      // branch flip on a runtime upgrade is expected, not a regression.)
      expect(endSpy).not.toHaveBeenCalled()
      expect(writeSpy).not.toHaveBeenCalled()
      expect(received()).not.toInclude('403')
    } else {
      // Half-open-capable runtime: a half-closed client is NOT dead and
      // still receives its verdict.
      await until(
        () => received().includes('403 Forbidden'),
        'deny verdict to half-closed client',
      )
    }
  })

  it('plain HTTP: a destroyed client mid-decision gets no verdict write and no crash', async () => {
    const { portReady, decision, resolveVerdict } = startProxy()
    const client = connectClient(await portReady)
    sockets.push(client)
    client.write(
      'GET http://blocked.decision.invalid/ HTTP/1.1\r\nHost: blocked.decision.invalid\r\n\r\n',
    )
    const { socket } = await decision

    client.destroy()
    await until(
      () => socket.destroyed,
      'proxy-side teardown after client destroy',
    )

    // Deny lands after the client is gone; the proxy must treat it as a
    // no-op rather than writing to the destroyed response.
    resolveVerdict(false)
    await Bun.sleep(50)
    // Reaching here without an unhandled error is the assertion; the
    // response was never written to a dead socket.
    expect(socket.destroyed).toBe(true)
  })
})
