import { afterAll, afterEach, beforeAll, describe, expect, it } from 'bun:test'
import { once } from 'node:events'
import { unlinkSync } from 'node:fs'
import {
  createServer as createHttpServer,
  request as httpRequest,
  type Server,
} from 'node:http'
import {
  connect,
  createServer as createTcpServer,
  type AddressInfo,
  type Socket,
} from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createHttpProxyServer } from '../../src/sandbox/http-proxy.js'
import { createMitmCA, disposeMitmCA } from '../../src/sandbox/mitm-ca.js'
import { resolveParentProxy } from '../../src/sandbox/parent-proxy.js'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import { createSocksProxyServer } from '../../src/sandbox/socks-proxy.js'
import { isWindows } from '../helpers/platform.js'

/**
 * The allow/deny filter canonicalizes a destination before matching
 * (`Api.Example.com.` → `api.example.com`, `127.1` → `127.0.0.1`), so it
 * admits every spelling of an allowed name. Everything downstream of that
 * decision — MITM routing, parent-proxy bypass, TLS-termination exemption,
 * credential injection, and the authority actually put on the wire — has to
 * key off the same canonical spelling. When MITM routing matched the raw
 * spelling instead, `CONNECT api.example.com.:443` passed the allowlist,
 * matched no MITM pattern, and dialed straight out, skipping the MITM proxy
 * with a one-character change to the hostname.
 *
 * Every destination here is either loopback or a name under `.invalid`
 * (RFC 6761: never resolves), and every allowed request is answered by a
 * recording MITM / parent stand-in, so a regression shows up as a 502 (the
 * direct dial of an unresolvable name), never as real egress.
 */

let sockSeq = 0
function shortSocketPath(): string {
  // macOS sun_path is 104 bytes; keep it short.
  return join(
    tmpdir(),
    `srt-chr-${process.pid}-${(sockSeq++).toString(36)}.sock`,
  )
}

type RecordedRequest = { method: string; url: string; host: string | undefined }

type RecordingMitm = {
  socketPath: string
  connects: string[]
  requests: RecordedRequest[]
  close(): Promise<void>
}

/**
 * Stand-in for the external MITM proxy: an HTTP server on a unix socket
 * that records the authority of every CONNECT and the request-target +
 * Host header of every plain request it receives, and answers 200.
 */
async function startRecordingMitm(): Promise<RecordingMitm> {
  const socketPath = shortSocketPath()
  const connects: string[] = []
  const requests: RecordedRequest[] = []
  const server = createHttpServer((req, res) => {
    requests.push({
      method: req.method!,
      url: req.url!,
      host: req.headers.host,
    })
    res.writeHead(200, { 'content-type': 'text/plain' })
    res.end('via-mitm')
  })
  server.on('connect', (req, socket) => {
    connects.push(req.url!)
    socket.on('error', () => {})
    socket.end('HTTP/1.1 200 Connection Established\r\n\r\n')
  })
  server.listen(socketPath)
  await once(server, 'listening')
  return {
    socketPath,
    connects,
    requests,
    close: async () => {
      await new Promise<void>(r => server.close(() => r()))
      try {
        unlinkSync(socketPath)
      } catch {
        // already gone
      }
    },
  }
}

type RecordingParent = {
  port: number
  connects: string[]
  requests: RecordedRequest[]
  close(): Promise<void>
}

/**
 * Stand-in for a parent (corporate) proxy on loopback TCP: records CONNECT
 * authorities and absolute-form plain requests, answers 200 to both. Also
 * used to observe the plain-HTTP path's forwarded authority — the MITM
 * recorder above cannot be, because Bun's http.request does not honour an
 * Agent's socketPath (a pre-existing gap in the plain-HTTP MITM leg under
 * Bun, unrelated to host spelling); the parent leg is ordinary TCP and the
 * proxy builds the forwarded request-target and Host header identically
 * for both.
 */
async function startRecordingParent(): Promise<RecordingParent> {
  const connects: string[] = []
  const requests: RecordedRequest[] = []
  const server = createHttpServer((req, res) => {
    requests.push({
      method: req.method!,
      url: req.url!,
      host: req.headers.host,
    })
    res.writeHead(200, { 'content-type': 'text/plain' })
    res.end('via-parent')
  })
  server.on('connect', (req, socket) => {
    connects.push(req.url!)
    socket.on('error', () => {})
    socket.end('HTTP/1.1 200 Connection Established\r\n\r\n')
  })
  const port = await listen(server)
  return { port, connects, requests, close: () => closeServer(server) }
}

/** Raw CONNECT through the proxy; resolves with the proxy's status line. */
function rawConnect(
  proxyPort: number,
  target: string,
  authToken?: string,
): Promise<string> {
  return new Promise((resolve, reject) => {
    const auth = authToken
      ? `Proxy-Authorization: Basic ${Buffer.from(`srt:${authToken}`).toString('base64')}\r\n`
      : ''
    const sock: Socket = connect(proxyPort, '127.0.0.1', () => {
      sock.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n${auth}\r\n`)
    })
    let buf = ''
    const finish = (): void => {
      sock.destroy()
      resolve(buf.split('\r\n')[0] ?? '')
    }
    sock.on('data', d => {
      buf += d.toString('latin1')
      if (buf.includes('\r\n')) finish()
    })
    sock.on('close', finish)
    sock.on('error', reject)
    sock.setTimeout(5_000, finish)
  })
}

/** Absolute-form plain-HTTP request through the proxy. */
function rawGet(
  proxyPort: number,
  absoluteUrl: string,
  hostHeader: string,
  authToken?: string,
): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      {
        host: '127.0.0.1',
        port: proxyPort,
        method: 'GET',
        path: absoluteUrl,
        headers: {
          host: hostHeader,
          ...(authToken
            ? {
                'proxy-authorization': `Basic ${Buffer.from(`srt:${authToken}`).toString('base64')}`,
              }
            : {}),
        },
        agent: false,
      },
      res => {
        let body = ''
        res.setEncoding('utf8')
        res.on('data', d => (body += d))
        res.on('end', () => resolve({ status: res.statusCode!, body }))
        res.on('error', reject)
      },
    )
    req.on('error', reject)
    req.end()
  })
}

function listen(server: Server): Promise<number> {
  return new Promise(resolve =>
    server.listen(0, '127.0.0.1', () =>
      resolve((server.address() as AddressInfo).port),
    ),
  )
}

function closeServer(server: Server | undefined): Promise<void> {
  return new Promise(resolve => {
    if (!server) return resolve()
    server.close(() => resolve())
    // Idle keep-alive client connections would otherwise hold close() open.
    server.closeAllConnections?.()
  })
}

describe.if(!isWindows)(
  'http-proxy: routes and dials the canonical host',
  () => {
    let mitm: RecordingMitm
    let parent: RecordingParent
    let proxy: Server | undefined

    beforeAll(async () => {
      mitm = await startRecordingMitm()
      parent = await startRecordingParent()
    })
    afterAll(async () => {
      await mitm.close()
      await parent.close()
    })
    afterEach(async () => {
      await closeServer(proxy)
      proxy = undefined
      mitm.connects.length = 0
      mitm.requests.length = 0
      parent.connects.length = 0
      parent.requests.length = 0
    })

    it('CONNECT: filter sees the raw spelling; MITM lookup and the forwarded authority are canonical', async () => {
      const filterSaw: string[] = []
      const mitmLookups: string[] = []
      proxy = createHttpProxyServer({
        filter: (_port, host) => {
          filterSaw.push(host)
          return true
        },
        getMitmSocketPath: host => {
          mitmLookups.push(host)
          return host === 'api.mitm.invalid' ? mitm.socketPath : undefined
        },
      })
      const port = await listen(proxy)

      expect(await rawConnect(port, 'Api.MITM.invalid.:443')).toMatch(
        /^HTTP\/1\.1 200 /,
      )
      expect(filterSaw).toEqual(['Api.MITM.invalid.'])
      expect(mitmLookups).toEqual(['api.mitm.invalid'])
      expect(mitm.connects).toEqual(['api.mitm.invalid:443'])
    })

    it('CONNECT: an inet_aton spelling reaches the MITM lookup in dotted-quad form', async () => {
      const mitmLookups: string[] = []
      proxy = createHttpProxyServer({
        filter: () => true,
        getMitmSocketPath: host => {
          mitmLookups.push(host)
          return mitm.socketPath
        },
      })
      const port = await listen(proxy)

      expect(await rawConnect(port, '127.1:443')).toMatch(/^HTTP\/1\.1 200 /)
      expect(await rawConnect(port, '0x7f.0.0.1:443')).toMatch(
        /^HTTP\/1\.1 200 /,
      )
      expect(await rawConnect(port, '2130706433:443')).toMatch(
        /^HTTP\/1\.1 200 /,
      )
      expect(mitmLookups).toEqual(['127.0.0.1', '127.0.0.1', '127.0.0.1'])
      expect(mitm.connects).toEqual([
        '127.0.0.1:443',
        '127.0.0.1:443',
        '127.0.0.1:443',
      ])
    })

    it('plain HTTP: MITM lookup and injector destHost are canonical; forwarded request-target and Host are rebuilt from it', async () => {
      const filterSaw: string[] = []
      const mitmLookups: string[] = []
      const injectorSaw: string[] = []
      proxy = createHttpProxyServer({
        filter: (_port, host) => {
          filterSaw.push(host)
          return true
        },
        getMitmSocketPath: host => {
          mitmLookups.push(host)
          return undefined
        },
        mutateHeadersPlaintext: (_headers, destHost) => {
          injectorSaw.push(destHost)
        },
        parentProxy: resolveParentProxy({
          http: `http://127.0.0.1:${parent.port}`,
          noProxy: '',
        }),
      })
      const port = await listen(proxy)

      const res = await rawGet(
        port,
        'http://Api.MITM.invalid./v1/thing?q=1',
        'Api.MITM.invalid.',
      )
      expect(res).toEqual({ status: 200, body: 'via-parent' })
      // The URL parser lowercases; the trailing dot is what it leaves behind.
      expect(filterSaw).toEqual(['api.mitm.invalid.'])
      expect(mitmLookups).toEqual(['api.mitm.invalid'])
      expect(injectorSaw).toEqual(['api.mitm.invalid'])
      expect(parent.requests).toEqual([
        {
          method: 'GET',
          url: 'http://api.mitm.invalid/v1/thing?q=1',
          host: 'api.mitm.invalid',
        },
      ])
    })

    it('plain HTTP: an explicit non-default port survives canonicalization', async () => {
      proxy = createHttpProxyServer({
        filter: () => true,
        parentProxy: resolveParentProxy({
          http: `http://127.0.0.1:${parent.port}`,
          noProxy: '',
        }),
      })
      const port = await listen(proxy)

      const res = await rawGet(
        port,
        'http://api.mitm.invalid.:8080/x',
        'api.mitm.invalid.:8080',
      )
      expect(res.status).toBe(200)
      expect(parent.requests).toEqual([
        {
          method: 'GET',
          url: 'http://api.mitm.invalid:8080/x',
          host: 'api.mitm.invalid:8080',
        },
      ])
    })

    it('plain HTTP: an IPv6 literal is bare for the hooks and re-bracketed on the wire', async () => {
      const mitmLookups: string[] = []
      proxy = createHttpProxyServer({
        filter: () => true,
        getMitmSocketPath: host => {
          mitmLookups.push(host)
          return undefined
        },
        parentProxy: resolveParentProxy({
          http: `http://127.0.0.1:${parent.port}`,
          noProxy: '',
        }),
      })
      const port = await listen(proxy)

      // Documentation prefix (RFC 3849): not loopback, so it is not
      // parent-bypassed, and never dialed because the parent answers.
      const res = await rawGet(
        port,
        'http://[2001:0db8:0000:0000:0000:0000:0000:0001]:8080/x',
        '[2001:0db8:0000:0000:0000:0000:0000:0001]:8080',
      )
      expect(res.status).toBe(200)
      expect(mitmLookups).toEqual(['2001:db8::1'])
      expect(parent.requests).toEqual([
        {
          method: 'GET',
          url: 'http://[2001:db8::1]:8080/x',
          host: '[2001:db8::1]:8080',
        },
      ])
    })

    it('CONNECT: the parent proxy is asked for the canonical authority', async () => {
      proxy = createHttpProxyServer({
        filter: () => true,
        parentProxy: resolveParentProxy({
          http: `http://127.0.0.1:${parent.port}`,
          noProxy: '',
        }),
      })
      const port = await listen(proxy)
      expect(await rawConnect(port, 'Upstream.invalid.:80')).toMatch(
        /^HTTP\/1\.1 200 /,
      )
      expect(parent.connects).toEqual(['upstream.invalid:80'])
    })

    it('CONNECT: the tlsTerminate exemption hook is consulted with the canonical host', async () => {
      const ca = createMitmCA({})
      const exemptionSaw: string[] = []
      try {
        proxy = createHttpProxyServer({
          filter: () => true,
          mitmCA: ca,
          shouldTerminateTLS: host => {
            exemptionSaw.push(host)
            return false
          },
          // Exempted → opaque tunnel → normal routing, which we point at the
          // recorder so the test needs no real upstream.
          getMitmSocketPath: () => mitm.socketPath,
        })
        const port = await listen(proxy)
        expect(await rawConnect(port, 'Pinned.invalid.:443')).toMatch(
          /^HTTP\/1\.1 200 /,
        )
        expect(exemptionSaw).toEqual(['pinned.invalid'])
        expect(mitm.connects).toEqual(['pinned.invalid:443'])
      } finally {
        await disposeMitmCA(ca)
      }
    })
  },
)

describe.if(!isWindows)('socks-proxy: dials the canonical host', () => {
  let tcp: ReturnType<typeof createTcpServer> | undefined
  let wrapper: ReturnType<typeof createSocksProxyServer> | undefined
  let parent: RecordingParent | undefined

  afterEach(async () => {
    await wrapper?.close()
    tcp?.close()
    await parent?.close()
    wrapper = tcp = parent = undefined
  })

  it('filter sees the raw spelling; the parent proxy is asked for the canonical authority', async () => {
    parent = await startRecordingParent()
    const filterSaw: string[] = []
    wrapper = createSocksProxyServer({
      filter: (_port, host) => {
        filterSaw.push(host)
        return true
      },
      parentProxy: resolveParentProxy({
        http: `http://127.0.0.1:${parent.port}`,
        noProxy: '',
      }),
    })
    const w = wrapper
    tcp = createTcpServer(s => w.handleConnection(s))
    tcp.listen(0, '127.0.0.1')
    await once(tcp, 'listening')
    const socksPort = (tcp.address() as AddressInfo).port

    const sock = connect(socksPort, '127.0.0.1')
    await once(sock, 'connect')
    const chunks: Buffer[] = []
    sock.on('data', d => chunks.push(d))
    sock.on('error', () => {})
    // Greeting offering no-auth (no token configured), then CONNECT.
    sock.write(Buffer.from([0x05, 0x01, 0x00]))
    const host = Buffer.from('Upstream.invalid.')
    sock.write(
      Buffer.concat([
        Buffer.from([0x05, 0x01, 0x00, 0x03, host.length]),
        host,
        Buffer.from([0x00, 0x50]), // 80
      ]),
    )
    await once(sock, 'close')
    const reply = Buffer.concat(chunks)
    // method-select 05 00, then the CONNECT reply with REP=0 (granted).
    expect(reply.subarray(0, 2)).toEqual(Buffer.from([0x05, 0x00]))
    expect(reply[2]).toBe(0x05)
    expect(reply[3]).toBe(0x00)

    expect(filterSaw).toEqual(['Upstream.invalid.'])
    expect(parent.connects).toEqual(['upstream.invalid:80'])
  })
})

describe.if(!isWindows)(
  'SandboxManager: mitmProxy routing vs allowlist spellings',
  () => {
    let mitm: RecordingMitm
    let parent: RecordingParent
    let origin: Server
    let originPort: number

    beforeAll(async () => {
      mitm = await startRecordingMitm()
      parent = await startRecordingParent()
      origin = createHttpServer((_req, res) => res.end('origin'))
      originPort = await listen(origin)
    })
    afterAll(async () => {
      await SandboxManager.reset()
      await mitm.close()
      await parent.close()
      await closeServer(origin)
    })
    afterEach(async () => {
      await SandboxManager.reset()
      mitm.connects.length = 0
      mitm.requests.length = 0
      parent.connects.length = 0
      parent.requests.length = 0
    })

    async function start(network: {
      allowedDomains: string[]
      deniedDomains?: string[]
      mitmDomains: string[]
      viaParent?: boolean
    }): Promise<{ port: number; token: string }> {
      await SandboxManager.initialize({
        network: {
          allowedDomains: network.allowedDomains,
          deniedDomains: network.deniedDomains ?? [],
          mitmProxy: {
            socketPath: mitm.socketPath,
            domains: network.mitmDomains,
          },
          ...(network.viaParent
            ? {
                parentProxy: {
                  http: `http://127.0.0.1:${parent.port}`,
                  noProxy: '',
                },
              }
            : {}),
        },
        filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
      })
      return {
        port: SandboxManager.getProxyPort()!,
        token: SandboxManager.getProxyAuthToken()!,
      }
    }

    it.each([
      ['exact pattern', 'api.mitm.invalid'],
      ['wildcard pattern', '*.mitm.invalid'],
    ])(
      'a trailing-dot spelling of a MITM host is routed to the MITM socket (%s)',
      async (_label, pattern) => {
        const { port, token } = await start({
          allowedDomains: [pattern],
          mitmDomains: [pattern],
        })
        // Pre-fix this passed the allowlist, missed the MITM pattern, and
        // dialed `api.mitm.invalid.` directly — observable here as a 502,
        // since nothing under .invalid resolves.
        expect(await rawConnect(port, 'api.mitm.invalid.:443', token)).toMatch(
          /^HTTP\/1\.1 200 /,
        )
        expect(await rawConnect(port, 'API.Mitm.Invalid:443', token)).toMatch(
          /^HTTP\/1\.1 200 /,
        )
        expect(mitm.connects).toEqual([
          'api.mitm.invalid:443',
          'api.mitm.invalid:443',
        ])
      },
    )

    it('plain HTTP: a trailing-dot spelling is allowed and forwarded under its canonical authority', async () => {
      // Observed at a parent proxy rather than the MITM socket: Bun's
      // http.request cannot speak to a unix-socket Agent (see
      // startRecordingParent), and the proxy builds the forwarded authority
      // the same way for both legs. The MITM-domain lookup itself is shared
      // with the CONNECT path pinned above.
      const { port, token } = await start({
        allowedDomains: ['files.example.invalid'],
        mitmDomains: ['api.mitm.invalid'],
        viaParent: true,
      })
      const res = await rawGet(
        port,
        'http://Files.Example.invalid./v1/files',
        'Files.Example.invalid.',
        token,
      )
      expect(res).toEqual({ status: 200, body: 'via-parent' })
      expect(parent.requests).toEqual([
        {
          method: 'GET',
          url: 'http://files.example.invalid/v1/files',
          host: 'files.example.invalid',
        },
      ])
      // ...and a spelling that canonicalizes to a non-allowed name is still
      // refused before anything is forwarded.
      const denied = await rawGet(
        port,
        'http://other.example.invalid./v1/files',
        'other.example.invalid.',
        token,
      )
      expect(denied.status).toBe(403)
      expect(parent.requests).toHaveLength(1)
      expect(mitm.requests).toEqual([])
    })

    it('CONNECT via a parent proxy: MITM domains still win, and the parent gets the canonical authority otherwise', async () => {
      const { port, token } = await start({
        allowedDomains: ['api.mitm.invalid', 'other.example.invalid'],
        mitmDomains: ['api.mitm.invalid'],
        viaParent: true,
      })
      expect(await rawConnect(port, 'api.mitm.invalid.:443', token)).toMatch(
        /^HTTP\/1\.1 200 /,
      )
      expect(
        await rawConnect(port, 'Other.Example.invalid.:443', token),
      ).toMatch(/^HTTP\/1\.1 200 /)
      expect(mitm.connects).toEqual(['api.mitm.invalid:443'])
      expect(parent.connects).toEqual(['other.example.invalid:443'])
    })

    it('inet_aton spellings of a MITM-pinned IP are routed to the MITM socket', async () => {
      const { port, token } = await start({
        allowedDomains: ['127.0.0.1'],
        mitmDomains: ['127.0.0.1'],
      })
      for (const spelling of [
        '127.1',
        '0x7f.0.0.1',
        '2130706433',
        '127.0.0.1.',
      ]) {
        expect(
          await rawConnect(port, `${spelling}:${originPort}`, token),
        ).toMatch(/^HTTP\/1\.1 200 /)
      }
      // Every spelling went to the MITM, none to the origin behind it.
      expect(mitm.connects).toEqual(
        Array(4).fill(`127.0.0.1:${originPort}`) as string[],
      )
    })

    it('an allowed host that canonicalizes to a non-MITM name still dials directly', async () => {
      const { port, token } = await start({
        allowedDomains: ['api.mitm.invalid', '127.0.0.1'],
        mitmDomains: ['api.mitm.invalid'],
      })
      expect(await rawConnect(port, `127.1:${originPort}`, token)).toMatch(
        /^HTTP\/1\.1 200 /,
      )
      expect(await rawConnect(port, `127.0.0.1.:${originPort}`, token)).toMatch(
        /^HTTP\/1\.1 200 /,
      )
      expect(mitm.connects).toEqual([])
    })

    it('a host outside the allowlist is denied however it is spelled, and never reaches the MITM', async () => {
      const { port, token } = await start({
        allowedDomains: ['api.mitm.invalid'],
        mitmDomains: ['*.mitm.invalid'],
      })
      for (const target of [
        'other.mitm.invalid:443',
        'other.mitm.invalid.:443',
        'OTHER.mitm.invalid.:443',
      ]) {
        expect(await rawConnect(port, target, token)).toMatch(
          /^HTTP\/1\.1 403 /,
        )
      }
      expect(mitm.connects).toEqual([])
    })

    it('an IPv4-mapped spelling of a deny-listed address is refused even when that spelling is allow-listed', async () => {
      const { port, token } = await start({
        allowedDomains: ['[::ffff:127.0.0.1]'],
        deniedDomains: ['127.0.0.1'],
        mitmDomains: [],
      })
      for (const target of [
        `[::ffff:127.0.0.1]:${originPort}`,
        `[::FFFF:7F00:1]:${originPort}`,
        `[0:0:0:0:0:ffff:7f00:1]:${originPort}`,
      ]) {
        expect(await rawConnect(port, target, token)).toMatch(
          /^HTTP\/1\.1 403 /,
        )
      }
    })

    it('deniedDomains wins over every spelling of the denied host', async () => {
      const { port, token } = await start({
        allowedDomains: ['*.mitm.invalid', '127.0.0.1'],
        deniedDomains: ['evil.mitm.invalid', '127.0.0.1'],
        mitmDomains: ['*.mitm.invalid'],
      })
      for (const target of [
        'evil.mitm.invalid:443',
        'evil.mitm.invalid.:443',
        'EVIL.MITM.invalid.:443',
        `127.1:${originPort}`,
        `0x7f.0.0.1:${originPort}`,
        `2130706433:${originPort}`,
        `0177.0.0.1:${originPort}`,
      ]) {
        expect(await rawConnect(port, target, token)).toMatch(
          /^HTTP\/1\.1 403 /,
        )
      }
      // ...while a sibling that is merely allowed still routes to the MITM
      // under any spelling — pinning that allow and MITM agree.
      expect(await rawConnect(port, 'ok.mitm.invalid.:443', token)).toMatch(
        /^HTTP\/1\.1 200 /,
      )
      expect(mitm.connects).toEqual(['ok.mitm.invalid:443'])
    })
  },
)
