import { describe, test, expect, beforeAll, afterAll } from 'bun:test'
import { createServer, type Server } from 'node:http'
import { connect } from 'node:net'
import type { AddressInfo } from 'node:net'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { connect as tlsConnect, type TLSSocket } from 'node:tls'
import { createHttpProxyServer } from '../../src/sandbox/http-proxy.js'
import { createMitmCA, disposeMitmCA } from '../../src/sandbox/mitm-ca.js'

// A sandboxed client whose process tree is torn down mid-exchange resets
// its proxy connection. The runtime then destroys the server-side req/res
// with an error (ECONNRESET / "aborted", emitted from node:_http_server);
// without 'error' listeners on those streams the event escalates to an
// uncaughtException. A burst of simultaneous teardowns — one aborted
// subagent killing its whole process tree — crashes the host process.
// These tests drive the plain-HTTP request path with clients that vanish
// mid-request and assert nothing escapes to the process level.
describe('http proxy survives client aborts', () => {
  const uncaught: Error[] = []
  const onUncaught = (err: Error): void => {
    uncaught.push(err)
  }

  let upstream: Server
  let upstreamPort: number
  let proxy: Server
  let proxyPort: number

  beforeAll(async () => {
    process.on('uncaughtException', onUncaught)
    // Upstream stalls before responding so client aborts land while the
    // proxied exchange is still in flight.
    upstream = createServer((req, res) => {
      req.resume()
      setTimeout(() => {
        if (!res.writableEnded) {
          res.writeHead(200, { 'content-type': 'text/plain' })
          res.end('ok')
        }
      }, 300)
    })
    await new Promise<void>(r => upstream.listen(0, '127.0.0.1', r))
    upstreamPort = (upstream.address() as AddressInfo).port

    proxy = createHttpProxyServer({ filter: () => true })
    await new Promise<void>(r => proxy.listen(0, '127.0.0.1', () => r()))
    proxyPort = (proxy.address() as AddressInfo).port
  })

  afterAll(async () => {
    await new Promise<void>(r => proxy.close(() => r()))
    await new Promise<void>(r => upstream.close(() => r()))
    process.off('uncaughtException', onUncaught)
  })

  /** Open a raw connection to the proxy, write `data`, destroy after `ms`. */
  const abortAfter = (data: string, ms: number): Promise<void> =>
    new Promise(resolve => {
      const sock = connect(proxyPort, '127.0.0.1', () => {
        sock.write(data)
        setTimeout(() => {
          sock.destroy()
          resolve()
        }, ms)
      })
      sock.on('error', () => {})
    })

  test('client destroyed mid request body', async () => {
    uncaught.length = 0
    await abortAfter(
      `POST http://127.0.0.1:${upstreamPort}/upload HTTP/1.1\r\n` +
        `Host: 127.0.0.1:${upstreamPort}\r\n` +
        'Content-Length: 100000\r\n' +
        '\r\n' +
        'partial-body-then-gone',
      50,
    )
    await new Promise(r => setTimeout(r, 500))
    expect(uncaught).toEqual([])
  })

  test('client destroyed while awaiting the response', async () => {
    uncaught.length = 0
    await abortAfter(
      `GET http://127.0.0.1:${upstreamPort}/slow HTTP/1.1\r\n` +
        `Host: 127.0.0.1:${upstreamPort}\r\n` +
        '\r\n',
      50,
    )
    await new Promise(r => setTimeout(r, 500))
    expect(uncaught).toEqual([])
  })

  test('burst of simultaneous client aborts', async () => {
    uncaught.length = 0
    await Promise.all(
      Array.from({ length: 15 }, (_, i) =>
        abortAfter(
          `POST http://127.0.0.1:${upstreamPort}/burst-${i} HTTP/1.1\r\n` +
            `Host: 127.0.0.1:${upstreamPort}\r\n` +
            'Content-Length: 100000\r\n' +
            '\r\n' +
            'partial',
          30,
        ),
      ),
    )
    await new Promise(r => setTimeout(r, 600))
    expect(uncaught).toEqual([])
  })

  test('malformed bytes then disconnect hits clientError, not the process', async () => {
    uncaught.length = 0
    await abortAfter('\x16\x03\x01 not http at all\r\n', 50)
    await new Promise(r => setTimeout(r, 300))
    expect(uncaught).toEqual([])
  })
})

// With `filterRequest` configured (how SandboxManager wires the proxy in
// production), body-carrying requests are teed via Readable.toWeb(req), so
// the stream that gets piped upstream is a tee branch — not `req` itself.
// A client abort then errors that branch, and pipe() does not handle source
// errors: without an explicit listener the abort escapes as an
// uncaughtException from node:_http_server.
describe('http proxy with filterRequest survives client aborts', () => {
  const uncaught: Error[] = []
  const onUncaught = (err: Error): void => {
    uncaught.push(err)
  }

  let upstream: Server
  let upstreamPort: number
  let proxy: Server
  let proxyPort: number

  beforeAll(async () => {
    process.on('uncaughtException', onUncaught)
    upstream = createServer((req, res) => {
      req.resume()
      setTimeout(() => {
        if (!res.writableEnded) {
          res.writeHead(200, { 'content-type': 'text/plain' })
          res.end('ok')
        }
      }, 300)
    })
    await new Promise<void>(r => upstream.listen(0, '127.0.0.1', r))
    upstreamPort = (upstream.address() as AddressInfo).port

    proxy = createHttpProxyServer({
      filter: () => true,
      filterRequest: async () => ({ action: 'allow' }),
    })
    await new Promise<void>(r => proxy.listen(0, '127.0.0.1', () => r()))
    proxyPort = (proxy.address() as AddressInfo).port
  })

  afterAll(async () => {
    await new Promise<void>(r => proxy.close(() => r()))
    await new Promise<void>(r => upstream.close(() => r()))
    process.off('uncaughtException', onUncaught)
  })

  const abortPostAfter = (ms: number, rst: boolean): Promise<void> =>
    new Promise(resolve => {
      const sock = connect(proxyPort, '127.0.0.1', () => {
        sock.write(
          `POST http://127.0.0.1:${upstreamPort}/upload HTTP/1.1\r\n` +
            `Host: 127.0.0.1:${upstreamPort}\r\n` +
            'Content-Length: 100000\r\n' +
            '\r\n' +
            'partial-body-then-gone',
        )
        setTimeout(() => {
          if (rst && 'resetAndDestroy' in sock) {
            ;(
              sock as unknown as { resetAndDestroy: () => void }
            ).resetAndDestroy()
          } else {
            sock.destroy()
          }
          resolve()
        }, ms)
      })
      sock.on('error', () => {})
    })

  test('client FIN mid teed request body', async () => {
    uncaught.length = 0
    await abortPostAfter(50, false)
    await new Promise(r => setTimeout(r, 500))
    expect(uncaught).toEqual([])
  })

  test('client RST mid teed request body', async () => {
    uncaught.length = 0
    await abortPostAfter(50, true)
    await new Promise(r => setTimeout(r, 500))
    expect(uncaught).toEqual([])
  })

  test('burst of simultaneous aborts on teed bodies', async () => {
    uncaught.length = 0
    await Promise.all(
      Array.from({ length: 15 }, (_, i) => abortPostAfter(30, i % 2 === 0)),
    )
    await new Promise(r => setTimeout(r, 600))
    expect(uncaught).toEqual([])
  })
})

// The crash fixes must not weaken the proxy's delivery semantics: an
// aborted upload must never reach the upstream framed as complete, denied
// clients must still get their 403 and then lose the connection, and the
// clientError 400 must actually arrive. These pin the guards a bare
// "no uncaughtException" assertion cannot.
describe('client-abort delivery semantics', () => {
  const uncaught: Error[] = []
  const onUncaught = (err: Error): void => {
    uncaught.push(err)
  }

  type UpstreamEvent = { url: string; event: string }
  const upstreamEvents: UpstreamEvent[] = []
  let upstreamRequests = 0
  let upstream: Server
  let upstreamPort: number
  let proxy: Server
  let proxyPort: number
  let filterDelayMs = 0
  let filterMode: 'allow' | 'deny' = 'allow'

  beforeAll(async () => {
    process.on('uncaughtException', onUncaught)
    upstream = createServer((req, res) => {
      upstreamRequests++
      req.on('error', () =>
        upstreamEvents.push({ url: req.url!, event: 'error' }),
      )
      req.on('aborted', () =>
        upstreamEvents.push({ url: req.url!, event: 'aborted' }),
      )
      req.on('end', () => upstreamEvents.push({ url: req.url!, event: 'end' }))
      req.resume()
      if (req.url === '/download') {
        res.writeHead(200, { 'content-length': String(64 * 1024 * 1024) })
        const chunk = Buffer.alloc(65536, 67)
        const iv = setInterval(() => res.write(chunk), 5)
        res.on('close', () => clearInterval(iv))
        res.on('error', () => clearInterval(iv))
        return
      }
      setTimeout(() => {
        if (!res.writableEnded) {
          try {
            res.end('ok')
          } catch {
            // client already gone
          }
        }
      }, 300)
    })
    await new Promise<void>(r => upstream.listen(0, '127.0.0.1', r))
    upstreamPort = (upstream.address() as AddressInfo).port

    proxy = createHttpProxyServer({
      filter: () => true,
      filterRequest: async () => {
        if (filterDelayMs) await new Promise(r => setTimeout(r, filterDelayMs))
        return { action: filterMode, reason: 'semantics' }
      },
    })
    await new Promise<void>(r => proxy.listen(0, '127.0.0.1', () => r()))
    proxyPort = (proxy.address() as AddressInfo).port
  })

  afterAll(async () => {
    // Lingering keep-alive client sockets (the malformed-bytes and smuggle
    // tests) would otherwise make close() wait out its own timeouts.
    ;(
      proxy as Server & { closeAllConnections?: () => void }
    ).closeAllConnections?.()
    ;(
      upstream as Server & { closeAllConnections?: () => void }
    ).closeAllConnections?.()
    await Promise.all([
      new Promise<void>(r => {
        const t = setTimeout(r, 2000)
        proxy.close(() => {
          clearTimeout(t)
          r()
        })
      }),
      new Promise<void>(r => {
        const t = setTimeout(r, 2000)
        upstream.close(() => {
          clearTimeout(t)
          r()
        })
      }),
    ])
    process.off('uncaughtException', onUncaught)
  })

  test('aborted chunked upload never reaches the upstream framed as complete', async () => {
    uncaught.length = 0
    upstreamEvents.length = 0
    filterDelayMs = 0
    filterMode = 'allow'
    await new Promise<void>(resolve => {
      const s = connect(proxyPort, '127.0.0.1', () => {
        s.write(
          `POST http://127.0.0.1:${upstreamPort}/truncated HTTP/1.1\r\n` +
            `Host: 127.0.0.1:${upstreamPort}\r\n` +
            'Transfer-Encoding: chunked\r\n' +
            '\r\n' +
            '6\r\nchunk1\r\n',
        )
        setTimeout(() => {
          s.destroy()
          resolve()
        }, 250)
      })
      s.on('error', () => {})
    })
    await new Promise(r => setTimeout(r, 800))
    const truncated = upstreamEvents.filter(e => e.url === '/truncated')
    expect(truncated.some(e => e.event === 'end')).toBe(false)
    expect(uncaught).toEqual([])
  })

  test('abort during a slow filterRequest: no crash, no complete upstream delivery', async () => {
    uncaught.length = 0
    upstreamEvents.length = 0
    filterDelayMs = 500
    filterMode = 'allow'
    await new Promise<void>(resolve => {
      const s = connect(proxyPort, '127.0.0.1', () => {
        s.write(
          `POST http://127.0.0.1:${upstreamPort}/slowfilter HTTP/1.1\r\n` +
            `Host: 127.0.0.1:${upstreamPort}\r\n` +
            'Content-Length: 100000\r\n' +
            '\r\n' +
            'partial',
        )
        setTimeout(() => {
          s.destroy()
          resolve()
        }, 100)
      })
      s.on('error', () => {})
    })
    await new Promise(r => setTimeout(r, 1200))
    filterDelayMs = 0
    const events = upstreamEvents.filter(e => e.url === '/slowfilter')
    expect(events.some(e => e.event === 'end')).toBe(false)
    expect(uncaught).toEqual([])
  })

  test('client abort mid-download does not crash the proxy', async () => {
    uncaught.length = 0
    filterMode = 'allow'
    await new Promise<void>(resolve => {
      const s = connect(proxyPort, '127.0.0.1', () => {
        s.write(
          `GET http://127.0.0.1:${upstreamPort}/download HTTP/1.1\r\n` +
            `Host: 127.0.0.1:${upstreamPort}\r\n` +
            '\r\n',
        )
      })
      let got = 0
      s.on('data', d => {
        got += d.length
        if (got > 256 * 1024) {
          const rad = (s as unknown as { resetAndDestroy?: () => void })
            .resetAndDestroy
          if (rad) rad.call(s)
          else s.destroy()
          resolve()
        }
      })
      s.on('error', () => {})
      setTimeout(resolve, 3000)
    })
    await new Promise(r => setTimeout(r, 800))
    expect(uncaught).toEqual([])
  })

  test('denied mid-upload client receives the 403 and then loses the connection', async () => {
    uncaught.length = 0
    filterMode = 'deny'
    let resp = ''
    let closed = false
    await new Promise<void>(resolve => {
      const s = connect(proxyPort, '127.0.0.1', () => {
        s.write(
          `POST http://127.0.0.1:${upstreamPort}/denied HTTP/1.1\r\n` +
            `Host: 127.0.0.1:${upstreamPort}\r\n` +
            'Content-Length: 9999999\r\n' +
            '\r\n' +
            'partial...',
        )
      })
      s.on('data', d => {
        resp += d.toString()
      })
      s.on('close', () => {
        closed = true
        resolve()
      })
      s.on('error', () => {})
      setTimeout(resolve, 4000)
    })
    filterMode = 'allow'
    expect(resp).toContain('403')
    expect(resp).toContain('semantics')
    expect(closed).toBe(true)
    expect(uncaught).toEqual([])
  })

  test('malformed bytes get an HTTP 400 back (Node) or a prompt close (Bun), never a crash', async () => {
    uncaught.length = 0
    let resp = ''
    let closed = false
    await new Promise<void>(resolve => {
      const s = connect(proxyPort, '127.0.0.1', () => {
        s.write('GARBAGE REQUEST LINE\r\n\r\n')
      })
      s.on('data', d => {
        resp += d.toString()
      })
      s.on('close', () => {
        closed = true
        resolve()
      })
      s.on('error', () => {})
      setTimeout(resolve, 2500)
    })
    // Node delivers the 400; Bun drops the write on a parse-errored socket
    // (verified empirically) and the handler's backstop closes it instead.
    expect(resp === '' || resp.startsWith('HTTP/1.1 400')).toBe(true)
    expect(closed).toBe(true)
    expect(uncaught).toEqual([])
  })

  test('GET with a body: callback sees a bodyless Request, upstream gets the body', async () => {
    uncaught.length = 0
    const received: string[] = []
    const echo = createServer((req, res) => {
      const chunks: Buffer[] = []
      req.on('error', () => {})
      req.on('data', c => chunks.push(c))
      req.on('end', () => {
        received.push(Buffer.concat(chunks).toString())
        res.end('ok')
      })
    })
    await new Promise<void>(r => echo.listen(0, '127.0.0.1', r))
    const eport = (echo.address() as AddressInfo).port
    let callbackBody: unknown = 'unset'
    const p2 = createHttpProxyServer({
      filter: () => true,
      filterRequest: async r => {
        callbackBody = r.body
        return { action: 'allow' }
      },
    })
    await new Promise<void>(r => p2.listen(0, '127.0.0.1', () => r()))
    const pport = (p2.address() as AddressInfo).port
    let resp = ''
    await new Promise<void>(resolve => {
      const s = connect(pport, '127.0.0.1', () => {
        const body = 'get-body-payload'
        s.write(
          `GET http://127.0.0.1:${eport}/g HTTP/1.1\r\n` +
            `Host: 127.0.0.1:${eport}\r\n` +
            'Transfer-Encoding: chunked\r\n' +
            '\r\n' +
            `${body.length.toString(16)}\r\n${body}\r\n0\r\n\r\n`,
        )
      })
      s.on('data', d => {
        resp += d.toString()
        if (resp.includes('ok')) {
          s.destroy()
          resolve()
        }
      })
      s.on('error', () => {})
      setTimeout(resolve, 3000)
    })
    ;(
      p2 as Server & { closeAllConnections?: () => void }
    ).closeAllConnections?.()
    ;(
      echo as Server & { closeAllConnections?: () => void }
    ).closeAllConnections?.()
    await new Promise<void>(r => {
      const t = setTimeout(r, 1500)
      p2.close(() => {
        clearTimeout(t)
        r()
      })
    })
    await new Promise<void>(r => {
      const t = setTimeout(r, 1500)
      echo.close(() => {
        clearTimeout(t)
        r()
      })
    })
    expect(resp.startsWith('HTTP/1.1 200')).toBe(true)
    expect(callbackBody).toBe(null)
    expect(received).toEqual(['get-body-payload'])
    expect(uncaught).toEqual([])
  })

  test('oversized header block gets 431 (Node) or a silent close (Bun), never a crash', async () => {
    uncaught.length = 0
    let resp = ''
    await new Promise<void>(resolve => {
      const s = connect(proxyPort, '127.0.0.1', () => {
        s.write(
          `GET http://127.0.0.1:${upstreamPort}/hdr HTTP/1.1\r\n` +
            `Host: 127.0.0.1:${upstreamPort}\r\n` +
            'X-Big: ' +
            'a'.repeat(40000) +
            '\r\n\r\n',
        )
      })
      s.on('data', d => {
        resp += d.toString()
      })
      s.on('close', resolve)
      s.on('error', () => {})
      setTimeout(resolve, 2500)
    })
    expect(resp === '' || resp.startsWith('HTTP/1.1 431')).toBe(true)
    expect(uncaught).toEqual([])
  })

  test('abort mid-upload to a blocked host does not crash', async () => {
    uncaught.length = 0
    const blocking = createHttpProxyServer({ filter: () => false })
    await new Promise<void>(r => blocking.listen(0, '127.0.0.1', () => r()))
    const bport = (blocking.address() as AddressInfo).port
    await new Promise<void>(resolve => {
      const s = connect(bport, '127.0.0.1', () => {
        s.write(
          `POST http://127.0.0.1:${upstreamPort}/blocked HTTP/1.1\r\n` +
            `Host: 127.0.0.1:${upstreamPort}\r\n` +
            'Content-Length: 100000\r\n' +
            '\r\n' +
            'partial',
        )
        setTimeout(() => {
          s.destroy()
          resolve()
        }, 80)
      })
      s.on('error', () => {})
    })
    await new Promise(r => setTimeout(r, 500))
    await new Promise<void>(r => blocking.close(() => r()))
    expect(uncaught).toEqual([])
  })

  test('GET with Content-Length: 0 passes the filter and succeeds', async () => {
    // Fetch-spec Requests reject a body on GET (Node throws; Bun is
    // lenient): the declared-body tee must not leak into the callback's
    // Request or innocent bodyless-framed GETs get 403'd as malformed.
    uncaught.length = 0
    filterMode = 'allow'
    let resp = ''
    await new Promise<void>(resolve => {
      const s = connect(proxyPort, '127.0.0.1', () => {
        s.write(
          `GET http://127.0.0.1:${upstreamPort}/empty-get HTTP/1.1\r\n` +
            `Host: 127.0.0.1:${upstreamPort}\r\n` +
            'Content-Length: 0\r\n' +
            '\r\n',
        )
      })
      s.on('data', d => {
        resp += d.toString()
        if (resp.includes('ok')) {
          s.destroy()
          resolve()
        }
      })
      s.on('error', () => {})
      setTimeout(resolve, 3000)
    })
    expect(resp.startsWith('HTTP/1.1 200')).toBe(true)
    expect(uncaught).toEqual([])
  })

  test('empty Transfer-Encoding value does not trigger teeing or re-framing', async () => {
    uncaught.length = 0
    filterMode = 'allow'
    let resp = ''
    await new Promise<void>(resolve => {
      const s = connect(proxyPort, '127.0.0.1', () => {
        s.write(
          `GET http://127.0.0.1:${upstreamPort}/empty-te HTTP/1.1\r\n` +
            `Host: 127.0.0.1:${upstreamPort}\r\n` +
            'Transfer-Encoding:\r\n' +
            '\r\n',
        )
      })
      s.on('data', d => {
        resp += d.toString()
        if (resp.includes('ok')) {
          s.destroy()
          resolve()
        }
      })
      s.on('error', () => {})
      setTimeout(resolve, 3000)
    })
    expect(resp.startsWith('HTTP/1.1 200')).toBe(true)
    expect(uncaught).toEqual([])
  })

  test('GET with a chunked body cannot smuggle even without filterRequest', async () => {
    // The re-framing must not depend on the tee existing: a filterless
    // deployment forwards req directly, and TE is still stripped as
    // hop-by-hop.
    uncaught.length = 0
    const bare = createHttpProxyServer({ filter: () => true })
    await new Promise<void>(r => bare.listen(0, '127.0.0.1', () => r()))
    const bport = (bare.address() as AddressInfo).port
    upstreamEvents.length = 0
    upstreamRequests = 0
    await new Promise<void>(resolve => {
      const s = connect(bport, '127.0.0.1', () => {
        const smuggled =
          `POST http://127.0.0.1:${upstreamPort}/admin2 HTTP/1.1\r\n` +
          `Host: 127.0.0.1:${upstreamPort}\r\nContent-Length: 0\r\n\r\n`
        s.write(
          `GET http://127.0.0.1:${upstreamPort}/legit2 HTTP/1.1\r\n` +
            `Host: 127.0.0.1:${upstreamPort}\r\n` +
            'Transfer-Encoding: chunked\r\n' +
            '\r\n' +
            `${smuggled.length.toString(16)}\r\n${smuggled}\r\n` +
            '0\r\n\r\n',
        )
      })
      s.on('data', () => {})
      s.on('close', resolve)
      s.on('error', () => {})
      setTimeout(resolve, 3000)
    })
    await new Promise(r => setTimeout(r, 500))
    ;(
      bare as Server & { closeAllConnections?: () => void }
    ).closeAllConnections?.()
    await new Promise<void>(r => {
      const t = setTimeout(r, 1500)
      bare.close(() => {
        clearTimeout(t)
        r()
      })
    })
    expect(upstreamEvents.some(e => e.url === '/admin2')).toBe(false)
    expect(upstreamRequests).toBeLessThanOrEqual(1)
    expect(uncaught).toEqual([])
  })

  test('GET with a chunked body cannot smuggle a second request upstream', async () => {
    uncaught.length = 0
    upstreamEvents.length = 0
    upstreamRequests = 0
    filterMode = 'allow'
    await new Promise<void>(resolve => {
      const s = connect(proxyPort, '127.0.0.1', () => {
        const smuggled =
          `POST http://127.0.0.1:${upstreamPort}/admin HTTP/1.1\r\n` +
          `Host: 127.0.0.1:${upstreamPort}\r\nContent-Length: 0\r\n\r\n`
        s.write(
          `GET http://127.0.0.1:${upstreamPort}/legit HTTP/1.1\r\n` +
            `Host: 127.0.0.1:${upstreamPort}\r\n` +
            'Transfer-Encoding: chunked\r\n' +
            '\r\n' +
            `${smuggled.length.toString(16)}\r\n${smuggled}\r\n` +
            '0\r\n\r\n',
        )
      })
      s.on('data', () => {})
      s.on('close', resolve)
      s.on('error', () => {})
      setTimeout(resolve, 3000)
    })
    await new Promise(r => setTimeout(r, 500))
    expect(upstreamEvents.some(e => e.url === '/admin')).toBe(false)
    expect(upstreamRequests).toBeLessThanOrEqual(1)
    expect(uncaught).toEqual([])
  })
})

// TLS-terminated path: the same abort classes must hold through the inner
// HTTPS server (the request handler listeners, inner clientError, and the
// teed-body wiring are otherwise unreachable by the plain-HTTP tests).
describe('client aborts through the TLS-terminating path', () => {
  const FIXTURE_DIR = join(import.meta.dir, '..', 'fixtures', 'tls-terminate')
  const CA_PEM = readFileSync(join(FIXTURE_DIR, 'ca.crt'), 'utf8')
  const ca = createMitmCA({
    caCertPath: join(FIXTURE_DIR, 'ca.crt'),
    caKeyPath: join(FIXTURE_DIR, 'ca.key'),
  })

  const uncaught: Error[] = []
  const onUncaught = (err: Error): void => {
    uncaught.push(err)
  }

  let proxy: Server
  let proxyPort: number

  beforeAll(async () => {
    process.on('uncaughtException', onUncaught)
    proxy = createHttpProxyServer({
      filter: () => true,
      mitmCA: ca,
      filterRequest: async () => ({ action: 'allow' }),
    })
    await new Promise<void>(r => proxy.listen(0, '127.0.0.1', () => r()))
    proxyPort = (proxy.address() as AddressInfo).port
  })

  afterAll(async () => {
    await new Promise<void>(r => proxy.close(() => r()))
    await disposeMitmCA(ca)
    process.off('uncaughtException', onUncaught)
  })

  /** CONNECT through the proxy, complete the TLS handshake, run fn. */
  const throughTunnel = (
    fn: (tls: TLSSocket, done: () => void) => void,
  ): Promise<void> =>
    new Promise(resolve => {
      const raw = connect(proxyPort, '127.0.0.1', () => {
        raw.write(
          'CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\n\r\n',
        )
      })
      raw.on('error', () => {})
      raw.once('data', () => {
        const tls = tlsConnect(
          { socket: raw, ca: CA_PEM, servername: 'localhost' },
          () => fn(tls, () => resolve()),
        )
        tls.on('error', () => resolve())
      })
      setTimeout(resolve, 4000)
    })

  test('TLS client destroyed mid request body', async () => {
    uncaught.length = 0
    await throughTunnel((tls, done) => {
      tls.write(
        'POST /upload HTTP/1.1\r\nHost: localhost\r\n' +
          'Content-Length: 100000\r\n\r\npartial',
      )
      setTimeout(() => {
        tls.destroy()
        done()
      }, 150)
    })
    await new Promise(r => setTimeout(r, 800))
    expect(uncaught).toEqual([])
  })

  test('garbage bytes after the TLS handshake do not crash', async () => {
    uncaught.length = 0
    await throughTunnel((tls, done) => {
      tls.write('\x00\x01 not http\r\n\r\n')
      setTimeout(() => {
        tls.destroy()
        done()
      }, 150)
    })
    await new Promise(r => setTimeout(r, 600))
    expect(uncaught).toEqual([])
  })
})
