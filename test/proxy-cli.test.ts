import { describe, expect, test } from 'bun:test'
import { spawn } from 'node:child_process'
import { existsSync, readFileSync } from 'node:fs'
import { connect, createServer, type Socket } from 'node:net'
import type { Writable } from 'node:stream'
import { connect as tlsConnect } from 'node:tls'
import { encodeFrame } from '../src/sandbox/decider-client.js'
import { generateCa } from '../src/sandbox/mitm-ca.js'
import { SERVES_EMITTED_CONNECTIONS } from './helpers/emitted-connections.js'

const ENTRY = new URL('../src/proxy-main.ts', import.meta.url).pathname
const TASKSET =
  process.platform === 'linux'
    ? (['/usr/bin/taskset', '/bin/taskset'].find(p => existsSync(p)) ?? null)
    : null
/** The first CPU this process may run on (Linux). */
const FIRST_CPU =
  /^Cpus_allowed_list:\s*(\d+)/m.exec(
    process.platform === 'linux'
      ? readFileSync('/proc/self/status', 'utf8')
      : '',
  )?.[1] ?? '0'
const HELLO = readFileSync(
  new URL('./fixtures/srt-proxy-hello.json', import.meta.url),
  'utf8',
)

function run(args: string[], env?: Record<string, string>) {
  const child = spawn(process.execPath, [ENTRY, ...args], {
    stdio: ['ignore', 'ignore', 'pipe', 'pipe', 'pipe'],
    env: env && { ...process.env, ...env },
  })
  let stderr = ''
  child.stderr!.on('data', d => (stderr += d))
  const exited = new Promise<number | null>(resolve =>
    child.once('exit', code => resolve(code)),
  )
  return { child, exited, stderr: () => stderr }
}

/** The loopback port a proxy started with `--listen 127.0.0.1:0` serves. */
function servingPort(p: ReturnType<typeof run>): Promise<number> {
  return new Promise<number>((resolve, reject) => {
    const t = setInterval(() => {
      const m = /serving 127\.0\.0\.1:(\d+)/.exec(p.stderr())
      if (m) {
        clearInterval(t)
        resolve(Number(m[1]))
      }
    }, 20)
    void p.exited.then(code => {
      clearInterval(t)
      reject(new Error(`exited ${code}: ${p.stderr()}`))
    })
  })
}

describe('srt-proxy entry', () => {
  test('without a decider it refuses to start (exit 2)', async () => {
    const p = run(['--listen', '127.0.0.1:0'])
    expect(await p.exited).toBe(2)
    expect(p.stderr()).toContain('a decider is required')
  })

  test('with SRT_PROXY_REPORT_RSS_MS set, reports its resident set size on stderr', async () => {
    const p = run(['--listen', '127.0.0.1:0', '--decider-fd', '3'], {
      SRT_PROXY_REPORT_RSS_MS: '20',
    })
    try {
      const sizes = await new Promise<number[]>((resolve, reject) => {
        const t = setInterval(() => {
          const found = [...p.stderr().matchAll(/^srt-proxy rss (\d+)$/gm)]
          if (found.length >= 2) {
            clearInterval(t)
            resolve(found.map(m => Number(m[1])))
          }
        }, 20)
        void p.exited.then(code => {
          clearInterval(t)
          reject(new Error(`exited ${code}: ${p.stderr()}`))
        })
      })
      for (const n of sizes) expect(n).toBeGreaterThan(0)
    } finally {
      p.child.kill()
      await p.exited
    }
  }, 20_000)

  test('speaks the pinned hello first, serves after the decider answers, and stops when the lifeline ends', async () => {
    const p = run([
      '--listen',
      '127.0.0.1:0',
      '--decider-fd',
      '3',
      '--lifeline-fd',
      '4',
      '--strip-response-header',
      'set-cookie',
    ])
    const decider = p.child.stdio[3] as Socket
    const lifeline = p.child.stdio[4] as Writable
    const first = await new Promise<Buffer>(resolve =>
      decider.once('data', (c: Buffer) => resolve(c)),
    )
    expect(first.readUInt32BE(0)).toBe(first.length - 4)
    expect(first.subarray(4).toString('utf8')).toBe(HELLO)
    decider.write(
      encodeFrame({
        t: 'hello',
        proto: 1,
        allowedDomains: ['allowed.test:443'],
        deniedDomains: [],
      }),
    )
    const port = await servingPort(p)
    // A host outside the decider's list is refused before it is asked.
    const reply = await new Promise<string>(resolve => {
      const c = connect(port, '127.0.0.1', () =>
        c.write(
          'CONNECT other.test:443 HTTP/1.1\r\nHost: other.test:443\r\n\r\n',
        ),
      )
      let out = ''
      c.on('data', d => (out += d))
      c.on('close', () => resolve(out))
      c.on('error', () => resolve(out))
    })
    expect(reply).toStartWith('HTTP/1.1 403')
    lifeline.end()
    expect(await p.exited).toBe(0)
    expect(p.stderr()).toContain('lifeline closed')
  }, 20_000)

  test('a decider that stops reading stops the proxy, and the request in hand is refused', async () => {
    const p = run([
      '--listen',
      '127.0.0.1:0',
      '--decider-in',
      '3',
      '--decider-out',
      '4',
    ])
    try {
      const toProxy = p.child.stdio[3] as Socket
      const fromProxy = p.child.stdio[4] as Socket
      await new Promise<void>(resolve =>
        fromProxy.once('data', () => resolve()),
      )
      toProxy.write(
        encodeFrame({
          t: 'hello',
          proto: 1,
          allowedDomains: ['allowed.test:80'],
          deniedDomains: [],
        }),
      )
      const port = await servingPort(p)
      // The decider's reading end goes away while its writing end stays
      // open, so the proxy learns of it only by failing to write a frame.
      await new Promise<void>(resolve => {
        fromProxy.once('close', () => resolve())
        fromProxy.destroy()
      })
      const reply = await new Promise<string>(resolve => {
        const c = connect(port, '127.0.0.1', () =>
          c.write(
            'GET http://allowed.test/x HTTP/1.1\r\nHost: allowed.test\r\nConnection: close\r\n\r\n',
          ),
        )
        let out = ''
        c.on('data', d => (out += d))
        c.on('close', () => resolve(out))
        c.on('error', () => resolve(out))
      })
      expect(reply).toStartWith('HTTP/1.1 503')
      let timer: ReturnType<typeof setTimeout> | undefined
      const code = await Promise.race([
        p.exited,
        new Promise<string>(resolve => {
          timer = setTimeout(() => resolve('still running'), 3000)
        }),
      ])
      clearTimeout(timer)
      expect(p.stderr()).toContain('stopped (decider: write error')
      expect(code).toBe(0)
    } finally {
      p.child.kill('SIGKILL')
    }
  }, 20_000)

  // Each form runs twice. Pinned to one CPU, reads of descriptors that sit
  // idle (the lifeline, the decider between frames) must not starve the
  // writes to the decider: Bun sizes its thread pool by CPUs. Pinning needs
  // Linux and taskset; elsewhere those cases show as skipped, and the
  // unpinned ones do not cover the starvation. A handed listening socket
  // needs a runtime that serves emitted connections; elsewhere all four
  // show as skipped.
  for (const pin of [false, true]) {
    test.skipIf(!SERVES_EMITTED_CONNECTIONS || (pin && TASKSET === null)).each([
      ['on two streams', ['--decider-in', '4', '--decider-out', '5']],
      ['on one socket', ['--decider-fd', '4']],
    ])(
      `the descriptor forms${pin ? ', pinned to one CPU' : ''}: a handed listening socket, the decider %s, the CA on its own`,
      async (_form, deciderArgs) => {
        // The host's side of the handover: a listening socket it made, passed
        // as a descriptor, and closed here once the proxy has its copy.
        const listener = createServer()
        await new Promise<void>(r => listener.listen(0, '127.0.0.1', r))
        const port = (listener.address() as { port: number }).port
        const fd = (listener as unknown as { _handle: { fd: number } })._handle
          .fd
        const ca = generateCa()
        const argv = [
          process.execPath,
          ENTRY,
          '--listen-fd',
          '3',
          ...deciderArgs,
          '--lifeline-fd',
          '6',
          '--ca-fd',
          '7',
        ]
        const pinned = pin ? [TASKSET!, '-c', FIRST_CPU, ...argv] : argv
        const child = spawn(pinned[0]!, pinned.slice(1), {
          stdio: [
            'ignore',
            'ignore',
            'pipe',
            fd,
            'pipe',
            'pipe',
            'pipe',
            'pipe',
          ],
        })
        listener.close()
        let stderr = ''
        child.stderr!.on('data', d => (stderr += d))
        const exited = new Promise<number | null>(resolve =>
          child.once('exit', code => resolve(code)),
        )
        // The extra stdio entries are the parent's ends of socket pairs.
        const io = child.stdio as unknown as Socket[]
        const [toProxy, lifeline, caStream] = [io[4]!, io[6]!, io[7]!]
        const fromProxy = deciderArgs.includes('--decider-fd')
          ? toProxy
          : io[5]!
        caStream.end(ca.keyPem + ca.certPem)
        // The decider: answer the hello, then deny every request.
        const asked: Array<Record<string, unknown>> = []
        let buf = Buffer.alloc(0)
        fromProxy.on('data', (c: Buffer) => {
          buf = Buffer.concat([buf, c])
          while (buf.length >= 4 && buf.length >= 4 + buf.readUInt32BE(0)) {
            const f = JSON.parse(
              buf.subarray(4, 4 + buf.readUInt32BE(0)).toString(),
            ) as Record<string, unknown>
            buf = buf.subarray(4 + buf.readUInt32BE(0))
            if (f.t === 'hello') {
              toProxy.write(
                encodeFrame({
                  t: 'hello',
                  proto: 1,
                  allowedDomains: ['allowed.test:443'],
                  deniedDomains: [],
                }),
              )
              continue
            }
            asked.push(f)
            toProxy.write(
              encodeFrame({
                t: 'verdict',
                id: f.id as number,
                action: 'deny',
                status: 403,
                reason: 'denied by the test decider',
              }),
            )
          }
        })
        await new Promise<void>((resolve, reject) => {
          const t = setInterval(() => {
            if (stderr.includes('serving fd 3')) {
              clearInterval(t)
              resolve()
            }
          }, 20)
          void exited.then(code => {
            clearInterval(t)
            reject(new Error(`exited ${code}: ${stderr}`))
          })
        })
        // A tunnel to the allowed host, terminated with a leaf of the handed CA,
        // and a request the decider denies.
        const reply = await new Promise<string>((resolve, reject) => {
          const c = connect(port, '127.0.0.1', () =>
            c.write(
              'CONNECT allowed.test:443 HTTP/1.1\r\nHost: allowed.test:443\r\n\r\n',
            ),
          )
          c.on('error', reject)
          let head = ''
          const onData = (x: Buffer): void => {
            head += x.toString('latin1')
            if (!head.includes('\r\n\r\n')) return
            c.off('data', onData)
            const t = tlsConnect({
              socket: c,
              ca: ca.certPem,
              servername: 'allowed.test',
              ALPNProtocols: ['http/1.1'],
            })
            let out = ''
            t.on('secureConnect', () =>
              t.write(
                'GET /x HTTP/1.1\r\nHost: allowed.test\r\nConnection: close\r\n\r\n',
              ),
            )
            t.on('data', y => (out += y))
            t.on('close', () => resolve(out))
            t.on('error', reject)
          }
          c.on('data', onData)
        })
        expect(reply).toStartWith('HTTP/1.1 403')
        expect(reply).toContain('denied by the test decider')
        expect(asked).toHaveLength(1)
        expect(asked[0]).toMatchObject({
          t: 'req',
          host: 'allowed.test',
          path: '/x',
        })
        lifeline.end()
        expect(await exited).toBe(0)
        expect(stderr).toContain('lifeline closed')
      },
      20_000,
    )
  }
})

/** Whether this host can bind the IPv6 loopback address. */
const HAS_IPV6_LOOPBACK = await new Promise<boolean>(resolve => {
  const s = createServer()
  s.once('error', () => resolve(false))
  s.listen(0, '::1', () => s.close(() => resolve(true)))
})

/** Resolves with stderr once it matches `re`; rejects if the proxy exits first. */
function stderrMatching(
  p: ReturnType<typeof run>,
  re: RegExp,
): Promise<string> {
  return new Promise<string>((resolve, reject) => {
    const check = () => {
      if (re.test(p.stderr())) resolve(p.stderr())
    }
    p.child.stderr!.on('data', check)
    void p.exited.then(code =>
      re.test(p.stderr())
        ? resolve(p.stderr())
        : reject(new Error(`exited ${code}: ${p.stderr()}`)),
    )
    check()
  })
}

describe('srt-proxy --listen address', () => {
  const DECIDER = ['--decider-fd', '3']

  for (const addr of ['0.0.0.0:0', ':0', '[::]:0', '192.0.2.1:0'])
    test(`${addr} is refused without --listen-any-interface (exit 2)`, async () => {
      const p = run(['--listen', addr, ...DECIDER])
      expect(await p.exited).toBe(2)
      expect(p.stderr()).toContain('is not a loopback address')
      expect(p.stderr()).toContain('--listen-any-interface')
      expect(p.stderr()).not.toContain('serving')
    })

  test('a bare port is refused with a message about the expected form (exit 2)', async () => {
    const p = run(['--listen', '8080', ...DECIDER])
    expect(await p.exited).toBe(2)
    expect(p.stderr()).toContain('--listen needs <host:port>')
  })

  async function starts(args: string[], serving: RegExp): Promise<string> {
    const p = run([...args, ...DECIDER])
    const decider = p.child.stdio[3] as Socket
    decider.once('data', () =>
      decider.write(
        encodeFrame({
          t: 'hello',
          proto: 1,
          allowedDomains: [],
          deniedDomains: [],
        }),
      ),
    )
    try {
      return await stderrMatching(p, serving)
    } finally {
      p.child.kill('SIGKILL')
      await p.exited
    }
  }

  test('127.0.0.1:0 starts without the flag and without a warning', async () => {
    const err = await starts(
      ['--listen', '127.0.0.1:0'],
      /serving 127\.0\.0\.1:\d+/,
    )
    expect(err).not.toContain('warning')
  })

  test.skipIf(!HAS_IPV6_LOOPBACK)(
    '[::1]:0 starts without the flag',
    async () => {
      const err = await starts(['--listen', '[::1]:0'], /serving ::1:\d+/)
      expect(err).not.toContain('warning')
    },
  )

  test('0.0.0.0:0 starts with --listen-any-interface and warns that the listener is exposed', async () => {
    const err = await starts(
      ['--listen', '0.0.0.0:0', '--listen-any-interface'],
      /serving 0\.0\.0\.0:\d+/,
    )
    expect(err).toContain(
      'warning: --listen-any-interface: the listener on 0.0.0.0:0 is reachable from other hosts and is unauthenticated',
    )
  })
})
