import { describe, expect, test } from 'bun:test'
import { spawn } from 'node:child_process'
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { createServer } from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { quote } from '../src/utils/shell-quote.js'
import { bwrapCanNamespace } from './helpers/bwrap-namespace.js'
import { isLinux } from './helpers/platform.js'

async function waitFor(
  check: () => boolean,
  timeout: number,
): Promise<boolean> {
  const deadline = Date.now() + timeout
  while (!check()) {
    if (Date.now() >= deadline) return false
    await new Promise(resolve => setTimeout(resolve, 20))
  }
  return true
}

interface ProcessIdentity {
  name: string
  parent: number
  start: string
  state: string
}

function processIdentity(pid: number): ProcessIdentity | undefined {
  try {
    const value = readFileSync(`/proc/${pid}/stat`, 'utf8')
    const fields = value.slice(value.lastIndexOf(')') + 2).split(' ')
    return {
      name: value.slice(value.indexOf('(') + 1, value.lastIndexOf(')')),
      parent: Number(fields[1]),
      start: fields[19]!,
      state: fields[0]!,
    }
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code
    if (code === 'ENOENT' || code === 'ESRCH') return undefined
    throw error
  }
}

function descendants(pid: number): Map<number, ProcessIdentity> {
  const table = new Map<number, ProcessIdentity>()
  for (const name of readdirSync('/proc')) {
    if (!/^\d+$/.test(name)) continue
    const row = processIdentity(Number(name))
    if (row) table.set(Number(name), row)
  }
  const owned = new Map<number, ProcessIdentity>()
  const root = table.get(pid)
  if (root) owned.set(pid, root)
  let previous: number
  do {
    previous = owned.size
    for (const [child, row] of table) {
      if (owned.has(row.parent)) owned.set(child, row)
    }
  } while (owned.size !== previous)
  return owned
}

function running(owned: Map<number, ProcessIdentity>): number[] {
  return [...owned].flatMap(([pid, row]) => {
    const current = processIdentity(pid)
    return current?.start === row.start && current.state !== 'Z' ? [pid] : []
  })
}

function socketFiles(dir: string): string[] {
  return readdirSync(dir).filter(name => {
    try {
      return lstatSync(join(dir, name)).isSocket()
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false
      throw error
    }
  })
}

describe.skipIf(!isLinux || !bwrapCanNamespace())(
  'Linux CLI socket ownership after SIGKILL',
  () => {
    for (const external of [false, true]) {
      test(`removes socket files and bridge processes with ${external ? 'separate external proxies' : 'the internal mux'}`, async () => {
        const root = mkdtempSync(join(tmpdir(), 'srt-kill-'))
        const sockets = join(root, 'sockets')
        mkdirSync(sockets)
        const upstream = createServer((_req, res) => res.write('PROXY-READY'))
        const other = createServer((_req, res) => res.end('unused'))
        await new Promise<void>(resolve =>
          upstream.listen(0, '127.0.0.1', resolve),
        )
        await new Promise<void>(resolve =>
          other.listen(0, '127.0.0.1', resolve),
        )
        const upstreamAddress = upstream.address()
        const otherAddress = other.address()
        if (!upstreamAddress || typeof upstreamAddress === 'string') {
          throw new Error('Missing upstream TCP address')
        }
        if (!otherAddress || typeof otherAddress === 'string') {
          throw new Error('Missing second TCP address')
        }
        const settings = join(root, 'settings.json')
        const socat = join(root, 'socat')
        writeFileSync(
          socat,
          '#!/bin/sh\ncase "$1" in\n' +
            'UNIX-LISTEN:*) exec socat "$1,unlink-close=0" "$2" ;;\n' +
            '*) exec socat "$@" ;;\nesac\n',
          { mode: 0o755 },
        )
        writeFileSync(
          settings,
          JSON.stringify({
            filesystem: { denyRead: [], allowWrite: [root], denyWrite: [] },
            network: {
              allowedDomains: ['127.0.0.1'],
              deniedDomains: [],
              allowAllUnixSockets: true,
              ...(external
                ? {
                    httpProxyPort: upstreamAddress.port,
                    socksProxyPort: otherAddress.port,
                  }
                : {}),
            },
            enableWeakerNestedSandbox: true,
            socatPath: socat,
          }),
        )
        let cleanupError: unknown
        try {
          for (let trial = 0; trial < 2; trial++) {
            const marker = join(root, `ready-${trial}`)
            const worker = join(root, `worker-${trial}.py`)
            writeFileSync(
              worker,
              'import base64, http.client, os, sys, time, urllib.parse\n' +
                'p = urllib.parse.urlsplit(os.environ["HTTP_PROXY"])\n' +
                'c = http.client.HTTPConnection(p.hostname, p.port, timeout=5)\n' +
                'auth = urllib.parse.unquote(p.username or "") + ":" + urllib.parse.unquote(p.password or "")\n' +
                'c.request("GET", "http://127.0.0.1:" + sys.argv[2] + "/", headers={"Proxy-Authorization": "Basic " + base64.b64encode(auth.encode()).decode()})\n' +
                'response = c.getresponse()\n' +
                'assert response.read(len(b"PROXY-READY")) == b"PROXY-READY"\n' +
                'with open(sys.argv[1], "w") as f: f.write("started")\ntime.sleep(30)\n',
            )
            const child = spawn(
              'bun',
              [
                'run',
                join(process.cwd(), 'src', 'cli.ts'),
                '-s',
                settings,
                '-c',
                quote([
                  'python3',
                  worker,
                  marker,
                  String(upstreamAddress.port),
                ]),
              ],
              {
                env: { ...process.env, TMPDIR: sockets },
                detached: true,
                stdio: ['ignore', 'pipe', 'pipe'],
              },
            )
            let stderr = ''
            let exited = false
            let owned = new Map<number, ProcessIdentity>()
            child.stdout.resume()
            child.stderr.on(
              'data',
              (chunk: Buffer) => (stderr += String(chunk)),
            )
            const finished = new Promise<void>((resolve, reject) => {
              child.once('exit', () => {
                exited = true
                resolve()
              })
              child.once('error', reject)
            })
            try {
              const started = await waitFor(
                () =>
                  exited ||
                  (existsSync(marker) &&
                    readFileSync(marker, 'utf8') === 'started'),
                15_000,
              )
              if (!started || exited)
                throw new Error(`Proxy control never started: ${stderr}`)
              expect(readFileSync(marker, 'utf8')).toBe('started')
              expect(
                await new Promise<number>((resolve, reject) =>
                  upstream.getConnections((error, count) =>
                    error ? reject(error) : resolve(count),
                  ),
                ),
              ).toBeGreaterThan(0)
              expect(socketFiles(sockets).length).toBeGreaterThan(0)
              owned = descendants(child.pid!)
              expect(owned.size).toBeGreaterThan(1)
              expect(child.kill('SIGKILL')).toBe(true)
              await waitFor(
                () =>
                  exited &&
                  socketFiles(sockets).length === 0 &&
                  running(owned).length === 0,
                3_000,
              )
              expect({
                exited,
                sockets: socketFiles(sockets),
                processes: running(owned).map(pid => ({
                  pid,
                  ...processIdentity(pid),
                })),
              }).toEqual({ exited: true, sockets: [], processes: [] })
            } finally {
              if (!owned.size && child.pid) owned = descendants(child.pid)
              for (const pid of running(owned)) {
                try {
                  process.kill(pid, 'SIGKILL')
                } catch (error) {
                  if ((error as NodeJS.ErrnoException).code !== 'ESRCH')
                    cleanupError = error
                }
              }
              await finished
            }
          }
        } finally {
          upstream.closeAllConnections()
          other.closeAllConnections()
          await new Promise<void>(resolve => upstream.close(() => resolve()))
          await new Promise<void>(resolve => other.close(() => resolve()))
          rmSync(root, { recursive: true, force: true })
        }
        expect(cleanupError).toBeUndefined()
      }, 45_000)
    }
  },
)
