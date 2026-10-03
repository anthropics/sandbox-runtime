import { describe, expect, test } from 'bun:test'
import { execFile } from 'node:child_process'
import { mkdtemp, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
import { loopbackListenOptions } from '../../src/sandbox/listen-in-range.js'

const run = promisify(execFile)

/**
 * gh-458: srt is a one-process-one-proxy design — the mux backend binds a
 * pid-scoped unix socket and each process mints its own proxyAuthToken. A
 * plain `listen(port, host)` breaks that: under Node's `cluster` the primary
 * intercepts listen(), shares a single handle across workers and round robins
 * connections. A sandboxed child of worker A then lands on worker B's proxy
 * carrying A's token and is answered with 407.
 *
 * The listener must therefore be exclusive. This drives a real cluster rather
 * than asserting on the shape of the call, so it fails if the flag is dropped.
 */
const WORKERS = 3

const script = (exclusive: boolean) => `
import cluster from 'node:cluster'
import net from 'node:net'
if (cluster.isPrimary) {
  const ports = new Set()
  let ready = 0
  for (let i = 0; i < ${WORKERS}; i++) cluster.fork()
  cluster.on('message', (w, m) => {
    ports.add(m.port)
    if (++ready === ${WORKERS}) {
      console.log(ports.size)
      for (const id in cluster.workers) cluster.workers[id].kill()
      process.exit(0)
    }
  })
} else {
  const srv = net.createServer()
  const done = () => process.send({ port: srv.address().port })
  ${
    exclusive
      ? "srv.listen({ port: 0, host: '127.0.0.1', exclusive: true }, done)"
      : "srv.listen(0, '127.0.0.1', done)"
  }
}
`

async function distinctPorts(exclusive: boolean): Promise<number> {
  const dir = await mkdtemp(join(tmpdir(), 'srt-cluster-'))
  const file = join(dir, 'probe.mjs')
  await writeFile(file, script(exclusive))
  const { stdout } = await run(process.execPath, [file], { timeout: 30_000 })
  return Number(stdout.trim())
}

describe('mux listener under node cluster', () => {
  test('a plain listen shares one handle across workers', async () => {
    expect(await distinctPorts(false)).toBe(1)
  }, 40_000)

  test('an exclusive listen gives every worker its own port', async () => {
    expect(await distinctPorts(true)).toBe(WORKERS)
  }, 40_000)
})

describe('loopbackListenOptions', () => {
  test('marks the listener exclusive so cluster cannot share it', () => {
    expect(loopbackListenOptions(60080)).toEqual({
      port: 60080,
      host: '127.0.0.1',
      exclusive: true,
    })
  })
})
