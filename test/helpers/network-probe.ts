import { randomUUID } from 'node:crypto'
import { createSocket } from 'node:dgram'
import { createServer } from 'node:http'
import type { Socket } from 'node:net'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import { spawnAsync, type RunResult } from './spawn.js'

export async function runNetworkProbe(
  command: string,
  sandboxed: boolean,
): Promise<RunResult & { status: number; signal: null }> {
  const id = randomUUID()
  const started = `NETWORK_PROBE_STARTED_${id}`
  const completed = `NETWORK_PROBE_COMPLETED_${id}`
  const probe =
    `printf '%s\\n' '${started}'; ${command}; ` +
    `result=$?; printf '\\n%s:%s\\n' '${completed}' "$result"; exit "$result"`
  const wrapped = sandboxed
    ? await SandboxManager.wrapWithSandbox(probe)
    : probe
  const result = await spawnAsync(wrapped, {
    shell: true,
    timeout: 5000,
    env: {
      ...process.env,
      HTTP_PROXY: '',
      HTTPS_PROXY: '',
      ALL_PROXY: '',
      http_proxy: '',
      https_proxy: '',
      all_proxy: '',
      NO_PROXY: '',
      no_proxy: '',
    },
  })
  if (
    result.signal !== null ||
    result.status === null ||
    !result.stdout.includes(started) ||
    !result.stdout.includes(`${completed}:${result.status}`)
  ) {
    throw new Error(
      `Network probe did not complete its client command: ${JSON.stringify(result)}`,
    )
  }
  return { ...result, status: result.status, signal: result.signal }
}

type HttpTarget = {
  url: string
  httpsUrl: string
  body: string
  connections: () => number
}

export async function withHttpTarget(
  test: (target: HttpTarget) => Promise<void>,
): Promise<void> {
  const body = `NETWORK_FIXTURE_${randomUUID()}`
  const sockets = new Set<Socket>()
  let connections = 0
  const server = createServer((_request, response) => response.end(body))
  server.on('connection', socket => {
    connections++
    sockets.add(socket)
    socket.on('error', () => {})
    socket.once('close', () => sockets.delete(socket))
  })
  try {
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject)
      server.listen(0, '127.0.0.1', resolve)
    })
    const address = server.address()
    if (address === null || typeof address === 'string') {
      throw new Error('Network fixture has no listening port')
    }
    await test({
      url: `http://127.0.0.1:${address.port}/`,
      httpsUrl: `https://127.0.0.1:${address.port}/`,
      body,
      connections: () => connections,
    })
  } finally {
    for (const socket of sockets) socket.destroy()
    await new Promise<void>(resolve => server.close(() => resolve()))
  }
}

export async function withDnsTarget(
  test: (target: { command: string; queries: () => number }) => Promise<void>,
): Promise<void> {
  let queries = 0
  const server = createSocket('udp4', (query, sender) => {
    if (query.length < 12) throw new Error('DNS fixture received a short query')
    queries++
    const response = Buffer.from(query)
    // RFC1035: a response with RCODE=5 is a received REFUSED verdict,
    // distinct from the connection refusal/timeout expected inside the sandbox.
    response.writeUInt16BE(0x8185, 2)
    server.send(response, sender.port, sender.address)
  })
  try {
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject)
      server.bind(0, '127.0.0.1', resolve)
    })
    const { port } = server.address()
    const client =
      'const { Resolver } = require("node:dns").promises;' +
      'const resolver = new Resolver({ timeout: 500, tries: 1 });' +
      'resolver.setServers(["127.0.0.1:" + process.argv[1]]);' +
      'resolver.resolve4("probe.example").then(' +
      '() => { process.exitCode = 2; },' +
      'error => { console.log("DNS_CODE:" + error.code);' +
      'process.exitCode = error.code === "EREFUSED" ? 0 : 1; });'
    await test({
      command: `node -e '${client}' ${port}`,
      queries: () => queries,
    })
  } finally {
    await new Promise<void>(resolve => server.close(resolve))
  }
}
