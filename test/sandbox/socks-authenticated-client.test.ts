import { spawn } from 'node:child_process'
import { createServer, type Server } from 'node:net'
import { once } from 'node:events'
import { afterEach, describe, expect, it } from 'bun:test'
import { createSocksProxyServer } from '../../src/sandbox/socks-proxy.js'
import { isMacOS } from '../helpers/platform.js'

describe.if(isMacOS)('authenticated SOCKS5 ProxyCommand client', () => {
  let proxyTcp: Server | undefined
  let targetTcp: Server | undefined
  let wrapper: ReturnType<typeof createSocksProxyServer> | undefined

  afterEach(async () => {
    await wrapper?.close()
    proxyTcp?.close()
    targetTcp?.close()
    wrapper = undefined
    proxyTcp = undefined
    targetTcp = undefined
  })

  async function listen(server: Server): Promise<number> {
    server.listen(0, '127.0.0.1')
    await once(server, 'listening')
    return (server.address() as { port: number }).port
  }

  async function start(): Promise<{ proxyPort: number; targetPort: number }> {
    targetTcp = createServer(socket => {
      socket.on('data', data => socket.write(data))
    })
    const targetPort = await listen(targetTcp)

    wrapper = createSocksProxyServer({
      proxyAuthToken: 'tok-123',
      filter: () => true,
    })
    proxyTcp = createServer(socket => wrapper!.handleConnection(socket))
    const proxyPort = await listen(proxyTcp)
    return { proxyPort, targetPort }
  }

  it('authenticates and pipes bytes to the requested destination', async () => {
    const { proxyPort, targetPort } = await start()
    const helper = new URL(
      '../../src/sandbox/socks5-proxy-command.ts',
      import.meta.url,
    )
    const child = spawn(process.execPath, [
      helper.pathname,
      String(proxyPort),
      'srt.command',
      'tok-123',
      '127.0.0.1',
      String(targetPort),
    ])
    const output: Buffer[] = []
    child.stdout.on('data', chunk => output.push(chunk))
    child.stdin.write('round-trip')

    await new Promise<void>((resolve, reject) => {
      child.stdout.on('data', () => {
        child.kill()
        resolve()
      })
      child.once('error', reject)
    })

    expect(Buffer.concat(output).toString()).toBe('round-trip')
  })

  it('rejects an invalid token without contacting the destination', async () => {
    const { proxyPort, targetPort } = await start()
    let contacted = false
    targetTcp!.close()
    targetTcp = createServer(() => {
      contacted = true
    })
    const replacementTargetPort = await listen(targetTcp)
    const helper = new URL(
      '../../src/sandbox/socks5-proxy-command.ts',
      import.meta.url,
    )
    const child = spawn(process.execPath, [
      helper.pathname,
      String(proxyPort),
      'srt.command',
      'wrong-token',
      '127.0.0.1',
      String(replacementTargetPort || targetPort),
    ])
    const exitCode = await once(child, 'close')

    expect(exitCode[0]).not.toBe(0)
    expect(contacted).toBe(false)
  })
})
