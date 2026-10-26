import { afterEach, beforeEach, describe, expect, it } from 'bun:test'
import { spawnSync } from 'node:child_process'
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { initializeLinuxNetworkBridge } from '../../src/sandbox/linux-sandbox-utils.js'
import { quote } from '../../src/utils/shell-quote.js'
import { isLinux } from '../helpers/platform.js'

const socat = spawnSync('which', ['socat'], { encoding: 'utf8' }).stdout?.trim()

describe.if(isLinux && Boolean(socat))('Linux bridge startup deadline', () => {
  let dir: string

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'bridge-startup-'))
  })

  afterEach(() => {
    for (const side of ['http', 'socks']) {
      const pidFile = join(dir, `${side}.pid`)
      if (!existsSync(pidFile)) continue
      try {
        process.kill(Number(readFileSync(pidFile, 'utf8')), 'SIGTERM')
      } catch {
        // The timeout path already terminates the bridges.
      }
      rmSync(readFileSync(join(dir, `${side}.socket`), 'utf8').trim(), {
        force: true,
      })
    }
    rmSync(dir, { recursive: true, force: true })
  })

  function standIn(delayed: string, stalled = false): string {
    const script = join(dir, 'socat')
    writeFileSync(
      script,
      '#!/bin/sh\n' +
        'case "$1" in *claude-http-*) side=http ;; *) side=socks ;; esac\n' +
        `echo $$ > ${quote([dir])}/"$side.pid"\n` +
        'socket=${1#UNIX-LISTEN:}\n' +
        `printf '%s\\n' "\${socket%%,*}" > ${quote([dir])}/"$side.socket"\n` +
        (stalled
          ? 'exec sleep 30\n'
          : `case "$side" in ${delayed === 'both' ? '*' : delayed}) sleep 0.9 ;; esac\nexec ${quote([socat!])} "$@"\n`),
      { mode: 0o755 },
    )
    return script
  }

  for (const delayed of ['http', 'socks', 'both']) {
    it(`waits for delayed ${delayed} sockets before returning`, async () => {
      const shared = delayed === 'both'
      const bridge = await initializeLinuxNetworkBridge(
        0,
        shared ? 0 : 1,
        standIn(delayed),
      )
      expect(statSync(bridge.httpSocketPath).isSocket()).toBe(true)
      expect(statSync(bridge.socksSocketPath).isSocket()).toBe(true)
      expect(bridge.httpBridgeProcess.killed).toBe(false)
      expect(bridge.socksBridgeProcess.killed).toBe(false)
      expect(bridge.httpBridgeProcess === bridge.socksBridgeProcess).toBe(
        shared,
      )
    }, 15000)
  }

  it('times out and terminates both bridges when sockets never appear', async () => {
    const started = performance.now()
    // eslint-disable-next-line @typescript-eslint/await-thenable
    await expect(
      initializeLinuxNetworkBridge(0, 1, standIn('both', true)),
    ).rejects.toThrow('Failed to create bridge sockets')
    const elapsed = performance.now() - started
    expect(elapsed).toBeGreaterThanOrEqual(5000)
    expect(elapsed).toBeLessThan(10000)

    for (const side of ['http', 'socks']) {
      const pid = Number(readFileSync(join(dir, `${side}.pid`), 'utf8'))
      let alive = true
      const deadline = performance.now() + 1000
      while (alive && performance.now() < deadline) {
        try {
          process.kill(pid, 0)
          await new Promise(resolve => setTimeout(resolve, 10))
        } catch {
          alive = false
        }
      }
      expect(alive).toBe(false)
    }
  }, 15000)
})
