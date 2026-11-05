import { afterAll, beforeAll, describe, expect, it } from 'bun:test'
import { checkLinuxDependencies } from '../../src/sandbox/linux-sandbox-utils.js'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import { quote } from '../../src/utils/shell-quote.js'
import { bwrapCanNamespaceNetwork } from '../helpers/bwrap-namespace.js'
import { isLinux } from '../helpers/platform.js'
import { spawnAsync } from '../helpers/spawn.js'

/**
 * What is timed is connect(2) alone. A handshake the listener's queue has room
 * for the kernel finishes by itself, however busy the host and however slowly
 * the listener accepts. One it has no room for it drops, and the client sends
 * again after a second.
 */
const BURST = `
import os, selectors, socket, time, urllib.parse
for name in ('HTTP_PROXY', 'FTP_PROXY'):
    to = urllib.parse.urlparse(os.environ[name])
    waiting = selectors.DefaultSelector()
    began = time.monotonic()
    for _ in range(64):
        s = socket.socket()
        s.setblocking(False)
        s.connect_ex((to.hostname, to.port))
        waiting.register(s, selectors.EVENT_WRITE)
    made, late = [], 0
    while len(made) < 64 and time.monotonic() - began < 20:
        for key, _ in waiting.select(1):
            waiting.unregister(key.fileobj)
            if key.fileobj.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == 0:
                made.append(key.fileobj)
                late += time.monotonic() - began > 0.9
    print('%s made=%d late=%d' % (name, len(made), late))
    for s in made:
        s.close()
`

describe.if(isLinux)('the bridges inside the Linux sandbox', () => {
  beforeAll(async () => {
    expect(checkLinuxDependencies().errors).toEqual([])
    await SandboxManager.reset()
  })

  afterAll(async () => {
    await SandboxManager.reset()
  })

  it.skipIf(!bwrapCanNamespaceNetwork())(
    'take 64 connections made at once, each at its first try',
    async () => {
      await SandboxManager.initialize({
        network: { allowedDomains: [], deniedDomains: [] },
        filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
      })
      const r = await spawnAsync(
        await SandboxManager.wrapWithSandbox(quote(['python3', '-c', BURST])),
        { shell: true, encoding: 'utf8', timeout: 60000 },
      )
      expect(r.stdout).toBe(
        'HTTP_PROXY made=64 late=0\nFTP_PROXY made=64 late=0\n',
      )
    },
    70000,
  )
})
