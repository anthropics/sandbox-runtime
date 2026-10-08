import { afterEach, expect, spyOn, test } from 'bun:test'
import * as platform from '../../src/utils/platform.js'
import * as javaAgent from '../../src/sandbox/java-proxy-agent.js'
import * as muxProxy from '../../src/sandbox/mux-proxy.js'
import { overrideEmittedConnectionProbe } from '../../src/sandbox/emitted-connection.js'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import type { SandboxRuntimeConfig } from '../../src/sandbox/sandbox-config.js'

const cleanup: Array<() => void | Promise<void>> = []
afterEach(async () => {
  await SandboxManager.reset()
  while (cleanup.length) await cleanup.pop()!()
})

test('reset during initialization leaves no initialized proxy context', async () => {
  const platformSpy = spyOn(platform, 'getPlatform').mockReturnValue('macos')
  let release!: () => void
  let entered!: () => void
  const started = new Promise<void>(resolve => {
    entered = resolve
  })
  const gate = new Promise<void>(resolve => {
    release = resolve
  })
  const agentSpy = spyOn(
    javaAgent,
    'getJavaProxyAgentJarPathAsync',
  ).mockImplementation(async () => {
    entered()
    await gate
    return null
  })
  cleanup.push(
    () => platformSpy.mockRestore(),
    () => agentSpy.mockRestore(),
  )
  const config: SandboxRuntimeConfig = {
    network: {
      allowedDomains: [],
      deniedDomains: [],
      httpProxyPort: 32101,
      socksProxyPort: 32101,
    },
    filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
  }
  const initializing = SandboxManager.initialize(config)
  await started
  const resetting = SandboxManager.reset()
  release()
  await Promise.all([initializing, resetting])
  expect(SandboxManager.getProxyPort()).toBeUndefined()
  expect(SandboxManager.getSocksProxyPort()).toBeUndefined()
})

test('initialization waits for an in-flight reset', async () => {
  const platformSpy = spyOn(platform, 'getPlatform').mockReturnValue('macos')
  const agentSpy = spyOn(
    javaAgent,
    'getJavaProxyAgentJarPathAsync',
  ).mockResolvedValue(null)
  let release!: () => void
  let entered!: () => void
  const started = new Promise<void>(resolve => {
    entered = resolve
  })
  const gate = new Promise<void>(resolve => {
    release = resolve
  })
  const createMux = muxProxy.createMuxProxyServer
  const muxSpy = spyOn(muxProxy, 'createMuxProxyServer').mockImplementation(
    options => {
      const mux = createMux(options)
      const close = mux.close.bind(mux)
      mux.close = async () => {
        entered()
        await gate
        await close()
      }
      return mux
    },
  )
  cleanup.push(
    () => platformSpy.mockRestore(),
    () => agentSpy.mockRestore(),
    () => muxSpy.mockRestore(),
  )
  const config: SandboxRuntimeConfig = {
    network: { allowedDomains: [], deniedDomains: [] },
    filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
  }
  await SandboxManager.initialize(config)
  const resetting = SandboxManager.reset()
  await started
  const initializing = SandboxManager.initialize({
    ...config,
    network: { ...config.network, httpProxyPort: 32102, socksProxyPort: 32102 },
  })
  release()
  await Promise.all([resetting, initializing])
  expect(agentSpy).toHaveBeenCalledTimes(2)
  expect(SandboxManager.getProxyPort()).toBe(32102)
})

test('an invalid address range does not publish a rejected config', async () => {
  const previousConfig = SandboxManager.getConfig()
  const previouslyEnabled = SandboxManager.isSandboxingEnabled()
  const invalid: SandboxRuntimeConfig = {
    network: {
      allowedDomains: [],
      deniedDomains: [],
      deniedResolvedAddresses: ['not-an-address'],
    },
    filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
  }
  const [result] = await Promise.allSettled([
    SandboxManager.initialize(invalid),
  ])
  expect(result?.status).toBe('rejected')
  expect(SandboxManager.getConfig()).toEqual(previousConfig)
  expect(SandboxManager.isSandboxingEnabled()).toBe(previouslyEnabled)
})

test('missing CA files do not publish a rejected config', async () => {
  const previousConfig = SandboxManager.getConfig()
  const previouslyEnabled = SandboxManager.isSandboxingEnabled()
  const platformSpy = spyOn(platform, 'getPlatform').mockReturnValue('macos')
  overrideEmittedConnectionProbe(() => true)
  cleanup.push(
    () => platformSpy.mockRestore(),
    () => overrideEmittedConnectionProbe(undefined),
  )
  const invalid: SandboxRuntimeConfig = {
    network: {
      allowedDomains: [],
      deniedDomains: [],
      tlsTerminate: {
        caCertPath: '__srt_test_missing_ca__.crt',
        caKeyPath: '__srt_test_missing_ca__.key',
      },
    },
    filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
  }
  const [result] = await Promise.allSettled([
    SandboxManager.initialize(invalid),
  ])
  expect(result?.status).toBe('rejected')
  expect(SandboxManager.getConfig()).toEqual(previousConfig)
  expect(SandboxManager.isSandboxingEnabled()).toBe(previouslyEnabled)
})

test('concurrent initialization keeps the first config and starts infrastructure once', async () => {
  // External proxy ports avoid opening listeners; the mocked macOS dependency
  // check and Java lookup avoid provisioning or launching any host processes.
  const platformSpy = spyOn(platform, 'getPlatform').mockReturnValue('macos')
  const agentSpy = spyOn(
    javaAgent,
    'getJavaProxyAgentJarPathAsync',
  ).mockResolvedValue(null)
  cleanup.push(
    () => platformSpy.mockRestore(),
    () => agentSpy.mockRestore(),
  )
  const config = (port: number): SandboxRuntimeConfig => ({
    network: {
      allowedDomains: [],
      deniedDomains: [],
      httpProxyPort: port,
      socksProxyPort: port,
    },
    filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
  })
  await Promise.all([
    SandboxManager.initialize(config(32101)),
    SandboxManager.initialize(config(32102)),
  ])
  expect(agentSpy).toHaveBeenCalledTimes(1)
  expect(SandboxManager.getProxyPort()).toBe(32101)
  expect(SandboxManager.getConfig()?.network.httpProxyPort).toBe(32101)
})

test('a rejected initialization attempt can be retried', async () => {
  const platformSpy = spyOn(platform, 'getPlatform').mockReturnValue('macos')
  const agentSpy = spyOn(javaAgent, 'getJavaProxyAgentJarPathAsync')
    .mockRejectedValueOnce(new Error('synthetic startup failure'))
    .mockResolvedValue(null)
  cleanup.push(
    () => platformSpy.mockRestore(),
    () => agentSpy.mockRestore(),
  )
  const config: SandboxRuntimeConfig = {
    network: {
      allowedDomains: [],
      deniedDomains: [],
      httpProxyPort: 32101,
      socksProxyPort: 32101,
    },
    filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
  }
  const results = await Promise.allSettled([
    SandboxManager.initialize(config),
    SandboxManager.initialize(config),
  ])
  expect(results.map(result => result.status)).toEqual(['rejected', 'rejected'])
  expect(agentSpy).toHaveBeenCalledTimes(1)
  await SandboxManager.initialize(config)
  expect(agentSpy).toHaveBeenCalledTimes(2)
  expect(SandboxManager.getProxyPort()).toBe(32101)
})

test('concurrent initialization creates only one local proxy', async () => {
  const platformSpy = spyOn(platform, 'getPlatform').mockReturnValue('macos')
  const agentSpy = spyOn(
    javaAgent,
    'getJavaProxyAgentJarPathAsync',
  ).mockResolvedValue(null)
  const muxSpy = spyOn(muxProxy, 'createMuxProxyServer')
  cleanup.push(
    () => platformSpy.mockRestore(),
    () => agentSpy.mockRestore(),
    () => muxSpy.mockRestore(),
  )
  const config: SandboxRuntimeConfig = {
    network: { allowedDomains: [], deniedDomains: [] },
    filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
  }
  await Promise.all([
    SandboxManager.initialize(config),
    SandboxManager.initialize(config),
  ])
  expect(muxSpy).toHaveBeenCalledTimes(1)
  expect(SandboxManager.getProxyPort()).toBeNumber()
  await SandboxManager.reset()
  expect(SandboxManager.getProxyPort()).toBeUndefined()
})

test('startup failure waits for proxy cleanup before allowing a retry', async () => {
  const platformSpy = spyOn(platform, 'getPlatform').mockReturnValue('macos')
  const agentSpy = spyOn(javaAgent, 'getJavaProxyAgentJarPathAsync')
    .mockRejectedValueOnce(new Error('synthetic startup failure'))
    .mockResolvedValue(null)
  const createMux = muxProxy.createMuxProxyServer
  let cleanupFinished = false
  const muxSpy = spyOn(muxProxy, 'createMuxProxyServer').mockImplementation(
    options => {
      const mux = createMux(options)
      const close = mux.close.bind(mux)
      mux.close = async () => {
        await close()
        await new Promise(resolve => setTimeout(resolve, 25))
        cleanupFinished = true
      }
      return mux
    },
  )
  cleanup.push(
    () => platformSpy.mockRestore(),
    () => agentSpy.mockRestore(),
    () => muxSpy.mockRestore(),
  )
  const config: SandboxRuntimeConfig = {
    network: { allowedDomains: [], deniedDomains: [] },
    filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
  }
  const [result] = await Promise.allSettled([SandboxManager.initialize(config)])
  expect(result?.status).toBe('rejected')
  expect(cleanupFinished).toBe(true)
  expect(SandboxManager.getProxyPort()).toBeUndefined()
  await SandboxManager.initialize(config)
  expect(SandboxManager.getProxyPort()).toBeNumber()
})
