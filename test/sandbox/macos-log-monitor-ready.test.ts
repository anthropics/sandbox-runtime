import { afterEach, describe, expect, it, spyOn } from 'bun:test'
import * as macosSandboxUtils from '../../src/sandbox/macos-sandbox-utils.js'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import { isMacOS } from '../helpers/platform.js'

const onMacOS = isMacOS ? describe : describe.skip

afterEach(async () => {
  await SandboxManager.reset()
})

const initWithLogMonitor = (): Promise<void> =>
  SandboxManager.initialize(
    {
      network: { allowedDomains: [], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    },
    undefined,
    true,
  )

onMacOS('initialize() waits for the macOS log monitor to be reading', () => {
  it('does not resolve before the monitor is ready', async () => {
    let makeReady!: () => void
    const ready = new Promise<void>(resolve => {
      makeReady = resolve
    })
    const spy = spyOn(
      macosSandboxUtils,
      'startMacOSSandboxLogMonitor',
    ).mockImplementation(() => Object.assign(() => {}, { ready }))
    try {
      let settled = false
      const init = initWithLogMonitor().then(() => {
        settled = true
      })
      await new Promise(resolve => setTimeout(resolve, 1000))
      expect(settled).toBe(false)
      makeReady()
      await init
      expect(settled).toBe(true)
    } finally {
      spy.mockRestore()
    }
  })

  it('rejects and stops the monitor when it exits before it is reading', async () => {
    let stopped = 0
    const spy = spyOn(
      macosSandboxUtils,
      'startMacOSSandboxLogMonitor',
    ).mockImplementation(() =>
      Object.assign(
        () => {
          stopped++
        },
        { ready: Promise.reject(new Error('log stream exited with code 1')) },
      ),
    )
    try {
      await expect(initWithLogMonitor()).rejects.toThrow(
        /log monitor did not start: log stream exited with code 1/,
      )
      expect(stopped).toBe(1)
    } finally {
      spy.mockRestore()
    }
  })

  it('rejects when the monitor is not reading within the bound', async () => {
    let stopped = 0
    const spy = spyOn(
      macosSandboxUtils,
      'startMacOSSandboxLogMonitor',
    ).mockImplementation(() =>
      Object.assign(
        () => {
          stopped++
        },
        { ready: new Promise<void>(() => {}) },
      ),
    )
    try {
      await expect(initWithLogMonitor()).rejects.toThrow(
        /did not start reading within 2000 ms/,
      )
      expect(stopped).toBe(1)
    } finally {
      spy.mockRestore()
    }
  }, 10_000)

  it('a real log stream becomes ready', async () => {
    const stop = macosSandboxUtils.startMacOSSandboxLogMonitor(
      () => {},
      undefined,
      key => key,
    )
    try {
      await stop.ready
    } finally {
      stop()
    }
  })
})
