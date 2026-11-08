import { expect, it, mock, spyOn } from 'bun:test'
import * as childProcess from 'child_process'
import { EventEmitter } from 'events'
import { startMacOSSandboxLogMonitor } from '../../src/sandbox/macos-sandbox-utils.js'

function startMonitor() {
  const child = Object.assign(new EventEmitter(), {
    pid: 123 as number | undefined,
    exitCode: null as number | null,
    signalCode: null,
    kill: mock((signal: NodeJS.Signals) => Boolean(signal)),
  })
  const spawn = spyOn(childProcess, 'spawn').mockReturnValue(
    child as unknown as childProcess.ChildProcess,
  )
  try {
    const stop = startMacOSSandboxLogMonitor(
      () => {},
      undefined,
      key => key,
    )
    return { child, stop }
  } finally {
    spawn.mockRestore()
  }
}

it('waits for the monitor streams to close and shares pending shutdown', async () => {
  const { child, stop } = startMonitor()
  const stopped = stop()
  expect(stopped).toBeInstanceOf(Promise)
  expect(stop()).toBe(stopped)
  expect(child.kill.mock.calls).toEqual([['SIGTERM']])

  let settled = false
  const observed = Promise.resolve(stopped).then(() => {
    settled = true
  })
  child.exitCode = 0
  child.emit('exit', 0)
  await Promise.resolve()
  expect(settled).toBe(false)
  child.emit('close', 0)
  await observed
  expect(settled).toBe(true)
})

it('does not signal a monitor whose streams already closed', async () => {
  const { child, stop } = startMonitor()
  child.emit('close', 0)
  await stop()
  expect(child.kill).not.toHaveBeenCalled()
})

it('waits for close after a failed spawn without sending a signal', async () => {
  const { child, stop } = startMonitor()
  child.pid = undefined
  child.emit('error', new Error('spawn failed'))
  const stopped = stop()
  child.emit('close', -1)
  await stopped
  expect(child.kill).not.toHaveBeenCalled()
})

it('escalates to SIGKILL if the monitor does not exit after SIGTERM', async () => {
  const { child, stop } = startMonitor()
  const stopped = stop()
  try {
    await new Promise<void>(resolve => setTimeout(resolve, 1100))
    expect(child.kill.mock.calls).toEqual([['SIGTERM'], ['SIGKILL']])
  } finally {
    child.emit('close', null, 'SIGKILL')
  }
  await stopped
})
