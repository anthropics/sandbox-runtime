import { afterEach, beforeEach, describe, expect, it, spyOn } from 'bun:test'
import * as childProcess from 'node:child_process'
import { EventEmitter, once } from 'node:events'
import { syncBuiltinESMExports } from 'node:module'
import { PassThrough } from 'node:stream'

import {
  startMacOSSandboxLogMonitor,
  type SandboxViolationEvent,
} from '../../src/sandbox/macos-sandbox-utils.js'
import type { IgnoreViolationsConfig } from '../../src/sandbox/sandbox-config.js'
import { encodeSandboxedCommand } from '../../src/sandbox/sandbox-utils.js'

describe('macOS sandbox log monitor stream parsing', () => {
  let stdout: PassThrough
  let violations: SandboxViolationEvent[]
  let stopMonitor: (() => void) | undefined
  let spawnSpy: ReturnType<typeof spyOn>

  beforeEach(() => {
    stdout = new PassThrough()
    violations = []
    const child = Object.assign(new EventEmitter(), {
      stdout,
      stderr: new PassThrough(),
      kill: () => true,
    }) as unknown as childProcess.ChildProcess
    spawnSpy = spyOn(childProcess, 'spawn').mockReturnValue(child)
    syncBuiltinESMExports()
  })

  afterEach(() => {
    stopMonitor?.()
    spawnSpy.mockRestore()
    syncBuiltinESMExports()
  })

  const denial = (path: string): string =>
    `2026-01-01 00:00:00.000000+0000 Sandbox: sh(4242) deny(1) file-write-create ${path}`

  const commandTag = (command: string): string =>
    `CMD64_${encodeSandboxedCommand(command)}_END_test-session`

  const startMonitor = (ignore?: IgnoreViolationsConfig): void => {
    stopMonitor = startMacOSSandboxLogMonitor(
      violation => violations.push(violation),
      ignore,
      key => `resolved:${key}`,
    )
  }

  it('reports each denial and its following command from one chunk', () => {
    startMonitor()
    stdout.write(
      `${denial('/outside/one')}\n${commandTag('command one')}\n${denial('/outside/two')}\n${commandTag('command two')}\n`,
    )

    expect(
      violations.map(({ line, command, encodedCommand }) => ({
        line,
        command,
        encodedCommand,
      })),
    ).toEqual([
      {
        line: 'sh(4242) deny(1) file-write-create /outside/one',
        command: 'resolved:command one',
        encodedCommand: encodeSandboxedCommand('command one'),
      },
      {
        line: 'sh(4242) deny(1) file-write-create /outside/two',
        command: 'resolved:command two',
        encodedCommand: encodeSandboxedCommand('command two'),
      },
    ])
  })

  it('retains partial denial and command lines across chunks', () => {
    startMonitor()
    const violationLine = denial('/outside/split')
    const tag = commandTag('split command')
    stdout.write(violationLine.slice(0, 18))
    stdout.write(`${violationLine.slice(18)}\n${tag.slice(0, 9)}`)
    expect(violations).toHaveLength(0)

    stdout.write(`${tag.slice(9)}\n`)

    expect(violations).toHaveLength(1)
    expect(violations[0]).toMatchObject({
      line: 'sh(4242) deny(1) file-write-create /outside/split',
      command: 'resolved:split command',
      encodedCommand: encodeSandboxedCommand('split command'),
    })
  })

  it('does not attribute an untagged denial to the next denial command', () => {
    startMonitor()
    stdout.write(
      `${denial('/outside/untagged')}\n${denial('/outside/tagged')}\n${commandTag('tagged command')}\n`,
    )

    expect(violations.map(({ line, command }) => ({ line, command }))).toEqual([
      {
        line: 'sh(4242) deny(1) file-write-create /outside/untagged',
        command: undefined,
      },
      {
        line: 'sh(4242) deny(1) file-write-create /outside/tagged',
        command: 'resolved:tagged command',
      },
    ])
  })

  it('closes an untagged denial at the next timestamped log entry', () => {
    startMonitor()
    stdout.write(
      `${denial('/outside/untagged')}\n2026-01-01 00:00:01.000000+0000 other-process[1]: unrelated event\n${commandTag('stale command')}\n`,
    )

    expect(violations.map(({ line, command }) => ({ line, command }))).toEqual([
      {
        line: 'sh(4242) deny(1) file-write-create /outside/untagged',
        command: undefined,
      },
    ])
  })

  it('preserves UTF-8 characters split across byte chunks', () => {
    startMonitor()
    const unicodeChar = '\u00e9'
    const text = `${denial(`/outside/caf${unicodeChar}`)}\n${commandTag('unicode path')}\n`
    const bytes = Buffer.from(text)
    const splitAt = bytes.indexOf(Buffer.from(unicodeChar)) + 1

    stdout.write(bytes.subarray(0, splitAt))
    stdout.write(bytes.subarray(splitAt))

    expect(violations[0]?.line).toBe(
      `sh(4242) deny(1) file-write-create /outside/caf${unicodeChar}`,
    )
  })

  it('continues after filtering a noisy denial in a multi-entry chunk', () => {
    startMonitor()
    stdout.write(
      `${denial('/outside/mach-lookup com.apple.diagnosticd')}\n${commandTag('noisy command')}\n${denial('/outside/real')}\n${commandTag('real command')}\n`,
    )

    expect(violations.map(({ line, command }) => ({ line, command }))).toEqual([
      {
        line: 'sh(4242) deny(1) file-write-create /outside/real',
        command: 'resolved:real command',
      },
    ])
  })

  it('flushes a final command tag without requiring a trailing newline', async () => {
    startMonitor()
    const tag = commandTag('final command')
    const ended = once(stdout, 'end')
    stdout.write(`${denial('/outside/final')}\n${tag}`)
    stdout.end()
    await ended

    expect(violations).toHaveLength(1)
    expect(violations[0]).toMatchObject({
      line: 'sh(4242) deny(1) file-write-create /outside/final',
      command: 'resolved:final command',
      encodedCommand: encodeSandboxedCommand('final command'),
    })
  })

  it('flushes an untagged final denial when stdout ends', async () => {
    startMonitor()
    const ended = once(stdout, 'end')
    stdout.write(`${denial('/outside/final-untagged')}\n`)
    stdout.end()
    await ended

    expect(violations).toHaveLength(1)
    expect(violations[0]).toMatchObject({
      line: 'sh(4242) deny(1) file-write-create /outside/final-untagged',
      command: undefined,
    })
  })

  it('applies ignoreViolations to each entry in a coalesced chunk', () => {
    startMonitor({
      'ignore-me': ['file-write-create /outside/ignored'],
    })
    stdout.write(
      `${denial('/outside/ignored')}\n${commandTag('ignore-me')}\n${denial('/outside/keep')}\n${commandTag('keep-me')}\n`,
    )

    expect(violations.map(({ line, command }) => ({ line, command }))).toEqual([
      {
        line: 'sh(4242) deny(1) file-write-create /outside/keep',
        command: 'resolved:keep-me',
      },
    ])
  })
})
