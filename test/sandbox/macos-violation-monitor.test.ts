import { afterEach, describe, expect, it } from 'bun:test'
import {
  chmodSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { delimiter, join } from 'node:path'

import {
  startMacOSSandboxLogMonitor,
  type SandboxViolationEvent,
} from '../../src/sandbox/macos-sandbox-utils.js'
import { isWindows } from '../helpers/platform.js'

const d = isWindows ? describe.skip : describe
const cleanups: Array<() => void> = []

afterEach(() => {
  while (cleanups.length > 0) {
    cleanups.pop()?.()
  }
})

function violationRecord(details: string, command?: string): string {
  const tag =
    command === undefined
      ? ''
      : `\nCMD64_${Buffer.from(command).toString('base64')}_END_fixture_SBX`
  return `${JSON.stringify({
    eventMessage: `kernel Sandbox: ${details}${tag}`,
  })}\n`
}

function compactViolationRecord(details: string, command?: string): string {
  const tag =
    command === undefined
      ? ''
      : `\nCMD64_${Buffer.from(command).toString('base64')}_END_fixture_SBX`
  return `2026-09-06 kernel Sandbox: ${details}${tag}\n`
}

function startFixture(
  chunks: Buffer[],
  callback: (event: SandboxViolationEvent) => void,
  options: {
    compactChunks?: Buffer[]
    ignoreViolations?: Record<string, string[]>
    resolveCommandText?: (decodedId: string) => string
    chunkDelayMs?: number
  } = {},
): { argsPath: string; stop: () => void; waitForExit: () => Promise<void> } {
  const fixtureDir = mkdtempSync(join(tmpdir(), 'srt-log-fixture-'))
  const logPath = join(fixtureDir, 'log')
  const argsPath = join(fixtureDir, 'args.json')
  const pidPath = join(fixtureDir, 'pid')
  const encodedChunksByStyle = {
    compact: (options.compactChunks ?? chunks).map(chunk =>
      chunk.toString('base64'),
    ),
    ndjson: chunks.map(chunk => chunk.toString('base64')),
  }
  const fixtureSource = `#!/usr/bin/env node
const fs = require('node:fs')
fs.writeFileSync(process.env.SRT_TEST_LOG_ARGS, JSON.stringify(process.argv.slice(2)))
fs.writeFileSync(process.env.SRT_TEST_LOG_PID, String(process.pid))
const chunksByStyle = ${JSON.stringify(encodedChunksByStyle)}
const styleIndex = process.argv.indexOf('--style')
const style = styleIndex === -1 ? 'compact' : process.argv[styleIndex + 1]
const chunks = chunksByStyle[style] ?? []
;(async () => {
  for (const chunk of chunks) {
    process.stdout.write(Buffer.from(chunk, 'base64'))
    await new Promise(resolve => setTimeout(resolve, ${options.chunkDelayMs ?? 10}))
  }
})()
`
  writeFileSync(logPath, fixtureSource)
  chmodSync(logPath, 0o755)

  const previousPath = process.env.PATH
  const previousArgsPath = process.env.SRT_TEST_LOG_ARGS
  const previousPidPath = process.env.SRT_TEST_LOG_PID
  process.env.PATH = `${fixtureDir}${delimiter}${previousPath ?? ''}`
  process.env.SRT_TEST_LOG_ARGS = argsPath
  process.env.SRT_TEST_LOG_PID = pidPath
  const stopMonitor = startMacOSSandboxLogMonitor(
    callback,
    options.ignoreViolations,
    options.resolveCommandText,
  )
  process.env.PATH = previousPath
  if (previousArgsPath === undefined) {
    delete process.env.SRT_TEST_LOG_ARGS
  } else {
    process.env.SRT_TEST_LOG_ARGS = previousArgsPath
  }
  if (previousPidPath === undefined) {
    delete process.env.SRT_TEST_LOG_PID
  } else {
    process.env.SRT_TEST_LOG_PID = previousPidPath
  }

  let stopped = false
  const stop = () => {
    if (stopped) return
    stopped = true
    stopMonitor()
  }
  cleanups.push(() => {
    stop()
    rmSync(fixtureDir, { recursive: true, force: true })
  })
  const waitForExit = async () => {
    await waitFor(() => existsSync(pidPath), 'expected fixture process id')
    const pid = Number(readFileSync(pidPath, 'utf8'))
    await waitFor(() => {
      try {
        process.kill(pid, 0)
        return false
      } catch {
        return true
      }
    }, 'expected fixture process to exit')
  }
  return { argsPath, stop, waitForExit }
}

async function waitFor(
  predicate: () => boolean,
  message: string,
  timeoutMs = 1500,
): Promise<void> {
  const deadline = Date.now() + timeoutMs
  while (!predicate()) {
    if (Date.now() >= deadline) {
      throw new Error(message)
    }
    await Bun.sleep(10)
  }
}

d('macOS sandbox violation monitor stream framing', () => {
  it('reports every coalesced record with its own command attribution', async () => {
    const events: SandboxViolationEvent[] = []
    const chunk = Buffer.from(
      violationRecord('first deny file-read-data /tmp/a', 'cmd-a') +
        violationRecord('second deny file-read-data /tmp/b', 'cmd-b'),
    )
    const compactChunk = Buffer.from(
      compactViolationRecord('first deny file-read-data /tmp/a', 'cmd-a') +
        compactViolationRecord('second deny file-read-data /tmp/b', 'cmd-b'),
    )

    startFixture([chunk], event => events.push(event), {
      compactChunks: [compactChunk],
    })
    await waitFor(() => events.length >= 2, 'expected two violation events')

    expect(events.map(({ line, command }) => ({ line, command }))).toEqual([
      { line: 'first deny file-read-data /tmp/a', command: 'cmd-a' },
      { line: 'second deny file-read-data /tmp/b', command: 'cmd-b' },
    ])
  })

  it('waits for all chunks of one NDJSON record', async () => {
    const events: SandboxViolationEvent[] = []
    const record = Buffer.from(
      violationRecord('deny file-read-data /tmp/split', 'split-command'),
    )
    const compactRecord = Buffer.from(
      compactViolationRecord('deny file-read-data /tmp/split', 'split-command'),
    )
    const compactSplitAt = compactRecord.indexOf(Buffer.from('\nCMD64_'))

    startFixture(
      [record.subarray(0, 17), record.subarray(17, 41), record.subarray(41)],
      event => events.push(event),
      {
        compactChunks: [
          compactRecord.subarray(0, compactSplitAt),
          compactRecord.subarray(compactSplitAt),
        ],
      },
    )
    await waitFor(() => events.length > 0, 'expected a violation event')

    expect(events).toHaveLength(1)
    expect(events[0]).toMatchObject({
      line: 'deny file-read-data /tmp/split',
      command: 'split-command',
    })
  })

  it('preserves a multibyte path split across chunks', async () => {
    const events: SandboxViolationEvent[] = []
    const record = Buffer.from(
      violationRecord('deny file-read-data /tmp/中文.txt', 'unicode-command'),
    )
    const splitAt = record.indexOf(Buffer.from('中')) + 1
    const compactRecord = Buffer.from(
      compactViolationRecord(
        'deny file-read-data /tmp/中文.txt',
        'unicode-command',
      ),
    )
    const compactSplitAt = compactRecord.indexOf(Buffer.from('中')) + 1

    startFixture(
      [record.subarray(0, splitAt), record.subarray(splitAt)],
      event => events.push(event),
      {
        compactChunks: [
          compactRecord.subarray(0, compactSplitAt),
          compactRecord.subarray(compactSplitAt),
        ],
      },
    )
    await waitFor(() => events.length > 0, 'expected a Unicode violation')

    expect(events[0].line).toBe('deny file-read-data /tmp/中文.txt')
    expect(events[0].command).toBe('unicode-command')
  })

  it('does not carry attribution into an untagged record', async () => {
    const events: SandboxViolationEvent[] = []
    const chunk = Buffer.from(
      violationRecord(
        'first deny file-read-data /tmp/tagged',
        'tagged-command',
      ) + violationRecord('second deny file-read-data /tmp/untagged'),
    )
    const compactChunk = Buffer.from(
      compactViolationRecord(
        'first deny file-read-data /tmp/tagged',
        'tagged-command',
      ) + compactViolationRecord('second deny file-read-data /tmp/untagged'),
    )

    startFixture([chunk], event => events.push(event), {
      compactChunks: [compactChunk],
    })
    await waitFor(() => events.length >= 2, 'expected two violation events')

    expect(events[0]).toMatchObject({
      command: 'tagged-command',
      encodedCommand: Buffer.from('tagged-command').toString('base64'),
    })
    expect(events[1].command).toBeUndefined()
    expect(events[1].encodedCommand).toBeUndefined()
  })

  it('recovers after non-record output and applies command-specific ignores', async () => {
    const events: SandboxViolationEvent[] = []
    const output = [
      'Filtering the log data using "composedMessage ENDSWITH fixture"',
      '{"eventMessage":',
      JSON.stringify({ count: 0, finished: 1 }),
      violationRecord(
        'deny file-read-data /tmp/ignored',
        'ignored-id',
      ).trimEnd(),
      violationRecord(
        'valid deny file-read-data /tmp/kept',
        'kept-id',
      ).trimEnd(),
    ].join('\n')
    const compactOutput = [
      'Filtering the log data using "composedMessage ENDSWITH fixture"',
      compactViolationRecord(
        'deny file-read-data /tmp/ignored',
        'ignored-id',
      ).trimEnd(),
      compactViolationRecord(
        'valid deny file-read-data /tmp/kept',
        'kept-id',
      ).trimEnd(),
    ].join('\n')

    startFixture([Buffer.from(`${output}\n`)], event => events.push(event), {
      compactChunks: [Buffer.from(`${compactOutput}\n`)],
      ignoreViolations: { 'resolved ignored': ['/tmp/ignored'] },
      resolveCommandText: id => `resolved ${id.replace('-id', '')}`,
    })
    await waitFor(() => events.length > 0, 'expected the valid violation')

    expect(events).toHaveLength(1)
    expect(events[0]).toMatchObject({
      line: 'valid deny file-read-data /tmp/kept',
      command: 'resolved kept',
    })
  })

  it('suppresses one noisy record without dropping the next record', async () => {
    const events: SandboxViolationEvent[] = []
    const chunk = Buffer.from(
      violationRecord('deny network-outbound mDNSResponder', 'noisy') +
        violationRecord('deny file-read-data /tmp/kept', 'kept'),
    )
    const compactChunk = Buffer.from(
      compactViolationRecord('deny network-outbound mDNSResponder', 'noisy') +
        compactViolationRecord('deny file-read-data /tmp/kept', 'kept'),
    )

    startFixture([chunk], event => events.push(event), {
      compactChunks: [compactChunk],
    })
    await waitFor(() => events.length > 0, 'expected the non-noisy violation')

    expect(events).toHaveLength(1)
    expect(events[0]).toMatchObject({
      line: 'deny file-read-data /tmp/kept',
      command: 'kept',
    })
  })

  it('processes a complete final record without a newline and ignores a partial one', async () => {
    const completeEvents: SandboxViolationEvent[] = []
    const partialEvents: SandboxViolationEvent[] = []

    const completeFixture = startFixture(
      [
        Buffer.from(
          violationRecord(
            'deny file-read-data /tmp/complete',
            'complete',
          ).trimEnd(),
        ),
      ],
      event => completeEvents.push(event),
      {
        compactChunks: [
          Buffer.from(
            compactViolationRecord(
              'deny file-read-data /tmp/complete',
              'complete',
            ).trimEnd(),
          ),
        ],
      },
    )
    const partialFixture = startFixture(
      [Buffer.from('{"eventMessage":"kernel Sandbox: deny file-read-data')],
      event => partialEvents.push(event),
      {
        compactChunks: [
          Buffer.from('2026-09-06 kernel Sandbox: deny file-read-data'),
        ],
      },
    )
    await Promise.all([
      completeFixture.waitForExit(),
      partialFixture.waitForExit(),
    ])

    expect(completeEvents).toHaveLength(1)
    expect(partialEvents).toHaveLength(0)
  })

  it('does not deliver records after explicit stop', async () => {
    const events: SandboxViolationEvent[] = []
    const first = violationRecord('deny file-read-data /tmp/first', 'first')
    const second = violationRecord('deny file-read-data /tmp/second', 'second')
    const compactFirst = compactViolationRecord(
      'deny file-read-data /tmp/first',
      'first',
    )
    const compactSecond = compactViolationRecord(
      'deny file-read-data /tmp/second',
      'second',
    )
    const { stop } = startFixture(
      [Buffer.from(first), Buffer.from(second)],
      event => events.push(event),
      {
        compactChunks: [Buffer.from(compactFirst), Buffer.from(compactSecond)],
        chunkDelayMs: 200,
      },
    )

    await waitFor(() => events.length > 0, 'expected the first violation')
    stop()
    await Bun.sleep(100)

    expect(events).toHaveLength(1)
    expect(events[0].command).toBe('first')
  })

  it('requests NDJSON while retaining the session predicate', async () => {
    const { argsPath } = startFixture([], () => {})
    await waitFor(() => existsSync(argsPath), 'expected captured log arguments')

    const args = JSON.parse(readFileSync(argsPath, 'utf8')) as string[]
    expect(args).toContain('stream')
    expect(args).toContain('--style')
    expect(args).toContain('ndjson')
    expect(args.some(arg => arg.includes('eventMessage ENDSWITH'))).toBe(true)
  })
})
