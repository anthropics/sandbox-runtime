import { afterEach, describe, expect, spyOn, test } from 'bun:test'
import type { SandboxViolationEvent } from '../../src/sandbox/macos-sandbox-utils.js'
import { SandboxViolationStore } from '../../src/sandbox/sandbox-violation-store.js'
import {
  createSystemLogViolationSink,
  formatSystemLogMessage,
  tagSystemLogMessage,
  writeSystemLogLine,
  type LoggerSpawner,
  type SpawnedLogger,
} from '../../src/sandbox/system-log-violation-sink.js'

/**
 * A fake `logger` child. Tests drive `exit` / `error` explicitly so the
 * in-flight accounting can be observed deterministically.
 */
class FakeChild implements SpawnedLogger {
  private handlers: { error?: (err: Error) => void; exit?: () => void } = {}
  unrefCalled = false
  on(event: 'error', listener: (err: Error) => void): unknown
  on(event: 'exit', listener: () => void): unknown
  on(event: 'error' | 'exit', listener: (...args: never[]) => void): unknown {
    if (event === 'error') {
      this.handlers.error = listener as (err: Error) => void
    } else {
      this.handlers.exit = listener as () => void
    }
    return this
  }
  unref(): void {
    this.unrefCalled = true
  }
  exit(): void {
    this.handlers.exit?.()
  }
  fail(err: Error): void {
    this.handlers.error?.(err)
  }
}

function fakeSpawner(): {
  spawn: LoggerSpawner
  calls: { command: string; args: string[]; child: FakeChild }[]
} {
  const calls: { command: string; args: string[]; child: FakeChild }[] = []
  const spawn: LoggerSpawner = (command, args) => {
    const child = new FakeChild()
    calls.push({ command, args, child })
    return child
  }
  return { spawn, calls }
}

function proxyEvent(
  overrides: Partial<SandboxViolationEvent> = {},
): SandboxViolationEvent {
  return {
    line: 'deny network-outbound api.example.com:443 (host is not on the allow list)',
    command: 'curl https://api.example.com/v1',
    encodedCommand: 'Y3VybA==',
    timestamp: new Date(0),
    source: 'proxy',
    ...overrides,
  }
}

const savedDebug = process.env.SRT_DEBUG
afterEach(() => {
  if (savedDebug === undefined) {
    delete process.env.SRT_DEBUG
  } else {
    process.env.SRT_DEBUG = savedDebug
  }
})

describe('formatSystemLogMessage', () => {
  test('macOS line carries source, store line, quoted command and the _SBX tag', () => {
    const msg = formatSystemLogMessage(proxyEvent(), 'darwin')
    expect(msg).toBe(
      'srt proxy deny network-outbound api.example.com:443 (host is not on the allow list) cmd="curl https://api.example.com/v1" _SBX',
    )
  })

  test('Linux line has no _SBX tag', () => {
    const msg = formatSystemLogMessage(proxyEvent(), 'linux')
    expect(msg.endsWith('_SBX')).toBe(false)
    expect(msg.startsWith('srt proxy deny network-outbound')).toBe(true)
  })

  test('the _SBX token is space-separated so it can never match the per-session monitor suffix', () => {
    // startMacOSSandboxLogMonitor streams `ENDSWITH "_<random>_SBX"`. A
    // message that ended in `<something>_SBX` with no space could, for the
    // right <something>, be re-ingested as a seatbelt violation.
    const msg = formatSystemLogMessage(
      proxyEvent({ command: 'echo _abc123xyz' }),
      'darwin',
    )
    expect(msg).toMatch(/ _SBX$/)
    expect(msg).not.toMatch(/_[a-z0-9]{9}_SBX$/)
  })

  test('omits cmd= when there is no command', () => {
    const msg = formatSystemLogMessage(
      proxyEvent({ command: undefined }),
      'linux',
    )
    expect(msg).not.toContain('cmd=')
  })

  test('falls back to a generic source label when source is unset', () => {
    const msg = formatSystemLogMessage(
      proxyEvent({ source: undefined }),
      'linux',
    )
    expect(msg.startsWith('srt sandbox deny')).toBe(true)
  })

  test('collapses control characters and newlines to one physical line', () => {
    const msg = formatSystemLogMessage(
      proxyEvent({
        line: 'deny network-outbound evil\n.example.com:443\x1b[31m',
        command: 'sh -c "a\nb"',
      }),
      'linux',
    )
    expect(msg).not.toContain('\n')
    expect(msg).not.toContain('\x1b')
  })

  test('replaces double quotes inside the command so cmd="..." stays parseable', () => {
    const msg = formatSystemLogMessage(
      proxyEvent({ command: 'sh -c "curl x"' }),
      'linux',
    )
    expect(msg).toContain(`cmd="sh -c 'curl x'"`)
  })

  test('truncates long commands and bounds the whole message', () => {
    const msg = formatSystemLogMessage(
      proxyEvent({
        line: `deny network-outbound ${'h'.repeat(2000)}:443`,
        command: 'x'.repeat(5000),
      }),
      'darwin',
    )
    expect(msg.length).toBeLessThanOrEqual(1000)
    expect(msg.endsWith(' _SBX')).toBe(true)
  })
})

describe('createSystemLogViolationSink', () => {
  test('returns undefined on platforms without logger(1)', () => {
    const { spawn } = fakeSpawner()
    expect(createSystemLogViolationSink({ platform: 'win32', spawn })).toBe(
      undefined,
    )
  })

  test('spawns logger -t srt with the formatted message for a proxy denial', () => {
    const { spawn, calls } = fakeSpawner()
    const sink = createSystemLogViolationSink({ platform: 'darwin', spawn })!
    sink.handle(proxyEvent())
    expect(calls).toHaveLength(1)
    expect(calls[0]!.command).toBe('logger')
    expect(calls[0]!.args).toEqual([
      '-t',
      'srt',
      formatSystemLogMessage(proxyEvent(), 'darwin'),
    ])
    expect(calls[0]!.child.unrefCalled).toBe(true)
    expect(sink.written).toBe(1)
  })

  test('forwards seccomp denials', () => {
    const { spawn, calls } = fakeSpawner()
    const sink = createSystemLogViolationSink({ platform: 'linux', spawn })!
    sink.handle(
      proxyEvent({ line: 'deny openat /etc/shadow', source: 'seccomp' }),
    )
    expect(calls).toHaveLength(1)
    expect(calls[0]!.args[2]).toStartWith('srt seccomp deny openat /etc/shadow')
  })

  test('skips seatbelt denials because the kernel already logs them', () => {
    const { spawn, calls } = fakeSpawner()
    const sink = createSystemLogViolationSink({ platform: 'darwin', spawn })!
    sink.handle(
      proxyEvent({ line: 'deny(1) file-read-data /etc/x', source: 'seatbelt' }),
    )
    expect(calls).toHaveLength(0)
    expect(sink.written).toBe(0)
    expect(sink.dropped).toBe(0)
  })

  test('drops events beyond the in-flight cap and resumes once children exit', () => {
    const { spawn, calls } = fakeSpawner()
    const sink = createSystemLogViolationSink({
      platform: 'linux',
      spawn,
      maxInFlight: 2,
    })!
    sink.handle(proxyEvent())
    sink.handle(proxyEvent())
    sink.handle(proxyEvent())
    expect(calls).toHaveLength(2)
    expect(sink.dropped).toBe(1)

    calls[0]!.child.exit()
    sink.handle(proxyEvent())
    expect(calls).toHaveLength(3)
    expect(sink.written).toBe(3)
  })

  test('disables itself after a spawn error (e.g. logger not on PATH)', () => {
    const { spawn, calls } = fakeSpawner()
    const sink = createSystemLogViolationSink({ platform: 'linux', spawn })!
    sink.handle(proxyEvent())
    calls[0]!.child.fail(
      Object.assign(new Error('spawn logger ENOENT'), { code: 'ENOENT' }),
    )
    sink.handle(proxyEvent())
    sink.handle(proxyEvent())
    expect(calls).toHaveLength(1)
  })

  test('disables itself when the spawner throws synchronously', () => {
    let attempts = 0
    const spawn: LoggerSpawner = () => {
      attempts++
      throw new Error('EAGAIN')
    }
    const sink = createSystemLogViolationSink({ platform: 'linux', spawn })!
    sink.handle(proxyEvent())
    sink.handle(proxyEvent())
    expect(attempts).toBe(1)
  })

  test('never writes to stderr, with or without SRT_DEBUG', () => {
    // The host process shares a terminal with the sandboxed child; stderr
    // output from the host corrupts TUI rendering. Only logger may be used.
    for (const debug of [undefined, '1']) {
      if (debug === undefined) {
        delete process.env.SRT_DEBUG
      } else {
        process.env.SRT_DEBUG = debug
      }
      const writes: string[] = []
      const errSpy = spyOn(process.stderr, 'write').mockImplementation(
        (chunk: string | Uint8Array) => {
          writes.push(typeof chunk === 'string' ? chunk : chunk.toString())
          return true
        },
      )
      const consoleSpy = spyOn(console, 'error').mockImplementation(() => {})
      const warnSpy = spyOn(console, 'warn').mockImplementation(() => {})
      try {
        const { spawn } = fakeSpawner()
        const sink = createSystemLogViolationSink({
          platform: 'darwin',
          spawn,
        })!
        sink.handle(proxyEvent())
        expect(writes).toHaveLength(0)
        if (debug === undefined) {
          // Without SRT_DEBUG not even the debug channel may be touched.
          expect(consoleSpy).not.toHaveBeenCalled()
          expect(warnSpy).not.toHaveBeenCalled()
        }
      } finally {
        errSpy.mockRestore()
        consoleSpy.mockRestore()
        warnSpy.mockRestore()
      }
    }
  })
})

describe('SandboxViolationStore.onViolation', () => {
  test('delivers each sanitized event exactly once and supports unsubscribe', () => {
    const store = new SandboxViolationStore()
    const seen: SandboxViolationEvent[] = []
    const off = store.onViolation(v => seen.push(v))

    store.addViolation(proxyEvent({ line: 'deny <a>\nb' }))
    store.addViolation(proxyEvent({ line: 'deny c' }))
    expect(seen.map(v => v.line)).toEqual(['deny a b', 'deny c'])
    expect(seen[0]!.source).toBe('proxy')

    off()
    store.addViolation(proxyEvent({ line: 'deny d' }))
    expect(seen).toHaveLength(2)
  })

  test('is not replayed on subscription, unlike subscribe()', () => {
    const store = new SandboxViolationStore()
    store.addViolation(proxyEvent())
    const seen: SandboxViolationEvent[] = []
    store.onViolation(v => seen.push(v))
    expect(seen).toHaveLength(0)
  })

  test('the sink wired to a store forwards proxy denials and skips seatbelt ones', () => {
    const store = new SandboxViolationStore()
    const { spawn, calls } = fakeSpawner()
    const sink = createSystemLogViolationSink({ platform: 'darwin', spawn })!
    store.onViolation(sink.handle)

    store.addViolation(proxyEvent({ source: 'seatbelt' }))
    store.addViolation(proxyEvent({ source: 'proxy' }))
    expect(calls).toHaveLength(1)
    expect(calls[0]!.args[2]).toStartWith('srt proxy deny network-outbound')
  })
})

describe('tagSystemLogMessage / writeSystemLogLine', () => {
  test('tags with a space-separated _SBX on macOS only', () => {
    expect(tagSystemLogMessage('srt startup version=1.2.3', 'darwin')).toBe(
      'srt startup version=1.2.3 _SBX',
    )
    expect(tagSystemLogMessage('srt startup version=1.2.3', 'linux')).toBe(
      'srt startup version=1.2.3',
    )
  })

  test('collapses control characters and bounds the line', () => {
    const tagged = tagSystemLogMessage(`a\nb${'x'.repeat(2000)}`, 'darwin')
    expect(tagged).not.toContain('\n')
    expect(tagged.length).toBeLessThanOrEqual(1000)
    expect(tagged.endsWith(' _SBX')).toBe(true)
  })

  test('writes one line via logger -t srt and returns the child', () => {
    const { spawn, calls } = fakeSpawner()
    const child = writeSystemLogLine('srt startup version=1.2.3 _SBX', {
      platform: 'darwin',
      spawn,
    })
    expect(child).toBeDefined()
    expect(calls).toHaveLength(1)
    expect(calls[0]!.args).toEqual([
      '-t',
      'srt',
      'srt startup version=1.2.3 _SBX',
    ])
    expect(calls[0]!.child.unrefCalled).toBe(true)
  })

  test('is a no-op on platforms without logger(1)', () => {
    const { spawn, calls } = fakeSpawner()
    expect(
      writeSystemLogLine('x', { platform: 'win32', spawn }),
    ).toBeUndefined()
    expect(calls).toHaveLength(0)
  })

  test('routes synchronous and asynchronous spawn failures to onError', () => {
    const errors: string[] = []
    const throwing: LoggerSpawner = () => {
      throw new Error('EAGAIN')
    }
    expect(
      writeSystemLogLine('x', {
        platform: 'linux',
        spawn: throwing,
        onError: e => errors.push(e.message),
      }),
    ).toBeUndefined()

    const { spawn, calls } = fakeSpawner()
    writeSystemLogLine('x', {
      platform: 'linux',
      spawn,
      onError: e => errors.push(e.message),
    })
    calls[0]!.child.fail(new Error('spawn logger ENOENT'))
    expect(errors).toEqual(['EAGAIN', 'spawn logger ENOENT'])
  })
})
