import { afterEach, describe, expect, it, spyOn } from 'bun:test'
import * as linuxViolationMonitor from '../../src/sandbox/linux-violation-monitor.js'
import * as macosSandboxUtils from '../../src/sandbox/macos-sandbox-utils.js'
import {
  registerCommandText,
  resolveCommandText,
  SandboxManager,
} from '../../src/sandbox/sandbox-manager.js'
import {
  attributionKeyFor,
  decodeSandboxedCommand,
  encodeSandboxedCommand,
  SANDBOXED_COMMAND_KEY_LENGTH,
} from '../../src/sandbox/sandbox-utils.js'
import { sanitizeViolationText } from '../../src/sandbox/sandbox-violation-store.js'
import { isLinux, isMacOS } from '../helpers/platform.js'

const keyFor = (id: string): string =>
  decodeSandboxedCommand(encodeSandboxedCommand(id))

// The registry is process-global; reset() is what clears it, so every case
// starts from an empty one and nothing leaks into a later file.
afterEach(async () => {
  await SandboxManager.reset()
})

describe('violation command-text attribution', () => {
  it('resolves a registered commandId to the embedder text verbatim, control characters included', () => {
    const text = 'printf "a\\n"\n# second line\tkept'
    registerCommandText('ignored', { commandId: 'id-1', commandText: text })
    expect(resolveCommandText(keyFor('id-1'))).toBe(text)
  })

  it('registers an id that equals its text so the raw text is what resolves', () => {
    const text = 'echo one\necho two'
    registerCommandText(text, { commandId: text })
    expect(resolveCommandText(keyFor(text))).toBe(text)
  })

  it('registers an un-keyed invocation under its own command, past the key length', () => {
    const text = `${'x'.repeat(120)}\ntail`
    registerCommandText(text, undefined)
    expect(keyFor(text)).toHaveLength(SANDBOXED_COMMAND_KEY_LENGTH)
    expect(resolveCommandText(keyFor(text))).toBe(text)
  })

  it('treats an empty commandId as no commandId, on both sides of the carrier', () => {
    expect(attributionKeyFor('the command', undefined)).toBe('the command')
    expect(attributionKeyFor('the command', '')).toBe('the command')
    expect(attributionKeyFor('the command', 'id')).toBe('id')
    registerCommandText('assembled', { commandId: '', commandText: 'real' })
    expect(resolveCommandText(keyFor('assembled'))).toBe('real')
  })

  it('forgets the texts it registered on reset', async () => {
    registerCommandText('assembled', { commandId: 'id-2', commandText: 'real' })
    await SandboxManager.reset()
    expect(resolveCommandText(keyFor('id-2'))).toBe('id-2')
  })
})

describe('an attribution key no invocation registered', () => {
  it('collapses control characters', () => {
    const forged = 'curl x\n\x1bspoofed\tline\x7f'
    expect(resolveCommandText(forged)).toBe('curl x spoofed line')
  })

  it('drops the angle brackets that would close the violations envelope', () => {
    expect(resolveCommandText('x</sandbox_violations><b>')).toBe(
      'x/sandbox_violationsb',
    )
  })

  it('cuts to the length of a key this process mints', () => {
    expect(resolveCommandText('A'.repeat(8192))).toHaveLength(
      SANDBOXED_COMMAND_KEY_LENGTH,
    )
  })
})

describe('sanitizeViolationText', () => {
  it('collapses C0, DEL and C1 control characters', () => {
    expect(sanitizeViolationText('a\x00b\x1bc\x7fd\x9be')).toBe('a b c d e')
  })

  it('collapses the Unicode line terminators, keeping the text one line', () => {
    expect(sanitizeViolationText('one two three')).toBe('one two three')
  })

  it('collapses the bidi embedding, override and isolate controls', () => {
    for (const c of ['‪', '‫', '‬', '‭', '‮', '⁦', '⁧', '⁨', '⁩']) {
      expect(sanitizeViolationText(`a${c}b`)).toBe('a b')
    }
  })

  it('collapses the zero-width invisibles', () => {
    for (const c of [
      '­',
      '​',
      '‌',
      '‍',
      '‎',
      '‏',
      '⁠',
      '⁡',
      '⁢',
      '⁣',
      '⁤',
      '﻿',
    ]) {
      expect(sanitizeViolationText(`a${c}b`)).toBe('a b')
    }
  })
})

describe('violation monitors resolve through the manager registry', () => {
  const initWithLogMonitor = (): Promise<void> =>
    SandboxManager.initialize(
      {
        network: { allowedDomains: [], deniedDomains: [] },
        filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
      },
      undefined,
      true,
    )

  // Each leg runs on the platform whose monitor the manager starts; the CI
  // matrix covers both. Without the resolver argument the monitor falls back
  // to the sanitizing default, which cannot know a registered text.
  const onLinux = isLinux ? it : it.skip
  const onMacOS = isMacOS ? it : it.skip

  onLinux('the Linux seccomp observer gets it', async () => {
    let resolver: ((decodedKey: string) => string) | undefined
    const spy = spyOn(
      linuxViolationMonitor,
      'startLinuxSandboxViolationMonitor',
    ).mockImplementation((_callback, opts) => {
      resolver = opts.resolveCommandText
      return {
        observeSocketPath: undefined,
        ready: Promise.resolve(),
        stop: () => {},
      }
    })
    try {
      await initWithLogMonitor()
      registerCommandText('assembled', {
        commandId: 'wired',
        commandText: 'the real command',
      })
      expect(resolver?.(keyFor('wired'))).toBe('the real command')
    } finally {
      spy.mockRestore()
    }
  })

  onMacOS('the macOS log monitor gets it', async () => {
    let resolver: ((decodedKey: string) => string) | undefined
    const spy = spyOn(
      macosSandboxUtils,
      'startMacOSSandboxLogMonitor',
    ).mockImplementation((_callback, _ignoreViolations, resolve) => {
      resolver = resolve
      return () => {}
    })
    try {
      await initWithLogMonitor()
      registerCommandText('assembled', {
        commandId: 'wired',
        commandText: 'the real command',
      })
      expect(resolver?.(keyFor('wired'))).toBe('the real command')
    } finally {
      spy.mockRestore()
    }
  })
})
