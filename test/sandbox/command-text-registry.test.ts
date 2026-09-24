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
import {
  SandboxViolationStore,
  sanitizeUnregisteredCommandKey,
} from '../../src/sandbox/sandbox-violation-store.js'
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

// The declared type is `string | undefined`, but JavaScript callers do pass
// null. Keying on it throws in encodeSandboxedCommand, and the registry write
// is the first thing wrapWithSandbox does, so the whole wrap goes down with it.
const nullCommandId = null as unknown as undefined

describe.if(isLinux || isMacOS)("a JavaScript caller's null commandId", () => {
  it('wraps, and attributes the invocation under its command', async () => {
    expect(attributionKeyFor('the command', nullCommandId)).toBe('the command')
    await SandboxManager.initialize({
      network: { allowedDomains: [], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    })
    const wrapped = await SandboxManager.wrapWithSandbox(
      'echo hi',
      undefined,
      undefined,
      undefined,
      { commandId: nullCommandId, commandText: 'the real command' },
    )
    expect(wrapped).not.toBe('echo hi')
    expect(resolveCommandText(keyFor('echo hi'))).toBe('the real command')
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

  it('cuts between characters, never through a surrogate pair', () => {
    // 101 UTF-16 code units: a cut at 100 lands inside the last pair and
    // leaves a lone high surrogate, which renders as a replacement character.
    const key = `a${'\u{1f600}'.repeat(50)}`
    const cut = resolveCommandText(key)
    expect(cut).toBe(`a${'\u{1f600}'.repeat(49)}`)
    expect(/[\ud800-\udbff]$/.test(cut)).toBe(false)
  })
})

describe('the characters a violation record cannot carry', () => {
  const storedLine = (line: string): string => {
    const store = new SandboxViolationStore()
    store.addViolation({ line, timestamp: new Date() })
    return store.getViolations()[0].line
  }

  // Both the stored `line` and the unregistered-key fallback go through one
  // sanitizer, so each case asserts on both.
  it.each([
    ['U+0000 NULL', '\u0000'],
    ['U+001B ESCAPE', '\u001b'],
    ['U+007F DELETE', '\u007f'],
    ['U+009B CONTROL SEQUENCE INTRODUCER', '\u009b'],
    ['U+00AD SOFT HYPHEN', '\u00ad'],
    ['U+061C ARABIC LETTER MARK', '\u061c'],
    ['U+200B ZERO WIDTH SPACE', '\u200b'],
    ['U+200C ZERO WIDTH NON-JOINER', '\u200c'],
    ['U+200D ZERO WIDTH JOINER', '\u200d'],
    ['U+200E LEFT-TO-RIGHT MARK', '\u200e'],
    ['U+200F RIGHT-TO-LEFT MARK', '\u200f'],
    ['U+2028 LINE SEPARATOR', '\u2028'],
    ['U+2029 PARAGRAPH SEPARATOR', '\u2029'],
    ['U+202A LEFT-TO-RIGHT EMBEDDING', '\u202a'],
    ['U+202B RIGHT-TO-LEFT EMBEDDING', '\u202b'],
    ['U+202C POP DIRECTIONAL FORMATTING', '\u202c'],
    ['U+202D LEFT-TO-RIGHT OVERRIDE', '\u202d'],
    ['U+202E RIGHT-TO-LEFT OVERRIDE', '\u202e'],
    ['U+2060 WORD JOINER', '\u2060'],
    ['U+2061 FUNCTION APPLICATION', '\u2061'],
    ['U+2062 INVISIBLE TIMES', '\u2062'],
    ['U+2063 INVISIBLE SEPARATOR', '\u2063'],
    ['U+2064 INVISIBLE PLUS', '\u2064'],
    ['U+2066 LEFT-TO-RIGHT ISOLATE', '\u2066'],
    ['U+2067 RIGHT-TO-LEFT ISOLATE', '\u2067'],
    ['U+2068 FIRST STRONG ISOLATE', '\u2068'],
    ['U+2069 POP DIRECTIONAL ISOLATE', '\u2069'],
    ['U+FEFF ZERO WIDTH NO-BREAK SPACE', '\ufeff'],
    ['U+E0001 LANGUAGE TAG', '\u{e0001}'],
    ['U+E0041 TAG LATIN CAPITAL LETTER A', '\u{e0041}'],
    ['U+E007F CANCEL TAG', '\u{e007f}'],
  ])('collapses %s', (_name, character) => {
    expect(sanitizeUnregisteredCommandKey(`a${character}b`)).toBe('a b')
    expect(storedLine(`a${character}b`)).toBe('a b')
  })

  it('drops the angle brackets from a line as well as from a key', () => {
    expect(storedLine('deny file-write /x<y>z')).toBe('deny file-write /xyz')
  })

  it('leaves text that renders as what it says alone', () => {
    expect(storedLine('deny network-outbound example.com:443')).toBe(
      'deny network-outbound example.com:443',
    )
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

  // One case per platform: the resolver argument is required, so this proves
  // the manager passes the registry-backed one rather than some other.
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
