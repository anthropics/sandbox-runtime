import { describe, it, expect, beforeAll, afterAll } from 'bun:test'
import { spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  wrapCommandWithSandboxMacOS,
  resolveInheritedStdioTtys,
  type TtyProbes,
} from '../../src/sandbox/macos-sandbox-utils.js'
import { isMacOS } from '../helpers/platform.js'

const CTTY = join(import.meta.dir, '../helpers/pty-ctty.py')
const UTILS = join(import.meta.dir, '../../src/sandbox/macos-sandbox-utils.ts')
const CLI = join(import.meta.dir, '../../src/cli.ts')

/** The e2e cases drive the real CLI through a pty; both are hard deps. */
const hasDeps = ['python3', 'bun'].every(
  bin => spawnSync('command', ['-v', bin], { shell: true }).status === 0,
)

/**
 * Seatbelt matches ioctl rules by device path, and a terminal is a pty slave
 * (`/dev/ttysNNN`) that the base profile's `/dev/tty` literal does not cover.
 * Without a rule for it, TIOCSETA/TIOCSETAW return EPERM, no TUI can enter raw
 * mode, and the terminal echoes capability replies, KKP key encodings and
 * mouse events as literal text — issues #419 and #391.
 */
describe.if(isMacOS)('macOS pty rules: inherited-stdio terminal grant', () => {
  const BROAD_REGEX = '(regex #"^/dev/ttys")'
  const PSEUDO_TTY = '(allow pseudo-tty)'
  const TTY_A = '/dev/ttys991'
  const TTY_B = '/dev/ttys992'

  // A read restriction is required, otherwise the wrapper short-circuits and
  // returns the bare command with no profile at all.
  const baseParams = {
    command: 'true',
    needsNetworkRestriction: false,
    readConfig: { denyOnly: ['/work/priv'] },
    writeConfig: undefined,
  }

  it('grants ioctl on the given terminal, and nothing more', () => {
    const profile = wrapCommandWithSandboxMacOS({
      ...baseParams,
      inheritedTtys: [TTY_A],
    })

    expect(profile).toContain(`(allow file-ioctl (literal "${TTY_A}"))`)
    // ioctl is all raw mode needs. A read/write grant would be policy surface
    // that buys nothing here, and would matter if the child never receives
    // this terminal.
    expect(profile).not.toContain(
      `(allow file-read* file-write* (literal "${TTY_A}"))`,
    )
    expect(profile).not.toContain(BROAD_REGEX)
    expect(profile).not.toContain(PSEUDO_TTY)
  })

  it('grants every distinct inherited terminal, not just the first', () => {
    // stdio split across two terminals: a program reading keys from one while
    // sizing the other needs both, and granting only the first leaves the
    // second returning EPERM.
    const profile = wrapCommandWithSandboxMacOS({
      ...baseParams,
      inheritedTtys: [TTY_A, TTY_B],
    })

    expect(profile).toContain(`(allow file-ioctl (literal "${TTY_A}"))`)
    expect(profile).toContain(`(allow file-ioctl (literal "${TTY_B}"))`)
  })

  it('ignores paths that are not pty slave devices', () => {
    // The parameter is exported and reaches a (literal ...) rule, so the
    // shape is enforced rather than trusted.
    const profile = wrapCommandWithSandboxMacOS({
      ...baseParams,
      inheritedTtys: ['/etc/passwd', '/dev/ttysNOPE', TTY_A],
    })

    expect(profile).not.toContain('/etc/passwd')
    expect(profile).not.toContain('/dev/ttysNOPE')
    expect(profile).toContain(`(allow file-ioctl (literal "${TTY_A}"))`)
  })

  it('emits no pty rules when no terminal is passed', () => {
    // The wrapper never detects one on its own: the caller decides stdio
    // after this returns, so detection here would be a guess.
    const profile = wrapCommandWithSandboxMacOS({ ...baseParams })

    expect(profile).not.toContain(PSEUDO_TTY)
    expect(profile).not.toContain(BROAD_REGEX)
    expect(profile).not.toContain('/dev/ttys')
  })

  it('grants every pty when allowPty is true', () => {
    const profile = wrapCommandWithSandboxMacOS({
      ...baseParams,
      allowPty: true,
      inheritedTtys: [TTY_A],
    })

    expect(profile).toContain(PSEUDO_TTY)
    expect(profile).toContain(BROAD_REGEX)
    expect(profile).toContain('(literal "/dev/ptmx")')
    expect(profile).not.toContain(`(allow file-ioctl (literal "${TTY_A}"))`)
  })

  it('treats allowPty:false identically to unset (inherited ioctl, no wide grant)', () => {
    // `false` collapses into the default rather than emitting nothing: an
    // explicit `false` and an absent flag must produce the same profile, so
    // `false` cannot silently reproduce the raw-mode bug. Only `true` widens.
    const asFalse = wrapCommandWithSandboxMacOS({
      ...baseParams,
      allowPty: false,
      inheritedTtys: [TTY_A],
    })
    const asUnset = wrapCommandWithSandboxMacOS({
      ...baseParams,
      inheritedTtys: [TTY_A],
    })

    expect(asFalse).toContain(`(allow file-ioctl (literal "${TTY_A}"))`)
    expect(asFalse).not.toContain(PSEUDO_TTY)
    expect(asFalse).not.toContain(BROAD_REGEX)
    expect(asFalse).toBe(asUnset)
  })
})

describe('resolveInheritedStdioTtys: rdev matching (injected probes)', () => {
  // Injected probes exercise the match/no-match/dedup and every error path in
  // process. The real-fs path needs a genuine pty on fd 0/1/2 and is covered by
  // the e2e resolver tests below.
  const probes = (
    over: Partial<TtyProbes> & { ttys?: number[] },
  ): TtyProbes => ({
    isatty: fd => (over.ttys ?? []).includes(fd),
    listPtySlaves: () => ['ttys001', 'ttys002', 'ttys003'],
    rdevOfFd: () => 0,
    rdevOfPath: () => -1,
    ...over,
  })

  it('returns [] when no fd is a tty', () => {
    expect(resolveInheritedStdioTtys(probes({ ttys: [] }))).toEqual([])
  })

  it('resolves a tty fd to the device with the matching rdev', () => {
    const p = probes({
      ttys: [1],
      rdevOfFd: () => 42,
      rdevOfPath: path => (path === '/dev/ttys002' ? 42 : 0),
    })
    expect(resolveInheritedStdioTtys(p)).toEqual(['/dev/ttys002'])
  })

  it('deduplicates when two fds share one device', () => {
    const p = probes({
      ttys: [1, 2],
      rdevOfFd: () => 7,
      rdevOfPath: path => (path === '/dev/ttys001' ? 7 : 0),
    })
    expect(resolveInheritedStdioTtys(p)).toEqual(['/dev/ttys001'])
  })

  it('returns every distinct device across fds', () => {
    const p = probes({
      ttys: [0, 1],
      rdevOfFd: fd => (fd === 0 ? 7 : 9),
      rdevOfPath: path =>
        path === '/dev/ttys001' ? 7 : path === '/dev/ttys003' ? 9 : 0,
    })
    expect(resolveInheritedStdioTtys(p)).toEqual([
      '/dev/ttys001',
      '/dev/ttys003',
    ])
  })

  it('returns [] when /dev cannot be scanned', () => {
    const p = probes({
      ttys: [1],
      listPtySlaves: () => {
        throw new Error('EACCES')
      },
    })
    expect(resolveInheritedStdioTtys(p)).toEqual([])
  })

  it('skips an fd whose rdev cannot be read, keeps the others', () => {
    const p = probes({
      ttys: [0, 1],
      rdevOfFd: fd => {
        if (fd === 0) throw new Error('EBADF')
        return 9
      },
      rdevOfPath: path => (path === '/dev/ttys003' ? 9 : 0),
    })
    expect(resolveInheritedStdioTtys(p)).toEqual(['/dev/ttys003'])
  })

  it('skips a slave whose rdev cannot be read (racing teardown)', () => {
    const p = probes({
      ttys: [1],
      rdevOfFd: () => 42,
      rdevOfPath: () => {
        throw new Error('ENOENT')
      },
    })
    expect(resolveInheritedStdioTtys(p)).toEqual([])
  })

  it('skips an fd with no matching device', () => {
    const p = probes({ ttys: [1], rdevOfFd: () => 999, rdevOfPath: () => 0 })
    expect(resolveInheritedStdioTtys(p)).toEqual([])
  })
})

describe.if(isMacOS)('macOS pty rules: harness dependencies', () => {
  it('has python3 and bun available', () => {
    // The Seatbelt-behaviour tests below are gated on these. Without this
    // check a macOS runner missing either would quietly reduce the suite to
    // string assertions and still report green.
    expect(hasDeps).toBe(true)
  })
})

describe.if(isMacOS && hasDeps)('macOS pty rules: resolver', () => {
  const runOnCtty = (...args: string[]) =>
    spawnSync('python3', [CTTY, ...args], {
      encoding: 'utf8',
      timeout: 120_000,
      env: { ...process.env, PTY_DEADLINE: '60' },
    })

  it('resolves the real device when a terminal is attached', () => {
    // The rdev-to-/dev/ttysNNN matching is the one genuinely non-obvious piece
    // of logic here, and the piped case below cannot reach it.
    const probe = `
      import { resolveInheritedStdioTtys } from ${JSON.stringify(UTILS)}
      console.log('RESOLVED:' + JSON.stringify(resolveInheritedStdioTtys()))
    `
    const res = runOnCtty('bun', '--eval', probe)
    const match = /RESOLVED:(\[.*\])/.exec(res.stdout ?? '')

    expect(match).not.toBeNull()
    const devices = JSON.parse(match![1]) as string[]
    expect(devices.length).toBeGreaterThan(0)
    for (const device of devices) expect(device).toMatch(/^\/dev\/ttys\d+$/)
  })

  it('resolves BOTH devices when stdio spans two terminals', () => {
    // The case a single-pty harness cannot reach. Returning on the first
    // matching fd leaves the other terminal without a rule, so operations
    // against it still fail with EPERM.
    const probe = `
      import { resolveInheritedStdioTtys } from ${JSON.stringify(UTILS)}
      console.log('RESOLVED:' + JSON.stringify(resolveInheritedStdioTtys()))
    `
    const res = spawnSync(
      'python3',
      [
        join(import.meta.dir, '../helpers/pty-split.py'),
        'bun',
        '--eval',
        probe,
      ],
      { encoding: 'utf8', timeout: 120_000 },
    )
    const match = /RESOLVED:(\[.*\])/.exec(res.stdout ?? '')

    expect(match).not.toBeNull()
    const devices = JSON.parse(match![1]) as string[]
    expect(devices.length).toBe(2)
    expect(new Set(devices).size).toBe(2)
    for (const device of devices) expect(device).toMatch(/^\/dev\/ttys\d+$/)
  })

  it('resolves nothing when stdio is piped', () => {
    const probe = `
      import { resolveInheritedStdioTtys } from ${JSON.stringify(UTILS)}
      console.log('RESOLVED:' + JSON.stringify(resolveInheritedStdioTtys()))
    `
    const res = spawnSync('bun', ['--eval', probe], {
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe'],
    })

    expect(res.status).toBe(0)
    expect(res.stdout).toContain('RESOLVED:[]')
  })

  it('emits a rule only when the caller asserts inheritsStdio', () => {
    // The sandbox-manager gate: wrapping returns a string and the caller picks
    // stdio afterwards, so a library consumer gets nothing unless it says so.
    const probe = `
      import { SandboxManager } from ${JSON.stringify(join(import.meta.dir, '../../src/index.ts'))}
      await SandboxManager.initialize({
        filesystem: { denyRead: ['/work/priv'], allowWrite: ['/tmp'], denyWrite: [] },
        network: { allowedDomains: [], deniedDomains: [] },
      })
      const re = /dev\\/ttys[0-9]+/
      const without = await SandboxManager.wrapWithSandbox('true')
      const With = await SandboxManager.wrapWithSandbox('true', undefined, undefined, undefined, { inheritsStdio: true })
      console.log('GATE:' + JSON.stringify({ without: re.test(without), with: re.test(With) }))
      await SandboxManager.reset()
    `
    const res = runOnCtty('bun', '--eval', probe)
    const match = /GATE:(\{.*\})/.exec(res.stdout ?? '')

    expect(match).not.toBeNull()
    expect(JSON.parse(match![1])).toEqual({ without: false, with: true })
  })

  it('allowPty:false resolves inherited ttys like unset (manager gate)', () => {
    // Regression for the `!== true` gate: an explicit `allowPty: false` must
    // still resolve and grant the inherited terminals — inherited-only ioctl,
    // no `pseudo-tty` — not be suppressed the way a `=== undefined` gate did.
    const probe = `
      import { SandboxManager } from ${JSON.stringify(join(import.meta.dir, '../../src/index.ts'))}
      await SandboxManager.initialize({
        filesystem: { denyRead: ['/work/priv'], allowWrite: ['/tmp'], denyWrite: [] },
        network: { allowedDomains: [], deniedDomains: [] },
        allowPty: false,
      })
      const re = /dev\\/ttys[0-9]+/
      const asFalse = await SandboxManager.wrapWithSandbox('true', undefined, undefined, undefined, { inheritsStdio: true })
      console.log('FALSEGATE:' + JSON.stringify({
        hasInheritedDevice: re.test(asFalse),
        hasPseudoTty: /pseudo-tty/.test(asFalse),
      }))
      await SandboxManager.reset()
    `
    const res = runOnCtty('bun', '--eval', probe)
    const match = /FALSEGATE:(\{.*\})/.exec(res.stdout ?? '')

    expect(match).not.toBeNull()
    expect(JSON.parse(match![1])).toEqual({
      hasInheritedDevice: true,
      hasPseudoTty: false,
    })
  })
})

/**
 * End-to-end through the CLI on a pty that is genuinely the child's
 * controlling terminal. These are the tests that would have caught #419: the
 * unit tests above pin generated strings, which cannot tell you whether
 * Seatbelt actually permits the ioctl.
 */
describe.if(isMacOS && hasDeps)('macOS pty rules: end to end', () => {
  const DIR = join(tmpdir(), 'srt-pty-e2e-' + Date.now())
  const SETTINGS = join(DIR, 'settings.json')
  const SETTINGS_BROAD = join(DIR, 'settings-allowpty.json')

  // The probe reports the errno so a refusal can be identified rather than
  // merely counted: EPERM (1) is Seatbelt, EACCES (13) is the kernel saying
  // this is not the caller's controlling terminal.
  //
  // Measured caveat: inside the sandbox Seatbelt refuses BEFORE the kernel's
  // controlling-terminal check, so a harness that lost the controlling
  // terminal also reports EPERM there. The errno assertion alone therefore
  // cannot prove the harness is sound — the unsandboxed control test below is
  // what does that, and it fails with EACCES if the prerequisite breaks.
  const INJECTED = 'TIOCSTI-INJECTED-MARKER'
  const TIOCSTI_PROBE = [
    'import fcntl,sys',
    'TIOCSTI=0x80017472',
    'try:',
    `    [fcntl.ioctl(sys.stdin.fileno(), TIOCSTI, c.encode()) for c in ${JSON.stringify(INJECTED)}]`,
    '    print("TIOCSTI-ALLOWED")',
    'except OSError as e: print("TIOCSTI-DENIED errno=%d" % e.errno)',
  ].join('\n')

  beforeAll(() => {
    mkdirSync(DIR, { recursive: true })
    const base = {
      filesystem: { denyRead: [], allowWrite: [DIR], denyWrite: [] },
      network: { allowedDomains: [], deniedDomains: [] },
    }
    // No allowPty key at all: this is the default path users get.
    writeFileSync(SETTINGS, JSON.stringify(base))
    writeFileSync(SETTINGS_BROAD, JSON.stringify({ ...base, allowPty: true }))
  })

  afterAll(() => {
    if (existsSync(DIR)) rmSync(DIR, { recursive: true, force: true })
  })

  const SPAWN_OPTS = {
    encoding: 'utf8' as const,
    timeout: 120_000,
    env: { ...process.env, PTY_DEADLINE: '90' },
  }

  /** Through the sandbox: the real CLI, on a controlling terminal. */
  const runSandboxed = (shellCommand: string, settings = SETTINGS) =>
    spawnSync(
      'python3',
      [CTTY, 'bun', CLI, '--settings', settings, '-c', shellCommand],
      SPAWN_OPTS,
    )

  /** The same harness with no sandbox in between, for control cases. */
  const runUnsandboxed = (...args: string[]) =>
    spawnSync('python3', [CTTY, ...args], SPAWN_OPTS)

  it('lets a sandboxed program enter raw mode with no allowPty key', () => {
    const res = runSandboxed('stty raw; echo "STTY-RC=$?"')
    expect(res.stdout).toContain('STTY-RC=0')
  })

  it('does not echo an injected KKP key encoding back as text (#391)', () => {
    // The byte-level reproduction of #391: write the Kitty Keyboard Protocol
    // encoding of Ctrl+C to the pty master and read back. A terminal left in
    // canonical+ECHO mode returns it verbatim, which is exactly the `^[[99;5u`
    // the issue reports seeing on screen; in raw mode nothing comes back.
    const res = spawnSync(
      'python3',
      [
        join(import.meta.dir, '../helpers/pty-kkp.py'),
        'bun',
        CLI,
        '--settings',
        SETTINGS,
        '-c',
        // The marker is the harness's injection trigger AND this test's
        // liveness proof: a child that died at startup echoes nothing, which
        // would otherwise be indistinguishable from a pass.
        'stty raw 2>/dev/null; echo KKP-CHILD-READY; sleep 3',
      ],
      { encoding: 'utf8', timeout: 120_000 },
    )

    expect(res.stdout).toContain('KKP-ECHOED=NO')
    expect(res.stdout).not.toContain('KKP-ECHOED=YES')
    expect(res.stdout).not.toContain('KKP-ECHOED=UNKNOWN')
  })

  // Control. Every TIOCSTI assertion below is only meaningful if the harness
  // really hands the child a CONTROLLING terminal, because macOS returns
  // EACCES for a terminal that is merely attached. This test fails if that
  // prerequisite ever breaks, so the denial tests cannot pass vacuously.
  it('proves the harness grants a controlling terminal: TIOCSTI works unsandboxed', () => {
    const res = runUnsandboxed('python3', '-c', TIOCSTI_PROBE)

    expect(res.stdout).toContain('TIOCSTI-ALLOWED')
    // The injected text is echoed back by the terminal, which is the injection
    // actually landing rather than merely being permitted.
    expect(res.stdout).toContain(INJECTED)
  })

  it('refuses keystroke injection with EPERM in the default mode', () => {
    const res = runSandboxed(`python3 -c '${TIOCSTI_PROBE}'`)

    expect(res.stdout).toContain('TIOCSTI-DENIED errno=1')
    expect(res.stdout).not.toContain('TIOCSTI-ALLOWED')
  })

  it('refuses keystroke injection with EPERM under allowPty: true', () => {
    // The broad mode grants ioctl over every pty, so this is where an
    // injection primitive would appear first if the rules ever widened.
    const res = runSandboxed(`python3 -c '${TIOCSTI_PROBE}'`, SETTINGS_BROAD)

    expect(res.stdout).toContain('TIOCSTI-DENIED errno=1')
    expect(res.stdout).not.toContain('TIOCSTI-ALLOWED')
  })
})
