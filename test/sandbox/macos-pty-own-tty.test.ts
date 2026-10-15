import { describe, it, expect, beforeAll, afterAll, afterEach } from 'bun:test'
import { spawn, spawnSync } from 'node:child_process'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createInterface } from 'node:readline'
import {
  assertPtySlavePaths,
  wrapCommandWithSandboxMacOS,
} from '../../src/sandbox/macos-sandbox-utils.js'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import type { FsWriteRestrictionConfig } from '../../src/sandbox/sandbox-schemas.js'
import { isLinux, isMacOS } from '../helpers/platform.js'

const HELPER = join(import.meta.dir, '..', 'helpers', 'pty-own.py')
const hasPython =
  spawnSync('python3', ['-c', 'import pty'], { stdio: 'ignore' }).status === 0

type Ttys = { own: string; other: string }

/**
 * Runs `build(ttys)` on a pty that is its controlling terminal, where `ttys`
 * names that pty and a second one the command must not reach.
 */
async function runOnOwnPty(
  build: (ttys: Ttys) => string,
): Promise<{ status: number | null; output: string; ttys: Ttys }> {
  const child = spawn('python3', [HELPER], {
    stdio: ['pipe', 'pipe', 'inherit'],
  })
  const lines = createInterface({ input: child.stdout })[Symbol.asyncIterator]()
  const ttys = JSON.parse((await lines.next()).value) as Ttys
  child.stdin.end(JSON.stringify({ command: build(ttys), timeout: 10 }) + '\n')
  const result = JSON.parse((await lines.next()).value)
  return { ...result, ttys }
}

describe('assertPtySlavePaths', () => {
  it('accepts pty slave device paths', () => {
    expect(() =>
      assertPtySlavePaths(['/dev/ttys000', '/dev/ttys012', '/dev/ttys1000']),
    ).not.toThrow()
  })

  it.each([
    '/dev/ttys*',
    '/dev/ttys',
    '/dev/ttys01',
    '/dev/tty',
    '/dev/ptmx',
    '/dev/ttyp0',
    'ttys012',
    '/dev/ttys012/',
    '/dev/../dev/ttys012',
    '/dev/ttys012\n',
    '/dev/ttys012") (allow default',
    '',
  ])('refuses %p', device => {
    expect(() => assertPtySlavePaths([device])).toThrow(/not a pty slave/)
  })
})

describe.if(isLinux || isMacOS)('wrapWithSandbox: the ttys option', () => {
  afterEach(async () => {
    await SandboxManager.reset()
  })

  const init = () =>
    SandboxManager.initialize({
      network: { allowedDomains: [], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: [tmpdir()], denyWrite: [] },
    })

  it.if(isMacOS)('reaches the macOS profile', async () => {
    await init()
    const wrapped = await SandboxManager.wrapWithSandbox(
      'true',
      undefined,
      undefined,
      undefined,
      { ttys: ['/dev/ttys012'] },
    )
    expect(wrapped).toContain('(allow file-ioctl (literal "/dev/ttys012"))')
  })

  it('refuses a malformed entry on every platform', async () => {
    await init()
    const outcome = await SandboxManager.wrapWithSandbox(
      'true',
      undefined,
      undefined,
      undefined,
      { ttys: ['/dev/ttys*'] },
    ).then(
      () => 'wrapped',
      (err: unknown) => String(err),
    )
    expect(outcome).toMatch(/not a pty slave/)
  })
})

describe('macOS profile: ttys', () => {
  const writeConfig: FsWriteRestrictionConfig = {
    allowOnly: [tmpdir()],
    denyWithinAllow: [],
  }
  const wrap = (extra: { allowPty?: boolean; ttys?: string[] }) =>
    wrapCommandWithSandboxMacOS({
      command: 'true',
      needsNetworkRestriction: false,
      readConfig: undefined,
      writeConfig,
      ...extra,
    })

  it('grants file-ioctl on each named device as a literal', () => {
    const wrapped = wrap({ ttys: ['/dev/ttys012'] })
    expect(wrapped).toContain('(allow file-ioctl (literal "/dev/ttys012"))')
    expect(wrapped).not.toContain('^/dev/ttys')
    expect(wrapped).not.toContain('(allow pseudo-tty)')
  })

  it('adds no pty rule without ttys', () => {
    expect(wrap({})).not.toContain('/dev/ttys')
  })

  it('leaves allowPty: true as it was', () => {
    expect(wrap({ allowPty: true, ttys: ['/dev/ttys012'] })).toBe(
      wrap({ allowPty: true }),
    )
  })

  it('refuses a malformed entry before wrapping', () => {
    expect(() => wrap({ ttys: ['/dev/ttys*'] })).toThrow(/not a pty slave/)
  })

  it('refuses a malformed entry even when nothing is restricted', () => {
    expect(() =>
      wrapCommandWithSandboxMacOS({
        command: 'true',
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig: undefined,
        ttys: ['/dev/ttys*'],
      }),
    ).toThrow(/not a pty slave/)
  })
})

describe.if(isMacOS && hasPython)('macOS: a shell on its own pty', () => {
  let base: string
  beforeAll(() => {
    base = mkdtempSync(join(tmpdir(), 'srt-own-tty-'))
  })
  afterAll(() => {
    rmSync(base, { recursive: true, force: true })
  })

  const wrap = (command: string, ttys?: string[], allowPty?: boolean) =>
    wrapCommandWithSandboxMacOS({
      command,
      needsNetworkRestriction: false,
      readConfig: undefined,
      writeConfig: { allowOnly: [base], denyWithinAllow: [] },
      ttys,
      allowPty,
    })

  const REACH_OTHER = (other: string) =>
    `stty -a <${other} >/dev/null 2>&1 && echo OTHER_OPEN || echo OTHER_DENIED; ` +
    `stty -echo <${other} 2>/dev/null && echo OTHER_SET || echo OTHER_SET_DENIED`

  // `stty -echo` is TIOCSETA, what a line editor does at every prompt. Under
  // `set -m` the shell gives a foreground job the terminal with TIOCSPGRP,
  // so the job's process group is the terminal's: that is job control.
  const TERMINAL_WORK =
    'stty -echo && stty echo && stty -a >/dev/null && echo STTY_OK; ' +
    'set -m; python3 -c "import os; ' +
    "print('FG_OK' if os.tcgetpgrp(0) == os.getpgrp() else 'FG_NOT_OWNED')\""

  it('cannot set its terminal without a grant', async () => {
    const { output } = await runOnOwnPty(() => wrap(TERMINAL_WORK))
    expect(output).not.toMatch(/^STTY_OK\r?$/m)
    expect(output).not.toMatch(/^FG_OK\r?$/m)
  })

  it('sets its own terminal and runs job control with ttys', async () => {
    const { status, output } = await runOnOwnPty(({ own }) =>
      wrap(TERMINAL_WORK, [own]),
    )
    expect(output).toMatch(/^STTY_OK\r?$/m)
    expect(output).toMatch(/^FG_OK\r?$/m)
    expect(status).toBe(0)
  })

  it('still cannot reach another terminal', async () => {
    const { output, ttys } = await runOnOwnPty(({ own, other }) =>
      wrap(REACH_OTHER(other), [own]),
    )
    expect(ttys.own).not.toBe(ttys.other)
    expect(output).toMatch(/^OTHER_DENIED\r?$/m)
    expect(output).toMatch(/^OTHER_SET_DENIED\r?$/m)
  })

  it('reaches another terminal under allowPty: true (control)', async () => {
    const { output } = await runOnOwnPty(({ other }) =>
      wrap(REACH_OTHER(other), undefined, true),
    )
    expect(output).toMatch(/^OTHER_OPEN\r?$/m)
    expect(output).toMatch(/^OTHER_SET\r?$/m)
  })
})
