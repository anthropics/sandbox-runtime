import {
  describe,
  it,
  expect,
  beforeAll,
  afterAll,
  afterEach,
  spyOn,
} from 'bun:test'
import { spawnSync } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
} from 'node:fs'
import { connect } from 'node:net'
import { homedir, tmpdir } from 'node:os'
import { join } from 'node:path'

import { isLinux } from '../helpers/platform.js'
import * as linuxViolationMonitorModule from '../../src/sandbox/linux-violation-monitor.js'
import {
  startLinuxSandboxViolationMonitor,
  type LinuxViolationMonitor,
  type LinuxViolationMonitorOptions,
} from '../../src/sandbox/linux-violation-monitor.js'
import { getApplySeccompBinaryPath } from '../../src/sandbox/generate-seccomp-filter.js'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import {
  encodeSandboxedCommand,
  MAX_ENCODED_COMMAND_BYTES,
} from '../../src/sandbox/sandbox-utils.js'
import { sanitizeUnregisteredCommandKey } from '../../src/sandbox/sandbox-violation-store.js'

const d = isLinux ? describe : describe.skip

/** Simulate apply-seccomp's outer stub: connect and write JSON lines. */
const send = (socketPath: string, lines: string[]): Promise<void> =>
  new Promise((res, rej) => {
    const c = connect(socketPath, () => {
      c.write(lines.join('\n') + '\n')
      c.end()
    })
    c.on('close', () => res())
    c.on('error', rej)
  })

d('linux-violation-monitor (listener)', () => {
  let mon: LinuxViolationMonitor
  const violations: {
    line: string
    encodedCommand?: string
    command?: string
  }[] = []
  const allow = '/tmp/srt-test-allow'
  const deny = '/tmp/srt-test-allow/deny'

  beforeAll(async () => {
    mon = startLinuxSandboxViolationMonitor(
      v =>
        violations.push({
          line: v.line,
          encodedCommand: v.encodedCommand,
          command: v.command,
        }),
      {
        allowWritePaths: [allow, '/dev'],
        denyWritePaths: [deny],
        resolveCommandText: sanitizeUnregisteredCommandKey,
      },
    )
    await mon.ready
  })
  afterAll(() => mon.stop())

  it('binds a filesystem unix socket', () => {
    expect(mon.observeSocketPath).toBeDefined()
    expect(existsSync(mon.observeSocketPath!)).toBe(true)
  })

  it('filters allowed writes, surfaces denied writes', async () => {
    violations.length = 0
    await send(mon.observeSocketPath!, [
      JSON.stringify({ encodedCommand: 'dGVzdA==' }), // base64("test")
      JSON.stringify({ nr: 257, syscall: 'openat', path: `${allow}/ok` }),
      JSON.stringify({ nr: 257, syscall: 'openat', path: '/dev/null' }),
      JSON.stringify({ nr: 257, syscall: 'openat', path: `${deny}/bad` }),
      JSON.stringify({ nr: 263, syscall: 'unlinkat', path: '/etc/passwd' }),
    ])
    await new Promise(r => setTimeout(r, 50))
    expect(violations.map(v => v.line)).toEqual([
      `deny openat ${deny}/bad`,
      'deny unlinkat /etc/passwd',
    ])
    expect(violations[0].encodedCommand).toBe('dGVzdA==')
  })

  it('drops unresolved relative paths instead of guessing', async () => {
    // apply-seccomp resolves relative paths before emitting; a relative
    // path here means resolution failed. Best-effort telemetry: never
    // classify what could not be evaluated against policy.
    violations.length = 0
    await send(mon.observeSocketPath!, [
      JSON.stringify({ nr: 83, syscall: 'mkdir', path: 'rel/dir' }),
      JSON.stringify({ nr: 257, syscall: 'openat', path: '/etc/passwd' }),
    ])
    await new Promise(r => setTimeout(r, 50))
    expect(violations.map(v => v.line)).toEqual(['deny openat /etc/passwd'])
  })

  it('reports the normalized path it classified, not the spelling', async () => {
    violations.length = 0
    await send(mon.observeSocketPath!, [
      // inside allow once collapsed → not a violation
      JSON.stringify({ syscall: 'openat', path: `${allow}/sub/../ok` }),
      // escapes allow once collapsed → violation, under the collapsed path
      JSON.stringify({ syscall: 'openat', path: `${allow}/../escape` }),
    ])
    await new Promise(r => setTimeout(r, 50))
    expect(violations.map(v => v.line)).toEqual(['deny openat /tmp/escape'])
  })

  it('suppresses by the normalized path, so a detour cannot evade it', async () => {
    // `ignoreViolations` is matched against the same collapsed path the
    // policy check used: a `node_modules/..` detour neither smuggles a
    // suppression nor hides which file was written.
    const lines: string[] = []
    const mon2 = startLinuxSandboxViolationMonitor(v => lines.push(v.line), {
      allowWritePaths: ['/tmp/srt-ignore-allow'],
      denyWritePaths: [],
      ignoreViolations: { '*': ['node_modules'] },
      resolveCommandText: sanitizeUnregisteredCommandKey,
    })
    await mon2.ready
    try {
      await send(mon2.observeSocketPath!, [
        JSON.stringify({
          syscall: 'openat',
          path: '/home/u/.ssh/node_modules/../authorized_keys',
        }),
      ])
      await new Promise(r => setTimeout(r, 50))
      expect(lines).toEqual(['deny openat /home/u/.ssh/authorized_keys'])
    } finally {
      mon2.stop()
    }
  })

  it('handles concurrent connections (one per command)', async () => {
    violations.length = 0
    await Promise.all([
      send(mon.observeSocketPath!, [
        JSON.stringify({ syscall: 'openat', path: '/a' }),
      ]),
      send(mon.observeSocketPath!, [
        JSON.stringify({ syscall: 'openat', path: '/b' }),
      ]),
      send(mon.observeSocketPath!, [
        JSON.stringify({ syscall: 'openat', path: '/c' }),
      ]),
    ])
    await new Promise(r => setTimeout(r, 50))
    expect(violations.map(v => v.line).sort()).toEqual([
      'deny openat /a',
      'deny openat /b',
      'deny openat /c',
    ])
  })

  it('reports an unregistered attribution key as untrusted bytes', async () => {
    violations.length = 0
    await send(mon.observeSocketPath!, [
      JSON.stringify({
        encodedCommand: encodeSandboxedCommand('x<a>\u202eb\ncdef'),
      }),
      JSON.stringify({ syscall: 'openat', path: '/etc/passwd' }),
    ])
    await new Promise(r => setTimeout(r, 50))
    expect(violations.map(v => v.command)).toEqual(['xa b cdef'])
  })

  it('drops an attribution longer than a minted key, keeping the violation', async () => {
    violations.length = 0
    await send(mon.observeSocketPath!, [
      JSON.stringify({ encodedCommand: 'A'.repeat(MAX_ENCODED_COMMAND_BYTES) }),
      JSON.stringify({ syscall: 'openat', path: '/etc/one' }),
    ])
    await send(mon.observeSocketPath!, [
      JSON.stringify({
        encodedCommand: 'A'.repeat(MAX_ENCODED_COMMAND_BYTES + 1),
      }),
      JSON.stringify({ syscall: 'openat', path: '/etc/two' }),
    ])
    await new Promise(r => setTimeout(r, 50))
    expect(violations.map(v => v.line).sort()).toEqual([
      'deny openat /etc/one',
      'deny openat /etc/two',
    ])
    const oversized = violations.find(v => v.line.endsWith('/etc/two'))!
    expect(oversized.encodedCommand).toBeUndefined()
    expect(oversized.command).toBeUndefined()
    expect(
      violations.find(v => v.line.endsWith('/etc/one'))!.encodedCommand,
    ).toBeDefined()
  })

  it('ignores malformed lines and observe_init_error', async () => {
    violations.length = 0
    await send(mon.observeSocketPath!, [
      'not json',
      JSON.stringify({ observe_init_error: 'seccomp: EINVAL' }),
      JSON.stringify({ nr: 257 }), // no path
      JSON.stringify({ syscall: 'openat', path: '/x' }),
    ])
    await new Promise(r => setTimeout(r, 50))
    expect(violations.map(v => v.line)).toEqual(['deny openat /x'])
  })
})

// End-to-end against the real binary. Skipped if the vendored binary is
// missing for this arch (e.g. CI hasn't rebuilt it yet).
const applyPath = isLinux ? getApplySeccompBinaryPath() : null
const de = applyPath && existsSync(applyPath) ? describe : describe.skip

de('linux-violation-monitor + apply-seccomp (e2e)', () => {
  const work = mkdtempSync(join(tmpdir(), 'srt-vmon-'))
  const allow = join(work, 'rw')
  const deny = join(work, 'ro')
  let mon: LinuxViolationMonitor
  const violations: string[] = []

  beforeAll(async () => {
    spawnSync('mkdir', ['-p', allow, deny])
    mon = startLinuxSandboxViolationMonitor(v => violations.push(v.line), {
      allowWritePaths: [allow, '/dev'],
      denyWritePaths: [deny],
      resolveCommandText: sanitizeUnregisteredCommandKey,
    })
    await mon.ready
  })
  afterAll(() => {
    mon.stop()
    rmSync(work, { recursive: true, force: true })
  })

  it('captures write-intent paths from a real workload', async () => {
    const r = spawnSync(
      applyPath!,
      ['/bin/sh', '-c', `echo a > ${allow}/ok; echo b > ${deny}/bad`],
      {
        env: {
          ...process.env,
          SRT_OBSERVE_SOCK: mon.observeSocketPath!,
        },
      },
    )
    expect(r.status).toBe(0)
    await new Promise(r => setTimeout(r, 100))
    expect(violations).toContain(`deny openat ${deny}/bad`)
    expect(violations.some(v => v.includes(`${allow}/ok`))).toBe(false)
  })

  it('resolves relative paths against the workload cwd', async () => {
    violations.length = 0
    const r = spawnSync(
      applyPath!,
      [
        '/bin/sh',
        '-c',
        // Allowed relative write, then a relative write that escapes into
        // the deny dir — both spelled relative, resolved by the supervisor.
        `cd ${allow} && echo a > rel-ok.txt && echo b > ../ro/rel-bad.txt`,
      ],
      { env: { ...process.env, SRT_OBSERVE_SOCK: mon.observeSocketPath! } },
    )
    expect(r.status).toBe(0)
    await new Promise(r => setTimeout(r, 100))
    // The allowed relative write resolved inside allow → no violation.
    expect(violations.some(v => v.includes('rel-ok.txt'))).toBe(false)
    // The escaping relative write resolved into deny → violation, reported
    // under the collapsed path.
    expect(violations).toContain(`deny openat ${deny}/rel-bad.txt`)
  })

  it('does not hang when the listener stops reading (full pipe drops)', () => {
    // The event pipe is a bounded queue; a stalled consumer must cost
    // log lines, never workload time. 3000 writes far exceeds the pipe
    // capacity — pre-fix this froze at the first full-pipe write.
    const stall = startLinuxSandboxViolationMonitor(() => {}, {
      allowWritePaths: ['/'],
      denyWritePaths: [],
      resolveCommandText: sanitizeUnregisteredCommandKey,
    })
    return stall.ready.then(() => {
      const dir = mkdtempSync(join(tmpdir(), 'srt-vmon-stall-'))
      try {
        const t0 = Date.now()
        const r = spawnSync(
          applyPath!,
          [
            '/bin/sh',
            '-c',
            `cd ${dir} && i=0; while [ $i -lt 3000 ]; do echo x > f$i; i=$((i+1)); done && echo DONE`,
          ],
          {
            env: { ...process.env, SRT_OBSERVE_SOCK: stall.observeSocketPath! },
            timeout: 20_000,
          },
        )
        expect(r.status).toBe(0)
        expect(String(r.stdout)).toContain('DONE')
        expect(Date.now() - t0).toBeLessThan(15_000)
      } finally {
        stall.stop()
        rmSync(dir, { recursive: true, force: true })
      }
    })
  }, 30_000)

  it('does not hang when the listener is unreachable', () => {
    const t0 = Date.now()
    const r = spawnSync(
      applyPath!,
      ['/bin/sh', '-c', `echo a > ${allow}/ok2; exit 5`],
      {
        env: { ...process.env, SRT_OBSERVE_SOCK: '/nonexistent/sock' },
        timeout: 5000,
      },
    )
    expect(r.status).toBe(5)
    expect(Date.now() - t0).toBeLessThan(3000)
  })

  it('reports signal death as 128+signal', () => {
    // The namespace init cannot distinguish a worker's exit(128+N) from
    // a real signal death, so the status is relayed verbatim as an exit
    // code; the layer above (bwrap) applies its own normalization.
    const r = spawnSync(applyPath!, ['/bin/sh', '-c', 'kill -TERM $$'])
    expect(r.status).toBe(128 + 15)
  })
})

d('the write configuration the manager hands the monitor', () => {
  // `~`-spelled, relative and glob entries reach the monitor as configured,
  // while the paths it classifies come from the kernel; and bwrap refuses
  // more than the configuration names, because it adds the built-in write
  // denies on top. The fixture is a real tree: bwrap skips a write allow
  // path that does not exist, so a non-existent one would prove nothing.
  const NAME = `srt-monitor-allow-${randomBytes(4).toString('hex')}`
  const HOME_SPELLING = join(homedir(), NAME)
  let ALLOW: string
  let DENY: string
  let originalCwd: string

  beforeAll(() => {
    originalCwd = process.cwd()
    mkdirSync(join(HOME_SPELLING, 'secrets'), { recursive: true })
    mkdirSync(join(HOME_SPELLING, '.git', 'hooks'), { recursive: true })
    ALLOW = realpathSync(HOME_SPELLING)
    DENY = join(ALLOW, 'secrets')
  })
  afterAll(() => rmSync(HOME_SPELLING, { recursive: true, force: true }))

  afterEach(async () => {
    process.chdir(originalCwd)
    await SandboxManager.reset()
  })

  it('classifies a ~ allow, a ~ deny and a built-in deny the way bwrap does', async () => {
    let handedOver: LinuxViolationMonitorOptions | undefined
    const spy = spyOn(
      linuxViolationMonitorModule,
      'startLinuxSandboxViolationMonitor',
    ).mockImplementation((_callback, opts) => {
      handedOver = opts
      return {
        observeSocketPath: undefined,
        ready: Promise.resolve(),
        stop: () => {},
      }
    })
    try {
      // The built-in denies are resolved against the cwd of the initialize()
      // call, so make that the tree the allow rule covers.
      process.chdir(ALLOW)
      await SandboxManager.initialize(
        {
          network: { allowedDomains: [], deniedDomains: [] },
          filesystem: {
            denyRead: [],
            allowWrite: [`~/${NAME}`, `~/${NAME}/g/*`],
            denyWrite: [`~/${NAME}/secrets`],
          },
        },
        undefined,
        true,
      )
    } finally {
      process.chdir(originalCwd)
      spy.mockRestore()
    }
    expect(handedOver).toBeDefined()
    // A glob is dropped, not kept as a prefix: bwrap never binds one, so
    // treating it as an allow would excuse writes bwrap refuses.
    expect(handedOver!.allowWritePaths.some(p => p.includes('*'))).toBe(false)

    // Drive the real listener with exactly what the manager handed over.
    const lines: string[] = []
    const monitor = startLinuxSandboxViolationMonitor(
      v => lines.push(v.line),
      handedOver!,
    )
    await monitor.ready
    try {
      await send(monitor.observeSocketPath!, [
        JSON.stringify({ syscall: 'openat', path: `${ALLOW}/file` }),
        JSON.stringify({ syscall: 'openat', path: `${DENY}/token` }),
        JSON.stringify({
          syscall: 'openat',
          path: `${ALLOW}/.git/hooks/pre-commit`,
        }),
      ])
      await new Promise(r => setTimeout(r, 50))
      expect(lines).toEqual([
        `deny openat ${DENY}/token`,
        `deny openat ${ALLOW}/.git/hooks/pre-commit`,
      ])
    } finally {
      monitor.stop()
    }
  }, 30_000)
})
