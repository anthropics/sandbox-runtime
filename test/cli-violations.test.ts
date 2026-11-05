import { describe, it, expect, afterEach, beforeEach } from 'bun:test'
import { spawnSync } from 'child_process'
import * as fs from 'fs'
import * as os from 'os'
import * as path from 'path'
import { isMacOS, isWindows } from './helpers/platform.js'

// The built CLI, as control-fd.test.ts runs it: these cases are about what
// a caller of the `srt` binary can observe, which the barrel cannot show.
const CLI_PATH = path.join(process.cwd(), 'dist', 'cli.js')

// Same cap as control-fd.test.ts, and for the same reason: under bun's 5 s
// per-test default a hang has to name itself as a hang.
const EXIT_TIMEOUT_MS = 4500

// Seatbelt reports a refusal through `log stream`, which delivers after the
// fact; the wrapped command sleeps past its refused write so srt is still
// running when the line lands, and the file is then polled rather than read
// once, because "after the fact" has no fixed bound.
const VIOLATION_WAIT_MS = 3000
const POLL_MS = 100

function readWhen(
  file: string,
  predicate: (text: string) => boolean,
): Promise<string> {
  return new Promise((resolve, reject) => {
    const deadline = Date.now() + VIOLATION_WAIT_MS
    const tick = (): void => {
      const text = fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : ''
      if (predicate(text)) {
        resolve(text)
      } else if (Date.now() > deadline) {
        reject(
          new Error(
            `${file} did not match within ${VIOLATION_WAIT_MS}ms; contents:\n${text}`,
          ),
        )
      } else {
        setTimeout(tick, POLL_MS)
      }
    }
    tick()
  })
}

// /bin/bash for the wrapped script, and a seatbelt or bwrap to refuse the
// write; the Windows legs run neither.
describe.skipIf(isWindows)('--violations', () => {
  let tmpDir: string
  let settingsPath: string
  let forbiddenDir: string
  let reportPath: string

  function runSrt(args: string[]): {
    status: number | null
    stdout: string
    stderr: string
  } {
    const result = spawnSync('node', [CLI_PATH, ...args], {
      stdio: ['ignore', 'pipe', 'pipe'],
      encoding: 'utf8',
      timeout: EXIT_TIMEOUT_MS,
      // srt traps SIGTERM and only forwards it, so the default timeout
      // signal would leave a hung srt alive and spawnSync waiting forever.
      killSignal: 'SIGKILL',
    })
    if (result.error) {
      throw new Error(
        `srt did not exit within ${EXIT_TIMEOUT_MS}ms of the wrapped command: ${result.error.message}`,
      )
    }
    return {
      status: result.status,
      stdout: result.stdout,
      stderr: result.stderr,
    }
  }

  function writeScript(body: string): string {
    const script = path.join(tmpDir, 'test.sh')
    fs.writeFileSync(script, `#!/bin/bash\n${body}\n`, { mode: 0o755 })
    return script
  }

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'violations-test-'))
    forbiddenDir = path.join(tmpDir, 'forbidden')
    fs.mkdirSync(forbiddenDir)
    settingsPath = path.join(tmpDir, 'srt-settings.json')
    fs.writeFileSync(
      settingsPath,
      JSON.stringify({
        network: { allowedDomains: [], deniedDomains: [] },
        filesystem: { denyRead: [], allowWrite: [], denyWrite: [forbiddenDir] },
      }),
    )
    reportPath = path.join(tmpDir, 'violations.log')
  })

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true })
  })

  it('refuses to run the command when the report path is not writable', () => {
    // A parent directory that does not exist: the open fails before srt
    // builds anything, and the wrapped command must never have started.
    const script = writeScript('echo RAN')

    const { status, stdout, stderr } = runSrt([
      '--settings',
      settingsPath,
      '--violations',
      path.join(tmpDir, 'missing-dir', 'violations.log'),
      '--',
      script,
    ])

    expect(status).toBe(1)
    expect(stderr).toContain('--violations')
    expect(stderr).toContain('is not writable')
    expect(stdout).not.toContain('RAN')
  })

  it('creates the report and leaves a run with no refusals unchanged', () => {
    const script = writeScript('echo CLEAN_RUN')

    const { status, stdout } = runSrt([
      '--settings',
      settingsPath,
      '--violations',
      reportPath,
      '--',
      script,
    ])

    expect(status).toBe(0)
    expect(stdout).toContain('CLEAN_RUN')
    // Touched at start-up, so a caller can watch it from the first moment;
    // a clean run writes nothing into it.
    expect(fs.existsSync(reportPath)).toBe(true)
    expect(fs.readFileSync(reportPath, 'utf8')).not.toContain('file-write')
  })

  it('does not write a report when the flag is absent', () => {
    // Pins the default: the flag is the only thing that turns the report
    // on, so a run without it leaves no file behind.
    const script = writeScript(
      `echo x > ${path.join(forbiddenDir, 'f.txt')}\necho NO_FLAG_DONE`,
    )

    const { status, stdout } = runSrt([
      '--settings',
      settingsPath,
      '--',
      script,
    ])

    expect(status).toBe(0)
    expect(stdout).toContain('NO_FLAG_DONE')
    expect(fs.existsSync(reportPath)).toBe(false)
  })

  // Seatbelt is the producer this exercises. The Linux observer needs the
  // seccomp notify build and bwrap, which the unit legs do not set up.
  it.skipIf(!isMacOS)(
    'records a refused write with the path it was aimed at',
    async () => {
      // The sleep keeps srt alive while `log stream` delivers the deny; a
      // script that exits right after the refusal can beat its own report.
      const target = path.join(forbiddenDir, 'f.txt')
      const script = writeScript(
        `echo x > ${target}\nsleep 1.2\necho WRITE_DONE`,
      )

      const { status, stdout, stderr } = runSrt([
        '--settings',
        settingsPath,
        '--violations',
        reportPath,
        '--',
        script,
      ])

      // The refusal itself is unchanged: the command still sees it on its
      // own stderr and its exit status is its own (the script's last line).
      expect(status).toBe(0)
      expect(stdout).toContain('WRITE_DONE')
      expect(stderr).toContain('Operation not permitted')
      expect(fs.existsSync(target)).toBe(false)

      // Seatbelt reports the canonical path (/private/var/... for a /var/...
      // tmpdir), and it reports other refusals the shell makes along the way
      // (sysctl probes), so the line is looked for, not the whole file.
      const realTarget = fs.realpathSync(forbiddenDir) + '/f.txt'
      const report = await readWhen(reportPath, text =>
        text.includes(realTarget),
      )
      const line = report.split('\n').find(l => l.includes(realTarget))
      expect(line).toBeDefined()
      expect(line).toContain('deny(1) file-write-create')
    },
  )
})
