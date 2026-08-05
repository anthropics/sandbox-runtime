import { describe, it, expect, beforeAll, afterAll } from 'bun:test'
import { spawn, spawnSync } from 'node:child_process'
import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdtempSync,
  rmSync,
  statSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { getApplySeccompBinaryPath } from '../../src/sandbox/generate-seccomp-filter.js'
import { isLinux } from '../helpers/platform.js'

/**
 * Regression tests for running apply-seccomp as an execute-only binary
 * (mode 0111, as some managed environments install it).
 *
 * Exec'ing a binary the user cannot read makes the process non-dumpable,
 * which leaves /proc/self/{setgroups,uid_map,gid_map} root-owned. The
 * unprivileged fallback path (taken when the first unshare returns EPERM)
 * must temporarily raise PR_SET_DUMPABLE to write the uid/gid maps — and
 * restore it afterwards so the helper is not left ptrace-able by same-uid
 * processes.
 *
 * These tests are only meaningful without root: root can read the binary
 * regardless of its mode, so the non-dumpable condition never triggers
 * (CI's Linux legs run as the non-root `runner` user, so they do run
 * there). They also require the unprivileged fallback path itself, i.e.
 * no CAP_SYS_ADMIN — the same condition as the rest of this suite when
 * apply-seccomp is spawned directly.
 */

const isUnprivileged =
  typeof process.getuid === 'function' && process.getuid() !== 0

let applySeccomp: string | null = null
let workDir: string

function makeCopy(mode: number): string {
  const copy = join(workDir, `apply-seccomp-${mode.toString(8)}`)
  if (!existsSync(copy)) {
    copyFileSync(applySeccomp!, copy)
  }
  chmodSync(copy, mode)
  return copy
}

function runCopy(mode: number): {
  status: number | null
  stdout: string
  stderr: string
} {
  const r = spawnSync(makeCopy(mode), ['/bin/echo', 'ok'], {
    stdio: 'pipe',
    timeout: 10000,
  })
  return {
    status: r.status,
    stdout: r.stdout?.toString() ?? '',
    stderr: r.stderr?.toString() ?? '',
  }
}

/* Spawn a copy running `sleep`, wait for setup to finish, and return the
 * uid owning the outer helper's /proc entries — root iff dumpable is 0. */
async function procOwnerDuringRun(mode: number): Promise<number> {
  const child = spawn(makeCopy(mode), ['/bin/sleep', '3'], { stdio: 'ignore' })
  try {
    // Namespace setup is a handful of syscalls; 500ms is ample margin.
    await new Promise(resolve => setTimeout(resolve, 500))
    return statSync(`/proc/${child.pid}/environ`).uid
  } finally {
    child.kill('SIGKILL')
    await new Promise(resolve => child.on('exit', resolve))
  }
}

describe.if(isLinux && isUnprivileged)(
  'apply-seccomp as an execute-only binary',
  () => {
    beforeAll(() => {
      applySeccomp = getApplySeccompBinaryPath()
      expect(applySeccomp).toBeTruthy()
      expect(existsSync(applySeccomp!)).toBe(true)
      workDir = mkdtempSync(join(tmpdir(), 'srt-execute-only-'))
    })

    afterAll(() => {
      if (workDir) {
        rmSync(workDir, { recursive: true, force: true })
      }
    })

    it('sanity: a readable copy (0755) runs a command', () => {
      const r = runCopy(0o755)
      expect(r.stderr).toBe('')
      expect(r.status).toBe(0)
      expect(r.stdout).toContain('ok')
    })

    it('an execute-only copy (0111) still starts the sandbox', () => {
      // Without the temporary PR_SET_DUMPABLE bump this fails:
      //   apply-seccomp: write /proc/self/setgroups ...: Permission denied
      const r = runCopy(0o111)
      expect(r.stderr).toBe('')
      expect(r.status).toBe(0)
      expect(r.stdout).toContain('ok')
    })

    it('restores non-dumpable after setup for an execute-only copy', async () => {
      // dumpable=0 keeps /proc/<pid> root-owned; if the helper were left
      // dumpable, its /proc entries would belong to our own uid and any
      // same-uid process could ptrace it for the lifetime of the command.
      expect(await procOwnerDuringRun(0o111)).toBe(0)
    })

    it('preserves dumpable for a readable copy (save/restore, not force-0)', async () => {
      expect(await procOwnerDuringRun(0o755)).toBe(process.getuid!())
    })
  },
)
