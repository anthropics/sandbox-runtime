import { describe, it, expect } from 'bun:test'
import { spawnSync } from 'node:child_process'
import { getApplySeccompBinaryPath } from '../../src/sandbox/generate-seccomp-filter.js'
import { whichSync } from '../../src/utils/which.js'
import { isLinux } from '../helpers/platform.js'

/**
 * Fault-injection coverage for the EINVAL fallback around
 * unshare(CLONE_NEWUSER) in apply-seccomp.c (anthropics/claude-code#86928).
 *
 * The real trigger, a multicall embedder (seccomp.argv0) calling in with a
 * non-empty thread group, cannot occur in the standalone binary: execve()
 * leaves it single-threaded. strace injects the EINVAL instead.
 *
 * unshare call order in the outer process: #1 is CLONE_NEWNS|CLONE_NEWPID
 * (EPERM when unprivileged), #2 is CLONE_NEWUSER. Each test asserts the
 * injection hit CLONE_NEWUSER, so a reordering fails loudly. strace counts
 * `when=` per tracee: without -f only the outer process is injected; with -f
 * the forked child's #2 (CLONE_NEWNS|CLONE_NEWPID after the user namespace)
 * is injected too.
 */

const strace = isLinux ? whichSync('strace') : null
const binary = isLinux ? getApplySeccompBinaryPath() : null
const isUnprivileged =
  typeof process.getuid === 'function' && process.getuid() !== 0

// ptrace may be unavailable (some containers); probe before committing.
const ptraceWorks =
  strace !== null &&
  spawnSync(strace, ['-qq', '-e', 'trace=exit_group', '/bin/true']).status === 0

function runInjected(
  follow: boolean,
  command: string[],
): { status: number | null; stdout: string; stderr: string } {
  const r = spawnSync(
    strace!,
    [
      ...(follow ? ['-f'] : []),
      '-qq',
      '-e',
      'trace=unshare',
      '-e',
      'inject=unshare:error=EINVAL:when=2',
      binary!,
      ...command,
    ],
    { encoding: 'utf8', timeout: 30_000 },
  )
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' }
}

function injectedLines(stderr: string): string[] {
  return stderr.split('\n').filter(line => line.includes('(INJECTED)'))
}

// The fallback lives on the unprivileged path (first unshare returns EPERM).
describe.if(isLinux && isUnprivileged && binary !== null && ptraceWorks)(
  'apply-seccomp unshare(CLONE_NEWUSER) EINVAL fallback',
  () => {
    it('continues in a forked child and relays its exit status', () => {
      const r = runInjected(false, ['/bin/sh', '-c', 'echo ran; exit 42'])
      const injected = injectedLines(r.stderr)
      expect(injected.length).toBe(1)
      expect(injected[0]).toContain('CLONE_NEWUSER')
      // Without the fallback this exits 1 with
      // "apply-seccomp: unshare(CLONE_NEWUSER): Invalid argument".
      expect(r.stderr).not.toContain('apply-seccomp:')
      expect(r.stdout).toContain('ran')
      expect(r.status).toBe(42)
    })

    it('still fails closed when setup fails in the forked child', () => {
      const r = runInjected(true, ['/bin/sh', '-c', 'echo ran'])
      const injected = injectedLines(r.stderr)
      expect(injected.length).toBe(2)
      expect(injected[0]).toContain('CLONE_NEWUSER')
      expect(r.stderr).toContain(
        'apply-seccomp: unshare(CLONE_NEWPID|CLONE_NEWNS) after userns',
      )
      expect(r.stdout).not.toContain('ran')
      expect(r.status).not.toBe(0)
    })
  },
)
