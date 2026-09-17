import { spawnSync } from 'node:child_process'

let probed: boolean | undefined

/**
 * Whether bwrap here can run the same namespace/proc surface the wrapped
 * commands use (--unshare-pid/--unshare-user/--proc). A bare --ro-bind probe
 * passes on hosts where mounting a fresh /proc in the new PID namespace
 * still EPERMs, turning a live arm into a false red. No --unshare-net: the
 * suites pass needsNetworkRestriction: false, so the commands under test
 * never create a netns and the probe must not require one — a
 * netns-restricted host would otherwise silently skip the arm.
 *
 * Lazy and memoised: it spawns a process, which nothing that merely imports
 * a test helper should pay for.
 */
export function bwrapCanNamespace(): boolean {
  return (probed ??=
    spawnSync(
      'bwrap',
      [
        '--unshare-pid',
        '--unshare-user',
        '--cap-drop',
        'ALL',
        '--ro-bind',
        '/',
        '/',
        '--proc',
        '/proc',
        'true',
      ],
      { timeout: 5000 },
    ).status === 0)
}
