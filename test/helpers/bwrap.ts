import { spawnSync } from 'node:child_process'

/**
 * Whether bwrap can run the namespace/proc surface the wrapped commands use
 * (--unshare-pid, --unshare-user, --proc): a bare --ro-bind probe passes on
 * hosts where mounting a fresh /proc in the new PID namespace still EPERMs.
 * No --unshare-net, so a netns-restricted host does not skip tests that
 * never create one.
 */
export function bwrapCanNamespace(): boolean {
  return (
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
    ).status === 0
  )
}
