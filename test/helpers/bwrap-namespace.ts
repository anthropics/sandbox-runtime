import { spawnSync } from 'node:child_process'

function probe(extraArgs: string[]): boolean {
  return (
    spawnSync(
      'bwrap',
      [
        '--unshare-pid',
        '--unshare-user',
        ...extraArgs,
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

let probed: boolean | undefined
let probedWithNetwork: boolean | undefined

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
  return (probed ??= probe([]))
}

/**
 * The same probe with --unshare-net added, for the suites whose wrap does
 * restrict the network: that wrap creates a network namespace, which a host
 * can refuse while still granting the PID and user namespaces above. Kept
 * apart from {@link bwrapCanNamespace} so the suites that never create one
 * are not skipped along with these.
 */
export function bwrapCanNamespaceNetwork(): boolean {
  return (probedWithNetwork ??= probe(['--unshare-net']))
}
