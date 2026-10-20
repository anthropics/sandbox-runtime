import { spyOn } from 'bun:test'
import * as fs from 'node:fs'
import { setMountPointManifestPlacesForTesting } from '../../../src/sandbox/bwrap-mount-manifests.js'

// Whatever loads this is a process on a host of its own, as far as the mount
// point manifests can tell: the places that follow from the user id, and the
// /etc/passwd that says where the user's home is, are under $SRT_TEST_HOST (see
// makePlaces), the boot is $SRT_TEST_BOOT, and everything under
// $SRT_TEST_NETWORK is on NFS. Two processes that differ in the first two and
// have one home under the third are two hosts that mount one home. What it does
// not stand in for is what a network file system caches.
const { SRT_TEST_HOST, SRT_TEST_BOOT, SRT_TEST_NETWORK } = process.env
if (
  SRT_TEST_HOST === undefined ||
  SRT_TEST_BOOT === undefined ||
  SRT_TEST_NETWORK === undefined
) {
  throw new Error('a host needs its three variables')
}

const NFS_SUPER_MAGIC = 0x6969
const statfs = fs.statfsSync
spyOn(fs, 'statfsSync').mockImplementation(((
  p: unknown,
  ...rest: unknown[]
) => {
  const real = (statfs as (...args: unknown[]) => { type: number })(p, ...rest)
  return `${String(p)}/`.startsWith(`${SRT_TEST_NETWORK}/`)
    ? { ...real, type: NFS_SUPER_MAGIC }
    : real
}) as never)

const read = fs.readFileSync
spyOn(fs, 'readFileSync').mockImplementation(((
  file: unknown,
  ...rest: unknown[]
) =>
  file === '/proc/sys/kernel/random/boot_id'
    ? `${SRT_TEST_BOOT}\n`
    : (read as (...args: unknown[]) => unknown)(file, ...rest)) as never)

setMountPointManifestPlacesForTesting(SRT_TEST_HOST)

export * from '../../../src/sandbox/linux-sandbox-utils.js'
export {
  collectMountPoints,
  liveMountPoints,
  publishMountPointManifest,
} from '../../../src/sandbox/bwrap-mount-manifests.js'
