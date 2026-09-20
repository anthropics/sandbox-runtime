/**
 * Which mount points on the host a running sandbox still relies on (Linux).
 *
 * A deny on a path that does not exist needs a mount point there: bwrap makes
 * an empty file (or, for an intermediate component, an empty directory) on the
 * host and binds /dev/null or an empty directory over it. Unlinking that file
 * while a sandbox is still bound over it detaches the mount inside that
 * sandbox — the denied path can then be created, and what is written lands on
 * the host. A mount point may therefore only be removed when no running
 * sandbox relies on it, and nothing a process counts for itself can decide
 * that: a second srt process, a caller that crashes, one that cleans up early,
 * twice or never, each gets a different answer.
 *
 * The kernel is asked instead. Each wrap writes a manifest naming the mount
 * points it relies on into a per-user runtime directory and passes
 * `--lock-file <manifest>` to bwrap. bubblewrap's sandbox init process opens
 * that path and holds an fcntl read lock (F_RDLCK through F_SETLK) on it for
 * exactly the sandbox's lifetime; the kernel drops the lock however the
 * sandbox ends, SIGKILL included. /proc/locks then answers, for any process
 * and at any moment, whether a sandbox that named a mount point is still
 * running, so cleanup becomes a garbage collect any process may run at any
 * time and any number of times: a mount point goes only when no live manifest
 * names it.
 *
 * The lock belongs to the sandbox's init process, not to the command: bwrap
 * opens the manifest with O_CLOEXEC, so the descriptor does not survive the
 * exec into the command, and a POSIX lock is only dropped by the process that
 * took it. The directory is bound read-only into every sandbox whose
 * invocation names a manifest in it, so a sandboxed command can neither
 * delete nor rewrite one.
 */

import { randomBytes } from 'node:crypto'
import * as fs from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { z } from 'zod'
import { logForDebugging } from '../utils/debug.js'
import { isAbsenceErrno } from './sandbox-utils.js'

/** The only manifest layout this version writes and reads. */
const MANIFEST_VERSION = 1
const MANIFEST_SUFFIX = '.json'

/**
 * A manifest written this recently counts as live even with no lock on it and
 * its writer gone. bubblewrap takes the lock in the sandbox's init process,
 * which it forks alongside the command, so a wrapping process killed between
 * the exec and that fcntl would otherwise leave a starting sandbox's mount
 * point unclaimed. The window to cover is bubblewrap's own startup, a few
 * milliseconds; this is two orders of magnitude more, and short enough that a
 * mount point a killed process left behind is collectable while the command
 * after it is still being wrapped.
 */
const MANIFEST_GRACE_MS = 500

/** How long a collect or a publish waits for the directory lock. */
const DIRECTORY_LOCK_WAIT_MS = 2_000

/** Between attempts at the directory lock. */
const DIRECTORY_LOCK_RETRY_MS = 25

/**
 * A directory lock this old is broken, for a process that died between taking
 * it and the unlink. Far past the milliseconds a collect takes.
 */
const DIRECTORY_LOCK_STALE_MS = 60_000

/**
 * A manifest whose contents cannot be read is dropped once it is this old and
 * no sandbox holds its lock — long past anything that could still be using
 * what it names, and long enough that another version of this library writing
 * to the same directory keeps its manifests for as long as it needs them.
 */
const UNREADABLE_MANIFEST_MAX_AGE_MS = 60 * 60 * 1000

const ManifestSchema = z.object({
  version: z.literal(MANIFEST_VERSION),
  /** The process that wrapped, and its start time, to tell a recycled pid. */
  pid: z.number().int().nonnegative(),
  start: z.string(),
  /** When the manifest was written, for {@link MANIFEST_GRACE_MS}. */
  created: z.number(),
  /** The mount points bwrap makes on the host for that wrap's deny paths. */
  paths: z.array(z.string()),
  /**
   * The empty directories those mount points bind FROM, which this library
   * makes itself. A live bind's source must stay, so they go the same way the
   * mount points do, and are held to what {@link removeMountSource} asks: a
   * source that is no longer our own private empty directory is not ours to
   * remove.
   */
  sources: z.array(z.string()),
})

type Manifest = z.infer<typeof ManifestSchema> & {
  file: string
  /** The inode /proc/locks reports a lock on. */
  inode: number
  /**
   * Whether this process has taken the manifest away: it wrote it, the caller
   * says the command is done, and nothing held the lock. Only a lock can still
   * make it live, and only for the moment between that reading and the unlink
   * — the path is gone, so no further sandbox can open it.
   */
  released: boolean
}

/** Manifests this process wrote and has not released. */
const ownManifests = new Set<string>()

let manifestDirectory: string | undefined
let directoryFailureLogged = false

/**
 * Field 22 of /proc/PID/stat, the process's start time in clock ticks. The
 * comm field can hold spaces and parentheses, so the fields are counted from
 * the last ')' rather than from the start of the line.
 */
function startTimeFromProcStat(stat: string): string | undefined {
  return stat
    .slice(stat.lastIndexOf(')') + 1)
    .trim()
    .split(' ')[19]
}

function processStartTime(pid: number): string | undefined {
  try {
    return startTimeFromProcStat(fs.readFileSync(`/proc/${pid}/stat`, 'utf8'))
  } catch {
    return undefined
  }
}

/**
 * Whether the process a manifest names is still running. Only "the process is
 * gone" answers no: a /proc that cannot be read must not make a live sandbox's
 * manifest collectable.
 */
function writerIsRunning(pid: number, start: string): boolean {
  try {
    return (
      startTimeFromProcStat(fs.readFileSync(`/proc/${pid}/stat`, 'utf8')) ===
      start
    )
  } catch (e) {
    return !isAbsenceErrno(e)
  }
}

/**
 * The inodes /proc/locks reports a lock on, of any kind. Any lock on a
 * manifest is the one bubblewrap's sandbox init holds — nothing else opens one
 * to lock it — and the device is deliberately not compared: a filesystem whose
 * /proc/locks device differs from the one stat reports (an overlay, a bind of
 * a subvolume) would otherwise hide a live sandbox's lock, while an inode
 * number colliding with an unrelated locked file's only keeps a mount point
 * around longer.
 *
 * `undefined` when the list could not be read, which every caller reads as
 * "every manifest is locked".
 */
function lockedInodes(): Set<number> | undefined {
  let text: string
  try {
    text = fs.readFileSync('/proc/locks', 'utf8')
  } catch (e) {
    logForDebugging(
      `[Sandbox Linux] /proc/locks could not be read (${String(e)}) - leaving every mount point where it is`,
      { level: 'warn' },
    )
    return undefined
  }
  const inodes = new Set<number>()
  for (const line of text.split('\n')) {
    // The major:minor:inode word, which sits one field later on the lines that
    // describe a blocked request ("2: -> POSIX ADVISORY WRITE ...").
    for (const word of line.split(/\s+/)) {
      const match = /^[0-9a-f]+:[0-9a-f]+:(\d+)$/.exec(word)
      if (match?.[1] !== undefined) {
        inodes.add(Number(match[1]))
        break
      }
    }
  }
  return inodes
}

/** Whether `dir` is a directory of ours that nobody else can write. */
function isOurPrivateDirectory(dir: string): boolean {
  try {
    const stat = fs.lstatSync(dir)
    return (
      stat.isDirectory() &&
      stat.uid === process.getuid?.() &&
      (stat.mode & 0o077) === 0
    )
  } catch {
    return false
  }
}

function makeOurPrivateDirectory(dir: string): boolean {
  try {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 })
    // mkdir asks for 0700 but the umask applies, and a directory an earlier
    // run left keeps the mode it was made with, so set it here rather than let
    // the check below reject a directory that is ours.
    fs.chmodSync(dir, 0o700)
  } catch {
    // Someone else's directory at that name, or a filesystem that will not
    // take one: the check below decides.
  }
  return isOurPrivateDirectory(dir)
}

/**
 * The directory manifests live in: under $XDG_RUNTIME_DIR when there is one,
 * else a per-user directory under the system temp dir, else — when neither can
 * be made ours alone, as in a sandbox that binds them read-only — a private
 * directory only this process knows, which keeps the guarantee within this
 * process and loses only what other processes would have read.
 *
 * Revalidated on every use: the temp dir is somewhere sandboxed commands
 * commonly write, and a directory swapped for a symlink between two wraps
 * would put manifests somewhere else entirely.
 */
function ensureManifestDirectory(): string | undefined {
  if (
    manifestDirectory !== undefined &&
    isOurPrivateDirectory(manifestDirectory)
  ) {
    return manifestDirectory
  }
  const runtimeDir = process.env['XDG_RUNTIME_DIR']
  const shared =
    runtimeDir !== undefined && path.isAbsolute(runtimeDir)
      ? [path.join(runtimeDir, 'srt-mount-points')]
      : []
  shared.push(
    path.join(tmpdir(), `srt-mount-points-${process.getuid?.() ?? 0}`),
  )
  for (const candidate of shared) {
    if (makeOurPrivateDirectory(candidate)) {
      manifestDirectory = candidate
      return candidate
    }
  }
  try {
    const private_ = fs.mkdtempSync(path.join(tmpdir(), 'srt-mount-points-'))
    fs.chmodSync(private_, 0o700)
    manifestDirectory = private_
    logForDebugging(
      `[Sandbox Linux] No shared directory for mount point manifests, using one only this process knows: ${private_}`,
      { level: 'warn' },
    )
    return private_
  } catch (e) {
    manifestDirectory = undefined
    if (!directoryFailureLogged) {
      directoryFailureLogged = true
      logForDebugging(
        `[Sandbox Linux] No directory for mount point manifests (${String(e)}) - the mount points this process makes are left on the host`,
        { level: 'warn' },
      )
    }
    return undefined
  }
}

/** Block this thread, the only sleep available to a synchronous cleanup. */
function sleep(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms)
}

/** Break a directory lock whose holder is gone, or that is simply too old. */
function breakStaleDirectoryLock(lockFile: string): boolean {
  let holder: string
  let age: number
  try {
    const fd = fs.openSync(lockFile, 'r')
    try {
      age = Date.now() - fs.fstatSync(fd).mtimeMs
      holder = fs.readFileSync(fd, 'utf8')
    } finally {
      fs.closeSync(fd)
    }
  } catch {
    // Gone between the failed create and this read: the next attempt takes it.
    return true
  }
  const [pid, start] = holder.trim().split(' ')
  const held =
    pid !== undefined &&
    start !== undefined &&
    writerIsRunning(Number(pid), start) &&
    age < DIRECTORY_LOCK_STALE_MS
  if (held) {
    return false
  }
  try {
    fs.unlinkSync(lockFile)
  } catch {
    // Another process broke it first.
  }
  return true
}

/**
 * Run `body` while holding the manifest directory's lock, so a collect works
 * from a set of manifests no other srt process is changing under it, and
 * report whether it ran.
 *
 * The lock serialises srt processes; it is not what makes a mount point safe
 * to remove. That is the kernel's answer about each manifest, re-read
 * immediately before every unlink, which is also what covers the one actor
 * outside this lock: the bubblewrap a wrap has already handed to its caller.
 */
function withDirectoryLock<T>(
  dir: string,
  body: () => T,
): { ran: true; value: T } | { ran: false } {
  const lockFile = path.join(dir, 'directory.lock')
  const deadline = Date.now() + DIRECTORY_LOCK_WAIT_MS
  for (;;) {
    let fd: number
    try {
      fd = fs.openSync(lockFile, 'wx', 0o600)
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== 'EEXIST') {
        return { ran: false }
      }
      if (!breakStaleDirectoryLock(lockFile) && Date.now() >= deadline) {
        return { ran: false }
      }
      sleep(DIRECTORY_LOCK_RETRY_MS)
      continue
    }
    try {
      fs.writeSync(
        fd,
        `${process.pid} ${processStartTime(process.pid) ?? ''}\n`,
      )
    } catch {
      // A holder that cannot be identified is broken by age alone.
    } finally {
      fs.closeSync(fd)
    }
    try {
      return { ran: true, value: body() }
    } finally {
      try {
        fs.unlinkSync(lockFile)
      } catch {
        // Broken by another process while we held it: nothing to undo.
      }
    }
  }
}

function readManifest(file: string): Manifest | undefined {
  let inode: number
  let text: string
  try {
    const fd = fs.openSync(file, 'r')
    try {
      inode = fs.fstatSync(fd).ino
      text = fs.readFileSync(fd, 'utf8')
    } finally {
      fs.closeSync(fd)
    }
  } catch {
    return undefined
  }
  let json: unknown
  try {
    json = JSON.parse(text)
  } catch {
    return undefined
  }
  const parsed = ManifestSchema.safeParse(json)
  return parsed.success
    ? { ...parsed.data, file, inode, released: false }
    : undefined
}

/** Whether a sandbox that named this manifest may still be running. */
function isLive(manifest: Manifest, locked: Set<number>): boolean {
  if (locked.has(manifest.inode)) {
    return true
  }
  if (manifest.released) {
    return false
  }
  return (
    Date.now() - manifest.created < MANIFEST_GRACE_MS ||
    writerIsRunning(manifest.pid, manifest.start)
  )
}

/**
 * Remove an empty directory a placeholder bound from, if it is still our own.
 * It sits under the system temp dir, which sandboxed commands commonly can
 * write, so anything that is not a private empty directory of ours — a
 * symlink, a directory whose mode has been widened, one with something in it —
 * is somebody else's and is left exactly as found.
 */
function removeMountSource(source: string): boolean {
  try {
    const stat = fs.lstatSync(source)
    if (
      !stat.isDirectory() ||
      stat.uid !== process.getuid?.() ||
      (stat.mode & 0o077) !== 0 ||
      fs.readdirSync(source).length > 0
    ) {
      logForDebugging(
        `[Sandbox Linux] Left the empty-directory mount source behind, it is no longer our own empty directory: ${source}`,
      )
      return false
    }
    fs.rmdirSync(source)
    logForDebugging(
      `[Sandbox Linux] Cleaned up the empty-directory mount source: ${source}`,
    )
    return true
  } catch {
    // Gone, or no longer ours to look at.
  }
  return false
}

/**
 * Remove a mount point, if it is still the empty file or directory bwrap made.
 * Anything with content, or a directory something has written into, is left
 * where it is.
 */
function removeMountPoint(mountPoint: string): boolean {
  try {
    const stat = fs.statSync(mountPoint)
    if (stat.isFile() && stat.size === 0) {
      fs.unlinkSync(mountPoint)
      logForDebugging(
        `[Sandbox Linux] Cleaned up bwrap mount point (file): ${mountPoint}`,
      )
      return true
    }
    if (stat.isDirectory()) {
      if (fs.readdirSync(mountPoint).length > 0) {
        logForDebugging(
          `[Sandbox Linux] Left a bwrap mount point directory behind, something has written into it: ${mountPoint}`,
        )
        return false
      }
      // rmdir, not a recursive remove: it neither follows a symlink nor
      // descends, so a path that is no longer ours is left exactly as found.
      fs.rmdirSync(mountPoint)
      logForDebugging(
        `[Sandbox Linux] Cleaned up bwrap mount point (dir): ${mountPoint}`,
      )
      return true
    }
  } catch {
    // Already gone, or no longer ours to look at.
  }
  return false
}

/** What {@link publishMountPointManifest} wrote, for the bwrap invocation. */
export type MountPointManifest = {
  /** The directory to bind read-only inside the sandbox. */
  dir: string
  /** The manifest, for bubblewrap's --lock-file. */
  file: string
}

/**
 * Record the mount points this wrap relies on, and the empty directories they
 * bind from, before the sandbox that relies on them can start, and say where
 * to point bubblewrap's --lock-file.
 *
 * `undefined` when there is nothing to record, or when no manifest could be
 * written — in which case the caller must not track those mount points at all:
 * what this process cannot record, no process may remove.
 */
export function publishMountPointManifest(
  mountPoints: readonly string[],
  sources: readonly string[],
): MountPointManifest | undefined {
  if (mountPoints.length === 0 && sources.length === 0) {
    return undefined
  }
  const dir = ensureManifestDirectory()
  if (dir === undefined) {
    return undefined
  }
  const file = path.join(
    dir,
    `${process.pid}-${randomBytes(8).toString('hex')}${MANIFEST_SUFFIX}`,
  )
  const temporary = `${file}.tmp`
  const body: z.infer<typeof ManifestSchema> = {
    version: MANIFEST_VERSION,
    pid: process.pid,
    start: processStartTime(process.pid) ?? '',
    created: Date.now(),
    paths: [...new Set(mountPoints)],
    sources: [...new Set(sources)],
  }
  // Written beside the manifest and renamed onto it, so a collect in another
  // process reads it whole or not at all. Taking the directory lock for the
  // rename keeps a collect from running between the manifests it listed and
  // its unlinks; publishing without the lock is still sound, because the
  // rename is atomic and the sandbox this manifest covers cannot have started.
  try {
    fs.writeFileSync(temporary, JSON.stringify(body), { mode: 0o600 })
    const publish = (): void => fs.renameSync(temporary, file)
    if (!withDirectoryLock(dir, publish).ran) {
      publish()
    }
  } catch (e) {
    try {
      fs.unlinkSync(temporary)
    } catch {
      // Never made.
    }
    logForDebugging(
      `[Sandbox Linux] Could not record the mount points this command relies on (${String(e)}) - they are left on the host`,
      { level: 'warn' },
    )
    return undefined
  }
  ownManifests.add(file)
  return { dir, file }
}

/**
 * Drop the manifest of a wrap that never produced a command. No sandbox can
 * hold its lock, so the mount points it named are no one's.
 */
export function discardMountPointManifest(file: string): void {
  ownManifests.delete(file)
  try {
    fs.unlinkSync(file)
  } catch {
    // Collected already.
  }
}

/**
 * The mount points named by a manifest whose sandbox may still be running.
 *
 * An empty set when the directory or /proc/locks cannot be read: the shape of
 * the file on the host still recognises a mount point an earlier sandbox left
 * behind, and this only adds the ones a live manifest vouches for.
 */
export function liveMountPoints(): Set<string> {
  const live = new Set<string>()
  const dir = ensureManifestDirectory()
  const locked = dir === undefined ? undefined : lockedInodes()
  if (dir === undefined || locked === undefined) {
    return live
  }
  let names: string[]
  try {
    names = fs.readdirSync(dir)
  } catch {
    return live
  }
  for (const name of names) {
    if (!name.endsWith(MANIFEST_SUFFIX)) continue
    const manifest = readManifest(path.join(dir, name))
    if (manifest !== undefined && isLive(manifest, locked)) {
      for (const mountPoint of manifest.paths) {
        live.add(mountPoint)
      }
    }
  }
  return live
}

/**
 * Release the manifests of this process's finished wraps and remove every
 * mount point no live manifest names, from any process, at any time, any
 * number of times. Returns the mount points removed.
 */
export function collectMountPoints(): string[] {
  const dir = ensureManifestDirectory()
  if (dir === undefined) {
    return []
  }
  const collected = withDirectoryLock(dir, () => collectUnderLock(dir))
  if (!collected.ran) {
    logForDebugging(
      `[Sandbox Linux] Another process holds the mount point directory, leaving this pass to it: ${dir}`,
    )
    return []
  }
  return collected.value
}

function collectUnderLock(dir: string): string[] {
  let names: string[]
  try {
    names = fs.readdirSync(dir)
  } catch (e) {
    logForDebugging(
      `[Sandbox Linux] The mount point manifests could not be listed (${String(e)}) - nothing removed`,
      { level: 'warn' },
    )
    return []
  }
  const manifests: Manifest[] = []
  const unreadable: string[] = []
  for (const name of names) {
    if (!name.endsWith(MANIFEST_SUFFIX)) continue
    const file = path.join(dir, name)
    const manifest = readManifest(file)
    if (manifest === undefined) {
      unreadable.push(file)
    } else {
      manifests.push(manifest)
    }
  }
  const locked = lockedInodes()
  if (locked === undefined) {
    return []
  }

  // Release this process's own wraps: the caller says their commands are done.
  // One whose manifest is still locked has a sandbox running under it, and
  // unlinking the manifest would take the kernel's answer about it away. What
  // a released manifest named is still collected below — it is the usual way a
  // mount point goes, right after the command that relied on it.
  const outstanding: Manifest[] = []
  for (const manifest of manifests) {
    if (ownManifests.has(manifest.file) && !locked.has(manifest.inode)) {
      ownManifests.delete(manifest.file)
      manifest.released = true
      try {
        fs.unlinkSync(manifest.file)
      } catch {
        // Collected by another process already.
      }
    }
    outstanding.push(manifest)
  }

  // A manifest whose contents cannot be read — a file another version of this
  // library wrote, a truncated one, one this process may not read — names
  // mount points that cannot be honoured one by one. While the kernel says a
  // sandbox is running under it, or it is new enough that one may be starting,
  // nothing at all is removed; once it is neither, whatever it names is not in
  // use and it stands in the way of nothing.
  let unreadableIsLive = false
  for (const file of unreadable) {
    let stat: fs.Stats
    try {
      stat = fs.statSync(file)
    } catch {
      continue
    }
    const age = Date.now() - stat.mtimeMs
    if (locked.has(stat.ino) || age < MANIFEST_GRACE_MS) {
      unreadableIsLive = true
    } else if (age > UNREADABLE_MANIFEST_MAX_AGE_MS) {
      try {
        fs.unlinkSync(file)
      } catch {
        // Gone already.
      }
    }
  }
  if (unreadableIsLive) {
    logForDebugging(
      '[Sandbox Linux] A mount point manifest a sandbox is running under could not be read - leaving every mount point where it is',
      { level: 'warn' },
    )
    return []
  }

  const finished: Manifest[] = []
  const claimed = new Set<string>()
  for (const manifest of outstanding) {
    if (isLive(manifest, locked)) {
      for (const path of [...manifest.paths, ...manifest.sources]) {
        claimed.add(path)
      }
    } else {
      finished.push(manifest)
    }
  }
  // Each path once, and as a mount point where a manifest names it as one.
  const candidates = new Map<string, boolean>()
  for (const manifest of finished) {
    for (const mountPoint of manifest.paths) {
      if (!claimed.has(mountPoint)) {
        candidates.set(mountPoint, false)
      }
    }
    for (const source of manifest.sources) {
      if (!claimed.has(source) && !candidates.has(source)) {
        candidates.set(source, true)
      }
    }
  }

  const removed: string[] = []
  for (const [candidate, isSource] of candidates) {
    // The kernel is asked again immediately before the unlink. A manifest
    // cannot appear mid-pass — publishing takes this same directory lock — but
    // the bubblewrap a wrap has already handed to its caller takes its lock
    // outside it, so a manifest that was unlocked when this pass started can
    // be locked by the time its mount point is reached.
    const lockedNow = lockedInodes()
    if (lockedNow === undefined) {
      return removed
    }
    const live = finished.some(
      manifest =>
        (manifest.paths.includes(candidate) ||
          manifest.sources.includes(candidate)) &&
        isLive(manifest, lockedNow),
    )
    if (live) {
      continue
    }
    if (isSource ? removeMountSource(candidate) : removeMountPoint(candidate)) {
      removed.push(candidate)
    }
  }
  for (const manifest of finished) {
    if (manifest.released) {
      continue
    }
    const lockedNow = lockedInodes()
    if (lockedNow === undefined) {
      return removed
    }
    if (isLive(manifest, lockedNow)) {
      continue
    }
    try {
      fs.unlinkSync(manifest.file)
    } catch {
      // Collected by another process already.
    }
  }
  return removed
}
