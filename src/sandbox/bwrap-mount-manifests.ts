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
 * took it. The directory is bound read-only into every sandbox that
 * restricts writes at all, whether or not its own invocation names a manifest
 * in it, and so is the other name a process of the same user would keep its
 * manifests under (see {@link mountPointManifestDirectories}), so a sandboxed
 * command can neither delete nor rewrite one, its own or another sandbox's.
 * What that leaves out is a sandbox this library did not start, or an older
 * release of it did, with the directory writable, and a process that looks
 * for its runtime or temp directory somewhere this one does not.
 *
 * Both of the kernel's answers are relative to a PID namespace: /proc/locks
 * lists a lock only when its holder has a pid in the namespace of the /proc
 * being read, and /proc/PID is local to it. A manifest therefore says which
 * PID namespace wrote it, and a process in another one does not judge it at
 * all: to that process it is live, and only a process in the namespace that
 * wrote it, which can see both answers, ever collects what it names.
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
 * A directory lock this old is broken whoever holds it, a holder that is
 * still running included: far past the milliseconds a collect takes. It is
 * the only way out for a holder that cannot be asked after, one in another
 * PID namespace or one whose lock says nothing this process can read. A
 * holder in this namespace is asked after directly, and the lock of one that
 * is gone is broken at once, whatever its age.
 */
const DIRECTORY_LOCK_STALE_MS = 60_000

/**
 * How many mount points a pass removes on one look at /proc/locks, and for how
 * long one look is good. Each look reads all of /proc/locks, whose size is the
 * host's and not this library's, so one per removal made a pass over many
 * mount points on a busy host outlast the wait above. A removal takes some ten
 * microseconds, and a sandbox takes several milliseconds, about four on a fast
 * machine, to get from its manifest being published to its binds being in
 * place (the wrap returns, the caller spawns a shell, bubblewrap sets up its
 * namespaces), so a look shared by this many removals, under a millisecond's
 * worth, is as good as one each. The time limit is for a pass that is held up
 * between two removals, which then looks again before the next, and is kept
 * under that start-up time.
 */
const REMOVALS_PER_LOOK = 64
const LOCKS_GOOD_FOR_MS = 2

/**
 * For how long one listing of the manifest directory is good. A manifest
 * published for a sandbox that is about to start is the usual way for a pass
 * to be out of date, and listing a directory of a few manifests costs less
 * than one removal, so this is kept an order of magnitude under the time that
 * sandbox needs to get to its binds, and not at the two milliseconds above. It
 * is a time and not "before every removal" so that a directory of thousands of
 * manifests, which takes milliseconds to list, is not listed thousands of
 * times.
 */
const LISTING_GOOD_FOR_MS = 0.25

/**
 * A manifest whose contents cannot be read is dropped once it is this old and
 * no sandbox holds its lock — long past anything that could still be using
 * what it names, and long enough that another version of this library writing
 * to the same directory keeps its manifests for as long as it needs them.
 */
const UNREADABLE_MANIFEST_MAX_AGE_MS = 60 * 60 * 1000

/**
 * What a manifest, and the directory lock, is written as before it is moved
 * into place. A process killed between the two leaves the file behind, and a
 * pass removes one that is as old as an unreadable manifest has to be.
 */
const TEMPORARY_SUFFIX = '.tmp'

const ManifestSchema = z.object({
  version: z.literal(MANIFEST_VERSION),
  /** The process that wrapped, and its start time, to tell a recycled pid. */
  pid: z.number().int().nonnegative(),
  start: z.string(),
  /**
   * The PID namespace the wrapping process was in, as `readlink
   * /proc/self/ns/pid` names it. `pid` and the lock bubblewrap takes can only
   * be asked after from there. Absent from a manifest written before the field
   * existed, which is then from a namespace nobody can name.
   */
  ns: z.string().optional(),
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
  /** The inode /proc/locks reports a lock on, and the device it is on. */
  inode: string
  device: string
  /**
   * Whether this process has given the manifest up: it wrote it, the caller
   * says the command is done, and nothing held the lock when the pass began.
   * Its writer is running and it may be young, and neither keeps it: only a
   * lock can still make it live. The file stays where it is until the end of
   * the pass, like any other finished manifest's.
   */
  released: boolean
}

/**
 * Manifests this process wrote and that are still on disk as far as it knows,
 * each with the key of the command it was wrapped for where the caller gave
 * the wrap one, and whether the caller has said that command is over. That is
 * remembered, not acted on at once: a pass can turn back half way, a removal
 * can be refused, a sandbox can still hold the lock, and in each case the
 * manifest has to stay on disk, since it is all that names the mount points,
 * and go at a later pass whatever that pass is told to release.
 */
const ownManifests = new Map<
  string,
  { commandKey: string | undefined; over: boolean }
>()

/**
 * Which of this process's own manifests a collect may release. Releasing one
 * says "the command this was wrapped for is over", which only the caller
 * knows, so it is the caller that says which:
 * - `all`: no wrap of this process is outstanding, or the process is ending;
 * - `none`: some are, and nothing says which of them is over, so only what
 *   OTHER processes have finished with is taken away;
 * - one command: that command is over, whatever else is still running.
 * Releasing the manifest of a wrap whose command has not started yet is what
 * must never happen: bubblewrap opens the manifest to lock it, and a command
 * whose manifest is gone refuses to start, or, if it got its lock in the
 * moment between the pass's last look at /proc/locks and the unlink, runs on
 * with nothing on disk naming its mount points.
 */
export type OwnManifestRelease = 'all' | 'none' | { commandKey: string }

let manifestDirectory: string | undefined
// Whether that is the last resort below, which no other process knows of.
let manifestDirectoryIsPrivate = false
let directoryFailureLogged = false
// Set once the last resort has been tried and found wanting, so a process on a
// temp dir that keeps no modes does not make a fresh directory on every call.
let manifestDirectoryUnavailable = false

/** Everything here is for bubblewrap, which is Linux's. */
const onLinux = (): boolean => process.platform === 'linux'

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

let pidNamespace: string | undefined | null = null

/**
 * The PID namespace this process is in, as the kernel names it
 * (`pid:[4026531836]`), or `undefined` where it cannot be told.
 */
function ownPidNamespace(): string | undefined {
  if (pidNamespace === null) {
    try {
      pidNamespace = fs.readlinkSync('/proc/self/ns/pid')
    } catch {
      pidNamespace = undefined
    }
  }
  return pidNamespace
}

/**
 * The device half of what /proc/locks prints for a file, from the number stat
 * gives for it: `major:minor`, in decimal.
 */
function deviceOf(dev: bigint): string {
  const major = ((dev >> 8n) & 0xfffn) | ((dev >> 32n) & ~0xfffn)
  const minor = (dev & 0xffn) | ((dev >> 12n) & ~0xffn)
  return `${major}:${minor}`
}

/**
 * The filesystems on which the device stat reports for a file is the one
 * /proc/locks prints for a lock on it: both are the superblock's. It is not so
 * everywhere - a btrfs subvolume and some overlay arrangements give stat a
 * device of their own - and there only the inode number can be compared.
 */
const FILESYSTEMS_WITH_ONE_DEVICE = new Set([
  0x01021994, // tmpfs, which is what $XDG_RUNTIME_DIR is
  0xef53, // ext2, ext3, ext4
  0x58465342, // xfs
])

function reportsTheLockedDevice(dir: string): boolean {
  try {
    return FILESYSTEMS_WITH_ONE_DEVICE.has(Number(fs.statfsSync(dir).type))
  } catch {
    return false
  }
}

/** The locks /proc/locks lists, of any kind, by what they are on. */
type Locks = {
  /** Every inode number with a lock on it, whatever filesystem it is on. */
  inodes: Set<string>
  /** The same locks as `major:minor:inode`, in decimal. */
  files: Set<string>
  /** Whether a manifest's device can be held against `files`. */
  comparesDevices: boolean
}

/**
 * Whether /proc/locks lists a lock on this file. Any lock on a manifest is the
 * one bubblewrap's sandbox init holds: nothing else opens one to lock it.
 *
 * The device is compared where the manifests' filesystem reports the one
 * /proc/locks prints, and only there. Inode numbers are per filesystem, and on
 * a tmpfs they are small and handed out in order, so a manifest in a young
 * runtime directory can share its number with some unrelated locked file on
 * another filesystem; it then read as live for as long as that lock was held,
 * and every path it named as a mount point for every later wrap.
 * Where the two devices cannot be compared the inode number alone decides,
 * which errs towards "locked": the other way round would hide a live
 * sandbox's lock.
 */
function holdsLock(
  locks: Locks,
  file: { inode: string; device: string },
): boolean {
  return locks.comparesDevices
    ? locks.files.has(`${file.device}:${file.inode}`)
    : locks.inodes.has(file.inode)
}

/**
 * What /proc/locks lists, for the manifests in `dir`. Only the locks whose
 * holder has a pid in the PID namespace of the /proc being read are listed,
 * which is why a manifest from another namespace is never judged by this.
 *
 * `undefined` when the list could not be read, which every caller reads as
 * "every manifest is locked".
 */
function readLocks(dir: string): Locks | undefined {
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
  const inodes = new Set<string>()
  const files = new Set<string>()
  for (const line of text.split('\n')) {
    // The major:minor:inode word, which sits one field later on the lines that
    // describe a blocked request ("2: -> POSIX ADVISORY WRITE ...").
    for (const word of line.split(/\s+/)) {
      const match = /^([0-9a-f]+):([0-9a-f]+):(\d+)$/.exec(word)
      if (match !== null) {
        const inode = String(BigInt(match[3]!))
        inodes.add(inode)
        files.add(
          `${parseInt(match[1]!, 16)}:${parseInt(match[2]!, 16)}:${inode}`,
        )
        break
      }
    }
  }
  return { inodes, files, comparesDevices: reportsTheLockedDevice(dir) }
}

/** Whether `dir` is a directory of ours that nobody else can write, and we can. */
function isOurPrivateDirectory(dir: string): boolean {
  try {
    const stat = fs.lstatSync(dir)
    if (
      !stat.isDirectory() ||
      stat.uid !== process.getuid?.() ||
      (stat.mode & 0o077) !== 0
    ) {
      return false
    }
    // Ours, and no use if it cannot be written: a directory an outer sandbox
    // binds read-only reads as ours in every other respect.
    fs.accessSync(dir, fs.constants.W_OK | fs.constants.X_OK)
    return true
  } catch {
    return false
  }
}

/**
 * Make `dir` a directory of ours alone, or say it cannot be.
 *
 * The name is predictable and sits where sandboxed commands commonly write,
 * so what is found there is looked at before it is touched: through a
 * descriptor opened without following a link, so that a symlink planted at
 * the name is refused rather than having its target's mode changed, and the
 * mode is set on that descriptor, never on the path.
 */
function makeOurPrivateDirectory(dir: string): boolean {
  try {
    fs.mkdirSync(dir, { mode: 0o700 })
  } catch {
    // There already, or cannot be made: the look below decides.
  }
  let fd: number | undefined
  try {
    fd = fs.openSync(
      dir,
      fs.constants.O_RDONLY |
        fs.constants.O_DIRECTORY |
        fs.constants.O_NOFOLLOW,
    )
    const stat = fs.fstatSync(fd)
    if (!stat.isDirectory() || stat.uid !== process.getuid?.()) {
      return false
    }
    // mkdir asks for 0700 but the umask applies, and a directory an earlier
    // run left keeps the mode it was made with.
    if ((stat.mode & 0o777) !== 0o700) {
      fs.fchmodSync(fd, 0o700)
    }
  } catch {
    return false
  } finally {
    if (fd !== undefined) fs.closeSync(fd)
  }
  return isOurPrivateDirectory(dir)
}

/**
 * Whether a manifest kept under `dir` would be out of bubblewrap's reach: the
 * wrap mounts a fresh /dev and /proc after every bind, which buries whatever
 * was bound beneath them, and bubblewrap opens the manifest after its mounts.
 */
function isBuriedBySandboxMounts(dir: string): boolean {
  return ['/dev', '/proc', '/sys'].some(
    root => dir === root || dir.startsWith(`${root}/`),
  )
}

/**
 * The names under which the processes of this user keep their manifests where
 * several can find them, in the order they are tried: under $XDG_RUNTIME_DIR
 * when there is one, else under the system temp dir. One that a sandbox's own
 * mounts would bury is left out.
 */
function sharedManifestDirectoryNames(): string[] {
  const runtimeDir = process.env['XDG_RUNTIME_DIR']
  const shared =
    runtimeDir !== undefined && path.isAbsolute(runtimeDir)
      ? [path.join(runtimeDir, 'srt-mount-points')]
      : []
  shared.push(
    path.join(tmpdir(), `srt-mount-points-${process.getuid?.() ?? 0}`),
  )
  return shared.filter(candidate => !isBuriedBySandboxMounts(candidate))
}

/**
 * The directory manifests live in: under $XDG_RUNTIME_DIR when there is one,
 * else a per-user directory under the system temp dir, else - when neither can
 * be made ours alone and written, as in a sandbox that binds them read-only -
 * a private directory only this process knows, which keeps the guarantee
 * within this process and loses only what other processes would have read.
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
  manifestDirectoryIsPrivate = false
  for (const candidate of sharedManifestDirectoryNames()) {
    if (makeOurPrivateDirectory(candidate)) {
      manifestDirectory = candidate
      return candidate
    }
  }
  manifestDirectory = undefined
  if (manifestDirectoryUnavailable || isBuriedBySandboxMounts(tmpdir())) {
    return undefined
  }
  try {
    const private_ = fs.mkdtempSync(path.join(tmpdir(), 'srt-mount-points-'))
    if (!makeOurPrivateDirectory(private_)) {
      // A temp dir that keeps no modes or ownership: nothing made in it can be
      // told from somebody else's, now or on the next call.
      try {
        fs.rmdirSync(private_)
      } catch {
        // Left; it is empty.
      }
      throw new Error(`${private_} cannot be made private`)
    }
    manifestDirectory = private_
    manifestDirectoryIsPrivate = true
    logForDebugging(
      `[Sandbox Linux] No shared directory for mount point manifests, using one only this process knows: ${private_}`,
      { level: 'warn' },
    )
    return private_
  } catch (e) {
    manifestDirectoryUnavailable = true
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

/** Whether `dir` is a real directory, not a link to one, and the user's. */
function isOurDirectory(dir: string): boolean {
  try {
    const stat = fs.lstatSync(dir)
    return stat.isDirectory() && stat.uid === process.getuid?.()
  } catch {
    return false
  }
}

/**
 * Every directory a sandbox must not be able to write, because some process
 * of this user keeps manifests in it and a collect on the host believes what
 * it finds there: both shared names, as this process sees them, and the one
 * this process has settled on where that is neither. For a wrap to bind
 * read-only, whether or not it has a manifest of its own.
 *
 * Both names, and not only the one this process uses: a process started with
 * $XDG_RUNTIME_DIR uses the first and one started without it (from cron, over
 * a plain ssh, as a service) the second, and a sandbox of the first kind with
 * the temp dir writable could otherwise delete and forge the manifests of the
 * second. Each is made if it can be, so that a sandboxed command cannot make
 * it first and fill it before the process that will believe it comes along;
 * one that is there and the user's is listed even when it cannot be written
 * from here. The last resort is not made for this: there is nothing to keep
 * out of reach in a directory nobody has made.
 */
export function mountPointManifestDirectories(): string[] {
  if (!onLinux()) {
    return []
  }
  const dirs = new Set<string>()
  for (const candidate of sharedManifestDirectoryNames()) {
    makeOurPrivateDirectory(candidate)
    if (isOurDirectory(candidate)) {
      dirs.add(candidate)
    }
  }
  if (manifestDirectory !== undefined && isOurDirectory(manifestDirectory)) {
    dirs.add(manifestDirectory)
  }
  return [...dirs]
}

/**
 * Take away the directory only this process knows, once nothing is left in
 * it, when the process or its session is ending: nobody else would. With the
 * manifest of a sandbox that is still running in it, it stays.
 */
export function removePrivateManifestDirectory(): void {
  if (manifestDirectory === undefined || !manifestDirectoryIsPrivate) {
    return
  }
  try {
    fs.rmdirSync(manifestDirectory)
  } catch {
    // Not empty, or gone already.
    return
  }
  manifestDirectory = undefined
  manifestDirectoryIsPrivate = false
}

/** Block this thread, the only sleep available to a synchronous cleanup. */
function sleep(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms)
}

/**
 * What a process leaves in the directory lock: who it is, and the PID
 * namespace in which that can be asked after.
 */
function directoryLockContent(): string {
  return `${process.pid} ${processStartTime(process.pid) ?? '?'} ${ownPidNamespace() ?? '?'}\n`
}

/**
 * Take the directory lock, and say what it now holds, or why it was not taken:
 * `held` when something is at its name already, `unavailable` when this
 * process cannot make one there at all.
 *
 * The lock comes into being whole. Made with O_EXCL and written to afterwards
 * it stood empty for a moment, and a waiter that read it then found no holder
 * in it and removed it at once, so two processes were inside together. It is
 * written under another name and linked into place instead: link fails when
 * the name is taken, exactly as O_EXCL does, and what it puts there is never
 * seen half made. A filesystem without hard links gets no lock, and no pass.
 */
function takeDirectoryLock(
  dir: string,
  lockFile: string,
): { content: string } | 'held' | 'unavailable' {
  const content = directoryLockContent()
  const temporary = path.join(
    dir,
    `directory.lock.${process.pid}.${randomBytes(8).toString('hex')}${TEMPORARY_SUFFIX}`,
  )
  try {
    fs.writeFileSync(temporary, content, { mode: 0o600, flag: 'wx' })
  } catch {
    return 'unavailable'
  }
  try {
    fs.linkSync(temporary, lockFile)
    return { content }
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === 'EEXIST'
      ? 'held'
      : 'unavailable'
  } finally {
    try {
      fs.unlinkSync(temporary)
    } catch {
      // Gone with the directory.
    }
  }
}

/**
 * Give the directory lock up, if it is still this process's. One broken for
 * its age while this process was held up belongs to whoever took it next, and
 * removing that one by name let a third process in beside it.
 */
function releaseDirectoryLock(lockFile: string, content: string): void {
  try {
    if (fs.readFileSync(lockFile, 'utf8') === content) {
      fs.unlinkSync(lockFile)
    }
  } catch {
    // Broken by another process while we held it: nothing to undo.
  }
}

/**
 * What stands at the directory lock's name, once taking it has failed:
 * - `free`: nothing any more, or the lock of a holder that is gone, removed;
 * - `held`: somebody's lock, to be waited for;
 * - `stuck`: something this process can neither read as a lock nor remove,
 *   which no amount of waiting changes.
 *
 * Breaking a lock is three steps - read who holds it, ask after them, unlink -
 * and not one, so two waiters can both find the same holder gone and the
 * slower one's unlink can land on the lock a third process has taken since.
 * Nothing here prevents that. It is why nothing rests on this lock: see
 * {@link withDirectoryLock}.
 */
function examineDirectoryLock(lockFile: string): 'free' | 'held' | 'stuck' {
  let holder: string
  let age: number
  try {
    // Looked at before it is opened, and opened without blocking or following
    // a link: opening a FIFO to read waits for a writer, and nothing but a
    // regular file is a lock this library made.
    if (!fs.lstatSync(lockFile).isFile()) {
      return 'stuck'
    }
    const fd = fs.openSync(
      lockFile,
      fs.constants.O_RDONLY | fs.constants.O_NONBLOCK | fs.constants.O_NOFOLLOW,
    )
    try {
      const stat = fs.fstatSync(fd)
      if (!stat.isFile()) {
        return 'stuck'
      }
      age = Date.now() - stat.mtimeMs
      holder = fs.readFileSync(fd, 'utf8')
    } finally {
      fs.closeSync(fd)
    }
  } catch (e) {
    // Gone between the failed attempt and this look: the next attempt takes
    // it. Anything else is a file that is there and cannot be read.
    return (e as NodeJS.ErrnoException).code === 'ENOENT' ? 'free' : 'stuck'
  }
  // A holder can be asked after only in the PID namespace it named, when that
  // is this one: elsewhere its pid means nothing, or means some other
  // process. One that cannot be asked after is believed until the lock is
  // older than any pass, as is one that did not say who it is.
  const who = /^(\d+) (\d+) (\S+)\n$/.exec(holder)
  const held =
    age < DIRECTORY_LOCK_STALE_MS &&
    (who === null ||
      who[3] !== ownPidNamespace() ||
      writerIsRunning(Number(who[1]), who[2]!))
  if (held) {
    return 'held'
  }
  try {
    fs.unlinkSync(lockFile)
  } catch (e) {
    // Another process broke it first; or it cannot be removed from here, in
    // which case it is still there and the next attempt would find it so.
    return (e as NodeJS.ErrnoException).code === 'ENOENT' ? 'free' : 'stuck'
  }
  return 'free'
}

/**
 * Run `body` while holding the manifest directory's lock, and report whether
 * it ran, and if not, whether that was for somebody `held` it all the while.
 * It gives up, without running `body`, after {@link DIRECTORY_LOCK_WAIT_MS} of
 * finding the lock held, and at once when what is at the lock's name is
 * nothing it could ever take: the wait is this thread's, in the wrap, in the
 * clean-up after every command and in the exit handler, and nothing about a
 * lock is worth more of it than that.
 *
 * The lock keeps srt processes out of each other's way most of the time; it
 * does not exclude, and nothing may rest on it. Its holder can be held up past
 * the age at which it is broken, the break itself is not atomic (see
 * {@link examineDirectoryLock}), and a publish that cannot have the lock goes
 * ahead without it. What makes a mount point safe to remove is looked at
 * again immediately before the removals and at short intervals during them:
 * the directory, for a manifest that was not there when the pass began, and
 * the kernel's answer about every manifest the pass knows of (see
 * {@link collectUnderLock}).
 */
function withDirectoryLock<T>(
  dir: string,
  body: () => T,
): { ran: true; value: T } | { ran: false; held: boolean } {
  const lockFile = path.join(dir, 'directory.lock')
  const deadline = Date.now() + DIRECTORY_LOCK_WAIT_MS
  for (;;) {
    const taken = takeDirectoryLock(dir, lockFile)
    if (taken === 'unavailable') {
      return { ran: false, held: false }
    }
    if (taken !== 'held') {
      try {
        return { ran: true, value: body() }
      } finally {
        releaseDirectoryLock(lockFile, taken.content)
      }
    }
    if (examineDirectoryLock(lockFile) === 'stuck') {
      logForDebugging(
        `[Sandbox Linux] ${lockFile} is not a lock this process can take or break - going on without it`,
        { level: 'warn' },
      )
      return { ran: false, held: false }
    }
    // On every round, whatever the look above found: a lock that is broken
    // and taken again by others for as long as this process keeps asking is
    // as good as held.
    if (Date.now() >= deadline) {
      return { ran: false, held: true }
    }
    sleep(DIRECTORY_LOCK_RETRY_MS)
  }
}

function readManifest(file: string): Manifest | undefined {
  let inode: string
  let device: string
  let text: string
  try {
    const fd = fs.openSync(file, 'r')
    try {
      const stat = fs.fstatSync(fd, { bigint: true })
      inode = String(stat.ino)
      device = deviceOf(stat.dev)
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
    ? { ...parsed.data, file, inode, device, released: false }
    : undefined
}

/**
 * Whether a sandbox that named this manifest may still be running, as far as
 * THIS process can tell.
 *
 * It can tell only about a manifest written in its own PID namespace: the
 * writer's pid and the sandbox's lock are both invisible from any other. So a
 * manifest from another namespace is live here whatever /proc says, for good:
 * what it names is collected by a process in the namespace that wrote it, and
 * by nobody if that namespace has gone, which leaves empty files behind and
 * opens nothing. One that does not say where it is from is live while a
 * process with its writer's pid and start time can be seen, and otherwise
 * until it is as old as an unreadable manifest has to be to be dropped.
 */
function isLive(manifest: Manifest, locks: Locks): boolean {
  if (holdsLock(locks, manifest)) {
    return true
  }
  if (manifest.released) {
    return false
  }
  const here = ownPidNamespace()
  if (manifest.ns === undefined || here === undefined) {
    return (
      writerIsRunning(manifest.pid, manifest.start) ||
      Date.now() - manifest.created < UNREADABLE_MANIFEST_MAX_AGE_MS
    )
  }
  if (manifest.ns !== here) {
    return true
  }
  return (
    Date.now() - manifest.created < MANIFEST_GRACE_MS ||
    writerIsRunning(manifest.pid, manifest.start)
  )
}

/**
 * What became of a path a pass set out to remove: `left` when there is
 * nothing more to do about it - it is gone, or is no longer what bubblewrap or
 * this library made - and `failed` when it is still that and could not be
 * removed from here, which a later pass, or another process, may yet manage.
 */
type Removal = 'removed' | 'left' | 'failed'

/** Whether a failed removal means the path is no longer ours to remove. */
function meansNothingToRemove(e: unknown): boolean {
  const code = (e as NodeJS.ErrnoException | undefined)?.code
  // Not empty after all: something was written into it between the look and
  // the rmdir.
  return isAbsenceErrno(e) || code === 'ENOTEMPTY' || code === 'EEXIST'
}

/**
 * Remove an empty directory a placeholder bound from, if it is still our own.
 * It sits under the system temp dir, which sandboxed commands commonly can
 * write, so anything that is not a private empty directory of ours — a
 * symlink, a directory whose mode has been widened, one with something in it —
 * is somebody else's and is left exactly as found.
 */
function removeMountSource(source: string): Removal {
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
      return 'left'
    }
    fs.rmdirSync(source)
    logForDebugging(
      `[Sandbox Linux] Cleaned up the empty-directory mount source: ${source}`,
    )
    return 'removed'
  } catch (e) {
    if (meansNothingToRemove(e)) {
      return 'left'
    }
    logForDebugging(
      `[Sandbox Linux] Could not remove the empty-directory mount source (${String(e)}): ${source}`,
    )
    return 'failed'
  }
}

/**
 * Whether `p` still has the shape of a file bubblewrap made to bind onto: a
 * regular file (not a link to one), empty, with no write bit, under one name,
 * and ours. A manifest is only a claim about a path, and the directory it
 * sits in is only as private as its host, so nothing is removed on a
 * manifest's word that does not also look like what bubblewrap leaves.
 */
export function isBwrapFileMountPoint(p: string): boolean {
  try {
    const stat = fs.lstatSync(p)
    return (
      stat.isFile() &&
      stat.size === 0 &&
      (stat.mode & 0o222) === 0 &&
      stat.nlink === 1 &&
      stat.uid === process.getuid?.()
    )
  } catch {
    return false
  }
}

/**
 * What kind of mount point the path a live manifest names still is, by what
 * is there now: an empty regular file, a directory, or neither any more. A
 * manifest says a path was a mount point when it was written; a file that has
 * been written to since, or a link put in its place, is somebody's own.
 */
export function kindOfMountPoint(p: string): 'file' | 'directory' | undefined {
  try {
    const stat = fs.lstatSync(p)
    if (stat.isFile() && stat.size === 0) {
      return 'file'
    }
    return stat.isDirectory() ? 'directory' : undefined
  } catch {
    return undefined
  }
}

/**
 * Remove a mount point, if it is still the empty file or directory bwrap made.
 * Anything else - a file with content or a write bit, a link, a directory
 * something has written into or that is not ours - is left where it is.
 */
function removeMountPoint(mountPoint: string): Removal {
  try {
    if (isBwrapFileMountPoint(mountPoint)) {
      fs.unlinkSync(mountPoint)
      logForDebugging(
        `[Sandbox Linux] Cleaned up bwrap mount point (file): ${mountPoint}`,
      )
      return 'removed'
    }
    const stat = fs.lstatSync(mountPoint)
    if (stat.isDirectory() && stat.uid === process.getuid?.()) {
      if (fs.readdirSync(mountPoint).length > 0) {
        logForDebugging(
          `[Sandbox Linux] Left a bwrap mount point directory behind, something has written into it: ${mountPoint}`,
        )
        return 'left'
      }
      // rmdir, not a recursive remove: it neither follows a symlink nor
      // descends, so a path that is no longer ours is left exactly as found.
      fs.rmdirSync(mountPoint)
      logForDebugging(
        `[Sandbox Linux] Cleaned up bwrap mount point (dir): ${mountPoint}`,
      )
      return 'removed'
    }
    logForDebugging(
      `[Sandbox Linux] Left a path a manifest names where it is, it no longer looks like a bwrap mount point: ${mountPoint}`,
    )
    return 'left'
  } catch (e) {
    if (meansNothingToRemove(e)) {
      return 'left'
    }
    logForDebugging(
      `[Sandbox Linux] Could not remove a bwrap mount point (${String(e)}): ${mountPoint}`,
    )
    return 'failed'
  }
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
 * written, in which case the caller must not track those mount points at all:
 * what this process cannot record it does not remove. That is as far as it
 * goes. Nothing on disk then says a sandbox relies on them, so a wrap in
 * another process that denies the same path takes the file for a leftover,
 * covers it, names it, and removes it after its own command, whether or not
 * the sandbox that could not be recorded is still running.
 */
export function publishMountPointManifest(
  mountPoints: readonly string[],
  sources: readonly string[],
  commandKey?: string,
): MountPointManifest | undefined {
  if (!onLinux() || (mountPoints.length === 0 && sources.length === 0)) {
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
  const temporary = `${file}${TEMPORARY_SUFFIX}`
  const body: z.infer<typeof ManifestSchema> = {
    version: MANIFEST_VERSION,
    pid: process.pid,
    start: processStartTime(process.pid) ?? '',
    ns: ownPidNamespace(),
    created: Date.now(),
    paths: [...new Set(mountPoints)],
    sources: [...new Set(sources)],
  }
  // Written beside the manifest and renamed onto it, so a collect in another
  // process reads it whole or not at all. The rename is made under the
  // directory lock where that can be had, which keeps it out of the middle of
  // most passes, and without it where it cannot: a wrap is not refused for
  // want of a lock. Either way a pass may already have listed the directory,
  // so what keeps this wrap's mount points is that every pass lists it again
  // before it removes anything (see collectUnderLock), and that the sandbox
  // this manifest covers has not started yet.
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
  ownManifests.set(file, { commandKey, over: false })
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
  if (!onLinux()) {
    return live
  }
  const dir = ensureManifestDirectory()
  const locks = dir === undefined ? undefined : readLocks(dir)
  if (dir === undefined || locks === undefined) {
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
    if (manifest !== undefined && isLive(manifest, locks)) {
      for (const mountPoint of manifest.paths) {
        live.add(mountPoint)
      }
    }
  }
  return live
}

/**
 * Release the manifests of the wraps of this process that `release` says are
 * over, and remove every mount point no live manifest names, from any process,
 * at any time, any number of times. Returns the mount points removed. Does
 * nothing anywhere but on Linux.
 */
export function collectMountPoints(
  release: OwnManifestRelease = 'all',
): string[] {
  if (!onLinux()) {
    return []
  }
  // What the caller says about its own commands is taken down first and kept,
  // whatever becomes of this pass: one that cannot have the lock, or turns
  // back half way, leaves the manifests for the next, which has to know they
  // are done with even when it is told to release nothing.
  for (const own of ownManifests.values()) {
    if (
      release === 'all' ||
      (release !== 'none' && own.commandKey === release.commandKey)
    ) {
      own.over = true
    }
  }
  const dir = ensureManifestDirectory()
  if (dir === undefined) {
    return []
  }
  const collected = withDirectoryLock(dir, () => collectUnderLock(dir))
  if (!collected.ran) {
    logForDebugging(
      collected.held
        ? `[Sandbox Linux] The lock on the mount point directory could not be had, leaving this pass to whoever has it: ${dir}`
        : `[Sandbox Linux] No lock can be taken on the mount point directory from here, so nothing is collected from it until that is put right: ${dir}`,
    )
    return []
  }
  return collected.value
}

/**
 * One pass, which the caller makes under the directory lock where it can.
 *
 * Nothing is taken off the disk until the end. A manifest is all that names
 * its mount points, so it goes last, after them, and only when every one of
 * them is gone or is no longer a mount point: a pass that turns back half way,
 * or a removal that is refused, leaves the manifest for a later pass to go by.
 * That holds for the manifests of this process as for anybody's. The ones the
 * caller has said are over are judged as if their writer were gone, and that
 * is all that sets them apart.
 *
 * The lock does not exclude (see {@link withDirectoryLock}), so the pass does
 * not rely on the directory staying as first listed. Immediately before it
 * removes anything, and again whenever its last listing is more than
 * {@link LISTING_GOOD_FOR_MS} old, it lists the directory again, where a
 * manifest that was not there at first keeps everything it names whatever
 * else is true of it: that is how a sandbox about to start on the same path
 * shows. And before the first removal, and again every
 * {@link REMOVALS_PER_LOOK} removals or {@link LOCKS_GOOD_FOR_MS}, it reads
 * /proc/locks again, where a manifest that has been locked since keeps what it
 * names. That one covers the actor no lock could: the bubblewrap a wrap has
 * already handed to its caller, which takes its lock whenever the caller
 * starts it. What is left is the time between a look and the removal made on
 * it, a quarter of a millisecond for a newly published manifest and two
 * milliseconds for one that was there all along, against the four or more a
 * sandbox takes to get from its start to its binds. A pass that is held up for
 * longer than that between looking and removing, with a sandbox starting on
 * the same path in that time, still takes that sandbox's mount point away.
 */
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
  const locks = readLocks(dir)
  if (locks === undefined) {
    return []
  }
  // What the pass knows of: the first listing, so that everything found
  // later is a newcomer.
  const known = new Set(names)
  // A manifest of this process that something else has taken off the disk is
  // nothing to remember.
  for (const file of ownManifests.keys()) {
    if (path.dirname(file) === dir && !known.has(path.basename(file))) {
      ownManifests.delete(file)
    }
  }

  // A manifest whose contents cannot be read — a file another version of this
  // library wrote, a truncated one, one this process may not read — names
  // mount points that cannot be honoured one by one. While the kernel says a
  // sandbox is running under it, or it is new enough that one may be starting,
  // nothing at all is removed; once it is neither, whatever it names is not in
  // use and it stands in the way of nothing.
  let unreadableIsLive = false
  for (const file of unreadable) {
    let stat: fs.BigIntStats
    try {
      stat = fs.statSync(file, { bigint: true })
    } catch {
      continue
    }
    const age = Date.now() - Number(stat.mtimeMs)
    if (
      holdsLock(locks, {
        inode: String(stat.ino),
        device: deviceOf(stat.dev),
      }) ||
      age < MANIFEST_GRACE_MS
    ) {
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

  // What a process killed between writing a file and moving it into place
  // left. Nothing reads these, and nothing else removes them.
  for (const name of names) {
    if (!name.endsWith(TEMPORARY_SUFFIX)) continue
    const file = path.join(dir, name)
    try {
      if (
        Date.now() - fs.lstatSync(file).mtimeMs >
        UNREADABLE_MANIFEST_MAX_AGE_MS
      ) {
        fs.unlinkSync(file)
      }
    } catch {
      // Moved into place, or removed by its writer, in the meantime.
    }
  }

  // The wraps of this process the caller has said are over, except that one
  // whose manifest is locked has a sandbox running under it all the same, and
  // is anybody's live manifest until the lock goes.
  for (const manifest of manifests) {
    manifest.released =
      ownManifests.get(manifest.file)?.over === true &&
      !holdsLock(locks, manifest)
  }

  const finished: Manifest[] = []
  const claimed = new Set<string>()
  const claim = (manifest: Manifest): void => {
    for (const named of [...manifest.paths, ...manifest.sources]) {
      claimed.add(named)
    }
  }
  for (const manifest of manifests) {
    if (isLive(manifest, locks)) {
      claim(manifest)
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

  // When the pass last made sure, and what it found then: `revived` are the
  // manifests of the first listing that read as finished then and as locked on
  // a later look. A finished manifest's writer is gone and its grace is over,
  // and neither comes back, so the lock is all that is asked after again.
  const revived = new Set<Manifest>()
  let removalsOnThisLook = 0
  let lookedAt: number | undefined
  let listedAt: number | undefined
  const locksAreFresh = (): boolean =>
    lookedAt !== undefined &&
    removalsOnThisLook < REMOVALS_PER_LOOK &&
    performance.now() - lookedAt < LOCKS_GOOD_FOR_MS
  const listingIsFresh = (): boolean =>
    listedAt !== undefined && performance.now() - listedAt < LISTING_GOOD_FOR_MS
  const readTheLocksAgain = (): boolean => {
    const locksNow = readLocks(dir)
    if (locksNow === undefined) {
      return false
    }
    for (const manifest of finished) {
      if (!revived.has(manifest) && holdsLock(locksNow, manifest)) {
        revived.add(manifest)
        claim(manifest)
      }
    }
    removalsOnThisLook = 0
    lookedAt = performance.now()
    return true
  }
  const listTheDirectoryAgain = (): boolean => {
    let namesNow: string[]
    try {
      namesNow = fs.readdirSync(dir)
    } catch {
      return false
    }
    for (const name of namesNow) {
      if (!name.endsWith(MANIFEST_SUFFIX) || known.has(name)) continue
      known.add(name)
      const file = path.join(dir, name)
      const arrived = readManifest(file)
      if (arrived !== undefined) {
        // Published since the pass began: a sandbox is about to start under
        // it, or has. Whatever it names stays, with no further question.
        claim(arrived)
      } else if (fs.existsSync(file)) {
        // There, and not to be read: what it names cannot be kept path by
        // path, so everything is.
        logForDebugging(
          `[Sandbox Linux] A mount point manifest that appeared during the pass could not be read - leaving the rest where it is: ${file}`,
          { level: 'warn' },
        )
        return false
      }
    }
    listedAt = performance.now()
    return true
  }
  // The kernel's list is read first and the directory listed last. Reading
  // the list takes as long as the host has locks, milliseconds on a busy one,
  // after which a listing made before it is out of date as well.
  const mayStillRemove = (): boolean =>
    (locksAreFresh() || readTheLocksAgain()) &&
    (listingIsFresh() || listTheDirectoryAgain())

  const removed: string[] = []
  const notRemoved = new Set<string>()
  for (const [candidate, isSource] of candidates) {
    if (!mayStillRemove()) {
      return removed
    }
    if (claimed.has(candidate)) {
      continue
    }
    const outcome = isSource
      ? removeMountSource(candidate)
      : removeMountPoint(candidate)
    removalsOnThisLook++
    if (outcome === 'removed') {
      removed.push(candidate)
    } else if (outcome === 'failed') {
      notRemoved.add(candidate)
    }
  }
  // The manifests themselves, last. Only a lock taken since can speak for one
  // of these; a manifest somebody else has published in the meantime cannot.
  for (const manifest of finished) {
    if (!locksAreFresh() && !readTheLocksAgain()) {
      return removed
    }
    if (revived.has(manifest)) {
      continue
    }
    // A mount point that is still there, still what bubblewrap made, and could
    // not be removed from here - a directory this process sees read-only, say
    // - is still somebody's to remove, and the manifest is all that says so.
    if (
      [...manifest.paths, ...manifest.sources].some(named =>
        notRemoved.has(named),
      )
    ) {
      continue
    }
    try {
      fs.unlinkSync(manifest.file)
    } catch {
      // Collected by another process already.
    }
    ownManifests.delete(manifest.file)
    removalsOnThisLook++
  }
  return removed
}

/**
 * Forget which directory the manifests are kept in, so that the next use
 * works it out again from the environment. Test seam: a test gives itself a
 * runtime directory of its own, so that what it lists, attacks and collects
 * is never another process's, and this module may have settled on the real
 * one before the test was loaded.
 */
export function forgetMountPointManifestDirectory(): void {
  manifestDirectory = undefined
  manifestDirectoryIsPrivate = false
  manifestDirectoryUnavailable = false
  directoryFailureLogged = false
}
