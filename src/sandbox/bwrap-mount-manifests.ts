/**
 * Which mount points on the host a running sandbox still relies on (Linux).
 *
 * A deny on a path that does not exist needs a mount point there: bwrap makes
 * an empty file or directory on the host and binds over it. Unlinking it while
 * a sandbox is bound over it detaches the mount inside that sandbox, and the
 * denied path can then be created on the host. So a mount point may be removed
 * only when no running sandbox relies on it, and no process can decide that by
 * counting for itself. README.md, "Write denies on paths that do not exist yet",
 * tells it in full.
 * What is kept in a per-user directory, and where its rules are:
 *
 * - `<id>.json`, a manifest: what a wrap relies on, written before its command
 *   is handed out and bound by bubblewrap before it makes anything ({@link
 *   publishMountPointManifest}).
 * - `<id>.started`, its record: the command line appends its own
 *   /proc/self/stat line and then execs bubblewrap, so the sandbox vouches for
 *   itself ({@link recordVouches}, {@link isLive}).
 * - `<id>.claimed` and `<id>.finished`, the names a clean-up gives a manifest
 *   before it removes what that names, and `<process>.pass`, the clean-up's own
 *   record, which wraps wait for ({@link collect}, which holds the invariants).
 *
 * Whatever cannot be read or asked (a manifest, a record, /proc) counts as live.
 * A reading in doubt refuses every wrap of this user that restricts writes, so
 * NO LASTING STATE OF THE DIRECTORY REFUSES WRAPS FOR EVER, AND NONE KEEPS WHAT
 * IS LEFT FOR EVER: every source of doubt is a condition of this process that
 * clears by itself, or a property of what is at a name, which has an end (an
 * hour, seven days, the process on a record, the boot).
 *
 * INVARIANT: all of this rests on the sandboxed command, which has the same
 * uid, being unable to write OR CREATE a directory a pass believes: one it made
 * itself would pass every check of owner and mode (see {@link
 * mountPointManifestDirectories}). Not covered: a sandbox this library did not
 * start; a name, or one above it, that is a link inside a write root; a parent
 * that is not there, where the command may make it.
 *
 * A mount point on a file system that other hosts mount too (a network home) is
 * there for all of them, and a directory of this host's tells them nothing. So
 * a wrap names those in a manifest of their own in the home directory, where
 * that is on such a file system (see {@link networkManifestDirectoryName}). No
 * host can ask after another's processes, so there a manifest is live by its
 * age, and the process that wrote it keeps it young (see {@link
 * keepOwnManifestsYoung}).
 */

import { spawnSync } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import * as fs from 'node:fs'
import { tmpdir, userInfo } from 'node:os'
import path from 'node:path'
import { z } from 'zod/v3'
import { logForDebugging } from '../utils/debug.js'
import { isAbsenceErrno } from './sandbox-utils.js'

/**
 * The manifest layout this version writes. It reads this one and any later one,
 * by the fields it knows (see {@link ManifestSchema}).
 */
const MANIFEST_VERSION = 1
const MANIFEST_SUFFIX = '.json'
const STARTED_SUFFIX = '.started'
const CLAIMED_SUFFIX = '.claimed'
const FINISHED_SUFFIX = '.finished'
const PASS_SUFFIX = '.pass'
/** Where a manifest is found, in the order it goes through them. */
const MANIFEST_SUFFIXES = [MANIFEST_SUFFIX, CLAIMED_SUFFIX, FINISHED_SUFFIX]

/**
 * A manifest this young counts as live with no started record yet, so that a
 * command is not refused its start because the process that wrapped it was
 * killed a moment before.
 */
const MANIFEST_GRACE_MS = 500

/**
 * A pass with no more candidates than this lists the manifest directories again
 * before every removal, so each is judged on a listing a few microseconds old.
 * An ordinary pass is a handful of paths.
 */
const LISTS_BEFORE_EACH_REMOVAL_UP_TO = 64

/**
 * For how long one listing is good in a larger pass: well under the time a
 * starting sandbox needs to reach its binds, and a time so a directory of
 * thousands is not listed thousands of times.
 */
const LISTING_GOOD_FOR_MS = 0.25

/**
 * How often a reading starts over because a listed manifest was gone when it
 * was opened (claimed, given back or collected meanwhile) before it gives up.
 */
const LISTING_ATTEMPTS = 8

/**
 * What is at a manifest's name and is not one this version reads counts as
 * live until it is this old, and is dropped then: long enough for another
 * version of this library to keep its own format.
 */
const UNREADABLE_MANIFEST_MAX_AGE_MS = 60 * 60 * 1000

/**
 * A manifest of another PID namespace, or that records none, counts as live
 * until it and its record are this old. Nothing else ends one whose namespace
 * is gone: a restarted container keeps its files and the host's boot id.
 */
const OTHER_NAMESPACE_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000

/**
 * A manifest whose processes cannot be asked after, and whose writer keeps it
 * young, counts as live until it and its record are this old. Far more than
 * {@link KEPT_YOUNG_EVERY_MS}, for what lies between two hosts: their clocks, a
 * minute of cached attributes, a timer that is late.
 */
const OTHER_KERNEL_MAX_AGE_MS = 10 * 60 * 1000

/** How often a process sets the time of its manifests that other kernels read. */
const KEPT_YOUNG_EVERY_MS = 60 * 1000

/**
 * For how long one listing is good in a pass over a directory that other
 * kernels reach, where a listing is a round trip to a server.
 */
const NETWORK_LISTING_GOOD_FOR_MS = 20

/**
 * A pass removes nothing more this long after it set out to go on record, and
 * leaves the rest to the next: an ordinary one takes milliseconds.
 */
const PASS_GOOD_FOR_MS = 2 * 1000

/**
 * Both clocks. Whoever cannot ask after a pass goes by the age of its record,
 * which is wall-clock time; the other stands still while the host is suspended
 * (a laptop asleep, a virtual machine paused), and this one can be set back.
 */
const bothClocks = (): readonly [number, number] => [
  performance.now(),
  Date.now(),
]

/**
 * A pass that cannot be asked after (another PID namespace's, another host's)
 * counts as under way until its record is this old: well past {@link
 * PASS_GOOD_FOR_MS}.
 */
const PASS_MAX_AGE_MS = 60 * 1000

/**
 * For how long a wrap waits for the passes under way before it gives up: past
 * {@link PASS_GOOD_FOR_MS}, so that only one that is held up outlasts it.
 */
const WAITS_FOR_PASSES_MS = 5 * 1000

/** The largest file read as a manifest; a real one is a few kilobytes. */
const MANIFEST_MAX_BYTES = 1024 * 1024

/**
 * The largest file read as a started record: a line of some 300 bytes for each
 * run, so fourteen thousand runs of one command line.
 */
const RECORD_MAX_BYTES = 4 * 1024 * 1024

/**
 * Suffix of a manifest before it is moved into place. One left by a killed
 * process is removed at {@link UNREADABLE_MANIFEST_MAX_AGE_MS}.
 */
const TEMPORARY_SUFFIX = '.tmp'

const ManifestSchema = z.object({
  /**
   * INVARIANT for every later version: it may add fields, and keeps these, the
   * five file names and what they mean, so a reader takes a later version by
   * the fields it knows. A manifest that is not read puts everything in doubt,
   * which would refuse every wrap of an older process for as long as a newer
   * one is at work beside it. A change that cannot keep to this takes another
   * directory name.
   */
  version: z.number().int().min(MANIFEST_VERSION),
  /** The process that wrapped, and its start time, to tell a recycled pid. */
  pid: z.number().int().nonnegative(),
  start: z.string(),
  /**
   * The writer's PID namespace (`readlink /proc/self/ns/pid`): a pid can only
   * be asked after from there. Absent where it could not be read.
   */
  ns: z.string().optional(),
  /**
   * The boot it was written in. Absent where that could not be read. All that
   * tells this kernel's from another's where more than one reaches the directory
   * (see {@link ONE_KERNEL_FILE_SYSTEMS}).
   */
  boot: z.string().optional(),
  /**
   * Its writer sets its time every {@link KEPT_YOUNG_EVERY_MS} for as long as it
   * holds on to it. Said by the writer, who alone knows: the same directory can
   * be on one kind of file system to the writer and on another to a reader.
   */
  keptYoung: z.boolean().optional(),
  /** When the manifest was written, for {@link MANIFEST_GRACE_MS}. */
  created: z.number(),
  /** The mount points bwrap makes on the host for that wrap's deny paths. */
  paths: z.array(z.string()),
  /**
   * The empty directories those mount points bind from. A live bind's source
   * must stay, so they are collected the same way (see {@link
   * removeMountSource}).
   */
  sources: z.array(z.string()),
})

type Manifest = z.infer<typeof ManifestSchema> & {
  /** Where it is: at its own name, `<id>.json`, or at one of a claim's two. */
  file: string
  claimed: boolean
  /** Claimed, and by its name no process was left on its record after that. */
  finished: boolean
  /** Its started record, `<id>.started`. */
  record: string
  /**
   * In a directory that other kernels reach, and not of this kernel and PID
   * namespace for all that can be told: nothing here can ask after it.
   */
  elsewhere: boolean
  /**
   * Another host's, and it names what this host does not reach (which, of one in
   * the home, is left out of its lists).
   */
  namesMore: boolean
  /** This process wrote it and the caller says its command is over. */
  released: boolean
}

/**
 * Manifests this process wrote that are still on disk, by their own name, with
 * the command key the caller gave and whether that command is over. Remembered
 * rather than acted on at once: a manifest must stay on disk until a pass
 * removes what it names.
 */
const ownManifests = new Map<
  string,
  {
    commandKey: string | undefined
    over: boolean
    /** Other kernels read it, and have its age to go by. */
    byItsAge: boolean
  }
>()

/**
 * The mount points, and the directories they bind from, that no manifest names:
 * of wraps that could record them nowhere, and what a plan has made on the host
 * itself (`madeByAPlan`, which are among the other two) until a manifest is
 * published that names it, which takes it out of here. No other process knows of
 * them, so they are this process's to remove once none of its wraps is
 * outstanding, and kept until then: in a pass like any other where there is a
 * directory by then, so that a path another process's manifest names is kept,
 * and on its own word where there is none.
 */
const unrecorded = {
  paths: new Set<string>(),
  sources: new Set<string>(),
  madeByAPlan: new Set<string>(),
}

function keepTrackOf(made: string, among: Set<string>): void {
  // Else a wrap that could record it nowhere relies on it, whoever makes it now.
  if (!among.has(made)) unrecorded.madeByAPlan.add(made)
  among.add(made)
}

/**
 * Has what a plan has made on the host itself removed at this process's own
 * clean-up, from then until a manifest names it: the plan may come to nothing
 * before that.
 */
export function keepTrackOfMountSource(source: string): void {
  keepTrackOf(source, unrecorded.sources)
}

export function keepTrackOfMountPoint(mountPoint: string): void {
  keepTrackOf(mountPoint, unrecorded.paths)
}

/**
 * Which of this process's own manifests a collect may release. Only the caller
 * knows that a command is over, and will not be run again:
 *
 * - `all`: no wrap of this process is outstanding, or the process is ending;
 * - `ended`: some are, and the caller says one is over and not which, so those
 *   that have run and ended are;
 * - one command: that command, whatever else is running, and those that have
 *   run and ended;
 * - `none`: the caller has said nothing, so only what other processes have
 *   finished with is collected.
 *
 * A released manifest is collected once no process on its record runs, and its
 * command line is refused its start from then on.
 */
export type OwnManifestRelease =
  | 'all'
  | 'ended'
  | 'none'
  | { commandKey: string }

let manifestDirectory: string | undefined
// Whether that is the last resort below, which no other process knows of.
let manifestDirectoryIsPrivate = false
// Set once the last resort has been tried and found wanting, so a process on a
// temp dir that keeps no modes does not make a fresh directory on every call.
let manifestDirectoryUnavailable = false

/** Everything here is for bubblewrap, which is Linux's. */
const onLinux = (): boolean => process.platform === 'linux'

/**
 * Field 22 of a /proc/PID/stat line, the start time in clock ticks, counted
 * from the last ')' because the comm field can hold spaces and parentheses.
 * `undefined` for a line that is cut short or is not one.
 */
function startTimeFromProcStat(stat: string): string | undefined {
  const comm = stat.lastIndexOf(')')
  const start = stat
    .slice(comm + 1)
    .trim()
    .split(' ')[19]
  return comm > 0 && start !== undefined && /^\d+$/.test(start)
    ? start
    : undefined
}

/**
 * This process as the /proc it sees numbers it, which is what a pass will ask
 * after. `process.pid` is another number where the process has a PID namespace
 * of its own under an outer /proc (a nested sandbox): nobody's there, or an
 * unrelated process's.
 */
function ownProcess(): { pid: number; start: string } {
  try {
    const stat = fs.readFileSync('/proc/self/stat', 'utf8')
    const pid = /^\d+/.exec(stat)?.[0]
    if (pid !== undefined) {
      return { pid: Number(pid), start: startTimeFromProcStat(stat) ?? '' }
    }
  } catch {
    // No /proc: every manifest counts as live then (see isLive).
  }
  return { pid: process.pid, start: '' }
}

/**
 * Whether the process with that pid and start time is running. Only "no such
 * process", a process that has exited and a start time that differs say no: a
 * sandboxed command can use up what this user may open, and a /proc that cannot
 * be read must not make a live sandbox's mount points collectable. An unknown
 * `start` leaves the pid alone to go by.
 *
 * One that has exited stays in /proc until its parent asks after it. Where that
 * is a process 1 that never asks, as in many a container, it stays for good,
 * and so would what its sandbox relied on. It has let go of its namespaces and
 * sent its children their signal by then, like one that is gone.
 */
function isRunning(pid: number, start: string): boolean {
  let stat: string
  try {
    stat = fs.readFileSync(`/proc/${pid}/stat`, 'utf8')
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code
    return code !== 'ENOENT' && code !== 'ESRCH'
  }
  // Field 3, the first after the comm: Z is a zombie, X and x are dead.
  if (/^ [ZXx] /.test(stat.slice(stat.lastIndexOf(')') + 1))) {
    return false
  }
  const found = startTimeFromProcStat(stat)
  return found === undefined || !/^\d+$/.test(start) || found === start
}

let pidNamespace: string | undefined | null = null

/** This process's PID namespace as the kernel names it, or `undefined`. */
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

let bootId: string | undefined

/** This boot as the kernel names it, or `undefined`. */
function ownBootId(): string | undefined {
  try {
    return (bootId ??=
      fs.readFileSync('/proc/sys/kernel/random/boot_id', 'utf8').trim() ||
      undefined)
  } catch {
    return undefined
  }
}

/**
 * The kinds of file system that only processes of this kernel reach, by
 * `statfs`'s type. On any other (NFS, 9p, virtiofs, FUSE) a manifest may be
 * another running kernel's, and only the boot id tells: two hosts each in their
 * initial PID namespace name that alike. So there a manifest is this kernel's
 * only when its boot id and ours can both be read and are equal. Any other, and
 * one of another PID namespace of this kernel, is live by its age (see {@link
 * OTHER_KERNEL_MAX_AGE_MS}).
 *
 * INVARIANT: a list of what is let in, not of what is kept out. On a local kind
 * that is missing, what an earlier boot left waits those minutes instead of
 * going at once. A kind wrongly let in, as the next network file system would be
 * by a list of the known ones, has a live sandbox judged finished and its mount
 * points removed.
 */
const ONE_KERNEL_FILE_SYSTEMS = new Set([
  0x01021994, // tmpfs
  0xef53, // ext2, ext3, ext4
  0x58465342, // xfs
  0x9123683e, // btrfs
  0x794c7630, // overlayfs
  0x2fc12fc1, // zfs
  0xf2f52010, // f2fs
])

/**
 * The directories found on none of those, and until when that is believed, by
 * `performance.now()`: on a network file system the question is a round trip
 * each time. For a minute, because a share can be unmounted, and what another
 * host names there is then not this host's to judge or collect any more. Never
 * the other answer: a share can be mounted, and that has to be seen at once.
 */
const foundWithinOthersReach = new Map<string, number>()
const FOUND_WITHIN_OTHERS_REACH_FOR_MS = 60 * 1000

/**
 * Whether `dir` is on one of those, or on a kind that other kernels reach too;
 * `absent` where it is not there. What else cannot be asked is thrown with
 * `orThrow`, and else counts as within their reach.
 */
function reachOf(
  dir: string,
  orThrow = false,
): 'one kernel' | 'others too' | 'absent' {
  if (performance.now() < (foundWithinOthersReach.get(dir) ?? -Infinity)) {
    return 'others too'
  }
  let type: number
  try {
    type = Number(fs.statfsSync(dir).type)
  } catch (e) {
    if (isAbsenceErrno(e)) return 'absent'
    if (orThrow) throw e
    return 'others too'
  }
  if (ONE_KERNEL_FILE_SYSTEMS.has(type)) {
    return 'one kernel'
  }
  if (foundWithinOthersReach.size >= 1024) foundWithinOthersReach.clear()
  foundWithinOthersReach.set(
    dir,
    performance.now() + FOUND_WITHIN_OTHERS_REACH_FOR_MS,
  )
  return 'others too'
}

/** Whether `dir` is on one of those. Not where that cannot be asked. */
const isReachedByOneKernel = (dir: string): boolean =>
  reachOf(dir) === 'one kernel'

/**
 * Whether other kernels reach what is in `dir`, going by the nearest directory
 * at or above it that is there: on a host that does not have `/scratch`,
 * `/scratch/x` is a name on its own root and no share.
 */
function othersReachInto(dir: string): boolean {
  for (;;) {
    const reach = reachOf(dir)
    if (reach !== 'absent' || dir === path.dirname(dir)) {
      return reach !== 'one kernel'
    }
    dir = path.dirname(dir)
  }
}

/** Whether other kernels reach the path `p`. */
const othersReach = (p: string): boolean => othersReachInto(path.dirname(p))

/**
 * Whether `file` was last written over `ms` ago. One that cannot be looked at,
 * or is not there, was not.
 */
function olderThan(file: string, ms: number): boolean {
  try {
    return Date.now() - fs.lstatSync(file).mtimeMs > ms
  } catch {
    return false
  }
}

/**
 * Whether `dir` is a directory of ours, with `alone`, that nobody else can
 * write, and, with `toWrite`, that we can. With `orThrow`, an error that says
 * neither "not there" nor "not to be written from here" is thrown, for a caller
 * that must not take it for a no.
 */
function isOurPrivateDirectory(
  dir: string,
  { orThrow = false, toWrite = true, alone = true } = {},
): boolean {
  try {
    const stat = fs.lstatSync(dir)
    if (
      !stat.isDirectory() ||
      stat.uid !== process.getuid?.() ||
      (alone && (stat.mode & 0o077) !== 0)
    ) {
      return false
    }
    // A directory an outer sandbox binds read-only reads as ours in every
    // other respect.
    if (toWrite) fs.accessSync(dir, fs.constants.W_OK | fs.constants.X_OK)
    return true
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code
    if (
      orThrow &&
      !isAbsenceErrno(e) &&
      code !== 'EACCES' &&
      code !== 'EROFS'
    ) {
      throw e
    }
    return false
  }
}

/**
 * Make `dir` a directory of ours alone, or say it cannot be. The name is
 * predictable and sandboxed commands can often write beside it, so it is opened
 * without following a link and its mode is set on the descriptor: a symlink
 * planted at the name is refused, not followed.
 */
function makeOurPrivateDirectory(dir: string): boolean {
  // As it mostly is, and all that follows comes to this question in the end: in
  // a network home each step of it is a round trip.
  if (!isReachedByOneKernel(dir) && isOurPrivateDirectory(dir)) {
    return true
  }
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
 * Whether bubblewrap could not reach a manifest under `dir`: the wrap mounts a
 * fresh /dev and /proc over whatever was bound beneath them.
 */
function isBuriedBySandboxMounts(dir: string): boolean {
  return ['/dev', '/proc', '/sys'].some(
    root => dir === root || dir.startsWith(`${root}/`),
  )
}

// Test seam: what stands in for `/` in the names that follow from the user id,
// and in /etc/passwd.
let root = '/'

/**
 * The names every process of this user works out alike, in the order tried:
 * under /var/tmp, which is local to the host and outlives a logout and a
 * reboot; under /run/user/UID, where that is a directory of the user's; under
 * /tmp. INVARIANT for every later version: it goes on reading these.
 *
 * To be written under (`toWrite`), /run/user/UID has to be closed to everyone
 * else as well. Not to be read under: where it is a write root the command can
 * chmod it, and must not make other processes read less by that. Reading more
 * does no harm, a manifest being only a claim about a path.
 */
function fixedManifestDirectoryNames(
  orThrow = false,
  toWrite = false,
): string[] {
  const uid = process.getuid?.() ?? 0
  const runtimeDir = path.join(root, 'run/user', String(uid))
  return [
    path.join(root, 'var/tmp', `srt-mount-points-${uid}`),
    ...(isOurPrivateDirectory(runtimeDir, {
      orThrow,
      toWrite: false,
      alone: toWrite,
    })
      ? [path.join(runtimeDir, 'srt-mount-points')]
      : []),
    path.join(root, 'tmp', `srt-mount-points-${uid}`),
  ]
}

/** What the directory in a network home is called. */
const NETWORK_DIRECTORY = '.srt-mount-points'

/** For how long "no such user" is taken for an answer. */
const NO_HOME_GOOD_FOR_MS = 60 * 1000

/**
 * For how long no answer at all is not asked for again. Each asking holds the
 * thread for as long as `getent` is given, and a wrap that is refused asks more
 * than once.
 */
const NO_ANSWER_GOOD_FOR_MS = 10 * 1000

let home: { dir: string | undefined; asked: number } | undefined
let noAnswer: { error: Error; asked: number } | undefined

/**
 * The user's home as the user database has it, not as the environment does, or
 * `undefined`. Asked once: the database may be a directory service.
 *
 * Node asks the C library. Bun answers `os.userInfo()` with `$HOME`, so there it
 * is /etc/passwd and then `getent`, at its usual places and never looked up on
 * `PATH`, for a user only a directory service knows.
 *
 * INVARIANT: no answer but a home is kept for good. A process that took an
 * outage for "no home" would neither read what the others keep there nor keep
 * its own sandboxes out of it, for as long as it runs. So it throws where it gets
 * no answer; and "no such user", which is also all that a directory service that
 * is down has the C library say, is asked again after {@link
 * NO_HOME_GOOD_FOR_MS}.
 */
function homeDirectory(): string | undefined {
  if (
    home !== undefined &&
    (home.dir !== undefined ||
      performance.now() - home.asked < NO_HOME_GOOD_FOR_MS)
  ) {
    return home.dir
  }
  if (
    noAnswer !== undefined &&
    performance.now() - noAnswer.asked < NO_ANSWER_GOOD_FOR_MS
  ) {
    throw noAnswer.error
  }
  const uid = String(process.getuid?.() ?? 0)
  const inPasswdLines = (text: string): string | undefined =>
    text
      .split('\n')
      .map(line => line.split(':'))
      .find(fields => fields[2] === uid)?.[5]
  let dir: string | undefined
  if (root === '/' && process.versions['bun'] === undefined) {
    try {
      dir = userInfo().homedir
    } catch {
      // No such user, for all it says.
    }
  } else {
    try {
      dir = inPasswdLines(
        fs.readFileSync(path.join(root, 'etc/passwd'), 'utf8'),
      )
    } catch (e) {
      if (!isAbsenceErrno(e)) throw e
    }
    const getent =
      dir === undefined
        ? ['usr/bin/getent', 'bin/getent', 'run/current-system/sw/bin/getent']
            .map(file => path.join(root, file))
            .find(file => fs.existsSync(file))
        : undefined
    if (getent !== undefined) {
      const asked = spawnSync(getent, ['passwd', uid], {
        encoding: 'utf8',
        env: {},
        stdio: ['ignore', 'pipe', 'ignore'],
        timeout: 5000,
      })
      // 2 is its word for "no such key".
      if (asked.status !== 0 && asked.status !== 2) {
        noAnswer = {
          error: new Error(
            `${getent} passwd ${uid} gave no answer (${asked.error?.message ?? `status ${asked.status}`})`,
          ),
          asked: performance.now(),
        }
        throw noAnswer.error
      }
      dir = inPasswdLines(asked.stdout)
    }
  }
  home = {
    dir: dir !== undefined && path.isAbsolute(dir) ? dir : undefined,
    asked: performance.now(),
  }
  return home.dir
}

/**
 * What {@link networkManifestDirectoryName} has found, once it has found one.
 * For what follows from the directories a wrap or a pass has already worked out:
 * it asks nothing, so it does not throw half way through either.
 */
let network: string | undefined

/**
 * Where the manifests go that name what other hosts reach too: in the user's
 * home directory, where that is itself on a file system more than one kernel
 * reaches, and `undefined` where it is not. Hosts that share a home work it out
 * alike, and on a host with a home of its own nothing is read or written there
 * (it is kept out of reach there too: see {@link
 * mountPointManifestDirectories}).
 *
 * Read, bound read-only and pinned like the places that follow from the user id,
 * and written only for what other hosts reach: it is no place for what they do
 * not, and does not stand in for one.
 *
 * INVARIANT: only on the file system's own word. A home that is not there, or
 * that this user may not enter, is no network home: no wrap could make or bind
 * the directory in it, and a sandboxed command that then made both would be
 * believed. Throws where it cannot tell (an error of the moment, twice, on a
 * home that may hold the directory): a wrap that went on would leave it unbound.
 * And only that there is one is remembered: a home on this host's own disk may
 * be what shows until the share is mounted over it.
 *
 * What speaks against a home directory, and what is done about it:
 *
 * - A network file system caches listings, and all of this rests on one process
 *   seeing what another has put into the directory. A client asks the server
 *   again for a directory it opens, and for one it has itself just changed.
 *   Where it matters each side has: a pass goes on record before the reading it
 *   decides on, and a wrap publishes before it lists the passes and reads the
 *   manifests again.
 * - It caches what is in the directories the mount points are in as well: see
 *   {@link lookAfreshAt}.
 * - Another boot id may be another live host's: see {@link
 *   ONE_KERNEL_FILE_SYSTEMS}.
 * - Nothing ages what is left there: see {@link OTHER_KERNEL_MAX_AGE_MS}.
 * - It is often inside a write root: it is bound read-only and what lies above
 *   it is pinned, like the others.
 */
function networkManifestDirectoryName(): string | undefined {
  if (network !== undefined) {
    return network
  }
  const dir = homeDirectory()
  if (dir === undefined || isBuriedBySandboxMounts(dir)) {
    return undefined
  }
  for (const last of [false, true]) {
    try {
      if (reachOf(dir, true) === 'others too') {
        network = path.join(dir, NETWORK_DIRECTORY)
      }
      break
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === 'EACCES') break
      if (last) throw e
    }
  }
  return network
}

/**
 * Whether other hosts that keep their manifests where this one does reach one of
 * `paths`: what they do is then this wrap's business, and the other way round.
 */
export function otherHostsReach(paths: readonly string[]): boolean {
  // Nothing is asked for a wrap that names nothing: it may restrict no write.
  return (
    paths.length > 0 &&
    networkManifestDirectoryName() !== undefined &&
    paths.some(othersReach)
  )
}

/**
 * Has a network file system compare what it remembers of `p` with the server's,
 * which it does for what is opened (close-to-open consistency).
 */
function openAndClose(p: string, flags: number): void {
  try {
    fs.closeSync(fs.openSync(p, flags))
  } catch {
    // Not there, or not to be opened: the look that follows says so.
  }
}

/**
 * Has this host ask again what is in the directories that hold `paths`, those
 * of them that other hosts reach. A network file system answers a look-up from
 * what it remembers, for seconds to a minute, so a mount point another host has
 * just removed would be found there still, by the wrap and by bubblewrap, which
 * would mount on what the server no longer has: the mount goes when the client
 * finds out. Opening a directory has the client compare it with the server's,
 * and look up again what is in one that has changed.
 *
 * Only where there is a network home: without the manifests in it no host knows
 * what another is about, and there is nothing to find out in time.
 */
export function lookAfreshAt(paths: Iterable<string>): void {
  if (network === undefined) {
    return
  }
  for (const dir of new Set([...paths].map(p => path.dirname(p)))) {
    if (othersReachInto(dir)) {
      openAndClose(dir, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY)
    }
  }
}

let keptYoung: ReturnType<typeof setInterval> | undefined

/** Sets the time of `file` to now, by this host's clock, if it can be set. */
function touch(file: string): void {
  const now = new Date()
  try {
    fs.utimesSync(file, now, now)
  } catch {
    // It has the server's.
  }
}

/**
 * Puts a file that holds `text` at `file`, in a directory other kernels read.
 * They go by its age, by this host's clock and not the server's, so it comes to
 * its name whole and with its time set. Throws, with nothing left there, where
 * it cannot be.
 */
function putWhereOtherKernelsRead(file: string, text: string): void {
  const temporary = `${file}${TEMPORARY_SUFFIX}`
  try {
    const fd = fs.openSync(temporary, 'wx', 0o600)
    try {
      if (text !== '') {
        // A network file system takes the bytes, and says only as they are
        // flushed that it has no room for them. Bun passes on neither what
        // closing the file says nor what the `flush` option finds.
        fs.writeFileSync(fd, text)
        fs.fsyncSync(fd)
      }
    } finally {
      fs.closeSync(fd)
    }
    touch(temporary)
    fs.renameSync(temporary, file)
  } catch (e) {
    drop(temporary)
    throw e
  }
}

/**
 * Has the time of every manifest of this process that other kernels read set
 * every {@link KEPT_YOUNG_EVERY_MS}, for as long as this process knows of one:
 * its age is all they have to go by. By this host's clock and not the server's,
 * so that what has to agree is the clocks of the hosts.
 *
 * On a timer, so a process that does not come back to its event loop for {@link
 * OTHER_KERNEL_MAX_AGE_MS} (stopped with its sandbox, or waiting for its command
 * in a call that blocks) is taken for gone by the other hosts. The timer does
 * not keep the process alive, and an error does not end it: the next tick may do.
 */
function keepOwnManifestsYoung(): void {
  const some = [...ownManifests.values()].some(own => own.byItsAge)
  if (some && keptYoung === undefined) {
    keptYoung = setInterval(setTheTimesOfOwnManifests, KEPT_YOUNG_EVERY_MS)
    keptYoung.unref()
  } else if (!some && keptYoung !== undefined) {
    clearInterval(keptYoung)
    keptYoung = undefined
  }
}

let settingTimes = false

/**
 * One tick of that. Not with the calls that wait: nobody has asked for anything
 * when it runs, and a server that does not answer would hold up the one thread
 * of whatever program this is part of. One request at a time, and no tick while
 * the last is at it, so that such a server ties up one thread of the pool those
 * requests run on and not all of them.
 */
function setTheTimesOfOwnManifests(): void {
  // Those a pass has collected since the last tick are forgotten by now.
  keepOwnManifestsYoung()
  if (settingTimes) {
    return
  }
  settingTimes = true
  const left = [...ownManifests].filter(([, own]) => own.byItsAge)
  const next = (): void => {
    const [file, own] = left.shift() ?? []
    if (file === undefined || own === undefined) {
      settingTimes = false
      return
    }
    const now = new Date()
    const done = (e: NodeJS.ErrnoException | null): void => {
      if (e !== null && !(isAbsenceErrno(e) && own.over)) {
        logForDebugging(
          `[Sandbox Linux] The time of the manifest ${file} could not be set (${String(e)}) - other hosts take its mount points for left behind once it is old`,
          { level: 'warn' },
        )
      }
      next()
    }
    fs.utimes(file, now, now, e =>
      // A pass of this host has it, and gives it back if a sandbox runs.
      e !== null && isAbsenceErrno(e)
        ? fs.utimes(`${idOf(file)}${CLAIMED_SUFFIX}`, now, now, done)
        : done(e),
    )
  }
  next()
}

/**
 * Where processes of this user keep manifests that others can find, in the
 * order tried: {@link fixedManifestDirectoryNames}, then, for a process that
 * can use none of those (a minimal or read-only image, another sandbox), under
 * $XDG_RUNTIME_DIR and under the system temp dir.
 */
function sharedManifestDirectoryNames(
  orThrow = false,
  toWrite = false,
): string[] {
  const shared = fixedManifestDirectoryNames(orThrow, toWrite)
  const runtimeDir = process.env['XDG_RUNTIME_DIR']
  if (runtimeDir !== undefined && path.isAbsolute(runtimeDir)) {
    shared.push(path.join(runtimeDir, 'srt-mount-points'))
  }
  shared.push(
    path.join(tmpdir(), `srt-mount-points-${process.getuid?.() ?? 0}`),
  )
  return [...new Set(shared)].filter(
    candidate => !isBuriedBySandboxMounts(candidate),
  )
}

/**
 * The directories whose manifests this process believes: it reads them all, and
 * claims and collects in those it can write. The names that follow from the
 * user id; the ones the environment gives only where none of those can be
 * written, because only processes with that environment keep them out of a
 * sandbox's reach; {@link networkManifestDirectoryName}; and the one it has
 * settled on. Each only while it is a directory of ours alone. Makes nothing.
 * Throws where it cannot tell.
 *
 * Each directory once, whatever it is called: where /var/tmp is a link to /tmp,
 * or a bind mount of it, two of the names are one directory. Every manifest in
 * it would be read at two names, and no pass could go on record in it twice.
 */
function believedManifestDirectories(): string[] {
  const names = fixedManifestDirectoryNames(true, true).some(dir =>
    isOurPrivateDirectory(dir, { orThrow: true }),
  )
    ? fixedManifestDirectoryNames(true)
    : sharedManifestDirectoryNames(true)
  const inTheHome = networkManifestDirectoryName()
  if (inTheHome !== undefined) names.push(inTheHome)
  if (manifestDirectory !== undefined) names.push(manifestDirectory)
  const byIdentity = new Map<string, string>()
  for (const dir of names) {
    if (!isOurPrivateDirectory(dir, { orThrow: true, toWrite: false })) continue
    let identity: string
    try {
      // As big integers: a number does not hold every inode number apart.
      const { dev, ino } = fs.lstatSync(dir, { bigint: true })
      identity = `${dev}:${ino}`
    } catch (e) {
      if (isAbsenceErrno(e)) continue
      throw e
    }
    // By the name this process writes under, which it knows its own manifests
    // by; else by one it can be written at (the other may be a read-only bind).
    const sofar = byIdentity.get(identity)
    if (
      sofar === undefined ||
      dir === manifestDirectory ||
      (sofar !== manifestDirectory &&
        !isOurPrivateDirectory(sofar) &&
        isOurPrivateDirectory(dir))
    ) {
      byIdentity.set(identity, dir)
    }
  }
  return [...byIdentity.values()]
}

/**
 * The directory manifests live in: the first shared name that can be made ours
 * alone, else a private directory only this process knows, which keeps the
 * guarantee within this process. Revalidated on every use, because a directory
 * swapped for a symlink between two wraps would send manifests elsewhere.
 */
function ensureManifestDirectory(): string | undefined {
  if (
    manifestDirectory !== undefined &&
    isOurPrivateDirectory(manifestDirectory)
  ) {
    return manifestDirectory
  }
  manifestDirectoryIsPrivate = false
  for (const candidate of sharedManifestDirectoryNames(false, true)) {
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
    logForDebugging(
      `[Sandbox Linux] No directory for mount point manifests (${String(e)}) - the mount points this process makes are kept in memory and removed at its own clean-up`,
      { level: 'warn' },
    )
    return undefined
  }
}

/**
 * Every directory a wrap must bind read-only because some process of this user
 * keeps manifests in it and a collect believes what it finds there: every
 * shared name, whichever this process writes to, the one in a network home, and
 * the one it settled on.
 *
 * Each is made if it can be, so a sandboxed command cannot make and fill it
 * first. One that can be neither made nor bound is not believed, and the
 * command does not bring it into being either:
 *
 * - its parent is not there: it is missing from /var, /run/user or /, which
 *   are root's to write (what the environment names may be missing anywhere);
 * - its parent is read-only: so is every mount made from it;
 * - another user has the name, in a sticky directory: only that user or root
 *   can remove or rename it.
 *
 * INVARIANT: the one in the home is kept out of reach on a host that does not
 * believe it as well. A home that is this host's own disk may be a network home
 * to others (it is to the clients of the server that exports it), who believe
 * what they find there. So it is bound wherever it is there, and where it is
 * not, but the command could make it (`commandMayMake`), it is made first.
 *
 * With `recording`, the directory this wrap's manifest will go to is settled
 * first, so the wrap can pin what lies above it before it publishes. Throws
 * where it cannot tell whether one of them is there.
 */
export function mountPointManifestDirectories(
  recording = false,
  commandMayMake: (dir: string) => boolean = () => false,
): string[] {
  if (!onLinux()) {
    return []
  }
  const dirs = new Set<string>()
  // A real directory, not a link to one, and the user's. An error of the moment
  // is not "not there": left unbound on that, it is believed again a moment
  // later, by this process and by every other.
  const isToBeBound = (dir: string): boolean =>
    isOurPrivateDirectory(dir, { orThrow: true, toWrite: false, alone: false })
  for (const candidate of sharedManifestDirectoryNames(true)) {
    makeOurPrivateDirectory(candidate)
    if (isToBeBound(candidate)) {
      dirs.add(candidate)
    }
  }
  const believed = networkManifestDirectoryName()
  const home = homeDirectory()
  const inTheHome =
    believed ??
    (home === undefined || isBuriedBySandboxMounts(home)
      ? undefined
      : path.join(home, NETWORK_DIRECTORY))
  if (inTheHome !== undefined) {
    if (believed !== undefined || commandMayMake(inTheHome)) {
      makeOurPrivateDirectory(inTheHome)
    }
    if (isToBeBound(inTheHome)) {
      dirs.add(inTheHome)
    }
  }
  if (recording) {
    ensureManifestDirectory()
  }
  if (manifestDirectory !== undefined && isToBeBound(manifestDirectory)) {
    dirs.add(manifestDirectory)
  }
  return [...dirs]
}

/**
 * Remove the directory only this process knows, once it is empty, when the
 * process or its session ends. It stays while a manifest is in it.
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

/** What is at a name and is not what this library keeps there. */
class NotOurs extends Error {}

/**
 * What can be a manifest of no version. A manifest is not synced before it is
 * moved into place, so a crash can leave one with nothing in it.
 */
class NotJson extends NotOurs {}

/**
 * Whether `file` is what an open does not refuse for what it is: a regular file
 * of the user's that its owner may read. What cannot be looked at may be.
 */
function isOwnReadableFile(file: string): boolean {
  try {
    const stat = fs.lstatSync(file)
    return (
      stat.isFile() &&
      stat.uid === process.getuid?.() &&
      (stat.mode & 0o400) !== 0
    )
  } catch {
    return true
  }
}

/**
 * What `file` holds, or `undefined` where nothing is there. Only a regular file
 * of the user's, no larger than `max`, is read, through a descriptor opened
 * without following a link and without blocking. Throws {@link NotOurs} for
 * anything else that is there, and the error itself where that cannot be told.
 */
function readOwnFile(file: string, max: number): string | undefined {
  let fd: number
  try {
    fd = fs.openSync(
      file,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK,
    )
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === 'ENOENT') return undefined
    // A link, a socket, a file of mode 000: that lasts. Anything else passes.
    throw isOwnReadableFile(file)
      ? e
      : new NotOurs(`${file} is not a readable regular file of this user's`)
  }
  try {
    const stat = fs.fstatSync(fd)
    if (!stat.isFile() || stat.uid !== process.getuid?.() || stat.size > max) {
      throw new NotOurs(`${file} is not a small regular file of this user's`)
    }
    return fs.readFileSync(fd, 'utf8')
  } finally {
    fs.closeSync(fd)
  }
}

/** `<directory>/<id>` of a manifest, its claim or its started record. */
const idOf = (file: string): string => file.slice(0, file.lastIndexOf('.'))

/**
 * What the manifests hold that have been read in a directory other kernels
 * reach, by `<directory>/<id>`, for as long as they are listed. There each read
 * is several round trips to a server, every wrap reads every manifest, and a
 * manifest is never rewritten: its name is all that changes.
 */
const remembered = new Map<
  string,
  {
    fields: z.infer<typeof ManifestSchema>
    /**
     * Until when, by `performance.now()`, it is young whatever happens: its time
     * is only ever set forward. A look at it is a round trip as well, and every
     * pass judges every manifest of every host.
     */
    youngUntil: number
  }
>()

/**
 * The manifest at `file`, which is its own name or a claim's, or `undefined`
 * where nothing is there. Throws like {@link readOwnFile}, and {@link NotOurs}
 * for what does not hold a manifest's fields. One that is {@link remembered} is
 * taken to be where the caller has just found it listed. `othersReadIt` says
 * whether its directory is one that other kernels reach.
 */
function readManifest(
  file: string,
  othersReadIt: boolean,
  reached: (p: string) => boolean = othersReach,
): Manifest | undefined {
  const id = idOf(file)
  let fields = othersReadIt ? remembered.get(id)?.fields : undefined
  if (fields === undefined) {
    let text: string | undefined
    try {
      text = readOwnFile(file, MANIFEST_MAX_BYTES)
    } catch (e) {
      // A network file system's word for a file another host has removed since
      // this one looked it up or opened it. Of a manifest, whose reader then
      // starts over; a record that cannot be read vouches, whatever the error.
      if ((e as NodeJS.ErrnoException).code !== 'ESTALE') throw e
    }
    if (text === undefined) {
      return undefined
    }
    let json: unknown
    try {
      json = JSON.parse(text)
    } catch {
      throw new NotJson(`${file} is not JSON`)
    }
    const parsed = ManifestSchema.safeParse(json)
    if (!parsed.success) {
      throw new NotOurs(`${file} is not a manifest this version can read`)
    }
    fields = parsed.data
    if (othersReadIt) remembered.set(id, { fields, youngUntil: -Infinity })
  }
  const ofThisBoot = fields.boot !== undefined && fields.boot === ownBootId()
  const elsewhere =
    othersReadIt &&
    // Its own it knows, where it cannot read what would say so.
    !ownManifests.has(`${id}${MANIFEST_SUFFIX}`) &&
    !(ofThisBoot && fields.ns !== undefined && fields.ns === ownPidNamespace())
  // INVARIANT: of what another host has put into the home only what that host
  // and this one both reach counts. `/data/x` there may be another file than
  // here, and here it may be the user's own. Asked at every reading: a share may
  // have been mounted since the last.
  const inTheHome = path.dirname(file) === network
  const counts = elsewhere && inTheHome ? reached : (): boolean => true
  return {
    ...fields,
    paths: fields.paths.filter(counts),
    sources: fields.sources.filter(counts),
    file,
    claimed: !file.endsWith(MANIFEST_SUFFIX),
    finished: file.endsWith(FINISHED_SUFFIX),
    record: `${id}${STARTED_SUFFIX}`,
    elsewhere,
    // In any other directory that both hosts read (a /var/tmp that diskless
    // nodes share) a manifest names all its wrap relies on, and all of it
    // counts, as before there was one in the home. It is as little for this
    // host to collect.
    namesMore:
      elsewhere &&
      (inTheHome || !ofThisBoot) &&
      ![...fields.paths, ...fields.sources].every(reached),
    released: ownManifests.get(`${id}${MANIFEST_SUFFIX}`)?.over === true,
  }
}

/**
 * Whether a process on the started record is running, or `undefined` with no
 * whole line on record. A record that cannot be read, is not the user's regular
 * file, or holds a line that is no /proc/PID/stat line vouches: only a process
 * that is gone says its sandbox has ended.
 *
 * A command line may be run again and again, and each run adds its line. Every
 * one of them is asked after, the last first: the first run may outlast all that
 * follow it.
 *
 * Not so an `orphan`, which has no manifest that can be read: it names no path,
 * so it protects none. Only a process that can be asked after vouches there, and
 * an error that says nothing of the file.
 *
 * What follows the last newline counts as not written, an empty record
 * included. The command line execs bubblewrap only once its whole line is
 * written, so no sandbox is behind it yet, and one that follows is refused its
 * start by a claim like any that has not put itself on record. Taking it for a
 * running sandbox would keep what a shell killed there named for ever.
 */
function recordVouches(record: string, orphan = false): boolean | undefined {
  let lines: string[]
  try {
    const text = readOwnFile(record, RECORD_MAX_BYTES)
    if (text === undefined) {
      return undefined
    }
    lines = text.split('\n').slice(0, -1).reverse()
  } catch (e) {
    return !(orphan && e instanceof NotOurs)
  }
  if (lines.length === 0) {
    return undefined
  }
  return lines.some(line => {
    const pid = /^(\d+) \(/.exec(line)?.[1]
    const start = startTimeFromProcStat(line)
    return pid === undefined || start === undefined
      ? !orphan
      : isRunning(Number(pid), start)
  })
}

const isOfAnotherBoot = (manifest: Manifest): boolean =>
  manifest.boot !== undefined &&
  manifest.boot !== (ownBootId() ?? manifest.boot)

/**
 * Whether this process can tell if the processes behind a manifest run: of this
 * kernel's, none of another boot does, and of this one it can ask after those of
 * its own PID namespace. What {@link isLive} says of any other goes by its age
 * alone.
 */
function canBeAskedAfter(manifest: Manifest): boolean {
  const here = ownPidNamespace()
  return (
    !manifest.elsewhere &&
    (isOfAnotherBoot(manifest) || (here !== undefined && manifest.ns === here))
  )
}

/**
 * A manifest is no longer at the name a listing showed it at: renamed, or
 * dropped. What was made of that listing is out of date.
 */
class Moved extends Error {}

/**
 * {@link isLive} for a manifest whose processes cannot be asked after: until it
 * and its record are old, by what its writer says it does about that. What
 * cannot be looked at is live.
 *
 * Throws {@link Moved} for one that is gone from its name. Not "live": whoever
 * dropped it may have kept a path for a manifest of the caller's, and a caller
 * that kept the path for this one in turn would leave it to nobody. And not
 * "finished": it may only have been claimed, and be given back.
 */
function isLiveByItsAge(manifest: Manifest): boolean {
  const maxAge = manifest.keptYoung
    ? OTHER_KERNEL_MAX_AGE_MS
    : OTHER_NAMESPACE_MAX_AGE_MS
  const known = remembered.get(idOf(manifest.file))
  if (known !== undefined && performance.now() < known.youngUntil) {
    return true
  }
  let age: number
  try {
    age = Date.now() - fs.lstatSync(manifest.file).mtimeMs
  } catch (e) {
    if (isAbsenceErrno(e)) throw new Moved(manifest.file)
    return true
  }
  try {
    age = Math.min(age, Date.now() - fs.lstatSync(manifest.record).mtimeMs)
  } catch (e) {
    if (!isAbsenceErrno(e)) return true
  }
  if (known !== undefined) {
    known.youngUntil = performance.now() + (maxAge - age)
  }
  return age <= maxAge
}

/**
 * Whether a sandbox that named this manifest may be running, or may yet start.
 * Where other kernels reach its directory, one that is not of this kernel and
 * PID namespace goes by its age, which its writer keeps low for as long as it
 * holds on to it. Where only this kernel does, none of another boot is, whatever
 * else the manifest says, and only a process in the PID namespace that wrote it
 * can tell; to any other it is live until {@link OTHER_NAMESPACE_MAX_AGE_MS}. A process on its started record that runs keeps
 * it live, whatever else. With none, no sandbox is past a claim, and one at its
 * own name that the caller has not released is live while its writer runs (its
 * command line may be run yet, for the first time or again), or while it is
 * young and has no record.
 */
function isLive(manifest: Manifest): boolean {
  if (manifest.elsewhere) {
    return isLiveByItsAge(manifest)
  }
  if (isOfAnotherBoot(manifest)) {
    return false
  }
  if (!canBeAskedAfter(manifest)) {
    return ownPidNamespace() === undefined || isLiveByItsAge(manifest)
  }
  const vouched = recordVouches(manifest.record)
  if (vouched === true) {
    return true
  }
  return (
    !manifest.claimed &&
    !manifest.released &&
    ((vouched === undefined &&
      Date.now() - manifest.created < MANIFEST_GRACE_MS) ||
      isRunning(manifest.pid, manifest.start))
  )
}

/**
 * Whether `manifest` names what this host does not reach, and is not so old that
 * no host that does will come for it any more. Collected from here, the rest of
 * what it names would have nothing left to name it; and held on to from here,
 * with what this host reaches removed, it would go on naming that.
 */
const isForAnotherHostToCollect = (manifest: Manifest): boolean =>
  manifest.namesMore &&
  (performance.now() <
    (remembered.get(idOf(manifest.file))?.youngUntil ?? -Infinity) ||
    !olderThan(manifest.file, OTHER_NAMESPACE_MAX_AGE_MS))

/**
 * What became of a path a pass set out to remove: `left` when it is gone or no
 * longer what bubblewrap or this library made, `occupied` when it is a directory
 * with something in it, `failed` when it is still a mount point and could not be
 * removed from here.
 */
type Removal = 'removed' | 'left' | 'occupied' | 'failed'

/** What a removal that threw says of the path. */
function afterFailedRemoval(e: unknown, what: string): Removal {
  const code = (e as NodeJS.ErrnoException | undefined)?.code
  // Not empty after all: something was put into it meanwhile.
  if (code === 'ENOTEMPTY' || code === 'EEXIST') {
    return 'occupied'
  }
  if (isAbsenceErrno(e)) {
    return 'left'
  }
  logForDebugging(`[Sandbox Linux] Could not remove ${what} (${String(e)})`)
  return 'failed'
}

/**
 * Remove an empty directory a placeholder bound from, if it is still our own.
 * It sits where sandboxed commands can often write, so anything but a private
 * empty directory of ours is left exactly as found.
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
    return afterFailedRemoval(e, `the empty-directory mount source ${source}`)
  }
}

/** {@link kindOfMountPoint}, throwing what the look at `p` throws. */
function shapeOf(p: string): 'file' | 'directory' | undefined {
  const stat = fs.lstatSync(p)
  if (stat.uid !== process.getuid?.()) {
    return undefined
  }
  if (stat.isDirectory()) {
    return 'directory'
  }
  return stat.isFile() && stat.size === 0 && stat.nlink === 1
    ? 'file'
    : undefined
}

/**
 * What kind of mount point `p` can still be, by what is there now: an empty
 * regular file (not a link) under one name, or a directory, and the user's;
 * `undefined` for anything else. A manifest is only a claim about a path, so
 * nothing is covered, spared or removed on its word that does not look like
 * what bubblewrap leaves; and the look proves nothing without a manifest.
 *
 * Not by its mode: bubblewrap makes the file 0444 from 0.5.0 and 0666 less the
 * umask before, and one taken for the user's own on its write bits is never
 * removed.
 */
export function kindOfMountPoint(p: string): 'file' | 'directory' | undefined {
  try {
    return shapeOf(p)
  } catch {
    return undefined
  }
}

/**
 * Remove a mount point if it is still the empty file or directory bwrap made;
 * anything else is left where it is.
 */
function removeMountPoint(mountPoint: string): Removal {
  try {
    const kind = shapeOf(mountPoint)
    if (kind === undefined) {
      logForDebugging(
        `[Sandbox Linux] Left a path a manifest names where it is, it no longer looks like a bwrap mount point: ${mountPoint}`,
      )
      return 'left'
    }
    if (kind === 'file') {
      fs.unlinkSync(mountPoint)
    } else {
      if (fs.readdirSync(mountPoint).length > 0) {
        return 'occupied'
      }
      // rmdir, not a recursive remove: it neither follows a symlink nor
      // descends, so a path that is no longer ours is left exactly as found.
      fs.rmdirSync(mountPoint)
    }
    logForDebugging(
      `[Sandbox Linux] Cleaned up bwrap mount point (${kind}): ${mountPoint}`,
    )
    return 'removed'
  } catch (e) {
    return afterFailedRemoval(e, `the bwrap mount point ${mountPoint}`)
  }
}

/** What {@link publishMountPointManifest} wrote, for the bwrap invocation. */
export type MountPointManifest = {
  /** The directory to bind read-only inside the sandbox. */
  dir: string
  /** The manifest, for bubblewrap to bind before it makes a mount point. */
  file: string
  /** Its started record, for the command line to append to before bubblewrap. */
  started: string
}

/**
 * Record the mount points this wrap relies on, and the empty directories they
 * bind from, before the sandbox can start. Returns what was written.
 *
 * All of it goes into a manifest in a place of this host's, as on a host with a
 * home of its own: a process of this host that does not see the home (a service
 * kept out of it, a container with another) reads it there. What other hosts
 * reach too goes into a second one as well, where they read it (see {@link
 * networkManifestDirectoryName}), and nothing else does: whoever reads a manifest
 * can then collect it whole. Where that one cannot be written (a home over its
 * quota) the first is all there is.
 *
 * What could be recorded nowhere is kept in memory and removed at this process's
 * own clean-up, since no other process will know of it. `too-large`, with
 * nothing written or added to that, for more than one manifest holds: its own
 * reader would refuse it, and every pass of every process would turn back at it.
 */
export function publishMountPointManifest(
  mountPoints: readonly string[],
  sources: readonly string[],
  commandKey?: string,
): MountPointManifest[] | 'too-large' {
  if (!onLinux() || (mountPoints.length === 0 && sources.length === 0)) {
    return []
  }
  type Named = { paths: string[]; sources: string[] }
  const writer = {
    version: MANIFEST_VERSION,
    ...ownProcess(),
    ns: ownPidNamespace(),
    boot: ownBootId(),
    created: Date.now(),
  }
  const textOf = (named: Named, keptYoung: boolean): string => {
    const body: z.infer<typeof ManifestSchema> = {
      ...writer,
      ...(keptYoung ? { keptYoung } : {}),
      ...named,
    }
    return JSON.stringify(body)
  }
  const all = {
    paths: [...new Set(mountPoints)],
    sources: [...new Set(sources)],
  }
  if (Buffer.byteLength(textOf(all, true)) > MANIFEST_MAX_BYTES) {
    return 'too-large'
  }
  const written = (
    dir: string | undefined,
    named: Named,
  ): MountPointManifest | undefined => {
    if (dir === undefined) {
      return undefined
    }
    const id = path.join(
      dir,
      `${process.pid}-${randomBytes(8).toString('hex')}`,
    )
    const file = `${id}${MANIFEST_SUFFIX}`
    const temporary = `${file}${TEMPORARY_SUFFIX}`
    const byItsAge = !isReachedByOneKernel(dir)
    try {
      if (byItsAge) {
        putWhereOtherKernelsRead(file, textOf(named, true))
      } else {
        // Written beside the manifest and renamed onto it, so that it is read
        // whole or not at all.
        fs.writeFileSync(temporary, textOf(named, false), { mode: 0o600 })
        fs.renameSync(temporary, file)
      }
      ownManifests.set(file, { commandKey, over: false, byItsAge })
      keepOwnManifestsYoung()
      return { dir, file, started: `${id}${STARTED_SUFFIX}` }
    } catch (e) {
      if (!byItsAge) drop(temporary)
      logForDebugging(
        `[Sandbox Linux] Could not record the mount points this command relies on in ${dir} (${String(e)})`,
        { level: 'warn' },
      )
      return undefined
    }
  }
  let inTheHome: string | undefined
  try {
    inTheHome = networkManifestDirectoryName()
  } catch {
    // The wrap has asked before this, and is refused by what asks after it.
  }
  const theirsToo =
    inTheHome === undefined
      ? { paths: [], sources: [] }
      : {
          paths: all.paths.filter(othersReach),
          sources: all.sources.filter(othersReach),
        }
  const inTheirSight =
    inTheHome !== undefined &&
    theirsToo.paths.length + theirsToo.sources.length > 0 &&
    makeOurPrivateDirectory(inTheHome)
      ? written(inTheHome, theirsToo)
      : undefined
  const here = written(ensureManifestDirectory(), all)
  if (here === undefined) {
    // Not what the other hosts' sight of it covers: that is for them.
    logForDebugging(
      "[Sandbox Linux] Mount points that could not be recorded on this host are kept in memory and removed at this process's own clean-up",
      { level: 'warn' },
    )
    for (const mountPoint of all.paths) unrecorded.paths.add(mountPoint)
    for (const source of all.sources) unrecorded.sources.add(source)
    for (const named of [...all.paths, ...all.sources]) {
      unrecorded.madeByAPlan.delete(named)
    }
  } else {
    // Not what an earlier wrap could record nowhere and this one names too:
    // that wrap's sandbox may outlast this manifest.
    for (const named of [...all.paths, ...all.sources]) {
      if (unrecorded.madeByAPlan.delete(named)) {
        unrecorded.paths.delete(named)
        unrecorded.sources.delete(named)
      }
    }
  }
  return [inTheirSight, here].filter(manifest => manifest !== undefined)
}

/**
 * Let go of the manifests of a wrap that produced no command: released, and
 * collected by a pass like any other. Not unlinked: a pass elsewhere may have
 * spared a path on its word and dropped the manifest that named the path till
 * then, and what nothing names any more stays on the host for good.
 */
export function discardMountPointManifests(files: readonly string[]): void {
  for (const file of files) {
    const own = ownManifests.get(file)
    if (own !== undefined) own.over = true
  }
  collectMountPoints('none')
}

function drop(file: string): boolean {
  try {
    fs.unlinkSync(file)
    return true
  } catch {
    // Gone already, or not a file.
    return false
  }
}

/** Every file in `dirs`. Throws where one of them cannot be listed. */
const filesIn = (dirs: readonly string[]): string[] =>
  dirs.flatMap(dir => fs.readdirSync(dir).map(name => path.join(dir, name)))

/** One reading of the manifest directories. */
type Reading = {
  /** Every file in them. */
  files: string[]
  /** The manifests that could be read, claimed ones among them. */
  manifests: Manifest[]
  /**
   * Why a sandbox may be running on paths that this reading cannot list, if one
   * may: nothing may then be removed on it.
   */
  inDoubt?: string
  /** All that doubt is, is that manifests kept moving while they were read. */
  keptChanging?: boolean
  /** What is there and is of no use to anybody any more. */
  spent: string[]
}

/**
 * Reads the manifests in `dirs`, every one that the listings showed. Doubt in
 * one directory is doubt.
 *
 * A pass renames a manifest to claim it, to give it back and to say that it is
 * finished, which can hide it from a listing under way, or show it twice, and
 * hide it from the open that follows one; and one published while the directory
 * is listed can be missed with its record shown. A record is never renamed. So
 * the reading starts over for a manifest that is listed at two names, for one
 * that is gone when opened, and for a record with no manifest listed beside it
 * whose manifest is there when asked for by name. One that is {@link remembered}
 * is not opened, and is where the listing showed it, as of the listing.
 *
 * A record with no manifest at any of its names puts the reading in doubt only
 * while a process on it runs (see {@link recordVouches}) and is spent otherwise,
 * one with no whole line past {@link MANIFEST_GRACE_MS} (its shell may be about
 * to write to it).
 *
 * Whatever is at a manifest's name and cannot be read puts the reading in doubt
 * too: always where that is an error of the moment (a sandboxed command can use
 * up what this user may open), and where it is what is there that cannot be
 * read as a manifest, while a process on its record runs or it is younger than
 * {@link UNREADABLE_MANIFEST_MAX_AGE_MS} ({@link MANIFEST_GRACE_MS} for a {@link
 * NotJson}).
 */
function readManifests(dirs: readonly string[]): Reading {
  const oneKernel = dirs.filter(isReachedByOneKernel)
  // Each directory is asked after once in a reading, whatever the answer.
  const reachedInto = new Map<string, boolean>()
  const reached = (p: string): boolean => {
    const dir = path.dirname(p)
    let answer = reachedInto.get(dir)
    if (answer === undefined) {
      answer = othersReachInto(dir)
      reachedInto.set(dir, answer)
    }
    return answer
  }
  // What cannot be asked after counts as there.
  const isThere = (file: string): boolean => {
    try {
      fs.lstatSync(file)
      return true
    } catch (e) {
      return !isAbsenceErrno(e)
    }
  }
  for (let attempt = 1; ; attempt++) {
    let files: string[]
    try {
      files = filesIn(dirs)
    } catch (e) {
      return { files: [], manifests: [], spent: [], inDoubt: String(e) }
    }
    const reading: Reading = { files, manifests: [], spent: [] }
    const listed = new Set<string>()
    let moved = false
    let twice = false
    for (const file of files) {
      if (!MANIFEST_SUFFIXES.some(suffix => file.endsWith(suffix))) {
        continue
      }
      // Listed at two of its names: renamed while the directory was listed.
      if (listed.has(idOf(file))) {
        twice = true
      }
      listed.add(idOf(file))
      try {
        const manifest = readManifest(
          file,
          !oneKernel.includes(path.dirname(file)),
          reached,
        )
        if (manifest === undefined) {
          moved = true
          continue
        }
        reading.manifests.push(manifest)
      } catch (e) {
        if (
          e instanceof NotOurs &&
          recordVouches(`${idOf(file)}${STARTED_SUFFIX}`, true) !== true &&
          olderThan(
            file,
            e instanceof NotJson
              ? MANIFEST_GRACE_MS
              : UNREADABLE_MANIFEST_MAX_AGE_MS,
          )
        ) {
          reading.spent.push(file)
        } else {
          const why = e instanceof Error ? e.message : String(e)
          reading.inDoubt ??= why.includes(file) ? why : `${file}: ${why}`
        }
      }
    }
    for (const id of remembered.keys()) {
      if (!listed.has(id)) remembered.delete(id)
    }
    for (const file of files) {
      if (file.endsWith(TEMPORARY_SUFFIX)) {
        // Left by a process killed between writing and moving into place.
        if (olderThan(file, UNREADABLE_MANIFEST_MAX_AGE_MS)) {
          reading.spent.push(file)
        }
      } else if (file.endsWith(PASS_SUFFIX)) {
        // Left by a process killed during its pass. One that is only overdue
        // may be under way yet, to those who can ask after it.
        const state = stateOfPass(file, oneKernel.includes(path.dirname(file)))
        if (
          state === 'over' ||
          (state === 'overdue' && olderThan(file, OTHER_NAMESPACE_MAX_AGE_MS))
        ) {
          reading.spent.push(file)
        }
      } else if (file.endsWith(STARTED_SUFFIX) && !listed.has(idOf(file))) {
        // Asked for in the order it goes through its names, and the record read
        // last. Only a claim given back can then pass between them unseen, and
        // a pass gives back only once it has found a process on the record,
        // which the read below finds too.
        if (
          MANIFEST_SUFFIXES.some(suffix => isThere(`${idOf(file)}${suffix}`))
        ) {
          moved = true
          continue
        }
        const vouched = recordVouches(file, true)
        if (vouched === true) {
          reading.inDoubt ??= `${file} has no manifest, and a process on it may be running`
        } else if (vouched === false || olderThan(file, MANIFEST_GRACE_MS)) {
          reading.spent.push(file)
        }
      }
    }
    // One that is at two names for good (a copy, a restored snapshot) is read
    // at both in the end, and judged at each like any other.
    if ((moved || twice) && attempt < LISTING_ATTEMPTS) {
      continue
    }
    if (moved) {
      reading.keptChanging = reading.inDoubt === undefined
      reading.inDoubt ??= `${dirs.join(', ')} kept changing`
    }
    return reading
  }
}

/** What the manifests name, on one reading, and what that reading listed. */
export type NamedMountPoints = {
  paths: ReadonlySet<string>
  listed: ReadonlySet<string>
}

/**
 * The mount points that any manifest names, a finished or claimed one included
 * (what only those name is a leftover the next pass removes), and what this
 * process could record nowhere. Makes nothing on the host.
 *
 * `inDoubt`, which says what could not be read and why, where the reading is in
 * doubt: a path it does not name may then be a running sandbox's mount point
 * all the same, and a wrap that took it for the caller's own would not name it
 * and would lose it under its own sandbox. With `keptChanging`, only because
 * other processes are busy in a directory: the next reading may do.
 *
 * `earlier` is a reading this call may answer with. A manifest is never
 * rewritten, so it still holds when the directories list nothing it did not,
 * `own` (the manifests the caller has published since) apart.
 */
export function namedMountPoints(
  earlier?: NamedMountPoints,
  own: readonly string[] = [],
): NamedMountPoints | { inDoubt: string; keptChanging?: boolean } {
  try {
    const dirs = onLinux() ? believedManifestDirectories() : []
    if (
      earlier !== undefined &&
      // What a plan has made itself since then is named from that moment.
      [...unrecorded.paths].every(kept => earlier.paths.has(kept)) &&
      filesIn(dirs).every(
        file => earlier.listed.has(file) || own.includes(file),
      )
    ) {
      return earlier
    }
    const reading = readManifests(dirs)
    if (reading.inDoubt !== undefined) {
      return { inDoubt: reading.inDoubt, keptChanging: reading.keptChanging }
    }
    return {
      paths: new Set([
        ...unrecorded.paths,
        ...reading.manifests.flatMap(manifest => manifest.paths),
      ]),
      listed: new Set(reading.files),
    }
  } catch (e) {
    // A directory cannot be looked at, or listed.
    return { inDoubt: String(e) }
  }
}

/**
 * Whether `p` is still something a clean-up would remove on a manifest's word:
 * an empty file or an empty directory. One that cannot be looked at may be.
 */
function isEmptyMountPoint(p: string): boolean {
  try {
    const kind = shapeOf(p)
    return kind === 'directory'
      ? fs.readdirSync(p).length === 0
      : kind === 'file'
  } catch (e) {
    return !isAbsenceErrno(e)
  }
}

/**
 * The mount points a sandbox that may still be running relies on, as the
 * manifests say at the moment of the call. For a caller that removes paths of
 * its own accord after a command: removing one from under a running sandbox
 * lifts the deny there. README.md, "Removing a path yourself", has the contract.
 *
 * `undefined` when it cannot tell: the caller must then skip every removal of an
 * empty file or an empty directory. It does not throw. A snapshot, whose only
 * safe use is to SKIP a removal.
 *
 * A path is in the set only while a live manifest names it (or this process
 * could record it nowhere) AND what is there is still an empty placeholder of
 * the user's, or cannot be looked at: a stale or forged manifest never makes a
 * caller spare a file with content. Makes nothing on the host. Empty off Linux.
 */
export function liveMountPoints(): ReadonlySet<string> | undefined {
  const spared = new Set<string>()
  if (!onLinux()) {
    return spared
  }
  const named = new Set<string>()
  try {
    for (let attempt = 1; ; attempt++) {
      const reading = readManifests(believedManifestDirectories())
      if (reading.inDoubt !== undefined) {
        throw new Error(reading.inDoubt)
      }
      named.clear()
      for (const mountPoint of unrecorded.paths) named.add(mountPoint)
      try {
        for (const manifest of reading.manifests) {
          if (
            !(manifest.finished && !canBeAskedAfter(manifest)) &&
            isLive(manifest)
          ) {
            for (const mountPoint of manifest.paths) named.add(mountPoint)
          }
        }
        break
      } catch (e) {
        if (!(e instanceof Moved) || attempt === LISTING_ATTEMPTS) throw e
      }
    }
  } catch (e) {
    logForDebugging(
      `[Sandbox Linux] Which mount points are live cannot be told (${String(e)})`,
      { level: 'warn' },
    )
    return undefined
  }
  for (const mountPoint of named) {
    if (isEmptyMountPoint(mountPoint)) {
      spared.add(mountPoint)
    }
  }
  return spared
}

/** In the name of every pass of this copy of the library, to tell its own. */
const ownPassMark = randomBytes(8).toString('hex')

/** The records of the pass this copy of the library is making, while it is. */
let ownPassOnRecord: readonly string[] = []

/** The number in `pid:[4026531836]`, and the boot id without its hyphens. */
const inAPassName = {
  ns: (): string => /\d+/.exec(ownPidNamespace() ?? '')?.[0] ?? '',
  boot: (): string => (ownBootId() ?? '').replace(/-/g, ''),
}

/**
 * Puts a pass of this process on record in each of `dirs`, until {@link
 * takePassOffRecord}, and returns those it is on record in. None, with nothing
 * left there, where it could not be in one of this host's own: nothing may then
 * be removed on a manifest's word. All but the one in the home where that takes
 * no record (a home over its quota), which need only stop what other hosts reach
 * from being removed.
 *
 * The name says whose it is: the pid, its start time, its PID namespace and the
 * boot, each left empty where it cannot be read. In the name, so that a pass is
 * on record whole or not at all and a listing is all it takes to judge one.
 */
function putPassOnRecord(dirs: readonly string[]): string[] {
  const { pid, start } = ownProcess()
  const name = `${pid}-${start}-${inAPassName.ns()}-${inAPassName.boot()}-${ownPassMark}${randomBytes(4).toString('hex')}${PASS_SUFFIX}`
  ownPassOnRecord = dirs.map(dir => path.join(dir, name))
  const onRecordIn: string[] = []
  for (const dir of dirs) {
    const file = path.join(dir, name)
    try {
      if (isReachedByOneKernel(dir)) {
        fs.closeSync(fs.openSync(file, 'wx', 0o600))
      } else {
        putWhereOtherKernelsRead(file, '')
      }
      onRecordIn.push(dir)
    } catch (e) {
      const inTheHome = dir === network
      logForDebugging(
        `[Sandbox Linux] The clean-up of mount points could not be put on record in ${dir} (${String(e)}) - leaving what ${inTheHome ? 'other hosts reach' : 'the manifests name'} where it is`,
        { level: 'warn' },
      )
      if (!inTheHome) {
        takePassOffRecord()
        return []
      }
    }
  }
  return onRecordIn
}

/** One that stays behind is dropped by the next pass, of any process. */
function takePassOffRecord(): void {
  const files = ownPassOnRecord
  ownPassOnRecord = []
  files.forEach(drop)
}

/**
 * Whether the pass on record at `file` may still remove something.
 *
 * A process of this kernel and PID namespace is asked after, and only one that
 * is gone says `over`. One of an earlier boot is, where only this kernel reaches
 * the directory (`oneKernel`), and so is one of this copy of the library that
 * it is not making now: a pass does not give the thread back.
 *
 * Any other, and a name that is none of ours, goes by its age, and is `overdue`
 * past {@link PASS_MAX_AGE_MS}: not to be waited for from here, and not known to
 * be over either. Its record is left for those who can ask.
 */
function stateOfPass(
  file: string,
  oneKernel: boolean,
): 'under way' | 'over' | 'overdue' {
  const byItsAge = (): 'under way' | 'over' | 'overdue' => {
    try {
      // Either way: one stamped by a clock that is hours ahead would else hold
      // up every wrap for those hours.
      return Math.abs(Date.now() - fs.lstatSync(file).mtimeMs) > PASS_MAX_AGE_MS
        ? 'overdue'
        : 'under way'
    } catch (e) {
      return isAbsenceErrno(e) ? 'over' : 'under way'
    }
  }
  const [pid, start, ns, boot, mark] =
    /^(\d+)-(\d*)-(\d*)-([0-9a-f]*)-([0-9a-f]+)\.pass$/
      .exec(path.basename(file))
      ?.slice(1) ?? []
  if (pid === undefined || start === undefined || mark === undefined) {
    return byItsAge()
  }
  if (mark.startsWith(ownPassMark)) {
    return ownPassOnRecord.includes(file) ? 'under way' : 'over'
  }
  if (boot === '' || boot !== inAPassName.boot()) {
    if (!oneKernel) return byItsAge()
    if (boot !== '' && inAPassName.boot() !== '') return 'over'
  }
  if (ns === '' || ns !== inAPassName.ns()) {
    return byItsAge()
  }
  return isRunning(Number(pid), start) ? 'under way' : 'over'
}

/**
 * The passes on record that may be under way. Throws where the directories
 * cannot be told or listed.
 *
 * Without `ofOtherHosts`, for a wrap that names nothing they reach, not those in
 * the home: a pass of another host removes nothing else, and one of this host
 * that may is on record in a place of this host's as well.
 */
export function passesUnderWay(ofOtherHosts = true): string[] {
  if (!onLinux()) {
    return []
  }
  const dirs = believedManifestDirectories().filter(
    dir => ofOtherHosts || dir !== network,
  )
  const oneKernel = dirs.filter(isReachedByOneKernel)
  return filesIn(dirs).filter(
    file =>
      file.endsWith(PASS_SUFFIX) &&
      stateOfPass(file, oneKernel.includes(path.dirname(file))) === 'under way',
  )
}

/**
 * Resolves once none of `passes` is under way any more, with `undefined`, or
 * with one that still is after `waitMs`: its process is held up (stopped, or
 * starved), and what it set out to remove may go at any moment after.
 *
 * For a wrap that has published its manifest, with what {@link passesUnderWay}
 * listed after that. Every pass that did not read the manifest is among them
 * (see {@link collect}); one that goes on record later has read it, and is not
 * waited for. Rejects like {@link passesUnderWay}, and with `signal`'s reason
 * once that is aborted.
 */
export async function passesToEnd(
  passes: readonly string[],
  signal?: AbortSignal,
  waitMs = WAITS_FOR_PASSES_MS,
  ofOtherHosts = true,
): Promise<string | undefined> {
  const deadline = performance.now() + waitMs
  let left = passes
  // Each look at the home is some round trips, from every host that waits.
  const longest = (): number =>
    left.some(pass => path.dirname(pass) === network) ? 250 : 50
  for (let pause = 1; ; pause = Math.min(pause * 2, longest())) {
    if (left.length === 0 || performance.now() >= deadline) {
      return left[0]
    }
    await new Promise(resolve => setTimeout(resolve, pause))
    signal?.throwIfAborted()
    // By its own name, which no other has: a directory that has two may be
    // listed by the other one this time.
    const underWay = new Set(
      passesUnderWay(ofOtherHosts).map(pass => path.basename(pass)),
    )
    left = left.filter(pass => underWay.has(path.basename(pass)))
  }
}

/**
 * Whether the manifest this process published at `file` is still its to start a
 * command under: not once a clean-up has been told that its command is over.
 */
export function holdsMountPointManifest(file: string): boolean {
  return ownManifests.get(file)?.over === false
}

/**
 * Release the manifests of the wraps of this process that `release` says are
 * over, and remove every mount point no live manifest names, from any process,
 * at any time, any number of times. Returns the mount points removed. Does
 * nothing anywhere but on Linux.
 */
export function collectMountPoints(release: OwnManifestRelease): string[] {
  if (!onLinux()) {
    return []
  }
  // Recorded first and kept whatever becomes of this pass, so a later pass
  // knows these commands are over even when told to release nothing.
  for (const [file, own] of ownManifests) {
    own.over ||=
      release === 'all' ||
      (release !== 'none' &&
        ((release !== 'ended' && own.commandKey === release.commandKey) ||
          recordVouches(`${idOf(file)}${STARTED_SUFFIX}`) === false))
  }
  // Made first: with one of the first places to write in, what the environment
  // names is not believed.
  ensureManifestDirectory()
  let dirs: string[]
  try {
    // The one in the home, where it is there, is set right as a wrap sets it. A
    // `chmod -R g+rX ~` opens it up, and passed over for that, what the other
    // hosts keep in it would go unread while what they reach is removed.
    const inTheHome = networkManifestDirectoryName()
    if (
      inTheHome !== undefined &&
      isOurPrivateDirectory(inTheHome, {
        orThrow: true,
        toWrite: false,
        alone: false,
      })
    ) {
      makeOurPrivateDirectory(inTheHome)
    }
    dirs = believedManifestDirectories()
  } catch (e) {
    logForDebugging(
      `[Sandbox Linux] Where the mount point manifests are cannot be told - leaving every mount point where it is (${String(e)})`,
      { level: 'warn' },
    )
    return []
  }
  if (dirs.length > 0) {
    return collect(dirs, release === 'all')
  }
  const removed: string[] = []
  if (release === 'all') {
    for (const mountPoint of childrenFirst(unrecorded.paths)) {
      if (removeMountPoint(mountPoint) === 'removed') removed.push(mountPoint)
    }
    for (const source of unrecorded.sources) {
      if (removeMountSource(source) === 'removed') removed.push(source)
    }
    Object.values(unrecorded).forEach(named => named.clear())
  }
  return removed
}

/** A path sorts after the directories it is in: a directory goes empty. */
const childrenFirst = (paths: Iterable<string>): string[] =>
  [...paths].sort().reverse()

/**
 * One pass over the manifest directories. It takes no lock and waits for
 * nothing; any number may run at once, over the same claims.
 *
 * INVARIANT: a path is removed only when every manifest that names it, in any
 * directory, is claimed and has no process on its record, by a reading of every
 * directory made after the claims in every directory. A directory that cannot
 * be written from here cannot be claimed in, so all it names is kept.
 * bubblewrap binds the manifest before it makes a mount point, so a start under
 * a claimed manifest is refused, and a sandbox that got past the claim wrote
 * its record first: every reading after the claim finds it. A manifest at its
 * own name keeps what it names, live or not, since a start under it can succeed
 * at any moment. Acting on a reading made before the claims would remove a
 * mount point from under a sandbox that started in between.
 *
 * A pass gives back the claims it made itself, and only when that reading finds
 * a process on the record, which every reading after the claim finds too. So
 * what remains is a manifest published after the reading, whose sandbox would
 * reach its bind on a path a claimed manifest names too.
 *
 * INVARIANT: a pass drops a manifest whose processes it can ask after only at
 * the name `<id>.finished`, which such a pass gives a claim it finds no process
 * behind, before that reading; and a pass that cannot ask keeps nothing on the
 * word of a manifest at that name. A path that is kept is dropped from the
 * manifests of this pass and left to the one it is kept for. To a pass that
 * cannot ask (one in another PID namespace, or on another host) a claim is live
 * like any other, so without the name each of two such passes would leave the
 * path to the other's manifest. With it, whichever reads second finds the
 * other's finished, and of all the manifests that name a path the pass over the
 * last to be finished keeps it for none. What such a manifest names alone is
 * still for those to remove who can ask, or for anybody once it is old. A pass
 * that goes by the age of a manifest does not give it the name: whoever can ask
 * goes on asking.
 *
 * INVARIANT: the pass is on record in every directory it can write from before
 * that reading until after its last removal, and removes nothing where it could
 * not be put there (in the home, only a pass that may remove what other hosts
 * reach, and that alone stays where the home takes no record). A wrap lists the passes once it has published, and hands no
 * command out while one is under way (see {@link passesToEnd}). So the wrap of
 * a manifest that the reading missed finds the pass on record, and no sandbox
 * starts under that manifest until the pass is over, for however long the pass
 * is held up between its reading and a removal.
 *
 * INVARIANT: the directories, worked out afresh, are listed again before every
 * removal (in a pass of over {@link LISTS_BEFORE_EACH_REMOVAL_UP_TO}
 * candidates, whenever the listing is {@link LISTING_GOOD_FOR_MS} old; those
 * that other kernels reach, whenever it is {@link NETWORK_LISTING_GOOD_FOR_MS}
 * old), and what has come to its name keeps what it names. The record above does not make
 * this redundant. A wrap sees no record of a pass that could go on none, or only
 * in a directory the wrap does not list (one inside another sandbox, which reads
 * the shared places and cannot write them); and a pass is on no record in a
 * directory that was made after it worked out where to go. Where the wrap does
 * wait, it then finds what it planned on and need not plan again.
 *
 * A manifest is all that names its mount points, so its claim is dropped last,
 * and stays, for a later pass, when the pass turns back, a removal is refused,
 * or a directory holds what another manifest names. Only content that no
 * manifest names makes a directory nobody's.
 */
function collect(dirs: readonly string[], unrecordedToo: boolean): string[] {
  const before = readManifests(dirs)
  before.spent.forEach(drop)
  const own = new Set<string>()
  let claims = false
  // Whether other hosts reach any of what this pass may come to remove.
  let othersReachSome =
    unrecordedToo &&
    network !== undefined &&
    [...unrecorded.paths, ...unrecorded.sources].some(othersReach)
  if (before.inDoubt === undefined) {
    // Forget own manifests that something else has removed.
    const there = new Set(before.files.map(idOf))
    for (const file of ownManifests.keys()) {
      if (dirs.includes(path.dirname(file)) && !there.has(idOf(file))) {
        ownManifests.delete(file)
      }
    }
    // Another pass is at one that has moved: it is that one's.
    const isLiveOrHasMoved = (manifest: Manifest): boolean => {
      try {
        return isLive(manifest)
      } catch (e) {
        if (e instanceof Moved) return true
        throw e
      }
    }
    for (const manifest of before.manifests) {
      if (isForAnotherHostToCollect(manifest)) continue
      const claim = manifest.claimed
        ? manifest.file
        : `${idOf(manifest.file)}${CLAIMED_SUFFIX}`
      if (!manifest.claimed) {
        if (isLiveOrHasMoved(manifest)) continue
        try {
          fs.renameSync(manifest.file, claim)
          own.add(claim)
        } catch {
          // Another pass has it, or the directory cannot be written.
          continue
        }
      }
      // Asked again, now that no sandbox can start under it.
      const over = !isLiveOrHasMoved({
        ...manifest,
        file: claim,
        claimed: true,
      })
      claims ||= over || own.has(claim)
      // What is in the home is collected on record there, whatever it names.
      othersReachSome ||=
        over &&
        network !== undefined &&
        (path.dirname(claim) === network ||
          [...manifest.paths, ...manifest.sources].some(othersReach))
      // Not of one that is only old: those who can ask go on asking.
      if (over && !manifest.finished && canBeAskedAfter(manifest)) {
        try {
          fs.renameSync(claim, `${idOf(claim)}${FINISHED_SUFFIX}`)
          own.delete(claim)
        } catch {
          // Another pass has said so, or has dropped it.
        }
      }
    }
  }
  // Nothing to remove, or nothing that may be: not worth a record, which every
  // wrap that is about to hand its command out would wait for.
  if (
    before.inDoubt !== undefined ||
    (!claims &&
      !(unrecordedToo && unrecorded.paths.size + unrecorded.sources.size > 0))
  ) {
    if (before.inDoubt !== undefined) {
      logForDebugging(
        `[Sandbox Linux] A sandbox may be running on mount points that cannot be listed - leaving every mount point where it is (${before.inDoubt})`,
        { level: 'warn' },
      )
    }
    return []
  }
  const writable = dirs.filter(dir => isOurPrivateDirectory(dir))
  // From before its record has its time: to whoever goes by the age of that,
  // what a server takes to put it at its name is time the pass has had.
  const since = bothClocks()
  try {
    // Off the record it removes nothing on a manifest's word. What is left to
    // remove is what this process could record nowhere, which no wrap elsewhere
    // knows for a mount point or waits for.
    //
    // Not on record in the home for what no other host reaches: every wrap on
    // every host that names what they do reach would wait for it.
    const onRecordIn = putPassOnRecord(
      writable.filter(dir => dir !== network || othersReachSome),
    )
    return removeWhatIsFinished(
      dirs,
      onRecordIn,
      own,
      unrecordedToo,
      since,
      // Where the home cannot be written from here at all (mounted read-only,
      // bound so by an outer sandbox) no pass of this host is ever seen there.
      // It goes by the manifests it reads, as it would with no home to read.
      network !== undefined &&
        writable.includes(network) &&
        !onRecordIn.includes(network),
    )
  } finally {
    takePassOffRecord()
  }
}

/**
 * The rest of {@link collect}, for as long as the pass is on record, which it
 * has been `since`: `own` are the claims it has made, `writable` the directories
 * it can claim in and is on record in. With `unseenByOtherHosts` it is not on
 * record where they look, though it could be, and nothing that they reach may
 * go.
 */
function removeWhatIsFinished(
  dirs: readonly string[],
  writable: readonly string[],
  own: ReadonlySet<string>,
  unrecordedToo: boolean,
  since: readonly [number, number],
  unseenByOtherHosts: boolean,
): string[] {
  const kept = new Set<string>()
  const keep = (
    manifest: Record<'paths' | 'sources', Iterable<string>>,
  ): void => {
    for (const named of [...manifest.paths, ...manifest.sources]) {
      kept.add(named)
    }
  }
  const finished: Manifest[] = []
  let reading: Reading
  for (let attempt = 1; ; attempt++) {
    reading = readManifests(dirs)
    if (reading.inDoubt !== undefined) {
      logForDebugging(
        `[Sandbox Linux] A sandbox may be running on mount points that cannot be listed - leaving every mount point where it is (${reading.inDoubt})`,
        { level: 'warn' },
      )
      return []
    }
    kept.clear()
    finished.length = 0
    // A wrap of this process is outstanding, and may be the one that relies on it.
    if (!unrecordedToo) keep(unrecorded)
    try {
      for (const manifest of reading.manifests) {
        if (isForAnotherHostToCollect(manifest)) {
          if (!manifest.finished && isLive(manifest)) keep(manifest)
          continue
        }
        const asked = canBeAskedAfter(manifest)
        if (
          manifest.claimed &&
          !isLive(manifest) &&
          // Else its last process has ended, or the renaming has failed, since
          // the claims: it is the next pass's, which says so before it reads.
          (manifest.finished || !asked) &&
          writable.includes(path.dirname(manifest.file))
        ) {
          finished.push(manifest)
          continue
        }
        // Not for this pass to remove, and nothing to keep anything for.
        if (manifest.finished && !asked) {
          continue
        }
        keep(manifest)
        if (own.has(manifest.file)) {
          try {
            fs.renameSync(
              manifest.file,
              `${idOf(manifest.file)}${MANIFEST_SUFFIX}`,
            )
          } catch {
            // Stays claimed, and kept while a process on its record runs.
          }
        }
      }
      break
    } catch (e) {
      if (!(e instanceof Moved)) throw e
      if (attempt === LISTING_ATTEMPTS) {
        logForDebugging(
          `[Sandbox Linux] The mount point manifests kept changing (${e.message}) - leaving every mount point where it is`,
          { level: 'warn' },
        )
        return []
      }
    }
  }

  // Each path once, and as a mount point where a manifest names it as one.
  const candidates = new Map<string, boolean>()
  for (const manifest of unrecordedToo ? [...finished, unrecorded] : finished) {
    for (const mountPoint of manifest.paths) {
      candidates.set(mountPoint, false)
    }
    for (const source of manifest.sources) {
      if (!candidates.has(source)) {
        candidates.set(source, true)
      }
    }
  }
  const known = new Set(reading.files)
  // This host's own directories as ever. Those that other kernels reach, where
  // a listing is a round trip, by a time of their own.
  const listed = [
    {
      oneKernel: true,
      at: -Infinity,
      goodFor:
        candidates.size <= LISTS_BEFORE_EACH_REMOVAL_UP_TO
          ? 0
          : LISTING_GOOD_FOR_MS,
    },
    { oneKernel: false, at: -Infinity, goodFor: NETWORK_LISTING_GOOD_FOR_MS },
  ]
  const newcomersKeepWhatTheyName = (): boolean => {
    const due = listed.filter(
      ({ at, goodFor }) => performance.now() - at >= goodFor,
    )
    if (due.length === 0) return true
    try {
      // The first place last: most is published there, so that listing is the
      // one to be a few microseconds old.
      const again = believedManifestDirectories()
        .reverse()
        .filter(dir =>
          due.some(({ oneKernel }) => oneKernel === isReachedByOneKernel(dir)),
        )
      for (const file of filesIn(again)) {
        if (known.has(file) || !file.endsWith(MANIFEST_SUFFIX)) continue
        // Published, or given back, since the reading. One that is gone again
        // is looked for the next time: it may be given back once more.
        const arrived = readManifest(
          file,
          !isReachedByOneKernel(path.dirname(file)),
        )
        if (arrived === undefined) continue
        keep(arrived)
        known.add(file)
      }
    } catch (e) {
      logForDebugging(
        `[Sandbox Linux] The mount point manifests could not be read again (${String(e)}) - leaving the rest where it is`,
        { level: 'warn' },
      )
      return false
    }
    for (const listing of due) listing.at = performance.now()
    return true
  }

  const removed: string[] = []
  const notRemoved = new Set<string>()
  const lookedAfreshAt = new Set<string>()
  for (const candidate of childrenFirst(candidates.keys())) {
    if (!newcomersKeepWhatTheyName()) {
      return removed
    }
    if (kept.has(candidate)) {
      continue
    }
    if (unseenByOtherHosts && othersReach(candidate)) {
      notRemoved.add(candidate)
      continue
    }
    // What is removed is looked at first, and removed by its name: another host
    // may have put a file of the user's there since this one last asked.
    if (!lookedAfreshAt.has(path.dirname(candidate))) {
      lookedAfreshAt.add(path.dirname(candidate))
      lookAfreshAt([candidate])
    }
    // Or have written into the very file (old bubblewrap makes it 0644), which
    // leaves the directory as it was.
    if (network !== undefined && othersReach(candidate)) {
      openAndClose(
        candidate,
        fs.constants.O_RDONLY |
          fs.constants.O_NOFOLLOW |
          fs.constants.O_NONBLOCK,
      )
    }
    // To a process that cannot ask after this one the pass is over by its age.
    // Asked last, after all that may have waited for a server.
    if (bothClocks().some((now, i) => now - since[i]! > PASS_GOOD_FOR_MS)) {
      logForDebugging(
        '[Sandbox Linux] The clean-up of mount points has taken too long - leaving the rest to the next',
        { level: 'warn' },
      )
      return removed
    }
    const outcome = candidates.get(candidate)
      ? removeMountSource(candidate)
      : removeMountPoint(candidate)
    if (outcome === 'removed') {
      removed.push(candidate)
    } else if (
      outcome === 'failed' ||
      (outcome === 'occupied' &&
        [...kept, ...notRemoved].some(p => p.startsWith(`${candidate}/`)))
    ) {
      notRemoved.add(candidate)
    }
  }
  if (unrecordedToo) {
    for (const named of Object.values(unrecorded)) {
      for (const one of named) if (!notRemoved.has(one)) named.delete(one)
    }
  }
  for (const manifest of finished) {
    // A mount point that could not be removed from here is still somebody's to
    // remove, and the manifest is all that says so. The record goes only with
    // the claim: a manifest given back since may have a sandbox on its record.
    if (
      ![...manifest.paths, ...manifest.sources].some(named =>
        notRemoved.has(named),
      ) &&
      drop(manifest.file)
    ) {
      drop(manifest.record)
      ownManifests.delete(`${idOf(manifest.file)}${MANIFEST_SUFFIX}`)
    }
  }
  return removed
}

/**
 * Look for the places that follow from the user id, for /etc/passwd and for
 * `getent` under `under` instead of `/`. Test seam, and nothing else may call it: no
 * environment keeps a test out of the ones the user's own processes keep.
 */
export function setMountPointManifestPlacesForTesting(under: string): void {
  root = under
  forgetMountPointManifestDirectory()
}

/**
 * Forget which directory the manifests are kept in, and which PID namespace
 * and boot this is, so the next use works them out again. Test seam: a test
 * gives itself a runtime directory of its own after this module may have
 * settled on the real one.
 */
export function forgetMountPointManifestDirectory(): void {
  pidNamespace = null
  bootId = undefined
  home = undefined
  noAnswer = undefined
  network = undefined
  foundWithinOthersReach.clear()
  remembered.clear()
  manifestDirectory = undefined
  manifestDirectoryIsPrivate = false
  manifestDirectoryUnavailable = false
  if (keptYoung !== undefined) {
    clearInterval(keptYoung)
    keptYoung = undefined
  }
  settingTimes = false
}
