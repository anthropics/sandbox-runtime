//! Cross-broker state DB for `srt-win acl` — refcount additive
//! sandbox-user ACEs (grant ALLOW / stamp DENY) so the LAST broker
//! to release a path can drop the ACE.
//!
//! TWO stores, split by scope and by writer:
//!
//! - SESSION store (`%LOCALAPPDATA%\sandbox-runtime\state.db`,
//!   per-user): brokers / ace_holders / working_aces, and the
//!   holderless `persistent_*` tables of `crate::persist`. These rows
//!   DRIVE ACL mutations on the owning user's files, so they are
//!   only trustworthy while only that user (and admins) can write
//!   them — the directory is stamped real-user-only on every open.
//! - MACHINE state (`HKLM\SOFTWARE\sandbox-runtime` — see
//!   `crate::reg` — plus the `ca\` key material under
//!   `%ProgramData%\sandbox-runtime`): install-owned, admin-written,
//!   read unprivileged. Not this module's concern beyond
//!   [`machine_store_dir`] and the recompose ambient fold-in.
//!
//! ## Disk-is-truth invariant
//!
//! A row is a refcount edge + `file_id` identity check. It NEVER
//! asserts on-disk state. Every add/drop/crash-recover routes
//! through [`recompose_at`], which reads the live `working_aces`
//! rows for the path and converges the on-disk ACEs for the
//! sandbox SID to exactly that set (walk-and-filter, no PROTECTED
//! rewrite, no SD snapshot). A poisoned row therefore degrades to
//! "sandbox user has an extra ACE the user can manually remove",
//! never to attacker-chosen permissions on the user's own files.
//!
//! ## Locking and crash safety
//!
//! Every `acl stamp|grant|restore|revoke|recover` runs under an
//! exclusive file lock on `.acl-init.lock` in the per-user session
//! dir (see `InitMutex::acquire` for why a file lock and not a
//! named mutex). The lock — NOT a DB transaction — serializes
//! whole operations across the user's brokers; the kernel drops it
//! when a holder dies, and crash-recovery runs unconditionally at
//! every acquire.
//!
//! There is deliberately NO single enclosing transaction. Each
//! path's (FS mutation + row change) commits independently so a
//! failure on path Y can't revert path X. The one ordering rule is
//! record-first: upsert, THEN `SetNamedSecurityInfoW`. A crash
//! between leaves a row whose ACE hasn't been written; the next
//! call re-derives and reapplies. A release commits its row changes
//! only after the converge succeeded, and a holder's deny rows are
//! never released while one of its grants may still be on disk.

use anyhow::{Context, Result, anyhow, bail};
use rusqlite::{Connection, OptionalExtension, params};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use windows::Win32::Foundation::{FILETIME, HANDLE, WAIT_OBJECT_0};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    WaitForSingleObject,
};

use crate::acl::{self, SbAce};
use crate::path_id::{self, FileId};

/// Holder PID — the LONG-LIVED process that owns a set of stamps
/// (the Node host in production), NOT the ephemeral `srt-win acl`
/// CLI process. Newtype to avoid confusing it with arbitrary PIDs
/// at call sites; the SQLite `brokers.pid` column stores the bare
/// `u32`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HolderPid(pub u32);

impl std::str::FromStr for HolderPid {
    type Err = std::num::ParseIntError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse::<u32>().map(HolderPid)
    }
}

/// Per-user session DB (brokers / ace_holders / working_aces).
const SESSION_SCHEMA_VERSION: i64 = 8;

const SESSION_SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS brokers (
  pid                 INTEGER PRIMARY KEY,
  process_create_time INTEGER NOT NULL,
  started_at          INTEGER NOT NULL
);
-- Additive explicit ACEs for the sandbox user. kind ∈
-- {'grant','deny','deny_fdc'}: `acl grant` writes ALLOW rows,
-- `acl stamp` writes DENY rows on the target plus a `deny_fdc`
-- row on the parent. Stores no original_sd — restore is a
-- walk-and-filter that drops the SID's ACEs, not a full-SD
-- restore. One row per (path, kind); a path may carry one grant
-- AND one deny (the recompose chokepoint applies both).
-- Refcounted via ace_holders.
CREATE TABLE IF NOT EXISTS working_aces (
  canonical_path TEXT NOT NULL,
  kind           TEXT NOT NULL,
  file_id        BLOB NOT NULL,
  -- The effective mask currently on disk: the MAX across live
  -- holders' want_mask (recomputed on every holder add/drop).
  mask           TEXT NOT NULL,
  PRIMARY KEY (canonical_path, kind)
);
CREATE TABLE IF NOT EXISTS ace_holders (
  canonical_path TEXT    NOT NULL,
  kind           TEXT    NOT NULL,
  pid            INTEGER NOT NULL REFERENCES brokers(pid) ON DELETE CASCADE,
  -- THIS holder's requested mask. The on-disk ACE is the MAX
  -- across live holders; release recomputes it so a holder that
  -- escalated the mask doesn't leave it escalated past its exit.
  want_mask      TEXT    NOT NULL,
  PRIMARY KEY (canonical_path, kind, pid)
);
CREATE INDEX IF NOT EXISTS ace_holders_by_pid ON ace_holders (pid);
-- Filesystem objects `acl stamp` created (empty file at a
-- non-existent deny target + any missing intermediate dirs) so a
-- Deny ACE could be stamped on the exact path. Placeholders are
-- PERMANENT once created (leave-in-place — never deleted by
-- restore/recover, so a user who wrote into one cannot lose data).
-- The record exists so a LATER holder denying the same or a
-- descendant path can discover and hold the full ancestor chain
-- (`Locked::placeholder_ancestors_of`) — otherwise releasing the
-- creating holder would strip intermediates the later holder
-- depends on.
CREATE TABLE IF NOT EXISTS placeholders (
  canonical_path TEXT PRIMARY KEY
);
-- Write roots whose grant is kept between sessions (`persist.rs`):
-- the root's capability SID, keyed by canonical path, valid for the
-- object with this file id. No holders: removed by `acl forget`.
CREATE TABLE IF NOT EXISTS persistent_roots (
  canonical_path TEXT PRIMARY KEY,
  file_id        BLOB NOT NULL,
  capability_sid TEXT NOT NULL
);
-- Sandbox-GROUP deny ACEs kept with a persistent root (same kinds
-- and masks as `working_aces`, never 'grant'). No holders: added and
-- widened by session starts, removed with `root` by `acl forget`.
CREATE TABLE IF NOT EXISTS persistent_denies (
  canonical_path TEXT NOT NULL,
  kind           TEXT NOT NULL,
  file_id        BLOB NOT NULL,
  mask           TEXT NOT NULL,
  root           TEXT NOT NULL,
  PRIMARY KEY (canonical_path, kind)
);
-- One row per path whose persistent ACEs were written: `spec` is the
-- ACE list the write was for, `done` is 0 from before the DACL write
-- until it returned. A session start skips the write only on a row
-- with `done = 1` for the same list and file id; crash recovery
-- replays a row left at 0.
CREATE TABLE IF NOT EXISTS persistent_writes (
  canonical_path TEXT PRIMARY KEY,
  file_id        BLOB NOT NULL,
  spec           TEXT NOT NULL,
  done           INTEGER NOT NULL
);
-- Paths the profile read grant (`profile.rs`) wrote on, and what each
-- carries: 'container', 'granted', 'file' or 'denied'. Valid for the
-- object with this file id (empty until the object was opened).
-- `created` is 1 for a directory the grant created empty. No holders:
-- removed by `profile forget`. Added without a schema version change:
-- the table is created by the first read-write open.
CREATE TABLE IF NOT EXISTS profile_paths (
  canonical_path TEXT PRIMARY KEY,
  file_id        BLOB NOT NULL,
  kind           TEXT NOT NULL,
  created        INTEGER NOT NULL
);
"#;

/// Outcome of a crash-recovery pass.
#[derive(Debug, Default)]
pub struct RecoveryReport {
    pub dead_brokers: u32,
    /// Orphaned `working_aces` rows whose ACE was revoked.
    pub aces_revoked: u32,
    /// Grant paths of dead holders (or holderless rows) that could
    /// not be released this pass. Their rows — and the same holder's
    /// deny rows — are kept for the next recovery.
    pub grants_pending: Vec<String>,
    /// Grant paths whose record `acl recover --force` dropped without
    /// locating the object; the ACE may still be on disk.
    pub grants_dropped: Vec<String>,
}

/// RAII guard for the init lock — an exclusive `LockFileEx` range
/// lock on `.acl-init.lock` inside the per-user session dir.
///
/// A FILE lock, not a named mutex, on purpose: the sandbox child
/// shares the broker's Terminal-Services session, and Windows named
/// objects are first-come — a child could CREATE the well-known
/// name before the broker and sit on it (create-first squatting
/// bypasses any DACL we would put on our own object; confirmed
/// empirically — a sandboxed `New-Object Threading.Mutex` held the
/// old `Local\` name and stalled the owner's acl ops for the full
/// timeout). The lock file lives in the session dir, whose DACL
/// excludes the sandbox child, so there is nothing for it to squat;
/// and the kernel releases file locks when the holder dies, which
/// also retires the abandoned-mutex special case (crash recovery
/// runs at every acquire regardless).
struct InitMutex {
    file: std::fs::File,
}
impl Drop for InitMutex {
    fn drop(&mut self) {
        use std::os::windows::fs::FileExt;
        use std::os::windows::io::AsRawHandle;
        use windows::Win32::Storage::FileSystem::UnlockFile;
        let file = &self.file;
        // The word goes before the lock does: a waiter never reads
        // "a profile operation" of a holder that has let go.
        if MARKED.swap(false, std::sync::atomic::Ordering::SeqCst) {
            let _ = file.seek_write(&[b'\n'; LOCK_WORD_LEN], LOCK_WORD_AT);
        }
        unsafe {
            let _ = UnlockFile(HANDLE(file.as_raw_handle()), 0, 0, 1, 0);
        }
    }
}

/// This process wrote the profile-operation word and clears it when
/// its outermost guard goes.
static MARKED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Where in the lock file the holder says it is a profile operation,
/// and how long that word is: `profile <pid>`, padded with newlines.
const LOCK_WORD_AT: u64 = 8;
const LOCK_WORD_LEN: usize = 24;

fn lock_file_path() -> Result<PathBuf> {
    Ok(session_store_dir()?.join(".acl-init.lock"))
}

/// Say that the lock this process holds is held for a profile
/// operation that is GOING AHEAD — called after the quiet check, so a
/// command that takes the lock only to refuse never says so.
pub fn mark_profile_operation() -> Result<()> {
    use std::os::windows::fs::FileExt;
    let mut word = [b'\n'; LOCK_WORD_LEN];
    let text = format!("profile {}", std::process::id());
    word[..text.len()].copy_from_slice(text.as_bytes());
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(lock_file_path()?)
        .context("open the init lock to mark it")?;
    file.seek_write(&word, LOCK_WORD_AT)
        .context("mark the init lock")?;
    MARKED.store(true, std::sync::atomic::Ordering::SeqCst);
    Ok(())
}

/// Whether the lock file's word names a profile operation of a process
/// that is still running. No word, another shape or a dead pid is not one.
fn word_says_profile_operation(file: &std::fs::File) -> bool {
    use std::os::windows::fs::FileExt;
    let mut word = [0u8; LOCK_WORD_LEN];
    if !file
        .seek_read(&mut word, LOCK_WORD_AT)
        .is_ok_and(|n| n == LOCK_WORD_LEN)
    {
        return false;
    }
    profile_word_pid(&word).is_some_and(pid_is_running)
}

/// The pid in a profile-operation word; `None` for anything else.
fn profile_word_pid(word: &[u8]) -> Option<u32> {
    std::str::from_utf8(word)
        .ok()?
        .trim_end_matches('\n')
        .strip_prefix("profile ")?
        .parse()
        .ok()
}

fn pid_is_running(pid: u32) -> bool {
    pid == std::process::id() || process_create_times().is_ok_and(|all| all.contains_key(&pid))
}

/// Whether a profile operation is running right now: the init lock is
/// held, and held for one.
pub fn profile_operation_running() -> bool {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Storage::FileSystem::{
        LOCK_FILE_FLAGS, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY, LockFileEx, UnlockFile,
    };
    use windows::Win32::System::IO::OVERLAPPED;
    let Ok(file) = lock_file_path().and_then(|p| {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(p)
            .map_err(Into::into)
    }) else {
        return false;
    };
    let mut ov = OVERLAPPED::default();
    let free = unsafe {
        LockFileEx(
            HANDLE(file.as_raw_handle()),
            LOCK_FILE_FLAGS(LOCKFILE_EXCLUSIVE_LOCK.0 | LOCKFILE_FAIL_IMMEDIATELY.0),
            None,
            1,
            0,
            &mut ov,
        )
    }
    .is_ok();
    if free {
        unsafe {
            let _ = UnlockFile(HANDLE(file.as_raw_handle()), 0, 0, 1, 0);
        }
        return false;
    }
    word_says_profile_operation(&file)
}

/// The init lock is held for a profile grant or forget, which takes
/// long: the caller was not made to wait it out. Exit code
/// [`EXIT_PROFILE_BUSY`] at the top level.
#[derive(Debug)]
pub struct ProfileBusy;

impl std::fmt::Display for ProfileBusy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            "the read grant on the user profile is being written or removed \
             (`srt-win profile grant` / `profile forget`); nothing can start until it is done",
        )
    }
}

impl std::error::Error for ProfileBusy {}

/// Exit code of any command that needed the init lock while a profile
/// grant or forget held it.
pub const EXIT_PROFILE_BUSY: i32 = 25;

/// How long a caller waits for the init lock before it asks whether the
/// holder is a profile operation: longer than any session operation takes.
const PROFILE_BUSY_AFTER_MS: u64 = 3_000;

impl InitMutex {
    fn acquire() -> Result<Self> {
        // Bounded: recovery under this lock is sub-second, so a minute
        // means a wedged holder.
        Self::acquire_within(PROFILE_BUSY_AFTER_MS, 60_000)
    }

    fn acquire_within(ask_after_ms: u64, timeout_ms: u64) -> Result<Self> {
        use std::os::windows::fs::FileExt;
        use std::os::windows::io::AsRawHandle;
        use windows::Win32::Storage::FileSystem::{
            LOCK_FILE_FLAGS, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY, LockFileEx,
        };
        use windows::Win32::System::IO::OVERLAPPED;
        let dir = session_store_dir()?;
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("create_dir_all {}", dir.display()))?;
        let path = lock_file_path()?;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            // Never truncate: byte 0 carries the kernel byte-range lock, the
            // bytes at `LOCK_WORD_AT` the holder's word.
            .truncate(false)
            .open(&path)
            .with_context(|| format!("open init-lock file {}", path.display()))?;
        const POLL_MS: u64 = 100;
        let started = std::time::Instant::now();
        let waited = || started.elapsed().as_millis() as u64;
        loop {
            let mut ov = OVERLAPPED::default();
            let r = unsafe {
                LockFileEx(
                    HANDLE(file.as_raw_handle()),
                    LOCK_FILE_FLAGS(LOCKFILE_EXCLUSIVE_LOCK.0 | LOCKFILE_FAIL_IMMEDIATELY.0),
                    None,
                    1,
                    0,
                    &mut ov,
                )
            };
            if r.is_ok() {
                // Clear what a holder that was killed left behind.
                file.seek_write(&[b'\n'; LOCK_WORD_LEN], LOCK_WORD_AT)
                    .context("clear the init lock's word")?;
                return Ok(Self { file });
            }
            // Held. After the short wait: if it is held for the walk
            // of a profile, say so now.
            if waited() >= ask_after_ms && word_says_profile_operation(&file) {
                return Err(anyhow::Error::new(ProfileBusy));
            }
            if waited() >= timeout_ms {
                bail!(
                    "init lock {} not acquired within {timeout_ms}ms — \
                     another srt-win/broker is holding it (wedged?)",
                    path.display(),
                );
            }
            std::thread::sleep(std::time::Duration::from_millis(POLL_MS));
        }
    }
}

/// The one seam through which install-time flows (ambient deny
/// stamping/clearing) serialize against this user's brokers —
/// acquire the session init lock without opening the session DB.
pub fn acquire_session_lock() -> Result<impl Drop> {
    InitMutex::acquire()
}

use crate::profile::is_access_denied;

/// Every holder row whose process is alive, except those of `except`.
/// Fails if the process list cannot be read. Call under the init lock,
/// after crash recovery.
pub fn live_holders(db: &Locked, except: Option<u32>) -> Result<Vec<KeptHolder>> {
    live_holders_with(db.conn(), except, alive_by_one_snapshot()?)
}

fn live_holders_with(
    conn: &Connection,
    except: Option<u32>,
    alive: impl Fn(u32, i64) -> bool,
) -> Result<Vec<KeptHolder>> {
    let rows: Vec<(i64, i64, String, String)> = query_vec(
        conn,
        "SELECT h.pid, b.process_create_time, h.kind, h.canonical_path \
         FROM ace_holders h JOIN brokers b ON b.pid = h.pid \
         ORDER BY h.pid, h.kind, h.canonical_path",
        [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
    )?;
    Ok(rows
        .into_iter()
        .filter(|&(pid, ct, _, _)| Some(pid as u32) != except && alive(pid as u32, ct))
        .map(|(pid, _, kind, path)| KeptHolder {
            pid: pid as u32,
            kind,
            path,
        })
        .collect())
}

/// A waitable handle on the live process `pid` if it is recorded as a
/// session; `None` if it is not recorded or gone (the command then holds
/// for itself); an error if it is recorded, alive and cannot be watched.
pub fn watch_session(pid: u32) -> Result<Option<crate::util::OwnedHandle>> {
    let Ok(Some(conn)) = open_db_ro() else {
        return Ok(None);
    };
    let recorded = conn
        .query_row(
            "SELECT b.process_create_time FROM ace_holders h JOIN brokers b ON b.pid = h.pid \
             WHERE h.pid = ?1 AND h.kind = ?2",
            params![pid as i64, KIND_KEPT_PROFILE],
            |r| r.get::<_, i64>(0),
        )
        .optional()
        .ok()
        .flatten();
    let Some(recorded) = recorded else {
        return Ok(None);
    };
    if !(DISK.alive)(pid, recorded) {
        return Ok(None);
    }
    let opened = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION
                | windows::Win32::System::Threading::PROCESS_SYNCHRONIZE,
            false,
            pid,
        )
    };
    let h = match opened {
        Ok(h) if !h.is_invalid() => crate::util::OwnedHandle(h),
        // Gone between the look and the open.
        _ if !(DISK.alive)(pid, recorded) => return Ok(None),
        Ok(_) => bail!("the session this command belongs to (process {pid}) cannot be watched"),
        Err(e) => {
            return Err(e).with_context(|| {
                format!("the session this command belongs to (process {pid}) cannot be watched")
            });
        }
    };
    // The handle is the holder's, not that of a process that has its
    // pid since: by the creation time read THROUGH it.
    let created = process_create_time(h.raw())
        .with_context(|| format!("the session's process {pid} cannot be identified"))?;
    if created != recorded || unsafe { WaitForSingleObject(h.raw(), 0) } == WAIT_OBJECT_0 {
        return Ok(None);
    }
    Ok(Some(h))
}

/// Open (creating if needed) the per-user SESSION DB. Stamps the
/// parent directory real-user-only on EVERY open — the session
/// store is the pre-split `%LOCALAPPDATA%` model: rows here are
/// TRUSTED because only the owning user (and admins) can write
/// them, which is exactly why session bookkeeping must not live in
/// the Users-writable machine store.
pub fn open_db() -> Result<Connection> {
    let dir = session_store_dir()?;
    std::fs::create_dir_all(&dir).with_context(|| format!("create_dir_all {}", dir.display()))?;
    // Stamp the directory `(OI)(CI)` real-user-only so the sandbox
    // child cannot tamper with state.db / -wal / -shm. Done on
    // EVERY open, not just first creation: defense-in-depth — the
    // child runs as a different user, but a working-tree grant
    // could otherwise expose this directory if it lives under a
    // granted root. `SetNamedSecurityInfoW` is
    // idempotent, so re-stamping an already-correct dir is a no-op.
    // Best-effort: if it fails we proceed (the `%LOCALAPPDATA%`
    // default DACL already excludes the separate `srt-sandbox`
    // user; the explicit stamp + sandbox-users DENY below is
    // belt-and-braces against a working-tree ALLOW grant covering
    // this directory) and warn so the test harness can assert. We
    // own this directory, so a user-applied custom DACL on it is
    // NOT preserved — it is rewritten on every open by design.
    let dir_str = dir.to_str().ok_or_else(|| {
        anyhow!(
            "state-DB directory path '{}' is not representable as \
             UTF-8 (contains unpaired surrogates); not supported",
            dir.display()
        )
    })?;
    // Include the sandbox-users DENY when the install has
    // provisioned that group. The credential file in this
    // directory is machine-scope DPAPI — readable-by-sandbox =
    // decryptable-by-sandbox — so the DENY is load-bearing once
    // the separate-user runner exists. The lookup distinguishes
    // "group genuinely absent" (install never run / older install
    // → DENY skipped, broker-only allow set still excludes the
    // sandbox user) from a transient SAM/LSA failure — the latter
    // is surfaced rather than silently dropping a security ACE.
    let deny_sid = match crate::sid::lookup_account_sid(crate::user::SANDBOX_GROUP) {
        Ok(s) => Some(s),
        Err(e) => {
            match crate::sid::sid_account_exists("S-1-5-32-545") {
                // BUILTIN\Users always maps; if it does, SAM is up
                // and the sandbox group is genuinely absent.
                Ok(crate::sid::SidExistence::Mapped) => None,
                _ => {
                    eprintln!(
                        "srt-win: WARNING: cannot resolve \
                         '{}' to add the state-dir DENY ACE \
                         ({e:#}); the broker-only allow set \
                         still excludes the sandbox user, but \
                         the explicit DENY is omitted for this \
                         stamp",
                        crate::user::SANDBOX_GROUP,
                    );
                    None
                }
            }
        }
    };
    if let Err(e) = acl::stamp_dir_inheriting(dir_str, deny_sid.as_deref()) {
        eprintln!(
            "srt-win: WARNING: failed to stamp state-DB dir {} \
             broker-only: {e:#}",
            dir.display()
        );
    }
    open_db_at(
        &dir.join("state.db"),
        SESSION_SCHEMA_SQL,
        SESSION_SCHEMA_VERSION,
    )
}

/// Filter on `release_aces` for the deny-ACE lifecycle.
pub const KIND_DENY: &[&str] = &["deny", "deny_fdc", "deny_delete", KIND_DENY_SATISFIED];
/// A read deny that could not be written (access denied) on an object
/// whose own access list gave the sandbox account no read at the time.
/// No ACE and no `working_aces` row stand behind the row.
pub const KIND_DENY_SATISFIED: &str = "deny_satisfied";
/// Filter on `release_aces` for the grant lifecycle.
pub const KIND_GRANT: &[&str] = &["grant"];
/// Holder rows with no ACE behind them: a session is running on a kept
/// write root (`kept_root`) or exists at all (`profile`). They go when the
/// session releases, or when crash recovery finds the holder dead.
pub const KIND_KEPT_ROOT: &str = "kept_root";
pub const KIND_KEPT_PROFILE: &str = "profile";
/// What a `profile` hold names. It is one resource — the calling
/// user's profile read grant, whether or not one is recorded at the
/// moment — and not a path.
pub const KEPT_PROFILE_PATH: &str = "(profile)";

/// A live session, other than the caller's, running on a kept grant.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct KeptHolder {
    pub pid: u32,
    /// [`KIND_KEPT_ROOT`] or [`KIND_KEPT_PROFILE`].
    pub kind: String,
    pub path: String,
}

/// The kept-grant holds of every holder but `except` whose process is
/// alive ([`Disk::alive`]: same PID, same creation time).
fn kept_holders_with(
    conn: &Connection,
    except: i64,
    alive: impl Fn(u32, i64) -> bool,
) -> Result<Vec<KeptHolder>> {
    let rows: Vec<(i64, i64, String, String)> = query_vec(
        conn,
        "SELECT h.pid, b.process_create_time, h.kind, h.canonical_path \
         FROM ace_holders h JOIN brokers b ON b.pid = h.pid \
         WHERE h.kind IN ('kept_root', 'profile') AND h.pid != ?1 \
         ORDER BY h.pid, h.kind, h.canonical_path",
        params![except],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
    )?;
    Ok(rows
        .into_iter()
        .filter(|&(pid, ct, _, _)| alive(pid as u32, ct))
        .map(|(pid, _, kind, path)| KeptHolder {
            pid: pid as u32,
            kind,
            path,
        })
        .collect())
}

/// `prepare → query_map → collect` with one error context. Shared
/// by every "list of T from one query" site so error plumbing is
/// edited once.
fn query_vec<T, P: rusqlite::Params>(
    conn: &Connection,
    sql: &str,
    p: P,
    row: impl FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
) -> Result<Vec<T>> {
    let mut s = conn
        .prepare(sql)
        .with_context(|| format!("prepare: {sql}"))?;
    let it = s
        .query_map(p, row)
        .with_context(|| format!("query: {sql}"))?;
    let mut v = Vec::new();
    for r in it {
        v.push(r.with_context(|| format!("row: {sql}"))?);
    }
    Ok(v)
}

/// Read-only open of the per-user SESSION DB. Returns `None` if it
/// doesn't exist yet. No mutex, no `create_dir_all`, no dir-stamp,
/// no schema apply.
pub fn open_db_ro() -> Result<Option<Connection>> {
    open_ro_at(&session_store_dir()?.join("state.db"))
}

fn open_ro_at(path: &std::path::Path) -> Result<Option<Connection>> {
    let schema_version = SESSION_SCHEMA_VERSION;
    let path = path.to_path_buf();
    // Degrade, don't fail: a garbage/unreadable session DB must read
    // as "nothing recorded" — an Err here would propagate through
    // crash_recovery into every acl op for this user. The RW open
    // path renames a corrupt file away and recreates it.
    match path.try_exists() {
        Ok(false) => return Ok(None),
        Ok(true) => {}
        Err(e) => bail!(
            "cannot determine state-DB presence at {}: {e}",
            path.display()
        ),
    }
    let conn = Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .with_context(|| format!("sqlite open RO {}", path.display()))?;
    conn.pragma_update(None, "busy_timeout", 5000)?;
    // Schema-mismatch chokepoint: a v≠SCHEMA_VERSION DB is from an
    // older install whose `sandbox_user` row is stranded. Reading
    // it would surface a stale credential. Return None so
    // `srt-win user status` reports `provisioned=false` and the TS
    // dependency-check tells the user to re-run `srt-win install`
    // (which routes through `open_db_at()` → renames the stale DB
    // to `.bak` and creates fresh) at the start of the session,
    // not mid-exec. Also covers a DB
    // with no schema at all (`open_db_at` crashed between
    // `Connection::open` and `execute_batch(SCHEMA_SQL)`): ver==0
    // and there's no `sandbox_user` row, so "not provisioned yet"
    // is the right answer.
    let ver: i64 = match conn.query_row("PRAGMA user_version", [], |r| r.get(0)) {
        Ok(v) => v,
        Err(e) => {
            eprintln!(
                "srt-win: state DB at {} is unreadable ({e}); treating \
                 as not provisioned. Re-run `srt-win install` to \
                 recreate it.",
                path.display(),
            );
            return Ok(None);
        }
    };
    if ver != schema_version {
        if ver != 0 {
            eprintln!(
                "srt-win: state DB at {} is at schema v{ver} \
                 (expected v{schema_version}); treating as not \
                 provisioned. Re-run `srt-win install` to migrate.",
                path.display(),
            );
        }
        return Ok(None);
    }
    Ok(Some(conn))
}

/// Open at an arbitrary path with the given schema + version.
/// Tests use `:memory:`.
pub(crate) fn open_db_at(
    path: &std::path::Path,
    schema_sql: &str,
    schema_version: i64,
) -> Result<Connection> {
    // Schema mismatch → rename + recreate. No ALTER/DROP migration:
    // the old DB is preserved (debugging/recovery) at
    // state.db.v<old>.<ts>.bak alongside `path`, and a fresh DB is
    // created at the expected schema. The next recovery converges
    // from the fresh (empty) rows. A PRE-SPLIT per-user DB carried
    // the DPAPI cred blob in its `sandbox_user` row (machine-scope:
    // readable = decryptable), so the blob is scrubbed from the
    // .bak below before anything else can read it. The .bak keeps
    // its directory's DACL (real-user-only stamp); no per-file
    // stamp.
    if path.exists() {
        let probe = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY);
        if let Ok(c) = probe {
            // A garbage (non-SQLite) file fails the pragma — mark it
            // ver -1 so it takes the rename-away path below instead
            // of reaching the schema apply (which would hard-error
            // forever on a file any local user can plant).
            let ver: i64 = c
                .query_row("PRAGMA user_version", [], |r| r.get(0))
                .unwrap_or(-1);
            drop(c);
            if ver != 0 && ver != schema_version {
                let dir = path
                    .parent()
                    .ok_or_else(|| anyhow!("state DB path '{}' has no parent", path.display()))?;
                let stem = path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("state.db");
                let ts = unix_now();
                let bak = dir.join(format!("{stem}.v{ver}.{ts}.bak"));
                std::fs::rename(path, &bak).map_err(|e| {
                    // SQLite's win32 VFS opens with no
                    // FILE_SHARE_DELETE; another live broker holds
                    // the file → rename fails 32 here where DROP
                    // TABLE under WAL would have succeeded.
                    if e.raw_os_error() == Some(32) {
                        anyhow!(
                            "rename incompatible state DB {} → {}: {e} \
                             — the DB is open in another process \
                             (likely a running srt-win/broker); close \
                             it and retry",
                            path.display(),
                            bak.display()
                        )
                    } else {
                        anyhow::Error::new(e).context(format!(
                            "rename incompatible state DB {} → {}",
                            path.display(),
                            bak.display()
                        ))
                    }
                })?;
                // WAL sidecars too (best-effort — they hold no cred,
                // only journal pages of it).
                for ext in ["-wal", "-shm"] {
                    let p = dir.join(format!("{stem}{ext}"));
                    let to = dir.join(format!("{stem}.v{ver}.{ts}.bak{ext}"));
                    let _ = std::fs::rename(&p, &to);
                }
                // Best-effort cred scrub (pre-split schemas only —
                // absent table/column is fine).
                if let Ok(bc) = Connection::open(&bak) {
                    let _ = bc.execute("UPDATE sandbox_user SET cred = x''", []);
                }
                eprintln!(
                    "srt-win: state DB at schema v{ver} found, expected \
                     v{schema_version}; renamed to {} and created fresh. \
                     Re-run `srt-win install` (and `srt-win user \
                     trust-ca <pem>` if you use TLS termination) to \
                     re-provision. `srt-win acl recover` will sweep \
                     any sandbox-user DENY ACEs from a prior install; \
                     PROTECTED-stamp DACLs from the removed same-user \
                     mode require manual `icacls <path> /reset`.",
                    bak.display(),
                );
            }
        }
    }
    let conn = Connection::open(path).with_context(|| format!("sqlite open {}", path.display()))?;
    // WAL = concurrent readers + single writer + crash safety.
    // `synchronous=NORMAL` is the recommended companion for WAL and
    // is durable across power loss. busy_timeout is belt-and-braces
    // — the named mutex already serializes whole operations across
    // brokers, but a brief contention inside one process (tests)
    // shouldn't error.
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "busy_timeout", 5000)?;
    conn.execute_batch(schema_sql).context("apply schema")?;
    conn.pragma_update(None, "user_version", schema_version)?;
    Ok(conn)
}

/// A fresh in-memory session database, for tests of the modules that
/// keep their tables in it.
#[cfg(test)]
pub(crate) fn open_memory_db_for_tests() -> Connection {
    open_db_at(
        std::path::Path::new(":memory:"),
        SESSION_SCHEMA_SQL,
        SESSION_SCHEMA_VERSION,
    )
    .expect("in-memory session database")
}

/// The machine-wide store dir: `%ProgramData%\sandbox-runtime` —
/// since the move of credential/marker/identity/CA-record/ambient
/// state to `HKLM\SOFTWARE\sandbox-runtime` ([`crate::reg`]), this
/// hosts only the managed CA key material (`ca\`), which must stay
/// on the filesystem because the broker's unelevated
/// generate-if-absent self-heal rewrites it. Created (and ACL'd) by
/// the elevated install (`install::provision_machine_store`); a
/// pre-created directory is healed there by taking ownership and
/// rewriting the DACL.
pub fn machine_store_dir() -> Result<PathBuf> {
    state_dir_from_base(std::env::var_os("ProgramData"), "ProgramData")
}

/// The per-user SESSION dir: `%LOCALAPPDATA%\sandbox-runtime` —
/// ACL-bookkeeping state (`state.db`: brokers/holders/working
/// ACEs). Per-user by design: these rows DRIVE ACL mutations on the
/// owning user's files, so they must only be writable by that user
/// (and admins) — in a shared store any local user could seed rows
/// for another user's broker to apply. Stamped real-user-only on
/// every [`open_db`].
pub fn session_store_dir() -> Result<PathBuf> {
    state_dir_from_base(std::env::var_os("LOCALAPPDATA"), "LOCALAPPDATA")
}

/// Errors if `var` (`%ProgramData%`) is unset,
/// empty, or yields a non-absolute path — a relative state dir
/// would put the ACL-protected DB in the CWD and break cross-broker
/// refcounting/recovery.
fn state_dir_from_base(base: Option<std::ffi::OsString>, var: &str) -> Result<PathBuf> {
    let base = base
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("{var} not set or empty"))?;
    let dir = base.join("sandbox-runtime");
    if !dir.is_absolute() {
        bail!(
            "state-DB directory '{}' is not absolute \
             ({var}='{}'); refusing relative state path",
            dir.display(),
            base.display()
        );
    }
    Ok(dir)
}

/// Run `f` under the init mutex with the DB open. Crash recovery is
/// run first. `f` receives a `Locked` view whose mutating methods
/// each autocommit (single-statement) or use their own short
/// transaction — there is NO single enclosing transaction.
///
/// See module doc for the no-enclosing-tx and ordering rationale.
pub fn with_init_lock<R>(
    holder_pid: HolderPid,
    force_recover: bool,
    f: impl FnOnce(&mut Locked) -> Result<R>,
) -> Result<(R, RecoveryReport)> {
    let (_mutex, conn, report) = locked_recovered(force_recover)?;
    let mut locked = Locked { conn, holder_pid };
    let out = f(&mut locked)?;
    Ok((out, report))
}

/// [`with_init_lock`] WITHOUT crash recovery, for a command that only
/// records its own hold: starting a command must not release what a dead
/// holder left behind.
pub fn with_init_lock_unrecovered<R>(
    holder_pid: HolderPid,
    f: impl FnOnce(&mut Locked) -> Result<R>,
) -> Result<R> {
    let _mutex = InitMutex::acquire()?;
    let mut locked = Locked {
        conn: open_db()?,
        holder_pid,
    };
    f(&mut locked)
}

/// [`with_init_lock`] for a profile grant or forget, held for the whole
/// run. `f` must refuse if [`live_holders`] finds anyone, and otherwise
/// call [`mark_profile_operation`].
pub fn with_profile_lock<R>(f: impl FnOnce(&mut Locked) -> Result<R>) -> Result<R> {
    let (_mutex, conn, _report) = locked_recovered(false)?;
    let mut locked = Locked {
        conn,
        holder_pid: HolderPid(std::process::id()),
    };
    f(&mut locked)
}

/// The shared critical-section preamble of [`with_init_lock`] and
/// [`with_install_lock`]: acquire the init mutex, open the DB, run
/// crash recovery. Keep the mutex guard alive for the whole
/// critical section.
fn locked_recovered(force_recover: bool) -> Result<(InitMutex, Connection, RecoveryReport)> {
    let mutex = InitMutex::acquire()?;
    let conn = open_db()?;
    let report = crash_recovery(&conn, force_recover)?;
    Ok((mutex, conn, report))
}

/// View inside `with_init_lock`. Owns the `Connection`; each method
/// commits independently (rusqlite autocommits a lone `execute`).
///
/// `holder_pid` is the LONG-LIVED owner of the stamps — typically
/// the Node host (sandbox-runtime) process, NOT this ephemeral
/// `srt-win acl` process. The CLI exits immediately; keying holders
/// on its PID would let the next acl op's crash-recovery reap it and
/// tear the stamp down. Keying on the caller-supplied holder PID
/// means a stamp persists until that process exits (or explicitly
/// restores), and refcount / crash-recovery track the real session.
pub struct Locked {
    conn: Connection,
    holder_pid: HolderPid,
}

impl Locked {
    /// The session DB connection, for `persist.rs`'s own tables.
    pub(crate) fn conn(&self) -> &Connection {
        &self.conn
    }

    /// Record `self.holder_pid` in `brokers`. The row's
    /// `process_create_time` is the HOLDER's, so crash-recovery
    /// checks whether the holder — not this short-lived CLI — is
    /// still alive.
    ///
    /// UPSERT, not `INSERT OR REPLACE`: with `foreign_keys=ON` and
    /// `ace_holders.pid REFERENCES brokers ON DELETE CASCADE`,
    /// REPLACE is a DELETE (cascading away every `ace_holders` row
    /// for this pid) plus a fresh INSERT — so a holder's *second*
    /// `acl stamp`/`grant` would silently drop its first batch's
    /// holds, and the next crash-recovery would strip those ACEs
    /// while the holder's child is still running. `ON CONFLICT DO
    /// UPDATE` updates in place and leaves child rows intact.
    pub fn register_broker(&self) -> Result<()> {
        let ct = pid_create_time(self.holder_pid.0)
            .with_context(|| format!("read create-time of holder pid {}", self.holder_pid.0))?;
        self.register_broker_at(ct)
    }

    /// [`Self::register_broker`] for a holder created at `ct`. A row
    /// for this pid with another creation time is a dead process whose
    /// pid was reused: its holds are set aside, not adopted.
    fn register_broker_at(&self, ct: i64) -> Result<()> {
        let pid = self.holder_pid.0 as i64;
        let tx = self
            .conn
            .unchecked_transaction()
            .context("begin register tx")?;
        let prior: Option<(i64, i64)> = tx
            .query_row(
                "SELECT process_create_time, started_at FROM brokers WHERE pid = ?1",
                params![pid],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if let Some((old_ct, old_started)) = prior.filter(|&(c, _)| c != ct) {
            // Negative pids name no process; recovery treats them as dead.
            let lowest: Option<i64> =
                tx.query_row("SELECT MIN(pid) FROM brokers", [], |r| r.get(0))?;
            let aside = lowest.unwrap_or(0).min(0) - 1;
            tx.execute(
                "INSERT INTO brokers (pid, process_create_time, started_at) \
                 VALUES (?1, ?2, ?3)",
                params![aside, old_ct, old_started],
            )
            .context("INSERT brokers (set aside)")?;
            tx.execute(
                "UPDATE ace_holders SET pid = ?1 WHERE pid = ?2",
                params![aside, pid],
            )
            .context("UPDATE ace_holders (set aside)")?;
            eprintln!(
                "srt-win: pid {pid} was reused; the holds of the earlier \
                 process are kept apart for recovery"
            );
        }
        tx.execute(
            "INSERT INTO brokers (pid, process_create_time, started_at) \
             VALUES (?1, ?2, ?3) \
             ON CONFLICT(pid) DO UPDATE SET \
               process_create_time = excluded.process_create_time, \
               started_at          = excluded.started_at",
            params![pid, ct, unix_now()],
        )
        .context("INSERT brokers")?;
        tx.commit().context("commit register")?;
        Ok(())
    }

    /// Record that the holder's session runs on these kept grants:
    /// each kept write root, and the profile read grant if `profile`
    /// names the profile it is recorded for. Idempotent.
    pub fn hold_kept(&self, roots: &[String], profile: Option<&str>) -> Result<()> {
        if roots.is_empty() && profile.is_none() {
            return Ok(());
        }
        self.register_broker()?;
        let pid = self.holder_pid.0 as i64;
        let mut insert = self.conn.prepare_cached(
            "INSERT OR IGNORE INTO ace_holders (canonical_path, kind, pid, want_mask) \
             VALUES (?1, ?2, ?3, '')",
        )?;
        for root in roots {
            insert
                .execute(params![root, KIND_KEPT_ROOT, pid])
                .context("INSERT kept-root hold")?;
        }
        if let Some(profile) = profile {
            insert
                .execute(params![profile, KIND_KEPT_PROFILE, pid])
                .context("INSERT profile hold")?;
        }
        Ok(())
    }

    /// Record a read deny of the holder that the object's own access
    /// list stands in for ([`KIND_DENY_SATISFIED`]).
    fn note_satisfied_deny(&self, canon: &str) -> Result<()> {
        delete_holder(&self.conn, Some(self.holder_pid.0 as i64), canon, "deny")?;
        self.conn
            .execute(
                "DELETE FROM working_aces WHERE canonical_path = ?1 AND kind = ?2 \
                 AND NOT EXISTS (SELECT 1 FROM ace_holders \
                                 WHERE canonical_path = ?1 AND kind = ?2)",
                params![canon, "deny"],
            )
            .context("DELETE unwritten deny")?;
        self.conn
            .execute(
                "INSERT OR IGNORE INTO ace_holders (canonical_path, kind, pid, want_mask) \
                 VALUES (?1, ?2, ?3, 'denyRead')",
                params![canon, KIND_DENY_SATISFIED, self.holder_pid.0 as i64],
            )
            .context("INSERT satisfied deny")?;
        Ok(())
    }

    /// Drop the holder's kept-grant holds (its session, or its one
    /// command, is ending). The broker row goes with the last hold of
    /// any kind.
    pub fn release_kept(&self) -> Result<()> {
        self.conn
            .execute(
                "DELETE FROM ace_holders WHERE pid = ?1 AND kind IN ('kept_root', 'profile')",
                params![self.holder_pid.0 as i64],
            )
            .context("DELETE kept holds")?;
        if self.my_ace_holds(None)?.is_empty() {
            self.unregister_broker()?;
        }
        Ok(())
    }

    /// The live sessions, other than the holder's own, that run on a
    /// kept grant. Crash recovery has already run under this lock, so
    /// a holder that died is not among them.
    pub fn other_kept_holders(&self) -> Result<Vec<KeptHolder>> {
        kept_holders_with(
            &self.conn,
            self.holder_pid.0 as i64,
            alive_by_one_snapshot()?,
        )
    }

    /// Remove the holder's `brokers` row. CASCADE drops its
    /// `holders` rows.
    pub fn unregister_broker(&self) -> Result<()> {
        self.conn
            .execute(
                "DELETE FROM brokers WHERE pid = ?1",
                params![self.holder_pid.0 as i64],
            )
            .context("DELETE brokers")?;
        Ok(())
    }

    /// Register the holder, run `f`, and on per-path failure roll
    /// back any ACEs `f` freshly added (then drop the broker row if
    /// it now holds nothing). All-or-nothing for `apply_aces`.
    fn with_broker_registration(
        &self,
        sandbox_sid: &str,
        f: impl FnOnce(&Self) -> Result<(Vec<AceWitness>, usize)>,
    ) -> Result<(Vec<AceWitness>, usize)> {
        self.register_broker()?;
        let (witnesses, failed) = f(self)?;
        if failed > 0 {
            let mut left = Vec::new();
            for w in witnesses.iter().filter(|w| w.holder_added) {
                let why = match self.release_one_ace(&w.canon, w.ace.kind(), sandbox_sid) {
                    Ok(r) if r.is_pending() => r.as_str().to_string(),
                    Ok(_) => continue,
                    Err(e) => format!("{e:#}"),
                };
                eprintln!(
                    "srt-win: WARNING: rollback {} '{}': {why}; \
                     ACE left in place",
                    w.ace.kind(),
                    w.canon
                );
                left.push(format!("'{}'", w.canon));
            }
            if !left.is_empty() {
                bail!(
                    "{failed} path(s) failed and {} could not be rolled back \
                     (ACE left in place, rows kept for retry): {}",
                    left.len(),
                    left.join(", ")
                );
            }
            if self
                .my_ace_holds(None)
                .map(|h| h.is_empty())
                .unwrap_or(false)
            {
                let _ = self.unregister_broker();
            }
        }
        Ok((witnesses, failed))
    }

    /// Apply additive sandbox-user ACEs on each `(canon, ace)` and
    /// record `self.holder_pid` as a holder. Refcounted: a path
    /// already held by another holder gets its on-disk ACE
    /// re-converged (idempotent) and a holder row added; release
    /// recomputes the effective mask from the remaining holders.
    ///
    /// `Deny` targets implicitly add a `(parent, DenyFdc)` entry so
    /// the sandbox user cannot `del`/`ren` the file via parent-FDC
    /// even when the parent carries an inherited
    /// `BUILTIN\Users:(F)`. Multiple denied siblings under one
    /// parent share the parent's `deny_fdc` row (PK
    /// `(path, kind, pid)` dedupes within one holder; refcount
    /// handles cross-holder).
    ///
    /// All-or-nothing per batch (via [`Self::with_broker_registration`]).
    pub fn apply_aces(
        &self,
        sandbox_sid: &str,
        targets: &[(String, SbAce)],
    ) -> Result<(Vec<AceWitness>, usize)> {
        self.apply_aces_and(sandbox_sid, targets, &[])
    }

    /// [`Self::apply_aces`], plus a read deny on each of `also`: the
    /// recorded paths of the profile read grant that a read deny among
    /// `targets` has to be written on as well.
    pub fn apply_aces_and(
        &self,
        sandbox_sid: &str,
        targets: &[(String, SbAce)],
        also: &[String],
    ) -> Result<(Vec<AceWitness>, usize)> {
        self.with_broker_registration(sandbox_sid, |db| {
            let mut witnesses = Vec::with_capacity(targets.len());
            let mut failed = 0usize;
            let mut one = |canon: &str, ace: SbAce| -> bool {
                match db.ensure_ace(canon, ace, sandbox_sid) {
                    Ok(w) => {
                        witnesses.push(w);
                        true
                    }
                    // Access denied on an object whose own access list already gives
                    // the sandbox account no read: the deny is satisfied, not failed.
                    Err(e)
                        if ace == SbAce::Deny(crate::acl::DenyMask::ReadDeny)
                            && is_access_denied(&e)
                            && crate::profile::closed_to_sandbox(canon) =>
                    {
                        eprintln!(
                            "srt-win: '{canon}' cannot be given a read deny and is closed to \
                             the sandbox account by its own access list"
                        );
                        if let Err(e) = db.note_satisfied_deny(canon) {
                            eprintln!("srt-win: {} '{canon}': {e:#}", ace.kind());
                            failed += 1;
                        }
                        false
                    }
                    Err(e) => {
                        eprintln!("srt-win: {} '{canon}': {e:#}", ace.kind());
                        failed += 1;
                        false
                    }
                }
            };
            for (canon, ace) in targets {
                // Skip the parent-FDC ACE when the file's own
                // Deny failed (e.g. hardlink refuse) — the batch
                // is going to roll back anyway (`failed > 0`),
                // and stamping the parent first just to release
                // it in the same pass wastes a SetSecurityInfo
                // round-trip and clutters the failure output.
                if one(canon, *ace)
                    && matches!(ace, SbAce::Deny(_) | SbAce::DenyDelete)
                    && let Some(p) = path_id::canonical_parent_of(canon)
                {
                    one(&p, SbAce::DenyFdc);
                }
            }
            let read_deny = SbAce::Deny(crate::acl::DenyMask::ReadDeny);
            for canon in also {
                match db.ensure_ace(canon, read_deny, sandbox_sid) {
                    Ok(w) => witnesses.push(w),
                    Err(e) if path_id::is_not_found(&e) => {}
                    // Access denied, and the object's own access list already gives
                    // the sandbox account no read: satisfied, not failed.
                    Err(e) if is_access_denied(&e) && crate::profile::closed_to_sandbox(canon) => {
                        if let Err(e) = db.note_satisfied_deny(canon) {
                            eprintln!("srt-win: {} '{canon}': {e:#}", read_deny.kind());
                            failed += 1;
                        }
                    }
                    Err(e) => {
                        eprintln!("srt-win: {} '{canon}': {e:#}", read_deny.kind());
                        failed += 1;
                    }
                }
            }
            Ok((witnesses, failed))
        })
    }

    /// Disk-first single-ACE converge. Record-first upsert (holder
    /// row plus `working_aces` row) then [`recompose_at`] so a
    /// crash between leaves a row whose ACE hasn't been written —
    /// the next call re-derives and reapplies.
    fn ensure_ace(&self, canon: &str, want: SbAce, sandbox_sid: &str) -> Result<AceWitness> {
        let (cur_id, links, is_dir) = path_id::capture_id_and_links(canon)
            .with_context(|| format!("capture file_id+links '{canon}'"))?;
        // Hardlink guard: NTFS hardlinks share one SD across
        // distinct canonical paths, but `ace_holders` is
        // PATH-keyed. A Deny on one alias is invisible to a holder
        // of another — `release_one_ace` on the alias sees
        // remaining=0 and recomposes the SHARED DACL without the
        // deny while the other holder's child is still running.
        // Refuse Deny on multi-link files; Grant is fail-open so
        // an early release is safe, and `DenyFdc` only targets
        // directories.
        if matches!(want, SbAce::Deny(_)) && !is_dir && links > 1 {
            bail!(
                "deny refused: '{canon}' has {links} hardlink(s); \
                 ace_holders rows are path-keyed, so releasing an \
                 alias would prematurely strip the shared deny ACE"
            );
        }
        let prior: Option<Vec<u8>> = self
            .conn
            .prepare_cached(
                "SELECT file_id FROM working_aces \
                 WHERE canonical_path = ?1 AND kind = ?2",
            )?
            .query_row(params![canon, want.kind()], |r| r.get(0))
            .optional()
            .context("SELECT working_aces")?;
        if let Some(fid) = &prior
            && FileId::from_bytes(fid)? != cur_id
        {
            bail!(
                "'{canon}': file_id changed since prior {} — path \
                 was substituted (refusing)",
                want.kind()
            );
        }
        // Holder row first (`want_mask` is THIS holder's request,
        // independent of what other holders want — `effective_ace`
        // computes the MAX). UPSERT so a re-apply at a different
        // mask updates this holder's want. `holder_added` must
        // reflect whether THIS call inserted a NEW (canon, kind,
        // pid) row — NOT whether `working_aces` was empty
        // (`prior.is_none()`): the latter would give a second
        // holder of an already-held path `holder_added=false`,
        // and partial-failure rollback (`with_broker_registration`)
        // would leak its row. SQLite's UPSERT `changes()` returns
        // 1 for both branches, so probe first.
        let already_held: bool = self
            .conn
            .prepare_cached(
                "SELECT 1 FROM ace_holders WHERE \
                 canonical_path = ?1 AND kind = ?2 AND pid = ?3 \
                 LIMIT 1",
            )?
            .exists(params![canon, want.kind(), self.holder_pid.0 as i64])
            .context("SELECT ace_holders (held?)")?;
        self.conn
            .prepare_cached(
                "INSERT INTO ace_holders \
                 (canonical_path, kind, pid, want_mask) \
                 VALUES (?1, ?2, ?3, ?4) \
                 ON CONFLICT(canonical_path, kind, pid) \
                 DO UPDATE SET want_mask = excluded.want_mask",
            )?
            .execute(params![
                canon,
                want.kind(),
                self.holder_pid.0 as i64,
                want.as_str()
            ])
            .context("UPSERT ace_holders")?;
        let holder_added = !already_held;
        let eff = effective_ace(&self.conn, canon, want.kind())?.unwrap_or(want);
        self.conn
            .prepare_cached(
                "INSERT INTO working_aces \
                 (canonical_path, kind, file_id, mask) \
                 VALUES (?1, ?2, ?3, ?4) \
                 ON CONFLICT(canonical_path, kind) DO UPDATE SET \
                   file_id = excluded.file_id, \
                   mask    = excluded.mask",
            )?
            .execute(params![
                canon,
                want.kind(),
                cur_id.as_bytes().as_slice(),
                eff.as_str()
            ])
            .context("UPSERT working_aces")?;
        recompose_at(&self.conn, canon, sandbox_sid)?;
        Ok(AceWitness {
            canon: canon.to_string(),
            ace: eff,
            already: prior.is_some(),
            holder_added,
            _sealed: (),
        })
    }

    /// Release this holder's `(canon, kind)` hold — see
    /// [`release_hold`].
    fn release_one_ace(&self, canon: &str, kind: &str, sandbox_sid: &str) -> Result<AceRelease> {
        release_hold(
            &self.conn,
            Some(self.holder_pid.0 as i64),
            canon,
            kind,
            sandbox_sid,
            &DISK,
            false,
        )
    }

    /// `(canon, kind)` rows held by this holder, optionally filtered
    /// to one set of kinds.
    fn my_ace_holds(&self, kinds: Option<&[&str]>) -> Result<Vec<(String, String)>> {
        let all: Vec<(String, String)> = query_vec(
            &self.conn,
            "SELECT canonical_path, kind FROM ace_holders \
             WHERE pid = ?1",
            params![self.holder_pid.0 as i64],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        Ok(all
            .into_iter()
            .filter(|(_, k)| kinds.is_none_or(|ks| ks.contains(&k.as_str())))
            .collect())
    }

    /// Release every ACE hold of `self.holder_pid` for `kinds` and
    /// unregister if none remain. A path whose release errored is
    /// reported as [`AceRelease::Failed`]; its rows are still held.
    pub fn release_aces(
        &self,
        sandbox_sid: &str,
        kinds: &[&str],
    ) -> Result<(Vec<(String, AceRelease)>, usize)> {
        let holds = self.my_ace_holds(Some(kinds))?;
        // A deny outlives every grant it was stamped under.
        if !kinds.contains(&"grant") && !holds.is_empty() {
            let grants = self.my_ace_holds(Some(KIND_GRANT))?.len();
            if grants > 0 {
                eprintln!(
                    "srt-win: deny release refused: holder {} still has \
                     {grants} grant(s) recorded; run `acl revoke` first",
                    self.holder_pid.0
                );
                return Ok((
                    holds
                        .into_iter()
                        .map(|(canon, _)| (canon, AceRelease::GrantPending))
                        .collect(),
                    0,
                ));
            }
        }
        let mut out = Vec::with_capacity(holds.len());
        let mut failed = 0usize;
        for (canon, kind) in &holds {
            match self.release_one_ace(canon, kind, sandbox_sid) {
                Ok(r) => out.push((canon.clone(), r)),
                Err(e) => {
                    eprintln!(
                        "srt-win: WARNING: release {kind} '{canon}': \
                         {e:#}; ACE left in place, rows kept for retry"
                    );
                    out.push((canon.clone(), AceRelease::Failed));
                    failed += 1;
                }
            }
        }
        if self
            .my_ace_holds(None)
            .map(|h| h.is_empty())
            .unwrap_or(false)
        {
            self.unregister_broker()?;
        }
        Ok((out, failed))
    }

    /// Record a placeholder component `acl stamp` is about to
    /// create (see the `placeholders` table comment). Idempotent
    /// (`INSERT OR IGNORE`); called intent-first — before the
    /// on-disk create — so a crash between record and create leaves
    /// a harmless orphan row rather than an unrecorded on-disk
    /// component a later holder cannot discover.
    pub fn record_placeholder(&self, canon: &str) -> Result<()> {
        self.conn
            .prepare_cached(
                "INSERT OR IGNORE INTO placeholders (canonical_path) \
                 VALUES (?1)",
            )?
            .execute(params![canon])
            .with_context(|| format!("INSERT placeholders '{canon}'"))?;
        Ok(())
    }

    /// Every recorded placeholder that is a STRICT ancestor of
    /// `canon` (i.e. `canon` starts with `placeholder || '\'`) —
    /// the discovery half of the full-chain hold (see the
    /// `placeholders` table comment). The table is tiny, so filter
    /// in Rust rather than a `LIKE` pattern that would have to
    /// escape `?`/`_` in canonical paths.
    pub fn placeholder_ancestors_of(&self, canon: &str) -> Result<Vec<String>> {
        let all: Vec<String> = query_vec(
            &self.conn,
            "SELECT canonical_path FROM placeholders",
            [],
            |r| r.get(0),
        )?;
        let cb = canon.as_bytes();
        Ok(all
            .into_iter()
            .filter(|p| cb.get(p.len()) == Some(&b'\\') && canon.starts_with(p.as_str()))
            .collect())
    }
}

/// Read all `working_aces` rows for `canon` and converge the on-disk
/// ACEs for `sandbox_sid` to exactly that set. The single chokepoint
/// for sandbox-user ACE state — every add/drop/crash-recover routes
/// here so a path with both a grant AND a deny (or a parent that is
/// both granted and `deny_fdc`'d) is handled consistently.
fn recompose_at(conn: &Connection, canon: &str, sandbox_sid: &str) -> Result<()> {
    let rows: Vec<(String, String)> = query_vec(
        conn,
        "SELECT kind, mask FROM working_aces \
         WHERE canonical_path = ?1",
        params![canon],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let mut set = acl::SbAceSet::default();
    for (k, m) in &rows {
        match SbAce::parse(k, m)? {
            SbAce::Grant(g) => set.grant = Some(g),
            SbAce::Deny(d) => set.deny = Some(d),
            SbAce::DenyFdc => set.deny_fdc = true,
            SbAce::DenyDelete => set.deny_delete = true,
        }
    }
    // Install-time ambient write-deny (HKLM AmbientDenies) folds
    // into every converge on the path, so session release/recovery
    // cannot strip it. WriteDeny is the floor: a session's wider
    // ReadDeny wins while its row is held, and the floor returns on
    // release. The registry value is admin-written (HKLM\SOFTWARE
    // default DACL), so the list is trustworthy as read.
    if crate::install::ambient_deny_recorded(canon) {
        set.deny.get_or_insert(acl::DenyMask::WriteDeny);
    }
    // The sandbox group, for the one place where a session's allow
    // goes ahead of another entry of ours (`apply_sandbox_aces_over`).
    let group = crate::install::read_setup()
        .ok()
        .flatten()
        .map(|s| s.sandbox_group_sid);
    acl::apply_sandbox_aces_over(canon, sandbox_sid, set, group.as_deref())
        .with_context(|| format!("recompose '{canon}' ({set:?})"))
}

/// Sealed proof that [`Locked::apply_aces`] converged `canon` to
/// carry `ace` for the sandbox user.
#[must_use]
#[allow(clippy::manual_non_exhaustive)]
#[derive(Debug)]
pub struct AceWitness {
    pub canon: String,
    pub ace: SbAce,
    /// A row already existed (another holder, or a re-apply).
    pub already: bool,
    pub holder_added: bool,
    _sealed: (),
}

/// Per-path outcome of [`Locked::release_aces`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AceRelease {
    /// ACE removed (last holder); row deleted.
    Revoked,
    /// Other holders remain at the SAME effective mask; ACE
    /// untouched.
    StillHeld,
    /// Other holders remain at a NARROWER mask; ACE re-applied at
    /// the new MAX(want_mask).
    Downgraded,
    /// `file_id` mismatch; for `grant` the ACE was revoked at the
    /// relocated path. Row deleted.
    Relocated { moved_to: String },
    /// `file_id` mismatch — row deleted, ACE on the foreign object
    /// not touched.
    Mismatch,
    /// The object is positively gone — the path is not found AND,
    /// for a grant, its volume reports no file with the recorded
    /// `file_id`. Row deleted.
    Gone,
    /// Holder row removed but no `working_aces` row found.
    NoRow,
    /// Where the ACE is now could not be established. Nothing was
    /// changed: rows kept, ACE may still be on disk.
    Unreadable,
    /// The release errored (row update or converge). Nothing was
    /// changed: rows kept, ACE may still be on disk.
    Failed,
    /// A deny hold whose holder still has a grant recorded. Nothing
    /// was changed: a deny outlives every grant it was stamped under.
    GrantPending,
    /// `acl recover --force` only: the record of a grant that could
    /// not be located was dropped; its ACE may still be on disk.
    Dropped,
}

impl AceRelease {
    /// The rows are still there and the ACE may still be on disk.
    pub fn is_pending(&self) -> bool {
        matches!(
            self,
            AceRelease::Unreadable | AceRelease::Failed | AceRelease::GrantPending
        )
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            AceRelease::Revoked => "revoked",
            AceRelease::StillHeld => "stillHeld",
            AceRelease::Downgraded => "downgraded",
            AceRelease::Relocated { .. } => "relocated",
            AceRelease::Mismatch => "mismatch",
            AceRelease::Gone => "gone",
            AceRelease::NoRow => "noRow",
            AceRelease::Unreadable => "unreadable",
            AceRelease::Failed => "failed",
            AceRelease::GrantPending => "grantPending",
            AceRelease::Dropped => "dropped",
        }
    }
}

/// The filesystem and process probes a release or recovery performs.
/// Injectable so the row bookkeeping can be unit-tested without real
/// ACLs or processes.
struct Disk {
    gate: fn(&str, FileId) -> IdGate,
    locate: fn(&FileId) -> path_id::Located,
    converge: fn(&Connection, &str, &str) -> Result<()>,
    alive: fn(u32, i64) -> bool,
}

const DISK: Disk = Disk {
    gate: identity_gate,
    locate: path_id::locate_by_file_id,
    converge: recompose_at,
    alive: is_process_alive,
};

/// `MAX(want_mask)` across the holders of `(canon, kind)`.
fn effective_ace(conn: &Connection, canon: &str, kind: &str) -> Result<Option<SbAce>> {
    let masks: Vec<String> = query_vec(
        conn,
        "SELECT want_mask FROM ace_holders \
         WHERE canonical_path = ?1 AND kind = ?2",
        params![canon, kind],
        |r| r.get(0),
    )?;
    masks
        .iter()
        .map(|m| SbAce::parse(kind, m))
        .reduce(|a, b| Ok(a?.max(b?)))
        .transpose()
}

fn delete_holder(conn: &Connection, holder: Option<i64>, canon: &str, kind: &str) -> Result<()> {
    if let Some(pid) = holder {
        conn.prepare_cached(
            "DELETE FROM ace_holders WHERE canonical_path = ?1 \
             AND kind = ?2 AND pid = ?3",
        )?
        .execute(params![canon, kind, pid])
        .context("DELETE ace_holders")?;
    }
    Ok(())
}

/// Release `holder`'s hold on `(canon, kind)` (`None`: a holderless
/// row). Where the ACE is now is established before any row changes,
/// and the row changes commit only after the converge succeeded.
fn release_hold(
    conn: &Connection,
    holder: Option<i64>,
    canon: &str,
    kind: &str,
    sandbox_sid: &str,
    disk: &Disk,
    force: bool,
) -> Result<AceRelease> {
    let row: Option<(Vec<u8>, String)> = conn
        .prepare_cached(
            "SELECT file_id, mask FROM working_aces \
             WHERE canonical_path = ?1 AND kind = ?2",
        )?
        .query_row(params![canon, kind], |r| Ok((r.get(0)?, r.get(1)?)))
        .optional()?;
    let Some((fid, stored)) = row else {
        delete_holder(conn, holder, canon, kind)?;
        return Ok(AceRelease::NoRow);
    };
    let want_id = FileId::from_bytes(&fid)?;

    enum Site {
        Here,
        Moved(String),
        Gone,
        Foreign,
        Dropped,
    }
    let site = match (disk.gate)(canon, want_id) {
        IdGate::Match => Site::Here,
        IdGate::Unreadable => {
            eprintln!(
                "srt-win: {kind} '{canon}': open failed; ACE left \
                 in place, rows kept for retry"
            );
            return Ok(AceRelease::Unreadable);
        }
        // The ALLOW ACE travels with a moved object: chase it by
        // file_id and revoke there.
        IdGate::Mismatch if kind == "grant" => match (disk.locate)(&want_id) {
            path_id::Located::At(at) => Site::Moved(at),
            path_id::Located::Gone => Site::Gone,
            path_id::Located::Unknown if force => Site::Dropped,
            path_id::Located::Unknown | path_id::Located::VolumeAbsent => {
                eprintln!(
                    "srt-win: grant '{canon}': not at its path and \
                     could not be located by file_id; ACE may \
                     still be on disk, rows kept for retry"
                );
                return Ok(AceRelease::Unreadable);
            }
        },
        // DENY/FDC are left in place on the moved object
        // (fail-closed).
        IdGate::Mismatch => Site::Foreign,
    };

    let tx = conn.unchecked_transaction().context("begin release tx")?;
    delete_holder(&tx, holder, canon, kind)?;
    let new_eff = effective_ace(&tx, canon, kind)?;
    match new_eff {
        Some(e) => tx
            .execute(
                "UPDATE working_aces SET mask = ?3 \
                 WHERE canonical_path = ?1 AND kind = ?2",
                params![canon, kind, e.as_str()],
            )
            .context("UPDATE working_aces (downgrade)")?,
        None => tx
            .execute(
                "DELETE FROM working_aces \
                 WHERE canonical_path = ?1 AND kind = ?2",
                params![canon, kind],
            )
            .context("DELETE working_aces")?,
    };
    let out = match site {
        Site::Here => {
            (disk.converge)(&tx, canon, sandbox_sid)?;
            match new_eff {
                Some(e) if e.as_str() == stored => AceRelease::StillHeld,
                Some(_) => AceRelease::Downgraded,
                None => AceRelease::Revoked,
            }
        }
        Site::Moved(at) => {
            eprintln!(
                "srt-win: grant '{canon}': file_id moved to '{at}'; \
                 revoking there"
            );
            (disk.converge)(&tx, &at, sandbox_sid)?;
            AceRelease::Relocated { moved_to: at }
        }
        Site::Gone => {
            eprintln!(
                "srt-win: grant '{canon}': path and file_id both \
                 gone; dropping row"
            );
            AceRelease::Gone
        }
        Site::Foreign => {
            eprintln!(
                "srt-win: {kind} '{canon}': file_id mismatch — \
                 path substituted; not touching ACE on the \
                 foreign object (fail-closed)"
            );
            AceRelease::Mismatch
        }
        Site::Dropped => {
            eprintln!(
                "srt-win: acl recover --force: grant '{canon}' could not \
                 be located; its record is dropped and its ACE may still \
                 be on disk"
            );
            AceRelease::Dropped
        }
    };
    tx.commit().context("commit release")?;
    Ok(out)
}

/// Release the holds of dead brokers, then prune them. Each hold is
/// its own transaction ([`release_hold`]).
fn crash_recovery(conn: &Connection, force: bool) -> Result<RecoveryReport> {
    // Identity comes from the validated machine-store read, never
    // from raw rows: the session DB is user-writable.
    let sb = crate::install::read_setup()?.map(|s| s.sandbox_user_sid);
    let report = recover_with(conn, sb.as_deref(), &DISK, force)?;
    // Persistent-grant DACL writes that were started and not seen to
    // finish (they have no holder, so nothing above covers them).
    crate::persist::replay_pending(conn);
    Ok(report)
}

/// What one recovery pass releases with.
struct Recovery<'a> {
    conn: &'a Connection,
    sb: &'a str,
    disk: &'a Disk,
    force: bool,
}

/// Release `(canon, kind)` for recovery; `false` when its rows are
/// still there (so the caller must not go on to dependent rows).
fn recover_one(
    rc: &Recovery<'_>,
    holder: Option<i64>,
    canon: &str,
    kind: &str,
    report: &mut RecoveryReport,
) -> bool {
    let done = match release_hold(rc.conn, holder, canon, kind, rc.sb, rc.disk, rc.force) {
        Ok(r) if r.is_pending() => false,
        Ok(AceRelease::Dropped) => {
            report.grants_dropped.push(canon.to_string());
            true
        }
        Ok(AceRelease::StillHeld | AceRelease::Downgraded | AceRelease::NoRow) => true,
        Ok(_) => {
            report.aces_revoked += 1;
            true
        }
        Err(e) => {
            eprintln!(
                "srt-win: WARNING: recover {kind} '{canon}': {e:#}; \
                 ACE left in place, rows kept for retry"
            );
            false
        }
    };
    if !done && kind == "grant" {
        report.grants_pending.push(canon.to_string());
    }
    done
}

/// Release `holds` grants-first; the non-grant rows only if every
/// grant was released, and not at all when `blocked`.
fn recover_holds(
    rc: &Recovery<'_>,
    holder: Option<i64>,
    holds: &[(String, String)],
    mut blocked: bool,
    report: &mut RecoveryReport,
) {
    for (canon, kind) in holds.iter().filter(|(_, k)| k == "grant") {
        blocked |= !recover_one(rc, holder, canon, kind, report);
    }
    let denies = holds.iter().filter(|(_, k)| k != "grant");
    if blocked {
        let kept = denies.count();
        if kept > 0 {
            eprintln!(
                "srt-win: WARNING: a grant{} could not be released; \
                 keeping {kept} deny row(s) until it can",
                holder
                    .map(|p| format!(" of dead holder {p}"))
                    .unwrap_or_default(),
            );
        }
        return;
    }
    for (canon, kind) in denies {
        recover_one(rc, holder, canon, kind, report);
    }
}

fn recover_with(
    conn: &Connection,
    sb: Option<&str>,
    disk: &Disk,
    force: bool,
) -> Result<RecoveryReport> {
    let mut report = RecoveryReport::default();

    // 1. Find dead brokers.
    let dead: Vec<i64> = query_vec(
        conn,
        "SELECT pid, process_create_time FROM brokers",
        [],
        |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)),
    )?
    .into_iter()
    // A negative pid is a dead broker set aside by `register_broker`.
    .filter(|&(pid, ct)| pid < 0 || !(disk.alive)(pid as u32, ct))
    .map(|(pid, _)| pid)
    .collect();

    // 2. Release each dead broker's holds before pruning it: deleting
    //    the broker first would CASCADE its holder rows away.
    for pid in dead {
        let holds: Vec<(String, String)> = query_vec(
            conn,
            "SELECT canonical_path, kind FROM ace_holders \
             WHERE pid = ?1 ORDER BY canonical_path, kind",
            params![pid],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        if let Some(sb) = sb {
            let rc = Recovery {
                conn,
                sb,
                disk,
                force,
            };
            recover_holds(&rc, Some(pid), &holds, false, &mut report);
        }
        let left: i64 = conn
            .query_row(
                "SELECT count(*) FROM ace_holders WHERE pid = ?1",
                params![pid],
                |r| r.get(0),
            )
            .context("count holds of dead broker")?;
        if left == 0 {
            conn.execute("DELETE FROM brokers WHERE pid = ?1", params![pid])
                .context("DELETE dead broker")?;
            report.dead_brokers += 1;
        }
    }

    // 3. Holderless `working_aces` rows: their deny rows are kept
    //    while ANY grant is still pending.
    if let Some(sb) = sb {
        let orphans: Vec<(String, String)> = query_vec(
            conn,
            "SELECT g.canonical_path, g.kind \
             FROM working_aces g \
             LEFT JOIN ace_holders h \
               ON h.canonical_path = g.canonical_path \
              AND h.kind = g.kind \
             WHERE h.canonical_path IS NULL \
             ORDER BY g.canonical_path, g.kind",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let blocked = !report.grants_pending.is_empty();
        let rc = Recovery {
            conn,
            sb,
            disk,
            force,
        };
        recover_holds(&rc, None, &orphans, blocked, &mut report);
    }
    Ok(report)
}

enum IdGate {
    Match,
    Mismatch,
    Unreadable,
}

/// `(path, file_id)` identity check. Not found or different inode →
/// `Mismatch` (the object, and its ACE, may live on elsewhere); any
/// other open error → `Unreadable`.
fn identity_gate(path: &str, expect: FileId) -> IdGate {
    match path_id::capture_file_id(path) {
        Ok(cur) if cur == expect => IdGate::Match,
        Ok(_) => IdGate::Mismatch,
        Err(e) => {
            if path_id::is_not_found(&e) {
                IdGate::Mismatch
            } else {
                eprintln!("srt-win: '{path}': cannot read file_id ({e:#})");
                IdGate::Unreadable
            }
        }
    }
}

/// True if `pid` refers to a live process whose CreationTime
/// matches `expected_create_filetime`. PID-recycle guard.
fn is_process_alive(pid: u32, expected_create_filetime: i64) -> bool {
    if pid == std::process::id() {
        // Don't reap ourselves even if the stored CreationTime is
        // somehow stale.
        return true;
    }
    // From the system's process list: opening the process cannot tell a
    // dead holder whose pid was reused from a live one.
    match process_create_times() {
        Ok(all) => listed_alive(&all, pid, expected_create_filetime),
        // No complete list: ask the process directly; what that cannot
        // settle counts as alive (never reap a holder that may be live).
        Err(_) => is_process_alive_by_opening(pid, expected_create_filetime),
    }
}

/// A holder is DEAD only on positive evidence from a complete list: its pid
/// is absent, or listed with another creation time. Recorded with no
/// creation time (0), it counts as alive while the pid exists.
fn listed_alive(all: &std::collections::HashMap<u32, i64>, pid: u32, recorded: i64) -> bool {
    match all.get(&pid) {
        None => false,
        Some(&created) => recorded == 0 || created == recorded,
    }
}

/// [`is_process_alive`] over ONE reading of the process list, for a query
/// that judges a holder per row. Fails, rather than guess, if the list
/// cannot be read.
fn alive_by_one_snapshot() -> Result<impl Fn(u32, i64) -> bool> {
    let all = process_create_times().context(
        "cannot tell which sandbox sessions are running (the system's process list could \
         not be read); nothing was changed",
    )?;
    Ok(move |pid, created| pid == std::process::id() || listed_alive(&all, pid, created))
}

/// Every process on the machine: pid to creation time (a FILETIME as
/// one integer, the form [`process_create_time`] gives).
fn process_create_times() -> Result<std::collections::HashMap<u32, i64>> {
    #[link(name = "ntdll", kind = "raw-dylib")]
    unsafe extern "system" {
        fn NtQuerySystemInformation(
            class: u32,
            info: *mut core::ffi::c_void,
            len: u32,
            returned: *mut u32,
        ) -> i32;
    }
    const SYSTEM_PROCESS_INFORMATION: u32 = 5;
    const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004_u32 as i32;
    // Of each entry: the offset of the next one (0 at the last), the
    // creation time, the pid.
    const NEXT_AT: usize = 0;
    const CREATED_AT: usize = 32;
    const PID_AT: usize = 80;
    const ENTRY_MIN: usize = PID_AT + 8;

    let mut buf: Vec<u64> = vec![0; 64 * 1024];
    for _ in 0..8 {
        let mut needed = 0u32;
        let status = unsafe {
            NtQuerySystemInformation(
                SYSTEM_PROCESS_INFORMATION,
                buf.as_mut_ptr().cast(),
                (buf.len() * 8) as u32,
                &mut needed,
            )
        };
        if status == STATUS_INFO_LENGTH_MISMATCH {
            // More processes than fit, and more may start meanwhile.
            buf = vec![0; (buf.len() * 2).max(needed as usize / 8 + 1024)];
            continue;
        }
        if status < 0 {
            bail!("NtQuerySystemInformation(processes): status {status:#x}");
        }
        let bytes = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), buf.len() * 8) };
        // Only what the system said it wrote.
        let written = match needed as usize {
            0 => bytes.len(),
            n => n.min(bytes.len()),
        };
        return parse_process_list(&bytes[..written], NEXT_AT, CREATED_AT, PID_AT, ENTRY_MIN)
            .context("the process list is incomplete");
    }
    bail!("the process list kept growing")
}

/// The list as pid → creation time, or `None` if it is not complete:
/// an entry that does not fit in what was written, or a chain that
/// does not end in a last entry.
fn parse_process_list(
    bytes: &[u8],
    next_at: usize,
    created_at: usize,
    pid_at: usize,
    entry_min: usize,
) -> Option<std::collections::HashMap<u32, i64>> {
    let mut out = std::collections::HashMap::new();
    let mut at = 0usize;
    loop {
        let entry = bytes.get(at..).filter(|e| e.len() >= entry_min)?;
        let u32_at = |o: usize| u32::from_le_bytes(entry[o..o + 4].try_into().unwrap());
        let i64_at = |o: usize| i64::from_le_bytes(entry[o..o + 8].try_into().unwrap());
        out.insert(i64_at(pid_at) as u32, i64_at(created_at));
        match u32_at(next_at) as usize {
            0 => return Some(out),
            next => at = at.checked_add(next)?,
        }
    }
}

fn is_process_alive_by_opening(pid: u32, expected_create_filetime: i64) -> bool {
    // SYNCHRONIZE so the WaitForSingleObject(0) signaled-check works.
    let h = match unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION
                | windows::Win32::System::Threading::PROCESS_SYNCHRONIZE,
            false,
            pid,
        )
    } {
        Ok(h) if !h.is_invalid() => h,
        // A spurious `Ok` with an invalid handle is "uncertain" —
        // treat as ALIVE, matching the conservative stance below
        // (better to leave a stale row than reap a live broker and
        // restore a file it still holds).
        Ok(_) => return true,
        // Treat as DEAD only on ERROR_INVALID_PARAMETER (87) — the
        // "no such PID" signal. Every other error (ACCESS_DENIED,
        // transient low-memory, etc.) is uncertain → ALIVE, so we
        // never reap (and restore a file still used by) a holder
        // that's actually running.
        Err(e) => {
            return (e.code().0 as u32 & 0xFFFF) != 87;
        }
    };
    let h = crate::util::OwnedHandle(h);
    match process_create_time(h.raw()) {
        Ok(ct) => {
            ct == expected_create_filetime
                // An exited process whose handle is still held
                // elsewhere remains openable with the same
                // CreationTime — without this check it reads as
                // alive forever and is never reaped. Only
                // WAIT_OBJECT_0 (= signaled = exited) is "dead";
                // WAIT_TIMEOUT and WAIT_FAILED are both "alive"
                // (uncertain → ALIVE, matching the conservative
                // stance everywhere else in this function).
                && unsafe { WaitForSingleObject(h.raw(), 0) }
                    != WAIT_OBJECT_0
        }
        // Transient GetProcessTimes failure → uncertain → ALIVE,
        // matching the conservative stance everywhere else (better
        // a stale row than a live holder reaped and its files
        // restored under it).
        Err(_) => true,
    }
}

/// Creation FILETIME (as i64) of an arbitrary PID. Opens the
/// process for limited query; special-cases self to avoid needing
/// OpenProcess rights on our own token.
fn pid_create_time(pid: u32) -> Result<i64> {
    if pid == std::process::id() {
        return process_create_time(unsafe { GetCurrentProcess() });
    }
    let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }
        .with_context(|| format!("OpenProcess({pid}) for create-time"))?;
    if h.is_invalid() {
        bail!("OpenProcess({pid}) returned invalid handle");
    }
    let h = crate::util::OwnedHandle(h);
    process_create_time(h.raw())
}

/// FILETIME (100-ns since 1601-01-01) → i64 for storage.
fn process_create_time(h: HANDLE) -> Result<i64> {
    let mut create = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    unsafe {
        GetProcessTimes(h, &mut create, &mut exit, &mut kernel, &mut user)
            .context("GetProcessTimes")?;
    }
    Ok(((create.dwHighDateTime as i64) << 32) | (create.dwLowDateTime as i64))
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_dir_rejects_empty_or_relative() {
        use std::ffi::OsString;
        // Unset or empty → error (var_os returns Some("") for a
        // present-but-empty var, which the old code accepted).
        assert!(state_dir_from_base(None, "ProgramData").is_err());
        assert!(state_dir_from_base(Some(OsString::from("")), "ProgramData").is_err());
        // Relative → error (would put the broker-only-stamped DB
        // in CWD).
        assert!(state_dir_from_base(Some(OsString::from("rel")), "ProgramData").is_err());
        // Absolute → ok.
        let ok = state_dir_from_base(
            Some(OsString::from(r"C:\Users\u\AppData\Local")),
            "ProgramData",
        );
        assert_eq!(
            ok.unwrap(),
            PathBuf::from(r"C:\Users\u\AppData\Local\sandbox-runtime")
        );
    }

    /// Open an in-memory DB and run `f` against a `Locked` view
    /// (autocommit, like production). Skips the named mutex + dir
    /// stamp (those are integration-tested via the G-rows in
    /// smoke-exec.ps1).
    fn with_mem_db<R>(f: impl FnOnce(&mut Locked) -> R) -> R {
        let conn = open_db_at(
            std::path::Path::new(":memory:"),
            SESSION_SCHEMA_SQL,
            SESSION_SCHEMA_VERSION,
        )
        .unwrap();
        let mut db = Locked {
            conn,
            holder_pid: HolderPid(std::process::id()),
        };
        f(&mut db)
    }

    /// Regression: `register_broker` uses ON CONFLICT DO UPDATE,
    /// not INSERT OR REPLACE — the latter would CASCADE-delete
    /// this holder's existing `ace_holders` rows on a second
    /// stamp/grant.
    #[test]
    fn second_register_broker_keeps_existing_holds() {
        with_mem_db(|db| {
            db.register_broker().unwrap();
            // Two holds via direct INSERT (ensure_ace needs a real
            // file; the CASCADE behavior under test is pure SQL).
            for p in [r"\\?\C:\a", r"\\?\C:\b"] {
                db.conn
                    .execute(
                        "INSERT INTO ace_holders \
                         (canonical_path, kind, pid, want_mask) \
                         VALUES (?1, 'deny', ?2, 'denyRead')",
                        params![p, db.holder_pid.0 as i64],
                    )
                    .unwrap();
            }
            assert_eq!(db.my_ace_holds(None).unwrap().len(), 2);
            // Second batch by the same holder.
            db.register_broker().unwrap();
            // Holds intact (would be 0 with INSERT OR REPLACE).
            assert_eq!(db.my_ace_holds(None).unwrap().len(), 2);
        });
    }

    #[test]
    fn schema_applies_in_memory() {
        // Session schema: bookkeeping tables only — the setup
        // record lives in the MACHINE schema since the store split.
        with_mem_db(|db| {
            let n: i64 = db
                .conn
                .query_row(
                    "SELECT count(*) FROM sqlite_master WHERE type='table' \
                     AND name IN ('brokers','working_aces','ace_holders', \
                                  'placeholders','sandbox_user')",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(
                n, 4,
                "session schema: 4 bookkeeping tables, no sandbox_user"
            );
        });
    }

    #[test]
    fn aliveness_self_is_alive() {
        let ct = process_create_time(unsafe { GetCurrentProcess() }).unwrap();
        assert!(is_process_alive(std::process::id(), ct));
        // Same PID, wrong create time would normally be "recycled →
        // dead", but we special-case ourselves.
        assert!(is_process_alive(std::process::id(), ct + 1));
    }

    #[test]
    fn aliveness_bogus_pid_is_dead() {
        // PID 0x7FFF_FFFE is well above any plausible live PID.
        assert!(!is_process_alive(0x7FFF_FFFE, 0));
    }

    const TREE: &str = r"\\?\C:\tree";
    const SECRET: &str = r"\\?\C:\tree\secret";
    const SID: &str = "S-1-5-21-1";

    /// Every probe answers "all good".
    const OK_DISK: Disk = Disk {
        gate: |_, _| IdGate::Match,
        locate: |_| path_id::Located::Gone,
        converge: |_, _, _| Ok(()),
        alive: |_, _| false,
    };

    /// One hold of `pid` on `(canon, kind)`, with its broker and working row.
    fn seed(conn: &Connection, pid: i64, canon: &str, kind: &str, mask: &str) {
        conn.execute(
            "INSERT OR IGNORE INTO brokers (pid, process_create_time, started_at) \
             VALUES (?1, 0, 0)",
            params![pid],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO ace_holders (canonical_path, kind, pid, want_mask) \
             VALUES (?1, ?2, ?3, ?4)",
            params![canon, kind, pid, mask],
        )
        .unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO working_aces (canonical_path, kind, file_id, mask) \
             VALUES (?1, ?2, ?3, ?4)",
            params![canon, kind, [0u8; 24].as_slice(), mask],
        )
        .unwrap();
    }

    /// `(brokers, ace_holders, working_aces)` row counts.
    fn counts(conn: &Connection) -> (i64, i64, i64) {
        let n = |t: &str| -> i64 {
            conn.query_row(&format!("SELECT count(*) FROM {t}"), [], |r| r.get(0))
                .unwrap()
        };
        (n("brokers"), n("ace_holders"), n("working_aces"))
    }

    /// A profile operation that is going ahead is named to those it keeps out;
    /// before that, after it, or under another word, it is an ordinary wait.
    #[test]
    fn a_profile_operation_going_ahead_is_named_to_those_it_keeps_out() {
        use std::os::windows::fs::FileExt;
        let busy = |r: Result<InitMutex>| r.err().is_some_and(|e| e.is::<ProfileBusy>());
        let held = InitMutex::acquire_within(100, 400).unwrap();
        let r = InitMutex::acquire_within(100, 400);
        assert!(r.is_err() && !busy(r));
        assert!(!profile_operation_running());
        mark_profile_operation().unwrap();
        let started = std::time::Instant::now();
        assert!(busy(InitMutex::acquire_within(200, 5_000)));
        assert!(started.elapsed().as_millis() < 2_000, "told promptly");
        assert!(profile_operation_running());
        let file = &held.file;
        for stale in [&b"profile\n"[..], b"profile 2147483646", b"session\n"] {
            let mut word = [b'\n'; LOCK_WORD_LEN];
            word[..stale.len()].copy_from_slice(stale);
            file.seek_write(&word, LOCK_WORD_AT).unwrap();
            let r = InitMutex::acquire_within(100, 400);
            assert!(r.is_err() && !busy(r), "{stale:?}");
            assert!(!profile_operation_running());
        }
        mark_profile_operation().unwrap();
        drop(held);
        assert!(!profile_operation_running());
        let next = InitMutex::acquire_within(100, 400).unwrap();
        let mut word = [0u8; LOCK_WORD_LEN];
        next.file.seek_read(&mut word, LOCK_WORD_AT).unwrap();
        assert_eq!(profile_word_pid(&word), None);
        drop(next);
    }

    /// A holder is alive if the process list has its pid with the recorded
    /// creation time; absent or another process's, it is dead.
    #[test]
    fn a_holder_is_judged_by_the_process_list() {
        let all = process_create_times().unwrap();
        let me = std::process::id();
        assert_eq!(
            all.get(&me).copied(),
            Some(process_create_time(unsafe { GetCurrentProcess() }).unwrap())
        );
        let (&other, &created) = all.iter().find(|&(&pid, _)| pid != me && pid > 4).unwrap();
        assert!(is_process_alive(other, created));
        assert!(!is_process_alive(other, created + 1));
        assert!(!is_process_alive(4, 1));
        assert!(!is_process_alive(0x7FFF_FFFE, 0));
        let mut two = vec![0u8; 200];
        two[0..4].copy_from_slice(&100u32.to_le_bytes());
        two[32..40].copy_from_slice(&7i64.to_le_bytes());
        two[80..88].copy_from_slice(&11u64.to_le_bytes());
        two[132..140].copy_from_slice(&9i64.to_le_bytes());
        two[180..188].copy_from_slice(&12u64.to_le_bytes());
        let parsed = parse_process_list(&two, 0, 32, 80, 88).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!((parsed[&11], parsed[&12]), (7, 9));
        assert!(parse_process_list(&two[..150], 0, 32, 80, 88).is_none());
        assert!(parse_process_list(&two[..100], 0, 32, 80, 88).is_none());
        assert!(parse_process_list(&two[..40], 0, 32, 80, 88).is_none());
        assert!(parse_process_list(&[], 0, 32, 80, 88).is_none());
        assert!(listed_alive(&parsed, 11, 7));
        assert!(!listed_alive(&parsed, 11, 8), "its pid is another's now");
        assert!(!listed_alive(&parsed, 13, 7), "its pid is nobody's");
        assert!(listed_alive(&parsed, 11, 0));
        assert!(!listed_alive(&parsed, 13, 0));
        let mut child = std::process::Command::new("cmd")
            .args(["/c", "ping -n 3 127.0.0.1 >nul"])
            .spawn()
            .unwrap();
        let recorded = pid_create_time(child.id()).unwrap();
        assert!(is_process_alive(child.id(), recorded));
        assert!(alive_by_one_snapshot().unwrap()(child.id(), recorded));
        let pid = child.id();
        child.kill().ok();
        child.wait().unwrap();
        drop(child);
        let gone = (0..50).any(|_| {
            if !is_process_alive(pid, recorded) {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
            false
        });
        assert!(gone);
    }

    /// A read deny the object's own list stands in for leaves one row
    /// — no deny holder, nothing to take off the object — and
    /// releasing it leaves no holder at all.
    #[test]
    fn a_satisfied_deny_is_released_without_a_write() {
        with_mem_db(|db| {
            let canon = r"\\?\C:\Users\me\AppData\Local\Closed";
            let pid = db.holder_pid.0 as i64;
            seed(db.conn(), pid, canon, "deny", "denyRead");
            db.note_satisfied_deny(canon).unwrap();
            let kinds: Vec<String> = query_vec(
                db.conn(),
                "SELECT kind FROM ace_holders WHERE canonical_path = ?1",
                params![canon],
                |r| r.get(0),
            )
            .unwrap();
            assert_eq!(kinds, [KIND_DENY_SATISFIED]);
            let working: i64 = db
                .conn()
                .query_row("SELECT COUNT(*) FROM working_aces", [], |r| r.get(0))
                .unwrap();
            assert_eq!(working, 0);
            assert_eq!(
                live_holders_with(db.conn(), None, |_, _| true)
                    .unwrap()
                    .len(),
                1
            );
            let (_, failed) = db.release_aces(SID, KIND_DENY).unwrap();
            assert_eq!(failed, 0, "nothing was written, nothing fails");
            assert_eq!(counts(db.conn()), (0, 0, 0));
            assert!(
                live_holders_with(db.conn(), None, |_, _| true)
                    .unwrap()
                    .is_empty()
            );
        });
    }

    /// Who runs on a kept grant: live holders other than the caller,
    /// and never one whose process is gone.
    #[test]
    fn kept_grant_holders_are_the_live_other_sessions() {
        with_mem_db(|db| {
            let me = db.holder_pid.0 as i64;
            let (other, dead) = (me + 1, me + 2);
            let root = r"\\?\C:\work".to_owned();
            db.hold_kept(std::slice::from_ref(&root), Some(KEPT_PROFILE_PATH))
                .unwrap();
            db.hold_kept(std::slice::from_ref(&root), Some(KEPT_PROFILE_PATH))
                .unwrap();
            assert_eq!(counts(&db.conn), (1, 2, 0));
            let alone = Locked {
                conn: open_memory_db_for_tests(),
                holder_pid: HolderPid(db.holder_pid.0),
            };
            alone.hold_kept(&[], None).unwrap();
            assert_eq!(counts(&alone.conn), (0, 0, 0));
            fn alive(_pid: u32, create_time: i64) -> bool {
                create_time != 2
            }
            for (pid, create_time) in [(other, 1), (dead, 2)] {
                db.conn
                    .execute(
                        "INSERT INTO brokers (pid, process_create_time, started_at) \
                         VALUES (?1, ?2, 0)",
                        params![pid, create_time],
                    )
                    .unwrap();
                for (kind, path) in [("kept_root", root.as_str()), ("profile", "p")] {
                    db.conn
                        .execute(
                            "INSERT INTO ace_holders (canonical_path, kind, pid, want_mask) \
                             VALUES (?1, ?2, ?3, '')",
                            params![path, kind, pid],
                        )
                        .unwrap();
                }
            }
            seed(&db.conn, other, TREE, "grant", "modify");
            let held = kept_holders_with(&db.conn, me, alive).unwrap();
            assert_eq!(
                held,
                [
                    KeptHolder {
                        pid: other as u32,
                        kind: "kept_root".into(),
                        path: root.clone()
                    },
                    KeptHolder {
                        pid: other as u32,
                        kind: "profile".into(),
                        path: "p".into()
                    },
                ]
            );
            let all = live_holders_with(&db.conn, None, alive).unwrap();
            assert_eq!(all.len(), 5, "{all:?}");
            assert!(all.iter().all(|h| i64::from(h.pid) != dead));
            assert!(
                all.iter()
                    .any(|h| h.kind == "grant" && i64::from(h.pid) == other)
            );
            let but_me = live_holders_with(&db.conn, Some(me as u32), alive).unwrap();
            assert_eq!(but_me.len(), 3);
            let held = kept_holders_with(&db.conn, other, alive).unwrap();
            assert!(held.iter().all(|h| i64::from(h.pid) == me) && held.len() == 2);

            let disk = Disk { alive, ..OK_DISK };
            let report = recover_with(&db.conn, Some(SID), &disk, false).unwrap();
            assert_eq!(report.dead_brokers, 1);
            let left: i64 = db
                .conn
                .query_row(
                    "SELECT count(*) FROM ace_holders WHERE pid = ?1",
                    params![dead],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(left, 0);
            assert_eq!(kept_holders_with(&db.conn, me, alive).unwrap().len(), 2);

            db.release_kept().unwrap();
            let mine: i64 = db
                .conn
                .query_row(
                    "SELECT count(*) FROM brokers WHERE pid = ?1",
                    params![me],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(mine, 0);
            assert!(
                kept_holders_with(&db.conn, other, alive)
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(kept_holders_with(&db.conn, me, alive).unwrap().len(), 2);
        });
    }

    #[test]
    fn unreadable_release_changes_nothing() {
        with_mem_db(|db| {
            let me = db.holder_pid.0 as i64;
            seed(&db.conn, me, TREE, "grant", "modify");
            let disk = Disk {
                gate: |_, _| IdGate::Unreadable,
                ..OK_DISK
            };
            let r = release_hold(&db.conn, Some(me), TREE, "grant", SID, &disk, false).unwrap();
            assert_eq!(r, AceRelease::Unreadable);
            assert_eq!(r.as_str(), "unreadable");
            assert_eq!(counts(&db.conn), (1, 1, 1));
            let r = release_hold(&db.conn, Some(me), TREE, "grant", SID, &OK_DISK, false).unwrap();
            assert_eq!(r, AceRelease::Revoked);
            assert_eq!(counts(&db.conn), (1, 0, 0));
        });
    }

    #[test]
    fn failed_converge_rolls_the_rows_back() {
        with_mem_db(|db| {
            let me = db.holder_pid.0 as i64;
            seed(&db.conn, me, TREE, "grant", "modify");
            let disk = Disk {
                converge: |_, _, _| bail!("SetNamedSecurityInfoW failed"),
                ..OK_DISK
            };
            assert!(release_hold(&db.conn, Some(me), TREE, "grant", SID, &disk, false).is_err());
            assert_eq!(counts(&db.conn), (1, 1, 1));
        });
    }

    #[test]
    fn moved_grant_is_missing_only_when_positively_gone() {
        with_mem_db(|db| {
            let me = db.holder_pid.0 as i64;
            seed(&db.conn, me, TREE, "grant", "modify");
            let disk = Disk {
                gate: |_, _| IdGate::Mismatch,
                locate: |_| path_id::Located::Unknown,
                ..OK_DISK
            };
            let r = release_hold(&db.conn, Some(me), TREE, "grant", SID, &disk, false).unwrap();
            assert_eq!(r, AceRelease::Unreadable);
            assert_eq!(counts(&db.conn), (1, 1, 1));
            let disk = Disk {
                gate: |_, _| IdGate::Mismatch,
                locate: |_| path_id::Located::At(r"\\?\C:\moved".into()),
                converge: |_, _, _| bail!("converge failed"),
                ..OK_DISK
            };
            assert!(release_hold(&db.conn, Some(me), TREE, "grant", SID, &disk, false).is_err());
            assert_eq!(counts(&db.conn), (1, 1, 1));
            let disk = Disk {
                gate: |_, _| IdGate::Mismatch,
                ..OK_DISK
            };
            let r = release_hold(&db.conn, Some(me), TREE, "grant", SID, &disk, false).unwrap();
            assert_eq!(r, AceRelease::Gone);
            assert_eq!(r.as_str(), "gone");
            assert_eq!(counts(&db.conn), (1, 0, 0));
        });
    }

    #[test]
    fn recovery_keeps_a_holders_denies_while_its_grant_is_pending() {
        with_mem_db(|db| {
            let c = &db.conn;
            seed(c, 41, TREE, "grant", "modify");
            seed(c, 41, SECRET, "deny", "denyWrite");
            seed(c, 41, TREE, "deny_fdc", "fdc");
            seed(c, 42, r"\\?\C:\other", "grant", "read");
            seed(c, 42, r"\\?\C:\other\x", "deny", "denyRead");

            let disk = Disk {
                gate: |p, _| {
                    if p == TREE {
                        IdGate::Unreadable
                    } else {
                        IdGate::Match
                    }
                },
                ..OK_DISK
            };
            let rep = recover_with(c, Some(SID), &disk, false).unwrap();
            assert_eq!(rep.grants_pending, vec![TREE.to_string()]);
            // 42 released and pruned; 41 untouched and still registered.
            assert_eq!(rep.dead_brokers, 1);
            assert_eq!(rep.aces_revoked, 2);
            assert_eq!(counts(c), (1, 3, 3));

            let disk = Disk {
                converge: |_, p, _| {
                    if p == TREE {
                        bail!("converge failed")
                    }
                    Ok(())
                },
                ..OK_DISK
            };
            let rep = recover_with(c, Some(SID), &disk, false).unwrap();
            assert_eq!(rep.grants_pending, vec![TREE.to_string()]);
            assert_eq!(counts(c), (1, 3, 3));

            let rep = recover_with(c, Some(SID), &OK_DISK, false).unwrap();
            assert!(rep.grants_pending.is_empty());
            assert_eq!((rep.dead_brokers, rep.aces_revoked), (1, 3));
            assert_eq!(counts(c), (0, 0, 0));
        });
    }

    #[test]
    fn recovery_keeps_holderless_denies_while_any_grant_is_pending() {
        with_mem_db(|db| {
            let c = &db.conn;
            seed(c, 41, TREE, "grant", "modify");
            seed(c, 41, SECRET, "deny", "denyWrite");
            c.execute("DELETE FROM brokers", []).unwrap();
            assert_eq!(counts(c), (0, 0, 2));

            let disk = Disk {
                gate: |p, _| {
                    if p == TREE {
                        IdGate::Unreadable
                    } else {
                        IdGate::Match
                    }
                },
                ..OK_DISK
            };
            let rep = recover_with(c, Some(SID), &disk, false).unwrap();
            assert_eq!(rep.grants_pending, vec![TREE.to_string()]);
            assert_eq!(counts(c), (0, 0, 2));

            let rep = recover_with(c, Some(SID), &OK_DISK, false).unwrap();
            assert!(rep.grants_pending.is_empty());
            assert_eq!(counts(c), (0, 0, 0));
        });
    }

    #[test]
    fn deny_release_is_refused_while_the_holder_has_a_grant() {
        with_mem_db(|db| {
            let me = db.holder_pid.0 as i64;
            seed(&db.conn, me, TREE, "grant", "modify");
            seed(&db.conn, me, SECRET, "deny", "denyWrite");
            let (out, failed) = db.release_aces(SID, KIND_DENY).unwrap();
            assert_eq!(out, vec![(SECRET.to_string(), AceRelease::GrantPending)]);
            assert_eq!(failed, 0);
            assert!(out[0].1.is_pending());
            assert_eq!(out[0].1.as_str(), "grantPending");
            assert_eq!(counts(&db.conn), (1, 2, 2));
        });
    }

    #[test]
    fn forced_recovery_drops_only_a_grant_that_cannot_be_located() {
        with_mem_db(|db| {
            let c = &db.conn;
            seed(c, 41, TREE, "grant", "modify");
            seed(c, 41, SECRET, "deny", "denyWrite");
            let lost = Disk {
                gate: |p, _| {
                    if p == TREE {
                        IdGate::Mismatch
                    } else {
                        IdGate::Match
                    }
                },
                locate: |_| path_id::Located::Unknown,
                ..OK_DISK
            };
            let rep = recover_with(c, Some(SID), &lost, false).unwrap();
            assert_eq!(rep.grants_pending, vec![TREE.to_string()]);
            assert!(rep.grants_dropped.is_empty());
            assert_eq!(counts(c), (1, 2, 2));

            // A path that merely cannot be opened is not dropped.
            let closed = Disk {
                gate: |p, _| {
                    if p == TREE {
                        IdGate::Unreadable
                    } else {
                        IdGate::Match
                    }
                },
                ..OK_DISK
            };
            let rep = recover_with(c, Some(SID), &closed, true).unwrap();
            assert!(rep.grants_dropped.is_empty());
            assert_eq!(counts(c), (1, 2, 2));

            let rep = recover_with(c, Some(SID), &lost, true).unwrap();
            assert_eq!(rep.grants_dropped, vec![TREE.to_string()]);
            assert!(rep.grants_pending.is_empty());
            assert_eq!((rep.dead_brokers, rep.aces_revoked), (1, 1));
            assert_eq!(counts(c), (0, 0, 0));
        });
    }

    #[test]
    fn a_reused_pid_does_not_adopt_the_dead_brokers_holds() {
        with_mem_db(|db| {
            let me = db.holder_pid.0 as i64;
            seed(&db.conn, me, TREE, "grant", "modify");
            db.register_broker_at(7).unwrap();
            let holds_of = |pid: i64| -> i64 {
                db.conn
                    .query_row(
                        "SELECT count(*) FROM ace_holders WHERE pid = ?1",
                        params![pid],
                        |r| r.get(0),
                    )
                    .unwrap()
            };
            assert_eq!((holds_of(me), holds_of(-1)), (0, 1));
            // The same process registering again moves nothing.
            db.register_broker_at(7).unwrap();
            assert_eq!(counts(&db.conn), (2, 1, 1));
            // Recovery releases the set-aside holds whatever the probe says.
            let disk = Disk {
                alive: |_, _| true,
                ..OK_DISK
            };
            let rep = recover_with(&db.conn, Some(SID), &disk, false).unwrap();
            assert_eq!((rep.dead_brokers, rep.aces_revoked), (1, 1));
            assert_eq!(counts(&db.conn), (1, 0, 0));
        });
    }

    #[test]
    fn recovery_without_a_sandbox_identity_leaves_holds_in_place() {
        with_mem_db(|db| {
            let c = &db.conn;
            seed(c, 41, TREE, "grant", "modify");
            c.execute(
                "INSERT INTO brokers (pid, process_create_time, started_at) \
                 VALUES (43, 0, 0)",
                [],
            )
            .unwrap();
            let rep = recover_with(c, None, &OK_DISK, false).unwrap();
            // Only the hold-less dead broker is pruned.
            assert_eq!(rep.dead_brokers, 1);
            assert_eq!(counts(c), (1, 1, 1));
        });
    }
}
