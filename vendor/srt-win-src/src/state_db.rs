//! Cross-broker state DB for `srt-win acl` — refcount additive
//! sandbox-user ACEs (grant ALLOW / stamp DENY) so the LAST broker
//! to release a path can drop the ACE.
//!
//! TWO stores, split by scope and by writer:
//!
//! - SESSION store (`%LOCALAPPDATA%\sandbox-runtime\state.db`,
//!   per-user): brokers / ace_holders / working_aces. These rows
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
//! call re-derives and reapplies.
//!
//! ## One converge per path per batch
//!
//! `SetNamedSecurityInfoW` on a directory re-propagates to every
//! unprotected descendant, so a converge of a granted project root
//! costs a walk of the whole tree. One batch routinely touches the
//! same path several times — every deny target adds a `deny_fdc`
//! row on its parent, a placeholder directory carries both
//! `deny_delete` and `deny_fdc` — so the batch loops
//! ([`Locked::apply_aces`], [`release_batch`] for release and crash
//! recovery) run every per-row step exactly as before (capture,
//! guards, identity gate, row writes) and defer only the
//! [`recompose_at`] to the path's LAST touch in the batch
//! ([`last_touches`]). `recompose_at` reads the rows as they then
//! stand, so the one write lands the same DACL the last of the
//! repeated writes used to; the skipped ones were intermediate
//! states holding a subset of those rows. Record-first is
//! unaffected: a row still always precedes its write, only by more.
//!
//! The converge itself skips the write when the path's DACL is
//! already the composed one AND `converged_dacls` records that our
//! last write of exactly that DACL ran to completion
//! ([`ConvergedLedger`]). That table is the one place a row vouches
//! for disk state, and only ever toward LESS trust: it can veto a
//! skip the live DACL comparison would allow, never grant one the
//! comparison refuses, and a missing, stale or unreadable row means
//! "write".
//!
//! ## Write-intent journal
//!
//! Record-first covers a killed APPLY: the row outlives the unwritten
//! ACE. A killed RELEASE is the mirror case and rows cannot cover it:
//! release drops its `working_aces` row first and walks the tree
//! second, so a broker killed mid-propagation (the caller's timeout
//! on a large tree) leaves descendants still carrying the inherited
//! sandbox ACE with no row anywhere for recovery to find — an ALLOW
//! the next session never revokes. So every real DACL write is
//! bracketed by a `write_intents` row ([`record_write_intent`] before
//! the write, [`clear_write_intent`] once it has returned), and crash
//! recovery re-runs the converge — forced, from the rows as they now
//! stand — for each intent that survived ([`recover_write_intents`]).
//! The journal adds a breadcrumb around the propagation only; no
//! existing ordering changes.
//!
//! The journal covers a write that STARTED. A release that fails
//! before or without one — the path cannot be identified, or the
//! converge returns an error — must not lose its rows either, or the
//! ACE stays on disk with nothing recording it. So a release
//! establishes where the ACE is before it changes any row
//! ([`AceRelease::Unreadable`] changes none), and a converge that
//! returns an error has the rows of every hold it was owed for put
//! back ([`Undo`], [`AceRelease::Failed`]); the next release or
//! recovery retries.
//!
//! ## Release order: grants before denies
//!
//! A holder's DENY rows protect targets under trees its GRANT rows
//! open up, and the sandbox account is shared between sessions. So a
//! holder's deny rows are never released while one of its grants may
//! still be on disk: crash recovery releases a dead holder's grants
//! first, finishes interrupted writes second, and releases deny rows
//! last — keeping them for the next pass while a grant of the same
//! holder, or any interrupted write, is still pending
//! ([`recover_with`]).

use anyhow::{Context, Result, anyhow, bail};
use rusqlite::{Connection, OptionalExtension, params};
use std::collections::{HashMap, HashSet};
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
-- Completion record for the converge's write-skip: the DACL
-- (`acl::dacl_fingerprint`) our last COMPLETED write left on the
-- object `file_id` at this path. Deleted before every write and
-- re-inserted only after it returns, so a write killed
-- mid-propagation leaves no row and the next converge rewrites
-- (re-propagates) instead of trusting a half-walked subtree. Only
-- kept while the path carries sandbox ACEs. Additive (`IF NOT
-- EXISTS`, no schema-version bump): a binary without it neither
-- reads nor needs it.
CREATE TABLE IF NOT EXISTS converged_dacls (
  canonical_path TEXT PRIMARY KEY,
  file_id        BLOB NOT NULL,
  dacl           BLOB NOT NULL
);
-- Write-intent journal: a DACL write on the object `file_id` at this
-- path was started and has not been seen to return. Inserted before
-- every real `SetNamedSecurityInfoW` of a converge, deleted after it
-- succeeds; a surviving row is a propagation that may have been cut
-- short, which crash recovery re-runs from the then-current rows.
-- Keyed by (path, object) so a write on a substituted path cannot
-- overwrite the breadcrumb for the object that was there before.
-- Additive (`IF NOT EXISTS`, no schema-version bump).
CREATE TABLE IF NOT EXISTS write_intents (
  canonical_path TEXT NOT NULL,
  file_id        BLOB NOT NULL,
  PRIMARY KEY (canonical_path, file_id)
);
"#;

/// Outcome of a crash-recovery pass.
#[derive(Debug, Default)]
pub struct RecoveryReport {
    pub dead_brokers: u32,
    /// Orphaned `working_aces` rows whose ACE was revoked.
    pub aces_revoked: u32,
    /// Interrupted DACL writes (`write_intents` rows) whose converge
    /// was re-run to completion.
    pub writes_resumed: u32,
    /// `write_intents` rows still present after this pass (converge
    /// failed or path unreadable — retried by the next pass).
    pub writes_pending: u32,
    /// Grant paths of dead holders (or holderless rows) that could
    /// not be released this pass. Their rows — and the same holder's
    /// deny rows — are kept for the next recovery.
    pub grants_pending: Vec<String>,
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
        use std::os::windows::io::AsRawHandle;
        use windows::Win32::Storage::FileSystem::UnlockFile;
        unsafe {
            let _ = UnlockFile(HANDLE(self.file.as_raw_handle()), 0, 0, 1, 0);
        }
    }
}

impl InitMutex {
    fn acquire() -> Result<Self> {
        use std::os::windows::io::AsRawHandle;
        use windows::Win32::Storage::FileSystem::{
            LOCK_FILE_FLAGS, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY, LockFileEx,
        };
        use windows::Win32::System::IO::OVERLAPPED;
        let dir = session_store_dir()?;
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("create_dir_all {}", dir.display()))?;
        let path = dir.join(".acl-init.lock");
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            // Never truncate: the file's only role is carrying the
            // kernel byte-range lock; its content is irrelevant.
            .truncate(false)
            .open(&path)
            .with_context(|| format!("open init-lock file {}", path.display()))?;
        // Bounded, not infinite: crash-recovery under this lock is
        // sub-second and real contention is a handful of concurrent
        // acl ops for ONE user, so a minute means a wedged holder —
        // fail the op loudly rather than hang.
        const ACQUIRE_TIMEOUT_MS: u64 = 60_000;
        const POLL_MS: u64 = 100;
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_millis(ACQUIRE_TIMEOUT_MS);
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
                return Ok(Self { file });
            }
            if std::time::Instant::now() >= deadline {
                bail!(
                    "init lock {} not acquired within {ACQUIRE_TIMEOUT_MS}ms — \
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
pub const KIND_DENY: &[&str] = &["deny", "deny_fdc", "deny_delete"];
/// Filter on `release_aces` for the grant lifecycle.
pub const KIND_GRANT: &[&str] = &["grant"];

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
        let now = unix_now();
        self.conn
            .execute(
                "INSERT INTO brokers (pid, process_create_time, started_at) \
                 VALUES (?1, ?2, ?3) \
                 ON CONFLICT(pid) DO UPDATE SET \
                   process_create_time = excluded.process_create_time, \
                   started_at          = excluded.started_at",
                params![self.holder_pid.0 as i64, ct, now],
            )
            .context("INSERT brokers")?;
        Ok(())
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
            let added: Vec<(String, String)> = witnesses
                .iter()
                .filter(|w| w.holder_added)
                .map(|w| (w.canon.clone(), w.ace.kind().to_string()))
                .collect();
            // Warnings for holds that could not be rolled back come
            // from the batch; their rows stay held for a later retry.
            let _ = self.release_holds(&added, sandbox_sid);
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
    /// Every entry is recorded in order ([`Self::record_ace`]); each
    /// PATH is converged once, when its last entry in the batch has
    /// been recorded (module doc, "One converge per path per
    /// batch"). A failed converge fails every entry recorded on that
    /// path.
    ///
    /// All-or-nothing per batch (via [`Self::with_broker_registration`]).
    pub fn apply_aces(
        &self,
        sandbox_sid: &str,
        targets: &[(String, SbAce)],
    ) -> Result<(Vec<AceWitness>, usize)> {
        self.with_broker_registration(sandbox_sid, |db| {
            let plan = plan_ace_ops(targets);
            let last = last_touches(plan.iter().map(|op| op.canon.as_str()));
            // `done[i]`: op `i` recorded (and, once its path has
            // converged, written). A witness leaves its slot for the
            // caller only as `Some` — i.e. only once converged.
            let mut done: Vec<Option<AceWitness>> = Vec::new();
            done.resize_with(plan.len(), || None);
            // Recorded, converge still owed: path → op indices.
            let mut owed: HashMap<&str, Vec<usize>> = HashMap::new();
            let mut failed = 0usize;
            for (i, op) in plan.iter().enumerate() {
                let canon = op.canon.as_str();
                // Skip the parent-FDC ACE when the file's own
                // Deny failed (e.g. hardlink refuse) — the batch
                // is going to roll back anyway (`failed > 0`),
                // and stamping the parent first just to release
                // it in the same pass wastes a SetSecurityInfo
                // round-trip and clutters the failure output.
                if op.implied_by.is_none_or(|t| done[t].is_some()) {
                    match db.record_ace(canon, op.ace) {
                        Ok(w) => {
                            done[i] = Some(w);
                            owed.entry(canon).or_default().push(i);
                        }
                        Err(e) => {
                            eprintln!("srt-win: {} '{canon}': {e:#}", op.ace.kind());
                            failed += 1;
                        }
                    }
                }
                if last[i]
                    && let Some(ops) = owed.remove(canon)
                    && let Err(e) = recompose_at(&db.conn, canon, sandbox_sid)
                {
                    for k in ops {
                        eprintln!("srt-win: {} '{canon}': {e:#}", plan[k].ace.kind());
                        done[k] = None;
                        failed += 1;
                    }
                }
            }
            Ok((done.into_iter().flatten().collect(), failed))
        })
    }

    /// The record half of a single-ACE converge: capture the path's
    /// identity, run the guards, then the record-first upserts
    /// (holder row plus `working_aces` row). The caller OWES a
    /// [`recompose_at`] on `canon` before its batch ends — a crash
    /// in between leaves a row whose ACE hasn't been written; the
    /// next call re-derives and reapplies. The returned witness is
    /// only handed out of [`Self::apply_aces`] once that converge
    /// has succeeded.
    fn record_ace(&self, canon: &str, want: SbAce) -> Result<AceWitness> {
        let (cur_id, links, is_dir) = path_id::capture_id_and_links(canon)
            .with_context(|| format!("capture file_id+links '{canon}'"))?;
        // Hardlink guard: NTFS hardlinks share one SD across
        // distinct canonical paths, but `ace_holders` is
        // PATH-keyed. A Deny on one alias is invisible to a holder
        // of another — a release on the alias sees
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
        let eff = self.effective_ace(canon, want.kind())?.unwrap_or(want);
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
        Ok(AceWitness {
            canon: canon.to_string(),
            ace: eff,
            already: prior.is_some(),
            holder_added,
            _sealed: (),
        })
    }

    /// `MAX(want_mask)` across live holders of `(canon, kind)`.
    fn effective_ace(&self, canon: &str, kind: &str) -> Result<Option<SbAce>> {
        effective_ace(&self.conn, canon, kind)
    }

    /// Release this holder's `holds` — see [`release_batch`].
    fn release_holds(&self, holds: &[(String, String)], sandbox_sid: &str) -> Vec<AceRelease> {
        release_batch(
            &self.conn,
            Some(self.holder_pid.0 as i64),
            holds,
            sandbox_sid,
            &DISK,
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

    /// Release every ACE hold of `self.holder_pid` for the given
    /// `kinds` ([`KIND_GRANT`] for `acl revoke`; [`KIND_DENY`] for
    /// `acl restore --sandbox-user-sid`) and unregister if no holds
    /// of any kind remain. Per-path catch-and-continue
    /// ([`release_batch`]): a hold whose release errored is reported
    /// as [`AceRelease::Failed`] (and counted in the second tuple
    /// field); its rows are still held.
    pub fn release_aces(
        &self,
        sandbox_sid: &str,
        kinds: &[&str],
    ) -> Result<(Vec<(String, AceRelease)>, usize)> {
        let holds = self.my_ace_holds(Some(kinds))?;
        let released = self.release_holds(&holds, sandbox_sid);
        let failed = released
            .iter()
            .filter(|r| matches!(r, AceRelease::Failed))
            .count();
        let out: Vec<(String, AceRelease)> = holds
            .into_iter()
            .map(|(canon, _)| canon)
            .zip(released)
            .collect();
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
    recompose(conn, canon, sandbox_sid, false)
}

/// [`recompose_at`], optionally with the write FORCED (never skipped
/// as already-converged) — the journal recovery's form.
fn recompose(conn: &Connection, canon: &str, sandbox_sid: &str, force_write: bool) -> Result<()> {
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
    // The object the completion record must be about. Unreadable →
    // no identity → no skip (the write below reports the real error).
    let ledger = ConvergedLedger {
        conn,
        canon,
        file_id: path_id::capture_file_id(canon).ok(),
        // A path left with no sandbox ACE needs no record (and the
        // table must not grow with every path ever stamped): it is
        // withdrawn by the write and not restored.
        keep: !set.is_empty(),
        force_write,
    };
    acl::converge_sandbox_aces(canon, sandbox_sid, set, Some(&ledger))
        .with_context(|| format!("recompose '{canon}' ({set:?})"))
}

/// [`acl::WriteLedger`] over `converged_dacls` for one path — see
/// that trait for why the write-skip needs a completion record, and
/// the table comment for its lifecycle.
struct ConvergedLedger<'a> {
    conn: &'a Connection,
    canon: &'a str,
    /// The path's current identity; `None` (unreadable) never
    /// matches and is never recorded.
    file_id: Option<FileId>,
    /// Whether a completed write is worth recording.
    keep: bool,
    /// Never report completion — the write always happens.
    force_write: bool,
}

impl acl::WriteLedger for ConvergedLedger<'_> {
    fn completed(&self, dacl: &[u8]) -> bool {
        if self.force_write {
            return false;
        }
        let Some(id) = self.file_id else {
            return false;
        };
        let row: rusqlite::Result<Option<(Vec<u8>, Vec<u8>)>> = self
            .conn
            .query_row(
                "SELECT file_id, dacl FROM converged_dacls \
                 WHERE canonical_path = ?1",
                params![self.canon],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional();
        // Same object, same DACL. A read error, a malformed blob or
        // a substituted path all read as "not completed".
        matches!(row, Ok(Some((fid, was)))
            if was == dacl && FileId::from_bytes(&fid).is_ok_and(|f| f == id))
    }

    fn begin(&self) -> Result<()> {
        self.conn
            .execute(
                "DELETE FROM converged_dacls WHERE canonical_path = ?1",
                params![self.canon],
            )
            .context("DELETE converged_dacls")?;
        // Journal the write (module doc, "Write-intent journal").
        let Some(id) = self.file_id else {
            bail!(
                "'{}': file_id unreadable — cannot journal the DACL write",
                self.canon
            );
        };
        record_write_intent(self.conn, self.canon, &id)?;
        // Never on the recovery replay (`force_write`): a recovery
        // run with the variable still set must be able to finish
        // the write the hook interrupted.
        #[cfg(feature = "test-hooks")]
        if !self.force_write {
            debug_kill_before_write(self.canon);
        }
        Ok(())
    }

    fn complete(&self, dacl: &[u8]) {
        // The write returned: retire its journal row. Best-effort — a
        // row that outlives its write only costs one redundant
        // forced converge at the next recovery.
        if let Some(id) = self.file_id {
            let _ = clear_write_intent(self.conn, self.canon, &id.as_bytes());
        }
        let (true, Some(id)) = (self.keep, self.file_id) else {
            return;
        };
        // Best-effort: without the row the next converge just writes.
        let _ = self.conn.execute(
            "INSERT OR REPLACE INTO converged_dacls \
             (canonical_path, file_id, dacl) VALUES (?1, ?2, ?3)",
            params![self.canon, id.as_bytes().as_slice(), dacl],
        );
    }
}

// ─── Write-intent journal ───────────────────────────────────────────

/// Journal a DACL write about to start on the object `id` at `canon`
/// (see the `write_intents` table comment). Autocommitted before the
/// write, like every other row here; idempotent.
fn record_write_intent(conn: &Connection, canon: &str, id: &FileId) -> Result<()> {
    conn.execute(
        "INSERT OR IGNORE INTO write_intents (canonical_path, file_id) \
         VALUES (?1, ?2)",
        params![canon, id.as_bytes().as_slice()],
    )
    .with_context(|| format!("INSERT write_intents '{canon}'"))?;
    Ok(())
}

/// Retire the journal row for `(canon, id)` — its write returned, or
/// recovery has dealt with it.
fn clear_write_intent(conn: &Connection, canon: &str, id: &[u8]) -> Result<()> {
    conn.execute(
        "DELETE FROM write_intents \
         WHERE canonical_path = ?1 AND file_id = ?2",
        params![canon, id],
    )
    .with_context(|| format!("DELETE write_intents '{canon}'"))?;
    Ok(())
}

/// Test hook for the journal's smoke row — compiled ONLY under the
/// off-by-default `test-hooks` cargo feature, so no shipped broker
/// contains it. With `SANDBOX_RUNTIME_WIN_DEBUG` set AND
/// `SANDBOX_RUNTIME_WIN_DEBUG_KILL_BEFORE_DACL_WRITE` naming a path
/// suffix, exit hard (no unwinding, like a kill) right after the
/// intent row for a matching path is committed and before its DACL
/// write — the state a broker killed at the start of a propagation
/// leaves behind. Fires at most once per process (it exits) and
/// never on the recovery replay (see the call site).
#[cfg(feature = "test-hooks")]
fn debug_kill_before_write(canon: &str) {
    if std::env::var_os("SANDBOX_RUNTIME_WIN_DEBUG").is_none() {
        return;
    }
    if let Ok(suffix) = std::env::var("SANDBOX_RUNTIME_WIN_DEBUG_KILL_BEFORE_DACL_WRITE")
        && !suffix.is_empty()
        && canon
            .to_ascii_lowercase()
            .ends_with(&suffix.to_ascii_lowercase())
    {
        eprintln!("srt-win: debug: killed before dacl write '{canon}'");
        std::process::exit(86);
    }
}

/// Finish every DACL write the journal shows as started and not
/// returned: re-run the path's converge from the rows that exist NOW
/// (after a killed release: none, so the sandbox ACEs come off the
/// whole subtree), with the write forced. The row goes only once that
/// converge has returned, so a pass that is itself killed, or whose
/// converge fails, leaves it for the next one; re-running a completed
/// converge changes nothing, so the pass is idempotent.
///
/// Path-anchored and fail-closed, as release is: when `canon` is gone
/// or now names a different object the journal row is dropped and
/// nothing is touched — the moved object is NOT chased by file_id
/// (the journal does not know whether a deny was involved, and
/// converging a relocated deny target from its new path's rows would
/// strip the deny). A path that cannot be opened keeps its row for a
/// later pass unless `force` drops it.
fn recover_write_intents(
    conn: &Connection,
    sandbox_sid: &str,
    force: bool,
    disk: &Disk,
    report: &mut RecoveryReport,
) -> Result<()> {
    let intents: Vec<(String, Vec<u8>)> = query_vec(
        conn,
        "SELECT canonical_path, file_id FROM write_intents",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    for (canon, fid) in &intents {
        let gate = match FileId::from_bytes(fid) {
            Ok(want) => (disk.gate)(canon, want),
            // A malformed identity can never match anything.
            Err(_) => IdGate::Mismatch,
        };
        match gate {
            IdGate::Match => match recompose(conn, canon, sandbox_sid, true) {
                Ok(()) => {
                    clear_write_intent(conn, canon, fid)?;
                    report.writes_resumed += 1;
                }
                Err(e) => eprintln!(
                    "srt-win: interrupted DACL write '{canon}': \
                     re-converge failed ({e:#}); will retry"
                ),
            },
            IdGate::Mismatch => {
                eprintln!(
                    "srt-win: interrupted DACL write '{canon}': path \
                     is gone or names a different object; not \
                     touching it (fail-closed), dropping the journal \
                     row"
                );
                clear_write_intent(conn, canon, fid)?;
            }
            IdGate::Unreadable if force => {
                eprintln!(
                    "srt-win: interrupted DACL write '{canon}': \
                     unreadable; dropping the journal row (--force)"
                );
                clear_write_intent(conn, canon, fid)?;
            }
            IdGate::Unreadable => {} // row kept; the gate reported
        }
    }
    report.writes_pending = count_write_intents(conn)?;
    Ok(())
}

/// Journal rows outstanding — DACL writes started and not yet seen
/// to return.
fn count_write_intents(conn: &Connection) -> Result<u32> {
    conn.query_row("SELECT count(*) FROM write_intents", [], |r| r.get(0))
        .context("count write_intents")
}

/// Whether a row change still needs its path converged on disk
/// ([`recompose_at`]) by the caller — see [`release_row`].
#[derive(Debug)]
enum Converge {
    /// Rows changed and the identity gate matched; the caller must
    /// `recompose_at` the path (once per path per batch suffices),
    /// and put the rows back ([`Undo::restore`]) if that fails.
    Owed(Undo),
    /// Nothing left to do on disk at this path.
    Done,
}

/// The rows one release changed, as they were — so that a converge
/// which then returns an error does not leave the ACE on disk with
/// nothing recording it.
#[derive(Debug)]
struct Undo {
    canon: String,
    kind: String,
    file_id: Vec<u8>,
    /// `working_aces.mask` before the release.
    mask: String,
    /// The released holder row: `(pid, want_mask)`.
    holder: Option<(i64, String)>,
}

impl Undo {
    fn restore(&self, conn: &Connection) -> Result<()> {
        let tx = conn.unchecked_transaction().context("begin undo tx")?;
        tx.execute(
            "INSERT OR REPLACE INTO working_aces \
             (canonical_path, kind, file_id, mask) VALUES (?1, ?2, ?3, ?4)",
            params![self.canon, self.kind, self.file_id, self.mask],
        )
        .context("restore working_aces")?;
        if let Some((pid, want)) = &self.holder {
            tx.execute(
                "INSERT OR REPLACE INTO ace_holders \
                 (canonical_path, kind, pid, want_mask) VALUES (?1, ?2, ?3, ?4)",
                params![self.canon, self.kind, pid, want],
            )
            .context("restore ace_holders")?;
        }
        tx.commit().context("commit undo")
    }
}

/// For a batch that touches `paths[i]` at step `i`: `out[i]` is true
/// iff no LATER step touches the same path — the step after which
/// that path's deferred converge runs (module doc, "One converge per
/// path per batch"). Exactly one `true` per distinct path, so each
/// path is converged once however often the batch touches it.
/// Paths are compared as the DB keys them: exact canonical strings.
fn last_touches<'a>(paths: impl IntoIterator<Item = &'a str>) -> Vec<bool> {
    let paths: Vec<&str> = paths.into_iter().collect();
    let mut seen = HashSet::new();
    let mut last: Vec<bool> = paths.iter().rev().map(|p| seen.insert(*p)).collect();
    last.reverse();
    last
}

/// One step of an [`Locked::apply_aces`] batch.
#[derive(Debug, PartialEq, Eq)]
struct PlannedAce {
    canon: String,
    ace: SbAce,
    /// `Some(i)`: this is the parent-FDC entry implied by step `i`
    /// (a `Deny`/`DenyDelete` target) and is skipped when step `i`
    /// did not go through.
    implied_by: Option<usize>,
}

/// Expand `targets` into the batch's steps, in order: each target,
/// followed — for a `Deny`/`DenyDelete` target with a stampable
/// parent — by the implied `(parent, DenyFdc)`. Repeats are kept:
/// every step still runs its own capture, guards and upserts; only
/// the per-path converge is shared.
fn plan_ace_ops(targets: &[(String, SbAce)]) -> Vec<PlannedAce> {
    let mut plan = Vec::with_capacity(targets.len());
    for (canon, ace) in targets {
        let target = plan.len();
        plan.push(PlannedAce {
            canon: canon.clone(),
            ace: *ace,
            implied_by: None,
        });
        if matches!(ace, SbAce::Deny(_) | SbAce::DenyDelete)
            && let Some(parent) = path_id::canonical_parent_of(canon)
        {
            plan.push(PlannedAce {
                canon: parent,
                ace: SbAce::DenyFdc,
                implied_by: Some(target),
            });
        }
    }
    plan
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
    Missing,
    /// Holder row removed but no `working_aces` row found.
    NoRow,
    /// Where the ACE is now could not be established (the path could
    /// not be opened for a reason other than not-found, or a moved
    /// grant could not be located by `file_id`). Nothing was changed:
    /// the holder row and the `working_aces` row are kept, and the
    /// ACE may still be on disk.
    Unreadable,
    /// The release errored (row update or converge). The rows are as
    /// they were before it; the ACE may still be on disk.
    Failed,
}

impl AceRelease {
    /// The rows are still there and the ACE may still be on disk.
    pub fn is_pending(&self) -> bool {
        matches!(self, AceRelease::Unreadable | AceRelease::Failed)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            AceRelease::Revoked => "revoked",
            AceRelease::StillHeld => "stillHeld",
            AceRelease::Downgraded => "downgraded",
            AceRelease::Relocated { .. } => "relocated",
            AceRelease::Mismatch => "mismatch",
            AceRelease::Missing => "missing",
            AceRelease::NoRow => "noRow",
            AceRelease::Unreadable => "unreadable",
            AceRelease::Failed => "failed",
        }
    }
}

/// A `(canonical_path, kind)` pair naming one ACE row.
type Hold = (String, String);

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

/// Release `holder`'s hold on `(canon, kind)` (`None`: a row that
/// has no holder left); recompute the effective ACE from the
/// remaining holders (downgrade if this holder was the one that
/// escalated it; revoke when zero remain).
///
/// Where the ACE is now is established BEFORE any row changes. If
/// the path now resolves to a different `file_id` (or is not found),
/// the ACE on the foreign object is NOT touched — except for `grant`,
/// where the ALLOW ACE travelled with the object, so it is chased by
/// `file_id` and revoked at the moved path (before the row goes). A
/// failed open is not evidence of absence — the sandboxed process can
/// provoke one — so anything short of a positive answer returns
/// [`AceRelease::Unreadable`] with nothing changed.
///
/// The row half only: when the identity gate matches, the on-disk
/// converge of `canon` is left to the caller ([`Converge::Owed`]) so
/// a batch can run it once per path. The reported [`AceRelease`] is
/// then provisional on that converge succeeding; if it does not, the
/// caller restores the rows from the [`Undo`].
fn release_row(
    conn: &Connection,
    holder: Option<i64>,
    canon: &str,
    kind: &str,
    sandbox_sid: &str,
    disk: &Disk,
) -> Result<(AceRelease, Converge)> {
    let delete_holder = || -> Result<()> {
        if let Some(pid) = holder {
            conn.prepare_cached(
                "DELETE FROM ace_holders WHERE canonical_path = ?1 \
                 AND kind = ?2 AND pid = ?3",
            )?
            .execute(params![canon, kind, pid])
            .context("DELETE ace_holders")?;
        }
        Ok(())
    };
    let row: Option<(Vec<u8>, String)> = conn
        .prepare_cached(
            "SELECT file_id, mask FROM working_aces \
             WHERE canonical_path = ?1 AND kind = ?2",
        )?
        .query_row(params![canon, kind], |r| Ok((r.get(0)?, r.get(1)?)))
        .optional()?;
    let Some((fid, stored)) = row else {
        delete_holder()?;
        return Ok((AceRelease::NoRow, Converge::Done));
    };
    let want_id = FileId::from_bytes(&fid)?;

    enum Site {
        Here,
        Moved(String),
        Gone,
        Foreign,
    }
    let site = match (disk.gate)(canon, want_id) {
        IdGate::Match => Site::Here,
        IdGate::Unreadable => {
            eprintln!(
                "srt-win: {kind} '{canon}': open failed; ACE left \
                 in place, rows kept for retry"
            );
            return Ok((AceRelease::Unreadable, Converge::Done));
        }
        // The granted object moved (or its path was swapped). The
        // ALLOW ACE travels with the object → the sandbox user still
        // has access at the new path. Chase by file_id and revoke
        // there (then re-converge if the new path happens to be
        // tracked too).
        IdGate::Mismatch if kind == "grant" => match (disk.locate)(&want_id) {
            path_id::Located::At(at) => Site::Moved(at),
            path_id::Located::Gone => Site::Gone,
            path_id::Located::Unknown => {
                eprintln!(
                    "srt-win: grant '{canon}': not at its path and \
                     could not be located by file_id; ACE may \
                     still be on disk, rows kept for retry"
                );
                return Ok((AceRelease::Unreadable, Converge::Done));
            }
        },
        // DENY/FDC are left in place on the moved object
        // (fail-closed).
        IdGate::Mismatch => Site::Foreign,
    };
    // A relocated grant is converged here, at the path it moved to —
    // whose rows this release does not touch — and before the row
    // goes, so an error leaves the row for a retry.
    if let Site::Moved(at) = &site {
        eprintln!(
            "srt-win: grant '{canon}': file_id moved to '{at}'; \
             revoking there"
        );
        (disk.converge)(conn, at, sandbox_sid)?;
    }

    let held: Option<(i64, String)> = match holder {
        Some(pid) => conn
            .prepare_cached(
                "SELECT want_mask FROM ace_holders WHERE canonical_path = ?1 \
                 AND kind = ?2 AND pid = ?3",
            )?
            .query_row(params![canon, kind, pid], |r| r.get(0))
            .optional()?
            .map(|want| (pid, want)),
        None => None,
    };
    delete_holder()?;
    let new_eff = effective_ace(conn, canon, kind)?;
    match new_eff {
        Some(e) => conn
            .execute(
                "UPDATE working_aces SET mask = ?3 \
                 WHERE canonical_path = ?1 AND kind = ?2",
                params![canon, kind, e.as_str()],
            )
            .context("UPDATE working_aces (downgrade)")?,
        None => conn
            .execute(
                "DELETE FROM working_aces \
                 WHERE canonical_path = ?1 AND kind = ?2",
                params![canon, kind],
            )
            .context("DELETE working_aces")?,
    };
    Ok(match site {
        Site::Here => (
            match new_eff {
                Some(e) if e.as_str() == stored => AceRelease::StillHeld,
                Some(_) => AceRelease::Downgraded,
                None => AceRelease::Revoked,
            },
            Converge::Owed(Undo {
                canon: canon.to_string(),
                kind: kind.to_string(),
                file_id: fid,
                mask: stored,
                holder: held,
            }),
        ),
        Site::Moved(at) => (AceRelease::Relocated { moved_to: at }, Converge::Done),
        Site::Gone => {
            eprintln!(
                "srt-win: grant '{canon}': path and file_id both \
                 gone; dropping row"
            );
            (AceRelease::Missing, Converge::Done)
        }
        Site::Foreign => {
            eprintln!(
                "srt-win: {kind} '{canon}': file_id mismatch — \
                 path substituted; not touching ACE on the \
                 foreign object (fail-closed)"
            );
            (AceRelease::Mismatch, Converge::Done)
        }
    })
}

/// Release `holds` of `holder` (`None`: rows with no holder left), one
/// outcome per hold, in order.
///
/// Every hold's rows are released in order ([`release_row`], identity
/// gate included); each PATH is converged once, after its last hold in
/// the batch (module doc, "One converge per path per batch"). A failed
/// converge fails every hold released on that path: their rows are
/// put back and they are reported [`AceRelease::Failed`], as is a
/// hold whose row step errored.
fn release_batch(
    conn: &Connection,
    holder: Option<i64>,
    holds: &[(String, String)],
    sandbox_sid: &str,
    disk: &Disk,
) -> Vec<AceRelease> {
    let last = last_touches(holds.iter().map(|(canon, _)| canon.as_str()));
    let mut released: Vec<AceRelease> = Vec::with_capacity(holds.len());
    // Rows released, converge still owed: path → (hold index, undo).
    let mut owed: HashMap<&str, Vec<(usize, Undo)>> = HashMap::new();
    let warn = |kind: &str, canon: &str, e: &anyhow::Error| {
        eprintln!(
            "srt-win: WARNING: release {kind} '{canon}': \
             {e:#}; ACE left in place, rows kept for retry"
        );
    };
    for (i, (canon, kind)) in holds.iter().enumerate() {
        released.push(
            match release_row(conn, holder, canon, kind, sandbox_sid, disk) {
                Ok((r, Converge::Owed(undo))) => {
                    owed.entry(canon.as_str()).or_default().push((i, undo));
                    r
                }
                Ok((r, Converge::Done)) => r,
                Err(e) => {
                    warn(kind, canon, &e);
                    AceRelease::Failed
                }
            },
        );
        if last[i]
            && let Some(rows) = owed.remove(canon.as_str())
            && let Err(e) = (disk.converge)(conn, canon, sandbox_sid)
        {
            for (k, undo) in rows.into_iter().rev() {
                warn(&holds[k].1, canon, &e);
                if let Err(u) = undo.restore(conn) {
                    eprintln!(
                        "srt-win: WARNING: release {} '{canon}': could \
                         not put its rows back ({u:#}); the ACE is no \
                         longer recorded",
                        holds[k].1
                    );
                }
                released[k] = AceRelease::Failed;
            }
        }
    }
    released
}

/// Release the holds of dead brokers, then prune them. `force` drops
/// journal rows whose path cannot be opened
/// ([`recover_write_intents`]).
fn crash_recovery(conn: &Connection, force: bool) -> Result<RecoveryReport> {
    // Identity comes from the VALIDATED machine-store read (name↔SID
    // + sandbox-group membership against SAM), never from raw rows:
    // the session DB is user-writable, and this SID is about to be
    // written into DACLs. No valid identity → no disk work (the
    // session rows stay put for a later recovery).
    let sb = crate::install::read_setup()?.map(|s| s.sandbox_user_sid);
    recover_with(conn, sb.as_deref(), force, &DISK)
}

/// Release `holds` for recovery ([`release_batch`]) and account for
/// them in `report`. Returns whether every one was released.
fn recover_batch(
    conn: &Connection,
    holder: Option<i64>,
    holds: &[(String, String)],
    sb: &str,
    disk: &Disk,
    report: &mut RecoveryReport,
) -> bool {
    let mut all = true;
    let released = release_batch(conn, holder, holds, sb, disk);
    for ((canon, kind), r) in holds.iter().zip(released) {
        if r.is_pending() {
            all = false;
            if kind == "grant" {
                report.grants_pending.push(canon.clone());
            }
        } else if !matches!(
            r,
            AceRelease::StillHeld | AceRelease::Downgraded | AceRelease::NoRow
        ) {
            report.aces_revoked += 1;
        }
    }
    all
}

/// Crash recovery proper, with the sandbox identity and the disk
/// probes passed in.
///
/// Order (module doc, "Release order: grants before denies"):
///
/// 1. Each dead broker's GRANT holds, while its holder rows still say
///    whose they are — deleting the broker first would CASCADE them
///    away and leave no way to tell which deny rows belong with which
///    grants.
/// 2. Holderless GRANT rows (a holder row lost without its release).
/// 3. Interrupted DACL writes (module doc, "Write-intent journal"). A
///    converge in steps 1–2 that completes on a journaled path
///    retires that journal row itself.
/// 4. The deny, deny-delete and parent delete-child rows — of a dead
///    broker only if every one of its grants was released, of no
///    holder only if no grant at all is pending, and of nobody while
///    an interrupted write is still pending (the journal does not say
///    whose write it was, or whether it was taking a grant off).
/// 5. Prune every dead broker that holds nothing any more. One with a
///    hold that could not be released stays, dead, for the next pass.
///
/// Each hold's rows and converge are committed independently, so a
/// failure on path Y leaves path X's release durable. A path carrying
/// both a grant and a deny row is converged in step 1 and again in
/// step 4.
fn recover_with(
    conn: &Connection,
    sb: Option<&str>,
    force: bool,
    disk: &Disk,
) -> Result<RecoveryReport> {
    let mut report = RecoveryReport::default();
    let is_grant = |(_, kind): &(String, String)| kind == "grant";

    let dead: Vec<i64> = query_vec(
        conn,
        "SELECT pid, process_create_time FROM brokers",
        [],
        |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)),
    )?
    .into_iter()
    .filter(|&(pid, ct)| !(disk.alive)(pid as u32, ct))
    .map(|(pid, _)| pid)
    .collect();

    if let Some(sb) = sb {
        // Deny rows whose release waits on step 3: (holder, rows).
        let mut denies: Vec<(Option<i64>, Vec<Hold>)> = Vec::new();
        // 1.
        for &pid in &dead {
            let holds: Vec<(String, String)> = query_vec(
                conn,
                "SELECT canonical_path, kind FROM ace_holders \
                 WHERE pid = ?1 ORDER BY canonical_path, kind",
                params![pid],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            let (grants, others): (Vec<_>, Vec<_>) = holds.into_iter().partition(is_grant);
            if recover_batch(conn, Some(pid), &grants, sb, disk, &mut report) {
                denies.push((Some(pid), others));
            } else {
                eprintln!(
                    "srt-win: WARNING: recovery could not release \
                     every grant of dead holder {pid}; keeping its {} \
                     deny row(s) until it can",
                    others.len()
                );
            }
        }
        // 2.
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
        let (grants, others): (Vec<_>, Vec<_>) = orphans.into_iter().partition(is_grant);
        recover_batch(conn, None, &grants, sb, disk, &mut report);
        if report.grants_pending.is_empty() {
            denies.push((None, others));
        } else if !others.is_empty() {
            eprintln!(
                "srt-win: WARNING: a grant is still pending; keeping \
                 {} holderless deny row(s) until it is released",
                others.len()
            );
        }
        // 3. The table is empty unless a write was cut short.
        report.writes_pending = count_write_intents(conn)?;
        if report.writes_pending > 0 {
            recover_write_intents(conn, sb, force, disk, &mut report)?;
        }
        // 4.
        if report.writes_pending > 0 {
            eprintln!(
                "srt-win: WARNING: {} interrupted DACL write(s) still \
                 pending; keeping dead holders' deny rows until they \
                 finish",
                report.writes_pending
            );
        } else {
            for (holder, rows) in &denies {
                recover_batch(conn, *holder, rows, sb, disk, &mut report);
            }
        }
    } else {
        report.writes_pending = count_write_intents(conn)?;
    }

    // 5.
    for pid in dead {
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
    Ok(report)
}

enum IdGate {
    Match,
    Mismatch,
    Unreadable,
}

/// `(path, file_id)` identity check. `path` not found
/// (ERROR_FILE/PATH_NOT_FOUND) or different inode → `Mismatch`;
/// any other open error → `Unreadable` (retryable, not a
/// mismatch). `Mismatch` says only that the recorded object is not
/// at `path` — renaming an ancestor or swapping a component produces
/// it while the object, and its ACE, live on elsewhere.
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
            // Two holds via direct INSERT (record_ace needs a real
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

    /// Exactly one converge per distinct path, placed at the path's
    /// final touch — so it sees every row the batch recorded there.
    #[test]
    fn last_touches_marks_one_final_touch_per_path() {
        assert_eq!(last_touches([]), Vec::<bool>::new());
        assert_eq!(last_touches(["a"]), [true]);
        // root touched three times (grant-root FDC from two denied
        // children + a placeholder): only the third converges it.
        assert_eq!(
            last_touches(["f1", "root", "f2", "root", "ph", "root"]),
            [true, false, true, false, true, true],
        );
        // Exact-string identity, as the DB keys paths.
        assert_eq!(last_touches(["A", "a", "A"]), [false, true, true]);
        for seq in [vec!["x", "y", "x", "z", "y", "x"], vec!["p"; 5]] {
            let last = last_touches(seq.iter().copied());
            let distinct: HashSet<&str> = seq.iter().copied().collect();
            assert_eq!(last.iter().filter(|l| **l).count(), distinct.len());
            for (i, p) in seq.iter().enumerate() {
                assert_eq!(last[i], !seq[i + 1..].contains(p), "step {i}");
            }
        }
    }

    /// Batch composition for the session-init shape: a root-level
    /// deny plus a deny under a placeholder directory. The root is
    /// touched twice (parent-FDC of the deny, parent-FDC of the
    /// placeholder) but is converged once, last — after every row
    /// destined for it has been recorded.
    #[test]
    fn plan_ace_ops_implies_parent_fdc_and_coalesces_root() {
        use acl::{DenyMask, GrantMask};
        let root = r"\\?\C:\proj";
        let p = |rel: &str| format!(r"{root}\{rel}");
        let deny = SbAce::Deny(DenyMask::WriteDeny);
        let targets = vec![
            (p(r".claude\settings.json"), deny),
            (p(".claude"), SbAce::DenyDelete),
            (p(".mcp.json"), deny),
            (root.to_string(), SbAce::Grant(GrantMask::Modify)),
        ];
        let plan = plan_ace_ops(&targets);
        let step = |canon: String, ace, implied_by| PlannedAce {
            canon,
            ace,
            implied_by,
        };
        assert_eq!(
            plan,
            [
                step(p(r".claude\settings.json"), deny, None),
                step(p(".claude"), SbAce::DenyFdc, Some(0)),
                step(p(".claude"), SbAce::DenyDelete, None),
                step(root.to_string(), SbAce::DenyFdc, Some(2)),
                step(p(".mcp.json"), deny, None),
                step(root.to_string(), SbAce::DenyFdc, Some(4)),
                // A grant implies no parent entry.
                step(root.to_string(), SbAce::Grant(GrantMask::Modify), None),
            ],
        );
        let last = last_touches(plan.iter().map(|op| op.canon.as_str()));
        assert_eq!(last, [true, false, true, false, true, false, true]);
        // A top-level deny target has no stampable parent.
        let top = plan_ace_ops(&[(r"\\?\C:\x".to_string(), deny)]);
        assert_eq!(top.len(), 1);
    }

    /// The completion record vouches for one (path, object, DACL)
    /// triple, is withdrawn by `begin`, and is not kept for a path
    /// left without sandbox ACEs.
    #[test]
    fn converged_ledger_records_only_completed_writes() {
        use acl::WriteLedger;
        with_mem_db(|db| {
            let id = |n: u8| FileId {
                volume_serial: 7,
                id128: [n; 16],
            };
            let ledger = |canon, n, keep| ConvergedLedger {
                conn: &db.conn,
                canon,
                file_id: Some(id(n)),
                keep,
                force_write: false,
            };
            let (a, b) = (r"\\?\C:\a", r"\\?\C:\b");
            let l = ledger(a, 1, true);
            assert!(!l.completed(b"X"), "no record yet");
            l.begin().unwrap();
            assert!(!l.completed(b"X"), "begun, not completed");
            l.complete(b"X");
            assert!(l.completed(b"X"));
            // Another DACL, another object at the path, another
            // path, or an unreadable identity: not completed.
            assert!(!l.completed(b"Y"));
            assert!(!ledger(a, 2, true).completed(b"X"));
            assert!(!ledger(b, 1, true).completed(b"X"));
            let blind = ConvergedLedger {
                file_id: None,
                ..ledger(a, 1, true)
            };
            assert!(!blind.completed(b"X"));
            // The next write withdraws it; killed before `complete`,
            // it stays withdrawn.
            l.begin().unwrap();
            assert!(!l.completed(b"X"));
            // A converge to "no sandbox ACEs" leaves no row behind.
            l.complete(b"X");
            let gone = ledger(a, 1, false);
            gone.begin().unwrap();
            gone.complete(b"Z");
            assert!(!gone.completed(b"Z") && !l.completed(b"X"));
            blind.complete(b"X");
            assert!(!l.completed(b"X"), "no identity → nothing recorded");
            let rows: i64 = db
                .conn
                .query_row("SELECT count(*) FROM converged_dacls", [], |r| r.get(0))
                .unwrap();
            assert_eq!(rows, 0);
        });
    }

    fn intents(db: &Locked) -> Vec<(String, Vec<u8>)> {
        query_vec(
            &db.conn,
            "SELECT canonical_path, file_id FROM write_intents \
             ORDER BY canonical_path, file_id",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap()
    }

    /// Journal bookkeeping: the row appears at `begin`, survives
    /// until `complete`, is keyed by (path, object), and a forced
    /// ledger never reports completion.
    #[test]
    fn write_intent_brackets_the_write() {
        use acl::WriteLedger;
        with_mem_db(|db| {
            let id = |n: u8| FileId {
                volume_serial: 7,
                id128: [n; 16],
            };
            let ledger = |n, keep, force_write| ConvergedLedger {
                conn: &db.conn,
                canon: r"\\?\C:\a",
                file_id: Some(id(n)),
                keep,
                force_write,
            };
            assert!(intents(db).is_empty());
            // A release-to-empty write (`keep: false`): journaled all
            // the same — it is the case rows cannot cover.
            let l = ledger(1, false, false);
            l.begin().unwrap();
            l.begin().unwrap(); // idempotent
            assert_eq!(
                intents(db),
                [(r"\\?\C:\a".to_string(), id(1).as_bytes().to_vec())],
                "killed here → the intent is what recovery finds",
            );
            // Another object at the same path journals separately and
            // its completion does not retire the first row.
            let other = ledger(2, true, false);
            other.begin().unwrap();
            assert_eq!(intents(db).len(), 2);
            other.complete(b"X");
            assert_eq!(intents(db).len(), 1);
            l.complete(b"");
            assert!(intents(db).is_empty(), "write returned → row retired");
            // Forced: a matching completion record does not count.
            assert!(other.completed(b"X"));
            assert!(!ledger(2, true, true).completed(b"X"));
            // No identity → no journal row possible → no write.
            let blind = ConvergedLedger {
                file_id: None,
                ..ledger(1, true, false)
            };
            assert!(blind.begin().is_err());
        });
    }

    /// Recovery over real paths: a surviving intent on a live
    /// directory is re-converged from the (empty) rows — stripping
    /// the sandbox ACE a killed release left — and retired; an intent
    /// whose path is gone or substituted is dropped untouched; a
    /// second pass finds nothing.
    #[test]
    fn recover_write_intents_finishes_a_killed_release() {
        const FAKE_SB_SID: &str = "S-1-5-32-546";
        let dir = std::env::temp_dir().join(format!("srtwin-intent-{}", std::process::id()));
        let (live, swapped) = (dir.join("live"), dir.join("swapped"));
        std::fs::create_dir_all(&live).unwrap();
        std::fs::create_dir_all(&swapped).unwrap();
        let canon =
            |p: &std::path::Path| path_id::canonicalize_path(p.to_str().unwrap()).unwrap().0;
        let (live, swapped) = (canon(&live), canon(&swapped));
        let gone = format!(r"{live}\never-existed");
        let grant = acl::SbAceSet {
            grant: Some(acl::GrantMask::Modify),
            ..Default::default()
        };
        // The killed release's residue: ACE on disk, no row.
        acl::apply_sandbox_aces(&live, FAKE_SB_SID, grant).unwrap();
        acl::apply_sandbox_aces(&swapped, FAKE_SB_SID, grant).unwrap();
        let sid = crate::sid::sid_bytes(FAKE_SB_SID).unwrap();
        // Any EXPLICIT ACE for the stand-in sandbox SID on `p`.
        let has_ace = |p: &str| {
            let (_sd, dacl) = acl::read_file_dacl(p).unwrap();
            let (explicit, ..) = acl::filter_aces(dacl, |hdr, body| {
                hdr.AceFlags & 0x10 == 0 && acl::ace_sid_is(body, &sid)
            })
            .unwrap();
            !explicit.is_empty()
        };
        assert!(has_ace(&live) && has_ace(&swapped));
        with_mem_db(|db| {
            let live_id = path_id::capture_file_id(&live).unwrap();
            record_write_intent(&db.conn, &live, &live_id).unwrap();
            // `swapped` journaled under another object's identity;
            // `gone` does not exist.
            record_write_intent(&db.conn, &swapped, &live_id).unwrap();
            record_write_intent(&db.conn, &gone, &live_id).unwrap();

            let mut report = RecoveryReport::default();
            recover_write_intents(&db.conn, FAKE_SB_SID, false, &DISK, &mut report).unwrap();
            assert_eq!((report.writes_resumed, report.writes_pending), (1, 0));
            assert!(intents(db).is_empty());
            assert!(!has_ace(&live), "interrupted release finished");
            assert!(has_ace(&swapped), "substituted path not touched");

            let mut again = RecoveryReport::default();
            recover_write_intents(&db.conn, FAKE_SB_SID, false, &DISK, &mut again).unwrap();
            assert_eq!((again.writes_resumed, again.writes_pending), (0, 0));
        });
        acl::apply_sandbox_aces(&swapped, FAKE_SB_SID, acl::SbAceSet::default()).unwrap();
        std::fs::remove_dir_all(&dir).ok();
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
                                  'placeholders','converged_dacls', \
                                  'write_intents','sandbox_user')",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(
                n, 6,
                "session schema: 6 bookkeeping tables, no sandbox_user"
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

    // ── Release / recovery bookkeeping, with the disk side faked ──

    const TREE: &str = r"\\?\C:\tree";
    const SECRET: &str = r"\\?\C:\tree\secret";
    const SID: &str = "S-1-5-21-1";

    /// Every probe answers "all good": the object is at its path,
    /// the converge succeeds, every broker is dead.
    const OK_DISK: Disk = Disk {
        gate: |_, _| IdGate::Match,
        locate: |_| path_id::Located::Gone,
        converge: |_, _, _| Ok(()),
        alive: |_, _| false,
    };
    const TREE_UNREADABLE: Disk = Disk {
        gate: |p, _| {
            if p == TREE {
                IdGate::Unreadable
            } else {
                IdGate::Match
            }
        },
        ..OK_DISK
    };

    /// One hold of `pid` on `(canon, kind)`, with its broker and
    /// working row.
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

    fn hold(canon: &str, kind: &str) -> (String, String) {
        (canon.to_string(), kind.to_string())
    }

    #[test]
    fn unreadable_release_changes_nothing() {
        with_mem_db(|db| {
            let me = db.holder_pid.0 as i64;
            seed(&db.conn, me, TREE, "grant", "modify");
            let holds = [hold(TREE, "grant")];
            let r = release_batch(&db.conn, Some(me), &holds, SID, &TREE_UNREADABLE);
            assert_eq!(r, [AceRelease::Unreadable]);
            assert_eq!(r[0].as_str(), "unreadable");
            assert_eq!(counts(&db.conn), (1, 1, 1));
            // Readable again → the same hold releases.
            let r = release_batch(&db.conn, Some(me), &holds, SID, &OK_DISK);
            assert_eq!(r, [AceRelease::Revoked]);
            assert_eq!(counts(&db.conn), (1, 0, 0));
        });
    }

    #[test]
    fn failed_converge_puts_the_rows_back() {
        with_mem_db(|db| {
            let c = &db.conn;
            let me = db.holder_pid.0 as i64;
            // A wider holder (me) and a narrower one on the grant,
            // plus two deny kinds that share one path's converge.
            seed(c, 7, TREE, "grant", "read");
            seed(c, me, TREE, "grant", "modify");
            seed(c, me, SECRET, "deny_delete", "delete");
            seed(c, me, SECRET, "deny_fdc", "fdc");
            let rows = |c: &Connection| -> Vec<(String, String, i64, String, String)> {
                query_vec(
                    c,
                    "SELECT h.canonical_path, h.kind, h.pid, h.want_mask, w.mask \
                     FROM ace_holders h JOIN working_aces w \
                       ON w.canonical_path = h.canonical_path AND w.kind = h.kind \
                     ORDER BY 1, 2, 3",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
                )
                .unwrap()
            };
            let before = rows(c);
            let disk = Disk {
                converge: |_, _, _| bail!("SetNamedSecurityInfoW failed"),
                ..OK_DISK
            };
            let holds = [
                hold(SECRET, "deny_delete"),
                hold(TREE, "grant"),
                hold(SECRET, "deny_fdc"),
            ];
            let r = release_batch(c, Some(me), &holds, SID, &disk);
            assert_eq!(
                r,
                [AceRelease::Failed, AceRelease::Failed, AceRelease::Failed]
            );
            assert_eq!(rows(c), before);
            // And once the converge works, the same holds release.
            let r = release_batch(c, Some(me), &holds, SID, &OK_DISK);
            assert_eq!(
                r,
                [
                    AceRelease::Revoked,
                    AceRelease::Downgraded,
                    AceRelease::Revoked
                ]
            );
            assert_eq!(counts(c), (2, 1, 1));
        });
    }

    #[test]
    fn moved_grant_is_missing_only_when_positively_gone() {
        with_mem_db(|db| {
            let me = db.holder_pid.0 as i64;
            seed(&db.conn, me, TREE, "grant", "modify");
            let holds = [hold(TREE, "grant")];
            // Not at its path, and the chase by file id could not
            // answer: the ACE may be anywhere → keep the rows.
            let disk = Disk {
                gate: |_, _| IdGate::Mismatch,
                locate: |_| path_id::Located::Unknown,
                ..OK_DISK
            };
            let r = release_batch(&db.conn, Some(me), &holds, SID, &disk);
            assert_eq!(r, [AceRelease::Unreadable]);
            assert_eq!(counts(&db.conn), (1, 1, 1));
            // Found elsewhere but the revoke there fails → rows kept.
            let disk = Disk {
                gate: |_, _| IdGate::Mismatch,
                locate: |_| path_id::Located::At(r"\\?\C:\moved".into()),
                converge: |_, _, _| bail!("converge failed"),
                ..OK_DISK
            };
            let r = release_batch(&db.conn, Some(me), &holds, SID, &disk);
            assert_eq!(r, [AceRelease::Failed]);
            assert_eq!(counts(&db.conn), (1, 1, 1));
            // The volume says no such file → gone, row dropped.
            let disk = Disk {
                gate: |_, _| IdGate::Mismatch,
                ..OK_DISK
            };
            let r = release_batch(&db.conn, Some(me), &holds, SID, &disk);
            assert_eq!(r, [AceRelease::Missing]);
            assert_eq!(counts(&db.conn), (1, 0, 0));
        });
    }

    #[test]
    fn recovery_keeps_a_holders_denies_while_its_grant_is_pending() {
        with_mem_db(|db| {
            let c = &db.conn;
            // Dead holder 41: grant on TREE, deny stamps under it.
            seed(c, 41, TREE, "grant", "modify");
            seed(c, 41, SECRET, "deny", "denyWrite");
            seed(c, 41, TREE, "deny_fdc", "fdc");
            // Dead holder 42: its own grant and deny, both releasable.
            seed(c, 42, r"\\?\C:\other", "grant", "read");
            seed(c, 42, r"\\?\C:\other\x", "deny", "denyRead");

            let rep = recover_with(c, Some(SID), false, &TREE_UNREADABLE).unwrap();
            assert_eq!(rep.grants_pending, vec![TREE.to_string()]);
            // 42 fully released and pruned; 41 untouched, still
            // registered so the next pass knows whose rows these are.
            assert_eq!(rep.dead_brokers, 1);
            assert_eq!(rep.aces_revoked, 2);
            assert_eq!(counts(c), (1, 3, 3));

            // Converge error on the grant: same outcome.
            let disk = Disk {
                converge: |_, p, _| {
                    if p == TREE {
                        bail!("converge failed")
                    }
                    Ok(())
                },
                ..OK_DISK
            };
            let rep = recover_with(c, Some(SID), false, &disk).unwrap();
            assert_eq!(rep.grants_pending, vec![TREE.to_string()]);
            assert_eq!(counts(c), (1, 3, 3));

            // Releasable → grant first, then the denies, then prune.
            let rep = recover_with(c, Some(SID), false, &OK_DISK).unwrap();
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
            // Holder rows lost without a release.
            c.execute("DELETE FROM brokers", []).unwrap();
            assert_eq!(counts(c), (0, 0, 2));

            let rep = recover_with(c, Some(SID), false, &TREE_UNREADABLE).unwrap();
            assert_eq!(rep.grants_pending, vec![TREE.to_string()]);
            assert_eq!(counts(c), (0, 0, 2));

            let rep = recover_with(c, Some(SID), false, &OK_DISK).unwrap();
            assert!(rep.grants_pending.is_empty());
            assert_eq!(counts(c), (0, 0, 0));
        });
    }

    #[test]
    fn recovery_keeps_denies_while_an_interrupted_write_is_pending() {
        with_mem_db(|db| {
            let c = &db.conn;
            // The killed grant release's residue: its rows are gone,
            // the journal row is not — and the path cannot be opened.
            record_write_intent(c, TREE, &FileId::from_bytes(&[0u8; 24]).unwrap()).unwrap();
            seed(c, 41, SECRET, "deny", "denyWrite");

            let rep = recover_with(c, Some(SID), false, &TREE_UNREADABLE).unwrap();
            assert_eq!(rep.writes_pending, 1);
            assert_eq!((rep.dead_brokers, rep.aces_revoked), (0, 0));
            assert_eq!(counts(c), (1, 1, 1));

            // Journal row dealt with → the deny goes.
            clear_write_intent(c, TREE, &[0u8; 24]).unwrap();
            let rep = recover_with(c, Some(SID), false, &OK_DISK).unwrap();
            assert_eq!((rep.dead_brokers, rep.aces_revoked), (1, 1));
            assert_eq!(counts(c), (0, 0, 0));
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
            let rep = recover_with(c, None, false, &OK_DISK).unwrap();
            // The hold-less dead broker is pruned; the one with a
            // hold stays until its ACE can be released.
            assert_eq!(rep.dead_brokers, 1);
            assert_eq!(counts(c), (1, 1, 1));
        });
    }
}
