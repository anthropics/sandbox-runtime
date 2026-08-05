//! Cross-broker state DB for `srt-win acl` — refcount additive
//! sandbox-user ACEs (grant ALLOW / stamp DENY) so the LAST broker
//! to release a path can drop the ACE.
//!
//! Lives at `%LOCALAPPDATA%\sandbox-runtime\state.db` (rusqlite,
//! WAL). The directory is ACL-stamped real-user-only `(OI)(CI)` on
//! every open so the sandbox child cannot tamper with the refcount.
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
//! Every `acl stamp|grant|restore|revoke|recover` runs under a
//! single named mutex `Local\sandbox-runtime-acl-init`
//! (real-user-only DACL). The mutex — NOT a DB transaction —
//! serializes whole operations across brokers; `WAIT_ABANDONED`
//! tells us the previous holder died mid-op (crash-recovery
//! already runs unconditionally).
//!
//! There is deliberately NO single enclosing transaction. Each
//! path's (FS mutation + row change) commits independently so a
//! failure on path Y can't revert path X. The one ordering rule is
//! record-first: upsert, THEN `SetNamedSecurityInfoW`. A crash
//! between leaves a row whose ACE hasn't been written; the next
//! call re-derives and reapplies.

use anyhow::{Context, Result, anyhow, bail};
use rusqlite::{Connection, OptionalExtension, params};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use windows::Win32::Foundation::{CloseHandle, FILETIME, HANDLE, WAIT_ABANDONED, WAIT_OBJECT_0};
use windows::Win32::System::Threading::{
    CreateMutexExW, GetCurrentProcess, GetProcessTimes, INFINITE, MUTEX_ALL_ACCESS, OpenProcess,
    PROCESS_QUERY_LIMITED_INFORMATION, ReleaseMutex, WaitForSingleObject,
};

use crate::acl::{self, SbAce};
use crate::path_id::{self, FileId};
use crate::util::{pcwstr, wstr};

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

/// `Local\` = per–Terminal-Services-session namespace. Brokers for
/// the SAME user in DIFFERENT TS sessions share the state DB
/// (`%LOCALAPPDATA%`) but NOT this mutex — they would not exclude
/// each other. `Global\` would, but creating it requires
/// `SeCreateGlobalPrivilege`, which an unelevated broker may lack.
/// The cross-session same-user case is rare enough that we accept
/// the limitation for v1; revisit if a real use case appears.
const MUTEX_NAME: &str = r"Local\sandbox-runtime-acl-init";
const SCHEMA_VERSION: i64 = 7;

const SCHEMA_SQL: &str = r#"
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
-- Install-time setup record: the sandbox user's DPAPI-encrypted
-- credential plus the setup marker. One row per provisioned
-- sandbox user (currently exactly one). Additive table — no
-- schema-version bump.
CREATE TABLE IF NOT EXISTS sandbox_user (
  username        TEXT    PRIMARY KEY,
  user_sid        TEXT    NOT NULL,
  group_sid       TEXT    NOT NULL,
  cred            BLOB    NOT NULL,
  marker_version  INTEGER NOT NULL,
  created_at_unix INTEGER NOT NULL,
  -- DER-encoded MITM CA certificate (`srt-win user trust-ca`).
  -- NULL when no CA was installed. Persisted so `user status` can
  -- surface the thumbprint + PEM to the host's tlsTerminate setup
  -- without it having to re-read the original file.
  ca_cert         BLOB
);
"#;

/// Outcome of a crash-recovery pass.
#[derive(Debug, Default)]
pub struct RecoveryReport {
    pub dead_brokers: u32,
    /// Orphaned `working_aces` rows whose ACE was revoked.
    pub aces_revoked: u32,
}

/// RAII guard for the init mutex. Releases on drop. The mutex
/// HANDLE itself is closed too — `CreateMutexExW` returns a fresh
/// handle every call (with `ERROR_ALREADY_EXISTS` set if the kernel
/// object already existed), so each `acquire` owns its own handle.
struct InitMutex {
    h: HANDLE,
}
impl Drop for InitMutex {
    fn drop(&mut self) {
        unsafe {
            let _ = ReleaseMutex(self.h);
            let _ = CloseHandle(self.h);
        }
    }
}

impl InitMutex {
    /// Create-or-open and acquire the init mutex. The mutex carries
    /// a real-user-only DACL so a sandbox child cannot open it (and
    /// therefore cannot stall stamps by sitting on the lock).
    fn acquire() -> Result<Self> {
        let sa = acl::build_init_mutex_sa().context("build init-mutex SECURITY_ATTRIBUTES")?;
        let name = wstr(MUTEX_NAME);
        // Don't request CREATE_MUTEX_INITIAL_OWNER — if another
        // broker already created the mutex this call opens it,
        // and INITIAL_OWNER would silently NOT acquire in that
        // case. A separate Wait gives a uniform code path and
        // surfaces WAIT_ABANDONED.
        let h = unsafe {
            CreateMutexExW(
                Some(sa.as_ptr()),
                pcwstr(&name),
                0, // dwFlags — no CREATE_MUTEX_INITIAL_OWNER
                MUTEX_ALL_ACCESS.0,
            )
        }
        .with_context(|| format!("CreateMutexExW({MUTEX_NAME})"))?;
        // `sa` can drop now — the kernel object owns its SD.

        let r = unsafe { WaitForSingleObject(h, INFINITE) };
        match r {
            WAIT_OBJECT_0 => {}
            WAIT_ABANDONED => {
                // Previous holder died while owning the mutex. We
                // now own it. Crash-recovery (which the caller will
                // run next) handles the cleanup; nothing extra here.
                eprintln!(
                    "srt-win: init-mutex WAIT_ABANDONED — previous \
                     `srt-win acl` died mid-operation; running recovery"
                );
            }
            other => {
                let err = std::io::Error::last_os_error();
                unsafe {
                    let _ = CloseHandle(h);
                }
                bail!(
                    "WaitForSingleObject({MUTEX_NAME}): unexpected {other:?} \
                     ({err})"
                );
            }
        }
        Ok(Self { h })
    }
}

/// Open (creating if needed) the state DB at the default location.
/// Stamps the parent directory real-user-only on EVERY open.
pub fn open_db() -> Result<Connection> {
    let dir = state_dir()?;
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
    open_db_at(&dir.join("state.db"))
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

/// Read-only open of the state DB at the default location. Returns
/// `None` if `state.db` doesn't exist yet. No mutex, no
/// `create_dir_all`, no dir-stamp, no schema apply — for the
/// per-Bash-call hot path (`install::read_setup` / `read_ca_cert`).
pub fn open_db_ro() -> Result<Option<Connection>> {
    let path = state_dir()?.join("state.db");
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
    let ver: i64 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .context("read user_version (RO)")?;
    if ver != SCHEMA_VERSION {
        if ver != 0 {
            eprintln!(
                "srt-win: state DB at {} is at schema v{ver} \
                 (expected v{SCHEMA_VERSION}); treating as not \
                 provisioned. Re-run `srt-win install` to migrate.",
                path.display(),
            );
        }
        return Ok(None);
    }
    Ok(Some(conn))
}

/// Open at an arbitrary path. Tests use `:memory:` via
/// `open_db_at(Path::new(":memory:"))`.
pub(crate) fn open_db_at(path: &std::path::Path) -> Result<Connection> {
    // Schema mismatch → rename + recreate. No ALTER/DROP migration:
    // the old DB is preserved (debugging/recovery) at
    // state.db.v<old>.<ts>.bak alongside `path`, and a fresh DB is
    // created at the expected schema. `acl recover` sweeps orphaned
    // ACEs by trustee SID without the old rows. The `sandbox_user`
    // row (cred + ca_cert) is in the renamed-away DB → the hint
    // says re-run install + trust-ca. The .bak inherits the
    // PROTECTED broker-only DACL from the state dir (stamped by
    // [`open_db`]); no per-file stamp needed. Chokepoint here so
    // direct callers (`clear_setup`, `trust_ca`) don't silently
    // bump `user_version` on a stale DB.
    if path.exists() {
        let probe = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY);
        if let Ok(c) = probe {
            let ver: i64 = c
                .query_row("PRAGMA user_version", [], |r| r.get(0))
                .unwrap_or(0);
            drop(c);
            if ver != 0 && ver != SCHEMA_VERSION {
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
                eprintln!(
                    "srt-win: state DB at schema v{ver} found, expected \
                     v{SCHEMA_VERSION}; renamed to {} and created fresh. \
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
    conn.execute_batch(SCHEMA_SQL).context("apply schema")?;
    conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    Ok(conn)
}

/// One row of the `sandbox_user` table — the install-time setup
/// record: the sandbox user's DPAPI-encrypted credential plus the
/// setup marker. Written by `srt-win install`, read by the
/// non-elevated broker. The `ca_cert` column is read/written
/// separately ([`read_ca_cert`] / [`set_ca_cert`]) so this struct
/// carries exactly what [`write_setup_info`] owns.
#[derive(Debug, Clone)]
pub struct SetupInfo {
    pub sandbox_user: String,
    pub sandbox_user_sid: String,
    pub sandbox_group_sid: String,
    /// DPAPI ciphertext of the sandbox user's password.
    pub cred: Vec<u8>,
    pub marker_version: u32,
    pub created_at_unix: u64,
}

/// Write the setup record. `ON CONFLICT … DO UPDATE` (NOT
/// `INSERT OR REPLACE`) so a re-install preserves any column this
/// function doesn't own — currently `ca_cert`, whose only writer
/// is [`set_ca_cert`]. Install is sequential under self-elevation,
/// so the caller doesn't need [`with_init_lock`].
pub fn write_setup_info(conn: &Connection, info: &SetupInfo) -> Result<()> {
    // Single-row invariant: [`read_setup_info`] does `LIMIT 1`, so a
    // `--force` re-install under a different `--sandbox-user` name
    // must not leave the old row behind (the ON CONFLICT keys on
    // username and would insert a second row). This DOES drop the
    // old row's `ca_cert` — intentionally: the CA was written into
    // the OLD user's `CurrentUser\Root` hive, so preserving the
    // record for the NEW user would lie about a Root install that
    // hasn't happened. Same-name re-install skips this DELETE and
    // the ON CONFLICT below preserves `ca_cert`.
    conn.execute(
        "DELETE FROM sandbox_user WHERE username != ?1",
        params![info.sandbox_user],
    )
    .context("DELETE stale sandbox_user row")?;
    conn.execute(
        "INSERT INTO sandbox_user \
           (username, user_sid, group_sid, cred, marker_version, \
            created_at_unix) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
         ON CONFLICT(username) DO UPDATE SET \
           user_sid        = excluded.user_sid, \
           group_sid       = excluded.group_sid, \
           cred            = excluded.cred, \
           marker_version  = excluded.marker_version, \
           created_at_unix = excluded.created_at_unix",
        params![
            info.sandbox_user,
            info.sandbox_user_sid,
            info.sandbox_group_sid,
            info.cred,
            info.marker_version,
            info.created_at_unix as i64,
        ],
    )
    .context("UPSERT sandbox_user")?;
    Ok(())
}

/// Hydrate the setup record. `Ok(None)` when no install has run
/// (no row, or the `sandbox_user` table itself absent —
/// [`open_db_ro`] doesn't apply schema). Currently exactly one
/// sandbox user is provisioned, so this reads the single row.
pub fn read_setup_info(conn: &Connection) -> Result<Option<SetupInfo>> {
    match conn
        .query_row(
            "SELECT username, user_sid, group_sid, cred, \
                    marker_version, created_at_unix \
             FROM sandbox_user LIMIT 1",
            [],
            |r| {
                Ok(SetupInfo {
                    sandbox_user: r.get(0)?,
                    sandbox_user_sid: r.get(1)?,
                    sandbox_group_sid: r.get(2)?,
                    cred: r.get(3)?,
                    marker_version: r.get(4)?,
                    created_at_unix: r.get::<_, i64>(5)? as u64,
                })
            },
        )
        .optional()
    {
        Ok(v) => Ok(v),
        Err(e) if missing_sandbox_user_table(&e) => Ok(None),
        Err(e) => Err(anyhow!("SELECT sandbox_user: {e}")),
    }
}

/// Read just the `ca_cert` column from the (single) row. `Ok(None)`
/// when no install has run, no CA was recorded, or the table/column
/// is absent.
pub fn read_ca_cert(conn: &Connection) -> Result<Option<crate::cert_store::CertDer>> {
    match conn
        .query_row("SELECT ca_cert FROM sandbox_user LIMIT 1", [], |r| r.get(0))
        .optional()
    {
        Ok(v) => Ok(v.flatten()),
        Err(e) if missing_sandbox_user_table(&e) => Ok(None),
        Err(e) => Err(anyhow!("SELECT sandbox_user.ca_cert: {e}")),
    }
}

/// Overwrite just the `ca_cert` column on the (single) existing
/// row. `srt-win user trust-ca` uses this to record a CA without
/// re-provisioning. Fails when no install has run yet.
pub fn set_ca_cert(conn: &Connection, der: &crate::cert_store::CertDer) -> Result<()> {
    let n = conn
        .execute("UPDATE sandbox_user SET ca_cert = ?1", params![der])
        .context("UPDATE sandbox_user.ca_cert")?;
    if n == 0 {
        bail!("no sandbox-user row to attach CA to — run `srt-win install`");
    }
    Ok(())
}

/// `DELETE FROM sandbox_user` — uninstall clears the credential
/// and marker in one go.
pub fn clear_setup_info(conn: &Connection) -> Result<()> {
    match conn.execute("DELETE FROM sandbox_user", []) {
        Ok(_) => Ok(()),
        Err(e) if missing_sandbox_user_table(&e) => Ok(()),
        Err(e) => Err(anyhow!("clear_setup_info: {e}")),
    }
}

fn missing_sandbox_user_table(e: &rusqlite::Error) -> bool {
    matches!(
        e,
        rusqlite::Error::SqliteFailure(_, Some(m))
            if m.contains("no such table") && m.contains("sandbox_user")
    )
}

/// `%LOCALAPPDATA%\sandbox-runtime`. Errors if `LOCALAPPDATA` is
/// unset, empty, or yields a non-absolute path — a relative state
/// dir would put the broker-only-stamped DB in the CWD and break
/// cross-broker refcounting/recovery.
pub fn state_dir() -> Result<PathBuf> {
    state_dir_from(std::env::var_os("LOCALAPPDATA"))
}

fn state_dir_from(local_app_data: Option<std::ffi::OsString>) -> Result<PathBuf> {
    let base = local_app_data
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("LOCALAPPDATA not set or empty"))?;
    let dir = base.join("sandbox-runtime");
    if !dir.is_absolute() {
        bail!(
            "state-DB directory '{}' is not absolute \
             (LOCALAPPDATA='{}'); refusing relative state path",
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
    let _mutex = InitMutex::acquire()?;
    let conn = open_db()?;
    let report = crash_recovery(&conn, force_recover)?;
    let mut locked = Locked { conn, holder_pid };
    let out = f(&mut locked)?;
    Ok((out, report))
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
            for w in witnesses.iter().filter(|w| w.holder_added) {
                if let Err(e) = self.release_one_ace(&w.canon, w.ace.kind(), sandbox_sid) {
                    eprintln!(
                        "srt-win: WARNING: rollback {} '{}': {e:#}; \
                         ACE left in place",
                        w.ace.kind(),
                        w.canon
                    );
                }
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
        self.with_broker_registration(sandbox_sid, |db| {
            let mut witnesses = Vec::with_capacity(targets.len());
            let mut failed = 0usize;
            let mut one = |canon: &str, ace: SbAce| -> bool {
                match db.ensure_ace(canon, ace, sandbox_sid) {
                    Ok(w) => {
                        witnesses.push(w);
                        true
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
        recompose_at(&self.conn, canon, sandbox_sid)?;
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
        let masks: Vec<String> = query_vec(
            &self.conn,
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

    /// Release one `(canon, kind)` hold; recompute the effective ACE
    /// from the remaining holders (downgrade if this holder was the
    /// one that escalated it; revoke when zero remain).
    /// Identity-validated: if the path now resolves to a different
    /// `file_id`, the row is dropped and the ACE on the foreign
    /// object is NOT touched — except for `Grant`, where we
    /// best-effort `locate_by_file_id` and revoke at the moved path
    /// so the sandbox user does not keep stale access.
    fn release_one_ace(&self, canon: &str, kind: &str, sandbox_sid: &str) -> Result<AceRelease> {
        self.conn
            .prepare_cached(
                "DELETE FROM ace_holders WHERE canonical_path = ?1 \
                 AND kind = ?2 AND pid = ?3",
            )?
            .execute(params![canon, kind, self.holder_pid.0 as i64])
            .context("DELETE ace_holders (self)")?;
        let row: Option<(Vec<u8>, String)> = self
            .conn
            .prepare_cached(
                "SELECT file_id, mask FROM working_aces \
                 WHERE canonical_path = ?1 AND kind = ?2",
            )?
            .query_row(params![canon, kind], |r| Ok((r.get(0)?, r.get(1)?)))
            .optional()?;
        let Some((fid, stored)) = row else {
            return Ok(AceRelease::NoRow);
        };
        let new_eff = self.effective_ace(canon, kind)?;
        // Row update first (record-first), then converge disk.
        match new_eff {
            Some(e) => self
                .conn
                .execute(
                    "UPDATE working_aces SET mask = ?3 \
                     WHERE canonical_path = ?1 AND kind = ?2",
                    params![canon, kind, e.as_str()],
                )
                .context("UPDATE working_aces (downgrade)")?,
            None => self
                .conn
                .execute(
                    "DELETE FROM working_aces \
                     WHERE canonical_path = ?1 AND kind = ?2",
                    params![canon, kind],
                )
                .context("DELETE working_aces")?,
        };
        let want_id = FileId::from_bytes(&fid)?;
        match identity_gate(canon, want_id) {
            IdGate::Match => {
                recompose_at(&self.conn, canon, sandbox_sid)?;
                Ok(match new_eff {
                    Some(e) if e.as_str() == stored => AceRelease::StillHeld,
                    Some(_) => AceRelease::Downgraded,
                    None => AceRelease::Revoked,
                })
            }
            IdGate::Mismatch if kind == "grant" => {
                // The granted object moved. The ALLOW ACE travels
                // with the inode → the sandbox user still has
                // access at the new path. Chase by file_id and
                // revoke there (then re-converge if the new path
                // happens to be tracked too). DENY/FDC are left in
                // place on the moved inode (fail-closed).
                Ok(match path_id::locate_by_file_id(&want_id) {
                    Some(at) => {
                        eprintln!(
                            "srt-win: grant '{canon}': file_id moved \
                             to '{at}'; revoking there"
                        );
                        recompose_at(&self.conn, &at, sandbox_sid)?;
                        AceRelease::Relocated { moved_to: at }
                    }
                    None => {
                        eprintln!(
                            "srt-win: grant '{canon}': file_id not \
                             found on volume; dropping row"
                        );
                        AceRelease::Missing
                    }
                })
            }
            IdGate::Mismatch => {
                eprintln!(
                    "srt-win: {kind} '{canon}': file_id mismatch — \
                     path substituted; not touching ACE on the \
                     foreign object (fail-closed)"
                );
                Ok(AceRelease::Mismatch)
            }
            IdGate::Unreadable => {
                eprintln!(
                    "srt-win: {kind} '{canon}': open failed; \
                     dropping row"
                );
                Ok(AceRelease::Missing)
            }
        }
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
    /// of any kind remain. Per-path catch-and-continue.
    pub fn release_aces(
        &self,
        sandbox_sid: &str,
        kinds: &[&str],
    ) -> Result<(Vec<(String, AceRelease)>, usize)> {
        let holds = self.my_ace_holds(Some(kinds))?;
        let mut out = Vec::with_capacity(holds.len());
        let mut failed = 0usize;
        for (canon, kind) in &holds {
            match self.release_one_ace(canon, kind, sandbox_sid) {
                Ok(r) => out.push((canon.clone(), r)),
                Err(e) => {
                    eprintln!(
                        "srt-win: WARNING: release {kind} '{canon}': \
                         {e:#}; ACE left in place"
                    );
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
    acl::apply_sandbox_aces(canon, sandbox_sid, set)
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
    /// Path no longer opens — row deleted.
    Missing,
    /// Holder row removed but no `working_aces` row found.
    NoRow,
}

impl AceRelease {
    pub fn as_str(&self) -> &'static str {
        match self {
            AceRelease::Revoked => "revoked",
            AceRelease::StillHeld => "stillHeld",
            AceRelease::Downgraded => "downgraded",
            AceRelease::Relocated { .. } => "relocated",
            AceRelease::Mismatch => "mismatch",
            AceRelease::Missing => "missing",
            AceRelease::NoRow => "noRow",
        }
    }
}

/// Prune dead brokers and revoke any sandbox-user ACEs they orphaned.
///
/// Per-path commit: the dead-broker prune is one short tx (pure DB,
/// CASCADE); then each orphan's (recompose FS mutation + row
/// delete) is committed independently, so a failure on path Y
/// leaves path X's recompose+delete durable. `force` is reserved
/// for a future "force-recompose ignoring file-id mismatch" mode.
fn crash_recovery(conn: &Connection, force: bool) -> Result<RecoveryReport> {
    let mut report = RecoveryReport::default();

    // 1. Find dead brokers.
    let dead: Vec<i64> = query_vec(
        conn,
        "SELECT pid, process_create_time FROM brokers",
        [],
        |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)),
    )?
    .into_iter()
    .filter(|&(pid, ct)| !is_process_alive(pid as u32, ct))
    .map(|(pid, _)| pid)
    .collect();
    // 2. Delete dead brokers in one short tx; CASCADE drops their
    //    holder rows. (No-op if none — but still cheap.)
    if !dead.is_empty() {
        report.dead_brokers = dead.len() as u32;
        let tx = conn
            .unchecked_transaction()
            .context("begin prune-dead tx")?;
        for pid_i in &dead {
            tx.execute("DELETE FROM brokers WHERE pid = ?1", params![pid_i])
                .context("DELETE dead broker")?;
        }
        tx.commit().context("commit prune-dead")?;
    }
    // Even with no dead brokers there can be orphaned ACE rows
    // (a broker that unregistered but crashed before releasing), so
    // always run step 3.

    // 3. Orphaned sandbox-user ACEs: any working_aces row with
    //     zero ace_holders is one whose holder died (CASCADE
    //     dropped the holder row above). Re-converge the path —
    //     `recompose_at` reads the (possibly remaining) rows and
    //     applies exactly that, so a path with one orphaned kind
    //     and one still-held kind keeps the held one. Sandbox SID
    //     comes from `read_setup_info` — when no sandbox user is
    //     provisioned, there are no `working_aces` rows to orphan.
    if let Some(sb) = read_setup_info(conn)?.map(|s| s.sandbox_user_sid) {
        let orphan_aces: Vec<(String, String, Vec<u8>)> = query_vec(
            conn,
            "SELECT g.canonical_path, g.kind, g.file_id \
             FROM working_aces g \
             LEFT JOIN ace_holders h \
               ON h.canonical_path = g.canonical_path \
              AND h.kind = g.kind \
             WHERE h.canonical_path IS NULL",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        for (canon, kind, fid) in orphan_aces {
            conn.execute(
                "DELETE FROM working_aces \
                 WHERE canonical_path = ?1 AND kind = ?2",
                params![&canon, &kind],
            )
            .context("DELETE working_aces (orphan)")?;
            let want = FileId::from_bytes(&fid)?;
            match identity_gate(&canon, want) {
                IdGate::Match => {
                    if let Err(e) = recompose_at(conn, &canon, &sb) {
                        eprintln!(
                            "srt-win: orphaned {kind} '{canon}': \
                             recompose failed ({e:#})"
                        );
                        continue;
                    }
                }
                IdGate::Mismatch if kind == "grant" => {
                    if let Some(at) = path_id::locate_by_file_id(&want) {
                        let _ = recompose_at(conn, &at, &sb);
                    }
                }
                _ => {} // gone/substituted — nothing on disk to do
            }
            report.aces_revoked += 1;
        }
    }
    let _ = force; // reserved for a future "force-recompose" mode
    Ok(report)
}

enum IdGate {
    Match,
    Mismatch,
    Unreadable,
}

/// `(path, file_id)` identity check. `path` gone
/// (ERROR_FILE/PATH_NOT_FOUND) or different inode → `Mismatch`;
/// any other open error → `Unreadable` (retryable, not a
/// mismatch).
fn identity_gate(path: &str, expect: FileId) -> IdGate {
    match path_id::capture_file_id(path) {
        Ok(cur) if cur == expect => IdGate::Match,
        Ok(_) => IdGate::Mismatch,
        Err(e) => {
            if path_id::is_not_found(&e) {
                IdGate::Mismatch
            } else {
                eprintln!(
                    "srt-win: '{path}': cannot read file_id ({e:#}); \
                     leaving row (use `acl recover --force`)"
                );
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
        assert!(state_dir_from(None).is_err());
        assert!(state_dir_from(Some(OsString::from(""))).is_err());
        // Relative → error (would put the broker-only-stamped DB
        // in CWD).
        assert!(state_dir_from(Some(OsString::from("rel"))).is_err());
        // Absolute → ok.
        let ok = state_dir_from(Some(OsString::from(r"C:\Users\u\AppData\Local")));
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
        let conn = open_db_at(std::path::Path::new(":memory:")).unwrap();
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
        with_mem_db(|db| {
            let n: i64 = db
                .conn
                .query_row(
                    "SELECT count(*) FROM sqlite_master WHERE type='table' \
                     AND name IN ('brokers','working_aces','ace_holders', \
                                  'sandbox_user','placeholders')",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(n, 5);
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
}
