//! Broker-initialize world-writable-directory audit — the bounded,
//! dynamic complement to `ambient.rs`'s static install-time list.
//!
//! `ambient.rs` covers Windows' STOCK world-writable corners, known
//! ahead of time and stamped by the elevated install. Third-party
//! software creates more of them (`icacls <dir> /grant Everyone:F`
//! is a depressingly common installer workaround) — sometimes on
//! `PATH` or in DLL search paths, where a sandbox-writable directory
//! is a persistence/planting vector against the real user. Those
//! cannot be known at install time, so the broker runs this audit at
//! every session initialize: scan a small fixed root set, flag
//! directories whose DACL carries an EXPLICIT ALLOW granting write
//! to Everyone / BUILTIN\Users / Authenticated Users (or a NULL
//! DACL), and stamp each hit with the same additive
//! `(D;OICI;WriteDeny;;;<sb-SID>)` shape as `acl stamp --deny-write`.
//! INHERITED world-write is deliberately out of scope — see
//! [`dacl_grants_world_write`]'s doc for why (the stock volume-root
//! `Authenticated Users:(OI)(CI)(IO)(M)` would otherwise flag every
//! plain `C:\<dir>` and materialize denies over huge trees).
//!
//! ## Scope and budgets
//!
//! Roots: the top-level directories of `%SystemDrive%`, `%TEMP%`,
//! `%PUBLIC%`, every `PATH` entry of the broker's environment, and
//! the immediate children of the broker's cwd. Depth 1 — this is a
//! cheap sweep of the highest-value surfaces, not a filesystem walk.
//! Hard budgets bound the worst case: [`WALL_BUDGET`] wall-clock,
//! [`MAX_DACL_READS`] DACL probes, [`MAX_DIR_ENTRIES`] entries per
//! enumerated root. Budget exhaustion is never silent: every skip
//! class is counted in [`AuditOutcome`] and summarized on stderr by
//! the `audit-ww` CLI arm.
//!
//! The budgets bound the SCAN. The stamping step is bounded by the
//! flagged count instead, and each stamp's cost is proportional to
//! the flagged subtree's size (`SetNamedSecurityInfoW` materializes
//! the inheritable `(OI)(CI)` ACE onto every unprotected
//! descendant) — the same cost the install-time `%ProgramData%`
//! ambient stamp already accepts, and the reason drive roots are
//! never candidates here (only children of the drive root are).
//!
//! ## Local fixed drives only; reparse-hardened probes
//!
//! UNC paths and non-fixed drives are rejected LEXICALLY before any
//! filesystem contact (`stat` on a UNC path initiates an SMB
//! connection carrying the broker's credentials — see the UNC
//! handling in `cli.rs::canonicalize_ace_targets`). The scan roots
//! include attacker-influencable locations (`%TEMP%`, the cwd, any
//! world-writable dir by definition), where a junction whose lexical
//! path looks local can reparse to `\\attacker\share` — so each
//! candidate is opened with `FILE_FLAG_OPEN_REPARSE_POINT` (the
//! object itself, no traversal), rejected if it carries
//! `FILE_ATTRIBUTE_REPARSE_POINT`, re-checked lexically on its
//! handle-derived canonical path, and has its DACL read BY HANDLE —
//! never by a name re-resolve after the check. Child enumeration
//! (`read_dir`) does not dereference child reparse points either;
//! reparse children are skipped outright. The final deny stamp goes
//! through the name-based [`crate::acl::apply_sandbox_aces`]
//! chokepoint on the handle-derived canonical path — the same
//! residual name-vs-handle window every other stamp site in this
//! crate accepts.
//!
//! ## Exclusions
//!
//! A candidate is skipped when it is, or sits under: a static
//! ambient-deny target (already floor-denied and recompose-folded),
//! a recorded ambient path, a live session write GRANT (the session
//! deliberately opened it for sandbox writes), or the machine state
//! dir. Matching is case-insensitive, extended-prefix-agnostic
//! prefix matching on whole path components.
//!
//! ## Session-tracking decision
//!
//! Audit denies are recorded as ORDINARY session `deny` rows
//! (`working_aces`/`ace_holders`) under the broker's holder PID via
//! [`crate::state_db::Locked::apply_aces`] — deliberately NOT as
//! persistent ambient entries. Rationale: (a) the flagged set is
//! environment-dependent (`PATH`, cwd) and can differ per session,
//! so a durable record would go stale; (b) the audit runs
//! unelevated and best-effort, so it can never guarantee coverage
//! the way the install-time list does — keeping `ambient.rs`
//! authoritative for the durable floor keeps the trust story simple;
//! (c) the session rows get the full existing lifecycle for free:
//! refcounting across concurrent brokers, release at `acl restore`
//! (the host's `reset()`), and crash-recovery reaping when the
//! holder dies. `apply_aces` also stamps the flagged dir's parent
//! with the standard `deny_fdc` ACE (never a volume root —
//! `canonical_parent_of` refuses those), which protects the deny
//! from a sandbox-side rename/delete of the flagged dir itself.

use anyhow::{Context, Result};
use std::collections::HashSet;
use std::time::{Duration, Instant};

use crate::acl::{self, DenyMask, SbAce};
use crate::path_id::{is_unc_path, strip_extended_prefix};
use crate::state_db::{self, HolderPid, RecoveryReport};

/// Wall-clock budget for the whole scan.
pub const WALL_BUDGET: Duration = Duration::from_secs(2);
/// Maximum candidate DACL probes (open + read) per audit.
pub const MAX_DACL_READS: u32 = 50_000;
/// Maximum entries consumed per enumerated root directory.
pub const MAX_DIR_ENTRIES: usize = 1_000;

/// The trustees whose ALLOW ACEs make a directory "world-writable":
/// Everyone, BUILTIN\Users, Authenticated Users. Every local
/// account — the sandbox user included — is a member of all three
/// (Everyone/Authenticated Users by definition; BUILTIN\Users
/// because provisioning adds the account to it for profile loads).
pub const FLAGGED_SIDS: [&str; 3] = ["S-1-1-0", "S-1-5-32-545", "S-1-5-11"];

/// `ACE_HEADER.AceFlags` bit: the ACE exists only to be inherited
/// by children and grants nothing on the container itself (e.g. the
/// stock `CREATOR OWNER` rows). Same raw-u8 convention as
/// `acl.rs`'s `INHERITED_ACE`.
const INHERIT_ONLY_ACE: u8 = 0x08;
/// `ACE_HEADER.AceFlags` bit: the ACE was derived from the parent's
/// inheritable set, not set explicitly on this object.
const INHERITED_ACE: u8 = 0x10;

/// Whether an ACE with `flags` applies to the directory itself (an
/// `INHERIT_ONLY` ACE does not — it grants nothing on the
/// container, only on future children).
pub fn ace_applies_to_container(flags: u8) -> bool {
    flags & INHERIT_ONLY_ACE == 0
}

/// Whether `mask` lets its trustee create content in a directory:
/// the specific `FILE_ADD_FILE`/`FILE_ADD_SUBDIRECTORY` bits, or a
/// generic bit the object's mapping resolves to include them
/// (`GENERIC_WRITE`/`GENERIC_ALL`).
pub fn mask_grants_dir_write(mask: u32) -> bool {
    const FILE_ADD_FILE: u32 = 0x0002;
    const FILE_ADD_SUBDIRECTORY: u32 = 0x0004;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const GENERIC_ALL: u32 = 0x1000_0000;
    mask & (FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY) != 0 || mask & (GENERIC_WRITE | GENERIC_ALL) != 0
}

/// True iff `p` is lexically a plain local drive path (`X:\…`,
/// optionally `\\?\`-prefixed) — NOT UNC in any spelling, NOT a
/// device path, NOT relative. This runs BEFORE any filesystem
/// syscall on the path: merely `stat`ing a UNC path sends the
/// broker's credentials to the named host.
pub fn lexically_local_drive_path(p: &str) -> bool {
    if is_unc_path(p) {
        return false;
    }
    let s = strip_extended_prefix(p);
    let b = s.as_bytes();
    // `\\.\PIPE\x` and friends survive is_unc_path; the drive-letter
    // shape check rejects them (first byte is `\`).
    b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/')
}

// ─── Budget ─────────────────────────────────────────────────────────

/// Scan budget accounting: a wall-clock deadline plus a DACL-probe
/// counter. Pure bookkeeping (no Win32) so the arithmetic is
/// unit-testable; the limits are injected for tests via
/// [`Budget::with_limits`].
pub struct Budget {
    deadline: Instant,
    max_dacl_reads: u32,
    dacl_reads: u32,
    wall_expired: bool,
    dacl_exhausted: bool,
}

impl Budget {
    pub fn new() -> Self {
        Self::with_limits(WALL_BUDGET, MAX_DACL_READS)
    }

    pub fn with_limits(wall: Duration, max_dacl_reads: u32) -> Self {
        Self {
            deadline: Instant::now() + wall,
            max_dacl_reads,
            dacl_reads: 0,
            wall_expired: false,
            dacl_exhausted: false,
        }
    }

    /// Charge one DACL probe. `false` = out of budget (wall or
    /// count; the corresponding flag latches).
    pub fn try_charge_dacl_read(&mut self) -> bool {
        if self.wall_expired_now() {
            return false;
        }
        if self.dacl_reads >= self.max_dacl_reads {
            self.dacl_exhausted = true;
            return false;
        }
        self.dacl_reads += 1;
        true
    }

    /// Check (and latch) wall-clock expiry without charging a probe
    /// — used inside enumeration loops.
    pub fn wall_expired_now(&mut self) -> bool {
        if !self.wall_expired && Instant::now() >= self.deadline {
            self.wall_expired = true;
        }
        self.wall_expired
    }

    pub fn dacl_reads(&self) -> u32 {
        self.dacl_reads
    }
    pub fn wall_expired(&self) -> bool {
        self.wall_expired
    }
    pub fn dacl_exhausted(&self) -> bool {
        self.dacl_exhausted
    }
}

impl Default for Budget {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Exclusions ─────────────────────────────────────────────────────

/// Comparable key for path containment checks: extended prefix
/// stripped, `/` → `\`, trailing separator trimmed, ASCII-lowercased.
/// NTFS default collation is case-insensitive for the ASCII range,
/// which is what the env-derived roots and canonical paths use.
fn norm_key(p: &str) -> String {
    strip_extended_prefix(p)
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_ascii_lowercase()
}

/// Prefix set for "already covered" checks: a candidate equal to, or
/// strictly under, any entry is excluded from the audit. Pure (no
/// Win32) so the component-boundary matching is unit-testable.
pub struct Exclusions {
    prefixes: Vec<String>,
}

impl Exclusions {
    pub fn new(paths: impl IntoIterator<Item = String>) -> Self {
        let mut prefixes: Vec<String> = paths
            .into_iter()
            .map(|p| norm_key(&p))
            .filter(|p| !p.is_empty())
            .collect();
        prefixes.sort();
        prefixes.dedup();
        Self { prefixes }
    }

    /// Whether `path` is one of the excluded prefixes or a
    /// descendant of one (component-boundary match — `C:\Program`
    /// does not cover `C:\ProgramData`).
    pub fn covers(&self, path: &str) -> bool {
        let k = norm_key(path);
        self.prefixes.iter().any(|p| {
            k == *p || (k.len() > p.len() && k.starts_with(p) && k.as_bytes()[p.len()] == b'\\')
        })
    }
}

// ─── Outcome ────────────────────────────────────────────────────────

/// What one audit did — every bounded/skipped class is counted so
/// the CLI summary can report exactly what was NOT covered (no
/// silent caps).
#[derive(Debug, Default)]
pub struct AuditOutcome {
    /// Candidate directories collected from the root set (post
    /// lexical filter + dedup + pre-probe exclusion check).
    pub candidates: u32,
    /// Candidates actually probed (open + DACL read).
    pub probed: u32,
    /// Canonical paths whose DACL grants write to a flagged SID.
    pub flagged: Vec<String>,
    /// Flagged paths whose deny stamp landed (recorded + on disk).
    pub stamped: Vec<String>,
    /// Flagged paths whose deny stamp failed `(path, error)` — the
    /// broker lacks `WRITE_DAC` there, or the recompose failed.
    pub failed: Vec<(String, String)>,
    /// Candidates never probed because a budget ran out first.
    pub skipped_budget: u32,
    /// Enumerated roots whose listing hit [`MAX_DIR_ENTRIES`].
    pub dirs_truncated: u32,
    /// Candidates whose probe failed for a reason other than
    /// not-found (access denied on the open, unreadable SD, …).
    pub unreadable: u32,
    /// Candidates skipped as reparse points (junction/symlink).
    pub reparse_skipped: u32,
    /// Candidates whose handle-derived canonical path was not a
    /// plain local drive path (e.g. resolved onto a UNC target).
    pub remote_skipped: u32,
    pub wall_expired: bool,
    pub dacl_exhausted: bool,
    pub dacl_reads: u32,
}

// ─── Scan (Win32) ───────────────────────────────────────────────────

/// `GetDriveTypeW(X:\) == DRIVE_FIXED`. Reads the local mount
/// table only — no network contact for remote/mapped letters.
fn drive_is_fixed(path: &str) -> bool {
    use windows::Win32::Storage::FileSystem::GetDriveTypeW;
    const DRIVE_FIXED: u32 = 3;
    let s = strip_extended_prefix(path);
    let Some(letter) = s.as_bytes().first().copied() else {
        return false;
    };
    let root = format!("{}:\\", letter as char);
    let w = crate::util::wstr(&root);
    unsafe { GetDriveTypeW(crate::util::pcwstr(&w)) == DRIVE_FIXED }
}

/// Outcome of probing one candidate directory.
enum Probe {
    /// World-writable; carries the handle-derived canonical path.
    Flagged(String),
    Clean,
    /// The object itself is a reparse point — never dereferenced.
    Reparse,
    /// Exists but is not a directory (stale `PATH` entry naming a
    /// file). Not an audit concern.
    NotDir,
    /// Canonical path resolved outside plain local-drive space.
    RemoteCanon,
}

/// Open `path` no-follow, reject reparse points, and read its DACL
/// BY HANDLE — see the module doc's reparse-hardening notes. The
/// open requests `READ_CONTROL` only, so it works on directories
/// the broker cannot write.
fn probe_dir(path: &str, flagged_sids: &[Vec<u8>]) -> Result<Probe> {
    use windows::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_ATTRIBUTE_DIRECTORY,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, GetFileInformationByHandle,
        OPEN_EXISTING,
    };
    let w = crate::util::wstr(path);
    let h = unsafe {
        CreateFileW(
            crate::util::pcwstr(&w),
            acl::Mask::READ_CONTROL.bits(),
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    }
    .with_context(|| format!("CreateFileW('{path}', no-follow)"))?;
    if h == INVALID_HANDLE_VALUE {
        anyhow::bail!("CreateFileW('{path}'): INVALID_HANDLE_VALUE");
    }
    let h = crate::util::OwnedHandle(h);
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    unsafe { GetFileInformationByHandle(h.raw(), &mut info) }
        .with_context(|| format!("GetFileInformationByHandle('{path}')"))?;
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
        return Ok(Probe::Reparse);
    }
    if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 == 0 {
        return Ok(Probe::NotDir);
    }
    let canon = crate::path_id::canonical_path_from_handle(h.raw(), path)?;
    if !lexically_local_drive_path(&canon) {
        return Ok(Probe::RemoteCanon);
    }
    let (sd, dacl) =
        acl::read_handle_dacl(&h).with_context(|| format!("read DACL by handle '{path}'"))?;
    // A NULL DACL is "everyone: full control" — the most
    // world-writable a directory can be. `filter_aces` treats null
    // as an empty ACE list, so special-case it here.
    let flagged = dacl.is_null() || dacl_grants_world_write(dacl, flagged_sids)?;
    drop(sd);
    Ok(if flagged {
        Probe::Flagged(canon)
    } else {
        Probe::Clean
    })
}

/// Whether `dacl` carries an EXPLICIT ALLOW ACE that grants
/// directory-write to any of `flagged_sids` and applies to the
/// container itself. `INHERIT_ONLY` ACEs do not apply; INHERITED
/// ACEs are deliberately out of scope: the stock volume-root DACL
/// carries `Authenticated Users:(OI)(CI)(IO)(M)`, so every plain
/// directory created under `C:\` inherits AU-Modify — flagging
/// those would deny-stamp (and `SetNamedSecurityInfoW`-materialize
/// across) arbitrarily many large innocent trees at every session
/// start. That inherited drive-root class is the one `ambient.rs`
/// explicitly tracks separately; the EXPLICIT world-write ACE is
/// the third-party-installer signature this audit targets.
fn dacl_grants_world_write(
    dacl: *const windows::Win32::Security::ACL,
    flagged_sids: &[Vec<u8>],
) -> Result<bool> {
    use windows::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;
    let hits = acl::filter_aces(dacl, |hdr, body| {
        if u32::from(hdr.AceType) != ACCESS_ALLOWED_ACE_TYPE
            || !ace_applies_to_container(hdr.AceFlags)
            || hdr.AceFlags & INHERITED_ACE != 0
            || body.len() < 8
        {
            return false;
        }
        // ACCESS_ALLOWED_ACE layout: header (4) then Mask (u32 LE).
        let mask = u32::from_le_bytes([body[4], body[5], body[6], body[7]]);
        mask_grants_dir_write(mask) && flagged_sids.iter().any(|s| acl::ace_sid_is(body, s))
    })?;
    Ok(!hits.0.is_empty())
}

/// Collect a root's immediate directory children as candidates.
/// Reparse-point children are skipped (never dereferenced);
/// listing stops at [`MAX_DIR_ENTRIES`] or wall expiry, counted in
/// `out`.
fn push_children(
    root: &str,
    candidates: &mut Vec<String>,
    seen: &mut HashSet<String>,
    budget: &mut Budget,
    out: &mut AuditOutcome,
) {
    if !lexically_local_drive_path(root) || !drive_is_fixed(root) {
        return;
    }
    let rd = match std::fs::read_dir(root) {
        Ok(r) => r,
        Err(_) => {
            out.unreadable += 1;
            return;
        }
    };
    let mut n = 0usize;
    for ent in rd {
        if budget.wall_expired_now() {
            return;
        }
        let Ok(ent) = ent else { continue };
        n += 1;
        if n > MAX_DIR_ENTRIES {
            out.dirs_truncated += 1;
            return;
        }
        // `file_type()` comes from the enumeration record — no
        // extra open, and it reports reparse points as symlinks
        // WITHOUT following them.
        let Ok(ft) = ent.file_type() else { continue };
        if !ft.is_dir() || ft.is_symlink() {
            continue;
        }
        push_candidate(candidates, seen, ent.path().display().to_string());
    }
}

/// Dedup + lexical-filter one candidate path.
fn push_candidate(candidates: &mut Vec<String>, seen: &mut HashSet<String>, p: String) {
    if !lexically_local_drive_path(&p) {
        return;
    }
    if seen.insert(norm_key(&p)) {
        candidates.push(p);
    }
}

/// Run the scan: collect candidates from the fixed root set, probe
/// each within `budget`, and return the outcome with `flagged`
/// filled (stamping is the caller's step).
fn scan(exclusions: &Exclusions, budget: &mut Budget) -> Result<AuditOutcome> {
    let mut out = AuditOutcome::default();
    let flagged_sids: Vec<Vec<u8>> = FLAGGED_SIDS
        .iter()
        .map(|s| crate::sid::sid_bytes(s))
        .collect::<Result<_>>()?;

    // ── Candidate collection ────────────────────────────────────
    let mut seen: HashSet<String> = HashSet::new();
    let mut candidates: Vec<String> = Vec::new();
    if let Some(sd) = std::env::var_os("SystemDrive") {
        let root = format!("{}\\", sd.to_string_lossy());
        push_children(&root, &mut candidates, &mut seen, budget, &mut out);
    }
    for var in ["TEMP", "PUBLIC"] {
        if let Some(v) = std::env::var_os(var) {
            push_candidate(&mut candidates, &mut seen, v.to_string_lossy().into_owned());
        }
    }
    if let Some(p) = std::env::var_os("PATH") {
        for e in std::env::split_paths(&p) {
            push_candidate(&mut candidates, &mut seen, e.display().to_string());
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        push_children(
            &cwd.display().to_string(),
            &mut candidates,
            &mut seen,
            budget,
            &mut out,
        );
    }

    // ── Probe ───────────────────────────────────────────────────
    let mut flagged_seen: HashSet<String> = HashSet::new();
    for cand in candidates {
        if exclusions.covers(&cand) {
            continue;
        }
        out.candidates += 1;
        if !drive_is_fixed(&cand) {
            out.remote_skipped += 1;
            continue;
        }
        if !budget.try_charge_dacl_read() {
            out.skipped_budget += 1;
            continue;
        }
        out.probed += 1;
        match probe_dir(&cand, &flagged_sids) {
            Ok(Probe::Flagged(canon)) => {
                // Re-check exclusions on the CANONICAL path — 8.3
                // short names or case differences in the raw
                // candidate must not dodge the prefix match.
                if !exclusions.covers(&canon) && flagged_seen.insert(norm_key(&canon)) {
                    out.flagged.push(canon);
                }
            }
            Ok(Probe::Clean) => {}
            Ok(Probe::Reparse) => out.reparse_skipped += 1,
            Ok(Probe::NotDir) => {}
            Ok(Probe::RemoteCanon) => out.remote_skipped += 1,
            Err(e) => {
                // Nonexistent candidates (stale PATH entries) are
                // normal; anything else is counted for the summary.
                if !crate::path_id::is_not_found(&e) {
                    out.unreadable += 1;
                }
            }
        }
    }
    out.wall_expired = budget.wall_expired();
    out.dacl_exhausted = budget.dacl_exhausted();
    out.dacl_reads = budget.dacl_reads();
    Ok(out)
}

/// Full audit under the session init lock: build the exclusion set
/// (static ambient targets + recorded ambient paths + live session
/// write grants + machine state dir), scan, then stamp each flagged
/// dir as a session write-deny hold for `holder` — one
/// [`crate::state_db::Locked::apply_aces`] call per path so a
/// failure (the broker lacks `WRITE_DAC` on a dir it does not own)
/// rolls back only that path and the rest still land. Best-effort
/// by design: per-path failures are collected in
/// [`AuditOutcome::failed`], never fatal.
pub fn audit_and_stamp(
    holder: HolderPid,
    sandbox_sid: &str,
) -> Result<(AuditOutcome, RecoveryReport)> {
    state_db::with_init_lock(holder, false, |db| {
        let mut excluded: Vec<String> = crate::ambient::ambient_deny_targets();
        excluded.extend(crate::install::ambient_recorded_paths().unwrap_or_default());
        excluded.extend(db.granted_write_paths()?);
        if let Ok(d) = state_db::machine_store_dir() {
            excluded.push(d.display().to_string());
        }
        let exclusions = Exclusions::new(excluded);
        let mut budget = Budget::new();
        let mut out = scan(&exclusions, &mut budget)?;
        for canon in out.flagged.clone() {
            match db.apply_aces(
                sandbox_sid,
                &[(canon.clone(), SbAce::Deny(DenyMask::WriteDeny))],
            ) {
                Ok((_, 0)) => out.stamped.push(canon),
                // apply_aces already printed the per-path warning
                // and rolled this path's fresh rows back.
                Ok((_, _failed)) => out.failed.push((
                    canon,
                    "stamp failed (see warning above); left unstamped".to_string(),
                )),
                Err(e) => out.failed.push((canon, format!("{e:#}"))),
            }
        }
        Ok(out)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_detection() {
        const FILE_ADD_FILE: u32 = 0x0002;
        const FILE_ADD_SUBDIRECTORY: u32 = 0x0004;
        assert!(mask_grants_dir_write(FILE_ADD_FILE));
        assert!(mask_grants_dir_write(FILE_ADD_SUBDIRECTORY));
        assert!(mask_grants_dir_write(0x4000_0000)); // GENERIC_WRITE
        assert!(mask_grants_dir_write(0x1000_0000)); // GENERIC_ALL
        assert!(mask_grants_dir_write(0x001f_01ff)); // FILE_ALL_ACCESS
        // Read/execute/list-only masks must NOT flag.
        assert!(!mask_grants_dir_write(0x0012_00a9)); // FILE_GENERIC_READ|EXECUTE
        assert!(!mask_grants_dir_write(0x8000_0000)); // GENERIC_READ
        assert!(!mask_grants_dir_write(0x0002_0000)); // READ_CONTROL
        assert!(!mask_grants_dir_write(0));
    }

    #[test]
    fn inherit_only_aces_do_not_apply() {
        assert!(ace_applies_to_container(0x00));
        assert!(ace_applies_to_container(0x03)); // (OI)(CI)
        assert!(ace_applies_to_container(0x10)); // INHERITED
        assert!(!ace_applies_to_container(0x08)); // (IO)
        assert!(!ace_applies_to_container(0x0b)); // (OI)(CI)(IO)
    }

    #[test]
    fn lexical_local_drive_filter() {
        for p in [r"C:\Tools", r"c:/tools", r"\\?\C:\Program Files", r"D:\x"] {
            assert!(lexically_local_drive_path(p), "should pass: {p}");
        }
        for p in [
            r"\\server\share\x",
            "//server/share/x",
            r"\\?\UNC\server\share",
            r"\\.\PIPE\x",
            r"relative\path",
            "C:",
            "",
        ] {
            assert!(!lexically_local_drive_path(p), "should reject: {p}");
        }
    }

    #[test]
    fn budget_accounting() {
        // Count exhaustion latches and stops charging.
        let mut b = Budget::with_limits(Duration::from_secs(60), 2);
        assert!(b.try_charge_dacl_read());
        assert!(b.try_charge_dacl_read());
        assert!(!b.try_charge_dacl_read());
        assert!(b.dacl_exhausted());
        assert!(!b.wall_expired());
        assert_eq!(b.dacl_reads(), 2);
        // Wall expiry latches without charging.
        let mut b = Budget::with_limits(Duration::ZERO, 100);
        assert!(b.wall_expired_now());
        assert!(!b.try_charge_dacl_read());
        assert!(b.wall_expired());
        assert_eq!(b.dacl_reads(), 0);
    }

    #[test]
    fn exclusion_matching() {
        let ex = Exclusions::new(vec![
            r"C:\ProgramData".to_string(),
            r"\\?\C:\Users\Public".to_string(),
            r"C:\Windows\Temp\".to_string(),
        ]);
        // Exact, case-insensitive, extended-prefix-agnostic.
        assert!(ex.covers(r"C:\ProgramData"));
        assert!(ex.covers(r"c:\programdata"));
        assert!(ex.covers(r"\\?\C:\ProgramData"));
        // Descendants.
        assert!(ex.covers(r"C:\ProgramData\ThirdParty"));
        assert!(ex.covers(r"\\?\C:\Users\Public\Downloads"));
        assert!(ex.covers(r"C:\Windows\Temp\x\y"));
        // Component-boundary: sibling prefixes do NOT match.
        assert!(!ex.covers(r"C:\ProgramDataX"));
        assert!(!ex.covers(r"C:\Users\PublicGames"));
        assert!(!ex.covers(r"C:\Windows"));
        assert!(!ex.covers(r"D:\ProgramData"));
    }

    /// Windows-only (needs `ConvertStringSecurityDescriptorToSecurityDescriptorW`,
    /// no elevation): the detection predicate over real DACLs built
    /// from SDDL.
    #[test]
    fn sddl_detection() {
        use windows::Win32::Security::GetSecurityDescriptorDacl;
        let flagged: Vec<Vec<u8>> = FLAGGED_SIDS
            .iter()
            .map(|s| crate::sid::sid_bytes(s).unwrap())
            .collect();
        let check = |sddl: &str| -> bool {
            let sd = crate::util::OwnedSd::from_sddl(sddl).unwrap();
            let mut present = windows::core::BOOL::from(false);
            let mut dacl: *mut windows::Win32::Security::ACL = std::ptr::null_mut();
            let mut defaulted = windows::core::BOOL::from(false);
            unsafe {
                GetSecurityDescriptorDacl(sd.ptr, &mut present, &mut dacl, &mut defaulted).unwrap();
            }
            dacl_grants_world_write(dacl, &flagged).unwrap()
        };
        // Everyone generic-write / BUILTIN\Users add-file (0x2 is
        // inside `FA`'s low bits; use explicit hex masks) /
        // Authenticated Users full.
        assert!(check("D:(A;OICI;GW;;;WD)"));
        assert!(check("D:(A;OICI;0x100002;;;BU)")); // FILE_ADD_FILE
        assert!(check("D:(A;OICI;FA;;;AU)"));
        // Read-only world access is fine.
        assert!(!check("D:(A;OICI;FR;;;WD)"));
        // Write for a non-flagged trustee (Administrators) is fine.
        assert!(!check("D:(A;OICI;FA;;;BA)"));
        // A DENY row for Everyone is not an ALLOW.
        assert!(!check("D:(D;OICI;FA;;;WD)"));
        // INHERIT_ONLY world-write grants nothing on the container.
        assert!(!check("D:(A;OICIIO;GW;;;WD)"));
        // INHERITED world-write is out of scope (the stock
        // volume-root `AU:(OI)(CI)(IO)(M)` class — see
        // dacl_grants_world_write's doc).
        assert!(!check("D:(A;OICIID;GW;;;WD)"));
        // …but an explicit row alongside inherited ones still flags.
        assert!(check("D:(A;OICIID;FR;;;WD)(A;OICI;GW;;;WD)"));
    }
}
