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
//! DACL), and stamp each hit with an additive `(OI)(CI)` deny for
//! the sandbox SID — [`crate::acl::SbAce::DenyAudit`]: the `acl
//! stamp --deny-write` mask PLUS `WRITE_DAC`/`WRITE_OWNER`, because
//! the flagged grants (`Everyone:(F)`, `GENERIC_ALL`) hand the
//! sandbox user `WRITE_DAC` through the very ACE that got the dir
//! flagged, so a plain write-deny would be self-strippable.
//! INHERITED world-write is deliberately out of scope — see
//! [`dacl_grants_world_write`]'s doc for why (the stock volume-root
//! `Authenticated Users:(OI)(CI)(IO)(M)` would otherwise flag every
//! plain `C:\<dir>` and materialize denies over huge trees).
//!
//! NULL-DACL directories are DETECTED (they appear in
//! [`AuditOutcome::flagged`]) but never stamped: a NULL DACL means
//! "everyone: full control", and recomposing it would materialize a
//! real DACL that `acl restore` can never return to NULL — a
//! durable permission change on a directory we don't own. They are
//! reported in [`AuditOutcome::failed`] with a distinct reason.
//!
//! ## Scope and budgets
//!
//! Roots: the top-level directories of `%SystemDrive%`; `%TEMP%`
//! and `%PUBLIC%` themselves (single candidates — enumerating
//! TEMP's thousands of entries would eat the budget); every `PATH`
//! entry of the broker's environment; and the immediate children
//! of the broker's cwd. Depth 1 — this is a
//! cheap sweep of the highest-value surfaces, not a filesystem walk.
//! Hard budgets bound the worst case: [`WALL_BUDGET`] wall-clock,
//! [`MAX_DACL_READS`] DACL probes, [`MAX_DIR_ENTRIES`] entries per
//! enumerated root. Budget exhaustion is never silent: every skip
//! class is counted in [`AuditOutcome::budget`] and summarized on
//! stderr by the `acl audit` CLI arm.
//!
//! Nothing is cached across sessions, deliberately: the flagged set
//! is environment-dependent (`PATH`, cwd, third-party installs
//! between sessions), so each session re-scans and the budgets
//! above bound what the re-scan can cost.
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
//! handle-derived canonical path (which is also where the
//! never-a-drive-root guard lands, so a `C:\.`-style spelling
//! cannot dodge it), and has its DACL read BY HANDLE — never by a
//! name re-resolve after the check. Child enumeration (`read_dir`)
//! does not dereference child reparse points either; reparse
//! children are skipped outright. The final deny stamp goes through
//! the name-based [`crate::acl::apply_sandbox_aces`] chokepoint on
//! the handle-derived canonical path — the same residual
//! name-vs-handle window every other stamp site in this crate
//! accepts.
//!
//! ## Exclusions
//!
//! A candidate is skipped when it is, or sits under: a static
//! ambient-deny target (already floor-denied and recompose-folded),
//! a recorded ambient path, a live session write GRANT (the session
//! deliberately opened it for sandbox writes), or the machine state
//! dir. Matching is case-insensitive, extended-prefix-agnostic
//! prefix matching on whole path components. Session READ grants
//! are deliberately NOT excluded — currently safe because the audit
//! deny leaves read+execute open (its mask carries no read bits),
//! but note the ordering-dependent edge: a read-granted dir that is
//! also world-writable WILL be write-deny-stamped.
//!
//! ## Session-tracking decision
//!
//! Audit denies are recorded as ORDINARY session `deny_audit` rows
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
//! holder dies. Two deliberate deviations from ordinary denies:
//! `apply_aces` stamps NO parent `deny_fdc` ACE for the audit kind
//! (audit parents — the drive root's dirs, `%TEMP%`'s parent, deep
//! `PATH` ancestors — can be huge trees, and materializing an
//! inheritable ACE across them at every session start is unbounded
//! cost the scan budgets don't cover; the flagged dir's own
//! `(OI)(CI)` deny covers the planting threat and its DELETE bit
//! covers rename-away — see the rationale comment in
//! `state_db::apply_aces`); and an audit deny YIELDS to a live
//! session write grant on the same path at the recompose chokepoint
//! (`SbAceSet::head_aces`) — foreground grant intent beats the
//! background floor, so one session's audit hold cannot break
//! another session's workspace.

use anyhow::{Context, Result};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use crate::acl::{self, SbAce};
use crate::path_id::{is_path_prefix, is_unc_path, strip_extended_prefix};
use crate::state_db::{self, HolderPid, RecoveryReport};

/// Wall-clock budget for the whole scan.
const WALL_BUDGET: Duration = Duration::from_secs(2);
/// Maximum candidate DACL probes (open + read) per audit.
const MAX_DACL_READS: u32 = 50_000;
/// Maximum entries consumed per enumerated root directory. `pub`
/// (unlike the other limits) because the CLI's partial-coverage
/// summary names it.
pub const MAX_DIR_ENTRIES: usize = 1_000;

/// The trustees whose ALLOW ACEs make a directory "world-writable":
/// Everyone, BUILTIN\Users, Authenticated Users. Every local
/// account — the sandbox user included — is a member of all three
/// (Everyone/Authenticated Users by definition; BUILTIN\Users
/// because provisioning adds the account to it for profile loads).
const FLAGGED_SIDS: [&str; 3] = [
    acl::SID_EVERYONE,
    acl::SID_BUILTIN_USERS,
    acl::SID_AUTHENTICATED_USERS,
];

/// Whether an ACE with `flags` applies to the directory itself (an
/// `INHERIT_ONLY` ACE does not — it grants nothing on the
/// container, only on future children).
fn ace_applies_to_container(flags: u8) -> bool {
    flags & acl::INHERIT_ONLY_ACE == 0
}

/// Whether `mask` makes a directory writable for its trustee: the
/// specific `FILE_ADD_FILE`/`FILE_ADD_SUBDIRECTORY` bits, a generic
/// bit the object's mapping resolves to include them
/// (`GENERIC_WRITE`/`GENERIC_ALL`) — or `WRITE_DAC`/`WRITE_OWNER`,
/// which are write-equivalent: an `Everyone:(WDAC)` dir lets any
/// member rewrite the DACL and grant itself write.
fn mask_grants_dir_write(mask: u32) -> bool {
    const DIR_WRITE: u32 = acl::Mask::FILE_ADD_FILE
        .with(acl::Mask::FILE_ADD_SUBDIRECTORY)
        .with(acl::Mask::GENERIC_WRITE)
        .with(acl::Mask::GENERIC_ALL)
        .with(acl::Mask::WRITE_DAC)
        .with(acl::Mask::WRITE_OWNER)
        .bits();
    mask & DIR_WRITE != 0
}

/// True iff `p` is lexically a plain local drive path (`X:\…`,
/// optionally `\\?\`-prefixed) — NOT UNC in any spelling, NOT a
/// device path, NOT relative. This runs BEFORE any filesystem
/// syscall on the path: merely `stat`ing a UNC path sends the
/// broker's credentials to the named host.
fn lexically_local_drive_path(p: &str) -> bool {
    if is_unc_path(p) {
        return false;
    }
    // `\\.\PIPE\x` and friends survive is_unc_path; the drive-letter
    // shape check rejects them (first byte is `\`).
    crate::util::drive_letter_root(strip_extended_prefix(p)).is_some()
}

// ─── Budget ─────────────────────────────────────────────────────────

/// Scan budget + coverage accounting: a wall-clock deadline, a
/// DACL-probe cap, and every per-class skip counter — one struct so
/// there is a single source of truth: [`scan`] owns it while
/// running and moves it into [`AuditOutcome::budget`] when done
/// (serialized as the JSON `budget` object). The arithmetic is pure
/// bookkeeping (no Win32) so it is unit-testable; the limits are
/// injected for tests via [`Budget::with_limits`].
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Budget {
    #[serde(skip)]
    deadline: Instant,
    #[serde(skip)]
    max_dacl_reads: u32,
    /// The wall-clock budget expired mid-scan.
    pub(crate) wall_expired: bool,
    /// Candidate DACL probes performed.
    pub(crate) dacl_reads: u32,
    /// The DACL-probe cap was hit.
    pub(crate) dacl_exhausted: bool,
    /// Candidates never probed because a budget ran out first.
    #[serde(rename = "skipped")]
    pub(crate) skipped_budget: u32,
    /// Enumerated roots whose listing hit [`MAX_DIR_ENTRIES`].
    pub(crate) dirs_truncated: u32,
    /// Candidates whose probe failed for a reason other than
    /// not-found (access denied on the open, unreadable SD, …), plus
    /// enumeration roots whose listing failed to open.
    pub(crate) unreadable: u32,
    /// Candidates skipped as reparse points (junction/symlink).
    pub(crate) reparse_skipped: u32,
    /// Candidates skipped as non-local: on a non-fixed drive, or
    /// whose handle-derived canonical path was not a plain local
    /// drive path (resolved onto a UNC target or a bare volume
    /// root).
    pub(crate) remote_skipped: u32,
    /// Enumeration ROOTS skipped whole because they are not local
    /// fixed-drive paths (e.g. a cwd on a mapped drive) — without
    /// this counter such a run would read as full coverage.
    pub(crate) roots_skipped_non_local: u32,
}

impl Budget {
    fn new() -> Self {
        Self::with_limits(WALL_BUDGET, MAX_DACL_READS)
    }

    fn with_limits(wall: Duration, max_dacl_reads: u32) -> Self {
        Self {
            deadline: Instant::now() + wall,
            max_dacl_reads,
            wall_expired: false,
            dacl_reads: 0,
            dacl_exhausted: false,
            skipped_budget: 0,
            dirs_truncated: 0,
            unreadable: 0,
            reparse_skipped: 0,
            remote_skipped: 0,
            roots_skipped_non_local: 0,
        }
    }

    /// Charge one DACL probe. `false` = out of budget (wall or
    /// count; the corresponding flag latches).
    fn try_charge_dacl_read(&mut self) -> bool {
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
    fn wall_expired_now(&mut self) -> bool {
        if !self.wall_expired && Instant::now() >= self.deadline {
            self.wall_expired = true;
        }
        self.wall_expired
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

/// A [`norm_key`] naming a bare drive root (`norm_key("C:\\") ==
/// "c:"`) — NEVER a candidate: the stock root's explicit `AU:(AD)`
/// ACE always flags, and stamping it would propagate an `(OI)(CI)`
/// deny across the entire volume.
fn is_drive_root_key(key: &str) -> bool {
    key.len() <= 2
}

/// Prefix set for "already covered" checks: a candidate equal to, or
/// strictly under, any entry is excluded from the audit. Pure (no
/// Win32) so the component-boundary matching is unit-testable.
struct Exclusions {
    prefixes: Vec<String>,
}

impl Exclusions {
    fn new(paths: impl IntoIterator<Item = String>) -> Self {
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
    fn covers(&self, path: &str) -> bool {
        self.covers_key(&norm_key(path))
    }

    /// As [`Self::covers`] for a caller that already normalized the
    /// candidate — [`norm_key`] runs once per candidate, not once
    /// per check.
    fn covers_key(&self, key: &str) -> bool {
        self.prefixes.iter().any(|p| is_path_prefix(p, key))
    }
}

// ─── Outcome ────────────────────────────────────────────────────────

/// What one audit did — every bounded/skipped class is counted so
/// the CLI summary can report exactly what was NOT covered (no
/// silent caps). Serialized as-is (camelCase) for `acl audit --json`;
/// the TS `WindowsWwAuditResult` interface mirrors this shape.
#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditOutcome {
    /// Candidate directories collected from the root set (post
    /// lexical filter + dedup + pre-probe exclusion check).
    pub(crate) candidates: u32,
    /// Candidates actually probed (open + DACL read).
    #[serde(rename = "scanned")]
    pub(crate) probed: u32,
    /// Canonical paths whose DACL grants write to a flagged SID
    /// (NULL-DACL hits included — those are detected, not stamped).
    pub(crate) flagged: Vec<String>,
    /// Flagged paths whose deny stamp landed (recorded + on disk).
    pub(crate) stamped: Vec<String>,
    /// Flagged paths left unstamped: the stamp failed (the broker
    /// lacks `WRITE_DAC` there, or the recompose failed) or was
    /// refused (NULL DACL).
    pub(crate) failed: Vec<FailedStamp>,
    /// How many of `failed` are NULL-DACL refusals (see module doc)
    /// — split out so the stderr summary can name the reason.
    pub(crate) null_dacl_refused: u32,
    /// Budget + coverage counters (the scan's [`Budget`], moved in
    /// whole at end of scan).
    pub(crate) budget: Budget,
}

/// One flagged path the audit did not stamp, with why.
#[derive(Debug, Serialize)]
pub struct FailedStamp {
    pub(crate) path: String,
    pub(crate) error: String,
}

// ─── Scan (Win32) ───────────────────────────────────────────────────

/// `GetDriveTypeW(X:\) == DRIVE_FIXED`, memoized per drive letter —
/// the scan asks once per candidate and most candidates share a
/// handful of drives, so children of a root validated in
/// [`push_children`] cost a map hit, not a syscall. Reads the local
/// mount table only — no network contact for remote/mapped letters.
#[derive(Default)]
struct FixedDriveCache(HashMap<u8, bool>);

impl FixedDriveCache {
    fn is_fixed(&mut self, path: &str) -> bool {
        use windows::Win32::Storage::FileSystem::GetDriveTypeW;
        let Some(root) = crate::util::drive_letter_root(strip_extended_prefix(path)) else {
            return false;
        };
        *self.0.entry(root.as_bytes()[0]).or_insert_with(|| {
            let w = crate::util::wstr(&root);
            unsafe { GetDriveTypeW(crate::util::pcwstr(&w)) == crate::util::DRIVE_FIXED }
        })
    }
}

/// Outcome of probing one candidate directory.
enum Probe {
    /// World-writable; carries the handle-derived canonical path
    /// and whether it flagged as a NULL DACL (detected, never
    /// stamped — see module doc).
    Flagged {
        canon: String,
        null_dacl: bool,
    },
    Clean,
    /// The object itself is a reparse point — never dereferenced.
    Reparse,
    /// Exists but is not a directory (stale `PATH` entry naming a
    /// file). Not an audit concern.
    NotDir,
    /// Canonical path resolved outside plain local-drive space — or
    /// onto a bare drive root (a `C:\.`-style spelling), which this
    /// module must never stamp.
    RemoteCanon,
}

/// Open `path` no-follow, reject reparse points, and read its DACL
/// BY HANDLE — see the module doc's reparse-hardening notes. The
/// open requests `READ_CONTROL` only, so it works on directories
/// the broker cannot write.
fn probe_dir(path: &str, flagged_sids: &[Vec<u8>]) -> Result<Probe> {
    use windows::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
        GetFileInformationByHandle,
    };
    let h = crate::path_id::open_for_metadata(
        path,
        acl::Mask::READ_CONTROL.bits(),
        /* no_follow */ true,
    )
    .with_context(|| format!("open '{path}' (no-follow)"))?;
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
    // Re-apply BOTH lexical guards to the HANDLE-DERIVED canonical
    // path. The pre-probe checks are lexical-only, so a `C:\.` or
    // `C:\foo\..` spelling (a real PATH-entry artifact) passes them
    // and resolves to the volume root HERE — every spelling funnels
    // through this one guard before the DACL is even read.
    if !lexically_local_drive_path(&canon) || is_drive_root_key(&norm_key(&canon)) {
        return Ok(Probe::RemoteCanon);
    }
    let (sd, dacl) =
        acl::read_handle_dacl(&h).with_context(|| format!("read DACL by handle '{path}'"))?;
    // A NULL DACL is "everyone: full control" — the most
    // world-writable a directory can be. `filter_aces` treats null
    // as an empty ACE list, so special-case it here.
    let null_dacl = dacl.is_null();
    let flagged = null_dacl || dacl_grants_world_write(dacl, flagged_sids)?;
    drop(sd);
    Ok(if flagged {
        Probe::Flagged { canon, null_dacl }
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
            || hdr.AceFlags & acl::INHERITED_ACE != 0
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
/// `budget`.
fn push_children(
    root: &str,
    candidates: &mut Vec<String>,
    seen: &mut HashSet<String>,
    budget: &mut Budget,
    drives: &mut FixedDriveCache,
) {
    if !lexically_local_drive_path(root) || !drives.is_fixed(root) {
        budget.roots_skipped_non_local += 1;
        return;
    }
    let rd = match std::fs::read_dir(root) {
        Ok(r) => r,
        Err(_) => {
            budget.unreadable += 1;
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
            budget.dirs_truncated += 1;
            return;
        }
        // `file_type()` comes from the enumeration record — no
        // extra open, and it reports reparse points as symlinks
        // WITHOUT following them.
        let Ok(ft) = ent.file_type() else { continue };
        if ft.is_symlink() {
            // Counted so the CI junction regression check has a
            // signal: a healthy run skips planted reparse points
            // HERE, before probe_dir ever sees them.
            budget.reparse_skipped += 1;
            continue;
        }
        if !ft.is_dir() {
            continue;
        }
        push_candidate(candidates, seen, ent.path().display().to_string());
    }
}

/// Dedup + lexical-filter one candidate path. NEVER a bare drive
/// root (see [`is_drive_root_key`]): a root can reach here via a
/// PATH entry of `C:\` (a common installer artifact) or
/// TEMP/PUBLIC set to a root. Lexical only — [`probe_dir`] re-runs
/// both guards on the handle-derived canonical path.
fn push_candidate(candidates: &mut Vec<String>, seen: &mut HashSet<String>, p: String) {
    if !lexically_local_drive_path(&p) {
        return;
    }
    let key = norm_key(&p);
    if is_drive_root_key(&key) {
        return;
    }
    if seen.insert(key) {
        candidates.push(p);
    }
}

/// Run the scan: collect candidates from the fixed root set, probe
/// each within `budget`, and return the outcome with `flagged`
/// filled, plus the subset to stamp (flagged minus NULL-DACL
/// refusals — stamping is the caller's step).
fn scan(exclusions: &Exclusions, mut budget: Budget) -> Result<(AuditOutcome, Vec<String>)> {
    let mut out = AuditOutcome::default();
    let mut to_stamp: Vec<String> = Vec::new();
    let flagged_sids: Vec<Vec<u8>> = FLAGGED_SIDS
        .iter()
        .map(|s| crate::sid::sid_bytes(s))
        .collect::<Result<_>>()?;
    let mut drives = FixedDriveCache::default();

    // ── Candidate collection ────────────────────────────────────
    let mut seen: HashSet<String> = HashSet::new();
    let mut candidates: Vec<String> = Vec::new();
    if let Some(sd) = std::env::var_os("SystemDrive") {
        let root = format!("{}\\", sd.to_string_lossy());
        push_children(&root, &mut candidates, &mut seen, &mut budget, &mut drives);
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
            &mut budget,
            &mut drives,
        );
    }

    // ── Probe ───────────────────────────────────────────────────
    let mut flagged_seen: HashSet<String> = HashSet::new();
    for cand in candidates {
        if exclusions.covers(&cand) {
            continue;
        }
        out.candidates += 1;
        // Memoized: a map hit for children whose root was already
        // validated in push_children; one real GetDriveTypeW per
        // first-seen letter (TEMP/PUBLIC/PATH entries).
        if !drives.is_fixed(&cand) {
            budget.remote_skipped += 1;
            continue;
        }
        if !budget.try_charge_dacl_read() {
            budget.skipped_budget += 1;
            continue;
        }
        out.probed += 1;
        match probe_dir(&cand, &flagged_sids) {
            Ok(Probe::Flagged { canon, null_dacl }) => {
                // Re-check exclusions on the CANONICAL path — 8.3
                // short names or case differences in the raw
                // candidate must not dodge the prefix match. One
                // norm_key per canonical path; the key doubles as
                // the dedup entry.
                let key = norm_key(&canon);
                if !exclusions.covers_key(&key) && flagged_seen.insert(key) {
                    if null_dacl {
                        // Detected, never stamped — see module doc.
                        out.null_dacl_refused += 1;
                        out.failed.push(FailedStamp {
                            path: canon.clone(),
                            error: "NULL DACL (everyone: full control); stamp refused — \
                                    recomposing would materialize a DACL that `acl \
                                    restore` cannot return to NULL"
                                .to_string(),
                        });
                        out.flagged.push(canon);
                    } else {
                        out.flagged.push(canon.clone());
                        to_stamp.push(canon);
                    }
                }
            }
            Ok(Probe::Clean) => {}
            Ok(Probe::Reparse) => budget.reparse_skipped += 1,
            Ok(Probe::NotDir) => {}
            Ok(Probe::RemoteCanon) => budget.remote_skipped += 1,
            Err(e) => {
                // Nonexistent candidates (stale PATH entries) are
                // normal; anything else is counted for the summary.
                if !crate::path_id::is_not_found(&e) {
                    budget.unreadable += 1;
                }
            }
        }
    }
    out.budget = budget;
    Ok((out, to_stamp))
}

/// Full audit. The session init lock is held only for the DB
/// touches, never across the scan: a first brief acquire runs crash
/// recovery (as every acquire does) and snapshots the DB-derived
/// exclusions; the scan itself — up to [`WALL_BUDGET`] of DACL
/// probes — runs UNLOCKED so concurrent brokers' `acl` ops are not
/// stalled behind it; a second brief acquire applies the stamps
/// (skipped entirely when nothing needs stamping). A concurrent
/// session's write grant landing between snapshot and stamp is
/// benign: the audit deny yields to a live write grant at the
/// recompose chokepoint (see `SbAceSet::head_aces`).
///
/// Stamping is one [`crate::state_db::Locked::apply_aces`] call per
/// path so a failure (the broker lacks `WRITE_DAC` on a dir it does
/// not own) rolls back only that path and the rest still land.
/// Best-effort by design: per-path failures are collected in
/// [`AuditOutcome::failed`], never fatal.
pub fn audit_and_stamp(
    holder: HolderPid,
    sandbox_sid: &str,
) -> Result<(AuditOutcome, RecoveryReport)> {
    let (granted_writes, mut report) =
        state_db::with_init_lock(holder, false, |db| db.granted_write_paths())?;
    let mut excluded: Vec<String> = crate::ambient::ambient_deny_targets();
    excluded.extend(crate::install::ambient_recorded_paths().unwrap_or_default());
    excluded.extend(granted_writes);
    if let Ok(d) = state_db::machine_store_dir() {
        excluded.push(d.display().to_string());
    }
    let exclusions = Exclusions::new(excluded);
    let (mut out, to_stamp) = scan(&exclusions, Budget::new())?;
    if !to_stamp.is_empty() {
        let ((), stamp_report) = state_db::with_init_lock(holder, false, |db| {
            for canon in to_stamp {
                match db.apply_aces(sandbox_sid, &[(canon.clone(), SbAce::DenyAudit)]) {
                    Ok((_, 0)) => out.stamped.push(canon),
                    // apply_aces already printed the per-path warning
                    // and rolled this path's fresh rows back.
                    Ok((_, _failed)) => out.failed.push(FailedStamp {
                        path: canon,
                        error: "stamp failed (see warning above); left unstamped".to_string(),
                    }),
                    Err(e) => out.failed.push(FailedStamp {
                        path: canon,
                        error: format!("{e:#}"),
                    }),
                }
            }
            Ok(())
        })?;
        // The second acquire runs crash recovery again (normally a
        // no-op right after the first); report the total.
        report.dead_brokers += stamp_report.dead_brokers;
        report.aces_revoked += stamp_report.aces_revoked;
    }
    Ok((out, report))
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
        // Write-equivalent security rights flag too: WRITE_DAC /
        // WRITE_OWNER let the trustee grant itself write.
        assert!(mask_grants_dir_write(0x0004_0000)); // WRITE_DAC
        assert!(mask_grants_dir_write(0x0008_0000)); // WRITE_OWNER
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
        assert!(b.dacl_exhausted);
        assert!(!b.wall_expired);
        assert_eq!(b.dacl_reads, 2);
        // Wall expiry latches without charging.
        let mut b = Budget::with_limits(Duration::ZERO, 100);
        assert!(b.wall_expired_now());
        assert!(!b.try_charge_dacl_read());
        assert!(b.wall_expired);
        assert_eq!(b.dacl_reads, 0);
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
        // WRITE_DAC- / WRITE_OWNER-only world grants are
        // write-equivalent (the trustee can grant itself write).
        assert!(check("D:(A;OICI;0x40000;;;WD)")); // WRITE_DAC
        assert!(check("D:(A;OICI;0x80000;;;WD)")); // WRITE_OWNER
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
