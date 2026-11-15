//! Install-time state: the sandbox-user **credential** (DPAPI
//! ciphertext), the **setup marker**, and the optional **MITM CA**
//! (DER), in the machine store (`state_db::machine_store_dir()`).
//!
//! Written by the elevated `srt-win install` step (after
//! [`crate::user::provision`]) and read by the non-elevated broker
//! at `srt-win exec` / `srt-win user status` time.
//!
//! The store is `HKLM\SOFTWARE\sandbox-runtime` ([`crate::reg`]):
//! identity + marker under the default admin-write/users-read DACL,
//! the DPAPI credential blob in the `Cred` subkey (Users read-only,
//! sandbox DENY), the CA record in the `Ca` subkey (user-recordable
//! for unelevated trust-ca, sandbox DENY). Only the managed CA key
//! material stays on the filesystem
//! ([`provision_machine_store`]).

use anyhow::{Context, Result, anyhow};
use windows::core::GUID;

use crate::state_db;
use crate::{dpapi, logon, runner, user};

/// Bumped when the `sandbox_user` row changes, when `install` gains a
/// step (v2: ambient stamps), or when an older broker must stop
/// launching here (v3: kept write grants). See [`check_marker`].
pub const SETUP_VERSION: u32 = 3;

/// `Err` unless `marker_version` is the one this build was made with.
/// The message is what `read_cred` callers print; it names the repair.
pub fn check_marker(marker_version: u32) -> Result<()> {
    if marker_version != SETUP_VERSION {
        return Err(anyhow!(
            "setup marker version mismatch (have {marker_version}, expected \
             {SETUP_VERSION}); re-run `srt-win install`",
        ));
    }
    Ok(())
}

/// Why a plain `install` must not replace an install with this marker
/// version (a newer build made it); `None` when it may proceed.
pub fn newer_setup_refusal(marker_version: u32) -> Option<String> {
    (marker_version > SETUP_VERSION).then(|| {
        format!(
            "existing install has setup version {marker_version}, newer than this \
             build's {SETUP_VERSION}; not replacing it. Use the release that made it, \
             or pass --force to replace it with this one."
        )
    })
}

/// The install record, only if its marker is this build's
/// ([`check_marker`]): required before launching or keeping a grant.
pub fn require_current_setup() -> Result<SetupInfo> {
    let info = read_setup()?.ok_or_else(|| {
        anyhow!(
            "no sandbox-user setup record in the state store — run \
             `srt-win install`"
        )
    })?;
    check_marker(info.marker_version)?;
    Ok(info)
}

#[derive(Debug, Clone)]
pub struct SetupInfo {
    pub sandbox_user: String,
    pub sandbox_user_sid: String,
    pub sandbox_group_sid: String,
    pub marker_version: u32,
    pub created_at_unix: u64,
}

/// Guard the one piece of install state that must stay on the
/// FILESYSTEM: `%ProgramData%\sandbox-runtime\ca\` — the managed
/// CA key material, which the broker's unelevated generate-if-absent
/// self-heal must be able to rewrite (so it cannot live under an
/// admin-only registry key). Everything else moved to
/// `HKLM\SOFTWARE\sandbox-runtime` ([`crate::reg`]), whose default
/// security model needs none of this.
///
/// `%ProgramData%`'s default DACL lets standard users pre-create
/// directories — including as junctions targeting a victim tree —
/// so the elevated install takes ownership and rewrites the DACL
/// by HANDLE with no-follow semantics (a planted reparse point is
/// removed, never followed). The DACL is deliberately multi-user:
/// SYSTEM/Administrators full; BUILTIN\Users modify (the ca\
/// self-heal); sandbox group explicit DENY (the CA key must not be
/// readable from inside the sandbox).
///
/// Accepted trade-off (decided): any REAL local user can read or
/// replace the CA key material. The sandbox account is
/// network-confined by SID-keyed WFP filters regardless of who
/// spawns it, and concurrently-interactive multi-user machines are
/// rare.
pub fn provision_machine_store(sandbox_group_sid: &str) -> Result<std::path::PathBuf> {
    let dir = state_db::machine_store_dir()?;
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("create machine state dir {}", dir.display()))?;
    let dir_str = dir
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("machine state dir is not UTF-8"))?;
    if !crate::util::enable_privilege("SeTakeOwnershipPrivilege")? {
        anyhow::bail!("SeTakeOwnershipPrivilege not held — machine store requires elevation");
    }
    crate::util::enable_privilege("SeRestorePrivilege")?;
    let h = match crate::acl::open_for_security_no_follow(dir_str) {
        Ok(h) => h,
        Err(e) if format!("{e:#}").contains("reparse point") => {
            std::fs::remove_dir(&dir)
                .with_context(|| format!("remove planted reparse point {}", dir.display()))?;
            std::fs::create_dir_all(&dir)
                .with_context(|| format!("recreate machine state dir {}", dir.display()))?;
            crate::acl::open_for_security_no_follow(dir_str)?
        }
        Err(e) => return Err(e),
    };
    crate::acl::set_handle_owner_admins(&h, "machine state dir")
        .context("take ownership of machine state dir")?;
    // 0x1301bf = FILE_GENERIC_READ|WRITE|EXECUTE + DELETE ("modify"
    // minus FILE_DELETE_CHILD).
    let sddl = format!(
        "D:P(D;OICI;FA;;;{sandbox_group_sid})\
         (A;OICI;FA;;;SY)\
         (A;OICI;FA;;;BA)\
         (A;OICI;0x1301bf;;;BU)"
    );
    crate::acl::set_handle_dacl_from_sddl(&h, &sddl, "machine state dir")?;
    drop(h);
    // Pre-registry alpha builds kept install.db/cred.dat here —
    // best-effort cleanup so stale copies don't linger.
    for f in [
        "cred.dat",
        "install.db",
        "install.db-wal",
        "install.db-shm",
        "state.db",
        "state.db-wal",
        "state.db-shm",
    ] {
        let _ = std::fs::remove_file(dir.join(f));
    }
    Ok(dir)
}

/// Record the install: identity + marker into
/// `HKLM\SOFTWARE\sandbox-runtime` and the DPAPI credential blob
/// into its `Cred` subkey (created with an explicit
/// SYSTEM/Admins-full, Users-read, sandbox-DENY DACL — atomic with
/// creation, and nothing unprivileged can pre-create a key under
/// HKLM\SOFTWARE). `MarkerVersion` is written LAST: registry writes
/// are not transactional across values, so the marker is the commit
/// point a crashed install never reaches.
pub fn write_setup(u: &user::ProvisionedUser) -> Result<()> {
    let blob = dpapi::protect_machine(u.password.as_bytes())?;
    let (base, _) = crate::reg::Key::create(crate::reg::BASE, None)?;
    // A --force re-install under a DIFFERENT sandbox-user name must
    // drop the recorded CA: the cert was written into the OLD
    // account's CurrentUser\Root hive, so keeping the record for
    // the new account would make the trust reconcile skip a re-trust
    // that has never happened (schannel then fails at runtime
    // instead of being healed at setup).
    let name_changed = base
        .get_sz("SandboxUser")?
        .is_some_and(|old| old != u.username);
    let cred_sddl = format!(
        "O:BAD:P(D;;KA;;;{})(A;;KA;;;SY)(A;;KA;;;BA)(A;;KR;;;BU)",
        u.group_sid
    );
    let cred = crate::reg::ensure_key_with_dacl(crate::reg::CRED_SUBKEY, &cred_sddl)?;
    cred.set_binary("Blob", &blob)?;
    // Ca subkey: Users KEY_READ|KEY_SET_VALUE (0x2001b) so the
    // unelevated trust-ca can record the DER; sandbox group DENY so
    // the CHILD cannot touch the record.
    let ca_sddl = format!(
        "O:BAD:P(D;;KA;;;{})(A;;KA;;;SY)(A;;KA;;;BA)(A;;0x2001b;;;BU)",
        u.group_sid
    );
    let ca = crate::reg::ensure_key_with_dacl(crate::reg::CA_SUBKEY, &ca_sddl)?;
    if name_changed {
        crate::reg::delete_value(&ca, "Der")?;
    }
    base.set_sz("SandboxUser", &u.username)?;
    base.set_sz("SandboxUserSid", &u.sid)?;
    base.set_sz("SandboxGroupSid", &u.group_sid)?;
    base.set_qword(
        "CreatedAt",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    )?;
    base.set_dword("MarkerVersion", SETUP_VERSION)?;
    Ok(())
}

/// Outcome of [`set_ambient_denies`].
#[derive(Debug, Default)]
pub struct AmbientReport {
    /// Paths whose deny ACE is on disk (freshly stamped or
    /// re-converged on re-install).
    pub applied: Vec<String>,
    /// Paths whose stamp failed (odd system DACL even with
    /// `SeRestorePrivilege`). `status` shows `present: false`, and
    /// a later install retries.
    pub failed: Vec<String>,
}

/// The recorded ambient-deny target list (HKLM `AmbientDenies`
/// MULTI_SZ). Empty when no install has run. Admin-written, so
/// trustworthy as read.
pub fn ambient_recorded_paths() -> Result<Vec<String>> {
    let Some(base) = crate::reg::Key::open(crate::reg::BASE, false)? else {
        return Ok(Vec::new());
    };
    Ok(base.get_multi_sz("AmbientDenies")?.unwrap_or_default())
}

/// Whether `canon` is a recorded ambient deny target — the
/// recompose fold-in predicate. Errors read as "not recorded"
/// (fail-open for the DENY floor is bounded: the next install
/// re-records and re-applies).
pub fn ambient_deny_recorded(canon: &str) -> bool {
    ambient_recorded_paths()
        .map(|v| v.iter().any(|p| p == canon))
        .unwrap_or(false)
}

/// Whether the install-time ambient write-deny step is complete:
/// every CURRENT target is both recorded and carrying its on-disk
/// deny ACE. An install that died mid-list falls through the
/// install early-out and finishes the remainder; "re-run `srt-win
/// install`" is the repair for on-disk drift. Targets that no
/// longer canonicalize are ignored; any error reads as incomplete
/// (the idempotent install steps just run).
pub fn ambient_complete(sandbox_sid: &str, raw_targets: &[String]) -> bool {
    let recorded = match ambient_recorded_paths() {
        Ok(v) => v,
        Err(_) => return false,
    };
    raw_targets.iter().all(|raw| {
        let Ok((canon, _)) = crate::path_id::canonicalize_path(raw) else {
            return true;
        };
        recorded.contains(&canon)
            && crate::acl::sandbox_deny_present(&canon, sandbox_sid).unwrap_or(false)
    })
}

/// Stamp the ambient write-denies: apply `(D;OICI;WriteDeny)` for
/// the sandbox SID DIRECTLY on each static env-derived target (per
/// path best-effort), then record the applied set in the registry.
/// Under the session init lock so a live broker's recompose in this
/// TS session cannot interleave a converge that misses the fresh
/// deny; SeRestorePrivilege enabled for TrustedInstaller-owned
/// targets.
pub fn set_ambient_denies(sandbox_sid: &str, raw_paths: &[String]) -> Result<AmbientReport> {
    let _lock = state_db::acquire_session_lock()?;
    if let Err(e) = crate::util::enable_privilege("SeRestorePrivilege") {
        eprintln!("srt-win: ambient deny: enable SeRestorePrivilege: {e:#}");
    }
    let mut report = AmbientReport::default();
    let deny_only = crate::acl::SbAceSet {
        deny: Some(crate::acl::DenyMask::WriteDeny),
        ..Default::default()
    };
    let mut recorded = ambient_recorded_paths()?;
    for raw in raw_paths {
        let canon = match crate::path_id::canonicalize_path(raw) {
            Ok((c, _)) => c,
            Err(e) => {
                eprintln!("srt-win: warning: ambient deny target '{raw}': {e:#}");
                report.failed.push(raw.clone());
                continue;
            }
        };
        match crate::acl::apply_sandbox_aces(&canon, sandbox_sid, deny_only) {
            Ok(()) => {
                if !recorded.contains(&canon) {
                    recorded.push(canon.clone());
                }
                report.applied.push(canon);
            }
            Err(e) => {
                eprintln!("srt-win: warning: ambient deny stamp '{canon}': {e:#}");
                report.failed.push(canon);
            }
        }
    }
    let (base, _) = crate::reg::Key::create(crate::reg::BASE, None)?;
    base.set_multi_sz("AmbientDenies", &recorded)?;
    Ok(report)
}

/// Remove the ambient write-denies (uninstall): per RECORDED path
/// (admin-written list — trustworthy), strip the sandbox SID's ACEs
/// directly; a failed removal keeps its entry so `status` surfaces
/// it and a later uninstall/install retries. Returns how many paths
/// actually carried a deny that was removed. Same lock + privilege
/// preamble as [`set_ambient_denies`].
pub fn clear_ambient_denies(sandbox_sid: &str) -> Result<usize> {
    let _lock = state_db::acquire_session_lock()?;
    if let Err(e) = crate::util::enable_privilege("SeRestorePrivilege") {
        eprintln!("srt-win: ambient deny: enable SeRestorePrivilege: {e:#}");
    }
    let recorded = ambient_recorded_paths()?;
    let mut removed = 0usize;
    let mut kept: Vec<String> = Vec::new();
    for canon in recorded {
        let had = crate::acl::sandbox_deny_present(&canon, sandbox_sid).unwrap_or(false);
        match crate::acl::apply_sandbox_aces(&canon, sandbox_sid, crate::acl::SbAceSet::default()) {
            Ok(()) => {
                if had {
                    removed += 1;
                }
            }
            Err(e) => {
                eprintln!("srt-win: warning: ambient deny removal '{canon}': {e:#}");
                kept.push(canon);
            }
        }
    }
    if let Some(base) = crate::reg::Key::open(crate::reg::BASE, true)? {
        base.set_multi_sz("AmbientDenies", &kept)?;
    }
    if !kept.is_empty() {
        eprintln!(
            "srt-win: warning: {} ambient deny path(s) could not be \
             cleared and stay recorded (retry via uninstall/install)",
            kept.len(),
        );
    }
    Ok(removed)
}

/// Read the install record from `HKLM\SOFTWARE\sandbox-runtime`.
/// `Ok(None)` when no install has run (key or marker absent). The
/// values are trustworthy as read: only administrators can write
/// them (HKLM\SOFTWARE default DACL), which is what deleted the
/// SAM cross-validation an earlier %ProgramData% file store needed.
pub fn read_setup() -> Result<Option<SetupInfo>> {
    let Some(base) = crate::reg::Key::open(crate::reg::BASE, false)? else {
        return Ok(None);
    };
    let (Some(marker_version), Some(sandbox_user), Some(sandbox_user_sid), Some(sandbox_group_sid)) = (
        base.get_dword("MarkerVersion")?,
        base.get_sz("SandboxUser")?,
        base.get_sz("SandboxUserSid")?,
        base.get_sz("SandboxGroupSid")?,
    ) else {
        // Partial write (install crashed before the marker commit
        // point) or manual tamper by an admin — either way the
        // repair is re-running the elevated install.
        return Ok(None);
    };
    Ok(Some(SetupInfo {
        sandbox_user,
        sandbox_user_sid,
        sandbox_group_sid,
        marker_version,
        created_at_unix: base.get_qword("CreatedAt")?.unwrap_or(0),
    }))
}

/// Registry value (MULTI_SZ): one `<sublayer guid>=<mode>` line per
/// sublayer whose filters an install wrote; an uninstall removes the line.
const LOOPBACK_MODES_VALUE: &str = "LoopbackModes";

const MODE_OPEN: &str = "open";
const MODE_CLOSED: &str = "closed";
/// The mode while an install replaces a set with the other mode: it
/// reads as an error, so nothing is launched until the install is done.
const MODE_CHANGING: &str = "changing";

fn sublayer_key(sublayer: &GUID) -> String {
    let d = sublayer.data4;
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        sublayer.data1,
        sublayer.data2,
        sublayer.data3,
        d[0],
        d[1],
        d[2],
        d[3],
        d[4],
        d[5],
        d[6],
        d[7]
    )
}

/// Parse the record lines; a line without `=` is dropped.
fn parse_loopback_modes(lines: &[String]) -> Vec<(String, String)> {
    lines
        .iter()
        .filter_map(|l| {
            let (k, v) = l.split_once('=')?;
            Some((k.to_ascii_lowercase(), v.to_string()))
        })
        .collect()
}

/// `modes` with `key` set to `mode` (`None` removes it), as lines to store.
fn loopback_modes_with(
    mut modes: Vec<(String, String)>,
    key: &str,
    mode: Option<&str>,
) -> Vec<String> {
    modes.retain(|(k, _)| k != key);
    if let Some(mode) = mode {
        modes.push((key.to_string(), mode.to_string()));
    }
    modes.iter().map(|(k, v)| format!("{k}={v}")).collect()
}

/// The loopback mode sandboxed commands run under, over every recorded
/// sublayer: open only if each is open (one closed set's BLOCK applies
/// to all), closed with no record. Any other word is an error, never "closed".
fn effective_loopback(modes: &[(String, String)]) -> Result<bool> {
    if let Some((k, v)) = modes
        .iter()
        .find(|(_, v)| v != MODE_OPEN && v != MODE_CLOSED)
    {
        return Err(anyhow!(
            "recorded loopback mode '{v}' (sublayer {k}) is not one this build knows"
        ));
    }
    Ok(!modes.is_empty() && modes.iter().all(|(_, v)| v == MODE_OPEN))
}

fn set_loopback_mode(sublayer: &GUID, mode: Option<&str>) -> Result<()> {
    let base = match mode {
        Some(_) => crate::reg::Key::create(crate::reg::BASE, None)?.0,
        None => match crate::reg::Key::open(crate::reg::BASE, true)? {
            Some(base) => base,
            None => return Ok(()),
        },
    };
    let modes = parse_loopback_modes(&base.get_multi_sz(LOOPBACK_MODES_VALUE)?.unwrap_or_default());
    let lines = loopback_modes_with(modes, &sublayer_key(sublayer), mode);
    base.set_multi_sz(LOOPBACK_MODES_VALUE, &lines)
}

/// Record the loopback mode of the filters committed under `sublayer`.
/// Call only AFTER the WFP transaction commits.
pub fn write_loopback_mode(sublayer: &GUID, open: bool) -> Result<()> {
    set_loopback_mode(sublayer, Some(if open { MODE_OPEN } else { MODE_CLOSED }))
}

/// Mark `sublayer`'s mode as changing, BEFORE its filters are replaced
/// with the other mode's.
pub fn mark_loopback_mode_changing(sublayer: &GUID) -> Result<()> {
    set_loopback_mode(sublayer, Some(MODE_CHANGING))
}

/// Drop `sublayer`'s recorded mode; every path that deletes its filters calls this.
pub fn clear_loopback_mode(sublayer: &GUID) -> Result<()> {
    set_loopback_mode(sublayer, None)
}

fn read_loopback_modes() -> Result<Vec<(String, String)>> {
    Ok(match crate::reg::Key::open(crate::reg::BASE, false)? {
        Some(base) => {
            parse_loopback_modes(&base.get_multi_sz(LOOPBACK_MODES_VALUE)?.unwrap_or_default())
        }
        None => Vec::new(),
    })
}

/// The mode recorded for `sublayer` alone; `Ok(None)` with no line.
pub fn read_loopback_mode(sublayer: &GUID) -> Result<Option<bool>> {
    let key = sublayer_key(sublayer);
    let own: Vec<_> = read_loopback_modes()?
        .into_iter()
        .filter(|(k, _)| *k == key)
        .collect();
    Ok(if own.is_empty() {
        None
    } else {
        Some(effective_loopback(&own)?)
    })
}

/// Whether the install record says loopback is open for sandboxed
/// commands ([`effective_loopback`]); `Ok(false)` with no install.
pub fn read_allow_loopback() -> Result<bool> {
    effective_loopback(&read_loopback_modes()?)
}

/// `Err` (operator-facing text) unless the session's loopback mode is
/// the one the install record has; a difference either way is refused.
pub fn require_allow_loopback(configured: bool) -> std::result::Result<(), String> {
    let installed = read_allow_loopback().map_err(|e| format!("read loopback mode: {e:#}"))?;
    if installed == configured {
        Ok(())
    } else {
        Err(crate::wfp::loopback_mismatch_hint(installed, configured))
    }
}

/// Read the recorded MITM CA (DER), if `srt-win user trust-ca`
/// ever ran. `Ok(None)` when no install has run or no CA
/// is recorded.
pub fn read_ca_cert() -> Result<Option<crate::cert_store::CertDer>> {
    let Some(ca) = crate::reg::Key::open(crate::reg::CA_SUBKEY, false)? else {
        return Ok(None);
    };
    match ca.get_binary("Der")? {
        // Round-trip through the parser so a corrupted stored value
        // reads as an error, not a poisoned CertDer.
        Some(der) => Ok(Some(crate::cert_store::CertDer::from_pem_or_der(&der)?)),
        None => Ok(None),
    }
}

/// Decrypted sandbox-user credential, as the broker needs it for
/// the two-hop launch. Zeroed on drop so the cleartext doesn't
/// linger past the `CreateProcessWithLogonW` call.
pub struct SandboxCred {
    pub user: String,
    pub pw: String,
}

impl Drop for SandboxCred {
    fn drop(&mut self) {
        // SAFETY: writing zeros into the String's bytes keeps it
        // valid UTF-8.
        unsafe { self.pw.as_mut_vec() }.fill(0);
    }
}

/// Decrypt and return the sandbox user's credential. Fails if the
/// caller cannot read the `Cred` key — by design, the sandbox user
/// is DENY'd on it (and on the store directory) and so cannot call
/// this to learn its own password.
pub fn read_cred() -> Result<SandboxCred> {
    let info = require_current_setup()?;
    let blob = read_cred_blob()?;
    let pw = String::from_utf8(dpapi::unprotect(&blob)?).context("password is not UTF-8")?;
    Ok(SandboxCred {
        user: info.sandbox_user,
        pw,
    })
}

/// The DPAPI blob from `HKLM\...\Cred\Blob`. A missing key/value
/// means the install is incomplete; the repair is the elevated
/// re-run either way.
pub(crate) fn read_cred_blob() -> Result<Vec<u8>> {
    let key = crate::reg::Key::open(crate::reg::CRED_SUBKEY, false)?.ok_or_else(|| {
        anyhow!(
            "no credential key (HKLM\\{}) — run `srt-win install` \
             (elevated) to (re)provision it",
            crate::reg::CRED_SUBKEY,
        )
    })?;
    key.get_binary("Blob")?.ok_or_else(|| {
        anyhow!(
            "credential key present but Blob value missing — re-run \
             `srt-win install` (elevated)"
        )
    })
}

/// Whether the credential blob exists AND decrypts — the
/// `cred_present` half of `srt-win user status`, and the credential
/// term of the install early-out. Readable by every real user,
/// which is the point of the shared credential: a SYSTEM/fleet
/// install must read as present from an ordinary user's session.
/// The DPAPI round-trip keeps self-heal working if the machine
/// DPAPI master key is ever lost (plain re-install rewrites the
/// blob instead of early-outing on a present-but-undecryptable one).
pub fn cred_present() -> bool {
    read_cred_blob()
        .and_then(|b| dpapi::unprotect(&b))
        .map(|pw| !pw.is_empty())
        .unwrap_or(false)
}

/// Write `der` into the **sandbox user's** `CurrentUser\Root` via a
/// one-shot `CreateProcessWithLogonW(srt-sandbox, "srt-win runner")`
/// carrying [`runner::RunnerCmd::InstallCa`], and — only on success
/// — record it in the `sandbox_user.ca_cert` column. The state-DB
/// record is what the host's `tlsTerminate` gate keys on, so it must
/// only exist when the registry write actually landed. Called only
/// from `srt-win user trust-ca` (with [`read_cred`]); `srt-win
/// install` never touches the CA. Persistent until `srt-win
/// uninstall` deletes the profile.
pub fn trust_ca(der: &crate::cert_store::CertDer, cred: &SandboxCred, sb_sid: &str) -> Result<()> {
    let code = logon::spawn_runner(
        &cred.user,
        &cred.pw,
        sb_sid,
        None,
        &runner::RunnerCmd::InstallCa { der: der.clone() },
        false,
        None,
    )
    .context("spawn runner for CA install")?;
    if code != 0 {
        return Err(anyhow!(
            "CA install runner exited {code} — the registry write \
             into the sandbox user's hive failed; CA NOT recorded"
        ));
    }
    // Set-value open, not KEY_WRITE: trust-ca runs UNELEVATED, and
    // the Ca DACL grants Users exactly KEY_READ|KEY_SET_VALUE.
    let ca = crate::reg::Key::open_for_set_value(crate::reg::CA_SUBKEY)?
        .ok_or_else(|| anyhow!("CA key absent — run `srt-win install` first"))?;
    ca.set_binary("Der", der.as_bytes())
}

/// Remove the install record: identity, marker, credential, and CA
/// record go with the account. Idempotent. When ambient-deny
/// removal left failed entries recorded ([`clear_ambient_denies`]'s
/// retry contract — `status` surfaces them and a later
/// uninstall/install retries), the base key and `AmbientDenies`
/// value survive; otherwise the whole tree is deleted.
pub fn clear_setup() -> Result<()> {
    let kept = ambient_recorded_paths()?;
    if kept.is_empty() {
        return crate::reg::delete_tree();
    }
    crate::reg::delete_subtree(crate::reg::CRED_SUBKEY)?;
    crate::reg::delete_subtree(crate::reg::CA_SUBKEY)?;
    if let Some(base) = crate::reg::Key::open(crate::reg::BASE, true)? {
        for v in [
            "SandboxUser",
            "SandboxUserSid",
            "SandboxGroupSid",
            "MarkerVersion",
            "CreatedAt",
            LOOPBACK_MODES_VALUE,
        ] {
            crate::reg::delete_value(&base, v)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wfp::DEFAULT_SUBLAYER_GUID;

    const A: &str = "2c5d0ad6-5f3b-4d4e-9b8f-1a3e7c9d0b21";
    const B: &str = "7d3c1a52-6e0b-4f8a-b1d4-2a9c5e7f3b60";

    fn modes(v: &[&str]) -> Vec<(String, String)> {
        parse_loopback_modes(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn sublayer_key_is_the_lowercase_guid() {
        assert_eq!(sublayer_key(&DEFAULT_SUBLAYER_GUID), A);
    }

    #[test]
    fn one_sublayer_changes_only_its_own_line() {
        let both = [format!("{A}=closed"), format!("{B}=open")];
        let got = loopback_modes_with(modes(&[&both[0], &both[1]]), A, Some(MODE_OPEN));
        assert_eq!(got, [format!("{B}=open"), format!("{A}=open")]);
        // An uninstall removes the line and leaves the other.
        let got = loopback_modes_with(modes(&[&both[0], &both[1]]), A, None);
        assert_eq!(got, [format!("{B}=open")]);
        // A key is matched whatever its case; a line without `=` is dropped.
        let upper = format!("{}=open", A.to_uppercase());
        assert_eq!(modes(&[&upper, "junk"]), modes(&[&format!("{A}=open")]));
    }

    #[test]
    fn loopback_is_open_only_when_every_recorded_set_is() {
        // No record: nothing installed, or a set from before the record.
        assert!(!effective_loopback(&[]).unwrap());
        assert!(effective_loopback(&modes(&[&format!("{A}=open")])).unwrap());
        assert!(!effective_loopback(&modes(&[&format!("{A}=closed")])).unwrap());
        // One closed set's BLOCK applies to every sandboxed connect.
        let mixed = modes(&[&format!("{A}=open"), &format!("{B}=closed")]);
        assert!(!effective_loopback(&mixed).unwrap());
    }

    #[test]
    fn a_mode_that_is_changing_or_unknown_is_an_error_not_closed() {
        for word in [MODE_CHANGING, "1", ""] {
            let m = modes(&[&format!("{A}=open"), &format!("{B}={word}")]);
            assert!(effective_loopback(&m).is_err(), "{word:?}");
        }
    }

    #[test]
    fn only_this_builds_marker_version_passes() {
        assert!(check_marker(SETUP_VERSION).is_ok());
        // Only a newer install is refused; an older one is upgraded.
        assert!(newer_setup_refusal(SETUP_VERSION).is_none());
        assert!(newer_setup_refusal(SETUP_VERSION - 1).is_none());
        let why = newer_setup_refusal(SETUP_VERSION + 1).unwrap();
        assert!(why.contains("newer than this build's"), "{why}");
        for other in [0, SETUP_VERSION - 1, SETUP_VERSION + 1, 99] {
            let e = check_marker(other).unwrap_err().to_string();
            assert!(e.contains("marker version mismatch"), "{e}");
            assert!(e.contains("re-run `srt-win install`"), "{e}");
        }
    }
}
