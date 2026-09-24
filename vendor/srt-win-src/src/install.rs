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

use crate::state_db;
use crate::{dpapi, logon, runner, user};

/// Bumped on schema-incompatible changes to the `sandbox_user`
/// row, or when `install` gains a step existing installs must pick
/// up (v2: ambient write-deny stamps — `ambient.rs`). The broker
/// compares this to the on-disk marker and refuses with a "re-run
/// `srt-win install`" message on mismatch; `install` treats a stale
/// marker as a partial install and completes the missing steps.
pub const SETUP_VERSION: u32 = 2;

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
    let info = read_setup()?.ok_or_else(|| {
        anyhow!(
            "no sandbox-user setup record in the state store — run \
             `srt-win install`"
        )
    })?;
    if info.marker_version != SETUP_VERSION {
        return Err(anyhow!(
            "setup marker version mismatch (have {}, expected {}); \
             re-run `srt-win install`",
            info.marker_version,
            SETUP_VERSION,
        ));
    }
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
        ] {
            crate::reg::delete_value(&base, v)?;
        }
    }
    Ok(())
}
