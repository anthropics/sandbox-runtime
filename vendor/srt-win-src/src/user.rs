//! Sandbox user account lifecycle.
//!
//! `srt-win install` provisions a dedicated local user
//! ([`SANDBOX_USER`]) and a local group ([`SANDBOX_GROUP`]) that
//! holds it. The sandboxed child runs **as that user** (via
//! `CreateProcessWithLogonW` from a non-elevated broker), so its
//! token carries a different user SID and a fresh logon session —
//! which structurally closes the surrogate-spawn class (schtasks,
//! `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`, BITS, RunAs="Interactive
//! User" COM) that a same-user restricted token cannot.
//!
//! This module is the **provisioning** half only: create/delete the
//! account, set/rotate its password, hide it from the logon UI, and
//! report status. The runner that actually launches the child under
//! this account lives in [`crate::runner`] / [`crate::logon`].
//!
//! ## Why a group AND a user
//!
//! [`SANDBOX_GROUP`] is the trustee for the credential-file DENY
//! ACE. Keying that on the *group* rather than the user SID means a
//! future multi-account design (e.g. per-session sandbox users)
//! only adds members; the DACLs don't change.

use anyhow::{Context, Result, anyhow, bail};
use serde::Serialize;
use std::ffi::c_void;
use windows::Win32::Foundation::ERROR_FILE_NOT_FOUND;
use windows::Win32::NetworkManagement::NetManagement::{
    NERR_PasswordTooShort, NERR_UserExists, NERR_UserNotFound, NetApiBufferFree, NetUserAdd,
    NetUserDel, NetUserGetInfo, NetUserModalsGet, NetUserSetInfo, UF_DONT_EXPIRE_PASSWD, UF_SCRIPT,
    USER_INFO_1, USER_INFO_1003, USER_INFO_1008, USER_MODALS_INFO_0, USER_PRIV_USER,
};
use windows::Win32::Security::Cryptography::{BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom};
use windows::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_READ, KEY_SET_VALUE, REG_DWORD, RegCloseKey, RegDeleteValueW,
    RegOpenKeyExW, RegQueryValueExW,
};
use windows::Win32::UI::Shell::DeleteProfileW;
use windows::core::{PCWSTR, PWSTR};

use crate::util::{pcwstr, wstr};
use crate::{sam, sid};

/// Default name for the dedicated local account the sandboxed child
/// runs as. Overridable at install time via `--sandbox-user`; the
/// active name is recorded in the setup marker
/// ([`crate::install::read_setup`]).
pub const SANDBOX_USER: &str = "srt-sandbox";

/// Local group that holds [`SANDBOX_USER`]. Trustee for the
/// credential-file DENY ACE.
pub const SANDBOX_GROUP: &str = "sandbox-runtime-users";

/// Result of [`provision`] — the password is returned in clear so
/// the caller can DPAPI-encrypt and persist it; it is not stored
/// anywhere by this module.
#[derive(Debug)]
pub struct ProvisionedUser {
    pub username: String,
    /// `S-1-5-21-…` of [`SANDBOX_USER`].
    pub sid: String,
    /// `S-1-5-21-…` of [`SANDBOX_GROUP`].
    pub group_sid: String,
    /// 32 chars, freshly generated on every [`provision`] call (so
    /// re-running install rotates it).
    pub password: String,
}

/// Result of [`status`]. Every field is independently observed so a
/// half-provisioned state (e.g. user exists but not in the group) is
/// surfaced rather than collapsed to a single boolean.
#[derive(Debug, Serialize)]
pub struct UserStatus {
    /// The account name that was queried (from the setup marker, or
    /// [`SANDBOX_USER`] when no install has run).
    pub name: String,
    pub exists: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    pub group_exists: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_sid: Option<String>,
    /// In `BUILTIN\Users` — required for interactive logon rights.
    pub in_builtin_users: bool,
    /// In [`SANDBOX_GROUP`].
    pub in_sandbox_group: bool,
    /// Winlogon `SpecialAccounts\UserList\srt-sandbox` = 0.
    pub hidden_from_logon: bool,
}

const WINLOGON_USERLIST: &str =
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList";

/// `BUILTIN\Users` — well-known SID that's stable across locales,
/// unlike the *name* "Users" / "Benutzer" / "Utilisateurs".
const SID_BUILTIN_USERS: &str = "S-1-5-32-545";

/// Create [`SANDBOX_GROUP`] and the local user `name` (idempotent),
/// set a fresh random password (rotated only if `we_own_it` — see
/// [`ensure_user`]), add the user to `BUILTIN\Users` and
/// [`SANDBOX_GROUP`], hide it from the Winlogon user-picker, and
/// return both SIDs plus the password.
///
/// `we_own_it` — the setup marker records `name` as the account a
/// prior `srt-win install` created. When false, a pre-existing
/// principal by that name is refused rather than adopted.
///
/// Requires elevation (NetUserAdd → `ERROR_ACCESS_DENIED` otherwise).
pub fn provision(name: &str, we_own_it: bool) -> Result<ProvisionedUser> {
    sam::ensure_local_group(SANDBOX_GROUP, "sandbox-runtime sandbox-user group")?;
    let password = ensure_user(name, we_own_it)?;

    // Resolve the freshly-created user's SID so group membership is
    // added by PSID — see [`sam::add_member`].
    let sid = sid::lookup_account_sid(name).context("resolve sandbox user SID")?;
    let user_psid = sid::LocalPsid::from_string(&sid)?;

    // BUILTIN\Users membership is required for the account to hold
    // the interactive-logon right that `CreateProcessWithLogonW`
    // depends on. Resolve the **localised** group name from the
    // well-known SID so this works on non-English Windows.
    let builtin_users =
        sid::lookup_account_name(SID_BUILTIN_USERS).context("resolve BUILTIN\\Users name")?;
    sam::add_member(&builtin_users, &user_psid)?;
    sam::add_member(SANDBOX_GROUP, &user_psid)?;

    set_logon_ui_hidden(name, true)?;

    let group_sid = sid::lookup_account_sid(SANDBOX_GROUP).context("resolve sandbox group SID")?;
    apply_logon_denials(&group_sid).context("stamp logon-type denials on the sandbox group")?;
    Ok(ProvisionedUser {
        username: name.into(),
        sid,
        group_sid,
        password,
    })
}

/// Delete `name`'s roaming/local profile (best-effort), the account
/// itself, [`SANDBOX_GROUP`], and the Winlogon hide value.
/// Idempotent — every step tolerates already-absent state.
pub fn deprovision(name: &str) -> Result<()> {
    // LSA account-rights entries would linger in the policy DB after
    // the group SID is deleted; strip them first. Best-effort — the
    // group may already be gone on a re-run.
    if let Ok(gsid) = sid::lookup_account_sid(SANDBOX_GROUP)
        && let Err(e) = remove_logon_denials(&gsid)
    {
        eprintln!("srt-win: warning: removing logon denials: {e:#}");
    }
    // Profile delete needs the SID *string*; resolve before
    // NetUserDel removes the SAM mapping. Failure to resolve (user
    // already gone) is fine — no profile to delete.
    if let Ok(s) = sid::lookup_account_sid(name) {
        let sid_w = wstr(&s);
        // Best-effort: profile may never have been created (no
        // `LOGON_WITH_PROFILE` yet), or may be locked by a stuck
        // child. Either way the account delete below still works.
        unsafe {
            let _ = DeleteProfileW(pcwstr(&sid_w), PCWSTR::null(), PCWSTR::null());
        }
    }
    let user_w = wstr(name);
    let rc = unsafe { NetUserDel(PCWSTR::null(), pcwstr(&user_w)) };
    if rc != 0 && rc != NERR_UserNotFound {
        return Err(anyhow!("NetUserDel({name}): {rc}"));
    }
    sam::delete_local_group(SANDBOX_GROUP)?;
    // Best-effort: the key may never have been created.
    let _ = set_logon_ui_hidden(name, false);
    Ok(())
}

/// Observe each piece of `name`'s provisioned state independently.
/// Does not require elevation.
pub fn status(name: &str) -> Result<UserStatus> {
    let sid = sid::lookup_account_sid(name).ok();
    let group_sid = sid::lookup_account_sid(SANDBOX_GROUP).ok();
    let in_builtin_users = sid
        .as_deref()
        .map(|s| sam::is_member_of(SID_BUILTIN_USERS, s))
        .transpose()?
        .unwrap_or(false);
    let in_sandbox_group = match (&sid, &group_sid) {
        (Some(u), Some(g)) => sam::is_member_of(g, u)?,
        _ => false,
    };
    Ok(UserStatus {
        name: name.into(),
        exists: sid.is_some(),
        sid,
        group_exists: group_sid.is_some(),
        group_sid,
        in_builtin_users,
        in_sandbox_group,
        hidden_from_logon: is_logon_ui_hidden(name),
    })
}

// ────────────────────── internals ──────────────────────

/// 32 characters drawn uniformly from an 85-symbol alphabet via
/// `BCryptGenRandom` (system CSPRNG). Excludes characters that
/// quoting layers between here and `CreateProcessWithLogonW` are
/// known to mishandle (`"`, `\`, ``` ` ```, whitespace) and the
/// shell-special `&|<>^` set, so the password survives any cmd /
/// PowerShell relay the runner spec may go through. ≈ 32 × log₂ 85
/// ≈ 205 bits; Windows local-account max length is 127.
fn gen_password() -> Result<String> {
    const ALPHA: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                           abcdefghijklmnopqrstuvwxyz\
                           0123456789!#$%()*+,-./:;=?@[]_{}~";
    const N: usize = 32;
    const { assert!(ALPHA.len() == 85) };
    let mut raw = [0u8; N];
    let st = unsafe { BCryptGenRandom(None, &mut raw, BCRYPT_USE_SYSTEM_PREFERRED_RNG) };
    if st.0 != 0 {
        return Err(anyhow!("BCryptGenRandom: NTSTATUS=0x{:08x}", st.0));
    }
    // Rejection sample so each output byte is a uniform pick from
    // ALPHA (85 doesn't divide 256). One refill is overwhelmingly
    // enough — the loop is a correctness backstop, not a hot path.
    let bound = (u8::MAX - (u8::MAX % ALPHA.len() as u8)) as usize;
    let mut out = Vec::with_capacity(N);
    let mut i = 0usize;
    while out.len() < N {
        if i == raw.len() {
            let st = unsafe { BCryptGenRandom(None, &mut raw, BCRYPT_USE_SYSTEM_PREFERRED_RNG) };
            if st.0 != 0 {
                return Err(anyhow!("BCryptGenRandom (refill): NTSTATUS=0x{:08x}", st.0));
            }
            i = 0;
        }
        let b = raw[i] as usize;
        i += 1;
        if b < bound {
            out.push(ALPHA[b % ALPHA.len()]);
        }
    }
    // Belt-and-suspenders for tightened complexity policies: if any of
    // the four classes is absent, seed four consecutive positions
    // (random base offset) with one forced pick from each. The retry
    // loop in [`ensure_user`] is the primary defence; this makes the
    // first attempt overwhelmingly likely to pass on its own.
    const CLASSES: [&[u8]; 4] = [
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        b"abcdefghijklmnopqrstuvwxyz",
        b"0123456789",
        b"!#$%()*+,-./:;=?@[]_{}~",
    ];
    if CLASSES.iter().any(|c| !out.iter().any(|b| c.contains(b))) {
        let mut extra = [0u8; 5];
        let st = unsafe { BCryptGenRandom(None, &mut extra, BCRYPT_USE_SYSTEM_PREFERRED_RNG) };
        if st.0 != 0 {
            return Err(anyhow!("BCryptGenRandom (seed): NTSTATUS=0x{:08x}", st.0));
        }
        let base = extra[0] as usize;
        for (k, class) in CLASSES.iter().enumerate() {
            out[(base + k) % N] = class[extra[1 + k] as usize % class.len()];
        }
    }
    Ok(String::from_utf8(out).expect("ALPHA is ASCII"))
}

/// `NetUserAdd(level=1)` if absent; on `NERR_UserExists`,
/// `NetUserSetInfo(level=1003)` to rotate the password and
/// `NetUserSetInfo(level=1008)` to OR `UF_DONT_EXPIRE_PASSWD` into
/// the existing flags. Either way the account ends up with the
/// returned password and a non-expiring password — even if an older
/// build or a domain GPO cleared the flag since the previous install.
///
/// Both password-bearing calls retry on `NERR_PasswordTooShort`
/// (2245) with a fresh [`gen_password`] draw — despite the name, SAM
/// returns 2245 for *any* local-policy rejection (complexity /
/// history / filter DLL), so a policy tightened between builds can
/// bounce an otherwise-valid 32-char draw.
///
/// `we_own_it` — the setup marker records `name` as an account a
/// prior install created. When **false**, any principal that already
/// resolves under `name` (local user, group, alias, domain
/// principal) is refused rather than adopted: srt-win will not
/// rotate the password of an account it didn't create.
fn ensure_user(name: &str, we_own_it: bool) -> Result<String> {
    let mut name_w = wstr(name);
    // Ownership guard runs FIRST, before any mutation, via
    // `LookupAccountNameW` (resolves users, groups, aliases, domain
    // principals alike) — so the friendly message is emitted
    // regardless of which rc `NetUserAdd` would return for the name
    // (`NERR_UserExists`/`NERR_GroupExists`/`ERROR_ALIAS_EXISTS`
    // vary by kind). Not-found → create path.
    if !we_own_it && sid::lookup_account_sid(name).is_ok() {
        bail!(
            "account '{name}' already exists and was not created by \
             srt-win. Pick a different --sandbox-user name (or omit \
             it for the default '{SANDBOX_USER}', which srt-win \
             manages)."
        );
    }
    let mut comment_w = wstr("sandbox-runtime sandboxed-child account");
    // Bound in the header (defense-in-depth) *and* in the inner
    // `attempt + 1 < MAX_PW_ATTEMPTS` guards — the last iteration
    // falls through to the standard error branches, and if a future
    // edit widens the guard the header still stops the loop.
    for attempt in 0..MAX_PW_ATTEMPTS {
        let password = gen_password().context("generate sandbox password")?;
        let mut pw_w = wstr(&password);
        let info = USER_INFO_1 {
            usri1_name: PWSTR(name_w.as_mut_ptr()),
            usri1_password: PWSTR(pw_w.as_mut_ptr()),
            usri1_password_age: 0,
            usri1_priv: USER_PRIV_USER,
            usri1_home_dir: PWSTR::null(),
            usri1_comment: PWSTR(comment_w.as_mut_ptr()),
            // UF_SCRIPT is required by SAM on workstation SKUs (legacy
            // LAN-Manager flag); without it NetUserAdd returns
            // NERR_BadUsername / ERROR_INVALID_PARAMETER.
            usri1_flags: UF_SCRIPT | UF_DONT_EXPIRE_PASSWD,
            usri1_script_path: PWSTR::null(),
        };
        let rc = unsafe { NetUserAdd(PCWSTR::null(), 1, &info as *const _ as *const u8, None) };
        if rc == 0 {
            return Ok(password);
        }
        if rc == NERR_PasswordTooShort && attempt + 1 < MAX_PW_ATTEMPTS {
            diag_2245("NetUserAdd", attempt, &password);
            continue;
        }
        if rc != NERR_UserExists {
            return Err(anyhow!("NetUserAdd({name}): {rc}"));
        }
        // Already exists — rotate the password so the credential file
        // about to be (re)written matches.
        let info1003 = USER_INFO_1003 {
            usri1003_password: PWSTR(pw_w.as_mut_ptr()),
        };
        let rc = unsafe {
            NetUserSetInfo(
                PCWSTR::null(),
                pcwstr(&name_w),
                1003,
                &info1003 as *const _ as *const u8,
                None,
            )
        };
        if rc == NERR_PasswordTooShort && attempt + 1 < MAX_PW_ATTEMPTS {
            diag_2245("NetUserSetInfo(1003)", attempt, &password);
            continue;
        }
        if rc != 0 {
            return Err(anyhow!(
                "NetUserSetInfo({name}, level=1003 password rotate): {rc}"
            ));
        }
        ensure_dont_expire(name, &name_w)?;
        return Ok(password);
    }
    bail!(
        "ensure_user({name}): password rejected by local policy after \
         {MAX_PW_ATTEMPTS} attempts (NERR_PasswordTooShort=2245)"
    )
}

const MAX_PW_ATTEMPTS: usize = 5;

/// Dump the local password policy and the failing password's class
/// composition (never the password itself) to stderr, so a 2245 on a
/// runner or a customer box is diagnosable from logs alone.
fn diag_2245(op: &str, attempt: usize, password: &str) {
    let (mut u, mut l, mut d, mut s) = (0u32, 0u32, 0u32, 0u32);
    for b in password.bytes() {
        match b {
            b'A'..=b'Z' => u += 1,
            b'a'..=b'z' => l += 1,
            b'0'..=b'9' => d += 1,
            _ => s += 1,
        }
    }
    let mut buf: *mut u8 = std::ptr::null_mut();
    let (min_len, hist) = if unsafe { NetUserModalsGet(PCWSTR::null(), 0, &mut buf) } == 0 {
        let m = unsafe { *(buf as *const USER_MODALS_INFO_0) };
        unsafe {
            let _ = NetApiBufferFree(Some(buf as *const c_void));
        }
        (
            m.usrmod0_min_passwd_len as i64,
            m.usrmod0_password_hist_len as i64,
        )
    } else {
        (-1, -1)
    };
    eprintln!(
        "srt-win: {op} 2245 (attempt {}/{MAX_PW_ATTEMPTS}) — policy: min_len={min_len} hist={hist}; \
         pw classes: U={u} L={l} D={d} S={s}; retrying",
        attempt + 1
    );
}

fn ensure_dont_expire(name: &str, name_w: &[u16]) -> Result<()> {
    // Re-assert UF_DONT_EXPIRE_PASSWD: read level-1 flags, OR in,
    // write back via level-1008 (flags only — level-1 SetInfo would
    // overwrite priv/home_dir/comment).
    let mut buf: *mut u8 = std::ptr::null_mut();
    let rc = unsafe { NetUserGetInfo(PCWSTR::null(), pcwstr(name_w), 1, &mut buf) };
    if rc != 0 {
        return Err(anyhow!("NetUserGetInfo({name}, level=1): {rc}"));
    }
    let cur_flags = unsafe { (*(buf as *const USER_INFO_1)).usri1_flags };
    unsafe {
        let _ = NetApiBufferFree(Some(buf as *const c_void));
    }
    let info1008 = USER_INFO_1008 {
        usri1008_flags: cur_flags | UF_DONT_EXPIRE_PASSWD,
    };
    let rc = unsafe {
        NetUserSetInfo(
            PCWSTR::null(),
            pcwstr(name_w),
            1008,
            &info1008 as *const _ as *const u8,
            None,
        )
    };
    if rc != 0 {
        return Err(anyhow!("NetUserSetInfo({name}, level=1008 flags): {rc}"));
    }
    Ok(())
}

/// Write (or delete) `HKLM\…\Winlogon\SpecialAccounts\UserList\<user>
/// = 0` so the account doesn't appear on the lock-screen user
/// picker. Cosmetic only — the account is still fully usable via
/// `CreateProcessWithLogonW`.
fn set_logon_ui_hidden(user: &str, hide: bool) -> Result<()> {
    if hide {
        crate::util::reg_set_value(
            HKEY_LOCAL_MACHINE,
            WINLOGON_USERLIST,
            user,
            REG_DWORD,
            &0u32.to_ne_bytes(),
        )?;
    } else {
        let sub_w = wstr(WINLOGON_USERLIST);
        let val_w = wstr(user);
        let mut hkey = HKEY::default();
        // Open (not create) — if the key was never made there's
        // nothing to delete.
        let r = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                pcwstr(&sub_w),
                None,
                KEY_SET_VALUE,
                &mut hkey,
            )
        };
        if r.is_err() {
            return Ok(());
        }
        unsafe {
            let _ = RegDeleteValueW(hkey, pcwstr(&val_w));
            let _ = RegCloseKey(hkey);
        }
    }
    Ok(())
}

fn is_logon_ui_hidden(user: &str) -> bool {
    let sub_w = wstr(WINLOGON_USERLIST);
    let val_w = wstr(user);
    let mut hkey = HKEY::default();
    let r = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            pcwstr(&sub_w),
            None,
            KEY_READ,
            &mut hkey,
        )
    };
    if r.is_err() {
        return false;
    }
    let mut data = [0u8; 4];
    let mut cb: u32 = 4;
    let r = unsafe {
        RegQueryValueExW(
            hkey,
            pcwstr(&val_w),
            None,
            None,
            Some(data.as_mut_ptr()),
            Some(&mut cb),
        )
    };
    unsafe {
        let _ = RegCloseKey(hkey);
    }
    // Hidden iff the value exists AND is 0 (a value of 1 explicitly
    // shows the account; absence = default = shown).
    r != ERROR_FILE_NOT_FOUND && r.is_ok() && cb == 4 && u32::from_ne_bytes(data) == 0
}

/// The logon-type denials stamped on [`SANDBOX_GROUP`]. Everything
/// except INTERACTIVE — which `CreateProcessWithLogonW`'s
/// `LOGON_WITH_PROFILE` logon performs and the sandbox launch
/// depends on (the account holds it via `BUILTIN\Users`).
///
/// - `SeDenyNetworkLogonRight`: the SMB redirector dials as SYSTEM
///   from kernel mode, so the SID-keyed WFP fence never classifies
///   its connects — red-teaming confirmed `net use \\127.0.0.1\IPC$`
///   succeeded from inside the sandbox, and the same mechanism
///   reaches remote shares (an exfil channel) and SMB-hosted RPC
///   pipes. SMB *authenticates* as the sandbox account though, so
///   denying it the network-logon right refuses the session at the
///   server regardless of which process carried the bytes.
///   CAVEAT (verified): LOOPBACK SMB stays reachable — NTLM
///   loopback auth reuses the client's existing logon session, so
///   no new network logon happens and the deny right never fires;
///   `LogonUser(NETWORK)` (what any REMOTE server's LSA runs)
///   returns 1385. Content behind loopback shares is still governed
///   by the same NTFS ACLs the sandbox is stamped with.
/// - `SeDenyBatchLogonRight`: a sandboxed child can REGISTER a
///   scheduled task (the service's DACL allows it); the task then
///   needs a batch logon to RUN. Denying it turns registration into
///   inert persistence-spam.
/// - `SeDenyServiceLogonRight` / `SeDenyRemoteInteractiveLogonRight`:
///   no legitimate flow runs the account as a service or over RDP.
const LOGON_DENIALS: [&str; 4] = [
    "SeDenyNetworkLogonRight",
    "SeDenyBatchLogonRight",
    "SeDenyServiceLogonRight",
    "SeDenyRemoteInteractiveLogonRight",
];

/// Open the local LSA policy, marshal [`LOGON_DENIALS`] as
/// LSA_UNICODE_STRINGs (each backed by its OWN allocation so the
/// pointers cannot dangle if the list grows), run `f`, and close the
/// policy on every path.
fn with_lsa_rights<F>(f: F) -> Result<()>
where
    F: FnOnce(
        windows::Win32::Security::Authentication::Identity::LSA_HANDLE,
        &[windows::Win32::Security::Authentication::Identity::LSA_UNICODE_STRING],
    ) -> windows::Win32::Foundation::NTSTATUS,
{
    use windows::Win32::Security::Authentication::Identity::{
        LSA_OBJECT_ATTRIBUTES, LSA_UNICODE_STRING, LsaClose, LsaNtStatusToWinError, LsaOpenPolicy,
        POLICY_CREATE_ACCOUNT, POLICY_LOOKUP_NAMES,
    };

    let attrs = LSA_OBJECT_ATTRIBUTES::default();
    let mut policy = Default::default();
    let status = unsafe {
        LsaOpenPolicy(
            None,
            &attrs,
            (POLICY_CREATE_ACCOUNT | POLICY_LOOKUP_NAMES) as u32,
            &mut policy,
        )
    };
    if status.is_err() {
        let gle = unsafe { LsaNtStatusToWinError(status) };
        anyhow::bail!("LsaOpenPolicy: win32 error {gle}");
    }
    // One owned buffer per right: growth of LOGON_DENIALS can never
    // invalidate an earlier entry's Buffer pointer.
    let bufs: Vec<(Vec<u16>, u16)> = LOGON_DENIALS
        .iter()
        .map(|r| crate::util::counted_utf16(r))
        .collect();
    let rights: Vec<LSA_UNICODE_STRING> = bufs
        .iter()
        .map(|(b, bytes)| LSA_UNICODE_STRING {
            Length: *bytes,
            MaximumLength: *bytes,
            Buffer: windows::core::PWSTR(b.as_ptr() as *mut u16),
        })
        .collect();
    let status = f(policy, &rights);
    let ret = if status.is_err() {
        let gle = unsafe { LsaNtStatusToWinError(status) };
        Err(anyhow::anyhow!(
            "LSA account-rights call: win32 error {gle}"
        ))
    } else {
        Ok(())
    };
    unsafe {
        let _ = LsaClose(policy);
    }
    ret
}

/// Stamp [`LOGON_DENIALS`] on `group_sid` via LSA policy. Idempotent
/// (adding an already-held right succeeds). Applied to the GROUP so
/// custom-named accounts (`--sandbox-user`) inherit without extra
/// plumbing. Local LSA policy — domain GPO can overwrite user-right
/// assignments on refresh, which is why the install path re-asserts
/// this on EVERY run (including the already-installed early-out),
/// not only at first provisioning.
pub fn apply_logon_denials(group_sid: &str) -> Result<()> {
    use windows::Win32::Security::Authentication::Identity::LsaAddAccountRights;
    let psid = sid::LocalPsid::from_string(group_sid)?;
    with_lsa_rights(|policy, rights| unsafe { LsaAddAccountRights(policy, psid.as_psid(), rights) })
        .context("LsaAddAccountRights")
}

/// Remove [`LOGON_DENIALS`] from `group_sid` (uninstall hygiene —
/// the group is deleted right after, but orphaned LSA account-rights
/// entries linger in the policy database otherwise). Best-effort.
pub fn remove_logon_denials(group_sid: &str) -> Result<()> {
    use windows::Win32::Security::Authentication::Identity::LsaRemoveAccountRights;
    let psid = sid::LocalPsid::from_string(group_sid)?;
    with_lsa_rights(|policy, rights| unsafe {
        LsaRemoveAccountRights(policy, psid.as_psid(), false, Some(rights))
    })
    .context("LsaRemoveAccountRights")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_shape() {
        let p = gen_password().expect("gen");
        assert_eq!(p.len(), 32);
        assert!(p.is_ascii());
        // No characters from the excluded set.
        for c in ['"', '\\', '`', ' ', '&', '|', '<', '>', '^'] {
            assert!(!p.contains(c), "password contains '{c}': {p}");
        }
        // At least one from each complexity class (post-seed guarantee).
        assert!(p.bytes().any(|b| b.is_ascii_uppercase()), "{p}");
        assert!(p.bytes().any(|b| b.is_ascii_lowercase()), "{p}");
        assert!(p.bytes().any(|b| b.is_ascii_digit()), "{p}");
        assert!(p.bytes().any(|b| !b.is_ascii_alphanumeric()), "{p}");
        // Two calls differ (overwhelmingly).
        assert_ne!(p, gen_password().unwrap());
    }

    #[test]
    fn builtin_users_name_resolves() {
        // The exact name is locale-dependent; just check it's
        // non-empty and round-trips back to the well-known SID.
        let name = sid::lookup_account_name(SID_BUILTIN_USERS).expect("name");
        assert!(!name.is_empty());
        let back = sid::lookup_account_sid(&name).expect("sid");
        assert_eq!(back, SID_BUILTIN_USERS);
    }

    #[test]
    fn status_for_absent_user_is_falsey() {
        // The CI smoke installs/uninstalls under the real names, so
        // here we only sanity-check that status() doesn't error and
        // its booleans agree with `exists`.
        let st = status(SANDBOX_USER).expect("status");
        assert_eq!(st.name, SANDBOX_USER);
        if !st.exists {
            assert!(st.sid.is_none());
            assert!(!st.in_builtin_users);
            assert!(!st.in_sandbox_group);
        }
    }
}
