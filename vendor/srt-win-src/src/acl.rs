//! ACL helpers for the sandbox-user FS model — `srt-win acl
//! stamp|grant|restore|revoke|recover`.
//!
//! The model is **additive explicit ACEs for the dedicated
//! `srt-sandbox` user SID**, never a `PROTECTED` rewrite or SD
//! snapshot:
//!
//! - `grant` ⇒ `(A;OICI;READ_EXEC|MODIFY_NO_FDC;;;<sb-SID>)` so the
//!   sandbox user (which has no inherent rights on real-user-owned
//!   files) can reach the working tree;
//! - `stamp` ⇒ `(D;OICI;mask;;;<sb-SID>)` on the target plus
//!   `(D;OICI;FILE_DELETE_CHILD;;;<sb-SID>)` on the parent;
//! - install-time ambient write-denies (`ambient.rs`) reuse the
//!   `stamp` deny shape, recorded in `ambient_denies` with no holder
//!   so they persist across sessions until `uninstall`.
//!
//! Restore = walk the path's explicit ACEs, drop any whose trustee
//! is `<sb-SID>`, write back preserving the DACL's protection state
//! (`UNPROTECTED` re-derives inherited ACEs; a `SE_DACL_PROTECTED`
//! path keeps its severed inheritance). The single chokepoint is
//! [`apply_sandbox_aces`] ([`SbAceSet`]): converge the path to
//! exactly the wanted ALLOW + DENY for `<sb-SID>`, idempotently.
//!
//! The PROTECTED allow-lists in [`set_path_dacl_from_sddl`]'s
//! callers are the ONE remaining `PROTECTED` consumer — they
//! protect the state stores from the sandbox child, not user
//! files. (Cross-broker serialization uses a file lock inside the
//! protected session dir, not a named mutex — named objects are
//! create-first squattable by a same-session sandbox child.)
//!
//! Globs are **rejected**. Directory targets get `(OI)(CI)` ACEs
//! so the additive grant/deny inherits to the whole subtree.
//!
//! With the write-restricted token (`crate::persist`) a write root is
//! granted once and the grant is kept between sessions. Such a root
//! carries a different ACE set, never one for the sandbox user SID —
//! see [`persistent_aces`].

use anyhow::{Context, Result, anyhow, bail};
use std::ffi::c_void;
use std::mem::size_of;
use windows::Win32::Security::Authorization::{
    GetNamedSecurityInfoW, SE_FILE_OBJECT, SetNamedSecurityInfoW,
};
use windows::Win32::Security::{
    ACE_FLAGS, ACE_HEADER, ACE_REVISION, ACL, ACL_REVISION, ACL_SIZE_INFORMATION,
    AclSizeInformation, AddAccessAllowedAceEx, AddAccessDeniedAceEx, AddAce, CONTAINER_INHERIT_ACE,
    DACL_SECURITY_INFORMATION, GetAce, GetAclInformation, GetLengthSid,
    GetSecurityDescriptorControl, InitializeAcl, InitializeSecurityDescriptor, OBJECT_INHERIT_ACE,
    OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    SE_DACL_PROTECTED, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR, SetSecurityDescriptorControl,
    SetSecurityDescriptorDacl, UNPROTECTED_DACL_SECURITY_INFORMATION,
};
use windows::Win32::Storage::FileSystem::{
    FILE_ALL_ACCESS, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ,
};
use windows::Win32::System::SystemServices::{
    ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE, SECURITY_DESCRIPTOR_REVISION,
};

use crate::sid::LocalPsid;
use crate::util::{OwnedSd, pcwstr, win32_ok, wstr};

/// Owner-Rights well-known SID. ANY ACE for this SID replaces
/// the kernel's implicit `READ_CONTROL|WRITE_DAC` grant to the
/// owner with exactly the ACE's mask.
pub const SID_OWNER_RIGHTS: &str = "S-1-3-4";
pub const SID_SYSTEM: &str = "S-1-5-18";
pub const SID_BUILTIN_ADMINS: &str = "S-1-5-32-544";
pub const SID_BUILTIN_USERS: &str = "S-1-5-32-545";

// ─── DACL builder primitives ────────────────────────────────────────
// The policy functions below declare ACE lists as `&[Allow]`; this
// section turns them into a self-owning ACL buffer. `Mask`'s field
// is private and `Allow::OWNER_RIGHTS` takes no mask, so neither a
// hex-typo (`0x0130_01bf` for `0x0013_01bf`) nor a mask-`0`
// `OWNER_RIGHTS` ACE (which `SetNamedSecurityInfoW` drops on write
// — a silent sandbox escape) is spellable from policy code.

/// Access mask. Construct via the named consts and
/// [`Mask::with`]/[`Mask::without`]; the inner `u32` is private so
/// hex literals at call sites are not possible.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Mask(u32);

impl Mask {
    // Standard rights.
    pub const DELETE: Self = Self(0x0001_0000);
    pub const READ_CONTROL: Self = Self(0x0002_0000);
    pub const WRITE_DAC: Self = Self(0x0004_0000);
    pub const SYNCHRONIZE: Self = Self(0x0010_0000);

    // Generic — resolved via the object's GENERIC_MAPPING.
    pub const GENERIC_ALL: Self = Self(0x1000_0000);

    // File/dir-specific.
    pub const FILE_DELETE_CHILD: Self = Self(0x0000_0040);
    pub const FILE_ALL: Self = Self(FILE_ALL_ACCESS.0);
    pub const FILE_WRITE_ATTRIBUTES: Self = Self(0x0000_0100);
    pub const FILE_GENERIC_READ: Self = Self(FILE_GENERIC_READ.0);
    pub const FILE_GENERIC_WRITE: Self =
        Self(windows::Win32::Storage::FileSystem::FILE_GENERIC_WRITE.0);
    pub const FILE_GENERIC_EXECUTE: Self = Self(FILE_GENERIC_EXECUTE.0);

    /// `FILE_GENERIC_READ | FILE_GENERIC_EXECUTE` — the
    /// [`GrantMask::ReadOnly`] mask.
    pub const FILE_READ_EXEC: Self = Self::FILE_GENERIC_READ.with(Self::FILE_GENERIC_EXECUTE);

    /// `FileSystemRights.Modify` MINUS `FILE_DELETE_CHILD` — the
    /// working-tree [`GrantMask::Modify`] mask granted to the
    /// sandbox-user SID via `acl grant`. The sandbox user can
    /// create/write/read/delete non-protected siblings (`DELETE`
    /// is in there) but `FILE_DELETE_CHILD` is withheld so a
    /// denied file inside the tree stays protected — the
    /// parent-FDC DENY (`SbAce::DenyFdc`) is evaluated first, but
    /// withholding it from the grant too is defense-in-depth.
    pub const MODIFY_NO_FDC: Self = Self::FILE_GENERIC_READ
        .with(Self::FILE_GENERIC_WRITE)
        .with(Self::FILE_GENERIC_EXECUTE)
        .with(Self::DELETE)
        .without(Self::FILE_DELETE_CHILD);

    /// `READ_CONTROL | WRITE_DAC` — what owning an object implicitly
    /// grants. Given explicitly to the real user on a persistent path
    /// (see [`persistent_aces`]).
    pub const OWNER_IMPLICIT: Self = Self::READ_CONTROL.with(Self::WRITE_DAC);

    pub const fn bits(self) -> u32 {
        self.0
    }
    pub const fn with(self, m: Self) -> Self {
        Self(self.0 | m.0)
    }
    pub const fn without(self, m: Self) -> Self {
        Self(self.0 & !m.0)
    }
}

impl std::ops::BitOr for Mask {
    type Output = Self;
    fn bitor(self, r: Self) -> Self {
        self.with(r)
    }
}

/// `(OI)(CI)` inheritance for directory-target ACEs.
pub const OICI: ACE_FLAGS = ACE_FLAGS(CONTAINER_INHERIT_ACE.0 | OBJECT_INHERIT_ACE.0);
/// No inheritance — the ACE applies to the object itself only.
pub const NO_INHERIT: ACE_FLAGS = ACE_FLAGS(0);

/// One row in an `&[Allow]` ACE list — `(SID, mask, inherit-flags)`.
/// The SID is a string so the policy function reads as an
/// SDDL-style table; [`build_allow_dacl`] does the
/// `ConvertStringSidToSidW` parsing once.
#[derive(Copy, Clone)]
pub struct Allow<'a>(pub &'a str, pub Mask, pub ACE_FLAGS);

impl Allow<'static> {
    /// The only `OWNER_RIGHTS` ACE this crate emits. Mask is fixed
    /// at `READ_CONTROL` — suppresses owner-implicit `WRITE_DAC`
    /// (so an owner-child cannot rewrite the DACL) while still
    /// letting the owner read it. **The mask must be non-zero**:
    /// `SetNamedSecurityInfoW` silently drops a mask-0 ALLOW ACE on
    /// write, so the conceptually-purer `OWNER_RIGHTS:0` never
    /// reaches disk. With this const + `Mask`'s private field, the
    /// mask-0 mistake is unspellable from policy code.
    pub const OWNER_RIGHTS: Self = Allow(SID_OWNER_RIGHTS, Mask::READ_CONTROL, NO_INHERIT);
}

/// Self-owning ACL: `buf` holds the `ACL` header + ACEs.
/// `AddAccessAllowedAceEx` copies SID bytes inline into each ACE
/// (`SidStart` embeds the SID — see the size calc in
/// [`build_allow_dacl`]), so once built `buf` is self-contained.
pub struct BuiltAcl {
    buf: Vec<u8>,
}

impl BuiltAcl {
    pub fn as_ptr(&self) -> *const ACL {
        self.buf.as_ptr() as *const ACL
    }

    /// Wrap this ACL in an absolute-format SD with `SE_DACL_PROTECTED`
    /// set, plus a `SECURITY_ATTRIBUTES` borrowing it — for
    /// `CreateMutexExW` and similar object-creation APIs that take
    /// a `*const SECURITY_ATTRIBUTES`. The returned [`OwnedSa`] owns
    /// the ACL, the SD, and the SA; pass [`OwnedSa::as_ptr`] and
    /// keep the [`OwnedSa`] alive until the call returns.
    ///
    /// No `O:`/`G:` (owner/group): an explicit owner SID at object
    /// creation goes through `SeAssignSecurity`, which rejects any
    /// owner that isn't the caller's user / an `SE_GROUP_OWNER`
    /// group / a `SeRestorePrivilege`-enabled token
    /// (`ERROR_INVALID_OWNER`); leaving them unset defaults
    /// owner/group to the caller, which is what we want.
    pub fn into_security_attributes(self) -> Result<OwnedSa> {
        let mut sd: Box<SECURITY_DESCRIPTOR> = Box::default();
        let psd = PSECURITY_DESCRIPTOR(&mut *sd as *mut _ as *mut c_void);
        unsafe {
            InitializeSecurityDescriptor(psd, SECURITY_DESCRIPTOR_REVISION)
                .context("InitializeSecurityDescriptor")?;
            SetSecurityDescriptorDacl(psd, true, Some(self.as_ptr()), false)
                .context("SetSecurityDescriptorDacl")?;
            SetSecurityDescriptorControl(psd, SE_DACL_PROTECTED, SE_DACL_PROTECTED)
                .context("SetSecurityDescriptorControl(PROTECTED)")?;
        }
        let sa = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: psd.0,
            bInheritHandle: false.into(),
        };
        Ok(OwnedSa {
            _acl: self,
            _sd: sd,
            sa,
        })
    }
}

/// A `SECURITY_ATTRIBUTES` with its backing SD and ACL. Heap-pins
/// the SD via `Box` so `sa.lpSecurityDescriptor` stays valid across
/// moves of the [`OwnedSa`] itself. Do not `Clone`.
pub struct OwnedSa {
    _acl: BuiltAcl,
    _sd: Box<SECURITY_DESCRIPTOR>,
    sa: SECURITY_ATTRIBUTES,
}

impl OwnedSa {
    pub fn as_ptr(&self) -> *const SECURITY_ATTRIBUTES {
        &self.sa
    }
}

/// Build an ALLOW-only DACL from an ACE table. Dedups by SID
/// (case-insensitive; first occurrence wins).
pub fn build_allow_dacl(aces: &[Allow<'_>]) -> Result<BuiltAcl> {
    // Parse SIDs first so the ACL sizing loop has the lengths.
    // Dedup by SID string (case-insensitive) — first wins.
    let mut seen = std::collections::HashSet::new();
    let parsed: Vec<(LocalPsid, u32, ACE_FLAGS)> = aces
        .iter()
        .filter(|Allow(s, _, _)| seen.insert(s.to_ascii_uppercase()))
        .map(|Allow(sid_str, m, fl)| {
            let sid = LocalPsid::from_string(sid_str)
                .with_context(|| format!("parse SID '{sid_str}'"))?;
            if unsafe { GetLengthSid(sid.as_psid()) } == 0 {
                bail!("GetLengthSid('{sid_str}') == 0");
            }
            Ok((sid, m.bits(), *fl))
        })
        .collect::<Result<_>>()?;
    let head: Vec<NewAce> = parsed
        .iter()
        .map(|(s, m, fl)| NewAce::Allow(s.as_psid(), *m, *fl))
        .collect();
    rebuild_acl(ACL_REVISION, &head, &(Vec::new(), 0, ACL_REVISION), &[])
}

/// Fixed prefix of `ACCESS_ALLOWED_ACE` / `ACCESS_DENIED_ACE`
/// (Header 4 + Mask 4); `SidStart` is the first DWORD of the SID.
const ACE_FIXED: usize = 8;

/// `n` rounded up to a DWORD boundary — `InitializeAcl` requires the
/// ACL buffer length to be DWORD-aligned.
const fn dword_align(n: usize) -> usize {
    (n + 3) & !3
}

/// One ACE to add at the head/tail of a [`rebuild_acl`] output.
/// `PSID` borrows the caller's SID buffer; keep it alive across the
/// call.
pub(crate) enum NewAce {
    Allow(PSID, u32, ACE_FLAGS),
    Deny(PSID, u32, ACE_FLAGS),
}

impl NewAce {
    fn sid(&self) -> PSID {
        let (Self::Allow(s, ..) | Self::Deny(s, ..)) = self;
        *s
    }
}

/// Size + `InitializeAcl(rev)` + `head` ACEs + `kept` raw ACEs +
/// `tail` ACEs → [`BuiltAcl`]. The single ACL-construction
/// chokepoint: [`build_allow_dacl`] (head only, `rev =
/// ACL_REVISION`), [`apply_sandbox_aces`] (head + kept, `rev` from
/// the source ACL via [`filter_aces`]), and `winsta::recompose_dacl`
/// (kept + tail) all thread through here.
///
/// `rev` MUST match the kept ACEs' source revision when `kept` is
/// non-empty (`AddAce` requires `ACL_REVISION_DS` when copying
/// object-type ACEs); pass [`KeptAces`].2.
pub(crate) fn rebuild_acl(
    rev: ACE_REVISION,
    head: &[NewAce],
    kept: &KeptAces,
    tail: &[NewAce],
) -> Result<BuiltAcl> {
    let mut total = size_of::<ACL>() + kept.1;
    for a in head.iter().chain(tail) {
        total += ACE_FIXED + unsafe { GetLengthSid(a.sid()) } as usize;
    }
    total = dword_align(total);
    let mut buf = vec![0u8; total];
    let acl = buf.as_mut_ptr() as *mut ACL;
    unsafe { InitializeAcl(acl, total as u32, rev) }.context("InitializeAcl")?;
    let add = |a: &NewAce| match *a {
        NewAce::Allow(s, m, f) => unsafe { AddAccessAllowedAceEx(acl, rev, f, m, s) }
            .with_context(|| format!("AddAccessAllowedAceEx({m:#x})")),
        NewAce::Deny(s, m, f) => unsafe { AddAccessDeniedAceEx(acl, rev, f, m, s) }
            .with_context(|| format!("AddAccessDeniedAceEx({m:#x})")),
    };
    head.iter().try_for_each(&add)?;
    for (ace, sz) in &kept.0 {
        unsafe { AddAce(acl, rev, u32::MAX, *ace, *sz as u32) }.context("AddAce(keep)")?;
    }
    tail.iter().try_for_each(&add)?;
    Ok(BuiltAcl { buf })
}

// ─── DACL read + ACE-walk primitives ────────────────────────────────
// Shared low-level wrappers so the recompose callers don't each
// open-code GetNamedSecurityInfoW + GetAce loops.
// `winsta.rs::recompose_dacl` uses `filter_aces` with its own
// predicate (it KEEPS inherited ACEs; the file caller here drops
// them).

/// Read a file's DACL via
/// `GetNamedSecurityInfoW(SE_FILE_OBJECT, DACL_SECURITY_INFORMATION)`.
/// The returned `*mut ACL` points INTO the returned `OwnedSd`'s
/// buffer — keep the `OwnedSd` alive while using the pointer.
pub(crate) fn read_file_dacl(canonical_path: &str) -> Result<(OwnedSd, *mut ACL)> {
    let w = wstr(canonical_path);
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut psd = PSECURITY_DESCRIPTOR::default();
    let r = unsafe {
        GetNamedSecurityInfoW(
            pcwstr(&w),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut dacl),
            None,
            &mut psd,
        )
    };
    win32_ok(r, &format!("GetNamedSecurityInfoW('{canonical_path}')"))?;
    Ok((OwnedSd::from_raw(psd), dacl))
}

/// Whether `sd`'s DACL carries `SE_DACL_PROTECTED` — inheritance from
/// the parent was deliberately severed (`icacls /inheritance:d`,
/// hardened trees). [`apply_sandbox_aces`] preserves this bit on
/// write-back: recomposing such a path with `UNPROTECTED_` would
/// silently re-enable inheritance, durably re-admitting the parent's
/// (often permissive — e.g. a data-drive root's `Authenticated
/// Users:(M)`) inheritable ACEs.
pub(crate) fn sd_dacl_protected(sd: &OwnedSd) -> Result<bool> {
    // The binding's `pcontrol` is a bare `*mut u16` (the wire shape
    // of `SECURITY_DESCRIPTOR_CONTROL`).
    let mut control: u16 = 0;
    let mut revision = 0u32;
    unsafe { GetSecurityDescriptorControl(sd.ptr, &mut control, &mut revision) }
        .context("GetSecurityDescriptorControl")?;
    Ok(control & SE_DACL_PROTECTED.0 != 0)
}

/// Whether [`write_file_dacl`] sets `PROTECTED_` (block inheritance
/// from the parent — the state-DB dir's allow-list, and
/// [`apply_sandbox_aces`] on a path whose DACL was already
/// protected) or `UNPROTECTED_DACL_SECURITY_INFORMATION` (re-derive
/// inherited ACEs from the parent — [`apply_sandbox_aces`] on the
/// common unprotected path).
pub(crate) enum Protection {
    Protected,
    Unprotected,
}

/// Write `acl` as `path`'s DACL via
/// `SetNamedSecurityInfoW(SE_FILE_OBJECT, DACL | <p>)`. Mirror of
/// [`read_file_dacl`].
pub(crate) fn write_file_dacl(path: &str, acl: *const ACL, p: Protection) -> Result<()> {
    let prot = match p {
        Protection::Protected => PROTECTED_DACL_SECURITY_INFORMATION,
        Protection::Unprotected => UNPROTECTED_DACL_SECURITY_INFORMATION,
    };
    let w = wstr(path);
    let r = unsafe {
        SetNamedSecurityInfoW(
            pcwstr(&w),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | prot,
            None,
            None,
            Some(acl),
            None,
        )
    };
    win32_ok(r, &format!("SetNamedSecurityInfoW('{path}')"))
}

/// `(kept ACE ptrs+sizes, Σ kept sizes, source AclRevision)`.
pub(crate) type KeptAces = (Vec<(*const c_void, u16)>, usize, ACE_REVISION);

/// Walk every ACE of `acl` and collect `(ptr, AceSize)` for those
/// `keep` accepts. Returns `(kept, Σ kept sizes, source AclRevision)`.
/// `acl == null` → `(∅, 0, ACL_REVISION)`. The kept pointers point
/// into `acl`'s buffer; caller must keep that buffer alive.
///
/// `keep` receives the raw `ACE_HEADER` and `body` = the full ACE
/// bytes (`hdr.AceSize` long, starting at the ACE pointer — so
/// `body[ACE_FIXED..]` is the embedded SID).
///
/// The source's `AclRevision` is returned so a caller building a
/// fresh ACL from kept ACEs can preserve it: `AddAce` requires
/// `ACL_REVISION_DS` (4) when copying object-type ACEs, and
/// `RtlValidAcl` rejects an ACL whose revision doesn't match its
/// ACEs.
pub(crate) fn filter_aces(
    acl: *const ACL,
    mut keep: impl FnMut(&ACE_HEADER, &[u8]) -> bool,
) -> Result<KeptAces> {
    if acl.is_null() {
        return Ok((Vec::new(), 0, ACL_REVISION));
    }
    let src_rev = ACE_REVISION(unsafe { (*acl).AclRevision } as u32);
    let mut info = ACL_SIZE_INFORMATION::default();
    unsafe {
        GetAclInformation(
            acl,
            &mut info as *mut _ as *mut c_void,
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
        .context("GetAclInformation")?;
    }
    let mut kept: Vec<(*const c_void, u16)> = Vec::new();
    let mut kept_sz = 0usize;
    for i in 0..info.AceCount {
        let mut ace: *mut c_void = std::ptr::null_mut();
        unsafe { GetAce(acl, i, &mut ace) }.map_err(|e| anyhow!("GetAce({i}): {e}"))?;
        if ace.is_null() {
            bail!("GetAce({i}) returned null");
        }
        let hdr = unsafe { &*(ace as *const ACE_HEADER) };
        let body = unsafe { std::slice::from_raw_parts(ace as *const u8, hdr.AceSize as usize) };
        if keep(hdr, body) {
            kept.push((ace as *const c_void, hdr.AceSize));
            kept_sz += hdr.AceSize as usize;
        }
    }
    Ok((kept, kept_sz, src_rev))
}

/// True iff `body[ACE_FIXED..]` starts with exactly `sid_bytes` —
/// i.e. the ACE's trustee SID is `sid_bytes`.
pub(crate) fn ace_sid_is(body: &[u8], sid_bytes: &[u8]) -> bool {
    body.get(ACE_FIXED..ACE_FIXED + sid_bytes.len()) == Some(sid_bytes)
}

/// Apply the broker-only DACL to a directory with `(OI)(CI)`
/// inheritance, optionally **prefixed** by a `(D;OICI;FA;;;
/// <deny_sid>)` ACE. Used by `state_db.rs` and `install.rs` to
/// protect `%LOCALAPPDATA%\sandbox-runtime\`.
///
/// `deny_sid` is the [`crate::user::SANDBOX_GROUP`] SID when the
/// sandbox user has been provisioned: the credential file in this
/// directory is encrypted with **machine-scope** DPAPI, which any
/// local account can decrypt — so the sandbox account MUST NOT be
/// able to read it. The real-user `PROTECTED` allow set already
/// excludes the sandbox user, but the explicit DENY makes that
/// intent visible in `Get-Acl` and survives any future widening of
/// the allow set.
///
/// Built via SDDL because [`build_allow_dacl`] only emits ALLOW
/// ACEs, and adding a generic DENY row to the [`Allow`] table
/// would invite misuse.
pub fn stamp_dir_inheriting(canonical_path: &str, deny_sid: Option<&str>) -> Result<()> {
    let deny = deny_sid
        .map(|s| format!("(D;OICI;FA;;;{s})"))
        .unwrap_or_default();
    // Trustee = the **real user** (the broker matches; the
    // `srt-sandbox` child does not). SY/BA = FILE_ALL `(OI)(CI)`;
    // OWNER_RIGHTS = READ_CONTROL `(OI)(CI)`. SDDL's `FA` =
    // `FILE_ALL_ACCESS`; `RC` = `READ_CONTROL`; `S-1-3-4` =
    // OWNER_RIGHTS. Canonical ACE order = DENY before ALLOW.
    let user_sid = crate::sid::current_user_sid()?;
    let sddl = format!(
        "D:P{deny}\
         (A;OICI;FA;;;{user_sid})\
         (A;OICI;FA;;;SY)\
         (A;OICI;FA;;;BA)\
         (A;OICI;RC;;;S-1-3-4)"
    );
    set_path_dacl_from_sddl(canonical_path, &sddl, "state-db dir")
}

/// SDDL → SD → DACL pointer → `SetNamedSecurityInfoW(PROTECTED)`.
/// One-shot helper for the few call sites that need a DENY ACE
/// (which the [`BuiltAcl`] machinery deliberately doesn't expose).
/// The `D:P` prefix in `sddl` is informational; `PROTECTED` is set
/// here regardless via `PROTECTED_DACL_SECURITY_INFORMATION`.
pub fn set_path_dacl_from_sddl(path: &str, sddl: &str, label: &str) -> Result<()> {
    use windows::Win32::Security::GetSecurityDescriptorDacl;
    let sd = crate::util::OwnedSd::from_sddl(sddl)
        .with_context(|| format!("{label}: build SD from SDDL"))?;
    let mut present = windows::core::BOOL::from(false);
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut defaulted = windows::core::BOOL::from(false);
    unsafe {
        GetSecurityDescriptorDacl(sd.ptr, &mut present, &mut dacl, &mut defaulted)
            .with_context(|| format!("{label}: GetSecurityDescriptorDacl"))?;
    }
    if !present.as_bool() || dacl.is_null() {
        bail!("{label}: SDDL '{sddl}' yielded no DACL");
    }
    write_file_dacl(path, dacl, Protection::Protected).context(label.to_owned())
}

/// Open `path` for security-descriptor writes with NO-FOLLOW
/// semantics and REJECT reparse points. `%ProgramData%`'s default
/// DACL lets standard users pre-create directories — including as
/// NTFS mount points / junctions targeting an arbitrary directory —
/// so an elevated install that take-owns and re-ACLs by NAME can be
/// redirected into re-ACLing a victim tree. Opening with
/// `FILE_FLAG_OPEN_REPARSE_POINT` pins the object itself (no
/// traversal), the attribute check rejects a planted reparse point,
/// and the returned HANDLE is what the security writes below
/// operate on — validate-then-use on the same object, not a name.
pub fn open_for_security_no_follow(path: &str) -> Result<crate::util::OwnedHandle> {
    use windows::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION;
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        GetFileInformationByHandle, OPEN_EXISTING,
    };
    let w = wstr(path);
    let h = unsafe {
        CreateFileW(
            pcwstr(&w),
            Mask::READ_CONTROL.bits() | Mask::WRITE_DAC.bits() | 0x0008_0000, // + WRITE_OWNER
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    }
    .with_context(|| format!("CreateFileW('{path}', no-follow)"))?;
    if h == INVALID_HANDLE_VALUE {
        bail!("CreateFileW('{path}'): INVALID_HANDLE_VALUE");
    }
    let owned = crate::util::OwnedHandle(h);
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    unsafe { GetFileInformationByHandle(owned.0, &mut info) }
        .with_context(|| format!("GetFileInformationByHandle('{path}')"))?;
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
        bail!(
            "'{path}' is a reparse point (junction/symlink) — refusing \
             to operate on a redirected store path; remove it and re-run"
        );
    }
    Ok(owned)
}

/// Set OWNER = `BUILTIN\Administrators` on an open handle (see
/// [`open_for_security_no_follow`] for why by-handle). Requires
/// `SeTakeOwnershipPrivilege`/`SeRestorePrivilege` enabled unless
/// the caller already owns the object.
pub fn set_handle_owner_admins(h: &crate::util::OwnedHandle, label: &str) -> Result<()> {
    use windows::Win32::Security::Authorization::{SE_FILE_OBJECT, SetSecurityInfo};
    let admins = crate::sid::LocalPsid::from_string(SID_BUILTIN_ADMINS)?;
    let r = unsafe {
        SetSecurityInfo(
            h.0,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            Some(admins.as_psid()),
            None,
            None,
            None,
        )
    };
    win32_ok(r, &format!("SetSecurityInfo(owner, {label})"))
}

/// Write a PROTECTED DACL parsed from `sddl` onto an open handle
/// (see [`open_for_security_no_follow`] for why by-handle).
pub fn set_handle_dacl_from_sddl(
    h: &crate::util::OwnedHandle,
    sddl: &str,
    label: &str,
) -> Result<()> {
    use windows::Win32::Security::Authorization::{SE_FILE_OBJECT, SetSecurityInfo};
    use windows::Win32::Security::GetSecurityDescriptorDacl;
    let sd = crate::util::OwnedSd::from_sddl(sddl)
        .with_context(|| format!("{label}: build SD from SDDL"))?;
    let mut present = windows::core::BOOL::from(false);
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut defaulted = windows::core::BOOL::from(false);
    unsafe {
        GetSecurityDescriptorDacl(sd.ptr, &mut present, &mut dacl, &mut defaulted)
            .with_context(|| format!("{label}: GetSecurityDescriptorDacl"))?;
    }
    if !present.as_bool() || dacl.is_null() {
        bail!("{label}: SDDL '{sddl}' yielded no DACL");
    }
    let r = unsafe {
        SetSecurityInfo(
            h.0,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(dacl),
            None,
        )
    };
    win32_ok(r, &format!("SetSecurityInfo(dacl, {label})"))
}

// ─── Additive grants (working-tree access for the sandbox user) ─────
//
// Under the separate-user model the sandbox user has NO inherent
// rights on real-user-owned files. `acl grant` adds an inheritable
// ALLOW ACE for the sandbox user's SID on a path (typically the
// working-tree root) so the child can read/write there; `acl stamp
// --sandbox-user-sid` adds an explicit DENY ACE on a path (and a
// `(OI)(CI)` `FILE_DELETE_CHILD` DENY on its parent) so the child
// can NOT read/write/delete it even when an inherited
// `BUILTIN\Users` ACE would otherwise allow. Both are ADDITIVE
// (the path keeps its own explicit ACEs and inheritance);
// revoke/restore drops the SID's ACEs by walk-and-filter, not a
// full-SD restore.

/// Per-grant access level. `Modify` is [`Mask::MODIFY_NO_FDC`] (the
/// working-tree grant — read/write/create/delete-own but NOT
/// `FILE_DELETE_CHILD`, so a denied file inside the granted tree
/// cannot be deleted via parent-FDC even where the only sb-user
/// access comes from this grant). `ReadOnly` is
/// [`Mask::FILE_READ_EXEC`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantMask {
    ReadOnly,
    Modify,
}

/// Per-deny mask. `ReadDeny` denies everything; `WriteDeny` leaves
/// read+execute. The bits are the *denied* rights.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyMask {
    WriteDeny,
    ReadDeny,
}

/// One explicit ACE the sandbox user holds on a path. The
/// separate-user FS model is entirely additive: `acl grant` adds
/// ALLOW ACEs, `acl stamp --sandbox-user-sid` adds DENY ACEs (plus
/// a `(OI)(CI)` `FILE_DELETE_CHILD` DENY on the parent). Restore
/// drops the SID's ACEs via walk-and-filter — no PROTECTED rewrite,
/// no SD snapshot, no calibration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SbAce {
    Grant(GrantMask),
    Deny(DenyMask),
    /// `(D;OICI;FILE_DELETE_CHILD;;;<sb>)` — applied to the parent
    /// of every denied target so the sandbox user cannot `del`/`ren`
    /// it via parent-FDC even when the parent carries an inherited
    /// `BUILTIN\Users:(F)` (which the sandbox user, a Users member,
    /// would otherwise pick up).
    DenyFdc,
    /// `(D;;DELETE;;;<sb>)` — object-only (`NO_INHERIT`) DELETE deny
    /// on a placeholder INTERMEDIATE directory. Blocks the sandbox
    /// from renaming/rmdir'ing the intermediate (which would bypass
    /// the leaf's stamp) without leaking any semantics onto children:
    /// a full-mask `(OI)(CI)` deny here would deny reads over the
    /// whole subtree if the placeholder later becomes a real user
    /// directory.
    DenyDelete,
}

impl GrantMask {
    fn bits(self) -> u32 {
        match self {
            GrantMask::ReadOnly => Mask::FILE_READ_EXEC.bits(),
            GrantMask::Modify => Mask::MODIFY_NO_FDC.bits(),
        }
    }
}

impl DenyMask {
    fn bits(self) -> u32 {
        match self {
            DenyMask::ReadDeny => Mask::FILE_ALL.bits(),
            // FILE_GENERIC_WRITE includes SYNCHRONIZE + READ_CONTROL
            // — denying SYNCHRONIZE blocks ANY synchronous open
            // (read included). Strip both so denyWrite leaves
            // read open. FILE_WRITE_ATTRIBUTES is already in
            // FILE_GENERIC_WRITE; the explicit `.with()` is
            // belt-and-braces (it survives a constant change).
            DenyMask::WriteDeny => Mask::FILE_GENERIC_WRITE
                .with(Mask::DELETE)
                .with(Mask::FILE_WRITE_ATTRIBUTES)
                .without(Mask::SYNCHRONIZE)
                .without(Mask::READ_CONTROL)
                .bits(),
        }
    }
}

impl SbAce {
    /// `'grant' | 'deny' | 'deny_fdc'` — the row's `kind` column.
    pub fn kind(self) -> &'static str {
        match self {
            SbAce::Grant(_) => "grant",
            SbAce::Deny(_) => "deny",
            SbAce::DenyFdc => "deny_fdc",
            SbAce::DenyDelete => "deny_delete",
        }
    }
    /// `'read' | 'modify' | 'denyRead' | 'denyWrite' | 'fdc'` — the
    /// row's `mask` / holder's `want_mask` column. Round-trips via
    /// [`SbAce::parse`].
    pub fn as_str(self) -> &'static str {
        match self {
            SbAce::Grant(GrantMask::ReadOnly) => "read",
            SbAce::Grant(GrantMask::Modify) => "modify",
            SbAce::Deny(DenyMask::ReadDeny) => "denyRead",
            SbAce::Deny(DenyMask::WriteDeny) => "denyWrite",
            SbAce::DenyFdc => "fdc",
            SbAce::DenyDelete => "delete",
        }
    }
    pub fn parse(kind: &str, mask: &str) -> Result<Self> {
        Ok(match (kind, mask) {
            ("grant", "read") => SbAce::Grant(GrantMask::ReadOnly),
            ("grant", "modify") => SbAce::Grant(GrantMask::Modify),
            ("deny", "denyRead") => SbAce::Deny(DenyMask::ReadDeny),
            ("deny", "denyWrite") => SbAce::Deny(DenyMask::WriteDeny),
            ("deny_fdc", _) => SbAce::DenyFdc,
            ("deny_delete", _) => SbAce::DenyDelete,
            (k, m) => bail!("unknown SbAce kind={k:?} mask={m:?}"),
        })
    }
    /// Widening within one kind: `Modify ⊃ ReadOnly`, `ReadDeny ⊃
    /// WriteDeny`, `DenyFdc` is unit. Cross-kind is meaningless (a
    /// path can hold one `Grant` row AND one `Deny` row; never
    /// merged).
    pub fn max(self, other: Self) -> Self {
        use DenyMask::ReadDeny as Dr;
        use GrantMask::Modify as Gm;
        match (self, other) {
            (SbAce::Grant(Gm), _) | (_, SbAce::Grant(Gm)) => SbAce::Grant(Gm),
            (SbAce::Grant(_), _) | (_, SbAce::Grant(_)) => self,
            (SbAce::Deny(Dr), _) | (_, SbAce::Deny(Dr)) => SbAce::Deny(Dr),
            _ => self,
        }
    }
}

/// What [`apply_sandbox_aces`] should converge a path to: at most one
/// ALLOW ACE, one DENY ACE, and one parent-FDC DENY for the sandbox
/// user. State-DB recomputes this from the live holder rows on every
/// change so cross-holder mask escalation/downgrade and the
/// grant/deny-on-same-path interaction are handled in one place.
#[derive(Debug, Clone, Copy, Default)]
pub struct SbAceSet {
    pub grant: Option<GrantMask>,
    pub deny: Option<DenyMask>,
    pub deny_fdc: bool,
    pub deny_delete: bool,
}

impl SbAceSet {
    /// The set's entries as [`NewAce`]s for `sid`, in canonical
    /// deny → deny-fdc → allow order. `Deny`/`DenyFdc`/`Grant` carry
    /// [`OICI`]; `DenyDelete` is object-only ([`NO_INHERIT`]) — see
    /// [`SbAce::DenyDelete`].
    fn head_aces(&self, sid: PSID) -> Vec<NewAce> {
        let mut v = Vec::with_capacity(4);
        if let Some(m) = self.deny {
            v.push(NewAce::Deny(sid, m.bits(), OICI));
        }
        if self.deny_delete {
            v.push(NewAce::Deny(sid, Mask::DELETE.bits(), NO_INHERIT));
        }
        if self.deny_fdc {
            v.push(NewAce::Deny(sid, Mask::FILE_DELETE_CHILD.bits(), OICI));
        }
        if let Some(m) = self.grant {
            v.push(NewAce::Allow(sid, m.bits(), OICI));
        }
        v
    }
}

/// Converge `canonical_path`'s explicit ACEs for `sandbox_sid` to
/// exactly `set`. Idempotent — every existing explicit ACE for the
/// SID (allow AND deny) is dropped, then `set`'s entries are
/// prepended in canonical (deny-before-allow) order. Inherited ACEs
/// are dropped too; on the (common) unprotected DACL,
/// `SetNamedSecurityInfoW` without `PROTECTED_` re-derives them from
/// the parent. A `SE_DACL_PROTECTED` DACL (inheritance deliberately
/// severed — its ACEs are normally all explicit, so nothing is
/// dropped; a hand-crafted stray `INHERITED_ACE`-flagged entry is
/// dropped and not re-derived, which fails closed) is written back
/// `PROTECTED_`: recomposing it `UNPROTECTED_` would
/// silently re-enable inheritance, and neither revoke nor restore
/// could undo that — the parent's inheritable ACEs (e.g. a data-drive
/// root's `Authenticated Users:(M)`) would durably re-open a path its
/// admin had locked down.
///
/// `SetEntriesInAclW(REVOKE_ACCESS)` is NOT used: per MSDN it
/// removes `ACCESS_ALLOWED_ACE`/`SYSTEM_AUDIT_ACE` for the trustee,
/// not `ACCESS_DENIED_ACE` — so a prior `Deny`/`DenyFdc` ACE would
/// survive. `SET_ACCESS` discards all but adds a new ALLOW ACE,
/// which is wrong when `set` is empty. So we walk + filter
/// manually.
///
/// Both grant and deny carry `(OI)(CI)` so directory targets cover
/// the subtree; on a file the inheritance flags are inert.
pub fn apply_sandbox_aces(canonical_path: &str, sandbox_sid: &str, set: SbAceSet) -> Result<()> {
    let sid = LocalPsid::from_string(sandbox_sid)
        .with_context(|| format!("parse sandbox SID '{sandbox_sid}'"))?;
    let sid_bytes = sid.as_bytes();
    // 1. Read the current DACL and its protection state. `sd` owns
    //    the buffer `old`/`keep` point into; it's freed after step
    //    4's write.
    let (sd, old) =
        read_file_dacl(canonical_path).with_context(|| format!("recompose '{canonical_path}'"))?;
    let protected =
        sd_dacl_protected(&sd).with_context(|| format!("recompose '{canonical_path}'"))?;
    // 2. Collect surviving explicit ACEs (drop inherited and any
    //    explicit ACE whose SID == sandbox_sid — allow AND deny).
    let kept = filter_aces(old, |hdr, body| {
        hdr.AceFlags & INHERITED_ACE == 0 && !ace_sid_is(body, sid_bytes)
    })?;
    // 3. Build fresh ACL: set's entries (deny-first canonical order)
    //    then surviving explicit ACEs.
    let new = rebuild_acl(kept.2, &set.head_aces(sid.as_psid()), &kept, &[])?;
    // 4. Write back, preserving the DACL's protection state:
    //    UNPROTECTED so the kernel re-derives inherited ACEs from the
    //    parent, PROTECTED when inheritance was severed before we
    //    touched the path (see doc comment).
    let prot = if protected {
        Protection::Protected
    } else {
        Protection::Unprotected
    };
    write_file_dacl(canonical_path, new.as_ptr(), prot)
        .with_context(|| format!("recompose '{canonical_path}'"))
}

/// Whether `canonical_path` carries an EXPLICIT `(OI)(CI)` deny ACE
/// for `sandbox_sid` covering at least the [`DenyMask::WriteDeny`]
/// bits. Drift check for `srt-win status`'s ambient write-deny
/// report and the install early-out's completeness check — a
/// recorded install-time stamp whose on-disk ACE is gone (e.g. an
/// `icacls /reset` by an admin) reads as absent, and an unrelated
/// narrow deny on the same path (a `DenyDelete` placeholder, a
/// parent-FDC ACE) must NOT count as the write-deny being intact.
pub fn sandbox_deny_present(canonical_path: &str, sandbox_sid: &str) -> Result<bool> {
    let sid = LocalPsid::from_string(sandbox_sid)
        .with_context(|| format!("parse sandbox SID '{sandbox_sid}'"))?;
    let sid_bytes = sid.as_bytes();
    let want_mask = DenyMask::WriteDeny.bits();
    let want_flags = OICI.0 as u8;
    let (_sd, dacl) = read_file_dacl(canonical_path)?;
    let denies = filter_aces(dacl, |hdr, body| {
        // ACCESS_DENIED_ACE layout: header (4) then Mask (u32 LE).
        let mask = u32::from_le_bytes([body[4], body[5], body[6], body[7]]);
        u32::from(hdr.AceType) == ACCESS_DENIED_ACE_TYPE
            && hdr.AceFlags & INHERITED_ACE == 0
            && hdr.AceFlags & want_flags == want_flags
            && mask & want_mask == want_mask
            && ace_sid_is(body, sid_bytes)
    })?;
    Ok(!denies.0.is_empty())
}

// ─── Persistent grants (write-restricted token) ─────────────────────
//
// `crate::persist` keeps a write root's grant between sessions. The
// functions here are its DACL half: what the ACEs are, reading them
// back for the session-start comparison, and writing them.

/// `CREATOR OWNER`: an inheritable ACE for it becomes, on each new
/// object, an ACE for that object's creator.
pub const SID_CREATOR_OWNER: &str = "S-1-3-0";

const INHERIT_FLAGS: u8 = 0x0f;
const GENERIC_WRITE: u32 = 0x4000_0000;

/// One plain allow or deny ACE: as read from a DACL, or as wanted on
/// a persistent path. Other ACE types (object, callback, audit) are
/// never produced or matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AceView {
    pub deny: bool,
    /// Carries `INHERITED_ACE`: it came from a directory above.
    pub inherited: bool,
    /// The object/container-inherit, no-propagate and inherit-only
    /// bits of the ACE flags.
    pub flags: u8,
    pub mask: u32,
    pub sid: String,
}

impl AceView {
    fn explicit(deny: bool, sid: &str, mask: u32, flags: ACE_FLAGS) -> Self {
        Self {
            deny,
            inherited: false,
            flags: flags.0 as u8 & INHERIT_FLAGS,
            mask,
            sid: sid.to_owned(),
        }
    }

    /// The ACE in SDDL, e.g. `(A;OICI;0x1301bf;;;S-1-5-32-545)`.
    pub fn sddl(&self) -> String {
        let mut fl = String::new();
        for (bit, s) in [(0x1u8, "OI"), (0x2, "CI"), (0x4, "NP"), (0x8, "IO")] {
            if self.flags & bit != 0 {
                fl.push_str(s);
            }
        }
        format!(
            "({};{fl};{:#x};;;{})",
            if self.deny { 'D' } else { 'A' },
            self.mask,
            self.sid
        )
    }
}

/// A binary SID as its `S-1-…` string, or `None` if `b` is not a
/// whole SID. Same rendering as `ConvertSidToStringSidW` (an
/// identifier authority below 2^32 in decimal, otherwise hex).
pub fn sid_string_from_bytes(b: &[u8]) -> Option<String> {
    let (&rev, &count) = (b.first()?, b.get(1)?);
    let auth = b.get(2..8)?;
    let subs = b.get(8..8 + 4 * count as usize)?;
    let authority = auth.iter().fold(0u64, |a, &x| (a << 8) | u64::from(x));
    let mut s = if authority < 1 << 32 {
        format!("S-{rev}-{authority}")
    } else {
        format!("S-{rev}-0x{authority:012X}")
    };
    for c in subs.as_chunks::<4>().0 {
        s.push_str(&format!("-{}", u32::from_le_bytes(*c)));
    }
    Some(s)
}

/// `(header, whole ACE bytes)` as an [`AceView`]; `None` for an ACE
/// type other than plain allow / deny, or a malformed one.
fn ace_view(hdr: &ACE_HEADER, body: &[u8]) -> Option<AceView> {
    let ty = u32::from(hdr.AceType);
    if ty != ACCESS_ALLOWED_ACE_TYPE && ty != ACCESS_DENIED_ACE_TYPE {
        return None;
    }
    let mask = u32::from_le_bytes(body.get(4..ACE_FIXED)?.try_into().ok()?);
    Some(AceView {
        deny: ty == ACCESS_DENIED_ACE_TYPE,
        inherited: hdr.AceFlags & INHERITED_ACE != 0,
        flags: hdr.AceFlags & INHERIT_FLAGS,
        mask,
        sid: sid_string_from_bytes(body.get(ACE_FIXED..)?)?,
    })
}

/// Every plain allow / deny ACE of `canonical_path`'s own DACL, in
/// DACL order. Reads one security descriptor; touches no descendant.
pub fn read_aces(canonical_path: &str) -> Result<Vec<AceView>> {
    let (_sd, dacl) = read_file_dacl(canonical_path)?;
    let mut out = Vec::new();
    filter_aces(dacl, |hdr, body| {
        out.extend(ace_view(hdr, body));
        false
    })?;
    Ok(out)
}

/// The trustees whose ACEs on a persistent path belong to this crate.
#[derive(Debug, Clone, Copy)]
pub struct PersistentTrustees<'a> {
    /// The sandbox group. `None` once the install record is gone;
    /// its ACEs can then no longer be told apart.
    pub group_sid: Option<&'a str>,
    /// The user the broker runs as.
    pub real_user_sid: &'a str,
}

/// Whether `a` is one of the ACEs [`persistent_aces`] produces: any
/// ACE for the sandbox group or for a capability SID, the owner-rights
/// ACE, or the real user's `READ_CONTROL | WRITE_DAC` ACE. The last
/// two are recognised by their exact mask, so an ACE the user wrote
/// for themselves (full control, say) is never taken for one of ours.
pub fn is_persistent_ace(a: &AceView, t: &PersistentTrustees<'_>) -> bool {
    t.group_sid == Some(a.sid.as_str())
        || crate::persist::is_capability_sid(&a.sid)
        || (!a.deny && a.sid == SID_OWNER_RIGHTS && a.mask == Mask::READ_CONTROL.bits())
        || (!a.deny && a.sid == t.real_user_sid && a.mask == Mask::OWNER_IMPLICIT.bits())
}

/// What a persistent path is to carry.
#[derive(Debug, Clone, Copy)]
pub struct PersistentWant<'a> {
    pub group_sid: &'a str,
    pub real_user_sid: &'a str,
    /// The path is a write root with this capability SID.
    pub capability_sid: Option<&'a str>,
    pub deny: Option<DenyMask>,
    pub deny_fdc: bool,
    pub deny_delete: bool,
}

/// The explicit ACEs of a persistent path, in the order they are
/// written at the head of its DACL. All inherit to files and
/// directories below (`(OI)(CI)`), except the object-only delete deny.
///
/// Denies come first and name the sandbox GROUP. The group is enabled
/// in every token of the sandbox account and is not a restricting
/// SID, so a deny for it applies in the ordinary access check whatever
/// the token shape.
///
/// A write root then carries four ALLOW ACEs:
///
/// 1. the sandbox group, [`Mask::MODIFY_NO_FDC`] — satisfies the
///    ordinary check;
/// 2. the root's capability SID, same mask — satisfies the check
///    against the restricting SIDs, which only a session that was
///    given this root has in its token;
/// 3. `OWNER RIGHTS`, `READ_CONTROL`. Its presence replaces what an
///    owner otherwise gets implicitly (`READ_CONTROL | WRITE_DAC`).
///    Files the sandbox creates are owned by the sandbox user, whose
///    SID is a restricting SID of every session; without this ACE a
///    session of another project could rewrite the DACL of any such
///    file here and then write it. It likewise stops the owner
///    removing a deny from an object it owns;
/// 4. the real user, `READ_CONTROL | WRITE_DAC`. ACE 3 applies to
///    every owner, the real user included, and they may own files
///    here with no ACE granting them `WRITE_DAC` (a folder that only
///    gives `Authenticated Users` modify). This gives back what
///    ownership gave them.
///
/// Why the order works. `OWNER RIGHTS` is an ALLOW: it takes nothing
/// away in the ACE walk, it only switches the implicit owner grant
/// off, so ACE 4 does not have to precede it. What can stop ACE 4 is
/// a DENY met earlier in the walk. The four are explicit ACEs at the
/// head of the root's DACL, ahead of every ACE the root had and of
/// everything it inherits; on a descendant they arrive as inherited
/// ACEs from the root, which are placed ahead of those inherited from
/// further up. So no deny of the root or of a directory above it is
/// reached before ACE 4. Only an explicit deny on the descendant
/// itself comes first — the one case where the real user had
/// `WRITE_DAC` as owner and no longer has it. None of the denies
/// written here name the real user.
///
/// No ACE names the sandbox USER SID: it is a restricting SID of
/// every session, so an ALLOW for it would pass both checks for all
/// of them.
pub fn persistent_aces(w: &PersistentWant<'_>) -> Vec<AceView> {
    let g = w.group_sid;
    let mut v = Vec::with_capacity(7);
    if let Some(m) = w.deny {
        v.push(AceView::explicit(true, g, m.bits(), OICI));
    }
    if w.deny_delete {
        v.push(AceView::explicit(true, g, Mask::DELETE.bits(), NO_INHERIT));
    }
    if w.deny_fdc {
        let fdc = Mask::FILE_DELETE_CHILD.bits();
        v.push(AceView::explicit(true, g, fdc, OICI));
    }
    if let Some(cap) = w.capability_sid {
        let modify = Mask::MODIFY_NO_FDC.bits();
        v.push(AceView::explicit(false, g, modify, OICI));
        v.push(AceView::explicit(false, cap, modify, OICI));
        let rc = Mask::READ_CONTROL.bits();
        v.push(AceView::explicit(false, SID_OWNER_RIGHTS, rc, OICI));
        let keep = Mask::OWNER_IMPLICIT.bits();
        v.push(AceView::explicit(false, w.real_user_sid, keep, OICI));
    }
    v
}

/// `aces` in the form two ACE lists are compared in: inheritance
/// flags mean nothing on a file and need not be stored there, so
/// they are dropped unless `is_dir`.
pub fn comparable(aces: &[AceView], is_dir: bool) -> Vec<AceView> {
    aces.iter()
        .map(|a| AceView {
            flags: if is_dir { a.flags } else { 0 },
            ..a.clone()
        })
        .collect()
}

/// The explicit persistent ACEs among `aces`, in DACL order, in
/// [`comparable`] form. Equal to `comparable(persistent_aces(..))`
/// exactly when the path carries the wanted set and nothing else of
/// ours.
pub fn persistent_on_disk(
    aces: &[AceView],
    t: &PersistentTrustees<'_>,
    is_dir: bool,
) -> Vec<AceView> {
    let own: Vec<AceView> = aces
        .iter()
        .filter(|a| !a.inherited && is_persistent_ace(a, t))
        .cloned()
        .collect();
    comparable(&own, is_dir)
}

/// Whether an ALLOW for `sid` among `aces` (explicit or inherited)
/// carries anything beyond read and execute.
pub fn allows_more_than_read(aces: &[AceView], sid: &str) -> bool {
    aces.iter()
        .any(|a| !a.deny && a.sid == sid && a.mask & !Mask::FILE_READ_EXEC.bits() != 0)
}

/// ACEs among `aces` that let the sandbox account write an object it
/// created here under ANY session's token, which the persistent ACE
/// set cannot take back: an inheritable `CREATOR OWNER` ALLOW with a
/// write right (each new object gets it as an ACE for the sandbox
/// user), and an `OWNER RIGHTS` ALLOW that includes `WRITE_DAC`.
/// Returned as text for a warning.
pub fn owner_write_paths(aces: &[AceView]) -> Vec<String> {
    let write = DenyMask::WriteDeny.bits()
        | Mask::WRITE_DAC.bits()
        | Mask::GENERIC_ALL.bits()
        | GENERIC_WRITE;
    aces.iter()
        .filter(|a| {
            !a.deny
                && ((a.sid == SID_CREATOR_OWNER && a.flags & 0x3 != 0 && a.mask & write != 0)
                    || (a.sid == SID_OWNER_RIGHTS
                        && a.mask & (Mask::WRITE_DAC.bits() | Mask::GENERIC_ALL.bits()) != 0))
        })
        .map(AceView::sddl)
        .collect()
}

/// Converge `canonical_path`'s explicit persistent ACEs (see
/// [`is_persistent_ace`]) to exactly `want`, written at the head of
/// the DACL in the given order; an empty `want` removes them. Every
/// other explicit ACE is kept, and the DACL's protection state is
/// preserved, as in [`apply_sandbox_aces`]. On a directory the write
/// re-derives the inherited ACEs of everything below it, so its cost
/// is linear in the tree.
pub fn write_persistent_aces(
    canonical_path: &str,
    t: &PersistentTrustees<'_>,
    want: &[AceView],
) -> Result<()> {
    let (sd, old) = read_file_dacl(canonical_path)
        .with_context(|| format!("persistent ACEs '{canonical_path}'"))?;
    let protected = sd_dacl_protected(&sd)?;
    let kept = filter_aces(old, |hdr, body| {
        hdr.AceFlags & INHERITED_ACE == 0
            && !ace_view(hdr, body).is_some_and(|a| is_persistent_ace(&a, t))
    })?;
    let sids: Vec<LocalPsid> = want
        .iter()
        .map(|a| LocalPsid::from_string(&a.sid))
        .collect::<Result<_>>()?;
    let head: Vec<NewAce> = want
        .iter()
        .zip(&sids)
        .map(|(a, s)| {
            let fl = ACE_FLAGS(u32::from(a.flags));
            if a.deny {
                NewAce::Deny(s.as_psid(), a.mask, fl)
            } else {
                NewAce::Allow(s.as_psid(), a.mask, fl)
            }
        })
        .collect();
    let new = rebuild_acl(kept.2, &head, &kept, &[])?;
    let prot = if protected {
        Protection::Protected
    } else {
        Protection::Unprotected
    };
    write_file_dacl(canonical_path, new.as_ptr(), prot)
        .with_context(|| format!("persistent ACEs '{canonical_path}'"))
}

const INHERITED_ACE: u8 = 0x10;
#[cfg(test)]
mod tests {
    use super::*;

    fn ace_count(d: &BuiltAcl) -> u16 {
        // ACL.AceCount is bytes 4–5 (LE u16).
        u16::from_le_bytes([d.buf[4], d.buf[5]])
    }

    /// IsolatedDesk's `[broker, sb, SY]:GA` DACL — 3 ACEs,
    /// revision 2, GENERIC_ALL on each. Regression for the
    /// `KeptAces`/`rebuild_acl` chokepoint: a sizing or revision
    /// bug here breaks the sandbox-user desktop attach (R1 hang).
    #[test]
    fn isolated_desk_dacl_shape() {
        let d = build_allow_dacl(&[
            Allow("S-1-5-21-1-2-3-1000", Mask::GENERIC_ALL, NO_INHERIT),
            Allow("S-1-5-21-1-2-3-1004", Mask::GENERIC_ALL, NO_INHERIT),
            Allow(SID_SYSTEM, Mask::GENERIC_ALL, NO_INHERIT),
        ])
        .unwrap();
        assert_eq!(d.buf[0], 2, "AclRevision");
        assert_eq!(ace_count(&d), 3);
    }

    #[test]
    fn build_allow_dacl_dedup() {
        // Same SID twice (case-insensitive) → 1 ACE; first wins.
        let d = build_allow_dacl(&[
            Allow(SID_BUILTIN_ADMINS, Mask::FILE_ALL, NO_INHERIT),
            Allow("s-1-5-32-544", Mask::FILE_READ_EXEC, NO_INHERIT),
        ])
        .unwrap();
        assert_eq!(ace_count(&d), 1);
    }

    /// Grant → revoke on a `SE_DACL_PROTECTED` directory must leave
    /// the protection bit (and the explicit ACE set) intact.
    /// Regression: [`apply_sandbox_aces`] used to write back
    /// `UNPROTECTED_` unconditionally, which re-enabled inheritance
    /// on a deliberately severed path — durably re-admitting the
    /// parent's inheritable ACEs (e.g. a data-drive root's
    /// `Authenticated Users:(M)`), and revoke could not undo it.
    #[test]
    fn recompose_preserves_dacl_protection() {
        // Guests — a resolvable well-known SID that is never the
        // test runner's own identity, standing in for the sandbox
        // user (no account provisioning needed to write ACEs).
        const FAKE_SB_SID: &str = "S-1-5-32-546";
        let dir = std::env::temp_dir().join(format!("srtwin-prot-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.to_str().unwrap();

        // Sever inheritance: protected DACL with an explicit
        // owner-side allow (mirrors `icacls /inheritance:d` plus a
        // lockdown to a fixed ACE set).
        let user_sid = crate::sid::current_user_sid().unwrap();
        let lockdown = build_allow_dacl(&[
            Allow(&user_sid, Mask::FILE_ALL, OICI),
            Allow(SID_SYSTEM, Mask::FILE_ALL, OICI),
        ])
        .unwrap();
        write_file_dacl(path, lockdown.as_ptr(), Protection::Protected).unwrap();
        let (sd, _) = read_file_dacl(path).unwrap();
        assert!(sd_dacl_protected(&sd).unwrap(), "setup: DACL protected");

        // Grant + revoke through the production chokepoint.
        let grant = SbAceSet {
            grant: Some(GrantMask::Modify),
            ..Default::default()
        };
        apply_sandbox_aces(path, FAKE_SB_SID, grant).unwrap();
        let (sd, dacl) = read_file_dacl(path).unwrap();
        assert!(sd_dacl_protected(&sd).unwrap(), "protection survives grant");
        let (aces, ..) = filter_aces(dacl, |hdr, _| hdr.AceFlags & INHERITED_ACE != 0).unwrap();
        assert!(aces.is_empty(), "no inherited ACEs re-derived after grant");

        apply_sandbox_aces(path, FAKE_SB_SID, SbAceSet::default()).unwrap();
        let (sd, dacl) = read_file_dacl(path).unwrap();
        assert!(
            sd_dacl_protected(&sd).unwrap(),
            "protection survives revoke"
        );
        let (aces, ..) = filter_aces(dacl, |hdr, _| hdr.AceFlags & INHERITED_ACE != 0).unwrap();
        assert!(aces.is_empty(), "no inherited ACEs re-derived after revoke");

        // The common case keeps its contract: an unprotected dir
        // stays unprotected across the same round-trip, and its
        // inherited ACEs (the parent's OICI lockdown entries
        // propagate to it) really are re-derived by the
        // `UNPROTECTED_` write-back — not merely "protection bit
        // still clear".
        let plain = dir.join("plain");
        std::fs::create_dir_all(&plain).unwrap();
        let plain_path = plain.to_str().unwrap();
        apply_sandbox_aces(plain_path, FAKE_SB_SID, grant).unwrap();
        apply_sandbox_aces(plain_path, FAKE_SB_SID, SbAceSet::default()).unwrap();
        let (sd, dacl) = read_file_dacl(plain_path).unwrap();
        assert!(
            !sd_dacl_protected(&sd).unwrap(),
            "unprotected dir stays unprotected"
        );
        let (aces, ..) = filter_aces(dacl, |hdr, _| hdr.AceFlags & INHERITED_ACE != 0).unwrap();
        assert!(
            !aces.is_empty(),
            "inherited ACEs re-derived on the unprotected dir"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    const GROUP: &str = "S-1-5-21-1-2-3-1002";
    const REAL: &str = "S-1-5-21-1-2-3-1000";
    const CAP: &str = "S-1-0-1936880739-1-2-3-4";
    const T: PersistentTrustees<'static> = PersistentTrustees {
        group_sid: Some(GROUP),
        real_user_sid: REAL,
    };

    fn root_want<'a>(cap: &'a str) -> PersistentWant<'a> {
        PersistentWant {
            group_sid: GROUP,
            real_user_sid: REAL,
            capability_sid: Some(cap),
            deny: None,
            deny_fdc: false,
            deny_delete: false,
        }
    }

    /// The exact ACE list of a persistent root, in DACL order.
    #[test]
    fn persistent_root_ace_list_is_pinned() {
        let sddl: Vec<String> = persistent_aces(&root_want(CAP))
            .iter()
            .map(AceView::sddl)
            .collect();
        assert_eq!(
            sddl,
            [
                format!("(A;OICI;0x1301bf;;;{GROUP})"),
                format!("(A;OICI;0x1301bf;;;{CAP})"),
                "(A;OICI;0x20000;;;S-1-3-4)".to_owned(),
                format!("(A;OICI;0x60000;;;{REAL})"),
            ]
        );
        // Denies lead, for the group; the delete deny does not
        // inherit. Without a capability SID there is no ALLOW at all.
        let denies = PersistentWant {
            capability_sid: None,
            deny: Some(DenyMask::WriteDeny),
            deny_fdc: true,
            deny_delete: true,
            ..root_want(CAP)
        };
        let sddl: Vec<String> = persistent_aces(&denies).iter().map(AceView::sddl).collect();
        assert_eq!(
            sddl,
            [
                format!("(D;OICI;{:#x};;;{GROUP})", DenyMask::WriteDeny.bits()),
                format!("(D;;0x10000;;;{GROUP})"),
                format!("(D;OICI;0x40;;;{GROUP})"),
            ]
        );
        let both = persistent_aces(&PersistentWant {
            deny_fdc: true,
            ..root_want(CAP)
        });
        assert_eq!(both.len(), 5);
        assert!(both[0].deny && !both[1..].iter().any(|a| a.deny));
        // No ACE of any persistent path names the sandbox user: only
        // the group, the capability SID, OWNER RIGHTS, the real user.
        assert!(
            both.iter()
                .all(|a| [GROUP, CAP, SID_OWNER_RIGHTS, REAL].contains(&a.sid.as_str()))
        );
    }

    /// What the session-start comparison accepts and what it does not.
    #[test]
    fn expected_dacl_comparison() {
        let want = persistent_aces(&root_want(CAP));
        let inherited = |sid: &str, mask: u32| AceView {
            deny: false,
            inherited: true,
            flags: 0x3,
            mask,
            sid: sid.to_owned(),
        };
        let other = |sid: &str, mask: u32| AceView {
            inherited: false,
            ..inherited(sid, mask)
        };
        // The wanted ACEs among unrelated ones: a match, on a
        // directory. The real user's own full-control ACE and an
        // inherited copy of a persistent ACE are not ours.
        let mut dacl = want.clone();
        dacl.push(other(REAL, Mask::FILE_ALL.bits()));
        dacl.push(other(SID_SYSTEM, Mask::FILE_ALL.bits()));
        dacl.push(inherited(GROUP, Mask::MODIFY_NO_FDC.bits()));
        dacl.push(inherited(
            "S-1-0-1936880739-9-9-9-9",
            Mask::MODIFY_NO_FDC.bits(),
        ));
        assert_eq!(persistent_on_disk(&dacl, &T, true), comparable(&want, true));

        let differs =
            |dacl: &[AceView]| persistent_on_disk(dacl, &T, true) != comparable(&want, true);
        // One ACE missing.
        for i in 0..want.len() {
            let mut d = want.clone();
            d.remove(i);
            assert!(differs(&d), "missing ACE {i}");
        }
        // A wrong mask, wrong inheritance flags, a deny in place of an
        // allow, a different capability SID, an extra ACE of ours.
        let mut d = want.clone();
        d[0].mask = Mask::FILE_ALL.bits();
        assert!(differs(&d));
        let mut d = want.clone();
        d[1].flags = 0x2;
        assert!(differs(&d));
        let mut d = want.clone();
        d[0].deny = true;
        assert!(differs(&d));
        let mut d = want.clone();
        d[1].sid = "S-1-0-1936880739-9-9-9-9".to_owned();
        assert!(differs(&d));
        let mut d = want.clone();
        d.insert(0, other(GROUP, Mask::FILE_DELETE_CHILD.bits()));
        assert!(differs(&d));
        // Order is part of it.
        let mut d = want.clone();
        d.swap(0, 3);
        assert!(differs(&d));
        // Nothing of ours on disk.
        assert!(persistent_on_disk(&[other(REAL, Mask::FILE_ALL.bits())], &T, true).is_empty());

        // On a file inheritance flags are not compared.
        let mut on_file = want.clone();
        for a in &mut on_file {
            a.flags = 0;
        }
        assert_eq!(
            persistent_on_disk(&on_file, &T, false),
            comparable(&want, false)
        );
        assert_ne!(
            persistent_on_disk(&on_file, &T, true),
            comparable(&want, true)
        );

        // With the install record gone the group's ACEs are no longer
        // recognised; the other three still are.
        let no_group = PersistentTrustees {
            group_sid: None,
            ..T
        };
        assert_eq!(persistent_on_disk(&want, &no_group, true).len(), 3);
    }

    #[test]
    fn sid_strings_from_ace_bytes() {
        for sid in [
            "S-1-1-0",
            "S-1-3-4",
            "S-1-5-32-545",
            "S-1-5-21-1-2-3-1000",
            CAP,
            "S-1-0-1936880739-4294967295-0-1-2",
        ] {
            let b = crate::sid::sid_bytes(sid).unwrap();
            assert_eq!(sid_string_from_bytes(&b).as_deref(), Some(sid));
            // A truncated SID is not one.
            assert_eq!(sid_string_from_bytes(&b[..b.len() - 1]), None);
        }
        assert_eq!(sid_string_from_bytes(&[]), None);
    }

    #[test]
    fn write_checks_on_a_root_dacl() {
        let ace = |sid: &str, mask: u32, flags: u8| AceView {
            deny: false,
            inherited: true,
            flags,
            mask,
            sid: sid.to_owned(),
        };
        let sb = "S-1-5-21-1-2-3-1001";
        assert!(!allows_more_than_read(
            &[ace(sb, Mask::FILE_READ_EXEC.bits(), 0x3)],
            sb
        ));
        assert!(allows_more_than_read(
            &[ace(sb, Mask::MODIFY_NO_FDC.bits(), 0x3)],
            sb
        ));
        assert!(!allows_more_than_read(
            &[ace(GROUP, Mask::MODIFY_NO_FDC.bits(), 0x3)],
            sb
        ));
        // CREATOR OWNER full control that inherits; the same ACE on
        // the object only does not reach new files. OWNER RIGHTS with
        // WRITE_DAC; ours (READ_CONTROL) is not reported.
        let found = owner_write_paths(&[
            ace(SID_CREATOR_OWNER, Mask::GENERIC_ALL.bits(), 0xb),
            ace(SID_CREATOR_OWNER, Mask::GENERIC_ALL.bits(), 0),
            ace(SID_CREATOR_OWNER, Mask::FILE_READ_EXEC.bits(), 0x3),
            ace(SID_OWNER_RIGHTS, Mask::FILE_ALL.bits(), 0x3),
            ace(SID_OWNER_RIGHTS, Mask::READ_CONTROL.bits(), 0x3),
        ]);
        assert_eq!(found.len(), 2, "{found:?}");
    }

    /// The persistent ACEs through the real DACL write and read:
    /// they land at the head, a child inherits them, a second write
    /// of the same list changes nothing, and an empty list removes
    /// them and leaves the rest.
    #[test]
    fn persistent_aces_round_trip_on_disk() {
        // Guests stands in for the sandbox group, as in
        // `recompose_preserves_dacl_protection`.
        const GROUP: &str = "S-1-5-32-546";
        let real = crate::sid::current_user_sid().unwrap();
        let cap = crate::persist::new_capability_sid().unwrap();
        let t = PersistentTrustees {
            group_sid: Some(GROUP),
            real_user_sid: &real,
        };
        let dir = std::env::temp_dir().join(format!("srtwin-persist-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("sub").join("f.txt"), b"x").unwrap();
        let path = dir.to_str().unwrap();
        let before = read_aces(path).unwrap();

        let want = persistent_aces(&PersistentWant {
            group_sid: GROUP,
            real_user_sid: &real,
            capability_sid: Some(&cap),
            deny: None,
            deny_fdc: true,
            deny_delete: false,
        });
        for _ in 0..2 {
            write_persistent_aces(path, &t, &want).unwrap();
            let aces = read_aces(path).unwrap();
            assert_eq!(persistent_on_disk(&aces, &t, true), comparable(&want, true));
            assert_eq!(
                comparable(&aces[..want.len()], true),
                comparable(&want, true)
            );
        }
        // A file two levels down carries each of them as inherited.
        let file = dir.join("sub").join("f.txt");
        let below = read_aces(file.to_str().unwrap()).unwrap();
        for w in &want {
            assert!(
                below
                    .iter()
                    .any(|a| a.inherited && a.deny == w.deny && a.sid == w.sid && a.mask == w.mask),
                "not inherited: {}",
                w.sddl()
            );
        }
        assert!(persistent_on_disk(&below, &t, false).is_empty());

        write_persistent_aces(path, &t, &[]).unwrap();
        let after = read_aces(path).unwrap();
        assert!(persistent_on_disk(&after, &t, true).is_empty());
        let explicit = |v: &[AceView]| {
            v.iter()
                .filter(|a| !a.inherited)
                .cloned()
                .collect::<Vec<_>>()
        };
        assert_eq!(explicit(&after), explicit(&before));
        let below = read_aces(file.to_str().unwrap()).unwrap();
        assert!(!below.iter().any(|a| a.sid == cap || a.sid == GROUP));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn mask_consts_regression() {
        let m = Mask::MODIFY_NO_FDC;
        assert_eq!(m.bits(), 0x0013_01bf);
        assert_ne!(m.bits() & Mask::DELETE.bits(), 0, "must carry DELETE");
        assert_eq!(m.bits() & Mask::FILE_DELETE_CHILD.bits(), 0);
        assert_eq!(m.bits() & 0xffe0_0000, 0, "stray high bits");

        let ow = Allow::OWNER_RIGHTS.1;
        assert_eq!(ow.bits(), Mask::READ_CONTROL.bits());
        assert_ne!(ow.bits(), 0);
        assert_eq!(ow.bits() & Mask::WRITE_DAC.bits(), 0);
    }
}
