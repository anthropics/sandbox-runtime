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
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::Authorization::{
    GetNamedSecurityInfoW, GetSecurityInfo, SE_FILE_OBJECT, SetNamedSecurityInfoW, SetSecurityInfo,
};
use windows::Win32::Security::{
    ACE_FLAGS, ACE_HEADER, ACE_REVISION, ACL, ACL_REVISION, ACL_SIZE_INFORMATION,
    AclSizeInformation, AddAccessAllowedAceEx, AddAccessDeniedAceEx, AddAce, CONTAINER_INHERIT_ACE,
    DACL_SECURITY_INFORMATION, GetAce, GetAclInformation, GetLengthSid,
    GetSecurityDescriptorControl, InitializeAcl, InitializeSecurityDescriptor, OBJECT_INHERIT_ACE,
    OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    SE_DACL_AUTO_INHERIT_REQ, SE_DACL_AUTO_INHERITED, SE_DACL_PROTECTED, SECURITY_ATTRIBUTES,
    SECURITY_DESCRIPTOR, SetKernelObjectSecurity, SetSecurityDescriptorControl,
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

    /// `FILE_GENERIC_READ | FILE_TRAVERSE` for a directory that is only
    /// passed through ([`ProfileAce::Container`]): what a generic-read open
    /// of the directory asks for. Not inherited, so it reads no file.
    pub const DIR_LIST: Self = Self(0x0012_00a9);

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
    rebuild_acl_seq(
        rev,
        &[AclPart::New(head), AclPart::Kept(kept), AclPart::New(tail)],
    )
}

/// One run of ACEs in a [`rebuild_acl_seq`] output.
pub(crate) enum AclPart<'a> {
    New(&'a [NewAce]),
    /// Raw ACEs of a source ACL ([`filter_aces`]). Every `Kept` part
    /// of one call must come from the same source ACL, and `rev` be
    /// that ACL's revision.
    Kept(&'a KeptAces),
}

/// [`rebuild_acl`] for any sequence of new and kept runs, written in
/// the order given.
pub(crate) fn rebuild_acl_seq(rev: ACE_REVISION, parts: &[AclPart<'_>]) -> Result<BuiltAcl> {
    let mut total = size_of::<ACL>();
    for p in parts {
        match p {
            AclPart::New(aces) => {
                for a in aces.iter() {
                    total += ACE_FIXED + unsafe { GetLengthSid(a.sid()) } as usize;
                }
            }
            AclPart::Kept(k) => total += k.1,
        }
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
    for p in parts {
        match p {
            AclPart::New(aces) => aces.iter().try_for_each(&add)?,
            AclPart::Kept(k) => {
                for (ace, sz) in &k.0 {
                    unsafe { AddAce(acl, rev, u32::MAX, *ace, *sz as u32) }
                        .context("AddAce(keep)")?;
                }
            }
        }
    }
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

/// [`read_file_dacl`] for an object that is already open: the DACL
/// of exactly that object, whatever its path resolves to now. The
/// handle needs `READ_CONTROL`.
pub(crate) fn read_handle_dacl(h: HANDLE, label: &str) -> Result<(OwnedSd, *mut ACL)> {
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut psd = PSECURITY_DESCRIPTOR::default();
    let r = unsafe {
        GetSecurityInfo(
            h,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut dacl),
            None,
            Some(&mut psd),
        )
    };
    win32_ok(r, &format!("GetSecurityInfo('{label}')"))?;
    Ok((OwnedSd::from_raw(psd), dacl))
}

/// [`write_file_dacl`] for an object that is already open. The
/// handle needs `WRITE_DAC`. As with the by-name call, the system
/// then brings the inherited ACEs of the objects below up to date.
pub(crate) fn write_handle_dacl(
    h: HANDLE,
    label: &str,
    acl: *const ACL,
    p: Protection,
) -> Result<()> {
    let prot = match p {
        Protection::Protected => PROTECTED_DACL_SECURITY_INFORMATION,
        Protection::Unprotected => UNPROTECTED_DACL_SECURITY_INFORMATION,
    };
    let r = unsafe {
        SetSecurityInfo(
            h,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | prot,
            None,
            None,
            Some(acl),
            None,
        )
    };
    win32_ok(r, &format!("SetSecurityInfo('{label}')"))
}

/// The object a persistent ACE list is read from and written to: a
/// path, opened by name for each call, or an open handle (with the
/// path it was opened by, for messages).
#[derive(Debug, Clone, Copy)]
pub enum DaclTarget<'a> {
    Path(&'a str),
    Handle(HANDLE, &'a str),
}

impl DaclTarget<'_> {
    fn label(&self) -> &str {
        match self {
            DaclTarget::Path(p) | DaclTarget::Handle(_, p) => p,
        }
    }

    fn read(&self) -> Result<(OwnedSd, *mut ACL)> {
        match self {
            DaclTarget::Path(p) => read_file_dacl(p),
            DaclTarget::Handle(h, p) => read_handle_dacl(*h, p),
        }
    }

    fn write(&self, acl: *const ACL, prot: Protection) -> Result<()> {
        match self {
            DaclTarget::Path(p) => write_file_dacl(p, acl, prot),
            DaclTarget::Handle(h, p) => write_handle_dacl(*h, p, acl, prot),
        }
    }
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

// ─── Writing a DACL: with or without the walk of the tree ───────────

/// How a DACL write was carried out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Written {
    /// The access list was already the one wanted: nothing written.
    Unchanged,
    /// Written on the object alone.
    Local,
    /// Written with the call that then brings the inherited entries
    /// of everything below up to date — a walk of the tree.
    Tree,
}

/// What a writer asks of [`commit_dacl`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Commit {
    /// Write; walk the tree only if the write changes what objects
    /// below inherit ([`same_inheritable`]).
    Write,
    /// The same, and no write at all if no explicit entry changes.
    IfChanged,
    /// Write with the walk whatever changes: a walk that was cut
    /// short is being finished.
    Walk,
}

thread_local! {
    /// `(tree walks, object-only writes)` made on this thread.
    static WRITES: std::cell::Cell<(usize, usize)> = const { std::cell::Cell::new((0, 0)) };
}

/// `(tree walks, object-only writes)` this thread has made so far. A
/// caller that reports on a run reads it before and after.
pub fn write_counts() -> (usize, usize) {
    WRITES.with(std::cell::Cell::get)
}

/// The explicit ACEs of `acl`, each as its bytes, in order.
fn explicit_raw(acl: *const ACL) -> Result<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    filter_aces(acl, |hdr, body| {
        if hdr.AceFlags & INHERITED_ACE == 0 {
            out.push(body.to_vec());
        }
        false
    })?;
    Ok(out)
}

/// Whether two lists of explicit ACEs (raw bytes, DACL order) hand the same
/// down: the `OI`/`CI` entries are identical, byte for byte and in order.
/// Only then may a DACL be written without the walk of the tree.
pub fn same_inheritable(before: &[Vec<u8>], after: &[Vec<u8>]) -> bool {
    // Byte 1 of an ACE is its flags; bits 0 and 1 are OI and CI.
    let handed_down = |aces: &'_ [Vec<u8>]| -> Vec<Vec<u8>> {
        aces.iter()
            .filter(|a| a.get(1).is_some_and(|f| f & 0x3 != 0))
            .cloned()
            .collect()
    };
    handed_down(before) == handed_down(after)
}

/// `SE_DACL_AUTO_INHERITED` of `sd`: the mark the system keeps on an
/// access list whose inherited entries it maintains.
fn sd_dacl_auto_inherited(sd: &OwnedSd) -> Result<bool> {
    let mut control: u16 = 0;
    let mut revision = 0u32;
    unsafe { GetSecurityDescriptorControl(sd.ptr, &mut control, &mut revision) }
        .context("GetSecurityDescriptorControl")?;
    Ok(control & SE_DACL_AUTO_INHERITED.0 != 0)
}

/// A handle on what `path` names that may write its access list —
/// resolved as the by-name calls resolve it, so that the list read by
/// name and the one written through this handle are one object's.
fn open_to_write_dacl(path: &str) -> Result<crate::util::OwnedHandle> {
    use windows::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    let w = wstr(path);
    let h = unsafe {
        CreateFileW(
            pcwstr(&w),
            Mask::READ_CONTROL.bits() | Mask::WRITE_DAC.bits(),
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
    }
    .with_context(|| format!("CreateFileW('{path}', WRITE_DAC)"))?;
    if h == INVALID_HANDLE_VALUE {
        bail!("CreateFileW('{path}'): INVALID_HANDLE_VALUE");
    }
    Ok(crate::util::OwnedHandle(h))
}

/// Write `explicit` plus `old`'s inherited entries on the object alone. The
/// auto-inherited mark survives only if the descriptor also carries
/// `SE_DACL_AUTO_INHERIT_REQ`; without it the system clears the mark.
fn write_dacl_on_object(
    h: HANDLE,
    old: *const ACL,
    explicit: &BuiltAcl,
    protected: bool,
    auto_inherited: bool,
) -> Result<()> {
    let inherited = filter_aces(old, |hdr, _| hdr.AceFlags & INHERITED_ACE != 0)?;
    let own = filter_aces(explicit.as_ptr(), |_, _| true)?;
    let full = rebuild_acl_seq(own.2, &[AclPart::Kept(&own), AclPart::Kept(&inherited)])?;
    let mut sd = SECURITY_DESCRIPTOR::default();
    let psd = PSECURITY_DESCRIPTOR(&mut sd as *mut _ as *mut c_void);
    let mut set = windows::Win32::Security::SECURITY_DESCRIPTOR_CONTROL(0);
    if auto_inherited {
        set |= SE_DACL_AUTO_INHERIT_REQ | SE_DACL_AUTO_INHERITED;
    }
    if protected {
        set |= SE_DACL_PROTECTED;
    }
    unsafe {
        InitializeSecurityDescriptor(psd, SECURITY_DESCRIPTOR_REVISION)
            .context("InitializeSecurityDescriptor")?;
        SetSecurityDescriptorDacl(psd, true, Some(full.as_ptr()), false)
            .context("SetSecurityDescriptorDacl")?;
        SetSecurityDescriptorControl(
            psd,
            SE_DACL_AUTO_INHERIT_REQ | SE_DACL_AUTO_INHERITED | SE_DACL_PROTECTED,
            set,
        )
        .context("SetSecurityDescriptorControl")?;
        SetKernelObjectSecurity(h, DACL_SECURITY_INFORMATION, psd)
            .context("SetKernelObjectSecurity")?;
    }
    Ok(())
}

/// Write `new` (the explicit entries) as `target`'s access list. On the
/// object alone when nothing handed down changes ([`same_inheritable`]);
/// otherwise, or if that fails or loses a mark, with the walking call.
pub(crate) fn commit_dacl(
    target: DaclTarget<'_>,
    sd: &OwnedSd,
    old: *const ACL,
    new: &BuiltAcl,
    how: Commit,
) -> Result<Written> {
    let protected = sd_dacl_protected(sd)?;
    let before = explicit_raw(old)?;
    let after = explicit_raw(new.as_ptr())?;
    if how == Commit::IfChanged && before == after {
        return Ok(Written::Unchanged);
    }
    if how != Commit::Walk && same_inheritable(&before, &after) {
        let auto = sd_dacl_auto_inherited(sd)?;
        let on_object = || -> Result<bool> {
            let opened;
            let h = match target {
                DaclTarget::Handle(h, _) => h,
                DaclTarget::Path(p) => {
                    opened = open_to_write_dacl(p)?;
                    opened.raw()
                }
            };
            write_dacl_on_object(h, old, new, protected, auto)?;
            // Read back: the mark must be what it was.
            let (now, _) = read_handle_dacl(h, target.label())?;
            Ok(sd_dacl_auto_inherited(&now)? == auto && sd_dacl_protected(&now)? == protected)
        };
        // Could it not be done that way, or did it not leave the
        // list's marks as they were, the walking call does both.
        if let Ok(true) = on_object() {
            WRITES.with(|w| w.set((w.get().0, w.get().1 + 1)));
            return Ok(Written::Local);
        }
    }
    let prot = if protected {
        Protection::Protected
    } else {
        Protection::Unprotected
    };
    target.write(new.as_ptr(), prot)?;
    WRITES.with(|w| w.set((w.get().0 + 1, w.get().1)));
    Ok(Written::Tree)
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
    /// The set's DENY entries as [`NewAce`]s for `sid`, deny →
    /// deny-delete → deny-fdc, and its ALLOW entry.
    fn aces(&self, sid: PSID) -> (Vec<NewAce>, Vec<NewAce>) {
        let mut v = Vec::with_capacity(3);
        if let Some(m) = self.deny {
            v.push(NewAce::Deny(sid, m.bits(), OICI));
        }
        if self.deny_delete {
            v.push(NewAce::Deny(sid, Mask::DELETE.bits(), NO_INHERIT));
        }
        if self.deny_fdc {
            v.push(NewAce::Deny(sid, Mask::FILE_DELETE_CHILD.bits(), OICI));
        }
        let allow = self
            .grant
            .map(|m| NewAce::Allow(sid, m.bits(), OICI))
            .into_iter()
            .collect();
        (v, allow)
    }
}

/// The ACE types that deny: plain, object, callback, callback-object.
fn is_deny_type(hdr: &ACE_HEADER) -> bool {
    matches!(u32::from(hdr.AceType), 1 | 6 | 10 | 12)
}

/// Where the entries written here go among the explicit entries that
/// are kept ([`place_around`]).
#[derive(Clone, Copy, Default)]
struct Placement {
    /// Our allows go at the head (behind our denies) instead of
    /// behind the last kept deny.
    allows_first: bool,
}

/// A DACL with `denies` at the head and `allows` after the last explicit
/// deny among the entries `stays` keeps, which are not moved.
fn place_around(
    acl: *const ACL,
    stays: impl Fn(&ACE_HEADER, &[u8]) -> bool,
    placement: Placement,
    denies: &[NewAce],
    allows: &[NewAce],
) -> Result<BuiltAcl> {
    // One pass for the cut point among the kept entries.
    let (mut seen, mut after_last_deny) = (0usize, 0usize);
    filter_aces(acl, |h, b| {
        if stays(h, b) {
            seen += 1;
            if is_deny_type(h) {
                after_last_deny = seen;
            }
        }
        false
    })?;
    let allows_at = if placement.allows_first {
        0
    } else {
        after_last_deny
    };
    let part = |from: usize, to: usize| {
        let mut at = 0usize;
        filter_aces(acl, |h, b| {
            stays(h, b) && {
                at += 1;
                at > from && at <= to
            }
        })
    };
    let (head, rest) = (part(0, allows_at)?, part(allows_at, seen)?);
    rebuild_acl_seq(
        rest.2,
        &[
            AclPart::New(denies),
            AclPart::Kept(&head),
            AclPart::New(allows),
            AclPart::Kept(&rest),
        ],
    )
}

/// Converge `canonical_path`'s explicit ACEs for `sandbox_sid` to exactly
/// `set`. Always writes, with the walk of the tree: the install's entry
/// point, where a repeated run must finish what a cut-short one left.
pub fn apply_sandbox_aces(canonical_path: &str, sandbox_sid: &str, set: SbAceSet) -> Result<()> {
    apply_sandbox_aces_how(canonical_path, sandbox_sid, set, None, Commit::Walk)
}

/// [`apply_sandbox_aces`] for a session: nothing is written if nothing
/// changes. Where the object carries an explicit read deny for the group,
/// the session's allow goes ahead of it (an exclusion admitted on purpose).
pub fn apply_sandbox_aces_over(
    canonical_path: &str,
    sandbox_sid: &str,
    set: SbAceSet,
    sandbox_group_sid: Option<&str>,
) -> Result<()> {
    apply_sandbox_aces_how(
        canonical_path,
        sandbox_sid,
        set,
        sandbox_group_sid,
        Commit::IfChanged,
    )
}

fn apply_sandbox_aces_how(
    canonical_path: &str,
    sandbox_sid: &str,
    set: SbAceSet,
    sandbox_group_sid: Option<&str>,
    how: Commit,
) -> Result<()> {
    let sid = LocalPsid::from_string(sandbox_sid)
        .with_context(|| format!("parse sandbox SID '{sandbox_sid}'"))?;
    let sid_bytes = sid.as_bytes();
    // 1. Read the current DACL and its protection state. `sd` owns
    //    the buffer `old`/`keep` point into; it's freed after step
    //    4's write.
    let (sd, old) =
        read_file_dacl(canonical_path).with_context(|| format!("recompose '{canonical_path}'"))?;
    // The surviving explicit ACEs (not inherited, not for sandbox_sid)
    // stay unmoved; the set's entries go around them.
    let (denies, allows) = set.aces(sid.as_psid());
    let stays = |hdr: &ACE_HEADER, body: &[u8]| {
        hdr.AceFlags & INHERITED_ACE == 0 && !ace_sid_is(body, sid_bytes)
    };
    let group = sandbox_group_sid
        .map(LocalPsid::from_string)
        .transpose()
        .context("parse sandbox group SID")?;
    let mut group_denies_here = false;
    if let (Some(group), false) = (&group, allows.is_empty()) {
        let group_bytes = group.as_bytes();
        filter_aces(old, |hdr, body| {
            // A deny of reading, that is: the delete-child and delete
            // denies kept beside a root say nothing about reads.
            let denies_read = body.len() >= 8 && body[4] & 0x1 != 0;
            group_denies_here |= stays(hdr, body)
                && is_deny_type(hdr)
                && denies_read
                && ace_sid_is(body, group_bytes);
            false
        })?;
    }
    let new = place_around(
        old,
        stays,
        Placement {
            allows_first: group_denies_here,
        },
        &denies,
        &allows,
    )?;
    // Protection is preserved; nothing is written if no explicit entry
    // changes ([`commit_dacl`]).
    commit_dacl(DaclTarget::Path(canonical_path), &sd, old, &new, how)
        .map(|_| ())
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
    read_aces_at(DaclTarget::Path(canonical_path))
}

/// [`read_aces`] of a path or of an open handle.
pub fn read_aces_at(target: DaclTarget<'_>) -> Result<Vec<AceView>> {
    let (_sd, dacl) = target.read()?;
    let mut out = Vec::new();
    filter_aces(dacl, |hdr, body| {
        out.extend(ace_view(hdr, body));
        false
    })?;
    Ok(out)
}

/// [`read_aces_at`], telling an object with no access list at all
/// (`None`: everyone may do everything) from one with an empty list.
pub fn read_dacl_views(target: DaclTarget<'_>) -> Result<Option<Vec<AceView>>> {
    let (_sd, dacl) = target.read()?;
    if dacl.is_null() {
        return Ok(None);
    }
    let mut out = Vec::new();
    filter_aces(dacl, |hdr, body| {
        out.extend(ace_view(hdr, body));
        false
    })?;
    Ok(Some(out))
}

/// The trustees whose ACEs on a persistent path belong to this crate.
#[derive(Debug, Clone, Copy)]
pub struct PersistentTrustees<'a> {
    /// The sandbox group. `None` once the install record is gone;
    /// its ACEs can then no longer be told apart.
    pub group_sid: Option<&'a str>,
    /// The user the broker runs as.
    pub real_user_sid: &'a str,
    /// Sandbox groups of earlier installs that kept grants were made
    /// for and may still name (the marker's record of them): their
    /// ACEs are ours to remove like the current group's.
    pub previous_group_sids: &'a [String],
    /// The sandbox user. A session's allow for it may precede our deny
    /// ([`persistent_layout_ok`]).
    pub sandbox_user_sid: Option<&'a str>,
    /// The DENY entries the record lists for the path: those wanted now and
    /// those of the last write. `None`: no record, so a deny is told by its
    /// mask ([`product_deny_shape`]).
    pub recorded_denies: Option<&'a [AceView]>,
}

/// What the profile read grant (`crate::profile`) allows on a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileAce {
    /// Listable ([`Mask::DIR_LIST`], not inherited); children are
    /// granted one by one.
    Container,
    /// Read + execute, inherited by everything below.
    Granted,
    /// A single file: read + execute.
    File,
}

/// Whether `a` is an entry this product manages on a persistent path. A
/// group or capability DENY the record does not list is FOREIGN: never
/// counted, never removed (a deny only narrows the sandbox account).
pub fn is_persistent_ace(a: &AceView, t: &PersistentTrustees<'_>) -> bool {
    if t.previous_group_sids.contains(&a.sid) {
        return true;
    }
    if t.group_sid == Some(a.sid.as_str()) || crate::persist::is_capability_sid(&a.sid) {
        return !a.deny
            || match t.recorded_denies {
                Some(listed) => listed
                    .iter()
                    .any(|d| d.deny && d.sid == a.sid && d.mask == a.mask),
                None => product_deny_shape(a.mask),
            };
    }
    (!a.deny && a.sid == SID_OWNER_RIGHTS && a.mask == Mask::READ_CONTROL.bits())
        || (!a.deny && a.sid == t.real_user_sid && a.mask == Mask::OWNER_IMPLICIT.bits())
}

/// Whether `mask` is one this product puts in a DENY: the two deny
/// masks, the delete deny, the delete-child deny.
pub fn product_deny_shape(mask: u32) -> bool {
    [
        DenyMask::ReadDeny.bits(),
        DenyMask::WriteDeny.bits(),
        Mask::DELETE.bits(),
        Mask::FILE_DELETE_CHILD.bits(),
    ]
    .contains(&mask)
}

/// The explicit DENY entries among `aces` that name the sandbox group
/// or a capability SID and are not this product's: left in place by
/// everything here, and said so when a path is forgotten.
pub fn foreign_group_denies(aces: &[AceView], t: &PersistentTrustees<'_>) -> Vec<AceView> {
    aces.iter()
        .filter(|a| {
            a.deny
                && !a.inherited
                && (t.group_sid == Some(a.sid.as_str())
                    || crate::persist::is_capability_sid(&a.sid))
                && !is_persistent_ace(a, t)
        })
        .cloned()
        .collect()
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
    /// The path is part of the profile read grant. Ignored on a write
    /// root, whose own allow for the group is wider and inherits.
    pub profile: Option<ProfileAce>,
}

/// The explicit ACEs a persistent path is to carry, denies first. None
/// names the sandbox USER: its SID is a restricting SID of every session,
/// so an allow for it would pass both checks for all of them.
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
    } else if let Some(p) = w.profile {
        let rx = Mask::FILE_READ_EXEC.bits();
        v.push(match p {
            ProfileAce::Container => AceView::explicit(false, g, Mask::DIR_LIST.bits(), NO_INHERIT),
            ProfileAce::Granted => AceView::explicit(false, g, rx, OICI),
            ProfileAce::File => AceView::explicit(false, g, rx, NO_INHERIT),
        });
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
/// [`comparable`] form: equal to `comparable(persistent_aces(..))`
/// exactly when the path carries the wanted set and nothing else of ours.
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

/// ACEs that let the sandbox account write an object it created here
/// under ANY session's token: an inheritable `CREATOR OWNER` write
/// ALLOW, or an `OWNER RIGHTS` ALLOW with `WRITE_DAC`. Text for a warning.
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

/// Converge the explicit persistent ACEs of `canonical_path` to exactly
/// `want` (empty removes them); every other explicit ACE is kept.
pub fn write_persistent_aces(
    canonical_path: &str,
    t: &PersistentTrustees<'_>,
    want: &[AceView],
) -> Result<Written> {
    write_persistent_aces_at(DaclTarget::Path(canonical_path), t, want, false)
}

/// [`write_persistent_aces`] on a path or an open handle. `finish_walk`
/// forces the walk of the tree: an earlier write may have been cut short.
pub fn write_persistent_aces_at(
    target: DaclTarget<'_>,
    t: &PersistentTrustees<'_>,
    want: &[AceView],
    finish_walk: bool,
) -> Result<Written> {
    let label = target.label();
    let (sd, old) = target
        .read()
        .with_context(|| format!("persistent ACEs '{label}'"))?;
    let stays = |hdr: &ACE_HEADER, body: &[u8]| {
        hdr.AceFlags & INHERITED_ACE == 0
            && !ace_view(hdr, body).is_some_and(|a| is_persistent_ace(&a, t))
    };
    let sids: Vec<LocalPsid> = want
        .iter()
        .map(|a| LocalPsid::from_string(&a.sid))
        .collect::<Result<_>>()?;
    let new_ace = |(a, s): (&AceView, &LocalPsid)| {
        let fl = ACE_FLAGS(u32::from(a.flags));
        if a.deny {
            NewAce::Deny(s.as_psid(), a.mask, fl)
        } else {
            NewAce::Allow(s.as_psid(), a.mask, fl)
        }
    };
    let pairs = || want.iter().zip(&sids);
    let denies: Vec<NewAce> = pairs().filter(|(a, _)| a.deny).map(new_ace).collect();
    let allows: Vec<NewAce> = pairs().filter(|(a, _)| !a.deny).map(new_ace).collect();
    // Our denies always go first — ahead of everything, a session's
    // entries included.
    let new = place_around(
        old,
        stays,
        Placement {
            allows_first: false,
        },
        &denies,
        &allows,
    )?;
    let how = if finish_walk {
        Commit::Walk
    } else {
        Commit::Write
    };
    commit_dacl(target, &sd, old, &new, how).with_context(|| format!("persistent ACEs '{label}'"))
}

/// Whether no explicit allow precedes one of our denies and no explicit
/// deny follows one of our allows. A session's allow for the sandbox user
/// ahead of our deny is the one exception.
pub fn persistent_layout_ok(aces: &[AceView], t: &PersistentTrustees<'_>) -> bool {
    let mut seen_allow = false;
    let mut seen_our_allow = false;
    for a in aces.iter().filter(|a| !a.inherited) {
        let ours = is_persistent_ace(a, t);
        if a.deny && (seen_our_allow || (ours && seen_allow)) {
            return false;
        }
        // A session's allow for the sandbox user ahead of our deny is
        // the one order the product defines that way itself.
        if !a.deny && t.sandbox_user_sid == Some(a.sid.as_str()) {
            continue;
        }
        seen_allow |= !a.deny;
        seen_our_allow |= !a.deny && ours;
    }
    true
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
        previous_group_sids: &[],
        sandbox_user_sid: None,
        recorded_denies: None,
    };

    fn root_want<'a>(cap: &'a str) -> PersistentWant<'a> {
        PersistentWant {
            group_sid: GROUP,
            real_user_sid: REAL,
            capability_sid: Some(cap),
            deny: None,
            deny_fdc: false,
            deny_delete: false,
            profile: None,
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
        // Without a capability SID there is no ALLOW at all.
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
        // The user's own full-control ACE and an inherited persistent ACE are not ours.
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

        // With the install record gone the group's ACEs are not recognised.
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
        // Ours (OWNER RIGHTS with READ_CONTROL only) is not reported.
        let found = owner_write_paths(&[
            ace(SID_CREATOR_OWNER, Mask::GENERIC_ALL.bits(), 0xb),
            ace(SID_CREATOR_OWNER, Mask::GENERIC_ALL.bits(), 0),
            ace(SID_CREATOR_OWNER, Mask::FILE_READ_EXEC.bits(), 0x3),
            ace(SID_OWNER_RIGHTS, Mask::FILE_ALL.bits(), 0x3),
            ace(SID_OWNER_RIGHTS, Mask::READ_CONTROL.bits(), 0x3),
        ]);
        assert_eq!(found.len(), 2, "{found:?}");
    }

    /// The persistent ACEs through the real DACL write and read.
    #[test]
    fn persistent_aces_round_trip_on_disk() {
        // Guests stands in for the sandbox group.
        const GROUP: &str = "S-1-5-32-546";
        let real = crate::sid::current_user_sid().unwrap();
        let cap = crate::persist::new_capability_sid().unwrap();
        let t = PersistentTrustees {
            group_sid: Some(GROUP),
            real_user_sid: &real,
            previous_group_sids: &[],
            sandbox_user_sid: None,
            recorded_denies: None,
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
            profile: None,
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

    /// What the profile read grant writes, per kind of path: one
    /// ALLOW for the group, read + execute at most, inheriting only
    /// on a directory granted whole.
    #[test]
    fn profile_ace_lists_are_pinned() {
        let list = |profile: Option<ProfileAce>, deny: Option<DenyMask>, cap: Option<&str>| {
            persistent_aces(&PersistentWant {
                capability_sid: cap,
                deny,
                profile,
                ..root_want(CAP)
            })
            .iter()
            .map(AceView::sddl)
            .collect::<Vec<_>>()
        };
        assert_eq!(
            list(Some(ProfileAce::Container), None, None),
            [format!("(A;;0x1200a9;;;{GROUP})")]
        );
        assert_eq!(
            list(Some(ProfileAce::Granted), None, None),
            [format!("(A;OICI;0x1200a9;;;{GROUP})")]
        );
        assert_eq!(
            list(Some(ProfileAce::File), None, None),
            [format!("(A;;0x1200a9;;;{GROUP})")]
        );
        assert_eq!(
            list(None, Some(DenyMask::ReadDeny), None),
            [format!("(D;OICI;0x1f01ff;;;{GROUP})")]
        );
        assert_eq!(
            list(Some(ProfileAce::Granted), Some(DenyMask::WriteDeny), None),
            [
                format!("(D;OICI;{:#x};;;{GROUP})", DenyMask::WriteDeny.bits()),
                format!("(A;OICI;0x1200a9;;;{GROUP})"),
            ]
        );
        assert_eq!(
            list(Some(ProfileAce::Container), None, Some(CAP)),
            list(None, None, Some(CAP))
        );
        const WRITE_BITS: u32 = 0x2 | 0x4 | 0x10 | 0x40 | 0x100 | 0x1_0000 | 0x4_0000 | 0x8_0000;
        const GENERIC_BITS: u32 = 0xf000_0000;
        for p in [ProfileAce::Container, ProfileAce::Granted, ProfileAce::File] {
            for a in persistent_aces(&PersistentWant {
                capability_sid: None,
                profile: Some(p),
                ..root_want(CAP)
            }) {
                assert!(!a.deny && a.sid == GROUP);
                assert_eq!(a.mask & (WRITE_BITS | GENERIC_BITS), 0, "{p:?}");
            }
        }
        // FILE_GENERIC_READ (list, read EA, read attributes, read
        // control, synchronize) and traverse.
        assert_eq!(
            Mask::DIR_LIST.bits(),
            0x1 | 0x8 | 0x80 | 0x2_0000 | 0x10_0000 | 0x20
        );
        assert_eq!(Mask::DIR_LIST.bits() & 0x0012_0089, 0x0012_0089);
    }

    /// A container entry written with the narrower mask of an earlier
    /// build is ours, and is not the wanted list: it is rewritten.
    #[test]
    fn a_container_entry_with_the_earlier_mask_converges() {
        let want = persistent_aces(&PersistentWant {
            capability_sid: None,
            profile: Some(ProfileAce::Container),
            ..root_want(CAP)
        });
        let earlier = AceView {
            mask: 0x0010_00a1,
            ..want[0].clone()
        };
        let listed: [AceView; 0] = [];
        for t in [
            T,
            PersistentTrustees {
                recorded_denies: Some(&listed),
                ..T
            },
        ] {
            assert!(is_persistent_ace(&earlier, &t));
            let on_disk = persistent_on_disk(std::slice::from_ref(&earlier), &t, true);
            assert_eq!(on_disk.len(), 1, "not left as someone else's");
            assert_ne!(on_disk, comparable(&want, true));
            assert_eq!(persistent_on_disk(&want, &t, true), comparable(&want, true));
        }
    }

    /// An explicit DENY already on the object stays in front of the allows
    /// written here; a DACL with allows at the head needs a rewrite.
    #[test]
    fn existing_denies_stay_ahead_of_the_allows_written_here() {
        const GROUP: &str = "S-1-5-32-546";
        const EVERYONE: &str = "S-1-1-0";
        let real = crate::sid::current_user_sid().unwrap();
        let t = PersistentTrustees {
            group_sid: Some(GROUP),
            real_user_sid: &real,
            previous_group_sids: &[],
            sandbox_user_sid: None,
            recorded_denies: None,
        };
        let cap = crate::persist::new_capability_sid().unwrap();
        let base = std::env::temp_dir().join(format!("srtwin-canon-{}", std::process::id()));
        let explicit = |p: &str| -> Vec<AceView> {
            read_aces(p)
                .unwrap()
                .into_iter()
                .filter(|a| !a.inherited)
                .collect()
        };
        let canonical = |aces: &[AceView]| {
            let first_allow = aces.iter().position(|a| !a.deny).unwrap_or(aces.len());
            aces[first_allow..].iter().all(|a| !a.deny)
        };
        let owner_sddl = format!(
            "D:P(D;OICI;0x10040;;;{EVERYONE})(D;OICI;0x1;;;{SID_BUILTIN_USERS})\
             (A;OICI;FA;;;{real})(A;OICI;FA;;;{SID_SYSTEM})"
        );
        for (name, want) in [
            (
                "root",
                persistent_aces(&PersistentWant {
                    group_sid: GROUP,
                    real_user_sid: &real,
                    capability_sid: Some(&cap),
                    deny: None,
                    deny_fdc: true,
                    deny_delete: false,
                    profile: None,
                }),
            ),
            (
                "profile",
                persistent_aces(&PersistentWant {
                    group_sid: GROUP,
                    real_user_sid: &real,
                    capability_sid: None,
                    deny: None,
                    deny_fdc: false,
                    deny_delete: false,
                    profile: Some(ProfileAce::Granted),
                }),
            ),
        ] {
            let dir = base.join(name);
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.to_str().unwrap();
            set_path_dacl_from_sddl(path, &owner_sddl, "test").unwrap();
            let before = explicit(path);
            write_persistent_aces(path, &t, &want).unwrap();
            let aces = explicit(path);
            assert!(canonical(&aces), "{name}: {aces:?}");
            assert!(persistent_layout_ok(&aces, &t), "{name}");
            assert_eq!(
                persistent_on_disk(&aces, &t, true),
                comparable(&want, true),
                "{name}"
            );
            let our_allow = aces
                .iter()
                .position(|a| !a.deny && is_persistent_ace(a, &t))
                .unwrap();
            for foreign in [EVERYONE, SID_BUILTIN_USERS] {
                let at = aces
                    .iter()
                    .position(|a| a.deny && a.sid == foreign)
                    .unwrap();
                assert!(
                    at < our_allow,
                    "{name}: deny for {foreign} behind our allow"
                );
            }
            write_persistent_aces(path, &t, &want).unwrap();
            assert_eq!(explicit(path), aces, "{name}");
            write_persistent_aces(path, &t, &[]).unwrap();
            assert_eq!(explicit(path), before, "{name}");

            let head: String = want.iter().map(AceView::sddl).collect();
            let old_sddl = format!("D:P{head}{}", &owner_sddl[3..]);
            set_path_dacl_from_sddl(path, &old_sddl, "test").unwrap();
            let old = explicit(path);
            assert_eq!(
                persistent_on_disk(&old, &t, true),
                comparable(&want, true),
                "{name}: the old layout holds the same entries"
            );
            let has_our_allow_first = want.iter().any(|a| !a.deny);
            assert_eq!(
                persistent_layout_ok(&old, &t),
                !has_our_allow_first,
                "{name}: the old layout is not canonical"
            );
            write_persistent_aces(path, &t, &want).unwrap();
            let repaired = explicit(path);
            assert!(canonical(&repaired), "{name}: {repaired:?}");
            assert!(persistent_layout_ok(&repaired, &t), "{name}");
            set_path_dacl_from_sddl(path, &format!("D:P(A;OICI;FA;;;{real})"), "test").unwrap();
        }
        std::fs::remove_dir_all(&base).ok();
    }

    /// Entries that are not ours are never moved by either writer, and taking
    /// ours out leaves the list exactly as it was, canonical or not.
    #[test]
    fn foreign_entries_keep_their_order_and_removal_restores_the_list() {
        const GROUP: &str = "S-1-5-32-546";
        const SB: &str = "S-1-5-32-547";
        const EVERYONE: &str = "S-1-1-0";
        let real = crate::sid::current_user_sid().unwrap();
        let t = PersistentTrustees {
            group_sid: Some(GROUP),
            real_user_sid: &real,
            previous_group_sids: &[],
            sandbox_user_sid: None,
            recorded_denies: None,
        };
        let cap = crate::persist::new_capability_sid().unwrap();
        let root = persistent_aces(&PersistentWant {
            group_sid: GROUP,
            real_user_sid: &real,
            capability_sid: Some(&cap),
            deny: None,
            deny_fdc: true,
            deny_delete: false,
            profile: None,
        });
        let session = SbAceSet {
            grant: Some(GrantMask::ReadOnly),
            deny_fdc: true,
            ..Default::default()
        };
        let explicit = |p: &str| -> Vec<AceView> {
            read_aces(p)
                .unwrap()
                .into_iter()
                .filter(|a| !a.inherited)
                .collect()
        };
        let sddl = |aces: &[AceView]| -> String { aces.iter().map(AceView::sddl).collect() };
        let ours = |a: &AceView| is_persistent_ace(a, &t) || a.sid == SB;
        let base = std::env::temp_dir().join(format!("srtwin-place-{}", std::process::id()));
        for (name, layout) in [
            (
                "posix",
                format!(
                    "(A;OICI;FA;;;{real})(D;OICI;0x116;;;{SID_BUILTIN_USERS})\
                     (A;OICI;0x1200a9;;;{SID_BUILTIN_USERS})"
                ),
            ),
            (
                "denies-first",
                format!(
                    "(D;OICI;0x10040;;;{EVERYONE})(D;OICI;0x2;;;{SID_BUILTIN_USERS})\
                     (A;OICI;FA;;;{real})(A;OICI;FA;;;{SID_SYSTEM})"
                ),
            ),
            (
                "mixed",
                format!(
                    "(A;OICI;FA;;;{real})(D;OICI;0x2;;;{EVERYONE})\
                     (A;OICI;0x1200a9;;;{SID_BUILTIN_USERS})(D;OICI;0x10000;;;{SID_BUILTIN_USERS})\
                     (A;OICI;FA;;;{SID_SYSTEM})"
                ),
            ),
            (
                "allows-only",
                format!("(A;OICI;FA;;;{real})(A;OICI;FA;;;{SID_SYSTEM})"),
            ),
        ] {
            let dir = base.join(name);
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.to_str().unwrap();
            set_path_dacl_from_sddl(path, &format!("D:P{layout}"), "test").unwrap();
            let before = explicit(path);
            assert_eq!(before.len(), layout.matches('(').count(), "{name}: setup");
            let last_foreign_deny = before.iter().rposition(|a| a.deny);

            let check = |when: &str| {
                let aces = explicit(path);
                let foreign: Vec<AceView> = aces.iter().filter(|a| !ours(a)).cloned().collect();
                assert_eq!(foreign, before, "{name}, {when}: the others moved");
                let first_allow = aces.iter().position(|a| !a.deny).unwrap();
                for (i, a) in aces.iter().enumerate() {
                    if a.deny && ours(a) {
                        assert!(i < first_allow, "{name}, {when}: {a:?} behind an allow");
                    }
                }
                let first_ours = aces.iter().position(|a| !a.deny && ours(a));
                if let Some(first_ours) = first_ours {
                    assert!(
                        aces[first_ours..].iter().all(|a| !a.deny),
                        "{name}, {when}: a deny behind our allow: {}",
                        sddl(&aces)
                    );
                    let foreign_before = aces[..first_ours].iter().filter(|a| !ours(a)).count();
                    assert_eq!(
                        foreign_before,
                        last_foreign_deny.map_or(0, |i| i + 1),
                        "{name}, {when}: {}",
                        sddl(&aces)
                    );
                }
                assert!(persistent_layout_ok(&aces, &t), "{name}, {when}");
                aces
            };

            write_persistent_aces(path, &t, &root).unwrap();
            let aces = check("kept grant");
            assert_eq!(persistent_on_disk(&aces, &t, true), comparable(&root, true));
            write_persistent_aces(path, &t, &root).unwrap();
            assert_eq!(
                explicit(path),
                aces,
                "{name}: a second write changes nothing"
            );
            write_persistent_aces(path, &t, &[]).unwrap();
            assert_eq!(explicit(path), before, "{name}: kept grant removed");

            apply_sandbox_aces(path, SB, session).unwrap();
            check("session grant");
            apply_sandbox_aces(path, SB, SbAceSet::default()).unwrap();
            assert_eq!(explicit(path), before, "{name}: session grant removed");

            write_persistent_aces(path, &t, &root).unwrap();
            apply_sandbox_aces(path, SB, session).unwrap();
            let both = check("kept, then session");
            assert_eq!(persistent_on_disk(&both, &t, true), comparable(&root, true));
            write_persistent_aces(path, &t, &root).unwrap();
            check("kept rewritten under the session");
            apply_sandbox_aces(path, SB, SbAceSet::default()).unwrap();
            check("session gone, kept stays");
            apply_sandbox_aces(path, SB, session).unwrap();
            write_persistent_aces(path, &t, &[]).unwrap();
            check("kept gone, session stays");
            apply_sandbox_aces(path, SB, SbAceSet::default()).unwrap();
            assert_eq!(explicit(path), before, "{name}: both removed");

            set_path_dacl_from_sddl(path, &format!("D:P(A;OICI;FA;;;{real})"), "test").unwrap();
        }
        std::fs::remove_dir_all(&base).ok();
    }

    /// A session allow admitted on an excluded path goes ahead of the
    /// group's exclusion deny on that object — and only there.
    #[test]
    fn an_admitted_session_allow_precedes_our_own_exclusion_deny() {
        const GROUP: &str = "S-1-5-32-546";
        const SB: &str = "S-1-5-32-547";
        const EVERYONE: &str = "S-1-1-0";
        let real = crate::sid::current_user_sid().unwrap();
        let t = PersistentTrustees {
            group_sid: Some(GROUP),
            real_user_sid: &real,
            previous_group_sids: &[],
            sandbox_user_sid: Some(SB),
            recorded_denies: None,
        };
        let exclusion = persistent_aces(&PersistentWant {
            group_sid: GROUP,
            real_user_sid: &real,
            capability_sid: None,
            deny: Some(DenyMask::ReadDeny),
            deny_fdc: false,
            deny_delete: false,
            profile: None,
        });
        let read = SbAceSet {
            grant: Some(GrantMask::ReadOnly),
            ..Default::default()
        };
        let explicit = |p: &str| -> Vec<AceView> {
            read_aces(p)
                .unwrap()
                .into_iter()
                .filter(|a| !a.inherited)
                .collect()
        };
        let at = |aces: &[AceView], sid: &str, deny: bool| {
            aces.iter().position(|a| a.sid == sid && a.deny == deny)
        };
        let base = std::env::temp_dir().join(format!("srtwin-admit-{}", std::process::id()));
        let dir = base.join("store");
        std::fs::create_dir_all(dir.join("inner")).unwrap();
        let path = dir.to_str().unwrap();
        set_path_dacl_from_sddl(
            path,
            &format!("D:P(D;OICI;0x10000;;;{EVERYONE})(A;OICI;FA;;;{real})"),
            "test",
        )
        .unwrap();
        write_persistent_aces(path, &t, &exclusion).unwrap();
        let before = explicit(path);

        apply_sandbox_aces_over(path, SB, read, Some(GROUP)).unwrap();
        let aces = explicit(path);
        assert!(
            at(&aces, SB, false) < at(&aces, GROUP, true),
            "the allow is behind the exclusion deny: {aces:?}"
        );
        assert!(persistent_layout_ok(&aces, &t));
        assert_eq!(
            persistent_on_disk(&aces, &t, true),
            comparable(&exclusion, true)
        );
        write_persistent_aces(path, &t, &exclusion).unwrap();
        let rewritten = explicit(path);
        assert!(
            at(&rewritten, GROUP, true) < at(&rewritten, SB, false),
            "{rewritten:?}"
        );
        assert_eq!(at(&rewritten, GROUP, true), Some(0));
        apply_sandbox_aces_over(path, SB, read, Some(GROUP)).unwrap();
        assert_eq!(explicit(path), aces);
        apply_sandbox_aces_over(path, SB, SbAceSet::default(), Some(GROUP)).unwrap();
        assert_eq!(explicit(path), before);

        let inner = dir.join("inner");
        let inner = inner.to_str().unwrap();
        apply_sandbox_aces_over(inner, SB, read, Some(GROUP)).unwrap();
        let all = read_aces(inner).unwrap();
        let allow = all.iter().position(|a| a.sid == SB && !a.deny).unwrap();
        let inherited = all.iter().position(|a| a.sid == GROUP && a.deny).unwrap();
        assert!(allow < inherited && all[inherited].inherited);
        apply_sandbox_aces_over(inner, SB, SbAceSet::default(), Some(GROUP)).unwrap();

        let both = SbAceSet {
            deny_fdc: true,
            ..read
        };
        apply_sandbox_aces_over(path, SB, both, Some(GROUP)).unwrap();
        let aces = explicit(path);
        assert!(at(&aces, SB, true) < at(&aces, SB, false));
        assert!(at(&aces, SB, false) < at(&aces, GROUP, true));
        apply_sandbox_aces_over(path, SB, SbAceSet::default(), Some(GROUP)).unwrap();

        write_persistent_aces(path, &t, &[]).unwrap();
        for group in [None, Some(GROUP)] {
            apply_sandbox_aces_over(path, SB, read, group).unwrap();
            let aces = explicit(path);
            assert!(at(&aces, EVERYONE, true) < at(&aces, SB, false), "{aces:?}");
            apply_sandbox_aces_over(path, SB, SbAceSet::default(), group).unwrap();
        }
        let fdc_only = persistent_aces(&PersistentWant {
            group_sid: GROUP,
            real_user_sid: &real,
            capability_sid: None,
            deny: None,
            deny_fdc: true,
            deny_delete: false,
            profile: None,
        });
        write_persistent_aces(path, &t, &fdc_only).unwrap();
        apply_sandbox_aces_over(path, SB, read, Some(GROUP)).unwrap();
        let aces = explicit(path);
        assert!(at(&aces, EVERYONE, true) < at(&aces, SB, false), "{aces:?}");

        set_path_dacl_from_sddl(path, &format!("D:P(A;OICI;FA;;;{real})"), "test").unwrap();
        std::fs::remove_dir_all(&base).ok();
    }

    /// Entries naming the group of an earlier install are recognised
    /// as ours when the marker still lists that group.
    #[test]
    fn entries_of_a_previous_group_are_ours_to_remove() {
        let old = "S-1-5-21-1-2-3-1001".to_owned();
        let ace = |sid: &str, deny: bool| AceView {
            deny,
            sid: sid.to_owned(),
            mask: 0x1200a9,
            flags: 3,
            inherited: false,
        };
        let previous = [old.clone()];
        let with = PersistentTrustees {
            group_sid: Some("S-1-5-21-1-2-3-2002"),
            real_user_sid: "S-1-5-21-9-9-9-500",
            previous_group_sids: &previous,
            sandbox_user_sid: None,
            recorded_denies: None,
        };
        let without = PersistentTrustees {
            previous_group_sids: &[],
            sandbox_user_sid: None,
            ..with
        };
        for deny in [false, true] {
            assert!(is_persistent_ace(&ace(&old, deny), &with));
            assert!(!is_persistent_ace(&ace(&old, deny), &without));
            assert_eq!(
                is_persistent_ace(&ace("S-1-5-21-1-2-3-2002", deny), &with),
                !deny
            );
            assert!(!is_persistent_ace(&ace("S-1-5-32-545", deny), &with));
        }
    }

    /// The fence an embedder may put on a write root for the sandbox
    /// group: do not delete, rename or re-permission this folder.
    const FENCE: u32 = 0x0001_0000 | 0x0004_0000 | 0x0008_0000 | 0x40;

    /// Which entries for the sandbox group are the product's.
    #[test]
    fn a_group_deny_the_record_does_not_list_is_foreign() {
        let deny = |sid: &str, mask: u32, flags: u8| AceView {
            deny: true,
            inherited: false,
            flags,
            mask,
            sid: sid.to_owned(),
        };
        let allow = |sid: &str, mask: u32| AceView {
            deny: false,
            ..deny(sid, mask, 0x3)
        };
        let fence = deny(GROUP, FENCE, 0);
        let want = persistent_aces(&PersistentWant {
            deny: Some(DenyMask::WriteDeny),
            deny_fdc: true,
            deny_delete: true,
            ..root_want(CAP)
        });
        let listed: Vec<AceView> = want.iter().filter(|a| a.deny).cloned().collect();
        let with_record = PersistentTrustees {
            recorded_denies: Some(&listed),
            ..T
        };
        for t in [&T, &with_record] {
            assert!(!is_persistent_ace(&fence, t));
            assert!(!is_persistent_ace(&deny(CAP, FENCE, 0), t));
            for w in &listed {
                assert!(is_persistent_ace(w, t), "{}", w.sddl());
            }
            let exclusion = persistent_aces(&PersistentWant {
                capability_sid: None,
                deny: Some(DenyMask::ReadDeny),
                ..root_want(CAP)
            });
            let t_ex = PersistentTrustees {
                recorded_denies: t.recorded_denies.map(|_| exclusion.as_slice()),
                ..*t
            };
            assert!(is_persistent_ace(&exclusion[0], &t_ex));
            assert!(is_persistent_ace(&allow(GROUP, 0x1f01ff), t));
            assert!(is_persistent_ace(&allow(CAP, 0x1200a9), t));
            assert!(!is_persistent_ace(&deny(SID_BUILTIN_USERS, FENCE, 0), t));
        }
        let delete_only = deny(GROUP, Mask::DELETE.bits(), 0);
        let none_listed = PersistentTrustees {
            recorded_denies: Some(&[]),
            ..T
        };
        assert!(is_persistent_ace(&delete_only, &T));
        assert!(!is_persistent_ace(&delete_only, &none_listed));
        assert!(!product_deny_shape(FENCE));

        let want_c = comparable(&want, true);
        let mut dacl = vec![fence.clone()];
        dacl.extend(want.clone());
        assert_eq!(persistent_on_disk(&dacl, &with_record, true), want_c);
        assert!(persistent_layout_ok(&dacl, &with_record));
        assert_eq!(
            foreign_group_denies(&dacl, &with_record),
            std::slice::from_ref(&fence)
        );
        let mut stray = dacl.clone();
        stray.push(allow(GROUP, 0x1f01ff));
        assert_ne!(persistent_on_disk(&stray, &with_record, true), want_c);
        let mut behind = want.clone();
        behind.push(fence.clone());
        assert_eq!(persistent_on_disk(&behind, &with_record, true), want_c);
        assert!(!persistent_layout_ok(&behind, &with_record));
    }

    /// The one test for writing without the walk of the tree.
    #[test]
    fn only_a_change_to_what_is_handed_down_needs_the_walk() {
        let ace = |ty: u8, flags: u8, tag: u8| vec![ty, flags, 12, 0, tag, 0, 0, 0, 1, 1, 0, 0];
        const OI: u8 = 0x1;
        const CI: u8 = 0x2;
        const NP: u8 = 0x4;
        const IO: u8 = 0x8;
        let a = ace(0, OI | CI, 1);
        let b = ace(1, CI, 2);
        let own = ace(0, 0, 3);
        let base = vec![a.clone(), own.clone(), b.clone()];
        let same = |after: &[Vec<u8>]| same_inheritable(&base, after);
        assert!(same(&[a.clone(), b.clone()]));
        assert!(same(&[
            ace(1, 0, 9),
            a.clone(),
            ace(0, NP, 8),
            b.clone(),
            own.clone()
        ]));
        assert!(same(&[a.clone(), ace(0, 0, 77), b.clone()]));
        assert!(same_inheritable(std::slice::from_ref(&own), &[]));
        assert!(same_inheritable(&[], &[]));
        assert!(!same(&[a.clone(), own.clone()]));
        assert!(!same(&[b.clone(), own.clone(), a.clone()]));
        assert!(!same(&[a.clone(), own.clone(), ace(1, CI, 3)]));
        assert!(!same(&[a.clone(), own.clone(), ace(0, CI, 2)]));
        for flags in [
            OI,
            CI,
            OI | CI,
            OI | IO,
            CI | IO,
            OI | CI | IO,
            CI | NP,
            OI | NP,
        ] {
            let extra = ace(0, flags, 5);
            assert!(
                !same(&[a.clone(), own.clone(), b.clone(), extra]),
                "{flags:#x}"
            );
        }
        assert!(!same(&[ace(0, OI, 1), own.clone(), b.clone()]));
        assert!(!same(&[ace(0, OI | CI | IO, 1), own.clone(), b.clone()]));
        assert!(!same(&[ace(0, 0, 1), own.clone(), b.clone()]));
        assert!(!same(&[a.clone(), ace(0, OI, 3), b.clone()]));
    }

    /// A write that changes only an entry of the directory itself touches
    /// nothing below; one that changes what is handed down reaches it. A
    /// foreign group deny survives both; a stray group allow does not.
    #[test]
    fn a_write_walks_the_tree_only_when_what_is_handed_down_changes() {
        const GROUP: &str = "S-1-5-32-546";
        let real = crate::sid::current_user_sid().unwrap();
        let cap = crate::persist::new_capability_sid().unwrap();
        let dir = std::env::temp_dir().join(format!("srtwin-local-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sub").join("deep")).unwrap();
        std::fs::write(dir.join("sub").join("deep").join("f.txt"), b"x").unwrap();
        let path = dir.to_str().unwrap();
        let child = dir.join("sub");
        let child = child.to_str().unwrap();
        let grandchild = dir.join("sub").join("deep").join("f.txt");
        let grandchild = grandchild.to_str().unwrap();
        let state = |p: &str| {
            let (sd, _) = read_file_dacl(p).unwrap();
            (
                read_aces(p).unwrap(),
                sd_dacl_auto_inherited(&sd).unwrap(),
                sd_dacl_protected(&sd).unwrap(),
            )
        };
        let below = || (state(child), state(grandchild));
        let inherited_raw = |p: &str| {
            let (_sd, dacl) = read_file_dacl(p).unwrap();
            let mut out: Vec<Vec<u8>> = Vec::new();
            filter_aces(dacl, |hdr, body| {
                if hdr.AceFlags & INHERITED_ACE != 0 {
                    out.push(body.to_vec());
                }
                false
            })
            .unwrap();
            out
        };
        let owner_and_group = |p: &str| {
            use windows::Win32::Security::{GROUP_SECURITY_INFORMATION, GetLengthSid};
            let w = wstr(p);
            let (mut owner, mut group) = (PSID::default(), PSID::default());
            let mut psd = PSECURITY_DESCRIPTOR::default();
            let r = unsafe {
                GetNamedSecurityInfoW(
                    pcwstr(&w),
                    SE_FILE_OBJECT,
                    OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION,
                    Some(&mut owner),
                    Some(&mut group),
                    None,
                    None,
                    &mut psd,
                )
            };
            win32_ok(r, "GetNamedSecurityInfoW(owner, group)").unwrap();
            let _sd = OwnedSd::from_raw(psd);
            let text = |sid: PSID| {
                let len = unsafe { GetLengthSid(sid) } as usize;
                let bytes = unsafe { std::slice::from_raw_parts(sid.0 as *const u8, len) };
                sid_string_from_bytes(bytes).unwrap()
            };
            (text(owner), text(group))
        };
        let counted = |f: &dyn Fn() -> Written| {
            let before = write_counts();
            let how = f();
            let after = write_counts();
            (how, after.0 - before.0, after.1 - before.1)
        };

        let root_marks = state(path);
        let root_inherited = inherited_raw(path);
        let root_owner = owner_and_group(path);
        assert!(!root_inherited.is_empty(), "setup: the root inherits");
        let fence = AceView {
            deny: true,
            inherited: false,
            flags: 0,
            mask: FENCE,
            sid: GROUP.to_owned(),
        };
        let (sd, old) = read_file_dacl(path).unwrap();
        let group = LocalPsid::from_string(GROUP).unwrap();
        let laid = place_around(
            old,
            |h, _| h.AceFlags & INHERITED_ACE == 0,
            Placement::default(),
            &[NewAce::Deny(group.as_psid(), FENCE, NO_INHERIT)],
            &[],
        )
        .unwrap();
        let untouched = below();
        assert_eq!(
            commit_dacl(DaclTarget::Path(path), &sd, old, &laid, Commit::Write).unwrap(),
            Written::Local
        );
        drop(sd);
        assert_eq!(below(), untouched, "an object-only write reached below");
        let now = state(path);
        assert_eq!(
            (now.1, now.2),
            (root_marks.1, root_marks.2),
            "the root's auto-inherited mark and protection"
        );
        assert_eq!(inherited_raw(path), root_inherited);
        assert_eq!(owner_and_group(path), root_owner);

        let want = persistent_aces(&PersistentWant {
            group_sid: GROUP,
            real_user_sid: &real,
            capability_sid: Some(&cap),
            deny: None,
            deny_fdc: false,
            deny_delete: false,
            profile: None,
        });
        let t = PersistentTrustees {
            group_sid: Some(GROUP),
            real_user_sid: &real,
            previous_group_sids: &[],
            sandbox_user_sid: None,
            recorded_denies: Some(&[]),
        };
        let (how, walks, _) = counted(&|| write_persistent_aces(path, &t, &want).unwrap());
        assert_eq!((how, walks), (Written::Tree, 1));
        let aces = read_aces(path).unwrap();
        assert_eq!(persistent_on_disk(&aces, &t, true), comparable(&want, true));
        assert!(persistent_layout_ok(&aces, &t));
        assert_eq!(
            foreign_group_denies(&aces, &t),
            std::slice::from_ref(&fence)
        );
        let at = |aces: &[AceView], deny: bool| {
            aces.iter().position(|a| a.sid == GROUP && a.deny == deny)
        };
        assert!(at(&aces, true) < at(&aces, false));
        assert!(
            state(grandchild)
                .0
                .iter()
                .any(|a| a.inherited && a.sid == cap),
            "the grant did not reach a deep child"
        );
        let granted_below = below();
        let marked = state(path);
        assert!(marked.1, "setup: the walking write marks the list");

        let fenced = persistent_aces(&PersistentWant {
            group_sid: GROUP,
            real_user_sid: &real,
            capability_sid: Some(&cap),
            deny: None,
            deny_fdc: false,
            deny_delete: true,
            profile: None,
        });
        let listed: Vec<AceView> = fenced.iter().filter(|a| a.deny).cloned().collect();
        let t_fenced = PersistentTrustees {
            recorded_denies: Some(&listed),
            ..t
        };
        let (how, walks, local) =
            counted(&|| write_persistent_aces(path, &t_fenced, &fenced).unwrap());
        assert_eq!((how, walks, local), (Written::Local, 0, 1));
        assert_eq!(below(), granted_below);
        let aces = read_aces(path).unwrap();
        assert_eq!(
            persistent_on_disk(&aces, &t_fenced, true),
            comparable(&fenced, true)
        );
        assert_eq!(
            foreign_group_denies(&aces, &t_fenced),
            std::slice::from_ref(&fence)
        );
        let now = state(path);
        assert_eq!(
            (now.1, now.2),
            (true, marked.2),
            "the auto-inherited mark was lost, or protection changed"
        );
        assert_eq!(inherited_raw(path), root_inherited);
        assert_eq!(owner_and_group(path), root_owner);
        let before = write_counts();
        assert_eq!(
            write_persistent_aces_at(DaclTarget::Path(path), &t_fenced, &fenced, true).unwrap(),
            Written::Tree
        );
        assert_eq!(write_counts().0 - before.0, 1);

        let (sd, old) = read_file_dacl(path).unwrap();
        let with_stray = place_around(
            old,
            |h, _| h.AceFlags & INHERITED_ACE == 0,
            Placement::default(),
            &[],
            &[NewAce::Allow(
                group.as_psid(),
                Mask::FILE_ALL.bits(),
                NO_INHERIT,
            )],
        )
        .unwrap();
        commit_dacl(DaclTarget::Path(path), &sd, old, &with_stray, Commit::Write).unwrap();
        drop(sd);
        let aces = read_aces(path).unwrap();
        assert_ne!(
            persistent_on_disk(&aces, &t_fenced, true),
            comparable(&fenced, true)
        );
        write_persistent_aces(path, &t_fenced, &fenced).unwrap();
        let aces = read_aces(path).unwrap();
        assert_eq!(
            persistent_on_disk(&aces, &t_fenced, true),
            comparable(&fenced, true)
        );
        assert!(
            !aces
                .iter()
                .any(|a| !a.deny && a.sid == GROUP && a.mask == Mask::FILE_ALL.bits())
        );

        let (how, walks, _) = counted(&|| write_persistent_aces(path, &t_fenced, &[]).unwrap());
        assert_eq!((how, walks), (Written::Tree, 1));
        let aces = read_aces(path).unwrap();
        assert!(persistent_on_disk(&aces, &t_fenced, true).is_empty());
        assert_eq!(
            foreign_group_denies(&aces, &t_fenced),
            std::slice::from_ref(&fence)
        );
        assert!(!state(grandchild).0.iter().any(|a| a.sid == cap));
        type Seen = (Vec<AceView>, bool, bool);
        type Kept<'a> = (&'a [AceView], bool);
        fn lists(s: &(Seen, Seen)) -> (Kept<'_>, Kept<'_>) {
            ((&s.0.0, s.0.2), (&s.1.0, s.1.2))
        }
        assert_eq!(
            lists(&below()),
            lists(&untouched),
            "forgetting restores what is below"
        );

        let session = SbAceSet {
            deny_delete: true,
            ..Default::default()
        };
        const SB: &str = "S-1-5-32-547";
        let before = write_counts();
        apply_sandbox_aces_over(path, SB, session, None).unwrap();
        assert_eq!(
            (write_counts().0 - before.0, write_counts().1 - before.1),
            (0, 1)
        );
        let before = write_counts();
        apply_sandbox_aces_over(path, SB, session, None).unwrap();
        assert_eq!(write_counts(), before, "an unchanged list is not written");
        apply_sandbox_aces_over(path, SB, SbAceSet::default(), None).unwrap();
        assert_eq!(lists(&below()), lists(&untouched));
        let shut = dir.join("shut");
        std::fs::create_dir_all(&shut).unwrap();
        let shut = shut.to_str().unwrap();
        let lockdown = build_allow_dacl(&[
            Allow(&real, Mask::FILE_ALL, OICI),
            Allow(SID_SYSTEM, Mask::FILE_ALL, OICI),
        ])
        .unwrap();
        write_file_dacl(shut, lockdown.as_ptr(), Protection::Protected).unwrap();
        let shut_before = state(shut);
        assert!(shut_before.2, "setup: protected");
        let (sd, old) = read_file_dacl(shut).unwrap();
        let with_own = place_around(
            old,
            |h, _| h.AceFlags & INHERITED_ACE == 0,
            Placement::default(),
            &[NewAce::Deny(group.as_psid(), FENCE, NO_INHERIT)],
            &[],
        )
        .unwrap();
        assert_eq!(
            commit_dacl(DaclTarget::Path(shut), &sd, old, &with_own, Commit::Write).unwrap(),
            Written::Local
        );
        drop(sd);
        let shut_after = state(shut);
        assert_eq!((shut_after.1, shut_after.2), (shut_before.1, true));
        assert_eq!(shut_after.0.len(), shut_before.0.len() + 1);
        assert!(inherited_raw(shut).is_empty());
        assert_eq!(owner_and_group(shut), owner_and_group(path));

        let before = write_counts();
        apply_sandbox_aces(path, SB, SbAceSet::default()).unwrap();
        assert_eq!(write_counts().0 - before.0, 1);

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A session's deny for the sandbox user stays in front of the
    /// group's allow, whichever of the two is written last, and
    /// removing the group's ACEs leaves it.
    #[test]
    fn a_session_deny_stays_ahead_of_the_group_allow() {
        const GROUP: &str = "S-1-5-32-546";
        const SB: &str = "S-1-5-32-547";
        let real = crate::sid::current_user_sid().unwrap();
        let t = PersistentTrustees {
            group_sid: Some(GROUP),
            real_user_sid: &real,
            previous_group_sids: &[],
            sandbox_user_sid: None,
            recorded_denies: None,
        };
        let want = persistent_aces(&PersistentWant {
            group_sid: GROUP,
            real_user_sid: &real,
            capability_sid: None,
            deny: None,
            deny_fdc: false,
            deny_delete: false,
            profile: Some(ProfileAce::Granted),
        });
        let deny = SbAceSet {
            deny: Some(DenyMask::ReadDeny),
            ..Default::default()
        };
        let check = |path: &str, when: &str| {
            let aces: Vec<AceView> = read_aces(path)
                .unwrap()
                .into_iter()
                .filter(|a| !a.inherited)
                .collect();
            let d = aces.iter().position(|a| a.deny && a.sid == SB);
            let a = aces.iter().position(|a| !a.deny && a.sid == GROUP);
            assert!(
                matches!((d, a), (Some(d), Some(a)) if d < a),
                "{when}: {aces:?}"
            );
            assert_eq!(
                persistent_on_disk(&aces, &t, true),
                comparable(&want, true),
                "{when}"
            );
        };
        let base = std::env::temp_dir().join(format!("srtwin-order-{}", std::process::id()));
        let a = base.join("deny-first");
        std::fs::create_dir_all(&a).unwrap();
        let a = a.to_str().unwrap();
        apply_sandbox_aces(a, SB, deny).unwrap();
        write_persistent_aces(a, &t, &want).unwrap();
        check(a, "allow written after the deny");
        let b = base.join("allow-first");
        std::fs::create_dir_all(&b).unwrap();
        let b = b.to_str().unwrap();
        write_persistent_aces(b, &t, &want).unwrap();
        apply_sandbox_aces(b, SB, deny).unwrap();
        check(b, "deny written after the allow");
        write_persistent_aces(b, &t, &want).unwrap();
        check(b, "allow rewritten");
        write_persistent_aces(b, &t, &[]).unwrap();
        let left = read_aces(b).unwrap();
        assert!(left.iter().any(|a| a.deny && !a.inherited && a.sid == SB));
        assert!(!left.iter().any(|a| a.sid == GROUP));
        std::fs::remove_dir_all(&base).ok();
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
