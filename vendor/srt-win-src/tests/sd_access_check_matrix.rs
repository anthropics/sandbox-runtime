//! Proof that the security descriptor on the WFP BLOCK filters
//! matches the token shapes `wfp::install_filters` relies on it to
//! match — and only those.
//!
//! WFP's `ALE_USER_ID` `FWP_MATCH_EQUAL` condition runs `AccessCheck`
//! on the token the connect is attributed to against the filter's
//! SD; the filter matches iff the check grants. This test calls
//! `AccessCheck` directly — no live WFP engine — so it pins the SD
//! semantics independent of the network stack.
//!
//! The sandbox account itself can't be exercised without
//! provisioning it, so the CALLING user stands in for it: the
//! sandbox-user SD is keyed on the caller's own SID wherever a row
//! is about "a token of the sandbox account", and on a SID the
//! caller does not carry wherever a row is about "some other user".
//!
//! | token                                   | sandbox-user SD |
//! |-----------------------------------------|-----------------|
//! | sandbox account, plain                  | match           |
//! | another real user                       | no match        |
//! | anonymous                               | no match        |
//! | AppContainer of the sandbox account     | match           |
//! | AppContainer of another real user       | no match        |
//! | sandbox account, user SID deny-only     | no match        |
//! | sandbox account, integrity lowered      | recorded        |
//!
//! The anonymous row is a gap the filter set leaves open: a thread of
//! the sandbox account that impersonates the anonymous token is not
//! matched, and no filter is keyed on the anonymous SID, which would
//! apply to every process on the machine. The row is asserted so the
//! gap stays visible.
//!
//! The deny-only row is not what the fence wants — it is what an
//! ALLOW ACE can do. A deny-only SID satisfies no ALLOW ACE, so no
//! descriptor of this shape reaches that token; the row is asserted
//! so the gap stays visible.
//!
//! ## Integrity levels and the generic mapping
//!
//! An access check runs the mandatory integrity check before it reads
//! the DACL. A token whose integrity level is below the descriptor's
//! label (medium when the descriptor has none) keeps only the rights
//! the caller's `GENERIC_MAPPING` files under read and execute. The
//! mapping the filtering engine passes is not something this crate
//! controls, so every row is evaluated under [`STRICT`], which files
//! the requested right under nothing: a grant under it holds under
//! any mapping.
//!
//! Each check prints one line to stderr (written past the test
//! harness's capture, so it shows for passing tests too): the token's
//! type, impersonation level and integrity level, the descriptor,
//! and the granted mask and Win32 status under [`STRICT`] and under
//! [`LENIENT`]. Denied under the first and granted under the second
//! means the mandatory check, not the DACL, refused. A failure of the
//! `AccessCheck` call itself is never read as "no match": it panics
//! with the Win32 error.

#![cfg(windows)]

use std::ffi::c_void;
use std::fmt;
use std::io::Write;
use std::mem::size_of;
use windows::Win32::Foundation::{
    CloseHandle, GENERIC_ALL, GENERIC_EXECUTE, GENERIC_READ, GENERIC_WRITE, GetLastError, HANDLE,
    HLOCAL, LocalFree,
};
use windows::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows::Win32::Security::{
    AccessCheck, CREATE_RESTRICTED_TOKEN_FLAGS, CreateRestrictedToken, DuplicateTokenEx,
    GENERIC_MAPPING, GetLengthSid, GetTokenInformation, ImpersonateAnonymousToken, PRIVILEGE_SET,
    PSECURITY_DESCRIPTOR, PSID, RevertToSelf, SID_AND_ATTRIBUTES, SecurityImpersonation,
    SetTokenInformation, TOKEN_ALL_ACCESS, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE,
    TOKEN_INFORMATION_CLASS, TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TokenImpersonation,
    TokenImpersonationLevel, TokenIntegrityLevel, TokenType,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken,
};
use windows::core::BOOL;

use srt_win::sid::{LocalPsid, psid_to_string};
use srt_win::util::wstr;
use srt_win::wfp::sddl_sandbox_user;

/// `CC` in SDDL is `ADS_RIGHT_DS_CREATE_CHILD` = bit 0. The filters
/// only need a single bit; `AccessCheck` is asked for that bit.
const DESIRED_ACCESS: u32 = 1;

/// Files [`DESIRED_ACCESS`] under no category. A token whose
/// integrity level is below the descriptor's label is then refused
/// whatever the DACL says — the strictest answer any mapping gives.
const STRICT: GENERIC_MAPPING = GENERIC_MAPPING {
    GenericRead: GENERIC_READ.0,
    GenericWrite: GENERIC_WRITE.0,
    GenericExecute: GENERIC_EXECUTE.0,
    GenericAll: GENERIC_ALL.0,
};

/// Files [`DESIRED_ACCESS`] under execute, which a no-write-up label
/// leaves to a token of lower integrity. Diagnostic only: a pair
/// denied under [`STRICT`] and granted under this one was refused by
/// the mandatory integrity check, not by the DACL.
const LENIENT: GENERIC_MAPPING = GENERIC_MAPPING {
    GenericRead: 0,
    GenericWrite: 0,
    GenericExecute: DESIRED_ACCESS,
    GenericAll: DESIRED_ACCESS,
};

/// The low mandatory level.
const LOW_INTEGRITY_SID: &str = "S-1-16-4096";

/// `SE_GROUP_INTEGRITY`: marks a SID as a token's integrity level.
const SE_GROUP_INTEGRITY: u32 = 0x20;

/// A well-formed RID under `BUILTIN` that maps to nothing — a SID no
/// token here carries.
const FOREIGN_SID: &str = "S-1-5-32-9999";

/// A well-formed AppContainer package SID. It names no installed
/// package; a lowbox token only needs the SID to be of this form.
const PACKAGE_SID: &str = "S-1-15-2-1111-2222-3333-4444-5555-6666-7777";

/// `OBJECT_ATTRIBUTES`, for the one call below that takes it.
#[repr(C)]
struct ObjectAttributes {
    length: u32,
    root_directory: HANDLE,
    object_name: *const c_void,
    attributes: u32,
    security_descriptor: *const c_void,
    security_quality_of_service: *const c_void,
}

// The system call that derives an AppContainer token from an
// existing one. `raw-dylib` so the test links without an import
// library for it.
#[link(name = "ntdll", kind = "raw-dylib")]
unsafe extern "system" {
    fn NtCreateLowBoxToken(
        token: *mut HANDLE,
        existing_token: HANDLE,
        desired_access: u32,
        object_attributes: *const ObjectAttributes,
        package_sid: PSID,
        capability_count: u32,
        capabilities: *const SID_AND_ATTRIBUTES,
        handle_count: u32,
        handles: *const HANDLE,
    ) -> i32;
}

fn own_primary_token() -> HANDLE {
    let mut primary = HANDLE::default();
    unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY,
            &mut primary,
        )
        .expect("OpenProcessToken");
    }
    primary
}

/// Impersonation-level duplicate of `token` — `AccessCheck` requires
/// an impersonation token. Closes `token`.
fn into_impersonation(token: HANDLE) -> HANDLE {
    let mut imp = HANDLE::default();
    unsafe {
        DuplicateTokenEx(
            token,
            TOKEN_ALL_ACCESS,
            None,
            SecurityImpersonation,
            TokenImpersonation,
            &mut imp,
        )
        .expect("DuplicateTokenEx");
        let _ = CloseHandle(token);
    }
    imp
}

/// The calling process's own token.
fn own_token() -> HANDLE {
    into_impersonation(own_primary_token())
}

/// The anonymous token: what a thread's effective token is after
/// `ImpersonateAnonymousToken`. It is used as opened — an
/// impersonation token already, and `TOKEN_QUERY` is all
/// `AccessCheck` and [`describe`] need.
fn anonymous_token() -> HANDLE {
    let mut tok = HANDLE::default();
    unsafe {
        ImpersonateAnonymousToken(GetCurrentThread()).expect("ImpersonateAnonymousToken");
        // open_as_self: the open is checked against the process
        // token, not the anonymous one the thread now carries (which
        // would be refused).
        let opened = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &mut tok);
        RevertToSelf().expect("RevertToSelf");
        opened.expect("OpenThreadToken(anonymous)");
    }
    tok
}

/// The calling process's own token with its integrity level lowered
/// to low. Unlike an AppContainer token it carries no package SID.
fn low_integrity_token() -> HANDLE {
    let tok = own_token();
    let low = LocalPsid::from_string(LOW_INTEGRITY_SID).expect("low integrity SID");
    let label = TOKEN_MANDATORY_LABEL {
        Label: SID_AND_ATTRIBUTES {
            Sid: low.as_psid(),
            Attributes: SE_GROUP_INTEGRITY,
        },
    };
    unsafe {
        SetTokenInformation(
            tok,
            TokenIntegrityLevel,
            &label as *const TOKEN_MANDATORY_LABEL as *const c_void,
            size_of::<TOKEN_MANDATORY_LABEL>() as u32 + GetLengthSid(low.as_psid()),
        )
        .expect("SetTokenInformation(TokenIntegrityLevel)");
    }
    tok
}

/// An AppContainer (lowbox) token derived from the calling process's
/// token, with no capabilities.
fn appcontainer_token() -> HANDLE {
    let package = LocalPsid::from_string(PACKAGE_SID).expect("package SID");
    let attrs = ObjectAttributes {
        length: size_of::<ObjectAttributes>() as u32,
        root_directory: HANDLE::default(),
        object_name: std::ptr::null(),
        attributes: 0,
        security_descriptor: std::ptr::null(),
        security_quality_of_service: std::ptr::null(),
    };
    let primary = own_primary_token();
    let mut lowbox = HANDLE::default();
    unsafe {
        let status = NtCreateLowBoxToken(
            &mut lowbox,
            primary,
            TOKEN_ALL_ACCESS.0,
            &attrs,
            package.as_psid(),
            0,
            std::ptr::null(),
            0,
            std::ptr::null(),
        );
        assert!(status >= 0, "NtCreateLowBoxToken: {status:#010x}");
        let _ = CloseHandle(primary);
    }
    into_impersonation(lowbox)
}

/// A restricted copy of the calling process's token whose user SID
/// is deny-only.
fn deny_only_user_token(me: &str) -> HANDLE {
    let user = LocalPsid::from_string(me).expect("own SID");
    let disable = [SID_AND_ATTRIBUTES {
        Sid: user.as_psid(),
        Attributes: 0,
    }];
    let primary = own_primary_token();
    let mut restricted = HANDLE::default();
    unsafe {
        CreateRestrictedToken(
            primary,
            CREATE_RESTRICTED_TOKEN_FLAGS(0),
            Some(&disable),
            None,
            None,
            &mut restricted,
        )
        .expect("CreateRestrictedToken");
        let _ = CloseHandle(primary);
    }
    into_impersonation(restricted)
}

/// One `u32`-sized token property, or the error reading it.
fn token_u32(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> Result<u32, String> {
    let mut value = 0u32;
    let mut len = 0u32;
    unsafe {
        GetTokenInformation(
            token,
            class,
            Some(&mut value as *mut u32 as *mut c_void),
            size_of::<u32>() as u32,
            &mut len,
        )
    }
    .map(|()| value)
    .map_err(|e| format!("<{e}>"))
}

/// The token's integrity level as a string SID, or the error reading
/// it.
fn token_integrity(token: HANDLE) -> Result<String, String> {
    // u64 elements: the buffer starts with a struct holding a pointer.
    let mut buf = [0u64; 16];
    let mut len = 0u32;
    unsafe {
        GetTokenInformation(
            token,
            TokenIntegrityLevel,
            Some(buf.as_mut_ptr() as *mut c_void),
            size_of_val(&buf) as u32,
            &mut len,
        )
        .map_err(|e| format!("<{e}>"))?;
        let label = &*(buf.as_ptr() as *const TOKEN_MANDATORY_LABEL);
        psid_to_string(label.Label.Sid).map_err(|e| format!("<{e:#}>"))
    }
}

/// The token properties an access check depends on besides its SIDs:
/// type (1 primary, 2 impersonation), impersonation level and
/// integrity level. A property that cannot be read is shown as its
/// error.
fn describe(token: HANDLE) -> String {
    let show = |r: Result<String, String>| r.unwrap_or_else(|e| e);
    let level = token_u32(token, TokenImpersonationLevel).map(|l| {
        match l {
            0 => "anonymous",
            1 => "identification",
            2 => "impersonation",
            3 => "delegation",
            _ => "unknown",
        }
        .to_string()
    });
    format!(
        "type={} level={} integrity={}",
        show(token_u32(token, TokenType).map(|t| t.to_string())),
        show(level),
        show(token_integrity(token)),
    )
}

/// What one `AccessCheck` call answered.
struct Verdict {
    granted: bool,
    mask: u32,
    /// The Win32 status the call left behind: the reason, when it
    /// did not grant.
    status: u32,
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.granted {
            write!(f, "GRANTED mask={:#x}", self.mask)
        } else {
            write!(f, "DENIED mask={:#x} win32={}", self.mask, self.status)
        }
    }
}

/// `AccessCheck(token, SD-from-sddl, DESIRED_ACCESS)` under `mapping`.
///
/// "Did not grant" and "the call failed" are different answers. The
/// first is returned. The second — a token that is not an
/// impersonation token or is below identification level, a
/// descriptor with no owner or group — panics with the Win32 error.
fn access_check(row: &str, token: HANDLE, sddl: &str, mapping: &GENERIC_MAPPING) -> Verdict {
    let w = wstr(sddl);
    let mut psd = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            windows::core::PCWSTR(w.as_ptr()),
            1, // SDDL_REVISION_1
            &mut psd,
            None,
        )
        .unwrap_or_else(|e| panic!("[{row}] SDDL {sddl} does not convert: {e}"));
    }
    let mut priv_set = PRIVILEGE_SET::default();
    let mut priv_set_len = size_of::<PRIVILEGE_SET>() as u32;
    let mut mask: u32 = 0;
    let mut granted = BOOL(0);
    let (r, status) = unsafe {
        let r = AccessCheck(
            psd,
            token,
            DESIRED_ACCESS,
            mapping,
            Some(&mut priv_set),
            &mut priv_set_len,
            &mut mask,
            &mut granted,
        );
        // Read before anything else can overwrite it.
        let status = GetLastError().0;
        let _ = LocalFree(Some(HLOCAL(psd.0)));
        (r, status)
    };
    if let Err(e) = r {
        panic!(
            "[{row}] AccessCheck itself failed — an API error, not a denial: {e} \
             (win32={status}); token {{{}}}, sd {sddl}",
            describe(token)
        );
    }
    Verdict {
        granted: granted.as_bool(),
        mask,
        status,
    }
}

/// Whether `token` matches the descriptor `sddl` under [`STRICT`].
/// Logs the pair, with the answer under [`LENIENT`] beside it.
fn check(row: &str, token: HANDLE, sddl: &str) -> bool {
    let strict = access_check(row, token, sddl, &STRICT);
    let lenient = access_check(row, token, sddl, &LENIENT);
    // Straight to the stream: the test harness captures the print
    // macros and drops what a passing test printed.
    let _ = std::io::stderr().write_all(
        format!(
            "sd_access_check_matrix: [{row}] token {{{}}} sd {sddl}: {strict}; \
             lenient mapping: {lenient}\n",
            describe(token)
        )
        .as_bytes(),
    );
    strict.granted
}

fn close(token: HANDLE) {
    unsafe {
        let _ = CloseHandle(token);
    }
}

#[test]
fn plain_tokens() {
    let tok = own_token();
    let me = srt_win::sid::current_user_sid().unwrap();

    // SD keyed on THIS token's user SID → GRANT (i.e. block-user
    // would fire — the sandbox user is fenced).
    assert!(
        check("plain / sandbox-user SD", tok, &sddl_sandbox_user(&me)),
        "sandbox-user SD keyed on own user SID must match own token"
    );
    // SD keyed on a SID this token does NOT carry → DENY (i.e. the
    // BLOCK does NOT match the broker / services / any other user →
    // falls through to default-permit). The package ACEs on the SD
    // must not change that: a token outside an AppContainer carries
    // neither package SID.
    assert!(
        !check(
            "plain / sandbox-user SD of another user",
            tok,
            &sddl_sandbox_user(FOREIGN_SID)
        ),
        "sandbox-user SD keyed on a foreign SID must NOT match own token"
    );
    close(tok);
}

#[test]
fn anonymous_token_is_not_matched() {
    let tok = anonymous_token();
    let me = srt_win::sid::current_user_sid().unwrap();

    // The gap, pinned: the sandbox-user SD does not reach a thread of
    // the sandbox account once it impersonates anonymous.
    assert!(
        !check("anonymous / sandbox-user SD", tok, &sddl_sandbox_user(&me)),
        "sandbox-user SD does not match the anonymous token"
    );
    close(tok);
}

#[test]
fn appcontainer_token_of_the_sandbox_account_matches() {
    let tok = appcontainer_token();
    let me = srt_win::sid::current_user_sid().unwrap();

    assert!(
        check(
            "AppContainer / sandbox-user SD",
            tok,
            &sddl_sandbox_user(&me)
        ),
        "sandbox-user SD must match an AppContainer token of that user"
    );
    // Why the package ACEs exist: the user ACE alone satisfies only
    // the user half of an AppContainer token's access check.
    assert!(
        !check(
            "AppContainer / user-only SD",
            tok,
            &format!("O:LSG:LSD:(A;;CC;;;{me})")
        ),
        "a user-only SD must NOT match an AppContainer token"
    );
    // The package ACEs grant nothing by themselves: an AppContainer
    // token of another user still fails the user half.
    assert!(
        !check(
            "AppContainer / sandbox-user SD of another user",
            tok,
            &sddl_sandbox_user(FOREIGN_SID)
        ),
        "sandbox-user SD keyed on a foreign SID must NOT match an AppContainer token"
    );
    close(tok);
}

#[test]
fn deny_only_user_sid_is_not_matched() {
    let me = srt_win::sid::current_user_sid().unwrap();
    let tok = deny_only_user_token(&me);

    // The gap, pinned: a deny-only SID satisfies no ALLOW ACE, and
    // the token carries neither package SID.
    assert!(
        !check("deny-only / sandbox-user SD", tok, &sddl_sandbox_user(&me)),
        "an ALLOW ACE does not match a deny-only user SID"
    );
    close(tok);
}

#[test]
fn lowered_integrity_token_of_the_sandbox_account() {
    let tok = low_integrity_token();
    let me = srt_win::sid::current_user_sid().unwrap();

    // Logged, not asserted. The sandbox-user SD has no label, so for
    // a token below medium integrity the answer is the mandatory
    // check's and turns on the generic mapping: this row shows it
    // under both. Whether the sandbox-user BLOCK reaches such a token
    // is therefore the filtering engine's mapping to decide, which
    // this test cannot observe.
    let _ = check(
        "low integrity / sandbox-user SD",
        tok,
        &sddl_sandbox_user(&me),
    );

    // This holds under any mapping: the DACL does not name this
    // token.
    assert!(
        !check(
            "low integrity / sandbox-user SD of another user",
            tok,
            &sddl_sandbox_user(FOREIGN_SID)
        ),
        "sandbox-user SD keyed on a foreign SID must NOT match a low-integrity token"
    );
    close(tok);
}
