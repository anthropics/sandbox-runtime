//! What the ACEs of a persistent write root grant to which token —
//! `AccessCheck` run directly on a security descriptor built from
//! [`srt_win::acl::persistent_aces`], against tokens built by
//! [`srt_win::token::make_sandbox_token`]. No file, no sandbox
//! account: the test's own user stands in for the sandbox user (it
//! owns the descriptor, as the sandbox user owns the files it
//! creates), and `Authenticated Users`, which its token carries and
//! which is not a restricting SID, stands in for the sandbox group.
//!
//! Pinned here:
//!   - a write-restricted token WITH the root's capability SID
//!     writes; one with another root's capability SID does not, and
//!     still reads;
//!   - neither can change the DACL of an object the sandbox user
//!     owns, and the `OWNER RIGHTS` ACE is what stops it;
//!   - a group deny holds against the token that has the capability
//!     SID;
//!   - the real user keeps `WRITE_DAC` on what they own, through
//!     their own ACE.

#![cfg(windows)]

use std::mem::size_of;
use windows::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows::Win32::Security::{
    AccessCheck, DuplicateTokenEx, GENERIC_MAPPING, PRIVILEGE_SET, PSECURITY_DESCRIPTOR,
    SecurityImpersonation, TOKEN_ALL_ACCESS, TokenImpersonation,
};
use windows::Win32::Storage::FileSystem::{
    FILE_ALL_ACCESS, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
};
use windows::core::BOOL;

use srt_win::acl::{AceView, DenyMask, PersistentWant, persistent_aces};
use srt_win::persist::new_capability_sid;
use srt_win::token::{make_sandbox_token, open_self_token};
use srt_win::util::wstr;

const FILE_READ_DATA: u32 = 0x1;
const FILE_WRITE_DATA: u32 = 0x2;
const WRITE_DAC: u32 = 0x0004_0000;

/// In every token of an authenticated logon; not a restricting SID.
const AUTHENTICATED_USERS: &str = "S-1-5-11";
/// A well-formed account SID no token here carries.
const SOMEONE_ELSE: &str = "S-1-5-21-1-2-3-1000";

/// An impersonation token (which `AccessCheck` requires) of the
/// sandbox child token built from this process's own: the default
/// one, or write-restricted with `caps`.
fn child_token(write_restricted: bool, caps: &[String]) -> HANDLE {
    let base = open_self_token().expect("open_self_token");
    let tok = make_sandbox_token(base, write_restricted, caps).expect("make_sandbox_token");
    let mut imp = HANDLE::default();
    unsafe {
        DuplicateTokenEx(
            tok,
            TOKEN_ALL_ACCESS,
            None,
            SecurityImpersonation,
            TokenImpersonation,
            &mut imp,
        )
        .expect("DuplicateTokenEx");
        let _ = CloseHandle(tok);
        let _ = CloseHandle(base);
    }
    imp
}

/// Whether `token` is granted `access` to an object owned by `owner`
/// whose DACL is exactly `aces`, under the file generic mapping (it
/// is what tells a write-restricted token's check which rights are
/// write rights).
fn granted(token: HANDLE, owner: &str, aces: &[AceView], access: u32) -> bool {
    let dacl: String = aces.iter().map(AceView::sddl).collect();
    let sddl = format!("O:{owner}G:{owner}D:{dacl}");
    let w = wstr(&sddl);
    let mut psd = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            windows::core::PCWSTR(w.as_ptr()),
            1, // SDDL_REVISION_1
            &mut psd,
            None,
        )
        .unwrap_or_else(|e| panic!("SD from '{sddl}': {e}"));
    }
    let mapping = GENERIC_MAPPING {
        GenericRead: FILE_GENERIC_READ.0,
        GenericWrite: FILE_GENERIC_WRITE.0,
        GenericExecute: FILE_GENERIC_EXECUTE.0,
        GenericAll: FILE_ALL_ACCESS.0,
    };
    let mut priv_set = PRIVILEGE_SET::default();
    let mut priv_set_len = size_of::<PRIVILEGE_SET>() as u32;
    let mut got: u32 = 0;
    let mut status = BOOL(0);
    let r = unsafe {
        AccessCheck(
            psd,
            token,
            access,
            &mapping,
            Some(&mut priv_set),
            &mut priv_set_len,
            &mut got,
            &mut status,
        )
    };
    unsafe {
        let _ = LocalFree(Some(HLOCAL(psd.0)));
    }
    r.unwrap_or_else(|e| panic!("AccessCheck('{sddl}', {access:#x}): {e}"));
    status.as_bool()
}

#[test]
fn persistent_root_access_matrix() {
    let me = srt_win::sid::current_user_sid().unwrap();
    let cap_a = new_capability_sid().unwrap();
    let cap_b = new_capability_sid().unwrap();
    let root_b = PersistentWant {
        group_sid: AUTHENTICATED_USERS,
        real_user_sid: SOMEONE_ELSE,
        capability_sid: Some(&cap_b),
        deny: None,
        deny_fdc: false,
        deny_delete: false,
    };
    // A file in root B that the sandbox user created: it owns it, and
    // the DACL is what B's ACEs put there.
    let in_b = persistent_aces(&root_b);

    let session_a = child_token(true, std::slice::from_ref(&cap_a));
    let session_b = child_token(true, std::slice::from_ref(&cap_b));
    let no_roots = child_token(true, &[]);
    let ordinary = child_token(false, &[]);

    // The session that was given B writes there.
    assert!(granted(session_b, &me, &in_b, FILE_WRITE_DATA));
    assert!(granted(session_b, &me, &in_b, FILE_READ_DATA));
    // A session given only A, or no root, does not — although the
    // group ACE is there and the file's owner is a restricting SID
    // of its token. It still reads.
    for (name, tok) in [("session A", session_a), ("no roots", no_roots)] {
        assert!(!granted(tok, &me, &in_b, FILE_WRITE_DATA), "{name} wrote");
        assert!(granted(tok, &me, &in_b, FILE_READ_DATA), "{name} read");
    }
    // The owner cannot rewrite the DACL, under any token shape.
    for (name, tok) in [
        ("session A", session_a),
        ("session B", session_b),
        ("no roots", no_roots),
        ("ordinary", ordinary),
    ] {
        assert!(!granted(tok, &me, &in_b, WRITE_DAC), "{name} got WRITE_DAC");
    }
    // ... and OWNER RIGHTS is the ACE that stops it: without it the
    // owner's implicit WRITE_DAC is back.
    let no_owner_rights: Vec<AceView> = in_b
        .iter()
        .filter(|a| a.sid != srt_win::acl::SID_OWNER_RIGHTS)
        .cloned()
        .collect();
    assert_eq!(no_owner_rights.len(), in_b.len() - 1);
    assert!(granted(ordinary, &me, &no_owner_rights, WRITE_DAC));

    // A deny kept with the root holds against the session that has
    // the capability SID, on an object the sandbox user owns.
    let denied = persistent_aces(&PersistentWant {
        deny: Some(DenyMask::WriteDeny),
        ..root_b
    });
    assert!(!granted(session_b, &me, &denied, FILE_WRITE_DATA));
    assert!(granted(session_b, &me, &denied, FILE_READ_DATA));
    assert!(!granted(session_b, &me, &denied, WRITE_DAC));

    // The ordinary token writes B through the group ACE alone — why
    // nothing may run under it while a persistent grant exists.
    assert!(granted(ordinary, &me, &in_b, FILE_WRITE_DATA));

    // The real user, on a file they own: the test's user is now the
    // real user, and no ACE names a group of theirs. WRITE_DAC comes
    // from their own ACE; with that ACE naming someone else, OWNER
    // RIGHTS has taken it away.
    const NO_GROUP_OF_OURS: &str = "S-1-5-32-9999";
    let as_real_user = PersistentWant {
        group_sid: NO_GROUP_OF_OURS,
        real_user_sid: &me,
        ..root_b
    };
    assert!(granted(
        ordinary,
        &me,
        &persistent_aces(&as_real_user),
        WRITE_DAC
    ));
    let not_named = PersistentWant {
        group_sid: NO_GROUP_OF_OURS,
        ..root_b
    };
    assert!(!granted(
        ordinary,
        &me,
        &persistent_aces(&not_named),
        WRITE_DAC
    ));

    unsafe {
        for t in [session_a, session_b, no_roots, ordinary] {
            let _ = CloseHandle(t);
        }
    }
}
