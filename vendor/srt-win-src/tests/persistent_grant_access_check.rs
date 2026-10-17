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

use srt_win::acl::{AceView, DenyMask, PersistentWant, ProfileAce, persistent_aces};
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
        profile: None,
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

/// What the profile read grant's entries give a sandboxed process, on
/// objects the real user owns: read and execute, listing for a
/// container, and no way to write, create, delete, rename or re-ACL
/// under either token shape. And how a session's read deny meets
/// them: one written beneath a granted directory wins by itself, one
/// that is only inherited from above the granted directory loses to
/// the directory's own allow — which is why a session stamps its
/// deny on the granted directory itself.
#[test]
fn profile_grant_access_matrix() {
    const FILE_APPEND_DATA: u32 = 0x4;
    const FILE_EXECUTE: u32 = 0x20;
    const FILE_DELETE_CHILD: u32 = 0x40;
    const FILE_READ_ATTRIBUTES: u32 = 0x80;
    const FILE_WRITE_ATTRIBUTES: u32 = 0x100;
    const DELETE: u32 = 0x0001_0000;
    const WRITE_OWNER: u32 = 0x0008_0000;
    let me = srt_win::sid::current_user_sid().unwrap();
    let list = |profile: Option<ProfileAce>, deny: Option<DenyMask>| {
        persistent_aces(&PersistentWant {
            group_sid: AUTHENTICATED_USERS,
            real_user_sid: SOMEONE_ELSE,
            capability_sid: None,
            deny,
            deny_fdc: false,
            deny_delete: false,
            profile,
        })
    };
    let granted_dir = list(Some(ProfileAce::Granted), None);
    let container = list(Some(ProfileAce::Container), None);
    let file = list(Some(ProfileAce::File), None);
    let excluded = list(None, Some(DenyMask::ReadDeny));

    let restricted = child_token(true, &[]);
    let with_a_root = child_token(true, &[new_capability_sid().unwrap()]);
    let ordinary = child_token(false, &[]);
    let every_write = [
        ("write data / add file", FILE_WRITE_DATA),
        ("append / add directory", FILE_APPEND_DATA),
        ("delete child", FILE_DELETE_CHILD),
        ("write attributes", FILE_WRITE_ATTRIBUTES),
        ("delete (and so rename)", DELETE),
        ("change permissions", WRITE_DAC),
        ("take ownership", WRITE_OWNER),
        ("generic write", FILE_GENERIC_WRITE.0),
    ];
    for (name, tok) in [
        ("write-restricted", restricted),
        ("write-restricted with a root", with_a_root),
        ("ordinary", ordinary),
    ] {
        // The real user owns everything in their profile.
        let can = |aces: &[AceView], access: u32| granted(tok, SOMEONE_ELSE, aces, access);
        // A granted directory (and what inherits from it), and a
        // granted file: read and execute.
        for (what, aces) in [("granted directory", &granted_dir), ("granted file", &file)] {
            assert!(can(aces, FILE_GENERIC_READ.0), "{name}: read {what}");
            assert!(can(aces, FILE_EXECUTE), "{name}: execute {what}");
            for (right, access) in every_write {
                assert!(!can(aces, access), "{name}: {right} on a {what}");
            }
        }
        // A container: list it and pass through it; no file data
        // rights beyond that, and no write.
        assert!(can(&container, FILE_READ_DATA), "{name}: list a container");
        assert!(
            can(&container, FILE_EXECUTE),
            "{name}: traverse a container"
        );
        assert!(can(&container, FILE_READ_ATTRIBUTES));
        assert!(!can(&container, FILE_GENERIC_READ.0));
        for (right, access) in every_write {
            assert!(!can(&container, access), "{name}: {right} on a container");
        }
        // An excluded path: nothing, also with an allow behind the
        // deny (as an entry inherited from somewhere would be).
        let mut excluded_with_allow = excluded.clone();
        excluded_with_allow.extend(granted_dir.iter().cloned());
        for aces in [&excluded, &excluded_with_allow] {
            assert!(!can(aces, FILE_READ_DATA), "{name}: read an excluded path");
            assert!(!can(aces, FILE_EXECUTE));
            assert!(!can(aces, FILE_READ_ATTRIBUTES));
        }
        // An ungranted file in a container carries nothing for the
        // group.
        assert!(!can(&[], FILE_READ_DATA), "{name}: read with no entry");

        // A session's read deny names the sandbox user (here: the
        // test's own user). On an object beneath a granted directory
        // the deny is inherited from nearer than the allow, or is
        // explicit: it comes first and wins.
        let session_deny = AceView {
            deny: true,
            inherited: false,
            flags: 0x3,
            mask: FILE_ALL_ACCESS.0,
            sid: me.clone(),
        };
        let mut beneath = vec![session_deny.clone()];
        beneath.extend(granted_dir.iter().cloned());
        assert!(
            !can(&beneath, FILE_READ_DATA),
            "{name}: a deny beneath a granted directory lost"
        );
        // On the granted directory itself, a deny that only arrives
        // by inheritance from above sits behind the directory's own
        // allow, and loses.
        let mut inherited_from_above = granted_dir.clone();
        inherited_from_above.push(session_deny);
        assert!(
            can(&inherited_from_above, FILE_READ_DATA),
            "{name}: the order of an explicit allow and an inherited deny changed"
        );
    }
}
