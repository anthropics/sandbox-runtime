//! Parent deletion protection must not spread over unrelated sibling trees.
//! All ACL changes are confined to a fresh owned fixture. No sandbox account,
//! elevation, WFP installation or machine-wide state is needed.
#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use srt_win::acl::{
    DenyMask, GrantMask, Mask, SbAceSet, apply_sandbox_aces, set_path_dacl_from_sddl,
};
use srt_win::sid::LocalPsid;
use srt_win::util::{OwnedSd, from_pwstr, local_free, pcwstr, wstr};
use windows::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
};
use windows::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, GetAce, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR,
};

const TEST_SID: &str = "S-1-5-32-546"; // Guests, never the runner's own identity.

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "srt-acl-parent-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::create_dir(&path).unwrap();
        Self(std::fs::canonicalize(path).unwrap())
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // Only the directory created by this fixture, never a caller-supplied
        // path; do not follow a replacement root reparse point on cleanup.
        if std::fs::canonicalize(&self.0).ok().as_ref() == Some(&self.0) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }
}

fn sandbox_aces(path: &Path) -> Vec<(u8, u8, u32)> {
    let name = wstr(path.to_str().unwrap());
    let sid = LocalPsid::from_string(TEST_SID).unwrap();
    let mut sd = PSECURITY_DESCRIPTOR::default();
    let mut acl: *mut ACL = std::ptr::null_mut();
    unsafe {
        GetNamedSecurityInfoW(
            pcwstr(&name),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut acl),
            None,
            &mut sd,
        )
        .ok()
        .unwrap();
    }
    let _sd = OwnedSd::from_raw(sd);
    let mut result = Vec::new();
    if !acl.is_null() {
        for i in 0..unsafe { (*acl).AceCount } {
            let mut ace = std::ptr::null_mut();
            unsafe { GetAce(acl, u32::from(i), &mut ace) }.unwrap();
            let header = unsafe { &*(ace as *const windows::Win32::Security::ACE_HEADER) };
            let bytes =
                unsafe { std::slice::from_raw_parts(ace as *const u8, header.AceSize as usize) };
            if bytes.get(8..8 + sid.as_bytes().len()) == Some(sid.as_bytes()) {
                result.push((
                    header.AceType,
                    header.AceFlags,
                    u32::from_le_bytes(bytes[4..8].try_into().unwrap()),
                ));
            }
        }
    }
    result
}

fn snapshot(path: &Path) -> String {
    let name = wstr(path.to_str().unwrap());
    let flags = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    let mut raw = PSECURITY_DESCRIPTOR::default();
    unsafe {
        GetNamedSecurityInfoW(
            pcwstr(&name),
            SE_FILE_OBJECT,
            flags,
            None,
            None,
            None,
            None,
            &mut raw,
        )
    }
    .ok()
    .unwrap();
    let _owned = OwnedSd::from_raw(raw);
    let mut text = windows::core::PWSTR::null();
    unsafe { ConvertSecurityDescriptorToStringSecurityDescriptorW(raw, 1, flags, &mut text, None) }
        .unwrap();
    let result = from_pwstr(text);
    local_free(text.0.cast());
    result
}

fn set_fixture_dacl(path: &Path, extra: &str) {
    let owner = srt_win::sid::current_user_sid().unwrap();
    set_path_dacl_from_sddl(
        path.to_str().unwrap(),
        &format!("D:P{extra}(A;OICI;FA;;;{owner})(A;OICI;FA;;;SY)"),
        "fixture setup",
    )
    .unwrap();
}

#[test]
fn parent_fdc_is_object_only_and_round_trips() {
    let fixture = Fixture::new();
    let sibling = fixture.0.join("unrelated");
    std::fs::create_dir(&sibling).unwrap();
    let existing = sibling.join("existing.txt");
    std::fs::write(&existing, "keep").unwrap();
    let before = sandbox_aces(&sibling);
    let original = snapshot(&fixture.0);
    let sibling_original = snapshot(&sibling);
    apply_sandbox_aces(
        fixture.0.to_str().unwrap(),
        TEST_SID,
        SbAceSet {
            deny_fdc: true,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(
        sandbox_aces(&fixture.0),
        vec![(1, 0, Mask::FILE_DELETE_CHILD.bits())]
    );
    assert_eq!(
        sandbox_aces(&sibling),
        before,
        "parent-only deny leaked to sibling"
    );
    assert!(sandbox_aces(&existing).is_empty());
    let future = sibling.join("future.txt");
    std::fs::write(&future, "keep").unwrap();
    assert!(sandbox_aces(&future).is_empty());
    apply_sandbox_aces(fixture.0.to_str().unwrap(), TEST_SID, SbAceSet::default()).unwrap();
    assert!(sandbox_aces(&fixture.0).is_empty());
    assert_eq!(sandbox_aces(&sibling), before);
    assert_eq!(
        snapshot(&fixture.0),
        original,
        "parent descriptor did not round-trip"
    );
    assert_eq!(
        snapshot(&sibling),
        sibling_original,
        "unrelated descriptor changed"
    );
}

#[test]
fn denied_tree_keeps_descendant_delete_child_protection() {
    let fixture = Fixture::new();
    let denied = fixture.0.join("denied");
    let nested = denied.join("nested");
    std::fs::create_dir_all(&nested).unwrap();
    for mask in [DenyMask::WriteDeny, DenyMask::ReadDeny] {
        apply_sandbox_aces(
            denied.to_str().unwrap(),
            TEST_SID,
            SbAceSet {
                deny: Some(mask),
                ..Default::default()
            },
        )
        .unwrap();
        for path in [&denied, &nested] {
            assert!(sandbox_aces(path).iter().any(|&(kind, _, bits)|
                kind == 1 && bits & Mask::FILE_DELETE_CHILD.bits() != 0),
                "denied tree lost FILE_DELETE_CHILD protection: {mask:?}");
        }
        apply_sandbox_aces(denied.to_str().unwrap(), TEST_SID, SbAceSet::default()).unwrap();
        assert!(sandbox_aces(&nested).is_empty());
    }
}

#[test]
fn object_aces_preserve_protection_and_other_principals() {
    let fixture = Fixture::new();
    set_fixture_dacl(&fixture.0, "(D;OICI;0x2;;;AN)(A;OICI;FR;;;BU)");
    let child = fixture.0.join("protected-child");
    std::fs::create_dir(&child).unwrap();
    set_fixture_dacl(&child, "(A;;FR;;;BU)");
    let original = snapshot(&fixture.0);
    let child_original = snapshot(&child);
    for set in [
        SbAceSet {
            deny_fdc: true,
            ..Default::default()
        },
        SbAceSet {
            deny_delete: true,
            ..Default::default()
        },
        SbAceSet {
            deny_fdc: true,
            deny_delete: true,
            ..Default::default()
        },
    ] {
        apply_sandbox_aces(fixture.0.to_str().unwrap(), TEST_SID, set).unwrap();
        assert!(snapshot(&fixture.0).contains("D:P"), "protection bit lost");
        apply_sandbox_aces(fixture.0.to_str().unwrap(), TEST_SID, SbAceSet::default()).unwrap();
        assert_eq!(snapshot(&fixture.0), original);
        assert_eq!(snapshot(&child), child_original);
    }
}

#[test]
fn legacy_parent_fdc_is_removed_from_existing_descendants() {
    for keep_parent in [false, true] {
        let fixture = Fixture::new();
        let child = fixture.0.join("child");
        std::fs::create_dir(&child).unwrap();
        set_fixture_dacl(&fixture.0, &format!("(D;OICI;0x40;;;{TEST_SID})"));
        assert!(
            !sandbox_aces(&child).is_empty(),
            "legacy setup did not propagate"
        );
        apply_sandbox_aces(
            fixture.0.to_str().unwrap(),
            TEST_SID,
            SbAceSet {
                deny_fdc: keep_parent,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(
            sandbox_aces(&child).is_empty(),
            "stale legacy inherited FDC survived"
        );
        assert_eq!(sandbox_aces(&fixture.0).len(), usize::from(keep_parent));
        apply_sandbox_aces(fixture.0.to_str().unwrap(), TEST_SID, SbAceSet::default()).unwrap();
    }
}

#[test]
fn grant_and_deny_removal_still_propagate_and_preserve_inherited_grants() {
    let fixture = Fixture::new();
    let parent = fixture.0.join("parent");
    let nested = parent.join("nested");
    std::fs::create_dir_all(&nested).unwrap();
    let grant = SbAceSet {
        grant: Some(GrantMask::Modify),
        ..Default::default()
    };
    apply_sandbox_aces(fixture.0.to_str().unwrap(), TEST_SID, grant).unwrap();
    let inherited = sandbox_aces(&parent);
    assert!(
        inherited
            .iter()
            .any(|&(kind, flags, _)| kind == 0 && flags & 0x10 != 0)
    );
    for set in [
        SbAceSet {
            deny_fdc: true,
            ..Default::default()
        },
        SbAceSet {
            deny: Some(DenyMask::WriteDeny),
            ..Default::default()
        },
    ] {
        apply_sandbox_aces(parent.to_str().unwrap(), TEST_SID, set).unwrap();
        apply_sandbox_aces(parent.to_str().unwrap(), TEST_SID, SbAceSet::default()).unwrap();
        assert_eq!(sandbox_aces(&parent), inherited, "inherited grant removed");
        assert!(!sandbox_aces(&nested).iter().any(|&(kind, _, _)| kind == 1));
    }
    apply_sandbox_aces(fixture.0.to_str().unwrap(), TEST_SID, SbAceSet::default()).unwrap();
    assert!(sandbox_aces(&parent).is_empty());
    assert!(
        sandbox_aces(&nested).is_empty(),
        "stale grant survived revoke"
    );
}

#[test]
fn object_ace_reapply_repairs_drift() {
    let fixture = Fixture::new();
    let set = SbAceSet {
        deny_fdc: true,
        ..Default::default()
    };
    apply_sandbox_aces(fixture.0.to_str().unwrap(), TEST_SID, set).unwrap();
    set_fixture_dacl(&fixture.0, ""); // Model a host-side ACL reset.
    assert!(sandbox_aces(&fixture.0).is_empty());
    apply_sandbox_aces(fixture.0.to_str().unwrap(), TEST_SID, set).unwrap();
    assert_eq!(
        sandbox_aces(&fixture.0),
        vec![(1, 0, Mask::FILE_DELETE_CHILD.bits())]
    );
    apply_sandbox_aces(fixture.0.to_str().unwrap(), TEST_SID, set).unwrap();
    assert_eq!(
        sandbox_aces(&fixture.0).len(),
        1,
        "reapply duplicated the ACE"
    );
}

#[test]
fn parent_fdc_keeps_inherited_denies_inherited_while_held() {
    let fixture = Fixture::new();
    let parent = fixture.0.join("parent");
    std::fs::create_dir(&parent).unwrap();
    apply_sandbox_aces(
        fixture.0.to_str().unwrap(),
        TEST_SID,
        SbAceSet {
            deny: Some(DenyMask::WriteDeny),
            ..Default::default()
        },
    )
    .unwrap();
    let inherited = sandbox_aces(&parent);
    assert!(inherited.iter().all(|&(_, flags, _)| flags & 0x10 != 0));
    for _ in 0..3 {
        apply_sandbox_aces(
            parent.to_str().unwrap(),
            TEST_SID,
            SbAceSet {
                deny_fdc: true,
                ..Default::default()
            },
        )
        .unwrap();
        let mut expected = vec![(1, 0, Mask::FILE_DELETE_CHILD.bits())];
        expected.extend_from_slice(&inherited);
        assert_eq!(
            sandbox_aces(&parent),
            expected,
            "inherited deny became explicit"
        );
    }
    apply_sandbox_aces(parent.to_str().unwrap(), TEST_SID, SbAceSet::default()).unwrap();
    assert_eq!(sandbox_aces(&parent), inherited);
    apply_sandbox_aces(fixture.0.to_str().unwrap(), TEST_SID, SbAceSet::default()).unwrap();
}

// Exercise real kernel opens/deletes/renames without provisioning another
// account: the normal token pass has the runner's access, the restricting-SID
// pass encounters TEST_SID denies and Everyone allows. This is an ACL test
// token, not a replacement for SRT's production sandbox-user token.
struct Impersonation;
impl Impersonation {
    fn begin() -> Self {
        use srt_win::util::OwnedHandle;
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::Security::{
            CreateRestrictedToken, DISABLE_MAX_PRIVILEGE, ImpersonateLoggedOnUser,
            SID_AND_ATTRIBUTES, TOKEN_DUPLICATE, TOKEN_QUERY,
        };
        use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
        let mut raw = HANDLE::default();
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &mut raw) }
            .unwrap();
        let original = OwnedHandle(raw);
        let sandbox = LocalPsid::from_string(TEST_SID).unwrap();
        let everyone = LocalPsid::from_string("S-1-1-0").unwrap();
        let restricting = [
            SID_AND_ATTRIBUTES {
                Sid: sandbox.as_psid(),
                Attributes: 0,
            },
            SID_AND_ATTRIBUTES {
                Sid: everyone.as_psid(),
                Attributes: 0,
            },
        ];
        let mut raw = HANDLE::default();
        unsafe {
            CreateRestrictedToken(
                original.raw(),
                DISABLE_MAX_PRIVILEGE,
                None,
                None,
                Some(&restricting),
                &mut raw,
            )
        }
        .unwrap();
        let restricted = OwnedHandle(raw);
        unsafe { ImpersonateLoggedOnUser(restricted.raw()) }.unwrap();
        Self
    }
}
impl Drop for Impersonation {
    fn drop(&mut self) {
        if unsafe { windows::Win32::Security::RevertToSelf() }.is_err() {
            std::process::abort();
        }
    }
}

#[test]
fn denied_targets_cannot_be_deleted_or_renamed_via_parent_fdc() {
    let fixture = Fixture::new();
    set_fixture_dacl(&fixture.0, "(A;OICI;FA;;;WD)");
    let allowed = fixture.0.join("allowed.txt");
    let denied = fixture.0.join("denied.txt");
    let denied_dir = fixture.0.join("denied-dir");
    let nested = denied_dir.join("nested.txt");
    let future = denied_dir.join("future.txt");
    std::fs::write(&allowed, "allowed").unwrap();
    std::fs::write(&denied, "denied").unwrap();
    std::fs::create_dir(&denied_dir).unwrap();
    std::fs::write(&nested, "nested").unwrap();
    {
        let _impersonation = Impersonation::begin();
        std::fs::rename(&allowed, fixture.0.join("renamed.txt")).unwrap();
        std::fs::rename(fixture.0.join("renamed.txt"), &allowed).unwrap();
        std::fs::write(&denied, "control").unwrap();
    }
    let deny = SbAceSet {
        deny: Some(DenyMask::WriteDeny),
        ..Default::default()
    };
    apply_sandbox_aces(denied.to_str().unwrap(), TEST_SID, deny).unwrap();
    apply_sandbox_aces(denied_dir.to_str().unwrap(), TEST_SID, deny).unwrap();
    std::fs::write(&future, "future").unwrap();
    apply_sandbox_aces(
        fixture.0.to_str().unwrap(),
        TEST_SID,
        SbAceSet {
            deny_fdc: true,
            ..Default::default()
        },
    )
    .unwrap();
    {
        let _impersonation = Impersonation::begin();
        assert_eq!(std::fs::read_to_string(&denied).unwrap(), "control");
        assert_eq!(
            std::fs::write(&denied, "forbidden").unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        for path in [&denied, &nested, &future] {
            assert_eq!(
                std::fs::remove_file(path).unwrap_err().kind(),
                std::io::ErrorKind::PermissionDenied,
                "delete must be denied by permissions"
            );
            assert_eq!(
                std::fs::rename(path, path.with_extension("moved"))
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::PermissionDenied,
                "rename must be denied by permissions"
            );
        }
        assert_eq!(
            std::fs::rename(&denied_dir, fixture.0.join("moved-dir"))
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::PermissionDenied
        );
        // Parent-only FDC must not stop a sibling's own DELETE right.
        std::fs::remove_file(&allowed).unwrap();
    }
    assert_eq!(std::fs::read_to_string(&denied).unwrap(), "control");
    assert_eq!(std::fs::read_to_string(&nested).unwrap(), "nested");
    assert_eq!(std::fs::read_to_string(&future).unwrap(), "future");
    for path in [&denied, &denied_dir, &fixture.0] {
        apply_sandbox_aces(path.to_str().unwrap(), TEST_SID, SbAceSet::default()).unwrap();
    }
    {
        let _impersonation = Impersonation::begin();
        std::fs::remove_file(&denied).unwrap();
        std::fs::remove_file(&nested).unwrap();
        std::fs::remove_file(&future).unwrap();
        std::fs::remove_dir(&denied_dir).unwrap();
    }
}

/// Explicit benchmark, not a timing-sensitive CI assertion. Run this same test
/// source against the base and patched revisions with `--ignored --nocapture`.
/// No profile-root ACL, sandbox account or installation is touched.
#[test]
#[ignore = "creates 11,000 synthetic files; run explicitly for performance evidence"]
fn benchmark_parent_acl_tree_size() {
    for count in [0, 1_000, 10_000] {
        let fixture = Fixture::new();
        let subtree = fixture.0.join("unrelated");
        std::fs::create_dir(&subtree).unwrap();
        let mut paths = vec![fixture.0.clone(), subtree.clone()];
        for index in 0..count {
            let path = subtree.join(format!("file-{index}.txt"));
            std::fs::write(&path, "sentinel").unwrap();
            paths.push(path);
        }
        let before: Vec<_> = paths.iter().map(|p| snapshot(p)).collect();
        let start = std::time::Instant::now();
        apply_sandbox_aces(
            fixture.0.to_str().unwrap(),
            TEST_SID,
            SbAceSet {
                deny_fdc: true,
                ..Default::default()
            },
        )
        .unwrap();
        let stamp = start.elapsed();
        let start = std::time::Instant::now();
        apply_sandbox_aces(fixture.0.to_str().unwrap(), TEST_SID, SbAceSet::default()).unwrap();
        let restore = start.elapsed();
        for (path, expected) in paths.iter().zip(&before) {
            assert_eq!(&snapshot(path), expected, "descriptor did not round-trip");
            if path.is_file() {
                assert_eq!(std::fs::read_to_string(path).unwrap(), "sentinel");
            }
        }
        eprintln!(
            "files={count} stamp_ms={:.3} restore_ms={:.3} descriptors_restored={}",
            stamp.as_secs_f64() * 1000.0,
            restore.as_secs_f64() * 1000.0,
            paths.len()
        );
    }
}
