//! Windows Filtering Platform (WFP) filter management for the
//! sandbox-runtime Windows network fence.
//!
//! ## Design
//!
//! At install time we provision the dedicated `srt-sandbox` local
//! user account ([`crate::user`]) and persist **one machine-wide**
//! filter set — two filters at each of `FWPM_LAYER_ALE_AUTH_CONNECT_V4`
//! and `_V6` (4 total), all under one persistent sublayer:
//!
//!   - **PERMIT loopback** (weight [`W_LOOPBACK`]) —
//!     `IP_REMOTE_ADDRESS` is `127.0.0.0/8` (v4) / `::1` (v6) **and**
//!     `IP_REMOTE_PORT` is in `[low, high]` (default 60080–60089). No
//!     user condition. The sandboxed child reaches the host proxies —
//!     which on Windows bind inside this range — but not arbitrary
//!     loopback listeners. (Linux/macOS restrict the child to exactly
//!     the two proxy ports; this range is the closest Windows
//!     analogue without per-`initialize()` admin.)
//!
//!   - **BLOCK sandbox user** (weight [`W_BLOCK`]) — `ALE_USER_ID` SD
//!     = [`sddl_sandbox_user`]. Matches only tokens whose user SID is
//!     `<srt-sandbox SID>`. Everyone else (the broker, services,
//!     SYSTEM, the real user) carries a different user SID → no match
//!     → falls through to default-permit.
//!
//! WFP's `ALE_USER_ID` condition with `FWP_MATCH_EQUAL` evaluates the
//! supplied security descriptor via `AccessCheck` against the
//! connecting token: the filter *matches* iff the check grants
//! access. Keying on the **user SID** means the surrogate-spawn
//! class (schtasks, `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`, BITS,
//! RunAs="Interactive User" COM) cannot defeat it: a process spawned
//! under `srt-sandbox` by ANY mechanism still has the user SID and
//! still matches the BLOCK.
//!
//! Filters carry a small JSON tag in `providerData` (`{tool, kind,
//! port_range?, user_sid}`) so install/uninstall/status can locate
//! them by enumeration. BFE enumeration is admin-gated (see
//! [`WfpAccessDenied`]) — `wfp status` returns `cannot-read` for a
//! non-elevated caller; the non-elevated readiness check is `srt-win
//! wfp verify` (a behavioral connect probe).

// The WFP structs are large and partially-initialised; the
// `..Default::default()` struct-update form clippy suggests is
// significantly less readable here than field-by-field assignment.
#![allow(clippy::field_reassign_with_default)]

use crate::util::wstr;
use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use std::ffi::c_void;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_ACTION_TYPE, FWP_BYTE_ARRAY16, FWP_BYTE_ARRAY16_TYPE,
    FWP_BYTE_BLOB, FWP_CONDITION_VALUE0, FWP_CONDITION_VALUE0_0, FWP_FILTER_ENUM_OVERLAPPING,
    FWP_MATCH_EQUAL, FWP_MATCH_RANGE, FWP_RANGE_TYPE, FWP_RANGE0, FWP_SECURITY_DESCRIPTOR_TYPE,
    FWP_UINT16, FWP_UINT64, FWP_V4_ADDR_AND_MASK, FWP_V4_ADDR_MASK, FWP_VALUE0, FWP_VALUE0_0,
    FWPM_ACTION0, FWPM_ACTION0_0, FWPM_CONDITION_ALE_USER_ID, FWPM_CONDITION_IP_REMOTE_ADDRESS,
    FWPM_CONDITION_IP_REMOTE_PORT, FWPM_DISPLAY_DATA0, FWPM_FILTER_CONDITION0,
    FWPM_FILTER_ENUM_TEMPLATE0, FWPM_FILTER_FLAG_PERSISTENT, FWPM_FILTER0,
    FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_SUBLAYER_FLAG_PERSISTENT,
    FWPM_SUBLAYER0, FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterCreateEnumHandle0,
    FwpmFilterDeleteByKey0, FwpmFilterDestroyEnumHandle0, FwpmFilterEnum0, FwpmFreeMemory0,
    FwpmSubLayerAdd0, FwpmSubLayerDeleteByKey0, FwpmTransactionAbort0, FwpmTransactionBegin0,
    FwpmTransactionCommit0,
};
use windows::core::{GUID, PCWSTR, PWSTR};

/// Default sublayer GUID. Stable so uninstall can find filters from a
/// previous install. Overridable via `--sublayer-guid` so an
/// enterprise that provisions WFP via its own tooling can point us at
/// theirs. {2c5d0ad6-5f3b-4d4e-9b8f-1a3e7c9d0b21}
pub const DEFAULT_SUBLAYER_GUID: GUID = GUID::from_u128(0x2c5d0ad6_5f3b_4d4e_9b8f_1a3e7c9d0b21);

/// Default loopback port range for the PERMIT filter. The JS mux
/// proxy (front-end + http backend) binds inside this range on
/// Windows so the sandboxed child can reach it. Ten ports leaves
/// headroom for both listeners and for `EADDRINUSE` retries.
/// Overridable via `--proxy-port-range`.
pub const DEFAULT_PROXY_PORT_RANGE: (u16, u16) = (60080, 60089);

/// Sanity cap on `--proxy-port-range` width (`high - low`). The
/// range exists to *narrow* loopback exposure relative to a
/// blanket all-of-127/8 PERMIT; an unbounded range would defeat
/// that.
pub const MAX_PROXY_PORT_RANGE_WIDTH: u16 = 64;

// WFP error codes we treat as benign idempotency outcomes.
const FWP_E_ALREADY_EXISTS: u32 = 0x80320009;
const FWP_E_FILTER_NOT_FOUND: u32 = 0x80320003;
const FWP_E_SUBLAYER_NOT_FOUND: u32 = 0x80320007;
const FWP_E_IN_USE: u32 = 0x8032000A;
// `FwpmEngineOpen0` / `FwpmFilterCreateEnumHandle0` are admin-gated
// by BFE; non-elevated callers get one of these.
const FWP_E_ACCESS_DENIED: u32 = 0x8032_0028;
const ERROR_ACCESS_DENIED: u32 = 5;

use crate::util::OwnedSd;

/// Typed marker for an admin-gated BFE call returning access-denied.
/// `FwpmFilterCreateEnumHandle0` (and on some configurations
/// `FwpmEngineOpen0`) require elevation; a non-elevated `wfp status`
/// hits this. [`filter_status`] downcasts and degrades to
/// `state:"cannot-read"`; the host's behavioral check is `wfp
/// verify`, not the enum.
#[derive(Debug)]
pub struct WfpAccessDenied {
    pub call: &'static str,
    pub rc: u32,
}
impl std::fmt::Display for WfpAccessDenied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: 0x{:08x} (BFE filter enumeration is admin-only)",
            self.call, self.rc
        )
    }
}
impl std::error::Error for WfpAccessDenied {}

fn is_bfe_access_denied(rc: u32) -> bool {
    rc == ERROR_ACCESS_DENIED || rc == FWP_E_ACCESS_DENIED
}

// ────────────────────── small RAII helpers ──────────────────────

/// Borrow an `OwnedSd` as the `FWP_BYTE_BLOB` shape WFP wants for
/// provider data. The caller must keep `sd` alive for the duration.
fn sd_byte_blob(sd: &OwnedSd) -> FWP_BYTE_BLOB {
    FWP_BYTE_BLOB {
        size: sd.len,
        data: sd.ptr.0 as *mut u8,
    }
}

/// WFP engine handle; closed on drop.
struct EngineHandle(HANDLE);

impl EngineHandle {
    fn open() -> Result<Self> {
        let mut h = HANDLE::default();
        // RPC_C_AUTHN_DEFAULT
        let rc = unsafe { FwpmEngineOpen0(PCWSTR::null(), 0xFFFF_FFFF, None, None, &mut h) };
        if rc != 0 {
            if is_bfe_access_denied(rc) {
                return Err(anyhow::Error::new(WfpAccessDenied {
                    call: "FwpmEngineOpen0",
                    rc,
                }));
            }
            return Err(anyhow!("FwpmEngineOpen0 failed: 0x{rc:08x}"));
        }
        Ok(Self(h))
    }
    fn h(&self) -> HANDLE {
        self.0
    }
}

impl Drop for EngineHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = FwpmEngineClose0(self.0);
            }
        }
    }
}

/// Open the engine, run `f` inside one WFP transaction
/// (`FwpmTransactionBegin0` … `Commit0`). Aborts the transaction if
/// `f` returns an error or panics, then closes the engine. Single
/// owner of the txn-envelope shape so the install/uninstall sites
/// can't drift.
fn with_wfp_txn<T>(f: impl FnOnce(&EngineHandle) -> Result<T>) -> Result<T> {
    let engine = EngineHandle::open()?;
    let rc = unsafe { FwpmTransactionBegin0(engine.h(), 0) };
    if rc != 0 {
        return Err(anyhow!("FwpmTransactionBegin0: 0x{rc:08x}"));
    }
    // Abort-on-unwind: if `f` panics, this guard's Drop aborts the
    // open txn before EngineHandle's Drop closes the session. On
    // the success path we `forget` it after Commit.
    struct AbortOnDrop(HANDLE);
    impl Drop for AbortOnDrop {
        fn drop(&mut self) {
            unsafe {
                let _ = FwpmTransactionAbort0(self.0);
            }
        }
    }
    let abort = AbortOnDrop(engine.h());
    let out = f(&engine)?;
    let rc = unsafe { FwpmTransactionCommit0(engine.h()) };
    if rc != 0 {
        // `abort` drops → Abort0 (no-op after a failed Commit, but
        // harmless).
        return Err(anyhow!("FwpmTransactionCommit0: 0x{rc:08x}"));
    }
    std::mem::forget(abort);
    Ok(out)
}

// ────────────────────── condition builders ──────────────────────

fn fwp_uint64(slot: &mut u64) -> FWP_VALUE0 {
    FWP_VALUE0 {
        r#type: FWP_UINT64,
        Anonymous: FWP_VALUE0_0 {
            uint64: slot as *mut u64,
        },
    }
}

fn cond_sd(field_key: GUID, blob: &mut FWP_BYTE_BLOB) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: field_key,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_SECURITY_DESCRIPTOR_TYPE,
            Anonymous: FWP_CONDITION_VALUE0_0 { sd: blob as *mut _ },
        },
    }
}

fn cond_v4_subnet(field_key: GUID, am: &mut FWP_V4_ADDR_AND_MASK) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: field_key,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_V4_ADDR_MASK,
            Anonymous: FWP_CONDITION_VALUE0_0 {
                v4AddrMask: am as *mut _,
            },
        },
    }
}

fn cond_v6_addr(field_key: GUID, addr: &mut FWP_BYTE_ARRAY16) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: field_key,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_BYTE_ARRAY16_TYPE,
            Anonymous: FWP_CONDITION_VALUE0_0 {
                byteArray16: addr as *mut _,
            },
        },
    }
}

fn fwp_uint16(v: u16) -> FWP_VALUE0 {
    FWP_VALUE0 {
        r#type: FWP_UINT16,
        Anonymous: FWP_VALUE0_0 { uint16: v },
    }
}

fn cond_port_range(field_key: GUID, range: &mut FWP_RANGE0) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: field_key,
        matchType: FWP_MATCH_RANGE,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_RANGE_TYPE,
            Anonymous: FWP_CONDITION_VALUE0_0 {
                rangeValue: range as *mut _,
            },
        },
    }
}

// ────────────────────── filter tagging ──────────────────────

/// JSON payload stored in each filter's `providerData` so we can
/// identify our own filters during enumerate/uninstall without fixed
/// filter GUIDs. The optional `port_range` mirrors the
/// `IP_REMOTE_PORT` range condition on `permit-loopback-user` so
/// `wfp status` can report it without unsafe condition-walking.
/// `user_sid` is always set on filters this version writes; legacy
/// installs (the discriminator-group filter set this version
/// supersedes) wrote it as `None`, and [`install_filters`]/
/// [`uninstall_filters`] clean those up too.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct FilterTag {
    /// Discriminator: `"srt-win"`. Anything else means the filter
    /// belongs to some other tool that happens to share our sublayer.
    pub tool: String,
    /// `permit-loopback-user` / `block-user`.
    pub kind: String,
    /// `[low, high]` for `permit-loopback-user`; `None` otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port_range: Option<[u16; 2]>,
    /// Sandbox user SID. `None` only on legacy installs that predate
    /// the user-SID-keyed design.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_sid: Option<String>,
}

impl FilterTag {
    fn user(kind: &str, sid: &str, range: Option<(u16, u16)>) -> Self {
        Self {
            tool: "srt-win".into(),
            kind: kind.into(),
            port_range: range.map(|(l, h)| [l, h]),
            user_sid: Some(sid.into()),
        }
    }
    fn to_blob_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("FilterTag is always serialisable")
    }
}

/// Number of filters in the user-SID-keyed set (2 per layer × v4/v6).
pub const FILTER_COUNT: usize = 4;

// Filter weights — kept below 2^60 so they stay in WFP's
// "manual weight" class (top 4 bits are auto-classifier). The
// loopback PERMIT must sit **above** the user-SID BLOCK so the
// sandbox user can still reach the host proxies. Module-level so
// [`install_filters`] and the const-asserts in `tests` share one
// source of truth.
pub(crate) const W_LOOPBACK: u64 = 0x0F80_0000_0000_0000;
pub(crate) const W_BLOCK: u64 = 0x0F40_0000_0000_0000;

// ────────────────────── filter enumeration ──────────────────────

const ALE_LAYERS: [(GUID, &str); 2] = [
    (FWPM_LAYER_ALE_AUTH_CONNECT_V4, "ale_auth_connect_v4"),
    (FWPM_LAYER_ALE_AUTH_CONNECT_V6, "ale_auth_connect_v6"),
];

/// Walk every filter at the two ALE connect layers under
/// `sublayer` that carries a parseable `srt-win` providerData tag,
/// invoking `f(layer_name, filterKey, &tag)` for each. Owns the
/// enum-handle and per-batch `FwpmFreeMemory0` lifecycle so callers
/// don't duplicate the unsafe FFI walk.
///
/// Errors are propagated (with the enum handle destroyed first) —
/// don't swallow them: inside `install_filters`' txn, a missed enum
/// error would skip stale-filter cleanup and the fresh set would be
/// added on top, growing the filter count every install.
fn for_each_tagged_filter(
    engine: &EngineHandle,
    sublayer: &GUID,
    mut f: impl FnMut(&'static str, GUID, &FilterTag),
) -> Result<()> {
    for (layer, layer_name) in ALE_LAYERS {
        let mut tmpl = FWPM_FILTER_ENUM_TEMPLATE0::default();
        tmpl.layerKey = layer;
        tmpl.enumType = FWP_FILTER_ENUM_OVERLAPPING;
        tmpl.actionMask = 0xFFFF_FFFF;
        let mut h = HANDLE::default();
        let rc = unsafe { FwpmFilterCreateEnumHandle0(engine.h(), Some(&tmpl), &mut h) };
        if rc != 0 {
            if is_bfe_access_denied(rc) {
                return Err(anyhow::Error::new(WfpAccessDenied {
                    call: "FwpmFilterCreateEnumHandle0",
                    rc,
                }));
            }
            return Err(anyhow!(
                "FwpmFilterCreateEnumHandle0({layer_name}): 0x{rc:08x}"
            ));
        }
        loop {
            let mut entries: *mut *mut FWPM_FILTER0 = std::ptr::null_mut();
            let mut n: u32 = 0;
            let rc = unsafe { FwpmFilterEnum0(engine.h(), h, 256, &mut entries, &mut n) };
            if rc != 0 {
                unsafe {
                    let _ = FwpmFilterDestroyEnumHandle0(engine.h(), h);
                }
                return Err(anyhow!("FwpmFilterEnum0({layer_name}): 0x{rc:08x}"));
            }
            if n == 0 {
                if !entries.is_null() {
                    unsafe {
                        FwpmFreeMemory0(&mut (entries as *mut c_void));
                    }
                }
                break;
            }
            let slice = unsafe { std::slice::from_raw_parts(entries, n as usize) };
            for &fp in slice {
                if fp.is_null() {
                    continue;
                }
                let flt = unsafe { &*fp };
                if &flt.subLayerKey != sublayer {
                    continue;
                }
                if flt.providerData.size == 0 || flt.providerData.data.is_null() {
                    continue;
                }
                let bytes = unsafe {
                    std::slice::from_raw_parts(
                        flt.providerData.data,
                        flt.providerData.size as usize,
                    )
                };
                if let Ok(tag) = serde_json::from_slice::<FilterTag>(bytes)
                    && tag.tool == "srt-win"
                {
                    // `tag` is owned (parsed from bytes); the
                    // `flt`/`bytes` borrows are released before
                    // FwpmFreeMemory0 below, so no FFI lifetime
                    // hazard for the closure.
                    f(layer_name, flt.filterKey, &tag);
                }
            }
            unsafe {
                FwpmFreeMemory0(&mut (entries as *mut c_void));
            }
            if (n as usize) < 256 {
                break;
            }
        }
        unsafe {
            let _ = FwpmFilterDestroyEnumHandle0(engine.h(), h);
        }
    }
    Ok(())
}

/// Delete every srt-win-tagged filter under `sublayer`. Returns the
/// number deleted. Does not delete the sublayer itself.
fn delete_tagged_filters(engine: &EngineHandle, sublayer: &GUID) -> Result<usize> {
    // Collect across both layers, then delete. Deletion is by global
    // filterKey GUID inside one txn, so per-layer ordering is not
    // load-bearing.
    let mut to_delete: Vec<GUID> = Vec::new();
    for_each_tagged_filter(engine, sublayer, |_, key, _| {
        to_delete.push(key);
    })?;
    let mut deleted = 0usize;
    for key in to_delete {
        let rc = unsafe { FwpmFilterDeleteByKey0(engine.h(), &key) };
        if rc == 0 {
            deleted += 1;
        } else if rc != FWP_E_FILTER_NOT_FOUND {
            return Err(anyhow!("FwpmFilterDeleteByKey0({key:?}): 0x{rc:08x}"));
        }
    }
    Ok(deleted)
}

// ────────────────────── install / uninstall ──────────────────────

#[allow(clippy::too_many_arguments)]
fn add_filter(
    engine: HANDLE,
    sublayer: &GUID,
    layer: GUID,
    name: &str,
    weight: u64,
    action: FWP_ACTION_TYPE,
    conditions: &mut [FWPM_FILTER_CONDITION0],
    tag_bytes: &mut [u8],
) -> Result<()> {
    let mut name_w = wstr(name);
    let mut desc_w = wstr("sandbox-runtime WFP filter");
    let mut weight_slot = weight;
    let mut filter = FWPM_FILTER0::default();
    // filterKey left zeroed → WFP assigns a fresh GUID. We identify
    // our filters via providerData, not by fixed key.
    filter.displayData = FWPM_DISPLAY_DATA0 {
        name: PWSTR(name_w.as_mut_ptr()),
        description: PWSTR(desc_w.as_mut_ptr()),
    };
    filter.flags = FWPM_FILTER_FLAG_PERSISTENT;
    filter.layerKey = layer;
    filter.subLayerKey = *sublayer;
    filter.weight = fwp_uint64(&mut weight_slot);
    filter.numFilterConditions = conditions.len() as u32;
    filter.filterCondition = if conditions.is_empty() {
        std::ptr::null_mut()
    } else {
        conditions.as_mut_ptr()
    };
    filter.action = FWPM_ACTION0 {
        r#type: action,
        Anonymous: FWPM_ACTION0_0 {
            filterType: GUID::zeroed(),
        },
    };
    filter.providerData = FWP_BYTE_BLOB {
        size: tag_bytes.len() as u32,
        data: tag_bytes.as_mut_ptr(),
    };
    let rc = unsafe { FwpmFilterAdd0(engine, &filter, None, None) };
    if rc != 0 && rc != FWP_E_ALREADY_EXISTS {
        return Err(anyhow!("FwpmFilterAdd0({name}): 0x{rc:08x}"));
    }
    Ok(())
}

// SDDL builder for the `ALE_USER_ID` security descriptor.
//
// Carries `O:LS G:LS` (owner + primary group = LocalService).
// WFP's kernel-side ALE_USER_ID match doesn't require the primary
// group to be set, but user-mode `AccessCheck` — which
// `tests/sd_access_check_matrix.rs` uses to prove this SD does
// what we claim — returns ERROR_INVALID_SECURITY_DESCR for an SD
// with no `G:`. The group's value is irrelevant to DACL
// evaluation; LS is just a stable, always-present principal.

/// SDDL for the BLOCK filter — ALLOW `<sandbox_user_sid>`. Matches
/// iff the connecting token carries that SID **enabled**, which for
/// a *user* SID means "is that user". The broker, services, and
/// every other process carry a different user SID → no match → fall
/// through to default-permit.
pub fn sddl_sandbox_user(sid: &str) -> String {
    format!("O:LSG:LSD:(A;;CC;;;{sid})")
}

/// Install (or refresh) the user-SID-keyed filter set under
/// `sublayer`. Two filters at each of the v4/v6 ALE-connect layers
/// ([`FILTER_COUNT`] total) — see the module doc for the design.
///
/// Idempotent: any existing srt-win-tagged filters under `sublayer`
/// — including legacy discriminator-group-keyed filters from a
/// pre-separate-user install — are deleted first, then a fresh set
/// is added, all inside one WFP transaction.
pub fn install_filters(
    sublayer: &GUID,
    sandbox_user_sid: &str,
    port_range: (u16, u16),
) -> Result<()> {
    debug_assert!(port_range.0 <= port_range.1);
    let sd_user = OwnedSd::from_sddl(&sddl_sandbox_user(sandbox_user_sid))
        .context("build sandbox-user SD")?;

    with_wfp_txn(|engine| {
        // Sublayer (idempotent). Display name identifies the owning
        // tool, not the user.
        let mut sl_name = wstr("srt-win");
        let mut sl_desc = wstr("sandbox-runtime WFP sublayer (sandbox-user fence)");
        let sl = FWPM_SUBLAYER0 {
            subLayerKey: *sublayer,
            displayData: FWPM_DISPLAY_DATA0 {
                name: PWSTR(sl_name.as_mut_ptr()),
                description: PWSTR(sl_desc.as_mut_ptr()),
            },
            flags: FWPM_SUBLAYER_FLAG_PERSISTENT,
            providerKey: std::ptr::null_mut(),
            providerData: FWP_BYTE_BLOB {
                size: 0,
                data: std::ptr::null_mut(),
            },
            weight: 0x8000,
        };
        let rc = unsafe { FwpmSubLayerAdd0(engine.h(), &sl, None) };
        if rc != 0 && rc != FWP_E_ALREADY_EXISTS {
            return Err(anyhow!("FwpmSubLayerAdd0: 0x{rc:08x}"));
        }

        // Idempotency + migration: drop EVERY stale srt-win filter
        // (both this version's user-keyed shape and any legacy
        // group-keyed filters from a prior install) before
        // re-adding. Inside the transaction so a crash leaves the
        // previous state intact.
        delete_tagged_filters(engine, sublayer)?;

        let mut sd_user_blob = sd_byte_blob(&sd_user);
        let mut v4_loop = FWP_V4_ADDR_AND_MASK {
            addr: 0x7F00_0000,
            mask: 0xFF00_0000,
        };
        let mut v6_loop = FWP_BYTE_ARRAY16 {
            byteArray16: [0; 16],
        };
        v6_loop.byteArray16[15] = 1;
        let mut port_range_slot = FWP_RANGE0 {
            valueLow: fwp_uint16(port_range.0),
            valueHigh: fwp_uint16(port_range.1),
        };

        let mut tag_lb =
            FilterTag::user("permit-loopback-user", sandbox_user_sid, Some(port_range))
                .to_blob_bytes();
        let mut tag_bk = FilterTag::user("block-user", sandbox_user_sid, None).to_blob_bytes();

        for (layer, label) in [
            (FWPM_LAYER_ALE_AUTH_CONNECT_V4, "v4"),
            (FWPM_LAYER_ALE_AUTH_CONNECT_V6, "v6"),
        ] {
            // PERMIT loopback ∩ port-range (no user condition).
            let addr_cond = if label == "v4" {
                cond_v4_subnet(FWPM_CONDITION_IP_REMOTE_ADDRESS, &mut v4_loop)
            } else {
                cond_v6_addr(FWPM_CONDITION_IP_REMOTE_ADDRESS, &mut v6_loop)
            };
            let mut c_lb = [
                addr_cond,
                cond_port_range(FWPM_CONDITION_IP_REMOTE_PORT, &mut port_range_slot),
            ];
            add_filter(
                engine.h(),
                sublayer,
                layer,
                &format!("srt-win-{label}-permit-loopback-user"),
                W_LOOPBACK,
                FWP_ACTION_PERMIT,
                &mut c_lb,
                &mut tag_lb,
            )?;
            // BLOCK sandbox user.
            let mut c_bk = [cond_sd(FWPM_CONDITION_ALE_USER_ID, &mut sd_user_blob)];
            add_filter(
                engine.h(),
                sublayer,
                layer,
                &format!("srt-win-{label}-block-user"),
                W_BLOCK,
                FWP_ACTION_BLOCK,
                &mut c_bk,
                &mut tag_bk,
            )?;
        }
        Ok(())
    })
}

/// Remove every srt-win-tagged filter under `sublayer`, then attempt
/// to delete the sublayer itself (best-effort; `FWP_E_IN_USE` means
/// foreign filters are still under it).
pub fn uninstall_filters(sublayer: &GUID) -> Result<usize> {
    with_wfp_txn(|engine| {
        let n = delete_tagged_filters(engine, sublayer)?;
        let rc = unsafe { FwpmSubLayerDeleteByKey0(engine.h(), sublayer) };
        if rc != 0
            && rc != FWP_E_SUBLAYER_NOT_FOUND
            && rc != FWP_E_FILTER_NOT_FOUND
            && rc != FWP_E_IN_USE
        {
            return Err(anyhow!("FwpmSubLayerDeleteByKey0: 0x{rc:08x}"));
        }
        Ok(n)
    })
}

/// Status of the WFP fence under `sublayer`. `installed` iff at
/// least one `block-user` srt-win filter exists. (We don't insist
/// on the exact count so enterprise tooling that adds extras under
/// the same sublayer doesn't break detection.) `port_range` is read
/// from the first `permit-loopback-user` tag.
///
/// `cannot-read` is the graceful-degrade state when BFE
/// enumeration is admin-gated ([`WfpAccessDenied`]). The
/// non-elevated readiness check is `srt-win wfp verify` (a
/// behavioral probe — spawns the runner as the sandbox user and
/// expects WSAEACCES on a direct connect), not this enum.
#[derive(Debug, Serialize)]
pub struct WfpStatus {
    pub state: &'static str,
    pub filters: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port_range: Option<[u16; 2]>,
    /// Sandbox-user SID read from the first user-keyed tag.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_sid: Option<String>,
    /// Populated only on `cannot-read`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
}

/// Live BFE enumeration. Admin-gated — a non-elevated caller gets
/// `state:"cannot-read"` (not an error) so `wfp status` exits 0
/// with a hint pointing at `wfp verify`. Elevated callers
/// (`install`'s early-return, the smoke scripts) get the real
/// per-filter counts.
pub fn filter_status(sublayer: &GUID) -> Result<WfpStatus> {
    let engine = match EngineHandle::open() {
        Ok(e) => e,
        Err(e) if e.downcast_ref::<WfpAccessDenied>().is_some() => {
            return Ok(cannot_read(e));
        }
        Err(e) => return Err(e),
    };
    let mut filters = 0usize;
    let mut have_block = false;
    let mut port_range: Option<[u16; 2]> = None;
    let mut user_sid: Option<String> = None;
    let enum_result = for_each_tagged_filter(&engine, sublayer, |_, _, tag| {
        filters += 1;
        if user_sid.is_none() {
            user_sid.clone_from(&tag.user_sid);
        }
        match tag.kind.as_str() {
            "block-user" => have_block = true,
            "permit-loopback-user" => port_range = tag.port_range,
            _ => {}
        }
    });
    if let Err(e) = enum_result {
        if e.downcast_ref::<WfpAccessDenied>().is_some() {
            return Ok(cannot_read(e));
        }
        return Err(e);
    }
    Ok(WfpStatus {
        state: if have_block { "installed" } else { "absent" },
        filters,
        port_range,
        user_sid,
        hint: None,
    })
}

fn cannot_read(e: anyhow::Error) -> WfpStatus {
    WfpStatus {
        state: "cannot-read",
        filters: 0,
        port_range: None,
        user_sid: None,
        hint: Some(format!(
            "{e}; elevation required for filter enum — run `srt-win \
             wfp verify` for a behavioral check"
        )),
    }
}

/// Parse a `--proxy-port-range LOW-HIGH` argument. Both ends are
/// inclusive. Validates `low <= high` and width `<=
/// MAX_PROXY_PORT_RANGE_WIDTH`.
pub fn parse_port_range(s: &str) -> Result<(u16, u16)> {
    let (lo_s, hi_s) = s
        .split_once('-')
        .ok_or_else(|| anyhow!("expected LOW-HIGH (e.g. 60080-60089)"))?;
    let lo: u16 = lo_s
        .trim()
        .parse()
        .map_err(|_| anyhow!("invalid low port '{lo_s}'"))?;
    let hi: u16 = hi_s
        .trim()
        .parse()
        .map_err(|_| anyhow!("invalid high port '{hi_s}'"))?;
    if lo == 0 {
        // Port 0 is "any" at bind time and never appears as a
        // remote port, so it's a dead slot in the range.
        return Err(anyhow!("low port must be >= 1"));
    }
    if lo > hi {
        return Err(anyhow!("low ({lo}) > high ({hi})"));
    }
    if hi - lo > MAX_PROXY_PORT_RANGE_WIDTH {
        return Err(anyhow!(
            "range too wide ({} ports); max width {}",
            hi - lo + 1,
            MAX_PROXY_PORT_RANGE_WIDTH + 1
        ));
    }
    Ok((lo, hi))
}

/// Parse a `--sublayer-guid` argument. Accepts braced or unbraced
/// canonical form. `GUID::try_from` only takes the unbraced form and
/// returns an unhelpful error on failure, so strip braces and
/// pre-validate the shape for a friendlier message.
pub fn parse_guid(s: &str) -> Result<GUID> {
    let t = s.trim().trim_start_matches('{').trim_end_matches('}');
    // 8-4-4-4-12 hex with hyphens, exactly 36 chars.
    let ok = t.len() == 36
        && t.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => b.is_ascii_hexdigit(),
        });
    if !ok {
        return Err(anyhow!(
            "invalid GUID '{s}': expected xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
        ));
    }
    GUID::try_from(t).map_err(|e| anyhow!("invalid GUID '{s}': {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The SDDL template used by `install_filters` must parse for a
    /// representative SID. Catches template typos without needing a
    /// live WFP engine.
    #[test]
    fn sddl_template_parses() {
        let sd =
            OwnedSd::from_sddl(&sddl_sandbox_user(crate::acl::SID_BUILTIN_USERS)).expect("sddl");
        assert!(!sd.ptr.0.is_null());
        assert!(sd.len > 0);
    }

    #[test]
    fn sddl_rejects_garbage() {
        assert!(OwnedSd::from_sddl("O:LSG:LSD:(A;;CC;;;NOT-A-SID)").is_err());
    }

    #[test]
    fn filter_tag_round_trip() {
        let sid = "S-1-5-21-1-2-3-1005";
        let bk = FilterTag::user("block-user", sid, None);
        assert_eq!(bk.user_sid.as_deref(), Some(sid));
        assert_eq!(bk.port_range, None);
        let lb = FilterTag::user("permit-loopback-user", sid, Some((60080, 60089)));
        assert_eq!(lb.port_range, Some([60080, 60089]));
        // Round-trips through JSON.
        let back: FilterTag = serde_json::from_slice(&lb.to_blob_bytes()).unwrap();
        assert_eq!(back, lb);
    }

    #[test]
    fn filter_tag_parses_legacy() {
        // A pre-port-range / pre-user-sid tag (the legacy
        // discriminator-group shape) must still parse so
        // uninstall/install can clean it up.
        let legacy = br#"{"tool":"srt-win","kind":"permit-loopback"}"#;
        let t: FilterTag = serde_json::from_slice(legacy).unwrap();
        assert_eq!(t.kind, "permit-loopback");
        assert_eq!(t.port_range, None);
        assert_eq!(t.user_sid, None);
    }

    /// const-assert the weight invariant directly so a reshuffle in
    /// `install_filters` fails to compile here.
    #[test]
    fn weight_invariant() {
        const { assert!(W_LOOPBACK > W_BLOCK) };
    }

    #[test]
    fn parse_port_range_ok() {
        assert_eq!(parse_port_range("60080-60089").unwrap(), (60080, 60089));
        assert_eq!(parse_port_range(" 1 - 1 ").unwrap(), (1, 1));
        assert_eq!(
            parse_port_range("1-65").unwrap(),
            (1, 1 + MAX_PROXY_PORT_RANGE_WIDTH)
        );
    }

    #[test]
    fn parse_port_range_rejects() {
        assert!(parse_port_range("60089-60080").is_err()); // low>high
        assert!(parse_port_range("1-1000").is_err()); // too wide
        assert!(parse_port_range("60080").is_err()); // no dash
        assert!(parse_port_range("a-b").is_err()); // not u16
        assert!(parse_port_range("0-65536").is_err()); // overflow
        assert!(parse_port_range("0-9").is_err()); // port 0
    }

    #[test]
    fn parse_guid_accepts_both_forms() {
        let g1 = parse_guid("2c5d0ad6-5f3b-4d4e-9b8f-1a3e7c9d0b21").unwrap();
        let g2 = parse_guid("{2c5d0ad6-5f3b-4d4e-9b8f-1a3e7c9d0b21}").unwrap();
        assert_eq!(g1, g2);
        assert_eq!(g1, DEFAULT_SUBLAYER_GUID);
    }

    #[test]
    fn parse_guid_rejects_garbage() {
        assert!(parse_guid("not-a-guid").is_err());
    }
}
