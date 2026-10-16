//! Windows Filtering Platform (WFP) filter management for the
//! sandbox-runtime Windows network fence.
//!
//! ## Design
//!
//! At install time we provision the dedicated `srt-sandbox` local
//! user account ([`crate::user`]) and persist **one machine-wide**
//! filter set — two filters at each of `FWPM_LAYER_ALE_AUTH_CONNECT_V4`
//! and `_V6` (4 total), plus one more per layer when loopback is
//! opened (6 total), all under one persistent sublayer
//! ([`filter_specs`] is the list):
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
//!   - **PERMIT loopback, open** (weight [`W_LOOPBACK`], optional) —
//!     the same address condition as the PERMIT above, with the port
//!     condition replaced by every port outside
//!     [`LOOPBACK_FLOOR_PORTS`] ([`open_loopback_port_ranges`]).
//!     Absent unless installed with `srt-win install
//!     --allow-loopback`. It lets the sandboxed child connect directly
//!     to local servers — a development server, a database, a server
//!     another sandboxed command started — over TCP and UDP alike (no
//!     filter of the set has a protocol condition). It opens every
//!     listener on loopback, whoever owns it, including any local
//!     forwarder that carries traffic off the machine; the floor is
//!     the short list of ports that stay blocked regardless.
//!
//!   - **BLOCK sandbox user** (weight [`W_BLOCK`]) — `ALE_USER_ID` SD
//!     = [`sddl_sandbox_user`]. Matches only tokens whose user SID is
//!     `<srt-sandbox SID>`. Everyone else (the broker, services,
//!     SYSTEM, the real user) carries a different user SID → no match
//!     → falls through to default-permit. The SD also carries ALLOW
//!     ACEs for the two all-packages SIDs so an AppContainer token
//!     derived from the sandbox account still matches (see
//!     [`sddl_sandbox_user`]).
//!
//! ## What the filters do not cover
//!
//! The identity WFP checks for a connect is the token that was in
//! effect when the SOCKET was created. Both gaps below are a sandboxed
//! thread putting a token the sandbox-user BLOCK does not match on
//! itself and then creating its socket. (A socket the process created
//! under its own token stays attributed to the sandbox account, and to
//! the BLOCK, even when the connect is made while impersonating.)
//!
//!   - The **anonymous token** (`ANONYMOUS LOGON`) is not the sandbox
//!     account, so the BLOCK does not match a socket created while
//!     impersonating it — to any destination, off the machine or on
//!     loopback. The only filter that could refuse it is one keyed on
//!     the anonymous SID itself, which would apply to every process on
//!     the machine that uses that token, sandboxed or not; this set
//!     carries none. `srt-win wfp verify` probes both destinations and
//!     reports a connect as the
//!     [`crate::probe::RESIDUAL_ANONYMOUS_EGRESS`] and
//!     [`crate::probe::RESIDUAL_ANONYMOUS_LOOPBACK`] residuals.
//!   - A token whose user SID has been made **deny-only**
//!     (`CreateRestrictedToken`) is matched by no ALLOW ACE, so the
//!     sandbox-user BLOCK does not match a socket created under it.
//!     No descriptor can fix that: the filter set blocks what it can
//!     name and permits the rest. `srt-win wfp verify` probes this
//!     shape and reports a connect as the [`RESIDUAL_DENY_ONLY`]
//!     residual.
//!
//! The probe makes each of these connects with the socket created
//! after the token is assumed as well as before; see [`crate::probe`].
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
//! port_range?, user_sid, rev}`) so install/uninstall/status can
//! locate them by enumeration. `rev` is [`FENCE_REVISION`]; a set
//! written by an earlier build lacks it or carries another and reads
//! as `outdated`. Whether loopback is open is part of what a
//! session must agree with the install about: it is recorded by the
//! presence of the `permit-loopback-open` filters and in the install
//! record, and `wfp verify` / `exec` refuse a session configured the
//! other way, in either direction ([`loopback_mismatch_hint`]). BFE
//! enumeration is admin-gated (see
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

/// Loopback ports that stay blocked for the sandbox account in every
/// mode, `--allow-loopback` included: local services that hand whoever
/// connects to them control of the machine, of another account, or of
/// another process, and the two best-known local forwarders. A floor,
/// not a guarantee: a service of either kind on any other port is
/// reachable once loopback is open. Ascending. The TypeScript library
/// carries the same ports (`WINDOWS_LOOPBACK_FLOOR_PORTS`) to describe
/// them.
pub const LOOPBACK_FLOOR_PORTS: [(u16, &str); 10] = [
    (53, "local DNS forwarder"),
    (1080, "local SOCKS proxy"),
    (2375, "container engine API"),
    (2376, "container engine API (TLS)"),
    (3389, "remote desktop"),
    (5985, "remote management (HTTP)"),
    (5986, "remote management (HTTPS)"),
    (9222, "browser remote debugging"),
    (9229, "JavaScript runtime inspector"),
    (47001, "remote management (compatibility listener)"),
];

/// Whether `port` is one of [`LOOPBACK_FLOOR_PORTS`].
pub fn is_loopback_floor_port(port: u16) -> bool {
    LOOPBACK_FLOOR_PORTS.iter().any(|(p, _)| *p == port)
}

/// Every port from 1 to 65535 that is not in `floor`, as inclusive
/// ranges in ascending order. `floor` must be ascending.
///
/// Port 0 is in no range. It is never the destination of a TCP or UDP
/// connect, and for ICMP the engine presents the message code in the
/// remote-port field, so leaving 0 out also keeps an echo request
/// (code 0) from matching a port condition built from these ranges.
pub(crate) fn port_ranges_outside(floor: &[u16]) -> Vec<(u16, u16)> {
    let mut ranges = Vec::new();
    let mut next: u32 = 1;
    for &p in floor {
        let p = u32::from(p);
        if p > next {
            ranges.push((next as u16, (p - 1) as u16));
        }
        next = next.max(p + 1);
    }
    if next <= u32::from(u16::MAX) {
        ranges.push((next as u16, u16::MAX));
    }
    ranges
}

/// The remote ports of the open-loopback PERMIT: everything but
/// [`LOOPBACK_FLOOR_PORTS`]. A port condition takes a range, and
/// conditions on one field are OR'ed, so "all but the floor" is the
/// complement written out as ranges.
pub(crate) fn open_loopback_port_ranges() -> Vec<(u16, u16)> {
    port_ranges_outside(&LOOPBACK_FLOOR_PORTS.map(|(p, _)| p))
}

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

fn cond_range(field_key: GUID, range: &mut FWP_RANGE0) -> FWPM_FILTER_CONDITION0 {
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

/// The conditions of a loopback PERMIT at one ALE connect layer: the
/// remote address is loopback (`127.0.0.0/8` or `::1`) AND the remote
/// port is in one of `ranges` (conditions on the same field are
/// OR'ed). Shared by the proxy-range PERMIT and the open-loopback
/// PERMIT so the two can only differ in their ports. The caller keeps
/// every referent alive until the filter is added.
fn loopback_permit_conditions(
    v4: bool,
    v4_loop: &mut FWP_V4_ADDR_AND_MASK,
    v6_loop: &mut FWP_BYTE_ARRAY16,
    ranges: &mut [FWP_RANGE0],
) -> Vec<FWPM_FILTER_CONDITION0> {
    let addr = if v4 {
        cond_v4_subnet(FWPM_CONDITION_IP_REMOTE_ADDRESS, v4_loop)
    } else {
        cond_v6_addr(FWPM_CONDITION_IP_REMOTE_ADDRESS, v6_loop)
    };
    let ports = ranges
        .iter_mut()
        .map(|r| cond_range(FWPM_CONDITION_IP_REMOTE_PORT, r));
    std::iter::once(addr).chain(ports).collect()
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
    /// `permit-loopback-user` / `permit-loopback-open` /
    /// `block-user`.
    pub kind: String,
    /// `[low, high]` for `permit-loopback-user`; `None` otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port_range: Option<[u16; 2]>,
    /// Sandbox user SID. `None` only on legacy installs that predate
    /// the user-SID-keyed design.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_sid: Option<String>,
    /// [`FENCE_REVISION`] of the build that wrote the filter. `None`
    /// on filters written before the revision was recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rev: Option<u32>,
}

impl FilterTag {
    fn user(kind: &str, sid: &str, range: Option<(u16, u16)>) -> Self {
        Self {
            tool: "srt-win".into(),
            kind: kind.into(),
            port_range: range.map(|(l, h)| [l, h]),
            user_sid: Some(sid.into()),
            rev: Some(FENCE_REVISION),
        }
    }
    fn to_blob_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("FilterTag is always serialisable")
    }
}

/// Tag kind of the PERMIT for the proxy port range. (The name is
/// historical; the filter carries no user condition.)
pub(crate) const KIND_PERMIT_PROXY: &str = "permit-loopback-user";
/// Tag kind of the open-loopback PERMIT.
pub(crate) const KIND_PERMIT_OPEN: &str = "permit-loopback-open";
pub(crate) const KIND_BLOCK_USER: &str = "block-user";

/// What one filter of the set matches and does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FilterShape {
    /// PERMIT: remote address is loopback AND remote port is in the
    /// range.
    PermitLoopback((u16, u16)),
    /// PERMIT: remote address is loopback AND remote port is in one
    /// of [`open_loopback_port_ranges`].
    PermitLoopbackOpen,
    /// BLOCK: the token is the sandbox account's.
    BlockUser,
}

/// One filter of the set, as added at EACH ALE connect layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FilterSpec {
    pub kind: &'static str,
    pub weight: u64,
    pub shape: FilterShape,
}

impl FilterSpec {
    /// The port range recorded in the filter's tag.
    pub(crate) fn port_range(&self) -> Option<(u16, u16)> {
        match self.shape {
            FilterShape::PermitLoopback(r) => Some(r),
            _ => None,
        }
    }
}

/// The filters [`install_filters`] adds at each ALE connect layer.
/// `allow_loopback` adds exactly one PERMIT and changes nothing else.
pub(crate) fn filter_specs(proxy_range: (u16, u16), allow_loopback: bool) -> Vec<FilterSpec> {
    let mut specs = vec![FilterSpec {
        kind: KIND_PERMIT_PROXY,
        weight: W_LOOPBACK,
        shape: FilterShape::PermitLoopback(proxy_range),
    }];
    if allow_loopback {
        specs.push(FilterSpec {
            kind: KIND_PERMIT_OPEN,
            weight: W_LOOPBACK,
            shape: FilterShape::PermitLoopbackOpen,
        });
    }
    specs.push(FilterSpec {
        kind: KIND_BLOCK_USER,
        weight: W_BLOCK,
        shape: FilterShape::BlockUser,
    });
    specs
}

/// Number of filters in the set: 2 per layer × v4/v6, plus one per
/// layer when loopback is open.
pub fn filter_count(allow_loopback: bool) -> usize {
    ALE_LAYERS.len() * filter_specs(DEFAULT_PROXY_PORT_RANGE, allow_loopback).len()
}

/// Revision of the filter set this build installs and requires.
/// Bumped whenever the set changes in a way an existing install must
/// pick up by re-running `srt-win install`:
///
///   1. loopback PERMIT + sandbox-user BLOCK (unrecorded — filters of
///      this revision carry no `rev`).
///   2. adds a BLOCK keyed on the anonymous SID, for off-loopback
///      destinations, and the all-packages ACEs on the sandbox-user
///      descriptor.
///   3. drops the anonymous BLOCK, which applied to every process on
///      the machine; keeps the all-packages ACEs. Installing over a
///      set that has the anonymous BLOCK deletes it along with the
///      rest ([`install_filters`] removes every tagged filter before
///      adding its own).
///   4. may carry the open-loopback PERMIT, and records whether it
///      does beside the revision. A set without the PERMIT has the
///      same filters as revision 3; the number moves so that a build
///      which does not know about open loopback never accepts a set
///      that may have it.
///
/// Recorded twice: in every filter's tag (what an elevated `wfp
/// status` reads) and in the install record (what the non-elevated
/// broker reads — it cannot enumerate filters).
pub const FENCE_REVISION: u32 = 4;

/// What the install record holds in place of a revision once an
/// uninstall has removed the filters but kept the account. Never a
/// revision a filter set carries.
pub const FENCE_REVISION_REMOVED: u32 = 0;

/// Filter kinds that must be present, at [`FENCE_REVISION`], on each
/// ALE connect layer for the fence to be current.
const REQUIRED_BLOCK_KINDS: [&str; 1] = [KIND_BLOCK_USER];

/// Name of the residual `srt-win wfp verify` reports when a connect
/// made under a copy of the sandbox token whose user SID is deny-only
/// is not blocked, in either socket ordering the probe tries. See the
/// module doc.
pub const RESIDUAL_DENY_ONLY: &str = "deny-only-user-sid";

// Filter weights — kept below 2^60 so they stay in WFP's
// "manual weight" class (top 4 bits are auto-classifier). The
// loopback PERMITs must sit **above** the user-SID BLOCK so the
// sandbox user can still reach the host proxies (and, when it is
// open, the rest of loopback). Module-level so
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

/// SDDL for the sandbox-user BLOCK filter — ALLOW `<sandbox_user_sid>`
/// plus ALLOW for ALL APPLICATION PACKAGES (`S-1-15-2-1`) and ALL
/// RESTRICTED APPLICATION PACKAGES (`S-1-15-2-2`).
///
/// The user ACE matches iff the connecting token carries that SID
/// **enabled**, which for a *user* SID means "is that user". The
/// broker, services, and every other process carry a different user
/// SID → no match → fall through to default-permit.
///
/// The two package ACEs exist for AppContainer tokens. The access
/// check of such a token has two halves that must BOTH grant: the
/// ordinary one over the user and group SIDs, and one over the
/// package and capability SIDs. With the user ACE alone, an
/// AppContainer process started under the sandbox account passes the
/// first half and fails the second, so the BLOCK would not match it.
/// The package ACEs supply the second half. They grant nothing by
/// themselves: a token outside an AppContainer does not carry either
/// SID, and an AppContainer token of any OTHER user still fails the
/// first half.
///
/// The descriptor carries no mandatory label: a process of the
/// sandbox account runs at medium integrity, the level an unlabelled
/// descriptor is given. A copy of its token
/// with the integrity level lowered is below that level; whether the
/// BLOCK still matches it is measured by the fence probe
/// ([`crate::probe`]), which requires it to.
pub fn sddl_sandbox_user(sid: &str) -> String {
    format!("O:LSG:LSD:(A;;CC;;;{sid})(A;;CC;;;S-1-15-2-1)(A;;CC;;;S-1-15-2-2)")
}

/// Install (or refresh) the filter set under `sublayer`:
/// [`filter_specs`] at each of the v4/v6 ALE-connect layers
/// ([`filter_count`] total) — see the module doc for the design.
///
/// Idempotent: any existing srt-win-tagged filters under `sublayer`
/// — including legacy discriminator-group-keyed filters from a
/// pre-separate-user install, the anonymous BLOCK filters of an
/// earlier revision, and an open-loopback PERMIT that is no
/// longer asked for — are deleted first, then a fresh set is added,
/// all inside one WFP transaction.
pub fn install_filters(
    sublayer: &GUID,
    sandbox_user_sid: &str,
    port_range: (u16, u16),
    allow_loopback: bool,
) -> Result<()> {
    debug_assert!(port_range.0 <= port_range.1);
    let specs = filter_specs(port_range, allow_loopback);
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
        // (this version's user-keyed shape, the anonymous BLOCK of
        // an earlier revision, and any legacy group-keyed filters
        // from a prior install) before re-adding. Inside the
        // transaction so a crash leaves the previous state intact.
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

        for (layer, label) in [
            (FWPM_LAYER_ALE_AUTH_CONNECT_V4, "v4"),
            (FWPM_LAYER_ALE_AUTH_CONNECT_V6, "v6"),
        ] {
            let v4 = label == "v4";
            for spec in &specs {
                let name = format!("srt-win-{label}-{}", spec.kind);
                let mut tag =
                    FilterTag::user(spec.kind, sandbox_user_sid, spec.port_range()).to_blob_bytes();
                match spec.shape {
                    // PERMIT loopback ∩ port-range (no user
                    // condition).
                    FilterShape::PermitLoopback((lo, hi)) => {
                        let mut ports = [FWP_RANGE0 {
                            valueLow: fwp_uint16(lo),
                            valueHigh: fwp_uint16(hi),
                        }];
                        let mut c =
                            loopback_permit_conditions(v4, &mut v4_loop, &mut v6_loop, &mut ports);
                        add_filter(
                            engine.h(),
                            sublayer,
                            layer,
                            &name,
                            spec.weight,
                            FWP_ACTION_PERMIT,
                            &mut c,
                            &mut tag,
                        )?;
                    }
                    // PERMIT loopback ∩ every port outside the floor
                    // (no user condition).
                    FilterShape::PermitLoopbackOpen => {
                        let mut ports: Vec<FWP_RANGE0> = open_loopback_port_ranges()
                            .into_iter()
                            .map(|(lo, hi)| FWP_RANGE0 {
                                valueLow: fwp_uint16(lo),
                                valueHigh: fwp_uint16(hi),
                            })
                            .collect();
                        let mut c =
                            loopback_permit_conditions(v4, &mut v4_loop, &mut v6_loop, &mut ports);
                        add_filter(
                            engine.h(),
                            sublayer,
                            layer,
                            &name,
                            spec.weight,
                            FWP_ACTION_PERMIT,
                            &mut c,
                            &mut tag,
                        )?;
                    }
                    FilterShape::BlockUser => {
                        let mut c = [cond_sd(FWPM_CONDITION_ALE_USER_ID, &mut sd_user_blob)];
                        add_filter(
                            engine.h(),
                            sublayer,
                            layer,
                            &name,
                            spec.weight,
                            FWP_ACTION_BLOCK,
                            &mut c,
                            &mut tag,
                        )?;
                    }
                }
            }
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

/// Status of the WFP fence under `sublayer` — see
/// [`classify_fence`] for `absent` / `installed` / `outdated`.
/// `port_range` is read from the first `permit-loopback-user` tag;
/// `allow_loopback` is whether the set carries a `permit-loopback-open`
/// filter.
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
    /// Whether the installed set opens loopback. Read off the filters
    /// by an elevated caller; a non-elevated one (`cannot-read`) gets
    /// the install record's.
    pub allow_loopback: bool,
    /// [`open_loopback_notice`], present exactly when `allow_loopback`
    /// is true once the install record has been folded in.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub loopback_notice: Option<String>,
    /// Sandbox-user SID read from the first user-keyed tag.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_sid: Option<String>,
    /// Populated on `cannot-read` and on `outdated`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
}

/// What to tell the operator when the fence is not at
/// [`FENCE_REVISION`]. One wording for `wfp status`, `wfp verify`
/// and `exec`.
pub fn outdated_hint(have: Option<u32>) -> String {
    if have == Some(FENCE_REVISION_REMOVED) {
        return "the network fence on this machine is not installed (its \
                filters were removed by an uninstall) — re-run `srt-win \
                install` (one UAC prompt)"
            .to_string();
    }
    // What the installed revision is missing.
    let gained = match have {
        Some(r) if r >= 3 => "which records whether the filters open loopback",
        _ => {
            "which has no machine-wide block on the anonymous token and \
             records whether the filters open loopback"
        }
    };
    let have = match have {
        Some(r) => format!("revision {r}"),
        None => "an unrecorded earlier revision".to_string(),
    };
    format!(
        "the network fence on this machine is out of date ({have}; \
         this build requires revision {FENCE_REVISION}, {gained}) — \
         re-run `srt-win install` (one UAC prompt)"
    )
}

/// `open` or `closed`.
pub fn fmt_loopback(open: bool) -> &'static str {
    if open { "open" } else { "closed" }
}

/// What to say wherever loopback is found open, so that "egress
/// blocked" is not read as the whole story.
pub fn open_loopback_notice() -> String {
    let floor: Vec<String> = LOOPBACK_FLOOR_PORTS
        .iter()
        .map(|(p, _)| p.to_string())
        .collect();
    format!(
        "loopback is open: the sandbox account can connect to every TCP \
         and UDP port on 127.0.0.0/8 and ::1 except {}. Every service \
         listening on localhost is reachable from sandboxed commands, \
         and any local forwarder (a DNS stub, a SOCKS or HTTP proxy, a \
         VPN agent) reachable there gives them a way off the machine; \
         the egress block covers direct connections only",
        floor.join(", "),
    )
}

/// What to tell the operator when the session's loopback mode is not
/// the one the installed filter set has, in either direction. One
/// wording for `wfp verify` and `exec`. Names the install command that
/// makes the machine match the session.
pub fn loopback_mismatch_hint(installed: bool, configured: bool) -> String {
    let flag = if configured { " --allow-loopback" } else { "" };
    format!(
        "the network fence on this machine does not match this \
         session's loopback mode (installed: {}; configured: {}) — \
         re-run `srt-win install{flag} --force` (one UAC prompt)",
        fmt_loopback(installed),
        fmt_loopback(configured),
    )
}

/// What to tell the operator when the install record and the session
/// agree that loopback is open but a connect to a loopback listener
/// was blocked: the filters in place are not the ones recorded.
pub fn loopback_closed_hint() -> String {
    "the network fence on this machine does not open loopback (a \
     connect to a loopback listener was blocked) — re-run `srt-win \
     install --allow-loopback --force` (one UAC prompt)"
        .to_string()
}

/// Classify an enumerated filter set, given `(layer, tag)` for every
/// srt-win filter under the sublayer.
///
///   - `absent` — no `block-user` filter at all.
///   - `installed` — every [`REQUIRED_BLOCK_KINDS`] filter is present
///     at [`FENCE_REVISION`] on BOTH ALE connect layers.
///   - `outdated` — anything in between: a set written by an earlier
///     build (no `rev`, or another one), or one missing a layer.
///     Also a set whose open-loopback PERMITs are not whole: present
///     on one layer only, or written at another revision.
///
/// Extra filters are ignored, so enterprise tooling that adds its own
/// under the same sublayer does not break detection.
pub(crate) fn classify_fence(tags: &[(&str, FilterTag)]) -> &'static str {
    if !tags.iter().any(|(_, t)| t.kind == "block-user") {
        return "absent";
    }
    let current = ALE_LAYERS.iter().all(|(_, layer)| {
        REQUIRED_BLOCK_KINDS.iter().all(|kind| {
            tags.iter()
                .any(|(l, t)| l == layer && t.kind == *kind && t.rev == Some(FENCE_REVISION))
        })
    });
    let open: Vec<&(&str, FilterTag)> = tags
        .iter()
        .filter(|(_, t)| t.kind == KIND_PERMIT_OPEN)
        .collect();
    let open_whole = open.is_empty()
        || (open.iter().all(|(_, t)| t.rev == Some(FENCE_REVISION))
            && ALE_LAYERS
                .iter()
                .all(|(_, layer)| open.iter().any(|(l, _)| l == layer)));
    if current && open_whole {
        "installed"
    } else {
        "outdated"
    }
}

/// Fold the install record's loopback mode into an enumerated
/// status. `recorded` is `None` when the machine has no install
/// record.
///
/// A non-elevated caller (`cannot-read`) has only the record, so it
/// reports the record's mode. An elevated caller that enumerated an
/// `installed` set whose mode differs from the record's reports
/// `outdated`: the non-elevated broker would otherwise hold sessions
/// to a mode the filters do not have.
pub fn apply_recorded_loopback(mut st: WfpStatus, recorded: Option<bool>) -> WfpStatus {
    match (st.state, recorded) {
        ("cannot-read", Some(open)) => st.allow_loopback = open,
        ("installed", Some(open)) if st.allow_loopback != open => {
            st.state = "outdated";
            st.hint = Some(format!(
                "the filters have loopback {} but the install record \
                 says {} — re-run `srt-win install` (one UAC prompt)",
                fmt_loopback(st.allow_loopback),
                fmt_loopback(open),
            ));
        }
        _ => {}
    }
    st.loopback_notice = st.allow_loopback.then(open_loopback_notice);
    st
}

/// Fold the install record's fence revision into an enumerated
/// status. `record` is `None` when the machine has no install record
/// at all, `Some(rev)` when it has one (`rev` itself is `None` for a
/// record written before the revision was kept).
///
/// A non-elevated caller cannot enumerate filters (`cannot-read`), so
/// the record is its only way to learn that the install predates this
/// build (`outdated`) or that an uninstall removed the filters
/// (`absent`); and an elevated caller that enumerated a
/// current-looking set under one sublayer still must not report
/// `installed` while the record says otherwise (`outdated`). Only a
/// record at [`FENCE_REVISION`] leaves `installed` or `cannot-read`
/// standing.
pub fn apply_recorded_revision(mut st: WfpStatus, record: Option<Option<u32>>) -> WfpStatus {
    if let Some(rev) = record
        && rev != Some(FENCE_REVISION)
        && matches!(st.state, "installed" | "cannot-read")
    {
        let removed = rev == Some(FENCE_REVISION_REMOVED);
        st.state = if removed && st.state == "cannot-read" {
            "absent"
        } else {
            "outdated"
        };
        st.hint = Some(outdated_hint(rev));
    }
    st
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
    let mut tags: Vec<(&'static str, FilterTag)> = Vec::new();
    let mut port_range: Option<[u16; 2]> = None;
    let mut user_sid: Option<String> = None;
    let enum_result = for_each_tagged_filter(&engine, sublayer, |layer, _, tag| {
        if user_sid.is_none() {
            user_sid.clone_from(&tag.user_sid);
        }
        if tag.kind == KIND_PERMIT_PROXY {
            port_range = tag.port_range;
        }
        tags.push((layer, tag.clone()));
    });
    if let Err(e) = enum_result {
        if e.downcast_ref::<WfpAccessDenied>().is_some() {
            return Ok(cannot_read(e));
        }
        return Err(e);
    }
    let state = classify_fence(&tags);
    Ok(WfpStatus {
        state,
        filters: tags.len(),
        port_range,
        allow_loopback: tags.iter().any(|(_, t)| t.kind == KIND_PERMIT_OPEN),
        loopback_notice: None,
        user_sid,
        hint: (state == "outdated").then(|| {
            // The oldest revision present is the one worth naming.
            outdated_hint(tags.iter().map(|(_, t)| t.rev).min().flatten())
        }),
    })
}

fn cannot_read(e: anyhow::Error) -> WfpStatus {
    WfpStatus {
        state: "cannot-read",
        filters: 0,
        port_range: None,
        allow_loopback: false,
        loopback_notice: None,
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
        let sd = OwnedSd::from_sddl(&sddl_sandbox_user("S-1-5-32-545")).expect("sddl");
        assert!(!sd.ptr.0.is_null());
        assert!(sd.len > 0);
    }

    #[test]
    fn sandbox_user_sddl_carries_both_package_aces() {
        let s = sddl_sandbox_user("S-1-5-21-1-2-3-1005");
        assert!(s.contains("(A;;CC;;;S-1-5-21-1-2-3-1005)"));
        assert!(s.contains("(A;;CC;;;S-1-15-2-1)"));
        assert!(s.contains("(A;;CC;;;S-1-15-2-2)"));
        // ALLOW only: a DENY ACE in a match descriptor would invert
        // which tokens the filter applies to.
        assert!(!s.contains("(D;"));
    }

    fn tag(kind: &str, rev: Option<u32>) -> FilterTag {
        FilterTag {
            rev,
            ..FilterTag::user(kind, "S-1-5-21-1-2-3-1005", None)
        }
    }

    fn full_set(rev: Option<u32>, kinds: &[&str]) -> Vec<(&'static str, FilterTag)> {
        ALE_LAYERS
            .iter()
            .flat_map(|(_, layer)| kinds.iter().map(move |k| (*layer, tag(k, rev))))
            .collect()
    }

    const ALL_KINDS: [&str; 2] = ["permit-loopback-user", "block-user"];
    /// The set revision 2 wrote: a BLOCK keyed on the anonymous SID
    /// beside the two this build writes.
    const REV2_KINDS: [&str; 3] = ["permit-loopback-user", "block-user", "block-anonymous"];

    /// A current set plus the open-loopback PERMIT on both layers.
    fn set_with_open_loopback() -> Vec<(&'static str, FilterTag)> {
        let mut set = full_set(Some(FENCE_REVISION), &ALL_KINDS);
        for (_, layer) in ALE_LAYERS {
            set.push((layer, tag(KIND_PERMIT_OPEN, Some(FENCE_REVISION))));
        }
        set
    }

    #[test]
    fn filter_list_with_loopback_closed_is_the_two_filter_set() {
        let specs = filter_specs((60080, 60089), false);
        assert_eq!(
            specs.iter().map(|s| s.kind).collect::<Vec<_>>(),
            ["permit-loopback-user", "block-user"]
        );
        assert_eq!(specs[0].shape, FilterShape::PermitLoopback((60080, 60089)));
        assert_eq!(specs[0].port_range(), Some((60080, 60089)));
        assert_eq!(specs[1].shape, FilterShape::BlockUser);
        assert_eq!(specs[1].port_range(), None);
        assert_eq!(filter_count(false), 4);
    }

    #[test]
    fn filter_list_with_loopback_open_adds_exactly_one_permit() {
        let closed = filter_specs((60080, 60089), false);
        let open = filter_specs((60080, 60089), true);
        assert_eq!(
            open.iter().map(|s| s.kind).collect::<Vec<_>>(),
            ["permit-loopback-user", "permit-loopback-open", "block-user"]
        );
        assert_eq!(filter_count(true), 6);
        // The added filter is a loopback PERMIT at the weight of the
        // proxy PERMIT: above the BLOCKs.
        let added = open[1];
        assert_eq!(added.shape, FilterShape::PermitLoopbackOpen);
        assert_eq!(added.weight, W_LOOPBACK);
        assert!(added.weight > W_BLOCK);
        // Everything else is the closed set, unchanged — the proxy
        // PERMIT included.
        let rest: Vec<FilterSpec> = open
            .iter()
            .copied()
            .filter(|s| s.kind != KIND_PERMIT_OPEN)
            .collect();
        assert_eq!(rest, closed);
        // The only PERMITs are the two loopback ones.
        for s in &open {
            assert_eq!(
                s.weight == W_LOOPBACK,
                matches!(
                    s.shape,
                    FilterShape::PermitLoopback(_) | FilterShape::PermitLoopbackOpen
                )
            );
        }
    }

    /// Whether `ranges` is ascending, without overlap, and covers
    /// exactly the ports from 1 to 65535 that are not in `floor`.
    fn is_complement(ranges: &[(u16, u16)], floor: &[u16]) -> bool {
        let ordered =
            ranges.iter().all(|(lo, hi)| lo <= hi) && ranges.windows(2).all(|w| w[0].1 < w[1].0);
        let covered = |p: u16| {
            ranges
                .iter()
                .filter(|(lo, hi)| (*lo..=*hi).contains(&p))
                .count()
        };
        ordered
            && covered(0) == 0
            && (1..=u16::MAX).all(|p| covered(p) == usize::from(!floor.contains(&p)))
    }

    #[test]
    fn open_loopback_ports_are_everything_but_the_floor() {
        let floor = LOOPBACK_FLOOR_PORTS.map(|(p, _)| p);
        assert!(floor.windows(2).all(|w| w[0] < w[1]), "floor not ascending");
        let ranges = open_loopback_port_ranges();
        assert!(is_complement(&ranges, &floor), "{ranges:?}");
        assert_eq!(
            ranges,
            [
                (1, 52),
                (54, 1079),
                (1081, 2374),
                (2377, 3388),
                (3390, 5984),
                (5987, 9221),
                (9223, 9228),
                (9230, 47000),
                (47002, 65535),
            ]
        );
        for required in [53, 1080, 2375, 2376, 3389, 5985, 5986, 9222, 9229, 47001] {
            assert!(is_loopback_floor_port(required), "{required}");
        }
        assert!(!is_loopback_floor_port(8080));
        // The proxy ports are not on the floor: their own PERMIT is
        // what opens them, with loopback open or closed.
        let (lo, hi) = DEFAULT_PROXY_PORT_RANGE;
        assert!((lo..=hi).all(|p| !is_loopback_floor_port(p)));
    }

    #[test]
    fn port_ranges_outside_handles_the_edges() {
        assert_eq!(port_ranges_outside(&[]), [(1, 65535)]);
        // The first and last ports, alone and adjacent to another.
        assert_eq!(port_ranges_outside(&[1]), [(2, 65535)]);
        assert_eq!(port_ranges_outside(&[65535]), [(1, 65534)]);
        assert_eq!(port_ranges_outside(&[1, 2, 65534, 65535]), [(3, 65533)]);
        // Port 0 is never in a range, listed or not.
        assert_eq!(port_ranges_outside(&[0]), [(1, 65535)]);
        // A repeated port changes nothing.
        assert_eq!(port_ranges_outside(&[80, 80]), [(1, 79), (81, 65535)]);
        for floor in [
            &[1u16, 3, 5][..],
            &[2, 3, 4],
            &[65533, 65535],
            &[0, 1, 65535],
        ] {
            assert!(
                is_complement(&port_ranges_outside(floor), floor),
                "{floor:?}"
            );
        }
    }

    #[test]
    fn classify_fence_with_loopback_open() {
        assert_eq!(classify_fence(&set_with_open_loopback()), "installed");
        // On one layer only.
        let mut half = set_with_open_loopback();
        let v6 = ALE_LAYERS[1].1;
        half.retain(|(l, t)| !(*l == v6 && t.kind == KIND_PERMIT_OPEN));
        assert_eq!(classify_fence(&half), "outdated");
        // Written at another revision.
        let mut old = full_set(Some(FENCE_REVISION), &ALL_KINDS);
        for (_, layer) in ALE_LAYERS {
            old.push((layer, tag(KIND_PERMIT_OPEN, Some(FENCE_REVISION - 1))));
        }
        assert_eq!(classify_fence(&old), "outdated");
        // PERMITs alone fence nothing.
        let only: Vec<_> = set_with_open_loopback()
            .into_iter()
            .filter(|(_, t)| t.kind.starts_with("permit"))
            .collect();
        assert_eq!(classify_fence(&only), "absent");
    }

    #[test]
    fn recorded_loopback_mode_is_reported_and_compared() {
        let with = |state, open| WfpStatus {
            allow_loopback: open,
            ..status(state)
        };
        // Non-elevated: the record's mode is what gets reported.
        for open in [false, true] {
            let st = apply_recorded_loopback(with("cannot-read", false), Some(open));
            assert_eq!(st.state, "cannot-read");
            assert_eq!(st.allow_loopback, open);
            assert_eq!(st.loopback_notice.is_some(), open);
        }
        // Elevated, filters and record agree.
        for open in [false, true] {
            let st = apply_recorded_loopback(with("installed", open), Some(open));
            assert_eq!(st.state, "installed");
            assert_eq!(st.allow_loopback, open);
            assert_eq!(st.loopback_notice.is_some(), open);
        }
        // Elevated, they disagree — either way round.
        for open in [false, true] {
            let st = apply_recorded_loopback(with("installed", open), Some(!open));
            assert_eq!(st.state, "outdated", "filters {open}, record {}", !open);
            assert!(st.hint.unwrap().contains("srt-win install"));
            assert_eq!(st.allow_loopback, open);
        }
        // No install record, or nothing installed: left alone.
        let st = apply_recorded_loopback(with("installed", true), None);
        assert_eq!(st.state, "installed");
        assert!(st.loopback_notice.is_some());
        for s in ["absent", "outdated"] {
            let st = apply_recorded_loopback(with(s, false), Some(true));
            assert_eq!(st.state, s);
            assert!(!st.allow_loopback && st.loopback_notice.is_none());
        }
    }

    #[test]
    fn loopback_hints_name_the_install_command() {
        let h = loopback_mismatch_hint(false, true);
        assert!(h.contains("installed: closed"));
        assert!(h.contains("configured: open"));
        assert!(h.contains("srt-win install --allow-loopback --force"));
        let h = loopback_mismatch_hint(true, false);
        assert!(h.contains("installed: open"));
        assert!(h.contains("configured: closed"));
        assert!(h.contains("srt-win install --force"));
        assert!(loopback_closed_hint().contains("srt-win install --allow-loopback"));
    }

    /// The notice says loopback is open, names every floor port, and
    /// says that a local forwarder is a way off the machine.
    #[test]
    fn open_loopback_notice_is_plain() {
        let n = open_loopback_notice();
        assert!(n.starts_with("loopback is open"));
        for (port, _) in LOOPBACK_FLOOR_PORTS {
            assert!(n.contains(&port.to_string()), "{port}");
        }
        assert!(n.contains("forwarder") && n.contains("off the machine"));
    }

    #[test]
    fn outdated_hint_says_what_each_revision_lacks() {
        for old in [None, Some(1), Some(2)] {
            let h = outdated_hint(old);
            assert!(h.contains("anonymous") && h.contains("open loopback"));
        }
        let h = outdated_hint(Some(3));
        assert!(h.contains("revision 3") && h.contains("open loopback"));
        assert!(!h.contains("anonymous"));
    }

    #[test]
    fn classify_fence_states() {
        assert_eq!(classify_fence(&[]), "absent");
        // Only a PERMIT left behind: nothing is fenced.
        assert_eq!(
            classify_fence(&full_set(Some(FENCE_REVISION), &["permit-loopback-user"])),
            "absent"
        );
        let current = full_set(Some(FENCE_REVISION), &ALL_KINDS);
        assert_eq!(current.len(), filter_count(false));
        assert_eq!(classify_fence(&current), "installed");
        // No kind this build writes names the anonymous token.
        assert!(current.iter().all(|(_, t)| !t.kind.contains("anonymous")));
        // The set the first build wrote: no rev.
        assert_eq!(classify_fence(&full_set(None, &ALL_KINDS)), "outdated");
        // The same kinds but written at an earlier revision.
        assert_eq!(classify_fence(&full_set(Some(1), &ALL_KINDS)), "outdated");
        // A revision-2 set, with its anonymous BLOCK: replaced by the
        // next install.
        assert_eq!(classify_fence(&full_set(Some(2), &REV2_KINDS)), "outdated");
        // One layer missing its BLOCK.
        let mut half = current.clone();
        let v6 = ALE_LAYERS[1].1;
        half.retain(|(l, t)| !(*l == v6 && t.kind == "block-user"));
        assert_eq!(classify_fence(&half), "outdated");
        // Foreign extras under the sublayer do not disturb a current set.
        let mut extra = current;
        extra.push((v6, tag("something-else", None)));
        assert_eq!(classify_fence(&extra), "installed");
    }

    #[test]
    fn revision_follows_the_anonymous_block_removal() {
        // One above the revision that dropped the anonymous BLOCK:
        // this set may also carry the open-loopback PERMIT.
        const { assert!(FENCE_REVISION == 4) };
        assert!(outdated_hint(Some(2)).contains("revision 2"));
        assert!(outdated_hint(Some(2)).contains("requires revision 4"));
    }

    fn status(state: &'static str) -> WfpStatus {
        WfpStatus {
            state,
            filters: 0,
            port_range: None,
            allow_loopback: false,
            loopback_notice: None,
            user_sid: None,
            hint: None,
        }
    }

    #[test]
    fn recorded_revision_overrides_installed_and_cannot_read() {
        let cur = Some(Some(FENCE_REVISION));
        for s in ["installed", "cannot-read", "absent", "outdated"] {
            assert_eq!(apply_recorded_revision(status(s), cur).state, s);
            // No install record at all: nothing to compare against.
            assert_eq!(apply_recorded_revision(status(s), None).state, s);
        }
        for old in [Some(None), Some(Some(FENCE_REVISION - 1))] {
            for s in ["installed", "cannot-read"] {
                let st = apply_recorded_revision(status(s), old);
                assert_eq!(st.state, "outdated");
                assert!(st.hint.unwrap().contains("srt-win install"));
            }
            assert_eq!(
                apply_recorded_revision(status("absent"), old).state,
                "absent"
            );
        }
    }

    /// After an uninstall that keeps the account, the record is
    /// `FENCE_REVISION_REMOVED`. A caller that cannot enumerate must
    /// then read `absent`; one that still enumerates a set (the reset
    /// landed and the filter removal did not, or another sublayer
    /// holds one) must read `outdated`. Neither may read `installed`.
    #[test]
    fn removed_record_never_reads_as_installed() {
        let removed = Some(Some(FENCE_REVISION_REMOVED));
        let st = apply_recorded_revision(status("cannot-read"), removed);
        assert_eq!(st.state, "absent");
        let hint = st.hint.unwrap();
        assert!(hint.contains("not installed") && hint.contains("srt-win install"));
        assert_eq!(
            apply_recorded_revision(status("installed"), removed).state,
            "outdated"
        );
        assert_eq!(
            apply_recorded_revision(status("absent"), removed).state,
            "absent"
        );
        // Whatever else the record holds, only FENCE_REVISION lets
        // `installed` or `cannot-read` through unchanged.
        for rev in [None, Some(0), Some(1), Some(FENCE_REVISION + 1)] {
            for s in ["installed", "cannot-read"] {
                let got = apply_recorded_revision(status(s), Some(rev)).state;
                assert!(matches!(got, "absent" | "outdated"), "{rev:?}/{s} -> {got}");
            }
        }
        const { assert!(FENCE_REVISION_REMOVED != FENCE_REVISION) };
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
        assert_eq!(bk.rev, Some(FENCE_REVISION));
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
        assert_eq!(t.rev, None);
        // The tag the 4-filter set wrote: a user SID but no rev.
        let prev = br#"{"tool":"srt-win","kind":"block-user","user_sid":"S-1-5-21-1"}"#;
        let t: FilterTag = serde_json::from_slice(prev).unwrap();
        assert_eq!(t.rev, None);
        // A kind this build no longer writes still parses as one of
        // ours, so install and uninstall delete it.
        let anon =
            br#"{"tool":"srt-win","kind":"block-anonymous","user_sid":"S-1-5-21-1","rev":2}"#;
        let t: FilterTag = serde_json::from_slice(anon).unwrap();
        assert_eq!((t.tool.as_str(), t.rev), ("srt-win", Some(2)));
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
