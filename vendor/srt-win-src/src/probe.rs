//! The behavioural fence probe behind `srt-win wfp verify`.
//!
//! The runner — a process of the sandbox account — makes TCP connects
//! under each token shape a sandboxed process can present to the
//! filtering engine, and reports one result per shape and
//! destination:
//!
//!   - **plain** — its own token, to the loopback probe target. The
//!     sandbox-user BLOCK must refuse it.
//!   - **anonymous** — while impersonating the anonymous token, to an
//!     off-loopback target. No filter covers a socket created under
//!     that token (see the `wfp` module doc), so a connect here is
//!     expected and is reported as the [`RESIDUAL_ANONYMOUS_EGRESS`]
//!     residual.
//!   - **anonymous, loopback** — while impersonating the anonymous
//!     token, to the loopback probe target. Not covered either; a
//!     connect here is reported as the
//!     [`RESIDUAL_ANONYMOUS_LOOPBACK`] residual.
//!   - **low integrity** and **untrusted integrity** — under a copy
//!     of its own token whose integrity level has been lowered, to the
//!     off-loopback target and to the loopback probe target. The copy
//!     still carries the sandbox account's SID, so the sandbox-user
//!     BLOCK must refuse all four. They are probed because an access
//!     check applies the mandatory integrity rule before it reads a
//!     descriptor's entries, and a process may lower the integrity
//!     level of a copy of its own token without any privilege.
//!   - **deny-only** — under a restricted copy of its own token whose
//!     user SID is deny-only, to the loopback probe target. A
//!     deny-only SID is matched by no ALLOW ACE, so the filters
//!     cannot be made to refuse it; a connect here is reported as the
//!     [`crate::wfp::RESIDUAL_DENY_ONLY`] residual.
//!
//! ## Two orderings per assumed identity
//!
//! Which token a connect is attributed to depends on when the socket
//! was created. A socket the process creates under its own token and
//! then connects while impersonating can be attributed to the
//! process — and refused by the sandbox-user BLOCK — whatever the
//! thread's token is at the connect. That ordering alone therefore
//! says nothing about the assumed identity. Every attempt made under
//! an assumed identity is run twice, on the one thread that holds the
//! token ([`SocketOrder`]):
//!
//!   - **socket after token** — assume the identity, create the
//!     socket, connect. The socket itself belongs to the assumed
//!     identity; this is the ordering a process trying to get out
//!     would use.
//!   - **socket before token** — create the socket, assume the
//!     identity, connect. Kept because an engine that attributes at
//!     connect time would let this one through instead.
//!
//! In both, the thread's token is read back after the socket exists
//! and the identity is assumed, immediately before the connect; an
//! attempt whose token is not the one asked for is an `error`, never
//! a `blocked`. One case is told apart from every other failure: the
//! call that puts the token on the thread (`ImpersonateAnonymousToken`
//! or `SetThreadToken`) returning access-denied is the kernel refusing
//! that identity to this process, reported as `denied`
//! ([`Outcome::Denied`]) — no connect can be made that way, which is
//! not the same as the probe failing to make one. Each ordering's own result is logged to stderr with
//! the ordering named, and the attempt reports the WORSE of the two
//! for the fence ([`Outcome::worse`]): one ordering getting through
//! is the attempt getting through.
//!
//! ## Which process probes
//!
//! For the ordinary child token the runner itself makes the attempts
//! (`RunnerCmd::ProbeEgress`). For the write-restricted child token
//! (`wfp verify --write-restricted-token`) the runner launches
//! `srt-win probe fence` as a lockdown child, and that child makes
//! them: "its own token" is then the write-restricted token, and every
//! assumed identity is built from it, as a sandboxed command would
//! build it.
//!
//! The probing process's stdout is the broker's stdout, so the
//! results travel back in its exit code ([`Report::encode`]), which a
//! lockdown child's runner passes on as its own.

use anyhow::{Context, Result, anyhow};
use std::net::SocketAddr;

use windows::Win32::Foundation::{CloseHandle, ERROR_ACCESS_DENIED, HANDLE, LUID};
use windows::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, FD_SET, FIONBIO, IN_ADDR, IN_ADDR_0, IN6_ADDR, IN6_ADDR_0, IPPROTO_TCP,
    SO_ERROR, SOCK_STREAM, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_IN6_0, SOCKET,
    SOCKET_ERROR, SOL_SOCKET, TIMEVAL, WSADATA, WSAEACCES, WSAECONNREFUSED, WSAEWOULDBLOCK,
    WSAGetLastError, WSAStartup, closesocket, connect, getsockopt, ioctlsocket, select, socket,
};
use windows::Win32::Security::{
    CREATE_RESTRICTED_TOKEN_FLAGS, CreateRestrictedToken, DuplicateTokenEx, GetTokenInformation,
    ImpersonateAnonymousToken, RevertToSelf, SID_AND_ATTRIBUTES, SecurityImpersonation,
    TOKEN_ALL_ACCESS, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
    TOKEN_STATISTICS, TOKEN_USER, TokenImpersonation, TokenIntegrityLevel, TokenStatistics,
    TokenUser,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken, SetThreadToken,
};

/// Name of the residual reported when a connect to an off-loopback
/// destination made while impersonating the anonymous token is not
/// blocked. Expected on every machine with such a destination: the
/// filter set has no filter for the anonymous token.
pub const RESIDUAL_ANONYMOUS_EGRESS: &str = "anonymous-egress";

/// Name of the residual reported when a connect to a loopback
/// destination made while impersonating the anonymous token is not
/// blocked.
pub const RESIDUAL_ANONYMOUS_LOOPBACK: &str = "anonymous-loopback";

/// The user SID of the anonymous token (`ANONYMOUS LOGON`).
const ANONYMOUS_SID: &str = "S-1-5-7";

/// The low mandatory level, as the last part of `S-1-16-<n>`.
const IL_LOW: u32 = 0x1000;
/// The untrusted mandatory level — the lowest.
const IL_UNTRUSTED: u32 = 0;

/// How long one connect may take. A refused or filtered connect
/// returns at once; the bound only matters for a destination that
/// does not answer.
const CONNECT_TIMEOUT_SECS: i32 = 4;

/// Result of one connect attempt.
///
/// No outcome is numbered zero, so an exit code whose field bits are
/// all clear is not a report of "everything blocked".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// `WSAEACCES` — a BLOCK filter refused the connect.
    Blocked = 1,
    /// The connect completed.
    Connected = 2,
    /// `WSAECONNREFUSED` — nothing was listening, which the
    /// destination can only say once the connect got past the
    /// filters. For the fence this is the same answer as
    /// [`Outcome::Connected`].
    Refused = 3,
    /// Timed out or failed some other way; says nothing about the
    /// fence.
    Unreachable = 4,
    /// The attempt was not made (no target for it).
    Skipped = 5,
    /// No connect was made under the token shape: it could not be
    /// built or assumed (for a reason other than [`Outcome::Denied`]),
    /// a socket could not be created under it, or the thread's token
    /// read back as something else.
    Error = 6,
    /// The kernel refused to put the token on the thread: the
    /// impersonation call returned access-denied. The process cannot
    /// present that identity at all, so there is no connect to fence.
    /// The last value a field of [`BITS`] bits holds.
    Denied = 7,
}

impl Outcome {
    const ALL: [Outcome; 7] = [
        Outcome::Blocked,
        Outcome::Connected,
        Outcome::Refused,
        Outcome::Unreachable,
        Outcome::Skipped,
        Outcome::Error,
        Outcome::Denied,
    ];

    fn from_bits(b: u32) -> Option<Self> {
        Self::ALL.into_iter().find(|o| *o as u32 == b)
    }

    /// The word used in `wfp verify`'s JSON.
    pub fn label(self) -> &'static str {
        match self {
            Outcome::Blocked => "blocked",
            Outcome::Connected => "connected",
            Outcome::Refused => "refused",
            Outcome::Unreachable => "unreachable",
            Outcome::Skipped => "skipped",
            Outcome::Error => "error",
            Outcome::Denied => "denied",
        }
    }

    /// Whether the connect got past the filters.
    pub fn passed_fence(self) -> bool {
        matches!(self, Outcome::Connected | Outcome::Refused)
    }

    /// How bad this outcome is for the fence; higher is worse.
    ///
    ///   - `Connected`, then `Refused`: the connect got past the
    ///     filters.
    ///   - `Error`, then `Unreachable`, then `Skipped`: nothing was
    ///     learned. These rank above `Blocked` so that a block in one
    ///     ordering cannot stand in for an ordering that was never
    ///     measured.
    ///   - `Denied`: the identity could not be assumed, so no connect
    ///     was made. Below the three above, so a refusal in one
    ///     ordering does not hide the other ordering going unmeasured;
    ///     above `Blocked`, because no filter was seen to act.
    ///   - `Blocked`: a filter refused the connect. The combined
    ///     result is `Blocked` only when every part was.
    fn severity(self) -> u8 {
        match self {
            Outcome::Blocked => 0,
            Outcome::Denied => 1,
            Outcome::Skipped => 2,
            Outcome::Unreachable => 3,
            Outcome::Error => 4,
            Outcome::Refused => 5,
            Outcome::Connected => 6,
        }
    }

    /// The worse of two outcomes for the fence ([`Self::severity`]).
    pub fn worse(self, other: Self) -> Self {
        if other.severity() > self.severity() {
            other
        } else {
            self
        }
    }
}

/// Every attempt's result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Report {
    pub plain: Outcome,
    pub anonymous: Outcome,
    pub anonymous_loopback: Outcome,
    pub deny_only: Outcome,
    /// Low integrity, to the off-loopback target.
    pub low_integrity: Outcome,
    /// Low integrity, to the loopback target.
    pub low_integrity_loopback: Outcome,
    /// Untrusted integrity, to the off-loopback target.
    pub untrusted_integrity: Outcome,
    /// Untrusted integrity, to the loopback target.
    pub untrusted_integrity_loopback: Outcome,
}

const BITS: u32 = 3;
const MASK: u32 = (1 << BITS) - 1;
/// Number of [`Outcome`] fields in a [`Report`].
const FIELDS: u32 = 8;
/// Marks a runner exit code as an encoded [`Report`]: the bit just
/// above the fields. Above every code the runner exits with for
/// another reason (0, and 1 for its own error path), so an unrelated
/// exit never decodes.
const REPORT_BASE: u32 = 1 << (FIELDS * BITS);

impl Report {
    fn fields(&self) -> [Outcome; FIELDS as usize] {
        [
            self.plain,
            self.anonymous,
            self.anonymous_loopback,
            self.deny_only,
            self.low_integrity,
            self.low_integrity_loopback,
            self.untrusted_integrity,
            self.untrusted_integrity_loopback,
        ]
    }

    pub fn encode(&self) -> u32 {
        self.fields()
            .into_iter()
            .enumerate()
            .fold(REPORT_BASE, |code, (i, o)| {
                code | (o as u32) << (i as u32 * BITS)
            })
    }

    pub fn decode(code: u32) -> Option<Self> {
        if code & !(REPORT_BASE - 1) != REPORT_BASE {
            return None;
        }
        let field = |i: u32| Outcome::from_bits((code >> (i * BITS)) & MASK);
        Some(Self {
            plain: field(0)?,
            anonymous: field(1)?,
            anonymous_loopback: field(2)?,
            deny_only: field(3)?,
            low_integrity: field(4)?,
            low_integrity_loopback: field(5)?,
            untrusted_integrity: field(6)?,
            untrusted_integrity_loopback: field(7)?,
        })
    }

    /// The attempts the filters are built to refuse, each with
    /// whether it may have been skipped (the ones aimed at the
    /// off-loopback target, which a machine can lack).
    fn must_be_blocked(&self) -> [(Outcome, bool); 5] {
        [
            (self.plain, false),
            (self.low_integrity, true),
            (self.low_integrity_loopback, false),
            (self.untrusted_integrity, true),
            (self.untrusted_integrity_loopback, false),
        ]
    }
}

/// `wfp verify` exit code: the fence refused everything it is built
/// to refuse.
pub const EXIT_FENCED: i32 = 0;
/// `wfp verify` exit code: the probe could not tell.
pub const EXIT_INCONCLUSIVE: i32 = 2;
/// `wfp verify` exit code: a connect the fence must refuse got past
/// it.
pub const EXIT_NOT_FENCED: i32 = 3;
/// `wfp verify` / `exec` exit code: the install record says the
/// filter set is not the one this build requires (written by an
/// earlier build, or — for `exec` — removed by an uninstall).
pub const EXIT_FENCE_OUTDATED: i32 = 19;

/// What `wfp verify` concludes from a [`Report`].
#[derive(Debug, PartialEq, Eq)]
pub struct Verdict {
    pub exit: i32,
    /// Named gaps the probe observed that the filters do not close.
    /// Only meaningful with [`EXIT_FENCED`]: the fence is active, and
    /// these are what it leaves open.
    pub residuals: Vec<&'static str>,
}

/// The plain and the four lowered-integrity attempts — the ones made
/// under a token that still carries the sandbox account's SID —
/// decide the exit code: any one getting
/// past the filters is a missing fence, and any one that neither got
/// past nor was blocked — the token could not be assumed, the connect
/// timed out — leaves the probe inconclusive. An attempt at the
/// off-loopback target that was skipped (the machine has no such
/// address to aim at) does not fail the probe. The three remaining
/// attempts — both anonymous ones and the deny-only one — never fail
/// it, whatever their outcome: the filters do not refuse them. One
/// that got through is reported as a residual instead of passing
/// silently.
///
/// `child_token` says the probing process held the very token a
/// sandboxed command gets (`wfp verify --write-restricted-token`,
/// whose attempts are made by a lockdown child). Only then does an
/// attempt the kernel refused ([`Outcome::Denied`]) count as closed,
/// like a blocked one: a command holds the same token and is refused
/// the same way. When the bare runner probes on behalf of the
/// ordinary child token, a refusal says nothing certain about the
/// child and stays inconclusive, as every other unassumed token does.
pub fn verdict(r: &Report, child_token: bool) -> Verdict {
    let must = r.must_be_blocked();
    let closed = |o: Outcome, may_skip: bool| {
        o == Outcome::Blocked
            || (may_skip && o == Outcome::Skipped)
            || (child_token && o == Outcome::Denied)
    };
    let exit = if must.iter().any(|(o, _)| o.passed_fence()) {
        EXIT_NOT_FENCED
    } else if must.iter().any(|(o, may_skip)| !closed(*o, *may_skip)) {
        EXIT_INCONCLUSIVE
    } else {
        EXIT_FENCED
    };
    let mut residuals = Vec::new();
    if exit == EXIT_FENCED {
        if r.anonymous.passed_fence() {
            residuals.push(RESIDUAL_ANONYMOUS_EGRESS);
        }
        if r.anonymous_loopback.passed_fence() {
            residuals.push(RESIDUAL_ANONYMOUS_LOOPBACK);
        }
        if r.deny_only.passed_fence() {
            residuals.push(crate::wfp::RESIDUAL_DENY_ONLY);
        }
    }
    Verdict { exit, residuals }
}

/// An off-loopback destination on this machine for the anonymous
/// and the lowered-integrity attempts: the address the machine would
/// use as the source of an outbound connection, at `port`. Nothing needs to listen there —
/// refused is as good an answer as connected.
///
/// Found by connecting a UDP socket to a documentation address, which
/// selects a route and a source address without sending anything.
/// `None` when the machine has no route off loopback.
pub fn off_loopback_target(port: u16) -> Option<SocketAddr> {
    use std::net::UdpSocket;
    for (bind, toward) in [("0.0.0.0:0", "192.0.2.1:9"), ("[::]:0", "[2001:db8::1]:9")] {
        let Ok(s) = UdpSocket::bind(bind) else {
            continue;
        };
        if s.connect(toward).is_err() {
            continue;
        }
        if let Ok(local) = s.local_addr() {
            let ip = local.ip();
            if !ip.is_loopback() && !ip.is_unspecified() {
                return Some(SocketAddr::new(ip, port));
            }
        }
    }
    None
}

// ────────────────────── the attempts ──────────────────────

/// Reverts the thread to the process token on drop.
struct Reverted;
impl Drop for Reverted {
    fn drop(&mut self) {
        unsafe {
            let _ = RevertToSelf();
        }
    }
}

/// Which token the connect is made under.
#[derive(Debug, Clone, Copy)]
enum Identity {
    Own,
    Anonymous,
    DenyOnlyUser,
    /// A copy of the own token at this mandatory level.
    LoweredIntegrity(u32),
}

/// When the socket is created, relative to assuming the identity. See
/// the module doc.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SocketOrder {
    /// Create the socket, assume the identity, connect.
    BeforeToken,
    /// Assume the identity, create the socket, connect.
    AfterToken,
}

impl SocketOrder {
    const BOTH: [SocketOrder; 2] = [SocketOrder::BeforeToken, SocketOrder::AfterToken];

    /// The name used in the stderr line for this ordering.
    fn label(self) -> &'static str {
        match self {
            SocketOrder::BeforeToken => "socket before token",
            SocketOrder::AfterToken => "socket after token",
        }
    }
}

/// What the thread's token must read back as while an identity is
/// assumed.
#[derive(Debug, Clone, Copy)]
enum Expect {
    /// The anonymous token: its user is `ANONYMOUS LOGON`.
    Anonymous,
    /// The token object that was set on the thread, and the mandatory
    /// level it was given, if one was.
    Token { id: LUID, integrity: Option<u32> },
}

/// An identity in effect on this thread. Reverts on drop.
struct Assumed {
    expect: Expect,
    _reverted: Reverted,
}

/// Room for a token property struct and the SID it points to.
/// u64 elements: these structs hold pointers.
type TokenInfoBuf = [u64; 16];

/// Read a token property into `buf` and return a view of it. `T`
/// must be the struct `class` returns. A SID pointer inside the
/// result points into `buf`, which the borrow keeps in place.
unsafe fn token_info<'a, T>(
    token: HANDLE,
    class: windows::Win32::Security::TOKEN_INFORMATION_CLASS,
    what: &'static str,
    buf: &'a mut TokenInfoBuf,
) -> Result<&'a T> {
    let mut len = 0u32;
    unsafe {
        GetTokenInformation(
            token,
            class,
            Some(buf.as_mut_ptr() as *mut std::ffi::c_void),
            size_of_val(buf) as u32,
            &mut len,
        )
        .with_context(|| format!("GetTokenInformation({what})"))?;
        Ok(&*(buf.as_ptr() as *const T))
    }
}

/// The identity of a token object, which a thread keeps when the
/// token is set on it.
fn token_id(token: HANDLE) -> Result<LUID> {
    let mut buf = TokenInfoBuf::default();
    let stats = unsafe {
        token_info::<TOKEN_STATISTICS>(token, TokenStatistics, "TokenStatistics", &mut buf)?
    };
    Ok(stats.TokenId)
}

/// Check that the thread carries the token `expect` describes, at
/// impersonation level. Setting a thread token can succeed and still
/// leave the thread with less than was asked for, and a call made in
/// between can drop the impersonation; a connect made then would say
/// nothing about the token shape under test.
fn confirm_thread_token(expect: Expect) -> Result<()> {
    let mut tok = HANDLE::default();
    // open_as_self: checked against the process token, not the one
    // the thread carries. Fails when the thread carries none.
    unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &mut tok) }
        .context("OpenThreadToken (is the thread still impersonating?)")?;
    let tok = crate::util::OwnedHandle(tok);
    let mut buf = TokenInfoBuf::default();
    let stats = *unsafe {
        token_info::<TOKEN_STATISTICS>(tok.raw(), TokenStatistics, "TokenStatistics", &mut buf)?
    };
    if stats.ImpersonationLevel.0 < SecurityImpersonation.0 {
        return Err(anyhow!(
            "thread token is at impersonation level {}; wanted {} or above",
            stats.ImpersonationLevel.0,
            SecurityImpersonation.0
        ));
    }
    match expect {
        Expect::Anonymous => {
            let user = unsafe {
                let user = token_info::<TOKEN_USER>(tok.raw(), TokenUser, "TokenUser", &mut buf)?;
                crate::sid::psid_to_string(user.User.Sid)?
            };
            if user != ANONYMOUS_SID {
                return Err(anyhow!(
                    "thread token's user is {user}; wanted {ANONYMOUS_SID}"
                ));
            }
        }
        Expect::Token { id, integrity } => {
            let got = stats.TokenId;
            if (got.LowPart, got.HighPart) != (id.LowPart, id.HighPart) {
                return Err(anyhow!(
                    "thread token is not the one that was set on the thread"
                ));
            }
            if let Some(rid) = integrity {
                let got = unsafe {
                    let label = token_info::<TOKEN_MANDATORY_LABEL>(
                        tok.raw(),
                        TokenIntegrityLevel,
                        "TokenIntegrityLevel",
                        &mut buf,
                    )?;
                    crate::sid::psid_to_string(label.Label.Sid)?
                };
                let want = format!("S-1-16-{rid}");
                if got != want {
                    return Err(anyhow!("thread token is at integrity {got}; wanted {want}"));
                }
            }
        }
    }
    Ok(())
}

/// Context on the error of an impersonation call the kernel answered
/// with access-denied: the process may not carry that token. Found
/// again by [`connect_as`], which reports [`Outcome::Denied`] for it.
#[derive(Debug)]
struct ImpersonationRefused(&'static str);

impl std::fmt::Display for ImpersonationRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} refused by the kernel", self.0)
    }
}

/// The error of the call that puts a token on the thread, marked
/// [`ImpersonationRefused`] when it is access-denied. Only these
/// calls are marked: access-denied while BUILDING a token (opening,
/// copying, restricting, relabelling) is a step the probe could not
/// take, not the kernel's answer about the finished token.
fn impersonation_error(call: &'static str, e: windows::core::Error) -> anyhow::Error {
    let refused = e.code() == ERROR_ACCESS_DENIED.to_hresult();
    let e = anyhow::Error::new(e);
    if refused {
        e.context(ImpersonationRefused(call))
    } else {
        e.context(call)
    }
}

/// Put `imp` on the thread and confirm it took.
fn impersonate(imp: HANDLE, integrity: Option<u32>) -> Result<Assumed> {
    let id = token_id(imp)?;
    unsafe { SetThreadToken(None, Some(imp)) }
        .map_err(|e| impersonation_error("SetThreadToken", e))?;
    // From here the thread is impersonating: revert on every path,
    // including a failed confirmation.
    let assumed = Assumed {
        expect: Expect::Token { id, integrity },
        _reverted: Reverted,
    };
    confirm_thread_token(assumed.expect)?;
    Ok(assumed)
}

/// Assume `id` on the current thread. `None` for the process's own
/// token, which needs nothing.
fn assume(id: Identity) -> Result<Option<Assumed>> {
    match id {
        Identity::Own => Ok(None),
        Identity::Anonymous => {
            unsafe { ImpersonateAnonymousToken(GetCurrentThread()) }
                .map_err(|e| impersonation_error("ImpersonateAnonymousToken", e))?;
            let assumed = Assumed {
                expect: Expect::Anonymous,
                _reverted: Reverted,
            };
            confirm_thread_token(assumed.expect)?;
            Ok(Some(assumed))
        }
        Identity::DenyOnlyUser => {
            let user = crate::sid::LocalPsid::from_string(&crate::sid::current_user_sid()?)?;
            let mut own = HANDLE::default();
            let mut restricted = HANDLE::default();
            let mut imp = HANDLE::default();
            let r = (|| -> Result<Assumed> {
                unsafe {
                    OpenProcessToken(
                        GetCurrentProcess(),
                        TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY,
                        &mut own,
                    )
                    .context("OpenProcessToken")?;
                    // The user SID in the disable list becomes
                    // deny-only in the new token.
                    let disable = [SID_AND_ATTRIBUTES {
                        Sid: user.as_psid(),
                        Attributes: 0,
                    }];
                    CreateRestrictedToken(
                        own,
                        CREATE_RESTRICTED_TOKEN_FLAGS(0),
                        Some(&disable),
                        None,
                        None,
                        &mut restricted,
                    )
                    .context("CreateRestrictedToken")?;
                    DuplicateTokenEx(
                        restricted,
                        TOKEN_ALL_ACCESS,
                        None,
                        SecurityImpersonation,
                        TokenImpersonation,
                        &mut imp,
                    )
                    .context("DuplicateTokenEx")?;
                }
                impersonate(imp, None)
            })();
            unsafe {
                for h in [own, restricted, imp] {
                    if !h.is_invalid() {
                        let _ = CloseHandle(h);
                    }
                }
            }
            r.map(Some)
        }
        Identity::LoweredIntegrity(rid) => {
            let mut own = HANDLE::default();
            let mut imp = HANDLE::default();
            let r = (|| -> Result<Assumed> {
                unsafe {
                    OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &mut own)
                        .context("OpenProcessToken")?;
                    DuplicateTokenEx(
                        own,
                        TOKEN_ALL_ACCESS,
                        None,
                        SecurityImpersonation,
                        TokenImpersonation,
                        &mut imp,
                    )
                    .context("DuplicateTokenEx")?;
                }
                // Lowering a token's integrity level takes no
                // privilege.
                crate::token::set_il(imp, rid)?;
                impersonate(imp, Some(rid))
            })();
            unsafe {
                for h in [own, imp] {
                    if !h.is_invalid() {
                        let _ = CloseHandle(h);
                    }
                }
            }
            r.map(Some)
        }
    }
}

struct Sock(SOCKET);
impl Drop for Sock {
    fn drop(&mut self) {
        unsafe {
            let _ = closesocket(self.0);
        }
    }
}

/// Map a Winsock connect error to an outcome. `WSAEACCES` is matched
/// on the raw code: it is what a BLOCK filter at the connect layer
/// produces, and nothing else in this path does.
fn classify_error(code: i32) -> Outcome {
    if code == WSAEACCES.0 {
        Outcome::Blocked
    } else if code == WSAECONNREFUSED.0 {
        Outcome::Refused
    } else {
        Outcome::Unreachable
    }
}

/// Non-blocking connect on an existing socket, waited for up to
/// [`CONNECT_TIMEOUT_SECS`]. Returns the outcome and the Winsock
/// error code behind it (0 for a completed connect).
fn connect_bounded(sock: &Sock, addr: &SocketAddr) -> (Outcome, i32) {
    let rc = unsafe {
        match addr {
            SocketAddr::V4(a) => {
                let sa = SOCKADDR_IN {
                    sin_family: AF_INET,
                    sin_port: a.port().to_be(),
                    sin_addr: IN_ADDR {
                        S_un: IN_ADDR_0 {
                            S_addr: u32::from_ne_bytes(a.ip().octets()),
                        },
                    },
                    sin_zero: [0; 8],
                };
                connect(
                    sock.0,
                    &sa as *const SOCKADDR_IN as *const SOCKADDR,
                    size_of::<SOCKADDR_IN>() as i32,
                )
            }
            SocketAddr::V6(a) => {
                let sa = SOCKADDR_IN6 {
                    sin6_family: AF_INET6,
                    sin6_port: a.port().to_be(),
                    sin6_flowinfo: a.flowinfo(),
                    sin6_addr: IN6_ADDR {
                        u: IN6_ADDR_0 {
                            Byte: a.ip().octets(),
                        },
                    },
                    Anonymous: SOCKADDR_IN6_0 {
                        sin6_scope_id: a.scope_id(),
                    },
                };
                connect(
                    sock.0,
                    &sa as *const SOCKADDR_IN6 as *const SOCKADDR,
                    size_of::<SOCKADDR_IN6>() as i32,
                )
            }
        }
    };
    if rc != SOCKET_ERROR {
        return (Outcome::Connected, 0);
    }
    let err = unsafe { WSAGetLastError() };
    if err != WSAEWOULDBLOCK {
        return (classify_error(err.0), err.0);
    }
    // In progress: writable = connected, exceptional = failed.
    let mut fds = [sock.0; 64];
    fds[0] = sock.0;
    let mut writable = FD_SET {
        fd_count: 1,
        fd_array: fds,
    };
    let mut failed = FD_SET {
        fd_count: 1,
        fd_array: fds,
    };
    let tv = TIMEVAL {
        tv_sec: CONNECT_TIMEOUT_SECS,
        tv_usec: 0,
    };
    let n = unsafe { select(0, None, Some(&mut writable), Some(&mut failed), Some(&tv)) };
    if n <= 0 {
        // 0 = timed out, SOCKET_ERROR = select itself failed.
        return (Outcome::Unreachable, 0);
    }
    let mut so_error: i32 = 0;
    let mut len = size_of::<i32>() as i32;
    let rc = unsafe {
        getsockopt(
            sock.0,
            SOL_SOCKET,
            SO_ERROR,
            windows::core::PSTR(&mut so_error as *mut i32 as *mut u8),
            &mut len,
        )
    };
    if rc == SOCKET_ERROR {
        return (Outcome::Unreachable, unsafe { WSAGetLastError() }.0);
    }
    if so_error == 0 {
        (Outcome::Connected, 0)
    } else {
        (classify_error(so_error), so_error)
    }
}

/// A non-blocking TCP socket for `target`'s address family, created
/// under whatever token the calling thread carries.
fn new_socket(target: &SocketAddr) -> Result<Sock> {
    let af = match target {
        SocketAddr::V4(_) => AF_INET,
        SocketAddr::V6(_) => AF_INET6,
    };
    let sock = Sock(
        unsafe { socket(af.0 as i32, SOCK_STREAM, IPPROTO_TCP.0) }
            .map_err(|e| anyhow!("socket: {e}"))?,
    );
    let mut nonblocking: u32 = 1;
    if unsafe { ioctlsocket(sock.0, FIONBIO, &mut nonblocking) } == SOCKET_ERROR {
        return Err(anyhow!("ioctlsocket(FIONBIO): {:?}", unsafe {
            WSAGetLastError()
        }));
    }
    Ok(sock)
}

/// One connect under `id`, with the socket created before or after
/// the identity is assumed. Everything runs on the calling thread,
/// which is the one that holds the assumed token. Returns the outcome
/// and what is behind it.
fn connect_as(id: Identity, target: &SocketAddr, order: SocketOrder) -> (Outcome, String) {
    let error = |what: &str, e: anyhow::Error| (Outcome::Error, format!("{what}: {e:#}"));
    let not_assumed = |e: anyhow::Error| {
        let outcome = if e.downcast_ref::<ImpersonationRefused>().is_some() {
            Outcome::Denied
        } else {
            Outcome::Error
        };
        (outcome, format!("assuming the token: {e:#}"))
    };
    let (sock, assumed) = match order {
        SocketOrder::BeforeToken => {
            let sock = match new_socket(target) {
                Ok(s) => s,
                Err(e) => return error("socket under the process token", e),
            };
            match assume(id) {
                Ok(a) => (sock, a),
                Err(e) => return not_assumed(e),
            }
        }
        SocketOrder::AfterToken => {
            let assumed = match assume(id) {
                Ok(a) => a,
                Err(e) => return not_assumed(e),
            };
            match new_socket(target) {
                Ok(s) => (s, assumed),
                Err(e) => return error("socket under the assumed token", e),
            }
        }
    };
    // The socket exists and the identity is assumed: the token must
    // still be the one asked for, or the connect measures nothing.
    if let Some(a) = &assumed
        && let Err(e) = confirm_thread_token(a.expect)
    {
        return error("token not in effect before the connect", e);
    }
    let (o, code) = connect_bounded(&sock, target);
    // Close the socket, then revert.
    drop(sock);
    drop(assumed);
    (o, format!("winsock error {code}"))
}

/// One attempt. Under the process's own token that is one connect;
/// under an assumed identity it is one per [`SocketOrder`], each
/// logged, and the result is the worse of the two for the fence.
fn attempt(name: &str, id: Identity, target: &SocketAddr) -> Outcome {
    // stderr, never stdout: the runner's stdout is the broker's, and
    // the broker prints its own JSON there.
    if matches!(id, Identity::Own) {
        let (outcome, detail) = connect_as(id, target, SocketOrder::BeforeToken);
        eprintln!(
            "srt-win: runner: egress probe [{name}] {target}: {} ({detail})",
            outcome.label().to_uppercase(),
        );
        return outcome;
    }
    let mut worst = Outcome::Blocked;
    for order in SocketOrder::BOTH {
        let (outcome, detail) = connect_as(id, target, order);
        eprintln!(
            "srt-win: runner: egress probe [{name}; {}] {target}: {} ({detail})",
            order.label(),
            outcome.label().to_uppercase(),
        );
        worst = worst.worse(outcome);
    }
    eprintln!(
        "srt-win: runner: egress probe [{name}] {target}: {} (the worse of both orderings)",
        worst.label().to_uppercase(),
    );
    worst
}

fn winsock_startup() -> Result<()> {
    let mut wsa = WSADATA::default();
    let rc = unsafe { WSAStartup(0x0202, &mut wsa) };
    if rc != 0 {
        return Err(anyhow!("WSAStartup: {rc}"));
    }
    Ok(())
}

/// `srt-win probe connect`: one connect to `target` (`ip:port`) under
/// the process's own token, as an exit code — **0** = refused by the
/// fence (`WSAEACCES`), **3** = connected, **2** = anything else
/// (refused by the destination, timed out, unreachable). One line of
/// diagnostics goes to stderr; stdout is left alone.
pub fn connect_once(target: &str) -> Result<u32> {
    let target: SocketAddr = target
        .parse()
        .with_context(|| format!("egress probe target '{target}'"))?;
    winsock_startup()?;
    Ok(match attempt("plain", Identity::Own, &target) {
        Outcome::Blocked => 0,
        Outcome::Connected => 3,
        _ => 2,
    })
}

/// Run every attempt. `target` is the loopback probe target;
/// `anonymous_target` the off-loopback one (`None` skips the attempts
/// aimed at it).
pub fn run(target: &str, anonymous_target: Option<&str>) -> Result<Report> {
    let parse = |s: &str| -> Result<SocketAddr> {
        s.parse()
            .with_context(|| format!("runner: ProbeEgress target '{s}'"))
    };
    let target = parse(target)?;
    let anonymous_target = anonymous_target.map(parse).transpose()?;
    winsock_startup()?;
    let off_loopback = |name: &str, id: Identity| match &anonymous_target {
        Some(t) => attempt(name, id, t),
        None => {
            eprintln!(
                "srt-win: runner: egress probe [{name}]: SKIPPED \
                 (no off-loopback target)"
            );
            Outcome::Skipped
        }
    };
    let low = Identity::LoweredIntegrity(IL_LOW);
    let untrusted = Identity::LoweredIntegrity(IL_UNTRUSTED);
    Ok(Report {
        plain: attempt("plain", Identity::Own, &target),
        anonymous: off_loopback("anonymous", Identity::Anonymous),
        anonymous_loopback: attempt("anonymous, loopback", Identity::Anonymous, &target),
        deny_only: attempt("deny-only user SID", Identity::DenyOnlyUser, &target),
        low_integrity: off_loopback("low integrity", low),
        low_integrity_loopback: attempt("low integrity, loopback", low, &target),
        untrusted_integrity: off_loopback("untrusted integrity", untrusted),
        untrusted_integrity_loopback: attempt("untrusted integrity, loopback", untrusted, &target),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The four lowered-integrity attempts blocked, the rest as
    /// given.
    fn report(p: Outcome, a: Outcome, al: Outcome, d: Outcome) -> Report {
        lowered(
            Report {
                plain: p,
                anonymous: a,
                anonymous_loopback: al,
                deny_only: d,
                low_integrity: Outcome::Blocked,
                low_integrity_loopback: Outcome::Blocked,
                untrusted_integrity: Outcome::Blocked,
                untrusted_integrity_loopback: Outcome::Blocked,
            },
            [Outcome::Blocked; 4],
        )
    }

    /// `r` with the four lowered-integrity attempts replaced, in
    /// field order.
    fn lowered(r: Report, l: [Outcome; 4]) -> Report {
        Report {
            low_integrity: l[0],
            low_integrity_loopback: l[1],
            untrusted_integrity: l[2],
            untrusted_integrity_loopback: l[3],
            ..r
        }
    }

    #[test]
    fn report_round_trips_every_combination() {
        for p in Outcome::ALL {
            for a in Outcome::ALL {
                for al in Outcome::ALL {
                    for d in Outcome::ALL {
                        // The other four fields take the same values
                        // in a different order, so every field sees
                        // every outcome beside differing neighbours.
                        let r = lowered(report(p, a, al, d), [d, al, a, p]);
                        assert_eq!(Report::decode(r.encode()), Some(r));
                    }
                }
            }
        }
    }

    #[test]
    fn unrelated_exit_codes_do_not_decode() {
        // 0 and 1 are the runner's ordinary exits; 2 and 3 were the
        // whole contract of an earlier single-attempt probe.
        for code in [
            0,
            1,
            2,
            3,
            15,
            255,
            0x0FFF,
            0x1000,
            0x2000,
            REPORT_BASE,
            REPORT_BASE - 1,
            REPORT_BASE << 1,
            0xC000_0005,
        ] {
            assert_eq!(Report::decode(code), None, "{code:#x}");
        }
        // In range, but a field holds no outcome: zero is not one.
        assert_eq!(Report::decode(REPORT_BASE | 1), None);
        assert_eq!(
            Report::decode((REPORT_BASE | (REPORT_BASE - 1)) & !MASK),
            None
        );
    }

    #[test]
    fn every_outcome_fits_a_field() {
        for o in Outcome::ALL {
            assert!(o as u32 >= 1 && o as u32 <= MASK, "{o:?}");
            assert_eq!(Outcome::from_bits(o as u32), Some(o));
        }
        // The largest outcome in every field is still a report, and
        // still below the bit that marks one.
        let all = [Denied; FIELDS as usize];
        let r = lowered(
            report(all[0], all[1], all[2], all[3]),
            [all[4], all[5], all[6], all[7]],
        );
        assert_eq!(Denied as u32, MASK);
        assert_eq!(r.encode(), REPORT_BASE | (REPORT_BASE - 1));
        assert_eq!(Report::decode(r.encode()), Some(r));
    }

    #[test]
    fn impersonation_error_marks_only_access_denied() {
        use windows::Win32::Foundation::ERROR_INVALID_HANDLE;
        let denied = impersonation_error(
            "SetThreadToken",
            windows::core::Error::from(ERROR_ACCESS_DENIED),
        );
        assert!(denied.downcast_ref::<ImpersonationRefused>().is_some());
        // The mark survives context added on the way up.
        let wrapped = denied.context("assuming the token");
        assert!(wrapped.downcast_ref::<ImpersonationRefused>().is_some());
        let other = impersonation_error(
            "SetThreadToken",
            windows::core::Error::from(ERROR_INVALID_HANDLE),
        );
        assert!(other.downcast_ref::<ImpersonationRefused>().is_none());
    }

    #[test]
    fn classify_error_codes() {
        assert_eq!(classify_error(10013), Outcome::Blocked);
        assert_eq!(classify_error(10061), Outcome::Refused);
        // ERROR_ACCESS_DENIED is not a filter refusal.
        assert_eq!(classify_error(5), Outcome::Unreachable);
        assert_eq!(classify_error(10060), Outcome::Unreachable);
    }

    use Outcome::*;

    /// The verdict when the bare runner probed (the ordinary token).
    fn verdict_runner(r: &Report) -> Verdict {
        verdict(r, false)
    }

    #[test]
    fn verdict_denied_is_closed_only_for_the_child_token() {
        let all_blocked = report(Blocked, Blocked, Blocked, Blocked);
        // Each attempt the fence must refuse, refused by the kernel
        // instead: closed when the child's own token was probed,
        // inconclusive when the runner stood in for it.
        // (The anonymous attempts are not among them: refused or
        // not, they never decide the exit.)
        let mut cases = vec![report(Denied, Blocked, Blocked, Blocked)];
        for field in 0..4 {
            let mut l = [Blocked; 4];
            l[field] = Denied;
            cases.push(lowered(all_blocked, l));
        }
        for r in &cases {
            let v = verdict(r, true);
            assert_eq!(v.exit, EXIT_FENCED, "{r:?}");
            assert!(v.residuals.is_empty());
            assert_eq!(verdict(r, false).exit, EXIT_INCONCLUSIVE, "{r:?}");
        }
        // Refused everywhere it can be: still fenced, no residual —
        // a token that cannot be assumed leaves nothing open.
        let r = lowered(report(Blocked, Denied, Denied, Denied), [Denied; 4]);
        assert_eq!(
            verdict(&r, true),
            Verdict {
                exit: EXIT_FENCED,
                residuals: vec![]
            }
        );
        // A refusal elsewhere does not excuse a leak or an unmeasured
        // attempt, and the other outcomes mean what they meant.
        for child_token in [true, false] {
            let leak = lowered(
                report(Blocked, Denied, Blocked, Blocked),
                [Connected, Blocked, Blocked, Blocked],
            );
            assert_eq!(verdict(&leak, child_token).exit, EXIT_NOT_FENCED);
            let odd = lowered(
                report(Blocked, Denied, Denied, Denied),
                [Error, Blocked, Blocked, Blocked],
            );
            assert_eq!(verdict(&odd, child_token).exit, EXIT_INCONCLUSIVE);
            // A residual is still named beside a refusal.
            let v = verdict(&report(Blocked, Blocked, Denied, Connected), child_token);
            assert_eq!(v.exit, EXIT_FENCED);
            assert_eq!(v.residuals, [crate::wfp::RESIDUAL_DENY_ONLY]);
        }
    }

    #[test]
    fn worse_ranks_outcomes_for_the_fence() {
        // Worst first. Each one beats everything after it, whichever
        // side it is on.
        let ranked = [
            Connected,
            Refused,
            Error,
            Unreachable,
            Skipped,
            Denied,
            Blocked,
        ];
        assert_eq!(ranked.len(), Outcome::ALL.len());
        for (i, a) in ranked.iter().enumerate() {
            assert_eq!(a.worse(*a), *a);
            for b in &ranked[i + 1..] {
                assert_eq!(a.worse(*b), *a, "{a:?} vs {b:?}");
                assert_eq!(b.worse(*a), *a, "{b:?} vs {a:?}");
            }
        }
    }

    #[test]
    fn worse_of_two_orderings() {
        // One ordering getting through is the attempt getting through.
        assert!(Blocked.worse(Connected).passed_fence());
        assert!(Refused.worse(Blocked).passed_fence());
        // A block in one ordering does not stand in for an ordering
        // that was not measured.
        assert_eq!(Blocked.worse(Error), Error);
        assert_eq!(Unreachable.worse(Blocked), Unreachable);
        // Blocked only when both were.
        assert_eq!(Blocked.worse(Blocked), Blocked);
        // A leak is not hidden by the other ordering failing.
        assert_eq!(Error.worse(Connected), Connected);
        // A refused token in one ordering does not make the attempt
        // blocked, and does not hide an unmeasured or leaking one.
        assert_eq!(Blocked.worse(Denied), Denied);
        assert_eq!(Denied.worse(Error), Error);
        assert_eq!(Denied.worse(Refused), Refused);
        assert!(!Denied.passed_fence());
    }

    #[test]
    fn socket_orders_are_named_apart() {
        assert_eq!(SocketOrder::BOTH.len(), 2);
        assert_ne!(
            SocketOrder::BeforeToken.label(),
            SocketOrder::AfterToken.label()
        );
    }

    #[test]
    fn verdict_fenced_without_residuals() {
        let v = verdict_runner(&report(Blocked, Blocked, Blocked, Blocked));
        assert_eq!(v.exit, EXIT_FENCED);
        assert!(v.residuals.is_empty());
    }

    #[test]
    fn verdict_names_each_residual() {
        let v = verdict_runner(&report(Blocked, Blocked, Connected, Connected));
        assert_eq!(v.exit, EXIT_FENCED);
        assert_eq!(
            v.residuals,
            [RESIDUAL_ANONYMOUS_LOOPBACK, crate::wfp::RESIDUAL_DENY_ONLY]
        );
        let v = verdict_runner(&report(Blocked, Connected, Connected, Connected));
        assert_eq!(v.exit, EXIT_FENCED);
        assert_eq!(
            v.residuals,
            [
                RESIDUAL_ANONYMOUS_EGRESS,
                RESIDUAL_ANONYMOUS_LOOPBACK,
                crate::wfp::RESIDUAL_DENY_ONLY
            ]
        );
        let v = verdict_runner(&report(Blocked, Blocked, Blocked, Refused));
        assert_eq!(v.residuals, [crate::wfp::RESIDUAL_DENY_ONLY]);
        // An attempt that could not be made is not a residual.
        let v = verdict_runner(&report(Blocked, Blocked, Error, Unreachable));
        assert_eq!(v.exit, EXIT_FENCED);
        assert!(v.residuals.is_empty());
    }

    #[test]
    fn verdict_plain_getting_out_is_not_fenced() {
        for through in [Connected, Refused] {
            let v = verdict_runner(&report(through, Blocked, Blocked, Blocked));
            assert_eq!(v.exit, EXIT_NOT_FENCED);
            // Residuals qualify a pass; a failure reports none.
            let v = verdict_runner(&report(through, Connected, Connected, Connected));
            assert_eq!(v.exit, EXIT_NOT_FENCED);
            assert!(v.residuals.is_empty());
        }
    }

    /// The off-loopback connect under the anonymous token is expected
    /// to get through. Whatever it does, it is never a probe failure.
    #[test]
    fn verdict_anonymous_egress_is_a_residual_never_a_failure() {
        // Under both child tokens alike.
        for child_token in [false, true] {
            for through in [Connected, Refused] {
                let v = verdict(&report(Blocked, through, Blocked, Blocked), child_token);
                assert_eq!(v.exit, EXIT_FENCED);
                assert_eq!(v.residuals, [RESIDUAL_ANONYMOUS_EGRESS]);
            }
            for other in [Blocked, Unreachable, Error, Skipped, Denied] {
                let v = verdict(&report(Blocked, other, Blocked, Blocked), child_token);
                assert_eq!(v.exit, EXIT_FENCED, "{other:?}");
                assert!(v.residuals.is_empty(), "{other:?}");
            }
        }
    }

    #[test]
    fn verdict_lowered_integrity_getting_out_is_not_fenced() {
        let all_blocked = report(Blocked, Blocked, Blocked, Blocked);
        for field in 0..4 {
            for through in [Connected, Refused] {
                let mut l = [Blocked; 4];
                l[field] = through;
                let v = verdict_runner(&lowered(all_blocked, l));
                assert_eq!(v.exit, EXIT_NOT_FENCED, "field {field} {through:?}");
                assert!(v.residuals.is_empty());
            }
        }
    }

    #[test]
    fn verdict_lowered_integrity_not_assumed_is_inconclusive() {
        let all_blocked = report(Blocked, Blocked, Blocked, Blocked);
        for field in 0..4 {
            // A token that could not be assumed is not a block.
            for odd in [Error, Unreachable] {
                let mut l = [Blocked; 4];
                l[field] = odd;
                assert_eq!(
                    verdict_runner(&lowered(all_blocked, l)).exit,
                    EXIT_INCONCLUSIVE,
                    "field {field} {odd:?}"
                );
            }
        }
        // Only the attempts at the off-loopback target can be skipped.
        let v = verdict_runner(&lowered(all_blocked, [Skipped, Blocked, Skipped, Blocked]));
        assert_eq!(v.exit, EXIT_FENCED);
        for loopback in [1, 3] {
            let mut l = [Blocked; 4];
            l[loopback] = Skipped;
            assert_eq!(
                verdict_runner(&lowered(all_blocked, l)).exit,
                EXIT_INCONCLUSIVE
            );
        }
    }

    #[test]
    fn verdict_inconclusive_and_skipped() {
        for odd in [Unreachable, Error, Skipped] {
            assert_eq!(
                verdict_runner(&report(odd, Blocked, Blocked, Blocked)).exit,
                EXIT_INCONCLUSIVE
            );
        }
    }
}
