//! The behavioural fence probe behind `srt-win wfp verify`: the runner
//! (a process of the sandbox account) makes TCP connects under each
//! token shape a sandboxed process can present to the filtering
//! engine, and returns the results in its exit code
//! ([`Report::encode`]) — its stdout is the broker's.
//!
//! A connect is attributed to the token in effect when its SOCKET was
//! created, so every attempt under an assumed identity runs twice
//! ([`SocketOrder`]) and reports the worse result. The thread's token
//! is read back before each connect: one that is not the token asked
//! for is an `error`, never a `blocked`.

use anyhow::{Context, Result, anyhow};
use std::net::SocketAddr;

use windows::Win32::Foundation::{CloseHandle, HANDLE, LUID};
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

/// Residual: an off-loopback connect made while impersonating the
/// anonymous token was not blocked. Expected on any machine with an
/// off-loopback address: no filter is keyed on that token.
pub const RESIDUAL_ANONYMOUS_EGRESS: &str = "anonymous-egress";

pub const RESIDUAL_ANONYMOUS_LOOPBACK: &str = "anonymous-loopback";

/// Residual: a connect under a copy of the sandbox token whose user SID
/// is deny-only was not blocked.
pub const RESIDUAL_DENY_ONLY: &str = "deny-only-user-sid";

/// Residual: a lowered-integrity attempt could not be set up (the token
/// could not be assumed, or no socket made under it), so no connect
/// under that shape was observed.
pub const RESIDUAL_LOWERED_INTEGRITY_UNPROBED: &str = "lowered-integrity-unprobed";

/// Residual: loopback is open and this machine has no off-loopback
/// address, so no attempt the filters must refuse could be made.
pub const RESIDUAL_EGRESS_UNPROBED: &str = "egress-unprobed";

const ANONYMOUS_SID: &str = "S-1-5-7";

const IL_LOW: u32 = 0x1000;
const IL_UNTRUSTED: u32 = 0;

/// Bound on one connect. It only matters for a destination that does
/// not answer: a refused or filtered connect returns at once.
const CONNECT_TIMEOUT_SECS: i32 = 4;

/// Result of one connect attempt. None is numbered zero, so an exit
/// code whose field bits are all clear is not a report of "everything
/// blocked".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// `WSAEACCES` — a BLOCK filter refused the connect.
    Blocked = 1,
    Connected = 2,
    /// `WSAECONNREFUSED` — the destination answered, so the connect
    /// got past the filters: for the fence, the same as `Connected`.
    Refused = 3,
    Unreachable = 4,
    Skipped = 5,
    /// No connect was made under the token shape: it could not be
    /// assumed, no socket could be created under it, or the thread's
    /// token did not read back as the one assumed.
    Error = 6,
}

impl Outcome {
    const ALL: [Outcome; 6] = [
        Outcome::Blocked,
        Outcome::Connected,
        Outcome::Refused,
        Outcome::Unreachable,
        Outcome::Skipped,
        Outcome::Error,
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
        }
    }

    pub fn passed_fence(self) -> bool {
        matches!(self, Outcome::Connected | Outcome::Refused)
    }

    /// Higher is worse for the fence. The outcomes that learned nothing
    /// rank above `Blocked`, so a block in one ordering cannot stand in
    /// for an ordering that was never measured.
    fn severity(self) -> u8 {
        match self {
            Outcome::Blocked => 0,
            Outcome::Skipped => 1,
            Outcome::Unreachable => 2,
            Outcome::Error => 3,
            Outcome::Refused => 4,
            Outcome::Connected => 5,
        }
    }

    pub fn worse(self, other: Self) -> Self {
        if other.severity() > self.severity() {
            other
        } else {
            self
        }
    }
}

/// One result per attempt. `anonymous`, `low_integrity` and
/// `untrusted_integrity` are aimed at the off-loopback target, the
/// rest at the loopback one; [`run`] says what changes with loopback open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Report {
    pub plain: Outcome,
    pub anonymous: Outcome,
    pub anonymous_loopback: Outcome,
    pub deny_only: Outcome,
    pub low_integrity: Outcome,
    pub low_integrity_loopback: Outcome,
    pub untrusted_integrity: Outcome,
    pub untrusted_integrity_loopback: Outcome,
    /// Own token, to the loopback target. Attempted exactly when
    /// loopback is open, where it must connect; else `Skipped`.
    pub open_loopback: Outcome,
}

const BITS: u32 = 3;
const MASK: u32 = (1 << BITS) - 1;
const FIELDS: u32 = 9;
/// Marks a runner exit code as an encoded [`Report`]: the bit just
/// above the fields, so the runner's other exits (0, and 1 for its own
/// error path) never decode.
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
            self.open_loopback,
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
            open_loopback: field(8)?,
        })
    }

    /// The report when the plain attempt already showed the fence is not
    /// blocking: the verdict is settled, so nothing else was attempted.
    fn unfenced_at_plain(plain: Outcome) -> Self {
        Self {
            plain,
            anonymous: Outcome::Skipped,
            anonymous_loopback: Outcome::Skipped,
            deny_only: Outcome::Skipped,
            low_integrity: Outcome::Skipped,
            low_integrity_loopback: Outcome::Skipped,
            untrusted_integrity: Outcome::Skipped,
            untrusted_integrity_loopback: Outcome::Skipped,
            open_loopback: Outcome::Skipped,
        }
    }

    /// The lowered-integrity attempts, which the filters must refuse like
    /// the plain one, each with whether it may have been skipped (a
    /// machine can lack an off-loopback target).
    fn lowered(&self) -> [(Outcome, bool); 4] {
        [
            (self.low_integrity, true),
            (self.low_integrity_loopback, false),
            (self.untrusted_integrity, true),
            (self.untrusted_integrity_loopback, false),
        ]
    }
}

pub const EXIT_FENCED: i32 = 0;
pub const EXIT_INCONCLUSIVE: i32 = 2;
pub const EXIT_NOT_FENCED: i32 = 3;
/// `wfp verify` / `exec` exit code: the installed loopback mode is not
/// the one this session asks for.
pub const EXIT_LOOPBACK_MISMATCH: i32 = 19;

#[derive(Debug, PartialEq, Eq)]
pub struct Verdict {
    pub exit: i32,
    /// Gaps the filters do not close; only set with [`EXIT_FENCED`].
    pub residuals: Vec<&'static str>,
}

/// The plain attempt must be blocked and no lowered-integrity one may pass;
/// one not set up (`Error`) is a residual, as the rest are when they connect.
/// With loopback open, `open_loopback` must connect ([`EXIT_LOOPBACK_MISMATCH`]).
pub fn verdict(r: &Report) -> Verdict {
    let lowered = r.lowered();
    // With loopback open every attempt the filters must refuse goes off
    // loopback, and a machine with no such address skips them all.
    let open = r.open_loopback != Outcome::Skipped;
    let exit = if r.plain.passed_fence() || lowered.iter().any(|(o, _)| o.passed_fence()) {
        EXIT_NOT_FENCED
    } else if !(r.plain == Outcome::Blocked || (open && r.plain == Outcome::Skipped))
        || lowered.iter().any(|(o, may_skip)| {
            !(matches!(o, Outcome::Blocked | Outcome::Error)
                || ((*may_skip || open) && *o == Outcome::Skipped))
        })
    {
        EXIT_INCONCLUSIVE
    } else {
        match r.open_loopback {
            Outcome::Connected | Outcome::Skipped => EXIT_FENCED,
            Outcome::Blocked => EXIT_LOOPBACK_MISMATCH,
            _ => EXIT_INCONCLUSIVE,
        }
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
            residuals.push(RESIDUAL_DENY_ONLY);
        }
        if lowered.iter().any(|(o, _)| *o == Outcome::Error) {
            residuals.push(RESIDUAL_LOWERED_INTEGRITY_UNPROBED);
        }
        if open && r.plain == Outcome::Skipped {
            residuals.push(RESIDUAL_EGRESS_UNPROBED);
        }
    }
    Verdict { exit, residuals }
}

/// This machine's outbound source address, at `port` (found with a
/// connected UDP socket, which sends nothing). Nothing needs to
/// listen there: refused is as good an answer as connected.
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

#[derive(Debug, Clone, Copy)]
enum Identity {
    Own,
    Anonymous,
    DenyOnlyUser,
    LoweredIntegrity(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SocketOrder {
    BeforeToken,
    AfterToken,
}

impl SocketOrder {
    const BOTH: [SocketOrder; 2] = [SocketOrder::BeforeToken, SocketOrder::AfterToken];

    fn label(self) -> &'static str {
        match self {
            SocketOrder::BeforeToken => "socket before token",
            SocketOrder::AfterToken => "socket after token",
        }
    }
}

/// What the thread's token must read back as under an identity.
#[derive(Debug, Clone, Copy)]
enum Expect {
    /// The anonymous token: its user is `ANONYMOUS LOGON`.
    Anonymous,
    /// The token object set on the thread, and the mandatory level it
    /// was given, if any.
    Token { id: LUID, integrity: Option<u32> },
}

/// An identity in effect on this thread; reverts on drop.
struct Assumed {
    expect: Expect,
}
impl Drop for Assumed {
    fn drop(&mut self) {
        if let Err(e) = unsafe { RevertToSelf() } {
            REVERT_FAILURE.with(|f| f.set(Some(e.code().0)));
        }
    }
}

thread_local! {
    /// The HRESULT of a `RevertToSelf` that failed on this thread.
    static REVERT_FAILURE: std::cell::Cell<Option<i32>> = const { std::cell::Cell::new(None) };
}

/// `Err` once a `RevertToSelf` has failed on this thread: a later
/// attempt would be made under the leftover token, so the run must end.
fn ensure_reverted() -> Result<()> {
    match REVERT_FAILURE.with(|f| f.get()) {
        Some(hr) => Err(anyhow!(
            "RevertToSelf failed ({hr:#010x}) after an assumed-identity attempt; \
             the probe cannot continue under a leftover token"
        )),
        None => Ok(()),
    }
}

/// Room for a token property struct and the SID it points to; u64
/// elements because the structs hold pointers.
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

/// A token object's identity; a thread keeps it when the token is set.
fn token_id(token: HANDLE) -> Result<LUID> {
    let mut buf = TokenInfoBuf::default();
    let stats = unsafe {
        token_info::<TOKEN_STATISTICS>(token, TokenStatistics, "TokenStatistics", &mut buf)?
    };
    Ok(stats.TokenId)
}

/// Check that the thread carries the token `expect` describes, at
/// impersonation level: setting a thread token can succeed and still
/// leave the thread with less than was asked for.
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

fn impersonate(imp: HANDLE, integrity: Option<u32>) -> Result<Assumed> {
    let id = token_id(imp)?;
    unsafe { SetThreadToken(None, Some(imp)) }.context("SetThreadToken")?;
    // From here the thread is impersonating: revert on every path,
    // including a failed confirmation.
    let assumed = Assumed {
        expect: Expect::Token { id, integrity },
    };
    confirm_thread_token(assumed.expect)?;
    Ok(assumed)
}

/// Assume `id` on the current thread; `None` for the process token.
fn assume(id: Identity) -> Result<Option<Assumed>> {
    match id {
        Identity::Own => Ok(None),
        Identity::Anonymous => {
            unsafe { ImpersonateAnonymousToken(GetCurrentThread()) }
                .context("ImpersonateAnonymousToken")?;
            let assumed = Assumed {
                expect: Expect::Anonymous,
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
                    // A SID in the disable list becomes deny-only.
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

/// Non-blocking connect, waited for up to [`CONNECT_TIMEOUT_SECS`].
/// Returns the outcome and the Winsock error behind it (0 if none).
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
    let fds = [sock.0; 64];
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

/// A non-blocking TCP socket, created under the thread's current token.
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

/// One connect under `id`; returns the outcome and what is behind it.
fn connect_as(id: Identity, target: &SocketAddr, order: SocketOrder) -> (Outcome, String) {
    let error = |what: &str, e: anyhow::Error| (Outcome::Error, format!("{what}: {e:#}"));
    let (sock, assumed) = match order {
        SocketOrder::BeforeToken => {
            let sock = match new_socket(target) {
                Ok(s) => s,
                Err(e) => return error("socket under the process token", e),
            };
            match assume(id) {
                Ok(a) => (sock, a),
                Err(e) => return error("assuming the token", e),
            }
        }
        SocketOrder::AfterToken => {
            let assumed = match assume(id) {
                Ok(a) => a,
                Err(e) => return error("assuming the token", e),
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

fn attempt(name: &str, id: Identity, target: &SocketAddr) -> Result<Outcome> {
    // stderr, never stdout: the runner's stdout is the broker's, and
    // the broker prints its own JSON there.
    if matches!(id, Identity::Own) {
        let (outcome, detail) = connect_as(id, target, SocketOrder::BeforeToken);
        eprintln!(
            "srt-win: runner: egress probe [{name}] {target}: {} ({detail})",
            outcome.label().to_uppercase(),
        );
        return Ok(outcome);
    }
    let mut worst = Outcome::Blocked;
    for order in SocketOrder::BOTH {
        let (outcome, detail) = connect_as(id, target, order);
        ensure_reverted()?;
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
    Ok(worst)
}

/// Run the attempts; with no `anonymous_target` the off-loopback ones
/// skip. The anonymous off-loopback one, which no filter refuses and
/// which can wait on its destination, runs only with `anonymous_egress`.
///
/// With `allow_loopback` nothing aimed at loopback is refused, so the
/// plain and deny-only attempts go to `anonymous_target` instead, the
/// other loopback ones skip, and `open_loopback` connects to `target`.
pub fn run(
    target: &str,
    anonymous_target: Option<&str>,
    anonymous_egress: bool,
    allow_loopback: bool,
) -> Result<Report> {
    let parse = |s: &str| -> Result<SocketAddr> {
        s.parse()
            .with_context(|| format!("runner: ProbeEgress target '{s}'"))
    };
    let target = parse(target)?;
    let anonymous_target = anonymous_target.map(parse).transpose()?;
    let mut wsa = WSADATA::default();
    let rc = unsafe { WSAStartup(0x0202, &mut wsa) };
    if rc != 0 {
        return Err(anyhow!("WSAStartup: {rc}"));
    }
    let skipped = |name: &str, why: &str| {
        eprintln!("srt-win: runner: egress probe [{name}]: SKIPPED ({why})");
        Ok(Outcome::Skipped)
    };
    let off_loopback = |name: &str, id: Identity| match &anonymous_target {
        Some(t) => attempt(name, id, t),
        None => skipped(name, "no off-loopback target"),
    };
    // An attempt the filters refuse at the loopback target while loopback
    // is closed; `elsewhere` is where it goes instead while it is open.
    let refused_on_loopback = |name: &str, id: Identity, elsewhere: bool| match allow_loopback {
        false => attempt(name, id, &target),
        true if elsewhere => off_loopback(name, id),
        true => skipped(name, "loopback is open"),
    };
    let low = Identity::LoweredIntegrity(IL_LOW);
    let untrusted = Identity::LoweredIntegrity(IL_UNTRUSTED);
    let plain = refused_on_loopback("plain", Identity::Own, true)?;
    if plain.passed_fence() {
        eprintln!("srt-win: runner: egress probe: the plain connect was not blocked; stopping");
        return Ok(Report::unfenced_at_plain(plain));
    }
    let anonymous = if anonymous_egress {
        off_loopback("anonymous", Identity::Anonymous)?
    } else {
        skipped("anonymous", "not requested")?
    };
    let loopback_il = "low integrity, loopback";
    let loopback_untrusted = "untrusted integrity, loopback";
    Ok(Report {
        plain,
        anonymous,
        anonymous_loopback: refused_on_loopback("anonymous, loopback", Identity::Anonymous, false)?,
        deny_only: refused_on_loopback("deny-only user SID", Identity::DenyOnlyUser, true)?,
        low_integrity: off_loopback("low integrity", low)?,
        low_integrity_loopback: refused_on_loopback(loopback_il, low, false)?,
        untrusted_integrity: off_loopback("untrusted integrity", untrusted)?,
        untrusted_integrity_loopback: refused_on_loopback(loopback_untrusted, untrusted, false)?,
        open_loopback: if allow_loopback {
            attempt("open loopback", Identity::Own, &target)?
        } else {
            Outcome::Skipped
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The four lowered-integrity attempts blocked, the rest as given.
    fn report(p: Outcome, a: Outcome, al: Outcome, d: Outcome) -> Report {
        Report {
            plain: p,
            anonymous: a,
            anonymous_loopback: al,
            deny_only: d,
            low_integrity: Outcome::Blocked,
            low_integrity_loopback: Outcome::Blocked,
            untrusted_integrity: Outcome::Blocked,
            untrusted_integrity_loopback: Outcome::Blocked,
            open_loopback: Outcome::Skipped,
        }
    }

    /// Loopback open on a machine with an off-loopback address: the
    /// loopback attempts skipped, `plain` and `open_loopback` as given.
    fn opened(plain: Outcome, open_loopback: Outcome) -> Report {
        Report {
            anonymous_loopback: Outcome::Skipped,
            low_integrity_loopback: Outcome::Skipped,
            untrusted_integrity_loopback: Outcome::Skipped,
            open_loopback,
            ..report(plain, Outcome::Skipped, Outcome::Blocked, Outcome::Blocked)
        }
    }

    #[test]
    fn verdict_with_loopback_open() {
        let v = verdict(&opened(Blocked, Connected));
        assert_eq!((v.exit, v.residuals.is_empty()), (EXIT_FENCED, true));
        // The direct connect off loopback is what must still be refused.
        for out in [Connected, Refused] {
            assert_eq!(verdict(&opened(out, Connected)).exit, EXIT_NOT_FENCED);
        }
        for unknown in [Unreachable, Error] {
            assert_eq!(verdict(&opened(unknown, Connected)).exit, EXIT_INCONCLUSIVE);
        }
        // Loopback recorded open, but the connect to our own listener was refused.
        assert_eq!(
            verdict(&opened(Blocked, Blocked)).exit,
            EXIT_LOOPBACK_MISMATCH
        );
        for unknown in [Refused, Unreachable, Error] {
            assert_eq!(verdict(&opened(Blocked, unknown)).exit, EXIT_INCONCLUSIVE);
        }
        // A lowered-integrity copy getting out off loopback still fails it.
        let mut leak = opened(Blocked, Connected);
        leak.untrusted_integrity = Refused;
        assert_eq!(verdict(&leak).exit, EXIT_NOT_FENCED);
    }

    #[test]
    fn verdict_with_loopback_open_and_no_off_loopback_address() {
        // Nothing the filters must refuse could be aimed anywhere: named, not failed.
        let mut r = opened(Skipped, Connected);
        (r.deny_only, r.low_integrity, r.untrusted_integrity) = (Skipped, Skipped, Skipped);
        let v = verdict(&r);
        assert_eq!(v.exit, EXIT_FENCED);
        assert_eq!(v.residuals, [RESIDUAL_EGRESS_UNPROBED]);
        // With loopback closed a skipped plain attempt is never a pass.
        let closed = report(Skipped, Blocked, Blocked, Blocked);
        assert_eq!(verdict(&closed).exit, EXIT_INCONCLUSIVE);
        assert!(verdict(&closed).residuals.is_empty());
    }

    /// `r` with the lowered-integrity attempts replaced, in field order.
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
                        // Reordered, so every field sees every outcome
                        // beside differing neighbours.
                        let r = lowered(report(p, a, al, d), [d, al, a, p]);
                        assert_eq!(Report::decode(r.encode()), Some(r));
                    }
                }
            }
        }
    }

    #[test]
    fn unrelated_exit_codes_do_not_decode() {
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
        // In range, but a field holds no outcome.
        assert_eq!(Report::decode(REPORT_BASE | 7), None);
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

    #[test]
    fn worse_ranks_outcomes_for_the_fence() {
        let ranked = [Connected, Refused, Error, Unreachable, Skipped, Blocked];
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
        assert!(Blocked.worse(Connected).passed_fence());
        assert!(Refused.worse(Blocked).passed_fence());
        // A block in one ordering does not stand in for an ordering
        // that was not measured.
        assert_eq!(Blocked.worse(Error), Error);
        assert_eq!(Unreachable.worse(Blocked), Unreachable);
        assert_eq!(Blocked.worse(Blocked), Blocked);
        assert_eq!(Error.worse(Connected), Connected);
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
        let v = verdict(&report(Blocked, Blocked, Blocked, Blocked));
        assert_eq!(v.exit, EXIT_FENCED);
        assert!(v.residuals.is_empty());
    }

    #[test]
    fn verdict_names_each_residual() {
        let v = verdict(&report(Blocked, Blocked, Connected, Connected));
        assert_eq!(v.exit, EXIT_FENCED);
        assert_eq!(
            v.residuals,
            [RESIDUAL_ANONYMOUS_LOOPBACK, RESIDUAL_DENY_ONLY]
        );
        let v = verdict(&report(Blocked, Connected, Connected, Connected));
        assert_eq!(v.exit, EXIT_FENCED);
        assert_eq!(
            v.residuals,
            [
                RESIDUAL_ANONYMOUS_EGRESS,
                RESIDUAL_ANONYMOUS_LOOPBACK,
                RESIDUAL_DENY_ONLY
            ]
        );
        let v = verdict(&report(Blocked, Blocked, Blocked, Refused));
        assert_eq!(v.residuals, [RESIDUAL_DENY_ONLY]);
        // An attempt that could not be made is not a residual.
        let v = verdict(&report(Blocked, Blocked, Error, Unreachable));
        assert_eq!(v.exit, EXIT_FENCED);
        assert!(v.residuals.is_empty());
    }

    #[test]
    fn verdict_plain_getting_out_is_not_fenced() {
        for through in [Connected, Refused] {
            let v = verdict(&report(through, Blocked, Blocked, Blocked));
            assert_eq!(v.exit, EXIT_NOT_FENCED);
            // Residuals qualify a pass; a failure reports none.
            let v = verdict(&report(through, Connected, Connected, Connected));
            assert_eq!(v.exit, EXIT_NOT_FENCED);
            assert!(v.residuals.is_empty());
        }
    }

    #[test]
    fn verdict_anonymous_egress_is_a_residual_never_a_failure() {
        for through in [Connected, Refused] {
            let v = verdict(&report(Blocked, through, Blocked, Blocked));
            assert_eq!(v.exit, EXIT_FENCED);
            assert_eq!(v.residuals, [RESIDUAL_ANONYMOUS_EGRESS]);
        }
        for other in [Blocked, Unreachable, Error, Skipped] {
            let v = verdict(&report(Blocked, other, Blocked, Blocked));
            assert_eq!(v.exit, EXIT_FENCED, "{other:?}");
            assert!(v.residuals.is_empty(), "{other:?}");
        }
    }

    #[test]
    fn verdict_lowered_integrity_getting_out_is_not_fenced() {
        let all_blocked = report(Blocked, Blocked, Blocked, Blocked);
        for field in 0..4 {
            for through in [Connected, Refused] {
                let mut l = [Blocked; 4];
                l[field] = through;
                let v = verdict(&lowered(all_blocked, l));
                assert_eq!(v.exit, EXIT_NOT_FENCED, "field {field} {through:?}");
                assert!(v.residuals.is_empty());
            }
        }
    }

    #[test]
    fn verdict_lowered_integrity_not_set_up_is_reported_not_failed() {
        let all_blocked = report(Blocked, Blocked, Blocked, Blocked);
        for field in 0..4 {
            // A token that could not be assumed is not a block: it is named.
            let mut l = [Blocked; 4];
            l[field] = Error;
            let v = verdict(&lowered(all_blocked, l));
            assert_eq!(v.exit, EXIT_FENCED, "field {field}");
            assert_eq!(v.residuals, [RESIDUAL_LOWERED_INTEGRITY_UNPROBED]);
            // A connect that was made and did not answer is still unknown.
            l[field] = Unreachable;
            let v = verdict(&lowered(all_blocked, l));
            assert_eq!(v.exit, EXIT_INCONCLUSIVE, "field {field}");
            assert!(v.residuals.is_empty());
        }
        // It does not excuse the plain attempt, nor a leak beside it.
        for plain in [Error, Unreachable, Skipped] {
            let r = lowered(report(plain, Blocked, Blocked, Blocked), [Error; 4]);
            assert_eq!(verdict(&r).exit, EXIT_INCONCLUSIVE, "{plain:?}");
        }
        let leak = lowered(all_blocked, [Error, Connected, Error, Error]);
        assert_eq!(verdict(&leak).exit, EXIT_NOT_FENCED);
        // It is named after the residuals that connected.
        let r = lowered(report(Blocked, Blocked, Blocked, Connected), [Error; 4]);
        assert_eq!(
            verdict(&r).residuals,
            [RESIDUAL_DENY_ONLY, RESIDUAL_LOWERED_INTEGRITY_UNPROBED]
        );
        // Only the attempts at the off-loopback target can be skipped.
        let v = verdict(&lowered(all_blocked, [Skipped, Blocked, Skipped, Blocked]));
        assert_eq!(v.exit, EXIT_FENCED);
        for loopback in [1, 3] {
            let mut l = [Blocked; 4];
            l[loopback] = Skipped;
            assert_eq!(verdict(&lowered(all_blocked, l)).exit, EXIT_INCONCLUSIVE);
        }
    }

    #[test]
    fn verdict_no_token_copy_can_be_assumed_is_fenced_with_each_reported() {
        // A restricted token: every impersonation of a copy is refused.
        let r = lowered(report(Blocked, Blocked, Blocked, Blocked), [Error; 4]);
        let v = verdict(&r);
        assert_eq!(v.exit, EXIT_FENCED);
        assert_eq!(v.residuals, [RESIDUAL_LOWERED_INTEGRITY_UNPROBED]);
        // The anonymous and deny-only copies refused as well.
        let r = lowered(report(Blocked, Error, Error, Error), [Error; 4]);
        let v = verdict(&r);
        assert_eq!(v.exit, EXIT_FENCED);
        assert_eq!(v.residuals, [RESIDUAL_LOWERED_INTEGRITY_UNPROBED]);
        // Each reaches the broker as `error`, not as a block.
        let r = Report::decode(r.encode()).unwrap();
        assert_eq!(r.plain.label(), "blocked");
        for (o, _) in r.lowered() {
            assert_eq!(o.label(), "error");
        }
        for o in [r.anonymous, r.anonymous_loopback, r.deny_only] {
            assert_eq!(o.label(), "error");
        }
    }

    #[test]
    fn a_failed_revert_ends_the_run() {
        assert!(ensure_reverted().is_ok());
        REVERT_FAILURE.with(|f| f.set(Some(0x8007_0005_u32 as i32)));
        let e = ensure_reverted().unwrap_err().to_string();
        REVERT_FAILURE.with(|f| f.set(None));
        assert!(
            e.contains("RevertToSelf") && e.contains("0x80070005"),
            "{e}"
        );
    }

    #[test]
    fn a_plain_attempt_past_the_fence_settles_the_verdict_alone() {
        for through in [Connected, Refused] {
            let r = Report::unfenced_at_plain(through);
            assert_eq!(r.plain, through);
            assert!(r.fields()[1..].iter().all(|o| *o == Skipped));
            let v = verdict(&r);
            assert_eq!(v.exit, EXIT_NOT_FENCED);
            assert!(v.residuals.is_empty());
            assert_eq!(Report::decode(r.encode()), Some(r));
        }
    }

    #[test]
    fn verdict_inconclusive_and_skipped() {
        for odd in [Unreachable, Error, Skipped] {
            assert_eq!(
                verdict(&report(odd, Blocked, Blocked, Blocked)).exit,
                EXIT_INCONCLUSIVE
            );
        }
    }
}
