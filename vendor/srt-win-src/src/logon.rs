//! Broker-side `CreateProcessWithLogonW` wrapper for the
//! broker→runner two-hop launch.
//!
//! Spawns `srt-win.exe runner` under the `srt-sandbox` account
//! (via the Secondary Logon service — no
//! `SeAssignPrimaryTokenPrivilege` needed on the broker), wires
//! three pipes to its stdio, writes the
//! [`crate::runner::RunnerCmd`] over stdin, pumps stdout/stderr
//! back to the broker's own stdio, waits, and returns the runner's
//! exit code.
//!
//! **The sandbox side only ever holds pipe CLIENT ends**: a server end can
//! `ImpersonateNamedPipeClient` whoever opened the other end, here the real
//! user. The read end of a `CreatePipe` pair is a server end, so stdin is
//! built by [`make_stdin_pipe`] instead.
//!
//! `lpEnvironment = NULL` + `LOGON_WITH_PROFILE` means the runner
//! starts with the **sandbox user's** profile environment
//! (`USERPROFILE`/`TEMP`/`LOCALAPPDATA` isolated; `PATH` = machine
//! `PATH`). The broker's `PATH` and the proxy var set ride to the
//! child via the spec's `env_overlay` instead, applied by the
//! runner's `build_env_block` — so profile-scoped vars stay the
//! sandbox user's while tool-resolution `PATH` is the broker's.
//!
//! **Do not key any ACL/WFP on the logon SID:** seclogon stamps the
//! broker's interactive logon SID into the runner's token. Key on
//! the **user SID** only.

use anyhow::{Context, Result, anyhow};
use serde::Serialize;
use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use windows::Win32::Foundation::{
    CloseHandle, ERROR_DIRECTORY, ERROR_LOGON_FAILURE, ERROR_NOT_SUPPORTED, ERROR_PIPE_BUSY,
    ERROR_SERVICE_DISABLED, ERROR_SERVICE_DOES_NOT_EXIST, GENERIC_READ, HANDLE,
    HANDLE_FLAG_INHERIT, HANDLE_FLAGS, SetHandleInformation, WAIT_OBJECT_0,
};
use windows::Win32::Security::Cryptography::{BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom};
use windows::Win32::Security::SECURITY_ATTRIBUTES;
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_MODE,
    FILE_WRITE_ATTRIBUTES, GetDriveTypeW, OPEN_EXISTING, PIPE_ACCESS_OUTBOUND, ReadFile,
    SECURITY_ANONYMOUS, SECURITY_SQOS_PRESENT, WriteFile,
};
use windows::Win32::System::Pipes::{
    CreateNamedPipeW, CreatePipe, NAMED_PIPE_MODE, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
    PIPE_TYPE_BYTE, PIPE_WAIT,
};
use windows::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, QUERY_SERVICE_CONFIGW, QueryServiceConfigW,
    QueryServiceStatus, SC_HANDLE, SC_MANAGER_CONNECT, SERVICE_DISABLED, SERVICE_QUERY_CONFIG,
    SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_START_TYPE, SERVICE_STATUS,
    SERVICE_STATUS_CURRENT_STATE,
};
use windows::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessWithLogonW,
    GetExitCodeProcess, INFINITE, LOGON_WITH_PROFILE, PROCESS_INFORMATION, ResumeThread,
    STARTF_USESTDHANDLES, STARTUPINFOW, WaitForMultipleObjects, WaitForSingleObject,
};
use windows::core::{PCWSTR, PWSTR};

use crate::acl::{Allow, Mask, NO_INHERIT, build_allow_dacl};
use crate::job::Job;
use crate::launch::{SpawnedChild, quote_arg};
use crate::sid::current_user_sid;
use crate::util::{OwnedHandle, pcwstr, scrub_wstr, wstr};
use crate::winsta::{IsolatedDesk, grant_sandbox_on_session_bno, grant_sandbox_on_winsta};

/// Typed error for [`spawn_runner`] with a mapped/network-drive
/// working directory. Per-user drive mappings and SMB share
/// authentication belong to the **real** user's logon session; the
/// `srt-sandbox` logon that seclogon creates for
/// `CreateProcessWithLogonW` has neither, so `lpCurrentDirectory`
/// pointing at a mapped drive fails inside seclogon with
/// `ERROR_DIRECTORY` (`0x8007010B`). A mechanism failure, not a
/// security block — typed so callers can present an actionable
/// message instead of a bare HRESULT.
#[derive(Debug)]
pub struct MappedDriveCwd {
    /// The drive root that resolved as `DRIVE_REMOTE` (`Z:\` for a
    /// mapped drive letter, `\\server\share\` for a raw UNC cwd).
    pub drive: String,
}

impl std::fmt::Display for MappedDriveCwd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the sandbox cannot start with a mapped/network-drive \
             working directory ({} is DRIVE_REMOTE — per-user drive \
             mappings do not exist under the sandbox logon). Use a \
             local-drive workspace.",
            self.drive,
        )
    }
}

impl std::error::Error for MappedDriveCwd {}

/// `GetDriveTypeW` return value for a network drive. The `windows`
/// crate parks this constant under `Win32_System_WindowsProgramming`
/// (a grab-bag feature we don't otherwise need); the value is a
/// stable Win32 ABI constant.
const DRIVE_REMOTE: u32 = 4;

/// Extract the drive root of `cwd` in the form `GetDriveTypeW`
/// wants: `X:\` for a drive-letter path, `\\server\share\` for a
/// UNC path. `None` for anything else (relative, device path
/// `\\.\…` / `\\?\…`, or malformed) — the caller falls through to
/// the `CreateProcessWithLogonW` attempt and the post-check catches
/// the `ERROR_DIRECTORY` case.
fn cwd_drive_root(cwd: &str) -> Option<String> {
    let b = cwd.as_bytes();
    if b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/')
    {
        return Some(format!("{}:\\", (b[0] as char).to_ascii_uppercase()));
    }
    if let Some(rest) = cwd.strip_prefix(r"\\") {
        // `\\?\…` / `\\.\…` are extended/device prefixes, not a
        // server name — leave to the post-check.
        if rest.starts_with(['?', '.']) {
            return None;
        }
        let mut it = rest.splitn(3, ['\\', '/']);
        if let (Some(srv), Some(share)) = (it.next(), it.next())
            && !srv.is_empty()
            && !share.is_empty()
        {
            return Some(format!(r"\\{srv}\{share}\"));
        }
    }
    None
}

/// Readiness of the Secondary Logon service (`seclogon`) that every
/// `CreateProcessWithLogonW` routes through, as `srt-win status` reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SeclogonState {
    /// Running, or stopped with a start type the SCM will demand-start.
    Ok,
    /// Start type is Disabled and the service is not running.
    Disabled,
    /// No `seclogon` service is registered on this machine.
    Missing,
    /// The SCM or the service could not be queried. Not proof of a problem:
    /// the launch itself is the ground truth.
    CannotRead,
}

/// A running service launches regardless of its start type (disabling does
/// not stop it), so only "Disabled and known not to run" is `Disabled`; with
/// the status unreadable, a Disabled start type is `CannotRead`.
fn classify_seclogon(
    start: SERVICE_START_TYPE,
    current: Option<SERVICE_STATUS_CURRENT_STATE>,
) -> SeclogonState {
    match (start == SERVICE_DISABLED, current) {
        (true, Some(SERVICE_RUNNING)) | (false, _) => SeclogonState::Ok,
        (true, Some(_)) => SeclogonState::Disabled,
        (true, None) => SeclogonState::CannotRead,
    }
}

/// Whether a failed logon call is the Secondary Logon service being unusable:
/// the probe says so, or the call failed with `ERROR_SERVICE_DISABLED` (which
/// any service on the logon path can cause) and the probe did not read it `Ok`.
fn logon_failure_is_seclogon(service_disabled_error: bool, state: SeclogonState) -> bool {
    match state {
        SeclogonState::Disabled | SeclogonState::Missing => true,
        SeclogonState::Ok => false,
        SeclogonState::CannotRead => service_disabled_error,
    }
}

/// `SC_HANDLE` closed on drop.
struct ScHandle(SC_HANDLE);

impl Drop for ScHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseServiceHandle(self.0);
        }
    }
}

/// Read-only probe of the Secondary Logon service, using rights the stock
/// service DACL grants every interactive user. Any failure to read is
/// [`SeclogonState::CannotRead`].
pub fn seclogon_state() -> SeclogonState {
    let Ok(scm) = (unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT) })
    else {
        return SeclogonState::CannotRead;
    };
    let scm = ScHandle(scm);
    let svc = match unsafe {
        OpenServiceW(
            scm.0,
            PCWSTR(wstr("seclogon").as_ptr()),
            SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS,
        )
    } {
        Ok(h) => ScHandle(h),
        Err(e) if e.code() == ERROR_SERVICE_DOES_NOT_EXIST.to_hresult() => {
            return SeclogonState::Missing;
        }
        Err(_) => return SeclogonState::CannotRead,
    };
    // Variable-length struct, documented maximum 8K bytes. `u64` elements
    // keep the buffer aligned for the struct's pointers.
    let mut buf = [0u64; 1024];
    let mut needed = 0u32;
    if unsafe {
        QueryServiceConfigW(
            svc.0,
            Some(buf.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>()),
            size_of_val(&buf) as u32,
            &mut needed,
        )
    }
    .is_err()
    {
        return SeclogonState::CannotRead;
    }
    let start = unsafe { (*buf.as_ptr().cast::<QUERY_SERVICE_CONFIGW>()).dwStartType };
    // A failed status query leaves the start type alone to decide.
    let mut st = SERVICE_STATUS::default();
    let current = unsafe { QueryServiceStatus(svc.0, &mut st) }
        .ok()
        .map(|()| st.dwCurrentState);
    classify_seclogon(start, current)
}

/// Typed error for [`spawn_runner`]: the Secondary Logon service is Disabled
/// (`missing == false`) or not registered (`missing == true`).
#[derive(Debug)]
pub struct SeclogonDisabled {
    pub missing: bool,
}

impl SeclogonDisabled {
    /// The [`SeclogonState`] this error corresponds to.
    pub fn state(&self) -> SeclogonState {
        if self.missing {
            SeclogonState::Missing
        } else {
            SeclogonState::Disabled
        }
    }
}

impl std::fmt::Display for SeclogonDisabled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.missing {
            write!(
                f,
                "the sandbox cannot start: the Windows Secondary Logon \
                 service (seclogon) is not present on this machine, and \
                 every sandboxed launch goes through it.",
            )
        } else {
            write!(
                f,
                "the sandbox cannot start: the Windows Secondary Logon \
                 service (seclogon) is disabled. An administrator must \
                 set its startup type to Manual (`sc.exe config \
                 seclogon start= demand`).",
            )
        }
    }
}

impl std::error::Error for SeclogonDisabled {}

/// One pipe pair. The runner's end is inheritable; the broker's is not, or
/// the runner's copy would keep the pipe open past its exit and hang the pump.
struct PipePair {
    broker: OwnedHandle,
    runner: OwnedHandle,
}

/// An anonymous pipe the runner WRITES to (stdout / stderr). Never
/// use this shape for a pipe the runner reads: the read end is the
/// server end (see [`make_stdin_pipe`]).
fn make_output_pipe() -> Result<PipePair> {
    let sa = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        bInheritHandle: true.into(),
        ..Default::default()
    };
    let mut read = HANDLE::default();
    let mut write = HANDLE::default();
    unsafe {
        CreatePipe(&mut read, &mut write, Some(&sa), 0).context("CreatePipe")?;
    }
    // Wrap immediately so the `?` below can't leak either end.
    let (broker, runner) = (OwnedHandle(read), OwnedHandle(write));
    // Broker end must NOT be inherited by the runner.
    unsafe {
        SetHandleInformation(broker.raw(), HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0))
            .context("SetHandleInformation(broker end)")?;
    }
    Ok(PipePair { broker, runner })
}

/// `dwOpenMode` of the stdin pipe's server end: the server only
/// writes, and the create fails unless this is the first pipe of
/// that name (so the name cannot already belong to someone else).
const STDIN_PIPE_OPEN_MODE: FILE_FLAGS_AND_ATTRIBUTES =
    FILE_FLAGS_AND_ATTRIBUTES(PIPE_ACCESS_OUTBOUND.0 | FILE_FLAG_FIRST_PIPE_INSTANCE.0);

/// `dwPipeMode` of the stdin pipe: a blocking byte stream, local
/// clients only.
const STDIN_PIPE_MODE: NAMED_PIPE_MODE = NAMED_PIPE_MODE(
    PIPE_TYPE_BYTE.0 | PIPE_READMODE_BYTE.0 | PIPE_WAIT.0 | PIPE_REJECT_REMOTE_CLIENTS.0,
);

/// One instance: once the broker's own client is connected, nobody
/// else can connect to the name or create a second server for it.
const STDIN_PIPE_MAX_INSTANCES: u32 = 1;

/// Server-side buffer; a larger write blocks until the runner reads.
const STDIN_PIPE_OUT_BUFFER: u32 = 64 * 1024;

/// Read, plus `FILE_WRITE_ATTRIBUTES`: what the read end of a `CreatePipe`
/// pair carries, so a child that sets the read mode on its stdin keeps working.
const STDIN_CLIENT_ACCESS: u32 = GENERIC_READ.0 | FILE_WRITE_ATTRIBUTES.0;

/// The client end is opened at the ANONYMOUS impersonation level, so
/// even the pipe's server end (which stays in the broker) could not
/// obtain a usable token for the broker's user through it.
const STDIN_CLIENT_FLAGS: FILE_FLAGS_AND_ATTRIBUTES =
    FILE_FLAGS_AND_ATTRIBUTES(SECURITY_SQOS_PRESENT.0 | SECURITY_ANONYMOUS.0);

/// Name of the stdin pipe: the broker's pid plus 128 random bits.
/// The name is not a secret (the DACL and the single instance keep
/// others out); it only has to be unique and hard to squat.
fn stdin_pipe_name(pid: u32, rand: &[u8; 16]) -> String {
    let hex: String = rand.iter().map(|b| format!("{b:02x}")).collect();
    format!(r"\\.\pipe\srt-win-stdin-{pid}-{hex}")
}

/// The runner's stdin pipe, with the runner holding the CLIENT end: the broker
/// keeps the server end of a named pipe and opens the client end itself. The
/// DACL grants only the broker's user; if any step fails the launch fails.
fn make_stdin_pipe() -> Result<PipePair> {
    once_more_if_pipe_busy(|| make_stdin_pipe_named(&fresh_stdin_pipe_name()?))
}

/// Run `make`, and once more if it failed with `ERROR_PIPE_BUSY`: another
/// process took the pipe's single instance before the broker's own connect.
fn once_more_if_pipe_busy<T>(mut make: impl FnMut() -> Result<T>) -> Result<T> {
    match make() {
        Err(e) if is_pipe_busy(&e) => make(),
        r => r,
    }
}

fn is_pipe_busy(e: &anyhow::Error) -> bool {
    e.downcast_ref::<windows::core::Error>()
        .is_some_and(|w| w.code() == ERROR_PIPE_BUSY.to_hresult())
}

fn fresh_stdin_pipe_name() -> Result<String> {
    let mut rand = [0u8; 16];
    unsafe { BCryptGenRandom(None, &mut rand, BCRYPT_USE_SYSTEM_PREFERRED_RNG) }
        .ok()
        .context("BCryptGenRandom (stdin pipe name)")?;
    Ok(stdin_pipe_name(std::process::id(), &rand))
}

fn make_stdin_pipe_named(name: &str) -> Result<PipePair> {
    let name_w = wstr(name);
    // Protected DACL with a single ACE for this process's user.
    // `bInheritHandle` is false: the server end stays in the broker.
    let me = current_user_sid().context("stdin pipe: current user SID")?;
    let sa = build_allow_dacl(&[Allow(&me, Mask::FILE_ALL, NO_INHERIT)])?
        .into_security_attributes()
        .context("stdin pipe: security descriptor")?;
    let server = unsafe {
        CreateNamedPipeW(
            pcwstr(&name_w),
            STDIN_PIPE_OPEN_MODE,
            STDIN_PIPE_MODE,
            STDIN_PIPE_MAX_INSTANCES,
            STDIN_PIPE_OUT_BUFFER,
            0,
            0,
            Some(sa.as_ptr()),
        )
    };
    if server.is_invalid() {
        return Err(anyhow!(
            "CreateNamedPipeW(runner stdin): {}",
            std::io::Error::last_os_error()
        ));
    }
    let broker = OwnedHandle(server);
    // Not inheritable at open; only this one handle is flipped below.
    let client = unsafe {
        CreateFileW(
            pcwstr(&name_w),
            STDIN_CLIENT_ACCESS,
            FILE_SHARE_MODE(0),
            None,
            OPEN_EXISTING,
            STDIN_CLIENT_FLAGS,
            None,
        )
    }
    .context("CreateFileW(runner stdin client end)")?;
    let runner = OwnedHandle(client);
    unsafe {
        SetHandleInformation(runner.raw(), HANDLE_FLAG_INHERIT.0, HANDLE_FLAG_INHERIT)
            .context("SetHandleInformation(runner stdin, inheritable)")?;
    }
    Ok(PipePair { broker, runner })
}

/// Pump `src` to `dst` until `src` reaches EOF (broken pipe). Runs
/// on a dedicated thread per stream so a slow consumer on one
/// doesn't block the other.
fn pump(src: HANDLE, dst: HANDLE) {
    let mut buf = [0u8; 8192];
    loop {
        let mut read = 0u32;
        let r = unsafe { ReadFile(src, Some(&mut buf), Some(&mut read), None) };
        if r.is_err() || read == 0 {
            break;
        }
        let mut off = 0u32;
        while off < read {
            let mut wrote = 0u32;
            let chunk = &buf[off as usize..read as usize];
            if unsafe { WriteFile(dst, Some(chunk), Some(&mut wrote), None) }.is_err() || wrote == 0
            {
                return;
            }
            off += wrote;
        }
    }
}

/// Spawn `srt-win runner` as `username`, send `cmd` over stdin, return its
/// exit code. If `holder` (a waitable process handle) ends first, the runner
/// and everything it started are terminated: [`HolderGone`].
pub fn spawn_runner(
    username: &str,
    password: &str,
    sb_sid: &str,
    cwd: Option<&str>,
    cmd: &crate::runner::RunnerCmd,
    quiet: bool,
    holder: Option<HANDLE>,
) -> Result<u32> {
    // Mapped/network-drive cwd pre-check: `DRIVE_REMOTE` on the
    // cwd's root means CPWLW would fail inside seclogon with
    // `ERROR_DIRECTORY` — fail fast with the typed error. The
    // post-CPWLW arm below maps `ERROR_DIRECTORY` to the same
    // error for shapes this pre-check doesn't recognise.
    if let Some(root) = cwd.and_then(cwd_drive_root)
        && unsafe { GetDriveTypeW(PCWSTR(wstr(&root).as_ptr())) } == DRIVE_REMOTE
    {
        return Err(MappedDriveCwd { drive: root }.into());
    }

    let cmd_bytes = crate::runner::encode_cmd(cmd)?;
    let stdin = make_stdin_pipe().context("runner stdin pipe")?;
    let stdout = make_output_pipe()?;
    let stderr = make_output_pipe()?;

    // Broker-side per-exec desktop on `WinSta0` with an explicit
    // `[broker, srt-sandbox, SY]:GA` DACL. The broker (interactive
    // user) has `WINSTA_CREATEDESKTOP` non-elevated; the runner does
    // not — so this MUST happen here, not inside the runner. Held
    // open until the runner exits so the kernel object survives the
    // whole two-hop chain. See `winsta.rs` module doc.
    let dbg = std::env::var_os("SANDBOX_RUNTIME_WIN_DEBUG").is_some();
    let mut desk = IsolatedDesk::new(sb_sid).context("broker IsolatedDesk")?;

    let exe = std::env::current_exe().context("current_exe")?;
    let exe_s = exe
        .to_str()
        .ok_or_else(|| anyhow!("current_exe is not UTF-8"))?;
    let exe_w = wstr(exe_s);
    // `lpCommandLine` is parsed via `CommandLineToArgvW`; quote
    // argv[0] so a path with spaces survives. The
    // `SRT_WIN_DISPATCH_ARG1` sentinel at argv[1] is what a
    // multicall embedder's dispatcher routes on (`argv[0]` cannot be
    // spoofed across CPWLW); `run_from_args` strips it before clap so
    // the standalone binary accepts it harmlessly. `runner` is the
    // only real argument.
    let mut cmdline_w = wstr(&format!(
        "{} {} runner",
        quote_arg(exe_s),
        crate::cli::SRT_WIN_DISPATCH_ARG1,
    ));
    let user_w = wstr(username);
    let domain_w = wstr(".");
    let mut pw_w = wstr(password);
    let cwd_w = cwd.map(wstr);

    // Broker→runner kill-on-close Job: broker dies → runner dies →
    // runner's Job → child dies. The assign succeeds on current
    // Windows (rc=0, live-probed 2026-07-16); if a future seclogon
    // job refused nesting (ERROR_NOT_SUPPORTED), the always-armed
    // `SpawnedChild` guard below is the fallback.
    // `breakaway_ok = true`: the runner's child must break away
    // past the inherited [seclogon, broker] job stack onto the
    // runner's own Job, which requires every containing job to
    // allow it.
    let job = Job::new(true).context("broker→runner job")?;

    let mut si: STARTUPINFOW = unsafe { zeroed() };
    si.cb = size_of::<STARTUPINFOW>() as u32;
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = stdin.runner.raw();
    si.hStdOutput = stdout.runner.raw();
    si.hStdError = stderr.runner.raw();
    // `lpDesktop = "WinSta0\srt-sb-…"`. The runner never touches
    // `Default`; `run_lockdown` fail-closes if it somehow lands there.
    si.lpDesktop = PWSTR(desk.desktop_name_ptr());
    let mut pi: PROCESS_INFORMATION = unsafe { zeroed() };
    // `CreateProcessWithLogonW` has no `bInheritHandles` parameter:
    // seclogon duplicates the `STARTF_USESTDHANDLES` handles into
    // the new logon, and nothing else. So no
    // `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` is needed (or possible —
    // there's no `STARTUPINFOEX` overload).
    let r = unsafe {
        CreateProcessWithLogonW(
            PCWSTR(user_w.as_ptr()),
            PCWSTR(domain_w.as_ptr()),
            PCWSTR(pw_w.as_ptr()),
            LOGON_WITH_PROFILE,
            PCWSTR(exe_w.as_ptr()),
            Some(PWSTR(cmdline_w.as_mut_ptr())),
            CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW | CREATE_SUSPENDED,
            // `NULL` → seclogon builds the sandbox user's profile
            // env (with `LOGON_WITH_PROFILE`). The broker's PATH
            // and proxy vars travel via the spec's env_overlay.
            None,
            match &cwd_w {
                Some(w) => PCWSTR(w.as_ptr()),
                None => PCWSTR::null(),
            },
            &si,
            &mut pi,
        )
    };
    // Scrub the UTF-16 password buffer now that seclogon has it.
    // (The UTF-8 source is zeroed by `SandboxCred::Drop`; this is a
    // separate heap allocation.) Before any `?` so the scrub runs
    // regardless of `r`. Volatile so DSE can't remove it in release.
    scrub_wstr(&mut pw_w);
    if let Err(e) = r {
        if e.code() == ERROR_LOGON_FAILURE.to_hresult() {
            return Err(anyhow!(
                "CreateProcessWithLogonW({username}): logon failure \
                 — the sandbox user's password is wrong or the \
                 account is disabled. Re-run `srt-win install` (one \
                 UAC prompt) to rotate the credential."
            ));
        }
        // `ERROR_DIRECTORY` = seclogon couldn't set the requested
        // cwd under the sandbox logon (mapped drive / unreachable
        // UNC share) — same typed error as the pre-check above,
        // catching shapes it didn't classify.
        if e.code() == ERROR_DIRECTORY.to_hresult() {
            let drive = cwd
                .and_then(cwd_drive_root)
                .or_else(|| cwd.map(str::to_owned))
                .unwrap_or_else(|| "<unknown>".into());
            return Err(MappedDriveCwd { drive }.into());
        }
        let state = seclogon_state();
        if logon_failure_is_seclogon(e.code() == ERROR_SERVICE_DISABLED.to_hresult(), state) {
            return Err(SeclogonDisabled {
                missing: state == SeclogonState::Missing,
            }
            .into());
        }
        return Err(anyhow!(
            "CreateProcessWithLogonW({username}): {e} — ensure the \
             Secondary Logon service (seclogon) is running."
        ));
    }
    if dbg {
        eprintln!(
            "srt-win: spawn_runner: CPWLW ok pid={} (suspended)",
            pi.dwProcessId
        );
    }
    // Runner exists, suspended. The guard is never defused: its
    // `Drop` `TerminateProcess`es the runner on every in-process
    // exit — `?`/panic reap directly; on normal return the runner
    // has already exited and the terminate is a no-op on the held
    // handle. It cannot cover an external kill of the broker —
    // that is the Job's role; if a build ever regresses the assign
    // above, elevated `taskkill /F /FI "USERNAME eq srt-sandbox"`
    // is the operator fallback (admins hold SeDebugPrivilege and
    // BA is in every sandbox process's DACL — the by-user-filter
    // denial is non-elevated-only). Declared after `job` so it
    // drops first: terminate before job-close.
    let child = SpawnedChild::new(pi);

    // Grant `srt-sandbox` on the broker's `WinSta0` (with a non-NULL
    // `lpDesktop`, seclogon skips its station auto-grant for the new
    // logon, so the runner can't attach without this) and on the
    // session `BaseNamedObjects` directory (so the lockdown child —
    // whose logon SIDs are deny-only — can still create the
    // named-object subdirectory msys2/cygwin needs). Both persist for
    // the broker's logon session: revoking on drop would race against
    // a concurrent `srt-win exec`. See `winsta.rs`.
    grant_sandbox_on_winsta(sb_sid)?;
    grant_sandbox_on_session_bno(sb_sid)?;
    if dbg {
        eprintln!("srt-win: spawn_runner: WinSta0 + BNO grants applied");
    }

    // Assign before resuming so there is no window where broker
    // death orphans it. ERROR_NOT_SUPPORTED (seclogon's job won't
    // nest) → log + continue; any OTHER error → propagate (the guard
    // terminates the suspended runner).
    if let Err(e) = job.assign(child.process()) {
        if e.root_cause()
            .downcast_ref::<windows::core::Error>()
            .map(|we| we.code() == ERROR_NOT_SUPPORTED.to_hresult())
            .unwrap_or(false)
        {
            if !quiet {
                eprintln!(
                    "srt-win: broker→runner Job assign not supported \
                     (seclogon job); relying on runner→child Job for \
                     kill-chain"
                );
            }
        } else {
            return Err(e.context("assign runner to job"));
        }
    }
    if unsafe { ResumeThread(child.thread()) } == u32::MAX {
        return Err(anyhow!(
            "ResumeThread(runner): {}",
            std::io::Error::last_os_error()
        ));
    }
    if dbg {
        eprintln!("srt-win: spawn_runner: runner resumed; writing spec");
    }
    // No `child.defuse()` — the guard stays armed (see its decl).

    // Close the runner-side pipe ends in the broker so the pumps
    // see EOF when the runner exits.
    drop(stdin.runner);
    drop(stdout.runner);
    drop(stderr.runner);

    // Write the spec, then close stdin so the runner's
    // `read_exact` doesn't block waiting for more.
    {
        let mut wrote = 0u32;
        unsafe {
            WriteFile(stdin.broker.raw(), Some(&cmd_bytes), Some(&mut wrote), None)
                .context("write RunnerCmd to runner stdin")?;
        }
        if wrote as usize != cmd_bytes.len() {
            return Err(anyhow!(
                "short write of RunnerCmd ({}/{} bytes)",
                wrote,
                cmd_bytes.len()
            ));
        }
    }
    drop(stdin.broker);

    // Pump stdout/stderr on dedicated threads. `HANDLE` wraps a
    // `*mut c_void` which is `!Send`; the value is just an opaque
    // index into the process's handle table, so cast to `isize` for
    // the move and reconstruct inside the thread. Broker stdio
    // handles are not OwnedHandle — they're owned by the process,
    // not us.
    let bout = std::io::stdout().as_raw().0 as isize;
    let berr = std::io::stderr().as_raw().0 as isize;
    let so = stdout.broker.into_raw().0 as isize;
    let se = stderr.broker.into_raw().0 as isize;
    let h = |v: isize| HANDLE(v as *mut c_void);
    let t_out = std::thread::spawn(move || {
        pump(h(so), h(bout));
        unsafe {
            let _ = CloseHandle(h(so));
        }
    });
    let t_err = std::thread::spawn(move || {
        pump(h(se), h(berr));
        unsafe {
            let _ = CloseHandle(h(se));
        }
    });

    if wait_for_child_or_holder(child.process(), holder) == Ended::HolderGone {
        // The whole tree, now: the runner (which takes its own job,
        // and so the command, with it) and then this job.
        drop(child);
        drop(job);
        return Err(anyhow::Error::new(HolderGone));
    }
    let _ = t_out.join();
    let _ = t_err.join();
    let mut code: u32 = 1;
    unsafe {
        GetExitCodeProcess(child.process(), &mut code).context("GetExitCodeProcess(runner)")?;
    }
    // Implicit drop order: `child` (armed, no-op on the exited
    // runner) then `job`. An explicit `drop(job)` here would close
    // the Job before the fallback terminate.
    Ok(code)
}

/// The process the command was started for ended while the command
/// ran; the command was terminated.
#[derive(Debug)]
pub struct HolderGone;

impl std::fmt::Display for HolderGone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            "the session that started this command ended; the command and everything it \
             started were terminated",
        )
    }
}

impl std::error::Error for HolderGone {}

#[derive(Debug, PartialEq, Eq)]
enum Ended {
    Child,
    HolderGone,
}

/// Wait for the runner or the holder, whichever ends first; the runner is
/// asked first. Anything else the wait can say (signalled holder, failed
/// wait, bad handle) counts as the holder gone.
fn wait_for_child_or_holder(child: HANDLE, holder: Option<HANDLE>) -> Ended {
    let Some(holder) = holder else {
        let rc = unsafe { WaitForSingleObject(child, INFINITE) };
        if rc != WAIT_OBJECT_0 {
            eprintln!("srt-win: WaitForSingleObject(runner) returned 0x{:x}", rc.0);
        }
        return Ended::Child;
    };
    let rc = unsafe { WaitForMultipleObjects(&[child, holder], false, INFINITE) };
    if rc == WAIT_OBJECT_0 {
        Ended::Child
    } else {
        Ended::HolderGone
    }
}

/// `std::io::Stdout`/`Stderr` → raw `HANDLE` for [`pump`].
trait AsRawHandle {
    fn as_raw(&self) -> HANDLE;
}
impl AsRawHandle for std::io::Stdout {
    fn as_raw(&self) -> HANDLE {
        HANDLE(std::os::windows::io::AsRawHandle::as_raw_handle(self))
    }
}
impl AsRawHandle for std::io::Stderr {
    fn as_raw(&self) -> HANDLE {
        HANDLE(std::os::windows::io::AsRawHandle::as_raw_handle(self))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::Foundation::ERROR_BROKEN_PIPE;
    use windows::Win32::Security::RevertToSelf;
    use windows::Win32::System::Pipes::{
        GetNamedPipeInfo, ImpersonateNamedPipeClient, PIPE_SERVER_END,
    };
    use windows::Win32::System::Services::{
        SERVICE_AUTO_START, SERVICE_DEMAND_START, SERVICE_STOPPED,
    };

    #[test]
    fn seclogon_disabled_only_when_not_running() {
        use SeclogonState as S;
        let stopped = Some(SERVICE_STOPPED);
        let running = Some(SERVICE_RUNNING);
        assert_eq!(classify_seclogon(SERVICE_DEMAND_START, stopped), S::Ok);
        assert_eq!(classify_seclogon(SERVICE_AUTO_START, running), S::Ok);
        assert_eq!(classify_seclogon(SERVICE_DISABLED, stopped), S::Disabled);
        assert_eq!(classify_seclogon(SERVICE_DISABLED, None), S::CannotRead);
        assert_eq!(classify_seclogon(SERVICE_DEMAND_START, None), S::Ok);
        // Disabled after it was started: still launches until the service stops.
        assert_eq!(classify_seclogon(SERVICE_DISABLED, running), S::Ok);
    }

    #[test]
    fn logon_failure_is_seclogon_only_when_the_probe_agrees() {
        use SeclogonState as S;
        for service_disabled_error in [true, false] {
            assert!(logon_failure_is_seclogon(
                service_disabled_error,
                S::Disabled
            ));
            assert!(logon_failure_is_seclogon(
                service_disabled_error,
                S::Missing
            ));
            assert!(!logon_failure_is_seclogon(service_disabled_error, S::Ok));
        }
        assert!(logon_failure_is_seclogon(true, S::CannotRead));
        assert!(!logon_failure_is_seclogon(false, S::CannotRead));
    }

    #[test]
    fn seclogon_state_json_values() {
        let j = |s: SeclogonState| serde_json::to_value(s).unwrap();
        assert_eq!(j(SeclogonState::Ok), "ok");
        assert_eq!(j(SeclogonState::Disabled), "disabled");
        assert_eq!(j(SeclogonState::Missing), "missing");
        assert_eq!(j(SeclogonState::CannotRead), "cannot-read");
    }

    #[test]
    fn seclogon_disabled_error_state_and_message() {
        let d = SeclogonDisabled { missing: false };
        assert_eq!(d.state(), SeclogonState::Disabled);
        assert!(d.to_string().contains("startup type to Manual"));
        let m = SeclogonDisabled { missing: true };
        assert_eq!(m.state(), SeclogonState::Missing);
        assert!(m.to_string().contains("not present"));
    }

    /// The command ends with its session: whichever of the two ends
    /// first decides, the command when both have, and a holder that
    /// cannot be waited on is a holder that is gone.
    #[test]
    fn the_wait_ends_with_the_child_or_with_the_holder() {
        use windows::Win32::System::Threading::{CreateEventW, SetEvent};
        let event =
            || crate::util::OwnedHandle(unsafe { CreateEventW(None, true, false, None) }.unwrap());
        let (child, holder) = (event(), event());
        unsafe { SetEvent(holder.raw()) }.unwrap();
        assert_eq!(
            super::wait_for_child_or_holder(child.raw(), Some(holder.raw())),
            super::Ended::HolderGone
        );
        unsafe { SetEvent(child.raw()) }.unwrap();
        assert_eq!(
            super::wait_for_child_or_holder(child.raw(), Some(holder.raw())),
            super::Ended::Child
        );
        let holder = event();
        assert_eq!(
            super::wait_for_child_or_holder(child.raw(), Some(holder.raw())),
            super::Ended::Child
        );
        assert_eq!(
            super::wait_for_child_or_holder(child.raw(), None),
            super::Ended::Child
        );
        let running = event();
        let closed = windows::Win32::Foundation::HANDLE::default();
        assert_eq!(
            super::wait_for_child_or_holder(running.raw(), Some(closed)),
            super::Ended::HolderGone
        );
        let (child, holder) = (event(), event());
        let signal = holder.raw().0 as isize;
        let t = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(200));
            unsafe { SetEvent(windows::Win32::Foundation::HANDLE(signal as *mut _)) }.unwrap();
        });
        assert_eq!(
            super::wait_for_child_or_holder(child.raw(), Some(holder.raw())),
            super::Ended::HolderGone
        );
        t.join().unwrap();
    }

    #[test]
    fn stdin_pipe_name_shape() {
        let n = stdin_pipe_name(1234, &[0xab; 16]);
        assert_eq!(
            n,
            r"\\.\pipe\srt-win-stdin-1234-abababababababababababababababab"
        );
        let mut r = [0u8; 16];
        r[15] = 0x0f;
        assert!(stdin_pipe_name(1, &r).ends_with("-0000000000000000000000000000000f"));
        assert_ne!(stdin_pipe_name(1, &[0; 16]), stdin_pipe_name(1, &r));
    }

    #[test]
    fn stdin_pipe_flags() {
        assert_eq!(STDIN_PIPE_OPEN_MODE.0 & 0x3, 0x2);
        assert_ne!(STDIN_PIPE_OPEN_MODE.0 & 0x0008_0000, 0);
        assert_eq!(STDIN_PIPE_OPEN_MODE.0 & 0x4000_0000, 0);
        assert_eq!(STDIN_PIPE_MODE.0, 0x8);
        assert_eq!(STDIN_PIPE_MAX_INSTANCES, 1);
        // GENERIC_READ | FILE_WRITE_ATTRIBUTES; SQOS present at level ANONYMOUS.
        assert_eq!(STDIN_CLIENT_ACCESS, 0x8000_0100);
        assert_eq!(STDIN_CLIENT_FLAGS.0, 0x0010_0000);
    }

    /// The runner's end reads like an anonymous pipe and cannot impersonate.
    #[test]
    fn stdin_pipe_runner_end_is_a_client_end() {
        let name = fresh_stdin_pipe_name().unwrap();
        let pipe = make_stdin_pipe_named(&name).unwrap();

        // Read first: until data has been read through it, even a server end
        // is refused impersonation.
        let payload = b"spec-bytes";
        let mut wrote = 0u32;
        unsafe { WriteFile(pipe.broker.raw(), Some(payload), Some(&mut wrote), None) }.unwrap();
        assert_eq!(wrote as usize, payload.len());
        let mut buf = [0u8; 64];
        let mut read = 0u32;
        unsafe { ReadFile(pipe.runner.raw(), Some(&mut buf), Some(&mut read), None) }.unwrap();
        assert_eq!(&buf[..read as usize], payload);

        let imp = unsafe { ImpersonateNamedPipeClient(pipe.runner.raw()) };
        if imp.is_ok() {
            unsafe { RevertToSelf().unwrap() };
            panic!("ImpersonateNamedPipeClient succeeded on the runner's stdin end");
        }
        let server_end = |h: HANDLE| {
            let mut flags = NAMED_PIPE_MODE(0);
            unsafe { GetNamedPipeInfo(h, Some(&mut flags), None, None, None) }
                .map(|()| flags.0 & PIPE_SERVER_END.0 != 0)
        };
        assert!(
            !server_end(pipe.runner.raw()).expect("GetNamedPipeInfo(runner end)"),
            "the runner's stdin end is the pipe's SERVER end"
        );
        // The write-only server end may not be queryable; when it is, it must
        // read as the server end, or the check above proves nothing.
        if let Ok(is_server) = server_end(pipe.broker.raw()) {
            assert!(is_server, "the broker's end is not the pipe's server end");
        }

        let name_w = wstr(&name);
        let again = unsafe {
            CreateFileW(
                pcwstr(&name_w),
                STDIN_CLIENT_ACCESS,
                FILE_SHARE_MODE(0),
                None,
                OPEN_EXISTING,
                STDIN_CLIENT_FLAGS,
                None,
            )
        };
        let busy = again.expect_err("a second client connected to the stdin pipe");
        assert_eq!(busy.code(), ERROR_PIPE_BUSY.to_hresult());
        assert!(is_pipe_busy(
            &anyhow::Error::from(busy).context("CreateFileW(runner stdin client end)")
        ));
        assert!(
            make_stdin_pipe_named(&name).is_err(),
            "a second server was created under the stdin pipe's name"
        );

        // ERROR_BROKEN_PIPE is what a reader treats as EOF.
        drop(pipe.broker);
        let eof = unsafe { ReadFile(pipe.runner.raw(), Some(&mut buf), Some(&mut read), None) };
        assert_eq!(
            eof.unwrap_err().code(),
            ERROR_BROKEN_PIPE.to_hresult(),
            "reader must see ERROR_BROKEN_PIPE after the writer closes"
        );
    }

    #[test]
    fn a_busy_stdin_pipe_is_retried_once() {
        let busy = || anyhow::Error::from(windows::core::Error::from(ERROR_PIPE_BUSY));
        let other = || anyhow::Error::from(windows::core::Error::from(ERROR_BROKEN_PIPE));
        assert!(is_pipe_busy(&busy().context("connect")));
        assert!(!is_pipe_busy(&other().context("connect")));
        assert!(!is_pipe_busy(&anyhow!("not a system error")));

        let mut calls = 0;
        let r = once_more_if_pipe_busy(|| {
            calls += 1;
            if calls == 1 { Err(busy()) } else { Ok(calls) }
        });
        assert_eq!((r.unwrap(), calls), (2, 2));

        let mut calls = 0;
        let r: Result<()> = once_more_if_pipe_busy(|| {
            calls += 1;
            Err(busy())
        });
        assert!(r.is_err_and(|e| is_pipe_busy(&e)));
        assert_eq!(calls, 2);

        let mut calls = 0;
        let r: Result<()> = once_more_if_pipe_busy(|| {
            calls += 1;
            Err(other())
        });
        assert!(r.is_err());
        assert_eq!(calls, 1);
    }

    #[test]
    fn drive_letter_root() {
        assert_eq!(cwd_drive_root(r"Z:\work\repo"), Some(r"Z:\".into()));
        assert_eq!(cwd_drive_root("c:/work"), Some(r"C:\".into()));
        assert_eq!(cwd_drive_root("relative"), None);
    }

    #[test]
    fn unc_root() {
        assert_eq!(
            cwd_drive_root(r"\\srv\share\dir\f"),
            Some(r"\\srv\share\".into()),
        );
        assert_eq!(cwd_drive_root(r"\\srv\share"), Some(r"\\srv\share\".into()));
        // server-only (no share) is not a valid UNC root
        assert_eq!(cwd_drive_root(r"\\srv"), None);
    }

    #[test]
    fn device_and_extended_prefix_skipped() {
        // `\\?\` / `\\.\` are extended/device prefixes, not UNC —
        // left to the CPWLW post-check.
        assert_eq!(cwd_drive_root(r"\\?\C:\x"), None);
        assert_eq!(cwd_drive_root(r"\\.\pipe\x"), None);
    }
}
