//! `srt-win runner` — the inside-the-logon half of the two-hop
//! launch.
//!
//! The broker (running as the **real** user) decrypts the sandbox
//! user's password and `CreateProcessWithLogonW`s **this**
//! subcommand under the `srt-sandbox` account. The runner reads a
//! [`RunnerCmd`] from stdin and either runs
//! [`crate::launch::run_lockdown`] (restricted token, job, desktop,
//! mitigations, handle whitelist), or — at install time — writes
//! the MITM CA into the sandbox user's `CurrentUser\Root` (see
//! [`crate::cert_store`]). The child inherits the runner's stdio,
//! which are the broker's pipes, so stdin flows broker → child and
//! stdout/stderr flow broker ← child without an extra pump.
//!
//! All state-DB work happens in the **broker**, never here: the
//! state-DB directory carries an explicit DENY for
//! `sandbox-runtime-users`, so the runner cannot open it.

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::os::windows::io::{AsRawHandle, FromRawHandle};

use crate::launch;

/// What the broker asks the runner to do. Passed over stdin (4-byte
/// LE length prefix + JSON). Stdin — not argv or env — because the
/// env overlay can exceed what `lpCommandLine` reliably carries, and
/// a temp file would need a path the sandbox user can read (the
/// broker's `%TEMP%` may not be).
#[derive(Debug, Serialize, Deserialize)]
pub enum RunnerCmd {
    /// Per-exec: run the target under [`crate::launch::run_lockdown`].
    Exec(RunnerSpec),
    /// Install-time, one-shot: write the DER-encoded CA into the
    /// **sandbox user's** `CurrentUser\Root` (direct
    /// `HKEY_USERS\<own-SID>\…\Root\Certificates\<thumb>` registry
    /// write — see [`crate::cert_store`]). Persistent until
    /// `srt-win uninstall` deletes the profile. Exit non-zero on
    /// failure.
    InstallCa { der: crate::cert_store::CertDer },
    /// `wfp verify` probe: attempt a direct TCP connect to `target`
    /// (`host:port`) **as the sandbox user**. The WFP block-user
    /// filter fires at `ALE_AUTH_CONNECT` — before any packet
    /// leaves — so an active fence yields WSAEACCES immediately;
    /// a missing fence lets the connect through. Exit **0** =
    /// WSAEACCES (fence active), **3** = connected (fence
    /// MISSING), **2** = any other error (timeout/unreachable —
    /// the broker treats it as failure). Exit 1 is reserved for
    /// the runner's own anyhow `Err` path so a malformed target
    /// or future runner bug isn't misread as `connected`. No
    /// desk/grants/lockdown — the probe runs as the bare runner
    /// (same as [`InstallCa`](Self::InstallCa)); the WFP filter
    /// keys on the user SID, which the runner already carries.
    ProbeEgress { target: String },
}

/// Inputs to a single [`RunnerCmd::Exec`].
#[derive(Debug, Serialize, Deserialize)]
pub struct RunnerSpec {
    /// `argv[0]` = target executable; `argv[1..]` = its arguments.
    pub argv: Vec<String>,
    /// `(KEY, VALUE)` pairs overlaid on the runner's own environment
    /// (= the sandbox user's `LOGON_WITH_PROFILE` defaults) when
    /// building the child's env block. Overlay wins on key conflict
    /// (case-insensitive), so the broker's `PATH` replaces the
    /// sandbox user's machine-only `PATH` while `USERPROFILE` /
    /// `TEMP` stay isolated. The proxy var set rides here too.
    pub env_overlay: Vec<(String, String)>,
}

/// Read a 4-byte little-endian length prefix followed by that many
/// bytes of JSON from stdin. The length prefix lets the runner know
/// when the spec ends without the broker closing the write end: for
/// `Exec` the broker keeps relaying the caller's stdin after the
/// spec, and the child inherits this handle to read the rest.
fn read_cmd_from_stdin() -> Result<RunnerCmd> {
    // Unbuffered: `std::io::stdin()` reads ahead, which would take
    // bytes past the spec that belong to the child.
    let mut stdin = std::mem::ManuallyDrop::new(unsafe {
        std::fs::File::from_raw_handle(std::io::stdin().as_raw_handle())
    });
    let mut len_buf = [0u8; 4];
    stdin
        .read_exact(&mut len_buf)
        .context("runner: read spec length prefix from stdin")?;
    let len = u32::from_le_bytes(len_buf) as usize;
    // Sanity cap — the spec is a few KB; anything in the MB range
    // means the broker/runner are out of sync.
    if len > 4 * 1024 * 1024 {
        return Err(anyhow!(
            "runner: spec length {len} exceeds 4 MiB sanity cap"
        ));
    }
    let mut buf = vec![0u8; len];
    stdin
        .read_exact(&mut buf)
        .context("runner: read spec body from stdin")?;
    serde_json::from_slice(&buf).context("runner: parse spec JSON")
}

/// Serialize `cmd` as `<u32 LE length><JSON>`. Broker-side helper —
/// lives here so the wire format has one definition.
pub fn encode_cmd(cmd: &RunnerCmd) -> Result<Vec<u8>> {
    let json = serde_json::to_vec(cmd).context("runner: encode cmd")?;
    let mut out = Vec::with_capacity(4 + json.len());
    out.extend_from_slice(&(json.len() as u32).to_le_bytes());
    out.extend_from_slice(&json);
    Ok(out)
}

/// Entry point for `srt-win runner`. Reads the command from stdin,
/// dispatches, and returns the exit code.
pub fn run() -> Result<u32> {
    match read_cmd_from_stdin()? {
        RunnerCmd::Exec(spec) => {
            if spec.argv.is_empty() {
                return Err(anyhow!("runner: spec.argv is empty"));
            }
            if std::env::var_os("SANDBOX_RUNTIME_WIN_DEBUG").is_some() {
                eprintln!(
                    "srt-win: runner: spec read (argv={} env_overlay={})",
                    spec.argv.len(),
                    spec.env_overlay.len(),
                );
            }
            let exe = std::path::PathBuf::from(&spec.argv[0]);
            launch::run_lockdown(&exe, &spec.argv[1..], &spec.env_overlay)
        }
        RunnerCmd::InstallCa { der } => {
            let thumb = crate::cert_store::install_root_ca(&der)?;
            eprintln!(
                "srt-win: runner: CA installed into sandbox-user \
                 CurrentUser\\Root (thumb={thumb})"
            );
            Ok(0)
        }
        RunnerCmd::ProbeEgress { target } => {
            use std::net::{SocketAddr, TcpStream};
            use std::time::Duration;
            // WSAEACCES — what WFP returns from ALE_AUTH_CONNECT
            // when the block-user filter denies the connect. Match
            // on the raw code (not `ErrorKind::PermissionDenied`)
            // so `ERROR_ACCESS_DENIED` (5) — which would mean
            // something OTHER than the WFP fence — falls through
            // to `unreachable`.
            const WSAEACCES: i32 = 10013;
            let addr: SocketAddr = target
                .parse()
                .with_context(|| format!("runner: ProbeEgress target '{target}'"))?;
            // stderr (not stdout): `spawn_runner` pumps the
            // runner's stdout straight to the broker's stdout, and
            // the broker writes its own JSON there. The exit code
            // is the contract; the line is diagnostic.
            match TcpStream::connect_timeout(&addr, Duration::from_secs(2)) {
                Err(e) if e.raw_os_error() == Some(WSAEACCES) => {
                    eprintln!(
                        "srt-win: runner: egress probe {target}: \
                         BLOCKED ({e})"
                    );
                    Ok(0)
                }
                Ok(_) => {
                    eprintln!(
                        "srt-win: runner: egress probe {target}: \
                         CONNECTED — WFP block-user filter is NOT in \
                         effect"
                    );
                    Ok(3)
                }
                Err(e) => {
                    eprintln!(
                        "srt-win: runner: egress probe {target}: \
                         UNREACHABLE: {e} (kind={:?}, os={:?})",
                        e.kind(),
                        e.raw_os_error(),
                    );
                    Ok(2)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cmd_roundtrip() {
        let s = RunnerCmd::Exec(RunnerSpec {
            argv: vec!["cmd.exe".into(), "/c".into(), "echo hi".into()],
            env_overlay: vec![("PATH".into(), r"C:\a;C:\b".into())],
        });
        let bytes = encode_cmd(&s).unwrap();
        assert_eq!(
            u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize,
            bytes.len() - 4
        );
        let back: RunnerCmd = serde_json::from_slice(&bytes[4..]).unwrap();
        match back {
            RunnerCmd::Exec(r) => {
                assert_eq!(r.argv, ["cmd.exe", "/c", "echo hi"]);
                assert_eq!(r.env_overlay.len(), 1);
            }
            _ => panic!("wrong variant"),
        }
        let ca = RunnerCmd::InstallCa {
            der: crate::cert_store::CertDer::raw(vec![0x30, 0x82]),
        };
        let bytes = encode_cmd(&ca).unwrap();
        let back: RunnerCmd = serde_json::from_slice(&bytes[4..]).unwrap();
        assert!(matches!(
            back, RunnerCmd::InstallCa { der } if der.as_bytes() == [0x30, 0x82]
        ));
        let probe = RunnerCmd::ProbeEgress {
            target: "127.0.0.1:49999".into(),
        };
        let bytes = encode_cmd(&probe).unwrap();
        let back: RunnerCmd = serde_json::from_slice(&bytes[4..]).unwrap();
        assert!(matches!(
            back, RunnerCmd::ProbeEgress { target } if target == "127.0.0.1:49999"
        ));
    }
}
