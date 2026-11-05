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
//! which are the broker's pipes, so stdout/stderr flow broker ←
//! runner ← child without an extra pump.
//!
//! All state-DB work happens in the **broker**, never here: the
//! state-DB directory carries an explicit DENY for
//! `sandbox-runtime-users`, so the runner cannot open it.

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use std::io::Read;

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
    /// `wfp verify` probe ([`crate::probe`]), run as the bare runner:
    /// no desk/grants/lockdown. Exits with the results encoded; exit 1
    /// stays the runner's own error path and never decodes as a report.
    ///
    /// Probes the runner's own token only; the write-restricted verify
    /// sends an [`Exec`](Self::Exec) of `srt-win probe egress`.
    ProbeEgress {
        target: String,
        #[serde(default)]
        anonymous_target: Option<String>,
        /// Also make the anonymous off-loopback attempt.
        #[serde(default)]
        anonymous_egress: bool,
        /// Loopback is open: see [`crate::probe::run`].
        #[serde(default)]
        allow_loopback: bool,
    },
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
    /// Build the child token write-restricted (see [`crate::token`]).
    #[serde(default)]
    pub write_restricted_token: bool,
    /// Capability SIDs of the session's write roots (`crate::persist`),
    /// added to the child token's restricting SIDs. Only with
    /// `write_restricted_token`.
    #[serde(default)]
    pub capability_sids: Vec<String>,
}

/// Read a 4-byte little-endian length prefix followed by that many
/// bytes of JSON from stdin. The length prefix lets the runner know
/// when the spec ends without the broker closing the write end
/// (which it does anyway — the prefix is just robustness against a
/// future stdin-after-spec use).
fn read_cmd_from_stdin() -> Result<RunnerCmd> {
    let mut stdin = std::io::stdin().lock();
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
            launch::run_lockdown(
                &exe,
                &spec.argv[1..],
                &spec.env_overlay,
                spec.write_restricted_token,
                &spec.capability_sids,
            )
        }
        RunnerCmd::InstallCa { der } => {
            let thumb = crate::cert_store::install_root_ca(&der)?;
            eprintln!(
                "srt-win: runner: CA installed into sandbox-user \
                 CurrentUser\\Root (thumb={thumb})"
            );
            Ok(0)
        }
        RunnerCmd::ProbeEgress {
            target,
            anonymous_target,
            anonymous_egress,
            allow_loopback,
        } => Ok(crate::probe::run(
            &target,
            anonymous_target.as_deref(),
            anonymous_egress,
            allow_loopback,
        )?
        .encode()),
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
            write_restricted_token: true,
            capability_sids: vec!["S-1-0-1936880739-1-2-3-4".into()],
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
                assert!(r.write_restricted_token);
                assert_eq!(r.capability_sids, ["S-1-0-1936880739-1-2-3-4"]);
            }
            _ => panic!("wrong variant"),
        }
        // A spec without the field is the ordinary token.
        let legacy = br#"{"Exec":{"argv":["cmd.exe"],"env_overlay":[]}}"#;
        match serde_json::from_slice::<RunnerCmd>(legacy).unwrap() {
            RunnerCmd::Exec(r) => {
                assert!(!r.write_restricted_token);
                assert!(r.capability_sids.is_empty());
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
            anonymous_target: Some("192.0.2.7:49999".into()),
            anonymous_egress: true,
            allow_loopback: true,
        };
        let bytes = encode_cmd(&probe).unwrap();
        let back: RunnerCmd = serde_json::from_slice(&bytes[4..]).unwrap();
        assert!(matches!(
            back,
            RunnerCmd::ProbeEgress {
                target,
                anonymous_target,
                anonymous_egress: true,
                allow_loopback: true,
            } if target == "127.0.0.1:49999"
                    && anonymous_target.as_deref() == Some("192.0.2.7:49999")
        ));
        // The off-loopback target and the two switches are optional on
        // the wire; the switches default to off.
        let back: RunnerCmd =
            serde_json::from_str(r#"{"ProbeEgress":{"target":"127.0.0.1:1"}}"#).unwrap();
        assert!(matches!(
            back,
            RunnerCmd::ProbeEgress {
                anonymous_target: None,
                anonymous_egress: false,
                allow_loopback: false,
                ..
            }
        ));
    }
}
