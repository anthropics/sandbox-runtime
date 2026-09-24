//! `srt-win` — Windows network sandbox helper for sandbox-runtime.
//!
//! This crate is the Rust half of the Windows backend. The library
//! exposes the SID, group, and WFP primitives so they can be unit-
//! tested, plus the full CLI dispatch as [`run_from_args`] so an
//! embedding multicall binary can link the crate directly. The
//! `srt-win` binary (`main.rs`) is a one-line shim over that entry
//! point.
//!
//! Windows-only. Building on other platforms yields an empty crate so
//! `cargo check` from a non-Windows host doesn't error.

#![cfg(windows)]

pub mod cli;
pub use cli::{SRT_WIN_DISPATCH_ARG1, run_from_args};

pub mod sam;
pub mod sid;
pub mod util;
pub mod wfp;

pub mod job;
pub mod launch;
pub mod self_protect;
pub mod token;
pub mod winsta;

pub mod acl;
pub mod ambient;
pub mod path_id;
pub mod reg;
pub mod state_db;

pub mod dpapi;
pub mod install;
pub mod user;

pub mod cert_store;
pub mod logon;
pub mod runner;
