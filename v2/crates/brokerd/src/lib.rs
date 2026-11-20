//! `credmgr-brokerd` — the broker library. `main.rs` is a thin binary
//! wrapper; everything testable lives here so the isolation suite
//! (`tests/isolation.rs`) can drive it directly. See
//! `docs/02_ARCHITECTURE.md §1-3`, `docs/06_ACCESS_GRAPH.md §4`,
//! `docs/10_API_AND_MCP.md §1`.
//!
//! `unsafe_code = "deny"` (this crate's own `Cargo.toml`, not the workspace
//! default of `forbid` — see the `[lints.rust]` comment there): `peer.rs`
//! carries a scoped `#![allow(unsafe_code)]` for raw peer-credential
//! syscalls, justified in that module's own doc comment; so do
//! `state/rotate/vault_lock.rs` (`flock`, ADR-076) and `locked_key.rs`
//! (`mlock` for hot key pages, ADR-156).

pub mod auth_backoff;
pub mod diag_log;
pub mod entry_doc;
pub mod locked_key;
pub mod maintenance;
pub mod ops;
#[cfg(unix)]
pub mod peer;
pub mod protocol;
pub mod rate_limit;
pub mod scope;
#[cfg(unix)]
pub mod server;
pub mod stable;
pub mod state;
pub mod token;
