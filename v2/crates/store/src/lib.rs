//! `credmgr-store` — everything that touches the filesystem for the vault:
//! on-disk layout, atomic writes, the signed registry/manifest pair, the
//! hash-chained audit log, the seal archive, and the generation counter that
//! detects a rolled-back registry.
//!
//! `crates/core` stays pure; this crate is where its pure primitives (seal/
//! open, `resolve()`, HMAC signing) meet real files. See
//! `docs/02_ARCHITECTURE.md §7`, `docs/03_DATA_MODEL.md §2, §8, §9`.
#![forbid(unsafe_code)]

pub mod archive;
pub mod atomic;
pub mod audit;
pub mod backup;
pub mod entry_archive;
pub mod error;
pub mod generation;
mod hexutil;
pub mod manifest;
pub mod paths;
pub mod rebuild;
pub mod registry_file;
pub mod rotation;
pub mod rotation_history;
pub mod verify;

pub use error::StoreError;
