//! `credmgr-core` — pure, I/O-free crypto, envelopes, registry types and the
//! access graph resolver. See `v2/docs/02_ARCHITECTURE.md` §9.
//!
//! No file, socket, clock, or environment access anywhere in this crate —
//! that purity is what makes the access rules exhaustively testable. Anything
//! that needs the current time (grant expiry) or "what's locked right now"
//! takes it as an explicit parameter instead of calling out for it.
#![forbid(unsafe_code)]

pub mod access;
pub mod cold;
pub mod envelope;
pub mod error;
pub mod fields;
pub mod generate;
pub mod inference;
pub mod keys;
pub mod names;
pub mod parser;
pub mod recovery;
pub mod registry;
pub mod signing;
pub mod totp;
