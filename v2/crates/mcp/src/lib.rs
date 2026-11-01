//! `credmgr-mcp` — the MCP stdio server, exposed to users as `credmgr mcp`
//! (a subcommand of the single `credmgr` binary, not a separate artefact —
//! "one artefact to sign, one to trust", `v2/docs/16_CROSS_PLATFORM.md` §2).
//!
//! Phase 5: [`tools`] is the live tool registry, [`server`] is the JSON-RPC
//! stdio loop that serves it, [`transport`] is how each tool call reaches
//! `credmgrd` — the same UDS wire protocol `credmgr-cli` uses, never a
//! direct call into broker state. `docs/13_TEST_PLAN.md`'s I-13 (this
//! crate's `tests/i13_tool_registry.rs`) is the anti-regression gate for
//! every tool this crate ever exposes: it enumerates [`tools::registry`],
//! so an addition mapping to the forbidden list (`docs/10_API_AND_MCP.md`
//! §3.2) fails the test by construction.
#![forbid(unsafe_code)]

pub mod server;
pub mod tools;
pub mod transport;
