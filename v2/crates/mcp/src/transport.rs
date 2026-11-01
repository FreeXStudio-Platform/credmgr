//! Talks to `credmgrd` over its local socket — `docs/10_API_AND_MCP.md §1`:
//! newline-delimited JSON, request/response with an `id`. This is the *only*
//! place this crate touches the wire; no tool here ever opens an envelope
//! or reads a key file directly.
//!
//! Deliberately duplicated from `crates/cli/src/transport.rs` rather than
//! shared via a dependency — `credmgr-cli` already depends on
//! `credmgr-mcp` (it hosts the `credmgr mcp` subcommand), so the reverse
//! dependency would be circular, and ~80 lines of self-contained socket
//! plumbing is exactly the kind of thing this codebase already duplicates
//! on purpose rather than couple two crates over (see
//! `credmgr-keystore/src/software.rs`'s `default_state_dir` for the same
//! call, made explicitly, for the same reason).

use std::fmt;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use credmgr_store::paths::VaultPaths;

#[derive(Debug)]
pub enum TransportError {
    /// Could not reach `credmgrd` at all — most often "it isn't running".
    Connect(std::io::Error),
    Io(std::io::Error),
    Malformed(String),
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportError::Connect(e) => {
                write!(f, "could not connect to credmgrd: {e} (is it running?)")
            }
            TransportError::Io(e) => write!(f, "i/o error talking to credmgrd: {e}"),
            TransportError::Malformed(detail) => {
                write!(
                    f,
                    "credmgrd sent a response this client could not parse: {detail}"
                )
            }
        }
    }
}

/// `CREDMGR_VAULT_DIR` is the same override `crates/store::paths` already
/// honours — reusing it (rather than inventing a second, socket-specific
/// env var) is what lets a test point an entire vault, socket included, at
/// one temp directory.
pub fn socket_path() -> PathBuf {
    VaultPaths::default_location().run_socket()
}

/// Send one request, read exactly one response line back — no token, so
/// the broker resolves scope from this process's own cwd/peer credentials
/// (`docs/13_TEST_PLAN.md` I-11: "resolves to a node with no token"), which
/// is exactly the MCP transport's whole scoping model
/// (`10_API_AND_MCP.md §3.4`: "the server inherits the agent session's cwd").
pub fn call(op: &str, params: Value) -> Result<Value, TransportError> {
    call_at(&socket_path(), op, params)
}

pub fn call_at(socket: &Path, op: &str, params: Value) -> Result<Value, TransportError> {
    let stream =
        std::os::unix::net::UnixStream::connect(socket).map_err(TransportError::Connect)?;
    let mut writer = stream.try_clone().map_err(TransportError::Io)?;
    let mut reader = BufReader::new(stream);

    let request = json!({ "id": "1", "op": op, "token": Value::Null, "params": params });
    writeln!(writer, "{request}").map_err(TransportError::Io)?;

    let mut line = String::new();
    reader.read_line(&mut line).map_err(TransportError::Io)?;
    if line.trim().is_empty() {
        return Err(TransportError::Malformed(
            "credmgrd closed the connection with no response".into(),
        ));
    }
    serde_json::from_str(&line).map_err(|e| TransportError::Malformed(e.to_string()))
}
