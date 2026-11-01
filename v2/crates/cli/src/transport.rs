//! Talks to `credmgrd` over its local socket — `docs/10_API_AND_MCP.md §1`:
//! newline-delimited JSON, request/response with an `id`. This is the *only*
//! place `credmgr` touches the wire; nothing in this crate ever opens an
//! envelope or reads a key file directly (Phase 4 exit gate: "none decrypts
//! directly").

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

/// Send one request, read exactly one response line back. `credmgrd` is a
/// one-request-then-response-per-line protocol (`server.rs`'s
/// `serve_connection` loop) — this function does not keep the connection
/// open past a single round trip, which keeps the CLI's transport as simple
/// as the protocol actually is.
pub fn call(op: &str, token: Option<&str>, params: Value) -> Result<Value, TransportError> {
    call_at(&socket_path(), op, token, params)
}

pub fn call_at(
    socket: &Path,
    op: &str,
    token: Option<&str>,
    params: Value,
) -> Result<Value, TransportError> {
    let stream =
        std::os::unix::net::UnixStream::connect(socket).map_err(TransportError::Connect)?;
    let mut writer = stream.try_clone().map_err(TransportError::Io)?;
    let mut reader = BufReader::new(stream);

    let request = json!({ "id": "1", "op": op, "token": token, "params": params });
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
