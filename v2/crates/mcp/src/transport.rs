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
    /// ADR-164 review P2-9: `CREDMGR_AGENT_TOKEN` is set to something that is not an agent token, so nothing is sent.
    Config(String),
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
            TransportError::Config(detail) => write!(f, "{detail}"),
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

/// ADR-164: the environment variable an agent client sets to an agent token
/// (`credmgr agent token issue`). It is the only token this server ever presents.
pub const AGENT_TOKEN_ENV: &str = "CREDMGR_AGENT_TOKEN";

/// The prefix every agent token carries (`credmgr_brokerd::token::AGENT_BEARER_PREFIX`,
/// restated: this crate does not depend on the broker).
const AGENT_TOKEN_PREFIX: &str = "cma_";

/// ADR-164: what the server presents, read from [`AGENT_TOKEN_ENV`].
/// `Ok(None)` when unset or empty: the broker scopes the session from its cwd, as
/// before. `Err` when set to anything that is not an agent token — above all a
/// login (`cmt_…`, which `credmgr unlock` prints as `CREDMGR_TOKEN`): this server
/// must never carry the owner's reach into an agent's hands (K-6), so it refuses
/// to start rather than guess. `CREDMGR_TOKEN` itself is never read here.
pub fn agent_token_from_env() -> Result<Option<String>, String> {
    agent_token_from(std::env::var(AGENT_TOKEN_ENV).ok())
}

/// [`agent_token_from_env`] for a given value (the testable half).
pub fn agent_token_from(raw: Option<String>) -> Result<Option<String>, String> {
    let Some(raw) = raw else { return Ok(None) };
    let token = raw.trim();
    if token.is_empty() {
        return Ok(None);
    }
    let shaped = token.len() == AGENT_TOKEN_PREFIX.len() + 64
        && token.starts_with(AGENT_TOKEN_PREFIX)
        && token[AGENT_TOKEN_PREFIX.len()..]
            .bytes()
            .all(|b| b.is_ascii_hexdigit());
    if !shaped {
        // Never echo the value: it may be a login.
        return Err(format!(
            "{AGENT_TOKEN_ENV} is set but does not hold an agent token (cma_ followed by 64 hex digits); \
             issue one with `credmgr agent token issue`. A login token is never accepted here."
        ));
    }
    Ok(Some(token.to_string()))
}

/// Send one request, read exactly one response line back. With no agent token
/// in [`AGENT_TOKEN_ENV`] it presents none, so the broker resolves scope from
/// this process's own cwd/peer credentials (`docs/13_TEST_PLAN.md` I-11:
/// "resolves to a node with no token") — the MCP transport's default scoping
/// model (`10_API_AND_MCP.md §3.4`: "the server inherits the agent session's
/// cwd"). With one (ADR-164) the token overrides, as `06 §4` step 1 says. A
/// malformed value refuses the call (review P2-9): `credmgr mcp` refuses to start
/// on it, but an embedder that skipped that check must not fall back to the cwd
/// scope silently either.
pub fn call(op: &str, params: Value) -> Result<Value, TransportError> {
    let token = token_for_call(std::env::var(AGENT_TOKEN_ENV).ok())?;
    call_with(&socket_path(), op, token.as_deref(), params)
}

/// What [`call`] presents for a given value of [`AGENT_TOKEN_ENV`]: nothing when unset, the token when it is one,
/// and a refusal (nothing sent) when it is set to anything else.
fn token_for_call(raw: Option<String>) -> Result<Option<String>, TransportError> {
    agent_token_from(raw).map_err(TransportError::Config)
}

pub fn call_at(socket: &Path, op: &str, params: Value) -> Result<Value, TransportError> {
    call_with(socket, op, None, params)
}

/// [`call_at`] presenting `token` (an agent token) when given.
pub fn call_with(
    socket: &Path,
    op: &str,
    token: Option<&str>,
    params: Value,
) -> Result<Value, TransportError> {
    let stream =
        std::os::unix::net::UnixStream::connect(socket).map_err(TransportError::Connect)?;
    let mut writer = stream.try_clone().map_err(TransportError::Io)?;
    let mut reader = BufReader::new(stream);

    let token = token.map_or(Value::Null, |t| Value::String(t.to_string()));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_an_agent_token_is_ever_presented() {
        assert_eq!(agent_token_from(None), Ok(None));
        assert_eq!(agent_token_from(Some("  ".into())), Ok(None));
        let agent = format!("cma_{}", "0f".repeat(32));
        assert_eq!(
            agent_token_from(Some(format!(" {agent}\n"))),
            Ok(Some(agent.clone()))
        );
        // A login, a truncated token, a token with a non-hex character: refused, and the
        // refusal never repeats the value.
        let login = format!("cmt_{}", "0f".repeat(16));
        for bad in [
            login.clone(),
            agent[..20].to_string(),
            format!("{}z", &agent[..67]),
        ] {
            let err = agent_token_from(Some(bad.clone())).unwrap_err();
            assert!(!err.contains(&bad), "{err}");
            // Review P2-9: a call with such a value is refused, never sent without a token.
            let refused = token_for_call(Some(bad.clone())).unwrap_err();
            assert!(matches!(refused, TransportError::Config(_)));
            assert!(!refused.to_string().contains(&bad));
        }
        assert_eq!(token_for_call(None).unwrap(), None);
    }
}
