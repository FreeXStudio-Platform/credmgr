//! One request, one response, over the broker's Unix domain socket.
//!
//! Mirrors `crates/cli/src/transport.rs` — deliberately, because that file is
//! the reference implementation of `10_API_AND_MCP.md §1` and reinventing the
//! framing would be the one place a second client could disagree with the
//! first about what the protocol is. Same shape: connect, write one
//! newline-terminated JSON object, read exactly one line back, close.
//!
//! Three things this adds over the CLI's copy, each because a GUI has a
//! constraint a one-shot CLI process does not:
//!
//! 1. **A read timeout.** A CLI that hangs is a terminal the user can Ctrl-C.
//!    A desktop app that hangs is a frozen window. If the deadline passes the
//!    call fails — note that the broker may still have *performed* the
//!    operation; a timeout is "I did not learn the answer", never "it did not
//!    happen".
//! 2. **The response `id` is checked against the request's.** The CLI sends a
//!    constant `"1"` and does not verify the echo. Reading a reply that
//!    belongs to a different request would be a serious bug, and on a
//!    one-round-trip-per-connection protocol it costs one comparison to make
//!    it impossible to miss.
//! 3. **Unix-only, explicitly.** `credmgrd` itself is Unix-only today —
//!    `server.rs` binds `std::os::unix::net::UnixListener`, so there is no
//!    Windows named pipe on the other end to talk to yet
//!    (`16_CROSS_PLATFORM.md` plans one). Rather than fail to compile on
//!    Windows, this returns an honest "unsupported on this platform" error,
//!    so the desktop shell still builds everywhere and says why.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde_json::{json, Value};

use crate::error::BridgeError;

/// Generous enough for `vault.unlock`, which does Argon2id key derivation
/// before it answers; short enough that a wedged broker does not leave the
/// window spinning indefinitely.
pub const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Monotonic per-process request id. Not a clock and not random — the
/// engine's determinism convention — and only ever used to prove a response
/// belongs to the request that produced it.
static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

fn next_request_id() -> String {
    NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed).to_string()
}

/// Send one op and return its `value` on success, or the typed denial.
///
/// `token` is attached here, Rust-side. Nothing above this function in the
/// call graph hands a token to the webview — see [`crate::session`].
pub fn call(
    socket: &std::path::Path,
    op: &str,
    token: Option<&str>,
    params: Value,
) -> Result<Value, BridgeError> {
    call_audited(socket, op, token, params).map(|(value, _audit)| value)
}

/// [`call`], also returning the `audit` id the broker's envelope carries beside
/// `value` (ADR-077: "every decision appends one audit record"). `None` when the
/// envelope has none (the record is best-effort on a locked vault). The shell
/// hands it to the page for the changing ops only (`commands::AUDIT_PASSTHROUGH`).
#[cfg(unix)]
pub fn call_audited(
    socket: &std::path::Path,
    op: &str,
    token: Option<&str>,
    params: Value,
) -> Result<(Value, Option<String>), BridgeError> {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;

    let stream = UnixStream::connect(socket).map_err(|e| {
        BridgeError::transport(format!(
            "could not connect to credmgrd at {}: {e} (is it running?)",
            socket.display()
        ))
    })?;
    stream
        .set_read_timeout(Some(READ_TIMEOUT))
        .map_err(|e| BridgeError::transport(format!("could not set a read timeout: {e}")))?;

    let mut writer = stream
        .try_clone()
        .map_err(|e| BridgeError::transport(format!("could not clone the socket: {e}")))?;
    let mut reader = BufReader::new(stream);

    let id = next_request_id();
    let request = json!({ "id": id, "op": op, "token": token, "params": params });
    writeln!(writer, "{request}")
        .map_err(|e| BridgeError::transport(format!("could not send the request: {e}")))?;

    // The reply line may be a revealed secret (`entry.reveal`, and `entry_copy`
    // above it), so the buffer that holds it is wiped when this function returns.
    // `BufReader`'s own 8 KiB buffer and the kernel's socket buffer are not
    // reachable from here: this narrows the number of plaintext copies, it does
    // not claim to remove them (see `crate::clipboard`, "Memory").
    let mut line = zeroize::Zeroizing::new(String::new());
    reader.read_line(&mut line).map_err(|e| {
        BridgeError::transport(format!(
            "no response from credmgrd within {READ_TIMEOUT:?}: {e}"
        ))
    })?;

    interpret_audited(&id, &line)
}

#[cfg(not(unix))]
pub fn call_audited(
    _socket: &std::path::Path,
    _op: &str,
    _token: Option<&str>,
    _params: Value,
) -> Result<(Value, Option<String>), BridgeError> {
    Err(BridgeError::bridge(
        "platform_unsupported",
        "credmgrd speaks a Unix domain socket; this platform has no transport to it yet \
         (16_CROSS_PLATFORM.md plans a Windows named pipe)",
    ))
}

/// The pure half — parse and adjudicate one response line. Split out so the
/// protocol rules are testable without a socket.
pub fn interpret(request_id: &str, line: &str) -> Result<Value, BridgeError> {
    interpret_audited(request_id, line).map(|(value, _audit)| value)
}

/// [`interpret`], keeping the envelope's `audit` id (a string, or `None`).
pub fn interpret_audited(
    request_id: &str,
    line: &str,
) -> Result<(Value, Option<String>), BridgeError> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Err(BridgeError::transport(
            "credmgrd closed the connection without answering",
        ));
    }
    let mut body: Value = serde_json::from_str(trimmed)
        .map_err(|e| BridgeError::protocol(format!("response was not JSON: {e}")))?;

    // `server.rs` answers an unparseable frame with `id: "?"` — a real
    // response to a real failure, not a desynchronised stream, so it is
    // adjudicated below like any other denial rather than rejected here.
    let echoed = body.get("id").and_then(Value::as_str).unwrap_or_default();
    if echoed != request_id && echoed != "?" {
        return Err(BridgeError::protocol(format!(
            "response id {echoed:?} does not match request id {request_id:?}"
        )));
    }

    match body.get("ok").and_then(Value::as_bool) {
        // Moved out, not cloned: a clone would leave a second copy of a revealed
        // secret in `body` until it is dropped.
        Some(true) => {
            let audit = body
                .get("audit")
                .and_then(Value::as_str)
                .map(str::to_string);
            let value = body
                .get_mut("value")
                .map(Value::take)
                .unwrap_or(Value::Null);
            Ok((value, audit))
        }
        Some(false) => Err(BridgeError::from_wire(&body)),
        None => Err(BridgeError::protocol(
            "response carried no boolean 'ok' field".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_matching_ok_frame_yields_its_value() {
        let out = interpret("4", r#"{"id":"4","ok":true,"value":{"locked":false}}"#).unwrap();
        assert_eq!(out["locked"], false);
    }

    #[test]
    fn the_envelopes_audit_id_is_kept_beside_the_value() {
        let (value, audit) = interpret_audited(
            "4",
            r#"{"id":"4","ok":true,"value":{"generation":3},"audit":"a_0123"}"#,
        )
        .unwrap();
        assert_eq!(value["generation"], 3);
        assert_eq!(audit.as_deref(), Some("a_0123"));
        // `interpret` still answers the value alone: nothing else changed shape.
        let plain = interpret(
            "4",
            r#"{"id":"4","ok":true,"value":{"generation":3},"audit":"a_0123"}"#,
        )
        .unwrap();
        assert!(plain.get("audit").is_none());
        let (_, none) = interpret_audited("5", r#"{"id":"5","ok":true,"value":{}}"#).unwrap();
        assert_eq!(none, None);
        // A non-string audit member is not an id.
        let (_, odd) =
            interpret_audited("6", r#"{"id":"6","ok":true,"value":{},"audit":7}"#).unwrap();
        assert_eq!(odd, None);
    }

    #[test]
    fn an_ok_frame_with_no_value_is_null_not_an_error() {
        // `to_wire` always emits `value`, but a null is the honest reading of
        // "succeeded, returned nothing" and must not masquerade as a failure.
        assert_eq!(
            interpret("1", r#"{"id":"1","ok":true}"#).unwrap(),
            Value::Null
        );
    }

    #[test]
    fn a_denial_becomes_a_broker_error_carrying_its_own_code() {
        let err = interpret("2", r#"{"id":"2","ok":false,"error":"vault_locked"}"#).unwrap_err();
        assert_eq!(err.code, "vault_locked");
        assert!(err.ends_session());
    }

    #[test]
    fn a_mismatched_id_is_refused_rather_than_believed() {
        let err = interpret("9", r#"{"id":"3","ok":true,"value":{"secretish":1}}"#).unwrap_err();
        assert_eq!(err.code, "malformed_response");
    }

    #[test]
    fn the_servers_unparseable_frame_marker_is_accepted_and_adjudicated() {
        // server.rs replies `to_wire("?", Malformed)` when it cannot parse a
        // request. That is a genuine answer to this caller, not a stray frame.
        let err = interpret(
            "5",
            r#"{"id":"?","ok":false,"error":"malformed_request","message":"expected value"}"#,
        )
        .unwrap_err();
        assert_eq!(err.code, "malformed_request");
    }

    #[test]
    fn a_truncated_line_is_a_transport_failure_not_a_denial() {
        let err = interpret("1", "   ").unwrap_err();
        assert_eq!(err.code, "broker_unreachable");
    }

    #[test]
    fn a_frame_without_ok_is_a_protocol_error() {
        let err = interpret("1", r#"{"id":"1","value":3}"#).unwrap_err();
        assert_eq!(err.code, "malformed_response");
    }

    #[test]
    fn request_ids_are_unique_and_monotonic_within_a_process() {
        let a: u64 = next_request_id().parse().unwrap();
        let b: u64 = next_request_id().parse().unwrap();
        assert!(b > a, "ids must advance so an echo check means something");
    }
}
