//! The bridge's error surface — one shape for everything that can go wrong
//! between the webview and `credmgrd`.
//!
//! Three sources of failure exist and a caller genuinely needs to tell them
//! apart, so [`ErrorSource`] names them rather than flattening everything
//! into one string:
//!
//! * `transport` — we never reached the broker. Almost always "credmgrd is
//!   not running". Recoverable by starting it; nothing about the vault is
//!   known either way.
//! * `protocol` — we reached it and got something the protocol does not
//!   promise. A bug on one side of the wire, never a normal state.
//! * `broker` — it answered, and its answer was a denial. `code` is then the
//!   broker's own `"error"` discriminant verbatim (`10_API_AND_MCP.md §1`,
//!   built by `crates/brokerd/src/protocol.rs::to_wire`), so the UI switches
//!   on exactly the vocabulary the audit log records.
//! * `bridge` — this crate failed on its own account (a thread panicked, a
//!   platform is unsupported). Never a vault state.
//!
//! **Broker codes are passed through, never translated.** A denial the UI
//! renders must be the same word `audit.tail` will show for it; inventing a
//! friendlier vocabulary here would put the log and the screen into two
//! different languages for one event. [`BROKER_ERROR_CODES`] is the closed
//! set, and `tests/drift_guards.rs` reads `protocol.rs` from disk and fails
//! if the broker grows a discriminant this list does not carry.

use serde::Serialize;
use serde_json::Value;

/// Every `"error"` discriminant `credmgrd` can put on the wire, verbatim.
///
/// Mirrors the arms of `crates/brokerd/src/protocol.rs::to_wire` one-for-one.
/// It is a *hand-copied* list across a deliberate workspace boundary
/// (ADR-035 keeps `src-tauri` off the 1.78 MSRV pin, so this crate cannot
/// simply `use credmgr_brokerd::protocol`), which is exactly the kind of
/// duplication that rots in silence — hence the drift guard. Do not edit
/// this list to make that test pass; edit it because the broker changed, and
/// then handle the new case.
pub const BROKER_ERROR_CODES: &[&str] = &[
    "node_access_denied",
    "two_factor_required",
    "approval_pending",
    "conflict",
    "vault_locked",
    // ADR-077 (G3): one locked node on an unlocked vault. Deliberately NOT in
    // `SESSION_ENDED_CODES` below - the login is still good.
    "node_locked",
    "wrong_passphrase",
    "malformed_request",
    "capability_not_held",
    "not_found",
    "entry_exists",
    "internal",
    "presence_required",
    "archive_expired",
    "approval_denied",
    "rate_limited",
    "gate_verification_failed",
    "gate_not_enrolling",
    "entry_removal_expired",
    "not_undoable",
    // ADR-061, vault bootstrap (`vault.init_begin`/`vault.init_confirm`).
    // Added 2026-09-24: the broker has emitted these four since 2026-08-31,
    // and the drift guard below this list sat red for three weeks because
    // this crate's suite runs outside `cargo test --workspace` (ADR-035).
    "vault_already_initialized",
    "vault_inside_git_working_tree",
    "vault_init_not_pending",
    "recovery_code_mismatch",
    // ADR-068: a token the broker no longer holds is refused, not demoted.
    "session_expired",
];

/// Every `code` this crate raises on its own account (`source` `transport`,
/// `protocol` or `bridge`) — the broker was never reached, answered nonsense,
/// or the shell itself failed. `bridge.ts`'s `BridgeLocalCode` is held to this
/// list by `tests/ts_client.rs`, which also scans `src/` and fails if a
/// `BridgeError::bridge("…")` call names a code that is not here.
pub const BRIDGE_LOCAL_CODES: &[&str] = &[
    "broker_unreachable",
    "malformed_response",
    "worker_failed",
    "encode_failed",
    "platform_unsupported",
    // The OS clipboard refused or raced (`entry_copy`, `copy_text`).
    "clipboard_failed",
    // `copy_text` was given more than `commands::COPY_TEXT_MAX_BYTES`.
    "text_too_large",
    // ADR-078: `entry_copy` was asked to copy an entry that has several fields
    // without being told which. Nothing was copied; name a field id and retry.
    "field_required",
    // ADR-078: `fields_preview` was given something it cannot preview (both
    // `text` and `fields`, neither, or a field the broker would refuse). The
    // message names an index or a count, never a label or a value.
    "invalid_fields",
    // ADR-082 (X9): `app_icon_set` was given an id outside `icon::MARK_IDS`; nothing changed.
    "unknown_icon",
    // `app_icon_set`: the OS or the window refused the icon (a decode or an AppKit failure).
    "icon_failed",
];

/// Broker denials that mean "the token you presented is no longer a login
/// session" — see [`crate::session`] for why the bridge drops its cached
/// token on these rather than waiting for the user to notice.
///
/// `session_expired` (ADR-068) is the broker saying so directly: the token
/// idled out (ADR-065), was dropped when the vault locked, or never existed.
/// Before ADR-068 the broker resolved an unknown token from the caller's cwd
/// instead, so a dead token silently *demoted* the app rather than failing
/// it — which is why `vault_locked` and a vault-level `locked: true` are
/// still honoured as the same signal (`session::Session::reconcile_ok`).
pub const SESSION_ENDED_CODES: &[&str] = &["vault_locked", "session_expired"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorSource {
    Transport,
    Protocol,
    Broker,
    Bridge,
}

/// What every bridge command returns on the failure path. Serialised as a
/// plain object so the webview can `switch (err.code)` without a decoder.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BridgeError {
    pub source: ErrorSource,
    /// For `source: "broker"`, the wire discriminant verbatim. Otherwise a
    /// bridge-local code from the small set below.
    pub code: String,
    pub message: String,
    /// The broker's own error body with `id`/`ok` removed, so a caller that
    /// wants `rule`/`remedy`/`expectedGeneration` has them without the
    /// bridge having to enumerate every field of every denial.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<Value>,
}

impl BridgeError {
    pub fn transport(message: impl Into<String>) -> Self {
        BridgeError {
            source: ErrorSource::Transport,
            code: "broker_unreachable".to_string(),
            message: message.into(),
            detail: None,
        }
    }

    pub fn protocol(message: impl Into<String>) -> Self {
        BridgeError {
            source: ErrorSource::Protocol,
            code: "malformed_response".to_string(),
            message: message.into(),
            detail: None,
        }
    }

    pub fn bridge(code: &str, message: impl Into<String>) -> Self {
        BridgeError {
            source: ErrorSource::Bridge,
            code: code.to_string(),
            message: message.into(),
            detail: None,
        }
    }

    /// Build a broker denial from the response frame.
    ///
    /// An `"error"` value this build does not know is still surfaced —
    /// reporting fails **open**, so a newer broker talking to an older shell
    /// produces a visible, correctly-attributed denial rather than a
    /// swallowed one. Only *authorization* fails closed, and that decision
    /// was already made by the broker before this frame existed.
    pub fn from_wire(body: &Value) -> Self {
        let code = body
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        let message = body
            .get("message")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| default_message(&code));
        let mut detail = body.clone();
        if let Some(object) = detail.as_object_mut() {
            object.remove("id");
            object.remove("ok");
        }
        BridgeError {
            source: ErrorSource::Broker,
            code,
            message,
            detail: Some(detail),
        }
    }

    /// True when this denial means the bridge's cached session token is dead.
    pub fn ends_session(&self) -> bool {
        self.source == ErrorSource::Broker && SESSION_ENDED_CODES.contains(&self.code.as_str())
    }
}

/// Several denials carry no `message` on the wire (`wrong_passphrase`,
/// `conflict`, `node_access_denied` carries its own). Rather than show the
/// raw discriminant to a human, name the ones a user can actually act on;
/// anything else falls back to the discriminant, which is still true.
fn default_message(code: &str) -> String {
    match code {
        "wrong_passphrase" => "that passphrase did not unlock the vault".to_string(),
        "two_factor_required" => {
            "the passphrase was accepted; a second factor is still required".to_string()
        }
        "conflict" => {
            "someone else changed this node since you loaded it; reload and retry".to_string()
        }
        "capability_not_held" => "this session does not hold that capability".to_string(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn from_wire_keeps_the_brokers_own_vocabulary_and_strips_the_envelope() {
        let body = json!({
            "id": "7", "ok": false, "error": "node_access_denied",
            "rule": "R8", "remedy": "ask for a grant", "message": "no grant"
        });
        let err = BridgeError::from_wire(&body);
        assert_eq!(err.source, ErrorSource::Broker);
        assert_eq!(err.code, "node_access_denied");
        assert_eq!(err.message, "no grant");
        let detail = err.detail.expect("detail is carried through");
        assert_eq!(detail["rule"], "R8");
        assert!(
            detail.get("id").is_none(),
            "envelope id must not leak into detail"
        );
        assert!(
            detail.get("ok").is_none(),
            "envelope ok must not leak into detail"
        );
    }

    #[test]
    fn an_unknown_discriminant_is_surfaced_not_swallowed() {
        let err =
            BridgeError::from_wire(&json!({ "id": "1", "ok": false, "error": "from_the_future" }));
        assert_eq!(err.code, "from_the_future");
        assert_eq!(err.source, ErrorSource::Broker);
    }

    /// ADR-077 (G3): locking one node must not log the owner out. `node_locked`
    /// is a real, known broker code and carries the node in `detail`, but it is
    /// not a session-ending one.
    #[test]
    fn node_locked_is_known_carries_its_node_and_does_not_end_the_session() {
        assert!(BROKER_ERROR_CODES.contains(&"node_locked"));
        assert!(!SESSION_ENDED_CODES.contains(&"node_locked"));
        let err = BridgeError::from_wire(&json!({
            "id": "1", "ok": false, "error": "node_locked", "node": "acme",
            "message": "node acme is locked; the vault itself is unlocked",
            "remedy": "unlock this node (vault.node_unlock) and retry",
        }));
        assert_eq!(err.source, ErrorSource::Broker);
        assert_eq!(err.code, "node_locked");
        assert!(!err.ends_session());
        assert_eq!(err.detail.expect("detail")["node"], "acme");
    }

    #[test]
    fn only_a_broker_vault_locked_or_session_expired_ends_the_session() {
        assert!(BridgeError::from_wire(&json!({ "error": "vault_locked" })).ends_session());
        assert!(BridgeError::from_wire(&json!({ "error": "session_expired" })).ends_session());
        assert!(!BridgeError::from_wire(&json!({ "error": "not_found" })).ends_session());
        // A transport failure means we never reached the broker — it says
        // nothing about whether our token is still good.
        assert!(!BridgeError::transport("credmgrd is not running").ends_session());
    }
}
