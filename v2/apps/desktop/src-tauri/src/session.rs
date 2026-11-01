//! Custody of the ADR-056 session token.
//!
//! **The token never crosses into the webview.** That is the whole point of
//! this type existing rather than the frontend holding a string and passing
//! it back down. `17_AIRLOCK_AND_LLM.md`'s A-1 gives this product no outbound
//! network surface at all; a capability token sitting in `localStorage` or in
//! a JS variable would hand every bug in the web layer — an injected script,
//! a stray `console.log`, a devtools screenshot — the full `global`-scoped
//! `Admin` capability the token carries. It is held here, attached to broker
//! calls Rust-side, and no command returns it.
//!
//! ## The dead-token problem this type exists to solve
//!
//! `vault.lock` revokes every outstanding session token (`state.rs::lock()`
//! drains `session_tokens` and calls `tokens.revoke` on each — ADR-056: "a
//! login session does not outlive the unlock it came from"). So does the
//! idle auto-lock (ADR-043), which fires on a timer with no user action at
//! all, and so does restarting `credmgrd`.
//!
//! Until ADR-068 that was dangerous rather than merely inconvenient: the
//! broker resolved a token id it did not recognise from the caller's cwd as
//! `Origin::Agent`, so **a revoked token silently demoted the caller** — a UI
//! holding one kept working with quietly fewer capabilities. Since ADR-068
//! the broker refuses a dead token with `session_expired` (a login that
//! idled out on its own clock, ADR-065, is the case no lock signal covers).
//!
//! The bridge treats any of these as authoritative proof its token is dead:
//!
//! * a denial whose code is in `SESSION_ENDED_CODES` (`vault_locked`,
//!   `session_expired`), and
//! * any successful response that reports the *vault* as locked — which is
//!   how the *idle* auto-lock gets noticed, since nothing pushes that event
//!   to us. "The vault", not "anything": see [`VAULT_STATE_OPS`].
//!
//! Both funnel through [`Session::reconcile_ok`] / [`Session::reconcile_err`],
//! called on every command by `commands::dispatch_at`.

use std::sync::Mutex;

use serde_json::Value;

use crate::error::BridgeError;

/// The ops whose top-level `locked` field is the **vault's** lock state
/// (`crates/brokerd/src/ops.rs`). Every other op that answers with a
/// `locked` field — today only `vault.node_lock`/`vault.node_unlock` — is
/// talking about something narrower. See [`Session::reconcile_ok`].
pub const VAULT_STATE_OPS: &[&str] = &[
    "vault.status",
    "vault.unlock",
    "vault.gate_verify",
    "vault.lock",
];

/// Tauri managed state. One per app instance.
#[derive(Default)]
pub struct Session {
    /// `None` = no login session held. Never serialised, never returned.
    token: Mutex<Option<String>>,
}

/// ADR-077: `Debug` says whether a login is held, never what it is — a derived
/// `Debug` here would print the bearer into any panic message or log line that
/// ever formatted the managed state.
impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("authenticated", &self.is_authenticated())
            .finish()
    }
}

impl Session {
    pub fn new() -> Self {
        Session::default()
    }

    /// A clone of the current token, for attaching to one outbound call.
    ///
    /// Cloned rather than borrowed on purpose: the lock is released before
    /// any blocking socket I/O begins, so a slow or wedged broker can never
    /// hold this mutex for the length of a round trip.
    pub fn token(&self) -> Option<String> {
        self.lock().clone()
    }

    pub fn is_authenticated(&self) -> bool {
        self.lock().is_some()
    }

    pub fn set(&self, token: String) {
        *self.lock() = Some(token);
    }

    pub fn clear(&self) {
        *self.lock() = None;
    }

    /// Take the `token` field out of an unlock/gate-verify response, store
    /// it, and leave a response the webview may safely receive.
    ///
    /// Returns whether a token was captured. Removing the field is not
    /// cosmetic — `vault.unlock`'s success body is literally
    /// `{"locked": false, "token": "cmt_…"}`, so forwarding it unmodified
    /// would publish the token to JS on the very first call.
    pub fn capture_token(&self, value: &mut Value) -> bool {
        let Some(object) = value.as_object_mut() else {
            return false;
        };
        match object.remove("token") {
            Some(Value::String(token)) => {
                self.set(token);
                true
            }
            // A non-string `token` is a protocol surprise. It is still
            // removed above (so it cannot reach the webview) and simply not
            // stored — the caller then looks unauthenticated, which is the
            // safe reading of "I did not understand the credential".
            _ => false,
        }
    }

    /// Fold one successful response to `op` into session state.
    ///
    /// A *vault* reporting `locked: true` means our token has been revoked —
    /// see the module docs. `vault.status` and `graph.snapshot`
    /// (`meta.vaultLocked`) both carry it, so ordinary UI polling notices an
    /// idle auto-lock without a dedicated event channel.
    ///
    /// **Whose `locked` it is depends on the op.** A top-level `locked` field
    /// is the vault's own state only on [`VAULT_STATE_OPS`]; `vault.node_lock`
    /// answers `{"node": …, "locked": true}` about *one node*, and reading
    /// that as "the vault locked" would drop the login the moment a user
    /// locked a single project, after which every later screen would answer
    /// with the app's own cwd scope instead of the login. So the
    /// flat field is honoured only where it means the vault, and
    /// `meta.vaultLocked` — which names the vault explicitly — everywhere.
    pub fn reconcile_ok(&self, op: &str, value: &Value) {
        let flat = if VAULT_STATE_OPS.contains(&op) {
            value.get("locked").and_then(Value::as_bool)
        } else {
            None
        };
        let locked = flat
            .or_else(|| {
                value
                    .get("meta")
                    .and_then(|m| m.get("vaultLocked"))
                    .and_then(Value::as_bool)
            })
            .unwrap_or(false);
        if locked {
            self.clear();
        }
    }

    /// Fold one denial into session state.
    pub fn reconcile_err(&self, error: &BridgeError) {
        if error.ends_session() {
            self.clear();
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Option<String>> {
        // A poisoned mutex here would mean a panic while holding a token.
        // Recovering the guard is right: the alternative is a permanently
        // unusable app, and the value behind it is a plain `Option<String>`
        // that no panic can leave half-written.
        self.token
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn debug_says_whether_a_login_is_held_and_never_prints_it() {
        let session = Session::new();
        assert!(format!("{session:?}").contains("authenticated: false"));
        session.set("cmt_0123456789abcdef0123456789abcdef".to_string());
        let shown = format!("{session:?}");
        assert!(shown.contains("authenticated: true"), "{shown}");
        assert!(
            !shown.contains("cmt_") && !shown.contains("0123456789"),
            "{shown}"
        );
    }

    #[test]
    fn capture_takes_the_token_out_of_the_body_it_returns() {
        let session = Session::new();
        let mut value = json!({ "locked": false, "token": "cmt_deadbeef" });
        assert!(session.capture_token(&mut value));
        assert!(session.is_authenticated());
        assert!(
            value.get("token").is_none(),
            "the token must not survive into the value handed to the webview"
        );
        assert_eq!(value["locked"], false);
    }

    #[test]
    fn a_non_string_token_is_still_stripped_but_never_stored() {
        let session = Session::new();
        let mut value = json!({ "locked": false, "token": 42 });
        assert!(!session.capture_token(&mut value));
        assert!(value.get("token").is_none());
        assert!(!session.is_authenticated());
    }

    #[test]
    fn a_locked_response_drops_the_token_which_is_how_idle_autolock_is_noticed() {
        let session = Session::new();
        session.set("cmt_live".to_string());
        session.reconcile_ok("vault.status", &json!({ "locked": true }));
        assert!(
            !session.is_authenticated(),
            "ADR-043's idle auto-lock revokes the token broker-side with no event to us"
        );
    }

    #[test]
    fn graph_snapshots_nested_lock_flag_is_honoured_too() {
        let session = Session::new();
        session.set("cmt_live".to_string());
        session.reconcile_ok(
            "graph.snapshot",
            &json!({ "nodes": [], "meta": { "vaultLocked": true } }),
        );
        assert!(!session.is_authenticated());
    }

    #[test]
    fn an_unlocked_response_leaves_the_session_alone() {
        let session = Session::new();
        session.set("cmt_live".to_string());
        session.reconcile_ok("vault.status", &json!({ "locked": false }));
        assert!(session.is_authenticated());
        session.reconcile_ok("entry.list", &json!({ "ids": [], "names": [] }));
        assert!(session.is_authenticated());
    }

    #[test]
    fn locking_one_node_is_not_mistaken_for_the_vault_locking() {
        // `vault.node_lock` answers `{"node", "locked": true}` about one node.
        // Read as vault state, it would log the user out for locking a project.
        let session = Session::new();
        session.set("cmt_live".to_string());
        session.reconcile_ok(
            "vault.node_lock",
            &json!({ "node": "acme", "locked": true }),
        );
        assert!(
            session.is_authenticated(),
            "a node-level lock must not end the vault-level login session"
        );
        // …while the same flat field on a vault-state op still does.
        session.reconcile_ok("vault.lock", &json!({ "locked": true }));
        assert!(!session.is_authenticated());
    }

    #[test]
    fn meta_vault_locked_is_honoured_on_any_op_because_it_names_the_vault() {
        let session = Session::new();
        session.set("cmt_live".to_string());
        session.reconcile_ok(
            "vault.node_lock",
            &json!({ "meta": { "vaultLocked": true } }),
        );
        assert!(!session.is_authenticated());
    }

    #[test]
    fn a_vault_locked_denial_ends_the_session_but_an_unreachable_broker_does_not() {
        let session = Session::new();
        session.set("cmt_live".to_string());
        session.reconcile_err(&BridgeError::transport("not running"));
        assert!(
            session.is_authenticated(),
            "failing to reach the broker says nothing about whether the token is still valid"
        );
        session.reconcile_err(&BridgeError::from_wire(&json!({ "error": "vault_locked" })));
        assert!(!session.is_authenticated());
    }
}
