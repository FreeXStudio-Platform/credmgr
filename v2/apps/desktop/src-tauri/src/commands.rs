//! The `#[tauri::command]` surface — what `invoke()` can reach.
//!
//! One command per broker op, named `<op with dots as underscores>`, and each
//! is a thin pass-through: it does not reshape, summarise, or re-interpret
//! what `credmgrd` said. That is deliberate. The broker is the single
//! enforcement point (ADR-001) and `10_API_AND_MCP.md §1` is the contract;
//! a bridge that "helpfully" normalised responses would become a second,
//! undocumented API that drifts from the first. The two exceptions are
//! narrow and both are about *removing*, never adding:
//!
//! * the session token is stripped out of unlock responses, `vault.recover`'s
//!   included ([`crate::session`]);
//! * the auth commands return [`AuthState`] instead of the raw body, so the
//!   webview learns *whether it is authenticated* without being told the
//!   credential that makes it so.
//!
//! **`two_factor_required` arrives as an error, not a state.** That is how it
//! is on the wire (`protocol.rs` makes it an `OpError`), and translating it
//! into a success variant here would put the bridge and the audit log into
//! different vocabularies for the same event. The UI branches on
//! `err.code === "two_factor_required"` and calls `vault_gate_verify`.
//!
//! ## Blocking I/O
//!
//! Every command is `async` and does its socket work inside
//! `spawn_blocking`. The transport is synchronous by design (mirroring
//! `crates/cli/src/transport.rs`), and `vault.unlock` blocks on Argon2id key
//! derivation for a noticeable fraction of a second — running that on the
//! runtime's own thread would stall unrelated commands, and running it on
//! the main thread would freeze the window.

use std::path::PathBuf;

use serde::Serialize;
use serde_json::{json, Map, Value};
use tauri::State;
use zeroize::{Zeroize, Zeroizing};

use crate::clipboard::Clipboard;
use crate::env_preview;
use crate::error::BridgeError;
use crate::fields_preview;
use crate::session::Session;
use crate::{transport, vault_paths};

/// What the webview is told about the login session. Deliberately does not
/// carry, hash, or hint at the token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthState {
    /// The vault's own lock state, as the broker reports it.
    pub locked: bool,
    /// Whether this bridge currently holds a live session token.
    pub authenticated: bool,
    /// ADR-077 (G2): whether a vault exists to unlock at all. `false` is the
    /// first-run signal — there is nothing behind a lock screen yet. Only
    /// `vault.status` reports it; every other auth response means a vault was
    /// there to answer, so it defaults to `true`.
    pub initialized: bool,
    /// ADR-090: how many agent requests are waiting for a person (a bare count,
    /// from `vault.status` only; every other auth response says 0). Left out of
    /// the page's copy when it is 0, so the common answer is unchanged.
    #[serde(skip_serializing_if = "is_zero")]
    pub pending_approvals: u32,
    /// ADR-098: unlocking with Touch ID is set up for this vault (`vault.status`), left out when not.
    #[serde(skip_serializing_if = "is_false")]
    pub touch_id_unlock: bool,
    /// ADR-156: the cross-node anomaly alarms the owner has not acknowledged (a bare count, from
    /// `vault.status` only, which carries it to the owner's own login only); left out when 0.
    #[serde(skip_serializing_if = "is_zero")]
    pub anomalies_unseen: u32,
    /// ADR-163: this vault can be opened with its recovery code when the passphrase is forgotten
    /// (`vault.status`: the recovery wrap exists), so the Lock screen offers "Forgot passphrase?";
    /// left out when not.
    #[serde(skip_serializing_if = "is_false")]
    pub recovery_unlock: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

fn is_zero(n: &u32) -> bool {
    *n == 0
}

/// The socket every command talks to, or a transport error explaining why we
/// could not even work out where it is.
fn socket() -> Result<PathBuf, BridgeError> {
    vault_paths::resolve_socket_path().ok_or_else(|| {
        BridgeError::transport(
            "cannot locate the vault directory: no CREDMGR_VAULT_DIR and no home directory",
        )
    })
}

/// Send one op to the broker with the session's token attached, and fold the
/// outcome back into session state.
///
/// The socket is a parameter rather than resolved in here so the whole flow
/// — token attachment, capture, and the lock reconciliation that depends on
/// both — is testable against a real socket at a temporary path, without
/// mutating `CREDMGR_VAULT_DIR` process-wide while other tests are running.
/// Each `#[tauri::command]` below is a thin wrapper that supplies `socket()`.
pub async fn dispatch_at(
    session: &Session,
    socket: PathBuf,
    op: &'static str,
    params: Value,
) -> Result<Value, BridgeError> {
    // Cloned out before the blocking call so the session mutex is never held
    // across socket I/O.
    let token = session.token();

    let outcome = tauri::async_runtime::spawn_blocking(move || {
        // ADR-148 §P2-4: enrolling a presence key proves this Mac holds it — the key signs a broker nonce
        // (Touch ID appears) before the enrolment is sent. The webview passes only the public key and label.
        let params = if op == "presence.enrol"
            && params.get("possession").is_none()
            && crate::presence::ready()
        {
            let (challenge, _) = transport::call_audited(
                &socket,
                "presence.challenge",
                token.as_deref(),
                json!({ "op": op, "params": params, "possession": true }),
            )?;
            crate::presence::attach_possession(&challenge, &params)?
        } else {
            params
        };
        let first = transport::call_audited(&socket, op, token.as_deref(), params.clone());
        match first {
            // ADR-098: the op needs the user's finger. Ask the broker for a challenge, let the Secure
            // Enclave sign it (Touch ID appears), and send the request again with the proof. The
            // webview sees none of it: only the final answer, or why the proof could not be made.
            Err(e)
                if e.code == "presence_required"
                    && op != "presence.challenge"
                    && crate::presence::ready() =>
            {
                let (challenge, _) = transport::call_audited(
                    &socket,
                    "presence.challenge",
                    token.as_deref(),
                    json!({ "op": op, "params": params }),
                )?;
                let proved = crate::presence::attach_proof(&challenge, &params)?;
                transport::call_audited(&socket, op, token.as_deref(), proved)
            }
            other => other,
        }
    })
    .await
    .map_err(|e| {
        BridgeError::bridge(
            "worker_failed",
            format!("the broker call did not complete: {e}"),
        )
    })?;

    match outcome {
        Ok((mut value, audit)) => {
            session.reconcile_ok(op, &value);
            attach_audit(op, &mut value, audit);
            Ok(value)
        }
        Err(error) => {
            session.reconcile_err(&error);
            Err(error)
        }
    }
}

/// The ops whose answer carries the id of the audit record the change wrote
/// (ADR-091, "audit passthrough"): every op that changes the vault's
/// content or policy. The id is what `entry.undo` is asked to undo, so the page
/// reads it from the change's own answer instead of searching `audit.tail`.
/// Reads are not listed: their answers keep exactly the shape the broker gives.
/// A test holds every name here to a real broker op.
pub const AUDIT_PASSTHROUGH: &[&str] = &[
    "entry.create",
    "entry.create_batch",
    "entry.alias",
    "entry.import_env",
    "entry.update",
    "entry.rotate",
    "entry.remove",
    "entry.restore",
    "entry.undo",
    "entry.set_expiry",
    "entry.move",
    "entry.tag_set",
    "merge.apply",
    "merge.auto",
    "merge.auto_all",
    "merge.dismiss",
    "merge.undismiss",
    "merge.restore_all",
    "vault.doctor_apply",
    "field.add",
    "field.update",
    "field.remove",
    "field.reorder",
    "notes.write",
    "node.create",
    "node.update",
    "node.policy",
    "settings.set",
    "settings.revert",
    "settings.request_decide",
    "node.set_workdirs",
    "node.reparent",
    "node.seal",
    "node.restore",
    "grant.create",
    "grant.revoke",
    "vault.pending_accept",
    "vault.pending_discard",
    "vault.approval_decide",
];

/// Put the envelope's `audit` id into the answer of a changing op - additively: an
/// object answer gains an `audit` member (never overwriting one the broker put
/// there), and anything else is left alone.
fn attach_audit(op: &str, value: &mut Value, audit: Option<String>) {
    let Some(id) = audit else { return };
    if !AUDIT_PASSTHROUGH.contains(&op) {
        return;
    }
    if let Some(object) = value.as_object_mut() {
        object.entry("audit").or_insert(Value::String(id));
    }
}

/// Read the `locked` flag out of a response, defaulting to *locked*.
///
/// Fail-safe direction: a body we cannot read must never be reported to the
/// UI as "unlocked and ready".
fn locked_from(value: &Value) -> bool {
    value.get("locked").and_then(Value::as_bool).unwrap_or(true)
}

/// Shared tail of the three authentication ops: fold the response into
/// session state and describe the result without naming the credential.
fn auth_state(session: &Session, value: &Value) -> AuthState {
    AuthState {
        locked: locked_from(value),
        authenticated: session.is_authenticated(),
        initialized: initialized_from(value),
        pending_approvals: pending_from(value),
        touch_id_unlock: value
            .get("touchIdUnlock")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        anomalies_unseen: count_from(value, "anomaliesUnseen"),
        recovery_unlock: value
            .get("recoveryUnlock")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    }
}

/// Read `pendingApprovals` (`vault.status`, ADR-090), defaulting to 0: a broker
/// that predates the field, and every response that is not `vault.status`,
/// has nothing waiting as far as this bridge can tell.
fn pending_from(value: &Value) -> u32 {
    count_from(value, "pendingApprovals")
}

/// A bare count member of an auth response, defaulting to 0 when absent or not a
/// whole number (`pendingApprovals`, ADR-090; `anomaliesUnseen`, ADR-156).
fn count_from(value: &Value, key: &str) -> u32 {
    value
        .get(key)
        .and_then(Value::as_u64)
        .map_or(0, |n| u32::try_from(n).unwrap_or(u32::MAX))
}

/// Read the `initialized` flag (`vault.status`, ADR-077), defaulting to
/// *initialised*: the fail-safe direction is to show the lock screen of a vault
/// that exists, never to offer to create a second one over it. A broker that
/// predates the field, and every response that is not `vault.status`, lands here.
fn initialized_from(value: &Value) -> bool {
    value
        .get("initialized")
        .and_then(Value::as_bool)
        .unwrap_or(true)
}

// ---------------------------------------------------------------------------
// Socket-injected cores. Each `#[tauri::command]` below is a wrapper over one
// of these; the tests drive these directly against a real socket at a
// temporary path (see `tests/bridge_wire.rs`).
// ---------------------------------------------------------------------------

pub async fn vault_status_at(session: &Session, socket: PathBuf) -> Result<AuthState, BridgeError> {
    let value = dispatch_at(session, socket, "vault.status", json!({})).await?;
    Ok(auth_state(session, &value))
}

pub async fn vault_unlock_at(
    session: &Session,
    socket: PathBuf,
    passphrase: String,
) -> Result<AuthState, BridgeError> {
    vault_unlock_with_at(session, socket, Some(passphrase), None).await
}

/// [`vault_unlock_at`] with the unlock method open: a passphrase, or `method: "device"` for Touch ID.
pub async fn vault_unlock_with_at(
    session: &Session,
    socket: PathBuf,
    passphrase: Option<String>,
    method: Option<String>,
) -> Result<AuthState, BridgeError> {
    // ADR-098: `method: "device"` opens the vault with Touch ID; the broker asks the system for the
    // fingerprint itself, so nothing secret travels. Otherwise the passphrase, as ever.
    let mut params = Map::new();
    if let Some(p) = &passphrase {
        params.insert("passphrase".into(), Value::String(p.clone()));
    }
    if let Some(m) = &method {
        params.insert("method".into(), Value::String(m.clone()));
    }
    let mut value = dispatch_at(
        session,
        socket.clone(),
        "vault.unlock",
        Value::Object(params),
    )
    .await?;
    if session.capture_token(&mut value) {
        revoke_unheld_agent_tokens(session, socket).await;
    }
    Ok(auth_state(session, &value))
}

pub async fn vault_gate_verify_at(
    session: &Session,
    socket: PathBuf,
    code: String,
) -> Result<AuthState, BridgeError> {
    let mut value = dispatch_at(
        session,
        socket.clone(),
        "vault.gate_verify",
        json!({ "code": code }),
    )
    .await?;
    if session.capture_token(&mut value) {
        revoke_unheld_agent_tokens(session, socket).await;
    }
    Ok(auth_state(session, &value))
}

/// ADR-163: open a locked vault with the recovery code alone, set the new passphrase and get a NEW
/// recovery code, in one broker call. The broker mints the login token as `vault.unlock` does; it is
/// captured here and never returned. The rest of the answer goes back as the broker gave it — the new
/// `recoveryCode` among it, which the Lock screen shows once and does not keep.
pub async fn vault_recover_at(
    session: &Session,
    socket: PathBuf,
    recovery_code: String,
    new_passphrase: String,
    code: Option<String>,
) -> Result<Value, BridgeError> {
    let mut params = Map::new();
    params.insert("recoveryCode".into(), Value::String(recovery_code));
    params.insert("newPassphrase".into(), Value::String(new_passphrase));
    if let Some(c) = code {
        params.insert("code".into(), Value::String(c));
    }
    let mut value = dispatch_at(session, socket, "vault.recover", Value::Object(params)).await?;
    session.capture_token(&mut value);
    Ok(value)
}

pub async fn vault_lock_at(session: &Session, socket: PathBuf) -> Result<AuthState, BridgeError> {
    let outcome = dispatch_at(session, socket, "vault.lock", json!({})).await;
    // Unconditional, including on the error path: a lock attempt that failed
    // to report may still have locked, and holding a token we are unsure
    // about is exactly the state this bridge exists to prevent.
    session.clear();
    let value = outcome?;
    Ok(AuthState {
        locked: locked_from(&value),
        authenticated: false,
        initialized: initialized_from(&value),
        pending_approvals: 0,
        touch_id_unlock: false,
        anomalies_unseen: 0,
        recovery_unlock: false,
    })
}

// ---------------------------------------------------------------------------
// Node-scoped agent tokens (ADR-164) — the two answers that carry a bearer
// ---------------------------------------------------------------------------
//
// `agent.token_issue` and `agent.token_rotate` answer the new bearer (`cma_…`) once. Like the
// login a `vault.unlock` answers (ADR-057), it never reaches the webview: the shell takes `token`
// out of the answer, writes it to the concealed, self-clearing clipboard (as `entry_copy` writes a
// value), wipes its own copy, and answers the metadata with `copied` and `clearAfterSeconds`. If
// the clipboard cannot take it, nobody holds the token, so the shell revokes it at once and says so
// (`copied: false`, `revoked`). The usual reason is a lock mid-call, which also ended the login a
// revoke needs (review P2-4): then the id is queued on the session and revoked by the next login
// (`revokePending: true`). The same goes for an answer the shell cannot read but that names a
// token. The Touch ID proof is the ordinary presence retry in `dispatch_at`.

/// An agent token's public id: `a_` and 16 lower-case hex digits.
fn is_agent_public_id(id: &str) -> bool {
    id.len() == 18
        && id.starts_with("a_")
        && id[2..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Revoke a minted token nobody holds. `Some(true)` revoked (or already gone), `Some(false)` queued for the next
/// login, `None` when the answer named no token to revoke.
async fn revoke_unheld(session: &Session, socket: PathBuf, id: Option<&Value>) -> Option<bool> {
    let id = id
        .and_then(Value::as_str)
        .filter(|i| is_agent_public_id(i))?;
    match dispatch_at(session, socket, "agent.token_revoke", json!({ "id": id })).await {
        Ok(_) => Some(true),
        Err(e) if e.code == "not_found" => Some(true),
        Err(_) => {
            session.queue_agent_revoke(id.to_string());
            Some(false)
        }
    }
}

/// ADR-164 review P2-4: after a login is captured, revoke the agent tokens an earlier lock left unheld. Best effort:
/// one that cannot be revoked now stays queued; one the broker no longer has (a restart ended it) is dropped.
async fn revoke_unheld_agent_tokens(session: &Session, socket: PathBuf) {
    for id in session.take_agent_revokes() {
        match dispatch_at(
            session,
            socket.clone(),
            "agent.token_revoke",
            json!({ "id": id }),
        )
        .await
        {
            Ok(_) => {}
            Err(e) if e.code == "not_found" => {}
            Err(_) => session.queue_agent_revoke(id),
        }
    }
}

/// Take the bearer out of an issue or rotate answer and hand it to the clipboard only.
async fn hand_agent_token_to_clipboard(
    session: &Session,
    clipboard: &Clipboard,
    ticket: crate::clipboard::CopyTicket,
    socket: PathBuf,
    mut value: Value,
) -> Result<Value, BridgeError> {
    let Some(object) = value.as_object_mut() else {
        scrub(&mut value);
        return Err(BridgeError::protocol(
            "the agent token answer was not an object; nothing was copied",
        ));
    };
    let token = match object.remove("token") {
        Some(Value::String(text)) => Zeroizing::new(text),
        other => {
            // An answer the shell cannot use, but it may name a token that was minted: revoke it (review P2-4).
            if let Some(mut other) = other {
                scrub(&mut other);
            }
            let id = object.get("id").cloned();
            scrub(&mut value);
            let revoked = revoke_unheld(session, socket, id.as_ref()).await;
            let what = match revoked {
                Some(true) => "; the token it named was revoked",
                Some(false) => "; the token it named will be revoked at the next unlock",
                None => "",
            };
            return Err(BridgeError::protocol(format!(
                "the agent token answer carried no text token; nothing was copied{what}"
            )));
        }
    };
    object.remove("shownOnce");
    let copied = clipboard.copy_secret_for(ticket, &token);
    drop(token);
    match copied {
        Ok(()) => {
            object.insert("copied".into(), Value::Bool(true));
            object.insert("clearAfterSeconds".into(), json!(clipboard.ttl().as_secs()));
        }
        Err(_) => {
            // Nobody holds the secret now; a live token no one has is only a risk.
            let id = object.get("id").cloned();
            let revoked = revoke_unheld(session, socket, id.as_ref()).await;
            let object = value
                .as_object_mut()
                .expect("checked to be an object above");
            object.insert("copied".into(), Value::Bool(false));
            object.insert("revoked".into(), Value::Bool(revoked == Some(true)));
            if revoked == Some(false) {
                object.insert("revokePending".into(), Value::Bool(true));
            }
        }
    }
    Ok(value)
}

/// Socket-injected core of [`agent_token_issue`].
pub async fn agent_token_issue_at(
    session: &Session,
    clipboard: &Clipboard,
    socket: PathBuf,
    node: String,
    label: String,
    capabilities: Vec<String>,
    expires_in: Option<i64>,
) -> Result<Value, BridgeError> {
    let mut params = Map::new();
    put(&mut params, "node", &node)?;
    put(&mut params, "label", &label)?;
    put(&mut params, "capabilities", &capabilities)?;
    put(&mut params, "expiresIn", &expires_in)?;
    let ticket = clipboard.ticket();
    let value = dispatch_at(
        session,
        socket.clone(),
        "agent.token_issue",
        Value::Object(params),
    )
    .await?;
    hand_agent_token_to_clipboard(session, clipboard, ticket, socket, value).await
}

/// Socket-injected core of [`agent_token_rotate`].
pub async fn agent_token_rotate_at(
    session: &Session,
    clipboard: &Clipboard,
    socket: PathBuf,
    id: String,
    expires_in: Option<i64>,
) -> Result<Value, BridgeError> {
    let mut params = Map::new();
    put(&mut params, "id", &id)?;
    put(&mut params, "expiresIn", &expires_in)?;
    let ticket = clipboard.ticket();
    let value = dispatch_at(
        session,
        socket.clone(),
        "agent.token_rotate",
        Value::Object(params),
    )
    .await?;
    hand_agent_token_to_clipboard(session, clipboard, ticket, socket, value).await
}

/// A token for exactly one node, a subset of what that node gives agents, with a mandatory expiry
/// (`expiresIn` seconds; one day when absent). Owner's login, the vault's second factor where
/// enrolled, and Touch ID. The new token goes to the concealed clipboard, never to the webview.
#[tauri::command]
pub async fn agent_token_issue(
    session: State<'_, Session>,
    clipboard: State<'_, Clipboard>,
    node: String,
    label: String,
    capabilities: Vec<String>,
    expires_in: Option<i64>,
) -> Result<Value, BridgeError> {
    agent_token_issue_at(
        &session,
        &clipboard,
        socket()?,
        node,
        label,
        capabilities,
        expires_in,
    )
    .await
}

/// A new secret and expiry for an existing token; the old secret stops working. Same gate and same
/// hand-over as [`agent_token_issue`].
#[tauri::command]
pub async fn agent_token_rotate(
    session: State<'_, Session>,
    clipboard: State<'_, Clipboard>,
    id: String,
    expires_in: Option<i64>,
) -> Result<Value, BridgeError> {
    agent_token_rotate_at(&session, &clipboard, socket()?, id, expires_in).await
}

// ---------------------------------------------------------------------------
// Touch ID (ADR-098)
// ---------------------------------------------------------------------------

/// What this Mac can do for Touch ID: Secure Enclave, biometry kind, device password, and whether this
/// Mac already holds a presence key. Local; never prompts.
#[tauri::command]
pub async fn presence_probe() -> Result<Value, BridgeError> {
    tauri::async_runtime::spawn_blocking(crate::presence::probe)
        .await
        .map_err(|e| {
            BridgeError::bridge("worker_failed", format!("the probe did not complete: {e}"))
        })?
}

// ---------------------------------------------------------------------------
// Agents (ADR-143): Settings -> Agents. Local, no broker call.
// ---------------------------------------------------------------------------

/// Which agent clients are on this Mac, whether CredMgr is wired into each, and the `credmgr`
/// binary path a snippet would carry. Reads config files; writes nothing.
#[tauri::command]
pub async fn agent_detect() -> Result<Value, BridgeError> {
    tauri::async_runtime::spawn_blocking(crate::agents::detect)
        .await
        .map_err(|e| {
            BridgeError::bridge(
                "worker_failed",
                format!("the detection did not complete: {e}"),
            )
        })?
}

/// The snippet to copy for a client (`generic` for any other).
#[tauri::command]
pub async fn agent_snippet(client: String) -> Result<Value, BridgeError> {
    tauri::async_runtime::spawn_blocking(move || crate::agents::snippet(&client))
        .await
        .map_err(|e| {
            BridgeError::bridge(
                "worker_failed",
                format!("the snippet did not complete: {e}"),
            )
        })?
}

/// What connecting (or disconnecting) a client would change: the file, a diff and a token. Writes nothing.
#[tauri::command]
pub async fn agent_plan(client: String, action: String) -> Result<Value, BridgeError> {
    tauri::async_runtime::spawn_blocking(move || crate::agents::plan(&client, &action))
        .await
        .map_err(|e| {
            BridgeError::bridge("worker_failed", format!("the plan did not complete: {e}"))
        })?
}

/// Write the change `agent_plan` showed, only if the file is still what it showed. The page calls this
/// only from the button in the diff dialog.
#[tauri::command]
pub async fn agent_apply(
    client: String,
    action: String,
    token: String,
) -> Result<Value, BridgeError> {
    tauri::async_runtime::spawn_blocking(move || crate::agents::apply(&client, &action, &token))
        .await
        .map_err(|e| {
            BridgeError::bridge("worker_failed", format!("the write did not complete: {e}"))
        })?
}

/// The Vault Protocol prompt (`format` `prompt`) or the text of `CREDMGR.md` (`md`) for a node:
/// names and structure from what the page already shows, never a value.
#[tauri::command]
pub fn agent_prompt(
    node: String,
    reachable: Vec<String>,
    level: String,
    format: String,
) -> Result<Value, BridgeError> {
    crate::agents::prompt(&node, reachable, &level, &format)
}

/// Create this Mac's presence key if there is none (never prompts) and answer its public half
/// (base64), which the screen then passes to `presence_enrol`.
#[tauri::command]
pub async fn presence_key_create() -> Result<String, BridgeError> {
    tauri::async_runtime::spawn_blocking(crate::presence::ensure_key)
        .await
        .map_err(|e| {
            BridgeError::bridge(
                "worker_failed",
                format!("the key step did not complete: {e}"),
            )
        })?
}

// ---------------------------------------------------------------------------
// The `invoke()` surface.
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn vault_status(session: State<'_, Session>) -> Result<AuthState, BridgeError> {
    vault_status_at(&session, socket()?).await
}

/// `07_TWO_FACTOR.md §3` step 1.
///
/// On success the broker mints the ADR-056 session token; it is captured
/// here and never returned. When a gate is enrolled this fails with
/// `two_factor_required` and no token exists yet — the login is not complete
/// until [`vault_gate_verify`] lands.
///
/// **On the passphrase argument.** `vault.unlock` ignores it today: the
/// broker's keystore is fixed at process start, and real per-request
/// passphrase wiring is Phase 5's `PlatformKeystore` work (ADR-041). It is
/// sent anyway, exactly as `crates/cli/src/main.rs::cmd_unlock` does, so the
/// call site needs no change the day that lands. It is taken by value and
/// dropped at the end of this call; Rust gives no guarantee the heap
/// allocation is zeroised, and a passphrase that arrived as a JS string was
/// already copied by the IPC layer before reaching us — a limitation worth
/// naming rather than papering over.
#[tauri::command]
pub async fn vault_unlock(
    session: State<'_, Session>,
    passphrase: Option<String>,
    method: Option<String>,
) -> Result<AuthState, BridgeError> {
    vault_unlock_with_at(&session, socket()?, passphrase, method).await
}

/// `07_TWO_FACTOR.md §3` step 3 — completes an unlock that returned
/// `two_factor_required`. Mints the session token on success.
#[tauri::command]
pub async fn vault_gate_verify(
    session: State<'_, Session>,
    code: String,
) -> Result<AuthState, BridgeError> {
    vault_gate_verify_at(&session, socket()?, code).await
}

/// ADR-163 — "Forgot passphrase?" on the Lock screen: the recovery code opens the vault, the new
/// passphrase replaces the forgotten one, and the answer carries a new recovery code (shown once).
/// `code` is the vault's second factor when one is enrolled (asked for after `two_factor_required`).
/// Mints the session token on success, captured here and never returned. The same caveat about the
/// IPC copies of the strings as [`vault_unlock`] applies.
#[tauri::command]
pub async fn vault_recover(
    session: State<'_, Session>,
    recovery_code: String,
    new_passphrase: String,
    code: Option<String>,
) -> Result<Value, BridgeError> {
    vault_recover_at(&session, socket()?, recovery_code, new_passphrase, code).await
}

/// Locks the vault. The broker revokes every session token as it does so
/// (ADR-056), so the local copy is dropped unconditionally.
///
/// A secret this app copied is taken off the clipboard first (C2: "also clear on
/// lock"), through the same ownership test as the 30 s clock: a later copy of the
/// user's own is left alone. It runs before the broker call and does not depend
/// on it, so a stopped `credmgrd` cannot leave a secret behind. The OS-triggered
/// locks do the same in [`crate::autolock::lock_for`].
#[tauri::command]
pub async fn vault_lock<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    session: State<'_, Session>,
    clipboard: State<'_, Clipboard>,
) -> Result<AuthState, BridgeError> {
    clipboard.clear_if_owned();
    let state = vault_lock_at(&session, socket()?).await?;
    // ADR-091 amendment: the page's own lock (button, ⌘L, idle timer) drops the page too, after this answer has been delivered.
    crate::autolock::schedule_page_lock_reload(&app);
    Ok(state)
}

#[tauri::command]
pub async fn whoami(session: State<'_, Session>) -> Result<Value, BridgeError> {
    dispatch_at(&session, socket()?, "whoami", json!({})).await
}

/// The node graph the vault view renders. Already filtered broker-side to
/// nodes this scope can `list` — a node absent from this response is not
/// hidden by the UI, it was never sent.
#[tauri::command]
pub async fn graph_snapshot(session: State<'_, Session>) -> Result<Value, BridgeError> {
    dispatch_at(&session, socket()?, "graph.snapshot", json!({})).await
}

/// Entry names and ids for one node, plus the manifest `generation`.
///
/// The `generation` is not incidental: every mutating op must echo the
/// caller's last-seen value and the broker answers `conflict` if it has moved
/// on (F-9's optimistic concurrency). A UI that discards it here cannot
/// perform a first update at all, so it is passed straight through.
///
/// ADR-167: `tag` narrows the list to the entries carrying that tag, on this one node (sent only when given).
#[tauri::command]
pub async fn entry_list(
    session: State<'_, Session>,
    node: String,
    tag: Option<String>,
) -> Result<Value, BridgeError> {
    let mut params = json!({ "node": node });
    if let Some(tag) = tag {
        params["tag"] = Value::String(tag);
    }
    dispatch_at(&session, socket()?, "entry.list", params).await
}

/// Decrypts one entry. The plaintext is in the response — this is the one
/// command whose payload is the secret itself, so nothing here logs, caches,
/// or retains it; it is handed to the caller and dropped.
///
/// May legitimately fail with `approval_pending` rather than a denial: when
/// the vault is locked but the target would otherwise be readable, the
/// broker opens a one-tap approval path instead (`06 §5` R1, ADR-042).
///
/// ADR-078: the answer is `{node, entry, fields: [{id, label, value, type, masked}],
/// value?}` - the fields in stored order, and `value` **only when exactly one field
/// is returned** (a one-field entry, or `field_ids` naming one). `field_ids` (sent
/// as `fieldIds`) narrows the answer to those fields; an id that names no field is
/// `not_found` and nothing is returned. Naming fields does not change who may ask:
/// an approval covers the entry.
#[tauri::command]
pub async fn entry_reveal(
    session: State<'_, Session>,
    node: String,
    entry: String,
    field_ids: Option<Vec<String>>,
) -> Result<Value, BridgeError> {
    entry_reveal_at(&session, socket()?, node, entry, field_ids).await
}

/// Socket-injected core of [`entry_reveal`] (`entry.reveal`).
pub async fn entry_reveal_at(
    session: &Session,
    socket: PathBuf,
    node: String,
    entry: String,
    field_ids: Option<Vec<String>>,
) -> Result<Value, BridgeError> {
    let mut params = Map::new();
    put(&mut params, "node", &node)?;
    put(&mut params, "entry", &entry)?;
    put(&mut params, "fieldIds", &field_ids)?;
    dispatch_at(session, socket, "entry.reveal", Value::Object(params)).await
}

// ---------------------------------------------------------------------------
// The clipboard commands (C2). Not broker ops: they are the shell's own, and
// one of them reaches the broker only to reveal.
// ---------------------------------------------------------------------------

/// What `entry_copy` and `copy_text` tell the webview. It names the fact and the
/// clock, never the content: there is no field in this struct a value could be
/// put in, and `tests/shell_ipc.rs` reads the serialised response for the
/// secret to prove it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CopyReceipt {
    pub copied: bool,
    /// Seconds until the shell empties the clipboard. `None` for plain text,
    /// which is never timed.
    pub clear_after_seconds: Option<u64>,
}

/// The most text `copy_text` will put on the clipboard. It is for an address or
/// a short label, not a data channel.
pub const COPY_TEXT_MAX_BYTES: usize = 4096;

/// Move the `value` out of a `entry.reveal` answer, leaving nothing behind, in
/// a wrapper that wipes it when dropped. Anything that is not text is wiped and
/// refused: a broker that changed what `value` means must not have its answer
/// written to the clipboard on a guess.
///
/// ADR-078: the answer also carries `fields` - the same value again for a
/// one-field entry, and *every* field's value for a several-field one (which has
/// no `value`: there is no one value to take). The caller wipes the rest with
/// [`scrub`] once this has taken `value`; an answer with no `value` is wiped here
/// before it is refused. A several-field answer is its own refusal,
/// `field_required`, because the way out is to name a field.
fn take_revealed_value(body: &mut Value) -> Result<Zeroizing<String>, BridgeError> {
    match body.as_object_mut().and_then(|o| o.remove("value")) {
        Some(Value::String(text)) => Ok(Zeroizing::new(text)),
        Some(mut other) => {
            scrub(&mut other);
            scrub(body);
            Err(BridgeError::protocol(
                "entry.reveal answered a value that is not text; nothing was copied",
            ))
        }
        None => {
            let several = body["fields"].as_array().map(Vec::len).filter(|n| *n > 1);
            scrub(body);
            match several {
                Some(count) => Err(BridgeError::bridge(
                    "field_required",
                    format!(
                        "this entry has {count} fields; name the one to copy (entryCopy takes a field id)"
                    ),
                )),
                None => Err(BridgeError::protocol(
                    "entry.reveal answered no value; nothing was copied",
                )),
            }
        }
    }
}

/// Wipe every string inside a JSON value.
fn scrub(value: &mut Value) {
    match value {
        Value::String(s) => s.zeroize(),
        Value::Array(items) => items.iter_mut().for_each(scrub),
        Value::Object(map) => map.values_mut().for_each(scrub),
        _ => {}
    }
}

/// Take any `value` out of a refusal before it can be returned to the webview.
///
/// `BridgeError::from_wire` forwards the broker's whole error body as `detail`,
/// which is right for every other command: the screen shows the broker's reasons
/// verbatim. A refusal never carries a revealed value, so for `entry_copy` the
/// only thing this removes is a broker bug. It is removed anyway because this
/// command exists to make "the plaintext does not reach the webview" true without
/// relying on the broker getting every error body right.
fn without_value(mut error: BridgeError) -> BridgeError {
    if let Some(Value::Object(detail)) = error.detail.as_mut() {
        // ADR-078: a reveal answers `fields` too, each carrying its value.
        for key in ["value", "fields"] {
            if let Some(mut leaked) = detail.remove(key) {
                scrub(&mut leaked);
            }
        }
    }
    error
}

/// Reveal an entry **Rust-side** and put it on the concealed clipboard.
///
/// The reveal goes through [`dispatch_at`] like every other op: the session
/// token is attached, the broker authorises and audits it exactly as it would
/// an `entry_reveal`, and every denial (`node_access_denied`, `node_locked`,
/// `approval_pending`, `vault_locked`…) comes back unchanged. What differs is
/// where the plaintext goes: into the pasteboard and nowhere else. The webview
/// gets a [`CopyReceipt`].
///
/// A [`CopyTicket`](crate::clipboard::CopyTicket) is taken before the broker is
/// asked, so a lock, sleep or quit that lands while the reveal is in flight
/// makes the write refuse instead of putting a secret on the pasteboard after
/// the lock that was meant to clear it (`crate::clipboard`, rule 4).
pub async fn entry_copy_at(
    session: &Session,
    clipboard: &Clipboard,
    socket: PathBuf,
    node: String,
    entry: String,
    field: Option<String>,
) -> Result<CopyReceipt, BridgeError> {
    let ticket = clipboard.ticket();
    // ADR-078: an entry with several fields has no one value to copy, so the
    // reveal is narrowed to the field the caller names (`fieldIds`); with none
    // named, a one-field entry still answers `value` and a several-field one is
    // refused as `field_required` without anything having been copied.
    let ids = field.map(|f| vec![f]);
    let mut revealed = entry_reveal_at(session, socket, node, entry, ids)
        .await
        .map_err(without_value)?;
    // From here the plaintext exists in this function and in the pasteboard.
    let secret = take_revealed_value(&mut revealed)?;
    // `fields[0].value` is the same plaintext again: wipe it, not just drop it.
    scrub(&mut revealed);
    drop(revealed);
    clipboard.copy_secret_for(ticket, &secret)?;
    Ok(CopyReceipt {
        copied: true,
        clear_after_seconds: Some(clipboard.ttl().as_secs()),
    })
}

/// Put non-secret text on the clipboard: no markers, no clock.
pub fn copy_text_at(clipboard: &Clipboard, text: &str) -> Result<CopyReceipt, BridgeError> {
    if text.len() > COPY_TEXT_MAX_BYTES {
        return Err(BridgeError::bridge(
            "text_too_large",
            format!("copy_text takes at most {COPY_TEXT_MAX_BYTES} bytes of text"),
        ));
    }
    clipboard.copy_plain(text)?;
    Ok(CopyReceipt {
        copied: true,
        clear_after_seconds: None,
    })
}

/// Copies an entry's value to the clipboard without the value ever entering the
/// webview: revealed Rust-side, written with the concealed and transient
/// markers, cleared after 30 s **only if it is still ours**, and also cleared
/// when the vault locks (including on sleep and screen lock) and when the app
/// quits. See [`crate::clipboard`].
///
/// ADR-078: pass `field` (a field id from `entryGet`) to copy one field of an entry
/// that has several - the reveal is narrowed to it, so the other fields' values
/// never reach this process. Without `field` a one-field entry copies as before and
/// a several-field one is refused with the local code `field_required`.
#[tauri::command]
pub async fn entry_copy(
    session: State<'_, Session>,
    clipboard: State<'_, Clipboard>,
    node: String,
    entry: String,
    field: Option<String>,
) -> Result<CopyReceipt, BridgeError> {
    entry_copy_at(&session, &clipboard, socket()?, node, entry, field).await
}

/// The live preview of a bulk paste: parsed and inferred with `credmgr-core`, in
/// the shell, with no broker call, no session and no audit record
/// ([`crate::fields_preview`]). Give `text` (the paste; `split` makes one entry per
/// `///` block instead of one entry in all) **or** `fields` (structured rows the
/// user has edited), never both. What it answers is what `entry_create` /
/// `entry_create_batch` will store, label and value byte for byte.
#[tauri::command]
pub fn fields_preview(
    text: Option<String>,
    fields: Option<Value>,
    split: Option<bool>,
) -> Result<fields_preview::Preview, BridgeError> {
    fields_preview::preview(text.as_deref(), fields.as_ref(), split.unwrap_or(false))
}

/// Copies non-secret text (a donation address, a node id) to the clipboard with
/// no concealment and no timer. For anything secret use [`entry_copy`]; this
/// command has no way to know the difference, so the caller must.
#[tauri::command]
pub fn copy_text(
    clipboard: State<'_, Clipboard>,
    text: String,
) -> Result<CopyReceipt, BridgeError> {
    copy_text_at(&clipboard, &text)
}

/// Sets the app's icon (the Dock on macOS, the window or taskbar elsewhere) to one of the six marks in
/// [`crate::icon::MARK_IDS`], until the app quits. The webview remembers the choice and calls this again after an unlock.
/// Not a broker op, no session needed: an icon carries no vault data.
#[tauri::command]
pub fn app_icon_set<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    window: tauri::WebviewWindow<R>,
    icon: String,
) -> Result<crate::icon::IconReceipt, BridgeError> {
    crate::icon::set(&app, Some(&window), &icon)
}

/// Turns the window's hiding from screen capture and screen sharing on or off (threat T10; Settings → Security). The window
/// is created protected; the page calls this after it has booted only when the user's stored choice is *off*, and again with
/// `true` when they switch it back on. Not a broker op, no session needed: it carries no vault data, and locking the vault
/// does not change it. The developer environment override (`CREDMGR_CONTENT_PROTECTION=off`) still wins.
#[tauri::command]
pub fn capture_protection_set<R: tauri::Runtime>(
    window: tauri::WebviewWindow<R>,
    enabled: bool,
) -> Result<crate::shell::CaptureReceipt, BridgeError> {
    Ok(crate::shell::set_capture_protection(&window, enabled))
}

/// Whether the window is minimised or hidden (`shell::window_state`). The page asks before it locks on `visibilitychange`, so a
/// window that is only covered, or that sits on another display that went dark, does not lock the vault. Carries no vault data.
#[tauri::command]
pub fn window_state<R: tauri::Runtime>(
    window: tauri::WebviewWindow<R>,
) -> Result<crate::shell::WindowState, BridgeError> {
    Ok(crate::shell::window_state(&window))
}

/// `env_preview` - a `.env` text read into name/value pairs (ADR-122), with the parser
/// `credmgr import-env` runs ([`crate::env_preview`]). Local: no broker, no socket, no session, no
/// audit record. The pairs go on to `entry_import_env`.
#[tauri::command]
pub fn env_preview(text: String) -> Result<env_preview::EnvPreview, BridgeError> {
    env_preview::preview(&text)
}

// ---------------------------------------------------------------------------
// Start at login (ADR-156). Local, no broker call: see `login_agent`.
// ---------------------------------------------------------------------------

async fn login_agent_run(
    f: fn() -> Result<crate::login_agent::LoginAgentStatus, BridgeError>,
) -> Result<crate::login_agent::LoginAgentStatus, BridgeError> {
    tauri::async_runtime::spawn_blocking(f).await.map_err(|e| {
        BridgeError::bridge(
            "worker_failed",
            format!("the launch agent step did not complete: {e}"),
        )
    })?
}

/// Whether the launch agent that starts `credmgrd` at login is in place and loaded. macOS only.
#[tauri::command]
pub async fn login_agent_status() -> Result<crate::login_agent::LoginAgentStatus, BridgeError> {
    login_agent_run(crate::login_agent::status).await
}

/// Write the launch agent (the bundled `credmgrd` by absolute path) and load it into this user's
/// `gui/<uid>` domain, which starts the broker now and at every login. Never root; idempotent.
#[tauri::command]
pub async fn login_agent_install() -> Result<crate::login_agent::LoginAgentStatus, BridgeError> {
    login_agent_run(crate::login_agent::install).await
}

/// Unload the launch agent (stopping the broker it started) and remove its file. Idempotent.
#[tauri::command]
pub async fn login_agent_uninstall() -> Result<crate::login_agent::LoginAgentStatus, BridgeError> {
    login_agent_run(crate::login_agent::uninstall).await
}

// ---------------------------------------------------------------------------
// Settings > Backup > Restore from a backup (ADR-166). Local, no broker call:
// the bundled `credmgr restore --json` does it (see `restore`), and refuses
// while a broker answers on the vault's socket.
// ---------------------------------------------------------------------------

/// Restore a backup archive into an empty folder (`target`, or the vault's own folder when it is
/// empty). The passphrase goes to the `credmgr` child's stdin, never its argv, and this copy is
/// wiped. Refused with `broker_running` while a broker answers, `restore_target_not_empty` for a
/// used folder, `restore_failed` for a wrong passphrase or a damaged archive, and
/// `restore_unavailable` when no `credmgr` program can be found.
#[tauri::command]
pub async fn backup_restore(
    archive: String,
    passphrase: String,
    target: Option<String>,
) -> Result<crate::restore::RestoreDone, BridgeError> {
    let passphrase = Zeroizing::new(passphrase);
    tauri::async_runtime::spawn_blocking(move || {
        crate::restore::restore(archive, passphrase, target)
    })
    .await
    .map_err(|e| {
        BridgeError::bridge(
            "worker_failed",
            format!("the restore did not complete: {e}"),
        )
    })?
}

/// A command the shell offers that is **not** one-to-one with a broker op, so
/// it cannot live in [`bridged`] (whose rows `tests/drift_guards.rs` holds to
/// "command = op with dots as underscores"). Described as data for the same
/// reason as [`BridgedOp`]: the drift guards read it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShellCommand {
    /// The name `invoke()` uses.
    pub command: &'static str,
    /// The Rust argument names; each is its own camelCase key.
    pub args: &'static [&'static str],
    /// The broker op it calls, if any.
    pub wraps_op: Option<&'static str>,
    /// The params it sends to that op.
    pub op_params: &'static [&'static str],
}

/// The shell-only commands.
pub const SHELL_COMMANDS: &[ShellCommand] = &[
    ShellCommand {
        command: "entry_copy",
        args: &["node", "entry", "field"],
        wraps_op: Some("entry.reveal"),
        // `field` is sent as `fieldIds: [field]`.
        op_params: &["node", "entry", "fieldIds"],
    },
    ShellCommand {
        command: "copy_text",
        args: &["text"],
        wraps_op: None,
        op_params: &[],
    },
    // ADR-098, Touch ID. What this Mac can do - local, never prompts.
    ShellCommand {
        command: "presence_probe",
        args: &[],
        wraps_op: None,
        op_params: &[],
    },
    // Create this Mac's Secure Enclave presence key (no prompt) and answer its public half, for
    // `presence_enrol`. Local - no broker op.
    ShellCommand {
        command: "presence_key_create",
        args: &[],
        wraps_op: None,
        op_params: &[],
    },
    ShellCommand {
        command: "app_icon_set",
        args: &["icon"],
        wraps_op: None,
        op_params: &[],
    },
    // Settings → Security: hide the window from screen capture (T10). Local - no broker op.
    ShellCommand {
        command: "capture_protection_set",
        args: &["enabled"],
        wraps_op: None,
        op_params: &[],
    },
    // Is the window minimised or hidden, or only out of sight? Local - no broker op.
    ShellCommand {
        command: "window_state",
        args: &[],
        wraps_op: None,
        op_params: &[],
    },
    // ADR-143, Settings -> Agents. All local - no broker op.
    ShellCommand {
        command: "agent_detect",
        args: &[],
        wraps_op: None,
        op_params: &[],
    },
    ShellCommand {
        command: "agent_snippet",
        args: &["client"],
        wraps_op: None,
        op_params: &[],
    },
    ShellCommand {
        command: "agent_plan",
        args: &["client", "action"],
        wraps_op: None,
        op_params: &[],
    },
    ShellCommand {
        command: "agent_apply",
        args: &["client", "action", "token"],
        wraps_op: None,
        op_params: &[],
    },
    ShellCommand {
        command: "agent_prompt",
        args: &["node", "reachable", "level", "format"],
        wraps_op: None,
        op_params: &[],
    },
    // ADR-078: the bulk-paste preview. Local - no broker op.
    ShellCommand {
        command: "fields_preview",
        args: &["text", "fields", "split"],
        wraps_op: None,
        op_params: &[],
    },
    // ADR-122: a `.env` text read into pairs. Local - no broker op.
    ShellCommand {
        command: "env_preview",
        args: &["text"],
        wraps_op: None,
        op_params: &[],
    },
    // ADR-156: start the broker at login (a launchd user agent). macOS only. Local - no broker op.
    ShellCommand {
        command: "login_agent_status",
        args: &[],
        wraps_op: None,
        op_params: &[],
    },
    ShellCommand {
        command: "login_agent_install",
        args: &[],
        wraps_op: None,
        op_params: &[],
    },
    ShellCommand {
        command: "login_agent_uninstall",
        args: &[],
        wraps_op: None,
        op_params: &[],
    },
    // ADR-166: restore a backup through the bundled `credmgr restore --json`. Local - no broker op.
    ShellCommand {
        command: "backup_restore",
        args: &["archive", "passphrase", "target"],
        wraps_op: None,
        op_params: &[],
    },
];

// ---------------------------------------------------------------------------
// The bridge surface as data.
// ---------------------------------------------------------------------------

/// One bridged broker op, described as data rather than only as code.
///
/// `tests/drift_guards.rs` reads [`bridged`] and compares it against
/// `crates/brokerd/src/ops.rs` on disk, in both directions: every op the
/// broker dispatches must have a command here, and every param a command
/// sends must be one that op's arm actually reads. A command that exists
/// only as code — invisible to that comparison — is exactly the drift the
/// guard exists to make impossible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BridgedOp {
    /// The name `invoke()` uses.
    pub command: &'static str,
    /// The broker op it carries, verbatim.
    pub op: &'static str,
    /// `(wire key, required)` for every param the command can send. An
    /// optional param is omitted from the frame when the caller passes
    /// nothing, so the broker's own default applies rather than one invented
    /// here.
    pub params: &'static [(&'static str, bool)],
    /// The Rust argument names, in the same order as `params`. Tauri exposes
    /// each to `invoke()` under its camelCase form, and every one of those
    /// equals its wire key — held by a test, so a UI author can read one set
    /// of names off either side.
    pub args: &'static [&'static str],
}

/// The commands above that carry hand-written behaviour the table cannot
/// express: token capture and [`AuthState`] for the eight that predate the
/// table (ADR-057) and for `vault_recover` (ADR-163), which captures the login
/// token its answer carries; and for the two agent-token commands (ADR-164)
/// the hand-over of a bearer to the concealed clipboard instead of the webview.
pub const HAND_WRITTEN: &[BridgedOp] = &[
    BridgedOp {
        command: "agent_token_issue",
        op: "agent.token_issue",
        params: &[
            ("node", true),
            ("label", true),
            ("capabilities", true),
            ("expiresIn", false),
        ],
        args: &["node", "label", "capabilities", "expires_in"],
    },
    BridgedOp {
        command: "agent_token_rotate",
        op: "agent.token_rotate",
        params: &[("id", true), ("expiresIn", false)],
        args: &["id", "expires_in"],
    },
    BridgedOp {
        command: "vault_status",
        op: "vault.status",
        params: &[],
        args: &[],
    },
    BridgedOp {
        command: "vault_unlock",
        op: "vault.unlock",
        params: &[("passphrase", false), ("method", false)],
        args: &["passphrase", "method"],
    },
    BridgedOp {
        command: "vault_gate_verify",
        op: "vault.gate_verify",
        params: &[("code", true)],
        args: &["code"],
    },
    BridgedOp {
        command: "vault_recover",
        op: "vault.recover",
        params: &[
            ("recoveryCode", true),
            ("newPassphrase", true),
            ("code", false),
        ],
        args: &["recovery_code", "new_passphrase", "code"],
    },
    BridgedOp {
        command: "vault_lock",
        op: "vault.lock",
        params: &[],
        args: &[],
    },
    BridgedOp {
        command: "whoami",
        op: "whoami",
        params: &[],
        args: &[],
    },
    BridgedOp {
        command: "graph_snapshot",
        op: "graph.snapshot",
        params: &[],
        args: &[],
    },
    BridgedOp {
        command: "entry_list",
        op: "entry.list",
        params: &[("node", true), ("tag", false)],
        args: &["node", "tag"],
    },
    BridgedOp {
        command: "entry_reveal",
        op: "entry.reveal",
        params: &[("node", true), ("entry", true), ("fieldIds", false)],
        args: &["node", "entry", "field_ids"],
    },
];

/// Every command this bridge exposes, hand-written and table-generated alike.
pub fn bridged() -> impl Iterator<Item = &'static BridgedOp> {
    HAND_WRITTEN.iter().chain(TABLE.iter())
}

/// Encode one argument into the params object. `None` (and anything else
/// that serialises to JSON `null`) is left out entirely, so an omitted
/// optional argument reaches the broker as *absent* and its own default
/// applies — the bridge never supplies a default of its own.
fn put<T: Serialize>(
    params: &mut Map<String, Value>,
    key: &str,
    value: &T,
) -> Result<(), BridgeError> {
    let value = serde_json::to_value(value).map_err(|e| {
        BridgeError::bridge(
            "encode_failed",
            format!("could not encode params.{key} for the broker: {e}"),
        )
    })?;
    if !value.is_null() {
        params.insert(key.to_string(), value);
    }
    Ok(())
}

macro_rules! wire_required {
    () => {
        true
    };
    (optional) => {
        false
    };
}

/// Generates, per row: a socket-injected `*_at` core the tests drive, a
/// `#[tauri::command]` wrapper that supplies the real socket, and one
/// [`BridgedOp`] in [`TABLE`] naming the same op and the same wire keys. One
/// row is the single place a command's op name and param names exist, so
/// the code and the metadata the drift guard reads cannot disagree.
///
/// Each generated command is the same thin pass-through as the hand-written
/// ones above: it does not reshape, summarise, or re-interpret what
/// `credmgrd` answers.
macro_rules! bridge_ops {
    ($(
        $(#[$meta:meta])*
        $command:ident / $core:ident => $op:literal {
            $( $arg:ident : $ty:ty => $key:literal $([$opt:ident])? ),* $(,)?
        }
    )*) => {
        $(
            #[doc = concat!("Socket-injected core of [`", stringify!($command), "`] (`", $op, "`).")]
            // One parameter per wire key is the point (a command's arguments ARE the
            // broker's params, held equal by `tests/drift_guards.rs`); the entry write
            // ops carry up to nine (ADR-078), so the count lint is allowed here.
            #[allow(clippy::too_many_arguments)]
            pub async fn $core(
                session: &Session,
                socket: PathBuf,
                $( $arg: $ty, )*
            ) -> Result<Value, BridgeError> {
                #[allow(unused_mut)]
                let mut params = Map::new();
                $( put(&mut params, $key, &$arg)?; )*
                dispatch_at(session, socket, $op, Value::Object(params)).await
            }

            $(#[$meta])*
            #[allow(clippy::too_many_arguments)]
            #[tauri::command]
            pub async fn $command(
                session: State<'_, Session>,
                $( $arg: $ty, )*
            ) -> Result<Value, BridgeError> {
                $core(&session, socket()?, $( $arg, )*).await
            }
        )*

        /// The commands generated by `bridge_ops!` — every broker op not
        /// covered by [`HAND_WRITTEN`].
        pub const TABLE: &[BridgedOp] = &[
            $( BridgedOp {
                command: stringify!($command),
                op: $op,
                params: &[ $( ($key, wire_required!($($opt)?)) ),* ],
                args: &[ $( stringify!($arg) ),* ],
            }, )*
        ];
    };
}

bridge_ops! {
    // -- Vault bootstrap (ADR-061) — the first-run screen -------------------

    /// First-run step 1: create a vault protected by `passphrase`. Answers
    /// `{recoveryCode}` — shown to the human **once** and never stored by
    /// the bridge; the screen must make them retype it into
    /// [`vault_init_confirm`]. Refused with `vault_already_initialized` or
    /// `vault_inside_git_working_tree`.
    vault_init_begin / vault_init_begin_at => "vault.init_begin" {
        passphrase: String => "passphrase",
    }

    /// First-run step 2: writes the vault on a matching retyped recovery
    /// code. Answers `{initialized: true}`; a mismatch is
    /// `recovery_code_mismatch` and leaves the pending setup in place.
    vault_init_confirm / vault_init_confirm_at => "vault.init_confirm" {
        recovery_code: String => "recoveryCode",
    }

    // -- Gate enrolment (`07_TWO_FACTOR.md §4`) -----------------------------

    /// Begins enrolling the vault's TOTP gate. Answers `{otpauthUri}` — the
    /// seed, for a QR code. Needs `Admin`. Replacing a gate already in force
    /// also needs the gate's second factor, fresh — the elevation window a
    /// successful `vault_gate_verify` opens — or it rejects with
    /// `two_factor_required` (ADR-064).
    vault_gate_enroll_begin / vault_gate_enroll_begin_at => "vault.gate_enroll_begin" {}

    /// Confirms enrolment with one valid `code`. Answers `{recoveryCodes}`,
    /// exactly once. `gate_not_enrolling` if no enrolment is in flight.
    /// Over an already-confirmed gate this completes a re-enrolment; until
    /// it does, the old gate stays in force (ADR-064).
    vault_gate_enroll_confirm / vault_gate_enroll_confirm_at => "vault.gate_enroll_confirm" {
        code: String => "code",
    }

    /// The last door (ADR-064, `07_TWO_FACTOR.md §4`): the vault passphrase
    /// **and** the printed root recovery code together reset a lost gate.
    /// Answers `{gateReset}`; it does not unlock — the screen then calls
    /// `vault_unlock` with the passphrase and offers re-enrolment. A wrong
    /// pair is `wrong_passphrase`, without saying which factor failed.
    vault_gate_recover / vault_gate_recover_at => "vault.gate_recover" {
        passphrase: String => "passphrase",
        recovery_code: String => "recoveryCode",
    }

    // -- Locked-write tray (F-1) and approvals (ADR-042) --------------------

    /// Entries written while the vault was locked, awaiting review:
    /// `{node, pending: [...]}`.
    vault_pending_list / vault_pending_list_at => "vault.pending_list" {
        node: String => "node",
    }

    /// Accepts one pending write into the node. Answers the new `generation`.
    vault_pending_accept / vault_pending_accept_at => "vault.pending_accept" {
        node: String => "node",
        entry: String => "entry",
    }

    /// Discards one pending write.
    vault_pending_discard / vault_pending_discard_at => "vault.pending_discard" {
        node: String => "node",
        entry: String => "entry",
    }

    /// Answers an `approval_pending` request (the one-tap path a locked
    /// reveal opens, ADR-042) with `approved` true or false. With `passphrase`
    /// (and `code`, the authenticator code, when two-factor is on) the decision
    /// is authorised by the unlock factors while the vault stays locked
    /// (ADR-088); the window has no screen for that yet - declared so the call
    /// site is right the day it does.
    vault_approval_decide / vault_approval_decide_at => "vault.approval_decide" {
        request: String => "request",
        approved: bool => "approved",
        passphrase: Option<String> => "passphrase" [optional],
        code: Option<String> => "code" [optional],
    }

    /// What a waiting request asks for (ADR-090): `{request, node, entry,
    /// nodeLabel, entryName, command, state, expiresIn, requestedAt, nameHidden?,
    /// cwd?}`, or, with no `request`, `{pending: [...]}` of every request waiting.
    /// Read-only; works while the vault is locked (then for any caller, with names
    /// withheld for `privateNames` nodes); on an unlocked vault the owner's login
    /// only. Not an MCP tool.
    vault_approval_get / vault_approval_get_at => "vault.approval_get" {
        request: Option<String> => "request" [optional],
    }

    // -- Per-node lock (F-7) ------------------------------------------------

    /// Locks one node. Answers `{node, locked: true}` — about **that node**,
    /// which is why `Session::reconcile_ok` does not read it as the vault
    /// locking (`session::VAULT_STATE_OPS`).
    vault_node_lock / vault_node_lock_at => "vault.node_lock" {
        node: String => "node",
    }

    /// Unlocks one node.
    vault_node_unlock / vault_node_unlock_at => "vault.node_unlock" {
        node: String => "node",
    }

    // -- Node lifecycle (`09_UI_UX_SPEC.md §9`) -----------------------------

    /// Nodes this scope may list: `{nodes: [...]}`. Filtered broker-side.
    node_list / node_list_at => "node.list" {}

    /// Creates a node `id` labelled `label` under `parent_id` (sent as
    /// `parentId`). Depth is capped at 2 by the broker, not here. `workdirs`
    /// optionally binds directories that scope an agent to it (ADR-066).
    node_create / node_create_at => "node.create" {
        id: String => "id",
        label: String => "label",
        parent_id: String => "parentId",
        workdirs: Option<Vec<String>> => "workdirs" [optional],
    }

    /// Replaces a node's bound directories (ADR-066) — absolute, existing,
    /// stored canonical, one directory to one node. Human-only; `[]` clears.
    node_set_workdirs / node_set_workdirs_at => "node.set_workdirs" {
        node: String => "node",
        workdirs: Vec<String> => "workdirs",
    }

    /// Renames a node (ADR-071). The id never changes — only the label a
    /// human reads: trimmed, 1–120 characters, no control characters.
    /// Human-only (`Capability::Admin` on the node).
    node_update / node_update_at => "node.update" {
        node: String => "node",
        label: String => "label",
    }

    /// Changes a node's policy by partial patch (ADR-071). `policy` holds any
    /// of `siblingVisibility`, `descendantRead`, `requireTwoFactor`,
    /// `lockAfterSeconds` (`null` clears), `privateNames`, `agentAccess`;
    /// `reason` is mandatory and lands in the audit record. Turning on
    /// `descendantRead`, or letting children share, widens reach and answers
    /// `presence_required` until presence can be attested.
    node_policy / node_policy_at => "node.policy" {
        node: String => "node",
        reason: String => "reason",
        policy: Value => "policy",
    }

    // -- The switchboard (ADR-155) — Settings reads and writes through it ----

    /// Every setting (`credmgr_core::settings::SETTINGS`) with its value, default, risk and the caller's rule; a
    /// project's settings too when `node` is given.
    settings_list / settings_list_at => "settings.list" {
        node: Option<String> => "node" [optional],
    }

    /// One setting in full, with its recent recorded changes.
    settings_get / settings_get_at => "settings.get" {
        id: String => "id",
        node: Option<String> => "node" [optional],
    }

    /// Changes a setting. The owner's change follows the rules the app always had (Touch ID to widen a project's reach,
    /// a fresh confirmation to loosen "confirm before showing secrets"); the answer carries the change id.
    settings_set / settings_set_at => "settings.set" {
        id: String => "id",
        value: Value => "value",
        reason: String => "reason",
        node: Option<String> => "node" [optional],
    }

    /// Puts back the value a recorded change replaced.
    settings_revert / settings_revert_at => "settings.revert" {
        change: String => "change",
        reason: Option<String> => "reason" [optional],
    }

    /// One waiting or decided agent request.
    settings_request_get / settings_request_get_at => "settings.request_get" {
        request: String => "request",
    }

    /// Every agent request (owner only).
    settings_request_list / settings_request_list_at => "settings.request_list" {}

    /// Approve or deny an agent's request (owner only). Approving a weakening change needs a fresh confirmation
    /// (`confirmation_required` until `session.confirm`).
    settings_request_decide / settings_request_decide_at => "settings.request_decide" {
        request: String => "request",
        approve: bool => "approve",
    }

    /// The LLM knowledge base, as Markdown.
    settings_kb / settings_kb_at => "settings.kb" {}

    // -- Notes (ADR-072) — the inspector's Notes section --------------------

    /// Reads a node's note — `{markdown, modified}`, `markdown: ""` when there
    /// is none. Needs the `notes` capability (never implied by `read`) and
    /// the node unlocked; a file that does not match its manifest digest is
    /// refused as `internal`.
    notes_read / notes_read_at => "notes.read" {
        node: String => "node",
    }

    /// Replaces a node's note (≤ 64 KiB of markdown; `""` removes it).
    /// `generation` is the manifest generation last read — a mismatch is
    /// `conflict`, as for an entry update.
    notes_write / notes_write_at => "notes.write" {
        node: String => "node",
        markdown: String => "markdown",
        generation: u64 => "generation",
    }

    /// Seals a node into Orphaned — names stay, values become human-only.
    node_seal / node_seal_at => "node.seal" {
        node: String => "node",
    }

    /// Restores a sealed node within its recovery window.
    node_restore / node_restore_at => "node.restore" {
        node: String => "node",
    }

    /// Moves a node under `new_parent` (sent as `newParent`). `reason` must
    /// be at least 8 characters. Needs presence (F-8), which no transport can
    /// attest yet, so the broker currently refuses every call with
    /// `presence_required` — wired now so the screen needs no change the day
    /// that lands.
    node_reparent / node_reparent_at => "node.reparent" {
        node: String => "node",
        new_parent: String => "newParent",
        reason: String => "reason",
    }

    // -- Grants (`09_UI_UX_SPEC.md §10`, `06_ACCESS_GRAPH.md §10.6`) --------

    /// Grants visible to this scope: `{grants: [...]}` — also the data
    /// source for the graph's dashed grant edges, which `graph.snapshot`
    /// does not emit.
    grant_list / grant_list_at => "grant.list" {}

    /// Creates a grant from node `from` to `to` — passed through verbatim as
    /// `{kind: "node"|"entry", nodeId, entryId?}`; the broker validates it.
    /// `scope` may hold only `read`, `reveal`, `notes`; `reason` must be at
    /// least 8 characters. Human-only, Pro-only in the UI.
    grant_create / grant_create_at => "grant.create" {
        from: String => "from",
        to: Value => "to",
        scope: Vec<String> => "scope",
        reason: String => "reason",
        direction: Option<String> => "direction" [optional],
        expires_at: Option<u64> => "expiresAt" [optional],
    }

    /// Revokes grant `id`. In both modes — revocation is safety, not a lever.
    grant_revoke / grant_revoke_at => "grant.revoke" {
        id: String => "id",
    }

    // -- Entry mutation (`09_UI_UX_SPEC.md §7`, `§8`) -----------------------
    //
    // Every op that changes an existing entry echoes the `generation` the
    // screen last saw (`entry_list`); the broker answers `conflict` with both
    // generations in `detail` if the node has moved on (F-9).

    /// Creates entry `name` in `node` (ADR-078): give **one of** `value` (a
    /// one-field entry; `label` is the field's free-text label, the broker
    /// defaulting it to `value`) **or** `fields` - `[{label, value, type?,
    /// masked?}]`, the order kept. `entry_type` (sent as `entryType`) and
    /// `sensitivity` pin the entry's own type and sensitivity; leave them out to
    /// infer them from the fields, and send `"auto"` only to clear a pinned one.
    /// Answers `{node, entry, pending, generation?, fieldCount, fieldIds}` -
    /// `pending: true` and no generation when the vault is locked (F-1's tray).
    entry_create / entry_create_at => "entry.create" {
        node: String => "node",
        name: String => "name",
        value: Option<String> => "value" [optional],
        label: Option<String> => "label" [optional],
        fields: Option<Value> => "fields" [optional],
        entry_type: Option<String> => "entryType" [optional],
        sensitivity: Option<String> => "sensitivity" [optional],
    }

    /// Creates many entries in one node (ADR-073) — `.env` import and a
    /// many-entry paste. `entries` is `[{name, value?, label?, fields?,
    /// entryType?, sensitivity?}]` (each item the body of `entry_create`,
    /// ADR-078), 1–500 of them. Every item is validated, and every name checked,
    /// before anything is written; a failure part-way answers `complete: false`
    /// with the ones created.
    entry_create_batch / entry_create_batch_at => "entry.create_batch" {
        node: String => "node",
        entries: Value => "entries",
    }

    /// Changes an entry (ADR-078). `value` replaces one field's value - the
    /// entry's only field, or the one `field` (an id) names; on a several-field
    /// entry without `field` the broker refuses. `label` renames that field.
    /// `fields` instead replaces the whole list (`[{id?, label, value, type?,
    /// masked?}]`: an `id` keeps a field's identity, the rest are dropped) and
    /// excludes `value`/`label`/`field`. `entry_type` / `sensitivity` set or
    /// (`"auto"`) clear the entry's pinned type / sensitivity. At least one of
    /// `value`, `fields`, `entryType`, `sensitivity`. Keeps no history.
    entry_update / entry_update_at => "entry.update" {
        node: String => "node",
        entry: String => "entry",
        value: Option<String> => "value" [optional],
        generation: u64 => "generation",
        label: Option<String> => "label" [optional],
        field: Option<String> => "field" [optional],
        fields: Option<Value> => "fields" [optional],
        entry_type: Option<String> => "entryType" [optional],
        sensitivity: Option<String> => "sensitivity" [optional],
    }

    /// Rotates an entry - the same body as [`entry_update`] - keeping the
    /// previous envelope as history (undoable); answers `rotatedAt`.
    entry_rotate / entry_rotate_at => "entry.rotate" {
        node: String => "node",
        entry: String => "entry",
        value: Option<String> => "value" [optional],
        generation: u64 => "generation",
        label: Option<String> => "label" [optional],
        field: Option<String> => "field" [optional],
        fields: Option<Value> => "fields" [optional],
        entry_type: Option<String> => "entryType" [optional],
        sensitivity: Option<String> => "sensitivity" [optional],
    }

    /// One entry's metadata (ADR-078), **never a value**: its type,
    /// sensitivity, `fieldCount`, `hasTotp`, generation, and for each field its
    /// id, label, effective type and masking (plus whether the type / masking is
    /// pinned). Labels are encrypted with the values, so this needs the vault
    /// **and the node** unlocked - `vault_locked` / `node_locked` otherwise, with
    /// no approval path. `read` capability.
    entry_get / entry_get_at => "entry.get" {
        node: String => "node",
        entry: String => "entry",
    }

    /// Adds fields to an entry (ADR-078): `fields` is `[{label, value, type?,
    /// masked?}]`, appended - or inserted at `position` (0 is first). Adding
    /// never replaces. Generation-checked; retains history, so `entry_undo`
    /// reverses it. Answers `{node, entry, generation, fieldCount, fieldIds,
    /// added}` (`added` = the ids minted, in order).
    field_add / field_add_at => "field.add" {
        node: String => "node",
        entry: String => "entry",
        generation: u64 => "generation",
        fields: Value => "fields",
        position: Option<u64> => "position" [optional],
    }

    /// Changes one field (ADR-078): `patch` holds any of `label`, `value`,
    /// `type`, `masked`, at least one. `type` / `masked` take `"auto"` to go back
    /// to inferring; a changed `value` / `label` re-infers an un-pinned type. The
    /// patch is an object (like `node_policy`'s) so the Rust keyword `type` is not
    /// an argument name. Generation-checked, undoable.
    field_update / field_update_at => "field.update" {
        node: String => "node",
        entry: String => "entry",
        generation: u64 => "generation",
        field: String => "field",
        patch: Value => "patch",
    }

    /// Removes one field (ADR-078). An entry keeps at least one field: removing
    /// the last is `malformed_request`. Generation-checked, undoable.
    field_remove / field_remove_at => "field.remove" {
        node: String => "node",
        entry: String => "entry",
        generation: u64 => "generation",
        field: String => "field",
    }

    /// Reorders an entry's fields (ADR-078): `order` must list every current
    /// field id exactly once. Generation-checked, undoable.
    field_reorder / field_reorder_at => "field.reorder" {
        node: String => "node",
        entry: String => "entry",
        generation: u64 => "generation",
        order: Vec<String> => "order",
    }

    /// Removes an entry into its 7-day recovery window (ADR-048).
    entry_remove / entry_remove_at => "entry.remove" {
        node: String => "node",
        entry: String => "entry",
        generation: u64 => "generation",
    }

    /// Restores a removed entry within its window. `mode` is `"replace"`
    /// (the broker's default) or `"keep-both"`.
    entry_restore / entry_restore_at => "entry.restore" {
        node: String => "node",
        entry: String => "entry",
        generation: u64 => "generation",
        mode: Option<String> => "mode" [optional],
    }

    /// Undoes the change recorded by audit record `id` — only an
    /// `entry.rotate`, an `entry.remove` or a field edit (`field.add`, `.update`,
    /// `.remove`, `.reorder`, ADR-078) is undoable (ADR-055).
    entry_undo / entry_undo_at => "entry.undo" {
        node: String => "node",
        id: String => "id",
        generation: u64 => "generation",
        mode: Option<String> => "mode" [optional],
    }

    // -- Stored TOTP (`07_TWO_FACTOR.md §6`) --------------------------------

    /// The current code for a TOTP entry: `{node, entry, code}`. On an entry
    /// with several fields, `field` (an id) names the one holding the seed;
    /// without it the seed is the only field, else the single TOTP-seed field,
    /// else the call is refused (ADR-078).
    totp_code / totp_code_at => "totp.code" {
        node: String => "node",
        entry: String => "entry",
        field: Option<String> => "field" [optional],
    }

    /// The TOTP entry's seed itself. Human-only; never an MCP tool
    /// (`10_API_AND_MCP.md §3.2`). Takes the same optional `field` as
    /// [`totp_code`] and answers `presence_required` whichever field is meant.
    totp_seed / totp_seed_at => "totp.seed" {
        node: String => "node",
        entry: String => "entry",
        field: Option<String> => "field" [optional],
    }

    // -- Search (`09_UI_UX_SPEC.md §6`) -------------------------------------

    /// Names matching `term` across nodes this scope can read. Results the
    /// caller may not see are omitted broker-side, silently
    /// (`06_ACCESS_GRAPH.md §5`) — never a denial.
    search / search_at => "search" {
        term: String => "term",
    }

    // -- Audit (recent activity, `/settings/audit`) -------------------------

    /// The newest audit records: `{records: [...]}`. `limit` defaults to 50
    /// broker-side and is clamped to 1…500. Recent activity refetches this
    /// after every successful mutation (`19_FRONTEND_DELIVERY_SCOPE.md §6.4`).
    audit_tail / audit_tail_at => "audit.tail" {
        limit: Option<u64> => "limit" [optional],
    }

    /// One unredacted audit record by `id`. Needs presence, so the broker
    /// refuses every call with `presence_required` today; `id` is sent anyway
    /// so the call site is already right (forward-declared — see the drift
    /// guard's `FORWARD_DECLARED`).
    audit_get / audit_get_at => "audit.get" {
        id: String => "id",
    }

    // -- Maintenance (`/settings/backup`, `/settings/maintenance`) ----------

    /// Integrity check of every node: `{ok, nodesChecked, errors, warnings}`.
    maintenance_verify / maintenance_verify_at => "maintenance.verify" {}

    /// Finds, and by default applies, repairs. `apply: false` is a dry run;
    /// `rebuild_registry` (sent as `rebuildRegistry`) is F-10's last-resort
    /// door and needs `passphrase` and `Admin`. `purge_expired_seals` (sent as
    /// `purgeExpiredSeals`, ADR-089) destroys the retained originals of nodes
    /// sealed more than seven days ago; with `apply: false` it only lists them.
    maintenance_doctor / maintenance_doctor_at => "maintenance.doctor" {
        apply: Option<bool> => "apply" [optional],
        rebuild_registry: Option<bool> => "rebuildRegistry" [optional],
        passphrase: Option<String> => "passphrase" [optional],
        purge_expired_seals: Option<bool> => "purgeExpiredSeals" [optional],
    }

    /// Writes an encrypted backup and prunes to `retain` copies (broker
    /// default 14). Answers `{path, retain, pruned}`.
    maintenance_backup / maintenance_backup_at => "maintenance.backup" {
        passphrase: String => "passphrase",
        retain: Option<u64> => "retain" [optional],
    }

    /// Replaces the root key (ADR-076, `04_CRYPTO_AND_KEYS.md §6`): a new key,
    /// every node key re-wrapped under it, both root wraps rewritten, every
    /// signed file signed again, and a **new root recovery code** issued —
    /// answered once as `{recoveryCode}` (plus `nodesRewrapped`,
    /// `vaultGeneration`, `filesReplaced`, `artifactsResigned`,
    /// `completionPending` and `notResigned`), and never stored by the bridge;
    /// the old code stops working at once. `passphrase` is the vault
    /// passphrase again: it is proven first and is what the new passphrase
    /// wrap is made from.
    ///
    /// The spec asks for the 2FA gate's second factor **and** presence, and
    /// presence cannot be attested by any transport yet, so the broker
    /// currently refuses every call with `presence_required` (after
    /// `two_factor_required` when a gate is enrolled and not freshly
    /// verified) — wired now so the screen needs no change the day that lands.
    maintenance_rotate_root / maintenance_rotate_root_at => "maintenance.rotate_root" {
        passphrase: String => "passphrase",
    }

    // -- Post-launch quick wins (ADR-156) ------------------------------------

    /// Change the vault passphrase: the current one proves it is the owner, the new one wraps the
    /// root key. A full root rotation, so the answer carries a NEW `recoveryCode` once (the old code
    /// stops working) — the screen shows it and must not keep it. Owner's login; the vault's second
    /// factor and an enrolled Touch ID key are asked for as for any vault-wide change.
    vault_set_passphrase / vault_set_passphrase_at => "vault.set_passphrase" {
        passphrase: String => "passphrase",
        new_passphrase: String => "newPassphrase",
    }

    /// The owner has seen the cross-node alarm (`vault.status`'s `anomaliesUnseen`); resets it.
    vault_anomalies_ack / vault_anomalies_ack_at => "vault.anomalies_ack" {}

    /// Set an entry's expiry (`expires_at`, unix seconds) or clear it (`clear: true`) — exactly one.
    /// Manifest metadata only.
    entry_set_expiry / entry_set_expiry_at => "entry.set_expiry" {
        node: String => "node",
        entry: String => "entry",
        generation: u64 => "generation",
        expires_at: Option<i64> => "expiresAt" [optional],
        clear: Option<bool> => "clear" [optional],
    }

    /// Entries expiring within `days` (30 when absent), one node or all; names and dates only.
    entry_expiring / entry_expiring_at => "entry.expiring" {
        node: Option<String> => "node" [optional],
        days: Option<u64> => "days" [optional],
    }

    /// One entry's audit trail (actions and times, never a value), plus its edit/rotation/expiry times.
    entry_history / entry_history_at => "entry.history" {
        node: String => "node",
        entry: String => "entry",
        limit: Option<u64> => "limit" [optional],
    }

    /// Names and aliases on one node that contain `term`.
    entry_search / entry_search_at => "entry.search" {
        node: String => "node",
        term: String => "term",
        // ADR-167: only the entries carrying this tag.
        tag: Option<String> => "tag" [optional],
    }

    /// Which entry a vault-global short reference names.
    entry_get_by_ref / entry_get_by_ref_at => "entry.get_by_ref" {
        reference: u64 => "reference",
    }

    // -- ADR-158 ---------------------------------------------------------------

    /// Move an entry to another node, re-encrypted to that node's key. `generation` is the source node's
    /// (F-9). The owner's login only; costs a fresh second factor and a Touch ID check every time, which
    /// this shell attaches when the broker answers `presence_required`. Answers `{node, entry, ref, name,
    /// from, generation, toGeneration, grantsRevoked, historyDropped}` - `node` is where the entry is now,
    /// `generation` the source's new one, `toGeneration` the destination's. Never a value.
    entry_move / entry_move_at => "entry.move" {
        node: String => "node",
        entry: String => "entry",
        to: String => "to",
        generation: u64 => "generation",
        reason: Option<String> => "reason" [optional],
    }

    // -- ADR-161 ---------------------------------------------------------------

    /// The doctor's tidy-up scan, phase 1: findings grouped by kind (shared values, near-identical names,
    /// misfiled, weak, mistyped, expired, expiring, stale), each with a proposal; a move proposal carries the
    /// exact `entry.move` params. Read-only, never a value, digest or fragment of one. The owner's login only.
    vault_doctor_scan / vault_doctor_scan_at => "vault.doctor_scan" {
        stale_days: Option<u64> => "staleDays" [optional],
        expiring_days: Option<u64> => "expiringDays" [optional],
    }

    // -- Node-scoped agent tokens (ADR-164) ----------------------------------
    //
    // Owner's login only; the broker refuses all four to any agent. `issue` and `rotate` are
    // hand-written (above the table): their answer carries a bearer secret, which the shell puts on
    // the concealed clipboard and never hands to the webview. `status` is metadata only.

    /// The live agent tokens, metadata only (never a secret); one node's when `node` is given.
    agent_token_status / agent_token_status_at => "agent.token_status" {
        node: Option<String> => "node" [optional],
    }

    /// End a token: its next request is refused. No proof (it only removes access).
    agent_token_revoke / agent_token_revoke_at => "agent.token_revoke" {
        id: String => "id",
    }

    // -- ADR-167: tags -----------------------------------------------------------

    /// Replace one entry's tags (`[]` clears): normalised by the broker (lower-cased, inner spaces to `-`),
    /// at most 16. Metadata only; the owner's sessions. Echoes the node's new generation and the stored tags.
    entry_tag_set / entry_tag_set_at => "entry.tag_set" {
        node: String => "node",
        entry: String => "entry",
        generation: u64 => "generation",
        tags: Value => "tags",
    }

    // -- ADR-168: merge suggestions and merges inside one node -------------------

    /// Groups of entries in one node that look like one thing (identical values, a shared value, names
    /// alike). Names and ids only; values are compared inside the broker and never leave it.
    merge_suggestions / merge_suggestions_at => "merge.suggestions" {
        node: String => "node",
        include_dismissed: Option<bool> => "includeDismissed" [optional],
    }

    /// Keep one entry and fold the others into it: their names become its aliases, their tags join its
    /// tags, and they are removed (each undoable for 7 days with `entry_undo`). A fresh second factor.
    merge_apply / merge_apply_at => "merge.apply" {
        node: String => "node",
        keep: String => "keep",
        drop: Value => "drop",
        generation: u64 => "generation",
    }

    /// Merge one suggestion, only when its entries' values are all identical. A fresh second factor.
    merge_auto / merge_auto_at => "merge.auto" {
        node: String => "node",
        key: String => "key",
        generation: u64 => "generation",
    }

    /// Every open identical suggestion: a dry run unless `apply` is `true` (then `generation` and a fresh
    /// second factor).
    merge_auto_all / merge_auto_all_at => "merge.auto_all" {
        node: String => "node",
        apply: Option<bool> => "apply" [optional],
        generation: Option<u64> => "generation" [optional],
    }

    /// Remember that a suggestion was rejected: it is not suggested again until undismissed or restored.
    merge_dismiss / merge_dismiss_at => "merge.dismiss" {
        node: String => "node",
        key: String => "key",
    }

    /// Forget one dismissal.
    merge_undismiss / merge_undismiss_at => "merge.undismiss" {
        node: String => "node",
        key: String => "key",
    }

    /// What the node remembers as dismissed, with the names of the entries still in it.
    merge_dismissed_list / merge_dismissed_list_at => "merge.dismissed_list" {
        node: String => "node",
    }

    /// Forget every dismissal on the node.
    merge_restore_all / merge_restore_all_at => "merge.restore_all" {
        node: String => "node",
    }

    // -- ADR-169 ---------------------------------------------------------------

    /// Apply every move of one doctor plan in one request. `moves` is the exact list the scan showed and the
    /// person confirmed: `[{node, entry, to, generation}]`, `generation` each source's from the scan. The
    /// owner's login only; one fresh second factor and one Touch ID check for the whole plan (the shell
    /// attaches the proof when the broker answers `presence_required`; it signs the whole list). Stops at the
    /// first move that fails: `{complete, applied: [entry.move's answer + index], stopped?, notApplied}`.
    /// Never a value.
    vault_doctor_apply / vault_doctor_apply_at => "vault.doctor_apply" {
        moves: Value => "moves",
        reason: Option<String> => "reason" [optional],
    }

    // -- Touch ID and sealed entries (ADR-098) -------------------------------

    /// Ask the broker for a presence challenge for an op. Nothing here is secret (a nonce and the digest
    /// to sign) and nothing the page holds can sign it; the shell itself uses the same op when a request
    /// comes back `presence_required`.
    presence_challenge / presence_challenge_at => "presence.challenge" {
        op: String => "op",
        params: Option<Value> => "params" [optional],
        // ADR-148: `true` asks for the proof-of-possession challenge of `presence.enrol`.
        possession: Option<bool> => "possession" [optional],
    }

    /// ADR-150: confirm it is the owner before the broker shows saved secrets again. With `passphrase`,
    /// the vault passphrase (a wrong one counts in the unlock back-off); without it, a Touch ID proof,
    /// which this shell attaches itself when the broker answers `presence_required`. Opens the
    /// session's trust window: `{confirmed, method, expiresIn}`. The passphrase is never logged or kept.
    session_confirm / session_confirm_at => "session.confirm" {
        passphrase: Option<String> => "passphrase" [optional],
    }

    /// What is set up: the enrolled presence keys, whether Touch ID unlock is on, and what this Mac can do.
    presence_status / presence_status_at => "presence.status" {}

    /// Enrol a presence key's public half (base64, from `presence_key_create`) under a label. The first
    /// key needs only the owner and a fresh second factor; later ones need a Touch ID proof.
    presence_enrol / presence_enrol_at => "presence.enrol" {
        public_key: String => "publicKey",
        label: Option<String> => "label" [optional],
    }

    /// Remove an enrolled presence key by id. With a key enrolled this needs a proof, which the shell
    /// supplies (Touch ID appears).
    presence_unenrol / presence_unenrol_at => "presence.unenrol" {
        id: String => "id",
    }

    /// Turn on unlocking this vault with Touch ID (needs the vault open and a fresh second factor).
    device_enrol / device_enrol_at => "device.enrol" {}

    /// Turn Touch ID unlock off.
    device_remove / device_remove_at => "device.remove" {}

    /// ADR-165: the machine lock's honest state (owner only; never an agent).
    keystore_status / keystore_status_at => "keystore.status" {}

    /// ADR-165: seal the passphrase unlock to this Mac's device key, in two phases (review N1). `phase:
    /// "prepare"` sends the vault passphrase and the CURRENT recovery code (both prove it is the owner; a wrong
    /// one counts in the unlock back-off) and answers a NEW `newRecoveryCode` once, changing nothing; the screen
    /// shows it and must not keep it. `phase: "commit"` sends that new code typed back, and only then is the
    /// root key rotated and every node re-keyed (the old code stops working). `phase: "cancel"` forgets a
    /// prepared bind. No value is logged or kept.
    keystore_bind / keystore_bind_at => "keystore.bind" {
        phase: String => "phase",
        passphrase: Option<String> => "passphrase" [optional],
        recovery_code: Option<String> => "recoveryCode" [optional],
    }

    /// ADR-165: turn the machine lock off. With a presence key enrolled this needs a proof, which the shell
    /// supplies (Touch ID appears); with a second factor on, a fresh one; with neither, the vault
    /// passphrase (`passphrase`, which counts in the unlock back-off).
    keystore_unbind / keystore_unbind_at => "keystore.unbind" {
        passphrase: Option<String> => "passphrase" [optional],
    }

    /// The sealed ("orphaned") entries - names only.
    orphan_list / orphan_list_at => "orphan.list" {}

    /// Read one sealed entry. Costs a fresh second factor and a Touch ID check every time.
    orphan_reveal / orphan_reveal_at => "orphan.reveal" {
        entry: String => "entry",
        field_ids: Option<Vec<String>> => "fieldIds" [optional],
    }

    // -- 2.0.0 broker features (ADR-130…134) -----------------------------------

    /// Replace a node's keypair and re-seal everything sealed to the old one (ADR-130). Costs a fresh
    /// second factor and a Touch ID check; one at a time. Answers `{node, publicKey, entries, note,
    /// history, removed}`.
    node_rekey / node_rekey_at => "node.rekey" {
        node: String => "node",
    }

    /// Permanently destroy sealed entries and the archives behind them (ADR-131). `confirm` is the fixed
    /// word `destroy-sealed-entries`; `count` is the number of entries the person was shown and the broker
    /// compares it. `entries` names ids; absent means every sealed entry. Costs a fresh second factor and a
    /// Touch ID check. Cannot be undone.
    orphan_destroy / orphan_destroy_at => "orphan.destroy" {
        confirm: String => "confirm",
        count: u64 => "count",
        entries: Option<Vec<String>> => "entries" [optional],
    }

    /// Entries whose field VALUES contain `term` (ADR-132): `{results: [{node, id, name}], truncated}` -
    /// never a value. Needs `reveal`; 12 searches a minute; a private node is never searched for an agent.
    search_content / search_content_at => "search.content" {
        term: String => "term",
        node: Option<String> => "node" [optional],
    }

    /// An age-encrypted archive of a node (ADR-133), built inside the broker: `{archive (base64),
    /// entries, omittedSeeds, format}`. Exactly one of `passphrase` or `recipients`. Costs a fresh second
    /// factor and a Touch ID check. The shell writes the file; the page never holds the plaintext.
    node_export / node_export_at => "node.export" {
        node: String => "node",
        passphrase: Option<String> => "passphrase" [optional],
        recipients: Option<Vec<String>> => "recipients" [optional],
    }

    /// A summary of the audit log for `[from, to)` (unix seconds): counts by action, actor and node,
    /// denials, presence uses, and whether the hash chain verifies (ADR-134). No values, no names.
    audit_report / audit_report_at => "audit.report" {
        from: u64 => "from",
        to: u64 => "to",
        node: Option<String> => "node" [optional],
    }

    // -- A node's own second factor (ADR-135) ---------------------------------

    /// Begin giving a project a second factor of its own: `{node, otpauthUri}`. Replacing one in force
    /// needs that factor's code, fresh. Owner login only; not for `global` (the vault's own gate has
    /// `vault_gate_*`).
    node_gate_enroll_begin / node_gate_enroll_begin_at => "node.gate_enroll_begin" {
        node: String => "node",
    }

    /// Confirm it with one valid `code`: `{node, recoveryCodes}`, once - ten codes of this node's own.
    node_gate_enroll_confirm / node_gate_enroll_confirm_at => "node.gate_enroll_confirm" {
        node: String => "node",
        code: String => "code",
    }

    /// Step up for one node: its own code, fresh for five minutes, opening that node and no other.
    node_gate_verify / node_gate_verify_at => "node.gate_verify" {
        node: String => "node",
        code: String => "code",
    }

    /// Remove a project's own second factor: with its fresh code and Touch ID (send neither optional), or
    /// the last door - `passphrase` and the root `recoveryCode` together - when the authenticator is lost.
    node_gate_remove / node_gate_remove_at => "node.gate_remove" {
        node: String => "node",
        passphrase: Option<String> => "passphrase" [optional],
        recovery_code: Option<String> => "recoveryCode" [optional],
    }

    // -- Generator (ADR-087) -------------------------------------------------

    /// Makes a password in the broker — never in page JavaScript. `length`
    /// (8-128, default 20), `symbols` (default on), `pronounceable` (default
    /// off) and `hex` (default off; lower-case hex, never with `pronounceable`
    /// or `symbols: true`) are all optional. Answers `{value, length, symbols, pronounceable,
    /// entropyBits}`; the value reaches a field only through `field_add`,
    /// `field_update` or `entry_create`, and is shown masked. Needs `create` or
    /// `update`; not an MCP tool.
    util_generate / util_generate_at => "util.generate" {
        length: Option<u64> => "length" [optional],
        symbols: Option<bool> => "symbols" [optional],
        pronounceable: Option<bool> => "pronounceable" [optional],
        hex: Option<bool> => "hex" [optional],
    }

    // -- Aliases, near-duplicate names, .env import (ADR-121, ADR-122) -------

    /// Sets the other names one entry answers to: the whole list, at most 8, `[]`
    /// clears it. Metadata only; a human session with `update`. Not an MCP tool.
    entry_alias / entry_alias_at => "entry.alias" {
        node: String => "node",
        entry: String => "entry",
        generation: u64 => "generation",
        aliases: Value => "aliases",
    }

    /// Which entries of a node have a name or alias resembling `name`, and whether
    /// `name` is already taken. `entry` leaves one entry out.
    entry_similar / entry_similar_at => "entry.similar" {
        node: String => "node",
        name: String => "name",
        entry: Option<String> => "entry" [optional],
    }

    /// A parsed `.env` file (name/value pairs the client read, 1-500) into one node.
    /// `dry_run` (sent as `dryRun`) lists what each pair would become and writes nothing;
    /// `on_conflict` (sent as `onConflict`) is `"refuse"` (default) or `"skip"`. Each
    /// pair becomes its own entry with its own audit record. No answer carries a value.
    entry_import_env / entry_import_env_at => "entry.import_env" {
        node: String => "node",
        entries: Value => "entries",
        dry_run: Option<bool> => "dryRun" [optional],
        on_conflict: Option<String> => "onConflict" [optional],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bridge_names_one_command_per_distinct_op() {
        let all: Vec<&BridgedOp> = bridged().collect();
        assert_eq!(all.len(), 111, "HAND_WRITTEN (11) + TABLE (100)");
        let mut ops: Vec<&str> = all.iter().map(|b| b.op).collect();
        ops.sort_unstable();
        ops.dedup();
        assert_eq!(ops.len(), 111, "no op is bridged twice");
        let mut commands: Vec<&str> = all.iter().map(|b| b.command).collect();
        commands.sort_unstable();
        commands.dedup();
        assert_eq!(commands.len(), 111, "no command name is used twice");
    }

    #[test]
    fn the_audit_passthrough_names_real_ops_and_only_changing_ones() {
        let ops: Vec<&str> = bridged().map(|b| b.op).collect();
        for op in AUDIT_PASSTHROUGH {
            assert!(ops.contains(op), "{op} is not a bridged op");
        }
        let mut sorted = AUDIT_PASSTHROUGH.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), AUDIT_PASSTHROUGH.len(), "listed twice");
        for read in [
            "entry.reveal",
            "entry.list",
            "entry.get",
            "graph.snapshot",
            "audit.tail",
            "vault.status",
            "vault.approval_get",
            "util.generate",
        ] {
            assert!(!AUDIT_PASSTHROUGH.contains(&read), "{read} is a read");
        }
    }

    #[test]
    fn attach_audit_adds_a_member_to_an_object_answer_of_a_changing_op_only() {
        let mut changed = json!({ "generation": 4 });
        attach_audit("field.add", &mut changed, Some("a_1".into()));
        assert_eq!(changed, json!({ "generation": 4, "audit": "a_1" }));

        let mut read = json!({ "entries": [] });
        attach_audit("entry.list", &mut read, Some("a_2".into()));
        assert_eq!(read, json!({ "entries": [] }));

        let mut theirs = json!({ "audit": "kept" });
        attach_audit("field.add", &mut theirs, Some("a_3".into()));
        assert_eq!(theirs["audit"], "kept");

        let mut none = json!({ "generation": 4 });
        attach_audit("field.add", &mut none, None);
        assert_eq!(none, json!({ "generation": 4 }));

        let mut not_object = json!([1]);
        attach_audit("field.add", &mut not_object, Some("a_4".into()));
        assert_eq!(not_object, json!([1]));
    }

    #[test]
    fn every_command_name_is_its_op_with_dots_as_underscores() {
        // The naming rule the module docs state, held for every row rather
        // than trusted — a UI author guessing `invoke()` names from op names
        // must be right every time.
        for b in bridged() {
            assert_eq!(b.command, b.op.replace('.', "_"), "{b:?}");
        }
    }

    #[test]
    fn every_invoke_argument_name_is_its_wire_key() {
        // Tauri maps a snake_case Rust argument to a camelCase `invoke()`
        // key. Holding that key equal to the wire key means the UI's
        // `invoke("node_create", { id, label, parentId })` and the broker's
        // `params.parentId` are the same word — one vocabulary, not two.
        fn camel(snake: &str) -> String {
            let mut out = String::new();
            let mut upper = false;
            for c in snake.chars() {
                if c == '_' {
                    upper = true;
                } else if upper {
                    out.extend(c.to_uppercase());
                    upper = false;
                } else {
                    out.push(c);
                }
            }
            out
        }
        for b in bridged() {
            assert_eq!(b.args.len(), b.params.len(), "{}", b.command);
            for (arg, (key, _)) in b.args.iter().zip(b.params) {
                assert_eq!(
                    camel(arg),
                    *key,
                    "{}: arg {arg} vs wire key {key}",
                    b.command
                );
            }
        }
    }

    #[test]
    fn the_shell_commands_are_seventeen_and_their_arguments_are_single_words() {
        // A single-word snake_case argument is its own camelCase `invoke()` key,
        // so `bridge.ts` and the Rust signature read the same.
        assert_eq!(SHELL_COMMANDS.len(), 18);
        for s in SHELL_COMMANDS {
            for arg in s.args {
                assert!(!arg.contains('_'), "{}: {arg}", s.command);
            }
            assert_eq!(
                s.wraps_op.is_some(),
                !s.op_params.is_empty(),
                "{}",
                s.command
            );
        }
    }

    #[test]
    fn a_revealed_value_is_moved_out_of_the_answer_not_copied() {
        let mut answer = json!({ "node": "acme", "entry": "e_1", "value": "s3cret" });
        let secret = take_revealed_value(&mut answer).unwrap();
        assert_eq!(secret.as_str(), "s3cret");
        assert!(
            answer.get("value").is_none(),
            "the answer must not keep a second copy of the value"
        );
        assert!(!answer.to_string().contains("s3cret"));
    }

    #[test]
    fn anything_but_text_is_refused_and_a_missing_value_is_a_protocol_error() {
        for odd in [
            json!(7),
            json!(true),
            json!(["s3cret"]),
            json!({ "k": "s3cret" }),
        ] {
            let mut answer = json!({ "value": odd });
            let error = take_revealed_value(&mut answer).unwrap_err();
            assert_eq!(error.code, "malformed_response");
            assert!(!error.message.contains("s3cret"), "{}", error.message);
        }
        let mut answer = json!({ "node": "acme" });
        assert_eq!(
            take_revealed_value(&mut answer).unwrap_err().code,
            "malformed_response"
        );
        // A bare scalar answer has no object to take from.
        let mut answer = json!("s3cret");
        assert!(take_revealed_value(&mut answer).is_err());
    }

    #[test]
    fn a_one_field_answer_leaves_the_value_in_fields_until_scrubbed() {
        // ADR-078: `fields[0].value` is the same plaintext as `value`. Taking `value`
        // is not enough - the caller must wipe the rest, and can.
        let mut answer = json!({
            "node": "acme", "entry": "e_1",
            "fields": [{ "id": "f_00000000", "label": "token", "value": "s3cret", "type": "text", "masked": false }],
            "value": "s3cret",
        });
        let secret = take_revealed_value(&mut answer).unwrap();
        assert_eq!(secret.as_str(), "s3cret");
        assert!(
            answer.to_string().contains("s3cret"),
            "the value is still in fields[0] until the caller wipes it"
        );
        scrub(&mut answer);
        assert!(!answer.to_string().contains("s3cret"), "{answer}");
        assert_eq!(
            answer["fields"][0]["value"], "",
            "wiped in place, not just dropped"
        );
    }

    #[test]
    fn a_several_field_answer_is_field_required_and_is_wiped_before_it_is_refused() {
        let mut answer = json!({
            "node": "acme", "entry": "e_1",
            "fields": [
                { "id": "f_0a1b2c3d", "label": "host", "value": "NEEDLE-A" },
                { "id": "f_4e5f6a7b", "label": "password", "value": "NEEDLE-B" },
            ],
        });
        let error = take_revealed_value(&mut answer).unwrap_err();
        assert_eq!(error.code, "field_required");
        assert!(error.message.contains("2 fields"), "{}", error.message);
        assert!(
            !error.message.contains("NEEDLE")
                && !serde_json::to_string(&error).unwrap().contains("NEEDLE"),
            "the refusal quotes no value"
        );
        assert!(
            !answer.to_string().contains("NEEDLE"),
            "every revealed field was wiped before the refusal: {answer}"
        );

        // An answer with no value and no several fields is still a protocol error.
        let mut empty = json!({ "node": "acme", "fields": [] });
        assert_eq!(
            take_revealed_value(&mut empty).unwrap_err().code,
            "malformed_response"
        );
    }

    #[test]
    fn a_refusal_loses_a_fields_key_too() {
        let wire = json!({
            "id": "1", "ok": false, "error": "node_access_denied",
            "fields": [{ "value": "plaintext" }], "value": "plaintext"
        });
        let stripped = without_value(BridgeError::from_wire(&wire));
        let detail = stripped.detail.expect("the reasons are kept");
        assert!(detail.get("fields").is_none() && detail.get("value").is_none());
    }

    #[test]
    fn scrub_wipes_every_string_however_deeply_nested() {
        let mut value = json!({ "a": ["x", { "b": "y" }], "c": "z", "n": 1 });
        scrub(&mut value);
        assert_eq!(value, json!({ "a": ["", { "b": "" }], "c": "", "n": 1 }));
    }

    #[test]
    fn a_refusal_loses_a_value_field_and_keeps_every_reason() {
        let wire = json!({
            "id": "1", "ok": false, "error": "node_access_denied",
            "rule": "R8", "remedy": "ask for a grant", "value": "plaintext"
        });
        let stripped = without_value(BridgeError::from_wire(&wire));
        let detail = stripped.detail.expect("the reasons are kept");
        assert!(detail.get("value").is_none());
        assert_eq!(detail["rule"], "R8");
        assert_eq!(detail["remedy"], "ask for a grant");
        assert_eq!(stripped.code, "node_access_denied");

        // Nothing to remove, nothing to invent: a transport failure has no detail.
        let bare = without_value(BridgeError::transport("no socket"));
        assert!(bare.detail.is_none());
    }

    #[test]
    fn the_receipt_has_no_field_a_value_could_travel_in() {
        let timed = serde_json::to_value(CopyReceipt {
            copied: true,
            clear_after_seconds: Some(30),
        })
        .unwrap();
        assert_eq!(timed, json!({ "copied": true, "clearAfterSeconds": 30 }));
        let plain = serde_json::to_value(CopyReceipt {
            copied: true,
            clear_after_seconds: None,
        })
        .unwrap();
        assert_eq!(plain, json!({ "copied": true, "clearAfterSeconds": null }));
    }

    #[test]
    fn an_omitted_optional_param_is_absent_not_null() {
        let mut params = Map::new();
        put(&mut params, "label", &None::<String>).unwrap();
        put(&mut params, "node", &"acme".to_string()).unwrap();
        assert_eq!(Value::Object(params), json!({ "node": "acme" }));
    }

    #[test]
    fn an_unreadable_lock_flag_reads_as_locked_not_as_ready() {
        assert!(locked_from(&json!({})));
        assert!(locked_from(&json!({ "locked": "no" })));
        assert!(!locked_from(&json!({ "locked": false })));
    }

    #[test]
    fn auth_state_serialises_without_anything_token_shaped() {
        let json = serde_json::to_string(&AuthState {
            locked: false,
            authenticated: true,
            initialized: true,
            pending_approvals: 0,
            touch_id_unlock: false,
            anomalies_unseen: 0,
            recovery_unlock: false,
        })
        .unwrap();
        assert_eq!(
            json,
            r#"{"locked":false,"authenticated":true,"initialized":true}"#
        );
        assert!(!json.contains("token"));
        // ADR-090: a waiting count rides along only when there is one.
        let json = serde_json::to_string(&AuthState {
            locked: true,
            authenticated: false,
            initialized: true,
            pending_approvals: 2,
            touch_id_unlock: false,
            anomalies_unseen: 0,
            recovery_unlock: false,
        })
        .unwrap();
        assert_eq!(
            json,
            r#"{"locked":true,"authenticated":false,"initialized":true,"pendingApprovals":2}"#
        );
    }

    #[test]
    fn a_missing_or_unreadable_waiting_count_reads_as_none_waiting() {
        assert_eq!(pending_from(&json!({})), 0);
        assert_eq!(pending_from(&json!({ "pendingApprovals": "3" })), 0);
        assert_eq!(pending_from(&json!({ "pendingApprovals": 3 })), 3);
    }

    #[test]
    fn the_anomaly_count_reaches_the_page_only_when_there_is_one() {
        // ADR-156: `vault.status` carries `anomaliesUnseen` to the owner's login only; the page's
        // copy carries it on, and leaves it out at 0 (or when the broker did not send it).
        let s = Session::new();
        let with = auth_state(&s, &json!({ "locked": false, "anomaliesUnseen": 3 }));
        assert_eq!(with.anomalies_unseen, 3);
        assert!(serde_json::to_string(&with)
            .unwrap()
            .contains(r#""anomaliesUnseen":3"#));
        for absent in [
            json!({ "locked": false }),
            json!({ "anomaliesUnseen": "2" }),
            json!({ "anomaliesUnseen": 0 }),
        ] {
            let a = auth_state(&s, &absent);
            assert_eq!(a.anomalies_unseen, 0);
            assert!(!serde_json::to_string(&a).unwrap().contains("anomalies"));
        }
    }
}
