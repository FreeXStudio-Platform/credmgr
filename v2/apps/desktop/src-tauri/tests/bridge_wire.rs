//! What actually crosses the socket, driven end to end against a real Unix
//! domain socket (`tests/common`).
//!
//! The bridge's whole risk surface is the wire and the token, so these are
//! the two things asserted hardest: that the ADR-056 session token is
//! attached Rust-side and never handed back, and that the bridge stops
//! believing in it the moment the broker stops honouring it.

mod common;

use common::{err, ok, FakeBroker};
use desktop_lib::commands;
use desktop_lib::session::Session;
use serde_json::{json, Value};
use tauri::async_runtime::block_on;

const MINTED: &str = "cmt_0123456789abcdef";

/// A broker that answers a clean unlock (no gate enrolled) and then serves
/// ordinary reads.
fn unlocking_broker() -> FakeBroker {
    FakeBroker::spawn(|request| match request["op"].as_str().unwrap_or_default() {
        "vault.unlock" => ok(json!({ "locked": false, "token": MINTED })),
        "vault.status" => ok(json!({ "locked": false })),
        "vault.lock" => ok(json!({ "locked": true })),
        "entry.list" => ok(json!({
            "node": "acme", "ids": ["e1"], "names": ["deploy-key"], "generation": 7
        })),
        other => err(
            "not_found",
            json!({ "message": format!("unknown op {other}") }),
        ),
    })
}

#[test]
fn the_session_token_is_captured_attached_and_never_returned() {
    let broker = unlocking_broker();
    let session = Session::new();

    let state = block_on(commands::vault_unlock_at(
        &session,
        broker.socket.clone(),
        "correct horse battery staple".to_string(),
    ))
    .expect("unlock succeeds");

    // 1. The webview is told it is authenticated, and nothing more.
    assert!(state.authenticated);
    assert!(!state.locked);
    let rendered = serde_json::to_string(&state).unwrap();
    assert!(
        !rendered.contains(MINTED) && !rendered.contains("cmt_") && !rendered.contains("token"),
        "the unlock result handed to the webview must not carry the token: {rendered}"
    );

    // 2. The unlock itself was sent unauthenticated — there was no token yet.
    assert_eq!(broker.op_on(0).as_deref(), Some("vault.unlock"));
    assert_eq!(
        broker.token_on(0),
        None,
        "vault.unlock is the call that mints the token; it cannot present one"
    );

    // 3. The very next call carries it, attached by the bridge, without the
    //    webview ever having seen or passed it.
    block_on(commands::dispatch_at(
        &session,
        broker.socket.clone(),
        "entry.list",
        json!({ "node": "acme" }),
    ))
    .expect("entry.list succeeds");
    assert_eq!(broker.token_on(1).as_deref(), Some(MINTED));
}

#[test]
fn two_factor_required_reaches_the_ui_as_the_brokers_own_code_and_mints_nothing() {
    let broker = FakeBroker::spawn(|request| match request["op"].as_str().unwrap_or_default() {
        "vault.unlock" => err(
            "two_factor_required",
            json!({ "challenge": "totp", "scope": "vault", "expiresIn": 120 }),
        ),
        "vault.gate_verify" => ok(json!({ "locked": false, "token": MINTED })),
        _ => ok(json!({ "locked": false })),
    });
    let session = Session::new();

    let error = block_on(commands::vault_unlock_at(
        &session,
        broker.socket.clone(),
        "pw".to_string(),
    ))
    .expect_err("a gated vault does not unlock on the passphrase alone");

    assert_eq!(error.code, "two_factor_required");
    assert_eq!(error.detail.as_ref().unwrap()["challenge"], "totp");
    assert!(
        !session.is_authenticated(),
        "factor 1 alone must not leave the bridge holding a session"
    );

    let state = block_on(commands::vault_gate_verify_at(
        &session,
        broker.socket.clone(),
        "000000".to_string(),
    ))
    .expect("the second factor completes the login");
    assert!(state.authenticated);

    // Requests so far: 0 = vault.unlock (no token yet), 1 = vault.gate_verify
    // (still no token — it is the call that mints one). Only a *subsequent*
    // call can show the token being attached, so make one.
    assert_eq!(
        broker.token_on(1),
        None,
        "gate_verify mints the token; it cannot present it"
    );
    block_on(commands::vault_status_at(&session, broker.socket.clone())).unwrap();
    assert_eq!(broker.token_on(2).as_deref(), Some(MINTED));
}

#[test]
fn locking_drops_the_token_so_the_next_call_goes_out_unauthenticated() {
    let broker = unlocking_broker();
    let session = Session::new();
    block_on(commands::vault_unlock_at(
        &session,
        broker.socket.clone(),
        "pw".into(),
    ))
    .unwrap();
    assert!(session.is_authenticated());

    let state = block_on(commands::vault_lock_at(&session, broker.socket.clone())).unwrap();
    assert!(state.locked && !state.authenticated);

    block_on(commands::dispatch_at(
        &session,
        broker.socket.clone(),
        "vault.status",
        json!({}),
    ))
    .unwrap();
    assert_eq!(
        broker.token_on(2),
        None,
        "vault.lock revokes every session token broker-side (ADR-056); presenting the \
         revoked one afterwards is refused as session_expired (ADR-068)"
    );
}

#[test]
fn an_idle_autolock_is_noticed_from_an_ordinary_status_poll() {
    // ADR-043's idle timer locks the vault with no user action and no event
    // channel to us. The only way a UI learns of it is that a later response
    // says `locked: true` — so that has to be enough.
    let broker = FakeBroker::spawn(|request| match request["op"].as_str().unwrap_or_default() {
        "vault.unlock" => ok(json!({ "locked": false, "token": MINTED })),
        _ => ok(json!({ "locked": true })),
    });
    let session = Session::new();
    block_on(commands::vault_unlock_at(
        &session,
        broker.socket.clone(),
        "pw".into(),
    ))
    .unwrap();
    assert!(session.is_authenticated());

    let state = block_on(commands::vault_status_at(&session, broker.socket.clone())).unwrap();
    assert!(state.locked);
    assert!(
        !state.authenticated && !session.is_authenticated(),
        "a locked vault means the token we hold was already revoked"
    );
}

#[test]
fn graph_snapshots_nested_lock_flag_also_ends_the_session() {
    let broker = FakeBroker::spawn(|request| match request["op"].as_str().unwrap_or_default() {
        "vault.unlock" => ok(json!({ "locked": false, "token": MINTED })),
        _ => ok(json!({ "nodes": [], "links": [], "meta": { "vaultLocked": true } })),
    });
    let session = Session::new();
    block_on(commands::vault_unlock_at(
        &session,
        broker.socket.clone(),
        "pw".into(),
    ))
    .unwrap();

    block_on(commands::dispatch_at(
        &session,
        broker.socket.clone(),
        "graph.snapshot",
        json!({}),
    ))
    .unwrap();
    assert!(!session.is_authenticated());
}

#[test]
fn a_vault_locked_denial_ends_the_session_too() {
    let broker = FakeBroker::spawn(|request| match request["op"].as_str().unwrap_or_default() {
        "vault.unlock" => ok(json!({ "locked": false, "token": MINTED })),
        _ => err("vault_locked", json!({ "message": "the vault is locked" })),
    });
    let session = Session::new();
    block_on(commands::vault_unlock_at(
        &session,
        broker.socket.clone(),
        "pw".into(),
    ))
    .unwrap();

    let error = block_on(commands::dispatch_at(
        &session,
        broker.socket.clone(),
        "entry.reveal",
        json!({ "node": "acme", "entry": "e1" }),
    ))
    .expect_err("locked");
    assert_eq!(error.code, "vault_locked");
    assert!(!session.is_authenticated());
}

/// ADR-077 (G3): one locked node is not a dead login. The broker used to answer
/// `vault_locked` for it, and the bridge — rightly — dropped the session on that;
/// `node_locked` is its own code, carries the node, and leaves the session alone.
#[test]
fn a_node_locked_denial_keeps_the_session_and_carries_the_node() {
    let broker = FakeBroker::spawn(|request| match request["op"].as_str().unwrap_or_default() {
        "vault.unlock" => ok(json!({ "locked": false, "token": MINTED })),
        "entry.reveal" => err(
            "node_locked",
            json!({
                "node": "acme",
                "message": "node acme is locked; the vault itself is unlocked",
                "remedy": "unlock this node (vault.node_unlock) and retry — the login is still valid",
            }),
        ),
        _ => ok(json!({ "node": "acme", "ids": [], "names": [], "entries": [], "generation": 1 })),
    });
    let session = Session::new();
    block_on(commands::vault_unlock_at(
        &session,
        broker.socket.clone(),
        "pw".into(),
    ))
    .unwrap();

    let error = block_on(commands::dispatch_at(
        &session,
        broker.socket.clone(),
        "entry.reveal",
        json!({ "node": "acme", "entry": "e1" }),
    ))
    .expect_err("the node is locked");
    assert_eq!(error.code, "node_locked");
    assert_eq!(
        error
            .detail
            .as_ref()
            .expect("the broker's body rides along")["node"],
        "acme"
    );
    assert!(
        session.is_authenticated(),
        "locking one node must not end the login"
    );

    // And the very next call still goes out with the token attached.
    block_on(commands::dispatch_at(
        &session,
        broker.socket.clone(),
        "entry.list",
        json!({ "node": "acme" }),
    ))
    .expect("the session is still good");
    assert_eq!(broker.token_on(2).as_deref(), Some(MINTED));
}

/// ADR-077 (G2): `vault.status` says whether a vault exists. A broker with none
/// answers `initialized: false` and the webview is told so; a broker that predates
/// the field, and every non-status auth response, reads as initialised.
#[test]
fn vault_status_reports_whether_a_vault_exists_and_defaults_to_yes() {
    let none_yet = FakeBroker::spawn(|_| ok(json!({ "locked": true, "initialized": false })));
    let session = Session::new();
    let state = block_on(commands::vault_status_at(&session, none_yet.socket.clone())).unwrap();
    assert!(state.locked && !state.authenticated && !state.initialized);
    assert_eq!(
        serde_json::to_string(&state).unwrap(),
        r#"{"locked":true,"authenticated":false,"initialized":false}"#
    );

    let there = FakeBroker::spawn(|_| ok(json!({ "locked": true, "initialized": true })));
    let state = block_on(commands::vault_status_at(
        &Session::new(),
        there.socket.clone(),
    ))
    .unwrap();
    assert!(state.initialized);

    // An older broker sends no `initialized`: the fail-safe reading is "a vault
    // exists" - never offer to create one over it.
    let older = FakeBroker::spawn(|_| ok(json!({ "locked": true })));
    let state = block_on(commands::vault_status_at(
        &Session::new(),
        older.socket.clone(),
    ))
    .unwrap();
    assert!(state.initialized);
}

#[test]
fn an_idled_out_login_is_refused_and_the_session_dropped() {
    // ADR-065 revokes a login unused for the idle timeout even while agents
    // keep the vault unlocked, so no `locked: true` ever reaches us. ADR-068
    // makes the broker say so instead of resolving the dead token from cwd.
    let broker = FakeBroker::spawn(|request| match request["op"].as_str().unwrap_or_default() {
        "vault.unlock" => ok(json!({ "locked": false, "token": MINTED })),
        _ => err(
            "session_expired",
            json!({ "message": "this login is no longer valid" }),
        ),
    });
    let session = Session::new();
    block_on(commands::vault_unlock_at(
        &session,
        broker.socket.clone(),
        "pw".into(),
    ))
    .unwrap();

    let error = block_on(commands::dispatch_at(
        &session,
        broker.socket.clone(),
        "entry.list",
        json!({ "node": "acme" }),
    ))
    .expect_err("expired");
    assert_eq!(error.code, "session_expired");
    assert!(!session.is_authenticated());
}

#[test]
fn conflict_reaches_the_caller_with_both_generations_intact() {
    // F-9's optimistic concurrency. A UI that cannot see both numbers cannot
    // tell the user what happened or reload to the right version.
    let broker = FakeBroker::spawn(|_| {
        err(
            "conflict",
            json!({ "node": "acme", "expectedGeneration": 7, "currentGeneration": 9 }),
        )
    });
    let session = Session::new();
    let error = block_on(commands::dispatch_at(
        &session,
        broker.socket.clone(),
        "entry.list",
        json!({ "node": "acme" }),
    ))
    .expect_err("conflict");

    assert_eq!(error.code, "conflict");
    let detail = error.detail.expect("conflict carries its generations");
    assert_eq!(detail["expectedGeneration"], 7);
    assert_eq!(detail["currentGeneration"], 9);
    assert!(
        !error.message.is_empty(),
        "conflict has no wire message; the bridge must supply a human one"
    );
}

#[test]
fn a_denial_keeps_the_brokers_vocabulary_rather_than_a_friendlier_one() {
    let broker = FakeBroker::spawn(|_| {
        err(
            "node_access_denied",
            json!({
                "subject": "acme", "target": "other", "capability": "reveal",
                "rule": "R8", "message": "no grant path", "remedy": "request a grant"
            }),
        )
    });
    let session = Session::new();
    let error = block_on(commands::dispatch_at(
        &session,
        broker.socket.clone(),
        "entry.reveal",
        json!({ "node": "other", "entry": "e1" }),
    ))
    .expect_err("denied");

    assert_eq!(error.code, "node_access_denied");
    let detail = error.detail.unwrap();
    assert_eq!(detail["rule"], "R8");
    assert_eq!(detail["remedy"], "request a grant");
}

#[test]
fn reads_pass_through_unreshaped() {
    let broker = unlocking_broker();
    let session = Session::new();
    let value = block_on(commands::dispatch_at(
        &session,
        broker.socket.clone(),
        "entry.list",
        json!({ "node": "acme" }),
    ))
    .unwrap();

    assert_eq!(value["names"][0], "deploy-key");
    assert_eq!(
        value["generation"], 7,
        "the manifest generation must survive: without it no caller can ever \
         perform a first update"
    );
    assert_eq!(broker.received()[0]["params"]["node"], "acme");
}

#[test]
fn a_missing_broker_is_a_transport_error_naming_the_socket() {
    let session = Session::new();
    let error = block_on(commands::vault_status_at(
        &session,
        std::path::PathBuf::from("/tmp/credmgr-nonexistent-socket-for-tests/b.sock"),
    ))
    .expect_err("nothing is listening there");

    assert_eq!(error.code, "broker_unreachable");
    assert!(error.message.contains("is it running?"));
}

#[test]
fn a_response_for_a_different_request_is_refused_rather_than_believed() {
    let broker = FakeBroker::spawn(|_| {
        // Deliberately sets its own id, so the harness does not echo the
        // request's — this is the desynchronised-stream case.
        json!({ "id": "not-the-one-you-sent", "ok": true, "value": { "locked": false } })
    });
    let session = Session::new();
    let error = block_on(commands::vault_status_at(&session, broker.socket.clone()))
        .expect_err("a mismatched id must not be accepted");
    assert_eq!(error.code, "malformed_response");
}

/// The bridge must never hand the webview a token under any op, not only the
/// two that mint one. A future op that starts returning a credential would
/// otherwise pass silently.
#[test]
fn no_command_result_ever_serialises_a_token_shaped_string() {
    let broker = FakeBroker::spawn(|_| ok(json!({ "locked": false, "token": MINTED })));
    let session = Session::new();

    let unlock = block_on(commands::vault_unlock_at(
        &session,
        broker.socket.clone(),
        "pw".into(),
    ))
    .unwrap();
    let gate = block_on(commands::vault_gate_verify_at(
        &session,
        broker.socket.clone(),
        "000000".into(),
    ))
    .unwrap();
    let status = block_on(commands::vault_status_at(&session, broker.socket.clone())).unwrap();

    for rendered in [
        serde_json::to_string(&unlock).unwrap(),
        serde_json::to_string(&gate).unwrap(),
        serde_json::to_string(&status).unwrap(),
    ] {
        assert!(
            !rendered.contains("cmt_"),
            "a token reached the webview: {rendered}"
        );
    }
}

/// The raw pass-through commands hand the broker's body straight to the
/// webview — so if a *read* op ever carried a token, it would ship. Prove the
/// only path that can capture one is the auth path, and that a stray token on
/// a read is not silently adopted as a session either.
#[test]
fn a_stray_token_on_a_read_response_is_not_adopted_as_a_session() {
    let broker = FakeBroker::spawn(|_| ok(json!({ "ids": [], "token": "cmt_stray" })));
    let session = Session::new();
    let value: Value = block_on(commands::dispatch_at(
        &session,
        broker.socket.clone(),
        "entry.list",
        json!({ "node": "acme" }),
    ))
    .unwrap();

    assert!(
        !session.is_authenticated(),
        "only vault.unlock/vault.gate_verify may establish a session"
    );
    // It does pass through to the webview, because reads are unreshaped —
    // recorded here as the known, accepted consequence of that choice rather
    // than left as an unexamined surprise. No real op returns one:
    // `mint_session_token` has exactly two call sites, both in the auth path.
    assert_eq!(value["token"], "cmt_stray");
}
