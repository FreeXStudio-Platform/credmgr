//! ADR-150 — "confirm before showing secrets", end to end against a durable vault and a real login.
//!
//! Each row tries to get a value (or weaken the rule) without the confirmation the policy asks for:
//! * off by default, and an older registry with no `revealConfirm` behaves exactly as before;
//! * on: `entry.reveal` and `totp.code` refuse the owner's login with `confirmation_required` until
//!   `session.confirm` (passphrase or Touch ID proof) opens the trust window, which then expires;
//! * "every time": one confirmation, one value;
//! * "only high and critical": a low value shows, a critical one asks; lowering an entry out of the band asks;
//! * turning it off or weakening it needs a fresh confirmation; turning it on or strengthening needs none;
//! * a lock ends every confirmation; an agent is never asked; a wrong passphrase feeds the unlock backoff.

mod f1_support;

use std::sync::Arc;
use std::time::Instant;

use serde_json::{json, Value};

use credmgr_brokerd::protocol::{OpError, Request};
use credmgr_brokerd::scope::BrokerScope;
use credmgr_brokerd::server;
use credmgr_brokerd::state::BrokerState;
use credmgr_core::access::Origin;
use credmgr_core::registry::{Capability, GLOBAL_ID};

use f1_support::*;

const REASON: &str = "test: confirm before showing secrets";

fn set_policy(
    state: &BrokerState,
    owner: &BrokerScope,
    now: i64,
    policy: Value,
) -> Result<Value, OpError> {
    call(
        state,
        owner,
        now,
        "node.policy",
        json!({ "node": GLOBAL_ID, "reason": REASON, "policy": { "revealConfirm": policy } }),
    )
}

fn confirm(state: &BrokerState, owner: &BrokerScope, now: i64) -> Value {
    call(
        state,
        owner,
        now,
        "session.confirm",
        json!({ "passphrase": PASSPHRASE }),
    )
    .expect("session.confirm")
}

fn reveal_at(
    state: &BrokerState,
    scope: &BrokerScope,
    now: i64,
    node: &str,
    entry: &str,
) -> Result<Value, OpError> {
    call(
        state,
        scope,
        now,
        "entry.reveal",
        json!({ "node": node, "entry": entry }),
    )
}

fn entry_with(
    state: &BrokerState,
    owner: &BrokerScope,
    node: &str,
    name: &str,
    value: &str,
    sensitivity: &str,
) -> String {
    call(
        state,
        owner,
        NOW,
        "entry.create",
        json!({ "node": node, "name": name, "value": value, "sensitivity": sensitivity }),
    )
    .expect("entry.create")["entry"]
        .as_str()
        .unwrap()
        .to_string()
}

fn is_confirmation_required(r: &Result<Value, OpError>, op: &str) -> bool {
    matches!(r, Err(OpError::ConfirmationRequired { operation, .. }) if operation == op)
}

/// A vault with a node `acme`, a critical and a low entry, and the owner's login.
fn setup() -> (Vault, Arc<BrokerState>, BrokerScope, String, String) {
    let (v, state) = created_vault(None);
    let owner = login(&state);
    create_node(&state, &owner, "acme");
    let critical = entry_with(&state, &owner, "acme", "db", "s3cr3t-critical", "critical");
    let low = entry_with(&state, &owner, "acme", "host", "db.internal", "low");
    (v, state, owner, critical, low)
}

#[test]
fn off_by_default_and_reveals_as_before() {
    let (_v, state, owner, critical, low) = setup();
    assert!(state.reveal_confirm_policy().is_default());
    assert_eq!(reveal(&state, &owner, "acme", &critical), "s3cr3t-critical");
    assert_eq!(reveal(&state, &owner, "acme", &low), "db.internal");
    // The registry carries no revealConfirm while it is off: older registries and newer ones read alike.
    let snap = call(&state, &owner, NOW, "graph.snapshot", json!({})).unwrap();
    assert_eq!(
        snap["revealConfirm"],
        json!({ "mode": "off", "windowSeconds": 300, "scope": "all" })
    );
}

#[test]
fn on_refuses_until_confirmed_then_the_window_expires() {
    let (_v, state, owner, critical, _low) = setup();
    set_policy(
        &state,
        &owner,
        NOW,
        json!({ "mode": "window", "windowSeconds": 300 }),
    )
    .expect("turning it on needs nothing");

    let r = reveal_at(&state, &owner, NOW, "acme", &critical);
    match &r {
        Err(OpError::ConfirmationRequired {
            operation,
            mode,
            window_seconds,
        }) => {
            assert_eq!(operation, "entry.reveal");
            assert_eq!(*mode, "window");
            assert_eq!(*window_seconds, 300);
        }
        other => panic!("expected confirmation_required, got {other:?}"),
    }

    let c = confirm(&state, &owner, NOW + 10);
    assert_eq!(c["method"], "passphrase");
    assert_eq!(c["expiresIn"], 300);
    // Inside the window: as many reveals as wanted, no further prompt.
    for t in [NOW + 10, NOW + 100, NOW + 309] {
        let v = reveal_at(&state, &owner, t, "acme", &critical).expect("inside the window");
        assert_eq!(v["value"], "s3cr3t-critical");
    }
    // The window is over: asked again.
    assert!(is_confirmation_required(
        &reveal_at(&state, &owner, NOW + 310, "acme", &critical),
        "entry.reveal"
    ));
}

#[test]
fn a_totp_code_is_a_secret_too() {
    let (_v, state, owner, _c, _l) = setup();
    let id = call(
        &state,
        &owner,
        NOW,
        "entry.create",
        json!({ "node": "acme", "name": "otp", "fields": [
            { "label": "seed", "value": "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP", "type": "totp-seed" }
        ] }),
    )
    .expect("entry.create")["entry"]
        .as_str()
        .unwrap()
        .to_string();
    set_policy(&state, &owner, NOW, json!({ "mode": "window" })).unwrap();
    let r = call(
        &state,
        &owner,
        NOW,
        "totp.code",
        json!({ "node": "acme", "entry": id }),
    );
    assert!(is_confirmation_required(&r, "totp.code"), "{r:?}");
    confirm(&state, &owner, NOW);
    call(
        &state,
        &owner,
        NOW,
        "totp.code",
        json!({ "node": "acme", "entry": id }),
    )
    .expect("confirmed");
}

#[test]
fn every_time_means_one_confirmation_per_value() {
    let (_v, state, owner, critical, low) = setup();
    set_policy(&state, &owner, NOW, json!({ "mode": "everyTime" })).unwrap();
    let r = reveal_at(&state, &owner, NOW, "acme", &critical);
    assert!(
        matches!(
            r,
            Err(OpError::ConfirmationRequired {
                mode: "everyTime",
                window_seconds: 0,
                ..
            })
        ),
        "{r:?}"
    );
    let c = confirm(&state, &owner, NOW);
    assert_eq!(c["expiresIn"], 60);
    reveal_at(&state, &owner, NOW, "acme", &critical).expect("one value");
    assert!(is_confirmation_required(
        &reveal_at(&state, &owner, NOW + 1, "acme", &low),
        "entry.reveal"
    ));
    // An unused confirmation does not last: 60 seconds.
    confirm(&state, &owner, NOW + 100);
    assert!(is_confirmation_required(
        &reveal_at(&state, &owner, NOW + 160, "acme", &critical),
        "entry.reveal"
    ));
}

#[test]
fn high_only_lets_low_values_through_and_guards_the_band_edge() {
    let (_v, state, owner, critical, low) = setup();
    set_policy(
        &state,
        &owner,
        NOW,
        json!({ "mode": "window", "scope": "high" }),
    )
    .unwrap();
    assert_eq!(reveal(&state, &owner, "acme", &low), "db.internal");
    assert!(is_confirmation_required(
        &reveal_at(&state, &owner, NOW, "acme", &critical),
        "entry.reveal"
    ));
    // Lowering the critical entry to low would take it out of the policy's reach: that edit asks too.
    let lower = json!({ "node": "acme", "entry": critical, "sensitivity": "low",
                        "generation": generation(&state, &owner, "acme") });
    let r = call(&state, &owner, NOW, "entry.update", lower.clone());
    assert!(is_confirmation_required(&r, "entry.update"), "{r:?}");
    confirm(&state, &owner, NOW);
    call(&state, &owner, NOW, "entry.update", lower).expect("confirmed: the owner may lower it");
}

#[test]
fn weakening_needs_a_fresh_confirmation_strengthening_does_not() {
    let (_v, state, owner, _c, _l) = setup();
    set_policy(&state, &owner, NOW, json!({ "mode": "window" })).unwrap();
    set_policy(&state, &owner, NOW, json!({ "mode": "everyTime" }))
        .expect("strengthening needs nothing");
    for weaker in [
        json!({ "mode": "window" }),
        json!({ "mode": "everyTime", "scope": "high" }),
        json!({ "mode": "off" }),
    ] {
        let r = set_policy(&state, &owner, NOW, weaker.clone());
        assert!(
            is_confirmation_required(&r, "node.policy"),
            "{weaker}: {r:?}"
        );
    }
    assert_eq!(
        state.reveal_confirm_policy().mode,
        credmgr_core::reveal_confirm::ConfirmMode::EveryTime,
        "a refused change changes nothing"
    );
    // A confirmation older than a minute is not fresh, even inside a long window.
    set_policy(
        &state,
        &owner,
        NOW,
        json!({ "mode": "window", "windowSeconds": 3600 }),
    )
    .expect_err("still weaker");
    confirm(&state, &owner, NOW);
    set_policy(
        &state,
        &owner,
        NOW + 30,
        json!({ "mode": "window", "windowSeconds": 3600 }),
    )
    .expect("fresh confirmation");
    // The confirmation was used up by that change; turning it off needs another.
    assert!(is_confirmation_required(
        &set_policy(&state, &owner, NOW + 31, json!({ "mode": "off" })),
        "node.policy"
    ));
    confirm(&state, &owner, NOW + 200);
    assert!(is_confirmation_required(
        &set_policy(&state, &owner, NOW + 261, json!({ "mode": "off" })),
        "node.policy"
    ));
    confirm(&state, &owner, NOW + 300);
    set_policy(&state, &owner, NOW + 301, json!({ "mode": "off" })).expect("turned off");
    assert!(state.reveal_confirm_policy().is_default());
}

#[test]
fn the_policy_is_vault_policy_and_well_formed() {
    let (_v, state, owner, _c, _l) = setup();
    let r = call(
        &state,
        &owner,
        NOW,
        "node.policy",
        json!({ "node": "acme", "reason": REASON, "policy": { "revealConfirm": { "mode": "window" } } }),
    );
    assert!(matches!(r, Err(OpError::Malformed(_))), "{r:?}");
    let r = set_policy(
        &state,
        &owner,
        NOW,
        json!({ "mode": "window", "windowSeconds": 42 }),
    );
    assert!(matches!(r, Err(OpError::Malformed(_))), "{r:?}");
    let r = set_policy(&state, &owner, NOW, json!({ "mode": "sometimes" }));
    assert!(matches!(r, Err(OpError::Malformed(_))), "{r:?}");
}

#[test]
fn the_policy_survives_a_restart() {
    let (v, state, owner, critical, _l) = setup();
    set_policy(
        &state,
        &owner,
        NOW,
        json!({ "mode": "window", "windowSeconds": 900, "scope": "high" }),
    )
    .unwrap();
    let (state, owner) = restart(&v, state, None);
    let p = state.reveal_confirm_policy();
    assert_eq!(p.window_seconds, 900);
    assert!(is_confirmation_required(
        &reveal_at(&state, &owner, NOW, "acme", &critical),
        "entry.reveal"
    ));
}

#[test]
fn a_lock_ends_every_confirmation() {
    let (_v, state, owner, critical, _l) = setup();
    set_policy(
        &state,
        &owner,
        NOW,
        json!({ "mode": "window", "windowSeconds": 3600 }),
    )
    .unwrap();
    confirm(&state, &owner, NOW);
    reveal_at(&state, &owner, NOW, "acme", &critical).expect("confirmed");
    call(&state, &owner, NOW, "vault.lock", json!({})).unwrap();
    let owner = login(&state);
    assert!(is_confirmation_required(
        &reveal_at(&state, &owner, NOW + 1, "acme", &critical),
        "entry.reveal"
    ));
}

#[test]
fn a_confirmation_belongs_to_one_login() {
    let (_v, state, owner, critical, _l) = setup();
    set_policy(&state, &owner, NOW, json!({ "mode": "window" })).unwrap();
    confirm(&state, &owner, NOW);
    let other = login(&state);
    assert!(is_confirmation_required(
        &reveal_at(&state, &other, NOW, "acme", &critical),
        "entry.reveal"
    ));
}

#[test]
fn agents_are_not_asked_and_cannot_confirm() {
    let (_v, state, owner, _critical, low) = setup();
    set_policy(&state, &owner, NOW, json!({ "mode": "everyTime" })).unwrap();
    let token = state
        .tokens
        .issue(
            "acme",
            vec![Capability::List, Capability::Read, Capability::Reveal],
            Origin::Agent,
            None,
        )
        .id;
    let agent = scope_of(&state, &token);
    // A low value on a Guarded node: an agent reads it as ADR-140 always allowed, with no confirmation.
    let v = reveal_at(&state, &agent, NOW, "acme", &low).expect("agent reveal");
    assert_eq!(v["value"], "db.internal");
    let r = call(
        &state,
        &agent,
        NOW,
        "session.confirm",
        json!({ "passphrase": PASSPHRASE }),
    );
    assert!(matches!(r, Err(OpError::CapabilityNotHeld { .. })), "{r:?}");
    // Nor can an agent change the policy.
    let r = set_policy(&state, &agent, NOW, json!({ "mode": "off" }));
    assert!(r.is_err());
}

#[test]
fn touch_id_confirms_with_a_presence_proof() {
    let (_v, state, owner, critical, _l) = setup();
    set_policy(&state, &owner, NOW, json!({ "mode": "window" })).unwrap();
    // No passphrase and no proof: the long-standing presence answer, which the shell turns into a prompt.
    let r = call(&state, &owner, NOW, "session.confirm", json!({}));
    assert!(matches!(r, Err(OpError::PresenceRequired { .. })), "{r:?}");
    let key = enrol_first_key(&state, &owner);
    let proved = with_proof(&state, &owner, &key, NOW, "session.confirm", json!({}));
    let c = call(&state, &owner, NOW, "session.confirm", proved).expect("proof confirms");
    assert_eq!(c["method"], "presence");
    reveal_at(&state, &owner, NOW, "acme", &critical).expect("confirmed by Touch ID");
}

#[test]
fn a_wrong_passphrase_is_refused_and_feeds_the_unlock_backoff() {
    let (_v, state, owner, _c, _l) = setup();
    let r = call(
        &state,
        &owner,
        NOW,
        "session.confirm",
        json!({ "passphrase": "not it" }),
    );
    assert!(matches!(r, Err(OpError::WrongPassphrase)), "{r:?}");

    let clock = Instant::now();
    let send = |pass: &str| {
        server::handle_request_at(
            &state,
            &peer(),
            &Request {
                id: "c".into(),
                op: "session.confirm".into(),
                token: owner.token_id.clone(),
                params: json!({ "passphrase": pass }),
            },
            NOW,
            clock,
        )
        .0
    };
    for _ in 0..5 {
        assert!(matches!(send("wrong"), Err(OpError::WrongPassphrase)));
    }
    // Backed off: even the right passphrase waits, and so does vault.unlock (one counter per uid).
    assert!(matches!(send(PASSPHRASE), Err(OpError::RateLimited { .. })));
    let (unlock, _) = server::handle_request_at(
        &state,
        &peer(),
        &Request {
            id: "u".into(),
            op: "vault.unlock".into(),
            token: None,
            params: json!({ "passphrase": PASSPHRASE }),
        },
        NOW,
        clock,
    );
    assert!(
        matches!(unlock, Err(OpError::RateLimited { .. })),
        "{unlock:?}"
    );
}

// --- Review fixes (ADR-150 amendment, 2026-11-08) -----------------------------------------------------------

/// Send `op` through the server (so the per-uid backoff applies) as the owner's login.
fn send_as(
    state: &Arc<BrokerState>,
    owner: &BrokerScope,
    clock: Instant,
    op: &str,
    params: Value,
) -> Result<Value, OpError> {
    server::handle_request_at(
        state,
        &peer(),
        &Request {
            id: "r".into(),
            op: op.into(),
            token: owner.token_id.clone(),
            params,
        },
        NOW,
        clock,
    )
    .0
}

fn pending_request(r: Result<Value, OpError>) -> String {
    match r {
        Err(OpError::ApprovalPending { request, .. }) => request,
        other => panic!("expected approval_pending, got {other:?}"),
    }
}

fn decide(
    state: &BrokerState,
    owner: &BrokerScope,
    now: i64,
    request: &str,
) -> Result<Value, OpError> {
    call(
        state,
        owner,
        now,
        "vault.approval_decide",
        json!({ "request": request, "approved": true }),
    )
}

/// Review P0: `vault.node_lock` → `entry.reveal` (approval pending) → `vault.approval_decide` → `entry.reveal`
/// used to hand the owner's login the value with no confirmation at all.
#[test]
fn locking_a_node_and_approving_is_not_a_way_round_it() {
    let (_v, state, owner, critical, _l) = setup();
    set_policy(
        &state,
        &owner,
        NOW,
        json!({ "mode": "window", "windowSeconds": 60 }),
    )
    .unwrap();
    call(
        &state,
        &owner,
        NOW,
        "vault.node_lock",
        json!({ "node": "acme" }),
    )
    .unwrap();
    let request = pending_request(reveal_at(&state, &owner, NOW, "acme", &critical));

    // Approving releases a value: the person approving is asked.
    let r = decide(&state, &owner, NOW, &request);
    assert!(
        is_confirmation_required(&r, "vault.approval_decide"),
        "{r:?}"
    );
    confirm(&state, &owner, NOW);
    decide(&state, &owner, NOW, &request).expect("confirmed: approved");

    // The window is over by the retry (the approval is not): the staged value is held back too.
    let r = reveal_at(&state, &owner, NOW + 61, "acme", &critical);
    assert!(is_confirmation_required(&r, "entry.reveal"), "{r:?}");
    confirm(&state, &owner, NOW + 62);
    let v = reveal_at(&state, &owner, NOW + 62, "acme", &critical).expect("confirmed: released");
    assert_eq!(v["value"], "s3cr3t-critical");
}

#[test]
fn every_time_asks_for_the_approval_and_again_for_the_value() {
    let (_v, state, owner, critical, _l) = setup();
    set_policy(&state, &owner, NOW, json!({ "mode": "everyTime" })).unwrap();
    call(
        &state,
        &owner,
        NOW,
        "vault.node_lock",
        json!({ "node": "acme" }),
    )
    .unwrap();
    let request = pending_request(reveal_at(&state, &owner, NOW, "acme", &critical));
    confirm(&state, &owner, NOW);
    decide(&state, &owner, NOW, &request).expect("one confirmation, one approval");
    let r = reveal_at(&state, &owner, NOW + 1, "acme", &critical);
    assert!(is_confirmation_required(&r, "entry.reveal"), "{r:?}");
    confirm(&state, &owner, NOW + 2);
    let v = reveal_at(&state, &owner, NOW + 2, "acme", &critical).expect("released");
    assert_eq!(v["value"], "s3cr3t-critical");
}

#[test]
fn denying_an_approval_is_never_gated() {
    let (_v, state, owner, critical, _l) = setup();
    set_policy(&state, &owner, NOW, json!({ "mode": "everyTime" })).unwrap();
    call(
        &state,
        &owner,
        NOW,
        "vault.node_lock",
        json!({ "node": "acme" }),
    )
    .unwrap();
    let request = pending_request(reveal_at(&state, &owner, NOW, "acme", &critical));
    call(
        &state,
        &owner,
        NOW,
        "vault.approval_decide",
        json!({ "request": request, "approved": false }),
    )
    .expect("deny needs nothing");
}

/// Review P1: a successful `session.confirm` must not clear the per-uid backoff, or a login could guess gate codes
/// (or the passphrase) without limit by confirming between guesses.
#[test]
fn a_successful_confirm_does_not_reset_the_backoff() {
    let (_v, state, owner, _c, _l) = setup();
    let clock = Instant::now();
    let pass = |p: &str| json!({ "passphrase": p });
    for _ in 0..4 {
        let r = send_as(&state, &owner, clock, "session.confirm", pass("wrong"));
        assert!(matches!(r, Err(OpError::WrongPassphrase)), "{r:?}");
    }
    send_as(&state, &owner, clock, "session.confirm", pass(PASSPHRASE)).expect("right one");
    let r = send_as(&state, &owner, clock, "session.confirm", pass("wrong"));
    assert!(matches!(r, Err(OpError::WrongPassphrase)), "{r:?}");
    // Five failures in all: backed off, the right passphrase included.
    let r = send_as(&state, &owner, clock, "session.confirm", pass(PASSPHRASE));
    assert!(matches!(r, Err(OpError::RateLimited { .. })), "{r:?}");
}

/// Review P3-b: a Touch ID confirmation that fails its check counts like a wrong passphrase.
#[test]
fn a_touch_id_confirmation_that_does_not_verify_feeds_the_backoff() {
    let (_v, state, owner, _c, _l) = setup();
    enrol_first_key(&state, &owner);
    let stranger = Signer::software();
    let clock = Instant::now();
    for _ in 0..5 {
        let forged = with_proof(&state, &owner, &stranger, NOW, "session.confirm", json!({}));
        let r = send_as(&state, &owner, clock, "session.confirm", forged);
        assert!(
            matches!(
                &r,
                Err(OpError::PresenceFailed {
                    reason: "invalid",
                    ..
                })
            ),
            "{r:?}"
        );
    }
    let r = send_as(
        &state,
        &owner,
        clock,
        "session.confirm",
        json!({ "passphrase": PASSPHRASE }),
    );
    assert!(matches!(r, Err(OpError::RateLimited { .. })), "{r:?}");
}

/// Review P3-a: an entry the manifest does not list is treated as critical, never let through.
#[test]
fn an_entry_missing_from_the_manifest_is_gated_as_critical() {
    let (_v, state, owner, _c, low) = setup();
    set_policy(
        &state,
        &owner,
        NOW,
        json!({ "mode": "window", "scope": "high" }),
    )
    .unwrap();
    // Drop the low entry's manifest row; its envelope stays on disk.
    state
        .manifests
        .write()
        .unwrap()
        .get_mut("acme")
        .unwrap()
        .entries
        .retain(|e| e.id != low);
    let r = reveal_at(&state, &owner, NOW, "acme", &low);
    assert!(is_confirmation_required(&r, "entry.reveal"), "{r:?}");
}

/// Review P3-c: a weakening change refused for another reason (here: presence for widening a level) keeps the
/// confirmation for the next attempt.
#[test]
fn a_weakening_refused_for_presence_keeps_the_confirmation() {
    let (_v, state, owner, _c, _l) = setup();
    set_policy(&state, &owner, NOW, json!({ "mode": "everyTime" })).unwrap();
    confirm(&state, &owner, NOW);
    let r = call(
        &state,
        &owner,
        NOW,
        "node.policy",
        json!({ "node": GLOBAL_ID, "reason": REASON,
                "policy": { "revealConfirm": { "mode": "off" }, "securityLevel": "open" } }),
    );
    assert!(matches!(r, Err(OpError::PresenceRequired { .. })), "{r:?}");
    set_policy(&state, &owner, NOW + 1, json!({ "mode": "off" })).expect("confirmation unspent");
}

/// Review P3-d: in "every time" mode an unknown field id is refused without spending the confirmation.
#[test]
fn a_bad_field_id_does_not_spend_an_every_time_confirmation() {
    let (_v, state, owner, critical, _l) = setup();
    set_policy(&state, &owner, NOW, json!({ "mode": "everyTime" })).unwrap();
    confirm(&state, &owner, NOW);
    let r = call(
        &state,
        &owner,
        NOW,
        "entry.reveal",
        json!({ "node": "acme", "entry": critical, "fieldIds": ["no-such-field"] }),
    );
    assert!(
        r.is_err() && !is_confirmation_required(&r, "entry.reveal"),
        "{r:?}"
    );
    reveal_at(&state, &owner, NOW + 1, "acme", &critical).expect("confirmation unspent");
}

/// Review P3-g: the stored policy ignores unknown keys, but a request naming one is refused.
#[test]
fn a_request_with_an_unknown_policy_key_is_refused() {
    let (_v, state, owner, _c, _l) = setup();
    let r = set_policy(
        &state,
        &owner,
        NOW,
        json!({ "mode": "window", "windowSecond": 60 }),
    );
    assert!(
        matches!(&r, Err(OpError::Malformed(m)) if m.contains("windowSecond")),
        "{r:?}"
    );
}

#[test]
fn the_wire_shape_names_the_code_and_the_remedy() {
    let w = credmgr_brokerd::protocol::to_wire(
        "1",
        &Err(OpError::ConfirmationRequired {
            operation: "entry.reveal".into(),
            mode: "window",
            window_seconds: 300,
        }),
    );
    assert_eq!(w["error"], "confirmation_required");
    assert_eq!(w["operation"], "entry.reveal");
    assert_eq!(w["mode"], "window");
    assert_eq!(w["windowSeconds"], 300);
    assert!(w["remedy"].as_str().unwrap().contains("session.confirm"));
}

#[test]
fn a_content_search_and_a_note_read_ask_like_a_value_does() {
    // ADR-156 supersedes the K-24 exemption: `search.content` answers as for a critical value,
    // `notes.read` as for a high one; an agent is asked neither.
    let (_v, state, owner, _critical, _low) = setup();
    call(
        &state,
        &owner,
        NOW,
        "notes.write",
        json!({ "node": "acme", "markdown": "root pw: hunter2",
        "generation": generation(&state, &owner, "acme") }),
    )
    .expect("notes.write");
    let search = json!({ "term": "s3cr3t" });
    let note = json!({ "node": "acme" });
    // Off: as before.
    call(&state, &owner, NOW, "search.content", search.clone()).expect("off: search");
    call(&state, &owner, NOW, "notes.read", note.clone()).expect("off: note");

    set_policy(
        &state,
        &owner,
        NOW,
        json!({ "mode": "window", "scope": "high" }),
    )
    .unwrap();
    let r = call(&state, &owner, NOW, "search.content", search.clone());
    assert!(is_confirmation_required(&r, "search.content"), "{r:?}");
    let r = call(&state, &owner, NOW, "notes.read", note.clone());
    assert!(is_confirmation_required(&r, "notes.read"), "{r:?}");

    confirm(&state, &owner, NOW + 1);
    let found = call(&state, &owner, NOW + 2, "search.content", search.clone()).unwrap();
    assert_eq!(
        found["results"].as_array().unwrap().len(),
        1,
        "one search hit"
    );
    let read = call(&state, &owner, NOW + 2, "notes.read", note.clone()).unwrap();
    assert_eq!(read["markdown"], "root pw: hunter2");

    // Every time: each search and each note read spends its own confirmation.
    set_policy(&state, &owner, NOW + 3, json!({ "mode": "everyTime" })).unwrap();
    confirm(&state, &owner, NOW + 4);
    call(&state, &owner, NOW + 4, "notes.read", note.clone()).expect("spends it");
    let r = call(&state, &owner, NOW + 4, "search.content", search.clone());
    assert!(is_confirmation_required(&r, "search.content"), "{r:?}");

    // An agent is not asked for a note.
    let token = state
        .tokens
        .issue("acme", vec![Capability::Notes], Origin::Agent, None)
        .id;
    let agent = scope_of(&state, &token);
    call(&state, &agent, NOW + 5, "notes.read", note).expect("agent note read");
}
