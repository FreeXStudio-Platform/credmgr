//! 4.3 / ADR-085 — `requireTwoFactor`, enforced per node. Real server wiring on a
//! throwaway vault with a real enrolled gate; time is moved explicitly so TOTP
//! steps and the elevation window are exercised, not skipped.

mod common;

use common::*;
use credmgr_brokerd::protocol::OpError;
use credmgr_core::totp::{decode_gate_secret_base32, Totp};
use serde_json::{json, Value};

fn two_factor_required<T: std::fmt::Debug>(r: &Result<T, OpError>) -> bool {
    matches!(r, Err(OpError::TwoFactorRequired { .. }))
}

fn totp_from_uri(uri: &str) -> Totp {
    let b32 = uri
        .split("secret=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap();
    Totp::new_gate(decode_gate_secret_base32(b32).unwrap())
}

fn set_policy(f: &Fixture, owner: &str, level: &str) {
    send(
        f,
        None,
        Some(owner),
        "node.policy",
        json!({ "node": "acme", "reason": "test", "policy": { "requireTwoFactor": level } }),
    )
    .expect("policy");
}

/// acme with one entry, a note, and an enrolled vault gate. Returns the owner
/// token, the entry id and the authenticator.
fn gated() -> (Fixture, String, String, Totp) {
    let (f, owner, entry) = with_acme();
    let begin = send(&f, None, Some(&owner), "vault.gate_enroll_begin", json!({})).expect("begin");
    let totp = totp_from_uri(begin["otpauthUri"].as_str().unwrap());
    send(
        &f,
        None,
        Some(&owner),
        "vault.gate_enroll_confirm",
        json!({ "code": totp.code(NOW as u64) }),
    )
    .expect("confirm");
    (f, owner, entry, totp)
}

/// Long after the enrolment elevation (5 minutes) has lapsed.
const LATER: i64 = NOW + 3600;

fn reveal(f: &Fixture, now: i64, entry: &str) -> Result<Value, OpError> {
    send_at(
        f,
        now,
        Some(&agent_cwd(f)),
        None,
        "entry.reveal",
        json!({ "node": "acme", "entry": entry }),
    )
}

#[test]
fn reveal_level_refuses_an_agents_reveal_without_a_fresh_second_factor() {
    let (f, owner, entry, totp) = gated();
    // The default level is `reveal`.
    let r = reveal(&f, LATER, &entry);
    assert!(two_factor_required(&r), "{r:?}");
    let wire = credmgr_brokerd::protocol::to_wire("r", &r);
    assert_eq!(wire["error"], "two_factor_required");
    assert_eq!(wire["challenge"], "totp");
    // A read of metadata is free at `reveal`.
    as_agent_at(
        &f,
        LATER,
        "entry.get",
        json!({ "node": "acme", "entry": entry }),
    )
    .expect("metadata is free");
    // totp.code is a value release too.
    let r = as_agent_at(
        &f,
        LATER,
        "totp.code",
        json!({ "node": "acme", "entry": entry }),
    );
    assert!(two_factor_required(&r), "{r:?}");
    // The owner's own session already passed the second factor to exist.
    send_at(
        &f,
        LATER,
        None,
        Some(&owner),
        "entry.reveal",
        json!({ "node": "acme", "entry": entry }),
    )
    .expect("owner reveals");

    // Stepping up (the owner proves the factor mid-session) opens the window…
    let up = send_at(
        &f,
        LATER,
        None,
        Some(&owner),
        "vault.gate_verify",
        json!({ "code": totp.code(LATER as u64) }),
    )
    .expect("step up");
    assert_eq!(up["elevated"], true);
    assert!(up.get("token").is_none(), "a step-up mints no token: {up}");
    reveal(&f, LATER + 60, &entry).expect("inside the window");
    // …and it closes again.
    let r = reveal(&f, LATER + 301, &entry);
    assert!(two_factor_required(&r), "{r:?}");
}

#[test]
fn a_wrong_step_up_code_is_refused_and_changes_nothing() {
    let (f, owner, entry, _totp) = gated();
    let r = send_at(
        &f,
        LATER,
        None,
        Some(&owner),
        "vault.gate_verify",
        json!({ "code": "000000" }),
    );
    assert!(matches!(r, Err(OpError::GateVerificationFailed)), "{r:?}");
    assert!(two_factor_required(&reveal(&f, LATER, &entry)));
}

#[test]
fn always_level_refuses_every_read_and_never_level_none() {
    let (f, owner, entry, _t) = gated();
    set_policy(&f, &owner, "always");
    for (op, params) in [
        ("entry.list", json!({ "node": "acme" })),
        ("entry.get", json!({ "node": "acme", "entry": entry })),
        ("entry.reveal", json!({ "node": "acme", "entry": entry })),
        ("vault.pending_list", json!({ "node": "acme" })),
    ] {
        let r = as_agent_at(&f, LATER, op, params);
        assert!(two_factor_required(&r), "{op}: {r:?}");
    }
    // search skips the node rather than failing the whole query.
    let hit = as_agent_at(&f, LATER, "search", json!({ "term": "API" })).expect("search");
    assert_eq!(hit["results"], json!([]), "{hit}");
    // The owner is unaffected.
    send_at(
        &f,
        LATER,
        None,
        Some(&owner),
        "entry.list",
        json!({ "node": "acme" }),
    )
    .expect("owner lists");
    // `never` asks for nothing.
    set_policy(&f, &owner, "never");
    reveal(&f, LATER, &entry).expect("never");
    as_agent_at(&f, LATER, "entry.list", json!({ "node": "acme" })).expect("never lists");
}

#[test]
fn nothing_is_asked_when_no_gate_is_enrolled() {
    let (f, owner, entry) = with_acme();
    set_policy(&f, &owner, "always");
    reveal(&f, LATER, &entry)
        .expect("no second factor exists, so none is asked (and nobody is locked out)");
    as_agent_at(&f, LATER, "entry.list", json!({ "node": "acme" })).expect("lists");
}

#[test]
fn the_policy_and_the_gate_survive_a_restart() {
    let (f, owner, entry, totp) = gated();
    set_policy(&f, &owner, "always");
    let f = restart(f);
    // After a restart the vault is locked and the gate still gates the login.
    let r = send_at(
        &f,
        LATER,
        None,
        None,
        "vault.unlock",
        json!({ "passphrase": PASSPHRASE }),
    );
    assert!(two_factor_required(&r), "{r:?}");
    let owner = send_at(
        &f,
        LATER,
        None,
        None,
        "vault.gate_verify",
        json!({ "code": totp.code(LATER as u64) }),
    )
    .expect("login completes")["token"]
        .as_str()
        .unwrap()
        .to_string();
    // Inside the login's own window the agent may read; once it lapses the
    // persisted `always` policy asks again.
    as_agent_at(&f, LATER + 10, "entry.list", json!({ "node": "acme" }))
        .expect("inside the window");
    let r = as_agent_at(&f, LATER + 400, "entry.list", json!({ "node": "acme" }));
    assert!(
        two_factor_required(&r),
        "policy persisted across the restart: {r:?}"
    );
    let r = reveal(&f, LATER + 400, &entry);
    assert!(two_factor_required(&r), "{r:?}");
    // The owner's session still reads.
    send_at(
        &f,
        LATER + 400,
        None,
        Some(&owner),
        "entry.list",
        json!({ "node": "acme" }),
    )
    .expect("owner");
}
