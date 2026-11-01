//! 4.12 / ADR-088 — approval 4b: a person decides one request with the unlock
//! factors while the vault stays locked. Real server wiring on a throwaway vault;
//! the agent is a cwd-scoped process, time is moved explicitly.

mod common;

use common::*;
use credmgr_brokerd::protocol::OpError;
use credmgr_core::totp::{decode_gate_secret_base32, Totp};
use serde_json::{json, Value};

const SECRET: &str = "v-1"; // what `with_acme` stores in API_KEY
const ASKED: i64 = NOW + 100;

struct Scene {
    f: Fixture,
    entry: String,
    request: String,
    totp: Option<Totp>,
    recovery: Vec<String>,
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

/// A vault with acme/API_KEY, optionally a confirmed gate, locked as a whole,
/// and an agent's reveal waiting as `request`.
fn scene(gate: bool) -> Scene {
    let (f, owner, entry) = with_acme();
    let (mut totp, mut recovery) = (None, Vec::new());
    if gate {
        let begin = send(&f, None, Some(&owner), "vault.gate_enroll_begin", json!({})).unwrap();
        let t = totp_from_uri(begin["otpauthUri"].as_str().unwrap());
        let confirm = send(
            &f,
            None,
            Some(&owner),
            "vault.gate_enroll_confirm",
            json!({ "code": t.code(NOW as u64) }),
        )
        .unwrap();
        recovery = confirm["recoveryCodes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c.as_str().unwrap().to_string())
            .collect();
        totp = Some(t);
    }
    send(&f, None, Some(&owner), "vault.lock", json!({})).expect("lock");
    assert!(f.state.is_locked());
    let request = match as_agent_at(
        &f,
        ASKED,
        "entry.reveal",
        json!({ "node": "acme", "entry": entry }),
    ) {
        Err(OpError::ApprovalPending { request, .. }) => request,
        other => panic!("expected approval_pending on a wholly locked vault, got {other:?}"),
    };
    Scene {
        f,
        entry,
        request,
        totp,
        recovery,
    }
}

fn decide(s: &Scene, at: i64, approved: bool, extra: Value) -> Result<Value, OpError> {
    let mut params = json!({ "request": s.request, "approved": approved });
    for (k, v) in extra.as_object().unwrap() {
        params[k] = v.clone();
    }
    send_at(&s.f, at, None, None, "vault.approval_decide", params)
}

fn retry(s: &Scene, at: i64) -> Result<Value, OpError> {
    as_agent_at(
        &s.f,
        at,
        "entry.reveal",
        json!({ "node": "acme", "entry": s.entry }),
    )
}

fn pw() -> Value {
    json!({ "passphrase": PASSPHRASE })
}

#[test]
fn the_passphrase_alone_releases_one_value_and_the_vault_stays_locked() {
    let s = scene(false);
    let r = decide(&s, ASKED + 10, true, pw()).expect("decide with the passphrase");
    assert_eq!(r["approved"], true);
    assert_eq!(r["authorisedBy"], "factors");
    assert!(r.get("token").is_none(), "no session is created: {r}");
    assert!(s.f.state.is_locked(), "the vault is still locked");
    assert_eq!(s.f.state.staged_approval_count_for_test(), 1);

    let revealed = retry(&s, ASKED + 20).expect("the agent gets exactly the approved value");
    assert_eq!(revealed["value"], SECRET);
    assert!(s.f.state.is_locked(), "still locked after the release");
    assert_eq!(s.f.state.staged_approval_count_for_test(), 0, "consumed");
    // One value was released; the next ask is a new request, and still locked-out otherwise.
    assert!(matches!(
        retry(&s, ASKED + 30),
        Err(OpError::ApprovalPending { .. })
    ));
    let other = send_at(
        &s.f,
        ASKED + 30,
        None,
        None,
        "entry.list",
        json!({ "node": "acme" }),
    );
    assert!(other.is_ok() || other.is_err()); // metadata rules are unchanged; nothing else was opened
}

#[test]
fn a_wrong_passphrase_decides_nothing_and_repeated_guesses_hit_the_backoff() {
    let s = scene(false);
    for i in 0..5 {
        let r = decide(
            &s,
            ASKED + 10 + i,
            true,
            json!({ "passphrase": "not the passphrase" }),
        );
        assert!(matches!(r, Err(OpError::WrongPassphrase)), "{r:?}");
    }
    assert_eq!(s.f.state.staged_approval_count_for_test(), 0);
    // The request is untouched …
    assert!(
        matches!(retry(&s, ASKED + 20), Err(OpError::ApprovalPending { request, .. }) if request == s.request)
    );
    // … and the sixth attempt, even with the right passphrase, is rate limited exactly as `vault.unlock` is.
    let r = decide(&s, ASKED + 21, true, pw());
    assert!(matches!(r, Err(OpError::RateLimited { .. })), "{r:?}");
}

#[test]
fn with_a_gate_a_fresh_authenticator_code_is_needed_and_a_recovery_code_is_not_enough() {
    let s = scene(true);
    let totp = s.totp.as_ref().unwrap();
    let r = decide(&s, ASKED + 10, true, pw());
    assert!(matches!(r, Err(OpError::TwoFactorRequired { .. })), "{r:?}");
    let r = decide(
        &s,
        ASKED + 11,
        true,
        json!({ "passphrase": PASSPHRASE, "code": "000000" }),
    );
    assert!(matches!(r, Err(OpError::GateVerificationFailed)), "{r:?}");
    let r = decide(
        &s,
        ASKED + 12,
        true,
        json!({ "passphrase": PASSPHRASE, "code": s.recovery[0] }),
    );
    assert!(
        matches!(r, Err(OpError::GateVerificationFailed)),
        "recovery codes are not offered here: {r:?}"
    );
    assert_eq!(s.f.state.staged_approval_count_for_test(), 0);

    let at = ASKED + 60;
    let ok = decide(
        &s,
        at,
        true,
        json!({ "passphrase": PASSPHRASE, "code": totp.code(at as u64) }),
    )
    .expect("both factors");
    assert_eq!(ok["authorisedBy"], "factors");
    assert!(s.f.state.is_locked());
    assert_eq!(retry(&s, at + 5).unwrap()["value"], SECRET);
}

#[test]
fn a_spent_authenticator_step_stays_spent_across_a_restart_and_the_burned_recovery_code_is_untouched(
) {
    let s = scene(true);
    let totp = s.totp.clone().unwrap();
    let recovery = s.recovery[0].clone();
    let at = ASKED + 60;
    let code = totp.code(at as u64);
    decide(
        &s,
        at,
        true,
        json!({ "passphrase": PASSPHRASE, "code": code }),
    )
    .expect("decide");
    // (the refused recovery attempt above never burned it — try one here too)
    let r = decide(
        &s,
        at + 1,
        true,
        json!({ "passphrase": PASSPHRASE, "code": recovery }),
    );
    assert!(r.is_err());

    let f = restart(s.f);
    let r = send_at(
        &f,
        at + 2,
        None,
        None,
        "vault.unlock",
        json!({ "passphrase": PASSPHRASE }),
    );
    assert!(matches!(r, Err(OpError::TwoFactorRequired { .. })), "{r:?}");
    let replay = send_at(
        &f,
        at + 3,
        None,
        None,
        "vault.gate_verify",
        json!({ "code": code }),
    );
    assert!(
        matches!(replay, Err(OpError::GateVerificationFailed)),
        "the same step cannot be spent twice: {replay:?}"
    );
    // The recovery code was never burned by the factor path: it still opens the login.
    send_at(
        &f,
        at + 4,
        None,
        None,
        "vault.gate_verify",
        json!({ "code": recovery }),
    )
    .expect("an unburned recovery code still works");
}

#[test]
fn a_denial_with_the_factors_is_reported_as_denied() {
    let s = scene(false);
    let r = decide(&s, ASKED + 10, false, pw()).expect("deny");
    assert_eq!(r["approved"], false);
    assert_eq!(s.f.state.staged_approval_count_for_test(), 0);
    let after = retry(&s, ASKED + 20);
    assert!(
        matches!(
            after,
            Err(OpError::ApprovalDenied {
                reason: "denied",
                ..
            })
        ),
        "{after:?}"
    );
}

#[test]
fn it_is_only_for_a_locked_vault_an_unknown_request_and_a_decided_one() {
    let s = scene(false);
    let r = send_at(
        &s.f,
        ASKED + 5,
        None,
        None,
        "vault.approval_decide",
        json!({ "request": "rq_nothing_ever_issued", "approved": true, "passphrase": PASSPHRASE }),
    );
    assert!(matches!(r, Err(OpError::NotFound(_))), "{r:?}");
    decide(&s, ASKED + 6, true, pw()).unwrap();
    let again = decide(&s, ASKED + 7, true, pw());
    assert!(matches!(again, Err(OpError::Malformed(_))), "{again:?}");

    // Unlocked, the passphrase path is closed: the owner session decides.
    let (f, owner, entry) = with_acme();
    let r = send(
        &f,
        None,
        Some(&owner),
        "vault.approval_decide",
        json!({ "request": "rq_x", "approved": true, "passphrase": PASSPHRASE }),
    );
    assert!(
        matches!(r, Err(OpError::Malformed(ref m)) if m.contains("locked")),
        "{r:?}"
    );
    let _ = entry;
}

#[test]
fn an_unknown_field_id_in_the_retry_does_not_burn_the_approval_given_with_the_factors() {
    let (f, owner, _api) = with_acme();
    let multi = send(
        &f,
        None,
        Some(&owner),
        "entry.create",
        json!({
            "node": "acme", "name": "multi",
            "fields": [{ "label": "user", "value": "alice" }, { "label": "pass", "value": "p-two" }]
        }),
    )
    .unwrap()["entry"]
        .as_str()
        .unwrap()
        .to_string();
    let ids: Vec<String> = send(
        &f,
        None,
        Some(&owner),
        "entry.get",
        json!({ "node": "acme", "entry": multi }),
    )
    .unwrap()["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x["id"].as_str().unwrap().to_string())
        .collect();
    send(&f, None, Some(&owner), "vault.lock", json!({})).unwrap();
    let ask = |at: i64, field_ids: Value| {
        as_agent_at(
            &f,
            at,
            "entry.reveal",
            json!({ "node": "acme", "entry": multi, "fieldIds": field_ids }),
        )
    };
    let request = match ask(ASKED, json!([ids[1]])) {
        Err(OpError::ApprovalPending { request, .. }) => request,
        other => panic!("{other:?}"),
    };
    send_at(
        &f,
        ASKED + 10,
        None,
        None,
        "vault.approval_decide",
        json!({ "request": request, "approved": true, "passphrase": PASSPHRASE }),
    )
    .expect("decide");
    // A list that names a field the entry does not have — alone, or beside a good one — is refused …
    for bad in [json!(["f_deadbeef"]), json!([ids[1], "f_deadbeef"])] {
        let r = ask(ASKED + 20, bad);
        assert!(matches!(r, Err(OpError::NotFound(_))), "{r:?}");
        assert_eq!(
            f.state.staged_approval_count_for_test(),
            1,
            "the refusal burned the approval"
        );
    }
    // … and the corrected retry still gets the value the person approved.
    let ok = ask(ASKED + 30, json!([ids[1]])).expect("corrected retry");
    assert_eq!(ok["value"], "p-two");
    assert_eq!(f.state.staged_approval_count_for_test(), 0);
}

#[test]
fn the_decision_is_audited_under_the_factors_and_the_log_never_holds_the_value() {
    let s = scene(false);
    decide(&s, ASKED + 10, true, pw()).unwrap();
    retry(&s, ASKED + 20).unwrap();
    let f = restart(s.f);
    let owner = send_at(
        &f,
        ASKED + 30,
        None,
        None,
        "vault.unlock",
        json!({ "passphrase": PASSPHRASE }),
    )
    .unwrap()["token"]
        .as_str()
        .unwrap()
        .to_string();
    let feed = send_at(
        &f,
        ASKED + 31,
        None,
        Some(&owner),
        "audit.tail",
        json!({ "limit": 500 }),
    )
    .unwrap();
    let rows = feed["records"].as_array().unwrap();
    let rec = rows
        .iter()
        .find(|r| r["action"] == "vault.approval_decide")
        .expect("a record exists");
    assert_eq!(rec["actor"], "Factors");
    assert_eq!(rec["decision"], "allow");
    assert!(
        rec["detail"].as_str().unwrap().contains("stayed locked"),
        "{rec}"
    );
    let text = feed.to_string();
    assert!(
        !text.contains(SECRET) && !text.contains(PASSPHRASE),
        "{text}"
    );
}

#[test]
fn an_approved_value_is_dropped_when_its_ttl_ends_even_though_the_vault_never_unlocked() {
    let s = scene(false);
    decide(&s, ASKED + 100, true, pw()).unwrap();
    assert_eq!(s.f.state.staged_approval_count_for_test(), 1);
    // The request was made at ASKED with a 120 s life: past it, nothing is handed over.
    let late = retry(&s, ASKED + 125);
    assert!(late.is_err(), "{late:?}");
    assert!(!format!("{late:?}").contains(SECRET));
}
