//! ADR-090 — `vault.approval_get` and the `pendingApprovals` count in
//! `vault.status`: the person deciding an approval sees what is being asked, on
//! a locked vault too, without anything being decrypted. Real server wiring on a
//! throwaway vault; time is moved explicitly.

mod common;

use common::*;
use credmgr_brokerd::protocol::OpError;
use serde_json::{json, Value};

const ASKED: i64 = NOW + 100;

/// acme/API_KEY, optionally `privateNames`, locked as a whole, and an agent's
/// reveal waiting as `request`.
fn scene(private: bool, lock: bool) -> (Fixture, String, String, String) {
    let (f, owner, entry) = with_acme();
    if private {
        send(
            &f,
            None,
            Some(&owner),
            "node.policy",
            json!({ "node": "acme", "reason": "hide names", "policy": { "privateNames": true } }),
        )
        .expect("policy");
    }
    if lock {
        send(&f, None, Some(&owner), "vault.lock", json!({})).expect("lock");
        assert!(f.state.is_locked());
    } else {
        // An unlocked vault asks for approval when the node itself is locked.
        send(
            &f,
            None,
            Some(&owner),
            "vault.node_lock",
            json!({ "node": "acme" }),
        )
        .expect("node lock");
    }
    let request = match as_agent_at(
        &f,
        ASKED,
        "entry.reveal",
        json!({ "node": "acme", "entry": entry }),
    ) {
        Err(OpError::ApprovalPending { request, .. }) => request,
        other => panic!("expected approval_pending, got {other:?}"),
    };
    (f, owner, entry, request)
}

fn status(f: &Fixture, at: i64) -> Value {
    send_at(f, at, None, None, "vault.status", json!({})).expect("status")
}

#[test]
fn status_counts_waiting_requests_and_names_nothing() {
    let (f, _owner, entry, request) = scene(false, true);
    let s = status(&f, ASKED + 1);
    assert_eq!(s["locked"], true);
    assert_eq!(s["pendingApprovals"], 1);
    let text = s.to_string();
    assert!(
        !text.contains("acme") && !text.contains(&entry) && !text.contains(&request),
        "the count names no node, entry or request: {text}"
    );
    // The same request asked again is the same slot, not a second one.
    let again = as_agent_at(
        &f,
        ASKED + 2,
        "entry.reveal",
        json!({ "node": "acme", "entry": entry }),
    );
    assert!(matches!(again, Err(OpError::ApprovalPending { .. })));
    assert_eq!(status(&f, ASKED + 3)["pendingApprovals"], 1);
}

#[test]
fn a_fresh_vault_has_no_waiting_requests() {
    let f = empty_broker();
    assert_eq!(status(&f, NOW)["pendingApprovals"], 0);
}

#[test]
fn a_locked_vault_describes_the_request_without_unlocking_or_decrypting() {
    let (f, _owner, entry, request) = scene(false, true);
    let r = send_at(
        &f,
        ASKED + 5,
        None,
        None,
        "vault.approval_get",
        json!({ "request": request }),
    )
    .expect("approval_get on a locked vault");
    assert_eq!(r["request"], json!(request));
    assert_eq!(r["node"], "acme");
    assert_eq!(r["entry"], json!(entry));
    assert_eq!(r["command"], "entry.reveal");
    assert_eq!(r["state"], "pending");
    assert_eq!(r["expiresIn"], 115);
    assert_eq!(r["requestedAt"], ASKED);
    assert!(
        r["nodeLabel"].is_string() && r["entryName"].is_string(),
        "a node without privateNames shows what the vault already holds in memory: {r}"
    );
    assert!(r.get("nameHidden").is_none(), "{r}");
    assert!(
        r.get("cwd").is_none(),
        "the requester's directory is the owner's, and a locked vault has no owner session: {r}"
    );
    assert!(f.state.is_locked(), "asking does not unlock");
    assert_eq!(
        f.state.staged_approval_count_for_test(),
        0,
        "nothing was staged"
    );
    assert!(
        !r.to_string().contains("v-1"),
        "no value is ever in the answer: {r}"
    );
}

#[test]
fn a_private_node_is_described_by_its_ids_only_on_a_locked_vault() {
    let (f, _owner, entry, request) = scene(true, true);
    let r = send_at(
        &f,
        ASKED + 5,
        None,
        None,
        "vault.approval_get",
        json!({ "request": request }),
    )
    .expect("approval_get");
    assert_eq!(r["nameHidden"], true, "{r}");
    assert!(r["nodeLabel"].is_null() && r["entryName"].is_null(), "{r}");
    assert_eq!(r["node"], "acme");
    assert_eq!(r["entry"], json!(entry));
    let list =
        send_at(&f, ASKED + 5, None, None, "vault.approval_get", json!({})).expect("the list");
    let one = &list["pending"][0];
    assert_eq!(one["request"], json!(request));
    assert!(
        one["entryName"].is_null() && one["nodeLabel"].is_null(),
        "{list}"
    );
}

#[test]
fn the_list_has_the_waiting_request_and_drops_it_when_it_expires() {
    let (f, _owner, _entry, first) = scene(false, true);
    let list = send_at(&f, ASKED + 1, None, None, "vault.approval_get", json!({})).unwrap();
    assert_eq!(list["pending"].as_array().unwrap().len(), 1);
    assert_eq!(list["pending"][0]["request"], json!(first));
    // 120 s later the request has expired: gone from the count, the list and `get`.
    let late = ASKED + 121;
    assert_eq!(status(&f, late)["pendingApprovals"], 0);
    let list = send_at(&f, late, None, None, "vault.approval_get", json!({})).unwrap();
    assert_eq!(list["pending"], json!([]));
    let gone = send_at(
        &f,
        late,
        None,
        None,
        "vault.approval_get",
        json!({ "request": first }),
    );
    assert!(matches!(gone, Err(OpError::NotFound(_))), "{gone:?}");
}

#[test]
fn an_unknown_request_is_not_found_and_a_decided_one_leaves_the_count() {
    let (f, _owner, _entry, request) = scene(false, true);
    let unknown = send_at(
        &f,
        ASKED + 1,
        None,
        None,
        "vault.approval_get",
        json!({ "request": "rq_doesnotexist" }),
    );
    assert!(matches!(unknown, Err(OpError::NotFound(_))), "{unknown:?}");
    let bad = send_at(
        &f,
        ASKED + 1,
        None,
        None,
        "vault.approval_get",
        json!({ "request": 7 }),
    );
    assert!(matches!(bad, Err(OpError::Malformed(_))), "{bad:?}");

    send_at(
        &f,
        ASKED + 10,
        None,
        None,
        "vault.approval_decide",
        json!({ "request": request, "approved": false, "passphrase": PASSPHRASE }),
    )
    .expect("deny with the factors");
    assert_eq!(status(&f, ASKED + 11)["pendingApprovals"], 0);
    let list = send_at(&f, ASKED + 11, None, None, "vault.approval_get", json!({})).unwrap();
    assert_eq!(
        list["pending"],
        json!([]),
        "a decided request is not waiting"
    );
    let one = send_at(
        &f,
        ASKED + 11,
        None,
        None,
        "vault.approval_get",
        json!({ "request": request }),
    )
    .unwrap();
    assert_eq!(one["state"], "denied");
}

#[test]
fn on_an_unlocked_vault_only_the_owner_session_may_ask_and_it_sees_the_names() {
    let (f, owner, entry, request) = scene(true, false);
    let r = send_at(
        &f,
        ASKED + 5,
        None,
        Some(&owner),
        "vault.approval_get",
        json!({ "request": request }),
    )
    .expect("the owner may ask");
    // ADR-083: the owner sees everything on a private node.
    assert_eq!(r["entry"], json!(entry));
    assert!(
        r["nodeLabel"].is_string() && r["entryName"].is_string(),
        "{r}"
    );
    assert!(r.get("nameHidden").is_none(), "{r}");
    assert!(
        r.get("cwd").is_some(),
        "the owner may see the requester's directory: {r}"
    );

    // An agent is refused (the token-less CLI peer is held to the same by cli_parity.rs): this is the owner's prompt.
    let agent = as_agent_at(
        &f,
        ASKED + 5,
        "vault.approval_get",
        json!({ "request": request }),
    );
    assert!(
        matches!(agent, Err(OpError::CapabilityNotHeld { .. })),
        "{agent:?}"
    );
    let list = as_agent_at(&f, ASKED + 5, "vault.approval_get", json!({}));
    assert!(
        matches!(list, Err(OpError::CapabilityNotHeld { .. })),
        "{list:?}"
    );

    let listed = send_at(
        &f,
        ASKED + 5,
        None,
        Some(&owner),
        "vault.approval_get",
        json!({}),
    )
    .unwrap();
    assert_eq!(listed["pending"].as_array().unwrap().len(), 1);
}

#[test]
fn a_token_less_look_at_status_or_the_waiting_list_does_not_keep_an_idle_vault_open() {
    // The window's Lock screen asks both every five seconds; a vault another client unlocked must still idle-lock.
    let (f, owner, _entry) = with_acme();
    let idle = 15 * 60;
    // one real request starts the clock
    send_at(&f, NOW, None, Some(&owner), "whoami", json!({})).expect("whoami");
    for i in 1..=10 {
        let at = NOW + i * 90;
        send_at(&f, at, None, None, "vault.status", json!({})).expect("status");
        let _ = send_at(&f, at, None, None, "vault.approval_get", json!({}));
    }
    f.state.tick_autolock(NOW + idle + 1);
    assert!(
        f.state.is_locked(),
        "the polls were not activity: the vault idle-locked"
    );
}

#[test]
fn a_logged_in_status_is_still_activity() {
    let (f, owner, _entry) = with_acme();
    let idle = 15 * 60;
    send_at(&f, NOW, None, Some(&owner), "whoami", json!({})).expect("whoami");
    send_at(
        &f,
        NOW + idle - 5,
        None,
        Some(&owner),
        "vault.status",
        json!({}),
    )
    .expect("status");
    f.state.tick_autolock(NOW + idle + 1);
    assert!(
        !f.state.is_locked(),
        "a live login's status resets the clock, as before"
    );
}
