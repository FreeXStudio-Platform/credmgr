//! ADR-140 - per-node security levels (`17_AIRLOCK_AND_LLM.md §2`), enforced where an agent's
//! request is decided. The fixture is the real server wiring over a real `vault.init_*` vault,
//! with an agent identified by its cwd (`acme`'s workdir) and the owner logged in.

mod common;

use common::*;
use serde_json::{json, Value};

use credmgr_brokerd::protocol::OpError;

fn set_level(f: &Fixture, owner: &str, level: &str) -> Result<Value, OpError> {
    send(
        f,
        None,
        Some(owner),
        "node.policy",
        json!({ "node": "acme", "reason": "test", "policy": { "securityLevel": level } }),
    )
}

/// Sets the level straight in the registry. Lowering a level through `node.policy` needs a presence
/// proof (a Touch ID touch); the fixture vault has no presence key, so a test that needs a node at
/// `Open` puts it there the way a vault written by an earlier session would have it.
fn force_level(f: &Fixture, level: credmgr_core::registry::SecurityLevel) {
    f.state
        .registry
        .write()
        .unwrap()
        .nodes
        .get_mut("acme")
        .unwrap()
        .policy
        .security_level = level;
}

/// An entry the inference calls `low` (a plain text field) and one it calls `critical` (a
/// private key), created by the owner.
fn two_entries(f: &Fixture, owner: &str) -> (String, String) {
    let low = send(
        f,
        None,
        Some(owner),
        "entry.create",
        json!({ "node": "acme", "name": "NOTE_LOW", "value": "plain", "sensitivity": "low" }),
    )
    .unwrap()["entry"]
        .as_str()
        .unwrap()
        .to_string();
    let high = send(
        f,
        None,
        Some(owner),
        "entry.create",
        json!({ "node": "acme", "name": "KEY_HIGH", "value": "v-high", "sensitivity": "high" }),
    )
    .unwrap()["entry"]
        .as_str()
        .unwrap()
        .to_string();
    (low, high)
}

fn reveal(f: &Fixture, entry: &str) -> Result<Value, OpError> {
    as_agent(f, "entry.reveal", json!({ "node": "acme", "entry": entry }))
}

fn is_pending(r: &Result<Value, OpError>) -> bool {
    matches!(r, Err(OpError::ApprovalPending { .. }))
}

#[test]
fn a_node_starts_guarded_and_whoami_and_the_graph_say_so() {
    let (f, owner, _e) = with_acme();
    let who = as_agent(&f, "whoami", json!({})).unwrap();
    assert_eq!(who["level"], "guarded");
    let g = send(&f, None, Some(&owner), "graph.snapshot", json!({})).unwrap();
    let acme = g["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["id"] == "acme")
        .unwrap();
    assert_eq!(acme["securityLevel"], "guarded");
}

#[test]
fn guarded_waits_for_high_and_critical_but_not_for_low() {
    let (f, owner, _e) = with_acme();
    let (low, high) = two_entries(&f, &owner);
    let r = reveal(&f, &low).expect("a low value comes straight back");
    assert_eq!(r["value"], "plain");
    let r = reveal(&f, &high);
    assert!(is_pending(&r), "{r:?}");
    // The owner decides; the agent's retry then gets the value, once.
    let request = match r {
        Err(OpError::ApprovalPending { request, .. }) => request,
        _ => unreachable!(),
    };
    send(
        &f,
        None,
        Some(&owner),
        "vault.approval_decide",
        json!({ "request": request, "approved": true }),
    )
    .expect("owner approves");
    let got = reveal(&f, &high).expect("approved");
    assert_eq!(got["value"], "v-high");
    assert!(is_pending(&reveal(&f, &high)), "an approval is used once");
}

#[test]
fn open_never_waits_and_sealed_always_waits() {
    let (f, owner, _e) = with_acme();
    let (low, high) = two_entries(&f, &owner);
    force_level(&f, credmgr_core::registry::SecurityLevel::Open);
    assert_eq!(reveal(&f, &high).unwrap()["value"], "v-high");
    assert_eq!(reveal(&f, &low).unwrap()["value"], "plain");
    set_level(&f, &owner, "sealed").unwrap();
    assert!(
        is_pending(&reveal(&f, &low)),
        "sealed waits even for a low value"
    );
    assert!(is_pending(&reveal(&f, &high)));
}

#[test]
fn the_owner_is_never_held_by_a_level() {
    let (f, owner, _e) = with_acme();
    let (_low, high) = two_entries(&f, &owner);
    set_level(&f, &owner, "sealed").unwrap();
    let got = send(
        &f,
        None,
        Some(&owner),
        "entry.reveal",
        json!({ "node": "acme", "entry": high }),
    )
    .expect("the owner reads their own value");
    assert_eq!(got["value"], "v-high");
}

#[test]
fn sealed_holds_an_agents_create_in_the_tray_and_refuses_a_change() {
    let (f, owner, entry) = with_acme();
    set_level(&f, &owner, "sealed").unwrap();
    // create -> the tray
    let created = as_agent(
        &f,
        "entry.create",
        json!({ "node": "acme", "name": "NEW_ONE", "value": "v-new" }),
    )
    .expect("an agent may add");
    assert_eq!(created["pending"], true, "{created}");
    let listed = send(
        &f,
        None,
        Some(&owner),
        "entry.list",
        json!({ "node": "acme" }),
    )
    .unwrap();
    let names = serde_json::to_string(&listed).unwrap();
    assert!(
        !names.contains("NEW_ONE"),
        "a held entry is not in the node yet: {names}"
    );
    let tray = send(
        &f,
        None,
        Some(&owner),
        "vault.pending_list",
        json!({ "node": "acme" }),
    )
    .unwrap();
    assert!(serde_json::to_string(&tray).unwrap().contains("NEW_ONE"));
    // ... and the owner can accept it.
    send(
        &f,
        None,
        Some(&owner),
        "vault.pending_accept",
        json!({ "node": "acme", "entry": created["entry"] }),
    )
    .expect("owner accepts");
    // update / rotate / remove are refused with rule L1
    let generation = send(
        &f,
        None,
        Some(&owner),
        "entry.list",
        json!({ "node": "acme" }),
    )
    .unwrap()["generation"]
        .as_u64()
        .unwrap_or(0);
    for (op, params) in [
        (
            "entry.update",
            json!({ "node": "acme", "entry": entry, "generation": generation, "value": "x" }),
        ),
        (
            "entry.rotate",
            json!({ "node": "acme", "entry": entry, "generation": generation, "value": "x" }),
        ),
        (
            "entry.remove",
            json!({ "node": "acme", "entry": entry, "generation": generation }),
        ),
    ] {
        let e = as_agent(&f, op, params).unwrap_err();
        assert!(
            matches!(e, OpError::NodeAccessDenied { rule: "L1", .. }),
            "{op}: {e:?}"
        );
    }
    // The value is still what the owner put there.
    let got = send(
        &f,
        None,
        Some(&owner),
        "entry.reveal",
        json!({ "node": "acme", "entry": entry }),
    )
    .unwrap();
    assert_eq!(got["value"], "v-1");
}

#[test]
fn guarded_and_open_let_an_agent_create_and_change_directly() {
    let (f, owner, entry) = with_acme();
    for level in ["guarded", "open"] {
        if level == "open" {
            force_level(&f, credmgr_core::registry::SecurityLevel::Open);
        }
        let created = as_agent(
            &f,
            "entry.create",
            json!({ "node": "acme", "name": format!("N_{level}"), "value": "v" }),
        )
        .unwrap();
        assert_eq!(created["pending"], false, "{level}: {created}");
    }
    let generation = send(
        &f,
        None,
        Some(&owner),
        "entry.list",
        json!({ "node": "acme" }),
    )
    .unwrap()["generation"]
        .as_u64()
        .unwrap_or(0);
    as_agent(
        &f,
        "entry.update",
        json!({ "node": "acme", "entry": entry, "generation": generation, "value": "v-2" }),
    )
    .expect("an agent on an Open node may update");
}

#[test]
fn sealed_gives_an_agent_no_totp_code() {
    let (f, owner, _e) = with_acme();
    set_level(&f, &owner, "sealed").unwrap();
    let totp = send(
        &f,
        None,
        Some(&owner),
        "entry.create",
        json!({ "node": "acme", "name": "TOTP_ONE", "value": "JBSWY3DPEHPK3PXP", "entryType": "totp" }),
    )
    .unwrap()["entry"]
        .as_str()
        .unwrap()
        .to_string();
    let e = as_agent(&f, "totp.code", json!({ "node": "acme", "entry": totp })).unwrap_err();
    assert!(
        matches!(e, OpError::NodeAccessDenied { rule: "L1", .. }),
        "{e:?}"
    );
}

#[test]
fn raising_the_level_needs_no_presence_and_lowering_it_does() {
    let (f, owner, _e) = with_acme();
    set_level(&f, &owner, "sealed").expect("raising is not gated");
    assert_eq!(
        as_agent(&f, "whoami", json!({})).unwrap()["level"],
        "sealed"
    );
    // Lowering widens what an agent may do: the broker wants the user's finger.
    let lowered = set_level(&f, &owner, "open");
    let wire = credmgr_brokerd::protocol::to_wire("r", &lowered);
    assert_eq!(wire["error"], "presence_required", "{wire}");
    assert_eq!(
        as_agent(&f, "whoami", json!({})).unwrap()["level"],
        "sealed",
        "nothing was applied"
    );
    // The same level again, and a change of some other field, are not widening.
    set_level(&f, &owner, "sealed").expect("no change of level is not a lowering");
}

#[test]
fn a_policy_patch_with_a_bad_level_is_refused() {
    let (f, owner, _e) = with_acme();
    let e = set_level(&f, &owner, "paranoid").unwrap_err();
    assert!(matches!(e, OpError::Malformed(_)), "{e:?}");
}

#[test]
fn a_registry_written_before_the_field_existed_reads_as_guarded() {
    let json = r#"{"siblingVisibility":"shared","descendantRead":false,"requireTwoFactor":"reveal","lockAfterSeconds":null,"privateNames":false,"agentAccess":"read-write"}"#;
    let p: credmgr_core::registry::NodePolicy = serde_json::from_str(json).unwrap();
    assert_eq!(
        p.security_level,
        credmgr_core::registry::SecurityLevel::Guarded
    );
}

// ---- ADR-148: the pre-stable security fixes -------------------------------------------------------------

fn generation_of(f: &Fixture, owner: &str) -> u64 {
    send(
        f,
        None,
        Some(owner),
        "entry.list",
        json!({ "node": "acme" }),
    )
    .unwrap()["generation"]
        .as_u64()
        .unwrap_or(0)
}

fn is_l1(r: &Result<Value, OpError>) -> bool {
    matches!(r, Err(OpError::NodeAccessDenied { rule: "L1", .. }))
}

#[test]
fn p1_3_an_agent_cannot_lower_an_entrys_sensitivity_on_a_guarded_node() {
    let (f, owner, _e) = with_acme();
    let (_low, high) = two_entries(&f, &owner);

    // An explicit override.
    let r = as_agent(
        &f,
        "entry.update",
        json!({ "node": "acme", "entry": high, "generation": generation_of(&f, &owner), "sensitivity": "low" }),
    );
    assert!(is_l1(&r), "explicit lowering is refused: {r:?}");

    // A re-inference: the owner stores a two-factor seed (inferred `high`); the agent replaces the value
    // with plain text, which would infer `low`.
    let seeded = send(
        &f,
        None,
        Some(&owner),
        "entry.create",
        json!({ "node": "acme", "name": "BACKUP_2FA", "value": "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP" }),
    )
    .unwrap()["entry"]
        .as_str()
        .unwrap()
        .to_string();
    let r = as_agent(
        &f,
        "entry.update",
        json!({ "node": "acme", "entry": seeded, "generation": generation_of(&f, &owner), "value": "plain words" }),
    );
    assert!(is_l1(&r), "lowering by re-inference is refused: {r:?}");

    // Both still wait for the owner.
    assert!(is_pending(&reveal(&f, &high)));
    assert!(is_pending(&reveal(&f, &seeded)));

    // The owner may lower it; an agent may raise it.
    let raised = as_agent(
        &f,
        "entry.update",
        json!({ "node": "acme", "entry": _low, "generation": generation_of(&f, &owner), "sensitivity": "critical" }),
    );
    assert!(raised.is_ok(), "raising is allowed: {raised:?}");
    send(
        &f,
        None,
        Some(&owner),
        "entry.update",
        json!({ "node": "acme", "entry": high, "generation": generation_of(&f, &owner), "sensitivity": "low" }),
    )
    .expect("the owner may lower it");
}

#[test]
fn p1_3_an_agent_cannot_undo_the_owners_raise_of_sensitivity() {
    use credmgr_brokerd::protocol::Request;
    let (f, owner, _e) = with_acme();
    let (low, _high) = two_entries(&f, &owner);
    let (rotated, audit) = credmgr_brokerd::server::handle_request_at(
        &f.state,
        &peer(None),
        &Request {
            id: "r".into(),
            op: "entry.rotate".into(),
            token: Some(owner.clone()),
            params: json!({ "node": "acme", "entry": low, "generation": generation_of(&f, &owner),
                            "value": "plain-2", "sensitivity": "high" }),
        },
        NOW,
        std::time::Instant::now(),
    );
    rotated.expect("the owner rotates and raises it");
    let r = as_agent(
        &f,
        "entry.undo",
        json!({ "node": "acme", "id": audit.expect("audited"), "generation": generation_of(&f, &owner) }),
    );
    assert!(is_l1(&r), "an agent's undo cannot lower it back: {r:?}");
    assert!(
        is_pending(&reveal(&f, &low)),
        "it still waits for the owner"
    );
}

#[test]
fn p1_4_only_the_owner_accepts_or_discards_a_held_entry() {
    let (f, owner, _e) = with_acme();
    set_level(&f, &owner, "sealed").unwrap();
    let mine = as_agent(
        &f,
        "entry.create",
        json!({ "node": "acme", "name": "HELD_ONE", "value": "v-held" }),
    )
    .unwrap();
    let other = as_agent(
        &f,
        "entry.create",
        json!({ "node": "acme", "name": "HELD_TWO", "value": "v-held-2" }),
    )
    .unwrap();
    for op in ["vault.pending_accept", "vault.pending_discard"] {
        for held in [&mine, &other] {
            let r = as_agent(&f, op, json!({ "node": "acme", "entry": held["entry"] }));
            assert!(
                matches!(r, Err(OpError::CapabilityNotHeld { .. })),
                "{op} by an agent is refused: {r:?}"
            );
        }
    }
    let tray = send(
        &f,
        None,
        Some(&owner),
        "vault.pending_list",
        json!({ "node": "acme" }),
    )
    .unwrap();
    assert_eq!(
        tray["pending"].as_array().unwrap().len(),
        2,
        "nothing moved"
    );
    send(
        &f,
        None,
        Some(&owner),
        "vault.pending_discard",
        json!({ "node": "acme", "entry": other["entry"] }),
    )
    .expect("the owner discards");
    send(
        &f,
        None,
        Some(&owner),
        "vault.pending_accept",
        json!({ "node": "acme", "entry": mine["entry"] }),
    )
    .expect("the owner accepts");
}

#[test]
fn p2_1_content_search_is_not_an_oracle_for_what_an_agent_cannot_reveal() {
    let (f, owner, _e) = with_acme();
    let (_low, _high) = two_entries(&f, &owner);
    let search = |term: &str| -> Value {
        as_agent(
            &f,
            "search.content",
            json!({ "term": term, "node": "acme" }),
        )
        .unwrap()
    };
    let hits = |v: &Value| v["results"].as_array().unwrap().len();
    // Guarded: the low value is searchable, the high one ("v-high") is not.
    assert_eq!(
        hits(&search("plain")),
        1,
        "a low value an agent may reveal is found"
    );
    assert_eq!(
        hits(&search("v-hi")),
        0,
        "a high value on a Guarded node is never matched"
    );
    // Sealed: nothing at all.
    set_level(&f, &owner, "sealed").unwrap();
    assert_eq!(
        hits(&search("plain")),
        0,
        "nothing on a Sealed node is matched"
    );
    // The owner still finds both.
    let owner_hits = send(
        &f,
        None,
        Some(&owner),
        "search.content",
        json!({ "term": "v-hi", "node": "acme" }),
    )
    .unwrap();
    assert_eq!(hits(&owner_hits), 1);
}

#[test]
fn a_node_that_does_not_exist_is_reported_as_missing_not_locked() {
    let (f, owner, _e) = with_acme();
    for (op, params) in [
        (
            "entry.create",
            json!({ "node": "nosuchnode", "name": "X", "value": "v" }),
        ),
        ("notes.read", json!({ "node": "nosuchnode" })),
    ] {
        let err = send(&f, None, Some(&owner), op, params).unwrap_err();
        let text = format!("{err:?}");
        assert!(
            matches!(err, OpError::NotFound(_)) && text.contains("no node nosuchnode"),
            "{op}: {text}"
        );
    }
}
