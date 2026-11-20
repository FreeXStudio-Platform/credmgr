//! ADR-169 — `vault.doctor_apply`: every move of one doctor plan in one request.
//!
//! * The request carries the exact plan the scan showed; every move is applied through `entry.move`'s
//!   commit, the factors are asked for once (one presence proof covers the whole plan, and is spent), and
//!   each moved entry is in its new node, readable there, and movable back with `entry.move`.
//! * Anything refusable is refused before anything moves: a stale generation, an entry named twice, a
//!   missing entry, a name a previous step already brought into the destination, the orphan, an unknown or
//!   locked node, a node whose own second factor is not fresh, an agent or a non-login scope, no proof, or
//!   a proof made for a different plan.
//! * A failure after the first move stops the plan: the answer says what was applied and where it stopped.

mod f1_support;

use serde_json::{json, Value};

use credmgr_brokerd::protocol::OpError;
use credmgr_brokerd::scope::BrokerScope;
use credmgr_brokerd::state::BrokerState;
use credmgr_core::access::Origin;
use credmgr_core::registry::{Capability, GLOBAL_ID};
use credmgr_core::totp::{decode_gate_secret_base32, Totp};

use f1_support::*;

const HOOK: &str = "TEST_hook-Qm81Lp";
const TOKEN: &str = "TEST_token-Zx52Rk";
const SHARED: &str = "TEST_shared-Wq73Pn";

fn node(state: &BrokerState, owner: &BrokerScope, id: &str, parent: &str) {
    call(
        state,
        owner,
        NOW,
        "node.create",
        json!({ "id": id, "label": id, "parentId": parent }),
    )
    .expect("node.create");
}

/// `acme` with two sub-nodes sharing a value (a move-to-parent proposal), `demo`, and two entries in
/// `global` named for a project (two misfiled proposals, both leaving `global`).
fn planted() -> (Vault, std::sync::Arc<BrokerState>, BrokerScope, Signer) {
    let (v, state) = created_vault(None);
    let owner = login(&state);
    node(&state, &owner, "acme", GLOBAL_ID);
    node(&state, &owner, "acme-web", "acme");
    node(&state, &owner, "acme-api", "acme");
    node(&state, &owner, "demo", GLOBAL_ID);
    create_entry(&state, &owner, GLOBAL_ID, "ACME_DEPLOY_HOOK", HOOK);
    create_entry(&state, &owner, GLOBAL_ID, "DEMO_API_TOKEN", TOKEN);
    create_entry(&state, &owner, "acme-web", "SHARED_KEY", SHARED);
    create_entry(&state, &owner, "acme-api", "SHARED_KEY_COPY", SHARED);
    let key = enrol_first_key(&state, &owner);
    (v, state, owner, key)
}

/// Every move proposal of one scan, in report order, exactly as the scan carried it.
fn plan_of(state: &BrokerState, owner: &BrokerScope) -> Vec<Value> {
    let report = call(state, owner, NOW, "vault.doctor_scan", json!({})).expect("scan");
    report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["proposal"]["op"] == "entry.move")
        .map(|f| f["proposal"]["move"].clone())
        .collect()
}

fn apply(
    state: &BrokerState,
    owner: &BrokerScope,
    key: &Signer,
    moves: &[Value],
) -> Result<Value, OpError> {
    let proved = with_proof(
        state,
        owner,
        key,
        NOW,
        "vault.doctor_apply",
        json!({ "moves": moves }),
    );
    call(state, owner, NOW, "vault.doctor_apply", proved)
}

fn names(state: &BrokerState, owner: &BrokerScope, node: &str) -> Vec<String> {
    let mut n: Vec<String> = call(state, owner, NOW, "entry.list", json!({ "node": node }))
        .unwrap()["names"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n.as_str().unwrap().to_string())
        .collect();
    n.sort();
    n
}

/// Every node's names, to show a refused plan changed nothing.
fn snapshot(state: &BrokerState, owner: &BrokerScope) -> Vec<(String, Vec<String>, u64)> {
    [GLOBAL_ID, "acme", "acme-web", "acme-api", "demo"]
        .iter()
        .map(|n| {
            (
                n.to_string(),
                names(state, owner, n),
                generation(state, owner, n),
            )
        })
        .collect()
}

fn entry_id(state: &BrokerState, node: &str, name: &str) -> String {
    state.manifests.read().unwrap()[node]
        .entries
        .iter()
        .find(|e| e.name == name)
        .unwrap()
        .id
        .clone()
}

#[test]
fn a_whole_plan_applies_in_one_request_with_one_proof() {
    let (v, state, owner, key) = planted();
    let plan = plan_of(&state, &owner);
    assert_eq!(
        plan.len(),
        3,
        "two misfiled and one move-to-parent: {plan:?}"
    );
    let global_before = generation(&state, &owner, GLOBAL_ID);

    let proved = with_proof(
        &state,
        &owner,
        &key,
        NOW,
        "vault.doctor_apply",
        json!({ "moves": plan }),
    );
    let done = call(&state, &owner, NOW, "vault.doctor_apply", proved.clone()).expect("apply");
    assert_eq!(done["complete"], true);
    assert_eq!(done["notApplied"], 0);
    let applied = done["applied"].as_array().unwrap();
    assert_eq!(applied.len(), 3);
    for (i, a) in applied.iter().enumerate() {
        assert_eq!(a["index"], i);
        assert_eq!(a["entry"], plan[i]["entry"]);
        assert_eq!(a["from"], plan[i]["node"]);
        assert_eq!(a["node"], plan[i]["to"]);
    }
    // Two moves left `global`: the second carried the generation the first one left.
    assert_eq!(
        generation(&state, &owner, GLOBAL_ID),
        global_before + 2,
        "global moved on once per move"
    );
    assert!(
        !done.to_string().contains("TEST_"),
        "no value in the answer"
    );

    // Each value is in its new node and reads back there.
    assert_eq!(names(&state, &owner, GLOBAL_ID), Vec::<String>::new());
    assert!(names(&state, &owner, "acme").contains(&"ACME_DEPLOY_HOOK".to_string()));
    assert_eq!(names(&state, &owner, "demo"), vec!["DEMO_API_TOKEN"]);
    let hook = entry_id(&state, "acme", "ACME_DEPLOY_HOOK");
    assert_eq!(reveal(&state, &owner, "acme", &hook), HOOK);
    let token = entry_id(&state, "demo", "DEMO_API_TOKEN");
    assert_eq!(reveal(&state, &owner, "demo", &token), TOKEN);
    verify_ok(&state, &owner);

    // The one proof was spent: the same request again is refused and moves nothing more.
    let again = call(&state, &owner, NOW, "vault.doctor_apply", proved);
    assert!(
        matches!(
            again,
            Err(OpError::PresenceFailed { .. }) | Err(OpError::Conflict { .. })
        ),
        "{again:?}"
    );

    // Each applied move is undone the ordinary way: `entry.move` back.
    let back = json!({ "node": "demo", "entry": token, "to": GLOBAL_ID,
                       "generation": generation(&state, &owner, "demo") });
    let back = with_proof(&state, &owner, &key, NOW, "entry.move", back);
    call(&state, &owner, NOW, "entry.move", back).expect("moved back");
    assert_eq!(names(&state, &owner, GLOBAL_ID), vec!["DEMO_API_TOKEN"]);

    // The trail: each planned move has the source's record and the destination's.
    let records = credmgr_store::audit::range(&v.paths(), 0, NOW + 1).unwrap();
    let to_records = records
        .iter()
        .filter(|r| r.action == "entry.move" && r.node_id.as_deref() == Some("acme"))
        .filter(|r| r.detail.as_deref() == Some("moved from global"))
        .count();
    assert_eq!(to_records, 1);
    let from_records = records
        .iter()
        .filter(|r| r.action == "entry.move" && r.node_id.as_deref() == Some(GLOBAL_ID))
        .filter(|r| {
            r.detail
                .as_deref()
                .is_some_and(|d| d.starts_with("moved to ") && d.ends_with("by vault.doctor_apply"))
        })
        .count();
    assert_eq!(from_records, 2);

    // And it survives a restart.
    let (state, owner) = restart(&v, state, None);
    assert_eq!(reveal(&state, &owner, "acme", &hook), HOOK);
}

#[test]
fn anything_refusable_is_refused_before_anything_moves() {
    let (_v, state, owner, key) = planted();
    let plan = plan_of(&state, &owner);
    let before = snapshot(&state, &owner);
    let refused = |moves: Vec<Value>, why: &str| -> OpError {
        let r = apply(&state, &owner, &key, &moves);
        assert_eq!(snapshot(&state, &owner), before, "{why}: nothing moved");
        r.expect_err(why)
    };

    // A stale generation (the scan was taken before some other change): conflict, no finger used.
    let mut stale = plan.clone();
    stale[1]["generation"] = json!(stale[1]["generation"].as_u64().unwrap() + 7);
    assert!(matches!(refused(stale, "stale"), OpError::Conflict { .. }));
    // The same entry twice.
    let twice = vec![plan[0].clone(), plan[0].clone()];
    assert!(matches!(refused(twice, "twice"), OpError::Malformed(_)));
    // An entry that is not there.
    let mut missing = plan.clone();
    missing[2]["entry"] = json!("e_not_there");
    assert!(matches!(refused(missing, "missing"), OpError::NotFound(_)));
    // The orphan, an unknown node, the same node.
    for (key_, value, why) in [
        ("to", json!("orphan"), "orphan"),
        ("to", json!("nowhere"), "unknown"),
    ] {
        let mut bad = plan.clone();
        bad[0][key_] = value;
        let e = refused(bad, why);
        assert!(
            matches!(e, OpError::Malformed(_) | OpError::NotFound(_)),
            "{why}: {e:?}"
        );
    }
    let mut same = plan.clone();
    same[0]["to"] = same[0]["node"].clone();
    assert!(matches!(refused(same, "same"), OpError::Malformed(_)));
    // Empty, and not a list.
    assert!(matches!(refused(vec![], "empty"), OpError::Malformed(_)));
    let r = call(
        &state,
        &owner,
        NOW,
        "vault.doctor_apply",
        json!({ "moves": "all" }),
    );
    assert!(matches!(r, Err(OpError::Malformed(_))), "{r:?}");
}

#[test]
fn a_name_an_earlier_step_brings_in_is_a_clash_found_before_anything_moves() {
    let (_v, state, owner, key) = planted();
    // `acme-web` and `global` each hold a `CLASH`; moving both into `acme` is refused at the second step.
    let a = create_entry(&state, &owner, "acme-web", "CLASH", "TEST_clash-a1");
    let b = create_entry(&state, &owner, GLOBAL_ID, "clash", "TEST_clash-b2");
    let before = snapshot(&state, &owner);
    let plan = vec![
        json!({ "node": "acme-web", "entry": a, "to": "acme",
                "generation": generation(&state, &owner, "acme-web") }),
        json!({ "node": GLOBAL_ID, "entry": b, "to": "acme",
                "generation": generation(&state, &owner, GLOBAL_ID) }),
    ];
    let r = apply(&state, &owner, &key, &plan);
    assert!(matches!(r, Err(OpError::EntryExists { .. })), "{r:?}");
    assert_eq!(snapshot(&state, &owner), before, "nothing moved");
}

#[test]
fn only_the_owners_login_with_its_factors_may_apply_a_plan() {
    let (_v, state, owner, key) = planted();
    let plan = plan_of(&state, &owner);
    let before = snapshot(&state, &owner);
    let all = vec![
        Capability::List,
        Capability::Read,
        Capability::Reveal,
        Capability::Create,
        Capability::Update,
        Capability::Admin,
    ];
    for (origin, token) in [
        (Origin::Agent, None),
        (Origin::HumanUi, Some("not-a-session".to_string())),
        (Origin::Cli, None),
    ] {
        let scope = BrokerScope {
            node_id: GLOBAL_ID.to_string(),
            capabilities: all.clone(),
            origin,
            token_id: token,
            bound_workdir: None,
        };
        let r = call(
            &state,
            &scope,
            NOW,
            "vault.doctor_apply",
            json!({ "moves": plan }),
        );
        assert!(
            matches!(r, Err(OpError::CapabilityNotHeld { .. })),
            "{origin:?}: {r:?}"
        );
    }
    // No proof: presence required.
    let r = call(
        &state,
        &owner,
        NOW,
        "vault.doctor_apply",
        json!({ "moves": plan }),
    );
    assert!(matches!(r, Err(OpError::PresenceRequired { .. })), "{r:?}");
    // A proof made for a different plan (one move dropped after signing): refused.
    let mut proved = with_proof(
        &state,
        &owner,
        &key,
        NOW,
        "vault.doctor_apply",
        json!({ "moves": plan }),
    );
    proved["moves"].as_array_mut().unwrap().pop();
    let r = call(&state, &owner, NOW, "vault.doctor_apply", proved);
    assert!(matches!(r, Err(OpError::PresenceFailed { .. })), "{r:?}");
    // A proof made for `entry.move` does not apply a plan.
    let mut wrong_op = with_proof(
        &state,
        &owner,
        &key,
        NOW,
        "entry.move",
        json!({ "moves": plan }),
    );
    wrong_op["moves"] = json!(plan);
    let r = call(&state, &owner, NOW, "vault.doctor_apply", wrong_op);
    assert!(matches!(r, Err(OpError::PresenceFailed { .. })), "{r:?}");
    // A locked destination.
    call(
        &state,
        &owner,
        NOW,
        "vault.node_lock",
        json!({ "node": "demo" }),
    )
    .expect("lock demo");
    let r = apply(&state, &owner, &key, &plan);
    assert!(matches!(r, Err(OpError::NodeLocked { .. })), "{r:?}");
    assert_eq!(
        snapshot_without(&state, &owner, "demo"),
        without(&before, "demo")
    );
}

fn snapshot_without(
    state: &BrokerState,
    owner: &BrokerScope,
    skip: &str,
) -> Vec<(String, Vec<String>, u64)> {
    [GLOBAL_ID, "acme", "acme-web", "acme-api", "demo"]
        .iter()
        .filter(|n| **n != skip)
        .map(|n| {
            (
                n.to_string(),
                names(state, owner, n),
                generation(state, owner, n),
            )
        })
        .collect()
}

fn without(snap: &[(String, Vec<String>, u64)], skip: &str) -> Vec<(String, Vec<String>, u64)> {
    snap.iter().filter(|s| s.0 != skip).cloned().collect()
}

#[test]
fn a_node_with_its_own_second_factor_asks_for_it_once_before_anything_moves() {
    let (_v, state, owner, key) = planted();
    let plan = plan_of(&state, &owner);
    // `demo` gets its own second factor; once its window has passed, the plan is refused before any move.
    let begin = call(
        &state,
        &owner,
        NOW,
        "node.gate_enroll_begin",
        json!({ "node": "demo" }),
    )
    .expect("begin");
    let uri = begin["otpauthUri"].as_str().unwrap();
    let b32 = uri
        .split("secret=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap();
    let totp = Totp::new_gate(decode_gate_secret_base32(b32).unwrap());
    call(
        &state,
        &owner,
        NOW,
        "node.gate_enroll_confirm",
        json!({ "node": "demo", "code": totp.code(NOW as u64) }),
    )
    .expect("confirm");
    let later = NOW + 3 * 3600;
    let before = snapshot(&state, &owner);
    let proved = with_proof(
        &state,
        &owner,
        &key,
        later,
        "vault.doctor_apply",
        json!({ "moves": plan }),
    );
    let r = call(&state, &owner, later, "vault.doctor_apply", proved);
    assert!(matches!(r, Err(OpError::TwoFactorRequired { .. })), "{r:?}");
    assert_eq!(snapshot(&state, &owner), before, "nothing moved");
}

#[test]
fn a_failure_after_the_first_move_stops_the_plan_and_says_what_was_applied() {
    let (v, state, owner, key) = planted();
    let plan = plan_of(&state, &owner);
    // A stray file at the second move's destination path: only the commit itself finds it.
    let stray = v.paths().entry_env(
        plan[1]["to"].as_str().unwrap(),
        plan[1]["entry"].as_str().unwrap(),
    );
    std::fs::create_dir_all(stray.parent().unwrap()).unwrap();
    std::fs::write(&stray, b"not an envelope").unwrap();

    let done = apply(&state, &owner, &key, &plan).expect("a report, not an error");
    assert_eq!(done["complete"], false);
    let applied = done["applied"].as_array().unwrap();
    assert_eq!(applied.len(), 1, "{done}");
    assert_eq!(applied[0]["entry"], plan[0]["entry"]);
    assert_eq!(done["stopped"]["index"], 1);
    assert_eq!(done["stopped"]["entry"], plan[1]["entry"]);
    assert_eq!(done["stopped"]["code"], "internal");
    assert_eq!(done["notApplied"], 2);
    // The first move stands; the second and third did not happen.
    let first_to = plan[0]["to"].as_str().unwrap();
    let first = plan[0]["entry"].as_str().unwrap();
    assert!(state.manifests.read().unwrap()[first_to]
        .entries
        .iter()
        .any(|e| e.id == first));
    let second_from = plan[1]["node"].as_str().unwrap();
    let second = plan[1]["entry"].as_str().unwrap();
    assert!(state.manifests.read().unwrap()[second_from]
        .entries
        .iter()
        .any(|e| e.id == second));
    let third_from = plan[2]["node"].as_str().unwrap();
    let third = plan[2]["entry"].as_str().unwrap();
    assert!(state.manifests.read().unwrap()[third_from]
        .entries
        .iter()
        .any(|e| e.id == third));

    // A failure at the very first move is the request's error, and nothing moved.
    std::fs::remove_file(&stray).unwrap();
    let rest: Vec<Value> = plan[1..]
        .iter()
        .map(|m| {
            let mut m = m.clone();
            let from = m["node"].as_str().unwrap().to_string();
            m["generation"] = json!(generation(&state, &owner, &from));
            m
        })
        .collect();
    let stray = v.paths().entry_env(
        rest[0]["to"].as_str().unwrap(),
        rest[0]["entry"].as_str().unwrap(),
    );
    std::fs::write(stray, b"not an envelope").unwrap();
    let r = apply(&state, &owner, &key, &rest);
    assert!(matches!(r, Err(OpError::Internal(_))), "{r:?}");
}
