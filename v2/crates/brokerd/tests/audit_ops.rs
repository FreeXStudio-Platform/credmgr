//! `audit.tail`/`audit.get` — `10_API_AND_MCP.md §1` / `18_ENDPOINT_INDEX.md
//! §1.6`. These are the read half of a gap this session also closed on the
//! write side: before this session, `handle_request` only ever appended an
//! audit record for the one `TokenWorkdirMismatch` anomaly path (I-12) —
//! nothing recorded an ordinary allow or deny, despite `10 §1`'s own
//! invariant list promising "every decision, allow or deny, appends one
//! audit record." `server::record_decision` is that generic, op-agnostic
//! write; these tests exercise it indirectly by going through
//! `server::handle_request` (not `ops::dispatch` directly, unlike most of
//! this workspace's other op tests) so the audit trail these assertions
//! read back is the one a real request actually produced.
//!
//! Fixture: Global; project "a" and unrelated project "b" (depth-1 siblings,
//! isolated by the model's own default rule — same shape `entry_lifecycle.rs`
//! already uses).

use std::sync::Arc;

use secrecy::SecretBox;
use serde_json::json;

use credmgr_brokerd::ops;
use credmgr_brokerd::peer::PeerInfo;
use credmgr_brokerd::protocol::{OpError, Request};
use credmgr_brokerd::scope::BrokerScope;
use credmgr_brokerd::server;
use credmgr_brokerd::state::BrokerState;
use credmgr_core::access::Origin;
use credmgr_core::registry::{Capability, Node, NodeKind, NodePolicy, Registry, GLOBAL_ID};
use credmgr_keystore::software::SoftwareKeystore;

struct Fixture {
    state: Arc<BrokerState>,
    _dir: tempfile::TempDir,
}

fn depth1(id: &str) -> Node {
    Node {
        id: id.to_string(),
        label: id.to_string(),
        kind: NodeKind::Project,
        depth: 1,
        parent_id: Some(GLOBAL_ID.to_string()),
        workdirs: Vec::new(),
        policy: NodePolicy::default(),
    }
}

fn build_fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let keystore = Box::new(SoftwareKeystore::new(
        SecretBox::new(Box::new("correct horse battery staple".to_string())),
        dir.path().join("keystore-state"),
    ));
    let paths = credmgr_store::paths::VaultPaths::new(dir.path().join("vault"));
    let state = Arc::new(BrokerState::new(keystore, paths));

    let root_key = SecretBox::new(Box::new([7u8; 32]));
    state.seed_root_key(&root_key);

    let mut reg = Registry::new();
    reg.nodes.insert(GLOBAL_ID.to_string(), Node::global());
    reg.nodes.insert("a".to_string(), depth1("a"));
    reg.nodes.insert("b".to_string(), depth1("b"));
    state.set_registry(reg);
    state.seed_node_key(&root_key, "a");
    state.seed_node_key(&root_key, "b");

    state
        .unlock(0)
        .expect("fixture keystore's own passphrase unlocks its own wrap");

    Fixture { state, _dir: dir }
}

fn peer() -> PeerInfo {
    PeerInfo {
        uid: 501,
        pid: 1,
        cwd: None,
    }
}

fn request(op: &str, token: &str, params: serde_json::Value) -> Request {
    Request {
        id: "r".to_string(),
        op: op.to_string(),
        token: Some(token.to_string()),
        params,
    }
}

fn admin_scope() -> BrokerScope {
    BrokerScope {
        node_id: GLOBAL_ID.to_string(),
        capabilities: vec![Capability::List, Capability::Admin],
        origin: Origin::HumanUi,
        token_id: None,
        bound_workdir: None,
    }
}

/// Global does not read its own descendants by default (`06_ACCESS_GRAPH.md`
/// R3 is direction-specific — every node reads Global, not the reverse; the
/// same finding ADR-047 already made for `graph.snapshot`), so a reader
/// that needs to see node "a"'s own records back must be scoped to "a"
/// itself, not to Global — `admin_scope()` above is for `audit.get`'s
/// capability check only, which does not target a node at all.
fn a_reader_scope() -> BrokerScope {
    BrokerScope {
        node_id: "a".to_string(),
        capabilities: vec![Capability::List],
        origin: Origin::HumanUi,
        token_id: None,
        bound_workdir: None,
    }
}

// ---------------------------------------------------------------------------
// audit.tail

#[test]
fn every_dispatched_request_appends_one_record_visible_via_tail() {
    let f = build_fixture();
    let token = f
        .state
        .tokens
        .issue("a", vec![Capability::List], Origin::HumanUi, None);

    let (result, audit_id) = server::handle_request(
        &f.state,
        &peer(),
        &request("entry.list", &token.id, json!({ "node": "a" })),
    );
    assert!(result.is_ok());
    let audit_id = audit_id.expect("a decision on an unlocked vault must produce an audit id");

    let response = ops::dispatch(
        &f.state,
        &a_reader_scope(),
        0,
        "audit.tail",
        &json!({ "limit": 10 }),
    )
    .expect("audit.tail");
    let records = response["records"].as_array().expect("records array");
    assert!(
        records.iter().any(|r| r["id"] == audit_id),
        "the id handle_request returned must actually be in the log: {records:?}"
    );
}

#[test]
fn tail_returns_newest_first() {
    let f = build_fixture();
    let token = f
        .state
        .tokens
        .issue("a", vec![Capability::List], Origin::HumanUi, None);

    let (_, first_id) = server::handle_request(
        &f.state,
        &peer(),
        &request("entry.list", &token.id, json!({ "node": "a" })),
    );
    let (_, second_id) =
        server::handle_request(&f.state, &peer(), &request("whoami", &token.id, json!({})));
    let first_id = first_id.expect("first request must be audited");
    let second_id = second_id.expect("second request must be audited");
    assert_ne!(first_id, second_id);

    let response = ops::dispatch(
        &f.state,
        &a_reader_scope(),
        0,
        "audit.tail",
        &json!({ "limit": 2 }),
    )
    .expect("audit.tail");
    let records = response["records"].as_array().expect("records array");
    assert_eq!(records.len(), 2);
    assert_eq!(
        records[0]["id"], second_id,
        "the most recent call comes first"
    );
    assert_eq!(records[1]["id"], first_id);
}

#[test]
fn tail_is_redacted_for_agent_origin_and_full_for_a_human_origin() {
    let f = build_fixture();
    let agent_token = f
        .state
        .tokens
        .issue("a", vec![Capability::List], Origin::Agent, None);

    let _ = server::handle_request(
        &f.state,
        &peer(),
        &request("entry.list", &agent_token.id, json!({ "node": "a" })),
    );

    let agent_response = ops::dispatch(
        &f.state,
        &BrokerScope {
            node_id: "a".to_string(),
            capabilities: vec![Capability::List],
            origin: Origin::Agent,
            token_id: None,
            bound_workdir: None,
        },
        0,
        "audit.tail",
        &json!({ "limit": 1 }),
    )
    .expect("audit.tail");
    let redacted = &agent_response["records"].as_array().expect("records")[0];
    let redacted_keys: std::collections::BTreeSet<&str> = redacted
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        redacted_keys,
        ["id", "timestamp", "actor", "action"].into_iter().collect(),
        "an agent origin must get exactly the four documented fields, nothing else: {redacted:?}"
    );

    let human_response = ops::dispatch(
        &f.state,
        &BrokerScope {
            node_id: "a".to_string(),
            capabilities: vec![Capability::List],
            origin: Origin::HumanUi,
            token_id: None,
            bound_workdir: None,
        },
        0,
        "audit.tail",
        &json!({ "limit": 1 }),
    )
    .expect("audit.tail");
    let full = &human_response["records"].as_array().expect("records")[0];
    assert_eq!(full["node"], "a");
    assert_eq!(full["decision"], "allow");
    assert!(
        full.get("detail").is_some(),
        "a non-agent origin gets the full record, including detail: {full:?}"
    );
}

#[test]
fn tail_never_shows_a_record_for_a_node_outside_the_callers_reachable_set() {
    let f = build_fixture();
    let token_a = f
        .state
        .tokens
        .issue("a", vec![Capability::List], Origin::HumanUi, None);
    let token_b = f
        .state
        .tokens
        .issue("b", vec![Capability::List], Origin::HumanUi, None);

    let _ = server::handle_request(
        &f.state,
        &peer(),
        &request("entry.list", &token_a.id, json!({ "node": "a" })),
    );
    let _ = server::handle_request(
        &f.state,
        &peer(),
        &request("entry.list", &token_b.id, json!({ "node": "b" })),
    );

    let scoped_to_a = BrokerScope {
        node_id: "a".to_string(),
        capabilities: vec![Capability::List],
        origin: Origin::HumanUi,
        token_id: None,
        bound_workdir: None,
    };
    let response = ops::dispatch(
        &f.state,
        &scoped_to_a,
        0,
        "audit.tail",
        &json!({ "limit": 50 }),
    )
    .expect("audit.tail");
    let records = response["records"].as_array().expect("records");
    assert!(
        records.iter().any(|r| r["node"] == "a"),
        "must see its own node's record: {records:?}"
    );
    assert!(
        !records.iter().any(|r| r["node"] == "b"),
        "depth-1 siblings do not share by default (R6 needs depth 2) — 'b' must never appear: {records:?}"
    );
}

#[test]
fn tail_works_while_the_vault_is_locked() {
    let f = build_fixture();
    let token = f
        .state
        .tokens
        .issue("a", vec![Capability::List], Origin::HumanUi, None);
    let (_, id) = server::handle_request(
        &f.state,
        &peer(),
        &request("entry.list", &token.id, json!({ "node": "a" })),
    );
    let id = id.expect("audited while unlocked");

    f.state.lock();
    assert!(f.state.is_locked());

    let response = ops::dispatch(
        &f.state,
        &a_reader_scope(),
        0,
        "audit.tail",
        &json!({ "limit": 10 }),
    )
    .expect("audit.tail must not need a root key to read — plaintext, like registry.json");
    let records = response["records"].as_array().expect("records");
    assert!(records.iter().any(|r| r["id"] == id));
}

#[test]
fn tail_without_list_capability_is_refused() {
    let f = build_fixture();
    let scope = BrokerScope {
        node_id: "a".to_string(),
        capabilities: vec![],
        origin: Origin::HumanUi,
        token_id: None,
        bound_workdir: None,
    };
    let err = ops::dispatch(&f.state, &scope, 0, "audit.tail", &json!({})).unwrap_err();
    assert!(matches!(
        err,
        OpError::CapabilityNotHeld {
            capability: Capability::List
        }
    ));
}

// ---------------------------------------------------------------------------
// audit.get

#[test]
fn audit_get_refuses_with_presence_required_even_for_a_real_id_and_admin_capability() {
    let f = build_fixture();
    let token = f
        .state
        .tokens
        .issue("a", vec![Capability::List], Origin::HumanUi, None);
    let (_, id) = server::handle_request(
        &f.state,
        &peer(),
        &request("entry.list", &token.id, json!({ "node": "a" })),
    );
    let id = id.expect("a real audited record");

    let err = ops::dispatch(
        &f.state,
        &admin_scope(),
        0,
        "audit.get",
        &json!({ "id": id }),
    )
    .unwrap_err();
    assert!(
        matches!(err, OpError::PresenceRequired { .. }),
        "no Phase 3/4/5 transport can attest presence yet (ADR-046/047's named gap): got {err:?}"
    );
}

#[test]
fn audit_get_without_admin_capability_is_capability_not_held_before_it_ever_reaches_presence() {
    let f = build_fixture();
    let scope = BrokerScope {
        node_id: "a".to_string(),
        capabilities: vec![Capability::List],
        origin: Origin::HumanUi,
        token_id: None,
        bound_workdir: None,
    };
    let err = ops::dispatch(
        &f.state,
        &scope,
        0,
        "audit.get",
        &json!({ "id": "a_anything" }),
    )
    .unwrap_err();
    assert!(matches!(
        err,
        OpError::CapabilityNotHeld {
            capability: Capability::Admin
        }
    ));
}
