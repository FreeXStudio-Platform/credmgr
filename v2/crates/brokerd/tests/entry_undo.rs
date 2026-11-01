//! `entry.undo` (ADR-055) — undoing a rotate and undoing a remove, both
//! addressed by audit id, both forward/audited actions that never rewrite
//! the audit log itself.
//!
//! Fixture: Global, project "a" holding one entry ("a_SECRET"), unrelated
//! project "b" — the same shape `entry_lifecycle.rs` (ADR-048) already
//! uses. Exercises `server::handle_request`, not `ops::dispatch` directly,
//! for every call whose audit id this file needs — `ops::dispatch` alone
//! never writes an audit record (`server::record_decision` is the only
//! call site; `audit_ops.rs`'s own fixture note says so).

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
use credmgr_core::inference::EntryType;
use credmgr_core::registry::{Capability, Node, NodeKind, NodePolicy, Registry, GLOBAL_ID};
use credmgr_keystore::software::SoftwareKeystore;
use credmgr_store::manifest::{Counts, ManifestBody, ManifestEntry, Sensitivity};

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

fn one_entry_manifest(entry_id: &str, name: &str) -> ManifestBody {
    ManifestBody {
        node_id: "a".to_string(),
        entries: vec![ManifestEntry {
            id: entry_id.to_string(),
            name: name.to_string(),
            r#ref: 1,
            entry_type: EntryType::Other,
            sensitivity: Sensitivity::Medium,
            field_count: 1,
            sha256: "0".repeat(64),
            modified: 1_700_000_000,
            expires_at: None,
            rotated_at: None,
            has_totp: false,
        }],
        counts: Counts {
            entries: 1,
            totp: 0,
        },
        notes_sha256: None,
        generation: 1,
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

    let node_pub = state.seed_node_key(&root_key, "a");
    state.seed_node_key(&root_key, "b");

    let sealed = credmgr_core::envelope::seal(b"s3cr3t-v1", &node_pub, "a", "e_a1")
        .expect("seal cannot fail for a small fixed payload");
    credmgr_store::atomic::write(&state.paths.entry_env("a", "e_a1"), &sealed)
        .expect("writing the fixture envelope");
    state.set_manifest("a", one_entry_manifest("e_a1", "a_SECRET"));

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

fn full_token(f: &Fixture, node: &str) -> String {
    f.state
        .tokens
        .issue(
            node,
            vec![
                Capability::List,
                Capability::Read,
                Capability::Reveal,
                Capability::Create,
                Capability::Update,
                Capability::Admin,
            ],
            Origin::HumanUi,
            None,
        )
        .id
}

fn reveal(f: &Fixture, token: &str, node: &str, entry: &str) -> String {
    let (result, _) = server::handle_request(
        &f.state,
        &peer(),
        &request(
            "entry.reveal",
            token,
            json!({ "node": node, "entry": entry }),
        ),
    );
    result.expect("entry.reveal")["value"]
        .as_str()
        .unwrap()
        .to_string()
}

fn current_generation(f: &Fixture, node: &str) -> u64 {
    f.state
        .manifests
        .read()
        .unwrap()
        .get(node)
        .map(|b| b.generation)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// undo a rotate

#[test]
fn undo_a_rotate_restores_the_exact_prior_value_and_the_original_record_survives() {
    let f = build_fixture();
    let token = full_token(&f, "a");

    let gen0 = current_generation(&f, "a");
    let (rotate_result, rotate_audit_id) = server::handle_request(
        &f.state,
        &peer(),
        &request(
            "entry.rotate",
            &token,
            json!({ "node": "a", "entry": "e_a1", "value": "s3cr3t-v2", "generation": gen0 }),
        ),
    );
    rotate_result.expect("rotate must succeed");
    let rotate_audit_id = rotate_audit_id.expect("a successful rotate must be audited");
    assert_eq!(reveal(&f, &token, "a", "e_a1"), "s3cr3t-v2");

    let gen1 = current_generation(&f, "a");
    let (undo_result, undo_audit_id) = server::handle_request(
        &f.state,
        &peer(),
        &request(
            "entry.undo",
            &token,
            json!({ "node": "a", "id": rotate_audit_id, "generation": gen1 }),
        ),
    );
    let undo_value = undo_result.expect("undo must succeed");
    assert_eq!(undo_value["undoneToGeneration"], gen0);
    assert!(
        undo_audit_id.is_some(),
        "the undo itself is a new audited action"
    );

    assert_eq!(
        reveal(&f, &token, "a", "e_a1"),
        "s3cr3t-v1",
        "the exact prior plaintext must come back"
    );

    // The original rotate record is untouched — undo appends, never erases.
    let tail = ops::dispatch(
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
        &json!({ "limit": 10 }),
    )
    .expect("audit.tail");
    let records = tail["records"].as_array().unwrap();
    assert!(
        records.iter().any(|r| r["id"] == rotate_audit_id
            && r["action"] == "entry.rotate"
            && r["decision"] == "allow"),
        "the original entry.rotate record must still be present, unmodified: {records:?}"
    );
}

#[test]
fn undoing_an_undo_of_a_rotate_is_symmetric() {
    let f = build_fixture();
    let token = full_token(&f, "a");

    let gen0 = current_generation(&f, "a");
    let (_, rotate_id) = server::handle_request(
        &f.state,
        &peer(),
        &request(
            "entry.rotate",
            &token,
            json!({ "node": "a", "entry": "e_a1", "value": "s3cr3t-v2", "generation": gen0 }),
        ),
    );
    let rotate_id = rotate_id.unwrap();

    let gen1 = current_generation(&f, "a");
    let (undo_response, _generic_undo_id) = server::handle_request(
        &f.state,
        &peer(),
        &request(
            "entry.undo",
            &token,
            json!({ "node": "a", "id": rotate_id, "generation": gen1 }),
        ),
    );
    let undo_response = undo_response.expect("undo must succeed");
    assert_eq!(reveal(&f, &token, "a", "e_a1"), "s3cr3t-v1");

    // `undo_rotate` records its own `entry.rotate`-shaped audit line
    // (mechanically, undoing a rotate *is* a rotate) — that is the id a
    // *second* `entry.undo` must resolve, not the generic "entry.undo"
    // line `record_decision` wrote for the outer request. Found by the
    // generation the undo itself produced, which the response names.
    let gen_after_undo = undo_response["generation"].as_u64().unwrap();
    let tail = ops::dispatch(
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
        &json!({ "limit": 20 }),
    )
    .unwrap();
    let rotate_shaped_undo_id = tail["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["action"] == "entry.rotate" && r["generation"] == gen_after_undo)
        .expect("undo_rotate must have recorded its own entry.rotate-shaped audit line")["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Undo the undo — must come back to v2.
    let gen2 = current_generation(&f, "a");
    let (redo_result, _) = server::handle_request(
        &f.state,
        &peer(),
        &request(
            "entry.undo",
            &token,
            json!({ "node": "a", "id": rotate_shaped_undo_id, "generation": gen2 }),
        ),
    );
    redo_result.expect("undoing an undo must itself work");
    assert_eq!(reveal(&f, &token, "a", "e_a1"), "s3cr3t-v2");
}

// ---------------------------------------------------------------------------
// undo a remove

#[test]
fn undo_a_remove_restores_the_entry() {
    let f = build_fixture();
    let token = full_token(&f, "a");

    let gen0 = current_generation(&f, "a");
    let (remove_result, remove_id) = server::handle_request(
        &f.state,
        &peer(),
        &request(
            "entry.remove",
            &token,
            json!({ "node": "a", "entry": "e_a1", "generation": gen0 }),
        ),
    );
    remove_result.expect("remove must succeed");
    let remove_id = remove_id.expect("a successful remove must be audited");

    let listed = ops::dispatch(
        &f.state,
        &BrokerScope {
            node_id: "a".to_string(),
            capabilities: vec![Capability::List],
            origin: Origin::HumanUi,
            token_id: None,
            bound_workdir: None,
        },
        0,
        "entry.list",
        &json!({ "node": "a" }),
    )
    .unwrap();
    assert!(listed["ids"].as_array().unwrap().is_empty());

    let gen1 = current_generation(&f, "a");
    let (undo_result, _) = server::handle_request(
        &f.state,
        &peer(),
        &request(
            "entry.undo",
            &token,
            json!({ "node": "a", "id": remove_id, "generation": gen1 }),
        ),
    );
    let value = undo_result.expect("undo of a remove must succeed within the window");
    assert_eq!(value["restoredName"], "a_SECRET");
    assert_eq!(reveal(&f, &token, "a", "e_a1"), "s3cr3t-v1");
}

#[test]
fn undo_a_remove_with_keep_both_when_the_name_was_reclaimed() {
    let f = build_fixture();
    let token = full_token(&f, "a");

    let gen0 = current_generation(&f, "a");
    let (_, remove_id) = server::handle_request(
        &f.state,
        &peer(),
        &request(
            "entry.remove",
            &token,
            json!({ "node": "a", "entry": "e_a1", "generation": gen0 }),
        ),
    );
    let remove_id = remove_id.unwrap();

    let gen1 = current_generation(&f, "a");
    let (create_result, _) = server::handle_request(
        &f.state,
        &peer(),
        &request(
            "entry.create",
            &token,
            json!({ "node": "a", "name": "a_SECRET", "value": "brand-new" }),
        ),
    );
    create_result.expect("a new entry may reclaim the removed name");

    let gen2 = current_generation(&f, "a");
    let (undo_result, _) = server::handle_request(
        &f.state,
        &peer(),
        &request(
            "entry.undo",
            &token,
            json!({ "node": "a", "id": remove_id, "generation": gen2, "mode": "keep-both" }),
        ),
    );
    let value = undo_result.expect("keep-both must not refuse on a reclaimed name");
    assert_eq!(value["restoredName"], "a_SECRET old");
    let _ = gen1;
}

// ---------------------------------------------------------------------------
// refusals

#[test]
fn undo_naming_the_wrong_node_is_not_found() {
    let f = build_fixture();
    let token = full_token(&f, "a");

    let gen0 = current_generation(&f, "a");
    let (_, rotate_id) = server::handle_request(
        &f.state,
        &peer(),
        &request(
            "entry.rotate",
            &token,
            json!({ "node": "a", "entry": "e_a1", "value": "s3cr3t-v2", "generation": gen0 }),
        ),
    );
    let rotate_id = rotate_id.unwrap();

    let token_b = full_token(&f, "b");
    let (undo_result, _) = server::handle_request(
        &f.state,
        &peer(),
        &request(
            "entry.undo",
            &token_b,
            json!({ "node": "b", "id": rotate_id, "generation": 0 }),
        ),
    );
    let err = undo_result.unwrap_err();
    assert!(
        matches!(err, OpError::NotFound(_)),
        "a record for a different node must read as not_found, never a hint: {err:?}"
    );
}

#[test]
fn undo_of_a_denied_action_is_not_undoable() {
    let f = build_fixture();
    let full = full_token(&f, "a");
    let read_only = f
        .state
        .tokens
        .issue(
            "a",
            vec![Capability::List, Capability::Read],
            Origin::HumanUi,
            None,
        )
        .id;

    // A denied rotate attempt (no Update capability) still gets audited.
    let (denied_result, denied_id) = server::handle_request(
        &f.state,
        &peer(),
        &request(
            "entry.rotate",
            &read_only,
            json!({ "node": "a", "entry": "e_a1", "value": "x", "generation": 0 }),
        ),
    );
    assert!(denied_result.is_err());
    let denied_id = denied_id.expect("a denial is still a decision and still gets audited");

    let gen0 = current_generation(&f, "a");
    let (undo_result, _) = server::handle_request(
        &f.state,
        &peer(),
        &request(
            "entry.undo",
            &full,
            json!({ "node": "a", "id": denied_id, "generation": gen0 }),
        ),
    );
    let err = undo_result.unwrap_err();
    assert!(
        matches!(err, OpError::NotUndoable { .. }),
        "nothing happened, so there is nothing to undo: {err:?}"
    );
}

#[test]
fn undo_of_a_create_is_not_undoable() {
    let f = build_fixture();
    let token = full_token(&f, "a");

    let (create_result, create_id) = server::handle_request(
        &f.state,
        &peer(),
        &request(
            "entry.create",
            &token,
            json!({ "node": "a", "name": "another", "value": "v" }),
        ),
    );
    create_result.expect("create must succeed");
    let create_id = create_id.unwrap();

    let gen0 = current_generation(&f, "a");
    let (undo_result, _) = server::handle_request(
        &f.state,
        &peer(),
        &request(
            "entry.undo",
            &token,
            json!({ "node": "a", "id": create_id, "generation": gen0 }),
        ),
    );
    let err = undo_result.unwrap_err();
    assert!(matches!(err, OpError::NotUndoable { .. }));
}

#[test]
fn undo_of_a_bogus_id_is_not_found() {
    let f = build_fixture();
    let token = full_token(&f, "a");
    let gen0 = current_generation(&f, "a");
    let err = ops::dispatch(
        &f.state,
        &BrokerScope {
            node_id: "a".to_string(),
            capabilities: vec![Capability::Update],
            origin: Origin::HumanUi,
            token_id: Some(token),
            bound_workdir: None,
        },
        0,
        "entry.undo",
        &json!({ "node": "a", "id": "a_does_not_exist", "generation": gen0 }),
    )
    .unwrap_err();
    assert!(matches!(err, OpError::NotFound(_)));
}

#[test]
fn undo_without_update_capability_is_refused() {
    let f = build_fixture();
    let err = ops::dispatch(
        &f.state,
        &BrokerScope {
            node_id: "a".to_string(),
            capabilities: vec![Capability::List],
            origin: Origin::HumanUi,
            token_id: None,
            bound_workdir: None,
        },
        0,
        "entry.undo",
        &json!({ "node": "a", "id": "a_whatever", "generation": 0 }),
    )
    .unwrap_err();
    assert!(matches!(
        err,
        OpError::CapabilityNotHeld {
            capability: Capability::Update
        }
    ));
}

#[test]
fn undo_while_vault_locked_is_refused() {
    let f = build_fixture();
    let token = full_token(&f, "a");

    let gen0 = current_generation(&f, "a");
    let (_, rotate_id) = server::handle_request(
        &f.state,
        &peer(),
        &request(
            "entry.rotate",
            &token,
            json!({ "node": "a", "entry": "e_a1", "value": "s3cr3t-v2", "generation": gen0 }),
        ),
    );
    let rotate_id = rotate_id.unwrap();

    f.state.lock();
    let gen1 = current_generation(&f, "a");
    let err = ops::dispatch(
        &f.state,
        &BrokerScope {
            node_id: "a".to_string(),
            capabilities: vec![Capability::Update],
            origin: Origin::HumanUi,
            token_id: None,
            bound_workdir: None,
        },
        0,
        "entry.undo",
        &json!({ "node": "a", "id": rotate_id, "generation": gen1 }),
    )
    .unwrap_err();
    assert!(matches!(err, OpError::VaultLocked));
}
