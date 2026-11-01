//! `entry.rotate` / `entry.remove` / `entry.restore` (ADR-048) — the
//! carried-over gap named in Sessions 5/7/8's own BUILD_LOG entries.
//!
//! Fixture: Global, project "a" holding one entry ("a_SECRET"), unrelated
//! project "b" (capability/cross-node denial has its own coverage already
//! in `isolation.rs`; this file is about the three ops' own mechanics, not
//! re-proving I-1..I-25).

use std::sync::Arc;

use secrecy::SecretBox;
use serde_json::json;

use credmgr_brokerd::ops;
use credmgr_brokerd::protocol::OpError;
use credmgr_brokerd::scope::BrokerScope;
use credmgr_brokerd::state::BrokerState;
use credmgr_core::access::Origin;
use credmgr_core::inference::EntryType;
use credmgr_core::registry::{Capability, Node, NodeKind, NodePolicy, Registry, GLOBAL_ID};
use credmgr_keystore::software::SoftwareKeystore;
use credmgr_store::manifest::{Counts, ManifestBody, ManifestEntry, Sensitivity};

const NOW: i64 = 1_800_000_000;
const DAY: i64 = 24 * 60 * 60;

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
            modified: NOW,
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

/// ADR-078: the one raw value these single-value tests mean, read from an entry
/// envelope of either payload kind — a legacy version-1 value (what the fixture
/// seals), or the version-2 field document every write now produces. Asserts the
/// entry has exactly one field, so a test that expects a single value cannot
/// pass against a multi-field document by accident.
fn plain_value(bytes: &[u8], node_priv: &x25519_dalek::StaticSecret) -> String {
    use secrecy::ExposeSecret;
    let (kind, plaintext) =
        credmgr_core::envelope::open_any(bytes, node_priv, "a", "e_a1").expect("opens");
    let doc = credmgr_core::fields::read_payload(
        kind,
        plaintext.expose_secret(),
        EntryType::Other,
        Sensitivity::Medium,
    )
    .expect("decodes");
    assert_eq!(doc.fields.len(), 1, "a single-value entry has one field");
    doc.fields[0].value.clone()
}

fn scope_for(node_id: &str, caps: &[Capability]) -> BrokerScope {
    BrokerScope {
        node_id: node_id.to_string(),
        capabilities: caps.to_vec(),
        origin: Origin::Agent,
        token_id: None,
        bound_workdir: None,
    }
}

const FULL: &[Capability] = &[
    Capability::List,
    Capability::Read,
    Capability::Reveal,
    Capability::Create,
    Capability::Update,
];

// ---------------------------------------------------------------------------
// entry.rotate

#[test]
fn rotate_replaces_the_value_bumps_generation_and_sets_rotated_at() {
    let f = build_fixture();
    let scope = scope_for("a", FULL);

    let result = ops::dispatch(
        &f.state,
        &scope,
        NOW,
        "entry.rotate",
        &json!({ "node": "a", "entry": "e_a1", "value": "s3cr3t-v2", "generation": 1 }),
    )
    .expect("rotate");

    assert_eq!(result["generation"], 2);
    assert_eq!(result["rotatedAt"], NOW);

    let node_priv = f.state.hot_node_key("a").expect("unlocked");
    let bytes = credmgr_store::atomic::read(&f.state.paths.entry_env("a", "e_a1")).unwrap();
    assert_eq!(plain_value(&bytes, &node_priv), "s3cr3t-v2");
}

#[test]
fn rotate_retains_the_previous_ciphertext_as_history() {
    let f = build_fixture();
    let scope = scope_for("a", FULL);

    ops::dispatch(
        &f.state,
        &scope,
        NOW,
        "entry.rotate",
        &json!({ "node": "a", "entry": "e_a1", "value": "s3cr3t-v2", "generation": 1 }),
    )
    .expect("rotate");

    // Retained under the PRE-rotate generation (1) — the value that was
    // live as of that generation.
    let history_path = f.state.paths.entry_history_env("a", "e_a1", 1);
    let history_bytes = credmgr_store::atomic::read(&history_path).unwrap();
    let node_priv = f.state.hot_node_key("a").unwrap();
    assert_eq!(plain_value(&history_bytes, &node_priv), "s3cr3t-v1");
}

#[test]
fn rotate_with_a_stale_generation_is_a_conflict_not_a_silent_overwrite() {
    let f = build_fixture();
    let scope = scope_for("a", FULL);

    let err = ops::dispatch(
        &f.state,
        &scope,
        NOW,
        "entry.rotate",
        &json!({ "node": "a", "entry": "e_a1", "value": "s3cr3t-v2", "generation": 999 }),
    )
    .expect_err("stale generation must be refused");
    assert!(matches!(
        err,
        OpError::Conflict {
            expected_generation: 999,
            current_generation: 1,
            ..
        }
    ));
}

#[test]
fn rotate_without_update_capability_is_refused() {
    let f = build_fixture();
    let scope = scope_for("a", &[Capability::List, Capability::Read]);

    let err = ops::dispatch(
        &f.state,
        &scope,
        NOW,
        "entry.rotate",
        &json!({ "node": "a", "entry": "e_a1", "value": "v2", "generation": 1 }),
    )
    .expect_err("no Update capability at all must be refused");
    assert!(matches!(
        err,
        OpError::CapabilityNotHeld {
            capability: Capability::Update
        }
    ));
}

#[test]
fn rotate_on_a_locked_vault_is_vault_locked_not_a_generic_denial() {
    let f = build_fixture();
    f.state.lock();
    let scope = scope_for("a", FULL);

    let err = ops::dispatch(
        &f.state,
        &scope,
        NOW,
        "entry.rotate",
        &json!({ "node": "a", "entry": "e_a1", "value": "v2", "generation": 1 }),
    )
    .expect_err("a locked vault must refuse rotate");
    assert!(matches!(err, OpError::VaultLocked));
}

// ---------------------------------------------------------------------------
// entry.remove

#[test]
fn remove_takes_the_entry_out_of_the_live_manifest_and_archives_the_envelope() {
    let f = build_fixture();
    let scope = scope_for("a", FULL);

    let result = ops::dispatch(
        &f.state,
        &scope,
        NOW,
        "entry.remove",
        &json!({ "node": "a", "entry": "e_a1", "generation": 1 }),
    )
    .expect("remove");
    assert_eq!(result["removed"], true);
    assert_eq!(result["generation"], 2);

    let list = ops::dispatch(&f.state, &scope, NOW, "entry.list", &json!({ "node": "a" }))
        .expect("entry.list");
    assert!(list["ids"].as_array().unwrap().is_empty());

    assert!(!f.state.paths.entry_env("a", "e_a1").exists());
    assert!(f.state.paths.removed_entry_env("a", "e_a1").exists());
}

#[test]
fn remove_with_a_stale_generation_is_a_conflict() {
    let f = build_fixture();
    let scope = scope_for("a", FULL);

    let err = ops::dispatch(
        &f.state,
        &scope,
        NOW,
        "entry.remove",
        &json!({ "node": "a", "entry": "e_a1", "generation": 0 }),
    )
    .expect_err("stale generation must be refused");
    assert!(matches!(err, OpError::Conflict { .. }));
    // Refused before touching anything.
    assert!(f.state.paths.entry_env("a", "e_a1").exists());
}

#[test]
fn remove_an_unknown_entry_is_not_found() {
    let f = build_fixture();
    let scope = scope_for("a", FULL);

    let err = ops::dispatch(
        &f.state,
        &scope,
        NOW,
        "entry.remove",
        &json!({ "node": "a", "entry": "e_nope", "generation": 1 }),
    )
    .expect_err("no such entry");
    assert!(matches!(err, OpError::NotFound(_)));
}

#[test]
fn remove_on_a_locked_vault_is_vault_locked() {
    let f = build_fixture();
    f.state.lock();
    let scope = scope_for("a", FULL);

    let err = ops::dispatch(
        &f.state,
        &scope,
        NOW,
        "entry.remove",
        &json!({ "node": "a", "entry": "e_a1", "generation": 1 }),
    )
    .expect_err("a locked vault must refuse remove");
    assert!(matches!(err, OpError::VaultLocked));
}

// ---------------------------------------------------------------------------
// entry.restore

fn remove_e_a1(f: &Fixture) {
    ops::dispatch(
        &f.state,
        &scope_for("a", FULL),
        NOW,
        "entry.remove",
        &json!({ "node": "a", "entry": "e_a1", "generation": 1 }),
    )
    .expect("remove");
}

#[test]
fn restore_within_the_window_puts_the_entry_back_under_its_original_name_and_ref() {
    let f = build_fixture();
    remove_e_a1(&f);
    let scope = scope_for("a", FULL);

    let result = ops::dispatch(
        &f.state,
        &scope,
        NOW + DAY,
        "entry.restore",
        &json!({ "node": "a", "entry": "e_a1", "generation": 2 }),
    )
    .expect("restore");
    assert_eq!(result["restoredName"], "a_SECRET");

    let list = ops::dispatch(&f.state, &scope, NOW, "entry.list", &json!({ "node": "a" }))
        .expect("entry.list");
    assert_eq!(list["ids"].as_array().unwrap(), &vec![json!("e_a1")]);
    assert_eq!(list["names"].as_array().unwrap(), &vec![json!("a_SECRET")]);

    // The exact original ciphertext came back, byte for byte.
    let node_priv = f.state.hot_node_key("a").unwrap();
    let bytes = credmgr_store::atomic::read(&f.state.paths.entry_env("a", "e_a1")).unwrap();
    assert_eq!(plain_value(&bytes, &node_priv), "s3cr3t-v1");
}

#[test]
fn restore_replace_mode_refuses_when_a_live_entry_now_holds_the_name() {
    let f = build_fixture();
    remove_e_a1(&f);
    let scope = scope_for("a", FULL);

    // A DIFFERENT secret is created under the freed name before the undo.
    ops::dispatch(
        &f.state,
        &scope,
        NOW,
        "entry.create",
        &json!({ "node": "a", "name": "a_SECRET", "value": "a-new-different-secret" }),
    )
    .expect("create");

    let err = ops::dispatch(
        &f.state,
        &scope,
        NOW,
        "entry.restore",
        &json!({ "node": "a", "entry": "e_a1", "generation": 3, "mode": "replace" }),
    )
    .expect_err("replace must refuse rather than silently overwrite the new secret");
    assert!(matches!(err, OpError::EntryExists { ref name, .. } if name == "a_SECRET"));

    // Neither copy was touched by the refused attempt.
    assert!(f.state.paths.removed_entry_env("a", "e_a1").exists());
    let list = ops::dispatch(&f.state, &scope, NOW, "entry.list", &json!({ "node": "a" }))
        .expect("entry.list");
    assert_eq!(list["names"].as_array().unwrap(), &vec![json!("a_SECRET")]);
}

#[test]
fn restore_keep_both_mode_renames_around_the_collision() {
    let f = build_fixture();
    remove_e_a1(&f);
    let scope = scope_for("a", FULL);

    ops::dispatch(
        &f.state,
        &scope,
        NOW,
        "entry.create",
        &json!({ "node": "a", "name": "a_SECRET", "value": "a-new-different-secret" }),
    )
    .expect("create");

    let result = ops::dispatch(
        &f.state,
        &scope,
        NOW,
        "entry.restore",
        &json!({ "node": "a", "entry": "e_a1", "generation": 3, "mode": "keep-both" }),
    )
    .expect("keep-both must succeed despite the collision");
    assert_eq!(result["restoredName"], "a_SECRET old");

    let list = ops::dispatch(&f.state, &scope, NOW, "entry.list", &json!({ "node": "a" }))
        .expect("entry.list");
    let names: Vec<&str> = list["names"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n.as_str().unwrap())
        .collect();
    assert!(names.contains(&"a_SECRET"), "the newer entry is untouched");
    assert!(
        names.contains(&"a_SECRET old"),
        "the restored one is renamed"
    );
}

#[test]
fn restore_past_the_7_day_window_is_refused_and_final() {
    let f = build_fixture();
    remove_e_a1(&f);
    let scope = scope_for("a", FULL);

    let err = ops::dispatch(
        &f.state,
        &scope,
        NOW + 8 * DAY,
        "entry.restore",
        &json!({ "node": "a", "entry": "e_a1", "generation": 2 }),
    )
    .expect_err("past the window, restore is refused");
    assert!(matches!(
        err,
        OpError::EntryRemovalExpired { ref node, ref entry }
            if node == "a" && entry == "e_a1"
    ));
}

#[test]
fn restore_an_entry_that_was_never_removed_is_not_found() {
    let f = build_fixture();
    let scope = scope_for("a", FULL);

    let err = ops::dispatch(
        &f.state,
        &scope,
        NOW,
        "entry.restore",
        &json!({ "node": "a", "entry": "e_a1", "generation": 1 }),
    )
    .expect_err("e_a1 was never removed");
    assert!(matches!(err, OpError::NotFound(_)));
}

#[test]
fn restore_without_update_capability_is_refused() {
    let f = build_fixture();
    remove_e_a1(&f);
    let scope = scope_for("a", &[Capability::List, Capability::Read]);

    let err = ops::dispatch(
        &f.state,
        &scope,
        NOW,
        "entry.restore",
        &json!({ "node": "a", "entry": "e_a1", "generation": 2 }),
    )
    .expect_err("no Update capability at all must be refused");
    assert!(matches!(
        err,
        OpError::CapabilityNotHeld {
            capability: Capability::Update
        }
    ));
}
