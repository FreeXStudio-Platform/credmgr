//! `maintenance.verify|doctor|backup` — ADR-054, end to end via
//! `ops::dispatch`. Real on-disk vault state (registry+manifest+envelope
//! files via `credmgr_store::registry_file::save`/`manifest::save`/
//! `atomic::write`, then loaded with `BrokerState::verify_and_load_vault`),
//! not `state.set_registry`/`set_manifest`'s in-memory shortcut — the whole
//! point of `maintenance.verify`/`doctor` is checking what's durably
//! persisted, so a fixture that only ever existed in memory would prove
//! nothing about them. Mirrors `crates/brokerd/tests/isolation.rs`'s I-19/
//! I-20 "real on-disk vault" fixture pattern.

use std::sync::Arc;

use secrecy::SecretBox;
use serde_json::json;

use credmgr_brokerd::ops;
use credmgr_brokerd::protocol::OpError;
use credmgr_brokerd::scope::BrokerScope;
use credmgr_brokerd::state::BrokerState;
use credmgr_core::access::Origin;
use credmgr_core::inference::EntryType;
use credmgr_core::registry::{Capability, Node, NodeKind, NodePolicy, GLOBAL_ID};
use credmgr_keystore::software::SoftwareKeystore;
use credmgr_store::atomic;
use credmgr_store::manifest::{Counts, ManifestBody, ManifestEntry, Sensitivity};
use credmgr_store::paths::VaultPaths;
use credmgr_store::registry_file::{GateDoc, NodeDoc, RegistryDocument};

const NOW: i64 = 1_800_000_000;
/// SHA-256 of the `b"sealed-envelope-bytes"` `build_fixture` writes for `e_a1`.
const ENVELOPE_SHA256: &str = "fb12e38bc1ed014ee888392a2f5d59b3d594703a987d9c5fb1fef09fa102a739";
const ROOT_KEY: [u8; 32] = [9u8; 32];

struct Fixture {
    state: Arc<BrokerState>,
    paths: VaultPaths,
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

fn node_doc(node: Node) -> NodeDoc {
    NodeDoc {
        node,
        created: NOW,
        gate: GateDoc::default(),
        pinned: None,
        public_key: "11".repeat(32),
    }
}

fn one_entry_manifest(node_id: &str, entry_id: &str, name: &str, generation: u64) -> ManifestBody {
    ManifestBody {
        node_id: node_id.to_string(),
        entries: vec![ManifestEntry {
            id: entry_id.to_string(),
            name: name.to_string(),
            r#ref: 1,
            entry_type: EntryType::Other,
            sensitivity: Sensitivity::Medium,
            field_count: 1,
            // ADR-067: the digest of the envelope `build_fixture` writes, so
            // the fixture is a consistent vault under `find_digest_mismatches`.
            sha256: ENVELOPE_SHA256.to_string(),
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
        generation,
    }
}

/// Global + node "a" (one entry, manifest + a real envelope file, signed and
/// written for real) + unrelated depth-1 sibling "b" (registered but with no
/// manifest ever written — reachability-filter fixture, never touched by a
/// caller scoped only to "a"). Loaded into `state` via
/// `verify_and_load_vault` so authorization sees the same topology
/// `maintenance.*` re-reads from disk.
fn build_fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let paths = VaultPaths::new(dir.path().join("vault"));
    let keystore = Box::new(SoftwareKeystore::new(
        SecretBox::new(Box::new("correct horse battery staple".to_string())),
        dir.path().join("keystore-state"),
    ));
    let state = Arc::new(BrokerState::new(keystore, paths.clone()));

    let manifest_a = one_entry_manifest("a", "e_a1", "a_SECRET", 1);
    let binding_a =
        credmgr_store::manifest::save(&paths, &ROOT_KEY, &manifest_a).expect("save manifest a");
    atomic::write(&paths.entry_env("a", "e_a1"), b"sealed-envelope-bytes").expect("write envelope");

    // `verify_and_load_vault` requires every registered node to have a real,
    // signed manifest on disk (fail-closed on any registry/manifest
    // mismatch) — "global" and "b" get empty ones, "a" gets real content.
    let binding_global =
        credmgr_store::manifest::save(&paths, &ROOT_KEY, &ManifestBody::new(GLOBAL_ID))
            .expect("save manifest global");
    let binding_b = credmgr_store::manifest::save(&paths, &ROOT_KEY, &ManifestBody::new("b"))
        .expect("save manifest b");

    let mut doc = RegistryDocument::new();
    doc.nodes
        .insert(GLOBAL_ID.to_string(), node_doc(Node::global()));
    doc.nodes.insert("a".to_string(), node_doc(depth1("a")));
    doc.nodes.insert("b".to_string(), node_doc(depth1("b")));
    doc.vault_generation = 1;
    doc.manifests.insert(GLOBAL_ID.to_string(), binding_global);
    doc.manifests.insert("a".to_string(), binding_a);
    doc.manifests.insert("b".to_string(), binding_b);
    credmgr_store::registry_file::save(&paths, &ROOT_KEY, &doc).expect("save registry");

    let counter =
        credmgr_store::generation::FileGenerationCounter::new(dir.path().join("gen-state"));
    state
        .verify_and_load_vault(&ROOT_KEY, &counter)
        .expect("load the real vault we just wrote");
    state.seed_root_key(&SecretBox::new(Box::new(ROOT_KEY)));

    Fixture {
        state,
        paths,
        _dir: dir,
    }
}

fn admin_scope(node_id: &str) -> BrokerScope {
    BrokerScope {
        node_id: node_id.to_string(),
        capabilities: vec![Capability::List, Capability::Admin],
        origin: Origin::HumanUi,
        token_id: None,
        bound_workdir: None,
    }
}

fn list_only_scope(node_id: &str) -> BrokerScope {
    BrokerScope {
        node_id: node_id.to_string(),
        capabilities: vec![Capability::List],
        origin: Origin::HumanUi,
        token_id: None,
        bound_workdir: None,
    }
}

fn no_caps_scope(node_id: &str) -> BrokerScope {
    BrokerScope {
        node_id: node_id.to_string(),
        capabilities: vec![],
        origin: Origin::HumanUi,
        token_id: None,
        bound_workdir: None,
    }
}

// ---------------------------------------------------------------------------
// maintenance.verify

#[test]
fn verify_reports_clean_for_a_consistent_vault() {
    let f = build_fixture();
    let value = ops::dispatch(
        &f.state,
        &list_only_scope("a"),
        NOW,
        "maintenance.verify",
        &json!({}),
    )
    .unwrap();
    assert_eq!(value["ok"], true);
    assert_eq!(
        value["nodesChecked"], 2,
        "\"a\" (R2, self) plus \"global\" (R3, every node reads global) — never \"b\""
    );
    assert!(value["errors"].as_array().unwrap().is_empty());
    assert!(value["warnings"].as_array().unwrap().is_empty());
}

#[test]
fn verify_without_list_capability_is_refused() {
    let f = build_fixture();
    let err = ops::dispatch(
        &f.state,
        &no_caps_scope("a"),
        NOW,
        "maintenance.verify",
        &json!({}),
    )
    .unwrap_err();
    assert!(matches!(
        err,
        OpError::CapabilityNotHeld {
            capability: Capability::List
        }
    ));
}

#[test]
fn verify_requires_the_vault_unlocked_to_check_hmacs() {
    let f = build_fixture();
    // Swap in a keystore that cannot unwrap the already-wrapped root (wrong
    // passphrase) — `reauth_root_key` fails the same way it would against a
    // genuinely locked broker; the op only ever sees "reauth failed", not
    // the reason, so this exercises the same mapping to `VaultLocked`.
    f.state
        .replace_keystore_for_test(Box::new(SoftwareKeystore::new(
            SecretBox::new(Box::new("different passphrase".to_string())),
            f.paths.root().join("unused-keystore-state"),
        )));
    let err = ops::dispatch(
        &f.state,
        &list_only_scope("a"),
        NOW,
        "maintenance.verify",
        &json!({}),
    )
    .unwrap_err();
    assert!(matches!(err, OpError::VaultLocked));
}

#[test]
fn verify_never_touches_a_node_outside_the_callers_scope() {
    let f = build_fixture();
    // Scoped to "b" (no manifest ever written for "b") — "a" must not be
    // named, counted, or have its (perfectly fine) manifest read at all.
    let value = ops::dispatch(
        &f.state,
        &list_only_scope("b"),
        NOW,
        "maintenance.verify",
        &json!({}),
    )
    .unwrap();
    // "b" (R2, self) plus "global" (R3) — "a" is reachable from neither rule
    // for a subject scoped to "b" (depth-1 siblings are isolated by default).
    assert_eq!(value["nodesChecked"], 2);
    assert_eq!(
        value["ok"], true,
        "b's own empty manifest and global's are both clean"
    );
    let errors = value["errors"].as_array().unwrap();
    assert!(!errors.iter().any(|e| e["node"] == "a"));
    let warnings = value["warnings"].as_array().unwrap();
    assert!(!warnings.iter().any(|w| w["node"] == "a"));
}

#[test]
fn verify_flags_a_dangling_envelope_with_no_manifest_entry() {
    let f = build_fixture();
    atomic::write(&f.paths.entry_env("a", "e_ghost"), b"nobody points at me").unwrap();

    let value = ops::dispatch(
        &f.state,
        &list_only_scope("a"),
        NOW,
        "maintenance.verify",
        &json!({}),
    )
    .unwrap();
    assert_eq!(
        value["ok"], true,
        "a dangling envelope is a warning, not an error"
    );
    let warnings = value["warnings"].as_array().unwrap();
    assert!(warnings
        .iter()
        .any(|w| w["detail"].as_str().unwrap().contains("e_ghost")));
}

/// ADR-067: the manifest digest is the envelope's, so a swapped envelope is
/// caught with no key — an error, because the value on disk is no longer the
/// one the signed manifest describes.
#[test]
fn verify_flags_an_envelope_whose_bytes_do_not_match_its_manifest_digest() {
    let f = build_fixture();
    atomic::write(&f.paths.entry_env("a", "e_a1"), b"a different envelope").unwrap();

    let value = ops::dispatch(
        &f.state,
        &list_only_scope("a"),
        NOW,
        "maintenance.verify",
        &json!({}),
    )
    .unwrap();
    assert_eq!(value["ok"], false);
    let errors = value["errors"].as_array().unwrap();
    assert!(errors.iter().any(|e| {
        let d = e["detail"].as_str().unwrap();
        d.contains("e_a1") && d.contains("digest mismatch")
    }));
}

#[test]
fn verify_flags_a_missing_envelope_the_manifest_names() {
    let f = build_fixture();
    std::fs::remove_file(f.paths.entry_env("a", "e_a1")).unwrap();

    let value = ops::dispatch(
        &f.state,
        &list_only_scope("a"),
        NOW,
        "maintenance.verify",
        &json!({}),
    )
    .unwrap();
    assert_eq!(value["ok"], false);
    let errors = value["errors"].as_array().unwrap();
    assert!(errors
        .iter()
        .any(|e| e["detail"].as_str().unwrap().contains("e_a1")));
}

#[test]
fn verify_flags_a_cross_binding_mismatch_without_touching_disk() {
    let f = build_fixture();
    // Re-save the manifest with a bumped generation (a real, validly-signed
    // write) but never update the registry's recorded binding — simulates a
    // crash between the two writes (`manifest.rs`'s own
    // `cross_binding_catches_a_manifest_rolled_back_alone` test, replayed
    // through the live op instead of the bare store function).
    let bumped = one_entry_manifest("a", "e_a1", "a_SECRET_v2", 2);
    credmgr_store::manifest::save(&f.paths, &ROOT_KEY, &bumped).unwrap();

    let before = std::fs::read(f.paths.registry()).unwrap();
    let value = ops::dispatch(
        &f.state,
        &list_only_scope("a"),
        NOW,
        "maintenance.verify",
        &json!({}),
    )
    .unwrap();
    assert_eq!(value["ok"], false);
    let errors = value["errors"].as_array().unwrap();
    assert!(errors.iter().any(|e| e["node"] == "a"));
    let after = std::fs::read(f.paths.registry()).unwrap();
    assert_eq!(before, after, "verify is read-only — it must never write");
}

#[test]
fn verify_reports_a_tampered_manifest_as_an_error() {
    let f = build_fixture();
    let manifest_path = f.paths.manifest("a");
    let mut raw: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
    raw["counts"]["entries"] = serde_json::json!(999);
    std::fs::write(&manifest_path, serde_json::to_vec_pretty(&raw).unwrap()).unwrap();

    let value = ops::dispatch(
        &f.state,
        &list_only_scope("a"),
        NOW,
        "maintenance.verify",
        &json!({}),
    )
    .unwrap();
    assert_eq!(value["ok"], false);
    let errors = value["errors"].as_array().unwrap();
    assert!(errors
        .iter()
        .any(|e| e["detail"].as_str().unwrap().contains("hmac")));
}

// ---------------------------------------------------------------------------
// maintenance.doctor

#[test]
fn doctor_with_nothing_wrong_applies_zero_fixes() {
    let f = build_fixture();
    let value = ops::dispatch(
        &f.state,
        &admin_scope("a"),
        NOW,
        "maintenance.doctor",
        &json!({}),
    )
    .unwrap();
    assert_eq!(value["fixCount"], 0);
    assert!(value["unfixable"].as_array().unwrap().is_empty());
}

#[test]
fn doctor_without_admin_capability_is_refused() {
    let f = build_fixture();
    let err = ops::dispatch(
        &f.state,
        &list_only_scope("a"),
        NOW,
        "maintenance.doctor",
        &json!({}),
    )
    .unwrap_err();
    assert!(matches!(
        err,
        OpError::CapabilityNotHeld {
            capability: Capability::Admin
        }
    ));
}

#[test]
fn doctor_resyncs_a_cross_binding_mismatch_when_apply_is_true() {
    let f = build_fixture();
    let bumped = one_entry_manifest("a", "e_a1", "a_SECRET_v2", 2);
    let fresh_binding = credmgr_store::manifest::save(&f.paths, &ROOT_KEY, &bumped).unwrap();

    let value = ops::dispatch(
        &f.state,
        &admin_scope("a"),
        NOW,
        "maintenance.doctor",
        &json!({ "apply": true }),
    )
    .unwrap();
    assert_eq!(value["applied"], true);
    assert_eq!(value["fixCount"], 1);
    assert_eq!(value["fixes"][0]["node"], "a");
    assert_eq!(value["fixes"][0]["type"], "cross-binding-resync");

    let doc = credmgr_store::registry_file::load(&f.paths, &ROOT_KEY).unwrap();
    let binding = doc.manifests.get("a").unwrap();
    assert_eq!(binding.manifest_hmac, fresh_binding.manifest_hmac);
    assert_eq!(binding.generation, 2);

    // Verify now reports clean, proving the fix actually took.
    let verified = ops::dispatch(
        &f.state,
        &list_only_scope("a"),
        NOW,
        "maintenance.verify",
        &json!({}),
    )
    .unwrap();
    assert_eq!(verified["ok"], true);
}

#[test]
fn doctor_dry_run_reports_the_fix_but_writes_nothing() {
    let f = build_fixture();
    let bumped = one_entry_manifest("a", "e_a1", "a_SECRET_v2", 2);
    credmgr_store::manifest::save(&f.paths, &ROOT_KEY, &bumped).unwrap();
    let before = std::fs::read(f.paths.registry()).unwrap();

    let value = ops::dispatch(
        &f.state,
        &admin_scope("a"),
        NOW,
        "maintenance.doctor",
        &json!({ "apply": false }),
    )
    .unwrap();
    assert_eq!(value["applied"], false);
    assert_eq!(
        value["fixCount"], 1,
        "a dry run still reports what would change"
    );

    let after = std::fs::read(f.paths.registry()).unwrap();
    assert_eq!(before, after, "apply:false must touch nothing on disk");
}

#[test]
fn doctor_refuses_to_launder_a_tampered_manifest() {
    let f = build_fixture();
    let manifest_path = f.paths.manifest("a");
    let mut raw: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
    raw["counts"]["entries"] = serde_json::json!(999);
    std::fs::write(&manifest_path, serde_json::to_vec_pretty(&raw).unwrap()).unwrap();
    let before = std::fs::read(f.paths.registry()).unwrap();

    let value = ops::dispatch(
        &f.state,
        &admin_scope("a"),
        NOW,
        "maintenance.doctor",
        &json!({ "apply": true }),
    )
    .unwrap();
    assert_eq!(
        value["fixCount"], 0,
        "a tampered manifest is never auto-resigned"
    );
    let unfixable = value["unfixable"].as_array().unwrap();
    assert!(unfixable.iter().any(|u| u["node"] == "a"));

    let after = std::fs::read(f.paths.registry()).unwrap();
    assert_eq!(before, after);
}

#[test]
fn doctor_rebuild_registry_requires_admin_before_the_presence_wall() {
    let f = build_fixture();
    let err = ops::dispatch(
        &f.state,
        &list_only_scope("a"),
        NOW,
        "maintenance.doctor",
        &json!({ "rebuildRegistry": true, "passphrase": "x" }),
    )
    .unwrap_err();
    assert!(
        matches!(
            err,
            OpError::CapabilityNotHeld {
                capability: Capability::Admin
            }
        ),
        "must fail on the capability check, never reach the presence wall, for a caller with no Admin at all"
    );
}

#[test]
fn doctor_rebuild_registry_is_presence_required_once_admin_is_held() {
    let f = build_fixture();
    let err = ops::dispatch(
        &f.state,
        &admin_scope("a"),
        NOW,
        "maintenance.doctor",
        &json!({ "rebuildRegistry": true, "passphrase": "x" }),
    )
    .unwrap_err();
    assert!(matches!(err, OpError::PresenceRequired { .. }));
}

#[test]
fn doctor_rebuild_registry_without_a_passphrase_is_malformed() {
    let f = build_fixture();
    let err = ops::dispatch(
        &f.state,
        &admin_scope("a"),
        NOW,
        "maintenance.doctor",
        &json!({ "rebuildRegistry": true }),
    )
    .unwrap_err();
    assert!(matches!(err, OpError::Malformed(_)));
}

// ---------------------------------------------------------------------------
// maintenance.backup

#[test]
fn backup_without_admin_capability_is_refused() {
    let f = build_fixture();
    let err = ops::dispatch(
        &f.state,
        &no_caps_scope("a"),
        NOW,
        "maintenance.backup",
        &json!({ "passphrase": "x" }),
    )
    .unwrap_err();
    assert!(matches!(
        err,
        OpError::CapabilityNotHeld {
            capability: Capability::Admin
        }
    ));
}

#[test]
fn backup_without_a_passphrase_is_malformed() {
    let f = build_fixture();
    let err = ops::dispatch(
        &f.state,
        &admin_scope("a"),
        NOW,
        "maintenance.backup",
        &json!({}),
    )
    .unwrap_err();
    assert!(matches!(err, OpError::Malformed(_)));
}

#[test]
fn backup_writes_a_real_encrypted_file_restorable_with_the_same_passphrase() {
    let f = build_fixture();
    let value = ops::dispatch(
        &f.state,
        &admin_scope("a"),
        NOW,
        "maintenance.backup",
        &json!({ "passphrase": "a backup passphrase" }),
    )
    .unwrap();
    let path = value["path"].as_str().unwrap();
    assert!(std::path::Path::new(path).exists());

    let ciphertext = std::fs::read(path).unwrap();
    let plaintext = credmgr_keystore::backup_passphrase::decrypt_with_passphrase(
        &SecretBox::new(Box::new("a backup passphrase".to_string())),
        &ciphertext,
    )
    .unwrap();
    let entries = credmgr_store::backup::unpack(&plaintext).unwrap();
    assert!(entries.iter().any(|e| e.relative_path == "registry.json"));
    assert!(entries
        .iter()
        .any(|e| e.relative_path == "nodes/a/entries/e_a1.env"));
}

#[test]
fn backup_prunes_beyond_retain_and_never_touches_a_manually_placed_file() {
    let f = build_fixture();
    atomic::write(
        &f.paths.backups_dir().join("my-manual-backup.enc"),
        b"keep me",
    )
    .unwrap();

    for t in [NOW, NOW + 1, NOW + 2] {
        ops::dispatch(
            &f.state,
            &admin_scope("a"),
            t,
            "maintenance.backup",
            &json!({ "passphrase": "x", "retain": 2 }),
        )
        .unwrap();
    }

    let remaining = credmgr_brokerd::maintenance::list_backup_files(&f.paths);
    assert_eq!(
        remaining.len(),
        2,
        "only the newest 2 of 3 survive retain:2"
    );
    assert!(f.paths.backups_dir().join("my-manual-backup.enc").exists());
}
