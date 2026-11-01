//! F5a (found while planning ADR-078): `node.seal` re-seals every entry under
//! the orphan key — which writes **different bytes** — but copied the *original*
//! envelope's digest into the orphan manifest. ADR-067 made `sha256` the digest
//! of the sealed envelope, so every orphaned entry's recorded digest described a
//! file that no longer existed there. It was invisible to `maintenance.verify`
//! through a normal login only because a login cannot `list` the orphan node
//! (ADR-065); the first caller who could would have been told every orphaned
//! entry was tampered with.
//!
//! Written failing first (C0): the assertion below is red against the code as it
//! stood, for exactly the documented reason — the orphan manifest's `sha256` is
//! the pre-seal digest, not the digest of the file on disk.

use std::sync::Arc;

use secrecy::SecretBox;
use serde_json::json;
use sha2::{Digest, Sha256};

use credmgr_brokerd::ops;
use credmgr_brokerd::scope::BrokerScope;
use credmgr_brokerd::state::BrokerState;
use credmgr_core::access::Origin;
use credmgr_core::inference::EntryType;
use credmgr_core::registry::{
    Capability, Node, NodeKind, NodePolicy, Registry, GLOBAL_ID, ORPHAN_ID,
};
use credmgr_keystore::software::SoftwareKeystore;
use credmgr_store::manifest::{Counts, ManifestBody, ManifestEntry, Sensitivity};

const NOW: i64 = 1_800_000_000;

fn hex_sha256(bytes: &[u8]) -> String {
    use std::fmt::Write;
    Sha256::digest(bytes)
        .iter()
        .fold(String::with_capacity(64), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

fn project(id: &str) -> Node {
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

/// Project "a" holding one **version-1** (alpha.6-shaped) entry, an orphan node
/// with a real keypair, the vault unlocked.
fn fixture() -> (Arc<BrokerState>, tempfile::TempDir, String) {
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
    reg.nodes.insert(ORPHAN_ID.to_string(), Node::orphan());
    reg.nodes.insert("a".to_string(), project("a"));
    state.set_registry(reg);
    state.seed_node_key(&root_key, ORPHAN_ID);
    let node_pub = state.seed_node_key(&root_key, "a");

    let original = credmgr_core::envelope::seal(b"a-secret-value", &node_pub, "a", "e_a1")
        .expect("seal of a small fixed payload cannot fail");
    credmgr_store::atomic::write(&state.paths.entry_env("a", "e_a1"), &original)
        .expect("writing the fixture envelope");
    let original_digest = hex_sha256(&original);
    state.set_manifest(
        "a",
        ManifestBody {
            node_id: "a".to_string(),
            entries: vec![ManifestEntry {
                id: "e_a1".to_string(),
                name: "a_SECRET".to_string(),
                r#ref: 1,
                entry_type: EntryType::Other,
                sensitivity: Sensitivity::Medium,
                field_count: 1,
                sha256: original_digest.clone(),
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
        },
    );
    state.unlock(0).expect("unlock");
    (state, dir, original_digest)
}

fn admin() -> BrokerScope {
    BrokerScope {
        node_id: "a".to_string(),
        capabilities: vec![Capability::Admin],
        origin: Origin::Cli,
        token_id: None,
        bound_workdir: None,
    }
}

#[test]
fn node_seal_writes_the_orphan_digest_of_the_resealed_bytes() {
    let (state, _dir, original_digest) = fixture();

    ops::dispatch(&state, &admin(), NOW, "node.seal", &json!({ "node": "a" })).expect("node.seal");

    // What is on disk under the orphan node now.
    let on_disk = credmgr_store::atomic::read(&state.paths.entry_env(ORPHAN_ID, "e_a1"))
        .expect("the resealed envelope is under the orphan node");
    let on_disk_digest = hex_sha256(&on_disk);
    assert_ne!(
        on_disk_digest, original_digest,
        "resealing under the orphan key writes different bytes (fresh ephemeral key and nonce)"
    );

    // What the orphan manifest says about it.
    let recorded = {
        let manifests = state.manifests.read().expect("manifests poisoned");
        let body = manifests.get(ORPHAN_ID).expect("orphan has a manifest");
        let entry = body
            .entries
            .iter()
            .find(|e| e.id == "e_a1")
            .expect("the sealed entry is listed under orphan");
        entry.sha256.clone()
    };
    assert_eq!(
        recorded, on_disk_digest,
        "ADR-067: the manifest's sha256 is the digest of the envelope file it describes — \
         the orphan copy, not the pre-seal one"
    );
}
