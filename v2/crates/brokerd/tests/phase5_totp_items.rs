//! TOTP items (`docs/07_TWO_FACTOR.md §6`) — the seed/code split: `totp.code`
//! returns the current 6 digits and nothing else, gated exactly like
//! `entry.reveal`; `totp.seed` returns the raw secret and is unreachable on
//! every transport Phase 3/4 has (`10_API_AND_MCP.md §3.2`: "No TOTP seed").
//!
//! Distinct from `tests/phase5_gate.rs`'s vault-wide *gate* 2FA — `07 §1`:
//! "gate and totp never share a word" — this file is entirely about a
//! stored credential's own TOTP seed, not the vault's unlock challenge.
//!
//! Fixture: Global, project "a" holding one ordinary entry (for the
//! capability/cross-node-denial checks) and one TOTP-seed entry (for the
//! seed/code split itself), project "b" unrelated to "a" (cross-node denial).

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
use credmgr_core::totp::Totp;
use credmgr_keystore::software::SoftwareKeystore;
use credmgr_store::manifest::{Counts, ManifestBody, ManifestEntry, Sensitivity};

const NOW: i64 = 1_800_000_000;

struct Fixture {
    state: Arc<BrokerState>,
    totp: Totp,
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

fn manifest_with(entries: Vec<ManifestEntry>) -> ManifestBody {
    let totp_count = entries
        .iter()
        .filter(|e| e.entry_type == EntryType::Totp)
        .count() as u32;
    ManifestBody {
        node_id: "a".to_string(),
        entries,
        counts: Counts {
            entries: 2,
            totp: totp_count,
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

    let ordinary = credmgr_core::envelope::seal(b"a-secret-value", &node_pub, "a", "e_a1")
        .expect("seal cannot fail for a small fixed payload");
    credmgr_store::atomic::write(&state.paths.entry_env("a", "e_a1"), &ordinary)
        .expect("writing the ordinary fixture envelope");

    let totp = Totp::new_gate(vec![5u8; 20]);
    let seed_base32 = totp.secret_base32();
    let totp_envelope =
        credmgr_core::envelope::seal(seed_base32.as_bytes(), &node_pub, "a", "e_totp1")
            .expect("seal cannot fail for a small fixed payload");
    credmgr_store::atomic::write(&state.paths.entry_env("a", "e_totp1"), &totp_envelope)
        .expect("writing the TOTP fixture envelope");

    state.set_manifest(
        "a",
        manifest_with(vec![
            ManifestEntry {
                id: "e_a1".to_string(),
                name: "a_SECRET".to_string(),
                r#ref: 1,
                entry_type: EntryType::Other,
                sensitivity: Sensitivity::Medium,
                field_count: 1,
                sha256: "0".repeat(64),
                modified: NOW,
                expires_at: None,
                rotated_at: None,
                has_totp: false,
            },
            ManifestEntry {
                id: "e_totp1".to_string(),
                name: "a_2FA".to_string(),
                r#ref: 2,
                entry_type: EntryType::Totp,
                sensitivity: Sensitivity::High,
                field_count: 1,
                sha256: "0".repeat(64),
                modified: NOW,
                expires_at: None,
                rotated_at: None,
                has_totp: false,
            },
        ]),
    );

    state
        .unlock(0)
        .expect("fixture keystore's own passphrase unlocks its own wrap");

    Fixture {
        state,
        totp,
        _dir: dir,
    }
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

// ---------------------------------------------------------------------------
// totp.code

#[test]
fn totp_code_returns_the_current_code_and_never_the_seed() {
    let f = build_fixture();
    let scope = scope_for(
        "a",
        &[Capability::List, Capability::Read, Capability::Reveal],
    );
    let response = ops::dispatch(
        &f.state,
        &scope,
        NOW,
        "totp.code",
        &json!({ "node": "a", "entry": "e_totp1" }),
    )
    .expect("totp.code with reveal capability on the entry's own node");

    let code = response["code"].as_str().expect("code field present");
    assert_eq!(code, f.totp.code(NOW as u64));
    assert_eq!(code.len(), 6);

    // The response has no field that could carry the raw seed under any name.
    let obj = response.as_object().expect("object response");
    let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, ["code", "entry", "node"]);
}

#[test]
fn totp_code_without_reveal_capability_is_refused_before_touching_the_entry() {
    let f = build_fixture();
    let scope = scope_for("a", &[Capability::List, Capability::Read]);
    let err = ops::dispatch(
        &f.state,
        &scope,
        NOW,
        "totp.code",
        &json!({ "node": "a", "entry": "e_totp1" }),
    )
    .unwrap_err();
    assert!(matches!(
        err,
        OpError::CapabilityNotHeld {
            capability: Capability::Reveal
        }
    ));
}

#[test]
fn totp_code_cross_node_is_denied_like_any_other_reveal() {
    let f = build_fixture();
    let scope = scope_for(
        "b",
        &[Capability::List, Capability::Read, Capability::Reveal],
    );
    let err = ops::dispatch(
        &f.state,
        &scope,
        NOW,
        "totp.code",
        &json!({ "node": "a", "entry": "e_totp1" }),
    )
    .unwrap_err();
    match err {
        OpError::NodeAccessDenied { target, rule, .. } => {
            assert_eq!(target, "a");
            assert_eq!(rule, "R8");
        }
        other => panic!("expected NodeAccessDenied, got {other:?}"),
    }
}

#[test]
fn totp_code_on_a_locked_vault_is_an_ordinary_denial_not_an_approval() {
    let f = build_fixture();
    f.state.lock();
    let scope = scope_for(
        "a",
        &[Capability::List, Capability::Read, Capability::Reveal],
    );
    let err = ops::dispatch(
        &f.state,
        &scope,
        NOW,
        "totp.code",
        &json!({ "node": "a", "entry": "e_totp1" }),
    )
    .unwrap_err();
    assert!(
        matches!(err, OpError::NodeAccessDenied { rule: "R1", .. }),
        "expected an ordinary R1 denial, not an approval_pending route \
         (that response shape carries the raw entry value, which for this \
         op is the seed — 07 §6), got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// totp.seed

#[test]
fn totp_seed_is_unreachable_even_with_full_capabilities_and_an_unlocked_vault() {
    let f = build_fixture();
    let scope = scope_for(
        "a",
        &[
            Capability::List,
            Capability::Read,
            Capability::Reveal,
            Capability::Admin,
        ],
    );
    let err = ops::dispatch(
        &f.state,
        &scope,
        NOW,
        "totp.seed",
        &json!({ "node": "a", "entry": "e_totp1" }),
    )
    .unwrap_err();
    assert!(matches!(
        err,
        OpError::PresenceRequired { operation } if operation == "totp.seed"
    ));
}

#[test]
fn totp_seed_without_reveal_capability_fails_the_capability_check_first() {
    let f = build_fixture();
    let scope = scope_for("a", &[Capability::List, Capability::Read]);
    let err = ops::dispatch(
        &f.state,
        &scope,
        NOW,
        "totp.seed",
        &json!({ "node": "a", "entry": "e_totp1" }),
    )
    .unwrap_err();
    assert!(matches!(
        err,
        OpError::CapabilityNotHeld {
            capability: Capability::Reveal
        }
    ));
}

#[test]
fn totp_seed_cross_node_is_an_ordinary_denial_not_presence_required() {
    let f = build_fixture();
    let scope = scope_for(
        "b",
        &[Capability::List, Capability::Read, Capability::Reveal],
    );
    let err = ops::dispatch(
        &f.state,
        &scope,
        NOW,
        "totp.seed",
        &json!({ "node": "a", "entry": "e_totp1" }),
    )
    .unwrap_err();
    assert!(
        matches!(err, OpError::NodeAccessDenied { rule: "R8", .. }),
        "an unreachable node must not even get as far as the presence \
         check — that would confirm the node exists, got {err:?}"
    );
}
