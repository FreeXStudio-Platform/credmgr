//! `graph.snapshot` — the UI's one-request graph contract
//! (`design/graph-engine/VAULT_GRAPH_SPEC.md §2`): "The canvas is fed one
//! object... must render correctly while the vault is fully locked." This
//! is Phase 6's first exit-gate bullet's backend half — the data contract
//! the Svelte canvas will consume, proven correct independently of any
//! frontend rendering code.
//!
//! Fixture: Global; project "a" (default policy — `requireTwoFactor:
//! reveal`, `07 §2`'s default) with 2 entries incl. 1 TOTP item; project "b"
//! (`requireTwoFactor: never`) with 1 entry, unrelated to "a" so depth-1
//! siblings stay isolated by the model's own default rule; sub-node "a1"
//! under "a", empty, to exercise a structural edge and the "parents do not
//! read children by default" isolation case.
//!
//! No node keys are seeded and no envelopes are written — `graph.snapshot`
//! never touches key material, only the registry, the manifests (already
//! proven readable with no key at all — `crates/store::manifest`'s own
//! `counts_are_readable_without_any_key_the_locked_graph_requirement` test),
//! and lock state, so this fixture stays deliberately lighter than the
//! reveal-path fixtures in `phase5_totp_items.rs`/`phase5_gate.rs`.

use std::sync::Arc;

use secrecy::SecretBox;
use serde_json::json;

use credmgr_brokerd::ops;
use credmgr_brokerd::scope::BrokerScope;
use credmgr_brokerd::state::{BrokerState, GATE_SCOPE_VAULT};
use credmgr_core::access::Origin;
use credmgr_core::registry::{
    Capability, Node, NodeKind, NodePolicy, Registry, TwoFactorRequirement, GLOBAL_ID,
};
use credmgr_core::totp::Totp;
use credmgr_keystore::software::SoftwareKeystore;
use credmgr_store::manifest::{Counts, ManifestBody};

const NOW: i64 = 1_800_000_000;

struct Fixture {
    state: Arc<BrokerState>,
    _dir: tempfile::TempDir,
}

fn depth1(id: &str, policy: NodePolicy) -> Node {
    Node {
        id: id.to_string(),
        label: id.to_string(),
        kind: NodeKind::Project,
        depth: 1,
        parent_id: Some(GLOBAL_ID.to_string()),
        workdirs: Vec::new(),
        policy,
    }
}

fn depth2(id: &str, parent: &str) -> Node {
    Node {
        id: id.to_string(),
        label: id.to_string(),
        kind: NodeKind::Sub,
        depth: 2,
        parent_id: Some(parent.to_string()),
        workdirs: Vec::new(),
        policy: NodePolicy::default(),
    }
}

fn manifest(node_id: &str, entries: u32, totp: u32) -> ManifestBody {
    ManifestBody {
        node_id: node_id.to_string(),
        entries: Vec::new(),
        counts: Counts { entries, totp },
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

    let b_policy = NodePolicy {
        require_two_factor: TwoFactorRequirement::Never,
        ..NodePolicy::default()
    };

    let mut reg = Registry::new();
    reg.nodes.insert(GLOBAL_ID.to_string(), Node::global());
    reg.nodes
        .insert("a".to_string(), depth1("a", NodePolicy::default()));
    reg.nodes.insert("b".to_string(), depth1("b", b_policy));
    reg.nodes.insert("a1".to_string(), depth2("a1", "a"));
    state.set_registry(reg);

    state.set_manifest("a", manifest("a", 2, 1));
    state.set_manifest("b", manifest("b", 1, 0));
    state.set_manifest("a1", manifest("a1", 0, 0));

    Fixture { state, _dir: dir }
}

/// A "sees the whole vault" scope does not exist yet on any real transport —
/// see ADR-047. Tests that need to enrol/confirm the vault-wide gate (a
/// global-scoped, `Admin`-gated operation, not a cross-node read) use this;
/// tests about the graph's own topology use [`scope_for`] with a node whose
/// *real* reachability (self + ancestors + Global, `06_ACCESS_GRAPH.md`
/// R2-R4) already covers what's being asserted, exactly as a real caller
/// would see it today.
fn admin_scope() -> BrokerScope {
    BrokerScope {
        node_id: GLOBAL_ID.to_string(),
        capabilities: vec![Capability::List, Capability::Admin],
        origin: Origin::HumanUi,
        token_id: None,
        bound_workdir: None,
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

/// Mirrors `phase5_gate.rs`'s helper of the same shape: real dispatch calls
/// through `vault.gate_enroll_begin`/`_confirm`, not direct state access.
fn enroll_and_confirm_gate(f: &Fixture) {
    let begin = ops::dispatch(
        &f.state,
        &admin_scope(),
        NOW,
        "vault.gate_enroll_begin",
        &json!({}),
    )
    .expect("enroll_begin");
    let uri = begin["otpauthUri"].as_str().expect("otpauthUri present");
    let secret_b32 = uri
        .split("secret=")
        .nth(1)
        .expect("uri has a secret param")
        .split('&')
        .next()
        .unwrap();
    let secret = decode_base32(secret_b32);
    let totp = Totp::new_gate(secret);
    let code = totp.code(NOW as u64);

    ops::dispatch(
        &f.state,
        &admin_scope(),
        NOW,
        "vault.gate_enroll_confirm",
        &json!({ "code": code }),
    )
    .expect("enroll_confirm with the freshly-generated code must succeed");
}

/// RFC 4648 base32 (no padding) decode, hand-written for the same reason
/// `phase5_gate.rs` hand-writes its own copy: too small to justify a
/// test-only dependency.
fn decode_base32(s: &str) -> Vec<u8> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut bits = 0u32;
    let mut bit_count = 0u32;
    let mut out = Vec::new();
    for c in s.chars() {
        let val = ALPHABET
            .iter()
            .position(|&b| b == c.to_ascii_uppercase() as u8)
            .expect("valid base32 char") as u32;
        bits = (bits << 5) | val;
        bit_count += 5;
        if bit_count >= 8 {
            bit_count -= 8;
            out.push((bits >> bit_count) as u8);
        }
    }
    out
}

fn node_by_id<'a>(nodes: &'a [serde_json::Value], id: &str) -> &'a serde_json::Value {
    nodes
        .iter()
        .find(|n| n["id"] == id)
        .unwrap_or_else(|| panic!("node '{id}' present in the snapshot"))
}

// ---------------------------------------------------------------------------

/// A depth-2 node's own reachable subgraph — self (R2), its parent (R4
/// ancestor), and Global (R3) — is available to a real cwd-scoped caller
/// today with no grant and no session mechanism, so this is the largest
/// legitimately-reachable topology this test file can assert against a
/// single real scope (see ADR-047 on why "the whole vault, unfiltered" is
/// not yet reachable by anything but a test fixture handing itself a token).
fn a1_scope() -> BrokerScope {
    scope_for(
        "a1",
        &[
            Capability::List,
            Capability::Read,
            Capability::Reveal,
            Capability::Create,
            Capability::Update,
        ],
    )
}

#[test]
fn renders_the_ancestor_chain_with_correct_counts_while_the_vault_is_locked() {
    let f = build_fixture();
    assert!(f.state.is_locked(), "fixture never called vault.unlock");

    let response = ops::dispatch(&f.state, &a1_scope(), NOW, "graph.snapshot", &json!({}))
        .expect("graph.snapshot must work on a locked vault — that is the whole point");

    assert_eq!(response["meta"]["vaultLocked"], true);
    assert_eq!(response["meta"]["generatedAt"], NOW);

    let nodes = response["nodes"].as_array().expect("nodes array");
    assert_eq!(
        nodes.len(),
        3,
        "global (R3), a (R4 ancestor), a1 (R2 self) — never b"
    );

    let a = node_by_id(nodes, "a");
    assert_eq!(a["counts"]["entries"], 2);
    assert_eq!(a["counts"]["totp"], 1);
    assert_eq!(a["kind"], "project");
    assert_eq!(a["depth"], 1);
    assert_eq!(a["parentId"], GLOBAL_ID);
    assert_eq!(a["health"], serde_json::Value::Null);

    let a1 = node_by_id(nodes, "a1");
    assert_eq!(a1["counts"]["entries"], 0);
    assert_eq!(a1["counts"]["totp"], 0);
    assert_eq!(a1["kind"], "sub");
    assert_eq!(a1["depth"], 2);
    assert_eq!(a1["parentId"], "a");

    let global = node_by_id(nodes, GLOBAL_ID);
    assert_eq!(global["counts"]["entries"], 0, "no manifest set for global");
    assert_eq!(global["parentId"], serde_json::Value::Null);
}

#[test]
fn structural_links_are_parent_child_only_and_never_carry_a_grant_kind() {
    let f = build_fixture();
    let response = ops::dispatch(&f.state, &a1_scope(), NOW, "graph.snapshot", &json!({}))
        .expect("graph.snapshot");
    let links = response["links"].as_array().expect("links array");
    assert_eq!(
        links.len(),
        2,
        "global->a, a->a1 — global->b is correctly absent: b is not in nodes[]"
    );
    for link in links {
        assert_eq!(link["kind"], "structural");
        assert_eq!(link["direction"], "down");
    }
    let has = |src: &str, tgt: &str| {
        links
            .iter()
            .any(|l| l["source"] == src && l["target"] == tgt)
    };
    assert!(has(GLOBAL_ID, "a"));
    assert!(has("a", "a1"));
}

#[test]
fn a_project_scoped_caller_never_sees_a_sibling_or_a_child_it_cannot_list() {
    let f = build_fixture();
    // node "a", cwd-scoped, no cross-node capability grant — the same shape
    // `isolation.rs`'s i2/i4 already prove for `entry.list`/`node.list`;
    // `graph.snapshot` reuses the identical `resolve_capability` filter.
    let scope = scope_for("a", &[Capability::List]);
    let response = ops::dispatch(&f.state, &scope, NOW, "graph.snapshot", &json!({}))
        .expect("graph.snapshot for a project-scoped caller");

    let nodes = response["nodes"].as_array().expect("nodes array");
    let ids: Vec<&str> = nodes.iter().map(|n| n["id"].as_str().unwrap()).collect();
    assert!(ids.contains(&GLOBAL_ID), "everything reads Global");
    assert!(ids.contains(&"a"), "self is always visible");
    assert!(
        !ids.contains(&"b"),
        "depth-1 projects never read each other by default"
    );
    assert!(
        !ids.contains(&"a1"),
        "parents do not read children by default — descendantRead is opt-in"
    );

    // No dangling link may reference a node this scope never received.
    let links = response["links"].as_array().expect("links array");
    for link in links {
        let src = link["source"].as_str().unwrap();
        let tgt = link["target"].as_str().unwrap();
        assert!(ids.contains(&src), "link source '{src}' must be in nodes[]");
        assert!(ids.contains(&tgt), "link target '{tgt}' must be in nodes[]");
    }
}

#[test]
fn gate_twofa_reflects_node_policy_and_the_vault_wide_gates_own_state() {
    let f = build_fixture();
    let b_scope = scope_for("b", &[Capability::List]);

    // No gate enrolled at all yet.
    let response = ops::dispatch(&f.state, &a1_scope(), NOW, "graph.snapshot", &json!({}))
        .expect("graph.snapshot");
    let nodes = response["nodes"].as_array().unwrap();
    assert_eq!(
        node_by_id(nodes, "a")["gate"]["twofa"],
        "enrolled",
        "a's default reveal policy, but the vault gate is not yet confirmed"
    );
    let b_response = ops::dispatch(&f.state, &b_scope, NOW, "graph.snapshot", &json!({}))
        .expect("graph.snapshot for b's own scope");
    assert_eq!(
        node_by_id(b_response["nodes"].as_array().unwrap(), "b")["gate"]["twofa"],
        "none",
        "b's policy is requireTwoFactor: never"
    );

    // `vault.gate_enroll_begin`/`_confirm` are global-scoped `Admin`
    // operations (`07 §4`), not a cross-node read — `admin_scope`'s node_id
    // is legitimately `global` for this call, no gap from ADR-047 applies.
    enroll_and_confirm_gate(&f);
    assert!(f.state.is_gate_confirmed(GATE_SCOPE_VAULT));

    let response = ops::dispatch(&f.state, &a1_scope(), NOW, "graph.snapshot", &json!({}))
        .expect("graph.snapshot after gate confirmation");
    let nodes = response["nodes"].as_array().unwrap();
    assert_eq!(
        node_by_id(nodes, "a")["gate"]["twofa"],
        "required",
        "confirmed vault gate + a reveal-requiring policy"
    );
    let b_response = ops::dispatch(&f.state, &b_scope, NOW, "graph.snapshot", &json!({}))
        .expect("graph.snapshot for b's own scope, after gate confirmation");
    assert_eq!(
        node_by_id(b_response["nodes"].as_array().unwrap(), "b")["gate"]["twofa"],
        "none",
        "b's own policy is unaffected by the vault gate confirming"
    );
}

#[test]
fn a_node_level_lock_shows_locked_on_that_node_only() {
    let f = build_fixture();
    // A node-level lock is only distinguishable from the vault-wide lock
    // `gate.locked` also reports — `locked = vault_locked || node_locked`,
    // §11 of the UI spec's "a node can also be locked on its own, while the
    // vault stays open" — once the vault itself is actually open.
    let root_key = secrecy::SecretBox::new(Box::new([9u8; 32]));
    f.state.seed_root_key(&root_key);
    f.state
        .unlock(NOW)
        .expect("no gate is enrolled in this fixture, so unlock needs only the passphrase");
    assert!(!f.state.is_locked());

    f.state.lock_node("a1");

    let response = ops::dispatch(&f.state, &a1_scope(), NOW, "graph.snapshot", &json!({}))
        .expect("graph.snapshot");
    let nodes = response["nodes"].as_array().unwrap();
    assert_eq!(node_by_id(nodes, "a1")["gate"]["locked"], true);
    assert_eq!(node_by_id(nodes, "a")["gate"]["locked"], false);
    assert_eq!(node_by_id(nodes, GLOBAL_ID)["gate"]["locked"], false);
}

#[test]
fn without_the_list_capability_the_whole_op_is_refused_before_it_touches_the_registry() {
    let f = build_fixture();
    let scope = scope_for("a", &[]);
    let err = ops::dispatch(&f.state, &scope, NOW, "graph.snapshot", &json!({}))
        .expect_err("no List capability at all must be refused");
    match err {
        credmgr_brokerd::protocol::OpError::CapabilityNotHeld { capability } => {
            assert_eq!(capability, Capability::List);
        }
        other => panic!("expected CapabilityNotHeld, got {other:?}"),
    }
}
