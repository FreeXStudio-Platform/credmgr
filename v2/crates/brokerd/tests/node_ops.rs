//! `node.create` — ADR-051. Never implemented before this session, despite
//! being a documented op (`18_ENDPOINT_INDEX.md`) and the literal prerequisite
//! for demonstrating `01_CONCEPT.md §7` success criterion 6 ("a fresh V2
//! vault, created and populated only through its own CLI/MCP/broker") — there
//! was no live path to create the *nodes* half of that at all.
//!
//! Same `Capability::Admin`-substitutes-for-2FA shape this crate's own
//! `ops.rs` module doc already established for `node.seal`/`node.restore`
//! (I-21) — not `node.reparent`/`grant.create`'s unconditional
//! `PresenceRequired`, because a brand-new, empty node has no existing data
//! whose reachability silently shifts. See ADR-051 for the full reasoning.

use std::sync::Arc;

use secrecy::SecretBox;
use serde_json::json;

use credmgr_brokerd::ops;
use credmgr_brokerd::protocol::OpError;
use credmgr_brokerd::scope::BrokerScope;
use credmgr_brokerd::state::BrokerState;
use credmgr_core::access::Origin;
use credmgr_core::registry::{Capability, Node, NodeKind, NodePolicy, Registry, GLOBAL_ID};

const NOW: i64 = 1_800_000_000;

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
    let keystore = Box::new(credmgr_keystore::software::SoftwareKeystore::new(
        SecretBox::new(Box::new("correct horse battery staple".to_string())),
        dir.path().join("keystore-state"),
    ));
    let paths = credmgr_store::paths::VaultPaths::new(dir.path().join("vault"));
    let state = Arc::new(BrokerState::new(keystore, paths));

    let root_key = SecretBox::new(Box::new([9u8; 32]));
    state.seed_root_key(&root_key);

    let mut reg = Registry::new();
    reg.nodes.insert(GLOBAL_ID.to_string(), Node::global());
    reg.nodes.insert("acme".to_string(), depth1("acme"));
    state.set_registry(reg);
    state.seed_node_key(&root_key, "acme");

    state
        .unlock(0)
        .expect("fixture keystore's own passphrase unlocks its own wrap");

    Fixture { state, _dir: dir }
}

fn scope_for(node_id: &str, caps: &[Capability]) -> BrokerScope {
    BrokerScope {
        node_id: node_id.to_string(),
        capabilities: caps.to_vec(),
        origin: Origin::Cli,
        token_id: None,
        bound_workdir: None,
    }
}

#[test]
fn requires_admin_capability() {
    let f = build_fixture();
    let err = ops::dispatch(
        &f.state,
        &scope_for("acme", &[Capability::List]),
        NOW,
        "node.create",
        &json!({ "id": "northwind", "label": "Northwind", "parentId": GLOBAL_ID }),
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
fn denied_without_admin_over_the_parent_specifically() {
    let f = build_fixture();
    // R3 makes `global` allow-by-default for *any* capability from *any*
    // subject (`06_ACCESS_GRAPH.md` R3 is not itself capability-scoped) — so
    // the meaningful denial case is a depth-1 *project* parent, which has no
    // such blanket rule: "acme" has Admin over itself, but that grants it
    // nothing over an unrelated sibling project's subtree.
    let mut reg = f.state.registry.write().expect("registry poisoned").clone();
    reg.nodes.insert("contoso".to_string(), depth1("contoso"));
    f.state.set_registry(reg);

    let err = ops::dispatch(
        &f.state,
        &scope_for("acme", &[Capability::Admin]),
        NOW,
        "node.create",
        &json!({ "id": "contoso-staging", "label": "Staging", "parentId": "contoso" }),
    )
    .unwrap_err();
    assert!(
        matches!(err, OpError::NodeAccessDenied { .. }),
        "acme's own Admin capability must not reach an unrelated sibling project: {err:?}"
    );
}

#[test]
fn creates_a_real_depth1_project_under_global() {
    let f = build_fixture();
    let response = ops::dispatch(
        &f.state,
        &scope_for(GLOBAL_ID, &[Capability::Admin]),
        NOW,
        "node.create",
        &json!({ "id": "northwind", "label": "Northwind", "parentId": GLOBAL_ID }),
    )
    .expect("node.create");
    assert_eq!(response["node"], "northwind");
    assert_eq!(response["created"], true);

    // Checked directly against the registry, not via `node.list` — Global's
    // own default policy is `descendant_read: false` (`registry::Node::global`
    // uses `NodePolicy::default()` for everything but `siblingVisibility`),
    // so a Global-*scoped* caller does not see its own children by default
    // (the same direction-specific-R3 trap ADR-047 already named for
    // `graph.snapshot`) — this assertion is about whether the mutation
    // happened, not about who can subsequently list it.
    let nodes: Vec<String> = f
        .state
        .registry
        .read()
        .expect("registry poisoned")
        .nodes
        .keys()
        .cloned()
        .collect();
    assert!(nodes.iter().any(|n| n == "northwind"), "{nodes:?}");
}

#[test]
fn creates_a_real_depth2_sub_node_under_a_project() {
    let f = build_fixture();
    ops::dispatch(
        &f.state,
        &scope_for("acme", &[Capability::Admin]),
        NOW,
        "node.create",
        &json!({ "id": "acme-staging", "label": "Staging", "parentId": "acme" }),
    )
    .expect("node.create under a depth-1 parent");

    // A depth-2 sibling under the SAME parent shares by default (R6) — prove
    // the new node actually landed at depth 2 with the right parent, not
    // just that the call returned ok, by exercising the access rule that
    // only fires for real depth-2 siblings.
    ops::dispatch(
        &f.state,
        &scope_for("acme", &[Capability::Admin]),
        NOW,
        "node.create",
        &json!({ "id": "acme-prod", "label": "Prod", "parentId": "acme" }),
    )
    .expect("node.create second sub-node");

    let registry = f.state.registry.read().expect("registry poisoned");
    let decision = credmgr_core::access::resolve(
        &credmgr_core::access::AccessContext {
            registry: &registry,
            vault_locked: false,
            locked_nodes: &std::collections::HashSet::new(),
            now: NOW,
        },
        &credmgr_core::access::Scope {
            node_id: "acme-staging".to_string(),
            origin: Origin::Cli,
            presence_attested: false,
        },
        &credmgr_core::access::Target::Node("acme-prod".to_string()),
        Capability::Read,
    );
    assert!(
        decision.is_allow(),
        "two freshly-created depth-2 siblings under the same parent must share by \
         default (06_ACCESS_GRAPH.md R6), got {decision:?}"
    );
}

#[test]
fn a_freshly_created_node_is_isolated_from_its_siblings_by_default() {
    let f = build_fixture();
    ops::dispatch(
        &f.state,
        &scope_for(GLOBAL_ID, &[Capability::Admin]),
        NOW,
        "node.create",
        &json!({ "id": "northwind", "label": "Northwind", "parentId": GLOBAL_ID }),
    )
    .expect("node.create");

    // acme existed before northwind; northwind must be unreachable from acme
    // and vice versa, with zero configuration (R8) — this is criterion 6's
    // actual claim: nothing is reachable from a node that never created or
    // received a grant for it.
    let registry = f.state.registry.read().expect("registry poisoned");
    let decision = credmgr_core::access::resolve(
        &credmgr_core::access::AccessContext {
            registry: &registry,
            vault_locked: false,
            locked_nodes: &std::collections::HashSet::new(),
            now: NOW,
        },
        &credmgr_core::access::Scope {
            node_id: "acme".to_string(),
            origin: Origin::Cli,
            presence_attested: false,
        },
        &credmgr_core::access::Target::Node("northwind".to_string()),
        Capability::Read,
    );
    assert!(
        !decision.is_allow(),
        "a brand-new sibling project must be isolated by default: {decision:?}"
    );
}

#[test]
fn rejects_a_reserved_id() {
    let f = build_fixture();
    let err = ops::dispatch(
        &f.state,
        &scope_for(GLOBAL_ID, &[Capability::Admin]),
        NOW,
        "node.create",
        &json!({ "id": GLOBAL_ID, "label": "nope", "parentId": GLOBAL_ID }),
    )
    .unwrap_err();
    assert!(matches!(err, OpError::Malformed(_)));
}

#[test]
fn rejects_a_duplicate_id() {
    let f = build_fixture();
    let err = ops::dispatch(
        &f.state,
        &scope_for(GLOBAL_ID, &[Capability::Admin]),
        NOW,
        "node.create",
        &json!({ "id": "acme", "label": "dup", "parentId": GLOBAL_ID }),
    )
    .unwrap_err();
    assert!(matches!(err, OpError::Malformed(_)));
}

#[test]
fn rejects_an_unknown_parent() {
    let f = build_fixture();
    let err = ops::dispatch(
        &f.state,
        &scope_for(GLOBAL_ID, &[Capability::Admin]),
        NOW,
        "node.create",
        &json!({ "id": "northwind", "label": "Northwind", "parentId": "does-not-exist" }),
    )
    .unwrap_err();
    // Same shape `node.seal`/`node.reparent` already have: `resolve_capability`
    // is checked before existence, so a target that resolves against no rule
    // at all (R8, because it is not even a real node) surfaces as a denial,
    // not a distinct not-found — consistent with, not a regression from, the
    // established sibling ops.
    assert!(matches!(err, OpError::NodeAccessDenied { .. }), "{err:?}");
}

#[test]
fn rejects_a_third_level_child_the_depth_cap() {
    let f = build_fixture();
    ops::dispatch(
        &f.state,
        &scope_for("acme", &[Capability::Admin]),
        NOW,
        "node.create",
        &json!({ "id": "acme-staging", "label": "Staging", "parentId": "acme" }),
    )
    .expect("depth-2 create");

    let err = ops::dispatch(
        &f.state,
        &scope_for("acme-staging", &[Capability::Admin]),
        NOW,
        "node.create",
        &json!({ "id": "acme-staging-eu", "label": "too deep", "parentId": "acme-staging" }),
    )
    .unwrap_err();
    assert!(
        matches!(err, OpError::Malformed(_)),
        "depth is capped at 2 (03_DATA_MODEL.md §1): {err:?}"
    );
}

#[test]
fn a_created_node_is_immediately_usable_for_a_real_entry() {
    let f = build_fixture();
    ops::dispatch(
        &f.state,
        &scope_for(GLOBAL_ID, &[Capability::Admin]),
        NOW,
        "node.create",
        &json!({ "id": "northwind", "label": "Northwind", "parentId": GLOBAL_ID }),
    )
    .expect("node.create");

    // Not a placeholder waiting for a second step — a real node key was
    // wrapped and seeded, so entry.create against it works right away.
    let created = ops::dispatch(
        &f.state,
        &scope_for("northwind", &[Capability::Create]),
        NOW,
        "entry.create",
        &json!({ "node": "northwind", "name": "API_KEY", "value": "s3cr3t" }),
    )
    .expect("entry.create against the freshly-created node");
    assert!(created.get("entry").is_some(), "{created:?}");
}
