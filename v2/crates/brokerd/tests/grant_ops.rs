//! `grant.list`/`create`/`revoke` — `10_API_AND_MCP.md §1`, `18_ENDPOINT_INDEX.md
//! §1.3`, ADR-050. Before this session neither op existed at all; `grant.create`'s
//! requirement was only ever named in the docs (`audit.get`'s own comment called
//! this out explicitly: "not a built precedent, just the same documented shape").
//!
//! `03_DATA_MODEL.md §6`: `Grant.to` is "the node being opened" — the endpoint
//! whose confidentiality boundary widens — so all three ops gate on
//! `Capability::Admin` resolved against `to`, never `from`. `list`/`create` follow
//! established precedent exactly (`audit.tail`'s readable-metadata shape,
//! `node.reparent`'s validate-everything-then-refuse-on-presence shape); `revoke`
//! is the one op here whose positive path genuinely executes today — `06
//! §6`: "Revoking ... is always reachable", no presence in the row `07 §2`
//! reserves for "create/modify" — the same `Capability::Admin`-alone
//! substitution `node.seal`/`node.restore` already use for a safe, one-click
//! action.
//!
//! Fixture: Global; project "a" and unrelated project "b" (depth-1 siblings,
//! isolated by the model's own default rule), plus one pre-seeded grant
//! `a → b` (read) so revoke/list have something real to act on.

use std::sync::Arc;

use secrecy::SecretBox;
use serde_json::json;

use credmgr_brokerd::ops;
use credmgr_brokerd::protocol::OpError;
use credmgr_brokerd::scope::BrokerScope;
use credmgr_brokerd::state::BrokerState;
use credmgr_core::access::Origin;
use credmgr_core::registry::{
    Capability, Direction, Grant, GrantTarget, Node, NodeKind, NodePolicy, Registry, GLOBAL_ID,
};
use credmgr_keystore::software::SoftwareKeystore;

const NOW: i64 = 1_800_000_000;
const GRANT_ID: &str = "g_a_to_b";

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

fn seed_grant() -> Grant {
    Grant {
        id: GRANT_ID.to_string(),
        from: "a".to_string(),
        to: GrantTarget::Node {
            node_id: "b".to_string(),
        },
        direction: Direction::OneWay,
        scope: vec![Capability::Read],
        expires_at: None,
        reason: "a's deploy job needs b's registry token".to_string(),
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
    reg.grants.push(seed_grant());
    state.set_registry(reg);
    state.seed_node_key(&root_key, "a");
    state.seed_node_key(&root_key, "b");

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

// ---------------------------------------------------------------------------
// grant.list

#[test]
fn list_requires_admin_capability() {
    let f = build_fixture();
    let err = ops::dispatch(
        &f.state,
        &scope_for("b", &[Capability::List]),
        NOW,
        "grant.list",
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
fn list_shows_only_grants_whose_exposed_node_this_scope_can_admin() {
    let f = build_fixture();

    // Scoped to "b" (the grant's `to`) with Admin — R2 self-admin — sees it.
    let seen_by_b = ops::dispatch(
        &f.state,
        &scope_for("b", &[Capability::Admin]),
        NOW,
        "grant.list",
        &json!({}),
    )
    .expect("grant.list");
    let grants = seen_by_b["grants"].as_array().expect("grants array");
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0]["id"], GRANT_ID);

    // Scoped to "a" (the grant's `from`) with Admin — no rule reaches "b"
    // from "a" for Admin (R5 descendant-read is opt-in and off by default,
    // and the grant itself only covers `read`, not `admin`) — sees nothing.
    let seen_by_a = ops::dispatch(
        &f.state,
        &scope_for("a", &[Capability::Admin]),
        NOW,
        "grant.list",
        &json!({}),
    )
    .expect("grant.list");
    assert_eq!(
        seen_by_a["grants"].as_array().expect("grants array").len(),
        0,
        "a grant a caller cannot even admin must be absent, not merely redacted"
    );
}

#[test]
fn list_returns_the_documented_grant_shape() {
    let f = build_fixture();
    let response = ops::dispatch(
        &f.state,
        &scope_for("b", &[Capability::Admin]),
        NOW,
        "grant.list",
        &json!({}),
    )
    .expect("grant.list");
    let grant = &response["grants"].as_array().expect("grants array")[0];
    assert_eq!(grant["id"], GRANT_ID);
    assert_eq!(grant["from"], "a");
    assert_eq!(grant["to"]["kind"], "node");
    assert_eq!(grant["to"]["nodeId"], "b");
    assert_eq!(grant["direction"], "one-way");
    assert_eq!(grant["scope"], json!(["read"]));
    assert!(grant["expiresAt"].is_null());
    assert_eq!(grant["reason"], "a's deploy job needs b's registry token");
}

// ---------------------------------------------------------------------------
// grant.create

fn valid_create_params() -> serde_json::Value {
    json!({
        "from": "a",
        "to": { "kind": "node", "nodeId": "b" },
        "scope": ["read"],
        "reason": "a's deploy job needs b's registry token",
    })
}

#[test]
fn create_rejects_a_short_reason() {
    let f = build_fixture();
    let mut params = valid_create_params();
    params["reason"] = json!("short");
    let err = ops::dispatch(
        &f.state,
        &scope_for("b", &[Capability::Admin]),
        NOW,
        "grant.create",
        &params,
    )
    .unwrap_err();
    assert!(matches!(err, OpError::Malformed(_)));
}

#[test]
fn create_rejects_orphan_as_either_endpoint() {
    let f = build_fixture();

    let mut to_orphan = valid_create_params();
    to_orphan["to"] = json!({ "kind": "node", "nodeId": "orphan" });
    let err = ops::dispatch(
        &f.state,
        &scope_for("b", &[Capability::Admin]),
        NOW,
        "grant.create",
        &to_orphan,
    )
    .unwrap_err();
    assert!(matches!(err, OpError::Malformed(_)), "grant TO orphan");

    let mut from_orphan = valid_create_params();
    from_orphan["from"] = json!("orphan");
    let err = ops::dispatch(
        &f.state,
        &scope_for("b", &[Capability::Admin]),
        NOW,
        "grant.create",
        &from_orphan,
    )
    .unwrap_err();
    assert!(matches!(err, OpError::Malformed(_)), "grant FROM orphan");
}

#[test]
fn create_rejects_scope_outside_read_reveal_notes() {
    let f = build_fixture();
    let mut params = valid_create_params();
    params["scope"] = json!(["admin"]);
    let err = ops::dispatch(
        &f.state,
        &scope_for("b", &[Capability::Admin]),
        NOW,
        "grant.create",
        &params,
    )
    .unwrap_err();
    assert!(
        matches!(err, OpError::Malformed(_)),
        "03_DATA_MODEL.md §6's Grant.scope type is (read|reveal|notes)[] only"
    );
}

#[test]
fn create_requires_admin_capability() {
    let f = build_fixture();
    let err = ops::dispatch(
        &f.state,
        &scope_for("b", &[Capability::List]),
        NOW,
        "grant.create",
        &valid_create_params(),
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
fn create_denies_when_caller_cannot_admin_the_exposed_node() {
    let f = build_fixture();
    // Scoped to "a", trying to expose "b" — no rule gives "a" Admin over "b".
    let err = ops::dispatch(
        &f.state,
        &scope_for("a", &[Capability::Admin]),
        NOW,
        "grant.create",
        &valid_create_params(),
    )
    .unwrap_err();
    assert!(matches!(err, OpError::NodeAccessDenied { rule: "R8", .. }));
}

#[test]
fn create_is_presence_required_once_every_other_invariant_holds() {
    let f = build_fixture();
    let err = ops::dispatch(
        &f.state,
        &scope_for("b", &[Capability::Admin]),
        NOW,
        "grant.create",
        &valid_create_params(),
    )
    .unwrap_err();
    assert!(
        matches!(&err, OpError::PresenceRequired { operation } if operation == "grant.create"),
        "correct but blocked, same shape as node.reparent and audit.get: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// grant.revoke

#[test]
fn revoke_requires_admin_capability() {
    let f = build_fixture();
    let err = ops::dispatch(
        &f.state,
        &scope_for("b", &[Capability::List]),
        NOW,
        "grant.revoke",
        &json!({ "id": GRANT_ID }),
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
fn revoke_unknown_id_is_not_found() {
    let f = build_fixture();
    let err = ops::dispatch(
        &f.state,
        &scope_for("b", &[Capability::Admin]),
        NOW,
        "grant.revoke",
        &json!({ "id": "g_does_not_exist" }),
    )
    .unwrap_err();
    assert!(matches!(err, OpError::NotFound(_)));
}

#[test]
fn revoke_denies_when_caller_cannot_admin_the_exposed_node() {
    let f = build_fixture();
    let err = ops::dispatch(
        &f.state,
        &scope_for("a", &[Capability::Admin]),
        NOW,
        "grant.revoke",
        &json!({ "id": GRANT_ID }),
    )
    .unwrap_err();
    assert!(matches!(err, OpError::NodeAccessDenied { rule: "R8", .. }));

    // Denial teaches nothing about the id's existence either way — the
    // grant must still be present.
    let registry = f.state.registry.read().unwrap();
    assert!(registry.grants.iter().any(|g| g.id == GRANT_ID));
}

#[test]
fn revoke_actually_removes_the_grant_and_a_second_revoke_is_not_found() {
    let f = build_fixture();
    let response = ops::dispatch(
        &f.state,
        &scope_for("b", &[Capability::Admin]),
        NOW,
        "grant.revoke",
        &json!({ "id": GRANT_ID }),
    )
    .expect("revoke succeeds while holding Admin over the exposed node");
    assert_eq!(response["id"], GRANT_ID);
    assert_eq!(response["revoked"], json!(true));

    {
        let registry = f.state.registry.read().unwrap();
        assert!(
            !registry.grants.iter().any(|g| g.id == GRANT_ID),
            "the grant must actually be gone, not merely reported as revoked"
        );
    }

    // I-6's own claim, restated for this op specifically: the very next
    // request sees the revocation, and revoking twice is not_found, not a
    // silent double-success.
    let second = ops::dispatch(
        &f.state,
        &scope_for("b", &[Capability::Admin]),
        NOW,
        "grant.revoke",
        &json!({ "id": GRANT_ID }),
    )
    .unwrap_err();
    assert!(matches!(second, OpError::NotFound(_)));
}
