//! The isolation suite — `docs/13_TEST_PLAN.md §3`. Phase 3's actual gate:
//! each test corresponds to a claim in `docs/05_THREAT_MODEL.md §3`, and a
//! claim without a test here is a hope, not a claim.
//!
//! **Coverage in THIS file:** I-1, I-2, I-3, I-4, I-5, I-6, I-7, I-8, I-9,
//! I-11, I-12, I-14, I-15, I-16, I-18, I-19, I-20, I-21, I-22, I-23, I-24,
//! I-25, and (ADR-078, the multi-field entry model) I-27, I-28, I-29.
//!
//! **Elsewhere in the workspace** (this list is the whole suite's index — keep
//! it true, a coverage note that lags the code is how a gap hides in plain
//! sight):
//! - **I-13** — `crates/mcp/tests/i13_tool_registry.rs`. Written once the MCP
//!   tool registry existed in Phase 4; it walks the live `tools::registry()`,
//!   not a copy. This note previously still said "unbuilt until Phase 4" long
//!   after Phase 4 shipped — corrected by the Phase 8 audit.
//! - **I-17** — `crates/core/tests/isolation_i17.rs`. resolve()'s random-graph
//!   fuzz is a pure access-graph property, not a broker one.
//!
//! **Still not implemented anywhere: I-10.** Its first half (a sealed node's
//! values are unreachable on every transport this build has) *is* proven —
//! `i21_seal_then_restore_…` and `i21b_…` here, plus
//! `crates/cli/tests/success_criteria.rs`'s criterion 2 over a real socket.
//! Its second half — "names remain listable" via native-with-presence — is not
//! testable yet because no transport can set `presence_attested: true` (the
//! same honest gap ADR-046 names for the hardware keystores). Tracked as a
//! known risk in `docs/PHASE8_AUDIT_REPORT.md`; do not mark I-10 done until a
//! native transport exists to make the positive path real.
//!
//! Fixture: `docs/06_ACCESS_GRAPH.md §2`'s own worked example — Global;
//! projects A, B, C, D; sub-nodes X, Y under A; one human grant X → B
//! (list+read, not reveal). Using the doc's own graph means every assertion
//! here can be checked directly against that section's table.

use std::sync::Arc;
use std::time::Instant;

use secrecy::SecretBox;

use credmgr_brokerd::ops;
use credmgr_brokerd::protocol::OpError;
use credmgr_brokerd::scope::{self, BrokerScope};
use credmgr_brokerd::server;
use credmgr_brokerd::state::BrokerState;
use credmgr_core::access::Origin;
use credmgr_core::inference::EntryType;
use credmgr_core::registry::{
    Capability, Direction, Grant, GrantTarget, Node, NodeKind, NodePolicy, Registry, GLOBAL_ID,
    ORPHAN_ID,
};
use credmgr_keystore::software::SoftwareKeystore;
use credmgr_store::manifest::{Counts, ManifestBody, ManifestEntry, Sensitivity};

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

fn one_entry_manifest(node_id: &str, entry_id: &str, name: &str) -> ManifestBody {
    ManifestBody {
        node_id: node_id.to_string(),
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

/// Seals `plaintext` to `node_id`'s own public key and writes the real
/// envelope file the broker will later read back at `entry.reveal` —
/// `crates/core::envelope`'s real seal/open, `crates/store::atomic`'s real
/// file I/O, not stand-ins.
fn seed_entry(
    state: &BrokerState,
    root_key: &SecretBox<[u8; 32]>,
    node_id: &str,
    entry_id: &str,
    plaintext: &[u8],
) {
    let node_pub = state.seed_node_key(root_key, node_id);
    let envelope = credmgr_core::envelope::seal(plaintext, &node_pub, node_id, entry_id)
        .expect("seal of a small fixed payload cannot fail");
    let path = state.paths.entry_env(node_id, entry_id);
    credmgr_store::atomic::write(&path, &envelope).expect("writing the fixture envelope");
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
    reg.nodes.insert(ORPHAN_ID.to_string(), Node::orphan());
    for id in ["a", "b", "c", "d"] {
        reg.nodes.insert(id.to_string(), depth1(id));
    }
    reg.nodes.insert("x".to_string(), depth2("x", "a"));
    reg.nodes.insert("y".to_string(), depth2("y", "a"));
    reg.grants.push(Grant {
        id: "g_x_to_b".to_string(),
        from: "x".to_string(),
        to: GrantTarget::Node {
            node_id: "b".to_string(),
        },
        direction: Direction::OneWay,
        scope: vec![Capability::List, Capability::Read],
        expires_at: None,
        reason: "isolation suite fixture".to_string(),
    });
    state.set_registry(reg);
    // Every node, including orphan, has a real keypair (`04_CRYPTO_AND_KEYS.md
    // §2`) — seal (I-21) needs orphan's public key to reseal into.
    state.seed_node_key(&root_key, ORPHAN_ID);

    for id in ["a", "b", "x", "y"] {
        let entry_id = format!("e_{id}1");
        state.set_manifest(
            id,
            one_entry_manifest(id, &entry_id, &format!("{id}_SECRET")),
        );
        seed_entry(
            &state,
            &root_key,
            id,
            &entry_id,
            format!("{id}-secret-value").as_bytes(),
        );
    }

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

const FULL: &[Capability] = &[
    Capability::List,
    Capability::Read,
    Capability::Reveal,
    Capability::Create,
    Capability::Update,
];

// ---------------------------------------------------------------------------
// I-1

#[test]
fn i1_cross_node_reveal_is_denied_with_no_leak() {
    let f = build_fixture();
    f.state.unlock(0).expect("unlock");
    let scope = scope_for("a", FULL);
    let err = ops::dispatch(
        &f.state,
        &scope,
        NOW,
        "entry.reveal",
        &serde_json::json!({ "node": "b", "entry": "e_b1" }),
    )
    .unwrap_err();
    match err {
        OpError::NodeAccessDenied {
            subject,
            target,
            rule,
            capability,
            ..
        } => {
            assert_eq!(subject, "a");
            assert_eq!(target, "b");
            assert_eq!(rule, "R8");
            assert_eq!(capability, Capability::Reveal);
        }
        other => panic!("expected NodeAccessDenied, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// I-2 (per-node calls; see module doc for why this isn't one aggregate call)

#[test]
fn i2_entry_list_covers_self_and_global_never_out_of_scope() {
    let f = build_fixture();
    f.state.unlock(0).expect("unlock");
    let scope = scope_for("a", FULL);

    let a_list = ops::dispatch(
        &f.state,
        &scope,
        NOW,
        "entry.list",
        &serde_json::json!({ "node": "a" }),
    )
    .expect("a can list itself");
    assert_eq!(a_list["ids"], serde_json::json!(["e_a1"]));

    ops::dispatch(
        &f.state,
        &scope,
        NOW,
        "entry.list",
        &serde_json::json!({ "node": GLOBAL_ID }),
    )
    .expect("a can list global (R3)");

    let denied = ops::dispatch(
        &f.state,
        &scope,
        NOW,
        "entry.list",
        &serde_json::json!({ "node": "b" }),
    )
    .unwrap_err();
    assert!(matches!(
        denied,
        OpError::NodeAccessDenied { rule: "R8", .. }
    ));
}

// ---------------------------------------------------------------------------
// I-3

#[test]
fn i3_search_only_matches_in_out_of_scope_node_returns_zero_results_same_as_no_match() {
    let f = build_fixture();
    f.state.unlock(0).expect("unlock");
    let scope = scope_for("a", FULL);

    // "b_SECRET" exists — but only on node `b`, which `a` cannot reach (R8).
    let out_of_scope = ops::dispatch(
        &f.state,
        &scope,
        NOW,
        "search",
        &serde_json::json!({ "term": "b_SECRET" }),
    )
    .expect("search itself is not an error, even when it finds nothing reachable");
    let out_of_scope_results = out_of_scope["results"].as_array().expect("results array");
    assert!(
        out_of_scope_results.is_empty(),
        "a term that matches only inside an unreachable node must yield zero results"
    );

    // A term that matches literally nowhere in the vault gets the exact same
    // shape — the result count is not allowed to distinguish "exists, but
    // you can't see it" from "does not exist at all" (I-3's stated assertion).
    let no_match = ops::dispatch(
        &f.state,
        &scope,
        NOW,
        "search",
        &serde_json::json!({ "term": "no-such-entry-anywhere-zzz" }),
    )
    .expect("search for a nonexistent term is not an error either");
    assert_eq!(
        out_of_scope["results"], no_match["results"],
        "out-of-scope match and true non-match must be byte-identical responses"
    );

    // A term reachable from `a`'s own scope (itself + Global; `x`/`y`/`b`/`c`/`d`
    // are not, by default policy) is found, and *only* the in-scope hit.
    let in_scope = ops::dispatch(
        &f.state,
        &scope,
        NOW,
        "search",
        &serde_json::json!({ "term": "SECRET" }),
    )
    .expect("search within scope succeeds");
    let in_scope_results = in_scope["results"].as_array().expect("results array");
    assert_eq!(
        in_scope_results.len(),
        1,
        "only a's own entry matches 'SECRET' from a's scope, not x/y/b/c/d's"
    );
    assert_eq!(in_scope_results[0]["node"], "a");
    assert_eq!(in_scope_results[0]["name"], "a_SECRET");
}

// ---------------------------------------------------------------------------
// I-4

#[test]
fn i4_subnode_reads_parent_and_sibling_and_global_never_other_projects() {
    let f = build_fixture();
    f.state.unlock(0).expect("unlock");
    let x = scope_for("x", FULL);

    for (target, expect_allow, why) in [
        ("a", true, "R4 ancestor"),
        ("y", true, "R6 sibling"),
        (GLOBAL_ID, true, "R3 global"),
        ("c", false, "isolated project"),
        ("d", false, "isolated project"),
    ] {
        let result = ops::dispatch(
            &f.state,
            &x,
            NOW,
            "entry.list",
            &serde_json::json!({ "node": target }),
        );
        assert_eq!(result.is_ok(), expect_allow, "{target}: {why}");
    }
    // "b" is reachable only via the grant, at `list`/`read` — covered by I-5.
}

// ---------------------------------------------------------------------------
// I-5

#[test]
fn i5_grant_covers_list_and_read_not_reveal_and_does_not_extend_to_the_sibling() {
    let f = build_fixture();
    f.state.unlock(0).expect("unlock");
    let x = scope_for("x", FULL);
    let y = scope_for("y", FULL);

    ops::dispatch(
        &f.state,
        &x,
        NOW,
        "entry.list",
        &serde_json::json!({ "node": "b" }),
    )
    .expect("x can list b via the grant");

    let reveal_denied = ops::dispatch(
        &f.state,
        &x,
        NOW,
        "entry.reveal",
        &serde_json::json!({ "node": "b", "entry": "e_b1" }),
    )
    .unwrap_err();
    assert!(
        matches!(reveal_denied, OpError::NodeAccessDenied { rule: "R8", .. }),
        "the grant's scope is [list, read], not reveal"
    );

    let y_denied = ops::dispatch(
        &f.state,
        &y,
        NOW,
        "entry.list",
        &serde_json::json!({ "node": "b" }),
    )
    .unwrap_err();
    assert!(
        matches!(y_denied, OpError::NodeAccessDenied { rule: "R8", .. }),
        "the grant is x's, not y's, even though x and y are siblings"
    );
}

// ---------------------------------------------------------------------------
// I-6

#[test]
fn i6_revoked_grant_denies_the_very_next_request() {
    let f = build_fixture();
    f.state.unlock(0).expect("unlock");
    let x = scope_for("x", FULL);

    ops::dispatch(
        &f.state,
        &x,
        NOW,
        "entry.list",
        &serde_json::json!({ "node": "b" }),
    )
    .expect("granted, before revocation");

    f.state
        .registry
        .write()
        .expect("registry poisoned")
        .grants
        .retain(|g| g.id != "g_x_to_b");

    let after = ops::dispatch(
        &f.state,
        &x,
        NOW,
        "entry.list",
        &serde_json::json!({ "node": "b" }),
    )
    .unwrap_err();
    assert!(matches!(
        after,
        OpError::NodeAccessDenied { rule: "R8", .. }
    ));
}

// ---------------------------------------------------------------------------
// I-7

#[test]
fn i7_expired_grant_is_denied_and_reported_as_expired() {
    let f = build_fixture();
    f.state.unlock(0).expect("unlock");
    f.state
        .registry
        .write()
        .expect("registry poisoned")
        .grants
        .iter_mut()
        .find(|g| g.id == "g_x_to_b")
        .unwrap()
        .expires_at = Some(NOW - 1);

    let x = scope_for("x", FULL);
    let err = ops::dispatch(
        &f.state,
        &x,
        NOW,
        "entry.list",
        &serde_json::json!({ "node": "b" }),
    )
    .unwrap_err();
    match err {
        OpError::NodeAccessDenied { rule, message, .. } => {
            assert_eq!(rule, "R8");
            assert!(
                message.contains("expired"),
                "message should distinguish expired from absent, got: {message}"
            );
        }
        other => panic!("expected NodeAccessDenied, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// I-8 / I-9

#[test]
fn i8_parent_cannot_read_children_by_default() {
    let f = build_fixture();
    f.state.unlock(0).expect("unlock");
    let a = scope_for("a", FULL);
    let denied = ops::dispatch(
        &f.state,
        &a,
        NOW,
        "entry.list",
        &serde_json::json!({ "node": "x" }),
    )
    .unwrap_err();
    assert!(matches!(
        denied,
        OpError::NodeAccessDenied { rule: "R8", .. }
    ));
}

#[test]
fn i9_descendant_read_opt_in_reaches_children_but_not_other_projects() {
    let f = build_fixture();
    f.state
        .registry
        .write()
        .expect("registry poisoned")
        .nodes
        .get_mut("a")
        .unwrap()
        .policy
        .descendant_read = true;
    f.state.unlock(0).expect("unlock");
    let a = scope_for("a", FULL);

    ops::dispatch(
        &f.state,
        &a,
        NOW,
        "entry.list",
        &serde_json::json!({ "node": "x" }),
    )
    .expect("descendantRead=true now permits a -> x (R5)");

    let still_denied = ops::dispatch(
        &f.state,
        &a,
        NOW,
        "entry.list",
        &serde_json::json!({ "node": "b" }),
    )
    .unwrap_err();
    assert!(matches!(
        still_denied,
        OpError::NodeAccessDenied { rule: "R8", .. }
    ));
}

// ---------------------------------------------------------------------------
// I-11 — cwd-derived scope through the real resolve_scope -> dispatch chain.

#[test]
fn i11_cwd_scoped_agent_cannot_reach_a_different_node_under_any_argument() {
    let f = build_fixture();
    f.state.unlock(0).expect("unlock");
    f.state
        .registry
        .write()
        .expect("registry poisoned")
        .nodes
        .get_mut("a")
        .unwrap()
        .workdirs
        .push("/Users/x/projects/a".to_string());

    let peer = credmgr_brokerd::peer::PeerInfo {
        uid: 501,
        pid: 4242,
        cwd: Some("/Users/x/projects/a/sub/dir".to_string()),
    };
    let (scope, _anomaly) = {
        let registry = f.state.registry.read().expect("registry poisoned");
        scope::resolve_scope(&registry, &f.state.tokens, &peer, None)
    };
    assert_eq!(scope.node_id, "a", "cwd under a's workdir resolves to a");

    let denied = ops::dispatch(
        &f.state,
        &scope,
        NOW,
        "entry.reveal",
        &serde_json::json!({ "node": "b", "entry": "e_b1" }),
    )
    .unwrap_err();
    assert!(matches!(
        denied,
        OpError::NodeAccessDenied { rule: "R8", .. } | OpError::CapabilityNotHeld { .. }
    ));
}

// ---------------------------------------------------------------------------
// I-14

#[test]
fn i14_locked_vault_still_lists_topology_but_reveal_requires_approval() {
    // Adapted per ADR-042: `06_ACCESS_GRAPH.md`'s R1 row and `07_TWO_FACTOR.md
    // §5a` both specify that a `reveal` against a locked-but-otherwise-
    // reachable target returns `approval_pending`, not a flat denial — this
    // test used to assert the pre-F-15 interim behaviour (a flat R1 denial
    // for every locked reveal); it now asserts the documented one.
    let f = build_fixture(); // never unlocked
    let a = scope_for("a", FULL);

    ops::dispatch(
        &f.state,
        &a,
        NOW,
        "entry.list",
        &serde_json::json!({ "node": "a" }),
    )
    .expect("topology/counts stay visible while locked");

    // "a" is reachable via R2 (self) and GLOBAL_ID via R3 — both would be
    // Allow if the vault weren't locked, so both are approval-eligible.
    // ADR-088: a request is recorded only for an entry that exists, so global gets one.
    f.state.insert_manifest_entry(
        GLOBAL_ID,
        ManifestEntry {
            id: "e_g1".to_string(),
            name: "G".to_string(),
            r#ref: 9,
            entry_type: EntryType::Other,
            sensitivity: Sensitivity::Medium,
            field_count: 1,
            sha256: "0".repeat(64),
            modified: NOW,
            expires_at: None,
            rotated_at: None,
            has_totp: false,
        },
    );
    for (target, entry) in [("a", "e_a1"), (GLOBAL_ID, "e_g1")] {
        let denied = ops::dispatch(
            &f.state,
            &a,
            NOW,
            "entry.reveal",
            &serde_json::json!({ "node": target, "entry": entry }),
        )
        .unwrap_err();
        assert!(
            matches!(denied, OpError::ApprovalPending { .. }),
            "target {target}: a locked reveal of an otherwise-reachable target must ask for \
             approval, not deny outright, got {denied:?}"
        );
    }

    // Node "c" has no path to "a" even unlocked (depth-1 projects never
    // share, `01_CONCEPT.md`) — locking the vault must not turn an
    // unreachable target into a notification; it stays an ordinary denial.
    let c = scope_for("c", FULL);
    let denied = ops::dispatch(
        &f.state,
        &c,
        NOW,
        "entry.reveal",
        &serde_json::json!({ "node": "a", "entry": "e_a1" }),
    )
    .unwrap_err();
    assert!(
        matches!(denied, OpError::NodeAccessDenied { rule: "R1", .. }),
        "an always-unreachable target must not become approval-eligible just because the \
         vault is also locked, got {denied:?}"
    );
}

// ---------------------------------------------------------------------------
// I-15 (adapted: Phase 5's TOTP doesn't exist yet, so "wrong factor" is a
// wrong keystore passphrase — same claim, the factor Phase 3 actually has).

#[test]
fn i15_wrong_passphrase_leaves_the_hot_set_empty() {
    let f = build_fixture();
    f.state
        .replace_keystore_for_test(Box::new(SoftwareKeystore::new(
            SecretBox::new(Box::new("definitely not the passphrase".to_string())),
            f._dir.path().join("wrong-keystore-state"),
        )));

    let err = f.state.unlock(0);
    assert!(err.is_err());
    assert!(
        f.state.hot_key_node_ids_for_test().is_empty(),
        "a failed unlock must not populate the hot set"
    );
}

#[test]
fn after_lock_every_hot_set_buffer_is_all_zero() {
    let f = build_fixture();
    f.state
        .unlock(0)
        .expect("unlock with the correct passphrase");
    assert!(!f.state.hot_key_node_ids_for_test().is_empty());

    f.state.lock();
    for node_id in f.state.hot_key_node_ids_for_test() {
        let bytes = f
            .state
            .hot_key_bytes_for_test(&node_id)
            .expect("still present, now zeroed");
        assert_eq!(
            bytes, [0u8; 32],
            "node {node_id}'s hot key must be all-zero"
        );
    }
}

// ---------------------------------------------------------------------------
// I-16

#[test]
fn i16_five_cross_node_denials_in_ten_minutes_trip_the_anomaly() {
    let f = build_fixture();
    f.state.unlock(0).expect("unlock");
    let token = f
        .state
        .tokens
        .issue("a", FULL.to_vec(), Origin::Agent, None);

    let peer = credmgr_brokerd::peer::PeerInfo {
        uid: 501,
        pid: 1,
        cwd: None,
    };
    // Four denials via the real `handle_request` wiring, then check the
    // fifth's return directly — `record_denial` trips exactly on the call
    // that reaches the threshold (rate_limit.rs's own unit tests cover
    // that boundary precisely); this test's job is confirming a denied
    // cross-node request from the real dispatch path feeds the counter at
    // all, not re-deriving the threshold arithmetic.
    for _ in 0..4 {
        let request = credmgr_brokerd::protocol::Request {
            id: "r".to_string(),
            op: "entry.reveal".to_string(),
            token: Some(token.id.clone()),
            params: serde_json::json!({ "node": "b", "entry": "e_b1" }),
        };
        let (result, _) = server::handle_request(&f.state, &peer, &request);
        assert!(
            matches!(result, Err(OpError::NodeAccessDenied { .. })),
            "fixture must actually deny b from a's token for this test to mean anything"
        );
    }
    let tripped = f.state.rate_limiter.record_denial(peer.uid, Instant::now());
    assert!(
        tripped,
        "the fifth cross-node denial in the window must trip the anomaly"
    );
}

// ---------------------------------------------------------------------------
// I-12

#[test]
fn i12_token_workdir_mismatch_proceeds_and_writes_an_anomaly_to_the_audit_log() {
    let f = build_fixture();
    f.state.unlock(0).expect("unlock");
    let token = f.state.tokens.issue(
        "a",
        FULL.to_vec(),
        Origin::Agent,
        Some("/projects/a".to_string()),
    );
    // The presenting process's live cwd disagrees with the token's own
    // recorded `boundWorkdir` — I-12's exact setup.
    let peer = credmgr_brokerd::peer::PeerInfo {
        uid: 501,
        pid: 1,
        cwd: Some("/projects/different".to_string()),
    };
    let request = credmgr_brokerd::protocol::Request {
        id: "r".to_string(),
        op: "entry.list".to_string(),
        token: Some(token.id.clone()),
        params: serde_json::json!({ "node": "a" }),
    };

    let (result, _) = server::handle_request(&f.state, &peer, &request);
    assert!(
        result.is_ok(),
        "a boundWorkdir/cwd mismatch must not block the request — \
         it proceeds under the token, only the mismatch gets logged"
    );

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after 1970")
        .as_secs() as i64;
    let year_month = credmgr_store::audit::year_month_for(now);
    let log_path = f.state.paths.audit_log(&year_month);
    let bytes = std::fs::read(log_path)
        .expect("handle_request must have appended the anomaly to this month's audit log for real");
    // Every request now also appends a generic allow/deny decision record
    // (`server::record_decision`, `10_API_AND_MCP.md §1`'s "every decision...
    // appends one audit record") alongside the anomaly, so this is no longer
    // necessarily the *last* line — find the anomaly record by its own
    // `action`, rather than assume position.
    let record: credmgr_store::audit::AuditRecord = String::from_utf8(bytes)
        .expect("audit log is UTF-8")
        .lines()
        .map(|line| {
            serde_json::from_str::<credmgr_store::audit::AuditRecord>(line)
                .expect("audit record is well-formed JSON")
        })
        .find(|r| r.action == "anomaly.token_workdir_mismatch")
        .expect("the anomaly record must be in this month's log");
    assert_eq!(record.action, "anomaly.token_workdir_mismatch");
    assert_eq!(record.node_id.as_deref(), Some("a"));
    assert!(
        record
            .detail
            .as_deref()
            .unwrap_or("")
            .contains("/projects/different"),
        "the audit detail must name the live cwd that disagreed, got {:?}",
        record.detail
    );
}

// ---------------------------------------------------------------------------
// I-22

#[test]
fn i22_whoami_names_only_reachable_nodes_never_out_of_scope_ones() {
    let f = build_fixture();
    f.state.unlock(0).expect("unlock");
    let y = scope_for("y", FULL);
    let result = ops::dispatch(&f.state, &y, NOW, "whoami", &serde_json::Value::Null).unwrap();
    let reachable: Vec<String> = result["reachable"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();

    for expected in [GLOBAL_ID, "a", "y", "x"] {
        assert!(
            reachable.contains(&expected.to_string()),
            "expected {expected} in {reachable:?}"
        );
    }
    for forbidden in ["b", "c", "d"] {
        assert!(
            !reachable.contains(&forbidden.to_string()),
            "{forbidden} must not appear anywhere in y's whoami payload, got {reachable:?}"
        );
    }
    let payload = serde_json::to_string(&result).unwrap();
    for forbidden in ["\"b\"", "\"c\"", "\"d\""] {
        assert!(
            !payload.contains(forbidden),
            "out-of-scope node id leaked into the serialised whoami payload: {payload}"
        );
    }
}

// ---------------------------------------------------------------------------
// I-24

#[test]
fn i24_entry_level_grant_narrows_list_to_exactly_the_granted_entry() {
    let f = build_fixture();
    // Node "a" gets a second entry, so narrowing has something to exclude.
    {
        let mut manifests = f.state.manifests.write().expect("manifests poisoned");
        let body = manifests.get_mut("a").unwrap();
        body.entries.push(ManifestEntry {
            id: "e_a2".to_string(),
            name: "a_OTHER_SECRET".to_string(),
            r#ref: 2,
            entry_type: EntryType::Other,
            sensitivity: Sensitivity::Medium,
            field_count: 1,
            sha256: "1".repeat(64),
            modified: NOW,
            expires_at: None,
            rotated_at: None,
            has_totp: false,
        });
        body.counts.entries = 2;
    }
    f.state
        .registry
        .write()
        .expect("registry poisoned")
        .grants
        .push(Grant {
            id: "g_b_to_a_entry".to_string(),
            from: "b".to_string(),
            to: GrantTarget::Entry {
                node_id: "a".to_string(),
                entry_id: "e_a1".to_string(),
            },
            direction: Direction::OneWay,
            scope: vec![Capability::List, Capability::Read],
            expires_at: None,
            reason: "I-24 fixture".to_string(),
        });
    f.state.unlock(0).expect("unlock");

    let b = scope_for("b", FULL);
    let result = ops::dispatch(
        &f.state,
        &b,
        NOW,
        "entry.list",
        &serde_json::json!({ "node": "a" }),
    )
    .expect("b can list a via the entry-level grant");
    let ids: Vec<String> = result["ids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        ids,
        vec!["e_a1".to_string()],
        "must be exactly the granted entry, never a's full inventory"
    );
}

// ---------------------------------------------------------------------------
// I-18

#[test]
fn i18_create_while_locked_lands_in_pending_and_update_is_refused_until_accepted() {
    let f = build_fixture();
    // Vault starts locked (default). Node "a" already has entry e_a1 and its
    // node key from `build_fixture`.
    let scope = scope_for("a", FULL);

    let generation_before = f.state.manifest_generation("a").expect("a has a manifest");

    // `entry.create` succeeds while locked (F-1)...
    let created = ops::dispatch(
        &f.state,
        &scope,
        NOW,
        "entry.create",
        &serde_json::json!({ "node": "a", "name": "a_NEW_SECRET", "value": "sekret" }),
    )
    .expect("create is permitted while locked");
    assert_eq!(created["pending"], serde_json::json!(true));
    let entry_id = created["entry"].as_str().unwrap().to_string();

    // ...and does NOT appear in the manifest, nor move its generation.
    {
        let manifests = f.state.manifests.read().unwrap();
        let body = manifests.get("a").unwrap();
        assert_eq!(body.generation, generation_before);
        assert!(
            !body.entries.iter().any(|e| e.id == entry_id),
            "a locked-vault create must not appear in the manifest until accepted"
        );
    }

    // `entry.update` on the pre-existing entry e_a1 is refused while locked.
    let update_err = ops::dispatch(
        &f.state,
        &scope,
        NOW,
        "entry.update",
        &serde_json::json!({
            "node": "a", "entry": "e_a1", "value": "new-value",
            "generation": generation_before,
        }),
    )
    .unwrap_err();
    assert_eq!(update_err, OpError::VaultLocked);

    // Accepting is also refused while locked — the review step is an
    // at-unlock action (`09_UI_UX_SPEC.md §7`), not a locked-vault write.
    let accept_while_locked = ops::dispatch(
        &f.state,
        &scope,
        NOW,
        "vault.pending_accept",
        &serde_json::json!({ "node": "a", "entry": entry_id }),
    )
    .unwrap_err();
    assert_eq!(accept_while_locked, OpError::VaultLocked);

    // Unlock, then accept.
    f.state.unlock(0).expect("unlock");
    let accepted = ops::dispatch(
        &f.state,
        &scope,
        NOW,
        "vault.pending_accept",
        &serde_json::json!({ "node": "a", "entry": entry_id }),
    )
    .expect("accept after unlock");
    assert_eq!(accepted["accepted"], serde_json::json!(true));

    // The entry appears exactly once in the manifest, generation advanced by one.
    let manifests = f.state.manifests.read().unwrap();
    let body = manifests.get("a").unwrap();
    let matches = body.entries.iter().filter(|e| e.id == entry_id).count();
    assert_eq!(matches, 1, "accepted entry must appear exactly once");
    assert_eq!(body.generation, generation_before + 1);
}

// ---------------------------------------------------------------------------
// I-25

#[test]
fn i25_concurrent_writers_same_starting_generation_exactly_one_wins() {
    let f = build_fixture();
    f.state.unlock(0).expect("unlock");
    let starting_generation = f.state.manifest_generation("a").expect("a has a manifest");

    const WRITERS: usize = 16;
    let barrier = Arc::new(std::sync::Barrier::new(WRITERS));
    let handles: Vec<_> = (0..WRITERS)
        .map(|i| {
            let state = Arc::clone(&f.state);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let scope = scope_for("a", FULL);
                // Maximise real overlap: every writer arrives at the
                // dispatch call at (as close to) the same instant.
                barrier.wait();
                ops::dispatch(
                    &state,
                    &scope,
                    NOW,
                    "entry.update",
                    &serde_json::json!({
                        "node": "a", "entry": "e_a1",
                        "value": format!("writer-{i}"),
                        "generation": starting_generation,
                    }),
                )
            })
        })
        .collect();

    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let successes = results.iter().filter(|r| r.is_ok()).count();
    let conflicts = results
        .iter()
        .filter(|r| matches!(r, Err(OpError::Conflict { .. })))
        .count();

    assert_eq!(successes, 1, "exactly one writer should win the race");
    assert_eq!(
        conflicts,
        WRITERS - 1,
        "every other writer must see conflict, never a silently lost write"
    );

    let final_generation = f.state.manifest_generation("a").unwrap();
    assert_eq!(
        final_generation,
        starting_generation + 1,
        "no lost writes and no double-application — exactly one generation bump"
    );
}

// ---------------------------------------------------------------------------
// I-21

const DAY: i64 = 24 * 60 * 60;

#[test]
fn i21_seal_then_restore_day_6_succeeds_byte_identical_day_8_is_gone() {
    let f = build_fixture();
    f.state.unlock(0).expect("unlock");
    let admin = scope_for("a", &[Capability::Admin]);

    // Seal "a" — its one entry (e_a1, "a-secret-value") moves to orphan.
    let sealed = ops::dispatch(
        &f.state,
        &admin,
        NOW,
        "node.seal",
        &serde_json::json!({ "node": "a" }),
    )
    .expect("seal succeeds while unlocked, holding Admin");
    assert_eq!(sealed["sealed"], serde_json::json!(true));

    {
        let registry = f.state.registry.read().unwrap();
        assert!(
            !registry.nodes.contains_key("a"),
            "sealed node leaves the graph entirely"
        );
    }
    {
        let manifests = f.state.manifests.read().unwrap();
        let orphan = manifests
            .get(ORPHAN_ID)
            .expect("orphan manifest exists after a seal");
        assert!(
            orphan.entries.iter().any(|e| e.id == "e_a1"),
            "the sealed entry's name stays listable under orphan"
        );
    }

    // Unreachable to anyone — R0, before any grant or rule could apply.
    let outsider = scope_for("b", FULL);
    let denied = ops::dispatch(
        &f.state,
        &outsider,
        NOW,
        "entry.reveal",
        &serde_json::json!({ "node": ORPHAN_ID, "entry": "e_a1" }),
    )
    .unwrap_err();
    assert!(matches!(
        denied,
        OpError::NodeAccessDenied { rule: "R0", .. }
    ));

    // Day 6: one-click restore succeeds.
    let day6 = NOW + 6 * DAY;
    let restored = ops::dispatch(
        &f.state,
        &admin,
        day6,
        "node.restore",
        &serde_json::json!({ "node": "a" }),
    )
    .expect("day-6 restore succeeds, inside the 7-day window");
    assert_eq!(restored["restored"], serde_json::json!(true));

    {
        let registry = f.state.registry.read().unwrap();
        assert!(registry.nodes.contains_key("a"), "node is reinstated");
    }

    // Byte-identical value, reachable again exactly as before sealing.
    let a_scope = scope_for("a", FULL);
    let revealed = ops::dispatch(
        &f.state,
        &a_scope,
        day6,
        "entry.reveal",
        &serde_json::json!({ "node": "a", "entry": "e_a1" }),
    )
    .expect("restored entry reveals again, from the node itself");
    assert_eq!(revealed["value"], serde_json::json!("a-secret-value"));
    {
        let manifests = f.state.manifests.read().unwrap();
        assert!(
            !manifests
                .get(ORPHAN_ID)
                .is_some_and(|m| m.entries.iter().any(|e| e.id == "e_a1")),
            "restore removes exactly the entries it put into orphan"
        );
    }

    // Seal again, then let the 7-day window lapse on THIS seal.
    ops::dispatch(
        &f.state,
        &admin,
        day6,
        "node.seal",
        &serde_json::json!({ "node": "a" }),
    )
    .expect("re-seal after a successful restore");
    let day8 = day6 + 8 * DAY;
    let expired = ops::dispatch(
        &f.state,
        &admin,
        day8,
        "node.restore",
        &serde_json::json!({ "node": "a" }),
    )
    .unwrap_err();
    assert!(
        matches!(expired, OpError::ArchiveExpired { .. }),
        "past the 7-day window, restore must refuse rather than quietly succeed"
    );
    // The failed attempt must not have disturbed anything sealed.
    let registry = f.state.registry.read().unwrap();
    assert!(
        !registry.nodes.contains_key("a"),
        "a refused restore leaves the node sealed, not half-restored"
    );
}

/// I-21 (companion) — `node.restore` must authorise against the *sealed node*,
/// not merely against "the caller's token happens to carry Admin somewhere".
///
/// `node.seal` resolves `Capability::Admin` against the target node, so an
/// Admin token scoped to an unrelated project `b` cannot seal `a` (R8). Restore
/// is the inverse of the same privileged operation and must be no weaker: if
/// `b` could restore `a`, then `b` could unilaterally undo a security action it
/// was never allowed to take — moving values that a deliberately made
/// human-only (`00_README` "no agent, no CLI, no automation, ever") back into
/// agent reach for whoever *can* read `a`. That is a cross-node integrity
/// violation even though `b` never reads a byte of `a` itself.
///
/// The sealed node has no registry entry left to resolve against — that is the
/// point of having sealed it — so the check resolves against the parent the
/// seal recorded, exactly as `node.create` (ADR-051) resolves Admin against the
/// parent of a node that does not exist yet.
#[test]
fn i21b_restore_is_refused_to_an_admin_token_from_an_unrelated_node() {
    let f = build_fixture();
    f.state.unlock(0).expect("unlock");

    // `a` seals itself — the legitimate path, already proven by I-21.
    let a_admin = scope_for("a", &[Capability::Admin]);
    ops::dispatch(
        &f.state,
        &a_admin,
        NOW,
        "node.seal",
        &serde_json::json!({ "node": "a" }),
    )
    .expect("a's own Admin token seals a");

    // Sanity: `b` could never have sealed `a` in the first place.
    let b_admin = scope_for("b", &[Capability::Admin]);
    let seal_denied = ops::dispatch(
        &f.state,
        &b_admin,
        NOW,
        "node.seal",
        &serde_json::json!({ "node": "c" }),
    )
    .unwrap_err();
    assert!(
        matches!(seal_denied, OpError::NodeAccessDenied { .. }),
        "baseline: an unrelated project's Admin token cannot seal another \
         project, got {seal_denied:?}"
    );

    // The claim under test: restore must be gated the same way.
    let restore_denied = ops::dispatch(
        &f.state,
        &b_admin,
        NOW + DAY,
        "node.restore",
        &serde_json::json!({ "node": "a" }),
    )
    .unwrap_err();
    assert!(
        matches!(restore_denied, OpError::NodeAccessDenied { .. }),
        "an unrelated project's Admin token must not restore another \
         project's sealed node, got {restore_denied:?}"
    );

    // And the refusal must be total, not partial: nothing may have moved.
    {
        let registry = f.state.registry.read().unwrap();
        assert!(
            !registry.nodes.contains_key("a"),
            "a refused restore leaves the node sealed, not half-restored"
        );
    }
    {
        let manifests = f.state.manifests.read().unwrap();
        assert!(
            manifests
                .get(ORPHAN_ID)
                .is_some_and(|m| m.entries.iter().any(|e| e.id == "e_a1")),
            "a refused restore leaves the sealed entry in orphan"
        );
    }

    // The rightful holder is unaffected — this is an authorisation fix, not a
    // functional regression of I-21's own path.
    ops::dispatch(
        &f.state,
        &a_admin,
        NOW + DAY,
        "node.restore",
        &serde_json::json!({ "node": "a" }),
    )
    .expect("a's own Admin token still restores a");
}

// ---------------------------------------------------------------------------
// I-23

#[test]
fn i23_reparent_refuses_on_every_phase3_surface_admin_included() {
    let f = build_fixture();
    f.state.unlock(0).expect("unlock");

    for origin in [Origin::Cli, Origin::Agent, Origin::HumanUi, Origin::Native] {
        let scope = BrokerScope {
            node_id: "x".to_string(),
            capabilities: vec![Capability::Admin],
            origin,
            token_id: None,
            bound_workdir: None,
        };
        let err = ops::dispatch(
            &f.state,
            &scope,
            NOW,
            "node.reparent",
            &serde_json::json!({
                "node": "x", "newParent": "b",
                "reason": "moving to align with acme",
            }),
        )
        .unwrap_err();
        assert!(
            matches!(err, OpError::PresenceRequired { .. }),
            "origin {origin:?}: Phase 3 has no presence-attestation transport, \
             so reparent must always refuse — got {err:?}"
        );
    }

    // Weaker gates are checked, and fail, before presence is ever reached.
    let short_reason = ops::dispatch(
        &f.state,
        &scope_for("x", &[Capability::Admin]),
        NOW,
        "node.reparent",
        &serde_json::json!({ "node": "x", "newParent": "b", "reason": "short" }),
    )
    .unwrap_err();
    assert!(matches!(short_reason, OpError::Malformed(_)));

    let no_admin = ops::dispatch(
        &f.state,
        &scope_for("x", FULL),
        NOW,
        "node.reparent",
        &serde_json::json!({
            "node": "x", "newParent": "b",
            "reason": "moving to align with acme",
        }),
    )
    .unwrap_err();
    assert!(matches!(
        no_admin,
        OpError::CapabilityNotHeld {
            capability: Capability::Admin
        }
    ));

    // The graph is untouched by every refused attempt.
    let registry = f.state.registry.read().unwrap();
    assert_eq!(
        registry.nodes.get("x").unwrap().parent_id.as_deref(),
        Some("a"),
        "no refused reparent may have moved the node"
    );
}

// ---------------------------------------------------------------------------
// I-19 / I-20 — `BrokerState::verify_and_load_vault`, the broker-start
// integrity check (`04_CRYPTO_AND_KEYS.md §6a`). Unlike every other test in
// this file, these exercise a *real on-disk* vault directory via
// `credmgr_store::registry_file::save`/`manifest::save`, not the in-memory
// `build_fixture()` — the whole point is proving the broker refuses what is
// actually sitting on disk, not what a test seeded directly into memory.

fn node_doc(node: Node) -> credmgr_store::registry_file::NodeDoc {
    credmgr_store::registry_file::NodeDoc {
        node,
        created: NOW,
        gate: credmgr_store::registry_file::GateDoc::default(),
        pinned: None,
        public_key: "11".repeat(32),
    }
}

/// Writes a real, validly-signed one-node vault to `paths` and returns the
/// root key used to sign it, ready for `verify_and_load_vault`.
fn write_real_vault(paths: &credmgr_store::paths::VaultPaths) -> [u8; 32] {
    let root_key = [9u8; 32];

    let manifest_a = one_entry_manifest("a", "e_a1", "a_SECRET");
    let binding =
        credmgr_store::manifest::save(paths, &root_key, &manifest_a).expect("save manifest a");

    let mut doc = credmgr_store::registry_file::RegistryDocument::new();
    doc.nodes.insert("a".to_string(), node_doc(depth1("a")));
    doc.vault_generation = 1;
    doc.manifests.insert("a".to_string(), binding);
    credmgr_store::registry_file::save(paths, &root_key, &doc).expect("save registry");

    root_key
}

#[test]
fn i19_tampered_manifest_is_refused_at_broker_open_naming_the_node() {
    let dir = tempfile::tempdir().expect("tempdir");
    let paths = credmgr_store::paths::VaultPaths::new(dir.path().join("vault"));
    let root_key = write_real_vault(&paths);
    let counter = credmgr_store::generation::FileGenerationCounter::new(dir.path().join("state"));

    let keystore = Box::new(SoftwareKeystore::new(
        SecretBox::new(Box::new("correct horse battery staple".to_string())),
        dir.path().join("keystore-state"),
    ));
    let state = BrokerState::new(keystore, paths.clone());

    // The untampered vault loads cleanly first — proves the failure below
    // comes from the tamper, not from a fixture mistake.
    state
        .verify_and_load_vault(&root_key, &counter)
        .expect("a freshly-written, untampered vault must load");

    // Hand-edit manifest.json: bump the entry count without re-signing —
    // exactly "remove an entry / bump a count" from I-19's setup.
    let manifest_path = paths.manifest("a");
    let mut raw: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
    raw["counts"]["entries"] = serde_json::json!(999);
    std::fs::write(&manifest_path, serde_json::to_vec_pretty(&raw).unwrap()).unwrap();

    let err = state
        .verify_and_load_vault(&root_key, &counter)
        .expect_err("a hand-edited manifest must be refused, not silently trusted");
    match err {
        credmgr_store::StoreError::ManifestTampered { node_id } => {
            assert_eq!(node_id, "a", "the refusal must name the tampered node");
        }
        other => panic!("expected ManifestTampered, got {other:?}"),
    }

    // Refusal must not have partially loaded state — the graph this broker
    // would render stays exactly what it was before the tamper (empty, in
    // this fresh `BrokerState`), never a half-applied update.
    assert!(
        state
            .registry
            .read()
            .unwrap()
            .nodes
            .get("a")
            .is_some_and(|n| n.id == "a"),
        "the last *good* load's state survives a later failed reload"
    );
}

#[test]
fn i20_rolled_back_registry_is_refused_on_the_generation_check() {
    let dir = tempfile::tempdir().expect("tempdir");
    let paths = credmgr_store::paths::VaultPaths::new(dir.path().join("vault"));
    let root_key = [9u8; 32];
    let counter = credmgr_store::generation::FileGenerationCounter::new(dir.path().join("state"));

    let keystore = Box::new(SoftwareKeystore::new(
        SecretBox::new(Box::new("correct horse battery staple".to_string())),
        dir.path().join("keystore-state"),
    ));
    let state = BrokerState::new(keystore, paths.clone());

    // Distinguishable entry names per vault-write, so later assertions can
    // tell *which* on-disk snapshot the broker actually has loaded, rather
    // than a value ("generation: 1") that happens to be constant across
    // every write this fixture makes and so would pass whether or not the
    // refusal actually left state alone.
    let save_at = |vault_generation: u64, entry_name: &str| {
        let manifest = one_entry_manifest("a", "e_a1", entry_name);
        let binding =
            credmgr_store::manifest::save(&paths, &root_key, &manifest).expect("save manifest");
        let mut doc = credmgr_store::registry_file::RegistryDocument::new();
        doc.nodes.insert("a".to_string(), node_doc(depth1("a")));
        doc.vault_generation = vault_generation;
        doc.manifests.insert("a".to_string(), binding);
        credmgr_store::registry_file::save(&paths, &root_key, &doc).expect("save registry");
    };

    // Generation 1, first-ever load — the ordinary "broker starts" path,
    // which also seeds the external counter to 1.
    save_at(1, "a_SECRET_gen1");
    state
        .verify_and_load_vault(&root_key, &counter)
        .expect("generation 1 loads and advances the external counter");

    // A grant gets revoked and the vault genuinely moves forward to
    // generation 2 — a normal write, advancing the external counter to 2.
    save_at(2, "a_SECRET_gen2");
    state
        .verify_and_load_vault(&root_key, &counter)
        .expect("generation 2 loads and advances the external counter to 2");

    // Now a stale-but-validly-signed generation-1 copy reappears on disk —
    // "a revoked grant reappears in it" in spirit: an attacker, or an
    // accidental backup restore, reinstates an older, legitimately-signed
    // state. Deliberately reuses the gen-1 entry name, distinct from gen-2's,
    // so a bug that silently accepted this write would be observable below.
    save_at(1, "a_SECRET_gen1");

    let err = state
        .verify_and_load_vault(&root_key, &counter)
        .expect_err("a rolled-back registry must be refused even though its signature verifies");
    assert!(
        matches!(
            err,
            credmgr_store::StoreError::GenerationRolledBack {
                on_disk: 1,
                external: 2,
            }
        ),
        "expected GenerationRolledBack{{on_disk: 1, external: 2}}, got {err:?}"
    );

    // The broker's last-known-good state — generation 2's data — is
    // untouched by the refused reload: still the gen-2 entry name, never
    // silently replaced by the replayed gen-1 snapshot.
    let manifests = state.manifests.read().unwrap();
    assert_eq!(
        manifests.get("a").unwrap().entries[0].name,
        "a_SECRET_gen2",
        "a refused reload must leave the last verified state exactly as it was"
    );
}

// ---------------------------------------------------------------------------
// I-27 .. I-29 — the multi-field entry model (ADR-078).
//
// These live in this file because it is the one `security.yml` runs as the
// security gate: a new op that reads or writes an entry's fields must be inside
// the same graph, the same lock rules and the same envelope authentication as
// every op before it.

/// The five ops ADR-078 added, each with a body that would succeed for the owner of
/// node `a` — so a refusal below is the graph's, never a malformed request's.
fn field_calls(generation: u64) -> Vec<(&'static str, serde_json::Value)> {
    vec![
        (
            "entry.get",
            serde_json::json!({ "node": "a", "entry": "e_a1" }),
        ),
        (
            "field.add",
            serde_json::json!({ "node": "a", "entry": "e_a1", "generation": generation,
                "fields": [{ "label": "extra", "value": "extra-value" }] }),
        ),
        (
            "field.update",
            serde_json::json!({ "node": "a", "entry": "e_a1", "generation": generation,
                "field": "f_00000000", "patch": { "label": "renamed" } }),
        ),
        (
            "field.remove",
            serde_json::json!({ "node": "a", "entry": "e_a1", "generation": generation,
                "field": "f_00000000" }),
        ),
        (
            "field.reorder",
            serde_json::json!({ "node": "a", "entry": "e_a1", "generation": generation,
                "order": ["f_00000000"] }),
        ),
    ]
}

#[test]
fn i27_entry_get_and_field_ops_obey_the_access_graph() {
    let f = build_fixture();
    f.state.unlock(0).expect("unlock");
    let generation = f.state.manifest_generation("a").expect("a has a manifest");

    // Control: the owner of `a` can use every one of them on `a`'s own entry (the fixture's
    // entry is a legacy version-1 value, so this also exercises the upgrade path).
    let owner = scope_for("a", FULL);
    let got = ops::dispatch(
        &f.state,
        &owner,
        NOW,
        "entry.get",
        &serde_json::json!({ "node": "a", "entry": "e_a1" }),
    )
    .expect("the owner reads its own entry's metadata");
    assert!(
        !got.to_string().contains("a-secret-value"),
        "entry.get never returns a value: {got}"
    );
    ops::dispatch(
        &f.state,
        &owner,
        NOW,
        "field.add",
        &field_calls(generation)[1].1,
    )
    .expect("and adds a field to it");

    // A scope rooted in B reaches nothing of A's through any of the five — and the refusal has
    // the same shape `entry.update` gives (R8, the node-level denial), not a different one.
    let generation = f.state.manifest_generation("a").unwrap();
    let in_b = scope_for("b", FULL);
    let update_err = ops::dispatch(
        &f.state,
        &in_b,
        NOW,
        "entry.update",
        &serde_json::json!({ "node": "a", "entry": "e_a1", "generation": generation, "value": "x" }),
    )
    .unwrap_err();
    assert!(
        matches!(update_err, OpError::NodeAccessDenied { rule: "R8", .. }),
        "{update_err:?}"
    );
    for (op, params) in field_calls(generation) {
        let err = ops::dispatch(&f.state, &in_b, NOW, op, &params).unwrap_err();
        match err {
            OpError::NodeAccessDenied {
                subject,
                target,
                rule,
                ..
            } => {
                assert_eq!(
                    (subject.as_str(), target.as_str(), rule),
                    ("b", "a", "R8"),
                    "{op}"
                );
            }
            other => panic!("{op}: expected NodeAccessDenied R8, got {other:?}"),
        }
    }
    // For every relationship in the graph — a parent and its child, shared depth-2 siblings, a child
    // and its parent, unrelated projects, a project and global — the five ops get EXACTLY the graph
    // decision `entry.update` gets. A stale generation isolates that decision: the generation check
    // comes after the graph check, so a graph-denied call is `node_access_denied` (with its rule) and
    // a graph-allowed one gets past it (`conflict`, or `ok` for the read-only `entry.get`).
    let class = |r: Result<serde_json::Value, OpError>| match r {
        Err(OpError::NodeAccessDenied { rule, .. }) => format!("denied {rule}"),
        _ => "reached".to_string(),
    };
    let mut seen_denied = false;
    let mut seen_reached = false;
    for (from, to, entry) in [
        ("a", "x", "e_x1"), // parent -> child: parents do not read children
        ("y", "x", "e_x1"), // shared depth-2 siblings
        ("x", "a", "e_a1"), // child -> parent
        ("c", "d", "e_d1"), // unrelated projects
        ("b", "a", "e_a1"), // unrelated projects
        ("x", "b", "e_b1"), // reached only through the grant X -> B (list + read)
    ] {
        let who = scope_for(from, FULL);
        let probe = class(ops::dispatch(
            &f.state,
            &who,
            NOW,
            "entry.update",
            &serde_json::json!({ "node": to, "entry": entry, "generation": u64::MAX, "value": "x" }),
        ));
        for (op, mut params) in field_calls(u64::MAX) {
            params["node"] = serde_json::json!(to);
            params["entry"] = serde_json::json!(entry);
            let got = class(ops::dispatch(&f.state, &who, NOW, op, &params));
            // `entry.get` is a `read`: the X -> B grant carries read, so it is reached even
            // where the `update` probe is denied. Every other op is an `update` and must match.
            let want = if op == "entry.get" && (from, to) == ("x", "b") {
                "reached".to_string()
            } else {
                probe.clone()
            };
            assert_eq!(got, want, "{op}: {from} -> {to}");
            seen_denied |= got.starts_with("denied");
            seen_reached |= got == "reached";
        }
    }
    assert!(
        seen_denied && seen_reached,
        "the table exercises both outcomes"
    );
    // A cwd-derived agent scope (the real resolve_scope -> dispatch chain) is denied on a foreign node too.
    f.state
        .registry
        .write()
        .unwrap()
        .nodes
        .get_mut("b")
        .unwrap()
        .workdirs
        .push("/srv/projects/b".to_string());
    let peer = credmgr_brokerd::peer::PeerInfo {
        uid: 501,
        pid: 4242,
        cwd: Some("/srv/projects/b/sub".to_string()),
    };
    let (agent_in_b, _) = {
        let registry = f.state.registry.read().unwrap();
        scope::resolve_scope(&registry, &f.state.tokens, &peer, None)
    };
    assert_eq!(agent_in_b.node_id, "b");
    for (op, params) in field_calls(generation) {
        let err = ops::dispatch(&f.state, &agent_in_b, NOW, op, &params).unwrap_err();
        assert!(
            matches!(
                err,
                OpError::NodeAccessDenied { rule: "R8", .. } | OpError::CapabilityNotHeld { .. }
            ),
            "{op}: {err:?}"
        );
    }

    // A read-only agent (list, read, reveal): `entry.get` works on its own node; every field
    // write is `capability_not_held` for `update`.
    let read_only = scope_for(
        "a",
        &[Capability::List, Capability::Read, Capability::Reveal],
    );
    let calls = field_calls(f.state.manifest_generation("a").unwrap());
    ops::dispatch(&f.state, &read_only, NOW, calls[0].0, &calls[0].1)
        .expect("a read-only agent reads metadata");
    for (op, params) in &calls[1..] {
        let err = ops::dispatch(&f.state, &read_only, NOW, op, params).unwrap_err();
        assert!(
            matches!(
                err,
                OpError::CapabilityNotHeld {
                    capability: Capability::Update
                }
            ),
            "{op}: {err:?}"
        );
    }

    // The unscoped fallback (global, list only) holds neither `read` nor `update`.
    let list_only = scope_for(GLOBAL_ID, &[Capability::List]);
    for (i, (op, params)) in calls.iter().enumerate() {
        let err = ops::dispatch(&f.state, &list_only, NOW, op, params).unwrap_err();
        let want = if i == 0 {
            Capability::Read
        } else {
            Capability::Update
        };
        assert!(
            matches!(&err, OpError::CapabilityNotHeld { capability } if *capability == want),
            "{op}: {err:?}"
        );
    }
}

#[test]
fn i28_field_ops_and_entry_get_refuse_while_locked() {
    let f = build_fixture();
    // The fixture vault starts locked.
    let owner = scope_for("a", FULL);
    let generation = f.state.manifest_generation("a").unwrap();

    // Whole vault locked: every field write and entry.get is `vault_locked`; no key, no read.
    for (op, params) in field_calls(generation) {
        let err = ops::dispatch(&f.state, &owner, NOW, op, &params).unwrap_err();
        assert_eq!(err, OpError::VaultLocked, "{op}");
    }
    // ...while `entry.create` with fields still lands in the tray (F-1), and says how many fields.
    let tray = ops::dispatch(
        &f.state,
        &owner,
        NOW,
        "entry.create",
        &serde_json::json!({ "node": "a", "name": "a_TRAYED", "fields": [
            { "label": "host", "value": "tray.fields.test" }, { "label": "note", "value": "words" }] }),
    )
    .expect("create is permitted while locked");
    assert_eq!(tray["pending"], serde_json::json!(true));
    assert_eq!(tray["fieldCount"], 2);
    assert_eq!(
        f.state.manifest_generation("a").unwrap(),
        generation,
        "the manifest did not move"
    );

    // One node locked on an otherwise unlocked vault: `node_locked` (ADR-077 G3) — a different code,
    // because the login is not over — for every one of them, and the tray still takes writes.
    f.state.unlock(0).expect("unlock");
    ops::dispatch(
        &f.state,
        &scope_for("a", &[Capability::Admin]),
        NOW,
        "vault.node_lock",
        &serde_json::json!({ "node": "a" }),
    )
    .expect("lock node a");
    for (op, params) in field_calls(generation) {
        let err = ops::dispatch(&f.state, &owner, NOW, op, &params).unwrap_err();
        assert_eq!(
            err,
            OpError::NodeLocked {
                node: "a".to_string()
            },
            "{op}"
        );
    }
    let tray = ops::dispatch(
        &f.state,
        &owner,
        NOW,
        "entry.create",
        &serde_json::json!({ "node": "a", "name": "a_TRAYED_2", "fields": [{ "label": "k", "value": "v" }] }),
    )
    .expect("a locked node still takes a deposit");
    assert_eq!(tray["pending"], serde_json::json!(true));
    // Another node is unaffected by it.
    ops::dispatch(
        &f.state,
        &scope_for("b", FULL),
        NOW,
        "entry.get",
        &serde_json::json!({ "node": "b", "entry": "e_b1" }),
    )
    .expect("node b is not locked");
}

#[test]
fn i29_payload_kind_cannot_be_flipped_or_moved() {
    let f = build_fixture();
    f.state.unlock(0).expect("unlock");
    let owner = scope_for("a", FULL);
    let reveal = |scope: &BrokerScope, node: &str, entry: &str| {
        ops::dispatch(
            &f.state,
            scope,
            NOW,
            "entry.reveal",
            &serde_json::json!({ "node": node, "entry": entry }),
        )
    };

    // A field document written by this build (version 2).
    let created = ops::dispatch(
        &f.state,
        &owner,
        NOW,
        "entry.create",
        &serde_json::json!({ "node": "a", "name": "a_DOC", "fields": [
            { "label": "host", "value": "doc.fields.test" }, { "label": "password", "value": "doc-secret-9f" }] }),
    )
    .expect("create");
    let doc_id = created["entry"].as_str().unwrap().to_string();
    let doc_path = f.state.paths.entry_env("a", &doc_id);
    let doc_bytes = credmgr_store::atomic::read(&doc_path).unwrap();
    assert_eq!(doc_bytes[4], 2, "a field document is a version-2 envelope");
    reveal(&owner, "a", &doc_id).expect("control: it reads");

    // v2 -> v1 on disk: the version byte is in the AAD, so this fails authentication. The JSON
    // text is NEVER returned as if it were a single raw value.
    let mut as_v1 = doc_bytes.clone();
    as_v1[4] = 1;
    credmgr_store::atomic::write(&doc_path, &as_v1).unwrap();
    let flipped = reveal(&owner, "a", &doc_id);
    assert!(
        flipped.is_err(),
        "a relabelled envelope is refused: {flipped:?}"
    );
    assert!(!format!("{flipped:?}").contains("doc-secret-9f"));
    credmgr_store::atomic::write(&doc_path, &doc_bytes).unwrap();

    // v1 -> v2 on a legacy envelope, likewise.
    let legacy_path = f.state.paths.entry_env("a", "e_a1");
    let legacy = credmgr_store::atomic::read(&legacy_path).unwrap();
    assert_eq!(legacy[4], 1);
    let mut as_v2 = legacy.clone();
    as_v2[4] = 2;
    credmgr_store::atomic::write(&legacy_path, &as_v2).unwrap();
    assert!(
        reveal(&owner, "a", "e_a1").is_err(),
        "a v1 envelope relabelled v2 is refused"
    );
    credmgr_store::atomic::write(&legacy_path, &legacy).unwrap();
    assert_eq!(
        reveal(&owner, "a", "e_a1").unwrap()["value"],
        serde_json::json!("a-secret-value"),
        "restored, it reads again"
    );

    // A version-2 envelope copied under another entry id, or into another node, does not open:
    // the entry id and the node id are in the AAD as well.
    credmgr_store::atomic::write(&f.state.paths.entry_env("a", "e_a1"), &doc_bytes).unwrap();
    assert!(
        reveal(&owner, "a", "e_a1").is_err(),
        "moved to another entry id"
    );
    credmgr_store::atomic::write(&legacy_path, &legacy).unwrap();
    credmgr_store::atomic::write(&f.state.paths.entry_env("b", "e_b1"), &doc_bytes).unwrap();
    let in_b = scope_for("b", FULL);
    assert!(reveal(&in_b, "b", "e_b1").is_err(), "moved to another node");

    // None of the refusals above, and no field op on an unrelated entry, reveals the document.
    let shown = format!("{:?}", reveal(&in_b, "b", "e_b1"));
    assert!(
        !shown.contains("doc-secret-9f") && !shown.contains("doc.fields.test"),
        "{shown}"
    );
}
