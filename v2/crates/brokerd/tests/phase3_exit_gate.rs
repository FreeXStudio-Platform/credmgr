//! Phase 3 exit-gate items that are not part of the I-1..I-25 isolation
//! suite (`docs/13_TEST_PLAN.md §3` has no `I-*` row for either of these —
//! confirmed by grep before writing this file) but are named directly in
//! `docs/12_BUILD_PLAN.md` Phase 3's own exit gate:
//!
//! - "Approval-on-demand: locked-vault reveal → notification → one approval
//!   → one value, and the vault is still locked afterwards." (F-15,
//!   `07_TWO_FACTOR.md §5a`, ADR-042.)
//! - "Auto-lock fires on idle, sleep and screen lock." (ADR-030, ADR-043.)
//!
//! Fixture: a trimmed version of `tests/isolation.rs`'s — Global, plus
//! depth-1 projects "a" (a real seeded entry, for the reveal/approval
//! tests) and "c" (unrelated, no relationship to "a", for the "must not
//! notify for something unreachable anyway" cases).

use std::sync::Arc;
use std::time::Instant;

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
    reg.nodes.insert("c".to_string(), depth1("c"));
    state.set_registry(reg);

    let node_pub = state.seed_node_key(&root_key, "a");
    let envelope = credmgr_core::envelope::seal(b"a-secret-value", &node_pub, "a", "e_a1")
        .expect("seal of a small fixed payload cannot fail");
    let path = state.paths.entry_env("a", "e_a1");
    credmgr_store::atomic::write(&path, &envelope).expect("writing the fixture envelope");
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
        },
    );
    state.seed_node_key(&root_key, "b");
    state.seed_node_key(&root_key, "c");

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

fn request_id_from_pending(err: OpError) -> String {
    match err {
        OpError::ApprovalPending { request, .. } => request,
        other => panic!("expected approval_pending, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Approval-on-demand (F-15, ADR-042)

#[test]
fn locked_reveal_of_reachable_target_asks_for_approval_and_retry_reuses_the_same_request() {
    let f = build_fixture(); // never unlocked
    let a = scope_for("a", FULL);

    let first = ops::dispatch(
        &f.state,
        &a,
        NOW,
        "entry.reveal",
        &json!({ "node": "a", "entry": "e_a1" }),
    )
    .unwrap_err();
    let id1 = request_id_from_pending(first);

    let second = ops::dispatch(
        &f.state,
        &a,
        NOW + 5,
        "entry.reveal",
        &json!({ "node": "a", "entry": "e_a1" }),
    )
    .unwrap_err();
    let id2 = request_id_from_pending(second);

    assert_eq!(
        id1, id2,
        "a retry before any decision must not spawn a second notification"
    );
}

#[test]
fn admin_decide_approve_then_retry_returns_the_value_and_the_vault_stays_locked() {
    let f = build_fixture(); // never unlocked

    let requester = scope_for("a", FULL);
    let pending = ops::dispatch(
        &f.state,
        &requester,
        NOW,
        "entry.reveal",
        &json!({ "node": "a", "entry": "e_a1" }),
    )
    .unwrap_err();
    let request_id = request_id_from_pending(pending);

    // The decider is a human, adapted to the factor Phase 3 actually has
    // (ADR-042) — `Capability::Admin` on the request's own node.
    let decider = scope_for("a", &[Capability::Admin]);
    let decided = ops::dispatch(
        &f.state,
        &decider,
        NOW + 10,
        "vault.approval_decide",
        &json!({ "request": request_id, "approved": true }),
    )
    .expect("an admin-capable decider approving a live request must succeed");
    assert_eq!(decided["approved"], json!(true));

    assert!(
        f.state.is_locked(),
        "deciding must not itself unlock the vault"
    );

    let revealed = ops::dispatch(
        &f.state,
        &requester,
        NOW + 20,
        "entry.reveal",
        &json!({ "node": "a", "entry": "e_a1" }),
    )
    .expect("the original requester's retry must now return the value");
    assert_eq!(revealed["value"], json!("a-secret-value"));

    assert!(
        f.state.is_locked(),
        "the vault must still be locked after the value was handed back (07 §5a)"
    );
}

#[test]
fn admin_decide_deny_then_retry_is_refused() {
    let f = build_fixture();
    let requester = scope_for("a", FULL);
    let pending = ops::dispatch(
        &f.state,
        &requester,
        NOW,
        "entry.reveal",
        &json!({ "node": "a", "entry": "e_a1" }),
    )
    .unwrap_err();
    let request_id = request_id_from_pending(pending);

    let decider = scope_for("a", &[Capability::Admin]);
    ops::dispatch(
        &f.state,
        &decider,
        NOW + 10,
        "vault.approval_decide",
        &json!({ "request": request_id, "approved": false }),
    )
    .expect("a denial decision is itself a successful call");

    let retried = ops::dispatch(
        &f.state,
        &requester,
        NOW + 20,
        "entry.reveal",
        &json!({ "node": "a", "entry": "e_a1" }),
    )
    .unwrap_err();
    assert!(
        matches!(
            retried,
            OpError::ApprovalDenied {
                reason: "denied",
                ..
            }
        ),
        "got {retried:?}"
    );
}

#[test]
fn an_undecided_request_defaults_to_denied_once_its_120_second_ttl_passes() {
    let f = build_fixture();
    let requester = scope_for("a", FULL);
    let pending = ops::dispatch(
        &f.state,
        &requester,
        NOW,
        "entry.reveal",
        &json!({ "node": "a", "entry": "e_a1" }),
    )
    .unwrap_err();
    let request_id = request_id_from_pending(pending);

    // `07 §5a`: "It times out in 120 seconds and defaults to deny."
    let retried = ops::dispatch(
        &f.state,
        &requester,
        NOW + 121,
        "entry.reveal",
        &json!({ "node": "a", "entry": "e_a1" }),
    )
    .unwrap_err();
    assert!(
        matches!(
            retried,
            OpError::ApprovalDenied {
                reason: "expired",
                ..
            }
        ),
        "got {retried:?}"
    );

    // The stale request id is gone, not merely marked — a decider trying it
    // late gets `not_found`, not a decision on a request nobody can act on
    // usefully any more.
    let decider = scope_for("a", &[Capability::Admin]);
    let late_decision = ops::dispatch(
        &f.state,
        &decider,
        NOW + 130,
        "vault.approval_decide",
        &json!({ "request": request_id, "approved": true }),
    )
    .unwrap_err();
    assert!(matches!(late_decision, OpError::NotFound(_)));
}

#[test]
fn a_consumed_approval_cannot_be_replayed_a_second_retry_starts_a_fresh_request() {
    let f = build_fixture();
    let requester = scope_for("a", FULL);
    let pending = ops::dispatch(
        &f.state,
        &requester,
        NOW,
        "entry.reveal",
        &json!({ "node": "a", "entry": "e_a1" }),
    )
    .unwrap_err();
    let first_id = request_id_from_pending(pending);

    let decider = scope_for("a", &[Capability::Admin]);
    ops::dispatch(
        &f.state,
        &decider,
        NOW + 10,
        "vault.approval_decide",
        &json!({ "request": first_id, "approved": true }),
    )
    .expect("approve");

    ops::dispatch(
        &f.state,
        &requester,
        NOW + 20,
        "entry.reveal",
        &json!({ "node": "a", "entry": "e_a1" }),
    )
    .expect("first retry consumes the approval and returns the value");

    // A second retry has nothing live to consume — "one entry, one field,
    // once" (`07 §5a`) — so it starts an entirely new request, not a replay
    // of the consumed one.
    let after = ops::dispatch(
        &f.state,
        &requester,
        NOW + 30,
        "entry.reveal",
        &json!({ "node": "a", "entry": "e_a1" }),
    )
    .unwrap_err();
    let second_id = request_id_from_pending(after);
    assert_ne!(
        first_id, second_id,
        "a consumed request id must never be reusable for a second value"
    );
}

#[test]
fn decide_requires_capability_admin_in_the_deciders_own_token() {
    let f = build_fixture();
    let requester = scope_for("a", FULL);
    let pending = ops::dispatch(
        &f.state,
        &requester,
        NOW,
        "entry.reveal",
        &json!({ "node": "a", "entry": "e_a1" }),
    )
    .unwrap_err();
    let request_id = request_id_from_pending(pending);

    let no_admin = scope_for("a", &[Capability::List, Capability::Read]);
    let err = ops::dispatch(
        &f.state,
        &no_admin,
        NOW + 5,
        "vault.approval_decide",
        &json!({ "request": request_id, "approved": true }),
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
fn decide_is_gated_on_admin_for_the_requests_own_node_not_any_node() {
    let f = build_fixture();
    let requester = scope_for("a", FULL);
    let pending = ops::dispatch(
        &f.state,
        &requester,
        NOW,
        "entry.reveal",
        &json!({ "node": "a", "entry": "e_a1" }),
    )
    .unwrap_err();
    let request_id = request_id_from_pending(pending);

    // "c" holds Admin in its own token ceiling, but has no relationship to
    // "a" at all (unrelated depth-1 projects) — Admin on "c" does not imply
    // Admin on "a"'s request.
    let wrong_node_admin = scope_for("c", &[Capability::Admin]);
    let err = ops::dispatch(
        &f.state,
        &wrong_node_admin,
        NOW + 5,
        "vault.approval_decide",
        &json!({ "request": request_id, "approved": true }),
    )
    .unwrap_err();
    assert!(
        matches!(err, OpError::NodeAccessDenied { .. }),
        "got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Auto-lock (ADR-030, ADR-043)

#[test]
fn idle_past_the_vault_threshold_locks_on_tick() {
    let f = build_fixture();
    f.state.unlock(0).expect("unlock");
    f.state.set_vault_idle_seconds(60);
    f.state.touch_activity("a", NOW);

    f.state.tick_autolock(NOW + 30);
    assert!(!f.state.is_locked(), "not idle long enough yet");

    f.state.tick_autolock(NOW + 61);
    assert!(
        f.state.is_locked(),
        "idle past the threshold must lock the vault"
    );
}

#[test]
fn activity_resets_the_idle_clock() {
    let f = build_fixture();
    f.state.unlock(0).expect("unlock");
    f.state.set_vault_idle_seconds(60);
    f.state.touch_activity("a", NOW);
    f.state.touch_activity("a", NOW + 50);

    f.state.tick_autolock(NOW + 90); // only 40s since the second touch
    assert!(
        !f.state.is_locked(),
        "fresh activity must restart the idle window"
    );
}

#[test]
fn a_nodes_own_lock_after_seconds_locks_only_that_node_not_the_vault() {
    let f = build_fixture();
    f.state.unlock(0).expect("unlock");
    f.state.set_vault_idle_seconds(900); // vault-wide default (ADR-030), well clear of this test
    {
        let mut reg = f.state.registry.write().expect("registry poisoned");
        reg.nodes.get_mut("a").unwrap().policy.lock_after_seconds = Some(300);
    }
    f.state.touch_activity("a", NOW);
    f.state.touch_activity("b", NOW);

    let newly_locked = f.state.tick_autolock(NOW + 301);
    assert_eq!(newly_locked, vec!["a".to_string()]);
    assert!(f.state.is_node_locked("a"));
    assert!(
        !f.state.is_node_locked("b"),
        "b has no lock_after_seconds policy"
    );
    assert!(
        !f.state.is_locked(),
        "a single critical node's own timer must not lock the whole vault"
    );
}

#[test]
fn external_lock_signal_locks_immediately_regardless_of_any_timer_state() {
    let f = build_fixture();
    f.state.unlock(0).expect("unlock");
    f.state.set_vault_idle_seconds(900);
    f.state.touch_activity("a", NOW);
    assert!(!f.state.is_locked());

    // Stands in for whichever of sleep / screen-lock / session-end Phase 5's
    // native shell observed (ADR-043) — the broker side is one call, always.
    f.state.external_lock_signal("screen locked");
    assert!(f.state.is_locked());
}

// ---------------------------------------------------------------------------
// Auth-failure backoff (07 §5, ADR-044)

fn wrong_keystore(dir: &std::path::Path) -> Box<SoftwareKeystore> {
    Box::new(SoftwareKeystore::new(
        SecretBox::new(Box::new("definitely not the passphrase".to_string())),
        dir.join("wrong-keystore-state"),
    ))
}

fn correct_keystore(dir: &std::path::Path) -> Box<SoftwareKeystore> {
    Box::new(SoftwareKeystore::new(
        SecretBox::new(Box::new("correct horse battery staple".to_string())),
        dir.join("keystore-state"),
    ))
}

#[test]
fn vault_unlock_locks_out_after_five_consecutive_wrong_passphrases() {
    let f = build_fixture(); // never unlocked
    f.state
        .replace_keystore_for_test(wrong_keystore(f._dir.path()));

    let peer = credmgr_brokerd::peer::PeerInfo {
        uid: 777,
        pid: 1,
        cwd: None,
    };
    let request = credmgr_brokerd::protocol::Request {
        id: "1".to_string(),
        op: "vault.unlock".to_string(),
        token: None,
        params: json!({}),
    };

    // One fixed `Instant`, read once and reused for every call below, via
    // `server::handle_request_at` — `handle_request`'s ordinary path always
    // stamps `Instant::now()` fresh for `AuthBackoff`'s 30-second lockout,
    // and two independent reads of that real clock (one in the 5th
    // failure's `record_failure`, one in the 6th call's `remaining_lockout`
    // check) can legitimately be seconds apart if the OS descheduled this
    // thread between them under CPU contention — the same load-sensitive
    // race `PROJECT_MAP.md §5.10` documents for `phase5_gate.rs`'s
    // `item2_failed_gate_attempts_back_off_and_share_the_passphrase_counter`,
    // reproduced here on first sight during a full `cargo test --workspace`
    // run. Reusing one fixed instant removes the race entirely.
    let clock = Instant::now();

    for i in 0..5 {
        let err = credmgr_brokerd::server::handle_request_at(&f.state, &peer, &request, NOW, clock)
            .0
            .unwrap_err();
        assert!(
            matches!(err, OpError::WrongPassphrase),
            "attempt {i}: got {err:?}"
        );
    }

    // Now even the CORRECT passphrase must be refused before it is ever
    // tried — proving the gate blocks the keystore call itself (`07 §5`:
    // "5 failures -> 30s lock"), not merely counts failures after the fact.
    f.state
        .replace_keystore_for_test(correct_keystore(f._dir.path()));
    let sixth = credmgr_brokerd::server::handle_request_at(&f.state, &peer, &request, NOW, clock)
        .0
        .unwrap_err();
    assert!(
        matches!(sixth, OpError::RateLimited { .. }),
        "got {sixth:?}"
    );
    assert!(
        f.state.is_locked(),
        "a rate-limited attempt must never have unlocked anything"
    );
}

#[test]
fn a_uids_lockout_does_not_affect_a_different_uid() {
    let f = build_fixture();
    f.state
        .replace_keystore_for_test(wrong_keystore(f._dir.path()));

    let attacker = credmgr_brokerd::peer::PeerInfo {
        uid: 777,
        pid: 1,
        cwd: None,
    };
    let request = credmgr_brokerd::protocol::Request {
        id: "1".to_string(),
        op: "vault.unlock".to_string(),
        token: None,
        params: json!({}),
    };
    for _ in 0..5 {
        credmgr_brokerd::server::handle_request(&f.state, &attacker, &request)
            .0
            .unwrap_err();
    }

    f.state
        .replace_keystore_for_test(correct_keystore(f._dir.path()));
    let owner = credmgr_brokerd::peer::PeerInfo {
        uid: 501,
        pid: 1,
        cwd: None,
    };
    let unlocked = credmgr_brokerd::server::handle_request(&f.state, &owner, &request).0;
    assert!(
        unlocked.is_ok(),
        "an unrelated uid's own first attempt must not inherit someone else's backoff, got {unlocked:?}"
    );
}
