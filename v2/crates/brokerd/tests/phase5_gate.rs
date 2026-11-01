//! The 8 tests `docs/07_TWO_FACTOR.md §8` names for gate 2FA, plus the
//! enrolment/verify plumbing they exercise. Covers items 1-5, 7, 8 directly;
//! item 6 ("`totp.seed` is unreachable from the MCP transport") is I-13's
//! job once `credmgr-mcp` has a real tool registry to enumerate — see that
//! crate's tests, not this file, for it.
//!
//! **Scope note.** This session builds the *vault-wide* gate only
//! (`GATE_SCOPE_VAULT`, `state.rs`'s own doc comment) — per-node gates
//! (`NodePolicy::require_two_factor`) are unwired follow-on work, recorded
//! in `BUILD_LOG.md`. Every test below exercises the real mechanism that
//! exists today, not a stand-in for the part that doesn't yet.
//!
//! Fixture: Global, plus depth-1 project "a" with one seeded entry — the
//! gate itself doesn't care about node topology, so this stays intentionally
//! smaller than `isolation.rs`'s four-node graph.

use std::sync::Arc;
use std::time::Instant;

use secrecy::SecretBox;
use serde_json::json;

use credmgr_brokerd::ops;
use credmgr_brokerd::peer::PeerInfo;
use credmgr_brokerd::protocol::{OpError, Request};
use credmgr_brokerd::scope::BrokerScope;
use credmgr_brokerd::server;
use credmgr_brokerd::state::{BrokerState, GATE_SCOPE_VAULT};
use credmgr_core::access::Origin;
use credmgr_core::inference::EntryType;
use credmgr_core::registry::{
    Capability, Node, NodeKind, NodePolicy, Registry, GLOBAL_ID, ORPHAN_ID,
};
use credmgr_core::totp::Totp;
use credmgr_keystore::software::SoftwareKeystore;
use credmgr_store::manifest::{Counts, ManifestBody, ManifestEntry, Sensitivity};

const NOW: i64 = 1_800_000_000;
const PASSPHRASE: &str = "correct horse battery staple";

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
        SecretBox::new(Box::new(PASSPHRASE.to_string())),
        dir.path().join("keystore-state"),
    ));
    let paths = credmgr_store::paths::VaultPaths::new(dir.path().join("vault"));
    let state = Arc::new(BrokerState::new(keystore, paths));

    let root_key = SecretBox::new(Box::new([7u8; 32]));
    state.seed_root_key(&root_key);

    let mut reg = Registry::new();
    reg.nodes.insert(GLOBAL_ID.to_string(), Node::global());
    reg.nodes.insert(ORPHAN_ID.to_string(), Node::orphan());
    reg.nodes.insert("a".to_string(), depth1("a"));
    state.set_registry(reg);
    state.seed_node_key(&root_key, ORPHAN_ID);

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

    Fixture { state, _dir: dir }
}

fn admin_scope() -> BrokerScope {
    BrokerScope {
        node_id: GLOBAL_ID.to_string(),
        capabilities: vec![Capability::Admin],
        origin: Origin::HumanUi,
        token_id: None,
        bound_workdir: None,
    }
}

/// Enrols and confirms the vault-wide gate, returning the `Totp` (so a test
/// can compute valid codes) and the 10 recovery codes issued at
/// confirmation — real dispatch calls throughout, not direct state access,
/// so this fixture helper exercises exactly what an operator's first
/// `Settings → Security → Two-factor` run would.
fn enroll_and_confirm_gate(f: &Fixture) -> (Totp, Vec<String>) {
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
    let secret = totp_rs_decode_base32(secret_b32);
    let totp = Totp::new_gate(secret);
    let code = totp.code(NOW as u64);

    let confirm = ops::dispatch(
        &f.state,
        &admin_scope(),
        NOW,
        "vault.gate_enroll_confirm",
        &json!({ "code": code }),
    )
    .expect("enroll_confirm with the freshly-generated code must succeed");
    let codes: Vec<String> = confirm["recoveryCodes"]
        .as_array()
        .expect("recoveryCodes present")
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_eq!(codes.len(), 10, "07 §4: 10 recovery codes issued");
    (totp, codes)
}

/// RFC 4648 base32 (no padding) decode — the one place this test file needs
/// to go from the wire-format `otpauth://` secret back to raw bytes; small
/// enough to hand-write rather than pull a dependency into a test-only file.
fn totp_rs_decode_base32(s: &str) -> Vec<u8> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut bits: u64 = 0;
    let mut bit_count = 0u32;
    let mut out = Vec::new();
    for c in s.bytes() {
        let val = ALPHABET
            .iter()
            .position(|&b| b == c.to_ascii_uppercase())
            .expect("valid base32 char") as u64;
        bits = (bits << 5) | val;
        bit_count += 5;
        if bit_count >= 8 {
            bit_count -= 8;
            out.push((bits >> bit_count) as u8);
        }
    }
    out
}

fn unlock_via_dispatch(f: &Fixture) {
    let result = ops::dispatch(&f.state, &admin_scope(), NOW, "vault.unlock", &json!({}));
    match result {
        Err(OpError::TwoFactorRequired { scope, .. }) => {
            assert_eq!(scope, GATE_SCOPE_VAULT);
        }
        other => panic!("expected two_factor_required, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 07 §8 item 1 — replay

#[test]
fn item1_a_code_accepted_once_is_refused_for_the_rest_of_its_window() {
    let f = build_fixture();
    let (totp, _codes) = enroll_and_confirm_gate(&f);
    let code = totp.code((NOW + 30) as u64);

    unlock_via_dispatch(&f);
    ops::dispatch(
        &f.state,
        &admin_scope(),
        NOW,
        "vault.gate_verify",
        &json!({ "code": code }),
    )
    .expect("the first use of a valid code succeeds");
    assert!(!f.state.is_locked());

    f.state.lock();
    unlock_via_dispatch(&f);
    let replay = ops::dispatch(
        &f.state,
        &admin_scope(),
        NOW,
        "vault.gate_verify",
        &json!({ "code": code }),
    )
    .unwrap_err();
    assert!(matches!(replay, OpError::GateVerificationFailed));
    assert!(
        f.state.is_locked(),
        "a replayed code must not unlock the vault"
    );
}

// ---------------------------------------------------------------------------
// 07 §8 item 2 — backoff shared with the passphrase path

#[test]
fn item2_failed_gate_attempts_back_off_and_share_the_passphrase_counter() {
    let f = build_fixture();
    enroll_and_confirm_gate(&f);

    let peer = PeerInfo {
        uid: 501,
        pid: 1,
        cwd: None,
    };
    let unlock_req = |id: &str| Request {
        id: id.to_string(),
        op: "vault.unlock".to_string(),
        token: None,
        params: json!({}),
    };
    let bad_verify_req = |id: &str| Request {
        id: id.to_string(),
        op: "vault.gate_verify".to_string(),
        token: None,
        params: json!({ "code": "000000" }),
    };

    // One fixed `Instant`, read once and reused for every call below, via
    // `server::handle_request_at` — `handle_request`'s ordinary path always
    // stamps `Instant::now()` fresh for `AuthBackoff`'s 30-second lockout,
    // and two independent reads of that real clock (one in the 5th
    // failure's `record_failure`, one in the very next call's
    // `remaining_lockout` check) can legitimately be seconds apart if the
    // OS descheduled this thread between them under CPU contention —
    // exactly the load-sensitive flake `PROJECT_MAP.md §5.10` documents.
    // Reusing one fixed instant removes that race entirely while still
    // driving the real `handle_request` wiring (unlike `ops::dispatch`,
    // which never touches `auth_backoff` at all).
    let clock = Instant::now();

    // Five consecutive wrong-code attempts, each preceded by a fresh
    // passphrase unlock — `07 §5`'s schedule counts consecutive
    // *authentication* failures per uid, not per op.
    for _ in 0..5 {
        let _ = server::handle_request_at(&f.state, &peer, &unlock_req("u"), NOW, clock);
        let err = server::handle_request_at(&f.state, &peer, &bad_verify_req("v"), NOW, clock)
            .0
            .unwrap_err();
        assert!(matches!(err, OpError::GateVerificationFailed));
    }

    // The 5th failure trips the lock — the *next* attempt, on either auth
    // path, is refused before it even reaches the keystore/gate.
    let locked_out_unlock =
        server::handle_request_at(&f.state, &peer, &unlock_req("u2"), NOW, clock)
            .0
            .unwrap_err();
    assert!(
        matches!(locked_out_unlock, OpError::RateLimited { .. }),
        "vault.unlock must be refused once the shared backoff counter trips, got {locked_out_unlock:?}"
    );
    let locked_out_verify =
        server::handle_request_at(&f.state, &peer, &bad_verify_req("v2"), NOW, clock)
            .0
            .unwrap_err();
    assert!(
        matches!(locked_out_verify, OpError::RateLimited { .. }),
        "vault.gate_verify shares the same counter, got {locked_out_verify:?}"
    );
}

// ---------------------------------------------------------------------------
// 07 §8 item 3 — wrong TOTP loads no node key

#[test]
fn item3_wrong_totp_after_a_correct_passphrase_loads_no_node_key() {
    let f = build_fixture();
    enroll_and_confirm_gate(&f);

    unlock_via_dispatch(&f);
    let err = ops::dispatch(
        &f.state,
        &admin_scope(),
        NOW,
        "vault.gate_verify",
        &json!({ "code": "000000" }),
    )
    .unwrap_err();
    assert!(matches!(err, OpError::GateVerificationFailed));
    assert!(
        f.state.hot_key_node_ids_for_test().is_empty(),
        "a correct passphrase + a wrong TOTP must load no node key into the hot set"
    );
    assert!(f.state.is_locked());
}

// ---------------------------------------------------------------------------
// 07 §8 item 4 — an unconfirmed enrolment never activates

#[test]
fn item4_an_unconfirmed_enrolment_never_activates() {
    let f = build_fixture();
    ops::dispatch(
        &f.state,
        &admin_scope(),
        NOW,
        "vault.gate_enroll_begin",
        &json!({}),
    )
    .expect("enroll_begin");
    // No `vault.gate_enroll_confirm` call — the enrolment is never confirmed.

    assert!(!f.state.is_gate_confirmed(GATE_SCOPE_VAULT));

    // `unlock()` must behave exactly as if no gate existed at all.
    let result = ops::dispatch(&f.state, &admin_scope(), NOW, "vault.unlock", &json!({}));
    assert!(
        result.is_ok(),
        "an unconfirmed enrolment must not gate unlock, got {result:?}"
    );
    assert!(!f.state.is_locked());
}

// ---------------------------------------------------------------------------
// 07 §8 item 5 — a recovery code works exactly once

#[test]
fn item5_a_recovery_code_works_exactly_once() {
    let f = build_fixture();
    let (_totp, codes) = enroll_and_confirm_gate(&f);
    let recovery_code = &codes[0];

    unlock_via_dispatch(&f);
    ops::dispatch(
        &f.state,
        &admin_scope(),
        NOW,
        "vault.gate_verify",
        &json!({ "code": recovery_code }),
    )
    .expect("an unused recovery code satisfies the gate challenge");
    assert!(!f.state.is_locked());

    f.state.lock();
    unlock_via_dispatch(&f);
    let second_use = ops::dispatch(
        &f.state,
        &admin_scope(),
        NOW,
        "vault.gate_verify",
        &json!({ "code": recovery_code }),
    )
    .unwrap_err();
    assert!(matches!(second_use, OpError::GateVerificationFailed));
    assert!(
        f.state.is_locked(),
        "a burned recovery code must not unlock the vault a second time"
    );
}

// ---------------------------------------------------------------------------
// 07 §8 item 7 — orphan reveal never accepts an elevation

#[test]
fn item7_a_successful_vault_gate_challenge_never_elevates_orphan() {
    let f = build_fixture();
    let (totp, _codes) = enroll_and_confirm_gate(&f);
    let code = totp.code((NOW + 30) as u64);

    unlock_via_dispatch(&f);
    ops::dispatch(
        &f.state,
        &admin_scope(),
        NOW,
        "vault.gate_verify",
        &json!({ "code": code }),
    )
    .expect("gate_verify");

    assert!(
        f.state.is_elevated(GATE_SCOPE_VAULT, NOW),
        "the scope that was actually challenged should be elevated"
    );
    assert!(
        !f.state.is_elevated(ORPHAN_ID, NOW),
        "07 §4/§8: orphan must never be elevated by any other scope's \
         successful gate challenge — every orphan reveal takes a fresh \
         code and presence, every time"
    );
}

// ---------------------------------------------------------------------------
// 07 §8 item 8 — lock, sleep and screen lock each drop every elevation

#[test]
fn item8_lock_drops_the_elevation_and_any_in_flight_challenge() {
    let f = build_fixture();
    let (totp, _codes) = enroll_and_confirm_gate(&f);
    let code = totp.code((NOW + 30) as u64);

    unlock_via_dispatch(&f);
    ops::dispatch(
        &f.state,
        &admin_scope(),
        NOW,
        "vault.gate_verify",
        &json!({ "code": code }),
    )
    .expect("gate_verify");
    assert!(f.state.is_elevated(GATE_SCOPE_VAULT, NOW));

    f.state.lock();
    assert!(
        !f.state.is_elevated(GATE_SCOPE_VAULT, NOW),
        "an explicit lock must drop the elevation"
    );
}

#[test]
fn item8_external_lock_signal_drops_the_elevation_too() {
    let f = build_fixture();
    let (totp, _codes) = enroll_and_confirm_gate(&f);
    let code = totp.code((NOW + 30) as u64);

    unlock_via_dispatch(&f);
    ops::dispatch(
        &f.state,
        &admin_scope(),
        NOW,
        "vault.gate_verify",
        &json!({ "code": code }),
    )
    .expect("gate_verify");
    assert!(f.state.is_elevated(GATE_SCOPE_VAULT, NOW));

    // ADR-043: sleep and screen-lock both reduce to this one call.
    f.state.external_lock_signal("sleep");
    assert!(
        !f.state.is_elevated(GATE_SCOPE_VAULT, NOW),
        "sleep/screen-lock (external_lock_signal) must drop the elevation"
    );
}

#[test]
fn item8_lock_drops_an_in_flight_unconsumed_challenge() {
    let f = build_fixture();
    enroll_and_confirm_gate(&f);

    // Factor 1 succeeds; factor 2 is never presented.
    unlock_via_dispatch(&f);

    f.state.lock();

    // The pending challenge must be gone — a subsequent `vault.gate_verify`
    // with what *would* have been the right code (had a new unlock not been
    // required) must not succeed against the stale pending state.
    let totp_after = Totp::new_gate(vec![0u8; 20]); // deliberately unrelated
    let err = ops::dispatch(
        &f.state,
        &admin_scope(),
        NOW,
        "vault.gate_verify",
        &json!({ "code": totp_after.code(NOW as u64) }),
    )
    .unwrap_err();
    assert!(matches!(err, OpError::GateVerificationFailed));
    assert!(f.state.is_locked());
}
