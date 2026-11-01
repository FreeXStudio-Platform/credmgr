//! ADR-056: a real `vault.unlock`/`vault.gate_verify` success mints a real,
//! non-fixture token — the gap ADR-047 named and nothing but a test fixture
//! could previously close. These tests drive the real dispatch path
//! (`server::handle_request`, not a hand-built `BrokerScope`) for every
//! assertion that is actually about the mechanism; the one assertion that
//! documents current `R3` behaviour (see the bottom of this file) is a
//! direct `credmgr_core::access::resolve()` call, since no real mint path in
//! this codebase can produce the scope shape it pins.
//!
//! Fixture: Global plus depth-1 project "a" (a sibling the login session
//! must *not* reach) — the same minimal two-node shape `audit_ops.rs`
//! already uses for the identical reason.

use std::sync::Arc;

use secrecy::SecretBox;
use serde_json::json;

use credmgr_brokerd::ops;
use credmgr_brokerd::peer::PeerInfo;
use credmgr_brokerd::protocol::{OpError, Request};
use credmgr_brokerd::scope::BrokerScope;
use credmgr_brokerd::server;
use credmgr_brokerd::state::{BrokerState, GATE_SCOPE_VAULT};
use credmgr_core::access::{self, AccessContext, Origin, Scope, Target};
use credmgr_core::registry::{Capability, Node, NodeKind, NodePolicy, Registry, GLOBAL_ID};
use credmgr_core::totp::Totp;
use credmgr_keystore::software::SoftwareKeystore;

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

/// Deliberately does **not** call `state.unlock(0)` — unlike several other
/// fixtures in this workspace that pre-unlock for their own unrelated
/// purposes, these tests exercise `vault.unlock` itself, so the vault must
/// start genuinely locked, exactly as a freshly-started `credmgrd` would.
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
    reg.nodes.insert("a".to_string(), depth1("a"));
    state.set_registry(reg);
    state.seed_node_key(&root_key, "a");

    Fixture { state, _dir: dir }
}

fn peer() -> PeerInfo {
    PeerInfo {
        uid: 501,
        pid: 1,
        cwd: None,
    }
}

fn request(op: &str, token: Option<&str>, params: serde_json::Value) -> Request {
    Request {
        id: "r".to_string(),
        op: op.to_string(),
        token: token.map(str::to_string),
        params,
    }
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

/// RFC 4648 base32 (no padding) decode — same small hand-written helper
/// `phase5_gate.rs` already carries, kept file-local rather than shared so
/// this test has no dependency on that file's own internals.
fn decode_base32(s: &str) -> Vec<u8> {
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

/// Enrols and confirms the vault-wide gate via real dispatch calls (matching
/// `phase5_gate.rs`'s own established pattern), returning the `Totp` so a
/// test can compute a valid code for `vault.gate_verify`.
fn enroll_and_confirm_gate(f: &Fixture) -> Totp {
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
    let totp = Totp::new_gate(decode_base32(secret_b32));
    let code = totp.code(NOW as u64);
    ops::dispatch(
        &f.state,
        &admin_scope(),
        NOW,
        "vault.gate_enroll_confirm",
        &json!({ "code": code }),
    )
    .expect("enroll_confirm with the freshly-generated code must succeed");
    totp
}

// ---------------------------------------------------------------------------
// A real, no-gate unlock mints a real token.

#[test]
fn unlock_with_no_gate_mints_a_token_scoped_to_global_with_every_capability() {
    let f = build_fixture();
    let (result, _) =
        server::handle_request(&f.state, &peer(), &request("vault.unlock", None, json!({})));
    let value = result.expect("a correct, ungated unlock must succeed");
    assert_eq!(value["locked"], json!(false));
    let token_id = value["token"]
        .as_str()
        .expect("a successful full unlock must mint and return a token")
        .to_string();

    let minted = f
        .state
        .tokens
        .get(&token_id)
        .expect("the minted token id must actually resolve in the token store");
    assert_eq!(minted.node_id, GLOBAL_ID);
    assert_eq!(
        minted.origin,
        Origin::HumanUi,
        "not Native — no presence attestation exists on this transport (ADR-056)"
    );
    assert_eq!(minted.bound_workdir, None);
    for cap in [
        Capability::List,
        Capability::Read,
        Capability::Reveal,
        Capability::Create,
        Capability::Update,
        Capability::Notes,
        Capability::Admin,
    ] {
        assert!(
            minted.capabilities.contains(&cap),
            "a login session withholds nothing from its own ceiling, missing {cap:?}"
        );
    }
}

#[test]
fn a_locked_out_vault_status_response_never_carries_a_token() {
    let f = build_fixture();
    let (result, _) =
        server::handle_request(&f.state, &peer(), &request("vault.status", None, json!({})));
    let value = result.expect("vault.status");
    assert!(
        value.get("token").is_none(),
        "vault.status is not a login op"
    );
}

// ---------------------------------------------------------------------------
// The two-step gate path only mints a token once the second factor lands.

#[test]
fn gate_enrolled_unlock_alone_mints_no_token_only_gate_verify_does() {
    // Driven via `ops::dispatch` with a fixed `NOW`, matching
    // `phase5_gate.rs`'s own established pattern for gate-2FA timing tests —
    // `server::handle_request` always stamps the real wall clock
    // (`now_epoch()`), which would put `vault.gate_verify`'s TOTP check at a
    // different instant than the code was generated for.
    let f = build_fixture();
    let totp = enroll_and_confirm_gate(&f);
    f.state.lock(); // undo the elevation `enroll_confirm` itself grants

    let first = ops::dispatch(&f.state, &admin_scope(), NOW, "vault.unlock", &json!({}));
    match first {
        Err(OpError::TwoFactorRequired { scope, .. }) => assert_eq!(scope, GATE_SCOPE_VAULT),
        other => panic!("expected two_factor_required, got {other:?}"),
    }

    // `NOW + 30`, a different TOTP step from the one `enroll_and_confirm_gate`
    // already consumed to confirm enrolment — `07 §5`'s replay ledger refuses
    // the identical `(scope, counterStep)` pair a second time.
    let code = totp.code((NOW + 30) as u64);
    let second = ops::dispatch(
        &f.state,
        &admin_scope(),
        NOW + 30,
        "vault.gate_verify",
        &json!({ "code": code }),
    );
    let value = second.expect("the correct code must complete the login");
    assert_eq!(value["locked"], json!(false));
    let token_id = value["token"]
        .as_str()
        .expect("vault.gate_verify's success must mint a token, the same as a gate-free unlock");
    let minted = f.state.tokens.get(token_id).expect("token resolves");
    assert_eq!(minted.origin, Origin::HumanUi);
    assert_eq!(minted.node_id, GLOBAL_ID);
}

// ---------------------------------------------------------------------------
// Locking revokes every session token minted since the last unlock.

#[test]
fn locking_the_vault_revokes_every_session_token_minted_since_the_last_unlock() {
    let f = build_fixture();
    let (r1, _) =
        server::handle_request(&f.state, &peer(), &request("vault.unlock", None, json!({})));
    let token_a = r1.unwrap()["token"].as_str().unwrap().to_string();
    f.state.lock();
    // Re-unlock and mint a second token — both must die on the *next* lock.
    let (r2, _) =
        server::handle_request(&f.state, &peer(), &request("vault.unlock", None, json!({})));
    let token_b = r2.unwrap()["token"].as_str().unwrap().to_string();

    assert!(
        f.state.tokens.get(&token_a).is_none(),
        "token_a died at the first lock() already"
    );
    assert!(
        f.state.tokens.get(&token_b).is_some(),
        "token_b is still live before the second lock"
    );

    f.state.lock();
    assert!(
        f.state.tokens.get(&token_b).is_none(),
        "token_b must be revoked by this lock()"
    );

    // A revoked session token no longer authenticates anything. Until ADR-068
    // this asserted only that it fell back to a weaker cwd/global scope; it is
    // now refused outright, so its holder learns the login is gone.
    let (denied, _) = server::handle_request(
        &f.state,
        &peer(),
        &request("whoami", Some(&token_b), json!({})),
    );
    assert_eq!(
        denied.expect_err("a revoked session token is refused"),
        OpError::SessionExpired
    );
    // … but it never stands between its holder and the ops that report or
    // re-establish a session, or that lock the vault.
    for op in ["vault.status", "vault.lock"] {
        let (r, _) =
            server::handle_request(&f.state, &peer(), &request(op, Some(&token_b), json!({})));
        assert!(r.is_ok(), "{op} with a dead token: {r:?}");
    }
    let (r, _) = server::handle_request(
        &f.state,
        &peer(),
        &request("vault.unlock", Some(&token_b), json!({})),
    );
    assert!(
        r.unwrap()["token"].is_string(),
        "a dead token does not block logging in again"
    );
    // A request that presents no token at all resolves exactly as before.
    let (r, _) = server::handle_request(&f.state, &peer(), &request("whoami", None, json!({})));
    assert!(r.is_ok(), "a tokenless request is not a dead-token request");
}

/// ADR-068: a token id the broker never issued is refused the same way.
#[test]
fn a_token_the_broker_never_issued_is_refused_not_resolved_from_cwd() {
    let f = build_fixture();
    let (r, _) = server::handle_request(
        &f.state,
        &peer(),
        &request(
            "entry.list",
            Some("tok_not_a_real_one"),
            json!({ "node": GLOBAL_ID }),
        ),
    );
    assert_eq!(r.expect_err("unknown token"), OpError::SessionExpired);
}

// ---------------------------------------------------------------------------
// audit.tail: unredacted for the login session — and, since ADR-065, across
// the owner's whole vault. Until 2026-09-24 this test pinned the opposite (a
// `global`-scoped login could not see a project's records, the limitation
// ADR-056 named and ADR-047 handed forward); ADR-065 closed it for a real
// login only, so the negative half now pins that a HumanUi token which did
// NOT come from a real unlock still cannot see the project.

#[test]
fn session_token_reads_every_projects_audit_unredacted_but_a_non_login_token_does_not() {
    let f = build_fixture();

    // A record that targets sibling project "a" — an ordinary List against
    // "a" by a token scoped to "a" itself.
    let a_token = f
        .state
        .tokens
        .issue("a", vec![Capability::List], Origin::HumanUi, None);
    let (r, _) = server::handle_request(
        &f.state,
        &peer(),
        &request("entry.list", Some(&a_token.id), json!({ "node": "a" })),
    );
    r.expect("entry.list against a's own scope");

    // The real login — mints a token whose own unlock already produced a
    // `global`-scoped audit record (`vault.unlock`'s own decision).
    let (unlock, _) =
        server::handle_request(&f.state, &peer(), &request("vault.unlock", None, json!({})));
    let session_token = unlock.unwrap()["token"].as_str().unwrap().to_string();

    let (tail, _) = server::handle_request(
        &f.state,
        &peer(),
        &request("audit.tail", Some(&session_token), json!({ "limit": 50 })),
    );
    let records = tail.unwrap()["records"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        !records.is_empty(),
        "the login's own unlock must itself be audited"
    );
    for r in &records {
        assert!(
            r.get("decision").is_some(),
            "Origin::HumanUi must get the unredacted shape (id/timestamp/actor/action/node/decision/...), got {r:?}"
        );
    }
    assert!(
        records.iter().any(|r| r["node"] == json!("a")),
        "ADR-065: the owner's login reaches every project, so project a's record is in its feed"
    );

    // A HumanUi, global, every-capability token that a real unlock did NOT
    // mint — e.g. anything a future code path might issue — gets none of that
    // reach: `is_owner_session` requires the id the unlock itself registered.
    let not_a_login = f.state.tokens.issue(
        GLOBAL_ID,
        vec![
            Capability::List,
            Capability::Read,
            Capability::Reveal,
            Capability::Create,
            Capability::Update,
            Capability::Notes,
            Capability::Admin,
        ],
        Origin::HumanUi,
        None,
    );
    let (tail, _) = server::handle_request(
        &f.state,
        &peer(),
        &request("audit.tail", Some(&not_a_login.id), json!({ "limit": 50 })),
    );
    for r in tail.unwrap()["records"]
        .as_array()
        .cloned()
        .unwrap_or_default()
    {
        assert_ne!(
            r["node"],
            json!("a"),
            "a HumanUi token that no real unlock minted must not see a project's records"
        );
    }
}

// ---------------------------------------------------------------------------
// The R3-universal-Admin decision (ADR-051, answered by ADR-056): pinned
// directly against `core::access::resolve()`, since no real mint path in
// this codebase can produce an Admin-holding, non-global-scoped subject to
// exercise this through the broker.

#[test]
fn r3_still_allows_any_admin_holding_subject_to_resolve_admin_against_global() {
    let mut reg = Registry::new();
    reg.nodes.insert(GLOBAL_ID.to_string(), Node::global());
    reg.nodes.insert("a".to_string(), depth1("a"));

    let ctx = AccessContext {
        registry: &reg,
        vault_locked: false,
        locked_nodes: &std::collections::HashSet::new(),
        now: NOW,
    };
    // A scope this ADR's own mechanism never constructs (it only ever mints
    // Admin scoped to `global`) — hand-built here specifically to document
    // current behaviour, per ADR-056's own "leave R3 unchanged" decision.
    let subject = Scope {
        node_id: "a".to_string(),
        origin: Origin::HumanUi,
        presence_attested: false,
    };
    let decision = access::resolve(
        &ctx,
        &subject,
        &Target::Node(GLOBAL_ID.to_string()),
        Capability::Admin,
    );
    assert_eq!(
        decision,
        access::Decision::Allow(access::Rule::R3),
        "R3 stays capability-unqualified by deliberate decision (ADR-056) — this is a real, \
         but after this session structurally unreachable-by-any-live-token, property"
    );
}
