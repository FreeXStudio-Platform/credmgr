//! ADR-079 (K-7 item 4, WP4a) — approval-on-demand on a locked live vault,
//! fail-closed.
//!
//! The defect (`PHASE8_AUDIT_REPORT.md §4`, K-7): on a vault the vault-wide lock
//! had closed, an agent's `entry.reveal` answered `approval_pending` — a promise
//! nothing could keep. The only principal that can decide an approval is the
//! owner session, and `lock()` revokes it; and the approved value needed a root
//! key a locked live vault does not hold, so the *retry* failed `internal` even
//! if somebody had managed to decide. 4a makes that honest and keeps it
//! fail-closed:
//!
//! * approving **stages** the value — it is decrypted when the human decides,
//!   while a root key is resident, and the retry only hands it over (it never
//!   derives a key);
//! * `lock()` (explicit, idle, sleep) drops every staged value, as do expiry and
//!   consumption — a staged approval never survives a lock;
//! * a wholly locked live vault answers `vault_locked` to a reveal and to a
//!   decision, and releases nothing;
//! * request ids are 128-bit.
//!
//! The live-vault tests run the real server wiring (`server::handle_request_at`)
//! on a vault `vault.init_*` created, with an agent identified by its cwd, exactly
//! as `adr077_ops.rs` does. The last section uses the in-memory fixture the
//! original ADR-042 tests use, which must keep working unchanged.

use std::path::PathBuf;
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use secrecy::SecretBox;
use serde_json::{json, Value};

use credmgr_brokerd::ops;
use credmgr_brokerd::peer::PeerInfo;
use credmgr_brokerd::protocol::{to_wire, OpError, Request};
use credmgr_brokerd::scope::BrokerScope;
use credmgr_brokerd::server;
use credmgr_brokerd::state::{ApprovalDecideError, ApprovalVerdict, BrokerState};
use credmgr_core::access::Origin;
use credmgr_core::inference::EntryType;
use credmgr_core::registry::{Capability, Node, NodeKind, NodePolicy, Registry, GLOBAL_ID};
use credmgr_keystore::software::SoftwareKeystore;
use credmgr_store::manifest::{Counts, ManifestBody, ManifestEntry, Sensitivity};

const NOW: i64 = 1_800_000_000;
const PASSPHRASE: &str = "correct horse battery staple";
/// The one value every live-vault scene stores. It must never appear in any
/// answer except the single successful retry of a still-valid approval.
const SECRET: &str = "v-live-secret-1";

// ------------------------------------------------------------------------------------------
// the live vault
// ------------------------------------------------------------------------------------------

struct Live {
    state: Arc<BrokerState>,
    acme_workdir: PathBuf,
    _dir: tempfile::TempDir,
}

fn anyone() -> BrokerScope {
    BrokerScope {
        node_id: GLOBAL_ID.to_string(),
        capabilities: vec![Capability::List],
        origin: Origin::Agent,
        token_id: None,
        bound_workdir: None,
    }
}

/// A scope that holds `Admin` on `global`, claimed in-process. The daemon never
/// hands one out without an owner session; tests use it to stand in for "some
/// caller that holds Admin" at moments when the real owner session is gone.
fn admin_claim() -> BrokerScope {
    BrokerScope {
        node_id: GLOBAL_ID.to_string(),
        capabilities: vec![
            Capability::List,
            Capability::Read,
            Capability::Reveal,
            Capability::Create,
            Capability::Update,
            Capability::Notes,
            Capability::Admin,
        ],
        origin: Origin::HumanUi,
        token_id: None,
        bound_workdir: None,
    }
}

fn peer(cwd: Option<&str>) -> PeerInfo {
    PeerInfo {
        uid: 501,
        pid: 1,
        cwd: cwd.map(str::to_string),
    }
}

fn send_at(
    f: &Live,
    now: i64,
    cwd: Option<&str>,
    token: Option<&str>,
    op: &str,
    params: Value,
) -> Result<Value, OpError> {
    let request = Request {
        id: "r".to_string(),
        op: op.to_string(),
        token: token.map(str::to_string),
        params,
    };
    server::handle_request_at(&f.state, &peer(cwd), &request, now, Instant::now()).0
}

fn send(
    f: &Live,
    cwd: Option<&str>,
    token: Option<&str>,
    op: &str,
    params: Value,
) -> Result<Value, OpError> {
    send_at(f, NOW, cwd, token, op, params)
}

fn wire(err: OpError) -> Value {
    to_wire("r", &Err(err))
}

/// `credmgr init` for real; the broker is returned running and locked.
fn created_vault() -> Live {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault_dir = dir.path().join("vault");
    let state_dir = dir.path().join("state");
    std::fs::create_dir_all(&vault_dir).unwrap();
    std::fs::create_dir_all(&state_dir).unwrap();
    let acme_workdir = dir.path().join("work").join("acme");
    std::fs::create_dir_all(acme_workdir.join("src")).unwrap();
    // The broker stores and compares real paths; on macOS the temp directory is
    // a symlink, so resolve it up front.
    let acme_workdir = std::fs::canonicalize(&acme_workdir).unwrap();
    let keystore = SoftwareKeystore::new(
        SecretBox::new(Box::default()),
        state_dir.join("placeholder-keystore"),
    );
    let state = Arc::new(BrokerState::new(
        Box::new(keystore),
        credmgr_store::paths::VaultPaths::new(vault_dir),
    ));
    state.set_state_dir_for_test(state_dir);
    let f = Live {
        state,
        acme_workdir,
        _dir: dir,
    };
    let begin = ops::dispatch(
        &f.state,
        &anyone(),
        NOW,
        "vault.init_begin",
        &json!({ "passphrase": PASSPHRASE }),
    )
    .expect("init_begin");
    let code = begin["recoveryCode"].as_str().unwrap().to_string();
    ops::dispatch(
        &f.state,
        &anyone(),
        NOW,
        "vault.init_confirm",
        &json!({ "recoveryCode": code }),
    )
    .expect("init_confirm");
    f
}

fn login(f: &Live) -> String {
    send(
        f,
        None,
        None,
        "vault.unlock",
        json!({ "passphrase": PASSPHRASE }),
    )
    .expect("unlock")["token"]
        .as_str()
        .unwrap()
        .to_string()
}

fn agent_cwd(f: &Live) -> String {
    format!("{}/src", f.acme_workdir.to_string_lossy())
}

/// The agent in acme's workdir asks for `entry` at `now`.
fn agent_reveal_at(f: &Live, now: i64, entry: &str) -> Result<Value, OpError> {
    let cwd = agent_cwd(f);
    send_at(
        f,
        now,
        Some(&cwd),
        None,
        "entry.reveal",
        json!({ "node": "acme", "entry": entry }),
    )
}

fn agent_reveal(f: &Live, entry: &str) -> Result<Value, OpError> {
    agent_reveal_at(f, NOW, entry)
}

fn pending_id(answer: Result<Value, OpError>) -> String {
    match answer {
        Err(OpError::ApprovalPending { request, .. }) => request,
        other => panic!("expected approval_pending, got {other:?}"),
    }
}

fn owner_decide(f: &Live, owner: &str, request: &str, approved: bool) -> Result<Value, OpError> {
    send(
        f,
        None,
        Some(owner),
        "vault.approval_decide",
        json!({ "request": request, "approved": approved }),
    )
}

/// A node-locked vault with one outstanding request: `acme` holds one entry,
/// the node is locked (the vault is not), and the agent in acme's workdir has
/// asked for the entry and been told to wait.
struct Scene {
    f: Live,
    owner: String,
    entry: String,
    request: String,
}

fn requested() -> Scene {
    let f = created_vault();
    let owner = login(&f);
    send(
        &f,
        None,
        Some(&owner),
        "node.create",
        json!({ "id": "acme", "label": "Acme", "parentId": "global",
                "workdirs": [f.acme_workdir.to_string_lossy()] }),
    )
    .expect("node.create");
    let entry = send(
        &f,
        None,
        Some(&owner),
        "entry.create",
        json!({ "node": "acme", "name": "API_KEY", "value": SECRET }),
    )
    .expect("entry.create")["entry"]
        .as_str()
        .unwrap()
        .to_string();
    send(
        &f,
        None,
        Some(&owner),
        "vault.node_lock",
        json!({ "node": "acme" }),
    )
    .expect("lock acme");
    let request = pending_id(agent_reveal(&f, &entry));
    assert_eq!(f.state.approval_count_for_test(), 1);
    assert_eq!(f.state.staged_approval_count_for_test(), 0);
    Scene {
        f,
        owner,
        entry,
        request,
    }
}

/// Every answer in a scene is checked for the secret: an `Err` carries none, and
/// an `Ok` is only ever the one allowed retry, which the caller inspects itself.
fn assert_not_released(answer: &Result<Value, OpError>, what: &str) {
    assert!(
        answer.is_err(),
        "{what}: a value was released when none may be: {answer:?}"
    );
    assert!(
        !format!("{answer:?}").contains(SECRET),
        "{what}: the secret leaked into an error"
    );
}

// ------------------------------------------------------------------------------------------
// a wholly locked live vault: vault_locked, nothing created, nothing released
// ------------------------------------------------------------------------------------------

#[test]
fn a_reveal_on_a_wholly_locked_live_vault_opens_a_request_a_person_can_decide_with_the_factors() {
    let f = created_vault();
    let owner = login(&f);
    send(
        &f,
        None,
        Some(&owner),
        "node.create",
        json!({ "id": "acme", "label": "Acme", "parentId": "global",
                "workdirs": [f.acme_workdir.to_string_lossy()] }),
    )
    .unwrap();
    let entry = send(
        &f,
        None,
        Some(&owner),
        "entry.create",
        json!({ "node": "acme", "name": "API_KEY", "value": SECRET }),
    )
    .unwrap()["entry"]
        .as_str()
        .unwrap()
        .to_string();

    // The whole vault locks - with the node ALSO locked, the vault-level answer wins.
    send(
        &f,
        None,
        Some(&owner),
        "vault.node_lock",
        json!({ "node": "acme" }),
    )
    .unwrap();
    send(&f, None, Some(&owner), "vault.lock", json!({})).expect("lock the vault");
    assert!(f.state.is_locked());

    // ADR-088 (4b): the request is recorded — a person can decide it with the
    // unlock factors while the vault stays locked — and nothing is released.
    let answer = agent_reveal(&f, &entry);
    assert!(
        matches!(&answer, Err(OpError::ApprovalPending { message, .. }) if message.contains("passphrase")),
        "{answer:?}"
    );
    assert_not_released(&answer, "reveal on a wholly locked vault");
    assert_eq!(f.state.approval_count_for_test(), 1);
    assert_eq!(f.state.staged_approval_count_for_test(), 0);
    assert!(f.state.is_locked(), "asking never unlocks anything");

    // The wire answer is the plain `approval_pending` through the daemon's own layer.
    let cwd = agent_cwd(&f);
    let request = Request {
        id: "r".into(),
        op: "entry.reveal".into(),
        token: None,
        params: json!({ "node": "acme", "entry": entry }),
    };
    let (result, _) =
        server::handle_request_at(&f.state, &peer(Some(&cwd)), &request, NOW, Instant::now());
    let on_the_wire = to_wire("r", &result);
    assert_eq!(on_the_wire["error"], "approval_pending", "{on_the_wire}");
    assert!(on_the_wire.get("value").is_none(), "{on_the_wire}");
}

#[test]
fn a_node_locked_vault_still_takes_the_approval_path_after_the_vault_is_unlocked_again() {
    // The honest refusal is specific to a WHOLLY locked vault: unlock it, lock one
    // node, and the agent is asked to wait for a human exactly as before.
    let f = created_vault();
    let owner = login(&f);
    send(
        &f,
        None,
        Some(&owner),
        "node.create",
        json!({ "id": "acme", "label": "Acme", "parentId": "global",
                "workdirs": [f.acme_workdir.to_string_lossy()] }),
    )
    .unwrap();
    let entry = send(
        &f,
        None,
        Some(&owner),
        "entry.create",
        json!({ "node": "acme", "name": "API_KEY", "value": SECRET }),
    )
    .unwrap()["entry"]
        .as_str()
        .unwrap()
        .to_string();
    send(&f, None, Some(&owner), "vault.lock", json!({})).unwrap();
    // ADR-088: wholly locked, the request is recorded (a person can decide it with
    // the factors); unlocking and locking the node keeps the very same request.
    let first = pending_id(agent_reveal(&f, &entry));

    let owner = login(&f);
    send(
        &f,
        None,
        Some(&owner),
        "vault.node_lock",
        json!({ "node": "acme" }),
    )
    .unwrap();
    let answer = agent_reveal(&f, &entry);
    assert_eq!(pending_id(answer), first);
    assert_eq!(f.state.approval_count_for_test(), 1);
}

#[test]
fn deciding_on_a_wholly_locked_live_vault_answers_vault_locked_and_releases_nothing() {
    let s = requested();
    // The whole vault locks while the agent is waiting: the owner session dies with it.
    send(&s.f, None, Some(&s.owner), "vault.lock", json!({})).expect("lock the vault");
    assert!(s.f.state.is_locked());

    // Through the daemon nobody can decide: the login that could is gone.
    let dead = owner_decide(&s.f, &s.owner, &s.request, true);
    assert!(matches!(dead, Err(OpError::SessionExpired)), "{dead:?}");

    // A caller that DOES hold Admin (an in-process claim) is still refused, for
    // an approval, a denial and an id nobody ever issued alike.
    for (request, approved) in [
        (s.request.as_str(), true),
        (s.request.as_str(), false),
        ("rq_nothing_ever_issued_this", true),
    ] {
        let answer = ops::dispatch(
            &s.f.state,
            &admin_claim(),
            NOW + 5,
            "vault.approval_decide",
            &json!({ "request": request, "approved": approved }),
        );
        assert!(
            matches!(answer, Err(OpError::VaultLocked)),
            "approved={approved} request={request}: {answer:?}"
        );
    }
    assert_eq!(
        s.f.state.staged_approval_count_for_test(),
        0,
        "nothing may be staged by a refused decision"
    );

    // The request is exactly as it was: undecided. Unlock again and the agent is
    // told to keep waiting on the SAME request - no decision was recorded.
    let _owner = login(&s.f);
    let again = agent_reveal(&s.f, &s.entry);
    assert_eq!(pending_id(again), s.request);
}

#[test]
fn an_agent_never_holds_admin_so_it_cannot_decide_even_on_an_unlocked_vault() {
    // Regression guard for the surrounding rule, not a new one: `Admin` stays
    // human-only. (The matrix asserts the same row against the real daemon.)
    let s = requested();
    let cwd = agent_cwd(&s.f);
    let answer = send(
        &s.f,
        Some(&cwd),
        None,
        "vault.approval_decide",
        json!({ "request": s.request, "approved": true }),
    );
    assert!(
        matches!(
            answer,
            Err(OpError::CapabilityNotHeld {
                capability: Capability::Admin
            })
        ),
        "{answer:?}"
    );
    assert_eq!(s.f.state.staged_approval_count_for_test(), 0);
}

// ------------------------------------------------------------------------------------------
// approving stages the value; the retry hands it over once
// ------------------------------------------------------------------------------------------

#[test]
fn approving_stages_the_value_and_the_retry_consumes_it_leaving_nothing_behind() {
    let s = requested();
    let decided = owner_decide(&s.f, &s.owner, &s.request, true).expect("approve");
    assert_eq!(decided["approved"], true);
    // The decision itself never returns the value.
    assert!(!decided.to_string().contains(SECRET), "{decided}");
    assert_eq!(s.f.state.staged_approval_count_for_test(), 1);
    assert!(
        !s.f.state.is_locked(),
        "the node is locked, the vault is not"
    );

    let got = agent_reveal(&s.f, &s.entry).expect("the retry hands over the staged value");
    assert_eq!(got["value"], SECRET);
    assert_eq!(got["node"], "acme");
    assert_eq!(
        s.f.state.staged_approval_count_for_test(),
        0,
        "consumption drops the staged value"
    );
    assert_eq!(s.f.state.approval_count_for_test(), 0);

    // Once. A second retry starts a brand-new request.
    let second = pending_id(agent_reveal(&s.f, &s.entry));
    assert_ne!(second, s.request, "a consumed id is never reusable");
}

/// Audit P1-1: an approval used to be keyed by (node, entry) alone, so a second caller was served the first one's approval,
/// whole. A request is now one slot per requester, and what it releases never goes beyond the fields it asked for.
#[test]
fn an_approval_is_taken_only_by_the_request_it_was_given_for() {
    // Two requesters (two keys) for the same entry are two requests.
    let s = requested();
    let a =
        s.f.state
            .approval_for_reveal("acme", &s.entry, None, "requester-a", None, NOW);
    let b =
        s.f.state
            .approval_for_reveal("acme", &s.entry, None, "requester-b", None, NOW);
    assert_ne!(a.id, b.id, "another requester is its own request");
    assert_ne!(
        a.id, s.request,
        "and not the agent's request in the work folder"
    );
    s.f.state.discard_approval(&a.id);
    s.f.state.discard_approval(&b.id);

    // The agent asks for one field; the person approves that request; the agent may not reach past it.
    let cwd = agent_cwd(&s.f);
    s.f.state.discard_approval(&s.request);
    let asked = pending_id(send_at(
        &s.f,
        NOW,
        Some(&cwd),
        None,
        "entry.reveal",
        json!({ "node": "acme", "entry": s.entry, "fieldIds": ["f_aaaaaaaa"] }),
    ));
    owner_decide(&s.f, &s.owner, &asked, true).expect("approve");
    // Asking for every field is not what was approved: refused, and the approval is still usable.
    let wider = agent_reveal(&s.f, &s.entry);
    assert_not_released(&wider, "a wider request");
    assert_eq!(
        s.f.state.staged_approval_count_for_test(),
        1,
        "the approval was not burned"
    );
}

/// Re-verification NEW-P2-a: the requester is the node and the token, not the process's working directory, so a caller
/// cannot mint requesters (and flood the table) from the subdirectories of its own folder.
#[test]
fn a_callers_subdirectories_are_one_requester() {
    let s = requested();
    let base = agent_cwd(&s.f);
    for sub in ["a", "a/b", "c/d/e", "x"] {
        let cwd = format!("{base}/{sub}");
        let again = pending_id(send_at(
            &s.f,
            NOW,
            Some(&cwd),
            None,
            "entry.reveal",
            json!({ "node": "acme", "entry": s.entry }),
        ));
        assert_eq!(
            again, s.request,
            "{sub}: the same request, not a new requester"
        );
    }
    assert_eq!(s.f.state.approval_count_for_test(), 1);
}

#[test]
fn a_denial_stages_nothing_and_a_decided_request_cannot_be_decided_again() {
    let s = requested();
    owner_decide(&s.f, &s.owner, &s.request, false).expect("deny");
    assert_eq!(s.f.state.staged_approval_count_for_test(), 0);

    let again = owner_decide(&s.f, &s.owner, &s.request, true);
    assert!(matches!(again, Err(OpError::Malformed(_))), "{again:?}");
    assert_eq!(
        s.f.state.staged_approval_count_for_test(),
        0,
        "a refused second decision must not stage anything"
    );

    let retried = agent_reveal(&s.f, &s.entry);
    assert!(
        matches!(
            retried,
            Err(OpError::ApprovalDenied {
                reason: "denied",
                ..
            })
        ),
        "{retried:?}"
    );
}

#[test]
fn an_approval_whose_entry_cannot_be_opened_stages_nothing_and_stays_undecided() {
    // A request for an entry that does not exist is not recorded at all (the table
    // holds one slot per real (node, entry), so an invented id cannot grow it) ...
    let s = requested();
    let answer = agent_reveal(&s.f, "e_000000000000");
    assert!(matches!(answer, Err(OpError::NotFound(_))), "{answer:?}");
    assert_eq!(
        s.f.state.approval_count_for_test(),
        1,
        "only the real request exists"
    );
    // ... and decrypting at decide time means a request whose envelope is gone is
    // refused to the decider instead of becoming an approval nothing can honour.
    std::fs::remove_file(s.f.state.paths.entry_env("acme", &s.entry)).unwrap();
    let answer = owner_decide(&s.f, &s.owner, &s.request, true);
    assert!(answer.is_err(), "{answer:?}");
    assert_eq!(s.f.state.staged_approval_count_for_test(), 0);
    // Not decided: it can still be denied, and default-denies at its TTL.
    owner_decide(&s.f, &s.owner, &s.request, false).expect("still undecided, so deniable");
}

// ------------------------------------------------------------------------------------------
// a staged approval never survives lock()
// ------------------------------------------------------------------------------------------

#[test]
fn a_staged_approval_never_survives_an_explicit_lock() {
    let s = requested();
    owner_decide(&s.f, &s.owner, &s.request, true).expect("approve");
    assert_eq!(s.f.state.staged_approval_count_for_test(), 1);

    send(&s.f, None, Some(&s.owner), "vault.lock", json!({})).expect("lock");
    assert_eq!(
        s.f.state.staged_approval_count_for_test(),
        0,
        "the value decrypted for the approval is gone the instant the vault locks"
    );

    // While locked the retry reports the approval as voided BY THE LOCK - not as
    // a refusal by the human, and never as the value (ADR-088: it used to be a bare
    // `vault_locked`; the request is now a real thing a person can answer).
    let during = agent_reveal(&s.f, &s.entry);
    match &during {
        Err(OpError::ApprovalDenied { request, reason }) => {
            assert_eq!(request, &s.request);
            assert_eq!(*reason, "locked");
        }
        other => panic!("expected approval_denied/locked, got {other:?}"),
    }
    assert_not_released(&during, "retry while locked");
    let body = wire(during.unwrap_err());
    assert_eq!(body["error"], "approval_denied");
    assert_eq!(body["reason"], "locked");

    // The next request is a fresh one and needs a fresh human decision.
    let _owner = login(&s.f);
    let fresh = pending_id(agent_reveal(&s.f, &s.entry));
    assert_ne!(fresh, s.request);
}

#[test]
fn the_sleep_signal_drops_a_staged_approval_too() {
    let s = requested();
    owner_decide(&s.f, &s.owner, &s.request, true).expect("approve");
    assert_eq!(s.f.state.staged_approval_count_for_test(), 1);
    s.f.state.external_lock_signal("sleep");
    assert!(s.f.state.is_locked());
    assert_eq!(s.f.state.staged_approval_count_for_test(), 0);
    assert_not_released(&agent_reveal(&s.f, &s.entry), "retry after sleep");
}

#[test]
fn the_idle_auto_lock_drops_a_staged_approval_too() {
    let s = requested();
    owner_decide(&s.f, &s.owner, &s.request, true).expect("approve");
    assert_eq!(s.f.state.staged_approval_count_for_test(), 1);

    s.f.state.set_vault_idle_seconds(60);
    s.f.state.touch_activity("acme", NOW);
    s.f.state.tick_autolock(NOW + 61);
    assert!(s.f.state.is_locked(), "idle past the threshold locks");
    assert_eq!(s.f.state.staged_approval_count_for_test(), 0);
    assert_not_released(
        &agent_reveal_at(&s.f, NOW + 62, &s.entry),
        "retry after idle",
    );
}

#[test]
fn a_lock_that_races_an_approval_stores_nothing() {
    // The deterministic form of the race: a decider reads the lock epoch, the
    // vault locks, and only then would the staged value be stored. The store step
    // refuses; nothing is staged and the request is still undecided.
    let s = requested();
    let epoch = s.f.state.lock_epoch();
    s.f.state.lock();
    assert!(
        s.f.state.lock_epoch() > epoch,
        "every lock moves the epoch on"
    );

    let verdict = ApprovalVerdict::Approve {
        staged: SecretBox::new(Box::new(SECRET.to_string())),
        lock_epoch: epoch,
    };
    let refused = s.f.state.decide_approval(&s.request, verdict, NOW + 1);
    assert_eq!(refused, Err(ApprovalDecideError::LockedMeanwhile));
    assert_eq!(s.f.state.staged_approval_count_for_test(), 0);
    let record =
        s.f.state
            .peek_approval(&s.request, NOW + 1)
            .expect("the request is still on record");
    assert_eq!(record.decision, None, "and still undecided");

    // The control: with the CURRENT epoch the very same call stores the value.
    let current = s.f.state.lock_epoch();
    let verdict = ApprovalVerdict::Approve {
        staged: SecretBox::new(Box::new(SECRET.to_string())),
        lock_epoch: current,
    };
    s.f.state
        .decide_approval(&s.request, verdict, NOW + 2)
        .expect("no lock since the epoch was read");
    assert_eq!(s.f.state.staged_approval_count_for_test(), 1);
    // ...and a lock now voids it.
    s.f.state.lock();
    assert_eq!(s.f.state.staged_approval_count_for_test(), 0);
}

/// The ordering the epoch argument rests on: a decider reads the epoch and THEN
/// checks `is_locked()`, so a lock must set the flag before it moves the epoch on.
/// If it moved the epoch first, a decider could read the new epoch, still see an
/// unlocked vault, and store its value after the void. An observer that spins on
/// "epoch, then flag" while a lock runs would catch that window; here it must
/// never see the epoch moved without the flag set.
///
/// The window this guards is microseconds wide, so one attempt can miss it (the
/// wrong order was caught in two runs of three when tried by hand). The in-memory
/// fixture can be unlocked again cheaply enough to try it a dozen times.
#[test]
fn once_the_lock_epoch_has_moved_the_vault_already_reads_as_locked() {
    const ATTEMPTS: usize = 12;
    let f = build_fixture();
    for attempt in 0..ATTEMPTS {
        f.state.unlock(0).expect("unlock the fixture");
        assert!(!f.state.is_locked(), "attempt {attempt}");
        let e0 = f.state.lock_epoch();

        let observer = {
            let state = Arc::clone(&f.state);
            std::thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(30);
                loop {
                    // The same two reads, in the same order, as `vault.approval_decide`.
                    let epoch = state.lock_epoch();
                    let locked = state.is_locked();
                    if epoch != e0 {
                        return (epoch, locked);
                    }
                    assert!(Instant::now() < deadline, "the lock never happened");
                }
            })
        };
        std::thread::sleep(Duration::from_millis(20)); // let it spin first
        f.state.lock();
        let (epoch, locked) = observer.join().expect("observer thread");
        assert!(epoch > e0, "attempt {attempt}");
        assert!(
            locked,
            "attempt {attempt}: the epoch moved but the vault still read as unlocked: a \
             decision could slip a staged value in behind the lock"
        );
    }
}

/// A decision racing a lock, many times over. The decider reads the epoch first
/// (as `vault.approval_decide` does, before it derives any key), then the two
/// threads are released together: the lock runs while the decider tries to store.
/// Whichever way they interleave, no staged value may be left behind - the store
/// is either refused (the epoch moved) or lands before the void and is voided.
/// (The in-memory fixture is used so a round costs nothing; `lock()` is the same
/// code the live vault runs.)
#[test]
fn a_decision_racing_a_lock_never_leaves_a_value_staged_behind_it() {
    const ROUNDS: usize = 1500;
    let f = build_fixture();
    let mut refused = 0usize;
    let mut stored_then_voided = 0usize;
    for round in 0..ROUNDS {
        let request = f
            .state
            .approval_for_reveal("a", &format!("e_race_{round}"), None, "k", None, NOW)
            .id;
        let epoch_read = f.state.lock_epoch();
        let barrier = Barrier::new(2);
        let outcome = std::thread::scope(|scope| {
            let decider = scope.spawn(|| {
                let verdict = ApprovalVerdict::Approve {
                    staged: SecretBox::new(Box::new("raced-value".to_string())),
                    lock_epoch: epoch_read,
                };
                barrier.wait();
                f.state.decide_approval(&request, verdict, NOW + 1)
            });
            let locker = scope.spawn(|| {
                barrier.wait();
                f.state.lock();
            });
            locker.join().expect("locker thread");
            decider.join().expect("decider thread")
        });
        assert!(
            f.state.lock_epoch() > epoch_read,
            "round {round}: the lock ran after the epoch read"
        );
        assert_eq!(
            f.state.staged_approval_count_for_test(),
            0,
            "round {round}: a value staged by a decision that began before a lock \
             survived the lock ({outcome:?})"
        );
        match outcome {
            Err(ApprovalDecideError::LockedMeanwhile) => refused += 1,
            Ok(()) => stored_then_voided += 1,
            other => panic!("round {round}: unexpected {other:?}"),
        }
        // Whatever the interleaving, leave no residue for the next round.
        f.state.discard_approval(&request);
    }
    // Reported, not asserted: the split depends on scheduling.
    eprintln!("race rounds: refused={refused} stored-then-voided={stored_then_voided}");
    assert_eq!(refused + stored_then_voided, ROUNDS);
}

// ------------------------------------------------------------------------------------------
// expiry
// ------------------------------------------------------------------------------------------

#[test]
fn an_approved_value_is_dropped_when_its_ttl_ends_even_if_nobody_retries() {
    let s = requested();
    owner_decide(&s.f, &s.owner, &s.request, true).expect("approve");
    assert_eq!(s.f.state.staged_approval_count_for_test(), 1);

    // Inside the TTL the timer leaves it alone.
    s.f.state.tick_autolock(NOW + 60);
    assert_eq!(s.f.state.staged_approval_count_for_test(), 1);
    assert!(!s.f.state.is_locked());

    // Past it, the timer zeroises it - the requester never has to come back for that.
    s.f.state.tick_autolock(NOW + 121);
    assert_eq!(
        s.f.state.staged_approval_count_for_test(),
        0,
        "a staged value must not outlive the request's 120 s"
    );
    assert!(!s.f.state.is_locked(), "expiry is not a lock");

    // The requester is told it expired, once.
    let late = agent_reveal_at(&s.f, NOW + 122, &s.entry);
    assert!(
        matches!(
            late,
            Err(OpError::ApprovalDenied {
                reason: "expired",
                ..
            })
        ),
        "{late:?}"
    );
    assert_not_released(&late, "retry after expiry");
}

#[test]
fn a_value_staged_at_the_last_second_is_not_handed_over_after_the_ttl() {
    // Without a tick: the retry itself must notice the expiry and drop the value.
    let s = requested();
    owner_decide(&s.f, &s.owner, &s.request, true).expect("approve");
    let late = agent_reveal_at(&s.f, NOW + 120, &s.entry);
    assert!(
        matches!(
            late,
            Err(OpError::ApprovalDenied {
                reason: "expired",
                ..
            })
        ),
        "{late:?}"
    );
    assert_eq!(s.f.state.staged_approval_count_for_test(), 0);
}

// ------------------------------------------------------------------------------------------
// ids
// ------------------------------------------------------------------------------------------

#[test]
fn approval_ids_are_128_bit_random_hex() {
    let s = requested();
    let mut ids = vec![s.request.clone()];
    // 40 real entries (a request is only recorded for an entry that exists).
    send(
        &s.f,
        None,
        Some(&s.owner),
        "vault.node_unlock",
        json!({ "node": "acme" }),
    )
    .unwrap();
    let real: Vec<String> = (0..40)
        .map(|i| {
            send(
                &s.f,
                None,
                Some(&s.owner),
                "entry.create",
                json!({ "node": "acme", "name": format!("N{i}"), "value": "v" }),
            )
            .unwrap()["entry"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect();
    send(
        &s.f,
        None,
        Some(&s.owner),
        "vault.node_lock",
        json!({ "node": "acme" }),
    )
    .unwrap();
    for id in &real {
        // A distinct (node, entry) pair is a distinct request.
        ids.push(pending_id(agent_reveal(&s.f, id)));
    }
    for id in &ids {
        let hex = id
            .strip_prefix("rq_")
            .unwrap_or_else(|| panic!("no rq_ prefix: {id}"));
        assert_eq!(hex.len(), 32, "128 bits = 32 hex digits: {id}");
        assert!(
            hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
            "lower-case hex only: {id}"
        );
    }
    let mut unique = ids.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), ids.len(), "no two requests share an id");
}

// ------------------------------------------------------------------------------------------
// the in-memory fixture (ADR-042's own) - unchanged behaviour, plus the 4a guarantees
// ------------------------------------------------------------------------------------------

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
    state.set_registry(reg);

    let node_pub = state.seed_node_key(&root_key, "a");
    let envelope = credmgr_core::envelope::seal(b"a-secret-value", &node_pub, "a", "e_a1")
        .expect("seal of a small fixed payload cannot fail");
    credmgr_store::atomic::write(&state.paths.entry_env("a", "e_a1"), &envelope)
        .expect("writing the fixture envelope");
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

fn fx_scope(caps: &[Capability]) -> BrokerScope {
    BrokerScope {
        node_id: "a".to_string(),
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

fn fx_reveal(f: &Fixture, now: i64) -> Result<Value, OpError> {
    ops::dispatch(
        &f.state,
        &fx_scope(FULL),
        now,
        "entry.reveal",
        &json!({ "node": "a", "entry": "e_a1" }),
    )
}

fn fx_decide(f: &Fixture, now: i64, request: &str, approved: bool) -> Result<Value, OpError> {
    ops::dispatch(
        &f.state,
        &fx_scope(&[Capability::Admin]),
        now,
        "vault.approval_decide",
        &json!({ "request": request, "approved": approved }),
    )
}

#[test]
fn the_retry_hands_over_the_staged_value_without_deriving_any_key() {
    let f = build_fixture(); // never unlocked: the ADR-042 shape
    let request = pending_id(fx_reveal(&f, NOW));
    fx_decide(&f, NOW + 10, &request, true).expect("approve");
    assert_eq!(f.state.staged_approval_count_for_test(), 1);

    // Make any LATER key derivation useless: re-wrap the root key under a
    // different one. A retry that re-derived the root key and unwrapped the node
    // key (the pre-ADR-079 behaviour) would now fail `internal`.
    let other = SecretBox::new(Box::new([9u8; 32]));
    f.state.seed_root_key(&other);
    {
        use secrecy::ExposeSecret;
        let derived = f
            .state
            .reauth_root_key("test")
            .expect("keystore still answers");
        assert_eq!(derived.expose_secret(), other.expose_secret());
        assert!(
            f.state
                .unwrap_node_key_with_root("a", derived.expose_secret())
                .is_none(),
            "the control: with the swapped root key the node key no longer unwraps"
        );
    }

    let got = fx_reveal(&f, NOW + 20).expect("the staged value needs no key at the retry");
    assert_eq!(got["value"], "a-secret-value");
    assert!(f.state.is_locked(), "and the vault is still locked");
    assert_eq!(f.state.staged_approval_count_for_test(), 0);
}

#[test]
fn on_the_fixture_a_lock_after_approval_voids_it_and_the_retry_is_told_locked() {
    // A fixture is not "durable", so it keeps the ADR-042 behaviour of answering
    // approval_pending while locked - but a lock still drops what was staged.
    let f = build_fixture();
    let request = pending_id(fx_reveal(&f, NOW));
    fx_decide(&f, NOW + 10, &request, true).expect("approve");
    assert_eq!(f.state.staged_approval_count_for_test(), 1);

    f.state.lock();
    assert_eq!(f.state.staged_approval_count_for_test(), 0);

    let retried = fx_reveal(&f, NOW + 20);
    match &retried {
        Err(OpError::ApprovalDenied { request: r, reason }) => {
            assert_eq!(r, &request);
            assert_eq!(*reason, "locked");
        }
        other => panic!("expected approval_denied/locked, got {other:?}"),
    }
    assert!(!format!("{retried:?}").contains("a-secret-value"));
}

#[test]
fn on_the_fixture_a_wholly_locked_vault_still_decides_and_completes_as_adr_042_says() {
    // The in-memory fixtures are explicitly out of 4a's refusal: there the keystore
    // really can re-derive the key, and ADR-042's own tests rely on it.
    let f = build_fixture();
    assert!(f.state.is_locked());
    let request = pending_id(fx_reveal(&f, NOW));
    let decided = fx_decide(&f, NOW + 5, &request, true).expect("a fixture decides while locked");
    assert_eq!(decided["approved"], true);
    let got = fx_reveal(&f, NOW + 6).expect("and completes");
    assert_eq!(got["value"], "a-secret-value");
}
