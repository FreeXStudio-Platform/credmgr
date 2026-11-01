//! ADR-077 — a session's bearer token never reaches the audit log.
//!
//! The defect (found by the endpoint-matrix lane, 2026-10-02): the audit record's
//! `actor` was the caller's token id — the bearer secret itself — and an anomaly's
//! `detail` embedded it too. The audit log is plaintext on disk and `audit.tail`
//! serves it to anyone who holds `list`, so any process under the owner's uid could
//! read the owner's live token out of the feed and replay it as the owner.
//!
//! Every test here drives the real wiring (`server::handle_request_at`: scope
//! resolution, dispatch, the audit write) against a vault `vault.init_*` created,
//! then looks at the produced **bytes** — the audit files on disk and the wire
//! responses — not at a field the implementation promises to have set. They go red
//! if `audit_actor` is pointed back at the bearer.

use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use secrecy::{ExposeSecret, SecretBox};
use serde_json::{json, Value};

use credmgr_brokerd::peer::PeerInfo;
use credmgr_brokerd::protocol::{OpError, Request};
use credmgr_brokerd::scope::BrokerScope;
use credmgr_brokerd::server;
use credmgr_brokerd::state::BrokerState;
use credmgr_core::access::Origin;
use credmgr_core::registry::{Capability, GLOBAL_ID};
use credmgr_keystore::software::SoftwareKeystore;

const NOW: i64 = 1_800_000_000;
const PASSPHRASE: &str = "correct horse battery staple";

struct Fixture {
    state: Arc<BrokerState>,
    vault_dir: std::path::PathBuf,
    /// A real directory an `acme` node can be bound to (`node.create` checks it).
    acme_workdir: std::path::PathBuf,
    _dir: tempfile::TempDir,
}

/// `credmgr init` for real, on a broker that is then returned still running.
fn created_vault() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault_dir = dir.path().join("vault");
    let state_dir = dir.path().join("state");
    std::fs::create_dir_all(&vault_dir).unwrap();
    std::fs::create_dir_all(&state_dir).unwrap();
    let acme_workdir = dir.path().join("work").join("acme");
    std::fs::create_dir_all(acme_workdir.join("src")).unwrap();
    // The broker stores and compares real paths; on macOS the temp directory is
    // a symlink (`/var` -> `/private/var`), so resolve it up front.
    let acme_workdir = std::fs::canonicalize(&acme_workdir).unwrap();
    let keystore = SoftwareKeystore::new(
        SecretBox::new(Box::default()),
        state_dir.join("placeholder-keystore"),
    );
    let state = Arc::new(BrokerState::new(
        Box::new(keystore),
        credmgr_store::paths::VaultPaths::new(vault_dir.clone()),
    ));
    state.set_state_dir_for_test(state_dir);

    let anyone = BrokerScope {
        node_id: GLOBAL_ID.to_string(),
        capabilities: vec![Capability::List],
        origin: Origin::Agent,
        token_id: None,
        bound_workdir: None,
    };
    let begin = credmgr_brokerd::ops::dispatch(
        &state,
        &anyone,
        NOW,
        "vault.init_begin",
        &json!({ "passphrase": PASSPHRASE }),
    )
    .expect("init_begin");
    let code = begin["recoveryCode"].as_str().unwrap().to_string();
    credmgr_brokerd::ops::dispatch(
        &state,
        &anyone,
        NOW,
        "vault.init_confirm",
        &json!({ "recoveryCode": code }),
    )
    .expect("init_confirm");
    Fixture {
        state,
        vault_dir,
        acme_workdir,
        _dir: dir,
    }
}

fn peer(cwd: Option<&str>) -> PeerInfo {
    PeerInfo {
        uid: 501,
        pid: 1,
        cwd: cwd.map(str::to_string),
    }
}

/// One request through the full server path (scope → dispatch → audit record).
fn send(
    f: &Fixture,
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
    server::handle_request_at(&f.state, &peer(cwd), &request, NOW, Instant::now()).0
}

/// A real login: the bearer `vault.unlock` hands back.
fn login(f: &Fixture) -> String {
    send(
        f,
        None,
        None,
        "vault.unlock",
        json!({ "passphrase": PASSPHRASE }),
    )
    .expect("unlock")["token"]
        .as_str()
        .expect("a real login mints a token")
        .to_string()
}

/// Every byte under `<vault>/audit/` — the log and its tip sidecar.
fn audit_bytes(vault_dir: &Path) -> String {
    let dir = vault_dir.join("audit");
    let mut all = String::new();
    for entry in std::fs::read_dir(dir).expect("the audit directory exists") {
        let path = entry.unwrap().path();
        all.push_str(&String::from_utf8_lossy(&std::fs::read(&path).unwrap()));
        all.push('\n');
    }
    assert!(
        all.contains("\"action\""),
        "the control: the audit log has records in it at all\n{all}"
    );
    all
}

fn assert_absent(what: &str, secret: &str, haystack: &str) {
    assert!(
        !haystack.contains(secret),
        "{what} contains a bearer token ({} bytes of secret found in {} bytes of text)",
        secret.len(),
        haystack.len()
    );
}

#[test]
fn a_session_token_never_reaches_the_audit_files_or_any_audit_response() {
    let f = created_vault();
    let owner = login(&f);

    // A realistic session: writes, a read, a denial, a malformed call, a lock.
    let acme = f.acme_workdir.clone();
    send(
        &f,
        None,
        Some(&owner),
        "node.create",
        json!({ "id": "acme", "label": "Acme", "parentId": "global",
                "workdirs": [acme.to_string_lossy()] }),
    )
    .expect("node.create");
    let created = send(
        &f,
        None,
        Some(&owner),
        "entry.create",
        json!({ "node": "acme", "name": "API_KEY", "value": "v-1" }),
    )
    .expect("entry.create");
    let entry = created["entry"].as_str().unwrap().to_string();
    send(
        &f,
        None,
        Some(&owner),
        "entry.reveal",
        json!({ "node": "acme", "entry": entry }),
    )
    .expect("entry.reveal");
    assert!(matches!(
        send(
            &f,
            None,
            Some(&owner),
            "entry.update",
            json!({ "node": "acme", "entry": entry, "value": "x", "generation": 0 })
        ),
        Err(OpError::Conflict { .. })
    ));
    assert!(matches!(
        send(&f, None, Some(&owner), "entry.list", json!({})),
        Err(OpError::Malformed(_))
    ));

    // The anomaly path writes its own record, with its own `detail`: a token
    // bound to a workdir, presented by a process somewhere else.
    let bound = f.state.tokens.issue(
        "acme",
        vec![Capability::List, Capability::Read],
        Origin::Agent,
        Some("/the/bound/workdir".to_string()),
    );
    send(
        &f,
        Some("/somewhere/else"),
        Some(&bound.id),
        "whoami",
        json!({}),
    )
    .expect("whoami under a bound token");

    // --- the bytes on disk ----------------------------------------------------------------
    let files = audit_bytes(&f.vault_dir);
    assert_absent("an audit file", &owner, &files);
    assert_absent("an audit file", &bound.id, &files);
    assert!(
        files.contains("anomaly.token_workdir_mismatch"),
        "the control: the anomaly record was written\n{files}"
    );

    // --- every audit response, as each kind of reader ----------------------------------------
    // The owner (full shape), an unscoped process, and a process inside acme's workdir.
    let as_owner = send(
        &f,
        None,
        Some(&owner),
        "audit.tail",
        json!({ "limit": 500 }),
    )
    .unwrap();
    let as_anyone = send(
        &f,
        Some("/tmp"),
        None,
        "audit.tail",
        json!({ "limit": 500 }),
    )
    .unwrap();
    let as_agent = send(
        &f,
        Some(&format!("{}/src", acme.to_string_lossy())),
        None,
        "audit.tail",
        json!({ "limit": 500 }),
    )
    .unwrap();
    for (who, feed) in [
        ("owner", &as_owner),
        ("unscoped", &as_anyone),
        ("agent", &as_agent),
    ] {
        let text = feed.to_string();
        assert_absent(&format!("the {who} audit.tail feed"), &owner, &text);
        assert_absent(&format!("the {who} audit.tail feed"), &bound.id, &text);
    }
    // audit.get answers a refusal; its body must be clean too.
    let get = send(
        &f,
        None,
        Some(&owner),
        "audit.get",
        json!({ "id": "a_000000000000" }),
    );
    match get {
        Err(e) => {
            let wire = credmgr_brokerd::protocol::to_wire("r", &Err(e)).to_string();
            assert_absent("the audit.get refusal", &owner, &wire);
        }
        Ok(v) => panic!("audit.get without presence must refuse, got {v}"),
    }

    // --- and the session is still identifiable, by a name that is not the key ----------------
    let public = f
        .state
        .tokens
        .public_id(&owner)
        .expect("the session is live");
    assert_ne!(public, owner);
    let records = as_owner["records"].as_array().unwrap();
    let mine: Vec<&Value> = records
        .iter()
        .filter(|r| r["action"] == "entry.reveal")
        .collect();
    assert_eq!(mine.len(), 1, "{records:?}");
    assert_eq!(
        mine[0]["actor"],
        json!(format!("HumanUi:{public}")),
        "the actor names the origin and the session's public id"
    );
    // The public id authenticates nothing: presenting it as a token is a dead login.
    assert!(matches!(
        send(
            &f,
            None,
            Some(&public),
            "entry.list",
            json!({ "node": "acme" })
        ),
        Err(OpError::SessionExpired)
    ));
    // The anomaly record names the *bound* session, also by public id.
    let anomaly = records
        .iter()
        .find(|r| r["action"] == "anomaly.token_workdir_mismatch")
        .expect("the anomaly is in the feed");
    assert_eq!(
        anomaly["actor"],
        json!(format!("Agent:{}", bound.public_id))
    );
    assert!(anomaly["detail"]
        .as_str()
        .unwrap()
        .contains(&bound.public_id));
}

/// Tokens die with their session; this checks the other half — a build that had
/// the leak left `cmt_…` strings in its audit files, and those must neither break
/// verification (history is not rewritten) nor ever be served again.
#[test]
fn a_record_written_by_a_leaking_build_still_verifies_and_is_never_served() {
    let f = created_vault();
    let owner = login(&f);
    // What the broker before ADR-077 wrote: the bearer as the actor, the bearer
    // inside an anomaly's detail.
    let old_bearer = "cmt_00112233445566778899aabbccddeeff";
    let root = f
        .state
        .reauth_root_key("test: write an old-style record")
        .expect("the vault is unlocked");
    let ym = credmgr_store::audit::year_month_for(NOW);
    credmgr_store::audit::append(
        &f.state.paths,
        root.expose_secret(),
        &ym,
        credmgr_store::audit::NewEvent {
            actor: old_bearer.to_string(),
            action: "anomaly.token_workdir_mismatch".to_string(),
            node_id: Some(GLOBAL_ID.to_string()),
            detail: Some(format!("token {old_bearer} bound to \"/a\", cwd is \"/b\"")),
            ..Default::default()
        },
        NOW,
    )
    .expect("append an old-style record");
    // A new record after it, through the real path.
    send(&f, None, Some(&owner), "whoami", json!({})).expect("whoami");

    // 1. The hash chain and the signed tip still verify across old and new lines:
    //    nothing rewrote history.
    credmgr_store::audit::verify(&f.state.paths, root.expose_secret(), &ym)
        .expect("the audit log verifies with an old-style line in it");
    let on_disk = audit_bytes(&f.vault_dir);
    assert!(
        on_disk.contains(old_bearer),
        "the control: the old line really is on disk, untouched\n{on_disk}"
    );

    // 2. Nothing serves it: the full shape, and the agent's redacted shape.
    let full = send(
        &f,
        None,
        Some(&owner),
        "audit.tail",
        json!({ "limit": 500 }),
    )
    .unwrap();
    let agent = send(
        &f,
        Some("/tmp"),
        None,
        "audit.tail",
        json!({ "limit": 500 }),
    )
    .unwrap();
    for (who, feed) in [("owner", full), ("agent", agent)] {
        let text = feed.to_string();
        assert_absent(&format!("the {who} feed"), old_bearer, &text);
        assert!(
            text.contains("[redacted-token]"),
            "the {who} feed shows the old line redacted, not missing\n{text}"
        );
    }
}

/// A bearer pasted into a free-text field (`reason`) is scrubbed on its way into
/// the log, whatever route it took — the choke point, not the call sites.
#[test]
fn a_bearer_typed_into_a_reason_is_scrubbed_before_it_is_written() {
    let f = created_vault();
    let owner = login(&f);
    send(
        &f,
        None,
        Some(&owner),
        "node.create",
        json!({ "id": "acme", "label": "Acme", "parentId": "global" }),
    )
    .expect("node.create");
    send(
        &f,
        None,
        Some(&owner),
        "node.policy",
        json!({ "node": "acme", "reason": format!("rotating {owner} soon"),
                "policy": { "privateNames": true } }),
    )
    .expect("node.policy");
    assert_absent("the audit files", &owner, &audit_bytes(&f.vault_dir));
}

/// `Debug` is how secrets end up in panic messages and test output; none of the
/// types that carry a bearer may print it.
#[test]
fn nothing_that_carries_a_bearer_prints_it() {
    let f = created_vault();
    let owner = login(&f);
    let request = Request {
        id: "r".to_string(),
        op: "whoami".to_string(),
        token: Some(owner.clone()),
        params: json!({}),
    };
    assert_absent("Request's Debug", &owner, &format!("{request:?}"));
    let registry = f.state.registry.read().unwrap().clone();
    let (scope, _) = credmgr_brokerd::scope::resolve_scope(
        &registry,
        &f.state.tokens,
        &peer(None),
        Some(&owner),
    );
    assert!(scope.token_id.is_some(), "the control: the token resolved");
    assert_absent("BrokerScope's Debug", &owner, &format!("{scope:?}"));
    let token = f.state.tokens.get(&owner).unwrap();
    assert_absent("Token's Debug", &owner, &format!("{token:?}"));
}
