//! Shared fixture for the Part 4 broker tests: a real `vault.init_*` vault on a
//! throwaway directory (`tempfile`), driven through the real server wiring
//! (`server::handle_request_at`), with the owner logged in and `acme` bound to a
//! real workdir. No test touches the user's own vault.
#![allow(dead_code)]

use std::sync::Arc;
use std::time::Instant;

use secrecy::SecretBox;
use serde_json::{json, Value};

use credmgr_brokerd::peer::PeerInfo;
use credmgr_brokerd::protocol::{to_wire, OpError, Request};
use credmgr_brokerd::scope::BrokerScope;
use credmgr_brokerd::server;
use credmgr_brokerd::state::BrokerState;
use credmgr_core::access::Origin;
use credmgr_core::registry::{Capability, GLOBAL_ID};
use credmgr_keystore::software::SoftwareKeystore;

pub const NOW: i64 = 1_800_000_000;
pub const PASSPHRASE: &str = "correct horse battery staple";

pub struct Fixture {
    pub state: Arc<BrokerState>,
    pub acme_workdir: std::path::PathBuf,
    pub _dir: tempfile::TempDir,
}

/// A broker over a directory with no vault in it (nothing initialised yet).
pub fn empty_broker() -> Fixture {
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
        credmgr_store::paths::VaultPaths::new(vault_dir),
    ));
    state.set_state_dir_for_test(state_dir);
    Fixture {
        state,
        acme_workdir,
        _dir: dir,
    }
}

pub fn anyone() -> BrokerScope {
    BrokerScope {
        node_id: GLOBAL_ID.to_string(),
        capabilities: vec![Capability::List],
        origin: Origin::Agent,
        token_id: None,
        bound_workdir: None,
    }
}

/// `credmgr init` for real; returns the broker still running (and unlocked by
/// the init itself being followed by a login in `login`).
pub fn created_vault() -> Fixture {
    let f = empty_broker();
    let begin = credmgr_brokerd::ops::dispatch(
        &f.state,
        &anyone(),
        NOW,
        "vault.init_begin",
        &json!({ "passphrase": PASSPHRASE }),
    )
    .expect("init_begin");
    let code = begin["recoveryCode"].as_str().unwrap().to_string();
    credmgr_brokerd::ops::dispatch(
        &f.state,
        &anyone(),
        NOW,
        "vault.init_confirm",
        &json!({ "recoveryCode": code }),
    )
    .expect("init_confirm");
    f
}

pub fn peer(cwd: Option<&str>) -> PeerInfo {
    PeerInfo {
        uid: 501,
        pid: 1,
        cwd: cwd.map(str::to_string),
    }
}

pub fn send(
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

pub fn login(f: &Fixture) -> String {
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

/// A logged-in broker with `acme` (bound to a real workdir) and one entry in it.
pub fn with_acme() -> (Fixture, String, String) {
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
        json!({ "node": "acme", "name": "API_KEY", "value": "v-1" }),
    )
    .expect("entry.create")["entry"]
        .as_str()
        .unwrap()
        .to_string();
    (f, owner, entry)
}

pub fn wire(err: OpError) -> Value {
    to_wire("r", &Err(err))
}

/// A directory inside `acme`'s workdir: a tokenless process there is a
/// cwd-scoped agent with `acme`'s `agentAccess` policy (read-write by default).
pub fn agent_cwd(f: &Fixture) -> String {
    format!("{}/src", f.acme_workdir.to_string_lossy())
}

/// `send` as that tokenless agent.
pub fn as_agent(f: &Fixture, op: &str, params: Value) -> Result<Value, OpError> {
    send(f, Some(&agent_cwd(f)), None, op, params)
}

/// Creates `name` in `acme` as the owner; the entry id.
pub fn create_as_owner(f: &Fixture, owner: &str, name: &str) -> String {
    send(
        f,
        None,
        Some(owner),
        "entry.create",
        json!({ "node": "acme", "name": name, "value": "v-1" }),
    )
    .expect("entry.create")["entry"]
        .as_str()
        .unwrap()
        .to_string()
}

/// `send` at an explicit clock, for tests that move time (TOTP steps, elevation).
pub fn send_at(
    f: &Fixture,
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

/// The restart: drops the broker and builds a fresh one over the same vault and
/// state directories. Nothing carries across except what is on disk.
pub fn restart(f: Fixture) -> Fixture {
    let Fixture {
        state,
        acme_workdir,
        _dir,
    } = f;
    drop(state);
    let state_dir = _dir.path().join("state");
    let vault_dir = _dir.path().join("vault");
    let keystore = SoftwareKeystore::new(
        SecretBox::new(Box::default()),
        state_dir.join("placeholder-keystore"),
    );
    let state = Arc::new(BrokerState::new(
        Box::new(keystore),
        credmgr_store::paths::VaultPaths::new(vault_dir),
    ));
    state.set_state_dir_for_test(state_dir);
    Fixture {
        state,
        acme_workdir,
        _dir,
    }
}

/// `as_agent` at an explicit clock.
pub fn as_agent_at(f: &Fixture, now: i64, op: &str, params: Value) -> Result<Value, OpError> {
    send_at(f, now, Some(&agent_cwd(f)), None, op, params)
}
