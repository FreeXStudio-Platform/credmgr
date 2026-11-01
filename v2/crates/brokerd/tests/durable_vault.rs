//! ADR-063 and ADR-064 — the vault on disk, across a broker restart.
//!
//! Every test here builds a real vault with `vault.init_*` into a temporary
//! directory, then "restarts" the broker the only way that means anything:
//! it drops the `BrokerState` and builds a **fresh** one over the same vault
//! and state directories, with the daemon's own inert placeholder keystore
//! (`credmgrd::main`). Nothing carries across except what is on disk — which
//! is exactly the property these tests exist for. Before ADR-063 every one
//! of them failed: the live unlock answered `wrong_passphrase` to the right
//! passphrase, and a restart kept the ciphertext files but lost every name,
//! node and gate.
//!
//! Test **`the_last_door_…`** is Phase 5's sixth exit-gate line
//! (`12_BUILD_PLAN.md §2.6`): "Passphrase plus root recovery code re-enrols
//! the gate after a simulated device loss."

use std::path::PathBuf;
use std::sync::Arc;

use secrecy::SecretBox;
use serde_json::{json, Value};

use credmgr_brokerd::ops;
use credmgr_brokerd::protocol::OpError;
use credmgr_brokerd::scope::BrokerScope;
use credmgr_brokerd::state::BrokerState;
use credmgr_core::access::Origin;
use credmgr_core::registry::{Capability, GLOBAL_ID};
use credmgr_core::totp::{decode_gate_secret_base32, Totp};
use credmgr_keystore::software::SoftwareKeystore;
use credmgr_store::paths::VaultPaths;

const NOW: i64 = 1_800_000_000;
const PASSPHRASE: &str = "correct horse battery staple";

/// What `mint_session_token` hands a real login: every capability, as a
/// human at the UI, on `global`.
fn human() -> BrokerScope {
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

/// The scope a real login presents: the token `vault.unlock` minted, which
/// is what makes it an owner session (ADR-065) rather than a fixture claim.
fn session(state: &BrokerState, token: &str) -> BrokerScope {
    let peer = credmgr_brokerd::peer::PeerInfo {
        uid: 501,
        pid: 1,
        cwd: None,
    };
    let registry = state.registry.read().unwrap().clone();
    credmgr_brokerd::scope::resolve_scope(&registry, &state.tokens, &peer, Some(token)).0
}

/// An unauthenticated local caller — what a locked-out operator is.
fn anyone() -> BrokerScope {
    BrokerScope {
        node_id: GLOBAL_ID.to_string(),
        capabilities: vec![Capability::List],
        origin: Origin::Agent,
        token_id: None,
        bound_workdir: None,
    }
}

struct Vault {
    vault_dir: PathBuf,
    state_dir: PathBuf,
    root_recovery_code: String,
    _dir: tempfile::TempDir,
}

impl Vault {
    fn paths(&self) -> VaultPaths {
        VaultPaths::new(self.vault_dir.clone())
    }

    /// A freshly started broker over this vault — the restart.
    fn broker(&self) -> Arc<BrokerState> {
        let keystore = SoftwareKeystore::new(
            SecretBox::new(Box::default()),
            self.state_dir.join("placeholder-keystore"),
        );
        let state = Arc::new(BrokerState::new(Box::new(keystore), self.paths()));
        state.set_state_dir_for_test(self.state_dir.clone());
        state
    }
}

fn call(
    state: &BrokerState,
    scope: &BrokerScope,
    now: i64,
    op: &str,
    params: Value,
) -> Result<Value, OpError> {
    ops::dispatch(state, scope, now, op, &params)
}

/// `credmgr init`, for real, on a broker that is then returned still running
/// — the same process a user would go on to unlock.
fn created_vault() -> (Vault, Arc<BrokerState>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault_dir = dir.path().join("vault");
    let state_dir = dir.path().join("state");
    std::fs::create_dir_all(&vault_dir).unwrap();
    std::fs::create_dir_all(&state_dir).unwrap();
    let mut vault = Vault {
        vault_dir,
        state_dir,
        root_recovery_code: String::new(),
        _dir: dir,
    };
    let state = vault.broker();
    let begin = call(
        &state,
        &anyone(),
        NOW,
        "vault.init_begin",
        json!({ "passphrase": PASSPHRASE }),
    )
    .expect("init_begin");
    let code = begin["recoveryCode"].as_str().unwrap().to_string();
    call(
        &state,
        &anyone(),
        NOW,
        "vault.init_confirm",
        json!({ "recoveryCode": code }),
    )
    .expect("init_confirm");
    vault.root_recovery_code = code;
    (vault, state)
}

fn unlock(state: &BrokerState, passphrase: &str) -> Result<Value, OpError> {
    call(
        state,
        &anyone(),
        NOW,
        "vault.unlock",
        json!({ "passphrase": passphrase }),
    )
}

/// Unlock and return the owner-session scope the minted token resolves to.
fn login(state: &BrokerState) -> BrokerScope {
    let token = unlock(state, PASSPHRASE).expect("unlock")["token"]
        .as_str()
        .expect("a real login mints a token")
        .to_string();
    session(state, &token)
}

/// Enrol and confirm the vault gate at `NOW`, returning its `Totp`.
fn enrol_gate(state: &BrokerState) -> (Totp, Vec<String>) {
    let begin =
        call(state, &human(), NOW, "vault.gate_enroll_begin", json!({})).expect("enroll_begin");
    let totp = totp_from_uri(begin["otpauthUri"].as_str().unwrap());
    let confirm = call(
        state,
        &human(),
        NOW,
        "vault.gate_enroll_confirm",
        json!({ "code": totp.code(NOW as u64) }),
    )
    .expect("enroll_confirm");
    let codes = confirm["recoveryCodes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap().to_string())
        .collect();
    (totp, codes)
}

fn totp_from_uri(uri: &str) -> Totp {
    let b32 = uri
        .split("secret=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap();
    Totp::new_gate(decode_gate_secret_base32(b32).unwrap())
}

fn two_factor_required(result: Result<Value, OpError>) -> bool {
    matches!(result, Err(OpError::TwoFactorRequired { .. }))
}

#[test]
fn a_vault_created_by_init_unlocks_with_its_passphrase_on_the_same_broker() {
    let (_vault, state) = created_vault();
    assert!(
        state.is_durable(),
        "a vault init wrote is disk-backed from that moment"
    );
    let unlocked = unlock(&state, PASSPHRASE).expect("the passphrase init was given opens it");
    assert_eq!(unlocked["locked"], false);
    assert!(unlocked["token"].as_str().unwrap().starts_with("cmt_"));
    assert!(!state.is_locked());
}

#[test]
fn after_a_restart_the_passphrase_unlock_loads_the_vault_from_disk() {
    let (vault, first) = created_vault();
    drop(first);

    let state = vault.broker();
    assert!(
        !state.is_durable(),
        "a fresh daemon has loaded nothing before an unlock"
    );
    assert!(state.registry.read().unwrap().nodes.is_empty());

    unlock(&state, PASSPHRASE).expect("the live unlock opens a vault it did not create");
    assert!(state.is_durable());
    assert!(!state.is_locked());
    assert!(state.registry.read().unwrap().nodes.contains_key(GLOBAL_ID));
}

#[test]
fn a_wrong_passphrase_opens_nothing_and_loads_nothing() {
    let (vault, first) = created_vault();
    drop(first);
    let state = vault.broker();

    assert!(matches!(
        unlock(&state, "not the passphrase"),
        Err(OpError::WrongPassphrase)
    ));
    assert!(state.is_locked());
    assert!(
        !state.is_durable(),
        "nothing was loaded under a key that was never proven"
    );
    assert!(state.registry.read().unwrap().nodes.is_empty());
    // And with no passphrase at all, the daemon's placeholder refuses too.
    assert!(matches!(
        call(&state, &anyone(), NOW, "vault.unlock", json!({})),
        Err(OpError::WrongPassphrase)
    ));
}

#[test]
fn nodes_and_entries_written_before_a_restart_are_there_after_it() {
    let (vault, state) = created_vault();
    let owner = login(&state);
    call(
        &state,
        &owner,
        NOW,
        "node.create",
        json!({ "id": "acme", "label": "Acme", "parentId": GLOBAL_ID }),
    )
    .expect("node.create");
    let created = call(
        &state,
        &owner,
        NOW,
        "entry.create",
        json!({ "node": "acme", "name": "DEPLOY_TOKEN", "value": "first-value" }),
    )
    .expect("the owner writes into their own project (ADR-065)");
    let entry = created["entry"].as_str().unwrap().to_string();
    let generation = created["generation"].as_u64().unwrap();
    call(
        &state,
        &owner,
        NOW,
        "entry.update",
        json!({ "node": "acme", "entry": entry, "value": "second-value", "generation": generation }),
    )
    .expect("entry.update");
    drop(state);

    let state = vault.broker();
    let owner = login(&state);
    let listed =
        call(&state, &owner, NOW, "entry.list", json!({ "node": "acme" })).expect("entry.list");
    assert_eq!(
        listed["names"],
        json!(["DEPLOY_TOKEN"]),
        "the name survived the restart"
    );
    assert_eq!(
        listed["generation"],
        generation + 1,
        "and so did the manifest generation"
    );
    let revealed = call(
        &state,
        &owner,
        NOW,
        "entry.reveal",
        json!({ "node": "acme", "entry": entry }),
    )
    .expect("reveal");
    assert_eq!(
        revealed["value"], "second-value",
        "the updated value, decrypted with the reloaded node key"
    );
    let verified = call(&state, &owner, NOW, "maintenance.verify", json!({})).unwrap();
    assert_eq!(
        verified["ok"], true,
        "the updated envelope matches its digest after a restart (ADR-067): {verified}"
    );
}

/// ADR-065: the owner's login reaches every project; nothing else widens.
#[test]
fn the_owner_session_reaches_every_project_but_an_agent_and_a_fixture_claim_do_not() {
    let (_vault, state) = created_vault();
    let owner = login(&state);
    for id in ["acme", "globex"] {
        call(
            &state,
            &owner,
            NOW,
            "node.create",
            json!({ "id": id, "label": id, "parentId": GLOBAL_ID }),
        )
        .expect("node.create");
    }
    call(
        &state,
        &owner,
        NOW,
        "entry.create",
        json!({ "node": "acme", "name": "A", "value": "a" }),
    )
    .unwrap();
    call(
        &state,
        &owner,
        NOW,
        "entry.create",
        json!({ "node": "globex", "name": "G", "value": "g" }),
    )
    .unwrap();

    let who = call(&state, &owner, NOW, "whoami", json!({})).unwrap();
    let mut reachable: Vec<String> = who["reachable"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    reachable.sort();
    assert_eq!(
        reachable,
        ["acme", "global", "globex"],
        "the owner's whole vault graph"
    );

    // An agent scoped to acme still cannot read globex — isolation between
    // projects is untouched.
    let agent = BrokerScope {
        node_id: "acme".into(),
        capabilities: vec![Capability::List, Capability::Read, Capability::Reveal],
        origin: Origin::Agent,
        token_id: None,
        bound_workdir: None,
    };
    assert!(matches!(
        call(
            &state,
            &agent,
            NOW,
            "entry.list",
            json!({ "node": "globex" })
        ),
        Err(OpError::NodeAccessDenied { .. })
    ));
    // Nor does a scope that merely *claims* HumanUi + every capability,
    // without a token a real unlock minted.
    assert!(matches!(
        call(
            &state,
            &human(),
            NOW,
            "entry.list",
            json!({ "node": "globex" })
        ),
        Err(OpError::NodeAccessDenied { .. })
    ));
    // And locking ends the reach with the session.
    call(&state, &owner, NOW, "vault.lock", json!({})).unwrap();
    assert!(!state.is_owner_session(&owner), "lock revokes the login");
}

/// ADR-066: a directory bound to a node scopes an agent launched in it —
/// the mechanism `03_DATA_MODEL.md §1` describes and nothing could set.
#[test]
fn a_bound_workdir_scopes_an_agent_to_its_project_and_survives_a_restart() {
    let (vault, state) = created_vault();
    let owner = login(&state);
    let project_dir = vault
        .vault_dir
        .parent()
        .unwrap()
        .join("work")
        .join("acme-repo");
    std::fs::create_dir_all(project_dir.join("src")).unwrap();
    call(
        &state,
        &owner,
        NOW,
        "node.create",
        json!({ "id": "acme", "label": "Acme", "parentId": GLOBAL_ID }),
    )
    .unwrap();
    let bound = call(
        &state,
        &owner,
        NOW,
        "node.set_workdirs",
        json!({ "node": "acme", "workdirs": [project_dir.to_string_lossy()] }),
    )
    .expect("the owner binds a directory");
    let canonical = std::fs::canonicalize(&project_dir)
        .unwrap()
        .to_string_lossy()
        .into_owned();
    assert_eq!(
        bound["workdirs"],
        json!([canonical]),
        "stored canonical, as the kernel reports a cwd"
    );

    // Refusals: relative, missing, the root, a directory another node owns, an agent.
    for (params, why) in [
        (
            json!({ "node": "acme", "workdirs": ["relative/dir"] }),
            "relative",
        ),
        (
            json!({ "node": "acme", "workdirs": ["/definitely/not/here/x9"] }),
            "missing",
        ),
        (json!({ "node": "acme", "workdirs": ["/"] }), "root"),
    ] {
        assert!(
            matches!(
                call(&state, &owner, NOW, "node.set_workdirs", params),
                Err(OpError::Malformed(_))
            ),
            "{why} must be refused"
        );
    }
    call(
        &state,
        &owner,
        NOW,
        "node.create",
        json!({ "id": "globex", "label": "G", "parentId": GLOBAL_ID }),
    )
    .unwrap();
    assert!(
        matches!(
            call(&state, &owner, NOW, "node.set_workdirs", json!({ "node": "globex", "workdirs": [canonical] })),
            Err(OpError::Malformed(m)) if m.contains("invariant")
        ),
        "one directory maps to one node"
    );
    let agent = BrokerScope {
        node_id: "acme".into(),
        capabilities: vec![
            Capability::List,
            Capability::Read,
            Capability::Reveal,
            Capability::Create,
            Capability::Update,
        ],
        origin: Origin::Agent,
        token_id: None,
        bound_workdir: Some(canonical.clone()),
    };
    assert!(matches!(
        call(
            &state,
            &agent,
            NOW,
            "node.set_workdirs",
            json!({ "node": "acme", "workdirs": [] })
        ),
        Err(OpError::CapabilityNotHeld { .. })
    ));
    drop(state);

    // After a restart, a process whose cwd is inside the directory resolves
    // to acme — and one outside it to global's list-only fallback.
    let state = vault.broker();
    let _owner = login(&state);
    let registry = state.registry.read().unwrap().clone();
    let inside = credmgr_brokerd::peer::PeerInfo {
        uid: 501,
        pid: 2,
        cwd: Some(format!("{canonical}/src")),
    };
    let (scope, _) = credmgr_brokerd::scope::resolve_scope(&registry, &state.tokens, &inside, None);
    assert_eq!(scope.node_id, "acme");
    assert_eq!(scope.origin, Origin::Agent);
    let outside = credmgr_brokerd::peer::PeerInfo {
        uid: 501,
        pid: 3,
        cwd: Some("/usr".into()),
    };
    let (scope, _) =
        credmgr_brokerd::scope::resolve_scope(&registry, &state.tokens, &outside, None);
    assert_eq!(scope.node_id, GLOBAL_ID);
    assert_eq!(scope.capabilities, vec![Capability::List]);
}

#[test]
fn an_enrolled_gate_survives_a_restart_and_still_gates_the_unlock() {
    let (vault, state) = created_vault();
    unlock(&state, PASSPHRASE).unwrap();
    let (totp, _codes) = enrol_gate(&state);
    drop(state);

    let state = vault.broker();
    assert!(
        two_factor_required(unlock(&state, PASSPHRASE)),
        "a restart must not silently drop the second factor"
    );
    assert!(state.is_locked());
    let next_step = NOW + 30;
    call(
        &state,
        &anyone(),
        next_step,
        "vault.gate_verify",
        json!({ "code": totp.code(next_step as u64) }),
    )
    .expect("the enrolled authenticator still completes the login");
    assert!(!state.is_locked());
}

#[test]
fn a_totp_step_accepted_before_a_restart_is_refused_after_it() {
    let (vault, state) = created_vault();
    unlock(&state, PASSPHRASE).unwrap();
    let (totp, _codes) = enrol_gate(&state); // consumes NOW's step
    drop(state);

    let state = vault.broker();
    assert!(two_factor_required(unlock(&state, PASSPHRASE)));
    assert!(
        matches!(
            call(
                &state,
                &anyone(),
                NOW,
                "vault.gate_verify",
                json!({ "code": totp.code(NOW as u64) })
            ),
            Err(OpError::GateVerificationFailed)
        ),
        "07 §5's replay rule holds across a restart"
    );
}

#[test]
fn a_burned_gate_recovery_code_stays_burned_across_a_restart() {
    let (vault, state) = created_vault();
    unlock(&state, PASSPHRASE).unwrap();
    let (_totp, codes) = enrol_gate(&state);
    call(&state, &human(), NOW, "vault.lock", json!({})).unwrap();
    assert!(two_factor_required(unlock(&state, PASSPHRASE)));
    call(
        &state,
        &anyone(),
        NOW,
        "vault.gate_verify",
        json!({ "code": codes[0] }),
    )
    .expect("recovery code once");
    drop(state);

    let state = vault.broker();
    assert!(two_factor_required(unlock(&state, PASSPHRASE)));
    assert!(
        matches!(
            call(
                &state,
                &anyone(),
                NOW,
                "vault.gate_verify",
                json!({ "code": codes[0] })
            ),
            Err(OpError::GateVerificationFailed)
        ),
        "a spent recovery code must not come back to life after a restart"
    );
    call(
        &state,
        &anyone(),
        NOW,
        "vault.gate_verify",
        json!({ "code": codes[1] }),
    )
    .expect("an unspent one still works");
}

/// Phase 5 exit-gate line 6 (`12_BUILD_PLAN.md §2.6`), `07_TWO_FACTOR.md §4`'s
/// last door: the authenticator is lost, every recovery code is gone, and
/// the passphrase **plus** the printed root recovery code re-enrol the gate.
#[test]
fn the_last_door_passphrase_plus_root_recovery_code_re_enrols_the_gate_after_device_loss() {
    let (vault, state) = created_vault();
    unlock(&state, PASSPHRASE).unwrap();
    let (_lost_totp, _lost_codes) = enrol_gate(&state);
    drop(state); // the device is lost; the broker restarts

    let state = vault.broker();
    assert!(
        two_factor_required(unlock(&state, PASSPHRASE)),
        "gated, and no factor left to answer with"
    );

    // Either factor alone is refused, and says nothing about which.
    let wrong_code = "0".repeat(vault.root_recovery_code.len());
    for (passphrase, code) in [
        (PASSPHRASE, wrong_code.as_str()),
        ("not the passphrase", vault.root_recovery_code.as_str()),
    ] {
        assert!(matches!(
            call(
                &state,
                &anyone(),
                NOW,
                "vault.gate_recover",
                json!({ "passphrase": passphrase, "recoveryCode": code })
            ),
            Err(OpError::WrongPassphrase)
        ));
        assert!(
            two_factor_required(unlock(&state, PASSPHRASE)),
            "a refused recovery leaves the gate in force"
        );
    }

    // Both together reset the gate — and it is not an unlock by itself.
    let reset = call(
        &state,
        &anyone(),
        NOW,
        "vault.gate_recover",
        json!({ "passphrase": PASSPHRASE, "recoveryCode": vault.root_recovery_code }),
    )
    .expect("passphrase + root recovery code");
    assert_eq!(reset["gateReset"], true);
    assert!(
        state.is_locked(),
        "recovery resets the gate; it does not unlock the vault"
    );

    // Re-enrolment: unlock on the passphrase, enrol a new authenticator …
    unlock(&state, PASSPHRASE).expect("with the gate reset, the passphrase alone unlocks");
    let (new_totp, _new_codes) = enrol_gate(&state);
    drop(state);

    // … which is the one that gates from now on, across a restart.
    let state = vault.broker();
    assert!(two_factor_required(unlock(&state, PASSPHRASE)));
    let later = NOW + 30;
    call(
        &state,
        &anyone(),
        later,
        "vault.gate_verify",
        json!({ "code": new_totp.code(later as u64) }),
    )
    .expect("the re-enrolled gate");
    assert!(!state.is_locked());
}

#[test]
fn starting_a_re_enrolment_and_walking_away_leaves_the_gate_in_force() {
    let (vault, state) = created_vault();
    unlock(&state, PASSPHRASE).unwrap();
    let (totp, _codes) = enrol_gate(&state);

    // Review M3: replacing a gate in force needs its second factor, fresh.
    assert!(
        two_factor_required(call(
            &state,
            &human(),
            NOW,
            "vault.gate_enroll_begin",
            json!({})
        )),
        "a login alone must not be able to swap the authenticator"
    );
    call(&state, &human(), NOW, "vault.lock", json!({})).unwrap();
    assert!(two_factor_required(unlock(&state, PASSPHRASE)));
    let verified_at = NOW + 30;
    call(
        &state,
        &anyone(),
        verified_at,
        "vault.gate_verify",
        json!({ "code": totp.code(verified_at as u64) }),
    )
    .expect("the second factor, fresh");
    call(
        &state,
        &human(),
        verified_at + 1,
        "vault.gate_enroll_begin",
        json!({}),
    )
    .expect("inside the elevation window a re-enrolment may begin");
    // … and is never confirmed. A mutation still writes the vault through.
    call(
        &state,
        &human(),
        verified_at + 2,
        "entry.create",
        json!({ "node": GLOBAL_ID, "name": "X", "value": "y" }),
    )
    .expect("an unrelated write persists the vault");
    drop(state);

    let state = vault.broker();
    assert!(
        two_factor_required(unlock(&state, PASSPHRASE)),
        "an abandoned re-enrolment must never have removed the confirmed gate"
    );
    let later = NOW + 60;
    call(
        &state,
        &anyone(),
        later,
        "vault.gate_verify",
        json!({ "code": totp.code(later as u64) }),
    )
    .expect("the original authenticator still works");
}

#[test]
fn a_tampered_registry_is_refused_at_unlock_and_nothing_is_loaded() {
    let (vault, first) = created_vault();
    drop(first);
    let registry = vault.paths().registry();
    let mut bytes = std::fs::read(&registry).unwrap();
    let at = bytes
        .iter()
        .position(|b| *b == b'G')
        .expect("the Global label");
    bytes[at] = b'H';
    std::fs::write(&registry, bytes).unwrap();

    let state = vault.broker();
    assert!(matches!(
        unlock(&state, PASSPHRASE),
        Err(OpError::Internal(_))
    ));
    assert!(state.is_locked());
    assert!(!state.is_durable());
    assert!(state.registry.read().unwrap().nodes.is_empty());
}

#[test]
fn a_rolled_back_registry_is_refused_at_unlock() {
    let (vault, state) = created_vault();
    let paths = vault.paths();
    let old_registry = std::fs::read(paths.registry()).unwrap();
    let old_sig = std::fs::read(paths.registry_sig()).unwrap();
    unlock(&state, PASSPHRASE).unwrap();
    call(
        &state,
        &human(),
        NOW,
        "entry.create",
        json!({ "node": GLOBAL_ID, "name": "K", "value": "v" }),
    )
    .expect("a write advances the vault generation");
    drop(state);

    // Put back the older, validly signed registry — a rollback, not a forgery.
    std::fs::write(paths.registry(), old_registry).unwrap();
    std::fs::write(paths.registry_sig(), old_sig).unwrap();

    let state = vault.broker();
    assert!(
        matches!(unlock(&state, PASSPHRASE), Err(OpError::Internal(m)) if m.contains("rolled back") || m.contains("generation")),
        "the external generation counter must catch a validly signed but older registry"
    );
    assert!(state.is_locked());
}

#[test]
fn the_gate_seed_is_never_written_to_disk_in_the_clear() {
    let (vault, state) = created_vault();
    unlock(&state, PASSPHRASE).unwrap();
    let begin = call(&state, &human(), NOW, "vault.gate_enroll_begin", json!({})).unwrap();
    let uri = begin["otpauthUri"].as_str().unwrap().to_string();
    let b32 = uri
        .split("secret=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap()
        .to_string();
    let totp = totp_from_uri(&uri);
    call(
        &state,
        &human(),
        NOW,
        "vault.gate_enroll_confirm",
        json!({ "code": totp.code(NOW as u64) }),
    )
    .unwrap();

    let raw = decode_gate_secret_base32(&b32).unwrap();
    let hex = raw.iter().fold(String::new(), |mut acc, b| {
        use std::fmt::Write;
        let _ = write!(acc, "{b:02x}");
        acc
    });
    for path in walk(&vault.vault_dir) {
        let bytes = std::fs::read(&path).unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(
            !text.contains(&b32),
            "{} holds the base32 seed",
            path.display()
        );
        assert!(
            !text.contains(&hex),
            "{} holds the hex seed",
            path.display()
        );
        assert!(
            !bytes.windows(raw.len()).any(|w| w == raw.as_slice()),
            "{} holds the raw seed bytes",
            path.display()
        );
    }
    let registry = std::fs::read_to_string(vault.paths().registry()).unwrap();
    assert!(
        registry.contains("\"twofa\""),
        "the gate itself is persisted — only its seed is sealed"
    );
}

#[test]
fn locking_drops_the_passphrase_keystore_so_nothing_can_be_written_while_locked() {
    let (_vault, state) = created_vault();
    unlock(&state, PASSPHRASE).unwrap();
    state
        .persist(NOW)
        .expect("an unlocked, disk-backed vault writes through");
    call(&state, &human(), NOW, "vault.lock", json!({})).unwrap();
    assert!(
        state.persist(NOW).is_err(),
        "after lock the broker can no longer re-derive the root key — nothing to write with"
    );
    assert!(
        matches!(
            call(&state, &anyone(), NOW, "vault.unlock", json!({})),
            Err(OpError::WrongPassphrase)
        ),
        "and a passphrase-less unlock is back to the inert placeholder"
    );
}

fn walk(dir: &std::path::Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let ft = std::fs::symlink_metadata(&path).unwrap().file_type();
        if ft.is_dir() {
            out.extend(walk(&path));
        } else if ft.is_file() {
            out.push(path);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Regressions for the adversarial review of ADR-063/064 (2026-09-24). Each
// test names the finding it pins; each failed against the first version.
// ---------------------------------------------------------------------------

/// C1: once the owner had unlocked with a passphrase, a passphrase-less
/// `vault.unlock` from any local process minted a whole-vault login.
#[test]
fn review_c1_a_passphrase_less_unlock_never_opens_a_disk_backed_vault() {
    let (_vault, state) = created_vault();
    unlock(&state, PASSPHRASE).expect("the owner unlocks");
    assert!(
        matches!(
            call(&state, &anyone(), NOW, "vault.unlock", json!({})),
            Err(OpError::WrongPassphrase)
        ),
        "while unlocked, a tokenless passphrase-less unlock must mint nothing"
    );
    call(&state, &human(), NOW, "vault.lock", json!({})).unwrap();
    assert!(
        matches!(
            call(&state, &anyone(), NOW, "vault.unlock", json!({})),
            Err(OpError::WrongPassphrase)
        ),
        "nor after the owner has locked"
    );
    assert!(state.is_locked());
}

/// H1(a): a missing rollback counter read as generation 0, so an older,
/// validly signed registry loaded as current.
#[test]
fn review_h1_a_missing_rollback_counter_is_refused_not_read_as_zero() {
    let (vault, first) = created_vault();
    drop(first);
    let counter_files: Vec<PathBuf> = std::fs::read_dir(&vault.state_dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.is_file())
        .collect();
    assert!(!counter_files.is_empty(), "init wrote a rollback counter");
    for f in counter_files {
        std::fs::remove_file(f).unwrap();
    }
    let state = vault.broker();
    assert!(
        matches!(unlock(&state, PASSPHRASE), Err(OpError::Internal(m)) if m.contains("rollback counter is missing")),
        "deleting the counter must not be a way to make an old registry current"
    );
    assert!(state.is_locked() && !state.is_durable());
}

/// H1(b): the registry was read twice, and `atomic::read` followed symlinks
/// and read FIFOs — so two reads could see two registries.
#[cfg(unix)]
#[test]
fn review_h1_b_a_symlinked_registry_is_refused() {
    let (vault, first) = created_vault();
    drop(first);
    let registry = vault.paths().registry();
    let real = registry.with_extension("json.real");
    std::fs::rename(&registry, &real).unwrap();
    std::os::unix::fs::symlink(&real, &registry).unwrap();
    let state = vault.broker();
    assert!(matches!(
        unlock(&state, PASSPHRASE),
        Err(OpError::Internal(_))
    ));
    assert!(!state.is_durable());
}

/// H2: `registry.json` and `registry.sig` are two writes; a crash between
/// them left a vault that could not be opened. The previous complete pair is
/// now recovered — and refused once a later write has completed.
#[test]
fn review_h2_a_write_interrupted_between_registry_and_signature_is_recovered() {
    let (vault, state) = created_vault();
    let owner = login(&state);
    call(
        &state,
        &owner,
        NOW,
        "entry.create",
        json!({ "node": GLOBAL_ID, "name": "FIRST", "value": "1" }),
    )
    .expect("a completed write");
    // Snapshot the external counter as it stands, then make one more write.
    let counter_snapshot: Vec<(PathBuf, Vec<u8>)> = std::fs::read_dir(&vault.state_dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.is_file())
        .map(|p| {
            let b = std::fs::read(&p).unwrap();
            (p, b)
        })
        .collect();
    call(
        &state,
        &owner,
        NOW,
        "entry.create",
        json!({ "node": GLOBAL_ID, "name": "SECOND", "value": "2" }),
    )
    .expect("the write that will be 'interrupted'");
    drop(state);

    // Simulate the crash: the new registry.json landed, its signature did
    // not, and so the counter was never advanced either.
    std::fs::write(vault.paths().registry_sig(), b"interrupted").unwrap();
    for (p, b) in &counter_snapshot {
        std::fs::write(p, b).unwrap();
    }

    let state = vault.broker();
    let owner = login(&state);
    let listed = call(
        &state,
        &owner,
        NOW,
        "entry.list",
        json!({ "node": GLOBAL_ID }),
    )
    .unwrap();
    let names: Vec<&str> = listed["names"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(
        names.contains(&"FIRST"),
        "the last completed write survives"
    );
    assert!(
        names.contains(&"SECOND"),
        "and so does the interrupted one's manifest, one generation ahead of its binding"
    );
    // The recovered vault writes and reopens cleanly.
    call(
        &state,
        &owner,
        NOW,
        "entry.create",
        json!({ "node": GLOBAL_ID, "name": "THIRD", "value": "3" }),
    )
    .expect("a write after recovery re-binds everything");
    drop(state);
    let state = vault.broker();
    login(&state);
}

/// H2, the other half: once a write has completed, the previous pair is one
/// generation behind the counter and must never be used again.
#[test]
fn review_h2_the_previous_registry_pair_is_refused_after_a_completed_write() {
    let (vault, state) = created_vault();
    let owner = login(&state);
    call(
        &state,
        &owner,
        NOW,
        "entry.create",
        json!({ "node": GLOBAL_ID, "name": "K", "value": "v" }),
    )
    .unwrap();
    drop(state);
    // Break the current pair; the counter already records the newer write.
    std::fs::write(vault.paths().registry_sig(), b"broken").unwrap();
    let state = vault.broker();
    assert!(matches!(
        unlock(&state, PASSPHRASE),
        Err(OpError::Internal(_))
    ));
}

/// M2: a write the locked vault accepts (into the pending tray) used to be
/// reported as `internal` because write-through could not run while locked.
#[test]
fn review_m2_a_locked_pending_write_reports_success() {
    let (_vault, state) = created_vault();
    let owner = login(&state);
    call(&state, &owner, NOW, "vault.lock", json!({})).unwrap();
    let v = call(
        &state,
        &human(),
        NOW,
        "entry.create",
        json!({ "node": GLOBAL_ID, "name": "P", "value": "v" }),
    )
    .expect("a locked create goes to the pending tray and says so");
    assert_eq!(v["pending"], true);
}

/// ADR-069 (K-7, the tray half): a write made while the vault was locked
/// used to be forgotten by a restart — its envelope stayed on disk, what it
/// was did not. It now comes back in the tray and can be accepted.
#[test]
fn a_locked_write_survives_a_restart_and_can_still_be_accepted() {
    let (vault, state) = created_vault();
    let owner = login(&state);
    call(&state, &owner, NOW, "vault.lock", json!({})).unwrap();
    let deposited = call(
        &state,
        &human(),
        NOW,
        "entry.create",
        json!({ "node": GLOBAL_ID, "name": "WHILE_LOCKED", "value": "tray-value" }),
    )
    .expect("a locked create goes to the tray");
    let entry = deposited["entry"].as_str().unwrap().to_string();
    drop(state);

    let state = vault.broker();
    let owner = login(&state);
    let tray = call(
        &state,
        &owner,
        NOW,
        "vault.pending_list",
        json!({ "node": GLOBAL_ID }),
    )
    .expect("pending_list");
    let items = tray["pending"].as_array().unwrap();
    assert_eq!(items.len(), 1, "the tray came back: {tray}");
    assert_eq!(items[0]["entry"], entry.as_str());
    assert_eq!(items[0]["name"], "WHILE_LOCKED");
    assert_eq!(items[0]["created"], NOW);

    call(
        &state,
        &owner,
        NOW,
        "vault.pending_accept",
        json!({ "node": GLOBAL_ID, "entry": entry }),
    )
    .expect("accepted after the restart");
    let revealed = call(
        &state,
        &owner,
        NOW,
        "entry.reveal",
        json!({ "node": GLOBAL_ID, "entry": entry }),
    )
    .expect("reveal");
    assert_eq!(revealed["value"], "tray-value");
    let pending_dir = vault
        .vault_dir
        .join("nodes")
        .join(GLOBAL_ID)
        .join("pending");
    let left: Vec<_> = std::fs::read_dir(pending_dir)
        .map(|d| d.flatten().map(|e| e.file_name()).collect())
        .unwrap_or_default();
    assert!(
        left.is_empty(),
        "accept removes the envelope and its sidecar: {left:?}"
    );
    let verified = call(&state, &owner, NOW, "maintenance.verify", json!({})).unwrap();
    assert_eq!(
        verified["ok"], true,
        "the accepted envelope matches its digest: {verified}"
    );

    // And the acceptance itself was written through: after another restart
    // the entry is in the manifest and the tray is empty.
    drop(state);
    let state = vault.broker();
    let owner = login(&state);
    let listed = call(
        &state,
        &owner,
        NOW,
        "entry.list",
        json!({ "node": GLOBAL_ID }),
    )
    .unwrap();
    assert!(listed["names"]
        .as_array()
        .unwrap()
        .iter()
        .any(|n| n == "WHILE_LOCKED"));
    let tray = call(
        &state,
        &owner,
        NOW,
        "vault.pending_list",
        json!({ "node": GLOBAL_ID }),
    )
    .unwrap();
    assert!(tray["pending"].as_array().unwrap().is_empty());
}

/// ADR-069: the tray is untrusted input. Nothing dropped into `pending/` can
/// fail the owner's unlock, and nothing malformed reaches the tray.
#[test]
fn a_hostile_or_broken_tray_file_never_blocks_the_unlock_and_never_reaches_the_tray() {
    let (vault, state) = created_vault();
    let owner = login(&state);
    call(&state, &owner, NOW, "vault.lock", json!({})).unwrap();
    let good = call(
        &state,
        &human(),
        NOW,
        "entry.create",
        json!({ "node": GLOBAL_ID, "name": "GOOD", "value": "v" }),
    )
    .unwrap()["entry"]
        .as_str()
        .unwrap()
        .to_string();
    drop(state);

    let pending = vault
        .vault_dir
        .join("nodes")
        .join(GLOBAL_ID)
        .join("pending");
    // An envelope with no sidecar, a sidecar that is not JSON, one with an
    // unknown field, an id this broker could not have minted, and a symlink.
    std::fs::write(pending.join("e_000000000001.env"), b"x").unwrap();
    std::fs::write(pending.join("e_000000000002.env"), b"x").unwrap();
    std::fs::write(pending.join("e_000000000002.meta.json"), b"not json").unwrap();
    std::fs::write(pending.join("e_000000000003.env"), b"x").unwrap();
    let mut smuggled: Value =
        serde_json::from_slice(&std::fs::read(pending.join(format!("{good}.meta.json"))).unwrap())
            .unwrap();
    smuggled["extra"] = json!(true);
    std::fs::write(
        pending.join("e_000000000003.meta.json"),
        serde_json::to_vec(&smuggled).unwrap(),
    )
    .unwrap();
    std::fs::write(pending.join("NOT_AN_ID.env"), b"x").unwrap();
    std::fs::copy(
        pending.join(format!("{good}.meta.json")),
        pending.join("NOT_AN_ID.meta.json"),
    )
    .unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(
            pending.join(format!("{good}.env")),
            pending.join("e_000000000004.env"),
        )
        .unwrap();
        std::fs::copy(
            pending.join(format!("{good}.meta.json")),
            pending.join("e_000000000004.meta.json"),
        )
        .unwrap();
    }

    let state = vault.broker();
    let owner = login(&state);
    let tray = call(
        &state,
        &owner,
        NOW,
        "vault.pending_list",
        json!({ "node": GLOBAL_ID }),
    )
    .unwrap();
    let ids: Vec<&str> = tray["pending"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["entry"].as_str().unwrap())
        .collect();
    assert_eq!(
        ids,
        vec![good.as_str()],
        "only the real locked write came back"
    );
}

/// L2: only the maximum accepted step survived a restart, so a lower step
/// inside the skew window could be replayed after one.
#[test]
fn review_l2_no_totp_step_at_or_below_the_last_accepted_is_accepted_after_a_restart() {
    let (vault, state) = created_vault();
    unlock(&state, PASSPHRASE).unwrap();
    let (totp, _codes) = enrol_gate(&state); // consumes NOW's step
    call(&state, &human(), NOW, "vault.lock", json!({})).unwrap();
    assert!(two_factor_required(unlock(&state, PASSPHRASE)));
    let ahead = NOW + 30;
    call(
        &state,
        &anyone(),
        ahead,
        "vault.gate_verify",
        json!({ "code": totp.code(ahead as u64) }),
    )
    .expect("the next step");
    // Any persisted write records that step as the floor.
    call(
        &state,
        &human(),
        ahead,
        "entry.create",
        json!({ "node": GLOBAL_ID, "name": "Z", "value": "z" }),
    )
    .unwrap();
    drop(state);

    let state = vault.broker();
    assert!(two_factor_required(unlock(&state, PASSPHRASE)));
    // NOW's code is still inside the ±1 skew window at `ahead`, and was
    // never in this process's ledger — it is below the floor.
    assert!(matches!(
        call(
            &state,
            &anyone(),
            ahead,
            "vault.gate_verify",
            json!({ "code": totp.code(NOW as u64) })
        ),
        Err(OpError::GateVerificationFailed)
    ));
}

/// L3: entry refs restarted at the default on every broker start.
#[test]
fn review_l3_entry_refs_continue_across_a_restart() {
    let (vault, state) = created_vault();
    let owner = login(&state);
    for name in ["A", "B", "C"] {
        call(
            &state,
            &owner,
            NOW,
            "entry.create",
            json!({ "node": GLOBAL_ID, "name": name, "value": "v" }),
        )
        .unwrap();
    }
    let before = state.next_ref();
    drop(state);
    let state = vault.broker();
    login(&state);
    assert!(
        state.next_ref() >= before,
        "refs continue past the highest one on disk"
    );
}

/// L4: the home directory would scope every project to one node.
#[test]
fn review_l4_the_home_directory_cannot_be_a_workdir() {
    let Some(home) = std::env::var_os("HOME") else {
        return;
    };
    let (_vault, state) = created_vault();
    let owner = login(&state);
    call(
        &state,
        &owner,
        NOW,
        "node.create",
        json!({ "id": "acme", "label": "A", "parentId": GLOBAL_ID }),
    )
    .unwrap();
    assert!(matches!(
        call(&state, &owner, NOW, "node.set_workdirs", json!({ "node": "acme", "workdirs": [home.to_string_lossy()] })),
        Err(OpError::Malformed(m)) if m.contains("home directory")
    ));
}

/// L6: request activity from anyone kept an idle owner login alive for ever.
#[test]
fn review_l6_an_unused_owner_login_expires_even_while_the_vault_stays_busy() {
    let (_vault, state) = created_vault();
    let owner = login(&state);
    assert!(state.is_owner_session(&owner));
    let idle = 15 * 60;
    // An agent keeps the vault itself busy up to the moment of the tick …
    state.touch_activity("acme", NOW + idle - 1);
    state.tick_autolock(NOW + idle);
    assert!(!state.is_locked(), "the vault is not idle");
    // … but the owner's login has not been used since it was minted.
    assert!(
        !state.is_owner_session(&owner),
        "an unused owner login expires on its own"
    );
}

/// ADR-068: the login L6 expires is refused on its next use rather than
/// resolved from the caller's cwd — nothing else tells its holder it is gone,
/// because the vault itself never locked.
#[test]
fn an_idled_out_login_is_refused_as_session_expired_while_the_vault_stays_unlocked() {
    use credmgr_brokerd::peer::PeerInfo;
    use credmgr_brokerd::protocol::Request;
    let (_vault, state) = created_vault();
    let owner = login(&state);
    let token = owner
        .token_id
        .clone()
        .expect("a login carries its token id");
    let idle = 15 * 60;
    state.touch_activity("acme", NOW + idle - 1);
    state.tick_autolock(NOW + idle);
    assert!(!state.is_locked());
    let peer = PeerInfo {
        uid: 501,
        pid: 1,
        cwd: None,
    };
    let request = |op: &str| Request {
        id: "r".into(),
        op: op.into(),
        token: Some(token.clone()),
        params: json!({ "node": GLOBAL_ID }),
    };
    let (r, _) = credmgr_brokerd::server::handle_request_at(
        &state,
        &peer,
        &request("entry.list"),
        NOW + idle + 1,
        std::time::Instant::now(),
    );
    assert_eq!(r.expect_err("idled-out login"), OpError::SessionExpired);
    let (r, _) = credmgr_brokerd::server::handle_request_at(
        &state,
        &peer,
        &request("vault.status"),
        NOW + idle + 1,
        std::time::Instant::now(),
    );
    assert_eq!(r.expect("status still answers")["locked"], false);
}

/// M4: a second broker over the same vault stole the socket and wrote the
/// vault from its own view.
#[cfg(unix)]
#[test]
fn review_m4_a_second_broker_refuses_to_start_on_a_live_socket() {
    let (vault, state) = created_vault();
    let socket = vault.vault_dir.join("s.sock");
    let first = Arc::clone(&state);
    let path = socket.clone();
    std::thread::spawn(move || {
        let _ = credmgr_brokerd::server::run(first, &path);
    });
    for _ in 0..100 {
        if std::os::unix::net::UnixStream::connect(&socket).is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let second = vault.broker();
    let err = credmgr_brokerd::server::run(second, &socket).expect_err("the socket is live");
    assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse);
}

/// ADR-067 (gap G-12): the manifest stored SHA-256 of the plaintext value, in a
/// plaintext file any same-user process can read — an unkeyed digest to
/// brute-force weak secrets against offline, skipping Argon2id. No file under
/// the vault directory may carry a digest of a stored value.
#[test]
fn g12_no_file_in_the_vault_carries_a_digest_of_a_stored_value() {
    use sha2::{Digest, Sha256};
    let (vault, state) = created_vault();
    let owner = login(&state);
    let weak = "password123";
    let created = call(
        &state,
        &owner,
        NOW,
        "entry.create",
        json!({ "node": GLOBAL_ID, "name": "WEAK", "value": weak }),
    )
    .unwrap();
    let entry = created["entry"].as_str().unwrap().to_string();
    let generation = created["generation"].as_u64().unwrap();
    call(
        &state,
        &owner,
        NOW,
        "entry.rotate",
        json!({ "node": GLOBAL_ID, "entry": entry, "value": "letmein", "generation": generation }),
    )
    .unwrap();
    let digests: Vec<String> = [weak, "letmein"]
        .iter()
        .map(|v| {
            Sha256::digest(v.as_bytes())
                .iter()
                .fold(String::new(), |mut acc, b| {
                    use std::fmt::Write;
                    let _ = write!(acc, "{b:02x}");
                    acc
                })
        })
        .collect();
    for path in walk(&vault.vault_dir) {
        let text = String::from_utf8_lossy(&std::fs::read(&path).unwrap()).into_owned();
        for d in &digests {
            assert!(
                !text.contains(d.as_str()),
                "{} carries the plaintext digest of a stored value",
                path.display()
            );
        }
    }
    // And the digest that is there is the envelope's: the key-free check in
    // `maintenance.verify` agrees with every file create and rotate wrote.
    let verified = call(&state, &owner, NOW, "maintenance.verify", json!({})).unwrap();
    assert_eq!(verified["ok"], true, "{verified}");
}

/// ADR-071: rename a node. The id — what grants, workdirs and every agent's
/// scope refer to — never changes; only the label.
#[test]
fn node_update_renames_a_node_and_the_label_survives_a_restart() {
    let (vault, state) = created_vault();
    let owner = login(&state);
    call(
        &state,
        &owner,
        NOW,
        "node.create",
        json!({ "id": "acme", "label": "Acme", "parentId": GLOBAL_ID }),
    )
    .unwrap();
    let renamed = call(
        &state,
        &owner,
        NOW,
        "node.update",
        json!({ "node": "acme", "label": "  Acme Corp  " }),
    )
    .expect("the owner renames a project");
    assert_eq!(renamed["label"], "Acme Corp", "trimmed");

    for (params, why) in [
        (json!({ "node": "acme", "label": "   " }), "blank"),
        (
            json!({ "node": "acme", "label": "bell\u{7}" }),
            "control character",
        ),
        (
            json!({ "node": "acme", "label": "x".repeat(121) }),
            "too long",
        ),
        (json!({ "node": "orphan", "label": "mine" }), "orphan"),
        (json!({ "node": "global", "label": "Everything" }), "global"),
        (json!({ "node": "acme" }), "missing label"),
    ] {
        assert!(
            matches!(
                call(&state, &owner, NOW, "node.update", params),
                Err(OpError::Malformed(_))
            ),
            "{why} must be refused"
        );
    }
    let agent = BrokerScope {
        node_id: "acme".into(),
        capabilities: vec![Capability::List, Capability::Admin],
        origin: Origin::Agent,
        token_id: None,
        bound_workdir: None,
    };
    assert!(matches!(
        call(
            &state,
            &agent,
            NOW,
            "node.update",
            json!({ "node": "acme", "label": "pwned" })
        ),
        Err(OpError::CapabilityNotHeld { .. })
    ));
    assert!(matches!(
        call(
            &state,
            &owner,
            NOW,
            "node.update",
            json!({ "node": "nope", "label": "x" })
        ),
        Err(OpError::NotFound(_)) | Err(OpError::NodeAccessDenied { .. })
    ));
    drop(state);

    let state = vault.broker();
    let _owner = login(&state);
    assert_eq!(
        state.registry.read().unwrap().nodes["acme"].label,
        "Acme Corp",
        "the rename was written through"
    );
}

/// ADR-071: `node.policy` — a partial patch, a mandatory reason, the admin
/// gate, and presence for the two fields that widen reach.
#[test]
fn node_policy_tightens_at_once_refuses_a_widening_without_presence_and_records_why() {
    let (vault, state) = created_vault();
    let owner = login(&state);
    let token = owner.token_id.clone().unwrap();
    let dir = vault.vault_dir.parent().unwrap().join("work").join("acme");
    std::fs::create_dir_all(&dir).unwrap();
    call(
        &state,
        &owner,
        NOW,
        "node.create",
        json!({ "id": "acme", "label": "Acme", "parentId": GLOBAL_ID, "workdirs": [dir.to_string_lossy()] }),
    )
    .unwrap();
    let canonical = std::fs::canonicalize(&dir)
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let agent_caps = |state: &BrokerState| {
        let registry = state.registry.read().unwrap().clone();
        let peer = credmgr_brokerd::peer::PeerInfo {
            uid: 501,
            pid: 9,
            cwd: Some(canonical.clone()),
        };
        credmgr_brokerd::scope::resolve_scope(&registry, &state.tokens, &peer, None)
            .0
            .capabilities
    };
    assert!(
        agent_caps(&state).contains(&Capability::Reveal),
        "default agentAccess is read-write"
    );

    // Malformed patches: no reason, unknown field, nothing to change.
    for (params, why) in [
        (
            json!({ "node": "acme", "policy": { "agentAccess": "none" } }),
            "no reason",
        ),
        (
            json!({ "node": "acme", "reason": "r", "policy": { "agentAcess": "none" } }),
            "typo'd field",
        ),
        (
            json!({ "node": "acme", "reason": "r", "policy": {} }),
            "empty patch",
        ),
        (
            json!({ "node": "orphan", "reason": "r", "policy": { "agentAccess": "none" } }),
            "orphan",
        ),
    ] {
        assert!(
            matches!(
                call(&state, &owner, NOW, "node.policy", params),
                Err(OpError::Malformed(_))
            ),
            "{why} must be refused"
        );
    }

    // Tightening lands at once, through the real server so the audit record is written.
    let peer = credmgr_brokerd::peer::PeerInfo {
        uid: 501,
        pid: 1,
        cwd: None,
    };
    let req = |params: Value| credmgr_brokerd::protocol::Request {
        id: "r".into(),
        op: "node.policy".into(),
        token: Some(token.clone()),
        params,
    };
    let (r, _) = credmgr_brokerd::server::handle_request_at(
        &state,
        &peer,
        &req(
            json!({ "node": "acme", "reason": "agents only read this project", "policy": { "agentAccess": "none", "lockAfterSeconds": 300 } }),
        ),
        NOW,
        std::time::Instant::now(),
    );
    let v = r.expect("a tightening needs only the admin gate");
    assert_eq!(v["policy"]["agentAccess"], "none");
    assert_eq!(v["policy"]["lockAfterSeconds"], 300);
    // ADR-083 and ADR-085 built the last two: nothing is left "stored but not acted on".
    assert_eq!(v["notEnforced"], json!([]));
    assert!(
        agent_caps(&state).is_empty(),
        "an agent in the directory lost every capability"
    );

    // Widening reach needs presence, which no transport can attest yet — and
    // the whole patch is refused, including its harmless half.
    assert!(matches!(
        call(
            &state,
            &owner,
            NOW,
            "node.policy",
            json!({ "node": "acme", "reason": "r", "policy": { "descendantRead": true, "privateNames": true } })
        ),
        Err(OpError::PresenceRequired { .. })
    ));
    let policy = state.registry.read().unwrap().nodes["acme"].policy.clone();
    assert!(
        !policy.descendant_read && !policy.private_names,
        "nothing from a refused patch landed"
    );
    call(
        &state,
        &owner,
        NOW,
        "node.policy",
        json!({ "node": "acme", "reason": "r", "policy": { "siblingVisibility": "isolated" } }),
    )
    .expect("isolating children narrows reach");
    assert!(matches!(
        call(
            &state,
            &owner,
            NOW,
            "node.policy",
            json!({ "node": "acme", "reason": "r", "policy": { "siblingVisibility": "shared" } })
        ),
        Err(OpError::PresenceRequired { .. })
    ));
    call(
        &state,
        &owner,
        NOW,
        "node.policy",
        json!({ "node": "acme", "reason": "r", "policy": { "lockAfterSeconds": null } }),
    )
    .expect("null clears the per-node timer");
    assert_eq!(
        state.registry.read().unwrap().nodes["acme"]
            .policy
            .lock_after_seconds,
        None
    );

    // The reason is in the audit record.
    let tail = call(&state, &owner, NOW, "audit.tail", json!({ "limit": 50 })).unwrap();
    assert!(
        tail["records"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["action"] == "node.policy"
                && r["detail"] == "reason: agents only read this project"),
        "{tail}"
    );
    drop(state);

    let state = vault.broker();
    let _owner = login(&state);
    assert!(
        agent_caps(&state).is_empty(),
        "the tightened policy was written through"
    );
}

/// ADR-072: a node's note — sealed under the node key, reachable only with
/// `notes`, held to the signed manifest's digest, surviving a restart.
#[test]
fn a_note_is_sealed_capability_gated_digest_bound_and_survives_a_restart() {
    let (vault, state) = created_vault();
    let owner = login(&state);
    for id in ["acme", "globex"] {
        call(
            &state,
            &owner,
            NOW,
            "node.create",
            json!({ "id": id, "label": id, "parentId": GLOBAL_ID }),
        )
        .unwrap();
    }
    let empty = call(&state, &owner, NOW, "notes.read", json!({ "node": "acme" })).unwrap();
    assert_eq!(empty["markdown"], "");
    assert_eq!(empty["modified"], Value::Null);

    let secret_words = "Acme deploys on Tuesdays; the vendor contact is in the wiki";
    assert!(matches!(
        call(
            &state,
            &owner,
            NOW,
            "notes.write",
            json!({ "node": "acme", "markdown": secret_words, "generation": 7 })
        ),
        Err(OpError::Conflict {
            current_generation: 0,
            ..
        })
    ));
    let wrote = call(
        &state,
        &owner,
        NOW,
        "notes.write",
        json!({ "node": "acme", "markdown": secret_words, "generation": 0 }),
    )
    .expect("the owner writes the note");
    assert_eq!(wrote["generation"], 1);
    let read = call(&state, &owner, NOW, "notes.read", json!({ "node": "acme" })).unwrap();
    assert_eq!(read["markdown"], secret_words);
    assert_eq!(read["modified"], NOW);

    // `notes` never rides along with `read`, and projects stay apart.
    let reader = BrokerScope {
        node_id: "acme".into(),
        capabilities: vec![Capability::List, Capability::Read, Capability::Reveal],
        origin: Origin::Agent,
        token_id: None,
        bound_workdir: None,
    };
    assert!(matches!(
        call(
            &state,
            &reader,
            NOW,
            "notes.read",
            json!({ "node": "acme" })
        ),
        Err(OpError::CapabilityNotHeld {
            capability: Capability::Notes
        })
    ));
    let globex_notes = BrokerScope {
        node_id: "globex".into(),
        capabilities: vec![Capability::List, Capability::Notes],
        origin: Origin::Agent,
        token_id: None,
        bound_workdir: None,
    };
    assert!(matches!(
        call(
            &state,
            &globex_notes,
            NOW,
            "notes.read",
            json!({ "node": "acme" })
        ),
        Err(OpError::NodeAccessDenied { .. })
    ));
    for path in walk(&vault.vault_dir) {
        let text = String::from_utf8_lossy(&std::fs::read(&path).unwrap()).into_owned();
        assert!(
            !text.contains("Tuesdays"),
            "{} carries the note in the clear",
            path.display()
        );
    }

    // A second version, then the first one's file restored over it: refused.
    let note_path = vault.vault_dir.join("nodes").join("acme").join("notes.env");
    let first = std::fs::read(&note_path).unwrap();
    call(
        &state,
        &owner,
        NOW,
        "notes.write",
        json!({ "node": "acme", "markdown": "v2", "generation": 1 }),
    )
    .unwrap();
    drop(state);
    let state = vault.broker();
    let owner = login(&state);
    assert_eq!(
        call(&state, &owner, NOW, "notes.read", json!({ "node": "acme" })).unwrap()["markdown"],
        "v2",
        "the note and its digest were written through"
    );
    std::fs::write(&note_path, first).unwrap();
    assert!(matches!(
        call(&state, &owner, NOW, "notes.read", json!({ "node": "acme" })),
        Err(OpError::Internal(m)) if m.contains("digest")
    ));
    let verified = call(&state, &owner, NOW, "maintenance.verify", json!({})).unwrap();
    assert_eq!(verified["ok"], false, "{verified}");

    // Clearing removes the file and the digest; verify is clean again.
    call(
        &state,
        &owner,
        NOW,
        "notes.write",
        json!({ "node": "acme", "markdown": "", "generation": 2 }),
    )
    .unwrap();
    assert!(!note_path.exists());
    assert_eq!(
        call(&state, &owner, NOW, "notes.read", json!({ "node": "acme" })).unwrap()["markdown"],
        ""
    );
    assert_eq!(
        call(&state, &owner, NOW, "maintenance.verify", json!({})).unwrap()["ok"],
        true
    );
}

/// ADR-073: many single-value entries in one call — all validated before any
/// is written, each created exactly as `entry.create` creates one.
#[test]
fn entry_create_batch_validates_everything_first_and_writes_through() {
    let (vault, state) = created_vault();
    let owner = login(&state);
    call(
        &state,
        &owner,
        NOW,
        "node.create",
        json!({ "id": "acme", "label": "Acme", "parentId": GLOBAL_ID }),
    )
    .unwrap();
    call(
        &state,
        &owner,
        NOW,
        "entry.create",
        json!({ "node": "acme", "name": "EXISTING", "value": "x" }),
    )
    .unwrap();

    // Refusals leave the node exactly as it was.
    for (entries, why) in [
        (json!([]), "empty"),
        (
            json!([{ "name": "A", "value": "1" }, { "name": "A", "value": "2" }]),
            "duplicate in batch",
        ),
        (json!([{ "name": "B" }]), "missing value"),
        (json!([{ "name": "", "value": "1" }]), "blank name"),
    ] {
        assert!(
            matches!(
                call(
                    &state,
                    &owner,
                    NOW,
                    "entry.create_batch",
                    json!({ "node": "acme", "entries": entries })
                ),
                Err(OpError::Malformed(_))
            ),
            "{why} must be refused"
        );
    }
    assert!(matches!(
        call(&state, &owner, NOW, "entry.create_batch", json!({ "node": "acme", "entries": [
            { "name": "NEW_ONE", "value": "1" }, { "name": "EXISTING", "value": "2" }
        ] })),
        Err(OpError::EntryExists { name, .. }) if name == "EXISTING"
    ));
    let names = call(&state, &owner, NOW, "entry.list", json!({ "node": "acme" })).unwrap()
        ["names"]
        .clone();
    assert_eq!(
        names,
        json!(["EXISTING"]),
        "a refused batch wrote nothing — not even its valid half"
    );

    let done = call(
        &state,
        &owner,
        NOW,
        "entry.create_batch",
        json!({ "node": "acme", "entries": [
        { "name": "DB_URL", "value": "postgres://db.internal:5432/app" },
        { "name": "API_TOKEN", "value": "tok-live-7f3a" },
        { "name": "PORT", "value": "8080", "label": "port" }
    ] }),
    )
    .expect("a clean batch lands");
    assert_eq!(done["complete"], true);
    assert_eq!(done["created"].as_array().unwrap().len(), 3);
    let token_entry = done["created"][1]["entry"].as_str().unwrap().to_string();
    drop(state);

    let state = vault.broker();
    let owner = login(&state);
    let listed = call(&state, &owner, NOW, "entry.list", json!({ "node": "acme" })).unwrap();
    assert_eq!(listed["names"].as_array().unwrap().len(), 4, "{listed}");
    let revealed = call(
        &state,
        &owner,
        NOW,
        "entry.reveal",
        json!({ "node": "acme", "entry": token_entry }),
    )
    .unwrap();
    assert_eq!(revealed["value"], "tok-live-7f3a");
    assert_eq!(
        call(&state, &owner, NOW, "maintenance.verify", json!({})).unwrap()["ok"],
        true
    );

    // No `create`, no batch; and while locked, the batch goes to the review tray.
    let reader = BrokerScope {
        node_id: "acme".into(),
        capabilities: vec![Capability::List, Capability::Read, Capability::Reveal],
        origin: Origin::Agent,
        token_id: None,
        bound_workdir: None,
    };
    assert!(matches!(
        call(
            &state,
            &reader,
            NOW,
            "entry.create_batch",
            json!({ "node": "acme", "entries": [{ "name": "X", "value": "1" }] })
        ),
        Err(OpError::CapabilityNotHeld {
            capability: Capability::Create
        })
    ));
    call(&state, &owner, NOW, "vault.lock", json!({})).unwrap();
    // While locked, the writer is an agent scoped to the project.
    let agent = BrokerScope {
        node_id: "acme".into(),
        capabilities: vec![Capability::List, Capability::Create],
        origin: Origin::Agent,
        token_id: None,
        bound_workdir: None,
    };
    let held = call(
        &state,
        &agent,
        NOW,
        "entry.create_batch",
        json!({ "node": "acme", "entries": [
        { "name": "LOCKED_A", "value": "a" }, { "name": "LOCKED_B", "value": "b" }
    ] }),
    )
    .unwrap();
    assert!(
        held["created"]
            .as_array()
            .unwrap()
            .iter()
            .all(|c| c["pending"] == true),
        "{held}"
    );
}
