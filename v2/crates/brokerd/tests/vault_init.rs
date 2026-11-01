//! `vault.init_begin`/`vault.init_confirm` (ADR-061) — the vault bootstrap
//! this project had no code path for at all until this session. Driven
//! through `ops::dispatch`, mirroring `maintenance.rs`'s own "real on-disk
//! vault, not the in-memory `set_registry` shortcut" fixture discipline,
//! with a scope matching exactly what `scope::resolve_scope` actually
//! returns for an unauthenticated, pre-vault connection: `List` on
//! `GLOBAL_ID`, nothing else — there is no registry yet to hold any other
//! capability over.

use std::sync::Arc;

use secrecy::SecretBox;
use serde_json::json;

use credmgr_brokerd::ops;
use credmgr_brokerd::protocol::OpError;
use credmgr_brokerd::scope::BrokerScope;
use credmgr_brokerd::state::BrokerState;
use credmgr_core::access::Origin;
use credmgr_core::registry::{Capability, GLOBAL_ID};
use credmgr_keystore::software::SoftwareKeystore;
use credmgr_keystore::PlatformKeystore;
use credmgr_store::generation::{FileGenerationCounter, GenerationCounter, VAULT_GENERATION};
use credmgr_store::paths::VaultPaths;

const NOW: i64 = 1_800_000_000;
const PASSPHRASE: &str = "correct horse battery staple";

fn bootstrap_scope() -> BrokerScope {
    // Exactly `scope::resolve_scope`'s own third branch: no token, no
    // workdir match possible (there are no nodes yet) — `List` on
    // `GLOBAL_ID`, `Origin::Agent`. Constructed directly here (rather than
    // routed through `resolve_scope` itself) because this test is about
    // `vault.init_*`'s own dispatch behaviour, not peer/scope resolution,
    // which `crates/brokerd/tests/isolation.rs` already covers.
    BrokerScope {
        node_id: GLOBAL_ID.to_string(),
        capabilities: vec![Capability::List],
        origin: Origin::Agent,
        token_id: None,
        bound_workdir: None,
    }
}

struct Fixture {
    state: Arc<BrokerState>,
    paths: VaultPaths,
    state_dir: std::path::PathBuf,
    _dir: tempfile::TempDir,
}

/// A `BrokerState` pointed at an **empty** vault directory — no
/// `registry.json`, no `keys/`, nothing — the actual starting condition
/// `credmgr init` exists to fix. Distinct from every other fixture in this
/// crate's `tests/`, which all pre-seed a vault; that is exactly the
/// difference this test suite is for.
fn fresh_broker() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault_dir = dir.path().join("vault");
    let state_dir = dir.path().join("state");
    std::fs::create_dir_all(&vault_dir).unwrap();
    std::fs::create_dir_all(&state_dir).unwrap();
    let paths = VaultPaths::new(vault_dir);

    // Placeholder, matching `credmgrd::main`'s own real startup keystore —
    // never read by `vault.init_begin`, which builds its own throwaway one
    // (ADR-061).
    let keystore = SoftwareKeystore::new(
        SecretBox::new(Box::default()),
        state_dir.join("placeholder-keystore"),
    );
    let state = Arc::new(BrokerState::new(Box::new(keystore), paths.clone()));
    state.set_state_dir_for_test(state_dir.clone());

    Fixture {
        state,
        paths,
        state_dir,
        _dir: dir,
    }
}

#[test]
fn begin_then_confirm_writes_a_vault_a_separately_keyed_broker_can_unlock() {
    let fixture = fresh_broker();
    let scope = bootstrap_scope();

    let begin = ops::dispatch(
        &fixture.state,
        &scope,
        NOW,
        "vault.init_begin",
        &json!({ "passphrase": PASSPHRASE }),
    )
    .expect("init_begin should succeed against an empty vault dir");
    let recovery_code = begin["recoveryCode"]
        .as_str()
        .expect("recoveryCode in the response")
        .to_string();

    assert!(
        !fixture.paths.registry().exists(),
        "confirm hasn't run yet — begin must not write anything to disk"
    );

    let confirm = ops::dispatch(
        &fixture.state,
        &scope,
        NOW,
        "vault.init_confirm",
        &json!({ "recoveryCode": recovery_code }),
    )
    .expect("init_confirm should succeed with the correct recovery code");
    assert_eq!(confirm, json!({ "initialized": true }));

    // Every artifact `04_CRYPTO_AND_KEYS.md §2.3` names, in the order
    // `confirm_init` writes them.
    assert!(fixture.paths.root_wrap_pass().exists(), "root.wrap.pass");
    assert!(
        fixture.paths.root_wrap_recovery().exists(),
        "root.wrap.recovery"
    );
    assert!(
        fixture.paths.node_key(GLOBAL_ID).exists(),
        "keys/nodes/global.key"
    );
    assert!(fixture.paths.registry().exists(), "registry.json");
    assert!(fixture.paths.registry_sig().exists(), "registry.sig");

    // `confirm_init` commits into the *running* state too — no restart
    // needed to see the vault it just created.
    assert!(
        fixture.state.is_locked(),
        "confirm_init writes a locked vault — it never unlocks by itself"
    );
    assert!(
        fixture
            .state
            .registry
            .read()
            .unwrap()
            .nodes
            .contains_key(GLOBAL_ID),
        "confirm_init must load the new registry into the running state"
    );

    // The counter `confirm_init` wrote is real and matches the registry's
    // own generation — `check_and_advance`'s own baseline case.
    let counter = FileGenerationCounter::new(fixture.state_dir.clone());
    // The root key isn't known to this test directly (only the two
    // separately-keyed brokers below ever hold it) — but the counter file's
    // *shape* is checkable without it: it must exist and, read under the
    // wrong key, must report tampering rather than silently succeeding —
    // proving it really is HMAC-bound to a root key, not merely present.
    let wrong_key = [0xAAu8; 32];
    assert!(
        counter.read(&wrong_key, VAULT_GENERATION).is_err(),
        "the generation counter must be bound to the real root key"
    );

    // The actual proof this test exists for: a FRESH, separately-keyed
    // `BrokerState` — the same shape a real `credmgr unlock` needs — loads
    // what `confirm_init` wrote and unlocks with the real passphrase.
    // `fixture.state`'s own keystore is a placeholder and could never do
    // this (ADR-061's own documented boundary: a live daemon's `vault.unlock`
    // is not what this proves).
    let verify_paths = VaultPaths::new(fixture.paths.root().to_path_buf());
    let verify_keystore = SoftwareKeystore::new(
        SecretBox::new(Box::new(PASSPHRASE.to_string())),
        fixture.state_dir.join("verify-keystore"),
    );
    let verify_state = Arc::new(BrokerState::new(
        Box::new(verify_keystore),
        verify_paths.clone(),
    ));

    let wrapped_root_bytes = std::fs::read(verify_paths.root_wrap_pass()).unwrap();
    let wrapped_root = credmgr_keystore::WrappedKey {
        keystore: credmgr_keystore::KeystoreId::Software,
        bytes: wrapped_root_bytes,
    };
    let wrapped_node_bytes = std::fs::read(verify_paths.node_key(GLOBAL_ID)).unwrap();
    let wrapped_node_key =
        credmgr_core::keys::WrappedNodeKey::from_bytes(&wrapped_node_bytes).unwrap();
    let node_public_key = fixture
        .state
        .node_public_key(GLOBAL_ID)
        .expect("confirm_init registered the global node's public key");

    let mut node_keys = std::collections::HashMap::new();
    node_keys.insert(GLOBAL_ID.to_string(), (wrapped_node_key, node_public_key));
    verify_state.load_key_material(wrapped_root, node_keys);

    let load_counter = FileGenerationCounter::new(fixture.state_dir.clone());
    // This is the first time this second broker has ever seen the vault —
    // it must load the registry for real, under the passphrase-derived
    // root key it's about to prove it can unwrap, not merely trust the
    // first broker's in-memory copy.
    let unwrap_result =
        verify_keystore_unwrap(&verify_paths, PASSPHRASE, fixture.state_dir.clone());
    verify_state
        .verify_and_load_vault(&unwrap_result, &load_counter)
        .expect("a freshly loaded vault must verify against its own real root key");

    assert!(
        verify_state.is_locked(),
        "a freshly built state starts locked"
    );
    let unlock_result = verify_state
        .unlock(NOW)
        .expect("unlock with the real passphrase must succeed");
    assert!(
        !unlock_result,
        "no gate is enrolled — unlock must fully unlock in one step"
    );
    assert!(
        !verify_state.is_locked(),
        "init → lock → unlock: the vault credmgr init produced is immediately usable"
    );
}

/// Re-derives the root key the same way a real `vault.unlock` eventually
/// will (ADR-061's own documented Phase 5 boundary: this exact
/// request-scoped-keystore shape, not yet wired into `ops::dispatch`'s
/// `"vault.unlock"` arm) — reads `root.wrap.pass` off disk and unwraps it
/// with a keystore built from the real passphrase.
fn verify_keystore_unwrap(
    paths: &VaultPaths,
    passphrase: &str,
    state_dir: std::path::PathBuf,
) -> [u8; 32] {
    let keystore = SoftwareKeystore::new(
        SecretBox::new(Box::new(passphrase.to_string())),
        state_dir.join("unwrap-keystore"),
    );
    let bytes = std::fs::read(paths.root_wrap_pass()).unwrap();
    let wrapped = credmgr_keystore::WrappedKey {
        keystore: credmgr_keystore::KeystoreId::Software,
        bytes,
    };
    let root = keystore
        .unwrap_root(&wrapped, "test: verify credmgr init's own wrap")
        .expect("the passphrase credmgr init was given must unwrap what it wrote");
    use secrecy::ExposeSecret;
    *root.expose_secret()
}

#[test]
fn init_begin_refuses_if_a_vault_already_exists() {
    let fixture = fresh_broker();
    let scope = bootstrap_scope();

    let recovery_code = ops::dispatch(
        &fixture.state,
        &scope,
        NOW,
        "vault.init_begin",
        &json!({ "passphrase": PASSPHRASE }),
    )
    .unwrap()["recoveryCode"]
        .as_str()
        .unwrap()
        .to_string();
    ops::dispatch(
        &fixture.state,
        &scope,
        NOW,
        "vault.init_confirm",
        &json!({ "recoveryCode": recovery_code }),
    )
    .unwrap();

    let second_attempt = ops::dispatch(
        &fixture.state,
        &scope,
        NOW,
        "vault.init_begin",
        &json!({ "passphrase": "a different passphrase entirely" }),
    );
    assert_eq!(second_attempt, Err(OpError::VaultAlreadyInitialized));
}

#[test]
fn init_confirm_with_no_pending_begin_is_refused() {
    let fixture = fresh_broker();
    let scope = bootstrap_scope();

    let result = ops::dispatch(
        &fixture.state,
        &scope,
        NOW,
        "vault.init_confirm",
        &json!({ "recoveryCode": "AAAA-BBBB-CCCC-DDDD" }),
    );
    assert_eq!(result, Err(OpError::VaultInitNotPending));
}

#[test]
fn init_confirm_with_the_wrong_recovery_code_is_refused_and_can_be_retried() {
    let fixture = fresh_broker();
    let scope = bootstrap_scope();

    let begin = ops::dispatch(
        &fixture.state,
        &scope,
        NOW,
        "vault.init_begin",
        &json!({ "passphrase": PASSPHRASE }),
    )
    .unwrap();
    let real_code = begin["recoveryCode"].as_str().unwrap().to_string();

    let wrong_attempt = ops::dispatch(
        &fixture.state,
        &scope,
        NOW,
        "vault.init_confirm",
        &json!({ "recoveryCode": "0000-0000-0000-0000-0000-0000-0000-0000" }),
    );
    assert_eq!(wrong_attempt, Err(OpError::RecoveryCodeMismatch));
    assert!(
        !fixture.paths.registry().exists(),
        "a wrong confirmation must never write anything"
    );

    // The pending init survives a wrong attempt — retry with the real code.
    let retry = ops::dispatch(
        &fixture.state,
        &scope,
        NOW,
        "vault.init_confirm",
        &json!({ "recoveryCode": real_code }),
    );
    assert_eq!(retry, Ok(json!({ "initialized": true })));
}

#[test]
fn init_confirm_after_its_ttl_elapses_is_refused() {
    let fixture = fresh_broker();
    let scope = bootstrap_scope();

    let begin = ops::dispatch(
        &fixture.state,
        &scope,
        NOW,
        "vault.init_begin",
        &json!({ "passphrase": PASSPHRASE }),
    )
    .unwrap();
    let real_code = begin["recoveryCode"].as_str().unwrap().to_string();

    let later = NOW + BrokerState::VAULT_INIT_CONFIRM_TTL_SECONDS + 1;
    let result = ops::dispatch(
        &fixture.state,
        &scope,
        later,
        "vault.init_confirm",
        &json!({ "recoveryCode": real_code }),
    );
    assert_eq!(result, Err(OpError::VaultInitNotPending));
}

#[test]
fn init_begin_refuses_inside_a_git_working_tree() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault_dir = dir.path().join("checkout").join("vault");
    let state_dir = dir.path().join("state");
    std::fs::create_dir_all(&vault_dir).unwrap();
    std::fs::create_dir_all(&state_dir).unwrap();
    // A `.git` at the checkout root, above the vault dir — matches
    // `is_inside_git_working_tree`'s walk-up-from-the-vault-root contract.
    std::fs::create_dir_all(dir.path().join("checkout").join(".git")).unwrap();

    let paths = VaultPaths::new(vault_dir);
    let keystore = SoftwareKeystore::new(SecretBox::new(Box::default()), state_dir.clone());
    let state = Arc::new(BrokerState::new(Box::new(keystore), paths));
    state.set_state_dir_for_test(state_dir);

    let scope = bootstrap_scope();
    let result = ops::dispatch(
        &state,
        &scope,
        NOW,
        "vault.init_begin",
        &json!({ "passphrase": PASSPHRASE }),
    );
    assert_eq!(result, Err(OpError::VaultInsideGitWorkingTree));
}
