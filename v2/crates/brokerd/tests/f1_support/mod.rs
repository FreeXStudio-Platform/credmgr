//! Shared fixture for the 2.0.0 broker-feature tests (ADR-130…134): a real `vault.init_*` vault in a
//! throwaway directory, "restarted" by building a fresh `BrokerState` over the same directories, the
//! unattended Secure Enclave test helper for presence proofs, and a TOTP gate for the second factor.
//! No test touches the user's own vault.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use secrecy::SecretBox;
use serde_json::{json, Value};

use credmgr_brokerd::ops;
use credmgr_brokerd::peer::PeerInfo;
use credmgr_brokerd::protocol::OpError;
use credmgr_brokerd::scope::BrokerScope;
use credmgr_brokerd::state::BrokerState;
use credmgr_core::access::Origin;
use credmgr_core::registry::{Capability, GLOBAL_ID};
use credmgr_core::totp::{decode_gate_secret_base32, Totp};
use credmgr_keystore::secure_enclave::Helper;
use credmgr_keystore::software::SoftwareKeystore;
use credmgr_store::paths::VaultPaths;

pub const NOW: i64 = 1_800_000_000;
/// Long after any elevation window a gate enrolment or step-up opened.
pub const LATER: i64 = NOW + 3600;
pub const PASSPHRASE: &str = "correct horse battery staple";

pub fn test_helper() -> Option<Helper> {
    if !cfg!(target_os = "macos") {
        return None;
    }
    let p = std::env::var_os("CREDMGR_PRESENCE_TEST_HELPER")
        .map(PathBuf::from)
        .or_else(|| {
            let guess = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../target/native/credmgr-presence-test");
            guess.is_file().then_some(guess)
        })?;
    let h = Helper::at(p);
    h.probe().ok()?.secure_enclave.then_some(h)
}

#[macro_export]
macro_rules! helper_or_skip {
    () => {
        match $crate::f1_support::test_helper() {
            Some(h) => h,
            None => {
                eprintln!("skipped: no Secure Enclave test helper (run native/macos/presence/build.sh --test-noauth)");
                return;
            }
        }
    };
}

pub fn peer() -> PeerInfo {
    PeerInfo {
        uid: 501,
        pid: 1,
        cwd: None,
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

pub struct Vault {
    pub vault_dir: PathBuf,
    pub state_dir: PathBuf,
    /// The printed root recovery code `vault.init_begin` answered (the last door's second factor).
    pub recovery_code: std::cell::RefCell<String>,
    pub _dir: tempfile::TempDir,
}

impl Vault {
    pub fn paths(&self) -> VaultPaths {
        VaultPaths::new(self.vault_dir.clone())
    }

    /// A fresh broker over this vault — a daemon that has just started.
    pub fn broker(&self, helper: Option<&Helper>) -> Arc<BrokerState> {
        let keystore = SoftwareKeystore::new(
            SecretBox::new(Box::default()),
            self.state_dir.join("placeholder-keystore"),
        );
        let state = Arc::new(BrokerState::new(Box::new(keystore), self.paths()));
        state.set_state_dir_for_test(self.state_dir.clone());
        state.set_presence_helper_for_test(helper.cloned());
        // A test must not pay a second of scrypt per passphrase export.
        state.stable.set_export_work_factor_for_test(Some(10));
        state
    }
}

pub fn call(
    state: &BrokerState,
    scope: &BrokerScope,
    now: i64,
    op: &str,
    params: Value,
) -> Result<Value, OpError> {
    ops::dispatch(state, scope, now, op, &params)
}

pub fn created_vault(helper: Option<&Helper>) -> (Vault, Arc<BrokerState>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault_dir = dir.path().join("vault");
    let state_dir = dir.path().join("state");
    std::fs::create_dir_all(&vault_dir).unwrap();
    std::fs::create_dir_all(&state_dir).unwrap();
    let vault = Vault {
        vault_dir,
        state_dir,
        recovery_code: std::cell::RefCell::new(String::new()),
        _dir: dir,
    };
    let state = vault.broker(helper);
    let begin = call(
        &state,
        &anyone(),
        NOW,
        "vault.init_begin",
        json!({ "passphrase": PASSPHRASE }),
    )
    .expect("init_begin");
    let code = begin["recoveryCode"].as_str().unwrap().to_string();
    vault.recovery_code.borrow_mut().clone_from(&code);
    call(
        &state,
        &anyone(),
        NOW,
        "vault.init_confirm",
        json!({ "recoveryCode": code }),
    )
    .expect("init_confirm");
    (vault, state)
}

pub fn login(state: &BrokerState) -> BrokerScope {
    let token = call(
        state,
        &anyone(),
        NOW,
        "vault.unlock",
        json!({ "passphrase": PASSPHRASE }),
    )
    .expect("unlock")["token"]
        .as_str()
        .expect("a real login mints a token")
        .to_string();
    scope_of(state, &token)
}

pub fn scope_of(state: &BrokerState, token: &str) -> BrokerScope {
    let registry = state.registry.read().unwrap().clone();
    credmgr_brokerd::scope::resolve_scope(&registry, &state.tokens, &peer(), Some(token)).0
}

/// A restart: drop the old broker, start a fresh one over the same vault, unlock.
pub fn restart(
    v: &Vault,
    old: Arc<BrokerState>,
    helper: Option<&Helper>,
) -> (Arc<BrokerState>, BrokerScope) {
    drop(old);
    let state = v.broker(helper);
    let owner = login(&state);
    (state, owner)
}

/// A presence key a test signs with. ADR-148 §P2-5: a **software** P-256 key, so every presence-gated row
/// runs on any host (Linux CI included) and checks the broker's verifier and its refusals; the Secure
/// Enclave itself is exercised only by the Touch ID unlock tests, which still need the test helper.
#[derive(Clone)]
pub struct Signer(p256::ecdsa::SigningKey);

impl Signer {
    pub fn software() -> Signer {
        Signer(p256::ecdsa::SigningKey::random(&mut rand_core::OsRng))
    }

    /// The uncompressed SEC1 point the broker enrols.
    pub fn public(&self) -> Vec<u8> {
        self.0
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    }

    /// Raw `r || s` over `digest` (hashed once more with SHA-256, as the Secure Enclave does).
    pub fn sign(&self, digest: &[u8]) -> Vec<u8> {
        use p256::ecdsa::signature::Signer as _;
        let sig: p256::ecdsa::Signature = self.0.sign(digest);
        sig.to_bytes().to_vec()
    }
}

/// What a client does: ask for a challenge, sign it, attach the proof.
pub fn with_proof(
    state: &BrokerState,
    scope: &BrokerScope,
    key: &Signer,
    now: i64,
    op: &str,
    params: Value,
) -> Value {
    let c = call(
        state,
        scope,
        now,
        "presence.challenge",
        json!({ "op": op, "params": params }),
    )
    .expect("presence.challenge");
    let digest = B64.decode(c["digest"].as_str().unwrap()).unwrap();
    let mut p = params;
    p["presence"] = json!({ "nonce": c["nonce"], "signature": B64.encode(key.sign(&digest)) });
    p
}

/// ADR-148 §P2-4: `params` (a `presence.enrol` request) with the new key's proof of possession attached.
pub fn with_possession(
    state: &BrokerState,
    scope: &BrokerScope,
    key: &Signer,
    now: i64,
    params: Value,
) -> Value {
    let c = call(
        state,
        scope,
        now,
        "presence.challenge",
        json!({ "op": "presence.enrol", "params": params, "possession": true }),
    )
    .expect("possession challenge");
    let digest = B64.decode(c["digest"].as_str().unwrap()).unwrap();
    let mut p = params;
    p["possession"] = json!({ "nonce": c["nonce"], "signature": B64.encode(key.sign(&digest)) });
    p
}

/// Enrol a fresh software presence key (with its proof of possession) as the vault's first.
pub fn enrol_first_key(state: &BrokerState, owner: &BrokerScope) -> Signer {
    let key = Signer::software();
    let ask = json!({ "publicKey": B64.encode(key.public()), "label": "test Mac" });
    let ask = with_possession(state, owner, &key, NOW, ask);
    call(state, owner, NOW, "presence.enrol", ask).expect("presence.enrol");
    key
}

/// Turn the vault's second factor on and return the authenticator.
pub fn enrol_gate(state: &BrokerState, owner: &BrokerScope) -> Totp {
    let begin = call(state, owner, NOW, "vault.gate_enroll_begin", json!({})).expect("begin");
    let uri = begin["otpauthUri"].as_str().unwrap();
    let b32 = uri
        .split("secret=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap();
    let totp = Totp::new_gate(decode_gate_secret_base32(b32).unwrap());
    call(
        state,
        owner,
        NOW,
        "vault.gate_enroll_confirm",
        json!({ "code": totp.code(NOW as u64) }),
    )
    .expect("confirm");
    totp
}

/// Give the second factor fresh at `at` (a step-up, as the window does).
pub fn step_up(state: &BrokerState, owner: &BrokerScope, totp: &Totp, at: i64) {
    call(
        state,
        owner,
        at,
        "vault.gate_verify",
        json!({ "code": totp.code(at as u64) }),
    )
    .expect("step-up");
}

// ---- content -------------------------------------------------------------

pub fn create_node(state: &BrokerState, owner: &BrokerScope, id: &str) {
    call(
        state,
        owner,
        NOW,
        "node.create",
        json!({ "id": id, "label": id, "parentId": GLOBAL_ID }),
    )
    .expect("node.create");
}

pub fn create_entry(
    state: &BrokerState,
    owner: &BrokerScope,
    node: &str,
    name: &str,
    value: &str,
) -> String {
    call(
        state,
        owner,
        NOW,
        "entry.create",
        json!({ "node": node, "name": name, "value": value }),
    )
    .expect("entry.create")["entry"]
        .as_str()
        .unwrap()
        .to_string()
}

pub fn reveal(state: &BrokerState, owner: &BrokerScope, node: &str, entry: &str) -> String {
    call(
        state,
        owner,
        NOW,
        "entry.reveal",
        json!({ "node": node, "entry": entry }),
    )
    .expect("entry.reveal")["value"]
        .as_str()
        .unwrap()
        .to_string()
}

pub fn generation(state: &BrokerState, owner: &BrokerScope, node: &str) -> u64 {
    call(state, owner, NOW, "entry.list", json!({ "node": node })).expect("entry.list")
        ["generation"]
        .as_u64()
        .unwrap()
}

pub fn verify_ok(state: &BrokerState, owner: &BrokerScope) {
    let v = call(state, owner, NOW, "maintenance.verify", json!({})).expect("maintenance.verify");
    assert_eq!(v["ok"], true, "maintenance.verify: {v}");
}

/// The Secure Enclave refuses key generation under heavy parallel use (`unable to generate key`); the tests
/// in one binary run in parallel, so every call into the helper takes this lock.
pub fn se_lock() -> std::sync::MutexGuard<'static, ()> {
    static SE: std::sync::Mutex<()> = std::sync::Mutex::new(());
    SE.lock().unwrap_or_else(|e| e.into_inner())
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .fold(String::new(), |mut acc, b| {
            use std::fmt::Write;
            let _ = write!(acc, "{b:02x}");
            acc
        })
}

/// The vault's root key, opened from `root.wrap.pass` with the test passphrase.
pub fn root_key(v: &Vault) -> [u8; 32] {
    use credmgr_keystore::{KeystoreId, PlatformKeystore, WrappedKey};
    use secrecy::ExposeSecret;
    let bytes = std::fs::read(v.paths().root_wrap_pass()).unwrap();
    SoftwareKeystore::new(
        SecretBox::new(Box::new(PASSPHRASE.to_string())),
        v.state_dir.join("ks"),
    )
    .unwrap_root(
        &WrappedKey {
            keystore: KeystoreId::Software,
            bytes,
        },
        "test",
    )
    .expect("the passphrase opens root.wrap.pass")
    .expose_secret()
    .to_owned()
}

/// What `seed_acme` made.
pub struct Seed {
    pub kept: String,
    pub rotated: String,
    pub removed: String,
    /// The generation `rotated` was at before its rotation (the key its retained history lives under).
    pub history_generation: u64,
}

/// A node `acme` with: an entry that was rotated once (so it has retained history), an entry that was not,
/// a note, and an entry removed inside its seven days.
pub fn seed_acme(state: &BrokerState, owner: &BrokerScope) -> Seed {
    create_node(state, owner, "acme");
    let rotated = create_entry(state, owner, "acme", "database", "alpha-1");
    let kept = create_entry(state, owner, "acme", "api", "beta-2");
    let removed = create_entry(state, owner, "acme", "old-key", "gamma-3");
    let history_generation = generation(state, owner, "acme");
    call(
        state,
        owner,
        NOW,
        "entry.rotate",
        json!({ "node": "acme", "entry": rotated, "value": "alpha-2", "generation": history_generation }),
    )
    .expect("entry.rotate");
    call(
        state,
        owner,
        NOW,
        "notes.write",
        json!({ "node": "acme", "markdown": "the note", "generation": generation(state, owner, "acme") }),
    )
    .expect("notes.write");
    call(
        state,
        owner,
        NOW,
        "entry.remove",
        json!({ "node": "acme", "entry": removed, "generation": generation(state, owner, "acme") }),
    )
    .expect("entry.remove");
    Seed {
        kept,
        rotated,
        removed,
        history_generation,
    }
}

/// ADR-165 N5: the root key a vault folder's `root.wrap.pass` opens to with `passphrase` — what an attacker
/// holding a copy of the folder and that passphrase computes offline. `None` if it does not open.
pub fn root_from_folder(vault_dir: &Path, passphrase: &str) -> Option<[u8; 32]> {
    use credmgr_keystore::{KeystoreId, PlatformKeystore, WrappedKey};
    use secrecy::ExposeSecret;
    let bytes = std::fs::read(vault_dir.join("keys/root.wrap.pass")).ok()?;
    let scratch = tempfile::tempdir().ok()?;
    SoftwareKeystore::new(
        SecretBox::new(Box::new(passphrase.to_string())),
        scratch.path().to_path_buf(),
    )
    .unwrap_root(
        &WrappedKey {
            keystore: KeystoreId::Software,
            bytes,
        },
        "test",
    )
    .ok()
    .map(|k| *k.expose_secret())
}

/// ADR-165 N5: a node's private key from a vault folder's `keys/nodes/<node>.key`, unwrapped with `root`.
pub fn node_key_from_folder(
    vault_dir: &Path,
    root: &[u8; 32],
    node: &str,
) -> Option<x25519_dalek::StaticSecret> {
    let bytes = std::fs::read(vault_dir.join("keys/nodes").join(format!("{node}.key"))).ok()?;
    let wrapped = credmgr_core::keys::WrappedNodeKey::from_bytes(&bytes).ok()?;
    credmgr_core::keys::unwrap_node_key(root, node, &wrapped).ok()
}

/// ADR-165 N5: whether `key` opens the envelope at `path` (an entry `entry` of `node`).
pub fn key_opens(key: &x25519_dalek::StaticSecret, path: &Path, node: &str, entry: &str) -> bool {
    std::fs::read(path)
        .ok()
        .is_some_and(|bytes| credmgr_core::envelope::open_any(&bytes, key, node, entry).is_ok())
}
