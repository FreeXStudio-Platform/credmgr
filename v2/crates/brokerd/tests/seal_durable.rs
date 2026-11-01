//! ADR-079 (K-7) — seal and restore on a vault that lives on disk.
//!
//! What this file proves, and how:
//!
//! * **K-7 is closed end to end.** In a vault `vault.init_*` made — not a fixture
//!   that hand-inserts an orphan — `node create` -> `set` -> `node seal` ->
//!   *restart* -> `node restore` brings every envelope back byte-identical, the
//!   node's policy and label with it, and survives another restart.
//! * **The orphan is custody-clean.** Its private half is in `keys/cold/orphan.key`
//!   and nowhere else: not in the hot set, not in `keys/nodes/`, not loaded even
//!   if a file is planted there; sealed values open with the cold key (the path
//!   the ADR allows) and with nothing else.
//! * **A crash at every step of the commit protocol leaves a vault that opens.**
//!   Each row of the crash table (`state/seal.rs`) is made to happen by stopping
//!   the real protocol at that step, dropping the broker, and starting a fresh
//!   one over the same directories — the same method the rotation suite uses.
//! * **The signed record is the authority.** A forged, rolled-back or swapped
//!   record, archive manifest, node key or cold key is refused, and a refusal
//!   moves nothing.
//! * **An alpha vault opens unchanged** and gains the orphan lazily, on the first
//!   seal — never as a side effect of unlock.

use std::path::PathBuf;
use std::sync::Arc;

use secrecy::{ExposeSecret, SecretBox};
use serde_json::{json, Value};

use credmgr_brokerd::ops;
use credmgr_brokerd::peer::PeerInfo;
use credmgr_brokerd::protocol::OpError;
use credmgr_brokerd::scope::BrokerScope;
use credmgr_brokerd::state::{BrokerState, PersistFault, SealFault, SealPause};
use credmgr_core::access::Origin;
use credmgr_core::keys::wrap_node_key;
use credmgr_core::registry::{Capability, GLOBAL_ID, ORPHAN_ID};
use credmgr_core::{cold, envelope};
use credmgr_keystore::software::SoftwareKeystore;
use credmgr_keystore::{KeystoreId, PlatformKeystore, WrappedKey};
use credmgr_store::paths::VaultPaths;
use credmgr_store::{archive, atomic, manifest, registry_file};

const NOW: i64 = 1_800_000_000;
const DAY: i64 = 24 * 60 * 60;
const PASSPHRASE: &str = "correct horse battery staple";

// ---------------------------------------------------------------------------
// Harness — a real vault made by `vault.init_*` in a temporary directory,
// "restarted" by building a fresh `BrokerState` over the same directories.
// ---------------------------------------------------------------------------

fn anyone() -> BrokerScope {
    BrokerScope {
        node_id: GLOBAL_ID.to_string(),
        capabilities: vec![Capability::List],
        origin: Origin::Agent,
        token_id: None,
        bound_workdir: None,
    }
}

fn peer() -> PeerInfo {
    PeerInfo {
        uid: 501,
        pid: 1,
        cwd: None,
    }
}

struct Env {
    vault_dir: PathBuf,
    state_dir: PathBuf,
    _dir: tempfile::TempDir,
}

impl Env {
    fn paths(&self) -> VaultPaths {
        VaultPaths::new(self.vault_dir.clone())
    }

    /// A fresh broker over this vault — a daemon that has just started.
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

fn created() -> (Env, Arc<BrokerState>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault_dir = dir.path().join("vault");
    let state_dir = dir.path().join("state");
    std::fs::create_dir_all(&vault_dir).unwrap();
    std::fs::create_dir_all(&state_dir).unwrap();
    let env = Env {
        vault_dir,
        state_dir,
        _dir: dir,
    };
    let state = env.broker();
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
    (env, state)
}

fn try_login(state: &BrokerState) -> Result<BrokerScope, OpError> {
    let token = call(
        state,
        &anyone(),
        NOW,
        "vault.unlock",
        json!({ "passphrase": PASSPHRASE }),
    )?["token"]
        .as_str()
        .expect("a real login mints a token")
        .to_string();
    let registry = state.registry.read().unwrap().clone();
    Ok(credmgr_brokerd::scope::resolve_scope(&registry, &state.tokens, &peer(), Some(&token)).0)
}

fn login(state: &BrokerState) -> BrokerScope {
    try_login(state).expect("unlock")
}

/// A restart: drop the old broker, start a fresh one over the same vault, unlock.
fn restart(env: &Env, old: Arc<BrokerState>) -> (Arc<BrokerState>, BrokerScope) {
    drop(old);
    let state = env.broker();
    let owner = login(&state);
    (state, owner)
}

fn passphrase() -> SecretBox<String> {
    SecretBox::new(Box::new(PASSPHRASE.to_string()))
}

fn create_node(state: &BrokerState, owner: &BrokerScope, id: &str, parent: &str) {
    call(
        state,
        owner,
        NOW,
        "node.create",
        json!({ "id": id, "label": id, "parentId": parent }),
    )
    .expect("node.create");
}

fn create_entry(
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

fn reveal(state: &BrokerState, owner: &BrokerScope, node: &str, entry: &str) -> String {
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

fn seal(state: &BrokerState, owner: &BrokerScope, node: &str, now: i64) -> Result<Value, OpError> {
    call(state, owner, now, "node.seal", json!({ "node": node }))
}

fn restore(
    state: &BrokerState,
    owner: &BrokerScope,
    node: &str,
    now: i64,
) -> Result<Value, OpError> {
    call(state, owner, now, "node.restore", json!({ "node": node }))
}

fn node_ids(state: &BrokerState, owner: &BrokerScope) -> Vec<String> {
    let mut ids: Vec<String> = call(state, owner, NOW, "node.list", json!({})).unwrap()["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|n| n.as_str().map(str::to_string))
        .collect();
    ids.sort();
    ids
}

fn verify(state: &BrokerState, owner: &BrokerScope) -> Value {
    call(state, owner, NOW, "maintenance.verify", json!({})).expect("maintenance.verify")
}

fn assert_verify_ok(state: &BrokerState, owner: &BrokerScope) {
    let v = verify(state, owner);
    assert_eq!(v["ok"], true, "maintenance.verify: {v}");
}

fn root_from_disk(env: &Env) -> [u8; 32] {
    let bytes = std::fs::read(env.paths().root_wrap_pass()).unwrap();
    SoftwareKeystore::new(passphrase(), env.state_dir.join("ks"))
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

fn registry_doc(env: &Env) -> registry_file::RegistryDocument {
    registry_file::load(&env.paths(), &root_from_disk(env)).expect("the registry opens")
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut out, b| {
        write!(out, "{b:02x}").unwrap();
        out
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex(&Sha256::digest(bytes))
}

/// A project `acme` with two entries; returns `(entry one, entry two)`.
fn acme_with_two_entries(state: &BrokerState, owner: &BrokerScope) -> (String, String) {
    create_node(state, owner, "acme", GLOBAL_ID);
    let one = create_entry(state, owner, "acme", "ONE", "value-one");
    let two = create_entry(state, owner, "acme", "TWO", "value-two");
    (one, two)
}

fn is_injected_crash(err: &OpError) -> bool {
    matches!(err, OpError::Internal(m) if m.contains("injected crash"))
}

// ---------------------------------------------------------------------------
// K-7 closed: the headline
// ---------------------------------------------------------------------------

#[test]
fn init_create_set_seal_restart_restore_reveal_restart_is_byte_identical_end_to_end() {
    let (env, state) = created();
    let owner = login(&state);
    let paths = env.paths();
    let (one, two) = acme_with_two_entries(&state, &owner);
    call(
        &state,
        &owner,
        NOW,
        "node.update",
        json!({ "node": "acme", "label": "Acme, Inc." }),
    )
    .unwrap();
    call(
        &state,
        &owner,
        NOW,
        "node.policy",
        json!({ "node": "acme", "reason": "journey", "policy": { "privateNames": true } }),
    )
    .unwrap();
    let env_one = std::fs::read(paths.entry_env("acme", &one)).unwrap();
    let env_two = std::fs::read(paths.entry_env("acme", &two)).unwrap();
    let key_file = std::fs::read(paths.node_key("acme")).unwrap();
    let created_at = registry_doc(&env).nodes["acme"].created;
    let node_before = state.registry.read().unwrap().nodes["acme"].clone();

    // --- seal -------------------------------------------------------------------
    let sealed = seal(&state, &owner, "acme", NOW).expect("a vault init made can seal (K-7)");
    assert_eq!(sealed, json!({ "node": "acme", "sealed": true }));
    assert_eq!(node_ids(&state, &owner), vec!["global"]);
    assert!(!paths.node_dir("acme").exists(), "the live directory moved");
    assert!(!paths.node_key("acme").exists(), "the live key moved");
    assert!(paths.archive_dir("acme").join("node.key").exists());
    assert!(paths.archive_dir("acme").join("meta.json").exists());
    for entry in [&one, &two] {
        assert!(
            paths.entry_env(ORPHAN_ID, entry).exists(),
            "the entry was re-encrypted into the orphan node"
        );
    }
    // The registry — signed — now says so.
    let doc = registry_doc(&env);
    assert!(!doc.nodes.contains_key("acme"));
    let record = &doc.sealed["acme"];
    assert_eq!(record.sealed_at, NOW);
    assert_eq!(record.orphan_entry_ids.len(), 2);
    assert_eq!(doc.format, registry_file::REGISTRY_FORMAT);
    // ADR-067 (F-b): the orphan rows carry the digest of the NEW envelope.
    assert_eq!(
        state.orphan_digest_mismatches().unwrap(),
        Vec::<String>::new()
    );
    assert_verify_ok(&state, &owner);

    // --- restart ----------------------------------------------------------------
    let (state, owner) = restart(&env, state);
    assert_eq!(
        node_ids(&state, &owner),
        vec!["global"],
        "the seal survived the restart (K-7: it used to be forgotten)"
    );
    assert_verify_ok(&state, &owner);

    // --- restore, on day 6 --------------------------------------------------------
    let restored = restore(&state, &owner, "acme", NOW + 6 * DAY).expect("day-6 restore");
    assert_eq!(restored, json!({ "node": "acme", "restored": true }));
    assert_eq!(node_ids(&state, &owner), vec!["acme", "global"]);
    assert_eq!(
        std::fs::read(paths.entry_env("acme", &one)).unwrap(),
        env_one
    );
    assert_eq!(
        std::fs::read(paths.entry_env("acme", &two)).unwrap(),
        env_two
    );
    assert_eq!(std::fs::read(paths.node_key("acme")).unwrap(), key_file);
    assert_eq!(reveal(&state, &owner, "acme", &one), "value-one");
    assert_eq!(reveal(&state, &owner, "acme", &two), "value-two");
    assert_eq!(
        state.registry.read().unwrap().nodes["acme"],
        node_before,
        "label, policy, workdirs, depth and parent are exactly what was sealed"
    );
    let doc = registry_doc(&env);
    assert!(doc.sealed.is_empty());
    assert_eq!(
        doc.nodes["acme"].created, created_at,
        "created is preserved"
    );
    assert!(
        !paths.archive_dir("acme").exists(),
        "the archive is retired"
    );
    for entry in [&one, &two] {
        assert!(
            !paths.entry_env(ORPHAN_ID, entry).exists(),
            "the orphan copies are gone"
        );
    }
    assert!(state
        .manifests
        .read()
        .unwrap()
        .get(ORPHAN_ID)
        .map_or(true, |m| m.entries.is_empty()));
    assert_verify_ok(&state, &owner);

    // --- and it is still restored after another restart ----------------------------
    let (state, owner) = restart(&env, state);
    assert_eq!(node_ids(&state, &owner), vec!["acme", "global"]);
    assert_eq!(reveal(&state, &owner, "acme", &one), "value-one");
    assert_verify_ok(&state, &owner);
}

#[test]
fn the_window_is_seven_days_from_the_signed_record_and_a_refusal_keeps_it() {
    let (env, state) = created();
    let owner = login(&state);
    acme_with_two_entries(&state, &owner);
    seal(&state, &owner, "acme", NOW).unwrap();

    let (state, owner) = restart(&env, state);
    // Day 8: expired — by name, and the record, the archive and the orphan copies stay.
    let err = restore(&state, &owner, "acme", NOW + 8 * DAY).unwrap_err();
    assert!(matches!(err, OpError::ArchiveExpired { .. }), "{err:?}");
    assert!(registry_doc(&env).sealed.contains_key("acme"));
    assert!(env.paths().archive_dir("acme").join("node.key").exists());
    // Still expired after a restart, still refused.
    let (state, owner) = restart(&env, state);
    assert!(matches!(
        restore(&state, &owner, "acme", NOW + 9 * DAY).unwrap_err(),
        OpError::ArchiveExpired { .. }
    ));
    // The id stays spoken for while the archive exists (F-d).
    let err = call(
        &state,
        &owner,
        NOW + 9 * DAY,
        "node.create",
        json!({ "id": "acme", "label": "again", "parentId": GLOBAL_ID }),
    )
    .unwrap_err();
    assert!(
        matches!(&err, OpError::Malformed(m) if m.contains("sealed node")),
        "{err:?}"
    );
    // Nothing is sealed under an id nobody sealed.
    assert!(matches!(
        restore(&state, &owner, "never-sealed", NOW).unwrap_err(),
        OpError::NotFound(_)
    ));
}

// ---------------------------------------------------------------------------
// The orphan's custody
// ---------------------------------------------------------------------------

#[test]
fn init_makes_the_orphan_node_with_a_cold_key_that_is_never_loaded() {
    let (env, state) = created();
    let owner = login(&state);
    let paths = env.paths();

    // On disk.
    let cold_bytes = std::fs::read(paths.orphan_key()).expect("keys/cold/orphan.key");
    assert_eq!(cold_bytes.len(), cold::COLD_FILE_LEN);
    assert!(
        !paths.node_key(ORPHAN_ID).exists(),
        "there is no keys/nodes/orphan.key"
    );
    let doc = registry_doc(&env);
    let orphan = &doc.nodes[ORPHAN_ID];
    assert_eq!(
        cold::parse_header(&cold_bytes).unwrap().public.as_bytes(),
        hex_to_32(&orphan.public_key).as_slice(),
        "the registry's orphan public key is the cold file's header"
    );
    assert!(
        manifest::load(&paths, &root_from_disk(&env), ORPHAN_ID)
            .unwrap()
            .body
            .entries
            .is_empty(),
        "init writes an empty orphan manifest"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&paths.orphan_key()), 0o600);
        assert_eq!(mode(&paths.keys_cold_dir()), 0o700);
    }

    // In memory: unlocked, the hot set holds every node key except the orphan's.
    let hot = state.hot_key_node_ids_for_test();
    assert!(hot.contains(&GLOBAL_ID.to_string()));
    assert!(
        !hot.contains(&ORPHAN_ID.to_string()),
        "the orphan's private half is never in the hot set: {hot:?}"
    );
    // A node created afterwards is persisted without ever writing an orphan key.
    create_node(&state, &owner, "acme", GLOBAL_ID);
    assert!(!paths.node_key(ORPHAN_ID).exists());
    // The orphan does not show in any list.
    assert_eq!(node_ids(&state, &owner), vec!["acme", "global"]);
    assert_verify_ok(&state, &owner);
}

fn hex_to_32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

#[test]
fn a_planted_orphan_node_key_is_never_loaded_and_verify_says_so() {
    let (env, state) = created();
    let rk = root_from_disk(&env);
    let paths = env.paths();
    // A perfectly valid node-wrap of the orphan's real private key, planted where
    // the loader would read a node key.
    let secret = cold::open_orphan_cold(&rk, &std::fs::read(paths.orphan_key()).unwrap(), None)
        .expect("the cold key opens under the root");
    atomic::write(
        &paths.node_key(ORPHAN_ID),
        &wrap_node_key(&rk, ORPHAN_ID, &secret).to_bytes(),
    )
    .unwrap();

    let (state, owner) = restart(&env, state);
    assert!(
        !state
            .hot_key_node_ids_for_test()
            .contains(&ORPHAN_ID.to_string()),
        "the loader treats the orphan as public-only whatever is on disk"
    );
    let v = verify(&state, &owner);
    assert_eq!(
        v["ok"], true,
        "a planted file is a warning, not damage: {v}"
    );
    assert!(
        v["warnings"].to_string().contains("keys/nodes/orphan.key"),
        "{v}"
    );
    // And a seal still works, and still never puts it in the hot set.
    create_node(&state, &owner, "acme", GLOBAL_ID);
    create_entry(&state, &owner, "acme", "K", "v");
    seal(&state, &owner, "acme", NOW).unwrap();
    assert!(!state
        .hot_key_node_ids_for_test()
        .contains(&ORPHAN_ID.to_string()));
}

#[test]
fn sealed_values_open_with_the_cold_key_and_with_nothing_else() {
    let (env, state) = created();
    let owner = login(&state);
    let paths = env.paths();
    let (one, _) = acme_with_two_entries(&state, &owner);
    let acme_pub_secret = {
        // The sealed node's own key, before it goes: what an attacker holding the
        // node key but not the cold key would try.
        let rk = root_from_disk(&env);
        let wrapped = credmgr_core::keys::WrappedNodeKey::from_bytes(
            &std::fs::read(paths.node_key("acme")).unwrap(),
        )
        .unwrap();
        credmgr_core::keys::unwrap_node_key(&rk, "acme", &wrapped).unwrap()
    };
    seal(&state, &owner, "acme", NOW).unwrap();

    // The product refuses to read it, to anyone, the owner included (R0).
    let err = call(
        &state,
        &owner,
        NOW,
        "entry.reveal",
        json!({ "node": ORPHAN_ID, "entry": one }),
    )
    .unwrap_err();
    assert!(
        matches!(err, OpError::NodeAccessDenied { rule: "R0", .. }),
        "{err:?}"
    );
    for op in ["entry.list", "entry.reveal"] {
        assert!(
            call(
                &state,
                &owner,
                NOW,
                op,
                json!({ "node": ORPHAN_ID, "entry": one })
            )
            .is_err(),
            "{op} on the orphan is refused"
        );
    }

    // The envelope is sealed to the orphan's public key: neither the sealed
    // node's old key nor the global node's opens it…
    let orphan_envelope = std::fs::read(paths.entry_env(ORPHAN_ID, &one)).unwrap();
    // (`open_any`, not `open`: an entry is a version-2 field document since ADR-078, and
    // the version-1-only `open` refuses it for its VERSION — which would make these two
    // negative assertions pass whatever the key. `open_any` refuses only a wrong key.)
    assert!(envelope::open_any(&orphan_envelope, &acme_pub_secret, ORPHAN_ID, &one).is_err());
    assert!(envelope::open_any(&orphan_envelope, &acme_pub_secret, "acme", &one).is_err());
    // …and the cold key — the one path the ADR allows — does.
    let rk = root_from_disk(&env);
    let secret = cold::open_orphan_cold(&rk, &std::fs::read(paths.orphan_key()).unwrap(), None)
        .expect("the cold key opens under the root");
    let (kind, plaintext) = envelope::open_any(&orphan_envelope, &secret, ORPHAN_ID, &one).unwrap();
    assert_eq!(
        kind,
        envelope::PayloadKind::FieldDocument,
        "the orphan copy is the same payload kind the entry was"
    );
    let doc = credmgr_core::fields::decode(plaintext.expose_secret()).expect("a field document");
    assert_eq!(doc.fields.len(), 1);
    assert_eq!(doc.fields[0].value, "value-one");
    // Not under any other root.
    assert!(cold::open_orphan_cold(
        &[3u8; 32],
        &std::fs::read(paths.orphan_key()).unwrap(),
        None
    )
    .is_err());
}

#[test]
fn a_backup_carries_the_cold_key() {
    let (env, state) = created();
    let owner = login(&state);
    let backup = call(
        &state,
        &owner,
        NOW,
        "maintenance.backup",
        json!({ "passphrase": "a backup passphrase" }),
    )
    .expect("maintenance.backup");
    let ciphertext = std::fs::read(backup["path"].as_str().unwrap()).unwrap();
    let plaintext = credmgr_keystore::backup_passphrase::decrypt_with_passphrase(
        &SecretBox::new(Box::new("a backup passphrase".to_string())),
        &ciphertext,
    )
    .expect("the backup decrypts");
    let entries = credmgr_store::backup::unpack(&plaintext).unwrap();
    let cold_entry = entries
        .iter()
        .find(|e| e.relative_path == "keys/cold/orphan.key")
        .expect("the bundle holds keys/cold/orphan.key");
    assert_eq!(
        cold_entry.contents,
        std::fs::read(env.paths().orphan_key()).unwrap()
    );
}

// ---------------------------------------------------------------------------
// A seal that cannot be recovered is refused before anything is written
// ---------------------------------------------------------------------------

/// Nothing a refused seal may have touched.
fn assert_nothing_sealed(env: &Env, state: &BrokerState, owner: &BrokerScope, entry: &str) {
    let paths = env.paths();
    assert!(
        paths.node_dir("acme").exists(),
        "the node's directory is where it was"
    );
    assert!(paths.node_key("acme").exists());
    assert!(
        !paths.archive_dir("acme").exists(),
        "no archive was started"
    );
    assert!(
        !paths.entry_env(ORPHAN_ID, entry).exists(),
        "no orphan copy was written"
    );
    assert!(registry_doc(env).sealed.is_empty());
    assert_eq!(node_ids(state, owner), vec!["acme", "global"]);
    assert_eq!(reveal(state, owner, "acme", entry), "value-one");
}

#[test]
fn a_seal_with_a_missing_or_swapped_cold_key_is_refused_and_writes_nothing() {
    let (env, state) = created();
    let owner = login(&state);
    let (one, _) = acme_with_two_entries(&state, &owner);
    let paths = env.paths();
    let rk = root_from_disk(&env);
    let good = std::fs::read(paths.orphan_key()).unwrap();

    // Missing.
    std::fs::remove_file(paths.orphan_key()).unwrap();
    let err = seal(&state, &owner, "acme", NOW).unwrap_err();
    assert!(
        matches!(&err, OpError::Internal(m) if m.contains("cold key")),
        "{err:?}"
    );
    assert_nothing_sealed(&env, &state, &owner, &one);

    // A genuine cold file of ANOTHER orphan keypair, sealed under this root: it
    // authenticates, but it is not the key the registry names.
    let (_, other) = cold::generate_orphan_cold(&rk);
    atomic::write(&paths.orphan_key(), &other).unwrap();
    let err = seal(&state, &owner, "acme", NOW).unwrap_err();
    assert!(
        matches!(&err, OpError::Internal(m) if m.contains("does not match")),
        "{err:?}"
    );
    assert_nothing_sealed(&env, &state, &owner, &one);

    // A cold file from another vault entirely (another root key).
    let (_, foreign) = cold::generate_orphan_cold(&[9u8; 32]);
    atomic::write(&paths.orphan_key(), &foreign).unwrap();
    assert!(seal(&state, &owner, "acme", NOW).is_err());
    assert_nothing_sealed(&env, &state, &owner, &one);

    // A torn file.
    let mut torn = good.clone();
    let last = torn.len() - 1;
    torn[last] ^= 1;
    atomic::write(&paths.orphan_key(), &torn).unwrap();
    assert!(seal(&state, &owner, "acme", NOW).is_err());
    assert_nothing_sealed(&env, &state, &owner, &one);

    // `maintenance.verify` names the damage; the real file puts everything right.
    let v = verify(&state, &owner);
    assert_eq!(v["ok"], false, "{v}");
    assert!(v["errors"].to_string().contains("orphan cold key"), "{v}");
    atomic::write(&paths.orphan_key(), &good).unwrap();
    assert_verify_ok(&state, &owner);
    seal(&state, &owner, "acme", NOW).expect("with the real key back, the seal goes through");
}

#[test]
fn doctor_regenerates_a_missing_cold_key_only_while_nothing_is_sealed_to_it() {
    let (env, state) = created();
    let owner = login(&state);
    let (one, _) = acme_with_two_entries(&state, &owner);
    let paths = env.paths();
    let before = std::fs::read(paths.orphan_key()).unwrap();

    // Nothing sealed yet: a missing key is regenerated, and a seal then works.
    std::fs::remove_file(paths.orphan_key()).unwrap();
    let dry = call(
        &state,
        &owner,
        NOW,
        "maintenance.doctor",
        json!({ "apply": false }),
    )
    .unwrap();
    assert_eq!(
        dry["fixes"][0]["type"], "orphan-cold-key-regenerated",
        "{dry}"
    );
    assert!(!paths.orphan_key().exists(), "a dry run changes nothing");
    let done = call(&state, &owner, NOW, "maintenance.doctor", json!({})).unwrap();
    assert_eq!(done["fixCount"], 1, "{done}");
    let regenerated = std::fs::read(paths.orphan_key()).unwrap();
    assert_ne!(regenerated, before, "a fresh keypair");
    assert_verify_ok(&state, &owner);
    seal(&state, &owner, "acme", NOW).expect("seal after the repair");
    assert!(paths.entry_env(ORPHAN_ID, &one).exists());

    // With orphaned data in the vault, the same damage is NOT repaired by
    // regenerating — that would strand what is sealed.
    std::fs::remove_file(paths.orphan_key()).unwrap();
    let refused = call(&state, &owner, NOW, "maintenance.doctor", json!({})).unwrap();
    assert_eq!(refused["fixCount"], 0, "{refused}");
    assert!(
        refused["unfixable"].to_string().contains("strand"),
        "{refused}"
    );
    assert!(
        !paths.orphan_key().exists(),
        "doctor did not invent a key over orphaned data"
    );
}

// ---------------------------------------------------------------------------
// The signed record is the authority
// ---------------------------------------------------------------------------

#[test]
fn an_edited_seal_record_fails_the_registry_signature_at_unlock() {
    let (env, state) = created();
    let owner = login(&state);
    acme_with_two_entries(&state, &owner);
    seal(&state, &owner, "acme", NOW).unwrap();
    drop(state);

    // Make an expired seal look fresh: push `sealedAt` forward in the plaintext registry.
    let path = env.paths().registry();
    let text = std::fs::read_to_string(&path).unwrap();
    let needle = format!("\"sealedAt\": {NOW}");
    assert!(
        text.contains(&needle),
        "the record's sealedAt is in the file"
    );
    std::fs::write(
        &path,
        text.replace(&needle, &format!("\"sealedAt\": {}", NOW + 9 * DAY)),
    )
    .unwrap();

    let state = env.broker();
    let err = try_login(&state).unwrap_err();
    assert!(
        matches!(&err, OpError::Internal(m) if m.contains("integrity")),
        "an edited record is a tampered registry: {err:?}"
    );
}

#[test]
fn an_older_registry_pair_that_still_names_the_seal_is_refused_by_the_rollback_counter() {
    let (env, state) = created();
    let owner = login(&state);
    acme_with_two_entries(&state, &owner);
    seal(&state, &owner, "acme", NOW).unwrap();
    // The pair that records the seal…
    let paths = env.paths();
    let sealed_json = std::fs::read(paths.registry()).unwrap();
    let sealed_sig = std::fs::read(paths.registry_sig()).unwrap();
    // …then the restore, which removes the record.
    restore(&state, &owner, "acme", NOW + DAY).unwrap();
    drop(state);

    // An attacker puts the old, validly signed pair back: the seal is "live" again.
    std::fs::write(paths.registry(), sealed_json).unwrap();
    std::fs::write(paths.registry_sig(), sealed_sig).unwrap();
    std::fs::remove_file(paths.registry_prev()).ok();
    std::fs::remove_file(paths.registry_sig_prev()).ok();

    let state = env.broker();
    let err = try_login(&state).unwrap_err();
    assert!(
        matches!(&err, OpError::Internal(m) if m.contains("rolled-back") || m.contains("behind")),
        "the external generation counter refuses it: {err:?}"
    );
}

/// An older, validly signed copy of the archived manifest — the rollback `04 §6a`
/// exists to stop — is swapped in. The signed record binds the generation and
/// HMAC, so the restore refuses, and nothing moves.
#[test]
fn an_older_signed_archive_manifest_swapped_in_makes_restore_refuse_and_move_nothing() {
    let (env, state) = created();
    let owner = login(&state);
    let paths = env.paths();
    create_node(&state, &owner, "acme", GLOBAL_ID);
    create_entry(&state, &owner, "acme", "ONE", "value-one");
    let older = std::fs::read(paths.manifest("acme")).unwrap();
    create_entry(&state, &owner, "acme", "TWO", "value-two");
    seal(&state, &owner, "acme", NOW).unwrap();

    std::fs::write(
        paths.archive_dir("acme").join("node").join("manifest.json"),
        older,
    )
    .unwrap();
    let err = restore(&state, &owner, "acme", NOW + DAY).unwrap_err();
    assert!(
        matches!(&err, OpError::Internal(m) if m.contains("does not match its seal record")),
        "{err:?}"
    );
    assert_still_sealed(&env, &state, &owner);
}

#[test]
fn a_swapped_archived_node_key_makes_restore_refuse_and_move_nothing() {
    let (env, state) = created();
    let owner = login(&state);
    let paths = env.paths();
    acme_with_two_entries(&state, &owner);
    seal(&state, &owner, "acme", NOW).unwrap();

    // Another node's genuine wrapped key (global's), validly wrapped under this root.
    let other = std::fs::read(paths.node_key(GLOBAL_ID)).unwrap();
    std::fs::write(paths.archive_dir("acme").join("node.key"), other).unwrap();
    let err = restore(&state, &owner, "acme", NOW + DAY).unwrap_err();
    assert!(
        matches!(&err, OpError::Internal(m) if m.contains("does not match its seal record")),
        "{err:?}"
    );
    assert_still_sealed(&env, &state, &owner);
}

#[test]
fn a_forged_archive_meta_makes_restore_refuse_and_a_missing_one_says_not_found() {
    let (env, state) = created();
    let owner = login(&state);
    let paths = env.paths();
    acme_with_two_entries(&state, &owner);
    seal(&state, &owner, "acme", NOW).unwrap();

    let meta = archive::meta_file(&paths.archive_dir("acme"));
    let good = std::fs::read(&meta).unwrap();
    std::fs::write(&meta, b"{\"nodeId\":\"acme\"}").unwrap();
    assert!(restore(&state, &owner, "acme", NOW + DAY).is_err());
    assert_still_sealed(&env, &state, &owner);

    std::fs::remove_file(&meta).unwrap();
    assert!(matches!(
        restore(&state, &owner, "acme", NOW + DAY).unwrap_err(),
        OpError::NotFound(_)
    ));
    // verify names it.
    let v = verify(&state, &owner);
    assert_eq!(v["ok"], false, "{v}");
    std::fs::write(&meta, good).unwrap();
    restore(&state, &owner, "acme", NOW + DAY).expect("with the real meta back");
}

fn assert_still_sealed(env: &Env, state: &BrokerState, owner: &BrokerScope) {
    let paths = env.paths();
    assert_eq!(node_ids(state, owner), vec!["global"]);
    assert!(registry_doc(env).sealed.contains_key("acme"));
    assert!(
        !paths.node_dir("acme").exists() && !paths.node_key("acme").exists(),
        "a refused restore leaves the files in the archive"
    );
    assert!(paths.archive_dir("acme").join("node").exists());
    assert!(paths.archive_dir("acme").join("node.key").exists());
}

#[test]
fn a_registry_of_a_newer_format_is_refused_by_name_at_unlock() {
    let (env, state) = created();
    drop(state);
    let rk = root_from_disk(&env);
    let mut doc = registry_doc(&env);
    doc.format = registry_file::REGISTRY_FORMAT + 1;
    registry_file::save(&env.paths(), &rk, &doc).unwrap();

    let state = env.broker();
    let err = try_login(&state).unwrap_err();
    assert!(
        matches!(&err, OpError::Internal(m) if m.contains("format 3") && m.contains("newer")),
        "{err:?}"
    );
}

// ---------------------------------------------------------------------------
// Sub-nodes, ids, workdirs
// ---------------------------------------------------------------------------

#[test]
fn a_project_with_live_sub_nodes_cannot_be_sealed_until_they_are() {
    let (env, state) = created();
    let owner = login(&state);
    create_node(&state, &owner, "acme", GLOBAL_ID);
    create_node(&state, &owner, "acme-api", "acme");
    create_entry(&state, &owner, "acme-api", "K", "sub-value");

    let err = seal(&state, &owner, "acme", NOW).unwrap_err();
    assert!(
        matches!(&err, OpError::Malformed(m) if m.contains("sub-nodes") && m.contains("acme-api")),
        "{err:?}"
    );
    assert_eq!(node_ids(&state, &owner), vec!["acme", "acme-api", "global"]);

    // Children first, then the parent.
    seal(&state, &owner, "acme-api", NOW).expect("the sub-node");
    seal(&state, &owner, "acme", NOW).expect("now the project has no live children");
    assert_eq!(node_ids(&state, &owner), vec!["global"]);

    // Restoring the child before its parent is refused, and says what to do.
    let (state, owner) = restart(&env, state);
    let err = restore(&state, &owner, "acme-api", NOW + DAY).unwrap_err();
    assert!(
        matches!(&err, OpError::Malformed(m) if m.contains("restore acme first")),
        "{err:?}"
    );
    assert_eq!(node_ids(&state, &owner), vec!["global"]);
    restore(&state, &owner, "acme", NOW + DAY).unwrap();
    restore(&state, &owner, "acme-api", NOW + DAY).unwrap();
    assert_eq!(node_ids(&state, &owner), vec!["acme", "acme-api", "global"]);
    let entry = state.manifests.read().unwrap()["acme-api"].entries[0]
        .id
        .clone();
    assert_eq!(reveal(&state, &owner, "acme-api", &entry), "sub-value");
}

#[test]
fn a_node_id_must_fit_the_grammar_and_none_leaves_the_vault() {
    let (env, state) = created();
    let owner = login(&state);
    let before = list_tree(&env.vault_dir);
    for bad in [
        "../x",
        "..",
        "a/b",
        "Acme",
        "has space",
        "removed-entries",
        "entry-history",
        "global",
        "orphan",
        "",
        &"x".repeat(65),
    ] {
        let err = call(
            &state,
            &owner,
            NOW,
            "node.create",
            json!({ "id": bad, "label": "x", "parentId": GLOBAL_ID }),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::Malformed(_)), "{bad:?}: {err:?}");
    }
    assert_eq!(
        list_tree(&env.vault_dir),
        before,
        "a refused id writes nothing"
    );
    assert!(
        !env.vault_dir.parent().unwrap().join("x").exists(),
        "and nothing escaped the vault"
    );
    create_node(&state, &owner, "ok_id-1", GLOBAL_ID);
}

fn list_tree(dir: &std::path::Path) -> Vec<String> {
    fn walk(dir: &std::path::Path, base: &std::path::Path, out: &mut Vec<String>) {
        let Ok(read) = std::fs::read_dir(dir) else {
            return;
        };
        for e in read.flatten() {
            let p = e.path();
            // The advisory lock is runtime state, created on first unlock.
            if p.ends_with("run") {
                continue;
            }
            out.push(p.strip_prefix(base).unwrap().to_string_lossy().into_owned());
            if p.is_dir() {
                walk(&p, base, out);
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, dir, &mut out);
    out.sort();
    out
}

#[test]
fn a_workdir_another_node_took_while_sealed_is_dropped_on_restore_and_reported() {
    let (env, state) = created();
    let owner = login(&state);
    let work = tempfile::tempdir().unwrap();
    let work_path = std::fs::canonicalize(work.path())
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let keep = tempfile::tempdir().unwrap();
    let keep_path = std::fs::canonicalize(keep.path())
        .unwrap()
        .to_string_lossy()
        .into_owned();
    call(
        &state,
        &owner,
        NOW,
        "node.create",
        json!({ "id": "acme", "label": "acme", "parentId": GLOBAL_ID,
                "workdirs": [work_path, keep_path] }),
    )
    .unwrap();
    seal(&state, &owner, "acme", NOW).unwrap();

    // While acme is sealed, another project claims one of its directories.
    call(
        &state,
        &owner,
        NOW,
        "node.create",
        json!({ "id": "other", "label": "other", "parentId": GLOBAL_ID, "workdirs": [work_path] }),
    )
    .expect("a sealed node's workdirs are free to take");

    let (state, owner) = restart(&env, state);
    let restored = restore(&state, &owner, "acme", NOW + DAY).unwrap();
    assert_eq!(
        restored["workdirsDropped"],
        json!([work_path]),
        "{restored}"
    );
    let registry = state.registry.read().unwrap();
    assert_eq!(registry.nodes["acme"].workdirs, vec![keep_path]);
    assert_eq!(registry.nodes["other"].workdirs, vec![work_path]);
}

// ---------------------------------------------------------------------------
// An alpha vault: opens unchanged, gains the orphan lazily
// ---------------------------------------------------------------------------

/// Rewrite `registry.json` through `edit` and sign it again under the real root
/// key, leaving the rollback counter as it was: a registry that authenticates
/// and says whatever the test needs it to.
fn rewrite_registry(env: &Env, edit: impl FnOnce(&mut Value)) {
    let rk = root_from_disk(env);
    let paths = env.paths();
    let mut value: Value =
        serde_json::from_slice(&std::fs::read(paths.registry()).unwrap()).unwrap();
    edit(&mut value);
    let bytes = serde_json::to_vec_pretty(&value).unwrap();
    let tag = credmgr_core::signing::sign(&rk, registry_file::REGISTRY_HMAC_LABEL, &bytes);
    atomic::write(&paths.registry(), &bytes).unwrap();
    atomic::write(&paths.registry_sig(), hex(&tag).as_bytes()).unwrap();
    std::fs::remove_file(paths.registry_prev()).ok();
    std::fs::remove_file(paths.registry_sig_prev()).ok();
}

/// Rewrite a freshly initialised vault into the shape an alpha.6 build wrote: the
/// registry has only `global` (no `orphan`, no `format`, no `sealed`), there is
/// no orphan manifest and no `keys/cold/`. Signed under the real root key and
/// level with the real rollback counter, so it is a vault an old build could have
/// left behind.
fn make_alpha_shaped(env: &Env) {
    let paths = env.paths();
    rewrite_registry(env, |value| {
        let object = value.as_object_mut().unwrap();
        object.remove("format");
        object.remove("sealed");
        object["nodes"].as_object_mut().unwrap().remove(ORPHAN_ID);
        object["manifests"]
            .as_object_mut()
            .unwrap()
            .remove(ORPHAN_ID);
    });
    std::fs::remove_dir_all(paths.node_dir(ORPHAN_ID)).unwrap();
    std::fs::remove_dir_all(paths.keys_cold_dir()).unwrap();
}

#[test]
fn an_alpha_vault_opens_unchanged_and_gains_the_orphan_on_its_first_seal_never_at_unlock() {
    let (env, state) = created();
    drop(state);
    make_alpha_shaped(&env);
    let paths = env.paths();
    let registry_before = std::fs::read(paths.registry()).unwrap();
    let doc = registry_doc(&env);
    assert_eq!(doc.format, 1, "an alpha registry reads as format 1");
    assert!(!doc.nodes.contains_key(ORPHAN_ID));

    // Unlock: it opens, and writes nothing to signed state (K-7: never as a side
    // effect of unlock).
    let state = env.broker();
    let owner = login(&state);
    assert_eq!(
        std::fs::read(paths.registry()).unwrap(),
        registry_before,
        "unlock did not touch the registry"
    );
    assert!(!paths.orphan_key().exists(), "and created no cold key");
    assert!(!paths.node_dir(ORPHAN_ID).exists());
    assert_eq!(node_ids(&state, &owner), vec!["global"]);

    // Ordinary work carries on.
    let (one, _) = acme_with_two_entries(&state, &owner);
    assert!(
        !paths.orphan_key().exists(),
        "ordinary writes do not create the orphan either"
    );

    // The first seal creates it, in the same vault, and works.
    seal(&state, &owner, "acme", NOW).expect("the first seal creates the orphan lazily");
    assert!(paths.orphan_key().exists());
    let doc = registry_doc(&env);
    assert!(doc.nodes.contains_key(ORPHAN_ID));
    assert_eq!(doc.format, registry_file::REGISTRY_FORMAT);
    assert_eq!(
        cold::parse_header(&std::fs::read(paths.orphan_key()).unwrap())
            .unwrap()
            .public
            .as_bytes(),
        hex_to_32(&doc.nodes[ORPHAN_ID].public_key).as_slice()
    );
    assert!(!state
        .hot_key_node_ids_for_test()
        .contains(&ORPHAN_ID.to_string()));

    // Restart: the vault, now with an orphan, loads — and the seal restores.
    let (state, owner) = restart(&env, state);
    assert_verify_ok(&state, &owner);
    restore(&state, &owner, "acme", NOW + DAY).unwrap();
    assert_eq!(reveal(&state, &owner, "acme", &one), "value-one");
}

#[test]
fn doctor_creates_the_orphan_in_an_alpha_vault_without_sealing_anything() {
    let (env, state) = created();
    drop(state);
    make_alpha_shaped(&env);
    let state = env.broker();
    let owner = login(&state);

    let done = call(&state, &owner, NOW, "maintenance.doctor", json!({})).unwrap();
    assert_eq!(done["fixes"][0]["type"], "orphan-created", "{done}");
    assert!(env.paths().orphan_key().exists());
    assert!(registry_doc(&env).nodes.contains_key(ORPHAN_ID));
    assert_verify_ok(&state, &owner);
    // A second run finds nothing.
    let again = call(&state, &owner, NOW, "maintenance.doctor", json!({})).unwrap();
    assert_eq!(again["fixCount"], 0, "{again}");
}

// ---------------------------------------------------------------------------
// The crash table: a crash at each step of the commit protocol
// ---------------------------------------------------------------------------

/// A vault with `acme` (two entries) and the broker that made it, plus the pieces
/// the crash tests read back.
struct Crashy {
    env: Env,
    state: Arc<BrokerState>,
    owner: BrokerScope,
    one: String,
    two: String,
}

fn crashy() -> Crashy {
    let (env, state) = created();
    let owner = login(&state);
    let (one, two) = acme_with_two_entries(&state, &owner);
    Crashy {
        env,
        state,
        owner,
        one,
        two,
    }
}

impl Crashy {
    /// The process dies; a fresh one starts and unlocks. Unlocking is the
    /// invariant every row of the table owes: the vault opens.
    fn crash_and_restart(self) -> (Env, Arc<BrokerState>, BrokerScope, String, String) {
        let (state, owner) = restart(&self.env, self.state);
        (self.env, state, owner, self.one, self.two)
    }
}

fn sealed_and_restorable(
    env: &Env,
    state: &BrokerState,
    owner: &BrokerScope,
    one: &str,
    two: &str,
) {
    let paths = env.paths();
    assert_eq!(node_ids(state, owner), vec!["global"], "sealed");
    assert!(registry_doc(env).sealed.contains_key("acme"));
    assert!(
        !paths.node_dir("acme").exists() && !paths.node_key("acme").exists(),
        "the files are in the archive"
    );
    assert!(paths.archive_dir("acme").join("node").exists());
    assert!(paths.archive_dir("acme").join("node.key").exists());
    assert_verify_ok(state, owner);
    restore(state, owner, "acme", NOW + DAY).expect("restorable");
    assert_eq!(reveal(state, owner, "acme", one), "value-one");
    assert_eq!(reveal(state, owner, "acme", two), "value-two");
    assert_verify_ok(state, owner);
}

fn live_and_sealable(env: &Env, state: &BrokerState, owner: &BrokerScope, one: &str, two: &str) {
    assert_eq!(node_ids(state, owner), vec!["acme", "global"], "live");
    assert!(registry_doc(env).sealed.is_empty());
    assert_eq!(reveal(state, owner, "acme", one), "value-one");
    assert_eq!(reveal(state, owner, "acme", two), "value-two");
    seal(state, owner, "acme", NOW + 1).expect("a retried seal succeeds");
    assert_eq!(node_ids(state, owner), vec!["global"]);
    assert!(registry_doc(env).sealed.contains_key("acme"));
    assert_verify_ok(state, owner);
}

#[test]
fn crash_row_seal_after_s2_leaves_the_node_live_and_housekeeping_clears_the_residue() {
    let c = crashy();
    let paths = c.env.paths();
    c.state
        .set_seal_fault_for_test(Some(SealFault::SealAfterPreCommit));
    let err = seal(&c.state, &c.owner, "acme", NOW).unwrap_err();
    assert!(is_injected_crash(&err), "{err:?}");
    // The crash left unread residue: orphan envelopes, no rows; a meta.json.
    assert!(paths.entry_env(ORPHAN_ID, &c.one).exists());
    assert!(paths.archive_dir("acme").join("meta.json").exists());

    let (env, state, owner, one, two) = c.crash_and_restart();
    let paths = env.paths();
    assert!(
        !paths.entry_env(ORPHAN_ID, &one).exists() && !paths.entry_env(ORPHAN_ID, &two).exists(),
        "orphan envelopes of a live node's entries, with no row, are removed at load"
    );
    assert!(
        !paths.archive_dir("acme").exists(),
        "and so is the aborted seal's archive/<id>"
    );
    assert_verify_ok(&state, &owner);
    live_and_sealable(&env, &state, &owner, &one, &two);
}

#[test]
fn crash_row_seal_s4_partial_orphan_manifest_written_registry_not() {
    let c = crashy();
    // The first persist is the seal's level-the-disk write; the second is the commit.
    c.state
        .set_persist_fault_after_for_test(1, Some(PersistFault::BeforeRegistry));
    let err = seal(&c.state, &c.owner, "acme", NOW).unwrap_err();
    assert!(is_injected_crash(&err), "{err:?}");

    // On disk: the orphan's manifest is one generation ahead of its binding and
    // holds acme's rows; the registry still has acme live.
    let rk = root_from_disk(&c.env);
    let paths = c.env.paths();
    let orphan_manifest = manifest::load(&paths, &rk, ORPHAN_ID).unwrap();
    let doc = registry_doc(&c.env);
    assert_eq!(
        orphan_manifest.body.generation,
        doc.manifests[ORPHAN_ID].generation + 1,
        "one generation ahead, however many entries — the loader accepts exactly this"
    );
    assert_eq!(orphan_manifest.body.entries.len(), 2);
    assert!(doc.nodes.contains_key("acme") && doc.sealed.is_empty());

    let (env, state, owner, one, two) = c.crash_and_restart();
    // It opens, the node is live and readable; the rows are harmless residue
    // that `maintenance.doctor` removes.
    assert_eq!(node_ids(&state, &owner), vec!["acme", "global"]);
    assert_eq!(reveal(&state, &owner, "acme", &one), "value-one");
    let dry = call(
        &state,
        &owner,
        NOW,
        "maintenance.doctor",
        json!({ "apply": false }),
    )
    .unwrap();
    assert_eq!(dry["fixes"][0]["type"], "orphan-residue-removed", "{dry}");
    call(&state, &owner, NOW, "maintenance.doctor", json!({})).unwrap();
    assert!(
        state
            .manifests
            .read()
            .unwrap()
            .get(ORPHAN_ID)
            .map_or(true, |m| m.entries.is_empty()),
        "doctor removed the rows"
    );
    assert!(!env.paths().entry_env(ORPHAN_ID, &one).exists());
    live_and_sealable(&env, &state, &owner, &one, &two);
}

#[test]
fn crash_row_seal_s4_partial_then_a_retry_replaces_the_residue_rather_than_doubling_it() {
    let c = crashy();
    c.state
        .set_persist_fault_after_for_test(1, Some(PersistFault::BeforeRegistry));
    assert!(is_injected_crash(
        &seal(&c.state, &c.owner, "acme", NOW).unwrap_err()
    ));
    let (env, state, owner, one, two) = c.crash_and_restart();
    // No doctor in between: the next seal of the node overwrites the residue.
    live_and_sealable(&env, &state, &owner, &one, &two);
    let orphan_rows = state.manifests.read().unwrap()[ORPHAN_ID].entries.len();
    assert_eq!(
        orphan_rows, 2,
        "one row per sealed entry — the residue was replaced, not doubled"
    );
}

#[test]
fn crash_row_seal_after_the_commit_before_either_move_is_rolled_forward_at_load() {
    let c = crashy();
    c.state
        .set_seal_fault_for_test(Some(SealFault::SealAfterCommit));
    assert!(is_injected_crash(
        &seal(&c.state, &c.owner, "acme", NOW).unwrap_err()
    ));
    let paths = c.env.paths();
    assert!(
        registry_doc(&c.env).sealed.contains_key("acme"),
        "committed"
    );
    assert!(
        paths.node_dir("acme").exists() && paths.node_key("acme").exists(),
        "…and nothing has moved"
    );
    let registry_before = std::fs::read(paths.registry()).unwrap();

    let (env, state, owner, one, two) = c.crash_and_restart();
    assert_eq!(
        std::fs::read(env.paths().registry()).unwrap(),
        registry_before,
        "housekeeping never writes signed state"
    );
    sealed_and_restorable(&env, &state, &owner, &one, &two);
}

#[test]
fn crash_row_seal_after_the_node_directory_moved_but_not_the_key() {
    let c = crashy();
    c.state
        .set_seal_fault_for_test(Some(SealFault::SealAfterNodeDirMoved));
    assert!(is_injected_crash(
        &seal(&c.state, &c.owner, "acme", NOW).unwrap_err()
    ));
    let paths = c.env.paths();
    assert!(paths.archive_dir("acme").join("node").exists());
    assert!(paths.node_key("acme").exists(), "the key has not moved yet");

    let (env, state, owner, one, two) = c.crash_and_restart();
    sealed_and_restorable(&env, &state, &owner, &one, &two);
}

#[test]
fn crash_row_seal_registry_written_counter_not() {
    let c = crashy();
    c.state
        .set_persist_fault_after_for_test(1, Some(PersistFault::AfterRegistryBeforeCounter));
    assert!(is_injected_crash(
        &seal(&c.state, &c.owner, "acme", NOW).unwrap_err()
    ));
    let (env, state, owner, one, two) = c.crash_and_restart();
    sealed_and_restorable(&env, &state, &owner, &one, &two);
}

/// A restore needs the node sealed first; this does it cleanly and hands back a
/// broker ready to crash during the restore.
fn sealed_crashy() -> Crashy {
    let c = crashy();
    seal(&c.state, &c.owner, "acme", NOW).expect("seal");
    c
}

#[test]
fn crash_row_restore_after_the_files_moved_back_but_before_the_commit() {
    let c = sealed_crashy();
    c.state
        .set_seal_fault_for_test(Some(SealFault::RestoreAfterMoveOut));
    let err = restore(&c.state, &c.owner, "acme", NOW + DAY).unwrap_err();
    assert!(is_injected_crash(&err), "{err:?}");
    let paths = c.env.paths();
    assert!(
        paths.node_dir("acme").exists() && paths.node_key("acme").exists(),
        "the files are back in their live places"
    );
    assert!(
        registry_doc(&c.env).sealed.contains_key("acme"),
        "still sealed"
    );

    let (env, state, owner, one, two) = c.crash_and_restart();
    // Housekeeping puts them back in the archive; the restore can be retried.
    sealed_and_restorable(&env, &state, &owner, &one, &two);
}

#[test]
fn crash_row_restore_r5_partial_orphan_manifest_written_registry_not() {
    let c = sealed_crashy();
    c.state
        .set_persist_fault_for_test(Some(PersistFault::BeforeRegistry));
    let err = restore(&c.state, &c.owner, "acme", NOW + DAY).unwrap_err();
    assert!(is_injected_crash(&err), "{err:?}");
    assert!(
        registry_doc(&c.env).sealed.contains_key("acme"),
        "still sealed"
    );

    let (env, state, owner, one, two) = c.crash_and_restart();
    // The orphan manifest lost its rows (one generation ahead — accepted); the
    // envelopes are still there; the record is still authoritative.
    sealed_and_restorable(&env, &state, &owner, &one, &two);
}

#[test]
fn crash_row_restore_committed_before_the_cleanup() {
    let c = sealed_crashy();
    c.state
        .set_seal_fault_for_test(Some(SealFault::RestoreAfterCommit));
    let err = restore(&c.state, &c.owner, "acme", NOW + DAY).unwrap_err();
    assert!(is_injected_crash(&err), "{err:?}");
    let paths = c.env.paths();
    assert!(registry_doc(&c.env).sealed.is_empty(), "committed");
    assert!(
        paths.entry_env(ORPHAN_ID, &c.one).exists(),
        "the orphan copies remain"
    );
    assert!(paths.archive_dir("acme").join("meta.json").exists());
    let registry_before = std::fs::read(paths.registry()).unwrap();

    let (env, state, owner, one, two) = c.crash_and_restart();
    let paths = env.paths();
    assert_eq!(
        std::fs::read(paths.registry()).unwrap(),
        registry_before,
        "housekeeping never writes signed state"
    );
    assert_eq!(node_ids(&state, &owner), vec!["acme", "global"], "restored");
    assert_eq!(reveal(&state, &owner, "acme", &one), "value-one");
    assert_eq!(reveal(&state, &owner, "acme", &two), "value-two");
    assert!(
        !paths.entry_env(ORPHAN_ID, &one).exists() && !paths.entry_env(ORPHAN_ID, &two).exists(),
        "housekeeping deleted the orphan envelopes"
    );
    assert!(
        !paths.archive_dir("acme").exists(),
        "and the leftover meta.json"
    );
    assert_verify_ok(&state, &owner);
}

/// Every row, in one place, as a table: after a crash and a restart each leaves a
/// vault that unlocks and verifies — the property the individual tests above
/// check in detail.
#[test]
fn every_crash_row_leaves_a_vault_that_unlocks_and_verifies() {
    enum Arm {
        Seal(SealFault),
        SealPersist(usize, PersistFault),
        RestorePersist(PersistFault),
        Restore(SealFault),
    }
    let rows = [
        ("seal S2", Arm::Seal(SealFault::SealAfterPreCommit)),
        (
            "seal S4 before registry",
            Arm::SealPersist(1, PersistFault::BeforeRegistry),
        ),
        (
            "seal S4 before counter",
            Arm::SealPersist(1, PersistFault::AfterRegistryBeforeCounter),
        ),
        ("seal S4 done", Arm::Seal(SealFault::SealAfterCommit)),
        ("seal S5 half", Arm::Seal(SealFault::SealAfterNodeDirMoved)),
        ("restore R1", Arm::Restore(SealFault::RestoreAfterMoveOut)),
        (
            "restore R5 before registry",
            Arm::RestorePersist(PersistFault::BeforeRegistry),
        ),
        (
            "restore R5 before counter",
            Arm::RestorePersist(PersistFault::AfterRegistryBeforeCounter),
        ),
        (
            "restore R5 done",
            Arm::Restore(SealFault::RestoreAfterCommit),
        ),
    ];
    for (name, arm) in rows {
        let c = crashy();
        let restoring = matches!(arm, Arm::Restore(_) | Arm::RestorePersist(_));
        if restoring {
            seal(&c.state, &c.owner, "acme", NOW).unwrap();
        }
        match arm {
            Arm::Seal(f) => c.state.set_seal_fault_for_test(Some(f)),
            Arm::Restore(f) => c.state.set_seal_fault_for_test(Some(f)),
            Arm::SealPersist(skip, f) => c.state.set_persist_fault_after_for_test(skip, Some(f)),
            Arm::RestorePersist(f) => c.state.set_persist_fault_for_test(Some(f)),
        }
        let result = if restoring {
            restore(&c.state, &c.owner, "acme", NOW + DAY)
        } else {
            seal(&c.state, &c.owner, "acme", NOW)
        };
        assert!(
            result.as_ref().is_err_and(is_injected_crash),
            "{name}: the fault fired: {result:?}"
        );
        let (_env, state, owner, one, _) = c.crash_and_restart();
        let v = verify(&state, &owner);
        assert_eq!(v["ok"], true, "{name}: {v}");
        // Whichever side of the commit it died on, the node is somewhere
        // consistent: live and readable, or sealed and restorable.
        if node_ids(&state, &owner).contains(&"acme".to_string()) {
            assert_eq!(reveal(&state, &owner, "acme", &one), "value-one", "{name}");
        } else {
            restore(&state, &owner, "acme", NOW + DAY).unwrap_or_else(|e| panic!("{name}: {e:?}"));
            assert_eq!(reveal(&state, &owner, "acme", &one), "value-one", "{name}");
        }
    }
}

// ---------------------------------------------------------------------------
// A persist failure that is NOT a crash is rolled back
// ---------------------------------------------------------------------------

#[test]
fn a_seal_whose_commit_fails_is_rolled_back_in_memory_and_on_disk() {
    let c = crashy();
    let paths = c.env.paths();
    let grants_before = state_grants(&c.state);
    // The level-the-disk write passes; the commit fails after the manifests landed.
    c.state
        .set_persist_fault_after_for_test(1, Some(PersistFault::FailBeforeRegistry));
    let err = seal(&c.state, &c.owner, "acme", NOW).unwrap_err();
    assert!(
        matches!(&err, OpError::Internal(m) if m.contains("rolled back")),
        "{err:?}"
    );
    assert!(
        !is_injected_crash(&err),
        "this one is a failure, not a crash"
    );

    // Memory: the node is live, readable, in the graph, with its key hot.
    assert_eq!(node_ids(&c.state, &c.owner), vec!["acme", "global"]);
    assert_eq!(reveal(&c.state, &c.owner, "acme", &c.one), "value-one");
    assert_eq!(reveal(&c.state, &c.owner, "acme", &c.two), "value-two");
    assert_eq!(state_grants(&c.state), grants_before);
    assert_eq!(c.state.manifest_generation("acme"), Some(2));
    // Disk: no archive, no orphan copy, no record.
    assert!(!paths.archive_dir("acme").exists());
    assert!(!paths.entry_env(ORPHAN_ID, &c.one).exists());
    assert!(registry_doc(&c.env).sealed.is_empty());
    assert!(paths.node_dir("acme").exists() && paths.node_key("acme").exists());
    // The orphan's manifest in memory is as it was: empty.
    assert!(c
        .state
        .manifests
        .read()
        .unwrap()
        .get(ORPHAN_ID)
        .map_or(true, |m| m.entries.is_empty()));

    // And the same broker seals it on a retry, and the result survives a restart.
    seal(&c.state, &c.owner, "acme", NOW + 1).expect("a retry succeeds");
    assert_eq!(node_ids(&c.state, &c.owner), vec!["global"]);
    let (state, owner) = restart(&c.env, c.state);
    assert_verify_ok(&state, &owner);
    restore(&state, &owner, "acme", NOW + DAY).unwrap();
    assert_eq!(reveal(&state, &owner, "acme", &c.one), "value-one");
}

#[test]
fn a_restore_whose_commit_fails_is_rolled_back_and_the_node_stays_sealed() {
    let c = sealed_crashy();
    let paths = c.env.paths();
    c.state
        .set_persist_fault_for_test(Some(PersistFault::FailBeforeRegistry));
    let err = restore(&c.state, &c.owner, "acme", NOW + DAY).unwrap_err();
    assert!(
        matches!(&err, OpError::Internal(m) if m.contains("rolled back")),
        "{err:?}"
    );
    assert!(!is_injected_crash(&err));

    // Still sealed, in memory and on disk; the files are back in the archive.
    assert_eq!(node_ids(&c.state, &c.owner), vec!["global"]);
    assert!(registry_doc(&c.env).sealed.contains_key("acme"));
    assert!(!paths.node_dir("acme").exists() && !paths.node_key("acme").exists());
    assert!(paths.archive_dir("acme").join("node").exists());
    assert!(paths.archive_dir("acme").join("node.key").exists());
    assert_eq!(
        c.state.manifests.read().unwrap()[ORPHAN_ID].entries.len(),
        2,
        "the orphan rows are back"
    );
    // A retry restores it.
    restore(&c.state, &c.owner, "acme", NOW + DAY).expect("a retry succeeds");
    assert_eq!(reveal(&c.state, &c.owner, "acme", &c.one), "value-one");
    let (state, owner) = restart(&c.env, c.state);
    assert_eq!(reveal(&state, &owner, "acme", &c.two), "value-two");
    assert_verify_ok(&state, &owner);
}

fn state_grants(state: &BrokerState) -> usize {
    state.registry.read().unwrap().grants.len()
}

// ---------------------------------------------------------------------------
// Rotation meets a seal whose moves did not finish
// ---------------------------------------------------------------------------

#[test]
fn a_rotation_finishes_the_moves_a_seal_left_pending_and_the_node_still_restores() {
    let c = crashy();
    // Committed, nothing moved — and the same broker (not a restart) goes on to rotate.
    c.state
        .set_seal_fault_for_test(Some(SealFault::SealAfterCommit));
    assert!(is_injected_crash(
        &seal(&c.state, &c.owner, "acme", NOW).unwrap_err()
    ));
    let paths = c.env.paths();
    assert!(paths.node_key("acme").exists(), "not yet in the archive");

    let outcome = c
        .state
        .rotate_root(passphrase(), NOW + 1)
        .expect("a rotation finishes the pending moves first");
    assert!(outcome.skipped.is_empty(), "{:?}", outcome.skipped);
    assert!(
        !paths.node_key("acme").exists(),
        "the key moved into the archive"
    );
    assert!(paths.archive_dir("acme").join("node.key").exists());

    let (state, owner) = restart(&c.env, c.state);
    restore(&state, &owner, "acme", NOW + DAY).expect("and it restores under the new root key");
    assert_eq!(reveal(&state, &owner, "acme", &c.one), "value-one");
    assert_eq!(reveal(&state, &owner, "acme", &c.two), "value-two");
}

// ---------------------------------------------------------------------------
// The orphan rows' digests, and a name collision
// ---------------------------------------------------------------------------

#[test]
fn two_sealed_nodes_with_the_same_entry_name_both_keep_a_row_and_restore_independently() {
    let (env, state) = created();
    let owner = login(&state);
    create_node(&state, &owner, "alpha", GLOBAL_ID);
    create_node(&state, &owner, "beta", GLOBAL_ID);
    let a = create_entry(&state, &owner, "alpha", "API_KEY", "alpha-value");
    let b = create_entry(&state, &owner, "beta", "API_KEY", "beta-value");
    seal(&state, &owner, "alpha", NOW).unwrap();
    seal(&state, &owner, "beta", NOW + 1).unwrap();

    {
        let manifests = state.manifests.read().unwrap();
        let names: Vec<&str> = manifests[ORPHAN_ID]
            .entries
            .iter()
            .map(|e| e.name.as_str())
            .collect();
        assert_eq!(names.len(), 2);
        assert!(
            names.contains(&"API_KEY") && names.contains(&"API_KEY (beta)"),
            "{names:?}"
        );
    }
    assert_eq!(
        state.orphan_digest_mismatches().unwrap(),
        Vec::<String>::new()
    );
    // The digest in each row is the digest of that row's envelope file.
    for entry in [&a, &b] {
        let bytes = std::fs::read(env.paths().entry_env(ORPHAN_ID, entry)).unwrap();
        let row = state.manifests.read().unwrap()[ORPHAN_ID]
            .entries
            .iter()
            .find(|e| &e.id == entry)
            .unwrap()
            .clone();
        assert_eq!(row.sha256, sha256_hex(&bytes));
    }

    // Restoring alpha leaves beta's seal — and its orphan row — alone.
    let (state, owner) = restart(&env, state);
    restore(&state, &owner, "alpha", NOW + DAY).unwrap();
    assert_eq!(reveal(&state, &owner, "alpha", &a), "alpha-value");
    let rows: Vec<String> = state.manifests.read().unwrap()[ORPHAN_ID]
        .entries
        .iter()
        .map(|e| e.id.clone())
        .collect();
    assert_eq!(rows, vec![b.clone()]);
    assert!(registry_doc(&env).sealed.contains_key("beta"));
    restore(&state, &owner, "beta", NOW + DAY).unwrap();
    assert_eq!(reveal(&state, &owner, "beta", &b), "beta-value");
}

/// `node.seal` and `node.restore` are no longer in the generic write-through
/// list: the registry write inside the op is their commit point (a second,
/// generic persist after it would prove nothing).
#[test]
fn seal_and_restore_commit_inside_the_op_not_through_the_generic_write_through() {
    assert!(!ops::PERSISTED_OPS.contains(&"node.seal"));
    assert!(!ops::PERSISTED_OPS.contains(&"node.restore"));
}

/// ADR-069 meets ADR-079: a node's locked-write tray travels with its directory
/// into the archive, and comes back with it — rebuilt at restore, because the
/// load that happened while the node was sealed had no manifest to scan it against.
#[test]
fn a_locked_write_waiting_in_a_sealed_nodes_tray_is_back_after_the_restore() {
    let (env, state) = created();
    let owner = login(&state);
    let (one, _) = acme_with_two_entries(&state, &owner);
    call(&state, &owner, NOW, "vault.lock", json!({})).unwrap();
    let deposited = call(
        &state,
        &BrokerScope {
            node_id: "acme".to_string(),
            capabilities: vec![Capability::Create, Capability::List],
            origin: Origin::HumanUi,
            token_id: None,
            bound_workdir: None,
        },
        NOW,
        "entry.create",
        json!({ "node": "acme", "name": "WHILE_LOCKED", "value": "tray-value" }),
    )
    .expect("a locked create goes to the tray");
    assert_eq!(deposited["pending"], true, "{deposited}");
    let pending_entry = deposited["entry"].as_str().unwrap().to_string();
    let owner = login(&state);
    seal(&state, &owner, "acme", NOW).unwrap();
    assert!(env
        .paths()
        .archive_dir("acme")
        .join("node/pending")
        .join(format!("{pending_entry}.env"))
        .exists());

    let (state, owner) = restart(&env, state);
    restore(&state, &owner, "acme", NOW + DAY).unwrap();
    let tray = call(
        &state,
        &owner,
        NOW,
        "vault.pending_list",
        json!({ "node": "acme" }),
    )
    .unwrap();
    let items = tray["pending"].as_array().unwrap();
    assert_eq!(items.len(), 1, "{tray}");
    assert_eq!(items[0]["name"], "WHILE_LOCKED");
    call(
        &state,
        &owner,
        NOW,
        "vault.pending_accept",
        json!({ "node": "acme", "entry": pending_entry }),
    )
    .expect("and it can still be accepted");
    assert_eq!(reveal(&state, &owner, "acme", &pending_entry), "tray-value");
    assert_eq!(reveal(&state, &owner, "acme", &one), "value-one");
}

/// A registry that authenticates but whose seal records contradict it is a
/// corrupt vault, refused whole: a record under one id holding another, a node
/// both live and sealed, an id that is not a safe file name.
#[test]
fn a_seal_record_that_contradicts_the_registry_is_refused_at_unlock() {
    for (what, edit) in [
        (
            "a record under one id that holds another",
            Box::new(|v: &mut Value| {
                let rec = v["sealed"]["acme"].clone();
                let mut wrong = rec;
                wrong["id"] = json!("someone-else");
                v["sealed"]["acme"] = wrong;
            }) as Box<dyn Fn(&mut Value)>,
        ),
        (
            "a node that is both live and sealed",
            Box::new(|v: &mut Value| {
                let rec = v["sealed"]["acme"].clone();
                v["nodes"]["acme"] = rec;
            }),
        ),
        (
            "an id that is not a safe file name",
            Box::new(|v: &mut Value| {
                let mut rec = v["sealed"]["acme"].clone();
                rec["id"] = json!("../x");
                v["sealed"].as_object_mut().unwrap().remove("acme");
                v["sealed"]["../x"] = rec;
            }),
        ),
        (
            "a record version this build does not know",
            Box::new(|v: &mut Value| {
                v["sealed"]["acme"]["v"] = json!(2);
            }),
        ),
    ] {
        let (env, state) = created();
        let owner = login(&state);
        acme_with_two_entries(&state, &owner);
        seal(&state, &owner, "acme", NOW).unwrap();
        drop(state);
        rewrite_registry(&env, |v| edit(v));
        let state = env.broker();
        let err = try_login(&state).unwrap_err();
        assert!(
            matches!(&err, OpError::Internal(m) if m.contains("not self-consistent")),
            "{what}: {err:?}"
        );
    }
}

/// A fixture that "seeds" the orphan's key (the in-memory suites do) gets the
/// public key `node.seal` needs and nothing more: the private half is never
/// wrapped, never in the hot set — the custody rule holds by construction.
#[test]
fn seeding_the_orphan_in_a_fixture_registers_only_its_public_key() {
    use credmgr_core::registry::{Node, Registry};
    let dir = tempfile::tempdir().unwrap();
    let keystore = SoftwareKeystore::new(
        SecretBox::new(Box::new(PASSPHRASE.to_string())),
        dir.path().join("ks"),
    );
    let state = BrokerState::new(
        Box::new(keystore),
        VaultPaths::new(dir.path().join("vault")),
    );
    let root = SecretBox::new(Box::new([7u8; 32]));
    state.seed_root_key(&root);
    let mut registry = Registry::new();
    registry.nodes.insert(GLOBAL_ID.to_string(), Node::global());
    registry.nodes.insert(ORPHAN_ID.to_string(), Node::orphan());
    state.set_registry(registry);
    state.seed_node_key(&root, GLOBAL_ID);
    let orphan_public = state.seed_node_key(&root, ORPHAN_ID);
    assert_eq!(state.node_public_key(ORPHAN_ID), Some(orphan_public));

    state.unlock(0).expect("unlock");
    let hot = state.hot_key_node_ids_for_test();
    assert!(hot.contains(&GLOBAL_ID.to_string()));
    assert!(!hot.contains(&ORPHAN_ID.to_string()), "{hot:?}");
    assert!(state.hot_node_key(ORPHAN_ID).is_none());
}

// ---------------------------------------------------------------------------
// C1 — the commit protocol is isolated from a concurrent write-through.
//
// Seal changes memory (the node leaves the registry, its manifest and key are
// taken, the orphan gets rows) and only then commits the registry that names the
// seal record. Another client's write-through used to be free to persist the
// *memory* in between — writing a registry with the node gone and no seal record —
// so a crash right there left a vault that would not unlock. The persist lock is
// now held from the first memory change to the end of the commit.
// ---------------------------------------------------------------------------

/// Park a seal/restore at `at`, race a write-through against it, and return what
/// the racing write-through did while parked (`true` = it got to finish).
fn race_a_write_through_against(
    state: &Arc<BrokerState>,
    owner: &BrokerScope,
    at: SealPause,
    node: &str,
    restoring: bool,
) -> (bool, Result<Value, OpError>) {
    use std::sync::mpsc;
    use std::time::Duration;
    let (reached, go) = state.set_seal_pause_for_test(at);
    let worker = {
        let (s, o, n) = (Arc::clone(state), owner.clone(), node.to_string());
        std::thread::spawn(move || {
            if restoring {
                restore(&s, &o, &n, NOW + 10)
            } else {
                seal(&s, &o, &n, NOW + 10)
            }
        })
    };
    reached
        .recv_timeout(Duration::from_secs(30))
        .expect("the seal/restore reached its pause");
    let (done_tx, done_rx) = mpsc::channel();
    let writer = {
        let s = Arc::clone(state);
        std::thread::spawn(move || {
            let r = s.persist(NOW + 11);
            let _ = done_tx.send(());
            r
        })
    };
    // While the seal/restore is parked inside its window, the write-through must wait.
    let finished_inside_the_window = done_rx.recv_timeout(Duration::from_millis(700)).is_ok();
    go.send(()).expect("release the parked seal/restore");
    let outcome = worker.join().expect("seal/restore thread");
    writer
        .join()
        .expect("write-through thread")
        .expect("the write-through succeeds once the window is closed");
    (finished_inside_the_window, outcome)
}

#[test]
fn a_write_through_cannot_slip_into_a_seals_window_and_the_vault_stays_whole() {
    let (env, state) = created();
    let owner = login(&state);
    create_node(&state, &owner, "acme", GLOBAL_ID);
    let entry = create_entry(&state, &owner, "acme", "TOKEN", "alpha-value");

    let (slipped, outcome) =
        race_a_write_through_against(&state, &owner, SealPause::SealBeforeCommit, "acme", false);
    assert!(
        !slipped,
        "a write-through ran to completion inside the seal's window (memory half-changed, \
         nothing committed): a crash there would leave the node gone and no seal record"
    );
    outcome.expect("the seal succeeds");

    // On disk the seal is whole: the record is in the registry, the node is not live.
    let doc = registry_doc(&env);
    assert!(
        doc.sealed.contains_key("acme"),
        "the seal record is committed"
    );
    assert!(
        !doc.nodes.contains_key("acme"),
        "the node left the live registry"
    );

    // And a daemon that starts from that disk restores it byte for byte.
    let (state, owner) = restart(&env, state);
    restore(&state, &owner, "acme", NOW + 20).expect("restore after the race");
    assert_eq!(reveal(&state, &owner, "acme", &entry), "alpha-value");
    assert_verify_ok(&state, &owner);
}

#[test]
fn a_write_through_cannot_slip_into_a_restores_window_either() {
    let (env, state) = created();
    let owner = login(&state);
    create_node(&state, &owner, "acme", GLOBAL_ID);
    let entry = create_entry(&state, &owner, "acme", "TOKEN", "beta-value");
    seal(&state, &owner, "acme", NOW + 1).expect("seal first");

    let (slipped, outcome) =
        race_a_write_through_against(&state, &owner, SealPause::RestoreBeforeCommit, "acme", true);
    assert!(
        !slipped,
        "a write-through ran to completion inside the restore's window (node back in memory, \
         registry still sealed): a crash there would leave a vault that will not unlock"
    );
    outcome.expect("the restore succeeds");

    let doc = registry_doc(&env);
    assert!(
        doc.nodes.contains_key("acme"),
        "the node is live again on disk"
    );
    assert!(!doc.sealed.contains_key("acme"), "the seal record is gone");

    let (state, owner) = restart(&env, state);
    assert_eq!(reveal(&state, &owner, "acme", &entry), "beta-value");
    assert_verify_ok(&state, &owner);
}

// ---------------------------------------------------------------------------
// C1 / ADR-080 — `graph.snapshot` lists the sealed nodes to a human who may restore
// ---------------------------------------------------------------------------

fn snapshot_meta(state: &BrokerState, scope: &BrokerScope) -> Value {
    call(state, scope, NOW + 5, "graph.snapshot", json!({})).expect("graph.snapshot")["meta"]
        .clone()
}

#[test]
fn the_snapshot_lists_sealed_nodes_to_the_owner_across_a_restart_and_not_to_an_agent() {
    let (env, state) = created();
    let owner = login(&state);
    assert_eq!(
        snapshot_meta(&state, &owner)["sealed"],
        json!([]),
        "nothing sealed yet: an empty list, not a missing key"
    );
    create_node(&state, &owner, "acme", GLOBAL_ID);
    create_entry(&state, &owner, "acme", "TOKEN", "gamma-value");
    seal(&state, &owner, "acme", NOW + 1).expect("seal");

    let sealed = snapshot_meta(&state, &owner)["sealed"].clone();
    assert_eq!(sealed.as_array().unwrap().len(), 1);
    assert_eq!(sealed[0]["id"], "acme");
    assert_eq!(sealed[0]["label"], "acme");
    assert_eq!(sealed[0]["sealedAt"], json!(NOW + 1));
    assert_eq!(sealed[0]["expiresAt"], json!(NOW + 1 + 7 * DAY));
    let keys: Vec<&str> = sealed[0]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys.len(),
        4,
        "id, label, sealedAt, expiresAt — nothing else: {keys:?}"
    );

    // An agent holding `list` gets the response it always got: no `sealed` key.
    assert!(
        snapshot_meta(&state, &anyone()).get("sealed").is_none(),
        "the sealed list is for a human who may restore"
    );

    // Still listed after a restart (the registry is the source, not the session) …
    let (state, owner) = restart(&env, state);
    assert_eq!(snapshot_meta(&state, &owner)["sealed"][0]["id"], "acme");
    // … and gone once restored.
    restore(&state, &owner, "acme", NOW + 20).expect("restore");
    assert_eq!(snapshot_meta(&state, &owner)["sealed"], json!([]));
}

// ---------------------------------------------------------------------------
// 4.11 / ADR-089 — isolation from a concurrent registry write, and the purge of
// expired seals (K-7 WP6)
// ---------------------------------------------------------------------------

/// Park a seal/restore at `at`, run `racer` on another thread while it is parked,
/// say whether `racer` finished while parked, then release and return both results.
fn race<R: Send + 'static>(
    state: &Arc<BrokerState>,
    owner: &BrokerScope,
    at: SealPause,
    node: &str,
    restoring: bool,
    // `true` when the racer is expected to get through (give it time under load);
    // `false` when it is expected to wait (a short look is enough to catch a leak).
    expect_finish: bool,
    racer: impl FnOnce(Arc<BrokerState>, BrokerScope) -> R + Send + 'static,
) -> (bool, Result<Value, OpError>, R) {
    use std::time::Duration;
    let (reached, go) = state.set_seal_pause_for_test(at);
    let worker = {
        let (s, o, n) = (Arc::clone(state), owner.clone(), node.to_string());
        std::thread::spawn(move || {
            if restoring {
                restore(&s, &o, &n, NOW + 10)
            } else {
                seal(&s, &o, &n, NOW + 10)
            }
        })
    };
    reached
        .recv_timeout(Duration::from_secs(30))
        .expect("the seal/restore reached its pause");
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let racing = {
        let (s, o) = (Arc::clone(state), owner.clone());
        std::thread::spawn(move || {
            let r = racer(s, o);
            let _ = done_tx.send(());
            r
        })
    };
    let patience = if expect_finish { 30_000 } else { 700 };
    let finished_while_parked = done_rx
        .recv_timeout(Duration::from_millis(patience))
        .is_ok();
    go.send(()).expect("release the parked seal/restore");
    let outcome = worker.join().expect("seal/restore thread");
    let raced = racing.join().expect("racing thread");
    (finished_while_parked, outcome, raced)
}

#[test]
fn a_child_created_between_the_sub_node_check_and_the_seals_lock_is_found_and_nothing_is_committed()
{
    let (env, state) = created();
    let owner = login(&state);
    let (one, _two) = acme_with_two_entries(&state, &owner);

    let (finished, sealed, created_kid) = race(
        &state,
        &owner,
        SealPause::SealBeforeLock,
        "acme",
        false,
        true,
        |s, o| {
            call(
                &s,
                &o,
                NOW + 11,
                "node.create",
                json!({ "id": "kid", "label": "kid", "parentId": "acme" }),
            )
        },
    );
    assert!(
        finished,
        "the persist lock is not held yet, so the child is created"
    );
    created_kid.expect("node.create under the parent");
    // The seal notices on re-check and refuses; it does not commit a registry whose
    // `kid` has a parent that is no longer there.
    let refused = sealed.expect_err("the seal must refuse");
    assert!(
        matches!(&refused, OpError::Malformed(m) if m.contains("sub-nodes") && m.contains("kid")),
        "{refused:?}"
    );
    let doc = registry_doc(&env);
    assert!(doc.sealed.is_empty(), "no seal record was committed");
    assert!(doc.nodes.contains_key("acme") && doc.nodes.contains_key("kid"));
    assert!(
        !env.paths().entry_env(ORPHAN_ID, &one).exists(),
        "the seal's orphan copies were removed"
    );

    // A daemon that starts from that disk opens it, and the tree can be sealed bottom-up.
    let (state, owner) = restart(&env, state);
    assert_verify_ok(&state, &owner);
    seal(&state, &owner, "kid", NOW + 20).expect("seal the child");
    seal(&state, &owner, "acme", NOW + 21).expect("then the parent");
}

#[test]
fn node_create_waits_for_a_seals_window_and_then_finds_its_parent_gone() {
    let (env, state) = created();
    let owner = login(&state);
    acme_with_two_entries(&state, &owner);
    let (finished, sealed, created_kid) = race(
        &state,
        &owner,
        SealPause::SealBeforeCommit,
        "acme",
        false,
        false,
        |s, o| {
            call(
                &s,
                &o,
                NOW + 11,
                "node.create",
                json!({ "id": "kid", "label": "kid", "parentId": "acme" }),
            )
        },
    );
    assert!(!finished, "node.create ran inside the seal's window");
    sealed.expect("the seal commits");
    assert!(
        matches!(created_kid, Err(OpError::NotFound(_))),
        "{created_kid:?}"
    );
    let (state, owner) = restart(&env, state);
    assert_verify_ok(&state, &owner);
    assert!(!state.registry.read().unwrap().nodes.contains_key("kid"));
    let _ = owner;
}

#[test]
fn a_directory_claimed_between_a_restores_checks_and_its_lock_is_dropped_not_committed() {
    let (env, state) = created();
    let owner = login(&state);
    let work = tempfile::tempdir().unwrap();
    let work_path = std::fs::canonicalize(work.path())
        .unwrap()
        .to_string_lossy()
        .into_owned();
    call(
        &state,
        &owner,
        NOW,
        "node.create",
        json!({ "id": "acme", "label": "acme", "parentId": GLOBAL_ID, "workdirs": [work_path] }),
    )
    .unwrap();
    create_node(&state, &owner, "other", GLOBAL_ID);
    let entry = create_entry(&state, &owner, "acme", "TOKEN", "alpha-value");
    seal(&state, &owner, "acme", NOW).unwrap();

    let claim = work_path.clone();
    let (finished, restored, claimed) = race(
        &state,
        &owner,
        SealPause::RestoreBeforeLock,
        "acme",
        true,
        true,
        move |s, o| {
            call(
                &s,
                &o,
                NOW + 11,
                "node.set_workdirs",
                json!({ "node": "other", "workdirs": [claim] }),
            )
        },
    );
    assert!(
        finished,
        "the restore holds no lock at that point, so the claim goes through"
    );
    claimed.expect("the claim");
    // The restore re-checks under its lock: the directory is now another node's, so
    // it is dropped and reported — not committed twice.
    let restored = restored.expect("the restore succeeds");
    assert_eq!(
        restored["workdirsDropped"],
        json!([work_path]),
        "{restored}"
    );
    let (state, owner) = restart(&env, state);
    assert_verify_ok(&state, &owner);
    assert_eq!(
        state.registry.read().unwrap().nodes["acme"].workdirs,
        Vec::<String>::new()
    );
    assert_eq!(
        state.registry.read().unwrap().nodes["other"].workdirs,
        vec![work_path]
    );
    assert_eq!(reveal(&state, &owner, "acme", &entry), "alpha-value");
}

#[test]
fn node_set_workdirs_waits_for_a_restores_window_and_is_then_refused_as_a_duplicate() {
    let (env, state) = created();
    let owner = login(&state);
    let work = tempfile::tempdir().unwrap();
    let work_path = std::fs::canonicalize(work.path())
        .unwrap()
        .to_string_lossy()
        .into_owned();
    call(
        &state,
        &owner,
        NOW,
        "node.create",
        json!({ "id": "acme", "label": "acme", "parentId": GLOBAL_ID, "workdirs": [work_path] }),
    )
    .unwrap();
    create_node(&state, &owner, "other", GLOBAL_ID);
    seal(&state, &owner, "acme", NOW).unwrap();

    let claim = work_path.clone();
    let (finished, restored, claimed) = race(
        &state,
        &owner,
        SealPause::RestoreBeforeCommit,
        "acme",
        true,
        false,
        move |s, o| {
            call(
                &s,
                &o,
                NOW + 11,
                "node.set_workdirs",
                json!({ "node": "other", "workdirs": [claim] }),
            )
        },
    );
    assert!(
        !finished,
        "node.set_workdirs ran inside the restore's window"
    );
    let restored = restored.expect("restore");
    assert!(
        restored
            .get("workdirsDropped")
            .map_or(true, |d| d == &json!([])),
        "the restore saw the directory free: {restored}"
    );
    assert!(matches!(claimed, Err(OpError::Malformed(_))), "{claimed:?}");
    let (state, owner) = restart(&env, state);
    assert_verify_ok(&state, &owner);
    let _ = owner;
    assert_eq!(
        state.registry.read().unwrap().nodes["acme"].workdirs,
        vec![work_path]
    );
}

fn doctor(
    state: &BrokerState,
    owner: &BrokerScope,
    now: i64,
    params: Value,
) -> Result<Value, OpError> {
    call(state, owner, now, "maintenance.doctor", params)
}

fn purged_ids(report: &Value, kind: &str) -> Vec<String> {
    report["fixes"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["type"] == kind)
        .map(|f| f["node"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn a_seal_is_purged_only_after_its_seven_days_and_only_when_asked() {
    let (env, state) = created();
    let owner = login(&state);
    let (one, _two) = acme_with_two_entries(&state, &owner);
    seal(&state, &owner, "acme", NOW).unwrap();
    let paths = env.paths();

    // Inside the window: nothing to purge, even when asked.
    let r = doctor(
        &state,
        &owner,
        NOW + 6 * DAY,
        json!({ "purgeExpiredSeals": true }),
    )
    .unwrap();
    assert!(purged_ids(&r, "purged-expired-seal").is_empty(), "{r}");
    assert!(registry_doc(&env).sealed.contains_key("acme"));

    // Past it, a plain doctor run purges nothing …
    let r = doctor(&state, &owner, NOW + 8 * DAY, json!({})).unwrap();
    assert!(purged_ids(&r, "purged-expired-seal").is_empty(), "{r}");
    assert!(paths.archive_dir("acme").exists());
    // … and a dry run only says what it would do.
    let r = doctor(
        &state,
        &owner,
        NOW + 8 * DAY,
        json!({ "apply": false, "purgeExpiredSeals": true }),
    )
    .unwrap();
    assert_eq!(
        purged_ids(&r, "would-purge-expired-seal"),
        vec!["acme"],
        "{r}"
    );
    assert!(paths.archive_dir("acme").exists() && registry_doc(&env).sealed.contains_key("acme"));
    // A non-boolean flag is refused, not guessed at.
    assert!(matches!(
        doctor(
            &state,
            &owner,
            NOW + 8 * DAY,
            json!({ "purgeExpiredSeals": "yes" })
        ),
        Err(OpError::Malformed(_))
    ));

    // Asked for, on day 8: the originals and the way back are gone.
    let r = doctor(
        &state,
        &owner,
        NOW + 8 * DAY,
        json!({ "purgeExpiredSeals": true }),
    )
    .unwrap();
    assert_eq!(purged_ids(&r, "purged-expired-seal"), vec!["acme"], "{r}");
    assert_eq!(r["fixes"][0]["archiveRemoved"], true);
    assert!(
        !paths.archive_dir("acme").exists(),
        "archive/acme is destroyed"
    );
    assert!(
        !registry_doc(&env).sealed.contains_key("acme"),
        "the seal record is forgotten"
    );
    // What the node held is still orphaned data — only the live node cannot come back.
    assert!(
        paths.entry_env(ORPHAN_ID, &one).exists(),
        "the orphan copy stays"
    );
    let again = restore(&state, &owner, "acme", NOW + 8 * DAY);
    assert!(matches!(again, Err(OpError::NotFound(_))), "{again:?}");
    // A second run finds nothing; the id is free; a restart opens the vault and it verifies.
    let r = doctor(
        &state,
        &owner,
        NOW + 9 * DAY,
        json!({ "purgeExpiredSeals": true }),
    )
    .unwrap();
    assert!(purged_ids(&r, "purged-expired-seal").is_empty());
    create_node(&state, &owner, "acme", GLOBAL_ID);
    let (state, owner) = restart(&env, state);
    assert_verify_ok(&state, &owner);
    // The purge is in the audit log.
    let feed = call(&state, &owner, NOW, "audit.tail", json!({ "limit": 500 }))
        .unwrap()
        .to_string();
    assert!(feed.contains("maintenance.purge_seal"), "{feed}");
}

#[test]
fn only_the_expired_seal_is_purged_and_a_locked_vault_or_a_non_admin_cannot() {
    let (env, state) = created();
    let owner = login(&state);
    create_node(&state, &owner, "old", GLOBAL_ID);
    create_node(&state, &owner, "young", GLOBAL_ID);
    create_entry(&state, &owner, "old", "A", "a");
    create_entry(&state, &owner, "young", "B", "b");
    seal(&state, &owner, "old", NOW).unwrap();
    seal(&state, &owner, "young", NOW + 5 * DAY).unwrap();

    // An agent never holds Admin.
    let agent = anyone();
    let r = doctor(
        &state,
        &agent,
        NOW + 8 * DAY,
        json!({ "purgeExpiredSeals": true }),
    );
    assert!(matches!(r, Err(OpError::CapabilityNotHeld { .. })), "{r:?}");

    let r = doctor(
        &state,
        &owner,
        NOW + 8 * DAY,
        json!({ "purgeExpiredSeals": true }),
    )
    .unwrap();
    assert_eq!(purged_ids(&r, "purged-expired-seal"), vec!["old"]);
    let doc = registry_doc(&env);
    assert!(!doc.sealed.contains_key("old") && doc.sealed.contains_key("young"));
    restore(&state, &owner, "young", NOW + 8 * DAY).expect("the younger seal is still restorable");

    state.lock();
    let r = doctor(
        &state,
        &owner,
        NOW + 9 * DAY,
        json!({ "purgeExpiredSeals": true }),
    );
    assert!(r.is_err(), "a locked vault purges nothing: {r:?}");
}
