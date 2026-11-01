//! ADR-076 — `maintenance.rotate_root`: replacing the root key.
//!
//! What this file proves, and how:
//!
//! * **The rotation is real.** Every file that was signed or wrapped under the
//!   old root key is signed or wrapped under the new one — the passphrase and
//!   recovery wraps, every node key, the registry, every manifest, the
//!   rollback counter, the audit tips, the gate seed, the seal archives, the
//!   removed-entry records and the rotation snapshots — and *only* the new one
//!   opens them. Checked by opening each with each key, not by reading a flag.
//! * **Nothing is lost.** The vault reopens after a restart, every entry reads
//!   back, and the node keypairs (so every envelope) are unchanged.
//! * **A crash at any point leaves a vault that opens** — with the old root key
//!   if the commit record was never written, with the new one if it was. The
//!   sweep cuts a rotation off before the commit, right after it, and after
//!   every single file of the roll-forward, restarts a fresh broker each time,
//!   and unlocks with the passphrase. A control proves the sweep can fail: the
//!   half-applied states it recovers from open with *neither* key until
//!   recovery has run.
//! * **No key material is written in the clear.** The vault and state
//!   directories are scanned, byte-for-byte and as hex, for the old and new
//!   root keys, a node's private key, the passphrase and both recovery codes.
//! * **The wire is gated like the other presence-gated ops.** Human-only,
//!   `Admin` on global, the gate's second factor, then `presence_required` —
//!   and a refusal changes nothing on disk.
//!
//! The rotation logic is driven through `BrokerState::rotate_root` and
//! `ops::rotate_root_response` directly, because the wire answers
//! `presence_required` until a transport can attest presence (the
//! `maintenance.doctor --rebuild-registry` precedent).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use secrecy::{ExposeSecret, SecretBox};
use serde_json::{json, Value};

use credmgr_brokerd::ops;
use credmgr_brokerd::peer::PeerInfo;
use credmgr_brokerd::protocol::{OpError, Request};
use credmgr_brokerd::scope::BrokerScope;
use credmgr_brokerd::server;
use credmgr_brokerd::state::{
    BrokerState, RotateRootError, RotationFault, RotationOutcome, VaultLock,
};
use credmgr_core::access::Origin;
use credmgr_core::keys::{unwrap_node_key, WrappedNodeKey};
use credmgr_core::recovery::parse_recovery_code;
use credmgr_core::registry::{Capability, GLOBAL_ID, ORPHAN_ID};
use credmgr_core::totp::{decode_gate_secret_base32, Totp};
use credmgr_keystore::software::SoftwareKeystore;
use credmgr_keystore::{KeystoreId, PlatformKeystore, WrappedKey};
use credmgr_store::generation::{FileGenerationCounter, GenerationCounter, VAULT_GENERATION};
use credmgr_store::paths::VaultPaths;
use credmgr_store::{audit, manifest, registry_file};

const NOW: i64 = 1_800_000_000;
const PASSPHRASE: &str = "correct horse battery staple";

// ---------------------------------------------------------------------------
// Harness — the same shape `durable_vault.rs` uses: a real vault made by
// `vault.init_*` in a temporary directory, "restarted" by building a fresh
// `BrokerState` over the same vault and state directories.
// ---------------------------------------------------------------------------

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

    fn broker(&self) -> Arc<BrokerState> {
        let keystore = SoftwareKeystore::new(
            SecretBox::new(Box::default()),
            self.state_dir.join("placeholder-keystore"),
        );
        let state = Arc::new(BrokerState::new(Box::new(keystore), self.paths()));
        state.set_state_dir_for_test(self.state_dir.clone());
        state
    }

    /// A byte-for-byte copy in its own temporary directory — a vault no broker
    /// is running over.
    fn cloned(&self) -> Vault {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = dir.path().join("vault");
        let state_dir = dir.path().join("state");
        copy_dir_all(&self.vault_dir, &vault_dir);
        copy_dir_all(&self.state_dir, &state_dir);
        Vault {
            vault_dir,
            state_dir,
            root_recovery_code: self.root_recovery_code.clone(),
            _dir: dir,
        }
    }
}

fn copy_dir_all(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir_all(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).unwrap();
        }
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

/// Through the real request path, so the call is audited and the audit id comes
/// back. Uses the wall clock, as the daemon does.
fn via_server(
    state: &Arc<BrokerState>,
    token: &str,
    op: &str,
    params: Value,
) -> (Result<Value, OpError>, Option<String>) {
    server::handle_request(
        state,
        &peer(),
        &Request {
            id: "r".to_string(),
            op: op.to_string(),
            token: Some(token.to_string()),
            params,
        },
    )
}

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

fn unlock(state: &BrokerState, passphrase: &str, now: i64) -> Result<Value, OpError> {
    call(
        state,
        &anyone(),
        now,
        "vault.unlock",
        json!({ "passphrase": passphrase }),
    )
}

/// Unlock; the owner-session scope and the raw token for `via_server`.
fn login_with_token(state: &BrokerState) -> (BrokerScope, String) {
    let token = unlock(state, PASSPHRASE, NOW).expect("unlock")["token"]
        .as_str()
        .expect("a real login mints a token")
        .to_string();
    let registry = state.registry.read().unwrap().clone();
    let scope =
        credmgr_brokerd::scope::resolve_scope(&registry, &state.tokens, &peer(), Some(&token)).0;
    (scope, token)
}

fn login(state: &BrokerState) -> BrokerScope {
    login_with_token(state).0
}

fn passphrase() -> SecretBox<String> {
    SecretBox::new(Box::new(PASSPHRASE.to_string()))
}

fn create_node(state: &BrokerState, owner: &BrokerScope, id: &str) {
    call(
        state,
        owner,
        NOW,
        "node.create",
        json!({ "id": id, "label": id, "parentId": GLOBAL_ID }),
    )
    .expect("node.create");
}

/// Create an entry; returns `(entry id, generation)`.
fn create_entry(
    state: &BrokerState,
    owner: &BrokerScope,
    node: &str,
    name: &str,
    value: &str,
) -> (String, u64) {
    let created = call(
        state,
        owner,
        NOW,
        "entry.create",
        json!({ "node": node, "name": name, "value": value }),
    )
    .expect("entry.create");
    (
        created["entry"].as_str().unwrap().to_string(),
        created["generation"].as_u64().unwrap(),
    )
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

fn verify_ok(state: &BrokerState, owner: &BrokerScope) {
    let verified = call(state, owner, NOW, "maintenance.verify", json!({})).expect("verify");
    assert_eq!(verified["ok"], true, "maintenance.verify: {verified}");
}

/// The root key `root.wrap.pass` on disk right now yields for `PASSPHRASE`.
fn root_from_disk(vault: &Vault) -> [u8; 32] {
    let bytes = std::fs::read(vault.paths().root_wrap_pass()).unwrap();
    SoftwareKeystore::new(passphrase(), vault.state_dir.join("ks"))
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

/// Which parts of the vault do **not** open under `rk`. Empty means the whole
/// vault — registry, every manifest and its cross-binding, the rollback
/// counter, every node key, every audit month — opens with it.
fn failures_under(vault: &Vault, rk: &[u8; 32], nodes: &[&str]) -> Vec<String> {
    let paths = vault.paths();
    let mut failures = Vec::new();
    let doc = match registry_file::load(&paths, rk) {
        Ok(doc) => Some(doc),
        Err(e) => {
            failures.push(format!("registry: {e}"));
            None
        }
    };
    for node in nodes {
        match manifest::load(&paths, rk, node) {
            Ok(m) => {
                if let Some(doc) = &doc {
                    if let Err(e) = manifest::verify_cross_binding(doc, node, &m) {
                        failures.push(format!("binding {node}: {e}"));
                    }
                }
            }
            Err(e) => failures.push(format!("manifest {node}: {e}")),
        }
        let key_ok = std::fs::read(paths.node_key(node))
            .ok()
            .and_then(|b| WrappedNodeKey::from_bytes(&b).ok())
            .map(|w| unwrap_node_key(rk, node, &w).is_ok())
            .unwrap_or(false);
        if !key_ok {
            failures.push(format!("node key {node}"));
        }
    }
    match FileGenerationCounter::new(vault.state_dir.clone()).read(rk, VAULT_GENERATION) {
        Ok(Some(_)) => {}
        other => failures.push(format!("counter: {other:?}")),
    }
    for month in audit::year_months(&paths).unwrap() {
        if let Err(e) = audit::verify(&paths, rk, &month) {
            failures.push(format!("audit {month}: {e}"));
        }
    }
    failures
}

/// Every regular file under `dir`.
fn files_under(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            files_under(&path, out);
        } else {
            out.push(path);
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut out, b| {
        write!(out, "{b:02x}").expect("writing to a String cannot fail");
        out
    })
}

/// `bytes` without trailing newlines (`trim_ascii_end` is past the 1.78 MSRV).
fn trim_nl(bytes: &[u8]) -> &[u8] {
    let mut end = bytes.len();
    while end > 0 && (bytes[end - 1] == b'\n' || bytes[end - 1] == b'\r') {
        end -= 1;
    }
    &bytes[..end]
}

/// ADR-078: what `scripts/emergency-decrypt.mjs` prints for an entry written by
/// this build. An entry created through `entry.create` is a version-2 envelope
/// and the script prints its field document as JSON (lossless: every label and
/// value survives in its escapes); this returns the one field's value, so the
/// tests that mean "the stored secret came out" can still say so. An entry that
/// is not a one-field document is a failure here, not a different answer.
fn emergency_value(stdout: &[u8]) -> Vec<u8> {
    let doc: serde_json::Value = serde_json::from_slice(trim_nl(stdout))
        .expect("the script printed a version-2 field document (JSON)");
    let fields = doc["fields"].as_array().expect("a document has fields");
    assert_eq!(fields.len(), 1, "one entry created with one value");
    fields[0]["value"]
        .as_str()
        .expect("the field has a value")
        .as_bytes()
        .to_vec()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// Fails if any secret appears in any file of the vault or state directory,
/// raw, as lower- or upper-case hex, or (for strings) verbatim.
fn assert_nothing_in_the_clear(vault: &Vault, secrets: &[(&str, Vec<u8>)]) {
    let mut files = Vec::new();
    files_under(&vault.vault_dir, &mut files);
    files_under(&vault.state_dir, &mut files);
    assert!(!files.is_empty());
    for file in files {
        let bytes = std::fs::read(&file).unwrap();
        for (label, secret) in secrets {
            for form in [
                secret.clone(),
                hex(secret).into_bytes(),
                hex(secret).to_uppercase().into_bytes(),
            ] {
                assert!(
                    !contains(&bytes, &form),
                    "{label} appears in the clear in {}",
                    file.display()
                );
            }
        }
    }
}

/// A fully populated vault, restarted-from-disk ready: two nodes, entries, one
/// updated entry, one removed entry, one rotated entry, and audit history from
/// the real request path. Returns the vault (no broker running over it) and the
/// ids the tests read back.
struct Populated {
    vault: Vault,
    entry_a: String,
    entry_b: String,
}

fn populated() -> Populated {
    let (vault, state) = created_vault();
    let (owner, token) = login_with_token(&state);
    create_node(&state, &owner, "acme");
    let (entry_a, _) = create_entry(&state, &owner, "acme", "DEPLOY_TOKEN", "alpha-secret");
    let (entry_b, gen_b) = create_entry(&state, &owner, "acme", "DB_PASSWORD", "bravo-secret");
    // History that is signed under the root key: a rotation snapshot…
    via_server(
        &state,
        &token,
        "entry.rotate",
        json!({ "node": "acme", "entry": entry_b, "value": "bravo-secret-2", "generation": gen_b }),
    )
    .0
    .expect("entry.rotate");
    // …and a removed-entry record.
    let (extra, _) = create_entry(&state, &owner, "acme", "TO_REMOVE", "charlie-secret");
    let generation = state.manifest_generation("acme").unwrap();
    via_server(
        &state,
        &token,
        "entry.remove",
        json!({ "node": "acme", "entry": extra, "generation": generation }),
    )
    .0
    .expect("entry.remove");
    // A few audited reads so the audit log and its tip exist.
    via_server(&state, &token, "entry.list", json!({ "node": "acme" }))
        .0
        .expect("entry.list");
    drop(state);
    Populated {
        vault,
        entry_a,
        entry_b,
    }
}

const NODES: [&str; 2] = [GLOBAL_ID, "acme"];

// ---------------------------------------------------------------------------
// The rotation
// ---------------------------------------------------------------------------

#[test]
fn a_rotation_moves_every_signed_and_wrapped_file_to_the_new_key_and_the_vault_reopens() {
    let p = populated();
    let vault = &p.vault;
    let old_rk = root_from_disk(vault);
    assert!(
        failures_under(vault, &old_rk, &NODES).is_empty(),
        "control: before the rotation the old key opens everything: {:?}",
        failures_under(vault, &old_rk, &NODES)
    );
    let old_pass_wrap = std::fs::read(vault.paths().root_wrap_pass()).unwrap();
    let old_recovery_wrap = std::fs::read(vault.paths().root_wrap_recovery()).unwrap();
    let old_acme_key = std::fs::read(vault.paths().node_key("acme")).unwrap();
    let doc_before = registry_file::load(&vault.paths(), &old_rk).unwrap();
    let months_before = audit::year_months(&vault.paths()).unwrap();
    assert!(
        !months_before.is_empty(),
        "the fixture produced audit history"
    );

    let state = vault.broker();
    let owner = login(&state);
    let acme_private_before = state.hot_key_bytes_for_test("acme").unwrap();

    let outcome = state
        .rotate_root(passphrase(), NOW + 10)
        .expect("the rotation");

    // The recovery code is new, well-formed, and not the old one.
    assert!(parse_recovery_code(&outcome.recovery_code).is_ok());
    assert_ne!(outcome.recovery_code, vault.root_recovery_code);
    assert_eq!(outcome.nodes_rewrapped, 2);
    assert!(outcome.files_replaced >= 10, "{outcome:?}");
    assert!(
        outcome.skipped.is_empty(),
        "nothing failed to verify, so nothing is left unsigned: {:?}",
        outcome.skipped
    );
    assert!(
        outcome.artifacts_resigned >= 3,
        "an audit tip, a rotation snapshot and a removed-entry record: {outcome:?}"
    );

    // Every file now opens under the NEW key — and under the old one, none of
    // the signed or wrapped ones do.
    let new_rk = root_from_disk(vault);
    assert_ne!(new_rk, old_rk);
    assert_eq!(
        failures_under(vault, &new_rk, &NODES),
        Vec::<String>::new(),
        "the new root key opens the whole vault"
    );
    let under_old = failures_under(vault, &old_rk, &NODES);
    for part in [
        "registry:",
        "manifest global",
        "manifest acme",
        "node key global",
        "node key acme",
        "counter:",
        "audit ",
    ] {
        assert!(
            under_old.iter().any(|f| f.starts_with(part)),
            "the old root key must no longer open {part}: {under_old:?}"
        );
    }

    // The wraps and the node key blobs are new bytes; the stage is gone.
    assert_ne!(
        std::fs::read(vault.paths().root_wrap_pass()).unwrap(),
        old_pass_wrap
    );
    assert_ne!(
        std::fs::read(vault.paths().root_wrap_recovery()).unwrap(),
        old_recovery_wrap
    );
    assert_ne!(
        std::fs::read(vault.paths().node_key("acme")).unwrap(),
        old_acme_key
    );
    assert!(!vault.paths().rotation_stage().exists());

    // A rotation re-wraps, it does not re-key: the same keypair, the same
    // public key in the registry, the same hot key in memory.
    let doc_after = registry_file::load(&vault.paths(), &new_rk).unwrap();
    for node in NODES {
        assert_eq!(
            doc_after.nodes[node].public_key, doc_before.nodes[node].public_key,
            "{node}'s public key must not change"
        );
    }
    assert_eq!(
        state.hot_key_bytes_for_test("acme").unwrap(),
        acme_private_before
    );
    let reopened = unwrap_node_key(
        &new_rk,
        "acme",
        &WrappedNodeKey::from_bytes(&std::fs::read(vault.paths().node_key("acme")).unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(reopened.to_bytes(), acme_private_before);
    assert!(
        doc_after.vault_generation > doc_before.vault_generation,
        "a rotation is a write: the generation moved forward"
    );

    // The running broker carries on under the new key: reads, a write that
    // persists under it, and a clean verify.
    assert_eq!(reveal(&state, &owner, "acme", &p.entry_a), "alpha-secret");
    assert_eq!(reveal(&state, &owner, "acme", &p.entry_b), "bravo-secret-2");
    let generation = state.manifest_generation("acme").unwrap();
    call(
        &state,
        &owner,
        NOW + 11,
        "entry.update",
        json!({ "node": "acme", "entry": p.entry_a, "value": "alpha-secret-2", "generation": generation }),
    )
    .expect("a write after the rotation");
    assert_eq!(
        failures_under(vault, &new_rk, &NODES),
        Vec::<String>::new(),
        "a write after the rotation is signed under the new key"
    );
    verify_ok(&state, &owner);
    drop(state);

    // The restart: a fresh broker, the same passphrase, nothing carried over.
    let state = vault.broker();
    let owner = login(&state);
    assert_eq!(reveal(&state, &owner, "acme", &p.entry_a), "alpha-secret-2");
    assert_eq!(reveal(&state, &owner, "acme", &p.entry_b), "bravo-secret-2");
    verify_ok(&state, &owner);

    // The old recovery code is dead; the new one is the last door.
    let old_code = call(
        &state,
        &anyone(),
        NOW,
        "vault.gate_recover",
        json!({ "passphrase": PASSPHRASE, "recoveryCode": vault.root_recovery_code }),
    );
    assert_eq!(old_code, Err(OpError::WrongPassphrase));
    let new_code = call(
        &state,
        &anyone(),
        NOW,
        "vault.gate_recover",
        json!({ "passphrase": PASSPHRASE, "recoveryCode": outcome.recovery_code }),
    )
    .expect("the new recovery code opens the new recovery wrap");
    assert_eq!(new_code["gateReset"], false, "no gate was in force");
}

#[test]
fn rotating_twice_works_and_each_rotation_retires_the_one_before() {
    let p = populated();
    let state = p.vault.broker();
    let owner = login(&state);
    let first = state.rotate_root(passphrase(), NOW + 1).unwrap();
    let rk1 = root_from_disk(&p.vault);
    let second = state.rotate_root(passphrase(), NOW + 2).unwrap();
    let rk2 = root_from_disk(&p.vault);
    assert_ne!(rk1, rk2);
    assert_ne!(first.recovery_code, second.recovery_code);
    assert!(failures_under(&p.vault, &rk2, &NODES).is_empty());
    assert!(!failures_under(&p.vault, &rk1, &NODES).is_empty());
    assert_eq!(reveal(&state, &owner, "acme", &p.entry_a), "alpha-secret");
}

#[test]
fn no_key_material_is_written_in_the_clear() {
    let p = populated();
    let vault = &p.vault;
    let old_rk = root_from_disk(vault);
    let state = vault.broker();
    login(&state);
    let node_private = state.hot_key_bytes_for_test("acme").unwrap();
    let global_private = state.hot_key_bytes_for_test(GLOBAL_ID).unwrap();

    let outcome = state.rotate_root(passphrase(), NOW + 1).unwrap();
    let new_rk = root_from_disk(vault);

    let plain_code = outcome.recovery_code.replace('-', "");
    let old_plain_code = vault.root_recovery_code.replace('-', "");
    let secrets: Vec<(&str, Vec<u8>)> = vec![
        ("the old root key", old_rk.to_vec()),
        ("the new root key", new_rk.to_vec()),
        ("acme's private key", node_private.to_vec()),
        ("global's private key", global_private.to_vec()),
        ("the passphrase", PASSPHRASE.as_bytes().to_vec()),
        (
            "the new recovery code (grouped)",
            outcome.recovery_code.clone().into_bytes(),
        ),
        (
            "the new recovery code (plain)",
            plain_code.clone().into_bytes(),
        ),
        (
            "the new recovery code (lower)",
            plain_code.to_lowercase().into_bytes(),
        ),
        ("the old recovery code (plain)", old_plain_code.into_bytes()),
    ];
    assert_nothing_in_the_clear(vault, &secrets);

    // The Debug form of the outcome — the thing a log line would print — hides the code.
    let rendered = format!("{outcome:?}");
    assert!(!rendered.contains(&plain_code) && !rendered.contains(&outcome.recovery_code));
    assert!(rendered.contains("<redacted>"));

    // …and still nothing after a restart and a write.
    drop(state);
    let state = vault.broker();
    let owner = login(&state);
    create_entry(&state, &owner, "acme", "AFTER", "delta-secret");
    assert_nothing_in_the_clear(vault, &secrets);
}

#[test]
fn a_wrong_passphrase_a_locked_vault_and_an_in_memory_vault_each_change_nothing() {
    let p = populated();
    let vault = &p.vault;
    let state = vault.broker();

    // Locked.
    assert!(matches!(
        state.rotate_root(passphrase(), NOW),
        Err(RotateRootError::NotDurable)
    ));
    let owner = login(&state);
    let snapshot = |v: &Vault| -> Vec<(PathBuf, Vec<u8>)> {
        let mut files = Vec::new();
        files_under(&v.vault_dir, &mut files);
        files_under(&v.state_dir, &mut files);
        files.sort();
        files
            .into_iter()
            .map(|f| {
                let bytes = std::fs::read(&f).unwrap();
                (f, bytes)
            })
            .collect()
    };
    let before = snapshot(vault);

    assert!(matches!(
        state.rotate_root(
            SecretBox::new(Box::new("not the passphrase".to_string())),
            NOW
        ),
        Err(RotateRootError::WrongPassphrase)
    ));
    assert_eq!(
        snapshot(vault),
        before,
        "a refused rotation changes no byte on disk"
    );
    assert_eq!(reveal(&state, &owner, "acme", &p.entry_a), "alpha-secret");

    call(&state, &owner, NOW, "vault.lock", json!({})).unwrap();
    assert!(matches!(
        state.rotate_root(passphrase(), NOW),
        Err(RotateRootError::Locked)
    ));
    assert_eq!(snapshot(vault), before);
}

/// The claim, stated at the size it holds: a tampered audit month the rotation
/// does not write to is left unsigned and **keeps failing verification**. The
/// fixture's history lives in the wall-clock month and the rotation runs at
/// `NOW + 1` (2027-01), so the month tampered with here is a *past* month from
/// the rotation's point of view — nothing is appended to it. (The original
/// version of this test passed for exactly that accidental reason and claimed
/// more; the next test is the case it left out.)
#[test]
fn a_tampered_audit_month_is_left_unsigned_so_it_keeps_failing_verification() {
    let p = populated();
    let vault = &p.vault;
    let month = audit::year_months(&vault.paths()).unwrap()[0].clone();
    assert_ne!(
        audit::year_month_for(NOW + 1),
        month,
        "premise: the rotation's own audit record lands in a different month, so this one is a past month"
    );
    // Truncate the last line of the month: the tip no longer agrees with the log.
    let log = vault.paths().audit_log(&month);
    let text = std::fs::read_to_string(&log).unwrap();
    let mut lines: Vec<&str> = text.lines().collect();
    assert!(lines.len() >= 2, "need a log with something to truncate");
    lines.pop();
    std::fs::write(&log, format!("{}\n", lines.join("\n"))).unwrap();
    let old_rk = root_from_disk(vault);
    assert!(audit::verify(&vault.paths(), &old_rk, &month).is_err());

    let state = vault.broker();
    login(&state);
    let outcome = state.rotate_root(passphrase(), NOW + 1).expect("rotates");
    let new_rk = root_from_disk(vault);

    assert!(
        outcome
            .skipped
            .iter()
            .any(|s| s.kind == "audit-tip" && s.id == month),
        "the tampered month is reported, not silently re-signed: {:?}",
        outcome.skipped
    );
    assert!(
        audit::verify(&vault.paths(), &new_rk, &month).is_err(),
        "re-signing a truncated log would have stamped the truncation authentic"
    );
    let reported = outcome
        .skipped
        .iter()
        .find(|s| s.kind == "audit-tip" && s.id == month)
        .unwrap();
    assert!(
        !reported.reason.contains("rotation's own audit record"),
        "a past month keeps failing — no caveat: {}",
        reported.reason
    );
    // Everything else opened with the new key.
    let rest: Vec<String> = failures_under(vault, &new_rk, &NODES)
        .into_iter()
        .filter(|f| !f.starts_with(&format!("audit {month}")))
        .collect();
    assert!(rest.is_empty(), "{rest:?}");
}

/// The case the test above does not reach, and the review's P3: the tampered
/// month is the one the rotation's own audit record is written to. The rotation
/// still refuses to re-sign it — but `audit::append` signs a month's tip over
/// whatever lines the log holds, for every request, so the record the rotation
/// then appends makes the truncated month verify again under the new key.
///
/// That is `audit::append`'s existing behaviour, not something a rotation can
/// undo, and the claim was wrong to say otherwise. So the rotation says so in
/// the one place the operator reads — the `reason` of the `notResigned` entry —
/// and this test pins both halves: the report is honest, and the weakness is as
/// described. If `audit::append` is ever changed to refuse to re-sign a month
/// that does not verify, the last assertion flips, and `CURRENT_MONTH_CAVEAT`
/// and the ADR's wording must go with it.
#[test]
fn a_tampered_current_audit_month_is_reported_with_the_caveat_that_the_next_record_signs_it() {
    let p = populated();
    let vault = &p.vault;
    let wall_now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let month = audit::year_month_for(wall_now);
    assert_eq!(
        audit::year_months(&vault.paths()).unwrap().last(),
        Some(&month),
        "premise: the fixture's history is in the current month, the one a rotation now writes to"
    );
    let log = vault.paths().audit_log(&month);
    let text = std::fs::read_to_string(&log).unwrap();
    let mut lines: Vec<&str> = text.lines().collect();
    assert!(lines.len() >= 2);
    lines.pop();
    std::fs::write(&log, format!("{}\n", lines.join("\n"))).unwrap();
    let old_rk = root_from_disk(vault);
    assert!(audit::verify(&vault.paths(), &old_rk, &month).is_err());

    let state = vault.broker();
    login(&state);
    let outcome = state.rotate_root(passphrase(), wall_now).expect("rotates");
    assert!(outcome.audited);
    let new_rk = root_from_disk(vault);

    let reported = outcome
        .skipped
        .iter()
        .find(|s| s.kind == "audit-tip" && s.id == month)
        .unwrap_or_else(|| panic!("the tampered month is reported: {:?}", outcome.skipped));
    assert!(
        reported
            .reason
            .contains("the month the rotation's own audit record was appended to"),
        "the report admits the month will verify again: {}",
        reported.reason
    );
    // The weakness, as described (see the doc comment above).
    assert!(
        audit::verify(&vault.paths(), &new_rk, &month).is_ok(),
        "the rotation's own record signed the truncated month's tip over what is left"
    );
    // Nothing else is wrong.
    assert_eq!(failures_under(vault, &new_rk, &NODES), Vec::<String>::new());
}

#[test]
fn a_gate_survives_a_rotation_and_still_gates_the_next_unlock() {
    let (vault, state) = created_vault();
    let owner = login(&state);
    // Enrol the vault gate.
    let begin = call(&state, &human(), NOW, "vault.gate_enroll_begin", json!({})).unwrap();
    let uri = begin["otpauthUri"].as_str().unwrap();
    let secret = uri
        .split("secret=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap();
    let totp = Totp::new_gate(decode_gate_secret_base32(secret).unwrap());
    let confirmed = call(
        &state,
        &human(),
        NOW,
        "vault.gate_enroll_confirm",
        json!({ "code": totp.code(NOW as u64) }),
    )
    .unwrap();
    let gate_recovery_code = confirmed["recoveryCodes"][0].as_str().unwrap().to_string();
    create_node(&state, &owner, "acme");
    create_entry(&state, &owner, "acme", "K", "v");

    state.rotate_root(passphrase(), NOW + 1).expect("rotates");
    drop(state);

    // The seed was re-sealed under the new key: the restart still finds a gate,
    // and the restarted broker still opens it with a code from the same seed.
    let state = vault.broker();
    let later = NOW + 90;
    assert!(matches!(
        unlock(&state, PASSPHRASE, later),
        Err(OpError::TwoFactorRequired { .. })
    ));
    call(
        &state,
        &anyone(),
        later,
        "vault.gate_verify",
        json!({ "code": totp.code(later as u64) }),
    )
    .expect("a TOTP code from the original seed opens the rotated vault");
    assert!(!state.is_locked());

    // The gate's own recovery codes are untouched by the root rotation.
    drop(state);
    let state = vault.broker();
    unlock(&state, PASSPHRASE, later + 200).unwrap_err();
    call(
        &state,
        &anyone(),
        later + 200,
        "vault.gate_verify",
        json!({ "code": gate_recovery_code }),
    )
    .expect("a gate recovery code still works");
}

/// A rotation spends the second-factor elevation it needed (`07 §5`), and an
/// unlock parked under the old root key — a second client's `vault.unlock`
/// waiting for its code — must not be completable afterwards: completing it
/// would install the old key as the resident one.
#[test]
fn a_rotation_spends_the_elevation_and_voids_an_unlock_parked_under_the_old_key() {
    use credmgr_brokerd::state::GATE_SCOPE_VAULT;

    let (vault, state) = created_vault();
    // Unlocked first: a gate enrolled on a locked vault is not written through.
    login(&state);
    let begin = call(&state, &human(), NOW, "vault.gate_enroll_begin", json!({})).unwrap();
    let uri = begin["otpauthUri"].as_str().unwrap();
    let secret = uri
        .split("secret=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap();
    let totp = Totp::new_gate(decode_gate_secret_base32(secret).unwrap());
    call(
        &state,
        &human(),
        NOW,
        "vault.gate_enroll_confirm",
        json!({ "code": totp.code(NOW as u64) }),
    )
    .unwrap();
    drop(state);

    // A fresh broker, fully unlocked through the gate — which opens the elevation.
    let state = vault.broker();
    let t = NOW + 100;
    assert!(matches!(
        unlock(&state, PASSPHRASE, t),
        Err(OpError::TwoFactorRequired { .. })
    ));
    let token = call(
        &state,
        &anyone(),
        t,
        "vault.gate_verify",
        json!({ "code": totp.code(t as u64) }),
    )
    .expect("gate_verify")["token"]
        .as_str()
        .unwrap()
        .to_string();
    let registry = state.registry.read().unwrap().clone();
    let owner =
        credmgr_brokerd::scope::resolve_scope(&registry, &state.tokens, &peer(), Some(&token)).0;
    create_node(&state, &owner, "acme");
    assert!(state.is_elevated(GATE_SCOPE_VAULT, t + 1), "control");

    // A second client starts an unlock and parks at the gate, holding the OLD root key.
    assert!(matches!(
        unlock(&state, PASSPHRASE, t + 31),
        Err(OpError::TwoFactorRequired { .. })
    ));

    state
        .rotate_root(passphrase(), t + 32)
        .expect("the rotation");
    assert!(
        !state.is_elevated(GATE_SCOPE_VAULT, t + 33),
        "the rotation spent the elevation: the next high-risk act re-challenges"
    );

    // The parked unlock is void — a valid code does not complete it…
    assert_eq!(
        call(
            &state,
            &anyone(),
            t + 62,
            "vault.gate_verify",
            json!({ "code": totp.code((t + 62) as u64) }),
        ),
        Err(OpError::GateVerificationFailed)
    );
    // …and the resident root key is still the NEW one: a write persists under it.
    assert!(!state.is_locked());
    create_entry(&state, &owner, "acme", "AFTER", "value");
    let new_rk = root_from_disk(&vault);
    assert_eq!(
        failures_under(&vault, &new_rk, &NODES),
        Vec::<String>::new()
    );
}

/// The recovery code exists for the day nothing else works: the standalone,
/// dependency-free Node script (`scripts/emergency-decrypt.mjs`, written
/// independently of the Rust) must open the rotated vault with the NEW code and
/// refuse the old one — proving the rewritten recovery wrap and the re-wrapped
/// node key are readable by something that shares no code with this crate.
#[test]
fn the_offline_emergency_script_opens_the_rotated_vault_with_the_new_code_only() {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/emergency-decrypt.mjs");
    let run = |vault: &Vault, entry: &str, code: &str| {
        std::process::Command::new("node")
            .arg(&script)
            .args(["--vault", &vault.vault_dir.to_string_lossy()])
            .args(["--node", "acme", "--entry", entry])
            .env("CREDMGR_RECOVERY_CODE", code)
            .output()
    };

    let p = populated();
    // The control: before the rotation the old code opens it. Also how a
    // machine without `node` skips this test rather than failing it.
    match run(&p.vault, &p.entry_a, &p.vault.root_recovery_code) {
        Ok(out) if out.status.success() => {
            assert_eq!(emergency_value(&out.stdout), b"alpha-secret");
        }
        Ok(out) => panic!(
            "control failed before any rotation: {}",
            String::from_utf8_lossy(&out.stderr)
        ),
        Err(_) => {
            eprintln!("skipped: `node` is not installed");
            return;
        }
    }

    let state = p.vault.broker();
    login(&state);
    let outcome = state.rotate_root(passphrase(), NOW + 1).expect("rotates");
    drop(state);

    let with_new = run(&p.vault, &p.entry_a, &outcome.recovery_code).unwrap();
    assert!(
        with_new.status.success(),
        "the new recovery code must open the rotated vault offline: {}",
        String::from_utf8_lossy(&with_new.stderr)
    );
    assert_eq!(emergency_value(&with_new.stdout), b"alpha-secret");

    let with_old = run(&p.vault, &p.entry_a, &p.vault.root_recovery_code).unwrap();
    assert!(
        !with_old.status.success(),
        "the old recovery code must no longer open anything"
    );
    assert!(
        String::from_utf8_lossy(&with_old.stderr).contains("authentication failed"),
        "{}",
        String::from_utf8_lossy(&with_old.stderr)
    );
}

// ---------------------------------------------------------------------------
// What rotation must not strand: seals, removals, undo
// ---------------------------------------------------------------------------

#[test]
fn a_seal_a_removal_and_an_undo_made_before_the_rotation_still_work_after_it() {
    let (vault, state) = created_vault();
    let (owner, token) = login_with_token(&state);
    // ADR-079: `credmgr init` made the orphan node and its cold key, so
    // `node.seal` has somewhere to seal to with no help from the test.
    create_node(&state, &owner, "acme");
    create_node(&state, &owner, "globex");
    let (sealed_entry, _) = create_entry(&state, &owner, "acme", "SEALED_ONE", "sealed-value");
    let (kept, kept_gen) = create_entry(&state, &owner, "globex", "KEPT", "kept-v1");
    let (removed, _) = create_entry(&state, &owner, "globex", "REMOVED", "removed-value");

    // Before the rotation: seal a node, remove an entry, rotate another.
    call(&state, &owner, NOW, "node.seal", json!({ "node": "acme" })).expect("node.seal");
    let globex_gen = state.manifest_generation("globex").unwrap();
    via_server(
        &state,
        &token,
        "entry.remove",
        json!({ "node": "globex", "entry": removed, "generation": globex_gen }),
    )
    .0
    .expect("entry.remove");
    let globex_gen = state.manifest_generation("globex").unwrap();
    let (rotated, rotate_audit) = via_server(
        &state,
        &token,
        "entry.rotate",
        json!({ "node": "globex", "entry": kept, "value": "kept-v2", "generation": globex_gen }),
    );
    rotated.expect("entry.rotate");
    let rotate_audit = rotate_audit.expect("audited");
    let _ = kept_gen;

    state
        .rotate_root(passphrase(), NOW + 5)
        .expect("the rotation");
    let new_rk = root_from_disk(&vault);

    // The retained node key in the seal archive was re-wrapped on disk too.
    let archived = std::fs::read(vault.paths().archive_dir("acme").join("node.key")).unwrap();
    assert!(
        unwrap_node_key(
            &new_rk,
            "acme",
            &WrappedNodeKey::from_bytes(&archived).unwrap()
        )
        .is_ok(),
        "the archived node key opens under the new root"
    );

    // Restore the sealed node: the archive's signed record verifies under the
    // new key, and the node comes back with a key that opens its envelopes.
    call(
        &state,
        &owner,
        NOW + 6,
        "node.restore",
        json!({ "node": "acme" }),
    )
    .expect("node.restore after a rotation");
    assert_eq!(
        reveal(&state, &owner, "acme", &sealed_entry),
        "sealed-value"
    );
    verify_ok(&state, &owner);

    // Restore the removed entry: its signed record verifies under the new key.
    let globex_gen = state.manifest_generation("globex").unwrap();
    via_server(
        &state,
        &token,
        "entry.restore",
        json!({ "node": "globex", "entry": removed, "generation": globex_gen }),
    )
    .0
    .expect("entry.restore after a rotation");
    assert_eq!(reveal(&state, &owner, "globex", &removed), "removed-value");

    // Undo the rotation made before the root rotation: the snapshot verifies.
    let globex_gen = state.manifest_generation("globex").unwrap();
    via_server(
        &state,
        &token,
        "entry.undo",
        json!({ "node": "globex", "id": rotate_audit, "generation": globex_gen }),
    )
    .0
    .expect("entry.undo after a rotation");
    assert_eq!(reveal(&state, &owner, "globex", &kept), "kept-v1");

    // And all of it survives a restart.
    drop(state);
    let state = vault.broker();
    let owner = login(&state);
    assert_eq!(
        reveal(&state, &owner, "acme", &sealed_entry),
        "sealed-value"
    );
    assert_eq!(reveal(&state, &owner, "globex", &kept), "kept-v1");
    assert_eq!(reveal(&state, &owner, "globex", &removed), "removed-value");
}

// ---------------------------------------------------------------------------
// Crash safety
// ---------------------------------------------------------------------------

/// What a restarted broker must be able to do with a vault a rotation was
/// cut off in, and which recovery code is the live one.
fn assert_opens_after_restart(vault: &Vault, p: &Populated, expect_new_root: bool, why: &str) {
    let state = vault.broker();
    // One unlock: the passphrase must open the vault on a fresh broker with
    // no help from anything but the files left on disk.
    let token = unlock(&state, PASSPHRASE, NOW)
        .unwrap_or_else(|e| panic!("{why}: unlock failed: {e:?}"))["token"]
        .as_str()
        .unwrap()
        .to_string();
    let owner = {
        let registry = state.registry.read().unwrap().clone();
        credmgr_brokerd::scope::resolve_scope(&registry, &state.tokens, &peer(), Some(&token)).0
    };
    assert_eq!(
        reveal(&state, &owner, "acme", &p.entry_a),
        "alpha-secret",
        "{why}"
    );
    assert_eq!(
        reveal(&state, &owner, "acme", &p.entry_b),
        "bravo-secret-2",
        "{why}"
    );
    verify_ok(&state, &owner);
    let rk = root_from_disk(vault);
    assert_eq!(
        failures_under(vault, &rk, &NODES),
        Vec::<String>::new(),
        "{why}: after recovery the whole vault opens under whichever root key the passphrase yields"
    );
    assert!(
        !vault.paths().rotation_stage().exists(),
        "{why}: recovery leaves no stage behind"
    );
    // Which recovery code is live tells which root key won.
    let old_code_works = call(
        &state,
        &anyone(),
        NOW,
        "vault.gate_recover",
        json!({ "passphrase": PASSPHRASE, "recoveryCode": vault.root_recovery_code }),
    )
    .is_ok();
    assert_eq!(
        old_code_works,
        !expect_new_root,
        "{why}: expected the {} recovery code to be the live one",
        if expect_new_root { "new" } else { "old" }
    );
}

#[test]
fn a_crash_before_the_commit_leaves_the_old_root_key_in_force() {
    let p = populated();
    let state = p.vault.broker();
    login(&state);
    let old_rk = root_from_disk(&p.vault);
    state.set_rotation_fault_for_test(Some(RotationFault::BeforeCommit));
    assert!(state.rotate_root(passphrase(), NOW + 1).is_err());
    drop(state); // the process is gone

    // Everything is staged, nothing is live, no commit record.
    assert!(p.vault.paths().rotation_stage().exists());
    assert!(!p.vault.paths().rotation_stage().join("COMMIT").exists());
    assert_eq!(root_from_disk(&p.vault), old_rk);
    assert_eq!(
        failures_under(&p.vault, &old_rk, &NODES),
        Vec::<String>::new()
    );

    assert_opens_after_restart(&p.vault, &p, false, "crash before the commit");
}

/// The first of the three phases: a crash while the replacement files are still
/// being written. Cut after every possible number of staged files — none, one,
/// …, all but the last — a fresh broker must unlock with the **old** root key,
/// read everything, and find the half-written stage gone. Nothing live may have
/// moved, because nothing live is touched before the commit record exists.
#[test]
fn a_crash_while_staging_at_every_point_leaves_the_old_root_key_in_force() {
    let p = populated();

    // How many files the rotation stages in total.
    let files = {
        let dry = p.vault.cloned();
        let state = dry.broker();
        login(&state);
        state
            .rotate_root(passphrase(), NOW + 1)
            .unwrap()
            .files_replaced
    };
    assert!(files >= 10);

    for staged in 0..files {
        let vault = p.vault.cloned();
        let state = vault.broker();
        login(&state);
        let old_rk = root_from_disk(&vault);
        state.set_rotation_fault_for_test(Some(RotationFault::DuringStaging(staged)));
        assert!(matches!(
            state.rotate_root(passphrase(), NOW + 1),
            Err(RotateRootError::Store(_))
        ));
        drop(state); // the process is gone, mid-staging

        let why = format!("crash after {staged} of {files} files were staged");
        let stage = vault.paths().rotation_stage();
        assert!(
            stage.exists(),
            "{why}: a stale stage is what a crash leaves"
        );
        assert!(!stage.join("COMMIT").exists(), "{why}: never committed");
        assert_eq!(root_from_disk(&vault), old_rk, "{why}");
        assert_eq!(
            failures_under(&vault, &old_rk, &NODES),
            Vec::<String>::new(),
            "{why}: no live file was touched"
        );
        assert_opens_after_restart(&vault, &p, false, &why);
    }
}

/// The commit call can report an error *after* the record landed (the rename
/// succeeded, a later directory sync did not). The record on disk is what
/// binds, so the rotation must carry on as committed and hand over the new
/// recovery code — "nothing changed" would be a lie that loses it.
#[test]
fn a_commit_that_reports_failure_after_the_record_landed_is_carried_through() {
    let p = populated();
    let vault = &p.vault;
    let state = vault.broker();
    login(&state);
    state.set_rotation_fault_for_test(Some(RotationFault::CommitReportsFailure));

    let outcome = state
        .rotate_root(passphrase(), NOW + 1)
        .expect("the record is on disk, so the rotation is committed and completes");
    assert!(!outcome.completion_pending);
    assert!(parse_recovery_code(&outcome.recovery_code).is_ok());
    drop(state);

    // The code it returned is the live one.
    let state = vault.broker();
    let owner = login(&state);
    assert_eq!(reveal(&state, &owner, "acme", &p.entry_a), "alpha-secret");
    call(
        &state,
        &anyone(),
        NOW,
        "vault.gate_recover",
        json!({ "passphrase": PASSPHRASE, "recoveryCode": outcome.recovery_code }),
    )
    .expect("the recovery code the committed rotation returned opens the vault's recovery wrap");
    let new_rk = root_from_disk(vault);
    assert_eq!(failures_under(vault, &new_rk, &NODES), Vec::<String>::new());
}

/// The sweep. A rotation is cut off at every point after the commit — before
/// any live file moved, and after each one — and a freshly started broker must
/// unlock with the passphrase and read everything back each time.
#[test]
fn a_crash_after_the_commit_at_every_point_still_opens_with_the_new_root_key() {
    let p = populated();

    // How many files a rotation of this vault replaces.
    let dry = p.vault.cloned();
    let files = {
        let state = dry.broker();
        login(&state);
        state
            .rotate_root(passphrase(), NOW + 1)
            .unwrap()
            .files_replaced
    };
    assert!(files >= 10);

    for cut in 0..=files {
        let vault = p.vault.cloned();
        let state = vault.broker();
        login(&state);
        state.set_rotation_fault_for_test(Some(RotationFault::DuringRollForward(cut)));
        assert!(state.rotate_root(passphrase(), NOW + 1).is_err());
        drop(state); // the process is gone, mid roll-forward

        let why = format!("crash after {cut} of {files} live files were replaced");
        // The commit record is the proof the rotation is binding. It survives
        // every cut — including the last one, where every file has moved and
        // only the record's own removal is left — so there is always something
        // for the restart to finish from.
        assert!(
            vault.paths().rotation_stage().join("COMMIT").exists(),
            "{why}: the commit record is still there to finish from"
        );
        assert_opens_after_restart(&vault, &p, true, &why);
    }

    // And right after the commit, before anything is live, the other way the
    // process can die there (the rotation's own error path, no memory switch).
    let vault = p.vault.cloned();
    let state = vault.broker();
    login(&state);
    state.set_rotation_fault_for_test(Some(RotationFault::AfterCommit));
    assert!(state.rotate_root(passphrase(), NOW + 1).is_err());
    drop(state);
    assert_opens_after_restart(&vault, &p, true, "crash immediately after the commit");
}

/// ADR-092 (batch 2): the factors of a decision made while the vault is locked
/// read the root wrap like an unlock does, so they finish an interrupted rotation
/// first (ADR-076: "every path about to read a root wrap"). Before this, a state
/// started over a half-rotated vault (not the daemon, whose start-up recovers)
/// derived the root key from a wrap that was mid-replacement.
#[test]
fn a_decision_with_the_factors_finishes_an_interrupted_rotation_first() {
    let p = populated();
    let state = p.vault.broker();
    login(&state);
    state.set_rotation_fault_for_test(Some(RotationFault::DuringRollForward(3)));
    assert!(state.rotate_root(passphrase(), NOW + 1).is_err());
    let new_rk = *state.reauth_root_key("test").unwrap().expose_secret();
    drop(state); // the process is gone, mid roll-forward
    let stage = p.vault.paths().rotation_stage();
    assert!(stage.join("COMMIT").exists(), "cut off mid roll-forward");

    let fresh = p.vault.broker(); // a new state over the half-rotated vault; nobody has unlocked it
    let root = fresh
        .approval_factors(passphrase(), None, NOW + 2)
        .expect("the factors open the vault once the rotation is finished");
    assert!(
        !stage.join("COMMIT").exists(),
        "the rotation was finished before the root wrap was read"
    );
    assert_eq!(
        *root.expose_secret(),
        new_rk,
        "the key the factors yield is the NEW root key, not one derived from a half-replaced wrap"
    );
}

/// The daemon itself, not just the library: `credmgrd`'s start-up finishes a
/// committed rotation before it serves a single request, so even an offline
/// tool that reads the vault after a bare `credmgrd` start sees a whole vault.
#[test]
fn the_daemon_finishes_an_interrupted_rotation_before_it_serves_anything() {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    let p = populated();
    let state = p.vault.broker();
    login(&state);
    state.set_rotation_fault_for_test(Some(RotationFault::DuringRollForward(3)));
    assert!(state.rotate_root(passphrase(), NOW + 1).is_err());
    let new_rk = *state.reauth_root_key("test").unwrap().expose_secret();
    drop(state);
    let stage = p.vault.paths().rotation_stage();
    assert!(stage.join("COMMIT").exists(), "cut off mid roll-forward");

    let mut child = Command::new(env!("CARGO_BIN_EXE_credmgrd"))
        .env("CREDMGR_VAULT_DIR", &p.vault.vault_dir)
        .env("CREDMGR_STATE_DIR", &p.vault.state_dir)
        .env("HOME", p.vault._dir.path())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn credmgrd");
    // Read the daemon's stderr as it speaks: the stage disappears a moment
    // before the daemon says so, and killing it in between would race.
    let mut stderr_pipe = child.stderr.take().expect("piped stderr");
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        use std::io::{BufRead, BufReader};
        for line in BufReader::new(&mut stderr_pipe)
            .lines()
            .map_while(Result::ok)
        {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut stderr = String::new();
    while Instant::now() < deadline && !stderr.contains("finished an interrupted root-key rotation")
    {
        if let Ok(line) = rx.recv_timeout(Duration::from_millis(100)) {
            stderr.push_str(&line);
            stderr.push('\n');
        }
    }
    let _ = child.kill();
    let _ = child.wait();

    assert!(
        stderr.contains("finished an interrupted root-key rotation"),
        "the daemon says what it did: {stderr}"
    );
    assert!(
        !stage.exists(),
        "start-up recovery removed the stage: {stderr}"
    );
    assert_eq!(
        failures_under(&p.vault, &new_rk, &NODES),
        Vec::<String>::new(),
        "the vault is whole under the new key before any unlock"
    );
}

/// The control that lets the sweep fail: without recovery, a rotation cut off
/// in the middle of its roll-forward leaves a vault that opens with *neither*
/// root key. That is the state the commit record exists to heal — so if
/// `recover` is ever not called, the sweep above goes red.
#[test]
fn without_recovery_a_half_applied_rotation_opens_with_neither_key() {
    let p = populated();
    let old_rk = root_from_disk(&p.vault);

    let dry = p.vault.cloned();
    let files = {
        let state = dry.broker();
        login(&state);
        state
            .rotate_root(passphrase(), NOW + 1)
            .unwrap()
            .files_replaced
    };

    let mut neither = 0;
    for cut in 1..files {
        let vault = p.vault.cloned();
        let state = vault.broker();
        login(&state);
        state.set_rotation_fault_for_test(Some(RotationFault::DuringRollForward(cut)));
        assert!(state.rotate_root(passphrase(), NOW + 1).is_err());
        let new_rk = *state.reauth_root_key("test").unwrap().expose_secret();
        drop(state);

        let old_ok = failures_under(&vault, &old_rk, &NODES).is_empty();
        let new_ok = failures_under(&vault, &new_rk, &NODES).is_empty();
        if !old_ok && !new_ok {
            neither += 1;
        }
    }
    assert!(
        neither > 0,
        "some cut points must leave a vault neither key opens — otherwise the commit record is guarding nothing"
    );
}

/// A roll-forward that fails in a *running* broker (here: a directory it cannot
/// write into) must not leave it serving a half-moved vault. It locks, says
/// why, and the next unlock — in the same process — finishes the job.
///
/// And it must still hand over the new recovery code: the commit record made
/// that code the live one, so an error here would destroy the only copy of a
/// code that works. The test then proves the returned code is the live one by
/// using it, and that the old one is dead.
#[cfg(unix)]
#[test]
fn a_roll_forward_that_fails_in_a_live_broker_locks_it_and_the_next_unlock_finishes_it() {
    use std::os::unix::fs::PermissionsExt;
    let p = populated();
    let vault = &p.vault;
    let state = vault.broker();
    let owner = login(&state);

    let keys_nodes = vault.paths().keys_dir().join("nodes");
    std::fs::set_permissions(&keys_nodes, std::fs::Permissions::from_mode(0o500)).unwrap();
    // A user who can write regardless (root in a container) cannot run this test.
    if std::fs::write(keys_nodes.join("probe"), b"x").is_ok() {
        let _ = std::fs::remove_file(keys_nodes.join("probe"));
        std::fs::set_permissions(&keys_nodes, std::fs::Permissions::from_mode(0o700)).unwrap();
        eprintln!("skipped: this user ignores directory permissions");
        return;
    }

    let result = state.rotate_root(passphrase(), NOW + 1);
    std::fs::set_permissions(&keys_nodes, std::fs::Permissions::from_mode(0o700)).unwrap();
    let outcome = result.expect("a committed rotation is a success, even when it cannot finish");
    assert!(
        outcome.completion_pending,
        "the move did not finish and the outcome says so: {outcome:?}"
    );
    assert!(
        !outcome.audited,
        "locked, with the audit tips still mid-move, nothing could be audited"
    );
    assert!(parse_recovery_code(&outcome.recovery_code).is_ok());

    assert!(
        state.is_locked(),
        "a committed rotation that could not be applied must not leave the vault serving"
    );
    assert!(
        vault.paths().rotation_stage().join("COMMIT").exists(),
        "the commit record stays so the next unlock can finish"
    );
    assert!(
        call(
            &state,
            &owner,
            NOW,
            "entry.reveal",
            json!({ "node": "acme", "entry": p.entry_a })
        )
        .is_err(),
        "a locked vault reveals nothing"
    );

    // The same process, the same passphrase: recovery runs first and completes it.
    let owner = login(&state);
    assert_eq!(reveal(&state, &owner, "acme", &p.entry_a), "alpha-secret");
    verify_ok(&state, &owner);
    assert!(!vault.paths().rotation_stage().exists());
    let new_rk = root_from_disk(vault);
    assert_eq!(failures_under(vault, &new_rk, &NODES), Vec::<String>::new());

    // The code the interrupted rotation handed over is the live one…
    call(
        &state,
        &anyone(),
        NOW + 2,
        "vault.gate_recover",
        json!({ "passphrase": PASSPHRASE, "recoveryCode": outcome.recovery_code }),
    )
    .expect("the recovery code returned with completion_pending opens the recovery wrap");
    // …and the one before it is dead.
    assert_eq!(
        call(
            &state,
            &anyone(),
            NOW + 3,
            "vault.gate_recover",
            json!({ "passphrase": PASSPHRASE, "recoveryCode": vault.root_recovery_code }),
        ),
        Err(OpError::WrongPassphrase)
    );
}

// ---------------------------------------------------------------------------
// The wire
// ---------------------------------------------------------------------------

#[test]
fn the_wire_gate_is_human_admin_two_factor_then_presence_and_a_refusal_changes_nothing() {
    let p = populated();
    let vault = &p.vault;
    let state = vault.broker();
    let owner = login(&state);
    let rk_before = root_from_disk(vault);
    let wraps_before = (
        std::fs::read(vault.paths().root_wrap_pass()).unwrap(),
        std::fs::read(vault.paths().root_wrap_recovery()).unwrap(),
    );
    let params = json!({ "passphrase": PASSPHRASE });

    // No passphrase / an empty one is malformed, before any authorisation.
    assert!(matches!(
        call(&state, &owner, NOW, "maintenance.rotate_root", json!({})),
        Err(OpError::Malformed(_))
    ));
    assert!(matches!(
        call(
            &state,
            &owner,
            NOW,
            "maintenance.rotate_root",
            json!({ "passphrase": "" })
        ),
        Err(OpError::Malformed(_))
    ));
    // An agent never.
    assert!(matches!(
        call(
            &state,
            &anyone(),
            NOW,
            "maintenance.rotate_root",
            params.clone()
        ),
        Err(OpError::CapabilityNotHeld { .. })
    ));
    let mut agent_with_admin = human();
    agent_with_admin.origin = Origin::Agent;
    assert!(matches!(
        call(
            &state,
            &agent_with_admin,
            NOW,
            "maintenance.rotate_root",
            params.clone()
        ),
        Err(OpError::CapabilityNotHeld { .. })
    ));
    // A human with Admin: presence is the last gate, and it cannot be met.
    assert_eq!(
        call(
            &state,
            &owner,
            NOW,
            "maintenance.rotate_root",
            params.clone()
        ),
        Err(OpError::PresenceRequired {
            operation: "maintenance.rotate_root".to_string()
        })
    );
    // Nothing moved.
    assert_eq!(root_from_disk(vault), rk_before);
    assert_eq!(
        wraps_before,
        (
            std::fs::read(vault.paths().root_wrap_pass()).unwrap(),
            std::fs::read(vault.paths().root_wrap_recovery()).unwrap()
        )
    );
    assert!(!vault.paths().rotation_stage().exists());

    // With a gate enrolled and no live elevation, the second factor comes first.
    let begin = call(&state, &human(), NOW, "vault.gate_enroll_begin", json!({})).unwrap();
    let uri = begin["otpauthUri"].as_str().unwrap();
    let secret = uri
        .split("secret=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap();
    let totp = Totp::new_gate(decode_gate_secret_base32(secret).unwrap());
    call(
        &state,
        &human(),
        NOW,
        "vault.gate_enroll_confirm",
        json!({ "code": totp.code(NOW as u64) }),
    )
    .unwrap();
    assert!(matches!(
        call(
            &state,
            &owner,
            NOW,
            "maintenance.rotate_root",
            params.clone()
        ),
        Err(OpError::TwoFactorRequired { .. })
    ));
}

/// The response shape the wire will carry once presence can be attested, and
/// the mapping of every failure — driven through the function the dispatch arm
/// will call.
#[test]
fn the_response_the_wire_will_carry_names_the_new_code_once_and_nothing_else_secret() {
    let p = populated();
    let state = p.vault.broker();
    login(&state);

    let wrong = ops::rotate_root_response(&state, "nope", NOW);
    assert_eq!(wrong, Err(OpError::WrongPassphrase));

    let ok = ops::rotate_root_response(&state, PASSPHRASE, NOW + 1).expect("rotates");
    assert_eq!(ok["rotated"], true);
    let code = ok["recoveryCode"].as_str().unwrap();
    assert!(parse_recovery_code(code).is_ok());
    assert_eq!(ok["nodesRewrapped"], 2);
    assert!(ok["vaultGeneration"].as_u64().unwrap() > 0);
    assert!(ok["filesReplaced"].as_u64().unwrap() >= 10);
    assert_eq!(ok["completionPending"], false);
    assert_eq!(ok["notResigned"], json!([]));
    let keys: Vec<&String> = ok.as_object().unwrap().keys().collect();
    assert!(
        !keys
            .iter()
            .any(|k| k.to_lowercase().contains("root") && *k != "rotated"),
        "no key material rides along in the response: {keys:?}"
    );
    assert!(
        ok.get("locked").is_none(),
        "the bridge reads `locked` as the vault's lock state — this answer must not carry one"
    );

    state.lock();
    assert_eq!(
        ops::rotate_root_response(&state, PASSPHRASE, NOW + 2),
        Err(OpError::VaultLocked)
    );
}

// ---------------------------------------------------------------------------
// The request barrier (ADR-076)
// ---------------------------------------------------------------------------

#[test]
fn an_exclusive_request_waits_for_the_ones_in_flight_and_holds_off_the_next() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    let (_vault, state) = created_vault();
    let ran = Arc::new(AtomicBool::new(false));

    let shared = state.request_barrier(false);
    let rotating = {
        let (state, ran) = (Arc::clone(&state), Arc::clone(&ran));
        std::thread::spawn(move || {
            let _alone = state.request_barrier(true);
            ran.store(true, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(150));
        })
    };
    std::thread::sleep(Duration::from_millis(150));
    assert!(
        !ran.load(Ordering::SeqCst),
        "the rotation must not start while a request is still in flight"
    );
    drop(shared);
    rotating.join().unwrap();
    assert!(ran.load(Ordering::SeqCst));
    // Once it is done, requests share the barrier again.
    let a = state.request_barrier(false);
    let b = state.request_barrier(false);
    drop((a, b));
}

/// The barrier is taken by the server's real request path, not just exercised
/// as a lock: a `maintenance.rotate_root` request waits for an in-flight
/// request, and an ordinary request waits for a rotation.
#[test]
fn the_servers_request_path_takes_the_barrier_exclusively_for_a_rotation_and_shared_otherwise() {
    use std::sync::mpsc;
    use std::time::Duration;

    let (_vault, state) = created_vault();
    let (_owner, token) = login_with_token(&state);

    // An in-flight request (the shared guard) holds a rotation request off…
    let in_flight = state.request_barrier(false);
    let (tx, rx) = mpsc::channel();
    let rotation = {
        let (state, token, tx) = (Arc::clone(&state), token.clone(), tx.clone());
        std::thread::spawn(move || {
            let answer = via_server(
                &state,
                &token,
                "maintenance.rotate_root",
                json!({ "passphrase": PASSPHRASE }),
            );
            tx.send(answer.0).unwrap();
        })
    };
    assert!(
        rx.recv_timeout(Duration::from_millis(300)).is_err(),
        "a rotation request must not run while another request is in flight"
    );
    drop(in_flight);
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(30))
            .expect("it runs once the barrier is free"),
        Err(OpError::PresenceRequired {
            operation: "maintenance.rotate_root".to_string()
        })
    );
    rotation.join().unwrap();

    // …and a held exclusive guard (a rotation in progress) holds an ordinary
    // request off.
    let rotating = state.request_barrier(true);
    let reader = {
        let (state, token, tx) = (Arc::clone(&state), token.clone(), tx);
        std::thread::spawn(move || {
            let answer = via_server(&state, &token, "entry.list", json!({ "node": "global" }));
            tx.send(answer.0.map(|_| json!(null))).unwrap();
        })
    };
    assert!(
        rx.recv_timeout(Duration::from_millis(300)).is_err(),
        "an ordinary request must not run while a rotation holds the barrier"
    );
    drop(rotating);
    rx.recv_timeout(Duration::from_secs(30))
        .expect("it runs once the rotation is done")
        .expect("and succeeds");
    reader.join().unwrap();
}

// ---------------------------------------------------------------------------
// The audit trail
// ---------------------------------------------------------------------------

/// A rotation is itself audited — and the record is the first one signed under
/// the new key, so the month it lands in verifies under the new key only.
#[test]
fn a_rotation_is_audited_and_the_record_is_signed_under_the_new_root_key() {
    let p = populated();
    let vault = &p.vault;
    let old_rk = root_from_disk(vault);
    let state = vault.broker();
    login(&state);

    let outcome = state.rotate_root(passphrase(), NOW + 1).expect("rotates");
    assert!(outcome.audited, "{outcome:?}");
    let new_rk = root_from_disk(vault);

    let record = audit::tail(&vault.paths(), 100)
        .unwrap()
        .into_iter()
        .find(|r| r.action == "maintenance.root_rotated")
        .expect("the rotation left an audit record");
    assert_eq!(record.decision.as_deref(), Some("allow"));
    assert_eq!(record.node_id.as_deref(), Some(GLOBAL_ID));
    assert_eq!(record.generation, Some(outcome.vault_generation));
    assert_eq!(record.timestamp, NOW + 1);
    let detail = record.detail.expect("a detail line");
    assert!(
        detail.contains("2 node keys re-wrapped") && detail.contains("0 left unsigned"),
        "{detail}"
    );
    // Counts only: not the recovery code, not a key, not the passphrase.
    let plain_code = outcome.recovery_code.replace('-', "");
    let raw = std::fs::read_to_string(vault.paths().audit_log(&audit::year_month_for(NOW + 1)))
        .unwrap()
        .to_lowercase();
    assert!(!raw.contains(&plain_code.to_lowercase()) && !raw.contains(&PASSPHRASE.to_lowercase()));

    // The month it landed in, and every earlier one, verify under the new key
    // — and under the old key none do.
    let month = audit::year_month_for(NOW + 1);
    assert!(audit::verify(&vault.paths(), &new_rk, &month).is_ok());
    assert!(audit::verify(&vault.paths(), &old_rk, &month).is_err());
    assert_eq!(failures_under(vault, &new_rk, &NODES), Vec::<String>::new());

    // And the chain keeps extending under the new key after a restart.
    drop(state);
    let state = vault.broker();
    let owner = login(&state);
    create_entry(&state, &owner, "acme", "AFTER", "echo-secret");
    assert_eq!(failures_under(vault, &new_rk, &NODES), Vec::<String>::new());
}

// ---------------------------------------------------------------------------
// The closed set: exactly the root-bound files change
// ---------------------------------------------------------------------------

/// The fail-closed half of the closed set. Key material this build does not
/// know how to re-wrap — here the hardware-keystore wrap, a stray file beside
/// the orphan cold key, and a stray node key — is wrapped under the OLD root
/// key; a rotation that carried on would strand it irrecoverably. So it is
/// refused, whole, with every byte of the vault unchanged, and goes through the
/// moment the file is gone. (`keys/cold/orphan.key` itself is NOT in this list:
/// since ADR-079 the vault `init` made holds one, the rotation re-seals it, and
/// the control call at the end of this test rotates a vault that has it.)
#[test]
fn a_vault_holding_key_material_the_rotation_cannot_rewrap_is_refused_and_unchanged() {
    let p = populated();
    let vault = &p.vault;
    let state = vault.broker();
    login(&state);

    assert!(
        vault.paths().orphan_key().exists(),
        "the vault `init` made holds the orphan cold key"
    );
    for planted in [
        vault.paths().root_wrap_se(),
        vault.paths().keys_cold_dir().join("orphan.key.bak"),
        vault
            .paths()
            .keys_dir()
            .join("nodes")
            .join("global.key.bak"),
    ] {
        std::fs::create_dir_all(planted.parent().unwrap()).unwrap();
        std::fs::write(
            &planted,
            b"wrapped under a root key this build never heard of",
        )
        .unwrap();
        let before = snapshot_all(vault);

        let err = state
            .rotate_root(passphrase(), NOW + 1)
            .expect_err("a rotation that would strand key material must refuse");
        let RotateRootError::Store(source) = &err else {
            panic!("expected a refusal that changed nothing, got {err:?}");
        };
        let shown = source.to_string();
        assert!(
            shown.contains("cannot re-wrap") && shown.contains("OLD"),
            "the refusal says why: {shown}"
        );
        assert_eq!(
            snapshot_all(vault),
            before,
            "a refused rotation changes no byte ({planted:?})"
        );
        assert!(!vault.paths().rotation_stage().exists());

        std::fs::remove_file(&planted).unwrap();
    }

    // Control: with nothing planted the same call succeeds.
    state
        .rotate_root(passphrase(), NOW + 2)
        .expect("nothing unrecognised is left, so the rotation goes through");
}

/// Every file under both directories, keyed by `vault/<rel>` or `state/<rel>`.
fn snapshot_all(vault: &Vault) -> std::collections::BTreeMap<String, Vec<u8>> {
    let mut out = std::collections::BTreeMap::new();
    for (tag, base) in [("vault", &vault.vault_dir), ("state", &vault.state_dir)] {
        let mut files = Vec::new();
        files_under(base, &mut files);
        for file in files {
            let rel = file
                .strip_prefix(base)
                .unwrap()
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            out.insert(format!("{tag}/{rel}"), std::fs::read(&file).unwrap());
        }
    }
    out
}

/// What a file is, for the purpose of a root-key rotation: `Some(Some(kind))`
/// — signed or wrapped under the root key, so it MUST change; `Some(None)` —
/// sealed to a node *public* key or a hash-chained log, so it MUST NOT;
/// `None` — nobody has decided, which fails the test. This is the executable
/// form of [`credmgr_brokerd::state::ROOT_BOUND_ARTEFACTS`].
fn classify(path: &str) -> Option<Option<&'static str>> {
    let parts: Vec<&str> = path.split('/').collect();
    let is_env = |s: &str| s.ends_with(".env");
    match parts.as_slice() {
        ["vault", "keys", "root.wrap.pass"] => Some(Some("root.wrap.pass")),
        ["vault", "keys", "root.wrap.recovery"] => Some(Some("root.wrap.recovery")),
        ["vault", "keys", "nodes", f] if f.ends_with(".key") => Some(Some("node-key")),
        ["vault", "keys", "cold", "orphan.key"] => Some(Some("orphan-cold-key")),
        ["vault", "registry.json" | "registry.sig" | "registry.json.prev" | "registry.sig.prev"] => {
            Some(Some("registry"))
        }
        ["vault", "nodes", _, "manifest.json"] => Some(Some("manifest")),
        ["vault", "nodes", _, "entries", f] if is_env(f) => Some(None),
        ["vault", "audit", f] if f.ends_with(".tip") => Some(Some("audit-tip")),
        ["vault", "audit", f] if f.ends_with(".log") => Some(None),
        ["vault", "archive", "removed-entries", _, _, "removed.json"] => {
            Some(Some("removed-entry"))
        }
        ["vault", "archive", "removed-entries", _, _, "entry.env"] => Some(None),
        ["vault", "archive", "entry-history", _, _, f] if f.ends_with(".json") => {
            Some(Some("entry-history"))
        }
        ["vault", "archive", "entry-history", _, _, f] if is_env(f) => Some(None),
        ["vault", "archive", id, "meta.json"]
            if !id.ends_with("-entries") && *id != "entry-history" =>
        {
            Some(Some("seal-meta"))
        }
        ["vault", "archive", _, "node.key"] => Some(Some("seal-node-key")),
        ["vault", "archive", _, "node", "manifest.json"] => Some(Some("seal-manifest")),
        ["vault", "archive", _, "node", "entries", f] if is_env(f) => Some(None),
        // The advisory lock every unlock and every rotation takes: an empty file
        // whose only meaning is the OS lock on it. Not root-bound, never changes.
        ["vault", "run", "rotation.lock"] => Some(None),
        ["state", "vaultGeneration.counter"] => Some(Some("counter")),
        _ => None,
    }
}

/// The invariant that makes "every root-wrapped artefact is re-wrapped" a
/// checkable statement instead of a hope: take every byte of the vault and of
/// the rollback-counter directory before and after a rotation, and require
/// that **exactly** the files the table says are root-bound changed, that every
/// other file is byte-identical, and that no file nobody classified exists.
///
/// It can go red three ways, each one a real defect: a root-bound file the
/// rotation missed (unchanged — it would no longer open), a file the rotation
/// touched that it should not (an envelope), and a new kind of file added to
/// the vault without anyone deciding which side of the line it is on.
#[test]
fn exactly_the_root_bound_files_change_and_every_file_is_accounted_for() {
    use credmgr_brokerd::state::ROOT_BOUND_ARTEFACTS;

    let p = populated();
    let vault = &p.vault;
    // A sealed node, so the archive's three signed files exist (and, since
    // ADR-079, the orphan's rows and the seal record in the registry that binds
    // them). The vault `init` made already holds the orphan cold key.
    let state = vault.broker();
    let owner = login(&state);
    create_node(&state, &owner, "globex");
    create_entry(&state, &owner, "globex", "G1", "globex-secret");
    call(
        &state,
        &owner,
        NOW,
        "node.seal",
        json!({ "node": "globex" }),
    )
    .expect("node.seal");

    let before = snapshot_all(vault);
    let outcome = state.rotate_root(passphrase(), NOW + 1).expect("rotates");
    assert!(outcome.skipped.is_empty(), "{:?}", outcome.skipped);
    let after = snapshot_all(vault);

    let mut kinds_changed = std::collections::BTreeSet::new();
    let mut problems = Vec::new();
    for (path, old_bytes) in &before {
        let Some(class) = classify(path) else {
            problems.push(format!("UNCLASSIFIED file in the vault: {path}"));
            continue;
        };
        let Some(new_bytes) = after.get(path) else {
            problems.push(format!("{path} disappeared"));
            continue;
        };
        match class {
            Some(kind) => {
                if new_bytes == old_bytes {
                    problems.push(format!(
                        "{path} ({kind}) is root-bound but was NOT replaced"
                    ));
                } else {
                    kinds_changed.insert(kind);
                }
            }
            None => {
                if new_bytes != old_bytes {
                    problems.push(format!("{path} is not root-bound but its bytes changed"));
                }
            }
        }
    }
    assert!(problems.is_empty(), "{problems:#?}");

    // The only new files are the rotation's own audit record's month.
    let month = audit::year_month_for(NOW + 1);
    let new_files: Vec<&String> = after.keys().filter(|k| !before.contains_key(*k)).collect();
    for f in &new_files {
        assert!(
            *f == &format!("vault/audit/{month}.log") || *f == &format!("vault/audit/{month}.tip"),
            "an unexpected new file after a rotation: {f}"
        );
    }
    assert!(!after.keys().any(|k| k.contains("rotation-pending")));

    // The fixture exercised every kind the table claims — so the table cannot
    // describe a kind this test never saw change.
    let expected: std::collections::BTreeSet<&str> = [
        "root.wrap.pass",
        "root.wrap.recovery",
        "node-key",
        "orphan-cold-key",
        "registry",
        "manifest",
        "audit-tip",
        "seal-meta",
        "seal-node-key",
        "seal-manifest",
        "removed-entry",
        "entry-history",
        "counter",
    ]
    .into_iter()
    .collect();
    assert_eq!(kinds_changed, expected);
    assert_eq!(
        ROOT_BOUND_ARTEFACTS.len(),
        expected.len(),
        "ROOT_BOUND_ARTEFACTS and this test's kinds must be edited together"
    );

    // And the sealed node still comes back, byte-identical, under the new key.
    call(
        &state,
        &owner,
        NOW + 2,
        "node.restore",
        json!({ "node": "globex" }),
    )
    .expect("a sealed node restores after a rotation");
    let globex_entry = {
        let ids = call(
            &state,
            &owner,
            NOW + 3,
            "entry.list",
            json!({ "node": "globex" }),
        )
        .unwrap();
        ids["ids"][0].as_str().unwrap().to_string()
    };
    assert_eq!(
        reveal(&state, &owner, "globex", &globex_entry),
        "globex-secret"
    );
}

// ---------------------------------------------------------------------------
// Hardening from the ADR-076 review
//
// A second process (or broker state) over the same vault; a commit record whose
// durability is unproven; a barrier asked for by someone who could not use it;
// a response the bridge can act on. Each test names the finding it answers and
// goes red if the fix is removed.
// ---------------------------------------------------------------------------

fn count_files(dir: &Path) -> usize {
    let mut files = Vec::new();
    files_under(dir, &mut files);
    files.len()
}

/// A rotation frozen half-way through staging on its own thread, holding the
/// vault lock with a half-written stage on disk — the worst moment for a second
/// process to start.
struct PausedRotation {
    resume: std::sync::mpsc::Sender<()>,
    thread: std::thread::JoinHandle<Result<RotationOutcome, RotateRootError>>,
}

impl PausedRotation {
    /// Start `state`'s rotation and return once `after_staged` files are on disk.
    fn start(state: &Arc<BrokerState>, after_staged: usize) -> PausedRotation {
        use std::sync::{mpsc, Mutex};
        use std::time::Duration;
        let (reached_tx, reached_rx) = mpsc::channel::<()>();
        let (resume_tx, resume_rx) = mpsc::channel::<()>();
        let (reached_tx, resume_rx) = (Mutex::new(reached_tx), Mutex::new(resume_rx));
        state.set_rotation_pause_for_test(
            after_staged,
            Arc::new(move || {
                reached_tx.lock().unwrap().send(()).unwrap();
                resume_rx
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(180))
                    .expect("the test resumes the frozen rotation");
            }),
        );
        let thread = {
            let state = Arc::clone(state);
            std::thread::spawn(move || state.rotate_root(passphrase(), NOW + 1))
        };
        reached_rx
            .recv_timeout(Duration::from_secs(120))
            .expect("the rotation reached the point it was frozen at");
        PausedRotation {
            resume: resume_tx,
            thread,
        }
    }

    /// Let it carry on and return what it returned.
    fn finish(self) -> Result<RotationOutcome, RotateRootError> {
        self.resume.send(()).unwrap();
        self.thread
            .join()
            .expect("the rotation thread did not panic")
    }
}

/// The review's P2. A second broker state — a second `credmgrd` — starting up
/// while the first is half-way through staging must **wait**, not run recovery
/// over the first's uncommitted stage (which looks exactly like a crashed one)
/// and delete it. Before the vault lock existed, the stage vanished under the
/// first rotation, which went on to commit a record naming files that were no
/// longer there and roll forward over a vault that opened with neither key.
#[test]
fn a_second_broker_state_started_mid_staging_waits_instead_of_deleting_the_stage() {
    use std::sync::mpsc;
    use std::time::Duration;

    let p = populated();
    let vault = &p.vault;
    let old_rk = root_from_disk(vault);
    let first = vault.broker();
    login(&first);
    let second = vault.broker();

    let paused = PausedRotation::start(&first, 3);
    let stage = vault.paths().rotation_stage();
    assert!(stage.exists() && !stage.join("COMMIT").exists());
    let staged = count_files(&stage);
    assert!(staged >= 3, "the stage is half-written: {staged}");

    // The second daemon unlocks now.
    let (tx, rx) = mpsc::channel();
    let waiting = {
        let second = Arc::clone(&second);
        std::thread::spawn(move || tx.send(unlock(&second, PASSPHRASE, NOW)).unwrap())
    };
    assert!(
        rx.recv_timeout(Duration::from_millis(600)).is_err(),
        "the second broker must be waiting on the rotation, not racing it"
    );
    assert!(
        stage.exists(),
        "the second broker deleted the first one's stage"
    );
    assert_eq!(count_files(&stage), staged, "…or touched it");
    assert_eq!(root_from_disk(vault), old_rk, "nothing live has moved");

    // The first rotation finishes normally; only then does the second unlock.
    let outcome = paused.finish().expect("the rotation was never disturbed");
    assert!(!outcome.completion_pending, "{outcome:?}");
    let unlocked = rx
        .recv_timeout(Duration::from_secs(120))
        .expect("the second broker unlocks once the rotation is done");
    waiting.join().unwrap();
    assert!(unlocked.is_ok(), "{unlocked:?}");

    // The vault opens with the NEW root key — whole — and the broker that
    // waited reads everything.
    let new_rk = root_from_disk(vault);
    assert_ne!(new_rk, old_rk);
    assert_eq!(failures_under(vault, &new_rk, &NODES), Vec::<String>::new());
    assert!(!stage.exists());
    let owner = login(&second);
    assert_eq!(reveal(&second, &owner, "acme", &p.entry_a), "alpha-secret");
    verify_ok(&second, &owner);
    // …and the code the first rotation returned is the live one.
    call(
        &second,
        &anyone(),
        NOW + 2,
        "vault.gate_recover",
        json!({ "passphrase": PASSPHRASE, "recoveryCode": outcome.recovery_code }),
    )
    .expect("the returned recovery code opens the new recovery wrap");
}

/// The same moment, with the lock bypassed — a recovery that calls the store
/// directly, as every daemon did before the lock. This is the control that
/// shows the lock is what protects the stage, and the proof that the
/// roll-forward's own checks are a real second line: the stage lost files, so
/// the rotation cannot be applied — and **nothing is half-applied**. The old
/// key still opens every file; recovery refuses (fails closed) rather than
/// moving the survivors over a vault that would then open with neither.
#[test]
fn a_recovery_that_bypasses_the_lock_deletes_the_stage_but_cannot_half_apply_the_rotation() {
    let p = populated();
    let vault = &p.vault;
    let old_rk = root_from_disk(vault);
    let first = vault.broker();
    login(&first);

    let paused = PausedRotation::start(&first, 3);
    // The old daemon start-up: store-level recover, no lock.
    let recovered =
        credmgr_store::rotation::recover(&vault.paths(), &vault.state_dir).expect("recover");
    assert_eq!(
        recovered,
        credmgr_store::rotation::Recovery::DiscardedStage,
        "without the lock, recovery takes the half-written stage for a crash's and deletes it"
    );
    // The rotation carries on, commits a record naming files that are gone, and
    // cannot roll forward.
    let outcome = paused
        .finish()
        .expect("committed, so the new code is handed over");
    assert!(outcome.completion_pending, "{outcome:?}");

    assert_eq!(
        failures_under(vault, &old_rk, &NODES),
        Vec::<String>::new(),
        "nothing was moved: every live file is still under the old root key"
    );
    assert_eq!(root_from_disk(vault), old_rk);
    assert!(
        vault.paths().rotation_stage().join("COMMIT").exists(),
        "the record stays: the failure is visible, not papered over"
    );
    assert!(
        unlock(&vault.broker(), PASSPHRASE, NOW).is_err(),
        "recovery fails closed on a stage that lost files — it does not half-apply it"
    );
}

/// Spawn the real `credmgrd` over `vault`, with its output (both streams)
/// delivered line by line.
struct Daemon {
    child: std::process::Child,
    lines: std::sync::mpsc::Receiver<String>,
    seen: String,
}

impl Daemon {
    fn spawn(vault: &Vault) -> Daemon {
        use std::io::{BufRead, BufReader};
        use std::process::{Command, Stdio};
        let mut child = Command::new(env!("CARGO_BIN_EXE_credmgrd"))
            .env("CREDMGR_VAULT_DIR", &vault.vault_dir)
            .env("CREDMGR_STATE_DIR", &vault.state_dir)
            .env("HOME", vault._dir.path())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn credmgrd");
        let (tx, rx) = std::sync::mpsc::channel::<String>();
        let out = child.stdout.take().expect("piped stdout");
        let err = child.stderr.take().expect("piped stderr");
        for pipe in [
            Box::new(out) as Box<dyn std::io::Read + Send>,
            Box::new(err) as Box<dyn std::io::Read + Send>,
        ] {
            let tx = tx.clone();
            std::thread::spawn(move || {
                for line in BufReader::new(pipe).lines().map_while(Result::ok) {
                    if tx.send(line).is_err() {
                        break;
                    }
                }
            });
        }
        Daemon {
            child,
            lines: rx,
            seen: String::new(),
        }
    }

    /// Read output until a line contains `needle` or `within` passes; returns
    /// whether it appeared. Everything read is kept in `seen`.
    fn wait_for(&mut self, needle: &str, within: std::time::Duration) -> bool {
        let deadline = std::time::Instant::now() + within;
        while std::time::Instant::now() < deadline {
            if self.seen.contains(needle) {
                return true;
            }
            if let Ok(line) = self
                .lines
                .recv_timeout(std::time::Duration::from_millis(50))
            {
                self.seen.push_str(&line);
                self.seen.push('\n');
            }
        }
        self.seen.contains(needle)
    }

    /// Drain whatever is already buffered.
    fn drain(&mut self) {
        // A reader thread forwards the child's lines; once the child has exited the last of them can still be in flight, so
        // wait for the channel to go quiet (or close) instead of taking only what has already arrived.
        while let Ok(line) = self
            .lines
            .recv_timeout(std::time::Duration::from_millis(500))
        {
            self.seen.push_str(&line);
            self.seen.push('\n');
        }
    }

    fn socket_answers(vault: &Vault) -> bool {
        std::os::unix::net::UnixStream::connect(vault.paths().run_socket()).is_ok()
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The review's P2, through the real binary: a `credmgrd` that starts while a
/// rotation is staging waits for it. It does not delete the stage, does not
/// serve in the meantime, and carries on to listen once the rotation is done.
#[test]
fn a_second_daemon_starting_mid_staging_waits_and_leaves_the_stage_alone() {
    use std::time::Duration;
    let p = populated();
    let vault = &p.vault;
    let old_rk = root_from_disk(vault);
    let first = vault.broker();
    login(&first);

    let paused = PausedRotation::start(&first, 3);
    let stage = vault.paths().rotation_stage();
    let staged = count_files(&stage);

    let mut daemon = Daemon::spawn(vault);
    // Long enough for a process that was going to recover and print to have done so.
    assert!(
        !daemon.wait_for("listening on", Duration::from_millis(1500)),
        "the daemon must still be waiting on the rotation's lock: {}",
        daemon.seen
    );
    assert!(
        daemon.child.try_wait().unwrap().is_none(),
        "it waits, it does not exit: {}",
        daemon.seen
    );
    assert!(stage.exists(), "the daemon deleted a stage it did not own");
    assert_eq!(count_files(&stage), staged);
    assert_eq!(root_from_disk(vault), old_rk);

    let outcome = paused.finish().expect("the rotation was never disturbed");
    assert!(!outcome.completion_pending);
    assert!(
        daemon.wait_for("listening on", Duration::from_secs(60)),
        "once the rotation is done the daemon starts: {}",
        daemon.seen
    );
    daemon.drain();
    assert!(
        !daemon.seen.contains("removed leftover") && !daemon.seen.contains("could not recover"),
        "it found nothing to recover: {}",
        daemon.seen
    );
    let new_rk = root_from_disk(vault);
    assert_ne!(new_rk, old_rk);
    assert_eq!(failures_under(vault, &new_rk, &NODES), Vec::<String>::new());
}

/// Review M4 plus the P2: a second daemon must not touch a vault a live broker
/// is serving — it leaves recovery to that broker, then `server::run` refuses it.
#[test]
fn a_second_daemon_does_not_touch_the_vault_while_one_is_already_serving_it() {
    use std::time::{Duration, Instant};
    let p = populated();
    let vault = &p.vault;
    let mut first = Daemon::spawn(vault);
    assert!(first.wait_for("listening on", Duration::from_secs(60)));
    let deadline = Instant::now() + Duration::from_secs(30);
    while !Daemon::socket_answers(vault) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        Daemon::socket_answers(vault),
        "the first daemon is serving: {}",
        first.seen
    );

    // Something a recovery would delete, planted while the first daemon serves.
    let stage = vault.paths().rotation_stage();
    credmgr_store::atomic::write(&stage.join("vault").join("leftover"), b"x").unwrap();

    let mut second = Daemon::spawn(vault);
    let exit = loop {
        if let Some(status) = second.child.try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < deadline + Duration::from_secs(30),
            "the second daemon should refuse to start: {}",
            second.seen
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    second.drain();
    assert!(!exit.success(), "{}", second.seen);
    assert!(
        second.seen.contains("already serving"),
        "it says why: {}",
        second.seen
    );
    assert!(
        stage.exists(),
        "the second daemon left the vault alone: {}",
        second.seen
    );
}

/// The review's P3 on start-up messages. A stage with no commit record is what
/// a rotation that FINISHED leaves if it is cut off between retiring its record
/// and removing the directory — the new root key is already in force. The old
/// message said "dropped a root-key rotation that never committed — the vault is
/// unchanged", which is false there. It no longer claims either.
#[test]
fn start_up_does_not_call_a_leftover_stage_an_uncommitted_rotation() {
    use std::time::Duration;
    let p = populated();
    let vault = &p.vault;
    let old_rk = root_from_disk(vault);
    {
        let state = vault.broker();
        login(&state);
        state.rotate_root(passphrase(), NOW + 1).expect("rotates");
    }
    let new_rk = root_from_disk(vault);
    assert_ne!(new_rk, old_rk, "the rotation completed");
    // The crash: record retired (it is), stage directory still there.
    let stage = vault.paths().rotation_stage();
    credmgr_store::atomic::write(&stage.join("vault").join("leftover"), b"x").unwrap();

    let mut daemon = Daemon::spawn(vault);
    assert!(
        daemon.wait_for("removed leftover staging files", Duration::from_secs(60)),
        "{}",
        daemon.seen
    );
    daemon.drain();
    for wrong in [
        "never committed",
        "is unchanged",
        "dropped a root-key rotation",
    ] {
        assert!(
            !daemon.seen.contains(wrong),
            "the message must not claim what the files cannot show ({wrong:?}): {}",
            daemon.seen
        );
    }
    assert!(daemon.seen.contains("rotate again"), "{}", daemon.seen);
    assert!(!stage.exists());
    assert_eq!(failures_under(vault, &new_rk, &NODES), Vec::<String>::new());
}

/// The lock itself: two holders exclude each other inside one process (as two
/// broker states, or a broker and a test, do), a waiter gives up after its
/// deadline with a message that says why, and dropping the guard frees it.
#[test]
fn the_vault_lock_excludes_times_out_with_a_reason_and_frees_on_drop() {
    use std::time::{Duration, Instant};
    let (vault, _state) = created_vault();
    let first = VaultLock::acquire(&vault.paths(), Duration::from_millis(100)).expect("free");

    let started = Instant::now();
    let err = VaultLock::acquire(&vault.paths(), Duration::from_millis(250))
        .expect_err("held by the first");
    assert!(
        started.elapsed() >= Duration::from_millis(250),
        "it waits out its deadline before giving up"
    );
    assert!(err.to_string().contains("rotation lock"), "{err}");

    drop(first);
    VaultLock::acquire(&vault.paths(), Duration::from_millis(100)).expect("freed on drop");

    // A symlink planted at the lock path is refused, not followed.
    #[cfg(unix)]
    {
        let lock = vault.paths().rotation_lock();
        std::fs::remove_file(&lock).unwrap();
        std::os::unix::fs::symlink(vault.vault_dir.join("registry.json"), &lock).unwrap();
        assert!(VaultLock::acquire(&vault.paths(), Duration::from_millis(100)).is_err());
    }
}

/// The child half of the next test: a process that takes the vault lock, says
/// so, and sits on it. A no-op unless the parent sets the environment variable,
/// so an ordinary run of this file passes straight through it.
#[test]
fn zz_vault_lock_holder_child_process() {
    use std::io::Write;
    let Some(dir) = std::env::var_os("CREDMGR_TEST_LOCK_HOLD") else {
        return;
    };
    let paths = VaultPaths::new(PathBuf::from(dir));
    let _held = VaultLock::acquire(&paths, std::time::Duration::from_secs(10))
        .expect("the child takes the lock");
    println!("LOCK-HELD");
    std::io::stdout().flush().unwrap();
    std::thread::sleep(std::time::Duration::from_secs(120));
}

/// What justifies `flock` over a lock *file*: it excludes across real
/// processes, and the kernel lets go the instant the holder dies — killed, not
/// politely dropped — so a rotation that crashed while holding it can never wedge
/// the vault behind a stale lock (the case recovery exists for).
#[test]
fn the_vault_lock_excludes_across_processes_and_is_released_when_its_holder_is_killed() {
    use std::io::{BufRead, BufReader};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    let (vault, _state) = created_vault();
    let mut child = Command::new(std::env::current_exe().expect("this test binary"))
        .args([
            "--exact",
            "zz_vault_lock_holder_child_process",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("CREDMGR_TEST_LOCK_HOLD", &vault.vault_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn the holder");
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    let stdout = child.stdout.take().unwrap();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut held = false;
    while Instant::now() < deadline && !held {
        if let Ok(line) = rx.recv_timeout(Duration::from_millis(100)) {
            held = line.contains("LOCK-HELD");
        }
    }
    assert!(held, "the child process took the lock");

    // Another process holds it: this one cannot.
    let refused = VaultLock::acquire(&vault.paths(), Duration::from_millis(300));
    assert!(
        refused.is_err(),
        "excluded by a lock held in another process"
    );

    // Killed — not dropped, not asked: the kernel releases the lock.
    child.kill().expect("kill the holder");
    child.wait().expect("reap it");
    VaultLock::acquire(&vault.paths(), Duration::from_secs(5))
        .expect("a dead holder's lock is released at once, with no stale lock file to clear");
}

/// A rotation that cannot get the lock refuses — nothing changed — and works the
/// moment the holder lets go.
#[test]
fn a_rotation_refuses_while_another_holder_has_the_vault_lock_and_changes_nothing() {
    use std::time::Duration;
    let p = populated();
    let vault = &p.vault;
    let state = vault.broker();
    login(&state);
    let before = snapshot_all(vault);

    let held = VaultLock::acquire(&vault.paths(), Duration::from_millis(100)).unwrap();
    let refused = state
        .rotate_root(passphrase(), NOW + 1)
        .expect_err("another holder owns the vault's rotation lock");
    assert!(
        matches!(&refused, RotateRootError::Store(e) if e.to_string().contains("rotation lock")),
        "{refused}"
    );
    assert_eq!(
        snapshot_all(vault),
        before,
        "a refused rotation changes no byte on disk and leaves no stage"
    );
    assert!(!vault.paths().rotation_stage().exists());

    drop(held);
    state
        .rotate_root(passphrase(), NOW + 2)
        .expect("free again, it goes through");
}

/// The review's P3 on durability. If the commit call reports an error after the
/// record landed AND the record cannot be proven durable, no live file may move:
/// a power loss could keep some moved files and lose the record that says to
/// finish. The rotation hands over its outcome as `completion_pending`, locks,
/// and the next unlock's recovery rolls forward.
#[test]
fn a_commit_record_that_cannot_be_proven_durable_moves_no_live_file() {
    let p = populated();
    let vault = &p.vault;
    let old_rk = root_from_disk(vault);
    let state = vault.broker();
    login(&state);
    let live_before: std::collections::BTreeMap<_, _> = snapshot_all(vault)
        .into_iter()
        .filter(|(path, _)| !path.contains("rotation-pending"))
        .collect();

    state.set_rotation_fault_for_test(Some(RotationFault::CommitNeverBecomesDurable));
    let outcome = state
        .rotate_root(passphrase(), NOW + 1)
        .expect("the record is on disk, so the rotation is committed and its code is handed over");
    assert!(outcome.completion_pending, "{outcome:?}");
    assert!(!outcome.audited);
    assert!(state.is_locked(), "pending completion locks the broker");
    assert!(vault.paths().rotation_stage().join("COMMIT").exists());

    let live_after: std::collections::BTreeMap<_, _> = snapshot_all(vault)
        .into_iter()
        .filter(|(path, _)| !path.contains("rotation-pending"))
        .collect();
    assert_eq!(
        live_after, live_before,
        "not one live file moved before the record was durable"
    );
    assert_eq!(root_from_disk(vault), old_rk);
    assert_eq!(failures_under(vault, &old_rk, &NODES), Vec::<String>::new());

    // The next unlock's recovery finishes the move, and the code is the live one.
    let owner = login(&state);
    assert_eq!(reveal(&state, &owner, "acme", &p.entry_a), "alpha-secret");
    verify_ok(&state, &owner);
    let new_rk = root_from_disk(vault);
    assert_ne!(new_rk, old_rk);
    assert_eq!(failures_under(vault, &new_rk, &NODES), Vec::<String>::new());
    call(
        &state,
        &anyone(),
        NOW + 2,
        "vault.gate_recover",
        json!({ "passphrase": PASSPHRASE, "recoveryCode": outcome.recovery_code }),
    )
    .expect("the returned code opens the recovery wrap once recovery has run");
}

/// The review's P3 on the bridge. A pending completion has locked the broker;
/// the answer says so where the bridge's `Session` reads it on every op
/// (`meta.vaultLocked`), and a clean rotation does not. There is still no
/// top-level `locked` — the bridge reads that as the vault's own state only on
/// `vault.status`-shaped answers.
#[test]
fn a_pending_completion_tells_the_bridge_the_broker_locked_itself() {
    let p = populated();
    let state = p.vault.broker();
    login(&state);

    state.set_rotation_fault_for_test(Some(RotationFault::CommitNeverBecomesDurable));
    let pending = ops::rotate_root_response(&state, PASSPHRASE, NOW + 1).expect("committed");
    assert_eq!(pending["completionPending"], true);
    assert_eq!(
        pending["meta"]["vaultLocked"], true,
        "the one field the bridge reconciles its login against: {pending}"
    );
    assert!(pending.get("locked").is_none());
    assert!(state.is_locked());

    login(&state); // recovery finishes it
    state.set_rotation_fault_for_test(None);
    let clean = ops::rotate_root_response(&state, PASSPHRASE, NOW + 2).expect("rotates");
    assert_eq!(clean["completionPending"], false);
    assert!(
        clean.get("meta").is_none(),
        "a clean rotation leaves the login alone: {clean}"
    );
}

/// The review's P3 on the barrier. Asking for a rotation drains every request
/// in flight and holds off the next, so it must not be free: a peer with no
/// token, a stale token or a backed-off uid is refused while sharing the
/// barrier like any other request. (The authorised owner session still gets the
/// exclusive barrier — the test above.)
#[test]
fn a_rotation_request_from_a_caller_who_could_not_run_it_does_not_stop_the_world() {
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    let (_vault, state) = created_vault();
    let (_owner, token) = login_with_token(&state);

    // A request is in flight: it holds the barrier shared.
    let in_flight = state.request_barrier(false);
    let ask = |token: Option<&str>| {
        let (tx, rx) = mpsc::channel();
        let (state, token) = (Arc::clone(&state), token.map(str::to_string));
        std::thread::spawn(move || {
            let answer = server::handle_request(
                &state,
                &peer(),
                &Request {
                    id: "r".to_string(),
                    op: "maintenance.rotate_root".to_string(),
                    token,
                    params: json!({ "passphrase": PASSPHRASE }),
                },
            );
            tx.send(answer.0).unwrap();
        });
        rx
    };
    let patience = Duration::from_secs(5);

    let tokenless = ask(None)
        .recv_timeout(patience)
        .expect("a token-less peer is refused without draining the in-flight request");
    assert!(tokenless.is_err(), "{tokenless:?}");

    let stale = ask(Some("cmt_0123456789abcdef0123456789abcdef"))
        .recv_timeout(patience)
        .expect("a stale token is refused without draining the in-flight request");
    assert_eq!(stale, Err(OpError::SessionExpired));

    // A real owner session, from a uid that has just failed its way into a lockout.
    for _ in 0..5 {
        state
            .auth_backoff
            .record_failure(peer().uid, Instant::now());
    }
    let backed_off = ask(Some(&token))
        .recv_timeout(patience)
        .expect("a backed-off uid is refused without draining the in-flight request");
    assert!(
        matches!(backed_off, Err(OpError::RateLimited { .. })),
        "{backed_off:?}"
    );
    drop(in_flight);
}

// ---------------------------------------------------------------------------
// ADR-079 x ADR-076 — the joint tests (plan §8, C5): a rotation of a vault that
// holds the orphan cold key and durable seal records.
// ---------------------------------------------------------------------------

const DAY: i64 = 24 * 60 * 60;

fn sha256_hex_of(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex(&Sha256::digest(bytes))
}

/// seal -> rotate_root -> restore, in a vault `credmgr init` made: byte-identical,
/// across a restart in the middle, with every binding the seal record holds
/// refreshed to the re-wrapped and re-signed archive.
#[test]
fn a_node_sealed_before_a_rotation_restores_byte_identical_after_it_and_after_a_restart() {
    let (vault, state) = created_vault();
    let owner = login(&state);
    create_node(&state, &owner, "acme");
    let (e1, _) = create_entry(&state, &owner, "acme", "ONE", "value-one");
    let (e2, _) = create_entry(&state, &owner, "acme", "TWO", "value-two");
    let paths = vault.paths();
    let env1 = std::fs::read(paths.entry_env("acme", &e1)).unwrap();
    let env2 = std::fs::read(paths.entry_env("acme", &e2)).unwrap();
    let key_file = std::fs::read(paths.node_key("acme")).unwrap();
    let old_rk = root_from_disk(&vault);

    call(&state, &owner, NOW, "node.seal", json!({ "node": "acme" })).expect("node.seal");
    assert!(
        !paths.node_dir("acme").exists() && !paths.node_key("acme").exists(),
        "a committed seal has moved the node's files into the archive"
    );

    let outcome = state.rotate_root(passphrase(), NOW + 5).expect("rotates");
    assert!(outcome.skipped.is_empty(), "{:?}", outcome.skipped);
    assert!(!outcome.completion_pending);
    let new_rk = root_from_disk(&vault);
    assert_ne!(new_rk, old_rk);

    // Every binding in the signed seal record verifies against the files it names.
    let doc = registry_file::load(&paths, &new_rk).expect("the registry opens under the new root");
    let record = &doc.sealed["acme"];
    let archived_key = std::fs::read(paths.archive_dir("acme").join("node.key")).unwrap();
    assert_eq!(
        sha256_hex_of(&archived_key),
        record.node_key_sha256,
        "the record binds the RE-WRAPPED node key"
    );
    assert_ne!(archived_key, key_file, "the retained key was re-wrapped");
    let archived_manifest = manifest::load_at(
        &paths.archive_dir("acme").join("node").join("manifest.json"),
        &new_rk,
        "acme",
    )
    .expect("the retained manifest verifies under the new root");
    assert_eq!(
        archived_manifest.body.generation,
        record.manifest.generation
    );
    assert_eq!(archived_manifest.hmac, record.manifest.manifest_hmac);
    // The envelopes inside the archive are sealed to the node's PUBLIC key: untouched.
    assert_eq!(
        std::fs::read(
            paths
                .archive_dir("acme")
                .join("node")
                .join("entries")
                .join(format!("{e1}.env"))
        )
        .unwrap(),
        env1
    );

    // A restart in the middle: a fresh broker, the same passphrase.
    drop(state);
    let state = vault.broker();
    let owner = login(&state);
    assert_eq!(
        call(&state, &owner, NOW + DAY, "node.list", json!({})).unwrap()["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|n| n.as_str())
            .collect::<Vec<_>>(),
        vec!["global"],
        "the seal survived the rotation and the restart: the node is still out of the graph"
    );

    call(
        &state,
        &owner,
        NOW + 6 * DAY,
        "node.restore",
        json!({ "node": "acme" }),
    )
    .expect("a node sealed before a rotation restores after it, on day 6");
    assert_eq!(std::fs::read(paths.entry_env("acme", &e1)).unwrap(), env1);
    assert_eq!(std::fs::read(paths.entry_env("acme", &e2)).unwrap(), env2);
    assert_eq!(reveal(&state, &owner, "acme", &e1), "value-one");
    assert_eq!(reveal(&state, &owner, "acme", &e2), "value-two");
    verify_ok(&state, &owner);
    let doc = registry_file::load(&paths, &new_rk).unwrap();
    assert!(doc.sealed.is_empty(), "the record is gone once restored");
    assert!(!paths.archive_dir("acme").exists());

    // And it stays restored across another restart.
    drop(state);
    let state = vault.broker();
    let owner = login(&state);
    assert_eq!(reveal(&state, &owner, "acme", &e1), "value-one");
}

/// init -> rotate_root: the cold key opens under the NEW root only, is the same
/// orphan keypair, and still opens what was sealed to it before the rotation.
#[test]
fn the_orphan_cold_key_opens_under_the_new_root_only_and_still_opens_what_was_sealed_before() {
    let (vault, state) = created_vault();
    let paths = vault.paths();
    let old_rk = root_from_disk(&vault);
    let before = std::fs::read(paths.orphan_key()).unwrap();
    let header = credmgr_core::cold::parse_header(&before).unwrap();
    let doc = registry_file::load(&paths, &old_rk).unwrap();
    assert_eq!(
        hex(header.public.as_bytes()),
        doc.nodes[ORPHAN_ID].public_key,
        "init wrote the registry's orphan public key and the file's header to agree"
    );
    assert!(credmgr_core::cold::open_orphan_cold(&old_rk, &before, Some(&header.public)).is_ok());

    // Something sealed to the orphan before the rotation.
    let owner = login(&state);
    create_node(&state, &owner, "acme");
    let (entry, _) = create_entry(&state, &owner, "acme", "SEALED", "cold-value");
    call(&state, &owner, NOW, "node.seal", json!({ "node": "acme" })).expect("node.seal");
    let orphan_envelope_path = paths.entry_env(ORPHAN_ID, &entry);
    let orphan_envelope = std::fs::read(&orphan_envelope_path).unwrap();

    state.rotate_root(passphrase(), NOW + 1).expect("rotates");
    let new_rk = root_from_disk(&vault);

    let after = std::fs::read(paths.orphan_key()).unwrap();
    assert_ne!(after, before, "the cold key file was re-sealed");
    assert_eq!(
        credmgr_core::cold::parse_header(&after).unwrap().public,
        header.public,
        "the orphan keypair is unchanged"
    );
    let secret = credmgr_core::cold::open_orphan_cold(&new_rk, &after, Some(&header.public))
        .expect("the cold key opens under the new root");
    assert!(
        credmgr_core::cold::open_orphan_cold(&old_rk, &after, None).is_err(),
        "…and under the old root no longer"
    );
    assert_eq!(
        std::fs::read(&orphan_envelope_path).unwrap(),
        orphan_envelope,
        "orphan envelopes are sealed to the public key: a rotation leaves them alone"
    );
    // ADR-078: an entry is a version-2 field document (`open` is version 1 only).
    let (kind, plaintext) =
        credmgr_core::envelope::open_any(&orphan_envelope, &secret, ORPHAN_ID, &entry)
            .expect("the envelope sealed before the rotation opens with the re-sealed cold key");
    assert_eq!(kind, credmgr_core::envelope::PayloadKind::FieldDocument);
    let doc = credmgr_core::fields::decode(plaintext.expose_secret()).expect("a field document");
    assert_eq!(doc.fields.len(), 1);
    assert_eq!(doc.fields[0].value, "cold-value");
    verify_ok(&state, &owner);
}

/// A cold key that does not open under the old root is left exactly as it is and
/// reported — never re-stamped — and the rotation does not pretend it moved it.
#[test]
fn a_torn_orphan_cold_key_is_left_alone_and_reported_by_a_rotation() {
    let (vault, state) = created_vault();
    let paths = vault.paths();
    let owner = login(&state);
    let mut torn = std::fs::read(paths.orphan_key()).unwrap();
    let last = torn.len() - 1;
    torn[last] ^= 1;
    std::fs::write(paths.orphan_key(), &torn).unwrap();

    let outcome = state.rotate_root(passphrase(), NOW + 1).expect("rotates");
    let reported: Vec<&str> = outcome.skipped.iter().map(|s| s.kind).collect();
    assert!(reported.contains(&"orphan-cold-key"), "{reported:?}");
    assert_eq!(std::fs::read(paths.orphan_key()).unwrap(), torn);
    // …and the vault says so, so a seal is refused rather than committed to it.
    let verified = call(&state, &owner, NOW + 2, "maintenance.verify", json!({})).unwrap();
    assert_eq!(verified["ok"], false, "{verified}");
}
