//! ADR-078 (multi-field entries) meets ADR-079 (durable seal and restore, the orphan
//! cold key, root rotation, staged approvals) — on a vault that lives on disk.
//!
//! The three features were built on separate branches that never saw each other, and
//! each one's own suite is green without the others. This file is what proves they
//! compose, on a vault `vault.init_*` made, restarted by building a fresh broker over
//! the same directories:
//!
//! * **seal -> restore is byte-identical for every kind of entry.** A multi-field
//!   entry (labels in two scripts, an empty label, a multi-line value, a TOTP seed, a
//!   type override, a masked override, an entry-level sensitivity override), a
//!   single-value entry and an alpha.6 raw-value entry all come back with the very
//!   envelope bytes they went in with, the same `entry.get` / `entry.reveal` answers,
//!   the same manifest row and a TOTP code that still computes. Between the two, the
//!   orphan copy of each is the *same payload kind* (a document stays a document, a
//!   raw value stays a raw value), carries the same plaintext as the original (opened
//!   with the cold key — the one path the ADR allows), and has a row whose digest is
//!   the digest of the bytes actually there and whose field count and TOTP flag are the
//!   entry's own.
//! * **seal -> rotate_root -> restore works.** The rotation re-wraps the archived node
//!   key and the cold key; nothing about a field document is touched by it, and it
//!   still restores byte-identical and reveals the same fields.
//! * **a field op on the Orphaned node is refused by R0, and changes nothing.** Every
//!   op that reads or writes an entry's fields — including the ones that did not
//!   exist when R0 was written — is shown to be refused for the owner, with the same
//!   params succeeding on the live node (so it is the node being refused, not the
//!   params), and the orphan's files and manifest are shown not to move.
//! * **an approved reveal of a multi-field entry on a live vault stages the document,
//!   not a string.** ADR-079 decrypts at decide time and the retry derives no key;
//!   ADR-078 narrows by `fieldIds` at the retry. Both hold at once, and a lock between
//!   the two still drops the staged document and releases nothing.
//!
//! Every value and label below is a generated fixture, never a real secret.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use secrecy::{ExposeSecret, SecretBox};
use serde_json::{json, Value};

use credmgr_brokerd::ops;
use credmgr_brokerd::peer::PeerInfo;
use credmgr_brokerd::protocol::{OpError, Request};
use credmgr_brokerd::scope::BrokerScope;
use credmgr_brokerd::server;
use credmgr_brokerd::state::BrokerState;
use credmgr_core::access::Origin;
use credmgr_core::envelope::{self, PayloadKind};
use credmgr_core::inference::EntryType;
use credmgr_core::keys::{unwrap_node_key, WrappedNodeKey};
use credmgr_core::registry::{Capability, GLOBAL_ID, ORPHAN_ID};
use credmgr_core::{cold, fields};
use credmgr_keystore::software::SoftwareKeystore;
use credmgr_keystore::{KeystoreId, PlatformKeystore, WrappedKey};
use credmgr_store::manifest::{ManifestEntry, Sensitivity};
use credmgr_store::paths::VaultPaths;

const NOW: i64 = 1_800_000_000;
const DAY: i64 = 24 * 60 * 60;
const PASSPHRASE: &str = "correct horse battery staple";
/// 32 base32 characters: a 160-bit TOTP seed.
const SEED: &str = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
/// A value a text box can hold and a lazy serialiser can break: newlines, a tab,
/// trailing spaces, two scripts and a symbol.
const MULTILINE: &str = "line one\nline two, trailing spaces   \n\tindented\nüñí-çødé ✓ 日本語\n";
const LEGACY_ID: &str = "e_legacy0";
const LEGACY_VALUE: &str = "legacy-raw-value-1";
const SINGLE_VALUE: &str = "tok-joint-single-1";

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

fn peer(cwd: Option<&str>) -> PeerInfo {
    PeerInfo {
        uid: 501,
        pid: 1,
        cwd: cwd.map(str::to_string),
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

fn ok(state: &BrokerState, scope: &BrokerScope, now: i64, op: &str, params: Value) -> Value {
    call(state, scope, now, op, params).unwrap_or_else(|e| panic!("{op} should succeed: {e:?}"))
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
    let begin = ok(
        &state,
        &anyone(),
        NOW,
        "vault.init_begin",
        json!({ "passphrase": PASSPHRASE }),
    );
    let code = begin["recoveryCode"].as_str().unwrap().to_string();
    ok(
        &state,
        &anyone(),
        NOW,
        "vault.init_confirm",
        json!({ "recoveryCode": code }),
    );
    (env, state)
}

/// A login: unlock, then resolve the minted token to the owner's scope.
fn login(state: &BrokerState) -> BrokerScope {
    let token = unlock_token(state);
    let registry = state.registry.read().unwrap().clone();
    credmgr_brokerd::scope::resolve_scope(&registry, &state.tokens, &peer(None), Some(&token)).0
}

fn unlock_token(state: &BrokerState) -> String {
    ok(
        state,
        &anyone(),
        NOW,
        "vault.unlock",
        json!({ "passphrase": PASSPHRASE }),
    )["token"]
        .as_str()
        .expect("a real login mints a token")
        .to_string()
}

fn passphrase() -> SecretBox<String> {
    SecretBox::new(Box::new(PASSPHRASE.to_string()))
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

fn assert_verify_ok(state: &BrokerState, owner: &BrokerScope, when: &str) {
    let v = ok(state, owner, NOW, "maintenance.verify", json!({}));
    assert_eq!(v["ok"], true, "maintenance.verify {when}: {v}");
}

fn node_ids(state: &BrokerState, owner: &BrokerScope) -> Vec<String> {
    let mut ids: Vec<String> = ok(state, owner, NOW, "node.list", json!({}))["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|n| n.as_str().map(str::to_string))
        .collect();
    ids.sort();
    ids
}

fn manifest_row(state: &BrokerState, node: &str, entry: &str) -> ManifestEntry {
    state
        .manifests
        .read()
        .unwrap()
        .get(node)
        .and_then(|b| b.entries.iter().find(|e| e.id == entry).cloned())
        .unwrap_or_else(|| panic!("{node} has no manifest row for {entry}"))
}

fn expected_code(seed: &str) -> String {
    credmgr_core::totp::Totp::from_stored_secret(
        seed,
        credmgr_core::totp::TotpAlgorithm::Sha1,
        credmgr_core::totp::DEFAULT_DIGITS,
        credmgr_core::totp::DEFAULT_PERIOD,
    )
    .unwrap()
    .code(NOW as u64)
}

// ---------------------------------------------------------------------------
// The scene: project `acme` holding one entry of each kind
// ---------------------------------------------------------------------------

struct Seeded {
    env: Env,
    state: Arc<BrokerState>,
    owner: BrokerScope,
    /// A seven-field entry (see `seeded`).
    multi: String,
    /// A single-value entry made by `entry.create` with `value` — a version-2 document of one field.
    single: String,
}

impl Seeded {
    /// Every entry id in the scene, in a stable order.
    fn ids(&self) -> [&str; 3] {
        [&self.multi, &self.single, LEGACY_ID]
    }
}

fn seeded() -> Seeded {
    let (env, state) = created();
    let owner = login(&state);
    let paths = env.paths();
    ok(
        &state,
        &owner,
        NOW,
        "node.create",
        json!({ "id": "acme", "label": "Acme", "parentId": GLOBAL_ID }),
    );

    let multi = ok(
        &state,
        &owner,
        NOW,
        "entry.create",
        json!({
            "node": "acme",
            "name": "PROD_DB",
            "sensitivity": "critical",
            "fields": [
                { "label": "host", "value": "db-7f3a.joint.test", "masked": true },
                { "label": "username", "value": "svc_joint" },
                { "label": "password", "value": "pw-5c1e90ab" },
                { "label": "port", "value": "5432", "type": "port" },
                { "label": "otp", "value": SEED },
                { "label": "ключ ✓", "value": MULTILINE },
                { "label": "", "value": "an unlabelled value" }
            ]
        }),
    )["entry"]
        .as_str()
        .unwrap()
        .to_string();
    let single = ok(
        &state,
        &owner,
        NOW,
        "entry.create",
        json!({ "node": "acme", "name": "API_TOKEN", "value": SINGLE_VALUE }),
    )["entry"]
        .as_str()
        .unwrap()
        .to_string();

    // An alpha.6-shaped entry: a raw value sealed as a version-1 envelope, with the
    // manifest row the old build would have written for it.
    let node_pub = state.node_public_key("acme").expect("acme's public key");
    let legacy =
        envelope::seal(LEGACY_VALUE.as_bytes(), &node_pub, "acme", LEGACY_ID).expect("seal v1");
    credmgr_store::atomic::write(&paths.entry_env("acme", LEGACY_ID), &legacy).unwrap();
    state.insert_manifest_entry(
        "acme",
        ManifestEntry {
            id: LEGACY_ID.to_string(),
            name: "FIXTURE_LEGACY_TOKEN".to_string(),
            r#ref: state.next_ref(),
            entry_type: EntryType::Other,
            sensitivity: Sensitivity::Low,
            field_count: 1,
            sha256: sha256_hex(&legacy),
            modified: NOW,
            expires_at: None,
            rotated_at: None,
            has_totp: false,
        },
    );
    state.persist(NOW).expect("write the seeded vault through");

    let s = Seeded {
        env,
        state,
        owner,
        multi,
        single,
    };
    // The scene is what it claims to be before anything is done to it.
    assert_eq!(manifest_row(&s.state, "acme", &s.multi).field_count, 7);
    assert!(manifest_row(&s.state, "acme", &s.multi).has_totp);
    assert_eq!(s.state.manifests.read().unwrap()["acme"].counts.totp, 1);
    let versions: Vec<u8> = s
        .ids()
        .iter()
        .map(|id| std::fs::read(paths.entry_env("acme", id)).unwrap()[4])
        .collect();
    assert_eq!(
        versions,
        vec![2, 2, 1],
        "two field documents and one legacy value"
    );
    assert_verify_ok(&s.state, &s.owner, "on the seeded vault");
    s
}

// ---------------------------------------------------------------------------
// A snapshot of everything a person could observe about the three entries
// ---------------------------------------------------------------------------

struct Snap {
    envelopes: Vec<Vec<u8>>,
    reveals: Vec<Value>,
    gets: Vec<Value>,
    rows: Vec<Value>,
    counts_totp: u32,
    totp_code: String,
}

fn snap(state: &BrokerState, owner: &BrokerScope, paths: &VaultPaths, s: &Seeded) -> Snap {
    let mut out = Snap {
        envelopes: Vec::new(),
        reveals: Vec::new(),
        gets: Vec::new(),
        rows: Vec::new(),
        counts_totp: 0,
        totp_code: String::new(),
    };
    for id in s.ids() {
        out.envelopes
            .push(std::fs::read(paths.entry_env("acme", id)).unwrap());
        out.reveals.push(ok(
            state,
            owner,
            NOW,
            "entry.reveal",
            json!({ "node": "acme", "entry": id }),
        ));
        let mut get = ok(
            state,
            owner,
            NOW,
            "entry.get",
            json!({ "node": "acme", "entry": id }),
        );
        // The manifest generation counts commits; a restore is one. Everything else in
        // the answer is the entry's own and must not move.
        get.as_object_mut().unwrap().remove("generation");
        out.gets.push(get);
        out.rows
            .push(serde_json::to_value(manifest_row(state, "acme", id)).unwrap());
    }
    out.counts_totp = state.manifests.read().unwrap()["acme"].counts.totp;
    out.totp_code = ok(
        state,
        owner,
        NOW,
        "totp.code",
        json!({ "node": "acme", "entry": s.multi }),
    )["code"]
        .as_str()
        .unwrap()
        .to_string();
    out
}

fn assert_same(before: &Snap, after: &Snap, when: &str) {
    assert!(
        before.envelopes == after.envelopes,
        "{when}: an entry envelope is not byte-identical"
    );
    assert!(
        before.reveals == after.reveals,
        "{when}: entry.reveal answered differently"
    );
    assert!(
        before.gets == after.gets,
        "{when}: entry.get answered differently\n before: {:#?}\n after: {:#?}",
        before.gets,
        after.gets
    );
    assert!(
        before.rows == after.rows,
        "{when}: a manifest row changed\n before: {:#?}\n after: {:#?}",
        before.rows,
        after.rows
    );
    assert_eq!(before.counts_totp, after.counts_totp, "{when}: counts.totp");
    assert_eq!(before.totp_code, after.totp_code, "{when}: the TOTP code");
}

/// What the three entries hold, opened with the sealed node's own key — read before a
/// seal, from the files a seal is about to move.
fn plaintexts_with_the_node_key(env: &Env, s: &Seeded) -> Vec<(PayloadKind, Vec<u8>)> {
    let paths = env.paths();
    let rk = root_from_disk(env);
    let wrapped =
        WrappedNodeKey::from_bytes(&std::fs::read(paths.node_key("acme")).unwrap()).unwrap();
    let node_secret = unwrap_node_key(&rk, "acme", &wrapped).unwrap();
    s.ids()
        .iter()
        .map(|id| {
            let bytes = std::fs::read(paths.entry_env("acme", id)).unwrap();
            let (kind, plain) = envelope::open_any(&bytes, &node_secret, "acme", id).unwrap();
            (kind, plain.expose_secret().clone())
        })
        .collect()
}

/// What the orphan node's copy of each entry holds, opened with the cold key — the
/// one path the ADR allows (no op exposes it).
fn plaintexts_with_the_cold_key(env: &Env, s: &Seeded) -> Vec<(PayloadKind, Vec<u8>)> {
    let paths = env.paths();
    let rk = root_from_disk(env);
    let cold_secret =
        cold::open_orphan_cold(&rk, &std::fs::read(paths.orphan_key()).unwrap(), None)
            .expect("the cold key opens under the root");
    s.ids()
        .iter()
        .map(|id| {
            let bytes = std::fs::read(paths.entry_env(ORPHAN_ID, id)).unwrap();
            let (kind, plain) = envelope::open_any(&bytes, &cold_secret, ORPHAN_ID, id)
                .unwrap_or_else(|e| {
                    panic!("the cold key must open the orphan copy of {id}: {e:?}")
                });
            (kind, plain.expose_secret().clone())
        })
        .collect()
}

/// The orphan copies are the entries, re-encrypted: same payload kind, same plaintext,
/// a digest of the bytes actually there, and the entry's own projection.
fn assert_orphan_copies_are_the_entries(env: &Env, state: &BrokerState, s: &Seeded) {
    let paths = env.paths();
    let at_the_cold_key = plaintexts_with_the_cold_key(env, s);
    for (i, id) in s.ids().iter().enumerate() {
        let on_disk = std::fs::read(paths.entry_env(ORPHAN_ID, id)).unwrap();
        let row = manifest_row(state, ORPHAN_ID, id);
        assert_eq!(
            row.sha256,
            sha256_hex(&on_disk),
            "{id}: the orphan row's digest is the digest of the resealed bytes (ADR-067, F-b)"
        );
        let expect_version = match at_the_cold_key[i].0 {
            PayloadKind::FieldDocument => 2,
            PayloadKind::RawValue => 1,
        };
        assert_eq!(
            on_disk[4], expect_version,
            "{id}: the envelope's version byte"
        );
        if let PayloadKind::FieldDocument = at_the_cold_key[i].0 {
            let doc = fields::decode(&at_the_cold_key[i].1).expect("a stored document decodes");
            assert_eq!(
                row.field_count as usize,
                doc.fields.len(),
                "{id}: the orphan row's field count is the document's"
            );
            assert_eq!(
                row.has_totp,
                fields::project(&doc).has_totp,
                "{id}: the orphan row's TOTP flag is the document's"
            );
        }
    }
    assert_eq!(
        state.orphan_digest_mismatches().unwrap(),
        Vec::<String>::new(),
        "every orphan row verifies"
    );
    // The projection the sealed node showed is the one the orphan rows carry.
    let multi = manifest_row(state, ORPHAN_ID, &s.multi);
    assert_eq!(multi.field_count, 7);
    assert!(
        multi.has_totp,
        "the multi-field entry still counts as holding a TOTP seed"
    );
    assert_eq!(
        state.manifests.read().unwrap()[ORPHAN_ID].counts.totp,
        1,
        "and the orphan node's counts.totp agrees"
    );
}

fn seal(state: &BrokerState, owner: &BrokerScope, now: i64) -> Value {
    ok(state, owner, now, "node.seal", json!({ "node": "acme" }))
}

fn restore(state: &BrokerState, owner: &BrokerScope, now: i64) -> Value {
    ok(state, owner, now, "node.restore", json!({ "node": "acme" }))
}

// ---------------------------------------------------------------------------
// 1. seal -> (restart) -> restore, byte for byte
// ---------------------------------------------------------------------------

#[test]
fn a_multi_field_entry_in_a_sealed_node_comes_back_byte_identical() {
    let s = seeded();
    let paths = s.env.paths();
    let before = snap(&s.state, &s.owner, &paths, &s);
    let originals = plaintexts_with_the_node_key(&s.env, &s);
    assert_eq!(originals[0].0, PayloadKind::FieldDocument);
    assert_eq!(originals[1].0, PayloadKind::FieldDocument);
    assert_eq!(originals[2].0, PayloadKind::RawValue);
    // The multi-field document really carries every field the scene put in it.
    let doc = fields::decode(&originals[0].1).unwrap();
    assert_eq!(doc.fields.len(), 7);
    assert!(doc.fields.iter().any(|f| f.value == MULTILINE));
    assert!(doc.fields.iter().any(|f| f.label == "ключ ✓"));
    assert!(doc.fields.iter().any(|f| f.label.is_empty()));

    // --- seal ------------------------------------------------------------------
    let sealed = seal(&s.state, &s.owner, NOW);
    assert_eq!(sealed, json!({ "node": "acme", "sealed": true }));
    assert_eq!(node_ids(&s.state, &s.owner), vec!["global"]);
    for id in s.ids() {
        assert!(
            !paths.entry_env("acme", id).exists(),
            "{id}: the live envelope moved to the archive"
        );
    }
    assert_orphan_copies_are_the_entries(&s.env, &s.state, &s);
    // Re-encrypting is not editing: the orphan copy holds exactly the plaintext the
    // sealed node's copy held, of the same kind.
    assert_eq!(
        plaintexts_with_the_cold_key(&s.env, &s),
        originals,
        "the orphan copy is the same payload, re-encrypted"
    );
    assert_verify_ok(&s.state, &s.owner, "after the seal");

    // --- restart, then restore on day 6 -----------------------------------------
    let mut s = s;
    s.restart();
    assert_eq!(
        node_ids(&s.state, &s.owner),
        vec!["global"],
        "the seal survived the restart"
    );
    assert_orphan_copies_are_the_entries(&s.env, &s.state, &s);
    assert_verify_ok(&s.state, &s.owner, "after the restart, still sealed");

    let restored = restore(&s.state, &s.owner, NOW + 6 * DAY);
    assert_eq!(restored, json!({ "node": "acme", "restored": true }));
    assert_eq!(node_ids(&s.state, &s.owner), vec!["acme", "global"]);
    let after = snap(&s.state, &s.owner, &paths, &s);
    assert_same(&before, &after, "after seal, restart and restore");
    assert_eq!(
        after.totp_code,
        expected_code(SEED),
        "and the restored seed still computes the code"
    );
    for id in s.ids() {
        assert!(
            !paths.entry_env(ORPHAN_ID, id).exists(),
            "{id}: the orphan copy is gone after the restore"
        );
    }
    assert_verify_ok(&s.state, &s.owner, "after the restore");

    // --- and it is still the same after another restart --------------------------
    s.restart();
    let again = snap(&s.state, &s.owner, &paths, &s);
    assert_same(&before, &again, "after a second restart");
    assert_verify_ok(&s.state, &s.owner, "after the second restart");

    // The fields are live, not just readable: the restored entry takes an edit.
    let generation = ok(
        &s.state,
        &s.owner,
        NOW,
        "entry.list",
        json!({ "node": "acme" }),
    )["generation"]
        .as_u64()
        .unwrap();
    let added = ok(
        &s.state,
        &s.owner,
        NOW,
        "field.add",
        json!({ "node": "acme", "entry": s.multi, "generation": generation,
                "fields": [{ "label": "after-restore", "value": "added-after-restore" }] }),
    );
    assert_eq!(added["added"].as_array().unwrap().len(), 1);
    assert_eq!(
        manifest_row(&s.state, "acme", &s.multi).field_count,
        8,
        "an edit on a restored multi-field entry is an ordinary edit"
    );
    assert_verify_ok(&s.state, &s.owner, "after an edit on the restored entry");
}

impl Seeded {
    /// A restart: drop the broker, start a fresh one over the same vault, unlock.
    fn restart(&mut self) {
        let fresh = self.env.broker();
        drop(std::mem::replace(&mut self.state, fresh));
        self.owner = login(&self.state);
    }
}

// ---------------------------------------------------------------------------
// 2. seal -> rotate_root -> restore
// ---------------------------------------------------------------------------

fn seal_rotate_restore(restart_before_rotating: bool) {
    let mut s = seeded();
    let paths = s.env.paths();
    let before = snap(&s.state, &s.owner, &paths, &s);
    let originals = plaintexts_with_the_node_key(&s.env, &s);
    let node_key_before = std::fs::read(paths.node_key("acme")).unwrap();
    let root_wrap_before = std::fs::read(paths.root_wrap_pass()).unwrap();

    seal(&s.state, &s.owner, NOW);
    assert_orphan_copies_are_the_entries(&s.env, &s.state, &s);
    if restart_before_rotating {
        s.restart();
    }

    let outcome = s
        .state
        .rotate_root(passphrase(), NOW + 1)
        .expect("a rotation over a vault with a sealed multi-field node");
    assert!(outcome.skipped.is_empty(), "{:?}", outcome.skipped);
    assert_ne!(
        std::fs::read(paths.root_wrap_pass()).unwrap(),
        root_wrap_before,
        "the root key really was replaced"
    );

    // The rotation re-wrapped the cold key under the new root and left the keypair
    // alone: the orphan copies still open with it, and hold the same documents.
    assert_eq!(
        plaintexts_with_the_cold_key(&s.env, &s),
        originals,
        "the cold key opened under the NEW root still opens the orphan copies"
    );
    assert_eq!(
        s.state.orphan_digest_mismatches().unwrap(),
        Vec::<String>::new()
    );

    s.restart();
    assert_eq!(node_ids(&s.state, &s.owner), vec!["global"], "still sealed");
    assert_verify_ok(&s.state, &s.owner, "after the rotation, still sealed");

    restore(&s.state, &s.owner, NOW + DAY);
    assert_eq!(node_ids(&s.state, &s.owner), vec!["acme", "global"]);
    let after = snap(&s.state, &s.owner, &paths, &s);
    assert_same(&before, &after, "after seal, rotate_root and restore");
    assert_eq!(after.totp_code, expected_code(SEED));
    assert_ne!(
        std::fs::read(paths.node_key("acme")).unwrap(),
        node_key_before,
        "the restored node key is wrapped under the new root key (so the rotation reached the archive)"
    );
    // The envelopes are sealed to the node's PUBLIC key, which a rotation never changes:
    // byte-identical above is the proof; and the restored key must open them.
    assert_eq!(
        plaintexts_with_the_node_key(&s.env, &s),
        originals,
        "the restored node key opens the restored entries to the same plaintext"
    );
    assert_verify_ok(&s.state, &s.owner, "after the restore");

    s.restart();
    let again = snap(&s.state, &s.owner, &paths, &s);
    assert_same(&before, &again, "after a restart following the restore");
}

#[test]
fn seal_then_rotate_root_then_restore_keeps_every_field() {
    seal_rotate_restore(false);
}

#[test]
fn seal_then_restart_then_rotate_root_then_restore_keeps_every_field() {
    seal_rotate_restore(true);
}

// ---------------------------------------------------------------------------
// 3. field ops on the Orphaned node are refused (R0), and change nothing
// ---------------------------------------------------------------------------

/// One request that touches an entry's fields (or makes one), with params that are
/// well-formed for `node`/`entry` as given.
struct Case {
    op: &'static str,
    params: Value,
}

/// Every op that reads or writes an entry's fields, built for `node`/`entry`. `ids` is
/// every field id the entry holds, in order (at least two): the ops that name one field
/// name the first, and a reorder lists them all, reversed.
fn field_cases(node: &str, entry: &str, generation: u64, ids: &[String]) -> Vec<Case> {
    let field = ids[0].as_str();
    let reversed: Vec<&String> = ids.iter().rev().collect();
    let case = |op, params| Case { op, params };
    vec![
        case("entry.get", json!({ "node": node, "entry": entry })),
        case("entry.reveal", json!({ "node": node, "entry": entry })),
        case(
            "entry.reveal",
            json!({ "node": node, "entry": entry, "fieldIds": [field] }),
        ),
        case(
            "entry.update",
            json!({ "node": node, "entry": entry, "generation": generation,
                    "fields": [{ "id": field, "label": "x", "value": "y" }] }),
        ),
        case(
            "entry.update",
            json!({ "node": node, "entry": entry, "generation": generation,
                    "field": field, "value": "y" }),
        ),
        case(
            "entry.rotate",
            json!({ "node": node, "entry": entry, "generation": generation,
                    "field": field, "value": "rotated-value-1" }),
        ),
        case(
            "field.add",
            json!({ "node": node, "entry": entry, "generation": generation,
                    "fields": [{ "label": "extra", "value": "extra-value" }] }),
        ),
        case(
            "field.update",
            json!({ "node": node, "entry": entry, "generation": generation,
                    "field": field, "patch": { "value": "patched" } }),
        ),
        case(
            "field.reorder",
            json!({ "node": node, "entry": entry, "generation": generation,
                    "order": reversed }),
        ),
        case(
            "field.remove",
            json!({ "node": node, "entry": entry, "generation": generation, "field": field }),
        ),
        case(
            "entry.create",
            json!({ "node": node, "name": "FIELDS_NEW",
                    "fields": [{ "label": "a", "value": "1" }, { "label": "b", "value": "2" }] }),
        ),
        case(
            "entry.create_batch",
            json!({ "node": node, "entries": [
                { "name": "BATCH_ONE", "fields": [{ "label": "a", "value": "1" }] }
            ] }),
        ),
        case(
            "totp.code",
            json!({ "node": node, "entry": entry, "field": field }),
        ),
        case(
            "totp.seed",
            json!({ "node": node, "entry": entry, "field": field }),
        ),
        case(
            "entry.remove",
            json!({ "node": node, "entry": entry, "generation": generation }),
        ),
    ]
}

fn orphan_files(env: &Env, s: &Seeded) -> Vec<Vec<u8>> {
    let paths = env.paths();
    s.ids()
        .iter()
        .map(|id| std::fs::read(paths.entry_env(ORPHAN_ID, id)).unwrap())
        .collect()
}

fn orphan_manifest(state: &BrokerState) -> Value {
    serde_json::to_value(&state.manifests.read().unwrap()[ORPHAN_ID]).unwrap()
}

#[test]
fn field_ops_on_the_orphaned_node_are_refused_by_r0_and_change_nothing() {
    let mut s = seeded();
    let paths = s.env.paths();

    // Two field ids of the multi-field entry, read before the seal takes the node away.
    let got = ok(
        &s.state,
        &s.owner,
        NOW,
        "entry.get",
        json!({ "node": "acme", "entry": s.multi }),
    );
    let field_ids: Vec<String> = got["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["id"].as_str().unwrap().to_string())
        .collect();

    seal(&s.state, &s.owner, NOW);
    // Run the whole table on the broker that sealed, and again after a restart.
    for round in ["right after the seal", "after a restart"] {
        if round == "after a restart" {
            s.restart();
        }
        let files_before = orphan_files(&s.env, &s);
        let manifest_before = orphan_manifest(&s.state);
        let generation = manifest_before["generation"].as_u64().unwrap();

        // Every orphaned entry, not only the multi-field one: a single-value document
        // and an alpha.6 value are field-op targets too.
        for entry in s.ids() {
            for case in field_cases(ORPHAN_ID, entry, generation, &field_ids) {
                let refused = call(&s.state, &s.owner, NOW, case.op, case.params.clone())
                    .expect_err(&format!(
                        "{round}: {} on the Orphaned node must be refused for the owner",
                        case.op
                    ));
                assert!(
                    matches!(refused, OpError::NodeAccessDenied { rule: "R0", .. }),
                    "{round}: {} on the Orphaned node: expected R0, got {refused:?}",
                    case.op
                );
                // And nothing about the refusal says what the entry holds.
                let text = format!("{refused:?}");
                for secret in [SEED, "pw-5c1e90ab", "svc_joint", SINGLE_VALUE, LEGACY_VALUE] {
                    assert!(
                        !text.contains(secret),
                        "{round}: {} leaked a value",
                        case.op
                    );
                }
            }
        }
        assert!(
            orphan_files(&s.env, &s) == files_before,
            "{round}: a refused op moved an orphan envelope"
        );
        assert_eq!(
            orphan_manifest(&s.state),
            manifest_before,
            "{round}: a refused op moved the orphan manifest"
        );
        assert_verify_ok(&s.state, &s.owner, round);

        // The sealed node's own id is gone, and a field op naming it is no way in either:
        // whatever it is answered with, it is a refusal that carries no value. (Today the
        // answer is `node_locked` for an op that needs the node's key — a sealed id has
        // no hot key, the same as it had before multi-field entries — `not_found` for a
        // create into a node that does not exist, and `presence_required` for
        // `totp.seed`, which is refused on every transport.)
        for case in field_cases("acme", &s.multi, 1, &field_ids) {
            match call(&s.state, &s.owner, NOW, case.op, case.params.clone()) {
                Err(err) => {
                    assert!(
                        matches!(
                            err,
                            OpError::NotFound(_)
                                | OpError::NodeAccessDenied { .. }
                                | OpError::NodeLocked { .. }
                                | OpError::PresenceRequired { .. }
                        ),
                        "{round}: {} naming the sealed node: {err:?}",
                        case.op
                    );
                    let text = format!("{err:?}");
                    for secret in [SEED, "pw-5c1e90ab", "svc_joint"] {
                        assert!(
                            !text.contains(secret),
                            "{round}: {} leaked a value",
                            case.op
                        );
                    }
                }
                // ADR-073: a batch reports a failed item in its body rather than as an
                // error. Naming a node that is sealed away, it must have created nothing.
                Ok(body) => assert!(
                    case.op == "entry.create_batch"
                        && body["created"].as_array().is_some_and(Vec::is_empty)
                        && body["complete"] == false,
                    "{round}: {} naming the sealed node was accepted: {body}",
                    case.op
                ),
            }
        }
        assert!(
            !paths.node_dir("acme").exists(),
            "{round}: nothing recreated the sealed node's directory"
        );
    }

    // The control: the very same requests, aimed at the live node once it is restored, do
    // what they say — so what refused them above was the node, not their params.
    restore(&s.state, &s.owner, NOW + DAY);
    let placeholder_ids = ["f_00000001".to_string(), "f_00000002".to_string()];
    for index in 0..field_cases("acme", "x", 0, &placeholder_ids).len() {
        // A fresh three-field entry per request, so one op's edit cannot stale the next.
        let name = format!("SCRATCH_{index}");
        let created = ok(
            &s.state,
            &s.owner,
            NOW,
            "entry.create",
            json!({ "node": "acme", "name": name, "fields": [
                { "label": "one", "value": "1" },
                { "label": "two", "value": "2" },
                { "label": "seed", "value": SEED }
            ] }),
        );
        let entry = created["entry"].as_str().unwrap().to_string();
        let got = ok(
            &s.state,
            &s.owner,
            NOW,
            "entry.get",
            json!({ "node": "acme", "entry": entry }),
        );
        let ids: Vec<String> = got["fields"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["id"].as_str().unwrap().to_string())
            .collect();
        let generation = ok(
            &s.state,
            &s.owner,
            NOW,
            "entry.list",
            json!({ "node": "acme" }),
        )["generation"]
            .as_u64()
            .unwrap();
        let case = field_cases("acme", &entry, generation, &ids).remove(index);
        let answer = call(&s.state, &s.owner, NOW, case.op, case.params);
        if case.op == "totp.seed" {
            // The one op that is refused on every transport that exists (07 §6) — a
            // different refusal from R0, which is the point.
            assert!(
                matches!(answer, Err(OpError::PresenceRequired { .. })),
                "totp.seed on the live node: {answer:?}"
            );
        } else if case.op == "totp.code" {
            // `field` names the first field, which is not a seed: the answer is a
            // refusal about the VALUE, never about the node.
            assert!(
                !matches!(answer, Err(OpError::NodeAccessDenied { .. })),
                "totp.code on the live node: {answer:?}"
            );
        } else {
            assert!(
                answer.is_ok(),
                "{} on the live node should succeed with the params the Orphaned node refused: {answer:?}",
                case.op
            );
        }
    }
    assert_verify_ok(&s.state, &s.owner, "after the control run");
}

// ---------------------------------------------------------------------------
// 4. an approved reveal of a multi-field entry on a live vault
// ---------------------------------------------------------------------------

struct Live {
    env: Env,
    state: Arc<BrokerState>,
    owner: String,
    workdir: PathBuf,
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

fn send_owner(f: &Live, op: &str, params: Value) -> Value {
    let owner = f.owner.clone();
    send_at(f, NOW, None, Some(&owner), op, params)
        .unwrap_or_else(|e| panic!("{op} should succeed: {e:?}"))
}

/// The agent in acme's workdir asks, at `now`.
fn agent_at(f: &Live, now: i64, op: &str, params: Value) -> Result<Value, OpError> {
    let cwd = format!("{}/src", f.workdir.to_string_lossy());
    send_at(f, now, Some(&cwd), None, op, params)
}

const PW: &str = "pw-live-approved-1";
const HOST: &str = "host-live-approved.joint.test";
const LIVE_SEED: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

/// A durable vault, `acme` bound to a workdir, one multi-field entry in it, and the
/// *node* locked (the vault itself is not).
fn live_with_a_locked_node() -> (Live, String, Vec<String>) {
    let (env, state) = created();
    let workdir = env.state_dir.parent().unwrap().join("work").join("acme");
    std::fs::create_dir_all(workdir.join("src")).unwrap();
    // The broker stores and compares real paths; the temp directory may be a symlink.
    let workdir = std::fs::canonicalize(&workdir).unwrap();
    let owner = unlock_token(&state);
    let f = Live {
        env,
        state,
        owner,
        workdir,
    };
    send_owner(
        &f,
        "node.create",
        json!({ "id": "acme", "label": "Acme", "parentId": GLOBAL_ID,
                "workdirs": [f.workdir.to_string_lossy()] }),
    );
    let entry = send_owner(
        &f,
        "entry.create",
        json!({ "node": "acme", "name": "PROD_DB", "fields": [
            { "label": "host", "value": HOST },
            { "label": "password", "value": PW },
            { "label": "otp", "value": LIVE_SEED }
        ] }),
    )["entry"]
        .as_str()
        .unwrap()
        .to_string();
    let got = send_owner(&f, "entry.get", json!({ "node": "acme", "entry": entry }));
    let ids = got["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x["id"].as_str().unwrap().to_string())
        .collect();
    send_owner(&f, "vault.node_lock", json!({ "node": "acme" }));
    (f, entry, ids)
}

fn pending(answer: Result<Value, OpError>) -> String {
    match answer {
        Err(OpError::ApprovalPending { request, .. }) => request,
        other => panic!("expected approval_pending, got {other:?}"),
    }
}

#[test]
fn an_approved_reveal_stages_the_whole_document_and_the_retry_narrows_it() {
    let (f, entry, ids) = live_with_a_locked_node();
    let params = json!({ "node": "acme", "entry": entry, "fieldIds": [ids[1]] });

    let request = pending(agent_at(&f, NOW, "entry.reveal", params.clone()));
    assert_eq!(f.state.staged_approval_count_for_test(), 0);
    send_at(
        &f,
        NOW + 10,
        None,
        Some(&f.owner.clone()),
        "vault.approval_decide",
        json!({ "request": request, "approved": true }),
    )
    .expect("the owner approves");
    assert_eq!(
        f.state.staged_approval_count_for_test(),
        1,
        "the document was opened and staged when the human approved"
    );

    let revealed = agent_at(&f, NOW + 20, "entry.reveal", params.clone()).expect("the retry");
    assert!(!f.state.is_locked(), "approving did not lock the vault");
    assert_eq!(
        revealed["fields"].as_array().unwrap().len(),
        1,
        "only the field asked for"
    );
    assert_eq!(revealed["fields"][0]["id"], ids[1].as_str());
    assert_eq!(revealed["value"], PW);
    let text = revealed.to_string();
    assert!(
        !text.contains(HOST) && !text.contains(LIVE_SEED),
        "no other field's value came out"
    );
    assert_eq!(
        f.state.staged_approval_count_for_test(),
        0,
        "consumption drops the staged document"
    );

    // An approval covers the entry: a second request, for all of it, is its own cycle.
    let all = json!({ "node": "acme", "entry": entry });
    let again = pending(agent_at(&f, NOW + 30, "entry.reveal", all.clone()));
    send_at(
        &f,
        NOW + 31,
        None,
        Some(&f.owner.clone()),
        "vault.approval_decide",
        json!({ "request": again, "approved": true }),
    )
    .expect("approve the second");
    let everything = agent_at(&f, NOW + 32, "entry.reveal", all).expect("retry for all of it");
    assert_eq!(everything["fields"].as_array().unwrap().len(), 3);
    assert!(
        everything.get("value").is_none(),
        "`value` is the single-field shape; three fields come back as fields"
    );
    // the seed field is reported but never returned (audit P0-1)
    assert_eq!(everything["fields"][2]["value"], Value::Null);
    assert_eq!(everything["fields"][2]["redacted"], "totp_seed");
    assert!(!everything.to_string().contains(LIVE_SEED));
}

#[test]
fn a_malformed_field_id_in_the_retry_does_not_burn_the_humans_approval() {
    let (f, entry, ids) = live_with_a_locked_node();
    let good = json!({ "node": "acme", "entry": entry, "fieldIds": [ids[1]] });
    let request = pending(agent_at(&f, NOW, "entry.reveal", good.clone()));
    send_at(
        &f,
        NOW + 10,
        None,
        Some(&f.owner.clone()),
        "vault.approval_decide",
        json!({ "request": request, "approved": true }),
    )
    .expect("the owner approves");
    assert_eq!(f.state.staged_approval_count_for_test(), 1);

    // A retry that names a field the entry does not have is refused …
    let bad = json!({ "node": "acme", "entry": entry, "fieldIds": ["f_deadbeef"] });
    let refused = agent_at(&f, NOW + 20, "entry.reveal", bad).expect_err("an unknown field id");
    assert!(
        matches!(refused, OpError::NotFound(_)),
        "an unknown field id is not_found, got {refused:?}"
    );
    // … and the approval is still there: the human is not asked a second time.
    assert_eq!(
        f.state.staged_approval_count_for_test(),
        1,
        "the refusal consumed the one-time approval"
    );
    let revealed = agent_at(&f, NOW + 30, "entry.reveal", good).expect("the corrected retry");
    assert_eq!(revealed["value"], PW);
    assert_eq!(
        f.state.staged_approval_count_for_test(),
        0,
        "the successful retry consumes it"
    );
}

#[test]
fn a_lock_between_the_approval_and_the_retry_drops_the_staged_document_and_releases_nothing() {
    let (f, entry, _ids) = live_with_a_locked_node();
    let all = json!({ "node": "acme", "entry": entry });

    let request = pending(agent_at(&f, NOW, "entry.reveal", all.clone()));
    send_at(
        &f,
        NOW + 10,
        None,
        Some(&f.owner.clone()),
        "vault.approval_decide",
        json!({ "request": request, "approved": true }),
    )
    .expect("approve");
    assert_eq!(f.state.staged_approval_count_for_test(), 1);

    // The human walks away: the whole vault locks.
    f.state.lock();
    assert_eq!(
        f.state.staged_approval_count_for_test(),
        0,
        "a staged approval never survives a lock"
    );
    let retried = agent_at(&f, NOW + 20, "entry.reveal", all);
    let text = format!("{retried:?}");
    assert!(retried.is_err(), "nothing is released: {retried:?}");
    for value in [PW, HOST, LIVE_SEED] {
        assert!(!text.contains(value), "an error carried a field's value");
    }

    // The vault comes back and the entry is whole: the lock voided the approval, not the data.
    drop(f.state);
    let state = f.env.broker();
    let owner = login(&state);
    let revealed = ok(
        &state,
        &owner,
        NOW + 30,
        "entry.reveal",
        json!({ "node": "acme", "entry": entry }),
    );
    assert_eq!(revealed["fields"].as_array().unwrap().len(), 3);
    assert_eq!(revealed["fields"][1]["value"], PW);
}
