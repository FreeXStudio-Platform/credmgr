//! ADR-078 — multi-field entries through the real broker.
//!
//! Two fixtures. `Mem` is the in-memory shape the other lifecycle suites use
//! (`entry_lifecycle.rs`, `entry_undo.rs`): project "a" and "b", an orphan node,
//! a seeded root key, the vault unlocked — fast, and it can seed an alpha.6-shaped
//! *version-1* entry by sealing a raw value with `envelope::seal`, which is how the
//! compatibility tests stand in for a vault written by the previous build. `Disk`
//! is a real vault made by `vault.init_*` in a temp directory that a test can
//! "restart" (a fresh `BrokerState` over the same directory) and whose files a test
//! can read, tamper with and walk.
//!
//! Every value and label below is a generated fixture, never a real secret. There
//! is no field-name vocabulary here either: the labels are just words a person might
//! type, and the broker is shown to treat all of them alike.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use secrecy::SecretBox;
use serde_json::{json, Value};

use credmgr_brokerd::ops;
use credmgr_brokerd::peer::PeerInfo;
use credmgr_brokerd::protocol::{OpError, Request};
use credmgr_brokerd::scope::BrokerScope;
use credmgr_brokerd::server;
use credmgr_brokerd::state::BrokerState;
use credmgr_core::access::Origin;
use credmgr_core::envelope::{self, PayloadKind};
use credmgr_core::fields;
use credmgr_core::inference::EntryType;
use credmgr_core::registry::{
    Capability, Node, NodeKind, NodePolicy, Registry, GLOBAL_ID, ORPHAN_ID,
};
use credmgr_keystore::software::SoftwareKeystore;
use credmgr_store::manifest::{ManifestEntry, Sensitivity};
use credmgr_store::paths::VaultPaths;

const NOW: i64 = 1_800_000_000;
const PASSPHRASE: &str = "correct horse battery staple";
/// 32 base32 characters: an infer-as-TOTP-seed value of 160 bits.
const SEED: &str = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
/// A second, different 32-character seed.
const SEED_2: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

const ALL: &[Capability] = &[
    Capability::List,
    Capability::Read,
    Capability::Reveal,
    Capability::Create,
    Capability::Update,
    Capability::Notes,
    Capability::Admin,
];

fn project(id: &str) -> Node {
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

fn scope(node: &str, caps: &[Capability]) -> BrokerScope {
    BrokerScope {
        node_id: node.to_string(),
        capabilities: caps.to_vec(),
        origin: Origin::HumanUi,
        token_id: None,
        bound_workdir: None,
    }
}

fn malformed(err: OpError) -> String {
    match err {
        OpError::Malformed(m) => m,
        other => panic!("expected malformed_request, got {other:?}"),
    }
}

fn labels(fields: &Value) -> Vec<String> {
    fields
        .as_array()
        .expect("an array of fields")
        .iter()
        .map(|f| f["label"].as_str().expect("a label").to_string())
        .collect()
}

fn ids(v: &Value) -> Vec<String> {
    v.as_array()
        .expect("an array of ids")
        .iter()
        .map(|i| i.as_str().expect("an id").to_string())
        .collect()
}

/// The ids of the `fields` of an `entry.get` / `entry.reveal` answer, in order.
fn ids_of(answer: &Value) -> Vec<String> {
    answer["fields"]
        .as_array()
        .expect("an answer with fields")
        .iter()
        .map(|f| f["id"].as_str().expect("a field id").to_string())
        .collect()
}

/// A four-field "server" entry: host, username, password and a free-text note.
fn server_fields() -> Value {
    json!([
        { "label": "host", "value": "db-7f3a.fields.test" },
        { "label": "username", "value": "svc_fields" },
        { "label": "password", "value": "pw-9d2c41aa" },
        { "label": "notes", "value": "free text, with spaces" }
    ])
}

// ===========================================================================
// The in-memory fixture
// ===========================================================================

struct Mem {
    state: Arc<BrokerState>,
    token: String,
    _dir: tempfile::TempDir,
}

impl Mem {
    fn new() -> Mem {
        let dir = tempfile::tempdir().expect("tempdir");
        let keystore = Box::new(SoftwareKeystore::new(
            SecretBox::new(Box::new(PASSPHRASE.to_string())),
            dir.path().join("keystore-state"),
        ));
        let paths = VaultPaths::new(dir.path().join("vault"));
        let state = Arc::new(BrokerState::new(keystore, paths));
        let root_key = SecretBox::new(Box::new([7u8; 32]));
        state.seed_root_key(&root_key);

        let mut reg = Registry::new();
        reg.nodes.insert(GLOBAL_ID.to_string(), Node::global());
        reg.nodes.insert(ORPHAN_ID.to_string(), Node::orphan());
        reg.nodes.insert("a".to_string(), project("a"));
        reg.nodes.insert("b".to_string(), project("b"));
        state.set_registry(reg);
        state.seed_node_key(&root_key, ORPHAN_ID);
        state.seed_node_key(&root_key, "a");
        state.seed_node_key(&root_key, "b");
        state.unlock(0).expect("the fixture keystore unlocks");

        let token = state
            .tokens
            .issue("a", ALL.to_vec(), Origin::HumanUi, None)
            .id;
        Mem {
            state,
            token,
            _dir: dir,
        }
    }

    /// Direct dispatch at the fixed clock, as owner of node "a".
    fn d(&self, op: &str, params: Value) -> Result<Value, OpError> {
        ops::dispatch(&self.state, &scope("a", ALL), NOW, op, &params)
    }

    fn ok(&self, op: &str, params: Value) -> Value {
        self.d(op, params)
            .unwrap_or_else(|e| panic!("{op} should succeed: {e:?}"))
    }

    fn err(&self, op: &str, params: Value) -> OpError {
        match self.d(op, params) {
            Ok(v) => panic!("{op} should have been refused, got {v}"),
            Err(e) => e,
        }
    }

    /// Through the real request path (`server::handle_request`), which is the one
    /// call site that writes an audit record — the only way to obtain an id for
    /// `entry.undo`. Uses the real clock.
    fn call(&self, op: &str, params: Value) -> (Result<Value, OpError>, Option<String>) {
        server::handle_request(
            &self.state,
            &PeerInfo {
                uid: 501,
                pid: 1,
                cwd: None,
            },
            &Request {
                id: "r".to_string(),
                op: op.to_string(),
                token: Some(self.token.clone()),
                params,
            },
        )
    }

    fn gen(&self, node: &str) -> u64 {
        self.state
            .manifests
            .read()
            .unwrap()
            .get(node)
            .map_or(0, |b| b.generation)
    }

    fn manifest_entry(&self, node: &str, entry: &str) -> ManifestEntry {
        self.state
            .manifests
            .read()
            .unwrap()
            .get(node)
            .and_then(|b| b.entries.iter().find(|e| e.id == entry).cloned())
            .expect("the entry is in the manifest")
    }

    fn counts_totp(&self, node: &str) -> u32 {
        self.state.manifests.read().unwrap()[node].counts.totp
    }

    /// Create a multi-field entry on "a" and return its id.
    fn create(&self, name: &str, fields: Value) -> String {
        let v = self.ok(
            "entry.create",
            json!({ "node": "a", "name": name, "fields": fields }),
        );
        v["entry"].as_str().unwrap().to_string()
    }

    fn get(&self, entry: &str) -> Value {
        self.ok("entry.get", json!({ "node": "a", "entry": entry }))
    }

    fn reveal(&self, entry: &str) -> Value {
        self.ok("entry.reveal", json!({ "node": "a", "entry": entry }))
    }

    /// The raw envelope version byte on disk for an entry.
    fn version_byte(&self, node: &str, entry: &str) -> u8 {
        credmgr_store::atomic::read(&self.state.paths.entry_env(node, entry)).unwrap()[4]
    }

    /// An alpha.6-shaped entry: a raw value sealed as a version-1 envelope, with
    /// the manifest row the old inference would have written.
    fn seed_legacy(
        &self,
        node: &str,
        entry: &str,
        name: &str,
        value: &str,
        entry_type: EntryType,
        sensitivity: Sensitivity,
    ) {
        let node_pub = self.state.node_public_key(node).expect("node key");
        let sealed =
            envelope::seal(value.as_bytes(), &node_pub, node, entry).expect("seal a raw value");
        credmgr_store::atomic::write(&self.state.paths.entry_env(node, entry), &sealed).unwrap();
        self.state.insert_manifest_entry(
            node,
            ManifestEntry {
                id: entry.to_string(),
                name: name.to_string(),
                r#ref: self.state.next_ref(),
                entry_type,
                sensitivity,
                field_count: 1,
                sha256: envelope_digest(&sealed),
                modified: NOW,
                expires_at: None,
                rotated_at: None,
                has_totp: false,
            },
        );
    }
}

/// SHA-256 of `bytes` as lowercase hex (ADR-067's digest of an envelope).
fn envelope_digest(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    use std::fmt::Write;
    Sha256::digest(bytes)
        .iter()
        .fold(String::with_capacity(64), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

// ===========================================================================
// create / get / reveal
// ===========================================================================

#[test]
fn create_with_fields_then_get_and_reveal_all_and_a_subset() {
    let m = Mem::new();
    let created = m.ok(
        "entry.create",
        json!({ "node": "a", "name": "PROD_DB", "fields": server_fields() }),
    );
    assert_eq!(created["pending"], false);
    assert_eq!(created["fieldCount"], 4);
    let field_ids = ids(&created["fieldIds"]);
    assert_eq!(field_ids.len(), 4);
    assert!(created["generation"].as_u64().unwrap() >= 1);
    let entry = created["entry"].as_str().unwrap();
    for id in &field_ids {
        assert!(fields::is_valid_field_id(id), "{id}");
        assert_ne!(
            id,
            fields::LEGACY_FIELD_ID,
            "a minted id is never the legacy one"
        );
    }

    // entry.get: structure, never a value.
    let got = m.get(entry);
    assert_eq!(got["name"], "PROD_DB");
    assert_eq!(got["type"], "server");
    assert_eq!(got["sensitivity"], "high");
    assert_eq!(got["fieldCount"], 4);
    assert_eq!(got["hasTotp"], false);
    assert_eq!(got["rotatedAt"], Value::Null);
    assert_eq!(got["typeOverridden"], false);
    assert_eq!(got["sensitivityOverridden"], false);
    assert_eq!(
        labels(&got["fields"]),
        ["host", "username", "password", "notes"],
        "the user's order and labels, verbatim"
    );
    assert_eq!(ids_of(&got), field_ids);
    let by_label = |l: &str| {
        got["fields"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["label"] == l)
            .unwrap()
            .clone()
    };
    assert_eq!(by_label("host")["type"], "host");
    assert_eq!(by_label("host")["masked"], false);
    assert_eq!(by_label("password")["type"], "password");
    assert_eq!(by_label("password")["masked"], true);
    assert_eq!(by_label("notes")["type"], "text");
    let shown = got.to_string();
    for secret in [
        "db-7f3a.fields.test",
        "svc_fields",
        "pw-9d2c41aa",
        "free text",
    ] {
        assert!(!shown.contains(secret), "entry.get leaked a value: {shown}");
    }

    // reveal everything: every field, no single `value`.
    let all = m.reveal(entry);
    assert_eq!(all["fields"].as_array().unwrap().len(), 4);
    assert!(
        all.get("value").is_none(),
        "more than one field: no `value`"
    );
    assert_eq!(all["fields"][2]["label"], "password");
    assert_eq!(all["fields"][2]["value"], "pw-9d2c41aa");
    assert_eq!(all["fields"][3]["value"], "free text, with spaces");
    assert_eq!(all["fields"][2]["id"], field_ids[2].as_str());

    // a subset comes back in STORED order, whatever order it was asked for in.
    let subset = m.ok(
        "entry.reveal",
        json!({ "node": "a", "entry": entry, "fieldIds": [field_ids[2], field_ids[0]] }),
    );
    assert_eq!(labels(&subset["fields"]), ["host", "password"]);
    assert!(subset.get("value").is_none());
    // exactly one field: the single-value shape every old caller reads.
    let one = m.ok(
        "entry.reveal",
        json!({ "node": "a", "entry": entry, "fieldIds": [field_ids[2]] }),
    );
    assert_eq!(one["value"], "pw-9d2c41aa");
    assert_eq!(one["fields"].as_array().unwrap().len(), 1);
    // repeats are ignored
    let dup = m.ok(
        "entry.reveal",
        json!({ "node": "a", "entry": entry, "fieldIds": [field_ids[1], field_ids[1]] }),
    );
    assert_eq!(dup["value"], "svc_fields");

    // an unknown id: not_found, no partial answer. An empty list is malformed.
    let missing = m.err(
        "entry.reveal",
        json!({ "node": "a", "entry": entry, "fieldIds": [field_ids[0], "f_deadbeef"] }),
    );
    assert!(matches!(missing, OpError::NotFound(_)), "{missing:?}");
    malformed(m.err(
        "entry.reveal",
        json!({ "node": "a", "entry": entry, "fieldIds": [] }),
    ));
    // a label sent where an id belongs is not echoed back.
    let OpError::NotFound(msg) = m.err(
        "entry.reveal",
        json!({ "node": "a", "entry": entry, "fieldIds": ["marker-label-xyz"] }),
    ) else {
        panic!("expected not_found")
    };
    assert!(!msg.contains("marker-label-xyz"), "{msg}");

    // entry.get for an entry that is not there.
    assert!(matches!(
        m.err(
            "entry.get",
            json!({ "node": "a", "entry": "e_000000000000" })
        ),
        OpError::NotFound(_)
    ));
    // The manifest carries only the projection.
    let row = m.manifest_entry("a", entry);
    assert_eq!(row.field_count, 4);
    assert!(!row.has_totp);
}

#[test]
fn a_single_value_create_now_keeps_its_label() {
    let m = Mem::new();
    // A label that was always sent is now stored — it used to be thrown away.
    let a = m.ok(
        "entry.create",
        json!({ "node": "a", "name": "LABELLED", "value": "pw-1a2b3c4d", "label": "password" }),
    );
    let got = m.get(a["entry"].as_str().unwrap());
    assert_eq!(got["fieldCount"], 1);
    assert_eq!(got["fields"][0]["label"], "password");
    assert_eq!(got["fields"][0]["type"], "password");
    assert_eq!(got["fields"][0]["masked"], true);
    assert_eq!(got["sensitivity"], "high");

    // No label: the documented default, which is an ordinary stored label.
    let b = m.ok(
        "entry.create",
        json!({ "node": "a", "name": "BARE", "value": "some-bare-value" }),
    );
    let got = m.get(b["entry"].as_str().unwrap());
    assert_eq!(got["fields"][0]["label"], "value");
    // And it reads back as the single `value` it always did.
    let revealed = m.reveal(b["entry"].as_str().unwrap());
    assert_eq!(revealed["value"], "some-bare-value");
    assert_eq!(revealed["fields"][0]["label"], "value");

    // `value` and `fields` are alternatives; `label` goes with `value`.
    let both = malformed(m.err(
        "entry.create",
        json!({ "node": "a", "name": "X", "value": "v", "fields": [{ "label": "l", "value": "v" }] }),
    ));
    assert!(both.contains("not both"), "{both}");
    let neither = malformed(m.err("entry.create", json!({ "node": "a", "name": "X" })));
    assert!(
        neither.contains("params.value or params.fields"),
        "{neither}"
    );
    let stray = malformed(m.err(
        "entry.create",
        json!({ "node": "a", "name": "X", "label": "l", "fields": [{ "label": "l", "value": "v" }] }),
    ));
    assert!(
        stray.contains("params.label goes with params.value"),
        "{stray}"
    );
    malformed(m.err(
        "entry.create",
        json!({ "node": "a", "name": "X", "fields": [] }),
    ));
    // a field with a bad shape: refused, naming the index and never what it carried.
    let bad = malformed(m.err(
        "entry.create",
        json!({ "node": "a", "name": "X",
                "fields": [{ "label": "ok", "value": "v" }, { "label": 5, "value": "marker-value-xyz" }] }),
    ));
    assert!(bad.contains("fields[1]"), "{bad}");
    assert!(!bad.contains("marker-value-xyz"), "{bad}");
    let unknown_key = malformed(m.err(
        "entry.create",
        json!({ "node": "a", "name": "X", "fields": [{ "label": "l", "value": "v", "marker-key-xyz": 1 }] }),
    ));
    assert!(!unknown_key.contains("marker-key-xyz"), "{unknown_key}");
    // label rules: one line, no control characters, at most 200 characters.
    for label in ["two\nlines", "tab\there", "nul\u{0}byte"] {
        let e = malformed(m.err(
            "entry.create",
            json!({ "node": "a", "name": "X", "fields": [{ "label": label, "value": "v" }] }),
        ));
        assert!(e.contains("one line"), "{e}");
    }
    malformed(m.err(
        "entry.create",
        json!({ "node": "a", "name": "X", "fields": [{ "label": "l".repeat(201), "value": "v" }] }),
    ));
    // ...but there is no vocabulary: an empty label, a CJK label and a label that
    // looks like another field's name are all just labels.
    let odd = m.ok(
        "entry.create",
        json!({ "node": "a", "name": "ODD", "fields": [
            { "label": "", "value": "v1" }, { "label": "密码", "value": "v2" },
            { "label": "password", "value": "v3" }, { "label": "password", "value": "v4" }] }),
    );
    let got = m.get(odd["entry"].as_str().unwrap());
    assert_eq!(labels(&got["fields"]), ["", "密码", "password", "password"]);
}

#[test]
fn reveal_carries_value_only_when_one_field_is_returned() {
    let m = Mem::new();
    m.seed_legacy(
        "a",
        "e_old1",
        "OLD",
        "legacy-value-1",
        EntryType::Other,
        Sensitivity::Low,
    );
    // A legacy entry is one field with no label and the reserved legacy id.
    let revealed = m.reveal("e_old1");
    assert_eq!(revealed["value"], "legacy-value-1");
    assert_eq!(revealed["fields"].as_array().unwrap().len(), 1);
    assert_eq!(revealed["fields"][0]["id"], fields::LEGACY_FIELD_ID);
    assert_eq!(revealed["fields"][0]["label"], "");
    // The multi-field entry has none.
    let multi = m.create("MULTI", server_fields());
    assert!(m.reveal(&multi).get("value").is_none());
    // A single-field entry created now has both.
    let single = m.ok(
        "entry.create",
        json!({ "node": "a", "name": "SINGLE", "value": "single-value-1" }),
    );
    let r = m.reveal(single["entry"].as_str().unwrap());
    assert_eq!(r["value"], "single-value-1");
    assert_eq!(r["fields"][0]["value"], "single-value-1");
}

// ===========================================================================
// field.add / update / remove / reorder
// ===========================================================================

#[test]
fn field_add_update_remove_reorder_with_generation_conflicts() {
    let m = Mem::new();
    let entry = m.create("OPS", server_fields());
    let ids0 = ids_of(&m.get(&entry));

    // ---- field.add
    let g = m.gen("a");
    let stale = m.err(
        "field.add",
        json!({ "node": "a", "entry": entry, "generation": g + 7,
                "fields": [{ "label": "region", "value": "eu-west" }] }),
    );
    assert!(
        matches!(
            stale,
            OpError::Conflict { expected_generation, current_generation, .. }
                if expected_generation == g + 7 && current_generation == g
        ),
        "{stale:?}"
    );
    assert_eq!(m.gen("a"), g, "a refused add wrote nothing");
    let added = m.ok(
        "field.add",
        json!({ "node": "a", "entry": entry, "generation": g,
                "fields": [{ "label": "region", "value": "eu-west" }, { "label": "tier", "value": "gold" }] }),
    );
    assert_eq!(added["generation"], g + 1);
    assert_eq!(added["fieldCount"], 6);
    let added_ids = ids(&added["added"]);
    assert_eq!(added_ids.len(), 2);
    let all_ids = ids(&added["fieldIds"]);
    assert_eq!(&all_ids[..4], ids0.as_slice(), "appended, nothing replaced");
    assert_eq!(&all_ids[4..], added_ids.as_slice());
    // insert at a position
    let at0 = m.ok(
        "field.add",
        json!({ "node": "a", "entry": entry, "generation": m.gen("a"), "position": 0,
                "fields": [{ "label": "first", "value": "1st" }] }),
    );
    assert_eq!(ids(&at0["fieldIds"])[0], ids(&at0["added"])[0]);
    // position past the end, negative, and non-integer are refused
    for position in [json!(99), json!(-1), json!("0"), json!(1.5)] {
        malformed(m.err(
            "field.add",
            json!({ "node": "a", "entry": entry, "generation": m.gen("a"), "position": position,
                    "fields": [{ "label": "x", "value": "y" }] }),
        ));
    }
    // nothing to add / missing fields / a bad item
    malformed(m.err(
        "field.add",
        json!({ "node": "a", "entry": entry, "generation": m.gen("a"), "fields": [] }),
    ));
    malformed(m.err(
        "field.add",
        json!({ "node": "a", "entry": entry, "generation": m.gen("a") }),
    ));
    malformed(m.err(
        "field.add",
        json!({ "node": "a", "entry": entry, "generation": m.gen("a"),
                "fields": [{ "label": "bad\nlabel", "value": "y" }] }),
    ));

    // ---- field.update
    let target = ids0[1].clone(); // "username"
    let g = m.gen("a");
    assert!(matches!(
        m.err(
            "field.update",
            json!({ "node": "a", "entry": entry, "generation": g + 1, "field": target,
                    "patch": { "label": "login" } })
        ),
        OpError::Conflict { .. }
    ));
    let renamed = m.ok(
        "field.update",
        json!({ "node": "a", "entry": entry, "generation": g, "field": target,
                "patch": { "label": "login" } }),
    );
    assert_eq!(renamed["generation"], g + 1);
    let got = m.get(&entry);
    let row = got["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["id"] == target.as_str())
        .unwrap();
    assert_eq!(row["label"], "login", "the id is stable across a rename");
    // a new value
    m.ok(
        "field.update",
        json!({ "node": "a", "entry": entry, "generation": m.gen("a"), "field": target,
                "patch": { "value": "svc_renamed" } }),
    );
    let one = m.ok(
        "entry.reveal",
        json!({ "node": "a", "entry": entry, "fieldIds": [target] }),
    );
    assert_eq!(one["value"], "svc_renamed");
    // a pinned type, then "auto" clears it
    m.ok(
        "field.update",
        json!({ "node": "a", "entry": entry, "generation": m.gen("a"), "field": target,
                "patch": { "type": "api-key", "masked": false } }),
    );
    let got = m.get(&entry);
    let row = got["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["id"] == target.as_str())
        .unwrap()
        .clone();
    assert_eq!(row["type"], "api-key");
    assert_eq!(row["typeOverridden"], true);
    assert_eq!(row["masked"], false);
    assert_eq!(row["maskedOverridden"], true);
    m.ok(
        "field.update",
        json!({ "node": "a", "entry": entry, "generation": m.gen("a"), "field": target,
                "patch": { "type": "auto", "masked": "auto" } }),
    );
    let got = m.get(&entry);
    let row = got["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["id"] == target.as_str())
        .unwrap()
        .clone();
    assert_eq!(row["typeOverridden"], false);
    assert_eq!(row["maskedOverridden"], false);
    // refusals: an unknown field, an empty patch, an unknown key, a bad type, no patch
    assert!(matches!(
        m.err(
            "field.update",
            json!({ "node": "a", "entry": entry, "generation": m.gen("a"), "field": "f_deadbeef",
                    "patch": { "label": "x" } })
        ),
        OpError::NotFound(_)
    ));
    malformed(m.err(
        "field.update",
        json!({ "node": "a", "entry": entry, "generation": m.gen("a"), "field": target, "patch": {} }),
    ));
    let unk = malformed(m.err(
        "field.update",
        json!({ "node": "a", "entry": entry, "generation": m.gen("a"), "field": target,
                "patch": { "marker-key-xyz": 1 } }),
    ));
    assert!(!unk.contains("marker-key-xyz"), "{unk}");
    let badtype = malformed(m.err(
        "field.update",
        json!({ "node": "a", "entry": entry, "generation": m.gen("a"), "field": target,
                "patch": { "type": "marker-type-xyz" } }),
    ));
    assert!(!badtype.contains("marker-type-xyz"), "{badtype}");
    malformed(m.err(
        "field.update",
        json!({ "node": "a", "entry": entry, "generation": m.gen("a"), "field": target,
                "patch": { "masked": null, "type": null } }),
    ));
    let nopatch = malformed(m.err(
        "field.update",
        json!({ "node": "a", "entry": entry, "generation": m.gen("a"), "field": target }),
    ));
    assert!(nopatch.contains("params.patch is required"), "{nopatch}");

    // ---- field.reorder
    let current = ids_of(&m.get(&entry));
    let mut reversed = current.clone();
    reversed.reverse();
    let g = m.gen("a");
    assert!(matches!(
        m.err(
            "field.reorder",
            json!({ "node": "a", "entry": entry, "generation": g + 3, "order": reversed })
        ),
        OpError::Conflict { .. }
    ));
    let reordered = m.ok(
        "field.reorder",
        json!({ "node": "a", "entry": entry, "generation": g, "order": reversed }),
    );
    assert_eq!(ids(&reordered["fieldIds"]), reversed);
    assert_eq!(reordered["generation"], g + 1);
    // not an exact permutation: missing, repeated, unknown, extra
    let mut missing = reversed.clone();
    missing.pop();
    let mut repeated = reversed.clone();
    let second = repeated[1].clone();
    repeated[0] = second;
    let mut unknown = reversed.clone();
    unknown[0] = "f_deadbeef".to_string();
    let mut extra = reversed.clone();
    extra.push("f_deadbeef".to_string());
    for bad in [missing, repeated, unknown, extra] {
        malformed(m.err(
            "field.reorder",
            json!({ "node": "a", "entry": entry, "generation": m.gen("a"), "order": bad }),
        ));
    }
    malformed(m.err(
        "field.reorder",
        json!({ "node": "a", "entry": entry, "generation": m.gen("a") }),
    ));

    // ---- field.remove
    let g = m.gen("a");
    let before = current.len();
    assert!(matches!(
        m.err(
            "field.remove",
            json!({ "node": "a", "entry": entry, "generation": g + 2, "field": current[0] })
        ),
        OpError::Conflict { .. }
    ));
    let removed = m.ok(
        "field.remove",
        json!({ "node": "a", "entry": entry, "generation": g, "field": current[0] }),
    );
    assert_eq!(removed["fieldCount"], before - 1);
    assert!(!ids(&removed["fieldIds"]).contains(&current[0]));
    assert!(matches!(
        m.err(
            "field.remove",
            json!({ "node": "a", "entry": entry, "generation": m.gen("a"), "field": current[0] })
        ),
        OpError::NotFound(_)
    ));

    // ---- none of the four is a rotation
    assert_eq!(m.get(&entry)["rotatedAt"], Value::Null);
    // the manifest row follows the document
    assert_eq!(
        m.manifest_entry("a", &entry).field_count as usize,
        before - 1
    );
    // an entry that is not there
    assert!(matches!(
        m.err(
            "field.add",
            json!({ "node": "a", "entry": "e_000000000000", "generation": m.gen("a"),
                    "fields": [{ "label": "x", "value": "y" }] })
        ),
        OpError::NotFound(_)
    ));
}

#[test]
fn field_remove_refuses_the_last_field() {
    let m = Mem::new();
    let single = m.ok(
        "entry.create",
        json!({ "node": "a", "name": "LONELY", "value": "only-value-1", "label": "token" }),
    );
    let entry = single["entry"].as_str().unwrap();
    let only = ids(&single["fieldIds"]).remove(0);
    let g = m.gen("a");
    let msg = malformed(m.err(
        "field.remove",
        json!({ "node": "a", "entry": entry, "generation": g, "field": only }),
    ));
    assert!(msg.contains("keeps at least one field"), "{msg}");
    assert_eq!(m.gen("a"), g, "a refused removal wrote nothing");
    assert_eq!(m.reveal(entry)["value"], "only-value-1");
    // the same is true after fields were added and all but one removed
    let two = m.ok(
        "field.add",
        json!({ "node": "a", "entry": entry, "generation": g,
                "fields": [{ "label": "extra", "value": "extra-value-1" }] }),
    );
    let extra = ids(&two["added"]).remove(0);
    m.ok(
        "field.remove",
        json!({ "node": "a", "entry": entry, "generation": m.gen("a"), "field": extra }),
    );
    malformed(m.err(
        "field.remove",
        json!({ "node": "a", "entry": entry, "generation": m.gen("a"), "field": only }),
    ));
}

// ===========================================================================
// undo
// ===========================================================================

#[test]
fn every_field_op_is_undoable_and_undo_restores_field_count_and_counts_totp() {
    let m = Mem::new();
    let entry = m.create(
        "UNDOABLE",
        json!([{ "label": "host", "value": "h-1.fields.test" }, { "label": "user", "value": "svc_one" }]),
    );
    let ids0 = ids_of(&m.get(&entry));
    let undo = |audit: &str| {
        let (r, _) = m.call(
            "entry.undo",
            json!({ "node": "a", "id": audit, "generation": m.gen("a") }),
        );
        r.expect("entry.undo")
    };
    let base = m.manifest_entry("a", &entry);
    assert_eq!((base.field_count, base.has_totp), (2, false));
    assert_eq!(m.counts_totp("a"), 0);

    // ---- field.add of a TOTP seed, then undo: fieldCount, hasTotp and counts.totp come back
    let (r, add_audit) = m.call(
        "field.add",
        json!({ "node": "a", "entry": entry, "generation": m.gen("a"),
                "fields": [{ "label": "otp", "value": SEED }] }),
    );
    r.expect("field.add");
    let row = m.manifest_entry("a", &entry);
    assert_eq!((row.field_count, row.has_totp), (3, true));
    assert_eq!(
        m.counts_totp("a"),
        1,
        "an entry carrying a seed counts toward counts.totp"
    );
    undo(&add_audit.expect("a field op is audited"));
    let row = m.manifest_entry("a", &entry);
    assert_eq!(
        (row.field_count, row.has_totp),
        (2, false),
        "F5c: fieldCount restored"
    );
    assert_eq!(m.counts_totp("a"), 0);
    assert_eq!(
        row.rotated_at, None,
        "a field edit is not a rotation, nor is its undo"
    );
    assert_eq!(m.reveal(&entry)["fields"].as_array().unwrap().len(), 2);

    // ---- undo of the undo: the redo takes the same branch
    let tail = m.ok("audit.tail", json!({ "limit": 50 }));
    let system_line = tail["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["action"] == "field.add" && r["actor"] == "system:entry.undo")
        .expect("undo_rotate records its line under the ORIGINAL action")["id"]
        .as_str()
        .unwrap()
        .to_string();
    undo(&system_line);
    let row = m.manifest_entry("a", &entry);
    assert_eq!((row.field_count, row.has_totp), (3, true), "the redo");
    assert_eq!(m.counts_totp("a"), 1);

    // ---- field.update, field.remove, field.reorder: each undone to the value / set / order before
    let before = m.reveal(&entry);
    let (r, upd) = m.call(
        "field.update",
        json!({ "node": "a", "entry": entry, "generation": m.gen("a"), "field": ids0[0],
                "patch": { "value": "h-2.fields.test" } }),
    );
    r.expect("field.update");
    assert_eq!(
        m.ok(
            "entry.reveal",
            json!({ "node": "a", "entry": entry, "fieldIds": [ids0[0]] })
        )["value"],
        "h-2.fields.test"
    );
    undo(&upd.unwrap());
    assert_eq!(m.reveal(&entry), before);

    let (r, rm) = m.call(
        "field.remove",
        json!({ "node": "a", "entry": entry, "generation": m.gen("a"), "field": ids0[1] }),
    );
    r.expect("field.remove");
    assert_eq!(m.manifest_entry("a", &entry).field_count, 2);
    undo(&rm.unwrap());
    assert_eq!(
        m.reveal(&entry),
        before,
        "the removed field is back, with its id and value"
    );
    assert_eq!(m.manifest_entry("a", &entry).field_count, 3);

    let mut order = ids_of(&before);
    order.reverse();
    let (r, mv) = m.call(
        "field.reorder",
        json!({ "node": "a", "entry": entry, "generation": m.gen("a"), "order": order }),
    );
    r.expect("field.reorder");
    assert_ne!(m.reveal(&entry), before);
    undo(&mv.unwrap());
    assert_eq!(m.reveal(&entry), before);

    // ---- entry.update keeps no history, and says so
    let (r, up) = m.call(
        "entry.update",
        json!({ "node": "a", "entry": entry, "generation": m.gen("a"), "field": ids0[0], "value": "h-3" }),
    );
    r.expect("entry.update");
    let (r, _) = m.call(
        "entry.undo",
        json!({ "node": "a", "id": up.unwrap(), "generation": m.gen("a") }),
    );
    let Err(OpError::NotUndoable { reason, .. }) = r else {
        panic!("entry.update is not undoable")
    };
    assert!(reason.contains("field.add"), "{reason}");

    // ---- a rotation DOES stamp rotatedAt; its undo does too (as before)
    let (r, rot) = m.call(
        "entry.rotate",
        json!({ "node": "a", "entry": entry, "generation": m.gen("a"), "field": ids0[0], "value": "h-4" }),
    );
    r.expect("entry.rotate");
    assert!(m.manifest_entry("a", &entry).rotated_at.is_some());
    undo(&rot.unwrap());
    assert!(m.manifest_entry("a", &entry).rotated_at.is_some());
}

// ===========================================================================
// update / rotate bodies
// ===========================================================================

#[test]
fn update_value_on_a_multi_field_entry_without_field_is_refused() {
    let m = Mem::new();
    let entry = m.create("AMBIG", server_fields());
    let field_ids = ids_of(&m.get(&entry));
    for op in ["entry.update", "entry.rotate"] {
        let g = m.gen("a");
        let msg = malformed(m.err(
            op,
            json!({ "node": "a", "entry": entry, "generation": g, "value": "x" }),
        ));
        assert_eq!(msg, "entry has 4 fields; pass params.field", "{op}");
        assert_eq!(m.gen("a"), g, "{op}: a refused edit wrote nothing");
    }
    // naming the field works, for both; and the other fields are untouched
    let r = m.ok(
        "entry.update",
        json!({ "node": "a", "entry": entry, "generation": m.gen("a"),
                "field": field_ids[2], "value": "pw-new-1" }),
    );
    assert_eq!(r["fieldCount"], 4);
    let r = m.ok(
        "entry.rotate",
        json!({ "node": "a", "entry": entry, "generation": m.gen("a"),
                "field": field_ids[2], "value": "pw-new-2", "label": "passphrase" }),
    );
    assert_eq!(r["rotatedAt"], NOW);
    let revealed = m.reveal(&entry);
    assert_eq!(revealed["fields"][2]["value"], "pw-new-2");
    assert_eq!(
        revealed["fields"][2]["label"], "passphrase",
        "label renames that field"
    );
    assert_eq!(revealed["fields"][0]["value"], "db-7f3a.fields.test");
    // an unknown field
    assert!(matches!(
        m.err(
            "entry.update",
            json!({ "node": "a", "entry": entry, "generation": m.gen("a"),
                    "field": "f_deadbeef", "value": "x" })
        ),
        OpError::NotFound(_)
    ));
    // shape rules
    for (body, needle) in [
        (json!({}), "give params.value"),
        (json!({ "label": "l" }), "give params.value"),
        (json!({ "field": field_ids[0] }), "give params.value"),
        (
            json!({ "label": "l", "entryType": "note" }),
            "go with params.value",
        ),
        (
            json!({ "field": field_ids[0], "sensitivity": "high" }),
            "go with params.value",
        ),
        (
            json!({ "fields": [{ "label": "a", "value": "b" }], "value": "x" }),
            "cannot be combined",
        ),
        (
            json!({ "fields": [{ "label": "a", "value": "b" }], "field": field_ids[0] }),
            "cannot be combined",
        ),
    ] {
        let mut params = json!({ "node": "a", "entry": entry, "generation": m.gen("a") });
        for (k, v) in body.as_object().unwrap() {
            params[k] = v.clone();
        }
        let msg = malformed(m.err("entry.update", params));
        assert!(msg.contains(needle), "{needle}: {msg}");
    }
}

#[test]
fn update_fields_keeps_given_ids_and_drops_the_rest() {
    let m = Mem::new();
    let entry = m.create("REPLACED", server_fields());
    let got = m.get(&entry);
    let old: Vec<String> = got["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["id"].as_str().unwrap().to_string())
        .collect();
    // keep "password" (renamed, new value), drop the other three, add one new.
    let r = m.ok(
        "entry.update",
        json!({ "node": "a", "entry": entry, "generation": m.gen("a"), "fields": [
            { "id": old[2], "label": "pass", "value": "pw-replaced-1" },
            { "label": "region", "value": "eu-west" }] }),
    );
    let new_ids = ids(&r["fieldIds"]);
    assert_eq!(new_ids.len(), 2);
    assert_eq!(new_ids[0], old[2], "a given id keeps the field's identity");
    assert!(
        !old.contains(&new_ids[1]),
        "a new field gets a fresh id, never a recycled one"
    );
    let revealed = m.reveal(&entry);
    assert_eq!(labels(&revealed["fields"]), ["pass", "region"]);
    assert_eq!(m.manifest_entry("a", &entry).field_count, 2);
    // ids must exist, and be named at most once
    assert!(matches!(
        m.err(
            "entry.update",
            json!({ "node": "a", "entry": entry, "generation": m.gen("a"),
                    "fields": [{ "id": "f_deadbeef", "label": "x", "value": "y" }] })
        ),
        OpError::NotFound(_)
    ));
    malformed(m.err(
        "entry.update",
        json!({ "node": "a", "entry": entry, "generation": m.gen("a"), "fields": [
            { "id": old[2], "label": "x", "value": "y" }, { "id": old[2], "label": "z", "value": "w" }] }),
    ));
    // a fields item may carry an id and the usual keys, and nothing else
    malformed(m.err(
        "entry.update",
        json!({ "node": "a", "entry": entry, "generation": m.gen("a"),
                "fields": [{ "label": "x", "value": "y", "marker-key-xyz": true }] }),
    ));
    // an empty replacement is not "remove everything"
    malformed(m.err(
        "entry.update",
        json!({ "node": "a", "entry": entry, "generation": m.gen("a"), "fields": [] }),
    ));
    // rotate takes the same body, and keeps history (so it is undoable)
    let before = m.gen("a");
    m.ok(
        "entry.rotate",
        json!({ "node": "a", "entry": entry, "generation": before,
                "fields": [{ "id": old[2], "label": "pass", "value": "pw-rotated-1" }] }),
    );
    assert!(
        credmgr_store::atomic::read(&m.state.paths.entry_history_env("a", &entry, before)).is_ok(),
        "the pre-rotate envelope was retained"
    );
}

// ===========================================================================
// overrides, notes
// ===========================================================================

#[test]
fn overrides_stick_and_auto_clears() {
    let m = Mem::new();
    let created = m.ok(
        "entry.create",
        json!({ "node": "a", "name": "OVERRIDDEN", "entryType": "server", "sensitivity": "critical",
                "fields": [{ "label": "x", "value": "plain text value" }] }),
    );
    let entry = created["entry"].as_str().unwrap().to_string();
    let got = m.get(&entry);
    assert_eq!(
        (got["type"].as_str(), got["typeOverridden"].as_bool()),
        (Some("server"), Some(true))
    );
    assert_eq!(
        (
            got["sensitivity"].as_str(),
            got["sensitivityOverridden"].as_bool()
        ),
        (Some("critical"), Some(true))
    );
    let row = m.manifest_entry("a", &entry);
    assert_eq!(
        (row.entry_type, row.sensitivity),
        (EntryType::Server, Sensitivity::Critical)
    );

    // editing a value does not clear what the user chose
    m.ok(
        "entry.update",
        json!({ "node": "a", "entry": entry, "generation": m.gen("a"), "value": "another plain text" }),
    );
    let got = m.get(&entry);
    assert_eq!(got["type"], "server");
    assert_eq!(got["sensitivity"], "critical");

    // "auto" clears them: back to what the fields say
    m.ok(
        "entry.update",
        json!({ "node": "a", "entry": entry, "generation": m.gen("a"),
                "entryType": "auto", "sensitivity": "auto" }),
    );
    let got = m.get(&entry);
    assert_eq!(
        (got["type"].as_str(), got["typeOverridden"].as_bool()),
        (Some("other"), Some(false))
    );
    assert_eq!(
        (
            got["sensitivity"].as_str(),
            got["sensitivityOverridden"].as_bool()
        ),
        (Some("low"), Some(false))
    );

    // metadata-only update: no value needed
    m.ok(
        "entry.update",
        json!({ "node": "a", "entry": entry, "generation": m.gen("a"), "entryType": "wallet" }),
    );
    assert_eq!(m.get(&entry)["type"], "wallet");

    // JSON null is refused (the bridge drops nulls, so it could never mean "clear"); so is nonsense
    for body in [
        json!({ "entryType": null, "value": "x" }),
        json!({ "sensitivity": null, "value": "x" }),
        json!({ "entryType": "marker-type-xyz", "value": "x" }),
        json!({ "sensitivity": "severe", "value": "x" }),
    ] {
        let mut params = json!({ "node": "a", "entry": entry, "generation": m.gen("a") });
        for (k, v) in body.as_object().unwrap() {
            params[k] = v.clone();
        }
        let msg = malformed(m.err("entry.update", params));
        assert!(!msg.contains("marker-type-xyz"), "{msg}");
    }

    // a field-level pin outlives a value change; "auto" releases it
    let fid = ids_of(&m.get(&entry)).remove(0);
    m.ok(
        "field.update",
        json!({ "node": "a", "entry": entry, "generation": m.gen("a"), "field": fid,
                "patch": { "type": "api-key" } }),
    );
    m.ok(
        "field.update",
        json!({ "node": "a", "entry": entry, "generation": m.gen("a"), "field": fid,
                "patch": { "value": "still just words" } }),
    );
    let f0 = m.get(&entry)["fields"][0].clone();
    assert_eq!(
        (f0["type"].as_str(), f0["masked"].as_bool()),
        (Some("api-key"), Some(true))
    );
    m.ok(
        "field.update",
        json!({ "node": "a", "entry": entry, "generation": m.gen("a"), "field": fid,
                "patch": { "type": "auto" } }),
    );
    assert_eq!(m.get(&entry)["fields"][0]["type"], "text");
    // the manifest row (sensitivity) follows the fields once nothing is pinned...
    m.ok(
        "entry.update",
        json!({ "node": "a", "entry": entry, "generation": m.gen("a"), "entryType": "auto" }),
    );
    // ...and a pinned api-key made it `high`, which is gone again with the pin
    assert_eq!(m.manifest_entry("a", &entry).sensitivity, Sensitivity::Low);
}

#[test]
fn note_entry_type_and_the_note_only_alias() {
    let m = Mem::new();
    // The design's note: an entry with one free-text field, entry type `note`.
    let n = m.ok(
        "entry.create",
        json!({ "node": "a", "name": "A NOTE", "entryType": "note",
                "fields": [{ "label": "note", "value": "remember to rotate the thing on Friday" }] }),
    );
    let got = m.get(n["entry"].as_str().unwrap());
    assert_eq!(got["type"], "note");
    assert_eq!(got["typeOverridden"], true);
    assert_eq!(got["fields"][0]["type"], "text");
    assert_eq!(got["fields"][0]["masked"], false);
    assert_eq!(got["sensitivity"], "low");
    // the legacy spelling is still accepted on input and written as `note`
    let alias = m.ok(
        "entry.create",
        json!({ "node": "a", "name": "ALIASED", "entryType": "note-only",
                "fields": [{ "label": "whatever", "value": "words" }] }),
    );
    assert_eq!(m.get(alias["entry"].as_str().unwrap())["type"], "note");
    assert_eq!(
        m.manifest_entry("a", alias["entry"].as_str().unwrap())
            .entry_type,
        EntryType::Note
    );
    // a single field labelled note/notes is SUGGESTED to be a note with no override
    let inferred = m.ok(
        "entry.create",
        json!({ "node": "a", "name": "INFERRED", "fields": [{ "label": " Notes ", "value": "some words" }] }),
    );
    let got = m.get(inferred["entry"].as_str().unwrap());
    assert_eq!(
        (got["type"].as_str(), got["typeOverridden"].as_bool()),
        (Some("note"), Some(false))
    );
    // content that looks like a seed phrase is still masked and critical — sensitivity follows
    // the fields, not the entry type
    let phrase =
        "abandon ability able about above absent absorb abstract absurd abuse access accident";
    let risky = m.ok(
        "entry.create",
        json!({ "node": "a", "name": "RISKY", "entryType": "note",
                "fields": [{ "label": "note", "value": phrase }] }),
    );
    let got = m.get(risky["entry"].as_str().unwrap());
    assert_eq!(got["type"], "note");
    assert_eq!(got["sensitivity"], "critical");
    assert_eq!(got["fields"][0]["masked"], true);
    // a node note (ADR-072) is a different thing: it does not appear as an entry
    m.ok(
        "notes.write",
        json!({ "node": "a", "markdown": "# node note", "generation": m.gen("a") }),
    );
    let listed = m.ok("entry.list", json!({ "node": "a" }));
    assert_eq!(listed["ids"].as_array().unwrap().len(), 4);
}

// ===========================================================================
// totp
// ===========================================================================

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

/// Audit P0-1: `entry.reveal` returned a stored 2FA seed to any caller, so the seed/code split (a leaked seed is worth
/// forever) held only for `totp.seed`. A reveal now says a seed field exists and withholds its value; `totp.code` still works.
#[test]
fn a_reveal_never_returns_a_stored_totp_seed() {
    let m = Mem::new();
    let two = m.create(
        "TWO_FA",
        json!([{ "label": "account", "value": "me@fields.test" }, { "label": "2fa", "value": SEED }]),
    );
    let got = m.reveal(&two);
    assert!(
        !got.to_string().contains(SEED),
        "the seed left the broker: {got}"
    );
    assert_eq!(
        got["fields"][0]["value"], "me@fields.test",
        "other fields are unchanged"
    );
    assert_eq!(got["fields"][1]["type"], "totp-seed");
    assert_eq!(got["fields"][1]["value"], Value::Null);
    assert_eq!(got["fields"][1]["redacted"], "totp_seed");

    // A one-field seed entry: the single-value shape is null, not the seed.
    let only = m.create("ONLY_SEED", json!([{ "label": "2fa", "value": SEED }]));
    let got = m.reveal(&only);
    assert!(
        !got.to_string().contains(SEED),
        "the seed left the broker: {got}"
    );
    assert_eq!(got["value"], Value::Null);

    // A bare otpauth URI is a seed too.
    let uri = format!("otpauth://totp/Acme:me?secret={SEED_2}&issuer=Acme");
    let via_uri = m.create("URI_SEED", json!([{ "label": "2fa", "value": uri }]));
    let got = m.reveal(&via_uri);
    assert!(
        !got.to_string().contains(SEED_2) && !got.to_string().contains("otpauth"),
        "the URI left the broker: {got}"
    );

    // The code still comes from totp.code.
    let code = m.ok("totp.code", json!({ "node": "a", "entry": only }));
    assert_eq!(code["code"], expected_code(SEED).as_str());
}

/// The final audit's re-verification of P0-1: the class a reveal withholds is the class `totp.code` computes from, the
/// formats services display are in it, and an agent cannot move a seed out of it by retyping the field.
#[test]
fn the_seed_class_is_one_class_and_an_agent_cannot_leave_it() {
    let m = Mem::new();
    let agent = {
        let mut sc = scope("a", ALL);
        sc.origin = Origin::Agent;
        sc.capabilities.retain(|c| *c != Capability::Admin);
        sc
    };
    let agent_d = |op: &str, params: Value| ops::dispatch(&m.state, &agent, NOW, op, &params);

    // Shapes services display are seeds: 24, 52 characters, grouped lower case.
    for (name, value) in [
        ("S24", "JBSWY3DPEHPK3PXPJBSWY3DP"),
        (
            "S52",
            "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSW",
        ),
        ("SGROUP", "jbsw y3dp ehpk 3pxp"),
    ] {
        let id = m.create(name, json!([{ "label": "2fa", "value": value }]));
        let got = m.reveal(&id);
        assert!(
            got["value"].is_null() && got["fields"][0]["redacted"] == "totp_seed",
            "{name}: {got}"
        );
        assert!(m.ok("totp.code", json!({ "node": "a", "entry": id }))["code"].is_string());
    }

    // An agent cannot retype a seed field; the answer is a refusal and nothing changed.
    let id = m.create("RETYPE", json!([{ "label": "2fa", "value": SEED }]));
    let field = ids_of(&m.get(&id)).remove(0);
    let gen = m.gen("a");
    for ty in [
        "password",
        "api-key",
        "private-key",
        "seed-phrase",
        "username",
        "host",
        "port",
        "url",
        "certificate",
        "text",
        "auto",
    ] {
        let patch = json!({ "type": ty });
        let refused = agent_d(
            "field.update",
            json!({ "node": "a", "entry": id, "generation": gen, "field": field, "patch": patch }),
        );
        assert!(
            matches!(refused, Err(OpError::CapabilityNotHeld { .. })),
            "{patch}: {refused:?}"
        );
    }
    // Renaming the field or unmasking it does not change what a reveal withholds.
    for patch in [json!({ "label": "renamed" }), json!({ "masked": false })] {
        agent_d(
            "field.update",
            json!({ "node": "a", "entry": id, "generation": m.gen("a"), "field": field, "patch": patch }),
        )
        .expect("a rename or an unmask is the caller's own edit");
    }
    assert!(
        m.reveal(&id)["value"].is_null(),
        "still withheld after the attempts"
    );
    assert!(m.counts_totp("a") > 0, "and still counted as a seed");

    // A plain lower-case run is a word to the broker, so totp.code refuses it too: one class, one test.
    let word = m.create(
        "LOWERCASE",
        json!([{ "label": "2fa", "value": "jbswy3dpehpk3pxp" }]),
    );
    assert_eq!(m.reveal(&word)["value"], "jbswy3dpehpk3pxp");
    let msg = malformed(m.err("totp.code", json!({ "node": "a", "entry": word })));
    assert!(msg.contains("not a TOTP seed"), "{msg}");
    // Its owner types it as a seed; then it is withheld and a code comes from it.
    let wf = ids_of(&m.get(&word)).remove(0);
    m.ok(
        "field.update",
        json!({ "node": "a", "entry": word, "generation": m.gen("a"), "field": wf, "patch": { "type": "totp-seed" } }),
    );
    assert!(m.reveal(&word)["value"].is_null());
    assert!(m.ok("totp.code", json!({ "node": "a", "entry": word }))["code"].is_string());
}

#[test]
fn totp_code_selects_the_only_seed_and_refuses_ambiguity() {
    let m = Mem::new();
    // two fields, exactly one seed: no `field` needed
    let one_seed = m.create(
        "ONE_SEED",
        json!([{ "label": "account", "value": "me@fields.test" }, { "label": "2fa", "value": SEED }]),
    );
    let got = m.get(&one_seed);
    assert_eq!(got["hasTotp"], true);
    assert_eq!(got["fields"][1]["type"], "totp-seed");
    let code = m.ok("totp.code", json!({ "node": "a", "entry": one_seed }));
    assert_eq!(code["code"], expected_code(SEED).as_str());
    assert!(
        code.get("seed").is_none() && !code.to_string().contains(SEED),
        "never the seed"
    );

    // two seeds: ambiguous without `field`, fine with it
    let two_seeds = m.create(
        "TWO_SEEDS",
        json!([{ "label": "personal", "value": SEED }, { "label": "work", "value": SEED_2 }]),
    );
    let msg = malformed(m.err("totp.code", json!({ "node": "a", "entry": two_seeds })));
    assert_eq!(
        msg,
        "entry has 2 fields and 2 TOTP seeds; pass params.field"
    );
    let work = ids_of(&m.get(&two_seeds)).remove(1);
    let code = m.ok(
        "totp.code",
        json!({ "node": "a", "entry": two_seeds, "field": work }),
    );
    assert_eq!(code["code"], expected_code(SEED_2).as_str());

    // several fields and no seed among them: also ambiguous
    let none = m.create("NO_SEED", server_fields());
    let msg = malformed(m.err("totp.code", json!({ "node": "a", "entry": none })));
    assert_eq!(
        msg,
        "entry has 4 fields and 0 TOTP seeds; pass params.field"
    );
    // an unknown field
    assert!(matches!(
        m.err(
            "totp.code",
            json!({ "node": "a", "entry": none, "field": "f_deadbeef" })
        ),
        OpError::NotFound(_)
    ));
    // a sole field is the seed whatever its inferred type — an 80-bit seed (16 chars) and a
    // short one both behave as they did before the field model
    let sole = m.ok(
        "entry.create",
        json!({ "node": "a", "name": "SOLE", "value": "JBSWY3DPEHPK3PXP" }),
    );
    let code = m.ok("totp.code", json!({ "node": "a", "entry": sole["entry"] }));
    assert_eq!(code["code"], expected_code("JBSWY3DPEHPK3PXP").as_str());
    let tiny = m.ok(
        "entry.create",
        json!({ "node": "a", "name": "TINY",
                "fields": [{ "label": "2fa", "value": "JBSWY3DPEHP", "type": "totp-seed" }] }),
    );
    let msg = malformed(m.err("totp.code", json!({ "node": "a", "entry": tiny["entry"] })));
    assert!(msg.contains("bits"), "{msg}");
    // totp.seed still never answers, with or without a field
    for params in [
        json!({ "node": "a", "entry": one_seed }),
        json!({ "node": "a", "entry": one_seed, "field": work }),
    ] {
        assert!(matches!(
            m.err("totp.seed", params),
            OpError::PresenceRequired { .. }
        ));
    }
    // a non-string field is refused, not ignored
    malformed(m.err(
        "totp.code",
        json!({ "node": "a", "entry": one_seed, "field": 7 }),
    ));
}

// ===========================================================================
// legacy
// ===========================================================================

#[test]
fn legacy_v1_entries_open_unchanged_and_the_first_write_upgrades_preserving_projection() {
    let m = Mem::new();
    // What alpha.6 wrote: a password-ish value whose label (lost) made it `high`, a TOTP seed
    // typed `totp`, and a plain text value.
    m.seed_legacy(
        "a",
        "e_pw",
        "OLD_PW",
        "hunter2xyz",
        EntryType::Other,
        Sensitivity::High,
    );
    m.seed_legacy(
        "a",
        "e_totp",
        "OLD_TOTP",
        SEED,
        EntryType::Totp,
        Sensitivity::High,
    );
    m.seed_legacy(
        "a",
        "e_txt",
        "OLD_TXT",
        "just some text",
        EntryType::Other,
        Sensitivity::Low,
    );

    // ---- reads: every value unchanged, and the projection is what the manifest already showed
    for (entry, value) in [("e_pw", "hunter2xyz"), ("e_txt", "just some text")] {
        assert_eq!(m.reveal(entry)["value"], value);
    }
    // A seed is never revealed (audit P0-1); it survived if it still makes the same code.
    assert_eq!(m.reveal("e_totp")["value"], Value::Null);
    assert_eq!(
        m.ok("totp.code", json!({ "node": "a", "entry": "e_totp" }))["code"],
        expected_code(SEED).as_str()
    );
    let pw = m.get("e_pw");
    assert_eq!(
        (pw["type"].as_str(), pw["sensitivity"].as_str()),
        (Some("other"), Some("high"))
    );
    assert_eq!(pw["fieldCount"], 1);
    assert_eq!(pw["fields"][0]["id"], fields::LEGACY_FIELD_ID);
    assert_eq!(pw["fields"][0]["label"], "");
    assert_eq!(
        pw["fields"][0]["masked"], true,
        "a `high` legacy value whose label was lost stays masked"
    );
    assert_eq!(m.get("e_totp")["type"], "totp");
    assert_eq!(m.get("e_totp")["hasTotp"], true);
    let txt = m.get("e_txt");
    assert_eq!(
        (
            txt["sensitivity"].as_str(),
            txt["fields"][0]["masked"].as_bool()
        ),
        (Some("low"), Some(false))
    );
    // reading rewrites nothing
    for entry in ["e_pw", "e_totp", "e_txt"] {
        assert_eq!(
            m.version_byte("a", entry),
            1,
            "{entry} is still a version-1 envelope after reads"
        );
    }
    // totp.code on a legacy seed
    assert_eq!(
        m.ok("totp.code", json!({ "node": "a", "entry": "e_totp" }))["code"],
        expected_code(SEED).as_str()
    );

    // ---- the first write upgrades ONE entry, preserving what it showed
    let g = m.gen("a");
    let added = m.ok(
        "field.add",
        json!({ "node": "a", "entry": "e_pw", "generation": g,
                "fields": [{ "label": "host", "value": "legacy.fields.test" }] }),
    );
    assert_eq!(added["fieldCount"], 2);
    assert_eq!(
        m.version_byte("a", "e_pw"),
        2,
        "re-sealed as a field document"
    );
    assert_eq!(
        m.version_byte("a", "e_txt"),
        1,
        "an entry nobody wrote to is still version 1"
    );
    let row = m.manifest_entry("a", "e_pw");
    assert_eq!(
        (row.entry_type, row.sensitivity),
        (EntryType::Other, Sensitivity::High),
        "type and sensitivity unchanged by the upgrade"
    );
    let pw = m.get("e_pw");
    assert_eq!(
        pw["fields"][0]["id"],
        fields::LEGACY_FIELD_ID,
        "the legacy field keeps its reserved id"
    );
    assert_eq!(pw["fields"][0]["masked"], true);
    let revealed = m.reveal("e_pw");
    assert_eq!(revealed["fields"][0]["value"], "hunter2xyz");
    assert_eq!(revealed["fields"][1]["value"], "legacy.fields.test");
    let new_id = ids(&added["added"]).remove(0);
    assert_ne!(
        new_id,
        fields::LEGACY_FIELD_ID,
        "a minted id never collides with the legacy one"
    );
    assert_eq!(
        ids(&added["fieldIds"]),
        [fields::LEGACY_FIELD_ID.to_string(), new_id]
    );

    // ---- a rotate of a legacy entry retains the old (version-1) bytes; undo puts them back
    let (r, rot) = m.call(
        "entry.rotate",
        json!({ "node": "a", "entry": "e_txt", "generation": m.gen("a"), "value": "rotated text" }),
    );
    r.expect("rotate a legacy entry");
    assert_eq!(m.version_byte("a", "e_txt"), 2);
    assert_eq!(m.reveal("e_txt")["value"], "rotated text");
    let (r, _) = m.call(
        "entry.undo",
        json!({ "node": "a", "id": rot.unwrap(), "generation": m.gen("a") }),
    );
    r.expect("undo");
    assert_eq!(
        m.version_byte("a", "e_txt"),
        1,
        "the original version-1 bytes came back"
    );
    assert_eq!(m.reveal("e_txt")["value"], "just some text");
    let txt = m.get("e_txt");
    assert_eq!(txt["sensitivity"], "low");
    assert_eq!(m.manifest_entry("a", "e_txt").field_count, 1);

    // ---- a single-value update of a legacy entry (the old call shape) still works
    m.ok(
        "entry.update",
        json!({ "node": "a", "entry": "e_totp", "generation": m.gen("a"), "value": "now just words" }),
    );
    assert_eq!(m.reveal("e_totp")["value"], "now just words");
}

#[test]
fn legacy_raw_value_that_looks_like_json_is_never_parsed() {
    let m = Mem::new();
    // A version-1 value that happens to be a perfectly valid field document.
    let lookalike = r#"{"v":1,"entryType":"wallet","fields":[{"id":"f_11111111","label":"smuggled","value":"x"}]}"#;
    m.seed_legacy(
        "a",
        "e_look",
        "LOOKALIKE",
        lookalike,
        EntryType::Other,
        Sensitivity::Low,
    );
    let revealed = m.reveal("e_look");
    assert_eq!(
        revealed["value"], lookalike,
        "one raw field holding that text"
    );
    assert_eq!(revealed["fields"].as_array().unwrap().len(), 1);
    assert_eq!(revealed["fields"][0]["id"], fields::LEGACY_FIELD_ID);
    assert_eq!(revealed["fields"][0]["label"], "");
    let got = m.get("e_look");
    assert_eq!(
        got["type"], "other",
        "the document's `entryType` was not honoured"
    );

    // The kind comes from the authenticated version byte, so a version-2 envelope whose plaintext
    // is NOT a document is a stored document that does not decode: internal, never a value.
    let node_pub = m.state.node_public_key("a").unwrap();
    let bogus = envelope::seal_as(
        PayloadKind::FieldDocument,
        b"not a document",
        &node_pub,
        "a",
        "e_look",
    )
    .unwrap();
    credmgr_store::atomic::write(&m.state.paths.entry_env("a", "e_look"), &bogus).unwrap();
    let e = m.err("entry.reveal", json!({ "node": "a", "entry": "e_look" }));
    assert!(matches!(e, OpError::Internal(_)), "{e:?}");
    assert!(!format!("{e:?}").contains("not a document"));
}

// ===========================================================================
// batch
// ===========================================================================

#[test]
fn create_batch_with_multi_field_items_validates_everything_first() {
    let m = Mem::new();
    let names = |m: &Mem| m.ok("entry.list", json!({ "node": "a" }))["names"].clone();
    // a control character in item 3's label: NOTHING is written, and the refusal names the item
    let g = m.gen("a");
    let msg = malformed(m.err(
        "entry.create_batch",
        json!({ "node": "a", "entries": [
            { "name": "ONE", "value": "v1" },
            { "name": "TWO", "fields": [{ "label": "a", "value": "b" }, { "label": "c", "value": "d" }] },
            { "name": "THREE", "fields": [{ "label": "marker\nlabel-xyz", "value": "marker-value-xyz" }] }] }),
    ));
    assert!(msg.contains("entries[2]"), "{msg}");
    assert!(!msg.contains("marker"), "{msg}");
    assert_eq!(names(&m), json!([]), "no item was created");
    assert_eq!(m.gen("a"), g);
    // each way an item can be malformed is caught before the first write
    for (item, needle) in [
        (
            json!({ "name": "X", "value": "v", "fields": [{ "label": "l", "value": "v" }] }),
            "not both",
        ),
        (json!({ "name": "X" }), "params.value or params.fields"),
        (json!({ "name": "X", "fields": [] }), "at least one field"),
        (json!({ "name": "X", "value": 5 }), "must be a string"),
        (json!({ "name": "X", "fields": "no" }), "must be an array"),
        (
            json!({ "name": "X", "value": "v", "entryType": "bogus" }),
            "entryType",
        ),
        (
            json!({ "name": "X", "value": "v", "entryType": null }),
            "must not be null",
        ),
    ] {
        let msg = malformed(m.err(
            "entry.create_batch",
            json!({ "node": "a", "entries": [{ "name": "FIRST", "value": "v" }, item] }),
        ));
        assert!(
            msg.contains(needle) && msg.contains("entries[1]"),
            "{needle}: {msg}"
        );
        assert_eq!(names(&m), json!([]), "{needle}: nothing was created");
    }
    // success: value items and multi-field items mixed, in one call
    let ok = m.ok(
        "entry.create_batch",
        json!({ "node": "a", "entries": [
            { "name": "ONE", "value": "v1", "label": "token" },
            { "name": "TWO", "fields": [{ "label": "a", "value": "b" }, { "label": "c", "value": "d" }],
              "entryType": "database" },
            { "name": "THREE", "fields": [{ "label": "otp", "value": SEED }] }] }),
    );
    assert_eq!(ok["complete"], true);
    assert_eq!(ok["total"], 3);
    let created = ok["created"].as_array().unwrap();
    assert_eq!(
        created
            .iter()
            .map(|c| c["fieldCount"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        [1, 2, 1]
    );
    let two = created[1]["entry"].as_str().unwrap();
    let got = m.get(two);
    assert_eq!(
        (got["type"].as_str(), got["fieldCount"].as_u64()),
        (Some("database"), Some(2))
    );
    assert_eq!(
        m.get(created[0]["entry"].as_str().unwrap())["fields"][0]["label"],
        "token"
    );
    assert_eq!(
        m.get(created[2]["entry"].as_str().unwrap())["hasTotp"],
        true
    );
    assert_eq!(m.counts_totp("a"), 1);
    // names are still unique inside the batch and against the node
    malformed(m.err(
        "entry.create_batch",
        json!({ "node": "a", "entries": [{ "name": "DUP", "value": "1" }, { "name": "DUP", "value": "2" }] }),
    ));
    assert!(matches!(
        m.err(
            "entry.create_batch",
            json!({ "node": "a", "entries": [{ "name": "FRESH", "value": "1" }, { "name": "ONE", "value": "2" }] })
        ),
        OpError::EntryExists { .. }
    ));
    assert!(!names(&m).as_array().unwrap().iter().any(|n| n == "FRESH"));
}

#[test]
fn an_oversize_document_is_refused() {
    let m = Mem::new();
    let big = "x".repeat(17 * 1024 * 1024);
    // one entry over the 16 MiB document limit
    let msg = malformed(m.err(
        "entry.create",
        json!({ "node": "a", "name": "HUGE", "fields": [{ "label": "blob", "value": big }] }),
    ));
    assert!(msg.contains("limit is 16777216"), "{msg}");
    assert_eq!(m.gen("a"), 0, "nothing was written");
    // an update that would push an existing entry over it leaves the entry alone
    let entry = m.create("SMALL", json!([{ "label": "blob", "value": "tiny" }]));
    let g = m.gen("a");
    malformed(m.err(
        "entry.update",
        json!({ "node": "a", "entry": entry, "generation": g, "value": big }),
    ));
    assert_eq!(m.gen("a"), g);
    assert_eq!(m.reveal(&entry)["value"], "tiny");
    drop(big);

    // the batch as a whole is bounded too: five documents under the per-document limit that
    // together are over 64 MiB are refused before the first write
    let part = "y".repeat(13 * 1024 * 1024);
    let items: Vec<Value> = (0..5)
        .map(|i| json!({ "name": format!("PART_{i}"), "fields": [{ "label": "blob", "value": part }] }))
        .collect();
    let msg = malformed(m.err(
        "entry.create_batch",
        json!({ "node": "a", "entries": items }),
    ));
    assert!(msg.contains("64 MiB"), "{msg}");
    assert_eq!(
        m.ok("entry.list", json!({ "node": "a" }))["names"],
        json!(["SMALL"])
    );
    // three of them fit
    let items: Vec<Value> = (0..3)
        .map(|i| json!({ "name": format!("PART_{i}"), "fields": [{ "label": "blob", "value": part }] }))
        .collect();
    let ok = m.ok(
        "entry.create_batch",
        json!({ "node": "a", "entries": items }),
    );
    assert_eq!(ok["complete"], true);
}

// ===========================================================================
// seal / restore
// ===========================================================================

#[test]
fn seal_and_restore_keep_v2_entries_readable_and_digests_true() {
    let m = Mem::new();
    let entry = m.create("TO_SEAL", server_fields());
    m.seed_legacy(
        "a",
        "e_old",
        "LEGACY",
        "legacy-bytes-1",
        EntryType::Other,
        Sensitivity::Low,
    );
    let before_new = m.reveal(&entry);
    let original_bytes =
        credmgr_store::atomic::read(&m.state.paths.entry_env("a", &entry)).unwrap();

    let sealed = m.ok("node.seal", json!({ "node": "a" }));
    assert_eq!(sealed["sealed"], true);
    // Both entries now live under orphan, each resealed as the SAME payload kind it was...
    let new_orphan =
        credmgr_store::atomic::read(&m.state.paths.entry_env(ORPHAN_ID, &entry)).unwrap();
    let old_orphan =
        credmgr_store::atomic::read(&m.state.paths.entry_env(ORPHAN_ID, "e_old")).unwrap();
    assert_eq!(new_orphan[4], 2, "a field document stays a field document");
    assert_eq!(old_orphan[4], 1, "a legacy value stays a legacy value");
    // ...and the orphan manifest records the digest of what is actually there, plus the projection.
    {
        let manifests = m.state.manifests.read().unwrap();
        let orphan = &manifests[ORPHAN_ID];
        let row = |id: &str| orphan.entries.iter().find(|e| e.id == id).unwrap().clone();
        assert_eq!(row(&entry).sha256, envelope_digest(&new_orphan));
        assert_eq!(row("e_old").sha256, envelope_digest(&old_orphan));
        assert_eq!(row(&entry).field_count, 4);
    }
    // The original is gone from the node and kept byte-for-byte in the archive.
    assert!(credmgr_store::atomic::read(&m.state.paths.entry_env("a", &entry)).is_err());

    // Restore: byte-identical, readable, fields intact.
    m.ok("node.restore", json!({ "node": "a" }));
    assert_eq!(
        credmgr_store::atomic::read(&m.state.paths.entry_env("a", &entry)).unwrap(),
        original_bytes
    );
    assert_eq!(m.reveal(&entry), before_new);
    assert_eq!(m.reveal("e_old")["value"], "legacy-bytes-1");
    assert_eq!(m.manifest_entry("a", &entry).field_count, 4);
}

// ===========================================================================
// payload kind: moved or flipped envelopes are refused (also I-29)
// ===========================================================================

#[test]
fn a_flipped_or_moved_envelope_is_refused_never_shown_as_a_value() {
    let m = Mem::new();
    let entry = m.create("FLIP", server_fields());
    let path = m.state.paths.entry_env("a", &entry);
    let good = credmgr_store::atomic::read(&path).unwrap();
    assert_eq!(good[4], 2);

    // version 2 -> 1: the tag no longer authenticates, so the JSON can never be returned as a value
    let mut flipped = good.clone();
    flipped[4] = 1;
    credmgr_store::atomic::write(&path, &flipped).unwrap();
    let e = m.err("entry.reveal", json!({ "node": "a", "entry": entry }));
    assert!(matches!(e, OpError::NotFound(_)), "{e:?}");
    credmgr_store::atomic::write(&path, &good).unwrap();
    assert_eq!(m.reveal(&entry)["fields"].as_array().unwrap().len(), 4);

    // and version 1 -> 2 on a legacy envelope
    m.seed_legacy(
        "a",
        "e_old",
        "OLD",
        "legacy-bytes-2",
        EntryType::Other,
        Sensitivity::Low,
    );
    let old_path = m.state.paths.entry_env("a", "e_old");
    let old = credmgr_store::atomic::read(&old_path).unwrap();
    let mut up = old.clone();
    up[4] = 2;
    credmgr_store::atomic::write(&old_path, &up).unwrap();
    assert!(m
        .d("entry.reveal", json!({ "node": "a", "entry": "e_old" }))
        .is_err());
    credmgr_store::atomic::write(&old_path, &old).unwrap();

    // a version-2 envelope moved to another entry id, and to another node, does not open
    let other = m.create("OTHER", json!([{ "label": "k", "value": "v" }]));
    credmgr_store::atomic::write(&m.state.paths.entry_env("a", &other), &good).unwrap();
    assert!(m
        .d("entry.reveal", json!({ "node": "a", "entry": other }))
        .is_err());
    let b_scope = scope("b", ALL);
    let b_pub = m.state.node_public_key("b").unwrap();
    let b_env = envelope::seal_as(PayloadKind::FieldDocument, b"{}", &b_pub, "b", "e_b1").unwrap();
    credmgr_store::atomic::write(&m.state.paths.entry_env("b", "e_b1"), &b_env).unwrap();
    m.state.insert_manifest_entry(
        "b",
        ManifestEntry {
            id: "e_b1".to_string(),
            name: "B".to_string(),
            r#ref: 1,
            entry_type: EntryType::Other,
            sensitivity: Sensitivity::Low,
            field_count: 1,
            sha256: envelope_digest(&b_env),
            modified: NOW,
            expires_at: None,
            rotated_at: None,
            has_totp: false,
        },
    );
    credmgr_store::atomic::write(&m.state.paths.entry_env("b", "e_b1"), &good).unwrap();
    assert!(ops::dispatch(
        &m.state,
        &b_scope,
        NOW,
        "entry.reveal",
        &json!({ "node": "b", "entry": "e_b1" })
    )
    .is_err());

    // None of these refusals revealed a stored document as text.
    let leak = format!(
        "{:?}",
        m.d("entry.reveal", json!({ "node": "a", "entry": other }))
    );
    assert!(
        !leak.contains("svc_fields") && !leak.contains("pw-9d2c41aa"),
        "{leak}"
    );
}

// ===========================================================================
// the real vault, on disk
// ===========================================================================

struct Disk {
    vault_dir: PathBuf,
    state_dir: PathBuf,
    _dir: tempfile::TempDir,
}

impl Disk {
    fn broker(&self) -> Arc<BrokerState> {
        let keystore = SoftwareKeystore::new(
            SecretBox::new(Box::default()),
            self.state_dir.join("placeholder-keystore"),
        );
        let state = Arc::new(BrokerState::new(
            Box::new(keystore),
            VaultPaths::new(self.vault_dir.clone()),
        ));
        state.set_state_dir_for_test(self.state_dir.clone());
        state
    }
}

fn anyone() -> BrokerScope {
    scope(GLOBAL_ID, &[Capability::List])
}

fn human() -> BrokerScope {
    scope(GLOBAL_ID, ALL)
}

fn call(state: &BrokerState, who: &BrokerScope, op: &str, params: Value) -> Result<Value, OpError> {
    ops::dispatch(state, who, NOW, op, &params)
}

/// One request through `server::handle_request` — the call path that writes an audit record.
fn req(state: &Arc<BrokerState>, token: &str, op: &str, params: Value) -> Result<Value, OpError> {
    server::handle_request(
        state,
        &PeerInfo {
            uid: 501,
            pid: 1,
            cwd: None,
        },
        &Request {
            id: "r".to_string(),
            op: op.to_string(),
            token: Some(token.to_string()),
            params,
        },
    )
    .0
}

/// A new login's token (each unlock mints one).
fn fresh_token(state: &BrokerState) -> String {
    call(
        state,
        &anyone(),
        "vault.unlock",
        json!({ "passphrase": PASSPHRASE }),
    )
    .expect("unlock")["token"]
        .as_str()
        .expect("a real login mints a token")
        .to_string()
}

fn login(state: &BrokerState) -> BrokerScope {
    let unlocked = call(
        state,
        &anyone(),
        "vault.unlock",
        json!({ "passphrase": PASSPHRASE }),
    )
    .expect("unlock");
    let token = unlocked["token"]
        .as_str()
        .expect("a real login mints a token");
    let peer = PeerInfo {
        uid: 501,
        pid: 1,
        cwd: None,
    };
    let registry = state.registry.read().unwrap().clone();
    credmgr_brokerd::scope::resolve_scope(&registry, &state.tokens, &peer, Some(token)).0
}

/// `credmgr init` for real; returns the vault and the broker still running, vault unlocked and a
/// project "acme" created.
fn disk_vault() -> (Disk, Arc<BrokerState>, BrokerScope) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault_dir = dir.path().join("vault");
    let state_dir = dir.path().join("state");
    std::fs::create_dir_all(&vault_dir).unwrap();
    std::fs::create_dir_all(&state_dir).unwrap();
    let disk = Disk {
        vault_dir,
        state_dir,
        _dir: dir,
    };
    let state = disk.broker();
    let begin = call(
        &state,
        &anyone(),
        "vault.init_begin",
        json!({ "passphrase": PASSPHRASE }),
    )
    .expect("init_begin");
    let code = begin["recoveryCode"].as_str().unwrap().to_string();
    call(
        &state,
        &anyone(),
        "vault.init_confirm",
        json!({ "recoveryCode": code }),
    )
    .expect("init_confirm");
    let owner = login(&state);
    call(
        &state,
        &owner,
        "node.create",
        json!({ "id": "acme", "label": "Acme", "parentId": GLOBAL_ID }),
    )
    .expect("node.create");
    (disk, state, owner)
}

fn verify_clean(state: &BrokerState, owner: &BrokerScope, when: &str) {
    let v = call(state, owner, "maintenance.verify", json!({})).expect("maintenance.verify");
    assert_eq!(v["ok"], true, "maintenance.verify after {when}: {v}");
}

fn field_ids_of(state: &BrokerState, owner: &BrokerScope, entry: &str) -> Vec<String> {
    let got = call(
        state,
        owner,
        "entry.get",
        json!({ "node": "acme", "entry": entry }),
    )
    .unwrap();
    got["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["id"].as_str().unwrap().to_string())
        .collect()
}

fn gen_of(state: &BrokerState, owner: &BrokerScope, node: &str) -> u64 {
    call(state, owner, "entry.list", json!({ "node": node })).unwrap()["generation"]
        .as_u64()
        .unwrap()
}

#[test]
fn fields_survive_a_restart() {
    let (disk, state, owner) = disk_vault();
    let created = call(
        &state,
        &owner,
        "entry.create",
        json!({ "node": "acme", "name": "PROD_DB", "fields": server_fields() }),
    )
    .unwrap();
    let entry = created["entry"].as_str().unwrap().to_string();
    verify_clean(&state, &owner, "create");
    let ids0 = field_ids_of(&state, &owner, &entry);

    // a field journey: add, update, reorder, remove — verify stays clean through every step
    let added = call(
        &state,
        &owner,
        "field.add",
        json!({ "node": "acme", "entry": entry, "generation": gen_of(&state, &owner, "acme"),
                "fields": [{ "label": "otp", "value": SEED }] }),
    )
    .unwrap();
    verify_clean(&state, &owner, "field.add");
    let otp = ids(&added["added"]).remove(0);
    call(
        &state,
        &owner,
        "field.update",
        json!({ "node": "acme", "entry": entry, "generation": gen_of(&state, &owner, "acme"),
                "field": ids0[2], "patch": { "value": "pw-after-restart-1", "label": "secret" } }),
    )
    .unwrap();
    verify_clean(&state, &owner, "field.update");
    let mut order = field_ids_of(&state, &owner, &entry);
    order.rotate_left(1);
    call(
        &state,
        &owner,
        "field.reorder",
        json!({ "node": "acme", "entry": entry, "generation": gen_of(&state, &owner, "acme"), "order": order }),
    )
    .unwrap();
    verify_clean(&state, &owner, "field.reorder");
    call(
        &state,
        &owner,
        "field.remove",
        json!({ "node": "acme", "entry": entry, "generation": gen_of(&state, &owner, "acme"),
                "field": ids0[3] }),
    )
    .unwrap();
    verify_clean(&state, &owner, "field.remove");
    let expected = call(
        &state,
        &owner,
        "entry.reveal",
        json!({ "node": "acme", "entry": entry }),
    )
    .unwrap();
    let expected_get = call(
        &state,
        &owner,
        "entry.get",
        json!({ "node": "acme", "entry": entry }),
    )
    .unwrap();
    assert_eq!(expected["fields"].as_array().unwrap().len(), 4);

    // ---- lock the vault and unlock it again (same process): the same answers
    call(&state, &owner, "vault.lock", json!({})).unwrap();
    let locked = call(
        &state,
        &owner,
        "entry.get",
        json!({ "node": "acme", "entry": entry }),
    );
    assert!(
        locked.is_err(),
        "a locked vault answers no metadata: {locked:?}"
    );
    let owner = login(&state);
    assert_eq!(
        call(
            &state,
            &owner,
            "entry.reveal",
            json!({ "node": "acme", "entry": entry })
        )
        .unwrap(),
        expected,
        "after lock and unlock"
    );
    assert_eq!(
        call(
            &state,
            &owner,
            "entry.get",
            json!({ "node": "acme", "entry": entry })
        )
        .unwrap(),
        expected_get
    );
    drop(state);

    // ---- the daemon restarts: nothing but the disk carries across
    let state = disk.broker();
    let owner = login(&state);
    let after = call(
        &state,
        &owner,
        "entry.reveal",
        json!({ "node": "acme", "entry": entry }),
    )
    .unwrap();
    assert_eq!(
        after, expected,
        "every label, value, id and the order survived"
    );
    let after_get = call(
        &state,
        &owner,
        "entry.get",
        json!({ "node": "acme", "entry": entry }),
    )
    .unwrap();
    assert_eq!(after_get, expected_get);
    assert_eq!(after_get["hasTotp"], true);
    assert_eq!(
        after["fields"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["id"] == otp.as_str())
            .unwrap()["value"],
        Value::Null,
        "a seed is never revealed (audit P0-1)"
    );
    let code = call(
        &state,
        &owner,
        "totp.code",
        json!({ "node": "acme", "entry": entry, "field": otp }),
    )
    .unwrap();
    assert_eq!(
        code["code"],
        expected_code(SEED).as_str(),
        "the seed survived the restart"
    );
    verify_clean(&state, &owner, "restart");
    let manifest_totp = state.manifests.read().unwrap()["acme"].counts.totp;
    assert_eq!(
        manifest_totp, 1,
        "counts.totp counts the entry that carries a seed"
    );
    // the field ops still work on the reloaded vault, and are still undoable by id
    let g = gen_of(&state, &owner, "acme");
    call(
        &state,
        &owner,
        "field.update",
        json!({ "node": "acme", "entry": entry, "generation": g, "field": ids0[0],
                "patch": { "value": "renamed.fields.test" } }),
    )
    .unwrap();
    verify_clean(&state, &owner, "a field edit after the restart");
}

/// Every file under `dir`, recursively.
fn files_under(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).into_iter().flatten().flatten() {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.is_file() {
                out.push(p);
            }
        }
    }
    out
}

fn contains_bytes(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|w| w == needle.as_bytes())
}

#[test]
fn no_label_or_value_reaches_the_manifest_or_the_audit_log() {
    let (disk, state, owner) = disk_vault();
    // Marker labels and values, unique per run so they can never be in a fixture by accident.
    let tag = format!("{:08x}", rand_u32());
    let l = |n: &str| format!("lbl-{n}-{tag}");
    let v = |n: &str| format!("val-{n}-{tag}");
    let markers: Vec<String> = ["a", "b", "c", "d", "e", "f", "g", "h"]
        .iter()
        .flat_map(|n| [l(n), v(n)])
        .collect();

    // Every call below goes through the real request path, because that is the one place an
    // audit record is written (`ops::dispatch` alone never writes one).
    let token = fresh_token(&state);
    let r = |op: &str, params: Value| req(&state, &token, op, params);
    let created = r(
        "entry.create",
        json!({ "node": "acme", "name": "MARKED", "fields": [
            { "label": l("a"), "value": v("a") }, { "label": l("b"), "value": v("b") }] }),
    )
    .unwrap();
    let entry = created["entry"].as_str().unwrap().to_string();
    let gen = || gen_of(&state, &owner, "acme");
    let fids = field_ids_of(&state, &owner, &entry);
    // every op that carries a label or a value
    r(
        "field.add",
        json!({ "node": "acme", "entry": entry, "generation": gen(),
        "fields": [{ "label": l("c"), "value": v("c") }] }),
    )
    .unwrap();
    r(
        "field.update",
        json!({ "node": "acme", "entry": entry, "generation": gen(),
        "field": fids[0], "patch": { "label": l("d"), "value": v("d") } }),
    )
    .unwrap();
    r(
        "entry.update",
        json!({ "node": "acme", "entry": entry, "generation": gen(),
        "field": fids[1], "value": v("e"), "label": l("e") }),
    )
    .unwrap();
    r(
        "entry.rotate",
        json!({ "node": "acme", "entry": entry, "generation": gen(),
        "fields": [{ "id": fids[0], "label": l("f"), "value": v("f") },
                   { "label": l("g"), "value": v("g") }] }),
    )
    .unwrap();
    r(
        "entry.create_batch",
        json!({ "node": "acme", "entries": [
        { "name": "BATCHED", "fields": [{ "label": l("h"), "value": v("h") }] }] }),
    )
    .unwrap();
    // reveal, subset reveal, get
    let revealed = r("entry.reveal", json!({ "node": "acme", "entry": entry })).unwrap();
    assert!(
        revealed.to_string().contains(&v("f")),
        "reveal does return values"
    );
    r(
        "entry.reveal",
        json!({ "node": "acme", "entry": entry, "fieldIds": [fids[0]] }),
    )
    .unwrap();
    r("entry.get", json!({ "node": "acme", "entry": entry })).unwrap();
    // refusals that carry a label where an id belongs
    for (op, params) in [
        (
            "field.update",
            json!({ "node": "acme", "entry": entry, "generation": gen(),
            "field": l("a"), "patch": { "value": v("a") } }),
        ),
        (
            "field.remove",
            json!({ "node": "acme", "entry": entry, "generation": gen(), "field": l("b") }),
        ),
        (
            "entry.reveal",
            json!({ "node": "acme", "entry": entry, "fieldIds": [l("a")] }),
        ),
        (
            "totp.code",
            json!({ "node": "acme", "entry": entry, "field": l("a") }),
        ),
    ] {
        assert!(r(op, params).is_err(), "{op}");
    }
    // the locked-write tray, then accept
    call(&state, &owner, "vault.lock", json!({})).unwrap();
    let tray = call(
        &state,
        &human(),
        "entry.create",
        json!({ "node": GLOBAL_ID, "name": "TRAYED",
        "fields": [{ "label": l("a"), "value": v("b") }] }),
    )
    .unwrap();
    assert_eq!(tray["pending"], true);
    let owner2 = login(&state);
    call(
        &state,
        &owner2,
        "vault.pending_accept",
        json!({ "node": GLOBAL_ID, "entry": tray["entry"] }),
    )
    .unwrap();

    // 1. A list response and the audit log carry no label and no value...
    let listed = call(&state, &owner2, "entry.list", json!({ "node": "acme" })).unwrap();
    let tail = call(&state, &owner2, "audit.tail", json!({ "limit": 500 })).unwrap();
    for shown in [listed.to_string(), tail.to_string()] {
        for marker in &markers {
            assert!(
                !shown.contains(marker.as_str()),
                "{marker} leaked into a response: {shown}"
            );
        }
    }
    // ...but the audit log does record WHICH field a call addressed, by id.
    let details: Vec<String> = tail["records"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|r| r["detail"].as_str().map(str::to_string))
        .collect();
    assert!(
        details.iter().any(|d| d == &format!("field: {}", fids[0])),
        "the field op names its field id: {details:?}"
    );
    assert!(
        details.iter().any(|d| d == &format!("fields: {}", fids[0])),
        "the subset reveal names its field ids: {details:?}"
    );
    // a label sent as a `field` is NOT logged — the record says only why it was refused
    assert!(!details.iter().any(|d| d.contains("lbl-")), "{details:?}");

    // 2. No file under the vault holds a label or a value in clear — manifest, registry,
    //    audit log, history snapshots, sidecars, envelopes: all of it.
    let files = files_under(&disk.vault_dir);
    assert!(files.len() > 10, "walked the whole vault: {}", files.len());
    for file in &files {
        let bytes = std::fs::read(file).unwrap();
        for marker in &markers {
            assert!(
                !contains_bytes(&bytes, marker),
                "{marker} is in clear in {}",
                file.display()
            );
        }
    }
    // The plaintext manifest carries the projection and nothing else about a field.
    let manifest_text = std::fs::read_to_string(
        disk.vault_dir
            .join("nodes")
            .join("acme")
            .join("manifest.json"),
    )
    .unwrap();
    assert!(manifest_text.contains("\"fieldCount\""), "{manifest_text}");
    for forbidden in ["\"label\"", "\"fields\"", "\"value\"", "\"masked\""] {
        assert!(
            !manifest_text.contains(forbidden),
            "{forbidden} in the manifest: {manifest_text}"
        );
    }
    verify_clean(&state, &owner2, "the whole journey");
}

fn rand_u32() -> u32 {
    use rand_core::{OsRng, RngCore};
    OsRng.next_u32()
}

#[test]
fn locked_create_with_fields_lands_in_the_tray_and_accept_recomputes_from_the_document() {
    let (disk, state, owner) = disk_vault();
    call(&state, &owner, "vault.lock", json!({})).unwrap();
    let deposited = call(
        &state,
        &human(),
        "entry.create",
        json!({ "node": GLOBAL_ID, "name": "TRAY_MULTI", "fields": [
            { "label": "host", "value": "tray.fields.test" }, { "label": "username", "value": "svc_tray" },
            { "label": "password", "value": "pw-tray-7c1e" }, { "label": "otp", "value": SEED }] }),
    )
    .expect("a locked create goes to the tray");
    assert_eq!(deposited["pending"], true);
    assert_eq!(deposited["fieldCount"], 4);
    assert!(
        deposited.get("generation").is_none(),
        "a tray entry has no generation yet"
    );
    let entry = deposited["entry"].as_str().unwrap().to_string();

    // The unsigned sidecar is untrusted input: forge every number and type in it.
    let meta_path = disk
        .vault_dir
        .join("nodes")
        .join(GLOBAL_ID)
        .join("pending")
        .join(format!("{entry}.meta.json"));
    let mut meta: Value = serde_json::from_slice(&std::fs::read(&meta_path).unwrap()).unwrap();
    meta["fieldCount"] = json!(99);
    meta["type"] = json!("wallet");
    meta["sensitivity"] = json!("low");
    std::fs::write(&meta_path, serde_json::to_vec(&meta).unwrap()).unwrap();
    drop(state);

    let state = disk.broker();
    let owner = login(&state);
    let tray = call(
        &state,
        &owner,
        "vault.pending_list",
        json!({ "node": GLOBAL_ID }),
    )
    .unwrap();
    assert_eq!(
        tray["pending"][0]["fieldCount"], 99,
        "the forged sidecar is what the tray DISPLAYS"
    );

    call(
        &state,
        &owner,
        "vault.pending_accept",
        json!({ "node": GLOBAL_ID, "entry": entry }),
    )
    .expect("accept");
    // ...but the manifest is computed from the document that was actually sealed.
    let got = call(
        &state,
        &owner,
        "entry.get",
        json!({ "node": GLOBAL_ID, "entry": entry }),
    )
    .unwrap();
    assert_eq!(
        got["fieldCount"], 4,
        "a tampered sidecar fieldCount never reaches the manifest"
    );
    assert_eq!(got["type"], "server");
    assert_eq!(got["sensitivity"], "high");
    assert_eq!(got["hasTotp"], true);
    let row = state.manifests.read().unwrap()[GLOBAL_ID]
        .entries
        .iter()
        .find(|e| e.id == entry)
        .unwrap()
        .clone();
    assert_eq!(
        (
            row.field_count,
            row.entry_type,
            row.sensitivity,
            row.has_totp
        ),
        (4, EntryType::Server, Sensitivity::High, true)
    );
    assert_eq!(state.manifests.read().unwrap()[GLOBAL_ID].counts.totp, 1);
    let revealed = call(
        &state,
        &owner,
        "entry.reveal",
        json!({ "node": GLOBAL_ID, "entry": entry }),
    )
    .unwrap();
    assert_eq!(revealed["fields"][2]["value"], "pw-tray-7c1e");
    verify_clean(&state, &owner, "accepting a tray entry");
    assert!(
        std::fs::read_dir(disk.vault_dir.join("nodes").join(GLOBAL_ID).join("pending"))
            .map(|d| d.count() == 0)
            .unwrap_or(true),
        "accept removed the envelope and the sidecar"
    );
}

#[test]
fn accept_refuses_a_pending_envelope_that_does_not_open() {
    let (disk, state, owner) = disk_vault();
    call(&state, &owner, "vault.lock", json!({})).unwrap();
    let deposited = call(
        &state,
        &human(),
        "entry.create",
        json!({ "node": GLOBAL_ID, "name": "BROKEN_TRAY", "fields": [{ "label": "a", "value": "b" }] }),
    )
    .unwrap();
    let entry = deposited["entry"].as_str().unwrap().to_string();
    let pending_env = disk
        .vault_dir
        .join("nodes")
        .join(GLOBAL_ID)
        .join("pending")
        .join(format!("{entry}.env"));
    let good = std::fs::read(&pending_env).unwrap();
    // flip a ciphertext byte
    let mut bad = good.clone();
    let last = bad.len() - 20;
    bad[last] ^= 0x55;
    std::fs::write(&pending_env, &bad).unwrap();

    let owner = login(&state);
    let g = gen_of(&state, &owner, GLOBAL_ID);
    let e = call(
        &state,
        &owner,
        "vault.pending_accept",
        json!({ "node": GLOBAL_ID, "entry": entry }),
    )
    .unwrap_err();
    assert!(matches!(e, OpError::Internal(_)), "{e:?}");
    // The tray is exactly as it was, and nothing entered the manifest or the entries directory.
    let tray = call(
        &state,
        &owner,
        "vault.pending_list",
        json!({ "node": GLOBAL_ID }),
    )
    .unwrap();
    assert_eq!(tray["pending"].as_array().unwrap().len(), 1);
    assert_eq!(gen_of(&state, &owner, GLOBAL_ID), g);
    assert!(!disk
        .vault_dir
        .join("nodes")
        .join(GLOBAL_ID)
        .join("entries")
        .join(format!("{entry}.env"))
        .exists());
    assert!(pending_env.exists());

    // A valid envelope sealed for a DIFFERENT entry id is also refused (the id is in the AAD).
    let other = call(
        &state,
        &owner,
        "entry.create",
        json!({ "node": GLOBAL_ID, "name": "OTHER", "fields": [{ "label": "a", "value": "b" }] }),
    )
    .unwrap();
    let other_bytes = std::fs::read(
        disk.vault_dir
            .join("nodes")
            .join(GLOBAL_ID)
            .join("entries")
            .join(format!("{}.env", other["entry"].as_str().unwrap())),
    )
    .unwrap();
    std::fs::write(&pending_env, other_bytes).unwrap();
    assert!(call(
        &state,
        &owner,
        "vault.pending_accept",
        json!({ "node": GLOBAL_ID, "entry": entry })
    )
    .is_err());

    // Restoring the original bytes makes it acceptable again: the refusal destroyed nothing.
    std::fs::write(&pending_env, &good).unwrap();
    call(
        &state,
        &owner,
        "vault.pending_accept",
        json!({ "node": GLOBAL_ID, "entry": entry }),
    )
    .expect("accept the intact envelope");
}

#[test]
fn a_deposit_made_while_only_the_node_was_locked_is_accepted_after_the_node_unlocks() {
    // The endpoint matrix found this: the tray tests above lock the WHOLE vault, but a deposit
    // can also be made while one node is locked on an unlocked vault.
    let (_disk, state, owner) = disk_vault();
    call(&state, &owner, "vault.node_lock", json!({ "node": "acme" })).expect("lock acme");
    let deposited = call(
        &state,
        &owner,
        "entry.create",
        json!({ "node": "acme", "name": "NODE_TRAY", "value": "node-tray-value-1" }),
    )
    .expect("a locked node takes the deposit");
    assert_eq!(deposited["pending"], true);
    let entry = deposited["entry"].as_str().unwrap().to_string();
    call(
        &state,
        &owner,
        "vault.node_unlock",
        json!({ "node": "acme" }),
    )
    .expect("unlock acme");
    let accepted = call(
        &state,
        &owner,
        "vault.pending_accept",
        json!({ "node": "acme", "entry": entry }),
    );
    assert!(accepted.is_ok(), "{accepted:?}");
    assert_eq!(
        call(
            &state,
            &owner,
            "entry.reveal",
            json!({ "node": "acme", "entry": entry })
        )
        .unwrap()["value"],
        "node-tray-value-1"
    );
    verify_clean(&state, &owner, "accepting a node-locked deposit");
}

#[test]
fn every_op_that_reads_the_node_key_works_after_a_node_lock_and_unlock() {
    // `lock_node` zeroises the node's hot key; `unlock_node` must bring it back. Nothing but the
    // whole-vault unlock used to, which stayed invisible while update/rotate only sealed to the
    // PUBLIC key.
    let (_disk, state, owner) = disk_vault();
    let created = call(
        &state,
        &owner,
        "entry.create",
        json!({ "node": "acme", "name": "CYCLED", "fields": server_fields() }),
    )
    .unwrap();
    let entry = created["entry"].as_str().unwrap().to_string();
    let fid = field_ids_of(&state, &owner, &entry);
    for round in 0..2 {
        call(&state, &owner, "vault.node_lock", json!({ "node": "acme" })).unwrap();
        // locked: refused, and a refusal never leaks a zeroed-key decrypt attempt as a value
        let err = call(
            &state,
            &owner,
            "entry.reveal",
            json!({ "node": "acme", "entry": entry }),
        );
        assert!(err.is_err(), "round {round}: a locked node does not reveal");
        call(
            &state,
            &owner,
            "vault.node_unlock",
            json!({ "node": "acme" }),
        )
        .unwrap();
        let g = || gen_of(&state, &owner, "acme");
        let revealed = call(
            &state,
            &owner,
            "entry.reveal",
            json!({ "node": "acme", "entry": entry }),
        )
        .unwrap();
        assert_eq!(
            revealed["fields"][2]["value"], "pw-9d2c41aa",
            "round {round}"
        );
        call(
            &state,
            &owner,
            "entry.get",
            json!({ "node": "acme", "entry": entry }),
        )
        .unwrap();
        call(
            &state,
            &owner,
            "entry.update",
            json!({ "node": "acme", "entry": entry,
            "generation": g(), "field": fid[0], "value": format!("host-{round}.fields.test") }),
        )
        .unwrap();
        call(
            &state,
            &owner,
            "field.add",
            json!({ "node": "acme", "entry": entry, "generation": g(),
            "fields": [{ "label": format!("extra-{round}"), "value": "x" }] }),
        )
        .unwrap();
        call(
            &state,
            &owner,
            "entry.rotate",
            json!({ "node": "acme", "entry": entry,
            "generation": g(), "field": fid[1], "value": format!("svc_{round}") }),
        )
        .unwrap();
    }
    verify_clean(&state, &owner, "two node lock/unlock cycles");
}

// ===========================================================================
// the rest of the surface
// ===========================================================================

#[test]
fn an_approved_reveal_returns_only_the_fields_asked_for() {
    // ADR-042's approval-on-demand path decrypts one entry while the vault stays locked. An approval
    // covers the entry; `fieldIds` narrows what the approved reveal hands back.
    let m = Mem::new();
    let entry = m.create("APPROVED", server_fields());
    let fids = ids_of(&m.get(&entry));
    m.state.lock();
    let agent = scope(
        "a",
        &[Capability::List, Capability::Read, Capability::Reveal],
    );
    let params = json!({ "node": "a", "entry": entry, "fieldIds": [fids[2]] });
    let pending = ops::dispatch(&m.state, &agent, NOW, "entry.reveal", &params).unwrap_err();
    let OpError::ApprovalPending { request, .. } = pending else {
        panic!("a locked reveal of a reachable entry asks for approval")
    };
    ops::dispatch(
        &m.state,
        &scope("a", &[Capability::Admin]),
        NOW + 10,
        "vault.approval_decide",
        &json!({ "request": request, "approved": true }),
    )
    .expect("the owner approves");
    let revealed =
        ops::dispatch(&m.state, &agent, NOW + 20, "entry.reveal", &params).expect("the retry");
    assert!(m.state.is_locked(), "approving does not unlock the vault");
    assert_eq!(
        revealed["fields"].as_array().unwrap().len(),
        1,
        "only the field asked for"
    );
    assert_eq!(revealed["fields"][0]["id"], fids[2].as_str());
    assert_eq!(revealed["value"], "pw-9d2c41aa");
    assert!(
        !revealed.to_string().contains("db-7f3a.fields.test"),
        "no other field's value came out"
    );
    // The approval was consumed: asking again starts a fresh request.
    let again = ops::dispatch(&m.state, &agent, NOW + 30, "entry.reveal", &params).unwrap_err();
    assert!(
        matches!(again, OpError::ApprovalPending { .. }),
        "{again:?}"
    );
}

#[test]
fn a_removed_multi_field_entry_is_restored_whole() {
    let m = Mem::new();
    let entry = m.create(
        "REMOVABLE",
        json!([{ "label": "host", "value": "h.fields.test" }, { "label": "otp", "value": SEED }]),
    );
    let before = m.reveal(&entry);
    assert_eq!(m.counts_totp("a"), 1);
    let (r, removed) = m.call(
        "entry.remove",
        json!({ "node": "a", "entry": entry, "generation": m.gen("a") }),
    );
    r.expect("entry.remove");
    assert_eq!(m.counts_totp("a"), 0, "a removed entry stops counting");
    let (r, _) = m.call(
        "entry.undo",
        json!({ "node": "a", "id": removed.unwrap(), "generation": m.gen("a") }),
    );
    r.expect("entry.undo of a removal");
    assert_eq!(
        m.reveal(&entry),
        before,
        "every field, id and value is back"
    );
    let row = m.manifest_entry("a", &entry);
    assert_eq!(
        (row.field_count, row.has_totp),
        (2, true),
        "the projection came back with it"
    );
    assert_eq!(m.counts_totp("a"), 1);
    assert_eq!(m.version_byte("a", &entry), 2);
}

#[test]
fn every_new_op_refuses_each_missing_required_param() {
    let m = Mem::new();
    let entry = m.create("PARAMS", server_fields());
    let fid = ids_of(&m.get(&entry)).remove(0);
    let g = m.gen("a");
    let cases: Vec<(&str, Value)> = vec![
        ("entry.get", json!({ "node": "a", "entry": entry })),
        (
            "field.add",
            json!({ "node": "a", "entry": entry, "generation": g,
                    "fields": [{ "label": "x", "value": "y" }] }),
        ),
        (
            "field.update",
            json!({ "node": "a", "entry": entry, "generation": g, "field": fid,
                    "patch": { "label": "x" } }),
        ),
        (
            "field.remove",
            json!({ "node": "a", "entry": entry, "generation": g, "field": fid }),
        ),
        (
            "field.reorder",
            json!({ "node": "a", "entry": entry, "generation": g, "order": ids_of(&m.get(&entry)) }),
        ),
    ];
    for (op, full) in cases {
        for key in full.as_object().unwrap().keys() {
            let mut params = full.clone();
            params.as_object_mut().unwrap().remove(key);
            let msg = malformed(m.err(op, params));
            assert!(
                msg.contains(&format!("params.{key}")),
                "{op} without {key}: {msg}"
            );
        }
    }
    assert_eq!(m.gen("a"), g, "none of the refusals wrote anything");
}

#[test]
fn entry_get_does_not_see_a_tray_entry() {
    let (_disk, state, owner) = disk_vault();
    call(&state, &owner, "vault.node_lock", json!({ "node": "acme" })).unwrap();
    let deposited = call(
        &state,
        &owner,
        "entry.create",
        json!({ "node": "acme", "name": "TRAYED", "fields": [{ "label": "a", "value": "b" }] }),
    )
    .unwrap();
    assert_eq!(deposited["pending"], true);
    call(
        &state,
        &owner,
        "vault.node_unlock",
        json!({ "node": "acme" }),
    )
    .unwrap();
    // It is not in the manifest yet, so it is not an entry yet: every read says so.
    for op in ["entry.get", "entry.reveal"] {
        let e = call(
            &state,
            &owner,
            op,
            json!({ "node": "acme", "entry": deposited["entry"] }),
        )
        .unwrap_err();
        assert!(matches!(e, OpError::NotFound(_)), "{op}: {e:?}");
    }
    let fid = deposited["fieldIds"][0].clone();
    let e = call(
        &state,
        &owner,
        "field.add",
        json!({ "node": "acme", "entry": deposited["entry"],
                "generation": gen_of(&state, &owner, "acme"),
                "fields": [{ "label": "x", "value": "y" }] }),
    )
    .unwrap_err();
    assert!(
        matches!(e, OpError::NotFound(_)),
        "a write to a tray entry: {e:?} ({fid})"
    );
}
