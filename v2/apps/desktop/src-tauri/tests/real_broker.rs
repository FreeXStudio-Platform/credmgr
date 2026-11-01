//! The bridge against the **real** `credmgrd` - the compiled daemon, a real vault, a
//! real socket - for the field-model operations (ADR-078).
//!
//! Every other bridge test talks to `tests/common`'s stand-in broker. That is the
//! right tool for the bridge's own properties (framing, token custody, error
//! mapping), and it cannot be the whole story for a new set of operations: a fake
//! that answers what the author *believes* the broker answers proves the bridge
//! sends the frame the author believes in. `tests/drift_guards.rs` closes most of
//! that gap by reading `ops.rs` off disk. This file closes the rest: the frames the
//! bridge's `*_at` cores put on the wire are the frames the real broker accepts,
//! and what comes back is what `bridge.ts` says it is.
//!
//! ADR-035 keeps this crate off the broker's MSRV pin, so it cannot link
//! `credmgr-brokerd`; it drives the **binary** instead. The daemon is
//! `<v2>/target/debug/credmgrd` (or `release`, or `$CREDMGRD_BIN`): build it first
//! with `cargo build -p credmgr-brokerd` in `v2/` - `cargo test --workspace` there
//! builds it too. **A missing binary fails these tests.** It is not skipped:
//! a gate that passes because the thing it checks was not there is not a gate.
//! (Set `CREDMGR_REAL_BROKER=skip` to say, out loud, that you know.)
//!
//! Every passphrase, value and seed below is a generated fixture. The daemon runs
//! against a vault, state directory and home directory under a private temp root,
//! so nothing here can touch a real vault.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use desktop_lib::commands;
use desktop_lib::fields_preview;
use desktop_lib::session::Session;
use serde_json::{json, Value};
use tauri::async_runtime::block_on;

const PASSPHRASE: &str = "fixture-pass-9d2c41";
/// 16 base32 characters = the 80-bit floor `totp.code` computes from (ADR-077).
const SEED_A: &str = "JBSWY3DPEHPK3PXP";
const SEED_B: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

fn v2_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("src-tauri is three levels below v2/")
        .to_path_buf()
}

fn daemon_binary() -> Option<PathBuf> {
    if let Some(explicit) = std::env::var_os("CREDMGRD_BIN") {
        return Some(PathBuf::from(explicit));
    }
    ["target/debug/credmgrd", "target/release/credmgrd"]
        .iter()
        .map(|p| v2_root().join(p))
        .find(|p| p.is_file())
}

/// A running `credmgrd` over a throwaway vault; killed when dropped.
struct Daemon {
    child: Child,
    socket: PathBuf,
    _root: tempfile::TempDir,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// `None` when the test has been told to skip.
fn start_daemon() -> Option<Daemon> {
    if std::env::var("CREDMGR_REAL_BROKER").as_deref() == Ok("skip") {
        eprintln!("CREDMGR_REAL_BROKER=skip: the real-broker bridge tests were NOT run");
        return None;
    }
    let binary = daemon_binary().unwrap_or_else(|| {
        panic!(
            "credmgrd is not built. Run `cargo build -p credmgr-brokerd` in {} (or set CREDMGRD_BIN). \
             These tests are the bridge's check against the real daemon and are not skipped silently.",
            v2_root().display()
        )
    });
    // A Unix socket path must stay under ~104 bytes, so the root is short and in /tmp.
    let root = tempfile::Builder::new()
        .prefix("cmbr")
        .tempdir_in("/tmp")
        .expect("temp root");
    let (vault, state, home) = (
        root.path().join("v"),
        root.path().join("s"),
        root.path().join("h"),
    );
    for dir in [&vault, &state, &home] {
        std::fs::create_dir_all(dir).expect("mkdir");
    }
    let log = std::fs::File::create(root.path().join("daemon.log")).expect("log");
    let child = Command::new(&binary)
        .env("CREDMGR_VAULT_DIR", &vault)
        .env("CREDMGR_STATE_DIR", &state)
        .env("HOME", &home)
        .env_remove("CREDMGR_TOKEN")
        .stdin(Stdio::null())
        .stdout(log.try_clone().expect("log clone"))
        .stderr(log)
        .spawn()
        .unwrap_or_else(|e| panic!("could not start {}: {e}", binary.display()));
    let socket = vault.join("run").join("broker.sock");
    let deadline = Instant::now() + Duration::from_secs(20);
    while std::os::unix::net::UnixStream::connect(&socket).is_err() {
        assert!(
            Instant::now() < deadline,
            "credmgrd never opened {}",
            socket.display()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    Some(Daemon {
        child,
        socket,
        _root: root,
    })
}

/// A daemon with an initialised, unlocked vault and one node, `fld`, under Global -
/// all through the bridge's own cores, the way the first-run screen and the lock
/// screen drive it.
fn ready() -> Option<(Daemon, Session)> {
    let daemon = start_daemon()?;
    let session = Session::new();
    let sock = daemon.socket.clone();
    let begun = block_on(commands::vault_init_begin_at(
        &session,
        sock.clone(),
        PASSPHRASE.into(),
    ))
    .expect("vault.init_begin");
    let code = begun["recoveryCode"]
        .as_str()
        .expect("recovery code")
        .to_string();
    block_on(commands::vault_init_confirm_at(
        &session,
        sock.clone(),
        code,
    ))
    .expect("vault.init_confirm");
    let state = block_on(commands::vault_unlock_at(
        &session,
        sock.clone(),
        PASSPHRASE.into(),
    ))
    .expect("vault.unlock");
    assert!(state.authenticated && !state.locked);
    block_on(commands::node_create_at(
        &session,
        sock,
        "fld".into(),
        "Fields".into(),
        "global".into(),
        None,
    ))
    .expect("node.create");
    Some((daemon, session))
}

fn sock(d: &Daemon) -> PathBuf {
    d.socket.clone()
}

fn labels(meta: &Value) -> Vec<String> {
    meta["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["label"].as_str().unwrap().to_string())
        .collect()
}

fn ids(meta: &Value) -> Vec<String> {
    meta["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["id"].as_str().unwrap().to_string())
        .collect()
}

fn is_field_id(id: &str) -> bool {
    id.len() == 10 && id.starts_with("f_") && id[2..].chars().all(|c| c.is_ascii_hexdigit())
}

#[test]
fn the_field_operations_work_through_the_bridge_against_the_real_daemon() {
    let Some((d, s)) = ready() else { return };

    // --- create with fields, then read it back three ways -------------------
    let created = block_on(commands::entry_create_at(
        &s,
        sock(&d),
        "fld".into(),
        "PROD_DB".into(),
        None,
        None,
        Some(json!([
            { "label": "host", "value": "db.fields.test" },
            { "label": "username", "value": "svc_91c2" },
            { "label": "password", "value": "pw-b04e77d1" },
        ])),
        None,
        None,
    ))
    .expect("entry.create with fields");
    assert_eq!(created["fieldCount"], 3);
    assert_eq!(created["pending"], false);
    let entry = created["entry"].as_str().unwrap().to_string();
    let created_ids: Vec<String> = created["fieldIds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert!(
        created_ids.iter().all(|i| is_field_id(i)),
        "{created_ids:?}"
    );

    // entry.get: labels, types, masking - and no value anywhere in the answer.
    let meta = block_on(commands::entry_get_at(
        &s,
        sock(&d),
        "fld".into(),
        entry.clone(),
    ))
    .expect("entry.get");
    assert_eq!(labels(&meta), ["host", "username", "password"]);
    assert_eq!(ids(&meta), created_ids);
    assert_eq!(meta["fieldCount"], 3);
    assert_eq!(
        meta["fields"][2]["masked"], true,
        "a password is masked by default"
    );
    assert_eq!(meta["typeOverridden"], false);
    let rendered = meta.to_string();
    assert!(
        !rendered.contains("pw-b04e77d1") && !rendered.contains("db.fields.test"),
        "entry.get carried a value: {rendered}"
    );

    // entry.reveal: every field, then one by id (where `value` appears).
    let all = block_on(commands::entry_reveal_at(
        &s,
        sock(&d),
        "fld".into(),
        entry.clone(),
        None,
    ))
    .expect("reveal all");
    assert_eq!(all["fields"].as_array().unwrap().len(), 3);
    assert!(
        all.get("value").is_none(),
        "no single value for three fields: {all}"
    );
    let one = block_on(commands::entry_reveal_at(
        &s,
        sock(&d),
        "fld".into(),
        entry.clone(),
        Some(vec![created_ids[2].clone()]),
    ))
    .expect("reveal one");
    assert_eq!(one["fields"].as_array().unwrap().len(), 1);
    assert_eq!(one["value"], "pw-b04e77d1");
    let unknown = block_on(commands::entry_reveal_at(
        &s,
        sock(&d),
        "fld".into(),
        entry.clone(),
        Some(vec!["f_deadbeef".into()]),
    ))
    .expect_err("an unknown field id");
    assert_eq!(unknown.code, "not_found");

    // --- field.add (at a position), field.update, field.reorder, field.remove ---
    let mut generation = meta["generation"].as_u64().unwrap();
    let added = block_on(commands::field_add_at(
        &s,
        sock(&d),
        "fld".into(),
        entry.clone(),
        generation,
        json!([{ "label": "region", "value": "eu-west-1" }]),
        Some(0),
    ))
    .expect("field.add");
    generation = added["generation"].as_u64().unwrap();
    assert_eq!(added["fieldCount"], 4);
    let region = added["added"][0].as_str().unwrap().to_string();
    assert_eq!(
        added["fieldIds"][0],
        region.as_str(),
        "inserted at position 0"
    );

    let updated = block_on(commands::field_update_at(
        &s,
        sock(&d),
        "fld".into(),
        entry.clone(),
        generation,
        region.clone(),
        json!({ "label": "zone", "type": "text", "masked": true }),
    ))
    .expect("field.update");
    generation = updated["generation"].as_u64().unwrap();
    let meta = block_on(commands::entry_get_at(
        &s,
        sock(&d),
        "fld".into(),
        entry.clone(),
    ))
    .unwrap();
    assert_eq!(meta["fields"][0]["label"], "zone");
    assert_eq!(meta["fields"][0]["typeOverridden"], true);
    assert_eq!(meta["fields"][0]["maskedOverridden"], true);
    assert_eq!(meta["fields"][0]["masked"], true);

    // "auto" clears the pins - the one spelling that works through the bridge, which drops nulls.
    let updated = block_on(commands::field_update_at(
        &s,
        sock(&d),
        "fld".into(),
        entry.clone(),
        generation,
        region.clone(),
        json!({ "type": "auto", "masked": "auto" }),
    ))
    .expect("field.update auto");
    generation = updated["generation"].as_u64().unwrap();
    let meta = block_on(commands::entry_get_at(
        &s,
        sock(&d),
        "fld".into(),
        entry.clone(),
    ))
    .unwrap();
    assert_eq!(meta["fields"][0]["typeOverridden"], false);
    assert_eq!(meta["fields"][0]["maskedOverridden"], false);

    // reorder: the exact permutation, and a non-permutation is refused.
    let mut order = ids(&meta);
    order.rotate_left(1);
    let reordered = block_on(commands::field_reorder_at(
        &s,
        sock(&d),
        "fld".into(),
        entry.clone(),
        generation,
        order.clone(),
    ))
    .expect("field.reorder");
    generation = reordered["generation"].as_u64().unwrap();
    assert_eq!(
        reordered["fieldIds"],
        json!(order),
        "the answer lists the ids in their new order"
    );
    let bad = block_on(commands::field_reorder_at(
        &s,
        sock(&d),
        "fld".into(),
        entry.clone(),
        generation,
        vec![order[0].clone()],
    ))
    .expect_err("not a permutation");
    assert_eq!(bad.code, "malformed_request");

    // a stale generation is a conflict carrying both generations
    let stale = block_on(commands::field_remove_at(
        &s,
        sock(&d),
        "fld".into(),
        entry.clone(),
        generation - 1,
        order[0].clone(),
    ))
    .expect_err("stale generation");
    assert_eq!(stale.code, "conflict");
    let detail = stale.detail.expect("conflict detail");
    assert_eq!(detail["currentGeneration"], generation);

    let removed = block_on(commands::field_remove_at(
        &s,
        sock(&d),
        "fld".into(),
        entry.clone(),
        generation,
        order[0].clone(),
    ))
    .expect("field.remove");
    generation = removed["generation"].as_u64().unwrap();
    assert_eq!(removed["fieldCount"], 3);

    // --- undo the removal through the bridge's own audit read -----------------
    let tail = block_on(commands::audit_tail_at(&s, sock(&d), Some(20))).expect("audit.tail");
    let record = tail["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["action"] == "field.remove")
        .expect("the removal is in the audit log");
    let undone = block_on(commands::entry_undo_at(
        &s,
        sock(&d),
        "fld".into(),
        record["id"].as_str().unwrap().into(),
        generation,
        None,
    ))
    .expect("entry.undo of a field.remove");
    assert!(undone["generation"].as_u64().unwrap() > generation);
    let meta = block_on(commands::entry_get_at(
        &s,
        sock(&d),
        "fld".into(),
        entry.clone(),
    ))
    .unwrap();
    assert_eq!(meta["fieldCount"], 4, "the removed field is back");
    generation = meta["generation"].as_u64().unwrap();

    // --- update / rotate: one field by id, and the whole list ----------------
    let password = ids(&meta)[ids(&meta).len() - 1].clone();
    let bare = block_on(commands::entry_update_at(
        &s,
        sock(&d),
        "fld".into(),
        entry.clone(),
        Some("pw-no-field".into()),
        generation,
        None,
        None,
        None,
        None,
        None,
    ))
    .expect_err("a value on a several-field entry without a field");
    assert_eq!(bare.code, "malformed_request");
    assert!(
        bare.message.contains("pass params.field"),
        "{}",
        bare.message
    );

    let rotated = block_on(commands::entry_rotate_at(
        &s,
        sock(&d),
        "fld".into(),
        entry.clone(),
        Some("pw-rotated-2".into()),
        generation,
        None,
        Some(password.clone()),
        None,
        None,
        None,
    ))
    .expect("entry.rotate of one field");
    generation = rotated["generation"].as_u64().unwrap();
    assert!(rotated["rotatedAt"].is_number());
    let got = block_on(commands::entry_reveal_at(
        &s,
        sock(&d),
        "fld".into(),
        entry.clone(),
        Some(vec![password.clone()]),
    ))
    .unwrap();
    assert_eq!(got["value"], "pw-rotated-2");

    let replaced = block_on(commands::entry_update_at(
        &s,
        sock(&d),
        "fld".into(),
        entry.clone(),
        None,
        generation,
        None,
        None,
        Some(json!([
            { "id": password, "label": "password", "value": "pw-rotated-2" },
            { "label": "port", "value": "5432" },
        ])),
        Some("server".into()),
        Some("high".into()),
    ))
    .expect("entry.update with fields and pins");
    assert_eq!(replaced["fieldCount"], 2);
    let meta = block_on(commands::entry_get_at(
        &s,
        sock(&d),
        "fld".into(),
        entry.clone(),
    ))
    .unwrap();
    assert_eq!(labels(&meta), ["password", "port"]);
    assert_eq!(
        meta["fields"][0]["id"],
        password.as_str(),
        "an id keeps a field's identity"
    );
    assert_eq!(meta["type"], "server");
    assert_eq!(meta["typeOverridden"], true);
    assert_eq!(meta["sensitivity"], "high");
    assert_eq!(meta["sensitivityOverridden"], true);
}

#[test]
fn totp_code_names_a_field_through_the_bridge_and_never_returns_a_seed() {
    let Some((d, s)) = ready() else { return };

    let make = |name: &str, fields: Value| {
        block_on(commands::entry_create_at(
            &s,
            sock(&d),
            "fld".into(),
            name.into(),
            None,
            None,
            Some(fields),
            None,
            None,
        ))
        .expect("create")
    };
    let one = make(
        "OTP_ONE",
        json!([
            { "label": "user", "value": "svc" },
            { "label": "authenticator", "value": SEED_A, "type": "totp-seed" },
        ]),
    );
    assert_eq!(
        block_on(commands::entry_get_at(
            &s,
            sock(&d),
            "fld".into(),
            one["entry"].as_str().unwrap().into()
        ))
        .unwrap()["hasTotp"],
        true
    );
    // One seed among other fields: found without being named.
    let code = block_on(commands::totp_code_at(
        &s,
        sock(&d),
        "fld".into(),
        one["entry"].as_str().unwrap().into(),
        None,
    ))
    .expect("totp.code");
    assert_eq!(code["code"].as_str().unwrap().len(), 6);
    assert!(
        !code.to_string().contains(SEED_A),
        "a seed in the answer: {code}"
    );

    // Two seeds: ambiguous without `field`, answered with it.
    let two = make(
        "OTP_TWO",
        json!([
            { "label": "first", "value": SEED_A, "type": "totp-seed" },
            { "label": "second", "value": SEED_B, "type": "totp-seed" },
        ]),
    );
    let entry = two["entry"].as_str().unwrap().to_string();
    let ambiguous = block_on(commands::totp_code_at(
        &s,
        sock(&d),
        "fld".into(),
        entry.clone(),
        None,
    ))
    .expect_err("two seeds, none named");
    assert_eq!(ambiguous.code, "malformed_request");
    let named = block_on(commands::totp_code_at(
        &s,
        sock(&d),
        "fld".into(),
        entry.clone(),
        Some(two["fieldIds"][1].as_str().unwrap().into()),
    ))
    .expect("totp.code with a field");
    assert_eq!(named["code"].as_str().unwrap().len(), 6);
    // totp.seed is human-only and presence-gated whichever field is meant.
    let seed = block_on(commands::totp_seed_at(
        &s,
        sock(&d),
        "fld".into(),
        entry,
        Some(two["fieldIds"][0].as_str().unwrap().into()),
    ))
    .expect_err("totp.seed");
    assert_eq!(seed.code, "presence_required");
}

/// "The preview is the contract" (`08 §5`), against the real broker: what
/// `fields_preview` showed is what the broker stored.
#[test]
fn what_fields_preview_showed_is_what_the_real_broker_stored() {
    let Some((d, s)) = ready() else { return };

    let text = "host: db.preview.test\nusername: svc\npassword:  two spaces kept\ntotp seed: JBSWY3DPEHPK3PXP\nnotes: a note\n///\nlone value\n";
    for (split, expected_entries) in [(false, 1), (true, 2)] {
        let preview = fields_preview::preview(Some(text), None, split).expect("preview");
        assert_eq!(preview.segments.len(), expected_entries);
        for (i, segment) in preview.segments.iter().enumerate() {
            // The screen sends the segment's fields: label and value verbatim, a pin only where there is one.
            let send: Vec<Value> = segment
                .fields
                .iter()
                .map(|f| {
                    let mut item = json!({ "label": f.label, "value": f.value });
                    if f.type_overridden {
                        item["type"] = json!(f.field_type);
                    }
                    if f.masked_overridden {
                        item["masked"] = json!(f.masked);
                    }
                    item
                })
                .collect();
            let name = format!("PREVIEW_{split}_{i}");
            let created = block_on(commands::entry_create_at(
                &s,
                sock(&d),
                "fld".into(),
                name,
                None,
                None,
                Some(Value::Array(send)),
                None,
                None,
            ))
            .expect("the broker accepts what the preview produced");
            let entry = created["entry"].as_str().unwrap().to_string();
            let meta = block_on(commands::entry_get_at(
                &s,
                sock(&d),
                "fld".into(),
                entry.clone(),
            ))
            .unwrap();

            // The projection the preview promised is the one the broker stored.
            assert_eq!(meta["type"], json!(segment.entry_type), "entry type");
            assert_eq!(
                meta["sensitivity"],
                json!(segment.sensitivity),
                "sensitivity"
            );
            assert_eq!(meta["fieldCount"], segment.field_count);
            assert_eq!(meta["hasTotp"], segment.has_totp);
            assert_eq!(meta["typeOverridden"], false, "previewing pinned nothing");
            // ...field by field: label, effective type, masking.
            for (stored, shown) in meta["fields"]
                .as_array()
                .unwrap()
                .iter()
                .zip(&segment.fields)
            {
                assert_eq!(stored["label"], shown.label.as_str());
                assert_eq!(stored["type"], json!(shown.field_type));
                assert_eq!(stored["masked"], shown.masked);
            }
            // ...and every value, byte for byte (including the two leading spaces).
            let revealed = block_on(commands::entry_reveal_at(
                &s,
                sock(&d),
                "fld".into(),
                entry,
                None,
            ))
            .unwrap();
            for (stored, shown) in revealed["fields"]
                .as_array()
                .unwrap()
                .iter()
                .zip(&segment.fields)
            {
                // a stored seed is never returned (ADR-094); every other value is, byte for byte
                if stored["type"] == "totp-seed" {
                    assert_eq!(stored["value"], Value::Null, "a seed stays in the broker");
                } else {
                    assert_eq!(stored["value"], shown.value.as_str());
                }
            }
        }
    }
}

#[test]
fn a_batch_of_multi_field_entries_is_validated_whole_through_the_bridge() {
    let Some((d, s)) = ready() else { return };

    let good = |name: &str| {
        json!({
            "name": name,
            "fields": [{ "label": "a", "value": "1" }, { "label": "b", "value": "2" }],
            "entryType": "note",
        })
    };
    let made = block_on(commands::entry_create_batch_at(
        &s,
        sock(&d),
        "fld".into(),
        json!([good("B1"), good("B2")]),
    ))
    .expect("entry.create_batch");
    assert_eq!(made["complete"], true);
    assert_eq!(made["created"].as_array().unwrap().len(), 2);
    assert_eq!(made["created"][0]["fieldCount"], 2);

    // One bad item (a control character in a label) writes nothing at all.
    let refused = block_on(commands::entry_create_batch_at(
        &s,
        sock(&d),
        "fld".into(),
        json!([
            good("B3"),
            { "name": "B4", "fields": [{ "label": "bad\nlabel", "value": "x" }] },
        ]),
    ))
    .expect_err("an invalid item");
    assert_eq!(refused.code, "malformed_request");
    assert!(
        refused.message.contains("entries[1]") && !refused.message.contains("bad"),
        "{}",
        refused.message
    );
    let listed = block_on(commands::dispatch_at(
        &s,
        sock(&d),
        "entry.list",
        json!({ "node": "fld" }),
    ))
    .unwrap();
    let names: Vec<&str> = listed["names"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n.as_str().unwrap())
        .collect();
    assert!(
        names.contains(&"B1")
            && names.contains(&"B2")
            && !names.contains(&"B3")
            && !names.contains(&"B4"),
        "{names:?}"
    );
}
