//! Golden byte shapes for the signed store documents as the alpha.6 code wrote
//! them (ADR-078, work package A0).
//!
//! Every signed document in the store — the node manifest, a rotation snapshot,
//! a removal archive — is verified by **re-serialising the parsed struct** and
//! comparing the HMAC against the stored tag. So adding a field to
//! `ManifestEntry` is only safe if the new field is *omitted* from the bytes
//! whenever it holds its default: otherwise the re-serialisation of an
//! alpha.6-written document gains a key it never had, the HMAC no longer
//! matches, and every existing vault refuses to open as tampered.
//!
//! The constants below were produced by the unmodified alpha.6 code (fixed test
//! keys, a fixed entry) **before** `has_totp` was added to the struct, and are
//! pinned verbatim. They are not regenerated from the code under test: that
//! would make the test agree with whatever the code does today, which is the
//! one thing it exists to refuse.

use credmgr_core::inference::EntryType;
use credmgr_store::manifest::{self, Counts, ManifestBody, ManifestEntry, Sensitivity};
use credmgr_store::paths::VaultPaths;
use credmgr_store::{atomic, entry_archive, rotation_history, StoreError};

const MANIFEST_KEY: [u8; 32] = [3u8; 32];
const HISTORY_KEY: [u8; 32] = [4u8; 32];

const ENTRY_JSON: &str = r#"{"id":"e_bbbbbbbbbbbb","name":"vps-root","ref":3060,"type":"server","sensitivity":"critical","fieldCount":4,"sha256":"deadbeef","modified":1700000000,"expiresAt":null,"rotatedAt":null}"#;

/// `manifest.json` exactly as `manifest::save` wrote it (key `[3; 32]`).
const MANIFEST_FILE: &str = r#"{
  "nodeId": "n_aaaaaaaa",
  "entries": [
    {
      "id": "e_bbbbbbbbbbbb",
      "name": "vps-root",
      "ref": 3060,
      "type": "server",
      "sensitivity": "critical",
      "fieldCount": 4,
      "sha256": "deadbeef",
      "modified": 1700000000,
      "expiresAt": null,
      "rotatedAt": null
    }
  ],
  "counts": {
    "entries": 1,
    "totp": 0
  },
  "notesSha256": null,
  "generation": 5,
  "hmac": "9492f7b937a717b25444813558d2eb9435f7eb5c5d39697cb6f90626761da23a"
}"#;

/// The rotation snapshot for generation 5 as `rotation_history::save` wrote it
/// (node `a`, key `[4; 32]`).
const ROTATION_FILE: &str = r#"{"nodeId":"a","entry":{"id":"e_bbbbbbbbbbbb","name":"vps-root","ref":3060,"type":"server","sensitivity":"critical","fieldCount":4,"sha256":"deadbeef","modified":1700000000,"expiresAt":null,"rotatedAt":null},"generation":5,"recordedAt":1700000000,"hmac":"4db100020a6726123f2ae15a376cec0c08e98fabe3c481b5f8723c4a99012ad7"}"#;

/// The removal-archive record as `entry_archive::remove` wrote it (node `a`,
/// key `[4; 32]`, removed at 1_700_000_000).
const REMOVAL_FILE: &str = r#"{"nodeId":"a","entry":{"id":"e_bbbbbbbbbbbb","name":"vps-root","ref":3060,"type":"server","sensitivity":"critical","fieldCount":4,"sha256":"deadbeef","modified":1700000000,"expiresAt":null,"rotatedAt":null},"removedAt":1700000000,"hmac":"1ddf06de0afd1e8d6cb3d908a1971f02c152ca36b9dbc5ba4ade1db9ad8c997c"}"#;

fn entry(has_totp: bool) -> ManifestEntry {
    ManifestEntry {
        id: "e_bbbbbbbbbbbb".to_string(),
        name: "vps-root".to_string(),
        r#ref: 3060,
        entry_type: EntryType::Server,
        sensitivity: Sensitivity::Critical,
        field_count: 4,
        sha256: "deadbeef".to_string(),
        modified: 1_700_000_000,
        expires_at: None,
        rotated_at: None,
        has_totp,
    }
}

fn paths() -> (tempfile::TempDir, VaultPaths) {
    let dir = tempfile::tempdir().unwrap();
    let paths = VaultPaths::new(dir.path().to_path_buf());
    (dir, paths)
}

#[test]
fn manifest_entry_without_totp_serialises_exactly_as_alpha6() {
    assert_eq!(serde_json::to_string(&entry(false)).unwrap(), ENTRY_JSON);
}

#[test]
fn the_has_totp_key_appears_only_when_true() {
    let on = serde_json::to_value(entry(true)).unwrap();
    assert_eq!(on["hasTotp"], true, "a true flag is written as `hasTotp`");
    let off = serde_json::to_value(entry(false)).unwrap();
    assert!(
        off.get("hasTotp").is_none(),
        "a false flag must be omitted, never written as `hasTotp: false`"
    );
}

#[test]
fn an_alpha6_entry_parses_with_the_flag_false_and_reserialises_byte_identically() {
    let parsed: ManifestEntry = serde_json::from_str(ENTRY_JSON).unwrap();
    assert_eq!(parsed, entry(false));
    assert!(!parsed.has_totp);
    assert_eq!(serde_json::to_string(&parsed).unwrap(), ENTRY_JSON);
}

#[test]
fn an_alpha6_manifest_still_loads_and_verifies() {
    let (_dir, paths) = paths();
    atomic::write(&paths.manifest("n_aaaaaaaa"), MANIFEST_FILE.as_bytes()).unwrap();

    let doc = manifest::load(&paths, &MANIFEST_KEY, "n_aaaaaaaa")
        .expect("the alpha.6 manifest must verify under the new struct");

    let mut expected = ManifestBody::new("n_aaaaaaaa");
    expected.generation = 5;
    expected.counts = Counts {
        entries: 1,
        totp: 0,
    };
    expected.entries.push(entry(false));
    assert_eq!(doc.body, expected);
    assert_eq!(
        doc.hmac,
        "9492f7b937a717b25444813558d2eb9435f7eb5c5d39697cb6f90626761da23a"
    );
}

#[test]
fn saving_an_alpha6_shaped_manifest_with_the_new_struct_writes_the_alpha6_bytes() {
    // The reverse direction: code that builds the same body today must produce
    // the file alpha.6 produced, byte for byte — including the HMAC.
    let (_dir, paths) = paths();
    let mut body = ManifestBody::new("n_aaaaaaaa");
    body.generation = 5;
    body.counts = Counts {
        entries: 1,
        totp: 0,
    };
    body.entries.push(entry(false));
    manifest::save(&paths, &MANIFEST_KEY, &body).unwrap();

    let written = String::from_utf8(atomic::read(&paths.manifest("n_aaaaaaaa")).unwrap()).unwrap();
    assert_eq!(written, MANIFEST_FILE);
}

#[test]
fn an_alpha6_rotation_snapshot_still_loads_and_verifies() {
    let (_dir, paths) = paths();
    atomic::write(
        &paths.entry_history_meta("a", "e_bbbbbbbbbbbb", 5),
        ROTATION_FILE.as_bytes(),
    )
    .unwrap();

    let loaded = rotation_history::load(&paths, &HISTORY_KEY, "a", "e_bbbbbbbbbbbb", 5)
        .expect("the alpha.6 rotation snapshot must verify under the new struct");
    assert_eq!(loaded, entry(false));
}

#[test]
fn an_alpha6_removal_archive_still_restores() {
    let (_dir, paths) = paths();
    atomic::write(
        &paths.removed_entry_meta("a", "e_bbbbbbbbbbbb"),
        REMOVAL_FILE.as_bytes(),
    )
    .unwrap();
    atomic::write(
        &paths.removed_entry_env("a", "e_bbbbbbbbbbbb"),
        b"ciphertext-bytes",
    )
    .unwrap();

    let peeked = entry_archive::peek(&paths, &HISTORY_KEY, "a", "e_bbbbbbbbbbbb", 1_700_000_100)
        .expect("the alpha.6 removal record must verify under the new struct");
    assert_eq!(peeked, entry(false));

    let restored =
        entry_archive::restore(&paths, &HISTORY_KEY, "a", "e_bbbbbbbbbbbb", 1_700_000_100).unwrap();
    assert_eq!(restored, entry(false));
    assert!(paths.entry_env("a", "e_bbbbbbbbbbbb").exists());
}

#[test]
fn a_document_that_carries_has_totp_cannot_be_read_back_by_dropping_the_key() {
    // What an alpha.6 binary would do to a beta vault (the documented one-way
    // door): it parses without knowing `hasTotp`, drops it, re-serialises and
    // finds the HMAC no longer matches. Simulated here by stripping the key
    // from a signed document that carried it — the signature must refuse.
    let (_dir, paths) = paths();
    let mut body = ManifestBody::new("n_aaaaaaaa");
    body.generation = 6;
    body.entries.push(entry(true));
    body.recount();
    manifest::save(&paths, &MANIFEST_KEY, &body).unwrap();

    let path = paths.manifest("n_aaaaaaaa");
    let mut doc: serde_json::Value = serde_json::from_slice(&atomic::read(&path).unwrap()).unwrap();
    let entry_obj = doc["entries"][0].as_object_mut().unwrap();
    assert_eq!(entry_obj.get("hasTotp"), Some(&serde_json::json!(true)));
    entry_obj.remove("hasTotp");
    atomic::write(&path, &serde_json::to_vec_pretty(&doc).unwrap()).unwrap();

    let err = manifest::load(&paths, &MANIFEST_KEY, "n_aaaaaaaa").unwrap_err();
    assert!(matches!(err, StoreError::ManifestTampered { .. }), "{err}");
}

#[test]
fn recount_counts_typed_totp_and_has_totp_entries_once_each() {
    let mut body = ManifestBody::new("n_aaaaaaaa");
    let mut typed = entry(false);
    typed.id = "e_000000000001".into();
    typed.entry_type = EntryType::Totp;
    let mut carrying = entry(true);
    carrying.id = "e_000000000002".into();
    let mut both = entry(true);
    both.id = "e_000000000003".into();
    both.entry_type = EntryType::Totp;
    let mut plain = entry(false);
    plain.id = "e_000000000004".into();
    body.entries = vec![typed, carrying, both, plain];

    body.recount();

    assert_eq!(body.counts.entries, 4);
    assert_eq!(
        body.counts.totp, 3,
        "typed totp, has_totp, and both — but never twice for one entry"
    );
}
