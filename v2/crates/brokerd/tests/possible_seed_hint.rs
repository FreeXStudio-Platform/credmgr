//! Issue #40 / ADR-111 - a field that could be a TOTP seed but is not typed as one.
//!
//! A seed in a shape the inference does not recognise (a plain lower-case run, a
//! padded one) is text until its owner types it `totp-seed`: an agent that may reveal
//! the entry can read it. The broker cannot protect what it cannot tell from a word,
//! but it can say so. These tests pin the hint the window and the CLI show: the reply
//! to every write names the field (`possibleSeedFields`) and carries the
//! `possible_totp_seed` warning, `entry.get` marks the field (`possibleSeed`), and the
//! hint goes away once the owner types the field.

mod common;

use common::*;
use serde_json::{json, Value};

/// A made-up 16-character base32 run in the shape the inference leaves as text.
const LOWER_SEED: &str = "kv3q7rzd2mwnh5ta";
/// The same idea, padded.
const PADDED_SEED: &str = "KV3Q7RZD2MWNH5TA====";

fn warnings(v: &Value) -> Vec<String> {
    v["warnings"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|w| w.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn create(f: &Fixture, owner: &str, name: &str, fields: Value) -> Value {
    send(
        f,
        None,
        Some(owner),
        "entry.create",
        json!({ "node": "acme", "name": name, "fields": fields }),
    )
    .expect("entry.create")
}

#[test]
fn a_write_names_the_field_that_could_be_a_seed_and_warns() {
    let (f, owner, _) = with_acme();
    let made = create(
        &f,
        &owner,
        "svc-login",
        json!([
            { "label": "username", "value": "alice" },
            { "label": "authenticator key", "value": LOWER_SEED },
        ]),
    );
    let ids: Vec<String> = made["fieldIds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_eq!(made["possibleSeedFields"], json!([ids[1]]), "{made}");
    assert!(
        warnings(&made).contains(&"possible_totp_seed".to_string()),
        "{made}"
    );

    // The padded shape is flagged too.
    let padded = create(
        &f,
        &owner,
        "svc-padded",
        json!([{ "label": "2fa", "value": PADDED_SEED }]),
    );
    assert_eq!(
        padded["possibleSeedFields"].as_array().unwrap().len(),
        1,
        "{padded}"
    );

    // Ordinary entries carry neither field, so every older reply keeps its shape.
    let plain = create(
        &f,
        &owner,
        "svc-plain",
        json!([
            { "label": "host", "value": "db.internal" },
            { "label": "password", "value": "Tr1cky-passw0rd-9" },
        ]),
    );
    assert!(
        plain.get("possibleSeedFields").is_none() && plain.get("warnings").is_none(),
        "{plain}"
    );
}

#[test]
fn entry_get_marks_the_field_and_the_hint_goes_once_the_owner_types_it() {
    let (f, owner, _) = with_acme();
    let made = create(
        &f,
        &owner,
        "svc-login",
        json!([{ "label": "key", "value": LOWER_SEED }]),
    );
    let entry = made["entry"].as_str().unwrap().to_string();
    let field = made["fieldIds"][0].as_str().unwrap().to_string();

    let got = send(
        &f,
        None,
        Some(&owner),
        "entry.get",
        json!({ "node": "acme", "entry": entry }),
    )
    .unwrap();
    assert_eq!(got["fields"][0]["possibleSeed"], true, "{got}");
    assert!(
        !got.to_string().contains(LOWER_SEED),
        "entry.get never carries a value"
    );

    // As it stands the broker cannot compute a code from it ...
    let refused = send(
        &f,
        None,
        Some(&owner),
        "totp.code",
        json!({ "node": "acme", "entry": entry }),
    );
    assert!(
        refused.is_err(),
        "an untyped lower-case run is text: {refused:?}"
    );

    // ... and a reveal returns it (the exposure the hint warns about).
    let revealed = send(
        &f,
        None,
        Some(&owner),
        "entry.reveal",
        json!({ "node": "acme", "entry": entry }),
    )
    .unwrap();
    assert_eq!(revealed["value"], LOWER_SEED);

    // The owner types it: it is a seed from then on, withheld from a reveal, and unflagged.
    let generation = got["generation"].as_u64().unwrap();
    send(
        &f,
        None,
        Some(&owner),
        "field.update",
        json!({ "node": "acme", "entry": entry, "generation": generation,
                "field": field, "patch": { "type": "totp-seed" } }),
    )
    .expect("the owner types the field");
    let after = send(
        &f,
        None,
        Some(&owner),
        "entry.get",
        json!({ "node": "acme", "entry": entry }),
    )
    .unwrap();
    assert!(after["fields"][0].get("possibleSeed").is_none(), "{after}");
    let revealed = send(
        &f,
        None,
        Some(&owner),
        "entry.reveal",
        json!({ "node": "acme", "entry": entry }),
    )
    .unwrap();
    assert_eq!(revealed["fields"][0]["redacted"], "totp_seed", "{revealed}");
    assert!(send(
        &f,
        None,
        Some(&owner),
        "totp.code",
        json!({ "node": "acme", "entry": entry }),
    )
    .is_ok());
}

#[test]
fn a_field_its_owner_typed_to_anything_is_never_flagged() {
    let (f, owner, _) = with_acme();
    let made = create(
        &f,
        &owner,
        "typed",
        json!([{ "label": "token", "value": LOWER_SEED, "type": "text" }]),
    );
    assert!(made.get("possibleSeedFields").is_none(), "{made}");
    let made = create(
        &f,
        &owner,
        "typed-seed",
        json!([{ "label": "key", "value": LOWER_SEED, "type": "totp-seed" }]),
    );
    assert!(made.get("possibleSeedFields").is_none(), "{made}");
}

#[test]
fn updates_rotations_and_field_adds_carry_the_hint_too() {
    let (f, owner, entry) = with_acme();
    let list = send(
        &f,
        None,
        Some(&owner),
        "entry.list",
        json!({ "node": "acme" }),
    )
    .unwrap();
    let generation = list["generation"].as_u64().unwrap();

    let added = send(
        &f,
        None,
        Some(&owner),
        "field.add",
        json!({ "node": "acme", "entry": entry, "generation": generation,
                "fields": [{ "label": "totp key", "value": LOWER_SEED }] }),
    )
    .expect("field.add");
    assert_eq!(
        added["possibleSeedFields"].as_array().unwrap().len(),
        1,
        "{added}"
    );
    assert!(warnings(&added).contains(&"possible_totp_seed".to_string()));

    let generation = added["generation"].as_u64().unwrap();
    let rotated = send(
        &f,
        None,
        Some(&owner),
        "entry.rotate",
        json!({ "node": "acme", "entry": entry, "generation": generation,
                "value": "v-2", "field": added["fieldIds"][0] }),
    )
    .expect("entry.rotate of the first field");
    // The seed-shaped field is still there, untyped: still named.
    assert_eq!(
        rotated["possibleSeedFields"].as_array().unwrap().len(),
        1,
        "{rotated}"
    );

    // A batch names the item.
    let batch = send(
        &f,
        None,
        Some(&owner),
        "entry.create_batch",
        json!({ "node": "acme", "entries": [
            { "name": "B_ONE", "value": "plain" },
            { "name": "B_TWO", "value": LOWER_SEED },
        ] }),
    )
    .unwrap();
    assert!(
        batch["created"][0].get("possibleSeedFields").is_none(),
        "{batch}"
    );
    assert_eq!(
        batch["created"][1]["possibleSeedFields"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert!(warnings(&batch).contains(&"possible_totp_seed".to_string()));
}

#[test]
fn the_name_warning_and_the_seed_warning_share_one_list() {
    let (f, owner, _) = with_acme();
    // Latin + Cyrillic in one name raises `mixed_script_name`; the value raises the seed hint.
    let mixed = "pаypal-2fa"; // the second letter is Cyrillic
    let made = send(
        &f,
        None,
        Some(&owner),
        "entry.create",
        json!({ "node": "acme", "name": mixed, "fields": [{ "label": "2fa", "value": LOWER_SEED }] }),
    )
    .unwrap();
    let w = warnings(&made);
    assert!(
        w.contains(&"mixed_script_name".to_string())
            && w.contains(&"possible_totp_seed".to_string()),
        "{w:?}"
    );
}
