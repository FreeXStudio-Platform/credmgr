//! 4.6 / ADR-087 — `util.generate`: the generator lives in the broker. Real
//! server wiring on a throwaway vault.

mod common;

use common::*;
use credmgr_brokerd::protocol::OpError;
use credmgr_core::access::Origin;
use credmgr_core::registry::Capability;
use serde_json::{json, Value};

fn gen_as_owner(f: &Fixture, owner: &str, params: Value) -> Result<Value, OpError> {
    send(f, None, Some(owner), "util.generate", params)
}

#[test]
fn the_default_value_is_twenty_characters_with_every_class_and_a_reported_strength() {
    let (f, owner, _) = with_acme();
    let r = gen_as_owner(&f, &owner, json!({})).expect("generate");
    let v = r["value"].as_str().unwrap();
    assert_eq!(v.len(), 20);
    assert_eq!(r["length"], 20);
    assert_eq!(r["symbols"], true);
    assert_eq!(r["pronounceable"], false);
    assert!(v.bytes().any(|b| b.is_ascii_lowercase()) && v.bytes().any(|b| b.is_ascii_uppercase()));
    assert!(v.bytes().any(|b| b.is_ascii_digit()) && v.bytes().any(|b| !b.is_ascii_alphanumeric()));
    assert_eq!(r["entropyBits"], 124);
    let again = gen_as_owner(&f, &owner, json!({})).unwrap();
    assert_ne!(again["value"], r["value"]);
}

#[test]
fn options_are_honoured_and_the_length_bounds_are_enforced() {
    let (f, owner, _) = with_acme();
    let plain = gen_as_owner(&f, &owner, json!({ "length": 30, "symbols": false })).unwrap();
    assert!(plain["value"]
        .as_str()
        .unwrap()
        .bytes()
        .all(|b| b.is_ascii_alphanumeric()));
    assert_eq!(plain["value"].as_str().unwrap().len(), 30);
    let pron = gen_as_owner(&f, &owner, json!({ "length": 20, "pronounceable": true })).unwrap();
    assert_eq!(pron["value"].as_str().unwrap().matches('-').count(), 4);
    assert!(gen_as_owner(&f, &owner, json!({ "length": 8 })).is_ok());
    assert!(gen_as_owner(&f, &owner, json!({ "length": 128 })).is_ok());
    for bad in [
        json!({ "length": 7 }),
        json!({ "length": 129 }),
        json!({ "length": -1 }),
        json!({ "length": "20" }),
        json!({ "symbols": "yes" }),
        json!({ "colour": 1 }),
    ] {
        let r = gen_as_owner(&f, &owner, bad.clone());
        assert!(matches!(r, Err(OpError::Malformed(_))), "{bad}: {r:?}");
    }
}

#[test]
fn a_caller_that_cannot_write_is_refused_and_an_agent_that_can_is_not() {
    let (f, _owner, _) = with_acme();
    let reader = f.state.tokens.issue(
        "acme",
        vec![Capability::List, Capability::Read, Capability::Reveal],
        Origin::Agent,
        None,
    );
    let r = send(&f, None, Some(&reader.id), "util.generate", json!({}));
    assert!(matches!(r, Err(OpError::CapabilityNotHeld { .. })), "{r:?}");
    // The cwd-scoped read-write agent may.
    as_agent(&f, "util.generate", json!({})).expect("a writer may generate");
}

#[test]
fn the_value_reaches_a_field_only_through_the_broker_and_never_the_audit_log() {
    let (f, owner, entry) = with_acme();
    let made = gen_as_owner(&f, &owner, json!({ "length": 24 })).unwrap();
    let value = made["value"].as_str().unwrap().to_string();
    let g = send(
        &f,
        None,
        Some(&owner),
        "entry.list",
        json!({ "node": "acme" }),
    )
    .unwrap()["generation"]
        .clone();
    send(&f, None, Some(&owner), "field.add",
        json!({ "node": "acme", "entry": entry, "generation": g, "fields": [{ "label": "generated", "value": value }] }))
        .expect("field.add");
    let revealed = send(
        &f,
        None,
        Some(&owner),
        "entry.reveal",
        json!({ "node": "acme", "entry": entry }),
    )
    .unwrap();
    assert!(revealed["fields"]
        .as_array()
        .unwrap()
        .iter()
        .any(|x| x["value"] == value.as_str()));
    let feed = send(
        &f,
        None,
        Some(&owner),
        "audit.tail",
        json!({ "limit": 500 }),
    )
    .unwrap()
    .to_string();
    assert!(
        !feed.contains(&value),
        "the generated value must not be audited"
    );
    assert!(feed.contains("util.generate"), "the call itself is");
}

#[test]
fn hex_makes_lower_case_hex_of_the_asked_length_and_refuses_a_contradiction() {
    let (f, owner, _) = with_acme();
    for length in [8usize, 20, 64, 128] {
        let r = gen_as_owner(&f, &owner, json!({ "hex": true, "length": length })).unwrap();
        let v = r["value"].as_str().unwrap();
        assert_eq!(v.len(), length);
        assert!(
            v.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "{v}"
        );
        assert_eq!(r["hex"], true);
        assert_eq!(r["symbols"], false, "hex carries no symbols");
        assert_eq!(r["pronounceable"], false);
        assert_eq!(r["entropyBits"], (length * 4) as u64);
    }
    // The default length applies, `symbols: false` is no contradiction, and a normal call reports hex false.
    let d = gen_as_owner(&f, &owner, json!({ "hex": true, "symbols": false })).unwrap();
    assert_eq!(d["value"].as_str().unwrap().len(), 20);
    assert_eq!(gen_as_owner(&f, &owner, json!({})).unwrap()["hex"], false);
    // Same bounds as every other mode; contradictions are refused.
    for bad in [
        json!({ "hex": true, "length": 7 }),
        json!({ "hex": true, "length": 129 }),
        json!({ "hex": "yes" }),
        json!({ "hex": true, "pronounceable": true }),
        json!({ "hex": true, "symbols": true }),
        json!({ "hex": true, "symbols": "yes" }),
    ] {
        let r = gen_as_owner(&f, &owner, bad.clone());
        assert!(matches!(r, Err(OpError::Malformed(_))), "{bad}: {r:?}");
    }
    let a = gen_as_owner(&f, &owner, json!({ "hex": true })).unwrap();
    let b = gen_as_owner(&f, &owner, json!({ "hex": true })).unwrap();
    assert_ne!(a["value"], b["value"]);
}
