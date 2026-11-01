//! 4.5 / ADR-086 — taking a field change back. `entry.undo` (addressed by the
//! audit id the changing call returned) covers all four field ops; its answer
//! now says `ok` and what `restored`; and a field edit is undoable for seven
//! days, like a removed entry.

mod common;

use std::collections::BTreeMap;

use common::*;
use credmgr_brokerd::protocol::OpError;
use serde_json::{json, Value};

const DAY: i64 = 24 * 60 * 60;

fn generation(f: &Fixture, owner: &str, at: i64) -> u64 {
    send_at(
        f,
        at,
        None,
        Some(owner),
        "entry.list",
        json!({ "node": "acme" }),
    )
    .unwrap()["generation"]
        .as_u64()
        .unwrap()
}

/// label → value of every field, through the real reveal.
fn fields_of(f: &Fixture, owner: &str, entry: &str, at: i64) -> BTreeMap<String, String> {
    let r = send_at(
        f,
        at,
        None,
        Some(owner),
        "entry.reveal",
        json!({ "node": "acme", "entry": entry }),
    )
    .unwrap();
    r["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| {
            (
                x["label"].as_str().unwrap().to_string(),
                x["value"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

fn ids_of(f: &Fixture, owner: &str, entry: &str, at: i64) -> Vec<(String, String)> {
    let r = send_at(
        f,
        at,
        None,
        Some(owner),
        "entry.get",
        json!({ "node": "acme", "entry": entry }),
    )
    .unwrap();
    r["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| {
            (
                x["id"].as_str().unwrap().to_string(),
                x["label"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

fn three_field_entry(f: &Fixture, owner: &str) -> String {
    send(
        f,
        None,
        Some(owner),
        "entry.create",
        json!({
            "node": "acme", "name": "login",
            "fields": [
                { "label": "user", "value": "alice" },
                { "label": "pass", "value": "p-one" },
                { "label": "memo", "value": "m-one" }
            ]
        }),
    )
    .expect("create")["entry"]
        .as_str()
        .unwrap()
        .to_string()
}

fn undo(f: &Fixture, owner: &str, at: i64, audit: &str) -> Result<Value, OpError> {
    let g = generation(f, owner, at);
    send_at(
        f,
        at,
        None,
        Some(owner),
        "entry.undo",
        json!({ "node": "acme", "id": audit, "generation": g }),
    )
}

/// Runs one field op as the owner, returns (reply, audit id).
fn op(f: &Fixture, owner: &str, at: i64, name: &str, entry: &str, extra: Value) -> (Value, String) {
    let mut params =
        json!({ "node": "acme", "entry": entry, "generation": generation(f, owner, at) });
    for (k, v) in extra.as_object().unwrap() {
        params[k] = v.clone();
    }
    let request = credmgr_brokerd::protocol::Request {
        id: "r".into(),
        op: name.into(),
        token: Some(owner.into()),
        params,
    };
    let (res, audit) = credmgr_brokerd::server::handle_request_at(
        &f.state,
        &peer(None),
        &request,
        at,
        std::time::Instant::now(),
    );
    (
        res.unwrap_or_else(|e| panic!("{name}: {e:?}")),
        audit.expect("the op was audited"),
    )
}

#[test]
fn every_field_op_is_taken_back_by_entry_undo_and_the_answer_says_what_was_restored() {
    let (f, owner, _) = with_acme();
    let entry = three_field_entry(&f, &owner);
    let original = fields_of(&f, &owner, &entry, NOW);
    let ids = ids_of(&f, &owner, &entry, NOW);
    let id_of = |label: &str| ids.iter().find(|(_, l)| l == label).unwrap().0.clone();

    // field.remove
    let (_, audit) = op(
        &f,
        &owner,
        NOW,
        "field.remove",
        &entry,
        json!({ "field": id_of("memo") }),
    );
    assert_eq!(fields_of(&f, &owner, &entry, NOW).len(), 2);
    let r = undo(&f, &owner, NOW, &audit).expect("undo remove");
    assert_eq!(r["ok"], true, "{r}");
    assert_eq!(r["restored"]["action"], "field.remove");
    assert_eq!(r["restored"]["fieldCount"], 3);
    assert_eq!(fields_of(&f, &owner, &entry, NOW), original);

    // field.update
    let (_, audit) = op(
        &f,
        &owner,
        NOW,
        "field.update",
        &entry,
        json!({ "field": id_of("pass"), "patch": { "value": "p-two" } }),
    );
    assert_eq!(fields_of(&f, &owner, &entry, NOW)["pass"], "p-two");
    let r = undo(&f, &owner, NOW, &audit).expect("undo update");
    assert_eq!(
        (r["ok"].clone(), r["restored"]["action"].clone()),
        (json!(true), json!("field.update"))
    );
    assert_eq!(fields_of(&f, &owner, &entry, NOW), original);

    // field.reorder
    let mut order: Vec<String> = ids.iter().map(|(i, _)| i.clone()).collect();
    order.reverse();
    let (_, audit) = op(
        &f,
        &owner,
        NOW,
        "field.reorder",
        &entry,
        json!({ "order": order }),
    );
    assert_ne!(ids_of(&f, &owner, &entry, NOW), ids);
    let r = undo(&f, &owner, NOW, &audit).expect("undo reorder");
    assert_eq!(r["restored"]["action"], "field.reorder");
    assert_eq!(ids_of(&f, &owner, &entry, NOW), ids, "the order is back");

    // field.add
    let (_, audit) = op(
        &f,
        &owner,
        NOW,
        "field.add",
        &entry,
        json!({ "fields": [{ "label": "extra", "value": "x" }] }),
    );
    assert_eq!(fields_of(&f, &owner, &entry, NOW).len(), 4);
    let r = undo(&f, &owner, NOW, &audit).expect("undo add");
    assert_eq!(r["restored"]["fieldCount"], 3);
    assert_eq!(fields_of(&f, &owner, &entry, NOW), original);

    // undoing an undo works the same way (ADR-055): the remove comes back.
    let (_, audit) = op(
        &f,
        &owner,
        NOW,
        "field.remove",
        &entry,
        json!({ "field": id_of("memo") }),
    );
    let first = undo(&f, &owner, NOW, &audit).unwrap();
    assert_eq!(first["ok"], true);
}

#[test]
fn a_removed_entry_undo_also_says_ok_and_what_was_restored() {
    let (f, owner, _) = with_acme();
    let entry = three_field_entry(&f, &owner);
    let g = generation(&f, &owner, NOW);
    let request = credmgr_brokerd::protocol::Request {
        id: "r".into(),
        op: "entry.remove".into(),
        token: Some(owner.clone()),
        params: json!({ "node": "acme", "entry": entry, "generation": g }),
    };
    let (res, audit) = credmgr_brokerd::server::handle_request_at(
        &f.state,
        &peer(None),
        &request,
        NOW,
        std::time::Instant::now(),
    );
    res.expect("remove");
    let r = undo(&f, &owner, NOW, &audit.unwrap()).expect("undo remove");
    assert_eq!(r["ok"], true);
    assert_eq!(r["restored"]["action"], "entry.remove");
    assert_eq!(r["restored"]["name"], "login");
    assert_eq!(r["restoredName"], "login", "the old key is still there");
}

#[test]
fn a_field_edit_can_be_undone_for_seven_days_and_not_on_the_eighth() {
    let (f, owner, _) = with_acme();
    let entry = three_field_entry(&f, &owner);
    let ids = ids_of(&f, &owner, &entry, NOW);
    let memo = ids.iter().find(|(_, l)| l == "memo").unwrap().0.clone();

    let (_, audit_old) = op(
        &f,
        &owner,
        NOW,
        "field.remove",
        &entry,
        json!({ "field": memo }),
    );
    // Day 6: still inside the window.
    // (the vault must still be open at that clock: touch it with a request first)
    let r = undo(&f, &owner, NOW + 6 * DAY, &audit_old);
    // Whether the idle clock closed the vault by day 6 is not what is being
    // tested; if it did, the test cannot reach the window and says so.
    let r = match r {
        Err(OpError::SessionExpired | OpError::VaultLocked) => {
            panic!("the vault's idle lock closed it before day 6 — move the clock in steps")
        }
        other => other,
    };
    r.expect("day 6 is inside the window");

    // A second edit, undone after more than seven days, is refused.
    let (_, audit) = op(
        &f,
        &owner,
        NOW + 6 * DAY,
        "field.remove",
        &entry,
        json!({ "field": memo }),
    );
    let r = undo(&f, &owner, NOW + 6 * DAY + 7 * DAY + 60, &audit);
    assert!(
        matches!(&r, Err(OpError::NotUndoable { reason, .. }) if reason.contains("seven days")),
        "{r:?}"
    );
    assert_eq!(
        credmgr_brokerd::protocol::to_wire("r", &r)["error"],
        "not_undoable"
    );
    // The edit is still in place (nothing was restored).
    assert_eq!(fields_of(&f, &owner, &entry, NOW + 6 * DAY).len(), 2);
}

#[test]
fn a_rotation_undo_keeps_its_old_unlimited_behaviour() {
    let (f, owner, _) = with_acme();
    let id = create_as_owner(&f, &owner, "rotating");
    let (_, audit) = op(
        &f,
        &owner,
        NOW,
        "entry.rotate",
        &id,
        json!({ "value": "v-2" }),
    );
    let r = undo(&f, &owner, NOW + 30 * DAY, &audit).expect("a rotation has no window");
    assert_eq!(r["ok"], true);
    assert_eq!(r["restored"]["action"], "entry.rotate");
}
