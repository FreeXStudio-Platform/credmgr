//! 4.1 / ADR-084 — one canonical form for names, enforced at the broker.
//! Every test drives the real server wiring on a throwaway `vault.init_*` vault.

mod common;

use common::*;
use credmgr_brokerd::protocol::OpError;
use serde_json::json;

const CYR_A: &str = "p\u{0430}yroll"; // payroll with a Cyrillic а
const CYR_C: &str = "\u{0441}loud"; // cloud with a Cyrillic с
const GRK_O: &str = "\u{03BF}pen"; // open with a Greek ο

fn exists(r: &Result<serde_json::Value, OpError>) -> bool {
    matches!(r, Err(OpError::EntryExists { .. }))
}

#[test]
fn a_cyrillic_twin_of_an_existing_name_is_refused_with_the_duplicate_error() {
    let (f, owner, _) = with_acme();
    create_as_owner(&f, &owner, "payroll");
    create_as_owner(&f, &owner, "cloud");
    create_as_owner(&f, &owner, "open");
    for twin in [CYR_A, CYR_C, GRK_O, "PAYROLL", "pay\u{200B}roll"] {
        let r = send(
            &f,
            None,
            Some(&owner),
            "entry.create",
            json!({ "node": "acme", "name": twin, "value": "x" }),
        );
        assert!(
            exists(&r),
            "{twin:?} must be refused as a duplicate, got {r:?}"
        );
    }
    // The wire code is the existing one.
    let r = send(
        &f,
        None,
        Some(&owner),
        "entry.create",
        json!({ "node": "acme", "name": CYR_A, "value": "x" }),
    );
    assert_eq!(wire(r.unwrap_err())["error"], "entry_exists");
}

#[test]
fn an_agent_cannot_write_a_twin_of_a_name_through_the_broker() {
    let (f, owner, _) = with_acme();
    create_as_owner(&f, &owner, "payroll");
    let r = as_agent(
        &f,
        "entry.create",
        json!({ "node": "acme", "name": CYR_A, "value": "x" }),
    );
    assert!(exists(&r), "{r:?}");
    // …and the batch route.
    let r = as_agent(
        &f,
        "entry.create_batch",
        json!({ "node": "acme", "entries": [{ "name": "fresh", "value": "1" }, { "name": CYR_A, "value": "2" }] }),
    );
    assert!(exists(&r), "{r:?}");
    // Nothing from the refused batch landed.
    let list = send(
        &f,
        None,
        Some(&owner),
        "entry.list",
        json!({ "node": "acme" }),
    )
    .unwrap();
    let names: Vec<_> = list["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["name"].as_str().unwrap().to_string())
        .collect();
    assert!(
        !names.iter().any(|n| n == "fresh" || n == CYR_A),
        "{names:?}"
    );
}

#[test]
fn a_twin_inside_one_batch_is_refused() {
    let (f, owner, _) = with_acme();
    let r = send(
        &f,
        None,
        Some(&owner),
        "entry.create_batch",
        json!({ "node": "acme", "entries": [{ "name": "payroll", "value": "1" }, { "name": CYR_A, "value": "2" }] }),
    );
    assert!(matches!(r, Err(OpError::Malformed(_))), "{r:?}");
}

#[test]
fn the_stored_name_stays_as_typed() {
    let (f, owner, _) = with_acme();
    // A pure-Cyrillic name is a normal name and is stored exactly.
    let pure = "\u{043F}\u{0440}\u{0438}\u{043C}\u{0435}\u{0440}";
    let r = send(
        &f,
        None,
        Some(&owner),
        "entry.create",
        json!({ "node": "acme", "name": pure, "value": "x" }),
    )
    .expect("pure Cyrillic accepted");
    assert!(
        r.get("warnings").is_none(),
        "no warning for a pure-script name: {r}"
    );
    let mixed = send(
        &f,
        None,
        Some(&owner),
        "entry.create",
        json!({ "node": "acme", "name": "MixedCase", "value": "x" }),
    )
    .unwrap();
    assert!(mixed.get("warnings").is_none());
    let list = send(
        &f,
        None,
        Some(&owner),
        "entry.list",
        json!({ "node": "acme" }),
    )
    .unwrap();
    let names: Vec<String> = list["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["name"].as_str().unwrap().to_string())
        .collect();
    assert!(
        names.contains(&pure.to_string()) && names.contains(&"MixedCase".to_string()),
        "{names:?}"
    );
}

#[test]
fn a_mixed_script_name_is_accepted_with_a_warning_field() {
    let (f, owner, _) = with_acme();
    let r = send(
        &f,
        None,
        Some(&owner),
        "entry.create",
        json!({ "node": "acme", "name": CYR_A, "value": "x" }),
    )
    .expect("accepted");
    assert_eq!(r["warnings"], json!(["mixed_script_name"]), "{r}");
    let b = send(
        &f,
        None,
        Some(&owner),
        "entry.create_batch",
        json!({ "node": "acme", "entries": [{ "name": GRK_O, "value": "x" }] }),
    )
    .expect("batch accepted");
    assert_eq!(b["warnings"], json!(["mixed_script_name"]), "{b}");
    // A node label gets the same flag.
    let n = send(
        &f,
        None,
        Some(&owner),
        "node.update",
        json!({ "node": "acme", "label": "Acm\u{0435}" }),
    )
    .expect("label accepted");
    assert_eq!(n["warnings"], json!(["mixed_script_name"]), "{n}");
}

#[test]
fn the_locked_write_tray_compares_canonical_forms_too() {
    let (f, owner, _) = with_acme();
    create_as_owner(&f, &owner, "payroll");
    send(
        &f,
        None,
        Some(&owner),
        "vault.node_lock",
        json!({ "node": "acme" }),
    )
    .expect("lock");
    // Against the manifest, while the node is locked…
    let r = as_agent(
        &f,
        "entry.create",
        json!({ "node": "acme", "name": CYR_A, "value": "x" }),
    );
    assert!(exists(&r), "{r:?}");
    // …and against an entry already waiting in the tray.
    as_agent(
        &f,
        "entry.create",
        json!({ "node": "acme", "name": "queued", "value": "x" }),
    )
    .expect("tray write");
    let r = as_agent(
        &f,
        "entry.create",
        json!({ "node": "acme", "name": "qu\u{0435}ued", "value": "x" }),
    );
    assert!(exists(&r), "{r:?}");
}

#[test]
fn restoring_a_removed_entry_whose_name_is_now_held_by_a_twin_is_a_collision() {
    let (f, owner, _) = with_acme();
    let id = create_as_owner(&f, &owner, "payroll");
    let generation = |f: &Fixture| -> u64 {
        send(
            f,
            None,
            Some(&owner),
            "entry.list",
            json!({ "node": "acme" }),
        )
        .unwrap()["generation"]
            .as_u64()
            .unwrap()
    };
    let g = generation(&f);
    send(
        &f,
        None,
        Some(&owner),
        "entry.remove",
        json!({ "node": "acme", "entry": id, "generation": g }),
    )
    .expect("remove");
    // A look-alike now holds the name (the original is gone, so the broker allows it).
    send(
        &f,
        None,
        Some(&owner),
        "entry.create",
        json!({ "node": "acme", "name": CYR_A, "value": "x" }),
    )
    .expect("twin of a removed name");
    let g = generation(&f);
    let r = send(
        &f,
        None,
        Some(&owner),
        "entry.restore",
        json!({ "node": "acme", "entry": id, "generation": g }),
    );
    assert!(
        exists(&r),
        "replace-mode restore collides with the twin: {r:?}"
    );
    let g = generation(&f);
    let kept = send(
        &f,
        None,
        Some(&owner),
        "entry.restore",
        json!({ "node": "acme", "entry": id, "generation": g, "mode": "keep-both" }),
    )
    .expect("keep-both");
    assert_eq!(kept["restoredName"], "payroll old");
}

// ── ADR-092: a name has a length, so `canonical_name` has bounded input ─────

fn malformed<T: std::fmt::Debug>(r: &Result<T, OpError>) -> bool {
    matches!(r, Err(OpError::Malformed(_)))
}

#[test]
fn an_entry_name_over_200_characters_is_refused_and_200_is_accepted() {
    let (f, owner, _) = with_acme();
    let at_cap = "a".repeat(200);
    let over = "a".repeat(201);
    send(
        &f,
        None,
        Some(&owner),
        "entry.create",
        json!({ "node": "acme", "name": at_cap, "value": "x" }),
    )
    .expect("200 characters is fine");
    let r = send(
        &f,
        None,
        Some(&owner),
        "entry.create",
        json!({ "node": "acme", "name": over, "value": "x" }),
    );
    assert!(malformed(&r), "{r:?}");
    assert_eq!(wire(r.unwrap_err())["error"], "malformed_request");
    // Characters, not bytes: 200 two-byte letters are 400 bytes and are accepted.
    send(
        &f,
        None,
        Some(&owner),
        "entry.create",
        json!({ "node": "acme", "name": "\u{00e9}".repeat(200), "value": "x" }),
    )
    .expect("200 characters");
    // A megabyte is refused by the same rule, without being folded first.
    let huge = "b".repeat(1_000_000);
    let r = send(
        &f,
        None,
        Some(&owner),
        "entry.create",
        json!({ "node": "acme", "name": huge, "value": "x" }),
    );
    assert!(malformed(&r), "{r:?}");
}

#[test]
fn the_message_names_the_bound_and_never_the_text() {
    let (f, owner, _) = with_acme();
    let secret_looking = format!("{}-visible-in-no-error", "z".repeat(210));
    let r = send(
        &f,
        None,
        Some(&owner),
        "entry.create",
        json!({ "node": "acme", "name": secret_looking, "value": "x" }),
    );
    let OpError::Malformed(msg) = r.unwrap_err() else {
        panic!("expected malformed")
    };
    assert!(msg.contains("200"), "{msg}");
    assert!(!msg.contains("visible-in-no-error"), "{msg}");
}

#[test]
fn a_batch_item_over_the_cap_is_refused_by_index_and_nothing_is_written() {
    let (f, owner, _) = with_acme();
    let r = send(
        &f,
        None,
        Some(&owner),
        "entry.create_batch",
        json!({
            "node": "acme",
            "entries": [ { "name": "fine", "value": "x" }, { "name": "c".repeat(201), "value": "y" } ],
        }),
    );
    let OpError::Malformed(msg) = r.unwrap_err() else {
        panic!("expected malformed")
    };
    assert!(msg.contains("entries[1].name"), "{msg}");
    let list = send(
        &f,
        None,
        Some(&owner),
        "entry.list",
        json!({ "node": "acme" }),
    )
    .expect("list");
    assert_eq!(
        list["names"],
        json!(["API_KEY"]),
        "a refused batch leaves nothing behind (only the fixture entry): {list}"
    );
}

#[test]
fn a_new_node_label_has_the_same_bounds_node_update_already_had() {
    let (f, owner, _) = with_acme();
    let create = |id: &str, label: String| {
        send(
            &f,
            None,
            Some(&owner),
            "node.create",
            json!({ "id": id, "label": label, "parentId": "global", "workdirs": [] }),
        )
    };
    let r = create("long-label", "L".repeat(121));
    assert!(malformed(&r), "{r:?}");
    let r = create("ctl-label", "bad\nlabel".to_string());
    assert!(malformed(&r), "{r:?}");
    let r = create("blank-label", "   ".to_string());
    assert!(malformed(&r), "{r:?}");
}
