//! ADR-120 - what is in Orphaned, by name. `entry.list` on the orphan node is refused to
//! everyone (R0) and `graph.snapshot` leaves that node out, so a window that asks only the
//! usual questions found Orphaned empty after a seal (C4 F-10). The owner's own login
//! session now gets `meta.orphaned` in the snapshot: ids and names, never a value.

mod common;

use common::*;
use credmgr_brokerd::protocol::OpError;
use serde_json::json;

#[test]
fn the_owner_s_snapshot_names_what_was_sealed_and_nobody_else_s_does() {
    let (f, owner, entry) = with_acme();
    create_as_owner(&f, &owner, "second");
    let snap = |token: Option<&str>| send(&f, None, token, "graph.snapshot", json!({})).unwrap();
    assert_eq!(
        snap(Some(&owner))["meta"]["orphaned"],
        json!([]),
        "nothing sealed yet: an empty list, not an absent key"
    );
    send(
        &f,
        None,
        Some(&owner),
        "node.seal",
        json!({ "node": "acme" }),
    )
    .unwrap();

    let s = snap(Some(&owner));
    let orphaned = s["meta"]["orphaned"]
        .as_array()
        .expect("a list for the owner");
    let mut got: Vec<String> = orphaned
        .iter()
        .map(|o| o["name"].as_str().unwrap().to_string())
        .collect();
    got.sort();
    assert_eq!(got, ["API_KEY", "second"]);
    assert!(orphaned.iter().any(|o| o["id"] == json!(entry)));
    // names and ids only
    for o in orphaned {
        assert_eq!(o.as_object().unwrap().len(), 2, "{o}");
    }
    // the orphan node itself is still not in the snapshot, and its own list is still refused (R0)
    assert!(s["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .all(|n| n["kind"] != "orphan"));
    let r = send(
        &f,
        None,
        Some(&owner),
        "entry.list",
        json!({ "node": "orphan" }),
    );
    assert!(matches!(r, Err(OpError::NodeAccessDenied { .. })), "{r:?}");
    // an agent gets no such key
    let agent = as_agent(&f, "graph.snapshot", json!({}));
    if let Ok(a) = agent {
        assert!(a["meta"].get("orphaned").is_none(), "{a}");
    }
}

#[test]
fn restoring_a_sealed_node_takes_its_names_out_of_orphaned_again() {
    let (f, owner, _) = with_acme();
    send(
        &f,
        None,
        Some(&owner),
        "node.seal",
        json!({ "node": "acme" }),
    )
    .unwrap();
    let s = send(&f, None, Some(&owner), "graph.snapshot", json!({})).unwrap();
    assert_eq!(s["meta"]["orphaned"].as_array().unwrap().len(), 1);
    send(
        &f,
        None,
        Some(&owner),
        "node.restore",
        json!({ "node": "acme" }),
    )
    .unwrap();
    let s = send(&f, None, Some(&owner), "graph.snapshot", json!({})).unwrap();
    assert_eq!(s["meta"]["orphaned"], json!([]));
}
