//! 4.2 / ADR-083 — `privateNames`: what a reader who is not the vault owner sees.
//! Real server wiring on a throwaway vault; the owner is a real login session.

mod common;

use common::*;
use credmgr_core::access::Origin;
use credmgr_core::registry::Capability;
use serde_json::{json, Value};

const SECRET_NAME: &str = "wallet-seed-zebra";
const SECRET_LABEL: &str = "recovery phrase quokka";

/// acme (3 entries, one named SECRET_NAME with a labelled field) and beta (2
/// entries), both `privateNames`, beta bound to its own workdir.
fn private_vault() -> (Fixture, String, String) {
    let (f, owner, _api_key) = with_acme();
    send(
        &f,
        None,
        Some(&owner),
        "entry.create",
        json!({ "node": "acme", "name": SECRET_NAME, "value": "v-2", "label": SECRET_LABEL }),
    )
    .expect("labelled entry");
    create_as_owner(&f, &owner, "third");
    let beta_dir = f._dir.path().join("work").join("beta");
    std::fs::create_dir_all(beta_dir.join("src")).unwrap();
    let beta_dir = std::fs::canonicalize(&beta_dir).unwrap();
    send(
        &f,
        None,
        Some(&owner),
        "node.create",
        json!({ "id": "beta", "label": "Beta Payroll", "parentId": "global",
                "workdirs": [beta_dir.to_string_lossy()] }),
    )
    .expect("beta");
    for n in ["b-one", "b-two"] {
        send(
            &f,
            None,
            Some(&owner),
            "entry.create",
            json!({ "node": "beta", "name": n, "value": "x" }),
        )
        .unwrap();
    }
    for node in ["acme", "beta"] {
        let r = send(
            &f,
            None,
            Some(&owner),
            "node.policy",
            json!({ "node": node, "reason": "hide names", "policy": { "privateNames": true } }),
        )
        .expect("policy");
        assert_eq!(
            r["notEnforced"],
            json!([]),
            "privateNames is enforced now: {r}"
        );
    }
    let beta_cwd = format!("{}/src", beta_dir.to_string_lossy());
    (f, owner, beta_cwd)
}

fn row<'a>(snap: &'a Value, id: &str) -> &'a Value {
    snap["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["id"] == id)
        .unwrap_or_else(|| panic!("no row {id}: {snap}"))
}

fn dump(v: &Value) -> String {
    v.to_string()
}

#[test]
fn an_agent_sees_an_opaque_row_with_a_count_in_the_graph_snapshot() {
    let (f, _owner, beta_cwd) = private_vault();
    let snap = as_agent(&f, "graph.snapshot", json!({})).expect("snapshot");
    let acme = row(&snap, "acme");
    assert_eq!(acme["nameHidden"], true);
    assert!(acme["name"].is_null() && acme["label"].is_null(), "{acme}");
    assert_eq!(acme["entryCount"], 3);
    assert!(acme.get("countHidden").is_none(), "{acme}");
    assert!(
        !dump(&snap).contains("Acme"),
        "the label must not appear anywhere: {snap}"
    );

    // A node with fewer than three entries hides its size too.
    let snap = send(&f, Some(&beta_cwd), None, "graph.snapshot", json!({})).expect("snapshot");
    let beta = row(&snap, "beta");
    assert_eq!(beta["nameHidden"], true);
    assert!(beta["entryCount"].is_null(), "{beta}");
    assert_eq!(beta["countHidden"], true);
    assert!(!dump(&snap).contains("Beta Payroll"), "{snap}");
}

#[test]
fn the_owner_sees_everything_and_a_badge() {
    let (f, owner, _) = private_vault();
    let snap = send(&f, None, Some(&owner), "graph.snapshot", json!({})).unwrap();
    for (id, label, n) in [("acme", "Acme", 3), ("beta", "Beta Payroll", 2)] {
        let r = row(&snap, id);
        assert_eq!(r["label"], label, "{r}");
        assert_eq!(r["nameHidden"], true, "badge: {r}");
        assert_eq!(r["counts"]["entries"], n);
    }
    // A node that is not private carries no badge.
    send(
        &f,
        None,
        Some(&owner),
        "node.policy",
        json!({ "node": "beta", "reason": "open again", "policy": { "privateNames": false } }),
    )
    .unwrap();
    let snap = send(&f, None, Some(&owner), "graph.snapshot", json!({})).unwrap();
    assert!(row(&snap, "beta").get("nameHidden").is_none());
    let list = send(
        &f,
        None,
        Some(&owner),
        "entry.list",
        json!({ "node": "acme" }),
    )
    .unwrap();
    assert!(
        list["names"]
            .as_array()
            .unwrap()
            .iter()
            .any(|n| n == SECRET_NAME),
        "{list}"
    );
    assert!(list.get("nameHidden").is_none());
}

#[test]
fn entry_list_is_empty_for_an_agent_with_a_count() {
    let (f, _owner, beta_cwd) = private_vault();
    let r = as_agent(&f, "entry.list", json!({ "node": "acme" })).expect("list");
    assert_eq!(r["entries"], json!([]));
    assert_eq!(r["nameHidden"], true);
    assert_eq!(r["count"], 3);
    assert_eq!(r["ids"], json!([]));
    assert_eq!(r["names"], json!([]));
    assert!(!dump(&r).contains(SECRET_NAME));
    let r = send(
        &f,
        Some(&beta_cwd),
        None,
        "entry.list",
        json!({ "node": "beta" }),
    )
    .expect("list");
    assert!(r["count"].is_null(), "{r}");
    assert_eq!(r["countHidden"], true);
    assert_eq!(r["entries"], json!([]));
}

#[test]
fn names_labels_and_notes_do_not_leak_through_get_search_the_tray_audit_or_notes() {
    let (f, owner, _) = private_vault();
    let owner_list = send(
        &f,
        None,
        Some(&owner),
        "entry.list",
        json!({ "node": "acme" }),
    )
    .unwrap();
    let secret_id = owner_list["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["name"] == SECRET_NAME)
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();

    // entry.get by id: no name, no label.
    let got = as_agent(
        &f,
        "entry.get",
        json!({ "node": "acme", "entry": secret_id }),
    )
    .expect("get");
    assert!(got["name"].is_null() && got["nameHidden"] == true, "{got}");
    assert!(
        !dump(&got).contains(SECRET_LABEL) && !dump(&got).contains(SECRET_NAME),
        "{got}"
    );
    // The owner still sees both.
    let got = send(
        &f,
        None,
        Some(&owner),
        "entry.get",
        json!({ "node": "acme", "entry": secret_id }),
    )
    .unwrap();
    assert!(dump(&got).contains(SECRET_LABEL) && dump(&got).contains(SECRET_NAME));

    // search: an agent finds nothing by a private name, the owner does.
    let hit = as_agent(&f, "search", json!({ "term": "zebra" })).unwrap();
    assert_eq!(hit["results"], json!([]), "{hit}");
    let hit = send(&f, None, Some(&owner), "search", json!({ "term": "zebra" })).unwrap();
    assert_eq!(hit["results"].as_array().unwrap().len(), 1);

    // the locked-write tray: an agent's own queued name is not echoed back to a reader without names.
    send(
        &f,
        None,
        Some(&owner),
        "vault.node_lock",
        json!({ "node": "acme" }),
    )
    .unwrap();
    as_agent(
        &f,
        "entry.create",
        json!({ "node": "acme", "name": "queued-marmot", "value": "x" }),
    )
    .expect("tray write");
    let tray = as_agent(&f, "vault.pending_list", json!({ "node": "acme" })).expect("tray");
    assert_eq!(tray["nameHidden"], true);
    assert!(!dump(&tray).contains("queued-marmot"), "{tray}");
    assert_eq!(tray["pending"].as_array().unwrap().len(), 1);
    let tray = send(
        &f,
        None,
        Some(&owner),
        "vault.pending_list",
        json!({ "node": "acme" }),
    )
    .unwrap();
    assert!(dump(&tray).contains("queued-marmot"));
    send(
        &f,
        None,
        Some(&owner),
        "vault.node_unlock",
        json!({ "node": "acme" }),
    )
    .unwrap();

    // audit: neither feed carries a name or a label (it never has; this pins it).
    for token in [None, Some(owner.as_str())] {
        let cwd = token.is_none().then(|| agent_cwd(&f));
        let feed = send(
            &f,
            cwd.as_deref(),
            token,
            "audit.tail",
            json!({ "limit": 500 }),
        )
        .unwrap();
        let text = dump(&feed);
        for needle in [SECRET_NAME, SECRET_LABEL, "queued-marmot"] {
            assert!(!text.contains(needle), "audit leaks {needle}: {text}");
        }
    }

    // notes: written by the owner, withheld from a reader with `notes` but no names.
    let notes_before = send(
        &f,
        None,
        Some(&owner),
        "notes.read",
        json!({ "node": "acme" }),
    )
    .unwrap();
    send(&f, None, Some(&owner), "notes.write",
        json!({ "node": "acme", "markdown": "payroll goes via quokka", "generation": notes_before["generation"] })).expect("note");
    let agent = f.state.tokens.issue(
        "acme",
        vec![
            Capability::List,
            Capability::Read,
            Capability::Reveal,
            Capability::Notes,
        ],
        Origin::Agent,
        None,
    );
    let note = send(
        &f,
        None,
        Some(&agent.id),
        "notes.read",
        json!({ "node": "acme" }),
    )
    .expect("notes.read");
    assert!(
        note["markdown"].is_null() && note["nameHidden"] == true,
        "{note}"
    );
    assert!(
        note["generation"].is_u64(),
        "a reader with `notes` can still write one: {note}"
    );
    assert!(!dump(&note).contains("quokka"));
    let note = send(
        &f,
        None,
        Some(&owner),
        "notes.read",
        json!({ "node": "acme" }),
    )
    .unwrap();
    assert_eq!(note["markdown"], "payroll goes via quokka");
}

#[test]
fn a_node_that_is_not_private_is_unchanged_for_an_agent() {
    let (f, owner, _) = with_acme();
    create_as_owner(&f, &owner, "plain-name");
    let snap = as_agent(&f, "graph.snapshot", json!({})).unwrap();
    let acme = row(&snap, "acme");
    assert_eq!(acme["label"], "Acme");
    assert!(acme.get("nameHidden").is_none());
    let l = as_agent(&f, "entry.list", json!({ "node": "acme" })).unwrap();
    assert!(l["names"]
        .as_array()
        .unwrap()
        .iter()
        .any(|n| n == "plain-name"));
}
