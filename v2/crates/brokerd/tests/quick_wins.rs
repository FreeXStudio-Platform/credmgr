//! ADR-156 — the post-launch quick-win ops (`entry.set_expiry`, `entry.expiring`, `entry.history`,
//! `entry.search`, `entry.get_by_ref`) end to end on a throwaway `vault.init_*` vault driven through the
//! real server wiring.

mod common;

use common::*;
use credmgr_brokerd::protocol::OpError;
use serde_json::{json, Value};

const DAY: i64 = 86_400;

fn owner_send(f: &Fixture, owner: &str, op: &str, params: Value) -> Result<Value, OpError> {
    send(f, None, Some(owner), op, params)
}

fn generation(f: &Fixture, owner: &str, node: &str) -> u64 {
    owner_send(f, owner, "entry.list", json!({ "node": node })).unwrap()["generation"]
        .as_u64()
        .unwrap()
}

fn set_expiry(
    f: &Fixture,
    owner: &str,
    node: &str,
    entry: &str,
    at: Value,
) -> Result<Value, OpError> {
    let g = generation(f, owner, node);
    let params = if at.is_null() {
        json!({ "node": node, "entry": entry, "generation": g, "clear": true })
    } else {
        json!({ "node": node, "entry": entry, "generation": g, "expiresAt": at })
    };
    owner_send(f, owner, "entry.set_expiry", params)
}

/// `acme` (the agent's workdir node, holding `API_KEY`) and a second node `other` the agent cannot reach,
/// holding `OTHER_KEY`.
fn two_nodes() -> (Fixture, String, String, String) {
    let (f, owner, acme_entry) = with_acme();
    owner_send(
        &f,
        &owner,
        "node.create",
        json!({ "id": "other", "label": "Other", "parentId": "global" }),
    )
    .expect("node.create other");
    let other_entry = owner_send(
        &f,
        &owner,
        "entry.create",
        json!({ "node": "other", "name": "OTHER_KEY", "value": "o-1" }),
    )
    .expect("entry.create other")["entry"]
        .as_str()
        .unwrap()
        .to_string();
    (f, owner, acme_entry, other_entry)
}

fn names_of(v: &Value, key: &str) -> Vec<String> {
    v[key]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["name"].as_str().unwrap().to_string())
        .collect()
}

// ---- expiry ------------------------------------------------------------------

#[test]
fn an_expiry_is_set_listed_in_its_window_and_cleared() {
    let (f, owner, entry) = with_acme();
    let g = generation(&f, &owner, "acme");
    let r = set_expiry(&f, &owner, "acme", &entry, json!(NOW + 10 * DAY)).unwrap();
    assert_eq!(r["expiresAt"], json!(NOW + 10 * DAY));
    assert_eq!(
        r["generation"].as_u64().unwrap(),
        g + 1,
        "a metadata write still moves the generation"
    );

    // entry.list carries it, as before ADR-156.
    let list = owner_send(&f, &owner, "entry.list", json!({ "node": "acme" })).unwrap();
    assert_eq!(list["entries"][0]["expiresAt"], json!(NOW + 10 * DAY));

    // Inside a 30-day window, outside a 5-day one.
    let in30 = owner_send(&f, &owner, "entry.expiring", json!({ "days": 30 })).unwrap();
    assert_eq!(names_of(&in30, "entries"), vec!["API_KEY"]);
    assert_eq!(in30["entries"][0]["expired"], json!(false));
    assert!(in30["entries"][0].get("value").is_none());
    let in5 = owner_send(&f, &owner, "entry.expiring", json!({ "days": 5 })).unwrap();
    assert!(in5["entries"].as_array().unwrap().is_empty());

    // The default window is 30 days; one node can be named.
    let default = owner_send(&f, &owner, "entry.expiring", json!({ "node": "acme" })).unwrap();
    assert_eq!(default["days"], json!(30));
    assert_eq!(names_of(&default, "entries"), vec!["API_KEY"]);

    // Cleared with null.
    let cleared = set_expiry(&f, &owner, "acme", &entry, Value::Null).unwrap();
    assert_eq!(cleared["expiresAt"], Value::Null);
    let after = owner_send(&f, &owner, "entry.expiring", json!({ "days": 3650 })).unwrap();
    assert!(after["entries"].as_array().unwrap().is_empty());
}

#[test]
fn an_already_expired_entry_is_listed_as_expired() {
    let (f, owner, entry) = with_acme();
    set_expiry(&f, &owner, "acme", &entry, json!(NOW - DAY)).unwrap();
    let r = owner_send(&f, &owner, "entry.expiring", json!({ "days": 1 })).unwrap();
    assert_eq!(r["entries"][0]["expired"], json!(true));
}

#[test]
fn set_expiry_refuses_bad_input_a_stale_generation_and_a_missing_entry() {
    let (f, owner, entry) = with_acme();
    let g = generation(&f, &owner, "acme");
    for bad in [json!("tomorrow"), json!(-5), json!(1.5)] {
        let e = owner_send(
            &f,
            &owner,
            "entry.set_expiry",
            json!({ "node": "acme", "entry": entry, "generation": g, "expiresAt": bad }),
        )
        .unwrap_err();
        assert!(matches!(e, OpError::Malformed(_)), "{bad}: {e:?}");
    }
    // Exactly one of expiresAt and clear: neither, both, or a null expiresAt alone is a mistake, never a clear.
    for bad in [
        json!({ "node": "acme", "entry": entry, "generation": g }),
        json!({ "node": "acme", "entry": entry, "generation": g, "expiresAt": null }),
        json!({ "node": "acme", "entry": entry, "generation": g, "expiresAt": NOW, "clear": true }),
    ] {
        let e = owner_send(&f, &owner, "entry.set_expiry", bad.clone()).unwrap_err();
        assert!(matches!(e, OpError::Malformed(_)), "{bad}: {e:?}");
    }
    let e = owner_send(
        &f,
        &owner,
        "entry.set_expiry",
        json!({ "node": "acme", "entry": entry, "generation": g + 7, "expiresAt": NOW }),
    )
    .unwrap_err();
    assert!(matches!(e, OpError::Conflict { .. }), "{e:?}");
    let e = owner_send(
        &f,
        &owner,
        "entry.set_expiry",
        json!({ "node": "acme", "entry": "e_nope", "generation": g, "expiresAt": NOW }),
    )
    .unwrap_err();
    assert!(matches!(e, OpError::NotFound(_)), "{e:?}");
    // Nothing above changed the generation.
    assert_eq!(generation(&f, &owner, "acme"), g);
    let e = owner_send(&f, &owner, "entry.expiring", json!({ "days": 0 })).unwrap_err();
    assert!(matches!(e, OpError::Malformed(_)));
}

#[test]
fn an_agent_cannot_list_expiry_and_cannot_set_it_on_a_node_it_does_not_reach() {
    let (f, owner, _acme_entry, other_entry) = two_nodes();
    let e = as_agent(&f, "entry.expiring", json!({ "days": 30 })).unwrap_err();
    assert!(
        matches!(e, OpError::CapabilityNotHeld { .. }),
        "expiry metadata is for human sessions (ADR-077's reading): {e:?}"
    );
    let g = generation(&f, &owner, "other");
    let e = as_agent(
        &f,
        "entry.set_expiry",
        json!({ "node": "other", "entry": other_entry, "generation": g, "expiresAt": NOW }),
    )
    .unwrap_err();
    assert!(
        matches!(
            e,
            OpError::NodeAccessDenied { .. } | OpError::CapabilityNotHeld { .. }
        ),
        "{e:?}"
    );
    assert_eq!(generation(&f, &owner, "other"), g);
}

#[test]
fn the_expiry_survives_a_restart() {
    let (f, owner, entry) = with_acme();
    set_expiry(&f, &owner, "acme", &entry, json!(NOW + DAY)).unwrap();
    let f = restart(f);
    let owner = login(&f);
    let r = owner_send(&f, &owner, "entry.expiring", json!({ "days": 2 })).unwrap();
    assert_eq!(names_of(&r, "entries"), vec!["API_KEY"]);
}

// ---- history -----------------------------------------------------------------

#[test]
fn history_lists_create_update_rotate_and_expiry_in_order_with_no_value() {
    let (f, owner, entry) = with_acme();
    let g = generation(&f, &owner, "acme");
    owner_send(
        &f,
        &owner,
        "entry.update",
        json!({ "node": "acme", "entry": entry, "generation": g, "value": "v-2-update-marker" }),
    )
    .unwrap();
    let g = generation(&f, &owner, "acme");
    owner_send(
        &f,
        &owner,
        "entry.rotate",
        json!({ "node": "acme", "entry": entry, "generation": g, "value": "v-3-rotate-marker" }),
    )
    .unwrap();
    set_expiry(&f, &owner, "acme", &entry, json!(NOW + DAY)).unwrap();

    let h = owner_send(
        &f,
        &owner,
        "entry.history",
        json!({ "node": "acme", "entry": entry }),
    )
    .unwrap();
    let actions: Vec<&str> = h["records"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["decision"] == "allow")
        .map(|r| r["action"].as_str().unwrap())
        .filter(|a| a.starts_with("entry.") && *a != "entry.list")
        .collect();
    assert_eq!(
        actions,
        vec![
            "entry.create",
            "entry.update",
            "entry.rotate",
            "entry.set_expiry"
        ]
    );
    assert_eq!(h["name"], "API_KEY");
    assert_eq!(h["exists"], json!(true));
    assert_eq!(h["rotatedAt"], json!(NOW));
    assert_eq!(h["expiresAt"], json!(NOW + DAY));
    let text = h.to_string();
    assert!(
        !text.contains("marker") && !text.contains("v-1"),
        "no value: {text}"
    );

    // Looking at the history is not part of it.
    let again = owner_send(
        &f,
        &owner,
        "entry.history",
        json!({ "node": "acme", "entry": entry, "limit": 2 }),
    )
    .unwrap();
    assert!(again["records"]
        .as_array()
        .unwrap()
        .iter()
        .all(|r| r["action"] != "entry.history"));
    assert_eq!(again["records"].as_array().unwrap().len(), 2);
    assert_eq!(again["truncated"], json!(true));
}

#[test]
fn history_of_another_nodes_entry_is_denied_to_an_agent() {
    let (f, _owner, _acme_entry, other_entry) = two_nodes();
    let e = as_agent(
        &f,
        "entry.history",
        json!({ "node": "other", "entry": other_entry }),
    )
    .unwrap_err();
    assert!(matches!(
        e,
        OpError::CapabilityNotHeld { .. } | OpError::NodeAccessDenied { .. }
    ));
    // Even on its own node, history is for human sessions.
    let e = as_agent(
        &f,
        "entry.history",
        json!({ "node": "acme", "entry": "anything" }),
    )
    .unwrap_err();
    assert!(matches!(e, OpError::CapabilityNotHeld { .. }));
}

// ---- entry.search ------------------------------------------------------------

#[test]
fn entry_search_finds_names_and_aliases_on_one_node_only() {
    let (f, owner, acme_entry, _other) = two_nodes();
    let g = generation(&f, &owner, "acme");
    owner_send(
        &f,
        &owner,
        "entry.alias",
        json!({ "node": "acme", "entry": acme_entry, "generation": g, "aliases": ["stripe-live"] }),
    )
    .unwrap();
    let by_name = owner_send(
        &f,
        &owner,
        "entry.search",
        json!({ "node": "acme", "term": "api" }),
    )
    .unwrap();
    assert_eq!(names_of(&by_name, "results"), vec!["API_KEY"]);
    let by_alias = owner_send(
        &f,
        &owner,
        "entry.search",
        json!({ "node": "acme", "term": "STRIPE" }),
    )
    .unwrap();
    assert_eq!(by_alias["results"][0]["alias"], "stripe-live");
    // OTHER_KEY lives on `other`, so a search of `acme` never finds it.
    let none = owner_send(
        &f,
        &owner,
        "entry.search",
        json!({ "node": "acme", "term": "other" }),
    )
    .unwrap();
    assert!(none["results"].as_array().unwrap().is_empty());
    // An agent may search its own node, never a foreign one.
    let mine = as_agent(&f, "entry.search", json!({ "node": "acme", "term": "key" })).unwrap();
    assert_eq!(names_of(&mine, "results"), vec!["API_KEY"]);
    let e = as_agent(
        &f,
        "entry.search",
        json!({ "node": "other", "term": "key" }),
    )
    .unwrap_err();
    assert!(matches!(
        e,
        OpError::NodeAccessDenied { .. } | OpError::CapabilityNotHeld { .. }
    ));
    let e = owner_send(
        &f,
        &owner,
        "entry.search",
        json!({ "node": "acme", "term": "" }),
    )
    .unwrap_err();
    assert!(matches!(e, OpError::Malformed(_)));
}

// ---- entry.get_by_ref --------------------------------------------------------

fn ref_of(f: &Fixture, owner: &str, node: &str, entry: &str) -> u64 {
    owner_send(
        f,
        owner,
        "entry.get",
        json!({ "node": node, "entry": entry }),
    )
    .unwrap()["ref"]
        .as_u64()
        .unwrap()
}

#[test]
fn a_ref_resolves_for_who_can_list_it_and_is_not_found_otherwise() {
    let (f, owner, acme_entry, other_entry) = two_nodes();
    let acme_ref = ref_of(&f, &owner, "acme", &acme_entry);
    let other_ref = ref_of(&f, &owner, "other", &other_entry);
    assert_ne!(acme_ref, other_ref, "refs are vault-global");

    let r = owner_send(
        &f,
        &owner,
        "entry.get_by_ref",
        json!({ "reference": other_ref }),
    )
    .unwrap();
    assert_eq!(r["node"], "other");
    assert_eq!(r["entry"], other_entry.as_str());
    assert_eq!(r["name"], "OTHER_KEY");

    let mine = as_agent(&f, "entry.get_by_ref", json!({ "reference": acme_ref })).unwrap();
    assert_eq!(mine["entry"], acme_entry.as_str());

    // I-3: a ref in a node the agent cannot reach is the same not_found as a ref that does not exist.
    let foreign = as_agent(&f, "entry.get_by_ref", json!({ "reference": other_ref })).unwrap_err();
    let missing = as_agent(&f, "entry.get_by_ref", json!({ "reference": 999_999 })).unwrap_err();
    assert!(matches!(foreign, OpError::NotFound(_)), "{foreign:?}");
    assert!(matches!(missing, OpError::NotFound(_)), "{missing:?}");
    assert_eq!(
        wire(foreign)["code"].clone(),
        wire(missing)["code"].clone(),
        "the refusal must not say whether the ref exists"
    );
    let e = owner_send(
        &f,
        &owner,
        "entry.get_by_ref",
        json!({ "reference": "abc" }),
    )
    .unwrap_err();
    assert!(matches!(e, OpError::Malformed(_)));
}
