//! ADR-167 — entry tags: `entry.tag_set`, `tags` on `entry.list` / `entry.get`, and the `tag` filter of
//! `entry.list` and `entry.search`.
//!
//! * A set is normalised (trimmed, lower-cased, inner spaces to one `-`, de-duplicated), replaces the old
//!   one, clears with `[]`, survives a restart, and travels with nothing else (the envelope is untouched).
//! * Limits: at most 16 tags of at most 32 characters from a fixed character set; a stale generation is a
//!   conflict; a missing entry is `not_found`.
//! * Agents never set tags (as aliases, ADR-121) but may filter by one on a node they can list.
//! * A filter narrows one node only: it never returns another node's entries, and an agent asking about a
//!   node it cannot list is refused with nothing named.
//! * A node that hides its names hides its tags, and refuses a filtered list.

mod f1_support;

use serde_json::{json, Value};

use credmgr_brokerd::protocol::OpError;
use credmgr_brokerd::scope::BrokerScope;
use credmgr_brokerd::state::BrokerState;
use credmgr_core::access::Origin;
use credmgr_core::registry::Capability;

use f1_support::*;

fn tag_set(
    state: &BrokerState,
    scope: &BrokerScope,
    node: &str,
    entry: &str,
    tags: Value,
) -> Result<Value, OpError> {
    let g = state
        .manifests
        .read()
        .unwrap()
        .get(node)
        .map_or(0, |m| m.generation);
    call(
        state,
        scope,
        NOW,
        "entry.tag_set",
        json!({ "node": node, "entry": entry, "generation": g, "tags": tags }),
    )
}

fn list_names(state: &BrokerState, scope: &BrokerScope, node: &str, tag: &str) -> Vec<String> {
    let r = call(
        state,
        scope,
        NOW,
        "entry.list",
        json!({ "node": node, "tag": tag }),
    )
    .expect("entry.list with a tag");
    let mut names: Vec<String> = r["names"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n.as_str().unwrap().to_string())
        .collect();
    names.sort();
    names
}

fn agent(node: &str, caps: Vec<Capability>) -> BrokerScope {
    BrokerScope {
        node_id: node.to_string(),
        capabilities: caps,
        origin: Origin::Agent,
        token_id: None,
        bound_workdir: None,
    }
}

#[test]
fn tags_are_normalised_replaced_cleared_listed_and_survive_a_restart() {
    let (v, state) = created_vault(None);
    let owner = login(&state);
    create_node(&state, &owner, "acme");
    let db = create_entry(&state, &owner, "acme", "database", "tags-db-Qz81");
    let api = create_entry(&state, &owner, "acme", "api", "tags-api-Lm27");

    let r = tag_set(
        &state,
        &owner,
        "acme",
        &db,
        json!([" Prod ", "staging   DB", "prod"]),
    )
    .unwrap();
    assert_eq!(r["tags"], json!(["prod", "staging-db"]), "{r}");
    assert_eq!(r["generation"], generation(&state, &owner, "acme"));
    tag_set(&state, &owner, "acme", &api, json!(["PROD"])).unwrap();

    let get = call(
        &state,
        &owner,
        NOW,
        "entry.get",
        json!({ "node": "acme", "entry": db }),
    )
    .unwrap();
    assert_eq!(get["tags"], json!(["prod", "staging-db"]));
    let list = call(&state, &owner, NOW, "entry.list", json!({ "node": "acme" })).unwrap();
    let row = list["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["id"] == db)
        .unwrap();
    assert_eq!(row["tags"], json!(["prod", "staging-db"]));

    assert_eq!(
        list_names(&state, &owner, "acme", "prod"),
        vec!["api", "database"]
    );
    assert_eq!(
        list_names(&state, &owner, "acme", "Staging DB"),
        vec!["database"]
    );
    assert!(list_names(&state, &owner, "acme", "nothing-here").is_empty());

    let found = call(
        &state,
        &owner,
        NOW,
        "entry.search",
        json!({ "node": "acme", "term": "a", "tag": "staging-db" }),
    )
    .unwrap();
    assert_eq!(found["results"].as_array().unwrap().len(), 1, "{found}");
    assert_eq!(found["results"][0]["id"], json!(db));

    // A restart reads them back from the signed manifest.
    let (state, owner) = restart(&v, state, None);
    assert_eq!(
        list_names(&state, &owner, "acme", "prod"),
        vec!["api", "database"]
    );
    // The value was never touched.
    assert_eq!(reveal(&state, &owner, "acme", &db), "tags-db-Qz81");

    // Replace and clear.
    let r = tag_set(&state, &owner, "acme", &db, json!(["db"])).unwrap();
    assert_eq!(r["tags"], json!(["db"]));
    let r = tag_set(&state, &owner, "acme", &db, json!([])).unwrap();
    assert_eq!(r["tags"], json!([]));
    let get = call(
        &state,
        &owner,
        NOW,
        "entry.get",
        json!({ "node": "acme", "entry": db }),
    )
    .unwrap();
    assert!(get.get("tags").is_none(), "no tags: no key {get}");
    assert_eq!(list_names(&state, &owner, "acme", "prod"), vec!["api"]);
    verify_ok(&state, &owner);
}

#[test]
fn limits_bad_tags_stale_generations_and_missing_entries_are_refused() {
    let (_v, state) = created_vault(None);
    let owner = login(&state);
    create_node(&state, &owner, "acme");
    let db = create_entry(&state, &owner, "acme", "database", "tags-db-Pw35");

    let seventeen: Vec<String> = (0..17).map(|i| format!("t{i}")).collect();
    let malformed = |r: Result<Value, OpError>| matches!(r, Err(OpError::Malformed(_)));
    assert!(malformed(tag_set(
        &state,
        &owner,
        "acme",
        &db,
        json!(seventeen)
    )));
    assert!(malformed(tag_set(
        &state,
        &owner,
        "acme",
        &db,
        json!(["a".repeat(33)])
    )));
    assert!(malformed(tag_set(
        &state,
        &owner,
        "acme",
        &db,
        json!(["no,commas"])
    )));
    assert!(malformed(tag_set(&state, &owner, "acme", &db, json!([""]))));
    assert!(malformed(tag_set(&state, &owner, "acme", &db, json!([7]))));
    assert!(malformed(call(
        &state,
        &owner,
        NOW,
        "entry.tag_set",
        json!({ "node": "acme", "entry": db, "generation": 1 }),
    )));
    assert!(malformed(call(
        &state,
        &owner,
        NOW,
        "entry.list",
        json!({ "node": "acme", "tag": "bad tag!" }),
    )));
    // Sixteen distinct tags of 32 characters are fine.
    let sixteen: Vec<String> = (0..16).map(|i| format!("{i:0>32}")).collect();
    tag_set(&state, &owner, "acme", &db, json!(sixteen)).unwrap();

    let g = generation(&state, &owner, "acme");
    let stale = call(
        &state,
        &owner,
        NOW,
        "entry.tag_set",
        json!({ "node": "acme", "entry": db, "generation": g - 1, "tags": ["x"] }),
    );
    assert!(matches!(stale, Err(OpError::Conflict { .. })), "{stale:?}");
    let missing = tag_set(&state, &owner, "acme", "e_000000000000", json!(["x"]));
    assert!(matches!(missing, Err(OpError::NotFound(_))), "{missing:?}");
}

#[test]
fn agents_never_set_tags_but_may_filter_a_node_they_can_list() {
    let (_v, state) = created_vault(None);
    let owner = login(&state);
    create_node(&state, &owner, "acme");
    let db = create_entry(&state, &owner, "acme", "database", "tags-db-Xc90");
    tag_set(&state, &owner, "acme", &db, json!(["prod"])).unwrap();

    let bot = agent(
        "acme",
        vec![Capability::List, Capability::Read, Capability::Update],
    );
    let refused = tag_set(&state, &bot, "acme", &db, json!(["agent-tag"]));
    assert!(
        matches!(refused, Err(OpError::CapabilityNotHeld { .. })),
        "{refused:?}"
    );
    let get = call(
        &state,
        &owner,
        NOW,
        "entry.get",
        json!({ "node": "acme", "entry": db }),
    )
    .unwrap();
    assert_eq!(get["tags"], json!(["prod"]), "unchanged");

    assert_eq!(list_names(&state, &bot, "acme", "prod"), vec!["database"]);
}

#[test]
fn a_tag_filter_never_returns_another_nodes_entries() {
    let (_v, state) = created_vault(None);
    let owner = login(&state);
    create_node(&state, &owner, "acme");
    create_node(&state, &owner, "beta");
    let a = create_entry(&state, &owner, "acme", "acme-db", "tags-a-Ny62");
    let b = create_entry(&state, &owner, "beta", "beta-db", "tags-b-Ty18");
    tag_set(&state, &owner, "acme", &a, json!(["prod"])).unwrap();
    tag_set(&state, &owner, "beta", &b, json!(["prod"])).unwrap();

    // Even the owner gets one node per request: the tag is not an index across nodes.
    assert_eq!(list_names(&state, &owner, "acme", "prod"), vec!["acme-db"]);
    assert_eq!(list_names(&state, &owner, "beta", "prod"), vec!["beta-db"]);

    // An agent of acme asking beta is refused, and the refusal names nothing of beta's.
    let bot = agent("acme", vec![Capability::List]);
    assert_eq!(list_names(&state, &bot, "acme", "prod"), vec!["acme-db"]);
    let cross = call(
        &state,
        &bot,
        NOW,
        "entry.list",
        json!({ "node": "beta", "tag": "prod" }),
    );
    let err = cross.expect_err("acme's agent cannot list beta");
    assert!(!format!("{err:?}").contains("beta-db"), "{err:?}");
    let search = call(
        &state,
        &bot,
        NOW,
        "entry.search",
        json!({ "node": "beta", "term": "db", "tag": "prod" }),
    );
    let err = search.expect_err("nor search it");
    assert!(!format!("{err:?}").contains("beta-db"), "{err:?}");
}

#[test]
fn a_node_that_hides_its_names_hides_its_tags_and_refuses_a_filtered_list() {
    let (_v, state) = created_vault(None);
    let owner = login(&state);
    create_node(&state, &owner, "acme");
    let db = create_entry(&state, &owner, "acme", "database", "tags-db-Hk44");
    tag_set(&state, &owner, "acme", &db, json!(["prod"])).unwrap();
    call(
        &state,
        &owner,
        NOW,
        "node.policy",
        json!({ "node": "acme", "reason": "hide names", "policy": { "privateNames": true } }),
    )
    .expect("node.policy");

    let bot = agent("acme", vec![Capability::List, Capability::Read]);
    let get = call(
        &state,
        &bot,
        NOW,
        "entry.get",
        json!({ "node": "acme", "entry": db }),
    )
    .unwrap();
    assert!(get.get("tags").is_none(), "{get}");
    assert_eq!(get["nameHidden"], true);
    let filtered = call(
        &state,
        &bot,
        NOW,
        "entry.list",
        json!({ "node": "acme", "tag": "prod" }),
    );
    assert!(filtered.is_err(), "{filtered:?}");
    // The owner still sees them.
    assert_eq!(list_names(&state, &owner, "acme", "prod"), vec!["database"]);
}
