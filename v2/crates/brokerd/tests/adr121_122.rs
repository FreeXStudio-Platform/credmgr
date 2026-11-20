//! ADR-121 (aliases, near-duplicate names) and ADR-122 (`.env` import), end to end on a
//! throwaway `vault.init_*` vault driven through the real server wiring.

mod common;

use common::*;
use credmgr_brokerd::protocol::OpError;
use serde_json::{json, Value};

const MARK: &str = "zz-secret-marker-7731";

fn alias(
    f: &Fixture,
    owner: &str,
    entry: &str,
    generation: u64,
    aliases: Value,
) -> Result<Value, OpError> {
    send(
        f,
        None,
        Some(owner),
        "entry.alias",
        json!({ "node": "acme", "entry": entry, "generation": generation, "aliases": aliases }),
    )
}

fn generation(f: &Fixture, owner: &str) -> u64 {
    send(
        f,
        None,
        Some(owner),
        "entry.list",
        json!({ "node": "acme" }),
    )
    .unwrap()["generation"]
        .as_u64()
        .unwrap()
}

fn names(f: &Fixture, owner: &str) -> Vec<String> {
    send(
        f,
        None,
        Some(owner),
        "entry.list",
        json!({ "node": "acme" }),
    )
    .unwrap()["names"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n.as_str().unwrap().to_string())
        .collect()
}

// ---------------------------------------------------------------------------
// aliases
// ---------------------------------------------------------------------------

#[test]
fn an_alias_is_listed_read_back_found_by_search_and_the_generation_moves() {
    let (f, owner, entry) = with_acme();
    let g = generation(&f, &owner);
    let r = alias(&f, &owner, &entry, g, json!(["stripe", "Payments Key"])).unwrap();
    assert_eq!(r["aliases"], json!(["stripe", "Payments Key"]));
    assert_eq!(r["generation"].as_u64().unwrap(), g + 1);

    let list = send(
        &f,
        None,
        Some(&owner),
        "entry.list",
        json!({ "node": "acme" }),
    )
    .unwrap();
    assert_eq!(
        list["entries"][0]["aliases"],
        json!(["stripe", "Payments Key"])
    );
    // `names` is still the names: an alias is not a second entry.
    assert_eq!(list["names"], json!(["API_KEY"]));

    let get = send(
        &f,
        None,
        Some(&owner),
        "entry.get",
        json!({ "node": "acme", "entry": entry }),
    )
    .unwrap();
    assert_eq!(get["aliases"], json!(["stripe", "Payments Key"]));

    let found = send(
        &f,
        None,
        Some(&owner),
        "search",
        json!({ "term": "payments" }),
    )
    .unwrap();
    assert_eq!(found["results"][0]["name"], "API_KEY");
    assert_eq!(found["results"][0]["alias"], "Payments Key");
    assert_eq!(found["results"][0]["id"], json!(entry));
    // a name match carries no `alias` key
    let by_name = send(&f, None, Some(&owner), "search", json!({ "term": "api_" })).unwrap();
    assert!(by_name["results"][0].get("alias").is_none());

    // clearing
    let g = generation(&f, &owner);
    let cleared = alias(&f, &owner, &entry, g, json!([])).unwrap();
    assert_eq!(cleared["aliases"], json!([]));
    let list = send(
        &f,
        None,
        Some(&owner),
        "entry.list",
        json!({ "node": "acme" }),
    )
    .unwrap();
    assert!(list["entries"][0].get("aliases").is_none());
}

#[test]
fn aliases_survive_a_restart() {
    let (f, owner, entry) = with_acme();
    let g = generation(&f, &owner);
    alias(&f, &owner, &entry, g, json!(["kept"])).unwrap();
    let f = restart(f);
    let owner = login(&f);
    let list = send(
        &f,
        None,
        Some(&owner),
        "entry.list",
        json!({ "node": "acme" }),
    )
    .unwrap();
    assert_eq!(list["entries"][0]["aliases"], json!(["kept"]));
}

#[test]
fn one_name_space_an_alias_cannot_take_a_name_or_an_alias_and_a_name_cannot_take_an_alias() {
    let (f, owner, entry) = with_acme();
    let other = create_as_owner(&f, &owner, "payroll");
    let g = generation(&f, &owner);
    // another entry's name, in every disguise the exact-name rule knows
    for taken in ["payroll", "PAYROLL", "p\u{0430}yroll", "pay\u{200B}roll"] {
        let r = alias(&f, &owner, &entry, g, json!([taken]));
        assert!(
            matches!(r, Err(OpError::EntryExists { .. })),
            "{taken:?}: {r:?}"
        );
    }
    // its own name
    let r = alias(&f, &owner, &entry, g, json!(["api_key"]));
    assert!(matches!(r, Err(OpError::Malformed(_))), "{r:?}");
    // twice in one list
    let r = alias(&f, &owner, &entry, g, json!(["x-one", "X-ONE"]));
    assert!(matches!(r, Err(OpError::Malformed(_))), "{r:?}");

    // a free alias is taken; the other entry cannot take it too, nor can a new entry be created or imported under it
    alias(&f, &owner, &entry, g, json!(["shared-name"])).unwrap();
    let g = generation(&f, &owner);
    let r = alias(&f, &owner, &other, g, json!(["Shared-Name"]));
    assert!(matches!(r, Err(OpError::EntryExists { .. })), "{r:?}");
    let r = send(
        &f,
        None,
        Some(&owner),
        "entry.create",
        json!({ "node": "acme", "name": "SHARED-NAME", "value": "x" }),
    );
    assert!(matches!(r, Err(OpError::EntryExists { .. })), "{r:?}");
    let r = send(
        &f,
        None,
        Some(&owner),
        "entry.create_batch",
        json!({ "node": "acme", "entries": [{ "name": "fine", "value": "1" }, { "name": "shared-name", "value": "2" }] }),
    );
    assert!(matches!(r, Err(OpError::EntryExists { .. })), "{r:?}");
    let r = send(
        &f,
        None,
        Some(&owner),
        "entry.import_env",
        json!({ "node": "acme", "entries": [{ "name": "shared-name", "value": "2" }] }),
    );
    assert!(matches!(r, Err(OpError::EntryExists { .. })), "{r:?}");
    assert!(!names(&f, &owner).contains(&"fine".to_string()));
}

#[test]
fn the_shape_of_an_alias_list_is_checked_and_a_stale_generation_conflicts() {
    let (f, owner, entry) = with_acme();
    let g = generation(&f, &owner);
    let nine: Vec<String> = (0..9).map(|i| format!("alias-number-{i}")).collect();
    for bad in [
        json!(nine),
        json!([""]),
        json!(["  "]),
        json!([5]),
        json!(["has\nnewline"]),
        json!("not-a-list"),
        json!(["x".repeat(201)]),
    ] {
        let r = alias(&f, &owner, &entry, g, bad.clone());
        assert!(matches!(r, Err(OpError::Malformed(_))), "{bad}: {r:?}");
    }
    let eight: Vec<String> = (0..8).map(|i| format!("alias-number-{i}")).collect();
    alias(&f, &owner, &entry, g, json!(eight)).unwrap();
    let r = alias(&f, &owner, &entry, g, json!(["late"]));
    assert!(matches!(r, Err(OpError::Conflict { .. })), "{r:?}");
    let r = send(
        &f,
        None,
        Some(&owner),
        "entry.alias",
        json!({ "node": "acme", "entry": "e_nope", "generation": generation(&f, &owner), "aliases": [] }),
    );
    assert!(matches!(r, Err(OpError::NotFound(_))), "{r:?}");
}

#[test]
fn an_agent_cannot_set_aliases_and_a_locked_node_refuses_the_owner() {
    let (f, owner, entry) = with_acme();
    let g = generation(&f, &owner);
    let r = as_agent(
        &f,
        "entry.alias",
        json!({ "node": "acme", "entry": entry, "generation": g, "aliases": ["spoof"] }),
    );
    assert!(matches!(r, Err(OpError::CapabilityNotHeld { .. })), "{r:?}");
    send(
        &f,
        None,
        Some(&owner),
        "vault.node_lock",
        json!({ "node": "acme" }),
    )
    .unwrap();
    let r = alias(&f, &owner, &entry, g, json!(["x-alias"]));
    assert!(matches!(r, Err(OpError::NodeLocked { .. })), "{r:?}");
}

#[test]
fn an_alias_that_looks_like_another_name_is_accepted_and_the_answer_says_so() {
    let (f, owner, entry) = with_acme();
    let other = create_as_owner(&f, &owner, "stripe-key");
    let g = generation(&f, &owner);
    let r = alias(&f, &owner, &entry, g, json!(["Stripe_Key", "unrelated"])).unwrap();
    let similar = r["similar"].as_array().expect("a similar list");
    assert_eq!(similar.len(), 1, "{r}");
    assert_eq!(similar[0]["id"], json!(other));
    assert_eq!(similar[0]["name"], "stripe-key");
    assert_eq!(similar[0]["reason"], "separators");
}

// ---------------------------------------------------------------------------
// entry.similar
// ---------------------------------------------------------------------------

#[test]
fn similar_names_are_listed_with_why_and_a_numbered_series_is_not() {
    let (f, owner, entry) = with_acme();
    let key = create_as_owner(&f, &owner, "stripe-key");
    create_as_owner(&f, &owner, "wallet1");
    let g = generation(&f, &owner);
    alias(&f, &owner, &entry, g, json!(["github-token"])).unwrap();

    let ask = |name: &str, skip: Option<&str>| {
        let mut p = json!({ "node": "acme", "name": name });
        if let Some(s) = skip {
            p["entry"] = json!(s);
        }
        send(&f, None, Some(&owner), "entry.similar", p).unwrap()
    };
    let r = ask("stirpe-key", None);
    assert_eq!(r["taken"], false);
    assert_eq!(r["similar"][0]["id"], json!(key));
    assert_eq!(r["similar"][0]["reason"], "one-edit");
    // an alias counts, and the answer names the alias and its entry
    let r = ask("github_token", None);
    assert_eq!(r["similar"][0]["id"], json!(entry));
    assert_eq!(r["similar"][0]["alias"], "github-token");
    assert_eq!(r["similar"][0]["reason"], "separators");
    // a numbered sibling is not a near-duplicate
    assert_eq!(ask("wallet2", None)["similar"], json!([]));
    // an exact (canonical) hit is `taken`, not "similar to itself"
    let r = ask("STRIPE-KEY", None);
    assert_eq!(r["taken"], true);
    assert_eq!(r["similar"], json!([]));
    // `entry` leaves one entry out (renaming or aliasing it)
    let r = ask("stripe-key", Some(&key));
    assert_eq!(r["taken"], false);
    // an agent that may list may ask
    let r = as_agent(
        &f,
        "entry.similar",
        json!({ "node": "acme", "name": "stirpe-key" }),
    )
    .unwrap();
    assert_eq!(r["similar"][0]["name"], "stripe-key");
}

#[test]
fn a_node_that_hides_its_names_answers_nothing_to_a_reader_who_may_not_see_them() {
    let (f, owner, _) = with_acme();
    create_as_owner(&f, &owner, "stripe-key");
    send(
        &f,
        None,
        Some(&owner),
        "node.policy",
        json!({ "node": "acme", "reason": "names are private", "policy": { "privateNames": true } }),
    )
    .unwrap();
    let r = as_agent(
        &f,
        "entry.similar",
        json!({ "node": "acme", "name": "stirpe-key" }),
    )
    .unwrap();
    assert_eq!(r["nameHidden"], true);
    assert_eq!(r["similar"], json!([]));
    // the owner's own login still sees them
    let r = send(
        &f,
        None,
        Some(&owner),
        "entry.similar",
        json!({ "node": "acme", "name": "stirpe-key" }),
    )
    .unwrap();
    assert_eq!(r["similar"][0]["name"], "stripe-key");
}

// ---------------------------------------------------------------------------
// entry.import_env
// ---------------------------------------------------------------------------

fn import(f: &Fixture, owner: &str, extra: Value, pairs: Value) -> Result<Value, OpError> {
    let mut p = json!({ "node": "acme", "entries": pairs });
    for (k, v) in extra.as_object().unwrap() {
        p[k] = v.clone();
    }
    send(f, None, Some(owner), "entry.import_env", p)
}

fn pairs() -> Value {
    json!([
        { "name": "DB_HOST", "value": format!("{MARK}-1") },
        { "name": "API_KEY", "value": format!("{MARK}-2") },
        { "name": "db_host", "value": format!("{MARK}-3") },
        { "name": "EMPTY_ONE", "value": "" },
        { "name": "STRIPE_KEY", "value": format!("{MARK}-4") },
    ])
}

#[test]
fn a_dry_run_lists_names_and_conflicts_writes_nothing_and_carries_no_value() {
    let (f, owner, _) = with_acme();
    create_as_owner(&f, &owner, "stripe-key");
    let before = names(&f, &owner);
    let g = generation(&f, &owner);
    let r = import(&f, &owner, json!({ "dryRun": true }), pairs()).unwrap();
    assert_eq!(r["dryRun"], true);
    assert_eq!(r["total"], 5);
    let statuses: Vec<&str> = r["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["status"].as_str().unwrap())
        .collect();
    assert_eq!(statuses, ["new", "exists", "duplicate", "empty", "new"]);
    assert_eq!(
        r["counts"],
        json!({ "new": 2, "exists": 1, "duplicate": 1, "empty": 1, "invalid": 0 })
    );
    // STRIPE_KEY resembles the stripe-key already there
    assert_eq!(r["items"][4]["similar"][0]["name"], "stripe-key");
    assert!(
        !r.to_string().contains(MARK),
        "a value reached the answer: {r}"
    );
    assert_eq!(names(&f, &owner), before, "a dry run writes nothing");
    assert_eq!(generation(&f, &owner), g);
}

#[test]
fn a_conflict_refuses_the_whole_import_unless_it_is_told_to_skip() {
    let (f, owner, _) = with_acme();
    let before = names(&f, &owner);
    let r = import(&f, &owner, json!({}), pairs());
    assert!(matches!(r, Err(OpError::EntryExists { .. })), "{r:?}");
    assert_eq!(names(&f, &owner), before, "nothing was written");
    let r = import(&f, &owner, json!({ "onConflict": "refuse" }), pairs());
    assert!(matches!(r, Err(OpError::EntryExists { .. })), "{r:?}");

    // skip: the new ones are written, the rest are reported by name and reason
    let ok = import(&f, &owner, json!({ "onConflict": "skip" }), pairs());
    // API_KEY exists; db_host repeats DB_HOST; the empty one is not an entry
    let ok = ok.unwrap();
    assert_eq!(ok["complete"], true);
    let created: Vec<&str> = ok["created"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    assert_eq!(created, ["DB_HOST", "STRIPE_KEY"]);
    let skipped: Vec<(&str, &str)> = ok["skipped"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| (c["name"].as_str().unwrap(), c["status"].as_str().unwrap()))
        .collect();
    assert_eq!(
        skipped,
        [
            ("API_KEY", "exists"),
            ("db_host", "duplicate"),
            ("EMPTY_ONE", "empty")
        ]
    );
    assert!(!ok.to_string().contains(MARK), "a value reached the answer");
    let after = names(&f, &owner);
    assert!(after.contains(&"DB_HOST".to_string()) && after.contains(&"STRIPE_KEY".to_string()));
    assert!(!after.contains(&"EMPTY_ONE".to_string()));
}

#[test]
fn a_clean_import_writes_each_entry_and_each_gets_its_own_audit_record() {
    let (f, owner, _) = with_acme();
    let r = import(
        &f,
        &owner,
        json!({}),
        json!([
            { "name": "TEST_ALPHA_TOKEN", "value": format!("{MARK}-a") },
            { "name": "TEST_BETA_TOKEN", "value": format!("{MARK}-b") },
            { "name": "TEST_GAMMA_TOKEN", "value": format!("{MARK}-c") },
        ]),
    )
    .unwrap();
    assert_eq!(r["complete"], true);
    assert_eq!(r["created"].as_array().unwrap().len(), 3);
    assert_eq!(r["skipped"], json!([]));
    assert!(!r.to_string().contains(MARK));

    // the entries exist with their values, read back through the normal path
    let id = r["created"][1]["entry"].as_str().unwrap();
    let got = send(
        &f,
        None,
        Some(&owner),
        "entry.reveal",
        json!({ "node": "acme", "entry": id }),
    )
    .unwrap();
    assert_eq!(got["fields"][0]["value"], format!("{MARK}-b"));

    // one `entry.create` record per entry (and the request's own `entry.import_env`)
    let tail = send(&f, None, Some(&owner), "audit.tail", json!({ "limit": 50 })).unwrap();
    let records = tail["records"].as_array().unwrap();
    let per_entry: Vec<&Value> = records
        .iter()
        .filter(|r| r["action"] == "entry.create" && r["detail"] == "import-env")
        .collect();
    assert_eq!(per_entry.len(), 3, "{records:?}");
    let ids: Vec<&str> = per_entry
        .iter()
        .map(|r| r["entry"].as_str().unwrap())
        .collect();
    for c in r["created"].as_array().unwrap() {
        assert!(ids.contains(&c["entry"].as_str().unwrap()), "{ids:?}");
    }
    assert!(records.iter().any(|r| r["action"] == "entry.import_env"));
    assert!(
        !tail.to_string().contains(MARK),
        "a value reached the audit trail"
    );
}

#[test]
fn the_shape_of_an_import_is_checked_before_anything_is_written() {
    let (f, owner, _) = with_acme();
    let before = names(&f, &owner);
    for (what, extra, pairs) in [
        ("no pairs", json!({}), json!([])),
        (
            "a bad name",
            json!({}),
            json!([{ "name": "OK_ONE", "value": "1" }, { "name": "bad\nname", "value": "2" }]),
        ),
        (
            "an empty name",
            json!({ "onConflict": "skip" }),
            json!([{ "name": "", "value": "2" }]),
        ),
        (
            "an extra key",
            json!({}),
            json!([{ "name": "A_B_C", "value": "1", "fields": [] }]),
        ),
        ("no value", json!({}), json!([{ "name": "A_B_C" }])),
        (
            "a non-string value",
            json!({}),
            json!([{ "name": "A_B_C", "value": 5 }]),
        ),
        (
            "an unknown onConflict",
            json!({ "onConflict": "overwrite" }),
            json!([{ "name": "A_B_C", "value": "1" }]),
        ),
        (
            "a non-boolean dryRun",
            json!({ "dryRun": "yes" }),
            json!([{ "name": "A_B_C", "value": "1" }]),
        ),
    ] {
        let r = import(&f, &owner, extra, pairs);
        assert!(matches!(r, Err(OpError::Malformed(_))), "{what}: {r:?}");
    }
    assert_eq!(names(&f, &owner), before);
    // and the dry run reports an invalid name instead of refusing
    let r = import(
        &f,
        &owner,
        json!({ "dryRun": true }),
        json!([{ "name": "bad\nname", "value": "2" }]),
    )
    .unwrap();
    assert_eq!(r["items"][0]["status"], "invalid");
    let too_many: Vec<Value> = (0..501)
        .map(|i| json!({ "name": format!("name-number-{i}"), "value": "v" }))
        .collect();
    let r = import(&f, &owner, json!({}), json!(too_many));
    assert!(matches!(r, Err(OpError::Malformed(_))), "{r:?}");
}

#[test]
fn an_agent_with_create_may_import_and_a_node_without_it_is_refused() {
    let (f, owner, _) = with_acme();
    let r = as_agent(
        &f,
        "entry.import_env",
        json!({ "node": "acme", "entries": [{ "name": "TEST_AGENT_TOKEN", "value": "v" }] }),
    )
    .unwrap();
    assert_eq!(r["complete"], true);
    assert!(names(&f, &owner).contains(&"TEST_AGENT_TOKEN".to_string()));
    // a node the agent is not in
    send(
        &f,
        None,
        Some(&owner),
        "node.create",
        json!({ "id": "other", "label": "Other", "parentId": "global" }),
    )
    .unwrap();
    let r = as_agent(
        &f,
        "entry.import_env",
        json!({ "node": "other", "entries": [{ "name": "TEST_NOPE_TOKEN", "value": "v" }] }),
    );
    assert!(matches!(r, Err(OpError::NodeAccessDenied { .. })), "{r:?}");
}
