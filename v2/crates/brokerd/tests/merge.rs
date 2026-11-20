//! ADR-168 — `merge.*`: suggestions and merges inside one node.
//!
//! * Suggestions name three kinds (identical, shared value, similar names) inside one node and carry no
//!   value, digest or fragment; neither does the audit trail.
//! * `merge.apply` keeps one entry, gives it the dropped names and aliases as aliases and the union of the
//!   tags, removes the others through the `entry.remove` path; `entry.undo` brings a dropped entry back under
//!   its own name and takes the merge's aliases off the kept one. It survives a restart.
//! * The decision memory: a dismissed key never returns until undismissed or restored; it is sealed to the
//!   node's key and bound by digest in the signed manifest (an older file put back is refused).
//! * `merge.auto` merges only identical groups; `merge.auto_all` is a dry run unless told, and changes
//!   nothing then.
//! * Only the owner's login with `Admin`; a fresh second factor for a merge (a stale generation costs no
//!   code); a dropped entry with a grant of its own is refused.

mod f1_support;

use serde_json::{json, Value};

use credmgr_brokerd::protocol::OpError;
use credmgr_brokerd::scope::BrokerScope;
use credmgr_brokerd::state::BrokerState;
use credmgr_core::access::Origin;
use credmgr_core::registry::{Capability, Direction, Grant, GrantTarget};

use f1_support::*;

const V_SAME: &str = "merge-same-value-Qx81LmZt";
const V_PASSWORD: &str = "merge-shared-password-Vk27Np";
const V_TOKEN_A: &str = "merge-token-a-Rr55Kq0w";
const V_TOKEN_B: &str = "merge-token-b-Hh62Jd4s";
const V_OTHER: &str = "merge-other-value-Wn19Xc";

fn planted_values() -> [&'static str; 5] {
    [V_SAME, V_PASSWORD, V_TOKEN_A, V_TOKEN_B, V_OTHER]
}

/// No planted value, and nothing shaped like a digest (a run of 32+ hex characters).
fn assert_no_value(text: &str, what: &str) {
    for v in planted_values() {
        assert!(!text.contains(v), "{what} carries a planted value");
    }
    let mut run = 0;
    for c in text.chars() {
        run = if c.is_ascii_hexdigit() { run + 1 } else { 0 };
        assert!(run < 32, "{what} carries something shaped like a digest");
    }
}

fn entry(
    state: &BrokerState,
    owner: &BrokerScope,
    node: &str,
    name: &str,
    fields: Value,
) -> String {
    call(
        state,
        owner,
        NOW,
        "entry.create",
        json!({ "node": node, "name": name, "fields": fields }),
    )
    .expect("entry.create")["entry"]
        .as_str()
        .unwrap()
        .to_string()
}

fn one(value: &str) -> Value {
    json!([{ "label": "value", "value": value }])
}

struct Planted {
    same_a: String,
    same_b: String,
    login_a: String,
    login_b: String,
    token_a: String,
    token_b: String,
}

/// `acme`: an identical pair (also alike by name), a pair sharing one value, a pair alike by name only,
/// and one entry nothing resembles.
fn planted(state: &BrokerState, owner: &BrokerScope) -> Planted {
    create_node(state, owner, "acme");
    let same_a = entry(state, owner, "acme", "STRIPE_KEY", one(V_SAME));
    let same_b = entry(state, owner, "acme", "stripe-key", one(V_SAME));
    let login_a = entry(
        state,
        owner,
        "acme",
        "DB_LOGIN",
        json!([{ "label": "user", "value": "svc-reader" }, { "label": "password", "value": V_PASSWORD }]),
    );
    let login_b = entry(
        state,
        owner,
        "acme",
        "WAREHOUSE",
        json!([{ "label": "user", "value": "svc-writer" }, { "label": "password", "value": V_PASSWORD }]),
    );
    let token_a = entry(state, owner, "acme", "deploy-token", one(V_TOKEN_A));
    let token_b = entry(state, owner, "acme", "deploy-tokn", one(V_TOKEN_B));
    entry(state, owner, "acme", "UNRELATED", one(V_OTHER));
    Planted {
        same_a,
        same_b,
        login_a,
        login_b,
        token_a,
        token_b,
    }
}

fn suggestions(state: &BrokerState, owner: &BrokerScope, node: &str) -> Value {
    call(
        state,
        owner,
        NOW,
        "merge.suggestions",
        json!({ "node": node }),
    )
    .expect("suggestions")
}

fn key(a: &str, b: &str) -> String {
    let mut ids = [a, b];
    ids.sort_unstable();
    ids.join("+")
}

fn find<'a>(r: &'a Value, key: &str) -> Option<&'a Value> {
    r["suggestions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["key"] == key)
}

fn names(state: &BrokerState, owner: &BrokerScope, node: &str) -> Vec<String> {
    let mut n: Vec<String> = call(state, owner, NOW, "entry.list", json!({ "node": node }))
        .unwrap()["names"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    n.sort();
    n
}

fn get(state: &BrokerState, owner: &BrokerScope, node: &str, entry: &str) -> Value {
    call(
        state,
        owner,
        NOW,
        "entry.get",
        json!({ "node": node, "entry": entry }),
    )
    .unwrap()
}

/// The raw audit files carry hash-chain digests of their own; only the planted values are looked for there.
fn assert_audit_has_no_value(v: &Vault) {
    let text = audit_text(v);
    for value in planted_values() {
        assert!(
            !text.contains(value),
            "the audit trail carries a planted value"
        );
    }
}

fn audit_text(v: &Vault) -> String {
    let dir = v.paths().audit_dir();
    let mut all = String::new();
    let Ok(files) = std::fs::read_dir(dir) else {
        return all; // nothing audited yet
    };
    for e in files {
        all.push_str(&String::from_utf8_lossy(
            &std::fs::read(e.unwrap().path()).unwrap(),
        ));
    }
    all
}

#[test]
fn suggestions_name_three_kinds_inside_one_node_and_carry_no_value() {
    let (v, state) = created_vault(None);
    let owner = login(&state);
    let p = planted(&state, &owner);
    let r = suggestions(&state, &owner, "acme");
    assert_eq!(r["valuesCompared"], true);
    assert_eq!(r["truncated"], false);

    let same = find(&r, &key(&p.same_a, &p.same_b)).expect("the identical pair");
    assert_eq!(same["kind"], "identical", "{r}");
    assert_eq!(same["identical"], true);
    assert_eq!(
        same["keep"],
        json!(p.same_a),
        "the oldest entry is the one proposed to keep"
    );
    let reasons = same["reasons"].as_array().unwrap();
    assert!(reasons.contains(&json!("same_values")) && reasons.contains(&json!("similar_names")));

    let login = find(&r, &key(&p.login_a, &p.login_b)).expect("the pair sharing a value");
    assert_eq!(login["kind"], "shared_value", "{r}");
    assert_eq!(login["identical"], false);

    let token = find(&r, &key(&p.token_a, &p.token_b)).expect("the pair alike by name");
    assert_eq!(token["kind"], "similar_names", "{r}");
    assert_eq!(r["suggestions"].as_array().unwrap().len(), 3, "{r}");
    // Strongest first.
    assert_eq!(r["suggestions"][0]["kind"], "identical");

    assert_no_value(&r.to_string(), "the suggestions");
    assert_audit_has_no_value(&v);
}

#[test]
fn a_merge_keeps_aliases_and_tags_and_undo_brings_the_entry_back_under_its_own_name() {
    let (v, state) = created_vault(None);
    let owner = login(&state);
    let p = planted(&state, &owner);
    let g = generation(&state, &owner, "acme");
    call(
        &state,
        &owner,
        NOW,
        "entry.alias",
        json!({ "node": "acme", "entry": p.same_b, "generation": g, "aliases": ["old-stripe"] }),
    )
    .unwrap();
    let g = generation(&state, &owner, "acme");
    call(
        &state,
        &owner,
        NOW,
        "entry.tag_set",
        json!({ "node": "acme", "entry": p.same_a, "generation": g, "tags": ["prod"] }),
    )
    .unwrap();
    let g = generation(&state, &owner, "acme");
    call(
        &state,
        &owner,
        NOW,
        "entry.tag_set",
        json!({ "node": "acme", "entry": p.same_b, "generation": g, "tags": ["db", "prod"] }),
    )
    .unwrap();

    let g = generation(&state, &owner, "acme");
    let r = call(
        &state,
        &owner,
        NOW,
        "merge.apply",
        json!({ "node": "acme", "keep": p.same_a, "drop": [p.same_b], "generation": g }),
    )
    .expect("merge.apply");
    assert_eq!(r["keep"], json!(p.same_a));
    assert_eq!(
        r["aliasesAdded"],
        json!(["stripe-key", "old-stripe"]),
        "{r}"
    );
    assert_eq!(r["tagsAdded"], json!(["db"]));
    assert_eq!(r["generation"], generation(&state, &owner, "acme"));
    let undo = r["merged"][0]["undo"]
        .as_str()
        .expect("an undo id")
        .to_string();
    assert_no_value(&r.to_string(), "the merge answer");

    let kept = get(&state, &owner, "acme", &p.same_a);
    assert_eq!(kept["aliases"], json!(["stripe-key", "old-stripe"]));
    assert_eq!(kept["tags"], json!(["prod", "db"]));
    assert!(!names(&state, &owner, "acme").contains(&"stripe-key".to_string()));
    let gone = call(
        &state,
        &owner,
        NOW,
        "entry.get",
        json!({ "node": "acme", "entry": p.same_b }),
    );
    assert!(matches!(gone, Err(OpError::NotFound(_))), "{gone:?}");
    assert_eq!(reveal(&state, &owner, "acme", &p.same_a), V_SAME);

    // It survives a restart, and so does the way back.
    let (state, owner) = restart(&v, state, None);
    let g = generation(&state, &owner, "acme");
    let back = call(
        &state,
        &owner,
        NOW,
        "entry.undo",
        json!({ "node": "acme", "id": undo, "generation": g }),
    )
    .expect("entry.undo of the merge's removal");
    assert_eq!(
        back["restoredName"], "stripe-key",
        "its own name, not '<name> old': {back}"
    );
    assert_eq!(back["mergeAliasesRemoved"], 2);
    let kept = get(&state, &owner, "acme", &p.same_a);
    assert!(
        kept.get("aliases").is_none(),
        "the merge's aliases are gone: {kept}"
    );
    assert_eq!(
        kept["tags"],
        json!(["prod", "db"]),
        "tags a merge added stay"
    );
    let restored = get(&state, &owner, "acme", &p.same_b);
    assert_eq!(restored["name"], "stripe-key");
    assert_eq!(restored["aliases"], json!(["old-stripe"]));
    assert_eq!(restored["tags"], json!(["db", "prod"]));
    assert_eq!(reveal(&state, &owner, "acme", &p.same_b), V_SAME);
    assert_audit_has_no_value(&v);
    verify_ok(&state, &owner);
}

#[test]
fn a_dismissed_suggestion_never_returns_and_the_memory_is_sealed_to_the_node() {
    let (v, state) = created_vault(None);
    let owner = login(&state);
    let p = planted(&state, &owner);
    let k = key(&p.login_a, &p.login_b);

    let r = call(
        &state,
        &owner,
        NOW,
        "merge.dismiss",
        json!({ "node": "acme", "key": k }),
    )
    .unwrap();
    assert_eq!(r["dismissed"], true);
    assert_eq!(r["generation"], generation(&state, &owner, "acme"));
    assert!(find(&suggestions(&state, &owner, "acme"), &k).is_none());
    let all = call(
        &state,
        &owner,
        NOW,
        "merge.suggestions",
        json!({ "node": "acme", "includeDismissed": true }),
    )
    .unwrap();
    assert_eq!(find(&all, &k).unwrap()["dismissed"], true);

    // Sealed on disk: the file names no entry; the signed manifest binds its digest.
    let file = v.paths().merge_env("acme");
    let sealed = std::fs::read(&file).expect("the memory file");
    let text = String::from_utf8_lossy(&sealed);
    assert!(
        !text.contains(&p.login_a) && !text.contains("e_"),
        "the memory is sealed"
    );
    let manifest = std::fs::read_to_string(v.paths().manifest("acme")).unwrap();
    assert!(manifest.contains("mergeSha256"));

    // It survives a restart.
    let (state, owner) = restart(&v, state, None);
    assert!(find(&suggestions(&state, &owner, "acme"), &k).is_none());
    let listed = call(
        &state,
        &owner,
        NOW,
        "merge.dismissed_list",
        json!({ "node": "acme" }),
    )
    .unwrap();
    assert_eq!(listed["dismissed"][0]["key"], json!(k));
    let named: Vec<&str> = listed["dismissed"][0]["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["name"].as_str().unwrap())
        .collect();
    assert!(named.contains(&"DB_LOGIN") && named.contains(&"WAREHOUSE"));

    let r = call(
        &state,
        &owner,
        NOW,
        "merge.undismiss",
        json!({ "node": "acme", "key": k }),
    )
    .unwrap();
    assert_eq!(r["restored"], true);
    assert!(find(&suggestions(&state, &owner, "acme"), &k).is_some());

    call(
        &state,
        &owner,
        NOW,
        "merge.dismiss",
        json!({ "node": "acme", "key": k }),
    )
    .unwrap();
    let r = call(
        &state,
        &owner,
        NOW,
        "merge.restore_all",
        json!({ "node": "acme" }),
    )
    .unwrap();
    assert_eq!(r["restored"], 1);
    assert!(find(&suggestions(&state, &owner, "acme"), &k).is_some());
    assert!(!file.exists(), "an empty memory leaves no file");

    // A key that is not well formed, or names an entry not in the node, is refused.
    let bad = call(
        &state,
        &owner,
        NOW,
        "merge.dismiss",
        json!({ "node": "acme", "key": "not-a-key" }),
    );
    assert!(matches!(bad, Err(OpError::Malformed(_))), "{bad:?}");
    let unknown = call(
        &state,
        &owner,
        NOW,
        "merge.dismiss",
        json!({ "node": "acme", "key": key(&p.login_a, "e_000000000000") }),
    );
    assert!(matches!(unknown, Err(OpError::NotFound(_))), "{unknown:?}");

    // An older memory file put back over the current one is refused, as an older note is.
    std::fs::write(&file, &sealed).unwrap();
    let refused = call(
        &state,
        &owner,
        NOW,
        "merge.suggestions",
        json!({ "node": "acme" }),
    );
    assert!(matches!(refused, Err(OpError::Internal(_))), "{refused:?}");
    std::fs::remove_file(&file).unwrap();
    verify_ok(&state, &owner);
}

#[test]
fn auto_merges_only_identical_groups_and_auto_all_is_a_dry_run_unless_told() {
    let (_v, state) = created_vault(None);
    let owner = login(&state);
    let p = planted(&state, &owner);
    let g = generation(&state, &owner, "acme");

    let shared = call(
        &state,
        &owner,
        NOW,
        "merge.auto",
        json!({ "node": "acme", "key": key(&p.login_a, &p.login_b), "generation": g }),
    );
    assert!(matches!(shared, Err(OpError::Malformed(_))), "{shared:?}");

    let before = names(&state, &owner, "acme");
    let dry = call(
        &state,
        &owner,
        NOW,
        "merge.auto_all",
        json!({ "node": "acme" }),
    )
    .unwrap();
    assert_eq!(dry["dryRun"], true);
    assert_eq!(dry["planned"].as_array().unwrap().len(), 1, "{dry}");
    assert_eq!(dry["planned"][0]["key"], json!(key(&p.same_a, &p.same_b)));
    assert_eq!(
        names(&state, &owner, "acme"),
        before,
        "a dry run changes nothing"
    );
    assert_eq!(generation(&state, &owner, "acme"), g);

    let no_gen = call(
        &state,
        &owner,
        NOW,
        "merge.auto_all",
        json!({ "node": "acme", "apply": true }),
    );
    assert!(matches!(no_gen, Err(OpError::Malformed(_))), "{no_gen:?}");
    let applied = call(
        &state,
        &owner,
        NOW,
        "merge.auto_all",
        json!({ "node": "acme", "apply": true, "generation": g }),
    )
    .unwrap();
    assert_eq!(applied["dryRun"], false);
    assert_eq!(applied["merged"].as_array().unwrap().len(), 1, "{applied}");
    let after = names(&state, &owner, "acme");
    assert_eq!(after.len(), before.len() - 1);
    assert!(!after.contains(&"stripe-key".to_string()));

    // Nothing identical is left; an identical key merged by `merge.auto` goes the same way.
    let a = entry(&state, &owner, "acme", "COPY_ONE", one(V_OTHER));
    let b = entry(&state, &owner, "acme", "COPY_TWO", one(V_OTHER));
    let _ = a;
    let g = generation(&state, &owner, "acme");
    let k3 = suggestions(&state, &owner, "acme")["suggestions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["kind"] == "identical")
        .expect("the new identical group (three copies of one value)")["key"]
        .as_str()
        .unwrap()
        .to_string();
    let merged = call(
        &state,
        &owner,
        NOW,
        "merge.auto",
        json!({ "node": "acme", "key": k3, "generation": g }),
    )
    .unwrap();
    assert_eq!(merged["merged"].as_array().unwrap().len(), 2, "{merged}");
    assert!(!names(&state, &owner, "acme").contains(&"COPY_TWO".to_string()));
    let _ = b;
}

#[test]
fn only_the_owners_login_merges_and_a_merge_asks_for_a_fresh_second_factor() {
    let (_v, state) = created_vault(None);
    let owner = login(&state);
    let p = planted(&state, &owner);
    let totp = enrol_gate(&state, &owner);
    let g = generation(&state, &owner, "acme");
    let k = key(&p.same_a, &p.same_b);
    let apply = json!({ "node": "acme", "keep": p.same_a, "drop": [p.same_b], "generation": g });

    let agent = BrokerScope {
        node_id: "acme".into(),
        capabilities: vec![
            Capability::List,
            Capability::Read,
            Capability::Reveal,
            Capability::Update,
            Capability::Admin,
        ],
        origin: Origin::Agent,
        token_id: None,
        bound_workdir: None,
    };
    for (op, params) in [
        ("merge.suggestions", json!({ "node": "acme" })),
        ("merge.apply", apply.clone()),
        (
            "merge.auto",
            json!({ "node": "acme", "key": k, "generation": g }),
        ),
        ("merge.auto_all", json!({ "node": "acme" })),
        ("merge.dismiss", json!({ "node": "acme", "key": k })),
        ("merge.undismiss", json!({ "node": "acme", "key": k })),
        ("merge.dismissed_list", json!({ "node": "acme" })),
        ("merge.restore_all", json!({ "node": "acme" })),
    ] {
        let r = call(&state, &agent, NOW, op, params);
        assert!(
            matches!(r, Err(OpError::CapabilityNotHeld { .. })),
            "{op}: {r:?}"
        );
    }
    let orphan = call(
        &state,
        &owner,
        NOW,
        "merge.suggestions",
        json!({ "node": "orphan" }),
    );
    assert!(matches!(orphan, Err(OpError::Malformed(_))), "{orphan:?}");

    // A stale generation costs no code; then the factor is asked for and nothing changes without it.
    let mut stale = apply.clone();
    stale["generation"] = json!(g - 1);
    let r = call(&state, &owner, LATER, "merge.apply", stale);
    assert!(matches!(r, Err(OpError::Conflict { .. })), "{r:?}");
    let r = call(&state, &owner, LATER, "merge.apply", apply.clone());
    assert!(matches!(r, Err(OpError::TwoFactorRequired { .. })), "{r:?}");
    assert!(names(&state, &owner, "acme").contains(&"stripe-key".to_string()));

    // A dropped entry with a grant of its own is refused, before any code.
    state.registry.write().unwrap().grants.push(Grant {
        id: "g_merge_test".into(),
        from: "global".into(),
        to: GrantTarget::Entry {
            node_id: "acme".into(),
            entry_id: p.same_b.clone(),
        },
        direction: Direction::OneWay,
        scope: vec![Capability::Read],
        expires_at: None,
        reason: "test".into(),
    });
    let r = call(&state, &owner, LATER, "merge.apply", apply.clone());
    assert!(
        matches!(r, Err(OpError::Malformed(ref m)) if m.contains("grant")),
        "{r:?}"
    );
    let dry = call(
        &state,
        &owner,
        LATER,
        "merge.auto_all",
        json!({ "node": "acme" }),
    )
    .unwrap();
    assert_eq!(dry["skipped"][0]["reason"], "grant", "{dry}");
    state
        .registry
        .write()
        .unwrap()
        .grants
        .retain(|g| g.id != "g_merge_test");

    step_up(&state, &owner, &totp, LATER);
    let r =
        call(&state, &owner, LATER, "merge.apply", apply).expect("merge.apply with a fresh code");
    assert_eq!(r["merged"].as_array().unwrap().len(), 1);
}

/// A write that lands after a merge passed its first generation check, while it waits for the node's write
/// lock, makes the merge answer `conflict` and write nothing: the generation and the plan are checked again
/// under the lock. `merge.auto` and `merge.auto_all` refuse a stale generation the same way.
#[test]
fn a_write_that_lands_before_the_merge_takes_the_lock_is_a_conflict_and_nothing_is_merged() {
    let (v, state) = created_vault(None);
    let owner = login(&state);
    let p = planted(&state, &owner);
    let g = generation(&state, &owner, "acme");

    let lock = state.node_write_lock("acme");
    let held = lock.lock().unwrap();
    let racer = {
        let state = std::sync::Arc::clone(&state);
        let owner = owner.clone();
        let (keep, gone) = (p.same_a.clone(), p.same_b.clone());
        std::thread::spawn(move || {
            call(
                &state,
                &owner,
                NOW,
                "merge.apply",
                json!({ "node": "acme", "keep": keep, "drop": [gone], "generation": g }),
            )
        })
    };
    std::thread::sleep(std::time::Duration::from_millis(300));
    // Another writer moves the node on (as a write that held the lock first would have).
    state
        .update_manifest_entry("acme", &p.token_a, |e| e.modified = NOW + 1)
        .expect("the entry exists");
    drop(held);
    let r = racer.join().unwrap();
    assert!(matches!(r, Err(OpError::Conflict { .. })), "{r:?}");
    assert!(
        names(&state, &owner, "acme").contains(&"stripe-key".to_string()),
        "nothing merged"
    );
    assert!(
        !v.paths().removed_entry_meta("acme", &p.same_b).exists(),
        "nothing archived"
    );

    let stale = generation(&state, &owner, "acme") - 1;
    let k = key(&p.same_a, &p.same_b);
    let r = call(
        &state,
        &owner,
        NOW,
        "merge.auto",
        json!({ "node": "acme", "key": k, "generation": stale }),
    );
    assert!(matches!(r, Err(OpError::Conflict { .. })), "{r:?}");
    let r = call(
        &state,
        &owner,
        NOW,
        "merge.auto_all",
        json!({ "node": "acme", "apply": true, "generation": stale }),
    );
    assert!(matches!(r, Err(OpError::Conflict { .. })), "{r:?}");
    assert!(names(&state, &owner, "acme").contains(&"stripe-key".to_string()));
}
