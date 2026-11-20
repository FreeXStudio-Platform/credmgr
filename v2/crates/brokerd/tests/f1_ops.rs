//! ADR-131…134 — Destroy orphans, content search, `--age` export, `audit.report`.
//!
//! Presence-gated rows sign with a software P-256 key (ADR-148 §P2-5), so they run on every host.

mod f1_support;

use std::process::Command;

use serde_json::{json, Value};

use credmgr_brokerd::peer::PeerInfo;
use credmgr_brokerd::protocol::{OpError, Request};
use credmgr_brokerd::scope::BrokerScope;
use credmgr_brokerd::server;
use credmgr_brokerd::state::{BrokerState, DestroyFault};
use credmgr_core::access::Origin;
use credmgr_core::registry::{Capability, ORPHAN_ID};

use f1_support::*;

const CONFIRM: &str = "destroy-sealed-entries";

// ---------------------------------------------------------------------------
// Destroy orphans (ADR-131)
// ---------------------------------------------------------------------------

/// Two nodes with two entries each, both sealed. Returns `(g1 entries, g2 entries)`.
fn two_sealed_nodes(state: &BrokerState, owner: &BrokerScope) -> (Vec<String>, Vec<String>) {
    let mut ids = Vec::new();
    for node in ["g1", "g2"] {
        create_node(state, owner, node);
        let a = create_entry(
            state,
            owner,
            node,
            &format!("{node}-first"),
            &format!("{node}-value-one"),
        );
        let b = create_entry(
            state,
            owner,
            node,
            &format!("{node}-second"),
            &format!("{node}-value-two"),
        );
        // one removal and one rotation each, so their archives have something behind them too.
        call(
            state,
            owner,
            NOW,
            "entry.rotate",
            json!({ "node": node, "entry": a, "value": "rotated", "generation": generation(state, owner, node) }),
        )
        .unwrap();
        ids.push(vec![a, b]);
        call(state, owner, NOW, "node.seal", json!({ "node": node })).expect("node.seal");
    }
    let g2 = ids.pop().unwrap();
    let g1 = ids.pop().unwrap();
    (g1, g2)
}

fn orphan_ids(state: &BrokerState, owner: &BrokerScope) -> Vec<String> {
    let mut v: Vec<String> = call(state, owner, NOW, "orphan.list", json!({})).unwrap()["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["entry"].as_str().unwrap().to_string())
        .collect();
    v.sort();
    v
}

#[test]
fn destroy_refuses_without_the_word_the_right_count_or_a_real_entry() {
    let (_v, state) = created_vault(None);
    let owner = login(&state);
    let (g1, _g2) = two_sealed_nodes(&state, &owner);

    let r = call(
        &state,
        &owner,
        NOW,
        "orphan.destroy",
        json!({ "confirm": "yes", "count": 4 }),
    );
    assert!(
        matches!(&r, Err(OpError::Malformed(m)) if m.contains("confirm")),
        "{r:?}"
    );
    let r = call(
        &state,
        &owner,
        NOW,
        "orphan.destroy",
        json!({ "confirm": CONFIRM, "count": 3 }),
    );
    assert!(
        matches!(&r, Err(OpError::Malformed(m)) if m.contains("4 sealed entries")),
        "{r:?}"
    );
    let r = call(
        &state,
        &owner,
        NOW,
        "orphan.destroy",
        json!({ "confirm": CONFIRM, "count": 1, "entries": ["e_ffffffffffff"] }),
    );
    assert!(matches!(r, Err(OpError::NotFound(_))), "{r:?}");
    // No word, no count: missing parameters are malformed, not a default.
    assert!(matches!(
        call(&state, &owner, NOW, "orphan.destroy", json!({})),
        Err(OpError::Malformed(_))
    ));
    // Nothing was touched by any of that.
    assert_eq!(orphan_ids(&state, &owner).len(), 4);
    assert_eq!(g1.len(), 2);

    // Not an agent's op, and not the owner's without a proof.
    let agent = BrokerScope {
        node_id: "global".into(),
        capabilities: vec![Capability::List, Capability::Admin],
        origin: Origin::Agent,
        token_id: None,
        bound_workdir: None,
    };
    assert!(call(
        &state,
        &agent,
        NOW,
        "orphan.destroy",
        json!({ "confirm": CONFIRM, "count": 4 })
    )
    .is_err());
    let r = call(
        &state,
        &owner,
        NOW,
        "orphan.destroy",
        json!({ "confirm": CONFIRM, "count": 4 }),
    );
    assert!(
        matches!(
            r,
            Err(OpError::PresenceRequired { .. }) | Err(OpError::Internal(_))
        ),
        "{r:?}"
    );
}

#[test]
fn destroying_some_entries_ends_their_seals_and_leaves_the_other_seal_restorable() {
    let (v, state) = created_vault(None);
    let owner = login(&state);
    let key = enrol_first_key(&state, &owner);
    let (g1, g2) = two_sealed_nodes(&state, &owner);
    assert!(v.paths().archive_dir("g1").exists() && v.paths().archive_dir("g2").exists());

    // Destroy ONE of g1's two entries: g1's seal cannot be restored faithfully any more, so its record ends.
    let ask = json!({ "confirm": CONFIRM, "count": 1, "entries": [g1[0]] });
    let proved = with_proof(&state, &owner, &key, NOW, "orphan.destroy", ask);
    let done = call(&state, &owner, NOW, "orphan.destroy", proved).expect("destroy");
    assert_eq!(done["destroyed"], 1);
    assert_eq!(done["sealsForgotten"], 1);

    let left = orphan_ids(&state, &owner);
    assert!(
        !left.contains(&g1[0]),
        "the destroyed entry is gone from the list"
    );
    assert!(left.contains(&g1[1]) && left.contains(&g2[0]) && left.contains(&g2[1]));
    assert!(
        !v.paths().entry_env(ORPHAN_ID, &g1[0]).exists(),
        "its envelope file is gone"
    );
    assert!(
        v.paths().entry_env(ORPHAN_ID, &g1[1]).exists(),
        "the untouched entry's file stays"
    );
    assert!(
        !v.paths().archive_dir("g1").exists(),
        "g1's retained originals are gone"
    );
    assert!(v.paths().archive_dir("g2").exists(), "g2's are not");
    // g1 cannot be restored; g2 can — with every entry it had.
    assert!(call(&state, &owner, NOW, "node.restore", json!({ "node": "g1" })).is_err());
    call(&state, &owner, NOW, "node.restore", json!({ "node": "g2" })).expect("g2 restores");
    assert_eq!(reveal(&state, &owner, "g2", &g2[1]), "g2-value-two");
    verify_ok(&state, &owner);

    // The proof was for one use: the same call again is refused.
    let again = call(
        &state,
        &owner,
        NOW,
        "orphan.destroy",
        with_proof(
            &state,
            &owner,
            &key,
            NOW,
            "orphan.destroy",
            json!({ "confirm": CONFIRM, "count": 1, "entries": [g1[1]] }),
        ),
    )
    .expect("a fresh proof destroys the next one");
    assert_eq!(again["destroyed"], 1);
}

#[test]
fn destroying_everything_leaves_nothing_sealed_and_survives_a_restart() {
    let (v, state) = created_vault(None);
    let owner = login(&state);
    let key = enrol_first_key(&state, &owner);
    let (_g1, _g2) = two_sealed_nodes(&state, &owner);

    let ask = json!({ "confirm": CONFIRM, "count": 4 });
    let proved = with_proof(&state, &owner, &key, NOW, "orphan.destroy", ask);
    let done = call(&state, &owner, NOW, "orphan.destroy", proved).expect("destroy all");
    assert_eq!(
        (done["destroyed"].as_u64(), done["sealsForgotten"].as_u64()),
        (Some(4), Some(2))
    );
    assert!(orphan_ids(&state, &owner).is_empty());
    let leftovers = std::fs::read_dir(v.paths().node_dir(ORPHAN_ID).join("entries"))
        .map(|r| r.flatten().count())
        .unwrap_or(0);
    assert_eq!(leftovers, 0, "no envelope file is left");
    assert!(!v.paths().archive_dir("g1").exists() && !v.paths().archive_dir("g2").exists());
    assert!(
        !v.paths().orphan_destroy_journal().exists(),
        "the journal is gone"
    );
    verify_ok(&state, &owner);

    let (state, owner) = restart(&v, state, None);
    assert!(orphan_ids(&state, &owner).is_empty());
    assert!(call(&state, &owner, NOW, "node.restore", json!({ "node": "g1" })).is_err());
    // And the ids are free: a new node may take the name.
    create_node(&state, &owner, "g1");
    verify_ok(&state, &owner);
}

#[test]
fn a_crash_before_the_commit_destroys_nothing_and_after_it_finishes_the_deletion() {
    for (label, fault, destroyed) in [
        ("after journal", DestroyFault::AfterJournal, false),
        ("after commit", DestroyFault::AfterCommit, true),
    ] {
        let (v, state) = created_vault(None);
        let owner = login(&state);
        let (g1, g2) = two_sealed_nodes(&state, &owner);
        state.set_destroy_fault_for_test(Some(fault));
        let r = state.destroy_orphans_durable(None, 4, NOW);
        assert!(r.is_err(), "{label}: {r:?}");
        assert!(
            v.paths().orphan_destroy_journal().exists(),
            "{label}: the crash left its journal"
        );
        drop(owner);

        let (state, owner) = restart(&v, state, None);
        assert!(
            !v.paths().orphan_destroy_journal().exists(),
            "{label}: the journal is settled"
        );
        if destroyed {
            assert!(orphan_ids(&state, &owner).is_empty(), "{label}");
            for id in g1.iter().chain(&g2) {
                assert!(
                    !v.paths().entry_env(ORPHAN_ID, id).exists(),
                    "{label}: {id} deleted by the journal"
                );
            }
            assert!(
                !v.paths().archive_dir("g1").exists() && !v.paths().archive_dir("g2").exists(),
                "{label}"
            );
        } else {
            assert_eq!(
                orphan_ids(&state, &owner).len(),
                4,
                "{label}: nothing was committed, nothing is lost"
            );
            assert!(
                v.paths().entry_env(ORPHAN_ID, &g1[0]).exists(),
                "{label}: files untouched"
            );
            assert!(v.paths().archive_dir("g1").exists(), "{label}");
            call(&state, &owner, NOW, "node.restore", json!({ "node": "g1" }))
                .expect("still restorable");
        }
        verify_ok(&state, &owner);
    }
}

/// ADR-148 P3 (rated PLAUSIBLE): a journal a destroy left behind, then a new node taking a sealed id
/// the destroy freed. NOT REPRODUCIBLE, and kept as the guard: a real crash restarts the broker, and
/// every unlock applies the journal (`durable.rs::load_from_disk`) before anyone can create a node; a
/// broker that survived (the fault seam models that: it returns an error instead of dying) still
/// refuses `node.create` for the id while `archive/<id>` exists (ADR-079 F-d), and the journal removes
/// that directory last (`destroy.rs`), so the sibling archives are gone before the id is free.
#[test]
fn a_leftover_destroy_journal_never_deletes_the_archives_of_a_node_that_took_a_freed_id() {
    let (v, state) = created_vault(None);
    let owner = login(&state);
    let (_g1, _g2) = two_sealed_nodes(&state, &owner);
    state.set_destroy_fault_for_test(Some(DestroyFault::AfterCommit));
    assert!(state.destroy_orphans_durable(None, 4, NOW).is_err());
    assert!(v.paths().orphan_destroy_journal().exists());

    // The broker lived, the journal is still pending, "g1"'s archive is still on disk: the id is held.
    let refused = call(
        &state,
        &owner,
        NOW,
        "node.create",
        json!({ "id": "g1", "label": "g1", "parentId": credmgr_core::registry::GLOBAL_ID }),
    );
    assert!(
        refused.is_err(),
        "a node may not take the id while the destroy's journal and archive are pending"
    );
    drop(owner);

    // The restart applies the journal; only then is the id free, and a new g1's history is its own.
    let (state, owner) = restart(&v, state, None);
    assert!(!v.paths().orphan_destroy_journal().exists());
    assert!(!v.paths().archive_dir("g1").exists());
    create_node(&state, &owner, "g1");
    let e = create_entry(&state, &owner, "g1", "fresh", "fresh-value-one");
    call(
        &state,
        &owner,
        NOW,
        "entry.rotate",
        json!({ "node": "g1", "entry": e, "value": "fresh-value-two", "generation": generation(&state, &owner, "g1") }),
    )
    .expect("rotate the new g1's entry");
    let history = v.paths().archive_root().join("entry-history").join("g1");
    let before: Vec<_> = walk(&history);
    assert!(
        before.iter().any(|p| p.contains(&e)),
        "the new g1 has history on disk: {before:?}"
    );
    drop(owner);

    // A second restart (no journal now) leaves the new node's history alone.
    let (state, owner) = restart(&v, state, None);
    let after: Vec<_> = walk(&history);
    assert!(
        after.iter().any(|p| p.contains(&e)),
        "the new node's history survived: before {before:?}, after {after:?}"
    );
    assert_eq!(reveal(&state, &owner, "g1", &e), "fresh-value-two");
    verify_ok(&state, &owner);
}

fn walk(dir: &std::path::Path) -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(read) = std::fs::read_dir(dir) {
        for entry in read.flatten() {
            let p = entry.path();
            if p.is_dir() {
                out.extend(walk(&p));
            } else {
                out.push(p.display().to_string());
            }
        }
    }
    out
}

#[test]
fn destroy_is_audited_by_name_and_count_and_never_names_an_entry() {
    let (v, state) = created_vault(None);
    let owner = login(&state);
    let key = enrol_first_key(&state, &owner);
    let (g1, _g2) = two_sealed_nodes(&state, &owner);

    let ask = json!({ "confirm": CONFIRM, "count": 1, "entries": [g1[0]] });
    let proved = with_proof(&state, &owner, &key, NOW, "orphan.destroy", ask);
    let (result, audit) = server::handle_request(
        &state,
        &peer(),
        &Request {
            id: "d".into(),
            op: "orphan.destroy".into(),
            token: owner.token_id.clone(),
            params: proved,
        },
    );
    result.expect("destroy through the real request path");
    assert!(audit.is_some(), "the request carried an audit id");
    let log = std::fs::read_to_string(
        v.paths().audit_log(&credmgr_store::audit::year_month_for(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
        )),
    )
    .unwrap();
    assert!(
        log.contains("\"orphan.destroy\""),
        "the record names the op"
    );
    assert!(
        !log.contains(&g1[0]) || log.matches(&g1[0]).count() <= 1,
        "an entry id is at most the request's own field"
    );
    assert!(!log.contains("g1-value-one"), "never a value");
}

// ---------------------------------------------------------------------------
// Content search (ADR-132)
// ---------------------------------------------------------------------------

fn agent_on(node: &str) -> BrokerScope {
    BrokerScope {
        node_id: node.to_string(),
        capabilities: vec![Capability::List, Capability::Read, Capability::Reveal],
        origin: Origin::Agent,
        token_id: None,
        bound_workdir: None,
    }
}

#[test]
fn content_search_finds_by_value_and_answers_ids_and_names_only() {
    let (_v, state) = created_vault(None);
    let owner = login(&state);
    create_node(&state, &owner, "acme");
    let hit = create_entry(
        &state,
        &owner,
        "acme",
        "database",
        "db password hunter2-plum for the svc user",
    );
    create_entry(&state, &owner, "acme", "other", "nothing relevant");
    // A stored 2FA seed is never matched, whatever the term.
    let seed = call(
        &state,
        &owner,
        NOW,
        "entry.create",
        json!({ "node": "acme", "name": "authenticator", "value": "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&issuer=x" }),
    )
    .expect("a seed entry")["entry"]
        .as_str()
        .unwrap()
        .to_string();

    let r = call(
        &state,
        &owner,
        NOW,
        "search.content",
        json!({ "term": "hunter2" }),
    )
    .expect("search");
    let rows = r["results"].as_array().unwrap();
    assert_eq!(rows.len(), 1, "{r}");
    assert_eq!(rows[0]["id"], json!(hit));
    assert_eq!(rows[0]["name"], "database");
    assert_eq!(rows[0]["node"], "acme");
    let text = r.to_string();
    assert!(
        !text.contains("hunter2") && !text.contains("db password"),
        "no value, no snippet: {text}"
    );
    assert_eq!(
        rows[0].as_object().unwrap().len(),
        3,
        "exactly node, id and name: {rows:?}"
    );

    // Case does not matter; a node filter narrows; a miss is an empty list, not an error.
    let r = call(
        &state,
        &owner,
        NOW,
        "search.content",
        json!({ "term": "HUNTER2", "node": "acme" }),
    )
    .unwrap();
    assert_eq!(r["results"].as_array().unwrap().len(), 1);
    let r = call(
        &state,
        &owner,
        NOW,
        "search.content",
        json!({ "term": "no-such-thing" }),
    )
    .unwrap();
    assert!(r["results"].as_array().unwrap().is_empty());
    let r = call(
        &state,
        &owner,
        NOW,
        "search.content",
        json!({ "term": "JBSWY3" }),
    )
    .unwrap();
    assert!(
        r["results"].as_array().unwrap().is_empty(),
        "a 2FA seed is not searchable: {r}"
    );
    let _ = seed;

    // Terms are bounded: a one-letter probe is an enumeration, not a search.
    for bad in ["", "ab", &"x".repeat(201)] {
        let r = call(
            &state,
            &owner,
            NOW,
            "search.content",
            json!({ "term": bad }),
        );
        assert!(matches!(r, Err(OpError::Malformed(_))), "{bad:?}: {r:?}");
    }
    assert!(matches!(
        call(
            &state,
            &owner,
            NOW,
            "search.content",
            json!({ "term": "hunter2", "node": "nowhere" })
        ),
        Err(OpError::NotFound(_))
    ));
}

#[test]
fn content_search_needs_reveal_is_rate_limited_and_blind_to_private_nodes_for_agents() {
    let (_v, state) = created_vault(None);
    let owner = login(&state);
    create_node(&state, &owner, "acme");
    let hit = create_entry(&state, &owner, "acme", "database", "needle-in-acme");

    // Without `reveal` it is refused, however much the caller may list.
    let mut reader = agent_on("acme");
    reader.capabilities = vec![Capability::List, Capability::Read];
    assert!(matches!(
        call(
            &state,
            &reader,
            NOW,
            "search.content",
            json!({ "term": "needle" })
        ),
        Err(OpError::CapabilityNotHeld {
            capability: Capability::Reveal
        })
    ));

    // An agent that may reveal on acme finds it; once acme is private it finds nothing, the owner still does.
    let agent = agent_on("acme");
    let r = call(
        &state,
        &agent,
        NOW,
        "search.content",
        json!({ "term": "needle" }),
    )
    .unwrap();
    assert_eq!(r["results"][0]["id"], json!(hit), "{r}");
    call(
        &state,
        &owner,
        NOW,
        "node.policy",
        json!({ "node": "acme", "reason": "test", "policy": { "privateNames": true } }),
    )
    .expect("node.policy");
    let r = call(
        &state,
        &agent,
        NOW,
        "search.content",
        json!({ "term": "needle" }),
    )
    .unwrap();
    assert!(
        r["results"].as_array().unwrap().is_empty(),
        "an agent never searches a private node: {r}"
    );
    let r = call(
        &state,
        &owner,
        NOW,
        "search.content",
        json!({ "term": "needle" }),
    )
    .unwrap();
    assert_eq!(r["results"].as_array().unwrap().len(), 1);

    // Rate limit: the 13th call inside a minute is refused with a wait; a rejected call is not counted;
    // the window passes.
    let mut at = NOW;
    let mut refused_at = None;
    for i in 0..13 {
        match call(
            &state,
            &agent,
            at,
            "search.content",
            json!({ "term": "needle" }),
        ) {
            Ok(_) => {}
            Err(OpError::RateLimited {
                retry_after_seconds,
            }) => {
                refused_at = Some((i, retry_after_seconds));
                break;
            }
            Err(e) => panic!("{e:?}"),
        }
        at += 1;
    }
    let (i, wait) = refused_at.expect("the limiter fires");
    assert!(i >= 10, "the window admits a dozen calls, not {i}");
    assert!((1..=60).contains(&wait));
    assert!(call(
        &state,
        &agent,
        at + 61,
        "search.content",
        json!({ "term": "needle" })
    )
    .is_ok());
    // The owner's session is its own caller: the agent's exhaustion did not touch it.
    assert!(call(
        &state,
        &owner,
        at,
        "search.content",
        json!({ "term": "needle" })
    )
    .is_ok());
}

#[test]
fn content_search_skips_a_node_that_would_ask_an_agent_for_a_second_factor_and_a_locked_vault_refuses(
) {
    let (_v, state) = created_vault(None);
    let owner = login(&state);
    create_node(&state, &owner, "acme");
    create_entry(&state, &owner, "acme", "database", "needle-in-acme");
    let totp = enrol_gate(&state, &owner);
    let agent = agent_on("acme");

    let r = call(
        &state,
        &agent,
        LATER,
        "search.content",
        json!({ "term": "needle" }),
    )
    .unwrap();
    assert!(
        r["results"].as_array().unwrap().is_empty(),
        "a node that asks for a second factor is skipped: {r}"
    );
    step_up(&state, &owner, &totp, LATER);
    let r = call(
        &state,
        &agent,
        LATER,
        "search.content",
        json!({ "term": "needle" }),
    )
    .unwrap();
    assert_eq!(
        r["results"].as_array().unwrap().len(),
        1,
        "with the factor fresh it is searched: {r}"
    );

    state.lock();
    assert!(matches!(
        call(
            &state,
            &agent,
            LATER,
            "search.content",
            json!({ "term": "needle" })
        ),
        Err(OpError::VaultLocked)
    ));
}

// ---------------------------------------------------------------------------
// Export (ADR-133)
// ---------------------------------------------------------------------------

fn age_tools() -> Option<(String, String)> {
    let age = std::env::var("CREDMGR_AGE_BIN").unwrap_or_else(|_| "age".into());
    let keygen = std::env::var("CREDMGR_AGE_KEYGEN_BIN").unwrap_or_else(|_| "age-keygen".into());
    (Command::new(&age).arg("--version").output().is_ok()
        && Command::new(&keygen).arg("--help").output().is_ok())
    .then_some((age, keygen))
}

#[test]
fn an_export_is_age_ciphertext_for_the_chosen_recipient_and_the_gates_are_in_front_of_it() {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;
    let (_v, state) = created_vault(None);
    let owner = login(&state);
    let key = enrol_first_key(&state, &owner);
    create_node(&state, &owner, "acme");
    create_entry(&state, &owner, "acme", "database", "export-value-one");
    create_entry(
        &state,
        &owner,
        "acme",
        "authenticator",
        "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&issuer=x",
    );

    let ask = json!({ "node": "acme", "passphrase": "a long export passphrase" });
    // Shape errors first, each before a prompt could be spent.
    for (bad, why) in [
        (
            json!({ "node": "acme" }),
            "neither passphrase nor recipients",
        ),
        (
            json!({ "node": "acme", "passphrase": "short" }),
            "a short passphrase",
        ),
        (
            json!({ "node": "acme", "passphrase": "a long export passphrase", "recipients": ["age1x"] }),
            "both",
        ),
        (
            json!({ "node": "acme", "recipients": ["not-an-age-key"] }),
            "a junk recipient",
        ),
        (
            json!({ "node": "orphan", "passphrase": "a long export passphrase" }),
            "the orphan node",
        ),
    ] {
        let r = call(&state, &owner, NOW, "node.export", bad);
        assert!(matches!(r, Err(OpError::Malformed(_))), "{why}: {r:?}");
    }
    // A proof is required; an agent is not the owner.
    assert!(matches!(
        call(&state, &owner, NOW, "node.export", ask.clone()),
        Err(OpError::PresenceRequired { .. })
    ));
    assert!(call(&state, &agent_on("acme"), NOW, "node.export", ask.clone()).is_err());

    let proved = with_proof(&state, &owner, &key, NOW, "node.export", ask);
    let out = call(&state, &owner, NOW, "node.export", proved).expect("passphrase export");
    assert_eq!(
        (
            out["format"].as_str(),
            out["entries"].as_u64(),
            out["omittedSeeds"].as_u64()
        ),
        (Some("age-v1"), Some(2), Some(1))
    );
    let cipher = B64.decode(out["archive"].as_str().unwrap()).unwrap();
    assert!(
        cipher.starts_with(b"age-encryption.org/v1\n-> scrypt "),
        "a passphrase age file"
    );
    let blob = String::from_utf8_lossy(&cipher).to_string();
    assert!(
        !blob.contains("export-value-one") && !blob.contains("JBSWY3"),
        "ciphertext, not text"
    );
    assert!(
        !out.to_string().contains("export-value-one"),
        "no plaintext in the response either"
    );

    // A recipient export opens with stock age, and holds the values — minus the seed.
    let Some((age, keygen)) = age_tools() else {
        eprintln!("skipped the stock-age half: no `age` binary on PATH");
        return;
    };
    let identity = String::from_utf8(Command::new(keygen).output().unwrap().stdout).unwrap();
    let recipient = identity
        .lines()
        .find_map(|l| l.strip_prefix("# public key: "))
        .unwrap()
        .to_string();
    let ask = json!({ "node": "acme", "recipients": [recipient] });
    let proved = with_proof(&state, &owner, &key, NOW, "node.export", ask);
    let out = call(&state, &owner, NOW, "node.export", proved).expect("recipient export");
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("id.txt"), &identity).unwrap();
    std::fs::write(
        dir.path().join("x.age"),
        B64.decode(out["archive"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    let opened = Command::new(age)
        .args(["-d", "-i"])
        .arg(dir.path().join("id.txt"))
        .arg(dir.path().join("x.age"))
        .output()
        .unwrap();
    assert!(
        opened.status.success(),
        "{}",
        String::from_utf8_lossy(&opened.stderr)
    );
    let doc: Value = serde_json::from_slice(&opened.stdout).unwrap();
    assert_eq!(doc["format"], "credmgr-export");
    assert_eq!(doc["node"]["id"], "acme");
    let text = doc.to_string();
    assert!(
        text.contains("export-value-one"),
        "the value is in the archive"
    );
    assert!(
        !text.contains("JBSWY3"),
        "the 2FA seed is not: an export is not a side door"
    );
    assert!(text.contains("totp_seed"), "and it says why");
}

#[test]
fn an_export_asks_for_a_fresh_second_factor_each_time() {
    let (_v, state) = created_vault(None);
    let owner = login(&state);
    let key = enrol_first_key(&state, &owner);
    create_node(&state, &owner, "acme");
    create_entry(&state, &owner, "acme", "database", "v");
    let totp = enrol_gate(&state, &owner);
    let ask = json!({ "node": "acme", "passphrase": "a long export passphrase" });

    assert!(matches!(
        call(&state, &owner, LATER, "node.export", ask.clone()),
        Err(OpError::TwoFactorRequired { .. })
    ));
    step_up(&state, &owner, &totp, LATER);
    let proved = with_proof(&state, &owner, &key, LATER, "node.export", ask.clone());
    call(&state, &owner, LATER, "node.export", proved).expect("with the factor and the proof");
    let proved = with_proof(&state, &owner, &key, LATER, "node.export", ask);
    assert!(
        matches!(
            call(&state, &owner, LATER, "node.export", proved),
            Err(OpError::TwoFactorRequired { .. })
        ),
        "the window did not survive the export"
    );
}

// ---------------------------------------------------------------------------
// audit.report (ADR-134)
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn put(
    state: &BrokerState,
    v: &Vault,
    at: i64,
    actor: &str,
    action: &str,
    node: Option<&str>,
    decision: &str,
    detail: Option<&str>,
) {
    let rk = root_key(v);
    credmgr_store::audit::append(
        &state.paths,
        &rk,
        &credmgr_store::audit::year_month_for(at),
        credmgr_store::audit::NewEvent {
            actor: actor.into(),
            action: action.into(),
            node_id: node.map(str::to_string),
            entry_id: None,
            decision: Some(decision.into()),
            detail: detail.map(str::to_string),
            generation: None,
        },
        at,
    )
    .unwrap();
}

#[test]
fn the_report_counts_by_actor_action_and_decision_and_carries_no_free_text() {
    let (v, state) = created_vault(None);
    let owner = login(&state);
    let t0 = NOW;
    put(
        &state,
        &v,
        t0 + 10,
        "s_alice",
        "entry.reveal",
        Some("acme"),
        "allow",
        None,
    );
    put(
        &state,
        &v,
        t0 + 20,
        "s_alice",
        "entry.reveal",
        Some("acme"),
        "allow",
        None,
    );
    put(
        &state,
        &v,
        t0 + 30,
        "agent:cli",
        "entry.reveal",
        Some("acme"),
        "deny",
        Some("node_access_denied"),
    );
    put(
        &state,
        &v,
        t0 + 40,
        "s_alice",
        "node.policy",
        Some("acme"),
        "allow",
        Some("reason: rotating the SECRET-HINT-ZEBRA"),
    );
    put(
        &state,
        &v,
        t0 + 50,
        "s_alice",
        "audit.get",
        None,
        "allow",
        None,
    );
    put(
        &state,
        &v,
        t0 + 60,
        "s_alice",
        "orphan.destroy",
        Some("orphan"),
        "deny",
        Some("presence_required"),
    );
    put(
        &state,
        &v,
        t0 + 70,
        "s_alice",
        "presence.enrol",
        None,
        "allow",
        None,
    );
    put(
        &state,
        &v,
        t0 - 5_000,
        "s_old",
        "entry.reveal",
        Some("acme"),
        "allow",
        None,
    ); // before the period.

    let r = call(
        &state,
        &owner,
        t0 + 100,
        "audit.report",
        json!({ "from": t0, "to": t0 + 1_000 }),
    )
    .expect("report");
    assert_eq!(r["records"], 7, "{r}");
    assert_eq!(r["decisions"], json!({ "allow": 5, "deny": 2, "other": 0 }));
    let reveal = r["byAction"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["action"] == "entry.reveal")
        .unwrap();
    assert_eq!(
        (
            reveal["count"].as_u64(),
            reveal["allow"].as_u64(),
            reveal["deny"].as_u64()
        ),
        (Some(3), Some(2), Some(1))
    );
    let alice = r["byActor"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["actor"] == "s_alice")
        .unwrap();
    assert_eq!(alice["count"], 6);
    assert_eq!(r["denials"]["total"], 2);
    let reasons: Vec<(String, String)> = r["denials"]["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| {
            (
                d["action"].as_str().unwrap().into(),
                d["reason"].as_str().unwrap().into(),
            )
        })
        .collect();
    assert!(reasons.contains(&("entry.reveal".into(), "node_access_denied".into())));
    assert!(reasons.contains(&("orphan.destroy".into(), "presence_required".into())));
    // Presence: audit.get and presence.enrol were allowed uses; the destroy was refused for want of it.
    assert_eq!(r["presence"]["uses"], 2);
    assert_eq!(r["presence"]["refused"], 1);
    assert_eq!(r["chain"]["verified"], true);
    // Free text a person wrote is never in the report.
    assert!(!r.to_string().contains("SECRET-HINT-ZEBRA"), "{r}");

    // A node filter narrows it.
    let r = call(
        &state,
        &owner,
        t0 + 100,
        "audit.report",
        json!({ "from": t0, "to": t0 + 1_000, "node": "orphan" }),
    )
    .unwrap();
    assert_eq!(r["records"], 1);
}

#[test]
fn the_report_is_the_owners_bounded_and_notices_a_broken_chain() {
    let (v, state) = created_vault(None);
    let owner = login(&state);
    put(
        &state,
        &v,
        NOW + 1,
        "s_a",
        "entry.reveal",
        Some("acme"),
        "allow",
        None,
    );
    put(
        &state,
        &v,
        NOW + 2,
        "s_a",
        "entry.reveal",
        Some("acme"),
        "allow",
        None,
    );

    let mut agent = agent_on("global");
    agent.capabilities = vec![Capability::List, Capability::Admin];
    assert!(call(
        &state,
        &agent,
        NOW,
        "audit.report",
        json!({ "from": NOW, "to": NOW + 10 })
    )
    .is_err());
    for bad in [
        json!({ "from": 10, "to": 5 }),
        json!({ "from": 0, "to": 400 * 86_400 }),
        json!({ "from": -1, "to": 5 }),
        json!({}),
    ] {
        let r = call(&state, &owner, NOW, "audit.report", bad);
        assert!(matches!(r, Err(OpError::Malformed(_))), "{r:?}");
    }

    // Edit a line of the log: the chain no longer verifies, and the report says so rather than hiding it.
    let log = v
        .paths()
        .audit_log(&credmgr_store::audit::year_month_for(NOW));
    let text = std::fs::read_to_string(&log).unwrap();
    std::fs::write(&log, text.replacen("s_a", "s_b", 1)).unwrap();
    let r = call(
        &state,
        &owner,
        NOW,
        "audit.report",
        json!({ "from": NOW, "to": NOW + 10 }),
    )
    .unwrap();
    assert_eq!(r["chain"]["verified"], false, "{r}");
}

#[allow(dead_code)]
fn _unused(_: PeerInfo) {}
