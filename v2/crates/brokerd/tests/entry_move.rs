//! ADR-158 — `entry.move`: an entry leaves one node and joins another, re-encrypted to the destination's key.
//!
//! * A move re-seals the value to the destination key; the source copy and its retained history are gone, the
//!   id and ref are kept, and nothing is left that the source key opens.
//! * A crash at every step of the commit protocol (`state/move_entry.rs`'s table) leaves a vault that unlocks,
//!   with the entry wholly in the source or wholly in the destination — never both, never neither. Each row is
//!   made to happen by stopping the real protocol there, dropping the broker and starting a fresh one.
//! * The op is the owner's: an agent is refused whatever its scope; a stale generation, the same node, the
//!   orphan, an unknown node and a name or alias already taken at the destination are refused and change
//!   nothing. Entry-level grants on the moved entry are revoked, never carried over. `entry.history` on the
//!   moved entry shows the move and the trail before it.

mod f1_support;

use std::time::Instant;

use serde_json::{json, Value};

use credmgr_brokerd::protocol::{OpError, Request};
use credmgr_brokerd::scope::BrokerScope;
use credmgr_brokerd::server;
use credmgr_brokerd::state::{BrokerState, MoveFault, PersistFault};
use credmgr_core::access::Origin;
use credmgr_core::envelope;
use credmgr_core::registry::{Capability, Direction, Grant, GrantTarget, GLOBAL_ID};

use f1_support::*;

/// `acme` (seeded: a rotated entry with history, a kept one, a note, a removed one) and an empty `beta`.
fn two_nodes() -> (
    Vault,
    std::sync::Arc<BrokerState>,
    BrokerScope,
    Seed,
    Signer,
) {
    let (v, state) = created_vault(None);
    let owner = login(&state);
    let seed = seed_acme(&state, &owner);
    create_node(&state, &owner, "beta");
    let key = enrol_first_key(&state, &owner);
    (v, state, owner, seed, key)
}

fn move_params(
    state: &BrokerState,
    owner: &BrokerScope,
    from: &str,
    entry: &str,
    to: &str,
) -> Value {
    json!({ "node": from, "entry": entry, "to": to, "generation": generation(state, owner, from) })
}

fn move_entry(
    state: &BrokerState,
    owner: &BrokerScope,
    key: &Signer,
    from: &str,
    entry: &str,
    to: &str,
) -> Result<Value, OpError> {
    let params = move_params(state, owner, from, entry, to);
    let proved = with_proof(state, owner, key, NOW, "entry.move", params);
    call(state, owner, NOW, "entry.move", proved)
}

fn names(state: &BrokerState, owner: &BrokerScope, node: &str) -> Vec<String> {
    call(state, owner, NOW, "entry.list", json!({ "node": node })).unwrap()["names"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n.as_str().unwrap().to_string())
        .collect()
}

fn hot_key(state: &BrokerState, node: &str) -> x25519_dalek::StaticSecret {
    x25519_dalek::StaticSecret::from(state.hot_key_bytes_for_test(node).expect("hot key"))
}

/// The entry lives in `at` and only there: its value reads back from `at`, the file opens with `at`'s key
/// under `at`'s id, the other node neither lists it nor holds a file for it, and the vault verifies.
fn assert_only_in(
    v: &Vault,
    state: &BrokerState,
    owner: &BrokerScope,
    entry: &str,
    value: &str,
    at: &str,
    not_at: &str,
) {
    assert_eq!(
        reveal(state, owner, at, entry),
        value,
        "it reads back from {at}"
    );
    let bytes = std::fs::read(v.paths().entry_env(at, entry)).expect("its file is in place");
    assert!(
        envelope::open_any(&bytes, &hot_key(state, at), at, entry).is_ok(),
        "it opens with {at}'s key"
    );
    assert!(
        envelope::open_any(&bytes, &hot_key(state, not_at), not_at, entry).is_err(),
        "{not_at}'s key does not open it"
    );
    let r = call(
        state,
        owner,
        NOW,
        "entry.reveal",
        json!({ "node": not_at, "entry": entry }),
    );
    assert!(
        matches!(r, Err(OpError::NotFound(_))),
        "{not_at} does not hold it: {r:?}"
    );
    assert!(
        !v.paths().entry_env(not_at, entry).exists(),
        "no file for it is left in {not_at}"
    );
    verify_ok(state, owner);
}

#[test]
fn a_move_re_seals_the_entry_to_the_destination_and_the_source_copy_is_gone() {
    let (v, state, owner, seed, key) = two_nodes();
    let old_ref = state.manifests.read().unwrap()["acme"]
        .entries
        .iter()
        .find(|e| e.id == seed.rotated)
        .unwrap()
        .r#ref;
    let acme_before = generation(&state, &owner, "acme");
    let beta_before = generation(&state, &owner, "beta");
    let history = v
        .paths()
        .entry_history_env("acme", &seed.rotated, seed.history_generation);
    assert!(
        history.exists(),
        "the seed rotated it, so it has retained history"
    );

    let done = move_entry(&state, &owner, &key, "acme", &seed.rotated, "beta").expect("move");
    assert_eq!(done["node"], "beta");
    assert_eq!(done["from"], "acme");
    assert_eq!(done["entry"], json!(seed.rotated), "the id is kept");
    assert_eq!(done["ref"], json!(old_ref), "the ref is kept");
    assert_eq!(done["name"], "database");
    assert_eq!(done["generation"].as_u64().unwrap(), acme_before + 1);
    assert_eq!(done["toGeneration"].as_u64().unwrap(), beta_before + 1);
    assert_eq!(done["grantsRevoked"], json!([]));
    assert_eq!(done["historyDropped"], json!(1));
    assert!(done.get("value").is_none() && !done.to_string().contains("alpha-2"));

    assert_only_in(&v, &state, &owner, &seed.rotated, "alpha-2", "beta", "acme");
    assert_eq!(names(&state, &owner, "beta"), vec!["database"]);
    assert!(!names(&state, &owner, "acme").contains(&"database".to_string()));
    assert!(
        !history.exists(),
        "the retained history went with the source copy"
    );
    assert!(
        !v.paths().move_stage(&seed.rotated).exists(),
        "the stage is removed"
    );
    // The rest of the source node is untouched.
    assert_eq!(reveal(&state, &owner, "acme", &seed.kept), "beta-2");

    // It survives a restart, and the expiry, ref and name travelled with the row.
    let (state, owner) = restart(&v, state, None);
    assert_only_in(&v, &state, &owner, &seed.rotated, "alpha-2", "beta", "acme");
    let by_ref = call(
        &state,
        &owner,
        NOW,
        "entry.get_by_ref",
        json!({ "reference": old_ref }),
    )
    .unwrap();
    assert_eq!(by_ref["node"], "beta");

    // And it can be moved back (the presence key is in the signed registry, so the same signer proves), and
    // edited where it now is with the generation the move answered.
    let back = move_entry(&state, &owner, &key, "beta", &seed.rotated, "acme").expect("back");
    assert_eq!(back["node"], "acme");
    assert_only_in(&v, &state, &owner, &seed.rotated, "alpha-2", "acme", "beta");
    call(
        &state,
        &owner,
        NOW,
        "entry.update",
        json!({ "node": "acme", "entry": seed.rotated, "value": "alpha-3",
                "generation": back["toGeneration"] }),
    )
    .expect("a write with the destination generation the move answered");
}

#[test]
fn the_expiry_and_aliases_travel_with_the_entry() {
    let (_v, state, owner, seed, key) = two_nodes();
    call(
        &state,
        &owner,
        NOW,
        "entry.set_expiry",
        json!({ "node": "acme", "entry": seed.kept, "generation": generation(&state, &owner, "acme"),
                "expiresAt": NOW + 86_400 }),
    )
    .unwrap();
    call(
        &state,
        &owner,
        NOW,
        "entry.alias",
        json!({ "node": "acme", "entry": seed.kept, "aliases": ["API_TOKEN"],
                "generation": generation(&state, &owner, "acme") }),
    )
    .expect("entry.alias");
    move_entry(&state, &owner, &key, "acme", &seed.kept, "beta").expect("move");
    let list = call(&state, &owner, NOW, "entry.list", json!({ "node": "beta" })).unwrap();
    assert_eq!(list["entries"][0]["expiresAt"], json!(NOW + 86_400));
    let found = call(
        &state,
        &owner,
        NOW,
        "entry.search",
        json!({ "node": "beta", "term": "API_TOKEN" }),
    )
    .unwrap();
    assert_eq!(
        found["results"][0]["id"],
        json!(seed.kept),
        "the alias answers at the destination"
    );
}

// ---- refusals -----------------------------------------------------------------------------------------

fn assert_unchanged(v: &Vault, state: &BrokerState, owner: &BrokerScope, seed: &Seed) {
    assert_eq!(reveal(state, owner, "acme", &seed.kept), "beta-2");
    assert!(names(state, owner, "beta").is_empty());
    assert!(!v.paths().entry_env("beta", &seed.kept).exists());
    assert!(!v.paths().move_stage_root().exists());
    verify_ok(state, owner);
}

#[test]
fn a_stale_generation_is_a_conflict_and_nothing_moves() {
    let (v, state, owner, seed, key) = two_nodes();
    let mut params = move_params(&state, &owner, "acme", &seed.kept, "beta");
    params["generation"] = json!(params["generation"].as_u64().unwrap() - 1);
    let proved = with_proof(&state, &owner, &key, NOW, "entry.move", params);
    let r = call(&state, &owner, NOW, "entry.move", proved);
    assert!(matches!(r, Err(OpError::Conflict { .. })), "{r:?}");
    assert_unchanged(&v, &state, &owner, &seed);
}

#[test]
fn an_agent_can_never_move_an_entry_whatever_its_scope() {
    let (v, state, owner, seed, key) = two_nodes();
    let params = move_params(&state, &owner, "acme", &seed.kept, "beta");
    // A cwd-scoped agent on acme with every capability, and one on global: neither is the owner.
    for node in ["acme", GLOBAL_ID] {
        let agent = BrokerScope {
            node_id: node.to_string(),
            capabilities: vec![
                Capability::List,
                Capability::Read,
                Capability::Reveal,
                Capability::Create,
                Capability::Update,
                Capability::Notes,
                Capability::Admin,
            ],
            origin: Origin::Agent,
            token_id: None,
            bound_workdir: None,
        };
        let r = call(&state, &agent, NOW, "entry.move", params.clone());
        assert!(
            matches!(
                r,
                Err(OpError::CapabilityNotHeld {
                    capability: Capability::Admin
                })
            ),
            "{node}: {r:?}"
        );
    }
    // Nor a scope that claims to be a person but holds no live login.
    let not_a_login = BrokerScope {
        node_id: GLOBAL_ID.to_string(),
        capabilities: vec![Capability::Admin, Capability::Update, Capability::Create],
        origin: Origin::HumanUi,
        token_id: None,
        bound_workdir: None,
    };
    let r = call(&state, &not_a_login, NOW, "entry.move", params.clone());
    assert!(matches!(r, Err(OpError::CapabilityNotHeld { .. })), "{r:?}");
    let _ = key;
    assert_unchanged(&v, &state, &owner, &seed);
}

#[test]
fn moving_into_the_same_node_the_orphan_or_a_node_that_does_not_exist_is_refused() {
    let (v, state, owner, seed, key) = two_nodes();
    for (to, want) in [
        ("acme", "malformed"),
        ("orphan", "malformed"),
        ("nowhere", "not_found"),
    ] {
        let r = move_entry(&state, &owner, &key, "acme", &seed.kept, to);
        match want {
            "malformed" => assert!(matches!(r, Err(OpError::Malformed(_))), "{to}: {r:?}"),
            _ => assert!(matches!(r, Err(OpError::NotFound(_))), "{to}: {r:?}"),
        }
    }
    // A sealed node is not a live node.
    create_node(&state, &owner, "gone");
    call(&state, &owner, NOW, "node.seal", json!({ "node": "gone" })).expect("seal");
    let r = move_entry(&state, &owner, &key, "acme", &seed.kept, "gone");
    assert!(matches!(r, Err(OpError::NotFound(_))), "{r:?}");
    // An entry the node does not hold.
    let r = move_entry(&state, &owner, &key, "acme", "e_000000000000", "beta");
    assert!(matches!(r, Err(OpError::NotFound(_))), "{r:?}");
    assert_unchanged(&v, &state, &owner, &seed);
}

#[test]
fn a_name_already_taken_at_the_destination_is_entry_exists() {
    let (v, state, owner, seed, key) = two_nodes();
    // The same name, typed differently (ADR-084 compares canonically).
    create_entry(&state, &owner, "beta", "API", "other");
    let r = move_entry(&state, &owner, &key, "acme", &seed.kept, "beta");
    assert!(
        matches!(&r, Err(OpError::EntryExists { node, name }) if node == "beta" && name == "api"),
        "{r:?}"
    );
    assert_eq!(reveal(&state, &owner, "acme", &seed.kept), "beta-2");
    assert!(!v.paths().entry_env("beta", &seed.kept).exists());
    assert!(!v.paths().move_stage_root().exists());
    verify_ok(&state, &owner);
}

#[test]
fn an_alias_the_entry_carries_that_is_taken_at_the_destination_is_entry_exists() {
    let (v, state, owner, seed, key) = two_nodes();
    call(
        &state,
        &owner,
        NOW,
        "entry.alias",
        json!({ "node": "acme", "entry": seed.kept, "aliases": ["API_TOKEN"],
                "generation": generation(&state, &owner, "acme") }),
    )
    .expect("entry.alias");
    create_entry(&state, &owner, "beta", "api_token", "other");
    let r = move_entry(&state, &owner, &key, "acme", &seed.kept, "beta");
    assert!(
        matches!(&r, Err(OpError::EntryExists { name, .. }) if name == "API_TOKEN"),
        "{r:?}"
    );
    assert_eq!(reveal(&state, &owner, "acme", &seed.kept), "beta-2");
    assert!(!v.paths().entry_env("beta", &seed.kept).exists());
    verify_ok(&state, &owner);
}

#[test]
fn a_move_costs_a_fresh_second_factor_and_a_presence_proof_every_time() {
    let (v, state, owner, seed, key) = two_nodes();
    let totp = enrol_gate(&state, &owner);
    let params = move_params(&state, &owner, "acme", &seed.kept, "beta");

    let r = call(&state, &owner, LATER, "entry.move", params.clone());
    assert!(matches!(r, Err(OpError::TwoFactorRequired { .. })), "{r:?}");
    step_up(&state, &owner, &totp, LATER);
    let r = call(&state, &owner, LATER, "entry.move", params.clone());
    assert!(matches!(r, Err(OpError::PresenceRequired { .. })), "{r:?}");

    // A proof made for another destination is not this move's.
    let mut elsewhere = params.clone();
    elsewhere["to"] = json!(GLOBAL_ID);
    let mut swapped = with_proof(&state, &owner, &key, LATER, "entry.move", elsewhere);
    swapped["to"] = json!("beta");
    assert!(matches!(
        call(&state, &owner, LATER, "entry.move", swapped),
        Err(OpError::PresenceFailed { .. })
    ));
    assert_unchanged(&v, &state, &owner, &seed);

    let proved = with_proof(&state, &owner, &key, LATER, "entry.move", params);
    call(&state, &owner, LATER, "entry.move", proved).expect("with the factor and the proof");
    assert_only_in(&v, &state, &owner, &seed.kept, "beta-2", "beta", "acme");
}

// ---- grants -------------------------------------------------------------------------------------------

#[test]
fn entry_grants_on_the_moved_entry_are_revoked_and_node_grants_stay() {
    let (v, state, owner, seed, key) = two_nodes();
    create_node(&state, &owner, "consumer");
    let grant = |id: &str, to: GrantTarget| Grant {
        id: id.to_string(),
        from: "consumer".to_string(),
        to,
        direction: Direction::OneWay,
        scope: vec![Capability::Read, Capability::Reveal],
        expires_at: None,
        reason: "test grant".to_string(),
    };
    {
        let mut registry = state.registry.write().unwrap();
        registry.grants.push(grant(
            "g_entry_moved",
            GrantTarget::Entry {
                node_id: "acme".into(),
                entry_id: seed.kept.clone(),
            },
        ));
        registry.grants.push(grant(
            "g_entry_other",
            GrantTarget::Entry {
                node_id: "acme".into(),
                entry_id: seed.rotated.clone(),
            },
        ));
        registry.grants.push(grant(
            "g_node",
            GrantTarget::Node {
                node_id: "acme".into(),
            },
        ));
    }
    state.persist(NOW).expect("persist the grants");

    let done = move_entry(&state, &owner, &key, "acme", &seed.kept, "beta").expect("move");
    assert_eq!(done["grantsRevoked"], json!(["g_entry_moved"]));
    let ids = |state: &BrokerState| -> Vec<String> {
        state
            .registry
            .read()
            .unwrap()
            .grants
            .iter()
            .map(|g| g.id.clone())
            .collect()
    };
    assert_eq!(ids(&state), vec!["g_entry_other", "g_node"]);
    // Nothing now names the entry at its new address: the grant was not carried to beta.
    assert!(!state
        .registry
        .read()
        .unwrap()
        .grants
        .iter()
        .any(|g| g.to.node_id() == "beta"));
    // The revocation was part of the commit: it is in the signed registry after a restart.
    let (state, _owner) = restart(&v, state, None);
    assert_eq!(ids(&state), vec!["g_entry_other", "g_node"]);
}

// ---- history ------------------------------------------------------------------------------------------

#[test]
fn entry_history_on_the_moved_entry_shows_the_move_and_the_trail_before_it() {
    let (_v, state) = created_vault(None);
    let token = call(
        &state,
        &anyone(),
        NOW,
        "vault.unlock",
        json!({ "passphrase": PASSPHRASE }),
    )
    .unwrap()["token"]
        .as_str()
        .unwrap()
        .to_string();
    let owner = scope_of(&state, &token);
    let send = |op: &str, params: Value| -> Result<Value, OpError> {
        let request = Request {
            id: "r".to_string(),
            op: op.to_string(),
            token: Some(token.clone()),
            params,
        };
        server::handle_request_at(&state, &peer(), &request, NOW, Instant::now()).0
    };
    for node in ["acme", "beta"] {
        send(
            "node.create",
            json!({ "id": node, "label": node, "parentId": GLOBAL_ID }),
        )
        .unwrap();
    }
    let entry = send(
        "entry.create",
        json!({ "node": "acme", "name": "KEY", "value": "v-1" }),
    )
    .unwrap()["entry"]
        .as_str()
        .unwrap()
        .to_string();
    let key = enrol_first_key(&state, &owner);
    let params = json!({ "node": "acme", "entry": entry, "to": "beta",
                         "generation": generation(&state, &owner, "acme"),
                         "reason": "doctor:plan-1" });
    let proved = with_proof(&state, &owner, &key, NOW, "entry.move", params);
    send("entry.move", proved).expect("move through the server");

    let h = send("entry.history", json!({ "node": "beta", "entry": entry })).unwrap();
    let rows = h["records"].as_array().unwrap();
    let seen: Vec<(String, String)> = rows
        .iter()
        .map(|r| {
            (
                r["action"].as_str().unwrap().to_string(),
                r["node"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    assert_eq!(
        seen,
        vec![
            ("entry.create".to_string(), "acme".to_string()),
            // The destination's record is written inside the op; the request's own record (the source's)
            // after it, as every request's is.
            ("entry.move".to_string(), "beta".to_string()),
            ("entry.move".to_string(), "acme".to_string()),
        ],
        "{h}"
    );
    assert!(rows.iter().all(|r| r["decision"] == "allow"));
    assert_eq!(h["exists"], true);
    assert_eq!(h["name"], "KEY");

    // One record in each node, read straight from the log: the source's carries the reason, the
    // destination's says where the entry came from.
    let log = call(&state, &owner, NOW, "audit.tail", json!({ "limit": 50 })).unwrap();
    let text = log.to_string();
    assert!(text.contains("doctor:plan-1"), "{text}");
    assert!(text.contains("moved from acme"), "{text}");
    assert!(!text.contains("v-1"), "no value is ever in the log");
}

// ---- the crash table ----------------------------------------------------------------------------------

/// `committed` says which side of the commit the crash is on.
fn crash_at(label: &str, arm: impl Fn(&BrokerState), committed: bool) {
    let (v, state, owner, seed, _key) = two_nodes();
    let g = generation(&state, &owner, "acme");
    arm(&state);
    let r = state.move_entry_durable("acme", &seed.rotated, "beta", g, NOW);
    assert!(
        r.is_err(),
        "{label}: the injected crash surfaces as an error: {r:?}"
    );
    assert!(
        v.paths()
            .move_stage(&seed.rotated)
            .join("plan.sealed")
            .exists(),
        "{label}: the crash left a stage with its plan for the next start to settle"
    );
    drop(owner);

    let (state, owner) = restart(&v, state, None);
    let history = v
        .paths()
        .entry_history_env("acme", &seed.rotated, seed.history_generation);
    if committed {
        assert_only_in(&v, &state, &owner, &seed.rotated, "alpha-2", "beta", "acme");
        assert!(!history.exists(), "{label}: the source's history went too");
    } else {
        assert_only_in(&v, &state, &owner, &seed.rotated, "alpha-2", "acme", "beta");
        assert!(history.exists(), "{label}: nothing was lost");
    }
    assert_eq!(reveal(&state, &owner, "acme", &seed.kept), "beta-2");
    assert!(
        !v.paths().move_stage(&seed.rotated).exists(),
        "{label}: the stage is settled and removed"
    );

    // A second restart changes nothing, and a move can be made again from here.
    let (state, owner) = restart(&v, state, None);
    let (from, to) = if committed {
        ("beta", "acme")
    } else {
        ("acme", "beta")
    };
    let g = generation(&state, &owner, from);
    state
        .move_entry_durable(from, &seed.rotated, to, g, NOW)
        .unwrap_or_else(|e| panic!("{label}: a move after recovery failed: {e:?}"));
    assert_only_in(&v, &state, &owner, &seed.rotated, "alpha-2", to, from);
}

#[test]
fn a_crash_after_the_stage_and_the_new_file_leaves_the_entry_where_it_was() {
    crash_at(
        "after stage",
        |s| s.set_move_fault_for_test(Some(MoveFault::AfterStage)),
        false,
    );
}

#[test]
fn a_crash_between_the_manifest_writes_and_the_registry_rolls_back() {
    // `skip 1`: the move writes the vault through once before it starts; the second persist is the commit.
    crash_at(
        "before registry",
        |s| s.set_persist_fault_after_for_test(1, Some(PersistFault::BeforeRegistry)),
        false,
    );
}

#[test]
fn a_crash_after_the_registry_landed_rolls_forward() {
    crash_at(
        "after registry, before counter",
        |s| s.set_persist_fault_after_for_test(1, Some(PersistFault::AfterRegistryBeforeCounter)),
        true,
    );
}

#[test]
fn a_crash_after_the_commit_before_the_source_copy_went_rolls_forward() {
    crash_at(
        "after commit",
        |s| s.set_move_fault_for_test(Some(MoveFault::AfterCommit)),
        true,
    );
}

#[test]
fn a_crash_with_only_one_manifest_written_never_leaves_two_copies() {
    // The write-through writes manifests before the registry, and the loader accepts a manifest one
    // generation ahead as an interrupted write. Put only the destination's new manifest on disk (the source's
    // still the old one) and the registry unchanged: without the stage this vault would open with the entry
    // in both nodes. The stage rolls both manifests back.
    let (v, state, owner, seed, _key) = two_nodes();
    let g = generation(&state, &owner, "acme");
    state.set_persist_fault_after_for_test(1, Some(PersistFault::BeforeRegistry));
    let acme_before = std::fs::read(v.paths().manifest("acme")).unwrap();
    assert!(state
        .move_entry_durable("acme", &seed.kept, "beta", g, NOW)
        .is_err());
    std::fs::write(v.paths().manifest("acme"), acme_before).unwrap();
    drop(owner);
    let (state, owner) = restart(&v, state, None);
    assert_only_in(&v, &state, &owner, &seed.kept, "beta-2", "acme", "beta");
}

#[test]
fn a_failed_commit_that_is_not_a_crash_rolls_back_in_the_same_process() {
    let (v, state, owner, seed, key) = two_nodes();
    state.set_persist_fault_after_for_test(1, Some(PersistFault::FailBeforeRegistry));
    let r = move_entry(&state, &owner, &key, "acme", &seed.kept, "beta");
    assert!(
        matches!(&r, Err(OpError::Internal(m)) if m.contains("rolled back")),
        "{r:?}"
    );
    assert_only_in(&v, &state, &owner, &seed.kept, "beta-2", "acme", "beta"); // no restart: memory is whole.
    assert!(!v.paths().move_stage(&seed.kept).exists());
    let (state, owner) = restart(&v, state, None);
    assert_only_in(&v, &state, &owner, &seed.kept, "beta-2", "acme", "beta");
    move_entry(&state, &owner, &key, "acme", &seed.kept, "beta").expect("and a later move works");
}

#[test]
fn a_stage_left_behind_is_a_warning_and_the_next_unlock_settles_it() {
    let (v, state, owner, seed, key) = two_nodes();
    state.set_move_fault_for_test(Some(MoveFault::StageLeftBehind));
    let done =
        move_entry(&state, &owner, &key, "acme", &seed.kept, "beta").expect("the move itself");
    assert!(
        done["cleanupWarning"]
            .as_str()
            .is_some_and(|w| w.contains("moved") && w.contains("next unlock")),
        "{done}"
    );
    assert!(v
        .paths()
        .move_stage(&seed.kept)
        .join("plan.sealed")
        .exists());
    // A later edit at the destination, then a restart: the stale stage must not roll anything back.
    call(
        &state,
        &owner,
        NOW,
        "entry.update",
        json!({ "node": "beta", "entry": seed.kept, "value": "beta-3",
                "generation": generation(&state, &owner, "beta") }),
    )
    .expect("a later edit");
    drop(owner);
    let (state, owner) = restart(&v, state, None);
    assert_only_in(&v, &state, &owner, &seed.kept, "beta-3", "beta", "acme");
    assert!(!v.paths().move_stage(&seed.kept).exists());
}

#[test]
fn a_tampered_plan_stops_the_vault_opening_rather_than_being_trusted() {
    let (v, state, owner, seed, _key) = two_nodes();
    let g = generation(&state, &owner, "acme");
    state.set_move_fault_for_test(Some(MoveFault::AfterCommit));
    assert!(state
        .move_entry_durable("acme", &seed.kept, "beta", g, NOW)
        .is_err());
    drop(owner);
    drop(state);
    let plan = v.paths().move_stage(&seed.kept).join("plan.sealed");
    let mut bytes = std::fs::read(&plan).unwrap();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0x01;
    std::fs::write(&plan, bytes).unwrap();
    let fresh = v.broker(None);
    let r = call(
        &fresh,
        &anyone(),
        NOW,
        "vault.unlock",
        json!({ "passphrase": PASSPHRASE }),
    );
    assert!(matches!(r, Err(OpError::Internal(_))), "{r:?}");
}
