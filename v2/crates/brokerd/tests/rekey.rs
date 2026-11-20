//! ADR-130 — `node.rekey`: replace a node's keypair and re-seal everything sealed to the old one.
//!
//! * A rekey changes the key and **every** file follows it: live entries, the note, retained history,
//!   removed entries; digests and signed records included. Nothing is left that only the old key opens.
//! * A crash at every step of the commit protocol (`state/rekey.rs`'s table) leaves a vault that unlocks,
//!   with the node either exactly as it was or completely re-keyed — each row is made to happen by
//!   stopping the real protocol there, dropping the broker and starting a fresh one over the same files.
//! * The op is the owner's, and costs a fresh second factor and a presence proof every time.

mod f1_support;

use serde_json::json;
use x25519_dalek::StaticSecret;

use credmgr_brokerd::protocol::OpError;
use credmgr_brokerd::scope::BrokerScope;
use credmgr_brokerd::state::{BrokerState, PersistFault, RekeyFault};
use credmgr_core::envelope;
use credmgr_core::registry::GLOBAL_ID;
use credmgr_store::{entry_archive, registry_file, rotation_history};

use f1_support::*;

fn registry_public(v: &Vault, node: &str) -> String {
    registry_file::load(&v.paths(), &root_key(v))
        .expect("the registry opens")
        .nodes[node]
        .public_key
        .clone()
}

fn opens_with(key: &StaticSecret, bytes: &[u8], node: &str, entry: &str) -> bool {
    envelope::open_any(bytes, key, node, entry).is_ok()
}

/// Every value, the note, and the removed entry's restore are still there, and every file is sealed to
/// the node's current key and described by a digest that matches it.
fn assert_acme_whole(v: &Vault, state: &BrokerState, owner: &BrokerScope, seed: &Seed) {
    assert_eq!(reveal(state, owner, "acme", &seed.rotated), "alpha-2");
    assert_eq!(reveal(state, owner, "acme", &seed.kept), "beta-2");
    let note =
        call(state, owner, NOW, "notes.read", json!({ "node": "acme" })).expect("notes.read");
    assert_eq!(note["markdown"], "the note");
    verify_ok(state, owner);

    let paths = v.paths();
    let rk = root_key(v);
    let key = state.hot_node_key("acme").expect("the node is unlocked");
    for (id, name) in [(&seed.rotated, "rotated"), (&seed.kept, "kept")] {
        let bytes = std::fs::read(paths.entry_env("acme", id)).unwrap();
        assert!(
            opens_with(&key, &bytes, "acme", id),
            "{name} entry opens with the current key"
        );
    }
    let note_bytes = std::fs::read(paths.notes_env("acme")).unwrap();
    assert!(
        opens_with(&key, &note_bytes, "acme", "notes"),
        "the note opens with the current key"
    );
    let hist =
        std::fs::read(paths.entry_history_env("acme", &seed.rotated, seed.history_generation))
            .unwrap();
    assert!(
        opens_with(&key, &hist, "acme", &seed.rotated),
        "retained history opens with the current key"
    );
    let snap = rotation_history::load(&paths, &rk, "acme", &seed.rotated, seed.history_generation)
        .expect("the history snapshot still verifies");
    assert_eq!(
        snap.sha256,
        sha256_hex(&hist),
        "the history snapshot describes the file now on disk"
    );
    let gone = std::fs::read(paths.removed_entry_env("acme", &seed.removed)).unwrap();
    assert!(
        opens_with(&key, &gone, "acme", &seed.removed),
        "the removed entry opens with the current key"
    );
    let record = entry_archive::peek(&paths, &rk, "acme", &seed.removed, NOW)
        .expect("the removal record verifies");
    assert_eq!(
        record.sha256,
        sha256_hex(&gone),
        "the removal record describes the file now on disk"
    );
}

fn rekey(state: &BrokerState, node: &str) -> Result<credmgr_brokerd::state::RekeyOutcome, OpError> {
    state.rekey_node_durable(node, NOW)
}

#[test]
fn a_rekey_changes_the_key_and_every_file_follows_it() {
    let (v, state) = created_vault(None);
    let owner = login(&state);
    let seed = seed_acme(&state, &owner);
    let old_public = registry_public(&v, "acme");
    let old_key = StaticSecret::from(state.hot_key_bytes_for_test("acme").expect("hot key"));
    let old_files: Vec<Vec<u8>> = [&seed.rotated, &seed.kept]
        .iter()
        .map(|id| std::fs::read(v.paths().entry_env("acme", id)).unwrap())
        .collect();

    let outcome = rekey(&state, "acme").expect("rekey");
    assert_eq!(
        (
            outcome.entries,
            outcome.note,
            outcome.history,
            outcome.removed
        ),
        (2, true, 1, 1)
    );
    let new_public = registry_public(&v, "acme");
    assert_ne!(new_public, old_public, "the registry names a new key");
    assert_eq!(outcome.public_key, new_public);
    assert_acme_whole(&v, &state, &owner, &seed);

    // Nothing is left that only the old key opens, and the old key opens nothing now.
    for (id, old) in [&seed.rotated, &seed.kept].iter().zip(&old_files) {
        let now_bytes = std::fs::read(v.paths().entry_env("acme", id)).unwrap();
        assert_ne!(&now_bytes, old, "the envelope was re-sealed");
        assert!(
            !opens_with(&old_key, &now_bytes, "acme", id),
            "the old key no longer opens it"
        );
    }
    assert!(
        !v.paths().rekey_stage("acme").exists(),
        "the stage is removed"
    );
    assert!(
        !v.paths().rekey_stage_root().exists()
            || std::fs::read_dir(v.paths().rekey_stage_root())
                .unwrap()
                .next()
                .is_none()
    );

    // And it survives a restart, including the removed entry's restore and the rotation's undo source.
    let (state, owner) = restart(&v, state, None);
    assert_acme_whole(&v, &state, &owner, &seed);
    call(
        &state,
        &owner,
        NOW,
        "entry.restore",
        json!({ "node": "acme", "entry": seed.removed, "generation": generation(&state, &owner, "acme") }),
    )
    .expect("a removed entry is still restorable after a rekey");
    assert_eq!(reveal(&state, &owner, "acme", &seed.removed), "gamma-3");
    verify_ok(&state, &owner);
}

#[test]
fn the_global_node_can_be_rekeyed_and_the_orphan_and_sealed_nodes_cannot() {
    let (v, state) = created_vault(None);
    let owner = login(&state);
    let in_global = create_entry(&state, &owner, GLOBAL_ID, "shared", "global-value");
    let before = registry_public(&v, GLOBAL_ID);
    rekey(&state, GLOBAL_ID).expect("rekey global");
    assert_ne!(registry_public(&v, GLOBAL_ID), before);
    assert_eq!(
        reveal(&state, &owner, GLOBAL_ID, &in_global),
        "global-value"
    );
    verify_ok(&state, &owner);

    assert!(matches!(
        rekey(&state, "orphan"),
        Err(OpError::Malformed(_))
    ));
    assert!(matches!(
        rekey(&state, "nowhere"),
        Err(OpError::Malformed(_) | OpError::NotFound(_))
    ));
    create_node(&state, &owner, "gone");
    call(&state, &owner, NOW, "node.seal", json!({ "node": "gone" })).expect("seal");
    assert!(
        matches!(rekey(&state, "gone"), Err(OpError::Malformed(_))),
        "a sealed node is not live"
    );
}

#[test]
fn writes_waiting_in_the_locked_write_tray_stop_a_rekey_and_nothing_changes() {
    let (v, state) = created_vault(None);
    let owner = login(&state);
    let seed = seed_acme(&state, &owner);
    state.add_pending(
        "acme",
        credmgr_brokerd::state::PendingEntry {
            id: "e_aaaaaaaaaaaa".into(),
            name: "waiting".into(),
            entry_type: credmgr_core::inference::EntryType::Other,
            sensitivity: credmgr_core::inference::Sensitivity::Low,
            field_count: 1,
            sha256: "0".repeat(64),
            created: NOW,
        },
    );
    let before = registry_public(&v, "acme");
    let r = rekey(&state, "acme");
    assert!(
        matches!(&r, Err(OpError::Malformed(m)) if m.contains("tray")),
        "{r:?}"
    );
    assert_eq!(registry_public(&v, "acme"), before);
    assert_acme_whole(&v, &state, &owner, &seed);
}

/// The crash table. `new` says which side of the commit the crash is on.
fn crash_at(label: &str, arm: impl Fn(&BrokerState), new: bool) {
    let (v, state) = created_vault(None);
    let owner = login(&state);
    let seed = seed_acme(&state, &owner);
    let before = registry_public(&v, "acme");

    arm(&state);
    let r = rekey(&state, "acme");
    assert!(
        r.is_err(),
        "{label}: the injected crash surfaces as an error: {r:?}"
    );
    assert!(
        v.paths().rekey_stage("acme").join("plan.sealed").exists(),
        "{label}: the crash left a stage with its plan for the next start to settle"
    );
    drop(owner);

    let (state, owner) = restart(&v, state, None);
    let after = registry_public(&v, "acme");
    if new {
        assert_ne!(
            after, before,
            "{label}: the commit happened, the node is re-keyed"
        );
    } else {
        assert_eq!(
            after, before,
            "{label}: the commit did not happen, the node is as it was"
        );
    }
    assert_acme_whole(&v, &state, &owner, &seed);
    assert!(
        !v.paths().rekey_stage("acme").exists(),
        "{label}: the stage is settled and removed"
    );

    // A second restart changes nothing, and a rekey can be done again from here.
    let (state, owner) = restart(&v, state, None);
    assert_acme_whole(&v, &state, &owner, &seed);
    rekey(&state, "acme")
        .unwrap_or_else(|e| panic!("{label}: a rekey after recovery failed: {e:?}"));
    assert_acme_whole(&v, &state, &owner, &seed);
}

#[test]
fn a_crash_after_the_stage_is_written_leaves_the_node_as_it_was() {
    crash_at(
        "after stage",
        |s| s.set_rekey_fault_for_test(Some(RekeyFault::AfterStage)),
        false,
    );
}

#[test]
fn a_crash_between_the_key_and_manifest_writes_and_the_registry_rolls_back() {
    // `skip 1`: the rekey writes the vault through once before it starts; the second persist is the commit.
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
fn a_crash_after_the_commit_before_any_install_rolls_forward() {
    crash_at(
        "after commit",
        |s| s.set_rekey_fault_for_test(Some(RekeyFault::AfterCommit)),
        true,
    );
}

#[test]
fn a_crash_after_the_first_file_was_installed_rolls_forward() {
    crash_at(
        "after first install",
        |s| s.set_rekey_fault_for_test(Some(RekeyFault::AfterFirstInstall)),
        true,
    );
}

#[test]
fn a_failed_commit_that_is_not_a_crash_rolls_back_in_the_same_process() {
    let (v, state) = created_vault(None);
    let owner = login(&state);
    let seed = seed_acme(&state, &owner);
    let before = registry_public(&v, "acme");
    state.set_persist_fault_after_for_test(1, Some(PersistFault::FailBeforeRegistry));
    let r = rekey(&state, "acme");
    assert!(
        matches!(&r, Err(OpError::Internal(m)) if m.contains("rolled back")),
        "{r:?}"
    );
    assert_eq!(registry_public(&v, "acme"), before);
    assert_acme_whole(&v, &state, &owner, &seed); // no restart: the live process is whole.
    assert!(!v.paths().rekey_stage("acme").exists());
    let (state, owner) = restart(&v, state, None);
    assert_acme_whole(&v, &state, &owner, &seed);
    rekey(&state, "acme").expect("and a later rekey works");
}

#[test]
fn a_tampered_plan_or_staged_file_stops_the_vault_opening_rather_than_being_trusted() {
    for tamper in ["plan", "file"] {
        let (v, state) = created_vault(None);
        let owner = login(&state);
        seed_acme(&state, &owner);
        state.set_rekey_fault_for_test(Some(RekeyFault::AfterCommit));
        assert!(rekey(&state, "acme").is_err());
        drop(owner);
        drop(state);

        let stage = v.paths().rekey_stage("acme");
        let victim = if tamper == "plan" {
            stage.join("plan.sealed")
        } else {
            stage.join("files").join("0")
        };
        let mut bytes = std::fs::read(&victim).unwrap();
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0x01;
        std::fs::write(&victim, bytes).unwrap();

        let fresh = v.broker(None);
        let r = call(
            &fresh,
            &anyone(),
            NOW,
            "vault.unlock",
            json!({ "passphrase": PASSPHRASE }),
        );
        assert!(matches!(r, Err(OpError::Internal(_))), "{tamper}: {r:?}");
    }
}

#[test]
fn rekey_costs_the_owner_a_fresh_second_factor_and_a_presence_proof_every_time() {
    let (v, state) = created_vault(None);
    let owner = login(&state);
    let seed = seed_acme(&state, &owner);
    let key = enrol_first_key(&state, &owner);
    let totp = enrol_gate(&state, &owner);
    let ask = json!({ "node": "acme" });

    // An agent is not the owner.
    let agent = anyone();
    assert!(call(&state, &agent, LATER, "node.rekey", ask.clone()).is_err());

    // The gate is enrolled and no step-up has been given: the second factor comes first.
    let r = call(&state, &owner, LATER, "node.rekey", ask.clone());
    assert!(matches!(r, Err(OpError::TwoFactorRequired { .. })), "{r:?}");
    step_up(&state, &owner, &totp, LATER);

    // The factor is fresh; the proof is not yet there.
    let r = call(&state, &owner, LATER, "node.rekey", ask.clone());
    assert!(matches!(r, Err(OpError::PresenceRequired { .. })), "{r:?}");

    // A proof made for another node is not this node's.
    let other = with_proof(
        &state,
        &owner,
        &key,
        LATER,
        "node.rekey",
        json!({ "node": "global" }),
    );
    let mut moved = other.clone();
    moved["node"] = json!("acme");
    assert!(matches!(
        call(&state, &owner, LATER, "node.rekey", moved),
        Err(OpError::PresenceFailed {
            reason: "invalid",
            ..
        })
    ));

    let before = registry_public(&v, "acme");
    let proved = with_proof(&state, &owner, &key, LATER, "node.rekey", ask.clone());
    let done =
        call(&state, &owner, LATER, "node.rekey", proved).expect("with the factor and the proof");
    assert_eq!(done["node"], "acme");
    assert_ne!(registry_public(&v, "acme"), before);
    assert_acme_whole(&v, &state, &owner, &seed);

    // The window did not survive: the next rekey asks for a code of its own.
    let again = with_proof(&state, &owner, &key, LATER, "node.rekey", ask.clone());
    let r = call(&state, &owner, LATER, "node.rekey", again);
    assert!(matches!(r, Err(OpError::TwoFactorRequired { .. })), "{r:?}");
}

// ---- ADR-148 §P2-3: a stage that outlives its rekey ------------------------------------------------------

#[test]
fn p2_3_a_crash_while_the_stage_is_being_removed_still_unlocks() {
    let (v, state) = created_vault(None);
    let owner = login(&state);
    let seed = seed_acme(&state, &owner);
    let before = registry_public(&v, "acme");
    state.set_rekey_fault_for_test(Some(RekeyFault::CleanupCutShort));
    assert!(rekey(&state, "acme").is_err());
    assert!(
        v.paths().rekey_stage("acme").join("plan.sealed").exists()
            && !v.paths().rekey_stage("acme").join("files").exists(),
        "the crash left a plan whose staged files are gone"
    );
    drop(owner);
    let (state, owner) = restart(&v, state, None);
    assert_ne!(
        registry_public(&v, "acme"),
        before,
        "the rekey had committed"
    );
    assert_acme_whole(&v, &state, &owner, &seed);
    assert!(!v.paths().rekey_stage("acme").exists());
}

#[test]
fn p2_3_a_stage_left_behind_never_overwrites_a_later_edit() {
    let (v, state) = created_vault(None);
    let owner = login(&state);
    let seed = seed_acme(&state, &owner);
    state.set_rekey_fault_for_test(Some(RekeyFault::StageLeftBehind));
    let done = rekey(&state, "acme").expect("the rekey itself succeeded");
    assert!(
        v.paths().rekey_stage("acme").join("plan.sealed").exists(),
        "its stage was left behind"
    );
    // ADR-148 addendum: a committed rekey whose cleanup failed answers success, with the failure said.
    assert!(
        done.cleanup_warning
            .as_deref()
            .is_some_and(|w| w.contains("re-keyed") && w.contains("next unlock")),
        "{:?}",
        done.cleanup_warning
    );
    // A later edit, then a restart: the stale stage must not put the staged bytes back.
    call(
        &state,
        &owner,
        NOW,
        "entry.update",
        json!({ "node": "acme", "entry": seed.kept, "value": "beta-3",
                "generation": generation(&state, &owner, "acme") }),
    )
    .expect("a later edit");
    call(
        &state,
        &owner,
        NOW,
        "notes.write",
        json!({ "node": "acme", "markdown": "a newer note", "generation": generation(&state, &owner, "acme") }),
    )
    .expect("a later note");
    drop(owner);
    let (state, owner) = restart(&v, state, None);
    assert_eq!(reveal(&state, &owner, "acme", &seed.kept), "beta-3");
    let note = call(&state, &owner, NOW, "notes.read", json!({ "node": "acme" })).unwrap();
    assert_eq!(note["markdown"], "a newer note");
    verify_ok(&state, &owner);
    assert!(!v.paths().rekey_stage("acme").exists());
}
