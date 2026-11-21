//! ADR-174 — two of the operator's decisions of 2026-11-20 that close ADR-165's open questions:
//!
//! * **N5-Q1, "Rotating the root key also replaces every project key."** `maintenance.rotate_root` re-keys
//!   every live node inside its own staged commit (`NodeKeys::Replace`, ADR-165 N5), as a passphrase change and
//!   a recovery already did. A byte-copy of the vault folder from before the rotation, plus the old root key
//!   (which the unchanged passphrase still opens from that copy), opens nothing written after it.
//! * **N5-Q2, "Sealed copies of removed projects are re-sealed to a new key on re-key."** The orphan's cold
//!   keypair is replaced even when it holds sealed copies, and those copies are re-sealed to the new cold key
//!   in the same staged commit; the human-only orphan reveal still opens them.
//!
//! A crash at any point of either leaves the vault on the old keys or on the new ones, never a mixture.

mod f1_support;

use std::path::Path;

use serde_json::json;

use credmgr_brokerd::state::{BrokerState, RotationFault, RotationOutcome};
use credmgr_core::registry::{GLOBAL_ID, ORPHAN_ID};

use f1_support::*;

fn copy_dir_all(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir_all(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).unwrap();
        }
    }
}

/// A byte-for-byte copy of `v` that no broker runs over.
fn cloned(v: &Vault) -> Vault {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault_dir = dir.path().join("vault");
    let state_dir = dir.path().join("state");
    copy_dir_all(&v.vault_dir, &vault_dir);
    copy_dir_all(&v.state_dir, &state_dir);
    Vault {
        vault_dir,
        state_dir,
        recovery_code: std::cell::RefCell::new(v.recovery_code.borrow().clone()),
        _dir: dir,
    }
}

/// The orphan's cold private key in a vault folder, opened under `root` (what an attacker with the folder and
/// the root key computes offline). `None` if it does not open.
fn cold_key_from_folder(vault: &Vault, root: &[u8; 32]) -> Option<x25519_dalek::StaticSecret> {
    let bytes = std::fs::read(vault.paths().orphan_key()).ok()?;
    credmgr_core::cold::open_orphan_cold(root, &bytes, None).ok()
}

/// A project `globex` with one entry, sealed: its entry is now a sealed copy in the orphan node. Returns the
/// copy's entry id (the orphan row id).
fn seal_globex(state: &BrokerState, owner: &credmgr_brokerd::scope::BrokerScope) -> String {
    create_node(state, owner, "globex");
    let entry = create_entry(state, owner, "globex", "G1", "globex-sealed-value");
    call(state, owner, NOW, "node.seal", json!({ "node": "globex" })).expect("node.seal");
    let rows = call(state, owner, NOW, "orphan.list", json!({})).expect("orphan.list");
    assert_eq!(rows["entries"].as_array().unwrap().len(), 1, "{rows}");
    assert_eq!(rows["entries"][0]["entry"], json!(entry));
    entry
}

/// The human-only reveal of a sealed copy: the owner's login and a presence proof for this exact request.
fn orphan_reveal(
    state: &BrokerState,
    owner: &credmgr_brokerd::scope::BrokerScope,
    key: &Signer,
    entry: &str,
) -> String {
    let proved = with_proof(
        state,
        owner,
        key,
        NOW,
        "orphan.reveal",
        json!({ "entry": entry }),
    );
    call(state, owner, NOW, "orphan.reveal", proved).expect("orphan.reveal")["value"]
        .as_str()
        .unwrap()
        .to_string()
}

fn rotate(state: &BrokerState) -> Result<RotationOutcome, credmgr_brokerd::state::RotateRootError> {
    state.rotate_root(
        secrecy::SecretBox::new(Box::new(PASSPHRASE.to_string())),
        NOW + 1,
    )
}

/// N5-Q1, the attack replayed. The passphrase does not change in a rotation, so the attacker who holds a copy
/// of the folder from before it and the passphrase computes the OLD root key from the copy, then the old node
/// keys; nothing written after the rotation opens with them, nor does any live envelope (each was re-sealed),
/// and the old root opens no live node key. The wire answers which nodes were re-keyed.
#[test]
fn a_copy_from_before_a_root_rotation_plus_its_root_key_opens_nothing_written_after_it() {
    let (v, state) = created_vault(None);
    let owner = login(&state);
    let seed = seed_acme(&state, &owner);
    let in_global = create_entry(&state, &owner, GLOBAL_ID, "SHARED", "global-before");
    let key = enrol_first_key(&state, &owner);

    let pre = cloned(&v);
    let old_root = root_from_folder(&pre.vault_dir, PASSPHRASE).expect("the old wrap opens");
    let old_acme = node_key_from_folder(&pre.vault_dir, &old_root, "acme").expect("old acme key");
    let old_global =
        node_key_from_folder(&pre.vault_dir, &old_root, GLOBAL_ID).expect("old global key");

    let ask = json!({ "passphrase": PASSPHRASE });
    let proved = with_proof(&state, &owner, &key, NOW, "maintenance.rotate_root", ask);
    let rotated =
        call(&state, &owner, NOW, "maintenance.rotate_root", proved).expect("the rotation");
    assert_eq!(rotated["completionPending"], json!(false));
    assert_eq!(
        rotated["nodesRekeyed"],
        json!(["acme", "global"]),
        "{rotated}"
    );
    // Two live entries, the note, one history slot, one removed entry, one in global.
    assert!(rotated["filesResealed"].as_u64().unwrap() >= 6, "{rotated}");
    assert_eq!(rotated["notResigned"], json!([]), "{rotated}");

    let owner = login(&state);
    let after = create_entry(
        &state,
        &owner,
        "acme",
        "AFTER",
        "written-after-the-rotation",
    );
    let after_global = create_entry(&state, &owner, GLOBAL_ID, "AFTER_G", "global-after");

    // 1. The copy's root key: the live folder no longer yields it, and it opens no live node key.
    let new_root = root_from_folder(&v.vault_dir, PASSPHRASE).expect("the new wrap opens");
    assert_ne!(new_root, old_root);
    assert!(node_key_from_folder(&v.vault_dir, &old_root, "acme").is_none());
    assert!(node_key_from_folder(&v.vault_dir, &old_root, GLOBAL_ID).is_none());
    // 2. The old node keys open nothing written after the rotation, and no live envelope from before it.
    let paths = v.paths();
    assert!(!key_opens(
        &old_acme,
        &paths.entry_env("acme", &after),
        "acme",
        &after
    ));
    assert!(!key_opens(
        &old_global,
        &paths.entry_env(GLOBAL_ID, &after_global),
        GLOBAL_ID,
        &after_global
    ));
    for id in [&seed.rotated, &seed.kept] {
        assert!(!key_opens(
            &old_acme,
            &paths.entry_env("acme", id),
            "acme",
            id
        ));
    }
    assert!(!key_opens(
        &old_global,
        &paths.entry_env(GLOBAL_ID, &in_global),
        GLOBAL_ID,
        &in_global
    ));
    assert!(!key_opens(
        &old_acme,
        &paths.notes_env("acme"),
        "acme",
        "notes"
    ));
    assert!(!key_opens(
        &old_acme,
        &paths.entry_history_env("acme", &seed.rotated, seed.history_generation),
        "acme",
        &seed.rotated
    ));
    assert!(!key_opens(
        &old_acme,
        &paths.removed_entry_env("acme", &seed.removed),
        "acme",
        &seed.removed
    ));
    // What the copy held before the rotation it still opens (inherent, and said in the ADR).
    assert!(key_opens(
        &old_acme,
        &pre.paths().entry_env("acme", &seed.kept),
        "acme",
        &seed.kept
    ));

    // 3. Everything still reads, on the running broker and after a restart; a removed entry still restores.
    let check = |state: &BrokerState, owner: &credmgr_brokerd::scope::BrokerScope| {
        assert_eq!(reveal(state, owner, "acme", &seed.rotated), "alpha-2");
        assert_eq!(reveal(state, owner, "acme", &seed.kept), "beta-2");
        assert_eq!(
            reveal(state, owner, "acme", &after),
            "written-after-the-rotation"
        );
        assert_eq!(reveal(state, owner, GLOBAL_ID, &in_global), "global-before");
        let note =
            call(state, owner, NOW, "notes.read", json!({ "node": "acme" })).expect("notes.read");
        assert_eq!(note["markdown"], "the note");
        verify_ok(state, owner);
    };
    check(&state, &owner);
    drop(state);
    let fresh = v.broker(None);
    let owner = login(&fresh);
    check(&fresh, &owner);
    call(
        &fresh,
        &owner,
        NOW,
        "entry.restore",
        json!({ "node": "acme", "entry": seed.removed, "generation": generation(&fresh, &owner, "acme") }),
    )
    .expect("a removed entry restores after the rotation");
    assert_eq!(reveal(&fresh, &owner, "acme", &seed.removed), "gamma-3");
    verify_ok(&fresh, &owner);
}

/// N5-Q1: a crash at every point of a re-keying root rotation — every staging cut, before the commit, right
/// after it, and after every file the roll-forward moves — ends in the old state (the old root key, every live
/// envelope still opening with the OLD node key) or the new one (a new root key, no live envelope opening with
/// the old key), never a mixture and never a vault that will not open.
#[test]
fn a_crash_anywhere_in_a_rekeying_rotation_leaves_the_old_keys_or_the_new_ones() {
    let (v, state) = created_vault(None);
    let owner = login(&state);
    let seed = seed_acme(&state, &owner);
    // N5-Q2: a sealed copy in the orphan, followed through every cut too.
    let copy = seal_globex(&state, &owner);
    let key = enrol_first_key(&state, &owner);
    drop(state);
    let old_root = root_from_folder(&v.vault_dir, PASSPHRASE).unwrap();
    let old_acme = node_key_from_folder(&v.vault_dir, &old_root, "acme").unwrap();
    let old_cold = cold_key_from_folder(&v, &old_root).unwrap();
    let copy_on_old_key = |vault: &Vault| {
        key_opens(
            &old_cold,
            &vault.paths().entry_env(ORPHAN_ID, &copy),
            ORPHAN_ID,
            &copy,
        )
    };

    let files = {
        let dry = cloned(&v);
        let state = dry.broker(None);
        login(&state);
        let outcome = rotate(&state).expect("a dry run");
        assert_eq!(outcome.nodes_rekeyed.as_ref().map(Vec::len), Some(2));
        assert!(outcome.orphan_key_replaced);
        outcome.files_replaced
    };

    let on_old_key = |vault: &Vault| -> Vec<bool> {
        let p = vault.paths();
        vec![
            key_opens(
                &old_acme,
                &p.entry_env("acme", &seed.rotated),
                "acme",
                &seed.rotated,
            ),
            key_opens(
                &old_acme,
                &p.entry_env("acme", &seed.kept),
                "acme",
                &seed.kept,
            ),
            key_opens(&old_acme, &p.notes_env("acme"), "acme", "notes"),
            key_opens(
                &old_acme,
                &p.entry_history_env("acme", &seed.rotated, seed.history_generation),
                "acme",
                &seed.rotated,
            ),
            key_opens(
                &old_acme,
                &p.removed_entry_env("acme", &seed.removed),
                "acme",
                &seed.removed,
            ),
        ]
    };
    let opens = |vault: &Vault, why: &str| {
        let fresh = vault.broker(None);
        let owner = login(&fresh);
        assert_eq!(
            reveal(&fresh, &owner, "acme", &seed.kept),
            "beta-2",
            "{why}"
        );
        assert_eq!(
            reveal(&fresh, &owner, "acme", &seed.rotated),
            "alpha-2",
            "{why}"
        );
        assert_eq!(
            orphan_reveal(&fresh, &owner, &key, &copy),
            "globex-sealed-value",
            "{why}: the sealed copy reveals"
        );
        assert!(
            fresh.orphan_digest_mismatches().unwrap().is_empty(),
            "{why}"
        );
        verify_ok(&fresh, &owner);
        assert!(!vault.paths().rotation_stage().exists(), "{why}");
    };
    let assert_old = |vault: &Vault, why: &str| {
        opens(vault, why);
        assert_eq!(
            root_from_folder(&vault.vault_dir, PASSPHRASE),
            Some(old_root),
            "{why}"
        );
        assert!(
            on_old_key(vault).iter().all(|o| *o),
            "{why}: every file on the old key"
        );
        assert!(
            copy_on_old_key(vault),
            "{why}: the sealed copy on the old cold key"
        );
    };
    let assert_new = |vault: &Vault, why: &str| {
        opens(vault, why);
        assert_ne!(
            root_from_folder(&vault.vault_dir, PASSPHRASE),
            Some(old_root),
            "{why}"
        );
        assert!(
            node_key_from_folder(&vault.vault_dir, &old_root, "acme").is_none(),
            "{why}"
        );
        assert!(
            on_old_key(vault).iter().all(|o| !*o),
            "{why}: no file on the old key"
        );
        assert!(
            !copy_on_old_key(vault),
            "{why}: the sealed copy on the new cold key"
        );
        assert!(cold_key_from_folder(vault, &old_root).is_none(), "{why}");
    };
    let crash = |fault: RotationFault| -> Vault {
        let vault = cloned(&v);
        let state = vault.broker(None);
        login(&state);
        state.set_rotation_fault_for_test(Some(fault));
        assert!(rotate(&state).is_err());
        drop(state);
        vault
    };

    for staged in 0..files {
        assert_old(
            &crash(RotationFault::DuringStaging(staged)),
            &format!("staging cut {staged}"),
        );
    }
    assert_old(&crash(RotationFault::BeforeCommit), "before the commit");
    assert_new(&crash(RotationFault::AfterCommit), "right after the commit");
    for cut in 0..=files {
        assert_new(
            &crash(RotationFault::DuringRollForward(cut)),
            &format!("roll-forward cut {cut}"),
        );
    }
}

/// N5-Q2: the orphan's cold key is replaced even though it holds sealed copies, which are re-sealed to the new
/// key in the same commit: the old cold key (from a copy of the folder made before) opens none of them, the new
/// one opens every one, the human-only reveal still gives the value (before and after a restart), the sealed
/// project still restores inside its window, and a passphrase change does the same.
#[test]
fn sealed_copies_are_resealed_to_a_new_orphan_key_and_still_reveal_and_restore() {
    let (v, state) = created_vault(None);
    let owner = login(&state);
    create_node(&state, &owner, "acme");
    let live = create_entry(&state, &owner, "acme", "LIVE", "live-value");
    let copy = seal_globex(&state, &owner);
    let key = enrol_first_key(&state, &owner);
    assert_eq!(
        orphan_reveal(&state, &owner, &key, &copy),
        "globex-sealed-value"
    );

    let pre = cloned(&v);
    let old_root = root_from_folder(&pre.vault_dir, PASSPHRASE).unwrap();
    let old_cold = cold_key_from_folder(&pre, &old_root).expect("the old cold key");
    let old_public =
        credmgr_core::cold::parse_header(&std::fs::read(pre.paths().orphan_key()).unwrap())
            .unwrap()
            .public;

    let ask = json!({ "passphrase": PASSPHRASE });
    let proved = with_proof(&state, &owner, &key, NOW, "maintenance.rotate_root", ask);
    let rotated =
        call(&state, &owner, NOW, "maintenance.rotate_root", proved).expect("the rotation");
    assert_eq!(
        rotated["notResigned"],
        json!([]),
        "nothing is kept or left: {rotated}"
    );
    // acme's entry, global's nothing, and the sealed copy.
    assert!(rotated["filesResealed"].as_u64().unwrap() >= 2, "{rotated}");

    let owner = login(&state);
    let paths = v.paths();
    let new_root = root_from_folder(&v.vault_dir, PASSPHRASE).unwrap();
    let new_cold =
        cold_key_from_folder(&v, &new_root).expect("the new cold key opens under the new root");
    let new_public = credmgr_core::cold::parse_header(&std::fs::read(paths.orphan_key()).unwrap())
        .unwrap()
        .public;
    assert_ne!(new_public, old_public, "a new orphan keypair");
    assert_eq!(
        state.node_public_key(ORPHAN_ID),
        Some(new_public),
        "memory names the new key"
    );
    let copy_path = paths.entry_env(ORPHAN_ID, &copy);
    assert!(
        !key_opens(&old_cold, &copy_path, ORPHAN_ID, &copy),
        "the old cold key opens no copy"
    );
    assert!(
        key_opens(&new_cold, &copy_path, ORPHAN_ID, &copy),
        "the new one does"
    );
    // The copy from before still opens its own copy with its own key (inherent).
    assert!(key_opens(
        &old_cold,
        &pre.paths().entry_env(ORPHAN_ID, &copy),
        ORPHAN_ID,
        &copy
    ));
    assert!(state.orphan_digest_mismatches().unwrap().is_empty());

    // The reveal, the listing and a clean verify, on the running broker and after a restart.
    let check = |state: &BrokerState, owner: &credmgr_brokerd::scope::BrokerScope| {
        assert_eq!(
            orphan_reveal(state, owner, &key, &copy),
            "globex-sealed-value"
        );
        let rows = call(state, owner, NOW, "orphan.list", json!({})).expect("orphan.list");
        assert_eq!(rows["entries"][0]["entry"], json!(copy));
        assert_eq!(reveal(state, owner, "acme", &live), "live-value");
        verify_ok(state, owner);
    };
    check(&state, &owner);
    drop(state);
    let fresh = v.broker(None);
    let owner = login(&fresh);
    check(&fresh, &owner);

    // A passphrase change replaces the cold key again, and the copy follows it.
    let before_change = std::fs::read(paths.orphan_key()).unwrap();
    let changed = fresh
        .set_passphrase(
            secrecy::SecretBox::new(Box::new(PASSPHRASE.to_string())),
            secrecy::SecretBox::new(Box::new("another passphrase for the vault".to_string())),
            NOW + 2,
        )
        .expect("the passphrase change");
    assert!(changed.orphan_key_replaced);
    assert!(changed.skipped.is_empty(), "{:?}", changed.skipped);
    assert!(!key_opens(&new_cold, &copy_path, ORPHAN_ID, &copy));
    assert_ne!(std::fs::read(paths.orphan_key()).unwrap(), before_change);
    drop(fresh);
    let fresh = v.broker(None);
    let owner = match call(
        &fresh,
        &anyone(),
        NOW,
        "vault.unlock",
        json!({ "passphrase": "another passphrase for the vault" }),
    ) {
        Ok(v) => scope_of(&fresh, v["token"].as_str().expect("a login token")),
        Err(e) => panic!("unlock with the new passphrase: {e:?}"),
    };
    assert_eq!(
        orphan_reveal(&fresh, &owner, &key, &copy),
        "globex-sealed-value"
    );

    // The sealed project still comes back inside its window, and its entry reads.
    call(
        &fresh,
        &owner,
        NOW + 3,
        "node.restore",
        json!({ "node": "globex" }),
    )
    .expect("the sealed project restores after the re-keys");
    let ids = call(
        &fresh,
        &owner,
        NOW + 3,
        "entry.list",
        json!({ "node": "globex" }),
    )
    .unwrap();
    let back = ids["ids"][0].as_str().unwrap().to_string();
    assert_eq!(
        reveal(&fresh, &owner, "globex", &back),
        "globex-sealed-value"
    );
    let rows = call(&fresh, &owner, NOW + 3, "orphan.list", json!({})).unwrap();
    assert!(
        rows["entries"].as_array().unwrap().is_empty(),
        "the restore took its copy back"
    );
    verify_ok(&fresh, &owner);
}
