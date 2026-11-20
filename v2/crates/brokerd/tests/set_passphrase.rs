//! ADR-156 — `vault.set_passphrase`: changing the vault passphrase.
//!
//! The change is a root rotation (ADR-076) whose new passphrase wrap is made from the new passphrase, so this
//! file proves what is new and leans on `rotate_root.rs` for the rotation itself:
//!
//! * after a change the new passphrase opens the vault — on a restarted broker too — and the old one does not;
//!   every entry still reads back, `maintenance.verify` is clean, and a new recovery code is answered once;
//! * a wrong current passphrase, an empty or identical new one, an agent, a missing second factor and a
//!   missing presence proof (when a presence key is enrolled) are each refused, and a refusal changes nothing
//!   on disk;
//! * with no presence key enrolled the current passphrase is enough (a Mac without Touch ID, a Linux machine);
//! * a crash before the commit leaves the OLD passphrase in force; a crash at any point after it leaves the
//!   NEW one in force once the next unlock has finished the move;
//! * through the real request path the call shares the unlock backoff, and its audit record carries neither
//!   passphrase.

mod f1_support;

use std::path::Path;
use std::sync::Arc;

use serde_json::json;

use credmgr_brokerd::protocol::{OpError, Request};
use credmgr_brokerd::server;
use credmgr_brokerd::state::{BrokerState, RotationFault};
use credmgr_core::access::Origin;

use f1_support::*;

const NEW_PASSPHRASE: &str = "a brand new passphrase for the vault";

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

fn unlock_with(state: &BrokerState, passphrase: &str) -> Result<serde_json::Value, OpError> {
    call(
        state,
        &anyone(),
        NOW,
        "vault.unlock",
        json!({ "passphrase": passphrase }),
    )
}

fn login_with(state: &BrokerState, passphrase: &str) -> credmgr_brokerd::scope::BrokerScope {
    let token = unlock_with(state, passphrase).expect("unlock")["token"]
        .as_str()
        .unwrap()
        .to_string();
    scope_of(state, &token)
}

/// The vault's passphrase-side files, to prove a refusal changed nothing.
fn wraps(v: &Vault) -> (Vec<u8>, Vec<u8>) {
    (
        std::fs::read(v.paths().root_wrap_pass()).unwrap(),
        std::fs::read(v.paths().root_wrap_recovery()).unwrap(),
    )
}

/// A vault with a node and an entry, logged in.
fn populated() -> (Vault, Arc<BrokerState>, String) {
    let (v, state) = created_vault(None);
    let owner = login(&state);
    create_node(&state, &owner, "acme");
    let entry = create_entry(&state, &owner, "acme", "API_KEY", "alpha-secret");
    (v, state, entry)
}

#[test]
fn the_new_passphrase_opens_the_vault_and_the_old_one_does_not() {
    let (v, state, entry) = populated();
    let owner = login(&state);
    let old_code = v.recovery_code.borrow().clone();

    let changed = call(
        &state,
        &owner,
        NOW,
        "vault.set_passphrase",
        json!({ "passphrase": PASSPHRASE, "newPassphrase": NEW_PASSPHRASE }),
    )
    .expect("vault.set_passphrase");
    assert_eq!(changed["passphraseChanged"], json!(true));
    assert_eq!(changed["rotated"], json!(true));
    assert_eq!(changed["completionPending"], json!(false));
    let new_code = changed["recoveryCode"]
        .as_str()
        .expect("a new recovery code");
    assert_ne!(new_code, old_code);
    // Nothing else secret in the answer.
    let text = changed.to_string();
    assert!(!text.contains(PASSPHRASE) && !text.contains(NEW_PASSPHRASE));

    // The running broker: the old passphrase is refused, the new one opens it.
    state.lock();
    assert_eq!(
        unlock_with(&state, PASSPHRASE),
        Err(OpError::WrongPassphrase)
    );
    let owner = login_with(&state, NEW_PASSPHRASE);
    assert_eq!(reveal(&state, &owner, "acme", &entry), "alpha-secret");

    // A restart: the same, from the files alone.
    drop(state);
    let fresh = v.broker(None);
    assert_eq!(
        unlock_with(&fresh, PASSPHRASE),
        Err(OpError::WrongPassphrase)
    );
    let owner = login_with(&fresh, NEW_PASSPHRASE);
    assert_eq!(reveal(&fresh, &owner, "acme", &entry), "alpha-secret");
    verify_ok(&fresh, &owner);

    // The old recovery code is dead with the old root key; the new one works with the new passphrase.
    assert!(call(
        &fresh,
        &anyone(),
        NOW,
        "vault.gate_recover",
        json!({ "passphrase": NEW_PASSPHRASE, "recoveryCode": old_code }),
    )
    .is_err());
    call(
        &fresh,
        &anyone(),
        NOW,
        "vault.gate_recover",
        json!({ "passphrase": NEW_PASSPHRASE, "recoveryCode": new_code }),
    )
    .expect("the new recovery code with the new passphrase");

    // And it can be changed again, back to the first one.
    let owner = login_with(&fresh, NEW_PASSPHRASE);
    call(
        &fresh,
        &owner,
        NOW,
        "vault.set_passphrase",
        json!({ "passphrase": NEW_PASSPHRASE, "newPassphrase": PASSPHRASE }),
    )
    .expect("a second change");
    fresh.lock();
    login_with(&fresh, PASSPHRASE);
}

#[test]
fn every_refusal_changes_nothing() {
    let (v, state, _) = populated();
    let owner = login(&state);
    let before = wraps(&v);
    let set = |scope: &credmgr_brokerd::scope::BrokerScope, params: serde_json::Value| {
        call(&state, scope, NOW, "vault.set_passphrase", params)
    };

    // Malformed, before any authorisation.
    assert!(matches!(set(&owner, json!({})), Err(OpError::Malformed(_))));
    assert!(matches!(
        set(&owner, json!({ "passphrase": PASSPHRASE })),
        Err(OpError::Malformed(_))
    ));
    assert!(matches!(
        set(
            &owner,
            json!({ "passphrase": PASSPHRASE, "newPassphrase": "" })
        ),
        Err(OpError::Malformed(_))
    ));
    assert!(matches!(
        set(
            &owner,
            json!({ "passphrase": PASSPHRASE, "newPassphrase": "x".repeat(1025) })
        ),
        Err(OpError::Malformed(_))
    ));
    // The same passphrase again: refused, not rotated.
    assert!(matches!(
        set(
            &owner,
            json!({ "passphrase": PASSPHRASE, "newPassphrase": PASSPHRASE })
        ),
        Err(OpError::Malformed(_))
    ));
    // An agent never, even one holding Admin.
    let mut agent = owner.clone();
    agent.origin = Origin::Agent;
    agent.token_id = None;
    assert!(matches!(
        set(
            &agent,
            json!({ "passphrase": PASSPHRASE, "newPassphrase": NEW_PASSPHRASE })
        ),
        Err(OpError::CapabilityNotHeld { .. })
    ));
    assert!(matches!(
        set(
            &anyone(),
            json!({ "passphrase": PASSPHRASE, "newPassphrase": NEW_PASSPHRASE })
        ),
        Err(OpError::CapabilityNotHeld { .. })
    ));
    // A wrong current passphrase.
    assert_eq!(
        set(
            &owner,
            json!({ "passphrase": "not the passphrase", "newPassphrase": NEW_PASSPHRASE })
        ),
        Err(OpError::WrongPassphrase)
    );
    assert_eq!(wraps(&v), before, "no refusal touched the root wraps");
    assert!(!v.paths().rotation_stage().exists());

    // A locked vault.
    state.lock();
    assert!(set(
        &owner,
        json!({ "passphrase": PASSPHRASE, "newPassphrase": NEW_PASSPHRASE })
    )
    .is_err());
    assert_eq!(wraps(&v), before);
    login(&state);
}

#[test]
fn a_second_factor_and_an_enrolled_presence_key_are_each_required() {
    let (v, state, _) = populated();
    let owner = login(&state);
    let before = wraps(&v);
    let params = json!({ "passphrase": PASSPHRASE, "newPassphrase": NEW_PASSPHRASE });

    // A presence key enrolled: a proof is required, and a proof for another op does not do.
    let key = enrol_first_key(&state, &owner);
    assert_eq!(
        call(&state, &owner, NOW, "vault.set_passphrase", params.clone()),
        Err(OpError::PresenceRequired {
            operation: "vault.set_passphrase".to_string()
        })
    );
    let wrong_op = with_proof(
        &state,
        &owner,
        &key,
        NOW,
        "maintenance.rotate_root",
        params.clone(),
    );
    assert!(matches!(
        call(&state, &owner, NOW, "vault.set_passphrase", wrong_op),
        Err(OpError::PresenceFailed { .. })
    ));
    assert_eq!(wraps(&v), before);

    // A second factor enrolled and not fresh: it comes before presence.
    let totp = enrol_gate(&state, &owner);
    let later = NOW + 600;
    assert!(matches!(
        call(
            &state,
            &owner,
            later,
            "vault.set_passphrase",
            params.clone()
        ),
        Err(OpError::TwoFactorRequired { .. })
    ));
    assert_eq!(wraps(&v), before);

    // Both given: it changes.
    step_up(&state, &owner, &totp, later);
    let proved = with_proof(
        &state,
        &owner,
        &key,
        later,
        "vault.set_passphrase",
        params.clone(),
    );
    call(&state, &owner, later, "vault.set_passphrase", proved).expect("with both factors");
    let fresh = v.broker(None);
    assert_eq!(
        unlock_with(&fresh, PASSPHRASE),
        Err(OpError::WrongPassphrase)
    );
    // The new passphrase is accepted, and the enrolled second factor still stands behind it.
    let opened = unlock_with(&fresh, NEW_PASSPHRASE);
    assert!(
        matches!(opened, Err(OpError::TwoFactorRequired { .. })),
        "the new passphrase passes, then the second factor is asked for: {opened:?}"
    );
}

#[test]
fn a_crash_before_the_commit_keeps_the_old_passphrase() {
    let (v, state, entry) = populated();
    login(&state);
    state.set_rotation_fault_for_test(Some(RotationFault::BeforeCommit));
    assert!(state
        .set_passphrase(
            secrecy::SecretBox::new(Box::new(PASSPHRASE.to_string())),
            secrecy::SecretBox::new(Box::new(NEW_PASSPHRASE.to_string())),
            NOW + 1,
        )
        .is_err());
    drop(state);

    let fresh = v.broker(None);
    assert_eq!(
        unlock_with(&fresh, NEW_PASSPHRASE),
        Err(OpError::WrongPassphrase)
    );
    let owner = login_with(&fresh, PASSPHRASE);
    assert_eq!(reveal(&fresh, &owner, "acme", &entry), "alpha-secret");
    verify_ok(&fresh, &owner);
    assert!(!v.paths().rotation_stage().exists());
}

#[test]
fn a_crash_at_every_point_after_the_commit_leaves_the_new_passphrase_in_force() {
    let (v, state, entry) = populated();
    drop(state);

    // How many live files a change replaces.
    let files = {
        let dry = cloned(&v);
        let state = dry.broker(None);
        login(&state);
        state
            .set_passphrase(
                secrecy::SecretBox::new(Box::new(PASSPHRASE.to_string())),
                secrecy::SecretBox::new(Box::new(NEW_PASSPHRASE.to_string())),
                NOW + 1,
            )
            .unwrap()
            .files_replaced
    };
    assert!(
        files >= 5,
        "a passphrase change rewrites at least five files"
    );

    // Count up from zero rather than iterate a range built from the change's result, so the failure
    // messages below name the cut without formatting anything the passphrase change returned.
    for cut in 0usize.. {
        if cut > files {
            break;
        }
        let vault = cloned(&v);
        let state = vault.broker(None);
        login(&state);
        state.set_rotation_fault_for_test(Some(RotationFault::DuringRollForward(cut)));
        assert!(state
            .set_passphrase(
                secrecy::SecretBox::new(Box::new(PASSPHRASE.to_string())),
                secrecy::SecretBox::new(Box::new(NEW_PASSPHRASE.to_string())),
                NOW + 1,
            )
            .is_err());
        drop(state);

        let why = format!("crash after {cut} files");
        let fresh = vault.broker(None);
        assert_eq!(
            unlock_with(&fresh, PASSPHRASE),
            Err(OpError::WrongPassphrase),
            "{why}: the old passphrase no longer opens it"
        );
        let owner = login_with(&fresh, NEW_PASSPHRASE);
        assert_eq!(
            reveal(&fresh, &owner, "acme", &entry),
            "alpha-secret",
            "{why}"
        );
        verify_ok(&fresh, &owner);
        assert!(!vault.paths().rotation_stage().exists(), "{why}");
    }
}

#[test]
fn through_the_wire_it_shares_the_backoff_and_audits_no_passphrase() {
    let (v, state, _) = populated();
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
    let send = |params: serde_json::Value| {
        server::handle_request(
            &state,
            &peer(),
            &Request {
                id: "r".into(),
                op: "vault.set_passphrase".into(),
                token: Some(token.clone()),
                params,
            },
        )
        .0
    };
    // Guesses at the current passphrase count towards the per-uid lockout like unlock's do.
    let mut limited = false;
    for i in 0..12 {
        match send(json!({ "passphrase": format!("guess {i}"), "newPassphrase": NEW_PASSPHRASE })) {
            Err(OpError::WrongPassphrase) => {}
            Err(OpError::RateLimited { .. }) => {
                limited = true;
                break;
            }
            other => panic!("unexpected answer to a wrong guess: {other:?}"),
        }
    }
    assert!(limited, "wrong guesses are rate-limited");

    // No audit line carries either passphrase.
    let mut files = Vec::new();
    fn walk(d: &Path, out: &mut Vec<std::path::PathBuf>) {
        if let Ok(rd) = std::fs::read_dir(d) {
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    walk(&p, out);
                } else {
                    out.push(p);
                }
            }
        }
    }
    walk(&v.vault_dir, &mut files);
    walk(&v.state_dir, &mut files);
    for f in files {
        let bytes = std::fs::read(&f).unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(
            !text.contains(NEW_PASSPHRASE) && !text.contains("guess 0"),
            "{} holds a passphrase",
            f.display()
        );
    }
}

// --- ADR-165 N5: a passphrase change replaces every live node's keypair ---------------------------------

fn change(state: &BrokerState) -> credmgr_brokerd::state::RotationOutcome {
    state
        .set_passphrase(
            secrecy::SecretBox::new(Box::new(PASSPHRASE.to_string())),
            secrecy::SecretBox::new(Box::new(NEW_PASSPHRASE.to_string())),
            NOW + 1,
        )
        .expect("the passphrase change")
}

/// ADR-165 N5, the attack replayed. The attacker holds a byte-copy of the vault folder made before the change
/// and the OLD passphrase, and a later copy holding secrets written after the change. They open the old wrap,
/// unwrap the old node keys and try the new envelopes: nothing written after the change opens, nor does any
/// live envelope (every one was re-sealed). What the old copy held before the change it still opens — inherent.
/// Meanwhile everything the vault held is still there: entries, the note, retained history, a removed entry's
/// restore, and a write waiting in the locked-write tray of a node that was locked during the change.
#[test]
fn a_copy_from_before_the_change_plus_the_old_passphrase_opens_nothing_written_after_it() {
    use credmgr_core::registry::GLOBAL_ID;
    let (v, state) = created_vault(None);
    let owner = login(&state);
    let seed = seed_acme(&state, &owner);
    let in_global = create_entry(&state, &owner, GLOBAL_ID, "SHARED", "global-before");
    // A node locked on its own, with a write waiting in its tray: neither refuses the change.
    call(
        &state,
        &owner,
        NOW,
        "vault.node_lock",
        json!({ "node": "acme" }),
    )
    .expect("node lock");
    let queued = create_entry(&state, &owner, "acme", "QUEUED", "queued-before");
    assert!(
        v.paths().pending_env("acme", &queued).exists(),
        "the write waits in the tray"
    );

    let pre = cloned(&v);
    let old_root = root_from_folder(&pre.vault_dir, PASSPHRASE).expect("the old wrap opens");
    let old_acme = node_key_from_folder(&pre.vault_dir, &old_root, "acme").expect("old acme key");
    let old_global =
        node_key_from_folder(&pre.vault_dir, &old_root, GLOBAL_ID).expect("old global key");

    let changed = call(
        &state,
        &owner,
        NOW,
        "vault.set_passphrase",
        json!({ "passphrase": PASSPHRASE, "newPassphrase": NEW_PASSPHRASE }),
    )
    .expect("vault.set_passphrase with a locked node and a full tray");
    assert_eq!(changed["completionPending"], json!(false));
    assert_eq!(
        changed["nodesRekeyed"],
        json!(["acme", "global"]),
        "global and acme get new keys"
    );
    // Two live entries, the note, one history slot, one removed entry, one in global, one in the tray.
    assert!(changed["filesResealed"].as_u64().unwrap() >= 7, "{changed}");
    assert_eq!(changed["notResigned"], json!([]), "nothing was left behind");

    // Writes after the change.
    let owner = login_with(&state, NEW_PASSPHRASE);
    call(
        &state,
        &owner,
        NOW,
        "vault.node_unlock",
        json!({ "node": "acme" }),
    )
    .expect("node unlock");
    let after = create_entry(&state, &owner, "acme", "AFTER", "written-after-the-change");
    let after_global = create_entry(&state, &owner, GLOBAL_ID, "AFTER_G", "global-after");

    // 1. The attacker: nothing written after the change opens with the old node keys…
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
    // …nor does any live envelope from before it (each was re-sealed), nor does the old root open a live key.
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
    assert!(!key_opens(
        &old_acme,
        &paths.pending_env("acme", &queued),
        "acme",
        &queued
    ));
    assert!(node_key_from_folder(&v.vault_dir, &old_root, "acme").is_none());
    assert!(root_from_folder(&v.vault_dir, PASSPHRASE).is_none());
    // What the copy held before the change it still opens (inherent, and said in the ADR).
    assert!(key_opens(
        &old_acme,
        &pre.paths().entry_env("acme", &seed.kept),
        "acme",
        &seed.kept
    ));

    // 2. Everything is still there, on the running broker and after a restart.
    let new_root = root_from_folder(&v.vault_dir, NEW_PASSPHRASE).expect("the new wrap opens");
    let check = |state: &BrokerState, owner: &credmgr_brokerd::scope::BrokerScope| {
        assert_eq!(reveal(state, owner, "acme", &seed.rotated), "alpha-2");
        assert_eq!(reveal(state, owner, "acme", &seed.kept), "beta-2");
        assert_eq!(
            reveal(state, owner, "acme", &after),
            "written-after-the-change"
        );
        assert_eq!(reveal(state, owner, GLOBAL_ID, &in_global), "global-before");
        let note =
            call(state, owner, NOW, "notes.read", json!({ "node": "acme" })).expect("notes.read");
        assert_eq!(note["markdown"], "the note");
        // The retained history slot opens with the new key and its signed record names the re-sealed file.
        let key = state.hot_node_key("acme").expect("acme is open");
        let hist = paths.entry_history_env("acme", &seed.rotated, seed.history_generation);
        assert!(key_opens(&key, &hist, "acme", &seed.rotated));
        let snap = credmgr_store::rotation_history::load(
            &paths,
            &new_root,
            "acme",
            &seed.rotated,
            seed.history_generation,
        )
        .expect("the history record verifies under the new root");
        assert_eq!(snap.sha256, sha256_hex(&std::fs::read(&hist).unwrap()));
        let gone = paths.removed_entry_env("acme", &seed.removed);
        let record =
            credmgr_store::entry_archive::peek(&paths, &new_root, "acme", &seed.removed, NOW)
                .expect("the removal record verifies under the new root");
        assert_eq!(record.sha256, sha256_hex(&std::fs::read(gone).unwrap()));
        verify_ok(state, owner);
    };
    check(&state, &owner);
    drop(state);
    let fresh = v.broker(None);
    let owner = login_with(&fresh, NEW_PASSPHRASE);
    check(&fresh, &owner);
    // The tray entry written to the locked node before the change is accepted and reads back.
    call(
        &fresh,
        &owner,
        NOW,
        "vault.pending_accept",
        json!({ "node": "acme", "entry": queued }),
    )
    .expect("the queued write is accepted after the change");
    assert_eq!(reveal(&fresh, &owner, "acme", &queued), "queued-before");
    // The removed entry still restores.
    call(
        &fresh,
        &owner,
        NOW,
        "entry.restore",
        json!({ "node": "acme", "entry": seed.removed, "generation": generation(&fresh, &owner, "acme") }),
    )
    .expect("a removed entry restores after the change");
    assert_eq!(reveal(&fresh, &owner, "acme", &seed.removed), "gamma-3");
    verify_ok(&fresh, &owner);
}

/// ADR-165 N5: a crash at every point of a passphrase change — while staging, before the commit, right after
/// it, and after every file the roll-forward moves — ends in the old state (old passphrase, every live
/// envelope still opening with the OLD node key) or the new one (new passphrase, no live envelope opening with
/// the old key), never a mixture and never a vault that will not open.
#[test]
fn a_crash_anywhere_in_the_rekeying_change_leaves_the_old_keys_or_the_new_ones() {
    let (v, state) = created_vault(None);
    let owner = login(&state);
    let seed = seed_acme(&state, &owner);
    drop(state);
    let old_root = root_from_folder(&v.vault_dir, PASSPHRASE).unwrap();
    let old_acme = node_key_from_folder(&v.vault_dir, &old_root, "acme").unwrap();

    let files = {
        let dry = cloned(&v);
        let state = dry.broker(None);
        login(&state);
        let outcome = change(&state);
        assert_eq!(outcome.nodes_rekeyed.as_ref().map(Vec::len), Some(2));
        outcome.files_replaced
    };

    let live_envelopes = |vault: &Vault| -> Vec<bool> {
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
    let assert_old = |vault: &Vault, why: &str| {
        let fresh = vault.broker(None);
        assert_eq!(
            unlock_with(&fresh, NEW_PASSPHRASE),
            Err(OpError::WrongPassphrase),
            "{why}"
        );
        let owner = login_with(&fresh, PASSPHRASE);
        assert_eq!(
            reveal(&fresh, &owner, "acme", &seed.kept),
            "beta-2",
            "{why}"
        );
        verify_ok(&fresh, &owner);
        assert!(
            live_envelopes(vault).iter().all(|o| *o),
            "{why}: every file on the old key"
        );
        assert!(!vault.paths().rotation_stage().exists(), "{why}");
    };
    let assert_new = |vault: &Vault, why: &str| {
        let fresh = vault.broker(None);
        assert_eq!(
            unlock_with(&fresh, PASSPHRASE),
            Err(OpError::WrongPassphrase),
            "{why}"
        );
        let owner = login_with(&fresh, NEW_PASSPHRASE);
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
        verify_ok(&fresh, &owner);
        assert!(
            live_envelopes(vault).iter().all(|o| !*o),
            "{why}: no file on the old key"
        );
        assert!(!vault.paths().rotation_stage().exists(), "{why}");
    };
    let crash = |fault: RotationFault| -> Vault {
        let vault = cloned(&v);
        let state = vault.broker(None);
        login(&state);
        state.set_rotation_fault_for_test(Some(fault));
        assert!(state
            .set_passphrase(
                secrecy::SecretBox::new(Box::new(PASSPHRASE.to_string())),
                secrecy::SecretBox::new(Box::new(NEW_PASSPHRASE.to_string())),
                NOW + 1,
            )
            .is_err());
        drop(state);
        vault
    };

    for staged in 0usize.. {
        if staged >= files {
            break;
        }
        assert_old(
            &crash(RotationFault::DuringStaging(staged)),
            &format!("staging cut {staged}"),
        );
    }
    assert_old(&crash(RotationFault::BeforeCommit), "before the commit");
    assert_new(&crash(RotationFault::AfterCommit), "right after the commit");
    for cut in 0usize.. {
        if cut > files {
            break;
        }
        assert_new(
            &crash(RotationFault::DuringRollForward(cut)),
            &format!("roll-forward cut {cut}"),
        );
    }
}

/// ADR-165 N5: the cost. The change is now O(entries): measured on a generated vault, printed, and bounded
/// loosely so a pathological slowdown fails. Run with `--ignored --nocapture` to read the numbers.
#[test]
#[ignore = "a measurement; run with --ignored --nocapture"]
fn the_cost_of_rekeying_on_a_passphrase_change_measured() {
    let (v, state) = created_vault(None);
    let owner = login(&state);
    let nodes = ["alpha", "bravo", "charlie", "delta", "echo"];
    for n in nodes {
        create_node(&state, &owner, n);
    }
    let per_node = 60;
    for n in nodes {
        for i in 0..per_node {
            create_entry(
                &state,
                &owner,
                n,
                &format!("TEST_KEY_{i}"),
                &format!("test-value-{n}-{i}"),
            );
        }
    }
    drop(state);

    // A plain root rotation (re-wrap only) on one copy, the re-keying passphrase change on another.
    let a = cloned(&v);
    let sa = a.broker(None);
    login(&sa);
    let t = std::time::Instant::now();
    let plain = sa
        .rotate_root(
            secrecy::SecretBox::new(Box::new(PASSPHRASE.to_string())),
            NOW + 1,
        )
        .unwrap();
    let rewrap = t.elapsed();

    let b = cloned(&v);
    let sb = b.broker(None);
    login(&sb);
    let t = std::time::Instant::now();
    let rekeyed = change(&sb);
    let rekey = t.elapsed();
    println!(
        "N5 cost, {} entries in {} nodes (+ global): rotate_root (re-wrap) {:?} for {} files; \
         set_passphrase (re-key) {:?} for {} files, {} re-sealed",
        nodes.len() * per_node,
        nodes.len(),
        rewrap,
        plain.files_replaced,
        rekey,
        rekeyed.files_replaced,
        rekeyed.files_resealed
    );
    assert_eq!(rekeyed.files_resealed, nodes.len() * per_node);
    assert!(
        rekey.as_secs() < 120,
        "a re-keying change of 300 entries took {rekey:?}"
    );
}
