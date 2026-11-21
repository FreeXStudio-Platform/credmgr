//! ADR-165 — the machine lock (ADR-144's smallest safe version, the file tier), with its failure injection.
//!
//! A bound `keys/root.wrap.pass` is the plain Argon2id wrap sealed a second time under a device key kept at
//! `<state>/machine/lock.key`, outside the vault folder. This file proves, against a real `vault.init_*` vault
//! on disk:
//!
//! * an unbound vault opens exactly as before (the file is never rewritten, its bytes never change);
//! * bind is a root rotation that proves the passphrase and the current recovery code and issues a new code,
//!   re-keys every node and gives the orphan a new keypair; the passphrase still opens the vault on this Mac,
//!   and a copy of the folder without the key does not open with the passphrase — the refusal names the
//!   machine lock and points to the recovery code, and never counts as a wrong passphrase;
//! * review P0-1, replayed exactly: a whole pre-bind copy of the folder (old wrap and old node-key wraps) plus
//!   the passphrase opens no secret written after the bind (it still opens what it held before, which is
//!   inherent), and putting the old wrap back into the live vault is refused and named, never a silent unbind;
//! * review P0-2: a CredMgr backup of a bound vault carries the passphrase wrap unsealed inside its own
//!   encryption, so after a later rotation and a lost device key the passphrase still opens it;
//! * the failures: a missing key, a wrong key, a truncated (to any length) or corrupted sealed wrap, a crash at
//!   every step of a bind or an unbind (including the real temporary file and a failure after the rename),
//!   a wrong recovery code or passphrase at bind, bind on a vault with no recovery code, the key inside the
//!   vault folder at bind and at a rotation, unbind without presence, the second factor or the passphrase, a
//!   rotation that cannot seal (reported, never silent), an agent caller (refused before anything is read);
//! * a root rotation and a passphrase change keep the vault bound (re-sealed to the same key), and an unbound
//!   vault stays unbound.
//! * review N1: bind is two phases; a prepare changes no file, and an abandoned one (restart, lock, timeout,
//!   cancel, a rotation in between) leaves the old code and root key fully valid; the commit takes the new code
//!   typed back (a wrong one is refused, uncounted), and a crash in its rotation before the commit record
//!   leaves the old code working;
//! * review N2/N3/N6: a bound vault's archives are written outside the vault folder, the archive passphrase is
//!   not compared with the vault passphrase, and a device key gone mid-session gives a backup error that says
//!   what to do;
//! * review N4: the bind record follows the vault's identity, not its path, and an interrupted unbind is never
//!   undone by a later rotation.

mod f1_support;

use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use secrecy::SecretBox;
use serde_json::{json, Value};

use credmgr_brokerd::protocol::{to_wire, OpError, Request};
use credmgr_brokerd::server;
use credmgr_brokerd::state::{BrokerState, MachineLockFault, RotationFault, BIND_PREPARE_SECONDS};
use credmgr_core::access::Origin;
use credmgr_core::keys::{unwrap_node_key, WrappedNodeKey};
use credmgr_keystore::backup_passphrase::decrypt_with_passphrase;
use credmgr_keystore::machine_lock::{self, WrapForm, PLAIN_PASS_WRAP_LEN};
use credmgr_keystore::software::SoftwareKeystore;
use credmgr_keystore::{KeystoreId, PlatformKeystore, WrappedKey};
use credmgr_store::backup::restore_bundle;

use f1_support::*;

const NEW_PASSPHRASE: &str = "a passphrase for the new machine";

fn key_path(v: &Vault) -> std::path::PathBuf {
    v.state_dir.join("machine").join("lock.key")
}

fn pass_wrap(v: &Vault) -> Vec<u8> {
    std::fs::read(v.paths().root_wrap_pass()).unwrap()
}

fn form(v: &Vault) -> WrapForm {
    machine_lock::classify(&pass_wrap(v))
}

fn unlock_with(state: &BrokerState, passphrase: &str) -> Result<Value, OpError> {
    call(
        state,
        &anyone(),
        NOW,
        "vault.unlock",
        json!({ "passphrase": passphrase }),
    )
}

fn recover(state: &BrokerState, code: &str, new_passphrase: &str) -> Result<Value, OpError> {
    call(
        state,
        &anyone(),
        NOW,
        "vault.recover",
        json!({ "recoveryCode": code, "newPassphrase": new_passphrase }),
    )
}

thread_local! {
    /// The presence key this test enrolled (each test runs on its own thread), so a bind phase can carry the
    /// proof ADR-174 O-5 asks for, as the shell and the CLI attach it.
    static PRESENCE: std::cell::RefCell<Option<Signer>> = const { std::cell::RefCell::new(None) };
}

/// Enrol a presence key, and remember it for [`bind_call`].
fn enrol_key(state: &BrokerState, owner: &credmgr_brokerd::scope::BrokerScope) -> Signer {
    let key = enrol_first_key(state, owner);
    PRESENCE.with(|p| *p.borrow_mut() = Some(key.clone()));
    key
}

/// A `keystore.bind` phase as a client sends it: with a presence proof for exactly this request when the vault
/// has a presence key enrolled (ADR-174 O-5).
fn bind_call(
    state: &BrokerState,
    owner: &credmgr_brokerd::scope::BrokerScope,
    at: i64,
    params: Value,
) -> Result<Value, OpError> {
    let params = PRESENCE
        .with(|p| {
            p.borrow()
                .as_ref()
                .filter(|_| !state.presence_keys().is_empty())
                .map(|k| with_proof(state, owner, k, at, "keystore.bind", params.clone()))
        })
        .unwrap_or(params);
    call(state, owner, at, "keystore.bind", params)
}

/// `keystore.bind` in its two phases (review N1): `prepare` with the passphrase and the vault's current
/// recovery code, then `commit` with the new code it showed typed back; that code becomes the current one.
fn bind(v: &Vault, state: &BrokerState, owner: &credmgr_brokerd::scope::BrokerScope) -> Value {
    bind_with(v, state, owner, PASSPHRASE)
}

fn bind_with(
    v: &Vault,
    state: &BrokerState,
    owner: &credmgr_brokerd::scope::BrokerScope,
    passphrase: &str,
) -> Value {
    let code = v.recovery_code.borrow().clone();
    let prepared = bind_call(
        state,
        owner,
        NOW,
        json!({ "phase": "prepare", "passphrase": passphrase, "recoveryCode": code }),
    )
    .expect("keystore.bind prepare");
    let new = prepared["newRecoveryCode"].as_str().map(str::to_string);
    if let Some(new) = &new {
        assert_ne!(new, &code, "a bind that rotates issues a new recovery code");
    }
    let answer = commit(state, owner, NOW, new.as_deref()).expect("keystore.bind commit");
    assert!(
        answer.get("recoveryCode").is_none() && answer["rotation"].get("recoveryCode").is_none(),
        "the commit never sends the code again: {answer}"
    );
    if let Some(new) = new {
        *v.recovery_code.borrow_mut() = new;
    }
    answer
}

/// `keystore.bind`'s prepare with the passphrase and the vault's current recovery code.
fn bind_params(v: &Vault) -> Value {
    json!({ "phase": "prepare", "passphrase": PASSPHRASE, "recoveryCode": v.recovery_code.borrow().clone() })
}

/// `keystore.bind`'s commit with `code` typed back.
fn commit(
    state: &BrokerState,
    owner: &credmgr_brokerd::scope::BrokerScope,
    at: i64,
    code: Option<&str>,
) -> Result<Value, OpError> {
    let mut params = json!({ "phase": "commit" });
    if let Some(code) = code {
        params["recoveryCode"] = json!(code);
    }
    bind_call(state, owner, at, params)
}

/// Prepare a bind and answer the new code it showed.
fn prepare(v: &Vault, state: &BrokerState, owner: &credmgr_brokerd::scope::BrokerScope) -> String {
    let p = bind_call(state, owner, NOW, bind_params(v)).expect("prepare");
    assert_eq!(p["phase"], "prepare");
    assert_eq!(p["changed"], false);
    p["newRecoveryCode"]
        .as_str()
        .expect("a new code")
        .to_string()
}

/// Every file under `dir` with its bytes, but the audit log (which records the requests themselves).
fn snapshot(dir: &Path) -> Vec<(std::path::PathBuf, Vec<u8>)> {
    if !dir.exists() {
        return Vec::new();
    }
    let mut out: Vec<_> = walk(dir)
        .into_iter()
        .filter(|p| !p.starts_with(dir.join("audit")))
        .map(|p| {
            let b = std::fs::read(&p).unwrap();
            (p, b)
        })
        .collect();
    out.sort();
    out
}

fn expect_not_prepared(r: Result<Value, OpError>, says: &str) {
    match r {
        Err(OpError::Malformed(m)) => {
            assert!(m.contains("nothing changed") && m.contains(says), "{m}")
        }
        other => panic!("expected a refused commit ({says}), got {other:?}"),
    }
}

/// The root key a plain passphrase wrap yields for `passphrase` (what an attacker with a copy computes).
fn open_plain_wrap(bytes: &[u8], passphrase: &str, scratch: &Path) -> Option<[u8; 32]> {
    use secrecy::ExposeSecret;
    SoftwareKeystore::new(
        SecretBox::new(Box::new(passphrase.to_string())),
        scratch.to_path_buf(),
    )
    .unwrap_root(
        &WrappedKey {
            keystore: KeystoreId::Software,
            bytes: bytes.to_vec(),
        },
        "test",
    )
    .ok()
    .map(|k| *k.expose_secret())
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        let target = to.join(e.file_name());
        if e.file_type().unwrap().is_dir() {
            copy_dir(&e.path(), &target);
        } else if e.file_type().unwrap().is_file() {
            std::fs::copy(e.path(), target).unwrap();
        }
    }
}

fn status(state: &BrokerState, owner: &credmgr_brokerd::scope::BrokerScope) -> Value {
    call(state, owner, NOW, "keystore.status", json!({})).expect("keystore.status")
}

fn refused_with(result: Result<Value, OpError>, reason: &str) {
    match result {
        Err(OpError::MachineLockRefused { reason: r }) => assert_eq!(r, reason),
        other => panic!("expected machine_lock_refused/{reason}, got {other:?}"),
    }
}

/// A vault with an entry, bound, on a freshly started broker (locked).
fn bound_vault() -> (Vault, Arc<BrokerState>, String) {
    let (v, state) = created_vault(None);
    let owner = login(&state);
    create_node(&state, &owner, "acme");
    let entry = create_entry(&state, &owner, "acme", "API_KEY", "alpha-secret");
    let answer = bind(&v, &state, &owner);
    assert_eq!(answer["bound"], true, "{answer}");
    assert_eq!(answer["changed"], true);
    assert_eq!(answer["deviceKeyCreated"], true);
    assert_eq!(
        answer["nodesRekeyed"],
        json!(["acme", "global"]),
        "{answer}"
    );
    assert_eq!(answer["rekeyFailed"], json!([]));
    assert_eq!(answer["orphanKeyReplaced"], true);
    assert_eq!(answer["rotation"]["machineLocked"], true);
    drop(state);
    let fresh = v.broker(None);
    (v, fresh, entry)
}

#[test]
fn an_unbound_vault_opens_exactly_as_before_and_status_says_the_tier_is_off() {
    let (v, state) = created_vault(None);
    let before = pass_wrap(&v);
    assert_eq!(before.len(), PLAIN_PASS_WRAP_LEN);
    assert_eq!(form(&v), WrapForm::Plain);
    let (state, owner) = restart(&v, state, None);
    assert_eq!(pass_wrap(&v), before, "an unlock never rewrites the wrap");
    let st = status(&state, &owner);
    assert_eq!(st["bound"], false);
    assert_eq!(st["tier"], "off");
    assert_eq!(st["secureEnclave"], false);
    assert_eq!(st["opensHere"], true);
    assert_eq!(st["recoveryUnlock"], true);
    assert_eq!(st["deviceKeyPresent"], false);
    assert!(!key_path(&v).exists(), "status makes no key");
    // An unbound rotation (a passphrase change is one) stays unbound and makes no key.
    let r = call(
        &state,
        &owner,
        NOW,
        "vault.set_passphrase",
        json!({ "passphrase": PASSPHRASE, "newPassphrase": NEW_PASSPHRASE }),
    )
    .expect("set_passphrase");
    assert_eq!(r["machineLocked"], false);
    assert_eq!(form(&v), WrapForm::Plain);
    assert!(!key_path(&v).exists());
    // Unbinding an unbound vault changes nothing (with nothing enrolled it still asks for the passphrase).
    let u = call(
        &state,
        &owner,
        NOW,
        "keystore.unbind",
        json!({ "passphrase": NEW_PASSPHRASE }),
    )
    .expect("unbind");
    assert_eq!(u["changed"], false);
    assert_eq!(u["plainWhileBound"], false);
    assert_eq!(u["warning"], Value::Null);
}

#[test]
fn bind_seals_the_wrap_the_passphrase_still_opens_it_here_and_status_is_honest() {
    let (v, state, entry) = bound_vault();
    let WrapForm::Sealed { key_id } = form(&v) else {
        panic!("the wrap must be sealed after bind");
    };
    // The key: 32 bytes, mode 0600, in the state directory, outside the vault folder.
    let key = std::fs::read(key_path(&v)).unwrap();
    assert_eq!(key.len(), 32);
    assert!(!key_path(&v).starts_with(&v.vault_dir));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(key_path(&v))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
    // No file in the vault folder holds the device key.
    for f in walk(&v.vault_dir) {
        let bytes = std::fs::read(&f).unwrap();
        assert!(
            !bytes.windows(32).any(|w| w == key.as_slice()),
            "{} holds the device key",
            f.display()
        );
    }
    // The passphrase opens it on this Mac, and the entry reads back.
    let owner = login(&state);
    assert_eq!(reveal(&state, &owner, "acme", &entry), "alpha-secret");
    let st = status(&state, &owner);
    assert_eq!(st["bound"], true);
    assert_eq!(st["tier"], "file");
    assert_eq!(st["opensHere"], true);
    assert_eq!(st["sealedKeyId"], machine_lock::key_id_hex(&key_id));
    assert_eq!(st["deviceKeyId"], st["sealedKeyId"]);
    let not = st["doesNotProtect"].as_str().unwrap();
    for said in [
        "stolen",
        "whole-disk",
        "Migration Assistant",
        "before the lock",
        "backup",
    ] {
        assert!(not.contains(said), "doesNotProtect must say {said}: {not}");
    }
    // ADR-174 O-2: the device key was made already excluded from Time Machine, so a Time Machine backup is covered
    // (claimed only where Time Machine exists).
    assert!(!not.contains("Time Machine"), "{not}");
    let on_macos = cfg!(target_os = "macos");
    assert_eq!(st["deviceKeyTimeMachineCovered"], on_macos);
    assert_eq!(
        st["protects"].as_str().unwrap().contains("Time Machine"),
        on_macos,
        "{}",
        st["protects"]
    );
    assert_eq!(st["preBindNodes"], json!([]));
    assert_eq!(st["warning"], Value::Null);
    // Bind again: no rotation, the same file, the same key, the same code.
    let before = pass_wrap(&v);
    let code = v.recovery_code.borrow().clone();
    let again = bind(&v, &state, &owner);
    assert_eq!(again["changed"], false);
    assert_eq!(again["deviceKeyCreated"], false);
    assert!(again.get("recoveryCode").is_none());
    assert_eq!(*v.recovery_code.borrow(), code);
    assert_eq!(pass_wrap(&v), before);
    verify_ok(&state, &owner);
}

#[test]
fn a_copied_vault_folder_without_the_device_key_is_refused_with_a_pointer_to_the_recovery_code() {
    let (v, state, entry) = bound_vault();
    drop(state);
    // The folder copied to another computer: the same vault and state, but no `machine/lock.key`.
    std::fs::remove_file(key_path(&v)).unwrap();
    let state = v.broker(None);
    let before = pass_wrap(&v);
    refused_with(unlock_with(&state, PASSPHRASE), "device_key_missing");
    // A wrong passphrase gets the same answer: the passphrase is never tried without the key.
    refused_with(
        unlock_with(&state, "not the passphrase"),
        "device_key_missing",
    );
    assert!(state.is_locked());
    assert_eq!(pass_wrap(&v), before);

    // On the wire: its own code, the reason, and the remedy names the recovery code.
    let wire = to_wire(
        "r",
        &Err(OpError::MachineLockRefused {
            reason: "device_key_missing",
        }),
    );
    assert_eq!(wire["error"], "machine_lock_refused");
    assert_eq!(wire["reason"], "device_key_missing");
    assert!(wire["remedy"].as_str().unwrap().contains("recovery code"));

    // The recovery code does not need the device key.
    let answer = recover(&state, &v.recovery_code.borrow(), NEW_PASSPHRASE).expect("recover");
    assert_eq!(answer["locked"], false);
    let owner = scope_of(&state, answer["token"].as_str().unwrap());
    assert_eq!(reveal(&state, &owner, "acme", &entry), "alpha-secret");
}

#[test]
fn a_machine_lock_refusal_never_feeds_the_guessing_backoff() {
    let (v, state, _) = bound_vault();
    drop(state);
    std::fs::remove_file(key_path(&v)).unwrap();
    let state = v.broker(None);
    let clock = Instant::now();
    for _ in 0..8 {
        let (answer, _) = server::handle_request_at(
            &state,
            &peer(),
            &Request {
                id: "r".into(),
                op: "vault.unlock".into(),
                token: None,
                params: json!({ "passphrase": PASSPHRASE }),
            },
            NOW,
            clock,
        );
        refused_with(answer, "device_key_missing");
    }
    // Not backed off: the recovery goes straight through.
    let (answer, _) = server::handle_request_at(
        &state,
        &peer(),
        &Request {
            id: "r".into(),
            op: "vault.recover".into(),
            token: None,
            params: json!({ "recoveryCode": v.recovery_code.borrow().clone(),
                            "newPassphrase": NEW_PASSPHRASE }),
        },
        NOW,
        clock,
    );
    assert_eq!(answer.expect("recover")["locked"], false);
}

#[test]
fn a_wrong_device_key_is_refused_and_the_old_key_opens_again() {
    let (v, state, _) = bound_vault();
    drop(state);
    let real = std::fs::read(key_path(&v)).unwrap();
    std::fs::write(key_path(&v), [7u8; 32]).unwrap();
    let state = v.broker(None);
    refused_with(unlock_with(&state, PASSPHRASE), "device_key_mismatch");
    // An unreadable key file (not 32 bytes) is its own reason, and is not replaced.
    std::fs::write(key_path(&v), b"short").unwrap();
    refused_with(unlock_with(&state, PASSPHRASE), "device_key_unreadable");
    assert_eq!(std::fs::read(key_path(&v)).unwrap(), b"short");
    std::fs::write(key_path(&v), real).unwrap();
    unlock_with(&state, PASSPHRASE).expect("the right key opens it again");
}

#[test]
fn a_truncated_or_corrupted_sealed_wrap_is_refused_and_the_recovery_code_still_opens_and_reseals() {
    for damage in ["truncate", "truncate-to-plain-length", "flip", "relabel"] {
        let (v, state, entry) = bound_vault();
        drop(state);
        let mut bytes = pass_wrap(&v);
        match damage {
            "truncate" => bytes.truncate(30),
            // Review P2-5: cut to exactly the plain wrap's length, it is opened as plain first; the passphrase
            // does not open it, and the answer is the damaged seal, not a wrong passphrase.
            "truncate-to-plain-length" => bytes.truncate(PLAIN_PASS_WRAP_LEN),
            "flip" => {
                let i = bytes.len() - 5;
                bytes[i] ^= 0x40;
            }
            // The key id swapped for another: the header is authenticated, so this is damage, not a mismatch
            // to be believed.
            _ => {
                let key = std::fs::read(key_path(&v)).unwrap();
                let mut k: [u8; 32] = key.try_into().unwrap();
                k[0] ^= 1;
                let other = machine_lock::DeviceKey::from_bytes(&k);
                bytes[8..16].copy_from_slice(&other.id());
            }
        }
        std::fs::write(v.paths().root_wrap_pass(), &bytes).unwrap();
        let state = v.broker(None);
        let want = if damage == "relabel" {
            "device_key_mismatch"
        } else {
            "sealed_wrap_damaged"
        };
        refused_with(unlock_with(&state, PASSPHRASE), want);
        assert!(state.is_locked());

        let answer = recover(&state, &v.recovery_code.borrow(), NEW_PASSPHRASE).expect("recover");
        assert_eq!(
            answer["machineLocked"], true,
            "{damage}: a bound vault stays bound"
        );
        assert!(matches!(form(&v), WrapForm::Sealed { .. }));
        let (state, owner) = {
            drop(state);
            let s = v.broker(None);
            let token = unlock_with(&s, NEW_PASSPHRASE).expect("new passphrase")["token"]
                .as_str()
                .unwrap()
                .to_string();
            let o = scope_of(&s, &token);
            (s, o)
        };
        assert_eq!(reveal(&state, &owner, "acme", &entry), "alpha-secret");
    }
}

#[test]
fn a_crash_at_any_point_of_a_bind_or_an_unbind_leaves_a_vault_the_owner_opens_and_status_names_it()
{
    // Bind, dying after the device key and the bind record are made: the wrap is still plain (the vault was
    // not bound), the passphrase opens it, the code is unchanged, and status names the interrupted bind.
    let (v, state) = created_vault(None);
    let owner = login(&state);
    create_node(&state, &owner, "acme");
    let entry = create_entry(&state, &owner, "acme", "API_KEY", "alpha-secret");
    let plain = pass_wrap(&v);
    let code = v.recovery_code.borrow().clone();
    state.set_machine_lock_fault_for_test(Some(MachineLockFault::AfterDeviceKey));
    let shown = prepare(&v, &state, &owner);
    assert!(commit(&state, &owner, NOW, Some(&shown)).is_err());
    assert!(key_path(&v).is_file());
    let key = std::fs::read(key_path(&v)).unwrap();
    let (state, owner) = restart(&v, state, None);
    assert_eq!(pass_wrap(&v), plain);
    // Review M2: the commit's record is pending until its rotation commits, so a crash before that leaves
    // nothing that counts: not bound, no false "a plain file was put back", no warning.
    let st = status(&state, &owner);
    assert_eq!(st["bound"], false);
    assert_eq!(st["markedBound"], false);
    assert_eq!(st["plainWhileBound"], false);
    assert_eq!(st["warning"], Value::Null, "{st}");

    // Bind, dying after its rotation committed and before any node was re-keyed: bound, a new code, and the
    // node whose key dates from before the bind is listed. The passphrase opens it.
    // The code of before the crash still proves itself at the next prepare (it was never replaced).
    state.set_machine_lock_fault_for_test(Some(MachineLockFault::AfterRotation));
    let new_code = prepare(&v, &state, &owner);
    let half = commit(&state, &owner, NOW, Some(&new_code)).expect("rotation committed");
    assert_ne!(new_code, code);
    *v.recovery_code.borrow_mut() = new_code;
    assert_eq!(
        half["deviceKeyCreated"], false,
        "the key made before the crash is the one used"
    );
    assert_eq!(std::fs::read(key_path(&v)).unwrap(), key);
    state.set_machine_lock_fault_for_test(None);
    let (state, owner) = restart(&v, state, None);
    assert!(matches!(form(&v), WrapForm::Sealed { .. }));
    let st = status(&state, &owner);
    assert_eq!(st["preBindNodes"], json!(["acme", "global"]), "{st}");
    assert!(st["warning"].as_str().unwrap().contains("acme"));
    // A second bind finishes it: no rotation, acme re-keyed, nothing listed any more.
    let finish = bind(&v, &state, &owner);
    assert_eq!(finish["changed"], false);
    assert_eq!(finish["nodesRekeyed"], json!(["acme", "global"]));
    assert_eq!(finish["preBindNodes"], json!([]));
    assert_eq!(finish["warning"], Value::Null);
    assert_eq!(reveal(&state, &owner, "acme", &entry), "alpha-secret");
    let sealed = pass_wrap(&v);

    // Unbind, dying between the fsync of the atomic writer's own temporary file and its rename: the live
    // file is still sealed, and the temporary file beside it holds the plain wrap.
    state.set_machine_lock_fault_for_test(Some(MachineLockFault::BeforeRename));
    let ask = json!({ "passphrase": PASSPHRASE });
    assert!(call(&state, &owner, NOW, "keystore.unbind", ask.clone()).is_err());
    assert_eq!(pass_wrap(&v), sealed);
    let keys_dir = v.paths().keys_dir();
    let strays: Vec<_> = std::fs::read_dir(keys_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with(".root.wrap.pass.tmp.")
        })
        .map(|e| e.path())
        .collect();
    assert_eq!(strays.len(), 1, "the crash left the real temporary file");
    let leaked_plain = std::fs::read(&strays[0]).unwrap();
    assert_eq!(machine_lock::classify(&leaked_plain), WrapForm::Plain);
    // The next start (every unlock settles the vault under its lock first) removes it: no file under the
    // vault folder holds the plain wrap any more.
    state.set_machine_lock_fault_for_test(None);
    let (state, owner) = restart(&v, state, None);
    assert_eq!(pass_wrap(&v), sealed);
    for f in walk(&v.vault_dir) {
        let bytes = std::fs::read(&f).unwrap();
        assert!(
            !bytes
                .windows(leaked_plain.len())
                .any(|w| w == leaked_plain.as_slice()),
            "{} still holds the plain wrap",
            f.display()
        );
    }

    // Unbind, the rename landed and the directory fsync "failed": the answer says the file WAS changed, and
    // status agrees (not bound, no stale record).
    state.set_machine_lock_fault_for_test(Some(MachineLockFault::AfterRename));
    match call(&state, &owner, NOW, "keystore.unbind", ask) {
        Err(OpError::Internal(m)) => {
            assert!(m.contains("WAS changed") && m.contains("not bound"), "{m}")
        }
        other => panic!("{other:?}"),
    }
    state.set_machine_lock_fault_for_test(None);
    assert_eq!(form(&v), WrapForm::Plain);
    let st = status(&state, &owner);
    assert_eq!(st["bound"], false);
    assert_eq!(st["plainWhileBound"], false);
    drop(state);
    let state = v.broker(None);
    let o = scope_of(
        &state,
        unlock_with(&state, PASSPHRASE).expect("opens after the unbind")["token"]
            .as_str()
            .unwrap(),
    );
    assert_eq!(reveal(&state, &o, "acme", &entry), "alpha-secret");
}

/// Review P0-1, replayed exactly. The attacker holds a whole copy of the vault folder made before the bind
/// (the old plain `root.wrap.pass` and the old node-key wraps), the passphrase, and a later copy holding a
/// secret written after the bind. They open the old wrap, unwrap the old node keys, and try the new secret's
/// envelope; they also put the old wrap back into the live vault. Both fail. What the old copy held before the
/// bind it still opens: inherent, and said in the ADR and the bind dialog.
#[test]
fn a_whole_pre_bind_copy_plus_the_passphrase_opens_nothing_written_after_the_bind() {
    let (v, state) = created_vault(None);
    let owner = login(&state);
    create_node(&state, &owner, "acme");
    let before_bind = create_entry(&state, &owner, "acme", "OLD_KEY", "written-before-the-bind");
    let pre = tempfile::tempdir().unwrap();
    copy_dir(&v.vault_dir, pre.path());
    let old_orphan = std::fs::read(pre.path().join("keys/cold/orphan.key")).unwrap();

    let answer = bind(&v, &state, &owner);
    assert_eq!(answer["orphanKeyReplaced"], true);
    let after_bind = create_entry(&state, &owner, "acme", "NEW_KEY", "written-after-the-bind");
    assert_ne!(
        std::fs::read(v.paths().orphan_key()).unwrap(),
        old_orphan,
        "the orphan has a new cold key"
    );

    // 1. The attacker's computation, from the pre-bind copy and the passphrase.
    let scratch = tempfile::tempdir().unwrap();
    let old_root = open_plain_wrap(
        &std::fs::read(pre.path().join("keys/root.wrap.pass")).unwrap(),
        PASSPHRASE,
        scratch.path(),
    )
    .expect("the old plain wrap opens with the passphrase (inherent)");
    let old_wrapped =
        WrappedNodeKey::from_bytes(&std::fs::read(pre.path().join("keys/nodes/acme.key")).unwrap())
            .unwrap();
    let old_node_key = unwrap_node_key(&old_root, "acme", &old_wrapped).expect("old node key");
    // What the copy held before the bind: open (inherent exposure of pre-bind data).
    let pre_env = std::fs::read(
        pre.path()
            .join("nodes/acme/entries")
            .join(format!("{before_bind}.env")),
    )
    .unwrap();
    assert!(
        credmgr_core::envelope::open_any(&pre_env, &old_node_key, "acme", &before_bind).is_ok()
    );
    // What was written after the bind: the old node key does not open it, nor does the old root key open
    // the live node-key wrap.
    let post_env = std::fs::read(v.paths().entry_env("acme", &after_bind)).unwrap();
    assert!(
        credmgr_core::envelope::open_any(&post_env, &old_node_key, "acme", &after_bind).is_err()
    );
    // …and the entry written before the bind, as it is in the live vault now (re-sealed by the re-key), is
    // closed to the old key too.
    let live_pre_env = std::fs::read(v.paths().entry_env("acme", &before_bind)).unwrap();
    assert!(
        credmgr_core::envelope::open_any(&live_pre_env, &old_node_key, "acme", &before_bind)
            .is_err()
    );
    let live_wrapped =
        WrappedNodeKey::from_bytes(&std::fs::read(v.paths().node_key("acme")).unwrap()).unwrap();
    assert!(unwrap_node_key(&old_root, "acme", &live_wrapped).is_err());
    // The old wrap does not open the new sealed one's content either: the live root is another key.
    let live_plain = machine_lock::open(
        &machine_lock::DeviceKey::load(&key_path(&v))
            .unwrap()
            .unwrap(),
        &pass_wrap(&v),
    )
    .unwrap();
    let live_root = open_plain_wrap(&live_plain, PASSPHRASE, scratch.path()).unwrap();
    assert_ne!(live_root, old_root, "the bind replaced the root key");

    // 2. The old wrap put back into the live vault (a synced folder someone can write to): the passphrase
    // opens the old wrap, but nothing signed accepts its root key, and the refusal names what happened. It
    // does not open, so it does not silently unbind either.
    drop(state);
    let sealed = pass_wrap(&v);
    std::fs::copy(
        pre.path().join("keys/root.wrap.pass"),
        v.paths().root_wrap_pass(),
    )
    .unwrap();
    let state = v.broker(None);
    refused_with(unlock_with(&state, PASSPHRASE), "plain_wrap_while_bound");
    assert!(state.is_locked());
    let st = state.machine_lock_status();
    assert!(st.plain_while_bound && st.marked_bound && !st.bound);
    // The owner's current recovery code opens it, and the vault is bound again (the bind record says so,
    // whatever the file says).
    let r = recover(&state, &v.recovery_code.borrow(), NEW_PASSPHRASE).expect("recover");
    assert_eq!(r["machineLocked"], true, "{r}");
    assert!(matches!(form(&v), WrapForm::Sealed { .. }));
    assert_ne!(pass_wrap(&v), sealed);
    let o = scope_of(&state, r["token"].as_str().unwrap());
    assert_eq!(
        reveal(&state, &o, "acme", &after_bind),
        "written-after-the-bind"
    );
}

/// Review P1-1: bind proves the current recovery code against the root key (and the passphrase), counts a
/// wrong one as a guess, and changes nothing when either is wrong.
#[test]
fn bind_proves_the_current_recovery_code_and_the_passphrase_and_a_wrong_one_is_a_counted_guess() {
    let (v, state) = created_vault(None);
    let token = unlock_with(&state, PASSPHRASE).expect("unlock")["token"]
        .as_str()
        .unwrap()
        .to_string();
    let owner = scope_of(&state, &token);
    let before = pass_wrap(&v);
    let code = v.recovery_code.borrow().clone();
    // A code of the right shape that is not this vault's.
    let mut wrong = code.clone().into_bytes();
    let i = wrong
        .iter()
        .position(|c| c.is_ascii_alphanumeric())
        .unwrap();
    wrong[i] = if wrong[i] == b'A' { b'B' } else { b'A' };
    let wrong = String::from_utf8(wrong).unwrap();
    for bad in [
        json!({ "phase": "prepare", "passphrase": PASSPHRASE, "recoveryCode": wrong }),
        json!({ "phase": "prepare", "passphrase": PASSPHRASE, "recoveryCode": "not a code" }),
    ] {
        assert!(
            matches!(
                call(&state, &owner, NOW, "keystore.bind", bad),
                Err(OpError::RecoveryCodeMismatch)
            ),
            "a wrong code is refused"
        );
    }
    assert!(matches!(
        call(
            &state,
            &owner,
            NOW,
            "keystore.bind",
            json!({ "phase": "prepare", "passphrase": "not the passphrase", "recoveryCode": code })
        ),
        Err(OpError::WrongPassphrase)
    ));
    for missing in [
        json!({ "phase": "prepare", "recoveryCode": code }),
        json!({ "phase": "prepare", "passphrase": PASSPHRASE }),
        // No phase: an older client's one-call bind is refused, never half done.
        json!({ "passphrase": PASSPHRASE, "recoveryCode": code }),
    ] {
        assert!(matches!(
            call(&state, &owner, NOW, "keystore.bind", missing),
            Err(OpError::Malformed(_))
        ));
    }
    assert_eq!(pass_wrap(&v), before);
    assert!(!key_path(&v).exists(), "nothing is made for a refused bind");
    assert_eq!(*v.recovery_code.borrow(), code);

    // Through the server, wrong codes are guesses: the fifth is followed by a lockout.
    let clock = Instant::now();
    for _ in 0..5 {
        let (r, _) = server::handle_request_at(
            &state,
            &peer(),
            &Request {
                id: "r".into(),
                op: "keystore.bind".into(),
                token: Some(token.clone()),
                params: json!({ "phase": "prepare", "passphrase": PASSPHRASE, "recoveryCode": wrong }),
            },
            NOW,
            clock,
        );
        assert!(matches!(r, Err(OpError::RecoveryCodeMismatch)), "{r:?}");
    }
    assert!(state
        .auth_backoff
        .remaining_lockout(peer().uid, clock)
        .is_some());
    assert_eq!(pass_wrap(&v), before);

    // After a bind, the code it replaced no longer binds: the new one is the one that works.
    let s2 = v.broker(None);
    let o2 = login(&s2);
    bind(&v, &s2, &o2);
    assert!(matches!(
        call(
            &s2,
            &o2,
            NOW,
            "keystore.bind",
            json!({ "phase": "prepare", "passphrase": PASSPHRASE, "recoveryCode": code })
        ),
        Err(OpError::RecoveryCodeMismatch)
    ));
}

/// Review P0-2: bind, back up, rotate (a new code), lose the Mac. The owner holds the passphrase and the
/// current code; the archive opens with the passphrase, because it carries the passphrase wrap unsealed
/// inside its own encryption.
#[test]
fn an_old_backup_of_a_bound_vault_opens_with_the_passphrase_after_a_rotation_and_a_lost_device_key()
{
    let (v, state, entry) = bound_vault();
    let owner = login(&state);
    let device_key = std::fs::read(key_path(&v)).unwrap();
    let sealed = pass_wrap(&v);
    // Review N3: no check of the archive passphrase against the vault passphrase (it was an unthrottled
    // oracle); review N2: the archive is written outside the vault folder, so no copy of the folder holds it.
    let same = call(
        &state,
        &owner,
        NOW,
        "maintenance.backup",
        json!({ "passphrase": PASSPHRASE }),
    )
    .expect("no oracle: the archive passphrase is not compared with the vault passphrase");
    assert_eq!(same["outsideVaultFolder"], true);
    let b = call(
        &state,
        &owner,
        NOW,
        "maintenance.backup",
        json!({ "passphrase": "an archive passphrase" }),
    )
    .expect("backup");
    assert_eq!(b["passphraseFileUnsealed"], true);
    assert_eq!(b["outsideVaultFolder"], true);
    let at = std::path::PathBuf::from(b["path"].as_str().unwrap());
    assert!(
        at.starts_with(v.state_dir.join("backups")) && !at.starts_with(&v.vault_dir),
        "{}",
        at.display()
    );
    assert!(
        walk(&v.vault_dir).iter().all(|f| !f
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("credmgr-backup-")),
        "a copy of the vault folder carries no archive of the bound vault"
    );
    let blob = std::fs::read(&at).unwrap();
    let archive = decrypt_with_passphrase(
        &SecretBox::new(Box::new("an archive passphrase".to_string())),
        &blob,
    )
    .expect("archive opens");
    assert!(
        !archive
            .windows(sealed.len())
            .any(|w| w == sealed.as_slice()),
        "the archive does not keep the sealed wrap"
    );
    assert!(
        !archive.windows(32).any(|w| w == device_key.as_slice()),
        "the archive never carries the device key"
    );
    // A later rotation, while bound: a new code, and the code of the backup's day is dead.
    let presence = enrol_key(&state, &owner);
    let proved = with_proof(
        &state,
        &owner,
        &presence,
        NOW,
        "maintenance.rotate_root",
        json!({ "passphrase": PASSPHRASE }),
    );
    let r = call(&state, &owner, NOW, "maintenance.rotate_root", proved).expect("rotate");
    assert_eq!(r["machineLocked"], true);
    drop(state);

    // The Mac is lost: a new machine, no device key, the archive restored.
    let new = tempfile::tempdir().unwrap();
    let moved = Vault {
        vault_dir: new.path().join("vault"),
        state_dir: new.path().join("state"),
        recovery_code: std::cell::RefCell::new(r["recoveryCode"].as_str().unwrap().to_string()),
        _dir: new,
    };
    // ADR-148 amendment with ADR-165: the bound vault's archive carries the restore ticket (never the counter)
    // beside the unsealed passphrase wrap. The ticket signs `registry.json` only, so the two compose: the
    // restore into a new folder with an empty state directory writes the one-shot accept marker, and the
    // first unlock with the passphrase checks it, writes the counter and consumes it.
    let packed = credmgr_store::backup::unpack(&archive).expect("archive unpacks");
    assert!(packed
        .iter()
        .any(|e| e.relative_path == "_state/restore.ticket"));
    assert!(packed
        .iter()
        .all(|e| !e.relative_path.starts_with("_state/")
            || e.relative_path == "_state/restore.ticket"));
    let report = restore_bundle(&archive, &moved.vault_dir, &moved.state_dir).expect("restore");
    assert_eq!(
        report.counter,
        credmgr_store::backup::CounterOutcome::AcceptMarker
    );
    let marker = credmgr_store::restore_marker::marker_path(&moved.state_dir);
    assert!(marker.exists(), "the restore wrote the accept marker");
    assert_eq!(form(&moved), WrapForm::Plain);
    let s = moved.broker(None);
    let o = scope_of(
        &s,
        unlock_with(&s, PASSPHRASE).expect("the passphrase opens the archive's vault")["token"]
            .as_str()
            .unwrap(),
    );
    assert!(
        !marker.exists(),
        "the first unlock consumed the marker (and wrote the counter)"
    );
    assert_eq!(reveal(&s, &o, "acme", &entry), "alpha-secret");
    let st = status(&s, &o);
    assert_eq!(
        st["bound"], false,
        "a restored vault is not bound until bound again here"
    );
    assert_eq!(st["plainWhileBound"], false);
}

/// ADR-174 O-1 (the owner's decision): "A backup of a locked vault still restores on another Mac with passphrase +
/// recovery code, so a dead Mac never means lost data." A CredMgr backup of a bound vault, restored on a Mac that
/// has never held this vault's device key, opens with the vault passphrase of the backup's day; and, restored
/// again on another such Mac, with the recovery code of the backup's day through `vault.recover` (the Lock
/// screen's "Forgot passphrase?"), which also issues a new code. Neither path reads a device key, and neither
/// Mac had one before.
#[test]
fn a_backup_of_a_bound_vault_restores_on_another_mac_with_the_passphrase_or_the_recovery_code() {
    let (v, state, entry) = bound_vault();
    let owner = login(&state);
    let code_of_the_day = v.recovery_code.borrow().clone();
    let b = call(
        &state,
        &owner,
        NOW,
        "maintenance.backup",
        json!({ "passphrase": "an archive passphrase" }),
    )
    .expect("backup");
    assert_eq!(b["passphraseFileUnsealed"], true);
    let blob = std::fs::read(b["path"].as_str().unwrap()).unwrap();
    let archive = decrypt_with_passphrase(
        &SecretBox::new(Box::new("an archive passphrase".to_string())),
        &blob,
    )
    .expect("archive opens");
    drop(state);
    // The Mac dies: its state folder, and the device key in it, are gone with it.
    std::fs::remove_dir_all(&v.state_dir).unwrap();

    let fresh_mac = |code: &str| {
        let new = tempfile::tempdir().unwrap();
        let mac = Vault {
            vault_dir: new.path().join("vault"),
            state_dir: new.path().join("state"),
            recovery_code: std::cell::RefCell::new(code.to_string()),
            _dir: new,
        };
        restore_bundle(&archive, &mac.vault_dir, &mac.state_dir).expect("restore");
        assert!(
            !key_path(&mac).exists(),
            "the other Mac holds no device key"
        );
        assert_eq!(
            form(&mac),
            WrapForm::Plain,
            "the archive's wrap is unsealed"
        );
        mac
    };

    // Another Mac, the passphrase.
    let a = fresh_mac(&code_of_the_day);
    let s = a.broker(None);
    let token = unlock_with(&s, PASSPHRASE).expect("the passphrase of the backup's day opens it")
        ["token"]
        .as_str()
        .unwrap()
        .to_string();
    let o = scope_of(&s, &token);
    assert_eq!(reveal(&s, &o, "acme", &entry), "alpha-secret");
    assert!(
        !key_path(&a).exists(),
        "opening needed no device key and made none"
    );
    drop(s);

    // Yet another Mac, the passphrase forgotten: the recovery code of the backup's day.
    let b = fresh_mac(&code_of_the_day);
    let s = b.broker(None);
    let answer = recover(&s, &code_of_the_day, NEW_PASSPHRASE)
        .expect("the recovery code of the backup's day opens it");
    assert_eq!(answer["locked"], false);
    assert_eq!(
        answer["machineLocked"], false,
        "a restored archive is not bound until bound again on that Mac"
    );
    let new_code = answer["recoveryCode"].as_str().unwrap().to_string();
    assert_ne!(new_code, code_of_the_day, "a recovery issues a new code");
    let o = scope_of(&s, answer["token"].as_str().unwrap());
    assert_eq!(reveal(&s, &o, "acme", &entry), "alpha-secret");
    drop(s);
    let s = b.broker(None);
    unlock_with(&s, NEW_PASSPHRASE).expect("the new passphrase opens it after a restart");
}

/// ADR-174 O-2 (the owner's decision): "Keep the Mac-bound device key out of Time Machine." The bind marks the key
/// with Time Machine's sticky exclusion before sealing under it; status reports it; an attribute that went away
/// is reported with a warning and set again by the next passphrase unlock; an unbound vault's unlock never makes
/// or touches a key.
#[cfg(target_os = "macos")]
#[test]
fn the_device_key_is_kept_out_of_time_machine_at_bind_and_again_at_every_unlock() {
    let (v, state, _entry) = bound_vault();
    assert_eq!(machine_lock::backup_excluded(&key_path(&v)), Some(true));
    let owner = login(&state);
    let st = status(&state, &owner);
    assert_eq!(st["deviceKeyTimeMachineExcluded"], true);
    assert_eq!(st["warning"], Value::Null);
    drop(state);

    // Something drops the attribute (a copy, a restore by another tool).
    let removed = std::process::Command::new("/usr/bin/xattr")
        .args(["-d", machine_lock::BACKUP_EXCLUDE_XATTR])
        .arg(key_path(&v))
        .status()
        .unwrap();
    assert!(removed.success());
    assert_eq!(machine_lock::backup_excluded(&key_path(&v)), Some(false));
    // The key's bytes are what they were; only the attribute changed.
    let key_bytes = std::fs::read(key_path(&v)).unwrap();

    let state = v.broker(None);
    let token = unlock_with(&state, PASSPHRASE).unwrap()["token"]
        .as_str()
        .unwrap()
        .to_string();
    // The unlock re-asserted it.
    assert_eq!(machine_lock::backup_excluded(&key_path(&v)), Some(true));
    assert_eq!(std::fs::read(key_path(&v)).unwrap(), key_bytes);
    let owner = scope_of(&state, &token);
    // Drop it again while the vault is open: status warns, in words that say what it means.
    std::process::Command::new("/usr/bin/xattr")
        .args(["-d", machine_lock::BACKUP_EXCLUDE_XATTR])
        .arg(key_path(&v))
        .status()
        .unwrap();
    let st = status(&state, &owner);
    assert_eq!(st["deviceKeyTimeMachineExcluded"], false);
    let w = st["warning"].as_str().unwrap();
    assert!(
        w.contains("Time Machine") && w.contains("next unlock"),
        "{w}"
    );
    assert!(
        !w.contains(&*v.state_dir.to_string_lossy()),
        "no path in the warning: {w}"
    );

    // While the key is not excluded, Time Machine is not claimed, and doesNotProtect says why.
    assert_eq!(st["deviceKeyTimeMachineCovered"], false);
    assert!(!st["protects"].as_str().unwrap().contains("Time Machine"));
    assert!(st["doesNotProtect"]
        .as_str()
        .unwrap()
        .contains("Time Machine backups that may hold this Mac's device key"));

    // An unbound vault: an unlock makes no key and marks nothing.
    let (u, s) = created_vault(None);
    drop(s);
    let s = u.broker(None);
    unlock_with(&s, PASSPHRASE).unwrap();
    assert!(!key_path(&u).exists());
    let o = login(&s);
    assert_eq!(status(&s, &o)["deviceKeyTimeMachineExcluded"], Value::Null);
}

/// ADR-174 O-2, the security review of the first build: a device key that already existed before the bind (made
/// before ADR-174: no exclusion attribute, no provenance) may be in older Time Machine backups. Binding a plain
/// vault puts it aside (excluded, renamed into `machine/retired/`, never deleted) and seals under a fresh key made
/// already excluded, so Time Machine is claimed; when another vault on this Mac is bound (and may be sealed under
/// the old key) the key is kept and excluded, and Time Machine is not claimed — doesNotProtect says why.
#[cfg(target_os = "macos")]
#[test]
fn an_existing_device_key_that_may_be_in_time_machine_is_replaced_at_bind_or_never_claimed() {
    use std::os::unix::fs::PermissionsExt;
    let make_old_key = |v: &Vault| -> Vec<u8> {
        let dir = key_path(v).parent().unwrap().to_path_buf();
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let old: Vec<u8> = (0..32u8)
            .map(|i| i.wrapping_mul(7).wrapping_add(3))
            .collect();
        std::fs::write(key_path(v), &old).unwrap();
        std::fs::set_permissions(key_path(v), std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(machine_lock::backup_excluded(&key_path(v)), Some(false));
        old
    };
    let old_id = |old: &[u8]| {
        let arr: [u8; 32] = old.try_into().unwrap();
        machine_lock::key_id_hex(&machine_lock::DeviceKey::from_bytes(&arr).id())
    };

    // Alone on this Mac: replaced.
    let (v, state) = created_vault(None);
    let old = make_old_key(&v);
    let owner = login(&state);
    let answer = bind(&v, &state, &owner);
    assert_eq!(answer["bound"], true, "{answer}");
    assert_eq!(answer["deviceKeyReplaced"], true);
    assert_eq!(answer["deviceKeyCreated"], true);
    assert_ne!(answer["deviceKeyId"], json!(old_id(&old)));
    assert_eq!(answer["sealedKeyId"], answer["deviceKeyId"]);
    let retired = key_path(&v)
        .parent()
        .unwrap()
        .join("retired")
        .join(format!("{}.key", old_id(&old)));
    assert_eq!(std::fs::read(&retired).unwrap(), old, "kept, never deleted");
    assert_eq!(machine_lock::backup_excluded(&retired), Some(true));
    assert_eq!(machine_lock::backup_excluded(&key_path(&v)), Some(true));
    assert_eq!(answer["deviceKeyTimeMachineCovered"], true);
    assert!(answer["protects"]
        .as_str()
        .unwrap()
        .contains("Time Machine"));
    // The vault opens with the passphrase on a fresh broker, under the new key.
    drop(state);
    let state = v.broker(None);
    unlock_with(&state, PASSPHRASE).expect("opens under the fresh key");
    drop(state);

    // Another vault on this Mac is bound: the key is kept (excluded from now on) and never claimed.
    let (w, state) = created_vault(None);
    let old = make_old_key(&w);
    let vaults = key_path(&w).parent().unwrap().join("vaults");
    std::fs::create_dir_all(&vaults).unwrap();
    let other_id = "0123456789abcdef0123456789abcdef";
    std::fs::write(
        vaults.join(format!("{other_id}.json")),
        json!({ "v": 2, "vaultId": other_id, "vault": "/elsewhere/another-vault" }).to_string(),
    )
    .unwrap();
    let owner = login(&state);
    let answer = bind(&w, &state, &owner);
    assert_eq!(answer["bound"], true, "{answer}");
    assert_eq!(answer["deviceKeyReplaced"], false);
    assert_eq!(answer["deviceKeyCreated"], false);
    assert_eq!(answer["deviceKeyId"], json!(old_id(&old)));
    assert_eq!(std::fs::read(key_path(&w)).unwrap(), old);
    assert_eq!(machine_lock::backup_excluded(&key_path(&w)), Some(true));
    assert_eq!(answer["deviceKeyTimeMachineCovered"], false);
    assert!(!answer["protects"]
        .as_str()
        .unwrap()
        .contains("Time Machine"));
    assert!(answer["doesNotProtect"]
        .as_str()
        .unwrap()
        .contains("Time Machine backups that may hold this Mac's device key"));
    // Status says the same.
    let st = status(&state, &owner);
    assert_eq!(st["deviceKeyTimeMachineCovered"], false);
}

/// ADR-174 O-5 (the owner's decision): "Turning the machine lock on needs Touch ID or your authenticator code." With
/// a presence key enrolled, the prepare and the commit each need a presence proof for exactly that request (one
/// made for the prepare does not open the commit), and a missing proof changes nothing and keeps the prepared bind;
/// a request refused anyway (a synced folder) is refused before any prompt. Status says what bind asks for.
#[test]
fn turning_the_lock_on_needs_touch_id_for_each_phase_where_a_presence_key_is_enrolled() {
    let (v, state) = created_vault(None);
    let owner = login(&state);
    assert_eq!(status(&state, &owner)["bindProof"], "none");
    let key = enrol_key(&state, &owner);
    assert_eq!(status(&state, &owner)["bindProof"], "presence");
    let before = snapshot(&v.vault_dir);

    let r = call(&state, &owner, NOW, "keystore.bind", bind_params(&v));
    assert!(matches!(r, Err(OpError::PresenceRequired { .. })), "{r:?}");
    assert!(!state.machine_lock_bind_pending(NOW));
    let proved = with_proof(&state, &owner, &key, NOW, "keystore.bind", bind_params(&v));
    let p = call(&state, &owner, NOW, "keystore.bind", proved).expect("prepare with Touch ID");
    let new_code = p["newRecoveryCode"].as_str().unwrap().to_string();
    assert_eq!(
        snapshot(&v.vault_dir),
        before,
        "the prepare changed nothing"
    );

    // The commit asks again; without a proof nothing changes and the prepared bind waits.
    let commit_params = json!({ "phase": "commit", "recoveryCode": new_code });
    let r = call(&state, &owner, NOW, "keystore.bind", commit_params.clone());
    assert!(matches!(r, Err(OpError::PresenceRequired { .. })), "{r:?}");
    assert_eq!(snapshot(&v.vault_dir), before);
    assert!(state.machine_lock_bind_pending(NOW));
    // A proof made for another request (here: the prepare's) does not open the commit.
    let wrong = with_proof(&state, &owner, &key, NOW, "keystore.bind", bind_params(&v));
    let mut replay = commit_params.clone();
    replay["presence"] = wrong["presence"].clone();
    let r = call(&state, &owner, NOW, "keystore.bind", replay);
    assert!(matches!(r, Err(OpError::PresenceFailed { .. })), "{r:?}");
    assert_eq!(snapshot(&v.vault_dir), before);
    let proved = with_proof(&state, &owner, &key, NOW, "keystore.bind", commit_params);
    let done = call(&state, &owner, NOW, "keystore.bind", proved).expect("commit with Touch ID");
    assert_eq!(done["bound"], true);
    assert_eq!(
        form(&v),
        WrapForm::Sealed {
            key_id: machine_lock::DeviceKey::load(&key_path(&v))
                .unwrap()
                .unwrap()
                .id()
        }
    );
    // Cancel never asks (it only forgets).
    call(
        &state,
        &owner,
        NOW,
        "keystore.bind",
        json!({ "phase": "cancel" }),
    )
    .expect("cancel");

    // A request refused anyway is refused before any prompt: a synced folder answers its own refusal.
    let root = tempfile::tempdir().unwrap();
    let dropbox = root.path().join("Dropbox");
    std::fs::create_dir_all(&dropbox).unwrap();
    std::fs::write(dropbox.join(".dropbox"), b"{}").unwrap();
    let (w, s) = vault_at(root, dropbox.join("vault"));
    let o = login(&s);
    enrol_key(&s, &o);
    expect_synced_refusal(
        call(&s, &o, NOW, "keystore.bind", bind_params(&w)),
        "Dropbox",
    );
}

/// ADR-174 O-5: with a second factor enrolled and no presence key, each phase needs it fresh (the five-minute
/// window a step-up opens). A refusal is `two_factor_required`, changes nothing, is not a counted guess, and keeps
/// the prepared bind, so a commit typed after the window closed works once the factor is given again.
#[test]
fn turning_the_lock_on_needs_a_fresh_second_factor_where_one_is_enrolled_and_no_touch_id() {
    let (v, state) = created_vault(None);
    let owner = login(&state);
    let totp = enrol_gate(&state, &owner);
    assert_eq!(status(&state, &owner)["bindProof"], "secondFactor");
    // (A step-up records the code it used in the vault, so "nothing changed" is checked around each refusal.)
    let before = snapshot(&v.vault_dir);
    let r = call(&state, &owner, LATER, "keystore.bind", bind_params(&v));
    assert!(matches!(r, Err(OpError::TwoFactorRequired { .. })), "{r:?}");
    assert!(!state.machine_lock_bind_pending(LATER));
    assert_eq!(snapshot(&v.vault_dir), before);
    step_up(&state, &owner, &totp, LATER);
    let p = call(&state, &owner, LATER, "keystore.bind", bind_params(&v)).expect("prepare");
    let new_code = p["newRecoveryCode"].as_str().unwrap().to_string();

    // The code written down slowly: the window has closed by the commit, inside the prepared bind's ten minutes.
    let late = LATER + 400;
    let before = snapshot(&v.vault_dir);
    let r = commit(&state, &owner, late, Some(&new_code));
    assert!(matches!(r, Err(OpError::TwoFactorRequired { .. })), "{r:?}");
    assert_eq!(snapshot(&v.vault_dir), before);
    assert!(
        state.machine_lock_bind_pending(late),
        "the prepared bind waits"
    );
    step_up(&state, &owner, &totp, late);
    let done = commit(&state, &owner, late, Some(&new_code)).expect("commit");
    assert_eq!(done["bound"], true);
    *v.recovery_code.borrow_mut() = new_code;
}

/// A vault created at `vault_dir` (made here), its state folder beside the temporary root.
fn vault_at(root: tempfile::TempDir, vault_dir: std::path::PathBuf) -> (Vault, Arc<BrokerState>) {
    std::fs::create_dir_all(&vault_dir).unwrap();
    let state_dir = root.path().join("state");
    std::fs::create_dir_all(&state_dir).unwrap();
    let v = Vault {
        vault_dir,
        state_dir,
        recovery_code: std::cell::RefCell::new(String::new()),
        _dir: root,
    };
    let state = v.broker(None);
    let begin = call(
        &state,
        &anyone(),
        NOW,
        "vault.init_begin",
        json!({ "passphrase": PASSPHRASE }),
    )
    .expect("init_begin");
    let code = begin["recoveryCode"].as_str().unwrap().to_string();
    call(
        &state,
        &anyone(),
        NOW,
        "vault.init_confirm",
        json!({ "recoveryCode": code }),
    )
    .expect("init_confirm");
    *v.recovery_code.borrow_mut() = code;
    (v, state)
}

fn expect_synced_refusal(r: Result<Value, OpError>, label: &str) {
    match r {
        Err(OpError::Malformed(m)) => assert!(
            m.contains("nothing changed") && m.contains(label) && m.contains("another Mac"),
            "{m}"
        ),
        other => panic!("expected the synced-folder refusal ({label}), got {other:?}"),
    }
}

/// ADR-174 O-3 (the owner's decision): "Refuse to lock a vault folder that two Macs share (iCloud/Dropbox)." A
/// vault folder in iCloud Drive, in a CloudStorage provider's folder or under a `.dropbox` marker is refused at
/// the prepare, before anything is proven or written (no device key, the wrap byte for byte as it was, no code
/// drawn), and status names the service; a folder that becomes synced between the phases is refused at the
/// commit, which keeps the prepared bind, and the bind goes through once the folder is out of it.
#[test]
fn bind_refuses_a_vault_folder_that_a_sync_service_shares_with_other_macs() {
    for (sub, label) in [
        (
            vec![
                "Library",
                "Mobile Documents",
                "com~apple~CloudDocs",
                "vault",
            ],
            "iCloud Drive",
        ),
        (
            vec!["Library", "CloudStorage", "Dropbox", "vault"],
            "Dropbox",
        ),
        (
            vec![
                "Library",
                "CloudStorage",
                "GoogleDrive-someone@example.com",
                "vault",
            ],
            "Google Drive",
        ),
    ] {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        let mut at = home.clone();
        for s in &sub {
            at.push(s);
        }
        let (v, state) = vault_at(root, at);
        state.set_sync_home_for_test(Some(home.clone()));
        let owner = login(&state);
        let before = snapshot(&v.vault_dir);
        let r = call(&state, &owner, NOW, "keystore.bind", bind_params(&v));
        expect_synced_refusal(r, label);
        assert_eq!(snapshot(&v.vault_dir), before, "nothing changed: {label}");
        assert!(!key_path(&v).exists(), "no device key was made: {label}");
        let st = status(&state, &owner);
        assert_eq!(st["syncedFolder"], label);
        assert_eq!(st["bound"], false);
        assert!(!st.to_string().contains("someone@example.com"));
        // A commit is refused the same way (and nothing waits for it anyway).
        expect_synced_refusal(commit(&state, &owner, NOW, Some("anything")), label);
        assert!(!state.machine_lock_bind_pending(NOW));
    }

    // A `.dropbox` marker in a parent (a Dropbox folder outside CloudStorage), found with no home at all.
    let root = tempfile::tempdir().unwrap();
    let dropbox = root.path().join("Dropbox");
    let (v, state) = vault_at(root, dropbox.join("work").join("vault"));
    let owner = login(&state);
    assert_eq!(status(&state, &owner)["syncedFolder"], Value::Null);
    // Prepared while the folder was not synced; then the folder becomes a Dropbox folder.
    let new_code = prepare(&v, &state, &owner);
    std::fs::write(dropbox.join(".dropbox"), b"{}").unwrap();
    let before = snapshot(&v.vault_dir);
    expect_synced_refusal(commit(&state, &owner, NOW, Some(&new_code)), "Dropbox");
    assert_eq!(snapshot(&v.vault_dir), before);
    assert!(!key_path(&v).exists());
    assert!(
        state.machine_lock_bind_pending(NOW),
        "the prepared bind still waits"
    );
    std::fs::remove_file(dropbox.join(".dropbox")).unwrap();
    let done =
        commit(&state, &owner, NOW, Some(&new_code)).expect("commit once the folder is not synced");
    assert_eq!(done["bound"], true);
    assert_eq!(done["syncedFolder"], Value::Null);
}

/// ADR-174 O-3: iCloud Drive's Desktop & Documents sync keeps `~/Desktop` in place and marks it with File Provider
/// attributes; a vault under such a folder is refused.
#[cfg(target_os = "macos")]
#[test]
fn bind_refuses_a_vault_under_a_folder_a_file_provider_marks() {
    let root = tempfile::tempdir().unwrap();
    let desktop = root.path().join("Desktop");
    let (v, state) = vault_at(root, desktop.join("vault"));
    let ok = std::process::Command::new("/usr/bin/xattr")
        .args(["-w", "com.apple.fileprovider.detached#B", "1"])
        .arg(&desktop)
        .status()
        .unwrap()
        .success();
    assert!(ok);
    let owner = login(&state);
    expect_synced_refusal(
        call(&state, &owner, NOW, "keystore.bind", bind_params(&v)),
        "Desktop & Documents",
    );
    assert!(!key_path(&v).exists());
    assert_eq!(form(&v), WrapForm::Plain);
}

#[test]
fn bind_refuses_a_vault_with_no_recovery_code_and_changes_nothing() {
    let (v, state) = created_vault(None);
    let owner = login(&state);
    std::fs::remove_file(v.paths().root_wrap_recovery()).unwrap();
    let before = pass_wrap(&v);
    match call(&state, &owner, NOW, "keystore.bind", bind_params(&v)) {
        Err(OpError::Malformed(m)) => assert!(m.contains("recovery code"), "{m}"),
        other => panic!("{other:?}"),
    }
    assert_eq!(pass_wrap(&v), before);
    assert!(!key_path(&v).exists(), "no key is made for a refused bind");
    // A damaged recovery wrap is no recovery code either.
    std::fs::write(v.paths().root_wrap_recovery(), b"junk").unwrap();
    assert!(matches!(
        call(&state, &owner, NOW, "keystore.bind", bind_params(&v)),
        Err(OpError::Malformed(_))
    ));
    assert_eq!(pass_wrap(&v), before);
}

#[test]
fn bind_refuses_a_device_key_inside_the_vault_folder() {
    let (v, state) = created_vault(None);
    let owner = login(&state);
    let inside = v.vault_dir.join("state-inside");
    state.set_state_dir_for_test(inside.clone());
    let before = pass_wrap(&v);
    match call(&state, &owner, NOW, "keystore.bind", bind_params(&v)) {
        Err(OpError::Malformed(m)) => assert!(m.contains("inside the vault folder"), "{m}"),
        other => panic!("{other:?}"),
    }
    assert_eq!(pass_wrap(&v), before);
    assert!(!inside.join("machine").exists());
}

/// Review P2-2: a rotation of a bound vault whose state directory is inside the vault folder does not make
/// the key there; it writes the wrap unsealed and says so (`machineLockRemoved`), and status names it.
#[test]
fn a_rotation_never_makes_the_device_key_inside_the_vault_folder_and_says_the_lock_was_removed() {
    let (v, state, entry) = bound_vault();
    let owner = login(&state);
    // Keep the bind record where the moved state directory will look for it.
    let inside = v.vault_dir.join("state-inside");
    copy_dir(&v.state_dir, &inside);
    std::fs::remove_dir_all(inside.join("machine").join("lock.key")).ok();
    std::fs::remove_file(inside.join("machine").join("lock.key")).ok();
    state.set_state_dir_for_test(inside.clone());
    let presence = enrol_key(&state, &owner);
    // The passphrase is proven through the real device key first, so give the rotation one to read…
    std::fs::copy(key_path(&v), inside.join("machine").join("lock.key")).unwrap();
    // …then the rotation's own reseal: it must refuse to use a key under the vault folder.
    let proved = with_proof(
        &state,
        &owner,
        &presence,
        NOW,
        "maintenance.rotate_root",
        json!({ "passphrase": PASSPHRASE }),
    );
    let r = call(&state, &owner, NOW, "maintenance.rotate_root", proved).expect("rotate");
    assert_eq!(r["machineLocked"], false);
    assert!(
        r["machineLockRemoved"]
            .as_str()
            .unwrap()
            .contains("inside the vault folder"),
        "{r}"
    );
    assert_eq!(form(&v), WrapForm::Plain);
    let st = status(&state, &owner);
    assert_eq!(st["plainWhileBound"], true);
    assert!(st["warning"].as_str().is_some());
    assert_eq!(reveal(&state, &owner, "acme", &entry), "alpha-secret");
}

/// Review P1-4: a recovery whose device key cannot be read or made keeps the vault openable, writes the wrap
/// unsealed, and says so in the answer and in status — never silently.
#[test]
fn a_recovery_that_cannot_seal_says_the_lock_was_removed_and_status_keeps_saying_it() {
    let (v, state, entry) = bound_vault();
    drop(state);
    // Something that is not a key file in the key's place: it is never replaced.
    std::fs::remove_file(key_path(&v)).unwrap();
    std::fs::create_dir(key_path(&v)).unwrap();
    let state = v.broker(None);
    refused_with(unlock_with(&state, PASSPHRASE), "device_key_unreadable");
    let r = recover(&state, &v.recovery_code.borrow(), NEW_PASSPHRASE).expect("recover");
    assert_eq!(r["machineLocked"], false);
    assert!(r["machineLockRemoved"].as_str().is_some(), "{r}");
    assert_eq!(form(&v), WrapForm::Plain);
    let owner = scope_of(&state, r["token"].as_str().unwrap());
    assert_eq!(reveal(&state, &owner, "acme", &entry), "alpha-secret");
    let st = status(&state, &owner);
    assert_eq!(st["plainWhileBound"], true);
    assert!(st["warning"].as_str().is_some());
    assert!(
        key_path(&v).is_dir(),
        "the thing in the key's place is left alone"
    );
}

#[test]
fn unbind_needs_the_second_factor_and_presence_where_enrolled_and_keeps_the_device_key() {
    let (v, state) = created_vault(None);
    let owner = login(&state);
    bind(&v, &state, &owner);
    let key = enrol_key(&state, &owner);
    let totp = enrol_gate(&state, &owner);
    let sealed = pass_wrap(&v);

    // Long after the enrolment's elevation: the second factor first.
    let r = call(&state, &owner, LATER, "keystore.unbind", json!({}));
    assert!(matches!(r, Err(OpError::TwoFactorRequired { .. })), "{r:?}");
    assert_eq!(pass_wrap(&v), sealed);
    step_up(&state, &owner, &totp, LATER);
    // Then presence.
    let r = call(&state, &owner, LATER, "keystore.unbind", json!({}));
    assert!(matches!(r, Err(OpError::PresenceRequired { .. })), "{r:?}");
    assert_eq!(pass_wrap(&v), sealed);
    // A proof for another op does not count.
    let wrong = with_proof(&state, &owner, &key, LATER, "device.remove", json!({}));
    let r = call(&state, &owner, LATER, "keystore.unbind", wrong);
    assert!(r.is_err(), "{r:?}");
    assert_eq!(pass_wrap(&v), sealed);

    let proved = with_proof(&state, &owner, &key, LATER, "keystore.unbind", json!({}));
    let u = call(&state, &owner, LATER, "keystore.unbind", proved).expect("unbind");
    assert_eq!(u["changed"], true);
    assert_eq!(u["bound"], false);
    assert_eq!(form(&v), WrapForm::Plain);
    assert!(
        key_path(&v).is_file(),
        "the device key is kept for older backups"
    );
    // Plain again: a copy without the key opens with the passphrase.
    drop(state);
    std::fs::remove_file(key_path(&v)).unwrap();
    let state = v.broker(None);
    // The passphrase passed (factor one); the enrolled gate now asks for its code.
    let r = unlock_with(&state, PASSPHRASE);
    assert!(
        matches!(r, Err(OpError::TwoFactorRequired { .. })),
        "unbound opens without the key: {r:?}"
    );
}

/// Review P2-4: with no Touch ID key and no second factor enrolled, unbind asks for the passphrase, and a
/// wrong one is a wrong passphrase (counted), changing nothing.
#[test]
fn unbind_with_nothing_enrolled_needs_the_passphrase() {
    let (v, state, _) = bound_vault();
    let owner = login(&state);
    let sealed = pass_wrap(&v);
    match call(&state, &owner, NOW, "keystore.unbind", json!({})) {
        Err(OpError::Malformed(m)) => assert!(m.contains("passphrase"), "{m}"),
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        call(
            &state,
            &owner,
            NOW,
            "keystore.unbind",
            json!({ "passphrase": "not the passphrase" })
        ),
        Err(OpError::WrongPassphrase)
    ));
    assert_eq!(pass_wrap(&v), sealed);
    let u = call(
        &state,
        &owner,
        NOW,
        "keystore.unbind",
        json!({ "passphrase": PASSPHRASE }),
    )
    .expect("unbind");
    assert_eq!(u["changed"], true);
    assert_eq!(form(&v), WrapForm::Plain);
    assert_eq!(
        u["plainWhileBound"], false,
        "the bind record goes with the unbind"
    );
}

#[test]
fn an_agent_is_refused_every_keystore_op_before_anything_is_read() {
    let (v, state) = created_vault(None);
    let owner = login(&state);
    let workdir = v._dir.path().join("acme-src");
    std::fs::create_dir_all(&workdir).unwrap();
    call(
        &state,
        &owner,
        NOW,
        "node.create",
        json!({ "id": "acme", "label": "Acme", "parentId": "global",
                "workdirs": [workdir.to_string_lossy()] }),
    )
    .expect("node.create");
    let before = pass_wrap(&v);
    let touches = state.machine_lock_touches_for_test();
    let mut agent = anyone();
    agent.token_id = Some("an-agent-token".to_string());
    agent.origin = Origin::Agent;
    for op in ["keystore.status", "keystore.bind", "keystore.unbind"] {
        let r = call(&state, &agent, NOW, op, bind_params(&v));
        assert!(
            matches!(r, Err(OpError::CapabilityNotHeld { .. })),
            "{op}: {r:?}"
        );
        // A token-less caller in a project folder, through the server.
        let (r, _) = server::handle_request_at(
            &state,
            &credmgr_brokerd::peer::PeerInfo {
                uid: 501,
                pid: 1,
                cwd: Some(workdir.to_string_lossy().into_owned()),
            },
            &Request {
                id: "r".into(),
                op: op.into(),
                token: None,
                params: bind_params(&v),
            },
            NOW,
            Instant::now(),
        );
        assert!(
            matches!(r, Err(OpError::CapabilityNotHeld { .. })),
            "{op}: {r:?}"
        );
    }
    // Review P2-8: not one of those requests reached the machine-lock code (status, bind or unbind) — the
    // refusal came before anything was read, not merely before anything changed.
    assert_eq!(state.machine_lock_touches_for_test(), touches);
    assert_eq!(pass_wrap(&v), before);
    assert!(!key_path(&v).exists());
    // The counter does count: the owner's status reaches it.
    status(&state, &owner);
    assert_eq!(state.machine_lock_touches_for_test(), touches + 1);
    // A locked vault cannot be bound.
    state.lock();
    assert!(call(&state, &owner, NOW, "keystore.bind", bind_params(&v)).is_err());
    assert_eq!(pass_wrap(&v), before);
}

#[test]
fn rotation_and_a_passphrase_change_while_bound_reseal_to_the_same_key() {
    let (v, state, entry) = bound_vault();
    let WrapForm::Sealed { key_id } = form(&v) else {
        panic!()
    };
    let owner = login(&state);
    let presence = enrol_key(&state, &owner);
    let ask = json!({ "passphrase": PASSPHRASE });
    let proved = with_proof(
        &state,
        &owner,
        &presence,
        NOW,
        "maintenance.rotate_root",
        ask,
    );
    let r = call(&state, &owner, NOW, "maintenance.rotate_root", proved).expect("rotate");
    assert_eq!(r["machineLocked"], true);
    assert!(r.get("deviceKeyCreated").is_none());
    assert_eq!(form(&v), WrapForm::Sealed { key_id });
    let (state, owner) = restart(&v, state, None);
    assert_eq!(reveal(&state, &owner, "acme", &entry), "alpha-secret");

    let ask = json!({ "passphrase": PASSPHRASE, "newPassphrase": NEW_PASSPHRASE });
    let proved = with_proof(&state, &owner, &presence, NOW, "vault.set_passphrase", ask);
    let p = call(&state, &owner, NOW, "vault.set_passphrase", proved).expect("set_passphrase");
    assert_eq!(p["machineLocked"], true);
    // ADR-165 N5: the change re-keyed every live node too, inside the same rotation.
    assert_eq!(p["nodesRekeyed"], json!(["acme", "global"]), "{p}");
    assert_eq!(form(&v), WrapForm::Sealed { key_id });
    drop(state);
    let state = v.broker(None);
    assert!(matches!(
        unlock_with(&state, PASSPHRASE),
        Err(OpError::WrongPassphrase)
    ));
    let token = unlock_with(&state, NEW_PASSPHRASE).expect("new passphrase")["token"]
        .as_str()
        .unwrap()
        .to_string();
    let owner = scope_of(&state, &token);
    assert_eq!(reveal(&state, &owner, "acme", &entry), "alpha-secret");
    // The bound state is whole after the re-key: still bound, opening here, the record attached, no node left
    // on a pre-bind key (each has a newer one), nothing to warn about.
    let st = status(&state, &owner);
    assert_eq!(st["bound"], true);
    assert_eq!(st["opensHere"], true);
    assert_eq!(st["markedBound"], true);
    assert_eq!(st["preBindNodes"], json!([]));
    assert_eq!(st["recordDetached"], false);
    assert_eq!(st["warning"], Value::Null, "{st}");

    // The device key removed while the vault is open: a rotation cannot prove the passphrase through it and
    // refuses with the machine-lock answer, changing nothing.
    let before = pass_wrap(&v);
    let real = std::fs::read(key_path(&v)).unwrap();
    std::fs::remove_file(key_path(&v)).unwrap();
    let ask = json!({ "passphrase": NEW_PASSPHRASE });
    let proved = with_proof(
        &state,
        &owner,
        &presence,
        NOW,
        "maintenance.rotate_root",
        ask,
    );
    refused_with(
        call(&state, &owner, NOW, "maintenance.rotate_root", proved),
        "device_key_missing",
    );
    assert_eq!(pass_wrap(&v), before);
    std::fs::write(key_path(&v), real).unwrap();
}

/// A copy of a bound vault's folder (not a CredMgr archive) on a new machine: the passphrase is refused, the
/// recovery code opens it and binds it to the new machine's key; the old machine's key no longer opens it.
#[test]
fn a_folder_copy_on_a_new_machine_opens_with_the_recovery_code_and_binds_there() {
    let (v, state, entry) = bound_vault();
    drop(state);
    let device_key = std::fs::read(key_path(&v)).unwrap();
    let sealed = pass_wrap(&v);
    let new = tempfile::tempdir().unwrap();
    let moved = Vault {
        vault_dir: new.path().join("vault"),
        state_dir: new.path().join("state"),
        recovery_code: std::cell::RefCell::new(v.recovery_code.borrow().clone()),
        _dir: new,
    };
    copy_dir(&v.vault_dir, &moved.vault_dir);
    // The rollback counter is carried over as a move would (it lives in the state directory); the device key
    // is not.
    std::fs::create_dir_all(&moved.state_dir).unwrap();
    std::fs::copy(
        v.state_dir.join("vaultGeneration.counter"),
        moved.state_dir.join("vaultGeneration.counter"),
    )
    .unwrap();
    assert_eq!(pass_wrap(&moved), sealed);
    let s = moved.broker(None);
    refused_with(unlock_with(&s, PASSPHRASE), "device_key_missing");
    let answer = recover(&s, &moved.recovery_code.borrow(), NEW_PASSPHRASE).expect("recover");
    assert_eq!(answer["locked"], false);
    assert_eq!(answer["machineLocked"], true, "bound to the new machine");
    assert_eq!(answer["deviceKeyCreated"], true);
    let new_key = std::fs::read(key_path(&moved)).unwrap();
    assert_ne!(new_key, device_key);
    let o = scope_of(&s, answer["token"].as_str().unwrap());
    assert_eq!(reveal(&s, &o, "acme", &entry), "alpha-secret");
    let st = status(&s, &o);
    assert_eq!(st["bound"], true);
    assert_eq!(st["opensHere"], true);
    drop(s);
    let s = moved.broker(None);
    unlock_with(&s, NEW_PASSPHRASE).expect("new passphrase on the new machine");
    drop(s);
    std::fs::write(key_path(&moved), &device_key).unwrap();
    let s = moved.broker(None);
    refused_with(unlock_with(&s, NEW_PASSPHRASE), "device_key_mismatch");
}

#[test]
fn the_recovery_code_opens_a_bound_vault_whose_device_key_is_lost_on_the_same_machine() {
    let (v, state, entry) = bound_vault();
    drop(state);
    let old = std::fs::read(key_path(&v)).unwrap();
    std::fs::remove_file(key_path(&v)).unwrap();
    let state = v.broker(None);
    let answer = recover(&state, &v.recovery_code.borrow(), NEW_PASSPHRASE).expect("recover");
    assert_eq!(answer["machineLocked"], true);
    assert_eq!(answer["deviceKeyCreated"], true);
    assert_ne!(std::fs::read(key_path(&v)).unwrap(), old);
    let owner = scope_of(&state, answer["token"].as_str().unwrap());
    assert_eq!(reveal(&state, &owner, "acme", &entry), "alpha-secret");
}

fn walk(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            out.extend(walk(&p));
        } else {
            out.push(p);
        }
    }
    out
}

/// Review N1: a bind's prepare proves both factors and shows the new code, and changes nothing durable: no
/// file in the vault folder or the state folder changes, no device key, no bind record, no identity file.
/// Abandoned in every way it can be (a restart, a lock, the time running out, a cancel, a rotation in
/// between), the old code and the old root key keep working and the commit is refused. A wrong code typed
/// back is refused, changes nothing, is not a counted guess, and the right one then commits.
#[test]
fn bind_is_two_phase_and_an_abandoned_prepare_leaves_the_old_code_and_root_fully_valid() {
    let (v, state) = created_vault(None);
    let owner = login(&state);
    create_node(&state, &owner, "acme");
    let entry = create_entry(&state, &owner, "acme", "API_KEY", "alpha-secret");
    let old_code = v.recovery_code.borrow().clone();
    let vault_before = snapshot(&v.vault_dir);
    let state_before = snapshot(&v.state_dir);
    let root_before = root_key(&v);

    let p = bind_call(&state, &owner, NOW, bind_params(&v)).expect("prepare");
    let shown = p["newRecoveryCode"].as_str().unwrap().to_string();
    assert_ne!(shown, old_code);
    assert_eq!(p["expiresIn"], BIND_PREPARE_SECONDS);
    assert_eq!(p["bound"], false, "{p}");
    assert_eq!(p["already"], false);
    assert!(state.machine_lock_bind_pending(NOW));
    assert_eq!(
        snapshot(&v.vault_dir),
        vault_before,
        "prepare writes nothing in the vault folder"
    );
    assert_eq!(
        snapshot(&v.state_dir),
        state_before,
        "nor in the state folder"
    );
    assert!(!key_path(&v).exists() && !v.vault_dir.join("vault.id").exists());
    assert_eq!(status(&state, &owner)["markedBound"], false);

    // Abandoned by a restart (a crash, a quit): the prepared bind is gone, the commit is refused, and the old
    // code still proves itself (the next prepare takes it) under the old root key.
    let (state, owner) = restart(&v, state, None);
    expect_not_prepared(
        commit(&state, &owner, NOW, Some(&shown)),
        "no bind is waiting",
    );
    assert_eq!(root_key(&v), root_before);
    assert_eq!(snapshot(&v.vault_dir), vault_before);

    // Abandoned by a lock.
    let shown = prepare(&v, &state, &owner);
    state.lock();
    let owner = login(&state);
    expect_not_prepared(
        commit(&state, &owner, NOW, Some(&shown)),
        "no bind is waiting",
    );

    // Abandoned by the time running out.
    let shown = prepare(&v, &state, &owner);
    expect_not_prepared(
        commit(&state, &owner, NOW + BIND_PREPARE_SECONDS + 1, Some(&shown)),
        "expired",
    );
    expect_not_prepared(
        commit(&state, &owner, NOW, Some(&shown)),
        "no bind is waiting",
    );

    // Cancelled.
    let shown = prepare(&v, &state, &owner);
    let c = call(
        &state,
        &owner,
        NOW,
        "keystore.bind",
        json!({ "phase": "cancel" }),
    )
    .expect("cancel");
    assert_eq!(c["changed"], false);
    expect_not_prepared(
        commit(&state, &owner, NOW, Some(&shown)),
        "no bind is waiting",
    );
    assert_eq!(snapshot(&v.vault_dir), vault_before);
    assert_eq!(*v.recovery_code.borrow(), old_code);

    // Overtaken by a rotation between the phases: the prepared material belongs to a root key the vault no
    // longer runs under, so the commit is refused and nothing of the prepare is used.
    let shown = prepare(&v, &state, &owner);
    let presence = enrol_key(&state, &owner);
    let proved = with_proof(
        &state,
        &owner,
        &presence,
        NOW,
        "maintenance.rotate_root",
        json!({ "passphrase": PASSPHRASE }),
    );
    let r = call(&state, &owner, NOW, "maintenance.rotate_root", proved).expect("rotate");
    *v.recovery_code.borrow_mut() = r["recoveryCode"].as_str().unwrap().to_string();
    expect_not_prepared(
        commit(&state, &owner, NOW, Some(&shown)),
        "root key changed",
    );
    assert_eq!(form(&v), WrapForm::Plain);
    assert!(!key_path(&v).exists());

    // A wrong code typed back (here the old one, and a malformed one, and none): refused, nothing written,
    // the prepared bind still waits, and through the server it is never a counted guess.
    let current = v.recovery_code.borrow().clone();
    state.lock();
    let token = unlock_with(&state, PASSPHRASE).unwrap()["token"]
        .as_str()
        .unwrap()
        .to_string();
    let owner = scope_of(&state, &token);
    let shown = prepare(&v, &state, &owner);
    let before = snapshot(&v.vault_dir);
    for typed in [Some(current.as_str()), Some("not a code"), None] {
        assert!(matches!(
            commit(&state, &owner, NOW, typed),
            Err(OpError::RecoveryCodeMismatch)
        ));
    }
    let clock = Instant::now();
    for _ in 0..8 {
        let (r, _) = server::handle_request_at(
            &state,
            &peer(),
            &Request {
                id: "r".into(),
                op: "keystore.bind".into(),
                token: Some(token.clone()),
                // ADR-174 O-5: with a presence key enrolled the client attaches a proof to each commit.
                params: with_proof(
                    &state,
                    &owner,
                    &presence,
                    NOW,
                    "keystore.bind",
                    json!({ "phase": "commit", "recoveryCode": current }),
                ),
            },
            NOW,
            clock,
        );
        assert!(matches!(r, Err(OpError::RecoveryCodeMismatch)), "{r:?}");
    }
    assert!(
        state
            .auth_backoff
            .remaining_lockout(peer().uid, clock)
            .is_none(),
        "retyping the shown code guesses at nothing"
    );
    assert_eq!(snapshot(&v.vault_dir), before);
    assert!(state.machine_lock_bind_pending(NOW));

    // The right code, typed back with different spacing and case: the bind commits, and only now is the
    // device key made and the code replaced.
    let typed = shown.to_lowercase().replace('-', " ");
    let done = commit(&state, &owner, NOW, Some(&typed)).expect("commit");
    assert_eq!(done["bound"], true, "{done}");
    assert_eq!(done["changed"], true);
    assert_eq!(done["nodesRekeyed"], json!(["acme", "global"]));
    assert!(done.get("recoveryCode").is_none() && done["rotation"].get("recoveryCode").is_none());
    assert!(key_path(&v).is_file());
    assert!(!state.machine_lock_bind_pending(NOW));
    expect_not_prepared(
        commit(&state, &owner, NOW, Some(&shown)),
        "no bind is waiting",
    );
    // The code shown at the prepare is the vault's code now; the one before it is dead.
    drop(state);
    let state = v.broker(None);
    assert!(matches!(
        recover(&state, &current, NEW_PASSPHRASE),
        Err(OpError::RecoveryCodeMismatch) | Err(OpError::WrongPassphrase)
    ));
    let r = recover(&state, &shown, NEW_PASSPHRASE).expect("the typed-back code opens the vault");
    let o = scope_of(&state, r["token"].as_str().unwrap());
    assert_eq!(reveal(&state, &o, "acme", &entry), "alpha-secret");
}

/// Review N1: a crash inside the commit's rotation before its commit record (a crash during staging, or just
/// before the record) leaves the old root key, the old code and the plain wrap fully valid: the passphrase
/// opens the vault and the old code still proves itself.
#[test]
fn a_crash_in_the_commit_before_the_rotation_commits_leaves_the_old_code_working() {
    for fault in [RotationFault::DuringStaging(1), RotationFault::BeforeCommit] {
        let (v, state) = created_vault(None);
        let owner = login(&state);
        create_node(&state, &owner, "acme");
        let entry = create_entry(&state, &owner, "acme", "API_KEY", "alpha-secret");
        let old_code = v.recovery_code.borrow().clone();
        let plain = pass_wrap(&v);
        let shown = prepare(&v, &state, &owner);
        state.set_rotation_fault_for_test(Some(fault));
        assert!(
            commit(&state, &owner, NOW, Some(&shown)).is_err(),
            "{fault:?}"
        );
        state.set_rotation_fault_for_test(None);
        let (state, owner) = restart(&v, state, None);
        assert_eq!(
            pass_wrap(&v),
            plain,
            "{fault:?}: the wrap is the old plain one"
        );
        assert_eq!(reveal(&state, &owner, "acme", &entry), "alpha-secret");
        // Review M2: the record the commit wrote before its rotation is pending, so nothing counts it: no
        // false "plain file put back", and a passphrase change does not silently seal (the owner did not
        // finish the bind).
        let st = status(&state, &owner);
        assert_eq!(st["markedBound"], false, "{fault:?}: {st}");
        assert_eq!(st["plainWhileBound"], false, "{fault:?}: {st}");
        assert_eq!(st["warning"], Value::Null, "{fault:?}: {st}");
        let changed = call(
            &state,
            &owner,
            NOW,
            "vault.set_passphrase",
            json!({ "passphrase": PASSPHRASE, "newPassphrase": NEW_PASSPHRASE }),
        )
        .expect("set_passphrase");
        assert_eq!(changed["machineLocked"], false, "{fault:?}: {changed}");
        assert_eq!(form(&v), WrapForm::Plain, "{fault:?}: no silent re-lock");
        *v.recovery_code.borrow_mut() = changed["recoveryCode"].as_str().unwrap().to_string();
        assert_ne!(*v.recovery_code.borrow(), old_code);
        // The bind can be done again with the current code and the new passphrase, and it then counts.
        let done = bind_with(&v, &state, &owner, NEW_PASSPHRASE);
        assert_eq!(done["bound"], true, "{fault:?}: {done}");
        assert_eq!(status(&state, &owner)["markedBound"], true);
    }
}

/// Review M1: archives written before the bind leave the vault folder at the commit, so a folder copied
/// after the bind carries none; one that cannot be moved is reported by the commit and counted by status, and
/// binding again moves what is left.
#[test]
fn the_commit_moves_pre_bind_archives_out_of_the_vault_folder_and_status_counts_any_left() {
    let (v, state) = created_vault(None);
    let owner = login(&state);
    create_node(&state, &owner, "acme");
    create_entry(&state, &owner, "acme", "API_KEY", "alpha-secret");
    let ask = json!({ "passphrase": "an archive passphrase" });
    let first = call(&state, &owner, NOW, "maintenance.backup", ask.clone()).expect("backup");
    let second = call(&state, &owner, NOW + 1, "maintenance.backup", ask.clone()).expect("backup");
    assert_eq!(first["outsideVaultFolder"], false);
    let in_folder = |v: &Vault| -> Vec<String> {
        std::fs::read_dir(v.paths().backups_dir())
            .map(|d| {
                d.filter_map(|e| e.ok())
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .filter(|n| n.starts_with("credmgr-backup-"))
                    .collect()
            })
            .unwrap_or_default()
    };
    assert_eq!(in_folder(&v).len(), 2);
    let first_bytes = std::fs::read(first["path"].as_str().unwrap()).unwrap();

    let done = bind(&v, &state, &owner);
    assert_eq!(done["archivesMoved"], 2, "{done}");
    assert_eq!(done["archivesNotMoved"], json!([]));
    assert!(
        in_folder(&v).is_empty(),
        "no archive is left in the vault folder"
    );
    let id = std::fs::read_to_string(v.paths().vault_id()).unwrap();
    let outside = v.state_dir.join("backups").join(id.trim());
    let moved = outside.join(
        std::path::Path::new(first["path"].as_str().unwrap())
            .file_name()
            .unwrap(),
    );
    assert_eq!(std::fs::read(moved).unwrap(), first_bytes, "moved intact");
    assert!(outside
        .join(
            std::path::Path::new(second["path"].as_str().unwrap())
                .file_name()
                .unwrap()
        )
        .is_file());
    let st = status(&state, &owner);
    assert_eq!(st["inFolderArchives"], 0);
    assert_eq!(st["warning"], Value::Null);
    // A copy of the folder made now carries no archive.
    let copy = tempfile::tempdir().unwrap();
    copy_dir(v.paths().root(), copy.path());
    assert!(walk(copy.path())
        .iter()
        .all(|p| !p.to_string_lossy().contains("credmgr-backup-")));
    // The moved archives are still found (the doctor's rebuild reads both folders).
    let rebuilt = call(&state, &owner, NOW + 2, "maintenance.backup", ask.clone())
        .expect("backup while bound");
    assert_eq!(rebuilt["outsideVaultFolder"], true);

    // An archive put back into the vault folder, and one whose move fails (its name is taken in the state
    // folder): status counts it with a warning, the commit reports it, and binding again moves it once the
    // way is clear.
    std::fs::create_dir_all(v.paths().backups_dir()).unwrap();
    std::fs::write(v.paths().backups_dir().join("credmgr-backup-5.enc"), b"old").unwrap();
    std::fs::create_dir_all(outside.join("credmgr-backup-5.enc").join("in-the-way")).unwrap();
    let st = status(&state, &owner);
    assert_eq!(st["inFolderArchives"], 1, "{st}");
    assert!(
        st["warning"]
            .as_str()
            .unwrap()
            .contains("still in the vault folder"),
        "{st}"
    );
    let p = bind_call(&state, &owner, NOW, bind_params(&v)).expect("prepare (already)");
    assert_eq!(p["already"], true);
    let again = commit(&state, &owner, NOW, None).expect("commit (already)");
    assert_eq!(again["archivesMoved"], 0, "{again}");
    assert_eq!(
        again["archivesNotMoved"][0]["file"], "credmgr-backup-5.enc",
        "{again}"
    );
    assert_eq!(status(&state, &owner)["inFolderArchives"], 1);
    std::fs::remove_dir_all(outside.join("credmgr-backup-5.enc")).unwrap();
    bind_call(&state, &owner, NOW, bind_params(&v)).expect("prepare (already)");
    let third = commit(&state, &owner, NOW, None).expect("commit (already)");
    assert_eq!(third["archivesMoved"], 1, "{third}");
    assert_eq!(status(&state, &owner)["inFolderArchives"], 0);
    assert_eq!(
        std::fs::read(outside.join("credmgr-backup-5.enc")).unwrap(),
        b"old"
    );
}

/// Review M3: a bind record that cannot be removed stops the unbind with the file still sealed and nothing
/// changed, rather than leave a plain file beside a record that would turn the lock back on later.
#[test]
fn an_unbind_whose_record_cannot_be_removed_fails_cleanly_and_leaves_the_lock_on() {
    let (v, state, entry) = bound_vault();
    let owner = login(&state);
    let id = std::fs::read_to_string(v.paths().vault_id()).unwrap();
    let record = v
        .state_dir
        .join("machine")
        .join("vaults")
        .join(format!("{}.json", id.trim()));
    assert!(record.is_file());
    // Something at the record's path that cannot be removed as a file (a directory with something in it;
    // this holds even for root, where permission bits would not).
    std::fs::remove_file(&record).unwrap();
    std::fs::create_dir_all(record.join("stuck")).unwrap();
    let sealed = pass_wrap(&v);
    match call(
        &state,
        &owner,
        NOW,
        "keystore.unbind",
        json!({ "passphrase": PASSPHRASE }),
    ) {
        Err(OpError::Internal(m)) => {
            assert!(
                m.contains("NOT turned off") && m.contains("nothing changed"),
                "{m}"
            )
        }
        other => panic!("expected a clean refusal, got {other:?}"),
    }
    assert_eq!(pass_wrap(&v), sealed, "the passphrase file is untouched");
    assert!(matches!(form(&v), WrapForm::Sealed { .. }));
    let (state, owner) = restart(&v, state, None);
    assert_eq!(reveal(&state, &owner, "acme", &entry), "alpha-secret");
    // Once the path is clear the unbind works, and a later rotation leaves the vault plain.
    std::fs::remove_dir_all(&record).unwrap();
    let off = call(
        &state,
        &owner,
        NOW,
        "keystore.unbind",
        json!({ "passphrase": PASSPHRASE }),
    )
    .expect("unbind");
    assert_eq!(off["bound"], false);
    let r = call(
        &state,
        &owner,
        NOW,
        "vault.set_passphrase",
        json!({ "passphrase": PASSPHRASE, "newPassphrase": NEW_PASSPHRASE }),
    )
    .expect("set_passphrase");
    assert_eq!(r["machineLocked"], false);
    assert_eq!(form(&v), WrapForm::Plain);
}

/// Review M4: a prepared bind belongs to the login that prepared it. Another login can neither commit it (even
/// with the shown code), nor cancel it, nor prepare over it while it waits; the first login's commit still
/// works.
#[test]
fn a_prepared_bind_belongs_to_the_login_that_prepared_it() {
    let (v, state) = created_vault(None);
    let first = login(&state);
    let second = login(&state);
    let shown = prepare(&v, &state, &first);
    let elsewhere = |r: Result<Value, OpError>| match r {
        Err(OpError::Malformed(m)) => {
            assert!(
                m.contains("another window") && m.contains("nothing changed"),
                "{m}"
            )
        }
        other => panic!("expected the bind to belong to the other login, got {other:?}"),
    };
    elsewhere(commit(&state, &second, NOW, Some(&shown)));
    elsewhere(call(
        &state,
        &second,
        NOW,
        "keystore.bind",
        json!({ "phase": "cancel" }),
    ));
    elsewhere(call(&state, &second, NOW, "keystore.bind", bind_params(&v)));
    assert!(
        state.machine_lock_bind_pending(NOW),
        "the first login's bind still waits"
    );
    assert_eq!(form(&v), WrapForm::Plain);
    let done = commit(&state, &first, NOW, Some(&shown)).expect("the first login commits");
    assert_eq!(done["bound"], true);
    *v.recovery_code.borrow_mut() = shown;
    // Once nothing waits (or it lapsed), another login may prepare.
    let p = bind_call(&state, &second, NOW, bind_params(&v)).expect("prepare");
    assert_eq!(p["already"], true);
    let late = call(&state, &first, NOW, "keystore.bind", bind_params(&v));
    elsewhere(late);
    let expired = call(
        &state,
        &first,
        NOW + BIND_PREPARE_SECONDS + 1,
        "keystore.bind",
        bind_params(&v),
    );
    assert!(
        expired.is_ok(),
        "an expired bind of another login does not block: {expired:?}"
    );
}

/// Review N4: the bind record follows the vault's identity, not its path, and an unbind removes it before it
/// writes the plain wrap: an unbind interrupted at any step never has the lock turned back on by a later
/// rotation, and a different vault put at the same path never inherits the record.
#[test]
fn an_interrupted_unbind_never_turns_the_lock_back_on_and_the_record_follows_the_vault_not_its_path(
) {
    let (v, state, entry) = bound_vault();
    let owner = login(&state);
    let presence = enrol_key(&state, &owner);
    let rotate = |state: &BrokerState, owner: &credmgr_brokerd::scope::BrokerScope| {
        let proved = with_proof(
            state,
            owner,
            &presence,
            NOW,
            "maintenance.rotate_root",
            json!({ "passphrase": PASSPHRASE }),
        );
        call(state, owner, NOW, "maintenance.rotate_root", proved).expect("rotate")
    };
    let id = std::fs::read_to_string(v.vault_dir.join("vault.id")).unwrap();
    let id = id.trim();
    assert_eq!(id.len(), 32);
    assert!(v
        .state_dir
        .join("machine")
        .join("vaults")
        .join(format!("{id}.json"))
        .is_file());

    // A crash between removing the record and writing the plain wrap: still sealed, still opening, still
    // bound by what status says; a rotation keeps it sealed (the lock was never off), and unbinding again
    // finishes.
    state.set_machine_lock_fault_for_test(Some(MachineLockFault::AfterRecordRemoved));
    let ask = || {
        let proved = with_proof(&state, &owner, &presence, NOW, "keystore.unbind", json!({}));
        call(&state, &owner, NOW, "keystore.unbind", proved)
    };
    assert!(ask().is_err());
    state.set_machine_lock_fault_for_test(None);
    assert!(matches!(form(&v), WrapForm::Sealed { .. }));
    let st = status(&state, &owner);
    assert_eq!(st["bound"], true);
    assert_eq!(st["markedBound"], false);
    assert_eq!(st["plainWhileBound"], false);
    assert_eq!(ask().expect("unbind finishes")["bound"], false);
    assert_eq!(form(&v), WrapForm::Plain);

    // Bound again, then an unbind whose rename lands and whose directory fsync fails: plain, no record, and
    // the next rotation and passphrase change leave it plain.
    bind(&v, &state, &owner);
    state.set_machine_lock_fault_for_test(Some(MachineLockFault::AfterRename));
    assert!(ask().is_err());
    state.set_machine_lock_fault_for_test(None);
    assert_eq!(form(&v), WrapForm::Plain);
    let r = rotate(&state, &owner);
    *v.recovery_code.borrow_mut() = r["recoveryCode"].as_str().unwrap().to_string();
    assert_eq!(r["machineLocked"], false, "{r}");
    assert_eq!(
        form(&v),
        WrapForm::Plain,
        "an interrupted unbind is never undone by a rotation"
    );
    let st = status(&state, &owner);
    assert_eq!(st["markedBound"], false);
    assert_eq!(st["warning"], Value::Null);
    let (state, owner) = restart(&v, state, None);
    assert_eq!(reveal(&state, &owner, "acme", &entry), "alpha-secret");

    // Bound once more, then a different vault put at the same path, with this Mac's state folder: it has its
    // own identity (none yet), so it does not inherit the record — not bound, and a rotation leaves it plain.
    // ADR-165 M5: the left-over record names this folder under another vault id, which is exactly what an
    // edited or removed `vault.id` looks like, so it is said (`recordDetached`), and nothing is repaired.
    bind(&v, &state, &owner);
    assert!(matches!(form(&v), WrapForm::Sealed { .. }));
    drop(state);
    let (other, other_state) = created_vault(None);
    drop(other_state);
    std::fs::remove_dir_all(&v.vault_dir).unwrap();
    copy_dir(&other.vault_dir, &v.vault_dir);
    std::fs::copy(
        other.state_dir.join("vaultGeneration.counter"),
        v.state_dir.join("vaultGeneration.counter"),
    )
    .unwrap();
    let state = v.broker(None);
    let owner = login(&state);
    let st = status(&state, &owner);
    assert_eq!(st["bound"], false);
    assert_eq!(st["markedBound"], false, "{st}");
    assert_eq!(st["plainWhileBound"], false);
    assert_eq!(st["recordDetached"], true, "{st}");
    assert!(st["warning"]
        .as_str()
        .unwrap()
        .contains("Nothing was repaired"));
    let presence = enrol_key(&state, &owner);
    let proved = with_proof(
        &state,
        &owner,
        &presence,
        NOW,
        "maintenance.rotate_root",
        json!({ "passphrase": PASSPHRASE }),
    );
    let r = call(&state, &owner, NOW, "maintenance.rotate_root", proved).expect("rotate");
    assert_eq!(r["machineLocked"], false, "{r}");
    assert_eq!(form(&v), WrapForm::Plain);
}

/// Review N6: the device key goes away while a bound vault is open. A backup cannot include a passphrase
/// file that opens the vault, so it refuses, writing nothing, with an error that says what to do; with the
/// key put back, or after the recovery code (which makes a new key), the backup works.
#[test]
fn a_backup_after_the_device_key_went_away_says_what_to_do_and_works_after_the_fix() {
    let (v, state, _) = bound_vault();
    let owner = login(&state);
    let real = std::fs::read(key_path(&v)).unwrap();
    std::fs::remove_file(key_path(&v)).unwrap();
    let ask = json!({ "passphrase": "an archive passphrase" });
    refused_with(
        call(&state, &owner, NOW, "maintenance.backup", ask.clone()),
        "backup_needs_device_key",
    );
    let wire = to_wire(
        "r",
        &call(&state, &owner, NOW, "maintenance.backup", ask.clone()),
    );
    assert!(
        wire["remedy"]
            .as_str()
            .unwrap()
            .contains("put the device key file back")
            && wire["remedy"].as_str().unwrap().contains("recovery code"),
        "{wire}"
    );
    assert!(!v.state_dir.join("backups").exists(), "nothing was written");

    // The key put back: the backup works.
    std::fs::write(key_path(&v), real).unwrap();
    call(&state, &owner, NOW, "maintenance.backup", ask.clone()).expect("backup with the key back");

    // Or: the key is gone for good; lock, open with the recovery code (a new key), back up.
    std::fs::remove_file(key_path(&v)).unwrap();
    state.lock();
    let r = recover(&state, &v.recovery_code.borrow(), NEW_PASSPHRASE).expect("recover");
    assert_eq!(r["machineLocked"], true);
    let owner = scope_of(&state, r["token"].as_str().unwrap());
    let b = call(&state, &owner, NOW, "maintenance.backup", ask).expect("backup after recovery");
    assert_eq!(b["passphraseFileUnsealed"], true);
    assert_eq!(b["outsideVaultFolder"], true);
}

/// Review N2: an unbound vault's archives stay where they always were (the vault folder's `backups/`).
#[test]
fn an_unbound_vault_still_backs_up_into_its_own_folder() {
    let (v, state) = created_vault(None);
    let owner = login(&state);
    let b = call(
        &state,
        &owner,
        NOW,
        "maintenance.backup",
        json!({ "passphrase": "an archive passphrase" }),
    )
    .expect("backup");
    assert_eq!(b["outsideVaultFolder"], false);
    assert_eq!(b["passphraseFileUnsealed"], false);
    assert!(std::path::Path::new(b["path"].as_str().unwrap()).starts_with(v.paths().backups_dir()));
}

/// ADR-165 M5: editing `vault.id`, or putting the folder back to a state from before the bind (no `vault.id`),
/// detaches this Mac's bind record from the vault. It is no longer silent: the owner's `vault.status` carries the
/// `machine_lock_record_detached` warning, `keystore.status` says `recordDetached` with the words the app and
/// `credmgr keystore status` show, and one audit record is written per detached state (not one per status
/// read). An agent's `vault.status` carries nothing. Nothing is repaired: `vault.id`, the passphrase file and
/// the record's identity stay as they are, and the warning goes away only when `vault.id` is put back.
#[test]
fn a_detached_bind_record_is_reported_to_the_owner_audited_once_and_never_to_an_agent() {
    let (v, state, _entry) = bound_vault();
    let owner = login(&state);
    let detached_audits = |state: &BrokerState, owner: &credmgr_brokerd::scope::BrokerScope| {
        let tail =
            call(state, owner, NOW, "audit.tail", json!({ "limit": 200 })).expect("audit.tail");
        tail["records"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["action"] == "keystore.bind_record_detached")
            .count()
    };
    let warns = |body: &Value| {
        body["warnings"]
            .as_array()
            .is_some_and(|w| w.iter().any(|w| w == "machine_lock_record_detached"))
    };
    let mut agent = anyone();
    agent.token_id = Some("an-agent-token".to_string());
    agent.origin = Origin::Agent;

    // Attached: nothing said.
    let body = call(&state, &owner, NOW, "vault.status", json!({})).unwrap();
    assert!(!warns(&body), "{body}");
    assert_eq!(status(&state, &owner)["recordDetached"], false);
    assert_eq!(detached_audits(&state, &owner), 0);

    // 1. `vault.id` edited to another valid id.
    let real_id = std::fs::read(v.paths().vault_id()).unwrap();
    let wrap_before = pass_wrap(&v);
    std::fs::write(v.paths().vault_id(), "0123456789abcdef0123456789abcdef\n").unwrap();
    let body = call(&state, &owner, NOW, "vault.status", json!({})).unwrap();
    assert!(warns(&body), "the owner is told: {body}");
    let st = status(&state, &owner);
    assert_eq!(st["recordDetached"], true, "{st}");
    let warning = st["warning"].as_str().expect("a warning sentence");
    assert!(
        warning.contains("vault.id") && warning.contains("Nothing was repaired"),
        "{warning}"
    );
    assert_eq!(detached_audits(&state, &owner), 1, "audited once");
    // Read again, twice: still said, not audited again.
    call(&state, &owner, NOW, "vault.status", json!({})).unwrap();
    call(&state, &owner, NOW, "vault.status", json!({})).unwrap();
    assert_eq!(
        detached_audits(&state, &owner),
        1,
        "one audit record per detached state"
    );
    // An agent learns nothing, and its read audits nothing.
    let seen_by_agent = call(&state, &agent, NOW, "vault.status", json!({})).unwrap();
    assert!(seen_by_agent.get("warnings").is_none(), "{seen_by_agent}");
    assert_eq!(detached_audits(&state, &owner), 1);
    // Nothing repaired.
    assert_eq!(
        std::fs::read(v.paths().vault_id()).unwrap(),
        b"0123456789abcdef0123456789abcdef\n"
    );
    assert_eq!(pass_wrap(&v), wrap_before);

    // 2. `vault.id` gone, as in a folder put back to a copy from before the bind: a new detached state, said and
    // audited once more.
    std::fs::remove_file(v.paths().vault_id()).unwrap();
    let body = call(&state, &owner, NOW, "vault.status", json!({})).unwrap();
    assert!(warns(&body), "{body}");
    assert_eq!(detached_audits(&state, &owner), 2);
    call(&state, &owner, NOW, "vault.status", json!({})).unwrap();
    assert_eq!(detached_audits(&state, &owner), 2);
    assert!(!v.paths().vault_id().exists(), "nothing repaired");

    // 3. `vault.id` put back: attached again, nothing said.
    std::fs::write(v.paths().vault_id(), real_id).unwrap();
    let body = call(&state, &owner, NOW, "vault.status", json!({})).unwrap();
    assert!(!warns(&body), "{body}");
    let st = status(&state, &owner);
    assert_eq!(st["recordDetached"], false);
    assert_eq!(st["markedBound"], true);
    assert_eq!(pass_wrap(&v), wrap_before);
}

/// ADR-165 M5: an unbound vault, and a vault bound on this Mac whose record is attached, never warn; nor does a
/// record written for another folder.
#[test]
fn no_detached_warning_for_an_unbound_vault_or_another_folders_record() {
    let (v, state) = created_vault(None);
    let owner = login(&state);
    let body = call(&state, &owner, NOW, "vault.status", json!({})).unwrap();
    assert!(body.get("warnings").is_none(), "{body}");
    // A record on this Mac for another folder (another vault bound here) is not this vault's business.
    let records = v.state_dir.join("machine").join("vaults");
    std::fs::create_dir_all(&records).unwrap();
    std::fs::write(
        records.join("fedcba9876543210fedcba9876543210.json"),
        serde_json::to_vec(&json!({
            "v": 2,
            "vaultId": "fedcba9876543210fedcba9876543210",
            "vault": "/somewhere/else/entirely",
            "preBindPublicKeys": []
        }))
        .unwrap(),
    )
    .unwrap();
    let body = call(&state, &owner, NOW, "vault.status", json!({})).unwrap();
    assert!(body.get("warnings").is_none(), "{body}");
    assert_eq!(status(&state, &owner)["recordDetached"], false);
    // The same record naming THIS folder is detached (this vault has no `vault.id`): said.
    std::fs::write(
        records.join("fedcba9876543210fedcba9876543210.json"),
        serde_json::to_vec(&json!({
            "v": 2,
            "vaultId": "fedcba9876543210fedcba9876543210",
            "vault": v.vault_dir.display().to_string(),
            "preBindPublicKeys": []
        }))
        .unwrap(),
    )
    .unwrap();
    let body = call(&state, &owner, NOW, "vault.status", json!({})).unwrap();
    assert_eq!(
        body["warnings"],
        json!(["machine_lock_record_detached"]),
        "{body}"
    );
}
