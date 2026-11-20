//! ADR-163 — `vault.recover`: opening the vault with the recovery code alone when the passphrase is forgotten.
//!
//! The op is a root rotation (ADR-076) started from the root key the recovery code opens, with the new
//! passphrase making the new passphrase wrap, so this file proves what is new and leans on `rotate_root.rs`
//! and `set_passphrase.rs` for the rotation itself:
//!
//! * a recovery opens the vault, sets the new passphrase, answers a new recovery code once, and the used code
//!   and the old passphrase stop opening anything — on the running broker and after a restart;
//! * a wrong or malformed code is refused and counted; an open vault, a vault with no recovery wrap, and an
//!   agent are refused cleanly — a token-less agent inside a project folder on a freshly started broker too,
//!   whose registry is only in memory once the code has opened the vault (review P1-1); every refusal leaves
//!   the root wraps byte for byte as they were;
//! * a recovery that committed but could not open the node keys answers locked, with the new code and no
//!   login (review P2-a); a recovery always runs alone, even when the vault looked open as it was asked
//!   (review P2-b);
//! * an enrolled second factor is still asked for (a TOTP code or one of the gate's backup codes), and a
//!   presence key is not (the owner who lost access may have lost the Mac's Touch ID too);
//! * through the real request path it shares the unlock backoff, both ways round;
//! * a crash at every step leaves a vault that opens with the old passphrase and the old code (before the
//!   commit) or the new passphrase and the new code (after it), never neither;
//! * a recovery wrap put back from before the recovery opens nothing;
//! * every attempt reaches the audit trail — those made while the vault was locked at the next unlock — and
//!   no file in the vault or the state directory holds the code or the new passphrase.

mod f1_support;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use serde_json::{json, Value};

use credmgr_brokerd::protocol::{OpError, Request};
use credmgr_brokerd::server;
use credmgr_brokerd::state::{BrokerState, RecoverError, RotateRootError, RotationFault};
use credmgr_core::access::Origin;
use credmgr_core::totp::{decode_gate_secret_base32, Totp};

use f1_support::*;

const NEW_PASSPHRASE: &str = "a passphrase chosen after forgetting the old one";
const TEST_NEWER_PASSPHRASE: &str = "and another one chosen after that";

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
    // ADR-165 N5: the folder as it was when cloned, untouched, for the crash tests' node-key witness.
    copy_dir_all(&v.vault_dir, &dir.path().join("pre-recovery"));
    Vault {
        vault_dir,
        state_dir,
        recovery_code: std::cell::RefCell::new(v.recovery_code.borrow().clone()),
        _dir: dir,
    }
}

fn secret(s: &str) -> secrecy::SecretBox<String> {
    secrecy::SecretBox::new(Box::new(s.to_string()))
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

fn scope_from(state: &BrokerState, answer: &Value) -> credmgr_brokerd::scope::BrokerScope {
    scope_of(state, answer["token"].as_str().expect("a login token"))
}

/// The root wraps, to prove a refusal changed nothing.
fn wraps(v: &Vault) -> (Vec<u8>, Vec<u8>) {
    (
        std::fs::read(v.paths().root_wrap_pass()).unwrap(),
        std::fs::read(v.paths().root_wrap_recovery()).unwrap(),
    )
}

/// A vault with a node and an entry, locked, on a freshly started broker (the state a person who forgot
/// the passphrase meets).
fn forgotten() -> (Vault, Arc<BrokerState>, String) {
    let (v, state) = created_vault(None);
    let owner = login(&state);
    create_node(&state, &owner, "acme");
    let entry = create_entry(&state, &owner, "acme", "API_KEY", "alpha-secret");
    drop(state);
    let fresh = v.broker(None);
    (v, fresh, entry)
}

fn old_code(v: &Vault) -> String {
    v.recovery_code.borrow().clone()
}

/// ADR-165 N5: what an attacker computes from a copy of the folder and the recovery code that was printed for
/// it: the root key from `root.wrap.recovery`, then `node`'s private key from `keys/nodes/<node>.key`.
fn node_key_with_code(vault_dir: &Path, code: &str, node: &str) -> x25519_dalek::StaticSecret {
    use credmgr_core::recovery::{
        parse_recovery_code, unwrap_root_with_recovery_code, RootRecoveryWrap,
    };
    let wrap = RootRecoveryWrap::from_bytes(
        &std::fs::read(vault_dir.join("keys/root.wrap.recovery")).unwrap(),
    )
    .unwrap();
    let code = parse_recovery_code(code).unwrap();
    let root = unwrap_root_with_recovery_code(&code, &wrap).expect("the code opens its own wrap");
    node_key_from_folder(vault_dir, &root, node).expect("the node key unwraps")
}

fn via_server(
    state: &Arc<BrokerState>,
    op: &str,
    params: Value,
    clock: Instant,
) -> Result<Value, OpError> {
    server::handle_request_at(
        state,
        &peer(),
        &Request {
            id: "r".into(),
            op: op.into(),
            token: None,
            params,
        },
        NOW,
        clock,
    )
    .0
}

fn files_under(dir: &Path, out: &mut Vec<PathBuf>) {
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                files_under(&p, out);
            } else {
                out.push(p);
            }
        }
    }
}

/// No file under the vault or the state directory contains any of `needles`, in any case, with or without the
/// recovery code's dashes.
fn assert_no_file_holds(v: &Vault, needles: &[&str]) {
    let mut files = Vec::new();
    files_under(&v.vault_dir, &mut files);
    files_under(&v.state_dir, &mut files);
    for f in files {
        let text = String::from_utf8_lossy(&std::fs::read(&f).unwrap()).to_lowercase();
        for needle in needles {
            let n = needle.to_lowercase();
            let bare = n.replace('-', "");
            assert!(
                !text.contains(&n) && (bare.len() < 16 || !text.contains(&bare)),
                "{} holds a secret",
                f.display()
            );
        }
    }
}

/// Turn the vault's second factor on; the authenticator and the gate's printed backup codes.
fn enrol_gate_with_codes(
    state: &BrokerState,
    owner: &credmgr_brokerd::scope::BrokerScope,
) -> (Totp, Vec<String>) {
    let begin = call(state, owner, NOW, "vault.gate_enroll_begin", json!({})).expect("begin");
    let uri = begin["otpauthUri"].as_str().unwrap();
    let b32 = uri
        .split("secret=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap();
    let totp = Totp::new_gate(decode_gate_secret_base32(b32).unwrap());
    let confirmed = call(
        state,
        owner,
        NOW,
        "vault.gate_enroll_confirm",
        json!({ "code": totp.code(NOW as u64) }),
    )
    .expect("confirm");
    let codes = confirmed["recoveryCodes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap().to_string())
        .collect();
    (totp, codes)
}

#[test]
fn a_recovery_opens_the_vault_sets_the_new_passphrase_and_retires_the_used_code() {
    let (v, state, entry) = forgotten();
    let used = old_code(&v);
    assert_eq!(
        call(&state, &anyone(), NOW, "vault.status", json!({})).unwrap()["recoveryUnlock"],
        json!(true)
    );

    let answer = recover(&state, &used, NEW_PASSPHRASE).expect("vault.recover");
    assert_eq!(answer["recovered"], json!(true));
    assert_eq!(answer["passphraseChanged"], json!(true));
    assert_eq!(answer["rotated"], json!(true));
    assert_eq!(answer["locked"], json!(false));
    assert_eq!(answer["completionPending"], json!(false));
    let new_code = answer["recoveryCode"]
        .as_str()
        .expect("a new recovery code")
        .to_string();
    assert_ne!(new_code, used);
    // Nothing else secret in the answer.
    let text = answer.to_string();
    assert!(!text.contains(&used) && !text.contains(NEW_PASSPHRASE));

    // It is open, under the token it answered.
    let owner = scope_from(&state, &answer);
    assert!(!state.is_locked());
    assert_eq!(reveal(&state, &owner, "acme", &entry), "alpha-secret");
    verify_ok(&state, &owner);

    // On the running broker: the old passphrase and the used code are refused; the new passphrase opens it.
    state.lock();
    assert_eq!(
        unlock_with(&state, PASSPHRASE),
        Err(OpError::WrongPassphrase)
    );
    assert_eq!(
        recover(&state, &used, TEST_NEWER_PASSPHRASE),
        Err(OpError::RecoveryCodeMismatch)
    );
    let owner = scope_from(
        &state,
        &unlock_with(&state, NEW_PASSPHRASE).expect("new passphrase"),
    );
    assert_eq!(reveal(&state, &owner, "acme", &entry), "alpha-secret");

    // After a restart, from the files alone: the same, and the NEW code is the one that opens it now.
    drop(state);
    let fresh = v.broker(None);
    assert_eq!(
        unlock_with(&fresh, PASSPHRASE),
        Err(OpError::WrongPassphrase)
    );
    assert_eq!(
        recover(&fresh, &used, TEST_NEWER_PASSPHRASE),
        Err(OpError::RecoveryCodeMismatch)
    );
    let again = recover(&fresh, &new_code, TEST_NEWER_PASSPHRASE).expect("the new code opens it");
    let owner = scope_from(&fresh, &again);
    assert_eq!(reveal(&fresh, &owner, "acme", &entry), "alpha-secret");
    verify_ok(&fresh, &owner);
    fresh.lock();
    assert_eq!(
        unlock_with(&fresh, NEW_PASSPHRASE),
        Err(OpError::WrongPassphrase)
    );
    unlock_with(&fresh, TEST_NEWER_PASSPHRASE).expect("the passphrase set by the second recovery");
}

#[test]
fn a_wrong_or_malformed_code_an_open_vault_and_bad_params_are_refused_and_change_nothing() {
    let (v, state, _) = forgotten();
    let before = wraps(&v);
    let code = old_code(&v);

    // Malformed asks, before any code is read.
    for params in [
        json!({}),
        json!({ "recoveryCode": code }),
        json!({ "newPassphrase": NEW_PASSPHRASE }),
        json!({ "recoveryCode": "", "newPassphrase": NEW_PASSPHRASE }),
        json!({ "recoveryCode": code, "newPassphrase": "" }),
        json!({ "recoveryCode": code, "newPassphrase": "x".repeat(1025) }),
        json!({ "recoveryCode": code, "newPassphrase": NEW_PASSPHRASE, "code": 123456 }),
    ] {
        assert!(
            matches!(
                call(&state, &anyone(), NOW, "vault.recover", params.clone()),
                Err(OpError::Malformed(_))
            ),
            "{params}"
        );
    }

    // A code of the right shape that is not this vault's, one of the wrong length, garbage, and one that
    // carries a multi-byte character at an odd offset (a panic before ADR-163): all one answer.
    let mut other = code.clone();
    let flip = if other.starts_with('0') { "1" } else { "0" };
    other.replace_range(0..1, flip);
    let mut non_ascii = "A".repeat(61);
    non_ascii.push('é');
    non_ascii.push('A');
    for wrong in [
        other.as_str(),
        "A1B2-C3D4",
        "not a recovery code at all",
        &non_ascii,
    ] {
        assert_eq!(
            recover(&state, wrong, NEW_PASSPHRASE),
            Err(OpError::RecoveryCodeMismatch),
            "{wrong}"
        );
    }
    assert!(state.is_locked());
    assert_eq!(wraps(&v), before, "no refusal touched the root wraps");
    assert!(!v.paths().rotation_stage().exists());

    // An open vault: nothing to recover; change the passphrase instead.
    let owner = login(&state);
    assert!(matches!(
        call(
            &state,
            &owner,
            NOW,
            "vault.recover",
            json!({ "recoveryCode": code, "newPassphrase": NEW_PASSPHRASE })
        ),
        Err(OpError::Malformed(_))
    ));
    assert_eq!(wraps(&v), before);
    // The old passphrase still opens it: nothing above was a recovery.
    state.lock();
    unlock_with(&state, PASSPHRASE).expect("the old passphrase still opens it");
}

#[test]
fn an_agent_is_refused_before_any_code_is_read() {
    let (v, state, _) = forgotten();
    let before = wraps(&v);
    // An agent's session (origin agent, holding a token) — whatever it holds, never.
    let mut agent = anyone();
    agent.token_id = Some("an-agent-token".to_string());
    agent.origin = Origin::Agent;
    assert!(matches!(
        call(
            &state,
            &agent,
            NOW,
            "vault.recover",
            json!({ "recoveryCode": old_code(&v), "newPassphrase": NEW_PASSPHRASE })
        ),
        Err(OpError::CapabilityNotHeld { .. })
    ));
    assert!(state.is_locked());
    assert_eq!(wraps(&v), before);
}

#[test]
fn an_agent_in_a_registered_project_folder_is_refused_through_the_server() {
    let (v, state) = created_vault(None);
    let owner = login(&state);
    let workdir = v._dir.path().join("acme-src");
    std::fs::create_dir_all(&workdir).unwrap();
    // The kernel reports a process's cwd resolved (macOS's temp dir is `/var/…`, a link to `/private/var/…`) and
    // `node.create` stores the workdir resolved, so the peer below must present the resolved path too.
    let workdir = std::fs::canonicalize(&workdir).unwrap();
    call(
        &state,
        &owner,
        NOW,
        "node.create",
        json!({ "id": "acme", "label": "Acme", "parentId": "global",
                "workdirs": [workdir.to_string_lossy()] }),
    )
    .expect("node.create");
    state.lock();
    let before = wraps(&v);
    let (answer, _) = server::handle_request_at(
        &state,
        &credmgr_brokerd::peer::PeerInfo {
            uid: 501,
            pid: 1,
            cwd: Some(workdir.to_string_lossy().into_owned()),
        },
        &Request {
            id: "r".into(),
            op: "vault.recover".into(),
            token: None,
            params: json!({ "recoveryCode": old_code(&v), "newPassphrase": NEW_PASSPHRASE }),
        },
        NOW,
        Instant::now(),
    );
    assert!(
        matches!(answer, Err(OpError::CapabilityNotHeld { .. })),
        "{answer:?}"
    );
    assert!(state.is_locked());
    assert_eq!(wraps(&v), before);
}

/// Review P1-1: on a broker that has not loaded the vault yet the registry is empty, so the check `ops.rs`
/// makes before any code is read cannot see the project folders. A token-less agent inside one, holding the
/// right code, must still be refused — after the code opened the vault and the registry is in memory, before
/// the second factor and before anything is rotated.
#[test]
fn an_agent_in_a_registered_project_folder_is_refused_by_a_freshly_started_broker() {
    let (v, state) = created_vault(None);
    let owner = login(&state);
    let workdir = v._dir.path().join("acme-src");
    std::fs::create_dir_all(&workdir).unwrap();
    // The kernel reports a process's cwd resolved (macOS's temp dir is `/var/…`, a link to `/private/var/…`) and
    // `node.create` stores the workdir resolved, so the peer below must present the resolved path too.
    let workdir = std::fs::canonicalize(&workdir).unwrap();
    call(
        &state,
        &owner,
        NOW,
        "node.create",
        json!({ "id": "acme", "label": "Acme", "parentId": "global",
                "workdirs": [workdir.to_string_lossy()] }),
    )
    .expect("node.create");
    let entry = create_entry(&state, &owner, "acme", "API_KEY", "alpha-secret");
    drop(state);

    // A daemon that has just started: nothing loaded, so nothing in memory names the project folder.
    let fresh = v.broker(None);
    assert!(!fresh.is_durable(), "the vault is not loaded yet");
    let before = wraps(&v);
    let (answer, _) = server::handle_request_at(
        &fresh,
        &credmgr_brokerd::peer::PeerInfo {
            uid: 501,
            pid: 1,
            cwd: Some(workdir.to_string_lossy().into_owned()),
        },
        &Request {
            id: "r".into(),
            op: "vault.recover".into(),
            token: None,
            params: json!({ "recoveryCode": old_code(&v), "newPassphrase": NEW_PASSPHRASE }),
        },
        NOW,
        Instant::now(),
    );
    assert!(
        matches!(answer, Err(OpError::CapabilityNotHeld { .. })),
        "{answer:?}"
    );
    assert!(fresh.is_locked(), "the refusal opened nothing");
    assert_eq!(wraps(&v), before, "and rotated nothing");
    assert!(!v.paths().rotation_stage().exists());

    // A person's terminal (no project folder) is still served, with the same code: nothing was spent.
    let answer = via_server(
        &fresh,
        "vault.recover",
        json!({ "recoveryCode": old_code(&v), "newPassphrase": NEW_PASSPHRASE }),
        Instant::now(),
    )
    .expect("a person recovers");
    let owner = scope_from(&fresh, &answer);
    assert_eq!(reveal(&fresh, &owner, "acme", &entry), "alpha-secret");
}

/// Review P2-a: a recovery whose rotation committed, with its files in place, but whose node keys this
/// process could not open, locks the vault again — which revokes every login. It must say so: locked, the
/// new recovery code (the used one no longer opens anything), and no login token.
#[test]
fn a_recovery_that_cannot_open_its_node_keys_answers_locked_with_the_new_code_and_no_login() {
    let (v, state, entry) = forgotten();
    state.set_recover_open_fault_for_test(true);
    let answer = recover(&state, &old_code(&v), NEW_PASSPHRASE).expect("the rotation committed");
    assert_eq!(answer["locked"], json!(true), "{answer}");
    assert_eq!(answer["meta"]["vaultLocked"], json!(true));
    assert!(
        answer.get("token").is_none(),
        "no login after the lock: {answer}"
    );
    assert_eq!(
        answer["completionPending"],
        json!(false),
        "the files are in place"
    );
    let new_code = answer["recoveryCode"]
        .as_str()
        .expect("the new code is still shown once")
        .to_string();
    assert_ne!(new_code, old_code(&v));
    assert!(state.is_locked());

    // The next unlock with the new passphrase opens it from disk; the old passphrase and the used code do not.
    assert_eq!(
        unlock_with(&state, PASSPHRASE),
        Err(OpError::WrongPassphrase)
    );
    assert_eq!(
        recover(&state, &old_code(&v), TEST_NEWER_PASSPHRASE),
        Err(OpError::RecoveryCodeMismatch)
    );
    let owner = scope_from(
        &state,
        &unlock_with(&state, NEW_PASSPHRASE).expect("new passphrase"),
    );
    assert_eq!(reveal(&state, &owner, "acme", &entry), "alpha-secret");
}

/// Review P2-b: the exclusive barrier is taken for every `vault.recover` from a uid that is not backed off,
/// not only when the vault looks locked as the server checks — an auto-lock between that check and the
/// dispatch would otherwise run the rotation beside other requests. On an open vault the op then refuses,
/// having waited only for the request already in flight.
#[test]
fn a_recovery_request_always_waits_for_the_requests_in_flight() {
    use std::sync::mpsc;
    use std::time::Duration;

    let (_v, state) = created_vault(None);
    let _owner = login(&state);
    assert!(
        !state.is_locked(),
        "the vault is open as the request arrives"
    );

    let in_flight = state.request_barrier(false);
    let (tx, rx) = mpsc::channel();
    let asking = {
        let state = Arc::clone(&state);
        std::thread::spawn(move || {
            let answer = via_server(
                &state,
                "vault.recover",
                json!({ "recoveryCode": "A1B2-C3D4", "newPassphrase": NEW_PASSPHRASE }),
                Instant::now(),
            );
            tx.send(answer).unwrap();
        })
    };
    assert!(
        rx.recv_timeout(Duration::from_millis(300)).is_err(),
        "a recovery must not run while another request is in flight, even on a vault that looks open"
    );
    drop(in_flight);
    let answer = rx
        .recv_timeout(Duration::from_secs(30))
        .expect("it runs once the barrier is free");
    assert!(matches!(answer, Err(OpError::Malformed(_))), "{answer:?}");
    asking.join().unwrap();
}

#[test]
fn a_vault_without_a_recovery_wrap_refuses_cleanly_until_the_next_passphrase_change_writes_one() {
    let (v, state, entry) = forgotten();
    drop(state);
    std::fs::remove_file(v.paths().root_wrap_recovery()).unwrap();
    let state = v.broker(None);
    let pass_before = std::fs::read(v.paths().root_wrap_pass()).unwrap();

    assert_eq!(
        call(&state, &anyone(), NOW, "vault.status", json!({})).unwrap()["recoveryUnlock"],
        json!(false),
        "the Lock screen and `credmgr recover` learn there is no way in by code"
    );
    assert!(matches!(
        recover(&state, &old_code(&v), NEW_PASSPHRASE),
        Err(OpError::NotFound(_))
    ));
    assert!(state.is_locked());
    assert_eq!(
        std::fs::read(v.paths().root_wrap_pass()).unwrap(),
        pass_before
    );
    assert!(!v.paths().root_wrap_recovery().exists());

    // The passphrase still opens it, and a passphrase change writes the recovery wrap.
    let owner = scope_from(&state, &unlock_with(&state, PASSPHRASE).unwrap());
    let changed = call(
        &state,
        &owner,
        NOW,
        "vault.set_passphrase",
        json!({ "passphrase": PASSPHRASE, "newPassphrase": NEW_PASSPHRASE }),
    )
    .expect("vault.set_passphrase");
    let code = changed["recoveryCode"].as_str().unwrap().to_string();
    assert!(v.paths().root_wrap_recovery().is_file());
    state.lock();
    assert_eq!(
        call(&state, &anyone(), NOW, "vault.status", json!({})).unwrap()["recoveryUnlock"],
        json!(true)
    );
    let answer = recover(&state, &code, TEST_NEWER_PASSPHRASE).expect("now it recovers");
    let owner = scope_from(&state, &answer);
    assert_eq!(reveal(&state, &owner, "acme", &entry), "alpha-secret");
}

#[test]
fn an_enrolled_second_factor_is_still_asked_for_and_a_presence_key_is_not() {
    let (v, state) = created_vault(None);
    let owner = login(&state);
    create_node(&state, &owner, "acme");
    let entry = create_entry(&state, &owner, "acme", "API_KEY", "alpha-secret");
    // A presence key enrolled: Touch ID cannot be required for a recovery (the point is that the owner lost
    // access), so it is not asked for.
    let _key = enrol_first_key(&state, &owner);
    let (totp, backup_codes) = enrol_gate_with_codes(&state, &owner);
    drop(state);
    let state = v.broker(None);
    let before = wraps(&v);
    let code = old_code(&v);
    let at = LATER;
    let ask = |extra: Value| {
        let mut p = json!({ "recoveryCode": code, "newPassphrase": NEW_PASSPHRASE });
        if let (Some(p), Some(e)) = (p.as_object_mut(), extra.as_object()) {
            p.extend(e.clone());
        }
        call(&state, &anyone(), at, "vault.recover", p)
    };

    // No second factor: asked for, nothing changed.
    assert!(matches!(
        ask(json!({})),
        Err(OpError::TwoFactorRequired { .. })
    ));
    // A wrong one: refused, nothing changed.
    assert_eq!(
        ask(json!({ "code": "000000" })),
        Err(OpError::GateVerificationFailed)
    );
    // A right one with a wrong recovery code is still a wrong recovery code (the code is checked first).
    assert_eq!(
        call(
            &state,
            &anyone(),
            at,
            "vault.recover",
            json!({ "recoveryCode": "00".repeat(32), "newPassphrase": NEW_PASSPHRASE,
                    "code": totp.code(at as u64) })
        ),
        Err(OpError::RecoveryCodeMismatch)
    );
    assert!(state.is_locked());
    assert_eq!(wraps(&v), before);

    // A gate backup code does (it is what the owner printed for a lost authenticator), and it is spent.
    let answer = ask(json!({ "code": backup_codes[0] })).expect("recovery code + gate backup code");
    let owner = scope_from(&state, &answer);
    assert_eq!(reveal(&state, &owner, "acme", &entry), "alpha-secret");
    let new_code = answer["recoveryCode"].as_str().unwrap().to_string();

    // The gate stands behind the new passphrase, and the spent backup code stays spent after a restart.
    drop(state);
    let fresh = v.broker(None);
    assert!(matches!(
        unlock_with(&fresh, NEW_PASSPHRASE),
        Err(OpError::TwoFactorRequired { .. })
    ));
    let later = at + 120;
    assert_eq!(
        call(
            &fresh,
            &anyone(),
            later,
            "vault.recover",
            json!({ "recoveryCode": new_code, "newPassphrase": TEST_NEWER_PASSPHRASE,
                    "code": backup_codes[0] })
        ),
        Err(OpError::GateVerificationFailed),
        "a spent gate backup code is spent"
    );
    // A fresh TOTP code with the new recovery code works.
    call(
        &fresh,
        &anyone(),
        later,
        "vault.recover",
        json!({ "recoveryCode": new_code, "newPassphrase": TEST_NEWER_PASSPHRASE,
                "code": totp.code(later as u64) }),
    )
    .expect("recovery code + TOTP");
}

#[test]
fn through_the_server_it_shares_the_unlock_backoff_both_ways_round() {
    let (v, state, _) = forgotten();
    let clock = Instant::now();
    let wrong = "00".repeat(32);

    // Wrong codes count; the fifth trips the lockout.
    for _ in 0..4 {
        assert_eq!(
            via_server(
                &state,
                "vault.recover",
                json!({ "recoveryCode": wrong, "newPassphrase": NEW_PASSPHRASE }),
                clock
            ),
            Err(OpError::RecoveryCodeMismatch)
        );
    }
    // The fifth failure is a wrong passphrase: one counter, so it trips the lockout for both doors.
    assert_eq!(
        via_server(
            &state,
            "vault.unlock",
            json!({ "passphrase": "not it" }),
            clock
        ),
        Err(OpError::WrongPassphrase)
    );
    // Locked out: even the RIGHT code is not read.
    assert!(matches!(
        via_server(
            &state,
            "vault.recover",
            json!({ "recoveryCode": old_code(&v), "newPassphrase": NEW_PASSPHRASE }),
            clock
        ),
        Err(OpError::RateLimited { .. })
    ));
    assert!(matches!(
        via_server(
            &state,
            "vault.unlock",
            json!({ "passphrase": PASSPHRASE }),
            clock
        ),
        Err(OpError::RateLimited { .. })
    ));
    assert!(state.is_locked());

    // After the lockout, the right code works and clears the counter.
    let after = clock + std::time::Duration::from_secs(31);
    let answer = via_server(
        &state,
        "vault.recover",
        json!({ "recoveryCode": old_code(&v), "newPassphrase": NEW_PASSPHRASE }),
        after,
    )
    .expect("the right code after the lockout");
    assert_eq!(answer["locked"], json!(false));
    assert_eq!(state.auth_backoff.remaining_lockout(501, after), None);
}

/// After a crash before the commit, a fresh broker opens the vault with the old passphrase and the old code,
/// and the new passphrase opens nothing.
fn assert_old_still_opens(vault: &Vault, entry: &str, why: &str) {
    let used = old_code(vault);
    // ADR-165 N5: the old state is whole — the node keypair too (no envelope was re-sealed).
    let old_acme = node_key_with_code(&vault.vault_dir, &used, "acme");
    assert!(
        key_opens(
            &old_acme,
            &vault.paths().entry_env("acme", entry),
            "acme",
            entry
        ),
        "{why}: the entry is still sealed to the old node key"
    );
    let fresh = vault.broker(None);
    let owner = scope_from(
        &fresh,
        &unlock_with(&fresh, PASSPHRASE)
            .unwrap_or_else(|e| panic!("{why}: the old passphrase must open it, got {e:?}")),
    );
    assert_eq!(
        reveal(&fresh, &owner, "acme", entry),
        "alpha-secret",
        "{why}"
    );
    verify_ok(&fresh, &owner);
    fresh.lock();
    assert_eq!(
        unlock_with(&fresh, NEW_PASSPHRASE),
        Err(OpError::WrongPassphrase),
        "{why}"
    );
    drop(fresh);
    assert!(
        !vault.paths().rotation_stage().exists(),
        "{why}: the stage is gone"
    );
    // The old code still opens it (on a copy, so the check does not itself re-key the vault under test).
    let probe = cloned(vault);
    recover(&probe.broker(None), &used, TEST_NEWER_PASSPHRASE)
        .unwrap_or_else(|e| panic!("{why}: the old code must still open it, got {e:?}"));
}

fn crash_recovery(vault: &Vault, fault: RotationFault) {
    let state = vault.broker(None);
    state.set_rotation_fault_for_test(Some(fault));
    let result = state.recover_with_code(
        &anyone(),
        &old_code(vault),
        secret(NEW_PASSPHRASE),
        None,
        NOW + 1,
    );
    // A crash while staging surfaces as the staging write's own error; every other seam as the injected crash.
    let died = match fault {
        RotationFault::DuringStaging(_) => {
            matches!(result, Err(RecoverError::Rotate(RotateRootError::Store(_))))
        }
        _ => matches!(
            result,
            Err(RecoverError::Rotate(RotateRootError::InjectedCrash))
        ),
    };
    assert!(died, "{fault:?}: {:?}", result.err());
}

#[test]
fn a_crash_before_the_commit_leaves_the_old_passphrase_and_the_old_code() {
    let (v, state, entry) = forgotten();
    drop(state);

    // How many files a recovery stages.
    let files = {
        let dry = cloned(&v);
        let state = dry.broker(None);
        state
            .recover_with_code(
                &anyone(),
                &old_code(&dry),
                secret(NEW_PASSPHRASE),
                None,
                NOW + 1,
            )
            .expect("a dry run")
            .rotation
            .files_replaced
    };
    assert!(files >= 5, "a recovery rewrites at least five files");

    let vault = cloned(&v);
    crash_recovery(&vault, RotationFault::BeforeCommit);
    assert_old_still_opens(&vault, &entry, "crash before the commit");

    for staged in 0usize.. {
        if staged >= files {
            break;
        }
        let vault = cloned(&v);
        crash_recovery(&vault, RotationFault::DuringStaging(staged));
        assert_old_still_opens(
            &vault,
            &entry,
            &format!("crash after staging {staged} files"),
        );
    }
}

#[test]
fn a_crash_at_every_point_after_the_commit_leaves_the_new_passphrase_and_the_new_code() {
    let (v, state, entry) = forgotten();
    drop(state);

    let files = {
        let dry = cloned(&v);
        let state = dry.broker(None);
        state
            .recover_with_code(
                &anyone(),
                &old_code(&dry),
                secret(NEW_PASSPHRASE),
                None,
                NOW + 1,
            )
            .expect("a dry run")
            .rotation
            .files_replaced
    };

    // The new code is made inside the call that "dies", so it is never seen: here the new passphrase is the
    // witness that the commit took, and the used code and the old passphrase the counter-witnesses.
    let vault = cloned(&v);
    crash_recovery(&vault, RotationFault::AfterCommit);
    assert_opens_after_crash_new_passphrase(&vault, &entry, "crash right after the commit");

    for cut in 0usize.. {
        if cut > files {
            break;
        }
        let vault = cloned(&v);
        crash_recovery(&vault, RotationFault::DuringRollForward(cut));
        assert_opens_after_crash_new_passphrase(
            &vault,
            &entry,
            &format!("crash after moving {cut} files"),
        );
    }
}

/// After the commit of a recovery that crashed (so its new code was never seen): the new passphrase opens the
/// vault, the old passphrase and the used code do not.
fn assert_opens_after_crash_new_passphrase(vault: &Vault, entry: &str, why: &str) {
    let used = old_code(vault);
    // ADR-165 N5: the new state is whole — the entry is sealed to the new node key, not the old one.
    let old_acme = old_acme_key_of(vault);
    let fresh = vault.broker(None);
    assert_eq!(
        unlock_with(&fresh, PASSPHRASE),
        Err(OpError::WrongPassphrase),
        "{why}"
    );
    assert_eq!(
        recover(&fresh, &used, TEST_NEWER_PASSPHRASE),
        Err(OpError::RecoveryCodeMismatch),
        "{why}: the used code is dead"
    );
    let owner = scope_from(
        &fresh,
        &unlock_with(&fresh, NEW_PASSPHRASE)
            .unwrap_or_else(|e| panic!("{why}: the new passphrase must open it, got {e:?}")),
    );
    assert_eq!(
        reveal(&fresh, &owner, "acme", entry),
        "alpha-secret",
        "{why}"
    );
    verify_ok(&fresh, &owner);
    assert!(
        !vault.paths().rotation_stage().exists(),
        "{why}: the stage is gone"
    );
    assert!(
        !key_opens(
            &old_acme,
            &vault.paths().entry_env("acme", entry),
            "acme",
            entry
        ),
        "{why}: no envelope is left on the old node key"
    );
}

/// The pre-recovery acme key of a cloned vault: every clone in these tests is made from the untouched
/// original, whose `pre-recovery` copy the helper keeps beside it.
fn old_acme_key_of(vault: &Vault) -> x25519_dalek::StaticSecret {
    node_key_with_code(
        &vault.vault_dir.with_file_name("pre-recovery"),
        &old_code(vault),
        "acme",
    )
}

/// ADR-165 N5, the attack replayed for a recovery: a byte-copy of the folder from before the recovery plus
/// the code that was used (or the forgotten passphrase) yields the old node keys, which open nothing written
/// after the recovery and no live envelope. The copy's own old contents still open with them (inherent).
#[test]
fn a_copy_from_before_the_recovery_plus_the_used_code_opens_nothing_written_after_it() {
    let (v, state, entry) = forgotten();
    let pre = cloned(&v);
    let used = old_code(&v);
    let old_acme = node_key_with_code(&pre.vault_dir, &used, "acme");
    let old_global = node_key_with_code(&pre.vault_dir, &used, credmgr_core::registry::GLOBAL_ID);

    let answer = recover(&state, &used, NEW_PASSPHRASE).expect("the recovery");
    assert_eq!(
        answer["nodesRekeyed"],
        json!(["acme", "global"]),
        "global and acme get new keys"
    );
    assert!(answer["filesResealed"].as_u64().unwrap() >= 1);
    let owner = scope_from(&state, &answer);
    let after = create_entry(
        &state,
        &owner,
        "acme",
        "AFTER",
        "written-after-the-recovery",
    );
    let after_global = create_entry(
        &state,
        &owner,
        credmgr_core::registry::GLOBAL_ID,
        "AFTER_G",
        "global-after-the-recovery",
    );

    let paths = v.paths();
    assert!(!key_opens(
        &old_acme,
        &paths.entry_env("acme", &after),
        "acme",
        &after
    ));
    assert!(!key_opens(
        &old_global,
        &paths.entry_env(credmgr_core::registry::GLOBAL_ID, &after_global),
        credmgr_core::registry::GLOBAL_ID,
        &after_global
    ));
    assert!(!key_opens(
        &old_acme,
        &paths.entry_env("acme", &entry),
        "acme",
        &entry
    ));
    // The same old keys from the forgotten passphrase: the copy's passphrase wrap gives the same old root.
    let old_root = root_from_folder(&pre.vault_dir, PASSPHRASE).unwrap();
    let via_passphrase = node_key_from_folder(&pre.vault_dir, &old_root, "acme").unwrap();
    assert!(!key_opens(
        &via_passphrase,
        &paths.entry_env("acme", &after),
        "acme",
        &after
    ));
    // Inherent: the copy's own contents.
    assert!(key_opens(
        &old_acme,
        &pre.paths().entry_env("acme", &entry),
        "acme",
        &entry
    ));

    // Everything reads, on the running broker and after a restart.
    assert_eq!(reveal(&state, &owner, "acme", &entry), "alpha-secret");
    assert_eq!(
        reveal(&state, &owner, "acme", &after),
        "written-after-the-recovery"
    );
    verify_ok(&state, &owner);
    drop(state);
    let fresh = v.broker(None);
    let owner = scope_from(
        &fresh,
        &unlock_with(&fresh, NEW_PASSPHRASE).expect("unlock"),
    );
    assert_eq!(reveal(&fresh, &owner, "acme", &entry), "alpha-secret");
    assert_eq!(
        reveal(&fresh, &owner, "acme", &after),
        "written-after-the-recovery"
    );
    verify_ok(&fresh, &owner);
}

#[test]
fn a_recovery_whose_commit_cannot_be_proven_durable_answers_the_code_and_stays_locked() {
    let (v, state, entry) = forgotten();
    state.set_rotation_fault_for_test(Some(RotationFault::CommitNeverBecomesDurable));
    let answer = recover(&state, &old_code(&v), NEW_PASSPHRASE).expect("committed, not finished");
    assert_eq!(answer["completionPending"], json!(true));
    assert_eq!(answer["locked"], json!(true));
    assert!(
        answer.get("token").is_none(),
        "no login until the move is finished"
    );
    let new_code = answer["recoveryCode"].as_str().unwrap().to_string();
    assert!(state.is_locked());
    state.set_rotation_fault_for_test(None);
    // The next unlock, with the NEW passphrase, finishes the move.
    let owner = scope_from(
        &state,
        &unlock_with(&state, NEW_PASSPHRASE).expect("finishes the move"),
    );
    assert_eq!(reveal(&state, &owner, "acme", &entry), "alpha-secret");
    drop(state);
    let probe = cloned(&v);
    recover(&probe.broker(None), &new_code, TEST_NEWER_PASSPHRASE)
        .expect("the code it answered is the live one");
}

#[test]
fn a_recovery_wrap_put_back_from_before_the_recovery_opens_nothing() {
    let (v, state, entry) = forgotten();
    let used = old_code(&v);
    let stale_wrap = std::fs::read(v.paths().root_wrap_recovery()).unwrap();
    let answer = recover(&state, &used, NEW_PASSPHRASE).expect("recovery");
    let new_code = answer["recoveryCode"].as_str().unwrap().to_string();
    drop(state);

    // An attacker who kept the old code and a copy of the old wrap writes the wrap back.
    std::fs::write(v.paths().root_wrap_recovery(), stale_wrap).unwrap();
    let fresh = v.broker(None);
    let refused = recover(&fresh, &used, TEST_NEWER_PASSPHRASE);
    assert!(
        matches!(refused, Err(OpError::Internal(_))),
        "the old wrap opens the OLD root key, which no signed file accepts: {refused:?}"
    );
    assert!(fresh.is_locked());
    // The vault is not damaged: the new passphrase still opens it (the put-back wrap only stops the new code).
    let owner = scope_from(&fresh, &unlock_with(&fresh, NEW_PASSPHRASE).unwrap());
    assert_eq!(reveal(&fresh, &owner, "acme", &entry), "alpha-secret");
    fresh.lock();
    assert_eq!(
        recover(&fresh, &new_code, TEST_NEWER_PASSPHRASE),
        Err(OpError::RecoveryCodeMismatch)
    );

    // On a broker that already holds the vault (loaded, then locked), the same.
    let held = v.broker(None);
    unlock_with(&held, NEW_PASSPHRASE).unwrap();
    held.lock();
    assert!(matches!(
        recover(&held, &used, TEST_NEWER_PASSPHRASE),
        Err(OpError::Internal(_))
    ));
    assert!(held.is_locked());
}

#[test]
fn every_attempt_is_audited_and_no_file_holds_the_code_or_the_new_passphrase() {
    let (v, state, _) = forgotten();
    let clock = Instant::now();
    let used = old_code(&v);
    let wrong = "ab".repeat(32);

    // Two refused attempts while the vault is locked: no root key to sign them with yet.
    for _ in 0..2 {
        assert_eq!(
            via_server(
                &state,
                "vault.recover",
                json!({ "recoveryCode": wrong, "newPassphrase": NEW_PASSPHRASE }),
                clock
            ),
            Err(OpError::RecoveryCodeMismatch)
        );
    }
    // The successful one: the rotation's own record, the decision record, and the two refusals before them.
    let answer = via_server(
        &state,
        "vault.recover",
        json!({ "recoveryCode": used, "newPassphrase": NEW_PASSPHRASE }),
        clock,
    )
    .expect("recovery");
    let new_code = answer["recoveryCode"].as_str().unwrap().to_string();
    let owner = scope_from(&state, &answer);

    let tail = call(&state, &owner, NOW, "audit.tail", json!({ "limit": 50 })).expect("audit.tail");
    let records = tail["records"].as_array().expect("records").clone();
    let recover_records: Vec<&Value> = records
        .iter()
        .filter(|r| r["action"] == "vault.recover")
        .collect();
    let denied = recover_records
        .iter()
        .filter(|r| r["decision"] == "deny")
        .count();
    let allowed = recover_records
        .iter()
        .filter(|r| r["decision"] == "allow")
        .count();
    assert_eq!(
        denied, 2,
        "both refusals made while locked are on the trail: {records:?}"
    );
    assert_eq!(allowed, 1, "the success is on the trail: {records:?}");
    assert!(
        records
            .iter()
            .any(|r| r["action"] == "vault.recovered_with_code"),
        "the rotation's own record names the recovery: {records:?}"
    );
    for r in &recover_records {
        if r["decision"] == "deny" {
            assert!(
                r["detail"]
                    .as_str()
                    .unwrap()
                    .starts_with("recovery_code_mismatch"),
                "{r}"
            );
        }
    }
    // Nothing waits any more.
    assert!(state.take_unaudited_recoveries().0.is_empty());

    verify_ok(&state, &owner);
    assert_no_file_holds(&v, &[&used, &new_code, &wrong, NEW_PASSPHRASE]);
}

#[test]
fn the_waiting_list_of_unaudited_attempts_is_bounded() {
    let (_v, state, _) = forgotten();
    for i in 0..(credmgr_brokerd::state::REFUSED_RECOVERY_QUEUE + 5) {
        state.note_unaudited_recovery(credmgr_brokerd::state::UnauditedRecovery {
            at: NOW + i as i64,
            actor: "human".to_string(),
            decision: "deny",
            reason: "recovery_code_mismatch",
        });
    }
    let (kept, dropped) = state.take_unaudited_recoveries();
    assert_eq!(kept.len(), credmgr_brokerd::state::REFUSED_RECOVERY_QUEUE);
    assert_eq!(dropped, 5);
    assert_eq!(kept[0].at, NOW + 5, "the oldest fall off the front");
}

#[test]
fn the_whole_vault_folder_rolled_back_to_before_the_recovery_is_refused_by_the_rollback_counter() {
    let (v, state, _) = forgotten();
    let used = old_code(&v);
    // A copy of the vault folder as it was before the recovery (an old backup, a synced copy).
    let before = tempfile::tempdir().unwrap();
    copy_dir_all(&v.vault_dir, before.path());
    recover(&state, &used, NEW_PASSPHRASE).expect("recovery");
    drop(state);

    // Put the old folder back, keeping the state directory (and its rollback counter) as it is.
    std::fs::remove_dir_all(&v.vault_dir).unwrap();
    copy_dir_all(before.path(), &v.vault_dir);
    let fresh = v.broker(None);
    assert!(
        matches!(recover(&fresh, &used, TEST_NEWER_PASSPHRASE), Err(OpError::Internal(_))),
        "the old code opens the old folder's wrap, but the counter is signed under the new root key"
    );
    assert!(matches!(
        unlock_with(&fresh, PASSPHRASE),
        Err(OpError::Internal(_))
    ));
    assert!(fresh.is_locked());
}
