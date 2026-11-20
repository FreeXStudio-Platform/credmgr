//! ADR-150 on the command line: with "confirm before showing secrets" on, `credmgr get` from a real login
//! is refused until the person confirms, says how (`credmgr confirm`) when it cannot ask, and works once
//! `credmgr confirm` took the passphrase from stdin. The REAL `credmgr` binary against a REAL broker over a
//! real durable vault (`vault.init_*`) and a real login token — never a fixture token, which is not a login
//! and could never confirm. The passphrase only ever travels on stdin.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;

use secrecy::SecretBox;
use serde_json::{json, Value};

use credmgr_brokerd::ops;
use credmgr_brokerd::scope::{resolve_scope, BrokerScope};
use credmgr_brokerd::state::BrokerState;
use credmgr_core::access::Origin;
use credmgr_core::registry::{Capability, GLOBAL_ID};
use credmgr_keystore::software::SoftwareKeystore;
use credmgr_store::paths::VaultPaths;

const PASSPHRASE: &str = "correct horse battery staple";
const VALUE: &str = "placeholder-value-for-the-cli-test";
const NOW: i64 = 1_800_000_000;

struct Fixture {
    vault_dir: PathBuf,
    token: String,
    _tmp: tempfile::TempDir,
}

fn anyone() -> BrokerScope {
    BrokerScope {
        node_id: GLOBAL_ID.to_string(),
        capabilities: vec![Capability::List],
        origin: Origin::Agent,
        token_id: None,
        bound_workdir: None,
    }
}

fn call(state: &BrokerState, scope: &BrokerScope, op: &str, params: Value) -> Value {
    ops::dispatch(state, scope, NOW, op, &params).unwrap_or_else(|e| panic!("{op}: {e:?}"))
}

fn start() -> Fixture {
    let tmp = tempfile::tempdir().expect("tempdir");
    let vault_dir = tmp.path().join("vault");
    let state_dir = tmp.path().join("state");
    std::fs::create_dir_all(&vault_dir).unwrap();
    std::fs::create_dir_all(&state_dir).unwrap();
    let paths = VaultPaths::new(vault_dir.clone());
    let keystore = SoftwareKeystore::new(SecretBox::new(Box::default()), state_dir.join("ks"));
    let state = Arc::new(BrokerState::new(Box::new(keystore), paths.clone()));
    state.set_state_dir_for_test(state_dir);

    let code = call(
        &state,
        &anyone(),
        "vault.init_begin",
        json!({ "passphrase": PASSPHRASE }),
    )["recoveryCode"]
        .as_str()
        .unwrap()
        .to_string();
    call(
        &state,
        &anyone(),
        "vault.init_confirm",
        json!({ "recoveryCode": code }),
    );
    let token = call(
        &state,
        &anyone(),
        "vault.unlock",
        json!({ "passphrase": PASSPHRASE }),
    )["token"]
        .as_str()
        .unwrap()
        .to_string();
    let registry = state.registry.read().unwrap().clone();
    let owner = resolve_scope(
        &registry,
        &state.tokens,
        &credmgr_brokerd::peer::PeerInfo {
            uid: 501,
            pid: 1,
            cwd: None,
        },
        Some(&token),
    )
    .0;
    call(
        &state,
        &owner,
        "node.create",
        json!({ "id": "acme", "label": "acme", "parentId": GLOBAL_ID }),
    );
    call(
        &state,
        &owner,
        "entry.create",
        json!({ "node": "acme", "name": "DB_PASSWORD", "value": VALUE }),
    );
    call(
        &state,
        &owner,
        "node.policy",
        json!({ "node": GLOBAL_ID, "reason": "cli test", "policy": { "revealConfirm": { "mode": "window" } } }),
    );

    std::fs::create_dir_all(paths.run_dir()).unwrap();
    std::fs::set_permissions(paths.run_dir(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = paths.run_socket();
    std::thread::spawn(move || {
        credmgr_brokerd::server::run(state, &socket).expect("fixture broker crashed");
    });
    for _ in 0..200 {
        if std::os::unix::net::UnixStream::connect(paths.run_socket()).is_ok() {
            return Fixture {
                vault_dir,
                token,
                _tmp: tmp,
            };
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    panic!("credmgrd fixture never opened its socket");
}

struct Out {
    ok: bool,
    stdout: String,
    stderr: String,
}

fn run(fx: &Fixture, args: &[&str], stdin: Option<&str>) -> Out {
    let mut child = Command::new(env!("CARGO_BIN_EXE_credmgr"))
        .args(args)
        .env("CREDMGR_VAULT_DIR", &fx.vault_dir)
        .env("CREDMGR_TOKEN", &fx.token)
        .env("CREDMGR_NO_PROMPT", "1")
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("launch credmgr");
    if let Some(text) = stdin {
        let mut pipe = child.stdin.take().unwrap();
        let _ = pipe.write_all(text.as_bytes());
    }
    let o = child.wait_with_output().unwrap();
    Out {
        ok: o.status.success(),
        stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
    }
}

#[test]
fn get_asks_for_a_confirmation_and_confirm_takes_the_passphrase_from_stdin() {
    let fx = start();

    // Not at a terminal, nothing to ask with: refused, the value nowhere, and the way forward named.
    let refused = run(&fx, &["get", "DB_PASSWORD", "--node", "acme"], None);
    assert!(!refused.ok);
    assert!(
        refused.stderr.contains("confirmation_required")
            && refused.stderr.contains("credmgr confirm"),
        "{}",
        refused.stderr
    );
    assert!(!refused.stdout.contains(VALUE) && !refused.stderr.contains(VALUE));

    // A wrong passphrase confirms nothing.
    let wrong = run(&fx, &["confirm"], Some("not the passphrase\n"));
    assert!(
        !wrong.ok && wrong.stderr.contains("wrong_passphrase"),
        "{}",
        wrong.stderr
    );
    assert!(!run(&fx, &["get", "DB_PASSWORD", "--node", "acme"], None).ok);

    // The passphrase on stdin (never argv) opens the trust window.
    let ok = run(&fx, &["confirm"], Some(&format!("{PASSPHRASE}\n")));
    assert!(ok.ok, "{}", ok.stderr);
    assert!(ok.stdout.contains("300 seconds"), "{}", ok.stdout);
    assert!(!ok.stdout.contains(PASSPHRASE) && !ok.stderr.contains(PASSPHRASE));

    let shown = run(&fx, &["get", "DB_PASSWORD", "--node", "acme"], None);
    assert!(shown.ok, "{}", shown.stderr);
    assert_eq!(shown.stdout.trim(), VALUE);
}

#[test]
fn confirm_refuses_extra_arguments_so_a_passphrase_never_rides_on_argv() {
    let fx = start();
    let out = run(&fx, &["confirm", PASSPHRASE], None);
    assert!(
        !out.ok && out.stderr.contains("usage: credmgr confirm"),
        "{}",
        out.stderr
    );
}
