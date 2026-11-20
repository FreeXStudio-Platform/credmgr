//! Issue #39 - an authenticator code is not a command-line argument.
//!
//! `credmgr gate verify` and `credmgr approve` used to take the code as an
//! argument, visible to every same-user process in `ps` while the command ran.
//! The code now comes from a prompt or stdin; the argv form survives only as
//! `--code-on-argv`, which `credmgr help` says is visible to `ps`.
//!
//! A scripted stand-in for `credmgrd` records exactly what the binary sends, so
//! the tests prove the code reaches the wire from stdin (and not from argv) rather
//! than inferring it from an error message. Test codes and passphrases are made up.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::process::{Command, Stdio};
use std::sync::mpsc;

use credmgr_store::paths::VaultPaths;
use serde_json::{json, Value};

struct Fake {
    _dir: tempfile::TempDir,
    vault_dir: std::path::PathBuf,
    seen: mpsc::Receiver<Value>,
}

/// A broker that answers each connection with the next scripted response and
/// reports every request it received.
fn fake_broker(script: Vec<Value>) -> Fake {
    // /tmp, not $TMPDIR: a Unix socket path must stay under ~104 bytes.
    let dir = tempfile::Builder::new()
        .prefix("cna")
        .tempdir_in("/tmp")
        .expect("tempdir");
    let vault_dir = dir.path().to_path_buf();
    let paths = VaultPaths::new(vault_dir.clone());
    std::fs::create_dir_all(paths.run_dir()).unwrap();
    std::fs::set_permissions(paths.run_dir(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let listener = UnixListener::bind(paths.run_socket()).expect("bind the stand-in broker");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for reply in script {
            let Ok((stream, _)) = listener.accept() else {
                return;
            };
            let mut writer = stream.try_clone().unwrap();
            let mut line = String::new();
            BufReader::new(stream).read_line(&mut line).unwrap();
            let request: Value = serde_json::from_str(&line).unwrap();
            let _ = tx.send(request);
            writeln!(writer, "{reply}").unwrap();
        }
    });
    Fake {
        _dir: dir,
        vault_dir,
        seen: rx,
    }
}

struct Out {
    ok: bool,
    stdout: String,
    stderr: String,
}

fn run(fx: &Fake, args: &[&str], stdin: Option<&str>) -> Out {
    let mut child = Command::new(env!("CARGO_BIN_EXE_credmgr"))
        .args(args)
        .env("CREDMGR_VAULT_DIR", &fx.vault_dir)
        .env_remove("CREDMGR_TOKEN")
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
    let out = child.wait_with_output().unwrap();
    Out {
        ok: out.status.success(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn step_up_ok() -> Value {
    json!({ "id": "1", "ok": true, "value": { "locked": false, "elevated": true, "expiresIn": 300 } })
}

fn approved_ok() -> Value {
    json!({ "id": "1", "ok": true, "value": { "request": "rq_x", "node": "acme", "entry": "e1" } })
}

fn two_factor_required() -> Value {
    json!({ "id": "1", "ok": false, "error": "two_factor_required", "challenge": "totp" })
}

#[test]
fn gate_verify_reads_the_code_from_stdin() {
    let fx = fake_broker(vec![step_up_ok()]);
    let out = run(&fx, &["gate", "verify"], Some("246810\n"));
    assert!(out.ok, "{}{}", out.stdout, out.stderr);
    assert!(
        out.stdout.contains("second factor accepted"),
        "{}",
        out.stdout
    );
    let req = fx.seen.try_recv().expect("one request reached the broker");
    assert_eq!(req["op"], "vault.gate_verify");
    assert_eq!(req["params"]["code"], "246810");
}

#[test]
fn gate_verify_trims_the_line_and_refuses_an_empty_one_without_calling_the_broker() {
    let fx = fake_broker(vec![step_up_ok()]);
    let out = run(&fx, &["gate", "verify"], Some("  135791 \r\n"));
    assert!(out.ok, "{}{}", out.stdout, out.stderr);
    assert_eq!(fx.seen.try_recv().unwrap()["params"]["code"], "135791");

    let fx = fake_broker(vec![step_up_ok()]);
    let out = run(&fx, &["gate", "verify"], Some("\n"));
    assert!(!out.ok);
    assert!(
        out.stderr.contains("no authenticator code"),
        "{}",
        out.stderr
    );
    let out = run(&fx, &["gate", "verify"], None);
    assert!(
        !out.ok && out.stderr.contains("no authenticator code"),
        "{}",
        out.stderr
    );
    assert!(
        fx.seen.try_recv().is_err(),
        "nothing was sent for an empty code"
    );
}

#[test]
fn the_old_positional_code_is_refused_and_never_sent() {
    let fx = fake_broker(vec![step_up_ok()]);
    let out = run(&fx, &["gate", "verify", "246810"], Some("999999\n"));
    assert!(!out.ok);
    assert!(
        out.stderr.contains("no longer a command-line argument"),
        "{}",
        out.stderr
    );
    assert!(
        !out.stderr.contains("246810") && !out.stdout.contains("246810"),
        "the refusal does not echo the code"
    );
    assert!(fx.seen.try_recv().is_err(), "no request left the process");
}

#[test]
fn the_argv_form_exists_only_behind_its_documented_flag() {
    let fx = fake_broker(vec![step_up_ok(), step_up_ok()]);
    let out = run(&fx, &["gate", "verify", "--code-on-argv", "112233"], None);
    assert!(out.ok, "{}{}", out.stdout, out.stderr);
    assert_eq!(fx.seen.try_recv().unwrap()["params"]["code"], "112233");

    // The old flag name is gone: it is an unknown option, not a silent argv form.
    let out = run(
        &fx,
        &["approve", "rq_x", "--code", "112233"],
        Some("pw-test\n"),
    );
    assert!(
        !out.ok && out.stderr.contains("unknown option"),
        "{}",
        out.stderr
    );
    assert!(fx.seen.try_recv().is_err());

    // And `help` says what the flag costs.
    let help = Command::new(env!("CARGO_BIN_EXE_credmgr"))
        .arg("help")
        .output()
        .unwrap();
    let help = String::from_utf8_lossy(&help.stdout);
    assert!(help.contains("--code-on-argv"), "help lists the flag");
    assert!(
        help.contains("`ps`"),
        "help says the argv form is visible to ps"
    );
}

#[test]
fn approve_takes_the_passphrase_from_the_first_stdin_line_and_the_code_from_the_second() {
    let fx = fake_broker(vec![approved_ok()]);
    let out = run(&fx, &["approve", "rq_x"], Some("pass-test-one\n314159\n"));
    assert!(out.ok, "{}{}", out.stdout, out.stderr);
    assert!(
        out.stdout.contains("approved request rq_x"),
        "{}",
        out.stdout
    );
    let req = fx.seen.try_recv().unwrap();
    assert_eq!(req["op"], "vault.approval_decide");
    assert_eq!(req["params"]["passphrase"], "pass-test-one");
    assert_eq!(req["params"]["code"], "314159");
    assert_eq!(req["params"]["approved"], true);
}

#[test]
fn approve_without_a_second_line_sends_no_code_and_explains_how_to_give_one() {
    let fx = fake_broker(vec![approved_ok(), two_factor_required()]);
    // No second factor asked: the passphrase alone is sent, with no `code`.
    let out = run(&fx, &["approve", "rq_x", "--deny"], Some("pass-test-two\n"));
    assert!(out.ok, "{}{}", out.stdout, out.stderr);
    let req = fx.seen.try_recv().unwrap();
    assert_eq!(req["params"]["passphrase"], "pass-test-two");
    assert!(req["params"].get("code").is_none(), "{req}");
    assert_eq!(req["params"]["approved"], false);

    // Two-factor is on and the pipe held no code: the refusal names the second line.
    let out = run(&fx, &["approve", "rq_x"], Some("pass-test-two\n"));
    assert!(!out.ok);
    assert!(
        out.stderr.contains("second line of stdin") && out.stderr.contains("two_factor_required"),
        "{}",
        out.stderr
    );
    assert!(
        !out.stderr.contains("--code <"),
        "no advice to put the code in argv: {}",
        out.stderr
    );
}

#[test]
fn approve_keeps_an_explicit_argv_code_behind_the_flag() {
    let fx = fake_broker(vec![approved_ok()]);
    let out = run(
        &fx,
        &["approve", "rq_x", "--code-on-argv", "998877"],
        Some("pass-test-three\n"),
    );
    assert!(out.ok, "{}{}", out.stdout, out.stderr);
    let req = fx.seen.try_recv().unwrap();
    assert_eq!(req["params"]["code"], "998877");
    assert_eq!(req["params"]["passphrase"], "pass-test-three");
}
