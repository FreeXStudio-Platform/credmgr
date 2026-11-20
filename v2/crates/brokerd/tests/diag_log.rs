//! ADR-159: the diagnostic log never holds a name, a value, a token or a path.
//!
//! Two halves. The first drives a sample of real ops — successes and failures, each carrying names,
//! values, notes, an `otpauth://` seed and a passphrase in its request — through the real server wiring
//! with the process-wide log on, then reads every file in the log directory and looks for each of those
//! strings. The second starts the real `credmgrd` binary twice: once without the switch (no log
//! directory may appear) and once with it (start-up, recovery and request lines appear, and the same
//! marker strings sent over the socket do not).
mod common;

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use common::*;

/// Every string a request below carries that must never reach the log.
const MARKERS: &[&str] = &[
    "ZEBRA_SECRET_NAME",
    "zebra-secret-value-91731",
    "Zebra Clandestine Project",
    "zebranode",
    "zebra private note text",
    "JBSWY3DPEHPK3PXPZEBRA",
    "otpauth://",
    "zebra wrong passphrase",
    "ZEBRA_ALIAS",
    "zebra-unknown-op",
    "zebra free text reason",
    PASSPHRASE,
];

fn read_all_logs(dir: &std::path::Path) -> String {
    let mut out = String::new();
    if let Ok(read) = std::fs::read_dir(dir) {
        for e in read.flatten() {
            out.push_str(&std::fs::read_to_string(e.path()).unwrap_or_default());
        }
    }
    out
}

fn assert_clean(log: &str, extra: &[&str]) {
    for marker in MARKERS.iter().chain(extra) {
        assert!(
            !log.contains(marker),
            "the diagnostic log holds {marker:?}:\n{log}"
        );
    }
    // Every line is `<timestamp> pid=<n> event=<label>` and `key=value` pairs of plain tokens.
    for line in log.lines() {
        let mut parts = line.split(' ');
        let ts = parts.next().unwrap_or("");
        assert!(ts.len() == 20 && ts.ends_with('Z'), "timestamp: {line}");
        for part in parts {
            let (k, v) = part.split_once('=').unwrap_or_else(|| panic!("{line}"));
            assert!(
                k.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
                "key {k:?} in {line}"
            );
            assert!(
                !v.is_empty()
                    && v.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-'),
                "value {v:?} in {line}"
            );
        }
    }
}

#[test]
fn a_sample_of_ops_with_names_and_values_leaves_none_of_them_in_the_log() {
    let logs = tempfile::tempdir().unwrap();
    credmgr_brokerd::diag_log::install(logs.path()).unwrap();

    let (f, owner, entry) = with_acme();
    let ok = |r: Result<Value, _>| r.expect("op");
    // Successes carrying names and values.
    ok(send(
        &f,
        None,
        Some(&owner),
        "node.create",
        json!({ "id": "zebranode", "label": "Zebra Clandestine Project", "parentId": "global" }),
    ));
    let zebra = ok(send(
        &f,
        None,
        Some(&owner),
        "entry.create",
        json!({ "node": "acme", "name": "ZEBRA_SECRET_NAME", "value": "zebra-secret-value-91731" }),
    ))["entry"]
        .as_str()
        .unwrap()
        .to_string();
    let revealed = ok(send(
        &f,
        None,
        Some(&owner),
        "entry.reveal",
        json!({ "node": "acme", "entry": zebra }),
    ));
    assert!(revealed.to_string().contains("zebra-secret-value-91731"));
    ok(send(
        &f,
        None,
        Some(&owner),
        "entry.create",
        json!({ "node": "acme", "name": "ZEBRA_TOTP",
                "value": "otpauth://totp/Zebra:me?secret=JBSWY3DPEHPK3PXPZEBRA&issuer=Zebra" }),
    ));
    let _ = send(
        &f,
        None,
        Some(&owner),
        "notes.write",
        json!({ "node": "acme", "markdown": "zebra private note text", "generation": 0 }),
    );
    let _ = send(
        &f,
        None,
        Some(&owner),
        "entry.alias",
        json!({ "node": "acme", "entry": entry, "alias": "ZEBRA_ALIAS" }),
    );

    // Failures carrying names and values.
    let dup = send(
        &f,
        None,
        Some(&owner),
        "entry.create",
        json!({ "node": "acme", "name": "ZEBRA_SECRET_NAME", "value": "zebra-secret-value-91731" }),
    );
    assert!(dup.is_err(), "a second entry of the same name is refused");
    assert!(send(
        &f,
        None,
        Some(&owner),
        "entry.reveal",
        json!({ "node": "zebranode-missing", "entry": "ZEBRA_SECRET_NAME" }),
    )
    .is_err());
    assert!(send(
        &f,
        None,
        None,
        "vault.unlock",
        json!({ "passphrase": "zebra wrong passphrase" }),
    )
    .is_err());
    assert!(send(
        &f,
        None,
        Some(&owner),
        "zebra-unknown-op",
        json!({ "value": "zebra-secret-value-91731" }),
    )
    .is_err());
    assert!(send(
        &f,
        None,
        Some("not-a-live-token-zebra"),
        "entry.list",
        json!({ "node": "acme" }),
    )
    .is_err());
    let _ = send(
        &f,
        None,
        Some(&owner),
        "settings.set",
        json!({ "id": "zebra.setting", "value": "zebra-secret-value-91731",
                "reason": "zebra free text reason" }),
    );
    // A token-less Lock-screen poll is not logged when it succeeds.
    ok(send(&f, None, None, "vault.status", json!({})));

    // A panic is recorded by file and line, never by its message.
    let caught = std::panic::catch_unwind(|| {
        panic!("zebra panic message {}", "zebra-secret-value-91731");
    });
    assert!(caught.is_err());

    let log = read_all_logs(logs.path());
    let workdir = f.acme_workdir.to_string_lossy().to_string();
    let vault_dir = f._dir.path().to_string_lossy().to_string();
    let home = std::env::var("HOME").unwrap_or_else(|_| "/nonexistent-home".into());
    assert_clean(
        &log,
        &[
            &owner,
            &entry,
            &zebra,
            &workdir,
            &vault_dir,
            &home,
            "not-a-live-token-zebra",
        ],
    );

    // And it is useful: ops, results and durations are there.
    assert!(
        log.contains("event=request op=node.create result=ok ms="),
        "{log}"
    );
    assert!(log.contains("op=entry.reveal result=ok"), "{log}");
    assert!(log.contains("op=entry.create result=entry_exists"), "{log}");
    assert!(
        log.contains("op=vault.unlock result=wrong_passphrase"),
        "{log}"
    );
    assert!(
        log.contains("op=unlisted result=malformed_request"),
        "{log}"
    );
    assert!(
        log.contains("op=entry.list result=session_expired"),
        "{log}"
    );
    assert!(!log.contains("op=vault.status result=ok"), "{log}");
    assert!(log.contains("event=panic line="), "{log}");
    assert!(log.contains("file=diag_log.rs"), "{log}");
    assert!(!log.contains("zebra panic message"), "{log}");
}

fn wait_for(socket: &std::path::Path) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if UnixStream::connect(socket).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("credmgrd never listened on {}", socket.display());
}

fn call(stream: &mut UnixStream, op: &str, token: Option<&str>, params: Value) -> Value {
    let mut req = json!({ "id": "t", "op": op, "params": params });
    if let Some(t) = token {
        req["token"] = json!(t);
    }
    writeln!(stream, "{req}").unwrap();
    let mut line = String::new();
    BufReader::new(stream.try_clone().unwrap())
        .read_line(&mut line)
        .unwrap();
    serde_json::from_str(&line).unwrap()
}

fn spawn_daemon(dir: &std::path::Path, logs: &std::path::Path, on: bool) -> std::process::Child {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_credmgrd"));
    cmd.env("CREDMGR_VAULT_DIR", dir.join("vault"))
        .env("CREDMGR_STATE_DIR", dir.join("state"))
        .env("CREDMGR_LOG_DIR", logs)
        .env("HOME", dir)
        .env_remove("CREDMGR_DIAG_LOG")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if on {
        cmd.env("CREDMGR_DIAG_LOG", "1");
    }
    cmd.spawn().expect("spawn credmgrd")
}

#[test]
fn the_daemon_writes_no_log_unless_switched_on_and_never_a_name_when_it_does() {
    let f = created_vault();
    let Fixture { state, _dir, .. } = f;
    drop(state);
    let dir = _dir.path();
    let socket = dir.join("vault").join("run").join("broker.sock");

    // Off by default: no directory, no file.
    let off_logs = dir.join("logs-off");
    let mut child = spawn_daemon(dir, &off_logs, false);
    wait_for(&socket);
    {
        let mut s = UnixStream::connect(&socket).unwrap();
        let v = call(
            &mut s,
            "vault.unlock",
            None,
            json!({ "passphrase": "zebra wrong passphrase" }),
        );
        assert_eq!(v["ok"], false);
    }
    let _ = child.kill();
    let _ = child.wait();
    assert!(
        !off_logs.exists(),
        "the log is off unless CREDMGR_DIAG_LOG=1"
    );

    // On: lifecycle and request lines, nothing that was in a request.
    let on_logs = dir.join("logs-on");
    let mut child = spawn_daemon(dir, &on_logs, true);
    wait_for(&socket);
    let token;
    {
        let mut s = UnixStream::connect(&socket).unwrap();
        let v = call(
            &mut s,
            "vault.unlock",
            None,
            json!({ "passphrase": "zebra wrong passphrase" }),
        );
        assert_eq!(v["ok"], false);
        let v = call(
            &mut s,
            "vault.unlock",
            None,
            json!({ "passphrase": PASSPHRASE }),
        );
        token = v["value"]["token"].as_str().expect("token").to_string();
        let v = call(
            &mut s,
            "node.create",
            Some(&token),
            json!({ "id": "zebranode", "label": "Zebra Clandestine Project", "parentId": "global" }),
        );
        assert_eq!(v["ok"], true, "{v}");
        let v = call(
            &mut s,
            "entry.create",
            Some(&token),
            json!({ "node": "zebranode", "name": "ZEBRA_SECRET_NAME", "value": "zebra-secret-value-91731" }),
        );
        assert_eq!(v["ok"], true, "{v}");
        let v = call(
            &mut s,
            "entry.create",
            Some(&token),
            json!({ "node": "zebranode", "name": "ZEBRA_SECRET_NAME", "value": "zebra-secret-value-91731" }),
        );
        assert_eq!(v["ok"], false, "{v}");
        let v = call(&mut s, "zebra-unknown-op", Some(&token), json!({}));
        assert_eq!(v["ok"], false, "{v}");
        writeln!(s, "this is not json ZEBRA_SECRET_NAME").unwrap();
        let mut line = String::new();
        BufReader::new(s.try_clone().unwrap())
            .read_line(&mut line)
            .unwrap();
    }
    let _ = child.kill();
    let _ = child.wait();

    let log = read_all_logs(&on_logs);
    let dir_text = dir.to_string_lossy().to_string();
    assert_clean(&log, &[&token, &dir_text]);
    assert!(log.contains("event=start version="), "{log}");
    assert!(log.contains("vault_dir=override vault=present"), "{log}");
    assert!(log.contains("event=recovery result=nothing"), "{log}");
    assert!(log.contains("event=listening"), "{log}");
    assert!(
        log.contains("op=vault.unlock result=wrong_passphrase"),
        "{log}"
    );
    assert!(log.contains("op=vault.unlock result=ok"), "{log}");
    assert!(log.contains("op=entry.create result=entry_exists"), "{log}");
    assert!(
        log.contains("op=unlisted result=malformed_request"),
        "{log}"
    );
    assert!(log.contains("event=frame error=not_json"), "{log}");
}
