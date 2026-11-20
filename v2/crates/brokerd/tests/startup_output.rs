//! ADR-159 amendment: what `credmgrd` prints at start-up and shutdown carries no home directory
//! and so no user name. The login agent used to send these lines to uncapped files; they are now
//! discarded there, and the lines themselves are name-free as a second guard.
//!
//! The paths below are generic fixtures (a temporary directory standing in for the home folder).

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

fn spawn(home: &std::path::Path, diag: bool) -> Child {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_credmgrd"));
    cmd.env("HOME", home)
        .env("CREDMGR_VAULT_DIR", home.join("vault-folder"))
        .env("CREDMGR_STATE_DIR", home.join("state-folder"))
        .env("CREDMGR_LOG_DIR", home.join("log-folder"))
        .env_remove("CREDMGR_DIAG_LOG")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if diag {
        cmd.env("CREDMGR_DIAG_LOG", "1");
    }
    cmd.spawn().expect("spawn credmgrd")
}

/// Collect every line the child prints until `needle` appears or `within` passes.
fn collect(child: &mut Child, needle: &str, within: Duration) -> String {
    let (tx, rx) = mpsc::channel::<String>();
    let out = child.stdout.take().unwrap();
    let err = child.stderr.take().unwrap();
    for r in [
        Box::new(out) as Box<dyn std::io::Read + Send>,
        Box::new(err) as Box<dyn std::io::Read + Send>,
    ] {
        let tx = tx.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(r).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
    }
    let mut seen = String::new();
    let deadline = Instant::now() + within;
    while Instant::now() < deadline && !seen.contains(needle) {
        if let Ok(line) = rx.recv_timeout(Duration::from_millis(50)) {
            seen.push_str(&line);
            seen.push('\n');
        }
    }
    // A moment more, so a line printed just after the needle is held to the same rule.
    while let Ok(line) = rx.recv_timeout(Duration::from_millis(300)) {
        seen.push_str(&line);
        seen.push('\n');
    }
    seen
}

#[test]
fn no_start_up_line_contains_the_home_directory() {
    let home = tempfile::tempdir().unwrap();
    let home_text = home.path().to_str().unwrap().to_string();
    let mut child = spawn(home.path(), true);
    let seen = collect(&mut child, "listening on", Duration::from_secs(30));
    let _ = child.kill();
    let _ = child.wait();

    assert!(
        seen.contains("listening on"),
        "the start-up line other tools wait for stays: {seen}"
    );
    assert!(
        seen.contains("no vault"),
        "a fresh folder says there is no vault yet: {seen}"
    );
    assert!(
        !seen.contains(&home_text),
        "a start-up line carries the home directory: {seen}"
    );
    assert!(
        !seen.contains("vault-folder")
            && !seen.contains("state-folder")
            && !seen.contains("log-folder")
            && !seen.contains(".sock"),
        "a start-up line names a folder or the socket: {seen}"
    );
    if let Ok(real_home) = std::env::var("USER") {
        assert!(
            real_home.len() < 3 || !seen.contains(&real_home),
            "a start-up line carries the user name: {seen}"
        );
    }
}

#[test]
fn a_second_broker_on_the_same_vault_refuses_without_naming_the_socket() {
    let home = tempfile::tempdir().unwrap();
    let home_text = home.path().to_str().unwrap().to_string();
    let mut first = spawn(home.path(), false);
    let seen_first = collect(&mut first, "listening on", Duration::from_secs(30));
    assert!(seen_first.contains("listening on"), "{seen_first}");

    let mut second = spawn(home.path(), false);
    let seen = collect(&mut second, "server error", Duration::from_secs(30));
    let _ = second.wait();
    let _ = first.kill();
    let _ = first.wait();

    assert!(
        seen.contains("server error") || seen.contains("already serving"),
        "the refusal is reported: {seen}"
    );
    assert!(
        !seen.contains(&home_text) && !seen.contains(".sock"),
        "the refusal carries a path: {seen}"
    );
}
