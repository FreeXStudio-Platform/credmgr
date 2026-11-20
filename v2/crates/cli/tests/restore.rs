//! Issue #36 - `credmgr restore`, the missing half of `credmgr backup`.
//!
//! The semantics of a restore (a complete tree, the generation counter, the refusals)
//! are proved against a real vault in `crates/brokerd/tests/backup_restore.rs`. This file
//! proves the command around them: the backup passphrase comes from stdin and never
//! from argv, a wrong one or a used target changes nothing, and the output says what
//! happened. The archive is built here from a small hand-made vault tree - the command
//! needs no broker and starts none.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use credmgr_store::atomic;
use credmgr_store::paths::VaultPaths;
use secrecy::SecretBox;

fn archive_passphrase() -> &'static str {
    "an archive passphrase for this test"
}

struct Env {
    dir: tempfile::TempDir,
}

impl Env {
    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }
}

/// A tiny vault tree, packed and encrypted exactly as `maintenance.backup` does; the
/// archive file's path.
fn make_archive(env: &Env) -> PathBuf {
    let paths = VaultPaths::new(env.path("source"));
    atomic::write(&paths.registry(), b"registry-json").unwrap();
    atomic::write(&paths.registry_sig(), b"registry-sig").unwrap();
    atomic::write(&paths.root_wrap_pass(), b"pass-wrap").unwrap();
    atomic::write(&paths.node_key("a"), b"node-key-a").unwrap();
    atomic::write(&paths.entry_env("a", "e_1"), b"envelope-1").unwrap();
    atomic::write(&paths.manifest("a"), b"manifest-a").unwrap();
    atomic::write(&paths.notes_env("a"), b"sealed-note").unwrap();
    atomic::write(&paths.archive_dir("sealed").join("node.key"), b"sealed-key").unwrap();
    let state = env.path("source-state");
    atomic::write(&state.join("vaultGeneration.counter"), b"counter").unwrap();

    let plain = credmgr_store::backup::create_backup(&paths, Some(&state)).unwrap();
    let blob = credmgr_keystore::backup_passphrase::encrypt_with_passphrase(
        &SecretBox::new(Box::new(archive_passphrase().to_string())),
        &plain,
    );
    let file = env.path("credmgr-backup-1.enc");
    std::fs::write(&file, blob).unwrap();
    file
}

struct Out {
    ok: bool,
    stdout: String,
    stderr: String,
}

fn run(args: &[&str], stdin: Option<&str>) -> Out {
    // No broker answers here, so a restore is never refused for a daemon this machine happens to run.
    let quiet = std::env::temp_dir().join("credmgr-restore-test-no-broker");
    run_with_vault(args, stdin, &quiet)
}

fn run_with_vault(args: &[&str], stdin: Option<&str>, vault_dir: &Path) -> Out {
    let mut child = Command::new(env!("CARGO_BIN_EXE_credmgr"))
        .args(args)
        .env_remove("CREDMGR_TOKEN")
        .env("CREDMGR_VAULT_DIR", vault_dir)
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
        let _ = child.stdin.take().unwrap().write_all(text.as_bytes());
    }
    let out = child.wait_with_output().unwrap();
    Out {
        ok: out.status.success(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

#[test]
fn restore_rebuilds_the_vault_and_the_counter_from_the_passphrase_on_stdin() {
    let env = Env {
        dir: tempfile::tempdir().unwrap(),
    };
    let archive = make_archive(&env);
    let target = env.path("restored");
    let state = env.path("restored-state");
    let out = run(
        &[
            "restore",
            s(&archive),
            "--to",
            s(&target),
            "--state-dir",
            s(&state),
        ],
        Some(&format!("{}\n", archive_passphrase())),
    );
    assert!(out.ok, "{}{}", out.stdout, out.stderr);
    assert!(out.stdout.contains("restored 8 files"), "{}", out.stdout);
    assert!(
        out.stdout.contains("generation counter restored"),
        "{}",
        out.stdout
    );
    assert!(out.stdout.contains("credmgr unlock"), "{}", out.stdout);
    for rel in [
        "registry.json",
        "keys/root.wrap.pass",
        "nodes/a/notes.env",
        "archive/sealed/node.key",
    ] {
        assert!(target.join(rel).is_file(), "{rel}");
    }
    assert_eq!(
        std::fs::read(state.join("vaultGeneration.counter")).unwrap(),
        b"counter"
    );
    assert!(
        !format!("{}{}", out.stdout, out.stderr).contains(archive_passphrase()),
        "the passphrase is never echoed"
    );
}

#[test]
fn a_wrong_passphrase_or_a_used_target_changes_nothing() {
    let env = Env {
        dir: tempfile::tempdir().unwrap(),
    };
    let archive = make_archive(&env);
    let target = env.path("restored");
    let state = env.path("restored-state");

    let out = run(
        &[
            "restore",
            s(&archive),
            "--to",
            s(&target),
            "--state-dir",
            s(&state),
        ],
        Some("not the passphrase\n"),
    );
    assert!(!out.ok);
    assert!(
        out.stderr.contains("wrong backup passphrase"),
        "{}",
        out.stderr
    );
    assert!(!target.exists() && !state.exists(), "nothing was written");

    // No passphrase on stdin at all.
    let out = run(
        &[
            "restore",
            s(&archive),
            "--to",
            s(&target),
            "--state-dir",
            s(&state),
        ],
        None,
    );
    assert!(
        !out.ok && out.stderr.contains("passphrase is required"),
        "{}",
        out.stderr
    );

    // A target that already holds something is refused before the passphrase is read.
    std::fs::create_dir_all(&target).unwrap();
    std::fs::write(target.join("keep.txt"), b"mine").unwrap();
    let out = run(
        &[
            "restore",
            s(&archive),
            "--to",
            s(&target),
            "--state-dir",
            s(&state),
        ],
        None,
    );
    assert!(!out.ok);
    assert!(
        out.stderr.contains("not an empty directory"),
        "{}",
        out.stderr
    );
    assert_eq!(std::fs::read(target.join("keep.txt")).unwrap(), b"mine");
    assert!(!state.exists());
}

#[test]
fn the_passphrase_has_no_argv_form_and_the_usage_is_explicit() {
    let env = Env {
        dir: tempfile::tempdir().unwrap(),
    };
    let archive = make_archive(&env);
    let out = run(
        &["restore", s(&archive), "--passphrase", "x"],
        Some(&format!("{}\n", archive_passphrase())),
    );
    assert!(
        !out.ok && out.stderr.contains("unknown option"),
        "{}",
        out.stderr
    );
    let out = run(&["restore"], None);
    assert!(
        !out.ok && out.stderr.contains("usage: credmgr restore"),
        "{}",
        out.stderr
    );
    let help = run(&["help"], None);
    assert!(
        help.stdout.contains("credmgr restore <archive>"),
        "help lists restore"
    );
}

#[test]
fn a_restore_is_refused_while_a_broker_answers_and_reads_no_passphrase() {
    // K-23 (d), ADR-156.
    let env = Env {
        dir: tempfile::tempdir().unwrap(),
    };
    let archive = make_archive(&env);
    let live = env.path("live-vault");
    let socket = VaultPaths::new(live.clone()).run_socket();
    std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
    let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    let target = env.path("restored");
    let state = env.path("restored-state");
    let out = run_with_vault(
        &[
            "restore",
            s(&archive),
            "--to",
            s(&target),
            "--state-dir",
            s(&state),
        ],
        Some(&format!("{}\n", archive_passphrase())),
        &live,
    );
    assert!(
        !out.ok && out.stderr.contains("credmgrd is running"),
        "{}",
        out.stderr
    );
    assert!(!target.exists() && !state.exists(), "nothing was written");

    // A socket file nobody listens on (a broker that died) does not block a restore.
    drop(listener);
    let out = run_with_vault(
        &[
            "restore",
            s(&archive),
            "--to",
            s(&target),
            "--state-dir",
            s(&state),
        ],
        Some(&format!("{}\n", archive_passphrase())),
        &live,
    );
    assert!(out.ok, "{}", out.stderr);
}

#[test]
fn json_mode_prints_one_object_for_the_app_and_names_each_refusal_by_code() {
    // ADR-166: the desktop app runs `credmgr restore --json` and passes the code on.
    let env = Env {
        dir: tempfile::tempdir().unwrap(),
    };
    let archive = make_archive(&env);
    let live = env.path("live-vault");
    let socket = VaultPaths::new(live.clone()).run_socket();
    std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
    let target = env.path("restored");
    let state = env.path("restored-state");
    let args = [
        "restore",
        s(&archive),
        "--to",
        s(&target),
        "--state-dir",
        s(&state),
        "--json",
    ];
    let pass = format!("{}\n", archive_passphrase());
    let object = |out: &Out| -> serde_json::Value {
        serde_json::from_str(out.stdout.trim())
            .unwrap_or_else(|e| panic!("one JSON object, got {:?}: {e}", out.stdout))
    };

    // A broker answers: refused before the passphrase is read, nothing written.
    let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    let out = run_with_vault(&args, Some(&pass), &live);
    assert!(!out.ok);
    let v = object(&out);
    assert_eq!(v["error"], "broker_running");
    assert!(v["message"]
        .as_str()
        .unwrap()
        .contains("credmgrd is running"));
    assert!(!target.exists() && !state.exists());
    drop(listener);

    // A wrong passphrase: restore_failed, nothing written.
    let out = run_with_vault(&args, Some("not the passphrase\n"), &live);
    assert!(!out.ok);
    assert_eq!(object(&out)["error"], "restore_failed");
    assert!(!target.exists());

    // The real thing: one object saying what was written.
    let out = run_with_vault(&args, Some(&pass), &live);
    assert!(out.ok, "{}", out.stderr);
    let v = object(&out);
    assert_eq!(v["restored"], true);
    assert_eq!(v["target"], s(&target));
    assert!(v["files"].as_u64().unwrap() > 0);
    assert!(["restored", "keptExisting", "notInArchive", "acceptMarker"]
        .contains(&v["counter"].as_str().unwrap()));

    // Now the target holds a vault: restore_target_not_empty.
    let out = run_with_vault(&args, Some(&pass), &live);
    assert!(!out.ok);
    assert_eq!(object(&out)["error"], "restore_target_not_empty");
}
