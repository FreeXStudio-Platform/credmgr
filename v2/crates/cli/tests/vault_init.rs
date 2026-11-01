//! `credmgr init` (ADR-061) driven as the real compiled binary, over real
//! stdin/stdout pipes, against a real running `credmgrd` — the wire-level
//! counterpart to `crates/brokerd/tests/vault_init.rs`'s direct-dispatch
//! proof. That file proves the on-disk artifacts are cryptographically
//! correct; this file proves the CLI's own op names, JSON field names, and
//! interactive-stdout-flushing actually reach a real broker over a real
//! socket — a class of bug the direct-dispatch test cannot see.
//!
//! Mirrors `broker_integration.rs`'s "real binary, real socket, never a
//! mock" discipline, but starting from an **empty** vault directory — the
//! one fixture shape that file's own `start_fixture_broker` deliberately
//! never builds, because every other command in this binary needs a vault
//! that already exists.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;

use secrecy::SecretBox;

use credmgr_brokerd::state::BrokerState;
use credmgr_keystore::software::SoftwareKeystore;
use credmgr_store::paths::VaultPaths;

const PASSPHRASE: &str = "correct horse battery staple";

struct Fixture {
    vault_dir: PathBuf,
    _tmp: tempfile::TempDir,
}

fn start_fixture_broker_on_empty_vault() -> Fixture {
    let tmp = tempfile::tempdir().expect("tempdir");
    let vault_dir = tmp.path().join("vault");
    let state_dir = tmp.path().join("state");
    std::fs::create_dir_all(&vault_dir).unwrap();
    std::fs::create_dir_all(&state_dir).unwrap();

    let paths = VaultPaths::new(vault_dir.clone());
    std::fs::create_dir_all(paths.run_dir()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(paths.run_dir(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    // Placeholder, matching `credmgrd::main`'s own real startup keystore —
    // never read by `vault.init_begin`'s own throwaway keystore (ADR-061).
    let keystore = SoftwareKeystore::new(SecretBox::new(Box::default()), state_dir.clone());
    let state = Arc::new(BrokerState::new(Box::new(keystore), paths.clone()));
    state.set_state_dir_for_test(state_dir);

    let socket_path = paths.run_socket();
    std::thread::spawn(move || {
        credmgr_brokerd::server::run(state, &socket_path).expect("fixture broker crashed");
    });
    wait_for_socket(&paths.run_socket());

    Fixture {
        vault_dir,
        _tmp: tmp,
    }
}

fn wait_for_socket(path: &Path) {
    for _ in 0..200 {
        if std::os::unix::net::UnixStream::connect(path).is_ok() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    panic!("credmgrd fixture never opened its socket at {path:?}");
}

/// Drives `credmgr init` interactively: writes the passphrase line, reads
/// stdout until the `RECOVERY_CODE=` marker line `cmd_init` prints, writes
/// the confirmation line back (either the real code or a deliberately wrong
/// one), then collects the rest of stdout/stderr and the exit status.
/// Necessarily more involved than `broker_integration.rs`'s single
/// `Command::output()` call — this command is the only one in the binary
/// that needs two round trips of interactive input, which is the whole
/// reason ADR-061 exists in two ops rather than one.
struct InitRun {
    ok: bool,
    stdout: String,
    stderr: String,
    recovery_code: String,
}

fn run_credmgr_init(
    vault_dir: &Path,
    passphrase: &str,
    confirm_with: impl FnOnce(&str) -> String,
) -> InitRun {
    let mut child = Command::new(env!("CARGO_BIN_EXE_credmgr"))
        .arg("init")
        .env("CREDMGR_VAULT_DIR", vault_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to launch credmgr init");

    let mut stdin = child.stdin.take().expect("child stdin");
    writeln!(stdin, "{passphrase}").expect("writing the passphrase line");

    let stdout = child.stdout.take().expect("child stdout");
    let mut reader = BufReader::new(stdout);
    let mut collected_stdout = String::new();
    let mut recovery_code = None;
    loop {
        let mut line = String::new();
        let n = reader
            .read_line(&mut line)
            .expect("reading a line from the child's stdout");
        if n == 0 {
            break; // EOF before the marker — an error path, handled below.
        }
        collected_stdout.push_str(&line);
        if let Some(code) = line.trim().strip_prefix("RECOVERY_CODE=") {
            recovery_code = Some(code.to_string());
            break;
        }
    }

    if let Some(code) = &recovery_code {
        let confirmation = confirm_with(code);
        writeln!(stdin, "{confirmation}").expect("writing the confirmation line");
    }
    drop(stdin); // EOF on stdin — nothing else this process reads afterward.

    // Drain whatever's left of stdout (the "vault created at ..." line, or
    // nothing on an error path).
    use std::io::Read;
    let mut rest = String::new();
    reader
        .read_to_string(&mut rest)
        .expect("reading the rest of the child's stdout");
    collected_stdout.push_str(&rest);

    let output = child.wait_with_output().expect("waiting for credmgr init");
    InitRun {
        ok: output.status.success(),
        stdout: collected_stdout,
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        recovery_code: recovery_code.unwrap_or_default(),
    }
}

#[test]
fn init_over_the_real_binary_and_socket_creates_a_vault() {
    let fixture = start_fixture_broker_on_empty_vault();

    let run = run_credmgr_init(&fixture.vault_dir, PASSPHRASE, |code| code.to_string());
    assert!(run.ok, "credmgr init failed: {}", run.stderr);
    assert!(
        !run.recovery_code.is_empty(),
        "expected a RECOVERY_CODE= line in stdout, got:\n{}",
        run.stdout
    );
    assert!(
        run.stdout.contains("vault created at"),
        "expected a success line, got:\n{}",
        run.stdout
    );

    let paths = VaultPaths::new(fixture.vault_dir.clone());
    assert!(paths.registry().exists(), "registry.json");
    assert!(paths.root_wrap_pass().exists(), "root.wrap.pass");
    assert!(paths.root_wrap_recovery().exists(), "root.wrap.recovery");
}

#[test]
fn init_over_the_real_binary_refuses_a_wrong_confirmation_and_writes_nothing() {
    let fixture = start_fixture_broker_on_empty_vault();

    let run = run_credmgr_init(&fixture.vault_dir, PASSPHRASE, |_real_code| {
        "0000-0000-0000-0000-0000-0000-0000-0000".to_string()
    });
    assert!(
        !run.ok,
        "credmgr init should have failed on a wrong confirmation"
    );

    let paths = VaultPaths::new(fixture.vault_dir.clone());
    assert!(
        !paths.registry().exists(),
        "a wrong confirmation must never write a vault"
    );
}

#[test]
fn init_over_the_real_binary_refuses_a_second_time_once_a_vault_exists() {
    let fixture = start_fixture_broker_on_empty_vault();

    let first = run_credmgr_init(&fixture.vault_dir, PASSPHRASE, |code| code.to_string());
    assert!(first.ok, "first init failed: {}", first.stderr);

    let second = run_credmgr_init(&fixture.vault_dir, "a different passphrase", |code| {
        code.to_string()
    });
    assert!(
        !second.ok,
        "a second init against an already-initialized vault must fail"
    );
}
