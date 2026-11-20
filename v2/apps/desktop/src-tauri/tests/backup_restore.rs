//! Restore from a backup (ADR-166) against the **real** programs: a real `credmgrd`
//! makes the archive (`maintenance.backup`, through the bridge's own core), and the real
//! `credmgr` restores it, run by `restore::restore_with` exactly as the
//! `backup_restore` command runs it.
//!
//! * While the broker answers on the vault's socket the restore is refused with
//!   `broker_running` and nothing is written (ADR-148's deferred item, K-23 (d)).
//! * Once the broker has stopped, the same call restores the archive into an empty
//!   folder and says what it wrote; a second restore into that folder is refused with
//!   `restore_target_not_empty`; a wrong passphrase is `restore_failed`.
//!
//! Both binaries come from `<v2>/target/debug` (or `release`, or `$CREDMGRD_BIN` /
//! `$CREDMGR_BIN`): build them with `cargo build -p credmgr-brokerd -p credmgr-cli` in
//! `v2/`. **A missing binary fails these tests** (`CREDMGR_REAL_BROKER=skip` says, out
//! loud, that you know). Everything runs under a private temp root: a throwaway vault,
//! state directory and home; the passphrases are generated fixtures.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use desktop_lib::commands;
use desktop_lib::restore;
use desktop_lib::session::Session;
use tauri::async_runtime::block_on;
use zeroize::Zeroizing;

const TEST_VAULT_PASS: &str = "fixture-pass-restore-61c0";
const TEST_BACKUP_PASS: &str = "fixture-backup-pass-0f3a";

fn v2_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("src-tauri is three levels below v2/")
        .to_path_buf()
}

fn binary(env: &str, name: &str) -> PathBuf {
    if let Some(explicit) = std::env::var_os(env) {
        return PathBuf::from(explicit);
    }
    ["target/debug", "target/release"]
        .iter()
        .map(|d| v2_root().join(d).join(name))
        .find(|p| p.is_file())
        .unwrap_or_else(|| {
            panic!(
                "{name} is not built. Run `cargo build -p credmgr-brokerd -p credmgr-cli` in {} (or set {env}). \
                 These tests are not skipped silently.",
                v2_root().display()
            )
        })
}

struct Root {
    dir: tempfile::TempDir,
}

impl Root {
    fn vault(&self) -> PathBuf {
        self.dir.path().join("v")
    }
    fn state(&self) -> PathBuf {
        self.dir.path().join("s")
    }
    fn home(&self) -> PathBuf {
        self.dir.path().join("h")
    }
    fn socket(&self) -> PathBuf {
        self.vault().join("run").join("broker.sock")
    }
}

struct Daemon {
    child: Child,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start(root: &Root) -> Daemon {
    let log = std::fs::File::create(root.dir.path().join("daemon.log")).expect("log");
    let child = Command::new(binary("CREDMGRD_BIN", "credmgrd"))
        .env("CREDMGR_VAULT_DIR", root.vault())
        .env("CREDMGR_STATE_DIR", root.state())
        .env("HOME", root.home())
        .env_remove("CREDMGR_TOKEN")
        .stdin(Stdio::null())
        .stdout(log.try_clone().expect("log clone"))
        .stderr(log)
        .spawn()
        .expect("start credmgrd");
    let deadline = Instant::now() + Duration::from_secs(20);
    while std::os::unix::net::UnixStream::connect(root.socket()).is_err() {
        assert!(
            Instant::now() < deadline,
            "credmgrd never opened its socket"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    Daemon { child }
}

/// A vault initialised and unlocked through the bridge's cores, then backed up; the archive's path.
fn backed_up(root: &Root) -> PathBuf {
    let session = Session::new();
    let sock = root.socket();
    let begun = block_on(commands::vault_init_begin_at(
        &session,
        sock.clone(),
        TEST_VAULT_PASS.into(),
    ))
    .expect("vault.init_begin");
    let code = begun["recoveryCode"]
        .as_str()
        .expect("recovery code")
        .to_string();
    block_on(commands::vault_init_confirm_at(
        &session,
        sock.clone(),
        code,
    ))
    .expect("vault.init_confirm");
    block_on(commands::vault_unlock_at(
        &session,
        sock.clone(),
        TEST_VAULT_PASS.into(),
    ))
    .expect("vault.unlock");
    let backup = block_on(commands::maintenance_backup_at(
        &session,
        sock,
        TEST_BACKUP_PASS.into(),
        None,
    ))
    .expect("maintenance.backup");
    let path = PathBuf::from(backup["path"].as_str().expect("archive path"));
    let path = if path.is_absolute() {
        path
    } else {
        root.vault().join(path)
    };
    assert!(path.is_file(), "the archive is at {}", path.display());
    path
}

#[test]
fn a_restore_is_refused_while_the_broker_runs_and_goes_through_once_it_has_stopped() {
    if std::env::var("CREDMGR_REAL_BROKER").as_deref() == Ok("skip") {
        eprintln!(
            "CREDMGR_REAL_BROKER=skip: the restore tests against the real programs were NOT run"
        );
        return;
    }
    let cli = binary("CREDMGR_BIN", "credmgr");
    // A Unix socket path must stay under ~104 bytes, so the root is short and in /tmp.
    let root = Root {
        dir: tempfile::Builder::new()
            .prefix("cmrs")
            .tempdir_in("/tmp")
            .expect("temp root"),
    };
    for d in [root.vault(), root.state(), root.home()] {
        std::fs::create_dir_all(d).expect("mkdir");
    }
    let daemon = start(&root);
    let archive = backed_up(&root);
    let archive_s = archive.to_str().unwrap();
    let target = root.dir.path().join("restored");
    let target_s = target.to_str().unwrap();
    let new_state = root.dir.path().join("restored-state");

    // The broker answers on the vault's socket: refused, before the passphrase is read; nothing written.
    let e = restore::restore_with(
        &cli,
        archive_s,
        Zeroizing::new(TEST_BACKUP_PASS.to_string()),
        Some(target_s),
        Some(&new_state),
        Some(&root.vault()),
    )
    .unwrap_err();
    assert_eq!(e.code, "broker_running", "{e:?}");
    assert!(e.message.contains("credmgrd is running"), "{}", e.message);
    assert!(
        !target.exists() && !new_state.exists(),
        "nothing was written"
    );

    // The broker stops (the app quits, or Start at login is turned off).
    drop(daemon);

    // A wrong passphrase: restore_failed, nothing written.
    let e = restore::restore_with(
        &cli,
        archive_s,
        Zeroizing::new("not the backup passphrase".to_string()),
        Some(target_s),
        Some(&new_state),
        Some(&root.vault()),
    )
    .unwrap_err();
    assert_eq!(e.code, "restore_failed", "{e:?}");
    assert!(!target.exists());

    // The real thing.
    let done = restore::restore_with(
        &cli,
        archive_s,
        Zeroizing::new(TEST_BACKUP_PASS.to_string()),
        Some(target_s),
        Some(&new_state),
        Some(&root.vault()),
    )
    .expect("restore");
    assert_eq!(done.target, target_s);
    assert!(done.files > 0 && done.bytes > 0, "{done:?}");
    assert_eq!(done.counter, "acceptMarker"); // ADR-148 amendment: a restore ticket, not the counter
    assert!(done.complete);
    assert!(target.join("registry.json").is_file() || target.read_dir().unwrap().next().is_some());

    // That folder now holds a vault: restore_target_not_empty.
    let e = restore::restore_with(
        &cli,
        archive_s,
        Zeroizing::new(TEST_BACKUP_PASS.to_string()),
        Some(target_s),
        Some(&new_state),
        Some(&root.vault()),
    )
    .unwrap_err();
    assert_eq!(e.code, "restore_target_not_empty", "{e:?}");

    // The restored vault opens: a broker on it unlocks with the vault passphrase.
    let restored_root = Root {
        dir: tempfile::Builder::new()
            .prefix("cmrt")
            .tempdir_in("/tmp")
            .expect("temp root"),
    };
    std::fs::rename(&target, restored_root.vault()).expect("move the restored vault");
    std::fs::rename(&new_state, restored_root.state()).expect("move its counter");
    std::fs::create_dir_all(restored_root.home()).expect("mkdir");
    let _again = start(&restored_root);
    let session = Session::new();
    let state = block_on(commands::vault_unlock_at(
        &session,
        restored_root.socket(),
        TEST_VAULT_PASS.into(),
    ))
    .expect("the restored vault unlocks");
    assert!(state.authenticated && !state.locked);
}
