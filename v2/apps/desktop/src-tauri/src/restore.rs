//! Settings > Backup > Restore from a backup (ADR-166): the app's half of `credmgr restore`.
//!
//! **The shell does not restore anything itself.** It runs the `credmgr` command-line
//! program - the one bundled beside the app (`Contents/MacOS/credmgr`, `tauri.conf.json`
//! `bundle.macOS.files`) or an installed one - as `credmgr restore <archive> --to <dir>
//! --json`, writes the backup passphrase to its stdin and reads back one JSON object. So:
//!
//! * there is **one** restore and one set of refusals, the command line's: the target must
//!   be empty or new, and no broker may answer on the vault's socket (K-23 (d), ADR-148's
//!   deferred item, ADR-156). The app shows the command's own code and words;
//! * the shell still links no crypto crate (ADR-035 keeps `credmgr-store` and
//!   `credmgr-keystore` out of this workspace) and decrypts nothing (ADR-001): the
//!   archive's passphrase layer is opened in the `credmgr` process, which writes the
//!   still-sealed vault files and exits;
//! * the passphrase never goes on a command line (argv is visible to every process of the
//!   user); it is written to the child's stdin and the shell's copy is wiped.
//!
//! Local: no broker call, no session, no audit record (there is no broker op for a restore,
//! and there cannot be one: a running broker is exactly what a restore refuses).

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde::Serialize;
use serde_json::Value;
use zeroize::Zeroizing;

use crate::error::BridgeError;

/// The command-line program's name.
pub const CLI_NAME: &str = "credmgr";

/// What a finished restore wrote, from `credmgr restore --json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RestoreDone {
    /// The vault folder the files were written into.
    pub target: String,
    /// Where the generation counter lives.
    pub state_dir: String,
    pub files: u64,
    pub bytes: u64,
    /// `restored`, `keptExisting`, `notInArchive` or `acceptMarker` (`crates/store` `CounterOutcome`).
    pub counter: String,
    /// `false` for an archive older than the complete format (no notes, sealed nodes or history in it).
    pub complete: bool,
}

/// Where a bundled or installed `credmgr` can be, given the app's own executable: beside it in
/// `Contents/MacOS`, in `../Resources` or `../libexec`, then the two install locations
/// `RELEASE.md` names. The same places, in the same order, Start at login looks for `credmgrd`.
pub fn cli_candidates(exe: &Path) -> Vec<PathBuf> {
    crate::login_agent::daemon_candidates(exe)
        .into_iter()
        .filter_map(|p| p.parent().map(|d| d.join(CLI_NAME)))
        .collect()
}

/// The `credmgr` the app runs: the first candidate that is a file.
pub fn locate_cli() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    cli_candidates(&exe).into_iter().find(|p| p.is_file())
}

/// The restore, with the `credmgr` binary and the child's vault folder named (tests point
/// both at throwaway paths; the command passes `None`, so the child resolves the vault the
/// way the broker does, from the same environment). `target` `None` is the command line's
/// default: the vault's own folder, which must then be empty.
pub fn restore_with(
    cli: &Path,
    archive: &str,
    passphrase: Zeroizing<String>,
    target: Option<&str>,
    state_dir: Option<&Path>,
    vault_dir: Option<&Path>,
) -> Result<RestoreDone, BridgeError> {
    if archive.trim().is_empty() {
        return Err(BridgeError::bridge(
            "restore_failed",
            "name the backup archive to restore",
        ));
    }
    if passphrase.is_empty() {
        return Err(BridgeError::bridge(
            "restore_failed",
            "the backup passphrase is required",
        ));
    }
    let mut cmd = Command::new(cli);
    cmd.arg("restore").arg(archive);
    if let Some(t) = target.filter(|t| !t.trim().is_empty()) {
        cmd.arg("--to").arg(t);
    }
    if let Some(s) = state_dir {
        cmd.arg("--state-dir").arg(s);
    }
    cmd.arg("--json")
        .env_remove("CREDMGR_TOKEN")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(v) = vault_dir {
        cmd.env("CREDMGR_VAULT_DIR", v);
    }
    let mut child = cmd.spawn().map_err(|e| {
        BridgeError::bridge(
            "restore_unavailable",
            format!("could not run {}: {e}", cli.display()),
        )
    })?;
    {
        // A refusal is made before the passphrase is read, so the child may already be gone:
        // a broken pipe here is not a failure of its own; the child's answer says what happened.
        let mut line = Zeroizing::new(String::with_capacity(passphrase.len() + 1));
        line.push_str(&passphrase);
        line.push('\n');
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(line.as_bytes());
        }
    }
    drop(passphrase);
    let mut stdout = String::new();
    if let Some(mut out) = child.stdout.take() {
        let _ = out.read_to_string(&mut stdout);
    }
    let status = child.wait().map_err(|e| {
        BridgeError::bridge("restore_failed", format!("the restore did not finish: {e}"))
    })?;
    interpret(status.success(), &stdout)
}

/// One JSON object from `credmgr restore --json`, as the app's answer or its refusal.
pub fn interpret(success: bool, stdout: &str) -> Result<RestoreDone, BridgeError> {
    let last = stdout
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("");
    let v: Value = serde_json::from_str(last).map_err(|_| {
        BridgeError::bridge(
            "restore_failed",
            "the restore gave no answer this app can read; run `credmgr restore` in a terminal to see why",
        )
    })?;
    if let Some(code) = v.get("error").and_then(Value::as_str) {
        let message = v
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("the restore was refused");
        // Each code by name (tests/ts_client.rs reads every `BridgeError::bridge("…")` here and holds
        // it to BRIDGE_LOCAL_CODES); one this shell does not know is a failed restore.
        return Err(match code {
            "broker_running" => BridgeError::bridge("broker_running", message),
            "restore_target_not_empty" => BridgeError::bridge("restore_target_not_empty", message),
            _ => BridgeError::bridge("restore_failed", message),
        });
    }
    if !success || v.get("restored").and_then(Value::as_bool) != Some(true) {
        return Err(BridgeError::bridge(
            "restore_failed",
            "the restore did not say it finished",
        ));
    }
    let text = |k: &str| v.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    Ok(RestoreDone {
        target: text("target"),
        state_dir: text("stateDir"),
        files: v.get("files").and_then(Value::as_u64).unwrap_or(0),
        bytes: v.get("bytes").and_then(Value::as_u64).unwrap_or(0),
        counter: text("counter"),
        complete: v.get("complete").and_then(Value::as_bool).unwrap_or(false),
    })
}

/// The command's body: find `credmgr`, then [`restore_with`].
pub fn restore(
    archive: String,
    passphrase: Zeroizing<String>,
    target: Option<String>,
) -> Result<RestoreDone, BridgeError> {
    let cli = locate_cli().ok_or_else(|| {
        BridgeError::bridge(
            "restore_unavailable",
            "no credmgr command-line program was found beside the app, in /usr/local/bin or in \
             /opt/homebrew/bin; install it, then restore with `credmgr restore` in a terminal",
        )
    })?;
    restore_with(&cli, &archive, passphrase, target.as_deref(), None, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_cli_is_looked_for_where_credmgrd_is() {
        let c = cli_candidates(Path::new(
            "/Applications/CredMgr.app/Contents/MacOS/desktop",
        ));
        assert_eq!(
            c,
            vec![
                PathBuf::from("/Applications/CredMgr.app/Contents/MacOS/credmgr"),
                PathBuf::from("/Applications/CredMgr.app/Contents/Resources/credmgr"),
                PathBuf::from("/Applications/CredMgr.app/Contents/libexec/credmgr"),
                PathBuf::from("/usr/local/bin/credmgr"),
                PathBuf::from("/opt/homebrew/bin/credmgr"),
            ]
        );
    }

    #[test]
    fn a_refusal_keeps_the_command_lines_code_and_words() {
        let e = interpret(
            false,
            r#"{"error":"broker_running","message":"credmgrd is running (it answers on /x)"}"#,
        )
        .unwrap_err();
        assert_eq!(e.code, "broker_running");
        assert!(e.message.contains("credmgrd is running"));
        let e = interpret(
            false,
            r#"{"error":"restore_target_not_empty","message":"m"}"#,
        )
        .unwrap_err();
        assert_eq!(e.code, "restore_target_not_empty");
        // A code this app does not know is a failed restore, never passed on as something else.
        let e = interpret(false, r#"{"error":"surprise","message":"m"}"#).unwrap_err();
        assert_eq!(e.code, "restore_failed");
        let e = interpret(false, "not json").unwrap_err();
        assert_eq!(e.code, "restore_failed");
        let e = interpret(true, r#"{"restored":false}"#).unwrap_err();
        assert_eq!(e.code, "restore_failed");
    }

    #[test]
    fn a_finished_restore_is_read_back_whole() {
        let done = interpret(
            true,
            r#"{"restored":true,"target":"/t","stateDir":"/s","files":7,"bytes":900,"counter":"restored","complete":true}"#,
        )
        .unwrap();
        assert_eq!(
            done,
            RestoreDone {
                target: "/t".into(),
                state_dir: "/s".into(),
                files: 7,
                bytes: 900,
                counter: "restored".into(),
                complete: true
            }
        );
    }

    #[test]
    fn nothing_runs_without_an_archive_or_a_passphrase() {
        let missing = Path::new("/nonexistent/credmgr");
        let e =
            restore_with(missing, " ", Zeroizing::new("p".into()), None, None, None).unwrap_err();
        assert_eq!(e.code, "restore_failed");
        let e = restore_with(
            missing,
            "/a",
            Zeroizing::new(String::new()),
            None,
            None,
            None,
        )
        .unwrap_err();
        assert_eq!(e.code, "restore_failed");
        let e =
            restore_with(missing, "/a", Zeroizing::new("p".into()), None, None, None).unwrap_err();
        assert_eq!(e.code, "restore_unavailable");
    }
}
