//! `--copy` (rc.2): put a value on the macOS clipboard instead of printing it, and take it off again 30 seconds
//! later - but only if the clipboard still holds that value.
//!
//! The rules, the same ones the desktop shell keeps (`apps/desktop/src-tauri/src/clipboard.rs`):
//!
//! * the value never reaches stdout, stderr or argv. It goes to `pbcopy` on that program's stdin;
//! * a detached copy of this binary (`credmgr __clipboard-clear <seconds>`, a hidden command) is handed the
//!   SHA-256 digest of the value (hex, on ITS stdin - never argv or an environment variable, which `ps` can
//!   show), so it never holds the secret and the value's length cannot matter. It sleeps, reads the clipboard
//!   through `pbpaste`, and empties it only when the digest of what is there is that digest. Something the
//!   person copied in the meantime is never wiped;
//! * unlike the desktop shell, `pbcopy` cannot set the nspasteboard.org "concealed" markers or keep the value off
//!   Universal Clipboard. That is a limit of the tool, stated here rather than hidden.
//!
//! macOS only: where `pbcopy` is missing `--copy` fails with a plain message and nothing is printed.

use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::time::Duration;

use secrecy::zeroize::Zeroizing;
use sha2::{Digest, Sha256};

/// How long a copied value stays on the clipboard.
pub const CLEAR_AFTER_SECS: u64 = 30;
/// The hidden command the detached clearer runs as. Not in the help text.
pub const CLEAR_COMMAND: &str = "__clipboard-clear";

/// Replaces the clipboard's contents with `text`, which travels only on `pbcopy`'s stdin.
fn write_clipboard(text: &str) -> Result<(), String> {
    let mut child = Command::new("pbcopy")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("--copy needs the macOS `pbcopy` and could not start it: {e}"))?;
    let mut stdin = child.stdin.take().ok_or("could not open pbcopy's input")?;
    let wrote = stdin.write_all(text.as_bytes());
    drop(stdin);
    let status = child.wait().map_err(|e| format!("pbcopy failed: {e}"))?;
    if wrote.is_err() || !status.success() {
        return Err("pbcopy did not accept the value; nothing was copied".to_string());
    }
    Ok(())
}

/// What the clipboard holds as text now, or `None` when it cannot be read.
fn read_clipboard() -> Option<Zeroizing<String>> {
    let out = Command::new("pbpaste")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8(out.stdout).ok().map(Zeroizing::new)
}

/// Lower-case hex SHA-256 of `text`: what the clearer is told instead of the value.
pub fn digest(text: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(64);
    for b in Sha256::digest(text.as_bytes()) {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// The rule, apart from the platform: `clear` runs only when `current` hashes to `value_digest`, so only when the
/// clipboard still holds exactly the copied value (of any length). Returns whether it ran.
pub fn clear_if_still(
    value_digest: &str,
    current: Option<&str>,
    clear: impl FnOnce() -> Result<(), String>,
) -> bool {
    match current {
        Some(now) if !now.is_empty() && digest(now) == value_digest => clear().is_ok(),
        _ => false,
    }
}

/// Copies `value` and schedules the clear. The value is not echoed anywhere. A clearer that cannot be started is
/// reported (the value is already on the clipboard, so the person must know it will not clear itself).
pub fn copy_secret(value: &str) -> Result<(), String> {
    write_clipboard(value)?;
    if let Err(why) = spawn_clearer(&digest(value), CLEAR_AFTER_SECS) {
        eprintln!("warning: the clipboard will NOT clear itself ({why}); clear it by hand");
    }
    Ok(())
}

fn spawn_clearer(value_digest: &str, secs: u64) -> Result<(), String> {
    use std::os::unix::process::CommandExt;
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let mut child = Command::new(exe)
        .arg(CLEAR_COMMAND)
        .arg(secs.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        // Its own process group: closing the terminal or Ctrl-C at the prompt must not kill the clear.
        .process_group(0)
        .spawn()
        .map_err(|e| e.to_string())?;
    let mut stdin = child.stdin.take().ok_or("no pipe to the clearer")?;
    stdin
        .write_all(value_digest.as_bytes())
        .map_err(|e| e.to_string())?;
    // Dropping the pipe ends the digest; the child is deliberately not waited for.
    Ok(())
}

/// The hidden `__clipboard-clear <seconds>` command: read the value's digest from stdin, wait, clear if still ours.
pub fn run_clear(args: &[String]) -> Result<(), String> {
    let secs: u64 = args.first().and_then(|s| s.parse().ok()).ok_or(
        "usage: credmgr __clipboard-clear <seconds>  (the value's SHA-256, hex, on stdin)",
    )?;
    let mut wanted = String::new();
    std::io::stdin()
        .take(128)
        .read_to_string(&mut wanted)
        .map_err(|e| e.to_string())?;
    let wanted = wanted.trim();
    if wanted.len() != 64 || !wanted.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("the clearer expects a SHA-256 digest (64 hex digits) on stdin".to_string());
    }
    std::thread::sleep(Duration::from_secs(secs));
    let now = read_clipboard();
    clear_if_still(wanted, now.as_ref().map(|s| s.as_str()), || {
        write_clipboard("")
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn digest_is_lower_case_sha256_hex() {
        assert_eq!(
            digest("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn clears_only_when_the_clipboard_still_holds_exactly_the_value() {
        let want = digest("v-1");
        let ran = Cell::new(false);
        assert!(clear_if_still(&want, Some("v-1"), || {
            ran.set(true);
            Ok(())
        }));
        assert!(ran.get());
        for other in [Some("v-2"), Some("v-1 "), Some(""), None] {
            let ran = Cell::new(false);
            assert!(!clear_if_still(&want, other, || {
                ran.set(true);
                Ok(())
            }));
            assert!(!ran.get(), "must not clear {other:?}");
        }
    }

    #[test]
    fn a_value_longer_than_any_buffer_is_still_cleared() {
        let long = "x7".repeat(10_000);
        let want = digest(&long);
        assert!(clear_if_still(&want, Some(&long), || Ok(())));
        assert!(!clear_if_still(&want, Some(&long[1..]), || Ok(())));
    }

    #[test]
    fn an_empty_clipboard_is_never_a_match() {
        assert!(!clear_if_still(&digest(""), Some(""), || Ok(())));
    }

    #[test]
    fn a_failed_clear_is_not_reported_as_done() {
        assert!(!clear_if_still(
            &digest("v"),
            Some("v"),
            || Err("no".into())
        ));
    }
}
