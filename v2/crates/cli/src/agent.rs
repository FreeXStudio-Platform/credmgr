//! Wiring agents to the vault (ADR-141, ADR-142, ADR-143): `credmgr mcp --print-config`,
//! `credmgr agent detect|connect|disconnect|init` and `credmgr prompt`.
//!
//! Everything decided about a client's file - its path, what the entry looks like, the splice, the
//! diff, the prompt text - lives in `credmgr_core::agentcfg`, which is pure. This file only reads
//! and writes.
//!
//! **What this never does:** write a client's config silently. `connect` and `disconnect` print the
//! file, the diff and the backup name first and need `--yes` (or an `y` typed at a terminal) before
//! the file is touched; Claude Code's `~/.claude.json` is never written at all (its live state);
//! a file that is not valid JSON is shown and left alone; the file is copied to
//! `<file>.credmgr-backup-<time>` before every write, written through a temporary file and a rename,
//! and read back and checked afterwards. **What it never carries:** a secret. The prompt and
//! `CREDMGR.md` hold node names, the binary's path and fixed text.

use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};

use credmgr_core::agentcfg::{self, Client, Detected, VaultView, CLIENTS};
use credmgr_core::registry::SecurityLevel;
use serde_json::{json, Value};

use crate::{call, reject_flags, take_bool_flag, take_flag_value};

// ---- paths and the clock -----------------------------------------------------------------------

fn home() -> Result<PathBuf, String> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .ok_or_else(|| "HOME is not set; cannot find the clients' config files".to_string())
}

/// The path written into a client's config: `--binary`, else this very executable.
fn binary_path(explicit: Option<String>) -> Result<String, String> {
    if let Some(p) = explicit {
        let path = Path::new(&p);
        if !path.is_absolute() {
            return Err("--binary must be an absolute path".to_string());
        }
        return Ok(p);
    }
    let exe = std::env::current_exe().map_err(|e| format!("cannot locate this executable: {e}"))?;
    let exe = exe.canonicalize().unwrap_or(exe);
    exe.to_str()
        .map(str::to_string)
        .ok_or_else(|| "this executable's path is not UTF-8".to_string())
}

/// `20261106T101500Z` from the system clock (UTC, civil-from-days; no time crate needed).
fn stamp_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}{m:02}{d:02}T{:02}{:02}{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Howard Hinnant's days-to-civil algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn client_arg(s: &str) -> Result<Client, String> {
    Client::parse(s).ok_or_else(|| {
        format!(
            "unknown client '{s}' - one of: {}",
            CLIENTS
                .iter()
                .map(|c| c.id())
                .collect::<Vec<_>>()
                .join(", ")
        )
    })
}

fn config_path(home: &Path, client: Client) -> PathBuf {
    home.join(client.config_rel_path())
}

/// The permission bits a rewritten file keeps: the original's, or owner read/write for a new file.
fn original_mode(path: &Path) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).map_or(0o600, |m| m.permissions().mode() & 0o777)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        0o600
    }
}

/// Create `path` new (`O_EXCL`; a link already there is an error, never followed) with `mode`.
fn create_new_private(path: &Path, mode: u32) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    options.open(path)
}

/// Sixteen hex characters that another process cannot predict: std's per-process randomly keyed hasher
/// (seeded from the OS) over the clock. A temp-name salt, not key material.
fn random_suffix() -> String {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u128(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos()),
    );
    format!("{:016x}", h.finish())
}

/// ADR-148 (P3): a file this command writes inside a project folder (`CREDMGR.md`) must not be a symbolic
/// link: following one would show, back up and replace whatever it points at (a key in `~/.ssh`, say).
fn refuse_symlink(path: &Path) -> Result<(), String> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => Err(format!(
            "{} is a symbolic link; credmgr will not follow it. Remove the link and run this again",
            path.display()
        )),
        _ => Ok(()),
    }
}

/// ADR-148 addendum: read `path` without ever following a link — `O_NOFOLLOW` on the open itself (a link
/// swapped in after any earlier check is refused by the kernel, not raced), `O_NONBLOCK` so a FIFO planted
/// there cannot hang the command, and the **opened handle** is checked to be a regular file. Returns the text
/// and that file's permission bits (what the backup and the replacement are created with).
fn read_no_follow(path: &Path) -> Result<Option<(String, u32)>, String> {
    use std::io::Read;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut file = match options.open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        #[cfg(unix)]
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
            return Err(format!(
            "{} is a symbolic link; credmgr will not follow it. Remove the link and run this again",
            path.display()
        ))
        }
        Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
    };
    let meta = file
        .metadata()
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    if !meta.is_file() {
        return Err(format!(
            "{} is not a regular file; credmgr will not read or replace it",
            path.display()
        ));
    }
    #[cfg(unix)]
    let mode = {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o777
    };
    #[cfg(not(unix))]
    let mode = 0o600;
    let mut text = String::new();
    file.read_to_string(&mut text)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    Ok(Some((text, mode)))
}

fn read_config(path: &Path) -> Result<Option<String>, String> {
    match std::fs::read_to_string(path) {
        Ok(t) => Ok(Some(t)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("cannot read {}: {e}", path.display())),
    }
}

// ---- credmgr mcp --print-config ----------------------------------------------------------------

/// `credmgr mcp --print-config [<client>]`: the exact configuration for a client, on stdout, so it
/// can be pasted or redirected. Prints nothing else on stdout and touches no file.
pub fn print_config(mut args: Vec<String>) -> Result<(), String> {
    const USAGE: &str = "usage: credmgr mcp --print-config [claude-code|claude-desktop|cursor|vscode|windsurf] [--binary <abs path>]";
    let binary = binary_path(take_flag_value(&mut args, "--binary"))?;
    reject_flags(&args, USAGE)?;
    let client = match args.as_slice() {
        [] => None,
        [one] if one == "generic" => None,
        [one] => Some(client_arg(one)?),
        _ => return Err(USAGE.to_string()),
    };
    print!("{}", agentcfg::snippet(client, &binary));
    match client {
        Some(Client::ClaudeCode) => {
            eprintln!(
                "\nOr, without editing any file, run:\n  {}",
                agentcfg::claude_code_command(&binary)
            );
        }
        Some(c) => {
            eprintln!(
                "\nPaste this into {} (or run `credmgr agent connect {}`).",
                c.config_rel_path(),
                c.id()
            );
        }
        None => {
            eprintln!("\nPaste the \"credmgr\" entry into your client's MCP servers object.");
        }
    }
    Ok(())
}

// ---- credmgr agent ...  -------------------------------------------------------------------------

pub fn cmd_agent(mut args: Vec<String>) -> Result<(), String> {
    const USAGE: &str = "usage: credmgr agent detect [--json]\n\
         \x20      credmgr agent connect <client> [--yes] [--binary <abs path>]\n\
         \x20      credmgr agent disconnect <client> [--yes]\n\
         \x20      credmgr agent init [--node <id>] [--dir <path>] [--yes]\n\
         \x20      credmgr agent token issue|ls|rotate|revoke ...   (node-scoped agent tokens)\n\
         clients: claude-code, claude-desktop, cursor, vscode, windsurf";
    if args.is_empty() {
        return Err(USAGE.to_string());
    }
    let sub = args.remove(0);
    match sub.as_str() {
        "detect" => cmd_detect(args),
        "connect" => cmd_connect(args, true),
        "disconnect" => cmd_connect(args, false),
        "init" => cmd_init_md(args),
        // ADR-164: node-scoped agent tokens (broker ops `agent.token_*`).
        "token" => crate::agent_tokens::cmd_token(args),
        _ => Err(USAGE.to_string()),
    }
}

fn cmd_detect(mut args: Vec<String>) -> Result<(), String> {
    let as_json = take_bool_flag(&mut args, "--json");
    let binary = binary_path(take_flag_value(&mut args, "--binary"))?;
    reject_flags(&args, "usage: credmgr agent detect [--json]")?;
    let home = home()?;
    let mut rows = Vec::new();
    for c in CLIENTS {
        let path = config_path(&home, c);
        let text = read_config(&path).unwrap_or(None);
        let dir_exists = path.parent().is_some_and(Path::is_dir);
        let d = agentcfg::detect(text.as_deref(), dir_exists, c, &binary);
        rows.push((c, path, d));
    }
    if as_json {
        let v: Vec<Value> = rows
            .iter()
            .map(|(c, p, d)| {
                json!({
                    "client": c.id(), "label": c.label(), "path": p.display().to_string(),
                    "state": d.id(), "writable": c.writable(),
                    "detail": if let Detected::Unreadable(w) = d { json!(w) } else { Value::Null },
                })
            })
            .collect();
        println!("{}", json!({ "binary": binary, "clients": v }));
        return Ok(());
    }
    for (c, p, d) in rows {
        println!("{:<18} {:<12} {}", c.label(), d.id(), p.display());
    }
    Ok(())
}

/// Ask `question` on a terminal; anything but y/yes is no. Not a terminal: no.
fn confirm(question: &str) -> bool {
    if !std::io::stdin().is_terminal() {
        return false;
    }
    eprint!("{question} [y/N] ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).is_ok() && matches!(line.trim(), "y" | "Y" | "yes")
}

fn print_diff(old: &str, new: &str) {
    for l in agentcfg::line_diff(old, new, 2) {
        println!("{} {}", l.kind, l.text);
    }
}

/// Copy, write through a temp file and a rename, and read back. The original's permission bits are
/// kept. Returns the backup path when the file existed.
fn write_with_backup(path: &Path, old: Option<&str>, new: &str) -> Result<Option<PathBuf>, String> {
    write_with_backup_mode(path, old, new, original_mode(path))
}

/// [`write_with_backup`] with the permission bits given (read from an already opened handle) rather than looked
/// up again by path.
fn write_with_backup_mode(
    path: &Path,
    old: Option<&str>,
    new: &str,
    mode: u32,
) -> Result<Option<PathBuf>, String> {
    let dir = path.parent().ok_or("the config file has no folder")?;
    std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let mut backup = None;
    if old.is_some() {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or("bad file name")?;
        // ADR-148 (P3): the backup is created new (never through a planted file or link, never over an
        // earlier backup made in the same second) and carries the original's bytes only.
        let original = old.unwrap_or_default();
        let base = agentcfg::backup_name(name, &stamp_now());
        let mut made = None;
        for n in 0..100 {
            let candidate = if n == 0 {
                dir.join(&base)
            } else {
                dir.join(format!("{base}.{n}"))
            };
            match create_new_private(&candidate, mode) {
                Ok(mut f) => {
                    f.write_all(original.as_bytes())
                        .and_then(|_| f.sync_all())
                        .map_err(|e| format!("cannot back up {}: {e}", path.display()))?;
                    made = Some(candidate);
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(format!("cannot back up {}: {e}", path.display())),
            }
        }
        backup = Some(made.ok_or_else(|| format!("cannot back up {}", path.display()))?);
    }
    // ADR-148 (P3): an unpredictable temp name, created new with the final permissions from the start
    // (never a window with wider ones, never through a pre-planted link).
    let tmp = dir.join(format!(
        ".{}.credmgr-tmp-{}-{}",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("config"),
        std::process::id(),
        random_suffix()
    ));
    {
        let mut f = create_new_private(&tmp, mode)
            .map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
        f.write_all(new.as_bytes())
            .map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
        f.sync_all()
            .map_err(|e| format!("cannot sync {}: {e}", tmp.display()))?;
    }
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("cannot replace {}: {e}", path.display())
    })?;
    // Verify: the file on disk is exactly what was shown.
    match std::fs::read_to_string(path) {
        Ok(t) if t == new => Ok(backup),
        _ => Err(format!(
            "{} did not read back as written{}",
            path.display(),
            backup.as_ref().map_or(String::new(), |b| format!(
                "; the original is at {}",
                b.display()
            ))
        )),
    }
}

fn cmd_connect(mut args: Vec<String>, connect: bool) -> Result<(), String> {
    let yes = take_bool_flag(&mut args, "--yes");
    let binary = binary_path(take_flag_value(&mut args, "--binary"))?;
    let usage = if connect {
        "usage: credmgr agent connect <client> [--yes] [--binary <abs path>]"
    } else {
        "usage: credmgr agent disconnect <client> [--yes]"
    };
    reject_flags(&args, usage)?;
    let [name] = args.as_slice() else {
        return Err(usage.to_string());
    };
    let client = client_arg(name)?;
    if !client.writable() {
        return Err(format!(
            "CredMgr never edits {} (it is Claude Code's live state file). Run this instead:\n  {}\n(to remove it: claude mcp remove {})",
            client.config_rel_path(),
            agentcfg::claude_code_command(&binary),
            agentcfg::SERVER_NAME,
        ));
    }
    let home = home()?;
    let path = config_path(&home, client);
    let existing = read_config(&path)?;
    let plan = if connect {
        agentcfg::plan_connect(existing.as_deref(), client, &binary)
    } else {
        match existing.as_deref() {
            Some(t) => agentcfg::plan_disconnect(t, client),
            None => {
                println!("{} has no config file; nothing to remove", client.label());
                return Ok(());
            }
        }
    }
    .map_err(|e| format!("{}: {e}\n(file: {})", client.label(), path.display()))?;
    if plan.unchanged {
        println!(
            "{}: already {} - {} left as it is",
            client.label(),
            if connect { "connected" } else { "disconnected" },
            path.display()
        );
        return Ok(());
    }
    println!("{} - {}", client.label(), path.display());
    print_diff(existing.as_deref().unwrap_or(""), &plan.new_text);
    if existing.is_some() {
        println!(
            "(the file is copied to {}.credmgr-backup-<time> first)",
            path.display()
        );
    }
    if !yes && !confirm("Write this change?") {
        return Err(
            "not written: nothing was changed (pass --yes, or answer y at a terminal)".to_string(),
        );
    }
    let backup = write_with_backup(&path, existing.as_deref(), &plan.new_text)?;
    println!(
        "{} {}{}",
        if connect {
            "connected:"
        } else {
            "disconnected:"
        },
        path.display(),
        backup.map_or(String::new(), |b| format!(" (backup: {})", b.display()))
    );
    println!("Restart {} to pick the change up.", client.label());
    Ok(())
}

// ---- the prompt and CREDMGR.md -----------------------------------------------------------------

/// What the vault says about `node` - names and structure, never a value. With no `node`, the
/// caller's own node as `whoami` reports it.
fn vault_view(node: Option<String>) -> Result<VaultView, String> {
    match node {
        None => {
            let w = call("whoami", json!({}))?;
            let own = w["node"]
                .as_str()
                .ok_or("whoami named no node")?
                .to_string();
            let mut reachable: Vec<String> = w["reachable"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default();
            reachable.sort();
            let level = w["level"]
                .as_str()
                .and_then(SecurityLevel::parse)
                .unwrap_or_default();
            Ok(VaultView {
                node: own,
                reachable,
                level,
            })
        }
        Some(node) => {
            let g = call("graph.snapshot", json!({}))?;
            let rows = g["nodes"]
                .as_array()
                .ok_or("graph.snapshot returned no nodes")?;
            let find = |id: &str| rows.iter().find(|r| r["id"].as_str() == Some(id));
            let start = find(&node).ok_or_else(|| format!("no node '{node}' you can see"))?;
            let level = start["securityLevel"]
                .as_str()
                .and_then(SecurityLevel::parse)
                .unwrap_or_default();
            // The node and its ancestors: what it can read without a grant (06 s3).
            let mut reachable = vec![node.clone()];
            let mut cur = start;
            while let Some(parent) = cur["parentId"].as_str() {
                reachable.push(parent.to_string());
                match find(parent) {
                    Some(p) => cur = p,
                    None => break,
                }
            }
            Ok(VaultView {
                node,
                reachable,
                level,
            })
        }
    }
}

/// `credmgr prompt [--node <id>] [--json]`.
pub fn cmd_prompt(mut args: Vec<String>) -> Result<(), String> {
    const USAGE: &str = "usage: credmgr prompt [--node <id>] [--json]";
    let as_json = take_bool_flag(&mut args, "--json");
    let node = take_flag_value(&mut args, "--node");
    reject_flags(&args, USAGE)?;
    if !args.is_empty() {
        return Err(USAGE.to_string());
    }
    let view = vault_view(node)?;
    let text = agentcfg::vault_protocol_prompt(&view);
    if as_json {
        println!(
            "{}",
            json!({ "node": view.node, "reachable": view.reachable, "level": view.level.as_str(), "prompt": text })
        );
    } else {
        print!("{text}");
    }
    Ok(())
}

/// `credmgr agent init [--node <id>] [--dir <path>] [--yes]`: write `CREDMGR.md` into a work folder.
fn cmd_init_md(mut args: Vec<String>) -> Result<(), String> {
    const USAGE: &str = "usage: credmgr agent init [--node <id>] [--dir <path>] [--yes]";
    let yes = take_bool_flag(&mut args, "--yes");
    let node = take_flag_value(&mut args, "--node");
    let dir = take_flag_value(&mut args, "--dir");
    let binary = binary_path(take_flag_value(&mut args, "--binary"))?;
    reject_flags(&args, USAGE)?;
    if !args.is_empty() {
        return Err(USAGE.to_string());
    }
    let dir = match dir {
        Some(d) => PathBuf::from(d),
        None => {
            std::env::current_dir().map_err(|e| format!("cannot read the current folder: {e}"))?
        }
    };
    if !dir.is_dir() {
        return Err(format!("{} is not a folder", dir.display()));
    }
    let view = vault_view(node)?;
    let text = agentcfg::credmgr_md(&view, &binary);
    let path = dir.join("CREDMGR.md");
    refuse_symlink(&path)?;
    // ADR-148 addendum: the check above is only the friendly message; the read itself refuses a link.
    let (existing, mode) = match read_no_follow(&path)? {
        Some((t, m)) => (Some(t), m),
        None => (None, 0o600),
    };
    if existing.as_deref() == Some(text.as_str()) {
        println!("{} is already up to date", path.display());
        return Ok(());
    }
    println!("{}", path.display());
    print_diff(existing.as_deref().unwrap_or(""), &text);
    let needs_consent = existing.is_some();
    // A new file is the command the person typed; replacing one needs the diff seen and a yes.
    if needs_consent && !yes && !confirm("Replace the existing CREDMGR.md?") {
        return Err(
            "not written: CREDMGR.md already exists (pass --yes to replace it)".to_string(),
        );
    }
    write_with_backup_mode(&path, existing.as_deref(), &text, mode)?;
    println!(
        "wrote {} - it holds node names and rules, no secret",
        path.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_stamp_is_basic_iso8601_utc() {
        let s = stamp_now();
        assert_eq!(s.len(), 16, "{s}");
        assert!(s.ends_with('Z') && s.as_bytes()[8] == b'T');
    }

    #[test]
    fn civil_dates_are_right() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19_723), (2024, 1, 1));
        assert_eq!(civil_from_days(20_398), (2025, 11, 6));
    }

    #[test]
    fn a_relative_binary_path_is_refused() {
        assert!(binary_path(Some("credmgr".into())).is_err());
        assert_eq!(
            binary_path(Some("/usr/local/bin/credmgr".into())).unwrap(),
            "/usr/local/bin/credmgr"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_credmgr_md_is_refused_and_two_backups_in_one_second_do_not_collide() {
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("id_test_key");
        std::fs::write(&secret, "not really a key").unwrap();
        let link = dir.path().join("CREDMGR.md");
        std::os::unix::fs::symlink(&secret, &link).unwrap();
        assert!(refuse_symlink(&link).is_err(), "a link is never followed");
        // ADR-148 addendum: nor by the read itself, whatever an earlier check said (no race to win).
        let refused = read_no_follow(&link).unwrap_err();
        assert!(refused.contains("symbolic link"), "{refused}");
        let fifo_or_dir = dir.path().join("a-folder");
        std::fs::create_dir(&fifo_or_dir).unwrap();
        assert!(
            read_no_follow(&fifo_or_dir).is_err(),
            "the opened handle must be a regular file"
        );
        std::fs::write(&secret, "plain").unwrap();
        assert_eq!(read_no_follow(&secret).unwrap().unwrap().0, "plain");
        assert!(read_no_follow(&dir.path().join("absent"))
            .unwrap()
            .is_none());
        std::fs::remove_file(&link).unwrap();
        assert!(refuse_symlink(&link).is_ok(), "an absent file is fine");

        let cfg = dir.path().join("config.json");
        std::fs::write(&cfg, "a").unwrap();
        let b1 = write_with_backup(&cfg, Some("a"), "b").unwrap().unwrap();
        let b2 = write_with_backup(&cfg, Some("b"), "c").unwrap().unwrap();
        assert_ne!(b1, b2, "the second backup does not overwrite the first");
        assert_eq!(std::fs::read_to_string(&b1).unwrap(), "a");
        assert_eq!(std::fs::read_to_string(&b2).unwrap(), "b");
    }

    #[test]
    fn a_write_keeps_a_backup_and_reads_back() {
        let dir = std::env::temp_dir().join(format!("credmgr-agent-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("mcp.json");
        std::fs::write(&f, "{\"a\": 1}\n").unwrap();
        let plan =
            agentcfg::plan_connect(Some("{\"a\": 1}\n"), Client::Cursor, "/bin/credmgr").unwrap();
        let backup = write_with_backup(&f, Some("{\"a\": 1}\n"), &plan.new_text)
            .unwrap()
            .unwrap();
        assert_eq!(std::fs::read_to_string(&backup).unwrap(), "{\"a\": 1}\n");
        assert_eq!(std::fs::read_to_string(&f).unwrap(), plan.new_text);
        assert!(backup
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("mcp.json.credmgr-backup-"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
