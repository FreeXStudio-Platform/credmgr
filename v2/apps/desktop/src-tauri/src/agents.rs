//! Wiring agent clients to CredMgr from Settings (ADR-141, ADR-142, ADR-143).
//!
//! The decisions - which file, what the entry looks like, the splice, the diff, the prompt - are
//! `credmgr_core::agentcfg`, the same pure module `credmgr agent` uses. This file only reads and
//! writes, and **writes nothing the person has not seen**: [`plan`] returns the path, the diff and a
//! `token`; [`apply`] recomputes the plan, refuses (`agent_changed`) if the file moved since the diff
//! was drawn, copies the file to `<file>.credmgr-backup-<time>`, writes through a temporary file and
//! a rename, and reads it back. Claude Code's `~/.claude.json` is never written: it is the client's
//! live state, so CredMgr shows the `claude mcp add` command instead.
//!
//! No broker call, no session, no secret: the shell holds none, and a snippet names only the path
//! to the `credmgr` binary. Not a broker op, so a connect is not an audit record; the backup file
//! is the trail (ADR-142).

use std::io::Write;
use std::path::{Path, PathBuf};

use credmgr_core::agentcfg::{self, Client, Detected, VaultView, CLIENTS};
use serde_json::{json, Value};

use crate::error::{BridgeError, ErrorSource};

/// A bridge-local error with a code from `error::BRIDGE_LOCAL_CODES`.
fn failed(code: &str, detail: impl Into<String>) -> BridgeError {
    BridgeError {
        source: ErrorSource::Bridge,
        code: code.to_string(),
        message: detail.into(),
        detail: None,
    }
}

fn home() -> Result<PathBuf, BridgeError> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .ok_or_else(|| {
            failed(
                "agent_refused",
                "HOME is not set; cannot find the clients' config files",
            )
        })
}

/// The `credmgr` command line tool: `CREDMGR_BIN`, a sibling of this executable, then the usual
/// install folders and `PATH`. `(path, found)`; when not found the bare name, which a client may
/// still resolve on its own `PATH`.
pub fn locate_binary() -> (String, bool) {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(p) = std::env::var_os("CREDMGR_BIN") {
        candidates.push(PathBuf::from(p));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join("credmgr"));
        }
    }
    for dir in ["/opt/homebrew/bin", "/usr/local/bin"] {
        candidates.push(Path::new(dir).join("credmgr"));
    }
    if let Some(h) = std::env::var_os("HOME") {
        let h = PathBuf::from(h);
        candidates.push(h.join(".local/bin/credmgr"));
        candidates.push(h.join(".cargo/bin/credmgr"));
    }
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            candidates.push(dir.join("credmgr"));
        }
    }
    for c in candidates {
        if c.is_absolute() && c.is_file() {
            let c = c.canonicalize().unwrap_or(c);
            if let Some(s) = c.to_str() {
                return (s.to_string(), true);
            }
        }
    }
    ("credmgr".to_string(), false)
}

fn client_of(id: &str) -> Result<Client, BridgeError> {
    Client::parse(id).ok_or_else(|| failed("agent_refused", format!("unknown client '{id}'")))
}

/// ADR-148 (P3): `text` with every string value inside an `"env": { ... }` object replaced by `"<redacted>"`,
/// line by line (the client files are JSON written one key per line). Only for display.
pub fn redact_env_values(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut depth: Option<i32> = None;
    for line in text.split_inclusive('\n') {
        let trimmed = line.trim_start();
        let opens = line.matches('{').count() as i32;
        let closes = line.matches('}').count() as i32;
        match depth {
            None if trimmed.starts_with("\"env\"") && opens > closes => {
                depth = Some(opens - closes);
                out.push_str(line);
            }
            Some(d) => {
                out.push_str(&mask_value(line));
                let d = d + opens - closes;
                depth = (d > 0).then_some(d);
            }
            None => out.push_str(line),
        }
    }
    out
}

/// `  "KEY": "value",` → `  "KEY": "<redacted>",`; any other line unchanged.
fn mask_value(line: &str) -> String {
    let Some(colon) = line.find("\":") else {
        return line.to_string();
    };
    let (head, rest) = line.split_at(colon + 2);
    let value = rest.trim_start();
    if !value.starts_with('"') {
        return line.to_string();
    }
    let tail = value
        .rfind('"')
        .filter(|&end| end > 0)
        .map_or("", |end| &value[end + 1..]);
    format!("{head} \"<redacted>\"{tail}")
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

/// Create `path` new (`O_EXCL`: a file or link already there is an error, never followed) with `mode`.
fn create_new_with_mode(path: &Path, mode: u32) -> std::io::Result<std::fs::File> {
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

/// A temp-name salt another process cannot predict (std's OS-seeded hasher over the clock).
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

fn read_config(path: &Path) -> Result<Option<String>, BridgeError> {
    match std::fs::read_to_string(path) {
        Ok(t) => Ok(Some(t)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(failed(
            "agent_refused",
            format!("cannot read {}: {e}", path.display()),
        )),
    }
}

/// Which clients are on this Mac, their state, and the exact command for Claude Code.
pub fn detect() -> Result<Value, BridgeError> {
    let home = home()?;
    let (binary, found) = locate_binary();
    let mut rows = Vec::new();
    for c in CLIENTS {
        let path = home.join(c.config_rel_path());
        let text = read_config(&path).unwrap_or(None);
        let dir_exists = path.parent().is_some_and(Path::is_dir);
        let d = agentcfg::detect(text.as_deref(), dir_exists, c, &binary);
        rows.push(json!({
            "client": c.id(),
            "label": c.label(),
            "path": path.display().to_string(),
            "state": d.id(),
            "detail": if let Detected::Unreadable(w) = &d { json!(w) } else { Value::Null },
            "writable": c.writable(),
            "container": c.container_key(),
        }));
    }
    Ok(json!({
        "binary": binary,
        "binaryFound": found,
        "clients": rows,
        "claudeCodeCommand": agentcfg::claude_code_command(&binary),
    }))
}

/// The snippet to copy for `client` (`"generic"` for any other client).
pub fn snippet(client: &str) -> Result<Value, BridgeError> {
    let (binary, _) = locate_binary();
    let c = if client == "generic" {
        None
    } else {
        Some(client_of(client)?)
    };
    Ok(json!({
        "client": client,
        "snippet": agentcfg::snippet(c, &binary),
        "command": if c == Some(Client::ClaudeCode) { json!(agentcfg::claude_code_command(&binary)) } else { Value::Null },
    }))
}

/// A stable-within-this-process fingerprint of (old file, new file), so [`apply`] writes exactly what
/// [`plan`] drew.
fn token_of(old: Option<&str>, new: &str) -> String {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    old.hash(&mut h);
    new.hash(&mut h);
    format!("{:016x}", h.finish())
}

struct Computed {
    path: PathBuf,
    existing: Option<String>,
    new_text: String,
    unchanged: bool,
    client: Client,
}

fn compute(client: &str, action: &str) -> Result<Computed, BridgeError> {
    let c = client_of(client)?;
    if !c.writable() {
        let (binary, _) = locate_binary();
        return Err(failed(
            "agent_refused",
            format!(
                "CredMgr never edits {} (Claude Code's live state file). Run this in a terminal instead: {}",
                c.config_rel_path(),
                agentcfg::claude_code_command(&binary)
            ),
        ));
    }
    let path = home()?.join(c.config_rel_path());
    let existing = read_config(&path)?;
    let (binary, _) = locate_binary();
    let plan = match action {
        "connect" => agentcfg::plan_connect(existing.as_deref(), c, &binary),
        "disconnect" => match existing.as_deref() {
            Some(t) => agentcfg::plan_disconnect(t, c),
            None => Ok(agentcfg::Plan {
                new_text: String::new(),
                unchanged: true,
            }),
        },
        other => return Err(failed("agent_refused", format!("unknown action '{other}'"))),
    }
    .map_err(|e| failed("agent_refused", format!("{}: {e}", c.label())))?;
    Ok(Computed {
        path,
        existing,
        new_text: plan.new_text,
        unchanged: plan.unchanged,
        client: c,
    })
}

/// What a connect or disconnect would do - the path, the diff, the backup name - without doing it.
pub fn plan(client: &str, action: &str) -> Result<Value, BridgeError> {
    let c = compute(client, action)?;
    let diff: Vec<Value> = if c.unchanged {
        Vec::new()
    } else {
        // ADR-148 (P3): the webview is shown the shape of the change, never another server's secrets. Every
        // value inside an `env` object (API keys, tokens other MCP servers keep in the same file) is masked
        // in both texts before they are diffed; the token below still binds the real bytes.
        let old = redact_env_values(c.existing.as_deref().unwrap_or(""));
        let new = redact_env_values(&c.new_text);
        agentcfg::line_diff(&old, &new, 2)
            .into_iter()
            .map(|l| json!({ "kind": l.kind.to_string(), "text": l.text }))
            .collect()
    };
    let backup = c
        .existing
        .as_ref()
        .and_then(|_| c.path.file_name().and_then(|n| n.to_str()))
        .map(|n| agentcfg::backup_name(n, "<time>"));
    Ok(json!({
        "client": c.client.id(),
        "label": c.client.label(),
        "action": action,
        "path": c.path.display().to_string(),
        "exists": c.existing.is_some(),
        "unchanged": c.unchanged,
        "diff": diff,
        "backupName": backup,
        "token": token_of(c.existing.as_deref(), &c.new_text),
    }))
}

/// Write the change [`plan`] showed. `token` is the one it returned: if the file or the plan moved
/// since, nothing is written (`agent_changed`).
pub fn apply(client: &str, action: &str, token: &str) -> Result<Value, BridgeError> {
    // ADR-148 (P3): never write a bare `"command": "credmgr"` — a client would run whichever `credmgr` comes
    // first on its own PATH. Without an absolute path to the real binary, connecting is refused.
    if action == "connect" && !locate_binary().1 {
        return Err(failed(
            "agent_refused",
            "the credmgr command was not found on this Mac; install it (the app's Settings shows how) \
             and connect again",
        ));
    }
    let c = compute(client, action)?;
    if token_of(c.existing.as_deref(), &c.new_text) != token {
        return Err(failed(
            "agent_changed",
            "the file changed since the diff was shown; nothing was written. Review it again.",
        ));
    }
    if c.unchanged {
        return Ok(json!({ "written": false, "path": c.path.display().to_string() }));
    }
    let backup = write_with_backup(&c.path, c.existing.as_deref(), &c.new_text)?;
    Ok(json!({
        "written": true,
        "path": c.path.display().to_string(),
        "backup": backup.map(|b| b.display().to_string()),
        "restart": c.client.label(),
    }))
}

/// The Vault Protocol prompt (`format: "prompt"`) or the `CREDMGR.md` text (`"md"`), from the view
/// the screen already has: a node, the nodes it reaches, its level. Names and structure only.
pub fn prompt(
    node: &str,
    reachable: Vec<String>,
    level: &str,
    format: &str,
) -> Result<Value, BridgeError> {
    let level = agentcfg::SecurityLevel::parse(level)
        .ok_or_else(|| failed("agent_refused", format!("unknown security level '{level}'")))?;
    let view = VaultView {
        node: node.to_string(),
        reachable,
        level,
    };
    let (binary, _) = locate_binary();
    let text = match format {
        "md" => agentcfg::credmgr_md(&view, &binary),
        _ => agentcfg::vault_protocol_prompt(&view),
    };
    Ok(json!({ "text": text, "format": format }))
}

// ---- the write ---------------------------------------------------------------------------------

fn stamp_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}{m:02}{d:02}T{:02}{:02}{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

fn write_failed(what: String) -> BridgeError {
    failed("agent_write_failed", what)
}

fn write_with_backup(
    path: &Path,
    old: Option<&str>,
    new: &str,
) -> Result<Option<PathBuf>, BridgeError> {
    let dir = path
        .parent()
        .ok_or_else(|| write_failed("the config file has no folder".into()))?;
    std::fs::create_dir_all(dir)
        .map_err(|e| write_failed(format!("cannot create {}: {e}", dir.display())))?;
    let mut backup = None;
    if old.is_some() {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| write_failed("bad file name".into()))?;
        // ADR-148 (P3): created new, never over an earlier backup or through a planted link.
        let base = agentcfg::backup_name(name, &stamp_now());
        let mut made = None;
        for n in 0..100 {
            let candidate = if n == 0 {
                dir.join(&base)
            } else {
                dir.join(format!("{base}.{n}"))
            };
            match create_new_with_mode(&candidate, original_mode(path)) {
                Ok(mut f) => {
                    f.write_all(old.unwrap_or_default().as_bytes())
                        .and_then(|_| f.sync_all())
                        .map_err(|e| {
                            write_failed(format!("cannot back up {}: {e}", path.display()))
                        })?;
                    made = Some(candidate);
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => {
                    return Err(write_failed(format!(
                        "cannot back up {}: {e}",
                        path.display()
                    )))
                }
            }
        }
        backup =
            Some(made.ok_or_else(|| write_failed(format!("cannot back up {}", path.display())))?);
    }
    // ADR-148 (P3): an unpredictable temp name, created new with its final permissions.
    let tmp = dir.join(format!(
        ".{}.credmgr-tmp-{}-{}",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("config"),
        std::process::id(),
        random_suffix()
    ));
    {
        let mut f = create_new_with_mode(&tmp, original_mode(path))
            .map_err(|e| write_failed(format!("cannot write {}: {e}", tmp.display())))?;
        f.write_all(new.as_bytes())
            .map_err(|e| write_failed(format!("cannot write {}: {e}", tmp.display())))?;
        f.sync_all()
            .map_err(|e| write_failed(format!("cannot sync {}: {e}", tmp.display())))?;
    }
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        write_failed(format!("cannot replace {}: {e}", path.display()))
    })?;
    match std::fs::read_to_string(path) {
        Ok(t) if t == new => Ok(backup),
        _ => Err(write_failed(format!(
            "{} did not read back as written{}",
            path.display(),
            backup.as_ref().map_or(String::new(), |b| format!(
                "; the original is at {}",
                b.display()
            ))
        ))),
    }
}

#[cfg(test)]
mod adr148_tests {
    use super::*;

    #[test]
    fn env_values_of_other_servers_never_reach_the_diff() {
        let text = "{\n  \"mcpServers\": {\n    \"other\": {\n      \"command\": \"npx\",\n      \"env\": {\n        \"API_KEY\": \"value-that-must-not-show\",\n        \"REGION\": \"eu\"\n      }\n    }\n  }\n}\n";
        let shown = redact_env_values(text);
        assert!(!shown.contains("value-that-must-not-show"), "{shown}");
        assert!(!shown.contains("\"eu\""), "{shown}");
        assert!(shown.contains("\"API_KEY\": \"<redacted>\","), "{shown}");
        assert!(
            shown.contains("\"command\": \"npx\""),
            "outside env is unchanged: {shown}"
        );
        assert_eq!(shown.lines().count(), text.lines().count());
    }
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
    fn the_token_changes_with_either_side() {
        assert_ne!(token_of(Some("a"), "b"), token_of(Some("a"), "c"));
        assert_ne!(token_of(Some("a"), "b"), token_of(None, "b"));
        assert_eq!(token_of(Some("a"), "b"), token_of(Some("a"), "b"));
    }

    #[test]
    fn claude_codes_state_file_is_never_planned_for_writing() {
        let e = compute("claude-code", "connect").err().expect("refused");
        assert_eq!(e.code, "agent_refused");
        assert!(e.message.contains("claude mcp add"));
    }
}
