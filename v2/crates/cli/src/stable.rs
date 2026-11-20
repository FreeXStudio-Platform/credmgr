//! ADR-130…134 — the command line of the 2.0.0 broker features: `node rekey`, `orphan ls|destroy`,
//! `search --deep`, `export --age`, `audit report`. Each is a thin client of one broker op; the broker
//! decides everything (this binary never decrypts, never holds a key). Declared from `main.rs`, which is
//! where the shared argument helpers (`call`, `take_flag_value`, …) live.

use std::io::Write;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::{json, Value};

use super::{
    call, read_authenticator_code, read_stdin_line, reject_flags, take_bool_flag, take_flag_value,
};

/// What `orphan.destroy` wants typed back: the word that says the person means it.
const DESTROY_CONFIRM: &str = "destroy-sealed-entries";

/// `two_factor_required` is a request to give the second factor, not a failure: say how.
pub(crate) fn with_second_factor_hint(r: Result<Value, String>) -> Result<Value, String> {
    r.map_err(|e| {
        if e.starts_with("two_factor_required") {
            format!(
                "{e}\n  give your authenticator code first (`credmgr gate verify`, or `credmgr gate verify --node <id>` \
                 for a project with its own second factor - the code is read from a prompt), then run this \
                 again - it asks for a fresh code every time"
            )
        } else {
            e
        }
    })
}

// ---- node rekey ------------------------------------------------------------

pub(crate) fn cmd_node_rekey(mut args: Vec<String>) -> Result<(), String> {
    const USAGE: &str = "usage: credmgr node rekey <id>";
    let as_json = take_bool_flag(&mut args, "--json");
    reject_flags(&args, USAGE)?;
    let [id] = args.as_slice() else {
        return Err(USAGE.to_string());
    };
    let v = with_second_factor_hint(call("node.rekey", json!({ "node": id })))?;
    if as_json {
        println!("{v}");
        return Ok(());
    }
    println!(
        "re-keyed '{id}': {} entr{} re-sealed{}, {} retained histor{}, {} removed entr{}\nnew public key {}",
        v["entries"],
        if v["entries"] == 1 { "y" } else { "ies" },
        if v["note"] == true { " and its note" } else { "" },
        v["history"],
        if v["history"] == 1 { "y" } else { "ies" },
        v["removed"],
        if v["removed"] == 1 { "y" } else { "ies" },
        v["publicKey"].as_str().unwrap_or("?"),
    );
    Ok(())
}

// ---- gate ... --node <id> (ADR-135) -----------------------------------------------

pub(crate) fn cmd_node_gate(sub: &str, node: &str, mut args: Vec<String>) -> Result<(), String> {
    const USAGE: &str =
        "usage: credmgr gate enroll --node <id> | gate verify --node <id> [--code-on-argv <n>] | gate remove [--last-door] --node <id>  (the verify code is read from a prompt or stdin)";
    match sub {
        "verify" => {
            // Same rule as the vault's own `gate verify` (issue #39, ADR-113): the code is typed at a prompt or read from stdin,
            // never a bare argument a process list would show; `--code-on-argv <n>` is the explicit, documented exception.
            let on_argv = take_flag_value(&mut args, "--code-on-argv");
            reject_flags(&args, USAGE)?;
            if !args.is_empty() {
                return Err(format!(
                    "the code is no longer a command-line argument (a process list shows it while the command runs).\n{USAGE}"
                ));
            }
            let code = match on_argv {
                Some(code) => code,
                None => read_authenticator_code()?,
            };
            let v = call("node.gate_verify", json!({ "node": node, "code": code }))?;
            println!(
                "{node} is open for {} seconds (its own code; no other project is affected)",
                v["expiresIn"]
            );
            Ok(())
        }
        "enroll" => {
            reject_flags(&args, USAGE)?;
            if !args.is_empty() {
                return Err(USAGE.to_string());
            }
            let begin =
                with_second_factor_hint(call("node.gate_enroll_begin", json!({ "node": node })))?;
            let uri = begin["otpauthUri"]
                .as_str()
                .ok_or("credmgrd did not return an otpauth URI")?;
            println!(
                "Add this to your authenticator app (it is {node}'s own secret - do not share it):"
            );
            println!();
            println!("OTPAUTH_URI={uri}");
            println!();
            println!("Then type the 6-digit code it shows (from stdin, one line):");
            std::io::Write::flush(&mut std::io::stdout()).ok();
            let code = read_stdin_line()?;
            let confirm = call(
                "node.gate_enroll_confirm",
                json!({ "node": node, "code": code.trim() }),
            )?;
            println!();
            println!(
                "{node} now has a second factor of its own. Recovery codes - each works once;"
            );
            println!("store them offline now, they will not be shown again:");
            println!();
            for c in confirm["recoveryCodes"].as_array().into_iter().flatten() {
                if let Some(c) = c.as_str() {
                    println!("GATE_RECOVERY_CODE={c}");
                }
            }
            Ok(())
        }
        "remove" => {
            let last_door = take_bool_flag(&mut args, "--last-door");
            reject_flags(&args, USAGE)?;
            if !args.is_empty() {
                return Err(USAGE.to_string());
            }
            let params = if last_door {
                println!("Vault passphrase (from stdin, one line):");
                std::io::Write::flush(&mut std::io::stdout()).ok();
                let passphrase = read_stdin_line()?;
                println!(
                    "Root recovery code - the one `credmgr init` printed (from stdin, one line):"
                );
                std::io::Write::flush(&mut std::io::stdout()).ok();
                let code = read_stdin_line()?;
                json!({ "node": node, "passphrase": passphrase, "recoveryCode": code })
            } else {
                json!({ "node": node })
            };
            let v = with_second_factor_hint(call("node.gate_remove", params))?;
            println!(
                "{node}: {}",
                if v["removed"] == true {
                    "its own second factor is removed; the vault's applies again"
                } else {
                    "it had no second factor of its own"
                }
            );
            Ok(())
        }
        other => Err(format!("unknown 'gate' subcommand: {other}\n{USAGE}")),
    }
}

// ---- orphan ls | destroy -----------------------------------------------------

pub(crate) fn cmd_orphan(mut args: Vec<String>) -> Result<(), String> {
    const USAGE: &str = "usage: credmgr orphan ls [--json] | credmgr orphan destroy (--all | <entry-id>...) --count <n> --confirm destroy-sealed-entries";
    if args.is_empty() {
        return Err(USAGE.to_string());
    }
    let sub = args.remove(0);
    match sub.as_str() {
        "ls" => {
            let as_json = take_bool_flag(&mut args, "--json");
            reject_flags(&args, USAGE)?;
            let v = call("orphan.list", json!({}))?;
            if as_json {
                println!("{v}");
                return Ok(());
            }
            let rows = v["entries"].as_array().cloned().unwrap_or_default();
            for r in &rows {
                println!(
                    "{}\t{}\t{}",
                    r["entry"].as_str().unwrap_or("?"),
                    r["type"].as_str().unwrap_or("?"),
                    r["name"].as_str().unwrap_or("?")
                );
            }
            eprintln!(
                "{} sealed entr{}",
                rows.len(),
                if rows.len() == 1 { "y" } else { "ies" }
            );
            Ok(())
        }
        // Permanent and never undoable: the person must say how many, and type the word.
        "destroy" => {
            let all = take_bool_flag(&mut args, "--all");
            let count = take_flag_value(&mut args, "--count")
                .ok_or_else(|| format!("--count <n> is required: the number of sealed entries you were shown (`credmgr orphan ls`)\n{USAGE}"))?
                .parse::<u64>()
                .map_err(|_| "--count must be a number".to_string())?;
            let confirm = take_flag_value(&mut args, "--confirm").ok_or_else(|| {
                format!("--confirm {DESTROY_CONFIRM} is required: this deletes sealed entries for good and cannot be undone\n{USAGE}")
            })?;
            reject_flags(&args, USAGE)?;
            if all != args.is_empty() {
                return Err(format!(
                    "name entries to destroy, or say --all - not both, not neither\n{USAGE}"
                ));
            }
            let mut params = json!({ "confirm": confirm, "count": count });
            if !all {
                params["entries"] = json!(args);
            }
            let v = with_second_factor_hint(call("orphan.destroy", params))?;
            println!(
                "destroyed {} sealed entr{}; {} seal record(s) ended, {} retained archive(s) removed. This cannot be undone.",
                v["destroyed"],
                if v["destroyed"] == 1 { "y" } else { "ies" },
                v["sealsForgotten"],
                v["archivesRemoved"]
            );
            Ok(())
        }
        _ => Err(USAGE.to_string()),
    }
}

// ---- search --deep ----------------------------------------------------------

pub(crate) fn cmd_search_content(
    term: &str,
    node: Option<String>,
    as_json: bool,
) -> Result<(), String> {
    let mut params = json!({ "term": term });
    if let Some(node) = node {
        params["node"] = json!(node);
    }
    let v = call("search.content", params)?;
    if as_json {
        println!("{v}");
        return Ok(());
    }
    for r in v["results"].as_array().into_iter().flatten() {
        println!(
            "{}\t{}",
            r["node"].as_str().unwrap_or("?"),
            r["name"].as_str().unwrap_or("?")
        );
    }
    if v["truncated"] == true {
        eprintln!("(the search stopped at its limit - narrow it with --node)");
    }
    Ok(())
}

// ---- export --age ----------------------------------------------------------------

pub(crate) fn cmd_export(mut args: Vec<String>) -> Result<(), String> {
    const USAGE: &str = "usage: credmgr export --node <id> --out <file> --age [--age-recipient <age1...>]... [--force]\n  \
        with --age alone the passphrase is read from stdin (twice: the passphrase, then again to confirm); \
        with --age-recipient the file opens with that age identity and no passphrase is read";
    let node = take_flag_value(&mut args, "--node").ok_or_else(|| USAGE.to_string())?;
    let out = take_flag_value(&mut args, "--out").ok_or_else(|| USAGE.to_string())?;
    let age = take_bool_flag(&mut args, "--age");
    let force = take_bool_flag(&mut args, "--force");
    let mut recipients = Vec::new();
    while let Some(r) = take_flag_value(&mut args, "--age-recipient") {
        recipients.push(r);
    }
    reject_flags(&args, USAGE)?;
    if !args.is_empty() {
        return Err(USAGE.to_string());
    }
    if !age {
        return Err(format!("an export is always encrypted: add --age\n{USAGE}"));
    }
    // Never stdout, never a device: the file is a plain path the person can see and delete.
    let path = std::path::PathBuf::from(&out);
    if out == "-" || out.starts_with("/dev/") {
        return Err(
            "--out must be a file path: an export is never written to stdout or a device"
                .to_string(),
        );
    }
    if path.exists() && !force {
        return Err(format!(
            "{out} already exists - choose another path, or add --force to replace it"
        ));
    }
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        if !parent.is_dir() {
            return Err(format!("the folder {} does not exist", parent.display()));
        }
    }

    let mut params = json!({ "node": node });
    if recipients.is_empty() {
        let passphrase = read_stdin_line()?;
        let again = read_stdin_line()?;
        if passphrase != again {
            return Err("the two passphrases differ - nothing was exported".to_string());
        }
        params["passphrase"] = json!(passphrase);
    } else {
        params["recipients"] = json!(recipients);
    }
    let v = with_second_factor_hint(call("node.export", params))?;
    let bytes = B64
        .decode(v["archive"].as_str().ok_or("the broker sent no archive")?)
        .map_err(|_| "the broker's archive was not valid base64".to_string())?;
    write_private_file(&path, &bytes, force)?;
    println!(
        "wrote {} entr{} of '{}' to {} (age, {}){}",
        v["entries"],
        if v["entries"] == 1 { "y" } else { "ies" },
        node,
        path.display(),
        if recipients.is_empty() {
            "passphrase".to_string()
        } else {
            format!("{} recipient(s)", recipients.len())
        },
        match v["omittedSeeds"].as_u64() {
            Some(n) if n > 0 => format!("; {n} 2FA seed(s) were left out on purpose"),
            _ => String::new(),
        }
    );
    Ok(())
}

/// Write `bytes` to `path` with mode 0600, through a temporary file in the same folder and a rename, so a
/// failure leaves no half file and an existing export is replaced whole or not at all.
fn write_private_file(path: &std::path::Path, bytes: &[u8], replace: bool) -> Result<(), String> {
    use std::os::unix::fs::OpenOptionsExt;
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    let tmp = dir.join(format!(".credmgr-export-{}.tmp", std::process::id()));
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|e| format!("could not create the export file: {e}"))?;
    let written = f.write_all(bytes).and_then(|_| f.sync_all());
    drop(f);
    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("could not write the export: {e}"));
    }
    if !replace {
        // ADR-148 (P3): place it without replacing, atomically — a hard link fails if the name exists, so a
        // file that appears between the check and the placement is never overwritten.
        let placed = std::fs::hard_link(&tmp, path);
        let _ = std::fs::remove_file(&tmp);
        return placed.map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                format!(
                    "{} appeared while exporting - nothing was replaced",
                    path.display()
                )
            } else {
                format!("could not place the export: {e}")
            }
        });
    }
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("could not place the export: {e}")
    })
}

// ---- audit report ------------------------------------------------------------------

/// Days since 1970-01-01 for a civil date (Howard Hinnant's `days_from_civil`, public domain).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `YYYY-MM-DD` -> unix seconds at 00:00 UTC.
pub(crate) fn parse_day(s: &str) -> Result<i64, String> {
    let bad = || format!("'{s}' is not a date - use YYYY-MM-DD");
    let mut it = s.split('-');
    let (Some(y), Some(m), Some(d), None) = (it.next(), it.next(), it.next(), it.next()) else {
        return Err(bad());
    };
    let (y, m, d): (i64, i64, i64) = (
        y.parse().map_err(|_| bad())?,
        m.parse().map_err(|_| bad())?,
        d.parse().map_err(|_| bad())?,
    );
    if !(1970..=9999).contains(&y) || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return Err(bad());
    }
    Ok(days_from_civil(y, m, d) * 86_400)
}

pub(crate) fn cmd_audit_report(mut args: Vec<String>) -> Result<(), String> {
    const USAGE: &str = "usage: credmgr audit report (--days <n> | --from YYYY-MM-DD --to YYYY-MM-DD) [--node <id>] [--json]\n  \
        --to is the first day NOT included (so --from 2026-11-01 --to 2026-12-01 is November)";
    let as_json = take_bool_flag(&mut args, "--json");
    let node = take_flag_value(&mut args, "--node");
    let days = take_flag_value(&mut args, "--days");
    let from = take_flag_value(&mut args, "--from");
    let to = take_flag_value(&mut args, "--to");
    reject_flags(&args, USAGE)?;
    if !args.is_empty() {
        return Err(USAGE.to_string());
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "the system clock is before 1970".to_string())?
        .as_secs() as i64;
    let (from, to) = match (days, from, to) {
        (Some(d), None, None) => {
            let d: i64 = d
                .parse()
                .map_err(|_| "--days must be a number".to_string())?;
            if !(1..=366).contains(&d) {
                return Err("--days is 1 to 366".to_string());
            }
            (now - d * 86_400, now)
        }
        (None, Some(f), Some(t)) => (parse_day(&f)?, parse_day(&t)?),
        _ => return Err(USAGE.to_string()),
    };
    let mut params = json!({ "from": from, "to": to });
    if let Some(node) = node {
        params["node"] = json!(node);
    }
    let r = call("audit.report", params)?;
    if as_json {
        println!("{r}");
        return Ok(());
    }
    print_report(&r);
    Ok(())
}

fn print_report(r: &Value) {
    let n = |v: &Value| v.as_u64().unwrap_or(0);
    println!(
        "audit report: {} record(s) - {} allowed, {} denied{}",
        n(&r["records"]),
        n(&r["decisions"]["allow"]),
        n(&r["decisions"]["deny"]),
        match r["node"].as_str() {
            Some(node) => format!(" (node {node} only)"),
            None => String::new(),
        }
    );
    let table = |title: &str, rows: &Value, key: &str| {
        let rows = rows.as_array().cloned().unwrap_or_default();
        if rows.is_empty() {
            return;
        }
        println!("\n{title}");
        for row in rows.iter().take(15) {
            println!(
                "  {:>6}  {:>5} ok {:>5} denied  {}",
                n(&row["count"]),
                n(&row["allow"]),
                n(&row["deny"]),
                row[key].as_str().unwrap_or("?")
            );
        }
    };
    table("by action", &r["byAction"], "action");
    table("by actor", &r["byActor"], "actor");
    table("by node", &r["byNode"], "node");
    let reasons = r["denials"]["reasons"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    if !reasons.is_empty() {
        println!("\ndenials ({})", n(&r["denials"]["total"]));
        for d in reasons.iter().take(15) {
            println!(
                "  {:>6}  {}  ({})",
                n(&d["count"]),
                d["action"].as_str().unwrap_or("?"),
                d["reason"].as_str().unwrap_or("?")
            );
        }
    }
    println!(
        "\npresence: {} use(s) of a presence-gated action, {} refused for want of it",
        n(&r["presence"]["uses"]),
        n(&r["presence"]["refused"])
    );
    println!(
        "audit chain: {} ({} month(s) checked)",
        if r["chain"]["verified"] == true {
            "intact"
        } else {
            "BROKEN - run `credmgr verify`"
        },
        r["chain"]["months"].as_array().map_or(0, Vec::len)
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn days_are_unix_midnights_utc() {
        assert_eq!(parse_day("1970-01-01").unwrap(), 0);
        assert_eq!(parse_day("2000-03-01").unwrap(), 951_868_800);
        assert_eq!(parse_day("2026-11-06").unwrap(), 1_793_923_200);
        for bad in [
            "2026-13-01",
            "2026-00-10",
            "26-1-1",
            "2026-11",
            "2026-11-06-1",
            "x",
            "1969-12-31",
        ] {
            assert!(parse_day(bad).is_err(), "{bad}");
        }
    }
}
