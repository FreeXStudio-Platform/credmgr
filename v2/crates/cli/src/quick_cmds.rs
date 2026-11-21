//! ADR-156 — the command line of the post-launch quick wins: `passphrase`, `expiring`, `history`,
//! `find`; ADR-158's `move`; ADR-161's `doctor --scan`; and ADR-163's `recover`. Each is a thin client of one broker op; the broker decides everything (this binary never
//! decrypts, never holds a key). Declared from `main.rs`, which is where the shared argument helpers
//! (`call`, `take_flag_value`, …) live.

use std::io::{IsTerminal, Write};

use secrecy::zeroize::Zeroizing;
use serde_json::{json, Value};

use super::stable::with_second_factor_hint;
use super::{call, read_stdin_line, reject_flags, take_bool_flag, take_flag_value};

// ---- passphrase ------------------------------------------------------------

/// Reads one secret line: at a terminal it is asked for on stderr (stdout stays the machine-readable
/// answer) without echo where the terminal allows it; piped, it is the next stdin line.
pub(crate) fn ask_secret(prompt: &str) -> Result<Zeroizing<String>, String> {
    if std::io::stdin().is_terminal() {
        eprint!("{prompt}: ");
        std::io::stderr().flush().ok();
    }
    read_stdin_line().map(Zeroizing::new)
}

/// `credmgr passphrase` — change the vault passphrase (`vault.set_passphrase`). The current
/// passphrase, then the new one, are read from stdin (one line each; at a terminal the new one is
/// asked twice). The change is a full root rotation, so a new recovery code is printed once.
pub(crate) fn cmd_passphrase(mut args: Vec<String>) -> Result<(), String> {
    const USAGE: &str =
        "usage: credmgr passphrase   (current passphrase, then the new one, from stdin)";
    let as_json = take_bool_flag(&mut args, "--json");
    reject_flags(&args, USAGE)?;
    if !args.is_empty() {
        return Err(USAGE.to_string());
    }
    let current = ask_secret("Current passphrase")?;
    if current.is_empty() {
        return Err("the current passphrase is required (first stdin line)".to_string());
    }
    let new = ask_secret("New passphrase")?;
    if new.is_empty() {
        return Err("a new passphrase is required (second stdin line)".to_string());
    }
    if std::io::stdin().is_terminal() {
        let again = ask_secret("New passphrase again")?;
        if *again != *new {
            return Err("the two new passphrases differ - nothing was changed".to_string());
        }
    }
    let value = with_second_factor_hint(call(
        "vault.set_passphrase",
        json!({ "passphrase": current.as_str(), "newPassphrase": new.as_str() }),
    ))?;
    if as_json {
        println!("{value}");
        return Ok(());
    }
    println!("passphrase changed");
    print!("{}", machine_lock_lines(&value));
    if let Some(code) = value["recoveryCode"].as_str() {
        println!();
        println!("New vault recovery code - write this down now, it will not be shown again:");
        println!("(the old recovery code no longer works)");
        println!();
        println!("RECOVERY_CODE={code}");
        println!();
    }
    if value["completionPending"].as_bool() == Some(true) {
        println!(
            "note: the change is committed and the vault locked itself; unlock with the NEW passphrase to finish it"
        );
    }
    Ok(())
}

/// ADR-165 (review P1-4): what a root rotation did to the machine lock, in words, after every passphrase
/// change and recovery. A lock that went away is a warning, never silence.
pub(crate) fn machine_lock_lines(value: &Value) -> String {
    let mut out = String::new();
    if let Some(why) = value["machineLockRemoved"].as_str() {
        out.push_str(&format!(
            "warning: the machine lock is OFF now - the new passphrase file could not be sealed to this Mac \
             ({why}). A copy of the vault folder opens with the passphrase alone until you run \
             `credmgr keystore bind` again.\n"
        ));
    } else if value["machineLocked"].as_bool() == Some(true) {
        out.push_str("machine lock: still on (the new passphrase file is sealed to this Mac)\n");
        if value["deviceKeyCreated"].as_bool() == Some(true) {
            out.push_str(
                "note: this Mac had no device key; one was made, and the vault is now locked to this Mac\n",
            );
        }
    }
    out
}

// ---- recover (ADR-163) -------------------------------------------------------

/// Overwrite every string inside `value` with zeros before it is dropped: the request a secret travelled in
/// is not left in freed memory by this process (the copies the transport made are its own to drop).
pub(crate) fn wipe_strings(value: &mut Value) {
    match value {
        Value::String(s) => {
            use secrecy::zeroize::Zeroize;
            s.zeroize();
        }
        Value::Array(items) => items.iter_mut().for_each(wipe_strings),
        Value::Object(map) => map.values_mut().for_each(wipe_strings),
        _ => {}
    }
}

/// `credmgr recover` — the passphrase is forgotten: open the vault with the recovery code (`vault.recover`).
/// The recovery code, then the new passphrase, are read from stdin (one line each; at a terminal the new
/// passphrase is asked twice). When the vault has a second factor, its code (or one of its printed backup
/// codes) is asked for after the broker says so, or read from a third stdin line. A new passphrase is set and
/// a new recovery code printed once, in the same step: the code that was used stops working. Nothing is ever
/// taken from the command line.
pub(crate) fn cmd_recover(mut args: Vec<String>) -> Result<(), String> {
    const USAGE: &str =
        "usage: credmgr recover [--json]   (recovery code, then the new passphrase, then a \
                         second-factor code if one is enrolled - one stdin line each)";
    let as_json = take_bool_flag(&mut args, "--json");
    reject_flags(&args, USAGE)?;
    if !args.is_empty() {
        return Err(USAGE.to_string());
    }
    let status = call("vault.status", json!({}))?;
    if status["locked"].as_bool() == Some(false) {
        return Err(
            "the vault is unlocked - change the passphrase with `credmgr passphrase` instead"
                .to_string(),
        );
    }
    if status["recoveryUnlock"].as_bool() == Some(false) {
        return Err(
            "this vault cannot be opened with a recovery code yet: it has no recovery-code wrap. One is \
             written the next time the passphrase is changed (`credmgr passphrase`) or the root key is \
             rotated; until then only the passphrase opens it"
                .to_string(),
        );
    }
    let code = ask_secret("Recovery code")?;
    if code.trim().is_empty() {
        return Err("the recovery code is required (first stdin line)".to_string());
    }
    let new = ask_secret("New passphrase")?;
    if new.is_empty() {
        return Err("a new passphrase is required (second stdin line)".to_string());
    }
    if std::io::stdin().is_terminal() {
        let again = ask_secret("New passphrase again")?;
        if *again != *new {
            return Err("the two new passphrases differ - nothing was changed".to_string());
        }
    }
    let mut params = json!({ "recoveryCode": code.as_str(), "newPassphrase": new.as_str() });
    let mut answer = call("vault.recover", params.clone());
    if matches!(&answer, Err(e) if e.starts_with("two_factor_required")) {
        let factor = ask_secret("Authenticator code (or one of its printed backup codes)")?;
        if factor.trim().is_empty() {
            wipe_strings(&mut params);
            return Err(
                "this vault has a second factor: give its code on the third stdin line - nothing was changed"
                    .to_string(),
            );
        }
        params["code"] = json!(factor.trim());
        answer = call("vault.recover", params.clone());
    }
    wipe_strings(&mut params);
    let mut value = answer.map_err(|e| {
        if e.starts_with("recovery_code_mismatch") {
            "recovery_code_mismatch: that recovery code does not open this vault - nothing was changed \
             (wrong guesses are rate-limited, like wrong passphrases)"
                .to_string()
        } else if e.starts_with("gate_verification_failed") {
            "gate_verification_failed: the second-factor code was not accepted - nothing was changed".to_string()
        } else {
            e
        }
    })?;
    if as_json {
        println!("{value}");
        wipe_strings(&mut value);
        return Ok(());
    }
    println!("vault recovered - the new passphrase is set");
    print!("{}", machine_lock_lines(&value));
    if let Some(code) = value["recoveryCode"].as_str() {
        println!();
        println!("New vault recovery code - write this down now, it will not be shown again:");
        println!("(the recovery code you just used no longer works)");
        println!();
        println!("RECOVERY_CODE={code}");
        println!();
    }
    // `locked: true` without a pending move: committed, files in place, but the broker could not open the node
    // keys and locked the vault again (ADR-163 review P2-a). Either way there is no login to hand out.
    if value["completionPending"].as_bool() == Some(true) || value["locked"].as_bool() == Some(true)
    {
        println!(
            "note: the change is committed and the vault locked itself; unlock with the NEW passphrase to finish it"
        );
    } else if let Some(token) = value["token"].as_str() {
        println!("export CREDMGR_TOKEN={token}");
        println!(
            "# CREDMGR_TOKEN opens every project in this vault until it locks - \
             keep it out of any shell an AI agent runs in. (Unlocked from inside a project's folder it \
             reaches that project only, and only from that folder.)"
        );
    }
    wipe_strings(&mut value);
    Ok(())
}

// ---- dates -----------------------------------------------------------------

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's `days_from_civil`).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `YYYY-MM-DD` (UTC) for unix seconds.
pub(crate) fn utc_date(secs: i64) -> String {
    let z = secs.div_euclid(86_400) + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

/// `--at`: unix seconds, or `YYYY-MM-DD` read as the start of that day in UTC.
pub(crate) fn parse_at(text: &str) -> Result<i64, String> {
    if let Ok(secs) = text.parse::<i64>() {
        return Ok(secs);
    }
    let bad = || format!("--at takes YYYY-MM-DD or unix seconds, not '{text}'");
    let parts: Vec<&str> = text.split('-').collect();
    let [y, m, d] = parts.as_slice() else {
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
    let secs = days_from_civil(y, m, d) * 86_400;
    // Refuse a day that does not exist (2027-02-30 would otherwise roll into March).
    if utc_date(secs) != format!("{y:04}-{m:02}-{d:02}") {
        return Err(bad());
    }
    Ok(secs)
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn opt_date(v: &Value) -> String {
    v.as_i64().map(utc_date).unwrap_or_else(|| "-".to_string())
}

// ---- expire / expiring -----------------------------------------------------

/// `credmgr expire <name>` — set or clear an entry's expiry (`entry.set_expiry`).
pub(crate) fn cmd_expire(mut args: Vec<String>) -> Result<(), String> {
    const USAGE: &str =
        "usage: credmgr expire <name> [--node <id>] (--at <YYYY-MM-DD|unix seconds> | --in <days> | --clear)";
    let node = take_flag_value(&mut args, "--node");
    let at = take_flag_value(&mut args, "--at");
    let within = take_flag_value(&mut args, "--in");
    let clear = take_bool_flag(&mut args, "--clear");
    reject_flags(&args, USAGE)?;
    let [name] = args.as_slice() else {
        return Err(USAGE.to_string());
    };
    let expires_at: Value = match (at, within, clear) {
        (Some(at), None, false) => json!(parse_at(&at)?),
        (None, Some(days), false) => {
            let days: i64 = days
                .trim_end_matches('d')
                .parse()
                .ok()
                .filter(|d| (1..=36_500).contains(d))
                .ok_or("--in takes a number of days, 1 to 36500")?;
            json!(now_secs() + days * 86_400)
        }
        (None, None, true) => Value::Null,
        _ => return Err(USAGE.to_string()),
    };
    let (node, entry) = super::resolve_name(name, node.as_deref())?;
    let generation = call("entry.list", json!({ "node": node }))?["generation"]
        .as_u64()
        .ok_or("credmgrd did not return the node's generation")?;
    let mut params = json!({ "node": node, "entry": entry, "generation": generation });
    if expires_at.is_null() {
        params["clear"] = json!(true);
    } else {
        params["expiresAt"] = expires_at;
    }
    let value = with_second_factor_hint(call("entry.set_expiry", params))?;
    match value["expiresAt"].as_i64() {
        Some(at) => println!("{name} expires {} (UTC)", utc_date(at)),
        None => println!("{name} no longer has an expiry"),
    }
    Ok(())
}

/// `credmgr move` — move an entry to another node (`entry.move`, ADR-158). The broker re-encrypts it to the
/// destination's key; this prints where it went and what changed with it, never a value. The owner's
/// login only; a fresh authenticator code and Touch ID every time (proved automatically when enrolled).
pub(crate) fn cmd_move(mut args: Vec<String>) -> Result<(), String> {
    const USAGE: &str =
        "usage: credmgr move <name> [--node <id>] --to <id> [--reason <text>] [--json]";
    let as_json = take_bool_flag(&mut args, "--json");
    let node = take_flag_value(&mut args, "--node");
    let to = take_flag_value(&mut args, "--to");
    let reason = take_flag_value(&mut args, "--reason");
    reject_flags(&args, USAGE)?;
    let ([name], Some(to)) = (args.as_slice(), to) else {
        return Err(USAGE.to_string());
    };
    let (node, entry) = super::resolve_name(name, node.as_deref())?;
    if node == to {
        return Err(format!("'{name}' is already in '{to}'"));
    }
    let generation = call("entry.list", json!({ "node": node }))?["generation"]
        .as_u64()
        .ok_or("credmgrd did not return the node's generation")?;
    let mut params = json!({ "node": node, "entry": entry, "to": to, "generation": generation });
    if let Some(reason) = reason {
        params["reason"] = json!(reason);
    }
    let value = with_second_factor_hint(call("entry.move", params))?;
    if as_json {
        println!("{value}");
        return Ok(());
    }
    println!("moved '{name}' from '{node}' to '{to}' (re-encrypted to {to}'s key; same ref)");
    let revoked = value["grantsRevoked"].as_array().map_or(0, Vec::len);
    if revoked > 0 {
        println!(
            "{revoked} grant{} that named it in '{node}' revoked",
            if revoked == 1 { "" } else { "s" }
        );
    }
    let dropped = value["historyDropped"].as_u64().unwrap_or(0);
    if dropped > 0 {
        println!(
            "{dropped} earlier value{} kept for undo did not move with it",
            if dropped == 1 { "" } else { "s" }
        );
    }
    if let Some(warning) = value["cleanupWarning"].as_str() {
        eprintln!("note: {warning}");
    }
    Ok(())
}

/// `credmgr expiring` — entries that expire within N days (`entry.expiring`). Names and dates only.
pub(crate) fn cmd_expiring(mut args: Vec<String>) -> Result<(), String> {
    const USAGE: &str = "usage: credmgr expiring [--days N] [--node <id>] [--json]";
    let as_json = take_bool_flag(&mut args, "--json");
    let node = take_flag_value(&mut args, "--node");
    let days = take_flag_value(&mut args, "--days");
    reject_flags(&args, USAGE)?;
    if !args.is_empty() {
        return Err(USAGE.to_string());
    }
    let mut params = json!({});
    if let Some(node) = node {
        params["node"] = json!(node);
    }
    if let Some(days) = days {
        params["days"] = json!(days
            .parse::<u64>()
            .map_err(|_| "--days takes a whole number of days")?);
    }
    let value = with_second_factor_hint(call("entry.expiring", params))?;
    if as_json {
        println!("{value}");
        return Ok(());
    }
    let rows = value["entries"].as_array().cloned().unwrap_or_default();
    if rows.is_empty() {
        println!(
            "nothing expires in the next {} days",
            value["days"].as_u64().unwrap_or(30)
        );
    }
    for r in rows {
        println!(
            "{}\t{}\t{}{}\tlast rotated {}",
            r["node"].as_str().unwrap_or("?"),
            r["name"].as_str().unwrap_or("?"),
            opt_date(&r["expiresAt"]),
            if r["expired"].as_bool() == Some(true) {
                " (expired)"
            } else {
                ""
            },
            opt_date(&r["rotatedAt"]),
        );
    }
    Ok(())
}

// ---- history / ref ---------------------------------------------------------

/// `credmgr history <name>` — what happened to one entry (`entry.history`): actions and times, never a value.
pub(crate) fn cmd_history(mut args: Vec<String>) -> Result<(), String> {
    const USAGE: &str = "usage: credmgr history <name> [--node <id>] [--limit N] [--json]";
    let as_json = take_bool_flag(&mut args, "--json");
    let node = take_flag_value(&mut args, "--node");
    let limit = take_flag_value(&mut args, "--limit");
    reject_flags(&args, USAGE)?;
    let [name] = args.as_slice() else {
        return Err(USAGE.to_string());
    };
    let (node, entry) = super::resolve_name(name, node.as_deref())?;
    let mut params = json!({ "node": node, "entry": entry });
    if let Some(limit) = limit {
        params["limit"] = json!(limit.parse::<u64>().map_err(|_| "--limit takes a number")?);
    }
    let value = with_second_factor_hint(call("entry.history", params))?;
    if as_json {
        println!("{value}");
        return Ok(());
    }
    println!(
        "{name} ({node}): last changed {}, last rotated {}, expires {}",
        opt_date(&value["modified"]),
        opt_date(&value["rotatedAt"]),
        opt_date(&value["expiresAt"]),
    );
    if value["truncated"].as_bool() == Some(true) {
        println!("(older records left out; --limit shows more, up to 500)");
    }
    for r in value["records"].as_array().cloned().unwrap_or_default() {
        println!(
            "{}\t{}\t{}\t{}\t{}",
            r["id"].as_str().unwrap_or("?"),
            r["timestamp"].as_i64().map(utc_date).unwrap_or_default(),
            r["action"].as_str().unwrap_or("?"),
            r["decision"].as_str().unwrap_or("-"),
            r["actor"].as_str().unwrap_or("?"),
        );
    }
    Ok(())
}

/// `credmgr ref <number>` — which entry a vault-global short reference names (`entry.get_by_ref`).
pub(crate) fn cmd_ref(mut args: Vec<String>) -> Result<(), String> {
    const USAGE: &str = "usage: credmgr ref <number> [--json]";
    let as_json = take_bool_flag(&mut args, "--json");
    reject_flags(&args, USAGE)?;
    let [wanted] = args.as_slice() else {
        return Err(USAGE.to_string());
    };
    let wanted: u64 = wanted.parse().map_err(|_| USAGE.to_string())?;
    let value = with_second_factor_hint(call("entry.get_by_ref", json!({ "reference": wanted })))?;
    if as_json {
        println!("{value}");
    } else {
        println!(
            "{}\t{}",
            value["node"].as_str().unwrap_or("?"),
            value["name"].as_str().unwrap_or("?")
        );
    }
    Ok(())
}

// ---- doctor --scan -----------------------------------------------------------

/// `credmgr doctor --scan` — the doctor's tidy-up scan (`vault.doctor_scan`, ADR-161): duplicate values,
/// near-duplicate names, misfiled, weak, mistyped, expired, expiring and stale entries, each with what to do
/// about it. Read-only: nothing changes, and no value is ever in the answer. A "move" proposal is printed
/// as the `credmgr move` command that applies it (which asks for its own code and Touch ID). The owner's
/// login only. With `--apply` (ADR-169) it then applies every move it proposed, after asking.
pub(crate) fn cmd_doctor_scan(mut args: Vec<String>) -> Result<(), String> {
    const USAGE: &str =
        "usage: credmgr doctor --scan [--stale-days N] [--expiring-days N] [--json]\n\
         \x20      credmgr doctor --scan --apply [--yes] [--json]";
    let as_json = take_bool_flag(&mut args, "--json");
    let apply = take_bool_flag(&mut args, "--apply");
    let yes = take_bool_flag(&mut args, "--yes");
    let stale = take_flag_value(&mut args, "--stale-days");
    let expiring = take_flag_value(&mut args, "--expiring-days");
    reject_flags(&args, USAGE)?;
    if !args.is_empty() || (yes && !apply) {
        return Err(USAGE.to_string());
    }
    let mut params = json!({});
    for (flag, key, given) in [
        ("--stale-days", "staleDays", stale),
        ("--expiring-days", "expiringDays", expiring),
    ] {
        if let Some(days) = given {
            params[key] = json!(days
                .parse::<u64>()
                .map_err(|_| format!("{flag} takes a whole number of days"))?);
        }
    }
    let value = call("vault.doctor_scan", params)?;
    if !apply {
        if as_json {
            println!("{value}");
            return Ok(());
        }
        print!("{}", render_scan(&value));
        return Ok(());
    }
    cmd_doctor_apply(&value, yes, as_json)
}

/// ADR-169: `credmgr doctor --scan --apply` — every move the scan just proposed, in one request
/// (`vault.doctor_apply`). The plan sent is exactly the one printed: each move's entry, from, to and the
/// generation the scan showed. Nothing moves until the person says yes at the terminal (or passed `--yes`);
/// the broker then asks for its code and Touch ID once for the whole plan and stops at the first move that
/// fails, saying what moved.
fn cmd_doctor_apply(report: &Value, yes: bool, as_json: bool) -> Result<(), String> {
    let plan = apply_plan(report);
    if plan.is_empty() {
        if as_json {
            println!(
                "{}",
                json!({ "complete": true, "applied": [], "notApplied": 0 })
            );
        } else {
            print!("{}", render_scan(report));
            println!("nothing to apply: the scan proposes no move");
        }
        return Ok(());
    }
    let preview = render_plan(&plan);
    if as_json {
        eprint!("{preview}");
    } else {
        print!("{}", render_scan(report));
        print!("{preview}");
    }
    let question = format!(
        "Apply these {} move{}? [y/N] ",
        plan.len(),
        if plan.len() == 1 { "" } else { "s" }
    );
    if !yes && !super::ask_at_terminal(&question) {
        return Err(
            "nothing moved. Answer y at the prompt, or pass --yes to apply the plan shown without asking"
                .to_string(),
        );
    }
    let moves: Vec<Value> = plan.iter().map(|(m, _)| m.clone()).collect();
    let value = with_second_factor_hint(call("vault.doctor_apply", json!({ "moves": moves })))?;
    if as_json {
        println!("{value}");
    } else {
        for a in value["applied"].as_array().cloned().unwrap_or_default() {
            println!(
                "moved {} from {} to {}",
                shell_quote(a["name"].as_str().unwrap_or("?")),
                a["from"].as_str().unwrap_or("?"),
                a["node"].as_str().unwrap_or("?"),
            );
            if let Some(warning) = a["cleanupWarning"].as_str() {
                eprintln!("note: {warning}");
            }
        }
    }
    if value["complete"].as_bool() == Some(true) {
        if !as_json {
            println!("applied all {} moves of the plan", plan.len());
        }
        return Ok(());
    }
    let stopped = &value["stopped"];
    let index = stopped["index"].as_u64().unwrap_or(0) as usize;
    let name = plan.get(index).map_or("?", |(_, n)| n.as_str());
    let left = value["notApplied"].as_u64().unwrap_or(0);
    Err(format!(
        "stopped at move {} of {} ({}): {}{}; {left} move{} not applied. The moves above stand; run the scan again",
        index + 1,
        plan.len(),
        shell_quote(name),
        stopped["code"].as_str().unwrap_or("?"),
        stopped["message"]
            .as_str()
            .map(|m| format!(" ({m})"))
            .unwrap_or_default(),
        if left == 1 { "" } else { "s" },
    ))
}

/// Every move proposal of a scan, in report order, with the moved entry's name: exactly the
/// `{node, entry, to, generation}` the scan carried.
fn apply_plan(report: &Value) -> Vec<(Value, String)> {
    report["findings"]
        .as_array()
        .map(|findings| {
            findings
                .iter()
                .filter(|f| f["proposal"]["op"] == "entry.move")
                .map(|f| {
                    let m = f["proposal"]["move"].clone();
                    let name = f["entries"]
                        .as_array()
                        .and_then(|a| a.iter().find(|e| e["entry"] == m["entry"]))
                        .and_then(|e| e["name"].as_str())
                        .unwrap_or("?")
                        .to_string();
                    (m, name)
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The plan as the person reads it before saying yes: one numbered line per move.
fn render_plan(plan: &[(Value, String)]) -> String {
    let mut out = format!(
        "the plan: {} move{} (each re-encrypted to its new project's key; grants on the entry and its undo history do not travel)\n",
        plan.len(),
        if plan.len() == 1 { "" } else { "s" }
    );
    for (i, (m, name)) in plan.iter().enumerate() {
        out.push_str(&format!(
            "  {}. {}: {} -> {}\n",
            i + 1,
            shell_quote(name),
            m["node"].as_str().unwrap_or("?"),
            m["to"].as_str().unwrap_or("?"),
        ));
    }
    out
}

/// The scan's answer as lines a person reads, grouped by kind in the broker's order.
fn render_scan(value: &Value) -> String {
    let mut out = String::new();
    let findings = value["findings"].as_array().cloned().unwrap_or_default();
    out.push_str(&format!(
        "tidy-up scan: {} entries in {} projects, {} compared by value; {} finding{}\n",
        value["entriesScanned"].as_u64().unwrap_or(0),
        value["nodesScanned"].as_u64().unwrap_or(0),
        value["valuesChecked"].as_u64().unwrap_or(0),
        findings.len(),
        if findings.len() == 1 { "" } else { "s" },
    ));
    let who = |e: &Value| {
        format!(
            "{}/{}",
            e["node"].as_str().unwrap_or("?"),
            e["name"].as_str().unwrap_or("?")
        )
    };
    for f in &findings {
        let entries: Vec<String> = f["entries"]
            .as_array()
            .map(|a| a.iter().map(who).collect())
            .unwrap_or_default();
        let detail = match f["kind"].as_str().unwrap_or("") {
            "duplicate_value" => format!(
                "{} share a value ({})",
                entries.join(", "),
                f["match"].as_str().unwrap_or("exact")
            ),
            "similar_names" => format!(
                "{} have near-identical names ({})",
                entries.join(" and "),
                f["similarity"].as_str().unwrap_or("?")
            ),
            "misfiled" => format!(
                "{} sits in global, which every project reads",
                entries.join("")
            ),
            "weak" => format!(
                "{} field '{}': {}",
                entries.join(""),
                f["fieldLabel"].as_str().unwrap_or("?"),
                f["reasons"]
                    .as_array()
                    .map(|r| r
                        .iter()
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join(", "))
                    .unwrap_or_default()
            ),
            "mistyped" => format!(
                "{} field '{}': {}",
                entries.join(""),
                f["fieldLabel"].as_str().unwrap_or("?"),
                f["reason"].as_str().unwrap_or("?")
            ),
            "expired" | "expiring" => format!(
                "{} {} {}{}",
                entries.join(""),
                if f["kind"] == "expired" {
                    "expired"
                } else {
                    "expires"
                },
                opt_date(&f["expiresAt"]),
                if f["source"] == "jwt" {
                    " (the token's own expiry)"
                } else {
                    ""
                }
            ),
            "stale" => format!(
                "{} last {} {}",
                entries.join(""),
                if f["basis"] == "rotated" {
                    "rotated"
                } else {
                    "changed"
                },
                opt_date(&f["lastChanged"])
            ),
            _ => entries.join(", "),
        };
        out.push_str(&format!(
            "{:<16} {detail}\n",
            f["kind"].as_str().unwrap_or("?")
        ));
        let proposal = &f["proposal"];
        if proposal["op"] == "entry.move" {
            let m = &proposal["move"];
            let name = f["entries"]
                .as_array()
                .and_then(|a| a.iter().find(|e| e["entry"] == m["entry"]))
                .and_then(|e| e["name"].as_str())
                .unwrap_or("?");
            // Entry names are free text and this line is meant to be pasted into a shell: quote every value.
            out.push_str(&format!(
                "{:<16} -> credmgr move {} --node {} --to {}\n",
                "",
                shell_quote(name),
                shell_quote(m["node"].as_str().unwrap_or("?")),
                shell_quote(m["to"].as_str().unwrap_or("?"))
            ));
        } else if let Some(action) = proposal["action"].as_str() {
            let say = match action {
                "merge" => "keep one entry and make the other names its aliases",
                "remove_copies" => "the copy higher up already reaches the others; remove the rest",
                "share" => "keep it in one project and grant the others, or use a shared node",
                "rename_or_merge" => "rename one, or merge them",
                _ => "",
            };
            if !say.is_empty() {
                out.push_str(&format!("{:<16} -> {say}\n", ""));
            }
        }
    }
    for s in value["skipped"].as_array().cloned().unwrap_or_default() {
        out.push_str(&format!(
            "skipped          {}: {} ({})\n",
            s["node"].as_str().unwrap_or("?"),
            if s["what"] == "values" {
                "values not compared"
            } else {
                "not read"
            },
            s["reason"].as_str().unwrap_or("?")
        ));
    }
    if value["truncated"].as_bool() == Some(true) {
        out.push_str("the scan stopped at its limit; what is shown is part of the vault\n");
    }
    out
}

/// POSIX single-quoting for a value printed inside a command the user may paste: plain
/// `[A-Za-z0-9_./:@%+=-]` words stay bare, anything else is wrapped in `'...'` with every `'` written
/// as `'\''`, so no character of the value is ever read by the shell as syntax.
pub(crate) fn shell_quote(value: &str) -> String {
    let plain = !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_./:@%+=-".contains(c));
    if plain {
        value.to_string()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn shell_quote_keeps_plain_words_and_neutralises_the_rest() {
        assert_eq!(super::shell_quote("API_KEY"), "API_KEY");
        assert_eq!(super::shell_quote("n_ab12"), "n_ab12");
        assert_eq!(super::shell_quote(""), "''");
        assert_eq!(super::shell_quote("a b"), "'a b'");
        assert_eq!(super::shell_quote("$(touch x)"), "'$(touch x)'");
        assert_eq!(super::shell_quote("`id`;rm"), "'`id`;rm'");
        assert_eq!(super::shell_quote("it's"), "'it'\\''s'");
    }
    use super::*;

    #[test]
    fn dates_round_trip_and_bad_days_are_refused() {
        assert_eq!(parse_at("1970-01-01").unwrap(), 0);
        assert_eq!(parse_at("2027-03-01").unwrap(), 1_803_859_200);
        assert_eq!(utc_date(1_803_859_200), "2027-03-01");
        assert_eq!(parse_at("1803859200").unwrap(), 1_803_859_200);
        assert_eq!(utc_date(parse_at("2028-02-29").unwrap()), "2028-02-29");
        for bad in [
            "2027-02-30",
            "2027-13-01",
            "tomorrow",
            "2027-1",
            "1969-12-31",
        ] {
            assert!(parse_at(bad).is_err(), "{bad}");
        }
    }
}
