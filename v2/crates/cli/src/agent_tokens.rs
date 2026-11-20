//! ADR-164 — `credmgr agent token issue|ls|rotate|revoke`: node-scoped agent tokens, as subcommands of
//! `credmgr agent` (ADR-142's command), so the top-level command count does not change. Each is a thin
//! client of one `agent.token_*` op; the broker decides everything. Issuing and rotating need the owner's
//! login (`CREDMGR_TOKEN`), a fresh second factor where one is enrolled and Touch ID (the shared `call`
//! asks for the proof itself). The new token is printed once, alone on stdout, so it can be piped into the
//! agent's environment without passing through the terminal's scrollback; the details go to stderr.

use serde_json::{json, Value};

use super::quick_cmds::utc_date;
use super::stable::with_second_factor_hint;
use super::{call, reject_flags, take_bool_flag, take_flag_value};

const USAGE: &str = "usage: credmgr agent token issue <node> --label <text> --cap <list,read,reveal,create,update> \
                     [--expires <90m|8h|2d|seconds>] [--json]\n\
                     \x20      credmgr agent token ls [--node <id>] [--json]\n\
                     \x20      credmgr agent token rotate <id> [--expires <...>] [--json]\n\
                     \x20      credmgr agent token revoke <id>";

pub(crate) fn cmd_token(mut args: Vec<String>) -> Result<(), String> {
    if args.is_empty() {
        return Err(USAGE.to_string());
    }
    let sub = args.remove(0);
    match sub.as_str() {
        "issue" => cmd_issue(args),
        "ls" | "list" | "status" => cmd_ls(args),
        "rotate" => cmd_rotate(args),
        "revoke" => cmd_revoke(args),
        _ => Err(USAGE.to_string()),
    }
}

/// `--expires`: `90m`, `8h`, `2d`, or plain seconds. The broker holds the bounds (one minute to seven days).
pub(crate) fn parse_expires(text: &str) -> Result<i64, String> {
    let bad = || format!("--expires takes 90m, 8h, 2d or seconds, not '{text}'");
    let text = text.trim();
    let (digits, unit) = match text.char_indices().last() {
        Some((i, c)) if c.is_ascii_alphabetic() => (&text[..i], c),
        _ => (text, 's'),
    };
    let n: i64 = digits.parse().map_err(|_| bad())?;
    let factor = match unit {
        's' => 1,
        'm' => 60,
        'h' => 3600,
        'd' => 86_400,
        _ => return Err(bad()),
    };
    n.checked_mul(factor).filter(|s| *s > 0).ok_or_else(bad)
}

fn parse_caps(text: &str) -> Vec<String> {
    text.split(',')
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .map(str::to_string)
        .collect()
}

fn utc_time(secs: i64) -> String {
    let rem = secs.rem_euclid(86_400);
    format!(
        "{} {:02}:{:02} UTC",
        utc_date(secs),
        rem / 3600,
        (rem % 3600) / 60
    )
}

fn caps_of(v: &Value, key: &str) -> String {
    v[key]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_default()
}

/// The answer that carries the secret: the token alone on stdout, the rest on stderr.
fn print_secret(v: &Value, as_json: bool) -> Result<(), String> {
    if as_json {
        println!("{v}");
        return Ok(());
    }
    let token = v["token"]
        .as_str()
        .ok_or("the broker's answer carried no token")?;
    println!("{token}");
    eprintln!(
        "agent token {} \"{}\" for node {} ({}), expires {}",
        v["id"].as_str().unwrap_or("?"),
        v["label"].as_str().unwrap_or(""),
        v["node"].as_str().unwrap_or("?"),
        caps_of(v, "capabilities"),
        v["expiresAt"].as_i64().map(utc_time).unwrap_or_default()
    );
    eprintln!(
        "shown once: give it to the agent as CREDMGR_AGENT_TOKEN (the MCP server reads it) or CREDMGR_TOKEN \
         (the command line). Revoke it with `credmgr agent token revoke {}`.",
        v["id"].as_str().unwrap_or("<id>")
    );
    Ok(())
}

fn cmd_issue(mut args: Vec<String>) -> Result<(), String> {
    let as_json = take_bool_flag(&mut args, "--json");
    let label = take_flag_value(&mut args, "--label");
    let caps = take_flag_value(&mut args, "--cap");
    let expires = take_flag_value(&mut args, "--expires");
    reject_flags(&args, USAGE)?;
    let [node] = args.as_slice() else {
        return Err(USAGE.to_string());
    };
    let label =
        label.ok_or("--label is required: a name for the agent that will hold the token")?;
    let caps = caps.ok_or(
        "--cap is required: the capabilities the token carries, for example --cap list,read",
    )?;
    let mut params = json!({ "node": node, "label": label, "capabilities": parse_caps(&caps) });
    if let Some(e) = expires {
        params["expiresIn"] = json!(parse_expires(&e)?);
    }
    let v = with_second_factor_hint(call("agent.token_issue", params))?;
    print_secret(&v, as_json)
}

fn cmd_ls(mut args: Vec<String>) -> Result<(), String> {
    let as_json = take_bool_flag(&mut args, "--json");
    let node = take_flag_value(&mut args, "--node");
    reject_flags(&args, USAGE)?;
    if !args.is_empty() {
        return Err(USAGE.to_string());
    }
    let mut params = json!({});
    if let Some(n) = node {
        params["node"] = json!(n);
    }
    let v = call("agent.token_status", params)?;
    if as_json {
        println!("{v}");
        return Ok(());
    }
    let tokens = v["tokens"].as_array().cloned().unwrap_or_default();
    if tokens.is_empty() {
        println!("no agent tokens");
        return Ok(());
    }
    for t in tokens {
        let last = t["lastUsedAt"].as_i64().map_or_else(
            || "never used".to_string(),
            |s| format!("last used {}", utc_time(s)),
        );
        println!(
            "{}  {:<24} node {:<16} {:<32} expires {}  {last}",
            t["id"].as_str().unwrap_or("?"),
            t["label"].as_str().unwrap_or(""),
            t["node"].as_str().unwrap_or("?"),
            caps_of(&t, "effectiveCapabilities"),
            t["expiresAt"].as_i64().map(utc_time).unwrap_or_default()
        );
    }
    Ok(())
}

fn cmd_rotate(mut args: Vec<String>) -> Result<(), String> {
    let as_json = take_bool_flag(&mut args, "--json");
    let expires = take_flag_value(&mut args, "--expires");
    reject_flags(&args, USAGE)?;
    let [id] = args.as_slice() else {
        return Err(USAGE.to_string());
    };
    let mut params = json!({ "id": id });
    if let Some(e) = expires {
        params["expiresIn"] = json!(parse_expires(&e)?);
    }
    let v = with_second_factor_hint(call("agent.token_rotate", params))?;
    print_secret(&v, as_json)
}

fn cmd_revoke(mut args: Vec<String>) -> Result<(), String> {
    let as_json = take_bool_flag(&mut args, "--json");
    reject_flags(&args, USAGE)?;
    let [id] = args.as_slice() else {
        return Err(USAGE.to_string());
    };
    let v = call("agent.token_revoke", json!({ "id": id }))?;
    if as_json {
        println!("{v}");
    } else {
        println!(
            "revoked {} \"{}\" (node {}); the next request with it is refused",
            v["id"].as_str().unwrap_or(id),
            v["label"].as_str().unwrap_or(""),
            v["node"].as_str().unwrap_or("?")
        );
    }
    Ok(())
}

/// ADR-164 review P1-2: who asked, for a request the owner decides (an approval, a setting request): the agent token by
/// label and public id when one asked, else the folder it asked from. Empty when the broker said neither.
pub(crate) fn asked_by(v: &Value) -> String {
    if let Some(id) = v["agentToken"]["id"].as_str() {
        return format!(
            "  asked by agent token \"{}\" ({id})",
            v["agentToken"]["label"].as_str().unwrap_or("")
        );
    }
    v["cwd"]
        .as_str()
        .map(|c| format!("  asked from {c}"))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expires_reads_minutes_hours_days_and_seconds() {
        assert_eq!(parse_expires("90m"), Ok(5400));
        assert_eq!(parse_expires("8h"), Ok(28_800));
        assert_eq!(parse_expires("2d"), Ok(172_800));
        assert_eq!(parse_expires("3600"), Ok(3600));
        for bad in ["", "0", "-5m", "2w", "h", "1.5h", "99999999999999999d"] {
            assert!(parse_expires(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_request_names_the_agent_token_that_asked_before_its_folder() {
        let by_token =
            json!({ "agentToken": { "id": "a_00000000000000a1", "label": "ci" }, "cwd": null });
        assert_eq!(
            asked_by(&by_token),
            "  asked by agent token \"ci\" (a_00000000000000a1)"
        );
        assert_eq!(
            asked_by(&json!({ "cwd": "/work/acme" })),
            "  asked from /work/acme"
        );
        assert_eq!(asked_by(&json!({})), "");
    }

    #[test]
    fn caps_are_split_on_commas() {
        assert_eq!(parse_caps("list, read,,reveal"), ["list", "read", "reveal"]);
    }
}
