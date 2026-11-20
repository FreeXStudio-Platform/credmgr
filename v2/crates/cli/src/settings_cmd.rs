//! ADR-155: `credmgr settings ...` and `credmgr kb` — the switchboard from a terminal, through the same broker
//! operations the app and the MCP server use.

use serde_json::{json, Value};

use crate::{call, reject_flags, take_bool_flag, take_flag_value};

const USAGE: &str = "usage: credmgr settings list [--node <id>] [--json]\n\
       credmgr settings get <id> [--node <id>] [--json]\n\
       credmgr settings set <id> <value> [--node <id>] --reason <why>   (value is JSON: 5, true, \"dark\", null)\n\
       credmgr settings toggle <id> [--node <id>] --reason <why>\n\
       credmgr settings revert <change> [--reason <why>]\n\
       credmgr settings requests [--json]\n\
       credmgr settings approve <request> | deny <request>   (owner; approving a weakening change asks you to confirm)\n\
       credmgr settings request <request>";

fn node_params(mut p: Value, node: Option<String>) -> Value {
    if let Some(n) = node {
        p["node"] = json!(n);
    }
    p
}

fn print_change(v: &Value) {
    if v["applied"] == true {
        println!(
            "{}: {} -> {}  ({}; change {})",
            v["id"].as_str().unwrap_or("?"),
            v["from"],
            v["to"],
            v["change"].as_str().unwrap_or("?"),
            v["changeId"].as_str().unwrap_or("?")
        );
    } else if v["state"] == "pending" {
        println!(
            "waiting for the owner's approval: request {} ({} -> {}), {} s left",
            v["request"].as_str().unwrap_or("?"),
            v["from"],
            v["to"],
            v["expiresIn"].as_u64().unwrap_or(0)
        );
    } else {
        println!(
            "{}: unchanged ({})",
            v["id"].as_str().unwrap_or("?"),
            v["value"]
        );
    }
}

pub fn cmd_settings(mut args: Vec<String>) -> Result<(), String> {
    let as_json = take_bool_flag(&mut args, "--json");
    let node = take_flag_value(&mut args, "--node");
    let reason = take_flag_value(&mut args, "--reason");
    reject_flags(&args, USAGE)?;
    let sub = if args.is_empty() {
        "list".to_string()
    } else {
        args.remove(0)
    };
    match (sub.as_str(), args.as_slice()) {
        ("list", []) => {
            let v = call("settings.list", node_params(json!({}), node))?;
            if as_json {
                println!("{v}");
                return Ok(());
            }
            let mut group = "";
            for s in v["settings"].as_array().into_iter().flatten() {
                let g = s["group"].as_str().unwrap_or("");
                if g != group {
                    group = g;
                    println!("\n{g}");
                }
                println!(
                    "  {:<42} {:<14} {}  [{}]",
                    s["id"].as_str().unwrap_or("?"),
                    s["value"].to_string(),
                    s["title"].as_str().unwrap_or(""),
                    s["you"].as_str().unwrap_or("")
                );
            }
            if v["node"].is_null() {
                println!("\nproject settings: credmgr settings list --node <id>");
            }
            Ok(())
        }
        ("get", [id]) => {
            let v = call("settings.get", node_params(json!({ "id": id }), node))?;
            if as_json {
                println!("{v}");
            } else {
                println!("{}  = {}", v["id"].as_str().unwrap_or("?"), v["value"]);
                println!("  {}", v["purpose"].as_str().unwrap_or(""));
                println!(
                    "  values: {}   default: {}",
                    v["values"].as_str().unwrap_or(""),
                    v["default"]
                );
                println!(
                    "  stored: {}   in the app: {}",
                    v["stored"].as_str().unwrap_or(""),
                    v["ui"].as_str().unwrap_or("")
                );
                println!("  you: {}", v["you"].as_str().unwrap_or(""));
                for c in v["recentChanges"].as_array().into_iter().flatten() {
                    println!(
                        "  change {}: {} -> {} by {} ({})",
                        c["id"].as_str().unwrap_or("?"),
                        c["from"],
                        c["to"],
                        c["by"].as_str().unwrap_or("?"),
                        c["reason"].as_str().unwrap_or("")
                    );
                }
            }
            Ok(())
        }
        ("set", [id, raw]) => {
            let value: Value =
                serde_json::from_str(raw).unwrap_or_else(|_| Value::String(raw.clone()));
            let reason = reason.ok_or("--reason is required: a setting change records why")?;
            let v = call(
                "settings.set",
                node_params(json!({ "id": id, "value": value, "reason": reason }), node),
            )?;
            if as_json {
                println!("{v}")
            } else {
                print_change(&v)
            }
            Ok(())
        }
        ("toggle", [id]) => {
            let current = call(
                "settings.get",
                node_params(json!({ "id": id }), node.clone()),
            )?;
            let now = current["value"].as_bool().ok_or_else(|| {
                format!(
                    "{id} is not an on/off setting (it takes {})",
                    current["values"].as_str().unwrap_or("?")
                )
            })?;
            let reason = reason.ok_or("--reason is required: a setting change records why")?;
            let v = call(
                "settings.set",
                node_params(json!({ "id": id, "value": !now, "reason": reason }), node),
            )?;
            if as_json {
                println!("{v}")
            } else {
                print_change(&v)
            }
            Ok(())
        }
        ("revert", [change]) => {
            let mut p = json!({ "change": change });
            if let Some(r) = reason {
                p["reason"] = json!(r);
            }
            let v = call("settings.revert", p)?;
            if as_json {
                println!("{v}")
            } else {
                print_change(&v)
            }
            Ok(())
        }
        ("requests", []) => {
            let v = call("settings.request_list", json!({}))?;
            if as_json {
                println!("{v}");
                return Ok(());
            }
            let list = v["requests"].as_array().cloned().unwrap_or_default();
            if list.is_empty() {
                println!("no setting requests");
            }
            for r in list {
                println!(
                    "{}  {}  {}{}: {} -> {}  ({}){}",
                    r["request"].as_str().unwrap_or("?"),
                    r["state"].as_str().unwrap_or("?"),
                    r["id"].as_str().unwrap_or("?"),
                    r["node"]
                        .as_str()
                        .map(|n| format!(" on {n}"))
                        .unwrap_or_default(),
                    r["from"],
                    r["to"],
                    r["reason"].as_str().unwrap_or(""),
                    crate::agent_tokens::asked_by(&r),
                );
            }
            Ok(())
        }
        ("request", [id]) => {
            let v = call("settings.request_get", json!({ "request": id }))?;
            println!("{v}");
            Ok(())
        }
        ("approve" | "deny", [id]) => {
            let v = call(
                "settings.request_decide",
                json!({ "request": id, "approve": sub == "approve" }),
            )?;
            if as_json {
                println!("{v}");
            } else if v["applied"] == true {
                println!(
                    "approved {id}: {} {} -> {} (change {})",
                    v["id"].as_str().unwrap_or("?"),
                    v["from"],
                    v["to"],
                    v["changeId"].as_str().unwrap_or("?")
                );
            } else {
                println!("denied {id}: nothing changed");
            }
            Ok(())
        }
        _ => Err(USAGE.to_string()),
    }
}

/// `credmgr kb`: the LLM knowledge base. Printed from the binary itself (no vault, no broker needed), so it is always
/// the text for exactly this version.
pub fn cmd_kb(args: Vec<String>) -> Result<(), String> {
    if !args.is_empty() {
        return Err("usage: credmgr kb".into());
    }
    print!("{}", credmgr_core::settings::kb_markdown());
    Ok(())
}
