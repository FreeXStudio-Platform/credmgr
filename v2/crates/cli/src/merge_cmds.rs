//! `credmgr merge …` (ADR-168): merge suggestions and merges inside one node, and the node's decision
//! memory. Every subcommand names one node (`--node`); nothing here compares or merges across nodes, and
//! nothing prints a value (the broker never answers one). Needs the owner's login (`credmgr unlock`).

use serde_json::{json, Value};

use crate::stable::with_second_factor_hint;
use crate::{call, reject_flags, resolve_name, take_bool_flag, take_flag_value};

const USAGE: &str = "usage: credmgr merge suggest|dismissed|restore-all --node <id> [--json]\n\
     \x20      credmgr merge apply --node <id> --keep <name> --drop <name>... [--json]\n\
     \x20      credmgr merge dismiss|undismiss|auto --node <id> --group <key> [--json]\n\
     \x20      credmgr merge auto-all --node <id> [--apply] [--json]";

fn names_of(entries: &Value) -> String {
    entries
        .as_array()
        .map(|a| {
            a.iter()
                .map(|e| e["name"].as_str().unwrap_or("(gone)").to_string())
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default()
}

fn kind_words(kind: &str) -> &'static str {
    match kind {
        "identical" => "identical values",
        "shared_value" => "a value in common",
        "similar_names" => "names that look alike",
        _ => "alike",
    }
}

fn generation_of(node: &str) -> Result<u64, String> {
    call("entry.list", json!({ "node": node }))?["generation"]
        .as_u64()
        .ok_or_else(|| "the broker did not say the node's generation".to_string())
}

fn print_merged(value: &Value) {
    let keep = value["keep"].as_str().unwrap_or("?");
    for m in value["merged"].as_array().into_iter().flatten() {
        println!(
            "merged {} into {keep} (undo with `credmgr undo {}`)",
            m["name"].as_str().unwrap_or("?"),
            m["undo"].as_str().unwrap_or("?")
        );
    }
}

pub fn cmd_merge(mut args: Vec<String>) -> Result<(), String> {
    if args.is_empty() {
        return Err(USAGE.to_string());
    }
    let sub = args.remove(0);
    let as_json = take_bool_flag(&mut args, "--json");
    let node = take_flag_value(&mut args, "--node").ok_or(USAGE)?;
    match sub.as_str() {
        "suggest" => {
            let include = take_bool_flag(&mut args, "--include-dismissed");
            reject_flags(&args, USAGE)?;
            if !args.is_empty() {
                return Err(USAGE.to_string());
            }
            let value = call(
                "merge.suggestions",
                json!({ "node": node, "includeDismissed": include }),
            )?;
            if as_json {
                println!("{value}");
                return Ok(());
            }
            let list = value["suggestions"].as_array().cloned().unwrap_or_default();
            if list.is_empty() {
                println!("no merge suggestions on {node}");
            }
            for s in &list {
                let dismissed = if s["dismissed"] == true {
                    " (dismissed)"
                } else {
                    ""
                };
                println!(
                    "{}: {}{dismissed}\n  key {}",
                    kind_words(s["kind"].as_str().unwrap_or("")),
                    names_of(&s["entries"]),
                    s["key"].as_str().unwrap_or("?")
                );
            }
            if value["valuesCompared"] == false {
                println!("values were not compared: give this node's second factor first");
            }
            Ok(())
        }
        "apply" => {
            let keep = take_flag_value(&mut args, "--keep").ok_or(USAGE)?;
            let mut drops = Vec::new();
            while let Some(d) = take_flag_value(&mut args, "--drop") {
                drops.push(d);
            }
            reject_flags(&args, USAGE)?;
            if drops.is_empty() || !args.is_empty() {
                return Err(USAGE.to_string());
            }
            let (_, keep_id) = resolve_name(&keep, Some(&node))?;
            let drop_ids = drops
                .iter()
                .map(|d| resolve_name(d, Some(&node)).map(|(_, id)| id))
                .collect::<Result<Vec<_>, _>>()?;
            let generation = generation_of(&node)?;
            let value = with_second_factor_hint(call(
                "merge.apply",
                json!({ "node": node, "keep": keep_id, "drop": drop_ids, "generation": generation }),
            ))?;
            if as_json {
                println!("{value}");
            } else {
                print_merged(&value);
            }
            Ok(())
        }
        "dismiss" | "undismiss" | "auto" => {
            let key = take_flag_value(&mut args, "--group").ok_or(USAGE)?;
            reject_flags(&args, USAGE)?;
            if !args.is_empty() {
                return Err(USAGE.to_string());
            }
            let value = match sub.as_str() {
                "dismiss" => call("merge.dismiss", json!({ "node": node, "key": key }))?,
                "undismiss" => call("merge.undismiss", json!({ "node": node, "key": key }))?,
                _ => {
                    let generation = generation_of(&node)?;
                    with_second_factor_hint(call(
                        "merge.auto",
                        json!({ "node": node, "key": key, "generation": generation }),
                    ))?
                }
            };
            if as_json {
                println!("{value}");
            } else if sub == "auto" {
                print_merged(&value);
            } else if sub == "dismiss" {
                println!("dismissed; it will not be suggested again");
            } else if value["restored"] == true {
                println!("it will be suggested again");
            } else {
                println!("that suggestion was not dismissed");
            }
            Ok(())
        }
        "dismissed" | "restore-all" => {
            reject_flags(&args, USAGE)?;
            if !args.is_empty() {
                return Err(USAGE.to_string());
            }
            let op = if sub == "dismissed" {
                "merge.dismissed_list"
            } else {
                "merge.restore_all"
            };
            let value = call(op, json!({ "node": node }))?;
            if as_json {
                println!("{value}");
            } else if sub == "dismissed" {
                let list = value["dismissed"].as_array().cloned().unwrap_or_default();
                if list.is_empty() {
                    println!("nothing dismissed on {node}");
                }
                for d in &list {
                    println!(
                        "{}\n  key {}",
                        names_of(&d["entries"]),
                        d["key"].as_str().unwrap_or("?")
                    );
                }
            } else {
                println!(
                    "{} dismissed suggestion(s) will be suggested again",
                    value["restored"].as_u64().unwrap_or(0)
                );
            }
            Ok(())
        }
        "auto-all" => {
            let apply = take_bool_flag(&mut args, "--apply");
            reject_flags(&args, USAGE)?;
            if !args.is_empty() {
                return Err(USAGE.to_string());
            }
            let value = if apply {
                let generation = generation_of(&node)?;
                with_second_factor_hint(call(
                    "merge.auto_all",
                    json!({ "node": node, "apply": true, "generation": generation }),
                ))?
            } else {
                call("merge.auto_all", json!({ "node": node }))?
            };
            if as_json {
                println!("{value}");
                return Ok(());
            }
            let planned = value["planned"].as_array().cloned().unwrap_or_default();
            if value["dryRun"] == true {
                if planned.is_empty() {
                    println!("nothing to merge automatically on {node}");
                }
                for p in &planned {
                    println!("would merge: {}", names_of(&p["entries"]));
                }
                if !planned.is_empty() {
                    println!("dry run: nothing was changed; add --apply to merge");
                }
            } else {
                for part in value["merged"].as_array().into_iter().flatten() {
                    print_merged(part);
                }
            }
            for s in value["skipped"].as_array().into_iter().flatten() {
                println!(
                    "skipped ({}): {}",
                    s["reason"].as_str().unwrap_or("?"),
                    names_of(&s["entries"])
                );
            }
            Ok(())
        }
        _ => Err(USAGE.to_string()),
    }
}
