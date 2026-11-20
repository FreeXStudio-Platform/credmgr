//! `credmgr alias`, `credmgr similar` and `credmgr import-env` (ADR-121, ADR-122) - kept in
//! their own file so `main.rs` only gains the dispatch lines and the usage text.
//!
//! Nothing here prints a value, and no command takes one on argv: `import-env` reads a
//! file (or `-` for stdin) and sends the pairs to the broker, which answers with names,
//! statuses and counts only.

use serde_json::{json, Value};

use crate::{
    call, partial_import_error, print_name_warnings, read_capped, reject_flags, resolve_name,
    take_bool_flag, take_flag_value, IMPORT_MAX_BYTES, IMPORT_MAX_ENTRIES,
};
use credmgr_core::names::same_name;

fn string_list(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// What a near-duplicate row reads like: `stripe-key (same letters, other separators or case)`.
fn near_line(n: &Value) -> String {
    let name = n["name"].as_str().unwrap_or("?");
    let via = match n["alias"].as_str() {
        Some(alias) => format!("{name}, by its alias '{alias}'"),
        None => name.to_string(),
    };
    let why = match n["reason"].as_str() {
        Some("separators") => "same letters, other separators or case",
        Some("one-edit") => "one letter apart",
        _ => "looks alike",
    };
    format!("{via} ({why})")
}

fn print_similar(rows: &Value, indent: &str) {
    if let Some(rows) = rows.as_array() {
        for n in rows {
            eprintln!("{indent}resembles: {}", near_line(n));
        }
    }
}

/// ADR-121: `credmgr alias <name> [--node <id>] [--add <alias>]... [--remove <alias>]...
/// [--clear] [--json]`. Without a change flag it lists the entry's aliases. Changing them needs
/// a login (`credmgr unlock`): the broker refuses a tokenless process.
pub fn cmd_alias(mut args: Vec<String>) -> Result<(), String> {
    const USAGE: &str = "usage: credmgr alias <name> [--node <id>] [--add <alias>]... \
         [--remove <alias>]... [--clear] [--json]";
    let as_json = take_bool_flag(&mut args, "--json");
    let clear = take_bool_flag(&mut args, "--clear");
    let node = take_flag_value(&mut args, "--node");
    // Literal flags, so the argv guard (`tests/no_secret_in_argv.rs`) sees each one.
    let mut add = Vec::new();
    while let Some(v) = take_flag_value(&mut args, "--add") {
        add.push(v);
    }
    let mut remove = Vec::new();
    while let Some(v) = take_flag_value(&mut args, "--remove") {
        remove.push(v);
    }
    reject_flags(&args, USAGE)?;
    let [name] = args.as_slice() else {
        return Err(USAGE.to_string());
    };
    let (node, entry) = resolve_name(name, node.as_deref())?;
    let meta = call("entry.get", json!({ "node": node, "entry": entry }))?;
    let generation = meta["generation"]
        .as_u64()
        .ok_or("the broker did not say the node's generation")?;
    let entry_name = meta["name"].as_str().unwrap_or(name).to_string();
    let current = string_list(&meta["aliases"]);

    if !clear && add.is_empty() && remove.is_empty() {
        if as_json {
            println!("{}", json!({ "name": entry_name, "aliases": current }));
        } else if current.is_empty() {
            println!("{entry_name} has no aliases");
        } else {
            for a in &current {
                println!("{a}");
            }
        }
        return Ok(());
    }

    let mut next: Vec<String> = if clear { Vec::new() } else { current.clone() };
    for r in &remove {
        let before = next.len();
        next.retain(|a| !same_name(a, r));
        if next.len() == before && !clear {
            return Err(format!("'{entry_name}' has no alias '{r}'"));
        }
    }
    for a in &add {
        if !next.iter().any(|x| same_name(x, a)) {
            next.push(a.clone());
        }
    }
    let value = call(
        "entry.alias",
        json!({ "node": node, "entry": entry, "generation": generation, "aliases": next }),
    )?;
    print_name_warnings(&value);
    print_similar(&value["similar"], "");
    if as_json {
        println!("{value}");
    } else {
        let now = string_list(&value["aliases"]);
        if now.is_empty() {
            println!("{entry_name} has no aliases");
        } else {
            println!("{entry_name} answers to: {}", now.join(", "));
        }
    }
    Ok(())
}

/// ADR-121: `credmgr similar <name> --node <id> [--json]` - which existing names look like a
/// candidate, and whether it is taken. Writes nothing.
pub fn cmd_similar(mut args: Vec<String>) -> Result<(), String> {
    const USAGE: &str = "usage: credmgr similar <name> --node <id> [--json]";
    let as_json = take_bool_flag(&mut args, "--json");
    let node = take_flag_value(&mut args, "--node").ok_or(USAGE)?;
    reject_flags(&args, USAGE)?;
    let [name] = args.as_slice() else {
        return Err(USAGE.to_string());
    };
    let value = call("entry.similar", json!({ "node": node, "name": name }))?;
    if as_json {
        println!("{value}");
        return Ok(());
    }
    if value["nameHidden"].as_bool() == Some(true) {
        println!("this node hides its names from this login; nothing to compare with");
        return Ok(());
    }
    if value["taken"].as_bool() == Some(true) {
        println!("'{name}' is already taken on {node} (as a name or an alias)");
    }
    match value["similar"].as_array() {
        Some(rows) if !rows.is_empty() => {
            for n in rows {
                println!("resembles: {}", near_line(n));
            }
        }
        _ => println!("no near-duplicate names on {node}"),
    }
    Ok(())
}

fn status_word(s: &str) -> &'static str {
    match s {
        "new" => "new      ",
        "exists" => "exists   ",
        "duplicate" => "duplicate",
        "empty" => "empty    ",
        "invalid" => "invalid  ",
        _ => "?        ",
    }
}

/// ADR-122: `credmgr import-env <file|-> --node <id> [--dry-run] [--on-conflict refuse|skip]
/// [--json]`. Reads the file here, previews every name against the node (`entry.import_env`
/// with `dryRun`), and only then - if nothing conflicts, or `--on-conflict skip` was given -
/// writes: each pair its own entry with its own audit record. Values are never printed.
pub fn cmd_import_env(mut args: Vec<String>) -> Result<(), String> {
    const USAGE: &str = "usage: credmgr import-env <file|-> --node <id> [--dry-run] \
         [--on-conflict refuse|skip] [--json]";
    let as_json = take_bool_flag(&mut args, "--json");
    let dry_run = take_bool_flag(&mut args, "--dry-run");
    let node = take_flag_value(&mut args, "--node").ok_or(USAGE)?;
    let on_conflict =
        take_flag_value(&mut args, "--on-conflict").unwrap_or_else(|| "refuse".into());
    if on_conflict != "refuse" && on_conflict != "skip" {
        return Err(format!(
            "--on-conflict takes refuse or skip, not '{on_conflict}'\n{USAGE}"
        ));
    }
    reject_flags(&args, USAGE)?;
    let [source] = args.as_slice() else {
        return Err(USAGE.to_string());
    };

    let label = if source == "-" { "stdin" } else { source };
    let text = if source == "-" {
        read_capped(std::io::stdin().lock(), IMPORT_MAX_BYTES, "the input")?
    } else {
        let file =
            std::fs::File::open(source).map_err(|e| format!("could not open '{source}': {e}"))?;
        read_capped(file, IMPORT_MAX_BYTES, &format!("'{source}'"))?
    };
    let parsed = credmgr_core::dotenv::parse(&text).map_err(|e| format!("{label}: {e}"))?;
    crate::warn_refused_env_lines(label, &parsed.refused_lines);
    if parsed.entries.is_empty() {
        let skipped = if parsed.skipped_empty.is_empty() {
            String::new()
        } else {
            format!(
                " ({} had an empty value: {})",
                parsed.skipped_empty.len(),
                parsed.skipped_empty.join(", ")
            )
        };
        return Err(format!(
            "nothing to import from {label}: no NAME=value line with a value{skipped}"
        ));
    }
    if parsed.entries.len() > IMPORT_MAX_ENTRIES {
        return Err(format!(
            "{label} holds {} entries; one import takes at most {IMPORT_MAX_ENTRIES} - \
             split the file and import the parts one after another",
            parsed.entries.len()
        ));
    }
    let pairs: Vec<Value> = parsed
        .entries
        .iter()
        .map(|e| json!({ "name": e.name, "value": e.value }))
        .collect();

    // The preview comes first, always: the names and what each would become.
    let plan = call(
        "entry.import_env",
        json!({ "node": node, "entries": pairs, "dryRun": true }),
    )?;
    print_name_warnings(&plan);
    let conflicts: Vec<String> = plan["items"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter(|i| matches!(i["status"].as_str(), Some("exists" | "duplicate")))
                .filter_map(|i| i["name"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    if dry_run {
        if as_json {
            println!("{plan}");
        } else {
            for i in plan["items"].as_array().into_iter().flatten() {
                println!(
                    "{} {}",
                    status_word(i["status"].as_str().unwrap_or("?")),
                    i["name"].as_str().unwrap_or("?")
                );
                print_similar(&i["similar"], "           ");
            }
            for name in &parsed.skipped_empty {
                println!("{} {name}", status_word("empty"));
            }
            let c = &plan["counts"];
            println!(
                "{} new, {} already there, {} repeated in the file, {} empty - nothing written (dry run)",
                c["new"], c["exists"], c["duplicate"], c["empty"]
            );
        }
        return Ok(());
    }
    if !conflicts.is_empty() && on_conflict == "refuse" {
        return Err(format!(
            "{} name(s) conflict, so nothing was written: {}. Run with --dry-run to see \
             every name, or --on-conflict skip to import the rest",
            conflicts.len(),
            conflicts.join(", ")
        ));
    }

    let mut value = call(
        "entry.import_env",
        json!({ "node": node, "entries": pairs, "onConflict": on_conflict }),
    )?;
    value["skippedEmpty"] = json!(parsed.skipped_empty);
    value["refusedLines"] = json!(parsed.refused_lines);
    print_name_warnings(&value);
    let created = value["created"].as_array().cloned().unwrap_or_default();
    let complete = value["complete"].as_bool() == Some(true);
    let held = created
        .iter()
        .filter(|c| c["pending"].as_bool() == Some(true))
        .count();
    if as_json {
        println!("{value}");
    } else {
        for c in &created {
            let name = c["name"].as_str().unwrap_or("?");
            if c["pending"].as_bool() == Some(true) {
                println!("held     {name}");
            } else {
                println!("created  {name}");
            }
        }
        for s in value["skipped"].as_array().into_iter().flatten() {
            println!(
                "skipped  {} ({})",
                s["name"].as_str().unwrap_or("?"),
                s["status"].as_str().unwrap_or("?")
            );
        }
        println!(
            "imported {} of {} entries into {node}",
            created.len(),
            value["total"].as_u64().unwrap_or(pairs.len() as u64)
        );
        if held > 0 {
            println!(
                "the vault is locked - {held} {} in the review tray; \
                 after unlocking, review them with `credmgr pending`",
                if held == 1 {
                    "entry waits"
                } else {
                    "entries wait"
                }
            );
        }
    }
    if !complete {
        return Err(partial_import_error(created.len(), &value["failed"]));
    }
    if source != "-" {
        eprintln!(
            "note: {source} still holds the plaintext values - delete it once you have checked the import"
        );
    }
    Ok(())
}

/// ADR-167: `credmgr tag <name> [--node <id>] [--add <tag>]... [--remove <tag>]... [--clear] [--json]`.
/// Without a change flag it lists the entry's tags. The set is edited here with the same normaliser the
/// broker uses and sent whole in one `entry.tag_set`; changing it needs a login (agents never tag).
pub fn cmd_tag(mut args: Vec<String>) -> Result<(), String> {
    const USAGE: &str = "usage: credmgr tag <name> [--node <id>] [--add <tag>]... \
         [--remove <tag>]... [--clear] [--json]";
    let as_json = take_bool_flag(&mut args, "--json");
    let clear = take_bool_flag(&mut args, "--clear");
    let node = take_flag_value(&mut args, "--node");
    // Literal flags, so the argv guard (`tests/no_secret_in_argv.rs`) sees each one.
    let mut add = Vec::new();
    while let Some(v) = take_flag_value(&mut args, "--add") {
        add.push(v);
    }
    let mut remove = Vec::new();
    while let Some(v) = take_flag_value(&mut args, "--remove") {
        remove.push(v);
    }
    reject_flags(&args, USAGE)?;
    let [name] = args.as_slice() else {
        return Err(USAGE.to_string());
    };
    let normalise = |list: &[String]| -> Result<Vec<String>, String> {
        list.iter()
            .map(|t| {
                credmgr_core::tags::normalise_tag(t)
                    .map_err(|e| format!("the tag '{t}' {}", e.as_str()))
            })
            .collect()
    };
    let add = normalise(&add)?;
    let remove = normalise(&remove)?;
    let (node, entry) = resolve_name(name, node.as_deref())?;
    let meta = call("entry.get", json!({ "node": node, "entry": entry }))?;
    let generation = meta["generation"]
        .as_u64()
        .ok_or("the broker did not say the node's generation")?;
    let entry_name = meta["name"].as_str().unwrap_or(name).to_string();
    let current = string_list(&meta["tags"]);

    if !clear && add.is_empty() && remove.is_empty() {
        if as_json {
            println!("{}", json!({ "name": entry_name, "tags": current }));
        } else if current.is_empty() {
            println!("{entry_name} has no tags");
        } else {
            for t in &current {
                println!("{t}");
            }
        }
        return Ok(());
    }
    let base: Vec<String> = if clear { Vec::new() } else { current };
    let next = credmgr_core::tags::edit_tags(&base, &add, &remove);
    let value = call(
        "entry.tag_set",
        json!({ "node": node, "entry": entry, "generation": generation, "tags": next }),
    )?;
    if as_json {
        println!("{value}");
    } else {
        let now = string_list(&value["tags"]);
        if now.is_empty() {
            println!("{entry_name} has no tags");
        } else {
            println!("{entry_name} is tagged: {}", now.join(", "));
        }
    }
    Ok(())
}
