//! The multi-field commands (ADR-078): `credmgr field ls|add|set|rm|mv`, and the
//! field selector and bulk-paste plumbing that `get`, `set` and `rotate` share.
//!
//! **Argv safety, same rule as the rest of the binary.** A *value* is only ever
//! read from stdin — `set --bulk`, `set --field`, `rotate --field`, `field add`
//! all take it there. What argv carries is *naming*: an entry name, a field's
//! label (free text, but a label, not a secret — it is listed by `field ls`, kept
//! in the clear nowhere on disk but never treated as a credential) or id, a
//! position, a type. `tests/no_secret_in_argv.rs` holds this whole directory to an
//! allowlist of flags, so a new flag that could carry a value fails a test.
//!
//! **Exit status.** A command that fails exits 1, except one refused because it did
//! not say *which field* - an entry with several fields and no `--field`, a label that
//! matches none or two - which exits 2 (`main::selection_error`), so a script can tell
//! "name the field" from "the vault said no".
//!
//! **The broker never parses the bulk grammar** (ADR-078 D5). `--bulk` parses the
//! text here, with the same `credmgr_core::parser` the desktop app's preview uses,
//! and sends the resulting `fields` array; what was parsed is what is stored.

use serde_json::{json, Value};

use crate::{
    call, call_audited, entry_generation, read_capped, read_stdin_value, reject_flags,
    resolve_name, selection_error, take_bool_flag, take_choice, take_flag_value, take_text_flag,
    IMPORT_MAX_BYTES,
};

/// How a field with no label is named in a message. A label may be empty (a
/// pasted value with no `label:`, or an entry saved by an alpha build, which kept
/// no labels).
pub const NO_LABEL: &str = "(no label)";

fn shown(label: &str) -> &str {
    if label.is_empty() {
        NO_LABEL
    } else {
        label
    }
}

// ---- selecting a field ---------------------------------------------------

/// `--field <label>` or `--field-id <id>`: which field a command means. Labels
/// are free text and need not be unique, so the id is the exact form.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Selector {
    pub label: Option<String>,
    pub id: Option<String>,
}

impl Selector {
    /// Takes `--field` / `--field-id` out of `args`. Both together is a
    /// contradiction, not a preference order.
    pub fn take(args: &mut Vec<String>) -> Result<Selector, String> {
        let label = take_text_flag(args, "--field")?;
        let id = take_flag_value(args, "--field-id");
        if label.is_some() && id.is_some() {
            return Err("give --field <label> or --field-id <id>, not both".to_string());
        }
        Ok(Selector { label, id })
    }

    pub fn is_some(&self) -> bool {
        self.label.is_some() || self.id.is_some()
    }
}

/// `entry.get` — an entry's metadata and field labels, never a value.
pub fn entry_meta(node: &str, entry: &str) -> Result<Value, String> {
    call("entry.get", json!({ "node": node, "entry": entry }))
}

fn fields_of(meta: &Value) -> &[Value] {
    meta["fields"].as_array().map_or(&[], Vec::as_slice)
}

/// `host, username, password` — the labels of an entry's fields, for an error
/// that tells the reader what they could have named.
pub fn label_list(fields: &[Value]) -> String {
    fields
        .iter()
        .map(|f| shown(f["label"].as_str().unwrap_or("")))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The id of the field `sel` names in `meta` (an `entry.get` answer). A label
/// matches exactly first; failing that, one case-insensitive match is accepted
/// (`Password` for `password`) — never when it is ambiguous. Two fields with the
/// same label are refused with their ids, never resolved by guessing.
pub fn pick(meta: &Value, name: &str, sel: &Selector) -> Result<String, String> {
    let fields = fields_of(meta);
    if let Some(id) = &sel.id {
        return if fields.iter().any(|f| f["id"].as_str() == Some(id.as_str())) {
            Ok(id.clone())
        } else {
            Err(selection_error(format!(
                "entry '{name}' has no field with the id {id} — see `credmgr field ls {name}`"
            )))
        };
    }
    let Some(label) = sel.label.as_deref() else {
        return Err(selection_error(
            "name a field with --field <label> or --field-id <id>",
        ));
    };
    let by = |same: &dyn Fn(&str) -> bool| -> Vec<&Value> {
        fields
            .iter()
            .filter(|f| same(f["label"].as_str().unwrap_or("")))
            .collect()
    };
    let mut found = by(&|l| l == label);
    if found.is_empty() {
        found = by(&|l| l.eq_ignore_ascii_case(label));
    }
    match found.as_slice() {
        [one] => Ok(one["id"].as_str().unwrap_or_default().to_string()),
        [] => Err(selection_error(format!(
            "entry '{name}' has no field labelled '{label}' — its fields are: {}",
            label_list(fields)
        ))),
        many => Err(selection_error(format!(
            "entry '{name}' has {} fields labelled '{label}' — pick one with --field-id: {}",
            many.len(),
            many.iter()
                .filter_map(|f| f["id"].as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ))),
    }
}

// ---- bulk text -----------------------------------------------------------

/// Reads the bulk paste from stdin and parses it with the real grammar
/// (`08 §3`) into a `fields` array, ready to send. Refuses an input with no
/// fields at all. Nothing here prints a value.
pub fn read_bulk_stdin() -> Result<Vec<Value>, String> {
    let text = read_capped(std::io::stdin().lock(), IMPORT_MAX_BYTES, "the input")?;
    bulk_fields(&text)
}

pub fn bulk_fields(text: &str) -> Result<Vec<Value>, String> {
    let parsed = credmgr_core::parser::parse_bulk(text);
    // Blank lines around a `///` come back as a whitespace-only unlabelled field
    // (the grammar is lossless); input that is nothing but that is no input.
    if parsed
        .iter()
        .all(|f| f.label.is_empty() && f.value.trim().is_empty())
    {
        return Err("nothing to store: the input holds no fields".to_string());
    }
    Ok(parsed
        .into_iter()
        .map(|f| json!({ "label": f.label, "value": f.value }))
        .collect())
}

/// Does `text` parse back to exactly this one field? Asked of the real parser,
/// so the form chosen below is one the bulk grammar will read back unchanged.
fn reads_back(text: &str, label: &str, value: &str) -> bool {
    let parsed = credmgr_core::parser::parse_bulk(text);
    matches!(parsed.as_slice(), [f] if f.label == label && f.value == value)
}

/// `label: value` lines for `get --all` — the form `set --bulk` reads. A field
/// whose value is one line and whose label the grammar accepts is a plain line;
/// anything else (a multi-line value such as a PEM block, a label the grammar
/// would not read, an unlabelled value) is its own block set off by a `///` line.
/// `get --json` is the exact form for a script; this one is for a person.
pub fn render_all(fields: &[(String, String)]) -> String {
    let mut out = String::new();
    let mut in_run = false;
    for (label, value) in fields {
        let line = format!("{label}: {value}");
        let simple =
            !label.is_empty() && !value.contains(['\n', '\r']) && reads_back(&line, label, value);
        if simple {
            if !out.is_empty() && !in_run {
                out.push_str("///\n");
            }
            out.push_str(&line);
            out.push('\n');
            in_run = true;
        } else {
            if !out.is_empty() {
                out.push_str("///\n");
            }
            if label.is_empty() {
                out.push_str(value);
            } else {
                out.push_str(label);
                out.push_str(":\n");
                out.push_str(value);
            }
            out.push('\n');
            in_run = false;
        }
    }
    out
}

/// The fields `entry.reveal` answered, as `(label, value)` pairs in stored
/// order. Falls back to the single `value` an answer without a `fields` array
/// carries, so a client never prints less than it was given.
pub fn revealed(answer: &Value) -> Vec<Value> {
    if let Some(fields) = answer["fields"].as_array() {
        return fields.clone();
    }
    match answer["value"].as_str() {
        Some(v) => vec![json!({ "id": "", "label": "", "value": v })],
        None => Vec::new(),
    }
}

pub fn pairs(fields: &[Value]) -> Vec<(String, String)> {
    fields
        .iter()
        .map(|f| {
            (
                f["label"].as_str().unwrap_or_default().to_string(),
                f["value"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect()
}

/// When the broker refuses an unaddressed value on a multi-field entry, say how
/// to address one — its own message names `params.field`, which is not a thing a
/// person typing `credmgr` can pass.
pub fn with_field_hint(error: String, name: &str) -> String {
    if error.contains("pass params.field") {
        format!(
            "{error}\n  remedy: name the field with --field <label> or --field-id <id> \
             (see `credmgr field ls {name}`), or replace every field with `credmgr set {name} --bulk`"
        )
    } else {
        error
    }
}

// ---- credmgr field … ------------------------------------------------------

const USAGE: &str = "usage: credmgr field ls|add|set|rm|mv <name> [--node <id>] ...\n\
     \x20 credmgr field ls <name> [--node <id>] [--json]\n\
     \x20 credmgr field add <name> (--label <l> | --bulk) [--at <n>] [--node <id>]   (value from stdin)\n\
     \x20 credmgr field set <name> (--field <l> | --field-id <id>) [--label <new>]\n\
     \x20                          [--type <t>|auto] [--mask on|off|auto] [--node <id>]\n\
     \x20 credmgr field rm <name> (--field <l> | --field-id <id>) [--node <id>]\n\
     \x20 credmgr field mv <name> (--field <l> | --field-id <id>) --to <n> [--node <id>]";

pub fn cmd_field(mut args: Vec<String>) -> Result<(), String> {
    if args.is_empty() {
        return Err(USAGE.to_string());
    }
    let sub = args.remove(0);
    match sub.as_str() {
        "ls" => cmd_ls(args),
        "add" => cmd_add(args),
        "set" => cmd_set(args),
        "rm" => cmd_rm(args),
        "mv" => cmd_mv(args),
        other => Err(format!(
            "unknown field subcommand '{other}' — use ls, add, set, rm or mv\n{USAGE}"
        )),
    }
}

/// `<name>` — exactly one positional, after every flag has been taken.
fn the_name(args: &[String], usage: &str) -> Result<String, String> {
    reject_flags(args, usage)?;
    match args {
        [name] => Ok(name.clone()),
        _ => Err(usage.to_string()),
    }
}

fn cmd_ls(mut args: Vec<String>) -> Result<(), String> {
    const USAGE: &str = "usage: credmgr field ls <name> [--node <id>] [--json]";
    let as_json = take_bool_flag(&mut args, "--json");
    let node = take_flag_value(&mut args, "--node");
    let name = the_name(&args, USAGE)?;
    let (node, entry) = resolve_name(&name, node.as_deref())?;
    let meta = entry_meta(&node, &entry)?;
    if as_json {
        println!("{meta}");
        return Ok(());
    }
    let fields = fields_of(&meta);
    println!(
        "{name} — {}, {}, {} field{}, generation {}",
        meta["type"].as_str().unwrap_or("?"),
        meta["sensitivity"].as_str().unwrap_or("?"),
        fields.len(),
        if fields.len() == 1 { "" } else { "s" },
        meta["generation"].as_u64().unwrap_or(0),
    );
    for (i, f) in fields.iter().enumerate() {
        println!(
            "{i}\t{}\t{}\t{}{}",
            f["id"].as_str().unwrap_or("?"),
            shown(f["label"].as_str().unwrap_or("")),
            f["type"].as_str().unwrap_or("?"),
            if f["masked"].as_bool() == Some(true) {
                "\tmasked"
            } else {
                ""
            },
        );
    }
    Ok(())
}

fn cmd_add(mut args: Vec<String>) -> Result<(), String> {
    const USAGE: &str =
        "usage: credmgr field add <name> (--label <l> | --bulk) [--at <n>] [--node <id>]   (value from stdin)";
    let bulk = take_bool_flag(&mut args, "--bulk");
    let label = take_text_flag(&mut args, "--label")?;
    let at = take_flag_value(&mut args, "--at");
    let node = take_flag_value(&mut args, "--node");
    let name = the_name(&args, USAGE)?;
    if bulk == label.is_some() {
        return Err(format!(
            "give --label <l> (one field, its value on stdin) or --bulk (`label: value` lines on stdin)\n{USAGE}"
        ));
    }
    let position = at
        .map(|s| {
            s.parse::<u64>()
                .map_err(|_| format!("--at takes a position from 0, got '{s}'"))
        })
        .transpose()?;

    let new_fields = match label {
        Some(label) => vec![json!({ "label": label, "value": read_stdin_value()? })],
        None => read_bulk_stdin()?,
    };
    let (node, entry) = resolve_name(&name, node.as_deref())?;
    let generation = entry_generation(&node)?;
    let mut params = json!({
        "node": node, "entry": entry, "generation": generation, "fields": new_fields,
    });
    if let Some(position) = position {
        params["position"] = json!(position);
    }
    let value = call("field.add", params)?;
    let added = value["added"].as_array().map_or(0, Vec::len);
    println!(
        "added {added} field{} to '{name}' — it now has {}",
        if added == 1 { "" } else { "s" },
        value["fieldCount"].as_u64().unwrap_or(0),
    );
    Ok(())
}

fn cmd_set(mut args: Vec<String>) -> Result<(), String> {
    const USAGE: &str = "usage: credmgr field set <name> (--field <l> | --field-id <id>) \
         [--label <new>] [--type <t>|auto] [--mask on|off|auto] [--node <id>]";
    let node = take_flag_value(&mut args, "--node");
    let selector = Selector::take(&mut args)?;
    let new_label = take_text_flag(&mut args, "--label")?;
    let mut types: Vec<&str> = credmgr_mcp::tools::FIELD_TYPE_NAMES.to_vec();
    types.push("auto");
    let new_type = take_choice(&mut args, "--type", &types)?;
    let mask = take_choice(&mut args, "--mask", &["on", "off", "auto"])?;
    let name = the_name(&args, USAGE)?;
    if !selector.is_some() {
        return Err(USAGE.to_string());
    }

    let mut patch = json!({});
    if let Some(label) = new_label {
        patch["label"] = json!(label);
    }
    if let Some(t) = new_type {
        patch["type"] = json!(t);
    }
    if let Some(m) = mask {
        patch["masked"] = match m.as_str() {
            "on" => json!(true),
            "off" => json!(false),
            _ => json!("auto"),
        };
    }
    if patch.as_object().is_some_and(|o| o.is_empty()) {
        return Err(format!(
            "nothing to change: give --label, --type or --mask. A value is never an argument — \
             change one with `credmgr set {name} --field …` or `credmgr rotate {name} --field …` \
             (the new value on stdin)"
        ));
    }

    let (node, entry) = resolve_name(&name, node.as_deref())?;
    let meta = entry_meta(&node, &entry)?;
    let id = pick(&meta, &name, &selector)?;
    call(
        "field.update",
        json!({
            "node": node, "entry": entry, "generation": meta["generation"].as_u64().unwrap_or(0),
            "field": id, "patch": patch,
        }),
    )?;
    println!("updated field {id} of '{name}'");
    Ok(())
}

fn cmd_rm(mut args: Vec<String>) -> Result<(), String> {
    const USAGE: &str =
        "usage: credmgr field rm <name> (--field <l> | --field-id <id>) [--node <id>]";
    let node = take_flag_value(&mut args, "--node");
    let selector = Selector::take(&mut args)?;
    let name = the_name(&args, USAGE)?;
    if !selector.is_some() {
        return Err(USAGE.to_string());
    }
    let (node, entry) = resolve_name(&name, node.as_deref())?;
    let meta = entry_meta(&node, &entry)?;
    let id = pick(&meta, &name, &selector)?;
    let label = fields_of(&meta)
        .iter()
        .find(|f| f["id"].as_str() == Some(id.as_str()))
        .and_then(|f| f["label"].as_str())
        .unwrap_or("")
        .to_string();
    let (value, audit) = call_audited(
        "field.remove",
        json!({
            "node": node, "entry": entry, "generation": meta["generation"].as_u64().unwrap_or(0),
            "field": id,
        }),
    )?;
    println!(
        "removed field {} ({id}) from '{name}' — it now has {} field{}",
        shown(&label),
        value["fieldCount"].as_u64().unwrap_or(0),
        if value["fieldCount"].as_u64() == Some(1) {
            ""
        } else {
            "s"
        },
    );
    if let Some(audit) = audit {
        println!("undo with: credmgr undo {audit} --node {node}");
    }
    Ok(())
}

fn cmd_mv(mut args: Vec<String>) -> Result<(), String> {
    const USAGE: &str =
        "usage: credmgr field mv <name> (--field <l> | --field-id <id>) --to <n> [--node <id>]";
    let node = take_flag_value(&mut args, "--node");
    let selector = Selector::take(&mut args)?;
    let to = take_flag_value(&mut args, "--to");
    let name = the_name(&args, USAGE)?;
    let (true, Some(to)) = (selector.is_some(), to) else {
        return Err(USAGE.to_string());
    };
    let to: usize = to
        .parse()
        .map_err(|_| format!("--to takes a position from 0, got '{to}'"))?;

    let (node, entry) = resolve_name(&name, node.as_deref())?;
    let meta = entry_meta(&node, &entry)?;
    let id = pick(&meta, &name, &selector)?;
    let mut order: Vec<String> = fields_of(&meta)
        .iter()
        .filter_map(|f| f["id"].as_str().map(str::to_string))
        .collect();
    if to >= order.len() {
        return Err(format!(
            "--to {to} is out of range: '{name}' has {} field{}, numbered 0 to {}",
            order.len(),
            if order.len() == 1 { "" } else { "s" },
            order.len().saturating_sub(1),
        ));
    }
    let from = order.iter().position(|o| *o == id).unwrap_or(to);
    if from == to {
        println!("field {id} of '{name}' is already at position {to}");
        return Ok(());
    }
    order.remove(from);
    order.insert(to, id.clone());
    call(
        "field.reorder",
        json!({
            "node": node, "entry": entry, "generation": meta["generation"].as_u64().unwrap_or(0),
            "order": order,
        }),
    )?;
    println!("moved field {id} of '{name}' to position {to}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta() -> Value {
        json!({
            "generation": 7,
            "fields": [
                { "id": "f_00000001", "label": "host", "type": "host", "masked": false },
                { "id": "f_00000002", "label": "Password", "type": "password", "masked": true },
                { "id": "f_00000003", "label": "twin", "type": "text", "masked": false },
                { "id": "f_00000004", "label": "twin", "type": "text", "masked": false },
                { "id": "f_00000005", "label": "", "type": "text", "masked": false },
            ],
        })
    }

    fn by_label(l: &str) -> Selector {
        Selector {
            label: Some(l.to_string()),
            id: None,
        }
    }

    #[test]
    fn a_label_matches_exactly_then_case_insensitively_and_never_ambiguously() {
        let m = meta();
        assert_eq!(pick(&m, "X", &by_label("host")).unwrap(), "f_00000001");
        // no exact match, one case-insensitive match
        assert_eq!(pick(&m, "X", &by_label("password")).unwrap(), "f_00000002");
        assert_eq!(pick(&m, "X", &by_label("PASSWORD")).unwrap(), "f_00000002");
        // two fields with one label: refused, and the ids are named
        let dup = pick(&m, "X", &by_label("twin")).unwrap_err();
        assert!(
            dup.contains("2 fields labelled 'twin'")
                && dup.contains("--field-id")
                && dup.contains("f_00000003")
                && dup.contains("f_00000004"),
            "{dup}"
        );
        // unknown: the labels that do exist are listed, an empty one as (no label)
        let none = pick(&m, "X", &by_label("nope")).unwrap_err();
        assert!(
            none.contains("no field labelled 'nope'")
                && none.contains("host, Password, twin, twin, (no label)"),
            "{none}"
        );
    }

    #[test]
    fn an_id_is_checked_against_the_entry_not_trusted() {
        let m = meta();
        let sel = Selector {
            label: None,
            id: Some("f_00000004".to_string()),
        };
        assert_eq!(pick(&m, "X", &sel).unwrap(), "f_00000004");
        let sel = Selector {
            label: None,
            id: Some("f_deadbeef".to_string()),
        };
        let e = pick(&m, "X", &sel).unwrap_err();
        assert!(
            e.contains("no field with the id f_deadbeef") && e.contains("credmgr field ls X"),
            "{e}"
        );
        assert!(pick(&m, "X", &Selector::default()).is_err());
    }

    #[test]
    fn the_selector_refuses_both_forms_together() {
        let mut a = vec![
            "--field".to_string(),
            "host".to_string(),
            "--field-id".to_string(),
            "f_00000001".to_string(),
        ];
        assert!(Selector::take(&mut a).unwrap_err().contains("not both"));
        let mut a = vec!["--field-id".to_string(), "f_00000001".to_string()];
        let s = Selector::take(&mut a).unwrap();
        assert_eq!(s.id.as_deref(), Some("f_00000001"));
        assert!(a.is_empty());
        // a label that is really the next option is refused, not swallowed
        let mut a = vec!["--field".to_string(), "--json".to_string()];
        assert!(Selector::take(&mut a)
            .unwrap_err()
            .contains("--field needs its text"));
    }

    #[test]
    fn bulk_text_becomes_a_fields_array_with_the_real_grammar() {
        let f = bulk_fields("host: db.example\nusername: svc\n").unwrap();
        assert_eq!(
            f,
            vec![
                json!({ "label": "host", "value": "db.example" }),
                json!({ "label": "username", "value": "svc" }),
            ]
        );
        // a value may begin with a space; nothing is trimmed (08 §3.5)
        let f = bulk_fields("password:  spaced").unwrap();
        assert_eq!(f[0]["value"], " spaced");
        assert!(bulk_fields("").unwrap_err().contains("no fields"));
        assert!(bulk_fields("\n\n///\n").unwrap_err().contains("no fields"));
    }

    /// `get --all` prints text that `set --bulk` reads back to the same fields.
    #[test]
    fn render_all_reads_back_to_the_same_fields() {
        let pem = "-----BEGIN KEY-----\nAAAA\nBBBB\n-----END KEY-----";
        let original = vec![
            ("host".to_string(), "db.example".to_string()),
            ("username".to_string(), "svc".to_string()),
            ("private key".to_string(), pem.to_string()),
            ("notes".to_string(), "one line".to_string()),
        ];
        let text = render_all(&original);
        assert!(text.contains("host: db.example\nusername: svc\n"), "{text}");
        assert!(
            text.contains("///\nprivate key:\n-----BEGIN KEY-----"),
            "{text}"
        );
        let back: Vec<(String, String)> = credmgr_core::parser::parse_bulk(&text)
            .into_iter()
            .map(|f| (f.label, f.value))
            .collect();
        assert_eq!(back, original, "{text}");

        // an unlabelled single value is just the value
        let one = vec![(String::new(), "plain value".to_string())];
        assert_eq!(render_all(&one), "plain value\n");
        // a label the grammar would not read still prints, on its own block
        let odd = vec![("a: b".to_string(), "v".to_string())];
        assert!(
            render_all(&odd).contains("a: b:\nv"),
            "{}",
            render_all(&odd)
        );
    }

    #[test]
    fn the_ambiguous_value_error_gets_a_remedy_naming_the_flags() {
        let hinted = with_field_hint(
            "malformed_request: entry has 4 fields; pass params.field".to_string(),
            "PROD_DB",
        );
        assert!(
            hinted.contains("--field <label>")
                && hinted.contains("credmgr field ls PROD_DB")
                && hinted.contains("credmgr set PROD_DB --bulk"),
            "{hinted}"
        );
        // anything else passes through untouched
        assert_eq!(with_field_hint("conflict".to_string(), "X"), "conflict");
    }

    #[test]
    fn revealed_falls_back_to_a_bare_value() {
        let with = json!({ "fields": [{ "id": "f_00000001", "label": "a", "value": "1" }] });
        assert_eq!(
            pairs(&revealed(&with)),
            [("a".to_string(), "1".to_string())]
        );
        let bare = json!({ "value": "only" });
        assert_eq!(
            pairs(&revealed(&bare)),
            [(String::new(), "only".to_string())]
        );
        assert!(revealed(&json!({})).is_empty());
    }

    #[test]
    fn the_field_type_choices_are_the_real_types() {
        for t in credmgr_mcp::tools::FIELD_TYPE_NAMES {
            serde_json::from_value::<credmgr_core::inference::FieldType>(json!(t)).unwrap();
        }
    }
}
