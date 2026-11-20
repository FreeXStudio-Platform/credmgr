//! `credmgr edit <name> --node <id>` — an entry's METADATA in `$EDITOR` (rc.2 §3 item 3; V1 had `edit`).
//!
//! Only metadata is ever fetched (`entry.get`: name, aliases, expiry, sensitivity, type, field labels, types and
//! masking, and `tags` when the broker sends them). No value is fetched, shown or editable here. The document is a
//! plain `key: value` file (see [`render`]); after the editor exits it is parsed, diffed against what was fetched,
//! and only the changed keys are applied through the existing broker ops. Nothing but the temp file's path is ever
//! passed to the editor, and the editor line is split on whitespace and run directly (no shell).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::quick_cmds::{parse_at, utc_date};
use crate::{call, reject_flags, resolve_name, take_bool_flag, take_flag_value};

const USAGE: &str = "usage: credmgr edit <name> --node <id> [--dry-run]   (metadata only, in $VISUAL / $EDITOR / vi)";

/// One field's metadata, never its value.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct FieldMeta {
    pub id: String,
    pub label: String,
    pub ftype: String,
    pub masked: bool,
}

/// What `entry.get` says about an entry (no value in it).
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Meta {
    pub name: String,
    pub aliases: Vec<String>,
    pub expires: Option<i64>,
    pub sensitivity: String,
    pub entry_type: String,
    /// `Some` only when the broker's `entry.get` carries a `tags` key.
    pub tags: Option<Vec<String>>,
    pub fields: Vec<FieldMeta>,
    pub generation: u64,
}

pub(crate) fn meta_from_get(v: &Value) -> Result<Meta, String> {
    if v["nameHidden"].as_bool() == Some(true) || v["name"].is_null() {
        return Err(
            "this node hides names from this login, so its entries cannot be edited here".into(),
        );
    }
    let s = |k: &str| {
        v[k].as_str()
            .map(str::to_string)
            .ok_or_else(|| format!("the broker's answer has no '{k}'"))
    };
    let strs = |x: &Value| -> Vec<String> {
        x.as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|i| i.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    };
    let mut fields = Vec::new();
    for f in v["fields"].as_array().cloned().unwrap_or_default() {
        fields.push(FieldMeta {
            id: f["id"].as_str().ok_or("a field has no id")?.to_string(),
            label: f["label"]
                .as_str()
                .ok_or("a field has no label")?
                .to_string(),
            ftype: f["type"].as_str().unwrap_or("text").to_string(),
            masked: f["masked"].as_bool().unwrap_or(true),
        });
    }
    Ok(Meta {
        name: s("name")?,
        aliases: strs(&v["aliases"]),
        expires: v["expiresAt"].as_i64(),
        sensitivity: s("sensitivity")?,
        entry_type: s("type")?,
        tags: v.get("tags").filter(|t| t.is_array()).map(strs),
        fields,
        generation: v["generation"]
            .as_u64()
            .ok_or("the broker did not say the generation")?,
    })
}

/// The document the editor opens.
pub(crate) fn render(m: &Meta) -> String {
    let mut o = String::new();
    o.push_str("# credmgr edit: metadata only. No secret value is in this file and none can be changed here.\n");
    o.push_str("# One `key: value` per line. A key you delete or leave unchanged changes nothing. Lines starting with # are ignored.\n");
    o.push_str("#\n# name: the entry's name. Shown for reference; renaming is not supported (an edit to it is refused).\n");
    o.push_str(&format!("name: {}\n", m.name));
    o.push_str("# aliases: other names for it, comma-separated; empty clears them.\n");
    o.push_str(&format!("aliases: {}\n", m.aliases.join(", ")));
    o.push_str("# expires: a date (YYYY-MM-DD, UTC) or `never`.\n");
    o.push_str(&format!(
        "expires: {}\n",
        m.expires.map_or("never".to_string(), utc_date)
    ));
    o.push_str("# sensitivity: low, medium, high, critical, or auto (infer it again).\n");
    o.push_str(&format!("sensitivity: {}\n", m.sensitivity));
    o.push_str("# type: the entry's type (login, api, ssh, wallet, ...) or auto.\n");
    o.push_str(&format!("type: {}\n", m.entry_type));
    if let Some(tags) = &m.tags {
        o.push_str("# tags: comma-separated; empty clears them.\n");
        o.push_str(&format!("tags: {}\n", tags.join(", ")));
    }
    o.push_str("#\n# Fields. For each: label (free text), type (password, api-key, ... or auto), masked (true, false or auto).\n");
    for f in &m.fields {
        o.push_str(&format!("field.{}.label: {}\n", f.id, f.label));
        o.push_str(&format!("field.{}.type: {}\n", f.id, f.ftype));
        o.push_str(&format!("field.{}.masked: {}\n", f.id, f.masked));
    }
    o
}

type Doc = BTreeMap<String, (usize, String)>;

/// Parsed document: key -> (line number, value). Unknown keys and malformed lines are refused with the line number.
pub(crate) fn parse(text: &str, m: &Meta) -> Result<Doc, String> {
    let mut allowed: Vec<String> = ["name", "aliases", "expires", "sensitivity", "type"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    if m.tags.is_some() {
        allowed.push("tags".into());
    }
    for f in &m.fields {
        for k in ["label", "type", "masked"] {
            allowed.push(format!("field.{}.{k}", f.id));
        }
    }
    let mut out = BTreeMap::new();
    for (i, raw) in text.lines().enumerate() {
        let n = i + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once(':') else {
            return Err(format!("line {n}: expected `key: value`"));
        };
        let k = k.trim().to_string();
        if !allowed.contains(&k) {
            return Err(format!("line {n}: unknown key '{k}'"));
        }
        if out.insert(k.clone(), (n, v.trim().to_string())).is_some() {
            return Err(format!("line {n}: '{k}' appears twice"));
        }
    }
    Ok(out)
}

/// One planned broker call (the generation is filled in when it is applied).
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Planned {
    pub op: &'static str,
    pub params: Value,
}

fn list(v: &str) -> Vec<String> {
    v.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Diff the parsed document against the fetched metadata and plan only what changed.
pub(crate) fn plan(m: &Meta, node: &str, entry: &str, doc: &Doc) -> Result<Vec<Planned>, String> {
    let base = || json!({ "node": node, "entry": entry });
    let mut ops = Vec::new();
    if let Some((n, v)) = doc.get("name") {
        if v != &m.name {
            return Err(format!(
                "line {n}: renaming an entry is not supported (no broker op for it); nothing applied"
            ));
        }
    }
    if let Some((_, v)) = doc.get("aliases") {
        let new = list(v);
        if new != m.aliases {
            let mut p = base();
            p["aliases"] = json!(new);
            ops.push(Planned {
                op: "entry.alias",
                params: p,
            });
        }
    }
    if let Some((n, v)) = doc.get("expires") {
        let new =
            if v.eq_ignore_ascii_case("never") || v.is_empty() {
                None
            } else {
                Some(parse_at(v).map_err(|_| {
                    format!("line {n}: expires takes YYYY-MM-DD or `never`, not '{v}'")
                })?)
            };
        // Compare as dates: the document shows a day, so a same-day value is unchanged.
        if new.map(utc_date) != m.expires.map(utc_date) {
            let mut p = base();
            match new {
                Some(at) => p["expiresAt"] = json!(at),
                None => p["clear"] = json!(true),
            }
            ops.push(Planned {
                op: "entry.set_expiry",
                params: p,
            });
        }
    }
    let mut update = base();
    let mut update_changed = false;
    if let Some((n, v)) = doc.get("sensitivity") {
        if v != &m.sensitivity {
            if v.is_empty() {
                return Err(format!("line {n}: sensitivity is empty"));
            }
            update["sensitivity"] = json!(v);
            update_changed = true;
        }
    }
    if let Some((n, v)) = doc.get("type") {
        if v != &m.entry_type {
            if v.is_empty() {
                return Err(format!("line {n}: type is empty"));
            }
            update["entryType"] = json!(v);
            update_changed = true;
        }
    }
    if update_changed {
        ops.push(Planned {
            op: "entry.update",
            params: update,
        });
    }
    if let (Some(old), Some((_, v))) = (&m.tags, doc.get("tags")) {
        let new = list(v);
        if &new != old {
            let mut p = base();
            p["tags"] = json!(new);
            ops.push(Planned {
                op: "entry.tag_set",
                params: p,
            });
        }
    }
    for f in &m.fields {
        let mut patch = serde_json::Map::new();
        if let Some((n, v)) = doc.get(&format!("field.{}.label", f.id)) {
            if v != &f.label {
                if v.is_empty() {
                    return Err(format!("line {n}: a field label cannot be empty"));
                }
                patch.insert("label".into(), json!(v));
            }
        }
        if let Some((n, v)) = doc.get(&format!("field.{}.type", f.id)) {
            if v != &f.ftype {
                if v.is_empty() {
                    return Err(format!("line {n}: a field type cannot be empty"));
                }
                patch.insert("type".into(), json!(v));
            }
        }
        if let Some((n, v)) = doc.get(&format!("field.{}.masked", f.id)) {
            let val = match v.as_str() {
                "true" => json!(true),
                "false" => json!(false),
                "auto" => json!("auto"),
                _ => return Err(format!("line {n}: masked takes true, false or auto")),
            };
            if v != &f.masked.to_string() {
                patch.insert("masked".into(), val);
            }
        }
        if !patch.is_empty() {
            let mut p = base();
            p["field"] = json!(f.id);
            p["patch"] = Value::Object(patch);
            ops.push(Planned {
                op: "field.update",
                params: p,
            });
        }
    }
    Ok(ops)
}

/// Split an editor command line on whitespace, honouring single and double quotes. No shell, no expansion.
pub(crate) fn split_editor(line: &str) -> Vec<String> {
    let (mut out, mut cur, mut quote, mut has) = (Vec::new(), String::new(), None::<char>, false);
    for c in line.chars() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), c) => cur.push(c),
            (None, '\'' | '"') => {
                quote = Some(c);
                has = true;
            }
            (None, c) if c.is_whitespace() => {
                if has || !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                    has = false;
                }
            }
            (None, c) => cur.push(c),
        }
    }
    if has || !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// `$VISUAL`, then `$EDITOR`, then `vi`.
fn editor_from_env() -> String {
    ["VISUAL", "EDITOR"]
        .iter()
        .filter_map(|k| std::env::var(k).ok())
        .find(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "vi".to_string())
}

fn run_editor(editor: &str, file: &Path) -> Result<(), String> {
    let parts = split_editor(editor);
    let (prog, rest) = parts.split_first().ok_or("the editor command is empty")?;
    let status = std::process::Command::new(prog)
        .args(rest)
        .arg(file)
        .status()
        .map_err(|e| format!("could not start the editor '{prog}': {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "the editor '{prog}' exited with {status}; nothing applied"
        ))
    }
}

/// A private temp dir (0700) holding the 0600 document; removed on drop unless `keep` is set.
struct Scratch {
    dir: PathBuf,
    file: PathBuf,
    keep: bool,
}

impl Scratch {
    fn new(text: &str) -> Result<Self, String> {
        use std::io::Write;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!("credmgr-edit-{}-{nanos}", std::process::id()));
        let mut b = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            b.mode(0o700);
        }
        b.create(&dir)
            .map_err(|e| format!("could not create a private temp dir: {e}"))?;
        let file = dir.join("entry.txt");
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        let s = Scratch {
            dir,
            file,
            keep: false,
        };
        o.open(&s.file)
            .and_then(|mut f| f.write_all(text.as_bytes()))
            .map_err(|e| format!("could not write the temp file: {e}"))?;
        Ok(s)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if !self.keep {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
}

/// The whole flow, with the broker call and the editor injected so it runs without either in tests.
/// Returns the lines to print.
pub(crate) fn run_edit<C>(
    call: &mut C,
    name: &str,
    node: &str,
    entry: &str,
    editor: &str,
    dry_run: bool,
) -> Result<Vec<String>, String>
where
    C: FnMut(&str, Value) -> Result<Value, String>,
{
    let got = call("entry.get", json!({ "node": node, "entry": entry }))?;
    let meta = meta_from_get(&got)?;
    let mut scratch = Scratch::new(&render(&meta))?;
    run_editor(editor, &scratch.file)?;
    let text = std::fs::read_to_string(&scratch.file)
        .map_err(|e| format!("could not read the edited file back: {e}"))?;
    let doc = parse(&text, &meta)?;
    let ops = plan(&meta, node, entry, &doc)?;
    if ops.is_empty() {
        return Ok(vec![format!("{name}: no changes")]);
    }
    let mut lines = Vec::new();
    if dry_run {
        lines.push(format!(
            "{name}: {} change(s) planned, none applied (--dry-run)",
            ops.len()
        ));
        for p in &ops {
            lines.push(format!("  {} {}", p.op, p.params));
        }
        return Ok(lines);
    }
    let mut generation = meta.generation;
    for (i, p) in ops.iter().enumerate() {
        let mut params = p.params.clone();
        params["generation"] = json!(generation);
        match call(p.op, params) {
            Ok(v) => {
                generation = match v["generation"].as_u64() {
                    Some(g) => g,
                    None => call("entry.get", json!({ "node": node, "entry": entry }))?
                        ["generation"]
                        .as_u64()
                        .ok_or("the broker did not say the generation")?,
                };
                lines.push(format!("  applied {}", p.op));
            }
            Err(e) => {
                let applied = lines.join("\n");
                if e.starts_with("conflict") {
                    scratch.keep = true;
                    return Err(format!(
                        "{e}\nthe entry changed meanwhile ({i} of {} change(s) were applied{}). Your edited file is kept at {} so you can retry; remove it when done.",
                        ops.len(),
                        if applied.is_empty() {
                            String::new()
                        } else {
                            format!(":\n{applied}\n")
                        },
                        scratch.file.display()
                    ));
                }
                return Err(format!(
                    "{e}\n{i} of {} change(s) were applied before this failed",
                    ops.len()
                ));
            }
        }
    }
    lines.insert(0, format!("{name}: updated"));
    Ok(lines)
}

pub(crate) fn cmd_edit(mut args: Vec<String>) -> Result<(), String> {
    let dry_run = take_bool_flag(&mut args, "--dry-run");
    let node = take_flag_value(&mut args, "--node");
    reject_flags(&args, USAGE)?;
    let ([name], Some(node)) = (args.as_slice(), node) else {
        return Err(USAGE.to_string());
    };
    let (node, entry) = resolve_name(name, Some(&node))?;
    let lines = run_edit(&mut call, name, &node, &entry, &editor_from_env(), dry_run)?;
    for l in lines {
        println!("{l}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    type Log = Rc<RefCell<Vec<(String, Value)>>>;

    fn get(tags: bool) -> Value {
        let mut v = json!({
            "node": "n", "entry": "e1", "name": "stripe", "aliases": ["pay"], "type": "api",
            "sensitivity": "high", "expiresAt": 1798761600, "generation": 7,
            "fields": [
                {"id": "f_00000001", "label": "key", "type": "api-key", "masked": true},
                {"id": "f_00000002", "label": "user", "type": "username", "masked": false}
            ]
        });
        if tags {
            v["tags"] = json!(["prod"]);
        }
        v
    }

    fn doc(m: &Meta, edit: impl Fn(String) -> String) -> Doc {
        parse(&edit(render(m)), m).unwrap()
    }

    #[test]
    fn untouched_document_plans_nothing() {
        let m = meta_from_get(&get(true)).unwrap();
        let text = render(&m);
        assert!(text.contains("expires: 2027-01-01"), "{text}");
        assert!(plan(&m, "n", "e1", &parse(&text, &m).unwrap())
            .unwrap()
            .is_empty());
    }

    #[test]
    fn changed_keys_map_to_ops() {
        let m = meta_from_get(&get(true)).unwrap();
        let d = doc(&m, |t| {
            t.replace("aliases: pay", "aliases: pay, billing")
                .replace("expires: 2027-01-01", "expires: never")
                .replace("sensitivity: high", "sensitivity: critical")
                .replace("tags: prod", "tags: prod, eu")
                .replace(
                    "field.f_00000001.label: key",
                    "field.f_00000001.label: secret key",
                )
                .replace(
                    "field.f_00000002.masked: false",
                    "field.f_00000002.masked: auto",
                )
        });
        let ops = plan(&m, "n", "e1", &d).unwrap();
        let names: Vec<&str> = ops.iter().map(|p| p.op).collect();
        assert_eq!(
            names,
            [
                "entry.alias",
                "entry.set_expiry",
                "entry.update",
                "entry.tag_set",
                "field.update",
                "field.update"
            ]
        );
        assert_eq!(ops[0].params["aliases"], json!(["pay", "billing"]));
        assert_eq!(ops[1].params["clear"], json!(true));
        assert_eq!(ops[2].params["sensitivity"], json!("critical"));
        assert!(ops[2].params.get("entryType").is_none());
        assert_eq!(ops[3].params["tags"], json!(["prod", "eu"]));
        assert_eq!(ops[4].params["patch"], json!({"label": "secret key"}));
        assert_eq!(ops[5].params["patch"], json!({"masked": "auto"}));
    }

    #[test]
    fn tags_absent_means_not_in_document_and_refused() {
        let m = meta_from_get(&get(false)).unwrap();
        let text = render(&m);
        assert!(!text.contains("tags:"));
        let e = parse(&format!("{text}tags: x\n"), &m).unwrap_err();
        assert!(e.contains("unknown key 'tags'"), "{e}");
    }

    #[test]
    fn bad_lines_are_refused_with_the_line_number() {
        let m = meta_from_get(&get(true)).unwrap();
        assert!(parse("nonsense\n", &m).unwrap_err().starts_with("line 1:"));
        assert!(parse("# c\nbogus: 1\n", &m)
            .unwrap_err()
            .starts_with("line 2:"));
        assert!(parse("name: a\nname: b\n", &m)
            .unwrap_err()
            .starts_with("line 2:"));
        let d = parse("expires: soonish\n", &m).unwrap();
        assert!(plan(&m, "n", "e", &d).unwrap_err().starts_with("line 1:"));
        let d = parse("field.f_00000001.masked: maybe\n", &m).unwrap();
        assert!(plan(&m, "n", "e", &d).unwrap_err().contains("masked"));
    }

    #[test]
    fn rename_is_refused() {
        let m = meta_from_get(&get(true)).unwrap();
        let d = parse("name: other\n", &m).unwrap();
        assert!(plan(&m, "n", "e", &d).unwrap_err().contains("renaming"));
    }

    #[test]
    fn hidden_names_are_refused() {
        let v = json!({"name": null, "nameHidden": true});
        assert!(meta_from_get(&v).unwrap_err().contains("hides names"));
    }

    #[test]
    fn editor_line_splits_without_a_shell() {
        assert_eq!(split_editor("code --wait"), ["code", "--wait"]);
        assert_eq!(split_editor("  vi  "), ["vi"]);
        assert_eq!(
            split_editor("'/Applications/My Ed/ed' -w"),
            ["/Applications/My Ed/ed", "-w"]
        );
        assert_eq!(split_editor("ed $(rm -rf x)"), ["ed", "$(rm", "-rf", "x)"]);
        assert!(split_editor("").is_empty());
    }

    #[cfg(unix)]
    fn script(dir: &Path, body: &str) -> String {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join("ed.sh");
        std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p.display().to_string()
    }

    #[cfg(unix)]
    fn tmp(tag: &str) -> PathBuf {
        let t = std::env::temp_dir().join(format!("ce-test-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&t).unwrap();
        t
    }

    /// Scripted broker: records calls; `fail_on` makes that op answer with the given error.
    fn broker(
        tags: bool,
        fail_on: Option<(&'static str, &'static str)>,
        log: Log,
    ) -> impl FnMut(&str, Value) -> Result<Value, String> {
        let mut g = 7u64;
        move |op, p| {
            log.borrow_mut().push((op.to_string(), p.clone()));
            if let Some((f, e)) = fail_on {
                if f == op {
                    return Err(e.to_string());
                }
            }
            if op == "entry.get" {
                return Ok(get(tags));
            }
            g += 1;
            Ok(json!({"generation": g}))
        }
    }

    #[cfg(unix)]
    #[test]
    fn full_flow_applies_only_changes_with_threaded_generations() {
        let t = tmp("a");
        let ed = script(
            &t,
            "sed -i.bak -e 's/^aliases: pay$/aliases: pay, billing/' -e 's/^sensitivity: high/sensitivity: low/' \"$1\"",
        );
        let log = Log::default();
        let mut c = broker(true, None, Rc::clone(&log));
        let out = run_edit(&mut c, "stripe", "n", "e1", &ed, false).unwrap();
        assert_eq!(out[0], "stripe: updated");
        let l = log.borrow();
        let ops: Vec<&str> = l.iter().map(|(o, _)| o.as_str()).collect();
        assert_eq!(ops, ["entry.get", "entry.alias", "entry.update"]);
        assert_eq!(l[1].1["generation"], json!(7));
        assert_eq!(l[2].1["generation"], json!(8));
        assert_eq!(l[2].1["sensitivity"], json!("low"));
        let _ = std::fs::remove_dir_all(&t);
    }

    #[cfg(unix)]
    #[test]
    fn dry_run_and_no_change_apply_nothing() {
        let t = tmp("d");
        let ed = script(
            &t,
            "sed -i.bak 's/^sensitivity: high/sensitivity: low/' \"$1\"",
        );
        let log = Log::default();
        let mut c = broker(false, None, Rc::clone(&log));
        let out = run_edit(&mut c, "s", "n", "e1", &ed, true).unwrap();
        assert!(
            out[0].contains("none applied") && out[1].contains("entry.update"),
            "{out:?}"
        );
        assert_eq!(log.borrow().len(), 1);
        let none = script(&t, "true");
        let out = run_edit(&mut c, "s", "n", "e1", &none, false).unwrap();
        assert_eq!(out, ["s: no changes"]);
        let _ = std::fs::remove_dir_all(&t);
    }

    #[cfg(unix)]
    #[test]
    fn malformed_edit_applies_nothing_and_leaves_no_file() {
        let t = tmp("m");
        let ed = script(
            &t,
            &format!(
                "echo \"$1\" > {}/path; echo 'junk line' >> \"$1\"",
                t.display()
            ),
        );
        let log = Log::default();
        let mut c = broker(false, None, Rc::clone(&log));
        let e = run_edit(&mut c, "s", "n", "e1", &ed, false).unwrap_err();
        assert!(e.starts_with("line "), "{e}");
        assert_eq!(log.borrow().len(), 1, "only the entry.get");
        let p = std::fs::read_to_string(t.join("path")).unwrap();
        assert!(!Path::new(p.trim()).exists(), "temp file must be gone");
        let _ = std::fs::remove_dir_all(&t);
    }

    #[cfg(unix)]
    #[test]
    fn conflict_keeps_the_file_and_says_so() {
        let t = tmp("c");
        let ed = script(
            &t,
            "sed -i.bak 's/^sensitivity: high/sensitivity: low/' \"$1\"",
        );
        let mut c = broker(
            false,
            Some((
                "entry.update",
                "conflict: the node is at generation 9, not 7",
            )),
            Log::default(),
        );
        let e = run_edit(&mut c, "s", "n", "e1", &ed, false).unwrap_err();
        assert!(
            e.contains("changed meanwhile") && e.contains("kept at"),
            "{e}"
        );
        let path = e
            .split("kept at ")
            .nth(1)
            .unwrap()
            .split(' ')
            .next()
            .unwrap();
        assert!(Path::new(path).exists());
        let _ = std::fs::remove_dir_all(Path::new(path).parent().unwrap());
        let _ = std::fs::remove_dir_all(&t);
    }

    #[cfg(unix)]
    #[test]
    fn scratch_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let s = Scratch::new("x").unwrap();
        let d = std::fs::metadata(&s.dir).unwrap().permissions().mode() & 0o777;
        let f = std::fs::metadata(&s.file).unwrap().permissions().mode() & 0o777;
        assert_eq!((d, f), (0o700, 0o600));
    }
}
