//! `credmgr import --format json` (rc.2): the JSON shape of the one-call batch import.
//!
//! The input is an array of entries. Each is one of
//!
//! ```text
//! {"name": "STRIPE_KEY", "value": "..."}                                   one field
//! {"name": "PROD_DB", "fields": [{"label": "host", "value": "..."},       several fields
//!                                {"label": "otp", "value": "...", "type": "totp-seed"}]}
//! ```
//!
//! and is passed to `entry.create_batch` as it is: the keys here are exactly the ones the broker reads from a
//! batch item (`name`, `value`, `label`, `fields`, `entryType`, `sensitivity`; and per field `label`, `value`,
//! `type`, `masked`). Anything else is refused up front, by index and key name, so a typo is never silently
//! dropped. The broker stays the authority on names, types and sensitivity.
//!
//! Nothing in this module prints or returns a value inside an error: refusals name an entry's position
//! (1-based) and the offending key or type, never what it held. A single-value entry with an empty value is
//! skipped and reported by name, the way an empty `NAME=` line is in a `.env` file.

use serde_json::{Map, Value};

/// What `entry.create_batch` is given, and what was left out.
pub struct Parsed {
    pub entries: Vec<Value>,
    /// Names whose single `value` was empty; not imported.
    pub skipped_empty: Vec<String>,
}

const ITEM_KEYS: &[&str] = &[
    "name",
    "value",
    "label",
    "fields",
    "entryType",
    "sensitivity",
];
const FIELD_KEYS: &[&str] = &["label", "value", "type", "masked"];

/// Parses the text of a JSON import file.
pub fn parse(text: &str) -> Result<Parsed, String> {
    // A `serde_json` syntax error names a line and column, never the text.
    let root: Value = serde_json::from_str(text).map_err(|e| format!("not valid JSON: {e}"))?;
    let items = root.as_array().ok_or(
        "a JSON import is an array of entries: [{\"name\": ..., \"value\": ...}, \
         {\"name\": ..., \"fields\": [{\"label\": ..., \"value\": ...}]}]",
    )?;
    let mut entries = Vec::with_capacity(items.len());
    let mut skipped_empty = Vec::new();
    for (i, item) in items.iter().enumerate() {
        let at = i + 1;
        let obj = item
            .as_object()
            .ok_or_else(|| format!("entry {at} is not an object"))?;
        if let Some(k) = unknown_key(obj, ITEM_KEYS) {
            return Err(format!(
                "entry {at} has a key the broker does not read: '{k}' (allowed: {})",
                ITEM_KEYS.join(", ")
            ));
        }
        let name = obj
            .get("name")
            .and_then(Value::as_str)
            .filter(|n| !n.is_empty())
            .ok_or_else(|| format!("entry {at} needs a \"name\" (a non-empty string)"))?;
        match (obj.get("value"), obj.get("fields")) {
            (Some(_), Some(_)) => {
                return Err(format!(
                    "entry {at} ({name}) has both \"value\" and \"fields\"; give one"
                ))
            }
            (None, None) => {
                return Err(format!(
                    "entry {at} ({name}) needs a \"value\" or a \"fields\" list"
                ))
            }
            (Some(v), None) => {
                let v = v
                    .as_str()
                    .ok_or_else(|| format!("entry {at} ({name}): \"value\" must be a string"))?;
                if v.is_empty() {
                    skipped_empty.push(name.to_string());
                    continue;
                }
            }
            (None, Some(f)) => {
                if obj.contains_key("label") {
                    return Err(format!(
                        "entry {at} ({name}): \"label\" names the field of a single \"value\"; with \"fields\" give each field its own label"
                    ));
                }
                let fields = f.as_array().filter(|a| !a.is_empty()).ok_or_else(|| {
                    format!("entry {at} ({name}): \"fields\" must be a non-empty list")
                })?;
                for (j, field) in fields.iter().enumerate() {
                    let fat = j + 1;
                    let fo = field.as_object().ok_or_else(|| {
                        format!("entry {at} ({name}) field {fat} is not an object")
                    })?;
                    if let Some(k) = unknown_key(fo, FIELD_KEYS) {
                        return Err(format!(
                            "entry {at} ({name}) field {fat} has a key the broker does not read: '{k}' (allowed: {})",
                            FIELD_KEYS.join(", ")
                        ));
                    }
                    if !fo.get("value").is_some_and(Value::is_string) {
                        return Err(format!(
                            "entry {at} ({name}) field {fat} needs a \"value\" string"
                        ));
                    }
                }
            }
        }
        entries.push(Value::Object(obj.clone()));
    }
    Ok(Parsed {
        entries,
        skipped_empty,
    })
}

fn unknown_key<'a>(obj: &'a Map<String, Value>, allowed: &[&str]) -> Option<&'a str> {
    obj.keys()
        .map(String::as_str)
        .find(|k| !allowed.contains(k))
}

/// Which parser a file wants: forced by `--format`, else by a `.json` extension, else `.env`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Env,
    Json,
}

impl Format {
    pub fn choose(forced: Option<&str>, source: &str) -> Result<Format, String> {
        match forced {
            Some("json") => Ok(Format::Json),
            Some("env") => Ok(Format::Env),
            Some(other) => Err(format!("--format takes json or env - got '{other}'")),
            None => {
                let json = source != "-"
                    && std::path::Path::new(source)
                        .extension()
                        .is_some_and(|e| e.eq_ignore_ascii_case("json"));
                Ok(if json { Format::Json } else { Format::Env })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn both_shapes_pass_through_exactly_as_the_broker_reads_them() {
        let p = parse(
            r#"[
              {"name": "A_ONE", "value": "gen-1"},
              {"name": "DB", "fields": [{"label": "host", "value": "h"},
                                        {"label": "otp", "value": "x", "type": "totp-seed", "masked": true}],
               "entryType": "server", "sensitivity": "high"},
              {"name": "L", "value": "v", "label": "token"}
            ]"#,
        )
        .unwrap();
        assert_eq!(p.entries.len(), 3);
        assert_eq!(p.entries[0], json!({"name": "A_ONE", "value": "gen-1"}));
        assert_eq!(p.entries[1]["fields"][1]["type"], "totp-seed");
        assert_eq!(p.entries[1]["sensitivity"], "high");
        assert_eq!(p.entries[2]["label"], "token");
        assert!(p.skipped_empty.is_empty());
    }

    #[test]
    fn an_empty_single_value_is_skipped_by_name() {
        let p = parse(r#"[{"name":"A","value":""},{"name":"B","value":"x"}]"#).unwrap();
        assert_eq!(p.skipped_empty, ["A"]);
        assert_eq!(p.entries.len(), 1);
    }

    #[test]
    fn refusals_name_the_position_and_key_and_never_a_value() {
        const V: &str = "placeholder-9f2c";
        for (input, needle) in [
            (
                format!(r#"{{"name":"A","value":"{V}"}}"#),
                "array of entries",
            ),
            (format!(r#"["{V}"]"#), "entry 1 is not an object"),
            (
                format!(r#"[{{"name":"A","value":"{V}","bogus":1}}]"#),
                "'bogus'",
            ),
            (format!(r#"[{{"value":"{V}"}}]"#), "needs a \"name\""),
            (
                format!(r#"[{{"name":"A","value":"{V}","fields":[]}}]"#),
                "both",
            ),
            (
                r#"[{"name":"A"}]"#.to_string(),
                "needs a \"value\" or a \"fields\"",
            ),
            (
                r#"[{"name":"A","value":5}]"#.to_string(),
                "must be a string",
            ),
            (
                format!(r#"[{{"name":"A","fields":[{{"label":"x","value":"{V}","kind":"t"}}]}}]"#),
                "'kind'",
            ),
            (
                r#"[{"name":"A","fields":[{"label":"x"}]}]"#.to_string(),
                "needs a \"value\"",
            ),
            (
                r#"[{"name":"A","fields":[]}]"#.to_string(),
                "non-empty list",
            ),
            (
                format!(r#"[{{"name":"A","label":"l","fields":[{{"value":"{V}"}}]}}]"#),
                "own label",
            ),
            (
                format!(r#"[{{"name":"ok","value":"{V}"}}, 7]"#),
                "entry 2 is not an object",
            ),
            (
                format!("[{{\"name\":\"A\",\"value\":\"{V}\""),
                "not valid JSON",
            ),
        ] {
            let e = parse(&input)
                .err()
                .unwrap_or_else(|| panic!("accepted {input}"));
            assert!(e.contains(needle), "{needle:?} not in {e:?}");
            assert!(!e.contains(V), "the error echoed a value: {e}");
        }
    }

    #[test]
    fn the_format_follows_the_flag_then_the_extension() {
        assert_eq!(Format::choose(None, "x.json").unwrap(), Format::Json);
        assert_eq!(Format::choose(None, "X.JSON").unwrap(), Format::Json);
        assert_eq!(Format::choose(None, ".env").unwrap(), Format::Env);
        assert_eq!(Format::choose(None, "-").unwrap(), Format::Env);
        assert_eq!(Format::choose(Some("json"), "-").unwrap(), Format::Json);
        assert_eq!(Format::choose(Some("env"), "x.json").unwrap(), Format::Env);
        assert!(Format::choose(Some("yaml"), "x").is_err());
    }
}
