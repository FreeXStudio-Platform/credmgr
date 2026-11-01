//! `fields_preview` - the live preview of a bulk paste (ADR-078, `08_FIELD_MODEL.md §5`).
//!
//! **No broker, no socket, no session, no audit record.** The preview runs here,
//! in the shell, on text the user is still typing: sending each keystroke to the
//! broker would write an audit record per keystroke and carry the secrets over
//! the socket for nothing. And it must be *the same code* the broker's world uses
//! (`credmgr_core::parser` for the grammar, `credmgr_core::fields` and `inference`
//! for what a field is and what an entry is projected to) because "the preview is
//! the contract" (`08 §5`): what the screen shows is what will be stored, byte for
//! byte. The webview keeps no second parser (the design's own `parseBulk` /
//! `inferType` were a second implementation and disagreed with core in three
//! places, F3).
//!
//! The broker never parses this grammar: the client previews, then sends the
//! previewed `fields` to `entry_create` / `entry_create_batch` verbatim.
//!
//! **What this module may use of `credmgr-core`.** `parser`, `fields` and
//! `inference` - pure text and type logic. This shell holds no key and decrypts
//! nothing (ADR-001); `tests/fields_preview.rs` reads this crate's source and
//! fails on any other `credmgr_core::` path (`envelope`, `keys`, `signing`, ...).
//!
//! **Nothing here logs, caches or retains its input.** The text and the field
//! values are used to build the answer and dropped; error messages name an index
//! or a count, never a label or a value (`FieldError`'s own rule).

use credmgr_core::fields::{self, FieldInput, Override};
use credmgr_core::inference::{infer_field_type, EntryType, FieldType, Sensitivity};
use credmgr_core::parser;
use serde::Serialize;
use serde_json::Value;

use crate::error::BridgeError;

/// The keys one element of `fields` may carry - the same set the broker accepts
/// for a field it is sent (`entry_doc::FIELD_INPUT_KEYS`).
pub const FIELD_INPUT_KEYS: &[&str] = &["label", "value", "type", "masked"];

/// One field as the preview shows it.
///
/// `label` and `value` are the parser's, byte for byte. `type` and `masked` are
/// the *effective* ones (the override if the caller sent one, else the inference),
/// `inferred_type` is what inference alone says, and the two `*_overridden` flags
/// say whether `type` / `masked` came from the caller. A screen that saves what it
/// previewed sends `type` / `masked` **only where the flag is set**, so a field
/// nobody touched keeps being inferred.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreviewField {
    pub label: String,
    pub value: String,
    #[serde(rename = "type")]
    pub field_type: FieldType,
    pub masked: bool,
    pub inferred_type: FieldType,
    pub type_overridden: bool,
    pub masked_overridden: bool,
}

/// One entry-to-be: what one `///`-separated block (or the whole paste) becomes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreviewSegment {
    /// The first non-empty label, else `untitled N` (N counts from 1). Making it
    /// unique among the node's existing names is the screen's job - it has the list.
    pub suggested_name: String,
    pub fields: Vec<PreviewField>,
    /// What the broker will store as the entry's type, absent a pinned one.
    pub entry_type: EntryType,
    pub sensitivity: Sensitivity,
    pub field_count: u32,
    pub has_totp: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Preview {
    pub segments: Vec<PreviewSegment>,
    /// The paste is one unlabelled blob of three or more lines (`08 §5`): offer
    /// "split by line instead". Only ever set for `text` input.
    pub single_blob_hint: bool,
}

fn invalid(message: impl Into<String>) -> BridgeError {
    BridgeError::bridge("invalid_fields", message)
}

/// `fields` (the JSON the screen holds) read into the core type, refusing what the
/// broker would refuse. A refusal names the element's index, never what it held.
pub fn parse_field_inputs(fields: &Value) -> Result<Vec<FieldInput>, BridgeError> {
    let items = fields
        .as_array()
        .ok_or_else(|| invalid("fields must be an array of {label, value} objects"))?;
    items
        .iter()
        .enumerate()
        .map(|(i, item)| {
            let object = item
                .as_object()
                .ok_or_else(|| invalid(format!("fields[{i}] must be an object")))?;
            if object
                .keys()
                .any(|k| !FIELD_INPUT_KEYS.contains(&k.as_str()))
            {
                return Err(invalid(format!(
                    "fields[{i}] has a key that is not one of: {}",
                    FIELD_INPUT_KEYS.join(", ")
                )));
            }
            // Not serde's own error: it can quote what it choked on.
            serde_json::from_value::<FieldInput>(item.clone())
                .map_err(|_| invalid(format!("fields[{i}] has a value of the wrong type")))
        })
        .collect()
}

/// One segment, from the fields it will hold. `fields::create` is the broker's own
/// validation (label rules, size cap) and id minting, so a preview that succeeds is
/// a paste the broker accepts.
fn segment(inputs: Vec<FieldInput>, number: usize) -> Result<PreviewSegment, BridgeError> {
    let doc = fields::create(inputs, Override::Keep, Override::Keep)
        .map_err(|e| invalid(e.to_string()))?;
    let projection = fields::project(&doc);
    let suggested_name = doc
        .fields
        .iter()
        .map(|f| f.label.trim())
        .find(|l| !l.is_empty())
        .map_or_else(|| format!("untitled {number}"), str::to_string);
    let fields = doc
        .fields
        .iter()
        .map(|f| {
            let (field_type, masked) = fields::effective(f);
            PreviewField {
                label: f.label.clone(),
                value: f.value.clone(),
                field_type,
                masked,
                inferred_type: infer_field_type(&f.label, &f.value),
                type_overridden: f.field_type.is_some(),
                masked_overridden: f.masked.is_some(),
            }
        })
        .collect();
    Ok(PreviewSegment {
        suggested_name,
        fields,
        entry_type: projection.entry_type,
        sensitivity: projection.sensitivity,
        field_count: projection.field_count,
        has_totp: projection.has_totp,
    })
}

fn inputs_of(parsed: Vec<parser::ParsedField>) -> Vec<FieldInput> {
    parsed.into_iter().map(FieldInput::from).collect()
}

/// `true` for a paste that is a single unlabelled value spread over three or more
/// non-blank lines - almost certainly several values pasted without labels.
fn is_single_blob(parsed: &[parser::ParsedField]) -> bool {
    match parsed {
        [only] => {
            only.label.is_empty()
                && only.value.lines().filter(|l| !l.trim().is_empty()).count() >= 3
        }
        _ => false,
    }
}

/// Preview `text` (parsed with the bulk grammar) or `fields` (already structured,
/// e.g. after the user edited a row) - exactly one of the two.
///
/// With `text`, `split: false` (the default) is one entry holding every field of
/// every `///` block; `split: true` is one entry per block. `fields` is always one
/// entry.
pub fn preview(
    text: Option<&str>,
    fields: Option<&Value>,
    split: bool,
) -> Result<Preview, BridgeError> {
    match (text, fields) {
        (Some(_), Some(_)) => Err(invalid("give text or fields, not both")),
        (None, None) => Err(invalid("give text or fields to preview")),
        (None, Some(fields)) => {
            let inputs = parse_field_inputs(fields)?;
            if inputs.is_empty() {
                return Ok(Preview {
                    segments: Vec::new(),
                    single_blob_hint: false,
                });
            }
            Ok(Preview {
                segments: vec![segment(inputs, 1)?],
                single_blob_hint: false,
            })
        }
        (Some(text), None) => {
            let blocks = parser::parse_bulk_segments(text);
            let single_blob_hint = {
                let flat: Vec<parser::ParsedField> = blocks.iter().flatten().cloned().collect();
                is_single_blob(&flat)
            };
            let groups: Vec<Vec<parser::ParsedField>> = if split {
                blocks
            } else if blocks.is_empty() {
                Vec::new()
            } else {
                vec![blocks.into_iter().flatten().collect()]
            };
            let segments = groups
                .into_iter()
                .enumerate()
                .map(|(i, group)| segment(inputs_of(group), i + 1))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Preview {
                segments,
                single_blob_hint,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn text(t: &str, split: bool) -> Preview {
        preview(Some(t), None, split).unwrap()
    }

    #[test]
    fn a_paste_is_one_entry_with_every_field_in_order_and_verbatim() {
        let p = text(
            "host: db.internal\nport: 5432\nusername: svc\npassword: pw-test-1  \n",
            false,
        );
        assert_eq!(p.segments.len(), 1);
        let s = &p.segments[0];
        assert_eq!(s.suggested_name, "host");
        assert_eq!(s.field_count, 4);
        let labels: Vec<&str> = s.fields.iter().map(|f| f.label.as_str()).collect();
        assert_eq!(labels, ["host", "port", "username", "password"]);
        // Nothing is trimmed - a trailing space is part of the value (08 §3.5).
        assert_eq!(s.fields[3].value, "pw-test-1  ");
        assert!(s.fields[3].masked, "a password is masked by default");
        assert_eq!(s.fields[3].field_type, FieldType::Password);
        assert_eq!(s.fields[3].inferred_type, FieldType::Password);
        assert!(!s.fields[3].type_overridden && !s.fields[3].masked_overridden);
        assert_eq!(s.entry_type, EntryType::Server);
        assert!(!p.single_blob_hint);
    }

    #[test]
    fn the_split_toggle_makes_one_entry_per_block_and_names_the_unlabelled() {
        let t = "host: a.example\npassword: p1\n///\nSOME UNLABELLED BLOCK\n///\nusername: u3";
        let merged = text(t, false);
        assert_eq!(merged.segments.len(), 1);
        assert_eq!(merged.segments[0].field_count, 4);

        let split = text(t, true);
        assert_eq!(split.segments.len(), 3);
        assert_eq!(split.segments[0].suggested_name, "host");
        assert_eq!(split.segments[1].suggested_name, "untitled 2");
        assert_eq!(split.segments[1].fields[0].label, "");
        assert_eq!(split.segments[2].suggested_name, "username");
        assert_eq!(
            split.segments.iter().map(|s| s.field_count).sum::<u32>(),
            merged.segments[0].field_count,
            "splitting moves fields between entries, it never loses one"
        );
    }

    #[test]
    fn empty_input_previews_nothing_rather_than_failing() {
        assert!(text("", false).segments.is_empty());
        assert!(text("", true).segments.is_empty());
        assert!(preview(None, Some(&json!([])), false)
            .unwrap()
            .segments
            .is_empty());
    }

    #[test]
    fn a_single_unlabelled_blob_of_three_lines_earns_the_split_by_line_hint() {
        assert!(text("one\ntwo\nthree\n", false).single_blob_hint);
        assert!(
            !text("one\ntwo\n", false).single_blob_hint,
            "two lines is not a blob"
        );
        assert!(
            !text("a: 1\nb: 2\nc: 3\n", false).single_blob_hint,
            "labelled lines are not a blob"
        );
        assert!(
            !text("one\n\n\n", false).single_blob_hint,
            "blank lines do not count"
        );
        // Splitting is the answer to the hint, not a way to hide it.
        assert!(text("one\ntwo\nthree\n", true).single_blob_hint);
    }

    #[test]
    fn a_noted_seed_or_totp_is_inferred_with_the_brokers_own_rules() {
        let p = text("note: remember to call\n", false);
        assert_eq!(
            p.segments[0].entry_type,
            EntryType::Note,
            "a lone note field is a note entry"
        );
        let p = text("totp seed: JBSWY3DPEHPK3PXP\n", false);
        assert!(p.segments[0].has_totp);
        assert_eq!(p.segments[0].entry_type, EntryType::Totp);
        assert_eq!(
            p.segments[0].sensitivity,
            credmgr_core::inference::default_sensitivity(FieldType::TotpSeed),
            "the strongest field's default sensitivity"
        );
    }

    #[test]
    fn structured_fields_keep_their_overrides_and_say_so() {
        let p = preview(
            None,
            Some(&json!([
                { "label": "token", "value": "abc", "type": "text", "masked": true },
                { "label": "password", "value": "pw-test" },
            ])),
            false,
        )
        .unwrap();
        let s = &p.segments[0];
        assert_eq!(s.field_count, 2);
        let a = &s.fields[0];
        assert_eq!(a.field_type, FieldType::Text);
        assert!(a.masked && a.masked_overridden && a.type_overridden);
        assert_eq!(a.inferred_type, infer_field_type("token", "abc"));
        let b = &s.fields[1];
        assert!(!b.type_overridden && !b.masked_overridden);
        assert_eq!(b.field_type, FieldType::Password);
    }

    #[test]
    fn bad_input_is_refused_by_index_and_never_echoes_what_it_was() {
        let both = preview(Some("a: b"), Some(&json!([])), false).unwrap_err();
        assert_eq!(both.code, "invalid_fields");
        assert!(preview(None, None, false).is_err());
        for (bad, needle) in [
            (json!("not an array"), "array"),
            (json!([1]), "fields[0] must be an object"),
            (
                json!([{ "label": "a", "value": "SECRET-A", "extra": 1 }]),
                "fields[0] has a key",
            ),
            (json!([{ "label": "a", "value": 7 }]), "wrong type"),
            (
                json!([{ "label": "a", "value": "x" }, { "label": "bad\nlabel", "value": "SECRET-B" }]),
                "field",
            ),
        ] {
            let e = preview(None, Some(&bad), false).unwrap_err();
            assert_eq!(e.code, "invalid_fields");
            assert!(e.message.contains(needle), "{needle}: {}", e.message);
            assert!(
                !e.message.contains("SECRET-A") && !e.message.contains("SECRET-B"),
                "an error echoed a value: {}",
                e.message
            );
            assert!(!e.message.contains("bad\nlabel"), "an error echoed a label");
        }
    }

    #[test]
    fn the_preview_answers_in_the_wire_names_the_screen_reads() {
        let v = serde_json::to_value(text("password: pw-test\n", false)).unwrap();
        assert_eq!(v["singleBlobHint"], false);
        let s = &v["segments"][0];
        for key in [
            "suggestedName",
            "fields",
            "entryType",
            "sensitivity",
            "fieldCount",
            "hasTotp",
        ] {
            assert!(s.get(key).is_some(), "segment lacks {key}");
        }
        let f = &s["fields"][0];
        for key in [
            "label",
            "value",
            "type",
            "masked",
            "inferredType",
            "typeOverridden",
            "maskedOverridden",
        ] {
            assert!(f.get(key).is_some(), "field lacks {key}");
        }
        assert_eq!(f["type"], "password");
        assert!(s["entryType"].is_string() && s["sensitivity"].is_string());
    }
}
