//! There is no field-name vocabulary — anywhere (ADR-011, ADR-078;
//! `docs/08_FIELD_MODEL.md §8` row 7).
//!
//! V1 prescribed field names per category (a per-category schema table) and nagged about the
//! ones you had not filled in. V2's rule is the opposite: a label is free text,
//! nothing looks one up in a table, and no word is reserved. Until now that
//! property held only because there was no field-name-consuming code at all; this
//! file makes it a gate, in two halves:
//!
//! 1. **Static** — none of V1's schema identifiers exists in any source file
//!    under `crates/` or the desktop app's `src*` trees.
//! 2. **Behavioural** — the field document accepts every label the rules allow,
//!    including the words that look like keys of the format itself, and rejects
//!    none for being "unknown".
//!
//! The banned identifiers are assembled from fragments below, so this file does
//! not match its own scan.

use std::fs;
use std::path::{Path, PathBuf};

use credmgr_core::fields::{create, decode, encode, validate, FieldInput, Override};

fn banned_identifiers() -> Vec<String> {
    [
        ("TYPE_", "SCHEMAS"),
        ("schemaFor", "Category"),
        ("missingSchema", "Fields"),
        ("orderFieldsBy", "Schema"),
        ("fieldLabelFor", "Name"),
    ]
    .iter()
    .map(|(a, b)| format!("{a}{b}"))
    .collect()
}

fn v2_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("v2 root")
}

/// Source and script files under `dir`, skipping build output and dependency
/// trees. A missing directory yields nothing (the desktop app is optional in a
/// partial checkout) — the caller asserts that *something* was scanned.
fn source_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            if matches!(
                name.as_ref(),
                "target" | "node_modules" | "dist" | ".git" | "gen"
            ) {
                continue;
            }
            source_files(&path, out);
        } else if matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("rs" | "ts" | "tsx" | "js" | "mjs" | "cjs" | "svelte" | "html" | "json")
        ) {
            out.push(path);
        }
    }
}

#[test]
fn no_source_file_references_a_predefined_field_name_list() {
    let root = v2_root();
    let mut files = Vec::new();
    source_files(&root.join("crates"), &mut files);
    let rust_files = files.len();
    // The desktop app: the front end and the Rust shell, whichever exist.
    let apps = root.join("apps/desktop");
    if let Ok(entries) = fs::read_dir(apps) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            if name.to_string_lossy().starts_with("src") {
                source_files(&entry.path(), &mut files);
            }
        }
    }
    assert!(
        rust_files >= 20,
        "the scan must actually read the crates (read {rust_files} files under crates/) — \
         a gate that scanned nothing would pass for the wrong reason"
    );

    let banned = banned_identifiers();
    let mut hits = Vec::new();
    for path in &files {
        let Ok(text) = fs::read_to_string(path) else {
            continue; // not UTF-8: not source we can be scanning for identifiers
        };
        for needle in &banned {
            if text.contains(needle.as_str()) {
                hits.push(format!(
                    "{} mentions {}",
                    path.strip_prefix(&root).unwrap_or(path).display(),
                    needle
                ));
            }
        }
    }
    assert!(
        hits.is_empty(),
        "a predefined field-name list has crept back (ADR-011):\n{}",
        hits.join("\n")
    );
}

#[test]
fn the_scan_would_notice_one() {
    // The gate is only worth having if it can fail: prove the matcher fires on a
    // synthetic file containing one of the identifiers, in a scratch directory.
    let dir = tempfile::tempdir().unwrap();
    let banned = banned_identifiers();
    fs::write(
        dir.path().join("offender.rs"),
        format!("const _X: () = {{ let _ = \"{}\"; }};\n", banned[0]),
    )
    .unwrap();
    let mut files = Vec::new();
    source_files(dir.path(), &mut files);
    assert_eq!(files.len(), 1);
    let text = fs::read_to_string(&files[0]).unwrap();
    assert!(banned.iter().any(|b| text.contains(b.as_str())));
}

#[test]
fn every_label_the_rules_allow_is_accepted_and_none_is_reserved() {
    // Words a vocabulary would plausibly bless, words a schema would treat as
    // structure, and words that are keys of the document format itself. None of
    // them is special.
    let labels = [
        "",
        "password",
        "username",
        "host",
        "port",
        "api key",
        "seed phrase",
        "private key",
        "totp",
        "note",
        "notes",
        "id",
        "label",
        "value",
        "type",
        "masked",
        "fields",
        "v",
        "entryType",
        "sensitivity",
        "__proto__",
        "constructor",
        "zzz never seen before",
        "密码",
        "пароль",
        "كلمة المرور",
        "🔑",
        "  padded  ",
        "a:b",
        "with \"quotes\" and \\ backslash",
    ];
    for label in labels {
        let doc = create(
            vec![FieldInput {
                label: label.to_string(),
                value: "v".to_string(),
                field_type: None,
                masked: None,
            }],
            Override::Keep,
            Override::Keep,
        )
        .unwrap_or_else(|e| panic!("label {label:?} refused: {e}"));
        validate(&doc).unwrap();
        let back = decode(&encode(&doc).unwrap()).unwrap();
        assert_eq!(
            back.fields[0].label, label,
            "stored verbatim, never normalised"
        );
    }
}

#[test]
fn the_same_label_may_appear_any_number_of_times_and_no_label_is_required() {
    // Duplicates are the user's business (`08 §3.4`); a document with no
    // meaningful label at all is as valid as one with all of them.
    let same: Vec<FieldInput> = (0..50)
        .map(|i| FieldInput {
            label: "key".to_string(),
            value: i.to_string(),
            field_type: None,
            masked: None,
        })
        .collect();
    let doc = create(same, Override::Keep, Override::Keep).unwrap();
    assert_eq!(doc.fields.len(), 50);

    let unlabelled = create(
        vec![FieldInput {
            label: String::new(),
            value: "just a value".to_string(),
            field_type: None,
            masked: None,
        }],
        Override::Keep,
        Override::Keep,
    )
    .unwrap();
    assert_eq!(unlabelled.fields[0].label, "");
}

#[test]
fn the_document_format_has_a_fixed_set_of_keys_and_none_of_them_is_a_field_name() {
    // The serialised keys are the *structure* of the document, fixed and small.
    // A field's label lives in a `label` VALUE, never as a key, which is what
    // keeps a vocabulary from ever being a schema.
    let doc = create(
        vec![FieldInput {
            label: "custom-label-xyz".to_string(),
            value: "v".to_string(),
            field_type: Some(credmgr_core::inference::FieldType::Text),
            masked: Some(false),
        }],
        Override::Set(credmgr_core::inference::EntryType::Other),
        Override::Set(credmgr_core::inference::Sensitivity::Low),
    )
    .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&encode(&doc).unwrap()).unwrap();
    let mut top: Vec<&str> = json
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    top.sort_unstable();
    assert_eq!(top, ["entryType", "fields", "sensitivity", "v"]);
    let mut field: Vec<&str> = json["fields"][0]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    field.sort_unstable();
    assert_eq!(field, ["id", "label", "masked", "type", "value"]);
    assert_eq!(json["fields"][0]["label"], "custom-label-xyz");
}
