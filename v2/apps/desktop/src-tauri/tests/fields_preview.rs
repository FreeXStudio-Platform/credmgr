//! `fields_preview` (ADR-078) held to the two things that make it safe to ship:
//!
//! 1. **The shell links `credmgr-core` for text and type logic only.** The shell
//!    holds no key and decrypts nothing (ADR-001); a dependency on the crate that
//!    contains `envelope`, `keys` and `signing` must not quietly become a use of
//!    them. This reads this crate's own source and fails on any `credmgr_core::`
//!    path outside the three modules the preview needs.
//! 2. **What it previews is what the broker accepts.** The preview's output is
//!    turned into `fields` the way the screen does it (label and value verbatim, a
//!    pin only where there is one), and those `fields` are checked against core's
//!    own `FieldInput` / `create` - the types the broker deserialises into - and
//!    against the parser's output, byte for byte.

use std::path::Path;

use credmgr_core::fields::{self, FieldInput, Override};
use credmgr_core::parser;
use desktop_lib::fields_preview::{preview, FIELD_INPUT_KEYS};
use serde_json::{json, Value};

/// The only `credmgr_core` modules this crate may name.
const ALLOWED_CORE_MODULES: &[&str] = &["parser", "fields", "inference"];

fn source_files() -> Vec<(String, String)> {
    fn walk(dir: &Path, out: &mut Vec<(String, String)>) {
        for entry in std::fs::read_dir(dir).expect("read dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push((
                    path.display().to_string(),
                    std::fs::read_to_string(&path).expect("read source"),
                ));
            }
        }
    }
    let mut out = Vec::new();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    walk(&root.join("src"), &mut out);
    walk(&root.join("tests"), &mut out);
    out
}

/// Every `credmgr_core::<module>` named in `text`, outside comments.
fn core_modules_named(text: &str) -> Vec<String> {
    let code: String = text
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    let mut found = Vec::new();
    let mut rest = code.as_str();
    while let Some(at) = rest.find("credmgr_core::") {
        rest = &rest[at + "credmgr_core::".len()..];
        let module: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if !module.is_empty() {
            found.push(module);
        }
    }
    found
}

#[test]
fn the_shell_uses_only_the_text_and_type_modules_of_core() {
    let mut named = Vec::new();
    for (file, text) in source_files() {
        // This file's own list and examples name every module on purpose.
        if file.ends_with("tests/fields_preview.rs") {
            continue;
        }
        for module in core_modules_named(&text) {
            assert!(
                ALLOWED_CORE_MODULES.contains(&module.as_str()),
                "{file} uses credmgr_core::{module}. The desktop shell holds no key and decrypts \
                 nothing (ADR-001); it links credmgr-core for {ALLOWED_CORE_MODULES:?} only"
            );
            named.push(module);
        }
    }
    // The check can fail: the preview module really does use core, so a scan that
    // found nothing would be a scan that cannot see.
    assert!(
        named.iter().any(|m| m == "parser") && named.iter().any(|m| m == "fields"),
        "found no credmgr_core use at all - the scan is blind: {named:?}"
    );
}

#[test]
fn the_scan_can_fail() {
    assert_eq!(
        core_modules_named("use credmgr_core::envelope::open;\nuse credmgr_core::{a};\n"),
        vec!["envelope"]
    );
    assert!(core_modules_named("// credmgr_core::envelope in a comment\n").is_empty());
}

/// The screen's "save what the preview showed" step, in Rust: label and value
/// verbatim, `type` / `masked` only where they are pins. (`bridge.ts`'s
/// `previewFieldInputs` is the same rule.)
fn fields_to_send(segment: &Value) -> Value {
    Value::Array(
        segment["fields"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| {
                let mut input = json!({ "label": f["label"], "value": f["value"] });
                if f["typeOverridden"] == true {
                    input["type"] = f["type"].clone();
                }
                if f["maskedOverridden"] == true {
                    input["masked"] = f["masked"].clone();
                }
                input
            })
            .collect(),
    )
}

fn preview_json(text: &str, split: bool) -> Value {
    serde_json::to_value(preview(Some(text), None, split).expect("preview")).unwrap()
}

#[test]
fn what_is_previewed_is_what_the_parser_produced_byte_for_byte() {
    let pem = "-----BEGIN KEY-----\nAAAA\nBBBB\n-----END KEY-----";
    let inputs = [
        "host: db.example.test\nusername: svc\npassword:  leading space kept\n",
        "private key:\n-----BEGIN KEY-----\nAAAA\nBBBB\n-----END KEY-----\n",
        "just one unlabelled value",
        "a: 1\n///\nb: 2\n///\n\n///\nc: 3\n",
        "ratio: 3:1\nurl: https://api.example.test/x?y=1\n",
        "tab:\tseparated\r\nwindows: line endings\r\n",
        pem,
        "",
        "///",
    ];
    for text in inputs {
        let merged = preview_json(text, false);
        let want: Vec<(String, String)> = parser::parse_bulk(text)
            .into_iter()
            .map(|f| (f.label, f.value))
            .collect();
        let got: Vec<(String, String)> = merged["segments"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|s| s["fields"].as_array().unwrap())
            .map(|f| {
                (
                    f["label"].as_str().unwrap().to_string(),
                    f["value"].as_str().unwrap().to_string(),
                )
            })
            .collect();
        assert_eq!(got, want, "merged preview of {text:?}");

        // Splitting regroups the same fields, in the same order: P-18's equivalence,
        // seen from the screen's side.
        let split = preview_json(text, true);
        let regrouped: Vec<(String, String)> = split["segments"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|s| s["fields"].as_array().unwrap())
            .map(|f| {
                (
                    f["label"].as_str().unwrap().to_string(),
                    f["value"].as_str().unwrap().to_string(),
                )
            })
            .collect();
        assert_eq!(regrouped, want, "split preview of {text:?}");
        assert_eq!(
            split["segments"].as_array().unwrap().len(),
            parser::parse_bulk_segments(text).len(),
            "one entry per block"
        );
    }
}

#[test]
fn the_fields_a_screen_sends_are_ones_the_broker_will_deserialise_and_accept() {
    let text = "host: db.example.test\nusername: svc\npassword: pw-test-1\nnotes: a note\n///\nlone value\n";
    for split in [false, true] {
        let p = preview_json(text, split);
        for segment in p["segments"].as_array().unwrap() {
            let send = fields_to_send(segment);
            // The broker deserialises `fields` into core's FieldInput (deny_unknown_fields)...
            let inputs: Vec<FieldInput> = serde_json::from_value(send.clone())
                .unwrap_or_else(|e| panic!("the broker would refuse {send}: {e}"));
            // ...with the key set it checks first, and builds the document from them.
            for item in send.as_array().unwrap() {
                assert!(item
                    .as_object()
                    .unwrap()
                    .keys()
                    .all(|k| FIELD_INPUT_KEYS.contains(&k.as_str())));
            }
            let doc = fields::create(inputs, Override::Keep, Override::Keep)
                .expect("a previewed segment is a document the broker accepts");
            // The projection the broker stores is the projection the preview showed.
            let projection = fields::project(&doc);
            assert_eq!(
                json!(projection.entry_type),
                segment["entryType"],
                "entry type"
            );
            assert_eq!(
                json!(projection.sensitivity),
                segment["sensitivity"],
                "sensitivity"
            );
            assert_eq!(json!(projection.field_count), segment["fieldCount"]);
            assert_eq!(json!(projection.has_totp), segment["hasTotp"]);
            // Nothing was pinned by merely previewing.
            assert!(doc
                .fields
                .iter()
                .all(|f| f.field_type.is_none() && f.masked.is_none()));
        }
    }
}

#[test]
fn a_users_pin_survives_the_round_trip_and_an_untouched_field_stays_inferred() {
    let p = preview(
        None,
        Some(&json!([
            { "label": "token", "value": "abc", "type": "text" },
            { "label": "password", "value": "pw-test-1" },
        ])),
        false,
    )
    .unwrap();
    let segment = serde_json::to_value(&p.segments[0]).unwrap();
    let send = fields_to_send(&segment);
    assert_eq!(
        send,
        json!([
            { "label": "token", "value": "abc", "type": "text" },
            { "label": "password", "value": "pw-test-1" },
        ]),
        "only the pin is sent back"
    );
}

#[test]
fn the_preview_never_widens_what_the_broker_would_refuse() {
    // A label with a control character, or an over-long one, is refused here for
    // the reason the broker would refuse it - by index, quoting nothing.
    for label in ["bad\nlabel", &"x".repeat(201)] {
        let e = preview(
            None,
            Some(&json!([{ "label": label, "value": "NEEDLE-1" }])),
            false,
        )
        .unwrap_err();
        assert_eq!(e.code, "invalid_fields");
        assert!(
            !e.message.contains("NEEDLE-1") && !e.message.contains("bad"),
            "{}",
            e.message
        );
    }
}
