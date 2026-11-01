//! Holds `apps/desktop/src/lib/bridge.ts` — the typed client the screens call
//! — to the bridge's own table, read off disk.
//!
//! The TypeScript file is hand-written (a generator would be a second build
//! system for one file), so it is exactly the kind of copy that drifts in
//! silence: a command renamed in Rust, a wire key added, an error code the
//! broker grew. Each of those compiles on both sides and fails only at
//! runtime, inside a screen. This guard turns them into a test failure here.

use std::collections::BTreeSet;
use std::path::Path;

use desktop_lib::autolock::{self, LockReason};
use desktop_lib::commands::{bridged, SHELL_COMMANDS};
use desktop_lib::error::{BRIDGE_LOCAL_CODES, BROKER_ERROR_CODES};
use desktop_lib::shell::{self, Inactive};

fn client() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../src/lib/bridge.ts");
    std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "cannot read {}: {e} — the typed client is part of the bridge contract",
            path.display()
        )
    })
}

/// The code of every `BridgeError::bridge("code", …)` call in `text`, comments
/// excluded: a doc comment may quote the call to explain it (`error.rs` does),
/// and quoting is not raising.
fn raised_codes(text: &str) -> BTreeSet<String> {
    let code_only: String = text
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    let mut raised = BTreeSet::new();
    let mut rest = code_only.as_str();
    while let Some(at) = rest.find("BridgeError::bridge(") {
        rest = &rest[at + "BridgeError::bridge(".len()..];
        let Some(open) = rest.find('"') else { break };
        let after = &rest[open + 1..];
        let Some(close) = after.find('"') else { break };
        raised.insert(after[..close].to_string());
        rest = &after[close..];
    }
    raised
}

/// `(command, keys of its argument object)` for every `invoke(...)` call in
/// the client. Every call uses shorthand properties (`{ node, entry }`), which
/// is what makes the key list recoverable without a TypeScript parser.
fn invoke_calls(source: &str) -> Vec<(String, BTreeSet<String>)> {
    let mut calls = Vec::new();
    for chunk in source.split("export const ").skip(1) {
        // End at the call's own `);`, not the first `;` — a multi-line
        // generic (`invoke<{\n  applied: boolean;\n …}>`) carries `;\n` inside
        // the type, and cutting there loses the command after it.
        let chunk = &chunk[..chunk.find(");\n").unwrap_or(chunk.len())];
        let Some(at) = chunk.find("invoke") else {
            continue;
        };
        let rest = &chunk[at..];
        // The command is the first string literal after `invoke<…>(`.
        let Some(open) = rest.find("(\"").or_else(|| rest.find("(\n")) else {
            continue;
        };
        let rest = &rest[open..];
        let Some(q1) = rest.find('"') else { continue };
        let Some(q2) = rest[q1 + 1..].find('"') else {
            continue;
        };
        let command = rest[q1 + 1..q1 + 1 + q2].to_string();
        let after = &rest[q1 + 2 + q2..];
        let keys = match (after.find('{'), after.find('}')) {
            (Some(o), Some(c)) if o < c => after[o + 1..c]
                .split(',')
                .map(|k| k.trim().to_string())
                .filter(|k| !k.is_empty())
                .collect(),
            _ => BTreeSet::new(),
        };
        calls.push((command, keys));
    }
    calls
}

#[test]
fn the_client_calls_every_bridged_command_once_with_exactly_its_wire_keys() {
    let calls = invoke_calls(&client());
    assert!(
        calls.len() >= 40,
        "parsed only {} invoke calls — parser broken",
        calls.len()
    );

    let mut problems = Vec::new();
    for b in bridged() {
        let matching: Vec<&(String, BTreeSet<String>)> =
            calls.iter().filter(|(c, _)| c == b.command).collect();
        match matching.as_slice() {
            [] => problems.push(format!("bridge.ts never invokes {}", b.command)),
            [(_, keys)] => {
                let wire: BTreeSet<String> = b.params.iter().map(|(k, _)| k.to_string()).collect();
                if *keys != wire {
                    problems.push(format!(
                        "{}: bridge.ts sends {keys:?}, the bridge takes {wire:?}",
                        b.command
                    ));
                }
            }
            _ => problems.push(format!("bridge.ts invokes {} more than once", b.command)),
        }
    }
    // The shell's own commands (clipboard): not broker ops, so not in `bridged()`,
    // but held to the client by the same rule — once, with exactly their keys.
    for s in SHELL_COMMANDS {
        let matching: Vec<&(String, BTreeSet<String>)> =
            calls.iter().filter(|(c, _)| c == s.command).collect();
        match matching.as_slice() {
            [] => problems.push(format!("bridge.ts never invokes {}", s.command)),
            [(_, keys)] => {
                let wire: BTreeSet<String> = s.args.iter().map(|k| k.to_string()).collect();
                if *keys != wire {
                    problems.push(format!(
                        "{}: bridge.ts sends {keys:?}, the shell takes {wire:?}",
                        s.command
                    ));
                }
            }
            _ => problems.push(format!("bridge.ts invokes {} more than once", s.command)),
        }
    }
    for (command, _) in &calls {
        if !bridged().any(|b| b.command == command)
            && !SHELL_COMMANDS.iter().any(|s| s.command == command)
        {
            problems.push(format!(
                "bridge.ts invokes {command}, which the bridge does not expose"
            ));
        }
    }
    assert!(
        problems.is_empty(),
        "bridge.ts drifted:\n{}",
        problems.join("\n")
    );
}

/// The members of `export type <name> =` up to its `;`, as the quoted words.
fn union_members(source: &str, name: &str) -> BTreeSet<String> {
    let marker = format!("export type {name} =");
    let body = source
        .split(&marker)
        .nth(1)
        .and_then(|s| s.split(';').next())
        .unwrap_or_else(|| panic!("bridge.ts declares {name}"));
    // Strip `/** … */` comments between members before splitting on `|`.
    let mut cleaned = String::new();
    let mut rest = body;
    while let Some(open) = rest.find("/*") {
        cleaned.push_str(&rest[..open]);
        let close = rest[open..].find("*/").expect("unterminated comment") + open + 2;
        rest = &rest[close..];
    }
    cleaned.push_str(rest);
    cleaned
        .split('|')
        .map(|s| s.trim().trim_matches('"').to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

#[test]
fn the_clients_local_error_codes_are_the_ones_the_shell_can_raise() {
    let in_ts = union_members(&client(), "BridgeLocalCode");
    let in_rust: BTreeSet<String> = BRIDGE_LOCAL_CODES.iter().map(|s| s.to_string()).collect();
    assert_eq!(
        in_ts, in_rust,
        "BridgeLocalCode in bridge.ts must equal BRIDGE_LOCAL_CODES in src/error.rs"
    );

    // And BRIDGE_LOCAL_CODES must be complete: every `BridgeError::bridge("…")`
    // call in the shell names a code on the list.
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut raised = BTreeSet::new();
    for entry in std::fs::read_dir(&src).expect("read src/") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("read source");
        raised.extend(raised_codes(&text));
    }
    assert!(
        !raised.is_empty(),
        "parsed no BridgeError::bridge calls — parser broken"
    );
    let unlisted: Vec<&String> = raised.iter().filter(|c| !in_rust.contains(*c)).collect();
    assert!(
        unlisted.is_empty(),
        "the shell raises codes BRIDGE_LOCAL_CODES (and bridge.ts) do not list: {unlisted:?}"
    );
}

#[test]
fn the_clients_event_names_and_payload_words_are_the_shells() {
    let source = client();

    // Event names.
    for (key, value) in [
        ("locked", autolock::EVENT_LOCKED),
        ("windowInactive", shell::EVENT_WINDOW_INACTIVE),
    ] {
        assert!(
            source.contains(&format!("{key}: \"{value}\"")),
            "bridge.ts SHELL_EVENTS.{key} must be {value:?}"
        );
    }

    // Payload words.
    let locks: BTreeSet<String> = LockReason::ALL
        .iter()
        .map(|r| r.as_str().to_string())
        .collect();
    assert_eq!(union_members(&source, "LockReason"), locks);
    let inactive: BTreeSet<String> = Inactive::ALL
        .iter()
        .map(|r| r.as_str().to_string())
        .collect();
    assert_eq!(union_members(&source, "WindowInactiveReason"), inactive);
}

#[test]
fn the_clients_receipt_has_exactly_the_fields_the_shell_sends() {
    // `CopyReceipt` is the only thing `entry_copy` answers; it must have no
    // field a value could travel in.
    let receipt = serde_json::to_value(desktop_lib::commands::CopyReceipt {
        copied: true,
        clear_after_seconds: Some(30),
    })
    .unwrap();
    let keys_in_rust: BTreeSet<String> = receipt.as_object().unwrap().keys().cloned().collect();

    let source = client();
    let body = source
        .split("export interface CopyReceipt {")
        .nth(1)
        .and_then(|s| s.split("\n}").next())
        .expect("bridge.ts declares CopyReceipt");
    let keys_in_ts: BTreeSet<String> = body
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with("/**") && !l.starts_with('*') && l.contains(':'))
        .filter_map(|l| l.split(':').next())
        .map(|k| k.trim().to_string())
        .collect();
    assert_eq!(keys_in_ts, keys_in_rust);
    assert_eq!(
        keys_in_rust,
        BTreeSet::from(["copied".to_string(), "clearAfterSeconds".to_string()])
    );
}

#[test]
fn the_clients_error_union_is_the_brokers_vocabulary_exactly() {
    let source = client();
    let union = source
        .split("export type BrokerErrorCode =")
        .nth(1)
        .and_then(|s| s.split(';').next())
        .expect("bridge.ts declares BrokerErrorCode");
    let in_ts: BTreeSet<String> = union
        .split('|')
        .map(|s| s.trim().trim_matches('"').to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let in_rust: BTreeSet<String> = BROKER_ERROR_CODES.iter().map(|s| s.to_string()).collect();
    assert_eq!(
        in_ts, in_rust,
        "BrokerErrorCode in bridge.ts must equal BROKER_ERROR_CODES (itself pinned to protocol.rs)"
    );
}

#[test]
fn a_code_quoted_in_a_comment_is_not_a_code_raised() {
    let source = "/// `BridgeError::bridge(\"…\")` is how a code is raised.\n\
                  // BridgeError::bridge(\"also_quoted\", \"x\")\n\
                  fn f() -> BridgeError { BridgeError::bridge(\"real_code\", \"x\") }\n\
                  fn g() -> BridgeError {\n    BridgeError::bridge(\n        \"split_across_lines\",\n        \"x\",\n    )\n}\n";
    let found: Vec<String> = raised_codes(source).into_iter().collect();
    assert_eq!(found, vec!["real_code", "split_across_lines"]);
}
