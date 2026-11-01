//! Phase 4 exit gate: "No command accepts a secret in argv (grep gate in
//! CI)." `docs/10_API_AND_MCP.md §2` names this explicitly — V1's
//! `credmgr set NAME "value"` put the secret in shell history, `ps` output,
//! and process listings; V2 refuses to have an equivalent code path at all.
//!
//! This is a structural check on the source, not a behavioural one: nothing
//! here can prove "there is no such flag" by trying every possible input, so
//! it instead greps the one file that defines every flag this binary
//! recognises and fails loudly the day a future session adds one. The
//! companion behavioural proof (`unlock`/`set` genuinely read from stdin,
//! not merely that no forbidden flag string appears) lives in
//! `broker_integration.rs`.

use std::fs;
use std::path::Path;

fn main_rs_source() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/main.rs");
    fs::read_to_string(path).expect("crates/cli/src/main.rs must exist and be readable")
}

/// Every `.rs` file under `src/`, as `(file name, text)`. The command set is no
/// longer one file (`fields.rs` holds the multi-field commands, ADR-078), so a
/// guard that read only `main.rs` would let a flag defined next door through.
fn cli_sources() -> Vec<(String, String)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut out: Vec<(String, String)> = fs::read_dir(dir)
        .expect("crates/cli/src must be readable")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "rs"))
        .map(|p| {
            (
                p.file_name().unwrap().to_string_lossy().into_owned(),
                fs::read_to_string(&p).expect("a src file must be readable"),
            )
        })
        .collect();
    out.sort();
    assert!(
        out.iter().any(|(n, _)| n == "main.rs") && out.iter().any(|(n, _)| n == "fields.rs"),
        "the CLI sources went missing: {:?}",
        out.iter().map(|(n, _)| n).collect::<Vec<_>>()
    );
    out
}

/// Flag names that would put a secret value in argv if they existed —
/// checked as literal string tokens `take_flag_value`/`take_bool_flag`
/// would be called with.
const FORBIDDEN_FLAGS: &[&str] = &[
    "--value",
    "--password",
    "--passphrase",
    "--secret",
    "--recovery-code",
    "--pass",
    // ADR-078: the spellings a multi-field command would be tempted by.
    "--new-value",
    "--field-value",
    "--data",
];

#[test]
fn no_forbidden_flag_is_ever_defined() {
    for (file, source) in cli_sources() {
        for flag in FORBIDDEN_FLAGS {
            assert!(
                !source.contains(flag),
                "{file} defines the flag {flag:?} — a secret must never be \
                 accepted as a CLI argument (10_API_AND_MCP.md §2)"
            );
        }
    }
}

/// Every flag that consumes the next argument, with what that argument is. A
/// flag takes a *name* or a *number* - a node, a label, an id, a position, a path -
/// never a value to store; values come from stdin (`set`, `rotate`, `field add`).
/// Adding a value-taking flag means adding it here, on purpose, saying what it
/// carries - which is the review this test exists to force (ADR-078).
const VALUE_TAKING_FLAGS: &[(&str, &str)] = &[
    ("--node", "a node id"),
    ("--parent", "a node id"),
    ("--workdir", "a directory"),
    ("--scope", "a capability name"),
    (
        "--label",
        "a field's or a node's label - a name, listed in the clear by `field ls`",
    ),
    ("--field", "a field's label, to select it"),
    ("--field-id", "a field id (f_ and hex), to select it"),
    ("--type", "a field type name, or auto"),
    ("--mask", "on, off or auto"),
    ("--at", "a position, counted from 0"),
    ("--to", "a position, counted from 0"),
    (
        "--reason",
        "why a policy change or grant was made - recorded in the audit log",
    ),
    ("--mode", "replace or keep-both"),
    ("--limit", "a number"),
    ("--retain", "a number"),
    ("--file", "a path"),
    ("--known-revoked", "token ids"),
    ("--lock-after-seconds", "a number or none"),
    ("--agent-access", "read-write, read-only or none"),
    ("--require-two-factor", "never, reveal or always"),
    ("--sibling-visibility", "shared or isolated"),
    ("--length", "a number of characters (8-128) for `generate`"),
    (
        "--code",
        "an authenticator code, worthless after about ninety seconds (the passphrase `approve` needs comes from stdin)",
    ),
];

/// The flag literal passed to each value-taking helper, found in the source.
fn value_flags_in(source: &str) -> Vec<String> {
    let mut found = Vec::new();
    for helper in ["take_flag_value(", "take_text_flag(", "take_choice("] {
        let mut rest = source;
        while let Some(at) = rest.find(helper) {
            rest = &rest[at + helper.len()..];
            let head = &rest[..rest.len().min(120)];
            // The call, not the definition: a call names its flag as a literal
            // before the first `;` or `{`.
            let stop = head.find([';', '{']).unwrap_or(head.len());
            let call = &head[..stop];
            if let Some(open) = call.find("\"--") {
                let tail = &call[open + 1..];
                if let Some(close) = tail.find('"') {
                    let flag = &tail[..close];
                    if flag.len() > 2
                        && flag
                            .chars()
                            .skip(2)
                            .all(|c| c.is_ascii_lowercase() || c == '-')
                    {
                        found.push(flag.to_string());
                    }
                }
            }
        }
    }
    found
}

/// The structural half of "no command accepts a value in argv": the set of flags
/// that take an argument is exactly the reviewed list above - nothing more, and
/// no dead entries. `fields_cli.rs` is the behavioural half.
#[test]
fn every_flag_that_takes_a_value_is_on_the_reviewed_allowlist() {
    let mut seen: Vec<String> = Vec::new();
    for (file, source) in cli_sources() {
        for flag in value_flags_in(&source) {
            assert!(
                VALUE_TAKING_FLAGS.iter().any(|(f, _)| *f == flag),
                "{file} takes a value from the flag {flag:?}, which is not on the reviewed \
                 allowlist in this test. A flag may carry a name or a number, never a secret \
                 (10_API_AND_MCP.md §2); if this one is such a flag, add it to VALUE_TAKING_FLAGS \
                 and say what it carries"
            );
            seen.push(flag);
        }
    }
    for (flag, _) in VALUE_TAKING_FLAGS {
        assert!(
            seen.iter().any(|f| f == flag),
            "{flag} is on the allowlist but no source takes it - delete the entry"
        );
    }
}

/// The allowlist itself must not name anything that sounds like a secret.
#[test]
fn the_allowlist_names_no_flag_that_could_carry_a_secret() {
    const SECRET_SOUNDING: &[&str] = &[
        "value",
        "pass",
        "secret",
        "token",
        "key",
        "seed",
        "mnemonic",
        "recovery",
        "text",
        "body",
        "content",
        "note",
        "env",
        "data",
        "credential",
        "otp",
        "totp",
    ];
    for (flag, carries) in VALUE_TAKING_FLAGS {
        for fragment in SECRET_SOUNDING {
            assert!(
                !flag.contains(fragment),
                "{flag} ({carries}) sounds like it carries a secret ({fragment:?})"
            );
        }
    }
}

/// The two commands that take a secret (`unlock`'s passphrase, `set`'s new
/// value) must read it from stdin — this asserts the call site exists, so
/// deleting the `read_stdin_value()` call from either command (leaving no
/// way to supply the value at all, rather than accepting it some other way)
/// fails this test rather than silently changing behaviour.
#[test]
fn unlock_and_set_read_their_secret_from_stdin() {
    let source = main_rs_source();
    let unlock_fn = extract_fn(&source, "fn cmd_unlock");
    let set_fn = extract_fn(&source, "fn cmd_set");
    assert!(
        unlock_fn.contains("read_stdin_value()"),
        "cmd_unlock must read the passphrase from stdin"
    );
    assert!(
        set_fn.contains("read_stdin_value()"),
        "cmd_set must read the new value from stdin"
    );
}

/// ADR-078: every command that writes a value - `rotate`, `field add`, and the
/// bulk form of `set` - gets it from stdin, and the call sites stay.
#[test]
fn the_field_commands_read_their_values_from_stdin() {
    let main = main_rs_source();
    let fields = cli_sources()
        .into_iter()
        .find(|(n, _)| n == "fields.rs")
        .unwrap()
        .1;
    let rotate_fn = extract_fn(&main, "fn cmd_rotate");
    assert!(
        rotate_fn.contains("read_stdin_value()"),
        "cmd_rotate must read the new value from stdin"
    );
    let set_fn = extract_fn(&main, "fn cmd_set");
    assert!(
        set_fn.contains("read_stdin_value()") && set_fn.contains("read_bulk_stdin()"),
        "cmd_set must read its value, or its bulk text, from stdin"
    );
    let add_fn = extract_fn(&fields, "fn cmd_add");
    assert!(
        add_fn.contains("read_stdin_value()") && add_fn.contains("read_bulk_stdin()"),
        "field add must read its value, or its bulk text, from stdin"
    );
    let bulk_fn = extract_fn(&fields, "pub fn read_bulk_stdin");
    assert!(
        bulk_fn.contains("std::io::stdin()"),
        "the bulk reader must read stdin"
    );
    // `field set` changes a label, a type or masking - it has no value to read,
    // and must not grow a way to be handed one.
    let field_set_fn = extract_fn(&fields, "fn cmd_set");
    assert!(
        !field_set_fn.contains("read_stdin") && !field_set_fn.contains("\"value\""),
        "`credmgr field set` must not take a value (use `set --field` / `rotate --field`)"
    );
}

/// `credmgr import` and `credmgr notes set` carry sensitive text too (a whole
/// `.env`; a note sealed like a value). Neither may take that text as an
/// argument: the file is a *path* argument, the text comes from the file or
/// stdin. Flag names that would put the text in argv are refused outright, and
/// the call sites that read it from a file or stdin must stay.
#[test]
fn import_and_notes_set_take_text_from_a_file_or_stdin_never_argv() {
    let source = main_rs_source();
    for flag in [
        "--text",
        "--note",
        "--content",
        "--markdown",
        "--env",
        "--body",
    ] {
        assert!(
            !source.contains(flag),
            "main.rs defines {flag:?} — import/notes text must come from a file or stdin, \
             never a CLI argument"
        );
    }
    let import_fn = extract_fn(&source, "fn cmd_import");
    assert!(
        import_fn.contains("std::io::stdin()") && import_fn.contains("File::open"),
        "cmd_import must read the .env text from a file or stdin"
    );
    let notes_fn = extract_fn(&source, "fn cmd_notes");
    assert!(
        notes_fn.contains("std::io::stdin()") && notes_fn.contains("File::open"),
        "cmd_notes set must read the note from --file or stdin"
    );
    // The only flags `notes set` defines are `--file` (a path) and `--json` on `show`.
    assert!(
        notes_fn.contains("\"--file\""),
        "cmd_notes set takes the note from `--file <path>` or stdin"
    );
}

/// Crude but sufficient function-body slice: from the `fn <name>` signature
/// to the next top-level `\nfn ` (or end of file). Good enough for a source
/// file this small and flat; not meant to handle nested braces generally.
fn extract_fn<'a>(source: &'a str, signature: &str) -> &'a str {
    let start = source
        .find(signature)
        .unwrap_or_else(|| panic!("main.rs must define `{signature}`"));
    let rest = &source[start..];
    let end = rest[1..].find("\nfn ").map(|i| i + 1).unwrap_or(rest.len());
    &rest[..end]
}
