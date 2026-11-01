//! Cross-workspace drift guards.
//!
//! ADR-035 keeps `src-tauri` in its own Cargo workspace, so this crate cannot
//! `use credmgr_brokerd::protocol` to stay honest by construction — the
//! broker's error vocabulary and the vault's socket path are both *hand
//! copied* across that boundary. Copied constants rot silently, and a test
//! that compared the copy against itself would pass on both sides of any
//! divergence.
//!
//! So these tests read the real files off disk and compare against them. They
//! are the reason the duplication is acceptable rather than merely convenient.
//!
//! This is the shape `PROJECT_MAP.md §5.11` asks for in another context: for
//! months three documents claimed a test `I-26` parsed `18_ENDPOINT_INDEX.md`
//! and made drift impossible, and no such test existed. A guard that reads the
//! other side's source is the version of that claim which is true.
//!
//! **If one of these fails, do not edit the constant to make it green.** It
//! means the broker changed. Handle the new case, then update the constant.

use std::path::{Path, PathBuf};

use desktop_lib::error::BROKER_ERROR_CODES;
use desktop_lib::vault_paths::{RUN_DIR_NAME, SOCKET_FILE_NAME, VAULT_DIR_ENV};

/// `<repo>/v2` — this crate is at `v2/apps/desktop/src-tauri`.
fn v2_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("src-tauri is three levels below v2/")
        .to_path_buf()
}

fn read(relative: &str) -> String {
    let path = v2_root().join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "drift guard cannot read {}: {e}\n\
             This guard exists to compare this crate's hand-copied constants against the \
             real source. If the file moved, fix this path — do not delete the guard.",
            path.display()
        )
    })
}

/// Every distinct string literal following a `"error":` key.
fn error_codes_in(source: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut rest = source;
    while let Some(at) = rest.find("\"error\":") {
        rest = &rest[at + "\"error\":".len()..];
        let Some(open) = rest.find('"') else { break };
        let after = &rest[open + 1..];
        let Some(close) = after.find('"') else { break };
        let code = &after[..close];
        // Skip interpolations/format holes; every real discriminant is a
        // plain snake_case literal.
        if !code.is_empty()
            && code.chars().all(|c| c.is_ascii_lowercase() || c == '_')
            && !found.iter().any(|f: &String| f == code)
        {
            found.push(code.to_string());
        }
        rest = after;
    }
    found.sort();
    found
}

/// Every quoted match-arm label — `"vault.status" =>`. Includes the nested
/// arms inside `entry.undo`, which is why callers only ever check membership.
fn match_arm_labels(source: &str) -> Vec<String> {
    let mut found = Vec::new();
    for line in source.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with('"') {
            continue;
        }
        let Some(close) = trimmed[1..].find('"') else {
            continue;
        };
        let label = &trimmed[1..=close];
        if trimmed[close + 2..].trim_start().starts_with("=>") {
            found.push(label.to_string());
        }
    }
    found
}

#[test]
fn the_bridges_error_vocabulary_matches_the_brokers_exactly() {
    let protocol = read("crates/brokerd/src/protocol.rs");
    let on_the_wire = error_codes_in(&protocol);
    assert!(
        !on_the_wire.is_empty(),
        "parsed zero error codes out of protocol.rs — the guard's parser is broken, \
         which is worse than a drift, because it would pass forever"
    );

    let mut ours: Vec<String> = BROKER_ERROR_CODES.iter().map(|s| s.to_string()).collect();
    ours.sort();

    let missing: Vec<&String> = on_the_wire.iter().filter(|c| !ours.contains(c)).collect();
    let extra: Vec<&String> = ours.iter().filter(|c| !on_the_wire.contains(c)).collect();

    assert!(
        missing.is_empty(),
        "credmgrd can return error codes this bridge does not know about: {missing:?}\n\
         Handle them in src/error.rs, then add them to BROKER_ERROR_CODES."
    );
    assert!(
        extra.is_empty(),
        "BROKER_ERROR_CODES lists codes the broker no longer emits: {extra:?}\n\
         Remove them, and check nothing in the UI still branches on them."
    );
}

/// The broker's **top-level** dispatch arms and each arm's source text.
///
/// Top-level only: the nested arm inside `entry.undo`'s inner match
/// (`entry.remove`, which `entry.undo` re-dispatches) sits at a deeper indent and
/// falls inside `entry.undo`'s body here, which is what makes this count 55
/// where a raw arm count reads 56. (The inner match's other arm is the
/// multi-pattern `"entry.rotate" | "field.add" | ...` ADR-078 wrote across
/// several lines: its label is not followed by `=>`, so a label scan does not read
/// it as an arm at all, and it never was a dispatch arm. A dotted-name grep reads
/// 51 — it drops `whoami` and `search`, whose labels carry no dot. The authority
/// for the number is `tools/corpus_check.py::broker_ops`; this parser is checked
/// against the same 55 below. The counts were 40/42 until ADR-064/066 added
/// `vault.gate_recover` and `node.set_workdirs`, 42/44 until ADR-071 added
/// `node.update` and `node.policy`, 44/46 until ADR-072 added `notes.read`
/// and `notes.write`, and 46/48 until ADR-073 added `entry.create_batch`, all
/// on 2026-09-24; 47/49 until ADR-076 added `maintenance.rotate_root`, and 48/50
/// (raw 51/53) until ADR-078 added `entry.get` and the four `field.*` ops, and
/// 53/55 until ADR-087 added `util.generate`, and 54/56 until ADR-090 added
/// `vault.approval_get`.)
fn top_level_arms(source: &str) -> Vec<(String, String)> {
    const INDENT: &str = "        \""; // the `match op {` arms in `dispatch`
    let lines: Vec<&str> = source.lines().collect();
    let mut starts = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let Some(rest) = line.strip_prefix(INDENT) else {
            continue;
        };
        let Some(close) = rest.find('"') else {
            continue;
        };
        if rest[close + 1..].trim_start().starts_with("=>") {
            starts.push((i, rest[..close].to_string()));
        }
    }
    starts
        .iter()
        .enumerate()
        .map(|(k, (i, name))| {
            let end = starts.get(k + 1).map_or(lines.len(), |(j, _)| *j);
            (name.clone(), lines[*i..end].join("\n"))
        })
        .collect()
}

/// Every key an arm reads: `params["k"]` and `params.get("k")`, each tagged
/// with whether the arm refuses the request without it (`ok_or_else` /
/// `is required` in the same statement).
fn params_read_by(body: &str) -> Vec<(String, bool)> {
    // rustfmt breaks a long chain as `params\n    .get("rebuildRegistry")`;
    // join `params` to a following `.` across any whitespace first, or that
    // read is invisible (it was, the first time this guard ran).
    let mut body_joined = String::with_capacity(body.len());
    let mut rest = body;
    while let Some(at) = rest.find("params") {
        body_joined.push_str(&rest[..at + "params".len()]);
        rest = &rest[at + "params".len()..];
        let trimmed = rest.trim_start();
        if trimmed.starts_with('.') {
            rest = trimmed;
        }
    }
    body_joined.push_str(rest);
    let body = body_joined.as_str();

    let mut found: Vec<(String, bool)> = Vec::new();
    for pattern in ["params[\"", "params.get(\""] {
        let mut rest = body;
        while let Some(at) = rest.find(pattern) {
            rest = &rest[at + pattern.len()..];
            let Some(close) = rest.find('"') else { break };
            let key = rest[..close].to_string();
            let statement = &rest[..rest.find(';').unwrap_or(rest.len())];
            // `is required".` — the exact tail of the broker's unconditional
            // refusal message. Not a bare `is required`: doctor's
            // `"params.passphrase is required for rebuildRegistry"` is
            // conditional, and the bridge rightly keeps that one optional.
            let required = statement.contains("ok_or_else") || statement.contains("is required\".");
            match found.iter_mut().find(|(k, _)| *k == key) {
                Some(entry) => entry.1 |= required,
                None => found.push((key, required)),
            }
        }
    }
    found
}

/// Keys the bridge sends that the broker's arm does not read **yet**, each
/// with the reason it is sent anyway. Anything not listed here and not read
/// by the arm fails the build: a param the broker ignores is a UI bug in
/// waiting — the screen believes it said something the vault never heard.
const FORWARD_DECLARED: &[(&str, &str, &str)] = &[(
    "audit.get",
    "id",
    "the positive path needs presence, which no transport can attest yet (ADR-047), so \
     the arm refuses before reading anything — sent so the call site is already right",
)];

#[test]
fn the_bridge_covers_every_op_the_broker_dispatches_and_nothing_else() {
    let ops_rs = read("crates/brokerd/src/ops.rs");
    let arms = top_level_arms(&ops_rs);
    let mut dispatched: Vec<&str> = arms.iter().map(|(n, _)| n.as_str()).collect();
    dispatched.sort_unstable();
    dispatched.dedup();
    assert_eq!(
        dispatched.len(),
        55,
        "parsed {} distinct top-level arms out of ops.rs, expected the 55 that \
         tools/corpus_check.py::broker_ops reports — either the broker grew an op (wire it, \
         then update this number and that tool's expectation together) or this parser broke",
        dispatched.len()
    );
    // The raw-arm miscount, pinned so nobody re-derives 54 as the op count from this file.
    assert_eq!(
        match_arm_labels(&ops_rs).len(),
        56,
        "55 ops + 1 nested entry.undo arm (entry.remove; the multi-pattern entry.rotate | \
         field.* arm has no `=>` after its first label and is not counted)"
    );

    let bridged: Vec<&str> = desktop_lib::commands::bridged().map(|b| b.op).collect();
    let unbridged: Vec<&&str> = dispatched
        .iter()
        .filter(|op| !bridged.contains(op))
        .collect();
    let phantom: Vec<&&str> = bridged
        .iter()
        .filter(|op| !dispatched.contains(op))
        .collect();
    assert!(
        unbridged.is_empty(),
        "credmgrd dispatches ops no invoke() command reaches: {unbridged:?}\n\
         Add a row to bridge_ops! in src/commands.rs (Phase 9's exit gate is 40 of 40)."
    );
    assert!(
        phantom.is_empty(),
        "the bridge sends ops credmgrd's dispatcher does not handle: {phantom:?}"
    );
}

#[test]
fn every_param_the_bridge_sends_is_one_the_broker_reads_and_every_required_one_is_sent() {
    let ops_rs = read("crates/brokerd/src/ops.rs");
    let arms = top_level_arms(&ops_rs);
    let mut problems = Vec::new();

    for b in desktop_lib::commands::bridged() {
        let body = &arms
            .iter()
            .find(|(n, _)| n == b.op)
            .unwrap_or_else(|| panic!("no arm for {}", b.op))
            .1;
        let read_by_arm = params_read_by(body);

        for (key, _) in b.params {
            let read = read_by_arm.iter().any(|(k, _)| k == key);
            let declared = FORWARD_DECLARED
                .iter()
                .any(|(op, k, _)| *op == b.op && k == key);
            if !read && !declared {
                problems.push(format!(
                    "{} sends params.{key}, which the {} arm never reads",
                    b.command, b.op
                ));
            }
            if read && declared {
                problems.push(format!(
                    "{}/{key} is in FORWARD_DECLARED but the arm now reads it — remove the entry",
                    b.op
                ));
            }
        }
        for (key, required) in &read_by_arm {
            let sent = b.params.iter().find(|(k, _)| k == key);
            match sent {
                None => problems.push(format!(
                    "the {} arm reads params.{key}, which {} can never send",
                    b.op, b.command
                )),
                Some((_, false)) if *required => problems.push(format!(
                    "the {} arm refuses without params.{key}, but {} makes it optional",
                    b.op, b.command
                )),
                _ => {}
            }
        }
    }
    assert!(
        problems.is_empty(),
        "bridge params drifted from ops.rs:\n{}",
        problems.join("\n")
    );
}

#[test]
fn every_bridged_command_is_registered_with_tauri() {
    // A command missing from `generate_handler!` compiles, passes every test
    // that drives its `*_at` core, and is then unreachable from `invoke()` at
    // runtime. Nothing but this read can see that.
    let lib_rs = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs"))
        .expect("read src/lib.rs");
    let handler = lib_rs
        .split("generate_handler![")
        .nth(1)
        .and_then(|s| s.split("])").next())
        .expect("lib.rs still calls generate_handler!");
    let missing: Vec<&str> = desktop_lib::commands::bridged()
        .map(|b| b.command)
        .chain(
            desktop_lib::commands::SHELL_COMMANDS
                .iter()
                .map(|s| s.command),
        )
        .filter(|c| !handler.contains(&format!("commands::{c},")))
        .collect();
    assert!(
        missing.is_empty(),
        "not registered in generate_handler!: {missing:?}"
    );

    // …and the reverse: nothing is registered that the tables do not describe,
    // so a command added to `generate_handler!` alone (the scaffold's `greet`
    // was exactly that) cannot sit there invisible to every other guard.
    let known: Vec<&str> = desktop_lib::commands::bridged()
        .map(|b| b.command)
        .chain(
            desktop_lib::commands::SHELL_COMMANDS
                .iter()
                .map(|s| s.command),
        )
        .collect();
    let registered: Vec<&str> = handler
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with("//"))
        .flat_map(|l| l.split(','))
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    let undescribed: Vec<&&str> = registered
        .iter()
        .filter(|r| {
            let name = r.rsplit("::").next().unwrap_or(r);
            !known.contains(&name)
        })
        .collect();
    assert!(
        undescribed.is_empty(),
        "registered in generate_handler! but described by neither bridged() nor SHELL_COMMANDS: \
         {undescribed:?}"
    );
    assert_eq!(
        registered.len(),
        known.len(),
        "generate_handler! registers {} commands, the tables describe {}",
        registered.len(),
        known.len()
    );
}

#[test]
fn the_shell_commands_that_reach_the_broker_send_params_the_broker_reads() {
    // `entry_copy` wraps `entry.reveal`. It is not in `bridged()` (its name is
    // not the op's), so the param guard above never sees it; this is the same
    // check for the shell's own table.
    let ops_rs = read("crates/brokerd/src/ops.rs");
    let arms = top_level_arms(&ops_rs);
    let mut problems = Vec::new();
    for s in desktop_lib::commands::SHELL_COMMANDS {
        let Some(op) = s.wraps_op else {
            assert!(
                s.op_params.is_empty(),
                "{} wraps no op but lists op params",
                s.command
            );
            continue;
        };
        let body = &arms
            .iter()
            .find(|(n, _)| n == op)
            .unwrap_or_else(|| panic!("{} wraps {op}, which ops.rs does not dispatch", s.command))
            .1;
        let read_by_arm = params_read_by(body);
        for key in s.op_params {
            if !read_by_arm.iter().any(|(k, _)| k == key) {
                problems.push(format!(
                    "{} sends params.{key}, which the {op} arm never reads",
                    s.command
                ));
            }
        }
        for (key, required) in &read_by_arm {
            if *required && !s.op_params.contains(&key.as_str()) {
                problems.push(format!(
                    "the {op} arm refuses without params.{key}, which {} never sends",
                    s.command
                ));
            }
        }
    }
    assert!(
        problems.is_empty(),
        "shell commands drifted from ops.rs:\n{}",
        problems.join("\n")
    );
}

#[test]
fn the_shell_commands_are_named_distinctly_from_every_broker_op_command() {
    // A shell command named like a bridged one would be two commands under one
    // `invoke()` name, and Tauri would keep whichever registered last.
    for s in desktop_lib::commands::SHELL_COMMANDS {
        assert!(
            !desktop_lib::commands::bridged().any(|b| b.command == s.command),
            "{} is both a shell command and a bridged op command",
            s.command
        );
    }
}

#[test]
fn the_socket_path_rule_still_matches_crates_store() {
    let paths_rs = read("crates/store/src/paths.rs");

    assert!(
        paths_rs.contains(&format!("join(\"{RUN_DIR_NAME}\")")),
        "crates/store no longer builds its run directory as join(\"{RUN_DIR_NAME}\") — \
         src-tauri/src/vault_paths.rs copies that rule and must be updated with it"
    );
    assert!(
        paths_rs.contains(&format!("join(\"{SOCKET_FILE_NAME}\")")),
        "the broker socket is no longer named {SOCKET_FILE_NAME:?} in crates/store — \
         src-tauri/src/vault_paths.rs still thinks it is"
    );
    assert!(
        paths_rs.contains(&format!("\"{VAULT_DIR_ENV}\"")),
        "{VAULT_DIR_ENV} is no longer the vault override in crates/store — \
         src-tauri/src/vault_paths.rs still honours it"
    );

    // `run_socket()` must remain "run_dir() + the socket name" rather than
    // acquiring an override of its own; the bridge assumes the vault dir is
    // the only variable in the path.
    let run_socket = paths_rs
        .split("pub fn run_socket")
        .nth(1)
        .expect("crates/store still defines run_socket()");
    let body = &run_socket[..run_socket.find('}').unwrap_or(run_socket.len())];
    assert!(
        body.contains("run_dir()") && body.contains(SOCKET_FILE_NAME),
        "run_socket() is no longer <vault>/{RUN_DIR_NAME}/{SOCKET_FILE_NAME}: {body}"
    );
    assert!(
        !body.contains("env::var"),
        "run_socket() has acquired its own environment override; \
         src-tauri resolves the socket assuming the vault dir is the only variable"
    );
}

#[test]
fn the_per_platform_vault_defaults_still_match_crates_store() {
    let paths_rs = read("crates/store/src/paths.rs");
    let default_dir = paths_rs
        .split("pub fn default_vault_dir")
        .nth(1)
        .expect("crates/store still defines default_vault_dir()");

    for expected in [
        "Library",
        "Application Support",
        "APPDATA",
        "XDG_DATA_HOME",
        ".local",
        "share",
        "credmgr",
    ] {
        assert!(
            default_dir.contains(expected),
            "default_vault_dir() no longer mentions {expected:?}; \
             src-tauri/src/vault_paths.rs::vault_dir_from mirrors its branch table"
        );
    }
}
