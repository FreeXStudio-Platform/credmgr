//! Every MCP tool's advertised input schema, held against the broker arm it
//! actually calls — `crates/brokerd/src/ops.rs`, read off disk.
//!
//! A tool is a thin, verbatim pass-through (`tools::call_tool`): the
//! agent's `arguments` become the op's `params` unchanged. So an advertised
//! property the arm never reads is a parameter the agent believes it sent
//! and the vault never heard, and a key the arm requires but the schema
//! omits (or marks optional) is a call that can only ever fail. Both
//! happened: `credmgr_search` advertised `query` while `search` reads
//! `term`, and `credmgr_list` advertised `node` as optional while
//! `entry.list` refuses without it — every agent search, and every list
//! that took the advertised default, was refused as `malformed_request`
//! (found 2026-09-24, gap G-14). The desktop bridge carries the same
//! guard (`apps/desktop/src-tauri/tests/drift_guards.rs`).

use std::path::Path;

use credmgr_mcp::tools::registry;

fn ops_rs() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../brokerd/src/ops.rs");
    std::fs::read_to_string(path).expect("read crates/brokerd/src/ops.rs")
}

/// The body of `op`'s top-level dispatch arm.
fn arm_body(source: &str, op: &str) -> String {
    let lines: Vec<&str> = source.lines().collect();
    let is_arm = |line: &str| {
        line.strip_prefix("        \"")
            .and_then(|rest| rest.find('"').map(|c| (rest, c)))
            .is_some_and(|(rest, c)| rest[c + 1..].trim_start().starts_with("=>"))
    };
    let start = lines
        .iter()
        .position(|l| l.starts_with(&format!("        \"{op}\" =>")))
        .unwrap_or_else(|| panic!("no top-level arm for {op} in ops.rs"));
    let end = lines[start + 1..]
        .iter()
        .position(|l| is_arm(l))
        .map_or(lines.len(), |i| start + 1 + i);
    lines[start..end].join("\n")
}

/// `(key, required)` for every `params["k"]` / `params.get("k")` in `body`.
fn params_read(body: &str) -> Vec<(String, bool)> {
    let joined = {
        let mut out = String::new();
        let mut rest = body;
        while let Some(at) = rest.find("params") {
            out.push_str(&rest[..at + 6]);
            rest = &rest[at + 6..];
            let trimmed = rest.trim_start();
            if trimmed.starts_with('.') {
                rest = trimmed;
            }
        }
        out.push_str(rest);
        out
    };
    let mut found: Vec<(String, bool)> = Vec::new();
    for pattern in ["params[\"", "params.get(\""] {
        let mut rest = joined.as_str();
        while let Some(at) = rest.find(pattern) {
            rest = &rest[at + pattern.len()..];
            let Some(close) = rest.find('"') else { break };
            let key = rest[..close].to_string();
            let statement = &rest[..rest.find(';').unwrap_or(rest.len())];
            let required = statement.contains("ok_or_else") || statement.contains("is required\".");
            match found.iter_mut().find(|(k, _)| *k == key) {
                Some(e) => e.1 |= required,
                None => found.push((key, required)),
            }
        }
    }
    found
}

#[test]
fn every_tool_schema_matches_the_params_its_op_reads() {
    let source = ops_rs();
    let mut problems = Vec::new();
    for tool in registry() {
        let schema = (tool.input_schema)();
        let advertised: Vec<String> = schema["properties"]
            .as_object()
            .map(|p| p.keys().cloned().collect())
            .unwrap_or_default();
        let required: Vec<String> = schema["required"]
            .as_array()
            .map(|r| {
                r.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        let read = params_read(&arm_body(&source, tool.op));

        for key in &advertised {
            if !read.iter().any(|(k, _)| k == key) {
                problems.push(format!(
                    "{} advertises `{key}`, which the {} arm never reads",
                    tool.name, tool.op
                ));
            }
        }
        for (key, arm_requires) in &read {
            if !advertised.contains(key) {
                problems.push(format!(
                    "the {} arm reads `{key}`, which {} does not advertise",
                    tool.op, tool.name
                ));
            } else if *arm_requires && !required.contains(key) {
                problems.push(format!(
                    "the {} arm refuses without `{key}`, but {} marks it optional",
                    tool.op, tool.name
                ));
            }
        }
    }
    assert!(
        problems.is_empty(),
        "MCP schemas drifted from ops.rs:\n{}",
        problems.join("\n")
    );
}
