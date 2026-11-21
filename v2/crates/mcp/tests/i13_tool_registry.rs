//! I-13 — `docs/13_TEST_PLAN.md §3`: "Enumerate every exported MCP tool.
//! None can create a grant, return a TOTP seed, read orphan data, alter
//! node policy, or purge audit — asserted over the tool list, so a newly
//! added tool fails the test." Deferred by `crates/brokerd/tests/isolation.rs`
//! until this crate had a real registry to enumerate (its own module doc:
//! "I-13 needs the MCP tool registry, unbuilt until Phase 4") — this file
//! is that enumeration, now that one exists.
//!
//! Walks `credmgr_mcp::tools::registry()` directly (the actual, live list
//! `tools/list` serves — not a hand-copied shadow of it) against
//! `10_API_AND_MCP.md §3.2`'s forbidden list, restated as
//! `credmgr_mcp::tools::FORBIDDEN_OPS`.

use credmgr_mcp::tools::{registry, FORBIDDEN_OPS};

/// `10_API_AND_MCP.md §3.2`'s items, phrased as substrings a tool's *name*
/// must never contain — a second, independent check from `FORBIDDEN_OPS`
/// (which catches a forbidden *op*), because a future tool could call a
/// permitted op under a misleading name, or vice versa; neither check alone
/// is the whole guarantee.
const FORBIDDEN_NAME_FRAGMENTS: &[&str] = &[
    "grant",
    "orphan",
    "totp_seed",
    "policy",
    "agent_access",
    "reparent",
    "purge",
    "recovery_window",
    "force_purge",
    // ADR-164: no tool issues, rotates, lists or revokes an agent token.
    "token",
];

#[test]
fn no_registered_tool_maps_to_a_forbidden_op() {
    for tool in registry() {
        assert!(
            !FORBIDDEN_OPS.contains(&tool.op),
            "tool {} maps to forbidden op {} (10_API_AND_MCP.md §3.2)",
            tool.name,
            tool.op
        );
    }
}

#[test]
fn no_registered_tool_name_contains_a_forbidden_fragment() {
    for tool in registry() {
        for fragment in FORBIDDEN_NAME_FRAGMENTS {
            assert!(
                !tool.name.contains(fragment),
                "tool name {} contains the forbidden fragment {fragment:?}",
                tool.name
            );
        }
    }
}

/// ADR-076: replacing the root key is human + 2FA + presence only. It is not
/// merely gated for agents — it is *absent*: on the forbidden list, so a tool
/// that ever maps to it fails the first test above, and in no tool's `op`.
#[test]
fn rotate_root_is_on_the_forbidden_list_and_no_tool_maps_to_it() {
    assert!(
        FORBIDDEN_OPS.contains(&"maintenance.rotate_root"),
        "maintenance.rotate_root must be named in FORBIDDEN_OPS (10_API_AND_MCP.md §3.2)"
    );
    assert!(
        registry().iter().all(|t| t.op != "maintenance.rotate_root"),
        "no MCP tool may ever call maintenance.rotate_root"
    );
    assert!(
        registry().iter().all(|t| !t.name.contains("rotate_root")),
        "no MCP tool may even be named for it"
    );
}

/// ADR-163: the recovery-code unlock is absent from MCP, like the rotation it performs: on the forbidden list,
/// mapped by no tool, and no tool is named for it.
#[test]
fn the_recovery_code_unlock_is_on_the_forbidden_list_and_no_tool_maps_to_it() {
    assert!(
        FORBIDDEN_OPS.contains(&"vault.recover"),
        "vault.recover must be named in FORBIDDEN_OPS (10_API_AND_MCP.md §3.2)"
    );
    assert!(registry().iter().all(|t| t.op != "vault.recover"));
    assert!(registry()
        .iter()
        .all(|t| !t.name.contains("recover") && !t.description.contains("recovery code")));
}

/// ADR-165: the machine lock's three ops are absent from MCP: on the forbidden list, mapped by no tool, and no
/// tool is named for them.
#[test]
fn the_machine_lock_ops_are_on_the_forbidden_list_and_no_tool_maps_to_them() {
    for op in ["keystore.status", "keystore.bind", "keystore.unbind"] {
        assert!(
            FORBIDDEN_OPS.contains(&op),
            "{op} must be named in FORBIDDEN_OPS (10_API_AND_MCP.md §3.2)"
        );
        assert!(registry().iter().all(|t| t.op != op), "{op} maps to a tool");
    }
    assert!(registry()
        .iter()
        .all(|t| !t.op.starts_with("keystore.") && !t.name.contains("keystore")));
}

/// The registry is not empty and not accidentally trivial — a would-be
/// regression where every tool silently failed to register (e.g. an empty
/// `vec![]` slipped in during a refactor) would make the two tests above
/// vacuously pass, which is worse than useless for a security gate.
#[test]
fn the_registry_actually_has_tools_in_it() {
    assert!(!registry().is_empty());
    assert!(registry().iter().any(|t| t.name == "credmgr_whoami"));
}

/// `07_TWO_FACTOR.md §8` item 6 (the one item `tests/phase5_gate.rs`
/// explicitly defers here): "`totp.seed` is unreachable from the MCP
/// transport, for every scope and every grant." No amount of scope or
/// grant can matter if the *tool* was never registered in the first place
/// — that is the actual guarantee this test makes, and it is
/// scope-independent by construction (a registry has no notion of caller
/// scope at all).
#[test]
fn totp_seed_op_never_appears_in_the_registry_under_any_tool_name() {
    assert!(
        registry().iter().all(|t| t.op != "totp.seed"),
        "no tool may ever call totp.seed — 10_API_AND_MCP.md §3.2, 07_TWO_FACTOR.md §6"
    );
}

/// ADR-078 (field model): the registry is **exactly** this reviewed set — every
/// tool name with the one broker op it maps to. Adding a tool, or pointing one at
/// another op, fails here until a human edits this list on purpose; that is the
/// point of I-13 ("a newly added tool fails the test"). The four field tools
/// (`credmgr_get_metadata`, `credmgr_field_add`, `credmgr_field_update`,
/// `credmgr_field_remove`) are the whole of what the field model gives an agent:
/// each is no wider than `credmgr_update`/`credmgr_remove`, which agents already
/// hold (F2).
const REVIEWED_TOOLS: &[(&str, &str)] = &[
    ("credmgr_whoami", "whoami"),
    ("credmgr_list", "entry.list"),
    ("credmgr_search", "search"),
    ("credmgr_get", "entry.reveal"),
    ("credmgr_get_metadata", "entry.get"),
    ("credmgr_notes_read", "notes.read"),
    ("credmgr_create", "entry.create"),
    ("credmgr_update", "entry.update"),
    ("credmgr_rotate", "entry.rotate"),
    ("credmgr_field_add", "field.add"),
    ("credmgr_field_update", "field.update"),
    ("credmgr_field_remove", "field.remove"),
    ("credmgr_remove", "entry.remove"),
    ("credmgr_undo", "entry.undo"),
    ("credmgr_totp_code", "totp.code"),
    ("credmgr_recent_changes", "audit.tail"),
    // ADR-155: the switchboard. settings.request_list and settings.request_decide stay owner-only (FORBIDDEN_OPS).
    ("credmgr_settings_list", "settings.list"),
    ("credmgr_settings_get", "settings.get"),
    ("credmgr_settings_set", "settings.set"),
    ("credmgr_settings_revert", "settings.revert"),
    ("credmgr_settings_request", "settings.request_get"),
    ("credmgr_kb", "settings.kb"),
];

#[test]
fn the_registry_is_exactly_the_reviewed_set_of_tools() {
    let mut live: Vec<(&str, &str)> = registry().iter().map(|t| (t.name, t.op)).collect();
    live.sort_unstable();
    let mut reviewed: Vec<(&str, &str)> = REVIEWED_TOOLS.to_vec();
    reviewed.sort_unstable();
    assert_eq!(
        live, reviewed,
        "the MCP registry changed: review the new tool against 10_API_AND_MCP.md §3.2, then \
         add it to REVIEWED_TOOLS in this file"
    );
    assert_eq!(registry().len(), 22);
}

/// ADR-174 (2): an agent may read a project's note through MCP and never write one. The one notes tool maps to
/// `notes.read`; no tool maps to `notes.write`; and the read tool's description tells the model the note is
/// untrusted user content.
#[test]
fn agents_read_notes_through_mcp_but_never_write_them() {
    let tools = registry();
    assert!(tools.iter().all(|t| t.op != "notes.write"));
    assert!(tools.iter().all(|t| t.name != "credmgr_notes_write"));
    let notes: Vec<_> = tools
        .iter()
        .filter(|t| t.op.starts_with("notes."))
        .collect();
    assert_eq!(notes.len(), 1);
    assert_eq!(notes[0].name, "credmgr_notes_read");
    assert_eq!(notes[0].op, "notes.read");
    assert!(
        notes[0].description.contains("UNTRUSTED USER CONTENT"),
        "the tool must label the note untrusted"
    );
}

/// ADR-155: the knowledge base names exactly the tools the server registers, so a model reading it can never be told
/// about a tool that does not exist or miss one that does.
#[test]
fn the_kb_lists_exactly_the_registered_tools() {
    let mut live: Vec<&str> = registry().iter().map(|t| t.name).collect();
    live.sort_unstable();
    let mut kb: Vec<&str> = credmgr_core::settings::MCP_TOOL_NAMES.to_vec();
    kb.sort_unstable();
    assert_eq!(
        live, kb,
        "update credmgr_core::settings::MCP_TOOL_NAMES and regenerate docs/LLM_KB.md"
    );
}

/// ADR-155: an agent can never decide or list the owner's waiting setting requests.
#[test]
fn no_tool_decides_a_setting_request() {
    for op in ["settings.request_decide", "settings.request_list"] {
        assert!(FORBIDDEN_OPS.contains(&op));
        assert!(registry().iter().all(|t| t.op != op), "{op}");
    }
}

/// `field.reorder` is presentation, not something an agent needs: it is neither
/// a tool nor behind another tool's name (ADR-078 D11). Every `field.*` tool is
/// one of the three the field model allows.
#[test]
fn field_reorder_is_not_an_agent_tool_and_only_three_field_tools_exist() {
    assert!(
        registry().iter().all(|t| t.op != "field.reorder"),
        "no MCP tool may call field.reorder"
    );
    assert!(
        registry().iter().all(|t| !t.name.contains("reorder")),
        "no MCP tool may be named for reordering"
    );
    let mut field_ops: Vec<&str> = registry()
        .iter()
        .filter(|t| t.op.starts_with("field."))
        .map(|t| t.op)
        .collect();
    field_ops.sort_unstable();
    assert_eq!(field_ops, ["field.add", "field.remove", "field.update"]);
}

/// None of the ops the field model made reachable is on the forbidden list —
/// `FORBIDDEN_OPS` is unchanged by ADR-078, and the three field writes plus
/// `entry.get` are allowed on purpose. (If a future ADR forbids one, this test and
/// the registry must change together, deliberately.)
#[test]
fn the_field_model_ops_are_allowed_and_the_forbidden_list_has_no_field_op() {
    for op in ["entry.get", "field.add", "field.update", "field.remove"] {
        assert!(
            !FORBIDDEN_OPS.contains(&op),
            "{op} is an agent-reachable op under ADR-078; it must not be on the forbidden list"
        );
    }
    assert!(
        FORBIDDEN_OPS.iter().all(|op| !op.starts_with("field.")),
        "the forbidden list names no field op"
    );
    // The seed stays unreachable whatever `field` a caller names.
    assert!(FORBIDDEN_OPS.contains(&"totp.seed"));
}

/// ADR-148 (P3): the 2.0 owner ops are on the forbidden list, and no tool maps to one.
#[test]
fn the_owner_ops_added_in_two_point_oh_are_forbidden() {
    for op in [
        "node.rekey",
        "orphan.destroy",
        "node.export",
        "node.gate_enroll_begin",
        "node.gate_enroll_confirm",
        "node.gate_verify",
        "node.gate_remove",
    ] {
        assert!(FORBIDDEN_OPS.contains(&op), "{op} must be forbidden");
        assert!(
            registry().iter().all(|t| t.op != op),
            "no tool may map to {op}"
        );
    }
}

/// ADR-164: tokens are how an agent authenticates, never something it can make. Every `agent.*` op is on the
/// forbidden list and no tool maps to the namespace at all.
#[test]
fn no_tool_reaches_the_agent_token_ops() {
    for op in [
        "agent.token_issue",
        "agent.token_status",
        "agent.token_rotate",
        "agent.token_revoke",
    ] {
        assert!(FORBIDDEN_OPS.contains(&op), "{op} must be on FORBIDDEN_OPS");
    }
    for tool in registry() {
        assert!(
            !tool.op.starts_with("agent."),
            "tool {} maps to {}, an agent-token op",
            tool.name,
            tool.op
        );
    }
}

/// ADR-168: every `merge.*` op is the owner's alone (a suggestion says which entries share a value), and
/// ADR-167: no tool sets tags (the broker refuses agents, as for aliases).
#[test]
fn every_merge_op_is_forbidden_and_no_tool_sets_tags() {
    for op in [
        "merge.suggestions",
        "merge.apply",
        "merge.auto",
        "merge.auto_all",
        "merge.dismiss",
        "merge.undismiss",
        "merge.dismissed_list",
        "merge.restore_all",
    ] {
        assert!(FORBIDDEN_OPS.contains(&op), "{op} must be forbidden");
        assert!(
            registry().iter().all(|t| t.op != op),
            "no tool may map to {op}"
        );
    }
    assert!(registry()
        .iter()
        .all(|t| t.op != "entry.tag_set" && t.op != "entry.alias"));
}

/// Wiring audit 2026-11-20: the ops the docs already call never-an-agent's but `FORBIDDEN_OPS` did not name, so a
/// tool mapping to one would have passed I-13. `10_API_AND_MCP.md` §3.2 (`orphan.list`), §4.2a (presence and
/// Touch ID, "none an MCP tool"), §4.2b (`session.confirm`), ADR-088/ADR-173 (deciding a held request) and §1.4
/// (the unredacted `audit.get`).
#[test]
fn orphan_list_presence_confirmation_approval_decisions_and_the_full_audit_record_are_forbidden() {
    for op in [
        "orphan.list",
        "orphan.reveal",
        "presence.challenge",
        "presence.enrol",
        "presence.status",
        "presence.unenrol",
        "device.enrol",
        "device.remove",
        "session.confirm",
        "vault.approval_decide",
        "audit.get",
    ] {
        assert!(FORBIDDEN_OPS.contains(&op), "{op} must be forbidden");
        assert!(
            registry().iter().all(|t| t.op != op),
            "no tool may map to {op}"
        );
    }
}

/// The broker's operations as `docs/help/ops.json` classifies them (`tools/gen_help.py` holds its key set equal to
/// the ops `ops.rs` dispatches): op name → `agent_reach`.
fn ops_json_reach() -> Vec<(String, String)> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/help/ops.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
    let doc: serde_json::Value = serde_json::from_str(&text).expect("ops.json is JSON");
    let ops = doc["ops"].as_object().expect("ops.json has an ops map");
    assert!(
        ops.len() > 100,
        "ops.json lists every broker op ({} found)",
        ops.len()
    );
    ops.iter()
        .map(|(op, row)| {
            let reach = row["agent_reach"]
                .as_str()
                .unwrap_or_else(|| panic!("ops.json {op}: agent_reach missing"))
                .to_string();
            (op.clone(), reach)
        })
        .collect()
}

/// Wiring audit Q-3: `FORBIDDEN_OPS` names **every** op the broker reserves for a person — each op `ops.json` marks
/// `human_only` (needs `admin`, the owner's login, the `notes` capability or presence; refused to every agent scope)
/// — so I-13's "no tool maps to a forbidden op" covers all of them, and a new human-only op that is not added here
/// fails this test instead of passing unguarded. The only way out is a reviewed tool for it (none exists: an op a
/// tool maps to would also have to stop being `human_only`). The converse holds too: a forbidden op that is a real
/// broker op is `human_only` (`tools/gen_help.py --check` enforces it as well). The old placeholder names (no such
/// op is dispatched) stay listed, harmlessly, as §3.2 records them.
#[test]
fn the_forbidden_list_names_every_human_only_op() {
    let reach = ops_json_reach();
    let tool_ops: Vec<&str> = registry().iter().map(|t| t.op).collect();
    let missing: Vec<&str> = reach
        .iter()
        .filter(|(op, r)| r == "human_only" && !tool_ops.contains(&op.as_str()))
        .map(|(op, _)| op.as_str())
        .filter(|op| !FORBIDDEN_OPS.contains(op))
        .collect();
    assert!(
        missing.is_empty(),
        "human-only ops missing from FORBIDDEN_OPS (add them in crates/mcp/src/tools.rs): {missing:?}"
    );
    for op in FORBIDDEN_OPS {
        if let Some((_, r)) = reach.iter().find(|(name, _)| name == op) {
            assert_eq!(
                r, "human_only",
                "{op} is forbidden to agents, so ops.json must class it human_only"
            );
        }
    }
    // No tool maps to a human-only op at all (a tool is an agent's way in).
    for tool in registry() {
        assert!(
            reach
                .iter()
                .all(|(op, r)| op != tool.op || r != "human_only"),
            "tool {} maps to {}, which ops.json marks human_only",
            tool.name,
            tool.op
        );
    }
}

/// Wiring audit Q-3: the fifteen human-only ops the audit found missing from the list, named one by one.
#[test]
fn the_fifteen_human_only_ops_the_wiring_audit_found_unlisted_are_forbidden() {
    for op in [
        "node.seal",
        "node.restore",
        "vault.node_lock",
        "vault.node_unlock",
        "vault.approval_get",
        "vault.anomalies_ack",
        "vault.pending_accept",
        "vault.pending_discard",
        "audit.report",
        "entry.expiring",
        "entry.history",
        "grant.list",
        "entry.alias",
        "entry.tag_set",
        "notes.write",
    ] {
        assert!(FORBIDDEN_OPS.contains(&op), "{op} must be forbidden");
        assert!(
            registry().iter().all(|t| t.op != op),
            "no tool may map to {op}"
        );
    }
}
