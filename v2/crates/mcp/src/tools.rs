//! The MCP tool registry — `docs/10_API_AND_MCP.md §3.1` — the "live tool
//! registry" `docs/13_TEST_PLAN.md` I-13 enumerates. **This is the whole
//! anti-regression point of this module:** I-13 walks [`registry`] and
//! asserts no entry's `op` is on `§3.2`'s forbidden list, so a future
//! session that adds a tool calling `grant.create` or `orphan.reveal` gets
//! a red test naming exactly why, rather than a silent capability leak.
//!
//! **Every tool here has a real backing op in `credmgr-brokerd` today.**
//! `§3.1` names a couple more this crate does not expose —
//! `credmgr_notes_read`/`credmgr_notes_write` (node notes are human-only by
//! design, ADR-072) — so they are not registered: a tool for an op an agent may
//! not use would be a stub, and this registry lists only what a caller can
//! actually complete.
//! `credmgr_rotate`/`credmgr_remove` were added in Session 12, once
//! `entry.rotate`/`entry.remove` (ADR-048, Session 11) existed to back them.
//! `credmgr_recent_changes` was added once `audit.tail` existed — its own
//! op is `Origin`-aware and returns the redacted shape documented in
//! `10 §3.1` for exactly this (an agent) caller by construction, not
//! because this tool asks it to. `credmgr_undo` was added in the
//! backend-finish pass (ADR-055), once `entry.undo` existed to back it —
//! the changelog-id-addressed op ADR-048 named and deferred, now real.
//!
//! **Multi-field entries (ADR-078).** `credmgr_get_metadata` (`entry.get`:
//! field ids, labels, types and masking — never a value), `credmgr_field_add`,
//! `credmgr_field_update` and `credmgr_field_remove` joined the registry with
//! the field model; each is no wider than what `credmgr_update` and
//! `credmgr_remove` already grant (the `update` capability, the vault and node
//! unlocked, generation-checked, undoable through `credmgr_undo`). **There is
//! no `field.reorder` tool:** reordering is presentation, not something an agent
//! needs, and a tool nobody needs is a tool nobody has to audit. An agent sends
//! *structure* — a `fields` array — never the `label: value` paste grammar: the
//! broker does not parse that grammar (it is the human paste format, parsed by
//! the CLI and the desktop app, which show the preview).

use serde_json::{json, Value};

use crate::transport::{self, TransportError};

/// One tool this server exposes over MCP's `tools/list`/`tools/call`.
pub struct ToolSpec {
    pub name: &'static str,
    pub description: &'static str,
    /// The exact `credmgr_brokerd::ops::dispatch` operation name this tool
    /// calls — never invented, always a real, already-tested op.
    pub op: &'static str,
    pub input_schema: fn() -> Value,
}

fn no_params_schema() -> Value {
    json!({ "type": "object", "properties": {}, "additionalProperties": false })
}

fn node_entry_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "node": { "type": "string", "description": "Node id." },
            "entry": { "type": "string", "description": "Entry id." },
        },
        "required": ["node", "entry"],
        "additionalProperties": false,
    })
}

/// `entry.list` requires `node`. This schema used to advertise it as
/// optional ("omit to use the caller's own scope"), which the broker never
/// implemented — every call that took the advertised option was refused as
/// malformed (review of 2026-09-24, gap G-14). Now pinned against
/// `ops.rs` by `tests/schemas_match_the_broker.rs`.
fn node_required_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "node": { "type": "string", "description": "Node id — your own is `node` in credmgr_whoami's answer." },
        },
        "required": ["node"],
        "additionalProperties": false,
    })
}

fn search_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "term": { "type": "string", "description": "Search term." },
        },
        "required": ["term"],
        "additionalProperties": false,
    })
}

/// The field types an entry's field can carry — the wire names of
/// `credmgr_core::inference::FieldType`. `tests::the_name_lists_match_core`
/// holds this list to the real enum, variant for variant.
pub const FIELD_TYPE_NAMES: &[&str] = &[
    "password",
    "api-key",
    "private-key",
    "seed-phrase",
    "totp-seed",
    "username",
    "host",
    "port",
    "url",
    "certificate",
    "text",
];

/// The wire names of `credmgr_core::inference::EntryType` (`note-only` is still
/// accepted on input by the broker, but is the old spelling and not advertised).
pub const ENTRY_TYPE_NAMES: &[&str] = &[
    "server",
    "database",
    "api",
    "wallet",
    "login",
    "ssh",
    "certificate",
    "token",
    "totp",
    "env-bundle",
    "note",
    "other",
];

/// The wire names of `credmgr_core::inference::Sensitivity`.
pub const SENSITIVITY_NAMES: &[&str] = &["low", "medium", "high", "critical"];

/// `names` plus the `"auto"` marker that clears a stored override (D6): leaving
/// a key out keeps it, `"auto"` goes back to inferring it, a name sets it.
fn names_or_auto(names: &[&str]) -> Vec<String> {
    names
        .iter()
        .map(|n| (*n).to_string())
        .chain(std::iter::once("auto".to_string()))
        .collect()
}

fn entry_type_property() -> Value {
    json!({
        "type": "string",
        "enum": names_or_auto(ENTRY_TYPE_NAMES),
        "description": "Pin the entry's type. Leave it out to infer it from the fields; \"auto\" clears a pinned type.",
    })
}

fn sensitivity_property() -> Value {
    json!({
        "type": "string",
        "enum": names_or_auto(SENSITIVITY_NAMES),
        "description": "Pin the entry's sensitivity. Leave it out to infer it from the fields; \"auto\" clears a pinned value.",
    })
}

/// One field as a client supplies it (`field.add`, `entry.create`): free text
/// label (empty is allowed), the value verbatim, and optional overrides.
fn field_input_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "label": { "type": "string", "description": "Free text, up to 200 characters, one line (it may be empty). There is no fixed list of labels." },
            "value": { "type": "string", "description": "The value, verbatim — never trimmed." },
            "type": { "type": "string", "enum": FIELD_TYPE_NAMES, "description": "Pin the field's type. Leave it out to infer it from the label and value." },
            "masked": { "type": "boolean", "description": "Pin whether the field is masked on screen. Leave it out to follow the type." },
        },
        "required": ["label", "value"],
        "additionalProperties": false,
    })
}

/// An element of an update/rotate `fields` list: a field that may name an
/// existing field by `id` to keep its identity.
fn field_replace_schema() -> Value {
    let mut schema = field_input_schema();
    schema["properties"]["id"] = json!({
        "type": "string",
        "description": "The id of an existing field (from credmgr_get_metadata) to keep. Leave it out to add a new field.",
    });
    schema
}

fn fields_array(item: Value, description: &str) -> Value {
    json!({
        "type": "array",
        "minItems": 1,
        "items": item,
        "description": description,
    })
}

fn create_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "node": { "type": "string" },
            "name": { "type": "string" },
            "value": { "type": "string", "description": "A single-value entry: give `value` (with an optional `label`) or `fields`, not both." },
            "label": { "type": "string", "description": "The label of `value`, default \"value\". Not allowed beside `fields`." },
            "fields": fields_array(
                field_input_schema(),
                "A multi-field entry: an array of {label, value} objects, in the order to keep. Send structure — the broker does not parse `label: value` text.",
            ),
            "entryType": entry_type_property(),
            "sensitivity": sensitivity_property(),
        },
        "required": ["node", "name"],
        "additionalProperties": false,
    })
}

/// `entry.update` and `entry.rotate` take one body (ADR-078); only the history
/// they keep differs.
fn edit_schema(value_description: &str) -> Value {
    json!({
        "type": "object",
        "properties": {
            "node": { "type": "string" },
            "entry": { "type": "string" },
            "generation": { "type": "integer", "description": "The entry's current generation, for optimistic concurrency (F-9)." },
            "value": { "type": "string", "description": value_description },
            "field": { "type": "string", "description": "With `value`: the id of the field to change. Required when the entry has more than one field." },
            "label": { "type": "string", "description": "With `value`: rename that field too." },
            "fields": fields_array(
                field_replace_schema(),
                "Replace the whole field list. A field with an `id` keeps its identity; fields you leave out are dropped. Cannot be combined with `value`, `field` or `label`.",
            ),
            "entryType": entry_type_property(),
            "sensitivity": sensitivity_property(),
        },
        "required": ["node", "entry", "generation"],
        "additionalProperties": false,
    })
}

fn update_schema() -> Value {
    edit_schema("The new value of one field (the entry's only field, or the one `field` names).")
}

fn rotate_schema() -> Value {
    edit_schema(
        "The new value of one field (the entry's only field, or the one `field` names). The previous ciphertext is retained as history.",
    )
}

fn get_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "node": { "type": "string", "description": "Node id." },
            "entry": { "type": "string", "description": "Entry id." },
            "fieldIds": {
                "type": "array",
                "minItems": 1,
                "items": { "type": "string" },
                "description": "Reveal only these fields (ids from credmgr_get_metadata). Leave it out to reveal every field.",
            },
        },
        "required": ["node", "entry"],
        "additionalProperties": false,
    })
}

fn totp_code_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "node": { "type": "string", "description": "Node id." },
            "entry": { "type": "string", "description": "Entry id." },
            "field": { "type": "string", "description": "The id of the field that holds the seed. Needed only when the entry has several fields, and not exactly one of them is a TOTP seed." },
        },
        "required": ["node", "entry"],
        "additionalProperties": false,
    })
}

fn field_add_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "node": { "type": "string" },
            "entry": { "type": "string" },
            "generation": { "type": "integer", "description": "The entry's current generation, for optimistic concurrency (F-9)." },
            "fields": fields_array(
                field_input_schema(),
                "The fields to add. They are appended — adding never replaces.",
            ),
            "position": { "type": "integer", "minimum": 0, "description": "Insert at this index instead of appending (0 is first)." },
        },
        "required": ["node", "entry", "generation", "fields"],
        "additionalProperties": false,
    })
}

fn field_update_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "node": { "type": "string" },
            "entry": { "type": "string" },
            "generation": { "type": "integer", "description": "The entry's current generation, for optimistic concurrency (F-9)." },
            "field": { "type": "string", "description": "The id of the field to change (from credmgr_get_metadata)." },
            "patch": {
                "type": "object",
                "description": "At least one key. `type` and `masked` take \"auto\" to go back to inferring.",
                "properties": {
                    "label": { "type": "string" },
                    "value": { "type": "string" },
                    "type": {
                        "type": "string",
                        "enum": names_or_auto(FIELD_TYPE_NAMES),
                    },
                    "masked": {
                        "anyOf": [
                            { "type": "boolean" },
                            { "type": "string", "enum": ["auto"] },
                        ],
                    },
                },
                "minProperties": 1,
                "additionalProperties": false,
            },
        },
        "required": ["node", "entry", "generation", "field", "patch"],
        "additionalProperties": false,
    })
}

fn field_remove_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "node": { "type": "string" },
            "entry": { "type": "string" },
            "generation": { "type": "integer", "description": "The entry's current generation, for optimistic concurrency (F-9)." },
            "field": { "type": "string", "description": "The id of the field to remove (from credmgr_get_metadata)." },
        },
        "required": ["node", "entry", "generation", "field"],
        "additionalProperties": false,
    })
}

fn remove_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "node": { "type": "string" },
            "entry": { "type": "string" },
            "generation": { "type": "integer", "description": "The entry's current generation, for optimistic concurrency (F-9)." },
        },
        "required": ["node", "entry", "generation"],
        "additionalProperties": false,
    })
}

fn undo_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "node": { "type": "string" },
            "id": { "type": "string", "description": "The audit record id (from credmgr_recent_changes) naming the rotate, field change or removal to undo." },
            "generation": { "type": "integer", "description": "The entry's current generation, for optimistic concurrency (F-9)." },
            "mode": { "type": "string", "enum": ["replace", "keep-both"], "description": "Only used when undoing a removal and the name has since been reclaimed. Default \"replace\" refuses rather than overwrite." },
        },
        "required": ["node", "id", "generation"],
        "additionalProperties": false,
    })
}

fn recent_changes_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "limit": { "type": "integer", "description": "Max records to return, default 50, capped at 500." },
        },
        "additionalProperties": false,
    })
}

pub fn registry() -> Vec<ToolSpec> {
    vec![
        ToolSpec {
            name: "credmgr_whoami",
            description: "Returns your own node, capabilities, and the nodes you can reach. \
                Call this first and reason about your own boundary instead of discovering it \
                by being denied — it names only nodes you can actually reach, nothing else. \
                You are scoped to one node (resolved from your working directory). You can \
                read that node, its ancestors, Global, and anything explicitly granted. You \
                cannot reach other nodes, and no argument to any tool changes that — if you \
                need something outside your scope, say so and ask the operator.",
            op: "whoami",
            input_schema: no_params_schema,
        },
        ToolSpec {
            name: "credmgr_list",
            description: "Lists entry names and metadata (no values) on a node. Scope-filtered \
                — never returns another node's entries.",
            op: "entry.list",
            input_schema: node_required_schema,
        },
        ToolSpec {
            name: "credmgr_search",
            description: "Searches entry names within your scope. Scope-filtered; a query that \
                only matches outside your scope returns zero results, indistinguishable from a \
                query that matches nothing at all.",
            op: "search",
            input_schema: search_schema,
        },
        ToolSpec {
            name: "credmgr_get",
            description: "Reveals an entry's values. The answer carries `fields` (id, label, \
                value, type, masked for each) and, when exactly one field is returned, `value`. \
                Pass `fieldIds` to reveal only some fields. Subject to the node's two-factor \
                policy and to the vault's lock state.",
            op: "entry.reveal",
            input_schema: get_schema,
        },
        ToolSpec {
            name: "credmgr_get_metadata",
            description: "Describes one entry without revealing it: its type, sensitivity, \
                generation and each field's id, label, type and masking — never a value. Use it \
                to find the field ids the other tools take. Needs the vault and node unlocked \
                (labels are encrypted with the values).",
            op: "entry.get",
            input_schema: node_entry_schema,
        },
        ToolSpec {
            name: "credmgr_create",
            description: "Creates a new entry (a name not already present on the node): one \
                `value`, or a `fields` array of {label, value} objects for several fields. \
                Send structure — the broker does not parse `label: value` text. Works on a \
                locked vault — lands in the pending tray for human review at next unlock.",
            op: "entry.create",
            input_schema: create_schema,
        },
        ToolSpec {
            name: "credmgr_update",
            description: "Modifies an existing entry: `value` replaces one field's value (name \
                the field with `field` when the entry has several), `fields` replaces the whole \
                list. Requires the vault unlocked — a locked-vault write-without-read-first \
                would be credential substitution, not an update.",
            op: "entry.update",
            input_schema: update_schema,
        },
        ToolSpec {
            name: "credmgr_rotate",
            description: "Replaces an entry's value (or its fields) and preserves the previous \
                ciphertext as history. Takes the same body as credmgr_update. Requires the \
                vault unlocked — same policy gate as credmgr_update: a legitimate rotation \
                implies you could have read what you are replacing.",
            op: "entry.rotate",
            input_schema: rotate_schema,
        },
        ToolSpec {
            name: "credmgr_field_add",
            description: "Adds fields to an entry (appended, or inserted at `position`) — it \
                never replaces what is there. The previous state is retained; credmgr_undo \
                reverses it. Requires the vault unlocked.",
            op: "field.add",
            input_schema: field_add_schema,
        },
        ToolSpec {
            name: "credmgr_field_update",
            description: "Changes one field — its label, its value, its type or its masking \
                (`\"auto\"` goes back to inferring a type or masking). The previous state is \
                retained; credmgr_undo reverses it. Requires the vault unlocked.",
            op: "field.update",
            input_schema: field_update_schema,
        },
        ToolSpec {
            name: "credmgr_field_remove",
            description: "Removes one field from an entry; the last field cannot be removed \
                (remove the entry instead). The previous state is retained; credmgr_undo \
                reverses it. Requires the vault unlocked.",
            op: "field.remove",
            input_schema: field_remove_schema,
        },
        ToolSpec {
            name: "credmgr_remove",
            description: "Soft-deletes an entry into a 7-day recovery window. Requires the \
                vault unlocked. The entry stops appearing in credmgr_list/credmgr_search \
                immediately; a human can recover it within the window.",
            op: "entry.remove",
            input_schema: remove_schema,
        },
        ToolSpec {
            name: "credmgr_undo",
            description: "Undoes a rotate, a field change or a removal, addressed by its audit \
                record id (from credmgr_recent_changes) — never by guessing at what changed. Requires the vault \
                unlocked. A removal's undo is only possible within its 7-day recovery window; a \
                rotation's undo has no time limit. This is itself a new, audited action — the \
                original record is never erased or rewritten.",
            op: "entry.undo",
            input_schema: undo_schema,
        },
        ToolSpec {
            name: "credmgr_totp_code",
            description: "Returns the current 6-digit code for a stored TOTP item. On an entry \
                with several fields, name the seed's field with `field` unless exactly one field \
                is a TOTP seed. Never returns the seed itself — there is no tool that does; a \
                leaked code is worth 30 seconds, a leaked seed is worth forever.",
            op: "totp.code",
            input_schema: totp_code_schema,
        },
        ToolSpec {
            name: "credmgr_recent_changes",
            description: "Redacted feed of recent decisions (allow and deny) — id, action, \
                timestamp, actor. Never before/after values, and never the fields an agent \
                caller cannot have (node, decision, detail): the underlying op is always \
                redacted for an agent origin, not merely by this tool's own choice.",
            op: "audit.tail",
            input_schema: recent_changes_schema,
        },
    ]
}

/// `10_API_AND_MCP.md §3.2`'s forbidden list, restated as the exact op
/// names no tool in [`registry`] may ever map to. Kept next to the registry
/// (not buried in a test file) so the two stay visibly in sync.
pub const FORBIDDEN_OPS: &[&str] = &[
    "node.create",
    "grant.create",
    "grant.update",
    "grant.revoke",
    "orphan.reveal",
    "orphan.read",
    "node.policy_update",
    "node.agent_access_update",
    "node.reparent",
    "audit.purge",
    "audit.window_shorten",
    "totp.seed",
    // ADR-054: `doctor`/`backup` mutate vault-wide state an agent must never
    // trigger; `verify` is read-only but its errors can name a specific
    // security-relevant condition (a tampered manifest) that belongs in
    // front of the human via the CLI, not silently in an agent's context.
    "maintenance.verify",
    "maintenance.doctor",
    "maintenance.backup",
    // ADR-064/066: resetting the 2FA gate and re-pointing a node's
    // directories are policy changes (`§3.2`) — human-only, never a tool.
    "vault.gate_recover",
    "vault.gate_enroll_begin",
    "vault.gate_enroll_confirm",
    "node.set_workdirs",
    // ADR-071: the real names of the policy change §3.2 forbids (the two
    // placeholder names above predate the op), and renaming a node.
    "node.policy",
    "node.update",
    // ADR-076: replacing the root key is the most consequential act the vault
    // has — human, 2FA and presence only. Absent, not gated.
    "maintenance.rotate_root",
];

/// Dispatch one `tools/call` — looks up the named tool, forwards `arguments`
/// to the broker as that tool's `op`, verbatim. No tool-specific logic here:
/// every tool in [`registry`] is a thin, direct mapping onto an existing
/// broker op, and the broker (not this crate) is the enforcement point.
pub fn call_tool(name: &str, arguments: Value) -> Result<Value, ToolCallError> {
    let tool = registry()
        .into_iter()
        .find(|t| t.name == name)
        .ok_or_else(|| ToolCallError::UnknownTool(name.to_string()))?;
    let response = transport::call(tool.op, arguments).map_err(ToolCallError::Transport)?;
    unwrap_ok(response)
}

/// `credmgrd`'s wire shape (`10_API_AND_MCP.md §1`) is always `{"id", "ok",
/// "value"}` on success or `{"id", "ok": false, "error", "message"?,
/// "remedy"?, ...}` on denial — `transport::call` returns that envelope
/// verbatim (it only speaks the transport, not the protocol's own success/
/// failure convention), so every caller of it must unwrap `ok` before
/// treating the response as a value. Mirrors `credmgr-cli/src/main.rs`'s
/// `unwrap_ok` exactly (duplicated for the same reason `transport.rs`
/// itself is: `credmgr-cli` already depends on this crate, so the reverse
/// dependency would be circular).
fn unwrap_ok(response: Value) -> Result<Value, ToolCallError> {
    if response["ok"].as_bool() == Some(true) {
        return Ok(response["value"].clone());
    }
    Err(ToolCallError::Denied(response))
}

#[derive(Debug)]
pub enum ToolCallError {
    UnknownTool(String),
    Transport(TransportError),
    /// The broker answered but refused the op — carries its full structured
    /// denial (`error`, `message`, `remedy`, etc., `10_API_AND_MCP.md §1`)
    /// so a caller can surface exactly what the broker said, not a
    /// re-summarized guess at it.
    Denied(Value),
}

impl std::fmt::Display for ToolCallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ToolCallError::UnknownTool(name) => write!(f, "unknown tool: {name}"),
            ToolCallError::Transport(e) => write!(f, "{e}"),
            ToolCallError::Denied(response) => {
                let error = response["error"].as_str().unwrap_or("unknown_error");
                write!(f, "{error}")?;
                if let Some(message) = response["message"].as_str() {
                    write!(f, ": {message}")?;
                }
                if let Some(remedy) = response["remedy"].as_str() {
                    write!(f, "\n  remedy: {remedy}")?;
                }
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_tool_name_is_unique() {
        let names: Vec<&str> = registry().iter().map(|t| t.name).collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            names.len(),
            "duplicate tool name in the registry"
        );
    }

    #[test]
    fn every_tool_has_a_valid_json_schema_object() {
        for tool in registry() {
            let schema = (tool.input_schema)();
            assert_eq!(
                schema["type"], "object",
                "tool {} schema must be a JSON Schema object",
                tool.name
            );
        }
    }

    /// The advertised enum lists are copies of core's wire names; this holds them
    /// to the real enums, variant for variant. The `match`es are exhaustive on
    /// purpose: a variant added to core without teaching this crate fails to
    /// compile here instead of silently being unadvertised.
    #[test]
    fn the_name_lists_match_core() {
        use credmgr_core::inference::{EntryType, FieldType, Sensitivity};

        fn field_types(t: FieldType) -> bool {
            match t {
                FieldType::Password
                | FieldType::ApiKey
                | FieldType::PrivateKey
                | FieldType::SeedPhrase
                | FieldType::TotpSeed
                | FieldType::Username
                | FieldType::Host
                | FieldType::Port
                | FieldType::Url
                | FieldType::Certificate
                | FieldType::Text => true,
            }
        }
        fn entry_types(t: EntryType) -> bool {
            match t {
                EntryType::Server
                | EntryType::Database
                | EntryType::Api
                | EntryType::Wallet
                | EntryType::Login
                | EntryType::Ssh
                | EntryType::Certificate
                | EntryType::Token
                | EntryType::Totp
                | EntryType::EnvBundle
                | EntryType::Note
                | EntryType::Other => true,
            }
        }
        fn sensitivities(t: Sensitivity) -> bool {
            match t {
                Sensitivity::Low
                | Sensitivity::Medium
                | Sensitivity::High
                | Sensitivity::Critical => true,
            }
        }
        assert!(field_types(FieldType::Text) && entry_types(EntryType::Note));
        assert!(sensitivities(Sensitivity::Low));

        // Every advertised name is a real variant, and serialises back to itself.
        for name in FIELD_TYPE_NAMES {
            let t: FieldType = serde_json::from_value(json!(name)).expect(name);
            assert_eq!(serde_json::to_value(t).unwrap(), json!(name));
        }
        for name in ENTRY_TYPE_NAMES {
            let t: EntryType = serde_json::from_value(json!(name)).expect(name);
            assert_eq!(serde_json::to_value(t).unwrap(), json!(name));
        }
        for name in SENSITIVITY_NAMES {
            let t: Sensitivity = serde_json::from_value(json!(name)).expect(name);
            assert_eq!(serde_json::to_value(t).unwrap(), json!(name));
        }
        // ...and the counts match, so no variant is left unadvertised.
        assert_eq!(FIELD_TYPE_NAMES.len(), 11);
        assert_eq!(ENTRY_TYPE_NAMES.len(), 12);
        assert_eq!(SENSITIVITY_NAMES.len(), 4);
    }

    /// ADR-078: the body of update/rotate no longer requires `value` (a `fields`
    /// list or an override is a complete request), create requires neither
    /// `value` nor `fields` (exactly one of them, which the broker checks), and
    /// the four overrides are advertised wherever the broker reads them.
    #[test]
    fn the_write_schemas_describe_the_multi_field_bodies() {
        let create = create_schema();
        assert_eq!(create["required"], json!(["node", "name"]));
        for key in ["value", "label", "fields", "entryType", "sensitivity"] {
            assert!(
                create["properties"].get(key).is_some(),
                "create lacks {key}"
            );
        }
        for schema in [update_schema(), rotate_schema()] {
            assert_eq!(schema["required"], json!(["node", "entry", "generation"]));
            for key in [
                "value",
                "field",
                "label",
                "fields",
                "entryType",
                "sensitivity",
            ] {
                assert!(schema["properties"].get(key).is_some(), "lacks {key}");
            }
            // an update's fields may keep a field's identity
            assert!(schema["properties"]["fields"]["items"]["properties"]
                .get("id")
                .is_some());
        }
        // a create's fields are new: no `id`
        assert!(create["properties"]["fields"]["items"]["properties"]
            .get("id")
            .is_none());
        // `auto` clears an override and is advertised only where it can mean that
        let entry_type = &create["properties"]["entryType"]["enum"];
        assert!(entry_type.as_array().unwrap().contains(&json!("auto")));
        assert!(entry_type.as_array().unwrap().contains(&json!("note")));
        assert!(!entry_type.as_array().unwrap().contains(&json!("note-only")));
        let field_type = &create["properties"]["fields"]["items"]["properties"]["type"]["enum"];
        assert!(!field_type.as_array().unwrap().contains(&json!("auto")));
        let patch_type =
            &field_update_schema()["properties"]["patch"]["properties"]["type"]["enum"];
        assert!(patch_type.as_array().unwrap().contains(&json!("auto")));
    }

    #[test]
    fn call_tool_rejects_an_unknown_name_before_touching_the_socket() {
        let err = call_tool("credmgr_does_not_exist", json!({})).unwrap_err();
        assert!(
            matches!(err, ToolCallError::UnknownTool(name) if name == "credmgr_does_not_exist")
        );
    }
}
