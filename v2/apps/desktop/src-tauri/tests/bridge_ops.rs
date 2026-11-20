//! The forty-six table-generated commands (`bridge_ops!` in
//! `src/commands.rs`) and the hand-written `entry_reveal`, driven end to end
//! over a real Unix socket.
//!
//! `tests/drift_guards.rs` proves the table *names* the right ops and keys by
//! reading `ops.rs`. This file proves the generated code *does* what the
//! table says: each command puts exactly its op and exactly the caller's
//! params on the wire, attaches the session token, leaves an omitted optional
//! out rather than sending `null`, and hands back the broker's body untouched.
//! Together they are Phase 9's exit gate for the bridge (`12_BUILD_PLAN.md
//! §5.1`): all 40 ops reachable, and no result across the whole surface
//! carrying a token-shaped string.

mod common;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use common::fake_pasteboard::FakePasteboard;
use common::{err, ok, FakeBroker};
use desktop_lib::clipboard::Clipboard;
use desktop_lib::commands;
use desktop_lib::session::Session;
use serde_json::{json, Value};
use tauri::async_runtime::block_on;

const MINTED: &str = "cmt_0123456789abcdef";
/// ADR-164: the agent bearer `agent.token_issue|rotate` answer once (invented).
const AGENT_BEARER: &str = "cma_00000000000000000000000000000000000000000000000000000000000000a1";

/// A success body shaped like the one `crates/brokerd/src/ops.rs` builds for
/// `op` — read from that file, per op. Shapes matter here only where the
/// bridge could misread them (`vault.node_lock`'s `locked`), and for the
/// token sweep, which needs every op to answer something realistic.
fn realistic(op: &str) -> Value {
    match op {
        "vault.status" => json!({ "locked": false }),
        "vault.unlock" | "vault.gate_verify" => json!({ "locked": false, "token": MINTED }),
        "vault.lock" => json!({ "locked": true }),
        "vault.gate_enroll_begin" => {
            json!({ "otpauthUri": "otpauth://totp/CredMgr:vault?secret=JBSWY3DPEHPK3PXP" })
        }
        "vault.gate_enroll_confirm" => json!({ "recoveryCodes": ["aaaa-bbbb", "cccc-dddd"] }),
        "vault.init_begin" => json!({ "recoveryCode": "RC-TEST-0000-1111" }),
        "vault.init_confirm" => json!({ "initialized": true }),
        "vault.gate_recover" => json!({ "gateReset": true }),
        // ADR-150: a confirmation opens the session's trust window.
        "session.confirm" => json!({ "confirmed": true, "method": "passphrase", "expiresIn": 300 }),
        "node.set_workdirs" => json!({ "node": "acme", "workdirs": ["/work/acme"] }),
        "node.update" => json!({ "node": "acme", "label": "Acme Corp" }),
        "notes.read" => {
            json!({ "node": "acme", "markdown": "why this project exists", "modified": 1 })
        }
        "entry.create_batch" => json!({
            "node": "acme",
            "created": [{ "name": "A", "entry": "e_000000000001", "pending": false }],
            "complete": true,
            "failed": null,
            "total": 1,
            "generation": 2
        }),
        "notes.write" => {
            json!({ "node": "acme", "generation": 4, "modified": 1, "cleared": false })
        }
        "node.policy" => json!({
            "node": "acme",
            "policy": { "agentAccess": "none" },
            "changed": ["agentAccess"],
            "reason": "r",
            "notEnforced": ["requireTwoFactor", "privateNames"]
        }),
        "whoami" => json!({ "node": "global", "capabilities": ["admin"], "reachable": ["acme"] }),
        // Bare ids, filtered broker-side — not node objects (`ops.rs` `node.list`).
        "node.list" => json!({ "nodes": ["global", "acme"] }),
        "graph.snapshot" => json!({
            "nodes": [], "links": [], "meta": { "generatedAt": 1, "vaultLocked": false }
        }),
        "audit.tail" => json!({ "records": [{ "id": "r1", "action": "entry.reveal" }] }),
        "entry.list" => json!({ "node": "acme", "ids": ["e1"], "names": ["k"], "generation": 7 }),
        "search" => json!({ "results": [{ "node": "acme", "entry": "e1", "name": "k" }] }),
        // ADR-078: `fields` always, `value` only when exactly one field comes back
        // (`entry_doc::reveal_json`).
        "entry.reveal" => json!({
            "node": "acme", "entry": "e1",
            "fields": [{
                "id": "f_00000000", "label": "", "value": "s3cr3t",
                "type": "text", "masked": false
            }],
            "value": "s3cr3t"
        }),
        // `entry_doc::get_json`: metadata and labels, never a value.
        "entry.get" => json!({
            "node": "acme", "entry": "e1", "name": "k", "ref": 1000,
            "type": "server", "sensitivity": "high", "fieldCount": 2, "hasTotp": false,
            "modified": 3, "rotatedAt": null, "expiresAt": null, "generation": 7,
            "typeOverridden": false, "sensitivityOverridden": false,
            "fields": [
                { "id": "f_0a1b2c3d", "label": "host", "type": "host", "masked": false,
                  "typeOverridden": false, "maskedOverridden": false },
                { "id": "f_4e5f6a7b", "label": "password", "type": "password", "masked": true,
                  "typeOverridden": false, "maskedOverridden": false }
            ]
        }),
        "totp.code" => json!({ "node": "acme", "entry": "e1", "code": "123456" }),
        "entry.create" => json!({
            "node": "acme", "entry": "e2", "pending": false, "generation": 8,
            "fieldCount": 1, "fieldIds": ["f_0a1b2c3d"]
        }),
        // `mutated_json`: the shape every update, rotate and field op answers.
        "entry.update" | "field.update" | "field.remove" | "field.reorder" => json!({
            "node": "acme", "entry": "e1", "generation": 8,
            "fieldCount": 2, "fieldIds": ["f_0a1b2c3d", "f_4e5f6a7b"]
        }),
        "field.add" => json!({
            "node": "acme", "entry": "e1", "generation": 8,
            "fieldCount": 2, "fieldIds": ["f_0a1b2c3d", "f_4e5f6a7b"], "added": ["f_4e5f6a7b"]
        }),
        "entry.rotate" => json!({
            "node": "acme", "entry": "e1", "generation": 8,
            "fieldCount": 1, "fieldIds": ["f_0a1b2c3d"], "rotatedAt": 5
        }),
        "entry.remove" => {
            json!({ "node": "acme", "entry": "e1", "removed": true, "generation": 8 })
        }
        "entry.restore" => {
            json!({ "node": "acme", "entry": "e1", "restoredName": "deploy-key", "generation": 9 })
        }
        // `undo_rotate`'s shape; an undone removal answers `do_entry_restore`'s.
        "entry.undo" => {
            json!({ "node": "acme", "entry": "e1", "generation": 9, "undoneToGeneration": 7 })
        }
        "vault.pending_list" => json!({ "node": "acme", "pending": [] }),
        "vault.pending_accept" => {
            json!({ "node": "acme", "entry": "e2", "accepted": true, "generation": 9 })
        }
        "vault.pending_discard" => json!({ "node": "acme", "entry": "e2", "discarded": true }),
        "vault.approval_get" => json!({
            "request": "rq_00000000000000000000000000000001", "node": "acme", "entry": "e1",
            "nodeLabel": "Acme", "entryName": "API_KEY", "command": "entry.reveal",
            "state": "pending", "expiresIn": 100, "requestedAt": 1
        }),
        "vault.node_lock" => json!({ "node": "acme", "locked": true }),
        "vault.node_unlock" => json!({ "node": "acme", "locked": false }),
        "vault.approval_decide" => {
            json!({ "request": "q1", "node": "acme", "entry": "e1", "approved": true })
        }
        "node.create" => json!({ "node": "acme-api", "created": true }),
        "node.seal" => json!({ "node": "acme", "sealed": true }),
        "node.restore" => json!({ "node": "acme", "restored": true }),
        "grant.list" => json!({ "grants": [] }),
        "grant.revoke" => json!({ "id": "g1", "revoked": true }),
        "maintenance.verify" => {
            json!({ "ok": true, "nodesChecked": 2, "errors": [], "warnings": [] })
        }
        "maintenance.doctor" => {
            json!({ "applied": true, "fixCount": 0, "fixes": [], "unfixable": [] })
        }
        "maintenance.backup" => json!({ "path": "/tmp/b.cmbak", "retain": 14, "pruned": 0 }),
        // `ops.rs` `util.generate` (ADR-087). A realistic length, and nothing shaped like a token.
        "util.generate" => json!({
            "value": "q7Vn-2xLw9RtZk4PdE8m", "length": 20, "symbols": true,
            "pronounceable": false, "entropyBits": 124
        }),
        // ADR-121 / ADR-122 (`ops/alias.rs`): names and counts, never a value.
        "entry.alias" => json!({
            "node": "acme", "entry": "e1", "generation": 8, "aliases": ["stripe"]
        }),
        "entry.similar" => json!({
            "node": "acme", "name": "stirpe-key", "taken": false,
            "similar": [{ "id": "e1", "name": "stripe-key", "reason": "one-edit" }]
        }),
        "entry.import_env" => json!({
            "node": "acme", "dryRun": true, "total": 2,
            "items": [{ "name": "A_B_C", "status": "new" }, { "name": "D_E_F", "status": "exists" }],
            "counts": { "new": 1, "exists": 1, "duplicate": 0, "empty": 0, "invalid": 0 }
        }),
        // `ops::rotate_root_response`'s shape (ADR-076) — the answer the
        // broker will give once a transport can attest presence. No `locked`
        // key: the session reads that as the vault's own lock state.
        "maintenance.rotate_root" => json!({
            "rotated": true,
            "recoveryCode": "RC-ROTATED-2222-3333",
            "nodesRewrapped": 2,
            "vaultGeneration": 9,
            "filesReplaced": 14,
            "artifactsResigned": 3,
            "completionPending": false,
            "notResigned": []
        }),
        // ADR-155 (`ops/switchboard.rs`): settings, never a value.
        "settings.list" => json!({
            "caller": "owner", "node": null, "note": "", "kb": "settings.kb",
            "settings": [{ "id": "app.theme", "scope": "vault", "value": "dark", "default": null, "risk": "cosmetic", "you": "direct" }]
        }),
        "settings.get" => {
            json!({ "id": "app.autoLockMins", "value": 15, "default": 15, "risk": "security", "you": "direct", "recentChanges": [] })
        }
        "settings.set" | "settings.revert" => json!({
            "applied": true, "change": "cosmetic", "changeId": "sc-0123456789abcdef", "id": "app.theme", "from": null, "to": "dark"
        }),
        "settings.request_get" => {
            json!({ "request": "sr-0123456789abcdef", "id": "app.autoLockMins", "state": "pending", "from": 15, "to": 0, "expiresIn": 600 })
        }
        "settings.request_list" => json!({ "requests": [] }),
        "settings.request_decide" => {
            json!({ "request": "sr-0123456789abcdef", "state": "denied", "applied": false })
        }
        "settings.kb" => json!({ "markdown": "# CredMgr", "format": "text/markdown" }),
        // ADR-156 (`ops/quick_ops.rs`, `ops::set_passphrase_response`): dates, names and counts — the
        // only secret is the new recovery code, shown once.
        "vault.set_passphrase" => json!({
            "rotated": true, "passphraseChanged": true, "recoveryCode": "RC-CHANGED-4444-5555",
            "nodesRewrapped": 2, "vaultGeneration": 10, "filesReplaced": 14,
            "artifactsResigned": 3, "completionPending": false, "notResigned": []
        }),
        // ADR-163 (`ops::recover_response`): the set_passphrase answer, plus the login token the bridge
        // must capture and never hand on. The new recovery code is the one secret the page sees, once.
        "vault.recover" => json!({
            "rotated": true, "passphraseChanged": true, "recovered": true, "locked": false,
            "recoveryCode": "RC-RECOVERED-6666-7777", "nodesRewrapped": 2, "vaultGeneration": 11,
            "filesReplaced": 14, "artifactsResigned": 3, "completionPending": false,
            "notResigned": [], "token": MINTED
        }),
        "vault.anomalies_ack" => json!({ "acknowledged": 1 }),
        "entry.set_expiry" => json!({
            "node": "acme", "entry": "e1", "generation": 9, "expiresAt": 1_900_000_000
        }),
        "entry.expiring" => json!({
            "days": 30, "now": 1_800_000_000,
            "entries": [{ "node": "acme", "id": "e1", "name": "stripe-key", "ref": 1000,
                          "expiresAt": 1_800_500_000, "rotatedAt": null, "expired": false }]
        }),
        "entry.history" => json!({
            "node": "acme", "entry": "e1", "exists": true, "truncated": false, "name": "stripe-key",
            "ref": 1000, "modified": 1_799_000_000, "rotatedAt": null, "expiresAt": null,
            "records": [{ "id": "a_0123456789ab", "timestamp": 1_799_000_000, "actor": "session s_01",
                          "action": "entry.create", "decision": "allow", "generation": 1 }]
        }),
        "entry.search" => {
            json!({ "node": "acme", "results": [{ "id": "e1", "name": "stripe-key" }] })
        }
        "entry.get_by_ref" => {
            json!({ "node": "acme", "entry": "e1", "name": "stripe-key", "ref": 1000 })
        }
        // ADR-161 (`ops/doctor_ops.rs`): names, ids, reasons and the move params — never a value.
        "vault.doctor_scan" => json!({
            "now": 1_800_000_000, "staleDays": 365, "expiringDays": 30, "nodesScanned": 3,
            "entriesScanned": 4, "valuesChecked": 4, "skipped": [], "truncated": false,
            "counts": { "duplicate_value": 1, "misfiled": 0, "similar_names": 0, "weak": 0,
                        "mistyped": 0, "expired": 0, "expiring": 0, "stale": 0 },
            "findings": [{ "kind": "duplicate_value", "match": "exact",
                "entries": [
                    { "node": "acme-web", "nodeLabel": "Acme web", "entry": "e1", "ref": 1000, "name": "KEY", "generation": 3 },
                    { "node": "acme-api", "nodeLabel": "Acme api", "entry": "e2", "ref": 1001, "name": "KEY", "generation": 5 }],
                "proposal": { "action": "move_to_parent", "op": "entry.move", "to": "acme", "toLabel": "Acme",
                              "move": { "node": "acme-web", "entry": "e1", "to": "acme", "generation": 3 } } }]
        }),
        // ADR-158 (`ops/move_ops.rs`): where the entry is now, both generations, what changed with it.
        "entry.move" => json!({
            "node": "beta", "entry": "e1", "ref": 1000, "name": "stripe-key", "from": "acme",
            "generation": 10, "toGeneration": 4, "grantsRevoked": [], "historyDropped": 0
        }),
        // ADR-165 (ops.rs `keystore.bind` / `keystore.unbind`): the status plus what changed. Review N1: a bind is
        // two calls; `prepare` answers the new code (and changes nothing), `commit` takes it typed back and is the
        // root rotation (and does not send the code again). One shape carries the fields of both.
        "keystore.bind" => json!({
            "bound": true, "tier": "file", "secureEnclave": false, "opensHere": true, "changed": true,
            "phase": "commit", "already": false, "newRecoveryCode": null, "expiresIn": 600,
            "deviceKeyCreated": true, "nodesRekeyed": ["acme", "global"], "rekeyFailed": [],
            "orphanKeyReplaced": true, "completionPending": false
        }),
        // ADR-165 (`ops.rs::machine_lock_status_json`): the honest tier, never a secret. Since ADR-164 the sweep below
        // refuses a dead fake broker, so the status needs a shape of its own.
        "keystore.status" => json!({
            "bound": false, "tier": "off", "secureEnclave": false, "opensHere": true,
            "sealedKeyId": null, "damaged": false, "deviceKeyPresent": false, "deviceKeyId": null,
            "deviceKeyUnreadable": false, "deviceKeyModeOpen": false
        }),
        "keystore.unbind" => json!({
            "bound": false, "tier": "off", "secureEnclave": false, "opensHere": true, "changed": true
        }),
        // ADR-098/148 presence, ADR-131/132/133/134/135 (`ops.rs`, `ops/stable_ops.rs`,
        // `ops/node_gate_ops.rs`). These had no shape, so the fake broker's thread panicked at
        // `presence.status` and every later sweep entry met a dead socket; the sweep now refuses
        // `broker_unreachable` so that cannot pass silently again.
        "presence.status" => json!({
            "helper": true, "secureEnclave": true, "biometry": "touchid", "passcode": true,
            "enrolled": [{ "id": "pk_01", "label": "This Mac", "createdAt": 1 }],
            "touchIdUnlock": false
        }),
        "presence.challenge" => json!({
            "nonce": "bm9uY2U=", "digest": "ZGlnZXN0", "expiresIn": 60,
            "reason": "Show the audit record"
        }),
        "presence.enrol" => json!({ "id": "pk_01", "label": "This Mac", "createdAt": 1 }),
        "presence.unenrol" => json!({ "removed": true }),
        "device.enrol" => json!({ "touchIdUnlock": true }),
        "device.remove" => json!({ "touchIdUnlock": false }),
        "orphan.list" => json!({
            "entries": [{ "entry": "e1", "name": "old-key", "ref": 1000, "type": "server", "modified": 1 }]
        }),
        // A sealed read answers like `entry.reveal` (`entry_doc::reveal_json`).
        "orphan.reveal" => json!({
            "node": "orphaned", "entry": "e1",
            "fields": [{ "id": "f_00000000", "label": "", "value": "s3cr3t", "type": "text", "masked": false }],
            "value": "s3cr3t"
        }),
        "orphan.destroy" => {
            json!({ "destroyed": 1, "sealsForgotten": 1, "archivesRemoved": 1 })
        }
        "node.rekey" => json!({
            "node": "acme", "publicKey": "age1qyqszqgpqyqszqgpqyqszqgpqyqszqgp", "entries": 2,
            "note": true, "history": 1, "removed": 0
        }),
        "search.content" => json!({
            "results": [{ "node": "acme", "id": "e1", "name": "stripe-key" }], "truncated": false
        }),
        "node.export" => json!({
            "node": "acme", "format": "age-v1", "entries": 2, "omittedSeeds": 0,
            "archive": "YWdlLWVuY3J5cHRpb24ub3JnL3Yx"
        }),
        "audit.report" => json!({
            "from": 0, "to": 1, "node": null, "records": 0,
            "decisions": { "allow": 0, "deny": 0, "other": 0 },
            "byAction": [], "byActor": [], "byNode": [],
            "denials": { "total": 0, "reasons": [], "recent": [] },
            "presence": { "uses": 0, "byOp": [], "refused": 0 },
            "chain": { "months": 0, "verified": true }
        }),
        "node.gate_enroll_begin" => json!({
            "node": "acme", "otpauthUri": "otpauth://totp/CredMgr:acme?secret=JBSWY3DPEHPK3PXP"
        }),
        "node.gate_enroll_confirm" => {
            json!({ "node": "acme", "recoveryCodes": ["aaaa-bbbb", "cccc-dddd"] })
        }
        "node.gate_verify" => json!({ "node": "acme", "elevated": true, "expiresIn": 300 }),
        "node.gate_remove" => json!({ "node": "acme", "removed": true }),
        // ADR-164 (`ops/agent_tokens.rs`): issue and rotate carry the bearer once, which the
        // shell must take off the answer before the webview sees it.
        "agent.token_issue" | "agent.token_rotate" => json!({
            "id": "a_00000000000000a1", "label": "ci", "node": "acme",
            "capabilities": ["list", "read"], "effectiveCapabilities": ["list", "read"],
            "createdAt": 1_800_000_000, "expiresAt": 1_800_086_400, "lastUsedAt": null,
            "rotatedAt": null, "token": AGENT_BEARER, "shownOnce": true
        }),
        "agent.token_status" => json!({
            "tokens": [{ "id": "a_00000000000000a1", "label": "ci", "node": "acme",
                         "capabilities": ["list"], "effectiveCapabilities": ["list"],
                         "createdAt": 1_800_000_000, "expiresAt": 1_800_086_400,
                         "lastUsedAt": null, "rotatedAt": null }],
            "max": 32, "defaultExpiresIn": 86_400, "maxExpiresIn": 604_800
        }),
        "agent.token_revoke" => {
            json!({ "revoked": true, "id": "a_00000000000000a1", "label": "ci", "node": "acme" })
        }
        // ADR-169 (`ops/move_ops.rs`): each applied move is entry.move's answer plus its index in the plan.
        "vault.doctor_apply" => json!({
            "complete": true, "notApplied": 0,
            "applied": [{
                "index": 0, "node": "acme", "entry": "e1", "ref": 1000, "name": "KEY", "from": "acme-web",
                "generation": 4, "toGeneration": 9, "grantsRevoked": [], "historyDropped": 0
            }]
        }),
        // ADR-167 (`ops/tags_ops.rs`) and ADR-168 (`ops/merge_ops.rs`): names, ids and keys, never a value. The
        // every-command sweep (ADR-164) refuses a dead fake broker, so each op it calls needs a shape.
        "entry.tag_set" => {
            json!({ "node": "acme", "entry": "e1", "generation": 5, "tags": ["prod"] })
        }
        "merge.suggestions" => json!({
            "node": "acme", "generation": 5, "valuesCompared": 2, "truncated": false, "dismissedCount": 0,
            "suggestions": [{ "key": "e1+e2", "kind": "identical", "reasons": ["identical"], "identical": true,
                "keep": "e1", "entries": [{ "entry": "e1", "ref": 1000, "name": "KEY" },
                                          { "entry": "e2", "ref": 1001, "name": "key" }] }]
        }),
        "merge.apply" | "merge.auto" => json!({
            "node": "acme", "generation": 6, "keep": "e1",
            "merged": [{ "entry": "e2", "name": "key", "undo": "u1" }], "aliasesAdded": ["key"], "tagsAdded": []
        }),
        "merge.auto_all" => json!({
            "node": "acme", "dryRun": true, "valuesCompared": 2, "generation": 5, "planned": [], "skipped": []
        }),
        "merge.dismiss" => {
            json!({ "node": "acme", "key": "e1+e2", "dismissed": true, "generation": 6 })
        }
        "merge.undismiss" => {
            json!({ "node": "acme", "key": "e1+e2", "restored": true, "generation": 7 })
        }
        "merge.dismissed_list" => json!({ "node": "acme", "dismissed": [] }),
        "merge.restore_all" => json!({ "node": "acme", "restored": 0, "generation": 7 }),
        other => panic!("realistic() has no shape for {other} — add one from ops.rs"),
    }
}

/// Ops whose positive path needs presence, which no transport can attest
/// yet (ADR-047, F-8) — the real broker refuses every call to them with
/// `presence_required`, so the fake one does too rather than inventing a
/// success body the broker has never sent.
const PRESENCE_GATED: &[&str] = &[
    "totp.seed",
    "node.reparent",
    "grant.create",
    "audit.get",
    // ADR-076: `04 §6` asks for presence on a root-key rotation too.
    "maintenance.rotate_root",
];

/// A broker that answers every op the way `ops.rs` does today, so the whole
/// surface can be swept against one socket.
fn realistic_broker() -> FakeBroker {
    FakeBroker::spawn(|request| {
        let op = request["op"].as_str().unwrap_or_default();
        if PRESENCE_GATED.contains(&op) {
            err("presence_required", json!({ "operation": op }))
        } else {
            ok(realistic(op))
        }
    })
}

/// Log in so every later frame should carry [`MINTED`].
fn logged_in(broker: &FakeBroker) -> Session {
    let session = Session::new();
    block_on(commands::vault_unlock_at(
        &session,
        broker.socket.clone(),
        "pw".into(),
    ))
    .expect("unlock");
    assert!(session.is_authenticated());
    session
}

/// A broker that answers `maintenance.rotate_root` the way ADR-076 specifies
/// it will once presence can be attested (the success body), and every other
/// op as [`realistic_broker`] does.
fn rotating_broker() -> FakeBroker {
    FakeBroker::spawn(|request| {
        let op = request["op"].as_str().unwrap_or_default();
        if PRESENCE_GATED.contains(&op) && op != "maintenance.rotate_root" {
            err("presence_required", json!({ "operation": op }))
        } else {
            ok(realistic(op))
        }
    })
}

/// Assert that frame `index` is `op` with exactly `params`, carrying the
/// session token — the three things a generated command is responsible for.
fn assert_frame(broker: &FakeBroker, index: usize, op: &str, params: Value) {
    let frame = &broker.received()[index];
    assert_eq!(frame["op"], op, "frame {index}");
    assert_eq!(
        frame["params"], params,
        "{op} put different params on the wire"
    );
    assert_eq!(
        broker.token_on(index).as_deref(),
        Some(MINTED),
        "{op} went out without the session token"
    );
}

fn sock(broker: &FakeBroker) -> PathBuf {
    broker.socket.clone()
}

#[test]
fn vault_bootstrap_and_gate_enrolment_send_their_own_params() {
    let b = realistic_broker();
    let s = logged_in(&b);

    let v = block_on(commands::vault_init_begin_at(
        &s,
        sock(&b),
        "a long passphrase".into(),
    ))
    .unwrap();
    assert_frame(
        &b,
        1,
        "vault.init_begin",
        json!({ "passphrase": "a long passphrase" }),
    );
    assert_eq!(
        v["recoveryCode"], "RC-TEST-0000-1111",
        "shown once, so it must arrive verbatim"
    );

    block_on(commands::vault_init_confirm_at(
        &s,
        sock(&b),
        "RC-TEST-0000-1111".into(),
    ))
    .unwrap();
    assert_frame(
        &b,
        2,
        "vault.init_confirm",
        json!({ "recoveryCode": "RC-TEST-0000-1111" }),
    );

    let v = block_on(commands::vault_gate_enroll_begin_at(&s, sock(&b))).unwrap();
    assert_frame(&b, 3, "vault.gate_enroll_begin", json!({}));
    assert!(v["otpauthUri"].as_str().unwrap().starts_with("otpauth://"));

    let v = block_on(commands::vault_gate_enroll_confirm_at(
        &s,
        sock(&b),
        "123456".into(),
    ))
    .unwrap();
    assert_frame(
        &b,
        4,
        "vault.gate_enroll_confirm",
        json!({ "code": "123456" }),
    );
    assert_eq!(v["recoveryCodes"].as_array().unwrap().len(), 2);

    let v = block_on(commands::vault_gate_recover_at(
        &s,
        sock(&b),
        "a long passphrase".into(),
        "ROOT-RECOVERY".into(),
    ))
    .unwrap();
    assert_frame(
        &b,
        5,
        "vault.gate_recover",
        json!({ "passphrase": "a long passphrase", "recoveryCode": "ROOT-RECOVERY" }),
    );
    assert_eq!(v["gateReset"], true);
}

#[test]
fn the_pending_tray_approvals_and_node_locks_send_their_own_params() {
    let b = realistic_broker();
    let s = logged_in(&b);

    block_on(commands::vault_pending_list_at(&s, sock(&b), "acme".into())).unwrap();
    assert_frame(&b, 1, "vault.pending_list", json!({ "node": "acme" }));

    block_on(commands::vault_pending_accept_at(
        &s,
        sock(&b),
        "acme".into(),
        "e2".into(),
    ))
    .unwrap();
    assert_frame(
        &b,
        2,
        "vault.pending_accept",
        json!({ "node": "acme", "entry": "e2" }),
    );

    block_on(commands::vault_pending_discard_at(
        &s,
        sock(&b),
        "acme".into(),
        "e2".into(),
    ))
    .unwrap();
    assert_frame(
        &b,
        3,
        "vault.pending_discard",
        json!({ "node": "acme", "entry": "e2" }),
    );

    block_on(commands::vault_approval_decide_at(
        &s,
        sock(&b),
        "q1".into(),
        false,
        None,
        None,
    ))
    .unwrap();
    assert_frame(
        &b,
        4,
        "vault.approval_decide",
        json!({ "request": "q1", "approved": false }),
    );

    block_on(commands::vault_node_lock_at(&s, sock(&b), "acme".into())).unwrap();
    assert_frame(&b, 5, "vault.node_lock", json!({ "node": "acme" }));

    block_on(commands::vault_node_unlock_at(&s, sock(&b), "acme".into())).unwrap();
    assert_frame(&b, 6, "vault.node_unlock", json!({ "node": "acme" }));

    // ADR-090: with a request id it asks about that one; without, it lists.
    block_on(commands::vault_approval_get_at(
        &s,
        sock(&b),
        Some("q1".into()),
    ))
    .unwrap();
    assert_frame(&b, 7, "vault.approval_get", json!({ "request": "q1" }));
    block_on(commands::vault_approval_get_at(&s, sock(&b), None)).unwrap();
    assert_frame(&b, 8, "vault.approval_get", json!({}));
}

#[test]
fn node_lifecycle_sends_its_own_params_in_the_brokers_casing() {
    let b = realistic_broker();
    let s = logged_in(&b);

    block_on(commands::node_list_at(&s, sock(&b))).unwrap();
    assert_frame(&b, 1, "node.list", json!({}));

    block_on(commands::node_create_at(
        &s,
        sock(&b),
        "acme-api".into(),
        "Acme API".into(),
        "acme".into(),
        None,
    ))
    .unwrap();
    assert_frame(
        &b,
        2,
        "node.create",
        json!({ "id": "acme-api", "label": "Acme API", "parentId": "acme" }),
    );

    block_on(commands::node_seal_at(&s, sock(&b), "acme".into())).unwrap();
    assert_frame(&b, 3, "node.seal", json!({ "node": "acme" }));

    block_on(commands::node_restore_at(&s, sock(&b), "acme".into())).unwrap();
    assert_frame(&b, 4, "node.restore", json!({ "node": "acme" }));

    let e = block_on(commands::node_reparent_at(
        &s,
        sock(&b),
        "acme-api".into(),
        "other".into(),
        "moving under the platform team".into(),
    ))
    .unwrap_err();
    assert_eq!(e.code, "presence_required");
    assert_frame(
        &b,
        5,
        "node.reparent",
        json!({ "node": "acme-api", "newParent": "other", "reason": "moving under the platform team" }),
    );

    block_on(commands::node_create_at(
        &s,
        sock(&b),
        "beta".into(),
        "Beta".into(),
        "global".into(),
        Some(vec!["/work/beta".into()]),
    ))
    .unwrap();
    assert_frame(
        &b,
        6,
        "node.create",
        json!({ "id": "beta", "label": "Beta", "parentId": "global", "workdirs": ["/work/beta"] }),
    );

    block_on(commands::node_set_workdirs_at(
        &s,
        sock(&b),
        "acme".into(),
        vec!["/work/acme".into()],
    ))
    .unwrap();
    assert_frame(
        &b,
        7,
        "node.set_workdirs",
        json!({ "node": "acme", "workdirs": ["/work/acme"] }),
    );

    let v = block_on(commands::node_update_at(
        &s,
        sock(&b),
        "acme".into(),
        "Acme Corp".into(),
    ))
    .unwrap();
    assert_eq!(v["label"], "Acme Corp");
    assert_frame(
        &b,
        8,
        "node.update",
        json!({ "node": "acme", "label": "Acme Corp" }),
    );

    // The patch object passes through untouched — the broker owns its schema.
    let patch = json!({ "agentAccess": "none", "lockAfterSeconds": null });
    block_on(commands::node_policy_at(
        &s,
        sock(&b),
        "acme".into(),
        "agents only read this project".into(),
        patch.clone(),
    ))
    .unwrap();
    assert_frame(
        &b,
        9,
        "node.policy",
        json!({ "node": "acme", "reason": "agents only read this project", "policy": patch }),
    );

    let v = block_on(commands::notes_read_at(&s, sock(&b), "acme".into())).unwrap();
    assert_eq!(v["markdown"], "why this project exists");
    assert_frame(&b, 10, "notes.read", json!({ "node": "acme" }));
    block_on(commands::notes_write_at(
        &s,
        sock(&b),
        "acme".into(),
        "## Why\nDeploys on Tuesdays".into(),
        3,
    ))
    .unwrap();
    assert_frame(
        &b,
        11,
        "notes.write",
        json!({ "node": "acme", "markdown": "## Why\nDeploys on Tuesdays", "generation": 3 }),
    );
}

#[test]
fn grants_send_their_own_params_and_pass_the_target_through_untouched() {
    let b = realistic_broker();
    let s = logged_in(&b);

    block_on(commands::grant_list_at(&s, sock(&b))).unwrap();
    assert_frame(&b, 1, "grant.list", json!({}));

    // `to` is the broker's own tagged shape; the bridge must not re-encode it.
    let to = json!({ "kind": "entry", "nodeId": "other", "entryId": "e9" });
    let e = block_on(commands::grant_create_at(
        &s,
        sock(&b),
        "acme".into(),
        to.clone(),
        vec!["read".into(), "reveal".into()],
        "deploy needs the signing key".into(),
        None,
        None,
    ))
    .unwrap_err();
    assert_eq!(e.code, "presence_required");
    assert_frame(
        &b,
        2,
        "grant.create",
        json!({
            "from": "acme", "to": to, "scope": ["read", "reveal"],
            "reason": "deploy needs the signing key"
        }),
    );

    block_on(commands::grant_revoke_at(&s, sock(&b), "g1".into())).unwrap();
    assert_frame(&b, 3, "grant.revoke", json!({ "id": "g1" }));
}

#[test]
fn entry_mutations_send_the_generation_and_their_own_params() {
    let b = realistic_broker();
    let s = logged_in(&b);

    block_on(commands::entry_create_at(
        &s,
        sock(&b),
        "acme".into(),
        "deploy-key".into(),
        Some("v1".into()),
        Some("token".into()),
        None,
        None,
        None,
    ))
    .unwrap();
    assert_frame(
        &b,
        1,
        "entry.create",
        json!({ "node": "acme", "name": "deploy-key", "value": "v1", "label": "token" }),
    );

    block_on(commands::entry_update_at(
        &s,
        sock(&b),
        "acme".into(),
        "e1".into(),
        Some("v2".into()),
        7,
        None,
        None,
        None,
        None,
        None,
    ))
    .unwrap();
    assert_frame(
        &b,
        2,
        "entry.update",
        json!({ "node": "acme", "entry": "e1", "value": "v2", "generation": 7 }),
    );

    let v = block_on(commands::entry_rotate_at(
        &s,
        sock(&b),
        "acme".into(),
        "e1".into(),
        Some("v3".into()),
        8,
        None,
        None,
        None,
        None,
        None,
    ))
    .unwrap();
    assert_frame(
        &b,
        3,
        "entry.rotate",
        json!({ "node": "acme", "entry": "e1", "value": "v3", "generation": 8 }),
    );
    assert_eq!(v["rotatedAt"], 5, "the broker's body arrives unreshaped");

    block_on(commands::entry_remove_at(
        &s,
        sock(&b),
        "acme".into(),
        "e1".into(),
        8,
    ))
    .unwrap();
    assert_frame(
        &b,
        4,
        "entry.remove",
        json!({ "node": "acme", "entry": "e1", "generation": 8 }),
    );

    block_on(commands::entry_restore_at(
        &s,
        sock(&b),
        "acme".into(),
        "e1".into(),
        8,
        Some("keep-both".into()),
    ))
    .unwrap();
    assert_frame(
        &b,
        5,
        "entry.restore",
        json!({ "node": "acme", "entry": "e1", "generation": 8, "mode": "keep-both" }),
    );

    block_on(commands::entry_undo_at(
        &s,
        sock(&b),
        "acme".into(),
        "r1".into(),
        9,
        None,
    ))
    .unwrap();
    assert_frame(
        &b,
        6,
        "entry.undo",
        json!({ "node": "acme", "id": "r1", "generation": 9 }),
    );
}

#[test]
fn totp_search_and_audit_send_their_own_params() {
    let b = realistic_broker();
    let s = logged_in(&b);

    block_on(commands::totp_code_at(
        &s,
        sock(&b),
        "acme".into(),
        "e1".into(),
        None,
    ))
    .unwrap();
    assert_frame(&b, 1, "totp.code", json!({ "node": "acme", "entry": "e1" }));

    let e = block_on(commands::totp_seed_at(
        &s,
        sock(&b),
        "acme".into(),
        "e1".into(),
        None,
    ))
    .unwrap_err();
    assert_frame(&b, 2, "totp.seed", json!({ "node": "acme", "entry": "e1" }));
    assert_eq!(
        e.code, "presence_required",
        "wired now, refused broker-side until presence exists"
    );

    block_on(commands::search_at(&s, sock(&b), "deploy".into())).unwrap();
    assert_frame(&b, 3, "search", json!({ "term": "deploy" }));

    block_on(commands::audit_tail_at(&s, sock(&b), None)).unwrap();
    assert_frame(&b, 4, "audit.tail", json!({}));

    block_on(commands::audit_tail_at(&s, sock(&b), Some(200))).unwrap();
    assert_frame(&b, 5, "audit.tail", json!({ "limit": 200 }));

    let e = block_on(commands::audit_get_at(&s, sock(&b), "r1".into())).unwrap_err();
    assert_frame(&b, 6, "audit.get", json!({ "id": "r1" }));
    assert_eq!(e.code, "presence_required");
}

#[test]
fn maintenance_sends_its_own_params_and_omits_every_unset_option() {
    let b = realistic_broker();
    let s = logged_in(&b);

    block_on(commands::maintenance_verify_at(&s, sock(&b))).unwrap();
    assert_frame(&b, 1, "maintenance.verify", json!({}));

    // Every optional unset: the broker's own defaults (apply: true, no
    // rebuild) must govern, so nothing at all goes on the wire.
    block_on(commands::maintenance_doctor_at(
        &s,
        sock(&b),
        None,
        None,
        None,
        None,
    ))
    .unwrap();
    assert_frame(&b, 2, "maintenance.doctor", json!({}));

    block_on(commands::maintenance_doctor_at(
        &s,
        sock(&b),
        Some(false),
        Some(true),
        Some("pw".into()),
        Some(true),
    ))
    .unwrap();
    assert_frame(
        &b,
        3,
        "maintenance.doctor",
        json!({ "apply": false, "rebuildRegistry": true, "passphrase": "pw", "purgeExpiredSeals": true }),
    );

    block_on(commands::maintenance_backup_at(
        &s,
        sock(&b),
        "pw".into(),
        None,
    ))
    .unwrap();
    assert_frame(&b, 4, "maintenance.backup", json!({ "passphrase": "pw" }));

    block_on(commands::maintenance_backup_at(
        &s,
        sock(&b),
        "pw".into(),
        Some(3),
    ))
    .unwrap();
    assert_frame(
        &b,
        5,
        "maintenance.backup",
        json!({ "passphrase": "pw", "retain": 3 }),
    );
}

/// ADR-076: the root-key rotation carries only the passphrase, hands the new
/// recovery code to the screen verbatim and exactly once, and — answered with
/// the broker's *current* refusal — surfaces `presence_required` untranslated
/// without disturbing the login.
#[test]
fn maintenance_rotate_root_sends_the_passphrase_and_passes_the_recovery_code_through() {
    // What the broker answers today: presence cannot be attested.
    let b = realistic_broker();
    let s = logged_in(&b);
    let e = block_on(commands::maintenance_rotate_root_at(
        &s,
        sock(&b),
        "a long passphrase".into(),
    ))
    .expect_err("presence_required");
    assert_frame(
        &b,
        1,
        "maintenance.rotate_root",
        json!({ "passphrase": "a long passphrase" }),
    );
    assert_eq!(e.code, "presence_required");
    assert!(s.is_authenticated(), "a refused rotation is not a logout");

    // What it will answer once a transport can attest presence.
    let b = rotating_broker();
    let s = logged_in(&b);
    let v = block_on(commands::maintenance_rotate_root_at(
        &s,
        sock(&b),
        "a long passphrase".into(),
    ))
    .unwrap();
    assert_frame(
        &b,
        1,
        "maintenance.rotate_root",
        json!({ "passphrase": "a long passphrase" }),
    );
    assert_eq!(
        v["recoveryCode"], "RC-ROTATED-2222-3333",
        "shown once, so it must arrive verbatim"
    );
    assert_eq!(v["rotated"], true);
    assert_eq!(v["completionPending"], false);
    assert_eq!(v["notResigned"], json!([]));
    assert!(
        s.is_authenticated(),
        "the answer carries no `locked` flag, so it must not be read as one"
    );
    assert!(
        !serde_json::to_string(&v).unwrap().contains("cmt_"),
        "nothing token-shaped reaches the webview"
    );
}

/// ADR-087: the generator is one broker call; an option left out is left off the
/// wire (the broker's own defaults apply), and one given goes through as typed.
#[test]
fn util_generate_sends_only_the_options_it_was_given_and_returns_the_value_untouched() {
    let b = realistic_broker();
    let s = logged_in(&b);
    let v = block_on(commands::util_generate_at(
        &s,
        sock(&b),
        None,
        None,
        None,
        None,
    ))
    .unwrap();
    assert_frame(&b, 1, "util.generate", json!({}));
    assert_eq!(v["length"], 20);
    assert_eq!(v["entropyBits"], 124);
    block_on(commands::util_generate_at(
        &s,
        sock(&b),
        Some(32),
        Some(false),
        Some(true),
        None,
    ))
    .unwrap();
    assert_frame(
        &b,
        2,
        "util.generate",
        json!({ "length": 32, "symbols": false, "pronounceable": true }),
    );
    block_on(commands::util_generate_at(
        &s,
        sock(&b),
        Some(40),
        Some(false),
        None,
        Some(true),
    ))
    .unwrap();
    assert_frame(
        &b,
        3,
        "util.generate",
        json!({ "length": 40, "symbols": false, "hex": true }),
    );
    assert!(
        s.is_authenticated(),
        "the answer has no `locked`, so it is not read as one"
    );
}

/// ADR-121 / ADR-122: the three new ops send exactly their params, an option left out stays off
/// the wire, and the session is not disturbed by their answers.
#[test]
fn alias_similar_and_import_env_send_their_params_and_nothing_else() {
    let b = realistic_broker();
    let s = logged_in(&b);
    let v = block_on(commands::entry_alias_at(
        &s,
        sock(&b),
        "acme".into(),
        "e1".into(),
        7,
        json!(["stripe"]),
    ))
    .unwrap();
    assert_frame(
        &b,
        1,
        "entry.alias",
        json!({ "node": "acme", "entry": "e1", "generation": 7, "aliases": ["stripe"] }),
    );
    assert_eq!(v["aliases"], json!(["stripe"]));

    block_on(commands::entry_similar_at(
        &s,
        sock(&b),
        "acme".into(),
        "stirpe-key".into(),
        None,
    ))
    .unwrap();
    assert_frame(
        &b,
        2,
        "entry.similar",
        json!({ "node": "acme", "name": "stirpe-key" }),
    );
    block_on(commands::entry_similar_at(
        &s,
        sock(&b),
        "acme".into(),
        "stirpe-key".into(),
        Some("e1".into()),
    ))
    .unwrap();
    assert_frame(
        &b,
        3,
        "entry.similar",
        json!({ "node": "acme", "name": "stirpe-key", "entry": "e1" }),
    );

    let pairs = json!([{ "name": "A_B_C", "value": "v" }]);
    block_on(commands::entry_import_env_at(
        &s,
        sock(&b),
        "acme".into(),
        pairs.clone(),
        None,
        None,
    ))
    .unwrap();
    assert_frame(
        &b,
        4,
        "entry.import_env",
        json!({ "node": "acme", "entries": pairs }),
    );
    block_on(commands::entry_import_env_at(
        &s,
        sock(&b),
        "acme".into(),
        pairs.clone(),
        Some(true),
        Some("skip".into()),
    ))
    .unwrap();
    assert_frame(
        &b,
        5,
        "entry.import_env",
        json!({ "node": "acme", "entries": pairs, "dryRun": true, "onConflict": "skip" }),
    );
    assert!(s.is_authenticated());
}

/// The regression the op-aware `Session::reconcile_ok` exists for, over a
/// real socket: `vault.node_lock` answers `{node, locked: true}` about one
/// node, and must not end the vault-level login.
#[test]
fn locking_one_node_over_the_wire_keeps_the_login() {
    let b = realistic_broker();
    let s = logged_in(&b);

    let v = block_on(commands::vault_node_lock_at(&s, sock(&b), "acme".into())).unwrap();
    assert_eq!(
        v["locked"], true,
        "the node-level answer still reaches the UI"
    );
    assert!(
        s.is_authenticated(),
        "locking one project must not log the user out of the vault"
    );

    block_on(commands::vault_status_at(&s, sock(&b))).unwrap();
    assert_eq!(
        b.token_on(2).as_deref(),
        Some(MINTED),
        "the next call still carries the login token"
    );
}

#[test]
fn a_bootstrap_recovery_code_is_not_adopted_as_a_session() {
    let b = realistic_broker();
    let s = Session::new();
    let v = block_on(commands::vault_init_begin_at(
        &s,
        sock(&b),
        "pw pw pw pw".into(),
    ))
    .unwrap();
    assert_eq!(v["recoveryCode"], "RC-TEST-0000-1111");
    assert!(
        !s.is_authenticated(),
        "creating a vault is not logging into it — only unlock/gate_verify mint a session"
    );
    assert_eq!(b.token_on(0), None, "no session existed to attach");
}

#[test]
fn the_bootstrap_denials_reach_the_ui_in_the_brokers_own_words() {
    for (code, message) in [
        (
            "vault_already_initialized",
            "a vault already exists at this path",
        ),
        (
            "vault_inside_git_working_tree",
            "refusing to create a vault inside a git working tree",
        ),
        (
            "vault_init_not_pending",
            "no vault.init_begin is in flight, or it expired — start over",
        ),
        (
            "recovery_code_mismatch",
            "the retyped recovery code did not match",
        ),
    ] {
        let b = FakeBroker::spawn(move |_| err(code, json!({ "message": message })));
        let s = Session::new();
        let e =
            block_on(commands::vault_init_confirm_at(&s, sock(&b), "x".into())).expect_err(code);
        assert_eq!(e.code, code);
        assert_eq!(e.message, message);
        assert!(
            desktop_lib::error::BROKER_ERROR_CODES.contains(&code),
            "{code} must be in the bridge's closed vocabulary"
        );
    }
}

#[test]
fn a_conflicting_update_reaches_the_caller_with_both_generations() {
    let b = FakeBroker::spawn(|_| {
        err(
            "conflict",
            json!({ "node": "acme", "expectedGeneration": 7, "currentGeneration": 9 }),
        )
    });
    let s = Session::new();
    let e = block_on(commands::entry_update_at(
        &s,
        sock(&b),
        "acme".into(),
        "e1".into(),
        Some("v".into()),
        7,
        None,
        None,
        None,
        None,
        None,
    ))
    .expect_err("conflict");
    assert_eq!(e.code, "conflict");
    let detail = e.detail.unwrap();
    assert_eq!(detail["expectedGeneration"], 7);
    assert_eq!(detail["currentGeneration"], 9);
}

// ---- ADR-078: fields ------------------------------------------------------

/// A field list as the screen sends it: label and value, and a pin only where one exists.
fn two_fields() -> Value {
    json!([
        { "label": "host", "value": "db.example.test" },
        { "label": "password", "value": "pw-test-1", "masked": true },
    ])
}

#[test]
fn a_multi_field_create_sends_fields_and_the_pins_and_nothing_it_was_not_given() {
    let b = realistic_broker();
    let s = logged_in(&b);

    // `fields` form: no `value`, no `label` on the wire (the broker refuses both beside `fields`).
    block_on(commands::entry_create_at(
        &s,
        sock(&b),
        "acme".into(),
        "prod-db".into(),
        None,
        None,
        Some(two_fields()),
        Some("server".into()),
        Some("auto".into()),
    ))
    .unwrap();
    assert_frame(
        &b,
        1,
        "entry.create",
        json!({
            "node": "acme", "name": "prod-db", "fields": two_fields(),
            "entryType": "server", "sensitivity": "auto"
        }),
    );

    // Nothing pinned: neither override key is on the wire (the broker infers both).
    block_on(commands::entry_create_at(
        &s,
        sock(&b),
        "acme".into(),
        "plain".into(),
        None,
        None,
        Some(two_fields()),
        None,
        None,
    ))
    .unwrap();
    let frame = &b.received()[2]["params"];
    assert!(
        frame.get("entryType").is_none() && frame.get("sensitivity").is_none(),
        "{frame}"
    );
    assert!(
        frame.get("value").is_none() && frame.get("label").is_none(),
        "{frame}"
    );

    // A batch item is the same body.
    block_on(commands::entry_create_batch_at(
        &s,
        sock(&b),
        "acme".into(),
        json!([{ "name": "A", "fields": two_fields(), "entryType": "note" }]),
    ))
    .unwrap();
    assert_frame(
        &b,
        3,
        "entry.create_batch",
        json!({ "node": "acme", "entries": [{ "name": "A", "fields": two_fields(), "entryType": "note" }] }),
    );
}

#[test]
fn update_and_rotate_address_a_field_or_replace_the_list_and_send_overrides_as_given() {
    let b = realistic_broker();
    let s = logged_in(&b);

    // one field's value, by id, with a rename
    block_on(commands::entry_update_at(
        &s,
        sock(&b),
        "acme".into(),
        "e1".into(),
        Some("pw-2".into()),
        7,
        Some("secret".into()),
        Some("f_4e5f6a7b".into()),
        None,
        None,
        None,
    ))
    .unwrap();
    assert_frame(
        &b,
        1,
        "entry.update",
        json!({
            "node": "acme", "entry": "e1", "value": "pw-2", "generation": 7,
            "label": "secret", "field": "f_4e5f6a7b"
        }),
    );

    // the whole list, no `value`; an id keeps a field's identity
    let replace = json!([
        { "id": "f_0a1b2c3d", "label": "host", "value": "h2" },
        { "label": "port", "value": "5432", "type": "port" },
    ]);
    let v = block_on(commands::entry_rotate_at(
        &s,
        sock(&b),
        "acme".into(),
        "e1".into(),
        None,
        8,
        None,
        None,
        Some(replace.clone()),
        None,
        Some("critical".into()),
    ))
    .unwrap();
    assert_frame(
        &b,
        2,
        "entry.rotate",
        json!({
            "node": "acme", "entry": "e1", "generation": 8,
            "fields": replace, "sensitivity": "critical"
        }),
    );
    assert_eq!(v["rotatedAt"], 5);
    assert_eq!(v["fieldCount"], 1, "the broker's answer arrives unreshaped");
    assert_eq!(v["fieldIds"], json!(["f_0a1b2c3d"]));
}

#[test]
fn entry_get_and_the_field_operations_send_their_own_params_and_hand_back_the_brokers_body() {
    let b = realistic_broker();
    let s = logged_in(&b);

    let meta = block_on(commands::entry_get_at(
        &s,
        sock(&b),
        "acme".into(),
        "e1".into(),
    ))
    .unwrap();
    assert_frame(&b, 1, "entry.get", json!({ "node": "acme", "entry": "e1" }));
    assert_eq!(meta["fields"][1]["label"], "password");
    assert!(
        !serde_json::to_string(&meta).unwrap().contains("pw-test"),
        "entry.get carries no value"
    );

    // field.add: `position` only when given
    let added = block_on(commands::field_add_at(
        &s,
        sock(&b),
        "acme".into(),
        "e1".into(),
        7,
        json!([{ "label": "region", "value": "eu", "type": "text" }]),
        Some(0),
    ))
    .unwrap();
    assert_frame(
        &b,
        2,
        "field.add",
        json!({
            "node": "acme", "entry": "e1", "generation": 7,
            "fields": [{ "label": "region", "value": "eu", "type": "text" }], "position": 0
        }),
    );
    assert_eq!(added["added"], json!(["f_4e5f6a7b"]));
    block_on(commands::field_add_at(
        &s,
        sock(&b),
        "acme".into(),
        "e1".into(),
        8,
        json!([{ "label": "k", "value": "v" }]),
        None,
    ))
    .unwrap();
    assert!(
        b.received()[3]["params"].get("position").is_none(),
        "an omitted position is absent"
    );

    // field.update: the patch goes through verbatim, "auto" included
    block_on(commands::field_update_at(
        &s,
        sock(&b),
        "acme".into(),
        "e1".into(),
        8,
        "f_4e5f6a7b".into(),
        json!({ "label": "pass", "type": "auto", "masked": "auto" }),
    ))
    .unwrap();
    assert_frame(
        &b,
        4,
        "field.update",
        json!({
            "node": "acme", "entry": "e1", "generation": 8, "field": "f_4e5f6a7b",
            "patch": { "label": "pass", "type": "auto", "masked": "auto" }
        }),
    );

    block_on(commands::field_remove_at(
        &s,
        sock(&b),
        "acme".into(),
        "e1".into(),
        8,
        "f_4e5f6a7b".into(),
    ))
    .unwrap();
    assert_frame(
        &b,
        5,
        "field.remove",
        json!({ "node": "acme", "entry": "e1", "generation": 8, "field": "f_4e5f6a7b" }),
    );

    block_on(commands::field_reorder_at(
        &s,
        sock(&b),
        "acme".into(),
        "e1".into(),
        8,
        vec!["f_4e5f6a7b".into(), "f_0a1b2c3d".into()],
    ))
    .unwrap();
    assert_frame(
        &b,
        6,
        "field.reorder",
        json!({
            "node": "acme", "entry": "e1", "generation": 8,
            "order": ["f_4e5f6a7b", "f_0a1b2c3d"]
        }),
    );
}

#[test]
fn reveal_and_totp_name_a_field_only_when_asked_to() {
    let b = realistic_broker();
    let s = logged_in(&b);

    // no ids: nothing but node and entry on the wire
    let v = block_on(commands::entry_reveal_at(
        &s,
        sock(&b),
        "acme".into(),
        "e1".into(),
        None,
    ))
    .unwrap();
    assert_frame(
        &b,
        1,
        "entry.reveal",
        json!({ "node": "acme", "entry": "e1" }),
    );
    assert_eq!(v["fields"].as_array().unwrap().len(), 1);
    assert_eq!(v["value"], "s3cr3t", "the broker's body arrives unreshaped");

    // ids: `fieldIds`, in the broker's casing
    block_on(commands::entry_reveal_at(
        &s,
        sock(&b),
        "acme".into(),
        "e1".into(),
        Some(vec!["f_0a1b2c3d".into(), "f_4e5f6a7b".into()]),
    ))
    .unwrap();
    assert_frame(
        &b,
        2,
        "entry.reveal",
        json!({ "node": "acme", "entry": "e1", "fieldIds": ["f_0a1b2c3d", "f_4e5f6a7b"] }),
    );

    // totp: `field`
    block_on(commands::totp_code_at(
        &s,
        sock(&b),
        "acme".into(),
        "e1".into(),
        Some("f_4e5f6a7b".into()),
    ))
    .unwrap();
    assert_frame(
        &b,
        3,
        "totp.code",
        json!({ "node": "acme", "entry": "e1", "field": "f_4e5f6a7b" }),
    );
    let _ = block_on(commands::totp_seed_at(
        &s,
        sock(&b),
        "acme".into(),
        "e1".into(),
        Some("f_4e5f6a7b".into()),
    ));
    assert_frame(
        &b,
        4,
        "totp.seed",
        json!({ "node": "acme", "entry": "e1", "field": "f_4e5f6a7b" }),
    );
}

#[test]
fn a_refused_field_op_reaches_the_caller_in_the_brokers_words() {
    // The bridge adds no vocabulary: the broker's `not_found` for an unknown field and
    // its `malformed_request` for the last field arrive as they were sent.
    for (code, message) in [
        ("not_found", "no field has the id f_deadbeef"),
        (
            "malformed_request",
            "an entry keeps at least one field - remove the entry instead",
        ),
        (
            "node_locked",
            "node acme is locked; the vault itself is unlocked",
        ),
    ] {
        let b = FakeBroker::spawn(move |_| err(code, json!({ "message": message })));
        let s = Session::new();
        let e = block_on(commands::field_remove_at(
            &s,
            sock(&b),
            "acme".into(),
            "e1".into(),
            1,
            "f_deadbeef".into(),
        ))
        .expect_err(code);
        assert_eq!(e.code, code);
        assert_eq!(e.message, message);
    }
}

/// Phase 9's exit-gate line, across the full surface rather than the
/// original eight: every command, answered realistically, hands the webview
/// nothing token-shaped. (Named without a count since ADR-071 — the count
/// had to change twice in one day.)
#[test]
fn no_result_across_every_command_carries_a_token_shaped_string() {
    let b = realistic_broker();
    let s = Session::new();
    let socket = sock(&b);
    let mut results: Vec<(String, String)> = Vec::new();

    macro_rules! sweep {
        ($name:literal, $call:expr) => {{
            let rendered = match block_on($call) {
                Ok(v) => serde_json::to_string(&v).unwrap(),
                Err(e) => serde_json::to_string(&e).unwrap(),
            };
            results.push(($name.to_string(), rendered));
        }};
    }

    sweep!(
        "vault_unlock",
        commands::vault_unlock_at(&s, socket.clone(), "pw".into())
    );
    sweep!(
        "vault_gate_verify",
        commands::vault_gate_verify_at(&s, socket.clone(), "0".into())
    );
    sweep!(
        "vault_status",
        commands::vault_status_at(&s, socket.clone())
    );
    sweep!(
        "whoami",
        commands::dispatch_at(&s, socket.clone(), "whoami", json!({}))
    );
    sweep!(
        "graph_snapshot",
        commands::dispatch_at(&s, socket.clone(), "graph.snapshot", json!({}))
    );
    sweep!(
        "entry_list",
        commands::dispatch_at(&s, socket.clone(), "entry.list", json!({ "node": "a" }))
    );
    sweep!(
        "entry_reveal",
        commands::entry_reveal_at(&s, socket.clone(), "a".into(), "e".into(), None)
    );
    sweep!(
        "vault_init_begin",
        commands::vault_init_begin_at(&s, socket.clone(), "p".into())
    );
    sweep!(
        "vault_init_confirm",
        commands::vault_init_confirm_at(&s, socket.clone(), "r".into())
    );
    sweep!(
        "vault_gate_enroll_begin",
        commands::vault_gate_enroll_begin_at(&s, socket.clone())
    );
    sweep!(
        "vault_gate_enroll_confirm",
        commands::vault_gate_enroll_confirm_at(&s, socket.clone(), "1".into())
    );
    sweep!(
        "vault_pending_list",
        commands::vault_pending_list_at(&s, socket.clone(), "a".into())
    );
    sweep!(
        "vault_pending_accept",
        commands::vault_pending_accept_at(&s, socket.clone(), "a".into(), "e".into())
    );
    sweep!(
        "vault_pending_discard",
        commands::vault_pending_discard_at(&s, socket.clone(), "a".into(), "e".into())
    );
    sweep!(
        "vault_approval_decide",
        commands::vault_approval_decide_at(&s, socket.clone(), "q".into(), true, None, None)
    );
    sweep!(
        "vault_approval_get",
        commands::vault_approval_get_at(&s, socket.clone(), None)
    );
    sweep!(
        "vault_node_lock",
        commands::vault_node_lock_at(&s, socket.clone(), "a".into())
    );
    sweep!(
        "vault_node_unlock",
        commands::vault_node_unlock_at(&s, socket.clone(), "a".into())
    );
    sweep!("node_list", commands::node_list_at(&s, socket.clone()));
    sweep!(
        "node_create",
        commands::node_create_at(&s, socket.clone(), "i".into(), "l".into(), "p".into(), None)
    );
    sweep!(
        "node_set_workdirs",
        commands::node_set_workdirs_at(&s, socket.clone(), "a".into(), vec![])
    );
    sweep!(
        "node_update",
        commands::node_update_at(&s, socket.clone(), "a".into(), "l".into())
    );
    sweep!(
        "entry_create_batch",
        commands::entry_create_batch_at(
            &s,
            socket.clone(),
            "a".into(),
            json!([{ "name": "A", "value": "1" }])
        )
    );
    sweep!(
        "notes_read",
        commands::notes_read_at(&s, socket.clone(), "a".into())
    );
    sweep!(
        "notes_write",
        commands::notes_write_at(&s, socket.clone(), "a".into(), "m".into(), 0)
    );
    sweep!(
        "node_policy",
        commands::node_policy_at(&s, socket.clone(), "a".into(), "r".into(), json!({}))
    );
    sweep!(
        "settings_list",
        commands::settings_list_at(&s, socket.clone(), None)
    );
    sweep!(
        "settings_get",
        commands::settings_get_at(&s, socket.clone(), "app.theme".into(), None)
    );
    sweep!(
        "settings_set",
        commands::settings_set_at(
            &s,
            socket.clone(),
            "app.theme".into(),
            json!("dark"),
            "r".into(),
            None
        )
    );
    sweep!(
        "settings_revert",
        commands::settings_revert_at(&s, socket.clone(), "sc-1".into(), None)
    );
    sweep!(
        "settings_request_get",
        commands::settings_request_get_at(&s, socket.clone(), "sr-1".into())
    );
    sweep!(
        "settings_request_list",
        commands::settings_request_list_at(&s, socket.clone())
    );
    sweep!(
        "settings_request_decide",
        commands::settings_request_decide_at(&s, socket.clone(), "sr-1".into(), false)
    );
    sweep!("settings_kb", commands::settings_kb_at(&s, socket.clone()));
    sweep!(
        "vault_gate_recover",
        commands::vault_gate_recover_at(&s, socket.clone(), "p".into(), "r".into())
    );
    sweep!(
        "node_seal",
        commands::node_seal_at(&s, socket.clone(), "a".into())
    );
    sweep!(
        "node_restore",
        commands::node_restore_at(&s, socket.clone(), "a".into())
    );
    sweep!(
        "node_reparent",
        commands::node_reparent_at(&s, socket.clone(), "a".into(), "b".into(), "r".into())
    );
    sweep!("grant_list", commands::grant_list_at(&s, socket.clone()));
    sweep!(
        "grant_create",
        commands::grant_create_at(
            &s,
            socket.clone(),
            "a".into(),
            json!({}),
            vec![],
            "r".into(),
            None,
            None
        )
    );
    sweep!(
        "grant_revoke",
        commands::grant_revoke_at(&s, socket.clone(), "g".into())
    );
    sweep!(
        "entry_create",
        commands::entry_create_at(
            &s,
            socket.clone(),
            "a".into(),
            "n".into(),
            Some("v".into()),
            None,
            None,
            None,
            None
        )
    );
    sweep!(
        "entry_update",
        commands::entry_update_at(
            &s,
            socket.clone(),
            "a".into(),
            "e".into(),
            Some("v".into()),
            1,
            None,
            None,
            None,
            None,
            None
        )
    );
    sweep!(
        "entry_rotate",
        commands::entry_rotate_at(
            &s,
            socket.clone(),
            "a".into(),
            "e".into(),
            Some("v".into()),
            1,
            None,
            None,
            None,
            None,
            None
        )
    );
    sweep!(
        "entry_get",
        commands::entry_get_at(&s, socket.clone(), "a".into(), "e".into())
    );
    sweep!(
        "field_add",
        commands::field_add_at(
            &s,
            socket.clone(),
            "a".into(),
            "e".into(),
            1,
            json!([{ "label": "l", "value": "v" }]),
            None
        )
    );
    sweep!(
        "field_update",
        commands::field_update_at(
            &s,
            socket.clone(),
            "a".into(),
            "e".into(),
            1,
            "f_0a1b2c3d".into(),
            json!({ "label": "l" })
        )
    );
    sweep!(
        "field_remove",
        commands::field_remove_at(&s, socket.clone(), "a".into(), "e".into(), 1, "f".into())
    );
    sweep!(
        "field_reorder",
        commands::field_reorder_at(
            &s,
            socket.clone(),
            "a".into(),
            "e".into(),
            1,
            vec!["f_0a1b2c3d".into()]
        )
    );
    sweep!(
        "entry_remove",
        commands::entry_remove_at(&s, socket.clone(), "a".into(), "e".into(), 1)
    );
    sweep!(
        "entry_restore",
        commands::entry_restore_at(&s, socket.clone(), "a".into(), "e".into(), 1, None)
    );
    sweep!(
        "entry_undo",
        commands::entry_undo_at(&s, socket.clone(), "a".into(), "r".into(), 1, None)
    );
    sweep!(
        "totp_code",
        commands::totp_code_at(&s, socket.clone(), "a".into(), "e".into(), None)
    );
    sweep!(
        "totp_seed",
        commands::totp_seed_at(&s, socket.clone(), "a".into(), "e".into(), None)
    );
    sweep!(
        "search",
        commands::search_at(&s, socket.clone(), "t".into())
    );
    sweep!(
        "audit_tail",
        commands::audit_tail_at(&s, socket.clone(), None)
    );
    sweep!(
        "audit_get",
        commands::audit_get_at(&s, socket.clone(), "r".into())
    );
    sweep!(
        "maintenance_verify",
        commands::maintenance_verify_at(&s, socket.clone())
    );
    sweep!(
        "maintenance_doctor",
        commands::maintenance_doctor_at(&s, socket.clone(), None, None, None, None)
    );
    sweep!(
        "maintenance_backup",
        commands::maintenance_backup_at(&s, socket.clone(), "p".into(), None)
    );
    sweep!(
        "util_generate",
        commands::util_generate_at(&s, socket.clone(), None, None, None, None)
    );
    sweep!(
        "entry_alias",
        commands::entry_alias_at(&s, socket.clone(), "acme".into(), "e1".into(), 7, json!([]))
    );
    sweep!(
        "entry_similar",
        commands::entry_similar_at(&s, socket.clone(), "acme".into(), "x".into(), None)
    );
    sweep!(
        "entry_import_env",
        commands::entry_import_env_at(&s, socket.clone(), "acme".into(), json!([]), None, None)
    );
    sweep!(
        "maintenance_rotate_root",
        commands::maintenance_rotate_root_at(&s, socket.clone(), "p".into())
    );
    sweep!(
        "vault_set_passphrase",
        commands::vault_set_passphrase_at(&s, socket.clone(), "p".into(), "q".into())
    );
    sweep!(
        "vault_recover",
        commands::vault_recover_at(&s, socket.clone(), "r".into(), "q".into(), None)
    );
    sweep!(
        "vault_anomalies_ack",
        commands::vault_anomalies_ack_at(&s, socket.clone())
    );
    sweep!(
        "entry_set_expiry",
        commands::entry_set_expiry_at(
            &s,
            socket.clone(),
            "acme".into(),
            "e1".into(),
            7,
            Some(1),
            None
        )
    );
    sweep!(
        "entry_expiring",
        commands::entry_expiring_at(&s, socket.clone(), None, None)
    );
    sweep!(
        "entry_history",
        commands::entry_history_at(&s, socket.clone(), "acme".into(), "e1".into(), None)
    );
    sweep!(
        "entry_search",
        commands::entry_search_at(&s, socket.clone(), "acme".into(), "k".into(), None)
    );
    sweep!(
        "entry_get_by_ref",
        commands::entry_get_by_ref_at(&s, socket.clone(), 1000)
    );
    sweep!(
        "vault_doctor_scan",
        commands::vault_doctor_scan_at(&s, socket.clone(), None, None)
    );
    sweep!(
        "entry_tag_set",
        commands::entry_tag_set_at(&s, socket.clone(), "acme".into(), "e1".into(), 7, json!([]))
    );
    sweep!(
        "merge_suggestions",
        commands::merge_suggestions_at(&s, socket.clone(), "acme".into(), None)
    );
    sweep!(
        "merge_apply",
        commands::merge_apply_at(
            &s,
            socket.clone(),
            "acme".into(),
            "e1".into(),
            json!(["e2"]),
            7
        )
    );
    sweep!(
        "merge_auto",
        commands::merge_auto_at(&s, socket.clone(), "acme".into(), "e1+e2".into(), 7)
    );
    sweep!(
        "merge_auto_all",
        commands::merge_auto_all_at(&s, socket.clone(), "acme".into(), None, None)
    );
    sweep!(
        "merge_dismiss",
        commands::merge_dismiss_at(&s, socket.clone(), "acme".into(), "e1+e2".into())
    );
    sweep!(
        "merge_undismiss",
        commands::merge_undismiss_at(&s, socket.clone(), "acme".into(), "e1+e2".into())
    );
    sweep!(
        "merge_dismissed_list",
        commands::merge_dismissed_list_at(&s, socket.clone(), "acme".into())
    );
    sweep!(
        "merge_restore_all",
        commands::merge_restore_all_at(&s, socket.clone(), "acme".into())
    );
    sweep!(
        "vault_doctor_apply",
        commands::vault_doctor_apply_at(
            &s,
            socket.clone(),
            json!([{ "node": "acme-web", "entry": "e1", "to": "acme", "generation": 3 }]),
            None
        )
    );
    sweep!(
        "entry_move",
        commands::entry_move_at(
            &s,
            socket.clone(),
            "acme".into(),
            "e1".into(),
            "beta".into(),
            7,
            None
        )
    );
    sweep!(
        "presence_status",
        commands::presence_status_at(&s, socket.clone())
    );
    sweep!(
        "session_confirm",
        commands::session_confirm_at(&s, socket.clone(), Some("p".into()))
    );
    sweep!(
        "presence_challenge",
        commands::presence_challenge_at(&s, socket.clone(), "audit.get".into(), None, None)
    );
    sweep!(
        "presence_enrol",
        commands::presence_enrol_at(&s, socket.clone(), "k".into(), None)
    );
    sweep!(
        "presence_unenrol",
        commands::presence_unenrol_at(&s, socket.clone(), "i".into())
    );
    sweep!(
        "device_enrol",
        commands::device_enrol_at(&s, socket.clone())
    );
    sweep!(
        "device_remove",
        commands::device_remove_at(&s, socket.clone())
    );
    sweep!(
        "keystore_status",
        commands::keystore_status_at(&s, socket.clone())
    );
    sweep!(
        "keystore_bind",
        commands::keystore_bind_at(
            &s,
            socket.clone(),
            "prepare".into(),
            Some("p".into()),
            Some("r".into())
        )
    );
    sweep!(
        "keystore_unbind",
        commands::keystore_unbind_at(&s, socket.clone(), None)
    );
    sweep!("orphan_list", commands::orphan_list_at(&s, socket.clone()));
    sweep!(
        "orphan_reveal",
        commands::orphan_reveal_at(&s, socket.clone(), "e".into(), None)
    );
    sweep!(
        "node_rekey",
        commands::node_rekey_at(&s, socket.clone(), "n".into())
    );
    sweep!(
        "orphan_destroy",
        commands::orphan_destroy_at(&s, socket.clone(), "c".into(), 0, None)
    );
    sweep!(
        "search_content",
        commands::search_content_at(&s, socket.clone(), "t".into(), None)
    );
    sweep!(
        "node_export",
        commands::node_export_at(&s, socket.clone(), "n".into(), None, None)
    );
    sweep!(
        "audit_report",
        commands::audit_report_at(&s, socket.clone(), 0, 1, None)
    );
    sweep!(
        "node_gate_enroll_begin",
        commands::node_gate_enroll_begin_at(&s, socket.clone(), "n".into())
    );
    sweep!(
        "node_gate_enroll_confirm",
        commands::node_gate_enroll_confirm_at(&s, socket.clone(), "n".into(), "c".into())
    );
    sweep!(
        "node_gate_verify",
        commands::node_gate_verify_at(&s, socket.clone(), "n".into(), "c".into())
    );
    sweep!(
        "node_gate_remove",
        commands::node_gate_remove_at(&s, socket.clone(), "n".into(), None, None)
    );
    // ADR-164: the two that carry a bearer hand it to the clipboard, not the webview.
    let board = Arc::new(FakePasteboard::default());
    let clipboard = Clipboard::with(board.clone(), Duration::from_secs(30));
    sweep!(
        "agent_token_issue",
        commands::agent_token_issue_at(
            &s,
            &clipboard,
            socket.clone(),
            "acme".into(),
            "ci".into(),
            vec!["list".into()],
            None
        )
    );
    sweep!(
        "agent_token_status",
        commands::agent_token_status_at(&s, socket.clone(), None)
    );
    sweep!(
        "agent_token_rotate",
        commands::agent_token_rotate_at(&s, &clipboard, socket.clone(), "a_1".into(), None)
    );
    sweep!(
        "agent_token_revoke",
        commands::agent_token_revoke_at(&s, socket.clone(), "a_1".into())
    );
    assert_eq!(board.text().as_deref(), Some(AGENT_BEARER));
    assert!(board.snapshot().concealed);
    // `vault_lock` last: it ends the session the sweep ran under.
    sweep!("vault_lock", commands::vault_lock_at(&s, socket.clone()));

    // Every bridged command, and nothing else, was swept.
    let mut swept: Vec<&str> = results.iter().map(|(n, _)| n.as_str()).collect();
    swept.sort_unstable();
    let mut expected: Vec<&str> = commands::bridged().map(|b| b.command).collect();
    expected.sort_unstable();
    assert_eq!(
        swept, expected,
        "the sweep must cover exactly the bridged surface"
    );

    for (name, rendered) in &results {
        assert!(
            !rendered.contains("broker_unreachable"),
            "{name} met a dead broker, so the sweep proved nothing for it: {rendered}"
        );
        assert!(
            !rendered.contains("cmt_"),
            "{name} handed the webview a token: {rendered}"
        );
        assert!(
            !rendered.contains("\"token\""),
            "{name} handed the webview a `token` field: {rendered}"
        );
        assert!(
            !rendered.contains("cma_"),
            "{name} handed the webview an agent token: {rendered}"
        );
    }
    assert!(!s.is_authenticated(), "vault_lock ended the session");
}

#[test]
fn the_quick_win_commands_send_their_own_params_and_omit_every_unset_option() {
    // ADR-156.
    let broker = realistic_broker();
    let s = logged_in(&broker);
    block_on(commands::vault_set_passphrase_at(
        &s,
        sock(&broker),
        "old".into(),
        "new".into(),
    ))
    .unwrap();
    assert_frame(
        &broker,
        1,
        "vault.set_passphrase",
        json!({ "passphrase": "old", "newPassphrase": "new" }),
    );
    block_on(commands::entry_set_expiry_at(
        &s,
        sock(&broker),
        "acme".into(),
        "e1".into(),
        7,
        Some(1_900_000_000),
        None,
    ))
    .unwrap();
    assert_frame(
        &broker,
        2,
        "entry.set_expiry",
        json!({ "node": "acme", "entry": "e1", "generation": 7, "expiresAt": 1_900_000_000 }),
    );
    block_on(commands::entry_set_expiry_at(
        &s,
        sock(&broker),
        "acme".into(),
        "e1".into(),
        8,
        None,
        Some(true),
    ))
    .unwrap();
    assert_frame(
        &broker,
        3,
        "entry.set_expiry",
        json!({ "node": "acme", "entry": "e1", "generation": 8, "clear": true }),
    );
    block_on(commands::entry_expiring_at(
        &s,
        sock(&broker),
        None,
        Some(7),
    ))
    .unwrap();
    assert_frame(&broker, 4, "entry.expiring", json!({ "days": 7 }));
    block_on(commands::entry_history_at(
        &s,
        sock(&broker),
        "acme".into(),
        "e1".into(),
        None,
    ))
    .unwrap();
    assert_frame(
        &broker,
        5,
        "entry.history",
        json!({ "node": "acme", "entry": "e1" }),
    );
    block_on(commands::entry_search_at(
        &s,
        sock(&broker),
        "acme".into(),
        "str".into(),
        None,
    ))
    .unwrap();
    assert_frame(
        &broker,
        6,
        "entry.search",
        json!({ "node": "acme", "term": "str" }),
    );
    let r = block_on(commands::entry_get_by_ref_at(&s, sock(&broker), 1000)).unwrap();
    assert_frame(&broker, 7, "entry.get_by_ref", json!({ "reference": 1000 }));
    assert_eq!(r["entry"], "e1");
    block_on(commands::vault_anomalies_ack_at(&s, sock(&broker))).unwrap();
    assert_frame(&broker, 8, "vault.anomalies_ack", json!({}));
}

#[test]
fn entry_move_sends_its_own_params_omits_an_unset_reason_and_passes_the_audit_id_through() {
    // ADR-158.
    let broker = realistic_broker();
    let s = logged_in(&broker);
    let r = block_on(commands::entry_move_at(
        &s,
        sock(&broker),
        "acme".into(),
        "e1".into(),
        "beta".into(),
        7,
        None,
    ))
    .unwrap();
    assert_frame(
        &broker,
        1,
        "entry.move",
        json!({ "node": "acme", "entry": "e1", "to": "beta", "generation": 7 }),
    );
    assert_eq!(r["node"], "beta");
    assert_eq!(r["toGeneration"], 4);
    block_on(commands::entry_move_at(
        &s,
        sock(&broker),
        "acme".into(),
        "e1".into(),
        "beta".into(),
        8,
        Some("doctor:plan-1".into()),
    ))
    .unwrap();
    assert_frame(
        &broker,
        2,
        "entry.move",
        json!({ "node": "acme", "entry": "e1", "to": "beta", "generation": 8, "reason": "doctor:plan-1" }),
    );
    assert!(
        desktop_lib::commands::AUDIT_PASSTHROUGH.contains(&"entry.move"),
        "a move changes the vault, so its answer carries its audit id"
    );
}

#[test]
fn vault_doctor_scan_sends_only_the_windows_it_is_given_and_answers_the_report_as_is() {
    // ADR-161.
    let broker = realistic_broker();
    let s = logged_in(&broker);
    let r = block_on(commands::vault_doctor_scan_at(
        &s,
        sock(&broker),
        None,
        None,
    ))
    .unwrap();
    assert_frame(&broker, 1, "vault.doctor_scan", json!({}));
    assert_eq!(r["findings"][0]["proposal"]["move"]["to"], "acme");
    block_on(commands::vault_doctor_scan_at(
        &s,
        sock(&broker),
        Some(90),
        Some(7),
    ))
    .unwrap();
    assert_frame(
        &broker,
        2,
        "vault.doctor_scan",
        json!({ "staleDays": 90, "expiringDays": 7 }),
    );
    assert!(
        !desktop_lib::commands::AUDIT_PASSTHROUGH.contains(&"vault.doctor_scan"),
        "a scan is a read: its answer keeps the broker's shape"
    );
}

#[test]
fn the_machine_lock_commands_send_the_passphrase_and_current_recovery_code_and_omit_an_unset_one() {
    // ADR-165 review P1-1: bind's prepare proves the passphrase AND the current recovery code. Review N1: its
    // commit sends only the new code typed back, and its cancel nothing else. Unbind sends a passphrase only
    // when the screen asked for one (nothing enrolled).
    let broker = realistic_broker();
    let s = logged_in(&broker);
    block_on(commands::keystore_bind_at(
        &s,
        sock(&broker),
        "prepare".into(),
        Some("pw".into()),
        Some("code".into()),
    ))
    .unwrap();
    assert_frame(
        &broker,
        1,
        "keystore.bind",
        json!({ "phase": "prepare", "passphrase": "pw", "recoveryCode": "code" }),
    );
    block_on(commands::keystore_bind_at(
        &s,
        sock(&broker),
        "commit".into(),
        None,
        Some("new".into()),
    ))
    .unwrap();
    assert_frame(
        &broker,
        2,
        "keystore.bind",
        json!({ "phase": "commit", "recoveryCode": "new" }),
    );
    block_on(commands::keystore_bind_at(
        &s,
        sock(&broker),
        "cancel".into(),
        None,
        None,
    ))
    .unwrap();
    assert_frame(&broker, 3, "keystore.bind", json!({ "phase": "cancel" }));
    block_on(commands::keystore_unbind_at(&s, sock(&broker), None)).unwrap();
    assert_frame(&broker, 4, "keystore.unbind", json!({}));
    block_on(commands::keystore_unbind_at(
        &s,
        sock(&broker),
        Some("pw".into()),
    ))
    .unwrap();
    assert_frame(&broker, 5, "keystore.unbind", json!({ "passphrase": "pw" }));
}

#[test]
fn recover_sends_its_own_params_keeps_the_login_token_and_hands_back_the_new_code() {
    // ADR-163. Nobody is logged in yet: the recovery IS the login.
    let broker = realistic_broker();
    let s = Session::new();
    let v = block_on(commands::vault_recover_at(
        &s,
        sock(&broker),
        "RC-OLD".into(),
        "new passphrase".into(),
        None,
    ))
    .unwrap();
    let frame = &broker.received()[0];
    assert_eq!(frame["op"], "vault.recover");
    assert_eq!(
        frame["params"],
        json!({ "recoveryCode": "RC-OLD", "newPassphrase": "new passphrase" }),
        "an unset second factor is left off the wire"
    );
    assert_eq!(
        broker.token_on(0),
        None,
        "the recovery mints the token; it cannot present one"
    );
    assert!(
        s.is_authenticated(),
        "the token the recovery minted is held by the bridge"
    );
    assert!(
        v.get("token").is_none(),
        "the token never reaches the webview: {v}"
    );
    assert_eq!(v["recoveryCode"], "RC-RECOVERED-6666-7777");
    assert_eq!(v["passphraseChanged"], true);

    // With the second factor, it is sent as `code`; the next call carries the captured token.
    block_on(commands::vault_recover_at(
        &s,
        sock(&broker),
        "RC-OLD".into(),
        "new passphrase".into(),
        Some("123456".into()),
    ))
    .unwrap();
    assert_frame(
        &broker,
        1,
        "vault.recover",
        json!({ "recoveryCode": "RC-OLD", "newPassphrase": "new passphrase", "code": "123456" }),
    );
}

/// ADR-164: an issued or rotated agent token goes to the concealed, self-clearing clipboard and is
/// taken off the answer; the webview gets the metadata, `copied` and the clock. The wire frame is
/// exactly the caller's params, with an omitted expiry left out.
#[test]
fn an_agent_token_goes_to_the_concealed_clipboard_never_to_the_webview() {
    let b = realistic_broker();
    let s = logged_in(&b);
    let board = Arc::new(FakePasteboard::default());
    let clipboard = Clipboard::with(board.clone(), Duration::from_secs(30));

    let v = block_on(commands::agent_token_issue_at(
        &s,
        &clipboard,
        sock(&b),
        "acme".into(),
        "ci".into(),
        vec!["list".into(), "read".into()],
        Some(3600),
    ))
    .unwrap();
    assert_frame(
        &b,
        1,
        "agent.token_issue",
        json!({ "node": "acme", "label": "ci", "capabilities": ["list", "read"], "expiresIn": 3600 }),
    );
    assert!(
        v.get("token").is_none() && v.get("shownOnce").is_none(),
        "{v}"
    );
    assert_eq!(v["copied"], json!(true));
    assert_eq!(v["clearAfterSeconds"], json!(30));
    assert_eq!(v["id"], json!("a_00000000000000a1"));
    let pasted = board.snapshot();
    assert_eq!(pasted.text.as_deref(), Some(AGENT_BEARER));
    assert!(pasted.concealed, "an agent token is copied as a secret");

    board.external_copy("something else");
    let v = block_on(commands::agent_token_rotate_at(
        &s,
        &clipboard,
        sock(&b),
        "a_00000000000000a1".into(),
        None,
    ))
    .unwrap();
    assert_frame(
        &b,
        2,
        "agent.token_rotate",
        json!({ "id": "a_00000000000000a1" }),
    );
    assert!(!serde_json::to_string(&v).unwrap().contains("cma_"), "{v}");
    assert_eq!(v["copied"], json!(true));
    assert_eq!(board.text().as_deref(), Some(AGENT_BEARER));
}

/// ADR-164: a lock between asking and answering means nobody may hold the new token, so the shell
/// writes nothing, revokes the token at once and says so.
#[test]
fn an_agent_token_that_cannot_be_copied_is_revoked_not_shown() {
    let b = realistic_broker();
    let s = logged_in(&b);
    let board = Arc::new(FakePasteboard::default());
    let clipboard = Clipboard::with(board.clone(), Duration::from_secs(30));
    // A token that is not text is refused before anything is copied.
    let odd = FakeBroker::spawn(|request| match request["op"].as_str().unwrap_or_default() {
        "agent.token_issue" => ok(json!({ "id": "a_1", "token": 7 })),
        op => ok(realistic(op)),
    });
    let e = block_on(commands::agent_token_issue_at(
        &s,
        &clipboard,
        sock(&odd),
        "acme".into(),
        "ci".into(),
        vec!["list".into()],
        None,
    ))
    .unwrap_err();
    assert!(!serde_json::to_string(&e).unwrap().contains("\"token\""));
    assert_eq!(board.snapshot().writes, 0);

    // Review P2-4: the same answer naming a real id is revoked even though nothing could be copied.
    let odd_named = FakeBroker::spawn(|request| match request["op"].as_str().unwrap_or_default() {
        "agent.token_issue" => ok(json!({ "id": "a_00000000000000a1", "token": 7 })),
        op => ok(realistic(op)),
    });
    let e = block_on(commands::agent_token_issue_at(
        &s,
        &clipboard,
        sock(&odd_named),
        "acme".into(),
        "ci".into(),
        vec!["list".into()],
        None,
    ))
    .unwrap_err();
    assert!(e.message.contains("revoked"), "{e:?}");
    let ops: Vec<String> = (0..odd_named.received().len())
        .filter_map(|i| odd_named.op_on(i))
        .collect();
    assert_eq!(ops, ["agent.token_issue", "agent.token_revoke"]);
    assert_eq!(board.snapshot().writes, 0);

    // A real lock while the broker answers: the ticket taken before dispatch is stale by the time
    // the answer arrives, so the copy is refused, and the lock also ended the login, so the broker
    // refuses the revoke the way the real one does (`session_expired`). The shell must not claim it
    // revoked anything; it keeps the id and revokes it with the next login.
    let racing = Arc::new(Clipboard::with(board.clone(), Duration::from_secs(30)));
    let lock_on_issue = racing.clone();
    let locked = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let locked_in_broker = locked.clone();
    let slow = FakeBroker::spawn(
        move |request| match request["op"].as_str().unwrap_or_default() {
            "agent.token_issue" => {
                lock_on_issue.clear_if_owned();
                locked_in_broker.store(true, std::sync::atomic::Ordering::SeqCst);
                ok(realistic("agent.token_issue"))
            }
            "vault.unlock" => {
                locked_in_broker.store(false, std::sync::atomic::Ordering::SeqCst);
                ok(realistic("vault.unlock"))
            }
            "agent.token_revoke" if locked_in_broker.load(std::sync::atomic::Ordering::SeqCst) => {
                err("session_expired", json!({}))
            }
            op => ok(realistic(op)),
        },
    );
    let v = block_on(commands::agent_token_issue_at(
        &s,
        &racing,
        sock(&slow),
        "acme".into(),
        "ci".into(),
        vec!["list".into()],
        None,
    ))
    .unwrap();
    assert_eq!(v["copied"], json!(false), "{v}");
    assert_eq!(
        v["revoked"],
        json!(false),
        "a refused revoke is not reported as done: {v}"
    );
    assert_eq!(v["revokePending"], json!(true), "{v}");
    assert!(v.get("token").is_none(), "{v}");
    assert_eq!(board.snapshot().writes, 0, "nothing reached the pasteboard");
    assert!(locked.load(std::sync::atomic::Ordering::SeqCst));
    let ops: Vec<String> = (0..slow.received().len())
        .filter_map(|i| slow.op_on(i))
        .collect();
    assert_eq!(ops, ["agent.token_issue", "agent.token_revoke"]);

    // The next login revokes it, and only once.
    // The queue lives on the session that minted the token.
    block_on(commands::vault_unlock_at(&s, sock(&slow), "pw".into())).expect("unlock");
    let ops: Vec<String> = (0..slow.received().len())
        .filter_map(|i| slow.op_on(i))
        .collect();
    assert_eq!(
        ops,
        [
            "agent.token_issue",
            "agent.token_revoke",
            "vault.unlock",
            "agent.token_revoke"
        ]
    );
    let last = slow.received().len() - 1;
    assert_frame(
        &slow,
        last,
        "agent.token_revoke",
        json!({ "id": "a_00000000000000a1" }),
    );
    block_on(commands::vault_unlock_at(&s, sock(&slow), "pw".into())).expect("unlock");
    assert_eq!(
        slow.received().len(),
        last + 2,
        "the queue is empty after a revoke"
    );
}

#[test]
fn vault_doctor_apply_sends_the_plan_verbatim_omits_an_unset_reason_and_passes_the_audit_id_through(
) {
    // ADR-169.
    let broker = realistic_broker();
    let s = logged_in(&broker);
    let plan = json!([
        { "node": "acme-web", "entry": "e1", "to": "acme", "generation": 3 },
        { "node": "global", "entry": "e2", "to": "acme", "generation": 11 }
    ]);
    let r = block_on(commands::vault_doctor_apply_at(
        &s,
        sock(&broker),
        plan.clone(),
        None,
    ))
    .unwrap();
    assert_frame(&broker, 1, "vault.doctor_apply", json!({ "moves": plan }));
    assert_eq!(r["complete"], true);
    assert_eq!(r["applied"][0]["toGeneration"], 9);
    block_on(commands::vault_doctor_apply_at(
        &s,
        sock(&broker),
        plan.clone(),
        Some("doctor:apply".into()),
    ))
    .unwrap();
    assert_frame(
        &broker,
        2,
        "vault.doctor_apply",
        json!({ "moves": plan, "reason": "doctor:apply" }),
    );
    assert!(
        desktop_lib::commands::AUDIT_PASSTHROUGH.contains(&"vault.doctor_apply"),
        "applying a plan changes the vault, so its answer carries its audit id"
    );
}
