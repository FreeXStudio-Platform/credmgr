/**
 * The drift guard: the shim's command -> op table must agree with `src-tauri/src/commands.rs`, in both directions.
 *
 *   node --test tests/real/drift-guard.test.mjs        (npm run test:real runs it before the browser suite)
 *
 * It needs neither a browser nor a Rust build: the Rust side is read as text. It also needs no daemon.
 *
 * Why it exists: the real-broker journeys drive the app through a Node re-implementation of the Tauri shell. If that
 * re-implementation drifted from the real shell (a command renamed, an argument added, an op changed) the journeys could pass
 * against a mapping the shipped app does not have. This test is what keeps the shim honest, and the canaries at the bottom prove
 * it can fail: each one breaks one thing in a copy and requires the comparison to say so.
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { LOCAL_CODES_USED } from "./shim/bridge-error.mjs";
import { BRIDGE_TS, COMMANDS_RS, OPS_RS, readBridgeInvokes, readBrokerOps, readShellSurface } from "./shim/commands-rs.mjs";
import { compareSurfaces } from "./shim/drift.mjs";
import { BROKER_COMMANDS, CLIPBOARD_CLEAR_AFTER_SECONDS, COPY_TEXT_MAX_BYTES, SESSION_ENDED_CODES, SHELL_COMMANDS, VAULT_STATE_OPS } from "./shim/table.mjs";

const clone = (v) => JSON.parse(JSON.stringify(v));

const shimSide = () => ({
  broker: clone(BROKER_COMMANDS),
  shell: clone(SHELL_COMMANDS),
  vaultStateOps: [...VAULT_STATE_OPS],
  sessionEndedCodes: [...SESSION_ENDED_CODES],
  copyTextMaxBytes: COPY_TEXT_MAX_BYTES,
  clipboardTtlSeconds: CLIPBOARD_CLEAR_AFTER_SECONDS,
  localCodesUsed: [...LOCAL_CODES_USED],
});

const rustSide = () => readShellSurface();
const brokerOps = () => readBrokerOps();
const invokes = () => readBridgeInvokes();

test("the shim's command table agrees with commands.rs, ops.rs and bridge.ts", () => {
  const findings = compareSurfaces(shimSide(), rustSide(), brokerOps(), invokes());
  assert.deepEqual(findings, [], `the shim has drifted from the Tauri shell:\n  - ${findings.join("\n  - ")}`);
});

test("the table is the size the shell says it is: 111 broker commands + 18 shell commands, 111 dispatched ops", () => {
  // Pinned so that a lost row cannot hide behind a parser that quietly reads fewer rows on both sides.
  // 111 = 11 hand-written + 100 generated (commands.rs asserts the same in its own unit test; 76 before ADR-155's eight settings
  // commands, 84 before ADR-156's seven, then ADR-158's entry_move, ADR-161's vault_doctor_scan, ADR-163's hand-written
  // vault_recover, ADR-164's four agent_token_* (issue and rotate hand-written, for the clipboard hand-over), ADR-165's three
  // keystore_*, ADR-167's entry_tag_set, ADR-168's eight merge_* and ADR-169's vault_doctor_apply). The shell commands add no op:
  // entry_copy wraps entry.reveal, which entry_reveal already carries, and the rest are local (window_state, ADR-156's three
  // login_agent_* among them); the typed client invokes every command once: 111 + 18 (ADR-166 added backup_restore, local).
  assert.equal(BROKER_COMMANDS.length, 111);
  assert.equal(SHELL_COMMANDS.length, 18);
  assert.equal(rustSide().broker.length, 111);
  assert.equal(rustSide().shell.length, 18);
  assert.equal(brokerOps().length, 111);
  assert.equal(invokes().length, 129);
});

test("the shim's six app icons are the shell's six (src-tauri/src/icon.rs MARK_IDS)", async () => {
  const { readFileSync } = await import("node:fs");
  const { APP_ICON_IDS } = await import("./shim/table.mjs");
  const src = readFileSync(new URL("../../src-tauri/src/icon.rs", import.meta.url), "utf8");
  const ids = [...(/pub const MARK_IDS:[^=]*=\s*&\[([^\]]*)\]/.exec(src)?.[1] ?? "").matchAll(/"(\w+)"/g)].map((m) => m[1]);
  assert.deepEqual(ids, APP_ICON_IDS);
});

// ── canaries: each breaks one thing and the comparison must object ────────────────────────────────────────────────────────────

function mustObject(name, mutate, expectText) {
  test(`canary: ${name}`, () => {
    const { shim, rust, ops, inv } = { shim: shimSide(), rust: rustSide(), ops: brokerOps(), inv: invokes() };
    const mutated = mutate({ shim, rust, ops, inv }) ?? { shim, rust, ops, inv };
    const findings = compareSurfaces(mutated.shim, mutated.rust, mutated.ops, mutated.inv);
    assert.ok(findings.length > 0, `the guard did not notice: ${name}`);
    if (expectText) assert.ok(findings.some((f) => f.includes(expectText)), `expected a finding mentioning ${expectText}, got:\n  - ${findings.join("\n  - ")}`);
  });
}

mustObject("a command renamed in the shim table", ({ shim }) => {
  shim.broker.find((r) => r.command === "entry_update").command = "entry_edit";
}, "entry_update");
mustObject("a command removed from the shim table", ({ shim }) => {
  shim.broker = shim.broker.filter((r) => r.command !== "vault_node_lock");
}, "vault_node_lock");
mustObject("a command only the shim has", ({ shim }) => {
  shim.broker.push({ command: "vault_wipe", op: "vault.wipe", params: [] });
}, "vault_wipe");
mustObject("an op changed in the shim table", ({ shim }) => {
  shim.broker.find((r) => r.command === "notes_write").op = "notes.put";
}, "notes_write");
mustObject("an argument dropped", ({ shim }) => {
  shim.broker.find((r) => r.command === "entry_remove").params.pop();
}, "entry_remove");
mustObject("an argument renamed", ({ shim }) => {
  shim.broker.find((r) => r.command === "node_create").params.find((p) => p.key === "parentId").key = "parent";
}, "node_create");
mustObject("an optional argument made required", ({ shim }) => {
  shim.broker.find((r) => r.command === "entry_create").params.find((p) => p.key === "label").required = true;
}, "entry_create");
mustObject("an argument's type changed", ({ shim }) => {
  shim.broker.find((r) => r.command === "entry_rotate").params.find((p) => p.key === "generation").kind = "string";
}, "entry_rotate");
mustObject("arguments reordered", ({ shim }) => {
  shim.broker.find((r) => r.command === "entry_reveal").params.reverse();
}, "entry_reveal");
mustObject("a field-model command removed from the shim table", ({ shim }) => {
  shim.broker = shim.broker.filter((r) => r.command !== "field_reorder");
}, "field_reorder");
mustObject("the local preview command removed from the shim", ({ shim }) => {
  shim.shell = shim.shell.filter((r) => r.command !== "fields_preview");
}, "fields_preview");
mustObject("an argument the preview takes dropped from the shim", ({ shim }) => {
  shim.shell.find((r) => r.command === "fields_preview").params.pop();
}, "fields_preview");
mustObject("the frame entry_copy sends to the reveal changed", ({ shim }) => {
  shim.shell.find((r) => r.command === "entry_copy").opParams = ["node", "entry"];
}, "entry_copy");
mustObject("a shell command renamed", ({ shim }) => {
  shim.shell.find((r) => r.command === "copy_text").command = "copy_string";
}, "copy_text");
mustObject("the clipboard clock changed", ({ shim }) => {
  shim.clipboardTtlSeconds = 31;
}, "CLEAR_AFTER");
mustObject("a session-ending code added", ({ shim }) => {
  shim.sessionEndedCodes.push("node_locked");
}, "SESSION_ENDED_CODES");
mustObject("a bridge-local code the shell does not define", ({ shim }) => {
  shim.localCodesUsed.push("made_up_code");
}, "made_up_code");
mustObject("bridge.ts invoking a command the shim does not serve", ({ inv }) => {
  inv.push("vault_export_everything");
}, "vault_export_everything");

// The same canaries, but breaking the RUST side by editing a copy of its text, so the parser itself is held to the guard too.
function mustObjectToRustEdit(name, file, edit, expectText) {
  test(`canary (commands.rs text edited): ${name}`, () => {
    const original = readFileSync(file, "utf8");
    const edited = edit(original);
    assert.ok(edited !== original, `the edit for "${name}" changed nothing: the canary would prove nothing`);
    const rust = file === COMMANDS_RS ? readShellSurface({ commandsText: edited }) : rustSide();
    const ops = file === OPS_RS ? readBrokerOps(edited) : brokerOps();
    const inv = file === BRIDGE_TS ? readBridgeInvokes(edited) : invokes();
    const findings = compareSurfaces(shimSide(), rust, ops, inv);
    assert.ok(findings.length > 0, `the guard did not notice: ${name}`);
    if (expectText) assert.ok(findings.some((f) => f.includes(expectText)), `expected a finding mentioning ${expectText}, got:\n  - ${findings.join("\n  - ")}`);
  });
}

mustObjectToRustEdit("a generated command renamed", COMMANDS_RS, (t) => t.replace("vault_node_lock / vault_node_lock_at", "vault_node_freeze / vault_node_freeze_at"), "vault_node");
mustObjectToRustEdit("an op changed", COMMANDS_RS, (t) => t.replace('=> "node.seal"', '=> "node.shred"'), "node_seal");
mustObjectToRustEdit("an argument added", COMMANDS_RS, (t) => t.replace('node_seal / node_seal_at => "node.seal" {\n        node: String => "node",\n', 'node_seal / node_seal_at => "node.seal" {\n        node: String => "node",\n        force: bool => "force",\n'), "node_seal");
// A required argument made optional, in the Rust text. The canary names `entry_remove`'s `generation`: it is required, it is the last
// argument of its row, and the row has stayed that shape across the field model. (It used to edit `entry_update`'s `value`, which
// ADR-078 made optional itself - `value` and `fields` are alternatives - so the edit matched nothing and the canary failed on its own
// precondition. A canary that edits a row must pick an argument that is required TODAY; the precondition below says so if it ever isn't.)
mustObjectToRustEdit("a required argument made optional", COMMANDS_RS, (t) => t.replace('entry_remove / entry_remove_at => "entry.remove" {\n        node: String => "node",\n        entry: String => "entry",\n        generation: u64 => "generation",', 'entry_remove / entry_remove_at => "entry.remove" {\n        node: String => "node",\n        entry: String => "entry",\n        generation: Option<u64> => "generation" [optional],'), "entry_remove");
mustObjectToRustEdit(
  "an optional argument made required",
  COMMANDS_RS,
  (t) =>
    t.replace(
      'totp_code / totp_code_at => "totp.code" {\n        node: String => "node",\n        entry: String => "entry",\n        field: Option<String> => "field" [optional],',
      'totp_code / totp_code_at => "totp.code" {\n        node: String => "node",\n        entry: String => "entry",\n        field: String => "field",',
    ),
  "totp_code",
);
mustObjectToRustEdit("the copy_text size cap changed", COMMANDS_RS, (t) => t.replace("COPY_TEXT_MAX_BYTES: usize = 4096", "COPY_TEXT_MAX_BYTES: usize = 8192"), "COPY_TEXT_MAX_BYTES");
mustObjectToRustEdit("an op the broker dispatches that the bridge does not carry", OPS_RS, (t) => t.replace('"node.seal" =>', '"node.seal" =>\n        "node.annihilate" => Ok(json!({})),\n        "node.seal.old" =>'), "node.annihilate");
mustObjectToRustEdit("a new typed-client call", BRIDGE_TS, (t) => t.replace('invoke<AuthState>("vault_status")', 'invoke<AuthState>("vault_status_v2")'), "vault_status");
