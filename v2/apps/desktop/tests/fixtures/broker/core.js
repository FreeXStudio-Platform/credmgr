/*
 * FIXTURE BROKER - core.  A scriptable fake of the Tauri shell's `invoke`, installed in the page by the Playwright specs.
 *
 * It runs INSIDE the page, so it is plain JavaScript with no imports; the files in this directory are concatenated, in the
 * order tests/fixtures/broker/index.ts lists, and injected with `page.addInitScript` (which runs outside the page's
 * Content-Security-Policy, so it cannot weaken the policy under test).
 *
 *   core.js      the dispatcher, the call log, the scripting queue, error shapes   (this file)
 *   seed.js      the in-memory vault: nodes, entries, grants, notes, audit
 *   fields.js    the field model (ADR-078): field ids, pins, inference and parser stand-ins, projection, the fields_preview logic
 *   session.js   vault_status / unlock / gate_verify / lock / init / whoami
 *   read.js      graph_snapshot, entry_list, entry_get, entry_reveal, totp, notes, search, grants, pending list, node lock
 *   write.js     entry_create(+batch), field add / update / remove / reorder, fields_preview, pending accept / discard
 *   admin.js     grant create / revoke, audit, maintenance
 *   install.js   defines window.__TAURI_INTERNALS__ and window.__BROKER__ (the control surface the specs call)
 *
 * EVERY HANDLER NEEDS AN EXAMPLE.  Next to each handler a file registers `B.examples.<command> = [ ... ]`: one or more
 * `{ reset?, setup?, args, error? }` (`reset`: broker options for a fresh vault; `setup()`: put the vault in the state the call
 * needs; `args`: an object, or a function returning one; `error`: the code the call must be refused with).
 * tests/unit/fixture-shape.test.ts runs each example and checks the answer, key by key and type by type, against the
 * TypeScript declaration of that command in src/lib/bridge.ts, so this fake cannot drift from the real wire unnoticed and a
 * spec that is green against it means something.  A handler without an example fails `npm test` and says which one.
 *
 * Everything in the vault is invented.  Values are `fixture-value-<name>`: obviously not credentials, and distinctive so a
 * spec can search the page, the storage and the logs for them.
 *
 * Errors are rejected as the bridge rejects them (src-tauri/src/error.rs): { source, code, message, detail? }.
 */
(function (B) {
  "use strict";

  B.handlers = B.handlers || {};
  B.examples = B.examples || {};
  B.calls = [];
  B.scripts = {};
  B.S = null;

  B.error = function (code, message, detail, source) {
    var e = { source: source || "broker", code: code, message: message || code };
    if (detail) e.detail = detail;
    return e;
  };
  B.clone = function (v) {
    return v === undefined ? undefined : JSON.parse(JSON.stringify(v));
  };
  B.now = function () {
    return Math.floor(Date.now() / 1000);
  };

  /** A human-session audit record. */
  B.audit = function (action, node, entry, decision) {
    var S = B.S;
    S.auditSeq += 1;
    S.audit.push({ id: "aud-" + S.auditSeq, timestamp: B.now(), actor: "human", action: action, node: node || null, entry: entry || null, decision: decision || "allow" });
  };

  /** Every operation that reads or changes the vault needs a login. */
  B.requireLogin = function () {
    if (B.S.locked || !B.S.authenticated) throw B.error("vault_locked", "the vault is locked");
  };
  B.node = function (id) {
    return B.S.nodes.filter(function (n) { return n.id === id; })[0] || null;
  };
  B.requireNode = function (id) {
    var n = B.node(id);
    if (!n) throw B.error("not_found", "no such node", { node: id });
    return n;
  };
  /**
   * requireTwoFactor (ADR-085): with a confirmed gate, a node at level `reveal` refuses a reveal, and at level `always` also a list, a get and a
   * note, until the factor was proven in the last five minutes (`elevated`).  The real broker asks this of a reader that is not the owner's login, so
   * the window's own login does not meet it: a spec turns it on with broker.set({ factorGate: true, tfLevels: { atlas: "always" } }) (a node whose
   * snapshot says twofa "required" and has no level here is `reveal`).  `scope`: "reveal" for a reveal or a TOTP code, "always" for a read.
   */
  B.needFactor = function (nodeId, scope) {
    var S = B.S;
    if (!S.factorGate || !S.gateEnrolled || S.elevated) return;
    var n = B.node(nodeId);
    if (!n) return;
    var level = (S.tfLevels || {})[nodeId] || (n.gate.twofa === "required" ? "reveal" : "never");
    if (level === "never" || (level === "reveal" && scope !== "reveal")) return;
    throw B.error("two_factor_required", "a second factor is required", { challenge: "totp", scope: "global", expiresIn: 300 });
  };
  /** A node's lock is not the vault's: the login survives it. */
  B.requireNodeOpen = function (id) {
    var n = B.requireNode(id);
    if (n.gate.locked) throw B.error("node_locked", "the node is locked", { node: id });
    return n;
  };

  /** What the bridge's `invoke` does: log the call, honour a scripted answer, else run the handler. */
  B.eventCalls = [];
  B.invoke = async function (cmd, args) {
    args = args || {};
    // The event plugin's listen/unlisten are the shell's, not the broker's: kept apart so "the app sent exactly these broker commands" stays true.
    if (cmd.indexOf("plugin:event|") === 0) B.eventCalls.push({ cmd: cmd, args: B.clone(args) });
    else B.calls.push({ cmd: cmd, args: B.clone(args) });
    var queue = B.scripts[cmd];
    if (queue && queue.length) {
      var next = queue.shift();
      if (next.delayMs) await new Promise(function (r) { setTimeout(r, next.delayMs); });
      if (next.error) throw B.error(next.error.code, next.error.message, next.error.detail, next.error.source);
      if (Object.prototype.hasOwnProperty.call(next, "result")) return B.clone(next.result);
      // `{}` (or only a delay) falls through to the real handler
    }
    if (B.S.unreachable && cmd.indexOf("plugin:") !== 0) {
      throw B.error("broker_unreachable", "credmgrd is not running", undefined, "transport");
    }
    var h = B.handlers[cmd];
    if (!h) throw B.error("internal", "the fixture broker has no handler for " + cmd);
    var before = B.S.audit.length;
    var out = B.clone(await h(args, B.S));
    // The shell passes the broker envelope's `audit` id into the answer of a changing op (src-tauri/src/commands.rs AUDIT_PASSTHROUGH, ADR-091).
    // tests/unit/adr090-091.test.ts holds this list to the Rust one.
    if (B.AUDITED.indexOf(cmd) >= 0 && B.S.audit.length > before && out && typeof out === "object" && !Array.isArray(out) && !("audit" in out)) {
      out.audit = B.S.audit[B.S.audit.length - 1].id;
    }
    return out;
  };

  B.AUDITED = [
    "entry_create", "entry_create_batch", "entry_update", "entry_rotate", "entry_remove", "entry_restore", "entry_undo",
    "field_add", "field_update", "field_remove", "field_reorder", "notes_write",
    "node_create", "node_update", "node_policy", "node_set_workdirs", "node_reparent", "node_seal", "node_restore",
    "grant_create", "grant_revoke", "vault_pending_accept", "vault_pending_discard", "vault_approval_decide",
  ];

  /** The broker's `names::mixes_scripts`: Latin letters together with Greek or Cyrillic ones (ADR-084). */
  B.mixesScripts = function (text) {
    var t = String(text);
    return /[A-Za-z]/.test(t) && /[\u0370-\u03ff\u0400-\u04ff]/.test(t);
  };
  /** The additive `warnings` of a name-creating answer. */
  B.nameWarnings = function (answer, names) {
    if (names.some(B.mixesScripts)) answer.warnings = ["mixed_script_name"];
    return answer;
  };
})((window.__brokerFixture = window.__brokerFixture || {}));
