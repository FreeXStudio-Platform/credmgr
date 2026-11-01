/* FIXTURE BROKER - writes: entries (single and batch, with fields), field add / update / remove / reorder, the locked-write tray, nodes
   (create, policy, seal, restore), and the shell's local fields_preview.  See core.js.

   It answers the way the real broker does (crates/brokerd/src/ops.rs), including the refusals a screen has to show:
     - an entry is created from `value` OR `fields`, never both and never neither; the field ops echo the node's generation and answer
       `conflict` for a stale one, `node_locked` for a locked node, `not_found` for an unknown field, and refuse to remove the last field;
     - names are compared exactly, against the node's manifest AND its tray; a batch checks every name before it writes any;
     - a write to a locked NODE waits in the tray (`pending: true`); accepting or discarding there answers `node_locked`;
     - node.policy answers `presence_required` for a change that widens reach (descendantRead on, siblingVisibility shared from
       isolated) and applies nothing; every other change applies;
     - node.seal moves the entries to the orphaned node, revokes the node's grants and removes ONLY that node (children, if any,
       are left standing: the real op does not seal them, and the screen must not offer it);
     - node.restore undoes a seal inside the window; `broker.set({ sealedExpired: true })` closes the window. */
(function (B) {
  "use strict";
  var H = B.handlers;

  /** Work folders that "exist" on the fixture's disk (the real broker canonicalises and checks them). */
  var HOME = "/opt/fixture-home";
  var DIRS = [HOME + "/projects/alpha", HOME + "/projects/beta", HOME + "/projects/gamma"];
  var DEFAULT_POLICY = { siblingVisibility: "shared", descendantRead: false, requireTwoFactor: "reveal", lockAfterSeconds: null, privateNames: false, agentAccess: "read-write" };

  function orphanNode() {
    return B.S.nodes.filter(function (n) { return n.kind === "orphan"; })[0] || null;
  }

  function exists(node, name) {
    var S = B.S;
    var all = (S.entries[node] || []).concat(S.pending[node] || []);
    return all.some(function (e) { return e.name === name; });
  }

  /**
   * The body of a create (ADR-078): exactly one of `value` (a one-field entry; `label` names the field, default "value") or `fields`;
   * `entryType` / `sensitivity` pin the entry's own type / sensitivity (`"auto"` and absent both mean inferred).  Validated before anything
   * is written: a refusal names an index or a parameter, never a label or a value.
   */
  function parseBody(a, where) {
    var hasValue = a.value !== undefined && a.value !== null;
    var hasFields = a.fields !== undefined && a.fields !== null;
    if (hasValue === hasFields) throw B.error("malformed_request", where + ": give either value or fields, not both and not neither");
    var fields;
    if (hasFields) {
      fields = B.makeFields(a.fields, where + ".fields");
    } else {
      if (typeof a.value !== "string") throw B.error("malformed_request", where + ".value must be a string");
      fields = B.makeFields([{ label: typeof a.label === "string" ? a.label : "value", value: a.value }], where);
    }
    var typePin = B.pinParam(a.entryType, B.ENTRY_TYPES, "entryType", { "note-only": "note" });
    var sensPin = B.pinParam(a.sensitivity, ["low", "medium", "high", "critical"], "sensitivity");
    return { fields: fields, typePin: typePin || undefined, sensPin: sensPin || undefined };
  }

  function create(node, name, body) {
    var S = B.S;
    var n = B.requireNode(node);
    if (typeof name !== "string" || !name) throw B.error("malformed_request", "params.name is required");
    if (exists(node, name)) throw B.error("entry_exists", "an entry with that name exists", { node: node, name: name });
    S.entrySeq += 1;
    var e = { id: "e-new-" + S.entrySeq, name: name, type: "other", sensitivity: "low", value: "", fields: body.fields, modified: B.now(), rotatedAt: null, expiresAt: null, created: B.now() };
    if (body.typePin) e.typePin = body.typePin;
    if (body.sensPin) e.sensPin = body.sensPin;
    B.project(e);
    var ids = body.fields.map(function (f) { return f.id; });
    // A write to a locked node waits in the review tray; it reaches the manifest only when accepted.
    if (n.gate.locked) {
      (S.pending[node] = S.pending[node] || []).push(e);
      return { node: node, entry: e.id, pending: true, fieldCount: ids.length, fieldIds: ids };
    }
    (S.entries[node] = S.entries[node] || []).push(e);
    S.generation[node] = (S.generation[node] || 1) + 1;
    return { node: node, entry: e.id, pending: false, generation: S.generation[node], fieldCount: ids.length, fieldIds: ids };
  }

  H.entry_create = function (a) {
    B.requireLogin();
    B.requireNode(a.node);
    var r = create(a.node, a.name, parseBody(a, "params"));
    B.audit("create", a.node, r.entry);
    return B.nameWarnings(r, [a.name]);
  };

  H.entry_create_batch = function (a) {
    B.requireLogin();
    B.requireNode(a.node);
    var entries = a.entries;
    if (!Array.isArray(entries) || !entries.length || entries.length > 500) throw B.error("malformed_request", "params.entries must hold 1-500 entries");
    var seen = {};
    var bodies = entries.map(function (e, i) {
      if (!e || typeof e.name !== "string" || !e.name) throw B.error("malformed_request", "entries[" + i + "].name is required");
      if (seen[e.name]) throw B.error("malformed_request", "entries[" + i + "]: the name appears twice in this batch");
      seen[e.name] = true;
      return parseBody(e, "entries[" + i + "]");
    });
    // Everything that can be checked is checked before the first write: a refused batch writes nothing.
    entries.forEach(function (e) {
      if (exists(a.node, e.name)) throw B.error("entry_exists", "an entry with that name exists", { node: a.node, name: e.name });
    });
    var created = entries.map(function (e, i) {
      var r = create(a.node, e.name, bodies[i]);
      return { name: e.name, entry: r.entry, pending: r.pending, fieldCount: r.fieldCount };
    });
    B.audit("create_batch", a.node);
    return B.nameWarnings({ node: a.node, created: created, complete: true, failed: null, total: created.length, generation: B.S.generation[a.node] || null }, entries.map(function (e) { return e.name; }));
  };

  // ───────────────────────────── fields (ADR-078): add, update, remove, reorder ─────────────────────────────
  // Every one: capability update, the node open (node_locked otherwise), the generation echoed (conflict otherwise), history retained
  // and undoable.  A first write to an entry written before the field model re-seals it as a field document, pinning what the manifest said.

  function fieldEntry(a) {
    B.requireLogin();
    B.requireNodeOpen(a.node);
    var e = (B.S.entries[a.node] || []).filter(function (x) { return x.id === a.entry; })[0];
    if (!e) throw B.error("not_found", "no such entry", { node: a.node, entry: a.entry });
    var current = B.S.generation[a.node] || 1;
    if (typeof a.generation !== "number") throw B.error("malformed_request", "params.generation is required");
    if (a.generation !== current) throw B.error("conflict", "the node changed since it was read", { node: a.node, expectedGeneration: a.generation, currentGeneration: current });
    // What entry.undo (ADR-086) puts back: the fields as they stand now, and the generation they belong to.
    pendingSnap = { fields: B.clone(B.fieldsOf(e)), hadFields: !!e.fields, typePin: e.typePin, sensPin: e.sensPin, before: current };
    return e;
  }
  var pendingSnap = null;
  function fieldNamed(e, id) {
    var f = B.fieldsOf(e).filter(function (x) { return x.id === id; })[0];
    if (!f) throw B.error("not_found", "no such field", { entry: e.id, field: id });
    return f;
  }
  function changed(a, e, action, extra) {
    B.project(e);
    B.S.generation[a.node] = (B.S.generation[a.node] || 1) + 1;
    B.audit(action, a.node, e.id);
    // The audit record carries the op's new generation (ADR-055), and the change stays undoable for seven days.
    var rec = B.S.audit[B.S.audit.length - 1];
    rec.generation = B.S.generation[a.node];
    if (pendingSnap) {
      B.S.fieldHistory[rec.id] = { node: a.node, entry: e.id, action: action, at: B.now(), snap: pendingSnap };
      pendingSnap = null;
    }
    var out = { node: a.node, entry: e.id, generation: B.S.generation[a.node], fieldCount: e.fields.length, fieldIds: e.fields.map(function (f) { return f.id; }) };
    for (var k in extra || {}) out[k] = extra[k];
    return out;
  }

  H.field_add = function (a) {
    var e = fieldEntry(a);
    var added = B.makeFields(a.fields, "params.fields");
    var fs = B.fieldsOf(e);
    var at = a.position === undefined || a.position === null ? fs.length : a.position;
    if (typeof at !== "number" || at < 0 || at > fs.length || at !== Math.floor(at)) throw B.error("malformed_request", "params.position must be between 0 and " + fs.length);
    B.materialize(e);
    e.fields.splice.apply(e.fields, [at, 0].concat(added));
    return changed(a, e, "field.add", { added: added.map(function (f) { return f.id; }) });
  };

  H.field_update = function (a) {
    var e = fieldEntry(a);
    var f = fieldNamed(e, a.field);
    var patch = a.patch;
    var keys = patch && typeof patch === "object" && !Array.isArray(patch) ? Object.keys(patch) : [];
    if (!keys.length) throw B.error("malformed_request", "params.patch sets no field - nothing to change");
    keys.forEach(function (k) { if (["label", "value", "type", "masked"].indexOf(k) < 0) throw B.error("malformed_request", "params.patch has a key that is not one of: label, value, type, masked"); });
    if (patch.label !== undefined && (typeof patch.label !== "string" || patch.label.length > 200 || /[\n\r\0]/.test(patch.label))) throw B.error("malformed_request", "params.patch.label must be one line of at most 200 characters");
    if (patch.value !== undefined && typeof patch.value !== "string") throw B.error("malformed_request", "params.patch.value must be a string");
    if (patch.type !== undefined && patch.type !== "auto" && B.FIELD_TYPES.indexOf(patch.type) < 0) throw B.error("malformed_request", "params.patch.type is not a field type");
    if (patch.masked !== undefined && patch.masked !== "auto" && typeof patch.masked !== "boolean") throw B.error("malformed_request", "params.patch.masked must be true, false or auto");
    B.materialize(e);
    var live = fieldNamed(e, a.field);
    if (patch.label !== undefined) live.label = patch.label;
    if (patch.value !== undefined) live.value = patch.value;
    if (patch.type !== undefined) { if (patch.type === "auto") delete live.typePin; else live.typePin = patch.type; }
    if (patch.masked !== undefined) { if (patch.masked === "auto") delete live.maskedPin; else live.maskedPin = patch.masked; }
    return changed(a, e, "field.update");
  };

  H.field_remove = function (a) {
    var e = fieldEntry(a);
    fieldNamed(e, a.field);
    if (B.fieldsOf(e).length === 1) throw B.error("malformed_request", "an entry keeps at least one field - remove the entry instead");
    B.materialize(e);
    e.fields = e.fields.filter(function (f) { return f.id !== a.field; });
    return changed(a, e, "field.remove");
  };

  H.field_reorder = function (a) {
    var e = fieldEntry(a);
    var ids = B.fieldsOf(e).map(function (f) { return f.id; });
    var order = a.order;
    if (!Array.isArray(order) || order.length !== ids.length || order.some(function (id) { return ids.indexOf(id) < 0; }) || order.some(function (id, i) { return order.indexOf(id) !== i; })) {
      throw B.error("malformed_request", "params.order must list every current field id exactly once");
    }
    B.materialize(e);
    var byId = {};
    e.fields.forEach(function (f) { byId[f.id] = f; });
    e.fields = order.map(function (id) { return byId[id]; });
    return changed(a, e, "field.reorder");
  };

  H.vault_pending_accept = function (a) {
    B.requireLogin();
    var S = B.S;
    B.requireNodeOpen(a.node);
    var q = S.pending[a.node] || [];
    var i = q.map(function (p) { return p.id; }).indexOf(a.entry);
    if (i < 0) throw B.error("not_found", "nothing is waiting under that id");
    // A rejected accept leaves the tray exactly as it was.
    if ((S.entries[a.node] || []).some(function (e) { return e.name === q[i].name; })) throw B.error("entry_exists", "an entry with that name exists", { node: a.node, name: q[i].name });
    var e = q.splice(i, 1)[0];
    (S.entries[a.node] = S.entries[a.node] || []).push(e);
    S.generation[a.node] = (S.generation[a.node] || 1) + 1;
    B.audit("pending_accept", a.node, a.entry);
    return { node: a.node, entry: a.entry, accepted: true, generation: S.generation[a.node] };
  };

  H.vault_pending_discard = function (a) {
    B.requireLogin();
    B.requireNodeOpen(a.node);
    var q = B.S.pending[a.node] || [];
    var i = q.map(function (p) { return p.id; }).indexOf(a.entry);
    if (i < 0) throw B.error("not_found", "nothing is waiting under that id");
    q.splice(i, 1);
    B.audit("pending_discard", a.node, a.entry);
    return { node: a.node, entry: a.entry, discarded: true };
  };

  // ───────────────────────────── nodes ─────────────────────────────

  H.node_create = function (a) {
    B.requireLogin();
    var S = B.S;
    if (typeof a.id !== "string" || !a.id) throw B.error("malformed_request", "params.id is required");
    if (typeof a.label !== "string") throw B.error("malformed_request", "params.label is required");
    if (typeof a.parentId !== "string") throw B.error("malformed_request", "params.parentId is required");
    var orphan = orphanNode();
    if (a.id === "global" || a.id === "orphan" || (orphan && a.id === orphan.id)) throw B.error("malformed_request", a.id + " is a reserved node id");
    if (B.node(a.id)) throw B.error("malformed_request", "a node named " + a.id + " already exists");
    var parent = B.node(a.parentId);
    if (!parent) throw B.error("not_found", "no node " + a.parentId);
    if (parent.kind === "orphan" || parent.depth >= 2) throw B.error("malformed_request", a.parentId + " is already at the depth cap");
    var workdirs = [];
    if (a.workdirs !== undefined && a.workdirs !== null) {
      if (!Array.isArray(a.workdirs)) throw B.error("malformed_request", "params.workdirs must be an array of absolute directory paths");
      a.workdirs.forEach(function (w) {
        if (typeof w !== "string" || w.charAt(0) !== "/") throw B.error("malformed_request", "workdir " + JSON.stringify(w) + " is not absolute");
        if (DIRS.indexOf(w) < 0) throw B.error("malformed_request", "workdir " + JSON.stringify(w) + " cannot be resolved");
        S.nodes.forEach(function (n) {
          if ((n.workdirs || []).indexOf(w) >= 0) throw B.error("malformed_request", "would violate a registry invariant: duplicate workdir");
        });
        if (workdirs.indexOf(w) < 0) workdirs.push(w);
      });
    }
    var node = {
      id: a.id, label: a.label.trim(), kind: parent.depth === 0 ? "project" : "sub", depth: parent.depth + 1, parentId: a.parentId,
      gate: { locked: false, twofa: "required" }, workdirs: workdirs, policy: B.clone(DEFAULT_POLICY),
    };
    var at = S.nodes.indexOf(orphan);
    S.nodes.splice(at < 0 ? S.nodes.length : at, 0, node);
    S.entries[a.id] = [];
    S.generation[a.id] = 1;
    B.audit("node_create", a.id);
    return B.nameWarnings({ node: a.id, created: true }, [a.label]);
  };

  H.node_policy = function (a) {
    B.requireLogin();
    var node = B.requireNode(a.node);
    var reason = typeof a.reason === "string" ? a.reason.trim() : "";
    if (!reason) throw B.error("malformed_request", "params.reason is required - a policy change records why");
    if (reason.length > 500) throw B.error("malformed_request", "params.reason is limited to 500 characters");
    if (node.kind === "orphan") throw B.error("malformed_request", "orphan's policy is fixed by design");
    var patch = a.policy;
    var fields = patch && typeof patch === "object" ? Object.keys(patch) : [];
    if (!fields.length) throw B.error("malformed_request", "params.policy sets no field - nothing to change");
    var allowed = { siblingVisibility: ["shared", "isolated"], requireTwoFactor: ["never", "reveal", "always"], agentAccess: ["read-write", "read-only", "none"] };
    fields.forEach(function (f) {
      if (!(f in DEFAULT_POLICY)) throw B.error("malformed_request", "params.policy: unknown field " + f);
      if (allowed[f] && allowed[f].indexOf(patch[f]) < 0) throw B.error("malformed_request", "params.policy: bad value for " + f);
    });
    node.policy = node.policy || B.clone(DEFAULT_POLICY);
    // Widening reach needs presence, which no transport can attest yet; the patch is all-or-nothing.
    if ((patch.descendantRead === true && !node.policy.descendantRead) || (patch.siblingVisibility === "shared" && node.policy.siblingVisibility === "isolated")) {
      throw B.error("presence_required", "presence cannot be attested by this transport");
    }
    fields.forEach(function (f) { node.policy[f] = patch[f]; });
    if ("requireTwoFactor" in patch) node.gate.twofa = patch.requireTwoFactor === "never" ? "none" : "required";
    B.audit("node_policy", a.node);
    return { node: a.node, policy: B.clone(node.policy), changed: fields, reason: reason, notEnforced: [] };
  };

  // entry.undo for a field change (ADR-086): the broker puts the fields back as they were before the call whose audit record `id` names, echoes the
  // node's CURRENT generation (conflict otherwise), and says what it restored.  A change is undoable for seven days and once; after that, or for
  // anything it does not know, `not_undoable`.  `broker.set({ undoExpired: true })` closes the window.
  H.entry_undo = function (a) {
    B.requireLogin();
    B.requireNodeOpen(a.node);
    var S = B.S;
    var h = (S.fieldHistory || {})[a.id];
    if (!h || h.node !== a.node || S.undoExpired) throw B.error("not_undoable", "that change can no longer be undone", { node: a.node });
    var current = S.generation[a.node] || 1;
    if (a.generation !== current) throw B.error("conflict", "the node changed since it was read", { node: a.node, expectedGeneration: a.generation, currentGeneration: current });
    var e = (S.entries[a.node] || []).filter(function (x) { return x.id === h.entry; })[0];
    if (!e) throw B.error("not_found", "no such entry", { node: a.node, entry: h.entry });
    if (h.snap.hadFields) e.fields = B.clone(h.snap.fields);
    else delete e.fields;
    B.project(e);
    S.generation[a.node] = current + 1;
    delete S.fieldHistory[a.id];
    B.audit("entry.undo", a.node, e.id);
    S.audit[S.audit.length - 1].generation = S.generation[a.node];
    return { ok: true, restored: { action: h.action, entry: e.id, fieldCount: B.fieldsOf(e).length }, generation: S.generation[a.node], undoneToGeneration: h.snap.before };
  };

  // util.generate (ADR-087): made in the broker.  The fixture's value is deterministic and obviously not a credential.
  var genSeq = 0;
  H.util_generate = function (a) {
    B.requireLogin();
    var length = a.length === undefined || a.length === null ? 20 : a.length;
    if (typeof length !== "number" || length !== Math.floor(length) || length < 8 || length > 128) throw B.error("malformed_request", "params.length must be 8 to 128");
    var symbols = a.symbols === undefined ? true : !!a.symbols;
    var pron = !!a.pronounceable;
    genSeq += 1;
    var value = ("fixture-generated-" + genSeq + "-q7Vn2xLw9RtZk4PdE8mJcHs5BuFyAa3GoNiKe6TqWz1XrYvUlOpDbCgMjSh0I").slice(0, length);
    var bits = pron ? Math.round(length / 2 * Math.log2(17 * 5)) : Math.round(length * Math.log2(symbols ? 76 : 62));
    return { value: value, length: length, symbols: symbols, pronounceable: pron, entropyBits: bits };
  };

  H.node_seal = function (a) {
    B.requireLogin();
    var S = B.S;
    var orphan = orphanNode();
    if (a.node === "global" || a.node === "orphan" || (orphan && a.node === orphan.id)) throw B.error("malformed_request", a.node + " cannot be sealed");
    var node = B.requireNode(a.node);
    if (node.gate.locked) throw B.error("node_locked", "the node is locked", { node: a.node });
    var moved = (S.entries[a.node] || []).slice();
    var orphanList = (S.entries[orphan.id] = S.entries[orphan.id] || []);
    var orphanIds = moved.map(function (e) {
      var taken = orphanList.some(function (o) { return o.name === e.name; });
      var sealed = { id: e.id, name: taken ? e.name + " (" + a.node + ")" : e.name, type: e.type, sensitivity: e.sensitivity, value: e.value, modified: B.now(), rotatedAt: e.rotatedAt, expiresAt: e.expiresAt };
      if (e.fields) sealed.fields = e.fields;
      orphanList.push(sealed);
      return e.id;
    });
    S.grants = S.grants.filter(function (g) { return g.from !== a.node && g.to.nodeId !== a.node; });
    S.sealed = S.sealed || {};
    S.sealed[a.node] = { node: node, entries: moved, orphanIds: orphanIds, sealedAt: B.now() };
    S.nodes = S.nodes.filter(function (n) { return n.id !== a.node; });
    delete S.entries[a.node];
    B.audit("node_seal", a.node);
    var answer = { node: a.node, sealed: true };
    // The real broker's answer carries no end-of-window time (it keeps the archive 7 days and says nothing more).  A spec rehearses a broker
    // that does, with broker.set({ sealAnswerExpiresAt: <unix seconds> }); without it the answer is exactly the real one.
    if (typeof S.sealAnswerExpiresAt === "number") answer.expiresAt = S.sealAnswerExpiresAt;
    return answer;
  };

  H.node_restore = function (a) {
    B.requireLogin();
    var S = B.S;
    var rec = S.sealed && S.sealed[a.node];
    if (!rec) throw B.error("not_found", "no sealed node " + a.node);
    if (S.sealedExpired) throw B.error("archive_expired", "the 7-day window for " + a.node + " is over", { node: a.node });
    var orphan = orphanNode();
    S.entries[orphan.id] = (S.entries[orphan.id] || []).filter(function (o) { return rec.orphanIds.indexOf(o.id) < 0; });
    var at = S.nodes.indexOf(orphan);
    S.nodes.splice(at < 0 ? S.nodes.length : at, 0, rec.node);
    S.entries[a.node] = rec.entries;
    delete S.sealed[a.node];
    B.audit("node_restore", a.node);
    return { node: a.node, restored: true };
  };

  // The shell's path plugin: where `~` points.
  H["plugin:path|resolve_directory"] = function () {
    return HOME;
  };

  // The shell's LOCAL preview of a bulk paste: no broker, no session, no audit record (so no requireLogin here either).  The page
  // keeps no parser of its own; what this answers is what the screen shows and what it then sends to entry.create, verbatim.
  H.fields_preview = function (a) {
    return B.preview(a);
  };

  // Examples for tests/unit/fixture-shape.test.ts (see core.js).
  var E = B.examples;
  var OPEN = { locked: false };
  // An entry written to the locked node waits in the tray; accepting or discarding it needs the node open.
  var WAITING = function () { return H.entry_create({ node: "cobalt", name: "waiting", value: "fixture-value-waiting" }); };
  var WAITING_NODE_OPEN = function () { WAITING(); H.vault_node_unlock({ node: "cobalt" }); };
  var WAITING_ID = function () { return { node: "cobalt", entry: B.S.pending.cobalt[0].id }; };
  E.entry_create = [
    { reset: OPEN, args: { node: "atlas", name: "new-entry", value: "fixture-value-new" } },
    { reset: OPEN, args: { node: "atlas", name: "new-entry", fields: [{ label: "host", value: "fixture-value-new.example.test" }, { label: "password", value: "fixture-value-new", masked: true }], entryType: "server", sensitivity: "high" } },
    { reset: OPEN, args: { node: "cobalt", name: "new-entry", value: "fixture-value-new" } },
    { reset: OPEN, args: { node: "atlas", name: "stripe-live", value: "fixture-value-new" }, error: "entry_exists" },
    // Exactly one of value / fields; a refusal names an index, never a label or a value.
    { reset: OPEN, args: { node: "atlas", name: "new-entry", value: "fixture-value-new", fields: [{ label: "a", value: "b" }] }, error: "malformed_request" },
    { reset: OPEN, args: { node: "atlas", name: "new-entry", fields: [{ label: "a\nb", value: "b" }] }, error: "malformed_request" },
  ];
  E.entry_create_batch = [
    { reset: OPEN, args: { node: "atlas", entries: [{ name: "one", value: "fixture-value-one" }, { name: "two", value: "fixture-value-two" }] } },
    { reset: OPEN, args: { node: "atlas", entries: [{ name: "one", fields: [{ label: "a", value: "b" }, { label: "c", value: "d" }] }] } },
    { reset: OPEN, args: { node: "atlas", entries: [{ name: "stripe-live", value: "fixture-value-one" }] }, error: "entry_exists" },
  ];
  // field.* (ADR-078): the generation is the node's, as entry.list / entry.get last said it.
  var GEN = function () { return B.S.generation.atlas || 1; };
  E.field_add = [
    { reset: OPEN, args: function () { return { node: "atlas", entry: "e-a2", generation: GEN(), fields: [{ label: "replica", value: "fixture-value-replica.example.test" }] }; } },
    { reset: OPEN, args: function () { return { node: "atlas", entry: "e-a1", generation: GEN(), fields: [{ label: "note", value: "fixture-value-note" }], position: 0 }; } },
    { reset: OPEN, args: { node: "atlas", entry: "e-a2", generation: 99, fields: [{ label: "a", value: "b" }] }, error: "conflict" },
    { reset: OPEN, args: function () { return { node: "atlas", entry: "e-a2", generation: GEN(), fields: [] }; }, error: "malformed_request" },
    { reset: OPEN, args: function () { return { node: "cobalt", entry: "e-c1", generation: 1, fields: [{ label: "a", value: "b" }] }; }, error: "node_locked" },
  ];
  E.field_update = [
    { reset: OPEN, args: function () { return { node: "atlas", entry: "e-a2", generation: GEN(), field: "f_00a20005", patch: { label: "remarks", value: "fixture-value-new-note", type: "auto", masked: true } }; } },
    { reset: OPEN, args: function () { return { node: "atlas", entry: "e-a2", generation: GEN(), field: "f_nope", patch: { label: "x" } }; }, error: "not_found" },
    { reset: OPEN, args: function () { return { node: "atlas", entry: "e-a2", generation: GEN(), field: "f_00a20005", patch: {} }; }, error: "malformed_request" },
    { reset: OPEN, args: { node: "atlas", entry: "e-a2", generation: 99, field: "f_00a20005", patch: { label: "x" } }, error: "conflict" },
  ];
  E.field_remove = [
    { reset: OPEN, args: function () { return { node: "atlas", entry: "e-a2", generation: GEN(), field: "f_00a20005" }; } },
    // An entry keeps at least one field.
    { reset: OPEN, args: function () { return { node: "atlas", entry: "e-a1", generation: GEN(), field: "f_00000000" }; }, error: "malformed_request" },
    { reset: OPEN, args: function () { return { node: "atlas", entry: "e-a2", generation: GEN(), field: "f_nope" }; }, error: "not_found" },
  ];
  E.field_reorder = [
    { reset: OPEN, args: function () { return { node: "atlas", entry: "e-a2", generation: GEN(), order: ["f_00a20005", "f_00a20004", "f_00a20003", "f_00a20002", "f_00a20001"] }; } },
    { reset: OPEN, args: function () { return { node: "atlas", entry: "e-a2", generation: GEN(), order: ["f_00a20005"] }; }, error: "malformed_request" },
  ];
  // The shell's local preview (no broker, no session, no audit record).  Exactly one of text / fields.
  E.fields_preview = [
    { reset: OPEN, args: { text: "host: db.example.test\nport: 5432\npassword: fixture-value-pw" } },
    { reset: OPEN, args: { text: "host: a.example.test\n///\napi key: fixture-value-key", split: true } },
    { reset: OPEN, args: { fields: [{ label: "token", value: "fixture-value-token", type: "api-key", masked: false }] } },
    { reset: OPEN, args: { text: "a: b", fields: [{ label: "a", value: "b" }] }, error: "invalid_fields" },
    { reset: OPEN, args: {}, error: "invalid_fields" },
  ];
  E.vault_pending_accept = [
    { reset: OPEN, setup: WAITING_NODE_OPEN, args: WAITING_ID },
    { reset: OPEN, setup: WAITING, args: WAITING_ID, error: "node_locked" },
    { reset: OPEN, setup: WAITING_NODE_OPEN, args: { node: "cobalt", entry: "e-nope" }, error: "not_found" },
  ];
  E.vault_pending_discard = [
    { reset: OPEN, setup: WAITING_NODE_OPEN, args: WAITING_ID },
    { reset: OPEN, setup: WAITING, args: WAITING_ID, error: "node_locked" },
  ];
  E.node_create = [
    { reset: OPEN, args: { id: "delta", label: "Delta", parentId: "global" } },
    { reset: OPEN, args: { id: "delta", label: "Delta", parentId: "atlas", workdirs: [HOME + "/projects/alpha"] } },
    { reset: OPEN, args: { id: "atlas", label: "Atlas again", parentId: "global" }, error: "malformed_request" },
    { reset: OPEN, args: { id: "delta", label: "Delta", parentId: "global", workdirs: ["/nowhere"] }, error: "malformed_request" },
  ];
  E.node_policy = [
    { reset: OPEN, args: { node: "atlas", reason: "fixture reason", policy: { agentAccess: "read-only", requireTwoFactor: "never" } } },
    { reset: OPEN, args: { node: "atlas", reason: "fixture reason", policy: { descendantRead: true } }, error: "presence_required" },
    { reset: OPEN, args: { node: "atlas", reason: "  ", policy: { agentAccess: "none" } }, error: "malformed_request" },
  ];
  // entry.undo: a field change just made, undone at the node's current generation; unknown ids and stale generations are refused.
  var CHANGED = function () { H.field_update({ node: "atlas", entry: "e-a2", generation: GEN(), field: "f_00a20005", patch: { label: "remarks" } }); };
  var LAST = function () { return B.S.audit[B.S.audit.length - 1].id; };
  E.entry_undo = [
    { reset: OPEN, setup: CHANGED, args: function () { return { node: "atlas", id: LAST(), generation: GEN() }; } },
    { reset: OPEN, setup: CHANGED, args: function () { return { node: "atlas", id: LAST(), generation: 99 }; }, error: "conflict" },
    { reset: OPEN, args: function () { return { node: "atlas", id: "aud-nope", generation: GEN() }; }, error: "not_undoable" },
    { reset: { locked: true }, args: { node: "atlas", id: "aud-1", generation: 1 }, error: "vault_locked" },
  ];
  E.util_generate = [
    { reset: OPEN, args: {} },
    { reset: OPEN, args: { length: 32, symbols: false, pronounceable: true } },
    { reset: OPEN, args: { length: 4 }, error: "malformed_request" },
    { reset: { locked: true }, args: {}, error: "vault_locked" },
  ];
  E.node_seal = [
    { reset: OPEN, args: { node: "beacon" } },
    { reset: OPEN, args: { node: "cobalt" }, error: "node_locked" },
    { reset: OPEN, args: { node: "global" }, error: "malformed_request" },
  ];
  E.node_restore = [
    { reset: OPEN, setup: function () { H.node_seal({ node: "beacon" }); }, args: { node: "beacon" } },
    { reset: OPEN, args: { node: "beacon" }, error: "not_found" },
    { reset: OPEN, setup: function () { H.node_seal({ node: "beacon" }); B.S.sealedExpired = true; }, args: { node: "beacon" }, error: "archive_expired" },
  ];

})((window.__brokerFixture = window.__brokerFixture || {}));
