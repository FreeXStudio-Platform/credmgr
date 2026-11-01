/* FIXTURE BROKER - reads: graph, entries, reveal, TOTP, notes, search, grants, tray, node lock.  See core.js. */
(function (B) {
  "use strict";
  var H = B.handlers;

  function list(node) {
    return B.S.entries[node] || [];
  }
  function findEntry(node, id) {
    var e = list(node).filter(function (x) { return x.id === id; })[0];
    if (!e) throw B.error("not_found", "no such entry", { node: node, entry: id });
    return e;
  }
  function generation(node) {
    return B.S.generation[node] || 1;
  }

  // Renders while locked; meta.vaultLocked is how an idle auto-lock is noticed.
  H.graph_snapshot = function () {
    var S = B.S;
    return {
      nodes: S.nodes.map(function (n) {
        var es = list(n.id);
        // `counts.totp` counts the entries that carry a TOTP seed (`hasTotp`), whatever their type.
        return { id: n.id, label: n.label, kind: n.kind, depth: n.depth, parentId: n.parentId, counts: { entries: es.length, totp: es.filter(function (e) { return B.hasTotp(e); }).length }, gate: { locked: n.gate.locked, twofa: n.gate.twofa }, health: null, ...(n.policy && n.policy.privateNames ? { nameHidden: true } : {}) };
      }),
      links: S.nodes.filter(function (n) { return n.parentId; }).map(function (n) { return { source: n.parentId, target: n.id, kind: "structural", direction: "down" }; }),
      meta: (function () {
        var m = { generatedAt: B.now() * 1000, vaultLocked: S.locked };
        // ADR-080: absent for an agent / a non-Admin (rehearsed with broker.set({ sealedListAbsent: true })); [] for the owner when nothing is sealed
        if (!S.sealedListAbsent) m.sealed = S.sealedExpired ? [] : Object.keys(S.sealed || {}).map(function (id) { var s = S.sealed[id]; return { id: id, label: s.node.label, sealedAt: s.sealedAt, expiresAt: s.sealedAt + 7 * 24 * 60 * 60 }; });
        return m;
      })(),
    };
  };

  // Metadata only (ADR-077): no label, no value, no hash.
  H.entry_list = function (a) {
    B.requireLogin();
    B.requireNode(a.node);
    B.needFactor(a.node, "always");
    var es = list(a.node);
    return {
      node: a.node,
      ids: es.map(function (e) { return e.id; }),
      names: es.map(function (e) { return e.name; }),
      entries: es.map(function (e) { return { id: e.id, name: e.name, type: e.type, sensitivity: e.sensitivity, fieldCount: B.fieldsOf(e).length, hasTotp: B.hasTotp(e), modified: e.modified, rotatedAt: e.rotatedAt, expiresAt: e.expiresAt }; }),
      generation: generation(a.node),
    };
  };

  // One entry's metadata (ADR-078), NEVER a value.  Labels are encrypted with the values, so it needs the node open: a locked node
  // answers node_locked and there is no approval path for it.  The orphaned node is native + presence only (R0).
  H.entry_get = function (a) {
    B.requireLogin();
    var n = B.requireNode(a.node);
    if (n.kind === "orphan") throw B.error("node_access_denied", "access denied", { rule: "R0", node: a.node });
    if (n.gate.locked) throw B.error("node_locked", "the node is locked", { node: a.node });
    B.needFactor(a.node, "always");
    var e = findEntry(a.node, a.entry);
    var fs = B.fieldsOf(e);
    return {
      node: a.node, entry: e.id, name: e.name, ref: list(a.node).indexOf(e) + 1, type: e.type, sensitivity: e.sensitivity, fieldCount: fs.length,
      hasTotp: B.hasTotp(e), modified: e.modified, rotatedAt: e.rotatedAt, expiresAt: e.expiresAt, generation: generation(a.node),
      typeOverridden: !!e.typePin, sensitivityOverridden: !!e.sensPin, fields: fs.map(B.fieldMeta),
    };
  };

  /** The fields a call names: `ids` (each must exist, else not_found and no partial answer), or all of them. */
  function pickFields(e, ids, node) {
    var fs = B.fieldsOf(e);
    if (ids === undefined || ids === null) return fs;
    if (!Array.isArray(ids) || !ids.length) throw B.error("malformed_request", "params.fieldIds must be a non-empty array of field ids");
    return ids.map(function (id) {
      var f = fs.filter(function (x) { return x.id === id; })[0];
      if (!f) throw B.error("not_found", "no such field", { node: node, entry: e.id, field: id });
      return f;
    });
  }

  /** Which field holds the seed: the one named, else the only field, else the one TOTP-seed field; else the call is malformed. */
  function seedField(e, id, node) {
    var fs = B.fieldsOf(e);
    if (id !== undefined && id !== null) {
      var named = fs.filter(function (x) { return x.id === id; })[0];
      if (!named) throw B.error("not_found", "no such field", { node: node, entry: e.id, field: id });
      return named;
    }
    if (fs.length === 1) return fs[0];
    var seeds = fs.filter(function (f) { return B.effective(f).type === "totp-seed"; });
    if (seeds.length === 1) return seeds[0];
    throw B.error("malformed_request", "entry has " + fs.length + " fields and " + seeds.length + " TOTP seeds; pass params.field");
  }

  // What the real broker answers for an OWNER session whose target node is locked (ADR-077, the be-fix lane): a reveal follows the
  // approval-on-demand path (ADR-042) and answers approval_pending; a TOTP code is an ordinary denial (rule R1); only the ops that
  // write or read a note answer node_locked.  A node lock is never vault_locked: the login survives it.
  function revealable(node) {
    var n = B.requireNode(node);
    // R0: the orphaned node is native + presence only, and presence is never attested, so a human is denied too.
    if (n.kind === "orphan") throw B.error("node_access_denied", "access denied", { rule: "R0", node: node });
    if (n.gate.locked) throw B.error("approval_pending", "The vault is locked; the request waits for a decision.", { request: "req-fixture-1", node: node });
    return n;
  }

  H.entry_reveal = function (a) {
    B.requireLogin();
    revealable(a.node);
    B.needFactor(a.node, "reveal");
    var e = findEntry(a.node, a.entry);
    var picked = pickFields(e, a.fieldIds, a.node);
    B.audit("reveal", a.node, a.entry);
    // `value` is present only when exactly one field came back (ADR-078): the single-value callers keep working, a several-field answer has none.
    var answer = { node: a.node, entry: a.entry, fields: picked.map(B.fieldWithValue) };
    if (picked.length === 1) answer.value = picked[0].value;
    return answer;
  };

  H.totp_code = function (a) {
    B.requireLogin();
    var n = B.requireNode(a.node);
    if (n.kind === "orphan") throw B.error("node_access_denied", "access denied", { rule: "R0", node: a.node });
    if (n.gate.locked) throw B.error("node_access_denied", "access denied", { rule: "R1", node: a.node });
    B.needFactor(a.node, "reveal");
    var e = findEntry(a.node, a.entry);
    var f = seedField(e, a.field, a.node);
    if (B.effective(f).type !== "totp-seed") throw B.error("malformed_request", "that field is not a TOTP seed");
    B.audit("totp", a.node, a.entry);
    return { node: a.node, entry: a.entry, code: "123456" };
  };

  // The seed is never returned to a webview: presence cannot be attested on any transport yet (ADR-047).
  H.totp_seed = function (a) {
    B.requireLogin();
    var n = B.requireNode(a.node);
    if (n.gate.locked) throw B.error("node_access_denied", "access denied", { rule: "R1", node: a.node });
    seedField(findEntry(a.node, a.entry), a.field, a.node);
    B.audit("totp_seed", a.node, a.entry, "deny");
    throw B.error("presence_required", "presence is required", { operation: "totp.seed" });
  };

  // The shell's concealed-clipboard command.  The value goes to the fixture's PASTEBOARD, which the page cannot see: the receipt
  // names the fact and the clock, never the content - exactly what the real command returns.  ADR-078: with several fields the
  // reveal is narrowed to the one named (`field`); without it a several-field entry is refused as `field_required` (a code of the
  // shell, not the broker's) and nothing is copied.
  H.entry_copy = function (a) {
    B.requireLogin();
    revealable(a.node);
    B.needFactor(a.node, "reveal");
    var e = findEntry(a.node, a.entry);
    var fs = B.fieldsOf(e);
    if ((a.field === undefined || a.field === null) && fs.length > 1) {
      throw B.error("field_required", "this entry has " + fs.length + " fields; name the one to copy (entryCopy takes a field id)", undefined, "bridge");
    }
    var picked = pickFields(e, a.field === undefined || a.field === null ? undefined : [a.field], a.node)[0];
    B.audit("reveal", a.node, a.entry);
    B.pasteboard = { value: picked.value, node: a.node, entry: a.entry, field: picked.id, concealed: true };
    return { copied: true, clearAfterSeconds: 30 };
  };

  // node.update: label 1-120 characters once trimmed; global and orphan are refused (malformed_request), as the broker does.
  H.node_update = function (a) {
    B.requireLogin();
    var n = B.requireNode(a.node);
    var label = String(a.label == null ? "" : a.label).trim();
    if (label.length < 1 || label.length > 120) throw B.error("malformed_request", "label must be 1 to 120 characters");
    if (n.kind === "global" || n.kind === "orphan") throw B.error("malformed_request", n.id + " cannot be renamed");
    n.label = label;
    B.audit("node_update", a.node);
    return B.nameWarnings({ node: a.node, label: label }, [label]);
  };

  H.notes_read = function (a) {
    B.requireLogin();
    B.requireNodeOpen(a.node);
    B.needFactor(a.node, "always");
    return { node: a.node, markdown: B.S.notes[a.node] || "", modified: null, generation: generation(a.node) };
  };

  H.node_list = function () {
    B.requireLogin();
    return { nodes: B.S.nodes.filter(function (n) { return n.kind !== "orphan"; }).map(function (n) { return n.id; }) };
  };

  // Names only; a node the caller may not read is omitted silently.
  H.search = function (a) {
    B.requireLogin();
    var term = String(a.term || "").toLowerCase();
    var out = [];
    B.S.nodes.forEach(function (n) {
      if (n.kind === "orphan") return;
      list(n.id).forEach(function (e) {
        if (term && e.name.toLowerCase().indexOf(term) >= 0) out.push({ node: n.id, id: e.id, name: e.name });
      });
    });
    return { results: out };
  };

  H.grant_list = function () {
    B.requireLogin();
    return { grants: B.S.grants };
  };

  H.vault_pending_list = function (a) {
    B.requireLogin();
    B.requireNode(a.node);
    return { node: a.node, pending: (B.S.pending[a.node] || []).map(function (p) { return { entry: p.id, name: p.name, type: p.type, sensitivity: p.sensitivity, fieldCount: B.fieldsOf(p).length, created: p.created }; }) };
  };

  H.vault_node_lock = function (a) {
    B.requireLogin();
    B.requireNode(a.node).gate.locked = true;
    B.audit("node_lock", a.node);
    return { node: a.node, locked: true };
  };
  H.vault_node_unlock = function (a) {
    B.requireLogin();
    B.requireNode(a.node).gate.locked = false;
    B.audit("node_unlock", a.node);
    return { node: a.node, locked: false };
  };
  // Examples for tests/unit/fixture-shape.test.ts (see core.js).
  var E = B.examples;
  var OPEN = { locked: false };
  E.graph_snapshot = [{ reset: OPEN, args: {} }];
  E.entry_list = [
    { reset: OPEN, args: { node: "atlas" } },
    { reset: OPEN, args: { node: "nowhere" }, error: "not_found" },
    { reset: { locked: true }, args: { node: "atlas" }, error: "vault_locked" },
  ];
  // ADR-078: `value` only when exactly one field comes back; `fieldIds` narrows the answer, and an unknown id is not_found with no partial answer.
  E.entry_reveal = [
    { reset: OPEN, args: { node: "atlas", entry: "e-a1" } },
    { reset: OPEN, args: { node: "atlas", entry: "e-a2" } },
    { reset: OPEN, args: { node: "atlas", entry: "e-a2", fieldIds: ["f_00a20004"] } },
    // An owner session on a locked node follows the approval-on-demand path (ADR-042, ADR-077): approval_pending, not node_locked.
    { reset: OPEN, args: { node: "cobalt", entry: "e-c1" }, error: "approval_pending" },
    { reset: OPEN, args: { node: "atlas", entry: "e-nope" }, error: "not_found" },
    { reset: OPEN, args: { node: "atlas", entry: "e-a2", fieldIds: ["f_nope"] }, error: "not_found" },
  ];
  E.entry_get = [
    { reset: OPEN, args: { node: "atlas", entry: "e-a1" } },
    { reset: OPEN, args: { node: "atlas", entry: "e-a2" } },
    // Labels are encrypted with the values: a locked node answers node_locked, there is no approval path for metadata.
    { reset: OPEN, args: { node: "cobalt", entry: "e-c1" }, error: "node_locked" },
    { reset: OPEN, args: { node: "atlas", entry: "e-nope" }, error: "not_found" },
    { reset: { locked: true }, args: { node: "atlas", entry: "e-a1" }, error: "vault_locked" },
  ];
  E.totp_code = [
    { reset: OPEN, args: { node: "atlas", entry: "e-a3" } },
    { reset: OPEN, args: { node: "atlas", entry: "e-a3", field: "f_00000000" } },
    { reset: OPEN, args: { node: "cobalt", entry: "e-c1" }, error: "node_access_denied" },
    { reset: OPEN, args: { node: "atlas", entry: "e-a2", field: "f_00a20004" }, error: "malformed_request" },
  ];
  // The seed is never returned (presence cannot be attested, ADR-047): the only declared answer is the refusal.
  E.totp_seed = [
    { reset: OPEN, args: { node: "atlas", entry: "e-a3" }, error: "presence_required" },
    { reset: OPEN, args: { node: "atlas", entry: "e-a3", field: "f_00000000" }, error: "presence_required" },
  ];
  E.node_update = [
    { reset: OPEN, args: { node: "atlas", label: "Atlas renamed" } },
    { reset: OPEN, args: { node: "atlas", label: "   " }, error: "malformed_request" },
    { reset: OPEN, args: { node: "global", label: "renamed" }, error: "malformed_request" },
  ];
  // The shell's concealed-clipboard command (src/lib/bridge.ts `entryCopy`): checked against its declaration like every other handler.
  E.entry_copy = [
    { reset: OPEN, args: { node: "atlas", entry: "e-a1" } },
    { reset: OPEN, args: { node: "atlas", entry: "e-a2", field: "f_00a20004" } },
    // Several fields and none named: the shell refuses with its own code, and copies nothing.
    { reset: OPEN, args: { node: "atlas", entry: "e-a2" }, error: "field_required" },
    { reset: OPEN, args: { node: "atlas", entry: "e-a2", field: "f_nope" }, error: "not_found" },
    { reset: OPEN, args: { node: "cobalt", entry: "e-c1" }, error: "approval_pending" },
  ];
  E.notes_read = [{ reset: OPEN, args: { node: "atlas" } }, { reset: OPEN, args: { node: "beacon" } }];
  E.node_list = [{ reset: OPEN, args: {} }];
  E.search = [{ reset: OPEN, args: { term: "s" } }];
  E.grant_list = [{ reset: OPEN, args: {} }];
  E.vault_pending_list = [
    { reset: OPEN, args: { node: "atlas" } },
    // A write to a locked node waits in the tray: list it, so the shape of an item is checked too.
    { reset: OPEN, setup: function () { H.entry_create({ node: "cobalt", name: "waiting", value: "fixture-value-waiting" }); }, args: { node: "cobalt" } },
  ];
  E.vault_node_lock = [{ reset: OPEN, args: { node: "atlas" } }];
  E.vault_node_unlock = [{ reset: OPEN, args: { node: "cobalt" } }];
})((window.__brokerFixture = window.__brokerFixture || {}));
