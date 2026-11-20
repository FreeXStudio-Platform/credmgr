/* FIXTURE BROKER - an entry's expiry and its history (ADR-156 quick wins 3 and 4; the desktop half is ADR-157), moving an entry (ADR-158),
   and the doctor's tidy-up scan (ADR-161).

   It answers the way the real broker does (crates/brokerd/src/ops/quick_ops.rs) for what a screen has to show:
     - entry.set_expiry takes exactly one of `expiresAt` (unix seconds, 0..9999-12-31) and `clear: true`, refuses a stale generation
       (`conflict`), a locked node (`node_locked`) and an entry that is not there (`not_found`), stores the date on the entry and answers
       `{node, entry, generation, expiresAt}`.  Manifest metadata only: the value is not touched;
     - entry.history answers the entry's own audit records, oldest first, the newest `limit` kept (`truncated` says it cut), with the
       entry's edit, rotation and expiry times while it `exists`.  Looking at the history is not part of it.  The fixture's own audit
       records use short action names ("alias", "reveal"); the real broker writes the op's name ("entry.alias", "entry.reveal"), so the
       answer spells them the broker's way.
   Neither answer carries a value. */
(function (B) {
  "use strict";
  var H = B.handlers;
  var EXPIRY_MAX = 253402300799;
  var HISTORY_MAX = 500;
  var HISTORY_DEFAULT = 100;

  function entryOf(node, id) {
    return (B.S.entries[node] || []).filter(function (x) { return x.id === id; })[0] || null;
  }
  /** The broker's op name for a fixture audit action. */
  function opName(action) {
    if (action.indexOf(".") >= 0) return action;
    if (action === "totp") return "totp.code";
    if (action === "totp_seed") return "totp.seed";
    if (action === "pending_accept") return "vault.pending_accept";
    return "entry." + action;
  }

  H.entry_set_expiry = function (a) {
    B.requireLogin();
    B.requireNodeOpen(a.node);
    var hasAt = typeof a.expiresAt === "number", clear = a.clear === true;
    if (hasAt === clear) throw B.error("malformed_request", "give exactly one of params.expiresAt and params.clear");
    if (hasAt && (a.expiresAt < 0 || a.expiresAt > EXPIRY_MAX || Math.floor(a.expiresAt) !== a.expiresAt)) {
      throw B.error("malformed_request", "params.expiresAt is unix seconds between 1970 and 9999, or null to clear it");
    }
    if (typeof a.generation !== "number") throw B.error("malformed_request", "params.generation is required");
    var e = entryOf(a.node, a.entry);
    if (!e) throw B.error("not_found", "no entry " + a.entry + " on node " + a.node, { node: a.node, entry: a.entry });
    var current = B.S.generation[a.node] || 1;
    if (a.generation !== current) throw B.error("conflict", "the node changed since it was read", { node: a.node, expectedGeneration: a.generation, currentGeneration: current });
    e.expiresAt = hasAt ? a.expiresAt : null;
    B.S.generation[a.node] = current + 1;
    B.audit("entry.set_expiry", a.node, e.id);
    return { node: a.node, entry: e.id, generation: B.S.generation[a.node], expiresAt: e.expiresAt };
  };

  H.entry_history = function (a) {
    B.requireLogin();
    B.requireNode(a.node);
    if (typeof a.entry !== "string" || !a.entry) throw B.error("malformed_request", "params.entry is required");
    var limit = Math.max(1, Math.min(HISTORY_MAX, typeof a.limit === "number" ? a.limit : HISTORY_DEFAULT));
    var rows = B.S.audit
      .filter(function (r) { return r.node === a.node && r.entry === a.entry && opName(r.action) !== "entry.history"; })
      .map(function (r) { return { id: r.id, timestamp: r.timestamp, actor: r.actor, action: opName(r.action), decision: r.decision, generation: null }; });
    var truncated = rows.length > limit;
    if (truncated) rows = rows.slice(rows.length - limit);
    var e = entryOf(a.node, a.entry);
    var out = { node: a.node, entry: a.entry, records: rows, truncated: truncated, exists: !!e };
    if (e) {
      out.name = e.name;
      out.ref = e.ref || 1;
      out.modified = e.modified;
      out.rotatedAt = e.rotatedAt;
      out.expiresAt = e.expiresAt;
    }
    return out;
  };

  /* entry.move (ADR-158, crates/brokerd/src/ops/move_ops.rs): one entry to another node, keeping its id, ref, name, aliases and expiry.
     Refuses the same node and the orphaned node (`malformed_request`), a node that is not there or an entry that is not (`not_found`), a
     locked node at either end (`node_locked`), a stale SOURCE generation (`conflict`) and a name or alias the destination already uses,
     compared without case (`entry_exists`).  Grants on the entry are revoked.  The real broker also asks for a fresh second factor and
     Touch ID (the shell answers Touch ID by itself), which a spec scripts with broker.script when it needs them.  The answer carries no value. */
  H.entry_move = function (a) {
    B.requireLogin();
    if (typeof a.generation !== "number") throw B.error("malformed_request", "params.generation is required");
    if (typeof a.to !== "string" || !a.to) throw B.error("malformed_request", "params.to is required");
    if (a.node === a.to) throw B.error("malformed_request", "params.to is the node the entry is already in");
    var from = B.requireNode(a.node), to = B.requireNode(a.to);
    if (from.kind === "orphan" || to.kind === "orphan") throw B.error("malformed_request", "entries move in and out of the orphan node only by sealing and restoring a node");
    B.requireNodeOpen(a.node);
    B.requireNodeOpen(a.to);
    var e = entryOf(a.node, a.entry);
    if (!e) throw B.error("not_found", "no entry " + a.entry + " on node " + a.node, { node: a.node, entry: a.entry });
    var current = B.S.generation[a.node] || 1;
    if (a.generation !== current) throw B.error("conflict", "the node changed since it was read", { node: a.node, expectedGeneration: a.generation, currentGeneration: current });
    var lc = function (n) { return String(n).toLowerCase(); };
    var mine = [e.name].concat(e.aliases || []).map(lc);
    var taken = (B.S.entries[a.to] || []).some(function (x) {
      return [x.name].concat(x.aliases || []).map(lc).some(function (n) { return mine.indexOf(n) >= 0; });
    });
    if (taken) throw B.error("entry_exists", "node " + a.to + " already has an entry named " + e.name + " or one of its aliases", { node: a.to });
    B.S.entries[a.node] = B.S.entries[a.node].filter(function (x) { return x.id !== e.id; });
    (B.S.entries[a.to] = B.S.entries[a.to] || []).push(e);
    B.S.generation[a.node] = current + 1;
    B.S.generation[a.to] = (B.S.generation[a.to] || 1) + 1;
    var revoked = B.S.grants.filter(function (g) { return g.to && g.to.kind === "entry" && g.to.nodeId === a.node && g.to.entryId === e.id; }).map(function (g) { return g.id; });
    B.S.grants = B.S.grants.filter(function (g) { return revoked.indexOf(g.id) < 0; });
    B.audit("entry.move", a.to, e.id);
    return {
      node: a.to, entry: e.id, ref: e.ref || 1, name: e.name, from: a.node,
      generation: B.S.generation[a.node], toGeneration: B.S.generation[a.to], grantsRevoked: revoked, historyDropped: 0,
    };
  };

  /* rc.2 §1 item 3: lookup by reference, a search of one node, and the audit report (crates/brokerd/src/ops/quick_ops.rs, stable_ops.rs).
     - entry.get_by_ref: the fixture numbers entries vault-wide in node order (or uses an entry's own `ref`), and answers `not_found` for a number
       it does not know and for one in a node that is locked, as the broker does for an entry the caller cannot list;
     - entry.search: names and aliases on one node containing the term, case-insensitive, 1 to 200 characters; never a value;
     - audit.report: counts over the fixture's audit records in [from, to), at most 366 days; actors are the records' own (public) ids. */
  function refs() {
    var out = [], n = 0;
    B.S.nodes.forEach(function (node) {
      (B.S.entries[node.id] || []).forEach(function (e) { n += 1; out.push({ node: node.id, e: e, ref: e.ref || n }); });
    });
    return out;
  }
  H.entry_get_by_ref = function (a) {
    B.requireLogin();
    if (typeof a.reference !== "number" || a.reference < 0 || Math.floor(a.reference) !== a.reference) throw B.error("malformed_request", "params.reference is a number");
    var hit = refs().filter(function (r) { return r.ref === a.reference; })[0];
    if (!hit || B.node(hit.node).gate.locked) throw B.error("not_found", "no entry with that reference");
    return { node: hit.node, entry: hit.e.id, name: hit.e.name, ref: hit.ref };
  };
  H.entry_search = function (a) {
    B.requireLogin();
    B.requireNodeOpen(a.node);
    var term = typeof a.term === "string" ? a.term : "";
    if (!term || Array.from(term).length > 200) throw B.error("malformed_request", "params.term is 1 to 200 characters");
    var t = term.toLowerCase();
    var results = [];
    (B.S.entries[a.node] || []).forEach(function (e) {
      if (String(e.name).toLowerCase().indexOf(t) >= 0) { results.push({ id: e.id, name: e.name }); return; }
      var alias = (e.aliases || []).filter(function (x) { return String(x).toLowerCase().indexOf(t) >= 0; })[0];
      if (alias) results.push({ id: e.id, name: e.name, alias: alias });
    });
    return { node: a.node, results: results };
  };
  H.audit_report = function (a) {
    B.requireLogin();
    if (typeof a.from !== "number" || typeof a.to !== "number") throw B.error("malformed_request", "params.from and params.to are required");
    if (a.to <= a.from) throw B.error("malformed_request", "params.to must be after params.from");
    if (a.to - a.from > 366 * 86400) throw B.error("malformed_request", "an audit report covers at most 366 days");
    var only = typeof a.node === "string" && a.node ? a.node : null;
    var recs = B.S.audit.filter(function (r) { return r.timestamp >= a.from && r.timestamp < a.to && (!only || r.node === only); });
    function tally(key) {
      var m = {};
      recs.forEach(function (r) {
        var k = key(r);
        if (k === null || k === undefined) return;
        var t = (m[k] = m[k] || { count: 0, allow: 0, deny: 0 });
        t.count += 1;
        if (r.decision === "deny") t.deny += 1; else if (r.decision === "allow") t.allow += 1;
      });
      return Object.keys(m).sort().map(function (k) { return { k: k, t: m[k] }; });
    }
    var allow = recs.filter(function (r) { return r.decision === "allow"; }).length;
    var deny = recs.filter(function (r) { return r.decision === "deny"; }).length;
    var denied = recs.filter(function (r) { return r.decision === "deny"; });
    return {
      from: a.from, to: a.to, node: only, records: recs.length,
      decisions: { allow: allow, deny: deny, other: recs.length - allow - deny },
      byAction: tally(function (r) { return r.action; }).map(function (x) { return { action: x.k, count: x.t.count, allow: x.t.allow, deny: x.t.deny }; }),
      byActor: tally(function (r) { return r.actor; }).map(function (x) { return { actor: x.k, count: x.t.count, allow: x.t.allow, deny: x.t.deny }; }),
      byNode: tally(function (r) { return r.node; }).map(function (x) { return { node: x.k, count: x.t.count, allow: x.t.allow, deny: x.t.deny }; }),
      denials: {
        total: denied.length,
        reasons: denied.length ? [{ action: denied[0].action, reason: "node_access_denied", count: denied.length }] : [],
        recent: denied.slice(-20).reverse().map(function (r) { return { id: r.id, timestamp: r.timestamp, actor: r.actor, action: r.action, node: r.node, reason: "node_access_denied" }; }),
      },
      presence: { uses: 0, byOp: [], refused: 0 },
      chain: { months: [], verified: true },
    };
  };

  // Examples for tests/unit/fixture-shape.test.ts (see core.js).
  /* entry.tag_set (ADR-167, crates/brokerd/src/ops/tags_ops.rs): the whole set, normalised (trimmed, lower-cased, inner spaces to one
     `-`; letters, digits and - _ . : /; at most 32 characters, at most 16 tags), a stale generation `conflict`, a locked node
     `node_locked`, a missing entry `not_found`.  Metadata only. */
  H.entry_tag_set = function (a) {
    B.requireLogin();
    B.requireNodeOpen(a.node);
    if (typeof a.generation !== "number") throw B.error("malformed_request", "params.generation is required");
    if (!Array.isArray(a.tags)) throw B.error("malformed_request", "params.tags is required");
    var e = entryOf(a.node, a.entry);
    if (!e) throw B.error("not_found", "no entry " + a.entry + " on node " + a.node, { node: a.node, entry: a.entry });
    var current = B.S.generation[a.node] || 1;
    if (a.generation !== current) throw B.error("conflict", "the node changed since it was read", { node: a.node, expectedGeneration: a.generation, currentGeneration: current });
    var out = [];
    a.tags.forEach(function (raw, i) {
      var t = typeof raw === "string" ? raw.trim().toLowerCase().replace(/\s+/g, "-") : "";
      if (!t || Array.from(t).length > 32 || !/^[\p{L}\p{N}\-_.:/]+$/u.test(t)) throw B.error("malformed_request", "params.tags[" + i + "] is not a usable tag");
      if (out.indexOf(t) < 0) out.push(t);
    });
    if (out.length > 16) throw B.error("malformed_request", "params.tags holds at most 16 tags");
    if (out.length) e.tags = out; else delete e.tags;
    e.modified = B.now();
    B.S.generation[a.node] = current + 1;
    B.audit("entry.tag_set", a.node, e.id);
    return { node: a.node, entry: e.id, generation: B.S.generation[a.node], tags: out.slice() };
  };

  /* merge.* (ADR-168, crates/brokerd/src/ops/merge_ops.rs), inside one node: suggestions by equal value (identical when every value is
     equal) and by names alike, apply (the kept entry takes the dropped names as aliases; a stale generation is `conflict`), dismiss and the
     decision memory, auto and auto_all (identical only, a dry run unless `apply`).  No answer carries a value. */
  var MERGE_DISMISSED = {};
  function memoryOf(node) { return (MERGE_DISMISSED[node] = MERGE_DISMISSED[node] || {}); }
  function mergeKey(ids) { return ids.slice().sort().join("+"); }
  function suggestionsOf(node) {
    var es = (B.S.entries[node] || []).slice();
    var byValue = {};
    es.forEach(function (e, i) { var v = typeof e.value === "string" ? e.value : JSON.stringify(B.fieldsOf(e).map(function (f) { return f.value; })); (byValue[v] = byValue[v] || []).push(i); });
    var out = [];
    Object.keys(byValue).forEach(function (v) {
      var idx = byValue[v];
      if (idx.length < 2 || v.length < 8) return;
      var members = idx.map(function (i) { return es[i]; });
      out.push({
        key: mergeKey(members.map(function (e) { return e.id; })), kind: "identical", reasons: ["same_values"], identical: true,
        keep: members[0].id, entries: members.map(function (e) { return { entry: e.id, ref: es.indexOf(e) + 1, name: e.name }; }),
      });
    });
    return out;
  }
  function mergeGate(a) {
    B.requireLogin();
    B.requireNodeOpen(a.node);
  }
  function applyMerge(node, keep, drop) {
    var es = B.S.entries[node] || [];
    var k = entryOf(node, keep);
    if (!k) throw B.error("not_found", "no entry " + keep + " on node " + node, { node: node, entry: keep });
    var gone = drop.map(function (id) {
      var d = entryOf(node, id);
      if (!d || id === keep) throw B.error("not_found", "no entry " + id + " on node " + node, { node: node, entry: id });
      return d;
    });
    var added = [];
    gone.forEach(function (d) { [d.name].concat(d.aliases || []).forEach(function (n) { if ((k.aliases || []).indexOf(n) < 0) { k.aliases = (k.aliases || []).concat([n]); added.push(n); } }); });
    var tagsBefore = (k.tags || []).slice(), tagsAdded = [];
    gone.forEach(function (d) { (d.tags || []).forEach(function (t) { if ((k.tags || []).indexOf(t) < 0) { k.tags = (k.tags || []).concat([t]); if (tagsBefore.indexOf(t) < 0) tagsAdded.push(t); } }); });
    B.S.entries[node] = es.filter(function (e) { return drop.indexOf(e.id) < 0; });
    B.S.generation[node] = (B.S.generation[node] || 1) + 1;
    var merged = gone.map(function (d) { B.audit("entry.remove", node, d.id); return { entry: d.id, name: d.name, undo: B.S.audit[B.S.audit.length - 1].id }; });
    return { keep: keep, merged: merged, aliasesAdded: added, tagsAdded: tagsAdded };
  }
  function needGeneration(a) {
    if (typeof a.generation !== "number") throw B.error("malformed_request", "params.generation is required");
    var current = B.S.generation[a.node] || 1;
    if (a.generation !== current) throw B.error("conflict", "the node changed since it was read", { node: a.node, expectedGeneration: a.generation, currentGeneration: current });
  }

  H.merge_suggestions = function (a) {
    mergeGate(a);
    var mem = memoryOf(a.node);
    var all = suggestionsOf(a.node);
    var shown = all.filter(function (s) { return a.includeDismissed === true || !mem[s.key]; }).map(function (s) { if (mem[s.key]) s.dismissed = true; return s; });
    return { node: a.node, generation: B.S.generation[a.node] || 1, valuesCompared: true, truncated: false, dismissedCount: Object.keys(mem).length, suggestions: shown };
  };
  H.merge_apply = function (a) {
    mergeGate(a);
    if (!Array.isArray(a.drop) || !a.drop.length) throw B.error("malformed_request", "params.drop holds 1 to 19 entry ids");
    needGeneration(a);
    var r = applyMerge(a.node, a.keep, a.drop);
    r.node = a.node;
    r.generation = B.S.generation[a.node];
    return r;
  };
  H.merge_auto = function (a) {
    mergeGate(a);
    needGeneration(a);
    var s = suggestionsOf(a.node).filter(function (x) { return x.key === a.key && !memoryOf(a.node)[x.key]; })[0];
    if (!s) throw B.error("malformed_request", "params.key is not an open suggestion for this node");
    var r = applyMerge(a.node, s.keep, s.entries.map(function (e) { return e.entry; }).filter(function (id) { return id !== s.keep; }));
    r.node = a.node;
    r.key = a.key;
    r.generation = B.S.generation[a.node];
    return r;
  };
  H.merge_auto_all = function (a) {
    mergeGate(a);
    var mem = memoryOf(a.node);
    var planned = suggestionsOf(a.node).filter(function (s) { return !mem[s.key]; });
    if (a.apply !== true) return { node: a.node, dryRun: true, generation: B.S.generation[a.node] || 1, planned: planned, skipped: [] };
    needGeneration(a);
    var merged = planned.map(function (s) { var r = applyMerge(a.node, s.keep, s.entries.map(function (e) { return e.entry; }).filter(function (id) { return id !== s.keep; })); r.key = s.key; return r; });
    return { node: a.node, dryRun: false, planned: planned, merged: merged, skipped: [], generation: B.S.generation[a.node] || 1 };
  };
  H.merge_dismiss = function (a) {
    mergeGate(a);
    if (typeof a.key !== "string" || a.key.split("+").length < 2) throw B.error("malformed_request", "params.key is 2 to 20 entry ids joined with +");
    memoryOf(a.node)[a.key] = B.now();
    B.S.generation[a.node] = (B.S.generation[a.node] || 1) + 1;
    return { node: a.node, key: a.key, dismissed: true, generation: B.S.generation[a.node] };
  };
  H.merge_undismiss = function (a) {
    mergeGate(a);
    var mem = memoryOf(a.node), had = !!mem[a.key];
    delete mem[a.key];
    if (had) B.S.generation[a.node] = (B.S.generation[a.node] || 1) + 1;
    return { node: a.node, key: a.key, restored: had, generation: B.S.generation[a.node] || 1 };
  };
  H.merge_dismissed_list = function (a) {
    mergeGate(a);
    var mem = memoryOf(a.node);
    return { node: a.node, dismissed: Object.keys(mem).map(function (k) { return { key: k, entries: k.split("+").map(function (id) { var e = entryOf(a.node, id); return { entry: id, name: e ? e.name : null }; }), dismissedAt: mem[k] }; }) };
  };
  H.merge_restore_all = function (a) {
    mergeGate(a);
    var n = Object.keys(memoryOf(a.node)).length;
    MERGE_DISMISSED[a.node] = {};
    if (n) B.S.generation[a.node] = (B.S.generation[a.node] || 1) + 1;
    return { node: a.node, restored: n, generation: B.S.generation[a.node] || 1 };
  };

  var E = B.examples;
  var OPEN = { locked: false }; // declared again here: the examples above this file's first OPEN run before it is assigned
  var NOW = function () { return B.now(); };
  var DENIED = function () { B.audit("entry.reveal", "atlas", "e-a1", "deny"); B.audit("entry.list", "atlas", null, "allow"); };
  E.entry_get_by_ref = [
    { reset: OPEN, args: { reference: 1 } },
    { reset: OPEN, args: { reference: 999 }, error: "not_found" },
    { reset: OPEN, args: { reference: 6 }, error: "not_found" }, // cobalt, a locked node: answered as if there were none
    { reset: { locked: true }, args: { reference: 1 }, error: "vault_locked" },
  ];
  E.entry_search = [
    { reset: OPEN, args: { node: "atlas", term: "STRIPE" } },
    { reset: OPEN, setup: function () { B.S.entries.atlas[0].aliases = ["live-payments"]; }, args: { node: "atlas", term: "payments" } },
    { reset: OPEN, args: { node: "atlas", term: "" }, error: "malformed_request" },
    { reset: OPEN, args: { node: "cobalt", term: "shop" }, error: "node_locked" },
  ];
  E.audit_report = [
    { reset: OPEN, setup: DENIED, args: function () { return { from: NOW() - 86400, to: NOW() + 1 }; } },
    { reset: OPEN, setup: DENIED, args: function () { return { from: NOW() - 86400, to: NOW() + 1, node: "atlas" }; } },
    { reset: OPEN, args: function () { return { from: NOW() - 400 * 86400, to: NOW() }; }, error: "malformed_request" },
    { reset: { locked: true }, args: { from: 0, to: 1 }, error: "vault_locked" },
  ];

  /* vault.doctor_scan (ADR-161, crates/brokerd/src/ops/doctor_ops.rs): a read over every open node but the orphaned one.  The real broker
     compares values by a keyed hash it drops after the scan; the fixture compares its own plain fixture values, inside this file, and
     answers what the real one would: names, ids, refs, generations, reasons, the `entry.move` params of a move proposal — never a value.
     Covers shared values (with the proposal for where the copies sit), misfiled entries in global, names that differ only in separators
     or case, expired, expiring and stale entries.  Weak and mistyped values are the real broker's (a spec scripts them when it needs them). */
  var DAY = 86400;
  function compact(n) { return String(n).toLowerCase().replace(/[-_. /:]/g, ""); }
  function ancestry(id) {
    var out = [id], at = B.node(id);
    while (at && at.parentId && out.indexOf(at.parentId) < 0) { out.push(at.parentId); at = B.node(at.parentId); }
    return out;
  }
  H.vault_doctor_scan = function (a) {
    B.requireLogin();
    var days = function (v, key, dflt) {
      if (v === undefined || v === null) return dflt;
      if (typeof v !== "number" || v < 1 || v > 3650 || Math.floor(v) !== v) throw B.error("malformed_request", "params." + key + " is 1 to 3650");
      return v;
    };
    var staleDays = days(a.staleDays, "staleDays", 365), expiringDays = days(a.expiringDays, "expiringDays", 30);
    var now = Math.floor(Date.now() / 1000);
    var seen = [], skipped = [], nodesScanned = 0;
    B.S.nodes.forEach(function (n) {
      if (n.kind === "orphan") return;
      if (n.gate.locked) { skipped.push({ node: n.id, nodeLabel: n.label, reason: "locked", what: "all" }); return; }
      nodesScanned++;
      (B.S.entries[n.id] || []).forEach(function (e) {
        seen.push({ n: n, e: e, ref: { node: n.id, nodeLabel: n.label, entry: e.id, ref: e.ref || 1, name: e.name, generation: B.S.generation[n.id] || 1 } });
      });
    });
    var findings = { duplicate_value: [], misfiled: [], similar_names: [], weak: [], mistyped: [], expired: [], expiring: [], stale: [] };
    var horizon = now + expiringDays * DAY, staleBefore = now - staleDays * DAY;
    seen.forEach(function (s) {
      var e = s.e;
      if (typeof e.expiresAt === "number" && e.expiresAt <= horizon) {
        var k = e.expiresAt <= now ? "expired" : "expiring";
        findings[k].push({ kind: k, entries: [s.ref], expiresAt: e.expiresAt, source: "manifest" });
      }
      var last = typeof e.rotatedAt === "number" ? e.rotatedAt : e.modified;
      if (typeof last === "number" && last < staleBefore) {
        findings.stale.push({ kind: "stale", entries: [s.ref], lastChanged: last, basis: typeof e.rotatedAt === "number" ? "rotated" : "modified" });
      }
    });
    var move = function (s, to, action) {
      var t = B.node(to);
      return { action: action, op: "entry.move", to: to, toLabel: t ? t.label : to, move: { node: s.ref.node, entry: s.ref.entry, to: to, generation: s.ref.generation } };
    };
    // Shared values: grouped by the fixture's own value, inside this file only.
    var groups = {};
    seen.forEach(function (s, i) {
      var vals = s.e.fields ? s.e.fields.map(function (f) { return f.value; }) : [s.e.value];
      vals.forEach(function (v) {
        if (typeof v !== "string" || v.trim().length < 8) return;
        var g = groups[v] = groups[v] || [];
        if (g.indexOf(i) < 0) g.push(i);
      });
    });
    Object.keys(groups).forEach(function (v) {
      var g = groups[v];
      if (g.length < 2) return;
      var nodes = g.map(function (i) { return seen[i].n.id; }).filter(function (x, j, arr) { return arr.indexOf(x) === j; });
      var proposal;
      if (nodes.length === 1) proposal = { action: "merge", op: null };
      else {
        var chains = nodes.map(ancestry);
        var common = chains[0].filter(function (c) { return chains.every(function (ch) { return ch.indexOf(c) >= 0; }); })[0];
        var keeper = g.filter(function (i) { return seen[i].n.id === common; })[0];
        if (keeper !== undefined) proposal = { action: "remove_copies", op: null, keep: { node: seen[keeper].ref.node, entry: seen[keeper].ref.entry, name: seen[keeper].ref.name } };
        else if (common && common !== "global") proposal = move(seen[g[0]], common, "move_to_parent");
        else proposal = { action: "share", op: null, options: ["grant", "shared_node"] };
      }
      findings.duplicate_value.push({ kind: "duplicate_value", match: "exact", entries: g.map(function (i) { return seen[i].ref; }), proposal: proposal });
    });
    // Misfiled: an entry in global named for exactly one project.
    var projects = B.S.nodes.filter(function (n) { return n.depth === 1 && n.kind !== "orphan"; });
    seen.forEach(function (s) {
      if (s.n.id !== "global") return;
      var first = compact(String(s.e.name).split(/[^A-Za-z0-9]/).filter(Boolean)[0] || "");
      var hits = projects.filter(function (p) { return first && (compact(p.id) === first || compact(p.label) === first); });
      if (hits.length === 1) findings.misfiled.push({ kind: "misfiled", entries: [s.ref], proposal: move(s, hits[0].id, "move_to_project") });
    });
    // Near-identical names: the same once separators and case are ignored, but not the same name.
    for (var i = 0; i < seen.length; i++) {
      for (var j = i + 1; j < seen.length; j++) {
        var x = seen[i].e.name, y = seen[j].e.name;
        if (x.toLowerCase() !== y.toLowerCase() && compact(x) === compact(y)) {
          findings.similar_names.push({ kind: "similar_names", similarity: "separators", sameNode: seen[i].n.id === seen[j].n.id, entries: [seen[i].ref, seen[j].ref], proposal: { action: "rename_or_merge", op: null } });
        }
      }
    }
    var order = ["duplicate_value", "misfiled", "similar_names", "weak", "mistyped", "expired", "expiring", "stale"];
    var counts = {}, all = [];
    order.forEach(function (k) { counts[k] = findings[k].length; all = all.concat(findings[k]); });
    return {
      now: now, staleDays: staleDays, expiringDays: expiringDays, nodesScanned: nodesScanned, entriesScanned: seen.length,
      valuesChecked: seen.length, skipped: skipped, truncated: false, counts: counts, findings: all,
    };
  };

  /* ADR-169: vault.doctor_apply — every move of one doctor plan in one request.  The real broker checks every step (in order, each seeing the
     earlier ones done) before it asks for its factors or moves anything, so a stale generation, a missing entry, a name clash, a locked node or
     the same entry twice is the request's error and nothing moved; then it applies each move through entry.move's commit, stopping at the first
     that fails (a failure only the commit finds — the fixture has none — is answered as a report).  Here the plan is run move by move through
     entry_move on a copy of the state's moving parts, which is put back if any step fails: the same outcome. */
  H.vault_doctor_apply = function (a) {
    B.requireLogin();
    if (!Array.isArray(a.moves) || a.moves.length < 1 || a.moves.length > 500) throw B.error("malformed_request", "params.moves holds 1 to 500 moves");
    var ids = {};
    a.moves.forEach(function (m, i) {
      ["node", "entry", "to"].forEach(function (k) {
        if (!m || typeof m[k] !== "string" || !m[k]) throw B.error("malformed_request", "params.moves[" + i + "]." + k + " is required");
      });
      if (typeof m.generation !== "number") throw B.error("malformed_request", "params.moves[" + i + "].generation is required");
      if (ids[m.entry]) throw B.error("malformed_request", "params.moves names the entry " + m.entry + " twice");
      ids[m.entry] = true;
    });
    a.moves.forEach(function (m) {
      var current = B.S.generation[m.node] || 1;
      if (m.generation !== current) throw B.error("conflict", "the node changed since it was read", { node: m.node, expectedGeneration: m.generation, currentGeneration: current });
    });
    var saved = JSON.stringify({ entries: B.S.entries, generation: B.S.generation, grants: B.S.grants, audit: B.S.audit });
    var generations = {}, applied = [];
    try {
      a.moves.forEach(function (m, index) {
        var gen = generations[m.node] !== undefined ? generations[m.node] : m.generation;
        var r = H.entry_move({ node: m.node, entry: m.entry, to: m.to, generation: gen });
        generations[m.node] = r.generation;
        generations[m.to] = r.toGeneration;
        r.index = index;
        applied.push(r);
      });
    } catch (e) {
      var back = JSON.parse(saved);
      B.S.entries = back.entries;
      B.S.generation = back.generation;
      B.S.grants = back.grants;
      B.S.audit = back.audit;
      throw e;
    }
    return { complete: true, applied: applied, notApplied: 0 };
  };

  var OPEN = { locked: false };
  var GEN = function () { return B.S.generation.atlas || 1; };
  E.entry_set_expiry = [
    { reset: OPEN, args: function () { return { node: "atlas", entry: "e-a1", generation: GEN(), expiresAt: 1790000000 }; } },
    { reset: OPEN, args: function () { return { node: "atlas", entry: "e-a1", generation: GEN(), clear: true }; } },
    { reset: OPEN, args: { node: "atlas", entry: "e-a1", generation: 99, expiresAt: 1790000000 }, error: "conflict" },
    { reset: OPEN, args: function () { return { node: "atlas", entry: "e-nope", generation: GEN(), expiresAt: 1790000000 }; }, error: "not_found" },
    { reset: OPEN, args: function () { return { node: "atlas", entry: "e-a1", generation: GEN(), expiresAt: 1790000000, clear: true }; }, error: "malformed_request" },
    { reset: OPEN, args: function () { return { node: "cobalt", entry: "e-c1", generation: 1, expiresAt: 1790000000 }; }, error: "node_locked" },
  ];
  E.entry_move = [
    { reset: OPEN, args: function () { return { node: "atlas", entry: "e-a1", to: "beacon", generation: GEN() }; } },
    { reset: OPEN, args: { node: "atlas", entry: "e-a1", to: "beacon", generation: 99 }, error: "conflict" },
    { reset: OPEN, args: function () { return { node: "atlas", entry: "e-a1", to: "atlas", generation: GEN() }; }, error: "malformed_request" },
    { reset: OPEN, args: function () { return { node: "atlas", entry: "e-a1", to: "orphaned", generation: GEN() }; }, error: "malformed_request" },
    { reset: OPEN, args: function () { return { node: "atlas", entry: "e-nope", to: "beacon", generation: GEN() }; }, error: "not_found" },
    { reset: OPEN, args: function () { return { node: "atlas", entry: "e-a1", to: "cobalt", generation: GEN() }; }, error: "node_locked" },
    { reset: OPEN, args: function () { return { node: "atlas", entry: "e-a1", to: "nowhere", generation: GEN() }; }, error: "not_found" },
  ];
  E.vault_doctor_scan = [
    { reset: OPEN, args: {} },
    { reset: OPEN, args: { staleDays: 90, expiringDays: 7 } },
    // A shared value in two sub-nodes of one project, one in two projects, and an entry misfiled in global.
    { reset: OPEN, setup: function () {
        B.S.nodes.push({ id: "staging-2", label: "staging-2", kind: "sub", depth: 2, parentId: "atlas", gate: { locked: false, twofa: "none" } });
        B.S.entries["staging-2"] = [{ id: "e-s2", name: "stg-db-copy", type: "server", sensitivity: "medium", value: "fixture-value-stg-db", modified: 1760000000, rotatedAt: null, expiresAt: null }];
        B.S.entries.beacon.push({ id: "e-b2", name: "stripe-copy", type: "api", sensitivity: "high", value: "fixture-value-stripe-live", modified: 1760000000, rotatedAt: null, expiresAt: null });
        B.S.entries.global.push({ id: "e-g2", name: "atlas-hook", type: "api", sensitivity: "low", value: "fixture-value-atlas-hook", modified: 1760000000, rotatedAt: null, expiresAt: null });
      }, args: {} },
    { reset: OPEN, args: { staleDays: 0 }, error: "malformed_request" },
    { reset: { locked: true }, args: {}, error: "vault_locked" },
  ];
  var GENOF = function (n) { return B.S.generation[n] || 1; };
  E.vault_doctor_apply = [
    // Two moves out of atlas: the second carries the generation the first left.
    { reset: OPEN, args: function () { return { moves: [
        { node: "atlas", entry: "e-a1", to: "beacon", generation: GEN() },
        { node: "atlas", entry: "e-a2", to: "beacon", generation: GEN() },
      ] }; } },
    { reset: OPEN, args: { moves: [{ node: "atlas", entry: "e-a1", to: "beacon", generation: 99 }] }, error: "conflict" },
    { reset: OPEN, args: function () { return { moves: [
        { node: "atlas", entry: "e-a1", to: "beacon", generation: GEN() },
        { node: "atlas", entry: "e-a1", to: "global", generation: GEN() },
      ] }; }, error: "malformed_request" },
    { reset: OPEN, args: function () { return { moves: [
        { node: "atlas", entry: "e-a1", to: "beacon", generation: GEN() },
        { node: "atlas", entry: "e-nope", to: "beacon", generation: GEN() },
      ] }; }, error: "not_found" },
    { reset: OPEN, args: function () { return { moves: [{ node: "atlas", entry: "e-a1", to: "cobalt", generation: GEN() }] }; }, error: "node_locked" },
    { reset: OPEN, args: function () { return { moves: [{ node: "global", entry: "e-g1", to: "beacon", generation: GENOF("global") }] }; } },
    { reset: OPEN, args: { moves: [] }, error: "malformed_request" },
    { reset: { locked: true }, args: { moves: [{ node: "atlas", entry: "e-a1", to: "beacon", generation: 1 }] }, error: "vault_locked" },
  ];
  E.entry_tag_set = [
    { reset: OPEN, args: function () { return { node: "atlas", entry: "e-a1", generation: GEN(), tags: ["Prod", "staging db"] }; } },
    { reset: OPEN, args: function () { return { node: "atlas", entry: "e-a1", generation: GEN(), tags: [] }; } },
    { reset: OPEN, args: { node: "atlas", entry: "e-a1", generation: 99, tags: ["x"] }, error: "conflict" },
    { reset: OPEN, args: function () { return { node: "atlas", entry: "e-a1", generation: GEN(), tags: ["no,commas"] }; }, error: "malformed_request" },
    { reset: OPEN, args: function () { return { node: "atlas", entry: "e-nope", generation: GEN(), tags: ["x"] }; }, error: "not_found" },
  ];
  var TWIN = function () {
    B.S.entries.atlas.push({ id: "e-a9", name: "copy-of-a1", type: "api", sensitivity: "high", value: "fixture-merge-twin-value", modified: 1760000000, rotatedAt: null, expiresAt: null });
    B.S.entries.atlas.push({ id: "e-a8", name: "another-copy", type: "api", sensitivity: "high", value: "fixture-merge-twin-value", modified: 1760000000, rotatedAt: null, expiresAt: null });
  };
  E.merge_suggestions = [
    { reset: OPEN, setup: TWIN, args: { node: "atlas" } },
    { reset: OPEN, args: { node: "atlas", includeDismissed: true } },
  ];
  E.merge_apply = [
    { reset: OPEN, setup: TWIN, args: function () { return { node: "atlas", keep: "e-a9", drop: ["e-a8"], generation: GEN() }; } },
    { reset: OPEN, setup: TWIN, args: { node: "atlas", keep: "e-a9", drop: ["e-a8"], generation: 99 }, error: "conflict" },
    { reset: OPEN, setup: TWIN, args: function () { return { node: "atlas", keep: "e-a9", drop: ["e-elsewhere"], generation: GEN() }; }, error: "not_found" },
  ];
  E.merge_auto = [
    { reset: OPEN, setup: TWIN, args: function () { return { node: "atlas", key: "e-a8+e-a9", generation: GEN() }; } },
    { reset: OPEN, setup: TWIN, args: function () { return { node: "atlas", key: "e-a1+e-a9", generation: GEN() }; }, error: "malformed_request" },
  ];
  E.merge_auto_all = [
    { reset: OPEN, setup: TWIN, args: { node: "atlas" } },
    { reset: OPEN, setup: TWIN, args: function () { return { node: "atlas", apply: true, generation: GEN() }; } },
  ];
  E.merge_dismiss = [
    { reset: OPEN, setup: TWIN, args: { node: "atlas", key: "e-a8+e-a9" } },
    { reset: OPEN, args: { node: "atlas", key: "e-a8" }, error: "malformed_request" },
  ];
  E.merge_undismiss = [
    { reset: OPEN, args: { node: "atlas", key: "e-a8+e-a9" } },
  ];
  E.merge_dismissed_list = [
    { reset: OPEN, args: { node: "atlas" } },
  ];
  E.merge_restore_all = [
    { reset: OPEN, args: { node: "atlas" } },
  ];
  E.entry_history = [
    { reset: OPEN, args: { node: "atlas", entry: "e-a1" } },
    { reset: OPEN, args: { node: "atlas", entry: "e-gone", limit: 10 } },
    { reset: OPEN, args: { node: "atlas", entry: "" }, error: "malformed_request" },
  ];
})((window.__brokerFixture = window.__brokerFixture || {}));
