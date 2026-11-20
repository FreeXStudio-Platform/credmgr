/* FIXTURE BROKER - aliases, near-duplicate names and the .env import (ADR-121, ADR-122), and the shell's local env_preview.

   It answers the way the real broker does (crates/brokerd/src/ops/alias.rs) for what a screen has to show:
     - entry.alias sets the WHOLE list (at most 8), echoes the node's new generation, refuses a stale one (`conflict`), a locked node
       (`node_locked`), a name or alias another entry has, compared case-insensitively here (`entry_exists`), and the entry's own name;
     - entry.similar answers `{taken, similar:[{id,name,alias?,reason}]}`; "near" is the broker's rule in small: the same letters with other
       separators or case, or one edit apart at five letters or more; a numbered series is not near;
     - entry.import_env with `dryRun` writes nothing and names every pair's status (new, exists, duplicate, empty, invalid); without it the
       `new` pairs become entries, `onConflict: "refuse"` (the default) writes nothing if any name conflicts, "skip" leaves them out;
     - env_preview is the shell's LOCAL parse of a .env text: `NAME=value`, `export`, `#` comments, single and double quotes on one line.
       A line it cannot read is `invalid_env`, named by NUMBER, never quoted.  (The real parser is crates/core/src/dotenv.rs.)
   No answer of entry.alias, entry.similar or entry.import_env carries a value. */
(function (B) {
  "use strict";
  var H = B.handlers;

  function list(node) {
    return B.S.entries[node] || [];
  }
  function lc(s) {
    return String(s).toLowerCase();
  }
  /** Every name an entry answers to. */
  function namesOf(e) {
    return [e.name].concat(e.aliases || []);
  }
  function taken(node, name, exceptId) {
    var c = lc(name);
    var held = list(node).some(function (e) {
      return e.id !== exceptId && namesOf(e).some(function (n) { return lc(n) === c; });
    });
    return held || (B.S.pending[node] || []).some(function (p) { return lc(p.name) === c; });
  }

  function compact(s) {
    return lc(s).replace(/[-_. /:\\]/g, "");
  }
  function trimDigits(s) {
    return s.replace(/[0-9]+$/, "");
  }
  function oneEdit(a, b) {
    if (Math.abs(a.length - b.length) > 1) return false;
    var i = 0;
    var n = Math.min(a.length, b.length);
    while (i < n && a[i] === b[i]) i += 1;
    if (i === n) return true;
    if (a.length === b.length) {
      if (a.slice(i + 1) === b.slice(i + 1)) return true;
      return i + 1 < a.length && a[i] === b[i + 1] && a[i + 1] === b[i] && a.slice(i + 2) === b.slice(i + 2);
    }
    var long = a.length > b.length ? a : b;
    var short = a.length > b.length ? b : a;
    return long.slice(i + 1) === short.slice(i);
  }
  function similarity(a, b) {
    if (lc(a) === lc(b)) return null;
    var ka = compact(a);
    var kb = compact(b);
    if (!ka || !kb) return null;
    if (ka === kb) return "separators";
    if (trimDigits(ka) === trimDigits(kb)) return null;
    if (Math.min(ka.length, kb.length) < 5) return null;
    return oneEdit(ka, kb) ? "one-edit" : null;
  }
  function near(node, name, exceptId, max) {
    var out = [];
    list(node).forEach(function (e) {
      if (e.id === exceptId || out.length >= max) return;
      var why = similarity(name, e.name);
      if (why) { out.push({ id: e.id, name: e.name, reason: why }); return; }
      var al = (e.aliases || []).filter(function (a) { return similarity(name, a); })[0];
      if (al !== undefined) out.push({ id: e.id, name: e.name, alias: al, reason: similarity(name, al) });
    });
    return out;
  }

  H.entry_alias = function (a) {
    B.requireLogin();
    B.requireNodeOpen(a.node);
    var e = list(a.node).filter(function (x) { return x.id === a.entry; })[0];
    if (!e) throw B.error("not_found", "no such entry", { node: a.node, entry: a.entry });
    var current = B.S.generation[a.node] || 1;
    if (typeof a.generation !== "number") throw B.error("malformed_request", "params.generation is required");
    if (!Array.isArray(a.aliases)) throw B.error("malformed_request", "params.aliases is required");
    if (a.aliases.length > 8) throw B.error("malformed_request", "params.aliases holds at most 8 names");
    if (a.generation !== current) throw B.error("conflict", "the node changed since it was read", { node: a.node, expectedGeneration: a.generation, currentGeneration: current });
    var seen = {};
    a.aliases.forEach(function (n, i) {
      if (typeof n !== "string" || !n.trim() || /[\u0000-\u001f]/.test(n) || Array.from(n).length > 200) throw B.error("malformed_request", "params.aliases[" + i + "] is not a usable name");
      if (seen[lc(n)]) throw B.error("malformed_request", "params.aliases[" + i + "] is the same name as an earlier alias");
      seen[lc(n)] = true;
      if (lc(n) === lc(e.name)) throw B.error("malformed_request", "params.aliases[" + i + "] is the entry's own name");
      if (taken(a.node, n, e.id)) throw B.error("entry_exists", "an entry with that name exists", { node: a.node, name: n });
    });
    var similar = [];
    a.aliases.forEach(function (n) { near(a.node, n, e.id, 20).forEach(function (x) { similar.push(x); }); });
    if (a.aliases.length) e.aliases = a.aliases.slice(); else delete e.aliases;
    e.modified = B.now();
    B.S.generation[a.node] = current + 1;
    B.audit("alias", a.node, e.id);
    var out = { node: a.node, entry: e.id, generation: B.S.generation[a.node], aliases: (e.aliases || []).slice() };
    if (similar.length) out.similar = similar.slice(0, 20);
    return B.nameWarnings(out, a.aliases);
  };

  H.entry_similar = function (a) {
    B.requireLogin();
    B.requireNode(a.node);
    B.needFactor(a.node, "always");
    if (typeof a.name !== "string" || !a.name.trim()) throw B.error("malformed_request", "params.name is not a usable name");
    return { node: a.node, name: a.name, taken: taken(a.node, a.name, a.entry), similar: near(a.node, a.name, a.entry, 20) };
  };

  // ───────────────────────────── the .env import ─────────────────────────────
  function planOf(a) {
    var seen = {};
    return a.entries.map(function (p) {
      var name = p && p.name;
      if (typeof name !== "string" || !name.trim() || /[\u0000-\u001f]/.test(name) || Array.from(name).length > 200) return "invalid";
      if (typeof p.value !== "string") throw B.error("malformed_request", "entries[].value is required");
      if (p.value === "") return "empty";
      if (taken(a.node, name)) return "exists";
      if (seen[lc(name)]) return "duplicate";
      seen[lc(name)] = true;
      return "new";
    });
  }

  H.entry_import_env = function (a) {
    B.requireLogin();
    B.requireNode(a.node);
    if (!Array.isArray(a.entries) || !a.entries.length || a.entries.length > 500) throw B.error("malformed_request", "params.entries must hold 1-500 pairs");
    a.entries.forEach(function (p, i) {
      if (!p || typeof p !== "object" || Object.keys(p).some(function (k) { return k !== "name" && k !== "value"; })) throw B.error("malformed_request", "entries[" + i + "] has a key that is not one of: name, value");
    });
    if (a.onConflict !== undefined && a.onConflict !== "refuse" && a.onConflict !== "skip") throw B.error("malformed_request", 'params.onConflict must be "refuse" or "skip"');
    var statuses = planOf(a);
    var counts = { new: 0, exists: 0, duplicate: 0, empty: 0, invalid: 0 };
    statuses.forEach(function (s) { counts[s] += 1; });
    if (a.dryRun) {
      var items = a.entries.map(function (p, i) {
        var row = { name: p.name, status: statuses[i] };
        if (statuses[i] === "new") { var n = near(a.node, p.name, null, 3); if (n.length) row.similar = n; }
        return row;
      });
      return B.nameWarnings({ node: a.node, dryRun: true, total: a.entries.length, items: items, counts: counts }, a.entries.map(function (p) { return p.name; }));
    }
    var skip = a.onConflict === "skip";
    statuses.forEach(function (s, i) {
      if (s === "invalid") throw B.error("malformed_request", "entries[" + i + "].name is empty, too long, or has a control character");
      if (s === "exists" && !skip) throw B.error("entry_exists", "an entry with that name exists", { node: a.node, name: a.entries[i].name });
      if (s === "duplicate" && !skip) throw B.error("malformed_request", "entries[" + i + "]: the name appears twice in this import");
    });
    var created = [];
    var skipped = [];
    statuses.forEach(function (s, i) {
      var p = a.entries[i];
      if (s !== "new") { skipped.push({ name: p.name, status: s }); return; }
      var r = H.entry_create({ node: a.node, name: p.name, value: p.value });
      created.push({ name: p.name, entry: r.entry, pending: r.pending, fieldCount: r.fieldCount });
    });
    return B.nameWarnings({ node: a.node, created: created, skipped: skipped, complete: true, failed: null, total: a.entries.length, counts: counts, generation: B.S.generation[a.node] || null }, a.entries.map(function (p) { return p.name; }));
  };

  // The shell's LOCAL .env reader: no broker, no session, no audit record (so no requireLogin here either).
  H.env_preview = function (a) {
    if (typeof a.text !== "string") throw B.error("invalid_env", "text is required", undefined, "bridge");
    var entries = [];
    var skippedEmpty = [];
    var seen = {};
    var lines = a.text.replace(/^﻿/, "").split(/\r\n|\r|\n/);
    for (var i = 0; i < lines.length; i += 1) {
      var line = lines[i].trim();
      if (!line || line.charAt(0) === "#") continue;
      if (line.indexOf("export ") === 0) line = line.slice(7).trim();
      var eq = line.indexOf("=");
      var name = eq < 0 ? "" : line.slice(0, eq).trim();
      if (eq < 0 || !/^[A-Za-z0-9_.-]+$/.test(name)) throw B.error("invalid_env", "line " + (i + 1) + ": expected NAME=value", undefined, "bridge");
      if (seen[name]) throw B.error("invalid_env", "line " + (i + 1) + ": " + name + " appears again (first on line " + seen[name] + ")", undefined, "bridge");
      seen[name] = i + 1;
      var value = line.slice(eq + 1).trim();
      var q = value.charAt(0);
      if ((q === '"' || q === "'") && value.length >= 2 && value.charAt(value.length - 1) === q) value = value.slice(1, -1);
      else value = value.replace(/\s+#.*$/, "");
      if (value === "") skippedEmpty.push(name); else entries.push({ name: name, value: value });
    }
    if (entries.length > 500) throw B.error("invalid_env", "that file holds " + entries.length + " entries; one import takes at most 500 - split it", undefined, "bridge");
    return { entries: entries, skippedEmpty: skippedEmpty };
  };

  // Examples for tests/unit/fixture-shape.test.ts (see core.js).
  var E = B.examples;
  var OPEN = { locked: false };
  var GEN = function () { return B.S.generation.atlas || 1; };
  E.entry_alias = [
    { reset: OPEN, args: function () { return { node: "atlas", entry: "e-a1", generation: GEN(), aliases: ["live-stripe", "payments"] }; } },
    { reset: OPEN, args: function () { return { node: "atlas", entry: "e-a1", generation: GEN(), aliases: [] }; } },
    { reset: OPEN, args: { node: "atlas", entry: "e-a1", generation: 99, aliases: ["x-alias"] }, error: "conflict" },
    { reset: OPEN, args: function () { return { node: "atlas", entry: "e-a1", generation: GEN(), aliases: ["PG-MAIN"] }; }, error: "entry_exists" },
    { reset: OPEN, args: function () { return { node: "atlas", entry: "e-a1", generation: GEN(), aliases: ["stripe-live"] }; }, error: "malformed_request" },
    { reset: OPEN, args: function () { return { node: "cobalt", entry: "e-c1", generation: 1, aliases: ["x-alias"] }; }, error: "node_locked" },
  ];
  E.entry_similar = [
    { reset: OPEN, args: { node: "atlas", name: "stripe_live" } },
    { reset: OPEN, args: { node: "atlas", name: "wholly-different" } },
    { reset: OPEN, args: { node: "atlas", name: "   " }, error: "malformed_request" },
  ];
  E.entry_import_env = [
    { reset: OPEN, args: { node: "atlas", entries: [{ name: "FIX_ONE", value: "fixture-value-one" }, { name: "stripe-live", value: "fixture-value-two" }], dryRun: true } },
    { reset: OPEN, args: { node: "atlas", entries: [{ name: "FIX_ONE", value: "fixture-value-one" }, { name: "FIX_TWO", value: "fixture-value-two" }] } },
    { reset: OPEN, args: { node: "atlas", entries: [{ name: "FIX_ONE", value: "fixture-value-one" }, { name: "stripe-live", value: "fixture-value-two" }], onConflict: "skip" } },
    { reset: OPEN, args: { node: "atlas", entries: [{ name: "stripe-live", value: "fixture-value-two" }] }, error: "entry_exists" },
    { reset: OPEN, args: { node: "atlas", entries: [] }, error: "malformed_request" },
  ];
  E.env_preview = [
    { reset: OPEN, args: { text: "# note\nexport FIX_ONE=fixture-value-one\nFIX_TWO=\"fixture value two\"\nFIX_EMPTY=\n" } },
    { reset: OPEN, args: { text: "fixture-bare-token-without-a-name" }, error: "invalid_env" },
  ];
})((window.__brokerFixture = window.__brokerFixture || {}));
