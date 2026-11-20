/*
 * FIXTURE BROKER - the switchboard (ADR-155, crates/brokerd/src/ops/switchboard.rs).  See core.js.
 *
 *   The registry    S.settings: the `app.*` values ever set (anything else reads as its default), S.settingsHistory: every applied
 *                   change, newest last.  Only the fifteen `app.*` settings are modelled (vault scope; the window's preferences).
 *   The caller      always the owner's login (the window): every change is direct.  An agent's weakening change is what fills
 *                   S.settingRequests; a spec seeds those with app.open({ broker: { settingRequests: [...] } }) (seed.js).
 *   Approving       a request (always a loosening) needs a confirmation made in the last 60 s and spends it (confirm.js keeps
 *                   S.confirmedAt / S.confirmSpent); without one, `confirmation_required`, as the real broker answers.
 */
(function (B) {
  "use strict";
  var H = B.handlers;
  var E = B.examples;
  var OPEN = { locked: false };
  var FRESH_SECONDS = 60;

  /** kind: "int" (choices), "range" [lo, hi], "bool", "choice", "nullable" (choices or null).  risk: "higher" (higher is weaker, 0 = never), "safeTrue", "cosmetic". */
  var DEFS = [
    { k: "autoLockMins", kind: "int", choices: [5, 15, 60, 0], def: 15, risk: "higher", group: "Locking and revealing", title: "Idle auto-lock (minutes)", ui: "Settings › Security › Auto-lock" },
    { k: "revealWindowSecs", kind: "int", choices: [10, 20, 60], def: 20, risk: "higher", group: "Locking and revealing", title: "Reveal window (seconds)", ui: "Settings › Security › Reveal window" },
    { k: "captureProtection", kind: "bool", def: true, risk: "safeTrue", group: "Locking and revealing", title: "Hide the window from screen capture", ui: "Settings › Security › Screen capture" },
    { k: "theme", kind: "nullable", choices: ["dark", "light"], def: null, risk: "cosmetic", title: "Theme" },
    { k: "colour", kind: "choice", choices: ["off", "on", "auto"], def: "off", risk: "cosmetic", title: "Accent colour" },
    { k: "hue", kind: "range", range: [0, 360], def: 198, risk: "cosmetic", title: "Accent hue" },
    { k: "intensity", kind: "range", range: [0, 100], def: 32, risk: "cosmetic", title: "Tint intensity" },
    { k: "greyscale", kind: "bool", def: false, risk: "cosmetic", title: "Greyscale" },
    { k: "contrastMode", kind: "nullable", choices: ["standard", "high"], def: null, risk: "cosmetic", title: "Contrast" },
    { k: "motion", kind: "choice", choices: ["system", "reduced"], def: "system", risk: "cosmetic", title: "Motion" },
    { k: "hwAccel", kind: "bool", def: true, risk: "cosmetic", title: "Hardware acceleration" },
    { k: "mode", kind: "choice", choices: ["lite", "pro"], def: "pro", risk: "cosmetic", title: "Mode" },
    { k: "backupRetain", kind: "int", choices: [14, 30], def: 14, risk: "cosmetic", title: "Backups kept" },
    { k: "entriesMode", kind: "choice", choices: ["all", "selected"], def: "all", risk: "cosmetic", title: "Entries on the map" },
    { k: "view", kind: "choice", choices: ["graph", "tree"], def: "graph", risk: "cosmetic", title: "View" },
  ];
  function defOf(id) {
    var d = DEFS.filter(function (x) { return "app." + x.k === id; })[0];
    if (!d) throw B.error("not_found", "no setting " + id);
    return d;
  }
  function valuesText(d) {
    if (d.kind === "bool") return "true | false";
    if (d.kind === "range") return d.range[0] + ".." + d.range[1];
    if (d.kind === "nullable") return d.choices.join(" | ") + " | null";
    return d.choices.join(" | ");
  }
  function valid(d, v) {
    if (d.kind === "bool") return typeof v === "boolean";
    if (d.kind === "range") return typeof v === "number" && Math.floor(v) === v && v >= d.range[0] && v <= d.range[1];
    if (d.kind === "nullable") return v === null || d.choices.indexOf(v) >= 0;
    return d.choices.indexOf(v) >= 0;
  }
  function current(d) {
    var id = "app." + d.k;
    return Object.prototype.hasOwnProperty.call(B.S.settings, id) ? B.S.settings[id] : d.def;
  }
  /** settings::classify: same, cosmetic, strengthens or weakens. */
  function classify(d, from, to) {
    if (JSON.stringify(from) === JSON.stringify(to)) return "same";
    if (d.risk === "cosmetic") return "cosmetic";
    if (d.risk === "safeTrue") return to === true ? "strengthens" : "weakens";
    var rank = function (v) { return v === 0 ? Infinity : v; };
    return rank(to) > rank(from) ? "weakens" : "strengthens";
  }
  function describe(d) {
    return {
      id: "app." + d.k,
      scope: "vault",
      group: d.group || "Appearance and behaviour",
      title: d.title,
      purpose: d.title + " (fixture).",
      ui: d.ui || "Settings › Appearance",
      stored: "global.policy.appPrefs." + d.k,
      values: valuesText(d),
      default: d.def,
      value: current(d),
      risk: d.risk === "cosmetic" ? "cosmetic" : "security",
      you: "direct",
    };
  }
  function reasonOf(r) {
    var t = typeof r === "string" ? r.trim() : "";
    if (!t) throw B.error("malformed_request", "params.reason must not be empty - a setting change records why");
    return t;
  }
  function write(d, from, to, reason, request, reverts) {
    var S = B.S;
    S.changeSeq += 1;
    var rec = { id: "chg-" + S.changeSeq, setting: "app." + d.k, from: from, to: to, by: "owner", at: B.now(), reason: reason };
    if (request) rec.request = request;
    if (reverts) rec.reverts = reverts;
    S.settings["app." + d.k] = to;
    S.settingsHistory.push(rec);
    return rec;
  }
  function setValue(d, to, reason, reverts) {
    B.requireLogin();
    if (!valid(d, to)) throw B.error("malformed_request", "app." + d.k + ": expected " + valuesText(d));
    var from = current(d);
    var change = classify(d, from, to);
    if (change === "same") return { applied: false, change: "same", id: "app." + d.k, value: from };
    var rec = write(d, from, to, reason, null, reverts);
    return { applied: true, change: change, changeId: rec.id, id: "app." + d.k, from: from, to: to };
  }
  function stateOf(r) {
    if (r.decided) return r.decided;
    return B.now() >= r.expiresAt ? "expired" : "pending";
  }
  function view(r) {
    return { request: r.request, id: r.id, node: r.node, from: r.from, to: r.to, reason: r.reason, state: stateOf(r), expiresIn: Math.max(0, r.expiresAt - B.now()), requestedAt: r.requestedAt, changeId: r.changeId, cwd: r.cwd };
  }
  function requestOf(id) {
    var r = B.S.settingRequests.filter(function (x) { return x.request === id; })[0];
    if (!r) throw B.error("not_found", "no request " + id);
    return r;
  }

  // A seeded value's history record (seed.js) changed it from the setting's default.
  var baseReset = B.reset;
  B.reset = function (options) {
    baseReset(options);
    B.S.settingsHistory.forEach(function (c) {
      var d = DEFS.filter(function (x) { return "app." + x.k === c.setting; })[0];
      if (d && c.from === null) c.from = d.def;
    });
  };

  H.settings_list = function (a) {
    B.requireLogin();
    return { caller: "owner", node: typeof a.node === "string" ? a.node : null, settings: DEFS.map(describe), note: a.node ? "" : "Project settings are listed with params.node.", kb: "settings.kb explains every setting and the rules." };
  };
  H.settings_get = function (a) {
    B.requireLogin();
    var d = defOf(a.id);
    var out = describe(d);
    out.recentChanges = B.S.settingsHistory.filter(function (c) { return c.setting === a.id; }).slice(-10).reverse().map(B.clone);
    return out;
  };
  H.settings_set = function (a) {
    var d = defOf(a.id);
    return setValue(d, a.value, reasonOf(a.reason), null);
  };
  H.settings_revert = function (a) {
    var rec = B.S.settingsHistory.filter(function (c) { return c.id === a.change; })[0];
    if (!rec) throw B.error("not_found", "no recorded change " + a.change);
    var reason = typeof a.reason === "string" && a.reason.trim() ? a.reason.trim() : "revert " + a.change;
    return setValue(defOf(rec.setting), rec.from, reason, rec.id);
  };
  H.settings_request_get = function (a) {
    B.requireLogin();
    return view(requestOf(a.request));
  };
  H.settings_request_list = function () {
    B.requireLogin();
    return { requests: B.S.settingRequests.map(view) };
  };
  H.settings_request_decide = function (a) {
    B.requireLogin();
    var S = B.S;
    var r = requestOf(a.request);
    var st = stateOf(r);
    if (st !== "pending") throw B.error("malformed_request", "request " + r.request + " is " + st);
    if (!a.approve) {
      r.decided = "denied";
      return { request: r.request, state: "denied", applied: false };
    }
    var d = defOf(r.id);
    var from = current(d);
    // The step-up: approving a loosening is the owner's own change plus a fresh confirmation, which it spends.
    if (classify(d, from, r.to) === "weakens") {
      var fresh = S.confirmedAt != null && !S.confirmSpent && B.now() - S.confirmedAt < FRESH_SECONDS;
      if (!fresh) {
        throw B.error("confirmation_required", "confirm it is you before approving this change", {
          operation: "settings.request_decide",
          mode: "everyTime",
          windowSeconds: 0,
          remedy: "confirm with session.confirm (Touch ID or the vault passphrase), then repeat the request",
        });
      }
      S.confirmSpent = true;
    }
    var rec = write(d, from, r.to, "approved agent request " + r.request + ": " + r.reason, r.request, null);
    r.decided = "approved";
    r.changeId = rec.id;
    return { request: r.request, state: "approved", applied: true, changeId: rec.id };
  };
  H.settings_kb = function () {
    return { markdown: "# CredMgr settings (fixture)\n\n" + DEFS.map(function (d) { return "- `app." + d.k + "`: " + valuesText(d); }).join("\n") + "\n", format: "text/markdown" };
  };

  var REQ = { locked: false, settingRequests: [{ id: "app.autoLockMins", from: 15, to: 60, reason: "fixture: longer sessions", cwd: "/tmp/fixture-project" }] };
  var confirmNow = function () { B.S.confirmedAt = B.now(); B.S.confirmSpent = false; };
  E.settings_list = [{ reset: OPEN, args: {} }, { reset: { locked: false, settings: { "app.theme": "dark" } }, args: {} }, { reset: { locked: true }, args: {}, error: "vault_locked" }];
  E.settings_get = [
    { reset: OPEN, args: { id: "app.autoLockMins" } },
    { reset: { locked: false, settings: { "app.autoLockMins": 60 } }, args: { id: "app.autoLockMins" } },
    { reset: OPEN, args: { id: "app.nope" }, error: "not_found" },
  ];
  E.settings_set = [
    { reset: OPEN, args: { id: "app.autoLockMins", value: 5, reason: "fixture" } },
    { reset: OPEN, args: { id: "app.theme", value: null, reason: "fixture" } },
    { reset: OPEN, args: { id: "app.captureProtection", value: false, reason: "fixture" } },
    { reset: OPEN, args: { id: "app.autoLockMins", value: 7, reason: "fixture" }, error: "malformed_request" },
    { reset: OPEN, args: { id: "app.autoLockMins", value: 5, reason: " " }, error: "malformed_request" },
    { reset: { locked: true }, args: { id: "app.autoLockMins", value: 5, reason: "fixture" }, error: "vault_locked" },
  ];
  E.settings_revert = [
    { reset: { locked: false, settings: { "app.autoLockMins": 60 } }, args: { change: "chg-seed-1" } },
    { reset: OPEN, args: { change: "chg-nope" }, error: "not_found" },
  ];
  E.settings_request_get = [{ reset: REQ, args: { request: "srq-1" } }, { reset: REQ, args: { request: "srq-9" }, error: "not_found" }];
  E.settings_request_list = [{ reset: REQ, args: {} }, { reset: OPEN, args: {} }];
  E.settings_request_decide = [
    { reset: REQ, args: { request: "srq-1", approve: false } },
    { reset: REQ, args: { request: "srq-1", approve: true }, error: "confirmation_required" },
    { reset: REQ, setup: confirmNow, args: { request: "srq-1", approve: true } },
    { reset: REQ, setup: function () { B.S.settingRequests[0].decided = "denied"; }, args: { request: "srq-1", approve: true }, error: "malformed_request" },
  ];
  E.settings_kb = [{ reset: OPEN, args: {} }];
})((window.__brokerFixture = window.__brokerFixture || {}));
