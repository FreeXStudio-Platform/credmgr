/*
 * FIXTURE BROKER - "Confirm before showing secrets" (ADR-150).  See core.js.
 *
 *   The policy       S.revealConfirm = { mode: "off"|"window"|"everyTime", windowSeconds, scope: "all"|"high" }, vault policy on the global node;
 *                    the owner's graph_snapshot carries it at the top level.  Start with one: installBroker(page, { revealConfirm: {...} }).
 *   session_confirm  the passphrase, or Touch ID (`touchId` option: presence attested; without it `presence_required`, as the real shell
 *                    passes it through when no presence key is enrolled).  Five wrong passphrases in a row: `rate_limited`.
 *   The gate         entry_reveal, entry_copy and totp_code answer `confirmation_required` (detail: operation, mode, windowSeconds) when the
 *                    policy asks for the entry's sensitivity and the session has no live confirmation.  "window": a confirmation is good
 *                    for windowSeconds; "everyTime": for ONE gated request within 60 s.  Checked after the checks the real broker makes
 *                    first (locked node, orphan, missing entry), which the wrapped handler still answers.
 *   node_policy      `revealConfirm` on the global node only; turning it off or loosening it needs a confirmation made in the last 60 s.
 *   A lock           ends every confirmation.  Specs move the clock with broker.set({ confirmedAt: <unix seconds> }).
 */
(function (B) {
  "use strict";
  var H = B.handlers;
  var E = B.examples;
  var OPEN = { locked: false };
  var FRESH_SECONDS = 60;
  var WINDOWS = [60, 300, 900, 3600];
  var DEFAULT = { mode: "off", windowSeconds: 300, scope: "all" };

  var baseReset = B.reset;
  B.reset = function (options) {
    baseReset(options);
    var o = options || {};
    B.S.revealConfirm = Object.assign({}, DEFAULT, o.revealConfirm || {});
    B.S.confirmedAt = null;
    B.S.confirmSpent = false;
    B.S.confirmFailures = 0;
  };

  function sensitivityOf(node, entry) {
    var e = (B.S.entries[node] || []).filter(function (x) { return x.id === entry; })[0];
    return e ? e.sensitivity || "low" : null;
  }
  /** How strongly a policy guards one sensitivity class: 0 nothing, larger is stricter. */
  function rank(p, sens) {
    if (p.mode === "off") return 0;
    if (p.scope === "high" && sens !== "high" && sens !== "critical") return 0;
    if (p.mode === "everyTime") return 1000;
    return 1 + 3600 / p.windowSeconds;
  }
  function weakens(from, to) {
    return ["low", "high"].some(function (s) { return rank(to, s) < rank(from, s); });
  }
  function refusal(operation) {
    var p = B.S.revealConfirm;
    return B.error("confirmation_required", "confirm it is you before a secret is shown", {
      operation: operation,
      mode: p.mode === "everyTime" ? "everyTime" : "window",
      windowSeconds: p.mode === "everyTime" ? 0 : p.windowSeconds,
      remedy: "confirm with session.confirm (Touch ID or the vault passphrase), then repeat the request",
    });
  }
  /** Is there a confirmation `need` accepts?  Spends an every-time (or fresh) one. */
  function satisfied(fresh) {
    var S = B.S;
    if (S.confirmedAt == null) return false;
    var age = B.now() - S.confirmedAt;
    if (fresh || S.revealConfirm.mode === "everyTime") {
      if (S.confirmSpent || age >= FRESH_SECONDS) return false;
      S.confirmSpent = true;
      return true;
    }
    return age < S.revealConfirm.windowSeconds;
  }
  function gate(node, entry, operation) {
    var S = B.S;
    if (S.locked || !S.authenticated || S.revealConfirm.mode === "off") return;
    var n = B.node(node);
    if (!n || n.kind === "orphan" || n.gate.locked) return;
    var sens = sensitivityOf(node, entry);
    if (!sens || rank(S.revealConfirm, sens) === 0) return;
    if (!satisfied(false)) throw refusal(operation);
  }

  ["entry_reveal", "entry_copy", "totp_code"].forEach(function (cmd) {
    var inner = H[cmd];
    var op = cmd === "totp_code" ? "totp.code" : "entry.reveal";
    H[cmd] = function (a, S) {
      gate(a.node, a.entry, op);
      return inner(a, S);
    };
  });

  var baseLock = H.vault_lock;
  H.vault_lock = function (a, S) {
    B.S.confirmedAt = null;
    B.S.confirmSpent = false;
    return baseLock(a, S);
  };

  var baseSnapshot = H.graph_snapshot;
  H.graph_snapshot = function (a, S) {
    var out = baseSnapshot(a, S);
    if (!B.S.locked && B.S.authenticated) out.revealConfirm = B.clone(B.S.revealConfirm);
    return out;
  };

  H.session_confirm = function (a) {
    B.requireLogin();
    var S = B.S;
    var method;
    if (typeof a.passphrase === "string") {
      if (S.confirmFailures >= 5) throw B.error("rate_limited", "too many attempts", { retryAfterSeconds: 30 });
      if (a.passphrase !== S.passphrase) {
        S.confirmFailures += 1;
        B.audit("session.confirm", null, null, "deny");
        throw B.error("wrong_passphrase", "wrong passphrase");
      }
      S.confirmFailures = 0;
      method = "passphrase";
    } else if (S.touchId) {
      method = "presence";
    } else {
      throw B.error("presence_required", "presence is required", { operation: "session.confirm" });
    }
    S.confirmedAt = B.now();
    S.confirmSpent = false;
    B.audit("session.confirm");
    var p = S.revealConfirm;
    return { confirmed: true, method: method, expiresIn: p.mode === "window" ? p.windowSeconds : FRESH_SECONDS };
  };

  var basePolicy = H.node_policy;
  H.node_policy = function (a, S) {
    var patch = a.policy;
    if (!patch || typeof patch !== "object" || !("revealConfirm" in patch)) return basePolicy(a, S);
    B.requireLogin();
    B.requireNode(a.node);
    var reason = typeof a.reason === "string" ? a.reason.trim() : "";
    if (!reason) throw B.error("malformed_request", "params.reason is required - a policy change records why");
    if (a.node !== "global") throw B.error("malformed_request", "revealConfirm is vault policy: set it on the global node");
    var rc = patch.revealConfirm || {};
    var next = Object.assign({}, DEFAULT, rc);
    if (["off", "window", "everyTime"].indexOf(next.mode) < 0 || WINDOWS.indexOf(next.windowSeconds) < 0 || ["all", "high"].indexOf(next.scope) < 0) {
      throw B.error("malformed_request", "params.policy.revealConfirm: bad value");
    }
    if (weakens(B.S.revealConfirm, next) && !satisfied(true)) throw refusal("node.policy");
    var rest = {};
    Object.keys(patch).forEach(function (k) { if (k !== "revealConfirm") rest[k] = patch[k]; });
    var answer;
    if (Object.keys(rest).length) answer = basePolicy({ node: a.node, reason: a.reason, policy: rest }, S);
    B.S.revealConfirm = next;
    if (!answer) {
      B.audit("node_policy", a.node);
      var n = B.node(a.node);
      answer = { node: a.node, policy: Object.assign({ siblingVisibility: "shared", descendantRead: false, requireTwoFactor: "reveal", lockAfterSeconds: null, privateNames: false, agentAccess: "read-write", securityLevel: "guarded" }, (n && n.policy) || {}), changed: [], reason: reason, notEnforced: [] };
    }
    answer.policy.revealConfirm = B.clone(next);
    answer.changed = answer.changed.concat(["revealConfirm"]);
    return answer;
  };

  var ON = { mode: "window", windowSeconds: 300, scope: "all" };
  E.session_confirm = [
    { reset: OPEN, args: function () { return { passphrase: B.S.passphrase }; } },
    { reset: { locked: false, touchId: true }, args: {} },
    { reset: OPEN, args: { passphrase: "not-it" }, error: "wrong_passphrase" },
    { reset: OPEN, args: {}, error: "presence_required" },
    { reset: { locked: true }, args: { passphrase: "x" }, error: "vault_locked" },
  ];
  E.graph_snapshot = (E.graph_snapshot || []).concat([{ reset: { locked: false, revealConfirm: ON }, args: {} }]);
  E.entry_reveal = (E.entry_reveal || []).concat([
    { reset: { locked: false, revealConfirm: ON }, args: { node: "atlas", entry: "e-a1" }, error: "confirmation_required" },
    // Only high and critical: a low entry shows without asking.
    { reset: { locked: false, revealConfirm: { mode: "window", windowSeconds: 300, scope: "high" } }, args: { node: "global", entry: "e-g1" } },
    { reset: { locked: false, revealConfirm: ON }, setup: function () { H.session_confirm({ passphrase: B.S.passphrase }); }, args: { node: "atlas", entry: "e-a1" } },
  ]);
  E.totp_code = (E.totp_code || []).concat([{ reset: { locked: false, revealConfirm: ON }, args: { node: "atlas", entry: "e-a3" }, error: "confirmation_required" }]);
  E.entry_copy = (E.entry_copy || []).concat([{ reset: { locked: false, revealConfirm: ON }, args: { node: "atlas", entry: "e-a1" }, error: "confirmation_required" }]);
  E.node_policy = (E.node_policy || []).concat([
    { reset: OPEN, args: { node: "global", reason: "fixture reason", policy: { revealConfirm: ON } } },
    { reset: { locked: false, revealConfirm: ON }, args: { node: "global", reason: "fixture reason", policy: { revealConfirm: { mode: "off", windowSeconds: 300, scope: "all" } } }, error: "confirmation_required" },
    { reset: OPEN, args: { node: "atlas", reason: "fixture reason", policy: { revealConfirm: ON } }, error: "malformed_request" },
  ]);
})((window.__brokerFixture = window.__brokerFixture || {}));
