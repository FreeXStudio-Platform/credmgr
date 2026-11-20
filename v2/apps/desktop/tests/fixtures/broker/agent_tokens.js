/* FIXTURE BROKER - node-scoped agent tokens (ADR-164).

   It answers the way the real broker does (crates/brokerd/src/ops/agent_tokens.rs) for what the Agents screen has to show:
     - agent_token_issue checks the label (1-64 characters, no control characters), the node (it exists, it is not the Orphaned node), the
       capabilities (a non-empty subset of list, read, reveal, create, update and of what the node's agentAccess gives agents), the expiry
       (60..604800 seconds, 86400 when absent) and the 32-token cap, then the second factor (`two_factor_required` when a gate is enrolled
       and the login is not elevated) and then Touch ID: with `touchId` set it answers the token, otherwise `presence_required`, exactly
       as totp_seed does.  The broker's answer carries the token (`cma_` + 64 hex) once, but this fixture answers what the SHELL hands
       the page (src-tauri `agent_token_issue_at`): the token taken off and put on the concealed clipboard, `copied: true` and
       `clearAfterSeconds: 30` in its place, so no token ever reaches a spec's page.  The invented token goes to the fixture's PASTEBOARD (`B.pasteboard`), as `entry_copy`'s value does;
     - agent_token_status lists the live tokens as metadata, never a secret;
     - agent_token_rotate gives a live token a new secret and expiry, behind the same gate;
     - agent_token_revoke removes it; no Touch ID.
   Every token here is invented: the hex is a counter, so a spec can search the page and the logs for it. */
(function (B) {
  "use strict";
  var H = B.handlers;
  var CAPS = ["list", "read", "reveal", "create", "update"];
  var TTL_DEFAULT = 86400, TTL_MIN = 60, TTL_MAX = 604800, MAX = 32;

  function store() {
    if (!B.S.agentTokens) B.S.agentTokens = { live: [], seq: 0 };
    return B.S.agentTokens;
  }
  function ceiling(n) {
    var access = (n.policy && n.policy.agentAccess) || "read-write";
    if (access === "none") return [];
    if (access === "read-only") return ["list", "read", "reveal"];
    return CAPS.slice();
  }
  function live() {
    var now = B.now();
    var s = store();
    s.live = s.live.filter(function (t) { return t.expiresAt > now; });
    return s.live;
  }
  function view(t) {
    var n = B.node(t.node);
    var cap = n ? ceiling(n) : [];
    return {
      id: t.id, label: t.label, node: t.node, capabilities: t.capabilities.slice(),
      effectiveCapabilities: t.capabilities.filter(function (c) { return cap.indexOf(c) >= 0; }),
      createdAt: t.createdAt, expiresAt: t.expiresAt, lastUsedAt: t.lastUsedAt, rotatedAt: t.rotatedAt,
    };
  }
  function hex(n, width) {
    var h = n.toString(16);
    while (h.length < width) h = "0" + h;
    return h;
  }
  function ttlOf(raw) {
    if (raw === undefined || raw === null) return TTL_DEFAULT;
    if (typeof raw !== "number" || Math.floor(raw) !== raw || raw < TTL_MIN || raw > TTL_MAX) {
      throw B.error("malformed_request", "params.expiresIn must be whole seconds from 60 to 604800 (seven days); an agent token always expires");
    }
    return raw;
  }
  /** The gate a new secret needs: the second factor where enrolled, then Touch ID. */
  function secretGate(op) {
    if (B.S.gateEnrolled && !B.S.elevated) throw B.error("two_factor_required", "a second factor is required", { challenge: "totp", scope: "global", expiresIn: 0 });
    if (!B.S.touchId) throw B.error("presence_required", "presence is required", { operation: op });
  }
  function secret(s) {
    s.seq += 1;
    return { token: "cma_" + hex(s.seq, 64), id: "a_" + hex(0xf1c0000 + s.seq, 16) };
  }

  /** What the shell answers the page: the metadata, and the token on the clipboard instead of in the answer. */
  function handedToClipboard(t, made) {
    B.pasteboard = { value: made.token, concealed: true };
    var answer = view(t);
    answer.copied = true;
    answer.clearAfterSeconds = 30;
    return answer;
  }

  H.agent_token_issue = function (a) {
    B.requireLogin();
    var label = typeof a.label === "string" ? a.label.trim() : "";
    if (!label || label.length > 64 || /[\u0000-\u001f\u007f]/.test(label)) throw B.error("malformed_request", "label must be 1-64 characters with no control characters");
    if (a.node === "orphaned") throw B.error("malformed_request", "an agent token cannot be issued for the Orphaned node");
    if (a.node === "global") throw B.error("malformed_request", "an agent token cannot be issued for Global: issue it for the project the agent works on");
    var n = B.requireNode(a.node);
    if (!Array.isArray(a.capabilities) || a.capabilities.length === 0) throw B.error("malformed_request", "params.capabilities must name at least one capability");
    var cap = ceiling(n), out = [];
    a.capabilities.forEach(function (c) {
      if (CAPS.indexOf(c) < 0) throw B.error("malformed_request", "an agent token may carry only list, read, reveal, create and update; notes and admin are never an agent's");
      if (cap.indexOf(c) < 0) throw B.error("malformed_request", "node " + a.node + " does not give agents " + c + ": change its agent access first, or ask for less");
      if (out.indexOf(c) < 0) out.push(c);
    });
    out.sort(function (x, y) { return CAPS.indexOf(x) - CAPS.indexOf(y); });
    var ttl = ttlOf(a.expiresIn);
    if (live().length >= MAX) throw B.error("malformed_request", "at most 32 agent tokens can be live at once; revoke one first");
    secretGate("agent.token_issue");
    var s = store(), made = secret(s), now = B.now();
    var t = { id: made.id, label: label, node: a.node, capabilities: out, createdAt: now, expiresAt: now + ttl, lastUsedAt: null, rotatedAt: null };
    s.live.push(t);
    B.audit("agent.token_issue", a.node, null);
    return handedToClipboard(t, made);
  };

  H.agent_token_status = function (a) {
    B.requireLogin();
    var only = a && typeof a.node === "string" ? a.node : null;
    return {
      tokens: live().filter(function (t) { return !only || t.node === only; }).map(view),
      max: MAX, defaultExpiresIn: TTL_DEFAULT, maxExpiresIn: TTL_MAX,
    };
  };

  H.agent_token_rotate = function (a) {
    B.requireLogin();
    if (typeof a.id !== "string" || !a.id) throw B.error("malformed_request", "params.id is required");
    var ttl = ttlOf(a.expiresIn);
    var t = live().filter(function (x) { return x.id === a.id; })[0];
    if (!t) throw B.error("not_found", "no live agent token " + a.id);
    secretGate("agent.token_rotate");
    var s = store(), made = secret(s), now = B.now();
    t.expiresAt = now + ttl;
    t.rotatedAt = now;
    B.audit("agent.token_rotate", t.node, null);
    return handedToClipboard(t, made);
  };

  H.agent_token_revoke = function (a) {
    B.requireLogin();
    if (typeof a.id !== "string" || !a.id) throw B.error("malformed_request", "params.id is required");
    var s = store();
    var t = live().filter(function (x) { return x.id === a.id; })[0];
    if (!t) throw B.error("not_found", "no live agent token " + a.id);
    s.live = s.live.filter(function (x) { return x !== t; });
    B.audit("agent.token_revoke", t.node, null);
    return { revoked: true, id: t.id, label: t.label, node: t.node };
  };

  // Examples for tests/unit/fixture-shape.test.ts (see core.js).
  var E = B.examples;
  var OPEN = { locked: false };
  var TOUCH = { locked: false, touchId: true };
  function oneToken() {
    return H.agent_token_issue({ node: "atlas", label: "fixture agent", capabilities: ["list", "read"] }).id;
  }
  E.agent_token_issue = [
    { reset: TOUCH, args: { node: "atlas", label: "fixture agent", capabilities: ["list", "read"], expiresIn: 3600 } },
    { reset: OPEN, args: { node: "atlas", label: "fixture agent", capabilities: ["list"] }, error: "presence_required" },
    { reset: TOUCH, args: { node: "atlas", label: "fixture agent", capabilities: ["admin"] }, error: "malformed_request" },
    { reset: TOUCH, args: { node: "atlas", label: "fixture agent", capabilities: ["list"], expiresIn: 604801 }, error: "malformed_request" },
    { reset: TOUCH, args: { node: "orphaned", label: "fixture agent", capabilities: ["list"] }, error: "malformed_request" },
  ];
  E.agent_token_status = [
    { reset: OPEN, args: {} },
    { reset: TOUCH, setup: oneToken, args: { node: "atlas" } },
  ];
  var lastId = null;
  E.agent_token_rotate = [
    { reset: TOUCH, setup: function () { lastId = oneToken(); }, args: function () { return { id: lastId, expiresIn: 7200 }; } },
    { reset: TOUCH, args: { id: "a_0000000000000000" }, error: "not_found" },
  ];
  E.agent_token_revoke = [
    { reset: TOUCH, setup: function () { lastId = oneToken(); }, args: function () { return { id: lastId }; } },
    { reset: OPEN, args: { id: "a_0000000000000000" }, error: "not_found" },
  ];
})((window.__brokerFixture = window.__brokerFixture || {}));
