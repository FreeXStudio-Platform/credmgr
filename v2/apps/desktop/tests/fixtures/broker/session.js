/* FIXTURE BROKER - session: status, unlock, second factor, lock, first-run bootstrap.  See core.js. */
(function (B) {
  "use strict";
  var H = B.handlers;

  function auth() {
    var S = B.S;
    return { locked: S.locked, authenticated: S.authenticated, initialized: S.initialized };
  }

  H.vault_status = function () {
    var out = auth();
    // ADR-090: a bare count of the requests waiting for a person, left out when 0 (as the shell does).
    var waiting = Object.keys(B.S.approvals || {}).length;
    if (waiting > 0) out.pendingApprovals = waiting;
    return out;
  };

  // Rejects two_factor_required when a gate is enrolled; the login completes with vault_gate_verify.
  H.vault_unlock = function (a) {
    var S = B.S;
    if (!S.initialized) throw B.error("internal", "there is no vault to unlock");
    if (typeof a.passphrase !== "string" || a.passphrase !== S.passphrase) {
      B.audit("unlock", null, null, "deny");
      throw B.error("wrong_passphrase", "wrong passphrase");
    }
    if (S.gateEnrolled) {
      S.pendingLogin = true;
      throw B.error("two_factor_required", "a second factor is required");
    }
    S.locked = false;
    S.authenticated = true;
    B.audit("unlock");
    return auth();
  };

  H.vault_gate_verify = function (a) {
    var S = B.S;
    if (!S.pendingLogin || a.code !== S.gateCode) {
      B.audit("gate_verify", null, null, "deny");
      throw B.error("gate_verification_failed", "that code was not accepted");
    }
    S.pendingLogin = false;
    S.locked = false;
    S.authenticated = true;
    B.audit("unlock");
    return auth();
  };

  // The bridge drops its login whatever the broker says.
  H.vault_lock = function () {
    var S = B.S;
    S.locked = true;
    S.authenticated = false;
    S.pendingLogin = false;
    S.elevated = false;
    return auth();
  };

  H.whoami = function () {
    B.requireLogin();
    return { node: "global", capabilities: ["list", "read", "reveal", "create", "update", "notes", "admin"], reachable: B.S.nodes.filter(function (n) { return n.kind !== "orphan"; }).map(function (n) { return n.id; }) };
  };

  // First run (ADR-061): begin shows the recovery code once; confirm needs it retyped.
  H.vault_init_begin = function (a) {
    var S = B.S;
    if (S.initialized) throw B.error("vault_already_initialized", "a vault already exists");
    if (typeof a.passphrase !== "string" || a.passphrase.length < 1) throw B.error("malformed_request", "passphrase too short");
    S.initPending = { passphrase: a.passphrase, recoveryCode: "FIXT-URE0-CODE-0001" };
    return { recoveryCode: S.initPending.recoveryCode };
  };
  H.vault_init_confirm = function (a) {
    var S = B.S;
    if (!S.initPending) throw B.error("vault_init_not_pending", "no vault creation is in progress");
    if (a.recoveryCode !== S.initPending.recoveryCode) throw B.error("recovery_code_mismatch", "the recovery code does not match");
    S.passphrase = S.initPending.passphrase;
    S.initPending = null;
    S.initialized = true;
    S.locked = true;
    return { initialized: true };
  };

  // Gate enrolment (07 section 4).  Over a gate already in force it needs the elevation a login's second factor opens; a spec turns
  // that on with broker.set({ elevated: true }), as the real broker does for five minutes after vault_gate_verify.
  var OTP_SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
  H.vault_gate_enroll_begin = function () {
    var S = B.S;
    B.requireLogin();
    if (S.gateEnrolled && !S.elevated) throw B.error("two_factor_required", "a fresh second factor is required", { challenge: "totp", scope: "global", expiresIn: 0 });
    S.enrolling = { secret: OTP_SECRET };
    return { otpauthUri: "otpauth://totp/CredMgr:global?secret=" + OTP_SECRET + "&issuer=CredMgr&period=30&digits=6" };
  };
  H.vault_gate_enroll_confirm = function (a) {
    var S = B.S;
    B.requireLogin();
    if (S.gateEnrolled && !S.elevated) throw B.error("two_factor_required", "a fresh second factor is required", { challenge: "totp", scope: "global", expiresIn: 0 });
    if (!S.enrolling) throw B.error("gate_not_enrolling", "no enrolment is in progress");
    if (a.code !== S.enrollCode) {
      B.audit("gate_enroll_confirm", null, null, "deny");
      throw B.error("gate_verification_failed", "that code was not accepted");
    }
    S.enrolling = null;
    S.gateEnrolled = true;
    S.gateCode = S.enrollCode;
    S.gateRecoveryCodes = [];
    for (var i = 1; i <= 10; i++) S.gateRecoveryCodes.push("FIXT-GATE-RC" + (i < 10 ? "0" : "") + i + "-0000-0000-0000-0000-0000-0000");
    B.audit("gate_enroll_confirm");
    return { recoveryCodes: S.gateRecoveryCodes.slice() };
  };
  // The last door (ADR-064): passphrase + the root recovery code reset the gate.  Does not log in.  Never says which factor was wrong.
  H.vault_gate_recover = function (a) {
    var S = B.S;
    if (a.passphrase !== S.passphrase || a.recoveryCode !== S.rootRecoveryCode) {
      B.audit("gate_recover", null, null, "deny");
      throw B.error("wrong_passphrase", "wrong passphrase");
    }
    var had = S.gateEnrolled;
    S.gateEnrolled = false;
    S.pendingLogin = false;
    B.audit("gate_recover");
    return { gateReset: had };
  };
  // A recovery code satisfies the login's second factor once, then is burned.
  var verify = H.vault_gate_verify;
  H.vault_gate_verify = function (a) {
    var S = B.S, codes = S.gateRecoveryCodes || [];
    var i = S.pendingLogin ? codes.indexOf(String(a.code).toUpperCase()) : -1;
    if (i >= 0) {
      codes.splice(i, 1);
      S.pendingLogin = false;
      S.locked = false;
      S.authenticated = true;
      S.elevated = true;
      B.audit("unlock");
      return auth();
    }
    // The step-up (ADR-085): from a logged-in session the owner's code opens a five-minute elevation and changes nothing else (no token, no new login).
    if (!S.locked && S.authenticated && !S.pendingLogin) {
      if (!S.gateEnrolled || String(a.code) !== String(S.gateCode)) {
        B.audit("gate_verify", null, null, "deny");
        throw B.error("gate_verification_failed", "that code was not accepted");
      }
      S.elevated = true;
      B.audit("gate_verify");
      return auth();
    }
    var r = verify(a);
    S.elevated = true;
    return r;
  };

  // A decision on an agent's waiting request (ADR-088).  With a passphrase it is authorised by the unlock factors and works ONLY while the vault is
  // locked (malformed_request otherwise): wrong passphrase, a confirmed gate with no code (two_factor_required) or a wrong one, a recovery code
  // refused, a request that names nothing (not_found).  Without a passphrase it is the logged-in session's decision.  A spec seeds a waiting
  // request with broker.set({ approvals: { "rq_fixture0001": { node: "atlas", entry: "e-a1" } } }).
  H.vault_approval_decide = function (a) {
    var S = B.S;
    if (typeof a.request !== "string" || !a.request) throw B.error("malformed_request", "params.request is required");
    if (typeof a.approved !== "boolean") throw B.error("malformed_request", "params.approved must be true or false");
    var viaFactors = typeof a.passphrase === "string";
    if (viaFactors) {
      if (!S.locked) throw B.error("malformed_request", "the vault is unlocked: decide with the session");
      if (a.passphrase !== S.passphrase) { B.audit("vault.approval_decide", null, null, "deny"); throw B.error("wrong_passphrase", "wrong passphrase"); }
      if (S.gateEnrolled) {
        if (!a.code) throw B.error("two_factor_required", "a second factor is required", { challenge: "totp", scope: "global", expiresIn: 300 });
        if (String(a.code) !== String(S.gateCode)) { B.audit("vault.approval_decide", null, null, "deny"); throw B.error("gate_verification_failed", "that code was not accepted"); }
      }
    } else {
      B.requireLogin();
    }
    var req = (S.approvals || {})[a.request];
    if (!req) throw B.error("not_found", "no such waiting request");
    delete S.approvals[a.request];
    S.decisions = (S.decisions || []).concat([{ request: a.request, approved: a.approved, viaFactors: viaFactors }]);
    B.audit("vault.approval_decide", req.node, req.entry);
    if (viaFactors) S.audit[S.audit.length - 1].actor = "Factors";
    var out = { request: a.request, node: req.node, entry: req.entry, approved: a.approved };
    if (viaFactors) out.authorisedBy = "factors";
    return out;
  };

  // What the waiting request(s) ask for (ADR-090).  Read-only, answered on a locked vault; unlocked, only the logged-in session may ask.  Names come from
  // the fixture's own nodes and entries; a node with privateNames has them withheld while the vault is locked (nobody is the owner's session then).
  H.vault_approval_get = function (a) {
    var S = B.S;
    if (!S.locked) B.requireLogin();
    var all = S.approvals || {};
    function view(id) {
      var req = all[id];
      var node = B.node(req.node);
      var entry = (S.entries[req.node] || []).filter(function (e) { return e.id === req.entry; })[0];
      var hidden = !!(node && node.policy && node.policy.privateNames && S.locked);
      var out = {
        request: id, node: req.node, entry: req.entry,
        nodeLabel: hidden || !node ? null : node.label,
        entryName: hidden || !entry ? null : entry.name,
        command: "entry.reveal", state: "pending",
        expiresIn: req.expiresIn || 100, requestedAt: req.requestedAt || 1800000000,
      };
      if (hidden) out.nameHidden = true;
      return out;
    }
    if (a.request !== undefined && a.request !== null) {
      if (typeof a.request !== "string") throw B.error("malformed_request", "params.request must be a string");
      if (!all[a.request]) throw B.error("not_found", "no pending approval " + a.request);
      return view(a.request);
    }
    return { pending: Object.keys(all).map(view) };
  };

  // The first project(s) a first run offers.  (The write package's fixture defines its own node_create; that one is loaded later and wins.)
  if (!H.node_create) {
    H.node_create = function (a) {
      var S = B.S;
      B.requireLogin();
      if (a.id === "global" || a.id === "orphan") throw B.error("malformed_request", a.id + " is a reserved node id");
      if (B.node(a.id)) throw B.error("malformed_request", "that node already exists");
      var parent = B.requireNode(a.parentId);
      S.nodes.push({ id: a.id, label: a.label, kind: "project", depth: parent.depth + 1, parentId: parent.id, gate: { locked: false, twofa: "none" } });
      S.entries[a.id] = [];
      B.audit("node_create", a.id);
      return B.nameWarnings({ node: a.id, created: true }, [a.label]);
    };
  }
  // Examples for tests/unit/fixture-shape.test.ts (see core.js).
  var E = B.examples;
  var WAITING_ONE = function () { B.S.approvals = { rq_fixture0009: { node: "atlas", entry: "e-a1" } }; };
  var PASS = function () { return { passphrase: B.S.passphrase }; };
  E.vault_status = [{ args: {} }, { reset: { initialized: false }, args: {} }, { reset: { locked: true }, setup: WAITING_ONE, args: {} }];
  // ADR-090.  The list, one request, an unknown one, and the owner-only refusal on an unlocked vault is the bridge's `vault_locked`-style login check.
  E.vault_approval_get = [
    { reset: { locked: true }, setup: WAITING_ONE, args: {} },
    { reset: { locked: true }, setup: WAITING_ONE, args: { request: "rq_fixture0009" } },
    { reset: { locked: true }, args: { request: "rq_nope" }, error: "not_found" },
  ];
  E.vault_unlock = [
    { reset: { locked: true }, args: PASS },
    { reset: { locked: true }, args: { passphrase: "not-the-passphrase" }, error: "wrong_passphrase" },
    { reset: { locked: true, gate: true }, args: PASS, error: "two_factor_required" },
  ];
  E.vault_gate_verify = [
    { reset: { locked: true, gate: true }, setup: function () { B.S.pendingLogin = true; }, args: function () { return { code: B.S.gateCode }; } },
    { reset: { locked: true, gate: true }, args: { code: "000000" }, error: "gate_verification_failed" },
  ];
  // The step-up: a logged-in session proves the factor; a wrong code, or no gate, is refused.
  E.vault_gate_verify.push(
    { reset: { locked: false, gate: true }, args: function () { return { code: B.S.gateCode }; } },
    { reset: { locked: false, gate: true }, args: { code: "000000" }, error: "gate_verification_failed" }
  );
  var WAITING = function () { B.S.approvals = { rq_fixture0001: { node: "atlas", entry: "e-a1" } }; };
  E.vault_approval_decide = [
    { reset: { locked: true }, setup: WAITING, args: function () { return { request: "rq_fixture0001", approved: true, passphrase: B.S.passphrase }; } },
    { reset: { locked: true, gate: true }, setup: WAITING, args: function () { return { request: "rq_fixture0001", approved: false, passphrase: B.S.passphrase, code: B.S.gateCode }; } },
    { reset: { locked: true, gate: true }, setup: WAITING, args: function () { return { request: "rq_fixture0001", approved: true, passphrase: B.S.passphrase }; }, error: "two_factor_required" },
    { reset: { locked: true }, setup: WAITING, args: { request: "rq_fixture0001", approved: true, passphrase: "not-the-passphrase" }, error: "wrong_passphrase" },
    { reset: { locked: true }, args: function () { return { request: "rq_nothing", approved: true, passphrase: B.S.passphrase }; }, error: "not_found" },
    { reset: { locked: false }, setup: WAITING, args: function () { return { request: "rq_fixture0001", approved: true, passphrase: B.S.passphrase }; }, error: "malformed_request" },
    { reset: { locked: false }, setup: WAITING, args: { request: "rq_fixture0001", approved: true } },
  ];
  E.vault_lock = [{ reset: { locked: false }, args: {} }];
  E.whoami = [{ reset: { locked: false }, args: {} }, { reset: { locked: true }, args: {}, error: "vault_locked" }];
  E.vault_init_begin = [
    { reset: { initialized: false }, args: { passphrase: "a-long-enough-passphrase" } },
    { reset: { initialized: true }, args: { passphrase: "a-long-enough-passphrase" }, error: "vault_already_initialized" },
  ];
  E.vault_init_confirm = [
    { reset: { initialized: false }, setup: function () { H.vault_init_begin({ passphrase: "a-long-enough-passphrase" }); }, args: function () { return { recoveryCode: B.S.initPending.recoveryCode }; } },
    { reset: { initialized: false }, args: { recoveryCode: "x" }, error: "vault_init_not_pending" },
  ];
  var OPEN = { locked: false };
  var BEGUN = function () { H.vault_gate_enroll_begin({}); };
  E.vault_gate_enroll_begin = [{ reset: OPEN, args: {} }, { reset: { locked: true }, args: {}, error: "vault_locked" }];
  E.vault_gate_enroll_confirm = [
    { reset: OPEN, setup: BEGUN, args: function () { return { code: B.S.enrollCode }; } },
    { reset: OPEN, setup: BEGUN, args: { code: "000000" }, error: "gate_verification_failed" },
    { reset: OPEN, args: { code: "654321" }, error: "gate_not_enrolling" },
  ];
  E.vault_gate_recover = [
    { reset: { locked: true, gate: true }, args: function () { return { passphrase: B.S.passphrase, recoveryCode: B.S.rootRecoveryCode }; } },
    { reset: { locked: true, gate: true }, args: function () { return { passphrase: B.S.passphrase, recoveryCode: "not-the-recovery-code" }; }, error: "wrong_passphrase" },
  ];
  E.node_create = [
    { reset: OPEN, args: { id: "newproj", label: "New project", parentId: "global" } },
    { reset: OPEN, args: { id: "atlas", label: "Again", parentId: "global" }, error: "malformed_request" },
  ];

  // The shell's own commands.
  H["plugin:app|version"] = function () {
    return "2.0.0-beta.1";
  };

  // Events: @tauri-apps/api/event's listen() registers a callback with the shell and gets an event id back.  B.emit(event, payload)
  // is what the shell would do: call every callback registered for that event with { event, id, payload }.
  B.listeners = {};
  var nextListener = 1;
  H["plugin:event|listen"] = function (a) {
    var id = nextListener++;
    B.listeners[id] = { event: a.event, handler: a.handler };
    return id;
  };
  H["plugin:event|unlisten"] = function (a) {
    delete B.listeners[a.eventId];
    return null;
  };
  B.emit = function (event, payload) {
    var n = 0;
    Object.keys(B.listeners).forEach(function (id) {
      var l = B.listeners[id];
      if (l.event === event && B.callbacks[l.handler]) {
        B.callbacks[l.handler]({ event: event, id: Number(id), payload: payload });
        n++;
      }
    });
    return n;
  };
})((window.__brokerFixture = window.__brokerFixture || {}));
