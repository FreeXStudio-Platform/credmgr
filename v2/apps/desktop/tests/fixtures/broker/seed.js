/* FIXTURE BROKER - the in-memory vault.  See core.js.  Rebuilt by B.reset(options); the options come from the spec. */
(function (B) {
  "use strict";

  function entry(id, name, type, sensitivity, extra) {
    var e = { id: id, name: name, type: type, sensitivity: sensitivity, value: "fixture-value-" + name, modified: 1760000000, rotatedAt: null, expiresAt: null };
    for (var k in extra || {}) e[k] = extra[k];
    return e;
  }
  /** The one multi-field entry of the default vault: a server with a host, a port, a user, a password and a note.  Values are distinctive. */
  function multiFieldEntry() {
    // The entry's type is inferred from its fields (server: host + username + password); its sensitivity is a pin, as a user's would be.
    var e = entry("e-a2", "pg-main", "server", "critical", { sensPin: "critical" });
    e.fields = [
      { id: "f_00a20001", label: "host", value: "fixture-value-pg-main.example.test" },
      { id: "f_00a20002", label: "port", value: "5432" },
      { id: "f_00a20003", label: "username", value: "fixture-value-pg-main-user" },
      { id: "f_00a20004", label: "password", value: "fixture-value-pg-main-password" },
      { id: "f_00a20005", label: "note", value: "fixture-value-pg-main-note", typePin: "text" },
    ];
    e.value = e.fields[0].value;
    return e;
  }
  function node(id, kind, depth, parentId, extra) {
    var n = { id: id, label: id, kind: kind, depth: depth, parentId: parentId, gate: { locked: false, twofa: "none" } };
    for (var k in extra || {}) n[k] = extra[k];
    return n;
  }

  /**
   * options: { passphrase, gateCode, gate: boolean (a second factor is enrolled), locked: boolean, initialized: boolean,
   *            unreachable: boolean (every broker call fails with broker_unreachable),
   *            touchId: boolean (presence is attested: totp_seed answers the seed),
   *            presenceKey: boolean (a presence key is enrolled: approving an agent's request from a login needs a proof, ADR-173) }
   */
  B.reset = function (options) {
    var o = options || {};
    B.calls.length = 0;
    B.scripts = {};
    B.S = {
      passphrase: o.passphrase,
      gateCode: o.gateCode,
      gateEnrolled: !!o.gate,
      // The root recovery code printed at first run (vault_gate_recover takes it with the passphrase) and the code a spec types to confirm an enrolment.
      rootRecoveryCode: o.rootRecoveryCode || "FIXT-ROOT-RECO-VERY-0001",
      enrollCode: o.enrollCode || "654321",
      // ADR-163: the vault has a recovery wrap, so the recovery code alone opens it (vault_recover); `recoveryUnlock: false` is a vault made before wraps existed.
      recoveryUnlock: o.recoveryUnlock !== false,
      enrolling: null,
      elevated: false,
      factorGate: false,
      tfLevels: {},
      approvals: o.approvals || {},
      windowState: o.windowState || null,
      fieldHistory: {},
      initialized: o.initialized !== false,
      unreachable: !!o.unreachable,
      presenceKey: !!o.presenceKey,
      touchId: !!o.touchId, // Touch ID is set up and the prompt is approved: totp_seed answers the seed (ADR-098); otherwise presence_required
      locked: o.locked !== false,
      authenticated: o.locked === false,
      pendingLogin: false,
      auditSeq: 0,
      audit: [],
      entrySeq: 0,
      nodes: [
        node("global", "global", 0, null, { gate: { locked: false, twofa: "enrolled" } }),
        node("atlas", "project", 1, "global", { gate: { locked: false, twofa: "required" } }),
        node("beacon", "project", 1, "global"),
        node("cobalt", "project", 1, "global", { gate: { locked: true, twofa: "none" } }),
        node("staging", "sub", 2, "atlas"),
        node("orphaned", "orphan", 1, "global"),
      ],
      entries: {
        global: [entry("e-g1", "licence-server", "api", "low")],
        // e-a1 and e-a3 are single-value entries written before the field model (one field, id f_00000000, no label); e-a2 holds several.
        atlas: [entry("e-a1", "stripe-live", "api", "high", { rotatedAt: 1751241600 }), multiFieldEntry(), entry("e-a3", "deploy-otp", "totp", "high")],
        beacon: [entry("e-b1", "registry-token", "api", "medium")],
        cobalt: [entry("e-c1", "shop-admin", "login", "high")],
        staging: [entry("e-s1", "stg-db", "server", "medium")],
        orphaned: [entry("e-o1", "old-root", "server", "critical")],
      },
      generation: {},
      pending: {},
      notes: { atlas: "Fixture note for atlas." },
      grants: [{ id: "g-f1", from: "beacon", to: { kind: "node", nodeId: "atlas" }, direction: "one-way", scope: ["read"], expiresAt: null, reason: "fixture grant" }],
      // The switchboard (ADR-155, switchboard.js): the `app.*` values the registry holds (only those ever set; the rest read as their
      // default), the change history, and agents' waiting requests.  A spec seeds them with app.open({ broker: { settings, settingRequests } }).
      settings: {},
      settingsHistory: [],
      changeSeq: 0,
      settingRequests: [],
    };
    // A seeded value was set before the spec started: it has a history (so the app's migration rule leaves it to the broker).
    Object.keys(o.settings || {}).forEach(function (id) {
      B.S.changeSeq += 1;
      B.S.settings[id] = o.settings[id];
      B.S.settingsHistory.push({ id: "chg-seed-" + B.S.changeSeq, setting: id, from: null, to: o.settings[id], by: "owner", at: 1760000000, reason: "seeded by the spec" });
    });
    // An agent's request: { id, to, from?, reason?, node?, cwd?, request?, expiresIn? (seconds, default 600) }.
    (o.settingRequests || []).forEach(function (r, i) {
      var t = Math.floor(Date.now() / 1000);
      B.S.settingRequests.push({
        request: r.request || "srq-" + (i + 1),
        id: r.id,
        node: r.node || null,
        from: Object.prototype.hasOwnProperty.call(r, "from") ? r.from : null,
        to: r.to,
        reason: r.reason || "an agent asked",
        cwd: r.cwd || null,
        requestedAt: t - (o.settingRequests.length - i),
        expiresAt: t + (r.expiresIn || 600),
        decided: null,
        changeId: null,
      });
    });
    (o.privateNodes || []).forEach(function (id) {
      var n = B.node(id);
      if (n) n.policy = { privateNames: true };
    });
    // A first run starts from nothing but the root and the orphaned node (a created vault holds no entries, no notes, no grants).
    if (!B.S.initialized) {
      B.S.nodes = B.S.nodes.filter(function (n) { return n.id === "global" || n.kind === "orphan"; });
      B.S.nodes[0].gate = { locked: false, twofa: "none" };
      B.S.entries = { global: [], orphaned: [] };
      B.S.notes = {};
      B.S.grants = [];
    }
  };
})((window.__brokerFixture = window.__brokerFixture || {}));
