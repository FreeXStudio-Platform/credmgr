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
   *            unreachable: boolean (every broker call fails with broker_unreachable) }
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
      enrolling: null,
      elevated: false,
      factorGate: false,
      tfLevels: {},
      approvals: o.approvals || {},
      fieldHistory: {},
      initialized: o.initialized !== false,
      unreachable: !!o.unreachable,
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
    };
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
