/* FIXTURE BROKER - administration: grants, audit, maintenance.  See core.js.

   Modelled on crates/brokerd/src/ops.rs, in the order it checks things:
     grant_create          validates the request, then ALWAYS answers presence_required (no transport can attest presence yet)
     audit_get             presence_required on every call
     maintenance_rotate_root / maintenance_doctor with rebuildRegistry
                           the passphrase must be present, then presence_required after every check that can be made without it
     maintenance_backup    ANY non-empty passphrase encrypts the archive (it is not the vault's); older archives beyond `retain` are pruned
   A spec that needs a different answer scripts it: broker.script("maintenance_verify", { result: { ... } }). */
(function (B) {
  "use strict";
  var H = B.handlers;

  var CAPS = ["read", "reveal", "notes"];

  H.grant_create = function (a) {
    B.requireLogin();
    if (typeof a.from !== "string" || !a.from) throw B.error("malformed_request", "params.from is required");
    if (!a.to || (a.to.kind !== "node" && a.to.kind !== "entry") || typeof a.to.nodeId !== "string") throw B.error("malformed_request", "params.to must be { kind, nodeId }");
    if (typeof a.reason !== "string" || a.reason.length < 8) throw B.error("malformed_request", "params.reason must be at least 8 characters");
    if (!Array.isArray(a.scope) || !a.scope.length || a.scope.some(function (c) { return CAPS.indexOf(c) < 0; })) throw B.error("malformed_request", "params.scope may only contain read, reveal or notes");
    throw B.error("presence_required", "presence cannot be attested by this transport", { operation: "grant.create" });
  };

  H.grant_revoke = function (a) {
    B.requireLogin();
    var S = B.S;
    var i = S.grants.map(function (g) { return g.id; }).indexOf(a.id);
    if (i < 0) throw B.error("not_found", "no such grant");
    S.grants.splice(i, 1);
    B.audit("grant.revoke");
    return { id: a.id, revoked: true };
  };

  // Newest first, the human-session shape (node, decision, detail, entry, generation).
  H.audit_tail = function (a) {
    B.requireLogin();
    var limit = Math.max(1, Math.min(500, a.limit || 50));
    return { records: B.S.audit.slice(-limit).reverse() };
  };

  H.audit_get = function () {
    B.requireLogin();
    throw B.error("presence_required", "presence cannot be attested by this transport", { operation: "audit.get" });
  };

  H.maintenance_verify = function () {
    B.requireLogin();
    return { ok: true, nodesChecked: B.S.nodes.length, errors: [], warnings: [] };
  };

  H.maintenance_doctor = function (a) {
    B.requireLogin();
    if (a.rebuildRegistry) {
      if (typeof a.passphrase !== "string") throw B.error("malformed_request", "params.passphrase is required for rebuildRegistry");
      throw B.error("presence_required", "presence cannot be attested by this transport", { operation: "maintenance.doctor --rebuild-registry" });
    }
    // ADR-089: with purgeExpiredSeals the doctor also lists the seals older than seven days: `would-purge-expired-seal` on a dry run,
    // `purged-expired-seal` once applied (the retained originals are gone for good; the entries stay in Orphaned).  A spec seeds one with
    // broker.set({ expiredSeals: [{ node: "old", sealedAt: 1750000000 }] }).
    var applied = a.apply !== false;
    var fixes = [];
    if (a.purgeExpiredSeals === true) {
      (B.S.expiredSeals || []).forEach(function (s) {
        fixes.push({ node: s.node, type: applied ? "purged-expired-seal" : "would-purge-expired-seal", sealedAt: s.sealedAt, archiveRemoved: applied });
      });
      if (applied) B.S.expiredSeals = [];
    }
    return { applied: applied, fixCount: fixes.length, fixes: fixes, unfixable: [] };
  };

  H.maintenance_backup = function (a) {
    B.requireLogin();
    if (typeof a.passphrase !== "string" || !a.passphrase) throw B.error("malformed_request", "params.passphrase must not be empty");
    var S = B.S;
    var retain = a.retain || 14;
    S.backups = S.backups || [];
    S.backupSeq = (S.backupSeq || 0) + 1;
    var path = "backups/credmgr-backup-" + (1760000000 + S.backupSeq) + ".enc";
    S.backups.push(path);
    var pruned = S.backups.slice(0, Math.max(0, S.backups.length - retain)).map(function (b) { return String(b.name || b.path || b); });
    S.backups = S.backups.slice(S.backups.length - Math.min(retain, S.backups.length));
    B.audit("maintenance.backup");
    return { path: path, retain: retain, pruned: pruned };
  };

  H.maintenance_rotate_root = function (a) {
    B.requireLogin();
    if (typeof a.passphrase !== "string" || !a.passphrase) throw B.error("malformed_request", "params.passphrase must not be empty");
    throw B.error("presence_required", "presence cannot be attested by this transport", { operation: "maintenance.rotate_root" });
  };

  // The shell's plain-text copy (src-tauri/src/commands.rs copy_text_at): no login (it never reaches the broker), no timer, at most
  // 4096 bytes.  The fake records what it was asked to copy in S.copied, so a spec can assert the exact text.  A spec that needs the
  // OS clipboard to refuse scripts it: broker.script("copy_text", { error: { code: "clipboard_failed", source: "bridge" } }).
  H.copy_text = function (a) {
    if (typeof a.text !== "string") throw B.error("malformed_request", "text must be a string", undefined, "bridge");
    if (a.text.length > 4096) throw B.error("text_too_large", "copy_text takes at most 4096 bytes of text", undefined, "bridge");
    B.S.copied = (B.S.copied || []).concat([a.text]);
    return { copied: true, clearAfterSeconds: null };
  };

  // The shell's screen-capture switch (src-tauri/src/commands.rs capture_protection_set): no login, no broker.  The window is created protected,
  // so the fake starts at `true`; S.captureProtection records the last choice and S.captureProtectionCalls how many times the app asked, so a spec
  // can assert both the state and that a start with no stored choice made no call at all.
  H.capture_protection_set = function (a) {
    if (typeof a.enabled !== "boolean") throw B.error("malformed_request", "enabled must be a boolean", undefined, "bridge");
    B.S.captureProtection = a.enabled;
    B.S.captureProtectionCalls = (B.S.captureProtectionCalls || 0) + 1;
    return { enabled: a.enabled, applied: true };
  };

  // Examples for tests/unit/fixture-shape.test.ts (see core.js).
  var E = B.examples;
  var OPEN = { locked: false };
  E.copy_text = [
    { reset: OPEN, args: { text: "0x0000000000000000000000000000000000000000" } },
    { reset: { locked: true }, args: { text: "no login is needed to copy a public address" } },
    { reset: OPEN, args: { text: new Array(4098).join("x") }, error: "text_too_large" },
  ];
  E.capture_protection_set = [
    { reset: OPEN, args: { enabled: false } },
    { reset: { locked: true }, args: { enabled: true } },
  ];
  E.grant_create =[{ reset: OPEN, args: { from: "beacon", to: { kind: "node", nodeId: "atlas" }, scope: ["read"], reason: "fixture reason" }, error: "presence_required" }];
  E.grant_revoke = [{ reset: OPEN, args: { id: "g-f1" } }, { reset: OPEN, args: { id: "g-nope" }, error: "not_found" }];
  E.audit_tail = [{ reset: OPEN, setup: function () { H.entry_reveal({ node: "atlas", entry: "e-a1" }); }, args: { limit: 10 } }];
  E.audit_get = [{ reset: OPEN, args: { id: "aud-1" }, error: "presence_required" }];
  E.maintenance_verify = [{ reset: OPEN, args: {} }];
  E.maintenance_doctor = [
    { reset: OPEN, args: { apply: false } },
    { reset: OPEN, args: { apply: true } },
    { reset: OPEN, setup: function () { B.S.expiredSeals = [{ node: "old", sealedAt: 1750000000 }]; }, args: { apply: false, purgeExpiredSeals: true } },
    { reset: OPEN, setup: function () { B.S.expiredSeals = [{ node: "old", sealedAt: 1750000000 }]; }, args: { apply: true, purgeExpiredSeals: true } },
    { reset: OPEN, args: { rebuildRegistry: true }, error: "malformed_request" },
    { reset: OPEN, args: function () { return { rebuildRegistry: true, passphrase: B.S.passphrase }; }, error: "presence_required" },
  ];
  // Any non-empty passphrase encrypts the archive (it is not the vault's), as in ops.rs.
  E.maintenance_backup = [
    { reset: OPEN, args: function () { return { passphrase: B.S.passphrase, retain: 14 }; } },
    { reset: OPEN, args: { passphrase: "any-other-passphrase", retain: 30 } },
    { reset: OPEN, args: { passphrase: "" }, error: "malformed_request" },
  ];
  E.maintenance_rotate_root = [
    { reset: OPEN, args: function () { return { passphrase: B.S.passphrase }; }, error: "presence_required" },
    { reset: OPEN, args: { passphrase: "" }, error: "malformed_request" },
  ];
})((window.__brokerFixture = window.__brokerFixture || {}));
