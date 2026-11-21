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
    // ADR-174 (6): a single-entry grant must expire, at most 90 days ahead.
    if (a.to.kind === "entry" && (typeof a.expiresAt !== "number" || a.expiresAt - Math.floor(Date.now() / 1000) > 90 * 86400)) throw B.error("malformed_request", "an entry-level grant must expire, at most 90 days ahead");
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

  // ADR-156: change the passphrase (crates/brokerd/src/ops.rs "vault.set_passphrase"): both passphrases present and non-empty, the owner's
  // login, the current one right (wrong_passphrase otherwise, nothing changes), the new one different; then a root rotation under the new
  // passphrase, so a NEW recovery code (S.rootRecoveryCode moves on, as the old one stops working).  No presence key is enrolled in the fake.
  H.vault_set_passphrase = function (a) {
    var S = B.S;
    if (typeof a.passphrase !== "string" || typeof a.newPassphrase !== "string") throw B.error("malformed_request", "params.passphrase and params.newPassphrase are required");
    if (!a.passphrase || !a.newPassphrase) throw B.error("malformed_request", "params.passphrase and params.newPassphrase must not be empty");
    B.requireLogin();
    if (a.passphrase !== S.passphrase) throw B.error("wrong_passphrase", "wrong passphrase");
    if (a.newPassphrase === a.passphrase) throw B.error("malformed_request", "the new passphrase is the same as the current one");
    S.passphrase = a.newPassphrase;
    S.passphraseChanges = (S.passphraseChanges || 0) + 1;
    var code = "FIXTURE-NEW-ROOT-" + S.passphraseChanges;
    S.rootRecoveryCode = code;
    B.audit("vault.set_passphrase");
    var r = { rotated: true, recoveryCode: code, nodesRewrapped: S.nodes.length, vaultGeneration: 2, filesReplaced: 3, artifactsResigned: 1, completionPending: false, notResigned: [], passphraseChanged: true, machineLocked: !!S.machineLock };
    if (S.machineLock && S.machineLockSealFails) { S.machineLock = false; r.machineLocked = false; r.machineLockRemoved = "the device key could not be read"; }
    return r;
  };

  // ADR-165: the machine lock (crates/brokerd/src/state/machine_lock.rs, ops.rs keystore.*).  "Bound" is S.machineLock; the device key is
  // S.deviceKeyId (made on the first bind, never removed by an unbind).  Owner only: the fixture has no agents, so that refusal is the
  // broker's own test.  Bind needs an open vault, a recovery code (S.recoveryUnlock), the passphrase and the CURRENT root recovery code
  // (review P1-1; a wrong code is recovery_code_mismatch), and is a root rotation that re-keys every project (review P0-1), so it issues a
  // NEW recovery code and the old one stops working; review N1: in two calls, the new code shown by the first and typed back into the second.  Unbind needs a fresh second factor where a gate is confirmed (S.elevated), Touch ID
  // where it is set up (S.touchId: the shell attaches the proof; without it, presence_required), and the passphrase where neither is set up
  // (S.noPresenceNoGate: without it, malformed_request).  S.machineLockSealFails makes a rotation answer `machineLockRemoved` (review P1-4).
  // The broker's own sentences (ops.rs machine_lock_status_json).
  var MACHINE_LOCK_PROTECTS = "a copy of the vault folder alone (a copied directory, a USB disk, a Time Machine backup, which leaves the device key out) made after the lock was turned on cannot be opened with the passphrase on another computer; it needs this Mac's device key or the recovery code of its day";
  // ADR-174 O-2: a key made before it was kept out of Time Machine is never claimed (S.deviceKeyPredates).
  var MACHINE_LOCK_PROTECTS_NO_TM = "a copy of the vault folder alone (a copied directory, a USB disk) made after the lock was turned on cannot be opened with the passphrase on another computer; it needs this Mac's device key or the recovery code of its day";
  var MACHINE_LOCK_OLD_KEY = "Time Machine backups that may hold this Mac's device key (it was made before it was kept out of Time Machine, or its exclusion did not hold; turn the lock off and on again to replace it with one no backup ever held); ";
  var MACHINE_LOCK_PROTECTS_OFF ="nothing extra: the passphrase alone opens a copy of the vault folder on any computer";
  var MACHINE_LOCK_DOES_NOT = "a stolen or unlocked Mac (its disk holds the vault folder and the device key; FileVault and a locked screen protect that); whole-disk images and Migration Assistant, which carry the device key with the folder; what a copy made before the lock was turned on already held; CredMgr backup archives, which hold the passphrase file unsealed inside their own encryption and open with their backup passphrase and the vault passphrase (while the lock is on they are written outside the vault folder, in CredMgr's state folder, so a copy of the vault folder does not carry them; one copied elsewhere is not covered); anyone holding the recovery code";
  function machineLockStatus() {
    var S = B.S, bound = !!S.machineLock, key = S.deviceKeyId || null, pre = S.machineLockPreBind || [];
    var plainWhileBound = !!S.machineLockPlainWhileBound, detached = !!S.machineLockRecordDetached;
    return {
      bound: bound, tier: bound ? "file" : "off", secureEnclave: false, opensHere: !bound || !!key,
      sealedKeyId: bound ? key : null, damaged: false, deviceKeyPresent: !!key, deviceKeyId: key, deviceKeyUnreadable: false,
      deviceKeyModeOpen: false, deviceKeyForeignOwner: false,
      recoveryUnlock: !!S.recoveryUnlock, markedBound: bound || plainWhileBound, plainWhileBound: plainWhileBound, preBindNodes: pre.slice(),
      // ADR-165 M5: S.machineLockRecordDetached — this Mac's record names this folder under another vault id; said first.
      recordDetached: detached,
      // ADR-174 O-2: the device key is kept out of Time Machine (made and marked together here).
      deviceKeyTimeMachineExcluded: key ? true : null,
      // ...and made already excluded, so a bound vault's Time Machine backups are covered (S.deviceKeyPredates: an older key, not claimed).
      deviceKeyTimeMachineCovered: bound && !!key && !S.deviceKeyPredates,
      // ADR-174 O-3: S.machineLockSyncedFolder — the vault folder is in a synced folder ("iCloud Drive"); bind refuses it.
      syncedFolder: S.machineLockSyncedFolder || null,
      // ADR-174 O-5: Touch ID where it is set up (S.touchId: the shell attaches the proof), else a fresh second factor (S.gateEnrolled).
      bindProof: S.touchId ? "presence" : S.gateEnrolled ? "secondFactor" : "none",
      warning: detached ? "this Mac's machine-lock record names this folder as vault 0123456789abcdef0123456789abcdef, but its vault.id is none: changed, removed, or an older copy was put back. Nothing was repaired. What was written after the lock stays protected; turn the lock off and on again"
        : plainWhileBound ? "this Mac recorded the vault as bound, but the passphrase file on disk is plain: turning the lock on was interrupted, or an older plain file was put back; bind again"
        : pre.length ? "turning the lock on did not finish: " + pre.join(", ") + " still use a key from before it; bind again" : null,
      protects: !bound ? MACHINE_LOCK_PROTECTS_OFF : S.deviceKeyPredates ? MACHINE_LOCK_PROTECTS_NO_TM : MACHINE_LOCK_PROTECTS,
      doesNotProtect: bound && S.deviceKeyPredates ? MACHINE_LOCK_DOES_NOT.replace("what a copy made before", MACHINE_LOCK_OLD_KEY + "what a copy made before") : MACHINE_LOCK_DOES_NOT,
    };
  }
  H.keystore_status = function () {
    B.requireLogin();
    return machineLockStatus();
  };
  // Review N1: bind is two calls.  `prepare` proves the passphrase and the CURRENT code and answers the NEW code (`newRecoveryCode`),
  // changing nothing (S.machineLockPending holds it, as the broker holds it in memory); `commit` takes that code typed back (a wrong one is
  // recovery_code_mismatch, the prepared bind still waits) and only then binds; `cancel` forgets it.  A vault already bound prepares with
  // `already: true` and no code, and its commit re-keys the projects still on a pre-bind key.  A lock forgets a prepared bind.
  H.keystore_bind = function (a) {
    var S = B.S, out;
    a = a || {};
    B.requireLogin();
    if (a.phase === "cancel") {
      S.machineLockPending = null;
      out = machineLockStatus();
      out.phase = "cancel";
      out.changed = false;
      return out;
    }
    if ((a.phase === "prepare" || a.phase === "commit") && S.machineLockSyncedFolder && !S.machineLock) {
      throw B.error("malformed_request", "the machine lock was not turned on (nothing changed): the vault folder is in " + S.machineLockSyncedFolder + ", which another Mac can open too. A lock tied to this Mac would make every other Mac need the recovery code, and a recovery there would move the lock and retire the code. Move the vault to a folder that is not synced, then turn the lock on");
    }
    // ADR-174 O-5: each phase that can change the vault asks for Touch ID (attached by the shell when S.touchId) or, without it, a fresh
    // second factor; a commit with nothing waiting refuses on its own first.
    if ((a.phase === "prepare" || (a.phase === "commit" && S.machineLockPending)) && !S.touchId && S.gateEnrolled && !S.elevated) {
      throw B.error("two_factor_required", "a fresh second factor is required", { challenge: "totp", scope: "vault", expiresIn: 0 });
    }
    if (a.phase === "commit") {
      var p = S.machineLockPending;
      if (!p) throw B.error("malformed_request", "the machine lock was not turned on (nothing changed): no bind is waiting for its recovery code (it was never started, was abandoned, or the vault was locked since); start again");
      if (p.code !== null && (typeof a.recoveryCode !== "string" || a.recoveryCode.trim() !== p.code)) throw B.error("recovery_code_mismatch", "the retyped recovery code did not match");
      S.machineLockPending = null;
      if (p.code === null) {
        var stale = (S.machineLockPreBind || []).slice();
        S.machineLockPreBind = [];
        out = machineLockStatus();
        out.phase = "commit";
        out.changed = false;
        out.deviceKeyCreated = false;
        out.nodesRekeyed = stale;
        out.rekeyFailed = [];
        return out;
      }
      var created = false;
      if (!S.deviceKeyId) { S.deviceKeyId = "00f1x7u7e0de71ce"; created = true; }
      S.machineLock = true;
      S.machineLockPlainWhileBound = false;
      S.rootRecoveryCode = p.code;
      var rekeyed = S.nodes.filter(function (n) { return n.kind !== "orphan"; }).map(function (n) { return n.id; });
      S.machineLockPreBind = [];
      B.audit("keystore.bind");
      out = machineLockStatus();
      out.phase = "commit";
      out.changed = true;
      out.deviceKeyCreated = created;
      out.nodesRekeyed = rekeyed;
      out.rekeyFailed = [];
      out.orphanKeyReplaced = true;
      out.completionPending = false;
      return out;
    }
    if (a.phase !== "prepare") throw B.error("malformed_request", "params.phase is required: \"prepare\", then \"commit\", or \"cancel\"");
    if (typeof a.passphrase !== "string" || typeof a.recoveryCode !== "string") throw B.error("malformed_request", "params.passphrase and params.recoveryCode are required");
    if (!S.recoveryUnlock) throw B.error("malformed_request", "this vault has no recovery code yet, so the machine lock cannot be turned on");
    if (a.passphrase !== S.passphrase) throw B.error("wrong_passphrase", "wrong passphrase");
    if (a.recoveryCode.trim() !== S.rootRecoveryCode) throw B.error("recovery_code_mismatch", "the recovery code does not open this vault");
    out = machineLockStatus();
    out.phase = "prepare";
    out.changed = false;
    out.expiresIn = 600;
    if (S.machineLock) {
      S.machineLockPending = { code: null };
      out.already = true;
      out.newRecoveryCode = null;
      out.nodesToRekey = (S.machineLockPreBind || []).slice();
      return out;
    }
    S.binds = (S.binds || 0) + 1;
    S.machineLockPending = { code: "FIXTURE-BOUND-ROOT-" + S.binds };
    out.already = false;
    out.newRecoveryCode = S.machineLockPending.code;
    out.nodesToRekey = [];
    return out;
  };
  /** Both phases at once, as a test's setup binds (the screen never does this: it shows the code and asks for it back). */
  B.bindNow = function () {
    var p = H.keystore_bind({ phase: "prepare", passphrase: B.S.passphrase, recoveryCode: B.S.rootRecoveryCode });
    return H.keystore_bind({ phase: "commit", recoveryCode: p.newRecoveryCode || undefined });
  };
  H.keystore_unbind = function (a) {
    var S = B.S;
    a = a || {};
    B.requireLogin();
    if (S.gateEnrolled && !S.elevated) throw B.error("two_factor_required", "a fresh second factor is required", { challenge: "totp", scope: "vault", expiresIn: 0 });
    if (S.noPresenceNoGate) {
      if (!a.passphrase) throw B.error("malformed_request", "params.passphrase is required: no Touch ID key and no second factor are enrolled, so turning the machine lock off asks for the passphrase");
      if (a.passphrase !== S.passphrase) throw B.error("wrong_passphrase", "wrong passphrase");
    } else if (!S.touchId) throw B.error("presence_required", "presence cannot be attested by this transport", { operation: "keystore.unbind" });
    var already = !S.machineLock;
    S.machineLock = false;
    S.machineLockPlainWhileBound = false;
    if (!already) B.audit("keystore.unbind");
    var out = machineLockStatus();
    out.changed = !already;
    return out;
  };

  // ADR-156: the owner has seen the cross-node alarm; the count goes back to 0.  S.anomalyAcks counts the calls for a spec.
  H.vault_anomalies_ack = function () {
    B.requireLogin();
    var n = B.S.anomaliesUnseen || 0;
    B.S.anomaliesUnseen = 0;
    B.S.anomalyAcks = (B.S.anomalyAcks || 0) + 1;
    return { acknowledged: n };
  };

  // ADR-156: start at login (src-tauri/src/login_agent.rs), local to the shell: no login, no broker.  By default the fake is what the shell is
  // off a Mac (platform_unsupported).  A spec plays a Mac with broker.set({ loginAgent: { installed, current, loaded, daemon } }); install and
  // uninstall then flip it, and S.loginAgentCalls records them.
  function loginAgent() {
    if (!B.S.loginAgent) throw B.error("platform_unsupported", "Start at login is not supported on this platform: it uses a macOS launchd user agent", undefined, "bridge");
    return B.S.loginAgent;
  }
  H.login_agent_status = function () { return B.clone(loginAgent()); };
  H.login_agent_install = function () {
    var st = loginAgent();
    if (!st.daemon) throw B.error("login_agent_failed", "no credmgrd was found beside the app, in /usr/local/bin or in /opt/homebrew/bin", undefined, "bridge");
    B.S.loginAgentCalls = (B.S.loginAgentCalls || []).concat(["install"]);
    B.S.loginAgent = { installed: true, current: true, loaded: true, daemon: st.daemon };
    if (B.S.unreachable) B.S.unreachable = false; // loading the agent starts the broker
    return B.clone(B.S.loginAgent);
  };
  H.login_agent_uninstall = function () {
    var st = loginAgent();
    B.S.loginAgentCalls = (B.S.loginAgentCalls || []).concat(["uninstall"]);
    B.S.loginAgent = { installed: false, current: false, loaded: false, daemon: st.daemon };
    return B.clone(B.S.loginAgent);
  };

  // Restore from a backup (ADR-166, src-tauri/src/restore.rs): the shell runs `credmgr restore --json`, whose refusals these are.  It needs no
  // login and never reaches the broker; the command itself refuses while a broker answers, which here is "the fake is reachable".  With the
  // broker down: the passphrase FIXTURE_BACKUP_PASSPHRASE opens any archive; a target named "used" is not empty; an archive named "missing"
  // cannot be read.  Each restore is recorded in S.restored.
  var TEST_BACKUP_PASS = "fixture-backup-passphrase";
  H.backup_restore = function (a) {
    if (typeof a.archive !== "string" || !a.archive.trim()) throw B.error("restore_failed", "name the backup archive to restore", undefined, "bridge");
    if (typeof a.passphrase !== "string" || !a.passphrase) throw B.error("restore_failed", "the backup passphrase is required", undefined, "bridge");
    var target = typeof a.target === "string" && a.target.trim() ? a.target : "/fixture/vault";
    if (/(^|\/)used$/.test(target)) throw B.error("restore_target_not_empty", target + " is not an empty directory", undefined, "bridge");
    if (!B.S.unreachable) throw B.error("broker_running", "credmgrd is running (it answers on /fixture/vault/run/broker.sock)", undefined, "bridge");
    if (/missing/.test(a.archive) || a.passphrase !== TEST_BACKUP_PASS) throw B.error("restore_failed", "could not decrypt the archive - wrong backup passphrase, or the file is damaged", undefined, "bridge");
    B.S.restored = (B.S.restored || []).concat([{ archive: a.archive, target: target }]);
    return { target: target, stateDir: "/fixture/state", files: 12, bytes: 4096, counter: "restored", complete: true };
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

  // The shell's window_state (src-tauri/src/shell.rs): no login, no broker.  By default it answers what a minimised window would (a hidden
  // page is a put-away window), so a spec that hides the page sees the lock; S.windowState overrides it, e.g. { minimized: false, visible: true }
  // for a window that is only covered or sits on a display that went dark.
  H.window_state = function () {
    if (B.S.windowState) return B.S.windowState;
    const hidden = typeof document !== "undefined" && document.hidden;
    return { minimized: !!hidden, visible: true };
  };

  // ADR-143, Settings -> Agents (src-tauri/src/agents.rs): the shell reads the assistants' config files and writes one entry on a click.  No login, no
  // broker.  S.agentFx is { client: state } (default below); a write flips the state and is recorded in S.agentWrites so a spec can assert it.  A change
  // to the "file" between the plan and the write is rehearsed with broker.set({ agentMoved: true }) -> agent_changed.
  var AGENT_LABELS = { "claude-code": "Claude Code", "claude-desktop": "Claude Desktop", cursor: "Cursor", vscode: "VS Code (Copilot)", windsurf: "Windsurf" };
  var AGENT_PATHS = { "claude-code": "~/.claude.json", "claude-desktop": "~/Library/Application Support/Claude/claude_desktop_config.json", cursor: "~/.cursor/mcp.json", vscode: "~/Library/Application Support/Code/User/mcp.json", windsurf: "~/.codeium/windsurf/mcp_config.json" };
  var AGENT_DEFAULT = { "claude-code": "ready", "claude-desktop": "connected", cursor: "ready", vscode: "not_found", windsurf: "unreadable" };
  var AGENT_CMD = "claude mcp add --scope user credmgr -- /opt/homebrew/bin/credmgr mcp";
  function agentState(c) { return (B.S.agentFx && B.S.agentFx[c]) || AGENT_DEFAULT[c]; }
  function agentClient(c) {
    if (!AGENT_LABELS[c]) throw B.error("agent_refused", "unknown client '" + c + "'", undefined, "bridge");
    return c;
  }
  H.agent_detect = function () {
    return {
      binary: B.S.noBinary ? "credmgr" : "/opt/homebrew/bin/credmgr", binaryFound: !B.S.noBinary, claudeCodeCommand: AGENT_CMD,
      clients: Object.keys(AGENT_LABELS).map(function (c) {
        return { client: c, label: AGENT_LABELS[c], path: AGENT_PATHS[c], state: agentState(c), detail: agentState(c) === "unreadable" ? "the file is not valid JSON (expected value at line 3 column 5); it was left alone" : null, writable: c !== "claude-code", container: c === "vscode" ? "servers" : "mcpServers" };
      }),
    };
  };
  H.agent_snippet = function (a) {
    var c = a.client === "generic" ? "generic" : agentClient(a.client);
    var key = c === "vscode" ? "servers" : "mcpServers";
    return { client: c, snippet: "{\n  \"" + key + "\": {\n    \"credmgr\": {\n      \"command\": \"/opt/homebrew/bin/credmgr\",\n      \"args\": [\"mcp\"]\n    }\n  }\n}\n", command: c === "claude-code" ? AGENT_CMD : null };
  };
  function agentPlan(c, action) {
    agentClient(c);
    if (c === "claude-code") throw B.error("agent_refused", "CredMgr never edits ~/.claude.json (Claude Code's live state file). Run this in a terminal instead: " + AGENT_CMD, undefined, "bridge");
    if (action !== "connect" && action !== "disconnect") throw B.error("agent_refused", "unknown action '" + action + "'", undefined, "bridge");
    var st = agentState(c);
    if (st === "unreadable") throw B.error("agent_refused", AGENT_LABELS[c] + ": the file is not valid JSON; it was left alone", undefined, "bridge");
    if (st === "other_entry" && action === "connect") throw B.error("agent_refused", AGENT_LABELS[c] + ": the file already has a different \"credmgr\" entry", undefined, "bridge");
    var unchanged = action === "connect" ? st === "connected" : st !== "connected";
    var exists = st !== "not_found";
    var sign = action === "connect" ? "+" : "-";
    return {
      client: c, label: AGENT_LABELS[c], action: action, path: AGENT_PATHS[c], exists: exists, unchanged: unchanged,
      diff: unchanged ? [] : [{ kind: " ", text: "  \"mcpServers\": {" }, { kind: sign, text: "    \"credmgr\": {" }, { kind: sign, text: "      \"command\": \"/opt/homebrew/bin/credmgr\"," }, { kind: sign, text: "      \"args\": [\"mcp\"]" }, { kind: sign, text: "    }" }, { kind: " ", text: "  }" }],
      backupName: exists ? "mcp.json.credmgr-backup-<time>" : null,
      token: "tok-" + c + "-" + action + "-" + st,
    };
  }
  H.agent_plan = function (a) { return agentPlan(a.client, a.action); };
  H.agent_apply = function (a) {
    var p = agentPlan(a.client, a.action);
    if (B.S.agentMoved || p.token !== a.token) throw B.error("agent_changed", "the file changed since the diff was shown; nothing was written. Review it again.", undefined, "bridge");
    if (p.unchanged) return { written: false, path: p.path };
    B.S.agentFx = Object.assign({}, B.S.agentFx || {});
    B.S.agentFx[a.client] = a.action === "connect" ? "connected" : "ready";
    B.S.agentWrites = (B.S.agentWrites || []).concat([{ client: a.client, action: a.action }]);
    return { written: true, path: p.path, backup: p.exists ? p.path + ".credmgr-backup-20261106T101500Z" : null, restart: AGENT_LABELS[a.client] };
  };
  H.agent_prompt = function (a) {
    if (["open", "guarded", "sealed"].indexOf(a.level) < 0) throw B.error("agent_refused", "unknown security level '" + a.level + "'", undefined, "bridge");
    B.S.agentPrompts = (B.S.agentPrompts || []).concat([{ node: a.node, reachable: a.reachable, level: a.level, format: a.format }]);
    return { text: (a.format === "md" ? "# CREDMGR.md\n\n" : "") + "## Credential access - CredMgr vault protocol\nYou are scoped to the node **" + a.node + "**. Security level: **" + a.level + "**.\n", format: a.format };
  };

  // Examples for tests/unit/fixture-shape.test.ts (see core.js).
  var E = B.examples;
  var OPEN = { locked: false };
  E.agent_detect = [{ reset: OPEN, args: {} }];
  E.agent_snippet = [{ reset: OPEN, args: { client: "cursor" } }, { reset: OPEN, args: { client: "claude-code" } }, { reset: OPEN, args: { client: "generic" } }, { reset: OPEN, args: { client: "nope" }, error: "agent_refused" }];
  E.agent_plan = [
    { reset: OPEN, args: { client: "cursor", action: "connect" } },
    { reset: OPEN, args: { client: "claude-desktop", action: "connect" } },
    { reset: OPEN, args: { client: "claude-desktop", action: "disconnect" } },
    { reset: OPEN, args: { client: "claude-code", action: "connect" }, error: "agent_refused" },
    { reset: OPEN, args: { client: "windsurf", action: "connect" }, error: "agent_refused" },
  ];
  E.agent_apply = [
    { reset: OPEN, args: { client: "cursor", action: "connect", token: "tok-cursor-connect-ready" } },
    { reset: OPEN, args: { client: "cursor", action: "connect", token: "stale" }, error: "agent_changed" },
  ];
  E.agent_prompt = [{ reset: OPEN, args: { node: "atlas", reachable: ["atlas", "global"], level: "guarded", format: "prompt" } }, { reset: OPEN, args: { node: "atlas", reachable: ["atlas"], level: "nope", format: "md" }, error: "agent_refused" }];
  var MAC = { installed: false, current: false, loaded: false, daemon: "/Applications/CredMgr.app/Contents/MacOS/credmgrd" };
  E.vault_set_passphrase = [
    { reset: OPEN, args: function () { return { passphrase: B.S.passphrase, newPassphrase: "a brand new fixture passphrase" }; } },
    { reset: OPEN, args: { passphrase: "not the passphrase", newPassphrase: "another one" }, error: "wrong_passphrase" },
    { reset: OPEN, args: function () { return { passphrase: B.S.passphrase, newPassphrase: B.S.passphrase }; }, error: "malformed_request" },
    { reset: { locked: true }, args: { passphrase: "x", newPassphrase: "y" }, error: "vault_locked" },
  ];
  E.vault_anomalies_ack = [{ reset: OPEN, setup: function () { B.S.anomaliesUnseen = 3; }, args: {} }, { reset: { locked: true }, args: {}, error: "vault_locked" }];
  E.backup_restore = [
    { reset: { locked: false, unreachable: true }, args: { archive: "/fixture/backups/a.enc", passphrase: TEST_BACKUP_PASS, target: "/fixture/new" } },
    { reset: { locked: false, unreachable: true }, args: { archive: "/fixture/backups/a.enc", passphrase: TEST_BACKUP_PASS } },
    { reset: OPEN, args: { archive: "/fixture/backups/a.enc", passphrase: TEST_BACKUP_PASS, target: "/fixture/new" }, error: "broker_running" },
    { reset: { locked: false, unreachable: true }, args: { archive: "/fixture/backups/a.enc", passphrase: TEST_BACKUP_PASS, target: "/fixture/used" }, error: "restore_target_not_empty" },
    { reset: { locked: false, unreachable: true }, args: { archive: "/fixture/backups/a.enc", passphrase: "wrong", target: "/fixture/new" }, error: "restore_failed" },
  ];
  E.login_agent_status = [{ reset: OPEN, args: {}, error: "platform_unsupported" }, { reset: OPEN, setup: function () { B.S.loginAgent = MAC; }, args: {} }];
  E.login_agent_install = [
    { reset: OPEN, setup: function () { B.S.loginAgent = MAC; }, args: {} },
    { reset: OPEN, setup: function () { B.S.loginAgent = { installed: false, current: false, loaded: false, daemon: null }; }, args: {}, error: "login_agent_failed" },
    { reset: OPEN, args: {}, error: "platform_unsupported" },
  ];
  E.login_agent_uninstall = [{ reset: OPEN, setup: function () { B.S.loginAgent = { installed: true, current: true, loaded: true, daemon: MAC.daemon }; }, args: {} }];
  var BIND = function () { return { phase: "prepare", passphrase: B.S.passphrase, recoveryCode: B.S.rootRecoveryCode }; };
  E.keystore_status = [
    { reset: OPEN, args: {} },
    { reset: OPEN, setup: function () { B.bindNow(); }, args: {} },
    { reset: { locked: true }, args: {}, error: "vault_locked" },
  ];
  E.keystore_bind = [
    { reset: OPEN, args: BIND },
    { reset: OPEN, setup: function () { B.bindNow(); }, args: BIND },
    { reset: OPEN, setup: function () { H.keystore_bind(BIND()); }, args: function () { return { phase: "commit", recoveryCode: B.S.machineLockPending.code }; } },
    { reset: OPEN, setup: function () { H.keystore_bind(BIND()); }, args: { phase: "commit", recoveryCode: "NOT-THE-NEW-CODE" }, error: "recovery_code_mismatch" },
    { reset: OPEN, args: { phase: "commit", recoveryCode: "r" }, error: "malformed_request" },
    { reset: OPEN, setup: function () { H.keystore_bind(BIND()); }, args: { phase: "cancel" } },
    { reset: OPEN, args: function () { return { phase: "prepare", passphrase: B.S.passphrase, recoveryCode: "NOT-THE-CODE" }; }, error: "recovery_code_mismatch" },
    { reset: OPEN, args: function () { return { phase: "prepare", passphrase: "not-the-passphrase", recoveryCode: B.S.rootRecoveryCode }; }, error: "wrong_passphrase" },
    { reset: OPEN, args: {}, error: "malformed_request" },
    { reset: { locked: false, recoveryUnlock: false }, args: BIND, error: "malformed_request" },
    { reset: { locked: true }, args: { phase: "prepare", passphrase: "p", recoveryCode: "r" }, error: "vault_locked" },
  ];
  E.keystore_unbind = [
    { reset: { locked: false, touchId: true }, setup: function () { B.bindNow(); }, args: {} },
    { reset: { locked: false, touchId: true }, args: {} },
    { reset: OPEN, setup: function () { B.bindNow(); }, args: {}, error: "presence_required" },
    { reset: OPEN, setup: function () { B.bindNow(); B.S.noPresenceNoGate = true; }, args: {}, error: "malformed_request" },
    { reset: OPEN, setup: function () { B.bindNow(); B.S.noPresenceNoGate = true; }, args: function () { return { passphrase: B.S.passphrase }; } },
    { reset: { locked: false, gate: true, touchId: true }, setup: function () { B.bindNow(); }, args: {}, error: "two_factor_required" },
    { reset: { locked: true }, args: {}, error: "vault_locked" },
  ];
  E.copy_text = [
    { reset: OPEN, args: { text: "0x0000000000000000000000000000000000000000" } },
    { reset: { locked: true }, args: { text: "no login is needed to copy a public address" } },
    { reset: OPEN, args: { text: new Array(4098).join("x") }, error: "text_too_large" },
  ];
  E.window_state = [{ reset: OPEN, args: {} }, { reset: { locked: true }, args: {} }];
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
