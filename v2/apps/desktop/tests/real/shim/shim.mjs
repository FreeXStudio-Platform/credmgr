/**
 * The shim: the Tauri shell's command layer, rewritten in Node over the REAL broker socket.
 *
 * In the app, `invoke("entry_update", {...})` reaches `src-tauri/src/commands.rs`, which turns it into a broker op, attaches the
 * login token it holds, speaks the socket protocol to `credmgrd`, and folds the answer back into session state. The fixture broker
 * the other end-to-end specs use replaces that whole stack with an in-page fake. This replaces only the shell: the commands below
 * run exactly the same steps in Node, and what answers is a real `credmgrd` on a real Unix socket over a real (throwaway) vault.
 *
 *   page:  invoke(cmd, args)  ->  window.__realInvoke  ->  Shim.invoke(cmd, args)  ->  transport.call(socket, op, token, params)
 *
 * What is ported, line for line:  the command -> op table (table.mjs, held to commands.rs by the drift guard), `put` (optional
 * arguments left out of the frame), the argument checks Tauri's own deserialiser makes, token custody and its reconciliation with
 * lock state (session.mjs), `AuthState`, the lock sequence, the wire framing and its id check (transport.mjs), the error shapes
 * (bridge-error.mjs), the two clipboard commands, and the local bulk-paste preview.
 *
 * What is NOT real, and is said so:
 *   - the clipboard is an in-memory object. The real shell writes the macOS pasteboard; a test must never overwrite the developer's
 *     clipboard, so {@link FakeClipboard} keeps what the shell would have written where a test can read it, and models the same
 *     rules (concealed, cleared after 30 s, cleared on lock, a lock racing a copy refuses the write).
 *   - `fields_preview` is a Node port (preview.mjs) of the shell's local Rust command, which runs credmgr-core's parser and
 *     inference. Nothing it answers is trusted by the vault: the page sends the previewed fields to the real broker, which validates
 *     and stores them with the real code.
 */
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";

import { daemonBinary } from "../daemon.mjs";
import { bridgeError, protocolError } from "./bridge-error.mjs";
import { preview } from "./preview.mjs";
import { Session } from "./session.mjs";
import { APP_ICON_IDS, BY_COMMAND, CLIPBOARD_CLEAR_AFTER_SECONDS, COPY_TEXT_MAX_BYTES } from "./table.mjs";
import { callAudited as transportCall } from "./transport.mjs";

/**
 * `backup_restore` (ADR-166): what src-tauri/src/restore.rs does, in Node.  It runs the built `credmgr restore --json` (beside the daemon
 * binary) with the daemon's throwaway vault as CREDMGR_VAULT_DIR and the passphrase on stdin, then reads its one JSON object.  The codes are
 * the command's own; one this shell does not know is `restore_failed`, as in restore.rs `interpret`.
 */
function runRestore(socketPath, params) {
  const cli = join(dirname(daemonBinary()), "credmgr");
  if (!existsSync(cli)) return Promise.reject(bridgeError("restore_unavailable", `no credmgr program at ${cli}; build it with cargo build -p credmgr-cli`));
  if (!params.archive || !String(params.archive).trim()) return Promise.reject(bridgeError("restore_failed", "name the backup archive to restore"));
  if (!params.passphrase) return Promise.reject(bridgeError("restore_failed", "the backup passphrase is required"));
  const args = ["restore", params.archive];
  if (params.target && String(params.target).trim()) args.push("--to", params.target);
  args.push("--json");
  const vaultDir = dirname(dirname(socketPath));
  return new Promise((resolveP, rejectP) => {
    const env = { PATH: process.env.PATH, HOME: join(dirname(vaultDir), "h"), CREDMGR_VAULT_DIR: vaultDir, CREDMGR_STATE_DIR: join(dirname(vaultDir), "s") };
    const child = spawn(cli, args, { env, stdio: ["pipe", "pipe", "pipe"] });
    let out = "";
    child.stdout.on("data", (d) => { out += d; });
    child.stdin.on("error", () => {}); // a refusal comes before the passphrase is read: the pipe may already be closed
    child.stdin.end(`${params.passphrase}\n`);
    child.on("error", (e) => rejectP(bridgeError("restore_unavailable", `could not run ${cli}: ${e.message}`)));
    child.on("close", (status) => {
      const last = out.split("\n").filter((l) => l.trim()).pop() ?? "";
      let v;
      try { v = JSON.parse(last); } catch { return rejectP(bridgeError("restore_failed", "the restore gave no answer this app can read")); }
      if (typeof v.error === "string") {
        const code = ["broker_running", "restore_target_not_empty", "restore_failed"].includes(v.error) ? v.error : "restore_failed";
        return rejectP(bridgeError(code, typeof v.message === "string" ? v.message : "the restore was refused"));
      }
      if (status !== 0 || v.restored !== true) return rejectP(bridgeError("restore_failed", "the restore did not say it finished"));
      resolveP({ target: v.target, stateDir: v.stateDir, files: v.files, bytes: v.bytes, counter: v.counter, complete: v.complete });
    });
  });
}

/**
 * `commands::AUDIT_PASSTHROUGH`: the ops whose answer carries the id of the audit record the change wrote (ADR-091). Held to the Rust list by
 * tests/unit/adr090-091.test.ts and to the broker's ops by the drift guard.
 */
export const AUDIT_PASSTHROUGH = new Set([
  "entry.create", "entry.create_batch", "entry.update", "entry.rotate", "entry.remove", "entry.restore", "entry.undo",
  "field.add", "field.update", "field.remove", "field.reorder", "notes.write",
  "node.create", "node.update", "node.policy", "node.set_workdirs", "node.reparent", "node.seal", "node.restore",
  "grant.create", "grant.revoke", "vault.pending_accept", "vault.pending_discard", "vault.approval_decide",
  "entry.alias", "entry.import_env", "entry.set_expiry", "entry.move",
  "entry.tag_set", "merge.apply", "merge.auto", "merge.auto_all", "merge.dismiss", "merge.undismiss", "merge.restore_all",
  "vault.doctor_apply",
  "settings.set", "settings.revert", "settings.request_decide",
]);

const clone = (v) => (v === undefined ? undefined : JSON.parse(JSON.stringify(v)));

/** `commands::without_value`: a refusal never carries a revealed value, so take `value` and (ADR-078) `fields` out of the detail. */
function withoutValue(error) {
  if (error?.detail && typeof error.detail === "object") {
    delete error.detail.value;
    delete error.detail.fields;
  }
  return error;
}

/**
 * `commands::take_revealed_value`: move `value` out of an `entry.reveal` answer. An answer with no `value` and several fields is the
 * caller's refusal to make (`field_required`: name the field); anything else that is not text is the broker's fault (protocol).
 */
function takeRevealedValue(body) {
  const object = body && typeof body === "object" && !Array.isArray(body) ? body : null;
  if (object && Object.prototype.hasOwnProperty.call(object, "value")) {
    const value = object.value;
    delete object.value;
    if (typeof value === "string") return value;
    throw protocolError("entry.reveal answered a value that is not text; nothing was copied");
  }
  const count = Array.isArray(body?.fields) ? body.fields.length : 0;
  if (count > 1) throw bridgeError("field_required", `this entry has ${count} fields; name the one to copy (entryCopy takes a field id)`);
  throw protocolError("entry.reveal answered no value; nothing was copied");
}

/** The pasteboard, as far as the clipboard rules go (`src-tauri/src/clipboard.rs`). Never touches the real pasteboard. */
export class FakeClipboard {
  text = null;
  concealed = false;
  ttlMs;
  #owned = false;
  #epoch = 0;
  #timer = null;
  /** Every write and clear, oldest first: `{ kind: "secret"|"plain"|"clear", length }`. Never the content. */
  history = [];

  constructor(ttlMs) {
    this.ttlMs = ttlMs;
  }

  /** A ticket is taken before the reveal; a lock that lands while the reveal is in flight invalidates it. */
  ticket() {
    return this.#epoch;
  }

  copySecretFor(ticket, text) {
    if (ticket !== this.#epoch) throw bridgeError("clipboard_failed", "the vault locked while the value was being copied; nothing was written");
    this.#write(text, true);
    this.history.push({ kind: "secret", length: text.length });
    this.#timer = setTimeout(() => this.clearIfOwned(), this.ttlMs);
    this.#timer.unref?.();
  }

  copyPlain(text) {
    this.#write(text, false);
    this.history.push({ kind: "plain", length: text.length });
  }

  /** Empties the clipboard only if it still holds a secret this shell put there; a later copy of the user's own is left alone. */
  clearIfOwned() {
    this.#epoch += 1;
    if (!this.#owned) return;
    this.text = null;
    this.concealed = false;
    this.#owned = false;
    clearTimeout(this.#timer);
    this.history.push({ kind: "clear", length: 0 });
  }

  #write(text, secret) {
    clearTimeout(this.#timer);
    this.text = text;
    this.concealed = secret;
    this.#owned = secret;
  }
}

/** Tauri's own argument deserialisation, per kind. Returns an error string or null. */
function checkKind(kind, value) {
  switch (kind) {
    case "string":
      return typeof value === "string" ? null : `invalid type: ${Array.isArray(value) ? "sequence" : typeof value}, expected a string`;
    case "bool":
      return typeof value === "boolean" ? null : `invalid type: ${typeof value}, expected a boolean`;
    case "u64":
      return Number.isSafeInteger(value) && value >= 0 ? null : `invalid value: ${JSON.stringify(value)}, expected u64`;
    case "i64":
      return Number.isSafeInteger(value) ? null : `invalid value: ${JSON.stringify(value)}, expected i64`;
    case "string[]":
      return Array.isArray(value) && value.every((s) => typeof s === "string") ? null : "invalid type, expected a sequence of strings";
    case "json":
      return null;
    default:
      throw new Error(`shim: unknown kind ${kind}`);
  }
}

export class Shim {
  /**
   * @param {object} options
   * @param {string} options.socketPath  the daemon's socket (must be the throwaway one: the caller proves it)
   * @param {number} [options.clipboardTtlMs]
   * @param {number} [options.readTimeoutMs]
   */
  constructor(options) {
    this.socketPath = options.socketPath;
    this.session = new Session();
    this.clipboard = new FakeClipboard(options.clipboardTtlMs ?? CLIPBOARD_CLEAR_AFTER_SECONDS * 1000);
    this.readTimeoutMs = options.readTimeoutMs;
    /** `{cmd, args}` for every command the page invoked, oldest first (copies). */
    this.calls = [];
    /** `{op, params}` for every frame this shim put on the wire, oldest first (copies). */
    this.wire = [];
    /** Answers the page's `invoke` got, by command, for tests that want the raw broker answer (secret-bearing: Node only). */
    this.answers = [];
    /** How long each command took, in order: `{cmd, ms, ok}`. Attached to a failing test, so a hang is visible as one. */
    this.timings = [];
  }

  /** The `invoke()` surface. Resolves with the command's answer or rejects with a BridgeError-shaped object / Tauri's string error. */
  async invoke(cmd, args) {
    const row = BY_COMMAND.get(cmd);
    this.calls.push({ cmd, args: clone(args ?? {}) });
    const started = Date.now();
    let result;
    try {
      // The framework's own refusals come first, exactly as in Tauri: an unknown command, then an argument that does not deserialise.
      if (!row) throw `Command ${cmd} not found`;
      const params = this.#collect(row, args ?? {});
      result = await this.#run(row, params);
    } catch (e) {
      this.answers.push({ cmd, error: clone(e) });
      this.timings.push({ cmd, ms: Date.now() - started, ok: false, code: e?.code });
      throw e;
    }
    this.answers.push({ cmd, result: clone(result) });
    this.timings.push({ cmd, ms: Date.now() - started, ok: true });
    return result;
  }

  /** `put` for every declared parameter, after the checks Tauri makes before a command body runs. */
  #collect(row, args) {
    const params = {};
    for (const { key, kind, required } of row.params) {
      const value = args[key];
      if (value === undefined || value === null) {
        if (required) throw `invalid args \`${key}\` for command \`${row.command}\`: command ${row.command} missing required key ${key}`;
        continue; // an omitted optional argument is absent from the frame, never null
      }
      const bad = checkKind(kind, value);
      if (bad) throw `invalid args \`${key}\` for command \`${row.command}\`: ${bad}`;
      params[key] = value;
    }
    return params;
  }

  /** `dispatch_at`: attach the token, talk to the broker, fold the answer into session state. */
  async #dispatch(op, params) {
    this.wire.push({ op, params: clone(params) });
    const token = this.session.token();
    let value;
    let audit;
    try {
      ({ value, audit } = await transportCall(this.socketPath, op, token, params, { timeoutMs: this.readTimeoutMs }));
    } catch (error) {
      this.session.reconcileErr(error);
      throw error;
    }
    this.session.reconcileOk(op, value);
    // `commands::attach_audit`: additively, for a changing op's object answer, never over a member the broker put there.
    if (audit && AUDIT_PASSTHROUGH.has(op) && value && typeof value === "object" && !Array.isArray(value) && !("audit" in value)) value.audit = audit;
    return value;
  }

  #authState(value) {
    const state = {
      locked: typeof value?.locked === "boolean" ? value.locked : true, // an unreadable flag reads as locked, never as ready
      authenticated: this.session.isAuthenticated(),
      initialized: typeof value?.initialized === "boolean" ? value.initialized : true, // fail-safe: show the lock screen of a vault that exists
    };
    // `commands::pending_from` (ADR-090): a bare count of waiting agent requests, left out when 0 or unreadable.
    if (Number.isSafeInteger(value?.pendingApprovals) && value.pendingApprovals > 0) state.pendingApprovals = value.pendingApprovals;
    // ADR-156: the unseen cross-node alarm count, the same rule (`commands::count_from`).
    if (Number.isSafeInteger(value?.anomaliesUnseen) && value.anomaliesUnseen > 0) state.anomaliesUnseen = value.anomaliesUnseen;
    // ADR-163: the vault can be opened with its recovery code (`commands::auth_state`), left out when not.
    if (value?.recoveryUnlock === true) state.recoveryUnlock = true;
    return state;
  }

  async #run(row, params) {
    switch (row.command) {
      case "vault_status":
        return this.#authState(await this.#dispatch(row.op, params));

      case "vault_unlock":
      case "vault_gate_verify": {
        const value = await this.#dispatch(row.op, params);
        this.session.captureToken(value);
        return this.#authState(value);
      }

      case "vault_recover": {
        // ADR-163 (`commands::vault_recover_at`): the token is captured and stripped; the rest, the new recovery code among it, is returned.
        const value = await this.#dispatch(row.op, params);
        this.session.captureToken(value);
        return value;
      }

      case "agent_token_issue":
      case "agent_token_rotate": {
        // ADR-164 (`commands::hand_agent_token_to_clipboard`): the bearer is taken off the answer and copied as a secret;
        // the page gets the metadata, `copied` and the clock. One that cannot be copied is revoked, never shown.
        const ticket = this.clipboard.ticket();
        const value = await this.#dispatch(row.op, params);
        if (!value || typeof value !== "object" || Array.isArray(value)) throw protocolError("the agent token answer was not an object; nothing was copied");
        const { token, shownOnce: _shownOnce, ...rest } = value;
        if (typeof token !== "string") {
          if (typeof rest.id === "string") await this.#dispatch("agent.token_revoke", { id: rest.id }).catch(() => {});
          throw protocolError("the agent token answer carried no text token; nothing was copied");
        }
        try {
          this.clipboard.copySecretFor(ticket, token);
        } catch {
          const revoked = typeof rest.id === "string" && (await this.#dispatch("agent.token_revoke", { id: rest.id }).then(() => true, () => false));
          return { ...rest, copied: false, revoked };
        }
        return { ...rest, copied: true, clearAfterSeconds: Math.round(this.clipboard.ttlMs / 1000) };
      }

      case "vault_lock": {
        // Taken off the clipboard first, before the broker call and independent of it.
        this.clipboard.clearIfOwned();
        let outcome;
        try {
          outcome = await this.#dispatch(row.op, params);
        } finally {
          // Unconditional, including on the error path: a lock that failed to report may still have locked.
          this.session.clear();
        }
        return { locked: typeof outcome?.locked === "boolean" ? outcome.locked : true, authenticated: false, initialized: typeof outcome?.initialized === "boolean" ? outcome.initialized : true };
      }

      case "entry_copy": {
        const ticket = this.clipboard.ticket();
        // The shell builds this frame itself: `field` goes out as `fieldIds: [field]` (commands.rs `entry_copy_at`; SHELL_COMMANDS.op_params).
        const frame = { node: params.node, entry: params.entry };
        if (params.field !== undefined) frame.fieldIds = [params.field];
        const revealed = await this.#dispatch(row.wrapsOp, frame).catch((error) => {
          throw withoutValue(error);
        });
        const secret = takeRevealedValue(revealed);
        this.clipboard.copySecretFor(ticket, secret);
        return { copied: true, clearAfterSeconds: Math.round(this.clipboard.ttlMs / 1000) };
      }

      case "copy_text": {
        if (Buffer.byteLength(params.text, "utf8") > COPY_TEXT_MAX_BYTES) {
          throw bridgeError("text_too_large", `copy_text takes at most ${COPY_TEXT_MAX_BYTES} bytes of text`);
        }
        this.clipboard.copyPlain(params.text);
        return { copied: true, clearAfterSeconds: null };
      }

      case "app_icon_set": {
        if (!APP_ICON_IDS.includes(params.icon)) throw bridgeError("unknown_icon", `app_icon_set takes one of: ${APP_ICON_IDS.join(", ")}`);
        return { icon: params.icon, dock: false, window: false };
      }

      case "presence_probe":
      case "presence_key_create":
        throw bridgeError("platform_unsupported", "Touch ID needs a Mac with a Secure Enclave and the credmgr-presence helper");

      case "login_agent_status":
      case "login_agent_install":
      case "login_agent_uninstall":
        // ADR-156: start at login is a macOS launchd agent; off a Mac the shell answers this, and so does the shim.
        throw bridgeError("platform_unsupported", "Start at login is not supported on this platform: it uses a macOS launchd user agent");

      case "backup_restore":
        return runRestore(this.socketPath, params);

      case "agent_detect":
        // Local: the shim has no home folder, so it finds no assistant (the shell reads real config files).
        return { binary: "credmgr", binaryFound: false, claudeCodeCommand: "claude mcp add --scope user credmgr -- credmgr mcp", clients: [] };
      case "agent_snippet":
      case "agent_plan":
      case "agent_apply":
      case "agent_prompt":
        throw bridgeError("agent_refused", "the shim has no assistant config files to read or write");

      case "capture_protection_set":
        // Local: the shim has no window to protect; it answers the choice, as the shell does when nothing overrides it.
        return { enabled: params.enabled, applied: true };

      case "window_state":
        // Local: the shim has no window; it answers one that is shown and not minimised, so the page never locks on it.
        return { minimized: false, visible: true };

      case "fields_preview":
        // Local: no broker call, no session, no token, no wire frame (and so nothing for the oracle to see).
        return preview({ text: params.text, fields: params.fields, split: params.split });

      case "env_preview":
        // Local in the shell (crates/core/src/dotenv.rs). Not ported to Node: a journey that reads a .env text goes through the fixture broker.
        throw bridgeError("worker_failed", "env_preview is not ported to the real-broker shim");

      default:
        // whoami, graph_snapshot, entry_list, entry_reveal and every generated command: a pass-through that reshapes nothing.
        return this.#dispatch(row.op, params);
    }
  }
}
