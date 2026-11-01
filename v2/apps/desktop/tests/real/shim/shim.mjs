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
import { bridgeError, protocolError } from "./bridge-error.mjs";
import { preview } from "./preview.mjs";
import { Session } from "./session.mjs";
import { APP_ICON_IDS, BY_COMMAND, CLIPBOARD_CLEAR_AFTER_SECONDS, COPY_TEXT_MAX_BYTES } from "./table.mjs";
import { callAudited as transportCall } from "./transport.mjs";

/**
 * `commands::AUDIT_PASSTHROUGH`: the ops whose answer carries the id of the audit record the change wrote (ADR-091). Held to the Rust list by
 * tests/unit/adr090-091.test.ts and to the broker's ops by the drift guard.
 */
export const AUDIT_PASSTHROUGH = new Set([
  "entry.create", "entry.create_batch", "entry.update", "entry.rotate", "entry.remove", "entry.restore", "entry.undo",
  "field.add", "field.update", "field.remove", "field.reorder", "notes.write",
  "node.create", "node.update", "node.policy", "node.set_workdirs", "node.reparent", "node.seal", "node.restore",
  "grant.create", "grant.revoke", "vault.pending_accept", "vault.pending_discard", "vault.approval_decide",
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

      case "capture_protection_set":
        // Local: the shim has no window to protect; it answers the choice, as the shell does when nothing overrides it.
        return { enabled: params.enabled, applied: true };

      case "fields_preview":
        // Local: no broker call, no session, no token, no wire frame (and so nothing for the oracle to see).
        return preview({ text: params.text, fields: params.fields, split: params.split });

      default:
        // whoami, graph_snapshot, entry_list, entry_reveal and every generated command: a pass-through that reshapes nothing.
        return this.#dispatch(row.op, params);
    }
  }
}
