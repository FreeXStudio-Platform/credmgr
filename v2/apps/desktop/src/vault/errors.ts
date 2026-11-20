/**
 * Error routing (spec B2): what the UI does with a rejection from the bridge.
 *
 * THE RULE: every error from a bridge call goes through {@link routeError}.  Nothing is swallowed, and nothing is shown
 * with text taken from the error itself except the broker's own `rule`/retry hints, which are not secrets: the message
 * a user sees is chosen HERE, by code.  (An unexpected code shows as `unexpected error (code)`, never its message.)
 *
 * routeError is split in two so each half is easy to test:
 *   - {@link classifyError} is pure: an error and its context in, a route out;
 *   - {@link routeError} runs the route against a {@link RouteHost} (the logic class supplies one).
 *
 * The notice API the screens use is `this.notify(kind, text)` on the logic class (logic/notice.js); {@link NoticeKind}
 * is its first argument.
 */
import { isBridgeError } from "../lib/bridge";

export type NoticeKind = "info" | "success" | "warn" | "error" | "presence";

/** What the caller knows about the operation that failed.  None of it is required. */
export interface ErrorContext {
  /** The broker operation, e.g. `entry.reveal`; shown in the presence notice. */
  op?: string;
  node?: string;
  entry?: string;
  /** The form field that sent the request (`passphrase`, `code`, `name`, ...); an inline error goes there. */
  field?: string;
  /** Set by a screen that renders the inline error itself, so no notice is raised on top of it. */
  inlineRendered?: boolean;
  /**
   * The broker had already done what was asked and only a later step failed (the re-read): the generic notice must not say
   * "Nothing was changed".  A string is the sentence that says what was saved ("Saved 1 entry to atlas."); `true` is the plain case.
   */
  changed?: boolean | string;
}

export type ErrorRoute =
  /** The login is gone (vault locked, session expired): clear everything and show the Lock screen. */
  | { route: "lock"; code: string }
  /** The vault is open but this node is locked: show the per-node locked panel. */
  | { route: "node-locked"; node: string | null }
  /** A second factor is needed: ask for the 6-digit code, verify it, retry the original call once. */
  | { route: "two-factor" }
  /** The operation needs Touch ID, which is not set up (or the prompt was not answered).  Nothing was changed. */
  | { route: "presence"; op: string | null; message: string }
  /** The broker cannot be reached. */
  | { route: "broker-down" }
  /** A problem with one input: show it next to the field.  `retryAfterSeconds` is set only for `rate_limited`. */
  | { route: "inline"; field: string | null; message: string; retryAfterSeconds?: number }
  /** Something changed underneath the user: reload these nodes (and the graph) and say so. */
  | { route: "refresh"; nodes: string[]; message: string }
  /** Anything else the user must be told. */
  | { route: "notice"; kind: NoticeKind; message: string }
  /** First-run only: the vault already exists, so the right screen is the Lock screen. */
  | { route: "already-initialized"; message: string };

/** The code of a rejection, or `null` if it is not a {@link import("../lib/bridge").BridgeError}. */
export function errorCode(e: unknown): string | null {
  return isBridgeError(e) ? String(e.code) : null;
}

/** Codes that mean "this process no longer holds a login". */
const SESSION_ENDED = new Set(["vault_locked", "session_expired"]);

export function isSessionEnded(e: unknown): boolean {
  const c = errorCode(e);
  return c !== null && SESSION_ENDED.has(c);
}

/** Raised by a stub that no wiring package has implemented yet.  It is a bug to ship it, so it is loud, not silent. */
export class NotWiredError extends Error {
  readonly code = "not_wired";
  constructor(readonly op: string) {
    super(`${op} is not wired to the broker yet`);
    this.name = "NotWiredError";
  }
}

const num = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);
const str = (v: unknown): string | null => (typeof v === "string" && v.length > 0 && v.length <= 200 ? v : null);

/** The broker's rule/remedy hints, bounded and string-only, for the "not permitted" line. */
function ruleOf(detail: Record<string, unknown> | undefined): string {
  const rule = str(detail?.rule);
  return rule ? ` (${rule})` : "";
}

/** "30 s", "12 min", "2 h": how long the broker asked the user to wait, rounded UP so the button never re-enables early. */
export function waitText(seconds: number): string {
  if (seconds < 120) return `${Math.max(1, Math.ceil(seconds))} s`;
  if (seconds < 7200) return `${Math.ceil(seconds / 60)} min`;
  return `${Math.ceil(seconds / 3600)} h`;
}

/**
 * What the Lock screen says about WHY it appeared, by the code that ended the login.  Chosen here, never taken from an
 * error's message.  `""` (the user's own Lock) says nothing.
 */
export function lockNoteFor(code: string | null): string {
  if (code === "session_expired") return "Your session ended. Unlock to continue.";
  if (code === "vault_locked") return "The vault was locked. Unlock to continue.";
  if (code === null || code === "") return "";
  return "The vault was locked.";
}

export const PRESENCE_TEXT = "Needs Touch ID. Set it up in Settings, Security, then try again. Nothing was changed.";

/**
 * What the user is told when this window locked but the broker did not confirm that the vault locked.  Chosen by code, like
 * every other message here; the error's own message is never shown.
 */
export function lockUnconfirmedText(code: string | null): string {
  if (code === "broker_unreachable") {
    return "This window is locked, but the broker could not be reached, so it was not told to lock the vault. The vault may stay open until the broker locks itself.";
  }
  return `This window is locked, but the broker did not confirm that the vault locked${code ? ` (${code})` : ""}. If you are unsure, lock it from the command line.`;
}

/**
 * What a failure AFTER a successful write says: that the write happened, and that only the screen is out of date.  `saved` is the
 * caller's sentence for what was saved (`true` when it has none).  Chosen by code; the error's own message is never shown.
 */
function afterWrite(saved: true | string, code: string | null): string {
  const what = saved === true ? "The change itself was saved." : saved.trim();
  return `${what} The screen could not be refreshed${code ? ` (${code})` : ""}; reload to see it.`;
}

/**
 * What `malformed_request` means for the operations on an entry's fields (ADR-078) and for a step-up with no gate (B-11), where it is something the user can act on rather
 * than a bug.  The message is chosen here; the broker's own text (which names an index or an id) is never shown.  `null`: not one of those.
 */
function malformedFieldRoute(ctx: ErrorContext): ErrorRoute | null {
  switch (ctx.op) {
    case "field.remove":
      return { route: "notice", kind: "warn", message: "An entry keeps at least one field. Remove the entry instead. Nothing was changed." };
    case "field.add":
    case "field.update":
      return { route: "inline", field: ctx.field ?? null, message: "The broker did not accept that field. A label is one line of at most 200 characters. Nothing was changed." };
    case "vault.recover":
      // ADR-163: the broker answers malformed_request to a recovery on a vault that is already open.
      return { route: "inline", field: ctx.field ?? "forgot", message: "The vault is already unlocked. Change the passphrase in Settings instead. Nothing was changed." };
    case "keystore.bind":
      // ADR-165: the broker refuses a bind with no recovery code (the way back on a new Mac), a device key inside the vault folder, or
      // (review P0-1) while a project is locked or something waits in the tray or the sealed entries, since every key is replaced, or
      // (review M4) while a bind another login prepared is waiting.
      return { route: "notice", kind: "warn", message: "The machine lock could not be turned on: it needs a recovery code set up first (change the passphrase once), every project unlocked with nothing waiting in the tray or the sealed entries, and the device key outside the vault folder; or a bind is already waiting in another CredMgr window or terminal (finish or close it there). Nothing was changed." };
    case "keystore.bind_commit":
      // Review N1: the commit found no prepared bind (the vault was locked, the app restarted, ten minutes passed) or one made under a root key
      // that has since changed, or (review M4) one another login prepared. Nothing was changed: the recovery code typed in the first step still works.
      return { route: "notice", kind: "warn", message: "The machine lock was not turned on: the step that showed the new recovery code ran out or was overtaken (a lock, a restart, ten minutes, or a passphrase change in between), or a bind started in another CredMgr window or terminal is the one waiting. Nothing was changed, and your current recovery code still works. Turn the lock on again." };
    case "keystore.unbind":
      // Review P2-4: with neither Touch ID nor a second factor set up, turning the lock off asks for the vault passphrase.
      return { route: "notice", kind: "warn", message: "Turning the machine lock off needs the vault passphrase here, because neither Touch ID nor a second factor is set up. Type it in the dialog. Nothing was changed." };
    case "vault.gate_verify":
      // B-11: a step-up with no gate enrolled is not a failed login (the broker does not count it): there is nothing to give.
      return { route: "notice", kind: "info", message: "No second factor is enrolled, so there is nothing to give. A node that asks for one is not asking anyone yet." };
    case "field.reorder":
      // The order named an id the entry no longer holds, or left one out: the entry changed under the screen.  The screen reloads it.
      return { route: "refresh", nodes: ctx.node ? [ctx.node] : [], message: "The fields could not be reordered because the entry changed. Reloaded; try again." };
    default:
      return null;
  }
}

export function classifyError(e: unknown, ctx: ErrorContext = {}): ErrorRoute {
  if (e instanceof NotWiredError) {
    return { route: "notice", kind: "info", message: "This is not available in this build yet." };
  }
  if (!isBridgeError(e)) {
    // A programming error (a TypeError in a handler, say).  Its message can quote data, so it is not shown.
    return { route: "notice", kind: "error", message: ctx.changed ? afterWrite(ctx.changed, null) : "Unexpected error. Nothing was changed." };
  }
  const code = String(e.code);
  const detail = e.detail;
  switch (code) {
    case "vault_locked":
    case "session_expired":
      return { route: "lock", code };
    case "node_locked":
      return { route: "node-locked", node: str(detail?.node) ?? ctx.node ?? null };
    case "two_factor_required":
      return { route: "two-factor" };
    case "presence_required":
    case "presence_not_enrolled":
      return { route: "presence", op: ctx.op ?? null, message: PRESENCE_TEXT };
    // ADR-098: Touch ID.  A dismissed prompt is not a failure, and nothing here quotes the broker or the helper.
    // ADR-150: "Confirm before showing secrets" is on.  The bridge already asked once (src/lib/bridge.ts); this is what is left:
    // the person cancelled (quiet: nothing was shown, nothing is wrong), or a second request needed its own confirmation.
    case "confirmation_required":
      return detail?.cancelled === true
        ? { route: "notice", kind: "info", message: ctx.op === "node.policy" || ctx.op === "settings.request_decide" ? "Not confirmed. The setting was not changed." : "Not confirmed. Nothing was shown." }
        : { route: "notice", kind: "info", message: "Confirm it is you (Touch ID or your passphrase) to show this, then try again." };
    case "presence_cancelled":
      return { route: "notice", kind: "info", message: "Touch ID was cancelled. Nothing was changed." };
    case "presence_locked_out":
      return { route: "notice", kind: "warn", message: "Touch ID is locked out. Unlock the Mac with its password, then try again. Nothing was changed." };
    case "presence_unavailable":
      return { route: "notice", kind: "warn", message: "This Mac cannot do Touch ID here (no Secure Enclave, or the helper is missing). Nothing was changed." };
    case "presence_error":
      return { route: "notice", kind: "error", message: "Touch ID could not be checked. Nothing was changed." };
    case "presence_failed": {
      const reason = str(detail?.reason);
      const text =
        reason === "not_enrolled"
          ? PRESENCE_TEXT
          : reason === "cancelled"
            ? "Touch ID was cancelled. Nothing was changed."
            : reason === "locked_out"
              ? "Touch ID is locked out. Unlock the Mac with its password, then try again. Nothing was changed."
              : reason === "expired"
                ? "The Touch ID check ran out or was already used. Try again. Nothing was changed."
                : "The Touch ID check did not verify. Nothing was changed.";
      return { route: reason === "not_enrolled" ? "presence" : "notice", ...(reason === "not_enrolled" ? { op: ctx.op ?? null, message: text } : { kind: "warn" as const, message: text }) } as ErrorRoute;
    }
    case "approval_pending":
      return { route: "notice", kind: "info", message: "Waiting for approval." };
    case "approval_denied":
      return { route: "notice", kind: "warn", message: "The request was denied." };
    case "conflict":
      return { route: "refresh", nodes: ctx.node ? [ctx.node] : [], message: "Changed elsewhere. Reloaded; try again." };
    case "wrong_passphrase":
      // ADR-165: the machine-lock dialog has closed by the time the broker answers, so the words go in a notice.
      if (ctx.op === "keystore.bind" || ctx.op === "keystore.unbind") return { route: "notice", kind: "warn", message: "Wrong passphrase. Nothing was changed." };
      // The last-door op (vault.gate_recover) never says which of its two factors failed, so neither does the message.
      if (ctx.op === "vault.gate_recover") return { route: "inline", field: ctx.field ?? "recovery", message: "The passphrase or the recovery code is wrong." };
      return { route: "inline", field: ctx.field ?? "passphrase", message: "Wrong passphrase." };
    case "gate_verification_failed":
      return { route: "inline", field: ctx.field ?? "code", message: "That code was not accepted." };
    case "machine_lock_refused":
      // ADR-165 review N6: a backup of an open, machine-locked vault whose device key went away since it was opened. Nothing was written.
      if (str(detail?.reason) === "backup_needs_device_key") return { route: "notice", kind: "warn", message: "The backup was not written: this Mac's device key went away (or changed) after the vault was opened, so the archive could not include a passphrase file that opens it. Put the key file back (machine/lock.key in CredMgr's state folder) and back up again, or lock the vault, open it with your recovery code (that makes a new key and a new recovery code) and then back up." };
      // ADR-165: the passphrase wrap is sealed to a device key this Mac does not hold (or it is damaged). The passphrase was never
      // tried, so this says nothing about it; the way in is the recovery code, which also seals the vault to this Mac again.
      return {
        route: "inline",
        field: ctx.field ?? "passphrase",
        message:
          str(detail?.reason) === "sealed_wrap_damaged"
            ? "The machine-locked passphrase file is damaged. Use \"Forgot passphrase? Use recovery code\" to open the vault. Nothing was changed."
            : str(detail?.reason) === "plain_wrap_while_bound"
            ? "This Mac recorded the vault as locked to it, but the passphrase file on disk is an older, unlocked one, and it does not open this vault. Use \"Forgot passphrase? Use recovery code\" to open it; that seals it again. Nothing was changed."
            : "This vault is locked to a Mac, and this Mac does not hold its device key (a new Mac, or the key file was lost). Use \"Forgot passphrase? Use recovery code\" to open it here. Nothing was changed.",
      };
    case "recovery_code_mismatch":
      // ADR-163: on the "Forgot passphrase?" step the code was not this vault's (or not a recovery code at all). It counts in the back-off.
      if (ctx.op === "vault.recover") return { route: "inline", field: ctx.field ?? "forgot", message: "That recovery code does not open this vault. Nothing was changed." };
      // ADR-165 review P1-1: bind proves the CURRENT code (a new one is issued at every passphrase change, rotation and bind).
      if (ctx.op === "keystore.bind") return { route: "notice", kind: "warn", message: "That is not the current recovery code. A new code is issued every time the passphrase is changed, the root key is rotated or the lock is turned on. Nothing was changed." };
      // Review N1: the code typed back is not the new one the first step showed (the dialog keeps it open; this is the fallback).
      if (ctx.op === "keystore.bind_commit") return { route: "notice", kind: "warn", message: "That is not the new recovery code that was shown. Nothing was changed." };
      return { route: "inline", field: ctx.field ?? "recoveryCode", message: "The recovery code does not match." };
    case "rate_limited": {
      const secs = num(detail?.retryAfterSeconds); // the broker's key (protocol.rs `rate_limited`)
      if (secs === null) return { route: "inline", field: ctx.field ?? null, message: "Too many attempts. Try again shortly." };
      return { route: "inline", field: ctx.field ?? null, message: `Too many attempts. Try again in ${waitText(secs)}.`, retryAfterSeconds: Math.min(Math.max(secs, 0), 86_400) };
    }
    case "node_access_denied":
    case "capability_not_held":
      return { route: "inline", field: ctx.field ?? null, message: `Not permitted${ruleOf(detail)}.` };
    case "entry_exists":
      // ADR-121: an alias lives in the same name space as a name, so a taken alias is taken as either.
      if (ctx.op === "entry.alias") return { route: "inline", field: ctx.field ?? "aliases", message: "One of those names is already taken in this node, as an entry name or as an alias. Nothing was changed." };
      if (ctx.op === "entry.import_env") return { route: "notice", kind: "warn", message: "A name in that file is already taken in this node. Nothing was imported." };
      return { route: "inline", field: ctx.field ?? "name", message: "An entry with that name already exists in this node." };
    case "not_found":
    case "archive_expired":
    case "entry_removal_expired":
    case "not_undoable":
      // ADR-163: the vault has no recovery wrap yet (made before they existed). Not something to reload: say when it appears.
      if (code === "not_found" && ctx.op === "vault.recover") return { route: "inline", field: ctx.field ?? "forgot", message: "This vault cannot be opened with its recovery code yet. That is set up the next time the passphrase is changed. Nothing was changed." };
      return { route: "refresh", nodes: ctx.node ? [ctx.node] : [], message: code === "not_found" ? "That no longer exists. Reloaded." : "That can no longer be undone. Reloaded." };
    case "vault_already_initialized":
      return { route: "already-initialized", message: "A vault already exists. Unlock it instead." };
    case "vault_init_not_pending":
      return { route: "inline", field: null, message: "No vault creation is in progress. Start again." };
    case "vault_inside_git_working_tree":
      return { route: "inline", field: null, message: "The vault folder is inside a git working tree. Choose another location." };
    case "gate_not_enrolling":
      return { route: "notice", kind: "warn", message: "No two-factor enrolment is in progress. Start again." };
    case "broker_unreachable":
      return { route: "broker-down" };
    // The shell's own codes (entryCopy, copyText): the clipboard is the shell's, not the broker's, and nothing in the vault changed.
    case "clipboard_failed":
      return { route: "notice", kind: "error", message: "The clipboard could not be written. Nothing was copied." };
    case "text_too_large":
      return { route: "notice", kind: "error", message: "That is too long to copy." };
    case "field_required":
      return { route: "notice", kind: "warn", message: "This entry has several fields: choose the one to copy. Nothing was copied." };
    case "unknown_icon":
    case "icon_failed":
      return { route: "notice", kind: "warn", message: "The app icon could not be changed." };
    case "invalid_fields":
      return { route: "notice", kind: "warn", message: "That paste could not be previewed. Nothing was changed." };
    // ADR-166, Restore from a backup: the bundled `credmgr restore --json`'s codes.  Said next to the form, in words chosen here.
    case "broker_running":
      return { route: "inline", field: ctx.field ?? "restore", message: "CredMgr's broker is running, and a restore never runs beside it. Quit CredMgr (and turn off Start at login, or stop credmgrd, if it keeps the broker running), then restore in a terminal: credmgr restore <archive> --to <an empty folder>. Nothing was read or written." };
    case "restore_target_not_empty":
      return { route: "inline", field: ctx.field ?? "restore", message: "That folder is not empty: a restore never merges into, or overwrites, a vault. Choose an empty or new folder. Nothing was written." };
    case "restore_failed":
      return { route: "inline", field: ctx.field ?? "restore", message: "The backup could not be restored: the backup passphrase is wrong, or the file is damaged or cannot be read. Nothing was written." };
    case "restore_unavailable":
      return { route: "inline", field: ctx.field ?? "restore", message: "The credmgr command-line program was not found beside the app or where it is installed. Install it, then restore in a terminal with credmgr restore. Nothing was run." };
    case "invalid_env": {
      // The shell's message names a line NUMBER and never the line; only the digits are taken from it, the rest is chosen here.
      const at = /^line (\d{1,7})\b/.exec(typeof e.message === "string" ? e.message : "");
      return { route: "inline", field: ctx.field ?? "env", message: `That is not a valid .env file${at ? ` (line ${at[1]})` : ""}. Nothing was imported.` };
    }
    case "malformed_request": {
      const field = malformedFieldRoute(ctx);
      if (field) return field;
      return { route: "notice", kind: "error", message: ctx.changed ? afterWrite(ctx.changed, code) : `Unexpected error (${code}). Nothing was changed.` };
    }
    default:
      // malformed_request, internal, malformed_response, worker_failed, encode_failed, platform_unsupported, and any code
      // this build does not know: a bug or a version mismatch.  The code is shown; the message is not.
      return { route: "notice", kind: "error", message: ctx.changed ? afterWrite(ctx.changed, code) : `Unexpected error (${code}). Nothing was changed.` };
  }
}

/** What the logic class provides so a route can be carried out.  Every method is called at most once per error. */
export interface RouteHost {
  notify(kind: NoticeKind, text: string): void;
  /** Clear everything the session held (names, notes, plaintext) and show the Lock screen. */
  lock(code: string): void;
  nodeLocked(node: string | null): void;
  promptTwoFactor(ctx: ErrorContext): void;
  brokerDown(): void;
  /** `field === null` means the error is not tied to one input.  `retry.afterSeconds` is set for `rate_limited` only. */
  inline(field: string | null, message: string, ctx: ErrorContext, retry?: { afterSeconds: number }): void;
  /** `ctx` is the failed call's, so a screen can also re-read the one entry it was working on. */
  refresh(nodes: string[], ctx?: ErrorContext): void;
  alreadyInitialized(): void;
}

/** Carry out the route for `e` on `host` and return it (the caller may want to branch on it, e.g. retry after 2FA). */
export function routeError(e: unknown, ctx: ErrorContext, host: RouteHost): ErrorRoute {
  const r = classifyError(e, ctx);
  switch (r.route) {
    case "lock":
      host.lock(r.code);
      break;
    case "node-locked":
      host.nodeLocked(r.node);
      break;
    case "two-factor":
      host.promptTwoFactor(ctx);
      break;
    case "presence":
      host.notify("presence", r.op ? `${r.message} (${r.op})` : r.message);
      break;
    case "broker-down":
      host.brokerDown();
      break;
    case "inline":
      host.inline(r.field, r.message, ctx, r.retryAfterSeconds === undefined ? undefined : { afterSeconds: r.retryAfterSeconds });
      // Never swallowed: until a screen renders the field error itself it is also raised as a notice.
      if (!ctx.inlineRendered) host.notify("error", r.message);
      break;
    case "refresh":
      host.refresh(r.nodes, ctx);
      host.notify("warn", r.message);
      break;
    case "already-initialized":
      host.alreadyInitialized();
      host.notify("info", r.message);
      break;
    case "notice":
      host.notify(r.kind, r.message);
      break;
  }
  return r;
}
