/**
 * Settings and administration (work package D): grants, the audit trail, maintenance, and the two small shell facts the
 * About screen needs (its version and the clipboard for a non-secret address).
 *
 * Four operations are refused by the broker with `presence_required` in this beta (`grantCreate`, `auditGet`, and the
 * human-only `totpSeed` and `nodeReparent`), and so is `maintenanceRotateRoot` after its other checks, and
 * `maintenanceDoctor` with `rebuildRegistry`.  They are called for real and the refusal is shown honestly: the logic class
 * routes it to the presence notice through `routeError`.  Nothing here pretends to have succeeded.
 *
 * A passphrase passed to an action is used for that one call and is never stored by the caller; the caller keeps it out of
 * its state, reads it from the input at the moment of the call, and lets it go out of scope.  It is never logged and never
 * part of an error: the router chooses the words for a refusal by code.
 *
 * What comes back from the broker is shown to a person, so every string that leaves this module for the screen passes through
 * {@link redactTokens} first.  The broker redacts bearer tokens itself (ADR-077); this is the second lock on that door, for
 * a record written by a build that predates the fix or a broker that is not this one.
 */
import * as live from "../../lib/bridge";
import type { AppIconId } from "../../lib/bridge";
import type { VaultModel } from "../model";
import { thenReread, type Written } from "./written";

// ─────────────────────────────── redaction ───────────────────────────────

/** A bearer token is `cmt_` and at least eight hex digits (the same shape `crates/brokerd/src/token.rs` redacts). */
const BEARER = /cmt_[0-9a-fA-F]{8,}/g;
const MAX_TEXT = 300;

/** Replace anything shaped like a session token, and bound the length, so nothing a record carries can flood or leak into the page. */
export function redactTokens(text: string): string {
  const clean = text.replace(BEARER, "[redacted-token]");
  return clean.length > MAX_TEXT ? `${clean.slice(0, MAX_TEXT)}…` : clean;
}

const text = (v: unknown): string | undefined => (typeof v === "string" ? redactTokens(v) : undefined);

/** One audit record, with every string cleaned.  Fields a session is not shown (an agent sees four) stay absent. */
export function scrubRecord(r: live.AuditRecord): live.AuditRecord {
  const out: live.AuditRecord = {
    id: text(r.id) ?? "",
    timestamp: typeof r.timestamp === "number" && Number.isFinite(r.timestamp) ? r.timestamp : 0,
    actor: text(r.actor) ?? "",
    action: text(r.action) ?? "",
  };
  const node = text(r.node);
  if (node !== undefined) out.node = node;
  else if (r.node === null) out.node = null;
  const entry = text(r.entry);
  if (entry !== undefined) out.entry = entry;
  else if (r.entry === null) out.entry = null;
  const decision = text(r.decision);
  if (decision !== undefined) out.decision = decision;
  const detail = text(r.detail);
  if (detail !== undefined) out.detail = detail;
  if (typeof r.generation === "number") out.generation = r.generation;
  return out;
}

type Problem = { node: string | null; detail: string };
const scrubProblem = (p: Problem): Problem => ({ node: typeof p?.node === "string" ? redactTokens(p.node) : null, detail: text(p?.detail) ?? "" });

// ─────────────────────────────── grants ───────────────────────────────

/**
 * Needs presence, which no transport can attest yet, so today the broker answers `presence_required` and nothing changes.
 * On success the grant list is read again (the graph's dashed edges come from it).  `scope` holds only `read`, `reveal`,
 * `notes`; `reason` is at least 8 characters.
 */
export async function createGrant(m: VaultModel, from: string, to: live.GrantTarget, scope: Array<"read" | "reveal" | "notes">, reason: string): Promise<Written<Awaited<ReturnType<typeof live.grantCreate>>>> {
  const r = await live.grantCreate(from, to, scope, reason);
  return thenReread(m, r, { grants: true });
}

/** Revocation is safety, not a lever: it works in both modes.  The grant list (and the graph's edges) are read again. */
export async function revokeGrant(m: VaultModel, id: string): Promise<Written<Awaited<ReturnType<typeof live.grantRevoke>>>> {
  const r = await live.grantRevoke(id);
  return thenReread(m, r, { grants: true });
}

// ─────────────────────────────── audit ───────────────────────────────

/** The newest `limit` audit records (default 50, at most 500), newest first, cleaned for display. */
export async function readAudit(_m: VaultModel, limit?: number): Promise<live.AuditRecord[]> {
  const { records } = await live.auditTail(limit);
  return (Array.isArray(records) ? records : []).map(scrubRecord);
}

/** The full record.  Refused with `presence_required` today. */
export async function getAudit(_m: VaultModel, id: string): Promise<live.AuditRecord> {
  return scrubRecord(await live.auditGet(id));
}

// ─────────────────────────────── maintenance ───────────────────────────────

type Verified = Awaited<ReturnType<typeof live.maintenanceVerify>>;
type Doctored = Awaited<ReturnType<typeof live.maintenanceDoctor>>;

export async function verifyVault(_m: VaultModel): Promise<Verified> {
  const r = await live.maintenanceVerify();
  return { ok: r.ok === true, nodesChecked: typeof r.nodesChecked === "number" ? r.nodesChecked : 0, errors: (r.errors ?? []).map(scrubProblem), warnings: (r.warnings ?? []).map(scrubProblem) };
}

/**
 * A dry run (`apply: false`) first; apply only after the user has read the fixes.  `purgeExpiredSeals` (ADR-089) adds the seals older
 * than seven days to what the doctor looks at: the dry run lists them (`would-purge-expired-seal`), applying removes the retained originals
 * for good (`purged-expired-seal`, with the node's id and when it was sealed).  `rebuildRegistry` needs the passphrase of
 * the latest backup and is refused with `presence_required` today.  A fix that was applied changes what the graph shows, so
 * it is read again.
 */
export async function runDoctor(m: VaultModel, opts: { apply: boolean; rebuildRegistry?: boolean; passphrase?: string; purgeExpiredSeals?: boolean }): Promise<Written<Doctored>> {
  const r = await live.maintenanceDoctor(opts.apply, opts.rebuildRegistry, opts.passphrase, opts.purgeExpiredSeals);
  const done: Doctored = {
    applied: r.applied === true,
    fixCount: typeof r.fixCount === "number" ? r.fixCount : 0,
    fixes: (Array.isArray(r.fixes) ? r.fixes : []).map((f) => ({ node: text(f?.node) ?? null, type: text(f?.type) ?? "fix", ...(typeof f?.sealedAt === "number" && Number.isFinite(f.sealedAt) ? { sealedAt: f.sealedAt } : {}) })),
    unfixable: (r.unfixable ?? []).map(scrubProblem),
  };
  return done.applied && done.fixCount > 0 ? thenReread(m, done, { graph: true }) : done;
}

/** `passphrase` encrypts the archive and is needed to open it again; it is not stored anywhere. */
export async function backupVault(_m: VaultModel, passphrase: string, retain?: number): Promise<{ path: string; retain: number; pruned: number }> {
  const r = await live.maintenanceBackup(passphrase, retain);
  return { path: text(r.path) ?? "", retain: r.retain, pruned: r.pruned.length };
}

/**
 * Returns the NEW root recovery code once: show it, make the user save it, and let it go out of scope.  `passphrase` is the
 * vault passphrase again.  Do NOT read the model after this: a rotation whose last step is still pending locks the vault, and
 * a read would send the user to the lock screen before they have seen the code.
 */
export async function rotateRootKey(_m: VaultModel, passphrase: string): Promise<live.RotateRootResult> {
  return live.maintenanceRotateRoot(passphrase);
}

// ─────────────────────────────── the shell ───────────────────────────────

const inShell = (): boolean => typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

/**
 * Put a NON-SECRET string on the clipboard (a donation address) through the shell's `copyText` (no concealment, no timer; at
 * most 4096 bytes).  THE PAGE NEVER WRITES TO THE CLIPBOARD ITSELF: not for this, and certainly not for a secret (those go through
 * the shell's `entryCopy`, so the value never enters the webview).  With no shell there is nothing to copy with and this
 * rejects, and so does a refusal from the shell, so a caller can say "copy failed" instead of "copied".
 * (tests/unit/architecture.test.ts fails if `navigator.clipboard` appears anywhere in `src/`.)
 */
export async function copyPlainText(value: string): Promise<void> {
  if (!inShell()) throw new Error("copying needs the CredMgr app: there is no shell to write the clipboard with");
  await live.copyText(value);
}

/**
 * Set the OS icon (Dock on macOS, window or taskbar elsewhere) to one of the six marks, through the shell's `appIconSet`.
 * Best effort: with no shell, or if the shell refuses, nothing changes and nothing is thrown (an icon is cosmetic and must
 * never block an unlock). Resolves `true` only when the shell reports a surface it changed.
 */
export async function setAppIcon(id: string): Promise<boolean> {
  if (!inShell()) return false;
  try {
    const r = await live.appIconSet(id as AppIconId);
    return !!(r && (r.dock || r.window));
  } catch {
    return false;
  }
}

/**
 * Hide the window from screen capture and screen sharing (`true`) or show it to them (`false`), through the shell's
 * `captureProtectionSet`.  With no shell (the browser preview, a test build) there is no window to protect: resolves `null`.
 * A refusal from the shell REJECTS, unlike the icon, because a caller that just turned protection ON must be able to say it
 * did not take.  The answer is the shell's receipt: `enabled` is what the window is now (the developer environment override
 * can keep it off), `applied` is whether the OS accepted.
 */
export async function setCaptureProtection(enabled: boolean): Promise<live.CaptureReceipt | null> {
  if (!inShell()) return null;
  return live.captureProtectionSet(enabled);
}

/** The app's own version, from the shell (`tauri.conf.json`), or `null` when there is no shell to ask. */
export async function appVersion(): Promise<string | null> {
  if (!inShell()) return null;
  try {
    const v = await live.getVersion();
    return typeof v === "string" && v.length > 0 && v.length <= 40 ? v : null;
  } catch {
    return null;
  }
}
