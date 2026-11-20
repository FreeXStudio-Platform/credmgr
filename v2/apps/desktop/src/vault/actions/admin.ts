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

/** A bearer token is `cmt_` (a login) or `cma_` (an agent token, ADR-164) and at least eight hex digits (the shapes
 *  `crates/brokerd/src/token.rs` redacts). */
const BEARER = /cm[ta]_[0-9a-fA-F]{8,}/g;
const MAX_TEXT = 300;

/** Replace anything shaped like a session token, and bound the length, so nothing a record carries can flood or leak into the page. */
export function redactTokens(text: string, max: number = MAX_TEXT): string {
  const clean = text.replace(BEARER, "[redacted-token]");
  return clean.length > max ? `${clean.slice(0, max)}…` : clean;
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

// ─────────────────────────────── agent tokens (ADR-164) ───────────────────────────────
// The owner's login only.  Issue and rotate never hand the page the secret: the shell puts it on the concealed clipboard
// (cleared after 30 seconds and at lock) and answers `copied` with the metadata, as the login never reaches the page
// (ADR-057).

/** The live agent tokens, metadata only. */
export function agentTokens(node?: string) {
  return live.agentTokenStatus(node);
}
/** Issue a token for one node.  The shell asks for Touch ID; the broker refuses an agent. */
export function issueAgentToken(node: string, label: string, capabilities: live.AgentTokenCapability[], expiresIn?: number) {
  return live.agentTokenIssue(node, label, capabilities, expiresIn);
}
/** A new secret for a token; the old one stops working. */
export function rotateAgentToken(id: string, expiresIn?: number) {
  return live.agentTokenRotate(id, expiresIn);
}
/** End a token now. */
export function revokeAgentToken(id: string) {
  return live.agentTokenRevoke(id);
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
export async function backupVault(_m: VaultModel, passphrase: string, retain?: number): Promise<{ path: string; retain: number; pruned: number; outsideVaultFolder: boolean }> {
  const r = await live.maintenanceBackup(passphrase, retain);
  return { path: text(r.path) ?? "", retain: r.retain, pruned: r.pruned.length, outsideVaultFolder: r.outsideVaultFolder === true };
}

/**
 * Restores a backup archive into an empty folder (ADR-166): the shell runs the bundled `credmgr restore --json`, so the refusals are the
 * command line's (`broker_running` while a broker answers on the vault's socket, `restore_target_not_empty`, `restore_failed`,
 * `restore_unavailable`).  It talks to no broker and touches no view: there is nothing to re-read, and the vault this window shows is not the
 * one written.  `passphrase` is the BACKUP's, sent once and not kept.
 */
export async function restoreBackup(archive: string, passphrase: string, target?: string): Promise<live.RestoreDone> {
  const r = await live.backupRestore(archive, passphrase, target);
  return {
    target: text(r.target) ?? "",
    stateDir: text(r.stateDir) ?? "",
    files: typeof r.files === "number" ? r.files : 0,
    bytes: typeof r.bytes === "number" ? r.bytes : 0,
    counter: text(r.counter) ?? "",
    complete: r.complete === true,
  };
}

/**
 * Returns the NEW root recovery code once: show it, make the user save it, and let it go out of scope.  `passphrase` is the
 * vault passphrase again.  Do NOT read the model after this: a rotation whose last step is still pending locks the vault, and
 * a read would send the user to the lock screen before they have seen the code.
 */
export async function rotateRootKey(_m: VaultModel, passphrase: string): Promise<live.RotateRootResult> {
  return live.maintenanceRotateRoot(passphrase);
}

/**
 * ADR-156: change the vault passphrase.  `passphrase` is the current one, `newPassphrase` the one that protects the root key from
 * now on.  It is a root rotation, so the answer carries a NEW recovery code exactly as {@link rotateRootKey} does: show it once,
 * make the user save it, let it go out of scope.  Both passphrases are used for this one call and never kept.  Do NOT read the
 * model after this, for the same reason as a rotation.
 */
export async function changePassphrase(_m: VaultModel, passphrase: string, newPassphrase: string): Promise<live.SetPassphraseResult> {
  return live.vaultSetPassphrase(passphrase, newPassphrase);
}

/** ADR-156: the owner has seen the cross-node anomaly alarm.  Resets the broker's count, and the model's, so the notice goes. */
export async function acknowledgeAnomalies(m: VaultModel): Promise<number> {
  const r = await live.vaultAnomaliesAck();
  m.setAnomaliesUnseen(0);
  return r.acknowledged;
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

// ─────────────────────────────── agents (ADR-143) ───────────────────────────────
// Local to the shell; nothing here reaches the broker, and nothing is a secret.  With no shell each resolves `null`.

/** Which assistants are on this Mac and whether CredMgr is wired into each.  Reads files, writes none. */
export async function agentDetect(): Promise<live.AgentDetect | null> {
  return inShell() ? live.agentDetect() : null;
}
/** The configuration to copy for a client (`generic` for any other). */
export async function agentSnippet(client: string) {
  return inShell() ? live.agentSnippet(client) : null;
}
/** The change a connect or disconnect would make: the file, a diff, a token.  Writes nothing. */
export async function agentPlan(client: string, action: "connect" | "disconnect") {
  return inShell() ? live.agentPlan(client, action) : null;
}
/** Write the planned change.  Called from the dialog's Write button only. */
export async function agentApply(client: string, action: "connect" | "disconnect", token: string) {
  if (!inShell()) throw new Error("writing needs the CredMgr app");
  return live.agentApply(client, action, token);
}
/** The Vault Protocol prompt, or the text of CREDMGR.md, for a node: names and structure only. */
export async function agentPrompt(node: string, reachable: string[], level: live.SecurityLevel, format: "prompt" | "md") {
  return inShell() ? live.agentPrompt(node, reachable, level, format) : null;
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

/**
 * Whether the window was put away (minimised, or hidden with the app) rather than merely out of sight (covered by another window,
 * or on a display that went dark). `null` with no shell (the browser preview, a test build): the caller then treats a hidden page
 * as put away, as before. A shell that cannot answer resolves `null` too.
 */
export async function windowPutAway(): Promise<boolean | null> {
  if (!inShell()) return null;
  try {
    const s = await live.windowState();
    return s.minimized || !s.visible;
  } catch {
    return null;
  }
}

// ─────────────────────────────── Touch ID (ADR-098) ─────────────────────

/** What this Mac can do and what is set up, or `null` when there is no shell to ask. */
export async function touchIdState(): Promise<{ probe: live.PresenceProbe; status: live.PresenceStatus } | null> {
  if (!inShell()) return null;
  const [probe, status] = await Promise.all([live.presenceProbe(), live.presenceStatus()]);
  return { probe, status };
}

/**
 * Turn Touch ID on for this vault: create this Mac's Secure Enclave key (no prompt), enrol its public half, and turn on
 * unlocking with it.  Needs the vault open and, when a second factor is on, a fresh code (the router asks for it).  Each
 * step that already holds is skipped, so running it again finishes what a refused attempt left.
 */
export async function touchIdSetUp(): Promise<void> {
  const { probe, status } = (await touchIdState()) ?? {};
  if (!probe || !status) return;
  if (status.enrolled.length === 0 || !probe.keyOnThisMac) {
    const publicKey = await live.presenceKeyCreate();
    await live.presenceEnrol(publicKey, "This Mac");
  }
  if (!status.touchIdUnlock) await live.deviceEnrol();
}

/** Turn Touch ID off: stop unlocking with it and forget this Mac's presence key (each needs a Touch ID check). */
export async function touchIdTurnOff(): Promise<void> {
  const state = await touchIdState();
  if (!state) return;
  if (state.status.touchIdUnlock) await live.deviceRemove();
  for (const key of state.status.enrolled) await live.presenceUnenrol(key.id);
}

// ─────────────────────────────── start at login (ADR-156) ──────────────

export type LoginAgentStatus = live.LoginAgentStatus;

/**
 * Whether the launch agent that starts the broker at login is in place, or `null` when there is no shell to ask or this platform
 * has no launchd (`platform_unsupported`): the screens then offer nothing.  Any other refusal is thrown.
 */
export async function loginAgentState(): Promise<LoginAgentStatus | null> {
  if (!inShell()) return null;
  try {
    return await live.loginAgentStatus();
  } catch (e) {
    if (live.isBridgeError(e) && e.code === "platform_unsupported") return null;
    throw e;
  }
}

/** Write and load the launch agent (starts the broker now and at every login).  Idempotent. */
export async function loginAgentTurnOn(): Promise<LoginAgentStatus> {
  return live.loginAgentInstall();
}

/** Unload the launch agent (stops the broker it started, which locks the vault) and remove it.  Idempotent. */
export async function loginAgentTurnOff(): Promise<LoginAgentStatus> {
  return live.loginAgentUninstall();
}

// ─────────────────────────────── machine lock (ADR-165) ──────────────

export type MachineLockStatus = live.KeystoreStatus;

/**
 * Whether the passphrase file is sealed to this Mac, or `null` when there is no shell to ask.  The broker's own `protects` /
 * `doesNotProtect` sentences pass through {@link redactTokens} like every other string shown from it.
 */
export async function machineLockState(): Promise<MachineLockStatus | null> {
  if (!inShell()) return null;
  return cleanMachineLock(await live.keystoreStatus());
}

/**
 * Turning the machine lock on, step one (review N1).  The vault passphrase and the CURRENT recovery code both prove it is the owner
 * (review P1-1); nothing changes yet.  The answer carries the NEW recovery code the bind will make the only one that works: show it,
 * have the person type it back ({@link machineLockConfirm}), and let it go out of scope.  Both typed values are used for this one call
 * and never kept.  An already-bound vault answers `already: true` and no code.
 */
export async function machineLockPrepare(passphrase: string, recoveryCode: string): Promise<live.KeystorePrepared> {
  return cleanMachineLock(await live.keystoreBindPrepare(passphrase, recoveryCode.trim()));
}

/**
 * Step two: the new code typed back (nothing for an already-bound vault).  Only now is the root key replaced, every project re-keyed and
 * the passphrase file sealed to this Mac (the broker makes the device key on first use).
 */
export async function machineLockConfirm(newRecoveryCode?: string): Promise<live.KeystoreChange> {
  return cleanMachineLock(await live.keystoreBindCommit(newRecoveryCode ? newRecoveryCode.trim() : undefined));
}

/** The dialog closed between the steps: the broker forgets the prepared bind.  Nothing had changed. */
export async function machineLockCancel(): Promise<void> {
  await live.keystoreBindCancel();
}

/**
 * Turn the machine lock off (a fresh second factor and Touch ID where they are on; the vault passphrase where neither is).  The device
 * key stays.  Idempotent.
 */
export async function machineLockTurnOff(passphrase?: string): Promise<live.KeystoreChange> {
  return cleanMachineLock(await live.keystoreUnbind(passphrase || undefined));
}

function cleanMachineLock<T extends MachineLockStatus>(st: T): T {
  return {
    ...st,
    protects: redactTokens(String(st.protects ?? "")),
    doesNotProtect: redactTokens(String(st.doesNotProtect ?? "")),
    ...(typeof st.warning === "string" ? { warning: redactTokens(st.warning) } : {}),
  };
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

// ─────────────── Confirm before showing secrets (ADR-150) ───────────────

/** The policy as the broker stores it (`off` when the broker says nothing: an older vault, or not the owner's login). */
export type RevealConfirm = live.RevealConfirm;
/** What a vault reads as when the broker says nothing (kept here, so this module reads nothing from the bridge at import time). */
const REVEAL_CONFIRM_OFF: RevealConfirm = { mode: "off", windowSeconds: 300, scope: "all" };
export type ConfirmationAsk = live.ConfirmationAsk;

/** The vault's "Confirm before showing secrets" policy, read from the broker's graph snapshot. `null` without a shell. */
export async function revealConfirmPolicy(): Promise<RevealConfirm | null> {
  if (!inShell()) return null;
  const snap = await live.graphSnapshot();
  return { ...REVEAL_CONFIRM_OFF, ...(snap.revealConfirm ?? {}) };
}

/**
 * Change the policy (`node.policy` on the global node, with a reason for the audit record).  Turning it on or making it stricter
 * needs nothing; turning it off or loosening it is refused with `confirmation_required` until the person confirms, which the
 * bridge asks for and then retries once (src/lib/bridge.ts).  Resolves with the policy the broker now holds.
 */
export async function setRevealConfirm(next: RevealConfirm): Promise<RevealConfirm> {
  const r = await live.nodePolicy("global", "Settings: confirm before showing secrets", { revealConfirm: next });
  return { ...REVEAL_CONFIRM_OFF, ...(r.policy.revealConfirm ?? next) };
}

/** Confirm it is the owner: Touch ID (no passphrase: the shell shows the prompt) or the vault passphrase.  Nothing is kept. */
export async function confirmIdentity(passphrase?: string): Promise<{ method: "passphrase" | "presence"; expiresIn: number }> {
  const r = await live.sessionConfirm(passphrase);
  return { method: r.method, expiresIn: r.expiresIn };
}

/** Install the screens' confirm dialog as the bridge's confirmation handler.  Returns the function that removes it. */
export function onConfirmationNeeded(handler: ((ask: ConfirmationAsk) => Promise<boolean>) | null): () => void {
  return live.setConfirmationHandler(handler);
}

// ─────────────────────────────── the doctor's tidy-up scan (ADR-161) ───────────────────────────────

export type DoctorReport = live.DoctorReport;
export type DoctorFinding = live.DoctorFinding;

/**
 * Runs the tidy-up scan (`vault.doctor_scan`).  A read: nothing in the vault changes, so nothing is re-read.  Names and labels the
 * broker returns are shown to a person, so each passes through {@link redactTokens} like an audit record's strings.
 */
export async function doctorScan(opts: { staleDays?: number; expiringDays?: number } = {}): Promise<DoctorReport> {
  const r = await live.vaultDoctorScan(opts.staleDays, opts.expiringDays);
  const clean = (v: unknown) => (typeof v === "string" ? redactTokens(v, 200) : v);
  return {
    ...r,
    findings: (Array.isArray(r.findings) ? r.findings : []).map((f) => ({
      ...f,
      fieldLabel: f.fieldLabel === undefined ? undefined : (clean(f.fieldLabel) as string),
      entries: (Array.isArray(f.entries) ? f.entries : []).map((e) => ({ ...e, name: clean(e.name) as string, nodeLabel: (clean(e.nodeLabel) as string | null) ?? null })),
    })),
    skipped: Array.isArray(r.skipped) ? r.skipped : [],
  };
}
