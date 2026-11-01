/**
 * Session setup (work package A): the first-run flow, second-factor enrolment and the lost-authenticator recovery.
 *
 * What is NOT here: the login itself.  Status, unlock, the second-factor step and lock are the model's own `boot`, `unlock`,
 * `gateVerify` and `lock`, because they change what the model is (its `status`).  These are the operations around them.
 *
 * The five functions `beginVault`, `confirmVault`, `beginGateEnrolment`, `confirmGateEnrolment` and `recoverGate` keep the
 * signatures and return types frozen in iteration 1 (they are thin wrappers over one bridge call each).  The composed flows
 * the screens need (`confirmFirstRun`, `recoverAndUnlock`, `createFirstProjects`) and the pure helpers (`describeEnrolment`,
 * `slugOf`) sit beside them and add to that surface; they change none of it.
 *
 * Handling rules every body keeps:
 *  - A passphrase passed in is used for that one call and is never stored here; the screen clears its input first.
 *  - A recovery code, a recovery-code list and an otpauth URI are returned to the caller ONCE and are never put in the view,
 *    in local storage, in a log line or in an error message.  The screen shows them, the user saves them, they go out of scope.
 *  - A rejection is never caught here (except where a function says so): the caller sends it to `routeError`.
 *
 * Order of a first run (ADR-061, 07 §4): `vault.init_begin` -> the user retypes the recovery code (optional: skipping sends the shown one, ADR-081) -> `vault.init_confirm` (the
 * vault is written, still locked) -> `vault.unlock` (a login, no gate yet) -> optionally `vault.gate_enroll_begin` /
 * `_confirm` -> optionally `node.create` for the first projects.
 */
import * as live from "../../lib/bridge";
import { NotWiredError } from "../errors";
import type { VaultModel } from "../model";
import { otpSecretOf, qrPath, type QrPath } from "../qr";

/** Starts vault creation.  Returns the root recovery code, shown once; the user may retype it into {@link confirmVault} (or skip: the shown code is sent). */
export async function beginVault(m: VaultModel, passphrase: string): Promise<Awaited<ReturnType<typeof live.vaultInitBegin>>> {
  void m;
  return live.vaultInitBegin(passphrase);
}

/** Finishes vault creation with the retyped recovery code.  `recovery_code_mismatch` leaves creation pending so the user can retry. */
export async function confirmVault(m: VaultModel, recoveryCode: string): Promise<Awaited<ReturnType<typeof live.vaultInitConfirm>>> {
  void m;
  return live.vaultInitConfirm(recoveryCode.trim());
}

/**
 * Starts enrolling a second factor.  Replacing a gate already in force needs its second factor, fresh: call within the
 * elevation window a successful `m.gateVerify` opens, or the broker rejects with `two_factor_required`.
 */
export async function beginGateEnrolment(m: VaultModel): Promise<Awaited<ReturnType<typeof live.vaultGateEnrollBegin>>> {
  void m;
  return live.vaultGateEnrollBegin();
}

/** Confirms the first code from the authenticator.  Returns the recovery codes exactly once. */
export async function confirmGateEnrolment(m: VaultModel, code: string): Promise<Awaited<ReturnType<typeof live.vaultGateEnrollConfirm>>> {
  const r = await live.vaultGateEnrollConfirm(code.trim());
  m.gateConfirmed = true; // this session's gate is now in force (spec B6.3)
  return r;
}

/**
 * The last door: the passphrase plus the printed root recovery code reset a lost second factor.  It does NOT unlock; call
 * `m.unlock` next, then offer re-enrolment.  A wrong pair is `wrong_passphrase`, never saying which factor failed.
 */
export async function recoverGate(m: VaultModel, passphrase: string, recoveryCode: string): Promise<Awaited<ReturnType<typeof live.vaultGateRecover>>> {
  void m;
  return live.vaultGateRecover(passphrase, recoveryCode.trim());
}

// ---- composed flows and helpers (additions; the five functions above are the frozen surface) -----------------------------

/**
 * `vault.init_confirm` with the retyped code, then the login the new vault needs (a created vault starts locked).  Resolves
 * with the model open and loaded.  A wrong code rejects `recovery_code_mismatch` and nothing is written.
 *
 * If the vault was written but the login after it failed (rate limit, broker gone), that is NOT thrown, for the same reason as
 * {@link recoverAndUnlock}: the vault exists, so the caller must go on to the Lock screen, not tell the user that creating it
 * failed.  It comes back as `unlockError`.
 */
export async function confirmFirstRun(m: VaultModel, retypedRecoveryCode: string, passphrase: string): Promise<{ unlockError?: unknown }> {
  await confirmVault(m, retypedRecoveryCode);
  try {
    await m.unlock(passphrase);
  } catch (unlockError) {
    return { unlockError };
  }
  return {};
}

export interface GateEnrolment {
  /** The QR code as one SVG path. */
  qr: QrPath;
  /** The shared secret, grouped in fours, for typing into an authenticator that cannot scan. */
  secret: string;
}

/** What the enrolment screen draws from `beginGateEnrolment`'s answer: the QR (encoded here, in the page) and the typed-in secret. */
export function describeEnrolment(r: { otpauthUri: string }): GateEnrolment {
  return { qr: qrPath(r.otpauthUri), secret: otpSecretOf(r.otpauthUri) };
}

/**
 * {@link recoverGate}, then the login that has to follow it (`vault.gate_recover` does not log in).
 *
 * If the reset worked but the login after it failed (rate limit, broker gone), that is NOT thrown: the gate is already reset, so
 * the caller must go on to the passphrase step, not tell the user the recovery failed.  It comes back as `unlockError`.
 */
export async function recoverAndUnlock(m: VaultModel, passphrase: string, recoveryCode: string): Promise<{ gateReset: boolean; unlockError?: unknown }> {
  const r = await recoverGate(m, passphrase, recoveryCode);
  try {
    await m.unlock(passphrase);
  } catch (unlockError) {
    return { gateReset: r.gateReset, unlockError };
  }
  return { gateReset: r.gateReset };
}

/** Node ids the broker reserves. */
const RESERVED = new Set(["global", "orphan"]);

/** `My Shop!` -> `my-shop`.  Lower-case ASCII letters, digits and hyphens; never a reserved id; never empty. */
export function slugOf(label: string): string {
  const base = label
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 40)
    .replace(/-+$/g, "");
  if (!base) return "project";
  return RESERVED.has(base) ? `${base}-project` : base;
}

export interface FirstProjects {
  /** Indexes (into the names passed) of the projects that now exist. */
  created: number[];
  /** The first failure, if any.  Nothing after it was attempted. */
  error?: unknown;
}

/**
 * `node.create` under `global` for each non-blank name, one at a time, in order.  Stops at the first failure and says which
 * names were created, so a retry does not create them twice.  Refreshes the model's graph once at the end, failure or not.
 * Never throws: the failure is returned for the caller to route.
 */
export async function createFirstProjects(m: VaultModel, names: string[]): Promise<FirstProjects> {
  const created: number[] = [];
  const taken = new Set(m.view.nodes.map((n) => n.id));
  let error: unknown;
  for (let i = 0; i < names.length; i++) {
    const label = names[i].trim().slice(0, 120);
    if (!label) continue;
    let id = slugOf(label);
    for (let n = 2; taken.has(id); n++) id = `${slugOf(label)}-${n}`;
    try {
      await live.nodeCreate(id, label, "global");
    } catch (e) {
      error = e;
      break;
    }
    taken.add(id);
    created.push(i);
  }
  if (created.length) {
    try {
      await m.refresh({ graph: true });
    } catch (e) {
      error ??= e;
    }
  }
  return { created, error };
}

// ---- the second factor after the login, and a decision while locked (ADR-085, ADR-088) -------------------------------------

/**
 * The step-up (ADR-085): a node whose `requireTwoFactor` is in force answers `two_factor_required` to a reveal (to every read, at level
 * `always`) until the owner has proven the factor in the last five minutes.  `vault.gate_verify {code}` from this logged-in session proves
 * it: `{locked:false, elevated:true, expiresIn:300}`, no token (the login this process holds stays what it was).  A recovery code is
 * not accepted here, only the authenticator's.  Resolves with how long the elevation lasts, in seconds.  A rejection is the caller's to route
 * (`gate_verification_failed` and `rate_limited` are inline messages in the dialog; a lost login is the Lock screen).
 */
export async function stepUp(m: VaultModel, code: string): Promise<{ expiresIn: number }> {
  if (m.kind !== "bridge") throw new NotWiredError("vault.gate_verify");
  const r = (await live.vaultGateVerify(code.trim())) as { locked?: boolean; expiresIn?: unknown };
  // A vault that answers "locked" took the login with it.
  if (r.locked === true) throw { source: "broker", code: "vault_locked", message: "the vault is locked" };
  return { expiresIn: typeof r.expiresIn === "number" && Number.isFinite(r.expiresIn) && r.expiresIn > 0 ? Math.min(r.expiresIn, 3600) : 300 };
}

/** What the locked-vault approval panel (S16a) is told: the decision was recorded; the vault is still locked. */
export interface ApprovalDecided {
  request: string;
  approved: boolean;
}

/**
 * Decide an agent's waiting `approval_pending` while the vault is LOCKED (ADR-088): `vault.approval_decide` with the request id the agent
 * was given, the passphrase and (when a second factor is enrolled) the authenticator's code.  The factors authorise it; no login is made,
 * nothing is read, and the vault stays locked.  A recovery code is refused by the broker.  The passphrase and code are used for this one
 * call and are not kept.  Rejections: `wrong_passphrase`, `two_factor_required` (a code is needed), `gate_verification_failed`,
 * `rate_limited` (shared with the login's backoff), `not_found` (no such waiting request).
 */
export async function decideApproval(m: VaultModel, request: string, approved: boolean, passphrase: string, code: string): Promise<ApprovalDecided> {
  if (m.kind !== "bridge") throw new NotWiredError("vault.approval_decide");
  const r = await live.vaultApprovalDecide(request.trim(), approved, passphrase, code.trim() || undefined);
  return { request: r.request, approved: r.approved };
}

/** One agent request waiting for a person, as the Lock screen lists it (ADR-090). Ids and the broker's own words; never a value. */
export interface WaitingApproval {
  request: string;
  node: string;
  entry: string;
  /** What to call it on the screen: the names when the broker gave them, the ids when it withheld them (`privateNames`) or does not hold them. */
  title: string;
  /** Unix milliseconds at which the request defaults to denied, from the broker's `expiresIn` at the moment it answered. */
  expiresAt: number;
}

/** The words for one waiting request.  Chosen here from the broker's fields; a hidden name is never guessed at and never replaced by a slug of anything. */
export function describeWaiting(a: live.ApprovalRequest): string {
  if (a.nameHidden === true) return `an entry in a node whose name is private (${a.node})`;
  const entry = a.entryName !== null && a.entryName !== undefined && a.entryName !== "" ? `“${a.entryName}”` : `entry ${a.entry.slice(0, 10)}`;
  const node = a.nodeLabel !== null && a.nodeLabel !== undefined && a.nodeLabel !== "" ? a.nodeLabel : a.node;
  return `${entry} in ${node}`;
}

/**
 * The agent requests waiting for a decision while the vault is LOCKED (ADR-090): `vault.status` says how many (a bare count), and only when
 * there is one, `vault.approval_get` says what they are.  Empty when the vault is not locked, when none is waiting, or when this page has no
 * shell.  Read-only, no login, nothing decrypted; rejections are the caller's to route (a broker that is not running is the usual one).
 */
export async function waitingApprovals(m: VaultModel, now: number = Date.now(), knownCount?: number): Promise<WaitingApproval[]> {
  if (m.kind !== "bridge") return [];
  // `knownCount`: the count the boot's own `vault.status` already gave, so the first look costs no second status call.
  if (knownCount === undefined) {
    const status = await live.vaultStatus();
    if (!status.locked || !(status.pendingApprovals && status.pendingApprovals > 0)) return [];
  } else if (!(knownCount > 0)) return [];
  const answer = await live.vaultApprovalGet();
  const list = "pending" in answer ? answer.pending : [answer];
  return list
    .filter((a) => a.state === "pending")
    .map((a) => ({
      request: a.request,
      node: a.node,
      entry: a.entry,
      title: describeWaiting(a),
      expiresAt: now + Math.max(0, a.expiresIn) * 1000,
    }));
}

// ---- the Lock screen's wording and the shell's events -------------------------------------------------------------------
// Re-exported here so that a screen reaches them as `session.*` through the vault index, which the wiring packages do not edit.

export { lockNoteFor, waitText } from "../errors";
export { onShellLocked, onShellWindowInactive, shellLockNote, takeReloadLockNote, rememberPageLockNote, SHELL_LOCKED_EVENT, SHELL_WINDOW_INACTIVE_EVENT } from "../shell-events";
