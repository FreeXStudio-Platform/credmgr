/**
 * Writes (work package C): entries, the locked-write tray, nodes, seal and restore.
 *
 * Every function here is the same three steps and nothing else: ONE bridge call (src/lib/bridge.ts), then
 * `model.refresh({...what that call touched})`, then return the broker's answer.  There are no optimistic writes: what the
 * screens show after a write is what the broker said next.  A rejection from the bridge call propagates untouched (the
 * caller, logic/write.js, sends it to `routeError`) and nothing is refreshed, because nothing changed.
 *
 * The one case the three steps do not cover: the broker DID the work and only the re-read after it failed.  Then nothing is
 * thrown (a throw would read as "the write failed", and a retry would meet `entry_exists` or `not_found`): the action resolves
 * with the broker's answer plus `readbackError`, and the caller says what was saved, that the screen is stale, and routes the
 * read's own error (a lost login, an unreachable broker).  tests/unit/architecture.test.ts fails a caller that never looks.
 *
 * Nothing in this file ever holds a secret longer than the call: the value of an entry goes to the bridge and is not kept,
 * logged or put into an error.
 */
import * as live from "../../lib/bridge";
import { errorCode, isSessionEnded, NotWiredError } from "../errors";
import type { VaultModel } from "../model";
import type { RefreshSpec } from "../types";
import { thenReread, type Written } from "./written";

export type { Written };

export interface EntryInput {
  name: string;
  /** A one-field entry: the value, with `label` naming the field.  Give this OR {@link EntryInput.fields}, never both. */
  value?: string;
  /** The field's label (a one-field entry only).  Free text; it is stored, and the broker infers the field's type from it and the value. */
  label?: string;
  /** Several fields, in the order to keep: send what a preview showed, verbatim.  `type` / `masked` only where the user pinned them. */
  fields?: live.FieldInput[];
  /** The user's pin of the entry's own type / sensitivity.  Leave out to let the broker infer; never send the inferred value back. */
  entryType?: live.EntryTypeName;
  sensitivity?: live.SensitivityName;
}

/** `pending: true` means the vault or node was locked and the entry waits in the review tray (no generation yet). */
export type EntryCreated = Awaited<ReturnType<typeof live.entryCreate>>;
export type EntriesCreated = Awaited<ReturnType<typeof live.entryCreateBatch>>;

/** The wire body of one entry: `fields` XOR `value`, a pin only if the user chose one. */
export function itemOf(e: EntryInput): live.EntryCreateItem {
  const item: live.EntryCreateItem = { name: e.name };
  if (e.fields) item.fields = e.fields;
  else {
    item.value = e.value ?? "";
    if (e.label && e.label.trim()) item.label = e.label.trim();
  }
  if (e.entryType) item.entryType = e.entryType;
  if (e.sensitivity) item.sensitivity = e.sensitivity;
  return item;
}

/** One entry.  Held for review (`pending: true`) when its node is locked; then only the tray changes. */
export async function createEntry(m: VaultModel, node: string, input: EntryInput): Promise<Written<EntryCreated>> {
  const one = itemOf(input);
  const r = await live.entryCreate(node, one.name, one.value, one.label, one.fields, one.entryType, one.sensitivity);
  return thenReread(m, r, r.pending ? { pending: true } : { graph: true, nodes: [node] });
}

/**
 * 1 to 500 entries in ONE call (ADR-073).  The broker checks every name before it writes anything, so a refusal writes
 * nothing and throws.  `complete: false` means a write failed part-way: report `failed` and what `created` lists (those are
 * saved, so they are refreshed).
 */
export async function createEntries(m: VaultModel, node: string, entries: EntryInput[]): Promise<Written<EntriesCreated>> {
  const r = await live.entryCreateBatch(node, entries.map(itemOf));
  const spec: RefreshSpec = {};
  if (r.created.some((c) => !c.pending)) {
    spec.graph = true;
    spec.nodes = [node];
  }
  if (r.created.some((c) => c.pending)) spec.pending = true;
  return spec.graph || spec.pending ? thenReread(m, r, spec) : r;
}

// ───────────────────────────── the fields of an entry (ADR-078) ─────────────────────────────

/** The node's generation as `entry.list` last said it (the entry's own detail is the fallback): the value every change to an entry echoes. */
export function generationOf(m: VaultModel, node: string, entry: string): number {
  const g = m.generation[node];
  if (typeof g === "number" && g > 0) return g;
  return m.detail(node, entry)?.generation ?? 0;
}

/** What a change to one entry's fields touches: the node's list (type, sensitivity, count, generation), the graph's counts, the entry's own fields. */
const fieldsTouched = (node: string, entry: string): RefreshSpec => ({ graph: true, nodes: [node], details: [{ node, entry }] });

/** Appends fields (`position` inserts instead).  Retains history; the broker mints the ids. */
export async function addFields(m: VaultModel, node: string, entry: string, fields: live.FieldInput[], position?: number): Promise<Written<Awaited<ReturnType<typeof live.fieldAdd>>>> {
  const r = await live.fieldAdd(node, entry, generationOf(m, node, entry), fields, position);
  return thenReread(m, r, fieldsTouched(node, entry));
}

/**
 * Changes one field: send only the keys the user changed.  A value held from before the change is dropped at once (it is the OLD value),
 * so nothing shows it again; the screen reads the entry's fields afresh.
 */
export async function updateField(m: VaultModel, node: string, entry: string, field: string, patch: live.FieldPatch): Promise<Written<Awaited<ReturnType<typeof live.fieldUpdate>>>> {
  const r = await live.fieldUpdate(node, entry, generationOf(m, node, entry), field, patch);
  m.dropEntrySecrets(node, entry);
  return thenReread(m, r, fieldsTouched(node, entry));
}

/** Removes one field.  The broker refuses to remove the last one (`malformed_request`); the entry is removed instead. */
export async function removeField(m: VaultModel, node: string, entry: string, field: string): Promise<Written<Awaited<ReturnType<typeof live.fieldRemove>>>> {
  const r = await live.fieldRemove(node, entry, generationOf(m, node, entry), field);
  m.dropEntrySecrets(node, entry);
  return thenReread(m, r, fieldsTouched(node, entry));
}

/** Puts the fields in this order: `order` lists every current field id exactly once.  The ids stay, so nothing held is dropped. */
export async function reorderFields(m: VaultModel, node: string, entry: string, order: string[]): Promise<Written<Awaited<ReturnType<typeof live.fieldReorder>>>> {
  const r = await live.fieldReorder(node, entry, generationOf(m, node, entry), order);
  return thenReread(m, r, fieldsTouched(node, entry));
}

/**
 * What `util.generate` made (ADR-087): made in the broker (OS randomness), never in page JavaScript.  The value is the caller's to hold for
 * as long as the dialog is open and to show MASKED; it enters a field only through {@link addFields} / {@link updateField}, is never put in a
 * notice, a log or storage, and is not audited.  `entropyBits` is the broker's estimate.
 */
export async function generatePassword(m: VaultModel, length: number, symbols: boolean, pronounceable: boolean): Promise<live.GeneratedPassword> {
  if (m.kind !== "bridge") throw new NotWiredError("util.generate");
  return live.utilGenerate(Math.max(8, Math.min(128, Math.round(length) || 20)), symbols, pronounceable);
}

/**
 * The audit record of a change, which is what `entry.undo` is asked to undo: the `audit` member of the change's own answer (the shell passes
 * the broker's envelope `audit` through for every changing op, ADR-091).  `null` when the answer has none (the record could not be written):
 * then no Undo is offered, and nothing is guessed from the audit trail.
 */
export function auditOf(answer: unknown): string | null {
  const id = (answer as { audit?: unknown } | null)?.audit;
  return typeof id === "string" && id !== "" ? id : null;
}

/** What a name the broker accepted but wants the person told about is called on the screen (ADR-084). */
export const MIXED_SCRIPT_TEXT = "This name mixes Latin with Greek or Cyrillic letters.";

/**
 * The notice text for the `warnings` of a name-creating answer (`entry.create`, `entry.create_batch`, `node.create`, `node.update`), or `""`.
 * Only the words the window knows are ever shown: an unknown warning code is ignored, never printed.  `batch` says "a name in this batch".
 */
export function nameWarningText(answer: unknown, batch = false): string {
  const w = (answer as { warnings?: unknown } | null)?.warnings;
  if (!Array.isArray(w) || !w.includes("mixed_script_name")) return "";
  return batch ? "A name in this batch mixes Latin with Greek or Cyrillic letters." : MIXED_SCRIPT_TEXT;
}

/** What the window remembers of the last field change so Undo can be offered: ids and a word, never a value or a label. */
export interface UndoToken {
  node: string;
  entry: string;
  /** The audit record to undo. */
  audit: string;
  /** "add field" / "edit" / "remove field". */
  text: string;
}

/**
 * Undo one field change with `entry.undo` (ADR-086).  Echoes the node's CURRENT generation (a stale one is `conflict`); the broker answers
 * what it restored, which is what the caller says, not a copy the window kept.  The old value, if any, is not shown here.  Then the node,
 * the graph and the entry's fields are read again.  A rejection is thrown for the caller to route (`not_undoable` after seven days,
 * `conflict` when the node moved on).
 */
export async function undoFieldChange(m: VaultModel, token: UndoToken): Promise<Written<live.FieldUndone>> {
  const raw = await live.entryUndo(token.node, token.audit, generationOf(m, token.node, token.entry));
  m.dropEntrySecrets(token.node, token.entry);
  const r = raw as live.FieldUndone;
  return thenReread(m, r, fieldsTouched(token.node, token.entry));
}

/** What a preview of a bulk paste or of edited rows says (src/lib/bridge.ts `FieldsPreview`). */
export type Preview = Awaited<ReturnType<typeof live.fieldsPreview>>;

/**
 * The live preview of a paste, parsed and inferred by the SAME Rust code the broker's world uses, locally: no broker call, no login, no
 * audit record, so it is safe on every keystroke.  The page keeps no parser of its own: what this shows is what is stored.  `split`
 * makes one entry per `///` block; otherwise one entry holds every field.
 */
export async function previewPaste(m: VaultModel, text: string, split: boolean): Promise<Preview> {
  if (m.kind !== "bridge") throw new NotWiredError("fields.preview");
  return live.fieldsPreview(text, undefined, split);
}

/** The preview of rows the user typed or edited, with their pins (type / masking) if any. */
export async function previewRows(m: VaultModel, fields: live.FieldInput[]): Promise<Preview> {
  if (m.kind !== "bridge") throw new NotWiredError("fields.preview");
  return live.fieldsPreview(undefined, fields);
}

/** The `fields` to send for a previewed segment: label and value verbatim, `type` / `masked` only where they are the user's pins. */
export const previewFieldInputs = (segment: live.PreviewSegment): live.FieldInput[] => live.previewFieldInputs(segment);

/**
 * Re-read the tray (every node's), for the moment the user opens it.  The graph comes with it: whether a row can be
 * accepted depends on its node's lock, which may have changed since the last read (another process can unlock a node).
 */
export async function listPending(m: VaultModel): Promise<void> {
  await m.refresh({ graph: true, pending: true });
}

/** Accepting is the ONLY thing that moves a held entry into its node. */
export async function acceptPending(m: VaultModel, node: string, entry: string): Promise<Written<Awaited<ReturnType<typeof live.vaultPendingAccept>>>> {
  const r = await live.vaultPendingAccept(node, entry);
  return thenReread(m, r, { graph: true, nodes: [node], pending: true });
}

export async function discardPending(m: VaultModel, node: string, entry: string): Promise<Written<Awaited<ReturnType<typeof live.vaultPendingDiscard>>>> {
  const r = await live.vaultPendingDiscard(node, entry);
  return thenReread(m, r, { pending: true });
}

export interface NodeInput {
  /** The slug; never changes. */
  id: string;
  /** What the user sees; 1 to 120 characters. */
  label: string;
  parentId: string;
  /** Absolute, existing directories that scope an agent to the node.  A leading `~` is expanded to the home directory. */
  workdirs?: string[];
}

/** `~` and `~/x` become the home directory; anything else is returned as typed (the broker requires absolute paths). */
export function expandHome(paths: string[], home: string): string[] {
  const base = home.replace(/\/+$/, "");
  return paths.map((p) => (p === "~" ? base : p.startsWith("~/") ? `${base}/${p.slice(2)}` : p));
}

async function resolveWorkdirs(paths: string[] | undefined): Promise<string[] | undefined> {
  const list = (paths ?? []).map((p) => p.trim()).filter(Boolean);
  if (!list.length) return undefined;
  return list.some((p) => p === "~" || p.startsWith("~/")) ? expandHome(list, await live.homeDir()) : list;
}

export async function createNode(m: VaultModel, input: NodeInput): Promise<Written<Awaited<ReturnType<typeof live.nodeCreate>>>> {
  const workdirs = await resolveWorkdirs(input.workdirs);
  const r = await live.nodeCreate(input.id, input.label, input.parentId, workdirs);
  return thenReread(m, r, { graph: true, nodes: [input.id] });
}

/**
 * Narrowing fields and widening fields (`descendantRead: true`, `siblingVisibility: "shared"`) go in SEPARATE calls, so a
 * `presence_required` on the widening ones does not discard the rest.
 */
export async function setNodePolicy(m: VaultModel, node: string, reason: string, patch: live.NodePolicyPatch): Promise<Written<Awaited<ReturnType<typeof live.nodePolicy>>>> {
  const r = await live.nodePolicy(node, reason, patch);
  return thenReread(m, r, { graph: true });
}

/**
 * The id for a node whose NAME is private (ADR-083, ADR-091): `n_` and twelve random lower-case hex digits, never anything derived from the
 * name.  A node id is chosen once, at creation, and the broker shows it to every reader who may list the node, so a slug of the name would
 * give the name away; this one says nothing.  Drawn from the platform's random source; `taken` (the ids the vault already has) is avoided.
 */
export function opaqueNodeId(taken: ReadonlySet<string> = new Set()): string {
  for (let attempt = 0; attempt < 16; attempt++) {
    const bytes = new Uint8Array(6);
    globalThis.crypto.getRandomValues(bytes);
    const id = "n_" + Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
    if (!taken.has(id)) return id;
  }
  throw new Error("could not find a free node id");
}

/** What the add-node dialog's advanced section asks for. */
export interface NodeChoices {
  /** "Sub-nodes see each other" */
  siblingShare: boolean;
  /** "2FA on reveal" */
  twofaOnReveal: boolean;
  /** "This node can read its children" */
  childRead: boolean;
  agentAccess: "read-write" | "read-only" | "none";
  /** "Hide this node's name from others" (`privateNames`, ADR-083): narrows who sees the node, so it is never "widening". */
  privateNames?: boolean;
}

/** What `node.create` gives a new node (core `NodePolicy::default`, 03_DATA_MODEL.md §1 "Defaults on create"). */
export const CREATE_DEFAULTS: {
  siblingVisibility: "shared" | "isolated";
  descendantRead: boolean;
  requireTwoFactor: "never" | "reveal" | "always";
  agentAccess: "read-write" | "read-only" | "none";
  privateNames: boolean;
} = { siblingVisibility: "shared", descendantRead: false, requireTwoFactor: "reveal", agentAccess: "read-write", privateNames: false };

export const POLICY_REASON_AT_CREATION = "set at creation";

/**
 * The dialog's choices as the two patches to send, relative to the defaults a new node already has: nothing is sent for a
 * field the user left alone.  A field that turns reach ON (`descendantRead: true`, `siblingVisibility: "shared"`) is
 * "widening": the broker answers `presence_required` for it until presence can be attested, so it travels alone.
 */
export function policyPatches(c: NodeChoices): { narrowing: live.NodePolicyPatch; widening: live.NodePolicyPatch } {
  const narrowing: live.NodePolicyPatch = {};
  const widening: live.NodePolicyPatch = {};
  const sibling = c.siblingShare ? "shared" : "isolated";
  if (sibling !== CREATE_DEFAULTS.siblingVisibility) (sibling === "shared" ? widening : narrowing).siblingVisibility = sibling;
  if (c.childRead !== CREATE_DEFAULTS.descendantRead) (c.childRead ? widening : narrowing).descendantRead = c.childRead;
  const twofa = c.twofaOnReveal ? "reveal" : "never";
  if (twofa !== CREATE_DEFAULTS.requireTwoFactor) narrowing.requireTwoFactor = twofa;
  if (c.agentAccess !== CREATE_DEFAULTS.agentAccess) narrowing.agentAccess = c.agentAccess;
  if ((c.privateNames === true) !== CREATE_DEFAULTS.privateNames) narrowing.privateNames = c.privateNames === true;
  return { narrowing, widening };
}

export interface NodeCreatedWithPolicy {
  node: string;
  /** Policy fields the broker applied. */
  applied: string[];
  /** Policy calls the broker refused (the node exists regardless); hand them to {@link policyReport}. */
  refused: Array<{ fields: string[]; error: unknown }>;
  /**
   * Set when the final re-read failed AFTER the broker had already created the node and answered every policy call: the node
   * exists, the view is just not up to date.  Route it (it is usually a lost login or an unreachable broker); do not say the
   * node was not created.
   */
  readbackError?: unknown;
  /** `node.create`'s own `warnings` (a name that mixes scripts, ADR-084); hand the whole object to {@link nameWarningText}. */
  warnings?: live.NameWarning[];
}

/**
 * Create a node, then apply its policy choices.  Creating can fail (nothing exists: the error is thrown).  Once the node
 * exists nothing is thrown any more: a refused policy call (`presence_required` for a widening field, or anything else) is
 * REPORTED in `refused`, the node and every other choice stand, and {@link policyReport} says exactly which part was not
 * applied and what that leaves the node as.  The view is re-read once, at the end.
 */
export async function createNodeWithPolicy(m: VaultModel, input: NodeInput, choices: NodeChoices): Promise<NodeCreatedWithPolicy> {
  const workdirs = await resolveWorkdirs(input.workdirs);
  const created = await live.nodeCreate(input.id, input.label, input.parentId, workdirs);
  const out: NodeCreatedWithPolicy = { node: input.id, applied: [], refused: [] };
  if (created.warnings?.length) out.warnings = created.warnings;
  const { narrowing, widening } = policyPatches(choices);
  for (const patch of [narrowing, widening]) {
    const fields = Object.keys(patch);
    if (!fields.length) continue;
    try {
      const r = await live.nodePolicy(input.id, POLICY_REASON_AT_CREATION, patch);
      out.applied.push(...r.changed);
    } catch (error) {
      out.refused.push({ fields, error });
    }
  }
  try {
    await m.refresh({ graph: true, nodes: [input.id] });
  } catch (error) {
    out.readbackError = error;
  }
  return out;
}

/** What a policy field is called to the user, and what a node has when the field was left at what `node.create` gave it. */
function describePolicyField(field: string, chosen: live.NodePolicyPatch): { label: string; chosen: string; stays: string; wider: boolean } | null {
  switch (field) {
    case "siblingVisibility":
      return { label: "sub-nodes seeing each other", chosen: chosen.siblingVisibility === "isolated" ? "isolated" : "shared", stays: CREATE_DEFAULTS.siblingVisibility, wider: chosen.siblingVisibility === "isolated" && CREATE_DEFAULTS.siblingVisibility === "shared" };
    case "descendantRead":
      return { label: "this node reading its children", chosen: chosen.descendantRead ? "on" : "off", stays: CREATE_DEFAULTS.descendantRead ? "on" : "off", wider: false };
    case "requireTwoFactor":
      // Enforced since ADR-085 (`node.policy` answers `notEnforced: []`): a reveal asks for the second factor when a gate is confirmed.
      return { label: "second factor on reveal", chosen: chosen.requireTwoFactor === "never" ? "off" : "on", stays: CREATE_DEFAULTS.requireTwoFactor === "never" ? "off" : "on", wider: false };
    case "privateNames":
      // Left at the default the node's name is visible to everyone who can see the node: wider than the user chose.
      return { label: "hiding this node's name from others", chosen: chosen.privateNames ? "on" : "off", stays: CREATE_DEFAULTS.privateNames ? "on" : "off", wider: chosen.privateNames === true };
    case "agentAccess":
      return { label: "agent access", chosen: String(chosen.agentAccess), stays: CREATE_DEFAULTS.agentAccess, wider: chosen.agentAccess !== undefined && chosen.agentAccess !== CREATE_DEFAULTS.agentAccess && CREATE_DEFAULTS.agentAccess === "read-write" };
    default:
      return null;
  }
}

function policyReason(code: string | null): string {
  switch (code) {
    case "presence_required":
      return "Choices like these need presence (Touch ID), which this beta cannot attest yet.";
    case "capability_not_held":
    case "node_access_denied":
      return "This login is not allowed to change the node's settings.";
    case "broker_unreachable":
      return "The broker could not be reached.";
    case "vault_locked":
    case "session_expired":
      return "The login ended.";
    case null:
      return "An unexpected error stopped it.";
    default:
      return `The broker refused it (${code}).`;
  }
}

export interface PolicyReport {
  /** `error` when the node ended up WIDER than the user chose, `warn` when it is no wider. */
  kind: "warn" | "error";
  /** One notice that names every part that was not applied, why, and the state the node is in.  Chosen by code; no error text, no value. */
  text: string;
  /** A refusal said the login is gone: show this text on the Lock screen instead of as a notice. */
  sessionEnded: boolean;
}

/**
 * The account of a node whose creation succeeded but whose policy choices were (partly) refused: ONE notice for all of it, so
 * a second refusal cannot replace the first, and the user is told plainly what state the node is in.  A node left at the
 * defaults while the user chose something narrower (agents locked out, sub-nodes isolated) is WIDER than chosen, and the text
 * says so and what to do (the CLI's `node policy`, or seal it); a refused widening (reading its children) leaves it narrower.
 * `null` when nothing was refused.
 */
export function policyReport(label: string, id: string, choices: NodeChoices, out: Pick<NodeCreatedWithPolicy, "applied" | "refused">): PolicyReport | null {
  if (!out.refused.length) return null;
  const { narrowing, widening } = policyPatches(choices);
  const chosen: live.NodePolicyPatch = { ...narrowing, ...widening };
  const fields = out.refused.flatMap((r) => r.fields);
  const described = fields.map((f) => ({ f, d: describePolicyField(f, chosen) }));
  const parts = described.map(({ f, d }) => (d ? `${d.label} (you chose ${d.chosen}; it stays ${d.stays})` : f));
  const reasons = [...new Set(out.refused.map((r) => policyReason(errorCode(r.error))))];
  const wider = described.filter(({ d }) => d?.wider).map(({ d }) => `${d!.label}: ${d!.stays}`);
  const appliedLabels = out.applied.map((f) => describePolicyField(f, chosen)?.label ?? f);
  let text = `Node “${label}” was created, but these choices were not applied: ${parts.join("; ")}. ${reasons.join(" ")}`;
  if (appliedLabels.length) text += ` Applied: ${appliedLabels.join(", ")}.`;
  text += wider.length
    ? ` The node is WIDER than you chose (${wider.join("; ")}). Fix it before storing anything in it: run "credmgr node policy ${id} --reason …" in a terminal, or seal the node.`
    : " The node is no wider than you chose.";
  return { kind: wider.length ? "error" : "warn", text, sessionEnded: out.refused.some((r) => isSessionEnded(r.error)) };
}

const today = (): string => new Date().toISOString().slice(0, 10);

/**
 * The end of the restore window, in Unix seconds, if the broker's `node.seal` answer says when it is.  Today it does not (it answers
 * `{ node, sealed }`; the window is a fixed 7 days kept broker-side), so this is `undefined` and the screen claims no deadline.  Read
 * only as a finite positive number under the bridge's own key for such a time (`expiresAt`, as on entries and grants); anything else
 * is ignored, never shown.
 */
export function sealExpiry(answer: unknown): number | undefined {
  const v = (answer as { expiresAt?: unknown } | null)?.expiresAt;
  return typeof v === "number" && Number.isFinite(v) && v > 0 ? v : undefined;
}

/**
 * Seal a node: its entries move to the orphaned node and the broker keeps the originals for 7 days.  The broker lists no
 * sealed node to a login that is not an Admin human, so the session remembers this one for Restore (`view.sealed`; `node` and `kids` and
 * `date` are the shape Settings' rows read) until the graph re-read below replaces it with the broker's own list (ADR-080).  The node's grants are revoked by the broker, so grants and the tray are re-read.
 */
export async function sealNode(m: VaultModel, node: string): Promise<Written<Awaited<ReturnType<typeof live.nodeSeal>>>> {
  const label = m.node(node)?.label ?? node;
  const r = await live.nodeSeal(node);
  const expiresAt = sealExpiry(r);
  m.rememberSealed({ id: node, label, node: { id: node, label }, kids: [], date: today(), ...(expiresAt === undefined ? {} : { expiresAt }) });
  return thenReread(m, r, { graph: true, grants: true, pending: true });
}

/** Undo a seal inside the 7-day window.  An expired or unknown archive is forgotten, then the error propagates. */
export async function restoreNode(m: VaultModel, node: string): Promise<Written<Awaited<ReturnType<typeof live.nodeRestore>>>> {
  let r: Awaited<ReturnType<typeof live.nodeRestore>>;
  try {
    r = await live.nodeRestore(node);
  } catch (e) {
    const c = errorCode(e);
    if (c === "archive_expired" || c === "not_found") m.forgetSealed(node);
    throw e;
  }
  m.forgetSealed(node);
  return thenReread(m, r, { graph: true, nodes: [node], pending: true });
}
