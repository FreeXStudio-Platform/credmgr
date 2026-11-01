/**
 * Read-path actions (work package B): the operations the inspector, the graph and the search box make that are not part of
 * loading the model.  Every one goes through src/lib/bridge.ts (never the shell's own invoke) and then, if it changed
 * anything the screens show, `model.refresh(...)`.  There are no optimistic writes.
 *
 * Plaintext rule: a value or a TOTP code returned here goes to the caller and nowhere else.  It is never put in the view,
 * in local storage, in a log line or in an error message, and the caller deletes it when the user hides it, when the
 * node changes, when the window is hidden and when the vault locks.  A TOTP code is held in the model's secret store
 * like a revealed value; the plaintext of a COPIED value never reaches the webview at all (see {@link copyEntry}).
 *
 * In a development or test build that runs without the Tauri shell (the in-memory example vault, which a release build does not
 * contain) there is no broker to ask, so every action that needs one answers {@link NotWiredError}, which the router shows as
 * "not available".
 */
import * as live from "../../lib/bridge";
import { NotWiredError } from "../errors";
import type { VaultModel } from "../model";
import { thenReread, type Written } from "./written";

/** A TOTP code is valid for one 30 s step of the clock (`totp.code` uses the default period). */
export const TOTP_STEP_MS = 30_000;

function needsBroker(m: VaultModel, op: string): void {
  if (m.kind !== "bridge") throw new NotWiredError(op);
}

/**
 * Entry names the caller may see, from the broker's own filter.  The term is matched against NAMES only (the broker never
 * searches values) and is trimmed; an empty term finds nothing.  Results come back for every node the caller may list,
 * including the orphaned node's items, which the caller maps to the orphaned view.
 */
export async function searchEntries(m: VaultModel, term: string): Promise<Array<{ node: string; id: string; name: string }>> {
  const t = term.trim();
  if (!t) return [];
  needsBroker(m, "search");
  const { results } = await live.search(t);
  return results.map((r) => ({ node: r.node, id: r.id, name: r.name }));
}

/**
 * Read one node's note into the view (`m.refresh({ notes: node })`).  `capability_not_held` (the `notes` capability is not
 * implied by `read`) and `node_locked` leave the note `null`; any other failure is thrown for the caller to route.
 */
export async function loadNotes(m: VaultModel, node: string): Promise<void> {
  await m.refresh({ notes: node });
}

/**
 * The node's lock, not the vault's: the login survives it.  Every revealed value is dropped first, so nothing read from
 * the node stays on screen after it is locked, and the graph is re-read so the lock shows.
 */
export async function lockNode(m: VaultModel, node: string): Promise<Written<Awaited<ReturnType<typeof live.vaultNodeLock>>>> {
  needsBroker(m, "vault.node_lock");
  const r = await live.vaultNodeLock(node);
  m.wipeSecrets();
  return thenReread(m, r, { graph: true, nodes: [node] });
}

/** Unlocking makes the node's entries and note readable again, so both are re-read with the graph. */
export async function unlockNode(m: VaultModel, node: string): Promise<Written<Awaited<ReturnType<typeof live.vaultNodeUnlock>>>> {
  needsBroker(m, "vault.node_unlock");
  const r = await live.vaultNodeUnlock(node);
  return thenReread(m, r, { graph: true, nodes: [node], notes: node });
}

/**
 * Renames a node (1 to 120 characters once trimmed).  The id never changes.  The global and orphaned nodes are refused by
 * the broker (`malformed_request`), so the screen does not offer it for them.
 */
export async function renameNode(m: VaultModel, node: string, label: string): Promise<Written<Awaited<ReturnType<typeof live.nodeUpdate>>>> {
  needsBroker(m, "node.update");
  const r = await live.nodeUpdate(node, label.trim());
  return thenReread(m, r, { graph: true });
}

/**
 * What {@link readTotp} hands back: the code's expiry (ms since the epoch), and whether the model is holding the code.  The code
 * itself is read back with `m.plain(node, entry, 0)` while it is held, and is not returned from here at all.
 */
export interface TotpShown {
  expiresAt: number;
  /** `false`: the user hid the field, changed node, hid the window or locked while the broker was answering, so the code was dropped on arrival. */
  held: boolean;
}

/**
 * A current TOTP code.  It is held in the model's secret store (under the seed field's id, `field`, or position 0 when none is named,
 * where a revealed value would sit) until the end of its 30 s step, or `maxWindowMs` if that is sooner, and is read back with
 * `m.plain(node, entry, field ?? 0)`.  On an entry with several fields `field` names the one that holds the seed (ADR-078).
 * It goes through the same ticketed path as a reveal (`holdFetched`), so a code that arrives after the window was hidden, the
 * node changed or the vault locked is discarded, exactly like a revealed value.  The broker never returns the seed
 * (`totp.seed` is presence-gated); this is the only way a TOTP entry is shown.
 */
export async function readTotp(m: VaultModel, node: string, entry: string, maxWindowMs = Number.POSITIVE_INFINITY, field?: string): Promise<TotpShown> {
  needsBroker(m, "totp.code");
  let expiresAt = 0;
  const { held } = await m.holdFetched(
    node,
    entry,
    field ?? 0,
    () => live.totpCode(node, entry, field),
    (r) => {
      const now = m.options.now();
      const windowMs = Math.min(maxWindowMs, TOTP_STEP_MS - (now % TOTP_STEP_MS));
      expiresAt = now + windowMs;
      return { value: r.code, windowMs };
    },
  );
  return { expiresAt, held };
}

/**
 * Asks for a TOTP seed.  The broker refuses every time (`presence_required`, ADR-047): there is no transport that can attest
 * presence yet.  Anything it ever returned would be discarded here, never shown and never kept.
 */
export async function readTotpSeed(m: VaultModel, node: string, entry: string, field?: string): Promise<void> {
  needsBroker(m, "totp.seed");
  await live.totpSeed(node, entry, field);
}

/** What {@link copyEntry} reports.  Never the value. */
export type CopyOutcome = { copied: true; clearAfterSeconds: number | null } | { copied: false; reason: "unavailable" };

type ShellCopy = (node: string, entry: string, field?: string) => Promise<{ copied: true; clearAfterSeconds: number | null }>;

/**
 * Copies ONE field's value to the clipboard WITHOUT the value entering the webview: the shell (`entry_copy`, src/lib/bridge.ts)
 * reveals it Rust-side, narrowed to the field `field` names, so no other field of the entry reaches the shell either (the same
 * audited path as a reveal, so every denial arrives unchanged), writes it with the concealed-clipboard markers and empties the
 * clipboard again after `clearAfterSeconds`.  The value is NEVER fetched into the page to be copied from there, and
 * `navigator.clipboard` is never used for a secret.  Without the Tauri shell (the demo vault of the headless gates) there is
 * nothing to copy with, and the answer says so.
 *
 * `copy` is injectable for tests only.
 */
export async function copyEntry(m: VaultModel, node: string, entry: string, field?: string, copy: ShellCopy = live.entryCopy): Promise<CopyOutcome> {
  if (m.kind !== "bridge") return { copied: false, reason: "unavailable" };
  const r = await copy(node, entry, field);
  return { copied: true, clearAfterSeconds: r.clearAfterSeconds };
}

/**
 * Read an entry's fields (`entry.get`: ids, labels, types, masking, never a value) into the model, for the entry detail to draw.
 * Rejects with the broker's refusal (`node_locked`, `not_found`) for the logic to route.  Resolves `undefined` when the source has
 * nothing of the kind or the login ended meanwhile.
 */
export async function loadEntryDetail(m: VaultModel, node: string, entry: string) {
  return m.loadDetail(node, entry);
}

/**
 * Show the fields that are not masked: ONE read of exactly those fields (`entry.reveal` with `fieldIds`), held for `windowMs`.  It is a
 * reveal like any other (audited, `reveal`-gated, an approval on a locked node), not a metadata read.  Resolves `true` only when every
 * value is held; `false` when the user moved on, hid the window or locked while the broker was answering, and the values were dropped.
 */
export async function revealUnmasked(m: VaultModel, node: string, entry: string, fields: string[], windowMs: number): Promise<boolean> {
  return m.revealMany(node, entry, fields, windowMs);
}
