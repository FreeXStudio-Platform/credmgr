/**
 * The view model: the plain, synchronous data the screens read.
 *
 * Rules (spec B1, frozen for the wiring packages):
 *  - NOTHING in here is a secret.  A field has a label, a type and a `masked` flag; its value lives in the model's
 *    private plaintext store and is reached only through `VaultModel.plain()`.
 *  - A `DView` is REPLACED as a whole when the model refreshes.  Do not hold a reference across a refresh.
 *  - Node ids are stable keys; labels are what the user sees and may change.
 */

export type DNodeKind = "global" | "project" | "sub";
export type DSensitivity = "low" | "medium" | "high" | "critical";

export interface DNode {
  id: string;
  label: string;
  kind: DNodeKind;
  depth: number;
  parentId: string | null;
  counts: { entries: number; totp: number };
  /** `locked` is the NODE's lock (the login survives it); `twofa` is the node's second-factor policy. */
  gate: { locked: boolean; twofa: "none" | "enrolled" | "required" };
  /** `true` when the node hides its name from everyone but its owner (`privateNames`, ADR-083); this login is the owner and still sees it. */
  nameHidden?: boolean;
  /** `null` in every broker response today. */
  health: null;
  /** The node's note as plain text, or `null` while it is not loaded (or not readable).  Never rendered as HTML. */
  notes: string | null;
}

/**
 * One field of an entry (ADR-078).  What the broker says about it and nothing else: no value (that is reached only through the model's
 * private store).  `label` is the user's own free text and may be empty (the screens then say "field N").
 */
export interface DField {
  /** `f_` and 8 hex digits, minted by the broker.  Absent only on a placeholder that stands for an item whose fields are not read (an orphaned item). */
  id?: string;
  label: string;
  type: string;
  masked: boolean;
  /** `type` is the user's pin, not what inference says.  The screens send a type only when the user changes it. */
  typeOverridden?: boolean;
  maskedOverridden?: boolean;
}

export interface DEntry {
  id: string;
  name: string;
  type: string;
  /** `null` until the broker reports it (neutral border). */
  sensitivity: DSensitivity | null;
  /** Some field holds a TOTP seed. */
  totp: boolean;
  /** One line under the name, e.g. `api · high · rotated 2026-06-30`. */
  meta: string;
  /** How many fields the entry has, as `entry.list` counts them. */
  fieldCount: number;
  /**
   * The fields, when the source has them with the list.  The broker's list does not (labels are encrypted with the values): a
   * bridge entry has `[]` here and its fields are read on demand into {@link DEntryDetail} (`VaultModel.detail`).
   */
  fields: DField[];
}

/**
 * What `entry.get` says about one entry: the fields' ids, labels, types and masking, never a value.  Read when an entry is opened and
 * after every change to its fields; dropped when the vault locks.  The labels are the user's own text: they go on screen and nowhere else.
 */
export interface DEntryDetail {
  node: string;
  entry: string;
  name: string;
  type: string;
  sensitivity: DSensitivity | null;
  fieldCount: number;
  hasTotp: boolean;
  /** The node's generation when this was read; the model's `generation[node]` is the one to echo. */
  generation: number;
  /** The entry's type / sensitivity is the user's pin rather than inferred. */
  typeOverridden: boolean;
  sensitivityOverridden: boolean;
  modified: number;
  rotatedAt: number | null;
  expiresAt: number | null;
  /** In stored order; every one has an id. */
  fields: Array<DField & { id: string }>;
}

export interface DGrant {
  id: string;
  /** The node that RECEIVES access. */
  from: string;
  to: string;
  toEntry: string | null;
  /** Capabilities joined with ` · `. */
  scope: string;
  /** `never`, or an ISO date. */
  expires: string;
  /** Not in the broker's API: `—` for real grants. */
  lastUsed: string;
  reason: string;
}

export interface DLink {
  source: string;
  target: string;
  kind: "structural" | "grant";
}

/** An item in the orphaned (sealed) node.  `from` and `date` exist only in the development and test example vault; the broker lists names only. */
export interface DOrphan {
  id: string;
  name: string;
  from?: string;
  date?: string;
}

/**
 * A sealed node that can still be restored.  The broker lists them in `graph.snapshot` `meta.sealed` (ADR-080) for a human Admin, so the
 * list survives a lock and a restart.  Where the key is absent (an agent, the example vault) the write actions remember the ones THIS
 * session sealed (src/vault/actions/write.ts `sealNode`); the extra fields are what Settings' sealed rows read.
 */
export interface DSealed {
  id: string;
  label: string;
  /** Unix seconds the broker says the restore window ends.  Present ONLY when the broker's `node.seal` answer carried one; today it does not. */
  expiresAt?: number;
  /** Unix seconds the node was sealed, when the broker listed it (`meta.sealed`). */
  sealedAt?: number;
  [extra: string]: unknown;
}

/** An entry held in the locked-write tray.  `fields`, `by` and `when` are display helpers derived from the broker's item (src/vault/bridge-source.ts `mapPending`), not broker data. */
export interface DPending {
  id: string;
  node: string;
  name: string;
  type: string;
  sensitivity: string;
  fieldCount: number;
  created: number;
  fields: DField[];
  totp?: boolean;
  by?: string;
  when?: string;
}

/**
 * Why this login could not list a node's entries.  A node that answered one of these is NOT an empty node: its entries exist (the
 * snapshot counts them) and are only out of this login's reach, so the screens say that instead of "no entries".
 */
/** `two_factor_required`: the node's level is `always` and no second factor was given in the last five minutes (ADR-085): a list needs the step-up. */
export type UnreadableCode = "node_locked" | "node_access_denied" | "capability_not_held" | "two_factor_required";

export const isUnreadableCode = (code: string | null | undefined): code is UnreadableCode =>
  code === "node_locked" || code === "node_access_denied" || code === "capability_not_held" || code === "two_factor_required";

export interface DView {
  nodes: DNode[];
  links: DLink[];
  grants: DGrant[];
  /** Entries by node id.  A node in {@link DView.unreadable} has `[]` here, and that `[]` means "could not be listed". */
  entries: Record<string, DEntry[]>;
  /** The nodes whose entries this login could not list, by node id, with the broker's reason.  Absent = listed fine (possibly with none). */
  unreadable: Record<string, UnreadableCode>;
  orphans: DOrphan[];
  sealed: DSealed[];
  pending: DPending[];
}

export function emptyView(): DView {
  return { nodes: [], links: [], grants: [], entries: {}, unreadable: {}, orphans: [], sealed: [], pending: [] };
}

/** Where the model is in the session lifecycle. */
export type ModelStatus = "starting" | "broker-down" | "uninitialized" | "locked" | "unlocked";

/** What `refresh()` re-reads.  Everything is optional; an empty spec refreshes nothing. */
export interface RefreshSpec {
  /** The graph snapshot (nodes, structural links, counts, gates). */
  graph?: boolean;
  /** The grant list (and the grant edges of the graph). */
  grants?: boolean;
  /** Entry lists of these nodes. */
  nodes?: string[];
  /** The locked-write tray of every node. */
  pending?: boolean;
  /** The note of this node. */
  notes?: string;
  /**
   * Entries whose fields (`entry.get`) are read again: the detail the model holds for each is REPLACED, or dropped when the broker no
   * longer has the entry.  A node whose entry list was just re-read is not enough, because the list carries no labels.
   */
  details?: Array<{ node: string; entry: string }>;
}
