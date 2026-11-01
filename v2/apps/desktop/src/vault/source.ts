/**
 * The seam between the model and the thing that answers its questions.
 *
 * `VaultModel` owns the state machine, the caches, the secret store and the subscriptions.  A `ModelSource` owns where the
 * data comes from.  There are two implementations:
 *
 *  - `BridgeSource` (bridge-source.ts): the real one.  Every call goes through src/lib/bridge.ts, and so to the broker.
 *    Used whenever the page runs inside the Tauri shell (and in the Playwright specs, which fake the shell's `invoke`).
 *  - `DemoSource` (demo-source.ts): an in-memory example vault, used only when there is no Tauri runtime at all in a
 *    development or test build (`vite dev`, vitest, `build-test/`).  A release build contains none of it
 *    (scripts/dc/verify-build.mjs fails the build if any of it is there): with no shell it answers "broker unreachable".
 *
 * A source speaks the VIEW vocabulary (`DNode`, `DEntry`, ...), never the wire's, so mapping bugs live in one file that
 * has unit tests, and the screens never see a bridge type.
 */
import type { DEntry, DEntryDetail, DGrant, DLink, DNode, DOrphan, DPending, DSealed, UnreadableCode } from "./types";

/** The login, as far as the model needs it (a subset of the bridge's `AuthState`). */
export interface AuthLite {
  locked: boolean;
  authenticated: boolean;
  /** `false` only on first run: there is no vault to unlock yet. */
  initialized: boolean;
  /** ADR-090: agent requests waiting for a person, from `vault.status` (absent = none, or a source that cannot say). */
  pendingApprovals?: number;
}

/** What a lock could confirm.  This process holds no login afterwards whatever it says. */
export interface LockResult {
  /** `true`: the broker answered the lock (or said the vault was already locked).  `false`: it could not be told, or refused. */
  confirmed: boolean;
  /** The error's code when not confirmed (never its message), else `null`. */
  code: string | null;
}

export interface GraphPart {
  /** Without the orphan node. */
  nodes: DNode[];
  /** Structural parent-to-child links only; grant edges are added by the model from {@link ModelSource.grants}. */
  links: DLink[];
  /** The registry's `kind: "orphan"` node, if any. */
  orphanNodeId: string | null;
  /**
   * The nodes the broker says are sealed and still restorable (`meta.sealed`).  ABSENT when the source cannot say (an agent login, a
   * non-Admin human, the example vault): the model then keeps the seals this session made.  `[]` means "none", and is authoritative.
   */
  sealed?: DSealed[];
}

export interface EntriesPart {
  entries: DEntry[];
  /** Echo it on every later mutation of an entry of this node, or the broker answers `conflict`. */
  generation: number;
  /** Set when the node's entries could NOT be listed by this login (and `entries` is `[]` only for that reason): the broker's reason. */
  unreadable?: UnreadableCode;
}

export interface ModelSource {
  readonly kind: "bridge" | "demo";
  status(): Promise<AuthLite>;
  /** Rejects with `two_factor_required` when a gate is enrolled; then call {@link gateVerify}. */
  unlock(passphrase: string): Promise<AuthLite>;
  gateVerify(code: string): Promise<AuthLite>;
  /**
   * Always ends with this process holding no login, even if the broker could not be told, and never rejects: a failure is
   * reported as `{ confirmed: false, code }` so the model can say so.  (A source that returns nothing is read as confirmed.)
   */
  lock(): Promise<LockResult | void>;
  graph(): Promise<GraphPart>;
  grants(): Promise<DGrant[]>;
  entries(node: string): Promise<EntriesPart>;
  /** The items of the orphaned node (names only; values are sealed). */
  orphans(): Promise<DOrphan[]>;
  /** Why the LAST {@link orphans} call returned nothing, when the orphaned node could not be listed by this login (else `null`).  Optional: only a source that can tell has it. */
  orphansUnreadable?(): UnreadableCode | null;
  pending(node: string): Promise<DPending[]>;
  /** The node's note as plain text; `""` when there is none; `null` when it cannot be read (no `notes` capability, node locked). */
  notes(node: string): Promise<string | null>;
  /**
   * One entry's fields without their values (`entry.get`): ids, labels, types, masking.  Rejects with the broker's refusal (`node_locked`,
   * `not_found`, ...), which the caller routes.  Optional: a source without it has no per-field metadata to show.
   */
  entryMeta?(node: string, entry: string): Promise<DEntryDetail>;
  /**
   * The plaintext of ONE field.  `field` is the field's id (`f_...`) and the reveal is narrowed to it, so no other field of the entry is
   * read; a number is a position in the entry's fields, for the example data that has no broker behind it.
   */
  reveal(node: string, entry: string, field: number | string): Promise<string>;
  /**
   * The plaintext of SEVERAL fields of one entry in one read (one audit record), by field id.  Used to show the fields that are not
   * masked without a click.  Optional: without it the model reveals them one at a time.
   */
  revealFields?(node: string, entry: string, fields: string[]): Promise<Array<{ id: string; value: string }>>;
}
