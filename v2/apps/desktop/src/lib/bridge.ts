/**
 * The typed client for the CredMgr desktop bridge — every `invoke()` the UI
 * can make, with the argument names and response shapes the broker actually
 * uses.
 *
 * This file is the **contract** between the front-end track and the Rust
 * bridge (`src-tauri/src/commands.rs`), not a UI component, which is why it
 * lives here and is owned by the bridge side. It is held to the Rust table by
 * `src-tauri/tests/ts_client.rs`: every command the bridge exposes must appear
 * here exactly once, with exactly its wire keys, and every broker error code
 * must appear in `BrokerErrorCode`. Edit the Rust side first; that guard then
 * tells you what to change here.
 *
 * Rules the screens inherit (`docs/19_FRONTEND_DELIVERY_SCOPE.md §3.2`):
 *
 * 1. **No session token ever reaches this layer.** Login is state held by the
 *    bridge; the auth calls return {@link AuthState} and nothing else.
 * 2. **`two_factor_required` is an error, not a state.** `vaultUnlock` rejects
 *    with `code === "two_factor_required"`; call `vaultGateVerify` next.
 * 3. **Broker error codes arrive verbatim** — the same words `auditTail`
 *    records. Switch on {@link BridgeError.code}.
 * 4. **Drive the lock screen from results, never a UI flag.** The idle
 *    auto-lock pushes nothing; a `vault_locked` rejection or
 *    `meta.vaultLocked` is how you learn of it.
 * 5. **Keep `generation`.** Every mutation of an existing entry echoes the
 *    value `entryList` last returned, or the broker answers `conflict`.
 * 6. **Refetch recent activity after every successful mutation** (§6.4) —
 *    there is no push channel.
 * 7. **An entry holds fields (ADR-078).** `entryGet` lists them (id, label, type,
 *    masking — never a value); `entryReveal(node, entry, fieldIds)` reads values, and
 *    `EntryReveal.value` exists only when exactly one field came back. Save what
 *    `fieldsPreview` showed: the preview is the contract. Send `entryType` and
 *    `sensitivity` only when the user picked one, and a field's `type` / `masked` only
 *    where `typeOverridden` / `maskedOverridden` say it is a pin — otherwise every entry
 *    is pinned to what inference said on the day it was saved.
 *
 * Four operations are wired but refused broker-side with `presence_required`
 * on every call until a transport can attest presence (ADR-047, F-8):
 * `totpSeed`, `nodeReparent`, `grantCreate`, `auditGet`. Design their screens
 * against that refusal, not against a success body.
 */

import { invoke } from "@tauri-apps/api/core";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/** Every `"error"` discriminant `credmgrd` can send (`protocol.rs::to_wire`). */
export type BrokerErrorCode =
  | "node_access_denied"
  | "two_factor_required"
  | "approval_pending"
  | "conflict"
  | "vault_locked"
  | "node_locked"
  | "wrong_passphrase"
  | "malformed_request"
  | "capability_not_held"
  | "not_found"
  | "entry_exists"
  | "internal"
  | "presence_required"
  | "archive_expired"
  | "approval_denied"
  | "rate_limited"
  | "gate_verification_failed"
  | "gate_not_enrolling"
  | "entry_removal_expired"
  | "not_undoable"
  | "vault_already_initialized"
  | "vault_inside_git_working_tree"
  | "vault_init_not_pending"
  | "recovery_code_mismatch"
  | "session_expired";

/** Codes the bridge raises itself, when the broker was never reached or answered nonsense. */
export type BridgeLocalCode =
  | "broker_unreachable"
  | "malformed_response"
  | "worker_failed"
  | "encode_failed"
  | "platform_unsupported"
  /** The OS clipboard could not be written (`entryCopy`, `copyText`). */
  | "clipboard_failed"
  /** `copyText` was given more than 4096 bytes. */
  | "text_too_large"
  /**
   * `entryCopy` was asked to copy an entry with several fields without a field id.
   * Nothing was copied. Pass the id of the field to copy (from {@link entryGet}).
   */
  | "field_required"
  /**
   * `fieldsPreview` was given something it cannot preview: both `text` and `fields`, neither,
   * or a field the broker would refuse. The message names an index, never a label or a value.
   */
  | "invalid_fields"
  /** `appIconSet` was given an id outside {@link APP_ICON_IDS}. Nothing changed. */
  | "unknown_icon"
  /** `appIconSet`: the OS or the window refused the icon. */
  | "icon_failed";

/** What every command rejects with (`src-tauri/src/error.rs::BridgeError`). */
export interface BridgeError {
  /** `broker` = a real denial; `transport` = credmgrd not reachable. */
  source: "transport" | "protocol" | "broker" | "bridge";
  code: BrokerErrorCode | BridgeLocalCode | (string & {});
  message: string;
  /** The broker's own denial body — `rule`, `remedy`, `expectedGeneration`… */
  detail?: Record<string, unknown>;
}

/** Narrow an unknown rejection to a {@link BridgeError}. */
export function isBridgeError(e: unknown): e is BridgeError {
  return (
    typeof e === "object" && e !== null && "code" in e && "source" in e && "message" in e
  );
}

// ---------------------------------------------------------------------------
// Shared shapes (`crates/brokerd/src/ops.rs`, `docs/19 §4`)
// ---------------------------------------------------------------------------

export type Capability = "list" | "read" | "reveal" | "create" | "update" | "notes" | "admin";
export type NodeKind = "global" | "project" | "sub" | "orphan";

/** The login, as the webview may know it — never the credential behind it. */
export interface AuthState {
  locked: boolean;
  authenticated: boolean;
  /**
   * Whether a vault exists to unlock (ADR-077). `false` only on first run:
   * route to the create-a-vault screen, not to a lock screen with nothing
   * behind it. Reported by `vaultStatus`; every other auth call means a vault
   * answered, so it is `true` there.
   */
  initialized: boolean;
  /**
   * How many agent requests are waiting for a person (ADR-090): a bare count from `vault.status`, left out when 0. No names;
   * {@link vaultApprovalGet} says what they are.
   */
  pendingApprovals?: number;
}

export interface Whoami {
  node: string;
  capabilities: Capability[];
  /** Reachable nodes only — never the whole registry (F-6). */
  reachable: string[];
}

export interface GraphNode {
  id: string;
  label: string;
  kind: NodeKind;
  depth: number;
  parentId: string | null;
  /** Exactly two numbers; there is no third. */
  counts: { entries: number; totp: number };
  gate: { locked: boolean; twofa: "none" | "enrolled" | "required" };
  /**
   * ADR-083: `true` on the OWNER's row of a node that hides its name (`privateNames`); the owner still sees every name, this only
   * says the node is hidden from everyone else. Absent otherwise.
   */
  nameHidden?: boolean;
  /** `null` in every response today — render a sane default, not an error. */
  health: unknown | null;
}

export interface GraphLink {
  source: string;
  target: string;
  /** Structural parent→child only; grant edges come from {@link grantList}. */
  kind: "structural";
  direction: "down";
}

export interface GraphSnapshot {
  nodes: GraphNode[];
  links: GraphLink[];
  /** Renders while locked; `vaultLocked` is how an idle auto-lock is noticed. */
  meta: {
    generatedAt: number;
    vaultLocked: boolean;
    /**
     * ADR-080: the nodes that are sealed and still restorable (id, label, the window — nothing
     * else), for a human session that may restore. Absent for an agent; `[]` when nothing is sealed.
     */
    sealed?: SealedNode[];
  };
}

/** One sealed node in `GraphSnapshot.meta.sealed` (ADR-080). */
export interface SealedNode {
  id: string;
  label: string;
  /** Unix seconds the node was sealed. */
  sealedAt: number;
  /** Unix seconds the 7-day restore window closes (`sealedAt` + 7 days). */
  expiresAt: number;
}

/**
 * One entry's plaintext manifest metadata (ADR-077): no label, no value, no
 * hash. Present for exactly the entries `ids` names.
 */
export interface EntryListRow {
  id: string;
  name: string;
  /** The inferred entry type. */
  type: string;
  sensitivity: "low" | "medium" | "high" | "critical";
  fieldCount: number;
  /** ADR-080: the entry carries a TOTP seed (so a list can mark it without opening it). */
  hasTotp: boolean;
  /** Unix seconds of the last change of any kind. */
  modified: number;
  /** Unix seconds of the last rotation; `null` if never rotated. */
  rotatedAt: number | null;
  /** Unix seconds the entry expires; `null` if it does not. */
  expiresAt: number | null;
}

export interface EntryList {
  node: string;
  ids: string[];
  names: string[];
  /**
   * The same entries with their manifest metadata (ADR-077). The broker returns it to human
   * sessions only — an agent/MCP caller gets `ids` and `names` — and every bridge session is a
   * human one, so here it is always present.
   */
  entries: EntryListRow[];
  /** Keep it: every later mutation of an entry here must echo it (F-9). */
  generation: number;
}

// --- Fields (ADR-078) --------------------------------------------------------

/** The wire names of `credmgr_core::inference::FieldType`. */
export type FieldTypeName =
  | "password"
  | "api-key"
  | "private-key"
  | "seed-phrase"
  | "totp-seed"
  | "username"
  | "host"
  | "port"
  | "url"
  | "certificate"
  | "text";

/** The wire names of `credmgr_core::inference::EntryType` (`note-only` is the old spelling of `note`). */
export type EntryTypeName =
  | "server"
  | "database"
  | "api"
  | "wallet"
  | "login"
  | "ssh"
  | "certificate"
  | "token"
  | "totp"
  | "env-bundle"
  | "note"
  | "other";

export type SensitivityName = "low" | "medium" | "high" | "critical";

/**
 * A field as the screen supplies it (create, add). Free-text `label` (up to 200
 * characters, one line, empty allowed — there is no fixed vocabulary); `value`
 * verbatim, never trimmed. `type` / `masked` are the user's **pins**: leave them out
 * to follow inference.
 */
export interface FieldInput {
  label: string;
  value: string;
  type?: FieldTypeName;
  masked?: boolean;
}

/** An element of an update/rotate `fields` list: an `id` keeps a field's identity, none adds a field. */
export interface FieldReplace extends FieldInput {
  id?: string;
}

/**
 * A change to one field. At least one key. `type` / `masked` take `"auto"` to go back to
 * inferring; JSON `null` is refused (the bridge drops nulls on the way in, so `"auto"` is
 * the one spelling that works everywhere).
 */
export interface FieldPatch {
  label?: string;
  value?: string;
  type?: FieldTypeName | "auto";
  masked?: boolean | "auto";
}

/** A field without its value (`entryGet`). */
export interface FieldMeta {
  /** `f_` and 8 hex digits; minted by the broker, stable for the field's life. A pre-ADR-078 entry's one field is `f_00000000`. */
  id: string;
  /** Free text; `""` is allowed and shows as "field N". */
  label: string;
  /** The effective type: the pin if there is one, else inferred. */
  type: FieldTypeName;
  /** The effective masking: the pin, else the type's default. */
  masked: boolean;
  typeOverridden: boolean;
  maskedOverridden: boolean;
}

/** `entryGet`'s answer: an entry's metadata and its fields' labels — never a value. */
export interface EntryMeta {
  node: string;
  entry: string;
  name: string;
  ref: number;
  /** The entry's type: the pin if there is one, else inferred from its fields. */
  type: EntryTypeName;
  sensitivity: SensitivityName;
  fieldCount: number;
  /** Some field is a TOTP seed. */
  hasTotp: boolean;
  modified: number;
  rotatedAt: number | null;
  expiresAt: number | null;
  /** The node's generation; every mutation of this entry echoes it (F-9). */
  generation: number;
  typeOverridden: boolean;
  sensitivityOverridden: boolean;
  fields: FieldMeta[];
}

/** One revealed field. The value is the plaintext: do not log, cache, or retain it. */
export interface RevealedField {
  id: string;
  label: string;
  value: string;
  type: FieldTypeName;
  masked: boolean;
}

export interface EntryReveal {
  node: string;
  entry: string;
  /** The fields asked for (all of them without `fieldIds`), in stored order. Plaintext. */
  fields: RevealedField[];
  /**
   * The plaintext of the one field — present **only when exactly one field was
   * returned** (a one-field entry, or `fieldIds` naming one), absent otherwise. Check
   * `fields.length`, not this.
   */
  value?: string;
}

/** What a mutation of an entry's fields answers. */
export interface FieldsChanged {
  node: string;
  entry: string;
  /** The node's new generation. */
  generation: number;
  fieldCount: number;
  /** Every field id, in the order they now stand. */
  fieldIds: string[];
  /** The audit record this change wrote (the broker's envelope `audit`, passed through by the shell for changing ops only; absent when the record could not be written). */
  audit?: string;
}

export interface AuditRecord {
  id: string;
  timestamp: number;
  actor: string;
  action: string;
  /** Present for human sessions; agent sessions see the four fields above only. */
  node?: string | null;
  decision?: "allow" | "deny" | string;
  detail?: unknown;
  entry?: string | null;
  generation?: number | null;
}

export interface PendingItem {
  entry: string;
  name: string;
  type: string;
  sensitivity: string;
  fieldCount: number;
  created: number;
}

export type GrantTarget =
  | { kind: "node"; nodeId: string }
  | { kind: "entry"; nodeId: string; entryId: string };

export interface Grant {
  id: string;
  /** The node that RECEIVES access. */
  from: string;
  to: GrantTarget;
  direction: "one-way" | "mutual";
  scope: Capability[];
  expiresAt: number | null;
  reason: string;
}

export interface NodeProblem {
  node: string | null;
  detail: string;
}

/** Entry restore / removal-undo answer (`do_entry_restore`). */
export interface EntryRestored {
  node: string;
  entry: string;
  restoredName: string;
  generation: number;
  /** The audit record this change wrote (the broker's envelope `audit`, passed through by the shell for changing ops only; absent when the record could not be written). */
  audit?: string;
}

/** Rotation-undo answer (`undo_rotate`). */
export interface RotationUndone {
  node: string;
  entry: string;
  generation: number;
  undoneToGeneration: number;
  /** The audit record this change wrote (the broker's envelope `audit`, passed through by the shell for changing ops only; absent when the record could not be written). */
  audit?: string;
}

/**
 * What `entry.undo` answers for a change to an entry's fields (ADR-086): `ok`, what was restored (`action` is the
 * undone call, e.g. `field.remove`; `fieldCount` is how many fields the entry has again), the node's new generation and the one
 * it went back to. The undone value is not in it.
 */
export interface FieldUndone {
  ok: true;
  restored: { action: string; entry: string; fieldCount?: number; name?: string };
  generation: number;
  undoneToGeneration: number;
  /** The audit record this change wrote (the broker's envelope `audit`, passed through by the shell for changing ops only; absent when the record could not be written). */
  audit?: string;
}

// ---------------------------------------------------------------------------
// Authentication and vault state — hand-written bridge commands
// ---------------------------------------------------------------------------

export const vaultStatus = () => invoke<AuthState>("vault_status");

/** Rejects with `two_factor_required` when a gate is enrolled — then call {@link vaultGateVerify}. */
export const vaultUnlock = (passphrase: string) =>
  invoke<AuthState>("vault_unlock", { passphrase });

export const vaultGateVerify = (code: string) =>
  invoke<AuthState>("vault_gate_verify", { code });

export const vaultLock = () => invoke<AuthState>("vault_lock");

export const whoami = () => invoke<Whoami>("whoami");

export const graphSnapshot = () => invoke<GraphSnapshot>("graph_snapshot");

export const entryList = (node: string) => invoke<EntryList>("entry_list", { node });

/**
 * May reject with `approval_pending` — a one-tap approval path, not a failure (ADR-042).
 * `fieldIds` narrows the answer to those fields (each must exist, else `not_found` and no
 * partial answer); leave it out to reveal every field. Show an unmasked field by revealing it
 * (an audited, `reveal`-gated read) — {@link entryGet} never carries a value.
 */
export const entryReveal = (node: string, entry: string, fieldIds?: string[]) =>
  invoke<EntryReveal>("entry_reveal", { node, entry, fieldIds });

/**
 * One entry's metadata (ADR-078), **never a value**: its type, sensitivity, generation and
 * each field's id, label, type and masking. Needs the vault *and* the node unlocked
 * (`vault_locked` / `node_locked`, no approval path — labels are encrypted with the values).
 * A tray (pending) entry is `not_found`.
 */
export const entryGet = (node: string, entry: string) =>
  invoke<EntryMeta>("entry_get", { node, entry });

// ---------------------------------------------------------------------------
// Vault bootstrap (ADR-061) — the first-run screen
// ---------------------------------------------------------------------------

/** Shows the recovery code once; make the human retype it into {@link vaultInitConfirm}. */
export const vaultInitBegin = (passphrase: string) =>
  invoke<{ recoveryCode: string }>("vault_init_begin", { passphrase });

export const vaultInitConfirm = (recoveryCode: string) =>
  invoke<{ initialized: true }>("vault_init_confirm", { recoveryCode });

// ---------------------------------------------------------------------------
// Gate enrolment (`07_TWO_FACTOR.md §4`)
// ---------------------------------------------------------------------------

/**
 * Replacing a gate already in force needs its second factor, fresh — call within the
 * elevation window a successful {@link vaultGateVerify} opens, or this rejects with
 * `two_factor_required` (ADR-064). A first enrolment needs nothing extra.
 */
export const vaultGateEnrollBegin = () =>
  invoke<{ otpauthUri: string }>("vault_gate_enroll_begin");

/** Returns the recovery codes exactly once. Over a confirmed gate, completes a re-enrolment. */
export const vaultGateEnrollConfirm = (code: string) =>
  invoke<{ recoveryCodes: string[] }>("vault_gate_enroll_confirm", { code });

/**
 * The last door (ADR-064): passphrase + the printed root recovery code reset a lost
 * gate. Does not unlock — call {@link vaultUnlock} next, then offer re-enrolment.
 * A wrong pair rejects with `wrong_passphrase`, never saying which factor failed.
 */
export const vaultGateRecover = (passphrase: string, recoveryCode: string) =>
  invoke<{ gateReset: boolean }>("vault_gate_recover", { passphrase, recoveryCode });

// ---------------------------------------------------------------------------
// Locked-write tray, approvals, per-node lock
// ---------------------------------------------------------------------------

export const vaultPendingList = (node: string) =>
  invoke<{ node: string; pending: PendingItem[] }>("vault_pending_list", { node });

export const vaultPendingAccept = (node: string, entry: string) =>
  invoke<{ node: string; entry: string; accepted: true; generation: number; audit?: string }>(
    "vault_pending_accept",
    { node, entry },
  );

export const vaultPendingDiscard = (node: string, entry: string) =>
  invoke<{ node: string; entry: string; discarded: true; audit?: string }>("vault_pending_discard", {
    node,
    entry,
  });

/**
 * With `passphrase` (and `code`, the authenticator code, when two-factor is on) the decision is
 * authorised by the unlock factors and works only while the vault is locked (ADR-088); the answer then
 * carries `authorisedBy: "factors"`. A recovery code is not accepted as `code`. No screen sends them yet.
 */
export const vaultApprovalDecide = (
  request: string,
  approved: boolean,
  passphrase?: string,
  code?: string,
) =>
  invoke<{
    request: string;
    node: string;
    entry: string;
    approved: boolean;
    authorisedBy?: "factors";
    audit?: string;
  }>("vault_approval_decide", { request, approved, passphrase, code });

/** One waiting request, as `vault.approval_get` describes it (ADR-090). */
export interface ApprovalRequest {
  request: string;
  /** The node id and the entry id: always present. A node whose name is private has an id that says nothing (ADR-091). */
  node: string;
  entry: string;
  /** Null when the broker withholds it (a `privateNames` node on a locked vault) or does not have it in memory. */
  nodeLabel: string | null;
  entryName: string | null;
  /** The op that asked: always `entry.reveal`. */
  command: string;
  state: "pending" | "approved" | "denied";
  /** Seconds left before the request defaults to denied. */
  expiresIn: number;
  /** Unix seconds. */
  requestedAt: number;
  /** True when the names are withheld because the node's name is private. */
  nameHidden?: true;
  /** Only to the owner's login session. */
  cwd?: string | null;
}

/**
 * What a waiting request asks for (ADR-090). With a `request` id: that one, or `not_found` once it expired or was decided and taken.
 * Without: `{pending: [...]}`, every request still waiting, oldest first. Read-only and answered on a locked vault too; on an unlocked
 * vault only the owner's login may ask (`capability_not_held` otherwise). Not an MCP tool.
 */
export const vaultApprovalGet = (request?: string) =>
  invoke<ApprovalRequest | { pending: ApprovalRequest[] }>("vault_approval_get", { request });

/** `locked` here is the node's, not the vault's — the login survives it. */
export const vaultNodeLock = (node: string) =>
  invoke<{ node: string; locked: true }>("vault_node_lock", { node });

export const vaultNodeUnlock = (node: string) =>
  invoke<{ node: string; locked: false }>("vault_node_unlock", { node });

// ---------------------------------------------------------------------------
// Nodes
// ---------------------------------------------------------------------------

/** Bare node ids this scope may list — use {@link graphSnapshot} for node objects. */
export const nodeList = () => invoke<{ nodes: string[] }>("node_list");

/** `workdirs` optionally binds directories that scope an agent to the node (ADR-066). */
export const nodeCreate = (id: string, label: string, parentId: string, workdirs?: string[]) =>
  invoke<{ node: string; created: true; audit?: string; warnings?: NameWarning[] }>("node_create", { id, label, parentId, workdirs });

/** Replaces a node's bound directories — absolute, existing, one directory to one node. `[]` clears. */
export const nodeSetWorkdirs = (node: string, workdirs: string[]) =>
  invoke<{ node: string; workdirs: string[]; audit?: string }>("node_set_workdirs", { node, workdirs });

/** Renames a node (ADR-071): the id never changes, only the label — trimmed, 1–120 characters. */
export const nodeUpdate = (node: string, label: string) =>
  invoke<{ node: string; label: string; audit?: string; warnings?: NameWarning[] }>("node_update", { node, label });

/** Every field optional; `lockAfterSeconds: null` clears the per-node timer. */
export interface NodePolicyPatch {
  siblingVisibility?: "shared" | "isolated";
  descendantRead?: boolean;
  requireTwoFactor?: "never" | "reveal" | "always";
  lockAfterSeconds?: number | null;
  privateNames?: boolean;
  agentAccess?: "read-write" | "read-only" | "none";
}

/**
 * Changes a node's policy (ADR-071). `reason` is mandatory and lands in the audit record.
 * Turning on `descendantRead`, or `siblingVisibility: "shared"`, widens reach and answers
 * `presence_required` until presence can be attested; the patch is then applied not at all.
 * `notEnforced` names the fields that are stored but not yet acted on.
 */
export const nodePolicy = (node: string, reason: string, policy: NodePolicyPatch) =>
  invoke<{
    node: string;
    policy: Required<NodePolicyPatch>;
    changed: string[];
    reason: string;
    notEnforced: string[];
    audit?: string;
  }>("node_policy", { node, reason, policy });

/**
 * A node's note (ADR-072): markdown, `""` when there is none. Needs the `notes` capability,
 * which `read` never implies, and the node unlocked. `generation` (ADR-077) is the manifest
 * generation a following `notesWrite` must be based on, so a caller with `notes` but not `list`
 * can write without `entryList`.
 */
export const notesRead = (node: string) =>
  invoke<{ node: string; markdown: string; modified: number | null; generation: number }>(
    "notes_read",
    { node },
  );

/**
 * Replaces a node's note (≤ 64 KiB; `""` removes it). `generation` is the manifest generation
 * last read — a mismatch answers `conflict`.
 */
export const notesWrite = (node: string, markdown: string, generation: number) =>
  invoke<{ node: string; generation: number; modified: number | null; cleared: boolean; audit?: string }>(
    "notes_write",
    { node, markdown, generation },
  );

export const nodeSeal = (node: string) =>
  invoke<{ node: string; sealed: true; audit?: string }>("node_seal", { node });

export const nodeRestore = (node: string) =>
  invoke<{ node: string; restored: true; audit?: string }>("node_restore", { node });

/** Refused with `presence_required` today (F-8). `reason` must be ≥ 8 characters. */
export const nodeReparent = (node: string, newParent: string, reason: string) =>
  invoke<Record<string, unknown>>("node_reparent", { node, newParent, reason });

// ---------------------------------------------------------------------------
// Grants
// ---------------------------------------------------------------------------

/** Also the data source for the graph's dashed grant edges. */
export const grantList = () => invoke<{ grants: Grant[] }>("grant_list");

/**
 * Refused with `presence_required` today (ADR-047). `scope` may hold only
 * `read`, `reveal`, `notes`; `reason` must be ≥ 8 characters. Pro-only in the UI.
 */
export const grantCreate = (
  from: string,
  to: GrantTarget,
  scope: Array<"read" | "reveal" | "notes">,
  reason: string,
) => invoke<Record<string, unknown>>("grant_create", { from, to, scope, reason });

/** In both modes — revocation is safety, not a lever. */
export const grantRevoke = (id: string) =>
  invoke<{ id: string; revoked: true; audit?: string }>("grant_revoke", { id });

// ---------------------------------------------------------------------------
// Entries — every call below that changes an existing entry takes `generation`
// ---------------------------------------------------------------------------

/** What `entryCreate` answers; `pending: true` (and no generation) when the vault is locked — F-1's tray. */
export type EntryCreated =
  | { node: string; entry: string; pending: true; fieldCount: number; fieldIds: string[]; audit?: string; warnings?: NameWarning[] }
  | {
      node: string;
      entry: string;
      pending: false;
      generation: number;
      fieldCount: number;
      fieldIds: string[];
      audit?: string;
      warnings?: NameWarning[];
    };

/** A warning the broker attaches to an accepted name (ADR-084). Anything else it may add in future is ignored by the window. */
export type NameWarning = "mixed_script_name";

/**
 * Creates an entry (ADR-078): give **`value`** (a one-field entry; `label` names the field,
 * default "value") **or `fields`** (several, in the order to keep) — not both, not neither.
 * `entryType` / `sensitivity` pin the entry's own type / sensitivity: send them only when the
 * user picked one, never the inferred value. Works while the vault is locked.
 */
export const entryCreate = (
  node: string,
  name: string,
  value?: string,
  label?: string,
  fields?: FieldInput[],
  entryType?: EntryTypeName | "auto",
  sensitivity?: SensitivityName | "auto",
) =>
  invoke<EntryCreated>("entry_create", {
    node,
    name,
    value,
    label,
    fields,
    entryType,
    sensitivity,
  });

/** One item of {@link entryCreateBatch}: the body of {@link entryCreate} plus its `name`. */
export interface EntryCreateItem {
  name: string;
  value?: string;
  label?: string;
  fields?: FieldInput[];
  entryType?: EntryTypeName | "auto";
  sensitivity?: SensitivityName | "auto";
}

/**
 * Creates many entries in one node (ADR-073) — `.env` import, a many-entry paste, and (with
 * `fieldsPreview`'s `split`) one entry per `///` block. 1–500 entries, 64 MiB in all; every item
 * is validated and every name checked before anything is written. `complete: false` means a
 * write failed part-way; `created` lists what was made (and saved) before it.
 */
export const entryCreateBatch = (node: string, entries: EntryCreateItem[]) =>
  invoke<{
    node: string;
    created: { name: string; entry: string; pending: boolean; fieldCount: number }[];
    complete: boolean;
    failed: { index: number; name: string; error: string } | null;
    total: number;
    generation: number | null;
    audit?: string;
    warnings?: NameWarning[];
  }>("entry_create_batch", { node, entries });

/**
 * Changes an entry (ADR-078). `value` replaces one field's value — the only field, or the one
 * `field` (an id) names; on a several-field entry without `field` the broker refuses. `label`
 * renames that field. `fields` instead replaces the whole list (an `id` keeps a field's identity;
 * fields left out are dropped) and excludes `value` / `label` / `field`. `entryType` /
 * `sensitivity` set or (`"auto"`) clear the entry's pins. Keeps no history; for that, rotate or
 * use the `field*` calls.
 */
export const entryUpdate = (
  node: string,
  entry: string,
  value: string | undefined,
  generation: number,
  label?: string,
  field?: string,
  fields?: FieldReplace[],
  entryType?: EntryTypeName | "auto",
  sensitivity?: SensitivityName | "auto",
) =>
  invoke<FieldsChanged>("entry_update", {
    node,
    entry,
    value,
    generation,
    label,
    field,
    fields,
    entryType,
    sensitivity,
  });

/** {@link entryUpdate}'s body, keeping the previous envelope as history (undoable); stamps `rotatedAt`. */
export const entryRotate = (
  node: string,
  entry: string,
  value: string | undefined,
  generation: number,
  label?: string,
  field?: string,
  fields?: FieldReplace[],
  entryType?: EntryTypeName | "auto",
  sensitivity?: SensitivityName | "auto",
) =>
  invoke<FieldsChanged & { rotatedAt: number }>("entry_rotate", {
    node,
    entry,
    value,
    generation,
    label,
    field,
    fields,
    entryType,
    sensitivity,
  });

/**
 * Adds fields (ADR-078): appended, or inserted at `position` (0 is first) — adding never
 * replaces. Retains history; {@link entryUndo} reverses it. `added` is the ids minted, in order.
 */
export const fieldAdd = (
  node: string,
  entry: string,
  generation: number,
  fields: FieldInput[],
  position?: number,
) =>
  invoke<FieldsChanged & { added: string[] }>("field_add", {
    node,
    entry,
    generation,
    fields,
    position,
  });

/** Changes one field (ADR-078). Retains history. A changed value or label re-infers an unpinned type. */
export const fieldUpdate = (
  node: string,
  entry: string,
  generation: number,
  field: string,
  patch: FieldPatch,
) => invoke<FieldsChanged>("field_update", { node, entry, generation, field, patch });

/** Removes one field (ADR-078). The last field cannot go: `malformed_request`. Retains history. */
export const fieldRemove = (node: string, entry: string, generation: number, field: string) =>
  invoke<FieldsChanged>("field_remove", { node, entry, generation, field });

/** Reorders the fields (ADR-078): `order` lists every current field id exactly once. Retains history. */
export const fieldReorder = (node: string, entry: string, generation: number, order: string[]) =>
  invoke<FieldsChanged>("field_reorder", { node, entry, generation, order });

/**
 * Creates one multi-field entry — {@link entryCreate} with a `fields` list and the pins, if
 * any, the user chose. Convenience only; it calls the same command.
 */
export const entryCreateFields = (
  node: string,
  name: string,
  fields: FieldInput[],
  pins?: { entryType?: EntryTypeName | "auto"; sensitivity?: SensitivityName | "auto" },
) => entryCreate(node, name, undefined, undefined, fields, pins?.entryType, pins?.sensitivity);

/** Changes one field's value — {@link entryUpdate} with `field`. Convenience only. */
export const fieldSetValue = (
  node: string,
  entry: string,
  field: string,
  value: string,
  generation: number,
) => entryUpdate(node, entry, value, generation, undefined, field);

/** Enters the 7-day recovery window (ADR-048). */
export const entryRemove = (node: string, entry: string, generation: number) =>
  invoke<{ node: string; entry: string; removed: true; generation: number; audit?: string }>("entry_remove", {
    node,
    entry,
    generation,
  });

export const entryRestore = (
  node: string,
  entry: string,
  generation: number,
  mode?: "replace" | "keep-both",
) => invoke<EntryRestored>("entry_restore", { node, entry, generation, mode });

/**
 * `id` is an audit record id; only a rotate, a removal or a field edit (`field*`, ADR-078) is undoable, a field edit for seven days
 * (then `not_undoable`, ADR-086). `generation` is the node's CURRENT generation. The id of the call being undone is the `audit`
 * member of that call's own answer (the shell passes it through for every changing op, ADR-091), so no search of {@link auditTail} is needed.
 */
export const entryUndo = (
  node: string,
  id: string,
  generation: number,
  mode?: "replace" | "keep-both",
) => invoke<EntryRestored | RotationUndone | FieldUndone>("entry_undo", { node, id, generation, mode });

// ---------------------------------------------------------------------------
// TOTP, search, audit
// ---------------------------------------------------------------------------

/**
 * The current code of a stored TOTP seed. On an entry with several fields, `field` (an id)
 * names the one holding the seed; without it the seed is the only field, else the single
 * TOTP-seed field, else the call rejects with `malformed_request` (ADR-078).
 */
export const totpCode = (node: string, entry: string, field?: string) =>
  invoke<{ node: string; entry: string; code: string }>("totp_code", { node, entry, field });

/** Refused with `presence_required` today, whichever field is meant. Human-only; never an MCP tool. */
export const totpSeed = (node: string, entry: string, field?: string) =>
  invoke<Record<string, unknown>>("totp_seed", { node, entry, field });

/** Results the caller may not see are omitted silently — never a denial. */
export const search = (term: string) =>
  invoke<{ results: Array<{ node: string; id: string; name: string }> }>("search", { term });

/** `limit` defaults to 50 broker-side, clamped to 1…500. */
export const auditTail = (limit?: number) =>
  invoke<{ records: AuditRecord[] }>("audit_tail", { limit });

/** Refused with `presence_required` today (ADR-047). */
export const auditGet = (id: string) => invoke<AuditRecord>("audit_get", { id });

// ---------------------------------------------------------------------------
// Maintenance
// ---------------------------------------------------------------------------

export const maintenanceVerify = () =>
  invoke<{ ok: boolean; nodesChecked: number; errors: NodeProblem[]; warnings: NodeProblem[] }>(
    "maintenance_verify",
  );

/**
 * `apply` defaults to true broker-side; `rebuildRegistry` needs `passphrase` and Admin.
 * `purgeExpiredSeals` (ADR-089) destroys the retained originals of nodes sealed more than seven days
 * ago - the fixes then say `purged-expired-seal`; with `apply: false` it lists `would-purge-expired-seal`.
 */
export const maintenanceDoctor = (
  apply?: boolean,
  rebuildRegistry?: boolean,
  passphrase?: string,
  purgeExpiredSeals?: boolean,
) =>
  invoke<{
    applied: boolean;
    fixCount: number;
    fixes: Array<Record<string, unknown>>;
    unfixable: NodeProblem[];
  }>("maintenance_doctor", { apply, rebuildRegistry, passphrase, purgeExpiredSeals });

/**
 * `retain` defaults to 14 broker-side. `pruned` is the NAMES of the older archives removed (an
 * array — it was typed as a count until C1 found the mismatch against the real broker).
 */
export const maintenanceBackup = (passphrase: string, retain?: number) =>
  invoke<{ path: string; retain: number; pruned: string[] }>("maintenance_backup", {
    passphrase,
    retain,
  });

/** What `maintenanceRotateRoot` answers (ADR-076). `recoveryCode` is the new root recovery code. */
export type RotateRootResult = {
  rotated: true;
  /** Shown once, never stored by the bridge. The previous code stops working at once. */
  recoveryCode: string;
  /** Registry nodes whose private key was re-wrapped under the new root key. */
  nodesRewrapped: number;
  vaultGeneration: number;
  filesReplaced: number;
  /** Audit tips, seal archives, removed-entry records and rotation snapshots re-signed. */
  artifactsResigned: number;
  /**
   * `true` when the rotation committed (so the new key and `recoveryCode` are
   * already the live ones) but moving the last files into place failed: the
   * vault has locked itself and the next unlock finishes the move. Show the
   * recovery code regardless — this is the only time it is ever returned.
   */
  completionPending: boolean;
  /**
   * Artefacts that did not verify under the old key and were deliberately left
   * untouched (a tampered audit month, say) — they keep failing verification.
   */
  notResigned: Array<{ kind: string; id: string; reason: string }>;
};

/**
 * Replaces the root key: a new key, every node key re-wrapped, both root wraps
 * rewritten, every signed file signed again, and a **new root recovery code**
 * (`RotateRootResult.recoveryCode`) that must be shown once and saved. `passphrase`
 * is the vault passphrase again — proven first, and what the new wrap is made from.
 * Human-only; never an MCP tool.
 *
 * Refused with `presence_required` today (after `two_factor_required` when a
 * gate is enrolled and not freshly verified): `04_CRYPTO_AND_KEYS.md §6` asks
 * for presence and no transport can attest it yet (ADR-047). Design the screen
 * against that refusal, not against a success body.
 */
export const maintenanceRotateRoot = (passphrase: string) =>
  invoke<RotateRootResult>("maintenance_rotate_root", { passphrase });

/** What `utilGenerate` answers (ADR-087). */
export type GeneratedPassword = {
  /** Made in the broker. Show it masked; it enters a field only through the broker, never the clipboard unmasked. */
  value: string;
  length: number;
  symbols: boolean;
  pronounceable: boolean;
  /** An estimate: length × log₂ of the pool (pronounceable counts consonants and vowels separately). */
  entropyBits: number;
};

/**
 * Makes a password in the broker, never in page JavaScript. Every option is optional: `length` 8-128
 * (default 20), `symbols` (default on), `pronounceable` (default off). Needs `create` or `update`.
 * Not an MCP tool.
 */
export const utilGenerate = (
  length?: number,
  symbols?: boolean,
  pronounceable?: boolean,
) => invoke<GeneratedPassword>("util_generate", { length, symbols, pronounceable });

// ---------------------------------------------------------------------------
// The shell's own commands and events
//
// Not broker operations: `src-tauri/src/commands.rs` (`SHELL_COMMANDS`),
// `src-tauri/src/autolock.rs` and `src-tauri/src/shell.rs`. The same tests hold
// these names to the Rust side as hold everything above.
// ---------------------------------------------------------------------------

/** What `entryCopy` and `copyText` answer. It names the fact and the clock, never the content. */
export interface CopyReceipt {
  copied: true;
  /** Seconds until the shell empties the clipboard; `null` for plain text, which is never timed. */
  clearAfterSeconds: number | null;
}

/**
 * Copies an entry's value to the clipboard **without the value ever entering the
 * webview**. The shell reveals it Rust-side (the same audited, token-bearing path
 * as `entryReveal`, so every denial arrives unchanged), writes it with the
 * concealed and transient pasteboard markers that clipboard managers honour, and
 * empties the clipboard after `clearAfterSeconds` (30) only if it still holds
 * this copy. The clipboard is also emptied, on the same condition, when the vault
 * locks (including on sleep and screen lock) and when the app quits. It is not
 * emptied when the window loses focus: that would make pasting into the app you
 * copied for impossible.
 *
 * Use this for every "copy" button on a secret. Never `navigator.clipboard`.
 *
 * ADR-078: for an entry with several fields pass the id of the field to copy — the reveal is
 * narrowed to it, so no other field's value reaches the shell. Without `field`, a one-field
 * entry copies as it always did and a several-field one rejects with `field_required`, nothing
 * copied.
 */
export const entryCopy = (node: string, entry: string, field?: string) =>
  invoke<CopyReceipt>("entry_copy", { node, entry, field });

/** One field of a {@link FieldsPreview}: the parser's label and value, byte for byte, and what inference says. */
export interface PreviewField {
  label: string;
  value: string;
  /** The effective type: your pin if you sent one, else inferred. */
  type: FieldTypeName;
  /** The effective masking. */
  masked: boolean;
  /** What inference alone says about this label and value. */
  inferredType: FieldTypeName;
  /** `type` / `masked` came from the `fields` you sent, not from inference. */
  typeOverridden: boolean;
  maskedOverridden: boolean;
}

/** One entry-to-be: what one `///` block (or the whole paste) becomes. */
export interface PreviewSegment {
  /** The first non-empty label, else `untitled N`. Making it unique among the node's names is the screen's job. */
  suggestedName: string;
  fields: PreviewField[];
  /** What the broker will store as the entry's type if you send no `entryType`. */
  entryType: EntryTypeName;
  sensitivity: SensitivityName;
  fieldCount: number;
  hasTotp: boolean;
}

export interface FieldsPreview {
  segments: PreviewSegment[];
  /** One unlabelled blob of three or more lines (`08 §5`): offer "split by line instead". Text input only. */
  singleBlobHint: boolean;
}

/**
 * The live preview of a bulk paste (ADR-078) — parsed and inferred by the same Rust code the
 * broker's world uses, **locally**: no broker call, no session, no audit record, so it is safe
 * on every keystroke. Give `text` (the paste; `split` makes one entry per `///` block, otherwise
 * one entry holds every field) **or** `fields` (rows you have edited), never both
 * (`invalid_fields`). What it shows is what {@link entryCreate} / {@link entryCreateBatch} will
 * store — use {@link previewFieldInputs} to turn a segment into the `fields` to send.
 */
export const fieldsPreview = (text?: string, fields?: FieldInput[], split?: boolean) =>
  invoke<FieldsPreview>("fields_preview", { text, fields, split });

/**
 * The `fields` to send for a previewed segment: label and value verbatim, and `type` /
 * `masked` only where they are the user's pins (`typeOverridden` / `maskedOverridden`), so a
 * field nobody touched keeps being inferred. Pure; calls nothing.
 */
export function previewFieldInputs(segment: PreviewSegment): FieldInput[] {
  return segment.fields.map((f) => {
    const input: FieldInput = { label: f.label, value: f.value };
    if (f.typeOverridden) input.type = f.type;
    if (f.maskedOverridden) input.masked = f.masked;
    return input;
  });
}

/**
 * Copies non-secret text (a donation address, a node id): no concealment, no
 * timer. Replaces whatever the clipboard held, including a pending secret.
 * At most 4096 bytes, otherwise `text_too_large`. It cannot tell a secret from
 * anything else, so the caller must: secrets go through `entryCopy`.
 */
export const copyText = (text: string) => invoke<CopyReceipt>("copy_text", { text });

/** The six app icons (X9), in the design's order. The ids `appIconSet` accepts; anything else is `unknown_icon`. */
export const APP_ICON_IDS = ["keep", "keepbone", "cells", "node", "seal", "keepsig"] as const;
export type AppIconId = (typeof APP_ICON_IDS)[number];

/** What `appIconSet` answers: which icon, and which surface it reached on this OS. */
export interface IconReceipt {
  icon: AppIconId;
  /** The Dock icon changed (macOS). */
  dock: boolean;
  /** The window or taskbar icon changed (Windows and Linux). */
  window: boolean;
}

/**
 * Sets the app icon (the Dock on macOS, the window or taskbar elsewhere) until the app quits. Not a broker op and needs no
 * login: an icon carries no vault data. The page remembers the choice (`credmgr_cosmetics`) and calls this again after an
 * unlock. An id outside {@link APP_ICON_IDS} is `unknown_icon` and nothing changes.
 */
export const appIconSet = (icon: AppIconId) => invoke<IconReceipt>("app_icon_set", { icon });

/** What `captureProtectionSet` answers. */
export interface CaptureReceipt {
  /** The window is now hidden from screen capture and screen sharing, as the shell set it. The developer override `CREDMGR_CONTENT_PROTECTION=off` wins, so this can be `false` after asking for `true`. */
  enabled: boolean;
  /** The operating system accepted the call. `false` leaves the window as it was. */
  applied: boolean;
}

/**
 * Hides the window from screen capture and screen sharing (`true`, the default: the window is created that way) or shows it to them
 * (`false`). Not a broker op and needs no login: it carries no vault data, and locking the vault does not change it. The page
 * remembers the user's choice (`credmgr_prefs`, `captureProtection`) and calls this after it boots only when that choice is
 * `false`; turning it off must first be confirmed in the app, because the window then appears in screenshots, recordings and screen shares.
 */
export const captureProtectionSet = (enabled: boolean) => invoke<CaptureReceipt>("capture_protection_set", { enabled });

/**
 * Events the shell pushes to the page, for `listen()` from `@tauri-apps/api/event`
 * (allowed by `core:default`).
 *
 * - `locked`: the shell locked the vault itself (sleep, screen lock, session
 *   switch) and dropped the login. The payload is a {@link LockReason}. Wipe
 *   everything revealed and show the lock screen; there is nothing to lock again.
 * - `windowInactive`: the window stopped being the one the user is looking at.
 *   The payload is a {@link WindowInactiveReason}. Wipe revealed values. The
 *   clipboard is deliberately left alone.
 */
export const SHELL_EVENTS = {
  locked: "credmgr://locked",
  windowInactive: "credmgr://window-inactive",
} as const;

/** Why the shell locked the vault (`credmgr://locked` payload). */
export type LockReason = "sleep" | "screens_sleep" | "session_resign" | "screen_locked" | "tray" | "window_closed";

/** Why the window went inactive (`credmgr://window-inactive` payload), best effort. */
export type WindowInactiveReason = "minimized" | "hidden" | "blurred";

// ---------------------------------------------------------------------------
// Shell facts that are not broker calls
// ---------------------------------------------------------------------------
//
// Two read-only questions the page asks the Tauri shell itself.  They live here so that this file and `src/vault/shell-events.ts`
// (the event listener) are the ONLY modules of the page that import from `@tauri-apps/`; tests/unit/architecture.test.ts holds
// every import to that list.  Neither one touches the broker, a login, or a secret.

/** The app's own version, from the shell (`tauri.conf.json`).  Rejects when there is no shell to ask. */
export const getVersion = (): Promise<string> => shellGetVersion();

/** The user's home directory, as an absolute path.  Used to expand a leading `~` in a node's work folders before they reach the broker. */
export const homeDir = (): Promise<string> => shellHomeDir();

// Imports are hoisted: they sit with the two wrappers they serve so this section stays one self-contained, append-only block.
import { getVersion as shellGetVersion } from "@tauri-apps/api/app";
import { homeDir as shellHomeDir } from "@tauri-apps/api/path";
