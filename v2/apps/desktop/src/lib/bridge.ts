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
 * 8. **Every command has a caller in the app, or says why not.** `tests/unit/ui-callers.test.ts` fails when an
 *    export here invokes a command that nothing under `src/design` or `src/vault` calls, unless its JSDoc carries
 *    the one marker `@no-ui-caller <reason>` (a command-line-only op, one the shell drives itself, one another
 *    command covers, or a screen that does not exist yet). It also fails a marker left on a command the app does call.
 *
 * Presence-gated operations (`totpSeed`, `nodeReparent`, `grantCreate`, `auditGet`
 * and the others ADR-098 lists) first answer `presence_required`; the shell then
 * asks for Touch ID itself (`src-tauri/src/presence.rs`) and repeats the request
 * with the proof. Without an enrolled presence key the refusal stands.
 */

import { invoke as shellInvoke, type InvokeArgs } from "@tauri-apps/api/core";

// ---------------------------------------------------------------------------
// Confirm before showing secrets (ADR-150): the one retry
// ---------------------------------------------------------------------------

/** What a `confirmation_required` refusal says, as far as the confirm dialog needs it. Never a value, never a name. */
export interface ConfirmationAsk {
  /** The command that was refused (`entry_reveal`, `entry_copy`, `totp_code`, `node_policy`, ...). */
  command: string;
  /** The broker operation the broker named, when it named one. */
  operation: string | null;
  /** `window`: one confirmation opens the trust window; `everyTime`: it is good for this one request. */
  mode: "window" | "everyTime" | null;
  /** The trust window the confirmation opens, in seconds (0 or absent for every-time). */
  windowSeconds: number | null;
}

/**
 * Asks the person to confirm (Touch ID or the vault passphrase, which the handler sends with {@link sessionConfirm}). Resolves
 * `true` once the broker accepted a confirmation, `false` when the person cancelled. Set by the screens, once.
 */
export type ConfirmationHandler = (ask: ConfirmationAsk) => Promise<boolean>;

let confirmationHandler: ConfirmationHandler | null = null;
/** One dialog at a time: calls refused together (a reveal and a TOTP code, say) wait on the same confirmation. */
let confirmationInFlight: Promise<boolean> | null = null;

/** Install the screen's confirmation handler. Returns the function that removes it again. */
export function setConfirmationHandler(handler: ConfirmationHandler | null): () => void {
  confirmationHandler = handler;
  return () => {
    if (confirmationHandler === handler) confirmationHandler = null;
  };
}

function askOf(command: string, e: BridgeError): ConfirmationAsk {
  const d = e.detail ?? {};
  const mode = d.mode === "window" || d.mode === "everyTime" ? d.mode : null;
  return {
    command,
    operation: typeof d.operation === "string" ? d.operation : null,
    mode,
    windowSeconds: typeof d.windowSeconds === "number" ? d.windowSeconds : null,
  };
}

/**
 * Every command goes through here. ADR-150: when the broker answers `confirmation_required` (the owner turned on "Confirm before
 * showing secrets"), the screen's handler asks the person to confirm, and the SAME command is sent again, exactly once. A
 * cancelled confirmation rejects with the original refusal marked `detail.cancelled = true`, which the error router shows as a
 * quiet notice; a second `confirmation_required` (an every-time confirmation another request spent first) is not retried again.
 * `session_confirm` itself is never retried here, so nothing can loop.
 */
const invoke = async <T>(command: string, args?: InvokeArgs): Promise<T> => {
  try {
    return await shellInvoke<T>(command, args);
  } catch (e) {
    if (!isBridgeError(e) || e.code !== "confirmation_required" || command === "session_confirm" || !confirmationHandler) throw e;
    const handler = confirmationHandler;
    if (!confirmationInFlight) {
      confirmationInFlight = handler(askOf(command, e))
        .catch(() => false)
        .finally(() => {
          confirmationInFlight = null;
        });
    }
    const confirmed = await confirmationInFlight;
    if (!confirmed) throw { ...e, detail: { ...(e.detail ?? {}), cancelled: true } } satisfies BridgeError;
    return shellInvoke<T>(command, args);
  }
};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/**
 * Every `"error"` discriminant `credmgrd` can send (`protocol.rs::to_wire`). `confirmation_required` (ADR-150): the owner turned on
 * "Confirm before showing secrets" and this session has no live confirmation; confirm with {@link sessionConfirm} (Touch ID or the
 * passphrase) and repeat the request. The bridge's own `invoke` does that once by itself when the screens installed a
 * {@link ConfirmationHandler}. `machine_lock_refused` (ADR-165): the passphrase file is sealed to a device key this Mac does not
 * hold, or is damaged (`detail.reason`: device_key_missing, device_key_mismatch, device_key_unreadable, sealed_wrap_damaged,
 * device_key_unwritable, or plain_wrap_while_bound: this Mac recorded the vault as bound but an older plain passphrase file sits on
 * disk and does not open it); the way in here is the recovery code ({@link vaultRecover}).
 */
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
  | "presence_failed"
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
  | "session_expired"
  | "confirmation_required"
  | "machine_lock_refused";

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
  /**
   * `envPreview` could not read the text as a `.env` file: a line the grammar refuses (named by number, never quoted), more than
   * 500 pairs, or more than 4 MiB.
   */
  | "invalid_env"
  /** `appIconSet` was given an id outside {@link APP_ICON_IDS}. Nothing changed. */
  | "unknown_icon"
  /** `appIconSet`: the OS or the window refused the icon. */
  | "icon_failed"
  /** ADR-098, Touch ID: the user dismissed the prompt. Not an error to shout about. */
  | "presence_cancelled"
  /** Touch ID is locked out. The Mac password unlocks it. */
  | "presence_locked_out"
  /** No Secure Enclave helper, or no Secure Enclave, on this Mac. */
  | "presence_unavailable"
  /** This Mac has no presence key yet. Set Touch ID up in Settings. */
  | "presence_not_enrolled"
  /** The helper said no for another reason. */
  | "presence_error"
  /** ADR-143, Settings -> Agents: the client or file cannot be edited, the message says why. Nothing was written. */
  | "agent_refused"
  /** The client's file changed since the diff was shown. Nothing was written, review it again. */
  | "agent_changed"
  /** The write or its read-back failed, the original is kept, and a backup sits beside it. */
  | "agent_write_failed"
  /**
   * ADR-156, start at login: the launch agent could not be written, removed or loaded (no `credmgrd` was found to point it at,
   * a file write failed, or `launchctl` said no). The message says which. What was on disk before is left as it was.
   */
  | "login_agent_failed"
  /**
   * ADR-166, Settings > Backup > Restore (the codes of the bundled `credmgr restore --json`). A broker answers on the vault's socket:
   * quit CredMgr (or stop `credmgrd`) and restore with `credmgr restore` in a terminal. Nothing was read or written.
   */
  | "broker_running"
  /** The folder to restore into is not empty: a restore never merges into, or overwrites, a vault. Nothing was written. */
  | "restore_target_not_empty"
  /** A wrong backup passphrase, a damaged archive, a file that cannot be read, or another refusal of the restore. Nothing was written. */
  | "restore_failed"
  /** No `credmgr` command-line program was found beside the app or in the install locations. Nothing was run. */
  | "restore_unavailable";

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
  /** ADR-098: unlocking with Touch ID is set up for this vault (reported by `vaultStatus`, absent when not). */
  touchIdUnlock?: boolean;
  /**
   * How many agent requests are waiting for a person (ADR-090): a bare count from `vault.status`, left out when 0. No names;
   * {@link vaultApprovalGet} says what they are.
   */
  pendingApprovals?: number;
  /**
   * ADR-156: how many cross-node anomaly alarms (an agent refused 5 times in 10 minutes for another project) the owner has not
   * acknowledged yet. A bare count, from `vault.status` only and only to the owner's own login; left out when 0. Reset by
   * {@link vaultAnomaliesAck}.
   */
  anomaliesUnseen?: number;
  /**
   * ADR-163: this vault can be opened with its recovery code when the passphrase is forgotten ({@link vaultRecover}), reported by
   * `vaultStatus` and left out when not. Absent on a vault made before recovery wraps existed: the next passphrase change writes one.
   */
  recoveryUnlock?: boolean;
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
  /** ADR-140: how much an agent may do here without the owner. Absent from an older broker: read it as `guarded`. */
  securityLevel?: SecurityLevel;
  /** `null` in every response today — render a sane default, not an error. */
  health: unknown | null;
}

/** ADR-140. `open`: no approvals. `guarded` (the default): a high or critical value waits for the owner. `sealed`: every value waits, adds wait in the tray, no changes. */
export type SecurityLevel = "open" | "guarded" | "sealed";

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
  /** ADR-150: the vault's "Confirm before showing secrets" policy, for the owner's own login. Absent for anyone else and for an older broker (read as off). */
  revealConfirm?: RevealConfirm;
  /** Renders while locked; `vaultLocked` is how an idle auto-lock is noticed. */
  meta: {
    generatedAt: number;
    vaultLocked: boolean;
    /**
     * ADR-080: the nodes that are sealed and still restorable (id, label, the window — nothing
     * else), for a human session that may restore. Absent for an agent; `[]` when nothing is sealed.
     */
    sealed?: SealedNode[];
    /**
     * ADR-120: the items in Orphaned by name (`id`, `name`; never a value), for the vault owner's own login session. `entry.list` on
     * the orphaned node is refused to everyone (R0) and the snapshot leaves that node out, so this is the only place a window learns
     * what was sealed. Absent for every other caller and for a broker that predates ADR-120.
     */
    orphaned?: Array<{ id: string; name: string }>;
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
  /** ADR-121: the other names this entry answers to. Absent when it has none. */
  aliases?: string[];
  /** ADR-167: the entry's tags (lower-cased labels). Absent when it has none. */
  tags?: string[];
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
  /**
   * ADR-111 (issue #40): present and `true` only when this field could be a 2FA seed that is not typed as one. An owner who typed it
   * (to anything) has answered, so it is absent then. Metadata: it says nothing about the value beyond that one bit.
   */
  possibleSeed?: boolean;
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
  /** ADR-121: the other names this entry answers to. Absent when it has none (and when the node hides its names from this caller). */
  aliases?: string[];
  /** ADR-167: the entry's tags. Absent when it has none (and when the node hides its names from this caller). */
  tags?: string[];
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
  /** ADR-111: the ids of the fields that could be a 2FA seed but are not typed as one. Absent when there are none. */
  possibleSeedFields?: string[];
  warnings?: NameWarning[];
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
export const vaultUnlock = (passphrase?: string, method?: "device") =>
  invoke<AuthState>("vault_unlock", { passphrase, method });

/**
 * ADR-098: unlock with Touch ID instead of the passphrase. The system shows the fingerprint (or Mac
 * password) prompt; nothing secret passes through the page. Rejects with `presence_failed` and
 * `detail.reason` `not_enrolled` when Touch ID unlock was never turned on, or `presence_failed`
 * with `cancelled` when the prompt was dismissed.
 */
export const vaultUnlockWithTouchId = () => vaultUnlock(undefined, "device");

export const vaultGateVerify = (code: string) =>
  invoke<AuthState>("vault_gate_verify", { code });

export const vaultLock = () => invoke<AuthState>("vault_lock");

export const whoami = () => invoke<Whoami>("whoami");

export const graphSnapshot = () => invoke<GraphSnapshot>("graph_snapshot");

/** ADR-167: `tag` narrows the list to the entries carrying it, on this one node. */
export const entryList = (node: string, tag?: string) => invoke<EntryList>("entry_list", { node, tag });

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
  /** ADR-164: the agent token that asked, by label and public id (to the owner, and on a locked vault). */
  agentToken?: { id: string; label: string };
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

/**
 * Bare node ids this scope may list — use {@link graphSnapshot} for node objects.
 * @no-ui-caller the app reads its nodes from graph_snapshot, which carries labels, policy and counts; node_list (ids only) serves the CLI and agents.
 */
export const nodeList = () => invoke<{ nodes: string[] }>("node_list");

/** `workdirs` optionally binds directories that scope an agent to the node (ADR-066). */
export const nodeCreate = (id: string, label: string, parentId: string, workdirs?: string[]) =>
  invoke<{ node: string; created: true; audit?: string; warnings?: NameWarning[] }>("node_create", { id, label, parentId, workdirs });

/**
 * Replaces a node's bound directories — absolute, existing, one directory to one node. `[]` clears.
 * @no-ui-caller no screen yet (rc.2 backlog): a node's work folders are set when it is created (node_create); changing them later is `credmgr node workdir`.
 */
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
  /** ADR-140. Lowering it (towards `open`) widens what an agent may do and needs presence (Touch ID). */
  securityLevel?: SecurityLevel;
  /**
   * ADR-150, on the global node only (any other node is `malformed_request`), the owner's login only. Turning it on or making it
   * stricter needs nothing; turning it off or loosening it answers `confirmation_required` unless the session confirmed in the
   * last 60 s (the bridge confirms and retries once).
   */
  revealConfirm?: RevealConfirm;
}

/**
 * ADR-150: "Confirm before showing secrets", vault policy held on the global node. `off` is the default (and what an older vault
 * reads as). `window`: one confirmation (Touch ID or the passphrase) and no more prompts for `windowSeconds`. `everyTime`: each
 * reveal needs its own. `scope: "high"` asks only for entries whose sensitivity is high or critical.
 */
export interface RevealConfirm {
  mode: "off" | "window" | "everyTime";
  /** One of {@link REVEAL_CONFIRM_WINDOWS}: 60, 300, 900 or 3600. */
  windowSeconds: number;
  scope: "all" | "high";
}

/** The trust windows the broker accepts, in seconds. */
export const REVEAL_CONFIRM_WINDOWS = [60, 300, 900, 3600] as const;
export const REVEAL_CONFIRM_DEFAULT: RevealConfirm = { mode: "off", windowSeconds: 300, scope: "all" };

/**
 * Changes a node's policy (ADR-071). `reason` is mandatory and lands in the audit record.
 * Turning on `descendantRead`, or `siblingVisibility: "shared"`, widens reach and answers
 * `presence_required` until presence can be attested; the patch is then applied not at all.
 * `notEnforced` names the fields that are stored but not yet acted on.
 */
export const nodePolicy = (node: string, reason: string, policy: NodePolicyPatch) =>
  invoke<{
    node: string;
    policy: Required<Omit<NodePolicyPatch, "revealConfirm">> & { revealConfirm?: RevealConfirm };
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
 * @no-ui-caller writing a note is a command-line action by design (`credmgr notes set`, HELP "notes"); the app shows a node's note read-only.
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

/**
 * Needs a Touch ID proof (F-8, ADR-098), which the shell attaches itself on `presence_required`. `reason` must be ≥ 8 characters.
 * @no-ui-caller no screen yet: moving a node under another parent is `credmgr node reparent` (Touch ID, ADR-098).
 */
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
  direction?: "one-way" | "mutual",
  expiresAt?: number,
) =>
  invoke<Record<string, unknown>>("grant_create", { from, to, scope, reason, direction, expiresAt });

/** In both modes — revocation is safety, not a lever. */
export const grantRevoke = (id: string) =>
  invoke<{ id: string; revoked: true; audit?: string }>("grant_revoke", { id });

// ---------------------------------------------------------------------------
// Entries — every call below that changes an existing entry takes `generation`
// ---------------------------------------------------------------------------

/** What `entryCreate` answers; `pending: true` (and no generation) when the vault is locked — F-1's tray. */
export type EntryCreated =
  | { node: string; entry: string; pending: true; fieldCount: number; fieldIds: string[]; audit?: string; warnings?: NameWarning[]; possibleSeedFields?: string[] }
  | {
      node: string;
      entry: string;
      pending: false;
      generation: number;
      fieldCount: number;
      fieldIds: string[];
      audit?: string;
      warnings?: NameWarning[];
      /** ADR-111: the ids of the fields that could be a 2FA seed but are not typed as one. Absent when there are none. */
      possibleSeedFields?: string[];
    };

/** A warning the broker attaches to an accepted name (ADR-084). Anything else it may add in future is ignored by the window. */
export type NameWarning = "mixed_script_name" | "possible_totp_seed";

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
    /** `possibleSeedFields` (ADR-111): the ids of this entry's fields that could be a 2FA seed but are not typed as one; absent when none. */
    created: { name: string; entry: string; pending: boolean; fieldCount: number; possibleSeedFields?: string[] }[];
    complete: boolean;
    failed: { index: number; name: string; error: string } | null;
    total: number;
    generation: number | null;
    audit?: string;
    warnings?: NameWarning[];
  }>("entry_create_batch", { node, entries });

/** An existing entry whose name or alias resembles a candidate name (ADR-121). */
export interface NearName {
  id: string;
  name: string;
  /** Set when it is an alias of that entry that resembles the candidate. */
  alias?: string;
  /** `separators`: the same letters with other separators or case. `one-edit`: one letter added, left out, changed or swapped. */
  reason: "separators" | "one-edit";
}

/**
 * Sets the other names one entry answers to (ADR-121): the whole list, at most 8, `[]` clears it. An alias lives in the node's one
 * name space: it cannot be, canonically, the name or alias of any other entry (`entry_exists`) or the entry's own name. A human
 * session with the `update` capability; metadata only, no value is read or rewritten. Echoes the node's new generation.
 */
export const entryAlias = (node: string, entry: string, generation: number, aliases: string[]) =>
  invoke<{
    node: string;
    entry: string;
    generation: number;
    aliases: string[];
    /** Existing names the new aliases resemble (a warning, never a refusal). Absent when none, and for a node that hides its names. */
    similar?: NearName[];
    audit?: string;
    warnings?: NameWarning[];
  }>("entry_alias", { node, entry, generation, aliases });

/**
 * Which entries of a node have a name or alias resembling `name` (ADR-121), and whether `name` is already taken exactly. `entry`
 * leaves one entry out (the one being aliased). A node whose names are hidden from this caller answers `nameHidden: true`.
 */
export const entrySimilar = (node: string, name: string, entry?: string) =>
  invoke<{ node: string; name?: string; taken?: boolean; nameHidden?: boolean; similar: NearName[] }>("entry_similar", { node, name, entry });

/** One pair of a parsed `.env` file. */
export interface EnvPair {
  name: string;
  value: string;
}

/** What one pair of an import would become (ADR-122). */
export type ImportStatus = "new" | "exists" | "duplicate" | "empty" | "invalid";

/**
 * A parsed `.env` file into one node (ADR-122). `dryRun: true` writes nothing and says, for every pair, what it would become and which
 * existing names it resembles; without it the `new` pairs are written, each as its own entry with its own audit record. `onConflict`
 * is `"refuse"` (the default: one conflicting pair and nothing is written) or `"skip"`. No answer carries a value.
 */
export const entryImportEnv = (node: string, entries: EnvPair[], dryRun?: boolean, onConflict?: "refuse" | "skip") =>
  invoke<{
    node: string;
    dryRun?: boolean;
    total: number;
    counts: Record<ImportStatus, number>;
    /** Dry run only. */
    items?: { name: string; status: ImportStatus; similar?: NearName[] }[];
    /** Write only. */
    created?: { name: string; entry: string; pending: boolean; fieldCount: number }[];
    skipped?: { name: string; status: ImportStatus }[];
    complete?: boolean;
    failed?: { index: number; name: string; error: string } | null;
    generation?: number | null;
    audit?: string;
    warnings?: NameWarning[];
  }>("entry_import_env", { node, entries, dryRun, onConflict });

/** What {@link envPreview} read out of a `.env` text. */
export interface EnvPreview {
  entries: EnvPair[];
  /** Names whose value was empty (an `.env.example` placeholder): not importable. */
  skippedEmpty: string[];
}

/**
 * Reads `.env` text into pairs with the same parser `credmgr import-env` uses - **locally**: no broker call, no session, no audit
 * record. A line the grammar refuses is named by number (`invalid_env`), never quoted. Hand the pairs to {@link entryImportEnv}.
 */
export const envPreview = (text: string) => invoke<EnvPreview>("env_preview", { text });

/**
 * Changes an entry (ADR-078). `value` replaces one field's value — the only field, or the one
 * `field` (an id) names; on a several-field entry without `field` the broker refuses. `label`
 * renames that field. `fields` instead replaces the whole list (an `id` keeps a field's identity;
 * fields left out are dropped) and excludes `value` / `label` / `field`. `entryType` /
 * `sensitivity` set or (`"auto"`) clear the entry's pins. Keeps no history; for that, rotate or
 * use the `field*` calls.
 * @no-ui-caller the app changes a value through field_update, which keeps history and offers Undo; entry_update (no history) is the CLI's `credmgr set`.
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
  /* ADR-165 review N2: `outsideVaultFolder` - the vault is machine-locked, so the archive (which holds the passphrase file unsealed) was
     written in CredMgr's state folder, not in the vault folder's backups/. */
  invoke<{ path: string; retain: number; pruned: string[]; passphraseFileUnsealed?: boolean; outsideVaultFolder?: boolean }>("maintenance_backup", {
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
  /** ADR-165: whether the new passphrase file is sealed to this Mac's device key (a bound vault stays bound). */
  machineLocked?: boolean;
  /** ADR-165: present when this rotation could NOT seal the new passphrase file, so the machine lock is now OFF; why, in plain words. */
  machineLockRemoved?: string;
  deviceKeyCreated?: boolean;
  /** ADR-165 N5 / ADR-174: the live projects given a new key in this rotation (sorted ids). */
  nodesRekeyed?: string[];
  /** ADR-165 N5 / ADR-174: envelopes re-sealed to the new keys, the sealed copies of removed projects included. */
  filesResealed?: number;
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

// ---------------------------------------------------------------------------
// Post-launch quick wins (ADR-156)
// ---------------------------------------------------------------------------

/** What `vaultSetPassphrase` answers: a root rotation under the new passphrase, so a NEW recovery code, shown once. */
export type SetPassphraseResult = RotateRootResult & {
  passphraseChanged: true;
};

/**
 * Change the vault passphrase. `passphrase` is the current one (proven first; `wrong_passphrase` changes nothing), `newPassphrase`
 * the one that wraps the root key from now on. It is a full root rotation: the answer carries a NEW `recoveryCode` (the old one stops
 * working at once) that must be shown once and never kept. Owner's login; a fresh second factor and Touch ID are asked for when set up.
 * Like {@link maintenanceRotateRoot}, do not read the vault after it: a rotation whose last step is pending locks the vault.
 */
export const vaultSetPassphrase = (passphrase: string, newPassphrase: string) =>
  invoke<SetPassphraseResult>("vault_set_passphrase", { passphrase, newPassphrase });

/**
 * What `vaultRecover` answers: the same root rotation as {@link vaultSetPassphrase}, so a NEW recovery code, shown once. `locked` is
 * `false` when the vault is now open (the shell captured the login token and holds it; the page never sees it) and `true` when the
 * rotation committed but its last file moves are pending: the vault stays locked and the NEW passphrase opens it.
 */
export type RecoverResult = RotateRootResult & {
  passphraseChanged: true;
  recovered: true;
  locked: boolean;
};

/**
 * ADR-163, "Forgot passphrase?": open a LOCKED vault with the printed recovery code alone. In the same call the vault is re-keyed under
 * `newPassphrase` and a NEW recovery code is issued (the used code and the forgotten passphrase stop working at once); show it once and
 * never keep it. `code` is the vault's second factor (a TOTP code or one of the gate's backup codes) when one is enrolled: without it the
 * broker answers `two_factor_required`. A wrong recovery code is `recovery_code_mismatch` and counts in the unlock back-off; a vault
 * with no recovery wrap is `not_found` (see {@link AuthState.recoveryUnlock}). Never offered to agents or over MCP.
 */
export const vaultRecover = (recoveryCode: string, newPassphrase: string, code?: string) =>
  invoke<RecoverResult>("vault_recover", { recoveryCode, newPassphrase, code });

/** The owner has seen the cross-node anomaly alarm (`AuthState.anomaliesUnseen`): resets the count. Owner's login only. */
export const vaultAnomaliesAck = () => invoke<{ acknowledged: number }>("vault_anomalies_ack");

/** Set an entry's expiry (`expiresAt`, unix seconds) or clear it (`clear: true`): exactly one of the two. Manifest metadata only. */
export const entrySetExpiry = (node: string, entry: string, generation: number, expiresAt?: number, clear?: boolean) =>
  invoke<{ node: string; entry: string; generation: number; expiresAt: number | null; audit?: string }>("entry_set_expiry", {
    node,
    entry,
    generation,
    expiresAt,
    clear,
  });

/** One row of {@link entryExpiring}: names and dates, never a value. */
export interface ExpiringEntry {
  node: string;
  id: string;
  name: string;
  ref: number;
  expiresAt: number;
  rotatedAt: number | null;
  expired: boolean;
}

/**
 * Entries that expire within `days` (the broker's 30 when absent), already expired included, soonest first; one node or every one.
 * @no-ui-caller no screen yet (rc.2 backlog): each entry's expiry chip and Tidy up's expired and expiring findings cover it in the app; the due list is `credmgr expiring`.
 */
export const entryExpiring = (node?: string, days?: number) =>
  invoke<{ days: number; now: number; entries: ExpiringEntry[] }>("entry_expiring", { node, days });

/** One audit record of {@link entryHistory}: an action and its time, never a value. */
export interface EntryHistoryRecord {
  id: string;
  timestamp: number;
  actor: string;
  action: string;
  decision: string;
  generation: number | null;
}

/** What {@link entryHistory} answers. The entry's own times are there only while it `exists`. */
export interface EntryHistory {
  node: string;
  entry: string;
  records: EntryHistoryRecord[];
  truncated: boolean;
  exists: boolean;
  name?: string;
  ref?: number;
  modified?: number;
  rotatedAt?: number | null;
  expiresAt?: number | null;
}

/** One entry's trail, oldest first (the newest `limit` kept), plus its edit, rotation and expiry times. */
export const entryHistory = (node: string, entry: string, limit?: number) =>
  invoke<EntryHistory>("entry_history", { node, entry, limit });

// ---------------------------------------------------------------------------
// Node-scoped agent tokens (ADR-164) — owner's login only; never an agent
// ---------------------------------------------------------------------------

/** The capabilities an agent token may carry; never `notes` or `admin`. */
export type AgentTokenCapability = "list" | "read" | "reveal" | "create" | "update";

/** One agent token as {@link agentTokenStatus} lists it: metadata, never a secret. */
export interface AgentTokenInfo {
  id: string;
  label: string;
  node: string;
  capabilities: AgentTokenCapability[];
  /** What it may do now: `capabilities` cut down to what the node gives agents today. */
  effectiveCapabilities: AgentTokenCapability[];
  createdAt: number;
  expiresAt: number;
  lastUsedAt: number | null;
  rotatedAt: number | null;
}

/**
 * What `agentTokenIssue` and `agentTokenRotate` answer: the metadata ({@link AgentTokenInfo}) and where the new token
 * went. Like the login (ADR-057), the token itself never reaches the page: the shell puts it on the concealed clipboard,
 * cleared after `clearAfterSeconds`, and wipes its own copy. If the clipboard could not take it, nobody holds the token,
 * so the shell revokes it at once (`copied: false`, `revoked` says whether that worked). When a lock also ended the
 * login the revoke needs, the shell keeps the id and revokes it at the next unlock (`revokePending: true`).
 */
export interface AgentTokenIssued {
  id: string;
  label: string;
  node: string;
  capabilities: AgentTokenCapability[];
  effectiveCapabilities: AgentTokenCapability[];
  createdAt: number;
  expiresAt: number;
  lastUsedAt: number | null;
  rotatedAt: number | null;
  copied: boolean;
  /** Present when `copied`: seconds until the clipboard clears itself. */
  clearAfterSeconds?: number;
  /** Present when not `copied`: whether the shell revoked the uncopied token. */
  revoked?: boolean;
  /** Present (true) when the revoke could not run now (a lock ended the login) and will run at the next unlock. */
  revokePending?: boolean;
}

/**
 * A token for exactly one node (`expiresIn` seconds, 60 to 604800, one day when absent). Needs the owner's login, the
 * vault's second factor where enrolled and Touch ID (the shell asks for the proof itself); `capabilities` must be a
 * subset of what the node gives agents. The new token goes to the concealed clipboard, never to the page.
 */
export const agentTokenIssue = (node: string, label: string, capabilities: AgentTokenCapability[], expiresIn?: number) =>
  invoke<AgentTokenIssued>("agent_token_issue", { node, label, capabilities, expiresIn });

/** The live agent tokens (one node's when `node` is given), with the broker's bounds. Metadata only. */
export const agentTokenStatus = (node?: string) =>
  invoke<{ tokens: AgentTokenInfo[]; max: number; defaultExpiresIn: number; maxExpiresIn: number }>("agent_token_status", { node });

/** A new secret and expiry for a token; the old secret stops working. Same gate as {@link agentTokenIssue}. */
export const agentTokenRotate = (id: string, expiresIn?: number) =>
  invoke<AgentTokenIssued>("agent_token_rotate", { id, expiresIn });

/** End a token now. No Touch ID: revoking only removes access. */
export const agentTokenRevoke = (id: string) =>
  invoke<{ revoked: true; id: string; label: string; node: string }>("agent_token_revoke", { id });

/** Names and aliases on one node that contain `term` (case-insensitive), only those carrying `tag` when given (ADR-167). Never values. */
export const entrySearch = (node: string, term: string, tag?: string) =>
  invoke<{ node: string; results: Array<{ id: string; name: string; alias?: string }> }>("entry_search", { node, term, tag });

/** Which entry a vault-global short reference names; `not_found` for one the caller could not list. */
export const entryGetByRef = (reference: number) =>
  invoke<{ node: string; entry: string; name: string; ref: number }>("entry_get_by_ref", { reference });

/** What {@link entryMove} answers (ADR-158): where the entry is now and what did not travel with it. Never a value. */
export interface EntryMoved {
  /** The destination: the node the entry is in now. */
  node: string;
  /** The entry's id and its vault-global short reference, both kept by the move. */
  entry: string;
  ref: number;
  name: string;
  /** The node it came from. */
  from: string;
  /** The source node's generation after the move; `toGeneration` is the destination's, which the next change to the moved entry echoes. */
  generation: number;
  toGeneration: number;
  /** Grants on this entry, revoked by the move (a grant names its node, so it cannot follow). */
  grantsRevoked: string[];
  /** Earlier values kept for Undo in the old node: dropped by the move. */
  historyDropped: number;
  /** Present only when the move is done but a staging file could not be removed (the next unlock removes it). */
  cleanupWarning?: string;
  audit?: string;
}

/**
 * Move one entry to another node (ADR-158): re-sealed to the destination's key in one crash-safe step, keeping its id, reference, name,
 * aliases and expiry. Grants on the entry are revoked and its Undo history is dropped. The owner's login only, `Admin` on both nodes,
 * a fresh second factor and Touch ID on every call; a stale `generation` (the source's) is `conflict`, a taken name `entry_exists`.
 */
export const entryMove = (node: string, entry: string, to: string, generation: number, reason?: string) =>
  invoke<EntryMoved>("entry_move", { node, entry, to, generation, reason });

/** One entry as a tidy-up finding names it (ADR-161): ids, ref, name, its node's generation as the scan read it. Never a value. */
export interface DoctorEntry {
  node: string;
  nodeLabel: string | null;
  entry: string;
  ref: number;
  name: string;
  generation: number;
}

/** What a finding proposes. `op` is `"entry.move"` only for a move the app can apply, with `move` holding that call's params. */
export interface DoctorProposal {
  action: "move_to_parent" | "move_to_project" | "share" | "merge" | "remove_copies" | "rename_or_merge";
  op: "entry.move" | null;
  to?: string;
  toLabel?: string | null;
  move?: { node: string; entry: string; to: string; generation: number };
  keep?: { node: string; entry: string; name: string };
  options?: string[];
}

/** The kinds a report carries, in the order the app shows them. */
export type DoctorKind = "duplicate_value" | "misfiled" | "similar_names" | "weak" | "mistyped" | "expired" | "expiring" | "stale";

/** One finding of {@link vaultDoctorScan}. Which optional keys are present depends on `kind`. */
export interface DoctorFinding {
  kind: DoctorKind;
  entries: DoctorEntry[];
  /** duplicate_value: `exact`, or `probable` (equal once trimmed and a URL's host lowercased). */
  match?: "exact" | "probable";
  /** similar_names. */
  similarity?: "separators" | "one_edit";
  sameNode?: boolean;
  /** weak, mistyped, and a JWT's expiry: the field (its id and label; never its value). */
  field?: string;
  fieldLabel?: string;
  reasons?: string[];
  reason?: "otpauth_uri" | "live_key_in_test" | "test_key_in_live";
  /** expired / expiring: the date, from the manifest or from a JWT's own `exp`. */
  expiresAt?: number;
  source?: "manifest" | "jwt";
  /** stale: when it last changed, and whether that was a rotation. */
  lastChanged?: number;
  basis?: "rotated" | "modified";
  proposal?: DoctorProposal;
}

/** What {@link vaultDoctorScan} answers. */
export interface DoctorReport {
  now: number;
  staleDays: number;
  expiringDays: number;
  nodesScanned: number;
  entriesScanned: number;
  valuesChecked: number;
  /** Nodes not read (`what: "all"`) or read by name only (`what: "values"`), and why. */
  skipped: { node: string; nodeLabel: string; reason: "locked" | "second_factor" | "not_listed"; what: "all" | "values" }[];
  /** The scan stopped at its entry, time or findings limit. */
  truncated: boolean;
  counts: Record<DoctorKind, number>;
  findings: DoctorFinding[];
}

/**
 * The doctor's tidy-up scan (ADR-161, phase 1): read-only, the owner's login only. Every finding names entries and nodes and says why;
 * none carries a value, a digest or a part of one. A move proposal carries the exact `entry.move` params, applied one by one through the
 * entry inspector's Move dialog (which asks for its own second factor and Touch ID).
 */
export const vaultDoctorScan = (staleDays?: number, expiringDays?: number) =>
  invoke<DoctorReport>("vault_doctor_scan", { staleDays, expiringDays });

/** One move of a doctor plan, exactly as the scan's proposal carried it (`DoctorProposal.move`). */
export type DoctorMove = { node: string; entry: string; to: string; generation: number };

/** What {@link vaultDoctorApply} answers (ADR-169). Never a value. */
export interface DoctorApplied {
  /** Every move of the plan was applied. */
  complete: boolean;
  /** The moves applied, in plan order: each is what {@link entryMove} answers, plus its `index` in the plan. */
  applied: (EntryMoved & { index: number })[];
  /** Where the plan stopped, when a move after the first one failed (a failure at the first move is the call's error, and nothing moved). */
  stopped?: { index: number; node: string; entry: string; to: string; code: string; message: string | null };
  /** How many moves of the plan were not applied. */
  notApplied: number;
  audit?: string;
}

/**
 * Apply every move of one doctor plan in one request (ADR-169). `moves` is the exact list the scan showed and the person confirmed;
 * the broker re-checks every step against the vault as it is, asks for one fresh second factor and one Touch ID check for the whole plan
 * (the proof signs the whole list), then moves each entry through `entry.move`'s crash-safe commit, stopping at the first that fails.
 * The owner's login only; a stale generation is `conflict` and a taken name `entry_exists`, both before anything moves.
 */
export const vaultDoctorApply = (moves: DoctorMove[], reason?: string) =>
  invoke<DoctorApplied>("vault_doctor_apply", { moves, reason });

/**
 * Replace one entry's tags (ADR-167): the whole set, `[]` clears it. The broker normalises each tag (trimmed, lower-cased, inner spaces
 * to `-`; letters, digits and `- _ . : /`; at most 32 characters, at most 16 tags) and answers what it stored. The owner's sessions;
 * metadata only. Echoes the node's new generation.
 */
export const entryTagSet = (node: string, entry: string, generation: number, tags: string[]) =>
  invoke<{ node: string; entry: string; generation: number; tags: string[]; audit?: string }>("entry_tag_set", {
    node,
    entry,
    generation,
    tags,
  });

/** One entry of a merge suggestion (ADR-168). Never a value. */
export interface MergeEntry {
  entry: string;
  ref: number;
  name: string;
}

/** One merge suggestion (ADR-168): entries of one node that look like one thing. `key` addresses it for dismiss and auto. */
export interface MergeSuggestion {
  key: string;
  kind: "identical" | "shared_value" | "similar_names";
  reasons: Array<"same_values" | "shared_value" | "similar_names">;
  /** Every entry holds the same values: `merge.auto` may merge it. */
  identical: boolean;
  /** The entry proposed to keep (the oldest). */
  keep: string;
  entries: MergeEntry[];
  dismissed?: boolean;
}

/** What {@link mergeSuggestions} answers (ADR-168). */
export interface MergeSuggestions {
  node: string;
  generation: number;
  /** `false` when the node's own second factor is not open: compared by name only. */
  valuesCompared: boolean;
  truncated: boolean;
  dismissedCount: number;
  suggestions: MergeSuggestion[];
}

/** One merged group (ADR-168): each dropped entry with the audit id that undoes it. Never a value. */
export interface MergePart {
  keep: string;
  merged: Array<{ entry: string; name: string; undo: string | null }>;
  aliasesAdded: string[];
  tagsAdded: string[];
  key?: string;
}

/** What `merge_apply` and `merge_auto` answer (ADR-168): the group, the node and its new generation. */
export interface MergeResult {
  node: string;
  keep: string;
  merged: Array<{ entry: string; name: string; undo: string | null }>;
  aliasesAdded: string[];
  tagsAdded: string[];
  generation: number;
  key?: string;
  audit?: string;
}

/** Merge suggestions inside one node (ADR-168). The owner's login only; read-only. */
export const mergeSuggestions = (node: string, includeDismissed?: boolean) =>
  invoke<MergeSuggestions>("merge_suggestions", { node, includeDismissed });

/**
 * Keep one entry and fold the others into it (ADR-168): their names become its aliases, their tags join its tags, and they are removed
 * (each undoable for 7 days with {@link entryUndo} and the `undo` id). A fresh second factor (`two_factor_required` otherwise); a stale
 * `generation` is `conflict`; a dropped entry with its own grant is `malformed_request`.
 */
export const mergeApply = (node: string, keep: string, drop: string[], generation: number) =>
  invoke<MergeResult>("merge_apply", { node, keep, drop, generation });

/**
 * Merge one suggestion, only when its values are all identical (ADR-168). A fresh second factor.
 * @no-ui-caller no screen yet (ADR-168): the app offers Merge and Dismiss in Tidy up; this one is the command line's `credmgr merge auto`.
 */
export const mergeAuto = (node: string, key: string, generation: number) =>
  invoke<MergeResult>("merge_auto", { node, key, generation });

/**
 * Every open identical suggestion (ADR-168): a dry run unless `apply` is `true` (then `generation` and a fresh second factor).
 * @no-ui-caller no screen yet (ADR-168): the app offers Merge and Dismiss in Tidy up; this one is the command line's `credmgr merge auto-all`.
 */
export const mergeAutoAll = (node: string, apply?: boolean, generation?: number) =>
  invoke<{
    node: string;
    dryRun: boolean;
    planned: MergeSuggestion[];
    merged?: MergePart[];
    skipped: Array<{ key: string; reason: string; entries: MergeEntry[] }>;
    generation: number;
    audit?: string;
  }>("merge_auto_all", { node, apply, generation });

/** Remember that a suggestion was rejected (ADR-168): it is not suggested again until undismissed or restored. */
export const mergeDismiss = (node: string, key: string) =>
  invoke<{ node: string; key: string; dismissed: true; generation: number; audit?: string }>("merge_dismiss", { node, key });

/**
 * Forget one dismissal (ADR-168).
 * @no-ui-caller no screen yet (ADR-168): the app offers Merge and Dismiss in Tidy up; this one is the command line's `credmgr merge undismiss`.
 */
export const mergeUndismiss = (node: string, key: string) =>
  invoke<{ node: string; key: string; restored: boolean; generation: number; audit?: string }>("merge_undismiss", { node, key });

/**
 * What the node remembers as dismissed (ADR-168), newest first; `name` is `null` for an entry no longer in the node.
 * @no-ui-caller no screen yet (ADR-168): the app offers Merge and Dismiss in Tidy up; this one is the command line's `credmgr merge dismissed`.
 */
export const mergeDismissedList = (node: string) =>
  invoke<{ node: string; dismissed: Array<{ key: string; entries: Array<{ entry: string; name: string | null }>; dismissedAt: number }> }>(
    "merge_dismissed_list",
    { node },
  );

/**
 * Forget every dismissal on the node (ADR-168).
 * @no-ui-caller no screen yet (ADR-168): the app offers Merge and Dismiss in Tidy up; this one is the command line's `credmgr merge restore-all`.
 */
export const mergeRestoreAll = (node: string) =>
  invoke<{ node: string; restored: number; generation: number; audit?: string }>("merge_restore_all", { node });

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
 * (default 20), `symbols` (default on), `pronounceable` (default off), `hex` (default off; lower-case hex,
 * refused with `pronounceable` or `symbols: true`). Needs `create` or `update`.
 * Not an MCP tool.
 */
export const utilGenerate = (
  length?: number,
  symbols?: boolean,
  pronounceable?: boolean,
  hex?: boolean,
) => invoke<GeneratedPassword>("util_generate", { length, symbols, pronounceable, hex });

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

// ─────────────────────────────── The switchboard (ADR-155) ───────────────────────────────

/** One setting as `settings.list` / `settings.get` describe it (`credmgr_core::settings`). */
export interface SettingView {
  id: string;
  scope: "vault" | "node";
  group: string;
  title: string;
  purpose: string;
  ui: string;
  stored: string;
  values: string;
  default: unknown;
  value: unknown;
  risk: "security" | "cosmetic";
  /** The rule for this caller: `direct`, `direct when stricter; approval when weaker`, `direct when stricter; never
   *  weaker (the owner's)` (an agent's own `node.agentAccess`), or `read only` (ADR-155 amendment: an agent changes only
   *  its own node's settings). The app's own login always reads `direct`. */
  you: string;
  recentChanges?: SettingChangeRecord[];
}

/** One applied change (`global.policy.settingsHistory`). */
export interface SettingChangeRecord {
  id: string;
  setting: string;
  node?: string;
  from: unknown;
  to: unknown;
  by: string;
  at: number;
  request?: string;
  reason: string;
  reverts?: string;
}

/** What `settings.set` / `settings.revert` answer. */
export interface SettingSetResult {
  applied: boolean;
  change: "same" | "cosmetic" | "strengthens" | "weakens";
  changeId?: string;
  id: string;
  from?: unknown;
  to?: unknown;
  value?: unknown;
  /** `pending` when an agent's weakening change waits for the owner. */
  state?: "pending";
  request?: string;
  expiresIn?: number;
}

/** An agent's request as `settings.request_get` / `settings.request_list` describe it. */
export interface SettingRequestView {
  request: string;
  id: string;
  node: string | null;
  from: unknown;
  to: unknown;
  reason: string;
  state: "pending" | "approved" | "denied" | "expired";
  expiresIn: number;
  requestedAt: number;
  changeId: string | null;
  cwd?: string | null;
  /** ADR-164: the agent token that asked, by label and public id; to the owner only. */
  agentToken?: { id: string; label: string };
}

export const settingsList = (node?: string) =>
  invoke<{ caller: string; node: string | null; settings: SettingView[]; note: string; kb: string }>("settings_list", { node });
export const settingsGet = (id: string, node?: string) => invoke<SettingView>("settings_get", { id, node });
export const settingsSet = (id: string, value: unknown, reason: string, node?: string) =>
  invoke<SettingSetResult>("settings_set", { id, value, reason, node });
/**
 * @no-ui-caller no screen yet (rc.2 backlog): the switchboard shows each setting and its history; a revert is `credmgr settings revert` or the MCP tool credmgr_settings_revert.
 */
export const settingsRevert = (change: string, reason?: string) => invoke<SettingSetResult>("settings_revert", { change, reason });
/**
 * @no-ui-caller the app lists waiting setting requests with settings_request_list, which carries each request whole; settings_request_get serves the CLI and MCP.
 */
export const settingsRequestGet = (request: string) => invoke<SettingRequestView>("settings_request_get", { request });
export const settingsRequestList = () => invoke<{ requests: SettingRequestView[] }>("settings_request_list", {});
export const settingsRequestDecide = (request: string, approve: boolean) =>
  invoke<{ request: string; state: string; applied: boolean; changeId?: string }>("settings_request_decide", { request, approve });
/**
 * @no-ui-caller the settings knowledge base is for AI clients (MCP credmgr_settings_kb) and `credmgr settings kb`; the app's own Help is generated from the same source.
 */
export const settingsKb = () => invoke<{ markdown: string; format: string }>("settings_kb", {});

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

/** What `windowState` answers. */
export interface WindowState {
  /** The window is in the Dock. */
  minimized: boolean;
  /** The window is shown (false when it or the whole app is hidden). A window covered by another, or on a display that is asleep, is still visible. */
  visible: boolean;
}

/** Whether the window is minimised or hidden, or only out of sight. Not a broker op, no login, no vault data. */
export const windowState = () => invoke<WindowState>("window_state");

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

// ---------------------------------------------------------------------------
// Touch ID, presence and sealed entries (ADR-098)
// ---------------------------------------------------------------------------

/** What this Mac can do for Touch ID. Local to the shell; never prompts. */
export interface PresenceProbe {
  secureEnclave: boolean;
  /** `touchid`, `faceid`, `other` or `none`. */
  biometry: string;
  /** A device password is set, so the prompt can fall back to it. */
  passcode: boolean;
  /** This Mac already holds a presence key. */
  keyOnThisMac: boolean;
}
export const presenceProbe = () => invoke<PresenceProbe>("presence_probe");

/** Create this Mac's Secure Enclave key (no prompt); answers its public half (base64) for {@link presenceEnrol}. */
export const presenceKeyCreate = () => invoke<string>("presence_key_create");

export interface PresenceStatus {
  helper: boolean;
  secureEnclave: boolean;
  biometry: string;
  passcode: boolean;
  enrolled: Array<{ id: string; label: string; createdAt: number }>;
  /** Unlocking this vault with Touch ID is set up. */
  touchIdUnlock: boolean;
}
export const presenceStatus = () => invoke<PresenceStatus>("presence_status");

/**
 * ADR-150: confirm it is the owner before a secret is shown again. With `passphrase`, the vault passphrase (`wrong_passphrase`
 * counts in the unlock back-off, then `rate_limited`); without it, Touch ID: the broker answers `presence_required` and the shell
 * shows the prompt and attaches the proof itself. When no presence key is enrolled that `presence_required` reaches the caller,
 * which then asks for the passphrase. Opens the session's trust window (`expiresIn` seconds; one request in every-time mode).
 */
export const sessionConfirm = (passphrase?: string) =>
  invoke<{ confirmed: true; method: "passphrase" | "presence"; expiresIn: number }>("session_confirm", { passphrase });

/** Ask the broker for a presence challenge. The shell does this itself when a request needs presence.
 *  `possession: true` (ADR-148) asks for the challenge a key being enrolled signs; the shell does that too.
 * @no-ui-caller the shell asks for a presence challenge itself when the broker wants Touch ID (presence.rs); the page never needs one.
 */
export const presenceChallenge = (op: string, params?: Record<string, unknown>, possession?: boolean) =>
  invoke<{ nonce: string; digest: string; expiresIn: number; reason: string }>("presence_challenge", {
    op,
    params,
    possession,
  });

/** Enrol this Mac's presence key. The first needs a fresh second factor (when one is on); later ones need Touch ID. */
export const presenceEnrol = (publicKey: string, label?: string) =>
  invoke<{ id: string; label: string; createdAt: number }>("presence_enrol", { publicKey, label });

export const presenceUnenrol = (id: string) => invoke<{ removed: boolean }>("presence_unenrol", { id });

/** Turn on unlocking with Touch ID (the vault must be open). */
export const deviceEnrol = () => invoke<{ touchIdUnlock: true }>("device_enrol");
export const deviceRemove = () => invoke<{ touchIdUnlock: false }>("device_remove");

// ---------------------------------------------------------------------------
// Machine lock (ADR-165): the passphrase wrap sealed to a device key file on this Mac
// ---------------------------------------------------------------------------

/**
 * What `keystore.status` answers (owner session only; agents are refused). `bound`: the passphrase wrap on disk is sealed, which
 * is the only place "bound" lives. `tier`: `"file"` (a 0600 key file outside the vault folder) or `"off"`; never the Secure
 * Enclave (`secureEnclave` is always false in this version). `opensHere`: the sealed wrap names the device key this Mac holds.
 * `protects` / `doesNotProtect`: the plain words the screens show, from the broker so they cannot drift.
 */
export interface KeystoreStatus {
  bound: boolean;
  tier: "file" | "off";
  secureEnclave: false;
  opensHere: boolean;
  sealedKeyId: string | null;
  damaged: boolean;
  deviceKeyPresent: boolean;
  deviceKeyId: string | null;
  deviceKeyUnreadable: boolean;
  /** The key file's mode lets others read it (the broker narrows it to 0600 the next time it reads it). */
  deviceKeyModeOpen?: boolean;
  /** The key file belongs to another user than its folder's. */
  deviceKeyForeignOwner?: boolean;
  recoveryUnlock: boolean;
  /** This Mac recorded the vault as bound (review P0-1). */
  markedBound?: boolean;
  /** Recorded as bound, yet the passphrase file on disk is plain: a bind was interrupted, or an old plain file was put back. */
  plainWhileBound?: boolean;
  /** Projects still on a key from before the lock was turned on (bind again to replace them). */
  preBindNodes?: string[];
  /** ADR-165 M5: this Mac's bind record names this vault folder under another vault id (`vault.id` edited or removed, or the folder put back to an older copy). Reported, never repaired. */
  recordDetached?: boolean;
  /** ADR-174 O-2: the device key file carries Time Machine's exclusion (`null`: no key file, or not macOS). */
  deviceKeyTimeMachineExcluded?: boolean | null;
  /** ADR-174 O-2: a Time Machine backup of the folder is covered: the wrap is sealed to a key made already excluded (never in a backup). */
  deviceKeyTimeMachineCovered?: boolean;
  /** ADR-174 O-3: the sync service the vault folder sits in ("iCloud Drive", "Dropbox", ...), or `null`. Bind refuses such a folder. */
  syncedFolder?: string | null;
  /** ADR-174 O-5: what each step of turning the lock on asks for beyond the passphrase and the recovery codes (Touch ID, a fresh second factor, or nothing more). */
  bindProof?: "presence" | "secondFactor" | "none";
  /** A plain-words warning to show beside the row when any of the three above is set (`null` otherwise). */
  warning?: string | null;
  protects: string;
  doesNotProtect: string;
}

/**
 * What `keystore.bind`'s `prepare` answers (review N1): the status, `changed: false` (nothing durable was written), and the NEW recovery
 * code the commit will make the only one that works (`newRecoveryCode`, shown once, never kept), which the commit takes typed back within
 * `expiresIn` seconds. A vault already bound answers `already: true`, no code, and the projects the commit will re-key (`nodesToRekey`).
 */
export type KeystorePrepared = KeystoreStatus & {
  phase: "prepare";
  changed: false;
  already: boolean;
  newRecoveryCode: string | null;
  expiresIn: number;
  nodesToRekey?: string[];
};

/**
 * What `keystore.bind`'s `commit` / `cancel` and `keystore.unbind` answer: the new status, whether anything changed, and (bind) whether a
 * key was made. A commit that changed something is a root rotation with every project re-keyed (review P0-1); the code it made live is
 * the one typed back, so it is not sent again. It carries `completionPending` / `meta.vaultLocked` as {@link RotateRootResult} does.
 */
export type KeystoreChange = KeystoreStatus & {
  changed: boolean;
  phase?: "commit" | "cancel";
  deviceKeyCreated?: boolean;
  nodesRekeyed?: string[];
  rekeyFailed?: Array<{ node: string; reason: string }>;
  /** The sealed-entries ("orphan") key pair was replaced in the same rotation. */
  orphanKeyReplaced?: boolean;
  /** The rotation's own answer (without its `recoveryCode`: the owner typed it back). */
  rotation?: Omit<RotateRootResult, "recoveryCode">;
  completionPending?: boolean;
};

export const keystoreStatus = () => invoke<KeystoreStatus>("keystore_status");
/**
 * Seal the passphrase wrap to this Mac, phase one (review N1): needs an open vault, the vault `passphrase` and the CURRENT `recoveryCode`
 * (the way back on a new Mac; a wrong one is `recovery_code_mismatch` and counts in the unlock back-off). Neither is kept. Changes
 * nothing; answers the NEW code in `newRecoveryCode`.
 */
/**
 * The one `keystore_bind` call, every phase (the drift guards want one call site per command, with its wire keys).
 * @no-ui-caller the app calls it only through keystoreBindPrepare, keystoreBindCommit and keystoreBindCancel just below (Settings > Security > Machine lock).
 */
export const keystoreBind = (phase: "prepare" | "commit" | "cancel", passphrase?: string, recoveryCode?: string) =>
  invoke<KeystorePrepared | KeystoreChange>("keystore_bind", { phase, passphrase, recoveryCode });
export const keystoreBindPrepare = (passphrase: string, recoveryCode: string) =>
  keystoreBind("prepare", passphrase, recoveryCode) as Promise<KeystorePrepared>;
/**
 * Phase two: the new code typed back (omitted for a vault that was already bound). Only now is the lock turned on. A code that is not the
 * one shown is `recovery_code_mismatch` (not counted; the prepared bind still waits); a missing, expired or overtaken one is
 * `malformed_request`, and the person starts again.
 */
export const keystoreBindCommit = (newRecoveryCode?: string) =>
  keystoreBind("commit", undefined, newRecoveryCode || undefined) as Promise<KeystoreChange>;
/** Forget a prepared bind (the dialog was closed). Nothing durable was changed by it. */
export const keystoreBindCancel = () => keystoreBind("cancel") as Promise<KeystoreChange>;
/**
 * Turn the machine lock off. Needs a fresh second factor where one is on (`two_factor_required`: verify with
 * {@link vaultGateVerify} and repeat), Touch ID where a presence key is enrolled (the shell attaches the proof itself), and the vault
 * `passphrase` where neither is set up (without it the broker answers `malformed`, naming `params.passphrase`).
 */
export const keystoreUnbind = (passphrase?: string) => invoke<KeystoreChange>("keystore_unbind", passphrase ? { passphrase } : {});

// ---------------------------------------------------------------------------
// Start at login (ADR-156): the shell's own, local commands - no broker op
// ---------------------------------------------------------------------------

/**
 * Whether the launch agent that starts `credmgrd` at login is in place (macOS only; elsewhere every call rejects with
 * `platform_unsupported`). `installed`: `~/Library/LaunchAgents/com.credmgr.brokerd.plist` exists; `current`: it is exactly what
 * {@link loginAgentInstall} would write now; `loaded`: launchd has it in this user's `gui/<uid>` domain; `daemon`: the absolute path
 * of the `credmgrd` it would start (`null` when none was found).
 */
export interface LoginAgentStatus {
  installed: boolean;
  current: boolean;
  loaded: boolean;
  daemon: string | null;
}
export const loginAgentStatus = () => invoke<LoginAgentStatus>("login_agent_status");

/**
 * Write the launch agent (pointing at the bundled `credmgrd` by absolute path) and load it into this user's launchd domain, which
 * starts the broker now and at every login. Never root. Idempotent: an agent already in place and loaded is left alone.
 * Rejects with `login_agent_failed` when no `credmgrd` was found or launchd said no.
 */
export const loginAgentInstall = () => invoke<LoginAgentStatus>("login_agent_install");

/** Unload the launch agent (which stops the broker it started, and so locks the vault) and remove its file. Idempotent. */
export const loginAgentUninstall = () => invoke<LoginAgentStatus>("login_agent_uninstall");

// ---------------------------------------------------------------------------
// Restore from a backup (ADR-166): the shell's own, local command - no broker op
// ---------------------------------------------------------------------------

/** What {@link backupRestore} wrote. `counter`: the generation counter was `restored` (an older backup), an existing one `keptExisting`, a one-time restore marker was written (`acceptMarker`, ADR-148 amendment), or `notInArchive`. */
export interface RestoreDone {
  target: string;
  stateDir: string;
  files: number;
  bytes: number;
  counter: "restored" | "keptExisting" | "notInArchive" | "acceptMarker" | (string & {});
  /** `false` for an archive older than the complete format: no notes, sealed nodes, removed entries or history in it. */
  complete: boolean;
}

/**
 * Restore a backup archive (`archive`, a file path) into an empty folder (`target`; left out, the vault's own folder, which must then be
 * empty). The shell runs the bundled `credmgr restore --json` with the passphrase on its stdin, so the app and the terminal share one
 * restore and one set of refusals: `broker_running` while a broker answers on the vault's socket (which is always, while this window is
 * unlocked), `restore_target_not_empty`, `restore_failed`, `restore_unavailable`. Local: no broker op, no session, no audit record.
 */
export const backupRestore = (archive: string, passphrase: string, target?: string) =>
  invoke<RestoreDone>("backup_restore", { archive, passphrase, target });

/**
 * The sealed ("orphaned") entries: names only.
 * @no-ui-caller the app reads sealed entries through entry_list on the orphaned node (bridge-source.ts) and opens them with orphan_reveal; orphan_list serves `credmgr orphan ls`.
 */
export const orphanList = () =>
  invoke<{ entries: Array<{ entry: string; name: string; ref: number; type: string; modified: number }> }>(
    "orphan_list",
  );

/** Read one sealed entry. Costs a fresh second factor and a Touch ID check every time. */
export const orphanReveal = (entry: string, fieldIds?: string[]) =>
  invoke<EntryReveal>("orphan_reveal", { entry, fieldIds });

// ---------------------------------------------------------------------------
// Agents: Settings -> Agents (ADR-141, ADR-142, ADR-143). Local to the shell; no broker call.
// ---------------------------------------------------------------------------

/** One agent client on this Mac. `state`: `not_found`, `ready` (present, not wired), `connected`, `other_entry` (a different credmgr entry is there), `unreadable`. */
export interface AgentClientRow {
  client: "claude-code" | "claude-desktop" | "cursor" | "vscode" | "windsurf";
  label: string;
  path: string;
  state: "not_found" | "ready" | "connected" | "other_entry" | "unreadable";
  /** Why it is unreadable, when it is. */
  detail: string | null;
  /** CredMgr may offer to write this client's file. False for Claude Code (its file is live state): it shows a command instead. */
  writable: boolean;
  container: string;
}
export interface AgentDetect {
  /** The `credmgr` binary a snippet carries, and whether it was found on this Mac. */
  binary: string;
  binaryFound: boolean;
  clients: AgentClientRow[];
  claudeCodeCommand: string;
}
export const agentDetect = () => invoke<AgentDetect>("agent_detect");

/** The text to copy for a client (`generic` for any other). For Claude Code `command` is the one-line alternative. */
export const agentSnippet = (client: string) =>
  invoke<{ client: string; snippet: string; command: string | null }>("agent_snippet", { client });

export interface AgentPlan {
  client: string;
  label: string;
  action: "connect" | "disconnect";
  path: string;
  exists: boolean;
  /** Nothing to do: already connected (or not connected). */
  unchanged: boolean;
  diff: Array<{ kind: " " | "+" | "-"; text: string }>;
  /** The copy taken before the write, e.g. `mcp.json.credmgr-backup-<time>`; null when the file does not exist yet. */
  backupName: string | null;
  /** Pass to {@link agentApply}: it writes only if the file is still what the diff showed. */
  token: string;
}
/** What connecting would change. Writes nothing. */
export const agentPlan = (client: string, action: "connect" | "disconnect") =>
  invoke<AgentPlan>("agent_plan", { client, action });

/** Write the planned change, from the button in the diff dialog only. Backs the file up first and reads it back. */
export const agentApply = (client: string, action: "connect" | "disconnect", token: string) =>
  invoke<{ written: boolean; path: string; backup?: string | null; restart?: string }>("agent_apply", {
    client,
    action,
    token,
  });

/** The Vault Protocol prompt (`format: "prompt"`) or the text of CREDMGR.md (`"md"`), for a node. Names and structure only. */
export const agentPrompt = (node: string, reachable: string[], level: SecurityLevel, format: "prompt" | "md") =>
  invoke<{ text: string; format: string }>("agent_prompt", { node, reachable, level, format });

// -- 2.0.0 broker features (ADR-130…134) ---------------------------------------------------------

/**
 * Replace a node's key and re-seal everything sealed to the old one. Costs a fresh second factor and Touch ID.
 * @no-ui-caller no screen yet (rc.2 backlog): a new key for a node is `credmgr node rekey` (ADR-130).
 */
export const nodeRekey = (node: string) =>
  invoke<{ node: string; publicKey: string; entries: number; note: boolean; history: number; removed: number }>(
    "node_rekey",
    { node },
  );

/** The word `orphan_destroy` wants in `confirm`: the person says they mean it. */
export const DESTROY_CONFIRM_WORD = "destroy-sealed-entries";

/**
 * Permanently destroy sealed entries and the archives behind them. `count` is the number of entries the
 * person was shown (the broker compares it); `entries` names ids, absent means every sealed entry. Costs a
 * fresh second factor and Touch ID. Cannot be undone.
 * @no-ui-caller permanent deletion stays a deliberate command-line step by design (`credmgr orphan destroy` with the count shown and a typed confirmation word, HELP "orphan-destroy").
 */
export const orphanDestroy = (confirm: string, count: number, entries?: string[]) =>
  invoke<{ destroyed: number; sealsForgotten: number; archivesRemoved: number }>("orphan_destroy", {
    confirm,
    count,
    entries,
  });

/**
 * Entries whose field VALUES contain `term`: node, id and name only - never a value. Needs `reveal`; rate limited.
 * @no-ui-caller no screen yet (rc.2 backlog): a search of values needs the reveal capability and is rate limited; `credmgr search --content`.
 */
export const searchContent = (term: string, node?: string) =>
  invoke<{ results: Array<{ node: string; id: string; name: string }>; truncated: boolean }>("search_content", {
    term,
    node,
  });

/**
 * An age-encrypted archive of a node, built inside the broker (base64). Give a passphrase (12+ characters)
 * or age recipients. Costs a fresh second factor and Touch ID. 2FA seeds are left out and counted.
 * @no-ui-caller no screen yet (rc.2 backlog): the archive comes back as base64 and the app has no save-to-file path (no file plugin, ADR-166 §7); `credmgr node export`.
 */
export const nodeExport = (node: string, passphrase?: string, recipients?: string[]) =>
  invoke<{ node: string; format: "age-v1"; entries: number; omittedSeeds: number; archive: string }>(
    "node_export",
    { node, passphrase, recipients },
  );

// -- A node's own second factor (ADR-135) ----------------------------------------------------

/**
 * Begin giving a project a second factor of its own. Not for `global` (use the vault's own `vaultGateEnroll*`).
 * @no-ui-caller no screen yet (rc.2 backlog): a project's own second factor (ADR-135) is set up with `credmgr node gate enroll`.
 */
export const nodeGateEnrollBegin = (node: string) =>
  invoke<{ node: string; otpauthUri: string }>("node_gate_enroll_begin", { node });

/**
 * Confirm it with one valid code; the project's own ten recovery codes come back once.
 * @no-ui-caller no screen yet (rc.2 backlog): a project's own second factor (ADR-135) is set up with `credmgr node gate enroll`.
 */
export const nodeGateEnrollConfirm = (node: string, code: string) =>
  invoke<{ node: string; recoveryCodes: string[] }>("node_gate_enroll_confirm", { node, code });

/**
 * Step up for one project: its own code opens that project (and no other) for five minutes.
 * @no-ui-caller no screen yet (rc.2 backlog): stepping up with a project's own second factor (ADR-135) is `credmgr node gate verify`.
 */
export const nodeGateVerify = (node: string, code: string) =>
  invoke<{ node: string; elevated: true; expiresIn: number }>("node_gate_verify", { node, code });

/**
 * Remove a project's own second factor. With neither optional it needs its fresh code and Touch ID; with
 * the vault `passphrase` and the root `recoveryCode` together it is the last door for a lost authenticator.
 * @no-ui-caller no screen yet (rc.2 backlog): removing a project's own second factor (ADR-135) is `credmgr node gate remove`.
 */
export const nodeGateRemove = (node: string, passphrase?: string, recoveryCode?: string) =>
  invoke<{ node: string; removed: boolean }>("node_gate_remove", { node, passphrase, recoveryCode });

export interface AuditReport {
  from: number;
  to: number;
  node: string | null;
  records: number;
  decisions: { allow: number; deny: number; other: number };
  byAction: Array<{ action: string; count: number; allow: number; deny: number }>;
  byActor: Array<{ actor: string; count: number; allow: number; deny: number }>;
  byNode: Array<{ node: string; count: number; allow: number; deny: number }>;
  denials: {
    total: number;
    reasons: Array<{ action: string; reason: string; count: number }>;
    recent: Array<{ id: string; timestamp: number; actor: string; action: string; node: string | null; reason: string }>;
  };
  presence: { uses: number; byOp: Array<{ op: string; count: number }>; refused: number };
  chain: { months: string[]; verified: boolean };
}

/** A summary of the audit log for `[from, to)` (unix seconds). No values, no entry names. */
export const auditReport = (from: number, to: number, node?: string) =>
  invoke<AuditReport>("audit_report", { from, to, node });
