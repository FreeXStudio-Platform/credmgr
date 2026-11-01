/**
 * `BridgeSource`: the model's data, from the broker, through src/lib/bridge.ts.
 *
 * Everything here is a mapping from the wire's vocabulary to the view's (types.ts), plus the handful of decisions about
 * which per-node failures are survivable.  No secret is ever mapped into a view type; a revealed value is returned to
 * the model's private store and nowhere else.
 */
import type * as live from "../lib/bridge";
import { errorCode } from "./errors";
import type { AuthLite, EntriesPart, GraphPart, LockResult, ModelSource } from "./source";
import { isUnreadableCode, type DEntry, type DEntryDetail, type DGrant, type DLink, type DNode, type DOrphan, type DPending, type DSealed, type DSensitivity, type UnreadableCode } from "./types";

/** The slice of src/lib/bridge.ts this source uses.  Wiring packages that read more extend the Pick. */
export type BridgeFns = Pick<
  typeof live,
  "vaultStatus" | "vaultUnlock" | "vaultGateVerify" | "vaultLock" | "graphSnapshot" | "entryList" | "entryGet" | "entryReveal" | "grantList" | "vaultPendingList" | "notesRead"
>;

const SENSITIVITIES: readonly string[] = ["low", "medium", "high", "critical"];

/**
 * Per-node failures that leave the rest of the vault readable.  What is shown for the node differs, and the difference matters:
 *  - a node this login may not read (`node_locked`, `node_access_denied`, `capability_not_held`) is reported as UNREADABLE for entries:
 *    its entries exist and are out of reach, which is not the same as having none;
 *  - a node that is gone (`not_found`: sealed or removed since the last graph) simply has nothing to list, and the graph read drops it.
 * Pending items and notes are secondary: their failures degrade to "none shown" / "no note".
 */
const SURVIVABLE = new Set(["node_locked", "node_access_denied", "capability_not_held", "not_found"]);

/** What the broker itself would answer once the vault is locked; shaped like a rejection from src/lib/bridge.ts. */
const VAULT_LOCKED = { source: "broker", code: "vault_locked", message: "the vault is locked" } as const;

/** Unix seconds to `YYYY-MM-DD` (UTC, so the same everywhere). */
export const isoDate = (secs: number): string => new Date(secs * 1000).toISOString().slice(0, 10);

export function mapNode(n: live.GraphNode): DNode {
  return {
    id: n.id,
    label: n.label,
    kind: n.kind === "global" || n.kind === "sub" ? n.kind : "project",
    depth: n.depth,
    parentId: n.parentId,
    counts: { entries: n.counts.entries, totp: n.counts.totp },
    gate: { locked: n.gate.locked, twofa: n.gate.twofa },
    ...(n.nameHidden === true ? { nameHidden: true } : {}),
    health: null,
    notes: null,
  };
}

export function mapEntryRow(row: live.EntryListRow): DEntry {
  const sensitivity: DSensitivity | null = SENSITIVITIES.includes(row.sensitivity) ? row.sensitivity : null;
  const parts = [row.type, ...(sensitivity ? [sensitivity] : []), ...(row.rotatedAt ? [`rotated ${isoDate(row.rotatedAt)}`] : [])];
  return {
    id: row.id,
    name: row.name,
    type: row.type,
    sensitivity,
    totp: row.hasTotp === true || row.type === "totp", // ADR-080: hasTotp is the broker's word (a login entry may carry a TOTP field)
    meta: parts.join(" · "),
    fieldCount: typeof row.fieldCount === "number" && row.fieldCount > 0 ? row.fieldCount : 1,
    // The list carries no labels (they are encrypted with the values), so there is nothing to show of the fields here: they are read
    // on demand with `entry.get` into the model's entry detail.  Nothing is invented in their place.
    fields: [],
  };
}

/** `entry.get`'s answer in the view's vocabulary.  It carries no value, and none is added. */
export function mapEntryMeta(m: live.EntryMeta): DEntryDetail {
  return {
    node: m.node,
    entry: m.entry,
    name: m.name,
    type: m.type,
    sensitivity: SENSITIVITIES.includes(m.sensitivity) ? m.sensitivity : null,
    fieldCount: m.fieldCount,
    hasTotp: m.hasTotp,
    generation: m.generation,
    typeOverridden: m.typeOverridden,
    sensitivityOverridden: m.sensitivityOverridden,
    modified: m.modified,
    rotatedAt: m.rotatedAt,
    expiresAt: m.expiresAt,
    fields: m.fields.map((f) => ({ id: f.id, label: f.label, type: f.type, masked: f.masked, typeOverridden: f.typeOverridden, maskedOverridden: f.maskedOverridden })),
  };
}

/** Older brokers answer `ids`/`names` only (no `entries`): the entry then has a neutral type and no sensitivity. */
export function mapEntryList(list: live.EntryList): EntriesPart {
  const rows = Array.isArray(list.entries) ? list.entries : null;
  const entries = rows
    ? rows.map(mapEntryRow)
    : (list.ids ?? []).map((id, i) =>
        mapEntryRow({ id, name: list.names?.[i] ?? id, type: "other", sensitivity: "" as DSensitivity, fieldCount: 1, modified: 0, rotatedAt: null, expiresAt: null, hasTotp: false }),
      );
  return { entries, generation: typeof list.generation === "number" ? list.generation : 0 };
}

export function mapGrant(g: live.Grant): DGrant {
  return {
    id: g.id,
    from: g.from,
    to: g.to.nodeId,
    toEntry: g.to.kind === "entry" ? g.to.entryId : null,
    scope: g.scope.join(" · "),
    expires: g.expiresAt === null ? "never" : isoDate(g.expiresAt),
    lastUsed: "—",
    reason: g.reason,
  };
}

export function mapPending(node: string, p: live.PendingItem): DPending {
  return {
    id: p.entry,
    node,
    name: p.name,
    type: p.type,
    sensitivity: p.sensitivity,
    fieldCount: p.fieldCount,
    created: p.created,
    // A held entry is sealed until it is accepted: its labels are not readable, so only the count is shown.
    fields: [],
    totp: p.type === "totp",
    by: "",
    when: new Date(p.created * 1000).toTimeString().slice(0, 5),
  };
}

const auth = (a: live.AuthState): AuthLite => ({ locked: a.locked, authenticated: a.authenticated, initialized: a.initialized !== false, pendingApprovals: a.pendingApprovals ?? 0 });

export class BridgeSource implements ModelSource {
  readonly kind = "bridge" as const;
  private orphanId: string | null = null;
  private orphanUnreadable: UnreadableCode | null = null;

  constructor(private readonly fns: BridgeFns) {}

  async status(): Promise<AuthLite> {
    return auth(await this.fns.vaultStatus());
  }

  async unlock(passphrase: string): Promise<AuthLite> {
    return auth(await this.fns.vaultUnlock(passphrase));
  }

  async gateVerify(code: string): Promise<AuthLite> {
    return auth(await this.fns.vaultGateVerify(code));
  }

  async lock(): Promise<LockResult> {
    // The bridge drops its token before it answers, whatever the broker says, so a failure here is not a reason to stay open.
    // It is a reason to SAY so: "this window is locked" and "the broker locked the vault" are different claims.
    try {
      await this.fns.vaultLock();
      return { confirmed: true, code: null };
    } catch (e) {
      const code = errorCode(e);
      // The login was already gone (idle lock, a lock from the command line): the vault IS locked, which is what was asked for.
      if (code === "vault_locked" || code === "session_expired") return { confirmed: true, code: null };
      return { confirmed: false, code: code ?? "unknown" };
    }
  }

  async graph(): Promise<GraphPart> {
    const snap = await this.fns.graphSnapshot();
    // The snapshot is served even while the vault is locked, and `meta.vaultLocked` is how an idle auto-lock is noticed
    // (bridge.ts rule 4).  Treat it as the lost login it is, so every caller's error routing ends at the Lock screen.
    if (snap.meta?.vaultLocked === true) throw VAULT_LOCKED;
    const orphan = snap.nodes.find((n) => n.kind === "orphan") ?? null;
    this.orphanId = orphan ? orphan.id : null;
    const nodes = snap.nodes.filter((n) => n.kind !== "orphan").map(mapNode);
    const known = new Set(nodes.map((n) => n.id));
    const links: DLink[] = snap.links.filter((l) => known.has(l.source) && known.has(l.target)).map((l) => ({ source: l.source, target: l.target, kind: "structural" as const }));
    // ADR-080: a human Admin's snapshot lists what is sealed and restorable, across locks and restarts.  The key is absent for anyone else.
    const sealed: DSealed[] | undefined = Array.isArray(snap.meta?.sealed)
      ? snap.meta.sealed.map((s) => ({ id: s.id, label: s.label, sealedAt: s.sealedAt, expiresAt: s.expiresAt }))
      : undefined;
    return { nodes, links, orphanNodeId: this.orphanId, ...(sealed ? { sealed } : {}) };
  }

  async grants(): Promise<DGrant[]> {
    return (await this.fns.grantList()).grants.map(mapGrant);
  }

  async entries(node: string): Promise<EntriesPart> {
    try {
      return mapEntryList(await this.fns.entryList(node));
    } catch (e) {
      const c = errorCode(e);
      if (isUnreadableCode(c)) return { entries: [], generation: 0, unreadable: c }; // out of this login's reach: NOT an empty node
      if (c && SURVIVABLE.has(c)) return { entries: [], generation: 0 }; // not_found: the node is gone, so there is nothing to list
      throw e;
    }
  }

  async orphans(): Promise<DOrphan[]> {
    this.orphanUnreadable = null;
    if (!this.orphanId) return [];
    const part = await this.entries(this.orphanId);
    this.orphanUnreadable = part.unreadable ?? null;
    return part.entries.map((e) => ({ id: e.id, name: e.name }));
  }

  orphansUnreadable(): UnreadableCode | null {
    return this.orphanUnreadable;
  }

  async pending(node: string): Promise<DPending[]> {
    try {
      return (await this.fns.vaultPendingList(node)).pending.map((p) => mapPending(node, p));
    } catch (e) {
      const c = errorCode(e);
      if (c && SURVIVABLE.has(c)) return [];
      throw e;
    }
  }

  async notes(node: string): Promise<string | null> {
    try {
      return (await this.fns.notesRead(node)).markdown;
    } catch (e) {
      const c = errorCode(e);
      if (c && SURVIVABLE.has(c)) return null;
      throw e;
    }
  }

  async entryMeta(node: string, entry: string): Promise<DEntryDetail> {
    return mapEntryMeta(await this.fns.entryGet(node, entry));
  }

  /**
   * ONE field's plaintext.  `field` is the field's id and the reveal is narrowed to it (`fieldIds`), so the other fields of the
   * entry are never read.  A call that names no field is answered only if the entry turns out to hold exactly one; a several-field
   * answer for it is refused, because there is no one value to hand back and nothing here may guess which one was meant.
   */
  async reveal(node: string, entry: string, field?: number | string): Promise<string> {
    const r = typeof field === "string" ? await this.fns.entryReveal(node, entry, [field]) : await this.fns.entryReveal(node, entry);
    if (!Array.isArray(r.fields) || r.fields.length !== 1) {
      throw { source: "bridge", code: "field_required", message: "the entry holds several fields: name the one to reveal" } as const;
    }
    return r.fields[0].value;
  }

  /** Several fields in ONE read: the broker answers exactly the ids asked for (or `not_found` for the whole call), in stored order. */
  async revealFields(node: string, entry: string, fields: string[]): Promise<Array<{ id: string; value: string }>> {
    const r = await this.fns.entryReveal(node, entry, fields);
    if (!Array.isArray(r.fields) || r.fields.length !== fields.length) {
      throw { source: "bridge", code: "malformed_response", message: "the broker answered a different set of fields than was asked for" } as const;
    }
    return r.fields.map((f) => ({ id: f.id, value: f.value }));
  }
}
