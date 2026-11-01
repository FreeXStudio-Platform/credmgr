// BridgeSource: the mapping from the wire's vocabulary to the view's, and which per-node failures are survivable.
import { describe, expect, it } from "vitest";

import type * as live from "../../src/lib/bridge";
import { BridgeSource, isoDate, mapEntryList, mapEntryMeta, mapEntryRow, mapGrant, mapNode, mapPending, type BridgeFns } from "../../src/vault/bridge-source";

const wireNode = (over: Partial<live.GraphNode> = {}): live.GraphNode => ({ id: "atlas", label: "atlas", kind: "project", depth: 1, parentId: "global", counts: { entries: 3, totp: 1 }, gate: { locked: true, twofa: "required" }, health: null, ...over });
const row = (over: Partial<live.EntryListRow> = {}): live.EntryListRow => ({ id: "e1", name: "stripe", type: "api", sensitivity: "high", fieldCount: 1, modified: 1, rotatedAt: null, expiresAt: null, hasTotp: false, ...over });
const bad = (code: string) => ({ source: "broker", code, message: code });

function fns(over: Partial<BridgeFns> = {}): BridgeFns {
  const nope = () => Promise.reject(new Error("not stubbed"));
  return { vaultStatus: nope, vaultUnlock: nope, vaultGateVerify: nope, vaultLock: nope, graphSnapshot: nope, entryList: nope, entryGet: nope, entryReveal: nope, grantList: nope, vaultPendingList: nope, notesRead: nope, ...over } as BridgeFns;
}

describe("mapping", () => {
  it("maps a node, with its counts and gate, and no note yet", () => {
    expect(mapNode(wireNode())).toEqual({ id: "atlas", label: "atlas", kind: "project", depth: 1, parentId: "global", counts: { entries: 3, totp: 1 }, gate: { locked: true, twofa: "required" }, health: null, notes: null });
    expect(mapNode(wireNode({ kind: "sub", depth: 2 })).kind).toBe("sub");
    expect(mapNode(wireNode({ kind: "global", depth: 0, parentId: null })).kind).toBe("global");
  });

  it("maps an entry row: type, sensitivity, a one-line meta with the rotation date, the field COUNT, and no invented fields, no value", () => {
    const e = mapEntryRow(row({ rotatedAt: Date.UTC(2026, 5, 30) / 1000 }));
    // The list carries no labels (they are encrypted with the values): the row claims no field it was not told about.
    expect(e).toEqual({ id: "e1", name: "stripe", type: "api", sensitivity: "high", totp: false, meta: "api · high · rotated 2026-06-30", fieldCount: 1, fields: [] });
    expect(mapEntryRow(row({ fieldCount: 5 })).fieldCount).toBe(5);
    expect(JSON.stringify(e)).not.toContain("value");
    expect(mapEntryRow(row({ type: "totp" })).totp).toBe(true);
    expect(mapEntryRow(row({ sensitivity: "bogus" as live.EntryListRow["sensitivity"] }))).toMatchObject({ sensitivity: null, meta: "api" });
  });

  it("falls back to ids and names when an older broker sends no entries", () => {
    const old = { node: "n", ids: ["a", "b"], names: ["A", "B"], generation: 4 } as unknown as live.EntryList;
    const part = mapEntryList(old);
    expect(part.generation).toBe(4);
    expect(part.entries.map((e) => [e.id, e.name, e.type, e.sensitivity])).toEqual([["a", "A", "other", null], ["b", "B", "other", null]]);
  });

  it("maps a grant to a plain row, 'never' when it does not expire", () => {
    const g = mapGrant({ id: "g1", from: "beacon", to: { kind: "node", nodeId: "atlas" }, direction: "one-way", scope: ["read", "notes"], expiresAt: null, reason: "r" });
    expect(g).toEqual({ id: "g1", from: "beacon", to: "atlas", toEntry: null, scope: "read · notes", expires: "never", lastUsed: "—", reason: "r" });
    expect(mapGrant({ id: "g2", from: "a", to: { kind: "entry", nodeId: "b", entryId: "e" }, direction: "one-way", scope: ["read"], expiresAt: Date.UTC(2026, 7, 30) / 1000, reason: "r" })).toMatchObject({ to: "b", toEntry: "e", expires: "2026-08-30" });
  });

  it("maps a tray item with the broker's field COUNT and no invented fields (a held entry's labels are not readable)", () => {
    const p = mapPending("atlas", { entry: "p1", name: "held", type: "api", sensitivity: "high", fieldCount: 2, created: 1_700_000_000 });
    expect(p).toMatchObject({ id: "p1", node: "atlas", fieldCount: 2, by: "" });
    expect(p.fields).toEqual([]);
    expect(JSON.stringify(p)).not.toContain("value\":\"");
  });

  it("maps entry.get to a detail: ids, labels, types, masking and the pins, never a value", () => {
    const meta: live.EntryMeta = {
      node: "atlas", entry: "e2", name: "pg-main", ref: 2, type: "server", sensitivity: "critical", fieldCount: 2, hasTotp: false, modified: 5, rotatedAt: null, expiresAt: null, generation: 7,
      typeOverridden: false, sensitivityOverridden: true,
      fields: [
        { id: "f_00000001", label: "host", type: "host", masked: false, typeOverridden: false, maskedOverridden: false },
        { id: "f_00000002", label: "", type: "password", masked: true, typeOverridden: true, maskedOverridden: false },
      ],
    };
    const d = mapEntryMeta(meta);
    expect(d).toMatchObject({ node: "atlas", entry: "e2", name: "pg-main", type: "server", sensitivity: "critical", fieldCount: 2, hasTotp: false, generation: 7, sensitivityOverridden: true });
    expect(d.fields).toEqual([
      { id: "f_00000001", label: "host", type: "host", masked: false, typeOverridden: false, maskedOverridden: false },
      { id: "f_00000002", label: "", type: "password", masked: true, typeOverridden: true, maskedOverridden: false },
    ]);
    expect(mapEntryMeta({ ...meta, sensitivity: "bogus" as live.SensitivityName }).sensitivity).toBeNull();
  });

  it("isoDate is UTC", () => {
    expect(isoDate(0)).toBe("1970-01-01");
  });
});

describe("BridgeSource", () => {
  it("keeps the orphan node out of the node list and remembers it", async () => {
    const src = new BridgeSource(
      fns({
        graphSnapshot: async () => ({ nodes: [wireNode({ id: "global", kind: "global", depth: 0, parentId: null }), wireNode(), wireNode({ id: "orph", kind: "orphan" })], links: [{ source: "global", target: "atlas", kind: "structural", direction: "down" }, { source: "global", target: "orph", kind: "structural", direction: "down" }], meta: { generatedAt: 1, vaultLocked: false } }),
        entryList: async (node: string) => ({ node, ids: ["o1"], names: ["old-root"], entries: [row({ id: "o1", name: "old-root" })], generation: 1 }),
      }),
    );
    const g = await src.graph();
    expect(g.nodes.map((n) => n.id)).toEqual(["global", "atlas"]);
    expect(g.links).toEqual([{ source: "global", target: "atlas", kind: "structural" }]);
    expect(g.orphanNodeId).toBe("orph");
    expect(await src.orphans()).toEqual([{ id: "o1", name: "old-root" }]);
  });

  it("treats a missing 'initialized' (an older bridge) as initialized", async () => {
    const src = new BridgeSource(fns({ vaultStatus: async () => ({ locked: true, authenticated: false } as live.AuthState) }));
    expect((await src.status()).initialized).toBe(true);
    const first = new BridgeSource(fns({ vaultStatus: async () => ({ locked: true, authenticated: false, initialized: false }) }));
    expect((await first.status()).initialized).toBe(false);
  });

  it("lock never throws, and says whether the broker confirmed it: the bridge drops its login whatever the broker says", async () => {
    const ok = new BridgeSource(fns({ vaultLock: async () => ({ locked: true, authenticated: false, initialized: true }) }));
    expect(await ok.lock()).toEqual({ confirmed: true, code: null });
    const down = new BridgeSource(fns({ vaultLock: () => Promise.reject(bad("broker_unreachable")) }));
    expect(await down.lock()).toEqual({ confirmed: false, code: "broker_unreachable" });
    const refused = new BridgeSource(fns({ vaultLock: () => Promise.reject(bad("internal")) }));
    expect(await refused.lock()).toEqual({ confirmed: false, code: "internal" });
    // not even a broker error: still no rejection, and no message copied out of the error
    const odd = new BridgeSource(fns({ vaultLock: () => Promise.reject(new Error("secret-looking text")) }));
    expect(await odd.lock()).toEqual({ confirmed: false, code: "unknown" });
  });

  it("a lock that finds the vault already locked IS confirmed: that is what was asked for", async () => {
    for (const code of ["vault_locked", "session_expired"]) {
      const src = new BridgeSource(fns({ vaultLock: () => Promise.reject(bad(code)) }));
      expect(await src.lock()).toEqual({ confirmed: true, code: null });
    }
  });

  it("a node this login may not read is reported UNREADABLE (not as an empty node) without failing the whole load; a node that is gone is just empty; a lost login is not survived", async () => {
    for (const code of ["node_locked", "node_access_denied", "capability_not_held"]) {
      const src = new BridgeSource(fns({ entryList: () => Promise.reject(bad(code)), vaultPendingList: () => Promise.reject(bad(code)), notesRead: () => Promise.reject(bad(code)) }));
      expect(await src.entries("n"), code).toEqual({ entries: [], generation: 0, unreadable: code });
      expect(await src.pending("n")).toEqual([]);
      expect(await src.notes("n")).toBeNull();
    }
    const missing = new BridgeSource(fns({ entryList: () => Promise.reject(bad("not_found")), vaultPendingList: () => Promise.reject(bad("not_found")), notesRead: () => Promise.reject(bad("not_found")) }));
    expect(await missing.entries("n")).toEqual({ entries: [], generation: 0 }); // gone: nothing to list, nothing unreadable
    expect(await missing.pending("n")).toEqual([]);
    expect(await missing.notes("n")).toBeNull();
    const gone = new BridgeSource(fns({ entryList: () => Promise.reject(bad("vault_locked")), vaultPendingList: () => Promise.reject(bad("session_expired")), notesRead: () => Promise.reject(bad("internal")) }));
    await expect(gone.entries("n")).rejects.toMatchObject({ code: "vault_locked" });
    await expect(gone.pending("n")).rejects.toMatchObject({ code: "session_expired" });
    await expect(gone.notes("n")).rejects.toMatchObject({ code: "internal" });
  });

  it("the orphaned node that cannot be listed is reported as unreadable too, and a later readable list clears it", async () => {
    let refuse: string | null = "node_access_denied";
    const src = new BridgeSource(
      fns({
        graphSnapshot: async () => ({ nodes: [wireNode({ id: "global", kind: "global", depth: 0, parentId: null }), wireNode({ id: "orph", kind: "orphan" })], links: [], meta: { generatedAt: 1, vaultLocked: false } }),
        entryList: async (node: string) => {
          if (refuse) throw bad(refuse);
          return { node, ids: ["o1"], names: ["old-root"], entries: [row({ id: "o1", name: "old-root" })], generation: 1 };
        },
      }),
    );
    expect(src.orphansUnreadable()).toBeNull(); // before anything was asked
    await src.graph();
    expect(await src.orphans()).toEqual([]);
    expect(src.orphansUnreadable()).toBe("node_access_denied");
    refuse = null;
    expect(await src.orphans()).toEqual([{ id: "o1", name: "old-root" }]);
    expect(src.orphansUnreadable()).toBeNull();
  });

  it("reveal narrows the broker's read to the ONE field named, and returns just that value", async () => {
    let seen: unknown[] = [];
    const one: live.EntryReveal = { node: "n", entry: "e", fields: [{ id: "f_00000002", label: "pw", value: "v", type: "password", masked: true }], value: "v" };
    const src = new BridgeSource(fns({ entryReveal: async (...a: unknown[]) => ((seen = a), one) }));
    expect(await src.reveal("n", "e", "f_00000002")).toBe("v");
    expect(seen).toEqual(["n", "e", ["f_00000002"]]);
  });

  it("reveal without a field id is answered only for an entry of exactly one field; several fields are refused, never guessed at", async () => {
    const f = (id: string) => ({ id, label: id, value: "v-" + id, type: "text" as const, masked: false });
    const single = new BridgeSource(fns({ entryReveal: async () => ({ node: "n", entry: "e", fields: [f("f_00000000")], value: "v-f_00000000" }) }));
    expect(await single.reveal("n", "e", 0)).toBe("v-f_00000000");
    const several = new BridgeSource(fns({ entryReveal: async () => ({ node: "n", entry: "e", fields: [f("f_00000001"), f("f_00000002")] }) }));
    await expect(several.reveal("n", "e", 0)).rejects.toMatchObject({ code: "field_required" });
  });

  it("revealFields reads exactly the ids asked for in ONE call, and refuses an answer that is a different set", async () => {
    const calls: unknown[][] = [];
    const f = (id: string) => ({ id, label: id, value: "v-" + id, type: "text" as const, masked: false });
    const src = new BridgeSource(fns({ entryReveal: async (...a: unknown[]) => (calls.push(a), { node: "n", entry: "e", fields: [f("f_00000001"), f("f_00000003")] }) }));
    expect(await src.revealFields("n", "e", ["f_00000001", "f_00000003"])).toEqual([{ id: "f_00000001", value: "v-f_00000001" }, { id: "f_00000003", value: "v-f_00000003" }]);
    expect(calls).toEqual([["n", "e", ["f_00000001", "f_00000003"]]]);
    await expect(src.revealFields("n", "e", ["f_00000001"])).rejects.toMatchObject({ code: "malformed_response" });
  });

  it("entryMeta asks entry.get for the entry and maps it", async () => {
    let seen: unknown[] = [];
    const meta: live.EntryMeta = { node: "n", entry: "e", name: "x", ref: 1, type: "other", sensitivity: "low", fieldCount: 1, hasTotp: false, modified: 1, rotatedAt: null, expiresAt: null, generation: 3, typeOverridden: false, sensitivityOverridden: false, fields: [{ id: "f_00000000", label: "", type: "text", masked: false, typeOverridden: false, maskedOverridden: false }] };
    const src = new BridgeSource(fns({ entryGet: async (...a: unknown[]) => ((seen = a), meta) }));
    expect((await src.entryMeta("n", "e")).fields.map((x) => x.id)).toEqual(["f_00000000"]);
    expect(seen).toEqual(["n", "e"]);
  });
});
