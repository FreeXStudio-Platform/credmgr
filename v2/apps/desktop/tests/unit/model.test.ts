// VaultModel: the state machine, the cache, the private secret store, refresh and mutate - against a scripted source.
import { describe, expect, it } from "vitest";

import { deepFreeze, mapPool, VaultModel } from "../../src/vault/model";
import type { AuthLite, EntriesPart, GraphPart, ModelSource } from "../../src/vault/source";
import type { DEntry, DEntryDetail, DGrant, DNode, DOrphan, DPending } from "../../src/vault/types";

const bridgeError = (code: string) => ({ source: "broker", code, message: code });

const node = (id: string, kind: DNode["kind"], parentId: string | null, entries = 0): DNode => ({
  id,
  label: id,
  kind,
  depth: parentId === null ? 0 : parentId === "global" ? 1 : 2,
  parentId,
  counts: { entries, totp: 0 },
  gate: { locked: false, twofa: "none" },
  health: null,
  notes: null,
});
const entry = (id: string, name: string, masked = true): DEntry => ({ id, name, type: "api", sensitivity: "high", totp: false, meta: "api · high", fieldCount: 1, fields: [{ label: "api", type: "api", masked }] });

/** A source that answers from memory, counts every call, and can be told to fail. */
class FakeSource implements ModelSource {
  readonly kind = "bridge" as const;
  calls: string[] = [];
  inFlight = 0;
  maxInFlight = 0;
  auth: AuthLite = { locked: true, authenticated: false, initialized: true };
  failOn: Record<string, unknown> = {};
  nodes = [node("global", "global", null, 1), node("atlas", "project", "global", 2), node("beacon", "project", "global", 1), node("dev", "sub", "atlas", 1), node("cobalt", "project", "global", 0)];
  entriesBy: Record<string, DEntry[]> = { global: [entry("g1", "licence")], atlas: [entry("a1", "stripe"), entry("a2", "pg")], beacon: [entry("b1", "reg")], dev: [entry("d1", "dev-db")], cobalt: [] };
  grantList: DGrant[] = [{ id: "gr1", from: "beacon", to: "atlas", toEntry: null, scope: "read", expires: "never", lastUsed: "—", reason: "fixture" }];
  note: Record<string, string | null> = { atlas: "an atlas note" };
  values: Record<string, string> = { "atlas/a1/0": "value-of-stripe" };
  generation = 7;
  /** What `meta.sealed` lists; `undefined` = the key is absent (an agent login, a non-Admin human). */
  sealedList: GraphPart["sealed"] = undefined;

  /**
   * The next call of this name waits for the first promise listed, the one after for the second, and so on (a broker that is
   * slow, so a test can act meanwhile).  Calls after the list is used up answer at once.
   */
  holds: Record<string, Array<Promise<void>>> = {};
  /** Tell `lock()` what to report (the real source never throws; a fake may, to prove the model copes). */
  lockResult: { confirmed: boolean; code: string | null } | void = undefined;
  lockThrows: unknown = null;

  private async hit(name: string): Promise<void> {
    this.calls.push(name);
    if (name in this.failOn) throw this.failOn[name];
    const held = this.holds[name]?.shift();
    if (held) await held;
    this.inFlight++;
    this.maxInFlight = Math.max(this.maxInFlight, this.inFlight);
    await new Promise((r) => setTimeout(r, 1));
    this.inFlight--;
  }
  async status() {
    await this.hit("status");
    return { ...this.auth };
  }
  async unlock(pass: string) {
    await this.hit("unlock");
    if (pass !== "right") throw bridgeError("wrong_passphrase");
    this.auth = { locked: false, authenticated: true, initialized: true };
    return { ...this.auth };
  }
  async gateVerify(code: string) {
    await this.hit("gateVerify");
    if (code !== "123456") throw bridgeError("gate_verification_failed");
    this.auth = { locked: false, authenticated: true, initialized: true };
    return { ...this.auth };
  }
  async lock() {
    await this.hit("lock");
    this.auth = { locked: true, authenticated: false, initialized: true };
    if (this.lockThrows) throw this.lockThrows;
    return this.lockResult;
  }
  async graph(): Promise<GraphPart> {
    await this.hit("graph");
    return { nodes: this.nodes.map((n) => ({ ...n })), links: this.nodes.filter((n) => n.parentId).map((n) => ({ source: n.parentId as string, target: n.id, kind: "structural" as const })), orphanNodeId: "orphaned", ...(this.sealedList ? { sealed: this.sealedList } : {}) };
  }
  async grants() {
    await this.hit("grants");
    return this.grantList;
  }
  /** Nodes whose entries this fake login may not list, with the broker's reason. */
  unreadableBy: Record<string, EntriesPart["unreadable"]> = {};
  orphansReason: EntriesPart["unreadable"] | null = null;
  async entries(n: string): Promise<EntriesPart> {
    const list = this.entriesBy[n] ?? []; // what the vault holds when the call is MADE, as a real broker would answer
    const why = this.unreadableBy[n];
    await this.hit(`entries:${n}`);
    return why ? { entries: [], generation: 0, unreadable: why } : { entries: list, generation: this.generation };
  }
  async orphans(): Promise<DOrphan[]> {
    await this.hit("orphans");
    return this.orphansReason ? [] : [{ id: "o1", name: "old-root" }];
  }
  orphansUnreadable() {
    return this.orphansReason ?? null;
  }
  async pending(n: string): Promise<DPending[]> {
    await this.hit(`pending:${n}`);
    return n === "atlas" ? [{ id: "p1", node: "atlas", name: "held", type: "api", sensitivity: "high", fieldCount: 1, created: 1, fields: [] }] : [];
  }
  async notes(n: string) {
    await this.hit(`notes:${n}`);
    return this.note[n] ?? null;
  }
  async reveal(n: string, e: string, f: number | string) {
    await this.hit(`reveal:${n}/${e}/${f}`);
    return this.values[`${n}/${e}/${f}`] ?? "value-default";
  }
  /** What `entry.get` says: the fields of the entries this fake knows, by "node/entry".  A missing one is not_found. */
  details: Record<string, DEntryDetail> = {};
  async entryMeta(n: string, e: string): Promise<DEntryDetail> {
    await this.hit(`meta:${n}/${e}`);
    const d = this.details[`${n}/${e}`];
    if (!d) throw bridgeError("not_found");
    return d;
  }
  async revealFields(n: string, e: string, ids: string[]) {
    await this.hit(`revealFields:${n}/${e}/${ids.join(",")}`);
    return ids.map((id) => ({ id, value: this.values[`${n}/${e}/${id}`] ?? "value-default" }));
  }
}

const open = async (src = new FakeSource(), options = {}) => {
  src.auth = { locked: false, authenticated: true, initialized: true };
  const m = new VaultModel(src, options);
  await m.boot();
  return { src, m };
};

describe("boot", () => {
  it("routes by what the broker says", async () => {
    const cases: Array<[Partial<AuthLite>, string]> = [
      [{ initialized: false }, "uninitialized"],
      [{ locked: true, authenticated: false }, "locked"],
      [{ locked: false, authenticated: false }, "locked"], // unlocked by another process: this one holds no login
      [{ locked: false, authenticated: true }, "unlocked"],
    ];
    for (const [auth, status] of cases) {
      const src = new FakeSource();
      src.auth = { locked: false, authenticated: true, initialized: true, ...auth };
      const m = new VaultModel(src);
      await m.boot();
      expect(m.status).toBe(status);
    }
  });

  it("does not read the vault unless it is open", async () => {
    const src = new FakeSource();
    const m = new VaultModel(src);
    await m.boot();
    expect(src.calls).toEqual(["status"]);
  });

  it("an unreachable broker is a status, not an exception; any other failure is thrown", async () => {
    const down = new FakeSource();
    down.failOn.status = { source: "transport", code: "broker_unreachable", message: "x" };
    const m = new VaultModel(down);
    await m.boot();
    expect(m.status).toBe("broker-down");

    const odd = new FakeSource();
    odd.failOn.status = bridgeError("internal");
    await expect(new VaultModel(odd).boot()).rejects.toMatchObject({ code: "internal" });
  });

  it("losing the login while loading ends in locked, not in an error", async () => {
    const src = new FakeSource();
    src.auth = { locked: false, authenticated: true, initialized: true };
    src.failOn.graph = bridgeError("vault_locked");
    const m = new VaultModel(src);
    await m.boot();
    expect(m.status).toBe("locked");
  });

  describe("a boot that does not end in 'unlocked' leaves nothing of the session the model held (a Lock screen reached by Retry)", () => {
    /** An open vault with a value revealed, then the broker answers `to` on the next boot (Retry). */
    async function sessionThenBoot(to: (src: FakeSource) => void) {
      const { src, m } = await open();
      expect(await m.reveal("atlas", "a1")).toBe(true);
      expect(m.view.nodes.length).toBeGreaterThan(0);
      expect(m.plain("atlas", "a1")).toBe("value-of-stripe");
      to(src);
      await m.boot();
      return { src, m };
    }
    const forgotten = (m: VaultModel) => {
      expect(m.view.nodes).toEqual([]);
      expect(m.view.entries).toEqual({});
      expect(m.view.pending).toEqual([]);
      expect(m.view.grants).toEqual([]);
      expect(m.secretCount).toBe(0);
      expect(m.plain("atlas", "a1")).toBeUndefined();
      expect(m.generation).toEqual({});
    };

    it("locked: the view and every revealed value are gone, so a later login cannot copy the old one", async () => {
      const { m } = await sessionThenBoot((src) => (src.auth = { locked: true, authenticated: false, initialized: true }));
      expect(m.status).toBe("locked");
      forgotten(m);
    });

    it("unlocked by another process (this one holds no login): the same", async () => {
      const { m } = await sessionThenBoot((src) => (src.auth = { locked: false, authenticated: false, initialized: true }));
      expect(m.status).toBe("locked");
      forgotten(m);
    });

    it("the broker is unreachable: the same, because a restarted broker has forgotten every login", async () => {
      const { m } = await sessionThenBoot((src) => (src.failOn.status = { source: "transport", code: "broker_unreachable", message: "x" }));
      expect(m.status).toBe("broker-down");
      forgotten(m);
    });

    it("no vault any more: the same", async () => {
      const { m } = await sessionThenBoot((src) => (src.auth = { locked: true, authenticated: false, initialized: false }));
      expect(m.status).toBe("uninitialized");
      forgotten(m);
    });

    it("a read still in flight from the old session publishes nothing into the cleared model", async () => {
      const { src, m } = await open();
      const g = gate();
      src.holds["graph"] = [g.wait];
      const reading = m.refresh({ graph: true });
      await until(() => src.calls.filter((c) => c === "graph").length === 2);
      src.auth = { locked: true, authenticated: false, initialized: true };
      await m.boot();
      g.release();
      await reading;
      forgotten(m);
    });

    it("the subscribers hear about it with the model already empty", async () => {
      const { src, m } = await open();
      src.auth = { locked: true, authenticated: false, initialized: true };
      const seen: Array<[string, number]> = [];
      m.subscribe(() => seen.push([m.status, m.view.nodes.length]));
      await m.boot();
      expect(seen.filter(([status]) => status === "locked").every(([, nodes]) => nodes === 0)).toBe(true);
      expect(seen.some(([status]) => status === "locked")).toBe(true);
    });
  });

  it("emits a status change to subscribers, and stops when they unsubscribe", async () => {
    const m = new VaultModel(new FakeSource());
    let n = 0;
    const off = m.subscribe(() => n++);
    await m.boot();
    expect(n).toBeGreaterThan(0);
    off();
    const before = n;
    await m.boot();
    expect(n).toBe(before);
  });
});

describe("unlock", () => {
  it("opens, loads, and forgets any second-factor state", async () => {
    const src = new FakeSource();
    const m = new VaultModel(src);
    await m.boot();
    await m.unlock("right");
    expect(m.status).toBe("unlocked");
    expect(m.gateConfirmed).toBe(false);
    expect(m.view.nodes.map((n) => n.id)).toEqual(["global", "atlas", "beacon", "dev", "cobalt"]);
  });

  it("a wrong passphrase rejects with the bridge's error and loads nothing", async () => {
    const src = new FakeSource();
    const m = new VaultModel(src);
    await m.boot();
    await expect(m.unlock("wrong")).rejects.toMatchObject({ code: "wrong_passphrase" });
    expect(m.status).toBe("locked");
    expect(src.calls).toEqual(["status", "unlock"]);
  });

  it("two_factor_required marks the gate confirmed; the code then completes the login", async () => {
    const src = new FakeSource();
    const m = new VaultModel(src);
    await m.boot();
    src.failOn.unlock = bridgeError("two_factor_required");
    await expect(m.unlock("right")).rejects.toMatchObject({ code: "two_factor_required" });
    expect(m.gateConfirmed).toBe(true);
    await expect(m.gateVerify("000000")).rejects.toMatchObject({ code: "gate_verification_failed" });
    expect(m.status).toBe("locked");
    await m.gateVerify("123456");
    expect(m.status).toBe("unlocked");
    expect(m.gateConfirmed).toBe(true);
  });
});

describe("loadAll", () => {
  it("builds one view: structural links, grant links, entries, orphans, the tray", async () => {
    const { m } = await open();
    const v = m.view;
    expect(v.links.filter((l) => l.kind === "structural").length).toBe(4);
    expect(v.links.filter((l) => l.kind === "grant")).toEqual([{ source: "beacon", target: "atlas", kind: "grant" }]);
    expect(Object.keys(v.entries).sort()).toEqual(["atlas", "beacon", "cobalt", "dev", "global"]);
    expect(v.orphans).toEqual([{ id: "o1", name: "old-root" }]);
    expect(v.pending.map((p) => p.id)).toEqual(["p1"]);
    expect(m.orphanNodeId).toBe("orphaned");
    expect(m.generation.atlas).toBe(7);
  });

  it("reads at most four nodes at a time", async () => {
    const src = new FakeSource();
    for (let i = 0; i < 20; i++) {
      src.nodes.push(node(`n${i}`, "project", "global"));
      src.entriesBy[`n${i}`] = [];
    }
    await open(src);
    expect(src.maxInFlight).toBeLessThanOrEqual(4 + 1); // 4 workers (+1 for a call from another phase that overlaps by a tick)
    expect(src.maxInFlight).toBeGreaterThan(1);
  });

  it("does not read notes unless asked (the real app reads one on select)", async () => {
    const { src, m } = await open();
    expect(src.calls.some((c) => c.startsWith("notes:"))).toBe(false);
    expect(m.node("atlas")?.notes).toBeNull();
  });

  it("reads every note when told to (the demo shows them all)", async () => {
    const { m } = await open(new FakeSource(), { eagerNotes: true });
    expect(m.node("atlas")?.notes).toBe("an atlas note");
    expect(m.node("beacon")?.notes).toBeNull();
  });
});

describe("a node this login cannot list is unreadable, not empty", () => {
  it("loadAll records the broker's reason per node, and only for the nodes that were refused", async () => {
    const src = new FakeSource();
    src.unreadableBy = { atlas: "node_access_denied", cobalt: "capability_not_held", beacon: "node_locked" };
    const { m } = await open(src);
    expect(m.view.unreadable).toEqual({ atlas: "node_access_denied", cobalt: "capability_not_held", beacon: "node_locked" });
    expect(m.view.entries.atlas).toEqual([]); // the empty list means "could not be listed" for exactly these nodes
    expect(m.view.entries.global.length).toBe(1); // and a node listed fine is untouched
    expect("global" in m.view.unreadable).toBe(false);
  });

  it("an empty node that listed fine is NOT unreadable (an empty list and an unreadable node are different answers)", async () => {
    const { m } = await open();
    expect(m.view.entries.cobalt).toEqual([]);
    expect(m.view.unreadable).toEqual({});
  });

  it("a refresh of the node sets the mark, clears it once the node is readable again, and leaves other nodes' marks alone", async () => {
    const src = new FakeSource();
    src.unreadableBy = { atlas: "node_access_denied", beacon: "node_locked" };
    const { m } = await open(src);
    delete src.unreadableBy.atlas;
    await m.refresh({ nodes: ["atlas"] });
    expect(m.view.unreadable).toEqual({ beacon: "node_locked" });
    expect(m.view.entries.atlas.length).toBe(2);
    src.unreadableBy.cobalt = "capability_not_held";
    await m.refresh({ nodes: ["cobalt"] });
    expect(m.view.unreadable).toEqual({ beacon: "node_locked", cobalt: "capability_not_held" });
  });

  it("a graph refresh drops the mark of a node that is gone", async () => {
    const src = new FakeSource();
    src.unreadableBy = { beacon: "node_access_denied" };
    const { m } = await open(src);
    src.nodes = src.nodes.filter((n) => n.id !== "beacon");
    await m.refresh({ graph: true });
    expect(m.view.unreadable).toEqual({});
  });

  it("the orphaned node can be unreadable too, and its mark follows the source's answer on every read", async () => {
    const src = new FakeSource();
    src.orphansReason = "node_access_denied";
    const { m } = await open(src);
    expect(m.view.orphans).toEqual([]);
    expect(m.view.unreadable).toEqual({ orphaned: "node_access_denied" });
    src.orphansReason = null;
    await m.refresh({ graph: true });
    expect(m.view.unreadable).toEqual({});
    expect(m.view.orphans).toEqual([{ id: "o1", name: "old-root" }]);
    src.orphansReason = "capability_not_held";
    await m.refresh({ graph: true });
    expect(m.view.unreadable).toEqual({ orphaned: "capability_not_held" });
  });

  it("a lock forgets the marks with everything else", async () => {
    const src = new FakeSource();
    src.unreadableBy = { atlas: "node_access_denied" };
    const { m } = await open(src);
    await m.lock();
    expect(m.view.unreadable).toEqual({});
  });

  it("the view the screens read is frozen, marks included", async () => {
    const src = new FakeSource();
    src.unreadableBy = { atlas: "node_locked" };
    const { m } = await open(src, { freezeView: true });
    expect(() => {
      (m.view.unreadable as Record<string, string>).x = "node_locked";
    }).toThrow();
  });
});

describe("refresh", () => {
  it("re-reads only what the spec names, and replaces the view instead of editing it", async () => {
    const { src, m } = await open();
    const before = m.view;
    const beforeAtlas = m.view.entries.atlas;
    src.calls = [];
    src.entriesBy.atlas = [entry("a1", "stripe"), entry("a2", "pg"), entry("a3", "new")];
    await m.refresh({ nodes: ["atlas"] });
    expect(src.calls).toEqual(["entries:atlas"]);
    expect(m.view).not.toBe(before);
    expect(m.view.entries.atlas.length).toBe(3);
    expect(beforeAtlas.length).toBe(2); // the old view is untouched
    expect(m.view.entries.beacon).toBe(before.entries.beacon); // what was not re-read is shared, not copied
  });

  it("an empty spec reads nothing and publishes nothing", async () => {
    const { src, m } = await open();
    let n = 0;
    m.subscribe(() => n++);
    src.calls = [];
    const before = m.view;
    await m.refresh({});
    expect(src.calls).toEqual([]);
    expect(m.view).toBe(before);
    expect(n).toBe(0);
  });

  it("graph refresh keeps loaded notes and drops entries of nodes that are gone", async () => {
    const { src, m } = await open(new FakeSource(), { eagerNotes: true });
    src.nodes = src.nodes.filter((n) => n.id !== "beacon");
    await m.refresh({ graph: true });
    expect(m.view.nodes.map((n) => n.id)).not.toContain("beacon");
    expect(m.view.entries.beacon).toBeUndefined();
    expect(m.node("atlas")?.notes).toBe("an atlas note");
  });

  it("grants refresh swaps the grant edges and keeps the structural ones", async () => {
    const { src, m } = await open();
    src.grantList = [];
    await m.refresh({ grants: true });
    expect(m.view.links.filter((l) => l.kind === "grant")).toEqual([]);
    expect(m.view.links.filter((l) => l.kind === "structural").length).toBe(4);
  });

  it("notes refresh sets one node's note", async () => {
    const { m } = await open();
    await m.refresh({ notes: "atlas" });
    expect(m.node("atlas")?.notes).toBe("an atlas note");
    expect(m.node("global")?.notes).toBeNull();
  });
});

describe("mutate", () => {
  it("refreshes after a success, and not after a failure", async () => {
    const { src, m } = await open();
    src.calls = [];
    expect(await m.mutate(async () => 42, { nodes: ["atlas"] })).toBe(42);
    expect(src.calls).toEqual(["entries:atlas"]);

    src.calls = [];
    await expect(m.mutate(async () => { throw bridgeError("entry_exists"); }, { nodes: ["atlas"] })).rejects.toMatchObject({ code: "entry_exists" });
    expect(src.calls).toEqual([]);
  });
});

describe("the secret store", () => {
  it("holds a revealed value for its window, then forgets it", async () => {
    let t = 1_000;
    const { m } = await open(new FakeSource(), { now: () => t, revealWindowMs: 5_000 });
    expect(m.plain("atlas", "a1")).toBeUndefined();
    await m.reveal("atlas", "a1");
    expect(m.plain("atlas", "a1")).toBe("value-of-stripe");
    expect(m.secretCount).toBe(1);
    t += 4_999;
    expect(m.plain("atlas", "a1")).toBe("value-of-stripe");
    t += 2;
    expect(m.plain("atlas", "a1")).toBeUndefined();
    expect(m.secretCount).toBe(0);
  });

  it("never puts a value in the view", async () => {
    const { m } = await open();
    await m.reveal("atlas", "a1");
    expect(JSON.stringify(m.view)).not.toContain("value-of-stripe");
  });

  it("hide, wipeSecrets and sweepSecrets each remove what they should", async () => {
    let t = 0;
    const { m } = await open(new FakeSource(), { now: () => t });
    await m.reveal("atlas", "a1", 0, 100);
    await m.reveal("atlas", "a2", 0, 1000);
    await m.reveal("beacon", "b1", 0, 1000);
    m.hide("atlas", "a2");
    expect(m.plain("atlas", "a2")).toBeUndefined();
    t = 500;
    expect(m.sweepSecrets()).toBe(1); // a1 expired
    expect(m.secretCount).toBe(1);
    m.wipeSecrets();
    expect(m.secretCount).toBe(0);
  });

  it("lock and clear wipe everything, and empty the view", async () => {
    const { src, m } = await open();
    await m.reveal("atlas", "a1");
    await m.lock();
    expect(src.calls).toContain("lock");
    expect(m.secretCount).toBe(0);
    expect(m.plain("atlas", "a1")).toBeUndefined();
    expect(m.view.nodes).toEqual([]);
    expect(m.view.entries).toEqual({});
    expect(m.view.pending).toEqual([]);
    expect(m.status).toBe("locked");
    expect(m.generation).toEqual({});
  });

  it("keeps the view on lock when told to (the demo does), but still wipes values", async () => {
    const { m } = await open(new FakeSource(), { clearViewOnLock: false });
    await m.reveal("atlas", "a1");
    await m.lock();
    expect(m.view.nodes.length).toBe(5);
    expect(m.secretCount).toBe(0);
  });

  it("fetches non-secret fields up front when told to, and keeps them until lock", async () => {
    const src = new FakeSource();
    src.entriesBy.atlas = [entry("a1", "stripe", false)];
    src.values["atlas/a1/0"] = "plainly-visible";
    const { m } = await open(src, { prefetchUnmasked: true });
    expect(m.plain("atlas", "a1")).toBe("plainly-visible");
    m.wipeSecrets();
    expect(m.plain("atlas", "a1")).toBe("plainly-visible"); // not a secret: window-hide does not drop it
    await m.lock();
    expect(m.plain("atlas", "a1")).toBeUndefined();
  });
});

/** A promise a test settles by hand, so it decides when a slow broker call answers. */
function gate(): { wait: Promise<void>; release: () => void } {
  let release!: () => void;
  const wait = new Promise<void>((r) => (release = r));
  return { wait, release };
}
const until = async (cond: () => boolean): Promise<void> => {
  for (let i = 0; i < 300 && !cond(); i++) await new Promise((r) => setTimeout(r, 2));
  if (!cond()) throw new Error("the condition never became true");
};
const callCount = (src: FakeSource, name: string): number => src.calls.filter((c) => c === name).length;

describe("a read that outlives its login publishes nothing", () => {
  it("a refresh still reading when the model is cleared resolves quietly and leaves the model empty", async () => {
    const { src, m } = await open();
    const g = gate();
    src.holds["entries:atlas"] = [g.wait];
    const run = m.refresh({ nodes: ["atlas"], graph: true });
    await until(() => callCount(src, "graph") === 2 && callCount(src, "entries:atlas") === 2);
    m.clear(); // the user locked, or the shell did, while the broker was still answering
    g.release();
    await expect(run).resolves.toBeUndefined();
    expect(m.status).toBe("locked");
    expect(m.view.nodes).toEqual([]);
    expect(m.view.entries).toEqual({});
    expect(m.generation).toEqual({});
    expect(m.orphanNodeId).toBeNull(); // not even the id the late answer carried
  });

  it("loadAll is the same: a late answer after a clear publishes nothing", async () => {
    const { src, m } = await open();
    m.clear();
    const g = gate();
    src.holds.graph = [g.wait];
    const run = m.loadAll();
    await until(() => callCount(src, "graph") === 2);
    m.clear();
    g.release();
    await expect(run).resolves.toBeUndefined();
    expect(m.view.nodes).toEqual([]);
    expect(m.view.entries).toEqual({});
  });

  it("an unlock whose vault load is cut off by a lock is refused with session_expired, never shown as an unlock", async () => {
    const src = new FakeSource();
    const m = new VaultModel(src);
    await m.boot(); // locked
    const g = gate();
    src.holds.graph = [g.wait];
    const run = m.unlock("right");
    await until(() => src.calls.includes("graph"));
    m.clear();
    g.release();
    await expect(run).rejects.toMatchObject({ code: "session_expired" });
    expect(m.status).toBe("locked");
    expect(m.view.nodes).toEqual([]);
  });

  it("the second-factor step is held to the same rule", async () => {
    const src = new FakeSource();
    const m = new VaultModel(src);
    await m.boot();
    const g = gate();
    src.holds.graph = [g.wait];
    const run = m.gateVerify("123456");
    await until(() => src.calls.includes("graph"));
    m.clear();
    g.release();
    await expect(run).rejects.toMatchObject({ code: "session_expired" });
    expect(m.status).toBe("locked");
  });

  it("a boot whose load is cut off ends in the state the clear set, not in unlocked", async () => {
    const src = new FakeSource();
    src.auth = { locked: false, authenticated: true, initialized: true };
    const m = new VaultModel(src);
    const g = gate();
    src.holds.graph = [g.wait];
    const run = m.boot();
    await until(() => src.calls.includes("graph"));
    m.clear(); // the shell locked the vault while the first load was still running
    g.release();
    await run;
    expect(m.status).toBe("locked"); // not "unlocked": the late answer must not undo the clear
    expect(m.view.nodes).toEqual([]);
    expect(m.view.entries).toEqual({});
  });
});

describe("refreshes are serialised", () => {
  it("a slow refresh and a fast one both land: neither overwrites the other's change", async () => {
    const { src, m } = await open();
    const g = gate();
    src.holds["entries:atlas"] = [g.wait];
    src.entriesBy.atlas = [entry("a9", "brand-new")];
    src.grantList = [...src.grantList, { id: "gr2", from: "cobalt", to: "atlas", toEntry: null, scope: "read", expires: "never", lastUsed: "—", reason: "second" }];
    const slow = m.refresh({ nodes: ["atlas"] });
    await until(() => callCount(src, "entries:atlas") === 2);
    const fast = m.refresh({ grants: true });
    await new Promise((r) => setTimeout(r, 20));
    expect(callCount(src, "grants")).toBe(1); // only the boot's: the second refresh waits its turn instead of racing
    g.release();
    await Promise.all([slow, fast]);
    expect(m.view.entries.atlas.map((e) => e.id)).toEqual(["a9"]);
    expect(m.view.grants.map((x) => x.id)).toEqual(["gr1", "gr2"]);
    expect(m.view.links.filter((l) => l.kind === "grant")).toHaveLength(2);
  });

  it("they publish in the order they were asked, so the newer answer is the one that stays", async () => {
    const { src, m } = await open();
    const g = gate();
    src.holds["entries:atlas"] = [g.wait];
    src.entriesBy.atlas = [entry("first", "first")];
    const a = m.refresh({ nodes: ["atlas"] }); // reads "first", then the broker is slow to answer
    await until(() => callCount(src, "entries:atlas") === 2);
    src.entriesBy.atlas = [entry("second", "second")]; // the vault changes; the second read is quick
    const b = m.refresh({ nodes: ["atlas"] });
    await new Promise((r) => setTimeout(r, 20));
    g.release();
    await Promise.all([a, b]);
    // unserialised, b would finish first and a's older answer would then overwrite it
    expect(m.view.entries.atlas.map((e) => e.id)).toEqual(["second"]);
  });

  it("a failed refresh rejects to its own caller and does not wedge the ones behind it", async () => {
    const { src, m } = await open();
    src.failOn.grants = bridgeError("internal");
    await expect(m.refresh({ grants: true })).rejects.toMatchObject({ code: "internal" });
    delete src.failOn.grants;
    await expect(m.refresh({ grants: true })).resolves.toBeUndefined();
    expect(callCount(src, "grants")).toBe(3);
  });

  it("a refresh keeps the sealed nodes the view holds when it publishes (they are session memory, not broker data)", async () => {
    const { m } = await open();
    const sealed = { id: "gone", label: "gone" };
    m.view = { ...m.view, sealed: [sealed] }; // (the writes package records these; here, by hand)
    await m.refresh({ grants: true });
    expect(m.view.sealed).toEqual([sealed]);
    await m.loadAll();
    expect(m.view.sealed).toEqual([sealed]);
  });
});

describe("the broker's list of sealed nodes (ADR-080)", () => {
  const seal = (id: string) => ({ id, label: id, sealedAt: 1_700_000_000, expiresAt: 1_700_000_000 + 7 * 86_400 });

  it("fills view.sealed on login, from the broker, with the real window", async () => {
    const src = new FakeSource();
    src.sealedList = [seal("old")];
    const { m } = await open(src);
    expect(m.view.sealed).toEqual([seal("old")]);
  });

  it("survives a lock and a fresh login (a restart): nothing is remembered by the session, the broker lists it again", async () => {
    const src = new FakeSource();
    src.sealedList = [seal("old")];
    const { m } = await open(src);
    await m.lock();
    expect(m.view.sealed).toEqual([]);
    src.auth = { locked: false, authenticated: true, initialized: true };
    await m.loadAll();
    expect(m.view.sealed).toEqual([seal("old")]);
  });

  it("a graph refresh replaces the session's memory with the broker's list, and [] clears it", async () => {
    const src = new FakeSource();
    src.sealedList = [seal("old")];
    const { m } = await open(src);
    m.rememberSealed({ id: "mine", label: "mine" });
    src.sealedList = [seal("old"), seal("mine")];
    await m.refresh({ graph: true });
    expect(m.view.sealed.map((x) => x.id)).toEqual(["old", "mine"]);
    expect(m.view.sealed[1]).toMatchObject({ expiresAt: seal("mine").expiresAt }); // the broker's window, not a guess
    src.sealedList = [];
    await m.refresh({ graph: true });
    expect(m.view.sealed).toEqual([]);
  });

  it("with the key absent the session's own memory stays", async () => {
    const { m } = await open(new FakeSource());
    m.rememberSealed({ id: "mine", label: "mine" });
    await m.refresh({ graph: true });
    expect(m.view.sealed.map((x) => x.id)).toEqual(["mine"]);
  });
});

describe("one open entry at a time (retainSecretsFor)", () => {
  it("keeps the named entry's values, drops every other, and cancels their pending reveals", async () => {
    const { m } = await open();
    await m.reveal("atlas", "a1");
    await m.reveal("atlas", "a2");
    await m.reveal("beacon", "b1");
    const before = m.wipeCount;
    m.retainSecretsFor("atlas", "a2");
    expect(m.plain("atlas", "a1")).toBeUndefined();
    expect(m.plain("beacon", "b1")).toBeUndefined();
    expect(m.plain("atlas", "a2")).toBeDefined();
    expect(m.secretCount).toBe(1);
    expect(m.wipeCount).toBe(before + 1);
    m.retainSecretsFor("atlas", "a2"); // nothing left to drop: not a wipe
    expect(m.wipeCount).toBe(before + 1);
    m.retainSecretsFor(null, null); // no entry open
    expect(m.secretCount).toBe(0);
  });

  it("a reveal still in flight for another entry is dropped on arrival", async () => {
    const src = new FakeSource();
    let release!: () => void;
    src.holds.reveal = [new Promise<void>((r) => (release = r))];
    const { m } = await open(src);
    const p = m.reveal("atlas", "a1");
    await until(() => src.calls.includes("reveal:atlas/a1/0"));
    m.retainSecretsFor("atlas", "a2");
    release();
    await expect(p).resolves.toBe(false);
    expect(m.secretCount).toBe(0);
  });
});

describe("a reveal that outlives its screen is dropped on arrival", () => {
  const started = (src: FakeSource, key: string) => until(() => src.calls.includes(`reveal:${key}`));

  it("an ordinary reveal reports that it holds the value", async () => {
    const { m } = await open();
    expect(await m.reveal("atlas", "a1")).toBe(true);
    expect(m.plain("atlas", "a1")).toBe("value-of-stripe");
  });

  it("clear() while the broker is answering: nothing is parked in memory", async () => {
    const { src, m } = await open();
    const g = gate();
    src.holds["reveal:atlas/a1/0"] = [g.wait];
    const run = m.reveal("atlas", "a1");
    await started(src, "atlas/a1/0");
    m.clear();
    g.release();
    expect(await run).toBe(false);
    expect(m.secretCount).toBe(0);
    expect(m.plain("atlas", "a1")).toBeUndefined();
  });

  it("hide() cancels only its own pending reveal", async () => {
    const { src, m } = await open();
    const g1 = gate();
    const g2 = gate();
    src.holds["reveal:atlas/a1/0"] = [g1.wait];
    src.holds["reveal:beacon/b1/0"] = [g2.wait];
    const a = m.reveal("atlas", "a1");
    const b = m.reveal("beacon", "b1");
    await started(src, "atlas/a1/0");
    await started(src, "beacon/b1/0");
    m.hide("atlas", "a1");
    g1.release();
    g2.release();
    expect(await a).toBe(false);
    expect(await b).toBe(true);
    expect(m.plain("atlas", "a1")).toBeUndefined();
    expect(m.plain("beacon", "b1")).toBe("value-default");
  });

  it("wipeSecrets() (the user moved to another node, the window was hidden) cancels every pending reveal", async () => {
    const { src, m } = await open();
    const g = gate();
    src.holds["reveal:atlas/a1/0"] = [g.wait];
    src.holds["reveal:atlas/a2/0"] = [g.wait];
    const a = m.reveal("atlas", "a1");
    const b = m.reveal("atlas", "a2");
    await started(src, "atlas/a2/0");
    m.wipeSecrets();
    g.release();
    expect([await a, await b]).toEqual([false, false]);
    expect(m.secretCount).toBe(0);
  });

  it("asking again supersedes the first request: one value is held, from the later answer", async () => {
    const { src, m } = await open();
    const g = gate();
    src.holds["reveal:atlas/a1/0"] = [g.wait];
    const first = m.reveal("atlas", "a1");
    await started(src, "atlas/a1/0");
    src.values["atlas/a1/0"] = "value-two";
    const second = m.reveal("atlas", "a1");
    g.release();
    expect(await first).toBe(false);
    expect(await second).toBe(true);
    expect(m.secretCount).toBe(1);
    expect(m.plain("atlas", "a1")).toBe("value-two");
  });

  it("a reveal the broker refuses leaves nothing behind, and a retry works", async () => {
    const { src, m } = await open();
    src.failOn["reveal:atlas/a1/0"] = bridgeError("capability_not_held");
    await expect(m.reveal("atlas", "a1")).rejects.toMatchObject({ code: "capability_not_held" });
    expect(m.secretCount).toBe(0);
    delete src.failOn["reveal:atlas/a1/0"];
    expect(await m.reveal("atlas", "a1")).toBe(true);
  });
});

describe("lock reports what the broker could confirm", () => {
  it("a confirmed lock says so and raises nothing", async () => {
    const calls: Array<string | null> = [];
    const { m } = await open(new FakeSource(), { onLockUnconfirmed: (c: string | null) => calls.push(c) });
    expect(await m.lock()).toEqual({ confirmed: true, code: null });
    expect(calls).toEqual([]);
    expect(m.status).toBe("locked");
  });

  it("an unconfirmed lock still ends locked and empty, and is reported once, by code, after the model has cleared", async () => {
    const seen: Array<{ code: string | null; status: string; nodes: number; secrets: number }> = [];
    const src = new FakeSource();
    src.lockResult = { confirmed: false, code: "broker_unreachable" };
    const { m } = await open(src, { onLockUnconfirmed: (code: string | null) => seen.push({ code, status: m.status, nodes: m.view.nodes.length, secrets: m.secretCount }) });
    await m.reveal("atlas", "a1");
    expect(await m.lock()).toEqual({ confirmed: false, code: "broker_unreachable" });
    expect(seen).toEqual([{ code: "broker_unreachable", status: "locked", nodes: 0, secrets: 0 }]);
  });

  it("lock forgets BEFORE the broker has answered: a slow or wedged broker cannot keep the vault on screen", async () => {
    const src = new FakeSource();
    const { m } = await open(src);
    await m.reveal("atlas", "a1");
    const g = gate();
    src.holds.lock = [g.wait];
    const seenOnChange: Array<{ status: string; nodes: number; secrets: number }> = [];
    m.subscribe(() => seenOnChange.push({ status: m.status, nodes: m.view.nodes.length, secrets: m.secretCount }));
    const run = m.lock();
    await until(() => callCount(src, "lock") === 1); // the broker has been asked, and has not answered
    expect(m.status).toBe("locked");
    expect(m.view.nodes).toEqual([]);
    expect(m.secretCount).toBe(0);
    expect(seenOnChange[0]).toEqual({ status: "locked", nodes: 0, secrets: 0 }); // announced before the answer
    g.release();
    await expect(run).resolves.toEqual({ confirmed: true, code: null });
  });

  it("a source that throws from lock() (it is not meant to) is treated as unconfirmed, never as an escape from locking", async () => {
    const seen: Array<string | null> = [];
    const src = new FakeSource();
    src.lockThrows = bridgeError("internal");
    const { m } = await open(src, { onLockUnconfirmed: (c: string | null) => seen.push(c) });
    expect(await m.lock()).toEqual({ confirmed: false, code: "internal" });
    expect(seen).toEqual(["internal"]);
    expect(m.status).toBe("locked");
    expect(m.view.nodes).toEqual([]);
    const other = new FakeSource();
    other.lockThrows = new Error("message that must not travel");
    const { m: m2 } = await open(other);
    expect(await m2.lock()).toEqual({ confirmed: false, code: "unknown" });
  });
});

describe("freezeView", () => {
  it("makes a leftover local mutation of the view throw", async () => {
    const { m } = await open(new FakeSource(), { freezeView: true });
    expect(() => {
      m.view.nodes.push(node("x", "project", "global"));
    }).toThrow();
    expect(() => {
      m.view.entries.atlas[0].name = "renamed";
    }).toThrow();
  });
});

describe("helpers", () => {
  it("mapPool keeps order and respects the limit", async () => {
    let running = 0;
    let peak = 0;
    const out = await mapPool([1, 2, 3, 4, 5, 6, 7, 8], 3, async (n) => {
      running++;
      peak = Math.max(peak, running);
      await new Promise((r) => setTimeout(r, 2));
      running--;
      return n * 2;
    });
    expect(out).toEqual([2, 4, 6, 8, 10, 12, 14, 16]);
    expect(peak).toBeLessThanOrEqual(3);
  });

  it("deepFreeze freezes nested data and tolerates already-frozen input", () => {
    const x = deepFreeze({ a: { b: [1, { c: 2 }] } });
    expect(Object.isFrozen(x.a.b[1])).toBe(true);
    expect(() => deepFreeze(x)).not.toThrow();
  });
});

// ───────────────────────────── entry details and per-field values (ADR-078) ─────────────────────────────

const detail = (node: string, entryId: string, over: Partial<DEntryDetail> = {}): DEntryDetail => ({
  node, entry: entryId, name: entryId, type: "server", sensitivity: "high", fieldCount: 2, hasTotp: false, generation: 7, typeOverridden: false, sensitivityOverridden: false, modified: 1, rotatedAt: null, expiresAt: null,
  fields: [
    { id: "f_00000001", label: "host", type: "host", masked: false },
    { id: "f_00000002", label: "password", type: "password", masked: true },
  ],
  ...over,
});

describe("entry details", () => {
  it("loadDetail reads the entry's fields once, keeps them out of the view, and hands them back on detail()", async () => {
    const { src, m } = await open();
    src.details["atlas/a2"] = detail("atlas", "a2");
    expect(m.detail("atlas", "a2")).toBeUndefined();
    const d = await m.loadDetail("atlas", "a2");
    expect(d?.fields.map((f) => f.id)).toEqual(["f_00000001", "f_00000002"]);
    expect(m.detail("atlas", "a2")).toBe(d);
    expect(JSON.stringify(m.view)).not.toContain("f_00000001"); // never part of the view the screens replace wholesale
    expect(src.calls.filter((c) => c === "meta:atlas/a2")).toHaveLength(1);
  });

  it("a refusal propagates to the caller and keeps nothing", async () => {
    const { m } = await open();
    await expect(m.loadDetail("atlas", "a2")).rejects.toMatchObject({ code: "not_found" });
    expect(m.detail("atlas", "a2")).toBeUndefined();
  });

  it("an answer that outlives its login is dropped: nothing is parked in a model that has locked", async () => {
    const { src, m } = await open();
    src.details["atlas/a2"] = detail("atlas", "a2");
    let release!: () => void;
    src.holds["meta:atlas/a2"] = [new Promise<void>((r) => (release = r))];
    const asked = m.loadDetail("atlas", "a2");
    await new Promise((r) => setTimeout(r, 5));
    m.clear();
    release();
    expect(await asked).toBeUndefined();
    expect(m.detail("atlas", "a2")).toBeUndefined();
  });

  it("lock forgets every detail with the rest of the session (the labels are the user's own text)", async () => {
    const { src, m } = await open();
    src.details["atlas/a2"] = detail("atlas", "a2");
    await m.loadDetail("atlas", "a2");
    await m.lock();
    expect(m.detail("atlas", "a2")).toBeUndefined();
  });

  it("a details refresh REPLACES the held detail, and drops it when the entry is gone or its node locked meanwhile", async () => {
    const { src, m } = await open();
    src.details["atlas/a2"] = detail("atlas", "a2");
    await m.loadDetail("atlas", "a2");
    src.details["atlas/a2"] = detail("atlas", "a2", { fieldCount: 3, fields: [...detail("atlas", "a2").fields, { id: "f_00000003", label: "note", type: "text", masked: false }] });
    await m.refresh({ details: [{ node: "atlas", entry: "a2" }, { node: "atlas", entry: "a2" }] });
    expect(m.detail("atlas", "a2")?.fieldCount).toBe(3);
    expect(src.calls.filter((c) => c === "meta:atlas/a2")).toHaveLength(2); // the duplicate was read once
    delete src.details["atlas/a2"];
    await m.refresh({ details: [{ node: "atlas", entry: "a2" }] });
    expect(m.detail("atlas", "a2")).toBeUndefined();
    src.failOn["meta:atlas/a1"] = bridgeError("node_locked");
    await expect(m.refresh({ details: [{ node: "atlas", entry: "a1" }] })).resolves.toBeUndefined(); // survivable: nothing to show
    src.failOn["meta:atlas/a2"] = bridgeError("vault_locked");
    await expect(m.refresh({ details: [{ node: "atlas", entry: "a2" }] })).rejects.toMatchObject({ code: "vault_locked" }); // a lost login is the caller's to route
  });

  it("the held detail is frozen like the view, so a screen cannot edit what the broker said", async () => {
    const { src, m } = await open(new FakeSource(), { freezeView: true });
    src.details["atlas/a2"] = detail("atlas", "a2");
    const d = await m.loadDetail("atlas", "a2");
    expect(Object.isFrozen(d)).toBe(true);
    expect(() => {
      (m.detail("atlas", "a2")!.fields[0] as { label: string }).label = "x";
    }).toThrow();
  });
});

describe("values are held per FIELD", () => {
  it("two fields of one entry are held, shown and hidden independently, by id", async () => {
    const { src, m } = await open();
    src.values["atlas/a2/f_00000001"] = "host-value";
    src.values["atlas/a2/f_00000002"] = "password-value";
    expect(await m.reveal("atlas", "a2", "f_00000002")).toBe(true);
    expect(m.plain("atlas", "a2", "f_00000002")).toBe("password-value");
    expect(m.plain("atlas", "a2", "f_00000001")).toBeUndefined();
    expect(await m.reveal("atlas", "a2", "f_00000001")).toBe(true);
    m.hide("atlas", "a2", "f_00000002");
    expect(m.plain("atlas", "a2", "f_00000002")).toBeUndefined();
    expect(m.plain("atlas", "a2", "f_00000001")).toBe("host-value");
    expect(src.calls.filter((c) => c.startsWith("reveal:"))).toEqual(["reveal:atlas/a2/f_00000002", "reveal:atlas/a2/f_00000001"]); // each read named its field
  });

  it("revealMany reads the fields in ONE call and holds each of them", async () => {
    const { src, m } = await open();
    src.values["atlas/a2/f_00000001"] = "host-value";
    src.values["atlas/a2/f_00000003"] = "note-value";
    expect(await m.revealMany("atlas", "a2", ["f_00000001", "f_00000003"])).toBe(true);
    expect(src.calls.filter((c) => c.startsWith("revealFields:"))).toEqual(["revealFields:atlas/a2/f_00000001,f_00000003"]);
    expect(m.plain("atlas", "a2", "f_00000001")).toBe("host-value");
    expect(m.plain("atlas", "a2", "f_00000003")).toBe("note-value");
    expect(m.secretCount).toBe(2);
    expect(JSON.stringify(m.view)).not.toContain("host-value");
  });

  it("revealMany with nothing to read asks the broker for nothing", async () => {
    const { src, m } = await open();
    expect(await m.revealMany("atlas", "a2", [])).toBe(true);
    expect(src.calls.filter((c) => c.startsWith("revealFields:"))).toEqual([]);
  });

  it("a revealMany that outlives its screen is dropped on arrival: wipe, drop and lock each cancel it", async () => {
    for (const cancel of ["wipe", "drop", "clear"] as const) {
      const { src, m } = await open();
      let release!: () => void;
      src.holds["revealFields:atlas/a2/f_00000001"] = [new Promise<void>((r) => (release = r))];
      const asked = m.revealMany("atlas", "a2", ["f_00000001"]);
      await new Promise((r) => setTimeout(r, 5));
      if (cancel === "wipe") m.wipeSecrets();
      else if (cancel === "drop") m.dropEntrySecrets("atlas", "a2");
      else m.clear();
      release();
      expect(await asked, cancel).toBe(false);
      expect(m.plain("atlas", "a2", "f_00000001"), cancel).toBeUndefined();
      expect(m.secretCount, cancel).toBe(0);
    }
  });

  it("dropEntrySecrets removes everything held for ONE entry and nothing of another, and counts as a wipe", async () => {
    const { m } = await open();
    await m.reveal("atlas", "a2", "f_00000001");
    await m.reveal("atlas", "a2", "f_00000002");
    await m.reveal("atlas", "a1", "f_00000001");
    const before = m.wipeCount;
    m.dropEntrySecrets("atlas", "a2");
    expect(m.plain("atlas", "a2", "f_00000001")).toBeUndefined();
    expect(m.plain("atlas", "a2", "f_00000002")).toBeUndefined();
    expect(m.plain("atlas", "a1", "f_00000001")).toBeDefined();
    expect(m.wipeCount).toBe(before + 1);
    m.wipeSecrets();
    expect(m.wipeCount).toBe(before + 2);
  });

  it("an id and a position are different keys (the example data has no ids)", async () => {
    const { m } = await open();
    await m.reveal("atlas", "a1", 0);
    expect(m.plain("atlas", "a1", 0)).toBeDefined();
    expect(m.plain("atlas", "a1", "0")).toBeDefined(); // a number and its string are one key, the way a Map key built from a template string is
    expect(m.plain("atlas", "a1", "f_00000000")).toBeUndefined();
  });
});
