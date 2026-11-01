// The read-path actions (work package B) against a faked Tauri `invoke`: the exact commands and argument keys they send, what
// they refresh afterwards, where a secret is allowed to live, and what they do when the broker refuses.
import { afterEach, describe, expect, it } from "vitest";

import * as live from "../../src/lib/bridge";
import { BridgeSource } from "../../src/vault/bridge-source";
import { VaultModel } from "../../src/vault/model";
import { DemoSource } from "../../src/vault/demo-source";
import { NotWiredError } from "../../src/vault/errors";
import { copyEntry, loadNotes, lockNode, readTotp, readTotpSeed, renameNode, searchEntries, TOTP_STEP_MS, unlockNode } from "../../src/vault/actions/read";

type Handler = (args: Record<string, unknown>) => unknown;
interface Call {
  cmd: string;
  args: Record<string, unknown>;
}

const refuse = (code: string, detail?: Record<string, unknown>) => ({ source: "broker", code, message: code, ...(detail ? { detail } : {}) });

/** Replace the Tauri shell's invoke with `handlers`, recording every call.  Returns the call log. */
function installInvoke(handlers: Record<string, Handler>): Call[] {
  const calls: Call[] = [];
  (globalThis as unknown as { window?: object }).window = {
    __TAURI_INTERNALS__: {
      invoke: async (cmd: string, args?: Record<string, unknown>) => {
        calls.push({ cmd, args: JSON.parse(JSON.stringify(args ?? {})) });
        const h = handlers[cmd];
        if (!h) throw refuse("internal", { note: `no handler for ${cmd}` });
        return h(args ?? {});
      },
    },
  };
  return calls;
}

afterEach(() => {
  delete (globalThis as unknown as { window?: object }).window;
});

const wireNode = (id: string, over: Partial<live.GraphNode> = {}): live.GraphNode => ({
  id, label: id, kind: id === "global" ? "global" : "project", depth: id === "global" ? 0 : 1, parentId: id === "global" ? null : "global",
  counts: { entries: 1, totp: 0 }, gate: { locked: false, twofa: "none" }, health: null, ...over,
});
const snapshot = (nodes: live.GraphNode[], vaultLocked = false): live.GraphSnapshot => ({
  nodes, links: nodes.filter((n) => n.parentId).map((n) => ({ source: n.parentId as string, target: n.id, kind: "structural", direction: "down" })), meta: { generatedAt: 1, vaultLocked },
});
const list = (node: string): live.EntryList => ({ node, ids: ["e1"], names: ["stripe"], entries: [{ id: "e1", name: "stripe", type: "api", sensitivity: "high", fieldCount: 1, modified: 1, rotatedAt: null, expiresAt: null, hasTotp: false }], generation: 3 });

/** A model over the real BridgeSource, with a controllable clock. */
function bridgeModel(now = () => 1_700_000_000_000): VaultModel {
  return new VaultModel(new BridgeSource(live), { now });
}

describe("search", () => {
  it("sends the trimmed term under the bridge's key and maps the results to names only", async () => {
    const calls = installInvoke({ search: () => ({ results: [{ node: "atlas", id: "e1", name: "stripe-live" }] }) });
    const rows = await searchEntries(bridgeModel(), "  stripe  ");
    expect(calls).toEqual([{ cmd: "search", args: { term: "stripe" } }]);
    expect(rows).toEqual([{ node: "atlas", id: "e1", name: "stripe-live" }]);
  });

  it("an empty term asks nothing", async () => {
    const calls = installInvoke({});
    expect(await searchEntries(bridgeModel(), "   ")).toEqual([]);
    expect(calls).toEqual([]);
  });

  it("a refusal propagates untouched (the screen routes it)", async () => {
    installInvoke({ search: () => { throw refuse("capability_not_held"); } });
    await expect(searchEntries(bridgeModel(), "x")).rejects.toMatchObject({ code: "capability_not_held" });
  });

  it("without the shell (the demo vault) it says it is not available instead of calling anything", async () => {
    const calls = installInvoke({});
    await expect(searchEntries(new VaultModel(new DemoSource()), "x")).rejects.toBeInstanceOf(NotWiredError);
    expect(calls).toEqual([]);
  });
});

describe("notes", () => {
  const graphAndNotes = (notes: Handler) => ({ graph_snapshot: () => snapshot([wireNode("global"), wireNode("atlas")]), grant_list: () => ({ grants: [] }), entry_list: (a: Record<string, unknown>) => list(a.node as string), vault_pending_list: (a: Record<string, unknown>) => ({ node: a.node, pending: [] }), notes_read: notes });

  it("reads one node's note into the view as plain text", async () => {
    const calls = installInvoke(graphAndNotes((a) => ({ node: a.node, markdown: "# heading <b>x</b>\nline two", modified: null })));
    const m = bridgeModel();
    await m.loadAll();
    expect(m.node("atlas")?.notes).toBeNull();
    await loadNotes(m, "atlas");
    expect(calls.filter((c) => c.cmd === "notes_read")).toEqual([{ cmd: "notes_read", args: { node: "atlas" } }]);
    expect(m.node("atlas")?.notes).toBe("# heading <b>x</b>\nline two"); // text, exactly as stored; the screen never turns it into markup
    expect(m.node("global")?.notes).toBeNull();
  });

  it.each(["capability_not_held", "node_locked"])("%s leaves the note null instead of failing the screen", async (code) => {
    installInvoke(graphAndNotes(() => { throw refuse(code); }));
    const m = bridgeModel();
    await m.loadAll();
    await loadNotes(m, "atlas");
    expect(m.node("atlas")?.notes).toBeNull();
  });

  it("any other failure is thrown for the router, here a lost login", async () => {
    installInvoke(graphAndNotes(() => { throw refuse("vault_locked"); }));
    const m = bridgeModel();
    await m.loadAll();
    await expect(loadNotes(m, "atlas")).rejects.toMatchObject({ code: "vault_locked" });
  });
});

describe("node lock, unlock and rename", () => {
  function vault(state: { locked: boolean; label: string }) {
    return installInvoke({
      graph_snapshot: () => snapshot([wireNode("global"), wireNode("atlas", { label: state.label, gate: { locked: state.locked, twofa: "none" } })]),
      grant_list: () => ({ grants: [] }),
      entry_list: (a) => list(a.node as string),
      vault_pending_list: (a) => ({ node: a.node, pending: [] }),
      notes_read: (a) => ({ node: a.node, markdown: "note", modified: null, generation: 1 }),
      vault_node_lock: (a) => { state.locked = true; return { node: a.node, locked: true }; },
      vault_node_unlock: (a) => { state.locked = false; return { node: a.node, locked: false }; },
      node_update: (a) => { state.label = a.label as string; return { node: a.node, label: a.label }; },
    });
  }

  it("lock sends the node, drops every revealed value, and the re-read graph shows the lock", async () => {
    const state = { locked: false, label: "atlas" };
    const calls = vault(state);
    const m = bridgeModel();
    await m.loadAll();
    await m.holdFetched("atlas", "e1", 0, async () => "a-value", (value) => ({ value, windowMs: 60_000 }));
    expect(m.secretCount).toBe(1);
    calls.length = 0;
    await lockNode(m, "atlas");
    expect(calls[0]).toEqual({ cmd: "vault_node_lock", args: { node: "atlas" } });
    expect(m.secretCount).toBe(0);
    expect(calls.map((c) => c.cmd)).toContain("graph_snapshot");
    expect(m.node("atlas")?.gate.locked).toBe(true);
  });

  it("unlock re-reads the graph, the node's entries and its note", async () => {
    const state = { locked: true, label: "atlas" };
    const calls = vault(state);
    const m = bridgeModel();
    await m.loadAll();
    calls.length = 0;
    await unlockNode(m, "atlas");
    expect(calls[0]).toEqual({ cmd: "vault_node_unlock", args: { node: "atlas" } });
    expect(calls.map((c) => c.cmd).sort()).toEqual(["entry_list", "graph_snapshot", "notes_read", "vault_node_unlock"]); // nothing else is re-read
    expect(calls.filter((c) => c.cmd === "entry_list")).toEqual([{ cmd: "entry_list", args: { node: "atlas" } }]);
    expect(calls.filter((c) => c.cmd === "notes_read")).toEqual([{ cmd: "notes_read", args: { node: "atlas" } }]);
    expect(m.node("atlas")?.gate.locked).toBe(false);
    expect(m.node("atlas")?.notes).toBe("note");
  });

  it("rename sends the trimmed label, then re-reads the graph; the id never changes", async () => {
    const state = { locked: false, label: "atlas" };
    const calls = vault(state);
    const m = bridgeModel();
    await m.loadAll();
    calls.length = 0;
    await renameNode(m, "atlas", "  Atlas Prod  ");
    expect(calls[0]).toEqual({ cmd: "node_update", args: { node: "atlas", label: "Atlas Prod" } });
    expect(m.node("atlas")).toMatchObject({ id: "atlas", label: "Atlas Prod" });
  });

  it("a refused rename changes nothing and refreshes nothing", async () => {
    const calls = installInvoke({
      graph_snapshot: () => snapshot([wireNode("global"), wireNode("atlas")]),
      grant_list: () => ({ grants: [] }),
      entry_list: (a) => list(a.node as string),
      vault_pending_list: (a) => ({ node: a.node, pending: [] }),
      node_update: () => { throw refuse("malformed_request"); },
    });
    const m = bridgeModel();
    await m.loadAll();
    calls.length = 0;
    await expect(renameNode(m, "global", "Root")).rejects.toMatchObject({ code: "malformed_request" });
    expect(calls.map((c) => c.cmd)).toEqual(["node_update"]);
    expect(m.node("global")?.label).toBe("global");
  });
});

describe("TOTP", () => {
  const vaultWithTotp = (code: Handler) => installInvoke({ totp_code: code });

  it("holds the code in the secret store until the end of its 30 s step, and never in the view", async () => {
    const t0 = 1_700_000_010_000; // 10 s into a step: 20 s left
    vaultWithTotp((a) => ({ node: a.node, entry: a.entry, code: "654321" }));
    const m = bridgeModel(() => t0);
    const shown = await readTotp(m, "atlas", "e3");
    expect(shown.expiresAt - t0).toBe(TOTP_STEP_MS - (t0 % TOTP_STEP_MS));
    expect(m.plain("atlas", "e3", 0)).toBe("654321");
    expect(JSON.stringify(m.view)).not.toContain("654321");
  });

  it("is also bounded by the reveal window when that is shorter", async () => {
    const t0 = 1_700_000_000_000 - (1_700_000_000_000 % TOTP_STEP_MS); // the very start of a step: 30 s left
    vaultWithTotp((a) => ({ node: a.node, entry: a.entry, code: "111222" }));
    const m = bridgeModel(() => t0);
    const shown = await readTotp(m, "atlas", "e3", 5_000);
    expect(shown.expiresAt - t0).toBe(5_000);
  });

  it("the code is gone once its step ends", async () => {
    let t = 1_700_000_000_000 - (1_700_000_000_000 % TOTP_STEP_MS);
    vaultWithTotp((a) => ({ node: a.node, entry: a.entry, code: "111222" }));
    const m = bridgeModel(() => t);
    await readTotp(m, "atlas", "e3");
    t += TOTP_STEP_MS - 1;
    expect(m.plain("atlas", "e3", 0)).toBe("111222");
    t += 1;
    expect(m.plain("atlas", "e3", 0)).toBeUndefined();
  });

  it("a code that arrives after the window was hidden, the node changed or the vault locked is discarded (held: false, nothing stored)", async () => {
    for (const cancel of [
      (m: VaultModel) => m.wipeSecrets(),
      (m: VaultModel) => m.hide("atlas", "e3", 0),
      (m: VaultModel) => m.clear(),
    ]) {
      let release!: () => void;
      const gate = new Promise<void>((r) => (release = r));
      vaultWithTotp(async (a) => { await gate; return { node: a.node, entry: a.entry, code: "135790" }; });
      const m = bridgeModel();
      const asking = readTotp(m, "atlas", "e3");
      cancel(m); // while the broker is still answering
      release();
      const shown = await asking;
      expect(shown.held).toBe(false);
      expect(m.secretCount).toBe(0);
      expect(m.plain("atlas", "e3", 0)).toBeUndefined();
    }
  });

  it("sends node and entry under the bridge's keys; a refusal stores nothing", async () => {
    const calls = vaultWithTotp(() => { throw refuse("node_access_denied", { rule: "R1" }); });
    const m = bridgeModel();
    await expect(readTotp(m, "cobalt", "e9")).rejects.toMatchObject({ code: "node_access_denied" });
    expect(calls).toEqual([{ cmd: "totp_code", args: { node: "cobalt", entry: "e9" } }]);
    expect(m.secretCount).toBe(0);
  });

  it("the seed is asked for and refused; nothing is kept", async () => {
    const calls = installInvoke({ totp_seed: () => { throw refuse("presence_required"); } });
    const m = bridgeModel();
    await expect(readTotpSeed(m, "atlas", "e3")).rejects.toMatchObject({ code: "presence_required" });
    expect(calls).toEqual([{ cmd: "totp_seed", args: { node: "atlas", entry: "e3" } }]);
    expect(m.secretCount).toBe(0);
  });

  it("on an entry with several fields the seed's field is named in both calls, and the code is held under THAT field", async () => {
    const calls = installInvoke({
      totp_code: (a) => ({ node: a.node, entry: a.entry, code: "246810" }),
      totp_seed: () => { throw refuse("presence_required"); },
    });
    const m = bridgeModel();
    await readTotp(m, "atlas", "e3", Number.POSITIVE_INFINITY, "f_00000007");
    expect(m.plain("atlas", "e3", "f_00000007")).toBe("246810");
    expect(m.plain("atlas", "e3", 0)).toBeUndefined(); // not under the position of a field that has an id
    await expect(readTotpSeed(m, "atlas", "e3", "f_00000007")).rejects.toMatchObject({ code: "presence_required" });
    expect(calls).toEqual([
      { cmd: "totp_code", args: { node: "atlas", entry: "e3", field: "f_00000007" } },
      { cmd: "totp_seed", args: { node: "atlas", entry: "e3", field: "f_00000007" } },
    ]);
  });
});

describe("copy", () => {
  it("goes through the shell's command and reports a receipt, never a value", async () => {
    const calls = installInvoke({});
    const seen: Array<[string, string, string | undefined]> = [];
    const r = await copyEntry(bridgeModel(), "atlas", "e1", "f_00000002", async (n, e, f) => { seen.push([n, e, f]); return { copied: true, clearAfterSeconds: 30 }; });
    expect(r).toEqual({ copied: true, clearAfterSeconds: 30 });
    expect(seen).toEqual([["atlas", "e1", "f_00000002"]]);
    expect(calls).toEqual([]); // the page asked the broker for nothing: no entry_reveal, so no value ever reached it
    expect(JSON.stringify(r)).not.toMatch(/value/i);
  });

  it("by default it is the bridge client's entry_copy that is called, with the node, the entry and the ONE field named, and nothing else", async () => {
    const calls = installInvoke({ entry_copy: () => ({ copied: true, clearAfterSeconds: 30 }) });
    const r = await copyEntry(bridgeModel(), "atlas", "e1", "f_00000002");
    expect(r).toEqual({ copied: true, clearAfterSeconds: 30 });
    expect(calls).toEqual([{ cmd: "entry_copy", args: { node: "atlas", entry: "e1", field: "f_00000002" } }]); // no entry_reveal: the value is not fetched into the page
  });

  it("with no field named only a one-field entry can be copied; the shell's field_required arrives unchanged", async () => {
    const calls = installInvoke({ entry_copy: (a) => { if (a.field === undefined) throw refuse("field_required"); return { copied: true, clearAfterSeconds: 30 }; } });
    await expect(copyEntry(bridgeModel(), "atlas", "e1")).rejects.toMatchObject({ code: "field_required" });
    expect(calls).toEqual([{ cmd: "entry_copy", args: { node: "atlas", entry: "e1" } }]);
  });

  it("a clipboard the shell could not write arrives unchanged, and nothing is reported as copied", async () => {
    installInvoke({ entry_copy: () => { throw refuse("clipboard_failed"); } });
    await expect(copyEntry(bridgeModel(), "atlas", "e1", "f_00000001")).rejects.toMatchObject({ code: "clipboard_failed" });
  });

  it("the shell's own refusals arrive unchanged", async () => {
    installInvoke({});
    await expect(copyEntry(bridgeModel(), "cobalt", "e1", "f_00000001", async () => { throw refuse("approval_pending"); })).rejects.toMatchObject({ code: "approval_pending" });
  });

  it("the demo vault has no shell to copy with", async () => {
    expect(await copyEntry(new VaultModel(new DemoSource()), "a", "b", "f_00000001", async () => ({ copied: true, clearAfterSeconds: 30 }))).toEqual({ copied: false, reason: "unavailable" });
  });
});

describe("the model", () => {
  const hold = (m: VaultModel, value: string, windowMs: number) => m.holdFetched("n", "e", 0, async () => value, (v) => ({ value: v, windowMs }));

  it("holdFetched keeps a value under the same expiry and wipe rules as a reveal", async () => {
    let t = 1_000;
    const m = new VaultModel(new DemoSource(), { now: () => t });
    expect(await hold(m, "v1", 100)).toEqual({ held: true, result: "v1" });
    expect(m.plain("n", "e", 0)).toBe("v1");
    expect(m.secretCount).toBe(1);
    t += 100;
    expect(m.plain("n", "e", 0)).toBeUndefined();
    await hold(m, "v2", 100);
    m.wipeSecrets();
    expect(m.plain("n", "e", 0)).toBeUndefined();
    await hold(m, "v3", 100);
    m.clear();
    expect(m.secretCount).toBe(0);
  });

  it("a value whose request was cancelled while the broker was answering is dropped on arrival, however it was cancelled", async () => {
    for (const cancel of [
      (m: VaultModel) => m.wipeSecrets(), // the window was hidden, or the node changed
      (m: VaultModel) => m.hide("n", "e", 0), // the user hid the field
      (m: VaultModel) => m.clear(), // the vault locked
    ]) {
      const m = new VaultModel(new DemoSource());
      let release!: () => void;
      const gate = new Promise<void>((r) => (release = r));
      const asking = m.holdFetched("n", "e", 0, async () => { await gate; return "late"; }, (value) => ({ value, windowMs: 60_000 }));
      cancel(m);
      release();
      expect(await asking).toEqual({ held: false, result: "late" });
      expect(m.secretCount).toBe(0);
      expect(m.plain("n", "e", 0)).toBeUndefined();
    }
  });
});

describe("a graph snapshot that says the vault is locked", () => {
  it("is a lost login: it rejects with vault_locked so every caller ends at the Lock screen", async () => {
    installInvoke({ graph_snapshot: () => snapshot([wireNode("global")], true), grant_list: () => ({ grants: [] }) });
    const src = new BridgeSource(live);
    await expect(src.graph()).rejects.toMatchObject({ source: "broker", code: "vault_locked" });
  });

  it("loadAll and refresh both surface it, and publish nothing", async () => {
    let locked = false;
    installInvoke({
      graph_snapshot: () => snapshot([wireNode("global")], locked),
      grant_list: () => ({ grants: [] }),
      entry_list: (a) => list(a.node as string),
      vault_pending_list: (a) => ({ node: a.node, pending: [] }),
    });
    const m = bridgeModel();
    await m.loadAll();
    const before = m.view;
    locked = true;
    await expect(m.refresh({ graph: true })).rejects.toMatchObject({ code: "vault_locked" });
    expect(m.view).toBe(before);
    await expect(m.loadAll()).rejects.toMatchObject({ code: "vault_locked" });
  });
});
