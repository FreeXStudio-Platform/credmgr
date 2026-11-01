// The read-path logic (work package B) in the two places a browser test cannot force: a handler that arrives twice, and answers that
// arrive out of order.  The logic class runs with no host, against a faked Tauri `invoke`, so the bridge source is the real one.
import { afterEach, describe, expect, it } from "vitest";

import Component from "../../src/design/logic/core.js";

type Handler = (args: Record<string, unknown>) => unknown | Promise<unknown>;
interface Call {
  cmd: string;
  args: Record<string, unknown>;
}

const node = (id: string, kind: string, parentId: string | null) => ({ id, label: id, kind, depth: kind === "global" ? 0 : 1, parentId, counts: { entries: 0, totp: 0 }, gate: { locked: false, twofa: "none" }, health: null });

/** A logic instance over the real BridgeSource, the Tauri shell replaced by `handlers`.  Returns the call log too. */
function bridgeLogic(handlers: Record<string, Handler>) {
  const calls: Call[] = [];
  (globalThis as unknown as { window?: object }).window = {
    __TAURI_INTERNALS__: {
      invoke: async (cmd: string, args?: Record<string, unknown>) => {
        calls.push({ cmd, args: JSON.parse(JSON.stringify(args ?? {})) });
        const h = handlers[cmd];
        if (!h) throw { source: "broker", code: "internal", message: `no handler for ${cmd}` };
        return h(args ?? {});
      },
    },
  };
  // there is no animation frame in a unit test, and a logic class with no host drops every setState: give it the smallest host that merges
  (globalThis as unknown as Record<string, unknown>).requestAnimationFrame = () => 0;
  (globalThis as unknown as Record<string, unknown>).cancelAnimationFrame = () => {};
  const logic = new (Component as any)({ mode: "pro" });
  logic.__host = {
    setLogicState(update: unknown, cb?: () => void) {
      const next = typeof update === "function" ? (update as (s: unknown) => unknown)(logic.state) : update;
      if (next) logic.state = { ...logic.state, ...(next as object) };
      cb?.();
    },
    forceUpdate() {},
  };
  return { logic, calls };
}

const vault: Record<string, Handler> = {
  graph_snapshot: () => ({ nodes: [node("global", "global", null), node("atlas", "project", "global")], links: [{ source: "global", target: "atlas", kind: "structural", direction: "down" }], meta: { generatedAt: 1, vaultLocked: false } }),
  grant_list: () => ({ grants: [] }),
  entry_list: (a) => ({ node: a.node, ids: [], names: [], entries: [], generation: 1 }),
  vault_pending_list: (a) => ({ node: a.node, pending: [] }),
};

afterEach(() => {
  delete (globalThis as unknown as { window?: object }).window;
  delete (globalThis as unknown as Record<string, unknown>).requestAnimationFrame;
  delete (globalThis as unknown as Record<string, unknown>).cancelAnimationFrame;
});

describe("rename", () => {
  it("Enter and the blur that follows it make ONE request: the first to arrive wins", async () => {
    const { logic, calls } = bridgeLogic({ ...vault, node_update: (a) => ({ node: a.node, label: a.label }) });
    await logic.model.loadAll();
    logic.state = { ...logic.state, renamingNode: "atlas", renameVal: "Atlas Prod" };
    await Promise.all([logic.commitRename("atlas"), logic.commitRename("atlas")]);
    expect(calls.filter((c) => c.cmd === "node_update")).toEqual([{ cmd: "node_update", args: { node: "atlas", label: "Atlas Prod" } }]);
    expect(logic.state.renamingNode).toBeNull();
  });

  it("an unchanged, empty or over-long name sends nothing", async () => {
    const { logic, calls } = bridgeLogic({ ...vault, node_update: (a) => ({ node: a.node, label: a.label }) });
    await logic.model.loadAll();
    for (const val of ["atlas", "   ", "x".repeat(121)]) {
      logic.state = { ...logic.state, renamingNode: "atlas", renameVal: val };
      await logic.commitRename("atlas");
    }
    expect(calls.filter((c) => c.cmd === "node_update")).toEqual([]);
  });

  it("a name that is not being edited is not sent (a blur after Escape)", async () => {
    const { logic, calls } = bridgeLogic({ ...vault, node_update: (a) => ({ node: a.node, label: a.label }) });
    await logic.model.loadAll();
    logic.state = { ...logic.state, renamingNode: null, renameVal: "Something" };
    await logic.commitRename("atlas");
    expect(calls.filter((c) => c.cmd === "node_update")).toEqual([]);
  });
});

describe("search answers that arrive out of order", () => {
  it("the answer for an older term never replaces the answer for the current one", async () => {
    const early = [{ node: "atlas", id: "e1", name: "early-hit" }];
    const late = [{ node: "atlas", id: "e2", name: "current-hit" }];
    const { logic } = bridgeLogic({
      ...vault,
      search: async (a) => {
        if (a.term === "ab") {
          await new Promise((r) => setTimeout(r, 60)); // the older request is slow
          return { results: early };
        }
        return { results: late };
      },
    });
    logic._mounted = true; // the guard the async handlers use to stop after unmount
    logic.state = { ...logic.state, searchQ: "ab" };
    const first = logic.runSearch("ab");
    logic.state = { ...logic.state, searchQ: "abc" }; // the user types on
    const second = logic.runSearch("abc");
    await Promise.all([first, second]);
    expect(logic.state.searchHits).toEqual({ q: "abc", rows: late });
  });

  it("a failed search for a term the user has already left is not shown", async () => {
    const { logic } = bridgeLogic({ ...vault, search: async () => { throw { source: "broker", code: "capability_not_held", message: "x" }; } });
    logic._mounted = true;
    logic.state = { ...logic.state, searchQ: "something-else" };
    await logic.runSearch("ab");
    expect(logic.state.notice ?? null).toBeNull();
  });

  it("after the window is gone (unmounted) a late answer touches nothing", async () => {
    const { logic } = bridgeLogic({ ...vault, search: async () => ({ results: [{ node: "atlas", id: "e1", name: "x" }] }) });
    logic.state = { ...logic.state, searchQ: "x" };
    logic._mounted = false;
    await logic.runSearch("x");
    expect(logic.state.searchHits).toBeUndefined();
  });
});

describe("a read-path refusal", () => {
  it("only a READ of a locked node is the locked panel: a refused unlock is shown, not swallowed", async () => {
    // the broker's snapshot says atlas is locked (the view is frozen in a test build, so it is the broker that has to say so)
    const lockedSnapshot = () => ({
      nodes: [node("global", "global", null), { ...node("atlas", "project", "global"), gate: { locked: true, twofa: "none" } }],
      links: [{ source: "global", target: "atlas", kind: "structural", direction: "down" }],
      meta: { generatedAt: 1, vaultLocked: false },
    });
    const { logic } = bridgeLogic({ ...vault, graph_snapshot: lockedSnapshot });
    await logic.model.loadAll();
    const denied = { source: "broker", code: "node_access_denied", message: "x", detail: { rule: "R2" } };
    // a refused UNLOCK (not a read) of a node the snapshot calls locked must still reach the router
    const unlock = logic.routeReadError(denied, { op: "vault.node_unlock", node: "atlas" });
    expect(unlock.route).toBe("inline"); // routeError's own answer for a denial: "Not permitted (R2)."
    // while the same refusal on a REVEAL of that node is the locked panel
    expect(logic.routeReadError(denied, { op: "entry.reveal", node: "atlas" }).route).toBe("node-locked");
  });
});
