// Where the graph first puts each node: computed from the tree the broker sent, never looked up by a node's name.
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import { layoutPositions } from "../../src/design/logic/graph.js";

const node = (id: string, kind: string, parentId: string | null) => ({ id, label: id, kind, parentId });

describe("layoutPositions", () => {
  const vault = [node("global", "global", null), node("zeta", "project", "global"), node("alpha", "project", "global"), node("mid", "project", "global"), node("zeta-a", "sub", "zeta"), node("zeta-b", "sub", "zeta")];
  const at = (m: Record<string, [number, number]>, id: string) => m[id];
  const dist = (a: [number, number], b: [number, number]) => Math.hypot(a[0] - b[0], a[1] - b[1]);

  it("puts global at the centre and every other node, and the orphaned one, somewhere of its own", () => {
    const p = layoutPositions(vault);
    expect(at(p, "global")).toEqual([0, 0]);
    const seen = new Set(Object.values(p).map(([x, y]) => `${x.toFixed(1)},${y.toFixed(1)}`));
    expect(seen.size).toBe(vault.length + 1); // six nodes + __orphan, no two on the same spot
    for (const [x, y] of Object.values(p)) expect(Number.isFinite(x) && Number.isFinite(y)).toBe(true);
  });

  it("is the same picture every time, whatever order the broker listed the nodes in", () => {
    expect(layoutPositions(vault)).toEqual(layoutPositions([...vault].reverse()));
  });

  it("keeps projects on one ring round global, and sub-nodes close to their own parent", () => {
    const p = layoutPositions(vault);
    const ring = dist(at(p, "global"), at(p, "alpha"));
    expect(dist(at(p, "global"), at(p, "zeta"))).toBeCloseTo(ring, 5);
    expect(dist(at(p, "global"), at(p, "mid"))).toBeCloseTo(ring, 5);
    const arm = dist(at(p, "zeta"), at(p, "zeta-a"));
    expect(arm).toBeLessThan(ring);
    expect(dist(at(p, "zeta"), at(p, "zeta-b"))).toBeCloseTo(arm, 5);
    expect(dist(at(p, "zeta-a"), at(p, "zeta-b"))).toBeGreaterThan(20); // siblings fan out, they do not stack
  });

  it("puts the orphaned node outside the ring", () => {
    const p = layoutPositions(vault);
    expect(dist(at(p, "global"), at(p, "__orphan"))).toBeGreaterThan(dist(at(p, "global"), at(p, "alpha")));
  });

  it("gives a vault of only global a place for every node, including the orphaned one", () => {
    const p = layoutPositions([node("global", "global", null)]);
    expect(Object.keys(p).sort()).toEqual(["__orphan", "global"]);
  });

  it("does not lose a node whose parent is missing from the snapshot", () => {
    const p = layoutPositions([node("global", "global", null), node("lost", "sub", "not-there")]);
    expect(p.lost).toBeDefined();
  });

  it("an empty vault still has somewhere for the orphaned node", () => {
    expect(Object.keys(layoutPositions([]))).toEqual(["__orphan"]);
  });

  it("the graph carries no table of node names (the demo's hand-placed coordinates are gone)", () => {
    const src = readFileSync(resolve(__dirname, "../../src/design/logic/graph.js"), "utf8");
    expect(src).not.toMatch(/pos0|atlas|beacon|cobalt|linux/); // ('staging' stays legal: it is a word the entry clustering ignores, not a node)
  });
});
