// rc.2 §1 item 3: find by reference (header search, entry.get_by_ref), the rail's node filter, Find in this node (entry.search) and the
// Audit report (audit.report).  The logic runs through the real bridge client against the fixture broker (tests/fixtures/broker/quick.js),
// with the shell's `invoke` wrapped so the command names and argument keys are the ones asserted here.
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { reportWindow } from "../../src/design/logic/auditreport.js";
import Component from "../../src/design/logic/core.js";
import { nodeFilterIds } from "../../src/design/logic/finder.js";
import { brokerScript } from "../fixtures/broker/script.mjs";

const ROOT = resolve(__dirname, "../..");
const read = (rel: string) => readFileSync(resolve(ROOT, rel), "utf8");
const g = globalThis as unknown as { window?: any };

function fixture() {
  const win: any = {};
  g.window = win;
  new Function("window", brokerScript({ locked: false }))(win);
  const calls: { cmd: string; args: Record<string, unknown> }[] = [];
  const inner = win.__TAURI_INTERNALS__.invoke;
  win.__TAURI_INTERNALS__.invoke = async (cmd: string, args: Record<string, unknown> = {}) => {
    calls.push({ cmd, args: JSON.parse(JSON.stringify(args)) });
    return inner(cmd, args);
  };
  return { calls, win };
}

const flush = async (n = 8) => {
  for (let i = 0; i < n; i++) await new Promise((r) => setTimeout(r, 0));
};

async function app() {
  const fx = fixture();
  const logic: any = new (Component as any)({ mode: "pro" });
  logic.__host = {
    setLogicState(update: any, cb?: () => void) {
      const patch = typeof update === "function" ? update(logic.state) : update;
      if (patch) logic.state = { ...logic.state, ...patch };
      cb?.();
    },
    forceUpdate() {},
  };
  const notes: [string, string][] = [];
  logic.notify = (k: string, t: string) => notes.push([k, t]);
  logic.buildEntryNodes = () => {};
  logic.renderGraph = () => {};
  logic._mounted = true;
  await logic.model.boot();
  logic.state = { ...logic.state, screen: "app", selected: "atlas", openEntry: null, dialog: null };
  logic.renderVals();
  await flush();
  return { logic, notes, ...fx };
}

afterEach(() => {
  delete g.window;
});

describe("the rail's node filter (no broker call)", () => {
  const nodes = [
    { id: "global", label: "global", kind: "global", parentId: null },
    { id: "atlas", label: "Atlas", kind: "project", parentId: "global" },
    { id: "staging", label: "Staging", kind: "sub", parentId: "atlas" },
    { id: "beacon", label: "Beacon", kind: "project", parentId: "global" },
  ];
  it("matches a label or an id, case-insensitive, and keeps a matching sub-node's project", () => {
    expect(nodeFilterIds(nodes, "")).toBe(null);
    expect([...nodeFilterIds(nodes, "STAG")!]).toEqual(["staging", "atlas"]);
    expect([...nodeFilterIds(nodes, "beac")!]).toEqual(["beacon"]);
    expect(nodeFilterIds(nodes, "zzz")!.size).toBe(0);
  });

  it("narrows the rail rows and the tree, and asks the broker nothing", async () => {
    const { logic, calls } = await app();
    const before = calls.length;
    logic.renderVals().onNodeFilter({ target: { value: "stag" } });
    const v = logic.renderVals();
    expect(v.railRows.map((r: { id: string }) => r.id)).toEqual(["atlas", "staging"]);
    expect(v.nodeFilterOn).toBe(true);
    logic.renderVals().onNodeFilter({ target: { value: "zzz" } });
    expect(logic.renderVals().nodeFilterNone).toBe(true);
    logic.renderVals().clearNodeFilter();
    expect(logic.renderVals().railRows.length).toBeGreaterThan(4);
    expect(calls.length).toBe(before);
  });
});

describe("Find in this node (entry.search)", () => {
  it("asks the broker for names and aliases on the selected node once typing pauses, and a result opens the entry", async () => {
    const { logic, calls, win } = await app();
    win.__brokerFixture.S.entries.atlas[0].aliases = ["live-payments"];
    let v = logic.renderVals();
    expect(v.nodeFindShow).toBe(true);
    v.onNodeFind({ target: { value: "pay" } });
    await new Promise((r) => setTimeout(r, 260));
    await flush();
    expect(calls.filter((c) => c.cmd === "entry_search")).toEqual([{ cmd: "entry_search", args: { node: "atlas", term: "pay" } }]);
    v = logic.renderVals();
    expect(v.nodeFindRows).toHaveLength(1);
    expect(v.nodeFindRows[0].name).toBe("stripe-live");
    expect(v.nodeFindRows[0].why).toBe("also called live-payments");
    v.nodeFindRows[0].open();
    expect(logic.state.openEntry).toBe("e-a1");
  });

  it("an answer for a term the user has typed past is dropped", async () => {
    const { logic, calls } = await app();
    logic.renderVals().onNodeFind({ target: { value: "str" } });
    logic.renderVals().onNodeFind({ target: { value: "zzz" } });
    await new Promise((r) => setTimeout(r, 260));
    await flush();
    expect(calls.filter((c) => c.cmd === "entry_search").map((c) => c.args.term)).toEqual(["zzz"]); // debounced: only the last
    expect(logic.renderVals().nodeFindNone).toBe(true);
  });
});

describe("find by reference (entry.get_by_ref, in the header search)", () => {
  it("a number is looked up as a reference and the entry it names comes first; it opens that entry in its node", async () => {
    const { logic, calls } = await app();
    logic.state = { ...logic.state, searchOpen: true, searchQ: "#2" }; // an answer is kept only for the term in the box
    await logic.runSearch("#2");
    const refCalls = calls.filter((c) => c.cmd === "entry_get_by_ref");
    expect(refCalls).toEqual([{ cmd: "entry_get_by_ref", args: { reference: 2 } }]);
    const v = logic.renderVals();
    expect(v.searchRows[0].glyph).toBe("#");
    expect(v.searchRows[0].label).toBe("stripe-live");
    expect(v.searchRows[0].meta).toBe("#2 · atlas");
    v.searchRows[0].go();
    expect(logic.state.selected).toBe("atlas");
    expect(logic.state.openEntry).toBe("e-a1");
  });

  it("a number the broker does not know (or one in a node this login cannot list) adds nothing; a word is not looked up", async () => {
    const { logic, calls } = await app();
    logic.state = { ...logic.state, searchQ: "6" };
    await logic.runSearch("6"); // cobalt is locked: answered not_found, the same as no such number
    expect(logic.state.searchHits.ref).toBe(null);
    logic.state = { ...logic.state, searchQ: "stripe" };
    await logic.runSearch("stripe");
    expect(calls.filter((c) => c.cmd === "entry_get_by_ref").map((c) => c.args.reference)).toEqual([6]);
  });
});

describe("the Audit report (audit.report)", () => {
  it("the window: the last N days, or two UTC dates (both inclusive), at most 366 days", () => {
    const now = 1_800_000_000;
    expect(reportWindow({ range: "7" }, now)).toEqual({ from: now - 7 * 86400, to: now + 1 });
    expect(reportWindow({ range: "dates", fromDay: "2026-10-01", toDay: "2026-10-31" }, now)).toEqual({
      from: Date.UTC(2026, 9, 1) / 1000,
      to: Date.UTC(2026, 10, 1) / 1000,
    });
    expect(reportWindow({ range: "dates", fromDay: "2026-10-31", toDay: "2026-10-01" }, now).error).toContain("before the start");
    expect(reportWindow({ range: "dates", fromDay: "2024-01-01", toDay: "2026-01-01" }, now).error).toContain("366 days");
    expect(reportWindow({ range: "dates", fromDay: "nope", toDay: "2026-01-01" }, now).error).toContain("YYYY-MM-DD");
  });

  it("Make report sends the window and the node chosen, and shows actions, sessions and refusals, never a value", async () => {
    const { logic, calls, win } = await app();
    win.__brokerFixture.S.audit.push({ id: "aud-x", timestamp: Math.floor(Date.now() / 1000) - 60, actor: "ses_fixture_agent", action: "entry.reveal", node: "atlas", entry: "e-a1", decision: "deny" });
    logic.state = { ...logic.state, overlay: "settings", setSection: "report" };
    let v = logic.renderVals();
    expect(v.setReport).toBe(true);
    v.onArNode({ target: { value: "atlas" } });
    await logic.renderVals().arRun();
    await flush();
    const sent = calls.filter((c) => c.cmd === "audit_report");
    expect(sent).toHaveLength(1);
    expect(sent[0].args.node).toBe("atlas");
    expect((sent[0].args.to as number) - (sent[0].args.from as number)).toBe(30 * 86400 + 1);
    v = logic.renderVals();
    expect(v.arShow).toBe(true);
    expect(v.arSummary).toContain("atlas only");
    expect(v.arByActor.map((x: { name: string }) => x.name)).toContain("ses_fixture_agent");
    expect(v.arDenialsShow).toBe(true);
    expect(v.arDenials[0].reason).toBe("node_access_denied");
    expect(JSON.stringify(v.arByAction)).not.toContain("fixture-value");
  });

  it("a bad window is said and nothing is sent", async () => {
    const { logic, calls } = await app();
    logic.state = { ...logic.state, overlay: "settings", setSection: "report" };
    logic.renderVals().onArRange({ target: { value: "dates" } });
    logic.renderVals().onArFrom({ target: { value: "2026-10-31" } });
    logic.renderVals().onArTo({ target: { value: "2026-10-01" } });
    await logic.renderVals().arRun();
    expect(logic.renderVals().arErr).toContain("before the start date");
    expect(calls.filter((c) => c.cmd === "audit_report")).toHaveLength(0);
  });
});

describe("the template", () => {
  it("the rail has the filter, the inspector Find in this node, Settings the report, and the search box says it takes a #ref", () => {
    expect(read("src/design/screens/S1-rail.html")).toContain("{{onNodeFilter}}");
    expect(read("src/design/screens/S4-inspector.html")).toContain("{{onNodeFind}}");
    expect(read("src/design/screens/S12-settings.html")).toContain("{{arRun}}");
    expect(read("src/design/screens/S1-header.html")).toContain('placeholder="search… or #ref  /"');
  });
});
