// ADR-167 (tag chips in the entry inspector) and ADR-168 (Merge and Dismiss in the Tidy up overlay).  The logic runs through the real
// bridge client against the fixture broker, with the shell's `invoke` wrapped so the command name and the argument keys the real bridge
// sends are the ones asserted here.
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import Component from "../../src/design/logic/core.js";
import { normaliseTag } from "../../src/design/logic/tags.js";
import { tidyMergePlan } from "../../src/design/logic/tidy.js";
import { brokerScript } from "../fixtures/broker/script.mjs";

const ROOT = resolve(__dirname, "../..");
const read = (rel: string) => readFileSync(resolve(ROOT, rel), "utf8");
const g = globalThis as unknown as { window?: any };

interface Call {
  cmd: string;
  args: Record<string, unknown>;
}

function fixture() {
  const win: any = {};
  g.window = win;
  new Function("window", brokerScript({ locked: false }))(win);
  const calls: Call[] = [];
  const failNext: Record<string, string> = {};
  const inner = win.__TAURI_INTERNALS__.invoke;
  win.__TAURI_INTERNALS__.invoke = async (cmd: string, args: Record<string, unknown> = {}) => {
    calls.push({ cmd, args: JSON.parse(JSON.stringify(args)) });
    if (failNext[cmd]) {
      const code = failNext[cmd];
      delete failNext[cmd];
      throw { source: "broker", code, message: code };
    }
    return inner(cmd, args);
  };
  return { calls, failNext, win };
}

const flush = async (n = 8) => {
  for (let i = 0; i < n; i++) await new Promise((r) => setTimeout(r, 0));
};

async function booted(state: Record<string, unknown>, plant?: (S: any) => void) {
  const fx = fixture();
  if (plant) plant(fx.win.__brokerFixture.S);
  const logic: any = new (Component as any)({ mode: "pro" });
  logic.__host = {
    setLogicState(update: any, cb?: () => void) {
      const patch = typeof update === "function" ? update(logic.state) : update;
      if (patch) logic.state = { ...logic.state, ...patch };
      cb?.();
    },
    forceUpdate() {},
  };
  logic.notify = () => {};
  logic.buildEntryNodes = () => {};
  logic.renderGraph = () => {};
  await logic.model.boot();
  logic.state = { ...logic.state, screen: "app", selected: "atlas", dialog: null, ...state };
  logic.renderVals();
  await flush();
  return { logic, ...fx };
}

afterEach(() => {
  delete g.window;
});

describe("tags in the inspector (entry.tag_set)", () => {
  it("normalises a tag the way the broker does", () => {
    expect(normaliseTag("  Staging   DB ")).toBe("staging-db");
    expect(normaliseTag("team:eu/payments")).toBe("team:eu/payments");
    expect(normaliseTag("no,commas")).toBeNull();
    expect(normaliseTag("")).toBeNull();
    expect(normaliseTag("a".repeat(33))).toBeNull();
  });

  it("adds a tag on Enter with the node's generation, shows what the broker stored, and removes one with its ✕", async () => {
    const { logic, calls } = await booted({ openEntry: "e-a1" });
    expect(logic.model.detail("atlas", "e-a1")).toBeTruthy();
    let v = logic.renderVals();
    expect(v.tagsShow).toBe(true);
    expect(v.tagChips).toEqual([]);
    const gen = logic.model.detail("atlas", "e-a1").generation;

    v.onTagDraft({ target: { value: "  Prod  Env " } });
    logic.renderVals().onTagKey({ key: "Enter", preventDefault() {} });
    await flush();
    const sent = calls.filter((c) => c.cmd === "entry_tag_set");
    expect(sent).toHaveLength(1);
    expect(sent[0].args).toEqual({ node: "atlas", entry: "e-a1", generation: gen, tags: ["prod-env"] });
    v = logic.renderVals();
    expect(v.tagChips.map((c: { tag: string }) => c.tag)).toEqual(["prod-env"]);
    expect(v.tagDraft).toBe("");

    v.tagChips[0].remove();
    await flush();
    const last = calls.filter((c) => c.cmd === "entry_tag_set").pop()!;
    expect(last.args.tags).toEqual([]);
    expect(logic.renderVals().tagChips).toEqual([]);
  });

  it("refuses a tag the broker would refuse without sending anything, and says a stale generation in words", async () => {
    const { logic, calls, failNext } = await booted({ openEntry: "e-a1" });
    logic.renderVals().onTagDraft({ target: { value: "bad,tag" } });
    logic.renderVals().onTagKey({ key: "Enter" });
    await flush();
    expect(calls.filter((c) => c.cmd === "entry_tag_set")).toHaveLength(0);
    expect(logic.renderVals().tagErrShow).toBe(true);

    failNext.entry_tag_set = "conflict";
    logic.renderVals().onTagDraft({ target: { value: "ok" } });
    logic.renderVals().onTagKey({ key: "Enter" });
    await flush();
    expect(logic.renderVals().tagErr).toMatch(/changed elsewhere/);
  });

  it("is in the inspector template, bound to the logic", () => {
    const html = read("src/design/screens/S4-inspector.html");
    expect(html).toContain("{{tagChips}}");
    expect(html).toContain('onKeyDown="{{onTagKey}}"');
  });
});

describe("Merge and Dismiss in Tidy up (merge.apply, merge.dismiss)", () => {
  const twin = (S: any) => {
    S.entries.atlas.push({ id: "e-t1", name: "TWIN_ONE", type: "api", sensitivity: "high", value: "fixture-twin-value-77", modified: 1760000000, rotatedAt: null, expiresAt: null });
    S.entries.atlas.push({ id: "e-t2", name: "TWIN_TWO", type: "api", sensitivity: "high", value: "fixture-twin-value-77", modified: 1760000000, rotatedAt: null, expiresAt: null });
  };

  it("plans a merge only for copies inside one node, keeping the oldest", () => {
    const e = (node: string, entry: string, ref: number) => ({ node, nodeLabel: node, entry, ref, name: entry, generation: 1 });
    const plan = tidyMergePlan({ kind: "duplicate_value", proposal: { action: "merge", op: null }, entries: [e("a", "e2", 9), e("a", "e1", 3)] });
    expect(plan).toEqual({ node: "a", keep: "e1", keepName: "e1", drop: ["e2"], key: "e1+e2" });
    expect(tidyMergePlan({ kind: "duplicate_value", proposal: { action: "share", op: null }, entries: [e("a", "e1", 1), e("b", "e2", 2)] })).toBeNull();
    expect(tidyMergePlan({ kind: "duplicate_value", proposal: { action: "merge", op: null }, entries: [e("a", "e1", 1), e("b", "e2", 2)] })).toBeNull();
  });

  it("Merge sends merge.apply with the kept entry and the node's generation, then scans again", async () => {
    const { logic, calls } = await booted({}, twin);
    logic.openTidy();
    await flush();
    const group = logic.renderVals().tidyGroups.find((gr: { kind: string }) => gr.kind === "duplicate_value");
    const row = group.rows.find((r: { mergeShow: boolean }) => r.mergeShow);
    expect(row).toBeTruthy();
    expect(row.mergeLabel).toMatch(/^Merge into /);
    const scansBefore = calls.filter((c) => c.cmd === "vault_doctor_scan").length;
    row.merge();
    await flush(16);
    const sent = calls.filter((c) => c.cmd === "merge_apply");
    expect(sent).toHaveLength(1);
    expect(sent[0].args.node).toBe("atlas");
    expect(Object.keys(sent[0].args).sort()).toEqual(["drop", "generation", "keep", "node"]);
    expect([sent[0].args.keep, ...(sent[0].args.drop as string[])].sort()).toEqual(["e-t1", "e-t2"]);
    expect(calls.filter((c) => c.cmd === "vault_doctor_scan").length).toBe(scansBefore + 1);
    for (const c of calls) expect(JSON.stringify(c.args)).not.toContain("fixture-twin-value-77");
  });

  it("Dismiss sends merge.dismiss with the group's key; a refused merge says so and changes nothing", async () => {
    const { logic, calls, failNext } = await booted({}, twin);
    logic.openTidy();
    await flush();
    const row = () => logic.renderVals().tidyGroups.find((gr: { kind: string }) => gr.kind === "duplicate_value").rows.find((r: { mergeShow: boolean }) => r.mergeShow);
    failNext.merge_apply = "two_factor_required";
    row().merge();
    await flush(16);
    expect(logic.renderVals().tidyActErr).toMatch(/second factor/);
    row().dismiss();
    await flush(16);
    const sent = calls.filter((c) => c.cmd === "merge_dismiss");
    expect(sent).toHaveLength(1);
    expect(sent[0].args).toEqual({ node: "atlas", key: "e-t1+e-t2" });
  });
});
