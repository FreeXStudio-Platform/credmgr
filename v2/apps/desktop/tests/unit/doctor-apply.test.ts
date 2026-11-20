// ADR-169: "Apply all moves" in Tidy up (vault.doctor_apply).  The logic runs through the real bridge client against the fixture broker
// (tests/fixtures/broker/quick.js), with the shell's `invoke` wrapped so the command name and the plan the real bridge sends are the ones
// asserted here.  Nothing is sent until the confirm's Apply; the plan sent is the report's own move proposals, generations included.
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import Component from "../../src/design/logic/core.js";
import { tidyAppliedText, tidyPlan } from "../../src/design/logic/tidy.js";
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
  const answerNext: Record<string, unknown> = {};
  const inner = win.__TAURI_INTERNALS__.invoke;
  win.__TAURI_INTERNALS__.invoke = async (cmd: string, args: Record<string, unknown> = {}) => {
    calls.push({ cmd, args: JSON.parse(JSON.stringify(args)) });
    if (failNext[cmd]) {
      const code = failNext[cmd];
      delete failNext[cmd];
      throw { source: "broker", code, message: code };
    }
    if (answerNext[cmd]) {
      const a = answerNext[cmd];
      delete answerNext[cmd];
      return a;
    }
    return inner(cmd, args);
  };
  return { calls, failNext, answerNext, win };
}

const flush = async (n = 8) => {
  for (let i = 0; i < n; i++) await new Promise((r) => setTimeout(r, 0));
};

/** The fixture vault with a shared value in two sub-nodes of atlas (a move to atlas) and an entry misfiled in global (a move to atlas). */
async function booted() {
  const fx = fixture();
  const S = fx.win.__brokerFixture.S;
  S.nodes.push({ id: "staging-2", label: "staging-2", kind: "sub", depth: 2, parentId: "atlas", gate: { locked: false, twofa: "none" } });
  S.entries["staging-2"] = [{ id: "e-s2", name: "stg-db-copy", type: "server", sensitivity: "medium", value: "fixture-value-stg-db", modified: 1760000000, rotatedAt: null, expiresAt: null }];
  S.entries.global.push({ id: "e-g2", name: "atlas-hook", type: "api", sensitivity: "low", value: "fixture-value-atlas-hook", modified: 1760000000, rotatedAt: null, expiresAt: null });
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
  await logic.model.boot();
  logic.state = { ...logic.state, screen: "app", selected: "atlas", dialog: null };
  logic.renderVals();
  await flush();
  logic.renderVals().openTidy();
  await flush();
  return { logic, notes, S, ...fx };
}

afterEach(() => {
  delete g.window;
});

describe("the plan", () => {
  const report = {
    findings: [
      { kind: "duplicate_value", entries: [{ node: "a-web", nodeLabel: "A web", entry: "e1", name: "K", generation: 3 }], proposal: { action: "move_to_parent", op: "entry.move", to: "a", toLabel: "A", move: { node: "a-web", entry: "e1", to: "a", generation: 3 } } },
      { kind: "duplicate_value", entries: [], proposal: { action: "share", op: null } },
      { kind: "misfiled", entries: [{ node: "global", nodeLabel: "Global", entry: "e2", name: "A_HOOK", generation: 9 }], proposal: { action: "move_to_project", op: "entry.move", to: "a", toLabel: "A", move: { node: "global", entry: "e2", to: "a", generation: 9 } } },
    ],
  };
  it("is every move proposal of the report, in order, untouched", () => {
    const plan = tidyPlan(report);
    expect(plan.map((p: any) => p.move)).toEqual([
      { node: "a-web", entry: "e1", to: "a", generation: 3 },
      { node: "global", entry: "e2", to: "a", generation: 9 },
    ]);
    expect(plan.map((p: any) => `${p.name}: ${p.fromLabel} → ${p.toLabel}`)).toEqual(["K: A web → A", "A_HOOK: Global → A"]);
    expect(tidyPlan({ findings: [] })).toEqual([]);
  });
  it("says what was applied, and where it stopped", () => {
    const plan = tidyPlan(report);
    expect(tidyAppliedText(plan, { complete: true, applied: [{}, {}], notApplied: 0 })).toBe("Moved 2 entries as planned.");
    const partial = tidyAppliedText(plan, { complete: false, applied: [{}], stopped: { index: 1, code: "internal" }, notApplied: 1 });
    expect(partial).toMatch(/Moved 1 entry, then stopped at “A_HOOK” \(internal\): 1 move was not made/);
  });
});

describe("Apply all moves (vault.doctor_apply)", () => {
  it("lists every move, sends nothing until Apply, then sends exactly the plan the scan showed and scans again", async () => {
    const { logic, calls, notes, S } = await booted();
    let v = logic.renderVals();
    expect(v.tidyApplyShow).toBe(true);
    expect(v.tidyApplyLabel).toBe("Apply all moves (2)");
    expect(v.tidyApplyOpen).toBe(false);
    const report = logic.state.tidy.report;
    const expected = tidyPlan(report).map((p: any) => p.move);

    v.openTidyApply();
    v = logic.renderVals();
    expect(v.tidyApplyOpen).toBe(true);
    expect(v.tidyApplyTitle).toBe("Apply 2 moves?");
    expect(v.tidyApplyRows.map((r: { text: string }) => r.text)).toEqual(["1. stg-db: staging → atlas", "2. atlas-hook: global → atlas"]);
    expect(calls.filter((c) => c.cmd === "vault_doctor_apply")).toHaveLength(0);
    expect(JSON.stringify(v.tidyApplyRows)).not.toMatch(/fixture-value/);

    await v.tidyApplyGo();
    await flush();
    const sent = calls.filter((c) => c.cmd === "vault_doctor_apply");
    expect(sent).toHaveLength(1);
    expect(sent[0].args.moves).toEqual(expected);
    expect(notes.at(-1)).toEqual(["success", "Moved 2 entries as planned."]);
    expect(S.entries.atlas.map((e: { id: string }) => e.id)).toEqual(expect.arrayContaining(expected.map((m: { entry: string }) => m.entry)));
    // The confirm closed and the scan ran again; nothing is left to move.
    expect(calls.filter((c) => c.cmd === "vault_doctor_scan")).toHaveLength(2);
    v = logic.renderVals();
    expect(v.tidyApplyOpen).toBe(false);
    expect(v.tidyApplyShow).toBe(false);
  });

  it("Cancel sends nothing", async () => {
    const { logic, calls } = await booted();
    logic.renderVals().openTidyApply();
    logic.renderVals().tidyApplyCancel();
    expect(logic.renderVals().tidyApplyOpen).toBe(false);
    expect(calls.filter((c) => c.cmd === "vault_doctor_apply")).toHaveLength(0);
  });

  it("a refusal before anything moved is said in the confirm, which stays open", async () => {
    const { logic, failNext, S } = await booted();
    const before = JSON.stringify(S.entries);
    failNext.vault_doctor_apply = "conflict";
    logic.renderVals().openTidyApply();
    await logic.renderVals().tidyApplyGo();
    await flush();
    const v = logic.renderVals();
    expect(v.tidyApplyOpen).toBe(true);
    expect(v.tidyApplyErrShow).toBe(true);
    expect(v.tidyApplyErr).toMatch(/changed since this scan.*Nothing was moved/);
    expect(JSON.stringify(S.entries)).toBe(before);
  });

  it("a plan the broker stopped part-way is reported as such, and the scan runs again", async () => {
    const { logic, answerNext, notes, calls } = await booted();
    const plan = tidyPlan(logic.state.tidy.report);
    answerNext.vault_doctor_apply = {
      complete: false,
      applied: [{ index: 0, node: "atlas", entry: plan[0].move.entry, ref: 1, name: plan[0].name, from: plan[0].move.node, generation: 2, toGeneration: 2, grantsRevoked: [], historyDropped: 0 }],
      stopped: { index: 1, node: plan[1].move.node, entry: plan[1].move.entry, to: "atlas", code: "internal", message: "x" },
      notApplied: 1,
    };
    logic.renderVals().openTidyApply();
    await logic.renderVals().tidyApplyGo();
    await flush();
    expect(notes.at(-1)?.[0]).toBe("warn");
    expect(notes.at(-1)?.[1]).toMatch(/stopped at “atlas-hook” \(internal\)/);
    expect(calls.filter((c) => c.cmd === "vault_doctor_scan")).toHaveLength(2);
    expect(logic.renderVals().tidyApplyOpen).toBe(false);
  });

  it("the fixture broker refuses a plan with a clash at its second step and moves nothing", async () => {
    const { logic, S } = await booted();
    const report = logic.state.tidy.report;
    // A name in atlas that the second move would bring in again.
    S.entries.atlas.push({ id: "e-clash", name: "atlas-hook", type: "api", sensitivity: "low", value: "fixture-value-clash", modified: 1760000000, rotatedAt: null, expiresAt: null });
    S.generation.atlas = (S.generation.atlas || 1);
    const before = JSON.stringify({ e: S.entries, g: S.generation });
    logic.setState({ tidy: { state: "ready", report, error: "", apply: { open: true, busy: false, error: "" } } });
    await logic.renderVals().tidyApplyGo();
    await flush();
    expect(logic.renderVals().tidyApplyErr).toMatch(/same name/);
    expect(JSON.stringify({ e: S.entries, g: S.generation })).toBe(before);
  });
});

describe("the template", () => {
  it("the overlay carries Apply all moves and its confirm list", () => {
    const ov = read("src/design/screens/S22-tidy.html");
    for (const b of [
      "{{tidyApplyShow}}",
      "{{openTidyApply}}",
      "{{tidyApplyLabel}}",
      "{{tidyApplyOpen}}",
      "{{tidyApplyRows}}",
      "{{m.text}}",
      "{{tidyApplyGo}}",
      "{{tidyApplyGoLabel}}",
      "{{tidyApplyCancel}}",
      "{{tidyApplyErr}}",
    ])
      expect(ov).toContain(b);
  });
});
