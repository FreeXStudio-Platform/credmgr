// ADR-161: the "Tidy up" overlay (vault.doctor_scan).  The logic runs through the real bridge client against the fixture broker
// (tests/fixtures/broker/quick.js), with the shell's `invoke` wrapped so the command name and argument keys the real bridge sends are
// the ones asserted here.  A move proposal opens the inspector's own Move dialog (ADR-158) with its destination chosen.
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import Component from "../../src/design/logic/core.js";
import { TIDY_KINDS, tidyAdvice, tidyLine } from "../../src/design/logic/tidy.js";
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

/** A logic instance on the fixture vault, with a shared value in two sub-nodes of atlas, one in two projects, and one misfiled entry. */
async function booted(plant = true) {
  const fx = fixture();
  const S = fx.win.__brokerFixture.S;
  if (plant) {
    S.nodes.push({ id: "staging-2", label: "staging-2", kind: "sub", depth: 2, parentId: "atlas", gate: { locked: false, twofa: "none" } });
    S.entries["staging-2"] = [{ id: "e-s2", name: "stg-db-copy", type: "server", sensitivity: "medium", value: "fixture-value-stg-db", modified: 1760000000, rotatedAt: null, expiresAt: null }];
    S.entries.beacon.push({ id: "e-b2", name: "stripe-copy", type: "api", sensitivity: "high", value: "fixture-value-stripe-live", modified: 1760000000, rotatedAt: null, expiresAt: null });
    S.entries.global.push({ id: "e-g2", name: "atlas-hook", type: "api", sensitivity: "low", value: "fixture-value-atlas-hook", modified: 1760000000, rotatedAt: null, expiresAt: null });
  }
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
  return { logic, notes, ...fx };
}

afterEach(() => {
  delete g.window;
});

describe("what a finding says", () => {
  const e = (node: string, name: string) => ({ node, nodeLabel: node, entry: "e", ref: 1, name, generation: 1 });
  it("names entries and reasons, never a value", () => {
    expect(tidyLine({ kind: "duplicate_value", match: "exact", entries: [e("a", "K"), e("b", "K")] })).toBe("a · K, b · K");
    expect(tidyLine({ kind: "duplicate_value", match: "probable", entries: [e("a", "K"), e("b", "K")] })).toMatch(/once spaces/);
    expect(tidyLine({ kind: "weak", entries: [e("a", "LOGIN")], fieldLabel: "password", reasons: ["short", "common_pattern"] })).toBe(
      "a · LOGIN · password: short, a common pattern",
    );
    expect(tidyLine({ kind: "mistyped", entries: [e("t", "S")], fieldLabel: "key", reason: "live_key_in_test" })).toBe("t · S · key: a live key in a test project");
    expect(tidyLine({ kind: "expired", entries: [e("a", "JWT")], expiresAt: 0, source: "jwt" })).toMatch(/the token’s own date/);
    expect(tidyLine({ kind: "stale", entries: [e("a", "OLD")], lastChanged: 0, basis: "rotated" })).toMatch(/last rotated/);
  });
  it("says what to do when the app does not apply it", () => {
    expect(tidyAdvice({ proposal: { action: "merge", op: null } })).toMatch(/aliases/);
    expect(tidyAdvice({ proposal: { action: "share", op: null } })).toMatch(/grant/);
    expect(tidyAdvice({ proposal: { action: "remove_copies", op: null, keep: { node: "atlas" } } })).toMatch(/atlas/);
    expect(TIDY_KINDS.map((k) => k.kind)).toEqual(["duplicate_value", "misfiled", "similar_names", "weak", "mistyped", "expired", "expiring", "stale"]);
  });
});

describe("Tidy up (vault.doctor_scan)", () => {
  it("is reachable from the Operations panel and Settings → Maintenance, and scans when it opens", async () => {
    const { logic, calls } = await booted();
    const row = logic.renderVals().opsRows.find((r: { name: string }) => r.name === "Tidy up");
    expect(row).toBeTruthy();
    row.run();
    expect(logic.state.overlay).toBe("tidy");
    await flush();
    const sent = calls.filter((c) => c.cmd === "vault_doctor_scan");
    expect(sent).toHaveLength(1);
    expect(sent[0].args).toEqual({});
    const v = logic.renderVals();
    expect(v.ovTidy).toBe(true);
    expect(v.tidySummaryShow).toBe(true);
    const kinds = v.tidyGroups.map((gr: { kind: string }) => gr.kind);
    expect(kinds.slice(0, 2)).toEqual(["duplicate_value", "misfiled"]);
    // Reopening a ready report does not scan again; Scan again does.
    logic.setState({ overlay: null });
    logic.renderVals().openTidy();
    await flush();
    expect(calls.filter((c) => c.cmd === "vault_doctor_scan")).toHaveLength(1);
    await logic.renderVals().tidyRescan();
    expect(calls.filter((c) => c.cmd === "vault_doctor_scan")).toHaveLength(2);
    // Nothing on screen is a value.
    expect(JSON.stringify(logic.renderVals().tidyGroups)).not.toMatch(/fixture-value/);
  });

  it("a move proposal opens the Move dialog with its project chosen, and after the move the scan runs again", async () => {
    const { logic, calls, notes } = await booted();
    logic.renderVals().openTidy();
    await flush();
    const dup = logic.renderVals().tidyGroups.find((gr: { kind: string }) => gr.kind === "duplicate_value");
    const moveRow = dup.rows.find((r: { moveShow: boolean }) => r.moveShow);
    expect(moveRow.moveLabel).toBe("Move to atlas");
    moveRow.move();
    expect(logic.state.dialog).toBe("move");
    expect(logic.state.moveForm).toMatchObject({ to: "atlas", origin: "tidy" });
    let v = logic.renderVals();
    expect(v.dlgMove).toBe(true);
    expect(v.mvTo).toBe("atlas");
    await v.saveMoveForm();
    await flush();
    const moved = calls.filter((c) => c.cmd === "entry_move");
    expect(moved).toHaveLength(1);
    expect(moved[0].args).toMatchObject({ to: "atlas" });
    expect(notes.at(-1)?.[0]).toBe("success");
    // The overlay stays, the dialog closed, and a second scan read what is left.
    expect(logic.state.dialog).toBe(null);
    expect(logic.state.overlay).toBe("tidy");
    expect(calls.filter((c) => c.cmd === "vault_doctor_scan")).toHaveLength(2);
    v = logic.renderVals();
    const after = v.tidyGroups.find((gr: { kind: string }) => gr.kind === "duplicate_value");
    expect(after.rows.some((r: { moveShow: boolean }) => r.moveShow)).toBe(false);
  });

  it("a misfiled entry in global offers its project", async () => {
    const { logic } = await booted();
    logic.renderVals().openTidy();
    await flush();
    const mis = logic.renderVals().tidyGroups.find((gr: { kind: string }) => gr.kind === "misfiled");
    expect(mis.rows).toHaveLength(1);
    expect(mis.rows[0].text).toBe("global · atlas-hook");
    expect(mis.rows[0].moveLabel).toBe("Move to atlas");
  });

  it("a refusal is said in the overlay and nothing else is shown", async () => {
    const { logic, failNext } = await booted();
    failNext.vault_doctor_scan = "rate_limited";
    logic.renderVals().openTidy();
    await flush();
    const v = logic.renderVals();
    expect(v.tidyErrShow).toBe(true);
    expect(v.tidyErr).toMatch(/already running/);
    expect(v.tidyGroups).toEqual([]);
  });

  it("a vault with nothing to tidy says so", async () => {
    const { logic, win } = await booted(false);
    const S = win.__brokerFixture.S;
    for (const k of Object.keys(S.entries)) for (const en of S.entries[k]) en.modified = Math.floor(Date.now() / 1000);
    for (const k of Object.keys(S.entries)) for (const en of S.entries[k]) en.rotatedAt = null;
    logic.renderVals().openTidy();
    await flush();
    const v = logic.renderVals();
    expect(v.tidyEmpty).toBe(true);
    // A locked node is said to be skipped.
    expect(v.tidySkipped.map((s: { text: string }) => s.text)).toContain("cobalt: not read (locked)");
  });
});

describe("the template", () => {
  it("the overlay is included, and the Operations row and Settings button open it", () => {
    expect(read("src/design/app.template.html")).toContain('<sc-include src="./screens/S22-tidy.html"></sc-include>');
    expect(read("src/design/screens/S12-settings.html")).toContain("{{openTidy}}");
    const ov = read("src/design/screens/S22-tidy.html");
    for (const b of ["{{tidyRescan}}", "{{tidyGroups}}", "{{r.move}}", "{{r.moveLabel}}", "{{closeOverlay}}"]) expect(ov).toContain(b);
  });
});
