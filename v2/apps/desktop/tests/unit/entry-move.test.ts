// ADR-158: the entry inspector's "Move to project…" and its dialog (entry.move).  The logic runs through the real bridge client
// against the fixture broker (tests/fixtures/broker/quick.js), with the shell's `invoke` wrapped so the command name and argument keys
// the real bridge sends are the ones asserted here.
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import Component from "../../src/design/logic/core.js";
import { movedText, moveTargets } from "../../src/design/logic/move.js";
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

/** A logic instance with entry `e-a1` (stripe-live, node atlas) open and its detail read. */
async function openEntry() {
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
  // No canvas here: the graph's own drawing is not what these tests are about.
  logic.buildEntryNodes = () => {};
  logic.renderGraph = () => {};
  await logic.model.boot();
  logic.state = { ...logic.state, screen: "app", selected: "atlas", openEntry: "e-a1", dialog: null };
  logic.renderVals();
  await flush();
  expect(logic.model.detail("atlas", "e-a1")).toBeTruthy();
  return { logic, notes, ...fx };
}

afterEach(() => {
  delete g.window;
});

describe("where an entry can go", () => {
  it("every other node that is not locked", () => {
    const nodes = [
      { id: "global", label: "global", gate: { locked: false } },
      { id: "atlas", label: "Atlas", gate: { locked: false } },
      { id: "cobalt", label: "Cobalt", gate: { locked: true } },
      { id: "beacon", label: "Beacon", gate: { locked: false } },
    ];
    expect(moveTargets(nodes, "atlas")).toEqual([
      { id: "global", label: "global" },
      { id: "beacon", label: "Beacon" },
    ]);
    expect(moveTargets([], "atlas")).toEqual([]);
  });

  it("the message says what did not travel, from the broker's own counts", () => {
    expect(movedText("k", "Beacon", { grantsRevoked: [], historyDropped: 0 })).toBe("“k” moved to Beacon.");
    expect(movedText("k", "Beacon", { grantsRevoked: ["g1"], historyDropped: 1 })).toBe(
      "“k” moved to Beacon. 1 grant on it was revoked. 1 earlier value kept for Undo was dropped.",
    );
    expect(movedText("k", "Beacon", { grantsRevoked: ["g1", "g2"], historyDropped: 3 })).toBe(
      "“k” moved to Beacon. 2 grants on it were revoked. 3 earlier values kept for Undo were dropped.",
    );
  });
});

describe("Move to project… (entry.move)", () => {
  it("is offered on an open entry, and the dialog lists the other open nodes, never the locked one or its own", async () => {
    const { logic } = await openEntry();
    let v = logic.renderVals();
    expect(v.moveBtnShow).toBe(true);
    expect(v.dlgMove).toBe(false);
    v.moveOpen();
    expect(logic.state.dialog).toBe("move");
    v = logic.renderVals();
    expect(v.dlgMove).toBe(true);
    expect(v.mvEntry).toBe("stripe-live");
    const ids = v.mvOpts.map((o: { id: string }) => o.id);
    expect(ids).not.toContain("atlas");
    expect(ids).not.toContain("cobalt"); // locked
    expect(ids).toContain("beacon");
    expect(v.mvTo).toBe(ids[0]);
    expect(v.mvSaveDisabled).toBe(false);
  });

  it("Move sends the source's generation and the chosen node, then the inspector follows the entry there", async () => {
    const { logic, calls, notes } = await openEntry();
    const gen = logic.model.generation.atlas;
    logic.renderVals().moveOpen();
    logic.renderVals().onMvTo({ target: { value: "beacon" } });
    await logic.renderVals().saveMoveForm();
    await flush();
    const sent = calls.filter((c) => c.cmd === "entry_move");
    expect(sent).toHaveLength(1);
    expect(sent[0].args).toEqual({ node: "atlas", entry: "e-a1", to: "beacon", generation: gen });
    expect(logic.state.dialog).toBe(null);
    expect(logic.state.moveForm).toBe(null);
    expect(logic.state.selected).toBe("beacon");
    expect(logic.state.openEntry).toBe("e-a1");
    expect(notes.at(-1)?.[0]).toBe("success");
    expect(notes.at(-1)?.[1]).toMatch(/^“stripe-live” moved to /);
    // Both lists were read again: the entry is in beacon and no longer in atlas.
    const lists = logic.model.view.entries;
    expect((lists.atlas || []).some((e: { id: string }) => e.id === "e-a1")).toBe(false);
    expect((lists.beacon || []).some((e: { id: string }) => e.id === "e-a1")).toBe(true);
    // Nothing the page sent or got back carries a value.
    expect(JSON.stringify(sent)).not.toMatch(/"value"/);
  });

  it("a name the destination already uses keeps the dialog open and says so; nothing moved", async () => {
    const { logic, failNext, calls } = await openEntry();
    logic.renderVals().moveOpen();
    logic.renderVals().onMvTo({ target: { value: "beacon" } });
    failNext.entry_move = "entry_exists";
    await logic.renderVals().saveMoveForm();
    await flush();
    expect(calls.filter((c) => c.cmd === "entry_move")).toHaveLength(1);
    expect(logic.state.dialog).toBe("move");
    expect(logic.state.moveForm.busy).toBe(false);
    const v = logic.renderVals();
    expect(v.mvErrShow).toBe(true);
    expect(v.mvErr).toMatch(/already has an entry called “stripe-live”/);
    expect(v.mvErr).toMatch(/Nothing was moved\.$/);
    expect(logic.state.selected).toBe("atlas");
  });

  it("a stale generation keeps the dialog for a retry, and a second Move goes through", async () => {
    const { logic, failNext, calls } = await openEntry();
    logic.renderVals().moveOpen();
    logic.renderVals().onMvTo({ target: { value: "beacon" } });
    failNext.entry_move = "conflict";
    await logic.renderVals().saveMoveForm();
    await flush();
    expect(logic.state.dialog).toBe("move");
    expect(logic.state.moveForm.to).toBe("beacon");
    await logic.renderVals().saveMoveForm();
    await flush();
    expect(calls.filter((c) => c.cmd === "entry_move")).toHaveLength(2);
    expect(logic.state.dialog).toBe(null);
    expect(logic.state.selected).toBe("beacon");
  });

  it("an entry that is gone closes the dialog", async () => {
    const { logic, failNext } = await openEntry();
    logic.renderVals().moveOpen();
    failNext.entry_move = "not_found";
    await logic.renderVals().saveMoveForm();
    await flush();
    expect(logic.state.dialog).toBe(null);
    expect(logic.state.moveForm).toBe(null);
  });

  it("Cancel sends nothing", async () => {
    const { logic, calls } = await openEntry();
    logic.renderVals().moveOpen();
    logic.renderVals().cancelMoveDlg();
    expect(logic.state.dialog).toBe(null);
    expect(calls.filter((c) => c.cmd === "entry_move")).toHaveLength(0);
  });

  it("the fixture broker revokes a grant on the moved entry and keeps the others", async () => {
    const { logic, win } = await openEntry();
    const S = win.__brokerFixture.S;
    S.grants.push({ id: "g-entry", from: "beacon", to: { kind: "entry", nodeId: "atlas", entryId: "e-a1" }, direction: "one-way", scope: ["read"], expiresAt: null, reason: "t" });
    logic.renderVals().moveOpen();
    logic.renderVals().onMvTo({ target: { value: "global" } });
    await logic.renderVals().saveMoveForm();
    await flush();
    expect(S.grants.map((x: { id: string }) => x.id)).toEqual(["g-f1"]);
  });
});

describe("the template", () => {
  it("the entry detail carries the control, and the dialog is included", () => {
    expect(read("src/design/screens/S4-inspector.html")).toContain("{{moveOpen}}");
    expect(read("src/design/app.template.html")).toContain('<sc-include src="./screens/dlg-move.html"></sc-include>');
    const dlg = read("src/design/screens/dlg-move.html");
    for (const b of ["{{saveMoveForm}}", "{{cancelMoveDlg}}", "{{mvOpts}}", "{{onMvTo}}"]) expect(dlg).toContain(b);
  });
});
