// rc.2 §1 item 1: Rotate…, Remove… and Undo-remove on an entry (entry.rotate, entry.remove, entry.restore).  The logic runs through the
// real bridge client against the fixture broker (tests/fixtures/broker/write.js), with the shell's `invoke` wrapped so the command name and
// argument keys the real bridge sends are the ones asserted here.
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import Component from "../../src/design/logic/core.js";
import { recentlyRemoved, REMOVE_WINDOW_DAYS, removeText, rotateFields } from "../../src/design/logic/lifecycle.js";
import { brokerScript } from "../fixtures/broker/script.mjs";

const ROOT = resolve(__dirname, "../..");
const read = (rel: string) => readFileSync(resolve(ROOT, rel), "utf8");
const g = globalThis as unknown as { window?: any };
const NEW_VALUE = "fixture-value-rotated-7c1e";

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

/** A logic instance with entry `entry` of node atlas open and its detail read (e-a1 stripe-live: one field; e-a2 pg-main: five). */
async function openEntry(entry = "e-a2") {
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
  await logic.model.boot();
  logic.state = { ...logic.state, screen: "app", selected: "atlas", openEntry: entry, dialog: null };
  logic.renderVals();
  await flush();
  expect(logic.model.detail("atlas", entry)).toBeTruthy();
  return { logic, notes, ...fx };
}

afterEach(() => {
  delete g.window;
});

describe("pure helpers", () => {
  it("the fields a rotation can change: hidden ones first, each named as the inspector names it", () => {
    const d = { fields: [{ id: "f1", label: "host", masked: false }, { id: "f2", label: "password", masked: true }, { id: "f3", label: "", masked: true }] };
    expect(rotateFields(d)).toEqual([
      { id: "f2", label: "password", masked: true },
      { id: "f3", label: "field 3", masked: true },
      { id: "f1", label: "host", masked: false },
    ]);
    expect(rotateFields(undefined)).toEqual([]);
  });

  it("the Remove dialog says what happens at once and for how long it can be undone", () => {
    const t = removeText("stripe-live", "Atlas");
    expect(t).toContain("“stripe-live” leaves Atlas at once");
    expect(t).toContain(`kept, sealed, for ${REMOVE_WINDOW_DAYS} days`);
    expect(t).toContain("Undo brings it back");
    expect(t).toContain("deleted for good");
  });

  it("removed in the last seven days: from audit rows, newest first, leaving out what was brought back or is past the window", () => {
    const now = 1_800_000_000;
    const rows = [
      { id: "a5", timestamp: now - 100, actor: "human", action: "entry.restore", node: "atlas", entry: "e-b", decision: "allow" },
      { id: "a4", timestamp: now - 200, actor: "human", action: "entry.remove", node: "atlas", entry: "e-a", decision: "allow" },
      { id: "a3", timestamp: now - 300, actor: "human", action: "entry.remove", node: "atlas", entry: "e-b", decision: "allow" },
      { id: "a2", timestamp: now - 400, actor: "human", action: "entry.remove", node: "atlas", entry: "e-d", decision: "deny" },
      { id: "a1", timestamp: now - 8 * 86400, actor: "human", action: "entry.remove", node: "atlas", entry: "e-c", decision: "allow" },
    ];
    expect(recentlyRemoved(rows, now)).toEqual([{ node: "atlas", entry: "e-a", removedAt: now - 200, daysLeft: 7 }]);
    expect(recentlyRemoved(null, now)).toEqual([]);
  });
});

describe("Rotate… (entry.rotate)", () => {
  it("is offered on an open entry; the dialog lists its fields, the hidden one first, and needs a value", async () => {
    const { logic } = await openEntry();
    let v = logic.renderVals();
    expect(v.rotateBtnShow).toBe(true);
    v.rotateOpen();
    v = logic.renderVals();
    expect(v.dlgRotate).toBe(true);
    expect(v.rtEntry).toBe("pg-main");
    expect(v.rtFieldPick).toBe(true);
    expect(v.rtField).toBe("f_00a20004"); // the password: pg-main's one hidden field
    expect(v.rtSaveDisabled).toBe(true);
    v.onRtValue({ target: { value: NEW_VALUE } });
    expect(logic.renderVals().rtSaveDisabled).toBe(false);
  });

  it("Rotate sends one entry_rotate with the field, the value and the node's generation, offers Undo, and keeps no value", async () => {
    const { logic, calls, notes } = await openEntry();
    logic._mounted = true; // Undo is offered only to a mounted window (fields.js offerUndo)
    const gen = logic.model.generation.atlas;
    logic.renderVals().rotateOpen();
    logic.renderVals().onRtValue({ target: { value: NEW_VALUE } });
    await logic.renderVals().saveRotateForm();
    await flush();
    const sent = calls.filter((c) => c.cmd === "entry_rotate");
    expect(sent).toEqual([{ cmd: "entry_rotate", args: { node: "atlas", entry: "e-a2", value: NEW_VALUE, generation: gen, field: "f_00a20004" } }]);
    expect(logic.state.dialog).toBe(null);
    expect(logic.state.rotateForm).toBe(null);
    expect(notes.at(-1)).toEqual(["success", "“pg-main” rotated. The previous value is kept as history; Undo puts it back."]);
    const v = logic.renderVals();
    expect(v.undoShow).toBe(true);
    expect(v.undoText).toBe("rotate");
    expect(JSON.stringify(logic.state)).not.toContain(NEW_VALUE);
    expect(JSON.stringify(logic.model.view)).not.toContain(NEW_VALUE);
    // Undo is entry.undo with the rotation's own audit id, at the node's current generation.
    await v.undoField();
    await flush();
    const undo = calls.filter((c) => c.cmd === "entry_undo");
    expect(undo).toHaveLength(1);
    expect(undo[0].args.node).toBe("atlas");
    expect(undo[0].args.generation).toBe(logic.model.generation.atlas - 1);
  });

  it("a one-field entry names its field and sends its id; Generate fills a masked value made by the broker", async () => {
    const { logic, calls } = await openEntry("e-a1");
    logic.renderVals().rotateOpen();
    let v = logic.renderVals();
    expect(v.rtFieldPick).toBe(false);
    expect(v.rtFieldOneShow).toBe(true);
    await v.rtGenerate();
    await flush();
    v = logic.renderVals();
    expect(calls.filter((c) => c.cmd === "util_generate")).toHaveLength(1);
    expect(v.rtGenOn).toBe(true);
    expect(v.rtValue).toMatch(/^•+$/);
    await v.saveRotateForm();
    await flush();
    const sent = calls.filter((c) => c.cmd === "entry_rotate");
    expect(sent).toHaveLength(1);
    expect(sent[0].args.field).toBe("f_00000000");
    expect(String(sent[0].args.value)).toMatch(/^fixture-generated-/);
  });

  it("a stale generation keeps the dialog for a retry; Cancel drops the typed value", async () => {
    const { logic, failNext, calls } = await openEntry();
    logic.renderVals().rotateOpen();
    logic.renderVals().onRtValue({ target: { value: NEW_VALUE } });
    failNext.entry_rotate = "conflict";
    await logic.renderVals().saveRotateForm();
    await flush();
    expect(logic.state.dialog).toBe("rotate");
    expect(logic.state.rotateForm.busy).toBe(false);
    logic.renderVals().cancelRotateDlg();
    expect(logic.state.rotateForm).toBe(null);
    expect(calls.filter((c) => c.cmd === "entry_rotate")).toHaveLength(1);
  });
});

describe("Remove… (entry.remove) and Undo (entry.restore)", () => {
  it("Remove asks first, then sends one entry_remove, closes the entry and offers Undo in the list", async () => {
    const { logic, calls, notes } = await openEntry("e-a1");
    const gen = logic.model.generation.atlas;
    let v = logic.renderVals();
    expect(v.removeBtnShow).toBe(true);
    v.removeOpen();
    v = logic.renderVals();
    expect(v.dlgRemoveEntry).toBe(true);
    expect(v.rmText).toContain("kept, sealed, for 7 days");
    expect(calls.filter((c) => c.cmd === "entry_remove")).toHaveLength(0); // opening the dialog sends nothing
    await v.saveRemoveForm();
    await flush();
    expect(calls.filter((c) => c.cmd === "entry_remove")).toEqual([{ cmd: "entry_remove", args: { node: "atlas", entry: "e-a1", generation: gen } }]);
    expect(logic.state.openEntry).toBe(null);
    expect(notes.at(-1)?.[1]).toBe("“stripe-live” removed. It is kept for 7 days; Undo in the list brings it back.");
    expect((logic.model.view.entries.atlas || []).some((e: { id: string }) => e.id === "e-a1")).toBe(false);
    v = logic.renderVals();
    expect(v.removedBarShow).toBe(true);
    expect(v.removedBarText).toBe("“stripe-live” was removed. It is kept for 7 days.");
    await v.removedUndo();
    await flush();
    const restore = calls.filter((c) => c.cmd === "entry_restore");
    expect(restore).toEqual([{ cmd: "entry_restore", args: { node: "atlas", entry: "e-a1", generation: gen + 1 } }]);
    expect(logic.state.removedUndo).toBe(null);
    expect(logic.state.openEntry).toBe("e-a1");
    expect(notes.at(-1)).toEqual(["success", "“stripe-live” is back."]);
    expect((logic.model.view.entries.atlas || []).some((e: { id: string }) => e.id === "e-a1")).toBe(true);
  });

  it("when another entry took the name, Undo says so and Restore as a copy sends keep-both", async () => {
    const { logic, calls, notes, win } = await openEntry("e-a1");
    logic.renderVals().removeOpen();
    await logic.renderVals().saveRemoveForm();
    await flush();
    // an entry called stripe-live appears in the meantime (the fixture's own create), and the list is read again
    win.__brokerFixture.handlers.entry_create({ node: "atlas", name: "stripe-live", value: "fixture-value-new" });
    await logic.model.refresh({ nodes: ["atlas"] });
    await logic.renderVals().removedUndo();
    await flush();
    expect(notes.at(-1)?.[0]).toBe("warn");
    let v = logic.renderVals();
    expect(v.removedCopyShow).toBe(true);
    await v.removedCopy();
    await flush();
    const restore = calls.filter((c) => c.cmd === "entry_restore");
    expect(restore).toHaveLength(2);
    expect(restore[1].args.mode).toBe("keep-both");
    expect(notes.at(-1)).toEqual(["success", "Restored as “stripe-live old”."]);
    v = logic.renderVals();
    expect(v.removedBarShow).toBe(false);
  });

  it("a stale generation keeps the Remove dialog; Cancel sends nothing", async () => {
    const { logic, failNext, calls } = await openEntry("e-a1");
    logic.renderVals().removeOpen();
    failNext.entry_remove = "conflict";
    await logic.renderVals().saveRemoveForm();
    await flush();
    expect(logic.state.dialog).toBe("removeEntry");
    logic.renderVals().cancelRemoveDlg();
    expect(logic.state.dialog).toBe(null);
    expect(calls.filter((c) => c.cmd === "entry_remove")).toHaveLength(1);
  });

  it("the audit view lists a removal of the last seven days with Restore", async () => {
    const { logic, calls } = await openEntry("e-a1");
    logic.renderVals().removeOpen();
    await logic.renderVals().saveRemoveForm();
    await flush();
    logic.setState({ removedUndo: null, overlay: "settings", setSection: "audit" });
    await logic.loadAudit();
    await flush();
    let v = logic.renderVals();
    expect(v.auditRemovedShow).toBe(true);
    expect(v.auditRemoved).toHaveLength(1);
    expect(v.auditRemoved[0].left).toBe("7 days left");
    await v.auditRemoved[0].restore();
    await flush();
    expect(calls.filter((c) => c.cmd === "entry_restore")).toHaveLength(1);
    v = logic.renderVals();
    expect(v.auditRemovedShow).toBe(false); // read again: the restore now follows the removal
  });
});

describe("the template", () => {
  it("the entry detail carries both controls, the list the Undo bar, and the dialogs are included", () => {
    const insp = read("src/design/screens/S4-inspector.html");
    for (const b of ["{{rotateOpen}}", "{{removeOpen}}", "{{removedUndo}}", "{{removedCopy}}"]) expect(insp).toContain(b);
    expect(read("src/design/app.template.html")).toContain('<sc-include src="./screens/dlg-lifecycle.html"></sc-include>');
    const dlg = read("src/design/screens/dlg-lifecycle.html");
    for (const b of ["{{saveRotateForm}}", "{{rtGenerate}}", "{{saveRemoveForm}}", "{{rmText}}"]) expect(dlg).toContain(b);
    expect(read("src/design/screens/S12-settings.html")).toContain("{{auditRemoved}}");
  });
});
