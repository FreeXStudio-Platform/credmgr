// ADR-157, the desktop half of ADR-156's quick wins 3 and 4: an entry's expiry chip and its Set / Change expiry dialog
// (entry.set_expiry), and the entry's History tab (entry.history).  The logic runs through the real bridge client against the
// fixture broker (tests/fixtures/broker/quick.js), with the shell's `invoke` wrapped so the command names and argument keys the real
// bridge sends are the ones asserted here.
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import Component from "../../src/design/logic/core.js";
import { actionText, expiryChip, parseDay, utcDay } from "../../src/design/logic/history.js";
import { brokerScript } from "../fixtures/broker/script.mjs";

const ROOT = resolve(__dirname, "../..");
const read = (rel: string) => readFileSync(resolve(ROOT, rel), "utf8");
const g = globalThis as unknown as { window?: any };
const DAY = 86400;

interface Call {
  cmd: string;
  args: Record<string, unknown>;
}

/** The fixture broker on a fake page, with every shell call recorded and `fail` able to refuse the next call of a command. */
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
  return { calls, failNext };
}

const flush = async (n = 6) => {
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

describe("dates: a calendar day in UTC, as the CLI reads --at", () => {
  it("parses YYYY-MM-DD to the start of that day in UTC and prints it back", () => {
    expect(parseDay("2026-12-31")).toBe(Date.UTC(2026, 11, 31) / 1000);
    expect(utcDay(parseDay("2026-12-31")!)).toBe("2026-12-31");
    expect(parseDay(" 1970-01-01 ")).toBe(0);
    expect(parseDay("9999-12-31")).toBe(Date.UTC(9999, 11, 31) / 1000);
  });
  it("refuses what is not a real calendar date", () => {
    for (const bad of ["", "2026-02-30", "2026-13-01", "26-01-01", "2026/01/01", "2026-1-1", "tomorrow", "1969-12-31"]) expect(parseDay(bad), bad).toBeNull();
  });
});

describe("the expiry chip", () => {
  const now = Date.UTC(2026, 10, 12, 15) / 1000; // 2026-11-12 15:00 UTC
  it("no expiry shows no chip", () => {
    expect(expiryChip(null, now)).toBeNull();
    expect(expiryChip(undefined, now)).toBeNull();
  });
  it("past is expired, within 30 days is soon, later is later, counted in whole UTC days", () => {
    expect(expiryChip(Date.UTC(2026, 10, 2) / 1000, now)).toEqual({ tone: "expired", text: "expired 2026-11-02 · 10 days ago" });
    expect(expiryChip(Date.UTC(2026, 10, 12) / 1000, now)).toEqual({ tone: "expired", text: "expired today · 2026-11-12" });
    expect(expiryChip(Date.UTC(2026, 10, 13) / 1000, now)).toEqual({ tone: "soon", text: "expires 2026-11-13 · in 1 day" });
    expect(expiryChip(Date.UTC(2026, 11, 12) / 1000, now)!.tone).toBe("soon");
    expect(expiryChip(Date.UTC(2026, 11, 13) / 1000, now)).toEqual({ tone: "later", text: "expires 2026-12-13" });
  });
});

describe("Set / Change expiry (entry.set_expiry)", () => {
  it("an entry with no expiry offers Set expiry and no chip", async () => {
    const { logic } = await openEntry();
    const v = logic.renderVals();
    expect(v.expiryBtnShow).toBe(true);
    expect(v.expiryChipShow).toBe(false);
    expect(v.expiryBtnLabel).toBe("Set expiry…");
  });

  it("saving a date sends the node's generation and the start of that UTC day, then the chip shows the stored date", async () => {
    const { logic, calls, notes } = await openEntry();
    const gen = logic.model.detail("atlas", "e-a1").generation;
    logic.renderVals().expiryOpen();
    expect(logic.state.dialog).toBe("expiry");
    let v = logic.renderVals();
    expect(v.dlgExpiry).toBe(true);
    expect(v.exSaveDisabled).toBe(true); // nothing typed yet
    expect(v.exClearShow).toBe(false); // nothing to remove
    v.onExDate({ target: { value: "2030-02-30" } });
    v = logic.renderVals();
    expect(v.exErrShow).toBe(true);
    expect(v.exSaveDisabled).toBe(true);
    v.onExDate({ target: { value: "2030-06-01" } });
    v = logic.renderVals();
    expect(v.exErrShow).toBe(false);
    expect(v.exSaveDisabled).toBe(false);
    await v.saveExpiryForm();
    await flush();
    const set = calls.filter((c) => c.cmd === "entry_set_expiry");
    expect(set).toHaveLength(1);
    expect(set[0].args).toEqual({ node: "atlas", entry: "e-a1", generation: gen, expiresAt: Date.UTC(2030, 5, 1) / 1000 });
    expect(logic.state.dialog).toBe(null);
    expect(notes.at(-1)).toEqual(["success", "“stripe-live” expires on 2030-06-01 (UTC)."]);
    v = logic.renderVals();
    expect(v.expiryChipShow).toBe(true);
    expect(v.expiryChipTone).toBe("later");
    expect(v.expiryChipText).toBe("expires 2030-06-01");
    expect(v.expiryBtnLabel).toBe("Change expiry…");
  });

  it("Remove expiry sends clear: true and no date, and the chip goes", async () => {
    const { logic, calls, notes } = await openEntry();
    logic.renderVals().expiryOpen();
    logic.renderVals().exIn90();
    await logic.renderVals().saveExpiryForm();
    await flush();
    logic.renderVals().expiryOpen();
    const v = logic.renderVals();
    expect(v.exClearShow).toBe(true);
    expect(v.exCurrent).toMatch(/^Now: \d{4}-\d{2}-\d{2} \(UTC\)\.$/);
    await v.clearExpiryForm();
    await flush();
    const set = calls.filter((c) => c.cmd === "entry_set_expiry");
    expect(set).toHaveLength(2);
    expect(set[1].args).toMatchObject({ node: "atlas", entry: "e-a1", clear: true });
    expect(set[1].args).not.toHaveProperty("expiresAt");
    expect(notes.at(-1)).toEqual(["success", "“stripe-live” no longer expires."]);
    expect(logic.renderVals().expiryChipShow).toBe(false);
  });

  it("the presets are today plus 30, 90 and 365 days", async () => {
    const { logic } = await openEntry();
    logic.renderVals().expiryOpen();
    const today = Math.floor(Date.now() / 1000);
    for (const [btn, days] of [["exIn30", 30], ["exIn90", 90], ["exIn365", 365]] as const) {
      logic.renderVals()[btn]();
      expect(logic.state.expiryForm.date).toBe(utcDay(today + days * DAY));
    }
  });

  it("a stale generation keeps the dialog open with the form, and a second Save goes through", async () => {
    const { logic, calls, failNext } = await openEntry();
    logic.renderVals().expiryOpen();
    logic.renderVals().onExDate({ target: { value: "2031-01-01" } });
    failNext.entry_set_expiry = "conflict";
    await logic.renderVals().saveExpiryForm();
    await flush();
    expect(logic.state.dialog).toBe("expiry");
    expect(logic.state.expiryForm.busy).toBe(false);
    expect(logic.state.expiryForm.date).toBe("2031-01-01");
    await logic.renderVals().saveExpiryForm();
    await flush();
    expect(calls.filter((c) => c.cmd === "entry_set_expiry")).toHaveLength(2);
    expect(logic.state.dialog).toBe(null);
  });

  it("an entry that is gone closes the dialog", async () => {
    const { logic, failNext } = await openEntry();
    logic.renderVals().expiryOpen();
    logic.renderVals().onExDate({ target: { value: "2031-01-01" } });
    failNext.entry_set_expiry = "not_found";
    await logic.renderVals().saveExpiryForm();
    await flush();
    expect(logic.state.dialog).toBe(null);
    expect(logic.state.expiryForm).toBe(null);
  });
});

describe("the History tab (entry.history)", () => {
  it("opens on Fields; History reads the trail once, with a limit, and shows it newest first in plain words, never a value", async () => {
    const { logic, calls } = await openEntry();
    let v = logic.renderVals();
    expect(v.entryTabsShow).toBe(true);
    expect(v.entryTabFields).toBe(true);
    expect(v.entryTabHistory).toBe(false);
    // make a record of our own: set an expiry
    v.expiryOpen();
    logic.renderVals().exIn30();
    await logic.renderVals().saveExpiryForm();
    await flush();
    logic.renderVals().entryTabToHistory();
    await flush();
    const hist = calls.filter((c) => c.cmd === "entry_history");
    expect(hist).toHaveLength(1);
    expect(hist[0].args).toEqual({ node: "atlas", entry: "e-a1", limit: 200 });
    v = logic.renderVals();
    expect(v.entryTabHistory).toBe(true);
    expect(v.entryTabFields).toBe(false);
    expect(v.entryTabHistorySel).toBe("true");
    expect(v.histShow).toBe(true);
    expect(v.histRows.length).toBeGreaterThan(0);
    expect(v.histRows[0]).toMatchObject({ what: "expiry changed", raw: "entry.set_expiry", who: "you", outcomeShow: false });
    expect(v.histTimes).toMatch(/expires \d{4}-\d{2}-\d{2} \(UTC\)$/);
    expect(JSON.stringify(v.histRows)).not.toMatch(/fixture-value/);
    // rendering again does not ask again
    logic.renderVals();
    await flush();
    expect(calls.filter((c) => c.cmd === "entry_history")).toHaveLength(1);
    // Refresh does
    v.histRefresh();
    await flush();
    expect(calls.filter((c) => c.cmd === "entry_history")).toHaveLength(2);
  });

  it("a change made while the tab is open reads the trail again", async () => {
    const { logic, calls } = await openEntry();
    logic.renderVals().entryTabToHistory();
    await flush();
    logic.renderVals().expiryOpen();
    logic.renderVals().exIn30();
    await logic.renderVals().saveExpiryForm();
    await flush();
    expect(calls.filter((c) => c.cmd === "entry_history")).toHaveLength(2);
    expect(logic.renderVals().histRows[0].raw).toBe("entry.set_expiry");
  });

  it("a refused read says so and offers a retry; it is not shown as an empty trail", async () => {
    const { logic, failNext, calls } = await openEntry();
    failNext.entry_history = "capability_not_held";
    logic.renderVals().entryTabToHistory();
    await flush();
    let v = logic.renderVals();
    expect(v.histFailed).toBe(true);
    expect(v.histShow).toBe(false);
    expect(v.histEmpty).toBe(false);
    expect(v.histFailedText).toBe("This login may not read this entry’s history.");
    v.histRetry();
    await flush();
    v = logic.renderVals();
    expect(v.histFailed).toBe(false);
    expect(v.histShow).toBe(true);
    expect(calls.filter((c) => c.cmd === "entry_history")).toHaveLength(2);
  });

  it("the tab belongs to the entry: another entry opens on Fields", async () => {
    const { logic } = await openEntry();
    logic.renderVals().entryTabToHistory();
    await flush();
    logic.state = { ...logic.state, openEntry: "e-a2" };
    const v = logic.renderVals();
    expect(v.entryTabFields).toBe(true);
    expect(v.entryTabHistory).toBe(false);
  });

  it("audit actions read as plain words; one the app does not know is shown as the broker named it", () => {
    expect(actionText("entry.reveal")).toBe("revealed");
    expect(actionText("entry.something_new")).toBe("entry.something_new");
  });
});

describe("the template", () => {
  it("the entry detail carries the chip, the tabs and the History panel, and the dialog is included", () => {
    const s4 = read("src/design/screens/S4-inspector.html");
    for (const b of ["{{expiryChipText}}", "{{expiryOpen}}", "{{entryTabToHistory}}", "{{histRows}}", "{{histRetry}}"]) expect(s4).toContain(b);
    expect(read("src/design/app.template.html")).toContain('<sc-include src="./screens/dlg-expiry.html"></sc-include>');
    const dlg = read("src/design/screens/dlg-expiry.html");
    for (const b of ["{{saveExpiryForm}}", "{{clearExpiryForm}}", "{{exDate}}"]) expect(dlg).toContain(b);
  });
});
