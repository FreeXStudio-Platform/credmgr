// The supporter extras and the milestone ask (ADR-082): the pack opens only with its code, nothing is stored on a wrong one, the ask
// follows the table and nothing else, the stored objects are cleaned, and a release bundle carries neither the test hooks nor the test pack.
// (End to end, in a real page and under the production policy: tests/e2e/extras.spec.ts.)
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import Component from "../../src/design/logic/core.js";
import { packClean } from "../../src/design/logic/extras.js";
import { RELEASE_BANS } from "../../scripts/dc/release-bans.mjs";
import { TEST_CODE, TEST_PACK, seal } from "../fixtures/extras/seal-test-pack.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");

class FakeStorage {
  data = new Map<string, string>();
  getItem(k: string) { return this.data.has(k) ? this.data.get(k)! : null; }
  setItem(k: string, v: string) { this.data.set(k, String(v)); }
  removeItem(k: string) { this.data.delete(k); }
}

let store: FakeStorage;
let saved: unknown;
beforeEach(() => {
  saved = (globalThis as any).localStorage;
  store = new FakeStorage();
  Object.defineProperty(globalThis, "localStorage", { value: store, configurable: true, writable: true });
});
afterEach(() => Object.defineProperty(globalThis, "localStorage", { value: saved, configurable: true, writable: true }));

/** A logic instance with no React host (setState applies at once), a vault of `entries` entries and a fixed calendar day. */
function logic(entries = 0, today = "2026-03-10", clear = true): any {
  const l: any = new (Component as any)({ mode: "pro" });
  l.setState = (u: any, cb?: () => void) => { l.state = { ...l.state, ...(typeof u === "function" ? u(l.state) : u) }; cb?.(); };
  l.today = () => today;
  l.usageSet({ entries });
  l.state = { ...l.state, screen: "app" };
  Object.defineProperty(l, "model", { value: { status: "unlocked", view: { nodes: [], grants: [], entries: {} }, subscribe: () => () => {} }, configurable: true });
  if (clear) store.data.clear(); // setting the entry count is not storage: start every test with an empty profile
  return l;
}

describe("the milestone ask", () => {
  const TABLE: Array<[number, number, string | null]> = [
    [49, 30, null], // not enough entries, however long in use
    [60, 13, null], // enough entries, not enough days
    [50, 14, "m1"],
    [149, 44, "m1"], // m1 was not yet asked in this table row; see "only the highest" below for the jump
    [150, 45, "m2"],
    [299, 89, "m2"],
    [300, 90, "m3"],
    [5000, 4000, "m3"],
  ];
  for (const [entries, days, want] of TABLE) {
    it(`${entries} entries and ${days} days -> ${want ?? "no ask"}`, () => {
      const l = logic(entries);
      l.usageSet({ days, last: "2026-03-10" });
      expect(l.usagePending()?.id ?? null).toBe(want);
    });
  }

  it("asks once for the highest milestone and marks the lower ones passed (a jump from below 50 to 300)", () => {
    const l = logic(300);
    l.usageSet({ days: 90, last: "2026-03-10" });
    l.maybeAsk();
    expect(l.state.donateToastOpen).toBe(true);
    expect(l.state.donateMs).toBe("300 entries");
    expect(l.usageGet().asked).toEqual(["m1", "m2", "m3"]);
    expect(l.usageGet().lastAsk).toBe("2026-03-10");
  });

  it("never twice in a day, and each milestone only once", () => {
    const l = logic(50);
    l.usageSet({ days: 14, last: "2026-03-10" });
    l.maybeAsk();
    expect(l.state.donateToastOpen).toBe(true);
    l.setState({ donateToastOpen: false });
    l.maybeAsk(); // the same day
    expect(l.state.donateToastOpen).toBe(false);
    l.today = () => "2026-03-11"; // the next day: m1 is spent, m2 needs 150
    l.maybeAsk();
    expect(l.state.donateToastOpen).toBe(false);
    l.usageSet({ entries: 150, days: 45 });
    l.maybeAsk();
    expect(l.state.donateMs).toBe("150 entries");
  });

  it("never over a dialog, in a game, on the Lock screen or while the toast is already up", () => {
    for (const patch of [{ dialog: "help" }, { overlay: "games" }, { overlay: "settings" }, { screen: "lock" }, { donateToastOpen: true }]) {
      const l = logic(300);
      l.usageSet({ days: 90, last: "2026-03-10" });
      l.setState({ donateToastOpen: false, ...patch });
      const before = l.usageGet().asked.length;
      l.maybeAsk();
      expect(l.usageGet().asked.length, JSON.stringify(patch)).toBe(before); // nothing marked: the ask simply did not happen
    }
  });

  it("never after a supporter code and never after 'don't remind me'", () => {
    const a = logic(300);
    a.usageSet({ days: 90, last: "2026-03-10" });
    store.setItem("credmgr_donate_unlocked", "1");
    expect(a.usagePending()).toBeNull();
    store.removeItem("credmgr_donate_unlocked");
    expect(a.usagePending()).not.toBeNull();
    const u = a.usageGet();
    u.optout = true;
    a.usageSave(u);
    expect(a.usagePending()).toBeNull();
  });

  it("counts a calendar day once per day and stores no time", () => {
    const l = logic(0);
    l.usageSet({ entries: 0 });
    l.usageTick();
    l.usageTick();
    expect(l.usageGet().days).toBe(1);
    l.today = () => "2026-03-11";
    l.usageTick();
    expect(l.usageGet()).toMatchObject({ days: 2, last: "2026-03-11" });
    expect(store.getItem("credmgr_usage")).not.toMatch(/\d{2}:\d{2}/);
  });
});

describe("the sealed pack", () => {
  it("opens with the code however it is typed (case, spaces) and stores the key and the flag", async () => {
    for (const typed of [TEST_CODE, TEST_CODE.toLowerCase(), `  ${TEST_CODE.toLowerCase()}  `, TEST_CODE.replace("-", " - ")]) {
      store.data.clear();
      const l = logic();
      expect(await l.extrasUnlock(typed), JSON.stringify(typed)).toBe(true);
      expect(l.state.pack.shapes.hexagon).toEqual({ n: 6, rot: -90 });
      expect(store.getItem("credmgr_donate_unlocked")).toBe("1");
      expect(store.getItem("credmgr_extras_key")).toMatch(/^[A-Za-z0-9+/]{43}=$/); // a 256-bit key, base64
    }
  });

  it("a wrong, empty or whitespace code opens nothing and stores nothing", async () => {
    for (const typed of ["wrong-code", "", "   ", TEST_CODE + "x", "A".repeat(100000), null, undefined]) {
      const l = logic();
      expect(await l.extrasUnlock(typed as string), String(typed).slice(0, 20)).toBe(false);
      expect(l.state.pack).toBeNull();
      expect([...store.data.keys()]).toEqual([]);
    }
  });

  it("reopens from the stored key without the code, and a foreign or damaged key opens nothing", async () => {
    const first = logic();
    await first.extrasUnlock(TEST_CODE);
    const again = logic(0, "2026-03-10", false);
    await again.loadExtras();
    expect(again.state.pack).not.toBeNull();
    store.setItem("credmgr_extras_key", store.getItem("credmgr_extras_key")!.replace(/^./, (c) => (c === "A" ? "B" : "A")));
    const bad = logic(0, "2026-03-10", false);
    await bad.loadExtras();
    expect(bad.state.pack).toBeNull();
    store.setItem("credmgr_extras_key", "not base64 at all");
    const worse = logic(0, "2026-03-10", false);
    await worse.loadExtras();
    expect(worse.state.pack).toBeNull();
  });

  it("packLoad (the test hook) opens it for the session and stores nothing", async () => {
    const l = logic();
    expect(await l.packLoad(TEST_CODE)).toBe(true);
    expect(l.cosmOn()).toBe(true);
    expect([...store.data.keys()]).toEqual([]);
  });

  it("the sealed blob is real AES-GCM: a different code, or one flipped ciphertext bit, fails to decrypt", async () => {
    const other = JSON.parse(await seal("some-other-code"));
    const l = logic();
    l.extrasBlob = () => JSON.stringify(other);
    expect(await l.extrasUnlock(TEST_CODE)).toBe(false);
    expect(await l.extrasUnlock("some-other-code")).toBe(true);
    const flipped = { ...other, d: Buffer.from(Buffer.from(other.d, "base64").map((b, i) => (i === 3 ? b ^ 1 : b))).toString("base64") };
    l.extrasBlob = () => JSON.stringify(flipped);
    const m = logic();
    m.extrasBlob = l.extrasBlob;
    expect(await m.extrasUnlock("some-other-code")).toBe(false);
  });
});

describe("packClean (the pack is data, and wrong numbers never reach a painter)", () => {
  it("keeps the real tables", () => {
    expect(packClean(TEST_PACK)).toEqual(TEST_PACK);
  });
  it("clamps numbers, drops unknown keys and values, and survives junk", () => {
    const c: any = packClean({ shapes: { hexagon: { n: 1e9, rot: "x" }, evil: { n: 6 }, square: { half: 99, corner: -3 } }, global: { sig: "red", ash: "ash" }, link: { ash: "javascript:1", bone: "bone@0.5" }, dots: { cool: [-5, 999], mono: 0, warm: "x" }, backdrop: { dots: { k: "dots", step: 0 }, lines: { k: "eval", step: 40 } }, extra: { code: "alert(1)" } });
    expect(c.shapes.hexagon).toEqual({ n: 16, rot: -90 });
    expect(c.shapes.square).toEqual({ half: 1, corner: 0 });
    expect(c.shapes.evil).toBeUndefined();
    expect(c.global).toEqual({ ash: "ash" });
    expect(c.link).toEqual({ bone: "bone@0.5" });
    expect(c.dots).toEqual({ cool: [0, 360], mono: 0 });
    expect(c.backdrop).toEqual({ dots: { k: "dots", step: 16 } });
    expect(c.extra).toBeUndefined();
    for (const junk of [null, undefined, 5, "x", [], { shapes: 7 }]) expect(() => packClean(junk)).not.toThrow();
  });
});

describe("what is drawn", () => {
  it("is the default while the pack is sealed, whatever is stored", () => {
    store.setItem("credmgr_cosmetics", JSON.stringify({ shape: "hexagon", global: "sig", backdrop: "rings", badge: "stamp", flourish: "on", trail: "comet" }));
    const l = logic();
    l.loadCosmetics();
    expect(l.cosmEff()).toEqual(l.cosmDef());
  });
  it("shows the graph defaults under high contrast or greyscale proof and the motion defaults under reduced motion, but keeps the rest", async () => {
    const l = logic();
    await l.extrasUnlock(TEST_CODE);
    l.setCosm({ shape: "octagon", global: "sig", link: "ash", dots: "warm", backdrop: "dots", flourish: "on", trail: "comet", badge: "stamp", halo: true });
    expect(l.cosmEff()).toMatchObject({ shape: "octagon", backdrop: "dots", flourish: "on", trail: "comet", halo: true });
    l.setState({ contrastMode: "high" });
    expect(l.cosmEff()).toMatchObject({ shape: "circle", global: "bone", link: "default", dots: "spectrum", backdrop: "plain", badge: "stamp", flourish: "on" });
    l.setState({ contrastMode: "standard", motion: "reduced" });
    expect(l.cosmEff()).toMatchObject({ shape: "octagon", flourish: "off", trail: "standard", halo: false, badge: "stamp" });
  });
  it("a node shape sits inside the circle of radius r (nothing that reads r changes)", async () => {
    const l = logic();
    await l.extrasUnlock(TEST_CODE);
    for (const shape of ["hexagon", "square", "octagon", "diamond"]) {
      const pts: Array<[number, number]> = [];
      // a rounded square's farthest point is on its corner arc: the arc's centre is (half - corner) from the middle on both axes, plus the radius
      const ctx = { beginPath() {}, closePath() {}, arc() {}, moveTo: (x: number, y: number) => pts.push([x, y]), lineTo: (x: number, y: number) => pts.push([x, y]), rect: (x: number, y: number, w: number, h: number) => pts.push([x, y], [x + w, y + h]), roundRect: (x: number, y: number, w: number, _h: number, rr: number) => { const c = w / 2 - rr, e = 100 + c + rr * Math.SQRT1_2; pts.push([e, e]); } };
      l.shapePath(ctx, 100, 100, 20, shape);
      expect(pts.length, shape).toBeGreaterThan(0);
      for (const [x, y] of pts) expect(Math.hypot(x - 100, y - 100), `${shape} (${x},${y})`).toBeLessThanOrEqual(20 + 1e-9);
    }
  });
});

describe("a release bundle", () => {
  it("bans the test hooks and the test pack by name, and the source still has them to ban", () => {
    for (const needle of ["usageSet", "packLoad"]) {
      const ban = RELEASE_BANS.find((b: any) => b.needle === needle);
      expect(ban, needle).toBeTruthy();
      for (const f of ban!.where) expect(readFileSync(join(ROOT, f), "utf8")).toContain(needle);
    }
  });
  it("selects the real blob outside a test build: the test blob is behind the build-time constant", () => {
    const src = readFileSync(join(ROOT, "src/design/logic/extras.js"), "utf8");
    expect(src).toMatch(/const TEST_BLOB = TEST \? '/);
    expect(src).toMatch(/extrasBlob\(\) \{ return TEST \? TEST_BLOB : REAL_BLOB; \}/);
    expect(src).toMatch(/const devMethods = TEST \? \{/);
  });
});
