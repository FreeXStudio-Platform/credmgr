// Decision D10: nothing that names a vault object is written to the webview's local storage in clear.
// pstore.js carries its own SHA-256 (graph positions are read synchronously while the graph is built, so the async
// Web Crypto API cannot be used), which makes it a piece of crypto code that must be proven against the platform's.
import { createHash } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import Component from "../../src/design/logic/core.js";
import { hid, sha256Hex } from "../../src/design/logic/pstore.js";
import { savePrefs } from "../../src/vault/prefs";
import { TEST_CODE } from "../fixtures/extras/seal-test-pack.mjs";

const ref = (text: string) => createHash("sha256").update(text, "utf8").digest("hex");

describe("sha256Hex", () => {
  // 55/56 and 63/64/65 straddle the padding boundaries of the 64-byte block; 119/120 the next.
  for (const n of [0, 1, 3, 55, 56, 57, 63, 64, 65, 119, 120, 121, 1000, 4096]) {
    it(`matches the platform for ${n} bytes`, () => {
      const text = "a".repeat(n);
      expect(sha256Hex(text)).toBe(ref(text));
    });
  }

  it("matches the platform for multi-byte UTF-8", () => {
    for (const text of ["", "abc", "ключ", "密钥 – ключ – κλειδί", "emoji \u{1F511} and a lone surrogate-free tail"]) {
      expect(sha256Hex(text)).toBe(ref(text));
    }
  });

  it("matches the published FIPS 180-4 test vectors", () => {
    expect(sha256Hex("abc")).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    expect(sha256Hex("")).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    expect(sha256Hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")).toBe("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
  });
});

describe("hid", () => {
  it("is 16 lower-case hex characters, deterministic, and never contains the id", () => {
    const k = hid("n", "payments-prod");
    expect(k).toMatch(/^[0-9a-f]{16}$/);
    expect(hid("n", "payments-prod")).toBe(k);
    expect(k.includes("payments")).toBe(false);
  });

  it("separates node ids from entry ids and one id from another", () => {
    expect(hid("n", "x")).not.toBe(hid("e", "x"));
    expect(hid("n", "x")).not.toBe(hid("n", "y"));
  });
});

class FakeStorage {
  data = new Map<string, string>();
  getItem(k: string) {
    return this.data.has(k) ? this.data.get(k)! : null;
  }
  setItem(k: string, v: string) {
    this.data.set(k, String(v));
  }
  removeItem(k: string) {
    this.data.delete(k);
  }
}

/** A logic instance with no React host: setState applies at once, the way the host would. */
function unmounted(): any {
  const logic: any = new (Component as any)({ mode: "pro" });
  logic.setState = (u: any, cb?: () => void) => {
    logic.state = { ...logic.state, ...(typeof u === "function" ? u(logic.state) : u) };
    cb?.();
  };
  return logic;
}

describe("what the app writes to local storage", () => {
  const DOCUMENTED = [
    "credmgr_gposV", "credmgr_gpos", "credmgr_gposEntry", "credmgr_cosmetics", "credmgr_prefs", "credpong_best", "credpong_level",
    "credmgr_donate_unlocked", "credmgr_extras_key", "credmgr_usage", "credmgr_keys", // ADR-082: flags, a derived key, calendar days; never an id or a name
  ];
  let store: FakeStorage;
  let saved: unknown;

  beforeEach(() => {
    saved = (globalThis as any).localStorage;
    store = new FakeStorage();
    Object.defineProperty(globalThis, "localStorage", { value: store, configurable: true, writable: true });
  });
  afterEach(() => {
    Object.defineProperty(globalThis, "localStorage", { value: saved, configurable: true, writable: true });
  });

  it("writes only documented keys, with no node or entry id in any key or value", async () => {
    const logic: any = unmounted();
    const nodeIds = ["linux", "payments-prod", "__orphan"];
    const entryIds = ["lx-1", "entry-secret-name"];
    logic.gpos = { linux: [10, 20], "payments-prod": [30, 40], __orphan: [50, 60] };
    logic.gposEntry = { "lx-1": [1, 2], "entry-secret-name": [3, 4] };

    logic.loadPositions(); // an unversioned profile: stamps the layout version
    logic.persistPositions();
    expect(await logic.extrasUnlock(` ${TEST_CODE.toLowerCase()} `)).toBe(true); // opens the pack: stores the derived key and the flag
    logic.setCosm({ halo: true, shape: "hexagon" });
    logic.usageSet({ days: 3 });
    logic.usageTick(); // one more calendar day: the dates and flags credmgr_usage keeps
    logic.rvExtras(logic.rvBase()).toggleSingleKeys(); // single-key shortcuts off: credmgr_keys = "off"
    savePrefs({ theme: "light", autoLockMins: 5 }); // the settings screen writes through the same function (see wp-d.test.ts)
    logic.cpSaveBest(120);
    logic.cpSaveLevel(3);

    const keys = [...store.data.keys()].sort();
    expect(keys).toEqual([...DOCUMENTED].sort());
    for (const [k, v] of store.data) {
      for (const id of [...nodeIds, ...entryIds]) {
        expect(k.includes(id), `key ${k} contains ${id}`).toBe(false);
        expect(v.includes(id), `value of ${k} contains ${id}`).toBe(false);
      }
    }
  });

  it("credmgr_usage holds calendar days and flags only, and credmgr_cosmetics only option names", async () => {
    const logic: any = unmounted();
    await logic.model.boot();
    logic.usageSet({ days: 49 });
    logic.usageTick();
    const u = JSON.parse(store.getItem("credmgr_usage")!);
    expect(Object.keys(u).sort()).toEqual(["asked", "days", "last", "lastAsk", "marks", "optout", "v"]);
    expect(u.last).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    for (const d of Object.values(u.marks)) expect(d).toMatch(/^\d{4}-\d{2}-\d{2}$/); // the day a milestone was first reached, never a name or a count
    // a junk object in storage is cleaned, not trusted
    store.setItem("credmgr_usage", JSON.stringify({ days: "x", last: "not a date", asked: ["m9", "m1"], optout: 1, marks: { proj1: "payments-prod", e10: "2026-10-01", other: "2026-10-01" } }));
    expect(logic.usageGet()).toMatchObject({ days: 0, last: "", asked: ["m1"], optout: true, marks: { e10: "2026-10-01" } });
    store.setItem("credmgr_cosmetics", JSON.stringify({ shape: "hexagon", mark: "<script>", halo: "yes", extra: "payments-prod", ring: true }));
    logic.loadCosmetics();
    expect(logic.state.cosm).toEqual({ mark: "keep", glyph: "classic", halo: true, ring: true, shape: "hexagon", global: "bone", link: "default", dots: "spectrum", backdrop: "plain", badge: "ring", icon: "keep", flourish: "off", trail: "standard" });
  });

  // Saved positions can only be matched to nodes the model knows, so each instance boots its model first.
  async function booted() {
    const logic: any = new (Component as any)({ mode: "pro" });
    await logic.model.boot();
    return logic;
  }

  it("restores positions saved under the hashed keys, and drops a legacy profile keyed by plain ids", async () => {
    const first: any = await booted();
    first.gpos = { linux: [11, 22] };
    first.loadPositions();
    first.persistPositions();

    const second: any = await booted();
    second.gpos = {};
    second.loadPositions();
    expect(second.gpos.linux).toEqual([11, 22]);

    store.setItem("credmgr_gposV", "2");
    store.setItem("credmgr_gpos", JSON.stringify({ linux: [1, 1] }));
    const third: any = await booted();
    third.gpos = {};
    third.loadPositions();
    expect(store.getItem("credmgr_gpos")).toBeNull();
    expect(third.gpos.linux).toBeUndefined();
  });
});
