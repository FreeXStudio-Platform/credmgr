// The switchboard glue (ADR-155): the app's preferences are the broker's `app.*` settings, read after an unlock (the broker wins),
// written when the person changes one in the window, and agents' waiting requests are listed and decided.  Each step is one bridge
// call; nothing is called at all without the shell.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../src/lib/bridge", () => ({
  settingsList: vi.fn(),
  settingsGet: vi.fn(),
  settingsSet: vi.fn(),
  settingsRequestList: vi.fn(),
  settingsRequestDecide: vi.fn(),
  isBridgeError: (e: unknown) => typeof e === "object" && e !== null && "code" in e && "source" in e && "message" in e,
}));

import * as bridge from "../../src/lib/bridge";
import type { SettingView } from "../../src/lib/bridge";
import * as sb from "../../src/vault/actions/switchboard";
import { switchboard as sbFromIndex } from "../../src/vault/index";
import { defaultPrefs, PREF_KEYS } from "../../src/vault/prefs";
import { switchboardMethods } from "../../src/design/logic/switchboard.js";

const b = bridge as unknown as Record<string, ReturnType<typeof vi.fn>>;
const g = globalThis as unknown as { window?: unknown; localStorage?: unknown };

/** What `settings.list` says about one app preference (only the keys the glue reads matter). */
function view(key: string, value: unknown, def: unknown = (defaultPrefs() as unknown as Record<string, unknown>)[key]): SettingView {
  return { id: `app.${key}`, scope: "vault", group: "g", title: key, purpose: "p", ui: "u", stored: "s", values: "v", default: def, value, risk: "cosmetic", you: "direct" };
}
function listing(values: Record<string, unknown> = {}) {
  return { caller: "owner", node: null, note: "", kb: "", settings: PREF_KEYS.map((k) => view(k, k in values ? values[k] : (defaultPrefs() as unknown as Record<string, unknown>)[k])) };
}

beforeEach(() => {
  for (const fn of Object.values(b)) if (typeof fn?.mockReset === "function") fn.mockReset();
  g.window = { __TAURI_INTERNALS__: {} };
});
afterEach(() => {
  delete g.window;
});

describe("ids", () => {
  it("maps every preference to app.<key> and back, and nothing else", () => {
    for (const k of PREF_KEYS) expect(sb.prefKeyOf(sb.settingId(k))).toBe(k);
    expect(sb.prefKeyOf("app.nope")).toBeNull();
    expect(sb.prefKeyOf("vault.confirmBeforeReveal.mode")).toBeNull();
    expect(sb.prefKeyOf(42)).toBeNull();
    expect(sbFromIndex.settingId("autoLockMins")).toBe("app.autoLockMins"); // exported through the vault index, like admin
  });

  it("reads only the app.* settings, and drops a value the cache's rules reject", () => {
    const r = sb.brokerPrefsOf([view("autoLockMins", 60), view("hue", 9999), { ...view("theme", "dark"), id: "node.securityLevel" }]);
    expect(r.values).toEqual({ autoLockMins: 60 });
    expect(r.defaults).toEqual({ autoLockMins: 15, hue: 198 });
  });
});

describe("planSync: the broker wins", () => {
  const broker = (values: Record<string, unknown>) => sb.brokerPrefsOf(listing(values).settings);

  it("applies a value the broker holds when the cache differs, and nothing when they agree", () => {
    expect(sb.planSync(broker({ autoLockMins: 60 }), { autoLockMins: 5 })).toEqual({ apply: { autoLockMins: 60 }, ask: [] });
    expect(sb.planSync(broker({ autoLockMins: 60 }), {})).toEqual({ apply: { autoLockMins: 60 }, ask: [] });
    expect(sb.planSync(broker({}), {})).toEqual({ apply: {}, ask: [] }); // a fresh vault and a fresh Mac: nothing to do, nothing written
    expect(sb.planSync(broker({ theme: "dark" }), { theme: "dark" })).toEqual({ apply: {}, ask: [] });
  });

  it("a broker still at its default against an explicit choice of this Mac is a question for the history, not an overwrite", () => {
    expect(sb.planSync(broker({}), { theme: "light", autoLockMins: 5 })).toEqual({ apply: {}, ask: ["theme", "autoLockMins"] });
  });
});

describe("readAppSettings", () => {
  it("without the shell calls nothing", async () => {
    delete g.window;
    expect(await sb.readAppSettings({ autoLockMins: 5 })).toBeNull();
    expect(await sb.pushAppSetting("autoLockMins", 5)).toBeNull();
    expect(await sb.pendingAgentRequests()).toBeNull();
    await expect(sb.decideAgentRequest("srq-1", true)).rejects.toThrow();
    for (const fn of Object.values(b)) if (typeof fn?.mockReset === "function") expect(fn).not.toHaveBeenCalled();
  });

  it("returns the broker's values to apply", async () => {
    b.settingsList.mockResolvedValue(listing({ autoLockMins: 60, theme: "dark" }));
    expect(await sb.readAppSettings({ autoLockMins: 5 })).toEqual({ apply: { autoLockMins: 60, theme: "dark" }, kept: {} });
    expect(b.settingsGet).not.toHaveBeenCalled();
    expect(b.settingsSet).not.toHaveBeenCalled();
  });

  it("sends up this Mac's earlier choice when the broker never recorded a change for it", async () => {
    b.settingsList.mockResolvedValue(listing({}));
    b.settingsGet.mockResolvedValue({ ...view("theme", null), recentChanges: [] });
    b.settingsSet.mockResolvedValue({ applied: true, change: "cosmetic", id: "app.theme" });
    expect(await sb.readAppSettings({ theme: "light" })).toEqual({ apply: {}, kept: { theme: "light" } });
    expect(b.settingsGet).toHaveBeenCalledWith("app.theme");
    expect(b.settingsSet).toHaveBeenCalledWith("app.theme", "light", sb.KEPT_REASON);
  });

  it("applies the broker's default when the broker has a history for the setting (an approved change back to the default stays)", async () => {
    b.settingsList.mockResolvedValue(listing({}));
    b.settingsGet.mockResolvedValue({ ...view("autoLockMins", 15), recentChanges: [{ id: "chg-1", setting: "app.autoLockMins", from: 5, to: 15, by: "owner", at: 1, reason: "r" }] });
    expect(await sb.readAppSettings({ autoLockMins: 5 })).toEqual({ apply: { autoLockMins: 15 }, kept: {} });
    expect(b.settingsSet).not.toHaveBeenCalled();
  });

  it("a refused history read or upload means the broker's value applies; a refused list rejects", async () => {
    b.settingsList.mockResolvedValue(listing({}));
    b.settingsGet.mockRejectedValueOnce({ source: "broker", code: "internal", message: "x" });
    expect(await sb.readAppSettings({ autoLockMins: 5 })).toEqual({ apply: { autoLockMins: 15 }, kept: {} });
    b.settingsGet.mockResolvedValue({ ...view("autoLockMins", 15), recentChanges: [] });
    b.settingsSet.mockRejectedValueOnce({ source: "broker", code: "malformed_request", message: "x" });
    expect(await sb.readAppSettings({ autoLockMins: 5 })).toEqual({ apply: { autoLockMins: 15 }, kept: {} });
    b.settingsList.mockRejectedValueOnce({ source: "broker", code: "vault_locked", message: "x" });
    await expect(sb.readAppSettings({})).rejects.toMatchObject({ code: "vault_locked" });
  });
});

describe("pushAppSetting", () => {
  it("sends app.<key> with the value and the reason the audit record keeps", async () => {
    b.settingsSet.mockResolvedValue({ applied: true, change: "strengthens", id: "app.autoLockMins", changeId: "chg-1" });
    expect(await sb.pushAppSetting("autoLockMins", 5)).toMatchObject({ applied: true });
    expect(b.settingsSet).toHaveBeenCalledWith("app.autoLockMins", 5, "changed in the app");
  });
  it("does not send a value the cache's rules reject, and rejects with the broker's refusal", async () => {
    expect(await sb.pushAppSetting("autoLockMins", 7)).toBeNull();
    expect(b.settingsSet).not.toHaveBeenCalled();
    b.settingsSet.mockRejectedValue({ source: "broker", code: "malformed_request", message: "x" });
    await expect(sb.pushAppSetting("theme", "dark")).rejects.toMatchObject({ code: "malformed_request" });
  });
});

describe("agents' requests", () => {
  const req = (over: Record<string, unknown> = {}) => ({ request: "srq-1", id: "app.autoLockMins", node: null, from: 15, to: 60, reason: "longer sessions", state: "pending", expiresIn: 300, requestedAt: 100, changeId: null, cwd: "/work/proj", ...over });

  it("lists only the pending ones, oldest first, with their values written out", async () => {
    b.settingsRequestList.mockResolvedValue({ requests: [req({ request: "srq-2", requestedAt: 200, to: null, id: "app.theme" }), req(), req({ request: "srq-3", state: "denied" }), req({ request: "srq-4", state: "expired" })] });
    const list = await sb.pendingAgentRequests();
    expect(list!.map((r) => r.request)).toEqual(["srq-1", "srq-2"]);
    expect(list![0]).toEqual({ request: "srq-1", id: "app.autoLockMins", node: null, from: "15", to: "60", reason: "longer sessions", cwd: "/work/proj", expiresIn: 300, requestedAt: 100, agentToken: null });
    expect(list![1].to).toBe("null (follow the system)");
  });

  // ADR-164 review P2-1/P1-2: a request made with an agent token says which token, by label and public id; anything that
  // is not a public id is dropped, and a token-shaped label is redacted like any other text an agent wrote.
  it("names the agent token that asked, and only a well-formed one", async () => {
    b.settingsRequestList.mockResolvedValue({ requests: [
      req({ agentToken: { id: "a_00000000000000a1", label: "ci" } }),
      req({ request: "srq-2", requestedAt: 200, agentToken: { id: "cma_" + "0".repeat(64), label: "x" } }),
      req({ request: "srq-3", requestedAt: 300, agentToken: { id: "a_00000000000000a3", label: "cma_" + "1".repeat(64) } }),
    ] });
    const list = await sb.pendingAgentRequests();
    expect(list![0].agentToken).toBe("agent token “ci” (a_00000000000000a1)");
    expect(list![1].agentToken).toBeNull();
    expect(list![2].agentToken).toContain("(a_00000000000000a3)");
    expect(JSON.stringify(list)).not.toMatch(/cma_[0-9a-f]{64}/);
  });

  it("cleans what an agent wrote before it reaches the screen: a token shape is redacted and a long reason is bounded", async () => {
    // Bounded at the broker's own limit (500, ADR-155), so a reason the broker accepted is shown whole (visual check 2026-11-09).
    b.settingsRequestList.mockResolvedValue({ requests: [req({ reason: "use cmt_0123456789abcdef please " + "x".repeat(700) })] });
    const [r] = (await sb.pendingAgentRequests())!;
    expect(r.reason).toContain("[redacted-token]");
    expect(r.reason).not.toContain("cmt_0123456789abcdef");
    expect(r.reason.length).toBeLessThanOrEqual(sb.REASON_MAX + 1);
  });

  it("approves and denies with one call each; a refusal rejects", async () => {
    b.settingsRequestDecide.mockResolvedValueOnce({ request: "srq-1", state: "approved", applied: true, changeId: "chg-2" });
    expect(await sb.decideAgentRequest("srq-1", true)).toEqual({ state: "approved", applied: true });
    b.settingsRequestDecide.mockResolvedValueOnce({ request: "srq-1", state: "denied", applied: false });
    expect(await sb.decideAgentRequest("srq-1", false)).toEqual({ state: "denied", applied: false });
    expect(b.settingsRequestDecide.mock.calls).toEqual([["srq-1", true], ["srq-1", false]]);
    b.settingsRequestDecide.mockRejectedValueOnce({ source: "broker", code: "confirmation_required", message: "x", detail: { cancelled: true } });
    await expect(sb.decideAgentRequest("srq-1", true)).rejects.toMatchObject({ code: "confirmation_required" });
  });
});

// ─────────────── the logic class's side (src/design/logic/switchboard.js), on a minimal host ───────────────

function memoryStorage() {
  const m = new Map<string, string>();
  return { getItem: (k: string) => m.get(k) ?? null, setItem: (k: string, v: string) => void m.set(k, v), removeItem: (k: string) => void m.delete(k), clear: () => m.clear(), key: () => null, length: 0 };
}

function host(over: Record<string, unknown> = {}) {
  const h: Record<string, any> = {
    model: { kind: "bridge", status: "unlocked" },
    state: { autoLockMins: 15, theme: null, captureProtection: true, sbRequests: [], sbBusy: null },
    notices: [] as Array<[string, string]>,
    routed: [] as unknown[],
    setState(patch: any, cb?: () => void) {
      const p = typeof patch === "function" ? patch(this.state) : patch;
      const prev = this.state;
      this.state = { ...this.state, ...p };
      // what settings.js afterUpdate does for every changed preference
      const changed: Record<string, unknown> = {};
      for (const k of PREF_KEYS) if (k in p && !Object.is(prev[k], this.state[k])) changed[k] = this.state[k];
      if (Object.keys(changed).length) this.queueSwitchboardPush(changed);
      cb?.();
    },
    notify(kind: string, text: string) { this.notices.push([kind, text]); },
    routeError(e: unknown) { this.routed.push(e); },
    armAutoLock: vi.fn(),
    applyCaptureProtection: vi.fn(),
    ...switchboardMethods,
    ...over,
  };
  return h;
}

describe("the logic class's sync", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    g.window = { __TAURI_INTERNALS__: {}, matchMedia: () => ({ matches: false }) };
    g.localStorage = memoryStorage();
  });
  afterEach(() => {
    vi.useRealTimers();
    delete g.localStorage;
  });

  it("after an unlock shows the broker's values, stores them in the cache, re-arms auto-lock, and sends nothing back", async () => {
    b.settingsList.mockResolvedValue(listing({ autoLockMins: 60, captureProtection: false }));
    b.settingsRequestList.mockResolvedValue({ requests: [] });
    const h = host();
    await h.syncSwitchboard(true);
    expect(h.state.autoLockMins).toBe(60);
    expect(h.state.captureProtection).toBe(false);
    expect(JSON.parse((g.localStorage as Storage).getItem("credmgr_prefs")!)).toEqual({ autoLockMins: 60, captureProtection: false });
    expect(h.armAutoLock).toHaveBeenCalled();
    expect(h.applyCaptureProtection).toHaveBeenCalledWith(false);
    await vi.advanceTimersByTimeAsync(2000);
    expect(b.settingsSet).not.toHaveBeenCalled(); // what came from the broker is not echoed to it
  });

  it("a change in the window is sent once, after a moment (a dragged slider is one call)", async () => {
    b.settingsSet.mockResolvedValue({ applied: true, change: "cosmetic", id: "app.hue" });
    const h = host();
    h.setState({ hue: 10 });
    h.setState({ hue: 20 });
    h.setState({ hue: 30 });
    expect(b.settingsSet).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(600);
    expect(b.settingsSet.mock.calls).toEqual([["app.hue", 30, "changed in the app"]]);
  });

  it("a refused write is a notice and the local change stays; a locked vault sends nothing", async () => {
    b.settingsSet.mockRejectedValue({ source: "broker", code: "internal", message: "x" });
    const h = host();
    h.setState({ autoLockMins: 5 });
    await vi.advanceTimersByTimeAsync(600);
    expect(h.state.autoLockMins).toBe(5);
    expect(h.notices).toEqual([["warn", expect.stringContaining("auto-lock")]]);
    b.settingsSet.mockReset();
    const locked = host({ model: { kind: "bridge", status: "locked" } });
    locked.setState({ autoLockMins: 60 });
    await vi.advanceTimersByTimeAsync(600);
    expect(b.settingsSet).not.toHaveBeenCalled();
    const demo = host({ model: { kind: "demo", status: "unlocked" } });
    demo.setState({ autoLockMins: 60 });
    await vi.advanceTimersByTimeAsync(600);
    expect(b.settingsSet).not.toHaveBeenCalled();
  });

  it("a new request is announced once; a decision re-reads the settings so an approved change shows at once", async () => {
    b.settingsRequestList.mockResolvedValue({ requests: [{ request: "srq-1", id: "app.autoLockMins", node: null, from: 15, to: 60, reason: "r", state: "pending", expiresIn: 300, requestedAt: 1, changeId: null }] });
    const h = host();
    await h.pollSettingRequests();
    await h.pollSettingRequests();
    expect(h.state.sbRequests.map((r: { request: string }) => r.request)).toEqual(["srq-1"]);
    expect(h.notices.filter(([k]: [string]) => k === "info")).toHaveLength(1);
    b.settingsRequestDecide.mockResolvedValue({ request: "srq-1", state: "approved", applied: true, changeId: "chg-1" });
    b.settingsList.mockResolvedValue(listing({ autoLockMins: 60 }));
    b.settingsRequestList.mockResolvedValue({ requests: [] });
    await h.decideSettingRequest("srq-1", true);
    expect(b.settingsRequestDecide).toHaveBeenCalledWith("srq-1", true);
    expect(h.state.autoLockMins).toBe(60);
    expect(h.state.sbRequests).toEqual([]);
    expect(h.state.sbBusy).toBeNull();
  });
});

describe("a request's reason is shown whole (visual check 2026-11-09)", () => {
  it("keeps the broker's full 500 characters and still strips a token", () => {
    const reason = "r".repeat(480) + " Bearer abcdefghijklmnopqrstuvwxyz0123456789";
    const out = sb.scrubRequest({ request: "sr-1", id: "app.autoLockMins", node: null, from: 15, to: 60, reason, state: "pending", expiresIn: 600, requestedAt: 0, changeId: null, cwd: null });
    expect(out.reason.startsWith("r".repeat(480))).toBe(true);
    expect(out.reason).not.toContain("abcdefghijklmnop");
    const full = "x".repeat(500);
    expect(sb.scrubRequest({ request: "sr-2", id: "app.theme", node: null, from: null, to: "dark", reason: full, state: "pending", expiresIn: 600, requestedAt: 0, changeId: null, cwd: null }).reason).toBe(full);
    expect(sb.REASON_MAX).toBe(500);
  });
});
