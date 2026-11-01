// Work package D (settings and administration), below the browser: the preferences, the admin actions against a faked
// shell, and the settings logic against a faked host.  The end-to-end behaviour is in tests/e2e/wp-d-*.spec.ts.
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import Component from "../../src/design/logic/core.js";
import { DONATE_CHAINS } from "../../src/design/logic/settings.js";
import * as admin from "../../src/vault/actions/admin";
import { defaultPrefs, loadPrefs, PREFS_KEY, pick, savePrefs, storedPrefs } from "../../src/vault/prefs";

const ROOT = resolve(__dirname, "../..");
const read = (rel: string) => readFileSync(resolve(ROOT, rel), "utf8");

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
const asStorage = (s: FakeStorage) => s as unknown as Storage;

describe("preferences (src/vault/prefs.ts)", () => {
  it("the defaults are the design's, and loading from an empty or unreachable storage gives them", () => {
    expect(loadPrefs(asStorage(new FakeStorage()))).toEqual(defaultPrefs());
    expect(loadPrefs(null)).toEqual(defaultPrefs());
    expect(storedPrefs(null)).toEqual({});
  });

  it("stores only what was saved, under the one documented key, and merges later saves", () => {
    const st = new FakeStorage();
    savePrefs({ theme: "dark" }, asStorage(st));
    savePrefs({ autoLockMins: 5, theme: "light" }, asStorage(st));
    expect([...st.data.keys()]).toEqual([PREFS_KEY]);
    expect(JSON.parse(st.data.get(PREFS_KEY)!)).toEqual({ theme: "light", autoLockMins: 5 });
    expect(loadPrefs(asStorage(st))).toEqual({ ...defaultPrefs(), theme: "light", autoLockMins: 5 });
  });

  it("screen-capture protection is ON by default, and only a stored boolean changes it: nothing stored, nothing readable, nothing odd means protected", () => {
    expect(defaultPrefs().captureProtection).toBe(true);
    expect(loadPrefs(null).captureProtection).toBe(true);
    expect(loadPrefs(asStorage(new FakeStorage())).captureProtection).toBe(true);
    const st = new FakeStorage();
    savePrefs({ captureProtection: false }, asStorage(st));
    expect(JSON.parse(st.data.get(PREFS_KEY)!)).toEqual({ captureProtection: false });
    expect(storedPrefs(asStorage(st)).captureProtection).toBe(false);
    expect(loadPrefs(asStorage(st)).captureProtection).toBe(false);
    // a damaged or hand-edited value is not "off": it is dropped, so the default (protected) applies and the page never calls the shell
    for (const bad of ["off", 0, null, "false", [], {}]) {
      expect(pick({ captureProtection: bad })).toEqual({});
    }
    st.setItem(PREFS_KEY, "{not json");
    expect(storedPrefs(asStorage(st)).captureProtection).toBeUndefined();
    expect(loadPrefs(asStorage(st)).captureProtection).toBe(true);
  });

  it("drops anything that is not a valid setting: unknown keys, wrong types, out-of-range numbers, values the selects do not offer", () => {
    expect(
      pick({
        theme: "neon", colour: "on", hue: 9999, intensity: -1, greyscale: "yes", contrastMode: "high", motion: "full", hwAccel: false, mode: "root",
        autoLockMins: 7, revealWindowSecs: 10, backupRetain: 30, entriesMode: "selected", view: "grid", evil: "<b>x</b>", node: "atlas",
      }),
    ).toEqual({ colour: "on", contrastMode: "high", hwAccel: false, revealWindowSecs: 10, backupRetain: 30, entriesMode: "selected" });
    expect(pick(null)).toEqual({});
    expect(pick("theme")).toEqual({});
    expect(pick([1, 2, 3])).toEqual({});
    // JSON.parse makes "__proto__" an own property; nothing is read from it and nothing is polluted
    expect(pick(JSON.parse('{"__proto__":{"polluted":true},"colour":"auto"}'))).toEqual({ colour: "auto" });
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });

  it("a damaged stored value is nothing stored, and the next save replaces it", () => {
    const st = new FakeStorage();
    st.setItem(PREFS_KEY, "{not json");
    expect(storedPrefs(asStorage(st))).toEqual({});
    savePrefs({ mode: "lite" }, asStorage(st));
    expect(JSON.parse(st.data.get(PREFS_KEY)!)).toEqual({ mode: "lite" });
  });

  it("storage that refuses is not an error: the prefs still come back, and nothing throws", () => {
    const refusing = {
      getItem: () => {
        throw new Error("denied");
      },
      setItem: () => {
        throw new Error("quota");
      },
    } as unknown as Storage;
    expect(() => loadPrefs(refusing)).not.toThrow();
    expect(savePrefs({ hue: 12 }, refusing)).toMatchObject({ hue: 12 });
    expect(savePrefs({ hue: 12 }, null)).toMatchObject({ hue: 12 });
  });

  it("a pref cannot hold a vault name, however it is asked to: every field is a closed set or a bounded number", () => {
    const out = pick({ theme: "atlas", colour: "stripe-live", view: "e-a1", mode: "global", hue: "atlas" });
    expect(out).toEqual({});
  });
});

// ─────────────────────────────── the admin actions, against a faked shell ───────────────────────────────

interface Call {
  cmd: string;
  args: Record<string, unknown>;
}
type Answer = unknown | ((args: Record<string, unknown>) => unknown);

function fakeShell(answers: Record<string, Answer>) {
  const calls: Call[] = [];
  (globalThis as unknown as { window: unknown }).window = {
    __TAURI_INTERNALS__: {
      invoke: async (cmd: string, args: Record<string, unknown> = {}) => {
        calls.push({ cmd, args: JSON.parse(JSON.stringify(args)) });
        const a = answers[cmd];
        if (a === undefined) throw { source: "broker", code: "internal", message: `no answer for ${cmd}` };
        const v = typeof a === "function" ? (a as (x: Record<string, unknown>) => unknown)(args) : a;
        if (v && typeof v === "object" && "__error" in (v as object)) throw (v as { __error: unknown }).__error;
        return v;
      },
      transformCallback: () => 1,
    },
  };
  return calls;
}
const fail = (code: string, detail?: Record<string, unknown>) => ({ __error: { source: "broker", code, message: code, detail } });

/** A model stand-in that records what the actions ask of it. */
function fakeModel() {
  const refreshed: unknown[] = [];
  return {
    refreshed,
    refresh: async (spec: unknown) => void refreshed.push(spec),
    mutate: async <T>(action: () => Promise<T>, spec: unknown) => {
      const r = await action();
      refreshed.push(spec);
      return r;
    },
  } as unknown as import("../../src/vault/model").VaultModel & { refreshed: unknown[] };
}

describe("admin actions (src/vault/actions/admin.ts)", () => {
  afterEach(() => {
    delete (globalThis as unknown as { window?: unknown }).window;
  });

  it("createGrant sends the bridge's keys and reads the grant list again only when the broker accepted it", async () => {
    const m = fakeModel();
    const calls = fakeShell({ grant_create: { created: true } });
    await admin.createGrant(m, "beacon", { kind: "node", nodeId: "atlas" }, ["read", "notes"], "a good reason");
    expect(calls).toEqual([{ cmd: "grant_create", args: { from: "beacon", to: { kind: "node", nodeId: "atlas" }, scope: ["read", "notes"], reason: "a good reason" } }]);
    expect(m.refreshed).toEqual([{ grants: true }]);

    const m2 = fakeModel();
    fakeShell({ grant_create: fail("presence_required") });
    await expect(admin.createGrant(m2, "beacon", { kind: "node", nodeId: "atlas" }, ["read"], "a good reason")).rejects.toMatchObject({ code: "presence_required" });
    expect(m2.refreshed).toEqual([]);
  });

  it("revokeGrant sends grant_revoke with the id and then refreshes the grants", async () => {
    const m = fakeModel();
    const calls = fakeShell({ grant_revoke: { id: "g1", revoked: true } });
    await admin.revokeGrant(m, "g1");
    expect(calls).toEqual([{ cmd: "grant_revoke", args: { id: "g1" } }]);
    expect(m.refreshed).toEqual([{ grants: true }]);
  });

  it("the audit trail comes back newest-first as the broker sent it, with every session token replaced, in any field", async () => {
    const token = "cmt_" + "0123456789abcdef".repeat(2); // built, not written: a session token shape must not sit in a source file as a literal
    const calls = fakeShell({
      audit_tail: { records: [{ id: "a1", timestamp: 5, actor: `HumanUi:${token}`, action: "vault.unlock", node: null, decision: "allow", detail: `used ${token} twice: ${token}`, entry: null }, { id: "a2", timestamp: 4, actor: "Agent", action: "audit.tail" }] },
    });
    const rows = await admin.readAudit(fakeModel(), 50);
    expect(calls).toEqual([{ cmd: "audit_tail", args: { limit: 50 } }]);
    expect(JSON.stringify(rows)).not.toContain(token);
    expect(JSON.stringify(rows)).not.toMatch(/cmt_[0-9a-f]{8}/);
    expect(rows[0]).toMatchObject({ actor: "HumanUi:[redacted-token]", detail: "used [redacted-token] twice: [redacted-token]", node: null });
    expect(rows[1]).toEqual({ id: "a2", timestamp: 4, actor: "Agent", action: "audit.tail" }); // the agent shape stays four fields; nothing is invented
  });

  it("a hostile record cannot flood the screen or bring an object into it", async () => {
    fakeShell({ audit_tail: { records: [{ id: "a1", timestamp: "now", actor: { evil: 1 }, action: "x".repeat(5000), detail: { nested: true } }] } });
    const [r] = await admin.readAudit(fakeModel());
    expect(r.actor).toBe("");
    expect(r.timestamp).toBe(0);
    expect(r.action.length).toBeLessThanOrEqual(301);
    expect(r.detail).toBeUndefined();
  });

  it("redactTokens follows the broker's rule: cmt_ and at least eight hex digits, the whole run", () => {
    expect(admin.redactTokens("a cmt_deadbeef b")).toBe("a [redacted-token] b");
    expect(admin.redactTokens("cmt_deadbeefDEADBEEF99")).toBe("[redacted-token]");
    expect(admin.redactTokens("cmt_abc and cmt_ and xcmt")).toBe("cmt_abc and cmt_ and xcmt"); // too short to be a bearer
  });

  it("getAudit asks for the record by id", async () => {
    const calls = fakeShell({ audit_get: { id: "a1", timestamp: 1, actor: "HumanUi", action: "entry.reveal", node: "atlas", decision: "allow" } });
    expect(await admin.getAudit(fakeModel(), "a1")).toMatchObject({ id: "a1", node: "atlas" });
    expect(calls).toEqual([{ cmd: "audit_get", args: { id: "a1" } }]);
  });

  it("verify, doctor and backup send their keys; doctor reads the graph again only after an APPLIED fix", async () => {
    const calls = fakeShell({
      maintenance_verify: { ok: false, nodesChecked: 2, errors: [{ node: "atlas", detail: "bad checksum" }], warnings: [] },
      maintenance_doctor: (a: Record<string, unknown>) => ({ applied: a.apply !== false, fixCount: 1, fixes: [{ node: "atlas", type: "cross-binding-resync" }], unfixable: [] }),
      maintenance_backup: { path: "backups/x.enc", retain: 30, pruned: ["backups/old-1.enc", "backups/old-2.enc"] },
    });
    const m = fakeModel();
    expect(await admin.verifyVault(m)).toEqual({ ok: false, nodesChecked: 2, errors: [{ node: "atlas", detail: "bad checksum" }], warnings: [] });
    await admin.runDoctor(m, { apply: false });
    expect(m.refreshed).toEqual([]); // a dry run changes nothing
    await admin.runDoctor(m, { apply: true });
    expect(m.refreshed).toEqual([{ graph: true }]);
    await admin.runDoctor(m, { apply: true, rebuildRegistry: true, passphrase: "p-1" });
    expect(await admin.backupVault(m, "p-2", 30)).toEqual({ path: "backups/x.enc", retain: 30, pruned: 2 });
    expect(calls.map((c) => c.cmd)).toEqual(["maintenance_verify", "maintenance_doctor", "maintenance_doctor", "maintenance_doctor", "maintenance_backup"]);
    expect(calls[1].args).toEqual({ apply: false });
    expect(calls[2].args).toEqual({ apply: true });
    expect(calls[3].args).toEqual({ apply: true, rebuildRegistry: true, passphrase: "p-1" });
    expect(calls[4].args).toEqual({ passphrase: "p-2", retain: 30 });
  });

  it("rotateRootKey returns the broker's answer and does not read the model afterwards", async () => {
    const m = fakeModel();
    const calls = fakeShell({ maintenance_rotate_root: { rotated: true, recoveryCode: "AAAA-BBBB", nodesRewrapped: 1, vaultGeneration: 2, filesReplaced: 3, artifactsResigned: 0, completionPending: true, notResigned: [] } });
    const r = await admin.rotateRootKey(m, "vault-pass");
    expect(r.recoveryCode).toBe("AAAA-BBBB");
    expect(calls).toEqual([{ cmd: "maintenance_rotate_root", args: { passphrase: "vault-pass" } }]);
    expect(m.refreshed).toEqual([]);
  });

  it("copyPlainText with no shell rejects, and never writes to the page's own clipboard", async () => {
    const written: string[] = [];
    Object.defineProperty(globalThis, "navigator", { value: { clipboard: { writeText: async (t: string) => void written.push(t) } }, configurable: true });
    await expect(admin.copyPlainText("0xabc")).rejects.toThrow(/shell/);
    expect(written).toEqual([]);
  });

  it("inside the shell, copyPlainText sends copy_text with the text and never touches the browser's clipboard, even when the shell refuses", async () => {
    const page: string[] = [];
    Object.defineProperty(globalThis, "navigator", { value: { clipboard: { writeText: async (t: string) => void page.push(t) } }, configurable: true });
    const calls = fakeShell({ copy_text: { copied: true, clearAfterSeconds: null } });
    await admin.copyPlainText("bc1qexample");
    expect(calls).toEqual([{ cmd: "copy_text", args: { text: "bc1qexample" } }]);
    fakeShell({ copy_text: fail("clipboard_failed") });
    await expect(admin.copyPlainText("bc1qexample")).rejects.toMatchObject({ code: "clipboard_failed" });
    expect(page).toEqual([]); // a refusal is a failure to report, not a reason to try the page's clipboard
  });

  it("setAppIcon asks the shell for app_icon_set, is false with no shell, and never throws when the shell refuses (an icon must not block an unlock)", async () => {
    expect(await admin.setAppIcon("seal")).toBe(false); // no window at all
    const calls = fakeShell({ app_icon_set: { icon: "seal", dock: true, window: false } });
    expect(await admin.setAppIcon("seal")).toBe(true);
    expect(calls).toEqual([{ cmd: "app_icon_set", args: { icon: "seal" } }]);
    fakeShell({ app_icon_set: { icon: "keep", dock: false, window: false } });
    expect(await admin.setAppIcon("keep")).toBe(false); // the shell reached no surface
    fakeShell({ app_icon_set: fail("unknown_icon") });
    expect(await admin.setAppIcon("nope")).toBe(false);
  });

  it("setCaptureProtection asks the shell for capture_protection_set, is null with no shell, and rejects when the shell refuses (a failed ON must be reportable)", async () => {
    expect(await admin.setCaptureProtection(false)).toBeNull(); // no window at all: nothing to protect or expose
    const calls = fakeShell({ capture_protection_set: { enabled: false, applied: true } });
    expect(await admin.setCaptureProtection(false)).toEqual({ enabled: false, applied: true });
    expect(calls).toEqual([{ cmd: "capture_protection_set", args: { enabled: false } }]);
    fakeShell({ capture_protection_set: { enabled: true, applied: true } });
    expect(await admin.setCaptureProtection(true)).toEqual({ enabled: true, applied: true });
    fakeShell({ capture_protection_set: fail("internal") });
    await expect(admin.setCaptureProtection(true)).rejects.toMatchObject({ code: "internal" });
  });

  it("appVersion asks the shell, and is null with no shell or an unusable answer", async () => {
    expect(await admin.appVersion()).toBeNull(); // no window at all
    const calls = fakeShell({ "plugin:app|version": "2.0.0-beta.1" });
    expect(await admin.appVersion()).toBe("2.0.0-beta.1");
    expect(calls.map((c) => c.cmd)).toEqual(["plugin:app|version"]);
    fakeShell({ "plugin:app|version": 42 });
    expect(await admin.appVersion()).toBeNull();
    fakeShell({ "plugin:app|version": fail("internal") });
    expect(await admin.appVersion()).toBeNull();
  });
});

// ─────────────────────────────── the settings logic, against a faked host ───────────────────────────────

/** A logic instance with a host that merges state synchronously (what DCHost does), in bridge or demo mode. */
function logicWith(opts: { shell: boolean }) {
  const logic: any = new (Component as any)({ mode: "pro" });
  logic.__host = {
    setLogicState(update: any, cb?: () => void) {
      const patch = typeof update === "function" ? update(logic.state) : update;
      logic.state = { ...logic.state, ...patch };
      cb?.();
    },
    forceUpdate() {},
  };
  expect(logic.model.kind).toBe(opts.shell ? "bridge" : "demo");
  return logic;
}

describe("settings logic (src/design/logic/settings.js)", () => {
  let store: FakeStorage;
  let savedStorage: unknown;
  beforeEach(() => {
    savedStorage = (globalThis as any).localStorage;
    store = new FakeStorage();
    Object.defineProperty(globalThis, "localStorage", { value: store, configurable: true, writable: true });
    // the little of the DOM the logic's lifecycle touches (applyTheme, focus handling)
    (globalThis as any).document = {
      documentElement: { dataset: {}, style: { setProperty() {}, removeProperty() {} } },
      activeElement: null,
      contains: () => false,
      querySelector: () => null,
      querySelectorAll: () => [],
    };
  });
  afterEach(() => {
    Object.defineProperty(globalThis, "localStorage", { value: savedStorage, configurable: true, writable: true });
    delete (globalThis as unknown as { window?: unknown }).window;
    delete (globalThis as any).document;
  });

  it("applies the stored preferences once at start and remembers a changed one afterwards, and only that one", () => {
    store.setItem(PREFS_KEY, JSON.stringify({ theme: "dark", autoLockMins: 5, hue: 9999 }));
    const logic = logicWith({ shell: false });
    logic.initSettings();
    logic.initSettings(); // idempotent: the hooks are installed once
    expect(logic.state).toMatchObject({ theme: "dark", autoLockMins: 5, hue: 198 });
    expect(JSON.parse(store.getItem(PREFS_KEY)!)).toEqual({ theme: "dark", autoLockMins: 5, hue: 9999 }); // loading wrote nothing

    const before = logic.state;
    logic.setState({ revealWindowSecs: 10, searchQ: "stripe" });
    logic.componentDidUpdate({}, before); // what the host calls after a commit
    expect(JSON.parse(store.getItem(PREFS_KEY)!)).toEqual({ theme: "dark", autoLockMins: 5, revealWindowSecs: 10 }); // hue 9999 was invalid and is gone; searchQ is not a preference
  });

  it("high contrast follows the operating system until one is picked", () => {
    (globalThis as any).window = { matchMedia: (q: string) => ({ matches: q.includes("prefers-contrast: more") }) };
    const logic = logicWith({ shell: false });
    logic.initSettings();
    expect(logic.state.contrastMode).toBe("high");
    expect(store.getItem(PREFS_KEY)).toBeNull();

    store.setItem(PREFS_KEY, JSON.stringify({ contrastMode: "standard" }));
    const picked = logicWith({ shell: false });
    picked.initSettings();
    expect(picked.state.contrastMode).toBe("standard");
  });

  it("a passphrase typed into the prompt is never in the logic's state, before or after the call, and is not resent", async () => {
    const PASS = "correct-horse-battery-staple-93";
    const calls = fakeShell({ maintenance_backup: { path: "backups/a.enc", retain: 14, pruned: [] }, vault_status: { locked: false, authenticated: true, initialized: true } });
    const logic = logicWith({ shell: true });
    const seen: string[] = [];
    const snap = () => seen.push(JSON.stringify(logic.state));
    logic.openAdminPass("backup");
    snap();
    expect(logic.state.dialog).toBe("adminPass");
    expect(logic.adm().prompt).toEqual({ kind: "backup" });
    // the inputs' onChange handlers are what put the text in the logic; read it as the template would
    const vals = logic.renderVals();
    vals.onAdminPass({ target: { value: PASS } });
    vals.onAdminRepeat({ target: { value: PASS } });
    snap();
    await logic.submitAdminPass();
    snap();
    expect(calls.filter((c) => c.cmd === "maintenance_backup")).toEqual([{ cmd: "maintenance_backup", args: { passphrase: PASS, retain: 14 } }]);
    for (const s of seen) expect(s).not.toContain(PASS);
    expect(logic._adminPass).toBe("");
    expect(logic.state.dialog).toBeNull();
    // a second submit with nothing typed sends nothing
    logic.openAdminPass("backup");
    await logic.submitAdminPass();
    expect(calls.filter((c) => c.cmd === "maintenance_backup")).toHaveLength(1);
    expect(logic.state.fieldErrors.adminPass).toBe("Enter the passphrase.");
  });

  it("in the browser preview, an administration action says there is no broker and calls nothing", async () => {
    const logic = logicWith({ shell: false });
    const r = await logic.runAdmin("maintenance.verify", async () => {
      throw new Error("must not run");
    });
    expect(r).toEqual({ ok: false, route: null });
    expect(logic.state.notice).toMatchObject({ kind: "info" });
    expect(logic.state.notice.text).toContain("no broker");
  });

  it("runs one administration call at a time, and reports a rejection through the router rather than throwing", async () => {
    fakeShell({});
    const logic = logicWith({ shell: true });
    let release!: () => void;
    const first = logic.runAdmin("a", () => new Promise<void>((res) => (release = res)));
    const second = await logic.runAdmin("b", async () => "ran");
    expect(second).toEqual({ ok: false, route: null }); // busy: the second call was not made
    release();
    expect(await first).toMatchObject({ ok: true });
    const failed = await logic.runAdmin("c", async () => {
      throw { source: "broker", code: "capability_not_held", message: "x", detail: { rule: "admin is required" } };
    });
    expect(failed.ok).toBe(false);
    expect(failed.route).toMatchObject({ route: "inline" });
    expect(logic.state.notice).toMatchObject({ kind: "error", text: "Not permitted (admin is required)." });
    expect(logic.adm().busy).toBeNull();
  });

  it("the Operations rows are the six that exist (Doctor and Doctor with purge are two rows); the five that do not are gone", () => {
    const logic = logicWith({ shell: false });
    const vals = logic.renderVals();
    expect(vals.opsRows.map((r: { name: string }) => r.name)).toEqual(["Verify integrity", "Doctor", "Doctor with purge", "Back up vault", "Rotate root key", "Audit report"]);
  });

  it("the donation addresses are exactly the ones in DONATE.md", () => {
    const md = read("../../DONATE.md");
    expect(DONATE_CHAINS).toHaveLength(5);
    for (const c of DONATE_CHAINS) expect(md, `${c.short} address is not in DONATE.md`).toContain(c.address);
  });
});

// ─────────────────────────────── the files this package owns ───────────────────────────────

describe("the files package D owns", () => {
  const OWNED = [
    "src/design/screens/S11-grant.html",
    "src/design/screens/S12-settings.html",
    "src/design/screens/S14-ops.html",
    "src/design/screens/S18-about.html",
    "src/design/screens/help.html",
    "src/design/screens/dlg-touch.html",
    "src/design/logic/settings.js",
    "src/vault/prefs.ts",
    "src/vault/actions/admin.ts",
  ];

  it("carry no mock badge, no 'not built' label and no word 'mock'", () => {
    for (const f of OWNED) {
      const t = read(f);
      expect(t, f).not.toMatch(/mock/i);
      expect(t, f).not.toMatch(/not built yet/i);
      expect(t, f).not.toMatch(/NotWiredError/);
    }
  });

  it("claim nothing the broker does not do: no expiry on a grant, no Touch ID prompt, no billing address but the reserved placeholder (ADR-082), no shared unlock code", () => {
    const text = OWNED.map(read).join("\n");
    expect(text).not.toMatch(new RegExp("THANKS" + "CREDMGR|billing@(?!example\\.com)|payments@|(?<!admin)@freexstudio", "i")); // the one public contact, admin@freexstudio.com, is allowed; the retired public code is built from pieces so it is not spelled in the repo
    expect(read("src/design/screens/S11-grant.html")).not.toMatch(/grant expiry|2FA code|>expiry</);
    expect(read("src/design/screens/dlg-touch.html")).not.toMatch(/>Touch ID</);
    expect(read("src/design/screens/S18-about.html")).not.toMatch(/paid licen|requires a paid/i);
  });

  it("load nothing from the network and call the shell only through src/lib/bridge.ts", () => {
    for (const f of OWNED) {
      const t = read(f);
      expect(t, f).not.toMatch(/https?:\/\//);
      expect(t, f).not.toMatch(/(^|[^A-Za-z0-9_$.])invoke\s*\(/);
      expect(t, f).not.toMatch(/\bfetch\s*\(|XMLHttpRequest|WebSocket|sendBeacon|eval\s*\(|new Function/);
    }
  });
});
