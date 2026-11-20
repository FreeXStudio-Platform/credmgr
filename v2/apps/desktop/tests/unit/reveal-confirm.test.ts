// ADR-150, "Confirm before showing secrets": the bridge's one retry (src/lib/bridge.ts), the admin actions that read and set the policy,
// and how the error router words what is left.  Against a faked Tauri `invoke`.
import { afterEach, describe, expect, it } from "vitest";

import * as live from "../../src/lib/bridge";
import { confirmIdentity, revealConfirmPolicy, setRevealConfirm } from "../../src/vault/actions/admin";
import { classifyError } from "../../src/vault/errors";
import { CONFIRM_WINDOW_MINUTES } from "../../src/design/logic/confirm.js";

type Handler = (args: Record<string, unknown>) => unknown;
interface Call {
  cmd: string;
  args: Record<string, unknown>;
}
const refuse = (code: string, detail?: Record<string, unknown>) => ({ source: "broker", code, message: code, ...(detail ? { detail } : {}) });
const NEED = refuse("confirmation_required", { operation: "entry.reveal", mode: "window", windowSeconds: 300 });

function installInvoke(handlers: Record<string, Handler>): Call[] {
  const calls: Call[] = [];
  (globalThis as unknown as { window?: object }).window = {
    __TAURI_INTERNALS__: {
      invoke: async (cmd: string, args?: Record<string, unknown>) => {
        calls.push({ cmd, args: JSON.parse(JSON.stringify(args ?? {})) });
        const h = handlers[cmd];
        if (!h) throw refuse("internal");
        return h(args ?? {});
      },
    },
  };
  return calls;
}

let removeHandler: () => void = () => {};
afterEach(() => {
  removeHandler();
  delete (globalThis as unknown as { window?: object }).window;
});

describe("the bridge asks once and repeats the same command once", () => {
  it("confirmation_required -> the handler -> the same command, same arguments", async () => {
    let n = 0;
    const calls = installInvoke({ entry_reveal: () => (n++ === 0 ? Promise.reject(NEED) : { node: "atlas", entry: "e1", fields: [] }) });
    const asked: live.ConfirmationAsk[] = [];
    removeHandler = live.setConfirmationHandler(async (ask) => { asked.push(ask); return true; });
    const r = await live.entryReveal("atlas", "e1", ["f_00000001"]);
    expect(r.entry).toBe("e1");
    expect(asked).toEqual([{ command: "entry_reveal", operation: "entry.reveal", mode: "window", windowSeconds: 300 }]);
    expect(calls.map((c) => c.cmd)).toEqual(["entry_reveal", "entry_reveal"]);
    expect(calls[1].args).toEqual(calls[0].args);
  });

  it("a cancelled confirmation rejects with the refusal marked cancelled, and nothing is sent again", async () => {
    const calls = installInvoke({ entry_reveal: () => Promise.reject(NEED) });
    removeHandler = live.setConfirmationHandler(async () => false);
    await expect(live.entryReveal("atlas", "e1")).rejects.toMatchObject({ code: "confirmation_required", detail: { cancelled: true } });
    expect(calls.map((c) => c.cmd)).toEqual(["entry_reveal"]);
  });

  it("never loops: a second refusal after the retry is passed on, and the handler was asked once", async () => {
    const calls = installInvoke({ totp_code: () => Promise.reject(NEED) });
    let asked = 0;
    removeHandler = live.setConfirmationHandler(async () => { asked++; return true; });
    await expect(live.totpCode("atlas", "e3")).rejects.toMatchObject({ code: "confirmation_required" });
    expect(asked).toBe(1);
    expect(calls.length).toBe(2);
  });

  it("session_confirm itself is never retried, and without a handler the refusal passes through", async () => {
    installInvoke({ session_confirm: () => Promise.reject(NEED), entry_reveal: () => Promise.reject(NEED) });
    let asked = 0;
    removeHandler = live.setConfirmationHandler(async () => { asked++; return true; });
    await expect(live.sessionConfirm("x")).rejects.toMatchObject({ code: "confirmation_required" });
    expect(asked).toBe(0);
    removeHandler();
    await expect(live.entryReveal("atlas", "e1")).rejects.toMatchObject({ code: "confirmation_required" });
  });

  it("two requests refused together share ONE confirmation", async () => {
    const seen = new Map<string, number>();
    installInvoke({
      entry_reveal: (a) => { const k = String(a.entry); const c = seen.get(k) ?? 0; seen.set(k, c + 1); return c === 0 ? Promise.reject(NEED) : { node: "atlas", entry: k, fields: [] }; },
    });
    let asked = 0;
    let release: (v: boolean) => void = () => {};
    removeHandler = live.setConfirmationHandler(() => { asked++; return new Promise<boolean>((r) => { release = r; }); });
    const both = Promise.all([live.entryReveal("atlas", "e1"), live.entryReveal("atlas", "e2")]);
    await new Promise((r) => setTimeout(r, 0));
    release(true);
    const [a, b] = await both;
    expect([a.entry, b.entry]).toEqual(["e1", "e2"]);
    expect(asked).toBe(1);
  });

  it("a handler that throws counts as cancelled", async () => {
    installInvoke({ entry_copy: () => Promise.reject(NEED) });
    removeHandler = live.setConfirmationHandler(async () => { throw new Error("dialog gone"); });
    await expect(live.entryCopy("atlas", "e1")).rejects.toMatchObject({ detail: { cancelled: true } });
  });

  it("other refusals are not touched", async () => {
    const calls = installInvoke({ entry_reveal: () => Promise.reject(refuse("node_locked", { node: "atlas" })) });
    removeHandler = live.setConfirmationHandler(async () => true);
    await expect(live.entryReveal("atlas", "e1")).rejects.toMatchObject({ code: "node_locked" });
    expect(calls.length).toBe(1);
  });
});

describe("the admin actions", () => {
  it("session_confirm: the passphrase under its key, Touch ID with no passphrase key at all", async () => {
    const calls = installInvoke({ session_confirm: (a) => ({ confirmed: true, method: a.passphrase ? "passphrase" : "presence", expiresIn: 300 }) });
    expect(await confirmIdentity("pw")).toEqual({ method: "passphrase", expiresIn: 300 });
    expect(await confirmIdentity()).toEqual({ method: "presence", expiresIn: 300 });
    expect(calls).toEqual([{ cmd: "session_confirm", args: { passphrase: "pw" } }, { cmd: "session_confirm", args: {} }]);
  });

  it("reads the policy from the owner's snapshot, and an older broker that says nothing reads as off", async () => {
    installInvoke({ graph_snapshot: () => ({ nodes: [], links: [], meta: { generatedAt: 1, vaultLocked: false }, revealConfirm: { mode: "everyTime", windowSeconds: 900, scope: "high" } }) });
    expect(await revealConfirmPolicy()).toEqual({ mode: "everyTime", windowSeconds: 900, scope: "high" });
    installInvoke({ graph_snapshot: () => ({ nodes: [], links: [], meta: { generatedAt: 1, vaultLocked: false } }) });
    expect(await revealConfirmPolicy()).toEqual({ mode: "off", windowSeconds: 300, scope: "all" });
  });

  it("sets it with node_policy on the global node, with a reason, and answers what the broker holds", async () => {
    const next: live.RevealConfirm = { mode: "window", windowSeconds: 60, scope: "all" };
    const calls = installInvoke({ node_policy: (a) => ({ node: "global", policy: { revealConfirm: (a.policy as { revealConfirm: unknown }).revealConfirm }, changed: ["revealConfirm"], reason: a.reason, notEnforced: [] }) });
    expect(await setRevealConfirm(next)).toEqual(next);
    expect(calls[0].cmd).toBe("node_policy");
    expect(calls[0].args).toMatchObject({ node: "global", policy: { revealConfirm: next } });
    expect(String(calls[0].args.reason).length).toBeGreaterThan(8);
  });

  it("the Settings windows are exactly the broker's", () => {
    expect(CONFIRM_WINDOW_MINUTES.map((m) => m * 60)).toEqual([...live.REVEAL_CONFIRM_WINDOWS]);
    expect(live.REVEAL_CONFIRM_DEFAULT).toEqual({ mode: "off", windowSeconds: 300, scope: "all" });
  });
});

describe("what the router says", () => {
  it("a cancel is quiet, never an error, and names what did not happen", () => {
    expect(classifyError({ ...NEED, detail: { cancelled: true } }, { op: "entry.reveal" })).toEqual({ route: "notice", kind: "info", message: "Not confirmed. Nothing was shown." });
    expect(classifyError({ ...NEED, detail: { cancelled: true } }, { op: "node.policy" })).toMatchObject({ kind: "info", message: "Not confirmed. The setting was not changed." });
    expect(classifyError(NEED, {})).toMatchObject({ route: "notice", kind: "info" });
  });
});
