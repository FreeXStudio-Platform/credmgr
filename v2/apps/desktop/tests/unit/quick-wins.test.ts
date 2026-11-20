// ADR-156, the desktop half of the post-launch quick wins, below the browser: change the passphrase (Settings › Security), start the
// broker at login (Settings › Security and the broker-down screen), the Touch ID row on a Mac without a Secure Enclave with the
// protection line, and the cross-node anomaly bar.  The logic runs against a faked shell (the layer below src/lib/bridge.ts), so the
// command names and argument keys asserted here are the ones the real bridge sends.
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import Component from "../../src/design/logic/core.js";
import * as admin from "../../src/vault/actions/admin";

const ROOT = resolve(__dirname, "../..");
const read = (rel: string) => readFileSync(resolve(ROOT, rel), "utf8");

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
const fail = (code: string, source = "broker") => ({ __error: { source, code, message: code } });

/** A logic instance with a host that merges state synchronously (what DCHost does). */
function logicWith(mode: "pro" | "lite" = "pro") {
  const logic: any = new (Component as any)({ mode });
  logic.__host = {
    setLogicState(update: any, cb?: () => void) {
      const patch = typeof update === "function" ? update(logic.state) : update;
      logic.state = { ...logic.state, ...patch };
      cb?.();
    },
    forceUpdate() {},
  };
  return logic;
}
const flush = () => new Promise((r) => setTimeout(r, 0));

beforeEach(() => {
  (globalThis as any).document = {
    documentElement: { dataset: {}, style: { setProperty() {}, removeProperty() {} } },
    activeElement: null,
    contains: () => false,
    querySelector: () => null,
    querySelectorAll: () => [],
  };
});
afterEach(() => {
  delete (globalThis as unknown as { window?: unknown }).window;
  delete (globalThis as any).document;
});

const ROTATED = { rotated: true, recoveryCode: "NEW1-CODE-2345", nodesRewrapped: 3, vaultGeneration: 4, filesReplaced: 5, artifactsResigned: 1, completionPending: false, notResigned: [], passphraseChanged: true };

// ─────────────────────────────── 1. change passphrase ───────────────────────────────

describe("Settings › Security › Change passphrase (vault.set_passphrase)", () => {
  const CURRENT = "the-current-passphrase-41";
  const NEXT = "a-brand-new-passphrase-77";

  function typeInto(logic: any, current: string, next: string, again: string) {
    const v = logic.renderVals();
    v.onAdminPass({ target: { value: current } });
    v.onAdminNew({ target: { value: next } });
    v.onAdminNewRepeat({ target: { value: again } });
  }

  it("asks for the current passphrase and the new one twice, then shows the NEW recovery code once, keeping no passphrase anywhere", async () => {
    const calls = fakeShell({ vault_set_passphrase: ROTATED });
    const logic = logicWith();
    const seen: string[] = [];
    const snap = () => seen.push(JSON.stringify(logic.state));

    logic.renderVals().openChangePassphrase();
    expect(logic.state.dialog).toBe("adminPass");
    const v = logic.renderVals();
    expect(v.dlgAdminPass).toBe(true);
    expect(v.adminPassNewShow).toBe(true);
    expect(v.adminPassRepeatShow).toBe(false); // the backup's repeat box is not this dialog's
    expect(v.adminPassLabel).toBe("current passphrase");
    expect(v.adminPassBody).toMatch(/recovery code/);

    typeInto(logic, CURRENT, NEXT, NEXT);
    snap();
    await logic.submitAdminPass();
    snap();

    expect(calls).toEqual([{ cmd: "vault_set_passphrase", args: { passphrase: CURRENT, newPassphrase: NEXT } }]); // and nothing read after it
    for (const s of seen) {
      expect(s).not.toContain(CURRENT);
      expect(s).not.toContain(NEXT);
    }
    expect(logic._adminPass).toBe("");
    expect(logic._adminNew).toBe("");
    expect(logic._adminNewRepeat).toBe("");

    // the recovery-code dialog the rotation uses, with the "write this down, it will not be shown again" treatment
    expect(logic.state.dialog).toBe("recovery");
    const r = logic.renderVals();
    expect(r.dlgRecovery).toBe(true);
    expect(r.recoveryCode).toBe("NEW1-CODE-2345");
    expect(r.recoveryNote).toMatch(/passphrase is changed/);
    expect(r.recoveryNote).toMatch(/previous recovery code no longer works/);
    expect(r.recoveryCloseDisabled).toBe(true); // closes only once "I have written it down" is ticked
    expect(logic.state.notice).toMatchObject({ kind: "success" });

    // Escape closes every dialog; the unacknowledged code comes back (only on the open vault's own screen)
    logic.model.status = "unlocked";
    logic.setState({ screen: "app" });
    const before = logic.state;
    logic.setState({ dialog: null });
    logic.afterUpdate(before);
    expect(logic.state.dialog).toBe("recovery");

    // acknowledged and closed: the code is gone from the logic
    r.onRecoverySaved({ target: { checked: true } });
    logic.renderVals().dismissRecovery();
    expect(logic.adm().recovery).toBeNull();
    expect(JSON.stringify(logic.state)).not.toContain("NEW1-CODE-2345");
  });

  it("refuses before calling anything: no current, no new, the two new ones differ, or the new one is the current one", async () => {
    const calls = fakeShell({ vault_set_passphrase: ROTATED });
    const logic = logicWith();
    const cases: Array<[string, string, string, string]> = [
      ["", NEXT, NEXT, "Enter the current passphrase."],
      [CURRENT, "", "", "Enter the new passphrase."],
      [CURRENT, NEXT, NEXT + "x", "The two new passphrases are different."],
      [CURRENT, CURRENT, CURRENT, "The new passphrase is the same as the current one."],
    ];
    for (const [cur, next, again, message] of cases) {
      logic.openAdminPass("passphrase");
      typeInto(logic, cur, next, again);
      await logic.submitAdminPass();
      expect(logic.state.fieldErrors.adminPass).toBe(message);
      expect(logic.state.dialog).toBe("adminPass");
    }
    expect(calls).toEqual([]);
  });

  it("a wrong current passphrase is said in the dialog, which stays open; nothing changed and no code is shown", async () => {
    const calls = fakeShell({ vault_set_passphrase: fail("wrong_passphrase") });
    const logic = logicWith();
    logic.openAdminPass("passphrase");
    typeInto(logic, "not-it", NEXT, NEXT);
    await logic.submitAdminPass();
    expect(calls.map((c) => c.cmd)).toEqual(["vault_set_passphrase"]);
    expect(logic.state.dialog).toBe("adminPass");
    expect(logic.state.fieldErrors.adminPass).toBeTruthy();
    expect(logic.adm().recovery).toBeNull();
  });

  it("the Security row is in both modes and opens the passphrase prompt", () => {
    fakeShell({});
    for (const mode of ["pro", "lite"] as const) {
      const logic = logicWith(mode);
      const v = logic.renderVals();
      expect(v.passphraseCaption).toMatch(/recovery code/);
      v.openChangePassphrase();
      expect(logic.adm().prompt).toEqual({ kind: "passphrase" });
    }
    const tpl = read("src/design/screens/S12-settings.html");
    expect(tpl).toContain('data-change-passphrase="1" onClick="{{openChangePassphrase}}"');
    expect(read("src/design/screens/dlg-touch.html")).toContain('onChange="{{onAdminNewRepeat}}"');
  });

  it("the action sends exactly the bridge's keys and does not read the model afterwards", async () => {
    const calls = fakeShell({ vault_set_passphrase: ROTATED });
    const refreshed: unknown[] = [];
    const m = { refresh: async (s: unknown) => void refreshed.push(s) } as any;
    const r = await admin.changePassphrase(m, "old", "new");
    expect(r.recoveryCode).toBe("NEW1-CODE-2345");
    expect(r.passphraseChanged).toBe(true);
    expect(calls).toEqual([{ cmd: "vault_set_passphrase", args: { passphrase: "old", newPassphrase: "new" } }]);
    expect(refreshed).toEqual([]);
  });
});

// ─────────────────────────────── 2. start at login ───────────────────────────────

describe("start the broker at login (login_agent_*)", () => {
  const DAEMON = "/Applications/CredMgr.app/Contents/MacOS/credmgrd";
  const OFF = { installed: false, current: false, loaded: false, daemon: DAEMON };
  const ON = { installed: true, current: true, loaded: true, daemon: DAEMON };

  it("off a Mac (platform_unsupported) the row is not offered, and nothing else is called", async () => {
    const calls = fakeShell({ login_agent_status: fail("platform_unsupported", "bridge") });
    expect(await admin.loginAgentState()).toBeNull();
    const logic = logicWith();
    logic.loadLoginAgent();
    await flush();
    const v = logic.renderVals();
    expect(v.loginAgentShow).toBe(false);
    expect(v.bootLoginAgentShow).toBe(false);
    expect(calls.map((c) => c.cmd)).toEqual(["login_agent_status", "login_agent_status"]);
  });

  it("with no shell at all it asks nothing", async () => {
    expect(await admin.loginAgentState()).toBeNull();
  });

  it("turning it on installs at once (the row says what it writes); turning it off asks first, because it stops the broker", async () => {
    let state = OFF;
    const calls = fakeShell({
      login_agent_status: () => state,
      login_agent_install: () => (state = ON),
      login_agent_uninstall: () => (state = { ...OFF }),
    });
    const logic = logicWith();
    logic.loadLoginAgent();
    await flush();
    let v = logic.renderVals();
    expect(v.loginAgentShow).toBe(true);
    expect(v.loginAgentOn).toBe(false);
    expect(v.loginAgentLabel).toBe("off");
    expect(v.loginAgentCaption).toContain(DAEMON);
    expect(v.loginAgentCaption).toMatch(/never root/);

    await v.toggleLoginAgent();
    await flush();
    expect(calls.filter((c) => c.cmd.startsWith("login_agent_") && c.cmd !== "login_agent_status")).toEqual([{ cmd: "login_agent_install", args: {} }]);
    v = logic.renderVals();
    expect(v.loginAgentOn).toBe(true);
    expect(v.loginAgentLabel).toBe("on");

    await v.toggleLoginAgent(); // the first click only asks
    v = logic.renderVals();
    expect(v.loginAgentOffAsk).toBe(true);
    expect(calls.some((c) => c.cmd === "login_agent_uninstall")).toBe(false);
    v.keepLoginAgent();
    expect(logic.renderVals().loginAgentOffAsk).toBe(false);

    await logic.renderVals().toggleLoginAgent();
    await logic.renderVals().confirmLoginAgentOff();
    await flush();
    expect(calls.filter((c) => c.cmd === "login_agent_uninstall")).toEqual([{ cmd: "login_agent_uninstall", args: {} }]);
    expect(logic.renderVals().loginAgentOn).toBe(false);
  });

  it("with no credmgrd found the switch cannot be turned on, and says why", async () => {
    fakeShell({ login_agent_status: { ...OFF, daemon: null } });
    const logic = logicWith();
    logic.loadLoginAgent();
    await flush();
    const v = logic.renderVals();
    expect(v.loginAgentDisabled).toBe(true);
    expect(v.loginAgentCaption).toMatch(/No credmgrd was found/);
    expect(v.bootLoginAgentShow).toBe(false);
  });

  it("an agent pointing at another credmgrd offers to update it, and updating installs again", async () => {
    const calls = fakeShell({ login_agent_status: { ...ON, current: false }, login_agent_install: ON });
    const logic = logicWith();
    logic.loadLoginAgent();
    await flush();
    const v = logic.renderVals();
    expect(v.loginAgentLabel).toBe("update");
    await v.toggleLoginAgent();
    expect(calls.some((c) => c.cmd === "login_agent_install")).toBe(true);
  });

  it("a refusal from the shell is said in a notice chosen by code, never the shell's own words", async () => {
    fakeShell({ login_agent_status: OFF, login_agent_install: { __error: { source: "bridge", code: "login_agent_failed", message: "launchctl said /secret/path" } } });
    const logic = logicWith();
    logic.loadLoginAgent();
    await flush();
    await logic.renderVals().toggleLoginAgent();
    expect(logic.state.notice).toMatchObject({ kind: "error" });
    expect(logic.state.notice.text).not.toContain("/secret/path");
    expect(logic.state.loginAgentBusy).toBe(false);
  });

  it("the broker-down screen offers it when the agent is not loaded, and retries the boot after starting it", async () => {
    const calls = fakeShell({ login_agent_status: OFF, login_agent_install: ON });
    const logic = logicWith();
    let retried = 0;
    logic.retryBoot = () => void retried++;
    logic.showBrokerDown();
    await flush();
    expect(logic.state.screen).toBe("brokerdown");
    const v = logic.renderVals();
    expect(v.isBrokerDown).toBe(true);
    expect(v.bootLoginAgentShow).toBe(true);
    await v.bootLoginAgent();
    expect(calls.map((c) => c.cmd)).toContain("login_agent_install");
    await new Promise((r) => setTimeout(r, 1600));
    expect(retried).toBe(1);
    expect(read("src/design/screens/boot.html")).toContain('onClick="{{bootLoginAgent}}"');
  });
});

// ─────────────────────────────── 3. Touch ID without a Secure Enclave ───────────────────────────────

describe("the Touch ID row and the protection line (presence.status secureEnclave)", () => {
  const probe = (secureEnclave: boolean) => ({ secureEnclave, biometry: secureEnclave ? "touchid" : "none", passcode: true, keyOnThisMac: false });
  const status = (secureEnclave: boolean, touchIdUnlock: boolean) => ({ helper: true, secureEnclave, biometry: secureEnclave ? "touchid" : "none", passcode: true, enrolled: [], touchIdUnlock });

  async function withAnswers(se: boolean, on: boolean) {
    const calls = fakeShell({ presence_probe: probe(se), presence_status: status(se, on) });
    const logic = logicWith();
    logic.loadTouch();
    await flush();
    await flush();
    return { logic, calls, v: logic.renderVals() };
  }

  it("no Secure Enclave: the row is shown greyed out and says why, Set up does nothing, and the line says passphrase only", async () => {
    const { logic, calls, v } = await withAnswers(false, false);
    expect(v.touchShow).toBe(true); // shown, not hidden
    expect(v.touchNoEnclave).toBe(true);
    expect(v.touchSetupDisabled).toBe(true);
    expect(v.touchCaption).toMatch(/^This Mac has no Secure Enclave/);
    expect(v.touchChipLabel).toBe("unavailable");
    expect(v.protectionShow).toBe(true);
    expect(v.protectionLine).toBe("Protected by your passphrase only; this Mac has no Secure Enclave.");
    const before = calls.length;
    v.touchSetUp();
    await flush();
    expect(calls.length).toBe(before);
    expect(logic.state.touchBusy).toBeFalsy();
  });

  it("a Secure Enclave with Touch ID on: the row works and the line says passphrase plus Touch ID", async () => {
    const { v } = await withAnswers(true, true);
    expect(v.touchShow).toBe(true);
    expect(v.touchNoEnclave).toBe(false);
    expect(v.touchSetupDisabled).toBe(false);
    expect(v.touchChipLabel).toBe("on");
    expect(v.protectionLine).toBe("Protected by your passphrase, plus Touch ID on this Mac.");
  });

  it("a Secure Enclave with Touch ID off: Set up is offered and the line says passphrase only", async () => {
    const { v } = await withAnswers(true, false);
    expect(v.touchSetupDisabled).toBe(false);
    expect(v.touchChipLabel).toBe("off");
    expect(v.protectionLine).toBe("Protected by your passphrase only. Touch ID is not set up on this Mac.");
  });

  it("presence.status is what decides; the probe is the fallback only when the status does not say", () => {
    fakeShell({});
    const logic = logicWith();
    logic.setState({ touch: { probe: probe(true), status: status(false, false) } });
    expect(logic.renderVals().touchNoEnclave).toBe(true);
    logic.setState({ touch: { probe: probe(false), status: { ...status(true, false), secureEnclave: undefined } } });
    expect(logic.renderVals().touchNoEnclave).toBe(true);
  });

  it("when nothing is known (not a Mac, no shell) there is no row and no line, rather than a guess", () => {
    fakeShell({});
    const v = logicWith().renderVals();
    expect(v.touchShow).toBe(false);
    expect(v.protectionShow).toBe(false);
  });
});

// ─────────────────────────────── 4. the anomaly bar ───────────────────────────────

describe("the cross-node anomaly bar (vault.status anomaliesUnseen, vault.anomalies_ack)", () => {
  const OPEN = { locked: false, authenticated: true, initialized: true };

  async function openWith(answers: Record<string, Answer>, mode: "pro" | "lite" = "pro") {
    const calls = fakeShell(answers);
    const logic = logicWith(mode);
    logic.model.status = "unlocked"; // the liveness check asks only while the model believes it is open
    logic.setState({ screen: "app" });
    await logic.model.checkSession();
    return { logic, calls };
  }

  it("shows when vault.status counts unseen alarms, says what happened, and the dismiss acknowledges it", async () => {
    let unseen = 2;
    const { logic, calls } = await openWith({ vault_status: () => ({ ...OPEN, ...(unseen ? { anomaliesUnseen: unseen } : {}) }), vault_anomalies_ack: () => ({ acknowledged: ((unseen = 0), 2) }) });
    let v = logic.renderVals();
    expect(v.anomalyBannerShow).toBe(true);
    expect(v.anomalyBannerText).toMatch(/blocked 2 times/);
    expect(v.anomalyBannerText).toMatch(/refused requests/);
    expect(v.anomalyAuditShow).toBe(true);

    await v.dismissAnomalyBanner();
    expect(calls.filter((c) => c.cmd === "vault_anomalies_ack")).toEqual([{ cmd: "vault_anomalies_ack", args: {} }]);
    v = logic.renderVals();
    expect(v.anomalyBannerShow).toBe(false);
    await logic.model.checkSession(); // and the next status (count gone) keeps it gone
    expect(logic.renderVals().anomalyBannerShow).toBe(false);
  });

  it("the link opens the audit view and acknowledges the alarm too", async () => {
    const { logic, calls } = await openWith({ vault_status: { ...OPEN, anomaliesUnseen: 1 }, vault_anomalies_ack: { acknowledged: 1 }, audit_tail: { records: [] } });
    const v = logic.renderVals();
    expect(v.anomalyBannerText).toMatch(/^An agent was blocked/);
    await v.anomalyOpenAudit();
    expect(logic.state.overlay).toBe("settings");
    expect(logic.state.setSection).toBe("audit");
    expect(calls.map((c) => c.cmd)).toContain("vault_anomalies_ack");
    expect(logic.model.anomaliesUnseen).toBe(0);
  });

  it("in Lite mode there is no audit button, and the words say where the audit view is", async () => {
    const { logic } = await openWith({ vault_status: { ...OPEN, anomaliesUnseen: 1 } }, "lite");
    const v = logic.renderVals();
    expect(v.anomalyBannerShow).toBe(true);
    expect(v.anomalyAuditShow).toBe(false);
    expect(v.anomalyBannerText).toMatch(/Pro mode/);
  });

  it("no count (absent, 0, or not a number) shows no bar; a lock drops the count with the login", async () => {
    for (const status of [OPEN, { ...OPEN, anomaliesUnseen: 0 }]) {
      const { logic } = await openWith({ vault_status: status });
      expect(logic.renderVals().anomalyBannerShow).toBe(false);
    }
    const { logic } = await openWith({ vault_status: { ...OPEN, anomaliesUnseen: 4 } });
    expect(logic.model.anomaliesUnseen).toBe(4);
    logic.model.clear();
    expect(logic.model.anomaliesUnseen).toBe(0);
  });

  it("a refused acknowledgement goes through the router and the bar stays", async () => {
    const { logic } = await openWith({ vault_status: { ...OPEN, anomaliesUnseen: 1 }, vault_anomalies_ack: fail("capability_not_held") });
    await logic.renderVals().dismissAnomalyBanner();
    expect(logic.renderVals().anomalyBannerShow).toBe(true);
    expect(logic.state.notice).toBeTruthy();
  });

  it("the bar sits under the header with the pending banner, and names the count only", () => {
    const tpl = read("src/design/screens/S20-banner.html");
    expect(tpl).toContain('data-screen-label="S20b Anomaly alarm"');
    expect(tpl).toContain('onClick="{{dismissAnomalyBanner}}"');
    expect(tpl).toContain('onClick="{{anomalyOpenAudit}}"');
  });
});
