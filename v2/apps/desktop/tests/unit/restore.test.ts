// ADR-166: Restore from a backup (Settings › Backup › Restore…, and the broker-unreachable screen).  The logic runs through the real bridge
// client against the fixture broker (tests/fixtures/broker/admin.js `backup_restore`, which answers what the shell's `credmgr restore
// --json` answers), with the shell's `invoke` wrapped so the command name and argument keys are the ones asserted here.
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import Component from "../../src/design/logic/core.js";
import { restoredLines } from "../../src/design/logic/restore.js";
import { classifyError } from "../../src/vault/errors";
import { brokerScript } from "../fixtures/broker/script.mjs";

const ROOT = resolve(__dirname, "../..");
const read = (rel: string) => readFileSync(resolve(ROOT, rel), "utf8");
const g = globalThis as unknown as { window?: any };
const PASS = "fixture-backup-passphrase";

function fixture() {
  const win: any = {};
  g.window = win;
  new Function("window", brokerScript({ locked: false }))(win);
  const calls: { cmd: string; args: Record<string, unknown> }[] = [];
  const inner = win.__TAURI_INTERNALS__.invoke;
  win.__TAURI_INTERNALS__.invoke = async (cmd: string, args: Record<string, unknown> = {}) => {
    calls.push({ cmd, args: JSON.parse(JSON.stringify(args)) });
    return inner(cmd, args);
  };
  return { calls, win };
}

const flush = async (n = 8) => {
  for (let i = 0; i < n; i++) await new Promise((r) => setTimeout(r, 0));
};

async function app() {
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
  logic.state = { ...logic.state, screen: "app", overlay: "settings", setSection: "backup", dialog: null };
  return { logic, notes, ...fx };
}

/** The broker stops: the window shows the broker-unreachable screen, which is where a restore can go through. */
async function brokerDown(logic: any, win: any) {
  win.__brokerFixture.S.unreachable = true;
  logic.model.clear("broker-down");
  logic.showBrokerDown();
  await flush();
  expect(logic.state.screen).toBe("brokerdown");
  expect(logic.renderVals().isBrokerDown).toBe(true);
}

afterEach(() => {
  delete g.window;
});

describe("what a finished restore says", () => {
  it("files and folder, the counter, the old format, and what to do next", () => {
    const lines = restoredLines({ target: "/r", stateDir: "/s", files: 1, bytes: 9, counter: "keptExisting", complete: false });
    expect(lines[0]).toBe("1 file restored into /r.");
    expect(lines[1]).toContain("/s already had a generation counter and it was kept");
    expect(lines[2]).toContain("predates the complete format");
    expect(lines.at(-1)).toContain("unlock with your vault passphrase, then run Verify");
    expect(restoredLines({ target: "/r", stateDir: "/s", files: 3, bytes: 9, counter: "restored", complete: true })[1]).toBe(
      "The generation counter was restored into /s.",
    );
  });

  it("each refusal is said in words chosen here, next to the form", () => {
    for (const code of ["broker_running", "restore_target_not_empty", "restore_failed", "restore_unavailable"]) {
      const r = classifyError({ source: "bridge", code, message: "the command's own words" }, { field: "restore.save" });
      expect(r.route).toBe("inline");
      expect((r as { field: string }).field).toBe("restore.save");
      expect((r as { message: string }).message).not.toContain("the command's own words");
    }
    const running = classifyError({ source: "bridge", code: "broker_running", message: "x" }, { field: "restore.save" }) as { message: string };
    expect(running.message).toContain("Quit CredMgr");
    expect(running.message).toContain("credmgr restore");
  });
});

describe("Restore… (backup_restore)", () => {
  it("is refused with broker_running while this window's broker answers, said next to the form, and the passphrase is not kept", async () => {
    const { logic, calls } = await app();
    let v = logic.renderVals();
    v.openRestore();
    v = logic.renderVals();
    expect(v.dlgRestore).toBe(true);
    expect(v.rsLiveShow).toBe(true); // this window is connected to a running broker: said before the press
    expect(v.rsSaveDisabled).toBe(true);
    v.onRsArchive({ target: { value: " /fixture/backups/a.enc " } });
    logic.renderVals().onRsPass({ target: { value: PASS } });
    v = logic.renderVals();
    expect(v.rsSaveDisabled).toBe(false);
    await v.saveRestoreForm();
    await flush();
    expect(calls.filter((c) => c.cmd === "backup_restore")).toEqual([{ cmd: "backup_restore", args: { archive: "/fixture/backups/a.enc", passphrase: PASS } }]);
    v = logic.renderVals();
    expect(v.rsErrShow).toBe(true);
    expect(v.rsErr).toContain("never runs beside it");
    expect(logic.state.dialog).toBe("restoreBackup"); // kept for the person to read
    v.cancelRestoreDlg();
    expect(logic.state.restoreForm).toBe(null);
    expect(JSON.stringify(logic.state)).not.toContain(PASS);
  });

  it("with no broker running it restores into the folder given, shows what was written, and drops the passphrase", async () => {
    const { logic, calls, win, notes } = await app();
    await brokerDown(logic, win);
    logic.renderVals().openRestore();
    logic.renderVals().onRsArchive({ target: { value: "/fixture/backups/a.enc" } });
    logic.renderVals().onRsTarget({ target: { value: "/fixture/new" } });
    logic.renderVals().onRsPass({ target: { value: PASS } });
    await logic.renderVals().saveRestoreForm();
    await flush();
    expect(calls.filter((c) => c.cmd === "backup_restore")).toEqual([
      { cmd: "backup_restore", args: { archive: "/fixture/backups/a.enc", passphrase: PASS, target: "/fixture/new" } },
    ]);
    const v = logic.renderVals();
    expect(v.rsDoneShow).toBe(true);
    expect(v.rsLiveShow).toBe(false); // no broker: nothing to warn about
    expect(v.rsFormShow).toBe(false);
    expect(v.rsDoneLines[0].text).toBe("12 files restored into /fixture/new.");
    expect(v.rsCloseLabel).toBe("Close");
    expect(logic.state.restoreForm.passphrase).toBe("");
    expect(notes.at(-1)).toEqual(["success", "Backup restored: 12 files written."]);
    expect(win.__brokerFixture.S.restored).toEqual([{ archive: "/fixture/backups/a.enc", target: "/fixture/new" }]);
  });

  it("a used folder and a wrong passphrase are said, and nothing is restored", async () => {
    const { logic, win } = await app();
    await brokerDown(logic, win);
    logic.renderVals().openRestore();
    logic.renderVals().onRsArchive({ target: { value: "/fixture/backups/a.enc" } });
    logic.renderVals().onRsTarget({ target: { value: "/fixture/used" } });
    logic.renderVals().onRsPass({ target: { value: PASS } });
    await logic.renderVals().saveRestoreForm();
    await flush();
    expect(logic.renderVals().rsErr).toContain("That folder is not empty");
    logic.renderVals().onRsTarget({ target: { value: "/fixture/new" } });
    logic.renderVals().onRsPass({ target: { value: "wrong" } });
    await logic.renderVals().saveRestoreForm();
    await flush();
    expect(logic.renderVals().rsErr).toContain("passphrase is wrong");
    expect(win.__brokerFixture.S.restored).toBeUndefined();
  });
});

describe("the template", () => {
  it("Settings › Backup and the broker-unreachable screen open the dialog, which is outside the unlocked app", () => {
    expect(read("src/design/screens/S12-settings.html")).toContain("{{openRestore}}");
    expect(read("src/design/screens/boot.html")).toContain("{{openRestore}}");
    const tpl = read("src/design/app.template.html");
    expect(tpl.indexOf('<sc-include src="./screens/dlg-restore.html"></sc-include>')).toBeGreaterThan(tpl.lastIndexOf("</sc-if>"));
    const dlg = read("src/design/screens/dlg-restore.html");
    for (const b of ["{{saveRestoreForm}}", "{{onRsPass}}", 'type="password"', "{{rsDoneLines}}"]) expect(dlg).toContain(b);
  });
});
