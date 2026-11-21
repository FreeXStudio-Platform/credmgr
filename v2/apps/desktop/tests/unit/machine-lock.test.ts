// ADR-165, the desktop half of the machine lock: the Security section's status line and Bind/Unbind controls, the dialog that asks first
// (and says what happens if this Mac is replaced), the bridge calls and what the error table says.  The logic runs exactly as in the app:
// the model reads through the real bridge client and the Tauri shell's `invoke` is the fixture broker (tests/fixtures/broker/admin.js),
// which answers keystore.* as crates/brokerd/src/ops.rs does.
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import Component from "../../src/design/logic/core.js";
import { classifyError } from "../../src/vault/errors";
import { brokerScript } from "../fixtures/broker/index";

interface FixtureControl {
  calls(cmd?: string): Array<{ cmd: string; args: Record<string, unknown> }>;
  state(): Record<string, any>;
  set(patch: Record<string, unknown>): void;
}
const g = globalThis as unknown as { window?: any; document?: any };
const broker = (): FixtureControl => g.window.__BROKER__;
const ROOT = resolve(__dirname, "../..");
const read = (p: string) => readFileSync(resolve(ROOT, p), "utf8");
const settle = () => new Promise((r) => setTimeout(r, 5));

/** A logic instance on the unlocked app with Settings open on Security, over a fixture vault. */
async function security(options: Record<string, unknown> = {}) {
  g.window = {};
  new Function("window", brokerScript({ locked: false, ...options }))(g.window);
  const l: any = new (Component as any)({ mode: "pro" });
  l.__host = {
    setLogicState(update: any, cb?: () => void) {
      const patch = typeof update === "function" ? update(l.state) : update;
      if (patch) l.state = { ...l.state, ...patch };
      cb?.();
    },
    forceUpdate() {},
  };
  await l.model.boot();
  expect(l.model.status).toBe("unlocked");
  l.state = { ...l.state, screen: "app", overlay: "settings", setSection: "security" };
  l._mlAsked = false;
  l.loadMachineLock();
  await settle();
  return l;
}

/** Open the dialog in the given direction and type into its fields, as the inputs' onChange handlers do. */
function typeInto(l: any, on: boolean, fields: { passphrase?: string; code?: string } = {}) {
  l.askMachineLock(on);
  const v = l.renderVals();
  if (fields.passphrase !== undefined) v.onMachineLockPass({ target: { value: fields.passphrase } });
  if (fields.code !== undefined) v.onMachineLockCode({ target: { value: fields.code } });
}
const PASS = "fixture-passphrase";
const ROOT_CODE = "FIXT-ROOT-RECO-VERY-0001";
/** Bind through the dialog: the passphrase and the current recovery code (step one), then the new code it shows typed back (step two). */
async function bindNow(l: any) {
  typeInto(l, true, { passphrase: PASS, code: broker().state().rootRecoveryCode });
  await l.setMachineLock(true);
  await settle();
  if (l.state.machineLockAsk === "confirm") {
    l.renderVals().onMachineLockRetype({ target: { value: l.renderVals().machineLockNewCode } });
    await l.setMachineLock(true);
    await settle();
  }
}

beforeEach(() => {
  g.document = { querySelector: () => null, querySelectorAll: () => [], documentElement: { dataset: {}, style: { setProperty() {}, removeProperty() {} } } };
});
afterEach(async () => {
  await settle();
  delete g.window;
  delete g.document;
});

describe("the Security section's machine lock row", () => {
  it("shows the honest state: off, a key file when on, never the Secure Enclave", async () => {
    const l = await security();
    let v = l.renderVals();
    expect(v).toMatchObject({ machineLockShow: true, machineLockOn: false, machineLockChipLabel: "off", machineLockLabel: "Bind…", machineLockDisabled: false });
    expect(v.machineLockCaption).toMatch(/does not protect a stolen or unlocked Mac/);
    expect(broker().calls("keystore_status")).toHaveLength(1);

    v.toggleMachineLock();
    l.renderVals().onMachineLockPass({ target: { value: PASS } });
    l.renderVals().onMachineLockCode({ target: { value: ROOT_CODE } });
    l.renderVals().confirmMachineLock();
    await settle();
    // Review N1: step two shows the new code and asks for it back; nothing is on yet.
    v = l.renderVals();
    expect(v).toMatchObject({ dlgMachineLock: true, machineLockConfirmStep: true, machineLockBind: false, machineLockOn: false, machineLockConfirmLabel: "Turn the lock on" });
    v.onMachineLockRetype({ target: { value: v.machineLockNewCode } });
    v.confirmMachineLock();
    await settle();
    v = l.renderVals();
    expect(v).toMatchObject({ machineLockOn: true, machineLockChipLabel: "on · file", machineLockChipState: "ok", machineLockLabel: "Unbind…" });
    expect(v.machineLockCaption).toMatch(/device key file on this Mac \(not the Secure Enclave\)/);
    expect(v.machineLockCaption).toMatch(/recovery code/);
    expect(l.state.machineLock.secureEnclave).toBe(false);
  });

  it("asks first: Bind opens the dialog that says what happens if this Mac is replaced, and Cancel changes nothing", async () => {
    const l = await security();
    l.renderVals().toggleMachineLock();
    let v = l.renderVals();
    expect(v).toMatchObject({ dlgMachineLock: true, machineLockBind: true, machineLockUnbind: false, machineLockConfirmStep: false, machineLockConfirmLabel: "Next" });
    expect(broker().calls("keystore_bind")).toEqual([]);
    v.cancelMachineLock();
    v = l.renderVals();
    expect(v.dlgMachineLock).toBe(false);
    expect(broker().calls("keystore_bind")).toEqual([]);
    expect(broker().state().machineLock).toBeFalsy();

    // The dialog's own words: the replaced-Mac paragraph names the recovery code and the Lock screen's way in; nothing claims the Secure Enclave.
    const html = read("src/design/screens/S12-settings.html");
    const dlg = html.slice(html.indexOf('{{dlgMachineLock}}'), html.indexOf('<sc-if value="{{ovSettings}}"'));
    expect(dlg).toMatch(/If you replace this Mac/);
    expect(dlg).toMatch(/Forgot passphrase\? Use recovery code/);
    expect(dlg).toMatch(/not a key sealed in the Secure Enclave/);
    expect(dlg).toMatch(/does not protect a stolen or unlocked Mac/);
    // Review P0-1 / P1-3 / P2-6: what a copy made before already held, Time Machine and Migration Assistant, backups, a second Mac.
    expect(dlg).toMatch(/Copies made before now<\/strong> still open with the passphrase, and still show what they held then/);
    // ADR-174 O-2: the device key is kept out of Time Machine, so the dialog no longer lists Time Machine as uncovered.
    expect(dlg).toMatch(/The device key is kept out of Time Machine/);
    expect(dlg).toMatch(/a whole-disk image or Migration Assistant/);
    expect(dlg).not.toMatch(/unlocked Mac, Time Machine/);
    expect(dlg).toMatch(/CredMgr backups/);
    expect(dlg).toMatch(/Another Mac sharing this vault folder needs the recovery code/);
    expect(dlg).toMatch(/gives you a <strong>new<\/strong> recovery code/);
    // Review N1: the new code is shown and typed back before anything changes; review N2: where backups are kept while the lock is on.
    expect(dlg).toMatch(/asked to type it back <strong>before<\/strong> anything changes/);
    expect(dlg).toMatch(/data-machine-lock-retype="1"/);
    expect(dlg).toMatch(/Nothing has changed yet/);
    expect(dlg).toMatch(/kept outside the vault folder, in CredMgr's state folder/);
    // Review P1-1: the passphrase and the current recovery code are typed in the dialog, never kept in React state.
    expect(dlg).toMatch(/data-machine-lock-pass="1"/);
    expect(dlg).toMatch(/data-machine-lock-code="1"/);
  });

  it("binds in two steps: the first changes nothing and shows the NEW code, the second takes it typed back (review N1)", async () => {
    const l = await security();
    typeInto(l, true, { passphrase: PASS, code: ` ${ROOT_CODE} ` });
    await l.setMachineLock(true);
    expect(broker().calls("keystore_bind")).toEqual([{ cmd: "keystore_bind", args: { phase: "prepare", passphrase: PASS, recoveryCode: ROOT_CODE } }]);
    // Nothing changed: not bound, the old code is still the vault's, and the typed values are gone.
    expect(broker().state().machineLock).toBeFalsy();
    expect(broker().state().rootRecoveryCode).toBe(ROOT_CODE);
    expect(l._mlPass).toBe("");
    expect(l._mlCode).toBe("");
    expect(JSON.stringify(l.state)).not.toContain(PASS);
    let v = l.renderVals();
    expect(v).toMatchObject({ dlgMachineLock: true, machineLockConfirmStep: true, machineLockNewCode: "FIXTURE-BOUND-ROOT-1", machineLockTitle: "write down your new recovery code" });

    // Nothing typed back, then a wrong code: the dialog stays, nothing changes, and the prepared bind still waits.
    await l.setMachineLock(true);
    expect(l.renderVals().machineLockError).toMatch(/Type the new recovery code back/);
    v.onMachineLockRetype({ target: { value: ROOT_CODE } });
    await l.setMachineLock(true);
    await settle();
    v = l.renderVals();
    expect(v.machineLockConfirmStep).toBe(true);
    expect(v.machineLockError).toMatch(/not the code shown above\. Nothing has changed/);
    expect(broker().state().machineLock).toBeFalsy();
    expect(broker().state().rootRecoveryCode).toBe(ROOT_CODE);

    // The right code: only now is the lock on and the code replaced.  No recovery dialog follows: the person has just typed it.
    v.onMachineLockRetype({ target: { value: " FIXTURE-BOUND-ROOT-1 " } });
    await l.setMachineLock(true);
    await settle();
    expect(broker().calls("keystore_bind").slice(-1)).toEqual([{ cmd: "keystore_bind", args: { phase: "commit", recoveryCode: "FIXTURE-BOUND-ROOT-1" } }]);
    expect(broker().state().machineLock).toBe(true);
    expect(broker().state().rootRecoveryCode).toBe("FIXTURE-BOUND-ROOT-1");
    expect(l.state.dialog).toBeNull();
    expect(l.state.machineLockShown).toBeNull();
    expect(l._mlRetype).toBe("");
    expect(l.state.notice?.text).toMatch(/only one that works/);
  });

  it("closing the dialog between the steps changes nothing and tells the broker to forget the prepared bind (review N1)", async () => {
    const l = await security();
    typeInto(l, true, { passphrase: PASS, code: ROOT_CODE });
    await l.setMachineLock(true);
    expect(l.renderVals().machineLockConfirmStep).toBe(true);
    l.renderVals().cancelMachineLock();
    await settle();
    expect(broker().calls("keystore_bind").slice(-1)).toEqual([{ cmd: "keystore_bind", args: { phase: "cancel" } }]);
    expect(broker().state().machineLockPending).toBeNull();
    expect(broker().state().machineLock).toBeFalsy();
    expect(broker().state().rootRecoveryCode).toBe(ROOT_CODE);
    expect(l.state.machineLockShown).toBeNull();

    // Escape (core.js closes every dialog): the same.
    typeInto(l, true, { passphrase: PASS, code: ROOT_CODE });
    await l.setMachineLock(true);
    const prev = l.state;
    l.state = { ...l.state, dialog: null };
    l.afterUpdate(prev);
    await settle();
    expect(broker().calls("keystore_bind").slice(-1)).toEqual([{ cmd: "keystore_bind", args: { phase: "cancel" } }]);
    expect(broker().state().machineLock).toBeFalsy();
    expect(l.state.machineLockShown).toBeNull();
  });

  it("a commit after the prepared bind was forgotten (a lock in between) changes nothing and says to start again (review N1)", async () => {
    const l = await security();
    typeInto(l, true, { passphrase: PASS, code: ROOT_CODE });
    await l.setMachineLock(true);
    const shown = l.renderVals().machineLockNewCode;
    broker().set({ machineLockPending: null });
    l.renderVals().onMachineLockRetype({ target: { value: shown } });
    await l.setMachineLock(true);
    await settle();
    expect(broker().state().machineLock).toBeFalsy();
    expect(broker().state().rootRecoveryCode).toBe(ROOT_CODE);
    expect(l.state.dialog).toBeNull();
    expect(l.state.notice?.text).toMatch(/ran out or was overtaken/);
    expect(l.state.notice?.text).toMatch(/current recovery code still works/);
  });

  it("asks for both values before calling, and a wrong recovery code changes nothing", async () => {
    const l = await security();
    typeInto(l, true, { passphrase: PASS });
    await l.setMachineLock(true);
    expect(broker().calls("keystore_bind")).toEqual([]);
    expect(l.renderVals().machineLockError).toMatch(/current recovery code/);
    typeInto(l, true, { code: ROOT_CODE });
    await l.setMachineLock(true);
    expect(broker().calls("keystore_bind")).toEqual([]);
    expect(l.renderVals().machineLockError).toMatch(/vault passphrase/);

    typeInto(l, true, { passphrase: PASS, code: "NOT-THE-CODE" });
    await l.setMachineLock(true);
    await settle();
    expect(broker().calls("keystore_bind")).toHaveLength(1);
    expect(broker().state().machineLock).toBeFalsy();
    expect(broker().state().rootRecoveryCode).toBe(ROOT_CODE);
    expect(l.state.dialog).not.toBe("recovery");
  });

  it("an unfinished bind (status names projects still on a pre-bind key) offers Bind again and says why", async () => {
    const l = await security();
    await bindNow(l);
    broker().set({ machineLockPreBind: ["atlas"] });
    l._mlAsked = false;
    l.loadMachineLock();
    await settle();
    const v = l.renderVals();
    expect(v).toMatchObject({ machineLockLabel: "Bind…", machineLockChipState: "warn" });
    expect(v.machineLockCaption).toMatch(/did not finish: atlas/);
    v.toggleMachineLock();
    expect(l.renderVals().machineLockBind).toBe(true);
  });

  it("says so when an older plain passphrase file sits under a vault recorded as bound", async () => {
    const l = await security();
    broker().set({ machineLockPlainWhileBound: true });
    l._mlAsked = false;
    l.loadMachineLock();
    await settle();
    const v = l.renderVals();
    expect(v.machineLockChipState).toBe("danger");
    expect(v.machineLockCaption).toMatch(/recorded the vault as bound, but the passphrase file on disk is plain/);
  });

  it("says so, in the broker's words and with a warn chip, when this Mac's record no longer matches the folder's vault.id (ADR-165 M5)", async () => {
    const l = await security();
    await bindNow(l);
    const binds = broker().calls("keystore_bind").length;
    broker().set({ machineLockRecordDetached: true });
    l._mlAsked = false;
    l.loadMachineLock();
    await settle();
    const v = l.renderVals();
    expect(v.machineLockChipState).toBe("warn");
    expect(v.machineLockCaption).toMatch(/but its vault\.id is none/);
    expect(v.machineLockCaption).toMatch(/Nothing was repaired/);
    // Reported, never repaired: the row still offers what it offered (Unbind on a bound vault), nothing is called.
    expect(v.machineLockLabel).toBe("Unbind…");
    expect(broker().calls("keystore_bind").length).toBe(binds);
  });

  it("offers no Bind on a vault without a recovery code, and says how to get one", async () => {
    const l = await security({ recoveryUnlock: false });
    const v = l.renderVals();
    expect(v).toMatchObject({ machineLockOn: false, machineLockDisabled: true });
    expect(v.machineLockCaption).toMatch(/Needs a recovery code first/);
    // and if a stale screen sends it anyway, the broker's refusal is routed to words chosen here, nothing changed
    typeInto(l, true, { passphrase: PASS, code: ROOT_CODE });
    await l.setMachineLock(true);
    expect(broker().state().machineLock).toBeFalsy();
    expect(l.state.notice?.text).toMatch(/needs a recovery code set up first/);
  });

  it("with a second factor and no Touch ID, asks for a fresh authenticator code before step one, and again if the window closed (ADR-174 O-5)", async () => {
    const l = await security({ gate: true, gateCode: "123456" });
    let v = l.renderVals();
    expect(l.state.machineLock.bindProof).toBe("secondFactor");
    v.toggleMachineLock();
    v = l.renderVals();
    expect(v).toMatchObject({ machineLockBind: true, machineLockFactorShow: true });
    expect(v.machineLockProofNote).toMatch(/second factor is asked for too/);
    // Without the code: nothing is sent.
    v.onMachineLockPass({ target: { value: PASS } });
    v.onMachineLockCode({ target: { value: broker().state().rootRecoveryCode } });
    await l.setMachineLock(true);
    expect(l.state.machineLockError).toMatch(/6-digit code from your authenticator/);
    expect(broker().calls("keystore_bind")).toEqual([]);
    // A wrong code is refused by the step-up; nothing is sent either.
    l.renderVals().onMachineLockFactor({ target: { value: "000000" } });
    await l.setMachineLock(true);
    await settle();
    expect(broker().calls("keystore_bind")).toEqual([]);
    expect(l.state.dialog).toBe("machineLock");
    // The right one: the step-up, then step one.
    l.renderVals().onMachineLockPass({ target: { value: PASS } });
    l.renderVals().onMachineLockCode({ target: { value: broker().state().rootRecoveryCode } });
    l.renderVals().onMachineLockFactor({ target: { value: "123456" } });
    await l.setMachineLock(true);
    await settle();
    expect(broker().calls("vault_gate_verify").length).toBeGreaterThanOrEqual(1);
    expect(l.state.machineLockAsk).toBe("confirm");
    expect(l._mlFactor).toBe("");
    // The five minutes run out while the code is written down: the commit asks again and the prepared bind waits.
    broker().set({ elevated: false });
    v = l.renderVals();
    v.onMachineLockRetype({ target: { value: v.machineLockNewCode } });
    await l.setMachineLock(true);
    await settle();
    v = l.renderVals();
    expect(broker().state().machineLock).toBeFalsy();
    expect(v).toMatchObject({ machineLockConfirmStep: true, machineLockFactorAgainShow: true });
    expect(v.machineLockError).toMatch(/Five minutes have passed/);
    v.onMachineLockRetype({ target: { value: v.machineLockNewCode } });
    v.onMachineLockFactor({ target: { value: "123456" } });
    await l.setMachineLock(true);
    await settle();
    expect(broker().state().machineLock).toBe(true);
    expect(l.renderVals().machineLockOn).toBe(true);
  });

  it("with Touch ID set up, says each step asks for it (the shell attaches the proof) (ADR-174 O-5)", async () => {
    const l = await security({ touchId: true, gate: true });
    l.renderVals().toggleMachineLock();
    const v = l.renderVals();
    expect(v.machineLockFactorShow).toBe(false);
    expect(v.machineLockProofNote).toMatch(/Touch ID is asked for at each step/);
    l.state = { ...l.state, dialog: null };
    await bindNow(l);
    expect(broker().state().machineLock).toBe(true);
  });

  it("claims Time Machine only for a device key made already excluded, and says what an older key means (ADR-174 O-2)", async () => {
    const l = await security();
    await bindNow(l);
    expect(l.renderVals().machineLockCaption).toMatch(/a Time Machine backup included \(the key is kept out of it\)/);
    broker().set({ deviceKeyPredates: true });
    l._mlAsked = false;
    l.loadMachineLock();
    await settle();
    const c = l.renderVals().machineLockCaption;
    expect(c).not.toMatch(/a Time Machine backup included/);
    expect(c).toMatch(/Time Machine backups may hold this device key/);
    expect(c).toMatch(/turn the lock off and on again to replace it/);
    expect(l.state.machineLock.doesNotProtect).toMatch(/Time Machine backups that may hold this Mac's device key/);
  });

  it("offers no Bind on a vault folder another Mac can open, names the service, and a stale Bind changes nothing (ADR-174 O-3)", async () => {
    const l = await security();
    broker().set({ machineLockSyncedFolder: "iCloud Drive" });
    l._mlAsked = false;
    l.loadMachineLock();
    await settle();
    const v = l.renderVals();
    expect(v).toMatchObject({ machineLockOn: false, machineLockDisabled: true });
    expect(v.machineLockCaption).toMatch(/in iCloud Drive, which another Mac can open too/);
    expect(v.machineLockCaption).toMatch(/not synced/);
    typeInto(l, true, { passphrase: PASS, code: broker().state().rootRecoveryCode });
    await l.setMachineLock(true);
    await settle();
    expect(broker().state().machineLock).toBeFalsy();
    expect(broker().state().machineLockPending).toBeFalsy();
    expect(l.state.machineLockAsk).not.toBe("confirm");
  });

  // Review P2-8: this runs against the fixture broker, so it proves what the SCREEN does with a presence_required answer (asks first,
  // changes nothing, shows the presence notice). That the real broker answers it is proven in crates/brokerd/tests/machine_lock.rs
  // (unbind_needs_the_second_factor_and_presence_where_enrolled_and_keeps_the_device_key).
  it("Unbind asks first; the screen shows the presence notice on presence_required and nothing changes", async () => {
    const l = await security();
    await bindNow(l);
    l.state = { ...l.state, dialog: null };
    l.renderVals().toggleMachineLock();
    const v = l.renderVals();
    expect(v).toMatchObject({ dlgMachineLock: true, machineLockUnbind: true, machineLockConfirmLabel: "Turn off", machineLockCancelLabel: "Keep it on" });
    v.confirmMachineLock();
    await settle();
    expect(broker().calls("keystore_unbind")).toEqual([{ cmd: "keystore_unbind", args: {} }]);
    expect(broker().state().machineLock).toBe(true);
    expect(l.state.notice?.kind).toBe("presence");
    expect(l.renderVals().machineLockOn).toBe(true);
  });

  it("Unbind with Touch ID set up turns it off and keeps the device key", async () => {
    const l = await security({ touchId: true });
    await bindNow(l);
    const key = broker().state().deviceKeyId;
    typeInto(l, false);
    await l.setMachineLock(false);
    expect(broker().state().machineLock).toBe(false);
    expect(broker().state().deviceKeyId).toBe(key);
    expect(l.renderVals()).toMatchObject({ machineLockOn: false, machineLockChipLabel: "off" });
    expect(l.state.notice?.text).toMatch(/machine lock is off/);
  });

  it("Unbind with a second factor enrolled and not fresh says how to get a fresh one", async () => {
    const l = await security({ touchId: true, gate: true });
    await bindNow(l);
    typeInto(l, false);
    await l.setMachineLock(false);
    expect(broker().state().machineLock).toBe(true);
    expect(l.state.notice?.text).toMatch(/fresh second factor/);
  });

  it("Unbind with neither Touch ID nor a second factor sends the passphrase typed in the dialog (review P2-4)", async () => {
    const l = await security();
    await bindNow(l);
    broker().set({ noPresenceNoGate: true });
    typeInto(l, false);
    await l.setMachineLock(false);
    expect(broker().calls("keystore_unbind")).toEqual([{ cmd: "keystore_unbind", args: {} }]);
    expect(broker().state().machineLock).toBe(true);
    typeInto(l, false, { passphrase: PASS });
    await l.setMachineLock(false);
    expect(broker().calls("keystore_unbind")[1]).toEqual({ cmd: "keystore_unbind", args: { passphrase: PASS } });
    expect(broker().state().machineLock).toBe(false);
    expect(l._mlPass).toBe("");
  });
});

describe("a rotation that removed the machine lock is shown (review P1-4)", () => {
  it("the passphrase change warns that the lock is off now", async () => {
    const l = await security();
    await bindNow(l);
    broker().set({ machineLockSealFails: true });
    l.state = { ...l.state, dialog: null, notice: null };
    l.openAdminPass("passphrase");
    l._adminPass = PASS;
    l._adminNew = "a brand new fixture passphrase";
    l._adminNewRepeat = "a brand new fixture passphrase";
    await l.submitAdminPass();
    await settle();
    expect(broker().calls("vault_set_passphrase")).toHaveLength(1);
    expect(broker().state().machineLock).toBe(false);
    expect(l.state.notice).toMatchObject({ kind: "warn" });
    expect(l.state.notice.text).toMatch(/machine lock is off now/);
  });

  it("the Forgot-passphrase step says the lock is off before the app opens", () => {
    const html = read("src/design/screens/S16-lock.html");
    expect(html).toMatch(/data-machine-lock-removed="1"[^>]*>\{\{forgotLockRemovedText\}\}/);
    const session = read("src/design/logic/session.js");
    expect(session).toMatch(/forgotLockRemoved:r\.machineLockRemoved\|\|''/);
    const source = read("src/vault/bridge-source.ts");
    expect(source).toMatch(/out\.machineLockRemoved = r\.machineLockRemoved/);
  });
});

describe("the error table for machine_lock_refused", () => {
  const err = (reason: string) => ({ source: "broker", code: "machine_lock_refused", message: "refused", detail: { reason } });

  it("on the Lock screen points to the recovery code and never blames the passphrase", () => {
    for (const reason of ["device_key_missing", "device_key_mismatch", "device_key_unreadable", "device_key_unwritable"]) {
      const r = classifyError(err(reason), { op: "vault.unlock", field: "passphrase" });
      expect(r).toMatchObject({ route: "inline", field: "passphrase" });
      expect((r as { message: string }).message).toMatch(/Forgot passphrase\? Use recovery code/);
      expect((r as { message: string }).message).not.toMatch(/Wrong passphrase/);
    }
    const d = classifyError(err("sealed_wrap_damaged"), { op: "vault.unlock", field: "passphrase" });
    expect((d as { message: string }).message).toMatch(/damaged/);
    expect((d as { message: string }).message).toMatch(/recovery code/);
  });

  it("on a backup whose device key went away mid-session says what to do (review N6)", () => {
    const r = classifyError(err("backup_needs_device_key"), { op: "maintenance.backup" });
    expect(r).toMatchObject({ route: "notice", kind: "warn" });
    expect((r as { message: string }).message).toMatch(/Put the key file back/);
    expect((r as { message: string }).message).toMatch(/recovery code/);
    expect((r as { message: string }).message).toMatch(/backup was not written/);
  });

  it("is a code the bridge declares", () => {
    expect(read("src/lib/bridge.ts")).toMatch(/\| "machine_lock_refused";/);
  });
});
