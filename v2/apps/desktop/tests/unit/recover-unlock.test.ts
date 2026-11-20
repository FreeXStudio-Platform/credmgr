// ADR-163, the desktop half of "Forgot passphrase? Use recovery code": the Lock screen's two steps (S16b), the model's recoverWithCode, the
// bridge call and what the error table says.  The logic runs exactly as in the app: the model reads through the real bridge client and the
// Tauri shell's `invoke` is the fixture broker (tests/fixtures/broker), which answers vault_recover as crates/brokerd/src/ops.rs does.
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import Component from "../../src/design/logic/core.js";
import { LOCK_FORGOT, LOCK_FORGOT_DONE, LOCK_PHRASE } from "../../src/design/logic/session.js";
import { classifyError } from "../../src/vault/errors";
import { brokerScript, FIXTURE_GATE_CODE, FIXTURE_PASSPHRASE, FIXTURE_ROOT_RECOVERY_CODE } from "../fixtures/broker/index";

interface FixtureControl {
  calls(cmd?: string): Array<{ cmd: string; args: Record<string, unknown> }>;
  state(): Record<string, any>;
  set(patch: Record<string, unknown>): void;
}
const g = globalThis as unknown as { window?: any; document?: any };
const broker = (): FixtureControl => g.window.__BROKER__;
const typing = (value: string) => ({ target: { value } });
const ticking = (checked: boolean) => ({ target: { checked } });
const NEW_PASS = "a fresh passphrase";

/** A logic instance on the Lock screen of a fixture vault, with a host that merges state synchronously (what DCHost does). */
async function lockScreen(options: Record<string, unknown> = {}) {
  g.window = {};
  new Function("window", brokerScript({ locked: true, ...options }))(g.window);
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
  expect(l.model.kind).toBe("bridge");
  expect(l.model.status).toBe("locked");
  l.state = { ...l.state, screen: "lock", lockStep: LOCK_PHRASE, fieldErrors: {} };
  return l;
}

/** Fill the recovery-code form the way a person does: through the handlers the template binds. */
function fill(l: any, code: string, pass = NEW_PASS, repeat = pass) {
  const v = l.renderVals();
  v.onForgotCode(typing(code));
  v.onForgotPass(typing(pass));
  l.renderVals().onForgotRepeat(typing(repeat));
}

beforeEach(() => {
  g.document = { querySelector: () => null, querySelectorAll: () => [], documentElement: { dataset: {}, style: { setProperty() {}, removeProperty() {} } } };
});
afterEach(async () => {
  await new Promise((r) => setTimeout(r, 5)); // refocusLock's caret move runs on a timer: let it find the fake document
  delete g.window;
  delete g.document;
});

describe("the Lock screen's \"Forgot passphrase?\" path (vault.recover)", () => {
  it("is offered on the passphrase step and opens the recovery-code form when the vault has a recovery wrap", async () => {
    const l = await lockScreen();
    expect(l.model.recoveryUnlock).toBe(true);
    let v = l.renderVals();
    expect(v).toMatchObject({ lockStepPass: true, lockStepForgot: false, lockStepForgotDone: false });
    v.gotoForgot();
    expect(l.state.lockStep).toBe(LOCK_FORGOT);
    v = l.renderVals();
    expect(v).toMatchObject({ lockStepPass: false, lockStepForgot: true, forgotNeedFactor: false, forgotDisabled: true });
    expect(v.aprLinkShow).toBe(false); // the locked-approval panel belongs to the passphrase step
  });

  it("on a vault with no recovery wrap says when the feature appears and stays on the passphrase step", async () => {
    const l = await lockScreen({ recoveryUnlock: false });
    expect(l.model.recoveryUnlock).toBe(false);
    l.renderVals().gotoForgot();
    expect(l.state.lockStep).toBe(LOCK_PHRASE);
    expect(l.state.lockNote).toMatch(/next time the passphrase is changed/);
    expect(broker().calls("vault_recover")).toEqual([]);
  });

  it("asks for a code, a new passphrase of at least four characters, typed twice the same", async () => {
    const l = await lockScreen();
    l.renderVals().gotoForgot();
    fill(l, FIXTURE_ROOT_RECOVERY_CODE, "abc");
    expect(l.renderVals()).toMatchObject({ forgotShort: true, forgotDisabled: true });
    fill(l, FIXTURE_ROOT_RECOVERY_CODE, NEW_PASS, NEW_PASS + "x");
    expect(l.renderVals()).toMatchObject({ forgotMismatch: true, forgotDisabled: true });
    fill(l, "", NEW_PASS);
    expect(l.renderVals().forgotDisabled).toBe(true);
    await l.doForgot(); // a disabled button's handler does nothing either
    expect(broker().calls("vault_recover")).toEqual([]);
    fill(l, FIXTURE_ROOT_RECOVERY_CODE, NEW_PASS);
    expect(l.renderVals()).toMatchObject({ forgotShort: false, forgotMismatch: false, forgotDisabled: false });
  });

  it("opens the vault, shows the NEW recovery code once, and the old code and passphrase stop working", async () => {
    const l = await lockScreen();
    l.renderVals().gotoForgot();
    fill(l, `  ${FIXTURE_ROOT_RECOVERY_CODE} `);
    await l.renderVals().submitForgot();

    const sent = broker().calls("vault_recover");
    expect(sent).toEqual([{ cmd: "vault_recover", args: { recoveryCode: FIXTURE_ROOT_RECOVERY_CODE, newPassphrase: NEW_PASS } }]); // trimmed; no `code` without a gate
    const S = broker().state();
    expect(S.passphrase).toBe(NEW_PASS);
    expect(S.rootRecoveryCode).not.toBe(FIXTURE_ROOT_RECOVERY_CODE);
    expect(l.model.status).toBe("unlocked");

    // The typed secrets are gone; only the new code is on screen, and the app opens only once it was saved.
    expect(l.state).toMatchObject({ lockStep: LOCK_FORGOT_DONE, forgotCode: "", forgotPass: "", forgotRepeat: "", forgotFactor: "", screen: "lock" });
    let v = l.renderVals();
    expect(v).toMatchObject({ lockStepForgotDone: true, lockStepForgot: false, forgotNewCode: S.rootRecoveryCode, forgotFinishDisabled: true, forgotFinishLabel: "Open the vault" });
    v.finishForgot();
    expect(l.state.screen).toBe("lock"); // not before the tick
    v.onForgotSaved(ticking(true));
    l.renderVals().finishForgot();
    expect(l.state.screen).toBe("app");
    expect(l.state.forgotNewCode).toBe(""); // the new code leaves state with the step
    expect(l.state.notice?.text).toMatch(/old recovery code and the old passphrase no longer open the vault/);

    // The used code is dead.
    await l.lockVault();
    await l.model.boot();
    l.state = { ...l.state, screen: "lock", lockStep: LOCK_PHRASE, fieldErrors: {} };
    l.renderVals().gotoForgot();
    fill(l, FIXTURE_ROOT_RECOVERY_CODE, "yet another one");
    await l.doForgot();
    expect(l.state.lockStep).toBe(LOCK_FORGOT);
    expect(l.state.forgotCode).toBe(""); // a wrong code is retyped
    expect(l.state.forgotPass).toBe("yet another one"); // the new passphrase need not be
    expect(l.renderVals().lockErrForgot).toBe("That recovery code does not open this vault. Nothing was changed.");
    expect(broker().state().passphrase).toBe(NEW_PASS);
    // ...and the old passphrase too; the new one opens it.
    await expect(l.model.unlock(FIXTURE_PASSPHRASE)).rejects.toMatchObject({ code: "wrong_passphrase" });
    await l.model.unlock(NEW_PASS);
    expect(l.model.status).toBe("unlocked");
  });

  it("still asks for an enrolled second factor, keeping the code and the new passphrase typed", async () => {
    const l = await lockScreen({ gate: true });
    l.renderVals().gotoForgot();
    fill(l, FIXTURE_ROOT_RECOVERY_CODE);
    await l.doForgot();
    expect(l.state).toMatchObject({ lockStep: LOCK_FORGOT, forgotNeedFactor: true, forgotCode: FIXTURE_ROOT_RECOVERY_CODE, forgotPass: NEW_PASS });
    expect(l.model.status).toBe("locked");
    expect(broker().state().passphrase).toBe(FIXTURE_PASSPHRASE); // nothing changed
    let v = l.renderVals();
    expect(v).toMatchObject({ forgotNeedFactor: true, forgotDisabled: true, lockErrForgot: "" });

    // A wrong factor: refused, the factor is cleared, nothing changes.
    v.onForgotFactor(typing("000000"));
    await l.doForgot();
    expect(l.state.forgotFactor).toBe("");
    expect(l.renderVals().lockErrForgot).toBe("That code was not accepted.");
    expect(broker().state().passphrase).toBe(FIXTURE_PASSPHRASE);

    l.renderVals().onForgotFactor(typing(FIXTURE_GATE_CODE));
    await l.doForgot();
    expect(broker().calls("vault_recover").at(-1)?.args).toEqual({ recoveryCode: FIXTURE_ROOT_RECOVERY_CODE, newPassphrase: NEW_PASS, code: FIXTURE_GATE_CODE });
    expect(l.state.lockStep).toBe(LOCK_FORGOT_DONE);
    expect(l.model.status).toBe("unlocked");
    expect(l.model.gateConfirmed).toBe(true);
  });

  it("a recovery whose last file moves are pending stays locked and sends the person to the new passphrase", async () => {
    const l = await lockScreen();
    (g.window.__brokerFixture.scripts as Record<string, unknown[]>).vault_recover = [
      { result: { rotated: true, recoveryCode: "FIXT-PEND-ING0-0001", nodesRewrapped: 1, vaultGeneration: 3, filesReplaced: 2, artifactsResigned: 0, completionPending: true, notResigned: [], passphraseChanged: true, recovered: true, locked: true } },
    ];
    l.renderVals().gotoForgot();
    fill(l, FIXTURE_ROOT_RECOVERY_CODE);
    await l.doForgot();
    expect(l.model.status).toBe("locked");
    const v = l.renderVals();
    expect(v).toMatchObject({ lockStepForgotDone: true, forgotNewCode: "FIXT-PEND-ING0-0001", forgotFinishLabel: "Go to unlock" });
    expect(v.forgotDoneText).toMatch(/unlock it with the new passphrase/);
    v.onForgotSaved(ticking(true));
    l.renderVals().finishForgot();
    expect(l.state).toMatchObject({ screen: "lock", lockStep: LOCK_PHRASE, forgotNewCode: "" });
    expect(l.state.lockNote).toMatch(/Unlock with the new passphrase/);
  });

  it("back, and a lock, forget everything typed on the form", async () => {
    const l = await lockScreen({ gate: true });
    l.renderVals().gotoForgot();
    fill(l, FIXTURE_ROOT_RECOVERY_CODE);
    l.renderVals().onForgotFactor(typing("12"));
    l.renderVals().gotoPassphrase();
    expect(l.state).toMatchObject({ lockStep: LOCK_PHRASE, forgotCode: "", forgotPass: "", forgotRepeat: "", forgotFactor: "", forgotNeedFactor: false });
    l.renderVals().gotoForgot();
    fill(l, FIXTURE_ROOT_RECOVERY_CODE);
    l.showLock("");
    expect(l.state).toMatchObject({ lockStep: LOCK_PHRASE, forgotCode: "", forgotPass: "", forgotRepeat: "", forgotNewCode: "" });
  });

  it("a back-off from the broker keeps the button off and says how long", async () => {
    const l = await lockScreen();
    (g.window.__brokerFixture.scripts as Record<string, unknown[]>).vault_recover = [{ error: { code: "rate_limited", detail: { retryAfterSeconds: 30 } } }];
    l.renderVals().gotoForgot();
    fill(l, FIXTURE_ROOT_RECOVERY_CODE);
    await l.doForgot();
    const v = l.renderVals();
    expect(v.lockErrForgot).toBe("Too many attempts. Try again in 30 s.");
    expect(v.forgotDisabled).toBe(true);
    clearTimeout(l._retryT);
  });
});

describe("what the error table says for vault.recover", () => {
  const err = (code: string) => ({ source: "broker", code, message: code });
  it("chooses its own words by code and never quotes the broker", () => {
    expect(classifyError(err("recovery_code_mismatch"), { op: "vault.recover" })).toEqual({ route: "inline", field: "forgot", message: "That recovery code does not open this vault. Nothing was changed." });
    expect(classifyError(err("not_found"), { op: "vault.recover" })).toMatchObject({ route: "inline", field: "forgot", message: expect.stringMatching(/next time the passphrase is changed/) });
    expect(classifyError(err("malformed_request"), { op: "vault.recover" })).toMatchObject({ route: "inline", field: "forgot", message: expect.stringMatching(/already unlocked/) });
    // other ops keep their old words
    expect(classifyError(err("recovery_code_mismatch"), { op: "vault.init_confirm" })).toMatchObject({ message: "The recovery code does not match." });
    expect(classifyError(err("not_found"), { op: "entry.get" })).toMatchObject({ route: "refresh" });
  });
});
